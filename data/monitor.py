"""Story 3: file-activity monitor.

Watches config["watch_root"] and appends one JSON line per file event
(Contract A) to config["events_path"].

Fix (Nov 2026): the old version ran `ausearch` over the whole audit log
*before* stamping each event, so as the log grew every event waited seconds
in watchdog's queue and got a late timestamp. Burst attacks ended up looking
like one event every ~2.5 s, which erased the timing signal from the dataset.

Now:
  1. The handler stamps the time and reads size/entropy immediately
     (a few milliseconds), then hands the event to a queue.
  2. A writer thread does the slow process lookup (optional, cached) and
     writes the line. Timestamps are therefore taken when the event arrives,
     no matter how slow the lookup is.

Usage:
    sudo python3 monitor.py                 # with process lookup (needs auditd rule)
    python3 monitor.py --no-process-lookup  # no sudo/auditd needed, pid = null
"""
import argparse
import json
import math
import os
import queue
import signal
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from config_paths import PROJECT, load_config


def timestamp(event_time):
    return datetime.fromtimestamp(event_time, tz=timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def file_entropy(path):
    """Shannon entropy (bits/byte) of the first 64 KB, or None if unreadable/empty."""
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
    except OSError:
        return None
    if not data:
        return None
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 4)


def make_user_owned(path):
    """Create the events file (and its folders). When run with sudo, hand them
    back to the real user, so the collection scripts (run without sudo) can
    still write their own files next to them."""
    path = Path(path)
    missing = [p for p in [path.parent, *path.parent.parents] if not p.exists()]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        for p in [path, *missing]:
            os.chown(p, int(uid), int(gid))


class ProcessLookup:
    """Matches file events to audit records. Refreshes its cache at most every
    `refresh_s` seconds and only reads recent audit records."""

    def __init__(self, refresh_s=0.5):
        from audit_reader import read_audit_events, match_process
        self._read = read_audit_events
        self._match = match_process
        self.refresh_s = refresh_s
        self._cache = []
        self._last = 0.0
        self.failed = False

    def find(self, path, old_path, event_time):
        for attempt in range(2):
            if attempt == 1 or not self._cache:
                if time.time() - self._last < self.refresh_s:
                    break
                try:
                    self._cache = self._read(start="recent")
                except (OSError, RuntimeError) as error:
                    if not self.failed:
                        print(f"[monitor] process lookup disabled: {error}")
                    self.failed = True
                    return {}
                self._last = time.time()
            for p in (path, old_path):
                if p:
                    hit = self._match(self._cache, p, event_time)
                    if hit:
                        return hit
        return {}


class Monitor(FileSystemEventHandler):
    def __init__(self, config, process_lookup=True, quiet=False):
        self.events_path = Path(config["events_path"])
        self.canaries = {str(Path(p).resolve()) for p in config["canary_paths"]}
        self.ignore = {str(self.events_path.resolve())}
        self.quiet = quiet
        self.q = queue.Queue()
        self.lookup = ProcessLookup() if process_lookup else None
        self.count = 0
        self.writer = threading.Thread(target=self._write_loop, daemon=True)
        self.writer.start()

    # ---- fast path: runs on watchdog's thread --------------------------------
    def _capture(self, op, path, old_path=None):
        t = time.time()                      # stamp FIRST
        path = str(Path(path).resolve())
        if path in self.ignore:
            return
        old_path = str(Path(old_path).resolve()) if old_path else None
        try:
            size = Path(path).stat().st_size
        except OSError:
            size = None
        event = {
            "ts": timestamp(t),
            "op": op,
            "path": path,
            "old_path": old_path,
            "ext": Path(path).suffix,
            "old_ext": Path(old_path).suffix if old_path else None,
            "is_canary": path in self.canaries or old_path in self.canaries,
            "size_bytes": size,
            "entropy": file_entropy(path) if size else None,
            "pid": None,
            "process_name": None,
            "process_exe": None,
        }
        self.q.put((t, event))

    def on_created(self, e):
        if not e.is_directory:
            self._capture("create", e.src_path)

    def on_modified(self, e):
        if not e.is_directory:
            self._capture("modify", e.src_path)

    def on_deleted(self, e):
        if not e.is_directory:
            self._capture("delete", e.src_path)

    def on_moved(self, e):
        if not e.is_directory:
            self._capture("rename", e.dest_path, e.src_path)

    # ---- slow path: writer thread ---------------------------------------------
    def _write_loop(self):
        make_user_owned(self.events_path)
        with open(self.events_path, "a", encoding="utf-8") as f:
            while True:
                item = self.q.get()
                if item is None:
                    break
                t, event = item
                if self.lookup and not self.lookup.failed:
                    info = self.lookup.find(event["path"], event["old_path"], t)
                    event["pid"] = info.get("pid")
                    event["process_name"] = info.get("process_name")
                    event["process_exe"] = info.get("exe")
                f.write(json.dumps(event) + "\n")
                f.flush()
                self.count += 1
                if not self.quiet:
                    flag = "  [CANARY]" if event["is_canary"] else ""
                    print(f"{event['op']:6} {event['path']}{flag}  pid={event['pid']}")

    def close(self):
        self.q.put(None)
        self.writer.join()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(PROJECT / "config.json"))
    ap.add_argument("--no-process-lookup", action="store_true",
                    help="skip auditd/ausearch (pid fields stay null)")
    ap.add_argument("--quiet", action="store_true", help="don't print each event")
    args = ap.parse_args()

    config = load_config(args.config)
    watch_root = Path(config["watch_root"]).resolve()
    watch_root.mkdir(parents=True, exist_ok=True)

    handler = Monitor(config, process_lookup=not args.no_process_lookup, quiet=args.quiet)
    observer = Observer()
    observer.schedule(handler, str(watch_root), recursive=True)
    observer.start()
    # Treat `kill` (SIGTERM) like Ctrl+C so the queue is flushed before exit.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    print(f"Monitoring: {watch_root}\nWriting to: {handler.events_path}\nCtrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    observer.stop()
    observer.join()
    handler.close()
    print(f"Stopped. {handler.count} events written.")


if __name__ == "__main__":
    main()
