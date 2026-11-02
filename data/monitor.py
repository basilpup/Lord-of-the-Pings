import time
import json
import math
from pathlib import Path
from datetime import datetime, UTC

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

PROJECT = Path(__file__).resolve().parent

with open(PROJECT / "config.json", encoding="utf-8") as f:
    CONFIG = json.load(f) # loads config.json

# extracts from the json
WATCH_ROOT = Path(CONFIG["watch_root"]).resolve() 
EVENTS_PATH = Path(CONFIG["events_path"])
CANARIES = {
    str(Path(p).resolve()) for p in CONFIG["canary_paths"]
}

def timestamp():
    return datetime.now(UTC).isoformat(timespec="milliseconds")

# calculate entropy
def file_entropy(path):
    try:
        with open(path, "rb") as f:
            data = f.read(65536) # reads the first 64KB

        if not data:
            return 0.0

        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        length = len(data)

        return round(
            -sum(
                (count / length * math.log2(count / length) # Shannon entropy equation (measures the average amount of uncertainty)
                           for count in counts if count)
            ),
            4 # round to 4 decimals
        )
    except (OSError, PermissionError):
        return None


def record_event(operation, path, old_path=None):
    path = str(Path(path).resolve())
    old_path = str(Path(old_path).resolve()) if old_path else None
    try: 
        size = Path(path).stat().st_size
    except OSError:
        size = None
    event = {
        "ts": timestamp(), # time the event was recorded
        "op": operation, # type of op
        "path": path, # current file path
        "old_path": old_path, # old file path
        "ext": Path(path).suffix, # current file extension
        "old_ext": Path(old_path).suffix if old_path else None, # old extension
        "is_canary": path in CANARIES or old_path in CANARIES, # if the event involved a canary file
        "size_bytes": size, # file size
        "entropy": file_entropy(path) if size is not None else None, # calculated entropy
        "pid": None, # process ID
        "process_name": None # process name
    }

    with open(EVENTS_PATH, "a", encoding="utf-8") as f: # writes the event to the JSON file
        f.write(json.dumps(event) + "\n")
        f.flush()
    print(operation, path)

# which events are created when watchdog detects a change
class ActivityHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            record_event("create", event.src_path)
    def on_modified(self, event):
        record_event("modify", event.src_path)
    def on_deleted(self, event):
        if not event.is_directory:
            record_event("delete", event.src_path)
    def on_moved(self, event):
        if not event.is_directory:
            record_event(
                "rename",
                event.dest_path,
                event.src_path
            )

# for starting the monitor 
if __name__ == "__main__":
    handler = ActivityHandler() # contains the four possible events
    observer = Observer() # watches the filesystem

    observer.schedule(
        handler,
        str(WATCH_ROOT), # observer watches the root
        recursive=True
    )

    observer.start() # starts the observer in the background

    print("Monitoring: ", WATCH_ROOT)
    print("Writing to: ", EVENTS_PATH)
    print("Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt: # stop when Ctrl+C
        observer.stop()

    observer.join()