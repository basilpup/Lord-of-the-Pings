"""Story 2: create the canary files and record a baseline.

Creates every file in config["canary_paths"] as a real file of its type
(a .docx is a real Word file, a .pem is a real key, ...) so they look like
genuine user documents, then writes a baseline of hashes, sizes, timestamps
and extensions for later diffing.

Usage:
    python3 place_canaries.py            # create missing canaries + write baseline
    python3 place_canaries.py --reset    # recreate ALL canaries (e.g. after attack runs) + new baseline
    python3 place_canaries.py --check    # compare current canaries against the baseline

Run it BEFORE starting the monitor so placing the files isn't logged as activity.
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from config_paths import PROJECT, load_config
from normal_script import create_sample


def baseline_path(config):
    return Path(config.get("canary_baseline_path", PROJECT / "canary_baseline.json"))


def iso(seconds):
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def describe(path):
    data = path.read_bytes()
    st = path.stat()
    return {
        "path": str(path),
        "ext": path.suffix,
        "size_bytes": st.st_size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "mtime": iso(st.st_mtime),
    }


def place(config, reset=False):
    records = []
    for raw in config["canary_paths"]:
        path = Path(raw)
        if reset or not path.exists():
            create_sample(path)
            print(f"created  {path}")
        else:
            print(f"exists   {path}")
        records.append(describe(path))
    out = baseline_path(config)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"created": iso(datetime.now().timestamp()),
                               "canaries": records}, indent=2), encoding="utf-8")
    print(f"\nBaseline for {len(records)} canaries written to {out}")


def check(config):
    base = json.loads(baseline_path(config).read_text(encoding="utf-8"))
    changed = 0
    for rec in base["canaries"]:
        path = Path(rec["path"])
        if not path.exists():
            siblings = sorted(p.name for p in path.parent.glob(path.name + "*")) if path.parent.exists() else []
            note = f" (found instead: {', '.join(siblings)})" if siblings else ""
            print(f"MISSING   {path}{note}")
            changed += 1
            continue
        now = describe(path)
        if now["sha256"] != rec["sha256"]:
            print(f"MODIFIED  {path}  size {rec['size_bytes']} -> {now['size_bytes']}, "
                  f"mtime {now['mtime']}")
            changed += 1
        else:
            print(f"ok        {path}")
    print(f"\n{changed} of {len(base['canaries'])} canaries changed since baseline.")
    return changed


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reset", action="store_true", help="recreate all canaries")
    ap.add_argument("--check", action="store_true", help="diff against baseline")
    args = ap.parse_args()
    cfg = load_config()
    if args.check:
        sys.exit(1 if check(cfg) else 0)
    place(cfg, reset=args.reset)
