"""Load config.json with every path made absolute.

Paths in config.json may be absolute ("/home/vboxuser/..."), use "~", or be
relative to this data/ folder ("lab-watch/..."). Relative paths let the repo
work wherever it is cloned.
"""
import json
import os
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
PATH_KEYS = ("watch_root", "events_path", "manifest_path", "alerts_path", "canary_baseline_path")


def resolve(p):
    p = Path(os.path.expanduser(str(p)))
    return (p if p.is_absolute() else PROJECT / p).resolve()


def load_config(path=PROJECT / "config.json"):
    with open(path, encoding="utf-8") as f:
        config = json.load(f)
    for key in PATH_KEYS:
        if key in config:
            config[key] = str(resolve(config[key]))
    config["canary_paths"] = [str(resolve(p)) for p in config.get("canary_paths", [])]
    return config
