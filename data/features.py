"""Shared feature code (Story 0, Contracts A -> B).

Story 6 (dataset building) and Story 9 (live service) must both call
extract_features() so training and live features cannot drift apart.
Reference implementation; owner going forward: Snow.
"""
import csv
import json
import math
from datetime import datetime, timezone

FEATURE_COLUMNS = [
    "event_count", "n_create", "n_modify", "n_rename", "n_delete",
    "n_ext_change", "n_unique_files", "n_canary_touched",
    "mean_gap_ms", "min_gap_ms", "mean_entropy", "max_entropy",
    "n_unique_processes",
]


def parse_ts(ts):
    """ISO 8601 UTC string -> seconds since epoch (float)."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def format_ts(seconds):
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def extract_features(events, window_seconds=1.0):
    """Turn the Contract A events of ONE window into a Contract B feature dict.

    `events` is a list of dicts, at least one event. Null rules:
    - fewer than 2 events: both gap features = window length in ms
    - no entropy values: both entropy features = 0
    - null pids are not counted as processes
    """
    times = sorted(parse_ts(e["ts"]) for e in events)
    gaps = [(b - a) * 1000.0 for a, b in zip(times, times[1:])]
    window_ms = window_seconds * 1000.0
    ent = [e["entropy"] for e in events if e.get("entropy") is not None]
    ops = [e["op"] for e in events]
    return {
        "event_count": len(events),
        "n_create": ops.count("create"),
        "n_modify": ops.count("modify"),
        "n_rename": ops.count("rename"),
        "n_delete": ops.count("delete"),
        "n_ext_change": sum(
            1 for e in events
            if e["op"] == "rename" and e.get("old_ext") is not None
            and e["old_ext"] != e["ext"]),
        "n_unique_files": len({e["path"] for e in events}),
        "n_canary_touched": len({e["path"] for e in events if e.get("is_canary")}),
        "mean_gap_ms": round(sum(gaps) / len(gaps), 3) if gaps else window_ms,
        "min_gap_ms": round(min(gaps), 3) if gaps else window_ms,
        "mean_entropy": round(sum(ent) / len(ent), 4) if ent else 0.0,
        "max_entropy": round(max(ent), 4) if ent else 0.0,
        "n_unique_processes": len({e["pid"] for e in events if e.get("pid") is not None}),
    }


def windows_for(events, window_seconds=1.0, step_seconds=0.25):
    """Group events into sliding windows on a fixed grid.

    A window [start, start + window_seconds) starts at a multiple of
    step_seconds. Windows with zero events are not produced.
    Returns {window_start_seconds: [events]} in time order.
    """
    out = {}
    for e in events:
        t = parse_ts(e["ts"])
        k = math.floor(t / step_seconds)
        while k * step_seconds > t - window_seconds:
            out.setdefault(round(k * step_seconds, 6), []).append(e)
            k -= 1
    return dict(sorted(out.items()))


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def build_dataset(events_path, manifest_path, out_path,
                  window_seconds=1.0, step_seconds=0.25):
    """Contract A events + Contract D manifest -> Contract B CSV.

    Label rule: a window is 1 (attack) if at least one of its events falls
    inside an attack run's [start_ts, end_ts]; otherwise 0.
    run_id: the attack run if labelled 1, else the run containing the
    window's first event.
    """
    events = load_jsonl(events_path)
    runs = [dict(r, s=parse_ts(r["start_ts"]), e=parse_ts(r["end_ts"]))
            for r in load_jsonl(manifest_path)]
    attack = [r for r in runs if r["label"] == 1]
    rows = []
    for start, evs in windows_for(events, window_seconds, step_seconds).items():
        times = [parse_ts(e["ts"]) for e in evs]
        hit = next((r for r in attack if any(r["s"] <= t < r["e"] for t in times)), None)
        owner = hit or next((r for r in runs if r["label"] == 0 and all(r["s"] <= t < r["e"] for t in times)), None) # assigns a normal run ID when all events fall inside the same normal run
        row = {"run_id": owner["run_id"] if owner else "unknown",
               "window_start": format_ts(start)}
        row.update(extract_features(evs, window_seconds))
        row["label"] = 1 if hit else 0
        rows.append(row)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["run_id", "window_start"] + FEATURE_COLUMNS + ["label"])
        w.writeheader()
        w.writerows(rows)
    return len(rows)


if __name__ == "__main__":
    build_dataset(
        "datasets/raw/events/events.jsonl", 
        "datasets/raw/manifests/manifest.jsonl", 
        "datasets/processed/dataset.csv"
        )
    
