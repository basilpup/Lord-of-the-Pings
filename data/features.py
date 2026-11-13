"""Shared feature code (Story 0, Contracts A -> B).

Story 6 (dataset building) and Story 9 (live service) must both call
extract_features() so training and live features cannot drift apart.
Reference implementation; owner going forward: Snow.
"""
import csv
import json
import math
from pathlib import Path
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
                  window_seconds=1.0, step_seconds=0.25, grace_seconds=0.5,
                  keep_unknown=False):
    """Contract A events + Contract D manifest -> Contract B CSV.

    Label rule: a window is 1 (attack) if at least one of its events falls
    inside an attack run's [start_ts, end_ts + grace]; otherwise 0.
    The grace period catches the last few events of a run, which the monitor
    can stamp a few milliseconds after the script records end_ts.
    run_id: the attack run if labelled 1, else the normal run that contains
    all of the window's events. Windows that belong to no run (e.g. manual
    activity between runs) get run_id "unknown" and are dropped unless
    keep_unknown=True.
    """
    events = load_jsonl(events_path)
    runs = [dict(r, s=parse_ts(r["start_ts"]), e=parse_ts(r["end_ts"]) + grace_seconds)
            for r in load_jsonl(manifest_path)]
    attack = [r for r in runs if r["label"] == 1]
    rows = []
    dropped = 0
    for start, evs in windows_for(events, window_seconds, step_seconds).items():
        times = [parse_ts(e["ts"]) for e in evs]
        hit = next((r for r in attack if any(r["s"] <= t <= r["e"] for t in times)), None)
        owner = hit or next((r for r in runs if r["label"] == 0 and all(r["s"] <= t <= r["e"] for t in times)), None)
        if owner is None and not keep_unknown:
            dropped += 1
            continue
        row = {"run_id": owner["run_id"] if owner else "unknown",
               "window_start": format_ts(start)}
        row.update(extract_features(evs, window_seconds))
        row["label"] = 1 if hit else 0
        rows.append(row)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["run_id", "window_start"] + FEATURE_COLUMNS + ["label"])
        w.writeheader()
        w.writerows(rows)
    if dropped:
        print(f"dropped {dropped} windows that belong to no run")
    return len(rows)


def summarize(csv_path):
    """Print a sanity check of a built dataset. Catches the old monitor bug,
    where every window held exactly one event."""
    with open(csv_path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    for label, name in (("0", "normal"), ("1", "attack")):
        sub = [r for r in rows if r["label"] == label]
        if not sub:
            print(f"{name:6}: no rows")
            continue
        counts = [int(r["event_count"]) for r in sub]
        runs = {r["run_id"] for r in sub}
        print(f"{name:6}: {len(sub):6} windows from {len(runs):3} runs | "
              f"events/window mean {sum(counts) / len(counts):.2f}, max {max(counts)}")
    if rows and max(int(r["event_count"]) for r in rows) <= 1:
        print("WARNING: every window has at most 1 event - timestamps look spread out. "
              "Is the fixed monitor.py running?")


if __name__ == "__main__":
    import argparse
    from config_paths import load_config, PROJECT
    cfg = load_config()
    ap = argparse.ArgumentParser(description="Build the labelled window dataset (Story 6).")
    ap.add_argument("--events", default=cfg["events_path"])
    ap.add_argument("--manifest", default=cfg["manifest_path"])
    ap.add_argument("--out", default=str(PROJECT / "datasets" / "processed" / "dataset.csv"))
    ap.add_argument("--keep-unknown", action="store_true")
    a = ap.parse_args()
    n = build_dataset(a.events, a.manifest, a.out, cfg["window_seconds"], cfg["step_seconds"],
                      keep_unknown=a.keep_unknown)
    print(f"wrote {n} rows to {a.out}")
    summarize(a.out)
