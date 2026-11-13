"""Story 6: run the normal and attack scripts repeatedly to collect training data.

Each round runs every normal pattern and every attack pattern once, in a
random order, with a pause between runs so that no 1-second window mixes
two runs. At the end it builds the labelled dataset.

Start the monitor FIRST, in another terminal:
    sudo .venv/bin/python monitor.py          (or: python monitor.py --no-process-lookup)
Then:
    python collect_data.py --rounds 5

Rough time per round: 10-20 minutes (the "slow" pacing modes are slow on purpose).
"""
import argparse
import random
import time
from pathlib import Path

import attack_script
import normal_script
from config_paths import PROJECT, load_config
from features import build_dataset, summarize


def events_size(path):
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--gap", type=float, default=3.0,
                    help="seconds of quiet between runs (must exceed window_seconds)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--only", choices=["normal", "attack"], default=None)
    ap.add_argument("--no-build", action="store_true", help="skip building the CSV at the end")
    args = ap.parse_args()

    cfg = load_config()
    if args.gap <= cfg["window_seconds"]:
        ap.error("--gap must be larger than window_seconds")
    if args.seed is not None:
        random.seed(args.seed)

    jobs = []
    if args.only != "attack":
        jobs += [(normal_script, n, f) for n, f in normal_script.PATTERNS.items()]
    if args.only != "normal":
        jobs += [(attack_script, n, f) for n, f in attack_script.PATTERNS.items()]

    normal_script.BASE_DIR.mkdir(parents=True, exist_ok=True)
    attack_script.BASE_DIR.mkdir(parents=True, exist_ok=True)

    before = events_size(cfg["events_path"])
    checked = False
    total = args.rounds * len(jobs)
    done = 0
    t0 = time.time()
    for r in range(1, args.rounds + 1):
        order = jobs[:]
        random.shuffle(order)
        for module, name, fn in order:
            done += 1
            print(f"\n=== round {r}/{args.rounds}, run {done}/{total} "
                  f"({(time.time() - t0) / 60:.1f} min elapsed) ===")
            module.run_activity(name, fn)
            time.sleep(args.gap)
            if not checked:
                checked = True
                if events_size(cfg["events_path"]) == before:
                    print(f"\nWARNING: nothing was written to {cfg['events_path']}.\n"
                          "Is monitor.py running in another terminal? Stopping.")
                    return

    print(f"\nCollection finished in {(time.time() - t0) / 60:.1f} min.")
    if not args.no_build:
        out = PROJECT / "datasets" / "processed" / "dataset.csv"
        n = build_dataset(cfg["events_path"], cfg["manifest_path"], out,
                          cfg["window_seconds"], cfg["step_seconds"])
        print(f"wrote {n} rows to {out}")
        summarize(out)


if __name__ == "__main__":
    main()
