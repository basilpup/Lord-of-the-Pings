# Lord of the Pings — canary-file ransomware detection

| Folder | What |
|---|---|
| `contracts/` | Shared formats (Story 0): config, event/dataset/model contracts, sample files |
| `data/` | Runs on the Ubuntu VM: canaries, monitor, normal + attack scripts, dataset builder (Stories 2–6) |
| `model/` | Training + evaluation (Stories 7–8). Runs anywhere with Python 3.12. |
| `training data/` | First dataset (`canarylotp.csv`, collected with the old monitor — see below) |

## On the VM (Ubuntu 24.04): collect data

```
git clone https://github.com/basilpup/Lord-of-the-Pings.git
cd Lord-of-the-Pings/data
bash setup_vm.sh                                    # once: packages, .venv, canaries, audit rule
```

Then two terminals, both in `data/`:

```
# Terminal 1 - leave running
sudo .venv/bin/python monitor.py

# Terminal 2
.venv/bin/python collect_data.py --rounds 5         # ~1 hour; builds datasets/processed/dataset.csv
```

Stop the monitor with Ctrl+C when collection finishes. Check the summary it prints:
attack windows should average several events each. Then commit
`data/datasets/processed/dataset.csv` (and `data/datasets/raw/`) and push.

`place_canaries.py --check` shows which canaries changed since the baseline;
`place_canaries.py --reset` recreates them.

## Train (anywhere)

```
python model/train.py
```

See `model/README.md`.

## Nov 2026 fixes

- **Monitor timestamps.** `monitor.py` used to run `ausearch` over the whole audit log
  before stamping each event. As the log grew, events queued for seconds and were
  stamped ~2.5 s apart, so every 1-second window held exactly one event and the
  "faster than a human" signal disappeared from `canarylotp.csv`. Events are now
  stamped on arrival; the process lookup runs on a separate thread and reads only
  recent audit records.
- **Config paths** in `data/config.json` are relative to `data/`, so the repo works
  wherever it is cloned (absolute paths still work).
- **Story 2:** `place_canaries.py` creates real-format canaries and a hash baseline.
- **Story 5:** attack "modifications" used the same `edit_sample()` as normal work, so
  nothing looked encrypted, and most of each attack run was spent creating files at
  normal pace — all labelled as attack. Now each attack run first creates its victim
  files (unlabelled setup, followed by a 2 s pause), then the labelled attack
  overwrites them with random bytes (high entropy, like encryption), renames, copies
  and deletes. It only touches files the run created inside its own folder.
  Added a stealthier `partial_encrypt` pattern.
- **Story 6:** `collect_data.py` runs every pattern repeatedly with gaps between runs
  and builds the full 13-feature dataset. The builder now drops windows that belong to
  no run and allows a 0.5 s grace period at the end of each run.
