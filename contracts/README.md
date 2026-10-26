# Story 0: shared contracts and sample files

Everything here is placeholder data for building against. The sample events are
synthetic log lines (no real file activity) and the model is a dummy.

| File | What it is | Contract |
|---|---|---|
| `config.json` | Watch root, canary paths, log paths, window settings | Shared config |
| `sample_events.jsonl` | 1,419 events across 14 runs | A: event log |
| `sample_dataset.csv` | 1,574 window rows built from the events above | B: dataset |
| `model.joblib`, `model_meta.json` | Dummy model (2-level decision tree) | C: model interface |
| `sample_manifest.jsonl` | One line per run: label, start, end, parameters | D: run manifest |
| `features.py` | Shared feature code used by Story 6 and Story 9 | A to B |
| `make_samples.py` | Regenerates all sample files | |
| `requirements.txt` | Pinned versions (a model file only loads under the same scikit-learn version) | |

## Who uses what

- **Story 3 (monitor):** write lines that look like `sample_events.jsonl` to `events_path`, flushing after each line.
- **Stories 4, 5, 10 (scripts):** act only inside `watch_root`; append one line per run to `manifest_path`.
- **Story 6 (dataset):** `features.build_dataset(events, manifest, out)`.
- **Stories 7 and 8 (model):** train on `sample_dataset.csv`, split by `run_id`; save `model.joblib` and `model_meta.json`.
- **Story 9 (service):** tail `events_path`; every `step_seconds` call `features.extract_features()` on the trailing window, then the model.

## Loading the model

```python
import json, joblib, pandas as pd
meta = json.load(open("model_meta.json"))
model = joblib.load("model.joblib")
row = pd.DataFrame([features], columns=meta["feature_columns"])
score = model.predict_proba(row)[0, 1]
alert = score >= meta["threshold"]
```

Changing any format here is a whole-group decision; bump `schema_version` when it happens.
