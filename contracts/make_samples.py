"""Generates the placeholder files. Synthetic log lines only: no real file
activity happens. Rerun to regenerate: python make_samples.py"""
import json, random, os
from features import format_ts, build_dataset, FEATURE_COLUMNS

random.seed(7)
cfg = json.load(open("config.json"))
ROOT = cfg["watch_root"]; CANARY = cfg["canary_paths"]
NORMAL = [f"{ROOT}/Documents/{n}" for n in
          ["notes.txt", "report_q3.docx", "budget.xlsx", "todo.md", "slides.pptx",
           "letter.docx", "draft.txt", "invoice_114.pdf"]] + \
         [f"{ROOT}/projects/site/{n}" for n in ["index.html", "app.py", "style.css", "README.md"]] + \
         [f"{ROOT}/Pictures/img_{i:03d}.jpg" for i in range(1, 31)] + \
         [f"{ROOT}/Downloads/file_{i:02d}.pdf" for i in range(1, 21)]
ALL = NORMAL + CANARY
BENIGN_PROCS = [(2114, "soffice.bin"), (3320, "code"), (1877, "nautilus"), (4051, "gedit")]
LOW_ENT = {".txt": 4.3, ".md": 4.4, ".py": 4.6, ".html": 4.8, ".css": 4.5, ".csv": 4.9,
           ".sql": 5.0, ".conf": 4.7, ".pem": 6.0, ".docx": 7.6, ".xlsx": 7.5, ".pptx": 7.7,
           ".pdf": 7.4, ".jpg": 7.9}

def ext(p):
    b = os.path.basename(p)
    return "." + b.rsplit(".", 1)[1] if "." in b.strip(".") else ""

events, manifest = [], []
def ev(t, op, path, old_path=None, size=None, entropy=None, proc=(None, None), canary=None):
    events.append({
        "ts": format_ts(t), "op": op, "path": path, "old_path": old_path,
        "ext": ext(path), "old_ext": ext(old_path) if old_path else None,
        "is_canary": (path in CANARY or old_path in CANARY) if canary is None else canary,
        "size_bytes": None if op == "delete" else size,
        "entropy": None if op == "delete" else entropy,
        "pid": proc[0], "process_name": proc[1]})

def benign(t0, duration, intensity):
    """Human-speed edits, saves, occasional renames/deletes."""
    t = t0
    while True:
        t += random.expovariate(intensity)
        if t > t0 + duration: break
        p = random.choice(NORMAL if random.random() < 0.97 else CANARY)
        proc = random.choice(BENIGN_PROCS)
        size = random.randint(2_000, 900_000)
        e = round(LOW_ENT.get(ext(p), 5.0) + random.uniform(-0.2, 0.1), 3)
        r = random.random()
        if r < 0.55:                       # plain save
            ev(t, "modify", p, size=size, entropy=e, proc=proc)
        elif r < 0.80:                     # atomic save via temp file (benign ext change)
            tmp = p + ".tmp"
            ev(t, "create", tmp, size=0, entropy=0.0, proc=proc, canary=False)
            ev(t + 0.012, "modify", tmp, size=size, entropy=e, proc=proc, canary=False)
            ev(t + 0.031, "rename", p, old_path=tmp, size=size, entropy=e, proc=proc)
        elif r < 0.90:                     # new file
            n = f"{ROOT}/Documents/untitled_{random.randint(1, 99)}.txt"
            ev(t, "create", n, size=0, entropy=0.0, proc=proc)
        elif r < 0.96:                     # rename, same extension
            d, b = os.path.split(p)
            ev(t, "rename", f"{d}/old_{b}", old_path=p, size=size, entropy=e, proc=proc)
        else:
            ev(t, "delete", f"{ROOT}/Downloads/tmp_{random.randint(1, 99)}.pdf", proc=proc)
    return t0 + duration

def attack(t0, rate, pattern, scope, null_proc=False):
    """Bulk activity; pattern in encrypt_rename | rename_only | replace."""
    t = t0
    proc = (None, None) if null_proc else (random.randint(6000, 9000), "python3")
    files = random.sample(ALL, k=min(scope, len(ALL)))
    for p in files:
        size = random.randint(2_000, 900_000)
        hi = round(random.uniform(7.90, 7.999), 3)
        t += random.expovariate(rate)
        if pattern == "encrypt_rename":
            ev(t, "modify", p, size=size, entropy=hi, proc=proc)
            t += random.expovariate(rate)
            ev(t, "rename", p + ".locked", old_path=p, size=size, entropy=hi, proc=proc)
        elif pattern == "rename_only":
            ev(t, "rename", p + ".enc", old_path=p, size=size,
               entropy=round(LOW_ENT.get(ext(p), 5.0), 3), proc=proc)
        else:
            ev(t, "create", p + ".crypt", size=size, entropy=hi, proc=proc, canary=False)
            t += random.expovariate(rate)
            ev(t, "delete", p, proc=proc)
    return t

def record(run_id, script, label, s, e, params):
    manifest.append({"run_id": run_id, "script": script, "label": label,
                     "start_ts": format_ts(s), "end_ts": format_ts(e), "params": params})

T = 1791212400.0   # 2026-10-05T15:00:00Z
plan = [("b", 120, 0.3), ("a", 40, "encrypt_rename", 45, False), ("b", 150, 0.5),
        ("a", 150, "rename_only", 70, False), ("b", 120, 0.2), ("a", 15, "encrypt_rename", 30, True),
        ("b", 180, 0.8), ("a", 80, "replace", 60, False), ("b", 120, 0.4),
        ("a", 300, "encrypt_rename", 70, False), ("b", 150, 0.6), ("a", 25, "replace", 40, False)]
nb = na = 0
for step in plan:
    if step[0] == "b":
        nb += 1; end = benign(T, step[1], step[2])
        record(f"benign_{nb:02d}", "sample_benign", 0, T, end,
               {"duration_s": step[1], "events_per_s": step[2]})
    else:
        na += 1; end = attack(T, *step[1:])
        record(f"attack_{na:02d}", "sample_attack", 1, T, end,
               {"events_per_s": step[1], "pattern": step[2], "files": step[3]})
    T = end + 5.0
# edge case: an attack that overlaps a benign run
nb += 1; b_end = benign(T, 90, 0.5)
record(f"benign_{nb:02d}", "sample_benign", 0, T, b_end, {"duration_s": 90, "events_per_s": 0.5})
na += 1; a_end = attack(T + 40, 60, "encrypt_rename", 40)
record(f"attack_{na:02d}", "sample_attack", 1, T + 40, a_end,
       {"events_per_s": 60, "pattern": "encrypt_rename", "files": 40, "note": "overlaps benign run"})

events.sort(key=lambda e: e["ts"])
with open("sample_events.jsonl", "w") as f:
    for e in events: f.write(json.dumps(e) + "\n")
with open("sample_manifest.jsonl", "w") as f:
    for m in manifest: f.write(json.dumps(m) + "\n")
rows = build_dataset("sample_events.jsonl", "sample_manifest.jsonl", "sample_dataset.csv",
                     cfg["window_seconds"], cfg["step_seconds"])

# placeholder model: a 2-level decision tree, i.e. a simple rule in a real model file
import pandas as pd, joblib, sklearn, sys
from sklearn.tree import DecisionTreeClassifier, export_text
df = pd.read_csv("sample_dataset.csv")
m = DecisionTreeClassifier(max_depth=2, random_state=0).fit(df[FEATURE_COLUMNS], df["label"])
joblib.dump(m, "model.joblib")
json.dump({"schema_version": 1, "placeholder": True,
           "note": "Dummy model trained on synthetic sample data. For wiring and testing only.",
           "feature_columns": FEATURE_COLUMNS, "threshold": 0.5,
           "window_seconds": cfg["window_seconds"], "step_seconds": cfg["step_seconds"],
           "python_version": sys.version.split()[0], "sklearn_version": sklearn.__version__},
          open("model_meta.json", "w"), indent=2)
print(len(events), "events;", len(manifest), "runs;", rows, "rows;", dict(df.label.value_counts()))
print(export_text(m, feature_names=FEATURE_COLUMNS))
print("train acc", m.score(df[FEATURE_COLUMNS], df["label"]))
