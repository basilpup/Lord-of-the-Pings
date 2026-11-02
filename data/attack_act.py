import json
import shutil
import time
import random
from pathlib import Path
from datetime import datetime, timezone

PROJECT = Path(__file__).resolve().parent
BASE_DIR = PROJECT / "lab-watch" / "attack_run"
MANIFEST_PATH = PROJECT / "datasets/raw/manifests/manifest.jsonl"

FILE_TYPES = [
    ".txt",
    ".csv",
    ".json",
    ".md",
    ".py",
    ".html",
    ".log",
    ".pdf",
    ".docx",
    ".xlsx",
    ".jpg",
    ".png"
]

def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def record_run(run_id, start_time, end_time):
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "run_id": run_id,
        "start_ts": start_time,
        "end_ts": end_time,
        "label": 1
    }
    with open(MANIFEST_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def create_dummy_file(folder, filename):
    extension = random.choice(FILE_TYPES)
    file_path = folder / f"{filename}{extension}"
    file_path.write_text(
        f"Simulated suspicious activity content for {filename}\n",
        encoding="utf-8"
    )
    return file_path

def main():
    run_id = "attack_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    watch_dir = BASE_DIR / run_id
    files_dir = watch_dir / "files"
    copies_dir = watch_dir / "copies"

    start_ts = timestamp()
    files_dir.mkdir(parents=True, exist_ok=True)
    copies_dir.mkdir(parents=True, exist_ok=True)

    print("Running attack!")
    print("Bulk files")

    act_files = []

    for i in range(25):
        file_path = create_dummy_file(files_dir, f"sample_{i}")
        act_files.append(file_path)
        time.sleep(random.uniform(0.01, 0.4))

    print("File modifications")
    for repetition in range(3):
        for file_path in act_files:
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(f"Mod: {repetition}\n")
            time.sleep(random.uniform(0.01, 0.4))

    print("Extra files")
    for i in range(15):
        create_dummy_file(files_dir, f"extra_{i}")
        time.sleep(random.uniform(0.01, 0.4))

    print("File copying")
    copied_files = []
    for i in range(10):
        source = act_files[i]
        destination = copies_dir / f"copy_{i}{source.suffix}"
        shutil.copy2(source, destination)
        copied_files.append(destination)
        time.sleep(random.uniform(0.01, 0.4))

    print("Renaming")
    renamed_files = []
    for i, file_path in enumerate(act_files[:20]):
        new_path = file_path.with_name(
            f"renamed_{i}{file_path.suffix}"
        )
        file_path.rename(new_path)
        renamed_files.append(new_path)
        time.sleep(random.uniform(0.01, 0.4))

    print("Extension changes")
    changed_files = []
    for file_path in renamed_files:
        new_path = file_path.with_name(file_path.name + ".locked-sim")
        file_path.rename(new_path)
        changed_files.append(new_path)
        time.sleep(random.uniform(0.01, 0.4))

    print("Modifying renamed files")
    for file_path in changed_files:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write("Adding evil\n")
        time.sleep(random.uniform(0.01, 0.2))

    print("Bulk deletion")
    for file_path in changed_files[:10]:
        if file_path.exists():
            file_path.unlink()
        time.sleep(random.uniform(0.05, 0.2))
    for file_path in copied_files[:5]:
        if file_path.exists():
            file_path.unlink()
        time.sleep(random.uniform(0.05, 0.2))
    end_ts = timestamp()

    record_run(run_id, start_ts, end_ts)
    print(f"Attack activity complete {run_id}")

if __name__ == "__main__":
    main()
