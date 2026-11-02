import json
import shutil
import time
from pathlib import Path
from datetime import datetime, timezone

PROJECT = Path(__file__).resolve().parent
BASE_DIR = PROJECT / "lab-watch" / "attack_run"
MANIFEST_PATH = PROJECT / "datasets/raw/manifests/manifest.jsonl"

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

def main():
    run_id = "attack_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    watch_dir = BASE_DIR / run_id
    files_dir = watch_dir / "files"
    copies_dir = watch_dir / "copies"

    files_dir.mkdir(parents=True, exist_ok=True)
    copies_dir.mkdir(parents=True, exist_ok=True)

    start_time = timestamp()

    print("Running attack!")
    print("Bulk files")

    files = []

    for i in range(25):
        file_path = files_dir / f"sample_{i}.txt"

        file_path.write_text(
            f"Sample file {i}.\n",
            encoding="utf-8"
        )

        files.append(file_path)
        time.sleep(0.1)

    print("File modifications")
    for repetition in range(3):
        for file_path in files:
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(
                    f"Mod: {repetition}.\n"
                )

    print("Extra files")
    for i in range(15):
        file_path = files_dir / f"extra_{i}.txt"

        file_path.write_text(
            "Extra stuff\n",
            encoding="utf-8"
        )

    print("File copying")
    for i in range(10):
        source = files_dir / f"sample_{i}.txt"
        destination = copies_dir / f"copy_{i}.txt"
        shutil.copy2(source, destination)


    print("Renaming")
    renamed_files = []

    for i, file_path in enumerate(files[:20]):
        new_path = file_path.with_name(
            f"renamed_{i}.txt"
        )
        file_path.rename(new_path)
        renamed_files.append(new_path)

    print("Extension changes")
    changed_files = []
    for file_path in renamed_files:
        new_path = file_path.with_suffix(".locked-sim")
        file_path.rename(new_path)
        changed_files.append(new_path)


    print("Modifying renamed files")
    for file_path in changed_files:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write("Additional simulated test activity.\n")


    print("Bulk deletion")
    for file_path in changed_files[:10]:
        if file_path.exists():
            file_path.unlink()

    for i in range(5):
        copy_path = copies_dir / f"copy_{i}.txt"

        if copy_path.exists():
            copy_path.unlink()

    end_time = timestamp()

    record_run(run_id, start_time, end_time)
    print(f"Attack activity complete {run_id}")

if __name__ == "__main__":
    main()
