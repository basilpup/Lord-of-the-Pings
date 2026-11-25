import json
import shutil
import random
import time
from pathlib import Path
from datetime import datetime, timezone

PROJECT = Path(__file__).resolve().parent
BASE_DIR = PROJECT / "lab-watch" / "normal"
MANIFEST_PATH = PROJECT / "datasets/raw/manifests/manifest.jsonl"

FILE_TYPES = [
    ".txt",
    ".csv",
    ".json",
    ".md",
    ".py",
    ".log",
]

def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def record_run(run_id, start_time, end_time):
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "run_id": run_id,
        "start_ts": start_time,
        "end_ts": end_time,
        "label": 0
    }

    with open(MANIFEST_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def create_dummy_file(folder, filename):
    extension = random.choice(FILE_TYPES)
    file_path = folder / f"{filename}{extension}"
    file_path.write_text(
        f"Normal activity content for {filename}\n",
        encoding="utf-8"
    )
    return file_path

def main():
    run_id = "normal_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    watch_dir = BASE_DIR / run_id
    documents = watch_dir / "documents"
    downloads = watch_dir / "downloads"
    projects = watch_dir / "projects"

    start_ts = timestamp()
    documents.mkdir(parents=True, exist_ok=True)
    downloads.mkdir(parents=True, exist_ok=True)
    projects.mkdir(parents=True, exist_ok=True)

    print("Running normal!")
    print("Creating documents")
    created_files = []
    for i in range(15):
        file_path = create_dummy_file(documents, f"document_{i}")
        created_files.append(file_path)
        time.sleep(random.uniform(4,10))

    print("Modifying documents")
    for file_path in created_files:  
        with open(file_path, "a", encoding="utf-8") as f:
            f.write("Writing more stuff\n")
        time.sleep(random.uniform(4,10))

    print("Creating a project file")

    project_file = projects / "project_notes.txt"
    project_file.write_text(
        "Project stuff\n",
        encoding="utf-8"
    )
    time.sleep(random.uniform(4,10))

    print("Copy files")
    copied_files = []
    for i in range(8):
        source = created_files[i]
        destination = downloads / f"download_{i}{source.suffix}"

        shutil.copy2(source, destination)
        copied_files.append(destination)
        time.sleep(random.uniform(4,10))

    print("Renaming files")
    renamed_files = []
    for i in [1, 3, 5]:
        old_path = created_files[i]
        new_path = old_path.with_name(f"Chaging{old_path.name}")
        old_path.rename(new_path)
        created_files[i] = new_path
        renamed_files.append(new_path)
        time.sleep(random.uniform(4,15))

    print("Editing the copied files")
    for file_path in [copied_files[1], copied_files[3], copied_files[5]]:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write("Editing...\n")
        time.sleep(random.uniform(4,8))

    print("Deleting files")
    for file_path in created_files[2:5]:
        if file_path.exists():
            file_path.unlink()
        time.sleep(random.uniform(5,14))

    end_ts = timestamp()
    record_run(run_id, start_ts, end_ts)
    print(f"Normal activity complete {run_id}")

if __name__ == "__main__":
    main()
