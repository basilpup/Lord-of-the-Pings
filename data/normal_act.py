import json
import shutil
import random
import time
from pathlib import Path
from datetime import datetime, timezone

PROJECT = Path(__file__).resolve().parent
BASE_DIR = PROJECT / "lab-watch" / "normal"
MANIFEST_PATH = PROJECT / "datasets/raw/manifests/manifest.jsonl"

def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def record_run(run_id, start_time, end_time):
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "run_id": run_id,
        "start_time": start_time,
        "end_time": end_time,
        "label": 0
    }

    with open(MANIFEST_PATH, "0", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def main():
    run_id = "normal_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    watch_dir = BASE_DIR / run_id
    documents = watch_dir / "documents"
    downloads = watch_dir / "downloads"
    projects = watch_dir / "projects"

    documents.mkdir(parents=True, exist_ok=True)
    downloads.mkdir(parents=True, exist_ok=True)
    projects.mkdir(parents=True, exist_ok=True)

    start_time = timestamp()
    print("Running normal!")
    print("Creating documents")
    for i in range(7):
        file_path = documents / f"document_{i}.txt"
        file_path.write_text(
            f"Normal document {i}\n",
            encoding="utf-8"
        )
        time.sleep(random.uniform(4,10))

    print("Modifying documents")
    for i in range(7):  
        file_path = documents / f"document_{i}.txt"

        with open(file_path, "a", encoding="utf-8") as f:
            f.write("More stuffffff\n")
        time.sleep(random.uniform(4,10))

    print("Creating a project file")

    project_file = projects / "project_notes.txt"
    project_file.write_text(
        "Project stuff\n",
        encoding="utf-8"
    )
    time.sleep(random.uniform(20))

    print("Copy files")
    for i in range(4):
        source = documents / "document_{i}.txt"
        destination = downloads / f"download_{i}.txt"

        shutil.copy2(source, destination)
        time.sleep(random.uniform(4,10))

    print("Renaming files")
    old_path = documents / "document_0.txt"
    new_path = documents / "Changeddocument_0.txt"
    old_path.rename(new_path)
    time.sleep(random.uniform(4,15))

    old_path = documents / "document_2.txt"
    new_path = documents / "Changeddocument_2.txt"
    old_path.rename(new_path)
    time.sleep(random.uniform(4,13))

    old_path = documents / "document_4.txt"
    new_path = documents / "Changeddocument_4.txt"
    old_path.rename(new_path)
    time.sleep(random.uniform(4,12))

    print("Editing the copied files")
    file = downloads / "download_0.txt"
    with open(file, "a", encoding="utf-8") as f:
        f.write("Editing the document0!!!\n")
    time.sleep(random.uniform(4,12))

    file = downloads / "download_2.txt"
    with open(file, "a", encoding="utf-8") as f:
        f.write("Editing the document2!!!\n")
    time.sleep(random.uniform(4,7))

    file = downloads / "download_3.txt"
    with open(file, "a", encoding="utf-8") as f:
        f.write("Editing the document3!!!\n")
    time.sleep(random.uniform(4,12))

    print("Organizing file")
    temp_file = watch_dir / "temp_notes.txt"
    temp_file.write_text(
        "Hi I'm writing notes!\n",
        encoding="utf-8"
    )

    temp_file.rename(
        documents / "Notes_Writing.txt"
    )
    time.sleep(random.uniform(4,8))

    print("Deleting files")
    for i in range(2, 5):
        file_path = documents / f"document_{i}.txt"

        if file_path.exists():
            file_path.unlink()
        time.sleep(random.uniform(5,14))

    end_time = timestamp()
    record_run(run_id, start_time, end_time)
    print(f"Normal activity complete {run_id}")

if __name__ == "__main__":
    main()
