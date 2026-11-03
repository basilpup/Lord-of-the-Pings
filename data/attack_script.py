import json
import random
import shutil
import time
import uuid
from pathlib import Path

from normal_script import (ALL_EXTENSIONS, create_sample,  edit_sample, timestamp)

PROJECT = Path(__file__).resolve().parent
BASE_DIR = PROJECT / "lab-watch" / "attack_run"
MANIFEST_PATH = PROJECT / "datasets" / "raw" / "manifests" / "manifest.jsonl"
CONFIG_PATH = PROJECT / "config.json"

class ActivityPacer:
    """Vary activity timing to avoid identical event patterns."""

    def __init__(self):
        self.mode = random.choices(population=["slow", "mixed", "burst"], weights=[10, 30, 60], k=1)[0]

    def pause(self):
        if self.mode == "slow":
            time.sleep(random.uniform(1.0, 2.0))
        elif self.mode == "mixed":
            time.sleep(random.uniform(0.5, 1))
        else:
            time.sleep(random.uniform(0.02, 0.1))

def load_config():
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

def touch_canaries():
    """
    Simulate suspicious modifications to the configured canary files.
    """
    config = load_config()

    for raw_path in config["canary_paths"]:
        canary = Path(raw_path).resolve()

        if not canary.exists():
            canary.parent.mkdir(parents=True, exist_ok=True)
            canary.write_text("Lab canary file\n", encoding="utf-8")

        # Open in append mode (or write mode if binary/non-text)
        try:
            with canary.open("a", encoding="utf-8") as file:
                file.write(f"\nSIMULATED SUSPICIOUS MODIFICATION: {timestamp()}\n")
            print(f"Touched canary: {canary.name}")
        except Exception as e:
            # Fallback for binary files if opening as utf-8 fails
            with canary.open("ab") as file:
                file.write(b"\nSIMULATED SUSPICIOUS MODIFICATION\n")
            print(f"Touched binary canary: {canary.name}")

def create_attack_files(folder, count, extensions=None, pacer=None):
    """Create files inside the current attack run directory."""
    folder.mkdir(parents=True, exist_ok=True)

    if extensions is None:
        extensions = ALL_EXTENSIONS

    paths = []

    for _ in range(count):
        ext = random.choice(extensions)
        path = folder / f"attack_{uuid.uuid4().hex[:8]}{ext}"

        create_sample(path)
        paths.append(path)

        if pacer:
            pacer.pause()
    return paths


def modify_files(paths, pacer, passes=1):
    """Modify the supplied generated files one or more times."""
    for _ in range(passes):
        for path in paths:
            if path.exists():
                edit_sample(path)

            pacer.pause()


def copy_files(paths, destination, pacer):
    """Copy generated files into a subdirectory of the current run."""
    destination.mkdir(parents=True, exist_ok=True)
    copied_paths = []

    for path in paths:
        if path.exists():
            copied = destination / path.name
            shutil.copy2(path, copied)
            copied_paths.append(copied)

        pacer.pause()
    return copied_paths


def rename_to_simulated_locked(paths, pacer):
    """
    Rename generated files with a simulated locked suffix.
    This does not encrypt the file contents.
    """
    renamed_paths = []

    for path in paths:
        if not path.exists():
            continue

        new_path = path.with_name(path.name + ".locked-sim")
        path.rename(new_path)
        renamed_paths.append(new_path)
        pacer.pause()
    return renamed_paths


def delete_generated_files(paths, run_folder, pacer):
    """
    Delete only explicitly supplied generated files that are inside
    the current attack run folder.
    """
    run_root = run_folder.resolve()
    for path in paths:
        resolved_path = path.resolve()
        try:
            resolved_path.relative_to(run_root)
        except ValueError:
            raise ValueError(f"Refusing to delete a file outside this run: {resolved_path}")
        if resolved_path.is_file():
            resolved_path.unlink()
        pacer.pause()

def attack_burst(folder, pacer):
    paths = create_attack_files(folder, random.randint(20, 40), ALL_EXTENSIONS, pacer)
    modify_files(paths, pacer, passes=2)
    rename_to_simulated_locked(paths, pacer)

def attack_mass_rename(folder, pacer):
    paths = create_attack_files(folder, random.randint(12, 30), ALL_EXTENSIONS, pacer)
    rename_to_simulated_locked(paths, pacer)

def attack_repeated_modify(folder, pacer):
    paths = create_attack_files(folder, random.randint(8, 20), ALL_EXTENSIONS, pacer)
    modify_files(paths, pacer, passes=3)

def attack_copy_burst(folder, pacer):
    paths = create_attack_files(folder, random.randint(10, 25), ALL_EXTENSIONS, pacer)
    copied = copy_files(paths, folder / "copies", pacer)
    rename_to_simulated_locked(copied, pacer)

def attack_document_batch(folder, pacer):
    paths = create_attack_files(folder, random.randint(10, 25), [".docx", ".pdf", ".xlsx", ".csv"], pacer)

    modify_files(paths, pacer, passes=2)
    rename_to_simulated_locked(paths, pacer)

def attack_image_batch(folder, pacer):
    paths = create_attack_files(folder, random.randint(10, 25), [".jpg", ".png", ".pdf"], pacer)

    modify_files(paths, pacer, passes=2)
    rename_to_simulated_locked(paths, pacer)

def attack_config_batch(folder, pacer):
    paths = create_attack_files(folder, random.randint(10, 25), [".sql", ".conf", ".json", ".csv", ".pem"], pacer)

    modify_files(paths, pacer, passes=2)
    rename_to_simulated_locked(paths, pacer)

def attack_extension_change(folder, pacer):
    paths = create_attack_files(folder, random.randint(15, 30), ALL_EXTENSIONS, pacer)
    rename_to_simulated_locked(paths, pacer)

def attack_mixed_cleanup(folder, pacer):
    paths = create_attack_files(folder, random.randint(15, 30), ALL_EXTENSIONS, pacer)

    modify_files(paths, pacer, passes=2)

    # Copy files into a run-specific directory.
    copied = copy_files(paths, folder / "temporary_copies", pacer)

    # Delete only those copies created by this run.
    delete_generated_files(copied, folder, pacer)

    # Rename a selection of the original generated files.
    selected = random.sample(paths, min(len(paths), random.randint(4, 10)))

    rename_to_simulated_locked(selected, pacer)


def attack_canary_batch(folder, pacer):
    paths = create_attack_files(
        folder,
        random.randint(10, 25),
        ALL_EXTENSIONS,
        pacer
    )

    modify_files(paths, pacer, passes=2)
    rename_to_simulated_locked(paths, pacer)


PATTERNS = {
    "burst": attack_burst,
    "mass_rename": attack_mass_rename,
    "repeated_modify": attack_repeated_modify,
    "copy_burst": attack_copy_burst,
    "document_batch": attack_document_batch,
    "image_batch": attack_image_batch,
    "config_batch": attack_config_batch,
    "extension_change": attack_extension_change,
    "mixed_cleanup": attack_mixed_cleanup,
    "canary_batch": attack_canary_batch,
}


def record_run(run_id, start_ts, end_ts, label):
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "run_id": run_id,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "label": label
    }
    with MANIFEST_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def run_activity(name, pattern):
    run_id = f"attack_{name}_{uuid.uuid4().hex[:10]}"
    folder = BASE_DIR / name / run_id
    folder.mkdir(parents=True, exist_ok=True)

    pacer = ActivityPacer()
    start_ts = timestamp()
    print(f"\nStarting attack: {name}")
    print(f"Run ID: {run_id}")
    print(f"Timing mode: {pacer.mode}")
    pattern(folder, pacer)

    # Trigger canaries for all batch/destructive attacks or whenever appropriate
    if "batch" in name or "cleanup" in name or name == "canary_batch":
        touch_canaries()

    end_ts = timestamp()
    record_run(run_id, start_ts, end_ts, 1)

    print(f"Completed attack: {name}")


def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    for name, pattern in PATTERNS.items():
        run_activity(name, pattern)
    print("Attack completed.")

if __name__ == "__main__":
    main()
