import json
import os
import random
import shutil
import time
import uuid
from pathlib import Path

from normal_script import ALL_EXTENSIONS, create_sample, timestamp

from config_paths import PROJECT, load_config

CONFIG = load_config()
BASE_DIR = Path(CONFIG["watch_root"]) / "attack_run"
MANIFEST_PATH = Path(CONFIG["manifest_path"])

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

def create_victim_files(folder, count, extensions=None):
    """Setup, NOT part of the attack: create the 'user files' the attack will hit.
    Real ransomware finds files that already exist, so this runs quickly and
    before the run's start_ts is recorded (those windows are not labelled)."""
    folder.mkdir(parents=True, exist_ok=True)
    if extensions is None:
        extensions = ALL_EXTENSIONS
    paths = []
    for _ in range(count):
        path = folder / f"file_{uuid.uuid4().hex[:8]}{random.choice(extensions)}"
        create_sample(path)
        paths.append(path)
    return paths


def simulate_encrypt(path):
    """Overwrite a generated lab file with random bytes of the same size.
    This mimics the high-entropy output of encryption. It only ever touches
    files this run created inside its own run folder; nothing is recoverable
    or needs to be, and no key exists."""
    size = max(path.stat().st_size, 1024)
    path.write_bytes(os.urandom(size))


def modify_files(paths, pacer, passes=1):
    """'Encrypt' the supplied generated files one or more times."""
    for _ in range(passes):
        for path in paths:
            if path.exists():
                simulate_encrypt(path)
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

# Each pattern = (number of victim files, their extensions, what the attack does).
# The victim files are created during setup; only the action is labelled as attack.

def attack_burst(paths, folder, pacer):
    modify_files(paths, pacer, passes=2)
    rename_to_simulated_locked(paths, pacer)

def attack_mass_rename(paths, folder, pacer):
    rename_to_simulated_locked(paths, pacer)

def attack_repeated_modify(paths, folder, pacer):
    modify_files(paths, pacer, passes=3)

def attack_copy_burst(paths, folder, pacer):
    # Write encrypted copies, then remove the originals (common ransomware style).
    copied = copy_files(paths, folder / "copies", pacer)
    modify_files(copied, pacer)
    rename_to_simulated_locked(copied, pacer)
    delete_generated_files(paths, folder, pacer)

def attack_encrypt_rename(paths, folder, pacer):
    modify_files(paths, pacer)
    rename_to_simulated_locked(paths, pacer)

def attack_extension_change(paths, folder, pacer):
    rename_to_simulated_locked(paths, pacer)

def attack_mixed_cleanup(paths, folder, pacer):
    modify_files(paths, pacer)
    copied = copy_files(paths, folder / "temporary_copies", pacer)
    delete_generated_files(copied, folder, pacer)
    selected = random.sample(paths, min(len(paths), random.randint(4, 10)))
    rename_to_simulated_locked(selected, pacer)

def attack_partial_encrypt(paths, folder, pacer):
    # Stealthier: encrypt only a subset, no renames.
    modify_files(random.sample(paths, max(1, len(paths) // 3)), pacer)


DOCS = [".docx", ".pdf", ".xlsx", ".csv"]
IMAGES = [".jpg", ".png", ".pdf"]
CONFIGS = [".sql", ".conf", ".json", ".csv", ".pem"]

PATTERNS = {
    "burst":            ((20, 40), ALL_EXTENSIONS, attack_burst),
    "mass_rename":      ((12, 30), ALL_EXTENSIONS, attack_mass_rename),
    "repeated_modify":  ((8, 20),  ALL_EXTENSIONS, attack_repeated_modify),
    "copy_burst":       ((10, 25), ALL_EXTENSIONS, attack_copy_burst),
    "document_batch":   ((10, 25), DOCS,           attack_encrypt_rename),
    "image_batch":      ((10, 25), IMAGES,         attack_encrypt_rename),
    "config_batch":     ((10, 25), CONFIGS,        attack_encrypt_rename),
    "extension_change": ((15, 30), ALL_EXTENSIONS, attack_extension_change),
    "mixed_cleanup":    ((15, 30), ALL_EXTENSIONS, attack_mixed_cleanup),
    "canary_batch":     ((10, 25), ALL_EXTENSIONS, attack_encrypt_rename),
    "partial_encrypt":  ((15, 30), ALL_EXTENSIONS, attack_partial_encrypt),
}


def record_run(run_id, start_ts, end_ts, label, **extra):
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {"run_id": run_id, "start_ts": start_ts, "end_ts": end_ts, "label": label, **extra}
    with MANIFEST_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


SETUP_QUIET_SECONDS = 2.0   # > window_seconds, so setup and attack never share a window


def run_activity(name, pattern):
    (low, high), extensions, action = pattern
    run_id = f"attack_{name}_{uuid.uuid4().hex[:10]}"
    folder = BASE_DIR / name / run_id

    # Setup (unlabelled): the victim's existing files.
    paths = create_victim_files(folder, random.randint(low, high), extensions)
    time.sleep(SETUP_QUIET_SECONDS)

    pacer = ActivityPacer()
    start_ts = timestamp()
    print(f"\nStarting attack: {name}")
    print(f"Run ID: {run_id}")
    print(f"Timing mode: {pacer.mode}")
    action(paths, folder, pacer)

    # Trigger canaries for all batch/destructive attacks
    if "batch" in name or "cleanup" in name:
        touch_canaries()

    end_ts = timestamp()
    record_run(run_id, start_ts, end_ts, 1, script="attack_script", pattern=name,
               timing=pacer.mode, files=len(paths))
    print(f"Completed attack: {name}")


def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    for name, pattern in PATTERNS.items():
        run_activity(name, pattern)
    print("Attack completed.")

if __name__ == "__main__":
    main()
