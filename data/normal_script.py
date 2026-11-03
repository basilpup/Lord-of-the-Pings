
import csv
import json
import random
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from docx import Document
from openpyxl import Workbook, load_workbook
from PIL import Image, ImageDraw
from reportlab.pdfgen import canvas
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


PROJECT = Path(__file__).resolve().parent
BASE_DIR = PROJECT / "lab-watch" / "normal"
MANIFEST_PATH = PROJECT / "datasets" / "raw" / "manifests" / "manifest.jsonl"
CONFIG_PATH = PROJECT / "config.json"

ALL_EXTENSIONS = [
    ".txt", ".md", ".log", ".py", ".json",
    ".csv", ".docx", ".pdf", ".xlsx",
    ".sql", ".conf", ".jpg", ".png", ".pem"
]


def timestamp():
    """Return a UTC timestamp suitable for the run manifest."""
    return datetime.now(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def random_text(lines=None):
    if lines is None:
        lines = random.randint(3, 12)

    samples = [
        "Project notes for the current lab activity.",
        "The document contains ordinary sample information.",
        "Review the latest changes before saving the file.",
        "This is synthetic data created for a filesystem lab.",
        "The team discussed the next project milestone.",
        "Remember to check the results after the activity.",
        "A routine update was made to this sample document.",
        "The example file contains no personal information."
    ]

    return "\n".join(random.choice(samples) for _ in range(lines))


class ActivityPacer:
    """Vary activity timing to avoid identical event patterns."""

    def __init__(self):
        self.mode = random.choice(["slow", "mixed", "burst"])

    def pause(self):
        if self.mode == "slow":
            time.sleep(random.uniform(0.8, 2.0))
        elif self.mode == "burst":
            time.sleep(random.uniform(0.02, 0.2))
        else:
            time.sleep(random.uniform(0.2, 1.0))


def random_filename(prefix="sample"):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def random_file_count(minimum=3, maximum=10):
    return random.randint(minimum, maximum)


def create_pem(path):
    """Create a disposable, unencrypted test private key."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pem_data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    path.write_bytes(pem_data)


def create_sample(path):
    """Create a valid sample file based on its extension."""
    path.parent.mkdir(parents=True, exist_ok=True)
    ext = path.suffix.lower()

    if ext == ".docx":
        document = Document()
        document.add_heading("Sample Lab Document", level=1)
        document.add_paragraph(random_text())
        document.save(path)

    elif ext == ".pdf":
        pdf = canvas.Canvas(str(path))
        pdf.drawString(72, 750, "Sample Lab PDF")
        pdf.drawString(72, 720, "Synthetic filesystem activity data.")
        pdf.drawString(72, 690, random_text(lines=2)[:90])
        pdf.save()

    elif ext == ".xlsx":
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Sample Data"
        sheet.append(["Record", "Description", "Status"])
        sheet.append([1, "Initial sample record", "Open"])
        sheet.append([2, "Synthetic lab information", "Reviewed"])
        workbook.save(path)

    elif ext == ".csv":
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["record", "description", "status"])
            writer.writerow([1, "Initial sample record", "open"])
            writer.writerow([2, "Synthetic lab information", "reviewed"])

    elif ext in (".png", ".jpg"):
        image = Image.new(
            "RGB",
            (640, 400),
            color=(
                random.randint(180, 245),
                random.randint(180, 245),
                random.randint(180, 245)
            )
        )
        draw = ImageDraw.Draw(image)
        draw.rectangle((40, 40, 300, 180), outline="black", width=4)
        draw.text((50, 200), "Synthetic lab image", fill="black")

        image_format = "PNG" if ext == ".png" else "JPEG"
        image.save(path, format=image_format)

    elif ext == ".pem":
        create_pem(path)

    elif ext == ".json":
        data = {
            "project": "filesystem-lab",
            "created": timestamp(),
            "description": random_text(lines=2)
        }
        path.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8"
        )

    elif ext == ".sql":
        path.write_text(
            "CREATE TABLE sample_records (\n"
            "    id INTEGER PRIMARY KEY,\n"
            "    description TEXT\n"
            ");\n\n"
            "INSERT INTO sample_records VALUES "
            "(1, 'Synthetic lab record');\n",
            encoding="utf-8"
        )

    elif ext == ".conf":
        path.write_text(
            "project=filesystem-lab\n"
            "mode=sample\n"
            "enabled=true\n",
            encoding="utf-8"
        )

    elif ext == ".py":
        path.write_text(
            '"""Synthetic sample Python file."""\n\n'
            "def sample_function():\n"
            '    return "filesystem lab sample"\n',
            encoding="utf-8"
        )

    else:
        path.write_text(random_text(), encoding="utf-8")


def edit_sample(path):
    """Make a harmless edit appropriate to the file type."""
    ext = path.suffix.lower()

    if not path.exists():
        create_sample(path)
        return

    if ext == ".docx":
        document = Document(path)
        document.add_paragraph(
            f"Routine document update: {timestamp()}"
        )
        document.save(path)

    elif ext == ".pdf":
        # Recreate the sample PDF with updated content.
        pdf = canvas.Canvas(str(path))
        pdf.drawString(72, 750, "Updated Sample Lab PDF")
        pdf.drawString(72, 720, f"Routine update: {timestamp()}")
        pdf.drawString(72, 690, random_text(lines=2)[:90])
        pdf.save()

    elif ext == ".xlsx":
        workbook = load_workbook(path)
        sheet = workbook.active
        sheet.append([
            sheet.max_row,
            f"Routine update: {timestamp()}",
            "Updated"
        ])
        workbook.save(path)

    elif ext in (".png", ".jpg"):
        image = Image.open(path).convert("RGB")
        draw = ImageDraw.Draw(image)
        x1 = random.randint(20, 400)
        y1 = random.randint(20, 250)
        draw.rectangle(
            (x1, y1, x1 + 80, y1 + 50),
            outline="black",
            width=4
        )
        image.save(path, format="PNG" if ext == ".png" else "JPEG")

    elif ext == ".pem":
        # Replace only the disposable test key.
        create_pem(path)

    else:
        with path.open("a", encoding="utf-8") as file:
            file.write(
                f"\nRoutine sample update: {timestamp()}\n"
            )


def make_files(folder, count=None, extensions=None, pacer=None):
    folder.mkdir(parents=True, exist_ok=True)

    if count is None:
        count = random_file_count()

    if extensions is None:
        extensions = ALL_EXTENSIONS

    paths = []

    for _ in range(count):
        ext = random.choice(extensions)
        path = folder / f"{random_filename()}{ext}"
        create_sample(path)
        paths.append(path)

        if pacer:
            pacer.pause()

    return paths


def edit_selection(paths, pacer=None, fraction=1.0):
    selected = list(paths)

    if fraction < 1.0:
        amount = max(1, int(len(selected) * fraction))
        selected = random.sample(selected, min(amount, len(selected)))

    for path in selected:
        edit_sample(path)

        if pacer:
            pacer.pause()


def touch_normal_canaries():
    """Perform harmless, routine interactions with configured canaries."""
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    watch_root = Path(config["watch_root"]).resolve()

    for raw_path in config["canary_paths"]:
        canary = Path(raw_path).resolve()

        try:
            canary.relative_to(watch_root)
        except ValueError:
            raise ValueError(
                f"Canary path is outside watch_root: {canary}"
            )

        if not canary.exists():
            canary.parent.mkdir(parents=True, exist_ok=True)
            canary.write_text(
                "Lab canary file\n",
                encoding="utf-8"
            )

        # Ordinary read followed by an ordinary note.
        canary.read_text(encoding="utf-8", errors="replace")

        with canary.open("a", encoding="utf-8") as file:
            file.write(
                f"\nRoutine lab note: {timestamp()}\n"
            )

        print(f"Normal activity touched canary: {canary.name}")


# ---------------------------------------------------------
# NORMAL ACTIVITY PATTERNS
# ---------------------------------------------------------

def normal_documents(folder, pacer):
    paths = make_files(
        folder,
        random_file_count(4, 10),
        [".txt", ".md", ".docx", ".pdf"],
        pacer
    )
    edit_selection(paths, pacer, fraction=0.5)


def normal_csv(folder, pacer):
    paths = make_files(
        folder,
        random_file_count(3, 8),
        [".csv", ".xlsx"],
        pacer
    )
    edit_selection(paths, pacer, fraction=0.7)


def normal_folders(folder, pacer):
    for subfolder_number in range(random.randint(3, 6)):
        subfolder = folder / f"folder_{subfolder_number}"
        make_files(
            subfolder,
            random_file_count(2, 5),
            [".txt", ".md", ".pdf", ".csv"],
            pacer
        )


def normal_copy_move(folder, pacer):
    source = folder / "source"
    destination = folder / "organized"

    paths = make_files(
        source,
        random_file_count(4, 9),
        [".txt", ".pdf", ".docx", ".csv"],
        pacer
    )

    destination.mkdir(parents=True, exist_ok=True)

    for path in paths:
        shutil.copy2(path, destination / path.name)
        pacer.pause()

    # Move a selection of copied files into another folder.
    moved = folder / "moved"
    moved.mkdir(parents=True, exist_ok=True)

    copied_files = list(destination.iterdir())
    for path in random.sample(
        copied_files,
        min(len(copied_files), random.randint(1, 3))
    ):
        shutil.move(str(path), str(moved / path.name))
        pacer.pause()


def normal_rename(folder, pacer):
    paths = make_files(
        folder,
        random_file_count(4, 10),
        [".txt", ".md", ".csv", ".pdf"],
        pacer
    )

    for path in paths:
        new_path = path.with_name(
            f"renamed_{uuid.uuid4().hex[:6]}{path.suffix}"
        )
        path.rename(new_path)
        pacer.pause()


def normal_code(folder, pacer):
    paths = make_files(
        folder,
        random_file_count(4, 9),
        [".py", ".json", ".sql", ".conf", ".md"],
        pacer
    )
    edit_selection(paths, pacer, fraction=0.6)


def normal_downloads(folder, pacer):
    download_folder = folder / "downloads"

    paths = make_files(
        download_folder,
        random_file_count(5, 12),
        [".pdf", ".jpg", ".png", ".docx", ".xlsx", ".txt"],
        pacer
    )

    # Some downloaded files are reviewed and modified.
    edit_selection(paths, pacer, fraction=0.3)


def normal_mixed(folder, pacer):
    paths = make_files(
        folder,
        random_file_count(8, 16),
        ALL_EXTENSIONS,
        pacer
    )

    edit_selection(paths, pacer, fraction=0.4)

    # Copy a few files into an archive folder.
    archive = folder / "archive"
    archive.mkdir(parents=True, exist_ok=True)

    for path in random.sample(
        paths,
        min(len(paths), random.randint(2, 4))
    ):
        shutil.copy2(path, archive / path.name)
        pacer.pause()


def normal_pdf_png(folder, pacer):
    paths = make_files(
        folder,
        random_file_count(5, 10),
        [".pdf", ".png", ".jpg"],
        pacer
    )
    edit_selection(paths, pacer, fraction=0.5)


def normal_extended_formats(folder, pacer):
    paths = make_files(
        folder,
        random_file_count(6, 12),
        [".sql", ".conf", ".json", ".csv", ".pem", ".py"],
        pacer
    )
    edit_selection(paths, pacer, fraction=0.4)


PATTERNS = {
    "documents": normal_documents,
    "csv": normal_csv,
    "folders": normal_folders,
    "copy_move": normal_copy_move,
    "rename": normal_rename,
    "code": normal_code,
    "downloads": normal_downloads,
    "mixed": normal_mixed,
    "pdf_png": normal_pdf_png,
    "extended_formats": normal_extended_formats,
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
    run_id = f"normal_{name}_{uuid.uuid4().hex[:10]}"
    folder = BASE_DIR / name / run_id
    folder.mkdir(parents=True, exist_ok=True)

    pacer = ActivityPacer()
    start_ts = timestamp()

    print(f"\nStarting normal pattern: {name}")
    print(f"Run ID: {run_id}")
    print(f"Timing mode: {pacer.mode}")

    pattern(folder, pacer)

    # Only selected normal patterns interact with canaries.
    if name in ("folders", "mixed"):
        touch_normal_canaries()

    end_ts = timestamp()
    record_run(run_id, start_ts, end_ts, 0)

    print(f"Completed normal pattern: {name}")


def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    for name, pattern in PATTERNS.items():
        run_activity(name, pattern)

    print("\nAll normal activity patterns completed.")


if __name__ == "__main__":
    main()
