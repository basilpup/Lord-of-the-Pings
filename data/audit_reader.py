import ast
import re
import subprocess
from pathlib import Path

AUDIT_KEY = "file_lab"
MATCH_TOLERANCE_SECONDS = 3.0

# Patterns for extracting audit record information.
HEADER_PATTERN = re.compile(
    r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)"
)

FIELD_PATTERNS = {
    "pid": re.compile(r"\bpid=(\d+)"),
    "process_name": re.compile(r'\bcomm=("(?:\\.|[^"])*"|\S+)'),
    "exe": re.compile(r'\bexe=("(?:\\.|[^"])*"|\S+)'),
    "name": re.compile(r'\bname=("(?:\\.|[^"])*"|\S+)'),
}


def extract_field(pattern, text):
    """Gets the first matching field from an audit record."""
    match = pattern.search(text)

    if not match:
        return None

    value = match.group(1)

    if value.startswith('"'):
        try:
            value = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            value = value.strip('"')

    return value


def read_audit_events():
    """Reads and groups audit records by event ID."""

    result = subprocess.run(
        ["ausearch", "-k", AUDIT_KEY, "--raw"],
        capture_output=True,
        text=True,
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Couldn't read audit records: {result.stderr.strip()}"
        )

    events = {}

    for line in result.stdout.splitlines():

        header = HEADER_PATTERN.search(line)

        if not header:
            continue

        timestamp = float(header.group(1))
        serial = header.group(2)

        event_id = (timestamp, serial)

        if event_id not in events:
            events[event_id] = {
                "timestamp": timestamp,
                "pid": None,
                "process_name": None,
                "exe": None,
                "paths": []
            }

        event = events[event_id]

        if line.startswith("type=SYSCALL"):

            event["pid"] = extract_field(
                FIELD_PATTERNS["pid"], line
            )

            event["process_name"] = extract_field(
                FIELD_PATTERNS["process_name"], line
            )

            event["exe"] = extract_field(
                FIELD_PATTERNS["exe"], line
            )

        elif line.startswith("type=PATH"):

            name = extract_field(
                FIELD_PATTERNS["name"], line
            )

            if name and name not in event["paths"]:
                event["paths"].append(name)

    return list(events.values())


def find_process_for_path(path, event_timestamp):
    """Finds the closest audit event matching a watchdog file event."""

    target_path = str(Path(path).resolve())

    audit_events = read_audit_events()
    matches = []

    for event in audit_events:

        if target_path not in event["paths"]:
            continue

        if event["pid"] is None:
            continue

        difference = abs(
            event["timestamp"] - event_timestamp
        )

        if difference <= MATCH_TOLERANCE_SECONDS:
            matches.append((difference, event))

    if not matches:
        return None

    matches.sort(key=lambda item: item[0])

    best_match = matches[0][1]

    return {
        "pid": int(best_match["pid"]),
        "process_name": best_match["process_name"],
        "exe": best_match["exe"]
    }
