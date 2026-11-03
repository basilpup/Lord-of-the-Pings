import ast
import re
import subprocess
from pathlib import Path

AUDIT_KEY = "file_lab"
MATCH_TOLERANCE_SECONDS = 3.0


# Matches the timestamp and serial number in an audit event.
# Example: msg=audit(1793650000.123:456)
HEADER_PATTERN = re.compile(
    r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)"
)


# Patterns for extracting fields from audit records.
FIELD_PATTERNS = {
    "pid": re.compile(r"\bpid=(\d+)"),
    "process_name": re.compile(
        r'\bcomm=("(?:\\.|[^"])*"|\S+)'
    ),
    "exe": re.compile(
        r'\bexe=("(?:\\.|[^"])*"|\S+)'
    ),
    "name": re.compile(
        r'\bname=("(?:\\.|[^"])*"|\S+)'
    ),
}


def extract_field(pattern, text):
    """Extracts the first matching field from an audit record."""

    match = pattern.search(text)

    if not match:
        return None

    value = match.group(1)

    # Decode quoted values, including escaped characters.
    if value.startswith('"'):
        try:
            value = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            value = value.strip('"')

    return value


def read_audit_events():
    """
    Reads audit records using ausearch and groups records
    by their timestamp and serial number.
    """

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

        # Extract the audit event ID.
        header = HEADER_PATTERN.search(line)

        if not header:
            continue

        timestamp = float(header.group(1))
        serial = header.group(2)

        event_id = (timestamp, serial)

        # Create a new event if it has not been seen before.
        if event_id not in events:
            events[event_id] = {
                "timestamp": timestamp,
                "serial": serial,
                "pid": None,
                "process_name": None,
                "exe": None,
                "paths": []
            }

        event = events[event_id]

        # Extract process information from SYSCALL records.
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

        # Extract filenames from PATH records.
        elif line.startswith("type=PATH"):

            name = extract_field(
                FIELD_PATTERNS["name"], line
            )

            if name and name not in event["paths"]:
                event["paths"].append(name)

    return list(events.values())


def find_process_for_path(path, event_timestamp):
    """
    Finds the closest audit event matching a watchdog file event.
    Returns process information or None if no match is found.
    """

    target_path = str(Path(path).resolve())

    audit_events = read_audit_events()

    matches = []

    for event in audit_events:

        # Check whether the audit event contains this file path.
        matching_path = False

        for audit_path in event["paths"]:
            if str(Path(audit_path).resolve()) == target_path:
                matching_path = True
                break

        if not matching_path:
            continue

        # A PID is required for a useful process match.
        if event["pid"] is None:
            continue

        # Calculate the difference between timestamps.
        difference = abs(
            event["timestamp"] - event_timestamp
        )

        if difference <= MATCH_TOLERANCE_SECONDS:
            matches.append((difference, event))

    if not matches:
        return None

    # Select the closest timestamp match.
    matches.sort(key=lambda item: item[0])

    best_match = matches[0][1]

    return {
        "pid": int(best_match["pid"]),
        "process_name": best_match["process_name"],
        "exe": best_match["exe"]
    }


if __name__ == "__main__":

    print("Reading audit events...")

    try:
        events = read_audit_events()

        events_with_paths = [
            event for event in events if event["paths"]
        ]

        print(f"Total audit events: {len(events)}")
        print(f"Events containing paths: {len(events_with_paths)}")

        print("\nSample events:")

        for event in events_with_paths[:5]:
            print(event)

    except (OSError, RuntimeError) as error:
        print(f"Audit reader error: {error}")
