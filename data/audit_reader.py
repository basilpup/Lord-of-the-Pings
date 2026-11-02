import ast
import re
import subprocess
from pathlib import Path

AUDIT_KEY = "file_lab"

MATCH_TOLERANCE_SECONDS = 3.0 # max time difference allowed netween an audit record and a watchdog event

"""Gets the first matching field from an audit record"""
def extract_field(pattern, text):
    match = re.search(pattern, text)
    return match.group(1) if match else None

def read_audit_events(): 
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

    for line in result.stdout.splitlines(): # processes each line returned by ausearch
        header = re.search(
            r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)", # gets the audit timestamp and serial number
            line 
        )
        if not header: 
            continue

        timestamp = float(header.group(1))
        serial = header.group(2)
 
        event_id = (timestamp, serial) 
        if event_id not in events: # create an event entry if this is the first record for this audit event
            events[event_id] = {
                "timestamp": timestamp,
                "pid": None,
                "process_name": None,
                "exe": None,
                "paths": []
            }

        event = events[event_id] # get event dictionary we are updating

        if line.startswith("type=SYSCALL"): # ADD COMMENT
            event["pid"] = extract_field(
                r"\bpid=(\d+)",
                line
            )

            event["process_name"] = extract_field( # ADD COMMENT
                r'\bcomm=("(?:\\.|[^"])*"|\S+)',
                line
            )

            event["exe"] = extract_field( # ADD COMMENT
                r'\bexe=("(?:\\.|[^"])*"|\S+)',
                line
            )

            # strips quotation marks from the values
            if event["process_name"]:
                event["process_name"] = (
                    event["process_name"].strip('"')
                )
            if event["exe"]:
                event["exe"] = event["exe"].strip('"')
        elif line.startswith("type=PATH"):
            name = extract_field(
                r'\bname=("(?:\\.|[^"])*"|\S+)',
                line
            )

            if name:
                if name.startswith('"'):
                    try:
                        name = ast.literal_eval(name)
                    except (ValueError, SyntaxError):
                        pass
                if name not in event["paths"]:
                    event["paths"].append(name)

    return list(events.values()) # return all grouped audit events as a list

# finds the audit event for a watchdog file event
def find_process_for_path(path, event_timestamp):
    target_path = str(Path(path).resolve()) # convert the path into an absolute path
    audit_events = read_audit_events() # gets audit events from auditd
    matches = [] # stores possible matches and timestamps

    for event in audit_events: # compare watchdog event with every audit event
        if target_path not in event["paths"]: # ADD COMMENT
            continue 
        if event["pid"] is None:
            continue
        if event["process_name"] is None:
            continue

        difference = abs(
            event["timestamp"] - event_timestamp # calculates the difference between timestamps
        )

        if difference <= MATCH_TOLERANCE_SECONDS:  # ADD COMMENT
            matches.append(
                (difference, event)
            )

    if not matches: # if no matches were found return none
        return None

    matches.sort(key=lambda item: item[0]) # sorts matches by timestamp difference
    best_match = matches[0][1] # gets the closest matching event

    return{ # returns the match 
        "pid": int(best_match["pid"]),
        "process_name": best_match["process_name"],
        "exe": best_match["exe"]
    }
