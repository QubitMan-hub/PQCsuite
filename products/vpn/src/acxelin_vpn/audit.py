"""Who did what, in an owner-only `audit.jsonl`: invitations and revocations next to the certificate authority (from the command
line or the console), kill-switch changes on each computer. `recent` merges in the enrollment service's own log. Callers pass
names, serials and reasons only; never a token, key or passphrase."""
import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from acxelin_core.files import append

LOG = "audit.jsonl"
EST = {"enrolled": "enroll", "enroll_refused": "enrollment refused", "renewed": "renew"}
_lock = threading.Lock()


def record(folder, action, **detail):
    line = {"time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "action": action, **detail}
    folder = Path(folder)
    with _lock:
        folder.mkdir(parents=True, exist_ok=True)
        append(folder / LOG, json.dumps(line))
    return line


def _read(path, n):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            rows = deque(f, n)
    except FileNotFoundError:
        return []
    out = []
    for row in rows:
        try:
            out.append(json.loads(row))
        except ValueError:
            pass
    return out


def _when(x):
    try:
        return datetime.fromisoformat(str(x.get("time", "")).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def recent(ca_dir, n=15):
    """The last n entries, newest first."""
    ca_dir = Path(ca_dir)
    rows = _read(ca_dir / LOG, n)
    for e in _read(ca_dir / "est-audit.jsonl", n):
        if e.get("event") in EST:
            rows.append({"time": e.get("time"), "action": EST[e["event"]], "name": e.get("common_name", "")}
                        | {k: e[k] for k in ("serial", "kind", "reason") if k in e})
    # ponytail: both logs keep whole seconds, so two entries in the same second may show in either order
    rows = sorted(enumerate(rows), key=lambda r: (_when(r[1]), r[0]), reverse=True)[:n]
    return [{k: v for k, v in x.items() if k != "token"} | {"time": _when(x).strftime("%Y-%m-%dT%H:%M:%SZ")} for _, x in rows]
