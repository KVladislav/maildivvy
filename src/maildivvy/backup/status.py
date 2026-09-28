"""The newest backup run as the rest of the machine may read it.

`/var/backups/maildivvy` is root's alone, so what other programs need to
know about it is written beside, world-readable and holding no secret: the newest run's
name and moment, what it held, and what the operator's store copy did. The pipeline's
enable gate reads it; nothing in it is a credential or a row.
"""

import json
import os
from pathlib import Path

STATUS = Path("/var/lib/maildivvy/backup/status.json")


def write(path, record):
    """Replace the status file whole: a reader never sees half of one."""
    path = Path(path)
    temporary = path.with_name(f".{path.name}.partial")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o644)   # the unit's mask is 0077
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def read(path=STATUS):
    """The newest run's record, or None when there is none that names a run."""
    try:
        record = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict) or not isinstance(record.get("stamp"), str) \
            or not record["stamp"]:
        return None
    return record


def problem(path=STATUS):
    """Why the machine cannot be said to have a backup; None when it has one."""
    if read(path) is None:
        return (f"no backup of the database and the fetch state has been taken yet "
                f"({path} names no run; run maildivvy-backup)")
    return None
