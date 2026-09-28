"""What one backup run is on disk, and how it is judged by what it holds.

A run is one directory under `/var/backups/maildivvy`, named by its UTC moment
(`20260923T003005Z`), holding the database dump, the fetch state and a manifest. It is
written as `.<stamp>.partial` and renamed only once both halves were judged good, so a
name that looks like a run IS one: the predecessor's failed runs each left a 20-byte gzip of
nothing that looked like a dump. The pair is renamed together, so a
database without its state is never left behind for a restore to pick.

⛔ JUDGED BY CONTENT, NEVER BY SIZE: a real dump grew from about 5 KB to
13 KB as the data grew, and no size tells an empty one apart. The dump is decoded to
the end and must hold every table of the database with exactly the rows the database
held at the dump's own snapshot; the state archive must list every entry of the state
directory with its owner, mode and bytes (the predecessor's archive was 45 bytes
of nothing after root lost the right to read the state).
"""

import datetime
import hashlib
import os
import re
import stat
import tarfile
from pathlib import Path

STAMP = re.compile(r"\d{8}T\d{6}Z")
DUMP = "database.dump"
STATE = "fetch.tar"
MANIFEST = "manifest.json"
ARCNAME = "fetch"   # the state directory's name inside the archive, whatever it is called

_TABLE = re.compile(r"^\d+; \d+ \d+ TABLE public (\S+) ")
_COPY = re.compile(r"^COPY ([^ ]+)(?: \(.*\))? FROM stdin;$")
_END = "\\."


class BackupError(Exception):
    """A run that must not count as a backup. The message says why."""


# --- names ---------------------------------------------------------------------------------------


def stamp_of(moment):
    """The run's name: its moment in UTC, sortable as text."""
    if moment.tzinfo is None:
        raise ValueError("a moment with no time zone; the run's name is UTC and is never guessed")
    return moment.astimezone(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def partial_name(stamp):
    return f".{stamp}.partial"


def complete_runs(names):
    """The names that are runs, oldest first. A partial, the lock and anything else are not."""
    return sorted(name for name in names if STAMP.fullmatch(name))


def beyond_keep(names, keep, held=None):
    """The runs to remove so that the newest `keep` stay: by count, never by age.

    `held` is the run a failed upgrade names as its way back: the only one taken
    before its migrations, so it is kept beside the count, never counted or removed."""
    if keep < 1:
        raise ValueError(f"keep {keep}: at least the newest run is kept")
    runs = [run for run in complete_runs(names) if run != held]
    return runs[:-keep] if len(runs) > keep else []


# --- the dump -------------------------------------------------------------------------------------


def tables_listed(listing):
    """The tables in `pg_restore --list`'s table of contents."""
    return {match.group(1) for match in map(_TABLE.match, listing.splitlines()) if match}


def _table_of(copied):
    schema, _, name = copied.partition(".")
    return (name or schema).strip('"')


def rows_counted(lines):
    """Rows per table in the decoded dump (`pg_restore -f -`): one line each inside COPY.

    A COPY block that never reaches its end marker is a dump cut short.
    """
    counted, table = {}, None
    for line in lines:
        line = line.rstrip("\n")
        if table is None:
            match = _COPY.match(line)
            if match:
                table = _table_of(match.group(1))
                counted[table] = 0
        elif line == _END:
            table = None
        else:
            counted[table] += 1
    if table is not None:
        raise BackupError(f"the dump ends inside the rows of table {table}: it was cut short")
    return counted


def dump_problems(expected, listed, counted):
    """Every way the dump differs from the database it was taken from; [] is a good dump.

    `expected` is {table: rows} read in the dump's own snapshot. An empty expectation is
    refused: a database with no tables and a dump of nothing agree, and prove nothing.
    """
    if not expected:
        return ["the database has no tables, so there is nothing to judge a dump by"]
    problems = []
    for table in sorted(expected):
        if table not in listed:
            problems.append(f"table {table} is not in the dump")
        if counted.get(table) != expected[table]:
            problems.append(f"table {table}: the database held {expected[table]} rows, "
                            f"the dump holds {counted.get(table, 0)}")
    for table in sorted(set(listed) - set(expected)):
        problems.append(f"table {table} is in the dump but not in the database")
    return problems


# --- the fetch state ------------------------------------------------------------------------------


def _missing(root):
    return BackupError(f"no fetch state at {root}: a backup without it would let a restored "
                       "machine fetch every retained message again")


def _digest(path):
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            sha.update(block)
    return sha.hexdigest()


def state_entries(root):
    """(name, kind, mode, uid, gid, size, sha256 or link target) of every entry, by name."""
    root = Path(root)
    if not root.is_dir():
        raise _missing(root)
    entries = []
    for path in [root, *root.rglob("*")]:
        name = ARCNAME if path == root else f"{ARCNAME}/{path.relative_to(root).as_posix()}"
        info = os.lstat(path)
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            entries.append((name, "dir", mode, info.st_uid, info.st_gid, 0, ""))
        elif stat.S_ISREG(info.st_mode):
            entries.append((name, "file", mode, info.st_uid, info.st_gid, info.st_size,
                            _digest(path)))
        elif stat.S_ISLNK(info.st_mode):
            entries.append((name, "symlink", mode, info.st_uid, info.st_gid, 0,
                            os.readlink(path)))
        else:
            raise BackupError(f"{path} is neither a file, a directory nor a link")
    return sorted(entries)


def write_state(root, path):
    """The state directory as a tar archive at `path`, `0600`, owners and modes kept."""
    root = Path(root)
    if not root.is_dir():
        raise _missing(root)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        with tarfile.open(fileobj=handle, mode="w", format=tarfile.PAX_FORMAT) as tar:
            tar.add(root, arcname=ARCNAME, recursive=True)
        handle.flush()
        os.fsync(handle.fileno())


def tar_entries(path):
    """The same entries as `state_entries`, read out of an archive."""
    entries = []
    with tarfile.open(path, "r") as tar:
        for member in tar:
            name = member.name.rstrip("/")
            mode = member.mode & 0o7777
            if member.isdir():
                entries.append((name, "dir", mode, member.uid, member.gid, 0, ""))
            elif member.isreg():
                sha = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
                entries.append((name, "file", mode, member.uid, member.gid, member.size, sha))
            elif member.issym():
                entries.append((name, "symlink", mode, member.uid, member.gid, 0,
                                member.linkname))
            else:
                raise BackupError(f"{path}: {name} is neither a file, a directory nor a link")
    return sorted(entries)


def state_problems(live, archived):
    """Every entry the two listings disagree on; [] is an archive that holds the state."""
    ours, theirs = {e[0]: e for e in live}, {e[0]: e for e in archived}
    problems = []
    for name in sorted(set(ours) | set(theirs)):
        if name not in theirs:
            problems.append(f"{name} is not in the state archive")
        elif name not in ours:
            problems.append(f"{name} is in the state archive but not in the state")
        elif ours[name] != theirs[name]:
            problems.append(f"{name} differs: {ours[name][1:6]} in the state, "
                            f"{theirs[name][1:6]} in the archive")
    return problems


def extract_state(path, parent):
    """Unpack an archive into a new directory `parent`; returns the state directory in it.

    Owners and modes are the archive's (the `tar` filter, numeric owners), and nothing is
    written outside `parent`.
    """
    parent = Path(parent)
    parent.mkdir(mode=0o700)
    with tarfile.open(path, "r") as tar:
        tar.extractall(parent, filter="tar", numeric_owner=True)
    return parent / ARCNAME
