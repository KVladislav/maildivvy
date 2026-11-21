"""maildivvy-import: file a directory of message files into a domain.

    maildivvy-import incoming --domain <label> --source <dir> [--manifest <tsv>]
                              [--scan] [--dry-run] [--result <path>]
    maildivvy-import sent --domain <label> --login <person> --source <dir> [--manifest <tsv>]
                          [--scan] [--dry-run] [--result <path>]

Run as the mail owner. `incoming` files each message into the domain archive's INBOX,
where the pass records it and links it to nobody; `sent` files each into the person's
Sent and names it in the archive's `Sent/<account>`, with its rows. People get the
history afterwards by a top-up, one per person.

⛔ ONE IMPORT OF A DOMAIN AT A TIME, under its own advisory lock (`locks.IMPORT`), taken
with try-lock: a second run refuses with 75. Deleting the domain, or a person's mailbox
in it, takes the same lock blocking; so that a deletion never holds the request queue for
long, the run stops as soon as it sees one asked for.

⛔ A RUN STOPS, AND IS RUN AGAIN, RATHER THAN WAITING FOR THE MACHINE. Before each file,
and while it waits for the pass, it reads the backup's and the upgrade's pause records and
stops on either; it stops before a copy would take the store's filesystem under health's
warn level (the snapshot's reserve); it stops when the pass does not record a slice
within its bound, when the store refuses a write, and when the database goes away under
it, as a restart of PostgreSQL in the middle of an import of many hours does (`went_away`).
Every stop exits 75 with what it finished written, and a second run repeats nothing: a
file's name in the store carries its SHA-256.

⛔ RENAMED ON THE STORE'S FILESYSTEM, COPIED FROM ANOTHER, NEVER HARDLINKED. A hardlink
leaves the archive's file sharing its inode with the staging tree, where it can be
changed in place; the archive's bytes are final. A file renamed must be the
mail owner's, with one link, and unchanged since it was read; a file copied is hashed again
as it is copied.

Not scanned unless `--scan`, which asks clamd: an infected file is refused, one over the
scanner's limit imported and said so, and clamd unavailable stops the run. Never rspamd.

Exit 0: the source done. 75: stopped, run it again. 1: a fault of ours or bad arguments.
A connection that cannot be made at the start is no stop and exits 1: a wrong password
fails there just as a server that is down does.
"""

import argparse
import hashlib
import os
import string
import sys
import time
from pathlib import Path
from typing import NamedTuple

from maildivvy.backup import status as backup_status
from maildivvy.fetch import locks
from maildivvy.importer import result, source
from maildivvy.lib import config, db, store

CONSUMER = "pipeline"
# A login in any case, folded as Dovecot and the interface fold it: ASCII only.
LOGIN_CASE = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
EX_OK, EX_FAULT, EX_STOPPED = 0, 1, 75
SLICE_FILES = 2000
SLICE_BYTES = 2 << 30
WAIT_BOUND = 1800     # seconds the pass has to record a slice
POLL = 5              # seconds between two readings while waiting
pause = time.sleep    # how a run waits between two readings
CHUNK = 1 << 20
FILE_MODE = 0o600     # every file the import puts in the store, renamed or copied

BACKUP_PAUSED = backup_status.STATUS.parent / "paused.json"
UPGRADE_PAUSED = Path("/etc/maildivvy/upgrade-paused.json")

# A deletion of the domain, of a mailbox in it, or of a person holding one, asked for and
# not finished: it waits for this run's lock, so the run stops for it.
DELETION = """
    SELECT kind, id FROM request
     WHERE state IN ('queued', 'running') AND (
           (kind = 'delete_domain' AND payload ->> 'domain_id' = %s::text)
        OR (kind = 'delete_mailbox' AND payload ->> 'mailbox_id' IN
                (SELECT id::text FROM mailbox WHERE domain_id = %s))
        OR (kind = 'delete_account' AND payload ->> 'account_id' IN
                (SELECT account_id::text FROM mailbox WHERE domain_id = %s)))
     ORDER BY id LIMIT 1
"""
DOMAIN = "SELECT id, label FROM domain WHERE label = %s"


class Stop(Exception):
    """The run ends here, resumable: run it again."""


class Fault(Exception):
    """The run cannot start, or a fault of ours: exit 1."""


# The SQLSTATE classes that say the database went away, not that the run is wrong: 08, a
# connection exception, and 57, an operator's intervention (a shutdown, a statement
# cancelled).
GONE = ("08", "57")


def went_away(err):
    """Why the run stops, when `err` is the database going away under it; None for every
    other failure, which stays a fault.

    A database error with no SQLSTATE is the connection's own, dropped under a statement;
    one of class 08 or 57 says the server closed it or was told to stop. Nothing is lost
    by either: what the run finished is written, and the next run goes on by the hashes.
    Any other class is a statement of ours the database refused, which running the import
    again would only repeat. Both stages are read here, so they stop alike.
    """
    if not hasattr(err, "pgcode") or (err.pgcode and err.pgcode[:2] not in GONE):
        return None
    said = str(err).strip().splitlines()
    what = f"{type(err).__name__}: {said[0]}" if said else type(err).__name__
    return f"the database went away ({what}): run the import again"


class Paths(NamedTuple):
    """Where a run works. The product fixes its layout; none of this is a setting."""

    store_root: Path = store.STORE_ROOT
    backup_paused: Path = BACKUP_PAUSED
    upgrade_paused: Path = UPGRADE_PAUSED


# --- what stops a run ---------------------------------------------------------------------------


def paused(paths):
    """Why the machine is paused for a backup or an upgrade, or None."""
    for path, who in ((paths.backup_paused, "a backup or a restore"),
                      (paths.upgrade_paused, "an upgrade")):
        try:
            exists = Path(path).exists()
        except OSError:
            exists = True   # a record we cannot even look for is read as one
        if exists:
            return f"{who} paused the machine ({path}): run the import again after it"
    return None


def deletion(cur, domain_id):
    """Why a deletion waits for this run, or None."""
    cur.execute(DELETION, (domain_id, domain_id, domain_id))
    row = cur.fetchone()
    if row is None:
        return None
    return (f"request {row[1]} ({row[0]}) deletes what this import writes into and waits "
            "for it")


def check(conn, paths, domain_id):
    """Stop before the next file when the machine is paused or a deletion waits."""
    why = paused(paths)
    if why is None:
        with conn.cursor() as cur:
            why = deletion(cur, domain_id)
        conn.commit()
    if why is not None:
        raise Stop(why)


class Reserve:
    """The snapshot's reserve: no copy takes the store's filesystem under health's
    warn level for the disk layout, in bytes or in inodes."""

    def __init__(self, root, bounds=None):
        self.root = Path(root)
        if bounds is None:
            from maildivvy.fetch import snapshot
            try:
                bounds = snapshot.reserve()
            except Exception as err:  # noqa: BLE001 - health's settings or the disk record
                raise Stop(f"the reserve cannot be read: {type(err).__name__}: {err}") from None
        self.percent, self.mode = bounds

    def room(self, size):
        from maildivvy.fetch import snapshot
        short = snapshot.short_of(os.statvfs(self.root), self.percent, size)
        if short is not None:
            raise Stop(f"a copy would take the store's filesystem under the {self.percent}% "
                       f"free health warns at with {self.mode} disks: {short}")


# --- moving one file into a maildir -------------------------------------------------------------


def fsync_path(path, directory=False):
    fd = os.open(path, os.O_RDONLY | (os.O_DIRECTORY if directory else 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def same_filesystem(path, directory):
    return os.stat(path, follow_symlinks=False).st_dev == os.stat(directory).st_dev


def put(record, box, name, reserve, owner=None):
    """`record`'s file into `box/cur/<name>`, its mtime the received moment; returns how
    it went there, `renamed` or `copied`, or raises `ValueError` for this file alone and
    `Stop` for the store.

    On the store's filesystem the file is renamed: it must be the mail owner's, with one
    link, and unchanged since it was read, and its mode and its mtime are set before the
    rename so its name is never seen with another: whatever mode it had in the staging
    tree, in the store it is the owner's alone, as a copy is. From another filesystem it is copied through `tmp/`,
    hashed and its line ends counted again as it is written, fsynced, its mtime set, then
    renamed into `cur/`: the name it gets carries the size and the IMAP size read before.
    """
    target = Path(box) / "cur" / name
    uid = os.geteuid() if owner is None else owner
    try:
        if same_filesystem(record.path, Path(box) / "cur"):
            found = os.stat(record.path, follow_symlinks=False)
            was = record.found
            if found.st_uid != uid or found.st_nlink != 1:
                raise ValueError("on the store's filesystem it is renamed, so it must be the "
                                 f"mail owner's with one link (owner {found.st_uid}, "
                                 f"{found.st_nlink} links)")
            if was is None or (found.st_ino, found.st_size, found.st_mtime_ns) != (
                    was.st_ino, was.st_size, was.st_mtime_ns):
                raise ValueError("it changed after it was read")
            os.chmod(record.path, FILE_MODE)
            os.utime(record.path, (record.received, record.received))
            fsync_path(record.path)
            os.rename(record.path, target)
            fsync_path(target.parent, directory=True)
            fsync_path(record.path.parent, directory=True)
            return "renamed"
        reserve.room(record.size)
        tmp = Path(box) / "tmp" / store.base_name(target)
        tmp.unlink(missing_ok=True)   # what a run stopped in the middle of a copy left
        digest, vsize, after_cr = hashlib.sha256(), 0, False
        src = os.open(record.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            dst = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
            try:
                while True:
                    chunk = os.read(src, CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                    vsize += len(chunk) + source.bare_line_feeds(chunk, after_cr)
                    after_cr = chunk.endswith(b"\r")
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(dst, view):]
                os.fsync(dst)
            finally:
                os.close(dst)
        finally:
            os.close(src)
        if digest.hexdigest() != record.sha256 or vsize != record.vsize:
            tmp.unlink(missing_ok=True)
            raise ValueError("it changed after it was read")
        os.utime(tmp, (record.received, record.received))
        os.rename(tmp, target)
        fsync_path(target.parent, directory=True)
        return "copied"
    except (ValueError, Stop):
        raise
    except FileNotFoundError as err:
        raise ValueError(f"it went while it was imported: {err.filename}") from None
    except OSError as err:
        raise Stop(f"the store refused a write: {err}") from None


def imported_hashes(box):
    """The SHA-256 of every imported name in one maildir's `cur/` and `new/`, listed once."""
    held = set()
    for part in store.PARTS:
        try:
            names = os.listdir(Path(box) / part)
        except FileNotFoundError:
            continue
        for name in names:
            found = store.IMPORTED.match(store.name_parts(name)[0])
            if found:
                held.add(found.group(2))
    return held


# --- the command --------------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="maildivvy-import",
                                     description="file a directory of message files into a domain")
    stages = parser.add_subparsers(dest="stage", required=True)
    for stage, words in ((source.INCOMING, "into the domain archive's INBOX"),
                         (source.SENT, "into a person's Sent and the archive's Sent/<account>")):
        sub = stages.add_parser(stage, help=words)
        sub.add_argument("--domain", required=True, help="the domain's label")
        if stage == source.SENT:
            sub.add_argument("--login", required=True, type=lambda typed: typed.translate(LOGIN_CASE),
                             help="the person's login, in any case")
        sub.add_argument("--source", required=True, type=Path, help="the directory of files")
        sub.add_argument("--manifest", type=Path, default=None,
                         help="path sha256 size received flags, tab-separated")
        sub.add_argument("--scan", action="store_true",
                         help="ask clamd about each file: infected is refused")
        sub.add_argument("--dry-run", action="store_true",
                         help="write nothing; print the results it would give")
        sub.add_argument("--result", type=Path, default=None,
                         help="the result file (default: <source>.import-<UTC>.tsv beside it)")
        sub.add_argument("--etc", default=str(config.ETC), help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def say(text):
    sys.stderr.write(f"maildivvy-import: {text}\n")


def stage_of(args, conn, domain, paths):
    if args.stage == source.INCOMING:
        from maildivvy.importer import incoming
        return incoming.Incoming(conn, domain, paths)
    from maildivvy.importer import sent
    return sent.Sent(conn, domain, args.login, paths, dry_run=args.dry_run)


def run(conn, args, paths, out, scanner=None, clock=None, sleep=None):
    """The run itself, its lock held: every record judged, written or refused, one line
    each in `out`, then the totals. Returns `(exit code, why it stopped)`."""
    clock, sleep = clock or time.monotonic, sleep or pause
    started = time.time()   # no manifest's received moment is later than this
    with conn.cursor() as cur:
        cur.execute(DOMAIN, (args.domain,))
        row = cur.fetchone()
    conn.commit()
    if row is None:
        raise Fault(f"no domain {args.domain!r}")
    domain = row
    stage = stage_of(args, conn, domain, paths)
    seen = source.Seen(held=stage.held())
    seen.add_ids(stage.ids())
    report = result.Result(out, held_before=seen.before)
    reserve = None
    stopped = None
    pending_files = pending_bytes = 0

    def checked():
        check(conn, paths, domain[0])

    try:
        if seen.before and not args.dry_run:
            # A run stopped after a slice and before the pass recorded it left names with
            # no row: their hashes are known here and their Message-IDs are not, so a
            # later file with one of those Message-IDs in other bytes would go in beside
            # it. The wait a slice ends with comes first, once.
            seen.add_ids(stage.wait(checked, clock, sleep))
        for record in source.records(args.source, stage.kind, args.manifest, started):
            if not args.dry_run:
                check(conn, paths, domain[0])
            verdict = seen.judge(record)
            if verdict is None and scanner is not None:
                try:
                    verdict, record = scanner.judge(record)
                except source.Unavailable as err:
                    raise Stop(str(err)) from None
            if verdict is not None:
                report.line(record, *verdict)
                continue
            if args.dry_run:
                seen.took(record)
                report.line(record, source.IMPORTED, "")
                continue
            if reserve is None:
                reserve = Reserve(paths.store_root)
            try:
                how = stage.put(record, reserve)
            except ValueError as err:
                report.line(record, source.REFUSED, str(err))
                continue
            seen.took(record)
            report.line(record, source.IMPORTED, how if how != "renamed" else "")
            pending_files += 1
            pending_bytes += record.size
            if pending_files >= SLICE_FILES or pending_bytes >= SLICE_BYTES:
                seen.add_ids(stage.wait(checked, clock, sleep))
                pending_files = pending_bytes = 0
        if pending_files and not args.dry_run:
            seen.add_ids(stage.wait(checked, clock, sleep))
    except Stop as err:
        stopped = str(err)
    except Exception as err:
        stopped = went_away(err)
        if stopped is None:
            # what it finished stays written, with the fault as its last line
            report.unrecorded = getattr(stage, "unrecorded", 0)
            report.totals(f"a fault: {type(err).__name__}: {err}")
            raise
    report.unrecorded = getattr(stage, "unrecorded", 0)   # incoming's alone
    report.totals(stopped)
    return (EX_STOPPED if stopped else EX_OK), stopped


def main(argv=None, paths=Paths()):  # noqa: B008 - Paths is an immutable NamedTuple
    args = parse_args(argv)
    try:
        conn = db.connect(CONSUMER, etc=args.etc)
    except config.ConfigError as err:
        say(str(err))
        return EX_FAULT
    out = None
    try:
        with conn.cursor() as cur:
            cur.execute(DOMAIN, (args.domain,))
            row = cur.fetchone()
            if row is None:
                say(f"no domain {args.domain!r}")
                return EX_FAULT
            if not args.dry_run and not locks.try_lock(cur, row[0], locks.IMPORT):
                say(f"another import of {args.domain} is running: run this one again after it")
                return EX_STOPPED
        conn.commit()
        if args.dry_run:
            out = sys.stdout
        else:
            path = args.result or result.path_for(args.source)
            try:
                out = result.open_new(path)
            except OSError as err:
                say(f"the result file {path} cannot be made: {err}")
                return EX_FAULT
            say(f"writing the result to {path}")
        try:
            code, stopped = run(conn, args, paths, out,
                                scanner=source.Scanner() if args.scan else None)
        except (Fault, source.SourceError) as err:
            say(str(err))
            return EX_FAULT
        except Exception as err:  # noqa: BLE001 - a fault of ours: one line and exit 1
            if went_away(err) is not None:
                raise   # before the run's first line: stopped below, as before its first query
            say(f"stopped by a fault: {type(err).__name__}: {err}")
            return EX_FAULT
        if stopped:
            say(f"stopped: {stopped}")
        return code
    except Exception as err:
        # the database gone before the run wrote a line: resumable all the same
        stopped = went_away(err)
        if stopped is None:
            raise
        say(f"stopped: {stopped}")
        return EX_STOPPED
    finally:
        if out is not None and out is not sys.stdout:
            out.close()
        conn.close()

