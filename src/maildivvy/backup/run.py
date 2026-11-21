"""`maildivvy-backup`: one run, or one restore.

    maildivvy-backup [--conf /etc/maildivvy/backup.conf]
    maildivvy-backup --restore <stamp>

A run, as root, from its daily timer or by hand:

1. collection and fan-out are paused, and any run of either is waited for (`pause.py`);
2. the database is dumped as its owner, in a snapshot whose every table is counted in
   the same transaction, and the fetch state is archived - in the same run, because the
   state is what stops a restored machine fetching a whole provider window again;
3. both are judged by what they hold (`archive.py`) and only then renamed,
   together, from `.<stamp>.partial` to `<stamp>`; runs beyond the count are removed,
   never the one a failed upgrade holds as its way back nor the
   newest whose store copy succeeded;
4. the operator's store-copy command runs, if one is set: after the dump, so the copy is
   never older than the dump it pairs with, and still inside the pause. One that exits 0
   marks the run `store-copied`;
5. collection and fan-out resume, whatever happened above; while an upgrade's pause is
   recorded (`/etc/maildivvy/upgrade-paused.json`), they are the upgrade's to start, and
   a run, or its unit's `--resume`, starts none and keeps its own record for a later run;
   a run that stopped none keeps no record.

A failed store copy fails the run, and keeps the dump: the database and the state are
good, and it is the store's half of the pair that is missing.

⛔ THE STORE COPY RUNS OUTSIDE THIS PROGRAM'S SANDBOX. The backup's unit may write only
its own two directories and keeps one capability, to read the fetch state;
the operator's command is the operator's infrastructure and may need to write
anywhere, keep owners, or reach another host. It runs as a transient unit of its own,
`maildivvy-store-copy.service`, as root, with `MAILDIVVY_BACKUP_STAMP` naming the run it
pairs with, and is stopped if this run is stopped while it goes.

A restore takes one run back: under the same pause, the state is unpacked beside the live
one and checked, swapped in, and only then is the database restored, in one transaction.
⛔ THE STATE BEFORE THE DATABASE. A restore stopped between the two, or inside either,
leaves the state older than the database, never newer: an older state fetches a window of
mail again, a newer one skips what came after the run. A database that is known
to have restored nothing gets the live state back; one that may have committed keeps the
run's state and leaves collection stopped until the restore is run again: until then a
run, and the unit's `--resume`, refuse and name it, since the newest run would pair a
database the restore may not have reached with the run's state, and collection would
fetch over that pair. The message store is not touched: its copy, and putting it back,
are the operator's. The transaction replaces everything the schema's owner holds, so the objects a migration added after the
dump go too (`Database.restore` says why not `pg_restore --clean`).
"""
# The record behind it.

import argparse
import datetime
import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from maildivvy.backup import archive, pause, status
from maildivvy.backup.archive import BackupError
from maildivvy.fetch import render
from maildivvy.lib import schema

CONF = Path("/etc/maildivvy/backup.conf")
BACKUPS = Path("/var/backups/maildivvy")
KEEP = 8                                         # the predecessor kept 8
STORE_COPY_UNIT = "maildivvy-store-copy.service"
LOCK = ".lock"
PAUSED = "paused.json"                           # beside status.json: the timers a run stopped
# the run a failed upgrade took before its migrations, written by maildivvy-install
# (installer/upgrade.py) until an upgrade finishes: the old version's only way back
HELD = Path("/etc/maildivvy/upgrade-held")
# maildivvy-install's record of an upgrade's pause: while it is there, collection is the
# upgrade's to start (installer/upgrade.py)
UPGRADE_PAUSED = Path("/etc/maildivvy/upgrade-paused.json")
# the installed release, written by maildivvy-install once every step passed (installer/upgrade.py)
VERSION = Path("/etc/maildivvy/version")


class NotRestored(BackupError):
    """The restore's transaction is known not to have committed: the database is as it was."""


def unfinished_restore(record):
    """Why a run must not go on because a restore did not complete, or None. Its pause's
    record outlives it only when it may have committed, or was killed: the state is the
    run's, the database may not be, and collection stays stopped until it is run again."""
    found = pause.read(record)
    if not found or found.get("by") != "restore":
        return None
    stamp = found.get("stamp")
    return (f"a restore of {stamp} did not complete and left collection stopped: the fetch "
            f"state is its, the database may not be. Run `maildivvy-backup --restore {stamp}` "
            "again first")


def resume(systemd, paths, say):
    """The unit's ExecStopPost: start what its run recorded and did not start itself,
    unless a restore that did not complete, or an upgrade, holds collection."""
    refused = unfinished_restore(paths.status.parent / PAUSED)
    if refused:
        say(f"maildivvy-backup: {refused}")
        return 1
    if paths.upgrade_paused.exists():
        say(f"started nothing: an upgrade's pause holds collection ({paths.upgrade_paused})")
        return 0
    return pause.resume_recorded(systemd, paths.status.parent / PAUSED, say)


def installed_release(path=VERSION):
    """The release the version file names, or None on a machine whose install never finished."""
    try:
        return Path(path).read_text().strip() or None
    except FileNotFoundError:
        return None


def not_restorable(stamp, manifest, installed, shipped):
    """Why run `stamp` must not be restored on this machine, or None.

    It may be when its schema is the one the installed programs ship, whichever release
    took it, or when the release that took it is the release installed: the way back from a
    failed upgrade, whose version file still names the release it came from, while the
    programs in place may be the new release's. ⛔ NOT A RUN TAKEN WHILE A FAILED UPGRADE
    HELD COLLECTION: its database already holds that upgrade's migrations, ahead of the
    release the version file names."""
    release, migrations, held = manifest.get("release"), manifest["migrations"], manifest.get("upgrade_held")
    if migrations == shipped:
        return None
    if held:
        return (f"run {stamp} was taken while a failed upgrade held run {held} as its way back: its "
                "database holds migrations the installed programs do not ship. Restore that run, "
                f"or a run taken after an upgrade finished")
    if release is not None and release == installed:
        return None
    newest, ships = (migrations or ["none"])[-1], (shipped or ["none"])[-1]
    return (f"run {stamp} was taken by Maildivvy {release or 'with no finished install'}, its schema "
            f"at migration {newest}; this machine runs {installed or 'no finished install'}, whose "
            f"programs ship migration {ships}. Restored here, those programs would run on another "
            f"schema, and the next install would migrate it with collection running. On a machine "
            f"rebuilt from nothing, install {release or 'the release that took it'} first, restore, "
            "then upgrade as usual; on this one, restore a run its own release took")


def held_stamp(path=HELD):
    """The stamp of the run a failed upgrade holds, or None when none is held."""
    try:
        return Path(path).read_text().strip() or None
    except FileNotFoundError:
        return None


@dataclass(frozen=True)
class Settings:
    keep: int = KEEP
    store_copy: str | None = None


@dataclass(frozen=True)
class Paths:
    backups: Path = BACKUPS
    fetch: Path = render.DEFAULT_STATE_DIR
    status: Path = field(default=status.STATUS)
    held: Path = HELD
    upgrade_paused: Path = UPGRADE_PAUSED
    version: Path = VERSION
    schema: Path = schema.DEFAULT_DIR      # the migrations the installed programs ship


def read_settings(path=CONF):
    """`keep=<runs>` and `store_copy=<command>`, `#` comments; a missing key is its default."""
    try:
        text = Path(path).read_text()
    except OSError as err:
        raise BackupError(f"cannot read {path}: {err.strerror}") from None
    values = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or key not in ("keep", "store_copy"):
            raise BackupError(f"{path} line {number}: not keep= or store_copy=")
        if key in values:
            raise BackupError(f"{path} line {number}: {key} given twice")
        values[key] = value
    keep = values.get("keep") or str(KEEP)
    if not keep.isdigit() or int(keep) < 1:
        raise BackupError(f"{path}: keep={keep}: a number of runs, at least 1")
    return Settings(keep=int(keep), store_copy=values.get("store_copy") or None)


class Database:
    """pg_dump and pg_restore as the schema's owner, from the owner's own db.conf."""

    def __init__(self, consumer="owner"):
        self.consumer = consumer

    def _environment(self):
        from maildivvy.lib import db
        return db.libpq_environment(self.consumer)

    def dump(self, path):
        """Dump into `path`; returns {table: rows} as the dump's own snapshot held them."""
        from psycopg2 import sql
        from maildivvy.lib import db

        environment = self._environment()
        conn = db.connect(self.consumer)
        try:
            conn.set_session(isolation_level="REPEATABLE READ", readonly=True)
            with conn.cursor() as cur:
                # the counts below are read in the very snapshot pg_dump dumps
                cur.execute("SELECT pg_export_snapshot()")
                snapshot = cur.fetchone()[0]
                done = subprocess.run(["pg_dump", "--format=custom", f"--snapshot={snapshot}",
                                       "--file", str(path)],
                                      env=environment, capture_output=True, text=True)
                if done.returncode != 0:
                    raise BackupError(f"pg_dump exited {done.returncode}: {_last(done)}")
                cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                            "ORDER BY tablename")
                counts = {}
                for (table,) in cur.fetchall():
                    cur.execute(sql.SQL("SELECT count(*) FROM public.{}").format(
                        sql.Identifier(table)))
                    counts[table] = cur.fetchone()[0]
            return counts
        finally:
            conn.rollback()
            conn.close()

    def listing(self, path):
        done = subprocess.run(["pg_restore", "--list", str(path)], capture_output=True, text=True)
        if done.returncode != 0:
            raise BackupError(f"pg_restore --list exited {done.returncode}: {_last(done)}")
        return done.stdout

    def script(self, path, *only):
        """The dump decoded to its end, line by line; a decoder that fails is a bad dump."""
        # stderr to a file, never a second pipe: a pipe nobody reads until stdout ends
        # would stop the decoder the moment it filled
        with tempfile.TemporaryFile("w+") as errors:
            with subprocess.Popen(["pg_restore", "--data-only", *only, "--file=-", str(path)],
                                  stdout=subprocess.PIPE, stderr=errors, text=True) as child:
                yield from child.stdout
            errors.seek(0)
            if child.returncode != 0:
                raise BackupError(f"pg_restore could not decode {path} (exit "
                                  f"{child.returncode}): {errors.read().strip()[-300:]}")

    def migrations(self, path):
        """The migrations the dump's `schema_version` holds."""
        return archive.migrations_of(self.script(path, "--table=schema_version"))

    def restore(self, path):
        """The dump back into the database, in one transaction: all of it or none.

        ⛔ NOT `pg_restore --clean`: it drops only the objects the dump holds, and a view a
        later migration added over a dumped table (after a failed upgrade, the very case a
        restore is for) refuses the table's drop. So everything the owner holds is dropped
        first, `DROP OWNED BY`, which keeps the schema and the database with their grants
        as the installation made them; then the dump, decoded by pg_restore, then the
        grants read back. psql runs it all in one transaction, and it is committed only
        when pg_restore decoded the dump to its end.

        ⛔ `NotRestored` ONLY WHEN NOTHING CAN HAVE COMMITTED: a failure before the COMMIT
        began to go out (the transaction ends with the session), or psql's exit 3, a
        statement that failed under ON_ERROR_STOP. Any other failure after it, a lost
        client or a stop while psql finishes, may have committed: a plain `BackupError`.
        """
        environment = self._environment()
        committing = False
        try:
            with tempfile.TemporaryFile("w+") as errors:
                with subprocess.Popen(["psql", "--no-psqlrc", "--quiet", "--set=ON_ERROR_STOP=1"],
                                      stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                      stderr=errors, env=environment, text=True) as psql:
                    _send(psql, "BEGIN;\nDROP OWNED BY CURRENT_USER;\n")
                    decoded = subprocess.run(["pg_restore", "--file=-", str(path)],
                                             stdout=psql.stdin, stderr=subprocess.PIPE,
                                             env=environment, text=True)
                    # set before the send: psql runs a last statement cut short at its end
                    committing = decoded.returncode == 0
                    # the dump's script empties search_path, and check_grants() names its
                    # tables bare; without the COMMIT the transaction ends with the session
                    _send(psql, "RESET search_path;\nSELECT check_grants();\nCOMMIT;\n"
                          if committing else "", close=True)
                errors.seek(0)
                # psql first: a psql that stopped early stops pg_restore too, with no message
                if psql.returncode != 0:
                    said = errors.read().strip()[-300:]
                    if not committing or psql.returncode == 3:
                        raise NotRestored(f"psql exited {psql.returncode}, nothing was "
                                          f"restored: {said}")
                    raise BackupError(f"psql exited {psql.returncode} after the COMMIT was "
                                      f"sent: the database may or may not be restored: {said}")
                if decoded.returncode != 0:
                    raise NotRestored(f"pg_restore exited {decoded.returncode}, nothing was "
                                      f"restored: {_last(decoded)}")
        except BackupError:
            raise
        except Exception as err:   # told to stop, among others
            if committing:
                raise
            raise NotRestored(f"{err}, nothing was restored") from err


def _send(child, text, close=False):
    """Text to a child's stdin; a child that has already stopped says why on its stderr."""
    try:
        child.stdin.write(text)
        child.stdin.flush()
    except BrokenPipeError:
        pass
    if close:
        try:
            child.stdin.close()   # closed even when the flush inside it fails
        except BrokenPipeError:
            pass


def _last(done):
    lines = (done.stderr or done.stdout or "").strip().splitlines()
    return lines[-1] if lines else "no message"


def store_copy(command, stamp, run=subprocess.run):
    """The operator's command, as root in a transient unit of its own; returns its exit."""
    argv = ["systemd-run", "--wait", "--pipe", "--quiet", "--collect",
            f"--unit={STORE_COPY_UNIT}", "--description=Maildivvy: the operator's store copy",
            f"--setenv=MAILDIVVY_BACKUP_STAMP={stamp}", "--", "/bin/sh", "-c", command]
    try:
        return run(argv, stdin=subprocess.DEVNULL).returncode
    except BaseException:
        run(["systemctl", "stop", STORE_COPY_UNIT], capture_output=True)
        raise


def _fsync(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _same_mode(source, target):
    info = os.stat(source)
    os.chmod(target, info.st_mode & 0o7777)
    if os.geteuid() == 0:
        os.chown(target, info.st_uid, info.st_gid)


class Backup:
    def __init__(self, paths, settings, systemd, database, store_copy, now, sleep, say):
        self.paths = paths
        self.settings = settings
        self.systemd = systemd
        self.database = database
        self.store_copy = store_copy
        self.now = now
        self.sleep = sleep
        self.say = say

    @property
    def paused_record(self):
        """What the pause stopped, beside the status: the unit's ExecStopPost resumes from it
        when a run is killed inside the pause."""
        return self.paths.status.parent / PAUSED

    # --- the two acts, each returning the program's exit code -----------------------------------

    def take(self):
        try:
            with self._locked():
                return self._take()
        except Exception as err:  # noqa: BLE001 - one line for the operator, and exit 1
            self.say(f"maildivvy-backup: {err}")
            return 1

    def restore(self, stamp):
        try:
            with self._locked():
                self._restore(stamp)
            return 0
        except Exception as err:  # noqa: BLE001 - one line for the operator, and exit 1
            self.say(f"maildivvy-backup: {err}")
            return 1

    # --- a run --------------------------------------------------------------------------------

    def _take(self):
        refused = unfinished_restore(self.paused_record)
        if refused:
            raise BackupError(refused)
        backups = self.paths.backups
        for name in os.listdir(backups):   # what a run that was killed left
            if name.startswith(".") and name.endswith(".partial"):
                shutil.rmtree(backups / name)
        with pause.paused(self.systemd, self.sleep, self.say, record=self.paused_record,
                          owner={"by": "backup"}, keep=self._handed_to_upgrade):
            # the run's name is the moment of the dump, after any wait for a run going
            moment = self.now()
            stamp = archive.stamp_of(moment)
            final, partial = backups / stamp, backups / archive.partial_name(stamp)
            if final.exists():
                raise BackupError(f"{final} exists already")
            partial.mkdir(mode=0o700)
            try:
                held = self._dump_and_state(partial, stamp, moment)
                os.rename(partial, final)
                _fsync(backups)
            finally:
                if partial.exists():
                    shutil.rmtree(partial)
            self.say(f"backup {stamp}: {held['tables']} tables, {held['rows']} rows, "
                     f"{held['state_entries']} fetch state entries")
            self._retain()
            copied = self._copy_store(stamp)
            # health names the restore point from it: the runs are root's alone
            status.write(self.paths.status, {**held, "store_copy": copied, "newest_store_copied":
                                             archive.newest_paired(self.paths.backups)})
        return 0 if copied in ("ok", "none configured") else 1

    def _handed_to_upgrade(self):
        """While an upgrade's pause is recorded, the timers are the upgrade's to start: this
        run starts none, and leaves what it stopped recorded as a backup's, which the
        upgrade that finishes, or a later run, starts. A run that stopped none (the upgrade's
        own backup: the upgrade had stopped them all) hands nothing over and leaves no
        record: one naming no timer would still read as a pause to whatever finds it."""
        if not self.paths.upgrade_paused.exists():
            return False
        self.say(f"an upgrade's pause holds collection ({self.paths.upgrade_paused}): "
                 "it starts the timers, this run none")
        stopped = pause.read_record(self.paused_record)
        # ⛔ Made a backup's first, and removed only as one: a restore's record that could not
        # be replaced (this run never began its pause) keeps refusing until it is run again.
        pause.write_record(self.paused_record, stopped, {"by": "backup"})
        if not stopped:
            self.paused_record.unlink()
        return True

    def _dump_and_state(self, partial, stamp, moment):
        dump = partial / archive.DUMP
        expected = self.database.dump(dump)
        os.chmod(dump, 0o600)
        problems = archive.dump_problems(expected,
                                         archive.tables_listed(self.database.listing(dump)),
                                         archive.rows_counted(self.database.script(dump)))
        if problems:
            raise BackupError("the dump is not the database: " + "; ".join(problems))

        tar = partial / archive.STATE
        archive.write_state(self.paths.fetch, tar)
        live = archive.state_entries(self.paths.fetch)
        problems = archive.state_problems(live, archive.tar_entries(tar))
        if problems:
            raise BackupError("the state archive is not the state: " + "; ".join(problems))

        held = {"stamp": stamp, "taken_at": moment.astimezone(datetime.timezone.utc).isoformat(),
                "tables": len(expected), "rows": sum(expected.values()),
                "state_entries": len(live)}
        # what a restore compares with the machine it restores on
        written_by = {"release": installed_release(self.paths.version),
                      "migrations": self.database.migrations(dump),
                      "upgrade_held": held_stamp(self.paths.held)}
        manifest = partial / archive.MANIFEST
        fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({**held, **written_by, "rows_per_table": expected}, handle, indent=2,
                      sort_keys=True)
            handle.write("\n")
        for name in (archive.DUMP, archive.STATE, archive.MANIFEST):
            _fsync(partial / name)
        _fsync(partial)
        return held

    def _retain(self):
        held = held_stamp(self.paths.held)
        if held and (self.paths.backups / held).is_dir():
            self.say(f"kept {held} beside the count: a failed upgrade holds it as its way back")
        paired = archive.newest_paired(self.paths.backups)
        for name in archive.beyond_keep(os.listdir(self.paths.backups), self.settings.keep, held=held):
            if name == paired:
                self.say(f"kept {paired} beside the count: the newest run with a store copy")
                continue
            shutil.rmtree(self.paths.backups / name)
            self.say(f"removed {name}: more than {self.settings.keep} runs are kept")

    def _copy_store(self, stamp):
        if not self.settings.store_copy:
            return "none configured"
        code = self.store_copy(self.settings.store_copy, stamp)
        if code != 0:
            self.say(f"maildivvy-backup: the store copy exited {code}; the dump {stamp} is "
                     "kept, and has no store copy paired with it")
            return f"failed, exit {code}"
        taken = self.paths.backups / stamp
        os.close(os.open(taken / archive.PAIRED, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        _fsync(taken)
        return "ok"

    # --- a restore ----------------------------------------------------------------------------

    def _restore(self, stamp):
        taken = self.paths.backups / stamp
        if not archive.STAMP.fullmatch(stamp) or not (taken / archive.MANIFEST).is_file():
            raise BackupError(f"no complete run {stamp!r} in {self.paths.backups}")
        try:
            manifest = json.loads((taken / archive.MANIFEST).read_text())
        except (OSError, ValueError) as err:
            raise BackupError(f"cannot read {taken / archive.MANIFEST}: {err}") from None
        if "migrations" not in manifest:
            self.say(f"run {stamp} records neither the release nor the schema that took it (a run "
                     "from before 0.3.0): restore it only on the release that took it")
        else:
            refused = not_restorable(stamp, manifest, installed_release(self.paths.version),
                                     [m.version for m in schema.migrations(self.paths.schema)])
            if refused:
                raise BackupError(refused)
        live = self.paths.fetch
        staging = live.parent / f".{live.name}.restore"
        previous = live.parent / f".{live.name}.previous"   # the live state, until the commit
        torn = False   # the state is the run's, the database may not be: collection stays stopped
        try:
            for leftover in (staging, previous):
                if leftover.exists():
                    shutil.rmtree(leftover)
            with pause.paused(self.systemd, self.sleep, self.say, record=self.paused_record,
                              owner={"by": "restore", "stamp": stamp},
                              keep=lambda: torn or self._handed_to_upgrade()):
                staged = archive.extract_state(taken / archive.STATE, staging)
                problems = archive.state_problems(archive.tar_entries(taken / archive.STATE),
                                                  archive.state_entries(staged))
                if problems:
                    raise BackupError("the state did not unpack as taken: " + "; ".join(problems))
                torn = True
                self._swap_state(staged, live, previous)
                try:
                    self.database.restore(taken / archive.DUMP)
                except NotRestored:
                    self._swap_state(previous, live, staged)
                    torn = False
                    raise
                torn = False
                self.say(f"restored {stamp}: the database and the fetch state")
        except Exception as err:
            if torn:
                raise BackupError(
                    f"{err}; the fetch state is {stamp}'s and the database may not be: "
                    f"collection is left stopped until `maildivvy-backup --restore {stamp}` "
                    "is run again") from err
            raise
        finally:
            for leftover in (staging, previous):
                if leftover.exists():
                    shutil.rmtree(leftover)

    @staticmethod
    def _swap_state(incoming, live, aside):
        """`live`'s entries into `aside`, then `incoming`'s into `live`, which takes its
        mode and owner, all made durable before the database's commit can be."""
        if not live.exists():
            os.rename(incoming, live)
            _fsync(live.parent)
            return
        if not incoming.exists():   # putting back a live state that was not there
            os.rename(live, aside)
            _fsync(live.parent)
            return
        aside.mkdir(mode=0o700, exist_ok=True)
        _same_mode(live, aside)
        for child in list(live.iterdir()):
            os.rename(child, aside / child.name)
        for child in list(incoming.iterdir()):
            os.rename(child, live / child.name)
        _same_mode(incoming, live)
        for directory in (aside, incoming, live):
            _fsync(directory)

    # --- one at a time ------------------------------------------------------------------------

    def _locked(self):
        return _Lock(self.paths.backups / LOCK)


class _Lock:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise BackupError("another maildivvy-backup is running") from None
        return self

    def __exit__(self, *exc):
        os.close(self.fd)
        return False


class Terminated(Exception):
    """systemd, a terminal that closed, or a Ctrl-C told the run to stop: it unwinds, and
    resumes on its way out."""


def _terminated(signum, frame):
    raise Terminated(f"told to stop (signal {signum})")


def stop_on_signals():
    """⛔ SIGHUP AND SIGINT TOO. A run from a shell has no unit's ExecStopPost behind it,
    and SIGHUP's default ends the process without its `finally`: an SSH session that
    dropped would leave collection stopped until the next run read the record."""
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, _terminated)


def parser():
    p = argparse.ArgumentParser(prog="maildivvy-backup", description=__doc__.split("\n\n")[0])
    p.add_argument("--conf", type=Path, default=CONF, help="the settings file")
    p.add_argument("--restore", metavar="STAMP", help="restore this run instead of taking one")
    p.add_argument("--resume", action="store_true",
                   help="start the timers a run that was stopped inside its pause left stopped "
                        "(the unit's ExecStopPost)")
    return p


def say(line):
    print(line, flush=True)


def main(argv=None):
    args = parser().parse_args(argv)
    if args.resume:
        # a run SIGKILLed, or stopped inside its own resume, never reached its `finally`
        return resume(pause.Systemd(), Paths(), say)
    stop_on_signals()
    try:
        settings = read_settings(args.conf)
    except BackupError as err:
        print(f"maildivvy-backup: {err}", file=sys.stderr)
        return 1
    backup = Backup(paths=Paths(), settings=settings, systemd=pause.Systemd(),
                    database=Database(), store_copy=store_copy,
                    now=lambda: datetime.datetime.now(datetime.timezone.utc),
                    sleep=time.sleep, say=say)
    return backup.restore(args.restore) if args.restore else backup.take()
