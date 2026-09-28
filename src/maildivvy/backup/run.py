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
   never the one a failed upgrade holds as its way back;
4. the operator's store-copy command runs, if one is set: after the dump, so the copy is
   never older than the dump it pairs with, and still inside the pause;
5. collection and fan-out resume, whatever happened above.

A failed store copy fails the run, and keeps the dump: the database and the state are
good, and it is the store's half of the pair that is missing.

⛔ THE STORE COPY RUNS OUTSIDE THIS PROGRAM'S SANDBOX. The backup's unit may write only
its own two directories and keeps one capability, to read the fetch state;
the operator's command is the operator's infrastructure and may need to write
anywhere, keep owners, or reach another host. It runs as a transient unit of its own,
`maildivvy-store-copy.service`, as root, with `MAILDIVVY_BACKUP_STAMP` naming the run it
pairs with, and is stopped if this run is stopped while it goes.

A restore takes one run back: under the same pause, the state is unpacked beside the live
one and checked, the database is restored in one transaction, and only then is the state
swapped in. A database that will not restore leaves the state as it was. The message
store is not touched: its copy, and putting it back, are the operator's.
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

CONF = Path("/etc/maildivvy/backup.conf")
BACKUPS = Path("/var/backups/maildivvy")
KEEP = 8                                         # the predecessor kept 8
STORE_COPY_UNIT = "maildivvy-store-copy.service"
LOCK = ".lock"
PAUSED = "paused.json"                           # beside status.json: the timers a run stopped
# the run a failed upgrade took before its migrations, written by maildivvy-install
# (installer/upgrade.py) until an upgrade finishes: the old version's only way back
HELD = Path("/etc/maildivvy/upgrade-held")


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

    def script(self, path):
        """The dump decoded to its end, line by line; a decoder that fails is a bad dump."""
        # stderr to a file, never a second pipe: a pipe nobody reads until stdout ends
        # would stop the decoder the moment it filled
        with tempfile.TemporaryFile("w+") as errors:
            with subprocess.Popen(["pg_restore", "--data-only", "--file=-", str(path)],
                                  stdout=subprocess.PIPE, stderr=errors, text=True) as child:
                yield from child.stdout
            errors.seek(0)
            if child.returncode != 0:
                raise BackupError(f"pg_restore could not decode {path} (exit "
                                  f"{child.returncode}): {errors.read().strip()[-300:]}")

    def restore(self, path):
        """The dump back into the database, in one transaction: all of it or none."""
        environment = self._environment()
        done = subprocess.run(["pg_restore", "--clean", "--if-exists", "--single-transaction",
                               "--exit-on-error", "--dbname", environment["PGDATABASE"],
                               str(path)], env=environment, capture_output=True, text=True)
        if done.returncode != 0:
            raise BackupError(f"pg_restore exited {done.returncode}, nothing was restored: "
                              f"{_last(done)}")


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


def _remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


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
        except Exception as err:
            self.say(f"maildivvy-backup: {err}")
            return 1

    def restore(self, stamp):
        try:
            with self._locked():
                self._restore(stamp)
            return 0
        except Exception as err:
            self.say(f"maildivvy-backup: {err}")
            return 1

    # --- a run --------------------------------------------------------------------------------

    def _take(self):
        backups = self.paths.backups
        for name in os.listdir(backups):   # what a run that was killed left
            if name.startswith(".") and name.endswith(".partial"):
                shutil.rmtree(backups / name)
        with pause.paused(self.systemd, self.sleep, self.say, record=self.paused_record):
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
            status.write(self.paths.status, {**held, "store_copy": copied})
        return 0 if copied in ("ok", "none configured") else 1

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
        manifest = partial / archive.MANIFEST
        fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({**held, "rows_per_table": expected}, handle, indent=2, sort_keys=True)
            handle.write("\n")
        for name in (archive.DUMP, archive.STATE, archive.MANIFEST):
            _fsync(partial / name)
        _fsync(partial)
        return held

    def _retain(self):
        held = held_stamp(self.paths.held)
        if held and (self.paths.backups / held).is_dir():
            self.say(f"kept {held} beside the count: a failed upgrade holds it as its way back")
        for name in archive.beyond_keep(os.listdir(self.paths.backups), self.settings.keep, held=held):
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
        return "ok"

    # --- a restore ----------------------------------------------------------------------------

    def _restore(self, stamp):
        taken = self.paths.backups / stamp
        if not archive.STAMP.fullmatch(stamp) or not (taken / archive.MANIFEST).is_file():
            raise BackupError(f"no complete run {stamp!r} in {self.paths.backups}")
        live = self.paths.fetch
        staging = live.parent / f".{live.name}.restore"
        if staging.exists():
            shutil.rmtree(staging)
        try:
            with pause.paused(self.systemd, self.sleep, self.say, record=self.paused_record):
                staged = archive.extract_state(taken / archive.STATE, staging)
                problems = archive.state_problems(archive.tar_entries(taken / archive.STATE),
                                                  archive.state_entries(staged))
                if problems:
                    raise BackupError("the state did not unpack as taken: " + "; ".join(problems))
                self.database.restore(taken / archive.DUMP)
                self._swap_state(staged, live)
                self.say(f"restored {stamp}: the database and the fetch state")
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    @staticmethod
    def _swap_state(staged, live):
        if not live.exists():
            os.rename(staged, live)
            return
        for child in list(live.iterdir()):
            _remove(child)
        for child in list(staged.iterdir()):
            os.rename(child, live / child.name)
        info = os.stat(staged)
        os.chmod(live, info.st_mode & 0o7777)
        if os.geteuid() == 0:
            os.chown(live, info.st_uid, info.st_gid)

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
    """systemd, or someone, told the run to stop: it unwinds, and resumes on its way out."""


def _terminated(signum, frame):
    raise Terminated(f"told to stop (signal {signum})")


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
        return pause.resume_recorded(pause.Systemd(), Paths().status.parent / PAUSED, say)
    signal.signal(signal.SIGTERM, _terminated)
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
