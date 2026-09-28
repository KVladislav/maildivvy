"""Which Maildivvy this machine runs, what the installer does with this release, and the
upgrade.

The installed version is `/etc/maildivvy/version`; the release carries its own in
`VERSION`. The installer:

- installs when no Maildivvy is installed. A first install records the release it is
  installing in `/etc/maildivvy/installing` until its steps passed, so one that did not
  finish is installed again, never taken for an installed machine;
- takes a machine with our schema and no version file for one installed before 0.1.0
  (the first version, or a run from a control machine, which writes no version), and
  upgrades it to a 0.1 release, never installs it afresh;
- re-runs every step for the same version, which re-proves the machine;
- upgrades to a newer release: while the major is 0 only to the next minor, so each
  migration path is one that was tested; from 1.0 within the major;
- refuses an older release, and a jump past the next minor.

An upgrade runs in this order: the new release's step 1 alone (its checks change nothing),
collection and fan-out paused, `maildivvy-backup` (its unit's run, as the daily timer does
it), the release's new migrations (each in its own transaction, by the release's own
applier), every installation step (step 13 enables the timers but leaves them stopped),
the version written, and collection resumed. Step 1 refusing or a backup that fails stops
the upgrade before any change; a later failure prints the backup's stamp and the steps
back, and once a migration was applied collection stays paused: the programs still
running may be the old ones, on the new schema.

The pause is recorded in `/etc/maildivvy/upgrade-paused.json`, so the timers a run left
stopped (a failed upgrade, or one killed with its SSH session) are started again at the
end of the next run's upgrade. Before its migrations a run records its backup's stamp in
`/etc/maildivvy/upgrade-held`: until an upgrade finishes, every later run keeps collection
paused whatever fails, even having applied nothing itself, and names that backup as the
way back, since its own already holds the new migrations; `maildivvy-backup` keeps that run
beside its count while the record is there; from before 0.1.0, whose `maildivvy-backup`
runs until step 13 and knows no hold, the installer keeps it hard-linked as
`.held-<stamp>` beside the runs too. An installer run that finishes (the upgrade,
or the old version's run that goes back) removes both records.
"""

import os
import re
import shutil
import subprocess
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

from maildivvy.backup import pause, status
from maildivvy.backup import run as backup_run
from maildivvy.installer import FAILED, Refusal, shown

VERSION_FILE = Path("/etc/maildivvy/version")
UNFINISHED = Path("/etc/maildivvy/installing")
PAUSE_RECORD = Path("/etc/maildivvy/upgrade-paused.json")
HELD = backup_run.HELD                            # maildivvy-backup reads it too
BACKUPS = backup_run.BACKUPS
MANIFEST = "manifest.json"                        # a complete run holds it (backup/archive.py)
RELEASE_FILE = "VERSION"
DATABASE = "maildivvy"
PSQL = Path("/usr/bin/psql")
PYTHON = "/usr/bin/python3"
BACKUP_UNIT = "maildivvy-backup.service"
BACKUP_PROGRAM = "/opt/maildivvy/bin/maildivvy-backup"

_VERSION = re.compile(r"(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})")


class Failed(Exception):
    """A part of the installation that did not do its work. The message says what it said."""


def parse_version(text, where):
    """(major, minor, patch) from a version file's one line."""
    match = _VERSION.fullmatch(text.removesuffix("\n"))
    if not match:
        raise Refusal(f"{where} does not hold a version (X.Y.Z): {text.strip()[:40]!r}")
    return tuple(int(n) for n in match.groups())


def release_version(root):
    """The version of the release unpacked at `root`."""
    path = Path(root) / RELEASE_FILE
    try:
        text = path.read_text()
    except FileNotFoundError:
        raise Refusal(f"no {RELEASE_FILE}: {root} is not an unpacked release") from None
    return parse_version(text, RELEASE_FILE)


# --- what is installed ----------------------------------------------------------------------


@dataclass(frozen=True)
class Found:
    version: tuple | None = None   # what the version file says
    first_version: bool = False    # our schema and no version file: installed before 0.1.0
    unfinished: bool = False       # a first install whose steps have not all passed yet


def schema_versions(run=subprocess.run, psql=PSQL):
    """The migrations our database records, [] when there is no Maildivvy database."""
    if not Path(psql).exists():
        return []
    done = run(["runuser", "-u", "postgres", "--", str(psql), "-X", "-At", "-d", DATABASE, "-c",
                "SELECT version FROM schema_version ORDER BY version"],
               capture_output=True, text=True, cwd="/")
    if done.returncode == 0:
        return done.stdout.split()
    if "does not exist" in done.stderr:   # no postgres account, no database, or no table
        return []
    lines = done.stderr.strip().splitlines() or [f"exit {done.returncode}"]
    raise Refusal(f"cannot tell whether Maildivvy is installed: its database did not answer: {lines[-1]}")


def installed(schema=schema_versions):
    """What of Maildivvy this machine holds."""
    if VERSION_FILE.exists():
        return Found(version=parse_version(VERSION_FILE.read_text(), str(VERSION_FILE)))
    if UNFINISHED.exists():
        return Found(unfinished=True)
    if schema():
        return Found(first_version=True)
    return Found()


# --- the version rule -----------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    action: str                    # install, reprove or upgrade
    release: tuple
    installed: tuple | None        # None: nothing, or a machine from before 0.1.0
    unfinished: bool = False

    @property
    def came_from(self):
        return shown(self.installed) if self.installed else "before 0.1.0"

    def says(self):
        if self.action == "install":
            again = " again: the first installation did not finish" if self.unfinished else ""
            return f"installing Maildivvy {shown(self.release)}{again}"
        if self.action == "reprove":
            return f"Maildivvy {shown(self.release)} is installed: every step is run again, and proves the machine"
        return (f"upgrading Maildivvy from {self.came_from} to {shown(self.release)}: step 1's checks, a "
                "backup, then the new migrations and every step")


def decide(found, release):
    """What to do with this release on this machine, or a Refusal saying why nothing."""
    if found.first_version:
        if release[:2] != (0, 1):
            raise Refusal(f"this machine runs Maildivvy from before 0.1.0, and {shown(release)} is past "
                          "the next minor: upgrade it with a 0.1 release first")
        return Plan("upgrade", release, None)
    if found.version is None:
        return Plan("install", release, None, unfinished=found.unfinished)
    old = found.version
    if release == old:
        return Plan("reprove", release, old)
    if release < old:
        raise Refusal(f"this release, {shown(release)}, is older than the installed {shown(old)}: a release "
                      "is never installed over a newer one")
    if old[0] == 0 and not (release[0] == 0 and release[1] <= old[1] + 1):
        raise Refusal(f"this release, {shown(release)}, is past the next minor of the installed {shown(old)}: "
                      f"upgrade to 0.{old[1] + 1} first")
    if old[0] > 0 and release[0] != old[0]:
        raise Refusal(f"this release, {shown(release)}, is a major version past the installed {shown(old)}: "
                      "its release notes say how to reach it")
    return Plan("upgrade", release, old)


# --- the records ----------------------------------------------------------------------------


def _write(path, text):
    path = Path(path)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    partial = path.with_name(f".{path.name}.partial")
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o644)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(partial, path)


def mark_unfinished(release):
    _write(UNFINISHED, shown(release) + "\n")


def write_version(release):
    """The installed version, once every step passed; a first install is finished then, and
    no upgrade is held any more: the database and the programs are one release again."""
    _write(VERSION_FILE, shown(release) + "\n")
    UNFINISHED.unlink(missing_ok=True)
    HELD.unlink(missing_ok=True)
    _drop_held_copies()


def finished(release):
    """A run that was no upgrade passed every step: as write_version, and a failed upgrade's
    pause record goes too, since step 13 started the timers; left for the way back through
    this version's run, it would read as a pause in health. An upgrade's own record is its
    pause's, removed when the pause ends."""
    write_version(release)
    PAUSE_RECORD.unlink(missing_ok=True)


def held_copy(stamp):
    """Where an upgrade from before 0.1.0 keeps its held run until an upgrade finishes: the
    first version's maildivvy-backup runs until step 13 installs the new one, and its
    retention knows no hold. Hard links beside the runs, under a name no retention counts."""
    return BACKUPS / f".held-{stamp}"


def _keep_held_copy(stamp):
    copy = held_copy(stamp)
    if copy.exists():
        shutil.rmtree(copy)
    shutil.copytree(BACKUPS / stamp, copy, copy_function=os.link)


def _drop_held_copies():
    for copy in BACKUPS.glob(".held-*"):
        shutil.rmtree(copy)


def held_since():
    """The stamp of the backup an earlier upgrade took before the migrations it applied, when
    no upgrade finished since; else None."""
    return backup_run.held_stamp(HELD)


# --- the upgrade's parts --------------------------------------------------------------------


def _logged(log, argv, done):
    log.write(f"$ {' '.join(argv)}\n{done.stdout or ''}{done.stderr or ''}")
    log.flush()


def take_backup(write, log, run=subprocess.run, status_path=status.STATUS):
    """One run of the backup's unit, as its timer does it; returns the new run's stamp."""
    before = status.read(status_path)
    since = f"@{int(time.time())}"
    argv = ["systemctl", "start", BACKUP_UNIT]
    done = run(argv, capture_output=True, text=True)
    _logged(log, argv, done)
    if done.returncode != 0:
        # the program's own lines, not systemd's about the unit
        journal = ["journalctl", "-q", "-o", "cat", "--no-pager", f"_SYSTEMD_UNIT={BACKUP_UNIT}", "--since", since]
        said = run(journal, capture_output=True, text=True)
        _logged(log, journal, said)
        lines = [line for line in (said.stdout or "").splitlines() if line.strip()]
        own = [line for line in lines if line.startswith("maildivvy-backup:")] or lines
        raise Failed(f"{BACKUP_UNIT} failed: {own[-1] if own else (done.stderr or '').strip()}")
    after = status.read(status_path)
    if not after or (before and after["stamp"] == before["stamp"]):
        raise Failed(f"{BACKUP_UNIT} ended and left no new run in {status_path}")
    return after["stamp"]


def apply_migrations(root, write, log, run=subprocess.run):
    """The release's migrations the database lacks, by the release's own applier; how many it applied."""
    root = Path(root)
    argv = [PYTHON, str(root / "bin" / "maildivvy-schema"), "--dir", str(root / "schema")]
    done = run(argv, capture_output=True, text=True, cwd="/")
    _logged(log, argv, done)
    if done.returncode != 0:
        lines = [line for line in (done.stderr or done.stdout or "").splitlines() if line.strip()]
        raise Failed(lines[-1].removeprefix("maildivvy-schema: ") if lines else f"the applier exited {done.returncode}")
    applied = 0
    for line in done.stdout.splitlines():
        if line.strip():
            write(f"  {line.strip()}")
            applied += line.startswith("applied ")
    return applied


def rollback(plan, stamp, store_copy, held, from_earlier_run=False, taken=None):
    """What the operator reads when the upgrade failed after its backup. `stamp` is the way
    back; with `from_earlier_run` it is an earlier run's, taken before the migrations that
    run applied, and `taken` this run's own, which already holds them."""
    back = (f"Run the installer of {plan.came_from} again, from its unpacked release: it re-proves the "
            "machine at that version, starts collection and fan-out and removes the upgrade's records."
            if plan.installed else
            "Run the installation of the version from before 0.1.0 again, as you did, from your control "
            f"machine; it does not know the upgrade's records, so remove them after: sudo rm -f {PAUSE_RECORD} "
            f"{HELD}" + (f"; sudo rm -rf {held_copy(stamp)}." if held else "."))
    store = ("the store from the copy that run made" if store_copy else
             "the store from your own copy of it (maildivvy_backup_store_copy is not set: the backup holds no store)")
    if from_earlier_run:
        lines = [f"The upgrade to {shown(plan.release)} failed. The version file still says {plan.came_from}, "
                 f"and an earlier run applied the new migrations after backup {stamp} was taken"
                 + (f"; this run's backup {taken} already holds them and is no way back." if taken else ".")]
        gone = not (BACKUPS / stamp / MANIFEST).is_file()
        if gone and (held_copy(stamp) / MANIFEST).is_file():
            lines.append(f"Run {stamp} was removed by the backup of the version from before 0.1.0, which knows "
                         f"no hold; the upgrade kept a copy. To go back, put it back first: sudo cp -al "
                         f"{held_copy(stamp)} {BACKUPS / stamp}")
        elif gone:
            lines.append(f"Warning: run {stamp} is no longer in {BACKUPS}. Restore it from a copy of it if you "
                         f"have one; without it there is no way back to {plan.came_from}, and the way on is to fix "
                         "what failed and run this installer again.")
    else:
        lines = [f"The upgrade to {shown(plan.release)} failed after backup {stamp} was taken. The version file "
                 f"still says {plan.came_from}."]
    if held:
        lines.append("Collection and fan-out stay paused: the database has the new migrations, and the programs "
                     "running may be the old ones. The next installer run that finishes starts them again.")
    return [*lines,
            f"To go back to {plan.came_from}:",
            f"  1. Restore run {stamp} as the administration guide's Restore says: {store}, then "
            f"sudo {BACKUP_PROGRAM} --restore {stamp}.",
            f"  2. {back}",
            "Or fix what failed and run this installer again: it takes a new backup and goes on."]


def upgrade(plan, root, steps, write, log, *, store_copy=True, systemd=None, sleep=time.sleep,
            backup=take_backup, migrate=apply_migrations):
    """The upgrade in its order; 0 when the new version is installed, else FAILED.

    `steps(preflight_only=False)` runs the release's play and returns its exit code."""
    if not store_copy:
        write("warning: maildivvy_backup_store_copy is not set: the backup before the upgrade holds the "
              "database, not the store; copy the store yourself first if you may need to go back")
    earlier = held_since()   # an earlier run failed past its migrations: they are applied already
    held = earlier is not None

    def stopped(reason=None):
        if not held:
            because = f"{reason}, and " if reason else ""
            write(f"The upgrade stopped before any change: {because}Maildivvy {plan.came_from} is installed "
                  "as it was.")
            return
        for line in rollback(plan, earlier, store_copy, held, from_earlier_run=True):
            write(line)

    code = steps(preflight_only=True)
    if code != 0:
        stopped(f"step 1 refused (exit {code})")
        return FAILED
    PAUSE_RECORD.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with pause.paused(systemd or pause.Systemd(), sleep, write, record=PAUSE_RECORD, keep=lambda: held):
        write("collection and fan-out are paused; taking a backup")
        try:
            stamp = backup(write, log)
        except Failed as failure:
            write(f"failed: {failure}")
            stopped()
            return FAILED
        write(f"backup {stamp} taken before the upgrade")
        try:
            if not held:
                # before the migrations: a run that fails in them, or is killed, is held too
                if not plan.installed:
                    _keep_held_copy(stamp)
                _write(HELD, stamp + "\n")
                held = True
            if migrate(root, write, log) == 0 and earlier is None:
                HELD.unlink()
                _drop_held_copies()
                held = False
            code = steps()
            if code != 0:
                raise Failed(f"an installation step failed (exit {code}); nothing after it ran")
            write_version(plan.release)
            held = False
        except Exception as failure:   # noqa: BLE001 - whatever failed, the operator gets the way back
            if not isinstance(failure, Failed):
                log.write(traceback.format_exc())
                log.flush()
            write(f"failed: {failure}")
            lines = (rollback(plan, earlier, store_copy, held, from_earlier_run=True, taken=stamp) if earlier else
                     rollback(plan, stamp, store_copy, held))
            for line in lines:
                write(line)
            return FAILED
    return 0
