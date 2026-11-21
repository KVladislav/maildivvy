"""Which Maildivvy this machine runs, what the installer does with this release, and the
upgrade.

The installed version is `/etc/maildivvy/version`; the release carries its own in
`VERSION`. The installer:

- installs when no Maildivvy is installed. A first install records the release it is
  installing in `/etc/maildivvy/installing` until its steps passed, so one that did not
  finish is installed again, never taken for an installed machine. Another release
  installs it afresh only while no one used it: one given an account, a domain or an
  external mailbox before it finished (the interface runs from step 15) runs the release
  recorded, and is upgraded from it;
- takes a machine with our schema and no version file for one installed before 0.1.0
  (the first version, or a run from a control machine, which writes no version), and
  upgrades it to a 0.1 release, never installs it afresh;
- re-runs every step for the same version, which re-proves the machine;
- upgrades to a newer release: while the major is 0 only to the next minor, so each
  migration path is one that was tested; from 1.0 within the major;
- refuses an older release, and a jump past the next minor.

An upgrade runs in this order: the new release's step 1 alone (its checks change nothing),
a backup already running waited for, collection and fan-out paused, `maildivvy-backup` (its
unit's run, as the daily timer does it, and one taken after the pause, never one joined),
both timers checked still stopped, the release's new migrations (each in its own
transaction, by the release's own applier), every installation step (step 13 enables the
timers but leaves them stopped), the version written, and collection resumed, with any
timer a backup left to it. Step 1 refusing, a backup that fails or timers started again
during it stop the upgrade before any change; a later failure prints the backup's stamp
and the steps back, and once a migration was applied collection stays paused: the programs still
running may be the old ones, on the new schema. Mail itself is not paused: from the
migrations until each program's step, the previous release's daemons, milter, interface
and Sent hook serve on the new schema, which is why a migration only adds (the
applier's rule, `maildivvy.lib.schema`).

The pause is recorded in `/etc/maildivvy/upgrade-paused.json`, so the timers a run left
stopped (a failed upgrade, or one killed with its SSH session) are started again at the
end of the next run's upgrade. ⛔ THE TIMERS ARE THE UPGRADE'S WHILE IT RUNS. Joined, a
backup already running would start the timers it stopped in its `finally`, under the
migrations: so the upgrade waits for it first, and stops the timers itself; and a backup
that runs while the record is there starts none, and leaves what it stopped to the
upgrade (`maildivvy-backup`), which starts it whenever its own pause ends with collection
resumed, failed or not, and removes that backup's record. Before its migrations a run records its backup's stamp in
`/etc/maildivvy/upgrade-held`: until an upgrade finishes, every later run keeps collection
paused whatever fails, even having applied nothing itself, and names that backup as the
way back, since its own already holds the new migrations; `maildivvy-backup` keeps that run
beside its count while the record is there; from before 0.1.0, whose `maildivvy-backup`
runs until step 13 and knows no hold, the installer keeps it hard-linked as
`.held-<stamp>` beside the runs too. An installer run that finishes (the upgrade,
or the old version's run that goes back) removes both records.
"""

import datetime
import os
import pwd
import re
import shutil
import subprocess
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from maildivvy.backup import archive, pause, status
from maildivvy.backup import run as backup_run
from maildivvy.installer import FAILED, Refusal, shown

import maildivvy_installed   # ansible/library: maildivvy-install puts it on the path

VERSION_FILE = Path("/etc/maildivvy/version")
UNFINISHED = Path("/etc/maildivvy/installing")
PAUSE_RECORD = backup_run.UPGRADE_PAUSED            # maildivvy-backup reads it too
HELD = backup_run.HELD                            # maildivvy-backup reads it too
BACKUP_PAUSE_RECORD = status.STATUS.parent / backup_run.PAUSED   # a backup's own pause
BACKUPS = backup_run.BACKUPS
MANIFEST = "manifest.json"                        # a complete run holds it (backup/archive.py)
RELEASE_FILE = "VERSION"
PSQL = maildivvy_installed.PSQL
PYTHON = "/usr/bin/python3"
BACKUP_UNIT = "maildivvy-backup.service"
BACKUP_PROGRAM = "/opt/maildivvy/bin/maildivvy-backup"

# The timers a release added, with the release that added them. The way back to a release
# before one leaves it enabled and running a program that release does not have, failing at
# every tick: the old release's own run never names it, so the way back stops it.
TIMERS_SINCE = {"maildivvy-snapshot.timer": (0, 3, 0)}

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
    version: tuple | None = None   # what the version file says, or a used unfinished install's record
    first_version: bool = False    # our schema and no version file: installed before 0.1.0
    unfinished: bool = False       # a first install whose steps have not all passed yet


def _read(run, psql, account):
    """maildivvy_installed's reading, which step 1 of a control machine's run makes too."""
    found = maildivvy_installed.read(run=run, psql=psql, account=account)
    if found["error"] is not None:
        raise Refusal(f"cannot tell whether Maildivvy is installed: its database did not answer: {found['error']}")
    return found


def schema_versions(run=subprocess.run, psql=PSQL, account=pwd.getpwnam):
    """The migrations our database records, [] when there is no Maildivvy database."""
    return _read(run, psql, account)["versions"]


def used(run=subprocess.run, psql=PSQL, account=pwd.getpwnam):
    """Whether someone used our database: a row in an account, a domain or an external mailbox."""
    return _read(run, psql, account)["used"]


def installed(release=None, schema=schema_versions, used=used):
    """What of Maildivvy this machine holds, for installing `release`."""
    if VERSION_FILE.exists():
        return Found(version=parse_version(VERSION_FILE.read_text(), str(VERSION_FILE)))
    if UNFINISHED.exists():
        began = parse_version(UNFINISHED.read_text(), str(UNFINISHED))
        if began != release and used():
            # used before it finished: its data is the release that began it, and only an
            # upgrade from that one (a backup, the version rule) may migrate it
            return Found(version=began, unfinished=True)
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

    @property
    def still(self):
        """What the machine records after a failed upgrade: still the version it came from."""
        if self.unfinished:
            return f"There is no version file: the unfinished installation of {self.came_from} is still recorded."
        return f"The version file still says {self.came_from}."

    def says(self):
        if self.action == "install":
            again = " again: the first installation did not finish" if self.unfinished else ""
            return f"installing Maildivvy {shown(self.release)}{again}"
        if self.action == "reprove":
            return f"Maildivvy {shown(self.release)} is installed: every step is run again, and proves the machine"
        came_from = f"the unfinished installation of {self.came_from}" if self.unfinished else self.came_from
        return (f"upgrading Maildivvy from {came_from} to {shown(self.release)}: step 1's checks, a "
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
    return Plan("upgrade", release, old, unfinished=found.unfinished)


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


def finished(release, write=lambda line: None, systemd=None):
    """A run that was no upgrade passed every step: as write_version, and a failed upgrade's
    pause record goes too, since step 13 started the timers; left for the way back through
    this version's run, it would read as a pause in health. An upgrade's own record is its
    pause's, removed when the pause ends.

    ⛔ THE WAY BACK ENDS HERE, SO WHAT WAS HANDED TO THE UPGRADE IS STARTED HERE TOO. A
    restore run under the failed upgrade's record (its way back, step 1) stops the timers a
    reboot started and leaves them to the upgrade as a backup's record. Step 13
    starts nothing while that record is there, and this run is no upgrade, so without this
    the machine the way back brought back never collected again."""
    write_version(release)
    PAUSE_RECORD.unlink(missing_ok=True)
    resume_handed(systemd or pause.Systemd(), write)


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


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def wait_for_backup(systemd, sleep, write):
    """A backup already running stopped the timers and starts them again as it ends: it is
    waited out before the upgrade pauses. Its unit's timeout bounds it, systemd stopping it
    there (the backup role's `maildivvy_backup_run_timeout`)."""
    if systemd.busy_with(BACKUP_UNIT):
        write(f"waiting for the backup already running ({BACKUP_UNIT}) to finish, at most its "
              "unit's timeout: the upgrade pauses collection and takes its own after it")
        pause.wait_idle(systemd, sleep, lambda line: None, units=(BACKUP_UNIT,))


def take_backup(write, log, run=subprocess.run, status_path=status.STATUS, *, since):
    """One run of the backup's unit, as its timer does it; returns the stamp of the run,
    which must have been taken after `since`, the pause: `systemctl start` joins a run
    already going, whose dump is from before it."""
    journal_since = f"@{int(time.time())}"
    argv = ["systemctl", "start", BACKUP_UNIT]
    done = run(argv, capture_output=True, text=True)
    _logged(log, argv, done)
    if done.returncode != 0:
        # the program's own lines, not systemd's about the unit
        journal = ["journalctl", "-q", "-o", "cat", "--no-pager", f"_SYSTEMD_UNIT={BACKUP_UNIT}", "--since",
                   journal_since]
        said = run(journal, capture_output=True, text=True)
        _logged(log, journal, said)
        lines = [line for line in (said.stdout or "").splitlines() if line.strip()]
        own = [line for line in lines if line.startswith("maildivvy-backup:")] or lines
        raise Failed(f"{BACKUP_UNIT} failed: {own[-1] if own else (done.stderr or '').strip()}")
    after = status.read(status_path)
    if not after or after["stamp"] < archive.stamp_of(since):
        newest = f": the newest, {after['stamp']}, began before it" if after else ""
        raise Failed(f"{BACKUP_UNIT} ended and left no run taken since the pause in {status_path}{newest}")
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
    back = (f"Run the installer of {plan.came_from} again, from its unpacked release: it "
            + ("finishes the installation" if plan.unfinished else "re-proves the machine at that version")
            + ", starts collection and fan-out and removes the upgrade's records."
            if plan.installed else
            "Run the installation of the version from before 0.1.0 again, as you did, from your control "
            f"machine; it does not know the upgrade's records, so remove them after: sudo rm -f {PAUSE_RECORD} "
            f"{HELD}" + (f"; sudo rm -rf {held_copy(stamp)}." if held else "."))
    added = [timer for timer, since in TIMERS_SINCE.items()
             if plan.installed is None or plan.installed < since <= plan.release]
    store = ("the store from the copy that run made" if store_copy else
             "the store from your own copy of it (maildivvy_backup_store_copy is not set: the backup holds no store)")
    if from_earlier_run:
        lines = [f"The upgrade to {shown(plan.release)} failed. {plan.still} An earlier run applied the new "
                 f"migrations after backup {stamp} was taken"
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
        lines = [f"The upgrade to {shown(plan.release)} failed after backup {stamp} was taken. {plan.still}"]
    if held:
        lines.append("Collection and fan-out stay paused: the database has the new migrations, and the programs "
                     "running may be the old ones. The next installer run that finishes starts them again.")
    return [*lines,
            f"To go back to {plan.came_from}:",
            f"  1. Restore run {stamp} as the administration guide's Restore says: {store}, then "
            f"sudo {BACKUP_PROGRAM} --restore {stamp}.",
            f"  2. {back}",
            *([f"  3. Stop and disable what {plan.came_from} does not have, which would fail at every tick: "
               f"sudo systemctl disable --now {' '.join(added)}."] if added else []),
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
            was = (f"the unfinished installation of {plan.came_from} is as it was: finish it with that release's "
                   "installer" if plan.unfinished else f"Maildivvy {plan.came_from} is installed as it was")
            write(f"The upgrade stopped before any change: {because}{was}.")
            return
        for line in rollback(plan, earlier, store_copy, held, from_earlier_run=True):
            write(line)

    code = steps(preflight_only=True)
    if code != 0:
        stopped(f"step 1 refused (exit {code})")
        return FAILED
    systemd = systemd or pause.Systemd()
    wait_for_backup(systemd, sleep, write)
    PAUSE_RECORD.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with handed_back(systemd, write), pause.paused(systemd, sleep, write, record=PAUSE_RECORD,
                                                   owner={"by": "upgrade"}, keep=lambda: held):
        write("collection and fan-out are paused; taking a backup")
        try:
            stamp = backup(write, log, since=now())
            started = [timer for timer in pause.TIMERS if systemd.active(timer)]
            if started:
                raise Failed(f"active again after the backup: {', '.join(started)}; the migrations never run "
                             "with collection on")
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


@contextmanager
def handed_back(systemd, write):
    """Entered before the upgrade's pause, so it ends after it, whichever way the upgrade
    went: what a backup left to the upgrade is started on every way out that resumed
    collection (a failed backup, a step that failed after no migration), not on success
    alone."""
    try:
        yield
    finally:
        resume_handed(systemd, write)


def resume_handed(systemd, write):
    """The timers a backup stopped while the upgrade's pause was recorded, and left to it:
    started, and the backup's record removed. One naming no timer is removed too (a backup
    of a release that still left one, having stopped none): whatever reads the record,
    the import for one, takes its existence for a pause.

    Not while the upgrade's own record is there: it failed after its migrations, collection
    stays paused, and both records wait for the run that finishes. Not a restore's record:
    that restore is to be run again. Not while a backup runs: what it stopped is its own
    until it ends."""
    if PAUSE_RECORD.exists():
        return
    found = pause.read(BACKUP_PAUSE_RECORD)
    if not found or found.get("by") != "backup" or systemd.busy_with(BACKUP_UNIT):
        return
    if found["timers"]:
        write(f"starting what a backup left stopped during the upgrade: {', '.join(found['timers'])}")
        if pause.resume(systemd, found["timers"], write):
            return   # said above; the record stays, and a backup's run resumes from it
    BACKUP_PAUSE_RECORD.unlink(missing_ok=True)
