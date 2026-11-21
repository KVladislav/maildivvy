"""Collection and fan-out paused around a backup or a restore, and always resumed.

⛔ STOPPING A TIMER DOES NOT STOP ITS RUN. A fetch holds its mailbox's lock and may run
for fifteen minutes; a pass holds its cursor rows, and a refetch beside it writes the
fetch state; a run of a snapshot's slices writes into the store and its rows
for up to an hour. So the pause is two steps: the timers are stopped, then the pause
WAITS until none of the services is running or has a job queued - it never kills one,
and it sets no bound of its own: each unit's own `TimeoutStartSec` bounds its run, and
the backup's unit bounds the backup.

⛔ RESUMED WHATEVER HAPPENED INSIDE. The timers are started again in a `finally`, even
when the dump or the operator's command failed or the run was told to stop; one timer
that will not start does not keep the other stopped. Only a timer that was active
before is started: an operator who had stopped collection finds it still stopped. A
timer not installed when the pause begins is one that what runs inside it installs (an
upgrade to the release that adds it, as added the snapshot's): nobody can have
stopped it, so it is started with the rest, and passed if it is still not there.

⛔ THE RECORD IS THE PAUSE, NOT THE STOPPED TIMERS. The fetch, the pass, the
requests and the snapshot units carry `ConditionPathExists=!` on this record and on an
upgrade's: while either is there, a start is skipped, whoever asks for it - a timer a
reboot started, a re-run of the install, an operator by hand. So the record is written
before the first stop and removed only after the last start: a timer that fires between
the start and the removal runs nothing, and its next period runs.

⛔ ONE OWNER STARTS WHAT IT STOPPED. A pause's record says who stopped the timers:
`{"by": "backup" | "restore" | "upgrade", "timers": [...]}`, a restore's with its
`stamp`. A pause that finds the timers already stopped records none of them as its own,
so it never starts timers another pause stopped (`maildivvy-backup` and the installer
say how each keeps out of the other's way).
"""

import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path

TIMERS = ("maildivvy-fetch.timer", "maildivvy-pass.timer", "maildivvy-snapshot.timer")
# The pass's timer starts the requests unit too, by the pass's Wants=: a refetch
# it runs writes the fetch state the backup dumps, so its run is waited for as well.
SERVICES = ("maildivvy-fetch.service", "maildivvy-pass.service", "maildivvy-requests.service",
            "maildivvy-snapshot.service")
IDLE = ("inactive", "failed")
POLL = 2.0   # seconds between two readings of a service still running


class SystemdError(Exception):
    """systemctl refused or failed. The message names the unit."""


class Systemd:
    """The few systemctl questions and acts the pause needs."""

    def __init__(self, run=subprocess.run):
        self.run = run

    def _systemctl(self, *argv):
        done = self.run(["systemctl", *argv], capture_output=True, text=True)
        return done

    def active(self, unit):
        return self._systemctl("is-active", "--quiet", unit).returncode == 0

    def installed(self, unit):
        """Whether systemd has the unit at all: `LoadState` is `not-found` for one never
        installed (measured, systemd 259)."""
        done = self._systemctl("show", "-p", "LoadState", "--value", unit)
        return done.returncode != 0 or done.stdout.strip() != "not-found"

    def _act(self, verb, unit):
        done = self._systemctl(verb, unit)
        if done.returncode != 0:
            raise SystemdError(f"systemctl {verb} {unit} exited {done.returncode}: "
                               f"{(done.stderr or done.stdout).strip()}")

    def stop(self, unit):
        self._act("stop", unit)

    def start(self, unit):
        """⚠️ Measured, systemd 259: a unit started five times in ten seconds is refused
        `start-limit-hit` and stays stopped. On a timer the limit protects nothing, and a
        timer left stopped is collection left stopped, so it is cleared and tried again."""
        try:
            self._act("start", unit)
        except SystemdError:
            self._systemctl("reset-failed", unit)
            self._act("start", unit)

    def busy_with(self, unit):
        """Running, starting, stopping, or with a job queued for it (measured: systemd 259
        reports `Job=<id>` while a start is queued, and `activating` while a oneshot runs)."""
        done = self._systemctl("show", "-p", "ActiveState", "-p", "Job", unit)
        if done.returncode != 0:
            raise SystemdError(f"systemctl show {unit} exited {done.returncode}: "
                               f"{done.stderr.strip()}")
        shown = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
        return shown.get("ActiveState") not in IDLE or shown.get("Job", "") != ""


def wait_idle(systemd, sleep, say, poll=POLL, units=SERVICES):
    told = set()
    while True:
        busy = [unit for unit in units if systemd.busy_with(unit)]
        if not busy:
            return
        for unit in busy:
            if unit not in told:
                say(f"waiting for {unit} to finish its run")
                told.add(unit)
        sleep(poll)


def resume(systemd, timers, say):
    """Start each timer; every failure is said, and the first one raised after all tried. A
    timer nothing installed is passed: there is nothing to start."""
    errors = []
    for timer in timers:
        if not systemd.installed(timer):
            continue
        try:
            systemd.start(timer)
        except SystemdError as err:
            say(f"could not resume {timer}: {err}")
            errors.append(err)
    return errors


def read(record):
    """The record as {"by": ..., "timers": [...]} (a restore's with its "stamp"), or None
    when there is none. Only our timers are ever read from it. A bare list is a record from
    before it named its owner: `by` None."""
    try:
        found = json.loads(Path(record).read_text())
    except (OSError, ValueError):
        return None
    if isinstance(found, list):
        found = {"by": None, "timers": found}
    if not isinstance(found, dict):
        return None
    listed = found.get("timers")
    timers = [timer for timer in TIMERS if isinstance(listed, list) and timer in listed]
    return {**found, "timers": timers}


def read_record(record):
    """The timers a run recorded as stopped by it, or []."""
    found = read(record)
    return found["timers"] if found else []


def write_record(record, timers, owner):
    """Replace the record whole: the stop's own unit reads it after a kill. 0644 whatever
    the mask (the backup unit's is 0077): health, as its own user, names the pause from it."""
    record = Path(record)
    partial = record.with_name(f".{record.name}.partial")
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o644)
        handle.write(json.dumps({**owner, "timers": list(timers)}))
    os.replace(partial, record)


def resume_recorded(systemd, record, say):
    """What the backup unit's ExecStopPost runs: start the timers a run that did not reach
    its own resume recorded, then forget them. 0 when nothing is left stopped."""
    timers = read_record(record)
    errors = resume(systemd, timers, say)
    if errors:
        return 1
    Path(record).unlink(missing_ok=True)
    return 0


@contextmanager
def paused(systemd, sleep, say, poll=POLL, record=None, owner=None, keep=None):
    """Stop both timers, wait for their runs, yield; then start again those that were on.

    ⛔ A KILLED RUN NEVER REACHES ITS `finally`. With `record`, what
    is stopped is written there first, the backup unit's ExecStopPost resumes from it
    (`resume_recorded`), and the next run resumes it too: a run killed before left the
    timers stopped, and a later run, finding them stopped, would never start them. `owner`
    is who the record names, {"by": ...}: the timers it lists become this run's.

    `keep`, called at the end, may say to leave them stopped (an upgrade that failed after
    its migrations): nothing is started and the record stays for the next run."""
    stopped = read_record(record) if record else []
    failed = False
    try:
        for timer in TIMERS:
            # before the stop: a stop that half-worked is resumed. A timer not installed yet
            # is one what runs inside the pause installs: started after it, as if it had been on
            if timer not in stopped and (systemd.active(timer) or not systemd.installed(timer)):
                stopped.append(timer)
        if record:
            write_record(record, stopped, owner or {})
        for timer in stopped:
            if systemd.active(timer):
                systemd.stop(timer)
        wait_idle(systemd, sleep, say, poll)
        yield tuple(stopped)
    except BaseException:
        failed = True
        raise
    finally:
        if keep is not None and keep():
            say(f"left stopped: {', '.join(stopped) or 'no timer was running'}")
        else:
            errors = resume(systemd, stopped, say)
            if record and not errors:
                Path(record).unlink(missing_ok=True)
            if errors and not failed:
                raise errors[0]
