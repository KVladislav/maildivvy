"""Collection and fan-out paused around a backup or a restore, and always resumed.

⛔ STOPPING A TIMER DOES NOT STOP ITS RUN. A fetch holds its mailbox's lock and may run
for fifteen minutes; a pass holds its cursor rows. So the pause is two steps: the two
timers are stopped, then the pause WAITS until neither service is running or has a job
queued - it never kills one, and it sets no bound of its own: each unit's own
`TimeoutStartSec` bounds its run, and the backup's unit bounds the backup.

⛔ RESUMED WHATEVER HAPPENED INSIDE. The timers are started again in a `finally`, even
when the dump or the operator's command failed or the run was told to stop; one timer
that will not start does not keep the other stopped. Only a timer that was active
before is started: an operator who had stopped collection finds it still stopped.
"""

import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path

TIMERS = ("maildivvy-fetch.timer", "maildivvy-pass.timer")
SERVICES = ("maildivvy-fetch.service", "maildivvy-pass.service")
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


def wait_idle(systemd, sleep, say, poll=POLL):
    told = set()
    while True:
        busy = [unit for unit in SERVICES if systemd.busy_with(unit)]
        if not busy:
            return
        for unit in busy:
            if unit not in told:
                say(f"waiting for {unit} to finish its run")
                told.add(unit)
        sleep(poll)


def resume(systemd, timers, say):
    """Start each timer; every failure is said, and the first one raised after all tried."""
    errors = []
    for timer in timers:
        try:
            systemd.start(timer)
        except SystemdError as err:
            say(f"could not resume {timer}: {err}")
            errors.append(err)
    return errors


def read_record(record):
    """The timers a run recorded as stopped by it, or []: only ours, never anything else."""
    try:
        found = json.loads(Path(record).read_text())
    except (OSError, ValueError):
        return []
    return [timer for timer in TIMERS if isinstance(found, list) and timer in found]


def write_record(record, timers):
    """Replace the record whole: the stop's own unit reads it after a kill."""
    record = Path(record)
    partial = record.with_name(f".{record.name}.partial")
    partial.write_text(json.dumps(list(timers)))
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
def paused(systemd, sleep, say, poll=POLL, record=None, keep=None):
    """Stop both timers, wait for their runs, yield; then start again those that were on.

    ⛔ A KILLED RUN NEVER REACHES ITS `finally`. With `record`, what
    is stopped is written there first, the backup unit's ExecStopPost resumes from it
    (`resume_recorded`), and the next run resumes it too: a run killed before left the
    timers stopped, and a later run, finding them stopped, would never start them.

    `keep`, called at the end, may say to leave them stopped (an upgrade that failed after
    its migrations): nothing is started and the record stays for the next run."""
    stopped = read_record(record) if record else []
    failed = False
    try:
        for timer in TIMERS:
            if systemd.active(timer) and timer not in stopped:
                stopped.append(timer)   # before the stop: a stop that half-worked is resumed
        if record:
            write_record(record, stopped)
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
