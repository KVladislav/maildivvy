"""The health report: four states, checks and subsystems, and the three outputs of one run.

⛔ FAIL OUTRANKS UNKNOWN. The source's check exited UNKNOWN
at the first section it could not read and threw away the FAILs it had already
collected: both scanners were down and it said UNKNOWN. Here every subsystem is read on
its own and the order is PASS < WARN < UNKNOWN < FAIL, so a reading that could not be
taken is reported beside a problem already found and never instead of it.

⛔ UNKNOWN IS NEVER PASS. Nothing read at all - a subsystem with
no check, a run with no subsystem, a JSON file that is missing, truncated or stale - is
UNKNOWN.

The outputs of one run: text for a person, a JSON file for a collector, written
atomically, and the plugin exit code of the worst state (0 PASS, 1 WARN, 2 FAIL,
3 UNKNOWN); and, amended by, the same run in Prometheus's text format, printed
or written into a textfile collector's directory. A collector that reads the file reads
its timestamp too: a file older than the schedule allows reads UNKNOWN, because the
checks themselves have stopped - except where it held a FAIL, which stays a FAIL until a
reading shows otherwise.
"""

import datetime
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

PASS, WARN, FAIL, UNKNOWN = "PASS", "WARN", "FAIL", "UNKNOWN"
STATES = (PASS, WARN, UNKNOWN, FAIL)  # in order, the last the worst
EXIT = {PASS: 0, WARN: 1, FAIL: 2, UNKNOWN: 3}
FORMAT = 1


def worst(states):
    """The worst of `states` in PASS < WARN < UNKNOWN < FAIL; UNKNOWN for none at all."""
    states = list(states)
    if not states:
        return UNKNOWN
    return max(states, key=STATES.index)


def exit_code(state):
    return EXIT[state]


@dataclass(frozen=True)
class Check:
    """One reading: what was read, and when it is not PASS, what is wrong in a sentence."""

    name: str
    state: str
    reading: str
    problem: str | None = None

    def __post_init__(self):
        if self.state not in STATES:
            raise ValueError(f"{self.name}: {self.state!r} is not one of {', '.join(STATES)}")
        if self.state != PASS and not self.problem:
            raise ValueError(f"{self.name}: a check that is {self.state} says what is wrong")

    def as_dict(self):
        return {"name": self.name, "state": self.state, "reading": self.reading,
                "problem": self.problem}


@dataclass
class Subsystem:
    name: str
    checks: list = field(default_factory=list)

    @property
    def state(self):
        return worst(check.state for check in self.checks)

    def as_dict(self):
        return {"name": self.name, "state": self.state,
                "checks": [check.as_dict() for check in self.checks]}


@dataclass
class Report:
    taken_at: datetime.datetime
    subsystems: list

    @property
    def state(self):
        return worst(subsystem.state for subsystem in self.subsystems)

    def only(self, name):
        """One subsystem of the report as a report of its own; UNKNOWN if it holds none."""
        found = [s for s in self.subsystems if s.name == name]
        if not found:
            found = [Subsystem(name, [Check("reading", UNKNOWN, "not in the report",
                                            f"the report holds no subsystem {name}")])]
        return Report(self.taken_at, found)


# --- text -------------------------------------------------------------------------------------


def text(whole, quiet=False):
    """One block per subsystem, each check with its reading and, when not PASS, what is
    wrong. `quiet` keeps the first line and what is not PASS: the timer's journal."""
    stamp = whole.taken_at.isoformat(timespec="seconds")
    lines = [f"{whole.state} maildivvy-health at {stamp}"]
    for subsystem in whole.subsystems:
        if quiet and subsystem.state == PASS:
            continue
        lines.append(f"{subsystem.state} {subsystem.name}")
        for check in subsystem.checks:
            if quiet and check.state == PASS:
                continue
            lines.append(f"  {check.state} {check.name}: {check.reading}")
            if check.state != PASS:
                lines.append(f"      {check.problem}")
    return "\n".join(lines) + "\n"


# --- the JSON file ----------------------------------------------------------------------------


def to_json(whole):
    return json.dumps({"format": FORMAT, "taken_at": whole.taken_at.isoformat(),
                       "state": whole.state,
                       "subsystems": [s.as_dict() for s in whole.subsystems],
                       "complete": True}, indent=2) + "\n"


def replace_whole(path, content):
    """Replace the file whole, world-readable: a collector never reads half of one."""
    path = Path(path)
    temporary = path.with_name(f".{path.name}.partial")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o644)  # the unit's mask is 0077
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def write_json(path, whole):
    replace_whole(path, to_json(whole))


# --- Prometheus -------------------------------------------------------------------------------
# A third rendering of the same run: each state as its plugin exit code, so a
# number means what the command's exit means. ⚠️ The numbers are not the severity order:
# UNKNOWN is 3 and FAIL, the worst, is 2, so an alert compares with `== 2` and `== 3`.

# node_exporter's textfile collector reads `*.prom` in its directory; the half-written file
# is `.maildivvy.prom.partial`, which it skips.
TEXTFILE = "maildivvy.prom"

HELP = {
    "maildivvy_check_state": "State of one health check: 0 PASS, 1 WARN, 2 FAIL, 3 UNKNOWN.",
    "maildivvy_subsystem_state": "State of one health subsystem, its worst check: "
                                 "0 PASS, 1 WARN, 2 FAIL, 3 UNKNOWN.",
    "maildivvy_health_last_run_timestamp_seconds": "When the reported health checks were taken, "
                                                   "in seconds since the epoch.",
}


def label_value(value):
    """A label value as the exposition format writes it: backslash, quote and newline escaped."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def labels(**pairs):
    return "{" + ",".join(f'{key}="{label_value(value)}"' for key, value in pairs.items()) + "}"


def to_prometheus(whole):
    samples = {
        "maildivvy_check_state": [f"{labels(subsystem=s.name, check=c.name)} {EXIT[c.state]}"
                                  for s in whole.subsystems for c in s.checks],
        "maildivvy_subsystem_state": [f"{labels(subsystem=s.name)} {EXIT[s.state]}"
                                      for s in whole.subsystems],
        "maildivvy_health_last_run_timestamp_seconds": [f" {whole.taken_at.timestamp():.3f}"],
    }
    lines = []
    for name, found in samples.items():
        if found:
            lines += [f"# HELP {name} {HELP[name]}", f"# TYPE {name} gauge"]
            lines += [name + sample for sample in found]
    return "\n".join(lines) + "\n"


def write_textfile(directory, whole):
    """The textfile collector's file in `directory`, replaced whole."""
    replace_whole(Path(directory) / TEXTFILE, to_prometheus(whole))


# The checks a reader of the file adds of its own: the file could not be read at all, or it
# is older than the schedule allows. The interface tells the two apart by these names.
REPORT_FILE = "report file"
FRESHNESS = "freshness"


def unreadable(path, why, now):
    return Report(now, [Subsystem("health", [Check(REPORT_FILE, UNKNOWN, str(path), why)])])


def read_json(path, now, stale_after):
    """The report a run wrote, as a collector should read it.

    Missing, unparseable or incomplete: UNKNOWN. Older than `stale_after` (or from the
    future): every subsystem gains an UNKNOWN check saying the checks have stopped, so a
    stale PASS reads UNKNOWN and a stale FAIL stays FAIL.
    """
    try:
        data = json.loads(Path(path).read_text())
    except OSError as err:
        return unreadable(path, f"cannot read the report: {err.strerror}", now)
    except ValueError:
        return unreadable(path, "the report is not whole JSON: a run was cut short", now)
    try:
        if not isinstance(data, dict) or data.get("complete") is not True:
            raise ValueError("the report does not say it is complete")
        taken_at = datetime.datetime.fromisoformat(data["taken_at"])
        if taken_at.tzinfo is None:          # a run writes UTC; a time with no zone has no age
            raise ValueError("the report's time names no zone")
        subsystems = [Subsystem(s["name"], [Check(c["name"], c["state"], c["reading"], c["problem"])
                                            for c in s["checks"]])
                      for s in data["subsystems"]]
    except (KeyError, TypeError, ValueError) as err:
        return unreadable(path, f"the report is not one this program writes: {err}", now)
    whole = Report(taken_at, subsystems)
    age = now - taken_at
    if age > stale_after or age < -datetime.timedelta(minutes=5):
        reading = f"taken at {taken_at.isoformat(timespec='seconds')}"
        why = (f"the last reading is {int(age.total_seconds() // 60)} min old, older than "
               f"{int(stale_after.total_seconds() // 60)} min: the checks have stopped")
        if age < datetime.timedelta(0):
            why = "the last reading is dated in the future: the clock or the file is wrong"
        for subsystem in whole.subsystems:
            subsystem.checks.append(Check(FRESHNESS, UNKNOWN, reading, why))
        if not whole.subsystems:
            whole.subsystems.append(Subsystem("health", [Check(FRESHNESS, UNKNOWN, reading, why)]))
    return whole
