"""The result of an import run: one line per file, then the totals.

    path<TAB>sha256<TAB>status<TAB>reason
    ...
    # total <n>
    # imported <n>
    # duplicate <n>
    # refused <n>
    # held before <n>
    # unrecorded <n>                     only when the pass recorded no row for some of them
    # stopped <why>                      only when the run stopped before the source's end

A run writes `<source>.import-<UTC>.tsv` beside the source unless it is named another
path, and `--dry-run` prints the same lines on the standard output and opens nothing for
writing. Each line is written and flushed as its file is done, so a run killed at any
point leaves the lines of every file it finished: the result files are the runs'
journal. `held before` is how many imported names the target folder held when the run
began, which accounts for a file renamed just before a stop that has no line anywhere.
`unrecorded` is how many imported names the pass moved its cursor past without a row:
it skipped them, and nobody gets them until each is recorded by hand.

A path is written with `\\`, a tab, a line feed and a carriage return escaped, so every
line has four fields.
"""

import datetime
import os
from pathlib import Path

from maildivvy.importer.source import DUPLICATE, IMPORTED, REFUSED

STATUSES = (IMPORTED, DUPLICATE, REFUSED)


def escape(text):
    return (str(text).replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")
            .replace("\r", "\\r"))


def path_for(source, now=None):
    """`<source>.import-<UTC>.tsv`, beside the source directory."""
    now = now or datetime.datetime.now(datetime.UTC)
    source = Path(source).resolve()
    return source.parent / f"{source.name}.import-{now.strftime('%Y%m%dT%H%M%SZ')}.tsv"


def open_new(path):
    """A result file of its own: never one that is there already, readable by its owner."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="\n")


class Result:
    """Counts each status and writes each line as it comes."""

    def __init__(self, out, held_before=0):
        self.out = out
        self.counts = dict.fromkeys(STATUSES, 0)
        self.held_before = held_before
        self.unrecorded = 0

    def line(self, record, status, reason=""):
        self.counts[status] += 1
        notes = "; ".join(part for part in (reason, *getattr(record, "notes", ())) if part)
        self.out.write("\t".join((escape(record.shown), record.sha256 or "", status,
                                  escape(notes))) + "\n")
        self.out.flush()

    @property
    def total(self):
        return sum(self.counts.values())

    def totals(self, stopped=None):
        lines = [f"# total {self.total}"] + [f"# {status} {self.counts[status]}"
                                             for status in STATUSES]
        lines.append(f"# held before {self.held_before}")
        if self.unrecorded:
            lines.append(f"# unrecorded {self.unrecorded}")
        if stopped:
            lines.append(f"# stopped {escape(stopped)}")
        self.out.write("\n".join(lines) + "\n")
        self.out.flush()
