"""`maildivvy-health`: run the checks and report them.

    maildivvy-health                        every subsystem; text, the JSON file, the exit code
    maildivvy-health --subsystem <name>     one subsystem; text and the exit code only
    maildivvy-health --cached [--subsystem <name>]
                                            no check run: the JSON file as a collector reads
                                            it, a stale one UNKNOWN
    maildivvy-health --quiet                the first line and what is not PASS (the timer)
    maildivvy-health --format prometheus    any of the above in Prometheus's text format
    maildivvy-health --textfile-dir <dir>   a run of every subsystem also writes
                                            <dir>/maildivvy.prom for node_exporter

The exit code is the worst state's: 0 PASS, 1 WARN, 2 FAIL, 3 UNKNOWN. A run that cannot
run at all - its settings refused, a program error - is 3 and writes no file, so the file
goes stale and a collector reads UNKNOWN: the checks have stopped.

Only a run of every subsystem writes `/var/lib/maildivvy/health/health.json`, and the
textfile when a directory is given: a run of one never replaces a whole report with part
of one.
"""
# The records behind it, and for the Prometheus output.

import argparse
import datetime
import sys
import traceback

from maildivvy.health import checks, report, settings
from maildivvy.health.report import UNKNOWN


def parser():
    p = argparse.ArgumentParser(prog="maildivvy-health", description=__doc__.split("\n\n")[0])
    p.add_argument("--subsystem", choices=list(checks.SUBSYSTEMS), help="report this one alone")
    p.add_argument("--cached", action="store_true",
                   help="read the last report from its file instead of running the checks")
    p.add_argument("--quiet", action="store_true", help="print only what is not PASS (text only)")
    p.add_argument("--format", choices=("text", "prometheus"), default="text",
                   help="what is printed: text for a person, or Prometheus's text format")
    p.add_argument("--textfile-dir", metavar="DIR",
                   help=f"a run of every subsystem also writes DIR/{report.TEXTFILE}, for "
                        "node_exporter's textfile collector")
    p.add_argument("--conf", default=str(settings.CONF), help=argparse.SUPPRESS)
    p.add_argument("--report", default=str(settings.REPORT), help=argparse.SUPPRESS)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        conf = settings.read(args.conf)
        now = datetime.datetime.now(datetime.timezone.utc)
        if args.cached:
            whole = report.read_json(args.report, now,
                                     datetime.timedelta(minutes=conf.stale_minutes))
            if args.subsystem:
                whole = whole.only(args.subsystem)
        else:
            whole = checks.run([args.subsystem] if args.subsystem else None, conf=conf, now=now)
            if not args.subsystem:
                report.write_json(args.report, whole)
                if args.textfile_dir:
                    report.write_textfile(args.textfile_dir, whole)
    except Exception as err:  # the checks did not run, or their result could not be kept: say so
        said = f"{UNKNOWN} maildivvy-health could not run: {type(err).__name__}: {err}"
        # in Prometheus's format each line a comment, so a scrape of it still parses
        prefix = "# " if args.format == "prometheus" else ""
        sys.stdout.write("".join(f"{prefix}{line}\n" for line in said.splitlines()))
        traceback.print_exc(file=sys.stderr)
        return report.exit_code(UNKNOWN)
    if args.format == "prometheus":
        sys.stdout.write(report.to_prometheus(whole))
    else:
        sys.stdout.write(report.text(whole, quiet=args.quiet))
    return report.exit_code(whole.state)
