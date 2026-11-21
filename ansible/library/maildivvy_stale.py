#!/usr/bin/python
"""Whether a daemon runs the configuration on disk: is any of its configuration newer than
the last time the daemon read it? Changes nothing.

A run stopped between writing a daemon's files and restarting it leaves the daemon on its
old configuration, and every later run finds the files already as it would write them, so
"restart when this run wrote" never restarts it. The daemon is asked instead: when its
unit last became active, or its container last started, or, for a daemon that is also
reloaded, the last line it logged on reading its configuration. A path that is a
directory counts with everything in it, so a file removed from it counts too.
"""

import json
import os
import re
import subprocess
from datetime import datetime, timezone

DOCUMENTATION = r"""
module: maildivvy_stale
short_description: Is any of a daemon's configuration newer than the daemon's last read of it?
description: Returns stale (a bool), newer (the paths newer than that read) and loaded (its time, or null).
options:
  paths: {type: list, elements: str, required: true}
  unit: {type: str, description: the systemd unit whose ActiveEnterTimestamp is a read}
  container: {type: str, description: the container whose StartedAt is a read}
  reloaded: {type: dict, description: "a journal line that is a read too: identifier and match (a pattern)"}
"""


def mtimes(paths):
    """{path: mtime} for every path that exists, and for everything under a directory."""
    found = {}
    for path in paths:
        if not os.path.lexists(path):
            continue
        found[path] = os.lstat(path).st_mtime
        if os.path.isdir(path) and not os.path.islink(path):
            for top, dirs, files in os.walk(path):
                for name in dirs + files:
                    entry = os.path.join(top, name)
                    found[entry] = os.lstat(entry).st_mtime
    return found


def _read(run, argv):
    done = run(argv, capture_output=True, text=True)
    return done.stdout.strip() if done.returncode == 0 else ""


def unit_started(unit, run=subprocess.run):
    """When the unit last became active, in seconds since the epoch; None if never."""
    text = _read(run, ["systemctl", "show", "-P", "ActiveEnterTimestamp", "--timestamp=us+utc", unit])
    # the weekday in front is in the machine's language, so it is not read
    match = re.fullmatch(r"\S+ (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6}) UTC", text)
    if not match:                           # empty, or "n/a": the unit has not been active
        return None
    return datetime.strptime(match[1], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()


def container_started(container, run=subprocess.run):
    """When the container last started; None if there is no such container."""
    text = _read(run, ["docker", "inspect", "--format", "{{.State.StartedAt}}", container])
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z", text)
    if not match or match[1].startswith("0001-"):   # Docker's zero time: created, never started
        return None
    started = datetime.fromisoformat(match[1]).replace(tzinfo=timezone.utc).timestamp()
    return started + float("0." + (match[2] or "0"))


def logged(identifier, pattern, run=subprocess.run):
    """When the daemon last logged a line matching the pattern; None if the journal holds none."""
    text = _read(run, ["journalctl", "-q", "-t", identifier, "-g", pattern, "-n", "1", "-o", "json",
                       "--output-fields=MESSAGE", "--no-pager"])
    try:
        return int(json.loads(text.splitlines()[0])["__REALTIME_TIMESTAMP"]) / 1_000_000
    except (IndexError, KeyError, ValueError):
        return None


def stale(paths, unit=None, container=None, reloaded=None, run=subprocess.run):
    """{"stale": bool, "newer": [paths], "loaded": seconds or None}. A daemon never started is stale."""
    reads = [unit_started(unit, run) if unit else None,
             container_started(container, run) if container else None,
             logged(reloaded["identifier"], reloaded["match"], run) if reloaded else None]
    reads = [read for read in reads if read is not None]
    loaded = max(reads) if reads else None
    newer = sorted(path for path, mtime in mtimes(paths).items() if loaded is None or mtime > loaded)
    return {"stale": loaded is None or bool(newer), "newer": newer, "loaded": loaded}


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={"paths": {"type": "list", "elements": "str", "required": True},
                       "unit": {"type": "str"}, "container": {"type": "str"}, "reloaded": {"type": "dict"}},
        required_one_of=[("unit", "container")], mutually_exclusive=[("unit", "container")],
        supports_check_mode=True)
    module.exit_json(changed=False, **stale(**module.params))


if __name__ == "__main__":
    main()
