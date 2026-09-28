"""How the checks read the machine: a command, a unit's properties, the journal over a
window, a TLS endpoint. Every reader raises `Unreadable` when it cannot take its reading,
and the check that asked becomes UNKNOWN; none of them answers "nothing" for "could not
look".
"""

import datetime
import json
import re
import socket
import ssl
import subprocess

TIMEOUT = 60
LOCAL = "127.0.0.1"


class Unreadable(Exception):
    """A reading that could not be taken. The message says what was asked and why."""


def command(argv, timeout=TIMEOUT, input=None, check=False):
    """Run `argv` (never through a shell) and return the finished process.

    ⛔ The exit code is read from the process itself, never through a pipe.
    """
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input,
                              errors="replace")
    except FileNotFoundError:
        raise Unreadable(f"{argv[0]} is not installed") from None
    except (OSError, subprocess.SubprocessError) as err:
        raise Unreadable(f"{' '.join(argv[:3])}: {err}") from None
    if check and done.returncode != 0:
        said = (done.stderr or done.stdout).strip().splitlines()
        raise Unreadable(f"{' '.join(argv[:3])} exited {done.returncode}"
                         + (f": {said[-1]}" if said else ""))
    return done


def show(unit, *properties):
    """`systemctl show`'s answer for these properties, as {name: value}."""
    argv = ["systemctl", "show", unit] + [f"--property={name}" for name in properties]
    out = command(argv, check=True).stdout
    found = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    missing = [name for name in properties if name not in found]
    if missing:
        raise Unreadable(f"systemctl show {unit} answered no {', '.join(missing)}")
    return found


def state(unit):
    """The word `systemctl is-active` prints, or Unreadable: it prints the state even when
    it exits non-zero, so the word is what is read."""
    word = command(["systemctl", "is-active", unit]).stdout.strip()
    if not word:
        raise Unreadable(f"systemctl is-active {unit} answered nothing")
    return word


def is_active(unit):
    """True or False, or Unreadable. ⚠️ A oneshot service is `activating` for the whole of
    its run and never `active`: whether one runs is `state(unit) in RUNNING`."""
    return state(unit) == "active"


# the states of a unit with something going: a oneshot runs `activating`, and stops
# `deactivating` through its ExecStopPost
RUNNING = ("activating", "active", "deactivating", "reloading")


def timestamp(value):
    """A timestamp as `systemctl show` prints it (`Wed 2026-09-23 11:47:02 UTC`); None
    for the empty value systemd prints when it never happened."""
    value = value.strip()
    if not value or value == "n/a":
        return None
    match = re.match(r"^\w{3} (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+)$", value)
    if not match:
        raise Unreadable(f"cannot read the time {value!r}")
    moment = datetime.datetime.fromisoformat(match.group(1))
    if match.group(2) == "UTC":
        return moment.replace(tzinfo=datetime.timezone.utc)
    return moment.astimezone()  # the machine's own zone, as systemd printed it


def journal(since, *match, until=None):
    """The journal's messages since `since`, for the given `FIELD=value` matches or `-u`
    units, as a list of strings.

    ⛔ THE WINDOW IS WRITTEN OUT AS AN EPOCH, never as a clock time:
    `--since '23:36'` is resolved against today, so after midnight the window lies in the
    future and the answer is `-- No entries --` with exit 0 - exactly what a quiet,
    healthy machine looks like. A caller pairs every must-be-empty window with a control.
    """
    argv = ["journalctl", "--no-pager", "--quiet", "-o", "cat",
            f"--since=@{int(since.timestamp())}"]
    if until is not None:
        argv.append(f"--until=@{int(until.timestamp())}")
    argv.extend(match)
    done = command(argv, timeout=120)
    if done.returncode != 0:
        raise Unreadable(f"journalctl exited {done.returncode}: {done.stderr.strip()[:200]}")
    return done.stdout.splitlines()


def finished_start_job(lines):
    """(moment, result) of the newest start job that finished, from `journalctl -o json` lines
    of one unit's `JOB_TYPE=start` entries; None when none did.

    systemd 259 journals a start job twice (measured 2026-09-23): `Starting ...` with no
    JOB_RESULT, then its end with JOB_RESULT `done`, or `failed` for a failed oneshot. A
    run still going has the first line only, and the run before it is the last one read.
    """
    for line in reversed(lines):
        entry = json.loads(line)
        if entry.get("JOB_RESULT"):
            micros = int(entry["__REALTIME_TIMESTAMP"])
            moment = datetime.datetime.fromtimestamp(micros / 1_000_000, datetime.timezone.utc)
            return moment, entry["JOB_RESULT"]
    return None


def last_start_job(unit, entries=20):
    """The unit's newest finished start job in the journal, across boots: see
    finished_start_job. systemd itself forgets a oneshot's last run at every boot."""
    done = command(["journalctl", "--no-pager", "--quiet", "-o", "json", "-n", str(entries),
                    f"UNIT={unit}", "JOB_TYPE=start"], timeout=120)
    if done.returncode != 0:
        raise Unreadable(f"journalctl exited {done.returncode}: {done.stderr.strip()[:200]}")
    return finished_start_job([line for line in done.stdout.splitlines() if line.strip()])


def tls_context(cafile):
    """Verification against the system trust store (`cafile` None), or against exactly the
    published certificate as its own anchor - never verification turned off.
    Python's default context accepts a chain that ends at a certificate it was given
    (`VERIFY_X509_PARTIAL_CHAIN`), which is how a staging or self-signed leaf is trusted.
    """
    context = ssl.create_default_context(cafile=cafile)
    context.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    return context


def tls_session(port, name, cafile, timeout=20, host=LOCAL):
    """A TLS connection to `host:port` verified for `name`; the caller closes it."""
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return tls_context(cafile).wrap_socket(raw, server_hostname=name)
    except BaseException:
        raw.close()
        raise


def served_certificate(port, name, cafile, timeout=20):
    """The DER certificate the endpoint serves, verified for `name`, or Unreadable."""
    try:
        with tls_session(port, name, cafile, timeout) as conn:
            return conn.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as err:
        raise Unreadable(f"{LOCAL}:{port} as {name}: {err}") from None


def lines_of(conn, until, limit=65536):
    """Read from a socket until `until(buffer)` is true or the peer closes."""
    buffer = b""
    while not until(buffer) and len(buffer) < limit:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buffer += chunk
    return buffer.decode("utf-8", "replace")


def load_json(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as err:
        raise Unreadable(f"{path}: {err}") from None
