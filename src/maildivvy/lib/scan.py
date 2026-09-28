"""The two scanners, over unix sockets, with our own size gate in front of both.

⛔ Four verdicts that never collapse into one another:

    clean        looked at, found nothing          -> delivered
    infected     found something                   -> withheld, a report in its place
    unscanned    over the size limit; nobody looked -> withheld, a report saying so
                 (or cut short at one of the scanner's own limits, which it names)
    unavailable  the scanner could not be reached,  -> the delivery filter holds the
                 or failed and said ERROR              message at the provider,
                                                       the milter answers 451

`unscanned` is one message that is too big; `unavailable` is every message at once.

⛔ The size gate is ours and it runs before any socket is contacted.
ClamAV has two limits that behave differently: a stream over `StreamMaxLength` gets
an error and a closed connection - no verdict - while the same bytes under
`MaxFileSize` are answered `OK`. A caller that watches only for errors therefore
reads an oversize message as clean. The gate is the lower of the two the daemon runs
with, read from its configuration file; the install sets both, and
proves the running daemon applies them by streaming one byte over the limit.

⛔ The scanner is handed bytes, never a path. The store is readable only
by the mail owner and the message is not a file yet, so a scanner that cannot reach
the store cannot damage it through a misconfiguration.

⛔ A failure of the spam scanner is no score, never spam. So is an answer
that is not an object and a score that is not a finite number; the action word is
passed on as given and decides nothing (the score is compared with the receiving
domain's threshold).
"""

import json
import math
import re
import socket
import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path

CLAMD_SOCKET = Path("/run/clamav/clamd.ctl")
CLAMD_CONF = Path("/etc/clamav/clamd.conf")
RSPAMD_SOCKET = Path("/run/maildivvy/rspamd/rspamd.sock")

CHUNK = 65536
CLAMD_TIMEOUT = 120  # seconds; a scan of a message, not of an archive of them
RSPAMD_TIMEOUT = 60
# clamd's own default for StreamMaxLength and MaxFileSize, used for a limit its
# configuration does not state: the lower reading is the safe one, since it withholds
# a message as `unscanned` rather than calling an unscanned one clean.
CLAMD_DEFAULT_LIMIT = 25 * 1024 * 1024
SIZE = re.compile(r"^(\d+)([KMG]?)$", re.IGNORECASE)
SUFFIX = {"": 1, "K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}
VERSION_LINE = re.compile(r"^ClamAV (?P<engine>[0-9][0-9a-zA-Z.\-]*)/(?P<sigs>\d+)/(?P<built>.+)$")
CURRENT_CVD = "current.cvd.clamav.net"  # the record freshclam reads (DNSDatabaseInfo)

CLEAN, INFECTED, UNSCANNED, UNAVAILABLE = "clean", "infected", "unscanned", "unavailable"

# The only ERROR that is a verdict about the message: the stream was past the daemon's
# `StreamMaxLength` (measured on clamd 1.5.4). Every other ERROR is the daemon failing.
SIZE_LIMIT_ERROR = "INSTREAM size limit exceeded. ERROR"
# What the daemon names a scan it cut short at MaxFileSize, MaxScanSize, MaxRecursion or
# MaxScanTime, with `AlertExceedsMax` set. Without it such a scan answers `OK` (measured).
LIMITS_EXCEEDED = "Heuristics.Limits.Exceeded."

# ⛔ ONE VALUE, THREE PLACES THAT MAY NOT DRIFT:
# the spam scanner's top band (`reject` in the rspamd role's `actions.conf`), the CHECK on
# `domain.spam_threshold` in `schema/0001_initial.sql`, and the bound the interface
# enforces on that field. A message the scanner rejects outright is then at or above every
# threshold a domain may hold, and needs no special case. A test ties the three
# (tests/unit/test_rspamd_role.py), and the installed machine is read back against its own
# database. Moving it moves the schema's bound with it,
# in a migration of its own.
TOP_SCORE = Decimal("150.00")


@dataclass(frozen=True)
class Verdict:
    """What the antivirus said, with the detail that says why."""

    verdict: str
    detail: str | None = None

    @property
    def withheld(self):
        """The two verdicts that keep a message from its readers."""
        return self.verdict in (INFECTED, UNSCANNED)


@dataclass(frozen=True)
class Score:
    """What the spam scanner said. `score` is None when there is no score at all."""

    score: float | None
    action: str
    detail: str | None = None


@dataclass(frozen=True)
class Version:
    """A ClamAV version reading: the engine, its signature set and when that was built."""

    engine: str
    signatures: int
    signatures_built: datetime | None


# --- the size gate ------------------------------------------------------------------------------


def size_limit(conf=CLAMD_CONF):
    """The lower of the daemon's two limits, in bytes.

    A limit the file does not state reads as clamd's own default. A limit that is
    there but is not a size is refused: a number nobody can read is never guessed at.
    """
    values = {}
    try:
        text = Path(conf).read_text()
    except OSError:
        text = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        name, _, value = line.partition(" ")
        if name in ("StreamMaxLength", "MaxFileSize"):
            values[name] = parse_size(name, value.strip())
    return min(values.get("StreamMaxLength", CLAMD_DEFAULT_LIMIT),
               values.get("MaxFileSize", CLAMD_DEFAULT_LIMIT))


def parse_size(name, value):
    """`50M` and `1024` as clamd reads them: the suffixes are binary."""
    match = SIZE.match(value)
    if not match:
        raise ValueError(f"{name} is {value!r}, which is not a size clamd would read")
    return int(match.group(1)) * SUFFIX[match.group(2).upper()]


# --- clamd --------------------------------------------------------------------------------------


def scan_virus(body, path=CLAMD_SOCKET, max_bytes=None, conf=CLAMD_CONF, timeout=CLAMD_TIMEOUT):
    """clamd over its unix socket, the gate first, then zINSTREAM."""
    if max_bytes is None:
        max_bytes = size_limit(conf)
    if len(body) > max_bytes:
        # ⛔ Before any socket is contacted. Not "try it and see".
        return Verdict(UNSCANNED, f"{len(body)} bytes is over the {max_bytes}-byte "
                                  "scan limit; nobody looked")
    try:
        with connect(path, timeout) as sock:
            sock.sendall(b"zINSTREAM\0")
            view = memoryview(body)
            try:
                for start in range(0, len(body), CHUNK):
                    chunk = view[start:start + CHUNK]
                    sock.sendall(struct.pack("!I", len(chunk)) + chunk)
                sock.sendall(struct.pack("!I", 0))
            except OSError as err:
                # Past its own limit the daemon answers and closes, so a send can fail
                # with the verdict already waiting to be read. Read it before giving up.
                answer = read_until_nul(sock)
                if not answer:
                    return Verdict(UNAVAILABLE, f"clamd {path}: {err}")
            else:
                answer = read_until_nul(sock)
    except OSError as err:
        return Verdict(UNAVAILABLE, f"clamd {path}: {err}")

    if not answer:
        return Verdict(UNAVAILABLE, f"clamd {path}: closed without answering")
    if answer.endswith("FOUND"):
        if LIMITS_EXCEEDED in answer:
            # ⛔ The daemon stopped at one of its own limits and says so (`AlertExceedsMax`,
            # which the install sets): nobody looked at all of it, and nothing was found
            # in what was looked at. Unscanned, never clean and never infected (review
            # measured on 1.5.4, a detection anywhere in the message is answered
            # instead of this).
            return Verdict(UNSCANNED, f"clamd: {answer}")
        # ⚠️ The detection name says which database answered, so it is kept whole: a
        # green EICAR does not prove the official databases loaded.
        return Verdict(INFECTED, answer)
    if answer == SIZE_LIMIT_ERROR:
        # Past the daemon's own limit: our gate should have caught it, so the daemon
        # is stricter than we are. That is not a clean verdict.
        return Verdict(UNSCANNED, f"clamd: {answer}")
    if answer.endswith("ERROR"):
        # ⛔ Any other error is the daemon failing, not a fact about this message:
        # unscanned would let `outbound_unscanned = send` send it. It is
        # the antivirus unavailable, a 451 outbound and the hold inbound.
        return Verdict(UNAVAILABLE, f"clamd: {answer}")
    if answer.endswith("OK"):
        return Verdict(CLEAN, answer)
    return Verdict(UNAVAILABLE, f"clamd: unrecognised answer {answer!r}")


def clamd_version(path=CLAMD_SOCKET, timeout=CLAMD_TIMEOUT):
    """What the running daemon reports, for health; None when it does not answer.

    The daemon answers this only with `EnableVersionCommand yes`, which the install sets.
    """
    try:
        with connect(path, timeout) as sock:
            sock.sendall(b"zVERSION\0")
            return parse_version(read_until_nul(sock))
    except OSError:
        return None


def parse_version(answer):
    """`ClamAV 1.5.3/28128/Sat Sep 19 06:24:24 2026` as the daemon writes it."""
    match = VERSION_LINE.match(answer or "")
    if not match:
        return None
    try:
        built = datetime.strptime(match.group("built").strip(), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        built = None
    return Version(match.group("engine"), int(match.group("sigs")), built)


def connect(path, timeout):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(str(path))
    except OSError:
        sock.close()
        raise
    return sock


def read_until_nul(sock, limit=8192):
    buf = b""
    while not buf.endswith(b"\0") and len(buf) < limit:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf.strip(b"\0").decode("utf-8", "replace").strip()


# --- upstream's current release, for health ---------------------------------------------


def current_cvd(record=CURRENT_CVD, timeout=20):
    """ClamAV's own `current.cvd` record: the release it recommends and the signature set.

    This is the record freshclam itself reads (`DNSDatabaseInfo`), so it is the same
    reading that makes freshclam call an installation outdated. None when the record
    cannot be read; health reports UNKNOWN then.
    """
    try:
        done = subprocess.run(["dig", "+short", "TXT", record], capture_output=True,
                              text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_current_cvd(done.stdout) if done.returncode == 0 else None


def parse_current_cvd(text):
    """`"1.4.6:63:28128:1789853340:1:90:49192:339"`: engine, main, daily, built at."""
    fields = (text or "").strip().strip('"').split(":")
    if len(fields) < 4 or not re.match(r"^\d+(\.\d+)+$", fields[0]):
        return None
    try:
        built = datetime.fromtimestamp(int(fields[3]))
        return Version(fields[0], int(fields[2]), built)
    except ValueError:
        return None


def older(version, than):
    """Version order, numerically field by field: `1.5.3` is older than `1.5.10`."""
    return version_fields(version) < version_fields(than)


def version_fields(version):
    return tuple(int(part) if part.isdigit() else -1 for part in str(version).split("."))


# --- rspamd -------------------------------------------------------------------------------------


def scan_spam(body, path=RSPAMD_SOCKET, headers=None, timeout=RSPAMD_TIMEOUT):
    """rspamd `/checkv2` over its unix socket. Any failure is no score."""
    request = [b"POST /checkv2 HTTP/1.1", b"Host: rspamd", b"Connection: close",
               b"Content-Length: " + str(len(body)).encode()]
    for name, value in (headers or {}).items():
        request.append(f"{name}: {value}".encode())
    try:
        with connect(path, timeout) as sock:
            sock.sendall(b"\r\n".join(request) + b"\r\n\r\n" + body)
            raw = b""
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                raw += chunk
    except OSError as err:
        return Score(None, UNAVAILABLE, f"rspamd {path}: {err}")

    if b"\r\n\r\n" not in raw:
        return Score(None, UNAVAILABLE, "rspamd: closed without answering")
    head, payload = raw.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0].decode("latin-1")
    if " 200" not in status:
        return Score(None, UNAVAILABLE, f"rspamd: answered {status.strip()}")
    try:
        answer = json.loads(payload or b"{}")
    except ValueError as err:
        return Score(None, UNAVAILABLE, f"rspamd: unparseable answer: {err}")
    if not isinstance(answer, dict):
        return Score(None, UNAVAILABLE, "rspamd: the answer is not an object")

    action = answer.get("action", UNAVAILABLE)
    score = answer.get("score")
    if score is None:
        return Score(None, action, "rspamd: the answer carries no score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        # ⛔ A score that is not a finite number is no score. Handed on, it raised in
        # the delivery filter's comparison and nothing was delivered.
        return Score(None, action, f"rspamd: the score is not a number: {score!r:.60}")
    return Score(float(score), action, None)
