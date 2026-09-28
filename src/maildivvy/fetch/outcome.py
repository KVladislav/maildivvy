"""What one mpop run was: its status, its structured cause and its detail.

Four outcomes go on the row (`ok`, `no_new_mail`, `auth_failed`, `error`) with a detail
naming the cause. Beside the detail the runner writes a
CAUSE FROM A CLOSED LIST, so that no screen ever classifies an error from its wording;
the list and its order are the schema's.

⛔ THE DETAIL IS MPOP'S OWN LINES, NOT THE LAST LINE OF THE OUTPUT. mpop
ends every failure with a generic trailer naming the account and the file and nothing
about what went wrong; the informative lines come before it.

⛔ A FAILURE IS MESSAGE-LEVEL ONLY WHEN MPOP NAMED THE MESSAGE, because
only then is there a message to be stuck on. mpop prints the message number only where
the server answered the RETR. Everything in this module about exit codes was measured
on the test VM against the stub provider:

    exit 74 + `returned exit status 75 (EX_TEMPFAIL`  the antivirus hold
    exit 74 + `returned exit status <other>`          our delivery refused THIS message
    exit 74 + `cannot read from TLS connection`       the connection died at RETR
    exit 76 + `command RETR n failed`                 the provider refused THIS message
    exit 77                                           the credential was refused

⛔ THE HOLD IS NOT A STUCK MESSAGE. mpop's exit code is 74 for it and for a
plain refusal alike, so the two are told apart by mpop's own line; counting the hold
toward the stuck-message hour would start skipping mail the antivirus was only late for.
"""

import re
from dataclasses import dataclass

EX_OK = 0
EX_IOERR = 74
EX_TEMPFAIL = 75  # what the delivery filter exits while the antivirus is unreachable
EX_PROTOCOL = 76
EX_NOPERM = 77

DETAIL_MAX = 500

OK, NO_NEW_MAIL, AUTH_FAILED, ERROR = "ok", "no_new_mail", "auth_failed", "error"
STATUSES = (OK, NO_NEW_MAIL, AUTH_FAILED, ERROR)

# `external_mailbox.last_fetch_cause`'s closed list, in the schema's order, which is
# the order of reading.
UNRECORDED = "unrecorded"      # the runner could not record what it decided
TIMEOUT = "timeout"            # our own timeout killed mpop
STUCK_MESSAGE = "stuck_message"  # mpop named one message it could not take
UNREACHABLE = "unreachable"    # the provider could not be reached
TRANSIENT = "transient"        # anything else, the antivirus hold included
CAUSES = (UNRECORDED, TIMEOUT, STUCK_MESSAGE, UNREACHABLE, TRANSIENT)

# The generic trailers. They name the account and the configuration file and nothing
# about the failure, so the LAST line is the one line worth dropping.
GENERIC = ("error during mail retrieval", "error during delivery")

RETR_FAILED = re.compile(r"^mpop: command RETR (\d+) failed", re.M)
# mpop names the delivery command's own sysexits status in a line of its own.
DELIVERY_STATUS = re.compile(r"returned exit status (\d+)")
# Words that mean the provider was not reached. Lower case: the reading folds the line.
UNREACHABLE_WORDS = ("connect", "timed out", "refused", "unreachable", "resolve",
                     "cannot locate host", "network", "no route")

NO_MPOP_DETAIL = "mpop reported no message of its own"

# ⚠️ The rule records `new: no messages`, measured against mpop 1.4.21. mpop 1.4.23
# was measured on the test VM to print THREE shapes on exit 0:
#   an empty maildrop        `no messages`
#   nothing new to retrieve  `new: no messages, total: 1 message in 20 bytes`
#   something retrieved      `new: 1 message in 20 bytes, total: …`
# So the 1.4.21 wording alone would read an empty provider mailbox as `ok`. The words
# that mean "nothing came" are the two below, and only a retrieval removes them.
NOTHING_RETRIEVED = "no messages"


@dataclass(frozen=True)
class Outcome:
    status: str
    cause: str | None
    detail: str | None
    held: bool = False
    message_level: bool = False
    retr_number: int | None = None
    # ⛔ The run reached the delivery filter and it answered with a real
    # verdict (the scanner was up), whatever the verdict was - a store that refused the
    # message included. It is NOT the antivirus-unreachable answer (EX_TEMPFAIL), which
    # is the hold. The runner clears `held_since` on this, so a hold that ends with a
    # refused message does not go on reporting the antivirus as down.
    scanner_answered: bool = False


def mpop_lines(out):
    """mpop's own complaints, the generic trailers dropped."""
    said = [line.strip() for line in out.splitlines() if line.strip().startswith("mpop:")]
    return [line for line in said if not any(g in line for g in GENERIC)]


def fetch_detail(out):
    """The detail for a fetch: mpop's lines, else the last thing it printed."""
    said = mpop_lines(out)
    if said:
        return "; ".join(said)[:DETAIL_MAX]
    printed = [line.strip() for line in out.splitlines() if line.strip()]
    return printed[-1][:DETAIL_MAX] if printed else None


def test_detail(out):
    """The detail for a password check, and it has NO fallback.

    The column is shown by the interface, and a fallback to arbitrary output is how a
    `--debug` line, the credential in it, would reach a screen.
    """
    said = mpop_lines(out)
    return "; ".join(said)[:DETAIL_MAX] if said else NO_MPOP_DETAIL


def delivery_status(out):
    """The sysexits status our delivery command returned, as mpop named it."""
    found = DELIVERY_STATUS.search(out)
    return int(found.group(1)) if found else None


def held(rc, out):
    """the antivirus is unreachable and this message waits at the provider."""
    return rc == EX_IOERR and delivery_status(out) == EX_TEMPFAIL


def retr_number(out):
    """The message number in `command RETR n failed`, or None."""
    found = RETR_FAILED.search(out)
    return int(found.group(1)) if found else None


def message_level(rc, out):
    """, minus the hold."""
    if rc == EX_PROTOCOL:
        return RETR_FAILED.search(out) is not None
    if rc == EX_IOERR:
        status = delivery_status(out)
        return status is not None and status != EX_TEMPFAIL
    return False


def cause_of(rc, out, stuck):
    if stuck:
        return STUCK_MESSAGE
    folded = "\n".join(mpop_lines(out)).lower()
    if any(word in folded for word in UNREACHABLE_WORDS):
        return UNREACHABLE
    return TRANSIENT


def read(rc, out):
    """What one fetch run was."""
    if rc == EX_OK:
        return Outcome(NO_NEW_MAIL if NOTHING_RETRIEVED in out else OK, None, None)
    if rc == EX_NOPERM:
        # A refused credential is its own status and never goes through the
        # classification: it has a human cause, and a screen says so.
        return Outcome(AUTH_FAILED, None, fetch_detail(out))
    stuck = message_level(rc, out)
    delivered = delivery_status(out)
    return Outcome(ERROR, cause_of(rc, out, stuck), fetch_detail(out),
                   held=held(rc, out), message_level=stuck, retr_number=retr_number(out),
                   scanner_answered=delivered is not None and delivered != EX_TEMPFAIL)


def timed_out(seconds):
    """Our own timeout killed mpop.

    None of the child's output is kept: on this path - a connection closed inside a
    message body - it has no bound.
    """
    return Outcome(ERROR, TIMEOUT, f"timed out after {int(seconds)} s; mpop killed")


def read_test(rc, out):
    """What one password check was: THREE statuses, not four.

    `no_new_mail` describes mail and a check is about a login, so the check never
    writes it - nor any of the fetch's columns, nor a cause.
    """
    if rc == EX_OK:
        return Outcome(OK, None, None)
    return Outcome(AUTH_FAILED if rc == EX_NOPERM else ERROR, None, test_detail(out))
