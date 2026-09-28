"""Both decisions the milter makes, as plain functions with no Milter object near them.

⛔ THE DECISION IS NOT A METHOD. pymilter's own harness rebuilds the
milter and discards a hand-bound instance, so a suite driving the class tests the
harness as much as the logic. This is the logic, and `tests/unit/test_milter_decision.py`
drives it directly.

⛔ IT FAILS CLOSED IN FIVE DIRECTIONS, and each is a refusal rather than a guess:

    a mismatched From          550 5.7.1, naming the address found and the one required
    no From, or several        550 - a guess would be worse
    an unknown login           550
    a login in a domain with no external mailbox   550 - the same answer, because the
                               view excludes both and the program cannot forget either
    an unreachable database    451 4.3.0 - temporary, because it is

⛔ A MISMATCH IS REJECTED, NEVER REWRITTEN. A rewrite leaves a
misconfigured client working wrongly for ever, records nothing about somebody trying it
on, and cannot be tightened later without breaking every client that had been silently
working. Nothing here can change a message: the only answers are continue and refuse.

⚠️ CASE IS NOT A MISMATCH AND NOTHING ELSE IS FOLDED. The domain part is
case-insensitive by definition and clients recase what a person typed, so letter case
and surrounding whitespace are ignored in both halves. Dots and `+tags` are compared as
entered: the folded `address_canonical` is the duplicate check's, and comparing it here
was measured to stop everyone with a dotted address from sending, because the relay
maps carry the address as entered.

⚠️ IT RUNS AT THE SMTP SERVER, before the internal-to-external
rewrite that the SMTP client does after the queue. What it compares is the internal
login the person typed against the external address they are entitled to; after the
rewrite that information is gone.

Then the same message is scanned, before Postfix queues it: *infected* is a
permanent refusal naming the detection, *unavailable* a temporary one, and a message
too large to scan follows its domain's own setting.
"""

import email.utils
from dataclasses import dataclass
from pathlib import Path

from maildivvy.lib import scan

SOURCE = Path(__file__).resolve()

CONTINUE, REJECT, TEMPFAIL = "continue", "reject", "tempfail"
ACTIONS = (CONTINUE, REJECT, TEMPFAIL)

# `domain.outbound_unscanned`'s two words. Anything else is a database nobody
# can read, and this program's character is to refuse rather than to guess.
SEND, REFUSE = "send", "refuse"

# The one view this program may read, and the whole of its database access.
VIEW = "milter_sender"
QUERY = f"SELECT sender, outbound_unscanned FROM {VIEW} WHERE login = %s"


class LookupUnavailable(Exception):
    """The database could not be read. A TEMPORARY refusal, not a refusal."""


@dataclass(frozen=True)
class Sender:
    """One row of `milter_sender`: the address a login may send as, and its domain's setting."""

    address: str
    outbound_unscanned: str


@dataclass(frozen=True)
class Answer:
    """What the milter does with this message. `sender` is set only on a continue."""

    action: str
    code: str | None = None
    dsn: str | None = None
    text: str | None = None
    sender: Sender | None = None


GO = Answer(CONTINUE)

# The bound a refusal's own words are kept inside. The protocol allows much more; what
# matters is that a detection name or a driver's message cannot run away with the line.
REPLY_LIMIT = 400


def refusal(code, dsn, text):
    """A refusal whose words libmilter will actually carry (⛔ measured 2026-09-20).

    `smfi_setreply` REFUSES a text with a newline in it, and one with a `%` in it, and
    pymilter then raises `milter.error: cannot set reply`. The decision is lost: what
    the client is told is pymilter's own `451 4.3.0 untrapped exception`, which names
    nothing and turns a permanent refusal into a temporary one. Both are reachable from
    ordinary input - a psycopg connection error is two lines, and `%` is a legal
    character in an address - so the words are flattened here, once, where every
    refusal is made.
    """
    flat = " ".join(str(text).split())
    # ⚠️ cut BEFORE escaping, each `%` counted as the two it becomes: a cut through an
    # escaped `%%` leaves one `%`, which the library refuses as above.
    if len(flat) + flat.count("%") > REPLY_LIMIT:
        kept, size = [], len("...")
        for char in flat:
            size += 2 if char == "%" else 1
            if size > REPLY_LIMIT:
                break
            kept.append(char)
        flat = "".join(kept).rstrip() + "..."
    return Answer(REJECT if str(code).startswith("5") else TEMPFAIL, code, dsn,
                  flat.replace("%", "%%"))


def parsed_address(value):
    """The address half of a From header, the display name discarded and case kept."""
    return email.utils.parseaddr(value or "")[1].strip()


def decide(login, from_headers, lookup):
    """The sender binding. `lookup(login)` answers a Sender, None, or LookupUnavailable."""
    if not login:
        return refusal("550", "5.7.1", "no authenticated login on this connection")

    if len(from_headers) != 1:
        return refusal("550", "5.7.1",
                       "a message must carry exactly one From header; this one carries "
                       f"{len(from_headers)}")

    claimed = parsed_address(from_headers[0])
    # ⚠️ `parseaddr` answers a NON-EMPTY string for something that is not an address:
    # measured, `parseaddr("Ann Example")` gives ('', 'Ann'). An emptiness check alone
    # is not enough, and the missing `@` is what tells a header with no address from one
    # with the wrong address - two different mistakes, worth saying differently.
    if not claimed or "@" not in claimed:
        return refusal("550", "5.7.1", "the From header carries no parseable address")

    try:
        allowed = lookup(login)
    except LookupUnavailable as err:
        # ⛔ 451, not 550: the message may be perfectly legitimate, we cannot tell right
        # now, and a permanent refusal would bounce it for ever.
        return refusal("451", "4.3.0", f"cannot reach the sender directory: {err}")

    if allowed is None:
        # An unknown login and a login in a domain with no external mailbox arrive here
        # as the SAME answer: the view excludes both.
        return refusal("550", "5.7.1", f"{login} may not send as any address")

    # ⛔ ASCII first, then the case: `str.lower()` folds the Kelvin sign
    # (U+212A) into an ASCII `k`, so a From that is not the address would match it once
    # folded. The binding ignores the case of the address and nothing else.
    if not claimed.isascii() or claimed.lower() != allowed.address.strip().lower():
        return refusal("550", "5.7.1",
                       f"the From header says <{claimed}>; {login} must send as "
                       f"<{allowed.address}>")

    return Answer(CONTINUE, sender=allowed)


def decide_scan(verdict, outbound_unscanned):
    """What our own antivirus's answer does to a submitted message."""
    if verdict.verdict == scan.INFECTED:
        return refusal("550", "5.7.1",
                       f"this message carries malware and was not sent: {verdict.detail}")
    if verdict.verdict == scan.UNAVAILABLE:
        # The client keeps the message and retries; nothing is queued unscanned.
        return refusal("451", "4.7.1",
                       f"the antivirus is temporarily unavailable: {verdict.detail}")
    if verdict.verdict == scan.UNSCANNED:
        # ⛔ the domain's own setting, read from the same view as the sender, so a change
        # in the interface takes effect on the next message with no restart.
        if outbound_unscanned == SEND:
            return GO
        return refusal("552", "5.3.4",
                       "this message is too large to scan and this domain does not send "
                       f"mail nobody looked at: {verdict.detail}")
    return GO


def sender_lookup(conf_path, connect=None):
    """A `lookup` backed by `milter_sender`, which is this role's one grant.

    A connection per lookup, closed again whatever happened, and every connect or query
    exception mapped to the temporary refusal.
    """
    if connect is None:
        from maildivvy.lib import db

        def connect():
            return db.connect_at(conf_path)

    def lookup(login):
        try:
            conn = connect()
        except Exception as err:
            raise LookupUnavailable(str(err)) from None
        try:
            with conn.cursor() as cur:
                cur.execute(QUERY, (login,))
                row = cur.fetchone()
        except Exception as err:
            raise LookupUnavailable(str(err)) from None
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return Sender(row[0], row[1]) if row else None

    return lookup
