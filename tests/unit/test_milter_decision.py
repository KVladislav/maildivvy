"""Install step 14's two decisions, as plain functions with no daemon near them.

⚠️ Both are deliberately outside the Milter class (``): pymilter's own
harness rebuilds the milter and discards a hand-bound instance, so a suite that drives
the class tests the harness. This is the logic, tested directly; the class itself, the
socket and the binding are read on the test VM.

The sender binding: case and surrounding whitespace are not a mismatch,
dots and `+tags` are compared as entered. The scan is the design's (amended by
).
"""

import pytest

from maildivvy.lib import scan
from maildivvy.milter import decision
from maildivvy.milter.decision import (CONTINUE, REJECT, TEMPFAIL, LookupUnavailable, Sender,
                                       decide, decide_scan)

ALLOWED = "Ivan.P@example.org"
LOGIN = "ivan@alpha"


def lookup_of(address=ALLOWED, outbound_unscanned="send"):
    """A `lookup` that answers for LOGIN alone, as the view does."""
    def lookup(login):
        return Sender(address, outbound_unscanned) if login == LOGIN else None
    return lookup


def unreachable(_login):
    raise LookupUnavailable("could not connect to server")


def header(address, display=""):
    return f'"{display}" <{address}>' if display else address


def answer(from_headers, login=LOGIN, lookup=None):
    return decide(login, from_headers, lookup or lookup_of())


# --- the address that is allowed through -------------------------

def test_the_address_as_entered_is_the_one_that_passes():
    assert answer([header(ALLOWED)]).action == CONTINUE


@pytest.mark.parametrize("spelling", ["ivan.p@example.org", "IVAN.P@EXAMPLE.ORG",
                                      "Ivan.P@Example.ORG", "iVaN.p@ExAmPlE.oRg"])
def test_letter_case_is_never_a_mismatch(spelling):
    # ⛔ the domain part is case-insensitive by definition and clients recase what a
    # person typed; neither half counts as a mismatch
    assert answer([header(spelling)]).action == CONTINUE


def test_surrounding_whitespace_is_never_a_mismatch():
    assert answer(["  Ivan.P@example.org\t"]).action == CONTINUE


@pytest.mark.parametrize("spelling", ["ivanp@example.org", "ivan.p+tag@example.org",
                                      "ivan..p@example.org", "ivan.p@mail.example.org"])
def test_dots_and_tags_are_compared_as_entered(spelling):
    # ⛔ the folded form is the duplicate check's and nothing else: folding here would
    # let a person send as an address the relay maps do not carry
    refusal = answer([header(spelling)])
    assert (refusal.action, refusal.code) == (REJECT, "550")


@pytest.mark.parametrize("spelling", ["\u212aate.K@kiev.example","kate.k@\u212aiev.example",
                                      "KATE.\u212a@KIEV.EXAMPLE"])
def test_an_address_that_only_folds_into_the_allowed_one_is_refused(spelling):
    """`str.lower()` folds the Kelvin sign (U+212A) into an ASCII `k`, so a From that
    is not the allowed address was accepted because it folded into it. The binding ignores the
    case of an ASCII address and nothing else: a character outside ASCII is a mismatch."""
    allowed = "Kate.K@kiev.example"
    assert spelling.lower() == allowed.lower()  # what the fold alone would have let through
    refusal = answer([header(spelling)], lookup=lookup_of(address=allowed))
    assert (refusal.action, refusal.code, refusal.dsn) == (REJECT, "550", "5.7.1"), spelling
    assert answer([header(allowed.upper())], lookup=lookup_of(address=allowed)).action == CONTINUE


def test_the_display_name_beside_the_right_address_is_free():
    for display in ["Ivan P", "someone.else@example.net", "<root@example.net>"]:
        assert answer([header(ALLOWED, display)]).action == CONTINUE


def test_the_right_address_used_as_a_display_name_in_front_of_a_foreign_one_is_refused():
    refusal = answer([header("stranger@example.net", display=ALLOWED)])
    assert (refusal.action, refusal.code, refusal.dsn) == (REJECT, "550", "5.7.1")
    assert "stranger@example.net" in refusal.text


# --- the five refusals, each naming what it refuses ---------------------------

def test_a_mismatch_names_both_the_address_found_and_the_one_required():
    refusal = answer([header("stranger@example.net")])
    assert (refusal.action, refusal.code, refusal.dsn) == (REJECT, "550", "5.7.1")
    assert "stranger@example.net" in refusal.text and ALLOWED in refusal.text
    assert LOGIN in refusal.text


@pytest.mark.parametrize("headers", [[], [ALLOWED, ALLOWED], [ALLOWED, "stranger@example.net"]])
def test_no_From_and_several_From_are_both_refused_rather_than_guessed_at(headers):
    refusal = answer(headers)
    assert (refusal.action, refusal.code, refusal.dsn) == (REJECT, "550", "5.7.1")
    assert str(len(headers)) in refusal.text


@pytest.mark.parametrize("value", ["Ann Example", "Ann", "", "   ", "<>", "Ann <>"])
def test_a_From_header_with_no_parseable_address_is_its_own_refusal(value):
    # ⚠️ `parseaddr("Ann Example")` answers ('', 'Ann'): a non-empty string that is not
    # an address, so an emptiness check alone would let it through
    refusal = answer([value])
    assert (refusal.action, refusal.code) == (REJECT, "550")
    assert "no parseable address" in refusal.text


@pytest.mark.parametrize("login", ["", None])
def test_a_connection_with_no_authenticated_login_is_refused(login):
    refusal = answer([header(ALLOWED)], login=login)
    assert (refusal.action, refusal.code, refusal.dsn) == (REJECT, "550", "5.7.1")
    assert "no authenticated login" in refusal.text


def test_an_unknown_login_and_a_login_with_no_external_mailbox_are_one_answer():
    # the view excludes both, so the program cannot forget either refusal
    for login in ["nobody@alpha", "ivan@free-domain"]:
        refusal = answer([header(ALLOWED)], login=login)
        assert (refusal.action, refusal.code, refusal.dsn) == (REJECT, "550", "5.7.1")
        assert login in refusal.text and "may not send as any address" in refusal.text


def test_an_unreachable_database_is_temporary_and_never_permanent():
    # ⛔ 451, not 550: the message may be perfectly legitimate, and a permanent refusal
    # would bounce it for ever
    refusal = answer([header(ALLOWED)], lookup=unreachable)
    assert (refusal.action, refusal.code, refusal.dsn) == (TEMPFAIL, "451", "4.3.0")
    assert "could not connect to server" in refusal.text


def test_the_lookup_is_never_reached_for_a_message_that_is_already_refused():
    # a mismatch does not need the directory, and an outage must not turn a refusal
    # into a temporary failure
    asked = []

    def lookup(login):
        asked.append(login)
        return Sender(ALLOWED, "send")

    assert decide(LOGIN, [], lookup).code == "550"
    assert decide("", [header(ALLOWED)], lookup).code == "550"
    assert decide(LOGIN, ["Ann Example"], lookup).code == "550"
    assert asked == []


# --- never a rewrite -----------------------------------------------------

def test_the_answer_can_only_refuse_or_continue_and_never_change_a_message():
    # a rewrite leaves a misconfigured client working wrongly for ever and records nothing
    assert set(decision.ACTIONS) == {CONTINUE, REJECT, TEMPFAIL}
    # and no part of the program asks the library for a change, by any of its names
    package = decision.SOURCE.parent
    written = "".join(path.read_text() for path in sorted(package.glob("*.py")))
    for word in ("chgheader", "addheader", "chgfrom", "addrcpt", "delrcpt",
                 "replacebody", "quarantine"):
        assert word not in written, word
    assert "set_flags(0)" in written  # nothing is even negotiated


@pytest.mark.parametrize("text, flat", [
    ("two\nlines", "two lines"),
    ("connection refused\n\tIs the server running?", "connection refused Is the server running?"),
    ("a%b@example.net may not send", "a%%b@example.net may not send"),
    ("  spaced   out  ", "spaced out"),
])
def test_a_refusals_words_are_flattened_because_the_library_will_not_carry_them(text, flat):
    # ⛔ measured: `smfi_setreply` refuses a text with a newline in it, and one with a
    # `%` in it, and pymilter then raises `milter.error: cannot set reply`. The whole
    # decision is lost and the client is told `451 4.3.0 untrapped exception`, which
    # names nothing and turns a permanent refusal into a temporary one.
    assert decision.refusal("550", "5.7.1", text).text == flat


def test_a_refusal_that_runs_away_is_cut_short_rather_than_dropped():
    long = decision.refusal("550", "5.7.1", "x" * 5000)
    assert len(long.text) == decision.REPLY_LIMIT and long.text.endswith("...")


@pytest.mark.parametrize("at", range(decision.REPLY_LIMIT - 8, decision.REPLY_LIMIT + 2))
def test_a_refusal_cut_short_never_leaves_a_lone_per_cent_sign(at):
    """The text was escaped and then cut, so a cut between the two signs of `%%` left
    one `%`, which the library refuses, and the decision was lost to `451 untrapped`."""
    text = "x" * at + "%" + "y" * 50
    cut = decision.refusal("550", "5.7.1", text).text
    assert len(cut) <= decision.REPLY_LIMIT
    assert "%" not in cut.replace("%%", ""), cut[-12:]


def test_the_code_decides_whether_a_refusal_is_permanent_or_temporary():
    assert decision.refusal("550", "5.7.1", "no").action == REJECT
    assert decision.refusal("552", "5.3.4", "no").action == REJECT
    assert decision.refusal("451", "4.3.0", "not now").action == TEMPFAIL


def test_what_is_compared_is_the_internal_login_against_the_external_address():
    # the SMTP client's generic rewrite happens after the queue; by then this
    # information is gone, which is why the check is the server's
    sender = decide(LOGIN, [header(ALLOWED)], lookup_of()).sender
    assert (sender.address, sender.outbound_unscanned) == (ALLOWED, "send")
    assert "@" in LOGIN and LOGIN != ALLOWED


# --- the lookup: one view, one connection per lookup --------------------------

class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, parameters):
        self.conn.statements.append((" ".join(statement.split()), parameters))

    def fetchone(self):
        return self.conn.row


class FakeConnection:
    def __init__(self, row):
        self.row = row
        self.statements = []
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True


def test_the_lookup_reads_one_view_and_opens_a_connection_for_each_message():
    made = []

    def connect():
        made.append(FakeConnection(("Ivan.P@example.org", "refuse")))
        return made[-1]

    lookup = decision.sender_lookup("/etc/maildivvy/milter/db.conf", connect=connect)
    assert lookup(LOGIN) == Sender("Ivan.P@example.org", "refuse")
    assert lookup(LOGIN) == Sender("Ivan.P@example.org", "refuse")
    assert len(made) == 2 and all(conn.closed for conn in made)
    [(statement, parameters)] = made[0].statements
    assert statement == "SELECT sender, outbound_unscanned FROM milter_sender WHERE login = %s"
    assert parameters == (LOGIN,)


def test_the_lookup_reads_no_other_relation_at_all():
    text = decision.SOURCE.read_text()
    for relation in ("external_mailbox", "account", "domain", "mailbox", "message",
                     "delivery", "request", "audit", "session"):
        assert f"FROM {relation}" not in text and f"JOIN {relation}" not in text


def test_a_login_the_view_does_not_carry_is_no_address():
    def connect():
        return FakeConnection(None)

    lookup = decision.sender_lookup("/etc/maildivvy/milter/db.conf", connect=connect)
    assert lookup("nobody@alpha") is None


def test_a_connect_failure_and_a_query_failure_are_both_the_temporary_refusal():
    def refusing_connect():
        raise OSError("no such file or directory")

    lookup = decision.sender_lookup("/etc/maildivvy/milter/db.conf", connect=refusing_connect)
    with pytest.raises(LookupUnavailable, match="no such file"):
        lookup(LOGIN)

    class Failing(FakeConnection):
        def cursor(self):
            raise RuntimeError("server closed the connection unexpectedly")

    broken = Failing(None)
    lookup = decision.sender_lookup("/etc/maildivvy/milter/db.conf", connect=lambda: broken)
    with pytest.raises(LookupUnavailable, match="server closed"):
        lookup(LOGIN)
    assert broken.closed  # the connection is given back even when the query raised


# --- the scan at submission -----------------------------------------------------

def verdict(kind, detail="detail"):
    return scan.Verdict(kind, detail)


def test_a_clean_message_goes_on_to_the_queue():
    assert decide_scan(verdict(scan.CLEAN, "stream: OK"), "send").action == CONTINUE
    assert decide_scan(verdict(scan.CLEAN, "stream: OK"), "refuse").action == CONTINUE


def test_an_infected_message_is_refused_permanently_and_the_detection_is_named():
    refusal = decide_scan(verdict(scan.INFECTED, "stream: Eicar-Signature FOUND"), "send")
    assert (refusal.action, refusal.code, refusal.dsn) == (REJECT, "550", "5.7.1")
    assert "Eicar-Signature FOUND" in refusal.text


def test_an_unreachable_antivirus_is_temporary_so_the_client_keeps_the_message():
    refusal = decide_scan(verdict(scan.UNAVAILABLE, "clamd: connection refused"), "send")
    assert (refusal.action, refusal.code, refusal.dsn) == (TEMPFAIL, "451", "4.7.1")
    assert "clamd: connection refused" in refusal.text


def test_a_message_too_large_to_scan_follows_its_domains_setting():
    too_large = verdict(scan.UNSCANNED, "9000000 bytes is over the 8000000-byte scan limit")
    assert decide_scan(too_large, "send").action == CONTINUE
    refusal = decide_scan(too_large, "refuse")
    assert (refusal.action, refusal.code, refusal.dsn) == (REJECT, "552", "5.3.4")
    assert "too large to scan" in refusal.text


def test_an_unreadable_setting_refuses_rather_than_sending_something_nobody_looked_at():
    # the column's CHECK allows two words; anything else is a database nobody can read,
    # and this program's character is to fail closed
    too_large = verdict(scan.UNSCANNED, "over the scan limit")
    for value in ["", None, "SEND", "maybe"]:
        assert decide_scan(too_large, value).code == "552"


def test_infected_and_unavailable_are_unchanged_by_the_setting():
    for value in ["send", "refuse"]:
        assert decide_scan(verdict(scan.INFECTED), value).code == "550"
        assert decide_scan(verdict(scan.UNAVAILABLE), value).code == "451"
