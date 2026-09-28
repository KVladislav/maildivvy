"""Reading mpop: the four outcomes, the structured cause, and what counts as a message.

The exit codes and the lines here are the ones measured on the test VM against the stub
provider. The table is repeated
as parameters rather than prose so that a change in mpop shows up here first.
"""

import pytest

from maildivvy.fetch import outcome

TRAILER = "mpop: error during mail retrieval (account em7 from /var/lib/maildivvy/fetch/7/mpoprc)\n"
COMMAND = "/opt/maildivvy/bin/maildivvy-deliver --domain alpha --spam-threshold 8.00"

# measured 2026-09-19: (case, mpop's exit code, mpop's own line).
MEASURED = {
    "hold": (74, f"mpop: {COMMAND} returned exit status 75 (EX_TEMPFAIL: temporary failure)"),
    "refusal 65": (74, f"mpop: {COMMAND} returned exit status 65 (EX_DATAERR: data format error)"),
    "refusal 77": (74, f"mpop: {COMMAND} returned exit status 77 (EX_NOPERM: permission denied)"),
    "dropped at RETR": (74, "mpop: cannot read from TLS connection: The TLS connection "
                            "was non-properly terminated."),
    "-ERR on RETR": (76, "mpop: command RETR 2 failed"),
    "refused login": (77, "mpop: authentication failed (method USER)"),
}


def said(case):
    rc, line = MEASURED[case]
    return rc, line + "\n" + TRAILER


def read(case):
    return outcome.read(*said(case))


# --- the four outcomes ---------------------------------------------


@pytest.mark.parametrize("printed", [
    "alice@example.test at 127.0.0.1:\nno messages\n",                     # 1.4.23, empty
    "alice@example.test at 127.0.0.1:\nnew: no messages, total: 1 message in 20 bytes\n",
    "new: no messages\n",                                                  # 1.4.21's wording
])
def test_exit_zero_with_nothing_retrieved_is_no_new_mail(printed):
    """⚠️ 1.4.23 prints `no messages` alone for an EMPTY maildrop, with no `new:`."""
    assert outcome.read(0, printed).status == outcome.NO_NEW_MAIL


@pytest.mark.parametrize("printed", [
    "alice@example.test at 127.0.0.1:\nnew: 1 message in 20 bytes, total: 1 message in 20 bytes\n",
    "new: 3 messages in 2048 bytes\n",
])
def test_exit_zero_with_something_retrieved_is_ok(printed):
    assert outcome.read(0, printed).status == outcome.OK


def test_a_refused_login_is_auth_failed_and_never_error():
    read_it = read("refused login")
    assert read_it.status == outcome.AUTH_FAILED
    assert "authentication failed" in read_it.detail


@pytest.mark.parametrize("case", ["hold", "refusal 65", "dropped at RETR", "-ERR on RETR"])
def test_every_other_exit_is_an_error(case):
    assert read(case).status == outcome.ERROR


def test_a_successful_outcome_carries_no_cause_and_no_detail():
    clean = outcome.read(0, "new: 1 message in 10 bytes\n")
    assert clean.cause is None and clean.detail is None


# --- the structured cause, from a closed list ------------------


def test_the_causes_are_the_schemas_closed_list_in_its_order():
    assert outcome.CAUSES == ("unrecorded", "timeout", "stuck_message", "unreachable", "transient")


@pytest.mark.parametrize("case, cause", [
    ("hold", "transient"),            # the antivirus is down; `held_since` says which
    ("refusal 65", "stuck_message"),  # our delivery refused this message
    ("refusal 77", "stuck_message"),
    ("dropped at RETR", "unreachable"),
    ("-ERR on RETR", "stuck_message"),
])
def test_each_measured_failure_has_its_cause(case, cause):
    assert read(case).cause == cause


def test_a_refused_credential_never_goes_through_the_classification():
    assert read("refused login").cause is None


@pytest.mark.parametrize("line, cause", [
    ("mpop: cannot connect to pop.example.org, port 995: Connection refused", "unreachable"),
    ("mpop: cannot locate host pop.example.org: Name or service not known", "unreachable"),
    ("mpop: network connection timed out", "unreachable"),
    ("mpop: the server sent an empty reply", "transient"),
])
def test_a_reachability_failure_is_told_from_a_transient_one(line, cause):
    assert outcome.read(74, line + "\n" + TRAILER).cause == cause


def test_an_error_mpop_said_nothing_about_is_transient_and_says_so():
    empty = outcome.read(74, "")
    assert empty.status == outcome.ERROR and empty.cause == "transient"
    assert empty.detail is None


def test_a_timeout_is_an_error_with_its_own_cause_and_none_of_the_childs_output():
    killed = outcome.timed_out(900)
    assert killed.status == outcome.ERROR and killed.cause == "timeout"
    assert killed.detail == "timed out after 900 s; mpop killed"
    assert not killed.message_level and not killed.held


def test_the_bookkeeping_cause_is_named_for_the_runner_to_use():
    assert outcome.UNRECORDED == "unrecorded"


# --- the detail is mpop's own lines -----------------------------------------------


def test_the_generic_trailer_is_dropped_and_the_informative_line_kept():
    detail = read("-ERR on RETR").detail
    assert detail == "mpop: command RETR 2 failed"
    assert "error during mail retrieval" not in detail


def test_several_lines_are_joined_in_the_order_mpop_printed_them():
    text = ("mpop: command RETR 2 failed\nmpop: POP3 server message: -ERR no such message\n"
            + TRAILER)
    assert outcome.read(76, text).detail == \
        "mpop: command RETR 2 failed; mpop: POP3 server message: -ERR no such message"


def test_the_detail_is_capped_at_five_hundred_characters():
    long = "\n".join(f"mpop: line {i} " + "x" * 80 for i in range(20))
    assert len(outcome.read(74, long).detail) == outcome.DETAIL_MAX == 500


def test_a_failure_with_no_mpop_line_falls_back_to_the_last_line_it_printed():
    assert outcome.read(74, "something else entirely\n\n").detail == "something else entirely"


# --- message-level only when mpop named the message -----------------------


@pytest.mark.parametrize("case, counts", [
    ("-ERR on RETR", True),        # 76 with `command RETR n failed`
    ("refusal 65", True),          # 74 with `returned exit status`, our delivery refusing it
    ("refusal 77", True),
    ("hold", False),               # the antivirus, not the message
    ("dropped at RETR", False),    # 74 over TLS, naming no message
    ("refused login", False),
])
def test_only_a_failure_naming_the_message_counts(case, counts):
    assert read(case).message_level is counts


def test_exit_seventysix_without_the_retr_line_names_no_message():
    assert not outcome.read(76, "mpop: the connection was closed\n" + TRAILER).message_level


def test_exit_seventyfour_naming_our_own_output_names_no_message():
    assert not outcome.read(74, "mpop: cannot write mail: No space left\n" + TRAILER).message_level


def test_the_hold_is_the_one_line_naming_exit_status_seventyfive():
    assert read("hold").held is True
    assert [case for case in MEASURED if outcome.read(*said(case)).held] == ["hold"]


def test_a_delivery_verdict_marks_the_scanner_answered_and_the_hold_does_not():
    """The runner clears a hold once the delivery filter answers, whatever the
    answer. Every delivery-side verdict but EX_TEMPFAIL says the scanner was up; the hold
    (EX_TEMPFAIL) and a failure that never reached delivery do not."""
    answered = [case for case in MEASURED if outcome.read(*said(case)).scanner_answered]
    assert answered == ["refusal 65", "refusal 77"]          # a delivery-side verdict, not TEMPFAIL
    assert read("hold").scanner_answered is False            # the antivirus was unreachable
    assert read("dropped at RETR").scanner_answered is False  # the connection died before delivery
    assert read("-ERR on RETR").scanner_answered is False     # the provider refused before delivery
    assert read("refused login").scanner_answered is False    # never got as far as a message


def test_a_hold_never_starts_the_stuck_message_hour():
    held = read("hold")
    assert held.held and not held.message_level
    assert held.cause != outcome.STUCK_MESSAGE


def test_the_failing_message_number_is_read_from_mpops_line():
    assert read("-ERR on RETR").retr_number == 2
    assert read("refusal 65").retr_number is None  # our delivery names no number


# --- the password check's own reading ----------------------------------------


def test_the_password_check_has_three_statuses_and_no_no_new_mail():
    assert outcome.read_test(0, "").status == outcome.OK
    assert outcome.read_test(0, "no messages\n").status == outcome.OK
    assert outcome.read_test(77, said("refused login")[1]).status == outcome.AUTH_FAILED
    assert outcome.read_test(74, said("dropped at RETR")[1]).status == outcome.ERROR


def test_the_checks_detail_never_falls_back_to_arbitrary_output():
    """A `--debug` line, the credential in it, is what a fallback would put on a screen."""
    debug = "--> PASS hunter2\n<-- +OK\nsomething unexpected\n"
    assert outcome.read_test(74, debug).detail == outcome.NO_MPOP_DETAIL
    assert "hunter2" not in outcome.read_test(74, debug).detail
    # the control: the same reading for a fetch does fall back
    assert outcome.read(74, debug).detail == "something unexpected"


def test_the_checks_detail_is_mpops_own_lines_when_it_has_them():
    assert outcome.read_test(77, said("refused login")[1]).detail == \
        "mpop: authentication failed (method USER)"
