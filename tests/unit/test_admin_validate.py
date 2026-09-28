"""The values the screens check before any constraint can fire.

Every rule here is the screen's own, and each one exists because the alternative is an
error page where a person deserved a sentence. The database keeps the
same rules as a second lock; the tests that read them back off the running schema run
on the test machine.
"""

from decimal import Decimal

import pytest

from maildivvy.admin import auth, validate


def refusal(function, *arguments, **keywords):
    with pytest.raises(validate.Refused) as raised:
        function(*arguments, **keywords)
    return str(raised.value)


# --- the domain label ----------------------------------------------------

@pytest.mark.parametrize("typed", ["Example", "ex_ample", "-example", "example-",
                                   "e" * 33, "exa.mple", "", "   "])
def test_a_label_that_is_not_one_lowercase_dns_label_is_refused(typed):
    assert refusal(validate.domain_label, typed)


@pytest.mark.parametrize("typed,stored", [("ex-ample9", "ex-ample9"), ("e" * 32, "e" * 32),
                                          ("  example  ", "example"), ("a", "a")])
def test_a_label_is_stripped_and_kept_as_typed(typed, stored):
    assert validate.domain_label(typed) == stored


def test_the_screens_label_rule_is_the_schemas_own_rule():
    # the same expression, so the screen and the CHECK cannot drift apart
    schema = (__import__("pathlib").Path(__file__).resolve().parents[2]
              / "schema" / "0001_initial.sql").read_text()
    assert f"label ~ '{validate.DOMAIN_LABEL.pattern}'" in schema


# --- a person's login -----------------------------------------------------
# ⚠️ The screens that take a login came later. The RULE is here with every other
# one, because one function has to serve the form and the journal's filter alike.

@pytest.mark.parametrize("typed", ["Ivan", "IVAN", "_ivan", "ivan_", ".ivan", "ivan.",
                                   "iv an", "iv@n", "i" * 65, "", "   "])
def test_a_login_the_schema_would_refuse_is_refused_as_typed(typed):
    assert refusal(validate.login, typed)


@pytest.mark.parametrize("typed,stored", [("ivan", "ivan"), ("iv.an_9-x", "iv.an_9-x"),
                                          ("  ivan  ", "ivan"), ("i" * 64, "i" * 64)])
def test_a_login_is_stripped_and_never_lowercased(typed, stored):
    assert validate.login(typed) == stored


def test_a_login_with_a_capital_is_refused_rather_than_folded():
    # a spelling nobody typed is one nobody was told, so it is never stored
    assert refusal(validate.login, "Ivan")


def test_the_match_is_whole_string_so_a_trailing_newline_cannot_pass():
    import re

    # ⚠️ `$` in Python accepts a trailing newline and the column does not, so the rule is
    # applied with `fullmatch`; the anchored `search` beside it is what would have passed
    assert re.search(validate.ACCOUNT_LOGIN.pattern, "ivan\n") is not None
    assert validate.ACCOUNT_LOGIN.fullmatch("ivan\n") is None
    assert "fullmatch" in validate.login.__code__.co_names


@pytest.mark.parametrize("reserved", ["archive", "break-glass"])
def test_the_reserved_logins_are_not_a_persons(reserved):
    assert "reserved" in refusal(validate.login, reserved)


def test_the_screens_login_rule_is_the_schemas_own_rule():
    schema = (__import__("pathlib").Path(__file__).resolve().parents[2]
              / "schema" / "0001_initial.sql").read_text()
    assert f"login ~ '{validate.ACCOUNT_LOGIN.pattern}'" in schema
    for reserved in validate.RESERVED_LOGINS:
        assert f"'{reserved}'" in schema


# --- dates typed into the interface ----------------------------------------

def test_a_calendar_date_is_taken_as_yyyy_mm_dd():
    assert validate.calendar_date(" 2026-09-22 ", "start date").isoformat() == "2026-09-22"


@pytest.mark.parametrize("typed", ["22/09/2026", "yesterday", "2026-13-01", "2026-09"])
def test_a_text_that_is_not_a_date_says_how_to_write_one(typed):
    assert refusal(validate.calendar_date, typed, "start date") == \
        "The start date is not a date. Give it as YYYY-MM-DD."


def test_an_empty_date_is_refused_and_never_widened():
    # A defect not repeated: an empty end date silently meaning "everything" delivered
    # a range nobody was shown
    assert refusal(validate.calendar_date, "", "end date") == \
        "The end date is needed. Give it as YYYY-MM-DD."


# --- the external address, and the dot-insensitive hosts ------------

@pytest.mark.parametrize("typed,canonical", [
    ("A.B+tag@gmail.com", "ab@gmail.com"),
    ("a.b@googlemail.com", "ab@googlemail.com"),
    ("ab@gmail.com", "ab@gmail.com"),
])
def test_a_consumer_hosts_dots_and_tag_are_folded_away(typed, canonical):
    display, folded = validate.external_address(typed)
    assert folded == canonical
    assert display == typed.strip()          # what is stored and shown is what was typed


@pytest.mark.parametrize("typed,canonical", [
    ("a.b@example.org", "a.b@example.org"),
    ("ab@example.org", "ab@example.org"),
    ("A.B+tag@example.org", "a.b+tag@example.org"),
])
def test_at_any_other_host_every_dot_and_tag_is_kept(typed, canonical):
    assert validate.external_address(typed)[1] == canonical


def test_the_consumer_host_list_is_a_constant_of_the_code():
    # facts about providers, shipped with the product, not a deployment setting
    assert validate.CONSUMER_HOSTS == frozenset({"gmail.com", "googlemail.com"})


@pytest.mark.parametrize("typed", ["", "   ", "nobody", "@example.org", "a@example",
                                   "+tag@gmail.com", ".@gmail.com"])
def test_an_address_that_is_not_one_is_refused(typed):
    assert refusal(validate.external_address, typed)


@pytest.mark.parametrize("inside", [" ", "\t", "\n", "\r", "\x00", "\x1f", "\x7f"])
def test_an_address_with_whitespace_or_a_control_character_inside_it_is_refused(inside):
    assert "no spaces, line breaks or control characters" in refusal(
        validate.external_address, f"some{inside}body@example.org")
    # the positive control: the same address without it is taken
    assert validate.external_address("somebody@example.org")[1] == "somebody@example.org"


# --- the POP3 login -------------------------------------------------------

@pytest.mark.parametrize("inside", [" ", "\t", "\n", "\r", "\x00", "\x1f", "\x7f"])
def test_a_login_with_whitespace_or_a_control_character_inside_it_is_refused(inside):
    assert "no spaces, line breaks or control characters" in refusal(
        validate.pop3_login, f"recent:some{inside}body")
    assert validate.pop3_login("recent:somebody") == "recent:somebody"


@pytest.mark.parametrize("typed,stored", [("", None), ("   ", None), (None, None),
                                          ("  user  ", "user")])
def test_an_empty_login_is_the_address_itself_and_a_typed_one_is_stripped(typed, stored):
    assert validate.pop3_login(typed) == stored


def test_one_rule_serves_the_address_and_the_login():
    # one function for both, so the two cannot drift
    assert "no_inner_whitespace" in validate.external_address.__code__.co_names
    assert "no_inner_whitespace" in validate.pop3_login.__code__.co_names


# --- the provider host and port --------------------------------------

@pytest.mark.parametrize("typed", ["pop .example.org", "a@example.org", "pop!example.org",
                                   "localhost", "192.0.2.256"])
def test_a_host_that_is_not_a_name_or_an_address_is_refused(typed):
    assert "host" in refusal(validate.host, typed, "POP3 host", "pop.example.org")


@pytest.mark.parametrize("typed", ["pop.example.org", "pop3.mail.example.org", "xn--80ak6aa92e.com",
                                   "correct.horse.battery.staple"])
def test_a_name_and_a_passphrase_of_dotted_words_are_both_taken(typed):
    assert validate.host(f"  {typed} ", "POP3 host", "pop.example.org") == typed


# ⛔ the relay verifies the provider's certificate against the configured host, and
# a relay configured as an IP address never matches, even with a certificate naming that
# address; mpop verifies an address only against a certificate naming it.
# So a host given as an address is refused where it is typed, for both hosts.
@pytest.mark.parametrize("what,example", [("POP3 host", "pop.example.org"),
                                          ("SMTP host", "smtp.example.org")])
@pytest.mark.parametrize("typed", ["192.0.2.10", "2001:db8::1", "[2001:db8::1]", "::1",
                                   "0x7f.0.0.1", "192.0.2.256", "pop.example.1"])
def test_a_host_given_as_an_ip_address_is_refused_with_the_name_it_needs(typed, what, example):
    assert refusal(validate.host, typed, what, example) == (
        f"The {what} must be a host name such as {example}, not an IP address: the "
        "provider's certificate is checked against that name.")


@pytest.mark.parametrize("typed, reason", [
    ("pop.example.org.", "without the dot at its end"),
    ("pop.пример.рф", "in its ASCII form, the one that starts xn--"),
    ("почта.example.org", "in its ASCII form, the one that starts xn--"),
])
def test_a_host_refused_for_another_reason_is_never_told_it_is_an_ip_address(typed, reason):
    """A trailing dot or a Unicode name was refused as "not an IP
    address", which is not why; the refusal says what is wrong with the name."""
    said = refusal(validate.host, typed, "POP3 host", "pop.example.org")
    assert "IP address" not in said and reason in said, said


@pytest.mark.parametrize("typed", ["localhost", "pop .example.org", "a@example.org"])
def test_no_host_refusal_offers_an_ip_address(typed):
    said = refusal(validate.host, typed, "SMTP host", "smtp.example.org")
    assert said.startswith("The SMTP host must be a host name such as smtp.example.org")
    assert "or an IP address" not in said


def test_the_host_fields_name_rule_is_the_schemas_own_rule():
    # the same expression for both columns, so the screen and the CHECK cannot drift apart
    schema = (__import__("pathlib").Path(__file__).resolve().parents[2]
              / "schema" / "0001_initial.sql").read_text()
    for column in ("pop3_host", "smtp_host"):
        assert f"{column} ~ '{validate.HOST_ENDS_IN_A_NAME.pattern}'" in schema, column
        assert f"{column} !~ ':'" in schema, column


def test_an_empty_host_says_which_one_is_needed():
    assert refusal(validate.host, "", "SMTP host", "smtp.example.org") == "The SMTP host is needed."


def test_the_host_field_and_the_journals_filter_are_one_function():
    # `is_host` is the rule in both places
    assert "is_host" in validate.host.__code__.co_names


@pytest.mark.parametrize("typed", ["0", "65536", "-1", "abc", "99 5", " 995 ", "9.5"])
def test_a_port_outside_one_to_65535_is_refused(typed):
    assert refusal(validate.port, typed, "POP3 port") == \
        "The POP3 port must be a whole number from 1 to 65535."


@pytest.mark.parametrize("typed", ["1", "995", "65535"])
def test_a_port_inside_the_range_is_taken_as_a_number(typed):
    assert validate.port(typed, "POP3 port") == int(typed)


def test_an_empty_port_takes_the_forms_default_where_there_is_one_and_is_refused_where_there_is_not():
    assert validate.port("", "POP3 port", default=995) == 995
    assert validate.port(None, "SMTP port", default=587) == 587
    assert refusal(validate.port, "", "POP3 port") == "The POP3 port is needed."


# --- the deletion window ---------------------------------------------------

@pytest.mark.parametrize("typed,days", [("", 14), ("   ", 14), (None, 14), ("45", 45),
                                        ("1", 1), ("1000000", 1000000)])
def test_the_window_defaults_to_fourteen_and_takes_a_positive_whole_number(typed, days):
    assert validate.window(typed) == days


@pytest.mark.parametrize("typed,says", [
    ("many", "whole number of days"), ("4.5", "whole number of days"),
    ("0", "more than zero days"), ("-3", "more than zero days"),
    ("1000001", "at most 1000000 days"),
])
def test_a_window_that_is_not_a_positive_number_of_days_says_which(typed, says):
    assert says in refusal(validate.window, typed)


def test_the_windows_bound_is_the_date_arithmetics_and_the_columns():
    # the screens add the window to a date, and dates end in the year 9999
    assert validate.WINDOW_MAX == 1000000
    schema = (__import__("pathlib").Path(__file__).resolve().parents[2]
              / "schema" / "0001_initial.sql").read_text()
    assert f"delete_window_days BETWEEN 1 AND {validate.WINDOW_MAX}" in schema


# --- the spam score threshold ----------------------------------------------

@pytest.mark.parametrize("typed,stored", [("8", "8.00"), ("8.004", "8.00"),
                                          ("150.004", "150.00"), ("1", "1.00"),
                                          ("  12.5  ", "12.50")])
def test_a_threshold_is_quantised_before_the_bounds_are_read(typed, stored):
    assert validate.spam_threshold(typed) == Decimal(stored)


@pytest.mark.parametrize("typed", ["150.006", "0.99", "151", "0", "-8"])
def test_a_threshold_outside_one_to_one_hundred_and_fifty_is_refused(typed):
    assert refusal(validate.spam_threshold, typed) == \
        "The spam score threshold must be a number from 1.00 to 150.00."


@pytest.mark.parametrize("typed", ["", "   ", "eight", "NaN", "nan", "Infinity", "-Infinity"])
def test_an_empty_threshold_and_the_two_parser_traps_are_refused_not_defaulted(typed):
    # `NaN` parses and then RAISES on a comparison instead of answering false, and
    # `Infinity` parses too: both are refused before any bound is read
    assert refusal(validate.spam_threshold, typed) == \
        "The spam score threshold must be a number, such as 8.00."


def test_a_magnitude_too_large_to_quantise_is_out_of_range_not_a_crash():
    assert refusal(validate.spam_threshold, "1e100000") == \
        "The spam score threshold must be a number from 1.00 to 150.00."


# --- passwords typed twice --------------------------------------------

def test_two_empty_password_fields_say_the_forms_own_sentence():
    assert refusal(validate.password_twice, "", "", empty="The archive needs a password.") == \
        "The archive needs a password."
    assert "typed twice" in refusal(validate.password_twice, "", "")


@pytest.mark.parametrize("first,second", [("a-long-enough-password", "another-password-here"),
                                          ("a-long-enough-password", ""),
                                          ("", "a-long-enough-password")])
def test_two_passwords_that_differ_are_refused(first, second):
    assert refusal(validate.password_twice, first, second) == "The two passwords differ."


def test_a_password_shorter_than_fifteen_characters_is_refused_and_nothing_else_is_asked():
    assert validate.PASSWORD_MIN == 15
    assert "15 characters" in refusal(validate.password_twice, "e" * 14, "e" * 14)
    # no composition rule: fifteen of one character is accepted
    assert validate.password_twice("e" * 15, "e" * 15) == "e" * 15


def test_a_password_past_the_hashers_limit_is_a_sentence_not_a_five_hundred():
    # The screen refuses a too-long password rather than letting make_hash raise
    assert validate.PASSWORD_MAX == auth.PASSWORD_MAX
    over = "e" * (validate.PASSWORD_MAX + 1)
    assert f"at most {validate.PASSWORD_MAX}" in refusal(validate.password_twice, over, over)
    with pytest.raises(ValueError):        # make_hash would indeed have raised on it
        auth.make_hash(over)
    assert validate.password_twice("e" * validate.PASSWORD_MAX, "e" * validate.PASSWORD_MAX)


def test_a_password_carrying_a_line_break_is_refused_because_it_could_not_be_checked_whole():
    # `openssl passwd -stdin` reads one line (auth.py), so a hash of it would be a hash
    # of the first line alone
    assert "line break" in refusal(validate.password_twice, "a-long\nenough-password",
                                   "a-long\nenough-password")


# --- the hash the screens store -----------------------------------

def test_the_hash_made_for_an_archive_is_the_one_dovecot_reads():
    made = auth.make_hash("a-long-enough-password")
    assert made.startswith(auth.PREFIX)
    assert auth.CRYPT.fullmatch(made[len(auth.PREFIX):])
    assert auth.verify_password("a-long-enough-password", made)
    assert not auth.verify_password("another-password-here", made)


def test_two_hashes_of_one_password_differ_because_the_salt_is_new_each_time():
    assert auth.make_hash("a-long-enough-password") != auth.make_hash("a-long-enough-password")
