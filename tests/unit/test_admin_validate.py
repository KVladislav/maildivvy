"""The values the screens check before any constraint can fire.

Every rule here is the screen's own, and each one exists because the alternative is an
error page where a person deserved a sentence. The database keeps the
same rules as a second lock; the tests that read them back off the running schema run
on the test machine.
"""

import re
import unicodedata
from pathlib import Path
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

@pytest.mark.parametrize("typed", ["_ivan", "ivan_", ".ivan", "ivan.",
                                   "iv an", "iv@n", "i" * 65, "", "   "])
def test_a_login_the_schema_would_refuse_is_refused_as_typed(typed):
    assert refusal(validate.login, typed)


@pytest.mark.parametrize("typed,stored", [("ivan", "ivan"), ("iv.an_9-x", "iv.an_9-x"),
                                          ("  ivan  ", "ivan"), ("i" * 64, "i" * 64),
                                          ("Ivan", "ivan"), ("IV.AN_9-X", "iv.an_9-x")])
def test_a_login_is_stripped_and_folded_to_lowercase(typed, stored):
    assert validate.login(typed) == stored


def test_only_ascii_capitals_are_folded_as_dovecot_folds_them():
    # str.lower() would make the Kelvin sign a `k`; no mail client sends that spelling
    assert refusal(validate.login, "\u212aate")
    assert auth.account_login("\u212aate") == "\u212aate"
    assert auth.account_login("  Ivan@Example.ORG ") == "ivan"


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


@pytest.mark.parametrize("typed", ["22/09/2026", "yesterday", "2026-13-01", "2026-09",
                                   # what `date.fromisoformat` also takes, and the text
                                   # goes on to the query as typed
                                   "2026-W45-2", "2026W452", "20260922", "2026-265",
                                   "2026-09-22T10:00", "２０２６-09-22"])
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
    # Google's two names for one mailbox are one host in the canonical form
    ("a.b@googlemail.com", "ab@gmail.com"),
    ("A.B+x@GoogleMail.com", "ab@gmail.com"),
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
                                   "+tag@gmail.com", ".@gmail.com", "x@.", "a@b@c.d",
                                   "a@.example.org", "a@example..org", "a@example.org."])
def test_an_address_that_is_not_one_is_refused(typed):
    assert refusal(validate.external_address, typed)


def test_the_duplicate_check_also_reads_a_googlemail_row_saved_before_the_two_were_one():
    assert validate.legacy_spellings("ab@gmail.com") == ["ab@gmail.com", "ab@googlemail.com"]
    assert validate.legacy_spellings("ab@example.org") == ["ab@example.org"]


@pytest.mark.parametrize("inside", [" ", "\t", "\n", "\r", "\x00", "\x1f", "\x7f", "\x81",
                                    "\x9f"])
def test_an_address_with_whitespace_or_a_control_character_inside_it_is_refused(inside):
    assert "no spaces, line breaks or control characters" in refusal(
        validate.external_address, f"some{inside}body@example.org")
    # the positive control: the same address without it is taken
    assert validate.external_address("somebody@example.org")[1] == "somebody@example.org"


# --- the POP3 login -------------------------------------------------------

@pytest.mark.parametrize("inside", [" ", "\t", "\n", "\r", "\x00", "\x1f", "\x7f", "\x81",
                                    "\x9f"])
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


def test_the_screens_character_rule_refuses_all_the_schemas_check_refuses():
    """One class on both sides: the columns' CHECK is `SCHEMA_CLASS`, which in the
    machine's database refuses C0, DEL, the C1 controls and Unicode's spaces; the screen
    refuses every control Unicode names and every space Python knows, so a value the
    form takes is never one the INSERT refuses with an error page."""
    schema = (__import__("pathlib").Path(__file__).resolve().parents[2]
              / "schema" / "0001_initial.sql").read_text()
    for column in ("address", "address_canonical", "pop3_login"):
        assert f"{column} ~ '^[^{validate.SCHEMA_CLASS}]+$'" in schema, column
    later = (__import__("pathlib").Path(__file__).resolve().parents[2]
             / "schema" / "0002_provider_login_keep_and_pins.sql").read_text()
    assert f"smtp_login ~ '^[^{validate.SCHEMA_CLASS}:]+$'" in later
    refused = [code for code in range(0x110000)
               if unicodedata.category(chr(code)) == "Cc" or chr(code).isspace()]
    # the control that the class was read at all: C0, DEL and all 32 C1 controls
    assert {*range(0x20), *range(0x7F, 0xA0)} <= set(refused)
    for code in refused:
        assert validate.INNER.search(f"a{chr(code)}b"), hex(code)
        assert "control characters" in refusal(validate.external_address,
                                                f"a{chr(code)}b@example.org"), hex(code)
    assert validate.external_address("a\xe9b@example.org")[1] == "a\xe9b@example.org"


# --- the SMTP login ----------------------------------------------------------------

@pytest.mark.parametrize("typed,stored", [("", None), ("   ", None), (None, None),
                                          ("  box-smtp  ", "box-smtp")])
def test_an_empty_smtp_login_is_the_pop3_login_and_a_typed_one_is_stripped(typed, stored):
    assert validate.smtp_login(typed) == stored


def test_an_smtp_login_with_a_colon_is_refused_since_postfix_splits_its_value_there():
    assert "no colon" in refusal(validate.smtp_login, "recent:box@example.org")
    assert "no spaces" in refusal(validate.smtp_login, "box smtp")
    assert "no_inner_whitespace" in validate.smtp_login.__code__.co_names


# --- a pinned certificate ------------------------------------------------------------

PIN = ":".join(["AB", "01"] * 16)


@pytest.mark.parametrize("typed", [
    PIN, PIN.lower(), PIN.replace(":", ""), PIN.replace(":", " "),
    f"sha256 Fingerprint={PIN}", f"SHA256 Fingerprint={PIN}", f"SHA256: {PIN}",
    f"  {PIN.lower()}  "])
def test_a_fingerprint_in_any_usual_spelling_is_stored_in_the_one(typed):
    assert validate.fingerprint(typed, "POP3 certificate fingerprint") == PIN
    assert validate.is_fingerprint(PIN)


@pytest.mark.parametrize("typed,stored", [("", None), ("   ", None), (None, None)])
def test_an_empty_fingerprint_is_no_pin(typed, stored):
    assert validate.fingerprint(typed, "SMTP certificate fingerprint") == stored


@pytest.mark.parametrize("typed", [PIN[:-3], PIN + ":CD", "zz" * 32, "sha1 Fingerprint=" + PIN,
                                   PIN + "\nkeep off", "AB-01" * 16])
def test_anything_but_a_sha256_fingerprint_is_refused(typed):
    assert refusal(validate.fingerprint, typed, "POP3 certificate fingerprint").startswith(
        "The POP3 certificate fingerprint must be a SHA-256 fingerprint")


# --- the provider host and port --------------------------------------

@pytest.mark.parametrize("typed", ["pop .example.org", "a@example.org", "pop!example.org",
                                   "localhost", "192.0.2.256"])
def test_a_host_that_is_not_a_name_or_an_address_is_refused(typed):
    assert "host" in refusal(validate.host, typed, "POP3 host", "pop.example.org")


@pytest.mark.parametrize("typed", ["pop\n.example.org", "pop.example\n.org"])
def test_a_line_break_ending_a_label_is_refused_by_the_field_not_by_the_column(typed):
    # `$` matches before a final newline: with `.match` these reached the CHECK
    assert not validate.is_host(typed)
    assert "host" in refusal(validate.host, typed, "POP3 host", "pop.example.org")
    # and the journal's filter no longer passes one as a host name
    assert not validate.is_host("pop.example.org\n")


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


@pytest.mark.parametrize("typed", ["0", "65536", "-1", "abc", "99 5", " 995 ", "9.5",
                                   "1" * 5000, "0" * 5000])
def test_a_port_outside_one_to_65535_is_refused(typed):
    assert refusal(validate.port, typed, "POP3 port") == \
        "The POP3 port must be a whole number from 1 to 65535."


@pytest.mark.parametrize("typed,number", [("1", 1), ("995", 995), ("65535", 65535),
                                          ("0" * 5000 + "995", 995)])
def test_a_port_inside_the_range_is_taken_as_a_number(typed, number):
    assert validate.port(typed, "POP3 port") == number


def test_an_empty_port_takes_the_forms_default_where_there_is_one_and_is_refused_where_there_is_not():
    assert validate.port("", "POP3 port", default=995) == 995
    assert validate.port(None, "SMTP port", default=587) == 587
    assert refusal(validate.port, "", "POP3 port") == "The POP3 port is needed."


# --- the protocol ------------------------------------------------------------------

@pytest.mark.parametrize("typed,default,chosen", [
    ("imap", "pop3", "imap"), ("pop3", "imap", "pop3"), (" imap ", "pop3", "imap"),
    (None, "pop3", "pop3"), (None, "imap", "imap"), ("", "imap", "imap")])
def test_a_protocol_is_pop3_or_imap_and_a_form_without_one_keeps_the_default(
        typed, default, chosen):
    assert validate.protocol(typed, default) == chosen


@pytest.mark.parametrize("typed", ["IMAP", "smtp", "imap4", "pop3 imap"])
def test_anything_else_is_refused_with_a_sentence(typed):
    assert refusal(validate.protocol, typed) == "The protocol is POP3 or IMAP."


def test_the_protocol_changes_only_while_the_mailbox_is_disabled():
    assert refusal(validate.protocol_change, "active", "pop3", "imap") == \
        validate.PROTOCOL_WHILE_ENABLED
    assert validate.protocol_change("active", "imap", "imap") == "imap"
    assert validate.protocol_change("deactivated", "pop3", "imap") == "imap"


def test_an_imap_mailbox_keeps_its_mail_at_the_provider_and_a_pop3_one_may_not():
    assert refusal(validate.keeps_at_provider, "imap", False) == validate.IMAP_KEEPS
    validate.keeps_at_provider("imap", True)
    validate.keeps_at_provider("pop3", False)


def test_the_protocols_the_screen_takes_are_the_schemas_own_list():
    """A protocol the column refuses would be an error page where a sentence was owed."""
    schema = Path(__file__).resolve().parents[2] / "schema" / "0008_collection_over_imap.sql"
    listed = re.search(r"CHECK \(protocol IN \(([^)]*)\)\)", schema.read_text()).group(1)
    assert set(re.findall(r"'([a-z0-9]+)'", listed)) == set(validate.PROTOCOLS) \
        == set(validate.PROVIDER_PORTS)


# --- the deletion window ---------------------------------------------------

@pytest.mark.parametrize("typed,days", [("", 14), ("   ", 14), (None, 14), ("45", 45),
                                        ("1", 1), ("1000000", 1000000)])
def test_the_window_defaults_to_fourteen_and_takes_a_positive_whole_number(typed, days):
    assert validate.window(typed) == days


@pytest.mark.parametrize("typed,says", [
    ("many", "whole number of days"), ("4.5", "whole number of days"),
    ("0", "more than zero days"), ("-3", "more than zero days"),
    ("1000001", "at most 1000000 days"),
    # past the 4300 digits `int()` reads, which raised rather than refused
    ("9" * 5000, "at most 1000000 days"), ("-" + "9" * 5000, "more than zero days"),
])
def test_a_window_that_is_not_a_positive_number_of_days_says_which(typed, says):
    assert says in refusal(validate.window, typed)


def test_the_windows_bound_is_the_date_arithmetics_and_the_columns():
    # the screens add the window to a date, and dates end in the year 9999
    assert validate.WINDOW_MAX == 1000000
    schema = (__import__("pathlib").Path(__file__).resolve().parents[2]
              / "schema" / "0001_initial.sql").read_text()
    assert f"delete_window_days BETWEEN 1 AND {validate.WINDOW_MAX}" in schema


@pytest.mark.parametrize("typed,high,read", [
    ("7", 10, 7), ("-7", 10, -7), ("0010", 10, 10), ("0" * 5000 + "3", 10, 3),
    ("11", 10, 11), ("1" * 5000, 10, 11), ("-" + "1" * 5000, 10, -11),
    (str(2 ** 63 - 1), 2 ** 63 - 1, 2 ** 63 - 1),
])
def test_a_number_spelt_longer_than_its_bound_reads_as_past_the_bound_without_int(
        typed, high, read):
    # `int()` raises past 4300 digits, so a field that read every number with it answered
    # a long one with an error page; one past the bound is all the check needs to know
    assert validate.whole_number(typed, high) == read


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
    # The limit is the hasher's 256 bytes of UTF-8: 129 Cyrillic letters pass it
    for over in ("e" * (auth.PASSWORD_MAX + 1), "я" * (auth.PASSWORD_MAX // 2 + 1)):
        said = refusal(validate.password_twice, over, over)
        assert "at most 256 bytes" in said and "128 Cyrillic letters" in said
        with pytest.raises(ValueError):    # make_hash would indeed have raised on it
            auth.make_hash(over)
    for most in ("e" * auth.PASSWORD_MAX, "я" * (auth.PASSWORD_MAX // 2)):
        assert validate.password_twice(most, most) == most


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
