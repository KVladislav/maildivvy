"""The report that stands in for a withheld message, and the notice put into a marked one.

Every field the report quotes comes out of a message that has already been judged
hostile, so the sender chose all of it. The tests here drive
those fields, not the wording: what they pin is that nothing a sender writes can become
a header of this report or a line of its body, that a header this machine cannot parse
does not stop the report being written, and that the two reasons get
different words.
"""

import email
import email.header
import email.policy

import pytest

from maildivvy.deliver import report
from maildivvy.lib import scan, store

DOMAIN = "example"
WITHHELD_ID = "0123456789abcdef0123456789abcdef"

ORDINARY = ("From: Someone <someone@example.org>\r\n"
            "To: archive@example\r\n"
            "Subject: an invoice\r\n"
            "Message-ID: <abc@example.org>\r\n"
            "\r\nwords\r\n")


def parse(text):
    return email.message_from_string(text, policy=email.policy.default)


def compose(reason=scan.INFECTED, original=ORDINARY, withheld_id=WITHHELD_ID, domain=DOMAIN):
    return report.compose(reason, parse(original), withheld_id, domain)


def parsed(**kwargs):
    return email.message_from_bytes(compose(**kwargs), policy=email.policy.default)


# --- infected and unscanned are different facts --------------------------------------


def test_the_infected_report_says_malware_and_the_unscanned_one_says_nobody_looked():
    infected = parsed(reason=scan.INFECTED).get_content()
    unscanned = parsed(reason=scan.UNSCANNED).get_content()
    assert "found malware in it" in infected
    assert "malware" not in unscanned  # not one word of it claims anything was found
    assert "too large to scan" in unscanned and "nobody looked at it" in unscanned
    assert "NOTHING IS KNOWN ABOUT IT" in unscanned
    assert "nothing is known" not in infected.lower()
    assert infected != unscanned
    for words in (infected, unscanned):
        assert store.QUARANTINE in words  # where the reader will find the message


@pytest.mark.parametrize("reason", [scan.CLEAN, scan.UNAVAILABLE, "", None, "Infected"])
def test_an_unrecognised_reason_raises_rather_than_defaulting(reason):
    """The default a programmer reaches for is the first branch, and the first branch
    is the malware wording - which would tell fifty people a virus was found."""
    with pytest.raises(report.UnknownReason):
        compose(reason=reason)


def test_the_reason_is_named_in_a_header_of_the_report_too():
    assert parsed(reason=scan.UNSCANNED)[report.REASON_HEADER] == scan.UNSCANNED


# --- nothing a sender writes becomes a header or a body ------------------------------


def test_an_encoded_word_subject_cannot_write_this_reports_headers_or_its_body():
    """Measured on the predecessor: an encoded word decodes to whatever bytes it carried,
    line breaks included, and those reach the string the parser hands back. A pair of
    them under the machine's own From line is a body of the sender's own."""
    # "hi\r\nX-Maildivvy-Spam-Mark: yes\r\n\r\nmy own body" as a base64 encoded word
    hostile = ("From: a@example.org\r\n"
               "Subject: =?utf-8?B?aGkNClgtTWFpbGRpdnZ5LVNwYW0tTWFyazogeWVzDQoNCm15IG93biBib2R5?=\r\n"
               "\r\nwords\r\n")
    message = parsed(original=hostile)
    assert message.get_all("X-Maildivvy-Spam-Mark") is None  # which would hide the report itself
    assert message.get_content().count("my own body") == 1  # only inside the quoted block
    assert "my own body" in message.get_content().split("The message it replaces:")[1]
    assert "hi X-Maildivvy-Spam-Mark: yes my own body" in message["Subject"]


def test_an_attachment_name_with_a_blank_line_stays_one_body_line():
    hostile = ("From: a@example.org\r\nSubject: attached\r\nMIME-Version: 1.0\r\n"
               'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
               "--b\r\nContent-Type: text/plain\r\n\r\nwords\r\n"
               "--b\r\nContent-Type: application/octet-stream\r\n"
               'Content-Disposition: attachment; filename="=?utf-8?B?eC5leGUNCg0KZmFrZSBub3RpY2U=?="\r\n'
               "\r\nAAEC\r\n--b--\r\n")
    body = parsed(original=hostile).get_content()
    lines = [line for line in body.splitlines() if "fake notice" in line]
    assert len(lines) == 1 and lines[0].lstrip().startswith("Attachments:")


def test_a_value_is_collapsed_before_it_is_encoded_never_after():
    """Encoding first would only hide the break inside an encoded word for the next
    reader to decode; this strips first and encodes what is left."""
    assert report.one_line("a\r\nb\tc\x7f  d") == "a b c d"
    assert report.one_line("é\r\né") == "é é"
    value = report.header_value("café\r\nX-Forged: yes")
    assert "\r" not in value and "\n" not in value
    assert value.startswith("=?utf-8?")  # what is left is not ASCII, so it is encoded whole
    assert str(email.header.make_header(email.header.decode_header(value))) \
        == "café X-Forged: yes"
    assert report.header_value("plain words") == "plain words"  # ASCII is left as it is


def test_the_header_block_is_ascii_while_the_body_declares_utf8():
    raw = compose(original=ORDINARY.replace("an invoice", "рейс — 1"))
    head = raw.split(b"\r\n\r\n", 1)[0]
    head.decode("ascii")  # raises if one byte of it is not
    message = email.message_from_bytes(raw, policy=email.policy.default)
    assert message.get_content_charset() == "utf-8"
    assert "рейс — 1" in message.get_content()
    assert "рейс — 1" in message["Subject"]


# --- a header this machine cannot read does not stop the report ----------------------


def test_a_from_the_library_refuses_to_parse_is_quoted_as_unreadable():
    """A strict address parser refuses a header whose encoded word decodes to a line
    break. Uncaught, the sender picks the exception: no report is written, nobody is
    told anything was withheld, and the delivery failure walks into the bounded retry."""
    hostile = ("From: =?utf-8?B?YQ0KYg==?= <a@example.org>\r\nSubject: hello\r\n\r\nwords\r\n")
    original = parse(hostile)
    with pytest.raises(Exception):
        str(original["From"])  # the control: reading it the plain way does raise
    body = parsed(original=hostile).get_content()
    assert "(an unreadable From header)" in body
    assert "hello" in body  # and the rest of the report is there


def test_a_message_missing_every_field_the_report_quotes_is_still_reported():
    body = parsed(original="\r\nnot even a header\r\n").get_content()
    assert "(no From header)" in body and "(no Subject header)" in body
    assert "(none)" in body and "(none named)" in body


def test_an_attachment_name_that_cannot_be_walked_does_not_stop_the_report():
    class Hostile:
        def get(self, name, missing=None):
            return missing

        def walk(self):
            raise ValueError("the sender picked this exception")

    body = report.compose(scan.INFECTED, Hostile(), WITHHELD_ID, DOMAIN).decode()
    assert "(an unreadable attachment name)" in body


# --- the report's own identity -----------------------------------------


def test_the_report_carries_the_withheld_id_as_its_own_message_id():
    message = parsed()
    assert message["Message-ID"] == f"<{WITHHELD_ID}@{DOMAIN}>"
    assert message[report.WITHHELD_HEADER] == WITHHELD_ID


def test_the_report_names_the_withheld_id_where_a_reader_and_the_pass_both_find_it():
    message = parsed()
    assert WITHHELD_ID in message.get_content()  # for a person
    assert message[report.WITHHELD_HEADER] == WITHHELD_ID  # for the pass
    assert message["From"] == f"maildivvy@{DOMAIN}" and message["To"] == f"archive@{DOMAIN}"
    assert message["Date"]


def test_a_message_that_is_both_infected_and_spam_is_quoted_with_its_mark():
    marked = ORDINARY.replace("Subject: an invoice",
                              f"Subject: {report.SPAM_SUBJECT_PREFIX}an invoice")
    body = parsed(original=marked).get_content()
    assert f"{report.SPAM_SUBJECT_PREFIX}an invoice" in body


# --- the notice inside a marked message ----------------------------------------------


def test_the_notice_states_the_score_and_the_threshold_and_never_who_receives_it():
    notice = report.spam_notice(9.25, 8.0)
    assert "9.25" in notice and "8.00" in notice
    assert "when the message arrived" in notice
    assert "does not re-mark" in notice
    for word in ("receive", "recipient", "mailbox", "deliver", "unwanted", "virus", "malware"):
        assert word not in notice.lower(), word


def test_the_html_notice_claims_the_same_things_and_escapes_what_it_shows():
    html = report.spam_notice(9.25, 8.0, html=True)
    assert "9.25" in html and "8.00" in html
    assert html.startswith("<") and "<p>" in html
    assert "&quot;[spam]&quot;" in html  # the quotes around the prefix, escaped
    assert "when the message arrived" in html and "does not re-mark" in html


def test_the_notices_lines_are_short_enough_to_stand_in_a_quoted_printable_leaf():
    for line in report.spam_notice(150.0, 1.0).splitlines():
        assert len(line) <= 72, line


def test_the_notice_names_the_subject_prefix_a_reader_can_see():
    assert report.SPAM_SUBJECT_PREFIX == "[spam] "  # the trailing space is part of it
    assert "[spam]" in report.spam_notice(9.0, 8.0)
