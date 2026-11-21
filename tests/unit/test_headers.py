"""A header's value as every program reads it (`lib/headers.py`): no control characters.

PostgreSQL holds no NUL in a text, and the driver refuses a string holding one before the
server is asked. The pass takes that refusal for the message's own fault, so one such
byte in a subject would leave a message in the archive with no row, for nobody. Dovecot
hands the pass U+FFFD for a NUL; the Sent hook and the import read the file themselves.
So the readers turn a NUL into U+FFFD and remove the other C0 control characters but the
tab, once, where the pass, the Sent hook and the import's key for a message already seen
all read.
"""

import datetime

import pytest

from maildivvy.fanout import pass_
from maildivvy.importer import source
from maildivvy.lib import headers
from maildivvy.senthook import hook

HASH = "{SHA512-CRYPT}$6$x$" + "x" * 86
# what a hostile or a broken sender puts in a header: a NUL, a bell, an escape sequence
SUBJECT = "Your\x00 invoice\x07 \x1b[31mis\tready\x1f"
MESSAGE_ID = "<in\x00voice\x01-7@example.org>"
SENDER = "Billing\x00 <Bill\x00ing@Example.org>"


def test_no_value_read_carries_a_nul_or_a_control_character_but_the_tab():
    assert headers.first_occurrence(SUBJECT) == "Your\ufffd invoice [31mis\tready"
    assert headers.first_occurrence(MESSAGE_ID) == "<in\ufffdvoice-7@example.org>"
    assert headers.sender_of(SENDER) == "bill\ufffding@example.org"
    assert headers.first_occurrence("\x01\x02\x1f") == ""
    # our own fields are read the same: the first line, and none of them in it
    assert headers.first_line("yes\x01\nno") == "yes"
    assert headers.ours_or_none("\x08none\x1b") is None
    assert headers.ours_or_none("W-1\x00") == "W-1\ufffd"
    assert headers.date_of("Tue, 15 Mar 2016 09:00:00\x01 +0300") == datetime.datetime(
        2016, 3, 15, 6, 0, tzinfo=datetime.timezone.utc)
    for value in (SUBJECT, MESSAGE_ID, "a\rb\x0bc\x0cd"):
        assert not any(ord(c) < 0x20 and c != "\t" for c in headers.first_occurrence(value))


def test_a_continuation_line_is_told_from_a_second_occurrence_before_anything_is_removed():
    """What tells them apart is the line's first character as it came."""
    assert headers.first_occurrence("one\x01\n two\r\n\tthree\x1b") == "one two three"
    # a line beginning with a control character is no continuation: the second
    # occurrence, dropped
    assert headers.first_occurrence("ours\n\x00 theirs") == "ours"
    # and a line holding nothing but control characters adds nothing
    assert headers.first_occurrence("one\n \x07\x01\n two") == "one two"


def test_the_pass_the_sent_hook_and_the_import_read_one_message_id_from_one_header():
    """The import passes over a file whose Message-ID the ledger holds, and the row it is
    held against was written by the pass or by the Sent hook. The pass reads the header
    through Dovecot, which hands it U+FFFD for a NUL; the other two read the file."""
    raw = (b"Message-ID: " + MESSAGE_ID.encode() + b"\r\nSubject: " + SUBJECT.encode()
           + b"\r\nFrom: " + SENDER.encode() + b"\r\n\r\na body\r\n")
    imported = source.first_value(source.header_section(raw), "message-id")
    from_dovecot = MESSAGE_ID.replace("\x00", "\ufffd")
    recorded = pass_.read({"uid": "1", "hdr.message-id": from_dovecot}).message_id
    sent = hook.read_message(raw)
    assert imported == recorded == sent.message_id == "<in\ufffdvoice-7@example.org>"
    assert sent.subject == "Your\ufffd invoice [31mis\tready"
    assert sent.sender == "bill\ufffding@example.org"


def test_a_message_with_a_nul_in_its_headers_is_recorded_without_it(database):
    """On the unit tier's real database, as the pipeline and as the Sent hook. The control
    is the refusal itself: the same statement with the value as it came is refused by the
    driver, with no SQLSTATE, which the pass takes for the message's own fault."""
    domain = database.value("INSERT INTO domain (label, archive_password_hash) VALUES "
                            "('example', %s) RETURNING id", (HASH,))
    record = {"uid": "3", "storageid": "1757.M3.host", "hdr.subject": SUBJECT,
              "hdr.message-id": MESSAGE_ID, "hdr.from": SENDER,
              headers.WITHHELD_FIELD: "W-1\x00\nnone"}
    conn = database.connect("pipeline")
    try:
        with conn.cursor() as cur:
            with pytest.raises(ValueError) as refused:
                cur.execute("INSERT INTO message (domain_id, subject) VALUES (%s, %s)",
                            (domain, SUBJECT))
            assert not hasattr(refused.value, "pgcode") and pass_.its_own_fault(refused.value)
            pass_.record_message(cur, pass_.Domain(domain, "example", True), "Quarantine",
                                 pass_.read(record))
        conn.commit()
    finally:
        conn.close()
    outgoing = hook.read_message(b"Message-ID: <sent\x00-1@example.org>\r\nSubject: "
                                 + SUBJECT.encode() + b"\r\nFrom: " + SENDER.encode()
                                 + b"\r\n\r\na body\r\n")
    conn = database.connect("senthook")
    try:
        with conn.cursor() as cur:
            cur.execute(hook.RECORD, (domain, outgoing.message_id, outgoing.date,
                                      outgoing.sender, outgoing.subject))
        conn.commit()
    finally:
        conn.close()
    assert database.sql("SELECT archive_uid, state, subject, message_id_header, sender, "
                        "withheld_id FROM message ORDER BY id") == [
        (3, "withheld", "Your\ufffd invoice [31mis\tready", "<in\ufffdvoice-7@example.org>",
         "bill\ufffding@example.org", "W-1\ufffd"),
        (None, "delivered", "Your\ufffd invoice [31mis\tready", "<sent\ufffd-1@example.org>",
         "bill\ufffding@example.org", None)]
