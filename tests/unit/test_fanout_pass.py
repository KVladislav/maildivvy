"""What the pass decides from a message's fields, and what it does on the filesystem.

The parts that need a real archive, a real Dovecot and real rows are driven on the test
VM. What is tested here is what is true of the
text: which header of which name is read, what a sender or a score turns into, which
messages get names at all, and that a link that already exists is success.

Nothing here spells a verdict header: every one of them comes from the delivery
filter's own modules, so the two programs cannot come to disagree about a name.
"""

import datetime
import hashlib
import os
from decimal import Decimal
from pathlib import Path

import pytest

from maildivvy.deliver import marks, report
from maildivvy.fanout import ledger as ledger_module
from maildivvy.fanout import pass_
from maildivvy.lib import headers, messageid, store


def record(**fields):
    """A doveadm answer for one message, with the keys the pass asks for."""
    answer = {"uid": "1"}
    answer.update(fields)
    return answer


MARK = f"hdr.{marks.SPAM_MARK_HEADER.lower()}"
SCORE = f"hdr.{marks.SPAM_SCORE_HEADER.lower()}"
WITHHELD = f"hdr.{report.WITHHELD_HEADER.lower()}"
REASON = f"hdr.{report.REASON_HEADER.lower()}"


# --- the header names come from the filter, never from a second spelling ------------------------


def test_the_block_the_filter_writes_is_the_block_the_pass_reads():
    # The filter's own block, as doveadm hands each of its fields back to the pass.
    def read_back(block):
        return pass_.read(record(**{headers.field(name): value for name, value in block
                                    if headers.field(name) in pass_.FIELDS}))

    spam = read_back(marks.verdict_headers("clean", None, 9.5, "add header", True,
                                           None, None, "c" * 32))
    assert spam.spam is True and spam.score == Decimal("9.50")
    assert spam.withheld_id == "c" * 32 and spam.reason is None and not spam.is_report
    clean = read_back(marks.verdict_headers("clean", None, None, None, False, None, None, None))
    assert clean.spam is False and clean.score is None
    assert clean.withheld_id is None and clean.reason is None
    # every field the pass asks Dovecot for, but the message's own, is one the block holds
    written = {headers.field(name) for name, _ in marks.verdict_headers(
        "clean", None, 1.0, "no action", False, None, None, "c" * 32)}
    assert set(pass_.FIELDS) - written == {"uid", "storageid", "hdr.from", "hdr.subject",
                                           "hdr.date", "hdr.message-id"}


def test_every_field_is_asked_for_as_one_lowercase_word():
    for field in pass_.FIELDS:
        assert field == field.lower()
        assert " " not in field


# --- of our own headers, only the first occurrence ----------------------------------


def test_a_senders_own_mark_below_ours_is_never_the_one_read():
    # doveadm hands both occurrences back in one field, ours first.
    assert pass_.read(record(**{MARK: "no\nyes"})).spam is False
    assert pass_.read(record(**{MARK: "yes\nno"})).spam is True


def test_a_senders_own_score_below_ours_is_never_the_one_read():
    assert pass_.read(record(**{SCORE: "1.00\n99.00"})).score == Decimal("1.00")


def test_a_folded_header_of_the_senders_keeps_its_continuation_lines():
    # a continuation line begins with whitespace; a second occurrence does not
    assert headers.first_occurrence("a long\n subject") == "a long subject"
    assert headers.first_occurrence("first\nsecond") == "first"
    assert headers.first_occurrence("") == ""


# --- the spam verdict is the mark and nothing else ----------------------------------


def test_an_absent_mark_is_not_spam_whatever_the_score_says():
    assert pass_.read(record()).spam is False
    assert pass_.read(record(**{SCORE: "150.00"})).spam is False
    assert pass_.read(record(**{MARK: ""})).spam is False


def test_only_the_marks_own_word_reads_as_spam():
    assert pass_.read(record(**{MARK: "yes"})).spam is True
    assert pass_.read(record(**{MARK: " YES "})).spam is True
    for value in ("no", "true", "1", "spam", "yes please"):
        assert pass_.read(record(**{MARK: value})).spam is False, value


# --- the score is stored, and no value of it raises ---------------------------------


def test_a_score_is_stored_as_the_scanner_gave_it():
    assert pass_.read(record(**{SCORE: "8.00"})).score == Decimal("8.00")
    assert pass_.read(record(**{SCORE: "-1.20"})).score == Decimal("-1.20")


def test_no_value_of_the_score_header_raises_and_an_unreadable_one_is_null():
    for value in ("", marks.NO_SCORE, "seven", "8.00 9.00", "NaN", "Infinity",
                  "99999999.00", "1e400", "0x10", " "):
        assert pass_.read(record(**{SCORE: value})).score is None, value


def test_a_score_too_wide_for_the_column_is_stored_as_null_rather_than_refused():
    # numeric(6,2): four digits before the point
    assert pass_.read(record(**{SCORE: "9999.99"})).score == Decimal("9999.99")
    assert pass_.read(record(**{SCORE: "10000.00"})).score is None


# --- the sender is the parsed address, never the first address-shaped token ---------------------


def test_the_sender_is_the_parsed_address_and_not_the_display_name():
    assert pass_.read(record(**{"hdr.from": "acme@gmail.com <impostor@example.net>"})) \
        .sender == "impostor@example.net"


def test_a_quoted_display_name_holding_an_angle_bracket_is_still_not_the_address():
    assert pass_.read(record(**{"hdr.from": '"weird <name" <real@example.org>'})) \
        .sender == "real@example.org"


def test_the_sender_is_lower_cased_and_never_folded():
    assert pass_.read(record(**{"hdr.from": "John.Smith+tag@Corp.Example"})) \
        .sender == "john.smith+tag@corp.example"


def test_a_from_that_parses_to_no_address_stores_no_sender():
    for value in ("", "(nobody)", "Someone"):
        assert pass_.read(record(**{"hdr.from": value})).sender is None, value


def test_nothing_in_the_pass_compares_the_sender_with_the_domains_own_address():
    # the sender rules are gone: a From proves nothing about who wrote a message, so
    # no query of this program reads the domain's own external address at all
    for sql in (pass_.DOMAINS, pass_.RECEIVERS, pass_.RECORD, ledger_module.LINK, pass_.REPORTED):
        assert "external_mailbox" not in sql and "address" not in sql, sql
    assert "sender" not in pass_.RECEIVERS


# --- the rest of the row ------------------------------------------------------------------------


def test_the_message_id_subject_and_date_are_read_from_their_own_headers():
    read = pass_.read(record(**{"hdr.message-id": "<m1@example.org>",
                                "hdr.subject": "hello",
                                "hdr.date": "Tue, 15 Sep 2026 10:00:00 +0000"}))
    assert read.message_id == "<m1@example.org>"
    assert read.subject == "hello"
    assert read.date is not None and read.date.year == 2026


def test_a_date_that_will_not_parse_is_no_date_and_does_not_raise():
    assert pass_.read(record(**{"hdr.date": "not a date"})).date is None
    assert pass_.read(record()).date is None


def test_the_withheld_id_and_the_report_reason_tell_the_two_copies_apart():
    withheld = pass_.read(record(**{WITHHELD: "abc123"}))
    assert withheld.withheld_id == "abc123" and withheld.reason is None
    report_row = pass_.read(record(**{WITHHELD: "abc123", REASON: "infected"}))
    assert report_row.is_report and report_row.reason == "infected"
    assert not withheld.is_report


def test_our_own_none_is_no_withheld_id_and_no_report_whatever_the_sender_added():
    """The filter's block always carries both fields, `none`
    where there is nothing to say, and the sender's copy below it is never read."""
    clean = pass_.read(record(**{WITHHELD: f"{report.NONE}\n{'a' * 32}",
                                 REASON: f"{report.NONE}\ninfected"}))
    assert clean.withheld_id is None and clean.reason is None and not clean.is_report
    held = pass_.read(record(**{WITHHELD: "b" * 32, REASON: f"{report.NONE}\ninfected"}))
    assert held.withheld_id == "b" * 32 and not held.is_report


class Ledger:
    """Just enough of the pipeline's database for one domain's tick: message rows.

    It refuses what PostgreSQL refuses of a message row: an index entry over the btree's
    2704 bytes (`message_domain_message_id_idx`), and any UID in `refused`, standing for a
    value the database will not take. A savepoint takes back the rows written after it.
    """

    BTREE_LIMIT = 2704

    def __init__(self, receivers=(), refused=(), refused_links=()):
        self.messages = []   # (id, withheld_id, state, report_of, archive_uid, message_id_header)
        self.cursors = {}
        self.numbering = {}  # folder -> the UIDVALIDITY its cursor row keeps (None: none)
        self.folder_rows = []  # what the way back reads of a folder's rows
        self.renumbered = {}
        self.answer = None
        self.receivers = list(receivers)
        self.refused = set(refused)
        self.refused_links = set(refused_links)
        self.links = []
        self.savepoint = None
        self.calls = []
        self.next_id = 0

    def commit(self):
        self.calls.append("commit")

    def rollback(self):
        self.calls.append("rollback")

    def close(self):
        self.calls.append("close")

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        sql = " ".join(sql.split())
        if sql.startswith("SELECT last_uid"):
            self.answer = (self.cursors.get(params[1], 0),)
        elif sql.startswith("SELECT uidvalidity, last_uid FROM pass_cursor"):
            self.answer = ((self.numbering[params[1]], self.cursors.get(params[1], 0))
                           if params[1] in self.numbering else None)
        elif sql.startswith("UPDATE pass_cursor SET uidvalidity"):
            if self.numbering.get(params[2]) is None:
                self.numbering[params[2]] = params[0]
        elif sql.startswith("UPDATE pass_cursor SET last_uid = %s, uidvalidity"):
            self.cursors[params[3]], self.numbering[params[3]] = params[0], params[1]
        elif sql.startswith("SELECT id, archive_uid, message_id_header"):
            self.answer = list(self.folder_rows)
        elif sql == " ".join(pass_.UNNUMBER.split()):
            self.renumbered.update({row[0]: None for row in self.folder_rows})
        elif sql.startswith("UPDATE message SET archive_uid"):
            self.renumbered[params[1]] = params[0]
        elif sql.startswith("UPDATE pass_cursor"):
            self.cursors[params[2]] = params[0]
        elif sql.startswith("SELECT id FROM message"):
            found = [m[0] for m in self.messages
                     if m[1] == params[1] and m[2] != "delivered"]
            self.answer = (found[0],) if found else None
        elif sql.startswith("SELECT 1 FROM message"):
            domain_id, uid, delivered = params
            found = [m for m in self.messages if m[4] == uid and (m[2] == "delivered") == delivered]
            self.answer = (1,) if found else None
        elif sql.startswith("INSERT INTO message"):
            if len((params[1] or "").encode()) > self.BTREE_LIMIT:
                raise RuntimeError("index row size exceeds btree version 4 maximum 2704")
            if params[2] in self.refused:
                raise RuntimeError(f"invalid value in UID {params[2]}\nDETAIL: a second line")
            self.next_id += 1  # a sequence: a rolled-back row's id is never given again
            row = (self.next_id, params[4], params[3], params[5], params[2], params[1])
            self.messages.append(row)
            self.answer = (row[0],)
        elif sql.startswith("SELECT r.mailbox_id"):
            self.answer = list(self.receivers)
        elif sql.startswith("INSERT INTO delivery"):
            if params[0] in self.refused_links:
                raise RuntimeError(f"delivery row of message {params[0]} refused")
            self.links.append(params)
        elif sql.startswith("SELECT id, label"):
            self.answer = [(1, "example", True)]
        elif sql.startswith("SAVEPOINT"):
            self.savepoint = (len(self.messages), len(self.links))
        elif sql.startswith("ROLLBACK TO SAVEPOINT"):
            del self.messages[self.savepoint[0]:]
            del self.links[self.savepoint[1]:]

    def fetchone(self):
        return self.answer

    def fetchall(self):
        return self.answer


def test_a_report_the_filter_stores_while_the_pass_reads_is_still_linked(monkeypatch):
    """The filter stores the withheld message, then its report.
    Read quarantine-first, a filter landing between the two readings left the report in
    INBOX and its message unread, so the report's row pointed at nothing, for ever.
    INBOX is listed first now: a report seen there has its message stored already."""
    withheld = record(uid="1", **{WITHHELD: "c" * 32, REASON: report.NONE})
    told = record(uid="1", **{WITHHELD: "c" * 32, REASON: "infected"})
    landed = []

    def fetch(login, folder, fields, *search):
        # the filter lands after the pass's first reading, whichever folder that was
        stored = {store.QUARANTINE: [withheld], pass_.INBOX: [told]}[folder] if landed else []
        landed.append(folder)
        above = int(search[1].split(":")[0])
        return [r for r in stored if int(r["uid"]) >= above]

    monkeypatch.setattr(pass_.doveadm, "fetch", fetch)
    ledger = Ledger()
    args = pass_.parse_args([])
    pass_.fan_out(ledger, pass_.Domain(1, "example", True), args)
    pass_.fan_out(ledger, pass_.Domain(1, "example", True), args)  # the next tick
    reports = [m for m in ledger.messages if m[2] == "delivered"]
    assert len(reports) == 1 and len(ledger.messages) == 2, ledger.messages
    assert reports[0][3] == [m[0] for m in ledger.messages if m[2] == "withheld"][0]


# --- one message never holds a domain's cursor --------------------------------------

# The standard library's parser raises OverflowError for both, which is neither of the two
# errors it documents; once, either one stopped its domain's fan-out for good.
OVERFLOWING_DATES = ("Mon, 1 Jan 2024 00:00:00 +99999999999999999999",
                     "Mon, 1 Jan 99999999999 00:00:00 +0000")
DOMAIN = pass_.Domain(1, "example", True)


def ordinary(uid, **fields):
    return record(uid=str(uid), **{"hdr.message-id": f"<m{uid}@example.org>", **fields})


def archive(monkeypatch, inbox, quarantine=()):
    """doveadm's answers for one domain's archive: a range above a cursor, or one UID."""
    def fetch(login, folder, fields, *search):
        held = {pass_.INBOX: list(inbox), store.QUARANTINE: list(quarantine)}[folder]
        if ":" not in search[1]:
            return [r for r in held if r["uid"] == search[1]]
        above = int(search[1].split(":")[0])
        return [r for r in held if int(r["uid"]) >= above]

    monkeypatch.setattr(pass_.doveadm, "fetch", fetch)


def linking(monkeypatch, tmp_path):
    """Names made by the tick: (source, maildirs) of every link_into call."""
    made = []
    monkeypatch.setattr(pass_.doveadm, "message_file", lambda *a, **k: tmp_path / "archived")
    monkeypatch.setattr(store, "link_into",
                        lambda source, boxes, root=None: made.append((source, boxes)) or [])
    return made


def test_no_value_of_the_date_header_raises_and_an_unreadable_one_is_no_date():
    for value in (*OVERFLOWING_DATES, "not a date", "", None):
        assert headers.date_of(value) is None, value
        assert pass_.read(record(**{"hdr.date": value})).date is None, value


def test_a_date_with_no_zone_or_an_unknown_one_is_utc_and_a_zoned_one_keeps_its_offset():
    utc = datetime.timezone.utc
    for value in ("Mon, 16 Nov 2026 10:00:00", "Mon, 16 Nov 2026 10:00:00 -0000"):
        assert headers.date_of(value) == datetime.datetime(2026, 11, 16, 10, tzinfo=utc), value
        assert pass_.read(record(**{"hdr.date": value})).date.tzinfo is utc, value
    zoned = headers.date_of("Mon, 16 Nov 2026 10:00:00 +0200")
    assert zoned.utcoffset() == datetime.timedelta(hours=2)
    assert zoned == datetime.datetime(2026, 11, 16, 8, tzinfo=utc)


def test_a_date_the_parser_cannot_hold_is_recorded_and_the_cursor_moves_past_it(monkeypatch):
    archive(monkeypatch, [ordinary(1), ordinary(2, **{"hdr.date": OVERFLOWING_DATES[0]}),
                          ordinary(3, **{"hdr.date": OVERFLOWING_DATES[1]}), ordinary(4)])
    ledger = Ledger()
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert [m[4] for m in ledger.messages] == [1, 2, 3, 4]
    assert ledger.cursors[pass_.INBOX] == 4


def test_a_message_id_over_the_index_limit_is_recorded_in_its_bounded_form(monkeypatch):
    huge = "<" + "x" * 4096 + "@example.org>"
    archive(monkeypatch, [ordinary(1), ordinary(2, **{"hdr.message-id": huge}), ordinary(3)])
    ledger = Ledger()
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert [m[4] for m in ledger.messages] == [1, 2, 3]
    assert ledger.messages[1][5] == messageid.stored(huge) != huge
    assert ledger.messages[0][5] == "<m1@example.org>"  # an ordinary one is kept as it is
    assert ledger.cursors[pass_.INBOX] == 3


def test_a_message_id_is_kept_as_it_is_up_to_its_bound_and_is_a_digest_beyond_it():
    assert messageid.stored("<m1@example.org>") == "<m1@example.org>"
    assert messageid.stored(None) is None and messageid.stored("") is None
    at_bound = "<" + "a" * (messageid.BOUND - 2) + ">"
    assert messageid.stored(at_bound) == at_bound
    over = at_bound + "b"
    assert messageid.stored(over) == "sha256:" + hashlib.sha256(over.encode()).hexdigest()
    assert messageid.stored(over + "c") != messageid.stored(over)
    # at four bytes a character the bound, with the domain's id beside it, fits the btree
    assert messageid.BOUND * 4 + 64 < Ledger.BTREE_LIMIT
    # a lone surrogate, which no encoder takes as it is, still gets a digest
    assert messageid.stored("\udcff" * (messageid.BOUND + 1)).startswith("sha256:")


def test_a_message_the_database_refuses_is_skipped_named_in_one_line_and_passed(
        monkeypatch, tmp_path, capsys):
    archive(monkeypatch, [ordinary(1), ordinary(2), ordinary(3)])
    made = linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")], refused={2})
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))

    assert [m[4] for m in ledger.messages] == [1, 3]
    assert ledger.links == [(1, 7), (2, 7)] and len(made) == 2  # its neighbours, linked
    assert ledger.cursors[pass_.INBOX] == 3                     # and the cursor past it
    err = capsys.readouterr().err
    assert "example INBOX: 2 recorded" in err  # the skipped one is not counted
    skipped = [line for line in err.splitlines() if pass_.SKIPPED in line]
    assert len(skipped) == 1, skipped
    assert "example INBOX UID 2" in skipped[0] and "DETAIL" in skipped[0]
    assert ("runuser -u vmail -- /opt/maildivvy/bin/maildivvy-pass --only example "
            "--folder INBOX --uid 2`") in skipped[0]


def test_a_message_refused_after_its_row_was_written_leaves_neither_row_nor_name(
        monkeypatch, tmp_path):
    """Every statement that can refuse a message runs before its first name is made, so a
    skip has no name to take back: a name with no row is a file the ledger never sees."""
    archive(monkeypatch, [ordinary(1), ordinary(2)])
    made = linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")], refused_links={1})
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert [m[4] for m in ledger.messages] == [2] and ledger.links == [(2, 7)]
    assert len(made) == 1 and ledger.cursors[pass_.INBOX] == 2


class DatabaseError(Exception):
    """psycopg2's shape: every error the server raised carries its SQLSTATE."""

    def __init__(self, pgcode):
        super().__init__(f"SQLSTATE {pgcode}")
        self.pgcode = pgcode


def test_only_a_messages_own_values_are_its_fault_and_anything_else_fails_the_domain():
    for own in ("22021", "23505", "54000"):  # bad encoding, a duplicate, the index's limit
        assert pass_.its_own_fault(DatabaseError(own)), own
    for systemic in ("42501", "40P01", "57014", "53100", None):
        assert not pass_.its_own_fault(DatabaseError(systemic)), systemic
    assert pass_.its_own_fault(OverflowError("a header we read"))


@pytest.mark.parametrize("fault", [pass_.doveadm.DoveadmError("UID 1 has no file"),
                                   PermissionError("new/ refused"),
                                   DatabaseError("42501")])  # a revoked grant refuses them all
def test_dovecot_or_the_store_refusing_still_fails_the_domain_and_keeps_its_cursor(
        monkeypatch, tmp_path, fault):
    """That is not this message's fault, and the next minute repeats the work."""
    archive(monkeypatch, [ordinary(1)])
    linking(monkeypatch, tmp_path)

    def refuse(*a, **k):
        raise fault

    monkeypatch.setattr(store, "link_into", refuse)
    ledger = Ledger(receivers=[(7, "ivan")])
    with pytest.raises(type(fault)):
        pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert pass_.INBOX not in ledger.cursors


# --- the way back for a skipped message: one UID, by hand ---------------------------------------


def by_hand(*argv):
    return pass_.parse_args(["--only", "example", *argv])


def test_a_skipped_uid_is_recorded_and_linked_by_hand_and_the_cursor_stays(monkeypatch, tmp_path):
    archive(monkeypatch, [ordinary(2, **{"hdr.date": OVERFLOWING_DATES[0]})])
    made = linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")])
    ledger.cursors[pass_.INBOX] = 5
    pass_.record_one(ledger, DOMAIN, pass_.INBOX, 2, by_hand("--uid", "2"))
    assert [m[4] for m in ledger.messages] == [2] and ledger.links == [(1, 7)] and len(made) == 1
    assert ledger.cursors[pass_.INBOX] == 5 and ledger.calls == ["commit"]


def test_a_uid_the_ledger_holds_in_that_folder_is_refused_by_hand(monkeypatch, tmp_path):
    archive(monkeypatch, [ordinary(2)], quarantine=[ordinary(2)])
    linking(monkeypatch, tmp_path)
    ledger = Ledger()
    ledger.cursors = {pass_.INBOX: 5, store.QUARANTINE: 5}
    pass_.record_one(ledger, DOMAIN, pass_.INBOX, 2, by_hand())
    with pytest.raises(pass_.Refused, match="holds"):
        pass_.record_one(ledger, DOMAIN, pass_.INBOX, 2, by_hand())
    # UIDs are per folder: the quarantine's UID 2 is another message
    pass_.record_one(ledger, DOMAIN, store.QUARANTINE, 2, by_hand())
    assert [(m[4], m[2]) for m in ledger.messages] == [(2, "delivered"), (2, "withheld")]


def test_a_uid_above_the_cursor_or_not_in_the_archive_is_refused_by_hand(monkeypatch, tmp_path):
    archive(monkeypatch, [ordinary(2), ordinary(6)])
    linking(monkeypatch, tmp_path)
    ledger = Ledger()
    ledger.cursors[pass_.INBOX] = 5
    with pytest.raises(pass_.Refused, match="next pass"):
        pass_.record_one(ledger, DOMAIN, pass_.INBOX, 6, by_hand())
    with pytest.raises(pass_.Refused, match="no UID 3"):
        pass_.record_one(ledger, DOMAIN, pass_.INBOX, 3, by_hand())
    assert ledger.messages == []


def test_by_hand_the_command_names_one_domain_and_a_refusal_is_one_line_and_exit_1(
        monkeypatch, capsys):
    with pytest.raises(SystemExit):
        pass_.parse_args(["--uid", "2"])  # a UID is a UID of one domain's folder
    archive(monkeypatch, [])
    ledger = Ledger()
    monkeypatch.setattr(pass_, "connect", lambda args: ledger)
    monkeypatch.setattr(pass_, "drain", lambda *a: pytest.fail("by hand drains nothing"))
    assert pass_.main(["--only", "example", "--uid", "2"]) == 1
    assert "maildivvy-pass: example INBOX UID 2: " in capsys.readouterr().err
    assert ledger.calls == ["rollback", "close"]
    assert pass_.main(["--only", "nowhere", "--uid", "2"]) == 1


# --- no UID under another UIDVALIDITY, and the way back -------------------------------


def numbered(monkeypatch, now, uids=None):
    """Dovecot's UIDVALIDITY for every folder of the archive, and the UIDs it answers
    (None: any)."""
    monkeypatch.setattr(ledger_module.doveadm, "mailbox_status",
                        lambda login, folder, *fields: {"uidvalidity": str(now)})

    def run(verb, login, fields, _, folder, __, uid):
        assert verb == ("fetch",) and fields == "uid storageid"
        return [{"uid": uid, "storageid": f"{uid}.M1P1.host"}] if uids is None or int(uid) in uids else []

    monkeypatch.setattr(ledger_module.doveadm, "run", run)


def test_a_tick_takes_the_folders_uidvalidity_when_its_row_keeps_none(monkeypatch, tmp_path):
    archive(monkeypatch, [ordinary(1)])
    linking(monkeypatch, tmp_path)
    numbered(monkeypatch, 111)
    ledger = Ledger(receivers=[(7, "ivan")])
    ledger.numbering = {pass_.INBOX: None, store.QUARANTINE: None}
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert ledger.numbering == {pass_.INBOX: 111, store.QUARANTINE: 111}
    assert ledger.cursors[pass_.INBOX] == 1 and ledger.links == [(1, 7)]


def test_a_renumbered_folder_fails_the_domains_tick_with_nothing_recorded_or_linked(
        monkeypatch, tmp_path, capsys):
    archive(monkeypatch, [ordinary(4)])
    made = linking(monkeypatch, tmp_path)
    numbered(monkeypatch, 222)
    ledger = Ledger(receivers=[(7, "ivan")])
    ledger.cursors = {pass_.INBOX: 3}
    ledger.numbering = {pass_.INBOX: 111, store.QUARANTINE: 222}
    monkeypatch.setattr(pass_, "connect", lambda args: ledger)
    monkeypatch.setattr(pass_, "drain", lambda *a: (0, 0))
    assert pass_.main([]) == 1
    assert ledger.messages == [] and ledger.links == [] and made == []
    assert ledger.cursors == {pass_.INBOX: 3} and ledger.numbering[pass_.INBOX] == 111
    lines = capsys.readouterr().err.splitlines()
    assert [line for line in lines if line.startswith(pass_.RENUMBERED)] == [
        f"{pass_.RENUMBERED} example INBOX: the archive's UIDVALIDITY is 222, the ledger's UIDs "
        "are 111's, so a UID may name another message: nothing is linked from it until "
        f"`{ledger_module.RENUMBER} --only example --folder INBOX --renumber` gives the rows "
        "their new numbers"], lines
    # both folders renumbered: one line each, from one run
    ledger.numbering = {pass_.INBOX: 111, store.QUARANTINE: 111}
    assert pass_.main([]) == 1
    lines = capsys.readouterr().err.splitlines()
    assert [line.split(":")[1:3] for line in lines if line.startswith(pass_.RENUMBERED)] == [
        [" renumbered", " example INBOX"], [" renumbered", " example Quarantine"]], lines
    # by hand too: a skipped UID is not recorded under another numbering
    with pytest.raises(ledger_module.Renumbered):
        pass_.record_one(ledger, DOMAIN, pass_.INBOX, 2, by_hand("--uid", "2"))


def test_a_folder_that_lost_its_uidlist_alone_fails_the_tick_under_the_same_uidvalidity(
        monkeypatch, tmp_path):
    """With `ctl/` gone and the index kept, Dovecot numbers every file again above the old
    numbers and keeps the UIDVALIDITY, so the old UIDs are simply not there."""
    archive(monkeypatch, [ordinary(6), ordinary(7)])  # the old 1 and 2, numbered again
    made = linking(monkeypatch, tmp_path)
    numbered(monkeypatch, 111, uids={6, 7})
    ledger = Ledger(receivers=[(7, "ivan")])
    ledger.cursors, ledger.numbering = {pass_.INBOX: 2}, {pass_.INBOX: 111}
    with pytest.raises(pass_.Stopped, match="holds no UID 2, the cursor's"):
        pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert ledger.messages == [] and made == [] and ledger.cursors == {pass_.INBOX: 2}
    # the control: the same folder still holding the cursor's UID is a tick like any other
    numbered(monkeypatch, 111, uids={2, 6, 7})
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert ledger.cursors[pass_.INBOX] == 7 and len(made) == 2


def test_the_cursors_uid_is_asked_by_its_files_name_and_a_first_failure_once_more(monkeypatch):
    """A folder that lost its uidlist and has not changed since its last sync answers its
    old UIDs from the index; the first lookup of a file's name numbers it again and fails.
    """
    answers = [pass_.doveadm.DoveadmError("doveadm fetch exited 134: Panic", 134), []]
    asked = []

    def run(verb, login, fields, *search):
        asked.append(fields)
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(ledger_module.doveadm, "run", run)
    assert ledger_module.holds_uid("example", pass_.INBOX, 4) is False
    assert asked == ["uid storageid", "uid storageid"]
    answers[:] = [pass_.doveadm.DoveadmError("one", 75), pass_.doveadm.DoveadmError("two", 75)]
    with pytest.raises(pass_.doveadm.DoveadmError, match="two"):
        ledger_module.holds_uid("example", pass_.INBOX, 4)
    answers[:] = [[{"uid": "4", "storageid": "base"}]]
    assert ledger_module.holds_uid("example", pass_.INBOX, 4) is True


def row(row_id, old_uid, uid, **fields):
    """A folder's row as the way back reads it, and the file it was written from."""
    message = ordinary(uid, **fields)
    read = pass_.read(message)
    return (row_id, old_uid, *pass_.row_key(read)), message


def test_the_way_back_pairs_each_row_with_the_file_it_was_written_from():
    # UID 3 was expunged by hand before the rebuild: 4 and 5 are 3 and 4 now
    first, file_1 = row(11, 1, 1)
    second, file_2 = row(12, 2, 2)
    fourth, file_3 = row(14, 4, 3)
    fifth, file_4 = row(15, 5, 4)
    found, lost = pass_.matched([first, second, fourth, fifth],
                                [pass_.read(f) for f in (file_4, file_3, file_2, file_1)])
    assert found == {11: 1, 12: 2, 14: 3, 15: 4} and lost == []
    # two copies of one message pair in order; a row with no file is lost
    same = {"hdr.message-id": "<twice@example.org>"}
    a, copy_a = row(21, 6, 7, **same)
    b, copy_b = row(22, 8, 9, **same)
    gone, _ = row(23, 10, 99)
    found, lost = pass_.matched([a, b, gone], [pass_.read(copy_b), pass_.read(copy_a)])
    assert found == {21: 7, 22: 9} and lost == [(23, 10)]


def test_the_way_back_renumbers_the_rows_and_takes_the_new_uidvalidity(monkeypatch):
    first, file_2 = row(11, 1, 2)
    fourth, file_4 = row(14, 4, 4)
    # delivered into the folder with no uidlist: the agent numbered it first
    delivered = ordinary(1, **{"hdr.message-id": "<delivered@example.org>"})
    later = ordinary(5)  # numbered above the newest row's file: the next tick's
    monkeypatch.setattr(pass_.doveadm, "fetch", lambda login, folder, fields, *search: (
        [delivered, file_2, file_4, later] if search == ("all",) else pytest.fail(search)))
    numbered(monkeypatch, 222)
    ledger = Ledger()
    ledger.cursors, ledger.numbering = {pass_.INBOX: 5}, {pass_.INBOX: 111}
    ledger.folder_rows = [first, fourth]
    assert pass_.renumber(ledger, DOMAIN, pass_.INBOX, pass_.parse_args([])) == (2, [], 1, [])
    assert ledger.renumbered == {11: 2, 14: 4}
    assert [(m[4], m[5]) for m in ledger.messages] == [(1, "<delivered@example.org>")]
    assert ledger.cursors[pass_.INBOX] == 4 and ledger.numbering[pass_.INBOX] == 222
    assert ledger.calls == ["commit"]
    # once is enough: the same numbering again is refused
    with pytest.raises(pass_.Refused, match="nothing to renumber"):
        pass_.renumber(ledger, DOMAIN, pass_.INBOX, pass_.parse_args([]))


def test_a_row_the_way_back_cannot_match_leaves_every_file_with_no_row_unrecorded(
        monkeypatch, capsys):
    """A row that finds no file may be one of the files with no row, read otherwise today:
    recorded again it would reach every receiver twice. Nothing is recorded, both lists are
    printed, and the command exits 1; the rows it matched are renumbered all the same."""
    first, file_2 = row(11, 1, 2)
    fourth, file_4 = row(14, 4, 4)
    gone, _ = row(16, 3, 99)
    rowless = ordinary(1, **{"hdr.subject": "read otherwise today"})
    monkeypatch.setattr(pass_.doveadm, "fetch", lambda *a: [rowless, file_2, file_4])
    numbered(monkeypatch, 222)
    ledger = Ledger()
    ledger.cursors, ledger.numbering = {pass_.INBOX: 5}, {pass_.INBOX: 111}
    ledger.folder_rows = [first, fourth, gone]
    monkeypatch.setattr(pass_, "connect", lambda args: ledger)
    assert pass_.main(["--only", "example", "--renumber"]) == 1
    assert ledger.messages == [], "a file with no row was recorded beside an unmatched row"
    assert ledger.renumbered == {11: 2, 14: 4, 16: None}
    assert ledger.cursors[pass_.INBOX] == 4 and ledger.numbering[pass_.INBOX] == 222
    err = capsys.readouterr().err
    assert "message 16 (UID 3) has no file in the folder any more" in err
    assert "UID 1 has no row and was NOT recorded" in err and "--uid 1`" in err
    assert "2 message(s) renumbered, 1 without a file, 0 recorded, 1 left unrecorded" in err


def test_a_row_written_with_a_control_character_still_finds_its_file():
    """A row written before the headers were read without control characters keeps them;
    its file is read without them now, and the two are still paired."""
    fields = {"hdr.subject": "Invoice\x01 March\x07", "hdr.message-id": "<a\x02b@example.org>",
              "hdr.from": "Olga <olga@example.org>"}
    file = pass_.read(ordinary(3, **fields))
    assert file.subject == "Invoice March" and file.message_id == "<ab@example.org>"
    old = (11, 1, "<a\x02b@example.org>", "olga@example.org", "Invoice\x01 March\x07", None)
    assert pass_.matched([old], [file]) == ({11: 3}, [])


def test_the_way_back_refuses_a_folder_none_of_whose_rows_it_finds(monkeypatch, capsys):
    first, _ = row(11, 1, 1)
    monkeypatch.setattr(pass_.doveadm, "fetch", lambda *a: [ordinary(1, **{"hdr.subject": "other"})])
    numbered(monkeypatch, 222)
    ledger = Ledger()
    ledger.cursors, ledger.numbering = {pass_.INBOX: 1}, {pass_.INBOX: 111}
    ledger.folder_rows = [first]
    monkeypatch.setattr(pass_, "connect", lambda args: ledger)
    assert pass_.main(["--only", "example", "--renumber"]) == 1
    assert "none of its 1 rows matches" in capsys.readouterr().err
    assert ledger.renumbered == {} and ledger.calls == ["rollback", "close"]
    with pytest.raises(SystemExit):
        pass_.parse_args(["--renumber"])  # one domain's folder


# --- which messages get names --------------------------------------------------


def test_a_message_in_the_quarantine_folder_gets_no_names():
    assert pass_.receives(pass_.read(record()), store.QUARANTINE, True) is False
    assert pass_.state_of(store.QUARANTINE) == "withheld"
    assert pass_.state_of(pass_.INBOX) == "delivered"


def test_spam_gets_no_names_where_the_domain_keeps_spam_back_and_names_where_it_does_not():
    spam = pass_.read(record(**{MARK: "yes"}))
    assert pass_.receives(spam, pass_.INBOX, False) is False
    assert pass_.receives(spam, pass_.INBOX, True) is True


def test_everything_else_reaches_every_mailbox_whatever_its_from():
    for sender in ("someone@example.org", "archive@alpha", ""):
        read = pass_.read(record(**{"hdr.from": sender}))
        assert pass_.receives(read, pass_.INBOX, False) is True


# --- the names themselves -----------------------------------------------


def test_a_receivers_name_is_the_archives_base_name_without_its_flags():
    assert store.base_name(Path("/s/d/archive/Maildir/new/1757.M1P2.host")) == "1757.M1P2.host"
    assert store.base_name(Path("/s/d/archive/Maildir/cur/1757.M1P2.host:2,S")) == "1757.M1P2.host"


def maildir(root, account):
    path = Path(root) / account / "Maildir" / "new"
    path.mkdir(parents=True)
    return path.parent


def test_a_link_is_a_second_name_for_one_file_and_never_a_copy(tmp_path):
    archive = maildir(tmp_path, "archive")
    source = archive / "new" / "1757.M1.host"
    source.write_bytes(b"the message")
    ivan = maildir(tmp_path, "ivan")

    touched = store.link_into(source, [ivan])
    assert touched == [ivan / "new"]
    copy = ivan / "new" / "1757.M1.host"
    assert copy.stat().st_ino == source.stat().st_ino
    assert source.stat().st_nlink == 2


def test_a_name_that_already_exists_is_success_and_the_tick_is_idempotent(tmp_path):
    archive = maildir(tmp_path, "archive")
    source = archive / "new" / "1757.M1.host"
    source.write_bytes(b"the message")
    ivan = maildir(tmp_path, "ivan")

    store.link_into(source, [ivan])
    store.link_into(source, [ivan])  # the retry: EEXIST, not an error
    assert len(list((ivan / "new").iterdir())) == 1
    assert source.stat().st_nlink == 2


def test_a_receivers_maildir_is_made_when_the_person_has_never_logged_in(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "mail_owner", lambda: (os.getuid(), os.getgid()))
    archive = maildir(tmp_path, "archive")
    source = archive / "new" / "1757.M1.host"
    source.write_bytes(b"the message")
    fresh = Path(tmp_path) / "newcomer" / "Maildir"

    store.link_into(source, [fresh], root=tmp_path)
    assert (fresh / "new" / "1757.M1.host").exists()
    assert (fresh / "cur").is_dir() and (fresh / "tmp").is_dir()
    assert oct(fresh.stat().st_mode)[-3:] == "700"


def test_every_directory_that_gained_a_name_is_fsynced_after_the_last_link(tmp_path, monkeypatch):
    order = []
    archive = maildir(tmp_path, "archive")
    source = archive / "new" / "1757.M1.host"
    source.write_bytes(b"the message")
    boxes = [maildir(tmp_path, name) for name in ("ivan", "olga")]

    real_link = os.link
    monkeypatch.setattr(store.os, "link", lambda src, dst: (order.append(("link", str(dst))),
                                                            real_link(src, dst))[1])
    monkeypatch.setattr(store.os, "fsync", lambda fd: order.append(("fsync", fd)))

    touched = store.link_into(source, boxes)
    store.fsync_dirs(touched)
    kinds = [kind for kind, _ in order]
    assert kinds == ["link", "link", "fsync", "fsync"]


# --- the queries ----------------------------------------------------------


def test_the_receivers_paths_are_derived_from_the_root_and_not_from_the_userdbs_home():
    assert "home" not in pass_.RECEIVERS
    assert "mailbox_receives" in pass_.RECEIVERS
    text = Path(pass_.__file__).read_text()
    assert "store.home(" in text     # the store library's one derivation
    assert "--store-root" in text    # from a root this run was given


def test_a_blocked_persons_mailbox_still_receives():
    # `mailbox_receives` is the view with no state predicate; the pass
    # adds none of its own.
    assert "state" not in pass_.RECEIVERS
    assert "as_of" not in pass_.RECEIVERS


def test_every_domain_is_read_including_one_with_no_external_mailbox():
    assert "external_mailbox" not in pass_.DOMAINS
    assert "spam_reaches_people" in pass_.DOMAINS


# --- the unit and the timer the programs role installs ------------------------------------------

ROLE = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "programs"


def role_vars():
    import yaml

    return yaml.safe_load((ROLE / "vars" / "main.yml").read_text())


def unit_text(name):
    return (ROLE / "templates" / f"{name}.j2").read_text()


def test_the_timer_runs_the_pass_every_minute_for_every_domain():
    assert role_vars()["maildivvy_pass_interval"] == "1min"
    timer = unit_text("maildivvy-pass.timer")
    assert "OnCalendar={{ maildivvy_pass_calendar }}" in timer
    assert "Unit=maildivvy-pass.service" in timer


def test_the_service_runs_the_installed_pass_as_the_mail_owner():
    service = unit_text("maildivvy-pass.service")
    assert "ExecStart={{ maildivvy_opt }}/bin/maildivvy-pass" in service
    assert "User=vmail" in service and "Type=oneshot" in service


def test_the_role_installs_the_pass_service_and_enables_only_its_timer():
    # every program task adds its own units to the same list, so this names its own
    units = {u["src"]: u for u in role_vars()["maildivvy_program_units"]}
    assert {"maildivvy-pass.service.j2", "maildivvy-pass.timer.j2"} <= set(units)
    assert units["maildivvy-pass.timer.j2"]["enabled"] is True
    assert "enabled" not in units["maildivvy-pass.service.j2"]


def test_the_cursor_is_read_and_written_per_domain_and_mailbox():
    for sql in (pass_.CURSOR, pass_.MOVE_CURSOR):
        assert "domain_id" in sql and "mailbox" in sql


def test_the_quarantine_is_recorded_before_inbox_so_a_report_finds_its_message(monkeypatch):
    # Both are in the archive before the tick: the withheld message, and its report.
    withheld = record(uid="1", **{WITHHELD: "c" * 32, REASON: report.NONE})
    told = record(uid="1", **{WITHHELD: "c" * 32, REASON: "infected"})
    archive(monkeypatch, [told], [withheld])
    ledger = Ledger()
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert [m[2] for m in ledger.messages] == ["withheld", "delivered"]
    assert ledger.messages[1][3] == ledger.messages[0][0], "the report points at nothing"
    assert ledger.cursors == {store.QUARANTINE: 1, pass_.INBOX: 1}


def test_a_delivery_row_names_a_mailbox_and_no_folder():
    assert "folder" not in ledger_module.LINK
    assert "mailbox_id" in ledger_module.LINK and "message_id" in ledger_module.LINK
    assert "ON CONFLICT" in ledger_module.LINK  # a repeated tick adds nothing


def test_a_pair_that_already_has_a_delivery_row_in_any_state_is_never_linked_again():
    sql = pass_.RECEIVERS.upper()
    assert "NOT EXISTS" in sql and "DELIVERY" in sql
    assert "D.STATE" not in sql  # a row in ANY state stops it, never only a linked one


# --- the command line and the exit code ---------------------------------------------------------


def test_the_pass_exits_nonzero_when_any_domain_failed(monkeypatch):
    seen = []

    def tick(conn, domain, args):
        seen.append(domain.label)
        if domain.label == "beta":
            raise RuntimeError("no archive")

    monkeypatch.setattr(pass_, "connect", lambda args: Connection([
        [(1, "alpha", True), (2, "beta", True), (3, "gamma", True)]]))
    monkeypatch.setattr(pass_, "fan_out", tick)
    assert pass_.main([]) == 1
    assert seen == ["alpha", "beta", "gamma"]  # the others continue


def test_a_failed_domain_rolls_its_own_transaction_back(monkeypatch):
    conn = Connection([[(1, "alpha", True), (2, "beta", True)]])

    def tick(connection, domain, args):
        if domain.label == "alpha":
            raise RuntimeError("no archive")

    monkeypatch.setattr(pass_, "connect", lambda args: conn)
    monkeypatch.setattr(pass_, "fan_out", tick)
    assert pass_.main([]) == 1
    assert conn.calls[:2] == ["rollback", "commit"]


def test_a_run_with_nothing_to_do_is_a_success(monkeypatch):
    monkeypatch.setattr(pass_, "connect", lambda args: Connection([[]]))
    monkeypatch.setattr(pass_, "fan_out", lambda *a: pytest.fail("no domain to fan out"))
    # the queue is drained even when no domain had anything; its own
    # tests are in test_fanout_requests.py
    monkeypatch.setattr(pass_, "drain", lambda conn, args: (0, 0))
    assert pass_.main([]) == 0


def test_the_pass_connects_as_the_pipeline_and_as_nothing_else():
    assert pass_.CONSUMER == "pipeline"


class Cursor:
    def __init__(self, answers):
        self.answers = list(answers)
        self.statements = []

    def execute(self, sql, params=None):
        self.statements.append((" ".join(sql.split()), params))

    def fetchall(self):
        return self.answers.pop(0)

    def fetchone(self):
        return self.answers.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Connection:
    def __init__(self, answers):
        self.cursor_ = Cursor(answers)
        self.calls = []

    def cursor(self):
        return self.cursor_

    def commit(self):
        self.calls.append("commit")

    def rollback(self):
        self.calls.append("rollback")

    def close(self):
        self.calls.append("close")


def test_the_requests_a_pass_drains_look_for_the_snapshots_in_the_store_it_was_given(
        monkeypatch, tmp_path):
    """A deletion or a discard removes a snapshot from the store this run was pointed at,
    never from the default one beside it."""
    seen = []
    monkeypatch.setattr(pass_.requests, "drain",
                        lambda conn, context, provider=False, budget=None, reconnect=None:
                        seen.append(context))
    pass_.drain(None, pass_.parse_args(["--store-root", str(tmp_path / "store")]))
    assert seen[0].store_root == tmp_path / "store"
    assert seen[0].snapshot_root == tmp_path / "store" / "_snapshots"
    assert pass_.requests.Context().snapshot_root == store.SNAPSHOT_ROOT   # the default's own


# --- an imported message: recorded, reaching nobody -------------------------------------

SHA = hashlib.sha256(b"an imported message").hexdigest()
RECEIVED = 1458000000  # 2016-03-15T00:00:00Z


def imported(uid, received=RECEIVED, **fields):
    """An INBOX record of a file the import wrote: its storage id is the whole base name."""
    return ordinary(uid, storageid=store.import_base(received, SHA, 1234, 1260), **fields)


def test_the_imported_name_is_matched_whole_and_carries_its_received_epoch():
    base = store.import_base(RECEIVED, SHA, 1234, 1260)
    assert base == f"{RECEIVED}.{SHA}.import,S=1234,W=1260"
    assert store.imported(base) == RECEIVED
    for other in (f"{RECEIVED}.M12P34.host,S=1234,W=1260",           # a delivery agent's
                  "7.42.snapshot,S=1234",                           # a snapshot's
                  f"{RECEIVED}.M1P2.host.import,S=12,W=13",          # `.import` inside a live name
                  f"{RECEIVED}.{SHA[:63]}.import,S=1234,W=1260",     # a short hash
                  f"{RECEIVED}.{SHA.upper()}.import,S=1234,W=1260",  # not ours: we write lower case
                  f"{RECEIVED}.{SHA}.import,S=1234",                 # no size over IMAP
                  f"{RECEIVED}.{SHA}.import,S=1234,W=1260,X=1",      # more after the sizes
                  f"x{RECEIVED}.{SHA}.import,S=1234,W=1260", "", None):
        assert store.imported(other) is None, other
    with pytest.raises(store.StoreError):
        store.import_base(RECEIVED, "not a hash", 1, 1)


def test_an_imported_message_is_recorded_and_fanned_out_to_nobody_beside_a_delivered_one(
        monkeypatch, tmp_path, capsys):
    archive(monkeypatch, [imported(1), ordinary(2)])
    made = linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")])
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert [(m[4], m[2]) for m in ledger.messages] == [(1, "delivered"), (2, "delivered")]
    assert ledger.links == [(2, 7)] and len(made) == 1   # the delivered one, as before
    assert ledger.cursors[pass_.INBOX] == 2
    assert "example INBOX: 2 recorded" in capsys.readouterr().err


def test_an_imported_messages_old_filter_block_is_not_this_machines_verdict(monkeypatch, tmp_path):
    old_block = {MARK: "yes", SCORE: "99.00", WITHHELD: "d" * 32, REASON: "infected"}
    read = pass_.read(imported(1, **old_block))
    assert (read.spam, read.score, read.withheld_id, read.reason, read.is_report) == \
        (False, None, None, None, False)
    assert read.received == RECEIVED
    # the same block on a delivered message is read as ever: the control
    assert pass_.read(ordinary(1, **old_block)).spam is True
    archive(monkeypatch, [imported(1, **old_block)])
    linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")])
    pass_.fan_out(ledger, pass_.Domain(1, "example", False), pass_.parse_args([]))
    # (id, withheld_id, state, report_of, archive_uid, message_id_header)
    assert [m[1:4] for m in ledger.messages] == [(None, "delivered", None)]
    assert ledger.links == []


def test_a_live_name_with_import_elsewhere_in_it_is_fanned_out_as_ever(monkeypatch, tmp_path):
    live = ordinary(1, storageid=f"{RECEIVED}.M1P2.host.import,S=12,W=13")
    assert pass_.read(live).received is None
    archive(monkeypatch, [live])
    made = linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")])
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert ledger.links == [(1, 7)] and len(made) == 1


def test_an_imported_name_in_the_quarantine_is_skipped_and_named_never_recorded(
        monkeypatch, tmp_path, capsys):
    archive(monkeypatch, [ordinary(1)], quarantine=[imported(1), ordinary(2, **{WITHHELD: "e" * 32})])
    linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")])
    pass_.fan_out(ledger, DOMAIN, pass_.parse_args([]))
    assert sorted((m[2], m[4]) for m in ledger.messages) == [("delivered", 1), ("withheld", 2)]
    assert ledger.cursors[store.QUARANTINE] == 2
    skipped = [line for line in capsys.readouterr().err.splitlines() if pass_.SKIPPED in line]
    assert len(skipped) == 1 and "example Quarantine UID 1: NotOurs" in skipped[0], skipped


def test_an_imported_uid_recorded_by_hand_links_nobody(monkeypatch, tmp_path):
    archive(monkeypatch, [imported(2)])
    made = linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")])
    ledger.cursors[pass_.INBOX] = 5
    pass_.record_one(ledger, DOMAIN, pass_.INBOX, 2, by_hand("--uid", "2"))
    assert [m[4] for m in ledger.messages] == [2] and ledger.links == [] and made == []


def test_the_way_back_over_imported_files_renumbers_them_and_links_nobody(monkeypatch, tmp_path):
    first, file_2 = row(11, 1, 2, storageid=store.import_base(RECEIVED, SHA, 1234, 1260))
    rowless = imported(1, received=RECEIVED - 86400)  # below the newest matched: recorded here
    monkeypatch.setattr(pass_.doveadm, "fetch", lambda login, folder, fields, *search: (
        [rowless, file_2] if search == ("all",) else pytest.fail(search)))
    numbered(monkeypatch, 222)
    made = linking(monkeypatch, tmp_path)
    ledger = Ledger(receivers=[(7, "ivan")])
    ledger.cursors, ledger.numbering = {pass_.INBOX: 1}, {pass_.INBOX: 111}
    ledger.folder_rows = [first]
    assert pass_.renumber(ledger, DOMAIN, pass_.INBOX, pass_.parse_args([])) == (1, [], 1, [])
    assert ledger.renumbered == {11: 2} and [m[4] for m in ledger.messages] == [1]
    assert ledger.links == [] and made == []


def test_an_imported_row_arrived_when_its_name_says_and_was_recorded_now(database, monkeypatch, tmp_path):
    """On the unit tier's real database, as the pipeline: the two moments, and no delivery."""
    domain = database.value("INSERT INTO domain (label, archive_password_hash) VALUES "
                            "('example', %s) RETURNING id", ("{SHA512-CRYPT}$6$x$" + "x" * 86,))
    database.sql("INSERT INTO account (login, password_hash) VALUES ('ivan', %s)",
                 ("{SHA512-CRYPT}$6$x$" + "x" * 86,))
    database.sql("INSERT INTO mailbox (account_id, domain_id) SELECT id, %s FROM account "
                 "WHERE login = 'ivan'", (domain,))
    archive(monkeypatch, [imported(1, **{"hdr.date": "Tue, 15 Mar 2016 09:00:00 +0300",
                                         MARK: "yes", SCORE: "12.00"}),
                          ordinary(2)])
    made = linking(monkeypatch, tmp_path)
    numbered(monkeypatch, 111)
    conn = database.connect("pipeline")
    try:
        pass_.fan_out(conn, pass_.Domain(domain, "example", True), pass_.parse_args([]))
        conn.commit()
    finally:
        conn.close()
    rows = database.sql(
        "SELECT archive_uid, state, is_spam, spam_score, withheld_id, report_of, "
        "extract(epoch FROM received_at)::bigint, imported_at IS NOT NULL, "
        "imported_at > received_at, message_date = '2016-03-15T06:00:00Z', "
        "(SELECT count(*) FROM delivery d WHERE d.message_id = m.id) "
        "FROM message m ORDER BY archive_uid")
    assert rows[0] == (1, "delivered", False, None, None, None, RECEIVED, True, True, True, 0)
    assert rows[1][:6] == (2, "delivered", False, None, None, None)
    assert rows[1][7:] == (False, None, None, 1)   # a delivered one, no Date: no import moment, linked
    assert len(made) == 1
    assert database.value("SELECT last_uid FROM pass_cursor WHERE mailbox = 'INBOX'") == 2


def test_a_top_up_put_back_between_two_batches_goes_on_after_the_next_runs_fan_out(
        bulk, monkeypatch):
    """The pass is a oneshot: while a top-up of any size was one transaction, no domain
    fanned out for its length. Put back once the drain's budget is spent, it costs the run
    nothing but that budget and one batch, and the run is not a failed one."""
    world = bulk(5)
    asked = world.ask()
    order = []
    monkeypatch.setattr(pass_, "fan_out",
                        lambda conn, domain, args: order.append((domain.label, world.rows())))
    drain, clock = pass_.requests.drain, iter([0, 0, pass_.requests.DRAIN_BUDGET])
    monkeypatch.setattr(pass_.requests, "drain", lambda conn, context, **how: drain(
        conn, context, clock=lambda: next(clock, 0), **how))
    argv = ["--store-root", str(world.context.store_root), "--etc", str(world.database.etc)]
    # the first run: the budget is spent when its first batch has committed
    assert pass_.main(argv) == 0
    assert world.request(asked)[:2] == ("queued", "2 message(s) linked so far")
    assert pass_.main(argv) == 0
    assert order == [("alpha", 0), ("alpha", 2)]
    assert world.request(asked)[0] == "done" and world.rows() == 5


def example(database):
    """`example` with ivan's mailbox, on the unit tier's real database; the domain's id."""
    domain = database.value("INSERT INTO domain (label, archive_password_hash) VALUES "
                            "('example', %s) RETURNING id", ("{SHA512-CRYPT}$6$x$" + "x" * 86,))
    database.sql("INSERT INTO account (login, password_hash) VALUES ('ivan', %s)",
                 ("{SHA512-CRYPT}$6$x$" + "x" * 86,))
    database.sql("INSERT INTO mailbox (account_id, domain_id) SELECT id, %s FROM account "
                 "WHERE login = 'ivan'", (domain,))
    return domain


def tick_on(database, domain):
    conn = database.connect("pipeline")
    try:
        pass_.fan_out(conn, pass_.Domain(domain, "example", True), pass_.parse_args([]))
        conn.commit()
    finally:
        conn.close()


def test_a_subject_the_database_refuses_is_recorded_without_its_display_fields(
        database, monkeypatch, tmp_path, capsys):
    """A lone surrogate, which the driver will not encode, in a subject: the message is
    recorded without its subject, sender and date, and linked, instead of being skipped
    for a field only a screen reads. Its neighbour is recorded whole."""
    domain = example(database)
    archive(monkeypatch, [ordinary(1, **{"hdr.subject": "Invoice \udcff", "hdr.from":
                                         "olga@example.org", "hdr.date":
                                         "Tue, 15 Mar 2016 09:00:00 +0300"}),
                          ordinary(2, **{"hdr.subject": "fine"})])
    made = linking(monkeypatch, tmp_path)
    numbered(monkeypatch, 111)
    tick_on(database, domain)
    rows = database.sql("SELECT archive_uid, message_id_header, subject, sender, message_date, "
                        "(SELECT count(*) FROM delivery d WHERE d.message_id = m.id) "
                        "FROM message m ORDER BY archive_uid")
    assert rows == [(1, "<m1@example.org>", None, None, None, 1),
                    (2, "<m2@example.org>", "fine", None, None, 1)]
    assert len(made) == 2
    err = capsys.readouterr().err
    assert pass_.SKIPPED not in err
    assert "example INBOX UID 1: recorded without its subject, sender and date, which the " \
        "database refused: UnicodeEncodeError" in err


def test_a_withheld_message_recorded_after_its_report_is_what_the_report_points_at(
        database, monkeypatch, tmp_path, capsys):
    """The report was recorded while its withheld message was not (skipped, then recorded
    later): the report's row points at nothing until the message's row is written, and
    then at it, so a release takes the report away."""
    domain = example(database)
    report_of = {"hdr.message-id": "<w1@example>", REASON: "Eicar-Signature", WITHHELD: "w1"}
    withheld = record(uid="1", **{"hdr.message-id": "<virus@example.org>", WITHHELD: "w1",
                                  REASON: "none"})
    archive(monkeypatch, [ordinary(1, **report_of)])
    linking(monkeypatch, tmp_path)
    numbered(monkeypatch, 111)
    tick_on(database, domain)
    assert database.value("SELECT report_of FROM message") is None
    assert "the report of withheld w1 has no message to point at" in capsys.readouterr().err

    archive(monkeypatch, [ordinary(1, **report_of)], quarantine=[withheld])
    tick_on(database, domain)
    found = database.one("SELECT r.report_of = w.id, w.state, w.withheld_id FROM message r, "
                         "message w WHERE r.archive_uid = 1 AND r.state = 'delivered' "
                         "AND w.state = 'withheld'")
    assert found == (True, "withheld", "w1")
