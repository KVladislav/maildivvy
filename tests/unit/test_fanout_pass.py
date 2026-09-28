"""What the pass decides from a message's fields, and what it does on the filesystem.

The parts that need a real archive, a real Dovecot and real rows are driven on the test
VM. What is tested here is what is true of the
text: which header of which name is read, what a sender or a score turns into, which
messages get names at all, and that a link that already exists is success.

Nothing here spells a verdict header: every one of them comes from the delivery
filter's own modules, so the two programs cannot come to disagree about a name.
"""

import os
from decimal import Decimal
from pathlib import Path

import pytest

from maildivvy.deliver import marks, report
from maildivvy.fanout import pass_
from maildivvy.lib import store


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


def test_every_header_the_pass_reads_is_the_filters_own_constant():
    assert MARK in pass_.FIELDS and SCORE in pass_.FIELDS
    assert WITHHELD in pass_.FIELDS and REASON in pass_.FIELDS
    text = Path(pass_.__file__).read_text()
    assert "X-Maildivvy" not in text, "a verdict header is spelled here a second time"


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
    assert pass_.first_occurrence("a long\n subject") == "a long subject"
    assert pass_.first_occurrence("first\nsecond") == "first"
    assert pass_.first_occurrence("") == ""


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
    for sql in (pass_.DOMAINS, pass_.RECEIVERS, pass_.RECORD, pass_.LINK, pass_.REPORTED):
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
    """Just enough of the pipeline's database for one domain's tick: message rows."""

    def __init__(self):
        self.messages = []   # (id, withheld_id, state, report_of)
        self.cursors = {}
        self.answer = None

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
        elif sql.startswith("UPDATE pass_cursor"):
            self.cursors[params[2]] = params[0]
        elif sql.startswith("SELECT id FROM message"):
            found = [m[0] for m in self.messages
                     if m[1] == params[1] and m[2] != "delivered"]
            self.answer = (found[0],) if found else None
        elif sql.startswith("INSERT INTO message"):
            row = (len(self.messages) + 1, params[4], params[3], params[5])
            self.messages.append(row)
            self.answer = (row[0],)
        elif sql.startswith("SELECT r.mailbox_id"):
            self.answer = []

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
    assert pass_.base_name(Path("/s/d/archive/Maildir/new/1757.M1P2.host")) == "1757.M1P2.host"
    assert pass_.base_name(Path("/s/d/archive/Maildir/cur/1757.M1P2.host:2,S")) == "1757.M1P2.host"


def maildir(root, account):
    path = Path(root) / account / "Maildir" / "new"
    path.mkdir(parents=True)
    return path.parent


def test_a_link_is_a_second_name_for_one_file_and_never_a_copy(tmp_path):
    archive = maildir(tmp_path, "archive")
    source = archive / "new" / "1757.M1.host"
    source.write_bytes(b"the message")
    ivan = maildir(tmp_path, "ivan")

    touched = pass_.link_into(source, [ivan])
    assert touched == [ivan / "new"]
    copy = ivan / "new" / "1757.M1.host"
    assert copy.stat().st_ino == source.stat().st_ino
    assert source.stat().st_nlink == 2


def test_a_name_that_already_exists_is_success_and_the_tick_is_idempotent(tmp_path):
    archive = maildir(tmp_path, "archive")
    source = archive / "new" / "1757.M1.host"
    source.write_bytes(b"the message")
    ivan = maildir(tmp_path, "ivan")

    pass_.link_into(source, [ivan])
    pass_.link_into(source, [ivan])  # the retry: EEXIST, not an error
    assert len(list((ivan / "new").iterdir())) == 1
    assert source.stat().st_nlink == 2


def test_a_receivers_maildir_is_made_when_the_person_has_never_logged_in(tmp_path, monkeypatch):
    monkeypatch.setattr(pass_.store, "mail_owner", lambda: (os.getuid(), os.getgid()))
    archive = maildir(tmp_path, "archive")
    source = archive / "new" / "1757.M1.host"
    source.write_bytes(b"the message")
    fresh = Path(tmp_path) / "newcomer" / "Maildir"

    pass_.link_into(source, [fresh], root=tmp_path)
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
    monkeypatch.setattr(pass_.os, "link", lambda src, dst: (order.append(("link", str(dst))),
                                                            real_link(src, dst))[1])
    monkeypatch.setattr(pass_.os, "fsync", lambda fd: order.append(("fsync", fd)))

    touched = pass_.link_into(source, boxes)
    pass_.fsync_dirs(touched)
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
    assert pass_.FOLDERS == (store.QUARANTINE, pass_.INBOX)


def test_a_delivery_row_names_a_mailbox_and_no_folder():
    assert "folder" not in pass_.LINK
    assert "mailbox_id" in pass_.LINK and "message_id" in pass_.LINK
    assert "ON CONFLICT" in pass_.LINK  # a repeated tick adds nothing


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
