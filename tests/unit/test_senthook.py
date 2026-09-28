"""What the Sent hook decides from the message it is handed, and what it refuses.

The parts that need a real Dovecot, a real APPEND and a real archive are driven on the
test VM. What is tested here is what is true of
the text and of the program's own shape: which header is read, which mailbox and which
login are refused, how the appended file is recognised among the candidates, and - the
rule everything else rests on - that nothing whatever makes the hook exit other than 0.

Nothing here spells a ledger rule a second time: the sender, the date and the header
unfolding are the pass's own functions, so the two programs cannot come to disagree
about one message.
"""

import datetime
import email.utils
import os
from pathlib import Path

import pytest

from maildivvy.fanout import pass_
from maildivvy.lib import config, doveadm, store
from maildivvy.senthook import hook


def message(subject="a sent message", message_id="<sent-1@example.org>", sender="ivan@example.org",
            date="Tue, 15 Sep 2026 10:00:00 +0000", body="what I wrote", extra=""):
    head = [f"From: {sender}", "To: someone@example.net", f"Subject: {subject}"]
    if message_id:
        head.append(f"Message-ID: {message_id}")
    if date:
        head.append(f"Date: {date}")
    if extra:
        head.append(extra)
    return ("\r\n".join(head) + f"\r\n\r\n{body}\r\n").encode()


def record(uid, base="1789000000.M1P1.host,S=10,W=11", size=None):
    answer = {"uid": str(uid), "storageid": base}
    if size is not None:
        answer["size.virtual"] = str(size)
    return answer


class Cursor:
    """A stand-in for the one cursor the hook uses; every statement and its answer."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.statements = []
        self.last = None

    def execute(self, statement, parameters=()):
        self.statements.append((statement, parameters))
        self.last = self.answers.pop(0) if self.answers else None

    def fetchone(self):
        return self.last

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        return False


class Connection:
    def __init__(self, answers=()):
        self.cursor_ = Cursor(answers)
        self.committed = self.rolled_back = self.closed = 0

    def cursor(self):
        return self.cursor_

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    def close(self):
        self.closed += 1


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A store root with one person's Sent holding one appended file, and an archive."""
    raw = message()
    base = "1789000000.M1P1.host,S=10,W=11"
    sent = store.maildir(store.home("acme", "ivan", tmp_path), "Sent") / "new"
    sent.mkdir(parents=True)
    (sent / base).write_bytes(raw.replace(b"\r\n", b"\n"))  # the maildir keeps LF
    store.maildir(store.archive_home("acme", tmp_path)).mkdir(parents=True)
    monkeypatch.setattr(hook, "STORE_ROOT", Path(tmp_path))
    # the archive's folder is made here by whoever runs the suite, not by `vmail`
    monkeypatch.setattr(store, "mail_owner", lambda: (os.getuid(), os.getgid()))
    return type("World", (), {"raw": raw, "base": base, "sent": sent, "root": tmp_path})


# --- the shape of the program ------------------------------------------------------


def test_every_refusal_writes_one_line_a_counter_can_find_and_still_exits_zero(capsys, monkeypatch):
    monkeypatch.setattr(hook, "STORE_ROOT", Path("/nonexistent"))
    for argv, environ in (([], {"USER": "ivan@acme"}),
                          (["Sent", "extra"], {"USER": "ivan@acme"}),
                          (["Drafts"], {"USER": "ivan@acme"}),
                          (["Sent"], {}),
                          (["Sent"], {"USER": "ivan"}),
                          (["Sent"], {"USER": "archive@acme"})):
        assert hook.main(argv, raw=message(), environ=environ) == 0
        lines = capsys.readouterr().err.splitlines()
        assert len(lines) == 1, lines
        assert lines[0].startswith(hook.FAILURE), lines[0]


def test_a_failure_of_any_kind_below_is_an_exit_of_zero_and_one_counted_line(capsys, monkeypatch):
    def raise_(*args, **kwargs):
        raise RuntimeError("the database fell over")

    monkeypatch.setattr(hook, "source_of", raise_)
    assert hook.main(["Sent"], raw=message(), environ={"USER": "ivan@acme"}) == 0
    line = capsys.readouterr().err.strip()
    assert line.startswith(hook.FAILURE) and "the database fell over" in line


def test_the_counted_marker_is_the_hooks_own_name_so_a_reading_cannot_be_another_programs():
    assert hook.FAILURE.startswith(hook.PREFIX) and hook.PREFIX == "maildivvy-sent-hook"
    assert hook.FAILURE.endswith("failed:")


def test_a_mailbox_other_than_sent_is_refused_inside_the_hook_whatever_the_binding_says(capsys):
    for mailbox in ("Drafts", "INBOX", "sent", "Sent/ivan", "Sent "):
        assert hook.main([mailbox], raw=message(), environ={"USER": "ivan@acme"}) == 0
        assert mailbox in capsys.readouterr().err
    assert hook.ONLY_MAILBOX == "Sent"


def test_the_archive_login_is_refused_since_no_person_holds_it(capsys):
    assert hook.main(["Sent"], raw=message(), environ={"USER": f"{store.ARCHIVE}@acme"}) == 0
    assert "archive@acme" in capsys.readouterr().err


def test_a_login_that_is_not_account_at_domain_is_refused():
    assert hook.account_of("ivan@acme") == ("ivan", "acme")
    assert hook.account_of("ivan.p@acme") == ("ivan.p", "acme")
    for bad in ("", "ivan", "@acme", "ivan@", "ivan@acme@acme"):
        with pytest.raises(hook.Refused):
            hook.account_of(bad)


# --- what is read from the message ---------------------------------------------------------------


def test_the_headers_are_read_from_the_header_block_alone_and_the_first_of_each_name():
    read = hook.read_message(message(subject="what I sent"))
    assert read.message_id == "<sent-1@example.org>"
    assert read.subject == "what I sent"
    assert read.sender == "ivan@example.org"
    assert read.date == email.utils.parsedate_to_datetime("Tue, 15 Sep 2026 10:00:00 +0000")
    # a second occurrence of a name, and a body that looks like a header, are not read
    raw = message(extra="X-Other: one") + b"Subject: not a header, this is the body\r\n"
    assert hook.read_message(raw).subject == "a sent message"


def test_a_message_with_no_message_id_reads_as_none_rather_than_raising():
    read = hook.read_message(message(message_id=""))
    assert read.message_id is None and read.subject == "a sent message"


def test_a_folded_subject_is_unfolded_and_the_sender_is_the_pass_s_own_parse():
    raw = message(subject="a subject that goes\r\n  on to a second line",
                  sender="acme@gmail.com <impostor@example.net>")
    read = hook.read_message(raw)
    assert read.subject == "a subject that goes on to a second line"
    assert read.sender == "impostor@example.net"  #, the pass's rule, once
    assert hook.read_message(message(date="not a date")).date is None


def test_a_header_that_is_not_utf_8_is_read_without_raising():
    raw = message().replace(b"a sent message", b"caf\xe9 \xff\xfe")
    assert hook.read_message(raw).subject.startswith("caf")


# --- finding the file the client appended ---------------------------------------------------------


def test_the_lookup_is_by_message_id_through_doveadm_and_never_a_listing(monkeypatch, world):
    asked = []

    def fetch(login, mailbox, fields, *search):
        asked.append((login, mailbox, tuple(fields), search))
        return [record(7, world.base, size=len(world.raw))]

    monkeypatch.setattr(hook.doveadm, "fetch", fetch)
    found = hook.source_of("ivan@acme", "acme", "ivan", world.raw, "<sent-1@example.org>",
                           root=world.root)
    assert found == world.sent / world.base
    assert asked == [("ivan@acme", "Sent", ("uid", "storageid", "size.virtual"),
                      ("header", "message-id", "<sent-1@example.org>"))]
    assert "savedsince" not in str(asked)  # the Message-ID path never widens the search


def test_a_message_with_no_message_id_is_found_by_the_append_itself(monkeypatch, world):
    """Open items § 3: a message sent without a Message-ID still gets its archive name."""
    other = world.sent / "1789000000.M2P2.host,S=9,W=9"
    other.write_bytes(b"another one\n")
    asked = []

    def fetch(login, mailbox, fields, *search):
        asked.append(search)
        return [record(9, other.name, size=len(world.raw)),   # the same size, other bytes
                record(7, world.base, size=len(world.raw))]

    monkeypatch.setattr(hook.doveadm, "fetch", fetch)
    found = hook.source_of("ivan@acme", "acme", "ivan", world.raw, None, root=world.root)
    assert found == world.sent / world.base  # chosen by its bytes, not by its UID
    assert asked == [("savedsince", hook.RECENT)]


def test_the_bytes_are_compared_with_the_line_endings_the_store_holds(world):
    stored = world.sent / world.base
    assert hook.same_message(world.raw, stored)           # CRLF handed in, LF on disk
    assert hook.same_message(world.raw.replace(b"\r\n", b"\n"), stored)
    assert not hook.same_message(world.raw + b"one more line\r\n", stored)


def test_among_several_files_of_one_message_id_the_newest_of_the_right_size_is_taken():
    raw = message()
    records = [record(3, "a", size=len(raw)), record(9, "b", size=len(raw) + 1),
               record(5, "c", size=len(raw))]
    assert hook.newest(records, raw)["storageid"] == "c"
    # with no size to go on, the newest answer is the one the append just made
    assert hook.newest([record(3, "a"), record(9, "b")], raw)["storageid"] == "b"
    assert hook.newest([], raw) is None


def test_a_message_no_lookup_finds_is_refused_rather_than_guessed(monkeypatch, world):
    monkeypatch.setattr(hook.doveadm, "fetch", lambda *a, **k: [])
    with pytest.raises(hook.Refused):
        hook.source_of("ivan@acme", "acme", "ivan", world.raw, "<sent-1@example.org>",
                       root=world.root)

    def raises(*args, **kwargs):
        raise doveadm.DoveadmError("doveadm fetch exited 68", 68)

    monkeypatch.setattr(hook.doveadm, "fetch", raises)
    with pytest.raises(doveadm.DoveadmError):
        hook.source_of("ivan@acme", "acme", "ivan", world.raw, None, root=world.root)


def test_a_storage_id_with_no_file_under_it_is_refused(monkeypatch, world):
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, "1789000000.M9P9.host,S=1,W=1")])
    with pytest.raises(hook.Refused):
        hook.source_of("ivan@acme", "acme", "ivan", world.raw, "<sent-1@example.org>",
                       root=world.root)


# --- the archive's folder ---------------------------------------------


def test_the_archive_folder_is_sent_under_the_senders_own_account():
    assert hook.archive_folder("ivan") == "Sent/ivan"
    assert hook.archive_folder("ivan.p") == "Sent/ivan.p"


def test_a_dotted_login_keeps_its_dot_in_the_folder_and_escapes_it_on_disk(tmp_path):
    folder = hook.archive_folder("ivan.p")
    plain = store.maildir(store.archive_home("acme", tmp_path), hook.archive_folder("ivan"))
    dotted = store.maildir(store.archive_home("acme", tmp_path), folder)
    assert dotted.name == ".Sent.ivan^2ep" and plain.name == ".Sent.ivan"
    assert dotted != plain


# --- the ledger and the names --------------------------------


def test_the_hook_adds_a_name_and_never_moves_the_file(monkeypatch, world, capsys):
    made = []
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])
    monkeypatch.setattr(hook.doveadm, "create_folder", lambda login, folder: made.append(folder))
    connection = Connection([(3,), (11,), None, (42,), None, None])  # domain, mailbox, recorded, id
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: connection)

    assert hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"}) == 0
    source = world.sent / world.base
    archive = store.maildir(store.archive_home("acme", world.root), "Sent/ivan") / "new" / world.base
    assert source.exists() and archive.exists()  # both names, and the file never moved
    assert source.stat().st_ino == archive.stat().st_ino
    # the parent is made by name too: a folder Dovecot makes on its way past has no ACL
    # of its own, and one without an ACL in an archive keeps every right
    assert made == ["Sent", "Sent/ivan"] and connection.committed == 1
    assert hook.FAILURE not in capsys.readouterr().err


def test_its_row_has_no_archive_number_and_the_senders_own_copy_gets_the_delivery_row(
        monkeypatch, world):
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])
    monkeypatch.setattr(hook.doveadm, "create_folder", lambda login, folder: None)
    connection = Connection([(3,), (11,), None, (42,), None, None])
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: connection)
    hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"})

    # the message row carries NULL where the archive's UID would be
    assert "archive_uid" in hook.RECORD and "NULL, 'delivered'" in hook.RECORD
    recorded = [p for s, p in connection.cursor_.statements if "INSERT INTO message" in s]
    assert recorded == [(3, "<sent-1@example.org>", hook.read_message(world.raw).date,
                         "ivan@example.org", "a sent message")]
    linked = [p for s, p in connection.cursor_.statements if "INSERT INTO delivery" in s]
    assert linked == [(42, 11)]  # exactly one, the sender's own mailbox


def test_a_row_the_feed_already_recorded_does_not_stop_the_hook(monkeypatch, world):
    """Open items § 5: the check matches only rows with NO archive number."""
    assert "archive_uid IS NULL" in hook.RECORDED
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])
    monkeypatch.setattr(hook.doveadm, "create_folder", lambda login, folder: None)
    # the feed's copy carries an archive UID, so RECORDED does not answer it: the ledger
    # stand-in answers None for the check and the hook writes its own row
    connection = Connection([(3,), (11,), None, (42,), None, None])
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: connection)
    assert hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"}) == 0
    assert connection.committed == 1


def test_a_message_already_recorded_without_an_archive_number_adds_nothing(monkeypatch, world,
                                                                           capsys):
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])
    monkeypatch.setattr(hook.doveadm, "create_folder", lambda login, folder: None)
    connection = Connection([(3,), (11,), (42,)])  # domain, mailbox, the row already there
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: connection)
    assert hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"}) == 0
    archive = store.maildir(store.archive_home("acme", world.root), "Sent/ivan")
    assert not archive.exists()
    assert connection.committed == 0 and connection.rolled_back == 1
    assert hook.FAILURE not in capsys.readouterr().err  # nothing to do is not a failure


def test_a_second_run_over_the_same_file_adds_no_second_name_and_no_second_row(
        monkeypatch, world, capsys):
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])
    monkeypatch.setattr(hook.doveadm, "create_folder", lambda login, folder: None)
    first = Connection([(3,), (11,), None, (42,), None, None])
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: first)
    hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"})

    # the second run: the archive's name is there already, so the database is never opened
    second = Connection([(3,), (11,), None, (42,), None, None])
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: second)
    assert hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"}) == 0
    archive = store.maildir(store.archive_home("acme", world.root), "Sent/ivan") / "new"
    assert [p.name for p in archive.iterdir()] == [world.base]
    assert second.committed == 0 and second.cursor_.statements == []
    assert hook.FAILURE not in capsys.readouterr().err


def test_a_message_with_no_message_id_is_kept_from_a_second_row_by_the_name_it_made(
        monkeypatch, world):
    raw = message(message_id="")
    (world.sent / world.base).write_bytes(raw.replace(b"\r\n", b"\n"))
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(raw))])
    monkeypatch.setattr(hook.doveadm, "create_folder", lambda login, folder: None)
    first = Connection([(3,), (11,), (42,), None, None])  # no RECORDED question is asked
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: first)
    assert hook.main(["Sent"], raw=raw, environ={"USER": "ivan@acme"}) == 0
    assert first.committed == 1
    asked = [s for s, _ in first.cursor_.statements]
    assert not any("message_id_header = " in s for s in asked)

    second = Connection([(3,), (11,), (42,), None, None])
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: second)
    assert hook.main(["Sent"], raw=raw, environ={"USER": "ivan@acme"}) == 0
    assert second.committed == 0 and second.cursor_.statements == []


def test_a_folder_that_exists_already_is_success_and_the_name_is_still_made(monkeypatch, world):
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])
    # what `create_folder` answers for a folder that was already there
    monkeypatch.setattr(hook.doveadm, "create_folder", lambda login, folder: False)
    connection = Connection([(3,), (11,), None, (42,), None, None])
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: connection)
    assert hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"}) == 0
    archive = store.maildir(store.archive_home("acme", world.root), "Sent/ivan") / "new"
    assert (archive / world.base).exists() and connection.committed == 1


def test_a_domain_or_a_mailbox_the_ledger_does_not_know_is_refused(monkeypatch, world, capsys):
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])
    monkeypatch.setattr(hook.doveadm, "create_folder", lambda login, folder: None)
    for answers in ([None], [(3,), None]):
        connection = Connection(answers)
        monkeypatch.setattr(hook.db, "connect", lambda *a, **k: connection)
        assert hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"}) == 0
        assert connection.committed == 0 and connection.closed == 1
        assert capsys.readouterr().err.startswith(hook.FAILURE)


def test_the_connection_is_closed_and_rolled_back_when_the_work_fails(monkeypatch, world, capsys):
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])

    def raises(login, folder):
        raise doveadm.DoveadmError("mailbox create: Permission denied", 77)

    monkeypatch.setattr(hook.doveadm, "create_folder", raises)
    connection = Connection([(3,), (11,), None, (42,)])
    monkeypatch.setattr(hook.db, "connect", lambda *a, **k: connection)
    assert hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"}) == 0
    assert connection.rolled_back == 1 and connection.committed == 0 and connection.closed == 1
    assert "Permission denied" in capsys.readouterr().err


def test_a_configuration_the_library_refuses_is_a_log_line_not_a_traceback(monkeypatch, world,
                                                                           capsys):
    def raises(*args, **kwargs):
        raise config.ConfigError("/etc/maildivvy/pipeline/db.conf is world-readable")

    monkeypatch.setattr(hook.db, "connect", raises)
    monkeypatch.setattr(hook.doveadm, "fetch",
                        lambda *a, **k: [record(7, world.base, size=len(world.raw))])
    assert hook.main(["Sent"], raw=world.raw, environ={"USER": "ivan@acme"}) == 0
    line = capsys.readouterr().err.strip()
    assert line.startswith(hook.FAILURE) and "world-readable" in line


# --- what the hook is, as a program -----------------------------------------------------------


def test_the_hook_reads_its_own_least_privileged_configuration():
    # The Sent hook has a role of its own, narrower than the pipeline's
    assert hook.CONSUMER == "senthook" and hook.CONSUMER in config.CONSUMERS


def test_the_ledgers_rules_are_the_passs_own_functions_never_a_second_spelling():
    text = Path(hook.__file__).read_text()
    assert "parseaddr" not in text and "parsedate" not in text
    assert hook.read_message.__module__ == "maildivvy.senthook.hook"
    assert pass_.sender_of("Someone <one@example.org>") == "one@example.org"


def test_the_entry_point_names_the_hooks_main():
    entry = Path(hook.__file__).resolve().parents[3].parent / "bin" / "maildivvy-sent-hook"
    if not entry.exists():  # in the deployed tree bin/ is beside lib/
        entry = Path(hook.__file__).resolve().parents[3] / "bin" / "maildivvy-sent-hook"
    text = entry.read_text()
    assert "from maildivvy.senthook.hook import main" in text
    assert "sys.dont_write_bytecode = True" in text


def test_the_recent_window_is_bounded_and_the_candidates_are_counted():
    assert hook.RECENT.endswith(("h", "d", "mins")) and hook.CANDIDATES >= 1


def test_the_date_and_the_delivery_state_are_the_ledgers_own_words():
    assert "'delivered'" in hook.RECORD and "'linked'" in hook.LINK
    assert isinstance(hook.read_message(message()).date, datetime.datetime)
