"""What is true of the request handlers without a machine: the queue's shape, the one
selector, the order of destruction, and the names on disk.

Everything that needs real rows, a real archive and a real Dovecot is driven on the
test VM. What is tested here is what a machine
cannot show as cheaply: that the bound of a range is spelt once and read by both the
count and the delivery, that a destructive handler unlinks before it deletes
rows and fails the suite when the two halves are swapped, that every kind the
schema allows has a handler, and that a per-message act carries none of the bulk
selector's spam condition.
"""

import datetime
import inspect
import os
import re
from pathlib import Path

import pytest

from maildivvy.fanout import pass_, requests
from maildivvy.fetch import locks
from maildivvy.lib import store

SCHEMA = Path(__file__).resolve().parents[2] / "schema" / "0001_initial.sql"


# --- the queue: one request per transaction -------------------------------------------


class Cursor:
    def __init__(self, answers=()):
        self.answers = list(answers)
        self.statements = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.statements.append((" ".join(sql.split()), params))

    def fetchone(self):
        return self.answers.pop(0)

    def fetchall(self):
        return self.answers.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Connection:
    """A connection that records the order of its commits and rollbacks."""

    def __init__(self, answers=()):
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


def queued(conn, *rows):
    """The claim's answers: one row per request, then None for the empty queue."""
    conn.cursor_.answers = [*rows, None]


ROW = (7, "connect", "ivan@alpha", {"mailbox_id": 1}, "olga", False)


def outcome(conn):
    """The parameters of the one statement that wrote a request's outcome."""
    written = [params for statement, params in conn.cursor_.statements
               if statement == " ".join(requests.FINISH.split())]
    assert len(written) == 1, written
    return written[0]


def test_the_claim_takes_one_row_with_skip_locked_and_the_oldest_first():
    sql = " ".join(requests.CLAIM.split()).upper()
    assert "FOR UPDATE SKIP LOCKED LIMIT 1" in sql
    assert "ORDER BY CREATED_AT, ID" in sql
    assert "STATE = 'RUNNING'" in sql and "STATE = 'QUEUED'" in sql


def test_the_claim_commits_before_the_handler_runs(monkeypatch):
    conn = Connection()
    queued(conn, ROW)
    seen = []
    monkeypatch.setitem(requests.HANDLERS, "connect",
                        lambda cur, request, context: seen.append(conn.calls[:]) or "done it")
    assert requests.drain(conn) == (1, 0)
    assert seen == [["commit"]], "the handler ran inside the claim's own transaction"
    # the claim, the handler, the outcome - and the claim that finds the queue empty
    assert conn.calls == ["commit", "commit", "commit", "commit"]


def test_a_failed_handler_is_rolled_back_and_its_reason_written_afterwards(monkeypatch):
    conn = Connection()
    queued(conn, ROW)

    def explode(cur, request, context):
        raise requests.RequestFailed("no mailbox 1")

    monkeypatch.setitem(requests.HANDLERS, "connect", explode)
    assert requests.drain(conn) == (0, 1)
    assert conn.calls == ["commit", "rollback", "commit", "commit"]
    assert outcome(conn) == ("failed", "no mailbox 1", 7)


def test_an_unknown_kind_fails_the_request_and_is_never_skipped():
    conn = Connection()
    queued(conn, (7, "invent_a_domain", None, {}, "olga", False))
    assert requests.drain(conn) == (0, 1)
    params = outcome(conn)
    assert params[0] == "failed" and "invent_a_domain" in params[1]


def test_a_reason_longer_than_the_column_keeps_is_cut_to_it(monkeypatch):
    conn = Connection()
    queued(conn, ROW)
    monkeypatch.setitem(requests.HANDLERS, "connect",
                        lambda cur, request, context: (_ for _ in ()).throw(
                            requests.RequestFailed("x" * 5000)))
    requests.drain(conn)
    assert len(outcome(conn)[1]) == requests.REASON_MAX == 2000


def test_an_error_that_is_not_a_refusal_is_named_by_its_kind(monkeypatch):
    conn = Connection()
    queued(conn, ROW)
    monkeypatch.setitem(requests.HANDLERS, "connect",
                        lambda cur, request, context: (_ for _ in ()).throw(KeyError("uid")))
    assert requests.drain(conn) == (0, 1)
    assert outcome(conn)[1].startswith("KeyError:")


def test_an_empty_queue_does_nothing_at_all():
    conn = Connection()
    queued(conn)
    assert requests.drain(conn) == (0, 0)
    assert conn.calls == ["commit"]  # the claim's own, and no handler


def test_every_kind_the_schema_allows_has_a_handler_and_every_handler_a_kind():
    text = SCHEMA.read_text()
    listed = re.search(r"kind\s+text NOT NULL CHECK \(kind IN \((.*?)\)\)", text, re.S)
    kinds = set(re.findall(r"'([a-z_]+)'", listed.group(1)))
    assert kinds == set(requests.HANDLERS), "the queue's kinds and its handlers disagree"


# --- the drain point: after the fan-out, never before it ----------------------------


def test_the_pass_drains_the_queue_after_the_fan_out_and_never_before_it(monkeypatch):
    order = []
    monkeypatch.setattr(pass_, "connect",
                        lambda args: Connection([[(1, "alpha", True), (2, "beta", True)]]))
    monkeypatch.setattr(pass_, "fan_out",
                        lambda conn, domain, args: order.append(f"fan out {domain.label}"))
    monkeypatch.setattr(pass_, "drain", lambda conn, args: order.append("drain") or (0, 0))
    assert pass_.main([]) == 0
    assert order == ["fan out alpha", "fan out beta", "drain"]


def test_a_queue_that_cannot_be_drained_at_all_fails_the_run(monkeypatch):
    monkeypatch.setattr(pass_, "connect", lambda args: Connection([[]]))
    monkeypatch.setattr(pass_, "drain", lambda conn, args: (_ for _ in ()).throw(
        RuntimeError("the connection went away")))
    assert pass_.main([]) == 1


def test_a_failed_request_does_not_fail_the_run(monkeypatch):
    monkeypatch.setattr(pass_, "connect", lambda args: Connection([[]]))
    monkeypatch.setattr(pass_, "drain", lambda conn, args: (0, 3))
    assert pass_.main([]) == 0


# --- the one selector, and its one bound -----------------------------------------


def test_the_count_and_the_delivery_read_the_same_text_and_the_same_parameters():
    assert requests.SELECTOR in requests.SELECT_FOR
    assert requests.SELECTOR in requests.COUNT_FOR
    # the only difference between the two is what is selected, never a condition
    assert requests.SELECT_FOR.replace(requests.SELECTOR, "") \
        .replace(" ORDER BY m.id", "") == "SELECT m.id, m.archive_uid, m.state"
    assert requests.COUNT_FOR.replace(requests.SELECTOR, "") == "SELECT count(*)"
    assert requests.selector_params(1, 2, "a", "b") == requests.selector_params(1, 2, "a", "b")


def test_the_end_of_a_range_is_a_whole_calendar_day_and_the_bound_is_in_the_query():
    assert "m.received_at < (%s::date + 1)" in requests.SELECTOR
    assert "<=" not in requests.SELECTOR, "the end read as an instant is the measured defect"
    # and nothing composes a bound of its own: the module names no time of day
    text = Path(requests.__file__).read_text()
    assert "23:59" not in text


def test_all_of_it_is_a_wide_pair_of_plain_dates_and_never_an_absent_one():
    assert requests.WIDE_UNTIL == "9999-12-31"
    assert datetime.date.fromisoformat(requests.WIDE_UNTIL)  # a calendar date, no time of day
    for missing in ({"since": "2026-09-01"}, {"until": "2026-09-01"}, {},
                    {"since": "", "until": "2026-09-01"},
                    {"since": "2026-09-01", "until": None}):
        with pytest.raises(requests.RequestFailed):
            requests.need_date(missing, "since")
            requests.need_date(missing, "until")


def test_both_ends_are_calendar_dates_and_an_instant_is_refused():
    assert requests.need_date({"since": "2026-09-17"}, "since") == datetime.date(2026, 9, 17)
    assert requests.need_date({"since": datetime.date(2026, 9, 17)}, "since") \
        == datetime.date(2026, 9, 17)
    for wrong in ("2026-09-17 12:00:00", "17/09/2026", "yesterday", "2026-13-01"):
        with pytest.raises(requests.RequestFailed):
            requests.need_date({"since": wrong}, "since")
    with pytest.raises(requests.RequestFailed):
        requests.need_date({"since": datetime.datetime(2026, 9, 17, 12)}, "since")


def test_the_bulk_selector_takes_only_what_the_archive_holds_and_this_mailbox_has_not_had():
    sql = " ".join(requests.SELECTOR.split())
    assert "m.state = ANY(%s)" in sql and requests.DELIVERABLE == ("delivered", "released")
    assert "m.archive_uid IS NOT NULL" in sql
    assert "NOT EXISTS (SELECT 1 FROM delivery dl" in sql
    assert "dl.state" not in sql, "a row in ANY state stops it, never only a linked one"
    assert "m.sender" not in sql, "nothing is excluded by sender (the operator, 2026-09-14)"
    assert "m.spam_score" not in sql, "the stored verdict, never the stored score"


def test_the_spam_condition_is_the_bulk_selectors_and_is_written_exactly_once():
    text = Path(requests.__file__).read_text()
    assert "(d.spam_reaches_people OR NOT m.is_spam)" in requests.SELECTOR
    # once in the selector, and once more only in the prose that says why (the docstring)
    assert text.count("d.spam_reaches_people") == 1, "a second spelling of the spam condition"
    for name in ("deliver_one", "release"):
        source = inspect.getsource(getattr(requests, name))
        assert "SELECT_FOR" not in source and "select_for" not in source
        assert "is_spam" not in source and "spam_reaches_people" not in source


def test_only_a_deliver_one_relinks_over_a_row_that_is_already_linked():
    assert "DO UPDATE SET state = 'linked'" in requests.RELINK
    assert "DO NOTHING" in requests.LINK
    assert "relink=True" in inspect.getsource(requests.deliver_one)
    for name in ("connect", "top_up", "release"):
        assert "relink=True" not in inspect.getsource(getattr(requests, name))


# --- a UID counts in the mailbox it was given in --------------------------------------


def test_a_withheld_or_released_messages_number_counts_in_the_quarantine():
    assert requests.archive_folder("delivered") == requests.INBOX
    assert requests.archive_folder("withheld") == store.QUARANTINE
    # ⛔ a released message's file never moved: its number still counts in the quarantine
    assert requests.archive_folder("released") == store.QUARANTINE


# --- destruction: the files first, the rows second ------------------------------------


def maildir(root, domain, account, folder=None):
    box = store.maildir(store.home(domain, account, root), folder)
    for part in ("cur", "new"):
        (box / part).mkdir(parents=True, exist_ok=True)
    return box


def context_of(tmp_path):
    return requests.Context(store_root=tmp_path / "store", index_root=tmp_path / "index")


def test_a_failed_request_takes_back_the_names_it_made_and_only_those(tmp_path, monkeypatch):
    """The rows of a failed request are rolled back, so the names
    it made account for nothing - for a release, a withheld message in people's mailboxes.
    A name that was there before the request is somebody's, and stays."""
    source = tmp_path / "archive-file"
    source.write_text("the message")
    boxes = [store.maildir(tmp_path / who) for who in ("ivan", "olga", "petro")]
    for box in boxes:
        for part in ("cur", "new", "tmp"):
            (box / part).mkdir(parents=True)
    os.link(source, boxes[1] / "new" / source.name)  # olga had it already
    conn = Connection()
    queued(conn, ROW)

    def half_way(cur, request, context):
        pass_.link_into(source, boxes[:2], tmp_path, made=context.made)
        # ivan reads it in between: his name moves to cur/ with its flags
        os.rename(boxes[0] / "new" / source.name, boxes[0] / "cur" / f"{source.name}:2,S")
        pass_.link_into(source, boxes[2:], tmp_path, made=context.made)
        raise requests.RequestFailed("the third receiver could not be linked")

    monkeypatch.setitem(requests.HANDLERS, "connect", half_way)
    assert requests.drain(conn) == (0, 1)
    assert source.stat().st_nlink == 2  # the archive's own name, and olga's from before
    assert (boxes[1] / "new" / source.name).exists()
    assert outcome(conn) == ("failed", "the third receiver could not be linked", 7)


def test_a_mailbox_is_unlinked_before_its_rows_are_deleted(tmp_path, monkeypatch):
    context = context_of(tmp_path)
    maildir(context.store_root, "alpha", "ivan")
    order = []
    real = requests.remove_mailbox_files
    monkeypatch.setattr(requests, "remove_mailbox_files",
                        lambda *a: order.append("files") or real(*a))
    cursor = Cursor([(4,)])
    cursor.execute = lambda sql, params=None: order.append(" ".join(sql.split()).split()[0].lower())

    names = requests.unlink_mailbox(cursor, requests.Mailbox(1, "ivan", "alpha", None, 1), context)
    assert names == 4
    assert order == ["select", "files", "delete", "delete"], \
        "the rows were deleted before the names they name were removed"


def test_removing_a_mailbox_takes_its_store_directory_and_both_index_trees(tmp_path):
    context = context_of(tmp_path)
    maildir(context.store_root, "alpha", "ivan")
    trees = store.index_paths("alpha", "ivan", context.index_root)
    for tree in trees:
        (tree / "dovecot.index").parent.mkdir(parents=True)
        (tree / "dovecot.index").write_text("x")
    other = maildir(context.store_root, "alpha", "olga")

    assert requests.remove_mailbox_files("alpha", "ivan", context) == 3
    assert not store.home("alpha", "ivan", context.store_root).exists()
    assert not any(tree.exists() for tree in trees)
    assert other.exists(), "the mailbox beside it was touched"
    # a second run is a success: there is nothing left to remove
    assert requests.remove_mailbox_files("alpha", "ivan", context) == 0


def test_a_domains_directories_go_together_and_a_surviving_index_is_never_left_alone(tmp_path):
    context = context_of(tmp_path)
    for account in ("archive", "ivan"):
        maildir(context.store_root, "alpha", account)
        for tree in store.index_paths("alpha", account, context.index_root):
            tree.mkdir(parents=True)
    for account in ("archive", "ivan"):
        requests.remove_mailbox_files("alpha", account, context)
    assert requests.rmdir_left(context.store_root / "alpha") is None
    assert requests.rmdir_left(context.index_root / "idx" / "alpha") is None
    assert not (context.index_root / "idx" / "alpha").exists()


def test_a_directory_that_still_holds_something_is_left_in_place_and_reported(tmp_path):
    context = context_of(tmp_path)
    maildir(context.store_root, "alpha", "unknown")
    left = requests.rmdir_left(context.store_root / "alpha")
    assert left and "NOT empty" in left
    assert (context.store_root / "alpha").is_dir(), "a directory nobody accounts for was emptied"
    assert requests.rmdir_left(context.store_root / "never-there") is None


# --- the report's names, the one path that scans -----------------------------------


def test_the_reports_names_go_from_every_folder_of_a_mailbox_whatever_their_flags(tmp_path):
    context = context_of(tmp_path)
    archive = maildir(context.store_root, "alpha", store.ARCHIVE)
    report = archive / "new" / "1757.M1.host"
    report.write_bytes(b"the report")
    home = store.home("alpha", "ivan", context.store_root)
    inbox = maildir(context.store_root, "alpha", "ivan")
    filed = maildir(context.store_root, "alpha", "ivan", "Keep")
    os.link(report, inbox / "cur" / "1757.M1.host:2,S")   # read, and moved to cur/
    os.link(report, filed / "cur" / "1757.M1.host:2,SF")  # and filed away, flagged
    own = inbox / "new" / "1757.M9.host"
    own.write_bytes(b"a draft of their own")

    removed = requests.remove_names(home, report.stat().st_ino, pass_.base_name(report))
    assert removed == 2
    assert own.exists(), "the person's own file was removed"
    assert report.exists(), "the archive's own copy was removed"


def test_a_name_whose_file_the_archive_no_longer_holds_still_goes_by_its_base_name(tmp_path):
    context = context_of(tmp_path)
    home = store.home("alpha", "ivan", context.store_root)
    inbox = maildir(context.store_root, "alpha", "ivan")
    (inbox / "cur" / "1757.M1.host:2,S").write_bytes(b"the report")
    assert requests.remove_names(home, None, "1757.M1.host") == 1
    assert requests.remove_names(home, None, "1757.M1.host") == 0


def test_a_mailbox_with_no_maildir_at_all_is_not_an_error(tmp_path):
    context = context_of(tmp_path)
    assert requests.maildir_parts(store.home("alpha", "nobody", context.store_root)) == []
    assert requests.remove_names(store.home("alpha", "nobody", context.store_root), 1, "x") == 0


# --- the journal row names the administrator who asked --------------------------------


def request_of(**fields):
    values = {"id": 7, "kind": "connect", "target": "ivan@alpha", "payload": {},
              "asked_by": "olga", "break_glass": False}
    values.update(fields)
    return requests.Request(**values)


def test_a_check_whose_credential_changed_while_it_ran_switches_nothing_on(monkeypatch):
    """The check runs in a separate process, so it and the activation are
    separate transactions. What it logged in with is read before it runs; after it, the
    row is locked and read again, and a change refuses the request - the verdict is about
    a credential no longer there. The row is never locked BEFORE the check, whose runner
    writes its verdict to that same row and would wait on the lock for ever."""
    stamp = datetime.datetime(2026, 9, 1, 12)
    monkeypatch.setattr(requests, "run_runner", lambda *a, **k: FakeProcess(returncode=0))
    changed = ("a-new-password",) + TESTED[1:]
    cursor = Cursor([("ivan.p@example.org", stamp), TESTED, ("ok", None, stamp + ONE_MINUTE),
                     changed])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.check_credential(cursor, 1, requests.Context())
    assert "changed while it was being checked" in str(refused.value)
    statements = [statement for statement, _ in cursor.statements]
    assert "FOR UPDATE" not in statements[0] and "FOR UPDATE" not in statements[1]
    assert "last_test_status" in statements[2] and statements[2].endswith("FOR UPDATE")
    # the control: the same credential after the check is the verdict, whole
    cursor = Cursor([("ivan.p@example.org", stamp), TESTED, ("ok", None, stamp + ONE_MINUTE),
                     TESTED])
    assert requests.check_credential(cursor, 1, requests.Context()) == ("ivan.p@example.org", "ok", None)


def test_the_pipeline_refuses_to_delete_the_last_active_administrator():
    # The row is an active administrator, and the locked active-admin set is
    # just them, so performing the deletion would leave nobody; it is refused here too
    cursor = Cursor([("solo", True, "active"), (0,)])
    with pytest.raises(requests.RequestFailed, match="last one"):
        requests.delete_account(cursor, request_of(kind="delete_account",
                                                   payload={"account_id": 5}), requests.Context())
    statements = [statement for statement, _ in cursor.statements]
    # the last-administrator lock the interface takes too, BEFORE the row is read
    assert "pg_advisory_xact_lock" in statements[0], "it did not take the 0007 lock first"
    assert statements[1].startswith("SELECT login, is_admin, state FROM account")
    assert "is_admin AND state = 'active' AND id <> %s" in statements[2]


def test_a_journal_row_names_the_asking_administrator_and_its_own_request():
    cursor = Cursor()
    requests.journal(cursor, request_of(break_glass=True), "top_up", "ivan@alpha",
                     {"messages": 3, "since": datetime.date(2026, 9, 1)})
    statement, params = cursor.statements[0]
    assert statement.startswith("INSERT INTO audit (actor, action, target, detail, "
                                "break_glass, request_id)")
    assert params[0] == "olga" and params[1] == "top_up" and params[2] == "ivan@alpha"
    assert '"since": "2026-09-01"' in params[3] and '"messages": 3' in params[3]
    assert params[4] is True, "the break-glass flag was dropped from the journal row"
    assert params[5] == 7


def test_a_request_naming_no_administrator_fails_rather_than_naming_the_daemon():
    for nobody in ("", "   ", None):
        with pytest.raises(requests.RequestFailed) as refused:
            requests.journal(Cursor(), request_of(asked_by=nobody), "top_up", "x", {})
        assert "administrator" in str(refused.value)


def test_enabling_writes_the_check_and_the_enable_and_a_refusal_writes_only_the_check(
        monkeypatch, tmp_path):
    rows = []
    context = requests.Context(backup_status=backed_up(tmp_path))  # the backup gate passed
    monkeypatch.setattr(requests, "check_credential",
                        lambda cur, rid, context: ("ivan.p@example.org", "auth_failed", "refused"))
    monkeypatch.setattr(requests, "journal",
                        lambda cur, request, action, target, detail: rows.append(action))
    with pytest.raises(requests.RequestFailed) as refused:
        requests.activate_external_mailbox(Cursor(), request_of(
            kind="activate_external_mailbox", payload={"external_mailbox_id": 1}),
            context)
    # ⚠️ none at all on a refusal: this handler's transaction is rolled back, so a row
    # written before the refusal would go with it. The request's outcome and the row's
    # own last_test_* columns are what record it.
    assert rows == [], "an enable that never happened was journaled"
    assert "still deactivated" in str(refused.value)

    rows.clear()
    monkeypatch.setattr(requests, "check_credential",
                        lambda cur, rid, context: ("ivan.p@example.org", "ok", None))
    cursor = Cursor()
    requests.activate_external_mailbox(cursor, request_of(
        kind="activate_external_mailbox", payload={"external_mailbox_id": 1}), context)
    assert rows == ["test_credential", "activate_external_mailbox"]
    assert "state = 'active'" in cursor.statements[0][0]


def test_a_password_checks_verdict_comes_from_the_row_and_only_when_its_stamp_moved(monkeypatch):
    stamp = datetime.datetime(2026, 9, 1, 12)
    monkeypatch.setattr(requests, "run_runner",
                        lambda *a, **k: FakeProcess(returncode=1, stderr="refused"))
    # the runner exited non-zero and the row says `auth_failed`: a real measurement
    cursor = Cursor([("ivan.p@example.org", stamp), TESTED,
                     ("auth_failed", "refused", stamp + ONE_MINUTE), TESTED])
    assert requests.check_credential(cursor, 1, requests.Context())[1] == "auth_failed"
    # the same answer with a stamp that did not move is last week's verdict, not this run's
    cursor = Cursor([("ivan.p@example.org", stamp), TESTED, ("ok", None, stamp)])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.check_credential(cursor, 1, requests.Context())
    assert "measured nothing" in str(refused.value)
    # and so is a row that has never been tested at all
    cursor = Cursor([("ivan.p@example.org", None), TESTED, (None, None, None)])
    with pytest.raises(requests.RequestFailed):
        requests.check_credential(cursor, 1, requests.Context())


ONE_MINUTE = datetime.timedelta(minutes=1)
# what a check logs in with: credential, POP3 login, host, port
TESTED = ("the-password", "recent:box", "pop.example.org", 995)


class FakeProcess:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = ""


def test_a_refused_password_is_a_finished_check_and_only_enabling_turns_it_into_a_failure(monkeypatch):
    monkeypatch.setattr(requests, "check_credential",
                        lambda cur, rid, context: ("ivan.p@example.org", "auth_failed", "refused"))
    answer = requests.test_credential(Cursor(), request_of(
        kind="test_credential", payload={"external_mailbox_id": 1}), requests.Context())
    assert "auth_failed" in answer  # done, with the provider's answer as its result


# --- the fetcher's own lock, taken blocking -----------------------------------------


def test_deleting_a_provider_mailbox_waits_for_the_fetcher_and_unmaps_before_it_deletes(tmp_path):
    context = requests.Context(fetch_state_root=tmp_path / "fetch")
    state = (tmp_path / "fetch" / "3")
    state.mkdir(parents=True)
    (state / "uidls").write_text("# mpop uidl list\n")
    cursor = Cursor([("ivan.p@example.org",)])  # the row; the xact lock and unmap answer nothing

    requests.delete_external_mailbox(cursor, request_of(
        kind="delete_external_mailbox", payload={"external_mailbox_id": 3}), context)
    statements = [statement for statement, _ in cursor.statements]
    # ⛔ A transaction-level lock, held until drain commits, and never released
    # by hand before the commit that removes the row
    assert "pg_advisory_xact_lock" in statements[1], "the fetcher's lock was not taken first"
    assert statements[2].startswith("UPDATE domain SET external_mailbox_id = NULL")
    assert statements[3].startswith("DELETE FROM external_mailbox")
    assert not any("pg_advisory_unlock" in s for s in statements), \
        "the lock must be held to commit, not released by a hand that runs before it"
    assert not state.exists(), "the fetcher's state outlived the row"


def test_the_lock_is_the_fetchers_own_namespace_read_from_its_module():
    source = Path(requests.__file__).read_text()
    assert hex(locks.NAMESPACE) not in source and str(locks.NAMESPACE) not in source
    # The deletion holds the fetcher's lock until it commits, so it takes the
    # transaction-level lock from the shared module and never unlocks by hand
    assert "locks.xact_lock(" in source and "locks.unlock(" not in source


# --- refusals before anything moves -------------------------------------------------------------


def test_delivering_by_id_refuses_a_message_of_another_domain():
    # the mailbox's row, then the message's: domain 2 where the mailbox is in domain 1
    cursor = Cursor([(1, "ivan", "alpha", None, 1), (50, 7, "delivered", 2)])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.deliver_one(cursor, request_of(
            kind="deliver_one", payload={"mailbox_id": 1, "message_id": 50}), requests.Context())
    assert "not a message of alpha" in str(refused.value)


def test_releasing_a_message_that_is_not_withheld_is_refused():
    cursor = Cursor([(50, 7, "delivered", 1)])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.release(cursor, request_of(kind="release", payload={"message_id": 50}),
                         requests.Context())
    assert "not withheld" in str(refused.value)


def test_deleting_a_mapped_domain_is_refused_and_the_refusal_names_the_mailbox():
    cursor = Cursor([("alpha", 3), ("ivan.p@example.org",)])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.delete_domain(cursor, request_of(kind="delete_domain",
                                                  payload={"domain_id": 1}), requests.Context())
    assert "ivan.p@example.org" in str(refused.value)
    assert not any("DELETE" in statement for statement, _ in cursor.statements)


def test_a_transfer_refuses_an_occupied_slot_before_anything_moves(tmp_path, monkeypatch):
    monkeypatch.setattr(requests.doveadm, "sessions", lambda login: pytest.fail("asked too late"))
    cursor = Cursor([(1, "ivan", "alpha", None, 1), ("olga",), (1,)])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.transfer(cursor, request_of(kind="transfer",
                                             payload={"mailbox_id": 1, "to_account_id": 2}),
                          context_of(tmp_path))
    assert "occupied slot" in str(refused.value)


def test_a_transfer_refuses_while_a_session_is_open(tmp_path, monkeypatch):
    monkeypatch.setattr(requests.doveadm, "sessions", lambda login: [{"username": login}])
    cursor = Cursor([(1, "ivan", "alpha", None, 1), ("olga",), None])
    context = context_of(tmp_path)
    maildir(context.store_root, "alpha", "ivan")
    with pytest.raises(requests.RequestFailed) as refused:
        requests.transfer(cursor, request_of(kind="transfer",
                                             payload={"mailbox_id": 1, "to_account_id": 2}),
                          context)
    assert "session(s) open" in str(refused.value)
    assert store.home("alpha", "ivan", context.store_root).exists(), "it moved anyway"


def test_a_transfer_renames_all_three_directories_and_puts_them_back_on_a_failure(tmp_path,
                                                                                  monkeypatch):
    monkeypatch.setattr(requests.doveadm, "sessions", lambda login: [])
    context = context_of(tmp_path)
    maildir(context.store_root, "alpha", "ivan")
    trees = store.index_paths("alpha", "ivan", context.index_root)
    for tree in trees:
        tree.mkdir(parents=True)

    cursor = Cursor([(1, "ivan", "alpha", None, 1), ("olga",), None])
    requests.transfer(cursor, request_of(kind="transfer",
                                         payload={"mailbox_id": 1, "to_account_id": 2}), context)
    assert store.home("alpha", "olga", context.store_root).exists()
    assert not store.home("alpha", "ivan", context.store_root).exists()
    assert all(tree.exists() for tree in store.index_paths("alpha", "olga", context.index_root))
    assert "UPDATE mailbox SET account_id" in cursor.statements[-2][0]

    # and back again, with the second rename made to fail: nothing is left half-moved
    real = os.rename
    calls = []

    def one_then_fail(source, destination):
        calls.append(source)
        if len(calls) == 2:
            raise OSError("no room")
        return real(source, destination)

    monkeypatch.setattr(requests.os, "rename", one_then_fail)
    cursor = Cursor([(1, "olga", "alpha", None, 1), ("ivan",), None])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.transfer(cursor, request_of(kind="transfer",
                                             payload={"mailbox_id": 1, "to_account_id": 3}),
                          context)
    assert "rolled back" in str(refused.value)
    assert store.home("alpha", "olga", context.store_root).exists()
    assert not store.home("alpha", "ivan", context.store_root).exists()


def test_a_transfer_whose_row_update_fails_puts_the_directories_back(tmp_path, monkeypatch):
    """The row update sits inside the undo block. If writing it (or its journal
    row) fails after the renames succeeded, the renames are undone, so the files and the
    row never disagree about who holds the mailbox."""
    monkeypatch.setattr(requests.doveadm, "sessions", lambda login: [])
    context = context_of(tmp_path)
    maildir(context.store_root, "alpha", "ivan")
    for tree in store.index_paths("alpha", "ivan", context.index_root):
        tree.mkdir(parents=True)

    class FailingUpdate(Cursor):
        def execute(self, sql, params=None):
            super().execute(sql, params)
            if sql.strip().startswith("UPDATE mailbox SET account_id"):
                raise Exception("the row could not be written")  # a DB error after the renames

    cursor = FailingUpdate([(1, "ivan", "alpha", None, 1), ("olga",), None])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.transfer(cursor, request_of(kind="transfer",
                                             payload={"mailbox_id": 1, "to_account_id": 2}), context)
    assert "rolled back" in str(refused.value)
    assert store.home("alpha", "ivan", context.store_root).exists(), "ivan's mailbox was not put back"
    assert not store.home("alpha", "olga", context.store_root).exists(), "olga kept the moved files"


# --- what a payload must carry -------------------------------------------------------------------


def test_a_payload_that_names_no_row_is_refused_rather_than_guessed_at():
    for payload in ({}, {"mailbox_id": None}, {"mailbox_id": ""}, {"mailbox_id": "seven"}):
        with pytest.raises(requests.RequestFailed):
            requests.need_int(payload, "mailbox_id")
    assert requests.need_int({"mailbox_id": "7"}, "mailbox_id") == 7
    assert requests.need_int({"mailbox_id": 7}, "mailbox_id") == 7


def test_no_handler_asks_dovecot_to_create_an_inbox():
    text = Path(requests.__file__).read_text()
    assert 'create_folder(login, INBOX' not in text
    assert '"mailbox", "create"' not in text, "a folder is made through the wrapper, which "\
                                              "refuses INBOX and tolerates one that exists"


# --- enabling a provider mailbox turns on provider-side deletion ---------------------


ACTIVATE = requests.Request(11, "activate_external_mailbox", "ivan.p@example.org",
                            {"external_mailbox_id": 3}, "olga", False)


def backed_up(tmp_path):
    written = tmp_path / "status.json"
    written.write_text('{"stamp": "20260923T000000Z", "taken_at": "2026-09-23T00:00:00+00:00"}')
    return written


def test_enabling_is_refused_until_a_backup_of_the_database_and_state_exists(tmp_path, monkeypatch):
    """The window deletes at the provider from the first run, so the machine becomes the
    only holder of that address's mail: no backup, no enable - and the provider is not
    even asked about the password, since nothing would come of its answer."""
    asked = []
    monkeypatch.setattr(requests, "check_credential", lambda *a: asked.append(a))
    context = requests.Context(backup_status=tmp_path / "status.json")
    cursor = Cursor([("ivan.p@example.org",)])
    with pytest.raises(requests.RequestFailed, match="no backup") as refused:
        requests.activate_external_mailbox(cursor, ACTIVATE, context)
    assert "ivan.p@example.org" in str(refused.value) and "still deactivated" in str(refused.value)
    assert asked == []
    assert not any("UPDATE external_mailbox" in s for s, _ in cursor.statements)


def test_with_a_backup_taken_the_enable_goes_on_to_the_provider(tmp_path, monkeypatch):
    monkeypatch.setattr(requests, "check_credential",
                        lambda cur, rid, context: ("ivan.p@example.org", "ok", None))
    context = requests.Context(backup_status=backed_up(tmp_path))
    cursor = Cursor([("ivan.p@example.org",)])
    answer = requests.activate_external_mailbox(cursor, ACTIVATE, context)
    assert "it is active" in answer
    assert any("SET state = 'active'" in s for s, _ in cursor.statements)
