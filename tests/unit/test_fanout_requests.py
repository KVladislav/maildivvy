"""What is true of the request handlers without a machine: the queue's shape, the one
selector, the order of destruction, and the names on disk.

Everything that needs real rows, a real archive and a real Dovecot is driven on the
test VM. What is tested here is what a machine
cannot show as cheaply: that the bound of a range is spelt once and read by both the
count and the delivery, that names taken out of a mailbox that stays go before
their rows while a mailbox deleted whole loses its rows first and its
directories after the commit, once its sessions have ended, that every kind the
schema allows has a handler, and that a per-message act carries none of the bulk
selector's spam condition.
"""

import datetime
import inspect
import json
import os
import re
import threading
import time
import types
from pathlib import Path

import pytest

import postgres
from bulk_world import named
from maildivvy.admin import journal
from maildivvy.admin.screens import common
from maildivvy.fanout import ledger, pass_, requests
from maildivvy.fetch import locks
from maildivvy.lib import adminlock, store

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


def queued(conn, *rows, draining=True, left=()):
    """The drainer's lock, what earlier deletions left (`left`, read only while it holds
    the lock), then the claim's answers: one row per request, then None for the empty
    queue."""
    conn.cursor_.answers = [(draining,), *([list(left)] if draining else []), *rows, None]


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
    assert seen == [["commit", "commit"]], "the handler ran inside the claim's own transaction"
    # the lock and the reset, the claim, the handler, the outcome - and the claim that
    # finds the queue empty
    assert conn.calls == ["commit", "commit", "commit", "commit", "commit"]


def test_the_passs_drain_claims_nothing_more_once_its_budget_is_spent(monkeypatch, capsys):
    """Every domain's next fan-out waits for this run: a queue of top-ups of hundreds of
    thousands of messages held it for hours (measured). A request under way that is not
    linking in batches runs to its end; the ones after it wait in the queue for the next
    run."""
    conn = Connection()
    queued(conn, ROW, (8, "connect", "olga@alpha", {"mailbox_id": 2}, "olga", False))
    now = [0.0]

    def slow(cur, request, context):
        now[0] += 100
        return "done it"

    monkeypatch.setitem(requests.HANDLERS, "connect", slow)
    assert requests.drain(conn, budget=150, clock=lambda: now[0]) == (2, 0)
    queued(conn, ROW, (8, "connect", "olga@alpha", {"mailbox_id": 2}, "olga", False),
           (9, "connect", "petro@alpha", {"mailbox_id": 3}, "olga", False))
    now[0] = 0.0
    assert requests.drain(conn, budget=150, clock=lambda: now[0]) == (2, 0)
    assert "waits for the next run" in capsys.readouterr().err
    claims = [s for s, _ in conn.cursor_.statements if s.startswith("UPDATE request SET state = 'running'")]
    assert len(claims) == 2 + 3 - 1   # the first run's two and its empty claim, the second's two
    # the pass's half is bounded, the provider drainer's is not: it holds no fan-out
    seen, again = {}, []
    monkeypatch.setattr(pass_.requests, "drain", lambda conn, context, provider=False,
                        budget=None, reconnect=None: (seen.setdefault(provider, budget),
                                                      again.append(reconnect)))
    pass_.drain(None, pass_.parse_args([]))
    pass_.drain(None, pass_.parse_args(["--provider-requests"]))
    assert seen == {False: requests.DRAIN_BUDGET, True: None}
    assert requests.DRAIN_BUDGET <= 300
    # and either drainer can write an outcome on a second connection, made as its first was
    monkeypatch.setattr(pass_, "connect", lambda args: ("a connection for", args.etc))
    assert [make() for make in again] == [("a connection for", "/etc/maildivvy")] * 2


def test_a_failed_handler_is_rolled_back_and_its_reason_written_afterwards(monkeypatch):
    conn = Connection()
    queued(conn, ROW)

    def explode(cur, request, context):
        raise requests.RequestFailed("no mailbox 1")

    monkeypatch.setitem(requests.HANDLERS, "connect", explode)
    assert requests.drain(conn) == (0, 1)
    assert conn.calls == ["commit", "commit", "rollback", "commit", "commit"]
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
    assert conn.calls == ["commit", "commit"]  # the reset's and the claim's, and no handler


@pytest.mark.parametrize("provider", [False, True])
def test_a_request_a_stopped_run_left_running_is_failed_before_the_drain_claims_anything(
        provider):
    """The claim commits before its handler runs, so a run killed inside a handler leaves
    the row `running` and nothing else would ever finish it. A drainer holding its own
    lock knows no other run of it is performing anything: every `running` row of its
    kinds is one a stopped run left. The other drainer's kinds are its own business."""
    conn = Connection()
    queued(conn)
    assert requests.drain(conn, provider=provider) == (0, 0)
    (lock, lock_params), (reset, reset_params), (left, left_params), (claim, _) = \
        conn.cursor_.statements
    assert lock == "SELECT pg_try_advisory_lock(%s, %s)"
    assert lock_params == (requests.DRAINING, int(provider))
    assert reset == " ".join(requests.LEFT_RUNNING.split())
    assert "WHERE state = 'running' AND (kind = ANY(%s)) = %s" in reset
    assert reset_params == ("the pass was stopped while performing it",
                            sorted(requests.PROVIDER), provider)
    # what earlier deletions of its kinds left, read in the same transaction
    assert left == " ".join(requests.LEFT.split())
    assert left_params == (sorted(requests.PROVIDER), provider)
    assert claim == " ".join(requests.CLAIM.split())
    assert conn.calls == ["commit", "commit"], "the reset was not committed before the claim"


@pytest.mark.parametrize("provider", [False, True])
def test_a_second_run_of_the_same_drainer_leaves_the_queue_to_the_one_draining(provider):
    """A pass run by hand while the timer's drains: its lock is taken, so the rows
    `running` are that run's, and this one neither resets nor claims anything."""
    conn = Connection()
    queued(conn, ROW, draining=False)
    assert requests.drain(conn, provider=provider) == (0, 0)
    ((lock, params),) = conn.cursor_.statements
    assert lock == "SELECT pg_try_advisory_lock(%s, %s)" and params[1] == int(provider)


def test_the_drainers_lock_is_a_namespace_no_other_lock_uses():
    from maildivvy.admin.screens import common  # noqa: PLC0415 - the interface's side
    assert requests.DRAINING not in {locks.NAMESPACE, locks.SNAPSHOT, adminlock.NAMESPACE,
                                     common.ONCE}
    # the snapshot's lock is its own too, so a slice never holds up the fetch,
    # and so is the import's
    assert len({locks.NAMESPACE, locks.SNAPSHOT, locks.IMPORT, adminlock.NAMESPACE, common.ONCE,
                requests.DRAINING}) == 6


def schema_kinds():
    """The queue's closed list as the newest migration that sets it has it."""
    found = None
    for path in sorted(SCHEMA.parent.glob("[0-9][0-9][0-9][0-9]_*.sql")):
        for listed in re.findall(r"CHECK \(kind IN \((.*?)\)\)", path.read_text(), re.S):
            found = set(re.findall(r"'([a-z_]+)'", listed))
    return found


def test_every_kind_the_schema_allows_has_a_handler_and_every_handler_a_kind():
    kinds = schema_kinds()
    assert "discard_snapshot" in kinds  # the control: the newest list, 0008's
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
    # nor a page: the rows above an id, in the order of the ids, so many of them
    assert requests.SELECT_FOR.replace(requests.SELECTOR, "") \
        == "SELECT m.id, m.archive_base, m.state AND m.id > %s ORDER BY m.id LIMIT %s"
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
    assert "DO NOTHING" in ledger.LINK
    assert "relink=True" in inspect.getsource(requests.deliver_one)
    for name in ("connect", "top_up", "release"):
        assert "relink=True" not in inspect.getsource(getattr(requests, name))


# --- a UID counts in the mailbox it was given in --------------------------------------


def test_a_withheld_or_released_messages_number_counts_in_the_quarantine():
    # the ledger's own reading of a row's folder, the one the requests look a UID up by
    assert ledger.folder_of("delivered") == requests.INBOX
    assert ledger.folder_of("withheld") == store.QUARANTINE
    # ⛔ a released message's file never moved: its number still counts in the quarantine
    assert ledger.folder_of("released") == store.QUARANTINE


# --- destruction: a name before its row; a whole mailbox's rows before its directories


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
        store.link_into(source, boxes[:2], tmp_path, made=context.made)
        # ivan reads it in between: his name moves to cur/ with its flags
        os.rename(boxes[0] / "new" / source.name, boxes[0] / "cur" / f"{source.name}:2,S")
        store.link_into(source, boxes[2:], tmp_path, made=context.made)
        raise requests.RequestFailed("the third receiver could not be linked")

    monkeypatch.setitem(requests.HANDLERS, "connect", half_way)
    assert requests.drain(conn) == (0, 1)
    assert source.stat().st_nlink == 2  # the archive's own name, and olga's from before
    assert (boxes[1] / "new" / source.name).exists()
    assert outcome(conn) == ("failed", "the third receiver could not be linked", 7)


def test_a_release_removes_the_reports_names_before_it_deletes_their_rows(monkeypatch):
    """The report stays in the archive and the mailboxes stay: its delivery rows are the
    list of whose names to remove, so they go only after the names."""
    order = []
    monkeypatch.setattr(requests, "remove_report",
                        lambda *a: order.append("names") or 2)
    monkeypatch.setattr(requests, "report_file", lambda *a: (None, "r1"))
    # the message, its domain, its reports, the receivers
    cursor = Cursor([(50, "w50", "withheld", 1, 3), ("alpha",), [(51, "r1", 4)], []])
    real = cursor.execute
    cursor.execute = lambda sql, params=None: (
        order.append("rows") if sql.startswith("DELETE FROM delivery") else None,
        real(sql, params))
    requests.release(cursor, request_of(kind="release", payload={"message_id": 50}),
                     requests.Context())
    assert order == ["names", "rows"], "the report's rows went before its names"


RELEASE = [(50, "w50", "withheld", 1, 3), ("alpha",)]   # then its reports, then receivers


def test_a_release_whose_report_cannot_be_read_fails_with_nothing_changed(monkeypatch):
    """A report whose file cannot be read is not "the report is gone": read so, the release
    deleted the report's rows and the report stayed in every mailbox for good. Nor is one
    the pass has not named yet."""
    def refuse(*a, **k):
        raise PermissionError("the archive could not be read")

    monkeypatch.setattr(requests.store, "resolve", refuse)
    for reports, said in (([(51, "r1", 4)], "could not be read, so nothing was released: the "
                                            "archive could not be read"),
                          ([(51, None, 4)], "has no archive name yet")):
        cursor = Cursor([*RELEASE, reports, []])
        with pytest.raises(requests.RequestFailed, match=said):
            requests.release(cursor, request_of(kind="release", payload={"message_id": 50}),
                             requests.Context())
        statements = [statement for statement, _ in cursor.statements]
        assert not any(s.startswith(("DELETE", "UPDATE message", "INSERT")) for s in statements)


@pytest.mark.parametrize("there", [False, True])
def test_a_report_is_found_by_its_base_name_whether_or_not_its_file_is_there(tmp_path, there):
    """A report's file gone from the archive still names the base name the names in
    people's mailboxes are found by, and Dovecot is not asked."""
    context = context_of(tmp_path)
    if there:
        archived(context.store_root, requests.INBOX, [4])
    box = maildir(context.store_root, "alpha", "ivan")
    (box / "cur" / "1700000004.M4P1.host:2,S").write_text("report")
    # the reports, nobody receiving the original, then the report's holders
    cursor = Cursor([*RELEASE, [(51, "1700000004.M4P1.host", 4)], [], [(5, "ivan")]])
    said = requests.release(cursor, request_of(kind="release", payload={"message_id": 50}),
                            context)
    assert said.endswith("1 report name(s) removed")
    assert not (box / "cur" / "1700000004.M4P1.host:2,S").exists()
    assert ("DELETE FROM delivery WHERE message_id = %s", (51,)) in cursor.statements


def test_a_report_with_no_archive_number_is_gone_and_its_rows_go(capsys):
    cursor = Cursor([*RELEASE, [(51, None, None)], []])
    said = requests.release(cursor, request_of(kind="release", payload={"message_id": 50}),
                            requests.Context())
    assert said.endswith("0 report name(s) removed")
    assert ("DELETE FROM delivery WHERE message_id = %s", (51,)) in cursor.statements
    assert "the report 51 of alpha has no archive name" in capsys.readouterr().err


def bounded(bound, namespace, key):
    """One blocking advisory lock waited for under its bound: the bound, the lock,
    then the session's own bound back."""
    return [("SET LOCAL lock_timeout = %s", (f"{bound}s",)),
            ("SELECT pg_advisory_xact_lock(%s, %s)", (namespace, key)),
            ("SET LOCAL lock_timeout TO DEFAULT", None)]


def test_a_deleted_mailbox_loses_its_rows_and_leaves_its_directories_to_after_the_commit(tmp_path):
    """The handler touches no file: a directory removed before the commit is made again by
    a client still logged in, and the row that keeps clients out is gone only at commit."""
    context = context_of(tmp_path)._replace(gone=[])
    box = maildir(context.store_root, "alpha", "ivan")
    cursor = Cursor([(4,)])
    names = requests.unlink_mailbox(cursor, requests.Mailbox(1, "ivan", "alpha", None, 1), context)
    assert names == 4
    # the import of its domain waited for first, then its rows
    assert cursor.statements[:3] == bounded(requests.IMPORT_WAIT, locks.IMPORT, 1)
    assert [statement.split()[0] for statement, _ in cursor.statements[3:]] == \
        ["SELECT", "DELETE", "DELETE"]
    assert box.is_dir(), "the handler removed a directory before its rows committed"
    assert context.gone == [["alpha", "ivan"]]


DELETE_MAILBOX = (7, "delete_mailbox", "ivan@alpha", {"mailbox_id": 1}, "olga", False)


def with_trees(context, label, account):
    """A mailbox's three directories, as a session leaves them."""
    maildir(context.store_root, label, account)
    for tree in store.index_paths(label, account, context.index_root):
        tree.mkdir(parents=True)
        (tree / "dovecot.index.log").write_text("x")
    return [store.home(label, account, context.store_root),
            *store.index_paths(label, account, context.index_root)]


def sessions_of(monkeypatch, conn, trees, open_for=0):
    """Dovecot's side: every kick and every `who`, with what was committed and on disk then.
    A session lasts `open_for` readings after its kick."""
    seen = []

    def kick(mask):
        seen.append(("kick", mask, conn.calls.count("commit"), all(t.exists() for t in trees)))
        return [{"count": "1"}]

    def who(mask):
        seen.append(("who", mask))
        return [{"username": mask}] if sum(1 for e in seen if e[0] == "who") <= open_for else []

    monkeypatch.setattr(requests.doveadm, "kick", kick)
    monkeypatch.setattr(requests.doveadm, "sessions", who)
    monkeypatch.setattr(requests.time, "sleep", lambda seconds: None)
    return seen


def test_a_deletions_directories_go_after_its_commit_once_its_sessions_have_ended(
        tmp_path, monkeypatch):
    conn = Connection()
    queued(conn, DELETE_MAILBOX, (1, "ivan", "alpha", None, 1), (4,))
    context = context_of(tmp_path)
    trees = with_trees(context, "alpha", "ivan")
    seen = sessions_of(monkeypatch, conn, trees, open_for=2)

    assert requests.drain(conn, context) == (1, 0)
    statements = [statement for statement, _ in conn.cursor_.statements]
    leave = statements.index(" ".join(requests.LEAVE.split()))
    assert statements.index("DELETE FROM mailbox WHERE id = %s") < leave
    assert conn.cursor_.statements[leave][1] == ('[["alpha", "ivan"]]', 7)
    # the lock's and the claim's commits, then the handler's: only then the kick
    kick = seen[0]
    assert kick == ("kick", "ivan@alpha", 3, True), "the sessions were ended before the rows committed"
    assert [e for e in seen if e[0] == "who"] == [("who", "ivan@alpha")] * 3, \
        "the directories went while a session was still open"
    assert not any(tree.exists() for tree in trees)
    assert outcome(conn)[0] == "done"
    assert statements[-2] == " ".join(requests.CLEAR.split()), "the list outlived the directories"


def test_a_session_that_does_not_end_keeps_its_directories_and_the_list_for_the_next_run(
        tmp_path, monkeypatch):
    conn = Connection()
    queued(conn, DELETE_MAILBOX, (1, "ivan", "alpha", None, 1), (4,))
    context = context_of(tmp_path)
    trees = with_trees(context, "alpha", "ivan")
    sessions_of(monkeypatch, conn, trees, open_for=10**6)
    monkeypatch.setattr(requests, "SESSIONS_END", 0)

    assert requests.drain(conn, context) == (0, 1)
    state, reason, _ = outcome(conn)
    assert state == "failed"
    assert "its rows are deleted" in reason and "did not end" in reason
    assert "the next run tries again" in reason
    assert all(tree.exists() for tree in trees), "removed under a session still open"
    statements = [statement for statement, _ in conn.cursor_.statements]
    assert " ".join(requests.CLEAR.split()) not in statements, "the list went with nothing removed"
    assert "commit" in conn.calls and "rollback" not in conn.calls, "the rows were not kept deleted"


def test_what_an_earlier_deletion_left_is_removed_by_the_next_run_and_a_held_slot_is_a_fault(
        tmp_path, monkeypatch, capsys):
    """A slot a row holds again is the same path, holding the deleted mail: it is not
    removed, and not dropped as if a new mailbox had directories of its own there. Its
    entry stays on the request, which stays failed, saying so."""
    conn = Connection()
    context = context_of(tmp_path)
    gone = with_trees(context, "alpha", "ivan")
    taken = with_trees(context, "alpha", "olga")
    sessions_of(monkeypatch, conn, gone)
    queued(conn, left=[(9, [["alpha", "ivan"], ["alpha", "olga"]], "its rows are deleted, but")])
    conn.cursor_.answers[2:2] = [(False,), (True,)]   # olga has a mailbox there again

    assert requests.drain(conn, context) == (0, 0)
    assert not any(tree.exists() for tree in gone)
    assert all(tree.exists() for tree in taken), "a held slot's directories were removed"
    statements = [statement for statement, _ in conn.cursor_.statements]
    assert " ".join(requests.RETRIED.split()) not in statements, "a held slot was a success"
    (params,) = [p for statement, p in conn.cursor_.statements
                 if statement == " ".join(requests.KEPT.split())]
    assert params[1:] == ('[["alpha", "olga"]]', 9)
    assert "olga@alpha's directories were not removed before a row held that slot" in params[0]
    assert "request 9: its rows are deleted, but olga@alpha's" in capsys.readouterr().err

    # nothing free left: the held entry alone, told again, and nothing ended or removed
    conn = Connection()
    queued(conn, left=[(9, [["alpha", "olga"]], params[0])])
    conn.cursor_.answers[2:2] = [(True,)]
    monkeypatch.setattr(requests.doveadm, "kick", lambda mask: pytest.fail(mask))
    assert requests.drain(conn, context) == (0, 0)
    assert all(tree.exists() for tree in taken)


def test_a_slot_a_deletion_has_not_cleared_is_refused_to_a_new_mailbox_and_a_new_domain(
        database):
    """On the real queue: the list a deletion left on its failed request names the slot, and
    every handler that would make a mailbox or an archive there refuses, naming it."""
    domain, mailbox = scene(database)
    # The list is written as the pipeline writes it, by UPDATE on the row: no request is
    # inserted carrying one.
    left = database.value(
        "INSERT INTO request (kind, target, payload, asked_by, state) VALUES ('delete_domain', "
        "'alpha', %s, 'olga', 'failed') RETURNING id", (json.dumps({"domain_id": 99}),))
    database.sql("UPDATE request SET payload = payload || %s WHERE id = %s",
                 (json.dumps({"gone": [["alpha", "ivan"], ["alpha", store.ARCHIVE],
                                       ["alpha", None]]}), left))
    done = database.value(
        "INSERT INTO request (kind, target, payload, asked_by, state) VALUES "
        "('delete_mailbox', 'olga@beta', %s, 'olga', 'done') RETURNING id",
        (json.dumps({"mailbox_id": 98}),))
    database.sql("UPDATE request SET payload = payload || %s WHERE id = %s",
                 (json.dumps({"gone": [["beta", "olga"]]}), done))
    conn = database.connect("pipeline")
    try:
        with conn.cursor() as cur:
            for handler, payload in ((requests.create_mailbox, {"mailbox_id": mailbox}),
                                     (requests.connect, {"mailbox_id": mailbox}),
                                     (requests.create_domain, {"domain_id": domain})):
                with pytest.raises(requests.RequestFailed) as refused:
                    handler(cur, request_of(payload=payload), requests.Context())
                assert f"request {left}, a deletion, has not finished removing" in \
                    str(refused.value), handler
            for label, account, found in (("alpha", "olga", None), ("beta", "olga", None),
                                          ("beta", None, None), ("alpha", None, left)):
                cur.execute(requests.STILL_LISTED, {"label": label, "account": account})
                assert (cur.fetchone() or (None,))[0] == found, (label, account)
    finally:
        conn.close()


def test_a_retry_that_raises_never_holds_the_queue(monkeypatch, capsys):
    """The retry runs before every claim: a fault in it that stopped the drain would hold
    every request behind it, on every run, for good."""
    conn = Connection()
    queued(conn, ROW, left=[(9, [["alpha", "ivan"]], "x")])
    monkeypatch.setattr(requests, "retry", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setitem(requests.HANDLERS, "connect", lambda cur, request, context: "done it")
    assert requests.drain(conn) == (1, 0)
    assert "rollback" in conn.calls
    assert "request 9's directories could not be tried again: RuntimeError: boom" in \
        capsys.readouterr().err


def test_a_domain_loses_every_row_before_any_file_and_its_archive_goes_last(tmp_path):
    """The domain's row is locked first; then its mailboxes', its messages' and its own
    rows; no file is touched in the transaction, and the archive's directories and then
    the domain's own are the last entries of what goes after the commit."""
    context = context_of(tmp_path)._replace(gone=[])
    archive = maildir(context.store_root, "alpha", store.ARCHIVE)
    cursor = Cursor([("alpha", None), [(1,)], (1, "ivan", "alpha", None, 1), (4,)])
    requests.delete_domain(cursor, request_of(kind="delete_domain", payload={"domain_id": 1}),
                           context)
    statements = [statement for statement, _ in cursor.statements]
    # the import of the domain is waited for before its row is locked
    assert cursor.statements[:3] == bounded(requests.IMPORT_WAIT, locks.IMPORT, 1)
    assert statements[3].endswith("FOR UPDATE")
    assert statements.index("DELETE FROM domain WHERE id = %s") < len(statements) - 1
    assert statements[-1].startswith("INSERT INTO audit")
    assert archive.is_dir(), "a file went before the rows committed"
    assert context.gone == [["alpha", "ivan"], ["alpha", store.ARCHIVE], ["alpha", None]]


def test_the_second_step_removes_a_domains_own_directories_only_by_rmdir(tmp_path, monkeypatch):
    context = context_of(tmp_path)
    with_trees(context, "alpha", store.ARCHIVE)
    stranger = maildir(context.store_root, "alpha", "unknown")
    monkeypatch.setattr(requests.doveadm, "kick", lambda mask: [])
    monkeypatch.setattr(requests.doveadm, "sessions", lambda mask: [])
    state, words = requests.after_commit([["alpha", store.ARCHIVE], ["alpha", None]], context)
    assert state == "done" and "NOT empty" in words
    assert stranger.is_dir()
    assert not store.home("alpha", store.ARCHIVE, context.store_root).exists()
    assert not (context.index_root / "idx" / "alpha").exists()


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

    removed = requests.remove_names(home, report.stat().st_ino, store.base_name(report))
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
    assert list(store.mailbox_files(store.home("alpha", "nobody", context.store_root))) == []
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
    assert cursor.statements[:3] == bounded(requests.ADMIN_WAIT, adminlock.NAMESPACE,
                                            adminlock.KEY), "it did not take the 0007 lock first"
    assert statements[3].startswith("SELECT login, is_admin, state FROM account")
    assert "is_admin AND state = 'active' AND id <> %s" in statements[4]


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
                        lambda cur, rid, context, **_: ("ivan.p@example.org", "auth_failed", "refused"))
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
                        lambda cur, rid, context, **_: ("ivan.p@example.org", "ok", None))
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
# what a check logs in with: credential, login, host, port, pinned certificate and protocol
TESTED = ("the-password", "recent:box", "pop.example.org", 995, None, "pop3")


class FakeProcess:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = ""


def test_a_check_whose_pinned_certificate_changed_while_it_ran_switches_nothing_on(monkeypatch):
    """The check trusts the server by the pin it read, so a pin changed meanwhile makes the
    verdict one about a server the row no longer trusts."""
    assert "pop3_cert_fingerprint" in requests.TESTED_AGAINST
    stamp = datetime.datetime(2026, 9, 1, 12)
    monkeypatch.setattr(requests, "run_runner", lambda *a, **k: FakeProcess(returncode=0))
    pinned = TESTED[:4] + (":".join(["AB", "01"] * 16),)
    cursor = Cursor([("ivan.p@example.org", stamp), TESTED, ("ok", None, stamp + ONE_MINUTE),
                     pinned])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.check_credential(cursor, 1, requests.Context())
    assert "changed while it was being checked" in str(refused.value)


def test_a_check_whose_protocol_changed_while_it_ran_switches_nothing_on(monkeypatch, database):
    """The same host and login checked over the other protocol are another server's answer:
    an IMAP mailbox set back to POP3 while its check ran is not switched on by
    a verdict about IMAP. On the real row, as the pipeline's role reads it: the row before
    the check and after it differ by their protocol alone."""
    rid = database.value(
        "INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host, "
        "credential, protocol, keep_at_provider) VALUES ('ivan.p@example.org', "
        "'ivan.p@example.org', 'imap.example.org', 'smtp.example.org', 'secret', 'imap', true) "
        "RETURNING id")

    def meanwhile(*args, **kwargs):
        # a person sets it back to POP3, and the runner writes its verdict about IMAP
        database.sql("UPDATE external_mailbox SET protocol = 'pop3', last_test_at = now(), "
                     "last_test_status = 'ok' WHERE id = %s", (rid,))
        return FakeProcess(returncode=0)

    monkeypatch.setattr(requests, "run_runner", meanwhile)
    conn = database.connect("pipeline")
    try:
        with conn.cursor() as cur:
            with pytest.raises(requests.RequestFailed) as refused:
                requests.check_credential(cur, rid, requests.Context(), start_mark=True)
            conn.rollback()
            # the control: unchanged meanwhile, the same verdict is this row's
            monkeypatch.setattr(requests, "run_runner", lambda *a, **k: database.sql(
                "UPDATE external_mailbox SET last_test_at = now() WHERE id = %s", (rid,))
                or FakeProcess(returncode=0))
            assert requests.check_credential(cur, rid, requests.Context())[1] == "ok"
    finally:
        conn.rollback()
        conn.close()
    assert "changed while it was being checked" in str(refused.value)
    assert "nothing was switched on" in str(refused.value)


def test_only_the_activations_check_asks_the_runner_for_the_mark(monkeypatch, tmp_path):
    """A plain check never writes the mark; the activation's check is the one
    that sets it, by passing `--start-mark` to the runner."""
    stamp = datetime.datetime(2026, 9, 1, 12)
    asked = []
    monkeypatch.setattr(requests, "run_runner",
                        lambda context, argv, *a: asked.append(argv) or FakeProcess(returncode=0))

    def checked():
        return Cursor([("ivan.p@example.org", stamp), TESTED, ("ok", None, stamp + ONE_MINUTE),
                       TESTED])

    requests.test_credential(checked(), request_of(
        kind="test_credential", payload={"external_mailbox_id": 3}), requests.Context())
    requests.activate_external_mailbox(checked(), ACTIVATE,
                                       requests.Context(backup_status=backed_up(tmp_path)))
    assert asked == [["--auth-only", "--only", "3"],
                     ["--auth-only", "--only", "3", "--start-mark"]]


def test_a_refused_password_is_a_finished_check_and_only_enabling_turns_it_into_a_failure(monkeypatch):
    monkeypatch.setattr(requests, "check_credential",
                        lambda cur, rid, context: ("ivan.p@example.org", "auth_failed", "refused"))
    answer = requests.test_credential(Cursor(), request_of(
        kind="test_credential", payload={"external_mailbox_id": 1}), requests.Context())
    assert "auth_failed" in answer  # done, with the provider's answer as its result


# --- the fetcher's own lock, taken blocking -----------------------------------------


def snapshot_of(tmp_path, mailbox_id):
    """A snapshot's directory as a slice leaves it, under a snapshot root of the test's own."""
    home = tmp_path / "snapshots" / str(mailbox_id)
    (home / "Maildir" / "cur").mkdir(parents=True)
    (home / "Maildir" / "cur" / "7.1.snapshot,S=3:2,S").write_text("one")
    (home / "manifest.json").write_text("{}")
    return home


def test_deleting_a_provider_mailbox_waits_for_the_fetcher_and_unmaps_before_it_deletes(tmp_path):
    context = requests.Context(fetch_state_root=tmp_path / "fetch",
                               snapshot_root=tmp_path / "snapshots")
    state = (tmp_path / "fetch" / "3")
    state.mkdir(parents=True)
    (state / "uidls").write_text("# mpop uidl list\n")
    taken = snapshot_of(tmp_path, 3)
    cursor = Cursor([("ivan.p@example.org",)])  # the row; the xact locks and unmap answer nothing

    answer = requests.delete_external_mailbox(cursor, request_of(
        kind="delete_external_mailbox", payload={"external_mailbox_id": 3}), context)
    statements = [statement for statement, _ in cursor.statements]
    # ⛔ A transaction-level lock, held until drain commits, and never released
    # by hand before the commit that removes the row; the snapshot's after the fetcher's,
    # so a slice in progress is waited for too
    assert cursor.statements[1:4] == bounded(requests.FETCH_WAIT, locks.NAMESPACE, 3), \
        "the fetcher's lock was not taken first"
    assert cursor.statements[4:7] == bounded(requests.SNAPSHOT_WAIT, locks.SNAPSHOT, 3), \
        "the snapshot's lock was not taken before the row went"
    assert statements[7].startswith("UPDATE domain SET external_mailbox_id = NULL")
    assert statements[8].startswith("DELETE FROM external_mailbox")
    assert not any("pg_advisory_unlock" in s for s in statements), \
        "the lock must be held to commit, not released by a hand that runs before it"
    assert not state.exists(), "the fetcher's state outlived the row"
    assert not taken.exists() and (tmp_path / "snapshots").is_dir(), "the snapshot outlived the row"
    assert "and snapshot" in answer
    assert '"snapshot_removed": true' in cursor.statements[-1][1][3]


def test_a_discard_waits_beside_the_pass_for_the_slice_that_holds_the_snapshots_lock(
        tmp_path, database):
    """Slices run back to back, so a discard that took the lock only while it was free would
    be refused almost every time: it waits for the slice in progress, and so it is drained
    beside the pass, never by it. On the real queue, row and lock, as the pipeline's role."""
    rid = database.value(
        "INSERT INTO external_mailbox (address, address_canonical, protocol, pop3_host, "
        "smtp_host, keep_at_provider, snapshot_requested_at, snapshot_started_at, "
        "snapshot_status, snapshot_refused, snapshot_left_out) VALUES ('ivan.p@example.org', "
        "'ivan.p@example.org', 'imap', 'imap.example.org', 'smtp.example.org', true, now(), "
        "now(), 'running', 1, 2) RETURNING id")
    asked = database.value(
        "INSERT INTO request (kind, target, payload, asked_by) VALUES ('discard_snapshot', "
        "'ivan.p@example.org', %s, 'olga') RETURNING id",
        (json.dumps({"external_mailbox_id": rid}),))
    taken = snapshot_of(tmp_path, rid)
    context = requests.Context(snapshot_root=tmp_path / "snapshots")
    waiting = ("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted "
               "AND classid = %s AND objid = %s")
    a_slice, drainer = database.connect("pipeline"), database.connect("pipeline")
    try:
        with a_slice.cursor() as cur:
            assert locks.try_lock(cur, rid, locks.SNAPSHOT)   # a slice is copying
        a_slice.commit()
        assert requests.drain(drainer, context) == (0, 0)   # the pass leaves it
        drained = []
        worker = threading.Thread(
            target=lambda: drained.append(requests.drain(drainer, context, provider=True)))
        worker.start()
        for _ in range(100):
            if database.value(waiting, (locks.SNAPSHOT, rid)):
                break
            time.sleep(0.1)
        assert database.value(waiting, (locks.SNAPSHOT, rid)) == 1, "the discard did not wait"
        assert taken.exists() and drained == [], "a discard went on beside a slice"
        with a_slice.cursor() as cur:
            assert locks.unlock(cur, rid, locks.SNAPSHOT)     # the slice ends
        a_slice.commit()
        worker.join(30)
        assert drained == [(1, 0)]
    finally:
        a_slice.close()
        drainer.close()
    assert database.one("SELECT state, result FROM request WHERE id = %s", (asked,)) == \
        ("done", "discarded the snapshot of ivan.p@example.org")
    assert not taken.exists() and (tmp_path / "snapshots").is_dir()
    assert database.one("SELECT snapshot_status, snapshot_started_at, snapshot_finished_at IS NOT "
                        "NULL, snapshot_refused, snapshot_left_out, snapshot_requested_at IS NOT "
                        "NULL FROM external_mailbox WHERE id = %s", (rid,)) == \
        (None, None, True, None, None, True)   # the interface's request column is its own
    assert database.one("SELECT actor, action, detail->>'status' FROM audit WHERE request_id = "
                        "%s", (asked,)) == ("olga", "discard_snapshot", "running")

    # nothing on disk: the row has none any more all the same
    again = database.value("INSERT INTO request (kind, target, payload, asked_by) VALUES "
                           "('discard_snapshot', 'ivan.p@example.org', %s, 'olga') RETURNING id",
                           (json.dumps({"external_mailbox_id": rid}),))
    drainer = database.connect("pipeline")
    try:
        assert requests.drain(drainer, context, provider=True) == (1, 0)
    finally:
        drainer.close()
    assert database.value("SELECT result FROM request WHERE id = %s", (again,)) == \
        "ivan.p@example.org had no snapshot on disk; none is asked for any more"


def test_an_import_that_holds_its_lock_fails_a_deletion_within_the_bound_and_the_queue_goes_on(
        tmp_path, database, monkeypatch):
    """An import suspended in a terminal never sees the deletion asked for: the deletion
    fails within IMPORT_WAIT, naming the import, with nothing deleted, and the request
    after it is performed in the same drain. On the real queue, row and lock."""
    domain, mailbox = scene(database)
    asked = database.value(
        "INSERT INTO request (kind, target, payload, asked_by) VALUES ('delete_mailbox', "
        "'ivan@alpha', %s, 'olga') RETURNING id", (json.dumps({"mailbox_id": mailbox}),))
    after = database.value(
        "INSERT INTO request (kind, target, payload, asked_by) VALUES ('create_mailbox', "
        "'ivan@alpha', %s, 'olga') RETURNING id", (json.dumps({"mailbox_id": mailbox}),))
    monkeypatch.setattr(requests, "IMPORT_WAIT", 1)
    context = context_of(tmp_path)
    monkeypatch.setitem(requests.HANDLERS, "create_mailbox", lambda cur, request, c: "made")
    an_import, drainer = database.connect("pipeline"), database.connect("pipeline")
    try:
        with an_import.cursor() as cur:
            assert locks.try_lock(cur, domain, locks.IMPORT)   # and then suspended
        an_import.commit()
        began = time.monotonic()
        assert requests.drain(drainer, context) == (1, 1)
        assert time.monotonic() - began < 10
    finally:
        an_import.close()
        drainer.close()
    state, result = database.one("SELECT state, result FROM request WHERE id = %s", (asked,))
    assert state == "failed"
    assert result.startswith("an import of this domain holds its lock: stop it")
    assert "not let go within 1 s" in result
    assert database.value("SELECT count(*) FROM mailbox WHERE id = %s", (mailbox,)) == 1
    assert database.value("SELECT state FROM request WHERE id = %s", (after,)) == "done"


def test_the_lock_is_the_fetchers_own_namespace_read_from_its_module():
    source = Path(requests.__file__).read_text()
    assert hex(locks.NAMESPACE) not in source and str(locks.NAMESPACE) not in source
    assert hex(locks.SNAPSHOT) not in source and str(locks.SNAPSHOT) not in source
    assert hex(locks.IMPORT) not in source and str(locks.IMPORT) not in source
    # The deletion holds the fetcher's lock until it commits, so it takes the
    # transaction-level lock from the shared module and never unlocks by hand
    assert "locks.xact_lock," in source and "locks.unlock(" not in source


# --- refusals before anything moves -------------------------------------------------------------


def test_delivering_by_id_refuses_a_message_of_another_domain():
    # the mailbox's row, then the message's: domain 2 where the mailbox is in domain 1
    cursor = Cursor([(1, "ivan", "alpha", None, 1), (50, 7, "delivered", 2)])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.deliver_one(cursor, request_of(
            kind="deliver_one", payload={"mailbox_id": 1, "message_id": 50}), requests.Context())
    assert "not a message of alpha" in str(refused.value)


def test_releasing_a_message_that_is_not_withheld_is_refused():
    cursor = Cursor([(50, "m50", "delivered", 1, 7)])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.release(cursor, request_of(kind="release", payload={"message_id": 50}),
                         requests.Context())
    assert "not withheld" in str(refused.value)


# --- no UID read, no numbering checked: a row's file is its base name (`0100`) ------------------


@pytest.mark.parametrize("kind, answers", [
    # the mailbox, its rows in range
    ("connect", [(1, "ivan", "alpha", None, 1), None, [(50, None, "delivered")]]),
    ("top_up", [(1, "ivan", "alpha", None, 1), [(50, None, "released")]]),
    # the mailbox, the message
    ("deliver_one", [(1, "ivan", "alpha", None, 1), (50, None, "delivered", 1, 3)]),
    # the message, its domain
    ("release", [(50, None, "withheld", 1, 3), ("alpha",)]),
])
def test_a_row_the_pass_has_not_named_yet_fails_its_request_with_nothing_linked(
        monkeypatch, kind, answers):
    """The previous release's rows, in a folder the pass has not ticked since the upgrade:
    a UID alone, which this release never links by."""
    for name in ("message_file", "fetch", "run", "mailbox_status"):
        monkeypatch.setattr(requests.doveadm, name,
                            lambda *a, **k: pytest.fail("Dovecot was asked for a message's file"))
    cursor = Cursor(answers)
    payload = {"mailbox_id": 1, "message_id": 50, "since": "2026-01-01", "until": "2026-12-31"}
    with pytest.raises(requests.RequestFailed, match="message 50 of alpha has no archive name yet"):
        requests.HANDLERS[kind](cursor, request_of(kind=kind, payload=payload), requests.Context())
    assert not [sql for sql, _ in cursor.statements if sql.startswith(("INSERT", "UPDATE", "DELETE"))]


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
    cursor = Cursor([(1, "ivan", "alpha", None, 1), ("olga",), None, None])
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

    cursor = Cursor([(1, "ivan", "alpha", None, 1), ("olga",), None, None])
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
    cursor = Cursor([(1, "olga", "alpha", None, 1), ("ivan",), None, None])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.transfer(cursor, request_of(kind="transfer",
                                             payload={"mailbox_id": 1, "to_account_id": 3}),
                          context)
    assert "rolled back" in str(refused.value)
    assert store.home("alpha", "olga", context.store_root).exists()
    assert not store.home("alpha", "ivan", context.store_root).exists()


def test_a_transfer_fsyncs_both_parents_of_its_renames_before_the_row_moves(tmp_path,
                                                                             monkeypatch):
    """A rename is durable only once its directory is; the row must not name the new
    holder of files a crash could put back under the old one."""
    monkeypatch.setattr(requests.doveadm, "sessions", lambda login: [])
    context = context_of(tmp_path)
    maildir(context.store_root, "alpha", "ivan")
    for tree in store.index_paths("alpha", "ivan", context.index_root):
        tree.mkdir(parents=True)
    cursor = Cursor([(1, "ivan", "alpha", None, 1), ("olga",), None, None])
    synced = []
    monkeypatch.setattr(store, "fsync_dirs", lambda dirs: synced.append(
        ({str(d) for d in dirs}, len(cursor.statements))))

    requests.transfer(cursor, request_of(kind="transfer",
                                         payload={"mailbox_id": 1, "to_account_id": 2}), context)
    moved = [store.home("alpha", "olga", context.store_root),
             *store.index_paths("alpha", "olga", context.index_root)]
    (dirs, statements_before), = synced
    assert dirs == {str(path.parent) for path in moved}
    assert not any("UPDATE mailbox" in sql for sql, _ in cursor.statements[:statements_before])


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

    cursor = FailingUpdate([(1, "ivan", "alpha", None, 1), ("olga",), None, None])
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
                        lambda cur, rid, context, **_: ("ivan.p@example.org", "ok", None))
    context = requests.Context(backup_status=backed_up(tmp_path))
    cursor = Cursor([("ivan.p@example.org",)])
    answer = requests.activate_external_mailbox(cursor, ACTIVATE, context)
    assert "it is active" in answer
    assert any("SET state = 'active'" in s for s, _ in cursor.statements)


# --- a slow request never holds the fan-out --------------------------------------------


REFETCH = request_of(kind="refetch", payload={"external_mailbox_id": 1})


def test_a_refetch_that_found_a_collection_already_running_fails_and_never_says_collected(
        monkeypatch):
    from maildivvy.fetch import runner

    monkeypatch.setattr(requests, "run_runner",
                        lambda *a, **k: FakeProcess(returncode=runner.EX_TEMPFAIL))
    cursor = Cursor([("ivan.p@example.org", "active")])
    with pytest.raises(requests.RequestFailed) as refused:
        requests.refetch(cursor, REFETCH, requests.Context())
    assert "already running" in str(refused.value) and "ask again" in str(refused.value)
    assert not any("INSERT INTO audit" in s for s, _ in cursor.statements)
    # the control: the same handler with a collection that ran is a success
    monkeypatch.setattr(requests, "run_runner", lambda *a, **k: FakeProcess(returncode=0))
    cursor = Cursor([("ivan.p@example.org", "active")])
    assert requests.refetch(cursor, REFETCH, requests.Context()) == "collected ivan.p@example.org"


def test_the_requests_that_wait_on_a_provider_are_drained_beside_the_pass_and_never_by_it():
    assert requests.PROVIDER == {"refetch", "test_credential", "activate_external_mailbox",
                                 "delete_external_mailbox", "discard_snapshot"}
    assert requests.PROVIDER <= set(requests.HANDLERS)
    # the kinds that select message rows stay behind the fan-out
    assert not requests.PROVIDER & {"connect", "top_up", "deliver_one", "release"}
    claim = " ".join(requests.CLAIM.split())
    for provider in (False, True):
        conn = Connection()
        queued(conn)
        assert requests.drain(conn, provider=provider) == (0, 0)
        (statement, params) = conn.cursor_.statements[-1]
        assert statement == claim and params == (sorted(requests.PROVIDER), provider)
    # ⛔ the pass takes every kind but these, so an unknown kind still reaches a drainer
    # and fails rather than waiting for ever
    assert "(kind = ANY(%s)) = %s" in claim


@pytest.mark.parametrize("argv, expected", [
    ([], ["fan out alpha", "drain False"]),
    (["--provider-requests"], ["drain True"]),
])
def test_the_provider_drainer_fans_nothing_out_and_the_pass_drains_after_its_fan_out(
        monkeypatch, argv, expected):
    order = []
    monkeypatch.setattr(pass_, "connect", lambda args: Connection([[(1, "alpha", True)]]))
    monkeypatch.setattr(pass_, "fan_out",
                        lambda conn, domain, args: order.append(f"fan out {domain.label}"))
    monkeypatch.setattr(requests, "drain", lambda conn, context, provider, budget=None,
                        reconnect=None: order.append(f"drain {provider}") or (0, 0))
    assert pass_.main(argv) == 0
    assert order == expected


def archived(root, folder, uids):
    """Archive files of `alpha` in one folder, by UID; returns {uid: storage id}."""
    box = store.maildir(store.archive_home("alpha", root), folder)
    for part in ("cur", "new", "tmp"):
        (box / part).mkdir(parents=True, exist_ok=True)
    ids = {}
    for uid in uids:
        ids[uid] = f"17000000{uid:02d}.M{uid}P1.host"
        (box / "cur" / f"{ids[uid]}:2,").write_text(f"message {uid}")
    return ids


def test_a_connect_finds_each_file_by_its_base_name_in_its_own_folder_and_never_asks_dovecot(
        tmp_path, monkeypatch):
    """A year of one domain is tens of thousands of messages: a lookup each was two
    doveadm processes a message, and a lookup a batch one reading of the folder's whole
    uidlist. The base name on the row names the file in the folder its state says."""
    context = context_of(tmp_path)
    inbox = archived(context.store_root, requests.INBOX, [3, 4, 9])
    held = archived(context.store_root, store.QUARANTINE, [2])
    for name in ("fetch", "run", "storage_id", "message_file"):
        monkeypatch.setattr(requests.doveadm, name, lambda *a, **k: pytest.fail("Dovecot asked"))
    maildir(context.store_root, "alpha", "ivan")
    rows = [(11, inbox[3], "delivered"), (12, inbox[4], "delivered"), (13, held[2], "released"),
            (14, inbox[9], "delivered")]
    as_of = datetime.datetime(2026, 9, 1)
    cursor = Cursor([(5, "ivan", "alpha", as_of, 1), None, rows])
    answer = requests.connect(cursor, request_of(payload={"mailbox_id": 5}), context)
    assert answer == "connected 4 message(s) to ivan@alpha"
    names = sorted(p.name for p in (store.maildir(store.home("alpha", "ivan", context.store_root))
                                    / "new").iterdir())
    assert names == sorted([*inbox.values(), held[2]])
    links = [params for statement, params in cursor.statements
             if statement == " ".join(ledger.LINK.split())]
    assert links == [(11, 5), (12, 5), (13, 5), (14, 5)]
    # a released message's base name is not looked for in INBOX
    cursor = Cursor([(6, "olga", "alpha", as_of, 1), None, [(15, held[2], "delivered")]])
    maildir(context.store_root, "alpha", "olga")
    with pytest.raises(requests.RequestFailed, match=f"{held[2]} is not in archive@alpha's INBOX"):
        requests.connect(cursor, request_of(payload={"mailbox_id": 6}), context)


def test_a_file_renamed_after_the_batch_found_it_is_looked_for_again(tmp_path, monkeypatch):
    context = context_of(tmp_path)
    inbox = archived(context.store_root, requests.INBOX, [3])
    folder = store.maildir(store.archive_home("alpha", context.store_root))
    # a flag set in between: the name the batch found is gone
    os.rename(folder / "cur" / f"{inbox[3]}:2,", folder / "cur" / f"{inbox[3]}:2,S")
    monkeypatch.setattr(requests, "archive_files",
                        lambda *a: {inbox[3]: folder / "cur" / f"{inbox[3]}:2,"})
    maildir(context.store_root, "alpha", "ivan")
    cursor = Cursor([(5, "ivan", "alpha", datetime.datetime(2026, 9, 1), 1),
                     None, [(11, inbox[3], "delivered")]])
    requests.connect(cursor, request_of(payload={"mailbox_id": 5}), context)
    assert (store.maildir(store.home("alpha", "ivan", context.store_root)) / "new"
            / inbox[3]).exists()


def test_a_base_name_with_no_file_is_left_out_of_a_batch_and_never_breaks_the_folder(tmp_path):
    context = context_of(tmp_path)
    inbox = archived(context.store_root, requests.INBOX, [3])
    assert requests.archive_files("alpha", requests.INBOX, [inbox[3], "1700000099.M99P1.host"],
                                  context.store_root) == {
        inbox[3]: store.maildir(store.archive_home("alpha", context.store_root)) / "cur" / f"{inbox[3]}:2,"}


def test_a_batch_of_consecutive_numbers_is_one_asking_of_dovecot_however_many_they_are():
    """What is left of asking Dovecot by UID, the pass's renumbering (`0100`): a run of
    numbers is one set."""
    assert requests.doveadm.uid_sets(range(20_001, 30_001)) == ["20001:30000"]
    # numbers already given leave holes: still one set, its runs joined
    assert requests.doveadm.uid_sets([7, 3, 4, 5, 9, 10, 4]) == ["3:5,7,9:10"]
    assert requests.doveadm.uid_sets([]) == []


def test_scattered_numbers_are_split_at_the_bound_and_every_one_is_named_once(monkeypatch):
    monkeypatch.setattr(requests.doveadm, "UID_SET_BYTES", 64)
    uids = [*range(1, 400, 2), *range(1_000_000, 1_000_050), 2_000_000]
    sets = requests.doveadm.uid_sets(uids)
    assert len(sets) > 1 and all(len(each) <= 64 for each in sets)
    assert [uid for each in sets for uid in named(each)] == sorted(uids)
    # one number longer than the bound is still asked for, alone
    monkeypatch.setattr(requests.doveadm, "UID_SET_BYTES", 3)
    assert requests.doveadm.uid_sets([10_000, 10_001, 20_000]) == ["10000:10001", "20000"]


# --- a top-up names imported mail as old mail -------------------------------------------

HASH = "{SHA512-CRYPT}$6$x$" + "x" * 86


def imported_files(root, seen):
    """Imported archive files of `alpha`'s INBOX, by UID: {uid: storage id}; `seen` names
    the UIDs whose archive name is seen."""
    box = store.maildir(store.archive_home("alpha", root))
    for part in ("cur", "new", "tmp"):
        (box / part).mkdir(parents=True, exist_ok=True)
    ids = {}
    for uid in seen:
        digest = f"{uid:064x}"
        ids[uid] = store.import_base(1458000000 + uid, digest, 100 + uid, 100 + uid)
        (box / "cur" / f"{ids[uid]}:2,{'S' if seen[uid] else ''}").write_text(f"imported {uid}")
    return ids


def subscribing(monkeypatch, root, refused=False):
    """`doveadm mailbox create -s` for a person: the folder's maildir, and each call
    recorded; `refused` answers as Dovecot does for a login its userdb does not hold."""
    asked = []

    def subscribed_folder(login, folder):
        asked.append((login, folder))
        if refused:
            raise requests.doveadm.DoveadmError("doveadm mailbox create -u ivan@alpha exited 67: "
                                                "User doesn't exist", 67)
        account, _, label = login.partition("@")
        box = store.maildir(store.home(label, account, root), folder)
        for part in ("cur", "new", "tmp"):
            (box / part).mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(requests.doveadm, "subscribed_folder", subscribed_folder)
    return asked


def test_a_top_up_names_imported_mail_seen_or_unseen_in_its_year_folder_and_collected_mail_in_new(
        tmp_path, monkeypatch):
    context = context_of(tmp_path)._replace(folders=set())
    live = archived(context.store_root, requests.INBOX, [3])
    old = imported_files(context.store_root, {1: True, 2: False})
    ids = {**live, **old}
    asked = subscribing(monkeypatch, context.store_root)
    maildir(context.store_root, "alpha", "ivan")
    rows = [(11, ids[1], "delivered"), (12, ids[2], "delivered"), (13, ids[3], "delivered")]
    cursor = Cursor([(5, "ivan", "alpha", datetime.datetime(2026, 9, 1), 1), rows])
    answer = requests.top_up(cursor, request_of(kind="top_up", payload={
        "mailbox_id": 5, "since": "2016-01-01", "until": "9999-12-31"}), context)
    assert answer.startswith("topped up 3 message(s) to ivan@alpha")
    home = store.home("alpha", "ivan", context.store_root)
    year = store.maildir(home, "Archives/2016")
    assert sorted(p.name for p in (year / "cur").iterdir()) == sorted([f"{old[1]}:2,S", f"{old[2]}:2,"])
    box = store.maildir(home)
    assert list((box / "cur").iterdir()) == []   # nothing of the history in INBOX
    assert [p.name for p in (box / "new").iterdir()] == [live[3]]
    # the parent and the year, made and subscribed through Dovecot once for both messages
    assert asked == [("ivan@alpha", "Archives"), ("ivan@alpha", "Archives/2016")]
    # one file each, a second name for it: never a copy
    archive = store.maildir(store.archive_home("alpha", context.store_root))
    assert (archive / "cur" / f"{old[1]}:2,S").stat().st_nlink == 2
    links = [params for statement, params in cursor.statements
             if statement == " ".join(ledger.LINK.split())]
    assert links == [(11, 5), (12, 5), (13, 5)]


def test_imported_mail_of_two_years_goes_into_two_folders_by_the_utc_year_of_its_name(
        tmp_path, monkeypatch):
    context = context_of(tmp_path)._replace(folders=set())
    asked = subscribing(monkeypatch, context.store_root)
    mailbox = requests.Mailbox(5, "ivan", "alpha", None, 1)
    for epoch in (1577836799, 1577836800):   # the last second of 2019 and the first of 2020
        source = tmp_path / f"{store.import_base(epoch, f'{epoch:064x}', 4, 4)}:2,S"
        source.write_text("old!")
        for _ in range(2):   # named again, as a second top-up or a deliver-one would: the same name
            requests.name_in(source, mailbox, context)
    home = store.home("alpha", "ivan", context.store_root)
    for year, epoch in (("2019", 1577836799), ("2020", 1577836800)):
        names = [p.name for p in (store.maildir(home, f"Archives/{year}") / "cur").iterdir()]
        assert [store.imported(store.base_name(n)) for n in names] == [epoch]
    assert asked == [("ivan@alpha", "Archives"), ("ivan@alpha", "Archives/2019"),
                     ("ivan@alpha", "Archives/2020")]


def test_a_top_up_dovecot_cannot_make_the_folders_for_fails_saying_so_and_names_no_history(
        tmp_path, monkeypatch):
    """A blocked person: Dovecot's userdb holds active accounts alone."""
    context = context_of(tmp_path)._replace(folders=set(), made=[])
    live = archived(context.store_root, requests.INBOX, [3])
    old = imported_files(context.store_root, {1: True})
    ids = {**live, **old}
    subscribing(monkeypatch, context.store_root, refused=True)
    maildir(context.store_root, "alpha", "ivan")
    cursor = Cursor([(5, "ivan", "alpha", datetime.datetime(2026, 9, 1), 1),
                     [(13, ids[3], "delivered"), (11, ids[1], "delivered")]])
    with pytest.raises(requests.RequestFailed, match="Archives could not be made and subscribed.*"
                                                     "unblock them and ask again"):
        requests.top_up(cursor, request_of(kind="top_up", payload={
            "mailbox_id": 5, "since": "2016-01-01", "until": "9999-12-31"}), context)
    # the live name before it is the drain's to take back, as any failure's; no history named
    assert [p.name for p in context.made] == [live[3]]
    assert not store.maildir(store.home("alpha", "ivan", context.store_root), "Archives/2016").exists()
    assert not [s for s, _ in cursor.statements if s == " ".join(ledger.LINK.split())]


def test_a_deliver_one_puts_an_imported_message_back_into_its_year_folder(tmp_path, monkeypatch):
    context = context_of(tmp_path)
    old = imported_files(context.store_root, {1: True})
    subscribing(monkeypatch, context.store_root)
    cursor = Cursor([(5, "ivan", "alpha", datetime.datetime(2026, 9, 1), 1),
                     (11, old[1], "delivered", 1, 1)])
    requests.deliver_one(cursor, request_of(kind="deliver_one", payload={
        "mailbox_id": 5, "message_id": 11}), context)
    year = store.maildir(store.home("alpha", "ivan", context.store_root), "Archives/2016")
    assert [p.name for p in (year / "cur").iterdir()] == [f"{old[1]}:2,S"]


def test_only_an_imported_messages_own_name_is_named_as_old_mail(tmp_path):
    source = tmp_path / "1458000000.M1P2.host.import,S=12,W=13:2,S"   # `.import` in a live name
    source.write_text("live")
    with pytest.raises(store.StoreError):
        store.link_imported(source, [tmp_path / "box"], tmp_path)
    imported = tmp_path / f"{store.import_base(1458000000, 'a' * 64, 4, 4)}:2,S"
    imported.write_text("old!")
    made = []
    for part in ("cur", "new", "tmp"):
        (tmp_path / "box" / "Maildir" / part).mkdir(parents=True)
    for _ in range(2):   # EEXIST is success, and only the first made it
        store.link_imported(imported, [tmp_path / "box" / "Maildir"], tmp_path, made=made)
    assert [p.name for p in made] == [imported.name]


def test_a_live_name_that_holds_import_is_new_mail_in_inbox(tmp_path, monkeypatch):
    context = context_of(tmp_path)
    asked = subscribing(monkeypatch, context.store_root)
    source = tmp_path / "1458000000.M1P2.host.import,S=12,W=13:2,S"
    source.write_text("live")
    maildir(context.store_root, "alpha", "ivan")
    requests.name_in(source, requests.Mailbox(5, "ivan", "alpha", None, 1), context)
    box = store.maildir(store.home("alpha", "ivan", context.store_root))
    assert [p.name for p in (box / "new").iterdir()] == [source.name.partition(":")[0]]
    assert asked == []


def test_a_failed_top_up_takes_back_an_imported_name_the_person_flagged_meanwhile(
        tmp_path, monkeypatch):
    archive = tmp_path / "archive"
    archive.mkdir()
    source = archive / f"{store.import_base(1458000000, 'b' * 64, 9, 9)}:2,S"
    source.write_text("old mail")
    box = store.maildir(tmp_path / "ivan")
    for part in ("cur", "new", "tmp"):
        (box / part).mkdir(parents=True)
    conn = Connection()
    queued(conn, (7, "top_up", "ivan@alpha", {"mailbox_id": 1}, "olga", False))

    def half_way(cur, request, context):
        store.link_imported(source, [box], tmp_path, made=context.made)
        # ivan flags it in between: his name is the same base with other flags
        base = store.base_name(source)
        os.rename(box / "cur" / f"{base}:2,S", box / "cur" / f"{base}:2,FS")
        raise requests.RequestFailed("the next message could not be linked")

    monkeypatch.setitem(requests.HANDLERS, "top_up", half_way)
    assert requests.drain(conn) == (0, 1)
    assert list((box / "cur").iterdir()) == [] and source.stat().st_nlink == 1
    assert outcome(conn) == ("failed", "the next message could not be linked", 7)


def scene(database):
    """`alpha` with ivan's mailbox, made now: its rows as the pass and the import wrote them."""
    domain = database.value("INSERT INTO domain (label, archive_password_hash) VALUES "
                            "('alpha', %s) RETURNING id", (HASH,))
    database.sql("INSERT INTO account (login, password_hash) VALUES ('ivan', %s)", (HASH,))
    mailbox = database.value("INSERT INTO mailbox (account_id, domain_id) SELECT id, %s FROM "
                             "account WHERE login = 'ivan' RETURNING id", (domain,))
    for uid, received in ((1, "2016-03-15"), (2, "2019-07-01"), (3, "2024-01-05")):
        database.sql("INSERT INTO message (domain_id, archive_uid, archive_base, received_at, "
                     "imported_at) VALUES (%s, %s, %s, %s, clock_timestamp())",
                     (domain, uid, f"base{uid}", received))
    database.sql("INSERT INTO message (domain_id, archive_uid, archive_base) VALUES (%s, 4, 'base4')",
                 (domain,))
    return domain, mailbox


def test_a_top_ups_count_is_what_it_links_and_takes_imported_history_by_its_old_date(database):
    domain, mailbox = scene(database)
    conn = database.connect("pipeline")
    try:
        with conn.cursor() as cur:
            for since, until, uids in (("2016-01-01", "2019-12-31", [1, 2]),
                                       ("2016-03-15", "2016-03-15", [1]),
                                       ("2000-01-01", requests.WIDE_UNTIL, [1, 2, 3, 4])):
                selected = requests.select_for(cur, mailbox, domain, since, until)
                assert [row[1] for row in selected] == [f"base{uid}" for uid in uids], (since, until)
                assert requests.count_for(cur, mailbox, domain, since, until) == len(uids)
    finally:
        conn.close()


def test_a_connect_reaches_no_imported_row_older_than_the_mailbox(database):
    domain, mailbox = scene(database)
    as_of = database.value("SELECT as_of FROM mailbox WHERE id = %s", (mailbox,))
    conn = database.connect("pipeline")
    try:
        with conn.cursor() as cur:
            rows = requests.select_for(cur, mailbox, domain, as_of, requests.WIDE_UNTIL)
    finally:
        conn.close()
    assert [row[1] for row in rows] == ["base4"]   # collected after the mailbox: the control



# --- a top-up and a connect link in batches ---------------------------------------------


def test_a_batch_is_its_names_then_their_directories_fsync_then_its_rows(tmp_path, monkeypatch):
    context = context_of(tmp_path)
    ids = archived(context.store_root, requests.INBOX, [3, 4, 9])
    box = maildir(context.store_root, "alpha", "ivan")
    cursor = Cursor()
    order = []
    monkeypatch.setattr(requests.store, "fsync_dirs", lambda directories: order.append(
        (sorted(str(d) for d in directories), len(list((box / "new").iterdir())),
         [s for s, _ in cursor.statements if s.startswith("INSERT")])))
    requests.link_messages(cursor, [(11, ids[3], "delivered"), (12, ids[4], "delivered"),
                                    (13, ids[9], "delivered")],
                           requests.Mailbox(5, "ivan", "alpha", None, 1), context)
    # one fsync of the one directory, with every name made and no row written yet
    assert order == [([str(box / "new")], 3, [])]
    assert [params for statement, params in cursor.statements
            if statement == " ".join(ledger.LINK.split())] == [(11, 5), (12, 5), (13, 5)]


def test_a_top_up_commits_each_batch_as_it_goes_with_its_count_on_the_request(bulk, monkeypatch):
    world = bulk(5)
    asked = world.ask()
    link, seen, pages = requests.link_messages, [], []

    def watched(cur, rows, mailbox, context):
        # what another connection reads when a batch starts: only what is committed
        seen.append((world.rows(), *world.request(asked)[:2]))
        pages.append(len(rows))
        return link(cur, rows, mailbox, context)

    monkeypatch.setattr(requests, "link_messages", watched)
    assert world.drain() == (1, 0)
    assert seen == [(0, "running", None), (2, "running", "2 message(s) linked so far"),
                    (4, "running", "4 message(s) linked so far")]
    # never more than a batch selected, and Dovecot never asked (`0100`)
    assert pages == [2, 2, 1] and world.fetched == []
    state, result, payload = world.request(asked)
    assert (state, result) == ("done", "topped up 5 message(s) to ivan@alpha, 2000-01-01 "
                                       "to 2030-12-31")
    assert payload["linked"] == 4 and payload["committed"] is True
    assert world.rows() == 5 and world.names() == world.given(range(1, 6))
    # one journal row, the pipeline's, naming the whole count
    assert world.database.sql("SELECT detail ->> 'messages' FROM audit WHERE request_id = %s",
                              (asked,)) == [("5",)]


def test_a_connect_links_in_batches_too_and_still_starts_where_the_mailbox_does(bulk):
    world = bulk(5, received=None)   # archived after the mailbox was made
    world.database.sql("INSERT INTO message (domain_id, archive_uid, received_at) "
                       "VALUES (%s, 99, '2020-01-01')", (world.domain,))
    asked = world.ask("connect")
    assert world.drain() == (1, 0)
    assert world.request(asked)[:2] == ("done", "connected 5 message(s) to ivan@alpha")
    assert world.request(asked)[2]["linked"] == 4   # two batches committed before the last
    assert world.rows() == 5 and world.names() == world.given(range(1, 6))


def test_a_budget_spent_between_two_batches_puts_the_request_back_in_its_place(
        bulk, monkeypatch, capsys):
    """A top-up of hundreds of thousands of messages held every domain's fan-out for its
    whole length (measured). It now holds it for the budget and one batch: it goes back in
    the queue, and the next run fans out before taking it up again, first."""
    world = bulk(7)
    first, second = world.ask(), world.ask()
    asked_at = world.database.value("SELECT created_at FROM request WHERE id = %s", (first,))
    now = [0.0]
    world.each_name(monkeypatch, lambda made: now.__setitem__(0, now[0] + 30))

    assert world.drain(budget=100, clock=lambda: now[0]) == (0, 0)
    assert f"request {first} (top_up) goes on in the next run" in capsys.readouterr().err
    state, result, payload = world.request(first)
    assert (state, result, payload["linked"]) == ("queued", "4 message(s) linked so far", 4)
    assert world.rows() == 4 and world.names() == world.given([1, 2, 3, 4])
    assert world.database.value("SELECT created_at FROM request WHERE id = %s",
                                (first,)) == asked_at
    assert world.request(second)[:2] == ("queued", None), "the drain went on past its budget"

    # the next run does not take it for a stopped run's, and takes it up before the other
    assert world.drain() == (2, 0)
    assert world.request(first)[:2] == ("done", "topped up 7 message(s) to ivan@alpha, "
                                                "2000-01-01 to 2030-12-31")
    assert world.request(second)[1].startswith("topped up 0 message(s)")
    assert world.database.value("SELECT (SELECT finished_at FROM request WHERE id = %s) <= "
                                "(SELECT finished_at FROM request WHERE id = %s)",
                                (first, second))
    # nothing linked twice: a row and a name each, and the archive's file has two names
    assert world.rows() == 7 and world.names() == world.given(range(1, 8))
    archive = store.maildir(store.archive_home("alpha", world.context.store_root)) / "cur"
    assert {path.stat().st_nlink for path in archive.iterdir()} == {2}


def test_the_count_a_screen_states_is_what_the_batches_link_in_all(bulk, monkeypatch):
    world = bulk(9, batch=3)
    # what the selector leaves out: outside the range, withheld, and spam the domain keeps back
    world.database.sql("UPDATE message SET received_at = '2019-06-01' WHERE archive_uid = 1")
    world.database.sql("UPDATE message SET state = 'withheld' WHERE archive_uid = 5")
    world.database.sql("UPDATE message SET is_spam = true WHERE archive_uid = 9")
    world.database.sql("UPDATE domain SET spam_reaches_people = false")
    with postgres.Closing(world.database.connect("admin")) as screen, screen.cursor() as cur:
        stated = requests.count_for(cur, world.mailbox, world.domain, "2020-01-01",
                                    "2020-01-01")
    assert stated == 6
    asked = world.ask(since="2020-01-01", until="2020-01-01")
    now = [0.0]
    world.each_name(monkeypatch, lambda made: now.__setitem__(0, now[0] + 40))
    runs = 0
    while world.request(asked)[0] == "queued":
        world.drain(budget=100, clock=lambda: now[0])
        now[0], runs = 0.0, runs + 1
    assert runs == 2   # a batch and the budget, then the batch that is left
    assert world.request(asked)[1].startswith(f"topped up {stated} message(s)")
    assert world.rows() == stated and world.names() == world.given([2, 3, 4, 6, 7, 8])


def test_a_failure_takes_back_the_batch_under_way_and_nothing_a_commit_accounts_for(
        bulk, monkeypatch):
    world = bulk(7)
    asked = world.ask()

    def fail(made):
        if made == 6:
            raise OSError("No space left on device")

    world.each_name(monkeypatch, fail)
    assert world.drain() == (0, 1)
    # batches one and two stay, a row and a name each; the fifth name went with its batch
    assert world.rows() == 4 and world.names() == world.given([1, 2, 3, 4])
    state, result, payload = world.request(asked)
    assert state == "failed" and payload["linked"] == 4
    assert result == ("OSError: No space left on device; 4 message(s) were linked before it "
                      "and stay: asking again goes on from there")
    # asked again, it goes on from there
    monkeypatch.setattr(requests, "link_name", requests.link_name.__closure__[0].cell_contents)
    again = world.ask()
    assert world.drain() == (1, 0)
    assert world.request(again)[1].startswith("topped up 3 message(s)")
    assert world.rows() == 7 and world.names() == world.given(range(1, 8))


def test_a_request_waiting_between_two_runs_still_refuses_a_second_asking_and_shows_its_count(
        bulk, monkeypatch):
    world = bulk(5)
    asked = world.ask()
    world.database.sql("INSERT INTO audit (actor, action, target, request_id) VALUES "
                       "('olga', 'top_up', 'ivan@alpha', %s)", (asked,))
    assert world.drain(budget=1, clock=iter([0, 0, 1]).__next__) == (0, 0)
    assert world.request(asked)[:2] == ("queued", "2 message(s) linked so far")
    olga = types.SimpleNamespace(login="olga", break_glass=False)
    with postgres.Closing(world.database.connect("admin")) as screen:
        # the guard every once-only act goes through reads it as one still owed
        assert common.ask_once(screen, "top_up", "ivan@alpha", {}, olga) is None
        # the mailbox's row still says it waits, which hides its buttons
        assert common.queue_reading("top_up", *world.request(asked)[:1], None,
                                    world.request(asked)[1])["waiting"] == "asked to top up"
        # and the journal shows the count beside the request's state
        (row,) = common.rows(screen, journal.SELECT, (None, None, "ivan@alpha", None, None, 10))
    assert (row["request_state"], row["request_result"]) == ("queued",
                                                             "2 message(s) linked so far")


@pytest.mark.parametrize("batch, kept", [(10_000, 0), (2, 2)])
def test_a_connection_that_dies_under_the_handler_still_takes_the_names_back(
        bulk, monkeypatch, batch, kept):
    """PostgreSQL restarted in the middle of a top-up: the rollback raised on the dead
    connection, the names the request had made were never reached and had no row for good
    (measured: 14,310 of them), and the request stayed running."""
    world = bulk(5, batch=batch)
    asked, other = world.ask(), world.ask()
    world.dies_after(monkeypatch, names=3)
    assert world.drain() == (0, 1)
    assert world.rows() == kept and world.names() == world.given(range(1, kept + 1))
    state, result, _ = world.request(asked)
    assert state == "failed" and "OperationalError" in result
    assert ("2 message(s) were linked before it and stay" in result) == bool(kept)
    # the outcome was written on a second connection, and the drain ended there
    assert world.request(other)[0] == "queued"


@pytest.mark.parametrize("lost, state, rows, said", [
    # a batch's commit: there, so its names stay and it counts; not there, so they go
    ((4, True), "failed", 4, "4 message(s) were linked before it and stay"),
    ((4, False), "failed", 2, "2 message(s) were linked before it and stay"),
    # the last commit, with the journal row: there, and the request is simply done
    ((5, True), "done", 5, "topped up 5 message(s)"),
    ((5, False), "failed", 4, "4 message(s) were linked before it and stay"),
])
def test_a_commit_that_raised_is_read_off_the_row_before_any_name_is_touched(
        bulk, lost, state, rows, said):
    """A connection that dies inside COMMIT may have committed. Taking the names back then
    leaves linked rows with no name, which no top-up restores and nothing reports."""
    world = bulk(5)
    asked = world.ask()
    # the commits of one run: the drainer's lock, the claim, batch one, batch two, the last
    done = world.drain(lost=lost)
    assert done == ((1, 0) if state == "done" else (0, 1))
    assert world.rows() == rows and world.names() == world.given(range(1, rows + 1))
    assert world.request(asked)[0] == state and said in world.request(asked)[1]


@pytest.mark.parametrize("landed, rows", [(True, 4), (False, 2)])
def test_a_commit_nobody_can_read_back_takes_no_name_and_the_next_run_fails_the_request(
        bulk, capsys, landed, rows):
    """The database is not back yet: what is not known is not acted on. A name with no row
    is reported by health and healed by asking again; a row with no name is neither."""
    world = bulk(5)
    asked = world.ask()
    assert world.drain(lost=(4, landed), reconnect=False) == (0, 0)
    assert "no name was taken back" in capsys.readouterr().err
    assert world.rows() == rows and world.names() == world.given([1, 2, 3, 4])
    assert world.request(asked)[0] == "running"
    # the next run fails it as a stopped run's, keeping what its row said; asking again heals
    again = world.ask()
    assert world.drain() == (1, 0)
    assert world.request(asked)[:2] == ("failed", f"{requests.STOPPED}; it had said: "
                                                  f"{rows} message(s) linked so far")
    assert world.request(again)[1].startswith(f"topped up {5 - rows} message(s)")
    assert world.rows() == 5 and world.names() == world.given(range(1, 6))


def test_the_reading_of_a_commit_in_doubt_waits_for_its_transaction_to_end(bulk):
    """The transaction in doubt wrote the request's row, so it holds it: read `FOR UPDATE`,
    the row answers only once that transaction is there or gone, never in between."""
    world = bulk(1)
    asked = world.ask()
    doubt, reader = world.connect(), world.connect()
    with doubt.cursor() as cur:
        cur.execute(requests.PROGRESS, (requests.progress(4), 4, asked))
    ended = []
    late = threading.Timer(0.5, lambda: (ended.append(True), doubt.commit()))
    late.start()
    try:
        assert requests.said(reader, asked, "linked") == 4 and ended == [True]
    finally:
        late.join()
    assert requests.said(reader, asked, "committed") is None
    assert "FOR UPDATE" in requests.SAID
