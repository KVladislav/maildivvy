"""The runner's own refusals, its queries and the credential helper, without a database.

The parts that need real rows, a real mpop and a real provider are driven on the test
VM. What is tested here is what is true of the text:
which columns the two queries select, what the command line refuses, and what the
credential helper writes on which stream.
"""

import contextlib
import datetime
import io
import json
import os
import signal
import time
from pathlib import Path

import pytest

from maildivvy.fetch import credential, locks, outcome, render, runner
from maildivvy.lib import config, retrieval


class Cursor:
    """A stand-in psycopg cursor: records statements, answers with a scripted row."""

    def __init__(self, answers=()):
        self.statements = []
        self.answers = list(answers)

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


ROW = (7, None, "Ivan.P@example.org", "pop.example.org", 995, "alpha", 14,
       "ivan.p@example.org", 8.00, None, False, None, "pop3", None, None)


# --- the two queries ---------------------------------------------------------


def test_both_queries_select_the_same_columns_in_the_mailboxs_own_order():
    assert runner.TO_FETCH.startswith(runner.COLUMNS)
    assert runner.TO_TEST.startswith(runner.COLUMNS)
    selected = runner.COLUMNS.split("SELECT")[1].split("FROM")[0]
    names = [part.strip().split(".")[1] for part in selected.split(",")]
    assert names == ["id", "pop3_login", "address", "pop3_host", "pop3_port", "label",
                     "delete_window_days", "address_canonical", "spam_threshold", "held_since",
                     "keep_at_provider", "pop3_cert_fingerprint", "protocol",
                     "imap_uidvalidity", "imap_last_uid"]
    assert len(names) == len(render.Mailbox._fields)


def test_the_domains_threshold_is_selected_with_the_row_and_not_by_a_second_query():
    assert "spam_threshold" in runner.COLUMNS
    assert runner.COLUMNS.count("SELECT") == 1
    assert "spam_threshold" not in runner.TO_FETCH.replace(runner.COLUMNS, "")


def test_the_password_check_selects_by_id_with_no_state_predicate():
    predicate = runner.TO_TEST.replace(runner.COLUMNS, "")
    assert "e.id = %s" in predicate
    assert "state" not in predicate


def test_the_fetch_selects_only_mapped_and_not_deactivated_rows():
    predicate = runner.TO_FETCH.replace(runner.COLUMNS, "")
    assert "e.state <> 'deactivated'" in predicate
    assert "JOIN domain d ON d.external_mailbox_id = e.id" in " ".join(runner.COLUMNS.split())


def test_a_row_becomes_a_mailbox_by_position_and_a_short_row_raises():
    """A row the query selected is held to the whole width, so a lost column never shifts
    the ones after it (here the last, and one in the middle)."""
    cur = Cursor([[ROW]])
    assert runner.rows_to_fetch(cur) == [render.Mailbox(*ROW)]
    for short in (ROW[:-1], ROW[:9] + ROW[10:]):
        with pytest.raises(TypeError):
            runner.row_to_test(Cursor([short]), 7)
        with pytest.raises(TypeError):
            runner.rows_to_fetch(Cursor([[short]]))


def test_an_unknown_id_has_no_row_to_test():
    assert runner.row_to_test(Cursor([None]), 99) is None


class Conn:
    """One scripted cursor for every `conn.cursor()` the runner opens."""

    def __init__(self, cursor):
        self.cur = cursor

    def cursor(self):
        return self.cur


def test_a_mailbox_deactivated_after_the_listing_is_not_fetched_once_more(monkeypatch, tmp_path):
    """The run lists its rows at its start; a Disable that lands before a mailbox's lock
    is taken must stop that mailbox's fetch, provider-side deletions included. The re-read
    under the lock carries the listing's own state predicate, so the database answers no
    row for it, and nothing is rendered, run or written."""
    monkeypatch.setattr(runner.render, "write_config", lambda *a: pytest.fail("rendered"))
    monkeypatch.setattr(runner, "run_mpop", lambda *a, **k: pytest.fail("mpop started"))
    # try-lock taken; the re-read finds no row the fetch collects; unlock.
    cur = Cursor([(True,), None, (True,)])
    args = runner.parse_args(["--state-dir", str(tmp_path)])
    assert runner.run_one(Conn(cur), render.Mailbox(*ROW), args) is None
    reread = cur.statements[1]
    assert reread == (" ".join(runner.TO_FETCH_ONE.split()), (7,))
    assert "e.state <> 'deactivated'" in reread[0]
    assert not any(sql.startswith("UPDATE") for sql, _ in cur.statements), "a status was written"


# --- the command line -------------------------------------------------------------


def test_a_password_check_without_a_named_mailbox_is_refused(capsys):
    assert runner.main(["--auth-only"]) == runner.EX_USAGE
    assert "needs --only" in capsys.readouterr().err


def test_the_refusal_happens_before_any_database_connection(monkeypatch):
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: pytest.fail("connected"))
    assert runner.main(["--auth-only"]) == runner.EX_USAGE


@pytest.mark.parametrize("argv", [["--start-mark"], ["--start-mark", "--only", "7"]])
def test_a_mark_is_never_set_by_a_run_of_collection_only_by_the_check(monkeypatch, capsys, argv):
    """`--start-mark` belongs to the check an activation runs; a collection asked for it is
    refused before anything is connected to, rather than the flag being dropped."""
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: pytest.fail("connected"))
    assert runner.main(argv) == runner.EX_USAGE
    assert "part of --auth-only" in capsys.readouterr().err
    assert runner.parse_args(["--auth-only", "--only", "7"]).start_mark is False


# --- the snapshot's slices ------------------------------------------------------------

SNAPSHOT_ROW = ROW[:12] + ("imap", 4242, 9)


@pytest.mark.parametrize("argv", [["--snapshot", "--auth-only", "--only", "7"],
                                  ["--snapshot", "--trace"]])
def test_a_slice_checks_no_password_and_keeps_no_trace(monkeypatch, capsys, argv):
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: pytest.fail("connected"))
    assert runner.main(argv) == runner.EX_USAGE
    assert "--snapshot takes a snapshot's slice and nothing else" in capsys.readouterr().err


def test_a_slice_lasts_ten_minutes_unless_told_and_never_no_time_at_all(capsys):
    assert runner.parse_args(["--snapshot"]).slice_seconds == 600
    assert runner.parse_args(["--snapshot", "--slice-seconds", "5"]).slice_seconds == 5
    for refused in ("0", "-3", "1.5"):
        with pytest.raises(SystemExit):
            runner.parse_args(["--snapshot", "--slice-seconds", refused])


def test_the_snapshots_rows_are_active_imap_rows_with_a_snapshot_under_way_or_asked_for():
    for query in (runner.TO_SNAPSHOT, runner.TO_SNAPSHOT_ONE):
        assert query.startswith(runner.COLUMNS)
        predicate = " ".join(query.replace(runner.COLUMNS, "").split())
        assert "e.state <> 'deactivated'" in predicate and "e.protocol = 'imap'" in predicate
        assert "snapshot_status IN ('pending', 'running', 'paused')" in predicate
        assert ("snapshot_status IS NULL AND e.snapshot_requested_at > "
                "coalesce(e.snapshot_finished_at, '-infinity')") in predicate
    assert runner.TO_SNAPSHOT_ONE.endswith("AND e.id = %s")


def test_a_slice_takes_the_snapshots_own_lock_and_reads_its_row_again_under_it(monkeypatch):
    """Never the fetch's lock, so a slice holds up no collection; a row that no longer wants
    a snapshot (deleted, discarded, deactivated) is left, and nothing of it is written."""
    monkeypatch.setattr(runner.snapshot, "take", lambda *a: pytest.fail("a slice was taken"))
    cur = Cursor([(True,), None, (True,)])
    args = runner.parse_args(["--snapshot"])
    assert runner.snapshot_one(Conn(cur), 7, args) is None
    assert cur.statements[0] == ("SELECT pg_try_advisory_lock(%s, %s)", (locks.SNAPSHOT, 7))
    assert cur.statements[1] == (" ".join(runner.TO_SNAPSHOT_ONE.split()), (7,))
    assert cur.statements[2] == ("SELECT pg_advisory_unlock(%s, %s)", (locks.SNAPSHOT, 7))
    assert locks.NAMESPACE not in {params[0] for _, params in cur.statements}

    taken = []
    monkeypatch.setattr(runner.snapshot, "take", lambda conn, mailbox, a: taken.append(mailbox)
                        or "pending")
    cur = Cursor([(True,), SNAPSHOT_ROW, (True,)])
    assert runner.snapshot_one(Conn(cur), 7, args) == "pending"
    assert taken == [render.Mailbox(*SNAPSHOT_ROW)]
    assert cur.statements[-1] == ("SELECT pg_advisory_unlock(%s, %s)", (locks.SNAPSHOT, 7))


def test_a_snapshot_whose_lock_is_held_is_skipped_and_never_waited_for(monkeypatch, capsys):
    monkeypatch.setattr(runner.snapshot, "take", lambda *a: pytest.fail("a slice was taken"))
    cur = Cursor([(False,)])
    assert runner.snapshot_one(Conn(cur), 7, runner.parse_args(["--snapshot"])) == runner.BUSY
    assert len(cur.statements) == 1 and "already running" in capsys.readouterr().err


@pytest.mark.parametrize("statuses, only, code", [
    (["pending", "paused", "done"], None, 0),   # paused is the next slice's to go on with
    (["done", "failed"], None, 1),              # a failed snapshot fails the run
    ([], None, 0),                              # nothing asked for is a success
    ([runner.BUSY], 7, runner.EX_TEMPFAIL),
    ([], 7, 1),                                 # --only naming a row with nothing to take
    (["paused"], 7, 0),
])
def test_a_run_of_slices_fails_only_when_a_snapshot_failed(monkeypatch, statuses, only, code):
    ids = list(range(7, 7 + len(statuses)))
    answers = dict(zip(ids, statuses))
    monkeypatch.setattr(runner, "snapshot_one", lambda conn, i, args: answers[i])
    cur = Cursor([[(i,) for i in ids]])
    argv = ["--snapshot"] + (["--only", str(only)] if only else [])
    assert runner.run_snapshots(Conn(cur), runner.parse_args(argv)) == code
    assert cur.statements == [(" ".join(runner.TO_SNAPSHOT.split()), None)]


def test_a_run_of_slices_takes_the_least_recently_advanced_first_and_none_past_its_bound(
        monkeypatch, capsys):
    """Each slice may take its whole time and the message in hand after it (GRACE). One that
    could end past SNAPSHOT_RUN_SECONDS is not started: systemd would stop it mid-slice at
    the unit's timeout. Left alone, its manifest is the oldest, so the next run takes it
    first."""
    clock = [0.0]
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock[0])
    advanced = {7: 300.0, 8: 0, 9: 200.0}       # 8 never advanced yet
    monkeypatch.setattr(runner.snapshot, "advanced_at", advanced.get)
    taken = []

    def one(conn, mailbox_id, args):
        taken.append(mailbox_id)
        clock[0] += args.slice_seconds + runner.snapshot.GRACE
        return "pending"

    monkeypatch.setattr(runner, "snapshot_one", one)
    args = runner.parse_args(["--snapshot", "--slice-seconds", "1500"])
    assert runner.run_snapshots(Conn(Cursor([[(7,), (8,), (9,)]])), args) == 0
    assert taken == [8, 9]          # 1,560 s each: a third would end at 4,680 s
    assert "external mailbox 7's snapshot - the next run takes it" in capsys.readouterr().err


def test_a_configuration_that_must_not_be_used_exits_seventyeight(monkeypatch, capsys):
    def refuse(*a, **k):
        raise config.ConfigError("db.conf is world-readable")

    monkeypatch.setattr(runner.db, "connect", refuse)
    assert runner.main([]) == runner.EX_CONFIG
    assert "world-readable" in capsys.readouterr().err


def test_the_runner_connects_as_the_pipeline_and_as_nothing_else():
    assert runner.CONSUMER == "pipeline" and credential.CONSUMER == "pipeline"


def test_the_default_timeout_and_stuck_hour_are_the_measured_ones():
    args = runner.parse_args([])
    assert args.timeout == 900 and args.stuck_after == 3600
    assert args.hold_bound_seconds == 3600  # the hold's bound, the filter's own default
    assert args.mpop == "/usr/local/bin/mpop"
    assert not args.trace


# --- zero mailboxes, and the exit code of a run -----------------


class Connection:
    def __init__(self, rows):
        self.cursor_ = Cursor([rows])
        self.closed = False

    def cursor(self):
        return self.cursor_

    def close(self):
        self.closed = True


def test_a_run_with_no_external_mailboxes_exits_zero_and_prints_nothing(monkeypatch, capsys):
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: Connection([]))
    assert runner.main([]) == 0
    printed = capsys.readouterr()
    assert printed.out == "" and printed.err == ""


@pytest.mark.parametrize("statuses, code", [
    ([], 0),
    (["ok"], 0),
    (["no_new_mail"], 0),
    ([runner.BUSY], 0),                # every mailbox was locked by another runner
    ([None], 0),                       # its row went while the run read the others
    (["ok", "error"], 1),
    (["ok", "auth_failed"], 1),        # counting only `error` survived every earlier test
    (["auth_failed", "no_new_mail"], 1),
])
def test_a_run_exits_non_zero_when_any_mailbox_failed(monkeypatch, statuses, code):
    rows = [(i, None, f"a{i}@x.test", "p.x.test", 995, "alpha", 14, f"a{i}@x.test", 8.00, None,
             False, None, "pop3", None, None)
            for i in range(len(statuses))]
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: Connection(rows))
    answers = iter(statuses)
    monkeypatch.setattr(runner, "run_one", lambda conn, mailbox, args: next(answers))
    assert runner.main([]) == code


def test_slow_mailboxes_are_all_collected_across_runs_the_least_recently_collected_first(
        monkeypatch, capsys):
    """Five mailboxes that each take 1,200 s: a run starts none that could end past its
    bound, and the next run starts with the ones left, as the query's order gives them,
    never at the lowest id again."""
    assert runner.TO_FETCH.endswith(" ORDER BY e.last_fetch_at NULLS FIRST, e.id")
    clock = [0.0]
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock[0])
    last = dict.fromkeys(range(1, 6))   # never collected
    taken = []

    def collect(conn, mailbox, args):
        clock[0] += 1200
        last[mailbox.id] = clock[0]
        taken.append(mailbox.id)
        return "ok"

    monkeypatch.setattr(runner, "run_one", collect)
    runs = []
    for _ in range(3):
        rows = [(i, None, f"a{i}@x.test", "p.x.test", 995, "alpha", 14, f"a{i}@x.test", 8.00,
                 None, False, None, "pop3", None, None)
                for i in sorted(last, key=lambda i: (last[i] is not None, last[i] or 0, i))]
        monkeypatch.setattr(runner.db, "connect", lambda *a, rows=rows, **k: Connection(rows))
        taken.clear()
        clock[0] += 60
        assert runner.main([]) == 0
        runs.append(list(taken))
    # 1,200 s, then 2,400 s: a third could end at 3,600 + 1,480 s, past the run's 3,300
    assert runs == [[1, 2], [3, 4], [5, 1]]
    assert "no time is left in this run for 3 mailbox(es)" in capsys.readouterr().err


def test_only_the_named_mailbox_is_fetched_with_only(monkeypatch):
    rows = [(i, None, f"a{i}@x.test", "p.x.test", 995, "alpha", 14, f"a{i}@x.test", 8.00, None,
             False, None, "pop3", None, None)
            for i in (1, 2, 3)]
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: Connection(rows))
    fetched = []
    monkeypatch.setattr(runner, "run_one",
                        lambda conn, mailbox, args: fetched.append(mailbox.id) or "ok")
    assert runner.main(["--only", "2"]) == 0
    assert fetched == [2]


def test_a_named_collection_that_found_its_lock_held_exits_with_a_code_of_its_own(monkeypatch):
    """A refetch reads this exit code: a run skipped on a held lock collected nothing,
    and exiting 0 had the request journal "collected". A timed run that skips a locked
    mailbox is still a success: another run is collecting it."""
    rows = [(i, None, f"a{i}@x.test", "p.x.test", 995, "alpha", 14, f"a{i}@x.test", 8.00, None,
             False, None, "pop3", None, None)
            for i in (1, 2)]
    monkeypatch.setattr(runner, "run_one", lambda conn, mailbox, args: runner.BUSY)
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: Connection(rows))
    assert runner.main(["--only", "2"]) == runner.EX_TEMPFAIL
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: Connection(rows))
    assert runner.main([]) == 0


@pytest.mark.parametrize("only, status", [("9", "ok"), ("2", None)])
def test_a_named_collection_that_ran_nothing_is_not_a_success(monkeypatch, capsys, only, status):
    """`--only` naming no row the fetch collects (deactivated, unmapped, deleted), or a
    row gone by the time its lock was taken, ran nothing: exit 0 would read as collected."""
    rows = [(i, None, f"a{i}@x.test", "p.x.test", 995, "alpha", 14, f"a{i}@x.test", 8.00, None,
             False, None, "pop3", None, None)
            for i in (1, 2)]
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: Connection(rows))
    monkeypatch.setattr(runner, "run_one", lambda conn, mailbox, args: status)
    assert runner.main(["--only", only]) == 1
    assert "nothing" in capsys.readouterr().err


# --- the lock namespace both sides share -------------------------------------


def test_the_fetch_takes_the_lock_with_try_lock_and_never_waits():
    cur = Cursor([(False,)])
    assert locks.try_lock(cur, 7) is False
    assert cur.statements == [("SELECT pg_try_advisory_lock(%s, %s)", (locks.NAMESPACE, 7))]


def test_the_namespace_is_named_once_so_the_two_locks_meet():
    package = Path(runner.__file__).parent
    spelling = [line for path in package.glob("*.py")
                for line in path.read_text().splitlines()
                if "advisory" in line and "%s" in line]
    assert all(str(locks.NAMESPACE) not in line and str(locks.SNAPSHOT) not in line
               for line in spelling)
    # try, transaction-level (a deletion and a discard), unlock - all in
    # locks.py, each taking the namespace it is given
    assert len(spelling) == 3
    assert all("(namespace, int(mailbox_id))" in line for line in spelling)


# --- the journal the runner writes -------------------------------------------


def test_the_journal_names_this_runner_the_canonical_address_and_no_row_id():
    cur = Cursor([])
    runner.audit(cur, "auto_skip_message", "ivan.p@example.org",
                 {"uidl": "abc", "stuck_runs": 3,
                  "skipped_at": datetime.datetime(2026, 9, 20, 6, 24)})
    sql, params = cur.statements[0]
    assert "INSERT INTO audit (actor, action, target, detail)" in sql
    assert "RETURNING" not in sql  # the pipeline has INSERT and no SELECT on the journal
    assert params[0] == runner.ACTOR == "maildivvy-fetch"
    assert params[2] == "ivan.p@example.org"
    assert params[3] == ('{"uidl": "abc", "stuck_runs": 3, '
                         '"skipped_at": "2026-09-20T06:24:00"}')


def test_the_deletion_date_is_the_skip_plus_the_window():
    skipped = datetime.datetime(2026, 9, 20, 6, 24)
    assert runner.deletion_date(skipped, 14) == datetime.datetime(2026, 10, 4, 6, 24)
    assert runner.deletion_date(skipped, None) is None  # no window, no day to name


def test_a_mailbox_kept_at_the_provider_names_no_deletion_date():
    skipped = datetime.datetime(2026, 9, 20, 6, 24)
    assert runner.deletion_date(skipped, 14, kept=True) is None


# --- the bounded retry of an IMAP mailbox ---------------------------------------------

# its mark is UID 2 under UIDVALIDITY 42, and the run stopped on UID 3
IMAP_ROW = (7, None, "Ivan.P@example.org", "imap.example.org", 993, "alpha", 14,
            "ivan.p@example.org", 8.00, None, True, None, render.IMAP, 42, 2)
SINCE = datetime.datetime(2026, 11, 17, 6, 0)
SKIPPED_AT = datetime.datetime(2026, 11, 17, 7, 0)
REFUSED_3 = outcome.Outcome(outcome.ERROR, outcome.STUCK_MESSAGE,
                            "message 3: the delivery filter exited 74", message_level=True,
                            retr_number=3, scanner_answered=True)
ENOUGH = runner.IMAP_STUCK_RUNS  # the runs stopped on one message under which nothing is skipped


def imap_retry(monkeypatch, tmp_path, cur, result):
    """The bounded retry on the IMAP row, with mpop's listing session and state file refused."""
    monkeypatch.setattr(runner, "stuck_identifier", lambda *a: pytest.fail("a listing session"))
    monkeypatch.setattr(runner.state_file, "record_skip", lambda *a: pytest.fail("a state file"))
    args = runner.parse_args(["--state-dir", str(tmp_path)])
    return runner.bounded_retry(Conn(cur), render.Mailbox(*IMAP_ROW), args, tmp_path / "7",
                                None, result)


def journaled(statement):
    sql, params = statement
    assert sql.startswith("INSERT INTO audit")
    return params[1], json.loads(params[3])


def test_an_imap_message_refused_for_the_stuck_period_is_skipped_once_past_the_mark(
        monkeypatch, tmp_path):
    """Inside the period a refusal is only counted. Past it, the mark moves past the UID the
    run stopped on, from the UIDVALIDITY the run started with, in one transaction with the
    skip's columns and its journal row; the episode ends there, so the message is skipped
    once. No listing session runs and no state file is written: the run named the UID."""
    counted = Cursor([(SINCE, 1, 0, None, False)])
    assert imap_retry(monkeypatch, tmp_path, counted, REFUSED_3) == outcome.ERROR
    [(sql, _)] = counted.statements
    assert "stuck_runs = stuck_runs + 1" in sql and "imap_last_uid" not in sql

    cur = Cursor([(SINCE, ENOUGH, 0, None, True), (SKIPPED_AT,)])
    assert imap_retry(monkeypatch, tmp_path, cur, REFUSED_3) == outcome.ERROR
    begin, (sql, params), journal, commit = cur.statements[1:]
    assert (begin, commit) == (("BEGIN", None), ("COMMIT", None))
    assert sql.startswith("UPDATE external_mailbox SET imap_last_uid = %s, last_skip_at = now()")
    assert "skip_streak = skip_streak + 1, stuck_since = NULL, stuck_runs = 0" in sql
    assert sql.endswith("AND imap_uidvalidity = %s AND imap_last_uid < %s RETURNING last_skip_at")
    assert params == (3, "42/3", 7, 42, 3)
    # the message stays at the provider: the journal names no deletion date
    assert journaled(journal) == ("auto_skip_message", {
        "uidl": "42/3", "stuck_since": "2026-11-17T06:00:00", "stuck_runs": ENOUGH,
        "skipped_at": "2026-11-17T07:00:00", "deletes_at": None})
    assert not any("last_listing_at" in sql for sql, _ in cur.statements)


def test_a_second_imap_episode_with_no_success_between_freezes_and_moves_no_mark(
        monkeypatch, tmp_path):
    cur = Cursor([(SINCE, ENOUGH, 1, None, True), (SKIPPED_AT,)])
    assert imap_retry(monkeypatch, tmp_path, cur, REFUSED_3) == outcome.ERROR
    sqls = [sql for sql, _ in cur.statements]
    assert sqls[1:3] == ["BEGIN", "UPDATE external_mailbox SET frozen_since = now() WHERE id = %s "
                                  "RETURNING frozen_since"]
    assert journaled(cur.statements[3])[0] == "fetch_frozen" and sqls[4:] == ["COMMIT"]
    assert not any("imap_last_uid" in sql for sql in sqls)
    # and a frozen mailbox skips nothing more, however long it stays stuck
    frozen = Cursor([(SINCE, 3, 1, SKIPPED_AT, True)])
    assert imap_retry(monkeypatch, tmp_path, frozen, REFUSED_3) == outcome.ERROR
    assert len(frozen.statements) == 1


@pytest.mark.parametrize("cause, hold", [
    (outcome.TRANSIENT, {"held": True}),                              # the antivirus hold
    (outcome.STORE, {"store_held": True, "scanner_answered": True}),  # the store's hold
])
def test_an_imap_hold_never_counts_toward_the_stuck_period(database, tmp_path, cause, hold):
    """The message waits above the mark, on the real row as the pipeline's role writes it: the
    run is recorded, an episode already running is paused (its start moves on by the time
    since the run before), and nothing is counted, skipped or journaled, though the episode
    began two hours ago and a refusal would have skipped the message."""
    rid = database.value(
        "INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host, "
        "protocol, keep_at_provider, state, imap_uidvalidity, imap_last_uid, stuck_since, "
        "stuck_runs, last_fetch_at) VALUES ('held@example.org', 'held@example.org', "
        "'imap.example.org', 'smtp.example.org', 'imap', true, 'active', 42, 2, "
        "now() - interval '2 hours', 3, now() - interval '10 minutes') RETURNING id")
    database.sql("INSERT INTO domain (label, archive_password_hash, external_mailbox_id) "
                 "VALUES ('held', '{SHA512-CRYPT}$6$salt$hash', %s)", (rid,))
    columns = ("stuck_since, stuck_runs, skip_streak, last_skip_uidl, imap_last_uid, "
               "last_fetch_status, last_fetch_cause")
    before = database.one(f"SELECT {columns} FROM external_mailbox WHERE id = %s", (rid,))
    conn = database.connect("pipeline")
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            mailbox = runner.row_to_test(cur, rid)
        result = outcome.Outcome(outcome.ERROR, cause, "message 3 held", **hold)
        args = runner.parse_args(["--state-dir", str(tmp_path)])
        assert runner.bounded_retry(conn, mailbox, args, tmp_path / str(rid), None,
                                    result) == outcome.ERROR
    finally:
        conn.close()
    after = database.one(f"SELECT {columns} FROM external_mailbox WHERE id = %s", (rid,))
    paused_by = after[0] - before[0]
    assert datetime.timedelta(minutes=9) < paused_by < datetime.timedelta(minutes=11)
    assert after[1:5] == before[1:5] == (3, 0, None, 2)
    assert after[5:] == (outcome.ERROR, cause)
    assert database.value("SELECT count(*) FROM audit") == 0


class Unwritable(Cursor):
    """The journal refuses its row."""

    def execute(self, sql, params=None):
        super().execute(sql, params)
        if sql.startswith("INSERT INTO audit"):
            raise RuntimeError("the journal refused the row")


def test_an_imap_skip_that_cannot_be_written_moves_no_mark(monkeypatch, tmp_path):
    """A mark changed since the run started (its server or login changed) is never written
    over: nothing is skipped and the outcome stands, with the detail saying why. A journal
    row that cannot be written rolls the mark's move back with it: `unrecorded`."""
    changed = Cursor([(SINCE, ENOUGH, 0, None, True), None])
    assert imap_retry(monkeypatch, tmp_path, changed, REFUSED_3) == outcome.ERROR
    sqls = [sql for sql, _ in changed.statements]
    assert sqls[1] == "BEGIN" and sqls[3] == "ROLLBACK" and len(sqls) == 5
    assert changed.statements[4] == (
        "UPDATE external_mailbox SET last_fetch_detail = left(coalesce(last_fetch_detail || '; ', "
        "'') || %s, %s), last_fetch_cause = coalesce(%s, last_fetch_cause) WHERE id = %s",
        ("message 3 not skipped: the row's mark changed during the run", outcome.DETAIL_MAX,
         None, 7))

    failing = Unwritable([(SINCE, ENOUGH, 0, None, True), (SKIPPED_AT,)])
    assert imap_retry(monkeypatch, tmp_path, failing, REFUSED_3) == outcome.ERROR
    sqls = [sql for sql, _ in failing.statements]
    assert sqls[1] == "BEGIN" and "imap_last_uid = %s" in sqls[2] and sqls[4] == "ROLLBACK"
    assert failing.statements[5][1] == ("skip not written: RuntimeError", outcome.DETAIL_MAX,
                                        outcome.UNRECORDED, 7)


# --- an IMAP mailbox's stuck hour is one of runs that reached the message -------------

DROPPED_3 = outcome.Outcome(outcome.ERROR, outcome.STUCK_MESSAGE,
                            "UID FETCH 3: the connection failed: socket error: EOF",
                            message_level=True, retr_number=3)
# the ways a run ends without reaching the message, or without the server refusing it
NEVER_REACHED = [
    outcome.Outcome(outcome.ERROR, outcome.UNREACHABLE, "imap.example.org:993: refused"),
    outcome.Outcome(outcome.ERROR, outcome.TIMEOUT, "timed out after 900 s with nothing filed"),
    outcome.Outcome(outcome.ERROR, outcome.TRANSIENT, "EXAMINE INBOX: NO [UNAVAILABLE]"),
    outcome.Outcome(outcome.AUTH_FAILED, None, "LOGIN: NO [AUTHENTICATIONFAILED]"),
]


class Stuck:
    """An IMAP row on the real schema, its mark UID 2 under UIDVALIDITY 42, and the bounded
    retry on it as the pipeline's role runs it. `later` is the timer's wait between two
    runs: it moves the row's times back, which is the same row that much later."""

    def __init__(self, database, tmp_path):
        self.database, self.folder = database, tmp_path
        self.id = database.value(
            "INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host, "
            "protocol, keep_at_provider, state, imap_uidvalidity, imap_last_uid) VALUES "
            "('stuck@example.org', 'stuck@example.org', 'imap.example.org', "
            "'smtp.example.org', 'imap', true, 'active', 42, 2) RETURNING id")
        database.sql("INSERT INTO domain (label, archive_password_hash, external_mailbox_id) "
                     "VALUES ('stuck', '{SHA512-CRYPT}$6$salt$hash', %s)", (self.id,))
        self.args = runner.parse_args(["--state-dir", str(tmp_path)])

    def later(self, minutes):
        self.database.sql(
            "UPDATE external_mailbox SET stuck_since = stuck_since - make_interval(mins => %s), "
            "last_fetch_at = last_fetch_at - make_interval(mins => %s) WHERE id = %s",
            (minutes, minutes, self.id))

    def run(self, result):
        conn = self.database.connect("pipeline")
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                mailbox = runner.row_to_test(cur, self.id)
            assert runner.bounded_retry(conn, mailbox, self.args, self.folder / str(self.id),
                                        None, result) == result.status
        finally:
            conn.close()

    def runs(self, count, result, minutes=3):
        """`count` runs ending as `result`, each the timer's `minutes` after the one before."""
        for _ in range(count):
            self.later(minutes)
            self.run(result)

    def state(self):
        """(the mark, the runs counted, skips in a row, the message skipped, the minutes the
        stuck clock has counted)."""
        return self.database.one(
            "SELECT imap_last_uid, stuck_runs, skip_streak, last_skip_uidl, "
            "round(extract(epoch FROM now() - stuck_since) / 60)::int FROM external_mailbox "
            "WHERE id = %s", (self.id,))

    def journal(self):
        return [(action, detail["stuck_runs"]) for action, detail in
                self.database.sql("SELECT action, detail FROM audit ORDER BY id")]


@pytest.mark.parametrize("between", NEVER_REACHED, ids=lambda result: result.cause or "auth_failed")
@pytest.mark.parametrize("drops_first", [1, ENOUGH + 2])
def test_an_hour_of_imap_runs_that_never_reached_the_message_counts_nothing(
        database, tmp_path, between, drops_first):
    """A connection drops over message 3; then for more than an hour every run ends before
    it asks for the message; then the first run to reach it drops again. The hour between
    was not one stopped on the message, so nothing is skipped: not after two drops, and not
    after enough of them to pass the floor, whose clock stands where the outage found it."""
    box = Stuck(database, tmp_path)
    box.run(DROPPED_3)
    box.runs(drops_first - 1, DROPPED_3)
    counted = 3 * (drops_first - 1)
    assert box.state() == (2, drops_first, 0, None, counted)

    box.runs(25, between)  # 75 minutes, and the clock has not moved
    assert box.state() == (2, drops_first, 0, None, counted)
    box.runs(1, DROPPED_3)
    assert box.state() == (2, drops_first + 1, 0, None, counted + 3)
    assert box.journal() == []


def test_a_gap_in_which_nobody_ran_is_not_an_hour_stopped_on_an_imap_message(database, tmp_path):
    """The timer stopped, or a backup paused it: no run wrote anything for two hours. The
    first run after it drops over the message again and does not find the hour passed,
    though the floor is: of the gap, one run's bound counts. The clock then goes on from
    there, and the message is skipped when the runs since have made the hour up."""
    box = Stuck(database, tmp_path)
    box.run(DROPPED_3)
    box.runs(ENOUGH + 1, DROPPED_3)  # 33 minutes of runs stopped on it
    box.runs(1, DROPPED_3, minutes=120)
    assert box.state() == (2, ENOUGH + 3, 0, None, 33 + runner.DEFAULT_TIMEOUT // 60)
    box.runs(3, DROPPED_3)  # 57 minutes
    assert box.state()[:4] == (2, ENOUGH + 6, 0, None) and box.journal() == []
    box.runs(1, DROPPED_3)
    assert box.state() == (3, 0, 1, "42/3", None)
    assert box.journal() == [("auto_skip_message", ENOUGH + 7)]


def test_an_hour_of_imap_runs_that_each_drop_over_the_message_skips_it_once(database, tmp_path):
    """Every run of the timer reaches message 3 and loses its connection over it. Inside the
    hour nothing is skipped; the run that completes it, the floor long passed, moves the mark
    past the message, once, with one journal row."""
    box = Stuck(database, tmp_path)
    box.run(DROPPED_3)
    box.runs(19, DROPPED_3)  # 57 minutes
    assert box.state() == (2, 20, 0, None, 57) and box.journal() == []
    box.runs(1, DROPPED_3)
    assert box.state() == (3, 0, 1, "42/3", None)
    assert box.journal() == [("auto_skip_message", 21)]


def test_fewer_imap_runs_than_the_floor_skip_nothing_though_the_hour_has_passed(
        database, tmp_path):
    """Runs ten minutes apart: the hour is complete at the seventh that stopped on the
    message, and nothing is skipped until the floor of runs is."""
    box = Stuck(database, tmp_path)
    box.run(DROPPED_3)
    box.runs(ENOUGH - 2, DROPPED_3, minutes=10)
    assert box.state() == (2, ENOUGH - 1, 0, None, 10 * (ENOUGH - 2)) and box.journal() == []
    box.runs(1, DROPPED_3, minutes=10)
    assert box.state() == (3, 0, 1, "42/3", None)
    assert box.journal() == [("auto_skip_message", ENOUGH)]


def test_under_the_floor_an_imap_mailbox_is_neither_skipped_nor_frozen(monkeypatch, tmp_path):
    """The statement that counts the run gives the time since the row's last run the bound of
    one run (`--timeout`), and its answer under the floor ends there, whatever the clock
    says: no skip, and no freeze of a mailbox that has skipped before."""
    for skip_streak in (0, 1):
        cur = Cursor([(SINCE, ENOUGH - 1, skip_streak, None, True)])
        assert imap_retry(monkeypatch, tmp_path, cur, REFUSED_3) == outcome.ERROR
        [(sql, params)] = cur.statements
        assert ("stuck_since = coalesce(stuck_since + greatest(now() - coalesce(last_fetch_at, "
                "now()) - make_interval(secs => %s), interval '0'), now()), "
                "stuck_runs = stuck_runs + 1 WHERE id = %s") in sql
        assert params[4:] == (runner.DEFAULT_TIMEOUT, 7, runner.DEFAULT_STUCK_AFTER)


def test_a_pop3_mailboxs_stuck_hour_is_the_clocks_from_the_first_refusal_as_it_was(
        monkeypatch, tmp_path):
    """What is decided for IMAP changes nothing of a POP3 mailbox's retry: a refusal starts
    the clock or leaves it, with no bound on the time since the last run; any other outcome
    leaves the episode alone; and past the hour the listing session is due after any number
    of runs."""
    listed = []
    monkeypatch.setattr(runner, "stuck_identifier",
                        lambda *a: listed.append(a[-1]) or (None, "the listing answered nothing"))
    args = runner.parse_args(["--state-dir", str(tmp_path)])

    def retry(cur, result):
        return runner.bounded_retry(Conn(cur), render.Mailbox(*ROW), args, tmp_path / "7",
                                    tmp_path / "mpoprc", result)

    refused = outcome.Outcome(outcome.ERROR, outcome.STUCK_MESSAGE, "mpop: command RETR 2 failed",
                              message_level=True, retr_number=2)
    cur = Cursor([(SINCE, 2, 0, None, True), (1,)])
    assert retry(cur, refused) == outcome.ERROR
    assert cur.statements[0] == (
        "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
        "last_fetch_cause = %s, last_fetch_detail = %s, "
        "held_since = CASE WHEN %s THEN NULL ELSE held_since END, "
        "stuck_since = coalesce(stuck_since, now()), stuck_runs = stuck_runs + 1 "
        "WHERE id = %s RETURNING stuck_since, stuck_runs, skip_streak, frozen_since, "
        "now() - stuck_since >= make_interval(secs => %s)",
        (outcome.ERROR, outcome.STUCK_MESSAGE, "mpop: command RETR 2 failed", False, 7, 3600.0))
    assert listed == [2] and "last_listing_at = now()" in cur.statements[1][0]

    cur = Cursor()
    unreachable = outcome.Outcome(outcome.ERROR, outcome.UNREACHABLE, "mpop: cannot connect")
    assert retry(cur, unreachable) == outcome.ERROR
    assert cur.statements == [(
        "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
        "last_fetch_cause = %s, last_fetch_detail = %s WHERE id = %s",
        (outcome.ERROR, outcome.UNREACHABLE, "mpop: cannot connect", 7))]


# --- the credential helper ---------------------------------------------------


class Rows:
    def __init__(self, row):
        self.row = row

    def cursor(self):
        return Cursor([self.row])

    def close(self):
        pass


def test_the_helper_prints_the_secret_and_nothing_else(monkeypatch, capsys):
    monkeypatch.setattr(credential.db, "connect", lambda *a, **k: Rows(("app-pass word",)))
    assert credential.main(["7"]) == 0
    printed = capsys.readouterr()
    assert printed.out == "app-pass word"  # no newline: mpop takes the whole of stdout
    assert printed.err == ""


@pytest.mark.parametrize("row", [None, ("",), (None,)])
def test_a_mailbox_with_no_credential_exits_one_with_an_empty_stdout(monkeypatch, capsys, row):
    monkeypatch.setattr(credential.db, "connect", lambda *a, **k: Rows(row))
    assert credential.main(["7"]) == 1
    printed = capsys.readouterr()
    assert printed.out == ""
    assert printed.err.startswith("maildivvy-credential: ")


@pytest.mark.parametrize("argv", [[], ["7", "8"], ["seven"], ["-1"]])
def test_a_usage_error_exits_sixtyfour_and_a_configuration_error_seventyeight(
        monkeypatch, capsys, argv):
    monkeypatch.setattr(credential.db, "connect", lambda *a, **k: pytest.fail("connected"))
    assert credential.main(argv) == credential.EX_USAGE
    assert capsys.readouterr().out == ""


def test_a_configuration_error_is_told_apart_from_a_missing_credential(monkeypatch, capsys):
    def refuse(*a, **k):
        raise config.ConfigError("db.conf contains password=")

    monkeypatch.setattr(credential.db, "connect", refuse)
    assert credential.main(["7"]) == credential.EX_CONFIG
    assert capsys.readouterr().out == ""


def test_the_helper_writes_to_stdout_exactly_once(monkeypatch):
    """A second write, even of a newline, would become part of the secret."""
    written = io.StringIO()
    monkeypatch.setattr(credential.db, "connect", lambda *a, **k: Rows(("secret",)))
    monkeypatch.setattr("sys.stdout", written)
    assert credential.main(["7"]) == 0
    assert written.getvalue() == "secret"


# --- what the listing session may say ------------------------------


def test_nothing_but_an_identifier_or_mpops_own_lines_leaves_the_listing(monkeypatch, tmp_path):
    conversation = ("--> PASS hunter2\n<-- +OK\n--> UIDL\n<-- +OK\n<-- 1 abc\n<-- .\n"
                    "mpop: the server said something\n")

    class Done:
        returncode = 1
        stdout = conversation
        stderr = ""

    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: Done())
    args = runner.parse_args(["--state-dir", str(tmp_path)])
    identifier, complaint = runner.stuck_identifier(
        args, tmp_path / "mpoprc", render.Mailbox(*ROW), tmp_path, None)
    assert identifier is None
    assert complaint == "mpop: the server said something"
    assert "hunter2" not in complaint


def test_a_listing_that_offers_nothing_is_a_complaint_and_never_an_empty_mailbox(
        monkeypatch, tmp_path):
    class Done:
        returncode = 0
        stdout = "--> UIDL\n<-- +OK\n<-- .\n"
        stderr = ""

    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: Done())
    args = runner.parse_args(["--state-dir", str(tmp_path)])
    identifier, complaint = runner.stuck_identifier(
        args, tmp_path / "mpoprc", render.Mailbox(*ROW), tmp_path, None)
    assert identifier is None and "nothing" in complaint


def test_the_listing_session_always_passes_keep_on(monkeypatch, tmp_path):
    seen = []

    class Done:
        returncode = 0
        stdout = "--> UIDL\n<-- +OK\n<-- 1 abc\n<-- .\n"
        stderr = ""

    def watched(argv, **kwargs):
        seen.append(argv)
        return Done()

    monkeypatch.setattr(runner.subprocess, "run", watched)
    args = runner.parse_args(["--state-dir", str(tmp_path)])
    runner.stuck_identifier(args, tmp_path / "mpoprc", render.Mailbox(*ROW), tmp_path, 1)
    assert "--keep=on" in seen[0] and "--skipsize=0" in seen[0] and "--debug" in seen[0]
    assert str(tmp_path / "uidls.listing") in seen[0]  # never the real state file
    assert str(tmp_path / "uidls") not in seen[0]


def test_the_timeout_kills_the_delivery_filter_mpop_started_as_well(tmp_path):
    """The timeout killed mpop and nothing it had started: the
    filter could go on and store the message mpop never recorded, which the next run
    then retrieves and stores again. A stand-in mpop starts a child that outlives it
    unless it is killed with it."""
    pidfile = tmp_path / "child.pid"
    mpop = tmp_path / "mpop"
    mpop.write_text(f"#!/bin/sh\nsleep 30 &\necho $! > {pidfile}\nwait\n")
    mpop.chmod(0o755)
    with pytest.raises(runner.subprocess.TimeoutExpired):
        runner.run_mpop([str(mpop)], timeout=1, grace=1)
    child = int(pidfile.read_text())
    try:
        for _ in range(50):  # the kill is sent; the kernel takes a moment to reap it
            if not running(child):
                break
            time.sleep(0.1)
        else:
            pytest.fail(f"the child {child} of the killed mpop is still running")
    finally:
        if running(child):
            with contextlib.suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)


def test_the_timeout_stops_mpop_so_it_records_what_it_delivered(tmp_path):
    """mpop writes its state once, after the retrieval loop, and SIGTERM ends that loop
    early and still writes it; SIGKILL wrote nothing, so a backlog longer than the
    timeout was stored again by every run and never converged. A stand-in mpop pipes
    each message through a filter that takes two seconds, waits for it as `pclose` does,
    and on SIGTERM records what was delivered. The timeout falls inside the first
    delivery: the filter must finish it (only mpop is signalled, not the filter) and
    mpop must record it."""
    mpop = tmp_path / "mpop"
    mpop.write_text(
        "#!/usr/bin/python3\nimport pathlib, signal, subprocess\n"
        "stop = []\n"
        "signal.signal(signal.SIGTERM, lambda *_: stop.append(1))\n"
        "delivered = 0\n"
        "while not stop:\n"
        f"    subprocess.run(['sh', '-c', 'sleep 2; echo stored >> {tmp_path}/stored'])\n"
        "    delivered += 1\n"
        f"pathlib.Path('{tmp_path}/uidls').write_text(str(delivered))\n"
        "raise SystemExit(75)\n")
    mpop.chmod(0o755)
    with pytest.raises(runner.subprocess.TimeoutExpired) as raised:
        runner.run_mpop([str(mpop)], timeout=1, grace=10)
    assert not isinstance(raised.value, runner.Killed)
    assert (tmp_path / "stored").read_text() == "stored\n"
    assert (tmp_path / "uidls").read_text() == "1"


def test_an_mpop_that_does_not_stop_within_the_grace_is_killed(tmp_path):
    mpop = tmp_path / "mpop"
    mpop.write_text("#!/bin/sh\ntrap '' TERM\nsleep 30\n")
    mpop.chmod(0o755)
    started = time.monotonic()
    with pytest.raises(runner.Killed):
        runner.run_mpop([str(mpop)], timeout=1, grace=1)
    assert time.monotonic() - started < 10


def running(pid):
    """Is the process there and not a zombie?"""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):  # gone before, or while, it is read
        return False
    return state != "Z"


def test_a_run_that_finishes_in_time_is_read_as_before(tmp_path):
    mpop = tmp_path / "mpop"
    mpop.write_text("#!/bin/sh\necho 'mpop: out'\necho 'mpop: err' >&2\nexit 74\n")
    mpop.chmod(0o755)
    done = runner.run_mpop([str(mpop)], timeout=10)
    assert (done.returncode, done.stdout, done.stderr) == (74, "mpop: out\n", "mpop: err\n")


def test_mpop_is_handed_both_ends_of_the_retrieval_pipe_and_the_runner_keeps_neither(tmp_path):
    """The filter can tell a message mpop finished from one it abandoned only if mpop
    alone holds the write end: the runner must not keep a copy."""
    mpop = tmp_path / "mpop"
    mpop.write_text("#!/usr/bin/python3\nimport os, sys\n"
                    f"read, write = (int(fd) for fd in os.environ['{retrieval.VARIABLE}'].split())\n"
                    "os.fstat(read), os.fstat(write)\n"
                    "print(read, write)\n")
    mpop.chmod(0o755)
    done = runner.run_mpop([str(mpop)], timeout=10)
    assert done.returncode == 0, done.stderr
    read, write = (int(fd) for fd in done.stdout.split())
    for fd in (read, write):
        with pytest.raises(OSError):
            os.fstat(fd)


def test_a_delivery_the_filter_could_not_check_is_carried_into_the_runners_journal(capsys):
    """The filter's words reach only mpop's output, which the
    runner reads and drops on a success; each one is written to the runner's own stderr,
    the fetch unit's journal, where health counts them."""
    said = ("mpop: new: 2 messages in 4 KiB\n"
            f"maildivvy: {retrieval.UNCHECKED}: started for a retrieval with no MAILDIVVY_RETRIEVAL\n")
    runner.say_unchecked("Ivan.P@example.org", said)
    err = capsys.readouterr().err
    assert err == (f"maildivvy-fetch: Ivan.P@example.org: maildivvy: {retrieval.UNCHECKED}: started for "
                   "a retrieval with no MAILDIVVY_RETRIEVAL\n")
    runner.say_unchecked("Ivan.P@example.org", "mpop: new: 2 messages in 4 KiB\n")
    assert capsys.readouterr().err == ""


def test_why_the_store_could_not_take_mail_is_carried_into_the_runners_journal(capsys):
    """The row's detail is mpop's line with the status alone; the probe's reason reaches
    the operator through the fetch unit's journal, and nothing else of the output does."""
    said = ("maildivvy-deliver: the delivery agent refused the message (exit 75: no space)\n"
            "maildivvy-deliver: the archive's store cannot take mail (/srv/x/tmp has 0 bytes "
            "free); the message stays at the provider and collection holds\n"
            "mpop: /opt/maildivvy/bin/maildivvy-deliver returned exit status 73\n"
            "a body line: maildivvy-deliver: the archive's store cannot take mail (forged)\n")
    runner.say_store("Ivan.P@example.org", said)
    assert capsys.readouterr().err == (
        "maildivvy-fetch: Ivan.P@example.org: maildivvy-deliver: the archive's store cannot "
        "take mail (/srv/x/tmp has 0 bytes free); the message stays at the provider and "
        "collection holds\n")


def test_the_retrieval_pipe_reads_waiting_while_mpop_lives_and_ended_after(tmp_path):
    """Driven with a stand-in mpop that pipes into a stand-in filter the way `popen`
    does, and exits without closing the pipe - mpop's error path - or closes it and
    waits, as `pclose` does."""
    for ends, expected in (("os._exit(74)", "abandoned"), ("pipe.close(); child.wait()", "waiting")):
        mpop = tmp_path / "mpop"
        mpop.write_text(
            "#!/usr/bin/python3\nimport os, subprocess, sys\n"
            f"sys.path.insert(0, {str(Path(retrieval.__file__).parents[2])!r})\n"
            "child = subprocess.Popen([sys.executable, '-c', "
            "'import sys; sys.path.insert(0, %r); from maildivvy.lib import retrieval; "
            "fd = retrieval.watch(); sys.stdin.buffer.read(); import time; time.sleep(0.2); "
            "open(%r, \"w\").write(\"waiting\" if retrieval.waiting(fd) else \"abandoned\")' "
            f"% (sys.path[0], {str(tmp_path / 'verdict')!r})], stdin=subprocess.PIPE, close_fds=False)\n"
            "pipe = child.stdin\npipe.write(b'half a message'); pipe.flush()\n"
            f"{ends}\n")
        mpop.chmod(0o755)
        runner.run_mpop([str(mpop)], timeout=10)
        verdict = tmp_path / "verdict"
        for _ in range(50):
            if verdict.exists() and verdict.read_text():
                break
            time.sleep(0.1)
        assert verdict.read_text() == expected, ends
        verdict.unlink()


def test_a_trace_is_written_0600(tmp_path):
    runner.write_trace(tmp_path, "--> PASS hunter2\n")
    assert oct((tmp_path / "trace").stat().st_mode)[-3:] == "600"


def test_the_runners_outcomes_are_the_columns_closed_lists():
    assert set(outcome.STATUSES) == {"ok", "no_new_mail", "auth_failed", "error"}
    assert set(outcome.CAUSES) == {"unrecorded", "timeout", "mark", "stuck_message", "store",
                                   "unreachable", "transient"}


# --- the unit and the timer the programs role installs -----------------------------------------

ROLE = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "programs"


def role_vars():
    import yaml

    return yaml.safe_load((ROLE / "vars" / "main.yml").read_text())


def role_defaults():
    import yaml

    return yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())


def unit_text(name):
    return (ROLE / "templates" / f"{name}.j2").read_text()


def test_the_timer_runs_the_fetch_every_three_minutes():
    assert role_defaults()["maildivvy_fetch_minutes"] == 3
    timer = unit_text("maildivvy-fetch.timer")
    assert "OnCalendar=*:0/{{ maildivvy_fetch_minutes | int }}" in timer
    assert "Unit=maildivvy-fetch.service" in timer


def test_the_service_runs_the_installed_runner_as_the_mail_owner():
    service = unit_text("maildivvy-fetch.service")
    assert "ExecStart={{ maildivvy_opt }}/bin/maildivvy-fetch" in service
    assert "User=vmail" in service and "Type=oneshot" in service


def test_the_role_installs_the_service_and_enables_only_the_timer():
    # every program task adds its own units to the same list, so this names its own
    # rather than the whole set
    units = {u["src"]: u for u in role_vars()["maildivvy_program_units"]}
    assert {"maildivvy-fetch.service.j2", "maildivvy-fetch.timer.j2"} <= set(units)
    assert units["maildivvy-fetch.timer.j2"]["enabled"] is True
    assert "enabled" not in units["maildivvy-fetch.service.j2"]
