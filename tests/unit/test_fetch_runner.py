"""The runner's own refusals, its queries and the credential helper, without a database.

The parts that need real rows, a real mpop and a real provider are driven on the test
VM. What is tested here is what is true of the text:
which columns the two queries select, what the command line refuses, and what the
credential helper writes on which stream.
"""

import datetime
import io
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
       "ivan.p@example.org", 8.00, None)


# --- the two queries ---------------------------------------------------------


def test_both_queries_select_the_same_columns_in_the_mailboxs_own_order():
    assert runner.TO_FETCH.startswith(runner.COLUMNS)
    assert runner.TO_TEST.startswith(runner.COLUMNS)
    selected = runner.COLUMNS.split("SELECT")[1].split("FROM")[0]
    names = [part.strip().split(".")[1] for part in selected.split(",")]
    assert names == ["id", "pop3_login", "address", "pop3_host", "pop3_port", "label",
                     "delete_window_days", "address_canonical", "spam_threshold", "held_since"]
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
    cur = Cursor([[ROW]])
    assert runner.rows_to_fetch(cur) == [render.Mailbox(*ROW)]
    with pytest.raises(TypeError):
        runner.row_to_test(Cursor([ROW[:-1]]), 7)


def test_an_unknown_id_has_no_row_to_test():
    assert runner.row_to_test(Cursor([None]), 99) is None


# --- the command line -------------------------------------------------------------


def test_a_password_check_without_a_named_mailbox_is_refused(capsys):
    assert runner.main(["--auth-only"]) == runner.EX_USAGE
    assert "needs --only" in capsys.readouterr().err


def test_the_refusal_happens_before_any_database_connection(monkeypatch):
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: pytest.fail("connected"))
    assert runner.main(["--auth-only"]) == runner.EX_USAGE


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
    ([None], 0),                       # every mailbox was locked by another runner
    (["ok", "error"], 1),
    (["ok", "auth_failed"], 1),        # counting only `error` survived every earlier test
    (["auth_failed", "no_new_mail"], 1),
])
def test_a_run_exits_non_zero_when_any_mailbox_failed(monkeypatch, statuses, code):
    rows = [(i, None, f"a{i}@x.test", "p.x.test", 995, "alpha", 14, f"a{i}@x.test", 8.00, None)
            for i in range(len(statuses))]
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: Connection(rows))
    answers = iter(statuses)
    monkeypatch.setattr(runner, "run_one", lambda conn, mailbox, args: next(answers))
    assert runner.main([]) == code


def test_only_the_named_mailbox_is_fetched_with_only(monkeypatch):
    rows = [(i, None, f"a{i}@x.test", "p.x.test", 995, "alpha", 14, f"a{i}@x.test", 8.00, None)
            for i in (1, 2, 3)]
    monkeypatch.setattr(runner.db, "connect", lambda *a, **k: Connection(rows))
    fetched = []
    monkeypatch.setattr(runner, "run_one",
                        lambda conn, mailbox, args: fetched.append(mailbox.id) or "ok")
    assert runner.main(["--only", "2"]) == 0
    assert fetched == [2]


# --- the lock namespace both sides share -------------------------------------


def test_the_fetch_takes_the_lock_with_try_lock_and_never_waits():
    cur = Cursor([(False,)])
    assert locks.try_lock(cur, 7) is False
    assert cur.statements == [("SELECT pg_try_advisory_lock(%s, %s)", (locks.NAMESPACE, 7))]


def test_a_deletion_takes_the_same_lock_blocking_under_the_same_namespace():
    cur = Cursor([])
    locks.lock(cur, 7)
    assert cur.statements == [("SELECT pg_advisory_lock(%s, %s)", (locks.NAMESPACE, 7))]


def test_the_namespace_is_named_once_so_the_two_locks_meet():
    package = Path(runner.__file__).parent
    spelling = [line for path in package.glob("*.py")
                for line in path.read_text().splitlines()
                if "advisory" in line and "%s" in line]
    assert all(str(locks.NAMESPACE) not in line for line in spelling)
    assert len(spelling) == 4  # try, blocking, transaction-level, unlock - all in locks.py


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
        runner.run_mpop([str(mpop)], timeout=1)
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
            os.kill(child, signal.SIGKILL)


def running(pid):
    """Is the process there and not a zombie?"""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
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
    assert set(outcome.CAUSES) == {"unrecorded", "timeout", "stuck_message",
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
