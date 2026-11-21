"""The incremental run of an IMAP mailbox, against the stub provider in-process,
with a stand-in delivery filter and a stand-in database row; and the password check of
such a mailbox, with the mark only an activation's check sets.

The stand-in filter is a script named as the real one, in the directory the runner is
given as `--bindir`. It reads the message, sleeps and exits as `script.json` says for its
Subject, and on exit 0 records the Subject in `filed`, in order. The row is a dictionary:
the stand-in cursor answers the credential from it and advances its mark under the
conditions the runner's own statement carries. The statements that guard the mark, and
the runner recording an IMAP row's outcome, are run on the unit tier's real schema too
(`database`), where a stand-in cannot hide a wrong condition. The real filter, Dovecot
and the scanners are the VM suite's.
"""

import datetime
import errno
import json
import os
import ssl
import sys
import time

import pytest

import imap as stub_imap
from maildivvy.fetch import imap, imap_collect, outcome, render, runner
from stubserver import make_certificate, read_log, settled_length, write_control

USER = "alice@example.test"
PASSWORD = "app-pass word"
UIDVALIDITY = 7

FILTER = f"""#!{sys.executable}
import json, pathlib, re, sys, time
here = pathlib.Path(__file__).parent
body = sys.stdin.buffer.read()
subject = re.search(rb"^Subject: (.*?)\\r?$", body, re.M).group(1).decode()
script = json.loads((here / "script.json").read_text())
time.sleep(script.get("sleep", {{}}).get(subject, 0))
code = script.get("exit", {{}}).get(subject, 0)
if code:
    sys.stderr.write(f"a line that is not the filter's own\\n")
    sys.stderr.write(f"maildivvy-deliver: scripted exit {{code}} for {{subject}}\\n")
    sys.exit(code)
with open(here / "filed", "a") as out:
    out.write(subject + "\\n")
(here / "argv").write_text(json.dumps(sys.argv[1:]))
"""


class Cursor:
    """The row's credential and mark, and the runner's statements on them."""

    def __init__(self, row):
        self.row = row
        self.answer = None

    def execute(self, sql, params=None):
        if sql.startswith("SELECT credential"):
            self.answer = (self.row["credential"],)
        elif sql == imap_collect.LAST_RUN:
            self.answer = self.row["last_run"]  # (its last cause, frozen and tried lately)
        elif sql.startswith("UPDATE external_mailbox SET imap_last_uid"):
            # `advance`, or a pass over the cap (`pass_over`), which names the skip too
            uid, *skipped, _id, uidvalidity, below = params
            assert "AND imap_uidvalidity = %s AND imap_last_uid < %s" in sql
            mark = self.row["mark"]
            if mark is not None and mark[0] == uidvalidity and mark[1] < below:
                self.row["mark"] = (uidvalidity, uid)
                self.row["advanced"].append(uid)
                self.row["skipped"] += skipped[:1]   # the name, then the column's
                self.answer = (1,)
            else:
                self.answer = None
        elif sql.startswith("INSERT INTO audit"):
            self.row["journal"].append((params[1], json.loads(params[3])))
        elif sql in ("BEGIN", "COMMIT", "ROLLBACK"):
            self.row["transactions"].append(sql)
        else:
            pytest.fail(f"an unexpected statement: {sql}")

    def fetchone(self):
        return self.answer

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Conn:
    def __init__(self, credential=PASSWORD, mark=(UIDVALIDITY, 0)):
        self.row = {"credential": credential, "mark": mark, "advanced": [],
                    "last_run": (None, False), "skipped": [], "journal": [],
                    "transactions": []}

    def cursor(self):
        return Cursor(self.row)


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    return make_certificate(tmp_path_factory.mktemp("certificate"), "provider.stub.test")


@pytest.fixture
def provider(tmp_path, certificate, monkeypatch):
    """The stub with five messages in its INBOX, Subjects 1 to 5, trusted as the machine's
    store would trust it."""
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate.ca))
    inbox = tmp_path / "account" / "INBOX"
    inbox.mkdir(parents=True)
    for uid in range(1, 6):
        (inbox / str(uid)).write_bytes(f"Subject: {uid}\n\nmessage {uid}\n".encode())
    stub = stub_imap.IMAPStub(tmp_path / "account", cert=certificate.cert, key=certificate.key,
                              log=tmp_path / "imap.log", control=tmp_path / "imap.json")
    stub.inbox = inbox
    rescript(stub)
    with stub:
        yield stub


def rescript(stub, **settings):
    write_control(stub.control_path, user=USER, password=PASSWORD,
                  uidvalidity={"INBOX": UIDVALIDITY}, **settings)


@pytest.fixture
def bindir(tmp_path):
    folder = tmp_path / "bin"
    folder.mkdir()
    deliver = folder / "maildivvy-deliver"
    deliver.write_text(FILTER)
    deliver.chmod(0o755)
    script(folder)
    return folder


def script(bindir, **settings):
    (bindir / "script.json").write_text(json.dumps(settings))


def filed(bindir):
    path = bindir / "filed"
    return path.read_text().split() if path.exists() else []


def mailbox(stub, **changes):
    row = dict(id=7, pop3_login=None, address=USER, pop3_host="127.0.0.1", pop3_port=None,
               label="alpha", window=14, target=USER, threshold=8.00, held_since=None,
               keep=True, pin=None, protocol=render.IMAP, imap_uidvalidity=UIDVALIDITY,
               imap_last_uid=0)
    row.update(changes)
    if row["pop3_port"] is None:
        row["pop3_port"] = stub.port
    return render.Mailbox(**row)


def collect(stub, bindir, conn=None, timeout=10, grace=5, **changes):
    conn = conn or Conn(mark=(changes.get("imap_uidvalidity", UIDVALIDITY),
                              changes.get("imap_last_uid", 0)))
    args = runner.parse_args(["--bindir", str(bindir), "--timeout", str(timeout)])
    result = imap_collect.collect(conn, mailbox(stub, **changes), args, grace)
    return result, conn.row["advanced"]


def commands(stub):
    return [r["command"] for r in read_log(stub.log_path) if "command" in r]


def refused(stub):
    return [r for r in read_log(stub.log_path) if r.get("event") == "refused"]


# --- the mark ---------------------------------------------------------------------------


def test_every_message_above_the_mark_is_filed_in_order_and_the_mark_follows_each_one(
        provider, bindir):
    result, advanced = collect(provider, bindir)
    assert result == outcome.Outcome(outcome.OK, None, None)
    assert filed(bindir) == ["1", "2", "3", "4", "5"]
    assert advanced == [1, 2, 3, 4, 5]  # one statement per message, after it was filed
    # the mpop delivery line's arguments, less `--retrieval`: the message is whole
    assert json.loads((bindir / "argv").read_text()) == [
        "--domain", "alpha", "--spam-threshold", "8.00"]
    assert refused(provider) == []
    assert "UID FETCH" in commands(provider) and "LOGOUT" in commands(provider)


def test_a_run_with_nothing_above_the_mark_is_no_new_mail(provider, bindir):
    result, advanced = collect(provider, bindir, imap_last_uid=5)
    assert result == outcome.Outcome(outcome.NO_NEW_MAIL, None, None)
    assert (filed(bindir), advanced) == ([], [])


def test_only_the_uids_above_the_mark_are_taken(provider, bindir):
    result, advanced = collect(provider, bindir, imap_last_uid=3)
    assert result.status == outcome.OK
    assert (filed(bindir), advanced) == (["4", "5"], [4, 5])


def test_an_empty_mark_collects_nothing_and_asks_nothing_of_the_provider(provider, bindir):
    result, advanced = collect(provider, bindir, conn=Conn(mark=None), imap_uidvalidity=None,
                               imap_last_uid=None)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.MARK)
    assert "activating" in result.detail
    assert (filed(bindir), advanced) == ([], [])
    assert commands(provider) == []  # not even a login


def test_another_uidvalidity_collects_nothing(provider, bindir):
    """The provider renumbered its INBOX: no UID under the mark names the same message."""
    result, advanced = collect(provider, bindir, conn=Conn(mark=(6, 2)), imap_uidvalidity=6,
                               imap_last_uid=2)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.MARK)
    assert "UIDVALIDITY is 7, not the mark's 6" in result.detail
    assert (filed(bindir), advanced) == ([], [])
    assert "UID FETCH" not in commands(provider)


def test_a_mark_that_could_not_be_written_stops_the_run_as_unrecorded(provider, bindir):
    """The row's mark was cleared during the run (its server changed): the message in hand
    was filed, and nothing after it is, since the next run could not know."""
    result, advanced = collect(provider, bindir, conn=Conn(mark=None))
    assert (result.status, result.cause) == (outcome.ERROR, outcome.UNRECORDED)
    assert result.detail.startswith("message 1 was filed and the mark was not advanced past it")
    assert (filed(bindir), advanced) == (["1"], [])


# --- a message over the cap -------------------------------------------------------------


def test_a_message_over_the_cap_is_passed_without_its_body_and_the_rest_are_filed(
        provider, bindir, monkeypatch):
    """Its size is asked first; over the cap, its body is never asked for, the mark moves past
    it in one transaction with a journal row naming its UID and size, and the run goes on."""
    monkeypatch.setattr(imap, "MESSAGE_CAP", 40)
    (provider.inbox / "3").write_bytes(b"Subject: 3\n\n" + b"x" * 100 + b"\n")
    conn = Conn()
    result, advanced = collect(provider, bindir, conn=conn)
    assert result.status == outcome.OK and result.cause is None, result.detail
    assert "message 3 of 116 bytes is over the 40-byte cap" in result.detail
    assert "kept at the provider" in result.detail
    assert (filed(bindir), advanced) == (["1", "2", "4", "5"], [1, 2, 3, 4, 5])
    assert conn.row["skipped"] == [f"{UIDVALIDITY}/3"]
    assert conn.row["transactions"] == ["BEGIN", "COMMIT"]
    (action, detail), = conn.row["journal"]
    assert action == "oversize_skip_message"
    assert (detail["uid"], detail["size"], detail["cap"]) == (3, 116, 40)
    bodies = [r["argument"] for r in read_log(provider.log_path)
              if r.get("command") == "UID FETCH" and "BODY.PEEK[]" in r["argument"]]
    assert [b.split()[0] for b in bodies] == ["1", "2", "4", "5"]
    assert refused(provider) == []


def test_a_message_at_the_cap_is_filed(provider, bindir, monkeypatch):
    monkeypatch.setattr(imap, "MESSAGE_CAP", len(b"Subject: 3\r\n\r\nmessage 3\r\n"))
    result, advanced = collect(provider, bindir)
    assert result == outcome.Outcome(outcome.OK, None, None)
    assert filed(bindir) == ["1", "2", "3", "4", "5"]


# --- what the filter answered, and what each answer becomes -----------


@pytest.mark.parametrize("code, cause, fields", [
    (75, outcome.TRANSIENT, {"held": True}),                                  # the antivirus hold
    (73, outcome.STORE, {"store_held": True, "scanner_answered": True}),      # the store's hold
    (74, outcome.STUCK_MESSAGE, {"message_level": True, "retr_number": 3,     # this message
                                 "scanner_answered": True}),
    (77, outcome.STUCK_MESSAGE, {"message_level": True, "retr_number": 3,     # any other refusal
                                 "scanner_answered": True}),
])
def test_a_failure_on_the_third_of_five_leaves_the_mark_at_the_second(
        provider, bindir, code, cause, fields):
    script(bindir, exit={"3": code})
    result, advanced = collect(provider, bindir)
    expected = {"held": False, "store_held": False, "message_level": False, "retr_number": None,
                "scanner_answered": False, **fields}
    assert (result.status, result.cause) == (outcome.ERROR, cause)
    assert {name: getattr(result, name) for name in expected} == expected
    assert (filed(bindir), advanced) == (["1", "2"], [1, 2])
    # the filter's own line, and nothing else it printed
    assert result.detail == (f"message 3: the delivery filter exited {code}; "
                             f"maildivvy-deliver: scripted exit {code} for 3; 2 filed; "
                             "3 still waiting above the mark")
    assert "UID FETCH" in commands(provider)
    assert [r for r in read_log(provider.log_path) if r.get("command") == "UID FETCH"][-1][
        "argument"].startswith("3 ")  # nothing above the third was read


def test_the_servers_no_on_a_message_is_that_messages_failure_without_the_scanner(
        provider, bindir):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 3, "action": "no"}])
    result, advanced = collect(provider, bindir)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.STUCK_MESSAGE)
    assert (result.message_level, result.retr_number, result.scanner_answered) == (True, 3, False)
    assert not result.held and not result.store_held
    assert "the server refused message 3" in result.detail
    assert (filed(bindir), advanced) == (["1", "2"], [1, 2])


@pytest.mark.parametrize("fault", [
    # Dovecot's two answers to a message it cannot read: `no-after`, and its default
    {"action": "no", "text": "[SERVERBUG] Internal error occurred. Refer to server log."},
    {"action": "bye", "text": "FETCH failed: Internal error reading the message"},
])
def test_a_message_refused_with_a_code_or_a_bye_is_that_messages_failure(provider, bindir,
                                                                         fault):
    """Whatever its code, and even as a BYE, the server's answer about one message counts
    toward the bounded retry, which skips it once the stuck period is over: read as the
    account's trouble, the INBOX would stop behind it on every run for ever. A refusal that
    is in fact the whole account's costs at most one skip, then a freeze."""
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 3, **fault}])
    result, advanced = collect(provider, bindir)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.STUCK_MESSAGE)
    assert (result.message_level, result.retr_number, result.scanner_answered) == (True, 3, False)
    assert "the server refused message 3: " in result.detail and fault["text"] in result.detail
    assert (filed(bindir), advanced) == (["1", "2"], [1, 2])


@pytest.mark.parametrize("fault", [
    {"action": "bad", "text": "Command Argument Error. 11"},
    {"action": "nobody"},
    {"action": "no-uid"},
])
def test_a_message_the_server_will_not_hand_over_is_that_messages_failure(
        provider, bindir, fault):
    """A BAD, its flags with no body, or the message under no UID: each counts toward the
    bounded retry as the message's own, which passes it once the stuck period is over,
    rather than stopping the INBOX behind it for good."""
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 3, **fault}])
    result, advanced = collect(provider, bindir)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.STUCK_MESSAGE)
    assert (result.message_level, result.retr_number, result.scanner_answered) == (True, 3, False)
    assert (filed(bindir), advanced) == (["1", "2"], [1, 2])
    assert refused(provider) == []


def test_a_message_expunged_since_the_search_is_passed_and_counted(provider, bindir):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "expunged"}])
    result, advanced = collect(provider, bindir)
    assert result.status == outcome.OK
    assert result.detail == "4 filed; 1 expunged at the provider before being read, passed"
    assert (filed(bindir), advanced) == (["1", "3", "4", "5"], [1, 2, 3, 4, 5])


def test_a_refused_password_is_auth_failed_and_never_carries_it(provider, bindir):
    result, advanced = collect(provider, bindir, conn=Conn(credential="the password changed"))
    assert (result.status, result.cause) == (outcome.AUTH_FAILED, None)
    assert "AUTHENTICATIONFAILED" in result.detail and "the password changed" not in result.detail
    assert (filed(bindir), advanced) == ([], [])


def test_a_mailbox_with_no_password_stored_sends_nothing(provider, bindir):
    result, _ = collect(provider, bindir, conn=Conn(credential=None))
    assert (result.status, result.cause) == (outcome.ERROR, outcome.TRANSIENT)
    assert result.detail == imap_collect.NO_SECRET
    assert commands(provider) == []


def test_a_login_refused_for_a_while_is_transient_and_never_auth_failed(provider, bindir):
    rescript(provider, faults=[{"command": "AUTHENTICATE", "action": "no",
                                "text": "[UNAVAILABLE] Too many simultaneous connections"}])
    result, advanced = collect(provider, bindir)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.TRANSIENT)
    assert "Too many simultaneous connections" in result.detail
    assert (filed(bindir), advanced) == ([], [])


def test_a_server_error_is_transient_and_a_delivery_line_that_cannot_be_built_asks_nothing(
        provider, bindir):
    """A NO to EXAMINE is the server's trouble (`transient`), as is a domain's threshold the
    query lost, which is known before anything is sent."""
    rescript(provider, faults=[{"command": "EXAMINE", "action": "no", "text": "[UNAVAILABLE] busy"}])
    result, advanced = collect(provider, bindir)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.TRANSIENT)
    assert result.detail == "EXAMINE INBOX: [UNAVAILABLE] busy"
    assert advanced == []

    rescript(provider)
    log = settled_length(provider.log_path)
    result, advanced = collect(provider, bindir, threshold=None)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.TRANSIENT)
    assert "no spam_threshold" in result.detail
    assert len(read_log(provider.log_path)) == log and advanced == []


@pytest.mark.parametrize("fault", [{"action": "drop"}, {"action": "truncate"}])
def test_a_connection_that_fails_over_a_message_is_its_failure_and_loses_nothing_before_it(
        provider, bindir, fault):
    """The server took the login, the EXAMINE and the search, then closed with no BYE over
    message 3, before its body or inside it: that message's failure, as a BYE is, so one
    that always does so is skipped after the stuck period instead of stopping the INBOX
    behind it for ever. What was filed is past the mark, and the next run starts at it."""
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 3, **fault}])
    result, advanced = collect(provider, bindir)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.STUCK_MESSAGE)
    assert (result.message_level, result.retr_number, result.scanner_answered) == (True, 3, False)
    assert not result.held and not result.store_held
    assert "UID FETCH 3" in result.detail
    assert (filed(bindir), advanced) == (["1", "2"], [1, 2])
    assert "2 filed" in result.detail and "3 still waiting above the mark" in result.detail


def test_a_connection_that_fails_before_the_fetch_is_sent_charges_no_message(
        provider, bindir, monkeypatch):
    """The connection is found dead when the `UID FETCH` of message 3 is written: the server
    was never asked for it, so the failure is the session's, `unreachable`, and the run
    names no message for the bounded retry to count. What was filed is past the mark."""
    send = imap._ReadOnly.send

    def broken_at_3(client, data):
        if b"UID FETCH 3 " in data:
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")
        return send(client, data)

    monkeypatch.setattr(imap._ReadOnly, "send", broken_at_3)
    result, advanced = collect(provider, bindir)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.UNREACHABLE)
    assert (result.message_level, result.retr_number) == (False, None)
    assert "UID FETCH 3" in result.detail and "the command was not sent" in result.detail
    assert (filed(bindir), advanced) == (["1", "2"], [1, 2])
    asked = [r["argument"] for r in read_log(provider.log_path) if r.get("command") == "UID FETCH"]
    # each one's size, then its body; nothing about message 3 was sent
    assert asked == [f"{uid} {items}" for uid in (1, 2)
                     for items in (imap.SIZE_ITEMS, imap.FETCH_ITEMS)]


class Refusing(Cursor):
    """The row refuses the mark's statement outright."""

    def execute(self, sql, params=None):
        if sql.startswith("UPDATE external_mailbox SET imap_last_uid"):
            raise RuntimeError("the statement failed")
        super().execute(sql, params)


def test_a_mark_whose_statement_fails_stops_the_run_as_unrecorded(provider, bindir):
    conn = Conn()
    conn.cursor = lambda: Refusing(conn.row)
    result, _ = collect(provider, bindir, conn=conn)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.UNRECORDED)
    assert result.detail.startswith("message 1 was filed and the mark was not advanced past it: "
                                    "RuntimeError")
    assert filed(bindir) == ["1"]


def test_a_server_that_cannot_be_reached_is_unreachable(provider, bindir):
    port = provider.port
    provider.stop()
    result, advanced = collect(provider, bindir, pop3_port=port)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.UNREACHABLE)
    assert not result.message_level and advanced == []


# --- the deadline ----------------------------------------------------


def test_at_the_deadline_a_run_that_filed_something_is_ok_and_the_rest_waits(provider, bindir):
    """The first message's filter outlasts the run's time and finishes within the grace:
    it is filed and marked, and the run stops before the next."""
    script(bindir, sleep={"1": 2.5})
    result, advanced = collect(provider, bindir, timeout=2)
    assert result.status == outcome.OK
    assert (filed(bindir), advanced) == (["1"], [1])
    assert result.detail == ("stopped between messages at the run's bound of 2 s; 1 filed; "
                             "4 still waiting above the mark; the next run takes the rest")


def test_at_the_deadline_a_run_that_filed_nothing_is_a_timeout_and_the_filter_is_killed(
        provider, bindir):
    script(bindir, sleep={"1": 30})
    started = time.monotonic()
    result, advanced = collect(provider, bindir, timeout=1, grace=0.5)
    assert time.monotonic() - started < 10
    assert (result.status, result.cause) == (outcome.ERROR, outcome.TIMEOUT)
    assert result.detail.startswith("timed out after 1 s with nothing filed: the delivery "
                                    "filter had not finished message 1")
    assert (filed(bindir), advanced) == ([], [])


def test_a_literal_that_trickles_past_the_deadline_is_a_timeout(provider, bindir):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 1, "action": "trickle",
                                "delay": 0.1}])
    result, advanced = collect(provider, bindir, timeout=1.5)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.TIMEOUT)
    assert (filed(bindir), advanced) == ([], [])


# --- the runner's side of it ---------------------------------------------------------------------


class RunnerCursor:
    """The runner's statements around one IMAP row: the lock, the re-read, the outcome."""

    def __init__(self, row):
        self.row = row
        self.statements = []
        self.answers = []

    def execute(self, sql, params=None):
        sql = " ".join(sql.split())
        self.statements.append(sql)
        if "pg_try_advisory_lock" in sql or "pg_advisory_unlock" in sql:
            self.answers.append((True,))
        elif sql.startswith("SELECT e.id"):
            self.answers.append(self.row)

    def fetchone(self):
        return self.answers.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):  # the runner's connection: one cursor for every statement
        return self


def imap_row():
    return (7, None, USER, "127.0.0.1", 993, "alpha", 14, USER, 8.00, None, True, None,
            render.IMAP, UIDVALIDITY, 0)


def test_the_runner_collects_an_imap_row_with_its_own_client_and_never_mpop(
        monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(runner.render, "write_config", lambda *a: pytest.fail("rendered"))
    monkeypatch.setattr(runner, "run_mpop", lambda *a, **k: pytest.fail("mpop started"))
    monkeypatch.setattr(imap_collect, "collect", lambda conn, mailbox, args, grace: (
        seen.append((mailbox.protocol, grace)) or outcome.Outcome(outcome.OK, None, None)))
    cur = RunnerCursor(imap_row())
    args = runner.parse_args(["--state-dir", str(tmp_path)])
    assert runner.run_one(cur, render.Mailbox(*imap_row()), args) == outcome.OK
    assert seen == [(render.IMAP, runner.STOP_GRACE)]
    assert any(sql.startswith("UPDATE external_mailbox SET last_fetch_at") for sql in cur.statements)
    assert not os.listdir(tmp_path)  # no configuration, no state directory


def test_a_trace_of_an_imap_row_is_refused_and_writes_nothing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(imap_collect, "collect", lambda *a: pytest.fail("collected"))
    cur = RunnerCursor(imap_row())
    args = runner.parse_args(["--state-dir", str(tmp_path), "--trace"])
    assert runner.run_one(cur, render.Mailbox(*imap_row()), args) == outcome.ERROR
    assert "has no trace" in capsys.readouterr().err
    assert not any(sql.startswith("UPDATE") for sql in cur.statements), "a status was written"
    assert cur.statements[-1].startswith("SELECT pg_advisory_unlock")


# --- the check, and the mark only an activation sets ------------------------


class CheckCursor:
    """The runner's statements around the check of one IMAP row, the row a dictionary: the
    lock, the credential, the mark's transaction with its journal row, and the check's own
    three columns. A ROLLBACK puts back the mark and the journal as BEGIN found them."""

    def __init__(self, row):
        self.row = row
        self.statements = []
        self.answer = None
        self.begun = None

    def execute(self, sql, params=None):
        sql = " ".join(sql.split())
        self.statements.append(sql)
        row = self.row
        if "pg_try_advisory_lock" in sql or "pg_advisory_unlock" in sql:
            self.answer = (True,)
        elif sql.startswith("SELECT credential"):
            self.answer = (row["credential"],)
        elif sql == "BEGIN":
            self.begun = (row["mark"], list(row["journal"]))
        elif sql == "COMMIT":
            self.begun = None
        elif sql == "ROLLBACK":
            row["mark"], row["journal"] = self.begun
            self.begun = None
        elif sql.startswith("UPDATE external_mailbox SET imap_uidvalidity"):
            assert self.begun is not None, "the mark was written outside its transaction"
            uidvalidity, last_uid, _id, protocol, host, login, *was = params
            held = (row["protocol"], row["host"], row["login"], row["mark"] or (None, None))
            if (protocol, host, login, tuple(was)) == held:
                row["mark"] = (uidvalidity, last_uid)
                self.answer = row["last_fetch"]
            else:
                self.answer = None
        elif sql.startswith("INSERT INTO audit"):
            assert self.begun is not None, "the journal row was written outside the transaction"
            row["journal"].append((params[0], params[1], params[2], json.loads(params[3])))
        elif sql.startswith("UPDATE external_mailbox SET last_test_at"):
            row["test"] = params[:2]
        else:
            pytest.fail(f"an unexpected statement: {sql}")

    def fetchone(self):
        return self.answer

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):  # the runner's connection: one cursor for every statement
        return self


def check_row(mark=None, credential=PASSWORD, last_fetch=(None, None)):
    return {"credential": credential, "protocol": render.IMAP, "host": "127.0.0.1",
            "login": None, "mark": mark, "last_fetch": last_fetch, "journal": [], "test": None}


def check(stub, row, tmp_path, *flags, **changes):
    """`maildivvy-fetch --auth-only` on the row as the runner reads it; (status, cursor)."""
    mark = row["mark"] or (None, None)
    box = mailbox(stub, imap_uidvalidity=mark[0], imap_last_uid=mark[1], **changes)
    cur = CheckCursor(row)
    args = runner.parse_args(["--state-dir", str(tmp_path / "state"), "--auth-only", "--only",
                              "7", *flags])
    return runner.run_auth_only(cur, box, args), cur


def wrote_a_fetch_column(cur):
    return [s for s in cur.statements if s.startswith("UPDATE")
            and not s.startswith("UPDATE external_mailbox SET last_test_at")]


@pytest.mark.parametrize("mark", [None, (6, 2)])
def test_a_plain_check_logs_in_examines_the_inbox_and_writes_only_its_three_columns(
        provider, tmp_path, mark):
    """Whatever mark the row holds, none or one of another numbering, a check that no
    activation asked for leaves it: it writes the check's three columns and nothing else."""
    row = check_row(mark=mark)
    status, cur = check(provider, row, tmp_path)
    assert status == outcome.OK and row["test"] == ("ok", None)
    assert row["mark"] == mark and row["journal"] == []
    assert wrote_a_fetch_column(cur) == [] and "BEGIN" not in cur.statements
    # a login and EXAMINE INBOX, nothing searched or read, and no configuration written
    # CAPABILITY is imaplib's to send or not, by Python's version (test_fetch_imap.py)
    assert {c for c in commands(provider)} - {"CAPABILITY"} == {"AUTHENTICATE", "EXAMINE", "LOGOUT"}
    assert refused(provider) == []
    assert not (tmp_path / "state").exists()
    assert cur.statements[0].startswith("SELECT pg_try_advisory_lock")
    assert cur.statements[-1].startswith("SELECT pg_advisory_unlock")


def test_a_refused_password_is_the_checks_auth_failed_and_sets_no_mark(provider, tmp_path):
    row = check_row(credential="the password changed")
    status, cur = check(provider, row, tmp_path, "--start-mark")
    assert status == outcome.AUTH_FAILED and row["test"][0] == outcome.AUTH_FAILED
    assert "the password changed" not in row["test"][1]
    assert row["mark"] is None and row["journal"] == [] and wrote_a_fetch_column(cur) == []


def test_the_activations_check_sets_an_empty_mark_where_the_inbox_stands_and_journals_it(
        provider, tmp_path):
    """The INBOX holds UIDs 1 to 5, so its UIDNEXT is 6 and the mark is 5: what is there
    now is the snapshot's, and everything after it the incremental run's."""
    row = check_row()
    status, cur = check(provider, row, tmp_path, "--start-mark")
    assert status == outcome.OK and row["test"] == ("ok", None)
    assert row["mark"] == (UIDVALIDITY, 5)
    assert row["journal"] == [(runner.ACTOR, "imap_mark_set", USER, {
        "uidvalidity": UIDVALIDITY, "last_uid": 5, "old_uidvalidity": None,
        "old_last_uid": None, "last_fetch_at": None, "last_fetch_status": None})]
    assert "UID FETCH" not in commands(provider) and refused(provider) == []
    # the mark and its journal row commit before the check's verdict is written
    assert cur.statements.index("COMMIT") < next(
        i for i, s in enumerate(cur.statements) if s.startswith("UPDATE external_mailbox SET last_test_at"))


def test_a_mark_from_another_uidvalidity_is_reset_with_the_old_one_and_the_last_fetch_journaled(
        provider, tmp_path):
    fetched_at = datetime.datetime(2026, 11, 16, 9, 30, tzinfo=datetime.UTC)
    row = check_row(mark=(6, 2), last_fetch=(fetched_at, outcome.ERROR))
    status, _ = check(provider, row, tmp_path, "--start-mark")
    assert status == outcome.OK and row["mark"] == (UIDVALIDITY, 5)
    assert row["journal"] == [(runner.ACTOR, "imap_mark_reset", USER, {
        "uidvalidity": UIDVALIDITY, "last_uid": 5, "old_uidvalidity": 6, "old_last_uid": 2,
        "last_fetch_at": fetched_at.isoformat(), "last_fetch_status": outcome.ERROR})]


def test_a_mark_of_the_same_uidvalidity_is_kept_so_what_arrived_meanwhile_is_collected(
        provider, tmp_path):
    """Deactivation keeps the mark: activated again, the mailbox collects from where it
    stopped, as a POP3 mailbox does, and not from where the INBOX stands now."""
    row = check_row(mark=(UIDVALIDITY, 3))
    status, cur = check(provider, row, tmp_path, "--start-mark")
    assert status == outcome.OK and row["mark"] == (UIDVALIDITY, 3)
    assert row["journal"] == [] and wrote_a_fetch_column(cur) == []


def test_a_server_that_does_not_say_uidnext_has_the_mark_set_at_its_last_uid(
        provider, tmp_path, monkeypatch):
    examine = imap.Session.examine
    monkeypatch.setattr(imap.Session, "examine",
                        lambda self, name: imap.Examined(examine(self, name).uidvalidity, None))
    row = check_row()
    assert check(provider, row, tmp_path, "--start-mark")[0] == outcome.OK
    assert row["mark"] == (UIDVALIDITY, 5)
    assert "UID SEARCH" in commands(provider) and "UID FETCH" not in commands(provider)


def test_a_mark_the_row_no_longer_matches_is_not_written_and_the_check_is_not_ok(
        provider, tmp_path):
    """The row's server changed while the check ran (the trigger cleared what it held): the
    mark the check found belongs to the server it logged in to, and is not carried to the
    other. The activation reads `error` and switches nothing on."""
    row = check_row()
    row["host"] = "imap.elsewhere.test"
    status, cur = check(provider, row, tmp_path, "--start-mark")
    assert status == outcome.ERROR and row["test"][0] == outcome.ERROR
    assert "the mark collection starts from was not set" in row["test"][1]
    assert row["mark"] is None and row["journal"] == []
    assert "ROLLBACK" in cur.statements and "COMMIT" not in cur.statements


def test_a_message_arriving_after_the_activations_check_is_collected_by_the_first_run(
        provider, bindir, tmp_path):
    row = check_row()
    assert check(provider, row, tmp_path, "--start-mark")[0] == outcome.OK
    (provider.inbox / "6").write_bytes(b"Subject: 6\n\nmessage 6\n")
    result, advanced = collect(provider, bindir, imap_uidvalidity=row["mark"][0],
                               imap_last_uid=row["mark"][1])
    assert result.status == outcome.OK
    assert (filed(bindir), advanced) == (["6"], [6])
    assert refused(provider) == []


# --- on the real schema (`database`): the guards, and the row the runner writes ----------------

HASH = "{SHA512-CRYPT}$6$salt$not-a-real-hash"


def pin_of(certificate):
    digest = imap.fingerprint(ssl.PEM_cert_to_DER_cert(certificate.cert.read_text()))
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def an_imap_row(database, label, port, mark=(UIDVALIDITY, 0), credential=PASSWORD, pin=None):
    """An enabled IMAP row, its login the stub's, a domain in front of it; its id. The schema
    takes a host's name and never an address, and the stub's certificate names no
    `localhost`: a row that reaches the stub holds its certificate's pin."""
    rid = database.value(
        "INSERT INTO external_mailbox (address, address_canonical, pop3_login, pop3_host, "
        "pop3_port, pop3_cert_fingerprint, smtp_host, credential, protocol, keep_at_provider, "
        "state, imap_uidvalidity, imap_last_uid) VALUES (%s, %s, %s, 'localhost', %s, %s, "
        "'smtp.example.test', %s, 'imap', true, 'active', %s, %s) RETURNING id",
        (f"{label}@example.test", f"{label}@example.test", USER, port, pin, credential, *mark))
    database.sql("INSERT INTO domain (label, archive_password_hash, external_mailbox_id) "
                 "VALUES (%s, %s, %s)", (label, HASH, rid))
    return rid


def test_the_marks_statements_hold_their_guards_on_the_real_row(database):
    """`advance`, `skip` and `set_mark` as the pipeline's role runs them. Each writes only over
    the mark its run or its check read: never backwards, never onto another numbering, never
    onto a row whose server, login or protocol changed since (the schema's trigger cleared its
    mark), and a NULL login is compared as a login."""
    rid = an_imap_row(database, "guards", 993, mark=(7, 2))
    changed = "the row's mark changed during the run"

    def mark():
        return database.one("SELECT imap_uidvalidity, imap_last_uid FROM external_mailbox "
                            "WHERE id = %s", (rid,))

    conn = database.connect("pipeline")
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            box = runner.row_to_test(cur, rid)
            assert imap_collect.advance(cur, box, 3) is None and mark() == (7, 3)
            assert imap_collect.advance(cur, box, 3) == changed      # not onto where it stands
            assert imap_collect.advance(cur, box, 2) == changed and mark() == (7, 3)
            name, at = imap_collect.skip(cur, box, 4)
            assert name == "7/4" and at is not None and mark() == (7, 4)
            assert database.one("SELECT last_skip_uidl, skip_streak FROM external_mailbox "
                                "WHERE id = %s", (rid,)) == ("7/4", 1)

            # the provider renumbered and an activation reset the mark: neither writes over it
            database.sql("UPDATE external_mailbox SET imap_uidvalidity = 8, imap_last_uid = 0 "
                         "WHERE id = %s", (rid,))
            assert imap_collect.advance(cur, box, 9) == changed
            assert imap_collect.skip(cur, box, 9) is None and mark() == (8, 0)

            # a new host clears the mark, for every writer: nothing writes one back
            database.sql("UPDATE external_mailbox SET pop3_host = 'imap.elsewhere.test' "
                         "WHERE id = %s", (rid,))
            assert mark() == (None, None)
            assert imap_collect.advance(cur, box, 9) == changed
            assert imap_collect.skip(cur, box, 9) is None and mark() == (None, None)

            # an activation's mark: onto the row as its check read it, and nothing else
            for login, change in ((None, None), (USER, None),
                                  (USER, "pop3_login = 'someone.else'"),
                                  (None, "pop3_login = 'someone.else'"),
                                  (USER, "pop3_host = 'imap.elsewhere.test'"),
                                  (USER, "protocol = 'pop3'"),
                                  (USER, "imap_uidvalidity = 7, imap_last_uid = 1")):
                database.sql("UPDATE external_mailbox SET protocol = 'imap', "
                             "pop3_host = 'localhost', pop3_login = %s, imap_uidvalidity = NULL, "
                             "imap_last_uid = NULL WHERE id = %s", (login, rid))
                read = runner.row_to_test(cur, rid)
                if change is not None:
                    database.sql(f"UPDATE external_mailbox SET {change} WHERE id = %s", (rid,))
                before = mark()
                written = imap_collect.set_mark(cur, read, 7, 5)
                if change is None:
                    assert written is not None and mark() == (7, 5), login
                    assert imap_collect.set_mark(cur, read, 7, 6) is None and mark() == (7, 5)
                else:
                    assert written is None and mark() == before, change
    finally:
        conn.close()


def test_a_pass_over_the_cap_moves_the_mark_and_journals_it_on_the_real_row(database):
    """As the pipeline's role: the mark and the last skip in one transaction with the journal
    row, under `advance`'s guard; no stuck episode is counted toward a freeze."""
    rid = an_imap_row(database, "oversize", 993, mark=(7, 2))
    conn = database.connect("pipeline")
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            box = runner.row_to_test(cur, rid)
            assert imap_collect.pass_over(cur, box, 3, 60_000_000) is None
            assert imap_collect.pass_over(cur, box, 3, 60_000_000) == \
                "the row's mark changed during the run"
    finally:
        conn.close()
    assert database.one("SELECT imap_last_uid, last_skip_uidl, skip_streak, stuck_runs "
                        "FROM external_mailbox WHERE id = %s", (rid,)) == (3, "7/3", 0, 0)
    assert database.value("SELECT oversize_skipped - 'at' FROM external_mailbox WHERE id = %s",
                          (rid,)) == {"uid": 3, "uidvalidity": 7, "size": 60_000_000}
    (action, detail), = database.sql(
        "SELECT action, detail FROM audit WHERE target = 'oversize@example.test'")
    assert action == "oversize_skip_message"
    assert (detail["uidl"], detail["size"], detail["cap"]) == ("7/3", 60_000_000, imap.MESSAGE_CAP)


def test_a_refused_password_is_recorded_on_the_imap_row_as_auth_failed(provider, bindir,
                                                                       database, certificate):
    rid = an_imap_row(database, "refusal", provider.port, credential="the password changed",
                      pin=pin_of(certificate))
    assert runner.main(["--etc", str(database.etc), "--bindir", str(bindir), "--timeout", "10",
                        "--only", str(rid)]) == 1
    status, cause, detail, mark = database.one(
        "SELECT last_fetch_status, last_fetch_cause, last_fetch_detail, imap_last_uid "
        "FROM external_mailbox WHERE id = %s", (rid,))
    assert (status, cause, mark) == (outcome.AUTH_FAILED, None, 0)
    assert "AUTHENTICATIONFAILED" in detail and "the password changed" not in detail
    assert filed(bindir) == []


def test_a_drop_after_the_mark_moved_is_the_next_messages_first_failure_and_skips_nothing(
        provider, bindir, database, certificate):
    """The stuck episode is the message's: the mark moving past one ends it. A run that
    files a message and then loses its connection over the next starts that message's own
    episode, though the mailbox was stuck for two hours on the one before, so on a flaky
    link, each run stopping somewhere else, a message that failed once is never skipped."""
    rid = an_imap_row(database, "flaky", provider.port, mark=(UIDVALIDITY, 2),
                      pin=pin_of(certificate))
    database.sql("UPDATE external_mailbox SET stuck_since = now() - interval '2 hours', "
                 "stuck_runs = 5 WHERE id = %s", (rid,))
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 4, "action": "drop"}])
    assert runner.main(["--etc", str(database.etc), "--bindir", str(bindir), "--timeout", "10",
                        "--only", str(rid)]) == 1
    assert filed(bindir) == ["3"]
    assert database.one(
        "SELECT imap_last_uid, now() - stuck_since < interval '1 minute', stuck_runs, "
        "skip_streak, last_skip_uidl, last_fetch_cause FROM external_mailbox WHERE id = %s",
        (rid,)) == (3, True, 1, 0, None, outcome.STUCK_MESSAGE)
    assert database.value("SELECT count(*) FROM audit") == 0


def test_two_drops_over_one_message_with_two_hours_of_no_runs_between_skip_nothing(
        provider, bindir, database, certificate):
    """The whole run, twice, on the real row: the connection drops over message 3, nothing
    runs for two hours (a stopped timer, a backup's pause), and the first run after drops
    over it again. Two runs stopped on the message; it is not skipped."""
    rid = an_imap_row(database, "outage", provider.port, mark=(UIDVALIDITY, 2),
                      pin=pin_of(certificate))
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 3, "action": "drop"}])
    run = ["--etc", str(database.etc), "--bindir", str(bindir), "--timeout", "10",
           "--only", str(rid)]
    assert runner.main(run) == 1
    database.sql("UPDATE external_mailbox SET stuck_since = stuck_since - interval '2 hours', "
                 "last_fetch_at = last_fetch_at - interval '2 hours' WHERE id = %s", (rid,))
    assert runner.main(run) == 1
    assert database.one(
        "SELECT imap_last_uid, stuck_runs, skip_streak, last_skip_uidl, last_fetch_cause "
        "FROM external_mailbox WHERE id = %s", (rid,)) == (2, 2, 0, None, outcome.STUCK_MESSAGE)
    assert database.value("SELECT count(*) FROM audit") == 0
    assert filed(bindir) == []


def test_a_fault_of_one_imap_mailbox_is_its_own_and_the_run_goes_on_to_the_next(
        provider, bindir, database, certificate):
    """The delivery filter is not installed, so the first mailbox's run cannot start it for
    its first message: that mailbox records `error`/`transient` naming why, its mark where it
    was, and the next mailbox, nothing above its mark, is still collected."""
    (bindir / "maildivvy-deliver").unlink()
    pin = pin_of(certificate)
    first = an_imap_row(database, "first", provider.port, pin=pin)
    second = an_imap_row(database, "second", provider.port, mark=(UIDVALIDITY, 5), pin=pin)
    assert runner.main(["--etc", str(database.etc), "--bindir", str(bindir),
                        "--timeout", "10"]) == 1
    rows = {rid: rest for rid, *rest in database.sql(
        "SELECT id, last_fetch_status, last_fetch_cause, last_fetch_detail, imap_last_uid "
        "FROM external_mailbox")}
    status, cause, detail, mark = rows[first]
    assert (status, cause, mark) == (outcome.ERROR, outcome.TRANSIENT, 0)
    assert detail.startswith("the run stopped on a fault of its own: FileNotFoundError")
    assert "maildivvy-deliver" in detail and PASSWORD not in detail
    assert rows[second][:2] == [outcome.NO_NEW_MAIL, None]
    assert refused(provider) == []


# --- what the provider is not asked, and a mark it numbered under ----------------------


def test_a_mark_above_the_inboxs_last_uid_is_the_mark_outcome_and_nothing_is_fetched(
        provider, bindir):
    """A provider that numbered the INBOX again under the same UIDVALIDITY: read as "no new
    mail", every message under the mark would never be collected, silently."""
    result, advanced = collect(provider, bindir, imap_last_uid=9)
    assert (result.status, result.cause) == (outcome.ERROR, outcome.MARK)
    assert "next UID is 6" in result.detail and "mark's 9" in result.detail
    assert (filed(bindir), advanced) == ([], [])
    assert "UID FETCH" not in commands(provider) and "UID SEARCH" not in commands(provider)


def test_a_store_still_held_asks_the_provider_nothing_and_one_that_can_take_mail_is_collected(
        provider, bindir, monkeypatch):
    probed = []
    found = ["/srv/maildivvy/store has 0 bytes free"]
    monkeypatch.setattr(imap_collect.deliver_filter, "store_failure",
                        lambda domain, folder, size: probed.append(domain) or found[0])
    conn = Conn()
    conn.row["last_run"] = (outcome.STORE, False)
    result, advanced = collect(provider, bindir, conn=conn)
    assert (result.status, result.cause, result.store_held) == (outcome.ERROR, outcome.STORE, True)
    assert "0 bytes free" in result.detail and "the provider was not asked" in result.detail
    assert probed == ["alpha"] and commands(provider) == [] and advanced == []

    found[0] = None
    result, advanced = collect(provider, bindir, conn=conn)
    assert result.status == outcome.OK and advanced == [1, 2, 3, 4, 5]


def test_a_frozen_mailbox_tried_within_the_hour_asks_the_provider_nothing(provider, bindir):
    conn = Conn()
    conn.row["last_run"] = (outcome.STUCK_MESSAGE, True)
    result, advanced = collect(provider, bindir, conn=conn)
    assert result == imap_collect.FROZEN
    assert commands(provider) == [] and advanced == []


def test_a_frozen_mailbox_is_tried_once_an_hour_and_nothing_is_written_between(
        provider, bindir, database, certificate):
    rid = an_imap_row(database, "frozen", provider.port, pin=pin_of(certificate))
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 1, "action": "no"}])
    database.sql("UPDATE external_mailbox SET frozen_since = now() - interval '2 hours', "
                 "last_fetch_at = now() - interval '10 minutes', last_fetch_status = 'error', "
                 "last_fetch_cause = 'stuck_message' WHERE id = %s", (rid,))
    argv = ["--etc", str(database.etc), "--bindir", str(bindir), "--timeout", "10",
            "--only", str(rid)]

    def last():
        return database.one("SELECT last_fetch_at, stuck_runs FROM external_mailbox "
                            "WHERE id = %s", (rid,))

    before = last()
    assert runner.main(argv[:-2]) == 1   # the timer's run, of every mailbox
    assert last() == before and commands(provider) == []

    database.sql("UPDATE external_mailbox SET last_fetch_at = now() - interval '61 minutes' "
                 "WHERE id = %s", (rid,))
    assert runner.main(argv[:-2]) == 1
    assert "UID FETCH" in commands(provider)
    assert last()[1] == before[1] + 1

    # a person's refetch of that one mailbox is never left for the hour
    provider.log_path.write_text("")
    assert runner.main(argv) == 1
    assert "UID FETCH" in commands(provider) and last()[1] == before[1] + 2


def test_a_nul_in_the_servers_answer_is_recorded_and_the_run_goes_on_to_the_next_mailbox(
        provider, bindir, database, certificate):
    pin = pin_of(certificate)
    first = an_imap_row(database, "nul", provider.port, pin=pin)
    second = an_imap_row(database, "after", provider.port, mark=(UIDVALIDITY, 5), pin=pin)
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 1, "action": "no",
                                "text": "cannot\u0000read"}])
    assert runner.main(["--etc", str(database.etc), "--bindir", str(bindir),
                        "--timeout", "10"]) == 1
    rows = {rid: rest for rid, *rest in database.sql(
        "SELECT id, last_fetch_status, last_fetch_cause, last_fetch_detail "
        "FROM external_mailbox")}
    assert rows[first][:2] == [outcome.ERROR, outcome.STUCK_MESSAGE]
    assert "cannot read" in rows[first][2]
    assert rows[second][:2] == [outcome.NO_NEW_MAIL, None]
