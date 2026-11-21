"""The null sender's transport: a notice Postfix wrote, filed in the sender's domain archive.

The database answers from this file and Dovecot's delivery agent is a script that
records how it was called. Postfix running the program through pipe(8) for a notice
about a message the provider refused is proved on the test VM.
"""

import io
import json
import os
import stat
import textwrap
from pathlib import Path

import pytest

from maildivvy.deliver import notice
from maildivvy.lib import store

ADDRESS = "Info@Example.org"
LABEL = "example"
# `-e`, so a rejection is an exit code; then the archive's door and the archive. No -m.
AGENT_ARGS = ["-e", "-o", "mail_plugins/acl=no", "-d", f"{store.ARCHIVE}@{LABEL}"]
NOTICE = (b"From: MAILER-DAEMON@mail.example.test (Mail Delivery System)\n"
          b"To: Info@Example.org\n"
          b"Subject: Undelivered Mail Returned to Sender\n"
          b"\nThe mail system\n\n<someone@example.net>: host smtp.example.org said: 552 too big\n")

AGENT = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, pathlib, sys
    record = pathlib.Path(os.environ["MAILDIVVY_TEST_AGENT_RECORD"])
    calls = json.loads(record.read_text()) if record.exists() else []
    calls.append({"argv": sys.argv[1:], "body": sys.stdin.buffer.read().decode("latin-1")})
    record.write_text(json.dumps(calls))
    sys.exit(int(os.environ.get("MAILDIVVY_TEST_AGENT_EXIT", "0")))
    """)


class Cursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, parameters):
        self.conn.asked.append(parameters)
        self.row = self.conn.rows.get(parameters[0].lower())

    def fetchone(self):
        return self.row


class Connection:
    """The external mailboxes the database holds, keyed by the folded address."""

    def __init__(self, rows):
        self.rows, self.asked, self.closed = rows, [], False

    def cursor(self):
        return Cursor(self)

    def close(self):
        self.closed = True


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    agent = tmp_path / "delivery-agent"
    agent.write_text(AGENT)
    agent.chmod(agent.stat().st_mode | stat.S_IEXEC)
    record = tmp_path / "agent-calls.json"
    monkeypatch.setenv("MAILDIVVY_TEST_AGENT_RECORD", str(record))

    def run(recipient=ADDRESS, rows=None, agent_exit=0, refused=None):
        conn = Connection({ADDRESS.lower(): (LABEL,)} if rows is None else rows)
        consumers = []

        def connect(consumer, autocommit=False):
            consumers.append(consumer)
            if refused is not None:
                raise refused
            return conn

        monkeypatch.setattr(notice.db, "connect", connect)
        monkeypatch.setenv("MAILDIVVY_TEST_AGENT_EXIT", str(agent_exit))
        monkeypatch.setattr(notice.sys, "stdin", io.TextIOWrapper(io.BytesIO(NOTICE)))
        code = notice.main(["--lda", str(agent), recipient])
        calls = json.loads(record.read_text()) if record.exists() else []
        if record.exists():
            os.remove(record)
        return code, calls, consumers, conn, capsys.readouterr().err

    return run


def test_a_notice_is_filed_unchanged_in_the_inbox_of_the_senders_domain_archive(run):
    code, calls, consumers, conn, _ = run()
    assert code == 0
    assert consumers == ["pipeline"] and conn.closed
    assert [call["argv"] for call in calls] == [AGENT_ARGS]
    # Postfix's own words: no scan, and no header block of ours
    assert calls[0]["body"].encode("latin-1") == NOTICE


def test_the_recipient_is_looked_up_with_its_case_folded(run):
    code, calls, _, conn, _ = run(recipient="INFO@EXAMPLE.ORG")
    assert code == 0 and len(calls) == 1
    assert "lower(e.address) = lower(%s)" in " ".join(notice.DOMAIN_OF.split())


def test_a_recipient_that_is_no_external_mailbox_of_ours_is_refused_and_named(run):
    code, calls, _, _, err = run(recipient="someone@elsewhere.example")
    assert code == notice.EX_NOUSER  # Postfix logs it and discards the notice
    assert calls == []
    assert "someone@elsewhere.example" in err


def test_a_database_that_cannot_be_reached_is_a_temporary_failure(run):
    code, calls, _, _, err = run(refused=OSError("connection refused"))
    assert code == notice.EX_TEMPFAIL  # Postfix keeps the notice and tries again
    assert calls == [] and "connection refused" in err


@pytest.mark.parametrize("agent_exit", [75, 77])
def test_the_delivery_agents_refusal_is_returned_as_it_is(run, agent_exit):
    code, calls, _, _, err = run(agent_exit=agent_exit)
    assert code == agent_exit and len(calls) == 1
    assert f"exit {agent_exit}" in err


def test_the_entry_point_names_the_programs_main():
    # bin/ beside src/ in a checkout, beside lib/ in the deployed tree
    text = (Path(notice.__file__).resolve().parents[3] / "bin" / "maildivvy-notice").read_text()
    assert "from maildivvy.deliver.notice import main" in text
    assert "sys.dont_write_bytecode = True" in text
