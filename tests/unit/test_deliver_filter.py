"""The delivery filter's own decisions, with stand-ins for the scanners and the agent.

The scanners answer from this file rather than over a socket (their protocol is pinned
in `tests/unit/test_scan.py`), and Dovecot's delivery agent is a script that records how
it was called. What is proved here is what the filter does with those answers: which
login and folder each message goes to, what it exits, that the report is written and is
neither scanned nor given a header block, and the inbound hold.

The same filter runs against the real scanners and the real agent on the test VM.
"""

import email
import email.policy
import io
import json
import os
import stat
import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from maildivvy.deliver import filter as deliver, marks, report
from maildivvy.lib import retrieval, scan, store

DOMAIN = "example"
ARCHIVE = f"{store.ARCHIVE}@{DOMAIN}"
# `-e`, so a rejection is an exit code and never a bounce the agent sends itself;
# then the archive's door and the archive.
AGENT_ARGS = ["-e", "-o", "mail_plugins/acl=no", "-d", ARCHIVE]
WITHHELD_FIELD = f"hdr.{report.WITHHELD_HEADER.lower()}"

PLAIN = (b"From: Someone <someone@example.org>\r\n"
         b"To: archive@example\r\n"
         b"Subject: an ordinary message\r\n"
         b"Content-Type: text/plain; charset=utf-8\r\n"
         b"\r\nplain words\r\n")

AGENT = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, pathlib, sys
    record = pathlib.Path(os.environ["MAILDIVVY_TEST_AGENT_RECORD"])
    calls = json.loads(record.read_text()) if record.exists() else []
    calls.append({"argv": sys.argv[1:],
                  "body": sys.stdin.buffer.read().decode("utf-8", "replace")})
    record.write_text(json.dumps(calls))
    sys.exit(int(os.environ.get("MAILDIVVY_TEST_AGENT_EXIT", "0")))
    """)


class Run:
    """One run of the filter: its exit code, what the agent got, what was scanned."""

    def __init__(self, code, calls, scanned, folders):
        self.code = code
        self.calls = calls
        self.scanned = scanned
        self.folders = folders

    @property
    def bodies(self):
        return [call["body"] for call in self.calls]

    def argv(self, call):
        return self.calls[call]["argv"]


@pytest.fixture
def filter_run(tmp_path, monkeypatch):
    """Run the filter with the scanners answering as the test says."""
    agent = tmp_path / "delivery-agent"
    agent.write_text(AGENT)
    agent.chmod(agent.stat().st_mode | stat.S_IEXEC)
    record = tmp_path / "agent-calls.json"
    monkeypatch.setenv("MAILDIVVY_TEST_AGENT_RECORD", str(record))

    def run(*argv, raw=PLAIN, virus=None, score=None, agent_exit=0, folder_error=None,
            quarantine=(), store_down=None, scanning=None):
        """`quarantine`: the withheld ids the archive's quarantine already holds;
        `store_down`: what the probe finds wrong with the store, None for nothing;
        `scanning`: called with each body the antivirus is handed, to raise."""
        virus = virus if virus is not None else scan.Verdict(scan.CLEAN, "stream: OK")
        score = score if score is not None else scan.Score(0.5, "no action")
        scanned, folders = [], []
        monkeypatch.setenv("MAILDIVVY_TEST_AGENT_EXIT", str(agent_exit))
        def scan_virus(body, **kw):
            scanned.append(("virus", body))
            if scanning is not None:
                scanning(body)
            return virus

        monkeypatch.setattr(deliver.scan, "scan_virus", scan_virus)
        monkeypatch.setattr(deliver.scan, "scan_spam",
                            lambda body, **kw: scanned.append(("spam", body)) or score)
        def create_folder(login, folder):
            folders.append((login, folder))
            if folder_error is not None:
                raise folder_error
            return True

        monkeypatch.setattr(deliver.doveadm, "create_folder", create_folder)

        def fetch(login, mailbox, fields, *search):
            assert (login, mailbox) == (ARCHIVE, store.QUARANTINE), (login, mailbox)
            return [{"uid": str(uid), WITHHELD_FIELD: held}
                    for uid, held in enumerate(quarantine, 1)]

        monkeypatch.setattr(deliver.doveadm, "fetch", fetch)
        probed = []
        monkeypatch.setattr(deliver, "store_failure",
                            lambda domain, folder, size: probed.append(folder) or store_down)
        monkeypatch.setattr(deliver.sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
        code = deliver.main(["--domain", DOMAIN, "--lda", str(agent), *argv])
        calls = json.loads(record.read_text()) if record.exists() else []
        if record.exists():
            os.remove(record)
        result = Run(code, calls, scanned, folders)
        result.probed = probed
        return result

    return run


def headers(body):
    head, _, _ = marks.split_header_block(body.encode())
    return [line.decode() for line in head.splitlines()]


def header(body, name):
    values = [line.split(": ", 1)[1] for line in headers(body)
              if line.lower().startswith(f"{name.lower()}:")]
    return values[0] if values else None


# --- a clean message: the archive's INBOX, and nothing else -----------------------


def test_a_clean_message_goes_to_the_domains_archive_and_nowhere_else(filter_run):
    run = filter_run()
    assert run.code == 0
    assert len(run.calls) == 1
    assert run.argv(0) == AGENT_ARGS  # no -m: INBOX
    assert run.folders == []  # nothing is created for an ordinary delivery


def test_the_envelope_sender_is_passed_through(filter_run):
    run = filter_run("-f", "bounce@example.org")
    assert run.argv(0)[-2:] == ["-f", "bounce@example.org"]


@pytest.mark.parametrize("code", [67, 77, 1])
def test_the_delivery_agents_exit_code_comes_back_unchanged(filter_run, code):
    """It is what the fetch runner reads as "our delivery refused this message"."""
    assert filter_run(agent_exit=code).code == code


@pytest.mark.parametrize("verdict", [scan.CLEAN, scan.INFECTED])
def test_the_agents_own_temporary_failure_is_never_the_antivirus_hold(filter_run, verdict):
    """The agent exits 75 on a full store and on a directory it
    may not write (measured on the test VM), and 75
    is the one exit that means "the antivirus is unreachable": passed through,
    the runner held the mailbox as an antivirus outage and never started the stuck hour.
    It comes back as a refusal of this message instead."""
    run = filter_run(virus=scan.Verdict(verdict, "detail"), agent_exit=75)
    assert run.code == deliver.EX_IOERR == 74
    assert len(run.calls) == 1  # it stopped at the first refusal
    assert run.probed  # and the store was asked about first, and could take mail


def test_the_agent_is_told_to_answer_a_rejection_with_an_exit_code(filter_run):
    """Without `-e` the agent answers a rejection (measured: a
    full quota) by mailing a bounce itself and exiting 0, so mpop records the message as
    retrieved and it is lost. With it, a rejection is exit 77 and the message stays at
    the provider."""
    run = filter_run(virus=scan.Verdict(scan.INFECTED, "found"))
    assert [call["argv"][0] for call in run.calls] == ["-e", "-e"]


@pytest.mark.parametrize("verdict", [scan.CLEAN, scan.INFECTED, scan.UNSCANNED])
def test_the_filter_never_rejects_whatever_the_verdict_is(filter_run, verdict):
    run = filter_run(virus=scan.Verdict(verdict, "detail"))
    assert run.code == 0 and run.calls


def test_the_scanner_sockets_it_reaches_for_are_the_librarys_own():
    """A wrong path is silent: the scanner reads as unavailable and nothing fails. The
    install probes these same two paths."""
    args = deliver.parse_args(["--domain", DOMAIN])
    assert args.clamd_socket == str(scan.CLAMD_SOCKET)
    assert args.rspamd_socket == str(scan.RSPAMD_SOCKET)


# --- the verdict headers -----------------------------------------------------


def test_the_message_is_scanned_as_bytes_and_the_verdicts_are_in_what_is_stored(filter_run):
    """Scanned before it is stored: the bytes handed to the agent already carry the
    verdicts, and the scanners were given the message itself, never a path into a store
    they cannot reach. Antivirus and spam are asked independently."""
    run = filter_run()
    assert [kind for kind, _ in run.scanned] == ["virus", "spam"]
    assert all(body == PLAIN for _, body in run.scanned)
    assert header(run.bodies[0], marks.SCAN_HEADER) == scan.CLEAN
    assert header(run.bodies[0], marks.SPAM_SCORE_HEADER) == "0.50"


def test_the_verdict_headers_are_the_first_lines_of_the_stored_message(filter_run):
    body = filter_run().bodies[0]
    assert headers(body)[0] == f"{marks.SCAN_HEADER}: clean"
    assert header(body, marks.SPAM_MARK_HEADER) == "no"
    assert header(body, marks.SPAM_SCORE_HEADER) == "0.50"
    assert body.endswith("plain words\r\n")  # and the sender's bytes are all still there


def test_the_threshold_on_the_command_line_is_the_one_it_compares_with(filter_run):
    high = filter_run("--spam-threshold", "8.00", score=scan.Score(7.99, "no action"))
    assert header(high.bodies[0], marks.SPAM_MARK_HEADER) == "no"
    low = filter_run("--spam-threshold", "1.00", score=scan.Score(7.99, "no action"))
    assert header(low.bodies[0], marks.SPAM_MARK_HEADER) == "yes"
    assert "Subject: [spam] an ordinary message" in low.bodies[0]


def test_a_message_the_scanner_gave_no_score_is_delivered_unmarked_with_the_literal(filter_run):
    run = filter_run(score=scan.Score(None, scan.UNAVAILABLE, "rspamd: the answer carries no score"))
    assert run.code == 0
    assert header(run.bodies[0], marks.SPAM_SCORE_HEADER) == marks.NO_SCORE
    assert header(run.bodies[0], marks.SPAM_MARK_HEADER) == "no"
    assert header(run.bodies[0], marks.SPAM_DETAIL_HEADER).startswith("rspamd")


# --- a withheld message and the report that replaces it -----------------


def test_a_withheld_message_goes_to_quarantine_and_its_report_to_the_inbox(filter_run):
    run = filter_run(virus=scan.Verdict(scan.INFECTED, "stream: Eicar-Test-Signature FOUND"))
    assert run.code == 0 and len(run.calls) == 2
    assert run.argv(0) == [*AGENT_ARGS, "-m", store.QUARANTINE]
    assert run.argv(1) == AGENT_ARGS  # the report: INBOX
    # the folder is made through Dovecot first: an agent handed a folder that does not
    # exist files the message in INBOX instead, where quarantine would reach every reader
    assert run.folders == [(ARCHIVE, store.QUARANTINE)]


def test_one_id_the_filter_mints_stands_in_both_before_either_is_delivered(filter_run):
    run = filter_run(virus=scan.Verdict(scan.UNSCANNED, "over the limit"))
    withheld = header(run.bodies[0], report.WITHHELD_HEADER)
    assert withheld and len(withheld) == 32
    assert header(run.bodies[1], report.WITHHELD_HEADER) == withheld
    assert header(run.bodies[1], "Message-ID") == f"<{withheld}@{DOMAIN}>"
    assert withheld in run.bodies[1]  # and a reader is told it too


def test_the_report_is_neither_scanned_nor_given_a_header_block_of_ours(filter_run):
    run = filter_run(virus=scan.Verdict(scan.INFECTED, "stream: Eicar FOUND"))
    # ⛔ One delivery makes exactly one request to each scanner: for the message, never
    # for the report it generates. A report this machine writes has no authenticated
    # path behind it and scores like mail from nowhere.
    assert [kind for kind, _ in run.scanned] == ["virus", "spam"]
    assert all(body == PLAIN for _, body in run.scanned)
    report_headers = [line.split(":")[0] for line in headers(run.bodies[1])]
    assert not [name for name in report_headers if name.startswith("X-Maildivvy-Spam")]
    assert marks.SCAN_HEADER not in report_headers
    assert report.WITHHELD_HEADER in report_headers  # the one header of ours it carries


def test_the_report_says_what_the_verdict_was_and_nothing_else(filter_run):
    infected = filter_run(virus=scan.Verdict(scan.INFECTED, "stream: Eicar FOUND")).bodies[1]
    unscanned = filter_run(virus=scan.Verdict(scan.UNSCANNED, "too large")).bodies[1]
    assert header(infected, report.REASON_HEADER) == scan.INFECTED
    assert header(unscanned, report.REASON_HEADER) == scan.UNSCANNED
    assert "found malware in it" in infected and "malware" not in unscanned


def test_a_message_the_scanner_failed_on_is_withheld_with_no_hold_and_its_own_report(filter_run):
    """The daemon failed on this message and still answers PING: *unscanned*, withheld in
    the quarantine with a report that says the scanner failed, and exit 0 - never the
    hold's 75, which would keep the mailbox and read as an outage."""
    run = filter_run(virus=scan.Verdict(
        scan.UNSCANNED, "clamd: Error writing to temporary file ERROR; the daemon answers "
        "PING, so it failed on this message", failed=True))
    assert run.code == 0
    assert run.folders == [(ARCHIVE, store.QUARANTINE)]
    assert header(run.bodies[0], marks.SCAN_HEADER) == scan.UNSCANNED
    assert header(run.bodies[1], report.REASON_HEADER) == scan.UNSCANNED
    assert "scanner failed on it" in run.bodies[1] and "too large" not in run.bodies[1]


def test_a_message_that_is_both_infected_and_spam_keeps_its_mark_in_quarantine(filter_run):
    run = filter_run("--spam-threshold", "1.00", score=scan.Score(9.0, "reject"),
                     virus=scan.Verdict(scan.INFECTED, "stream: Eicar FOUND"))
    assert header(run.bodies[0], marks.SPAM_MARK_HEADER) == "yes"
    assert "Subject: [spam] an ordinary message" in run.bodies[0]
    assert "[withheld] [spam] an ordinary message" in run.bodies[1]


def test_a_quarantine_folder_dovecot_will_not_make_stops_the_delivery(filter_run):
    """Nothing is delivered rather than delivered to the wrong folder: an agent handed
    a folder that does not exist files the message in INBOX and exits 0, where a withheld
    message would reach people. This proves (withheld,
    it reaches no one), not, which it was labelled with."""
    refused = deliver.doveadm.DoveadmError("doveadm mailbox create exited 75", 75)
    run = filter_run(virus=scan.Verdict(scan.INFECTED, "found"), folder_error=refused)
    assert run.code == deliver.EX_UNAVAILABLE == 69
    assert run.calls == []


@pytest.mark.parametrize("verdict", [scan.CLEAN, scan.INFECTED])
def test_every_message_filed_with_our_block_carries_our_own_report_fields(filter_run, verdict):
    """A field the pass reads is trusted in its first occurrence,
    which is ours only if we wrote one: a sender's `X-Maildivvy-Report-Reason` on clean
    mail made it a report, and a sender's withheld id pointed it at a withheld message
    whose release then took it from everybody. So the block always carries both."""
    forged = PLAIN.replace(b"\r\n\r\n", f"\r\n{report.REASON_HEADER}: infected\r\n"
                                        f"{report.WITHHELD_HEADER}: {'a' * 32}\r\n\r\n".encode())
    run = filter_run(raw=forged, virus=scan.Verdict(verdict, "detail"))
    reason = header(run.bodies[0], report.REASON_HEADER)
    withheld = header(run.bodies[0], report.WITHHELD_HEADER)
    assert reason == report.NONE
    if verdict == scan.CLEAN:
        assert withheld == report.NONE
    else:
        assert withheld not in (report.NONE, "a" * 32) and len(withheld) == 32


def test_input_that_starts_with_a_folded_line_does_not_continue_our_block(filter_run):
    """mpop writes its own `Received:` first, so this does not arrive from a fetch; the
    block must not depend on that. A first line that begins with whitespace is a
    continuation, and it must continue no header the product reads."""
    folded = f" {report.REASON_HEADER}: infected\r\n".encode() + PLAIN
    run = filter_run(raw=folded)
    stored = run.bodies[0]
    assert stored.encode().endswith(folded), "the sender's bytes are kept as they came"
    message = email.message_from_string(stored, policy=email.policy.default)
    for name in (report.REASON_HEADER, report.WITHHELD_HEADER):
        assert message[name] == report.NONE, name
    assert message[marks.SCAN_HEADER] == scan.CLEAN


def test_a_retried_withheld_message_is_not_stored_in_the_quarantine_twice(filter_run):
    """The report is saved after the quarantine copy; when its
    save fails the message stays at the provider, and every retry stored another copy
    under a new id. The id is the message's own now, so a retry finds its copy and
    writes only the report."""
    infected = scan.Verdict(scan.INFECTED, "found")
    first = filter_run(virus=infected)
    withheld = header(first.bodies[0], report.WITHHELD_HEADER)
    retried = filter_run(virus=infected, quarantine=[withheld])
    assert retried.code == 0 and len(retried.calls) == 1
    assert retried.argv(0) == AGENT_ARGS  # the report, into INBOX
    assert header(retried.bodies[0], report.WITHHELD_HEADER) == withheld
    # the control: another message's copy in the quarantine changes nothing
    other = filter_run(virus=infected, quarantine=["b" * 32])
    assert len(other.calls) == 2 and other.argv(0)[-1] == store.QUARANTINE


def test_the_withheld_id_is_the_same_on_every_retrieval_of_one_message():
    """mpop adds a Received line of its own, with the time, to every retrieval; it and
    the provider's are not what identifies the message."""
    one = b"Received: from pop (mpop) with POP3; Tue, 22 Sep 2026 10:00:00\r\n" + PLAIN
    two = (b"Received: from pop (mpop) with POP3;\r\n\tTue, 22 Sep 2026 10:03:00\r\n"
           + PLAIN)
    assert deliver.withheld_id_of(one) == deliver.withheld_id_of(two) \
        == deliver.withheld_id_of(PLAIN)
    assert len(deliver.withheld_id_of(PLAIN)) == 32
    assert deliver.withheld_id_of(PLAIN.replace(b"plain words", b"other words")) \
        != deliver.withheld_id_of(PLAIN)


def test_a_refused_report_comes_back_as_the_agents_exit_code(filter_run):
    run = filter_run(virus=scan.Verdict(scan.INFECTED, "found"), agent_exit=77)
    assert run.code == 77 and len(run.calls) == 1  # it stopped at the message


# --- the store, or this message -----------------------------------------------------


@pytest.mark.parametrize("agent_exit", [75, 77, 1])
def test_a_store_that_cannot_take_mail_is_the_stores_own_exit_whatever_the_agent_said(
        filter_run, capsys, agent_exit):
    run = filter_run(agent_exit=agent_exit, store_down="/srv/maildivvy/store has 0 bytes free")
    assert run.code == deliver.EX_CANTCREAT == 73
    assert run.probed == [None]  # INBOX, the folder this message was for
    said = capsys.readouterr().err
    assert f"exit {agent_exit}" in said and "0 bytes free" in said


def test_a_delivery_that_succeeds_never_asks_the_probe(filter_run):
    run = filter_run(store_down="never asked")
    assert run.code == 0 and run.probed == []


def test_the_agents_own_73_is_never_the_stores(filter_run):
    """73 from the filter means the store and nothing else."""
    assert filter_run(agent_exit=73).code == deliver.EX_IOERR


@pytest.mark.parametrize("store_down, code", [(None, 74), ("Dovecot did not answer", 73)])
def test_an_agent_that_does_not_answer_is_caught_and_asked_about(filter_run, monkeypatch,
                                                                 store_down, code):
    """The agent past its bound used to raise out of the filter."""
    def hung(*args, **kwargs):
        raise deliver.subprocess.TimeoutExpired("dovecot-lda", deliver.LDA_TIMEOUT)

    monkeypatch.setattr(deliver, "run_lda", hung)
    assert filter_run(store_down=store_down).code == code


def test_a_quarantine_store_that_cannot_take_mail_is_asked_about_its_own_folder(filter_run):
    run = filter_run(virus=scan.Verdict(scan.INFECTED, "found"), agent_exit=75,
                     store_down="no room")
    assert run.code == 73 and run.probed == [store.QUARANTINE]
    refused = deliver.doveadm.DoveadmError("doveadm mailbox create timed out after 300 s")
    run = filter_run(virus=scan.Verdict(scan.INFECTED, "found"), folder_error=refused,
                     store_down="Dovecot did not answer")
    assert run.code == 73 and run.calls == []


class FS:
    """An `os.statvfs` answer with room, unless the test says otherwise."""
    f_flag, f_bavail, f_frsize, f_files, f_favail = 0, 1 << 20, 4096, 1000, 900

    def __init__(self, **changed):
        self.__dict__.update(changed)


@pytest.fixture
def probe_store(tmp_path, monkeypatch):
    """The probe against a store and an index tree under `tmp_path`, Dovecot answering."""
    root, index_root = tmp_path / "store", tmp_path / "index"
    maildir = store.maildir(store.archive_home(DOMAIN, root))
    (maildir / "tmp").mkdir(parents=True)
    store.index_paths(DOMAIN, store.ARCHIVE, index_root)[0].mkdir(parents=True)
    asked = []
    monkeypatch.setattr(deliver.doveadm, "run",
                        lambda verb, login, *a, **kw: asked.append((verb, login, a)) or [{}])

    def probe(folder=None, size=100):
        return deliver.store_failure(DOMAIN, folder, size, root=root, index_root=index_root)

    probe.maildir, probe.asked = maildir, asked
    return probe


def test_a_store_with_room_that_dovecot_answers_for_is_not_the_failure(probe_store):
    assert probe_store() is None
    assert probe_store.asked == [(("mailbox", "status"), ARCHIVE, ("messages", "INBOX"))]


@pytest.mark.parametrize("fs, says", [
    (FS(f_bavail=0), "0 bytes free"),
    (FS(f_bavail=10), "40960 bytes free"),      # room, but not for this message and a margin
    (FS(f_favail=0), "no free inode"),
    (FS(f_flag=os.ST_RDONLY), "mounted read-only"),
])
def test_a_full_or_read_only_filesystem_is_the_stores_failure(probe_store, monkeypatch, fs, says):
    monkeypatch.setattr(deliver.os, "statvfs", lambda path: fs)
    assert says in probe_store()


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes into any directory")
def test_a_folder_the_mail_owner_may_not_write_is_the_stores_failure(probe_store):
    tmp = probe_store.maildir / "tmp"
    tmp.chmod(0o500)
    try:
        assert "not writable" in probe_store()
    finally:
        tmp.chmod(0o700)


def test_dovecot_not_answering_is_the_stores_failure(probe_store, monkeypatch):
    def silent(*args, **kwargs):
        raise deliver.doveadm.DoveadmError("doveadm mailbox status -u a timed out after 30 s")

    monkeypatch.setattr(deliver.doveadm, "run", silent)
    assert probe_store().startswith("Dovecot did not answer: ")


def test_a_folder_not_made_yet_is_probed_where_its_save_would_begin(probe_store, monkeypatch):
    seen = []
    monkeypatch.setattr(deliver.os, "statvfs", lambda path: seen.append(path) or FS())
    assert probe_store(folder=store.QUARANTINE) is None
    assert seen[0] == probe_store.maildir  # its own tmp/ is not there yet: the maildir is


# --- the antivirus hold ------------------------------------------------------


def ago(seconds):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


def test_an_unreachable_antivirus_exits_75_and_delivers_nothing(filter_run):
    run = filter_run(virus=scan.Verdict(scan.UNAVAILABLE, "clamd /run/clamav/clamd.ctl: no socket"))
    assert run.code == deliver.EX_TEMPFAIL == 75
    assert run.calls == []  # the message stays at the provider, unrecorded
    assert [kind for kind, _ in run.scanned] == ["virus"]  # not even scored


def test_the_hold_still_stands_inside_its_bound(filter_run):
    run = filter_run("--held-since", ago(60), "--hold-bound-seconds", "3600",
                     virus=scan.Verdict(scan.UNAVAILABLE, "no socket"))
    assert run.code == 75 and run.calls == []


def test_past_the_bound_the_message_is_delivered_marked_unavailable(filter_run):
    """A long outage delays mail by the bound; it does not stop it."""
    run = filter_run("--held-since", ago(7200), "--hold-bound-seconds", "3600",
                     virus=scan.Verdict(scan.UNAVAILABLE, "no socket"))
    assert run.code == 0 and len(run.calls) == 1
    assert header(run.bodies[0], marks.SCAN_HEADER) == scan.UNAVAILABLE
    assert run.argv(0) == AGENT_ARGS  # INBOX, not quarantine


def test_unavailable_is_delivered_and_unscanned_is_withheld_and_they_never_merge(filter_run):
    """*unscanned* is one message that is too big; *unavailable* is every message at once."""
    delivered = filter_run("--held-since", ago(7200), "--hold-bound-seconds", "0",
                           virus=scan.Verdict(scan.UNAVAILABLE, "no socket"))
    assert delivered.code == 0 and len(delivered.calls) == 1 and delivered.folders == []
    withheld = filter_run(virus=scan.Verdict(scan.UNSCANNED, "over the limit"))
    assert withheld.code == 0 and len(withheld.calls) == 2
    assert withheld.argv(0)[-1] == store.QUARANTINE


def test_a_held_since_that_is_not_a_time_is_refused_rather_than_guessed_at(filter_run):
    run = filter_run("--held-since", "an hour ago",
                     virus=scan.Verdict(scan.UNAVAILABLE, "no socket"))
    assert run.code == deliver.EX_USAGE and run.calls == []


def test_the_bound_defaults_to_an_hour():
    assert deliver.parse_args(["--domain", DOMAIN]).hold_bound_seconds == 3600
    assert deliver.parse_args(["--domain", DOMAIN]).held_since is None


NOW = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("seconds, bound, past", [
    (None, 3600, False),   # no hold has begun
    (10, 3600, False),
    (3600, 3600, False),   # at the bound it is still held
    (3601, 3600, True),
    (1, 0, True),          # a bound of zero delivers at once
])
def test_the_bound_is_measured_from_when_the_hold_began(seconds, bound, past):
    began = None if seconds is None else (NOW - timedelta(seconds=seconds)).isoformat()
    assert deliver.held_long_enough(began, bound, now=NOW) is past


def test_a_hold_stamped_without_a_time_zone_is_read_as_this_machines_clock():
    naive = (datetime.now() - timedelta(seconds=7200)).isoformat()
    assert deliver.held_long_enough(naive, 3600) is True
    assert deliver.held_long_enough(datetime.now().isoformat(), 3600) is False


# --- a message mpop stopped reading half-way is never stored --------------
#
# mpop 1.4.23 pipes a message into this filter as it reads it, and when the connection
# ends inside the body it leaves by its error path WITHOUT closing the pipe: the pipe is
# closed by its exit, so the filter reads end-of-file on half a message. On a message read
# to its end mpop closes the pipe and waits for the filter. The runner hands mpop both ends
# of a pipe of its own; mpop holds the write end until it exits, the filter closes its own
# copy at once, and end-of-file on the read end is then mpop gone.


class Retrieval:
    """The pipe the runner hands mpop, seen from the filter's side."""

    def __init__(self, monkeypatch):
        self.read, write = os.pipe()
        self.held = os.dup(write)       # mpop's own copy, which only its exit closes
        monkeypatch.setenv(retrieval.VARIABLE, f"{self.read} {write}")

    def ends(self):
        """mpop exits: its copy of the write end goes."""
        os.close(self.held)
        self.held = None

    def close(self):
        for fd in (self.read, self.held):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


@pytest.fixture
def a_retrieval(monkeypatch):
    made = Retrieval(monkeypatch)
    yield made
    made.close()


def test_a_message_the_retrieval_abandoned_is_scanned_perhaps_but_never_stored(filter_run,
                                                                                a_retrieval):
    a_retrieval.ends()
    run = filter_run()
    assert run.calls == [], "half a message was handed to the delivery agent"
    assert run.code == deliver.EX_IOERR and run.code != deliver.EX_TEMPFAIL


def test_a_message_the_retrieval_still_waits_for_is_stored(filter_run, a_retrieval):
    """The control: mpop alive and waiting in `pclose`, the message is filed as ever."""
    run = filter_run()
    assert run.code == 0 and len(run.calls) == 1


def test_a_withheld_message_the_retrieval_abandoned_leaves_no_report_either(filter_run,
                                                                           a_retrieval):
    a_retrieval.ends()
    run = filter_run(virus=scan.Verdict(scan.INFECTED, "stream: Eicar-Signature FOUND"))
    assert run.calls == [] and run.folders == []


def test_the_filter_keeps_no_copy_of_the_write_end_so_only_mpop_holds_it(filter_run,
                                                                         a_retrieval):
    write = int(os.environ[retrieval.VARIABLE].split()[1])
    filter_run()
    with pytest.raises(OSError):
        os.fstat(write)


@pytest.mark.parametrize("value", [None, "not a pipe", "998 999"])
def test_a_delivery_started_for_a_retrieval_without_its_pipe_files_and_says_so_in_the_recorded_words(
        filter_run, monkeypatch, capsys, value):
    """If the measured wiring regresses, the filter stored as before and
    said so only on a stderr nobody read, or not at all when the variable was gone. Started
    by the fetch (`--retrieval`), it still files - a wiring fault must not cost mail - and
    says `retrieval unchecked`, which the runner carries into its journal and health counts."""
    if value is None:
        monkeypatch.delenv(retrieval.VARIABLE, raising=False)
    else:
        monkeypatch.setenv(retrieval.VARIABLE, value)
    run = filter_run("--retrieval")
    assert run.code == 0 and len(run.calls) == 1
    assert retrieval.UNCHECKED in capsys.readouterr().err


def test_run_by_hand_with_no_retrieval_behind_it_the_filter_files_as_before(filter_run,
                                                                             monkeypatch):
    monkeypatch.delenv(retrieval.VARIABLE, raising=False)
    run = filter_run()
    assert run.code == 0 and len(run.calls) == 1


# --- a fault of the filter's own -------------------------------------------------------


def unreadable_conf(body):
    raise ValueError("StreamMaxLength is '50 M', which is not a size clamd would read")


def test_a_fault_that_a_message_of_the_filters_own_meets_too_holds_collection(filter_run,
                                                                              capsys):
    """A clamd.conf size it cannot read fails every message: exit 1 was read as this
    message's, and after the stuck hour it was skipped in every mailbox."""
    run = filter_run(scanning=unreadable_conf)
    assert run.code == deliver.EX_CANTCREAT and run.calls == []
    assert [body for _, body in run.scanned] == [PLAIN, deliver.CANNED]
    said = capsys.readouterr().err
    held = [line for line in said.splitlines() if line.startswith(deliver.STORE_SAID)]
    assert len(held) == 1 and "'50 M'" in held[0] and "collection holds" in held[0]


def test_a_delivery_agent_that_is_not_there_holds_collection(filter_run, tmp_path, capsys):
    run = filter_run("--lda", str(tmp_path / "no-such-agent"))
    assert run.code == deliver.EX_CANTCREAT and run.probed == [None]
    held = [line for line in capsys.readouterr().err.splitlines()
            if line.startswith(deliver.STORE_SAID)]
    assert "FileNotFoundError" in held[0] and "cannot be run" in held[0]


def test_a_fault_only_this_message_meets_is_its_own_and_the_store_is_not_blamed(filter_run,
                                                                               capsys):
    def this_one(body):
        if body == PLAIN:
            raise KeyError("something in this message")

    run = filter_run(scanning=this_one)
    assert run.code == deliver.EX_SOFTWARE and run.calls == []
    said = capsys.readouterr().err
    assert "KeyError" in said and deliver.STORE_SAID not in said


def test_the_canned_message_is_never_stored_and_never_handed_to_the_agent(filter_run,
                                                                          monkeypatch):
    stored = []
    monkeypatch.setattr(deliver, "run_lda", lambda *a, **kw: stored.append(a) or 1 / 0)
    run = filter_run()
    assert run.code == deliver.EX_SOFTWARE
    assert len(stored) == 1 and stored[0][2] != deliver.CANNED
