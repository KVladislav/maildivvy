"""The stub providers themselves: a POP3 server and an IMAP server over implicit TLS and
an SMTP relay sink behind STARTTLS, each recording every command it received.

These tests prove the test infrastructure, not the product, so they prove no
requirement, but for the IMAP stub's refusal of every command outside the read-only set:
the decision on collection over IMAP rests its proof that nothing reached a
provider on it. They drive the stubs with the standard library's own clients,
in-process, and once each as a separate process under the distribution's python3 with no
site packages, the way the test VM runs them for mpop, Postfix and our IMAP client.
"""

import base64
import imaplib
import os
import poplib
import signal
import smtplib
import socket
import ssl
import subprocess
import time
from pathlib import Path

import pytest

import imap
import pop3
import smtp
from stubserver import make_certificate, read_log, write_control

STUBS = Path(__file__).resolve().parents[1] / "stubs"
DISTRIBUTION_PYTHON = "/usr/bin/python3"
USER = "alice@example.test"
PASSWORD = "app-pass word"
DAY = 86400


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    return make_certificate(tmp_path_factory.mktemp("tls"), "provider.stub.test")


def client_context(certificate):
    return ssl.create_default_context(cafile=certificate.ca)


# --------------------------------------------------------------------------- POP3


def put(mailbox, uidl, body, age_days=0):
    path = mailbox / uidl
    path.write_bytes(body)
    stamp = time.time() - age_days * DAY
    os.utime(path, (stamp, stamp))
    return path


@pytest.fixture
def provider(tmp_path, certificate):
    """A running POP3 stub with three messages; `rescript` changes its control file."""
    mailbox = tmp_path / "mailbox"
    mailbox.mkdir()
    put(mailbox, "m1", b"Subject: one\n\nfirst\n")
    put(mailbox, "m2", b"Subject: two\n\n.leading dot\nsecond\n")
    put(mailbox, "m3", b"Subject: three\n\nthird\n")
    control = tmp_path / "pop3.json"
    write_control(control, user=USER, password=PASSWORD)
    stub = pop3.POP3Stub(mailbox, cert=certificate.cert, key=certificate.key,
                         log=tmp_path / "pop3.log", control=control)
    stub.mailbox_dir = mailbox
    stub.control_file = control
    with stub:
        yield stub


def rescript(stub, **settings):
    write_control(stub.control_file, **{"user": USER, "password": PASSWORD, **settings})


def pop(stub, certificate, timeout=5):
    return poplib.POP3_SSL("127.0.0.1", stub.port, context=client_context(certificate),
                           timeout=timeout)


def logged_in(stub, certificate, user=USER):
    client = pop(stub, certificate)
    client.user(user)
    client.pass_(PASSWORD)
    return client


def commands(stub, session=None):
    return [(r["command"], r["argument"]) for r in read_log(stub.log_path)
            if "command" in r and (session is None or r["session"] == session)]


def uidls(client):
    return [line.decode().split(" ", 1)[1] for line in client.uidl()[1]]


class RawSession:
    """A TLS socket driven line by line, to see exactly what a fault sends."""

    def __init__(self, stub, certificate, timeout=5):
        raw = socket.create_connection(("127.0.0.1", stub.port), timeout=timeout)
        self.sock = client_context(certificate).wrap_socket(raw, server_hostname="127.0.0.1")
        self.greeting = self.receive()

    def receive(self):
        data = b""
        while not data.endswith(b"\r\n"):
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def ask(self, line):
        self.sock.sendall(line.encode() + b"\r\n")
        return self.receive()

    def rest(self):
        """Everything until the server closes, or TimeoutError while it stays silent."""
        data = b""
        while chunk := self.sock.recv(4096):
            data += chunk
        return data

    def login(self):
        assert self.ask(f"USER {USER}").startswith(b"+OK")
        assert self.ask(f"PASS {PASSWORD}").startswith(b"+OK")

    def close(self):
        self.sock.close()


def test_pop3_speaks_only_implicit_tls_with_the_generated_certificate(provider, certificate):
    client = pop(provider, certificate)
    assert client.getwelcome().startswith(b"+OK")
    client.quit()

    with socket.create_connection(("127.0.0.1", provider.port), timeout=2) as plain:
        plain.sendall(b"CAPA\r\n")
        try:
            answer = plain.recv(4096)
        except (ConnectionResetError, TimeoutError):
            answer = b""
    assert not answer.startswith(b"+OK")


def test_pop3_user_pass_uidl_retr_and_every_command_recorded(provider, certificate):
    client = logged_in(provider, certificate)
    assert client.stat() == (3, sum(len(b) for b in (
        b"Subject: one\r\n\r\nfirst\r\n",
        b"Subject: two\r\n\r\n.leading dot\r\nsecond\r\n",
        b"Subject: three\r\n\r\nthird\r\n")))
    assert uidls(client) == ["m1", "m2", "m3"]
    assert client.retr(2)[1] == [b"Subject: two", b"", b".leading dot", b"second"]
    client.quit()

    assert commands(provider) == [
        ("USER", USER), ("PASS", PASSWORD), ("STAT", ""), ("UIDL", ""), ("RETR", "2"), ("QUIT", "")]


def test_pop3_list_size_is_the_octets_sent(provider, certificate):
    client = logged_in(provider, certificate)
    _, lines, _ = client.list()
    sizes = dict(line.decode().split() for line in lines)
    assert sizes == {"1": str(len(b"Subject: one\r\n\r\nfirst\r\n")),
                     "2": str(len(b"Subject: two\r\n\r\n.leading dot\r\nsecond\r\n")),
                     "3": str(len(b"Subject: three\r\n\r\nthird\r\n"))}
    client.quit()


def test_pop3_dele_is_performed_at_quit_and_not_when_the_session_drops(provider, certificate):
    client = logged_in(provider, certificate)
    client.dele(1)
    client.dele(2)
    client.rset()
    client.dele(1)
    assert uidls(client) == ["m2", "m3"]
    client.quit()
    assert sorted(p.name for p in provider.mailbox_dir.iterdir()) == ["m2", "m3"]

    session = RawSession(provider, certificate)
    session.login()
    assert session.ask("DELE 1").startswith(b"+OK")
    session.close()  # no QUIT: RFC 1939 keeps the message
    time.sleep(0.2)

    client = logged_in(provider, certificate)
    assert uidls(client) == ["m2", "m3"]
    client.quit()
    assert ("DELE", "1") in commands(provider)


def test_pop3_refuses_a_wrong_password_and_a_scripted_refusal(provider, certificate):
    client = pop(provider, certificate)
    client.user(USER)
    with pytest.raises(poplib.error_proto, match="AUTH"):
        client.pass_("wrong")

    rescript(provider, faults=[{"command": "PASS", "action": "err"}])
    client = pop(provider, certificate)
    client.user(USER)
    with pytest.raises(poplib.error_proto, match="AUTH"):
        client.pass_(PASSWORD)

    rescript(provider)  # the control: the same login is accepted again
    logged_in(provider, certificate).quit()


def test_pop3_answers_err_on_one_retr_and_serves_the_others(provider, certificate):
    rescript(provider, faults=[{"command": "RETR", "uidl": "m2", "action": "err"}])
    client = logged_in(provider, certificate)
    assert client.retr(1)[1][-1] == b"first"
    with pytest.raises(poplib.error_proto):
        client.retr(2)
    assert client.retr(3)[1][-1] == b"third"
    client.quit()


def test_pop3_drops_the_connection_at_retr_without_answering(provider, certificate):
    rescript(provider, faults=[{"command": "RETR", "uidl": "m1", "action": "drop"}])
    session = RawSession(provider, certificate)
    session.login()
    assert session.ask("RETR 1") == b""
    assert ("RETR", "1") in commands(provider)


def test_pop3_truncates_a_message_body_and_closes(provider, certificate):
    rescript(provider, faults=[{"command": "RETR", "uidl": "m1", "action": "truncate"}])
    session = RawSession(provider, certificate)
    session.login()
    answer = session.ask("RETR 1") + session.rest()
    assert answer.startswith(b"+OK")
    assert not answer.endswith(b"\r\n.\r\n")


def test_pop3_hangs_inside_a_body_until_the_stub_stops(provider, certificate):
    rescript(provider, faults=[{"command": "RETR", "uidl": "m3", "action": "hang"}])
    session = RawSession(provider, certificate, timeout=1)
    session.login()
    assert session.ask("RETR 3").startswith(b"+OK")
    with pytest.raises(TimeoutError):
        session.rest()

    started = time.monotonic()
    provider.stop()
    assert time.monotonic() - started < 3
    session.sock.settimeout(3)
    assert session.rest() == b""


def test_pop3_hangs_without_answering_a_command(provider, certificate):
    rescript(provider, faults=[{"command": "PASS", "action": "hang"}])
    session = RawSession(provider, certificate, timeout=1)
    assert session.ask(f"USER {USER}").startswith(b"+OK")
    with pytest.raises(TimeoutError):
        session.ask(f"PASS {PASSWORD}")


def test_pop3_login_delay_advertised_and_enforced_only_when_scripted(provider, certificate):
    rescript(provider, login_delay=300)
    client = logged_in(provider, certificate)
    assert client.capa()["LOGIN-DELAY"] == ["300"]
    client.quit()
    logged_in(provider, certificate).quit()  # declared, not enforced: a second login passes

    rescript(provider, login_delay=300, enforce_login_delay=True)
    client = pop(provider, certificate)
    client.user(USER)
    with pytest.raises(poplib.error_proto, match=r"\[LOGIN-DELAY\]"):
        client.pass_(PASSWORD)


def test_pop3_plain_login_offers_every_message_until_deleted(provider, certificate):
    put(provider.mailbox_dir, "old", b"Subject: old\n\nold\n", age_days=45)
    for _ in range(2):
        client = logged_in(provider, certificate)
        assert uidls(client) == ["m1", "m2", "m3", "old"]
        client.retr(4)
        client.quit()


def test_pop3_recent_login_reoffers_the_last_n_days_on_every_session(provider, certificate):
    put(provider.mailbox_dir, "old", b"Subject: old\n\nold\n", age_days=45)
    put(provider.mailbox_dir, "week", b"Subject: week\n\nweek\n", age_days=7)
    for _ in range(2):
        client = logged_in(provider, certificate, user=f"recent:{USER}")
        assert uidls(client) == ["m1", "m2", "m3", "week"]
        for number in range(1, 5):
            client.retr(number)
        client.quit()

    rescript(provider, recent_days=5)
    client = logged_in(provider, certificate, user=f"recent:{USER}")
    assert uidls(client) == ["m1", "m2", "m3"]
    client.quit()
    assert ("USER", f"recent:{USER}") in commands(provider)


def test_pop3_a_login_is_matched_byte_for_byte(provider, certificate):
    client = pop(provider, certificate)
    client.user(USER.upper())
    with pytest.raises(poplib.error_proto):
        client.pass_(PASSWORD)
    assert ("USER", USER.upper()) in commands(provider)


def test_pop3_serves_an_identifier_with_a_space(provider, certificate):
    put(provider.mailbox_dir, "has a space", b"Subject: s\n\ns\n")
    client = logged_in(provider, certificate)
    assert uidls(client)[0] == "has a space"
    client.quit()


# --------------------------------------------------------------------------- IMAP


@pytest.fixture
def mailstore(tmp_path, certificate):
    """A running IMAP stub: three messages in the INBOX, one in `Archive/2025`, and a
    Gmail-like `[Gmail]` that cannot be opened above an `All Mail` marked as all mail."""
    account = tmp_path / "account"
    for folder, uids in (("INBOX", (1, 2, 3)), ("Archive/2025", (7,)), ("[Gmail]/All Mail", (9,))):
        (account / folder).mkdir(parents=True)
        for uid in uids:
            (account / folder / str(uid)).write_bytes(f"Subject: {uid}\n\nbody {uid}\n".encode())
    control = tmp_path / "imap.json"
    stub = imap.IMAPStub(account, cert=certificate.cert, key=certificate.key,
                         log=tmp_path / "imap.log", control=control)
    stub.account = account
    stub.control_file = control
    reimap(stub)
    with stub:
        yield stub


GMAIL = {"[Gmail]": ["\\Noselect", "\\HasChildren"], "[Gmail]/All Mail": ["\\All"]}


def reimap(stub, **settings):
    write_control(stub.control_file, **{"user": USER, "password": PASSWORD, "attributes": GMAIL,
                                        **settings})


def imap_client(stub, certificate, timeout=5):
    return imaplib.IMAP4_SSL("127.0.0.1", stub.port, ssl_context=client_context(certificate),
                             timeout=timeout)


def examined(stub, certificate, folder="INBOX", timeout=5):
    client = imap_client(stub, certificate, timeout)
    client.login(USER, PASSWORD)
    client.select(f'"{folder}"', readonly=True)
    return client


def imap_events(stub, kind):
    return [r for r in read_log(stub.log_path) if r.get("event") == kind]


def test_imap_reads_by_uid_and_records_uid_commands_with_their_sub_command(mailstore,
                                                                         certificate):
    client = imap_client(mailstore, certificate)
    assert "AUTH=PLAIN" in client.capabilities
    client.login(USER, PASSWORD)
    typ, [count] = client.select('"INBOX"', readonly=True)
    assert (typ, count) == ("OK", b"3")
    assert client.response("UIDVALIDITY")[1] == [b"1"]
    assert client.response("UIDNEXT")[1] == [b"4"]
    assert client.uid("SEARCH", "UID", "2:*") == ("OK", [b"2 3"])
    typ, data = client.uid("FETCH", "2", "(BODY.PEEK[] FLAGS INTERNALDATE)")
    head, body = data[0]
    assert body == b"Subject: 2\r\n\r\nbody 2\r\n"
    assert head.startswith(b"2 (UID 2 FLAGS () INTERNALDATE ")
    assert head.endswith(b" BODY[] {%d}" % len(body))
    client.noop()
    client.logout()

    assert commands(mailstore) == [
        ("CAPABILITY", ""), ("LOGIN", f'{USER} "{PASSWORD}"'), ("EXAMINE", '"INBOX"'),
        ("UID SEARCH", "UID 2:*"), ("UID FETCH", "2 (BODY.PEEK[] FLAGS INTERNALDATE)"),
        ("NOOP", ""), ("LOGOUT", "")]
    assert imap_events(mailstore, "refused") == []


def test_imap_refuses_every_command_outside_the_read_only_set_and_logs_it(mailstore,
                                                                        certificate):
    client = examined(mailstore, certificate)
    attempts = {
        "STORE": lambda: client.store("1", "+FLAGS", "(\\Deleted)"),
        "UID STORE": lambda: client.uid("STORE", "1", "+FLAGS", "(\\Seen)"),
        "UID FETCH": lambda: client.uid("FETCH", "1", "(BODY[])"),
        "UID FETCH ": lambda: client.uid("FETCH", "1", "(RFC822.HEADER)"),  # not one it serves
        "EXPUNGE": lambda: client.expunge(),
        "CREATE": lambda: client.create("New"),
        "SELECT": lambda: client.select('"INBOX"'),
    }
    for attempt in attempts.values():
        with pytest.raises(imaplib.IMAP4.error, match="BAD"):
            attempt()
    with pytest.raises(imaplib.IMAP4.error, match="BAD"):
        imap_client(mailstore, certificate).login_cram_md5(USER, PASSWORD)

    refused = [r["command"] for r in imap_events(mailstore, "refused")]
    assert refused == [*(name.strip() for name in attempts), "AUTHENTICATE"]
    assert sorted(p.name for p in (mailstore.account / "INBOX").iterdir()) == ["1", "2", "3"]


def test_imap_auth_plain_carries_utf8_and_login_stands_alone_when_plain_is_not_offered(
        mailstore, certificate):
    reimap(mailstore, password="пароль")
    client = imap_client(mailstore, certificate)
    client.authenticate("PLAIN", lambda _: f"\0{USER}\0пароль")
    client.logout()

    reimap(mailstore, plain=False)
    client = imap_client(mailstore, certificate)
    assert "AUTH=PLAIN" not in client.capabilities
    client.login(USER, PASSWORD)
    client.logout()
    assert [(e["mechanism"], e["password"], e["accepted"]) for e in imap_events(mailstore, "auth")] \
        == [("PLAIN", "пароль", True), ("LOGIN", PASSWORD, True)]


def test_imap_refuses_a_wrong_password_and_a_scripted_refusal(mailstore, certificate):
    with pytest.raises(imaplib.IMAP4.error, match="AUTHENTICATIONFAILED"):
        imap_client(mailstore, certificate).login(USER, "wrong")

    reimap(mailstore, faults=[{"command": "LOGIN", "action": "no"}])
    with pytest.raises(imaplib.IMAP4.error, match="AUTHENTICATIONFAILED"):
        imap_client(mailstore, certificate).login(USER, PASSWORD)

    reimap(mailstore, faults=[{"command": "AUTHENTICATE", "action": "no", "text": "go away"}])
    with pytest.raises(imaplib.IMAP4.error, match="go away"):
        imap_client(mailstore, certificate).authenticate("PLAIN", lambda _: f"\0{USER}\0{PASSWORD}")

    reimap(mailstore)  # the control: the same login is accepted again
    imap_client(mailstore, certificate).login(USER, PASSWORD)


def test_imap_lists_every_folder_with_its_attributes_and_will_not_examine_a_noselect_one(
        mailstore, certificate):
    """It lists what the client asks, `"" "*"`, and answers any other listing BAD."""
    client = imap_client(mailstore, certificate)
    client.login(USER, PASSWORD)
    typ, listed = client.list('""', '"*"')
    assert listed == [b'() "/" "Archive"', b'() "/" "Archive/2025"', b'() "/" "INBOX"',
                      b'(\\Noselect \\HasChildren) "/" "[Gmail]"', b'(\\All) "/" "[Gmail]/All Mail"']
    with pytest.raises(imaplib.IMAP4.error, match="BAD"):
        client.list('""', '"%"')
    assert client.select('"[Gmail]"', readonly=True)[0] == "NO"
    assert client.select('"[Gmail]/All Mail"', readonly=True) == ("OK", [b"1"])
    assert client.uid("SEARCH", "UID", "1:9") == ("OK", [b"9"])
    assert imap_events(mailstore, "refused") == []


def test_imap_searches_one_uid_range_and_above_the_largest_answers_the_largest(mailstore,
                                                                              certificate):
    """RFC 9051: `*` is the largest UID in use and a range is read in either order. A set of
    several ranges, or a search by anything but UID, is not what the client sends: BAD."""
    client = examined(mailstore, certificate)
    assert client.uid("SEARCH", "UID", "4:*") == ("OK", [b"3"])
    assert client.uid("SEARCH", "UID", "2:3") == ("OK", [b"2 3"])
    assert client.uid("SEARCH", "UID", "*") == ("OK", [b"3"])
    for unserved in (("UID", "1,3"), ("ALL",)):
        with pytest.raises(imaplib.IMAP4.error, match="BAD"):
            client.uid("SEARCH", *unserved)
    assert imap_events(mailstore, "refused") == []


def test_imap_says_no_uidvalidity_for_a_folder_scripted_to_have_none(mailstore, certificate):
    reimap(mailstore, uidvalidity={"INBOX": None})
    client = examined(mailstore, certificate)
    assert client.response("UIDVALIDITY")[1] == [None]
    assert client.response("UIDNEXT")[1] == [b"4"]


def test_imap_uidvalidity_changes_between_sessions_when_rescripted(mailstore, certificate):
    examined(mailstore, certificate).logout()
    reimap(mailstore, uidvalidity={"INBOX": 99})
    client = examined(mailstore, certificate)
    assert client.response("UIDVALIDITY")[1] == [b"99"]


def test_imap_answers_no_on_one_uid_and_serves_the_others(mailstore, certificate):
    reimap(mailstore, faults=[{"command": "UID FETCH", "uid": 2, "action": "no"}])
    client = examined(mailstore, certificate)
    assert client.uid("FETCH", "2", "(BODY.PEEK[])")[0] == "NO"
    assert client.uid("FETCH", "3", "(BODY.PEEK[])")[1][0][1] == b"Subject: 3\r\n\r\nbody 3\r\n"


def test_imap_expunged_answers_ok_with_nothing_as_does_a_message_removed(mailstore,
                                                                       certificate):
    reimap(mailstore, faults=[{"command": "UID FETCH", "uid": 2, "action": "expunged"}])
    client = examined(mailstore, certificate)
    assert client.uid("FETCH", "2", "(BODY.PEEK[])") == ("OK", [None])
    (mailstore.account / "INBOX" / "3").unlink()
    assert client.uid("FETCH", "3", "(BODY.PEEK[])") == ("OK", [None])
    assert [r["uid"] for r in imap_events(mailstore, "fault")] == [2]
    # gone for that session, as an expunge is: no search lists either any more
    assert client.uid("SEARCH", "UID", "1:3") == ("OK", [b"1"])


def test_imap_answers_bad_on_one_uid_and_serves_the_others(mailstore, certificate):
    reimap(mailstore, faults=[{"command": "UID FETCH", "uid": 2, "action": "bad",
                               "text": "Command Argument Error. 11"}])
    client = examined(mailstore, certificate)
    with pytest.raises(imaplib.IMAP4.error, match="Command Argument Error"):
        client.uid("FETCH", "2", "(BODY.PEEK[])")
    assert client.uid("FETCH", "3", "(BODY.PEEK[])")[1][0][1] == b"Subject: 3\r\n\r\nbody 3\r\n"


@pytest.mark.parametrize("action, answer", [
    ("flags-first", [b"2 (UID 2 FLAGS (\\Seen))",
                     (b"2 (UID 2 FLAGS (\\Seen) BODY[] {22}", b"Subject: 2\r\n\r\nbody 2\r\n"),
                     b")"]),
    ("nobody", [b"2 (UID 2 FLAGS (\\Seen))"]),
    ("no-uid", [(b"2 (FLAGS (\\Seen) BODY[] {22}", b"Subject: 2\r\n\r\nbody 2\r\n"), b")"]),
])
def test_imap_answers_a_fetch_the_ways_a_server_may_and_a_careless_one_does(
        mailstore, certificate, action, answer):
    """Its flags in a response of their own before the message, its flags with no body, or
    the message in a response that leaves its UID out."""
    reimap(mailstore, flags={"INBOX": {"2": ["\\Seen"]}},
           faults=[{"command": "UID FETCH", "uid": 2, "action": action}])
    client = examined(mailstore, certificate)
    assert client.uid("FETCH", "2", "(BODY.PEEK[] FLAGS)") == ("OK", answer)


def test_imap_truncates_a_literal_and_closes(mailstore, certificate):
    reimap(mailstore, faults=[{"command": "UID FETCH", "uid": 1, "action": "truncate"}])
    client = examined(mailstore, certificate)
    with pytest.raises(imaplib.IMAP4.abort):
        client.uid("FETCH", "1", "(BODY.PEEK[])")


def test_imap_drops_and_hangs_when_scripted(mailstore, certificate):
    reimap(mailstore, faults=[{"command": "UID FETCH", "uid": 1, "action": "drop"}])
    client = examined(mailstore, certificate)
    with pytest.raises(imaplib.IMAP4.abort):
        client.uid("FETCH", "1", "(BODY.PEEK[])")

    reimap(mailstore, faults=[{"command": "EXAMINE", "action": "hang"}])
    with pytest.raises(TimeoutError):
        examined(mailstore, certificate, timeout=1)


def test_imap_trickles_a_literal_a_byte_at_a_time(mailstore, certificate):
    reimap(mailstore, faults=[{"command": "UID FETCH", "uid": 1, "action": "trickle",
                               "delay": 0.02}])
    client = examined(mailstore, certificate)
    body = b"Subject: 1\r\n\r\nbody 1\r\n"
    started = time.monotonic()
    assert client.uid("FETCH", "1", "(BODY.PEEK[])")[1][0][1] == body
    assert time.monotonic() - started >= 0.02 * (len(body) - 1)


# --------------------------------------------------------------------------- SMTP

ACCOUNTS = {"alice@example.test": "alice-secret", "bob@example.test": "bob-secret"}


@pytest.fixture
def relay(tmp_path, certificate):
    control = tmp_path / "smtp.json"
    write_control(control, accounts=ACCOUNTS)
    stub = smtp.SMTPStub(cert=certificate.cert, key=certificate.key,
                         log=tmp_path / "smtp.log", control=control)
    stub.control_file = control
    with stub:
        yield stub


def smtp_client(stub, certificate):
    client = smtplib.SMTP("127.0.0.1", stub.port, timeout=5)
    client.ehlo("client.test")
    return client


def secured(stub, certificate):
    client = smtp_client(stub, certificate)
    client.starttls(context=client_context(certificate))
    client.ehlo("client.test")
    return client


def events(stub, kind):
    return [r for r in read_log(stub.log_path) if r.get("event") == kind]


MESSAGE = b"From: alice@example.test\r\nSubject: hi\r\n\r\n.dotted line\r\nbody\r\n"


def test_smtp_records_auth_envelope_and_data(relay, certificate):
    client = secured(relay, certificate)
    assert "PLAIN" in client.esmtp_features["auth"]
    client.login("alice@example.test", "alice-secret")
    client.sendmail("alice@example.test", ["r1@elsewhere.test", "r2@elsewhere.test"], MESSAGE)
    client.quit()

    [auth] = events(relay, "auth")
    assert auth == {**auth, "user": "alice@example.test", "password": "alice-secret",
                    "accepted": True}
    [message] = events(relay, "message")
    assert message["auth_user"] == "alice@example.test"
    assert message["mail_from"] == "alice@example.test"
    assert message["rcpt_to"] == ["r1@elsewhere.test", "r2@elsewhere.test"]
    assert message["data"].encode("latin-1") == MESSAGE
    recorded = [r["command"] for r in read_log(relay.log_path) if "command" in r]
    assert recorded[:3] == ["EHLO", "STARTTLS", "EHLO"]
    assert {"AUTH", "MAIL", "RCPT", "DATA", "QUIT"} <= set(recorded)


def test_smtp_auth_login_names_the_account_that_sent(relay, certificate):
    client = secured(relay, certificate)
    client.user, client.password = "bob@example.test", "bob-secret"
    client.auth("LOGIN", client.auth_login)
    client.sendmail("bob@example.test", ["r@elsewhere.test"], MESSAGE)
    client.quit()
    [message] = events(relay, "message")
    assert message["auth_user"] == "bob@example.test"


def test_smtp_auth_plain_with_a_continuation(relay, certificate):
    client = secured(relay, certificate)
    assert client.docmd("AUTH", "PLAIN")[0] == 334
    token = base64.b64encode(b"\0alice@example.test\0alice-secret").decode()
    assert client.docmd(token)[0] == 235
    client.quit()


def test_smtp_refuses_auth_before_starttls_and_mail_before_auth(relay, certificate):
    client = smtp_client(relay, certificate)
    assert "auth" not in client.esmtp_features
    assert "starttls" in client.esmtp_features
    token = base64.b64encode(b"\0alice@example.test\0alice-secret").decode()
    assert client.docmd("AUTH", f"PLAIN {token}")[0] == 530
    client.quit()

    client = secured(relay, certificate)
    assert client.mail("alice@example.test")[0] == 530
    client.quit()
    assert events(relay, "message") == []


def test_smtp_speaks_implicit_tls_from_the_first_byte_when_scripted(relay, certificate):
    """A provider's port 465 is TLS before the greeting, with AUTH offered at once."""
    write_control(relay.control_file, accounts=ACCOUNTS, implicit_tls=True)
    client = smtplib.SMTP_SSL("127.0.0.1", relay.port, timeout=5, context=client_context(certificate))
    client.ehlo("client.test")
    assert "starttls" not in client.esmtp_features
    client.login("alice@example.test", "alice-secret")
    client.sendmail("alice@example.test", ["r@elsewhere.test"], MESSAGE)
    client.quit()
    [message] = events(relay, "message")
    assert message["auth_user"] == "alice@example.test"
    # the control: a client that waits for a greeting in clear text is never given one
    plain = socket.create_connection(("127.0.0.1", relay.port), timeout=1)
    with pytest.raises(TimeoutError):
        plain.recv(100)
    plain.close()


def test_smtp_refuses_a_wrong_password_and_a_scripted_refusal(relay, certificate):
    client = secured(relay, certificate)
    with pytest.raises(smtplib.SMTPAuthenticationError) as refused:
        client.login("alice@example.test", "bob-secret")
    assert refused.value.smtp_code == 535

    write_control(relay.control_file, accounts=ACCOUNTS, refuse_auth=True)
    client = secured(relay, certificate)
    with pytest.raises(smtplib.SMTPAuthenticationError):
        client.login("alice@example.test", "alice-secret")

    write_control(relay.control_file, accounts=ACCOUNTS)  # the control
    client = secured(relay, certificate)
    client.login("alice@example.test", "alice-secret")
    client.quit()
    verdicts = [(e["user"], e["accepted"]) for e in events(relay, "auth")]
    assert verdicts[-1] == ("alice@example.test", True)
    assert {accepted for _, accepted in verdicts[:-1]} == {False}


def test_smtp_refuses_a_scripted_recipient_at_rcpt_and_another_after_data(relay, certificate):
    write_control(relay.control_file, accounts=ACCOUNTS, refuse_rcpt=["gone@elsewhere.test"],
                  refuse_data=["small@elsewhere.test"])
    client = secured(relay, certificate)
    client.login("alice@example.test", "alice-secret")
    with pytest.raises(smtplib.SMTPRecipientsRefused) as refused:
        client.sendmail("alice@example.test", ["gone@elsewhere.test"], MESSAGE)
    assert refused.value.recipients["gone@elsewhere.test"][0] == 550
    with pytest.raises(smtplib.SMTPDataError) as refused:
        client.sendmail("alice@example.test", ["small@elsewhere.test"], MESSAGE)
    assert refused.value.smtp_code == 552
    client.sendmail("alice@example.test", ["r@elsewhere.test"], MESSAGE)  # the control
    client.quit()
    assert [m["rcpt_to"] for m in events(relay, "message")] == [["r@elsewhere.test"]]


# --------------------------------------------------------------------------- as a process


def start_process(script, tmp_path, certificate, *extra):
    process = subprocess.Popen(
        # -S -E -s: no site packages, no environment, no user site: the standard library only
        [DISTRIBUTION_PYTHON, "-S", "-E", "-s", str(STUBS / script),
         "--listen", "127.0.0.1:0", "--cert", str(certificate.cert),
         "--key", str(certificate.key), "--log", str(tmp_path / f"{script}.log"),
         "--control", str(tmp_path / f"{script}.json"), *extra],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = process.stdout.readline().split()
    assert line[:2] == ["listening", "127.0.0.1"], process.stderr.read()
    return process, int(line[2])


def stop_process(process):
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=5) == 0, process.stderr.read()


def test_pop3_runs_as_a_process_on_the_standard_library_alone(tmp_path, certificate):
    mailbox = tmp_path / "mailbox"
    mailbox.mkdir()
    put(mailbox, "m1", b"Subject: one\n\nfirst\n")
    write_control(tmp_path / "pop3.py.json", user=USER, password=PASSWORD)
    process, port = start_process("pop3.py", tmp_path, certificate, "--mailbox", str(mailbox))
    try:
        client = poplib.POP3_SSL("127.0.0.1", port, context=client_context(certificate),
                                 timeout=5)
        client.user(USER)
        client.pass_(PASSWORD)
        assert uidls(client) == ["m1"]
        client.quit()
    finally:
        stop_process(process)
    assert ("UIDL", "") in [(r["command"], r["argument"])
                            for r in read_log(tmp_path / "pop3.py.log") if "command" in r]


def test_smtp_runs_as_a_process_on_the_standard_library_alone(tmp_path, certificate):
    write_control(tmp_path / "smtp.py.json", accounts=ACCOUNTS)
    process, port = start_process("smtp.py", tmp_path, certificate)
    try:
        client = smtplib.SMTP("127.0.0.1", port, timeout=5)
        client.starttls(context=client_context(certificate))
        client.login("alice@example.test", "alice-secret")
        client.sendmail("alice@example.test", ["r@elsewhere.test"], MESSAGE)
        client.quit()
    finally:
        stop_process(process)
    [message] = [r for r in read_log(tmp_path / "smtp.py.log") if r.get("event") == "message"]
    assert message["rcpt_to"] == ["r@elsewhere.test"]


def test_imap_runs_as_a_process_on_the_standard_library_alone(tmp_path, certificate):
    inbox = tmp_path / "account" / "INBOX"
    inbox.mkdir(parents=True)
    (inbox / "1").write_bytes(b"Subject: one\n\nfirst\n")
    write_control(tmp_path / "imap.py.json", user=USER, password=PASSWORD)
    process, port = start_process("imap.py", tmp_path, certificate,
                                  "--mailbox", str(tmp_path / "account"))
    try:
        client = imaplib.IMAP4_SSL("127.0.0.1", port, ssl_context=client_context(certificate),
                                   timeout=5)
        client.login(USER, PASSWORD)
        client.select('"INBOX"', readonly=True)
        assert client.uid("SEARCH", "UID", "1:*") == ("OK", [b"1"])
        client.logout()
    finally:
        stop_process(process)
    assert ("UID SEARCH", "UID 1:*") in [(r["command"], r["argument"])
                                     for r in read_log(tmp_path / "imap.py.log") if "command" in r]
