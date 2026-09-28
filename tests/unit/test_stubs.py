"""The stub provider itself: a POP3 server over implicit TLS and an SMTP relay sink
behind STARTTLS, each recording every command it received.

These tests prove the test infrastructure, not the product, so they prove no
requirement. They drive the stubs with the standard library's own clients, in-process, and
once each as a separate process under the distribution's python3 with no site
packages, the way the test VM runs them for mpop and Postfix.
"""

import base64
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
