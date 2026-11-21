"""Our own IMAP client: the read-only guard, the transport and its pin, the login,
and reading the INBOX by UID, against the stub provider in-process.

The stub's certificate authority stands for the machine's trust store through
`SSL_CERT_FILE`, which OpenSSL reads for its default verification paths, the ones the
client's context loads: the client has no trust setting of its own to point at it.
"""

import imaplib
import os
import re
import shutil
import socket
import ssl
import time

import pytest

import imap as stub_imap
from maildivvy.fetch import imap
from stubserver import make_certificate, read_log, write_control

USER = "alice@example.test"
PASSWORD = "app-pass word"
HOST = "127.0.0.1"
READ_ONLY = {"CAPABILITY", "LOGIN", "AUTHENTICATE", "LIST", "EXAMINE", "UID SEARCH",
             "UID FETCH", "NOOP", "LOGOUT"}


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    return make_certificate(tmp_path_factory.mktemp("certificate"), "provider.stub.test")


@pytest.fixture
def trusted(certificate, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate.ca))


@pytest.fixture
def untrusted(monkeypatch):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)


def put(folder, uid, body):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / str(uid)).write_bytes(body)


@pytest.fixture
def provider(tmp_path, certificate):
    """A running stub with three messages in its INBOX; `rescript` changes its control file."""
    account = tmp_path / "account"
    for uid in (1, 2, 3):
        put(account / "INBOX", uid, f"Subject: {uid}\n\nmessage {uid}\n".encode())
    stub = stub_imap.IMAPStub(account, cert=certificate.cert, key=certificate.key,
                              log=tmp_path / "imap.log", control=tmp_path / "imap.json")
    stub.inbox = account / "INBOX"
    rescript(stub)
    with stub:
        yield stub


def rescript(stub, **settings):
    write_control(stub.control_path, **{"user": USER, "password": PASSWORD, **settings})


def connect(stub, pin=None, seconds=10, read_bound=imap.READ_BOUND):
    return imap.connect(HOST, stub.port, pin, time.monotonic() + seconds, read_bound)


def opened(stub, **kwargs):
    session = connect(stub, **kwargs)
    session.login(USER, PASSWORD)
    session.examine(imap.INBOX)
    return session


# imaplib sends CAPABILITY only when the greeting did not carry the capabilities: CPython
# 3.14.10 reads them from the greeting's response code, 3.14.4 asked. Either is a read, so
# the tests hold what the client sends besides it.
def commands(stub):
    return [(r["command"], r["argument"]) for r in read_log(stub.log_path)
            if "command" in r and r["command"] != "CAPABILITY"]


def events(stub, kind):
    return [r for r in read_log(stub.log_path) if r.get("event") == kind]


def pin_of(certificate):
    der = ssl.PEM_cert_to_DER_cert(certificate.cert.read_text())
    digest = imap.fingerprint(der)
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


# --- reading, and nothing else ---------------------------------------------------------


def test_a_whole_read_sends_only_commands_that_read_and_peeks_at_every_body(provider, trusted):
    with opened(provider) as session:
        assert session.uids_above(0, 3) == [1, 2, 3]
        bodies = [session.fetch(uid).data for uid in (1, 2, 3)]
    assert bodies == [f"Subject: {uid}\r\n\r\nmessage {uid}\r\n".encode() for uid in (1, 2, 3)]
    assert commands(provider) == [
        ("AUTHENTICATE", "PLAIN"), ("EXAMINE", '"INBOX"'),
        ("UID SEARCH", "UID 1:3"),
        *[("UID FETCH", f"{uid} (BODY.PEEK[] FLAGS INTERNALDATE)") for uid in (1, 2, 3)],
        ("LOGOUT", "")]
    assert events(provider, "refused") == []


def test_a_messages_size_is_asked_with_an_item_that_reads_and_its_body_is_not_sent(
        provider, trusted):
    put(provider.inbox, 4, b"Subject: four\n\n" + b"x" * 5000 + b"\n")
    with opened(provider) as session:
        assert session.size(4) == len(b"Subject: four\r\n\r\n" + b"x" * 5000 + b"\r\n")
        (provider.inbox / "2").unlink()
        assert session.size(2) is None   # expunged since the search: none said
    assert ("UID FETCH", "4 (RFC822.SIZE)") in commands(provider)
    assert not [a for c, a in commands(provider) if "BODY" in a]
    assert events(provider, "refused") == []


def test_the_cap_is_the_scan_limit_and_the_outgoing_limit_the_machine_is_installed_with():
    import yaml
    from pathlib import Path

    from maildivvy.lib import scan

    roles = Path(__file__).resolve().parents[2] / "ansible" / "roles"
    clamav = yaml.safe_load((roles / "clamav" / "defaults" / "main.yml").read_text())
    postfix = yaml.safe_load((roles / "postfix" / "defaults" / "main.yml").read_text())
    assert imap.MESSAGE_CAP == min(
        scan.parse_size("StreamMaxLength", clamav["maildivvy_clamav_stream_max"]),
        scan.parse_size("MaxFileSize", clamav["maildivvy_clamav_file_max"])) == \
        int(postfix["maildivvy_postfix_message_size_limit"])


def test_a_size_refused_is_that_messages_refusal_as_a_fetchs_is(provider, trusted):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "no",
                                "on_size": True}])
    with opened(provider) as session:
        with pytest.raises(imap.MessageRefused) as refused:
            session.size(2)
        assert session.size(3) is not None
    assert (refused.value.uid, refused.value.ended) == (2, False)


def test_a_literal_over_the_cap_is_never_read_and_ends_the_session_as_the_messages_refusal(
        provider, trusted, monkeypatch):
    """A server whose size says less than its literal: the literal's announced size is the
    bound, so the body is not read; the session is closed without a LOGOUT, which would read
    the literal still on its way."""
    monkeypatch.setattr(imap._ReadOnly, "literal_max", 40)
    put(provider.inbox, 4, b"Subject: four\n\n" + b"x" * 5000 + b"\n")
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 4, "action": "size", "size": 10}])
    with opened(provider) as session:
        assert session.size(4) == 10
        with pytest.raises(imap.MessageRefused) as refused:
            session.fetch(4)
    assert (refused.value.uid, refused.value.ended) == (4, True)
    assert "over the 40-byte cap" in str(refused.value)
    assert "LOGOUT" not in [c for c, _ in commands(provider)]


def test_examine_gives_the_uidvalidity_and_the_next_uid(provider, trusted):
    rescript(provider, uidvalidity={"INBOX": 4242})
    with connect(provider) as session:
        session.login(USER, PASSWORD)
        assert session.examine(imap.INBOX) == imap.Examined(4242, 4)


def test_a_message_comes_whole_with_its_flags_and_its_date(provider, trusted):
    put(provider.inbox, 4, b"Subject: four\n\n" + b"x" * 5000 + b"\n")
    stamp = 1_700_000_000
    os.utime(provider.inbox / "4", (stamp, stamp))
    rescript(provider, flags={"INBOX": {"4": ["\\Seen", "\\Flagged"]}})
    with opened(provider) as session:
        message = session.fetch(4)
    assert message == imap.Message(4, b"Subject: four\r\n\r\n" + b"x" * 5000 + b"\r\n",
                                   ("\\Seen", "\\Flagged"), stamp)


def test_the_uids_above_the_mark_are_asked_window_by_window_up_to_the_last_uid(
        provider, trusted, monkeypatch):
    """Each window names both its ends, so none holds what `*` would (by the RFC `UID 4:*`
    holds the largest UID, 3); nothing above the last UID is asked for."""
    monkeypatch.setattr(imap, "SEARCH_WINDOW", 2)
    put(provider.inbox, 7, b"Subject: 7\n\nlater\n")
    with opened(provider) as session:
        assert session.uids_above(0, 7) == [1, 2, 3, 7]
        assert session.uids_above(1, 3) == [2, 3]
        assert session.uids_above(3, 3) == []
        assert session.uids_above(imap.MAX_UID, imap.MAX_UID) == []
    searched = [argument for command, argument in commands(provider) if command == "UID SEARCH"]
    assert searched == ["UID 1:2", "UID 3:4", "UID 5:6", "UID 7:7", "UID 2:3"]


def test_the_last_uid_is_uidnext_less_one_or_else_the_largest_uid_in_use(provider, trusted):
    put(provider.inbox, 7, b"Subject: 7\n\nlater\n")
    with opened(provider) as session:
        examined = session.examine(imap.INBOX)
        assert session.last_uid(examined) == 7
        assert session.last_uid(imap.Examined(examined.uidvalidity, None)) == 7
    assert [argument for command, argument in commands(provider) if command == "UID SEARCH"] \
        == ["UID *"]


def test_a_folder_whose_uids_take_more_than_imaplibs_line_bound_is_read_whole(
        provider, trusted):
    """imaplib refuses an answer line over 1,000,000 bytes. 91,000 UIDs of ten digits are
    1,001,000 bytes in one `UID SEARCH UID n:*` answer, which fails (the control); asked a
    window at a time, every one of them comes back."""
    first = 1_000_000_001
    many = provider.inbox.parent / "Many"   # empty files, and gone at the end: /tmp is memory
    many.mkdir()
    try:
        for uid in range(first, first + 91_000):
            (many / str(uid)).touch()
        with opened(provider) as session:
            examined = session.examine("Many")
            uids = session.uids_above(first - 1, session.last_uid(examined))
            with pytest.raises(imaplib.IMAP4.error, match="got more than 1000000 bytes"):
                session._client.uid("SEARCH", "UID", f"{first}:*")
    finally:
        shutil.rmtree(many)
    assert uids == list(range(first, first + 91_000))
    searched = [argument for command, argument in commands(provider) if command == "UID SEARCH"]
    assert searched[:2] == [f"UID {first}:{first + 49_999}", f"UID {first + 50_000}:{first + 90_999}"]


def test_a_uid_expunged_since_the_search_gives_none(provider, trusted):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "expunged"}])
    with opened(provider) as session:
        assert session.uids_above(0, 3) == [1, 2, 3]
        (provider.inbox / "3").unlink()
        assert session.fetch(2) is None
        assert session.fetch(3) is None
        assert session.fetch(1).uid == 1
    # nothing sent for it, so each is looked for once more: gone, not refused
    assert [argument for command, argument in commands(provider) if command == "UID SEARCH"][1:] \
        == ["UID 2", "UID 3"]


def test_the_servers_no_on_one_uid_is_that_messages_failure_and_the_others_are_read(
        provider, trusted):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "no"}])
    with opened(provider) as session:
        with pytest.raises(imap.MessageRefused) as refused:
            session.fetch(2)
        assert session.fetch(3).uid == 3
    assert refused.value.uid == 2
    assert "message 2" in str(refused.value)


@pytest.mark.parametrize("fault", [
    # Dovecot's answer to a message it cannot read, with `imap_fetch_failure = no-after`
    {"action": "no", "text": "[SERVERBUG] Internal error occurred. Refer to server log."},
    {"action": "no", "text": "[UNAVAILABLE] backend down"},
    {"action": "no", "text": "[OVERQUOTA] Account exceeded command or bandwidth limits."},
    {"action": "bad", "text": "[LIMIT] try again"},
])
def test_a_fetch_refused_with_any_code_is_that_messages_refusal(provider, trusted, fault):
    """A code that says "for a while" does not make a UID FETCH's refusal the account's: a
    server answers so for one message it can never read, and read as anything else that
    message would stop the INBOX behind it for ever. The session goes on."""
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, **fault}])
    with opened(provider) as session:
        with pytest.raises(imap.MessageRefused) as refused:
            session.fetch(2)
        assert session.fetch(3).uid == 3
    assert (refused.value.uid, refused.value.ended) == (2, False)
    assert fault["text"] in str(refused.value)


def test_a_bye_while_the_server_answers_a_fetch_is_that_messages_refusal_and_ends_the_session(
        provider, trusted):
    """Dovecot's default answer to a message it cannot read is `* BYE FETCH failed` and a
    closed connection: the server's answer about that message, not a network's failure."""
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "bye",
                                "text": "FETCH failed: Internal error reading the message"}])
    with opened(provider) as session:
        assert session.fetch(1).uid == 1
        with pytest.raises(imap.MessageRefused) as refused:
            session.fetch(2)
    assert (refused.value.uid, refused.value.ended) == (2, True)
    assert str(refused.value) == ("the server refused message 2: the server ended the session: "
                                  "FETCH failed: Internal error reading the message")


def test_a_connection_dropped_with_no_bye_is_unreachable_not_a_refusal(provider, trusted):
    """The session cannot tell a drop over a message from the network's: its caller judges
    it, collection as the message's failure and a snapshot as a cut-off."""
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "drop"}])
    with opened(provider) as session:
        with pytest.raises(imap.Unreachable) as dropped:
            session.fetch(2)
    assert not isinstance(dropped.value, imap.MessageRefused)


@pytest.mark.parametrize("fault", [
    {"action": "bad", "text": "Command Argument Error. 11"},   # a BAD to its FETCH
    {"action": "nobody"},                                      # its flags, and no body
    {"action": "no-uid"},          # the message, its UID left out: the server still lists it
])
def test_an_answer_that_does_not_hand_the_message_over_is_that_messages_refusal(
        provider, trusted, fault):
    """Read as anything else, it would stop the INBOX behind it on every run, never counted
    toward the bounded retry; as the message's own refusal, the retry passes it."""
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, **fault}])
    with opened(provider) as session:
        with pytest.raises(imap.MessageRefused) as refused:
            session.fetch(2)
        assert session.fetch(3).uid == 3   # the session goes on
    assert refused.value.uid == 2 and "message 2" in str(refused.value)
    assert events(provider, "refused") == []


def test_the_messages_flags_sent_before_it_are_passed_over_for_the_message(provider, trusted):
    rescript(provider, flags={"INBOX": {"2": ["\\Seen"]}},
             faults=[{"command": "UID FETCH", "uid": 2, "action": "flags-first"}])
    with opened(provider) as session:
        message = session.fetch(2)
    assert (message.uid, message.data, message.flags) == (
        2, b"Subject: 2\r\n\r\nmessage 2\r\n", ("\\Seen",))


@pytest.mark.parametrize("data, read", [
    # a body sent as a quoted string, which RFC 9051 allows
    ([b'1 (UID 5 FLAGS (\\Seen) BODY[] "Subject: q \\"x\\"")'],
     imap.Message(5, b'Subject: q "x"', ("\\Seen",), None)),
    ([(b"1 (UID 5 BODY[] {3}", b"abc"), b" FLAGS ())"], imap.Message(5, b"abc", (), None)),
    ([b"1 (UID 6 FLAGS ())", (b"2 (UID 6 BODY[] {3}", b"abc"), b")"], None),  # another's
    ([None], None),                                                          # nothing at all
])
def test_a_fetch_answer_is_read_whatever_way_the_server_sends_the_body(data, read):
    assert imap.message_of(5, data) == read


@pytest.mark.parametrize("data", [
    [b"1 (UID 5 FLAGS () BODY[] NIL)"],
    [b"1 (UID 5 FLAGS (\\Seen))"],
])
def test_a_fetch_answer_with_the_message_and_no_body_is_its_refusal(data):
    with pytest.raises(imap.MessageRefused, match="without its body"):
        imap.message_of(5, data)


def test_a_connection_dropped_inside_a_literal_gives_no_message(provider, trusted):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "truncate"}])
    with opened(provider) as session:
        with pytest.raises(imap.Unreachable):
            session.fetch(2)


# --- the deadline ------------------------------------------------------------


def test_a_trickling_literal_is_stopped_at_the_deadline_whatever_the_bound_per_read(
        provider, trusted):
    """A byte every 0.05 s never trips a 60 s bound per read; the deadline stops it."""
    put(provider.inbox, 4, b"Subject: slow\n\n" + b"y" * 400 + b"\n")
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 4, "action": "trickle",
                                "delay": 0.05}])
    started = time.monotonic()
    session = opened(provider, seconds=1.5)
    with pytest.raises(imap.Deadline):
        session.fetch(4)
    assert time.monotonic() - started < 2.5
    session.logout()  # past the deadline: closed without a word


def test_a_silent_server_is_unreachable_after_the_bound_per_read(provider, trusted):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "hang"}])
    session = opened(provider, read_bound=0.5)
    started = time.monotonic()
    with pytest.raises(imap.Unreachable, match="sent nothing for 0.5 s"):
        session.fetch(2)
    assert time.monotonic() - started < 2
    session.logout()


def test_a_session_given_up_on_is_closed_without_a_logout_that_would_read_the_late_answer(
        provider, trusted):
    """The server answers after the bound per read, as Gmail once did: a LOGOUT
    would read that whole answer before its own, so the session is closed without one."""
    put(provider.inbox, 4, b"Subject: large\n\n" + b"z" * 200_000 + b"\n")
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 4, "action": "late",
                                "delay": 0.8}])
    session = opened(provider, read_bound=0.5)
    with pytest.raises(imap.Unreachable, match="sent nothing for 0.5 s"):
        session.fetch(4)
    session.logout()
    ended = time.monotonic() + 5
    while not events(provider, "closed") and time.monotonic() < ended:
        time.sleep(0.05)
    assert events(provider, "closed")
    assert [command for command, _ in commands(provider)][-1] == "UID FETCH"


def test_a_deadline_already_passed_connects_to_nothing(provider, trusted):
    with pytest.raises(imap.Deadline):
        connect(provider, seconds=-1)
    assert read_log(provider.log_path) == []


# --- the transport and the pin ---------------------------------------------------------


def test_a_pinned_server_is_accepted_by_its_certificate_alone(provider, certificate, untrusted):
    with connect(provider, pin=pin_of(certificate)) as session:
        session.login(USER, PASSWORD)
        assert session.examine(imap.INBOX).uidvalidity == 1


def test_a_pin_that_does_not_match_is_refused_before_a_command_is_sent(provider, certificate,
                                                                       trusted):
    pin = pin_of(certificate)
    with pytest.raises(imap.Unreachable, match="not the pinned one"):
        connect(provider, pin=pin[:-1] + ("1" if pin[-1] == "0" else "0"))
    assert commands(provider) == []


def test_without_a_pin_a_server_the_trust_store_does_not_vouch_for_is_refused(provider,
                                                                              untrusted):
    with pytest.raises(imap.Unreachable, match="certificate verify failed"):
        connect(provider)
    assert commands(provider) == []


def test_a_server_that_does_not_answer_the_connection_is_unreachable():
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        port = probe.getsockname()[1]
    with pytest.raises(imap.Unreachable, match=f"{HOST}:{port}"):
        imap.connect(HOST, port, None, time.monotonic() + 5)


# --- the login ----------------------------------------------------------------------------------


@pytest.mark.parametrize("plain", [True, False], ids=["plain", "login"])
def test_a_refused_login_is_auth_failed_and_its_text_never_holds_the_password(
        provider, trusted, plain):
    rescript(provider, plain=plain)
    with connect(provider) as session:
        with pytest.raises(imap.AuthFailed) as refused:
            session.login(USER, "wrong-secret")
    assert "AUTHENTICATIONFAILED" in str(refused.value)
    assert "wrong-secret" not in str(refused.value)

    # a server whose answer repeats the password: its answer is not kept
    command = "AUTHENTICATE" if plain else "LOGIN"
    rescript(provider, plain=plain, faults=[{"command": command, "action": "no",
                                             "text": f"[AUTHENTICATIONFAILED] {PASSWORD} is wrong"}])
    with connect(provider) as session:
        with pytest.raises(imap.AuthFailed) as refused:
            session.login(USER, PASSWORD)
    assert PASSWORD not in str(refused.value)
    assert imap.ECHOED in str(refused.value)

    # one the answer's folding or its cut at ANSWER_MAX would have hidden from the check
    spaced = "two  spaces\tand a tab"
    for text in (f"[AUTHENTICATIONFAILED] {spaced} is wrong",
                 "[AUTHENTICATIONFAILED] " + "x" * (imap.ANSWER_MAX - 30) + spaced):
        rescript(provider, plain=plain, password=spaced,
                 faults=[{"command": command, "action": "no", "text": text}])
        with connect(provider) as session:
            with pytest.raises(imap.AuthFailed) as refused:
                session.login(USER, spaced)
        assert str(refused.value).endswith(imap.ECHOED), str(refused.value)
        assert "two spaces" not in str(refused.value) and "two  spaces" not in str(refused.value)


@pytest.mark.parametrize("plain", [True, False], ids=["plain", "login"])
@pytest.mark.parametrize("code", ["UNAVAILABLE", "INUSE", "LIMIT", "SERVERBUG", "OVERQUOTA"])
def test_a_login_refused_for_a_while_is_a_server_error_and_not_a_refused_password(
        provider, trusted, plain, code):
    """RFC 5530's codes for a provider busy, down or at its limit of sessions say nothing of
    the password: the run is `transient`, a check `error`, a snapshot's slice paused."""
    command = "AUTHENTICATE" if plain else "LOGIN"
    rescript(provider, plain=plain, faults=[{"command": command, "action": "no",
                                             "text": f"[{code}] try again later"}])
    with connect(provider) as session:
        with pytest.raises(imap.ServerError, match=f"\\[{code}\\] try again later") as refused:
            session.login(USER, PASSWORD)
    assert not isinstance(refused.value, imap.AuthFailed)


@pytest.mark.parametrize("plain", [True, False], ids=["plain", "login"])
@pytest.mark.parametrize("unsendable", ["\r", "\n", "\x00"], ids=["cr", "lf", "nul"])
def test_a_password_with_a_line_break_or_a_nul_is_refused_before_anything_is_sent(
        provider, trusted, plain, unsendable):
    rescript(provider, plain=plain)
    secret = f"first{unsendable}a001 DELETE INBOX"
    with connect(provider) as session:
        with pytest.raises(imap.AuthFailed, match="nothing was sent") as refused:
            session.login(USER, secret)
        with pytest.raises(imap.AuthFailed, match="the login holds"):
            session.login(f"{USER}{unsendable}", PASSWORD)
    assert secret not in str(refused.value) and "DELETE" not in str(refused.value)
    assert [command for command, _ in commands(provider)] == ["LOGOUT"]


def test_plain_carries_utf8_and_login_is_used_only_when_plain_is_not_offered(provider,
                                                                            trusted):
    rescript(provider, password="пароль-1")
    with connect(provider) as session:
        session.login(USER, "пароль-1")
    rescript(provider, plain=False, password='pa"ss\\word')
    with connect(provider) as session:
        session.login(USER, 'pa"ss\\word')
    assert [(e["mechanism"], e["password"], e["accepted"]) for e in events(provider, "auth")] == [
        ("PLAIN", "пароль-1", True), ("LOGIN", 'pa"ss\\word', True)]

    rescript(provider, plain=False, password="пароль-1")
    with connect(provider) as session:
        with pytest.raises(imap.AuthFailed, match="nothing was sent"):
            session.login(USER, "пароль-1")
    assert len(events(provider, "auth")) == 2


def test_folders_are_every_folder_that_can_be_opened_with_its_delimiter_and_attributes(
        provider, trusted):
    for folder in ("[Gmail]/All Mail", "[Gmail]/Spam", "&BBIERQQ+BDQETwRJBDgENQ-"):
        put(provider.inbox.parent / folder, 1, b"Subject: one\n\none\n")
    rescript(provider, attributes={"INBOX": ["\\HasNoChildren"],
                                   "[Gmail]": ["\\Noselect", "\\HasChildren"],
                                   "[Gmail]/All Mail": ["\\All", "\\HasNoChildren"],
                                   "[Gmail]/Spam": ["\\Junk"], "Gone": ["\\NonExistent"]})
    with connect(provider) as session:
        session.login(USER, PASSWORD)
        assert session.folders() == [
            imap.Folder("&BBIERQQ+BDQETwRJBDgENQ-", "/", ()),
            imap.Folder("INBOX", "/", ("\\HasNoChildren",)),
            imap.Folder("[Gmail]/All Mail", "/", ("\\All", "\\HasNoChildren")),
            imap.Folder("[Gmail]/Spam", "/", ("\\Junk",))]
    assert ("LIST", '"" "*"') in commands(provider)
    assert events(provider, "refused") == []


@pytest.mark.parametrize("item, folder", [
    (b'(\\HasNoChildren) "." INBOX', imap.Folder("INBOX", ".", ("\\HasNoChildren",))),
    (b'() NIL "Notes"', imap.Folder("Notes", None, ())),
    (b'() "\\\\" "a\\\\b \\"c\\""', imap.Folder('a\\b "c"', "\\", ())),
    ((b'(\\Marked) "/" {9}', b"Lists/dev"), imap.Folder("Lists/dev", "/", ("\\Marked",))),
    (b'* not a list response', None),
])
def test_a_list_response_is_read_whatever_way_the_server_spells_its_name(item, folder):
    assert imap.listed(item) == folder


def test_a_mailbox_that_says_no_uidvalidity_is_a_server_error(provider, trusted):
    rescript(provider, uidvalidity={"INBOX": None})
    with connect(provider) as session:
        session.login(USER, PASSWORD)
        with pytest.raises(imap.ServerError, match="gave no UIDVALIDITY"):
            session.examine(imap.INBOX)


def test_a_folder_that_cannot_be_opened_is_a_server_error(provider, trusted):
    rescript(provider, attributes={"[Gmail]": ["\\Noselect"]})
    with connect(provider) as session:
        session.login(USER, PASSWORD)
        with pytest.raises(imap.ServerError, match=r"EXAMINE \[Gmail\]"):
            session.examine("[Gmail]")


@pytest.mark.parametrize("fault", [
    {"action": "no", "text": "[INUSE] mailbox locked"},
    {"action": "no", "text": "Server Unavailable. 15"},
    {"action": "bad", "text": "User is authenticated but not connected."},
])
def test_examine_refused_with_any_code_or_a_bad_is_a_server_error(provider, trusted, fault):
    """One kind of answer, whatever it says: a snapshot tells a folder's refusal from the
    whole account's by asking the INBOX, never by the words, and the session goes on."""
    rescript(provider, faults=[{"command": "EXAMINE", "folder": "INBOX", **fault}])
    with connect(provider) as session:
        session.login(USER, PASSWORD)
        with pytest.raises(imap.ServerError, match=f"EXAMINE INBOX: .*{re.escape(fault['text'])}"):
            session.examine(imap.INBOX)
        assert [folder.name for folder in session.folders()] == ["INBOX"]


# --- the guard ----------------------------------------------------------------------------------

WRITING = {
    "SELECT": lambda c: c.select("INBOX"),
    "STORE": lambda c: c.store("1", "+FLAGS", "(\\Seen)"),
    "UID STORE": lambda c: c.uid("STORE", "1", "+FLAGS", "(\\Seen)"),
    "UID COPY": lambda c: c.uid("COPY", "1", "Archive"),
    "UID MOVE": lambda c: c.uid("MOVE", "1", "Archive"),
    "EXPUNGE": lambda c: c.expunge(),
    "CREATE": lambda c: c.create("Archive"),
    "APPEND": lambda c: c.append("INBOX", None, None, b"Subject: x\r\n\r\nx\r\n"),
    "FETCH BODY[]": lambda c: c.uid("FETCH", "1", "(BODY[])"),
    "FETCH RFC822": lambda c: c.uid("FETCH", "1", "(RFC822)"),
}


@pytest.mark.parametrize("attempt", WRITING.values(), ids=WRITING.keys())
def test_the_guard_refuses_a_command_that_could_change_the_mailbox_before_it_is_sent(
        provider, trusted, attempt):
    with opened(provider) as session:
        with pytest.raises(imap.Forbidden):
            attempt(session._client)
        assert session.fetch(1).uid == 1  # nothing was sent, and the session goes on
    assert {command for command, _ in commands(provider)} <= READ_ONLY
    assert events(provider, "refused") == []


@pytest.mark.parametrize("name, args, refused", [
    ("UID", ("FETCH", "1", "(BODY.PEEK[] FLAGS INTERNALDATE)"), False),
    ("UID", ("FETCH", "1", "(RFC822.SIZE RFC822.HEADER BODY.PEEK[HEADER] BINARY.PEEK[1])"), False),
    ("UID", ("SEARCH", "UID", "5:*"), False),
    ("UID", ("SEARCH", "UID", "5:6\r\nA1 EXPUNGE"), True),   # a line break ends it early
    ("EXAMINE", ('"Lists\nA1 DELETE INBOX"',), True),
    ("EXAMINE", (b'"Lists\x00"',), True),
    ("UID", ("FETCH", "1", "(BODY[TEXT])"), True),
    ("UID", ("FETCH", "1", "(BINARY[1])"), True),
    ("UID", ("FETCH", "1", "(rfc822.text)"), True),
    ("UID", ("EXPUNGE", "1"), True),
    ("UID", (), True),
    ("FETCH", ("1", "(BODY.PEEK[])"), True),
    ("SELECT", ("INBOX",), True),
    ("EXAMINE", ("INBOX",), False),
])
def test_the_guard_reads_the_fetch_items_that_set_the_seen_flag(name, args, refused):
    assert (imap.refusal(name, args) is not None) == refused


def test_a_folder_name_holding_a_line_break_is_never_sent(provider, trusted):
    """A folder's name is the server's own words; carried into EXAMINE, a line break would
    end the command and start another, which the guard reads as a command of its own."""
    with connect(provider) as session:
        session.login(USER, PASSWORD)
        with pytest.raises(imap.Forbidden, match="line break"):
            session.examine("Lists\r\nA9 DELETE INBOX")
        assert session.examine(imap.INBOX).uidvalidity == 1   # nothing was sent
    assert [command for command, _ in commands(provider)] == [
        "AUTHENTICATE", "EXAMINE", "LOGOUT"]


# --- answers the client cannot use ----------------------------------------------------


def test_a_servers_words_reach_a_detail_without_their_control_characters(provider, trusted):
    """A NUL in a detail is refused by the database, which stopped every mailbox after it."""
    assert imap.words_of(b"one\x00two\x07three\x7f four") == "one two three four"
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "no",
                                "text": "cannot\u0000read\u0001it"}])
    with opened(provider) as session:
        with pytest.raises(imap.MessageRefused) as refused:
            session.fetch(2)
    assert str(refused.value).endswith("cannot read it")


@pytest.mark.parametrize("date", ["01-Jan-0000 00:00:00 +0000", "01-Foo-2025 00:00:00 +0000"],
                         ids=["year-0", "unknown-month"])
def test_a_date_no_calendar_holds_leaves_the_message_without_one(provider, trusted, date):
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "action": "date",
                                "text": date}])
    with opened(provider) as session:
        message = session.fetch(2)
    assert (message.uid, message.internaldate) == (2, None)
    assert message.data.startswith(b"Subject: 2")


@pytest.mark.parametrize("raised", [ValueError, KeyError, IndexError, TypeError, OverflowError])
def test_a_fetch_answer_that_cannot_be_read_is_that_messages_refusal(provider, trusted,
                                                                     monkeypatch, raised):
    """Never an exception past the caller, which made the same UID `transient` on every run,
    out of the bounded retry's sight: a `MessageRefused`, which it counts."""
    def unreadable(uid, data):
        raise raised("the parser could not read it")

    monkeypatch.setattr(imap, "message_of", unreadable)
    with opened(provider) as session:
        with pytest.raises(imap.MessageRefused, match=raised.__name__) as refused:
            session.fetch(2)
    assert (refused.value.uid, refused.value.ended) == (2, False)


def test_a_list_answer_that_cannot_be_read_is_a_server_error(provider, trusted, monkeypatch):
    monkeypatch.setattr(imap, "listed", lambda item: {}["delimiter"])
    with connect(provider) as session:
        session.login(USER, PASSWORD)
        with pytest.raises(imap.ServerError, match="LIST: the server's answer could not be read"):
            session.folders()


def test_an_empty_delimiter_is_a_flat_name_as_nil_is(provider, trusted):
    assert imap.listed(b'() "" "Notes/2025"') == imap.Folder("Notes/2025", None, ())
    rescript(provider, delimiter="")
    with connect(provider) as session:
        session.login(USER, PASSWORD)
        assert session.folders() == [imap.Folder("INBOX", None, ())]


@pytest.mark.parametrize("plain", [True, False], ids=["plain", "login"])
@pytest.mark.parametrize("text, password", [
    ("[AUTHENTICATIONFAILED] Invalid credentials", True),
    ("[EXPIRED] the password has expired", True),
    ("Authentication failed.", True),                              # no code: the password's
    ("[ALERT] Too many simultaneous connections", False),
    ("[AUTHORIZATIONFAILED] not allowed to log in here", False),
    ("[UNAVAILABLE] try again later", False),
    ("[WEBALERT https://example.test] log in by the browser", False),
])
def test_only_a_no_with_no_code_or_a_passwords_code_is_a_refused_password(
        provider, trusted, plain, text, password):
    command = "AUTHENTICATE" if plain else "LOGIN"
    rescript(provider, plain=plain, faults=[{"command": command, "action": "no", "text": text}])
    with connect(provider) as session:
        with pytest.raises(imap.Failure) as refused:
            session.login(USER, PASSWORD)
    assert isinstance(refused.value, imap.AuthFailed) is password
    assert isinstance(refused.value, imap.ServerError) is not password
    assert text in str(refused.value)


@pytest.mark.parametrize("plain", [True, False], ids=["plain", "login"])
def test_a_bad_to_a_login_is_the_servers_and_none_of_its_words_are_kept(provider, trusted,
                                                                        plain):
    """A server without AUTHENTICATE PLAIN may answer a LOGIN it cannot parse by repeating it,
    the password escaped otherwise than it was sent: no check for the password's spellings
    finds every echo, so a BAD's words are never kept."""
    secret = 'pa"ss\\word'
    command = "AUTHENTICATE" if plain else "LOGIN"
    echo = 'Error in IMAP command LOGIN: "alice" "pa\\\\"ss\\\\word" unexpected'
    rescript(provider, plain=plain, password=secret,
             faults=[{"command": command, "action": "bad", "text": echo}])
    with connect(provider) as session:
        with pytest.raises(imap.ServerError) as refused:
            session.login(USER, secret)
    assert not isinstance(refused.value, imap.AuthFailed)
    assert str(refused.value) == f"{command}{' PLAIN' if plain else ''}: {imap.MALFORMED}"
