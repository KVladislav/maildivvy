"""The snapshot of an IMAP mailbox: the folders taken and their paths, the
message files, the manifest and the resume, and the slice that drives them with its
statuses and its reserve, against the stub provider in-process.

The folder names are the ones Dovecot 2.4.2 was measured making, as the snapshot's
decision records them: the provider sends each in modified UTF-7, and the tree
must hold exactly the directory Dovecot would. The slice's lock, its unit, its pauses and
Dovecot reading the tree are the VM suite's. Every test ends with no command refused by
the stub.
"""

import errno
import json
import os
import time
from pathlib import Path

import pytest

import imap as stub_imap
from maildivvy.fetch import imap, snapshot
from maildivvy.lib import store
from pop3 import served
from stubserver import make_certificate, read_log, settled_length, write_control

USER = "alice@example.test"
PASSWORD = "app-pass word"
HOST = "127.0.0.1"
UIDVALIDITY = 7
ME = (os.getuid(), os.getgid())

# The provider's names (modified UTF-7) and the directories Dovecot made for them
MEASURED = {
    "&BBIERQQ+BDQETwRJBDgENQ-": ".&BBIERQQ+BDQETwRJBDgENQ-",                      # Входящие
    "&BB8EQAQ+BDUEOgRCBEs-/&BB4EQgRHBFEEQg- 2.1":
        ".&BB8EQAQ+BDUEOgRCBEs-.&BB4EQgRHBFEEQg- 2^2e1",                         # Проекты/Отчёт 2.1
    "&BBAEQARFBDgEMg-^&BEEEQgQwBEAESwQ5-": ".&BBAEQARFBDgEMg-^5e&BEEEQgQwBEAESwQ5-",  # Архив^старый
    "A&-B": ".A&-B",                                                              # A&B
}


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    return make_certificate(tmp_path_factory.mktemp("certificate"), "provider.stub.test")


@pytest.fixture
def provider(tmp_path, certificate, monkeypatch):
    """The stub, trusted as the machine's store would trust it, with an empty account."""
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate.ca))
    stub = stub_imap.IMAPStub(tmp_path / "account", cert=certificate.cert, key=certificate.key,
                              log=tmp_path / "imap.log", control=tmp_path / "imap.json")
    stub.account = tmp_path / "account"
    (stub.account / "INBOX").mkdir(parents=True)
    rescript(stub)
    with stub:
        yield stub
    assert events(stub, "refused") == []


@pytest.fixture
def taken(tmp_path):
    """The snapshot of external mailbox 42, under a snapshot root of its own."""
    root = tmp_path / "store" / "_snapshots"
    root.mkdir(parents=True)
    return snapshot.Snapshot(42, root, owner=ME)


def rescript(stub, uidvalidity=None, **settings):
    write_control(stub.control_path, user=USER, password=PASSWORD,
                  uidvalidity={"INBOX": UIDVALIDITY, **(uidvalidity or {})}, **settings)


def body(folder, uid):
    return f"Subject: {folder} {uid}\n\n{folder} {uid}\n".encode()


def put(stub, folder, *uids):
    (stub.account / folder).mkdir(parents=True, exist_ok=True)
    for uid in uids:
        (stub.account / folder / str(uid)).write_bytes(body(folder, uid))


def logged_in(stub):
    session = imap.connect(HOST, stub.port, None, time.monotonic() + 30)
    session.login(USER, PASSWORD)
    return session


def events(stub, kind):
    return [r for r in read_log(stub.log_path) if r.get("event") == kind]


def fetched(stub):
    return [r["argument"].split()[0] for r in read_log(stub.log_path)
            if r.get("command") == "UID FETCH"]


def copied(taken):
    """{(the folder's directory, uid): file name} of every message written, each once, and
    nothing left in a `tmp/`."""
    found = {}
    box = taken.home / "Maildir"
    for path in store.mailbox_files(taken.home):
        folder = "INBOX" if path.parent.parent == box else path.parent.parent.name
        key = (folder, int(path.name.split(".")[1]))
        assert key not in found, f"{key} written twice"
        found[key] = path.name
    for folder in [box, *box.glob(".*")]:
        assert list((folder / "tmp").iterdir()) == []
    return found


def folders(taken):
    return sorted(p.name for p in (taken.home / "Maildir").iterdir() if p.name.startswith("."))


def never():
    return False


def room(_size):
    return True


def run(stub, taken, mark=(UIDVALIDITY, 0), stop=never):
    """The snapshot started and walked in one session; the walk's status."""
    with logged_in(stub) as session:
        assert taken.start(session, mark, None, never) == snapshot.DONE
        return taken.walk(session, stop, room)


def walk(stub, taken, stop=never):
    with logged_in(stub) as session:
        return taken.walk(session, stop, room)


# --- the folders and their paths -----------------------------------------------------------


def test_each_folder_is_written_under_the_directory_dovecot_makes_for_its_name(provider,
                                                                               taken):
    for name in MEASURED:
        put(provider, name, 1)
    assert run(provider, taken) == snapshot.DONE
    # `Проекты` is a folder at the provider too, the parent of `Отчёт 2.1`, with no message
    assert folders(taken) == sorted([*MEASURED.values(), ".&BB8EQAQ+BDUEOgRCBEs-"])
    assert sorted(copied(taken)) == sorted((directory, 1) for directory in MEASURED.values())
    for name, directory in MEASURED.items():
        assert store.maildir(taken.home, name).name == directory
    paths = {f["name"]: f["path"] for f in taken.read()["folders"]}
    assert paths["&BB8EQAQ+BDUEOgRCBEs-/&BB4EQgRHBFEEQg- 2.1"] == \
        "&BB8EQAQ+BDUEOgRCBEs-/&BB4EQgRHBFEEQg- 2.1"


def test_a_folder_whose_name_cannot_be_a_path_here_is_left_out_and_named(provider, taken):
    """Under the provider's `.` a nested directory of the stub is one folder named `a/b`."""
    put(provider, "Lists.dev", 1)
    put(provider, "a/b", 1)
    put(provider, "Тест", 1)  # sent in UTF-8, which a server must not send our client
    rescript(provider, delimiter=".")
    assert run(provider, taken) == snapshot.DONE
    assert folders(taken) == [".Lists.dev", ".a"]
    assert sorted(copied(taken)) == [(".Lists.dev", 1)]
    assert taken.read()["left_out"] == [{"name": "a/b", "why": snapshot.SLASH},
                                        {"name": "Тест", "why": snapshot.NOT_ASCII}]


def test_a_folder_listed_but_refused_at_every_start_is_left_out_with_the_servers_words(
        provider, taken):
    """It would stop every slice: refused by OPEN_REFUSED_MAX starts in a row, the INBOX
    opening after each, it is left out with nothing copied to describe, and the rest of
    the account is taken."""
    put(provider, "Archive", 1)
    put(provider, "Private", 1)
    rescript(provider, faults=[{"command": "EXAMINE", "folder": "Private", "action": "no",
                                "text": "[NOPERM] not yours"}])
    for _ in range(snapshot.OPEN_REFUSED_MAX - 1):
        with logged_in(provider) as session, pytest.raises(imap.ServerError,
                                                           match="EXAMINE Private"):
            taken.start(session, (UIDVALIDITY, 0), None, never)
    assert taken.read()["left_out"] == []
    assert run(provider, taken) == snapshot.DONE
    assert taken.read()["left_out"] == [{"name": "Private",
                                         "why": "EXAMINE Private: [NOPERM] not yours"}]
    assert [f["name"] for f in taken.read()["folders"]] == ["INBOX", "Archive"]
    assert folders(taken) == [".Archive"]
    assert sorted(copied(taken)) == [(".Archive", 1)]


def test_the_start_stops_with_the_slice_and_the_next_goes_on_from_the_folder_it_reached(
        provider, taken):
    """Each folder's target is saved as its EXAMINE gives it, so a start among many folders
    that outlasts a slice is never begun again from the first."""
    for name in ("A", "B", "C", "D"):
        put(provider, name, 1)
    asked = []

    def after_two():
        asked.append(1)
        return len(asked) > 2

    with logged_in(provider) as session:
        assert taken.start(session, (UIDVALIDITY, 0), None, after_two) == snapshot.STOPPED
    started = taken.read()
    assert [f["target"] for f in started["folders"]] == [0, 1, 1, None, None]
    assert snapshot.summary(started).startswith("1 of 5 folders taken")
    assert run(provider, taken) == snapshot.DONE
    examined = [r["argument"] for r in read_log(provider.log_path) if r.get("command") == "EXAMINE"]
    assert [e for e in examined if e in ('"A"', '"B"', '"C"', '"D"')][:4] == [
        '"A"', '"B"', '"C"', '"D"']   # each examined once at the start, then by the walk
    assert sorted(copied(taken)) == [(".A", 1), (".B", 1), (".C", 1), (".D", 1)]


@pytest.mark.parametrize("name, why", [
    ("Lists\r\nA9 DELETE INBOX", snapshot.LINE_BREAK),
    ("Lists\x00", snapshot.LINE_BREAK),
    ("/".join(["&BB8EQAQ+BDUEOgRCBEs-" * 3] * 4), snapshot.TOO_LONG),
])
def test_a_name_no_command_could_send_back_or_no_directory_could_hold_is_left_out(name, why):
    """A line break would end the EXAMINE carrying it and start another command, and
    Maildir++ makes the whole hierarchy one directory name, of at most NAME_MAX bytes."""
    assert snapshot.path_of(imap.Folder(name, "/", ())) == (None, why)
    assert snapshot.path_of(imap.Folder("/".join(["&BB8EQAQ+BDUEOgRCBEs-"] * 4), "/", ()))[1] \
        is None   # nested, and short enough


def test_a_folder_too_deep_for_one_directory_name_is_left_out_and_the_rest_taken(provider,
                                                                                 taken):
    deep = "/".join(["x" * 100] * 3)   # `.xxx…xxx` of 303 bytes
    put(provider, deep, 1)
    put(provider, "Archive", 1)
    assert run(provider, taken) == snapshot.DONE
    left = {f["name"]: f["why"] for f in taken.read()["left_out"]}
    assert left == {deep: snapshot.TOO_LONG}
    assert sorted(copied(taken)) == [(".Archive", 1)]


def test_a_folder_that_cannot_be_opened_is_not_taken_and_all_junk_and_trash_are(provider,
                                                                                taken):
    put(provider, "[Gmail]/All Mail", 1, 2)
    put(provider, "[Gmail]/Spam", 3)
    put(provider, "[Gmail]/Trash", 4)
    rescript(provider, attributes={"[Gmail]": ["\\Noselect", "\\HasChildren"],
                                   "[Gmail]/All Mail": ["\\All"], "[Gmail]/Spam": ["\\Junk"],
                                   "[Gmail]/Trash": ["\\Trash"], "Gone": ["\\NonExistent"]})
    assert run(provider, taken) == snapshot.DONE
    assert folders(taken) == [".[Gmail].All Mail", ".[Gmail].Spam", ".[Gmail].Trash"]
    assert sorted(copied(taken)) == [(".[Gmail].All Mail", 1), (".[Gmail].All Mail", 2),
                                     (".[Gmail].Spam", 3), (".[Gmail].Trash", 4)]
    manifest = taken.read()
    assert {f["name"]: f["attributes"] for f in manifest["folders"]} == {
        "INBOX": [], "[Gmail]/All Mail": ["\\All"], "[Gmail]/Spam": ["\\Junk"],
        "[Gmail]/Trash": ["\\Trash"]}
    assert manifest["left_out"] == []
    examined = [r["argument"] for r in read_log(provider.log_path) if r.get("command") == "EXAMINE"]
    assert '"[Gmail]"' not in examined and '"Gone"' not in examined


# --- the message files --------------------------------------------------------------------


def test_a_file_carries_the_message_its_size_its_flags_and_its_date(provider, taken):
    flags = {1: [], 2: ["\\Seen"], 3: ["\\Answered", "\\Flagged"],
             4: ["\\Seen", "\\Draft", "$Forwarded", "\\Deleted", "\\Recent"]}
    letters = {1: "", 2: "S", 3: "FR", 4: "DST"}
    put(provider, "INBOX", *flags)
    for uid in flags:
        os.utime(provider.account / "INBOX" / str(uid), (1_700_000_000 + uid,) * 2)
    rescript(provider, flags={"INBOX": {str(uid): f for uid, f in flags.items()}})
    assert run(provider, taken, mark=(UIDVALIDITY, 4)) == snapshot.DONE

    box = taken.home / "Maildir"
    for uid in flags:
        data = served(body("INBOX", uid))
        name = f"{UIDVALIDITY}.{uid}.snapshot,S={len(data)}:2,{letters[uid]}"
        assert copied(taken)[("INBOX", uid)] == name
        path = box / "cur" / name
        assert path.read_bytes() == data
        assert path.stat().st_size == len(data)  # ,S= is the bytes written
        assert path.stat().st_mtime == 1_700_000_000 + uid
        assert path.stat().st_mode & 0o777 == 0o600
    inbox = taken.read()["folders"][0]
    assert (inbox["messages"], inbox["bytes"]) == (
        4, sum(len(served(body("INBOX", uid))) for uid in flags))


def test_the_inbox_is_taken_up_to_the_mark_and_the_others_up_to_their_last_uid_at_the_start(
        provider, taken):
    put(provider, "INBOX", 1, 2, 3, 4, 5)
    put(provider, "Archive", 1, 2)
    with logged_in(provider) as session:
        assert taken.start(session, (UIDVALIDITY, 3), None, never) == snapshot.DONE
    assert [(f["name"], f["uidvalidity"], f["target"]) for f in taken.read()["folders"]] == [
        ("INBOX", UIDVALIDITY, 3), ("Archive", 1, 2)]
    put(provider, "INBOX", 6)
    put(provider, "Archive", 3)
    assert walk(provider, taken) == snapshot.DONE
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 2),
                                     ("INBOX", 1), ("INBOX", 2), ("INBOX", 3)]


def test_a_message_expunged_at_the_provider_during_the_snapshot_is_passed(provider, taken):
    put(provider, "Archive", 1, 2, 3)
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "folder": "Archive",
                                "action": "expunged"}])
    assert run(provider, taken) == snapshot.DONE
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 3)]
    archive = taken.read()["folders"][1]
    assert (archive["last"], archive["target"], archive["messages"]) == (3, 3, 2)


# --- stops and the resume -----------------------------------------------------------------

EVERY = {"INBOX": (1, 2, 3), "Archive": (1, 2), "Lists": (5, 8)}
EXPECTED = sorted((name if name == "INBOX" else f".{name}", uid)
                  for name, uids in EVERY.items() for uid in uids)


@pytest.mark.parametrize("after", range(len(EXPECTED)))
def test_a_stop_after_any_message_then_a_resume_takes_every_message_exactly_once(
        provider, taken, monkeypatch, after):
    monkeypatch.setattr(snapshot, "PROGRESS_EVERY", 2)
    for name, uids in EVERY.items():
        put(provider, name, *uids)

    def written():
        return len(list(store.mailbox_files(taken.home)))

    assert run(provider, taken, mark=(UIDVALIDITY, 3), stop=lambda: written() >= after) == \
        snapshot.STOPPED
    assert written() == after
    saved = taken.read()
    assert sum(f["messages"] for f in saved["folders"]) == after

    assert walk(provider, taken) == snapshot.DONE
    assert sorted(copied(taken)) == EXPECTED
    assert len(fetched(provider)) == len(EXPECTED)  # nothing asked for twice
    done = taken.read()["folders"]
    assert all(f["last"] == f["target"] for f in done)
    assert sum(f["messages"] for f in done) == len(EXPECTED)


def test_a_stop_between_the_files_and_the_manifest_repeats_nothing(provider, taken):
    for name, uids in EVERY.items():
        put(provider, name, *uids)
    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 3), None, never)
        started = taken.read()
        assert taken.walk(session, never, room) == snapshot.DONE
    files, finished = copied(taken), taken.read()
    taken.save(started)  # the files are there, the manifest says nothing was done

    asked = len(fetched(provider))
    assert walk(provider, taken) == snapshot.DONE
    assert len(fetched(provider)) == asked
    assert copied(taken) == files
    assert taken.read() == finished


# --- a changed UIDVALIDITY ----------------------------------------------------------------


def test_a_renumbered_inbox_fails_the_snapshot_and_keeps_what_was_written(provider, taken):
    put(provider, "INBOX", 1, 2, 3)
    with logged_in(provider) as session:
        with pytest.raises(snapshot.Failed, match="no mark"):
            taken.start(session, (UIDVALIDITY, None), None, never)
    assert run(provider, taken, mark=(UIDVALIDITY, 3),
               stop=lambda: len(list(store.mailbox_files(taken.home))) >= 1) == snapshot.STOPPED

    rescript(provider, uidvalidity={"INBOX": UIDVALIDITY + 1})
    with pytest.raises(snapshot.Failed, match="renumbered the INBOX"):
        walk(provider, taken)
    assert sorted(copied(taken)) == [("INBOX", 1)]


def test_a_renumbered_folder_is_emptied_and_taken_again_under_its_new_numbering(provider,
                                                                                taken):
    put(provider, "INBOX", 1)
    put(provider, "Archive", 1, 2, 3)
    rescript(provider, uidvalidity={"Archive": 5})
    assert run(provider, taken, mark=(UIDVALIDITY, 1),
               stop=lambda: len(list(store.mailbox_files(taken.home))) >= 3) == snapshot.STOPPED
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 2), ("INBOX", 1)]

    # the provider renumbers the folder: other messages under the same UIDs, and fewer
    for uid in (1, 2, 3):
        (provider.account / "Archive" / str(uid)).unlink()
    (provider.account / "Archive" / "1").write_bytes(b"Subject: renumbered 1\n\nnew\n")
    (provider.account / "Archive" / "2").write_bytes(b"Subject: renumbered 2\n\nnew\n")
    rescript(provider, uidvalidity={"Archive": 6})
    assert walk(provider, taken) == snapshot.DONE

    names = copied(taken)
    assert sorted(names) == [(".Archive", 1), (".Archive", 2), ("INBOX", 1)]
    archive = taken.home / "Maildir" / ".Archive" / "cur"
    assert sorted(p.name.split(",")[0] for p in archive.iterdir()) == \
        ["6.1.snapshot", "6.2.snapshot"]
    assert (archive / names[(".Archive", 1)]).read_bytes() == b"Subject: renumbered 1\r\n\r\nnew\r\n"
    folder = taken.read()["folders"][1]
    assert (folder["uidvalidity"], folder["target"], folder["last"], folder["messages"]) == \
        (6, 2, 2, 2)


def test_the_manifest_is_whole_json_beside_the_tree_and_nothing_else_is_left(provider, taken):
    put(provider, "INBOX", 1)
    assert run(provider, taken, mark=(UIDVALIDITY, 1)) == snapshot.DONE
    assert sorted(p.name for p in taken.home.iterdir()) == ["Maildir", snapshot.MANIFEST]
    assert json.loads((taken.home / snapshot.MANIFEST).read_text()) == taken.read()
    assert (taken.home / snapshot.MANIFEST).stat().st_mode & 0o777 == 0o600
    assert taken.home.stat().st_mode & 0o777 == store.DIR_MODE


# --- the slice (`take`): its statuses, its reserve and its bounds ---------------------------------

PIN = None


class Row:
    """The pipeline's connection as a slice uses it: the row's snapshot status and stored
    password, and every statement written."""

    def __init__(self, status=None, secret=PASSWORD):
        self.status, self.secret = status, secret
        self.statements = []

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.statements.append((" ".join(sql.split()), params))
        self.last = sql

    def fetchone(self):
        if self.last == snapshot.STATUS_OF:
            return (self.status,)
        return (self.secret,)

    def written(self):
        (written,) = [params for sql, params in self.statements
                      if sql == " ".join(snapshot.SLICE_ENDS.split())]
        status, detail, finished, paused, refused, left_out, _ = written
        assert finished == (status in ("done", "failed"))
        assert paused == (status == "paused")
        return status, detail, refused, left_out

    def ended(self):
        """(the status, the detail) the slice left on the row."""
        return self.written()[:2]

    def refused(self):
        """How many messages the slice wrote the provider refused (`snapshot_refused`)."""
        return self.written()[2]

    def left_out(self):
        """How many folders the slice wrote the snapshot leaves out (`snapshot_left_out`)."""
        return self.written()[3]


class Fs:
    """`os.statvfs` of a filesystem of 1000 blocks of 4 KiB and 1000 inodes, `free` of each,
    less what the files under `holding` take, as a slice writes them."""

    def __init__(self, free=1000, inodes=1000, holding=None):
        self.free, self.inodes, self.holding = free, inodes, holding

    def __call__(self, path):
        used = [p.stat().st_size for p in Path(self.holding).rglob("*") if p.is_file()] \
            if self.holding else []
        free = self.free - sum(-(-size // 4096) for size in used)
        inodes = self.inodes - len(used)
        return os.statvfs_result((4096, 4096, 1000, free, free, 1000, inodes, inodes, 0, 255))


def mailbox_at(stub, uidvalidity=UIDVALIDITY, last=0, host=HOST, login=USER):
    from maildivvy.fetch import render
    return render.Mailbox(42, login, USER, host, stub.port, "alpha", None, USER, 8.0, None, True,
                          PIN, "imap", uidvalidity, last)


def args_for(seconds=600):
    return type("Args", (), {"slice_seconds": seconds})()


@pytest.fixture
def separate(monkeypatch):
    """Health's warn level read for the separate-disk layout: 20%."""
    from maildivvy.health import settings, system
    monkeypatch.setattr(settings, "read", lambda path=None: settings.Settings())
    monkeypatch.setattr(system, "disk_mode", lambda: "separate")


@pytest.fixture(autouse=True)
def roomy(monkeypatch):
    """The store's filesystem, as a slice reads it, has room: a test that says otherwise
    sets its own (`full`)."""
    monkeypatch.setattr(snapshot.os, "statvfs", Fs())


def full(monkeypatch, fs):
    monkeypatch.setattr(snapshot.os, "statvfs", fs)


def take(stub, taken, row, mailbox=None, seconds=600):
    return snapshot.take(row, mailbox or mailbox_at(stub), args_for(seconds), taken.root, ME)


def test_a_slice_starts_a_snapshot_asked_for_takes_it_whole_and_says_done(provider, taken,
                                                                           separate):
    put(provider, "INBOX", 1, 2)
    put(provider, "Archive", 1)
    row = Row(status=None)
    assert take(provider, taken, row, mailbox_at(provider, last=2)) == "done"
    assert row.statements[0] == (snapshot.STATUS_OF, (42,))
    assert row.statements[1] == (" ".join(snapshot.SLICE_STARTS.split()), (42,))
    status, detail = row.ended()
    assert (status, detail) == ("done", "2 of 2 folders taken, 3 messages, "
                                        f"{sum(len(served(body(f, u))) for f, u in (('INBOX', 1), ('INBOX', 2), ('Archive', 1)))} bytes")
    assert sorted(copied(taken)) == [(".Archive", 1), ("INBOX", 1), ("INBOX", 2)]
    assert taken.read()["server"] == {"protocol": "imap", "host": HOST, "login": USER}
    # the request is the interface's: the slice never writes it
    assert not any("snapshot_requested_at" in sql for sql, _ in row.statements)


def test_the_reserve_pauses_a_slice_before_the_message_that_would_take_the_store_under_it(
        provider, taken, separate, monkeypatch):
    """The separate layout warns under 20% free. With 400 of 1000 blocks free and the
    manifest in one, a message of 400 KiB, 101 blocks with its line ends, takes it to
    29.8%; the second would take it to 19.7%, and is not written."""
    put(provider, "INBOX")
    for uid in (1, 2, 3):
        (provider.account / "INBOX" / str(uid)).write_bytes(b"x" * 400 * 1024)
    full(monkeypatch, Fs(free=400, holding=taken.home))
    row = Row(status=None)
    assert take(provider, taken, row, mailbox_at(provider, last=3)) == "paused"
    status, detail = row.ended()
    assert "paused before the store's filesystem goes under the 20% free health warns at with " \
           "separate disks: 29.8% of its space" in detail
    assert sorted(copied(taken)) == [("INBOX", 1)], "a message was written past the reserve"
    assert len(fetched(provider)) == 2   # the one that did not fit is fetched again later

    # there is room again: the next slice goes on, and takes each message once
    full(monkeypatch, Fs())
    row = Row(status="paused")
    assert take(provider, taken, row) == "done"
    assert row.statements[1] == (snapshot.SLICE_GOES_ON, (42,))
    assert sorted(copied(taken)) == [("INBOX", 1), ("INBOX", 2), ("INBOX", 3)]


def test_the_reserve_counts_inodes_as_well_and_is_the_disk_layouts_warn_level(provider, taken,
                                                                              monkeypatch):
    from maildivvy.health import settings, system
    one = settings.Settings()
    monkeypatch.setattr(settings, "read", lambda path=None: one)
    monkeypatch.setattr(system, "disk_mode", lambda: "single")
    assert snapshot.reserve() == (one.single_disk_warn_percent, "single") == (30, "single")
    monkeypatch.setattr(system, "disk_mode", lambda: "separate")
    assert snapshot.reserve() == (one.disk_warn_percent, "separate") == (20, "separate")
    # health judges the same filesystem by the same bound
    assert settings.disk_bounds(one, "single") == (15, 30)
    assert settings.disk_bounds(one, "separate") == (10, 20)

    fs = Fs()
    assert snapshot.short_of(fs(None), 20, 4096) is None
    assert snapshot.short_of(Fs(inodes=200)(None), 20, 0) == \
        "100.0% of its space and 20.0% of its inodes are free"   # one file more is 19.9%
    assert snapshot.short_of(Fs(free=201)(None), 20, 4097) is not None   # two blocks: 19.9%
    assert snapshot.short_of(Fs(free=201)(None), 20, 4096) is None   # one: 20.0%, not under it

    put(provider, "INBOX", 1)
    row = Row(status=None)
    # 201 inodes free and the manifest in one: the message's file would leave 19.9%
    full(monkeypatch, Fs(inodes=201, holding=taken.home))
    assert take(provider, taken, row, mailbox_at(provider, last=1)) == "paused"
    assert "under the 20% free health warns at with separate disks" in row.ended()[1]
    assert "99.9% of its space and 20.0% of its inodes are free" in row.ended()[1]
    assert copied(taken) == {}


def test_a_reserve_that_cannot_be_read_pauses_and_nothing_is_asked_of_the_provider(
        provider, taken, monkeypatch):
    from maildivvy.health import settings, system
    from maildivvy.health.probe import Unreadable

    def unread():
        raise Unreadable("/etc/maildivvy/disks.json is absent")

    monkeypatch.setattr(settings, "read", lambda path=None: settings.Settings())
    monkeypatch.setattr(system, "disk_mode", unread)
    row = Row(status=None)
    assert take(provider, taken, row) == "paused"
    assert "the store's reserve cannot be known: /etc/maildivvy/disks.json is absent" in row.ended()[1]
    assert read_log(provider.log_path) == []


def test_a_slice_stops_at_its_end_and_the_next_goes_on_from_there(provider, taken, separate,
                                                                   monkeypatch):
    for name, uids in EVERY.items():
        put(provider, name, *uids)
    class Ending(snapshot.Bounds):
        def stop(self):   # the slice's time runs out before the fourth message
            return len(list(store.mailbox_files(taken.home))) >= 3

    monkeypatch.setattr(snapshot, "Bounds", Ending)
    row = Row(status=None)
    assert take(provider, taken, row, mailbox_at(provider, last=3)) == "pending"
    assert row.ended()[1].endswith("; the slice's time ran out, and the next goes on")
    assert len(copied(taken)) == 3
    monkeypatch.setattr(snapshot, "Bounds", Ending.__mro__[1])
    assert take(provider, taken, Row(status="pending")) == "done"
    assert sorted(copied(taken)) == EXPECTED
    assert len(fetched(provider)) == len(EXPECTED)


def test_a_folder_gone_at_the_provider_during_the_snapshot_is_left_out_and_never_retried(
        provider, taken, separate):
    put(provider, "INBOX", 1)
    put(provider, "Archive", 1, 2)
    put(provider, "Lists", 1)
    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 1), snapshot.server_of(mailbox_at(provider)), never)
    for path in (provider.account / "Archive").iterdir():
        path.unlink()
    (provider.account / "Archive").rmdir()   # deleted at the provider, after the start
    row = Row(status="pending")
    assert take(provider, taken, row) == "done"
    status, detail = row.ended()
    assert "gone at the provider during the snapshot: Archive" in detail
    archive = [f for f in taken.read()["folders"] if f["name"] == "Archive"][0]
    assert archive["gone"] and archive["last"] == archive["target"] == 2
    assert sorted(copied(taken)) == [(".Lists", 1), ("INBOX", 1)]
    # the next request is a new snapshot; this one is done, and asks the provider nothing more
    examined = [r["argument"] for r in read_log(provider.log_path) if r.get("command") == "EXAMINE"]
    assert examined.count('"Archive"') == 2   # at the start, and once to find it gone


def test_a_folder_gone_at_the_provider_takes_its_refused_messages_out_of_the_count(
        provider, taken, separate):
    """They can never be asked for again: the row stops counting them, and no round spends
    an EXAMINE and a LIST on a folder no longer there."""
    put(provider, "Archive", 1, 2, 3, 4)
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "folder": "Archive",
                                "action": "no"}])
    asked = []

    def after_three():
        asked.append(1)
        return len(asked) > 3

    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
        assert taken.walk(session, after_three, room) == snapshot.STOPPED
    assert taken.read()["folders"][1]["refused"] == [2]
    for path in (provider.account / "Archive").iterdir():
        path.unlink()
    (provider.account / "Archive").rmdir()   # deleted at the provider, before its end
    rescript(provider)
    before = len(read_log(provider.log_path))
    row = Row(status="pending")
    assert take(provider, taken, row) == "done"
    assert row.refused() == 0
    assert "gone at the provider during the snapshot: Archive" in row.ended()[1]
    archive = taken.read()["folders"][1]
    assert (archive["gone"], archive["refused"], archive["cut_off"], archive["messages"]) == \
        (True, [], None, 2)
    examined = [r["argument"] for r in read_log(provider.log_path)[before:]
                if r.get("command") == "EXAMINE"]
    assert examined.count('"Archive"') == 1   # to find it gone, and never again


@pytest.mark.parametrize("fault, said", [
    ({"command": "EXAMINE", "action": "no", "text": "[UNAVAILABLE] busy"},
     "EXAMINE Archive: [UNAVAILABLE] busy"),
    ({"command": "EXAMINE", "action": "no", "text": "Server Unavailable. 15"},
     "EXAMINE Archive: Server Unavailable. 15"),
    ({"command": "UID SEARCH", "action": "no", "text": "Server Unavailable. 15"},
     "UID SEARCH in Archive: Server Unavailable. 15"),
])
def test_a_provider_that_will_not_open_any_folder_after_the_start_leaves_none_out(
        provider, taken, separate, fault, said):
    """Whatever the refusal says, a code or none, to the EXAMINE or to the search after it:
    refused with the INBOX too after the start, the account is refused. Each slice pauses
    and counts nothing, so an outage longer than OPEN_REFUSED_MAX slices leaves no folder out."""
    put(provider, "Archive", 1)
    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
    rescript(provider, faults=[fault])
    for _ in range(snapshot.OPEN_REFUSED_MAX + 1):
        row = Row(status="pending")
        assert take(provider, taken, row) == "paused"
        assert said in row.ended()[1] and "the next slice tries again" in row.ended()[1]
    assert not [f for f in taken.read()["folders"] if f.get("gone")]
    assert [f["open_refused"] for f in taken.read()["folders"]] == [0, 0]
    assert (taken.read()["left_out"], row.left_out()) == ([], 0)
    rescript(provider)
    assert take(provider, taken, Row(status="paused")) == "done"
    assert sorted(copied(taken)) == [(".Archive", 1)]


def test_a_folder_refused_after_the_start_holds_up_no_other_and_is_judged_as_at_the_start(
        provider, taken, separate):
    """A later slice refused one folder's EXAMINE and another's search, the INBOX opening
    and searched: the walk goes on with the other folders. Whatever the refusal says, a
    code or none, each is counted by OPEN_REFUSED_MAX slices in a row and then left out.
    What was copied of it stays in the tree, and its entry in the manifest says what, so
    the import and the slice's counts see it."""
    put(provider, "Archive", 1, 2)
    put(provider, "Lists", 1)
    put(provider, "Private", 1)
    asked = []

    def after_one():
        asked.append(1)
        return len(asked) > 1

    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
        assert taken.walk(session, after_one, room) == snapshot.STOPPED
    assert sorted(copied(taken)) == [(".Archive", 1)]
    rescript(provider, faults=[
        {"command": "EXAMINE", "folder": "Archive", "action": "no", "text": "access withdrawn"},
        {"command": "UID SEARCH", "folder": "Private", "action": "no",
         "text": "[NOPERM] access withdrawn"}])
    before = len(read_log(provider.log_path))
    statuses = []
    for _ in range(snapshot.OPEN_REFUSED_MAX):
        row = Row(status=statuses[-1] if statuses else "pending")
        statuses.append(take(provider, taken, row))
        if len(statuses) == 1:   # the others taken past them, and neither left out at once
            assert sorted(copied(taken)) == [(".Archive", 1), (".Lists", 1)]
            assert taken.read()["left_out"] == []
            assert "UID SEARCH in Private: [NOPERM] access withdrawn" in row.ended()[1]
    assert statuses == ["paused"] * (snapshot.OPEN_REFUSED_MAX - 1) + ["done"]
    archive = served(body("Archive", 1))
    assert taken.read()["left_out"] == [
        {"name": "Archive", "why": "EXAMINE Archive: access withdrawn", "path": "Archive",
         "attributes": [], "uidvalidity": 1, "messages": 1, "bytes": len(archive)},
        {"name": "Private", "why": "UID SEARCH in Private: [NOPERM] access withdrawn",
         "path": "Private", "attributes": [], "uidvalidity": 1, "messages": 0, "bytes": 0}]
    assert row.left_out() == 2
    assert row.ended()[1] == (
        f"2 of 2 folders taken, 2 messages, {len(archive) + len(served(body('Lists', 1)))} "
        "bytes; 2 left out: Archive (1 copied before kept), Private")
    assert sorted(copied(taken)) == [(".Archive", 1), (".Lists", 1)]
    examined = [r["argument"] for r in read_log(provider.log_path)[before:]
                if r.get("command") == "EXAMINE"]
    assert (examined.count('"Archive"'), examined.count('"Private"')) == (snapshot.OPEN_REFUSED_MAX,) * 2


def test_a_folder_a_slice_opens_between_its_refusals_is_never_left_out(provider, taken,
                                                                       separate):
    """The bound counts refusals in a row: a slice that opens the folder forgets the ones
    before, so a large folder refused now and then over many slices is taken whole."""
    put(provider, "Archive", *range(1, snapshot.OPEN_REFUSED_MAX + 3))
    asked = []

    def after_one():
        asked.append(1)
        return len(asked) % 2 == 0

    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
    for _ in range(snapshot.OPEN_REFUSED_MAX + 1):
        rescript(provider, faults=[{"command": "EXAMINE", "folder": "Archive", "action": "no",
                                    "text": "[UNAVAILABLE] backend down"}])
        with logged_in(provider) as session, pytest.raises(imap.ServerError,
                                                           match="EXAMINE Archive"):
            taken.walk(session, never, room)
        assert taken.read()["folders"][1]["open_refused"] == 1
        rescript(provider)
        with logged_in(provider) as session:   # opened, and one message taken
            assert taken.walk(session, after_one, room) == snapshot.STOPPED
        assert taken.read()["folders"][1]["open_refused"] == 0
    assert taken.read()["left_out"] == []
    assert walk(provider, taken) == snapshot.DONE
    assert len(copied(taken)) == snapshot.OPEN_REFUSED_MAX + 2


@pytest.mark.parametrize("fault", [
    {"action": "no", "text": "[UNAVAILABLE] backend down"},
    {"action": "no", "text": "Server Unavailable. 15"},
    {"action": "no", "text": "[NOPERM] access withdrawn"},
    {"action": "bad", "text": "User is authenticated but not connected."},
])
def test_a_folder_refused_at_the_start_pauses_the_slice_and_is_taken_later(
        provider, taken, separate, fault):
    """A provider's brief trouble in the first slice must not drop a whole folder from the
    import, whatever its answer says: the folder keeps no target, the start goes on with
    the others, and the next slice asks again."""
    put(provider, "Archive", 1)
    put(provider, "Private", 1)
    rescript(provider, faults=[{"command": "EXAMINE", "folder": "Archive", **fault}])
    row = Row(status=None)
    assert take(provider, taken, row) == "paused"
    assert "EXAMINE Archive" in row.ended()[1] and "the next slice tries again" in row.ended()[1]
    assert (taken.read()["left_out"], row.left_out()) == ([], 0)
    started = {f["name"]: f for f in taken.read()["folders"]}
    assert (started["Archive"]["target"], started["Archive"]["open_refused"]) == (None, 1)
    assert started["Private"]["target"] == 1   # asked after it, in the same slice
    rescript(provider)
    row = Row(status="paused")
    assert take(provider, taken, row) == "done"
    assert [f["open_refused"] for f in taken.read()["folders"]] == [0, 0, 0]
    assert (taken.read()["left_out"], row.left_out()) == ([], 0)
    assert sorted(copied(taken)) == [(".Archive", 1), (".Private", 1)]


def test_a_folder_still_refused_for_a_while_after_every_slice_that_asked_is_left_out_and_counted(
        provider, taken, separate):
    """Counted by OPEN_REFUSED_MAX slices in a row, the first and those asking again, the
    folder is left out, the rest is taken, and the row counts the folder the copy does not
    hold."""
    put(provider, "Archive", 1)
    put(provider, "Private", 1)
    rescript(provider, faults=[{"command": "EXAMINE", "folder": "Private", "action": "no",
                                "text": "[UNAVAILABLE] backend down"}])
    statuses = []
    for _ in range(snapshot.OPEN_REFUSED_MAX):
        row = Row(status=statuses[-1] if statuses else None)
        statuses.append(take(provider, taken, row))
    assert statuses == ["paused"] * (snapshot.OPEN_REFUSED_MAX - 1) + ["done"]
    assert taken.read()["left_out"] == [{"name": "Private",
                                         "why": "EXAMINE Private: [UNAVAILABLE] backend down"}]
    assert row.left_out() == 1 and "1 left out: Private" in row.ended()[1]
    assert sorted(copied(taken)) == [(".Archive", 1)]
    examined = [r["argument"] for r in read_log(provider.log_path) if r.get("command") == "EXAMINE"]
    assert examined.count('"Private"') == snapshot.OPEN_REFUSED_MAX


@pytest.mark.parametrize("text", ["[UNAVAILABLE] Temporary System Error",
                                  "Server Unavailable. 15"])
def test_a_provider_refusing_every_folder_at_the_start_leaves_none_out(
        provider, taken, separate, text):
    """A folder's refusal counts only when the server opens the INBOX right after it, a code
    or none. Refused with the INBOX too, the account is refused: each slice pauses and
    counts nothing, so an outage longer than OPEN_REFUSED_MAX slices leaves no folder out, and the
    start goes on once it is over."""
    put(provider, "Archive", 1)
    put(provider, "Private", 1)
    rescript(provider, faults=[{"command": "EXAMINE", "action": "no", "text": text}])
    status = None
    for _ in range(snapshot.OPEN_REFUSED_MAX + 1):
        row = Row(status=status)
        status = take(provider, taken, row)
        assert status == "paused" and f"EXAMINE Archive: {text}" in row.ended()[1]
    assert [f["open_refused"] for f in taken.read()["folders"]] == [0, 0, 0]
    assert (taken.read()["left_out"], row.left_out()) == ([], 0)
    rescript(provider)
    assert take(provider, taken, Row(status="paused")) == "done"
    assert sorted(copied(taken)) == [(".Archive", 1), (".Private", 1)]


@pytest.mark.parametrize("when", ["start", "walk"])
def test_a_folder_the_session_ends_over_every_time_is_left_out_once_the_inbox_answers_first(
        provider, taken, separate, when):
    """A session that ends while a folder is opened brings no answer: the slice pauses and
    counts nothing. The next slice to try that folder opens and searches the INBOX first,
    so an end over it again counts as a refusal to open it: a server that fails on opening
    one folder every time, at the start or later, holds up the rest for OPEN_REFUSED_MAX + 1
    slices, and not for ever."""
    put(provider, "Archive", 1)
    put(provider, "Lists", 1)
    if when == "walk":
        with logged_in(provider) as session:
            taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
    rescript(provider, faults=[{"command": "EXAMINE", "folder": "Archive", "action": "drop"}])
    before = len(read_log(provider.log_path))
    statuses = []
    for _ in range(snapshot.OPEN_REFUSED_MAX + 2):
        row = Row(status=statuses[-1] if statuses else (None if when == "start" else "pending"))
        statuses.append(take(provider, taken, row))
        if len(statuses) == 1:   # no answer: recorded, and nothing counted
            assert "EXAMINE Archive: the connection failed" in row.ended()[1]
            archive = [f for f in taken.read()["folders"] if f["name"] == "Archive"][0]
            assert (archive["open_cut_off"], archive["open_refused"]) == (True, 0)
    assert statuses == ["paused"] * (snapshot.OPEN_REFUSED_MAX + 1) + ["done"]
    (left,) = taken.read()["left_out"]
    assert left["name"] == "Archive"
    assert left["why"].startswith("EXAMINE Archive: the connection failed")
    assert row.left_out() == 1 and "1 left out: Archive" in row.ended()[1]
    assert sorted(copied(taken)) == [(".Lists", 1)]
    examined = [r["argument"] for r in read_log(provider.log_path)[before:]
                if r.get("command") == "EXAMINE"]
    tries = [i for i, name in enumerate(examined) if name == '"Archive"']
    assert len(tries) == snapshot.OPEN_REFUSED_MAX + 1
    assert all(examined[i - 1] == '"INBOX"' for i in tries[1:])   # the INBOX asked first


def test_a_provider_ending_every_session_at_an_examine_leaves_no_folder_out(provider, taken,
                                                                          separate):
    """Ending the session at the INBOX asked first as well, the provider answers nothing at
    all: however many slices that lasts, nothing is counted, and the walk goes on once it
    is over."""
    put(provider, "Archive", 1)
    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
    rescript(provider, faults=[{"command": "EXAMINE", "action": "drop"}])
    for _ in range(snapshot.OPEN_REFUSED_MAX + 1):
        row = Row(status="pending")
        assert take(provider, taken, row) == "paused"
        assert "the connection failed" in row.ended()[1]
    assert [f["open_refused"] for f in taken.read()["folders"]] == [0, 0]
    assert (taken.read()["left_out"], row.left_out()) == ([], 0)
    rescript(provider)
    assert take(provider, taken, Row(status="paused")) == "done"
    assert sorted(copied(taken)) == [(".Archive", 1)]
    assert [f["open_cut_off"] for f in taken.read()["folders"]] == [False, False]


@pytest.mark.parametrize("fault", [
    # Dovecot's answer to a message it cannot read, with `imap_fetch_failure = no-after`
    {"action": "no", "text": "[SERVERBUG] Internal error occurred. Refer to server log."},
    {"action": "no", "text": "[UNAVAILABLE] Temporary System Error"},
])
def test_a_message_refused_with_any_code_is_passed_when_the_server_hands_over_the_next(
        provider, taken, separate, fault):
    """Whatever its code, a refusal the server follows by handing over the next message is
    the message's own: it is passed, holds up nothing, and is asked for again later."""
    put(provider, "Archive", 1, 2, 3)
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "folder": "Archive", **fault}])
    row = Row(status=None)
    assert take(provider, taken, row) == "pending"   # every folder taken, one to ask again
    assert row.refused() == 1
    assert [f["refused"] for f in taken.read()["folders"]] == [[], [2]]
    assert fetched(provider) == ["1", "2", "3"]
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 3)]


def test_a_bye_while_the_server_answers_a_message_refuses_it_and_pauses_the_slice(
        provider, taken, separate):
    """Dovecot's default answer to a message it cannot read ends the session, so nothing can
    prove it: its refusal stands, the slice pauses, the next goes on past it, and the
    rounds ask for it again."""
    put(provider, "Archive", 1, 2, 3)
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "folder": "Archive",
                                "action": "bye", "text": "FETCH failed: Internal error"}])
    row = Row(status=None)
    assert take(provider, taken, row) == "paused"
    assert "message 2: the server ended the session: FETCH failed: Internal error" in \
        row.ended()[1]
    assert row.refused() == 1 and taken.read()["folders"][1]["refused"] == [2]
    assert take(provider, taken, Row(status="paused")) == "pending"   # 3, then a round
    assert fetched(provider) == ["1", "2", "3"]
    rescript(provider)
    assert take(provider, taken, Row(status="pending")) == "done"
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 2), (".Archive", 3)]


def test_a_provider_refusing_every_message_for_a_while_marks_none_refused_and_uses_no_round(
        provider, taken, separate):
    """A refusal stands only while the server still hands messages over. Refused with every
    message the copy already holds that is asked as the proof, PROOFS of them, the account
    is refused for now: the slice takes its refusals back and pauses, so an outage, however
    many slices it lasts, marks nothing refused and leaves no message out of the copy."""
    put(provider, "Archive", *range(1, 16))
    asked = []

    def after_three():
        asked.append(1)
        return len(asked) > 3

    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
        assert taken.walk(session, after_three, room) == snapshot.STOPPED
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 2), (".Archive", 3)]
    rescript(provider, faults=[{"command": "UID FETCH", "action": "no", "text":
                                "[OVERQUOTA] Account exceeded command or bandwidth limits."}])
    for _ in range(snapshot.ASK_AGAIN + 1):
        before = len(fetched(provider))
        row = Row(status="pending")
        assert take(provider, taken, row) == "paused"
        assert (f"{snapshot.REFUSED_IN_A_ROW} message(s) refused in Archive, and the messages "
                "copied before asked as the proof refused too" in row.ended()[1]
                and "refuses the account for now" in row.ended()[1])
        archive = taken.read()["folders"][1]
        assert (archive["refused"], archive["last"], row.refused()) == ([], 3, 0)
        asked_for = fetched(provider)[before:]   # the ten after the copy, then the proofs
        assert asked_for[:snapshot.REFUSED_IN_A_ROW] == [
            str(uid) for uid in range(4, 4 + snapshot.REFUSED_IN_A_ROW)]
        assert sorted(asked_for[snapshot.REFUSED_IN_A_ROW:]) == ["1", "2", "3"]
    rescript(provider)
    assert take(provider, taken, Row(status="paused")) == "done"
    assert len(copied(taken)) == 15 and taken.read()["asked_again"] == 0


def test_a_proof_the_provider_no_longer_has_proves_nothing(provider, taken, separate):
    """A copied message expunged since proves nothing: the next smallest is asked, PROOFS at
    most. One refused, the account is refused and the refusals are taken back; all of them
    expunged, nothing can prove the refusals, and they stand as in a folder with nothing
    copied: REFUSED_IN_A_ROW of them pause the slice."""
    put(provider, "Archive", *range(1, 16))
    (provider.account / "Archive" / "3").write_bytes(body("Archive", 3) + b"x" * 100)
    asked = []

    def after_three():
        asked.append(1)
        return len(asked) > 3

    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
        assert taken.walk(session, after_three, room) == snapshot.STOPPED
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 2), (".Archive", 3)]
    for uid in (1, 2):   # the two smallest copied, expunged at the provider since
        (provider.account / "Archive" / str(uid)).unlink()
    rescript(provider, faults=[{"command": "UID FETCH", "action": "no", "text":
                                "[OVERQUOTA] Account exceeded command or bandwidth limits."}])
    before = len(fetched(provider))
    row = Row(status="pending")
    assert take(provider, taken, row) == "paused"
    assert (f"{snapshot.REFUSED_IN_A_ROW} message(s) refused in Archive, and the messages copied "
            "before asked as the proof refused too (3 in Archive)" in row.ended()[1])
    archive = taken.read()["folders"][1]
    assert (archive["refused"], archive["last"], row.refused()) == ([], 3, 0)
    proofs = fetched(provider)[before + snapshot.REFUSED_IN_A_ROW:]
    assert (sorted(proofs[:2]), proofs[2:]) == (["1", "2"], ["3"])

    (provider.account / "Archive" / "3").unlink()   # none of them left to prove with
    row = Row(status="paused")
    assert take(provider, taken, row) == "paused"
    assert f"{snapshot.REFUSED_IN_A_ROW} messages in a row refused, the last in Archive" in \
        row.ended()[1]
    archive = taken.read()["folders"][1]
    assert archive["refused"] == list(range(4, 4 + snapshot.REFUSED_IN_A_ROW))
    assert archive["last"] == 3 + snapshot.REFUSED_IN_A_ROW


def test_a_copied_message_the_provider_now_refuses_alone_proves_nothing_and_the_next_is_asked(
        provider, taken, separate):
    """The proof may be refused for its own trouble: while the next smallest copied message
    is handed over, the refusals stand and the walk goes on, so one bad message of the copy
    does not pause every slice at its folder's end."""
    put(provider, "Archive", 1, 2, 3, 4)
    for uid in (2, 3):   # larger than 1, which is asked first as the proof
        (provider.account / "Archive" / str(uid)).write_bytes(body("Archive", uid) + b"x" * 10 * uid)
    asked = []

    def after_three():
        asked.append(1)
        return len(asked) > 3

    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
        assert taken.walk(session, after_three, room) == snapshot.STOPPED
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 2), (".Archive", 3)]
    rescript(provider, faults=[{"command": "UID FETCH", "folder": "Archive", "uid": uid,
                                "action": "no"} for uid in (1, 4)])
    before = len(fetched(provider))
    row = Row(status="pending")
    assert take(provider, taken, row) == "pending"   # 4 refused and standing, a round to come
    assert fetched(provider)[before:] == ["4", "1", "2"]
    archive = taken.read()["folders"][1]
    assert (archive["refused"], archive["last"], row.refused()) == ([4], 4, 1)


def opened_and_fetched(stub):
    """(EXAMINE, the folder) and (UID FETCH, the UID) of every one the stub was sent, in
    order."""
    return [(r["command"], r["argument"].split()[0].strip('"')) for r in read_log(stub.log_path)
            if r.get("command") in ("EXAMINE", "UID FETCH")]


def copy_then_stop(stub, taken, mark, messages):
    """The snapshot started and walked in one session until `messages` were asked for."""
    asked = []

    def after():
        asked.append(1)
        return len(asked) > messages

    with logged_in(stub) as session:
        taken.start(session, mark, snapshot.server_of(mailbox_at(stub)), never)
        assert taken.walk(session, after, room) == snapshot.STOPPED


@pytest.mark.parametrize("copied_before", [0, 3])
def test_a_folder_the_provider_refuses_whole_is_told_from_the_account_by_another_folders_copy(
        provider, taken, separate, copied_before):
    """With nothing of the folder's own copy handed over, none copied yet or each refused,
    the INBOX's copy is asked as the proof: handed over, the account answers, so the
    folder's refusals stand, and its walk goes on past REFUSED_IN_A_ROW, opened again, to
    its end. Neither pauses the snapshot for ever, and the rounds ask for them again."""
    put(provider, "INBOX", 1)
    put(provider, "Archive", *range(1, copied_before + 13))
    for uid in range(1, copied_before + 1):   # the smallest first, so asked in UID order
        (provider.account / "Archive" / str(uid)).write_bytes(body("Archive", uid) + b"x" * uid)
    mark = (UIDVALIDITY, 1)
    copy_then_stop(provider, taken, mark, 1 + copied_before)
    assert len(copied(taken)) == 1 + copied_before
    rescript(provider, faults=[{"command": "UID FETCH", "folder": "Archive", "action": "no"}])
    before = len(opened_and_fetched(provider))
    row = Row(status="pending")
    assert take(provider, taken, row, mailbox_at(provider, last=1)) == "pending"
    refused = list(range(copied_before + 1, copied_before + 13))
    archive = taken.read()["folders"][1]
    assert (archive["refused"], archive["last"], row.refused()) == (refused, refused[-1], 12)
    own = [("UID FETCH", str(uid)) for uid in range(1, copied_before + 1)]
    proof = [*own, ("EXAMINE", "INBOX"), ("UID FETCH", "1"), ("EXAMINE", "Archive")]
    walked = [("UID FETCH", str(uid)) for uid in refused]
    asked = opened_and_fetched(provider)[before:]
    assert asked[asked.index(("EXAMINE", "Archive")) + 1:] == [
        *walked[:snapshot.REFUSED_IN_A_ROW], *proof, *walked[snapshot.REFUSED_IN_A_ROW:],
        *proof]


def test_a_provider_refusing_every_message_where_nothing_is_copied_yet_marks_none_refused(
        provider, taken, separate):
    """A folder with nothing copied yet has no proof of its own, but the INBOX's copy is
    one: refused too, the account is refused for now, so an outage that starts at a
    folder's first message, however many slices it lasts, marks nothing refused there and
    uses up no round."""
    put(provider, "INBOX", 1)
    put(provider, "Archive", *range(1, 13))
    mark = (UIDVALIDITY, 1)
    copy_then_stop(provider, taken, mark, 1)
    assert sorted(copied(taken)) == [("INBOX", 1)]
    rescript(provider, faults=[{"command": "UID FETCH", "action": "no", "text":
                                "[OVERQUOTA] Account exceeded command or bandwidth limits."}])
    for _ in range(snapshot.ASK_AGAIN + 1):
        row = Row(status="pending")
        assert take(provider, taken, row, mailbox_at(provider, last=1)) == "paused"
        assert ("the messages copied before asked as the proof refused too (1 in INBOX): the "
                "provider refuses the account for now" in row.ended()[1])
        archive = taken.read()["folders"][1]
        assert (archive["refused"], archive["last"], row.refused()) == ([], 0, 0)
    rescript(provider)
    assert take(provider, taken, Row(status="paused"), mailbox_at(provider, last=1)) == "done"
    assert len(copied(taken)) == 13 and taken.read()["asked_again"] == 0


@pytest.mark.parametrize("ending", [
    {"action": "bye", "text": "FETCH failed: Internal error"},   # Dovecot's, by default
    {"action": "drop"},
])
def test_a_proof_that_ends_the_session_every_time_lets_the_refusals_stand_after_a_bound(
        provider, taken, separate, ending):
    """A session ended over a proof cannot say whose trouble it is: the refusals are taken
    back and the slice pauses, counted in the folder's `proof_ended`, and at the
    PROOF_ENDED_MAX-th slice in a row they stand and the walk goes past them. A copied
    message the server now fails over every time holds its folder up for that many slices,
    not for ever."""
    put(provider, "Archive", 1, 2, 3, 4)
    for uid in (2, 3):   # larger than 1, which is asked first as the proof
        (provider.account / "Archive" / str(uid)).write_bytes(body("Archive", uid) + b"x" * uid)
    copy_then_stop(provider, taken, (UIDVALIDITY, 0), 3)
    rescript(provider, faults=[
        {"command": "UID FETCH", "folder": "Archive", "uid": 4, "action": "no"},
        {"command": "UID FETCH", "folder": "Archive", "uid": 1, **ending}])
    for count in range(1, snapshot.PROOF_ENDED_MAX):
        row = Row(status="pending" if count == 1 else "paused")
        assert take(provider, taken, row) == "paused"
        assert (f"1 message(s) refused in Archive, and the session ended over a message copied "
                f"before asked as the proof, so whose trouble it is cannot be told: {count} of "
                f"{snapshot.PROOF_ENDED_MAX} slices in a row" in row.ended()[1])
        archive = taken.read()["folders"][1]
        assert (archive["refused"], archive["last"], archive["proof_ended"],
                row.refused()) == ([], 3, count, 0)
    row = Row(status="paused")
    assert take(provider, taken, row) == "paused"
    assert (f"it did so on {snapshot.PROOF_ENDED_MAX} slices in a row, so they stand"
            in row.ended()[1])
    archive = taken.read()["folders"][1]
    assert (archive["refused"], archive["last"], row.refused()) == ([4], 4, 1)
    rescript(provider)   # the provider sends both now: the round copies 4
    assert take(provider, taken, Row(status="paused")) == "done"
    assert sorted(copied(taken)) == [(".Archive", uid) for uid in (1, 2, 3, 4)]


def test_a_message_the_folder_hands_over_between_two_ended_proofs_starts_the_count_again(
        provider, taken, separate):
    """The bound counts slices in a row: a message of the folder handed over since the last
    ended proof shows the server answers there, so the count starts again from it."""
    put(provider, "Archive", 1, 2, 3, 4, 5)
    for uid in (2, 3):   # larger than 1, which is asked first as the proof
        (provider.account / "Archive" / str(uid)).write_bytes(body("Archive", uid) + b"x" * uid)
    copy_then_stop(provider, taken, (UIDVALIDITY, 0), 3)
    bye = {"command": "UID FETCH", "folder": "Archive", "uid": 1, "action": "bye"}
    for refused in ((4, 5), (5,)):   # 4 and 5 refused, then 4 handed over and 5 refused
        rescript(provider, faults=[*({"command": "UID FETCH", "folder": "Archive", "uid": uid,
                                      "action": "no"} for uid in refused), bye])
        assert take(provider, taken, Row(status="pending")) == "paused"
        archive = taken.read()["folders"][1]
        assert (archive["refused"], archive["last"], archive["proof_ended"]) == (
            [], refused[0] - 1, 1)
    assert sorted(copied(taken)) == [(".Archive", uid) for uid in (1, 2, 3, 4)]


def test_a_slice_that_stops_for_its_time_takes_its_unproven_refusals_back(provider, taken,
                                                                          separate):
    """Nothing handed over after them proved them: none is marked refused, and the next
    slice asks for them again from before the first."""
    put(provider, "Archive", 1, 2, 3, 4, 5)
    rescript(provider, faults=[{"command": "UID FETCH", "folder": "Archive", "uid": uid,
                                "action": "no"} for uid in (2, 3)])
    asked = []

    def after_three():
        asked.append(1)
        return len(asked) > 3

    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 0), snapshot.server_of(mailbox_at(provider)), never)
        assert taken.walk(session, after_three, room) == snapshot.STOPPED
    assert fetched(provider) == ["1", "2", "3"]
    archive = taken.read()["folders"][1]
    assert (archive["refused"], archive["last"]) == ([], 1)
    rescript(provider)
    assert walk(provider, taken) == snapshot.DONE
    assert sorted(copied(taken)) == [(".Archive", uid) for uid in range(1, 6)]
    assert taken.read()["folders"][1]["refused"] == []


def test_messages_refused_one_after_another_pause_the_slice_and_cost_it_only_those(
        provider, taken, separate):
    """A folder of which nothing is copied yet has nothing to prove a refusal with, so its
    refusals stand; a provider refusing everything there says so only by refusing
    everything: the slice stops at REFUSED_IN_A_ROW, so the rest of the account is not
    marked refused, and those it marked are asked for again once every folder is taken."""
    many = snapshot.REFUSED_IN_A_ROW + 2
    put(provider, "Archive", *range(1, many + 1))
    rescript(provider, faults=[{"command": "UID FETCH", "folder": "Archive", "action": "no"}])
    row = Row(status=None)
    assert take(provider, taken, row) == "paused"
    assert f"{snapshot.REFUSED_IN_A_ROW} messages in a row refused" in row.ended()[1]
    archive = taken.read()["folders"][1]
    assert archive["refused"] == list(range(1, snapshot.REFUSED_IN_A_ROW + 1))
    assert archive["last"] == snapshot.REFUSED_IN_A_ROW
    assert fetched(provider) == [str(uid) for uid in range(1, snapshot.REFUSED_IN_A_ROW + 1)]
    rescript(provider)
    assert take(provider, taken, Row(status="paused")) == "pending"   # the rest, then a round
    assert take(provider, taken, Row(status="pending")) == "done"
    assert len(copied(taken)) == many


def test_a_message_the_provider_refuses_is_passed_and_asked_for_again_by_the_next_slice(
        provider, taken, separate):
    """A message's own refusal (a NO with no code) holds up nothing: the rest is taken, and
    once every folder is, the next slice asks for the refused message alone again."""
    put(provider, "Archive", 1, 2, 3)
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 2, "folder": "Archive",
                                "action": "no"}])
    row = Row(status=None)
    assert take(provider, taken, row) == "pending"
    assert row.ended()[1].endswith(
        "1 message(s) the provider refused to send, not copied, asked for again 0 of 6 times; "
        "the next slice asks the provider for them again")
    assert row.refused() == 1
    assert [f["refused"] for f in taken.read()["folders"]] == [[], [2]]
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 3)]

    rescript(provider)   # the provider sends it now
    row = Row(status="pending")
    assert take(provider, taken, row) == "done"
    assert (row.refused(), "refused" not in row.ended()[1]) == (0, True)
    assert sorted(copied(taken)) == [(".Archive", 1), (".Archive", 2), (".Archive", 3)]
    assert fetched(provider) == ["1", "2", "3", "2"]   # the refused one alone, again
    assert taken.read()["asked_again"] == 1


def test_a_message_refused_through_every_round_ends_the_snapshot_done_without_it(
        provider, taken, separate):
    """A round a slice, ASK_AGAIN of them; then the snapshot is done, and the row counts what
    it does not hold. A refused message expunged meanwhile is dropped from the count. With
    no message after them to hand over, each round's refusals stand once the server hands
    over the one the copy holds."""
    put(provider, "Archive", 1, 2, 3)
    rescript(provider, faults=[{"command": "UID FETCH", "folder": "Archive", "uid": uid,
                                "action": "no"} for uid in (1, 2)])
    statuses = []
    for _ in range(snapshot.ASK_AGAIN + 1):
        row = Row(status=statuses[-1] if statuses else None)
        statuses.append(take(provider, taken, row))
        if statuses[-1] == "pending" and len(statuses) == 2:
            (provider.account / "Archive" / "1").unlink()   # expunged at the provider
    assert statuses == ["pending"] * snapshot.ASK_AGAIN + ["done"]
    assert row.refused() == 1
    assert row.ended()[1].endswith("1 message(s) the provider refused to send, not copied, "
                                   f"asked for again {snapshot.ASK_AGAIN} of "
                                   f"{snapshot.ASK_AGAIN} times")
    assert fetched(provider).count("2") == 1 + snapshot.ASK_AGAIN
    assert fetched(provider).count("3") == 1 + snapshot.ASK_AGAIN   # copied, then each proof
    assert sorted(copied(taken)) == [(".Archive", 3)]
    # done is done: no slice asks again
    assert take(provider, taken, Row(status="done")) == "done"
    assert fetched(provider).count("2") == 1 + snapshot.ASK_AGAIN


def test_a_message_that_outlasts_the_slices_hard_bound_leaves_it_pending_not_paused(
        provider, taken, separate, monkeypatch):
    """Past the slice's end and GRACE the session's own deadline stops even a message in
    hand: the next slice goes on, and nothing outside the snapshot paused it."""
    monkeypatch.setattr(snapshot, "GRACE", 1)
    (provider.account / "INBOX" / "1").write_bytes(b"Subject: slow\n\n" + b"y" * 200 + b"\n")
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 1, "action": "trickle",
                                "delay": 0.05}])
    row = Row(status=None)
    started = time.monotonic()
    assert take(provider, taken, row, mailbox_at(provider, last=1), seconds=1) == "pending"
    assert time.monotonic() - started < 5
    assert row.ended()[1].endswith("the slice's time ran out, and the next goes on")
    assert copied(taken) == {}
    rescript(provider)
    assert take(provider, taken, Row(status="pending")) == "done"
    assert sorted(copied(taken)) == [("INBOX", 1)]


def test_a_message_no_whole_slice_can_download_is_refused_at_its_second_cut_off(
        provider, taken, separate, monkeypatch):
    """Cut off once, the next slice starts with it; cut off again, that slice spent on it,
    it stands as refused, the walk goes on past it, and the rounds ask for it again: a
    message too slow for any slice holds up the rest only once."""
    monkeypatch.setattr(snapshot, "GRACE", 1)
    (provider.account / "INBOX" / "1").write_bytes(b"Subject: slow\n\n" + b"y" * 200 + b"\n")
    put(provider, "INBOX", 2)
    rescript(provider, faults=[{"command": "UID FETCH", "uid": 1, "action": "trickle",
                                "delay": 0.05}])
    row = Row(status=None)
    assert take(provider, taken, row, mailbox_at(provider, last=2), seconds=1) == "pending"
    inbox = taken.read()["folders"][0]
    assert (inbox["cut_off"], inbox["refused"], row.refused()) == (1, [], 0)
    row = Row(status="pending")
    assert take(provider, taken, row, seconds=1) == "pending"
    inbox = taken.read()["folders"][0]
    assert (inbox["refused"], inbox["last"], row.refused()) == ([1], 1, 1)
    assert copied(taken) == {}
    rescript(provider)   # sent at speed now
    assert take(provider, taken, Row(status="pending")) == "pending"   # 2, then a round
    assert take(provider, taken, Row(status="pending")) == "done"
    assert sorted(copied(taken)) == [("INBOX", 1), ("INBOX", 2)]
    assert fetched(provider) == ["1", "1", "2", "1"]


def test_a_message_that_ends_the_session_twice_in_a_row_is_refused_and_once_is_forgotten(
        provider, taken, separate):
    """A connection that closes with no BYE over a message is a cut-off, as the slice's
    deadline is: once, the next slice starts with it, and handed over then it is forgotten;
    twice in a row, the slice having opened and searched the folder to reach it, it stands
    as refused, the walk goes on past it, and the rounds ask for it again. A message that
    kills the server's process every time holds up the rest only once."""
    put(provider, "Archive", 1, 2, 3, 4)
    rescript(provider, faults=[{"command": "UID FETCH", "folder": "Archive", "uid": 2,
                                "action": "drop"}])
    row = Row(status=None)
    assert take(provider, taken, row) == "paused"
    assert "UID FETCH 2: the connection failed" in row.ended()[1]
    archive = taken.read()["folders"][1]
    assert (archive["cut_off"], archive["refused"], row.refused()) == (2, [], 0)
    rescript(provider, faults=[{"command": "UID FETCH", "folder": "Archive", "uid": 3,
                                "action": "drop"}])
    assert take(provider, taken, Row(status="paused")) == "paused"   # 2 handed over, 3 not
    archive = taken.read()["folders"][1]
    assert (archive["cut_off"], archive["refused"]) == (3, [])
    row = Row(status="paused")
    assert take(provider, taken, row) == "paused"
    archive = taken.read()["folders"][1]
    assert (archive["refused"], archive["last"], row.refused()) == ([3], 3, 1)
    rescript(provider)
    assert take(provider, taken, Row(status="paused")) == "pending"   # 4, then a round
    assert take(provider, taken, Row(status="pending")) == "done"
    assert taken.read()["folders"][1]["cut_off"] is None
    assert sorted(copied(taken)) == [(".Archive", uid) for uid in (1, 2, 3, 4)]
    assert fetched(provider) == ["1", "2", "2", "3", "3", "4", "3"]


def test_a_store_that_refuses_a_write_pauses_the_slice_and_the_next_goes_on(
        provider, taken, separate, monkeypatch):
    """A full or read-only filesystem is outside the snapshot: paused and tried again, never
    failed for good."""
    put(provider, "INBOX", 1, 2)
    write = snapshot.write

    def refusing(box, uidvalidity, message):
        if message.uid == 2:
            raise OSError(errno.ENOSPC, "No space left on device")
        return write(box, uidvalidity, message)

    monkeypatch.setattr(snapshot, "write", refusing)
    row = Row(status=None)
    assert take(provider, taken, row, mailbox_at(provider, last=2)) == "paused"
    assert row.ended()[1].startswith("the store refused a write: [Errno 28] No space left")
    assert row.ended()[1].endswith("the next slice tries again")
    monkeypatch.setattr(snapshot, "write", write)
    assert take(provider, taken, Row(status="paused")) == "done"
    assert sorted(copied(taken)) == [("INBOX", 1), ("INBOX", 2)]


def test_a_refused_login_or_an_unreachable_provider_pauses_and_a_missing_password_asks_nothing(
        provider, taken, separate):
    row = Row(status=None, secret="not the password")
    assert take(provider, taken, row) == "paused"
    assert "the next slice tries again" in row.ended()[1]
    assert "not the password" not in row.ended()[1]
    row = Row(status="paused")
    assert take(provider, taken, row, mailbox_at(provider, host="127.0.0.2")) == "paused"
    assert row.ended()[1].startswith(f"127.0.0.2:{provider.port}: ")   # the connection's own words
    assert row.ended()[1].endswith("; the next slice tries again")
    log = settled_length(provider.log_path)
    row = Row(status="paused", secret=None)
    assert take(provider, taken, row) == "paused"
    assert row.ended()[1].startswith("no password is stored")
    assert len(read_log(provider.log_path)) == log


def test_a_snapshot_whose_mailbox_changed_server_or_login_fails_and_asks_nothing(provider, taken,
                                                                                 separate):
    put(provider, "INBOX", 1, 2)
    with logged_in(provider) as session:
        taken.start(session, (UIDVALIDITY, 2), snapshot.server_of(mailbox_at(provider)), never)
    log = settled_length(provider.log_path)
    row = Row(status="pending")
    assert take(provider, taken, row, mailbox_at(provider, login="someone.else")) == "failed"
    assert "changed since the snapshot started" in row.ended()[1]
    assert len(read_log(provider.log_path)) == log
    # a renumbered INBOX fails it too, and what was written stays
    rescript(provider, uidvalidity={"INBOX": UIDVALIDITY + 1})
    row = Row(status="pending")
    assert take(provider, taken, row) == "failed"
    assert "renumbered the INBOX" in row.ended()[1]
    assert taken.home.exists()


def test_a_detail_naming_many_folders_is_cut_to_a_fetch_details_bound(provider, taken, separate):
    """The detail names every folder left out, and the mailbox's page and health's warning
    both show it: however many there are, the row keeps no more than a fetch's detail."""
    from maildivvy.fetch import outcome
    for n in range(40):
        put(provider, f"Тест{n:02}" + "ж" * 20, 1)   # sent in UTF-8: each left out, and named
    row = Row(status=None)
    assert take(provider, taken, row) == "done"
    assert row.left_out() == 40
    detail = row.ended()[1]
    assert len(detail) == outcome.DETAIL_MAX
    assert detail.startswith("1 of 1 folders taken, 0 messages, 0 bytes; 40 left out: Тест00")


def test_a_new_request_starts_over_and_a_fault_of_ours_fails_the_snapshot(provider, taken, separate,
                                                                          monkeypatch):
    """The fault's kind alone reaches the row, which the interface shows, as for a
    collection's own fault: its words may hold anything the session held."""
    put(provider, "INBOX", 1)
    (taken.home / "Maildir" / ".Old" / "cur").mkdir(parents=True)  # a snapshot no row holds
    assert take(provider, taken, Row(status=None), mailbox_at(provider, last=1)) == "done"
    assert folders(taken) == []

    def broken(*args):
        raise imap.Forbidden(f"STORE is not a command that only reads; {PASSWORD}")

    monkeypatch.setattr(snapshot.Snapshot, "walk", broken)
    row = Row(status="pending")
    assert take(provider, taken, row) == "failed"
    assert row.ended()[1] == "the slice stopped on a fault of its own: Forbidden"


def test_a_discard_removes_the_whole_snapshot_and_nothing_beside_it(taken):
    (taken.home / "Maildir" / "cur").mkdir(parents=True)
    (taken.root / "43").mkdir()
    assert snapshot.discard(42, taken.root) is True
    assert not taken.home.exists() and (taken.root / "43").is_dir()
    assert snapshot.discard(42, taken.root) is False


def test_the_row_keeps_since_when_its_slices_have_left_the_snapshot_paused(database):
    """What health reads to warn of a snapshot paused for longer than a day: the first slice
    that leaves it paused sets the time, the `running` of a slice between two pauses keeps
    it, and the first that leaves it otherwise clears it; a new snapshot and a discard start
    with none. Each statement as the slice and the pass run it, as the pipeline's own role,
    one transaction each."""
    from maildivvy.fanout import requests
    rid = database.value(
        "INSERT INTO external_mailbox (address, address_canonical, protocol, pop3_host, "
        "smtp_host, keep_at_provider, state, snapshot_requested_at) VALUES ('box@example.org', "
        "'box@example.org', 'imap', 'imap.example.org', 'smtp.example.org', true, 'active', "
        "now()) RETURNING id")
    conn = database.connect("pipeline")

    def run(*statements):
        with conn.cursor() as cur:
            for sql, params in statements:
                cur.execute(sql, params)
        conn.commit()
        return database.one("SELECT snapshot_status, snapshot_paused_since FROM "
                            "external_mailbox WHERE id = %s", (rid,))

    def a_slice(status, start=snapshot.SLICE_GOES_ON, manifest=None):
        return run((start, (rid,)),
                   (snapshot.SLICE_ENDS, snapshot.ending(status, "d", manifest, rid)))

    def missing():
        return database.one("SELECT snapshot_refused, snapshot_left_out FROM external_mailbox "
                            "WHERE id = %s", (rid,))

    try:
        first = a_slice("paused", snapshot.SLICE_STARTS)[1]
        assert first is not None
        assert a_slice("paused") == ("paused", first)
        assert run((snapshot.SLICE_GOES_ON, (rid,))) == ("running", first)   # a slice going on
        assert a_slice("paused") == ("paused", first)
        assert a_slice("pending") == ("pending", None)
        again = a_slice("paused")[1]
        assert again is not None and again > first
        for ended in ("done", "failed"):
            database.sql("UPDATE external_mailbox SET snapshot_paused_since = now() WHERE id = %s",
                         (rid,))
            assert a_slice(ended) == (ended, None)
        database.sql("UPDATE external_mailbox SET snapshot_paused_since = now() WHERE id = %s",
                     (rid,))
        assert a_slice("paused", snapshot.SLICE_STARTS)[1] > again        # a new snapshot's own
        # the messages the provider refused and the folders left out: written by every
        # slice, none for a new snapshot or a discarded one
        short = {"folders": [{"refused": [3, 4]}], "left_out": [{"name": "Private", "why": "w"}]}
        assert a_slice("done", manifest=short) == ("done", None) and missing() == (2, 1)
        run((snapshot.SLICE_STARTS, (rid,)))
        assert missing() == (None, None)
        a_slice("done", manifest=short)
        assert run((requests.DISCARDED, (rid,))) == (None, None) and missing() == (None, None)
    finally:
        conn.close()
