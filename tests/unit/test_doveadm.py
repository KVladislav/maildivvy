"""The doveadm wrapper against a stand-in binary: the argv it builds, how it reads the
answer, and what it refuses before running anything.

The stand-in records every argv it was given and plays back scripted answers in order.
What real doveadm answers is measured on the VM.
"""

import json
import sys

import pytest

from maildivvy.lib import doveadm, store
from maildivvy.lib.doveadm import DoveadmError

FAKE = """#!{python}
import json, os, sys, time
state = os.environ["FAKE_DIR"]
with open(os.path.join(state, "calls"), "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
answers = json.load(open(os.path.join(state, "answers")))
n = sum(1 for _ in open(os.path.join(state, "calls"))) - 1
answer = answers[min(n, len(answers) - 1)]
time.sleep(answer.get("sleep", 0))
sys.stdout.write(answer.get("out", "[]"))
sys.stderr.write(answer.get("err", ""))
sys.exit(answer.get("rc", 0))
"""


class Fake:
    def __init__(self, directory):
        self.dir = directory

    def answer(self, *answers):
        (self.dir / "answers").write_text(json.dumps(list(answers) or [{}]))

    @property
    def calls(self):
        path = self.dir / "calls"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.fixture
def fake(tmp_path, monkeypatch):
    binary = tmp_path / "doveadm"
    binary.write_text(FAKE.format(python=sys.executable))
    binary.chmod(0o755)
    monkeypatch.setattr(doveadm, "DOVEADM", str(binary))
    monkeypatch.setenv("FAKE_DIR", str(tmp_path))
    made = Fake(tmp_path)
    made.answer({})
    return made


def record(uid, base):
    return {"uid": str(uid), "storageid": base}


# --- JSON, and a nonzero exit -------------------------------------------------------

def test_every_call_asks_for_json_before_the_verb(fake):
    fake.answer({}, {"out": '[{"messages":"0"}]'}, {"out": "[]"})
    doveadm.run(("mailbox", "list"), "ivan@example")
    doveadm.fetch("ivan@example", "INBOX", ["uid", "hdr.from"], "all")
    first, status, fetched = fake.calls
    assert first == ["-f", "json", "mailbox", "list", "-u", "ivan@example"]
    assert status == ["-f", "json", "mailbox", "status", "-u", "ivan@example", "messages", "INBOX"]
    assert fetched == ["-f", "json", "fetch", "-u", "ivan@example", "uid hdr.from", "mailbox", "INBOX", "all"]


def test_the_answer_is_read_as_json_with_newlines_kept_inside_a_field(fake):
    fake.answer({"out": '[{"messages":"1"}]'},
                {"out": json.dumps([{"uid": "7", "hdr.x-note": "first\n uid: 999999\nuid: 888"}])})
    assert doveadm.fetch("ivan@example", "INBOX", ["uid", "hdr.x-note"], "all") == [
        {"uid": "7", "hdr.x-note": "first\n uid: 999999\nuid: 888"}]


@pytest.mark.parametrize("field", ["hdr.From", "UID", "hdr.message-id uid", ""])
def test_a_field_not_lowercase_or_not_one_word_is_refused_before_running(fake, field):
    with pytest.raises(ValueError):
        doveadm.fetch("ivan@example", "INBOX", ["uid", field], "all")
    assert fake.calls == []


def test_a_nonzero_exit_raises_with_the_code_and_doveadms_own_line(fake):
    fake.answer({"rc": 67, "err": "doveadm(x@example): Error: cmd fetch: User doesn't exist\n"})
    with pytest.raises(DoveadmError) as raised:
        doveadm.run(("mailbox", "list"), "x@example")
    assert raised.value.returncode == 67
    assert "User doesn't exist" in str(raised.value) and "mailbox list" in str(raised.value)


@pytest.mark.parametrize("out", ["uid: 1\nstorageid: abc\n", "", '{"uid": "1"}'])
def test_an_answer_that_is_not_a_json_list_raises(fake, out):
    fake.answer({"out": out})
    with pytest.raises(DoveadmError, match="JSON"):
        doveadm.run(("mailbox", "list"), "ivan@example")


def test_a_hung_doveadm_raises_after_the_timeout(fake):
    fake.answer({"sleep": 5})
    with pytest.raises(DoveadmError, match="timed out"):
        doveadm.run(("mailbox", "list"), "ivan@example", timeout=0.5)


def test_a_missing_mailbox_raises_rather_than_reading_as_empty(fake):
    # doveadm's fetch answers `[]` with exit 0 for a mailbox that does not exist
    # (measured on 2.4.2); the status call before it is what tells the two apart
    fake.answer({"rc": 68, "err": "Mailbox Nope: Failed to lookup mailbox status: Mailbox doesn't exist: Nope"})
    with pytest.raises(DoveadmError) as raised:
        doveadm.fetch("ivan@example", "Nope", ["uid"], "all")
    assert raised.value.returncode == 68 and len(fake.calls) == 1


# --- a storage id by UID, and the file it names ------------------------------------

BASE = "1789853107.M293776P70974.maildivvy-test,S=109,W=115"


def test_the_storage_id_is_asked_for_one_uid(fake):
    fake.answer({"out": '[{"messages":"3"}]'}, {"out": json.dumps([record(5, BASE)])})
    assert doveadm.storage_id("ivan@example", "Sent", 5) == BASE
    assert fake.calls[1] == ["-f", "json", "fetch", "-u", "ivan@example", "uid storageid", "mailbox", "Sent",
                             "uid", "5"]


@pytest.mark.parametrize("records", [[], [record(6, BASE)], [record(5, BASE), record(5, BASE + "x")]])
def test_no_single_record_for_the_uid_raises(fake, records):
    fake.answer({"out": '[{"messages":"3"}]'}, {"out": json.dumps(records)})
    with pytest.raises(DoveadmError, match="UID 5"):
        doveadm.storage_id("ivan@example", "Sent", 5)


def test_the_file_is_resolved_from_the_storage_id_and_the_stores_derivation(fake, tmp_path):
    folder = store.maildir(store.home("example", "archive", root=tmp_path), "Quarantine")
    (folder / "cur").mkdir(parents=True)
    (folder / "cur" / f"{BASE}:2,S").write_text("m")
    fake.answer({"out": '[{"messages":"1"}]'}, {"out": json.dumps([record(1, BASE)])})
    found = doveadm.message_file("example", "archive", "Quarantine", 1, root=tmp_path)
    assert found == folder / "cur" / f"{BASE}:2,S"
    assert fake.calls[-1][4] == "archive@example"


def test_an_unresolved_name_is_looked_up_once_more_then_raises(fake, tmp_path):
    folder = store.maildir(store.home("example", "archive", root=tmp_path))
    (folder / "new").mkdir(parents=True)
    (folder / "new" / "unrelated").write_text("m")
    status, found = {"out": '[{"messages":"1"}]'}, {"out": json.dumps([record(1, BASE)])}
    fake.answer(status, found, status, found)
    with pytest.raises(DoveadmError, match="no file"):
        doveadm.message_file("example", "archive", "INBOX", 1, root=tmp_path)
    assert [call[2] for call in fake.calls] == ["mailbox", "fetch", "mailbox", "fetch"]


def test_a_name_that_moved_between_the_two_lookups_is_found_by_the_second(fake, tmp_path):
    folder = store.maildir(store.home("example", "archive", root=tmp_path))
    (folder / "cur").mkdir(parents=True)
    (folder / "cur" / f"{BASE}B:2,").write_text("m")
    status = {"out": '[{"messages":"1"}]'}
    fake.answer(status, {"out": json.dumps([record(1, BASE + "A")])}, status,
                {"out": json.dumps([record(1, BASE + "B")])})
    assert doveadm.message_file("example", "archive", "INBOX", 1, root=tmp_path) == folder / "cur" / f"{BASE}B:2,"


# --- folders ------------------------------------------------------

def test_a_folder_is_created_through_doveadm(fake):
    assert doveadm.create_folder("ivan@example", "Sent/ivan.p") is True
    assert fake.calls == [["-f", "json", "mailbox", "create", "-u", "ivan@example", "Sent/ivan.p"]]


def test_already_exists_is_success(fake):
    fake.answer({"rc": 65, "err": "doveadm(ivan@example): Error: cmd mailbox create: "
                                  "Can't create mailbox Sent: Mailbox already exists\n"})
    assert doveadm.create_folder("ivan@example", "Sent") is False


@pytest.mark.parametrize("answer", [
    {"rc": 65, "err": "Error: cmd mailbox create: Can't create mailbox Sent: Invalid mailbox name\n"},
    {"rc": 75, "err": "Error: cmd mailbox create: Can't create mailbox Sent: Mailbox already exists\n"},
    {"rc": 77, "err": "Error: cmd mailbox create: Can't create mailbox Sent: Permission denied\n"},
])
def test_any_other_refusal_still_raises(fake, answer):
    fake.answer(answer)
    with pytest.raises(DoveadmError):
        doveadm.create_folder("ivan@example", "Sent")


@pytest.mark.parametrize("name", ["INBOX", "inbox", "Inbox"])
def test_inbox_is_never_created(fake, name):
    with pytest.raises(ValueError, match="INBOX"):
        doveadm.create_folder("ivan@example", name)
    assert fake.calls == []


@pytest.mark.parametrize("name", ["", "Sent/", "/Sent", "Sent//x", "a\0b"])
def test_a_malformed_folder_name_is_refused_before_running(fake, name):
    with pytest.raises(store.StoreError):
        doveadm.create_folder("ivan@example", name)
    assert fake.calls == []


def test_a_folder_in_an_archive_is_created_past_the_acl_and_given_the_archives_acl(fake):
    assert doveadm.create_folder("archive@example", "Sent/ivan") is True
    create, acl = fake.calls
    assert create == ["-f", "json", "-o", "mail_plugins/acl=no", "mailbox", "create", "-u", "archive@example",
                      "Sent/ivan"]
    assert acl == ["-f", "json", "acl", "set", "-u", "archive@example", "Sent/ivan",
                   "owner", "lookup", "read", "write-seen"]


def test_an_archive_folder_that_exists_is_still_given_its_acl(fake):
    fake.answer({"rc": 65, "err": "Can't create mailbox Sent: Mailbox already exists\n"}, {})
    assert doveadm.create_folder("archive@example", "Sent") is False
    assert fake.calls[1][2:4] == ["acl", "set"]


def test_a_persons_folder_is_created_subscribed(fake):
    assert doveadm.subscribed_folder("ivan@example", "Archives/2019") is True
    assert fake.calls == [["-f", "json", "mailbox", "create", "-s", "-u", "ivan@example",
                           "Archives/2019"]]


def test_a_persons_folder_that_exists_is_subscribed_again(fake):
    fake.answer({"rc": 65, "err": "Can't create mailbox Archives: Mailbox already exists\n"}, {})
    assert doveadm.subscribed_folder("ivan@example", "Archives") is False
    assert fake.calls[1] == ["-f", "json", "mailbox", "subscribe", "-u", "ivan@example", "Archives"]


def test_a_refused_subscribed_create_raises_and_subscribes_nothing(fake):
    fake.answer({"rc": 68, "err": "Error: User doesn't exist\n"})
    with pytest.raises(DoveadmError):
        doveadm.subscribed_folder("blocked@example", "Archives")
    assert len(fake.calls) == 1


@pytest.mark.parametrize(("login", "folder"), [("ivan@example", "INBOX"), ("archive@example", "Archives")])
def test_neither_inbox_nor_an_archives_folder_is_subscribed_this_way(fake, login, folder):
    with pytest.raises(ValueError):
        doveadm.subscribed_folder(login, folder)
    assert fake.calls == []


def test_only_the_archive_login_is_an_archive():
    assert doveadm.is_archive("archive@example")
    assert not doveadm.is_archive("ivan@example")
    assert not doveadm.is_archive("archive.p@example")
    assert not doveadm.is_archive("archive")


# --- the sessions open on a login --------------------------------------------------


def test_the_sessions_of_a_login_are_asked_for_by_mask_and_no_session_is_an_empty_list(fake):
    """⚠️ `doveadm who -1` prints a column header even when nobody is logged in, so a
    line count reads one session where there are none; the JSON formatter has none."""
    fake.answer({"out": "[]"}, {"out": '[{"username":"ivan@example","connections":"1"}]'})
    assert doveadm.sessions("ivan@example") == []
    assert doveadm.sessions("ivan@example") == [{"username": "ivan@example",
                                                 "connections": "1"}]
    assert fake.calls[0] == ["-f", "json", "who", "-1", "ivan@example"], \
        "the login is a mask here, not -u"


def test_a_who_that_fails_raises_rather_than_reading_as_no_session(fake):
    fake.answer({"rc": 75, "err": "net_connect_unix(/run/dovecot/anvil) failed"})
    with pytest.raises(DoveadmError) as raised:
        doveadm.sessions("ivan@example")
    assert raised.value.returncode == 75


# --- a cut answer, fetched again in halves -------------------------------------

def test_a_json_list_that_stops_short_with_exit_0_is_a_cut_answer(fake):
    fake.answer({"out": '[{"messages":"2"}]'}, {"out": '[\n{"uid":"1","hdr.subject":"ok"},\n{"uid":"2","hdr.subject":"ends in a'})
    with pytest.raises(doveadm.Cut, match="printed no JSON"):
        doveadm.fetch("ivan@example", "INBOX", ["uid", "hdr.subject"], "all")
    fake.answer({"out": "uid: 1\n"})
    with pytest.raises(DoveadmError) as raised:
        doveadm.run(("mailbox", "list"), "ivan@example")
    assert not isinstance(raised.value, doveadm.Cut)


class Cutting:
    """doveadm as measured on 2.4.2 (2026-11-24): every fetch that starts at `start` and
    reaches `at` is cut, exit 0; every other range, and `at` alone, reads whole."""

    def __init__(self, monkeypatch, uids, start, at):
        self.uids, self.start, self.at, self.fetched, self.statuses = sorted(uids), start, at, [], []
        monkeypatch.setattr(doveadm, "run", self.run)

    def run(self, verb, login, *args, **kwargs):
        if verb == ("mailbox", "status"):
            self.statuses.append(args[0])
            return [{"messages": str(len(self.uids)), "uidnext": str(self.uids[-1] + 1)}]
        assert verb == ("fetch",) and args[3] == "uid"
        self.fetched.append(args[4])
        wanted = sorted(set(self.matching(args[4])))
        if wanted and wanted[0] == self.start and self.at in wanted and wanted != [self.at]:
            raise doveadm.Cut(f"doveadm fetch -u {login} printed no JSON: Unterminated string")
        if wanted == [self.at] and self.start == self.at:
            raise doveadm.Cut(f"doveadm fetch -u {login} printed no JSON: Unterminated string")
        return [{"uid": str(uid), "storageid": f"b{uid}"} for uid in wanted]

    def matching(self, uid_set):
        for part in uid_set.split(","):
            first, _, last = part.partition(":")
            top = self.uids[-1] if last == "*" else int(last or first)
            low, high = sorted((int(first), top))
            yield from (uid for uid in self.uids if low <= uid <= high)


def test_a_cut_range_is_fetched_again_in_halves_and_every_record_comes_back_once(monkeypatch):
    # the reported domain: `uid 276165:*` cut in UID 276197's subject every minute
    doveadm_ = Cutting(monkeypatch, range(276165, 278165), start=276165, at=276197)
    records = doveadm.fetch("archive@example", "INBOX", ["uid", "storageid"], "uid", "276165:*")
    assert [int(r["uid"]) for r in records] == list(range(276165, 278165))
    assert doveadm_.statuses == ["messages", "uidnext"]  # `*` resolved once, on the cut
    assert len(doveadm_.fetched) < 30, doveadm_.fetched


def test_a_cut_uid_set_of_several_runs_is_split_by_run(monkeypatch):
    uids = [3, 4, 5, 9, 10, 20, 31, 32]
    doveadm_ = Cutting(monkeypatch, uids, start=3, at=10)
    records = doveadm.fetch("archive@example", "INBOX", ["uid", "storageid"], "uid", "3:5,9:10,20,31:32")
    assert [int(r["uid"]) for r in records] == uids
    assert doveadm_.fetched[:2] == ["3:5,9:10,20,31:32", "3:5,9:10"]


def test_a_single_uid_still_cut_raises_after_a_few_runs_and_not_one_per_uid(monkeypatch):
    doveadm_ = Cutting(monkeypatch, range(1, 100_001), start=1, at=1)
    with pytest.raises(doveadm.Cut):
        doveadm.fetch("archive@example", "INBOX", ["uid", "storageid"], "uid", "1:*")
    assert doveadm_.fetched[-1] == "1" and len(doveadm_.fetched) <= 20, doveadm_.fetched


def test_a_cut_answer_to_a_search_that_is_not_by_uid_raises_without_fetching_again(monkeypatch):
    doveadm_ = Cutting(monkeypatch, range(1, 10), start=1, at=5)

    def run(verb, login, *args, **kwargs):
        if verb == ("fetch",):
            doveadm_.fetched.append(args[3:])
            raise doveadm.Cut("doveadm fetch printed no JSON")
        return doveadm_.run(verb, login, *args, **kwargs)

    monkeypatch.setattr(doveadm, "run", run)
    with pytest.raises(doveadm.Cut):
        doveadm.fetch("archive@example", "INBOX", ["uid"], "all")
    assert doveadm_.fetched == [("all",)]
