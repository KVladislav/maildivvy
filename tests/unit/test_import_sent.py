"""`maildivvy-import sent` on the unit tier's real database, with a store of its own:
the person's names, the archive's, the rows, and what a second run, a message
the Sent hook recorded live, a refused row and a person with no mailbox do.

Dovecot stands in only for the folders it makes, as the directories it would make.
"""

import hashlib
import os

import pytest

import eml_corpus
from maildivvy.fanout import ledger
from maildivvy.importer import run, sent, source
from maildivvy.lib import doveadm, store
from maildivvy.senthook import hook

HASH = "{SHA512-CRYPT}$6$x$" + "x" * 86


class World:
    def __init__(self, database, tmp_path, monkeypatch):
        self.database, self.tmp = database, tmp_path
        self.domain = database.value("INSERT INTO domain (label, archive_password_hash) VALUES "
                                     "('alpha', %s) RETURNING id", (HASH,))
        database.sql("INSERT INTO account (login, password_hash) VALUES ('ivan.p', %s), "
                      "('olga', %s)", (HASH, HASH))
        self.mailbox = database.value("INSERT INTO mailbox (account_id, domain_id) SELECT id, %s "
                                      "FROM account WHERE login = 'ivan.p' RETURNING id",
                                      (self.domain,))
        self.root = tmp_path / "store"
        self.made = []
        self.subscribed = []
        monkeypatch.setattr(doveadm, "create_folder", self.create_folder)
        monkeypatch.setattr(doveadm, "subscribed_folder", self.subscribed_folder)
        monkeypatch.setattr(run, "Reserve", lambda root: Room())
        self.paths = run.Paths(store_root=self.root, backup_paused=tmp_path / "p.json",
                               upgrade_paused=tmp_path / "u.json")
        self.source = tmp_path / "staging" / "sent"
        self.source.mkdir(parents=True)
        self.home = store.home("alpha", "ivan.p", self.root)
        self.archived = store.maildir(store.archive_home("alpha", self.root), "Sent/ivan.p")

    def create_folder(self, login, folder):
        """What Dovecot makes for `doveadm mailbox create`: the folder's maildir."""
        self.made.append((login, folder))
        account, _, label = login.partition("@")
        box = store.maildir(store.home(label, account, self.root), folder)
        for part in ("cur", "new", "tmp"):
            (box / part).mkdir(parents=True, exist_ok=True)

    def subscribed_folder(self, login, folder):
        """`doveadm mailbox create -s`: the folder's maildir, and the folder subscribed."""
        self.subscribed.append((login, folder))
        self.create_folder(login, folder)
        self.made.pop()

    def own_files(self):
        """`{name: path}` of every name in the `cur/` of the person's `Sent/<YYYY>` folders."""
        return {path.name: path for path in self.home.glob("Maildir/.Sent.[0-9][0-9][0-9][0-9]/cur/*")}

    def main(self, *more, login="ivan.p", name="result.tsv"):
        out = self.tmp / name
        code = run.main(["sent", "--domain", "alpha", "--login", login, "--source",
                         str(self.source), "--etc", str(self.database.etc), "--result", str(out),
                         *more], self.paths)
        return code, (out.read_text().splitlines() if out.exists() else [])


class Room:
    def room(self, size):
        pass


@pytest.fixture
def world(database, tmp_path, monkeypatch):
    return World(database, tmp_path, monkeypatch)


def statuses(lines):
    return {line.split("\t")[0]: (line.split("\t")[2], line.split("\t")[3])
            for line in lines if not line.startswith("#")}


def test_a_sent_message_is_named_in_the_persons_sent_and_the_archives_with_its_rows(world):
    made = eml_corpus.corpus(world.source, n=2, refusals=False)
    rows = []
    for m, flags in zip(made[:2], ("RS", "")):
        data = m.path.read_bytes()
        rows.append(f"{m.path.relative_to(world.source)}\t{hashlib.sha256(data).hexdigest()}"
                    f"\t{len(data)}\t\t{flags}")
    manifest = world.tmp / "manifest.tsv"
    manifest.write_text("\n".join(rows) + "\n")
    code, lines = world.main("--manifest", str(manifest))
    assert code == run.EX_OK, lines
    # the folders, made by name through Dovecot: the person's Sent, then the archive's
    # Sent and Sent/<account>, each with the archive's ACL
    assert world.made == [("ivan.p@alpha", "Sent"), ("archive@alpha", "Sent"),
                          ("archive@alpha", "Sent/ivan.p")]
    # and the person's year folder, subscribed, once for both
    assert world.subscribed == [("ivan.p@alpha", "Sent/2016")]
    own = sorted(world.own_files())
    archived = sorted(os.listdir(world.archived / "cur"))
    assert sorted(store.name_parts(n)[1] for n in own) == ["2,", "2,RS"]   # every flag it had
    assert {store.name_parts(n)[1] for n in archived} == {"2,S"}           # S alone
    for name in own:
        base = store.name_parts(name)[0]
        assert store.imported(base) is not None
        data = world.own_files()[name].read_bytes()
        sizes = store.IMPORTED.match(base).group(3, 4)   # the file's, and the one over IMAP
        assert sizes == (str(len(data)), str(eml_corpus.virtual_size(data)))
        twin = world.archived / "cur" / f"{base}:2,S"
        assert os.stat(world.own_files()[name]).st_ino == twin.stat().st_ino   # one file
        assert twin.stat().st_nlink == 2
    got = world.database.sql(
        "SELECT m.archive_uid, m.state, m.is_spam, m.sender, m.imported_at IS NOT NULL, "
        "extract(epoch FROM m.received_at)::bigint, d.mailbox_id, d.state FROM message m "
        "JOIN delivery d ON d.message_id = m.id ORDER BY m.id")
    assert [row[:5] for row in got] == [(None, "delivered", False, f"sender{n}@example.net", True)
                                        for n in (2, 1)]
    assert [row[5] for row in got] == [made[0].received, made[1].received]
    assert {row[6:] for row in got} == {(world.mailbox, "linked")}


def test_a_second_run_and_a_message_the_hook_recorded_live_add_nothing(world, monkeypatch):
    monkeypatch.setattr(run, "same_filesystem", lambda *a: False)    # copied: the source stays
    made = eml_corpus.corpus(world.source, n=3, refusals=False)
    live = [m for m in made if m.path.name == "0003.eml"][0]
    # the hook recorded this one when it was sent: a row with no archive number
    world.database.sql("INSERT INTO message (domain_id, message_id_header) VALUES (%s, %s)",
                       (world.domain, live.message_id))
    # the feed's copy of another, WITH an archive number, stops nothing (the hook's rule)
    world.database.sql("INSERT INTO message (domain_id, message_id_header, archive_uid) "
                       "VALUES (%s, '<corpus-1@example.org>', 5)", (world.domain,))
    code, first = world.main(name="first.tsv")
    found = statuses(first)
    assert code == run.EX_OK
    assert found["box1/0003.eml"][0] == source.DUPLICATE
    assert found["box1/0001.eml"] == (source.IMPORTED, "copied")
    names = sorted(world.own_files())
    rows = world.database.value("SELECT count(*) FROM message")
    code, second = world.main(name="second.tsv")
    assert code == run.EX_OK
    assert sorted(world.own_files()) == names
    assert world.database.value("SELECT count(*) FROM message") == rows
    assert {status for status, _ in statuses(second).values()} == {source.IMPORTED,
                                                                   source.DUPLICATE}


def test_a_person_with_no_mailbox_in_the_domain_is_refused(world):
    eml_corpus.corpus(world.source, n=1, refusals=False)
    assert world.main(login="olga")[0] == run.EX_FAULT
    assert world.main(login="nobody", name="nobody.tsv")[0] == run.EX_FAULT
    assert world.own_files() == {} and world.made == [] and world.subscribed == []


@pytest.mark.parametrize("mode", ["renamed", "copied"])
def test_a_row_the_ledger_refuses_takes_its_names_back(world, monkeypatch, mode):
    if mode == "copied":
        monkeypatch.setattr(run, "same_filesystem", lambda *a: False)
    made = eml_corpus.corpus(world.source, n=1, refusals=False)
    first = made[0].path
    data = first.read_bytes()

    class Refused(Exception):
        pgcode = "22021"   # a value of this message's own

    real = ledger.LINK
    calls = []

    def record(self, record, own):
        calls.append(record.shown)
        if len(calls) == 1:
            raise Refused("invalid byte sequence")
        return original(self, record, own)

    original = sent.Sent.record
    monkeypatch.setattr(sent.Sent, "record", record)
    code, lines = world.main()
    assert code == run.EX_OK and ledger.LINK == real
    status, reason = statuses(lines)["box1/0001.eml"]
    assert (status, reason) == (source.REFUSED, "the ledger refused its row: 22021")
    # its names are gone: the archive's link, and the person's own name put back or removed
    assert first.exists() and first.read_bytes() == data   # renamed back, or never moved
    assert first.stat().st_nlink == 1
    # the control: the same bytes under another path went in after it, one file, two names
    assert statuses(lines)["copies/same-bytes.eml"] == (source.IMPORTED, "" if mode == "renamed"
                                                         else "copied")
    assert len(world.own_files()) == 1 and len(os.listdir(world.archived / "cur")) == 1
    assert world.database.value("SELECT count(*) FROM delivery") == 1


@pytest.mark.parametrize("mode", ["renamed", "copied"])
def test_a_database_gone_under_a_sent_messages_rows_stops_the_run_and_takes_its_names_back(
        world, monkeypatch, mode):
    """As the incoming stage stops: 75 for the database going away, 1 for a statement of
    ours it refused, the names taken back either way."""
    if mode == "copied":
        monkeypatch.setattr(run, "same_filesystem", lambda *a: False)
    made = eml_corpus.corpus(world.source, n=1, refusals=False)
    first = made[0].path
    data = first.read_bytes()

    class Refused(Exception):
        pgcode = "42703"   # a column of ours that is not there

    for failure, code, last in (
            (world.database.psycopg2.OperationalError("server closed the connection unexpectedly"),
             run.EX_STOPPED, "# stopped the database went away (OperationalError: server closed "
                             "the connection unexpectedly): run the import again"),
            (Refused("column m.nothing does not exist"), run.EX_FAULT,
             "# stopped a fault: Refused: column m.nothing does not exist")):
        def record(self, record, own, failure=failure):
            raise failure

        with monkeypatch.context() as patched:
            patched.setattr(sent.Sent, "record", record)
            got, lines = world.main(name=f"{code}.tsv")
        assert (got, lines[-1]) == (code, last)
        assert [line for line in lines if not line.startswith("#")] == []   # no file has a line
        # its names are gone from both folders, and the file is where it was, whole
        assert world.own_files() == {} and os.listdir(world.archived / "cur") == []
        assert first.read_bytes() == data and first.stat().st_nlink == 1
        assert world.database.value("SELECT count(*) FROM message") == 0
    # the control: with the database back the same source goes in
    assert world.main()[0] == run.EX_OK
    assert len(world.own_files()) == 1 and len(os.listdir(world.archived / "cur")) == 1


def test_the_folders_are_made_as_the_hook_makes_them(monkeypatch, tmp_path):
    asked = []
    monkeypatch.setattr(doveadm, "create_folder", lambda login, folder: asked.append((login, folder)))
    box = hook.archive_folders("alpha", "ivan.p", tmp_path)
    assert asked == [("archive@alpha", "Sent"), ("archive@alpha", "Sent/ivan.p")]
    assert box == store.maildir(store.archive_home("alpha", tmp_path), "Sent/ivan.p")
    assert box.name == ".Sent.ivan^2ep"


class Killed(BaseException):
    """The run killed between the names and the rows: nothing of ours takes them back."""


def test_a_run_killed_between_the_names_and_the_rows_is_finished_by_the_next(world, monkeypatch):
    made = eml_corpus.corpus(world.source, n=2, refusals=False)
    with monkeypatch.context() as patched:
        patched.setattr(sent.Sent, "take_back", lambda *a: None)

        def killed(self, record, own):
            raise Killed()

        patched.setattr(sent.Sent, "record", killed)
        with pytest.raises(Killed):
            world.main(name="killed.tsv")
    # the first message is named in both places and has no row; its source is gone
    assert len(world.own_files()) == 1 and len(os.listdir(world.archived / "cur")) == 1
    assert world.database.value("SELECT count(*) FROM message") == 0
    first = made[0]
    assert not first.path.exists()
    # a dry run writes nothing, not even that
    assert world.main("--dry-run", name="dry.tsv")[0] == run.EX_OK
    assert world.database.value("SELECT count(*) FROM message") == 0
    code, lines = world.main()
    assert code == run.EX_OK
    rows = world.database.sql("SELECT m.message_id_header, extract(epoch FROM m.received_at)::bigint, "
                              "d.mailbox_id FROM message m JOIN delivery d ON d.message_id = m.id "
                              "ORDER BY m.id")
    assert rows[0] == (first.message_id, first.received, world.mailbox)
    assert len(rows) == 2 and len(world.own_files()) == 2
    assert len(os.listdir(world.archived / "cur")) == 2
    assert totals_of(lines)["held before"] == "1"


def totals_of(lines):
    return {line[2:].rsplit(" ", 1)[0]: line[2:].rsplit(" ", 1)[1]
            for line in lines if line.startswith("# ") and not line.startswith("# stopped")}


def test_sent_history_goes_into_a_subscribed_folder_of_its_year_and_a_second_run_reads_them_all(
        world, monkeypatch):
    monkeypatch.setattr(run, "same_filesystem", lambda *a: False)    # copied: the source stays
    made = eml_corpus.corpus(world.source, n=3, refusals=False)   # 2016, 2016, and 2017 by mtime
    assert world.main(name="first.tsv")[0] == run.EX_OK
    assert world.subscribed == [("ivan.p@alpha", "Sent/2016"), ("ivan.p@alpha", "Sent/2017")]
    years = {path.parent.parent.name: [] for path in world.own_files().values()}
    for path in world.own_files().values():
        years[path.parent.parent.name].append(store.imported(store.name_parts(path)[0]))
    assert sorted(years) == [".Sent.2016", ".Sent.2017"]
    assert sorted(years[".Sent.2017"]) == [m.received for m in made if m.received == eml_corpus.MTIME]
    assert not store.maildir(world.home, "Sent").joinpath("cur").exists() or \
        os.listdir(store.maildir(world.home, "Sent") / "cur") == []   # nothing in Sent itself
    names, rows = sorted(world.own_files()), world.database.value("SELECT count(*) FROM message")
    code, second = world.main(name="second.tsv")
    assert code == run.EX_OK and sorted(world.own_files()) == names
    assert world.database.value("SELECT count(*) FROM message") == rows
    assert totals_of(second)["held before"] == "3"
