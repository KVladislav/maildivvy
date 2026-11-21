"""A mailbox, an archive and a queue for the tests of a top-up or a connect in batches.

`bulk` is a fixture: `bulk(messages, batch=2, received="2020-01-01")` makes `alpha` with
ivan's mailbox on the unit tier's database, that many archived messages with their rows
and files, Dovecot answering for their numbers, `requests.BATCH` set to `batch` and a
page of the selection to two batches.
"""

import json

import pytest

from maildivvy.fanout import requests
from maildivvy.lib import store

HASH = "{SHA512-CRYPT}$6$x$" + "x" * 86


def named(uid_set):
    """The UIDs an IMAP sequence set names, as Dovecot reads `1:3,7`."""
    uids = []
    for part in uid_set.split(","):
        first, _, last = part.partition(":")
        uids.extend(range(int(first), int(last or first) + 1))
    return uids


class Lossy:
    """A connection whose `at`-th COMMIT is lost with the connection: `landed` says whether
    the database had committed it by then. Everything else is the connection's own."""

    def __init__(self, conn, at, landed, error):
        self.conn, self.at, self.landed, self.error = conn, at, landed, error
        self.commits = 0

    def __getattr__(self, name):
        return getattr(self.conn, name)

    def commit(self):
        self.commits += 1
        if self.commits != self.at:
            return self.conn.commit()
        if self.landed:
            self.conn.commit()
        self.conn.close()
        raise self.error("server closed the connection unexpectedly")


class Bulk:
    """`alpha` with ivan's mailbox, made now, and archived messages: their rows, their
    files in the archive's INBOX, and Dovecot answering for their numbers."""

    def __init__(self, database, tmp_path, monkeypatch, messages, received):
        self.database = database
        self.context = requests.Context(store_root=tmp_path / "store",
                                        index_root=tmp_path / "index")
        self.domain = database.value("INSERT INTO domain (label, archive_password_hash) VALUES "
                                     "('alpha', %s) RETURNING id", (HASH,))
        database.sql("INSERT INTO account (login, password_hash) VALUES ('ivan', %s)", (HASH,))
        self.mailbox = database.value(
            "INSERT INTO mailbox (account_id, domain_id) SELECT id, %s FROM account "
            "WHERE login = 'ivan' RETURNING id", (self.domain,))
        archive = store.maildir(store.archive_home("alpha", self.context.store_root))
        self.box = store.maildir(store.home("alpha", "ivan", self.context.store_root))
        for part in ("cur", "new", "tmp"):
            (archive / part).mkdir(parents=True)
            (self.box / part).mkdir(parents=True)
        self.ids = {}
        for uid in range(1, messages + 1):
            self.ids[uid] = f"17000000{uid:02d}.M{uid}P1.host"
            (archive / "cur" / f"{self.ids[uid]}:2,").write_text(f"message {uid}")
            database.sql("INSERT INTO message (domain_id, archive_uid, received_at) VALUES "
                         "(%s, %s, coalesce(%s, clock_timestamp()))", (self.domain, uid, received))
        self.fetched = []
        monkeypatch.setattr(requests.doveadm, "fetch", self.fetch)
        self.conns, self.pid, self.made = [], None, 0

    def fetch(self, login, folder, fields, *search):
        self.fetched.append(search[1])
        return [{"uid": str(uid), "storageid": self.ids[uid]}
                for uid in named(search[1])]

    def ask(self, kind="top_up", since="2000-01-01", until="2030-12-31"):
        payload = {"mailbox_id": self.mailbox}
        if kind == "top_up":
            payload.update(since=since, until=until)
        return self.database.value(
            "INSERT INTO request (kind, target, payload, asked_by) VALUES (%s, 'ivan@alpha', %s, "
            "'olga') RETURNING id", (kind, json.dumps(payload)))

    def connect(self):
        self.conns.append(self.database.connect("pipeline"))
        return self.conns[-1]

    def drain(self, lost=None, reconnect=True, **how):
        """One run of the drain on a connection of its own; `lost` is `(the commit that is
        lost with the connection, whether the database had committed it)`."""
        conn = self.connect()
        self.pid = conn.get_backend_pid()
        if lost:
            conn = Lossy(conn, *lost, self.database.psycopg2.OperationalError)
        try:
            return requests.drain(conn, self.context,
                                  reconnect=self.connect if reconnect else self.refused, **how)
        finally:
            conn.close()

    def refused(self):
        raise self.database.psycopg2.OperationalError("the database system is starting up")

    def close(self):
        for conn in self.conns:
            conn.close()

    def each_name(self, monkeypatch, then):
        """`then(how many names this world's requests have made)` after each one."""
        link = requests.link_name

        def counted(row, mailbox, context, source=None):
            touched = link(row, mailbox, context, source)
            self.made += 1
            then(self.made)
            return touched

        monkeypatch.setattr(requests, "link_name", counted)

    def dies_after(self, monkeypatch, names):
        """PostgreSQL ends the drain's own backend once it has made that many names."""
        self.each_name(monkeypatch, lambda made: made == names and self.database.sql(
            "SELECT pg_terminate_backend(%s)", (self.pid,)))

    def names(self):
        return sorted(p.name for p in (self.box / "new").iterdir())

    def given(self, uids):
        """The names of these messages, as the mailbox would hold them."""
        return sorted(self.ids[uid] for uid in uids)

    def rows(self):
        return self.database.value("SELECT count(*) FROM delivery WHERE mailbox_id = %s "
                                   "AND state = 'linked'", (self.mailbox,))

    def request(self, request_id):
        return self.database.one("SELECT state, result, payload FROM request WHERE id = %s",
                                 (request_id,))


@pytest.fixture
def bulk(database, tmp_path, monkeypatch):
    made = []

    def make(messages, batch=2, received="2020-01-01"):
        monkeypatch.setattr(requests, "BATCH", batch)
        monkeypatch.setattr(requests, "PAGE", 2 * batch)
        made.append(Bulk(database, tmp_path, monkeypatch, messages, received))
        return made[-1]

    yield make
    for each in made:
        each.close()
