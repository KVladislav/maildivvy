"""`maildivvy-import sent`: a person's sent mail, where the Sent hook would have put it.

Each message goes into the person's own `Sent/<YYYY>`, the UTC year of its received moment,
made through Dovecot and subscribed, with every flag it carries, named
`cur/<received epoch>.<sha256>.import,S=<bytes>,W=<vsize>:2,<flags>`; the archive gains a
hardlink to the same file in `Sent/<account>` with `S` alone, the folders made by name
with the archive's ACL as the hook makes them; then, in one transaction, a message row
with no archive number (its `received_at` the received moment, `imported_at` the insert)
and the person's own delivery row, as the hook writes them. A failure after the names
takes them back: a renamed file goes back where it came from, a copy is removed.

⛔ DEDUPLICATED AS THE HOOK IS: against the domain's rows with NO archive number (the
hook's `RECORDED`), so the feed's copy of a sending, recorded with one, never stops it.

⛔ A RUN STOPPED BETWEEN THE NAMES AND THE ROWS IS FINISHED BY THE NEXT. Every run first
reads the imported names of every one of the person's `Sent/<YYYY>`, and gives one whose Message-ID has no row
its archive name and its rows, from the file in the store: its source is gone by then,
renamed. A message with no Message-ID cannot be told from one recorded; it stays as it is.
"""

import datetime
import os
import re

from maildivvy.fanout import ledger
from maildivvy.importer import run, source
from maildivvy.lib import doveadm, messageid, store
from maildivvy.senthook import hook

MAILBOX = """
    SELECT m.id FROM mailbox m JOIN account a ON a.id = m.account_id
     WHERE a.login = %s AND m.domain_id = %s
"""
# The domain's rows with no archive number, the hook's, above the last one read.
SENT_ROWS = """
    SELECT id, message_id_header FROM message
     WHERE domain_id = %s AND archive_uid IS NULL AND id > %s ORDER BY id
"""
RECORD = """
    INSERT INTO message (domain_id, message_id_header, archive_uid, state, message_date,
                         sender, subject, is_spam, received_at, imported_at)
    VALUES (%s, %s, NULL, 'delivered', %s, %s, %s, false, %s, clock_timestamp()) RETURNING id
"""
# Which of these Message-IDs the domain's rows with no archive number hold.
RECORDED = """
    SELECT DISTINCT message_id_header FROM message
     WHERE domain_id = %s AND archive_uid IS NULL AND message_id_header = ANY(%s)
"""
# A year folder of the person's Sent on disk: `Sent/2019` is `.Sent.2019`, digits
# never escaped (`store.escape`).
YEAR_DIR = re.compile(r"^\.Sent\.\d{4}$")
# The SQLSTATE classes one message's own values can raise (as the pass reads them).
ITS_OWN = ("22", "23", "54")


class Sent:
    """One person's Sent in one domain, and the archive's `Sent/<account>`."""

    kind = source.SENT

    def __init__(self, conn, domain, login, paths, dry_run=False):
        self.conn = conn
        self.dry_run = dry_run
        self.domain_id, self.label = domain
        self.account = login
        self.root = paths.store_root
        with conn.cursor() as cur:
            cur.execute(MAILBOX, (login, self.domain_id))
            row = cur.fetchone()
        conn.commit()
        if row is None:
            raise run.Fault(f"{login} has no mailbox in {self.label}")
        self.mailbox_id = row[0]
        self.login = f"{login}@{self.label}"
        self.home = store.home(self.label, login, self.root)
        self.archive_box = None
        self.years = set()
        self.last_id = 0

    def held(self):
        """The hashes the person's `Sent/<YYYY>` folders hold; a name a stopped run left
        without its rows is finished first, unless this is a dry run."""
        names = {}
        try:
            folders = [entry for entry in sorted(store.maildir(self.home).iterdir())
                       if entry.is_dir() and YEAR_DIR.match(entry.name)]
        except FileNotFoundError:
            folders = []
        for box in folders:
            for part in store.PARTS:
                try:
                    listed = os.listdir(box / part)
                except FileNotFoundError:
                    continue
                for name in listed:
                    found = store.IMPORTED.match(store.name_parts(name)[0])
                    if found:
                        names[found.group(2)] = box / part / name
        if names and not self.dry_run:
            self.finish(names)
        return set(names)

    def finish(self, names):
        """Give each imported name whose Message-ID has no row its archive name and rows."""
        by_id = {}
        for path in names.values():
            with open(path, "rb") as file:
                section = source.header_section(file.read(source.HEAD_LIMIT)) or []
            message_id = messageid.stored(source.first_value(section, "message-id") or None)
            if message_id:
                by_id[message_id] = path
        if not by_id:
            return
        with self.conn.cursor() as cur:
            cur.execute(RECORDED, (self.domain_id, list(by_id)))
            recorded = {row[0] for row in cur.fetchall()}
        self.conn.commit()
        for message_id, path in by_id.items():
            if message_id in recorded:
                continue
            base = store.name_parts(path)[0]
            archived = self.folders() / "cur" / f"{base}:2,S"
            try:
                os.link(path, archived)
            except FileExistsError:
                pass
            store.fsync_dirs([archived.parent])
            self.record(source.Record(path, path.name, message_id=message_id,
                                      received=store.imported(base)), path)

    def ids(self):
        with self.conn.cursor() as cur:
            cur.execute(SENT_ROWS, (self.domain_id, self.last_id))
            rows = cur.fetchall()
        self.conn.commit()
        if rows:
            self.last_id = rows[-1][0]
        return [(message_id, row_id) for row_id, message_id in rows]

    def folders(self):
        """The person's Sent, made through Dovecot when missing, and the archive's
        `Sent/<account>`, made by name with the archive's ACL; once a run."""
        if self.archive_box is None:
            try:
                doveadm.create_folder(self.login, hook.ONLY_MAILBOX)
                self.archive_box = hook.archive_folders(self.label, self.account, self.root)
            except doveadm.DoveadmError as err:
                raise run.Stop(f"Dovecot did not make the Sent folders: {err}") from None
        return self.archive_box

    def year(self, base):
        """The person's `Sent/<YYYY>` for this message, made through Dovecot and subscribed,
        once a run each; its maildir."""
        folder = store.year_folder(base, store.SENT)
        if folder not in self.years:
            try:
                doveadm.subscribed_folder(self.login, folder)
            except doveadm.DoveadmError as err:
                raise run.Stop(f"Dovecot did not make {folder}: {err}") from None
            self.years.add(folder)
        return store.maildir(self.home, folder)

    def put(self, record, reserve):
        archive_box = self.folders()
        base = store.import_base(record.received, record.sha256, record.size, record.vsize)
        box = self.year(base)
        how = run.put(record, box, f"{base}:2,{record.flags}", reserve)
        own = box / "cur" / f"{base}:2,{record.flags}"
        archived = archive_box / "cur" / f"{base}:2,S"
        made = []
        try:
            try:
                os.link(own, archived)
                made.append(archived)
            except FileExistsError:
                pass
            store.fsync_dirs([archived.parent])
            self.record(record, own)
        except BaseException as err:
            self.take_back(record, own, how, made)
            if isinstance(err, run.Stop | ValueError):
                raise
            if getattr(err, "pgcode", None) and err.pgcode[:2] in ITS_OWN:
                raise ValueError(f"the ledger refused its row: {err.pgcode}") from None
            if isinstance(err, OSError):
                raise run.Stop(f"the store refused a write: {err}") from None
            raise   # the run tells a database that went away from a fault (`run.went_away`)
        return how

    def record(self, record, own):
        """The message row and the person's delivery row, in one transaction, read as the
        hook reads a sent message's header block."""
        with open(own, "rb") as file:
            outgoing = hook.read_message(file.read(source.HEAD_LIMIT))
        with self.conn.cursor() as cur:
            cur.execute(RECORD, (self.domain_id, record.message_id, outgoing.date,
                                 outgoing.sender, outgoing.subject,
                                 datetime.datetime.fromtimestamp(record.received, datetime.UTC)))
            message_id = cur.fetchone()[0]
            cur.execute(ledger.LINK, (message_id, self.mailbox_id))
        self.conn.commit()

    def take_back(self, record, own, how, made):
        """The names this file was given, back off: its rows were never committed."""
        try:
            self.conn.rollback()
        except Exception:  # noqa: BLE001, S110 - the connection's own failure; the names go all the same
            pass
        for path in made:
            path.unlink(missing_ok=True)
        if how == "renamed":
            os.rename(own, record.path)
        else:
            own.unlink(missing_ok=True)
        store.fsync_dirs([own.parent, *(p.parent for p in made)])

    def wait(self, check, clock, sleep):
        """Each file's rows are committed with it: nothing to wait for but the hook's rows
        recorded meanwhile."""
        check()
        return self.ids()
