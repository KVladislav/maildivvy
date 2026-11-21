"""`maildivvy-import incoming`: a domain archive's INBOX.

Each message is written into the archive's INBOX as
`cur/<received epoch>.<sha256>.import,S=<bytes>,W=<vsize>:2,` (or `:2,S`), and nothing
else: the pass tells the file by that name, records it, and links it to nobody
(`fanout/pass_.py`). `W=` is the size Dovecot gives the message over IMAP (`lib/store.py`).
So the pass stays the INBOX's only recorder, and live collection into the same INBOX
during an import needs no coordination of its own.

⛔ BACK-PRESSURE THROUGH THE PASS'S CURSOR. After a slice the run has Dovecot sync the
INBOX, reads its UIDNEXT, and waits until the pass's INBOX cursor is at UIDNEXT - 1 or
past it, then reads the domain's message rows above the last one it saw. So
deduplication sees every earlier slice and what live collection recorded meanwhile, and
one tick of the pass never holds more than a slice of imported files. A pass that does
not get there within the bound stops the run: the slice is in the store, and the next
run finds it by its hashes, and waits the same way before its first file, since the
hashes of a slice the pass has not recorded yet come without its Message-IDs.

⛔ A FILE WRITTEN IS NOT A MESSAGE RECORDED. The pass may skip a message it cannot
record and move its cursor past it. Once the cursor is past a slice, the run counts the
imported names among the UIDs it passed that have no row, and its result says
`# unrecorded <n>` when there are any: the daily ledger pass names them the next night,
and the result does not claim meanwhile what the ledger lacks.
"""

from maildivvy.importer import run, source
from maildivvy.lib import doveadm, store

# The domain's rows with an archive number, the ones incoming mail is deduplicated
# against, above the last one read.
ARCHIVED = """
    SELECT id, message_id_header FROM message
     WHERE domain_id = %s AND archive_uid IS NOT NULL AND id > %s ORDER BY id
"""
CURSOR = "SELECT last_uid FROM pass_cursor WHERE domain_id = %s AND mailbox = 'INBOX'"
# The INBOX numbers of a range that an imported row holds.
RECORDED = """
    SELECT archive_uid FROM message
     WHERE domain_id = %s AND state = 'delivered' AND imported_at IS NOT NULL
       AND archive_uid BETWEEN %s AND %s
"""


class Incoming:
    """The archive's INBOX of one domain."""

    kind = source.INCOMING

    def __init__(self, conn, domain, paths):
        self.conn = conn
        self.domain_id, self.label = domain
        self.login = f"{store.ARCHIVE}@{self.label}"
        self.box = store.maildir(store.archive_home(self.label, paths.store_root))
        self.last_id = 0
        self.counted = None     # the last UID whose row was looked for
        self.cursor_at_start = self.cursor()
        self.unrecorded = 0
        if not (self.box / "cur").is_dir():
            raise run.Fault(f"the archive of {self.label} has no INBOX at {self.box}: the "
                            "domain's archive is made when the domain is created")

    def held(self):
        return run.imported_hashes(self.box)

    def ids(self):
        """`(stored Message-ID, row id)` of the archive's rows above the last one read."""
        with self.conn.cursor() as cur:
            cur.execute(ARCHIVED, (self.domain_id, self.last_id))
            rows = cur.fetchall()
        self.conn.commit()
        if rows:
            self.last_id = rows[-1][0]
        return [(message_id, row_id) for row_id, message_id in rows]

    def put(self, record, reserve):
        base = store.import_base(record.received, record.sha256, record.size, record.vsize)
        name = f"{base}:2,{'S' if 'S' in record.flags else ''}"
        return run.put(record, self.box, name, reserve)

    def cursor(self):
        with self.conn.cursor() as cur:
            cur.execute(CURSOR, (self.domain_id,))
            row = cur.fetchone()
        self.conn.commit()
        return row[0] if row else 0

    def count_unrecorded(self, last):
        """Add the imported names numbered after the last count, up to `last`, that no row
        holds. The first count starts at the cursor as the run found it."""
        if self.counted is None:
            self.counted = min(self.cursor_at_start, last)
        if last <= self.counted:
            return
        first, self.counted = self.counted + 1, last
        try:
            records = doveadm.fetch(self.login, "INBOX", ["uid", "storageid"], "uid",
                                    f"{first}:{last}")
        except doveadm.DoveadmError as err:
            raise run.Stop(f"Dovecot did not say which messages the pass passed: {err}") from None
        named = {int(r["uid"]) for r in records if store.imported(r.get("storageid"))}
        with self.conn.cursor() as cur:
            cur.execute(RECORDED, (self.domain_id, first, last))
            held = {row[0] for row in cur.fetchall()}
        self.conn.commit()
        self.unrecorded += len(named - held)

    def wait(self, check, clock, sleep, bound=None):
        """Until the pass recorded everything the INBOX holds now; then the new rows."""
        bound = run.WAIT_BOUND if bound is None else bound
        check()   # a pause is the reason to give, not what Dovecot answers during it
        try:
            uidnext = int(doveadm.mailbox_status(self.login, "INBOX", "uidnext")["uidnext"])
        except (doveadm.DoveadmError, KeyError, ValueError) as err:
            raise run.Stop(f"Dovecot did not say where the INBOX stands: {err}") from None
        deadline = clock() + bound
        while True:
            at = self.cursor()
            if at >= uidnext - 1:
                self.count_unrecorded(uidnext - 1)
                return self.ids()
            if clock() >= deadline:
                raise run.Stop(f"the pass did not record the slice within {bound} s (its "
                               f"cursor is at {at}, the INBOX's last UID {uidnext - 1}): is "
                               "maildivvy-pass.timer running?")
            sleep(run.POLL)
            check()
