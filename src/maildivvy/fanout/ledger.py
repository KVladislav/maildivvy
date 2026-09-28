"""The ledger's consistency check: which names in a mailbox the ledger does not account for.

What a defect is was settled by the design. A message file in a person's mailbox is one
of two things:

- **a link**: its inode is one the domain archive holds too, so it came through the
  external mailbox, received or sent, and the ledger accounts for it;
- **the person's own file**: anything else, in any folder, whatever their client put
  there - a draft, a template, mail dragged in from a local store. The ledger does not
  track it and this check ignores it.

⛔ THE DEFECT IS A NAME POINTING AT AN ARCHIVE INODE WITH NO DELIVERY ROW for that
message and that mailbox: a fan-out that ran without recording, or a copy made where a
link was meant.

⛔ THE OPPOSITE IS NORMAL AND MUST NEVER BE REPORTED: a delivery row whose
file is gone is a message the person deleted, and that surviving row is exactly what
stops a later top-up posting it back. An assertion "no linked row without a file" was
committed once with six agreeing fixtures and a live PASS, because nobody had deleted
anything yet; it would have gone FAIL on the first ordinary deletion.

⛔ COUNT BY INODE, NEVER BY NAME. An IMAP COPY inside one mailbox makes a
second name for one inode and writes no row, and the specification says that is not an
unaccounted write.

⛔ KEY ON THE FOLDER AND THE UID TOGETHER. A UID names a message only
inside its mailbox: one archive's UID 1 is a different message in INBOX and in the
quarantine folder. Which folder a row belongs to is the row's own state, never
something to guess from the UID.

⛔ SELECT ON WHAT THE PRODUCT WROTE, NEVER ON A STORED HEADER. A count of
this machine's own notices by a prefix match on the stored subject read 9 of 10 and
gave no sign it had missed one: the tenth's subject is stored as an encoded word, which
is what the product writes whenever the quoted subject is not ASCII.
"""

from pathlib import Path
from typing import NamedTuple

from maildivvy.lib import doveadm, store

INBOX = "INBOX"
FOLDERS = (INBOX, store.QUARANTINE)
EX_NOUSER = 68  # doveadm's exit for a mailbox that does not exist (measured)
PARTS = ("cur", "new")  # the maildir's message directories; bookkeeping files are elsewhere

# The archive's own rows: the product wrote every column named here.
MESSAGES = """
    SELECT m.id, m.archive_uid, m.state
      FROM message m JOIN domain d ON d.id = m.domain_id
     WHERE d.label = %s AND m.archive_uid IS NOT NULL
"""
DELIVERIES = """
    SELECT dl.message_id, dl.mailbox_id
      FROM delivery dl JOIN message m ON m.id = dl.message_id
      JOIN domain d ON d.id = m.domain_id
     WHERE d.label = %s
"""
MAILBOXES = "SELECT mailbox_id, account FROM mailbox_receives WHERE domain = %s ORDER BY mailbox_id"


class Finding(NamedTuple):
    """One name the ledger does not account for."""

    mailbox_id: int
    account: str
    message_id: int
    path: str

    def __str__(self):
        return (f"{self.account}: {self.path} is the archive's message {self.message_id} "
                f"with no delivery row for mailbox {self.mailbox_id}")

    def public(self):
        """The finding without its path: health's report is
        world-readable, and a folder's name in the path is a person's own words."""
        return (f"{self.account}: a name for the archive's message {self.message_id} "
                f"with no delivery row for mailbox {self.mailbox_id}")


def folder_of(state):
    """The archive folder a message row belongs to: its own state, never its UID."""
    return INBOX if state == "delivered" else store.QUARANTINE


def by_folder_and_uid(rows):
    """`(folder, uid) -> message id` from rows of (id, archive_uid, state)."""
    return {(folder_of(state), int(uid)): message_id for message_id, uid, state in rows}


def message_files(box):
    """Every message file of one maildir directory: `cur/` and `new/`, nothing else."""
    for part in PARTS:
        directory = Path(box) / part
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.is_file():
                yield path


def mailbox_files(home):
    """Every message file of a mailbox: its INBOX and each of its folders."""
    maildir = Path(home) / "Maildir"
    if not maildir.is_dir():
        return
    yield from message_files(maildir)
    for child in sorted(maildir.iterdir()):
        if child.is_dir() and child.name.startswith("."):
            yield from message_files(child)


def inode_of(path):
    """The file's inode, or None for a file that went away while this ran.

    A person deleting their copy is an ordinary act, and it happens while the check
    reads their mailbox as readily as at any other moment.
    """
    try:
        return path.stat().st_ino
    except OSError:
        return None


def unaccounted(archive_by_inode, mailboxes, deliveries, domain, root=store.STORE_ROOT):
    """The findings: one per (mailbox, archive message) held with no delivery row.

    `archive_by_inode` maps an inode the archive holds to its ledger message id,
    `mailboxes` is (mailbox_id, account) and `deliveries` the (message id, mailbox id)
    pairs the ledger holds. Counted by inode, so a second name for one message inside
    one mailbox is one holding.
    """
    findings = []
    for mailbox_id, account in mailboxes:
        seen = set()
        for path in mailbox_files(store.home(domain, account, root)):
            message_id = archive_by_inode.get(inode_of(path))
            if message_id is None or message_id in seen:
                continue  # the person's own file, or a second name for one inode
            seen.add(message_id)
            if (message_id, mailbox_id) not in deliveries:
                findings.append(Finding(mailbox_id, account, message_id, str(path)))
    return findings


def archive_inodes(domain, by_uid, root=store.STORE_ROOT):
    """`inode -> message id` for every archive file the ledger has a row for.

    The archive's names come from Dovecot by UID, never from a directory listing.
    A file the archive no longer holds is simply absent: a row outliving
    its file is normal.
    """
    login = f"{store.ARCHIVE}@{domain}"
    found = {}
    for folder in FOLDERS:
        try:
            records = doveadm.fetch(login, folder, ["uid", "storageid"], "all")
        except doveadm.DoveadmError as err:
            if err.returncode == EX_NOUSER:  # the folder does not exist: nothing is in it
                continue
            raise
        folder_maildir = store.maildir(store.archive_home(domain, root), folder)
        for record in records:
            message_id = by_uid.get((folder, int(record["uid"])))
            path = store.resolve(folder_maildir, record["storageid"]) if message_id else None
            inode = inode_of(path) if path is not None else None
            if inode is not None:
                found[inode] = message_id
    return found


def check(conn, domain, root=store.STORE_ROOT):
    """Every name in this domain's mailboxes that the ledger does not account for."""
    with conn.cursor() as cur:
        cur.execute(MESSAGES, (domain,))
        by_uid = by_folder_and_uid(cur.fetchall())
        cur.execute(DELIVERIES, (domain,))
        deliveries = {(message_id, mailbox_id) for message_id, mailbox_id in cur.fetchall()}
        cur.execute(MAILBOXES, (domain,))
        mailboxes = list(cur.fetchall())
    return unaccounted(archive_inodes(domain, by_uid, root), mailboxes, deliveries, domain, root)
