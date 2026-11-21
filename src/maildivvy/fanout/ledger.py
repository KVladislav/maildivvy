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

import os
import stat
from pathlib import Path
from typing import NamedTuple

from maildivvy.lib import doveadm, store

# The archive's two folders, each with a UID sequence of its own.
# ⚠️ In no order anything may rely on: the pass reads the quarantine first and says so
# where it does (`fanout/pass_.py`'s `fan_out`).
INBOX = "INBOX"
FOLDERS = (INBOX, store.QUARANTINE)

# One more name for one message: the delivery row every program that makes a name in a
# person's mailbox writes, the pass, a request and the Sent hook alike. A repeated tick
# adds nothing.
LINK = """
    INSERT INTO delivery (message_id, mailbox_id, state, linked_at)
    VALUES (%s, %s, 'linked', now()) ON CONFLICT (message_id, mailbox_id) DO NOTHING
"""

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
# Where the pass has read each archive folder to, and the numbering that UID is of.
CURSORS = """
    SELECT c.mailbox, c.last_uid, c.uidvalidity
      FROM pass_cursor c JOIN domain d ON d.id = c.domain_id
     WHERE d.label = %s
"""
# The window's lookups: only the messages and the rows its names point at, each by its
# folder and UID together, which is the ledger's unique index: one lookup per
# name, never every row of the domain.
MESSAGES_BY_UID = """
    SELECT m.id, m.archive_uid, m.state
      FROM unnest(%s::boolean[], %s::bigint[]) AS k (inbox, uid)
      JOIN message m ON m.archive_uid = k.uid AND (m.state = 'delivered') = k.inbox
     WHERE m.domain_id = (SELECT id FROM domain WHERE label = %s) AND m.archive_uid IS NOT NULL
"""
DELIVERIES_OF = "SELECT message_id, mailbox_id FROM delivery WHERE message_id = ANY(%s)"

# --- the numbering the ledger's UIDs belong to -----------------------------------------
#
# ⛔ A UID NAMES ONE FILE ONLY WHILE THE FOLDER'S UIDLIST IS THE ONE IT WAS GIVEN BY. The
# pass's tick and every request that links by UID hold the folder to two facts before
# they read a UID, as measured on Dovecot 2.4.2: its UIDVALIDITY is the one kept
# on its cursor row, which a folder whose index trees were both lost changes as it
# numbers its files again from 1, closing any gap; and the cursor's own UID is still
# there, which a folder that lost its uidlist alone (`ctl/`) does not keep, since
# Dovecot numbers every file again above the old numbers under the same UIDVALIDITY. A
# row keeping no UIDVALIDITY takes Dovecot's, as the first tick after the upgrade does.

NUMBERING = "SELECT uidvalidity, last_uid FROM pass_cursor WHERE domain_id = %s AND mailbox = %s"
ADOPT = ("UPDATE pass_cursor SET uidvalidity = %s "
         "WHERE domain_id = %s AND mailbox = %s AND uidvalidity IS NULL")
# the way back's command, run as the mail owner (`fanout/pass_.py`'s `renumber`)
RENUMBER = f"runuser -u {store.MAIL_USER} -- /opt/maildivvy/bin/maildivvy-pass"


class Renumbered(Exception):
    """An archive folder no longer numbers its files as the ledger's UIDs were given."""

    def __init__(self, label, folder, why):
        self.label, self.folder = label, folder
        super().__init__(
            f"{label} {folder}: {why}, so a UID may name another message: nothing is "
            f"linked from it until `{RENUMBER} --only {label} --folder {folder} --renumber` "
            "gives the rows their new numbers")


def uidvalidity(label, folder):
    """The archive folder's UIDVALIDITY as Dovecot reads it now; None for a folder that
    is not there (a quarantine nothing was withheld into yet)."""
    try:
        status = doveadm.mailbox_status(f"{store.ARCHIVE}@{label}", folder, "uidvalidity")
    except doveadm.DoveadmError as err:
        if err.returncode == doveadm.EX_NOUSER:
            return None
        raise
    try:
        return int(status["uidvalidity"])
    except (KeyError, TypeError, ValueError):
        raise doveadm.DoveadmError(f"{store.ARCHIVE}@{label} {folder}: no UIDVALIDITY in "
                                   f"{status!r}") from None


def holds_uid(label, folder, uid):
    """Does the folder still hold this UID, its file looked up by name? Asked of a folder
    known to exist.

    ⚠️ BY ITS STORAGE ID, NEVER BY THE UID ALONE. A folder whose uidlist is gone and
    whose maildir has not changed since its last sync answers its old UIDs from the index;
    only a lookup of a file's name makes Dovecot read the folder and number its files
    again. That first lookup fails, the numbering done (2.4.2 panics printing it, exit
    134), so a failure is asked once more, and a second failure is Dovecot's own.
    """
    argv = ("uid storageid", "mailbox", folder, "uid", str(int(uid)))
    login = f"{store.ARCHIVE}@{label}"
    try:
        records = doveadm.run(("fetch",), login, *argv)
    except doveadm.DoveadmError:
        records = doveadm.run(("fetch",), login, *argv)
    return any(record.get("uid") == str(int(uid)) and record.get("storageid")
               for record in records)


def same_numbering(cur, domain_id, label, folder):
    """Raise `Renumbered` unless the folder still numbers its files as its cursor row says.

    A row that is not there, or a folder that is not there, has no UID of the ledger's
    to protect yet; a row keeping no UIDVALIDITY takes Dovecot's.
    """
    cur.execute(NUMBERING, (domain_id, folder))
    row = cur.fetchone()
    if row is None:
        return
    kept, last_uid = row
    now = uidvalidity(label, folder)
    if now is None:
        return
    if kept is None:
        cur.execute(ADOPT, (now, domain_id, folder))
    elif int(kept) != now:
        raise Renumbered(label, folder, f"the archive's UIDVALIDITY is {now}, the ledger's "
                                        f"UIDs are {int(kept)}'s")
    if last_uid and not holds_uid(label, folder, last_uid):
        raise Renumbered(label, folder, f"the archive holds no UID {int(last_uid)}, the "
                                        "cursor's, any more")


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
    """The archive folder a message row's UID counts in: its own state, never its UID.

    A withheld message's number is the quarantine folder's, and a RELEASED message is a
    withheld message whose state changed - its file never moved, so its number still
    counts there. Only a `delivered` message's counts in INBOX.
    """
    return INBOX if state == "delivered" else store.QUARANTINE


def by_folder_and_uid(rows):
    """`(folder, uid) -> message id` from rows of (id, archive_uid, state)."""
    return {(folder_of(state), int(uid)): message_id for message_id, uid, state in rows}


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
        findings += unaccounted_in(archive_by_inode, mailbox_id, account,
                                   lambda message_id, b=mailbox_id: (message_id, b) in deliveries,
                                   domain, root)
    return findings


def unaccounted_in(archive_by_inode, mailbox_id, account, has_row, domain, root=store.STORE_ROOT):
    """`unaccounted` over one mailbox, `has_row(message id)` saying whether the ledger
    holds that message's row for it: the daily pass reads one mailbox's rows at a time."""
    findings, seen = [], set()
    for path in store.mailbox_files(store.home(domain, account, root)):
        message_id = archive_by_inode.get(inode_of(path))
        if message_id is None or message_id in seen:
            continue  # the person's own file, or a second name for one inode
        seen.add(message_id)
        if not has_row(message_id):
            findings.append(Finding(mailbox_id, account, message_id, str(path)))
    return findings


def archive_listing(domain):
    """`{folder: Dovecot's records}` of the archive's folders, each record its `uid` and
    `storageid`; a folder that does not exist holds nothing and is left out.

    The archive's names come from Dovecot by UID, never from a directory listing.
    Taken once and read twice by the daily pass: for the inodes the ledger
    has a row for, and for the messages it has none for (`under_cursor`).
    """
    login = f"{store.ARCHIVE}@{domain}"
    listing = {}
    for folder in FOLDERS:
        try:
            listing[folder] = doveadm.fetch(login, folder, ["uid", "storageid"], "all")
        except doveadm.DoveadmError as err:
            if err.returncode != doveadm.EX_NOUSER:  # else no such folder: nothing is in it
                raise
    return listing


def archive_inodes(domain, by_uid, root=store.STORE_ROOT, listing=None):
    """`inode -> message id` for every archive file the ledger has a row for.

    `listing` is `archive_listing`'s answer when the caller took it already. A file the
    archive no longer holds is simply absent: a row outliving its file is normal.
    """
    listing = archive_listing(domain) if listing is None else listing
    found = {}
    for folder, records in listing.items():
        folder_maildir = store.maildir(store.archive_home(domain, root), folder)
        for record in records:
            message_id = by_uid.get((folder, int(record["uid"])))
            path = store.resolve(folder_maildir, record["storageid"]) if message_id else None
            inode = inode_of(path) if path is not None else None
            if inode is not None:
                found[inode] = message_id
    return found


# --- the archive's messages no row holds --------------------------------------------
#
# ⛔ A MESSAGE THE PASS SKIPPED IS A UID AT OR BELOW ITS FOLDER'S CURSOR WITH NO ROW. The pass
# moves its cursor past a message the database refused, naming it in one journal line; from
# then on no reading that starts from a row or from a person's mailbox can see it, since it
# has neither a row nor a name anywhere but the archive. The archive's own listing held to
# the rows is the one reading that lasts as long as the state does.
#
# ⛔ THE CURSORS AND THE ROWS ARE OF ONE MOMENT, AND THE LISTING IS TAKEN AFTER IT. A tick
# commits its rows and its cursor together, so a UID at or below a cursor read with the rows
# has a row among them unless it was skipped. A cursor read later than the rows would name
# every message a tick recorded in between; rows read later than the cursor would name a
# whole archive whose domain was deleted in between, its rows first and its files after.
# A UID above the cursor is mail the next tick records, and never a finding.
#
# ⛔ NEVER ACROSS A NUMBERING. The rows' UIDs and the listing's name the same
# files only while the folder numbers them as its cursor row says. A folder that fails
# either of the pass's two tests is named apart and not counted: the pass stops at it,
# health's fan-out check reads that, and `--renumber` tries every rowless file again.

# How many UIDs one folder's finding names; the count says how many there are.
NAMED = 10


class Unrecorded(NamedTuple):
    """One archive folder's messages at or below its cursor that no row holds."""

    folder: str
    count: int
    uids: list   # the first NAMED, oldest first


class UnderCursor(NamedTuple):
    """One domain's archive held to its rows: how many messages at or below the cursors
    were read, the folders holding some with no row, and the folders not read because
    their numbering is no longer the ledger's."""

    read: int
    unrecorded: list
    renumbered: list


def numbered_as_kept(domain, folder, kept, holds_cursor):
    """Does the folder still number its files as its cursor row says? The pass's own two
    tests (`same_numbering`), read without writing: whether the folder holds the cursor's
    UID is read from the listing already taken, which names every file."""
    if not holds_cursor:
        return False
    if kept is None:   # a row no tick has given a UIDVALIDITY yet: Dovecot's is taken
        return True
    now = uidvalidity(domain, folder)
    return now is not None and now == int(kept)


def under_cursor(domain, listing, by_uid, cursors):
    """The archive's messages at or below each folder's cursor that no row holds.

    `listing` is `archive_listing`'s, `by_uid` is `by_folder_and_uid`'s and `cursors` is
    `{folder: (last_uid, uidvalidity)}` from `CURSORS`, the last two read at one moment
    before the listing was taken. A folder with no cursor row, or one nothing was read of
    yet, has nothing at or below it.
    """
    read, unrecorded, renumbered = 0, [], []
    for folder in FOLDERS:
        last_uid, kept = cursors.get(folder, (0, None))
        if folder not in listing or not last_uid:
            continue
        below, rowless, holds_cursor = 0, [], False
        for record in listing[folder]:
            uid = int(record["uid"])
            if uid > last_uid:
                continue
            below += 1
            holds_cursor = holds_cursor or uid == last_uid
            if (folder, uid) not in by_uid:
                rowless.append(uid)
        if not numbered_as_kept(domain, folder, kept, holds_cursor):
            renumbered.append(folder)
            continue
        read += below
        if rowless:
            unrecorded.append(Unrecorded(folder, len(rowless), sorted(rowless)[:NAMED]))
    return UnderCursor(read, unrecorded, renumbered)


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


# --- the window: what changed since the last scan -------------------------------------
#
# ⛔ A NEW NAME FOR AN ARCHIVE INODE SETS TWO TIMES THE CHECK CAN READ: its directory's
# mtime (a name added, or renamed in or out of it) and the inode's ctime (a link counts
# up, and a rename sets it too). So a defect made since the last scan is a name whose
# inode's ctime is at or after it, in a directory whose mtime is at or after it, and
# nothing else needs reading. What was there before the window is the daily pass's.
#
# The window opens a minute before the last scan began: a file's times are the kernel's
# coarse clock, and a name made while the last scan was reading its directory is read again.
SLACK = 60
# Findings carried from one scan to the next, so a defect stays FAIL while its name is
# there and its row is not, though its ctime falls out of the window; the daily pass
# reads any beyond these.
CARRIED = 100


def changed_names(box_home, since):
    """(path, inode) of each name in one mailbox whose inode changed at or after `since`
    (seconds since the epoch) and has another name: an archive inode always does."""
    for directory in store.message_dirs(box_home):
        try:
            if directory.stat().st_mtime < since:
                continue
            with os.scandir(directory) as entries:
                listed = list(entries)
        except FileNotFoundError:
            continue   # a folder the person removed while this ran
        for entry in listed:
            try:
                found = entry.stat(follow_symlinks=False)
            except OSError:
                continue   # a name that went away while this ran
            if stat.S_ISREG(found.st_mode) and found.st_nlink > 1 and found.st_ctime >= since:
                yield Path(entry.path), found.st_ino


def names_of(box_home, inodes):
    """(path, inode) of each name in one mailbox whose inode is one of `inodes`: the
    listing's own inode numbers, so no file is opened or stat-ed."""
    for directory in store.message_dirs(box_home):
        try:
            with os.scandir(directory) as entries:
                listed = [(Path(e.path), e.inode()) for e in entries if e.inode() in inodes]
        except FileNotFoundError:
            continue
        yield from listed


def archive_uids(domain, inodes, root=store.STORE_ROOT):
    """`(folder, uid) -> inode` for each of `inodes` the archive holds a file for.

    The archive's directories are listed for their inode numbers alone; which message a
    name is comes from Dovecot, by its storage id (the base name a rename keeps), never
    from the name. A folder holding none of the inodes is not asked about.
    """
    login = f"{store.ARCHIVE}@{domain}"
    found = {}
    for folder in FOLDERS:
        folder_maildir = store.maildir(store.archive_home(domain, root), folder)
        bases = {}
        for part in store.PARTS:
            try:
                with os.scandir(folder_maildir / part) as entries:
                    for entry in entries:
                        if entry.inode() in inodes:
                            bases[store.base_name(entry.name)] = entry.inode()
            except FileNotFoundError:
                continue
        if not bases:
            continue
        try:
            records = doveadm.fetch(login, folder, ["uid", "storageid"], "all")
        except doveadm.DoveadmError as err:
            if err.returncode == doveadm.EX_NOUSER:
                continue
            raise
        for record in records:
            inode = bases.get(record.get("storageid"))
            if inode is not None:
                found[(folder, int(record["uid"]))] = inode
    return found


class Window(NamedTuple):
    """One domain's scan of what changed: its findings, how many names it read, and what
    the next scan carries, as [mailbox id, message id, inode]."""

    findings: list
    checked: int
    carry: list


def window(cur, domain, since, carried=(), root=store.STORE_ROOT):
    """The findings among the names changed at or after `since`, and those of `carried`
    (mailbox id, message id, inode) still held with no row.

    The same defect `unaccounted` finds, read from the names that changed alone: the
    archive and the ledger are asked only about the inodes those names hold.
    """
    cur.execute(MAILBOXES, (domain,))
    mailboxes = list(cur.fetchall())
    changed = {}
    for mailbox_id, account in mailboxes:
        changed[mailbox_id] = list(changed_names(store.home(domain, account, root), since))
    checked = sum(len(names) for names in changed.values())
    held = {}   # mailbox id -> {inode: message id}, the carried ones of this domain
    for mailbox_id, message_id, inode in carried:
        if mailbox_id in changed:
            held.setdefault(mailbox_id, {})[inode] = message_id
    for mailbox_id, account in mailboxes:
        if mailbox_id in held:
            names = names_of(store.home(domain, account, root), set(held[mailbox_id]))
            changed[mailbox_id].extend(names)
    inodes = {inode for names in changed.values() for _, inode in names}
    by_inode = {}
    if inodes:
        uids = archive_uids(domain, inodes, root)
        if uids:
            pairs = sorted(uids)
            cur.execute(MESSAGES_BY_UID, ([folder == INBOX for folder, _ in pairs],
                                          [uid for _, uid in pairs], domain))
            for (folder, uid), message_id in by_folder_and_uid(cur.fetchall()).items():
                if (folder, uid) in uids:
                    by_inode[uids[(folder, uid)]] = message_id
    for inodes_held in held.values():
        for inode, message_id in inodes_held.items():
            by_inode.setdefault(inode, message_id)
    deliveries = set()
    if by_inode:
        cur.execute(DELIVERIES_OF, (sorted(set(by_inode.values())),))
        deliveries = {(m, b) for m, b in cur.fetchall()}
    findings, carry = [], []
    for mailbox_id, account in mailboxes:
        seen = set()
        for path, inode in changed[mailbox_id]:
            message_id = by_inode.get(inode)
            if message_id is None or message_id in seen:
                continue   # the person's own file, or a second name for one inode
            seen.add(message_id)
            if (message_id, mailbox_id) not in deliveries:
                findings.append(Finding(mailbox_id, account, message_id, str(path)))
                carry.append([mailbox_id, message_id, inode])
    return Window(findings, checked, carry)
