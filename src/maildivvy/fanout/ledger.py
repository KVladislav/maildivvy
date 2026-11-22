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

⛔ KEY ON THE BASE NAME, NEVER ON THE UID (`0100`). A UID names a message only inside its
folder, and only while Dovecot keeps the numbering it gave; the
file's base name is the same in every folder and under every numbering, and is the name
of each of its hardlinks. Which folder a row's UID counts in is still the row's own
state, never something to guess from the UID.

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
    SELECT m.id, m.archive_base
      FROM message m JOIN domain d ON d.id = m.domain_id
     WHERE d.label = %s AND m.archive_base IS NOT NULL
"""
DELIVERIES = """
    SELECT dl.message_id, dl.mailbox_id
      FROM delivery dl JOIN message m ON m.id = dl.message_id
      JOIN domain d ON d.id = m.domain_id
     WHERE d.label = %s
"""
MAILBOXES = "SELECT mailbox_id, account FROM mailbox_receives WHERE domain = %s ORDER BY mailbox_id"
# Where the pass has read each archive folder to, the numbering that UID is of
# and the file it named (`0100`).
CURSORS = """
    SELECT c.mailbox, c.last_uid, c.uidvalidity, c.last_base
      FROM pass_cursor c JOIN domain d ON d.id = c.domain_id
     WHERE d.label = %s
"""
# The window's lookups: only the messages its names point at, by base name, which is the
# ledger's unique index (`0100`): one lookup per name, never every row of the domain.
MESSAGES_BY_BASE = """
    SELECT m.id, m.archive_base FROM message m
     WHERE m.domain_id = (SELECT id FROM domain WHERE label = %s) AND m.archive_base = ANY(%s)
"""
DELIVERIES_OF = "SELECT message_id, mailbox_id FROM delivery WHERE message_id = ANY(%s)"

# --- the numbering the cursor's UID belongs to (`0100`) ---------------------------------
#
# ⛔ A MESSAGE IS ITS FILE'S BASE NAME; A UID IS ONLY WHERE THE PASS HAS READ TO. The base name
# (Dovecot's storage id) never changes and is the name of every hardlink (`0100`); a UID names
# one file only while the folder's uidlist is the one it was given by. So before a tick
# lists a folder above its cursor it asks whether the cursor still means what it did: the
# folder's UIDVALIDITY is the one its row keeps (both index trees lost: a new one, numbered
# from 1), and the UID at the cursor is still there and names the file the cursor was moved
# to (the uidlist alone lost: every file numbered again above the old numbers under the same
# UIDVALIDITY; an older uidlist put back: the same numbers on other files). A folder that
# fails is CHANGED, and the tick gives its rows their new UIDs by base name and records
# whatever file has no row (`fanout/pass_.py`'s `reconcile`); nothing stops.
#
# ⛔ A ROW WITH NO BASE NAME YET IS NAMED BY ITS UID, AND ONLY UNDER THE NUMBERING IT WAS GIVEN.
# Rows the previous release wrote are UNNAMED until their folder's first tick under this one
# lists the folder and names them, which is right only while two facts hold. A folder
# renumbered before its rows were named has no exact way to them: it stops, and says the way
# back.

NUMBERING = ("SELECT uidvalidity, last_uid, last_base FROM pass_cursor "
             "WHERE domain_id = %s AND mailbox = %s")
ADOPT = ("UPDATE pass_cursor SET uidvalidity = %s "
         "WHERE domain_id = %s AND mailbox = %s AND uidvalidity IS NULL")
ADOPT_BASE = ("UPDATE pass_cursor SET last_base = %s "
              "WHERE domain_id = %s AND mailbox = %s AND last_base IS NULL")
# the cursor's file once the folder's rows are named: the previous release, run again by the
# upgrade's way back, moved `last_uid` and left this release's `last_base` behind it
NAMED_AT = "UPDATE pass_cursor SET last_base = %s WHERE domain_id = %s AND mailbox = %s"
# the UID the row of the cursor's last file was given, to ask whether it still names that file
UID_OF = "SELECT archive_uid FROM message WHERE domain_id = %s AND archive_base = %s"
# the folder's rows still named by their UID alone (migration 0012's `message_unnamed_idx`)
UNNAMED = """
    SELECT 1 FROM message WHERE domain_id = %s AND (state = 'delivered') = %s
       AND archive_uid IS NOT NULL AND archive_base IS NULL LIMIT 1
"""
NAME_BY_UID = """
    UPDATE message m SET archive_base = k.base
      FROM unnest(%s::bigint[], %s::text[]) AS k (uid, base)
     WHERE m.domain_id = %s AND (m.state = 'delivered') = %s
       AND m.archive_uid = k.uid AND m.archive_base IS NULL
"""
# a row whose UID names no file under a numbering that holds: its file was expunged by hand
NO_FILE = """
    UPDATE message SET archive_uid = NULL WHERE domain_id = %s AND (state = 'delivered') = %s
       AND archive_uid IS NOT NULL AND archive_base IS NULL
"""
# A changed numbering: every UID of the folder goes first (the unique index), then
# each row takes the UID its file has now; a row whose file is gone keeps none.
UNNUMBER = ("UPDATE message SET archive_uid = NULL "
            "WHERE domain_id = %s AND archive_uid IS NOT NULL AND (state = 'delivered') = %s")
NUMBER_BY_BASE = """
    UPDATE message m SET archive_uid = k.uid
      FROM unnest(%s::bigint[], %s::text[]) AS k (uid, base)
     WHERE m.domain_id = %s AND (m.state = 'delivered') = %s AND m.archive_base = k.base
"""
ROWLESS = """
    SELECT k.uid FROM unnest(%s::bigint[], %s::text[]) AS k (uid, base)
     WHERE NOT EXISTS (SELECT 1 FROM message m WHERE m.domain_id = %s AND m.archive_base = k.base)
     ORDER BY k.uid
"""
WITHOUT_FILE = """
    SELECT count(*) FROM message WHERE domain_id = %s AND (state = 'delivered') = %s
       AND archive_base IS NOT NULL AND archive_uid IS NULL
"""
# the previous release's way back, which a folder renumbered before its rows were named needs
PREVIOUS_RENUMBER = f"runuser -u {store.MAIL_USER} -- /opt/maildivvy/bin/maildivvy-pass"

KEPT, UNNAMED_ROWS, CHANGED = "kept", "unnamed", "changed"


class Numbering(NamedTuple):
    """What a folder's cursor means now: `state` KEPT, UNNAMED_ROWS (the numbering holds and
    rows wait for their names) or CHANGED; Dovecot's UIDVALIDITY and the base name at the
    cursor's UID (None: no such UID, or no cursor yet)."""

    state: str
    uidvalidity: int | None
    base: str | None


class Renumbered(Exception):
    """A folder numbered again before the rows of the previous release were named."""

    def __init__(self, label, folder, why):
        self.label, self.folder = label, folder
        super().__init__(
            f"{label} {folder}: {why}, before its rows had their archive names, so no row can "
            "be told its file: nothing is recorded or linked from it. Go back to the previous "
            "release (the upgrade's way back), run its "
            f"`{PREVIOUS_RENUMBER} --only {label} --folder {folder} --renumber`, and upgrade again")


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


def storage_at(label, folder, uid):
    """The base name of the file the folder numbers `uid`, or None for no such UID. Asked
    of a folder known to exist.

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
    for record in records:
        if record.get("uid") == str(int(uid)) and record.get("storageid"):
            return record["storageid"]
    return None


def numbering(cur, domain_id, label, folder):
    """The folder's `Numbering`, its cursor row locked by the caller; raises `Renumbered`
    for a folder numbered again while rows of it still wait for their names.

    A row keeping no UIDVALIDITY takes Dovecot's, and one keeping no base name the one at
    its UID, as the first tick after the upgrade does. A row or a folder that is not there
    has nothing to protect.
    """
    cur.execute(NUMBERING, (domain_id, folder))
    row = cur.fetchone()
    if row is None:
        return Numbering(KEPT, None, None)
    kept, last_uid, last_base = row
    now = uidvalidity(label, folder)
    if now is None:
        return Numbering(KEPT, None, None)
    if kept is None:
        cur.execute(ADOPT, (now, domain_id, folder))
        kept = now
    at = storage_at(label, folder, last_uid) if last_uid else None
    holds = int(kept) == now and (not last_uid or at is not None)
    cur.execute(UNNAMED, (domain_id, folder == INBOX))
    if cur.fetchone() is not None:
        if holds and last_base is not None and at != last_base:
            # The cursor moved without its base name (the previous release ran again after
            # this one), or an older uidlist was put back: either way the file this release
            # last read must still have the UID its row keeps.
            cur.execute(UID_OF, (domain_id, last_base))
            found = cur.fetchone()
            holds = (found is not None and found[0] is not None
                     and storage_at(label, folder, found[0]) == last_base)
            if not holds:
                raise Renumbered(label, folder, f"the archive's UID {int(last_uid)}, the "
                                                "cursor's, names another file than its rows say")
        if not holds:
            raise Renumbered(label, folder, (
                f"the archive's UIDVALIDITY is {now}, the ledger's UIDs are {int(kept)}'s"
                if int(kept) != now else
                f"the archive holds no UID {int(last_uid)}, the cursor's, any more"))
        return Numbering(UNNAMED_ROWS, now, at)
    if not holds or (last_base is not None and at != last_base):
        return Numbering(CHANGED, now, at)
    if last_base is None and at is not None:
        cur.execute(ADOPT_BASE, (at, domain_id, folder))
    return Numbering(KEPT, now, at)


def folder_records(label, folder):
    """Every file of the folder as Dovecot numbers it now: `[(uid, base name)]`, by UID."""
    records = doveadm.fetch(f"{store.ARCHIVE}@{label}", folder, ["uid", "storageid"], "all")
    return sorted((int(r["uid"]), r["storageid"]) for r in records if r.get("storageid"))


def name_rows(cur, domain_id, label, folder, found):
    """Give the folder's unnamed rows their base names, by the UIDs they were given under a
    numbering that still holds (`found` UNNAMED_ROWS); returns (named, without a file).

    A row whose UID names no file is a message expunged by hand: its UID is cleared, as a
    renumbering clears a row with no file, and it stays without a name.
    """
    listed = folder_records(label, folder)
    inbox = folder == INBOX
    cur.execute(NAME_BY_UID, ([uid for uid, _ in listed], [base for _, base in listed],
                              domain_id, inbox))
    named = cur.rowcount
    cur.execute(NO_FILE, (domain_id, inbox))
    gone = cur.rowcount
    cur.execute(NAMED_AT, (found.base, domain_id, folder))
    return named, gone


def renumber_rows(cur, domain_id, folder, listed):
    """Each of the folder's rows given the UID its file has now, by base name; returns
    (the UIDs of `listed` whose file no row names, how many of the folder's rows have no
    file). `listed` is `folder_records`' answer."""
    inbox = folder == INBOX
    uids, bases = [uid for uid, _ in listed], [base for _, base in listed]
    cur.execute(UNNUMBER, (domain_id, inbox))
    cur.execute(NUMBER_BY_BASE, (uids, bases, domain_id, inbox))
    cur.execute(ROWLESS, (uids, bases, domain_id))
    rowless = [int(uid) for uid, in cur.fetchall()]
    cur.execute(WITHOUT_FILE, (domain_id, inbox))
    return rowless, int(cur.fetchone()[0])


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


def by_base(rows):
    """`base name -> message id` from rows of (id, archive_base) (`0100`)."""
    return {base: message_id for message_id, base in rows}


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


def archive_listing(domain, root=store.STORE_ROOT):
    """`{folder: {base name: inode}}` of the archive's folders, from their directories; a
    folder that does not exist holds nothing and is left out.

    ⛔ A LISTING, AND NO `doveadm`, SINCE THE ROWS CARRY THE BASE NAME (`0100`). Only the
    directories' entries are read, for their names and inode numbers: no file is opened,
    nothing is picked to link, and a file still being written is in `tmp/`,
    which is not read. A name renamed from `new/` to `cur/` while this reads may be read
    twice, which one base holds once, or not at all, which the next run reads. Taken once
    and read twice by the daily pass: for the inodes the ledger has a row for, and for
    the files it has none for (`under_cursor`).
    """
    listing = {}
    for folder in FOLDERS:
        folder_maildir = store.maildir(store.archive_home(domain, root), folder)
        found, there = {}, False
        for part in store.PARTS:
            try:
                with os.scandir(folder_maildir / part) as entries:
                    there = True
                    for entry in entries:
                        found[store.base_name(entry.name)] = entry.inode()
            except FileNotFoundError:
                continue
        if there:
            listing[folder] = found
    return listing


def archive_inodes(domain, bases, root=store.STORE_ROOT, listing=None):
    """`inode -> message id` for every archive file the ledger has a row for.

    `bases` is `by_base`'s, and `listing` `archive_listing`'s answer when the caller took
    it already. A file the archive no longer holds is simply absent: a row outliving its
    file is normal.
    """
    listing = archive_listing(domain, root) if listing is None else listing
    found = {}
    for files in listing.values():
        for base, inode in files.items():
            message_id = bases.get(base)
            if message_id is not None:
                found[inode] = message_id
    return found


# --- the archive's messages no row holds --------------------------------------------
#
# ⛔ A MESSAGE THE PASS SKIPPED IS A FILE AT OR BELOW ITS FOLDER'S CURSOR WITH NO ROW. The pass
# moves its cursor past a message the database refused, naming it in one journal line; from
# then on no reading that starts from a row or from a person's mailbox can see it, since it
# has neither a row nor a name anywhere but the archive. The archive's own listing held to
# the rows is the one reading that lasts as long as the state does.
#
# ⛔ THE ROWS, THEN THE DIRECTORIES, THEN DOVECOT FOR WHAT IS ABOVE THE CURSOR. The rows and
# the cursors are read at one moment (a tick commits its rows and its cursor together), the
# folder's names after them, and Dovecot is asked last for the UIDs above the cursor read
# with the rows: a file that arrived after the rows is above that cursor whether or not a
# tick recorded it since, and so is never a finding. Rows read later than the names would
# name a whole archive whose domain was deleted in between, its rows first and its files
# after.
#
# ⛔ NEVER WHILE THE CURSOR MEANS SOMETHING ELSE (`0100`). A folder whose numbering
# changed is given its new numbers by the pass's next tick; until then "above the cursor"
# is not what it was, and the folder is named apart and not counted. So is a folder whose
# cursor has no base name yet: its rows are named by the pass's first tick of it.

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
    their cursor does not mean what it did, or does not say yet."""

    read: int
    unrecorded: list
    renumbered: list


def under_cursor(domain, listing, bases, cursors):
    """The archive's files at or below each folder's cursor that no row holds.

    `listing` is `archive_listing`'s, `bases` is `by_base`'s and `cursors` is `{folder:
    (last_uid, uidvalidity, last_base)}` from `CURSORS`, the last two read at one moment
    before the listing was taken. A folder with no cursor row, or one nothing was read of
    yet, has nothing at or below it. Dovecot is asked once a folder, for its UIDs from the
    cursor's up; and, only for a folder holding files with no row, once more for the UIDs
    of those, which the finding names.
    """
    login = f"{store.ARCHIVE}@{domain}"
    read, unrecorded, renumbered = 0, [], []
    for folder in FOLDERS:
        last_uid, kept, last_base = cursors.get(folder, (0, None, None))
        if folder not in listing or not last_uid:
            continue
        records = doveadm.fetch(login, folder, ["uid", "storageid"], "uid", f"{int(last_uid)}:*")
        at = {int(r["uid"]): r.get("storageid") for r in records}
        now = uidvalidity(domain, folder) if kept is not None else None
        if last_base is None or at.get(int(last_uid)) != last_base or (
                kept is not None and now != int(kept)):
            renumbered.append(folder)
            continue
        above = {base for uid, base in at.items() if uid > last_uid}
        below = [base for base in listing[folder] if base not in above]
        read += len(below)
        rowless = {base for base in below if base not in bases}
        if rowless:
            numbered = doveadm.fetch(login, folder, ["uid", "storageid"], "uid", f"1:{int(last_uid)}")
            uids = sorted(int(r["uid"]) for r in numbered if r.get("storageid") in rowless)
            unrecorded.append(Unrecorded(folder, len(rowless), uids[:NAMED]))
    return UnderCursor(read, unrecorded, renumbered)


def check(conn, domain, root=store.STORE_ROOT):
    """Every name in this domain's mailboxes that the ledger does not account for."""
    with conn.cursor() as cur:
        cur.execute(MESSAGES, (domain,))
        bases = by_base(cur.fetchall())
        cur.execute(DELIVERIES, (domain,))
        deliveries = {(message_id, mailbox_id) for message_id, mailbox_id in cur.fetchall()}
        cur.execute(MAILBOXES, (domain,))
        mailboxes = list(cur.fetchall())
    return unaccounted(archive_inodes(domain, bases, root), mailboxes, deliveries, domain, root)


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


def archive_bases(domain, inodes, root=store.STORE_ROOT):
    """`inode -> base name` for each of `inodes` the archive holds a file for.

    The archive's directories are listed for their names and inode numbers alone; which
    message a name is comes from its base name, which the row carries (`0100`), never
    from Dovecot's numbering.
    """
    found = {}
    for folder in FOLDERS:
        folder_maildir = store.maildir(store.archive_home(domain, root), folder)
        for part in store.PARTS:
            try:
                with os.scandir(folder_maildir / part) as entries:
                    for entry in entries:
                        if entry.inode() in inodes:
                            found[entry.inode()] = store.base_name(entry.name)
            except FileNotFoundError:
                continue
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
        names = archive_bases(domain, inodes, root)
        if names:
            cur.execute(MESSAGES_BY_BASE, (domain, sorted(set(names.values()))))
            rows = by_base(cur.fetchall())
            for inode, base in names.items():
                if base in rows:
                    by_inode[inode] = rows[base]
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
