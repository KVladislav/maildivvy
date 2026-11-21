"""The pass: record what the archive holds, and give every receiver a name for it.

    maildivvy-pass [--only <domain>] [--store-root <the store's root>]
    maildivvy-pass --only <domain> [--folder <folder>] --uid <n>    a skipped message, by hand
    maildivvy-pass --only <domain> [--folder <folder>] --renumber   a folder Dovecot renumbered

A timer runs this every minute for every domain, including a domain with no external
mailbox in front of it: a free domain is ordinary, mail can still be put into its
archive, and a pass that selected its domains by joining onto the external mailbox
would drop those domains in silence.

⛔ THIS IS THE ONLY MAKER OF NAMES FOR INCOMING MAIL. One file
per message, one more name per receiver, never a copy. Anything else that writes into a
person's mailbox is that person's own file, which the ledger does not track.

⛔ ONE CURSOR PER (DOMAIN, MAILBOX), EACH MOVED ONLY BY ITS OWN LOOP. INBOX
and the quarantine folder have independent UID sequences: a single cursor asked the
quarantine for `22:*` after 21 INBOX messages and never saw the one infected message
there - no row, no report link, nothing to release, and nothing logged.

⛔ THE CURSOR MOVES LAST, AND ONLY WHEN THE TICK SUCCEEDED. A failed tick
leaves it where it was and the next tick repeats the work, which is safe because the
message is in the archive already and nobody else has a name for it yet. A failed
domain rolls back on its own and the other domains carry on.

⛔ NO ONE MESSAGE MAY HOLD A DOMAIN'S CURSOR. Reading a message is total: a
header that will not parse is None, never an exception. Each message is then recorded
and linked inside its own savepoint, and one the database refuses is rolled back to it,
named in one `maildivvy-pass: skipped:` line with the command that records it by hand,
and passed: the cursor moves past it. Once, a Date the standard library could not hold
and a Message-ID longer than the index takes each stopped a domain's fan-out for good,
repeated every minute. Before it is skipped, a message the database refuses is tried
once more without its subject, sender and date, which only a screen reads.
Dovecot or the store refusing, or a database error no value of a
message can cause, is no message's fault, and still fails the domain with its cursor
where it was. Every statement that can refuse one
message runs before its first name is made, so a skipped message leaves no name behind.

⛔ EVERY DIRECTORY THAT GAINED A NAME IS FSYNCED AFTER THE LAST LINK AND BEFORE THE
LEDGER COMMITS. A crash that loses a name while its `linked` row
survives is silent: a top-up does not bring back a row that already exists, so that
person never gets the message and nothing says so. The file itself is the delivery
agent's to make durable; this program fsyncs only the directories it links into.

⛔ THE VERDICT IS THE MARK THE FILTER WROTE, AND NOTHING ELSE. It is not
recomputed from the score, from an action word or from the domain's threshold as it now
stands: those are how a file's mark and the ledger's verdict come to disagree about one
message. An absent mark is not spam, which is what carries this machine's own reports
through - the filter gives them no header block at all.

⛔ NO VALUE OF THE SCORE HEADER MAY RAISE. A conversion error here escapes
the whole domain's tick and leaves every cursor where it was for the sake of one
header. An unreadable or oversized score is stored as null, and nothing is decided from
the number: everything that filters on spam filters on the stored verdict.

⛔ A TICK READS NO UID OF A FOLDER DOVECOT NUMBERED AGAIN. Before either folder is
listed, each is held to the UIDVALIDITY its cursor row keeps and to its cursor's own UID
still being there; a folder that fails either fails the domain's tick with nothing
recorded or linked, in one `maildivvy-pass: renumbered:` line a folder, which health
reads, until `--renumber` gives the folder's rows their new numbers.

⛔ AN IMPORTED MESSAGE IS RECORDED AND REACHES NOBODY. The import files a
message into the archive's INBOX under a storage id of its own (`store.imported`); the
pass records it delivered, not spam, with no score, no withheld id and no report, whatever
filter headers an old store left in it, its `received_at` the moment its name carries and
`imported_at` the insert, and links it to nobody, on a tick, a `--renumber` and a `--uid`
alike: people get history only by a top-up. One such name in the quarantine is no import
of ours, and is skipped and named, never recorded.

⛔ THE NAMES OF OUR OWN HEADERS, AND HOW A HEADER IS READ, ARE `lib/headers.py`'s, the
module the filter writes its block through, never spelled here a second time, and only
their FIRST occurrence is read: the filter prepends its block and strips
nothing, so the sender's own copy of any of those names is still in the message, below
ours.
"""

import argparse
import datetime
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import NamedTuple

from maildivvy.fanout import ledger, requests
from maildivvy.lib import config, db, doveadm, headers, messageid, store
from maildivvy.lib.headers import first_line, first_occurrence

CONSUMER = "pipeline"
INBOX = ledger.INBOX

EX_CONFIG = 78
SKIPPED = "maildivvy-pass: skipped:"  # ⛔ the marker health counts; nothing else carries it
RENUMBERED = "maildivvy-pass: renumbered:"  # ⛔ the marker health names a folder by
BY_HAND = "/opt/maildivvy/bin/maildivvy-pass"  # the installed command a skipped line names

SCORE_LIMIT = Decimal(10) ** 4  # `message.spam_score` is numeric(6,2)

# Read through doveadm's JSON formatter, each field as one lowercase word.
FIELDS = ("uid", "storageid", "hdr.from", "hdr.subject", "hdr.date", "hdr.message-id",
          headers.MARK_FIELD, headers.SCORE_FIELD, headers.WITHHELD_FIELD, headers.REASON_FIELD)

# Every domain, whether or not anything collects mail for it.
DOMAINS = "SELECT id, label, spam_reaches_people FROM domain ORDER BY label"

CURSOR = """
    INSERT INTO pass_cursor (domain_id, mailbox, last_uid) VALUES (%s, %s, 0)
        ON CONFLICT (domain_id, mailbox) DO NOTHING
"""
# FOR UPDATE: two passes at once then queue per (domain, mailbox) instead of reading one
# range twice.
READ_CURSOR = "SELECT last_uid FROM pass_cursor WHERE domain_id = %s AND mailbox = %s FOR UPDATE"
MOVE_CURSOR = "UPDATE pass_cursor SET last_uid = %s WHERE domain_id = %s AND mailbox = %s"

# Who receives in this domain, whatever the person's state,
# minus the pairs the ledger already accounts for in ANY state: a delivery row that
# outlived its file is what stops a deleted message coming back. The account
# is what the store path is derived from, never the view's absolute `home`.
RECEIVERS = """
    SELECT r.mailbox_id, r.account
      FROM mailbox_receives r
     WHERE r.domain_id = %s
       AND NOT EXISTS (SELECT 1 FROM delivery d
                        WHERE d.message_id = %s AND d.mailbox_id = r.mailbox_id)
     ORDER BY r.mailbox_id
"""

RECORD = """
    INSERT INTO message (domain_id, message_id_header, archive_uid, state, withheld_id,
                         report_of, message_date, sender, subject, is_spam, spam_score)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
"""
# An imported message: the same columns in the same order, then the moment it
# arrived in the old store, and the insert's own moment beside it.
RECORD_IMPORTED = """
    INSERT INTO message (domain_id, message_id_header, archive_uid, state, withheld_id,
                         report_of, message_date, sender, subject, is_spam, spam_score,
                         received_at, imported_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, clock_timestamp()) RETURNING id
"""
REPORTED = """
    SELECT id FROM message
     WHERE domain_id = %s AND withheld_id = %s AND state <> 'delivered' ORDER BY id LIMIT 1
"""
# ⛔ A withheld message recorded after its report: skipped once and recorded by
# hand, or by a renumbering. The report's row points at nothing, and a release would leave
# the report standing; it is found by the Message-ID the filter gives every report,
# `<withheld id@domain>` (`deliver/report.py`), and pointed at the message now.
ORPHAN_REPORTS = """
    UPDATE message SET report_of = %s
     WHERE domain_id = %s AND report_of IS NULL AND state = 'delivered'
       AND withheld_id IS NULL AND message_id_header = %s
"""
# A UID by hand is refused when the ledger holds it already, in a sentence rather than the
# unique index's error. UIDs are per folder, and a `delivered` row's counts in
# INBOX, any other state's in the quarantine.
HELD = """
    SELECT 1 FROM message WHERE domain_id = %s AND archive_uid = %s
       AND (state = 'delivered') = %s
"""

# Not this message's fault: Dovecot or the store refused, and the next minute repeats it.
NOT_THE_MESSAGE = (doveadm.DoveadmError, store.StoreError, OSError)
# The SQLSTATE classes a message's own values can raise: a data exception, an integrity
# violation, a limit (the index's 2704 bytes is 54000). Any other database error - a
# privilege, a deadlock, a cancelled query - would refuse every message alike, and a skip
# would move the cursor past mail nobody then has.
ITS_OWN_SQLSTATES = ("22", "23", "54")


def its_own_fault(err):
    """Is this failure the one message's own, so the pass may skip it and move on?"""
    if isinstance(err, NOT_THE_MESSAGE):
        return False
    if hasattr(err, "pgcode"):  # a database error; no code means the connection's
        return (err.pgcode or "")[:2] in ITS_OWN_SQLSTATES
    return True


class Refused(Exception):
    """A UID by hand this program will not record."""


class NotOurs(ValueError):
    """An imported message's name where the import never files one: the message's own
    fault, skipped and named, never recorded."""


class Domain(NamedTuple):
    id: int
    label: str
    spam_reaches_people: bool


class Message(NamedTuple):
    """One message of the archive, as the ledger will record it."""

    uid: int
    storageid: str | None
    sender: str | None
    subject: str | None
    message_id: str | None
    date: datetime.datetime | None
    spam: bool
    score: Decimal | None
    withheld_id: str | None
    reason: str | None

    @property
    def is_report(self):
        """The report the filter wrote in place of a withheld message."""
        return self.reason is not None

    @property
    def received(self):
        """An imported message's received epoch; None for every other."""
        return store.imported(self.storageid)


# --- reading one message's fields ---------------------------------------------------------------


def score_of(field):
    """The scanner's score for the ledger, or None. Nothing here may raise."""
    try:
        score = Decimal(first_line(field))
    except (InvalidOperation, ValueError, ArithmeticError):
        return None
    if not score.is_finite() or abs(score) >= SCORE_LIMIT:
        return None
    return score


def read(record):
    """One doveadm record as the row the ledger will hold.

    ⛔ An imported message's filter headers are an old store's, never this machine's
    verdict: it is not spam, has no score, and is neither withheld nor a report.
    """
    storageid = record.get("storageid") or None
    message = Message(
        uid=int(record["uid"]),
        storageid=storageid,
        sender=headers.sender_of(record.get("hdr.from")),
        subject=first_occurrence(record.get("hdr.subject")) or None,
        message_id=first_occurrence(record.get("hdr.message-id")) or None,
        date=headers.date_of(record.get("hdr.date")),
        # ⛔ The mark, and only the mark.
        spam=first_line(record.get(headers.MARK_FIELD)).lower() == "yes",
        score=score_of(record.get(headers.SCORE_FIELD)),
        withheld_id=headers.ours_or_none(record.get(headers.WITHHELD_FIELD)),
        reason=headers.ours_or_none(record.get(headers.REASON_FIELD)),
    )
    if message.received is not None:
        message = message._replace(spam=False, score=None, withheld_id=None, reason=None)
    return message


def state_of(folder):
    """A message's ledger state is the folder it was filed into."""
    return "withheld" if folder == store.QUARANTINE else "delivered"


def receives(message, folder, spam_reaches_people):
    """Do people get a name for this message?

    Nothing is linked out of the quarantine until a release says so, and a
    message marked spam reaches nobody in a domain that keeps spam back - its row is
    written all the same, so the ledger still accounts for the archive's file.
    """
    if folder != INBOX:
        return False
    if message.received is not None:
        return False  # imported: history reaches people only by a top-up
    if message.spam and not spam_reaches_people:
        return False
    return True


# --- the names on disk ---------------------------------------------------------------------------


# --- one domain -----------------------------------------------------------------------------------


def above(login, folder, last_uid):
    """The archive's records above the cursor, oldest first; [] for a folder that is not there.

    A domain's quarantine folder exists only once something has been withheld, and
    doveadm's own answer for a missing mailbox is `[]` with exit 0, which our wrapper
    refuses to read as empty. A nonzero exit of any other kind fails the
    tick, with the cursor unchanged.
    """
    try:
        records = doveadm.fetch(login, folder, FIELDS, "uid", f"{int(last_uid) + 1}:*")
    except doveadm.DoveadmError as err:
        if err.returncode == doveadm.EX_NOUSER:
            return []
        raise
    return sorted((read(record) for record in records), key=lambda m: m.uid)


def record_message(cursor, domain, folder, message):
    """Write the ledger's message row, and the report's link to what it replaces."""
    if message.received is not None:
        return record_imported(cursor, domain, folder, message)
    report_of = None
    if message.is_report and message.withheld_id:
        cursor.execute(REPORTED, (domain.id, message.withheld_id))
        found = cursor.fetchone()
        report_of = found[0] if found else None
        if report_of is None:
            sys.stderr.write(f"maildivvy-pass: {domain.label}: the report of withheld "
                             f"{message.withheld_id} has no message to point at\n")
    cursor.execute(RECORD, (
        domain.id, messageid.stored(message.message_id), message.uid, state_of(folder),
        # ⛔ The withheld id is the WITHHELD message's, so a release finds one row by it;
        # the report carries the link in `report_of` instead.
        None if message.is_report else message.withheld_id,
        report_of, message.date, message.sender, message.subject, message.spam, message.score))
    message_id = cursor.fetchone()[0]
    if folder == store.QUARANTINE and message.withheld_id and not message.is_report:
        cursor.execute(ORPHAN_REPORTS, (message_id, domain.id, messageid.stored(
            f"<{message.withheld_id}@{domain.label}>")))
    return message_id


def record_imported(cursor, domain, folder, message):
    """An imported message's row: delivered, not spam, no score, no withheld id
    and no report; arrived when its name says, recorded now."""
    if folder != INBOX:
        raise NotOurs(f"{message.storageid} is an imported message's name in {folder}, "
                      "where the import files nothing")
    cursor.execute(RECORD_IMPORTED, (
        domain.id, messageid.stored(message.message_id), message.uid, "delivered", None, None,
        message.date, message.sender, message.subject, False, None,
        datetime.datetime.fromtimestamp(message.received, datetime.UTC)))
    return cursor.fetchone()[0]


def listing(conn, domain, folder):
    """The archive's records above this (domain, mailbox)'s cursor, the cursor locked."""
    with conn.cursor() as cur:
        cur.execute(CURSOR, (domain.id, folder))
        cur.execute(READ_CURSOR, (domain.id, folder))
        last_uid = cur.fetchone()[0]
    return above(f"{store.ARCHIVE}@{domain.label}", folder, last_uid)


class Stopped(Exception):
    """A domain's tick stopped because Dovecot renumbered one or both of its folders."""

    def __init__(self, renumbered):
        self.renumbered = renumbered
        super().__init__("; ".join(str(each) for each in renumbered))


def same_numbering(conn, domain):
    """Both folders held to the numbering their cursor rows keep, the cursors locked,
    before either is listed; every one renumbered is named at once."""
    renumbered = []
    with conn.cursor() as cur:
        for folder in ledger.FOLDERS:
            cur.execute(CURSOR, (domain.id, folder))
            cur.execute(READ_CURSOR, (domain.id, folder))
            try:
                ledger.same_numbering(cur, domain.id, domain.label, folder)
            except ledger.Renumbered as err:
                renumbered.append(err)
    if renumbered:
        raise Stopped(renumbered)


def fan_one(cur, domain, folder, message, args):
    """Record one message and link it; returns the directories that gained a name.

    ⛔ The rows first and the names last: everything that can refuse this one message is
    a statement, and it has refused before any name exists.
    """
    message_id = record_message(cur, domain, folder, message)
    if not receives(message, folder, domain.spam_reaches_people):
        return []
    cur.execute(RECEIVERS, (domain.id, message_id))
    receivers = cur.fetchall()
    if not receivers:
        return []
    # ⛔ Asked of Dovecot by UID, never by listing the directory, and asked again once
    # if the name moved in between. An unresolved name raises and the tick
    # fails with the cursor where it was.
    source = doveadm.message_file(domain.label, store.ARCHIVE, folder, message.uid,
                                  root=args.store_root)
    for mailbox_id, _ in receivers:
        cur.execute(ledger.LINK, (message_id, mailbox_id))
    return store.link_into(source, [store.maildir(store.home(domain.label, account, args.store_root))
                                    for _, account in receivers], args.store_root)


def reason_of(err):
    return " ".join(f"{type(err).__name__}: {err}".split())


def fan_one_or_bare(cur, domain, folder, message, args):
    """`fan_one`, and, when the database refuses the message for its own fault, once more
    without its subject, sender and date; returns the directories that gained a name.

    ⛔ NO MESSAGE IS UNRECORDABLE FOR A FIELD ONLY A SCREEN SHOWS. Those three are
    for reading; only the Message-ID feeds deduplication, and it is bounded already. A
    message the database refuses for one of them is recorded without all three, and says
    so; the by-hand `--uid` goes the same way, so the command a skip line names records
    what the pass could not. The caller holds the savepoint `message`.
    """
    try:
        return fan_one(cur, domain, folder, message, args)
    except Exception as err:
        bare = message._replace(sender=None, subject=None, date=None)
        if not its_own_fault(err) or bare == message:
            raise
        refused = err
    cur.execute("ROLLBACK TO SAVEPOINT message")
    touched = fan_one(cur, domain, folder, bare, args)
    sys.stderr.write(f"maildivvy-pass: {domain.label} {folder} UID {message.uid}: recorded "
                     "without its subject, sender and date, which the database refused: "
                     f"{reason_of(refused)}\n")
    return touched


def skipped(domain, folder, uid, err):
    """The one line a counter can find for a message the pass could not record."""
    reason = reason_of(err)
    sys.stderr.write(f"{SKIPPED} {domain.label} {folder} UID {uid}: {reason}; record it with "
                     f"`runuser -u {store.MAIL_USER} -- {BY_HAND} --only {domain.label} "
                     f"--folder {folder} --uid {uid}`\n")


def tick(conn, domain, folder, args, messages=None):
    """One (domain, mailbox): record what is above the cursor, link it, move the cursor.

    `messages` is the listing when the caller took it already (see `fan_out`).
    """
    if messages is None:
        messages = listing(conn, domain, folder)
    with conn.cursor() as cur:
        touched, recorded = [], 0
        for message in messages:
            cur.execute("SAVEPOINT message")
            try:
                touched += fan_one_or_bare(cur, domain, folder, message, args)
            except Exception as err:
                if not its_own_fault(err):
                    raise
                cur.execute("ROLLBACK TO SAVEPOINT message")
                skipped(domain, folder, message.uid, err)
            else:
                cur.execute("RELEASE SAVEPOINT message")
                recorded += 1

        if not messages:
            return 0
        # ⛔ After the last link, before the commit, and the cursor last of
        # all.
        store.fsync_dirs(touched)
        cur.execute(MOVE_CURSOR, (max(m.uid for m in messages), domain.id, folder))
    return recorded


def fan_out(conn, domain, args):
    """Both of a domain's mailboxes, in one transaction.

    ⛔ INBOX IS LISTED BEFORE THE QUARANTINE IS READ, and recorded after it.
    The filter stores a withheld message first and its report second, so a report in
    this INBOX listing has its message in the quarantine already when the quarantine is
    read. Read the other way round, a filter landing between the two readings left the
    report in the listing and its message out of it, and the report's row pointed at
    nothing for ever: the next tick reads above the cursor, and the report is below it.
    """
    same_numbering(conn, domain)
    inbox = listing(conn, domain, INBOX)
    # ⛔ The quarantine first, whatever order `ledger.FOLDERS` names them in: a report's
    # row points at the message it replaces through the withheld id, and
    # the filter files the withheld message before the report, so recording the
    # quarantine first is what lets one run record both and link them.
    for folder in (store.QUARANTINE, INBOX):
        count = tick(conn, domain, folder, args, messages=inbox if folder == INBOX else None)
        if count:
            sys.stderr.write(f"maildivvy-pass: {domain.label} {folder}: {count} recorded\n")


def record_one(conn, domain, folder, uid, args):
    """Record and link one UID the pass skipped, by hand; the cursor stays where it is.

    Refused for a UID above the cursor, which the next pass records, for one the archive
    does not hold, and for one the ledger holds already. A failure here is the operator's
    to read: nothing is skipped.
    """
    with conn.cursor() as cur:
        cur.execute(CURSOR, (domain.id, folder))
        cur.execute(READ_CURSOR, (domain.id, folder))  # and a running pass waits for us
        last_uid = cur.fetchone()[0]
        ledger.same_numbering(cur, domain.id, domain.label, folder)
        if uid > last_uid:
            raise Refused(f"above the cursor ({last_uid}): the next pass records it")
        cur.execute(HELD, (domain.id, uid, folder == INBOX))
        if cur.fetchone() is not None:
            raise Refused("the ledger holds it already")
        records = doveadm.fetch(f"{store.ARCHIVE}@{domain.label}", folder, FIELDS, "uid", str(uid))
        if not records:
            raise Refused(f"no UID {uid} in {store.ARCHIVE}@{domain.label}'s {folder}")
        cur.execute("SAVEPOINT message")
        store.fsync_dirs(fan_one_or_bare(cur, domain, folder, read(records[0]), args))
    conn.commit()


# --- the way back from a renumbered folder ------------------------------------------------

# A folder's rows as the pass wrote them, oldest number first.
FOLDER_ROWS = """
    SELECT id, archive_uid, message_id_header, sender, subject, withheld_id FROM message
     WHERE domain_id = %s AND archive_uid IS NOT NULL AND (state = 'delivered') = %s
     ORDER BY archive_uid, id
"""
RENUMBER_ROW = "UPDATE message SET archive_uid = %s WHERE id = %s"
# ⛔ EVERY NUMBER OF THE FOLDER GOES FIRST: one row per folder and UID is unique,
# and a row given its new number one at a time would meet another still holding it. A row
# no file matches keeps none: its file is not in the folder to link.
UNNUMBER = ("UPDATE message SET archive_uid = NULL "
            "WHERE domain_id = %s AND archive_uid IS NOT NULL AND (state = 'delivered') = %s")
NEW_NUMBERING = ("UPDATE pass_cursor SET last_uid = %s, uidvalidity = %s "
                 "WHERE domain_id = %s AND mailbox = %s")


def row_key(message):
    """What `record_message` writes of a message that a renumbering leaves unchanged."""
    return (messageid.stored(message.message_id), message.sender, message.subject,
            None if message.is_report else message.withheld_id)


def as_read_now(value):
    """A stored text as the headers are read today (`headers.CONTROLS`): a row
    written before the control characters were left out still holds them, and its file is
    read without. A digest is of the header as it was, and stays as it is."""
    if not isinstance(value, str) or value.startswith("sha256:"):
        return value
    return value.translate(headers.CONTROLS).strip() or None


def stored_key(fields):
    """A row's `row_key`, its Message-ID, sender and subject read as `as_read_now` reads."""
    message_id, sender, subject, withheld_id = fields
    return (as_read_now(message_id), as_read_now(sender), as_read_now(subject), withheld_id)


def matched(rows, messages):
    """`({row id: its new UID}, [the rows no file was found for])`.

    A row is the file whose fields it was written from; rows and files that share those
    fields pair in order, the oldest number with the oldest, since Dovecot numbers a
    rebuilt folder by its file names, which are the order of arrival.
    """
    files = {}
    for message in sorted(messages, key=lambda m: m.uid):
        files.setdefault(row_key(message), []).append(message.uid)
    found, lost = {}, []
    for row_id, old_uid, *fields in rows:
        uids = files.get(stored_key(fields))
        if uids:
            found[row_id] = uids.pop(0)
        else:
            lost.append((row_id, old_uid))
    return found, lost


def renumber(conn, domain, folder, args):
    """Give a renumbered folder's rows their new UIDs, and the cursor the new numbering.

    Each row is matched to the file it was written from, by the fields the pass read of
    it, and given that file's new UID; a row no file matches has no number any more (its
    file is not in the folder to link) and is returned. The cursor moves to the newest
    matched file. A file below it with no row is recorded and linked here, as a tick
    would: a delivery into a folder that lost its uidlist numbers its own message first,
    and a message the pass once skipped is tried again.

    ⛔ UNLESS A ROW WAS LEFT UNMATCHED. Its file may be one of those with no row,
    read today otherwise than when the row was written, and recorded again it would reach
    every receiver a second time: the outcome exists to prevent. Then no file is
    recorded, and both lists go to the operator, who records with `--uid` only what is
    not one of those rows. Returns `(renumbered, lost rows, recorded, the UIDs of the
    files left unrecorded)`.
    """
    with conn.cursor() as cur:
        cur.execute(CURSOR, (domain.id, folder))
        cur.execute(READ_CURSOR, (domain.id, folder))
        last_uid = cur.fetchone()[0]
        now = ledger.uidvalidity(domain.label, folder)
        if now is None:
            raise Refused(f"{store.ARCHIVE}@{domain.label} has no folder {folder}")
        try:
            ledger.same_numbering(cur, domain.id, domain.label, folder)
        except ledger.Renumbered:
            pass
        else:
            raise Refused(f"it numbers its files as the ledger's UIDs were given (UIDVALIDITY "
                          f"{now}, the cursor's UID there): nothing to renumber")
        cur.execute(FOLDER_ROWS, (domain.id, folder == INBOX))
        rows = cur.fetchall()
        messages = [read(record) for record in
                    doveadm.fetch(f"{store.ARCHIVE}@{domain.label}", folder, FIELDS, "all")]
        found, lost = matched(rows, messages)
        if rows and not found:
            raise Refused(f"none of its {len(rows)} rows matches a file of the folder")
        if not rows and last_uid:
            raise Refused(f"no row of it to find the cursor ({last_uid}) by")
        cur.execute(UNNUMBER, (domain.id, folder == INBOX))
        for row_id, uid in found.items():
            cur.execute(RENUMBER_ROW, (uid, row_id))
        cursor, rowed = max(found.values(), default=0), set(found.values())
        rowless = [m for m in messages if m.uid <= cursor and m.uid not in rowed]
    unrecorded = [m.uid for m in rowless] if lost else []
    recorded = tick(conn, domain, folder, args, messages=rowless) if rowless and not lost else 0
    with conn.cursor() as cur:
        cur.execute(NEW_NUMBERING, (cursor, now, domain.id, folder))
    conn.commit()
    return len(found), lost, recorded, unrecorded


# --- the command line -------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(description="record the archive's new mail and fan it out")
    parser.add_argument("--only", default=None, help="one domain's label")
    parser.add_argument("--store-root", default=str(store.STORE_ROOT),
                        help="the store's root; the paths are derived from it")
    parser.add_argument("--etc", default=str(config.ETC))
    parser.add_argument("--uid", type=int, default=None,
                        help="record and link this one UID the pass skipped; needs --only")
    parser.add_argument("--folder", choices=ledger.FOLDERS, default=INBOX, help="the UID's folder")
    parser.add_argument("--renumber", action="store_true",
                        help="give the folder's rows the numbers Dovecot gave their files "
                             "after a renumbering, and accept its UIDVALIDITY; needs --only")
    # what maildivvy-requests.service runs, beside the pass
    parser.add_argument("--provider-requests", action="store_true",
                        help="fan nothing out; drain only the requests that wait on a "
                             "provider, which the pass leaves to this run")
    args = parser.parse_args(argv)
    if args.uid is not None and args.only is None:
        parser.error("--uid is a UID of one domain's folder: name the domain with --only")
    if args.renumber and (args.only is None or args.uid is not None):
        parser.error("--renumber is one domain's folder: name the domain with --only, and no --uid")
    return args


def by_hand(conn, args):
    """`--uid` or `--renumber`: one domain's folder, and nothing else of the run (no
    fan-out, no request queue)."""
    with conn.cursor() as cur:
        cur.execute(DOMAINS)
        domains = [Domain(*row) for row in cur.fetchall() if row[1] == args.only]
    where = f"{args.only} {args.folder}" + ("" if args.renumber else f" UID {args.uid}")
    if not domains:
        sys.stderr.write(f"maildivvy-pass: {where}: no such domain\n")
        return 1
    try:
        if args.renumber:
            count, lost, recorded, unrecorded = renumber(conn, domains[0], args.folder, args)
        else:
            record_one(conn, domains[0], args.folder, args.uid, args)
    except Exception as err:  # noqa: BLE001 - one line for the operator, and exit 1
        conn.rollback()
        sys.stderr.write(f"maildivvy-pass: {where}: {type(err).__name__}: {err}\n")
        return 1
    if not args.renumber:
        sys.stderr.write(f"maildivvy-pass: {where}: recorded\n")
        return 0
    for row_id, old_uid in lost:
        sys.stderr.write(f"maildivvy-pass: {where}: message {row_id} (UID {old_uid}) has no "
                         "file in the folder any more; its number is cleared\n")
    for uid in unrecorded:
        # it may be one of the rows above, read otherwise today
        sys.stderr.write(f"maildivvy-pass: {where}: UID {uid} has no row and was NOT "
                         "recorded: if it is none of the messages above, record it with "
                         f"`runuser -u {store.MAIL_USER} -- {BY_HAND} --only {args.only} "
                         f"--folder {args.folder} --uid {uid}`\n")
    sys.stderr.write(f"maildivvy-pass: {where}: {count} message(s) renumbered, "
                     f"{len(lost)} without a file, {recorded} recorded, "
                     f"{len(unrecorded)} left unrecorded\n")
    return 1 if lost else 0


def connect(args):
    return db.connect(CONSUMER, etc=args.etc)


def drain(conn, args):
    """Perform what the administration interface queued (`fanout/requests.py`).

    A failed request is the request row's own business and does not
    fail the run; a queue that cannot be drained at all does.
    """
    root = Path(args.store_root)
    # the snapshots move with the store they are kept in
    # ⛔ The pass's half is bounded in time: the next minute's fan-out of every domain waits
    # for this run to end. The provider drainer runs beside the pass and holds
    # no fan-out, so its half is not. A request under which the database went away has its
    # outcome written on a second connection.
    return requests.drain(conn, requests.Context(store_root=root,
                                                 snapshot_root=root / store.SNAPSHOT_ROOT.name),
                          provider=args.provider_requests,
                          budget=None if args.provider_requests else requests.DRAIN_BUDGET,
                          reconnect=lambda: connect(args))


def main(argv=None):
    args = parse_args(argv)
    try:
        conn = connect(args)
    except config.ConfigError as err:
        sys.stderr.write(f"maildivvy-pass: {err}\n")
        return EX_CONFIG

    if args.uid is not None or args.renumber:
        try:
            return by_hand(conn, args)
        finally:
            conn.close()

    failed = False
    try:
        domains = []
        if not args.provider_requests:  # the pass beside it fans out
            with conn.cursor() as cur:
                cur.execute(DOMAINS)
                domains = [Domain(*row) for row in cur.fetchall()]
        for domain in domains:
            if args.only is not None and domain.label != args.only:
                continue
            try:
                fan_out(conn, domain, args)
                conn.commit()
            except Stopped as err:  # this domain alone, a line a folder, which health reads
                conn.rollback()
                failed = True
                for each in err.renumbered:
                    sys.stderr.write(f"{RENUMBERED} {each}\n")
            except Exception as err:  # noqa: BLE001 - this domain alone
                conn.rollback()
                failed = True
                sys.stderr.write(f"maildivvy-pass: {domain.label}: {type(err).__name__}: {err}\n")
        # ⛔ THE REQUEST QUEUE IS DRAINED HERE, AFTER THE FAN-OUT AND NEVER BEFORE IT.
        try:
            performed, refused = drain(conn, args)
            if performed or refused:
                sys.stderr.write(f"maildivvy-pass: requests: {performed} done, "
                                 f"{refused} failed\n")
        except Exception as err:  # noqa: BLE001 - the fan-out above already succeeded
            conn.rollback()
            failed = True
            sys.stderr.write(f"maildivvy-pass: the request queue: "
                             f"{type(err).__name__}: {err}\n")
    finally:
        conn.close()
    return 1 if failed else 0
