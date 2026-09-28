"""The pass: record what the archive holds, and give every receiver a name for it.

    maildivvy-pass [--only <domain>] [--store-root <the store's root>]

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

⛔ THE NAMES OF OUR OWN HEADERS ARE IMPORTED FROM THE FILTER (`deliver/marks.py`,
`deliver/report.py`), never spelled here a second time, and only their FIRST occurrence
is read: the filter prepends its block and strips nothing, so the sender's
own copy of any of those names is still in the message, below ours.
"""

import argparse
import datetime
import email.utils
import os
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import NamedTuple

from maildivvy.deliver import marks, report
from maildivvy.lib import config, db, doveadm, store

CONSUMER = "pipeline"
INBOX = "INBOX"

# ⛔ The quarantine first: a report's row points at the message it replaces through the
# withheld id, and the filter files the withheld message before the report,
# so reading the quarantine first is what lets one run record both and link them.
FOLDERS = (store.QUARANTINE, INBOX)

EX_CONFIG = 78
EX_NOUSER = 68  # doveadm's exit for a mailbox that does not exist (measured)

SCORE_LIMIT = Decimal(10) ** 4  # `message.spam_score` is numeric(6,2)

# Read through doveadm's JSON formatter, each field as one lowercase word.
MARK_FIELD = f"hdr.{marks.SPAM_MARK_HEADER.lower()}"
SCORE_FIELD = f"hdr.{marks.SPAM_SCORE_HEADER.lower()}"
WITHHELD_FIELD = f"hdr.{report.WITHHELD_HEADER.lower()}"
REASON_FIELD = f"hdr.{report.REASON_HEADER.lower()}"
FIELDS = ("uid", "hdr.from", "hdr.subject", "hdr.date", "hdr.message-id",
          MARK_FIELD, SCORE_FIELD, WITHHELD_FIELD, REASON_FIELD)

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
REPORTED = """
    SELECT id FROM message
     WHERE domain_id = %s AND withheld_id = %s AND state <> 'delivered' ORDER BY id LIMIT 1
"""
LINK = """
    INSERT INTO delivery (message_id, mailbox_id, state, linked_at)
    VALUES (%s, %s, 'linked', now()) ON CONFLICT (message_id, mailbox_id) DO NOTHING
"""


class Domain(NamedTuple):
    id: int
    label: str
    spam_reaches_people: bool


class Message(NamedTuple):
    """One message of the archive, as the ledger will record it."""

    uid: int
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


# --- reading one message's fields ---------------------------------------------------------------


def first_occurrence(field):
    """The first occurrence of a header, unfolded; every later one is dropped.

    doveadm hands a field back with its newlines inside it, so both a
    folded value's continuation lines and a second occurrence of the name arrive in one
    string. A continuation line begins with whitespace and a second occurrence does
    not, which is what tells them apart.
    """
    lines = (field or "").split("\n")
    value = [lines[0].strip()] if lines else []
    for line in lines[1:]:
        if not line[:1].isspace():
            break
        value.append(line.strip())
    return " ".join(part for part in value if part)


def first_line(field):
    """The first line of one of OUR OWN headers. Never the sender's second."""
    return (field or "").split("\n")[0].strip()


def ours_or_none(field):
    """One of the two report fields, where the filter's `none` means there is nothing.

    The filter writes both into every message it files with its block, so
    that a sender's copy is never the first occurrence.
    """
    value = first_line(field)
    return None if value in ("", report.NONE) else value


def sender_of(field):
    """The parsed address of the From header, lower-cased and never folded.

    In `From: acme@gmail.com <impostor@example.net>` the display name looks like the
    address, and the first address-shaped token is the display name. The
    library is asked first, because it reads quoting and comments properly; where it
    finds no address at all - which is what a display name holding an `@` makes of the
    field - the angle-addr is taken instead, because that is the address a reader sees.
    ⚠️ `email.message`'s own header parser answers `acme@gmail.com` for that field: the
    display name, which is precisely the value this rule exists to keep out of the
    ledger.

    A From that parses to no address at all stores nothing, and that is not an error:
    nothing that delivers reads this column.
    """
    value = first_occurrence(field)
    address = email.utils.parseaddr(value)[1]
    if "@" not in address:
        start, end = value.find("<"), value.find(">", value.find("<") + 1)
        address = value[start + 1:end] if start != -1 and end != -1 else ""
    return address.lower() if "@" in address else None


def score_of(field):
    """The scanner's score for the ledger, or None. Nothing here may raise."""
    try:
        score = Decimal(first_line(field))
    except (InvalidOperation, ValueError, ArithmeticError):
        return None
    if not score.is_finite() or abs(score) >= SCORE_LIMIT:
        return None
    return score


def date_of(field):
    """The message's own date, or None for one that has none or will not parse."""
    try:
        return email.utils.parsedate_to_datetime(first_occurrence(field))
    except (TypeError, ValueError):
        return None


def read(record):
    """One doveadm record as the row the ledger will hold."""
    return Message(
        uid=int(record["uid"]),
        sender=sender_of(record.get("hdr.from")),
        subject=first_occurrence(record.get("hdr.subject")) or None,
        message_id=first_occurrence(record.get("hdr.message-id")) or None,
        date=date_of(record.get("hdr.date")),
        # ⛔ The mark, and only the mark.
        spam=first_line(record.get(MARK_FIELD)).lower() == "yes",
        score=score_of(record.get(SCORE_FIELD)),
        withheld_id=ours_or_none(record.get(WITHHELD_FIELD)),
        reason=ours_or_none(record.get(REASON_FIELD)),
    )


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
    if message.spam and not spam_reaches_people:
        return False
    return True


# --- the names on disk ---------------------------------------------------------------------------


def base_name(path):
    """The receiver's name, derived from the archive's base name.

    A retry then produces the same name, so a repeated tick is idempotent instead of
    minting a second copy. The archive's own flags are not the receiver's: a message an
    administrator read is still new to everybody else.
    """
    return Path(path).name.split(":", 1)[0]


def link_into(source, maildirs, root=store.STORE_ROOT, made=None):
    """Add one name for `source` in the `new/` of each maildir; returns the directories touched.

    EEXIST is success. A person who has never logged in has no maildir yet,
    so it is made here, by the mail owner, 0700. `made`, when given,
    gets every name this call created, and no name that was there already: a request
    takes back what it made when it fails (`requests.take_back`).
    """
    name = base_name(source)
    touched = []
    for box in maildirs:
        directory = Path(box) / "new"
        if not directory.is_dir():
            for part in ("cur", "new", "tmp"):
                store.make_dir(Path(box) / part, root)
        try:
            os.link(source, directory / name)
        except FileExistsError:
            pass  # the name this tick would make is already there: the retry is done
        else:
            if made is not None:
                made.append(directory / name)
        touched.append(directory)
    return touched


def fsync_dirs(directories):
    """fsync each directory once, after the last link and before the ledger commits."""
    for directory in dict.fromkeys(str(d) for d in directories):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


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
        if err.returncode == EX_NOUSER:
            return []
        raise
    return sorted((read(record) for record in records), key=lambda m: m.uid)


def record_message(cursor, domain, folder, message):
    """Write the ledger's message row, and the report's link to what it replaces."""
    report_of = None
    if message.is_report and message.withheld_id:
        cursor.execute(REPORTED, (domain.id, message.withheld_id))
        found = cursor.fetchone()
        report_of = found[0] if found else None
        if report_of is None:
            sys.stderr.write(f"maildivvy-pass: {domain.label}: the report of withheld "
                             f"{message.withheld_id} has no message to point at\n")
    cursor.execute(RECORD, (
        domain.id, message.message_id, message.uid, state_of(folder),
        # ⛔ The withheld id is the WITHHELD message's, so a release finds one row by it;
        # the report carries the link in `report_of` instead.
        None if message.is_report else message.withheld_id,
        report_of, message.date, message.sender, message.subject, message.spam, message.score))
    return cursor.fetchone()[0]


def listing(conn, domain, folder):
    """The archive's records above this (domain, mailbox)'s cursor, the cursor locked."""
    with conn.cursor() as cur:
        cur.execute(CURSOR, (domain.id, folder))
        cur.execute(READ_CURSOR, (domain.id, folder))
        last_uid = cur.fetchone()[0]
    return above(f"{store.ARCHIVE}@{domain.label}", folder, last_uid)


def tick(conn, domain, folder, args, messages=None):
    """One (domain, mailbox): record what is above the cursor, link it, move the cursor.

    `messages` is the listing when the caller took it already (see `fan_out`).
    """
    if messages is None:
        messages = listing(conn, domain, folder)
    with conn.cursor() as cur:
        touched = []
        for message in messages:
            message_id = record_message(cur, domain, folder, message)
            if not receives(message, folder, domain.spam_reaches_people):
                continue
            cur.execute(RECEIVERS, (domain.id, message_id))
            receivers = cur.fetchall()
            if not receivers:
                continue
            # ⛔ Asked of Dovecot by UID, never by listing the directory, and asked again
            # once if the name moved in between. An unresolved name raises
            # and the tick fails with the cursor where it was.
            source = doveadm.message_file(domain.label, store.ARCHIVE, folder, message.uid,
                                          root=args.store_root)
            touched += link_into(source, [store.maildir(store.home(domain.label, account,
                                                                   args.store_root))
                                          for _, account in receivers], args.store_root)
            for mailbox_id, _ in receivers:
                cur.execute(LINK, (message_id, mailbox_id))

        if not messages:
            return 0
        # ⛔ After the last link, before the commit, and the cursor last of
        # all.
        fsync_dirs(touched)
        cur.execute(MOVE_CURSOR, (max(m.uid for m in messages), domain.id, folder))
    return len(messages)


def fan_out(conn, domain, args):
    """Both of a domain's mailboxes, in one transaction.

    ⛔ INBOX IS LISTED BEFORE THE QUARANTINE IS READ, and recorded after it.
    The filter stores a withheld message first and its report second, so a report in
    this INBOX listing has its message in the quarantine already when the quarantine is
    read. Read the other way round, a filter landing between the two readings left the
    report in the listing and its message out of it, and the report's row pointed at
    nothing for ever: the next tick reads above the cursor, and the report is below it.
    """
    inbox = listing(conn, domain, INBOX)
    for folder in FOLDERS:
        count = tick(conn, domain, folder, args, messages=inbox if folder == INBOX else None)
        if count:
            sys.stderr.write(f"maildivvy-pass: {domain.label} {folder}: {count} recorded\n")


# --- the command line -------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(description="record the archive's new mail and fan it out")
    parser.add_argument("--only", default=None, help="one domain's label")
    parser.add_argument("--store-root", default=str(store.STORE_ROOT),
                        help="the store's root; the paths are derived from it")
    parser.add_argument("--etc", default=str(config.ETC))
    return parser.parse_args(argv)


def connect(args):
    return db.connect(CONSUMER, etc=args.etc)


def drain(conn, args):
    """Perform what the administration interface queued (`fanout/requests.py`).

    ⛔ The import is inside this function on purpose: the handlers make names with this
    module's own `link_into`, so the two modules read each other and only one of the two
    directions can be an import at the top. A failed request is the request row's own
    business and does not fail the run; a queue that cannot be drained
    at all does.
    """
    from maildivvy.fanout import requests  # noqa: E402,PLC0415 - see above

    return requests.drain(conn, requests.Context(store_root=Path(args.store_root)))


def main(argv=None):
    args = parse_args(argv)
    try:
        conn = connect(args)
    except config.ConfigError as err:
        sys.stderr.write(f"maildivvy-pass: {err}\n")
        return EX_CONFIG

    failed = False
    try:
        with conn.cursor() as cur:
            cur.execute(DOMAINS)
            domains = [Domain(*row) for row in cur.fetchall()]
        for domain in domains:
            if args.only is not None and domain.label != args.only:
                continue
            try:
                fan_out(conn, domain, args)
                conn.commit()
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
