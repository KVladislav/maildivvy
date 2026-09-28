"""The IMAPSieve hook: the archive's name for an outgoing message, and nothing moved.

    maildivvy-sent-hook <mailbox>   < the message      USER=<login> in the environment

The client appends its copy to Sent once its SMTP transaction has succeeded, and that
append is the only way a sent message reaches this machine. Dovecot invokes
this program through `sent.sieve`, bound to that one folder, after the append has
committed.

⛔ IT ADDS A NAME AND MOVES NOTHING. The client's file stays exactly where
the client put it; the archive gains a hardlink to the same inode under
`Sent/<account>`, in `new/`, so it is unread for whoever opens the archive.
Moving the file would take it out of a live mailbox - Dovecot loses it and returns it
with a new UID - and would move the ctime every holder shares. Both routes end in the
same place and one of them costs nothing.

⛔ IT EXITS 0, ALWAYS. Nothing repairs a missed outgoing message: there is
no cursor over Sent and no repair pass, so a failure here is a message silently missing
from the archive. Every refusal and every failure writes ONE line beginning
`maildivvy-sent-hook: failed:`, which Dovecot puts in its log, and health counts those
lines for the `dovecot` subsystem. An exit of anything else would
fail the client's APPEND, which is what must never happen.

⛔ THE FILE IS FOUND THROUGH DOVECOT, NEVER BY LISTING THE MAILDIR. IMAPSieve
hands the program the bytes on stdin, the mailbox as its one argument and the login in
`USER` - no UID and no file name. The Message-ID is looked up in that person's Sent with
`doveadm fetch storageid`; a directory listing would race the client that is still
writing. A message with NO Message-ID is found by the append itself: the candidates saved in the last hour are asked for, and the one whose bytes
are the bytes this program was handed is the appended message. Nothing is guessed: a
lookup that finds no file records nothing.

⛔ THE "ALREADY RECORDED" CHECK MATCHES ONLY ROWS WITH NO ARCHIVE NUMBER. The provider's feed serves relayed mail back, and the pass records that copy under
the same Message-ID WITH an archive UID. A check by (domain,
Message-ID) alone would read the feed's copy as this message and leave the sender's own
mail with no name under `Sent/`, in exactly the window where the feed's copy arrives
first. A message with no Message-ID has no such key at all: what keeps its second run
from writing a second row is the name this program itself made, which is checked before
anything else is done.

⛔ THE LEDGER'S RULES ARE THE PASS'S OWN FUNCTIONS. The sender, the date and the
unfolding of a header are imported from `fanout/pass_.py`, so the two programs that
write `message` rows cannot come to disagree about one message.
"""

import email
import os
import re
import sys
from pathlib import Path
from typing import NamedTuple

from maildivvy.fanout import pass_
from maildivvy.lib import config, db, doveadm, store

CONSUMER = "senthook"  # its own least-privileged database role
PREFIX = "maildivvy-sent-hook"
FAILURE = f"{PREFIX}: failed:"  # ⛔ the marker health counts; nothing else carries it

ONLY_MAILBOX = "Sent"
STORE_ROOT = store.STORE_ROOT

# The window and the bound of the lookup that finds a message with no Message-ID. The
# append has just committed, so an hour is wide beyond any need; the bound is what keeps
# a busy Sent from being read in full.
RECENT = "1h"
CANDIDATES = 50
FIELDS = ("uid", "storageid", "size.virtual")  # size.virtual is the CRLF size, stdin's own

HEADER_END = re.compile(rb"\r?\n\r?\n")

DOMAIN_ID = "SELECT id FROM domain WHERE label = %s"
MAILBOX_ID = """
    SELECT m.id FROM mailbox m JOIN account a ON a.id = m.account_id
     WHERE a.login = %s AND m.domain_id = %s
"""
# ⛔ `archive_uid IS NULL`: the feed's copy of this same sending is not this message.
RECORDED = """
    SELECT id FROM message
     WHERE domain_id = %s AND message_id_header = %s AND archive_uid IS NULL
     ORDER BY id LIMIT 1
"""
# No archive UID: an outgoing message has no name in the archive's INBOX, so the bulk
# selectors, which require one, never pick it up.
RECORD = """
    INSERT INTO message (domain_id, message_id_header, archive_uid, state, message_date,
                         sender, subject, is_spam)
    VALUES (%s, %s, NULL, 'delivered', %s, %s, %s, false) RETURNING id
"""
# The sender's OWN copy, the one the client appended: every name in the store must have
# a row. The archive's name gets none, as the pass gives the archive none.
LINK = """
    INSERT INTO delivery (message_id, mailbox_id, state, linked_at)
    VALUES (%s, %s, 'linked', now()) ON CONFLICT (message_id, mailbox_id) DO NOTHING
"""


class Refused(Exception):
    """Something this hook will not act on. Logged as a failure; the exit is still 0."""


class Outgoing(NamedTuple):
    """What the ledger records of a sent message, read from its header block."""

    message_id: str | None
    subject: str | None
    sender: str | None
    date: object


def log(text):
    sys.stderr.write(f"{PREFIX}: {text}\n")


def failed(reason):
    """The one line a counter can find, for health."""
    sys.stderr.write(f"{FAILURE} {reason}\n")


# --- what the program was handed ------------------------------------------------------------


def account_of(login):
    """(account, domain) of a `<login>@<domain>`, or Refused."""
    account, at, domain = login.partition("@")
    if not at or not account or not domain or "@" in domain:
        raise Refused(f"USER is {login!r}, which is not an <account>@<domain> login")
    if account == store.ARCHIVE:
        raise Refused(f"{login} is a domain's archive, which no person holds; refusing it")
    return account, domain


def archive_folder(account):
    """`Sent/<account>` in the archive: the person's own login, dots and all."""
    return store.mailbox_name(ONLY_MAILBOX, account)


def read_message(raw):
    """The header block's first occurrence of each name the ledger keeps.

    Only the header block is parsed, and it is decoded with replacement: a header that
    is not UTF-8 is a message to record, not a message to lose, and the
    body is never decoded at all.
    """
    end = HEADER_END.search(raw)
    head = raw[:end.start()] if end else raw
    parsed = email.message_from_string(head.decode("utf-8", "replace"))
    return Outgoing(
        message_id=pass_.first_occurrence(parsed.get("Message-ID")) or None,
        subject=pass_.first_occurrence(parsed.get("Subject")) or None,
        sender=pass_.sender_of(parsed.get("From")),
        date=pass_.date_of(parsed.get("Date")),
    )


# --- the file the client appended ---------------------------------------------------------------


def normalise(data):
    """One line ending, so what stdin holds and what the maildir holds compare equal.

    ⚠️ Measured on 2.4.2: the program is handed the message in its CRLF form (the
    virtual message, `size.virtual`), while the maildir file keeps LF (`size.physical`).
    """
    return data.replace(b"\r\n", b"\n")


def same_message(raw, path):
    """Is the file at `path` the message this program was handed?"""
    try:
        return normalise(Path(path).read_bytes()) == normalise(raw)
    except OSError:
        return False


def newest(records, raw):
    """The record of the appended message: the newest UID, among those of its size.

    doveadm's `size.virtual` is the size of the form this program is handed, so a
    candidate of another size is another message. Where nothing carries a size, the
    newest answer is the append that has just happened.
    """
    sized = [r for r in records if str(r.get("size.virtual", "")) == str(len(raw))]
    pool = sized or list(records)
    return max(pool, key=lambda r: int(r["uid"])) if pool else None


def _resolve(domain, account, record_, root):
    """The file of one doveadm record in the person's own Sent, or None."""
    box = store.maildir(store.home(domain, account, root), ONLY_MAILBOX)
    return store.resolve(box, record_["storageid"])


def source_of(login, domain, account, raw, message_id, root=None):
    """The file the client appended, found through Dovecot alone.

    With a Message-ID, that header is what is looked up. Without one, the messages saved
    in the last hour are the candidates and the appended message is the one whose bytes
    are the bytes on stdin.
    """
    root = STORE_ROOT if root is None else root
    if message_id:
        records = doveadm.fetch(login, ONLY_MAILBOX, FIELDS, "header", "message-id", message_id)
        chosen = newest(records, raw)
        if chosen is None:
            raise Refused(f"no file in {login}'s {ONLY_MAILBOX} for Message-ID {message_id}")
        path = _resolve(domain, account, chosen, root)
        if path is None:
            raise Refused(f"storage id {chosen['storageid']!r} of {login}'s {ONLY_MAILBOX} "
                          f"has no file under new/ or cur/")
        return path

    records = doveadm.fetch(login, ONLY_MAILBOX, FIELDS, "savedsince", RECENT)
    sized = [r for r in records if str(r.get("size.virtual", "")) == str(len(raw))]
    for record_ in sorted(sized, key=lambda r: int(r["uid"]), reverse=True)[:CANDIDATES]:
        path = _resolve(domain, account, record_, root)
        if path is not None and same_message(raw, path):
            return path
    raise Refused(f"no message saved in {login}'s {ONLY_MAILBOX} in the last {RECENT} holds "
                  f"the {len(raw)} bytes this hook was handed (no Message-ID to look up)")


def already_named(source, archive_maildir):
    """Has this hook already given the archive a name for this very file?

    The archive's name is the source's base name, so a second run over one message
    computes the name it made the first time. It is the same file when it is the same
    inode: another message of the same name would be a different one.
    """
    existing = store.resolve(archive_maildir, pass_.base_name(source))
    if existing is None:
        return None
    return existing if Path(existing).stat().st_ino == Path(source).stat().st_ino else None


# --- the ledger and the name ----------------------------------------------------------------


def record(conn, domain, account, folder, outgoing, source, root):
    """One transaction: the message row, the archive's name, the sender's delivery row."""
    with conn.cursor() as cur:
        cur.execute(DOMAIN_ID, (domain,))
        found = cur.fetchone()
        if found is None:
            raise Refused(f"no domain {domain!r} in the ledger")
        domain_id = found[0]

        cur.execute(MAILBOX_ID, (account, domain_id))
        found = cur.fetchone()
        if found is None:
            raise Refused(f"{account}@{domain} has no mailbox row in the ledger")
        mailbox_id = found[0]

        if outgoing.message_id:
            cur.execute(RECORDED, (domain_id, outgoing.message_id))
            found = cur.fetchone()
            if found is not None:
                return None  # already recorded, by this hook; nothing to add

        cur.execute(RECORD, (domain_id, outgoing.message_id, outgoing.date,
                             outgoing.sender, outgoing.subject))
        message_id = cur.fetchone()[0]

        # Through Dovecot, so each folder carries its marker and the archive's ACL; a
        # folder that exists already is success.
        # ⛔ THE PARENT IS MADE BY NAME, not left to `Sent/<account>` to make on its way
        # past: a folder Dovecot creates as a parent has no ACL file of its own, and a
        # folder in an archive without one keeps every right - which is the archive
        # login, shared by the administrators, free to write into `Sent`.
        archive_login = f"{store.ARCHIVE}@{domain}"
        doveadm.create_folder(archive_login, ONLY_MAILBOX)
        doveadm.create_folder(archive_login, folder)
        archive_maildir = store.maildir(store.archive_home(domain, root), folder)
        pass_.fsync_dirs(pass_.link_into(source, [archive_maildir], root))

        cur.execute(LINK, (message_id, mailbox_id))
    conn.commit()
    return message_id


def perform(argv, raw, environ, root):
    """Everything the hook does, with every refusal raised rather than returned."""
    if len(argv) != 1:
        raise Refused(f"expected one argument, the mailbox; got {len(argv)}")
    mailbox = argv[0]
    # ⛔ The second lock: the binding names Sent alone, and this refusal is what makes a
    # mis-binding harmless instead of a hook that fans out somebody's Drafts.
    if mailbox != ONLY_MAILBOX:
        raise Refused(f"refusing mailbox {mailbox!r} - this hook is for {ONLY_MAILBOX} alone")

    account, domain = account_of(environ.get("USER", ""))
    login = f"{account}@{domain}"
    outgoing = read_message(raw)
    source = source_of(login, domain, account, raw, outgoing.message_id, root)

    folder = archive_folder(account)
    archive_maildir = store.maildir(store.archive_home(domain, root), folder)
    named = already_named(source, archive_maildir)
    if named is not None:
        log(f"{login}: {folder} holds this message already ({Path(named).name}); nothing to add")
        return

    conn = db.connect(CONSUMER)
    try:
        message_id = record(conn, domain, account, folder, outgoing, source, root)
        if message_id is None:
            conn.rollback()
            log(f"{login}: {outgoing.message_id} is recorded already; nothing to add")
        else:
            log(f"{login}: named {outgoing.message_id or 'a message with no Message-ID'} "
                f"in {store.ARCHIVE}@{domain}'s {folder}")
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def main(argv=None, raw=None, environ=None, root=None):
    """⛔ Returns 0 whatever happens. The stdin is read before anything else."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if raw is None:
        raw = sys.stdin.buffer.read()
    environ = os.environ if environ is None else environ
    try:
        perform(argv, raw, environ, STORE_ROOT if root is None else root)
    except (Refused, config.ConfigError, doveadm.DoveadmError) as err:
        failed(str(err))
    except Exception as err:  # noqa: BLE001 - nothing whatever fails the client's APPEND
        failed(f"{type(err).__name__}: {err}")
    return 0
