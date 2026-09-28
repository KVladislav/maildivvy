"""The one way our programs ask Dovecot about the store: `doveadm`, run as the mail owner.

Every call asks for the JSON formatter, with the flag before the verb (after it doveadm
exits 64), and the answer must parse as a JSON list. The default line format prints a
header's second occurrence, and a folded header's continuation, on a line of their own,
where a line parser reads a sender's `uid: 999999` as a field; JSON keeps each field in
its own string with its newlines inside, and replaces invalid UTF-8. Header
fields are asked for as lowercase `hdr.<name>`, so the key read back is the key asked for.

A nonzero exit raises `DoveadmError` with the code and doveadm's own lines. So does a
fetch from a mailbox that does not exist, which doveadm answers `[]` with exit 0
(measured on 2.4.2): the mailbox's status is asked first, and an empty answer then
means an empty mailbox.

A message's file comes from Dovecot by UID (`storageid`), resolved among the names of
`store.MESSAGE_NAMES`, never by listing a directory, and looked up once more if the file
moved in between.

Folders are made through Dovecot, never by mkdir: a directory without Dovecot's
`maildirfolder` marker is never listed. `INBOX` is never created, since to
Dovecot the maildir is the INBOX and the create always fails. "Mailbox
already exists" is success.

The archive's ACL (`owner lookup read write-seen`) binds doveadm too: a create or a save
there is refused `Permission denied`. The product's own writes into an archive run with
the ACL plugin off (`-o mail_plugins/acl=no`), and every folder made there is given the
archive's ACL itself, since a folder with no ACL file of its own keeps every right
(measured on 2.4.2).
"""

import json
import re
import subprocess

from maildivvy.lib import store

DOVEADM = "/usr/bin/doveadm"
TIMEOUT = 300  # seconds
EX_DATAERR = 65
ALREADY_EXISTS = "Mailbox already exists"
ACL_OFF = ("-o", "mail_plugins/acl=no")
ARCHIVE_ACL = ("owner", "lookup", "read", "write-seen")
FIELD = re.compile(r"^[a-z0-9][a-z0-9.<>_-]*$")


class DoveadmError(Exception):
    """doveadm failed, answered something that is not JSON, or did not name the message."""

    def __init__(self, message, returncode=None):
        super().__init__(message)
        self.returncode = returncode


def is_archive(login):
    """A domain archive's login, `archive@<domain>`; no person may have that login."""
    local, at, domain = login.partition("@")
    return local == store.ARCHIVE and bool(at) and bool(domain)


def run(verb, login, *args, input=None, acl=True, timeout=TIMEOUT):
    """Run `doveadm -f json <verb> -u <login> <args>`; returns the parsed JSON list."""
    argv = [DOVEADM, "-f", "json", *(() if acl else ACL_OFF), *verb, "-u", login, *args]
    return _json(argv, " ".join(verb) + f" -u {login}", input=input, timeout=timeout)


def sessions(login):
    """The sessions open on one login, one record each; `[]` for none.

    ⚠️ `doveadm who -1` prints a COLUMN HEADER even when nobody is logged in, so a line
    count reads one session where there are none - which is how a transfer comes to
    refuse every time, or, with the header subtracted wrongly, to rename an index tree
    under a live session. The JSON formatter has no header at all: no session is `[]`.
    The login is a mask here, not `-u`, which is why this does not go through `run`.
    """
    return _json([DOVEADM, "-f", "json", "who", "-1", login], f"who -1 {login}")


def _json(argv, command, input=None, timeout=TIMEOUT):
    """Run one doveadm command and read its answer as a JSON list."""
    try:
        done = subprocess.run(argv, input=input, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DoveadmError(f"doveadm {command} timed out after {timeout} s") from None
    stderr = done.stderr.decode("utf-8", "replace").strip()
    if done.returncode != 0:
        raise DoveadmError(f"doveadm {command} exited {done.returncode}: {stderr}", done.returncode)
    try:
        answer = json.loads(done.stdout.decode("utf-8", "replace"))
    except ValueError as err:
        raise DoveadmError(f"doveadm {command} printed no JSON: {err}") from None
    if not isinstance(answer, list):
        raise DoveadmError(f"doveadm {command} printed JSON that is not a list")
    return answer


def mailbox_status(login, mailbox, *fields):
    """One mailbox's status fields (`messages`, `uidnext`, `uidvalidity`...) as a dict."""
    answer = run(("mailbox", "status"), login, " ".join(fields or ("messages",)), mailbox)
    if len(answer) != 1:
        raise DoveadmError(f"doveadm mailbox status {mailbox} for {login} answered {len(answer)} records")
    return answer[0]


def fetch(login, mailbox, fields, *search):
    """The records of the messages matching `search` in one mailbox, one dict each."""
    for field in fields:
        if not isinstance(field, str) or not FIELD.match(field):
            raise ValueError(f"fetch field {field!r} is not one lowercase word")
    mailbox_status(login, mailbox)  # raises for a mailbox that does not exist
    return run(("fetch",), login, " ".join(fields), "mailbox", mailbox, *search)


def storage_id(login, mailbox, uid):
    """The storage id of the message with this UID: its maildir base name."""
    records = fetch(login, mailbox, ["uid", "storageid"], "uid", str(int(uid)))
    matching = [r for r in records if r.get("uid") == str(int(uid)) and r.get("storageid")]
    if len(matching) != 1 or len(records) != 1:
        raise DoveadmError(f"{login} {mailbox}: UID {uid} answered {len(records)} records, not one")
    return matching[0]["storageid"]


def message_file(domain, account, folder, uid, root=store.STORE_ROOT):
    """The file of one message, by UID, in a mailbox's folder; looked up twice at most."""
    login = f"{account}@{domain}"
    folder_maildir = store.maildir(store.home(domain, account, root), folder)
    for _ in range(2):
        base = storage_id(login, folder, uid)
        path = store.resolve(folder_maildir, base)
        if path is not None:
            return path
    raise DoveadmError(f"{login} {folder}: UID {uid} (storage id {base!r}) has no file "
                       f"under new/ or cur/ of {folder_maildir}")


def create_folder(login, folder):
    """Create a folder through Dovecot; True if made, False if it existed already.

    In an archive the folder is made past the ACL and then given the archive's ACL,
    also when it existed, so a folder never stays open for want of its own ACL file.
    """
    store.mailbox_name(*folder.split(store.SEPARATOR))
    if folder.upper() == "INBOX":
        raise ValueError("INBOX is never created: to Dovecot the maildir is the INBOX")
    archive = is_archive(login)
    try:
        run(("mailbox", "create"), login, folder, acl=not archive)
        made = True
    except DoveadmError as err:
        if err.returncode != EX_DATAERR or ALREADY_EXISTS not in str(err):
            raise
        made = False
    if archive:
        run(("acl", "set"), login, folder, *ARCHIVE_ACL)
    return made
