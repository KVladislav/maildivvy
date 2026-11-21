"""The snapshot of an IMAP mailbox: a read-only copy of every folder at the
provider into a Maildir++ tree in the store, for the import to read. Nothing in
it goes through the delivery filter or the pass.

    snap = Snapshot(mailbox_id)
    status = snap.start(session, mark, server, stop)  # the folders, their targets, the manifest
    status = snap.walk(session, stop, room)   # DONE, or STOPPED when stop() or room() said so

    status = take(conn, mailbox, args)   # one slice, as `maildivvy-fetch --snapshot` runs it

The runner takes the snapshot's own lock (`locks.SNAPSHOT`) and re-reads the row under
it; `take` does the rest of a slice: logs in, starts the snapshot or goes on with it, walks
until the slice's end or the reserve, and writes where it stands on the row.

⛔ NOTHING IS CHANGED AT THE PROVIDER. The session is collection's: every folder is opened
with EXAMINE and every body read with BODY.PEEK[], and its guard refuses anything else.
LIST is the one command the snapshot adds to what collection sends.

⛔ THE BOUNDARY IS NOT EXACT. The INBOX is taken up to the incremental mark it is given,
and every other folder up to its last UID at the start. Mail filed incrementally is in
both places, and mail moved while the snapshot runs may be missed or doubled: the import
deduplicates by Message-ID.

⛔ A MESSAGE'S FILE IS NAMED FROM (UIDVALIDITY, UID) ALONE, `<uidvalidity>.<uid>.snapshot`,
before its `,S=<bytes written>` and its flags. A walk skips every UID
whose name is already in `cur/`, so a slice stopped anywhere, between a file and the
manifest included, repeats nothing. A file is written to `tmp/`, fsynced, given the
message's INTERNALDATE as its mtime and renamed into `cur/`: it is whole or absent, and
`cur/` is fsynced before the manifest counts it.

⛔ A FOLDER'S PATH IS ITS NAME AS THE PROVIDER SENDS IT, in modified UTF-7, split at the
provider's delimiter, joined by `/` and put through `store.maildir()`. Dovecot stores a
folder under that name, escaped as `store.escape()` escapes it, and cannot open one
written in UTF-8, so no codec is written. A folder whose name cannot be such a
path (a part holding `/`, a name outside ASCII, a line break or a NUL, which could not be
sent back to the server either, or a directory name longer than NAME_MAX: Maildir++ makes
the whole hierarchy one name) is left out and named in the manifest.

THE START IS RESUMABLE, as the walk is. The first slice lists the folders and writes the
manifest; each folder's UIDVALIDITY and target are then taken by EXAMINE and saved as they
are read, so a slice whose time runs out among many folders leaves the rest to the next
one instead of starting over.

⛔ A FOLDER THE SERVER WILL NOT OPEN IS LEFT OUT ONLY WHEN THE REFUSAL LASTS, AND IS ITS
OWN, at the start and on every later slice alike (`_each_opened`). A refusal of its EXAMINE
or of the UID SEARCH after it, whatever it says (`imap.ServerError`: a NO with any code or
none, a BAD, no UIDVALIDITY), passes it for the other folders, keeping no target at the
start; the slice then pauses, and each later slice asks again. Such a refusal counts only
when the server opens and searches the INBOX right after it (`_count_refusal`): when it
refuses that too, the whole account is refused for now, and nothing is counted, so an
outage, however long, leaves no folder out. A slice that opens the folder forgets the
count (`open_refused`); counted in OPEN_REFUSED_MAX slices in a row, the folder is left
out, named with the server's answer: it would stop every slice. What was copied of it
stays in the tree, and its entry in `left_out` says what (`_leave_out`).

⛔ A SESSION THAT ENDS WHILE A FOLDER IS OPENED OR SEARCHED (closed, or silent for
`imap.READ_BOUND`) brings no answer: the slice pauses and nothing is counted, but the
folder's `open_cut_off` records it. The next slice that tries the folder opens and searches
the INBOX first, so a session that ends over it again, the account having answered,
counts as a refusal to open it: a server that fails on opening one folder every time holds
the snapshot up for OPEN_REFUSED_MAX + 1 slices, and not for ever.

⛔ A CHANGED UIDVALIDITY in the INBOX fails the snapshot (`Failed`): its boundary with the
mark is lost. In any other folder the folder's copy is emptied and taken again under the
new numbering, up to its last UID then.

⛔ A FOLDER GONE AT THE PROVIDER DURING THE SNAPSHOT IS LEFT OUT, NOT RETRIED. Its EXAMINE
would fail on every later slice and the snapshot would never end; one that the provider no
longer lists is marked `gone` with what was copied of it kept, and the messages it refused
forgotten: no round could ask for them again. A folder still listed that a later slice
cannot open is judged as at the start, above.

⛔ A MESSAGE THE PROVIDER WILL NOT SEND IS PASSED, AND ASKED FOR AGAIN A BOUNDED NUMBER OF
TIMES. Every refusal of its UID FETCH, whatever its code (`imap.MessageRefused`), names it
in its folder's `refused` and the walk goes on, for the same reason: the snapshot claims
no exact boundary, and one message must not hold up the rest. Once every folder is
taken, each later slice walks each folder again from its first refused message (what is
written or refused in that round is skipped), ASK_AGAIN rounds at most, one a slice: a
period of errors is outlasted, and a message refused for good ends the snapshot `done`
without it, counted on the row (`snapshot_refused`), which the mailbox's page and health
both show.

⛔ BUT A REFUSAL STANDS ONLY WHEN THE SERVER STILL HANDS MESSAGES OVER. One answer cannot
tell a message's refusal from the whole account's (a provider down, over a quota). The
refusals since the folder last handed a message over stand once it hands over the next
one; when the walk has none to ask before it would stop (the folder's end, or
REFUSED_IN_A_ROW refused in a row), messages the copy already holds are asked for again as
the proof, until one is handed over (`_proved`): the PROOFS smallest of the folder's own
copy, then of each other folder's copy, the INBOX's first, so a folder refused whole, or
one with nothing copied yet, is told from the account. One expunged since it was copied
proves nothing, and neither does one refused, which may be that message's own trouble.
When none is handed over and the server refused one, the account is refused for now:
those refusals are taken back, the walk's place is put before the first of them, and the
slice pauses, so an outage, however long, uses up no message's rounds and marks nothing
refused. A slice that stops for its time takes its unproven refusals back too. When no
message of the whole copy could be asked (nothing copied yet, or every proof asked
expunged), nothing can prove them: they stand, and REFUSED_IN_A_ROW of them pause the
slice.

⛔ A SESSION THAT ENDS OVER A PROOF (a BYE, or a connection that fails) cannot tell either:
its refusals are taken back and the slice pauses, but the folder's `proof_ended` counts
the slice, and at the PROOF_ENDED_MAX-th in a row they stand, so a copied message the
server now fails over every time holds the folder up for that many slices, not for ever.
A message of the folder handed over, or a proof, forgets the count. A BYE while the
server answers a message ends the session, so nothing can prove it: that message's
refusal stands as it is (Dovecot's answer to a message it cannot read), and the slice
pauses.

⛔ A MESSAGE THAT ENDS THE SESSION TWICE IN A ROW IS REFUSED, NOT ASKED FOR ON EVERY SLICE.
The slice's own deadline (its end and GRACE) cuts off the message in hand, and so does a
connection that fails while the server answers it, with no BYE (closed, or silent for
`imap.READ_BOUND`); the next slice starts with it. The folder's `cut_off` records its UID,
and a second cut-off of that UID, the next slice having logged in, opened the folder and
searched it to reach it, stands as its refusal, as a BYE's does; one handed over is
forgotten. The rounds ask for it again, and each cut-off of it then is a refusal at once.

`manifest.json`, beside `Maildir/` and written by temp file and rename, records each
folder taken (the provider's name, its path, its attributes, its UIDVALIDITY and target
UID, both None until its EXAMINE, the slices in a row whose refusal to open it counted,
whether the session last ended while it was opened, the last UID handled, its messages and
bytes, the UIDs refused, the UID a cut-off last ended the session over, the slices in a row
in which a proof of its refusals ended the session, whether it went),
the folders left out (each named with why, and one a slice had opened with its path,
attributes, UIDVALIDITY and the messages and bytes its copy keeps), the server it was taken
from and the rounds that asked the refused messages again. It is where the next slice
resumes, and what the row's detail is made from. It is saved after each folder and every
PROGRESS_EVERY messages.

THE SLICE (`take`) runs for up to `--slice-seconds`, from its own timer every ten minutes
as `vmail`, and leaves one of the row's statuses:

- `running` while it runs;
- `pending`: its time ran out and there is more to take, or refused messages to ask for
  again; the next slice goes on;
- `paused`: something outside the snapshot stopped it, and the next slice tries again:
  the reserve below, or a reserve that cannot be read, a provider that cannot be reached
  or refuses the login, a server's error, a store that refused a write, no password
  stored. The row keeps since when (`snapshot_paused_since`), and health warns of one
  paused for longer than a day;
- `done`, or `failed`: the INBOX renumbered, the mailbox's server or login changed since
  the start, its mark cleared before the first slice, or a fault of ours. Neither is taken
  up again: a discard ends it, and a new request starts another.

Each slice writes on the row how many messages the provider refused and the copy does not
hold (`snapshot_refused`), and how many folders it left out (`snapshot_left_out`).

⛔ THE RESERVE. Before each message is written the slice reads the snapshot's
filesystem, and stops `paused` rather than take it under the free share health warns at
for the disk layout (`health.conf`'s `disk_warn_percent`, or `single_disk_warn_percent`
on one disk), in space or in inodes: a copy for a later import must never be what holds
today's mail, which the delivery filter refuses at its own floor.

⛔ A SNAPSHOT IS ASKED FOR BY THE INTERFACE AND TAKEN BY NOTHING ELSE. The interface writes
`snapshot_requested_at` alone and the pipeline every other snapshot column, so a request
is new while the row has no status and the request is later than the last snapshot ended
(`WANTED`); a discard ends one too, so a request it discarded is not taken up again.
"""

import json
import os
import re
import shutil
import time
from pathlib import Path

from maildivvy.fetch import credential, imap, outcome, render
from maildivvy.health import settings as health_settings
from maildivvy.health import system as health_system
from maildivvy.health.probe import Unreadable
from maildivvy.lib import store

MANIFEST = "manifest.json"
PROGRESS_EVERY = 100   # messages handled between two saves of the manifest
FILE_MODE = 0o600
ASK_AGAIN = 6          # later slices that ask for the refused messages again, a round each
OPEN_REFUSED_MAX = 7   # slices in a row whose refusal to open a folder counted, that leave it out
REFUSED_IN_A_ROW = 10  # messages refused one after another before they are proved (`_proved`)
PROOFS = 3             # messages of one folder's copy asked for in turn, smallest first, as the proof
PROOF_ENDED_MAX = 7    # slices in a row a proof ended the session, after which the refusals stand
NAME_MAX = 255         # bytes of one directory name, on every filesystem the store may have

# What a start or a walk ends with: DONE, or STOPPED when the slice's `stop()` or `room()`
# said so. DONE is also the row's status of a snapshot taken whole.
DONE, STOPPED = "done", "stopped"
# The row's `snapshot_status` (`take`)
PENDING, RUNNING, PAUSED, FAILED = "pending", "running", "paused", "failed"
STATUSES = (PENDING, RUNNING, PAUSED, DONE, FAILED)   # the schema's CHECK, in its order
ENDED = (DONE, FAILED)

# Maildir's flag letters for IMAP's system flags; a name carries them in ASCII order.
FLAG_LETTERS = {"\\DRAFT": "D", "\\FLAGGED": "F", "\\ANSWERED": "R", "\\SEEN": "S",
                "\\DELETED": "T"}
WRITTEN = re.compile(r"^(\d+)\.(\d+)\.snapshot,S=(\d+):2,")

NOT_ASCII = ("the provider sent its name outside modified UTF-7, and Dovecot cannot open a "
             "folder written so")
SLASH = "a part of its name holds '/', which cannot be a folder under the store's separator"
LINE_BREAK = ("its name holds a line break or a NUL, which no command could send back to "
              "the server")
TOO_LONG = (f"its directory in the store would be a name longer than the {NAME_MAX} bytes a "
            "filesystem takes")


class Failed(Exception):
    """The snapshot cannot go on; its text is a detail fit for the row."""


def home(mailbox_id, root=store.SNAPSHOT_ROOT):
    """The snapshot's directory: `Maildir/` and the manifest."""
    return Path(root) / str(int(mailbox_id))


def path_of(folder):
    """(the folder's path in the tree, its parts joined by `/`, None), or (None, why the
    folder is left out)."""
    if not folder.name.isascii():
        return None, NOT_ASCII
    if imap.UNSENDABLE.search(folder.name):
        return None, LINE_BREAK
    parts = [folder.name] if folder.delimiter is None else folder.name.split(folder.delimiter)
    if any(store.SEPARATOR in part for part in parts):
        return None, SLASH
    try:
        path = store.mailbox_name(*parts)
    except store.StoreError as err:
        return None, str(err)
    if len(store.maildir("/", path).name.encode()) > NAME_MAX:
        return None, TOO_LONG
    return path, None


def is_inbox(name):
    return name.upper() == imap.INBOX


def base(uidvalidity, uid):
    return f"{uidvalidity}.{uid}.snapshot"


def file_name(uidvalidity, uid, size, flags):
    letters = sorted({FLAG_LETTERS[f.upper()] for f in flags if f.upper() in FLAG_LETTERS})
    return f"{base(uidvalidity, uid)},S={size}:2,{''.join(letters)}"


def written(box, uidvalidity):
    """{uid: size} of the files in a folder's `cur/` under this UIDVALIDITY."""
    found = {}
    with os.scandir(Path(box) / "cur") as entries:
        for entry in entries:
            parts = WRITTEN.match(entry.name)
            if parts and int(parts[1]) == uidvalidity:
                found[int(parts[2])] = int(parts[3])
    return found


def counted(have):
    """A folder's `messages` and `bytes`, from its copy as `written` reads it."""
    return {"messages": len(have), "bytes": sum(have.values())}


def _private_open(path, flags):
    """`open`'s opener for a file only the mail owner reads."""
    return os.open(path, flags, FILE_MODE)


def write(box, uidvalidity, message):
    """The message's file in `cur/`, through `tmp/`; the bytes written."""
    name = file_name(uidvalidity, message.uid, len(message.data), message.flags)
    temporary = Path(box) / "tmp" / name
    with open(temporary, "wb", opener=_private_open) as out:
        out.write(message.data)
        out.flush()
        os.fsync(out.fileno())
    if message.internaldate is not None:
        os.utime(temporary, (message.internaldate, message.internaldate))
    os.rename(temporary, Path(box) / "cur" / name)
    return len(message.data)


def empty(box):
    """Every file of one folder's maildir removed, its directories and other folders kept."""
    for part in ("cur", "new", "tmp"):
        with os.scandir(Path(box) / part) as entries:
            for entry in entries:
                if entry.is_file(follow_symlinks=False):
                    os.unlink(entry.path)


def entry(folder, path, uidvalidity=None, target=None):
    """A folder's place in the manifest; its UIDVALIDITY and target None until its EXAMINE."""
    return {"name": folder.name, "path": path, "attributes": list(folder.attributes),
            "uidvalidity": uidvalidity, "target": target, "open_refused": 0,
            "open_cut_off": False, "last": 0, "messages": 0, "bytes": 0, "refused": [],
            "cut_off": None, "proof_ended": 0, "gone": False}


def refused_of(manifest):
    """How many messages the provider refused and the snapshot does not hold, None before the
    start."""
    return None if manifest is None else sum(len(f["refused"]) for f in manifest["folders"])


def left_out_of(manifest):
    """How many folders at the provider the snapshot leaves out, None before the start."""
    return None if manifest is None else len(manifest["left_out"])


def asks_again(manifest):
    """Whether a later slice asks for the refused messages again (ASK_AGAIN)."""
    return bool(refused_of(manifest)) and manifest["asked_again"] < ASK_AGAIN


class Snapshot:
    """One external mailbox's snapshot, under `root`; directories made for `owner`, the
    (uid, gid) of the mail owner when None."""

    def __init__(self, mailbox_id, root=store.SNAPSHOT_ROOT, owner=None):
        self.root = Path(root)
        self.home = home(mailbox_id, root)
        self.owner = owner or (None, None)

    @property
    def manifest_path(self):
        return self.home / MANIFEST

    def maildir(self, folder):
        return store.maildir(self.home, folder["path"])

    def read(self):
        """The manifest, or None before the start."""
        try:
            return json.loads(self.manifest_path.read_text())
        except FileNotFoundError:
            return None

    def save(self, manifest):
        """The manifest by temp file and rename, both fsynced."""
        temporary = self.home / f".{MANIFEST}.tmp"
        with open(temporary, "w", opener=_private_open) as out:
            json.dump(manifest, out, indent=1)
            out.flush()
            os.fsync(out.fileno())
        os.rename(temporary, self.manifest_path)
        store.fsync_dirs([self.home])

    def start(self, session, mark, server, stop):
        """The snapshot's start, from where the last one stopped: DONE once every folder has
        its target, STOPPED when `stop()`, asked before each EXAMINE, said so first.

        The first lists the folders, makes the INBOX's maildir and writes the manifest; then
        each other folder's UIDVALIDITY and target are read by EXAMINE, its maildir made and
        the manifest saved. `mark` is the INBOX's (UIDVALIDITY, last UID collected), and
        `server` what the slice holds the next ones to (`server_of`). Raises `Failed` when
        there is no mark, and the session's own errors as they come; a folder the server will
        not open is passed, and its refusal raised once the other folders have their target
        (`_each_opened`).
        """
        manifest = self.read()
        if manifest is None:
            if mark is None or None in mark:
                raise Failed("the mailbox has no mark, so the INBOX's part of the snapshot has "
                             "no end; activate the mailbox again first")
            inbox_folder = imap.Folder(imap.INBOX, None, ())
            others, left_out = [], []
            for folder in session.folders():
                if is_inbox(folder.name):
                    inbox_folder = folder
                    continue
                path, why = path_of(folder)
                if why is not None:
                    left_out.append({"name": folder.name, "why": why})
                    continue
                others.append(entry(folder, path))
            manifest = {"folders": [entry(inbox_folder, imap.INBOX, *mark), *others],
                        "left_out": left_out, "server": server, "asked_again": 0}
            store.make_dir(self.home, self.root, *self.owner)
            store.make_maildir(self.maildir(manifest["folders"][0]), self.root, *self.owner)
            self.save(manifest)
        unstarted = [f for f in manifest["folders"] if f["target"] is None]
        for folder, (examined, target) in self._each_opened(session, manifest, unstarted,
                                                            self._target, stop):
            store.make_maildir(self.maildir(folder), self.root, *self.owner)
            folder.update(uidvalidity=examined.uidvalidity, target=target)
            self.save(manifest)
        return DONE if all(f["target"] is not None for f in manifest["folders"]) else STOPPED

    def walk(self, session, stop, room):
        """Take every folder's messages up to its target, from where the last walk left off.

        `stop()` is asked before each message is fetched, and `room(size)` before a fetched
        one is written; DONE when every folder is, and STOPPED when either said so. A walk
        that finds every folder taken and refused messages to ask for again (`asks_again`)
        is a round of asking: each folder holding some is walked again from its first.
        Raises `Failed` when the INBOX was renumbered, and the session's own errors as they
        come: what is written stays, and the next walk goes on from it. A folder the server
        will not open is passed, and its refusal raised once the other folders are walked
        (`_each_opened`).
        """
        manifest = self.read()
        if all(f["last"] >= f["target"] for f in manifest["folders"]) and asks_again(manifest):
            manifest["asked_again"] += 1
            for folder in manifest["folders"]:
                if folder["refused"]:
                    folder["last"], folder["refused"] = min(folder["refused"]) - 1, []
            self.save(manifest)
        unfinished = [f for f in manifest["folders"] if f["last"] < f["target"]]
        for folder, uids in self._each_opened(session, manifest, unfinished, self._uids_left):
            if self._take_folder(session, manifest, folder, uids, stop, room) == STOPPED:
                return STOPPED
        return DONE

    # --- opening a folder, at the start and on every later slice

    def _each_opened(self, session, manifest, folders, opening, stop=None):
        """(each of `folders` in turn, `opening(session, manifest, folder)`: its EXAMINE and
        the UID SEARCH after it), while `stop()`, asked before each, does not say so.

        A folder the server will not open (`imap.ServerError`) is judged (`_count_refusal`)
        and passed for the others, and its refusal raised once they are done: the slice
        pauses on it. A session that ends while one is opened (`imap.Unreachable`) ends the
        slice (`_ended_opening`), and the next slice to try that folder asks the INBOX first.
        One opened forgets both.
        """
        waiting = None   # a folder not opened: the slice pauses on it after the rest
        for folder in folders:
            if stop is not None and stop():
                return
            if folder["open_cut_off"]:
                self._inbox_answers(session)   # refused, it is the account's: raised
            try:
                opened = opening(session, manifest, folder)
            except imap.ServerError as err:
                waiting = self._count_refusal(session, manifest, folder, err) or waiting
                self.save(manifest)
                continue
            except imap.Unreachable as err:
                self._ended_opening(manifest, folder, err)
                raise
            folder.update(open_refused=0, open_cut_off=False)
            yield folder, opened
        if waiting is not None:
            raise waiting

    @staticmethod
    def _target(session, _manifest, folder):
        """The start's opening of a folder: (what its EXAMINE answered, its last UID now, which
        is its target)."""
        examined = session.examine(folder["name"])
        return examined, session.last_uid(examined)

    def _uids_left(self, session, manifest, folder):
        """The walk's opening of a folder: EXAMINEd, and its UIDs left to take searched;
        emptied and taken again first under a new numbering, but for the INBOX, whose
        renumbering fails the snapshot. None to take for a folder the provider no longer
        lists: it is marked `gone`, its refused messages and cut-off forgotten with it, and
        what was copied of it is kept."""
        try:
            examined = session.examine(folder["name"])
            if examined.uidvalidity != folder["uidvalidity"]:
                if is_inbox(folder["name"]):
                    raise Failed(f"the provider renumbered the INBOX (UIDVALIDITY "
                                 f"{examined.uidvalidity}, not the mark's "
                                 f"{folder['uidvalidity']}), so the snapshot's boundary with "
                                 "the incremental collection is lost")
                target = session.last_uid(examined)
                empty(self.maildir(folder))
                folder.update(uidvalidity=examined.uidvalidity, target=target, last=0,
                              messages=0, bytes=0, refused=[], cut_off=None, proof_ended=0)
                self.save(manifest)
            return session.uids_above(folder["last"], folder["target"])
        except imap.ServerError:
            if is_inbox(folder["name"]) or any(f.name == folder["name"]
                                               for f in session.folders()):
                raise
        folder.update(gone=True, refused=[], cut_off=None)
        return []

    def _count_refusal(self, session, manifest, folder, err):
        """A folder's EXAMINE, or the UID SEARCH after it, refused (`err`), at the start or on
        a later slice: `err` when the folder waits for the next slice to ask again, None when
        it is left out (`_count`). Raises `err` for the INBOX, and when the server refuses to
        open or search the INBOX right after it: the account's, and nothing counted."""
        if is_inbox(folder["name"]):
            raise err
        try:
            self._inbox_answers(session)
        except imap.ServerError:
            raise err from None
        return err if self._count(manifest, folder, err) else None

    def _ended_opening(self, manifest, folder, err):
        """A session that ended while the folder was opened or searched (`err`): no answer, and
        its `open_cut_off` records it. Recorded already, the INBOX answered first in this
        session (`_each_opened`), so it counts as a refusal to open the folder (`_count`).
        The INBOX's own is the account's: nothing is recorded."""
        if is_inbox(folder["name"]):
            return
        if folder["open_cut_off"]:
            self._count(manifest, folder, err)
        else:
            folder["open_cut_off"] = True
        self.save(manifest)

    @staticmethod
    def _inbox_answers(session):
        """The control that the account answers: the INBOX opened and searched. Raises the
        session's errors."""
        session.examine(imap.INBOX)
        session.uids_above(0, 1)   # one UID SEARCH, the smallest there is

    def _count(self, manifest, folder, err):
        """One more slice in a row whose refusal to open the folder counted: whether it still
        waits for the next, and at the OPEN_REFUSED_MAX-th it is left out (`_leave_out`)."""
        folder["open_refused"] += 1
        if folder["open_refused"] < OPEN_REFUSED_MAX:
            return True
        self._leave_out(manifest, folder, err)
        return False

    def _leave_out(self, manifest, folder, err):
        """The folder out of the walk and into `left_out`, named with `err`. What was copied
        of it stays in the tree, so its entry says what, as a `gone` folder's does: for one
        a slice opened, its path, attributes and UIDVALIDITY, and the messages and bytes in
        its `cur/`."""
        manifest["folders"].remove(folder)
        out = {"name": folder["name"], "why": str(err)}
        if folder["target"] is not None:   # opened once: its maildir is in the tree
            out.update(path=folder["path"], attributes=folder["attributes"],
                       uidvalidity=folder["uidvalidity"],
                       **counted(written(self.maildir(folder), folder["uidvalidity"])))
        manifest["left_out"].append(out)

    # --- taking a folder's messages

    def _take_folder(self, session, manifest, folder, uids, stop, room):
        """The folder's messages in `uids` taken in turn, past each one its copy holds or a
        slice refused, its place saved as it goes; DONE once it reaches its target, STOPPED
        when `stop()`, asked before each fetch, or `room(size)`, before each write, said so.

        Each message is asked for by `_ask`, which judges its refusals and cut-offs. When the
        walk stops or the session fails, the refusals nothing proved are taken back
        (`_take_back`) and the place saved first; the session's errors are raised, and what
        was written stays.
        """
        box = self.maildir(folder)
        have = written(box, folder["uidvalidity"])
        earlier = set(folder["refused"])  # refused before this walk, or earlier in this round
        unproven = []                     # refused since the folder last handed a message over
        try:
            for handled, uid in enumerate(uids, 1):
                if uid not in have and uid not in earlier:
                    if stop():
                        self._take_back(folder, unproven)
                        self._save_progress(manifest, folder, have)
                        return STOPPED
                    message = self._ask(session, manifest, folder, uid, have, unproven)
                    if message is not None:
                        if not room(len(message.data)):
                            self._save_progress(manifest, folder, have)
                            return STOPPED
                        have[uid] = write(box, folder["uidvalidity"], message)
                folder["last"] = uid
                if handled % PROGRESS_EVERY == 0:
                    self._save_progress(manifest, folder, have)
            if unproven:
                self._proved(session, manifest, folder, have, unproven)   # they stand, or raised
        except imap.Failure:
            self._take_back(folder, unproven)
            self._save_progress(manifest, folder, have)
            raise
        folder["last"] = folder["target"]
        self._save_progress(manifest, folder, have)
        return DONE

    def _ask(self, session, manifest, folder, uid, have, unproven):
        """The message `uid` from the server, or None when it is refused or was expunged since
        the search.

        A refusal joins the folder's `refused` and, until the folder hands over another
        message, `unproven`; at REFUSED_IN_A_ROW of them the proof is asked for at once
        (`_proved`), and with nothing to prove them they stand and the slice pauses. A
        session that ends over the message raises: a BYE's refusal stands, and so does a
        cut-off (the slice's deadline, or a connection that fails) of the UID the folder's
        `cut_off` records already, the second in a row; one that stands moves the folder's
        place to it.
        """
        try:
            message = session.fetch(uid)
        except (imap.Deadline, imap.Unreachable):
            if folder["cut_off"] == uid:
                # cut off again, reached by a session that logged in, opened the folder and
                # searched it: it stands, as a BYE's does
                folder["refused"].append(uid)
                folder["last"] = uid
            folder["cut_off"] = uid
            raise
        except imap.MessageRefused as err:
            folder["refused"].append(uid)
            if err.ended:
                folder["last"] = uid
                raise   # the session is over: nothing can prove it, and it stands
            unproven.append(uid)
            if (len(unproven) >= REFUSED_IN_A_ROW
                    and not self._proved(session, manifest, folder, have, unproven)):
                # nothing to prove with: they stand, and the slice pauses
                folder["last"] = uid
                unproven.clear()
                raise imap.ServerError(
                    f"{REFUSED_IN_A_ROW} messages in a row refused, the last in "
                    f"{folder['name']}: {err}") from None
            return None
        if message is not None:  # None: expunged since the search
            unproven.clear()     # it hands messages over: those refused stand
            folder["proof_ended"] = 0
            if folder["cut_off"] == uid:
                folder["cut_off"] = None   # handed over: the cut-off forgotten
        return message

    def _proved(self, session, manifest, folder, have, unproven):
        """Whether the refusals in `unproven` stand: True when the server hands over a message
        the copy holds, and they leave `unproven`.

        The PROOFS smallest of the folder's own copy (`have`) are asked first, then those of
        another folder's (`_handed_over_elsewhere`), after which the folder is opened again
        for its walk to go on. One expunged since it was copied proves nothing, and neither
        does one refused, which may be that message's own trouble. False when none could be
        asked, or each one asked was expunged: nothing proves them.

        Raises when none is handed over and the server refused one: the account is refused
        for now, nothing is counted, and the caller takes them back. When the session ends
        over a proof, whose trouble it is cannot be told: the folder's `proof_ended` counts
        the slice, and at the PROOF_ENDED_MAX-th in a row they stand before it raises
        (`_ended_proving`).
        """
        refused = []   # (the folder's name, its refusal) of each proof refused
        try:
            here = self._handed_over(session, folder, have, refused)
            elsewhere = not here and self._handed_over_elsewhere(session, manifest, folder,
                                                                 refused)
        except (imap.MessageRefused, imap.Unreachable) as err:   # a BYE, or a failure
            raise self._ended_proving(folder, unproven, err) from None
        if here or elsewhere:
            folder["proof_ended"] = 0
            unproven.clear()
            if elsewhere:
                self._reopen(session, folder)
            return True
        if not refused:
            return False
        named = ", ".join(f"{err.uid} in {name}" for name, err in refused)
        raise imap.ServerError(
            f"{len(unproven)} message(s) refused in {folder['name']}, and the messages copied "
            f"before asked as the proof refused too ({named}): the provider refuses the "
            f"account for now, and the next slice asks for them again; {refused[-1][1]}")

    @staticmethod
    def _handed_over(session, folder, have, refused):
        """Whether the server hands over one of the PROOFS smallest messages of `have`, the
        copy of `folder`, which the session has open, asked in turn. Each refused joins
        `refused`; a BYE's is raised, the session being over."""
        for proof in sorted(have, key=have.get)[:PROOFS]:
            try:
                if session.fetch(proof) is not None:
                    return True
            except imap.MessageRefused as err:
                if err.ended:
                    raise
                refused.append((folder["name"], err))
        return False

    def _handed_over_elsewhere(self, session, manifest, folder, refused):
        """`_handed_over` in the other folders whose copy holds a message, the INBOX first,
        each opened in turn: another folder answers for the account when this one's copy
        cannot. One the server will not open, or whose proofs were all expunged, passes to
        the next; once one refuses, no other is asked."""
        for other in manifest["folders"]:
            if other is folder or other["target"] is None or other["gone"]:
                continue
            copy = written(self.maildir(other), other["uidvalidity"])
            if not copy:
                continue
            try:
                session.examine(other["name"])
            except imap.ServerError:
                continue
            before = len(refused)
            if self._handed_over(session, other, copy, refused):
                return True
            if len(refused) > before:
                return False
        return False

    @staticmethod
    def _reopen(session, folder):
        """The folder opened again after a proof asked in another, for its walk to go on."""
        if session.examine(folder["name"]).uidvalidity != folder["uidvalidity"]:
            raise imap.ServerError(f"EXAMINE {folder['name']}: the provider renumbered it "
                                   "during the slice, and the next slice takes it again")

    @staticmethod
    def _ended_proving(folder, unproven, err):
        """What the slice ends with when the session ended over a proof (`err`): one more
        slice in a row in the folder's `proof_ended`, and at PROOF_ENDED_MAX the refusals in
        `unproven` stand, the walk's place past them."""
        folder["proof_ended"] += 1
        count, waiting = folder["proof_ended"], len(unproven)
        if count >= PROOF_ENDED_MAX:
            folder["last"] = max(folder["last"], *unproven)
            unproven.clear()
            fate = f"it did so on {count} slices in a row, so they stand"
        else:
            fate = (f"{count} of {PROOF_ENDED_MAX} slices in a row before they stand, and the "
                    "next slice asks for them again")
        return imap.ServerError(
            f"{waiting} message(s) refused in {folder['name']}, and the session ended over a "
            f"message copied before asked as the proof, so whose trouble it is cannot be "
            f"told: {fate}; {err}")

    @staticmethod
    def _take_back(folder, unproven):
        """Refusals nothing proved, out of the folder's `refused`, and its walk's place put
        before the first of them, so the next slice asks for them again. A refusal that
        stands after them (a BYE's, a second cut-off's) stays in `refused`, and the next walk
        passes it."""
        if unproven:
            folder["refused"] = [uid for uid in folder["refused"] if uid not in unproven]
            folder["last"] = min(unproven) - 1

    def _save_progress(self, manifest, folder, have):
        """The folder's copy made durable (its `cur/` fsynced) and counted from `have`, then
        the manifest saying so."""
        folder.update(counted(have))
        store.fsync_dirs([Path(self.maildir(folder)) / "cur"])
        self.save(manifest)


# --- the slice ------------------------------------------------------------------------

SLICE_SECONDS = 600       # a slice's length when the command line names none
GRACE = imap.READ_BOUND   # past the slice's end, how long the message in hand may still take

# The rows a slice goes on with, or starts (see the module's docstring): a snapshot under
# way, a `running` one included, which only a slice stopped without a word leaves behind,
# since the lock is held while one runs; or one asked for since the last one ended.
WANTED = ("(e.snapshot_status IN ('pending', 'running', 'paused') OR "
          "(e.snapshot_status IS NULL AND e.snapshot_requested_at > "
          "coalesce(e.snapshot_finished_at, '-infinity')))")
STATUS_OF = "SELECT snapshot_status FROM external_mailbox WHERE id = %s"
SLICE_STARTS = (f"UPDATE external_mailbox SET snapshot_status = '{RUNNING}', "
                "snapshot_started_at = now(), snapshot_finished_at = NULL, "
                "snapshot_detail = NULL, snapshot_paused_since = NULL, snapshot_refused = NULL, "
                "snapshot_left_out = NULL WHERE id = %s")
SLICE_GOES_ON = f"UPDATE external_mailbox SET snapshot_status = '{RUNNING}' WHERE id = %s"
# ⚠️ `snapshot_paused_since` is when the slices began to leave the snapshot paused: kept by
# every slice that leaves it paused again, the `running` of the slice between them included,
# and cleared by the first that leaves it otherwise. Health warns of one paused for longer
# than a day.
SLICE_ENDS = ("UPDATE external_mailbox SET snapshot_status = %s, snapshot_detail = %s, "
              "snapshot_finished_at = CASE WHEN %s THEN now() ELSE snapshot_finished_at END, "
              "snapshot_paused_since = CASE WHEN %s THEN coalesce(snapshot_paused_since, "
              "now()) END, snapshot_refused = %s, snapshot_left_out = %s WHERE id = %s")

TRIES_AGAIN = "the next slice tries again"
OUT_OF_TIME = "the slice's time ran out, and the next goes on"
ASKS_AGAIN = "the next slice asks the provider for them again"


def ending(status, detail, manifest, mailbox_id):
    """SLICE_ENDS's parameters for a slice that leaves the snapshot `status`, saying `detail`
    cut to `outcome.DETAIL_MAX` as every fetch detail is, with the messages and the folders
    the copy does not hold counted from `manifest` (`refused_of`, `left_out_of`)."""
    return (status, detail[:outcome.DETAIL_MAX], status in ENDED, status == PAUSED,
            refused_of(manifest), left_out_of(manifest), mailbox_id)


def reserve():
    """(the share of the store's filesystem, in percent, a snapshot never takes it under,
    the disk layout): health's warn level for the layout. Raises health's own
    errors when its settings or the disk record cannot be read."""
    conf = health_settings.read()
    mode = health_system.disk_mode()
    return health_settings.disk_bounds(conf, mode)[1], mode


def short_of(fs, percent, size):
    """What the filesystem has free, when one more file of `size` bytes would take it under
    `percent` free in space or in inodes, counted as health counts them; None when not."""
    if not fs.f_blocks:
        return "its filesystem reports no size"
    blocks = -(-size // fs.f_frsize) if fs.f_frsize else 0
    if min(health_system.free_percent(fs, blocks, 1)) >= percent:
        return None
    space, inodes = health_system.free_percent(fs)
    return f"{space:.1f}% of its space and {inodes:.1f}% of its inodes are free"


class Bounds:
    """One slice's two bounds, its end and the reserve; `full` says why the reserve stopped it."""

    def __init__(self, seconds, root, percent, mode):
        self.end = time.monotonic() + seconds
        self.root, self.percent, self.mode = root, percent, mode
        self.full = None

    def stop(self):
        return time.monotonic() >= self.end

    def room(self, size):
        short = short_of(os.statvfs(self.root), self.percent, size)
        if short is not None:
            self.full = (f"paused before the store's filesystem goes under the {self.percent}% "
                         f"free health warns at with {self.mode} disks: {short}; the next "
                         "slice goes on once there is room")
        return short is None


def server_of(mailbox):
    """What a snapshot is taken from: a snapshot goes on only with the same one. The
    protocol is there for the import, which reads it from the manifest: a slice takes IMAP
    mailboxes alone (`runner.SNAPSHOTS`), so it never differs between two slices."""
    return {"protocol": mailbox.protocol, "host": mailbox.pop3_host,
            "login": render.login_of(mailbox)}


def summary(manifest):
    """Where the snapshot stands, in words fit for the row's detail."""
    if manifest is None:
        return "not started"
    folders, left_out = manifest["folders"], manifest["left_out"]
    taken = sum(1 for f in folders if f["target"] is not None and f["last"] >= f["target"])
    on_disk = [*folders, *left_out]   # a folder left out keeps what was copied of it
    words = [f"{taken} of {len(folders)} folders taken, "
             f"{sum(f.get('messages', 0) for f in on_disk)} messages, "
             f"{sum(f.get('bytes', 0) for f in on_disk)} bytes"]
    if left_out:
        words.append(f"{len(left_out)} left out: " + ", ".join(
            f["name"] + (f" ({f['messages']} copied before kept)" if f.get("messages") else "")
            for f in left_out))
    gone = [f["name"] for f in folders if f["gone"]]
    if gone:
        words.append(f"gone at the provider during the snapshot: {', '.join(gone)}")
    refused = refused_of(manifest)
    if refused:
        words.append(f"{refused} message(s) the provider refused to send, not copied, asked "
                     f"for again {manifest['asked_again']} of {ASK_AGAIN} times")
    return "; ".join(words)


def take(conn, mailbox, args, root=store.SNAPSHOT_ROOT, owner=None):
    """One slice of an IMAP mailbox's snapshot, its lock held and its row re-read by the
    runner; the status it leaves on the row. `args` is the runner's command line: its
    `slice_seconds`. The row's detail says why the slice ended as it did and where the
    snapshot stands (`summary`), from the manifest read once the slice is over."""
    snap = Snapshot(mailbox.id, root, owner)
    # the database is read and written here and nowhere below: a statement that fails
    # leaves the row `running`, and the next slice goes on from the manifest
    with conn.cursor() as cur:
        cur.execute(STATUS_OF, (mailbox.id,))
        (status,) = cur.fetchone()
        cur.execute(SLICE_GOES_ON if status is not None else SLICE_STARTS, (mailbox.id,))
        secret = credential.secret_of(cur, mailbox.id)
    try:
        if status is None:
            # what a snapshot no row holds any more left behind: this request is a new one
            discard(mailbox.id, root)
        status, before, after = one_slice(snap, mailbox, secret, args)
        manifest = snap.read()
        if status == DONE and asks_again(manifest):
            status, after = PENDING, ASKS_AGAIN
        detail = "; ".join(words for words in (before, summary(manifest), after) if words)
    except Exception as err:  # noqa: BLE001 - a fault of ours: the snapshot fails, said, and is never retried
        # only the fault's kind, but for an OSError, as for a collection's
        said = f"{type(err).__name__}: {err}" if isinstance(err, OSError) else type(err).__name__
        status, detail, manifest = FAILED, f"the slice stopped on a fault of its own: {said}", None
    with conn.cursor() as cur:
        cur.execute(SLICE_ENDS, ending(status, detail, manifest, mailbox.id))
    return status


def one_slice(snap, mailbox, secret, args):
    """The slice itself: (the status, what the row's detail says before where the snapshot
    stands, and what after it), either None for nothing."""
    try:
        percent, mode = reserve()
    except (health_settings.SettingsError, Unreadable) as err:
        return PAUSED, f"the store's reserve cannot be known: {err}", None
    bounds = Bounds(args.slice_seconds, snap.root, percent, mode)
    if not bounds.room(0):
        return PAUSED, None, bounds.full
    started = snap.read()
    if started is not None and started["server"] != server_of(mailbox):
        return FAILED, ("the mailbox's server or login changed since the snapshot started, so "
                        "what is left to take is another mailbox's"), None
    if not secret:
        return PAUSED, credential.NO_SECRET, None
    try:
        with imap.connect(mailbox.pop3_host, mailbox.pop3_port, mailbox.pin,
                          bounds.end + GRACE) as session:
            session.login(render.login_of(mailbox), secret)
            walked = snap.start(session, (mailbox.imap_uidvalidity, mailbox.imap_last_uid),
                                server_of(mailbox), bounds.stop)
            if walked == DONE:
                walked = snap.walk(session, bounds.stop, bounds.room)
    except Failed as err:
        return FAILED, str(err), None
    except imap.Deadline:
        return PENDING, None, OUT_OF_TIME
    except imap.Failure as err:
        return PAUSED, str(err), TRIES_AGAIN
    except OSError as err:
        return PAUSED, f"the store refused a write: {err}", TRIES_AGAIN
    if walked == DONE:
        return DONE, None, None
    if bounds.full is not None:
        return PAUSED, None, bounds.full
    return PENDING, None, OUT_OF_TIME


def advanced_at(mailbox_id, root=store.SNAPSHOT_ROOT):
    """When the snapshot's manifest was last written, 0 for none yet: a run of slices takes
    the snapshot least recently advanced first."""
    try:
        return Snapshot(mailbox_id, root).manifest_path.stat().st_mtime
    except OSError:
        return 0


def discard(mailbox_id, root=store.SNAPSHOT_ROOT):
    """The snapshot's directory removed, whole; whether there was one. The caller holds the
    snapshot's lock (`locks.SNAPSHOT`)."""
    path = home(mailbox_id, root)
    if not path.exists():
        return False
    shutil.rmtree(path)
    return True
