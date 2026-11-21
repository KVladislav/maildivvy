"""The source of an import: a directory of whole message files, or a manifest of it.

Each file is one RFC 5322 message, already parsed out of whatever store held it. A run
reads the directory (sorted, recursive) or the manifest's rows into `Record`s, each read
whole once: its SHA-256, its size and the size Dovecot will give it over IMAP, its header
section, its Message-ID in the form the ledger stores, its received moment and its flags. A record that cannot be imported
carries the reason (`refused`); nothing here raises for one file.

`Seen` then judges each record against what the target already holds and what the run
has taken: the hashes of the target folder's imported names, listed once a run, and the
Message-IDs of the ledger's rows, which the caller fills.

⛔ A FILE IS READ THROUGH ONE DESCRIPTOR, OPENED WITHOUT FOLLOWING A SYMLINK. A symlink
is refused, never followed: the import renames or copies what it read, and a link would
make the file it reads another than the one it moves.

⛔ THE MESSAGE-ID IS READ AS THE PASS WILL READ IT. The pass stores the first occurrence
of Dovecot's `hdr.message-id`, unfolded, through `lib/messageid.py`; deduplicating by any
other spelling would let a message the ledger holds in through a difference of folding.
"""

import datetime
import hashlib
import os
import re
import stat
import time
from pathlib import Path
from typing import NamedTuple

from maildivvy.lib import headers, messageid

IMPORTED, DUPLICATE, REFUSED = "imported", "duplicate", "refused"
INCOMING, SENT = "incoming", "sent"

# Maildir's info letters a message may carry, in the order a name carries them (ASCII).
LETTERS = "DFRST"
DELETED = "T"            # flagged deleted: importing it to show it deleted imports nothing
ARCHIVE_FLAGS = "S"      # an archive's name carries `S` or nothing
DEFAULT_FLAGS = "S"      # a file no manifest row gives flags to is old mail, read
CHUNK = 1 << 20
HEAD_LIMIT = 1 << 20     # the header section is read up to this far
DAY = 86400              # how far past its file's mtime a Date header is still believed
# A header field's first line: a name of printable characters but the colon, then a colon.
FIELD = re.compile(rb"^[\x21-\x39\x3b-\x7e]+[ \t]*:")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_FIELDS = ("path", "sha256", "size", "received", "flags")


class SourceError(Exception):
    """The source or its manifest cannot be read at all: the run does not start."""


class Record(NamedTuple):
    """One file of the source, as read, or the reason it cannot be imported."""

    path: Path
    shown: str                     # the path as the result line names it
    sha256: str | None = None
    size: int | None = None
    vsize: int | None = None       # its size with every line end CR LF, the name's `W=`
    received: int | None = None    # the received moment, seconds since the epoch, UTC
    flags: str = ""                # Maildir letters, in name order
    message_id: str | None = None  # as the ledger stores it
    refused: str | None = None
    notes: tuple = ()
    gone: bool = False             # a manifest row whose file is not there
    found: os.stat_result | None = None  # the file as read, for the move to check


# --- the header section ------------------------------------------------------------------------


def header_section(head):
    """The header section's lines of a message's first bytes, or None for no header section.

    A message whose first line is not a header field (a blank line, an mbox `From ` line,
    anything else) has none. The section ends at the first empty line or the bytes read.
    """
    lines = head.split(b"\n")
    if not lines or not FIELD.match(lines[0]):
        return None
    section = []
    for line in lines:
        line = line[:-1] if line.endswith(b"\r") else line
        if not line:
            break
        section.append(line)
    return section


def first_value(section, name):
    """A field's first occurrence as Dovecot's `hdr.<name>` hands it to the pass, through
    `headers.first_occurrence`: its value's lines, unfolded; "" for no such field."""
    wanted = name.lower().encode()
    for index, line in enumerate(section):
        field, colon, value = line.partition(b":")
        if not colon or field.rstrip(b" \t").lower() != wanted or line[:1] in (b" ", b"\t"):
            continue
        lines = [value]
        for more in section[index + 1:]:
            if more[:1] not in (b" ", b"\t"):
                break
            lines.append(more)
        text = b"\n".join(lines).decode("utf-8", "replace")
        return headers.first_occurrence(text)
    return ""


# --- the received moment and the flags ---------------------------------------------------------


def iso_moment(text):
    """A manifest's `received`: ISO-8601 with `Z` or an offset, as seconds; None otherwise."""
    try:
        moment = datetime.datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        return None   # a moment with no zone is no moment
    return int(moment.timestamp())


def received_of(given, date, mtime, started=None):
    """`(seconds, refusal, notes)`: the manifest's `received`, else the Date header (a date
    with no zone is UTC), else the file's mtime. `started` is the run's start, now when
    not given.

    ⛔ NO MOMENT FROM THE FUTURE. The moment becomes the row's `received_at`, the file's
    mtime, which is the date a client sorts by, and the epoch in the file's name, all
    three for good: a message dated ahead of today would head every list, reach nobody by
    a top-up up to today, and reach every mailbox connected afterwards. A Date header is
    its sender's word, and old spam carries dates years ahead: one later than the file's
    mtime plus a day is passed over for the mtime, and the line says so (a day lets a
    zone slip through). A manifest's `received` is the operator's own word: one later than
    the run's start refuses the file, to be put right rather than guessed at.
    """
    if given:
        seconds = iso_moment(given)
        if seconds is None or seconds < 0:
            return None, f"received {given!r} cannot be read as a moment with a zone", ()
        if seconds > (time.time() if started is None else started):
            return None, f"received {given!r} is later than the start of this run", ()
        return seconds, None, ()
    when = headers.date_of(date) if date else None
    notes = ()
    if when is not None:
        try:
            seconds = int(when.timestamp())
        except (OverflowError, ValueError, OSError):
            seconds = -1
        if seconds > int(mtime) + DAY:
            notes = ("its Date is more than a day after the file's mtime: the mtime is taken",)
        elif seconds >= 0:
            return seconds, None, ()
    if mtime < 0:
        return None, "no Date to take, and an mtime before 1970: no received moment", ()
    return int(mtime), None, notes


def flags_of(given, stage):
    """`(flags, refusal, notes)` for one record.

    Incoming mail keeps `S` alone, since an archive's name carries nothing else, and its
    line says which letters it lost; a sent message keeps every letter.
    """
    letters = given if given is not None else DEFAULT_FLAGS
    if any(c not in LETTERS for c in letters):
        return "", f"flags {letters!r} are not Maildir's {', '.join(LETTERS)}", ()
    if DELETED in letters:
        return "", "flagged deleted (T): importing it would import nothing", ()
    kept = "".join(sorted(set(letters)))
    if stage == INCOMING:
        dropped = "".join(c for c in kept if c not in ARCHIVE_FLAGS)
        kept = "".join(c for c in kept if c in ARCHIVE_FLAGS)
        if dropped:
            return kept, None, (f"flags {', '.join(dropped)} dropped: an archive's name "
                                "carries S alone",)
    return kept, None, ()


# --- one file -----------------------------------------------------------------------------------


def bare_line_feeds(chunk, after_cr):
    """How many line feeds of `chunk` no carriage return precedes; `after_cr` says whether
    the bytes read before it ended in one, which a line end astride two chunks needs.

    A message's size over IMAP is its file's plus this count over the whole file, since
    Dovecot serves each such line feed as CR LF. A carriage return alone adds nothing.
    """
    count = chunk.count(b"\n") - chunk.count(b"\r\n")
    return count - 1 if after_cr and chunk[:1] == b"\n" else count


def read(path, shown, stage, expected=None, started=None):
    """One file as a `Record`. `expected` is its manifest row's (sha256, size, received,
    flags), each but the first two possibly None; `started` the run's start, which no
    manifest's `received` is later than."""
    sha, size, given_received, given_flags = expected or (None, None, None, None)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if expected is not None:
            return Record(path, shown, sha256=sha, size=size, gone=True,
                          refused="the manifest names it and it is not there")
        return Record(path, shown, refused="it went while the source was read")
    except OSError as err:
        if os.path.islink(path):
            return Record(path, shown, refused="a symlink, which is never followed")
        return Record(path, shown, refused=f"unreadable: {err.strerror or err}")
    try:
        found = os.fstat(fd)
        if not stat.S_ISREG(found.st_mode):
            return Record(path, shown, refused="not a regular file")
        if found.st_size == 0:
            return Record(path, shown, refused="empty")
        digest, head, length, bare, after_cr = hashlib.sha256(), b"", 0, 0, False
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            length += len(chunk)
            bare += bare_line_feeds(chunk, after_cr)
            after_cr = chunk.endswith(b"\r")
            if len(head) < HEAD_LIMIT and b"\n\n" not in head and b"\r\n\r\n" not in head:
                head += chunk[:HEAD_LIMIT - len(head)]
    except OSError as err:
        return Record(path, shown, refused=f"unreadable: {err.strerror or err}")
    finally:
        os.close(fd)
    record = Record(path, shown, sha256=digest.hexdigest(), size=length, vsize=length + bare,
                    found=found)
    if expected is not None and (sha != record.sha256 or size != length):
        return record._replace(refused=f"its hash or size is not the manifest's "
                                       f"({sha} {size})")
    section = header_section(head)
    if section is None:
        return record._replace(refused="no header section")
    received, refused, dated = received_of(given_received, first_value(section, "date"),
                                           found.st_mtime, started)
    if refused:
        return record._replace(refused=refused)
    flags, refused, notes = flags_of(given_flags, stage)
    if refused:
        return record._replace(refused=refused)
    return record._replace(received=received, flags=flags, notes=(*dated, *notes),
                           message_id=messageid.stored(first_value(section, "message-id") or None))


# --- the directory, or its manifest -------------------------------------------------------------


def walk(source, stage):
    """Every file under `source`, sorted by path, as records; a symlink or anything but a
    regular file or a directory is refused, never followed."""
    source = Path(source)

    def under(directory):
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as err:
            shown = os.path.relpath(directory, source)
            yield Record(Path(directory), shown, refused=f"unreadable: {err.strerror or err}")
            return
        for entry in entries:
            path = Path(entry.path)
            shown = path.relative_to(source).as_posix()
            if entry.is_symlink():
                yield Record(path, shown, refused="a symlink, which is never followed")
            elif entry.is_dir(follow_symlinks=False):
                yield from under(path)
            else:
                yield read(path, shown, stage)

    yield from under(source)


def manifest_rows(manifest):
    """`(line number, fields or refusal)` of a manifest: `path sha256 size received flags`,
    tab-separated, `#` comments and blank lines ignored, a first line naming the columns
    allowed. An empty `received` is read from the message, an empty `flags` is no flag."""
    try:
        text = Path(manifest).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as err:
        raise SourceError(f"the manifest {manifest} cannot be read: {err}") from None
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if number == 1 and [f.strip().lower() for f in fields] == list(MANIFEST_FIELDS):
            continue
        yield number, fields


def from_manifest(source, manifest, stage, started=None):
    """Each manifest row's file as a record, in the manifest's order."""
    source = Path(source).resolve()
    named = set()
    for number, fields in manifest_rows(manifest):
        shown = fields[0] if fields else ""
        if len(fields) != len(MANIFEST_FIELDS):
            yield Record(source / "-", shown or f"line {number}",
                         refused=f"manifest line {number} has {len(fields)} fields, not "
                                 f"{len(MANIFEST_FIELDS)}")
            continue
        relative, sha, size, received, flags = fields
        if not HEX64.match(sha) or not size.isdigit():
            yield Record(source / "-", shown, refused=f"manifest line {number}: "
                                                      "sha256 or size is malformed")
            continue
        path = Path(os.path.normpath(source / relative))
        if not relative or source not in path.parents:
            yield Record(path, shown, refused="outside the source")
            continue
        if path in named:
            yield Record(path, shown, refused=f"named twice in the manifest (line {number})")
            continue
        named.add(path)
        yield read(path, shown, stage, started=started,
                   expected=(sha, int(size), received.strip() or None, flags.strip()))


def records(source, stage, manifest=None, started=None):
    """The records of a run, from the directory or from its manifest; `started` is the
    run's start, now when not given."""
    if not Path(source).is_dir():
        raise SourceError(f"the source {source} is not a directory")
    if manifest is not None:
        return from_manifest(source, manifest, stage, time.time() if started is None else started)
    return walk(source, stage)


# --- deduplication ------------------------------------------------------------------------------


class Seen:
    """What the target holds and what the run has taken: the judge of every record.

    `held`: the hashes of the target folder's imported names, listed once a run; a file
    whose hash is there is in the store already, from an earlier run stopped before its
    line. `ids`: each stored Message-ID with what holds it, the ledger's rows (`add_ids`)
    and the run's own files.
    """

    def __init__(self, held=()):
        self.held = set(held)
        self.before = len(self.held)
        self.ids = {}
        self.hashes = {}

    def add_ids(self, rows):
        """`(stored Message-ID, message row id)` pairs of the ledger's rows."""
        for message_id, row_id in rows:
            if message_id:
                self.ids.setdefault(message_id, f"message {row_id}")

    def judge(self, record):
        """`(status, reason)`; None for a record to import."""
        if record.refused and not record.gone:
            return REFUSED, record.refused
        if record.sha256 in self.hashes:
            return DUPLICATE, f"the same bytes as {self.hashes[record.sha256]}"
        if record.sha256 in self.held:
            self.took(record)
            return IMPORTED, "in the store already: an earlier run took it"
        if record.gone:
            return REFUSED, record.refused
        if record.message_id and record.message_id in self.ids:
            return DUPLICATE, f"the Message-ID of {self.ids[record.message_id]}"
        return None

    def took(self, record):
        """The record is in the target now: what comes after it is judged against it."""
        self.hashes.setdefault(record.sha256, record.shown)
        if record.message_id:
            self.ids.setdefault(record.message_id, record.shown)


# --- `--scan`: clamd, never rspamd --------------------------------------------------------------


class Unavailable(Exception):
    """clamd cannot be asked: the run stops, to be run again once it answers."""


class Scanner:
    """Each record asked of clamd through `lib/scan.py`, as the delivery filter asks.

    Infected is refused. Over the scanner's limit, or cut short at one of its own limits,
    nobody looked: imported, and its line says so. A scan the daemon failed on while it
    still answers PING is refused, as nothing the daemon failed on is sent; no
    answer at all, or no PING, is clamd unavailable, which stops the run. Never rspamd: a
    verdict on years-old mail means nothing.
    """

    def __init__(self, scan=None, limit=None):
        from maildivvy.lib import scan as scanning
        self.scanning = scanning
        self.scan = scan or scanning.scan_virus
        self.limit = scanning.size_limit() if limit is None else limit

    def judge(self, record):
        """`(verdict or None, record)`; the record gains a note when nobody looked."""
        if record.size > self.limit:
            return None, record._replace(notes=(*record.notes, (
                f"not scanned: {record.size} bytes is over the {self.limit}-byte scan limit")))
        try:
            with open(record.path, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as f:
                body = f.read()
        except OSError as err:
            return (REFUSED, f"unreadable: {err.strerror or err}"), record
        if hashlib.sha256(body).hexdigest() != record.sha256:
            return (REFUSED, "it changed after it was read"), record
        found = self.scan(body, max_bytes=self.limit)
        if found.verdict == self.scanning.CLEAN:
            return None, record
        if found.verdict == self.scanning.INFECTED:
            return (REFUSED, f"infected: {found.detail}"), record
        if found.verdict == self.scanning.UNSCANNED and found.failed:
            return (REFUSED, f"the scanner failed on it: {found.detail}"), record
        if found.verdict == self.scanning.UNSCANNED:
            return None, record._replace(notes=(*record.notes, f"not scanned: {found.detail}"))
        raise Unavailable(f"clamd is unavailable: {found.detail}")
