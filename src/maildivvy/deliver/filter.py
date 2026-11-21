"""The delivery filter: runs BEFORE Dovecot's delivery agent, on bytes that are not a file yet.

    maildivvy-deliver --domain <label> [--spam-threshold 8.00] [--held-since <when>]

⛔ THE VERDICT HEADERS GO INTO THE BYTES BEFORE THE DELIVERY AGENT STORES THEM.
Once Dovecot has stored the file, writing a header into it corrupts
every holder's copy at once and disagrees with the size Dovecot indexed. The bytes are
final from here on.

⛔ NOTHING IS REJECTED: THE FILTER FILES. The mail was accepted twice
before it was scored, first by the provider and then by the fetch, so a rejection here
bounces nothing useful and loses the message.

⛔ ONLY THE DOMAIN'S ARCHIVE RECEIVES: a withheld message into the
archive's quarantine folder, the report that replaces it into the archive's INBOX. The
fan-out to people is a later, separate step. The delivery agent's non-zero exit code is
returned unchanged, which is what the fetch runner reads as "our delivery refused this
message" - with two exceptions: the agent's own 75, and a failure of the store itself.
Measured on the test VM on 2026-09-22, dovecot-lda 2.4.2 exits 75 on a full
store, on a directory it may not write and on a folder path that is not a directory,
stores nothing and falls back to nothing. Passed through, that 75 read as the antivirus
hold below; it is returned as 74 (`EX_IOERR`), a refusal of this message.

⛔ A STORE THAT CANNOT TAKE MAIL IS NOT A REFUSAL OF THIS MESSAGE. Read as one,
it started the bounded retry's hour, and a store full for longer than that skipped each
mailbox's next message: recorded as retrieved, never stored, deleted by the provider
after the window. So whenever the agent fails, or does not finish, a probe asks whether
the store could take any message now: room and inodes on the filesystems the save
writes to, those directories writable, and Dovecot answering a trivial `doveadm` call.
If it could not, the filter exits 73 (`EX_CANTCREAT`), which the fetch runner reads as a
hold of collection with a cause of its own; the message stays at the provider and the
stuck hour does not start. If it could, the failure is this message's, as before. The
agent's own 73 is returned as 74 too, so 73 from the filter means the store and nothing
else.

⛔ A FAULT OF THE FILTER'S OWN IS NOT A REFUSAL OF THIS MESSAGE UNTIL A MESSAGE OF ITS OWN
GOES THROUGH. An exception nothing here expected - a clamd.conf size it cannot
read, a delivery agent that is not there - left the filter with exit 1, which the fetch
read as this message's: after the stuck hour one message never stored was skipped in
every mailbox, and the next episode froze each of them. So the filter then puts CANNED
through the same path up to its storage (both scanners, the marks, the store's probe, the
delivery agent there to run). When that fails too the fault is the machine's: the store's
own exit 73, which holds collection, keeps the mail at the provider and is health's FAIL,
with the fault in its line. Only when it goes through is the fault this message's,
`EX_SOFTWARE`. A fault before the message was read is the machine's at once.

⛔ THE AGENT RUNS WITH `-e`. Without it the agent answers a rejection - a
full quota, measured - by mailing a bounce itself and exiting 0, and mpop then records
a message nobody stored. With it a rejection is exit 77 and the message stays at the
provider.

⛔ WHILE THE ANTIVIRUS IS UNREACHABLE THE MESSAGE WAITS AT THE PROVIDER. The
filter exits 75 (`EX_TEMPFAIL`), which mpop names in a line of its own and the fetch
runner tells apart from every refusal; the message is not recorded as retrieved and the
session stops. Nothing else in this program exits 75. Health goes FAIL from the first
such refusal, and the runner records `external_mailbox.held_since`, which it renders
back here as `--held-since`: once the hold has lasted longer than the bound (an hour by
default) the message is delivered marked *unavailable* instead, as it was before, so a
long outage delays mail by the bound rather than stopping it.

⛔ END-OF-FILE IS NOT PROOF OF A WHOLE MESSAGE. When the provider's
connection ends inside a body, mpop 1.4.23 exits without closing the pipe it was writing
into, and this program reads end-of-file on half a message. Before it stores anything it
asks whether mpop still waits for it (`lib/retrieval.py`); if not, it stores nothing and
the next run brings the message whole, since mpop recorded nothing.

⛔ THE REPORT THIS MACHINE WRITES IS NEITHER SCANNED NOR GIVEN A HEADER BLOCK OF OURS.
Scoring our own words tells us nothing and costs something specific: a
message this machine writes has no authenticated path behind it and scores like mail
from nowhere, while a domain may set its threshold as low as 1.00 - and a scanned
report is a report a withholding domain files away from everybody, when the report is
the only thing that says a message was withheld at all. The fan-out's half of this rule
is that an absent mark reads as not spam; neither half is safe alone.
"""

import argparse
import email
import email.message
import email.policy
import hashlib
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from maildivvy.deliver import marks, report
from maildivvy.lib import doveadm, headers, retrieval, scan, store

LDA = "/usr/lib/dovecot/dovecot-lda"
LDA_TIMEOUT = 300  # seconds

EX_TEMPFAIL = 75  # sysexits: the one exit that means "the antivirus is unreachable"
EX_USAGE = 64
EX_UNAVAILABLE = 69  # Dovecot would not make the quarantine folder: nothing is filed
EX_IOERR = 74  # the delivery agent's own temporary failure, which is never the hold
EX_CANTCREAT = 73  # the store cannot take any message now: collection holds
EX_SOFTWARE = 70  # a fault of the filter's own on this message, and on no other

# The probe: a filesystem with less than this beyond the message is full.
STORE_ROOM = 1 << 20  # bytes
PROBE_TIMEOUT = 30  # seconds for the trivial doveadm call
# the start of the line that says why; the fetch runner copies it into its journal
STORE_SAID = "maildivvy-deliver: the archive's store cannot take mail"

DEFAULT_SPAM_THRESHOLD = 8.00  # `domain.spam_threshold`'s own default; the fetch
# runner renders the domain's value onto the delivery line, so this is
# only what a hand-run of the filter gets.
DEFAULT_HOLD_BOUND = 3600  # seconds
# the message a fault of the filter's own is tried on, to tell the machine's from
# the message's. It is scanned and marked, and never stored.
CANNED = (b"From: maildivvy-deliver <postmaster@maildivvy.invalid>\r\n"
          b"To: archive@maildivvy.invalid\r\n"
          b"Subject: the delivery filter's own check\r\n"
          b"Message-ID: <filter-check@maildivvy.invalid>\r\n"
          b"Content-Type: text/plain; charset=us-ascii\r\n"
          b"\r\nA message the delivery filter puts through its own path after a fault.\r\n")
FAULT_MAX = 200  # characters of an exception's words in a line of ours


def parse_args(argv):
    parser = argparse.ArgumentParser(description="scan and mark a message, then file it")
    parser.add_argument("--domain", required=True, help="the receiving domain's label")
    parser.add_argument("--spam-threshold", type=float, default=DEFAULT_SPAM_THRESHOLD,
                        help="score at or above which this domain treats a message as spam")
    parser.add_argument("--held-since", default=None,
                        help="when this mailbox's antivirus hold began")
    parser.add_argument("--hold-bound-seconds", type=float, default=DEFAULT_HOLD_BOUND,
                        help="how long a hold may last before mail is delivered unavailable")
    parser.add_argument("--retrieval", action="store_true",
                        help="started by the fetch for a retrieval: its pipe must be there")
    parser.add_argument("--envelope-sender", "-f", default=None)
    parser.add_argument("--lda", default=LDA)
    parser.add_argument("--clamd-socket", default=str(scan.CLAMD_SOCKET))
    parser.add_argument("--rspamd-socket", default=str(scan.RSPAMD_SOCKET))
    return parser.parse_args(argv)


def held_long_enough(held_since, bound, now=None):
    """Has an antivirus hold outlasted its bound? A hold that has not begun has not."""
    if held_since is None:
        return False
    began = datetime.fromisoformat(held_since)
    if began.tzinfo is None:  # a naive value is this machine's own clock
        began = began.astimezone()
    return (now or datetime.now(timezone.utc)) - began > timedelta(seconds=float(bound))


def parsed(raw):
    """The message, for the report to quote; an empty one if it will not parse at all."""
    try:
        return email.message_from_bytes(raw, policy=email.policy.default)
    except Exception:  # noqa: BLE001 - the report is worth more than any parse
        return email.message.EmailMessage()


def run_lda(lda, login, body, folder=None, envelope_sender=None):
    """Hand the bytes to Dovecot's delivery agent, past the archive's read-only ACL.

    The archive is read-only to its own login (`owner lookup read write-seen`), which
    binds the delivery agent too, so the product's own writes run with the ACL plugin
    off - the same door the doveadm wrapper uses.
    """
    argv = [lda, "-e", *doveadm.ACL_OFF, "-d", login]
    if envelope_sender:
        argv += ["-f", envelope_sender]
    if folder:
        argv += ["-m", folder]
    return subprocess.run(argv, input=body, capture_output=True, timeout=LDA_TIMEOUT)


def existing(path):
    """The path, or the nearest directory above it that exists: what a save into it
    would have to create its way down from."""
    path = Path(path)
    while not path.exists() and path != path.parent:
        path = path.parent
    return path


def store_failure(domain, folder, size, root=store.STORE_ROOT, index_root=store.INDEX_ROOT):
    """Why the archive's store cannot take a message of `size` bytes now, or None.

    ⛔ Asked only after the agent failed: what it says decides whether the
    failure was the store's or this message's. It never stores, moves or removes
    anything. The paths are where the save writes - the folder's and INBOX's `tmp/`, where
    Dovecot writes a message before renaming it into `new/`, and the mailbox's index tree.
    """
    home = store.archive_home(domain, root)
    paths = [store.maildir(home) / "tmp", store.index_paths(domain, store.ARCHIVE, index_root)[0]]
    if folder:
        paths.insert(0, store.maildir(home, folder) / "tmp")
    for path in paths:
        where = existing(path)
        try:
            fs = os.statvfs(where)
        except OSError as err:
            return f"{where}: {err.strerror}"
        if fs.f_flag & os.ST_RDONLY:
            return f"{where} is on a filesystem mounted read-only"
        free = fs.f_bavail * fs.f_frsize
        if free < size + STORE_ROOM:
            return f"{where} has {free} bytes free"
        if fs.f_files and not fs.f_favail:
            return f"{where} has no free inode"
        if not where.is_dir():
            return f"{where} is not a directory"
        if not os.access(where, os.W_OK | os.X_OK):
            return f"{where} is not writable by the mail owner"
    try:
        doveadm.run(("mailbox", "status"), f"{store.ARCHIVE}@{domain}", "messages", "INBOX",
                    timeout=PROBE_TIMEOUT)
    except doveadm.DoveadmError as err:
        return f"Dovecot did not answer: {err}"
    return None


def holding(held):
    """The store's own exit, and the line that says why."""
    sys.stderr.write(f"{STORE_SAID} ({held}); the message stays at the provider and "
                     "collection holds\n")
    return EX_CANTCREAT


def deliver_one(what, lda, archive, body, probe, folder=None, envelope_sender=None):
    """Hand one message to the agent: 0, or the exit code for its failure.

    A failure, or no answer within the bound, asks the probe: the store's own 73 when the
    store cannot take mail, and otherwise a refusal of this message. ⛔ The agent's 75 is
    its own temporary failure and never the antivirus hold, and its 73, if it ever gave
    one, is never the store's: both are returned as 74, and so is a timeout.
    """
    try:
        done = run_lda(lda, archive, body, folder=folder, envelope_sender=envelope_sender)
    except subprocess.TimeoutExpired:
        code, said = EX_IOERR, f"no answer in {LDA_TIMEOUT} s"
    else:
        if done.returncode == 0:
            return 0
        code = EX_IOERR if done.returncode in (EX_TEMPFAIL, EX_CANTCREAT) else done.returncode
        said = f"exit {done.returncode}: {done.stderr.decode('utf-8', 'replace').strip()}"
    sys.stderr.write(f"maildivvy-deliver: the delivery agent refused the {what} ({said})\n")
    held = probe()
    return code if held is None else holding(held)


def withheld_id_of(raw):
    """The id that links a withheld message to its report: the same on every retrieval.

    The report is saved after the quarantine copy, and when its
    save fails the message stays at the provider and comes again. A fresh random id then
    stored a second copy each time. This one is a digest of the message without its
    Received fields - mpop adds one with the time to every retrieval - so a retry finds
    the copy it already stored. Two retrievals that differ only in their Received
    fields are one message.
    """
    head, separator, rest = marks.split_header_block(raw)
    kept, received = [], False
    for line in head.splitlines(keepends=True):
        if line[:1] not in (b" ", b"\t"):
            received = line.lower().startswith(b"received:")
        if not received:
            kept.append(line)
    return hashlib.sha256(b"".join(kept) + separator + rest).hexdigest()[:32]


def already_withheld(archive, withheld_id):
    """Does the archive's quarantine already hold the copy with this id?"""
    records = doveadm.fetch(archive, store.QUARANTINE, ["uid", headers.WITHHELD_FIELD], "all")
    return any(headers.first_line(record.get(headers.WITHHELD_FIELD)) == withheld_id
               for record in records)


def abandoned(watched):
    """True when the retrieval that piped this message in has gone without finishing it.

    ⛔ Asked before anything is stored: mpop 1.4.23 leaves a message
    it could not finish reading by exiting, so end-of-file on stdin is also half a message.
    Nothing is stored then, and nothing is lost: mpop recorded nothing, and the next run
    brings the message whole.
    """
    if retrieval.waiting(watched):
        return False
    sys.stderr.write("maildivvy-deliver: the retrieval ended before this message did; "
                     "nothing was stored, and the next fetch brings it whole\n")
    return True


def named(err):
    """An exception's kind and words, on one line, cut to FAULT_MAX."""
    return " ".join(f"{type(err).__name__}: {err}".split())[:FAULT_MAX]


def marked_up(raw, virus, args):
    """(the bytes to store, the report or None, the withheld id or None): the spam scan, the
    marks and the report, on the antivirus's verdict."""
    archive = f"{store.ARCHIVE}@{args.domain}"
    score = scan.scan_spam(raw, path=args.rspamd_socket, headers={"Deliver-To": archive})
    spam = marks.is_spam(score.score, args.spam_threshold)
    marked, mark_detail = (marks.mark_spam(raw, score.score, args.spam_threshold)
                           if spam else (raw, None))

    # The filter mints the link between a withheld message and its report and writes it
    # into both before either reaches the delivery agent: the agent returns no archive
    # UID, so there is nothing else to correlate them by. The report
    # quotes the marked bytes, so a message that is both infected and spam is named in
    # its report with the mark its held copy carries.
    withheld_id = withheld_id_of(raw) if virus.withheld else None
    text = report.compose(virus.verdict, parsed(marked), withheld_id, args.domain,
                          failed=virus.failed) if withheld_id else None

    body = marks.insert_headers(marked, marks.verdict_headers(
        verdict=virus.verdict, detail=virus.detail, score=score.score, action=score.action,
        spam=spam, score_detail=score.detail, mark_detail=mark_detail, withheld_id=withheld_id))
    return body, text, withheld_id


def broken(args):
    """Why no message could be filed now, or None: CANNED through the message's path up to
    its storage, which it never reaches."""
    try:
        marked_up(CANNED, scan.scan_virus(CANNED, path=args.clamd_socket), args)
        held = store_failure(args.domain, None, len(CANNED))
    except Exception as err:  # noqa: BLE001 - what fails on any message is the machine's
        return named(err)
    if held is not None:
        return held
    if not os.access(args.lda, os.X_OK):
        return f"the delivery agent {args.lda} cannot be run"
    return None


def fault(args, err):
    """The exit for an exception nothing here expected: the machine's hold when a
    message of the filter's own fails too, and this message's refusal when it does not."""
    said = named(err)
    sys.stderr.write(f"maildivvy-deliver: the filter failed on this message ({said})\n")
    why = broken(args)
    if why is None:
        sys.stderr.write("maildivvy-deliver: a message of the filter's own goes through, so "
                         "the fault is this message's\n")
        return EX_SOFTWARE
    return holding(f"the delivery filter fails on any message: {said}; its own check: {why}")


def main(argv=None):
    args = parse_args(argv)
    try:
        # before anything else is started, so no child of ours holds the write end either
        watched = retrieval.watch(expected=args.retrieval)
        raw = sys.stdin.buffer.read()
    except Exception as err:  # noqa: BLE001 - no message was read: the fault is the machine's
        return holding(f"the delivery filter failed before reading the message: {named(err)}")
    try:
        return filed(args, watched, raw)
    except Exception as err:  # noqa: BLE001 - `fault` tells the machine's from the message's
        return fault(args, err)


def filed(args, watched, raw):
    """The message scanned, marked and stored: 0, or the exit that says why not."""
    archive = f"{store.ARCHIVE}@{args.domain}"

    virus = scan.scan_virus(raw, path=args.clamd_socket)
    if virus.verdict == scan.UNAVAILABLE:
        try:
            past_the_bound = held_long_enough(args.held_since, args.hold_bound_seconds)
        except ValueError as err:
            sys.stderr.write(f"maildivvy-deliver: --held-since {args.held_since!r}: {err}\n")
            return EX_USAGE
        if not past_the_bound:
            # ⛔ The one exit that means this, and the message stays at the provider.
            sys.stderr.write(f"maildivvy-deliver: the antivirus is unreachable "
                             f"({virus.detail}); holding this message at the provider\n")
            return EX_TEMPFAIL
        sys.stderr.write("maildivvy-deliver: the antivirus has been unreachable since "
                         f"{args.held_since}, past the {args.hold_bound_seconds:.0f}-second "
                         "bound; delivering this message marked unavailable\n")

    body, text, withheld_id = marked_up(raw, virus, args)

    # the last moment before the first write: both scanners have answered by now
    if abandoned(watched):
        return EX_IOERR

    folder = store.QUARANTINE if virus.withheld else None

    def probe():  # the store, or this message?
        return store_failure(args.domain, folder, len(body) + len(text or b""))

    stored = False
    if folder:
        # Made through Dovecot, with the archive's own ACL: an agent handed a folder
        # that does not exist files the message in INBOX instead, where the quarantine
        # would reach every reader.
        try:
            doveadm.create_folder(archive, folder)
            # a retry after the report's save failed finds its own copy here
            stored = already_withheld(archive, withheld_id)
        except doveadm.DoveadmError as err:
            # Nothing is delivered rather than delivered to the wrong folder; the
            # message stays at the provider for the next run, as any other refusal.
            sys.stderr.write(f"maildivvy-deliver: no {folder} folder for {archive}: {err}\n")
            held = probe()
            return EX_UNAVAILABLE if held is None else holding(held)

    if not stored:
        code = deliver_one("message", args.lda, archive, body, probe, folder=folder,
                           envelope_sender=args.envelope_sender)
        if code:
            return code

    if text is not None:
        # ⛔ No header block and no scan on this path, and adding them for symmetry with
        # the message above is the specific mistake this comment exists to stop.
        return deliver_one("report", args.lda, archive, text, probe)
    return 0
