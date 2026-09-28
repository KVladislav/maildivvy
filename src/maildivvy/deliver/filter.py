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
message" - with one exception: the agent's own 75. Measured on the test VM (review
2026-09-22), dovecot-lda 2.4.2 exits 75 on a full
store, on a directory it may not write and on a folder path that is not a directory,
stores nothing and falls back to nothing. Passed through, that 75 read as the antivirus
hold below; it is returned as 74 (`EX_IOERR`), a refusal of this message, which is what
it is to the bounded retry.

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
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from maildivvy.deliver import marks, report
from maildivvy.lib import doveadm, retrieval, scan, store

LDA = "/usr/lib/dovecot/dovecot-lda"
LDA_TIMEOUT = 300  # seconds

EX_TEMPFAIL = 75  # sysexits: the one exit that means "the antivirus is unreachable"
EX_USAGE = 64
EX_UNAVAILABLE = 69  # Dovecot would not make the quarantine folder: nothing is filed
EX_IOERR = 74  # the delivery agent's own temporary failure, which is never the hold
WITHHELD_FIELD = f"hdr.{report.WITHHELD_HEADER.lower()}"

DEFAULT_SPAM_THRESHOLD = 8.00  # `domain.spam_threshold`'s own default; the fetch
# runner renders the domain's value onto the delivery line, so this is
# only what a hand-run of the filter gets.
DEFAULT_HOLD_BOUND = 3600  # seconds


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


def refused(what, done):
    """The exit code for a delivery the agent refused, and a line saying so.

    ⛔ The agent's 75 is its own temporary failure and never the antivirus hold.
    """
    sys.stderr.write(f"maildivvy-deliver: the delivery agent refused the {what} "
                     f"(exit {done.returncode}): "
                     f"{done.stderr.decode('utf-8', 'replace').strip()}\n")
    return EX_IOERR if done.returncode == EX_TEMPFAIL else done.returncode


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
    records = doveadm.fetch(archive, store.QUARANTINE, ["uid", WITHHELD_FIELD], "all")
    return any((record.get(WITHHELD_FIELD) or "").split("\n")[0].strip() == withheld_id
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


def main(argv=None):
    args = parse_args(argv)
    # before anything else is started, so no child of ours holds the write end either
    watched = retrieval.watch(expected=args.retrieval)
    raw = sys.stdin.buffer.read()
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
    text = report.compose(virus.verdict, parsed(marked), withheld_id, args.domain) \
        if withheld_id else None

    body = marks.insert_headers(marked, marks.verdict_headers(
        verdict=virus.verdict, detail=virus.detail, score=score.score, action=score.action,
        spam=spam, score_detail=score.detail, mark_detail=mark_detail, withheld_id=withheld_id))

    # the last moment before the first write: both scanners have answered by now
    if abandoned(watched):
        return EX_IOERR

    folder = store.QUARANTINE if virus.withheld else None
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
            return EX_UNAVAILABLE

    if not stored:
        done = run_lda(args.lda, archive, body, folder=folder,
                       envelope_sender=args.envelope_sender)
        if done.returncode != 0:
            return refused("message", done)

    if text is not None:
        # ⛔ No header block and no scan on this path, and adding them for symmetry with
        # the message above is the specific mistake this comment exists to stop.
        done = run_lda(args.lda, archive, text)
        if done.returncode != 0:
            return refused("report", done)
    return 0
