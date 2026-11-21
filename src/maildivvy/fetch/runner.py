"""The fetch runner: one mpop per external mailbox, and the bounded retry around it.

    maildivvy-fetch [--only <id>] [--auth-only [--start-mark]] [--trace]
    maildivvy-fetch --snapshot [--only <id>] [--slice-seconds <n>]

For every external mailbox with a domain in front of it and not deactivated: take the
try-lock, render the client's configuration from the row, run mpop under our own
timeout, and record one of four outcomes with a structured cause. An IMAP row
is collected by our own read-only client instead of mpop (`imap_collect.py`), under the
same lock, the same timeout and the same bounded retry. Its password check is a login
and EXAMINE INBOX by the same client, and the check an activation runs (`--start-mark`)
also sets the row's mark, the one fetch column a check ever writes.

⛔ ZERO EXTERNAL MAILBOXES IS A SUCCESS. A machine with nothing to collect
must not show a failed unit by design; the machine this replaces sat permanently in
`systemctl --failed`.

⛔ BUT A RUN IN WHICH ANY MAILBOX FAILED EXITS NON-ZERO. The
loop that threw each row's outcome away is why 21 scheduled runs delivered nothing and
every one of them reported success: the status went into a column nobody watched while
the exit code, the part systemd reads, was a constant 0. `error` and `auth_failed` both
mean it - a fix counting only `error` survived every test of the suite that found this.

⛔ THE BOUNDED RETRY. A mailbox stopped on one
message - the provider refusing it on every RETR, or our own delivery refusing it every
time - used to stop there on every run for ever, with everything behind it never
arriving. The clock starts at the first failure that NAMES A MESSAGE; after an hour the
message is found by a listing-only session and skipped, written to the database first
and to mpop's own state file second; a second episode with no successful run between
freezes the mailbox for a person. An IMAP run has already named its message by UID: it
is skipped by moving the row's mark past it, in the one transaction with the journal row,
with no listing session and no state file.

⛔ AN IMAP MAILBOX'S STUCK HOUR IS AN HOUR OF RUNS THAT REACHED THE MESSAGE. Over
IMAP a connection that fails over a message is that message's failure, and a connection
fails for reasons that are not the message's. Counted by the clock from the first
failure, as a POP3 refusal is, a message was skipped after two dropped connections with
an outage, a stopped timer or a backup's pause between them. So for an IMAP row the
clock runs only between runs that stopped on the message: a run that ended any other way
moves the episode's start on by the time since the run before it, as a hold does; a gap
longer than one run's bound (`--timeout`) counts as that bound, since nothing ran in the
rest of it; and nothing is skipped under IMAP_STUCK_RUNS runs stopped on the message,
whatever the clock says. A POP3 mailbox's hour is unchanged: there a message-level
failure is the server's refusal of that message in words.

⛔ THE ANTIVIRUS HOLD IS NOT A STUCK MESSAGE. The delivery filter exits
EX_TEMPFAIL while ClamAV is unreachable, mpop leaves the message unretrieved, and the
runner records `held_since` instead of counting the run toward the stuck hour. It
renders that time back onto the delivery line, which is how the filter learns that the
hold has outlasted its bound and the message must be delivered marked *unavailable*.

⛔ NOR IS A STORE THAT CANNOT TAKE MAIL. The filter exits 73 when its probe finds
the archive's store full, read-only or Dovecot not answering; the runner records the
cause `store`, and the stuck hour is paused as for the antivirus hold. No bound ends it:
there is no way to store the message anyway, and health's FAIL is what makes it seen.

⛔ A RUN OF ONE NAMED MAILBOX THAT COLLECTED NOTHING IS NOT A SUCCESS. A refetch reads
this exit code: `--only` naming a row the fetch does not collect, or a row gone by the time
its lock was taken, exits 1, and a lock held by another run exits 75 (EX_TEMPFAIL), so the
request says to ask again instead of journaling "collected". A timed run that skips a
locked mailbox is still a success: another run is collecting it.

⛔ ONE IMAP MAILBOX'S FAULT IS ITS OWN. Our client starts the delivery filter itself, so a
filter that cannot be started, or a database error on the way, would end the whole run
and leave every mailbox after it uncollected; it is recorded as that mailbox's
`error`/`transient` instead, and the run goes on.

⛔ A SNAPSHOT IS ITS OWN RUN, `--snapshot`, from its own unit and timer: one slice
of each IMAP mailbox's snapshot under way or asked for, under the snapshot's own lock and
never the fetch's, so a copy of many gigabytes holds up no collection. The run takes the
snapshot least recently advanced first, and starts no slice that could end after
SNAPSHOT_RUN_SECONDS, inside its unit's own timeout: a run stopped mid-slice would leave
that snapshot `running` and the unit failed. Its exit is 1 only when a snapshot failed;
one paused or still going is the next slice's to go on with.

⛔ A TIMED RUN TAKES THE LEAST RECENTLY COLLECTED MAILBOX FIRST, AND STARTS NONE THAT COULD
END PAST FETCH_RUN_SECONDS, as the snapshot's run does. Taken by id, four
mailboxes at their 900 s bound had the unit killed and the next run start at the first
again, so the mailboxes with the highest ids could wait for good.

⛔ A TRACE IS A SECRET. `mpop --debug` writes every command verbatim,
the one carrying the credential included, and whole message bodies. A trace is written
0600, the listing session's conversation is never written at all, and nothing but one
identifier or mpop's own `mpop:` lines leaves it. An IMAP row has no trace at all: the
client's debug output carries the password, so `--trace` refuses to collect it.
"""

import argparse
import contextlib
import datetime
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from maildivvy.fetch import imap_collect, locks, outcome, render, snapshot
from maildivvy.fetch import state as state_file
from maildivvy.deliver import filter as deliver_filter
from maildivvy.lib import config, db, retrieval, scan

CONSUMER = "pipeline"
ACTOR = "maildivvy-fetch"  # the journal's actor for everything this writes

DEFAULT_MPOP = "/usr/local/bin/mpop"
DEFAULT_TIMEOUT = 900       # seconds
DEFAULT_STUCK_AFTER = 3600  # seconds on one message before it is skipped
# the runs that must have stopped on one message before an IMAP mailbox skips it,
# whatever the clock says. The timer runs every three minutes, so an hour of them is
# about twenty.
IMAP_STUCK_RUNS = 10
LISTING_TIMEOUT = 300       # the listing session's own bound
# Seconds from SIGTERM to SIGKILL at the timeout (`stop`): the delivery filter's own
# bounds on the message in hand - two scans and a store - and a margin for mpop to write
# its state. ⛔ Not a round number below them: mpop waits for the filter, so a grace
# shorter than a slow delivery kills mpop in that wait and loses the whole run's state.
STOP_GRACE = scan.CLAMD_BOUND + scan.RSPAMD_TIMEOUT + deliver_filter.LDA_TIMEOUT + 30

EX_USAGE = 64
EX_TEMPFAIL = 75   # `--only`'s mailbox was locked by another run: nothing collected
EX_CONFIG = 78
BUSY = "busy"      # what `run_one` returns for a mailbox another run holds
# no slice starts that could end later than this after its run began; the snapshot
# unit's TimeoutStartSec (the role's `maildivvy_snapshot_run_timeout`) is a margin above it
SNAPSHOT_RUN_SECONDS = 3300
# no mailbox's collection starts that could end later than this after the run
# began - its timeout and the delivery in hand after it; the fetch unit's TimeoutStartSec
# (the role's `maildivvy_fetch_run_timeout`) is a margin above it
FETCH_RUN_SECONDS = 3300

COLUMNS = """
    SELECT e.id, e.pop3_login, e.address, e.pop3_host, e.pop3_port,
           d.label, e.delete_window_days, e.address_canonical,
           d.spam_threshold, e.held_since, e.keep_at_provider, e.pop3_cert_fingerprint,
           e.protocol, e.imap_uidvalidity, e.imap_last_uid
      FROM external_mailbox e
      JOIN domain d ON d.external_mailbox_id = e.id
"""
# The rows an ordinary run collects: a domain in front of it and not deactivated.
COLLECTED = " WHERE e.state <> 'deactivated'"
# ⛔ The least recently collected first: a run that stops for want of time leaves
# the rest first in line for the next, instead of starting at the lowest id again.
TO_FETCH = COLUMNS + COLLECTED + " ORDER BY e.last_fetch_at NULLS FIRST, e.id"
# ⛔ The re-read under a fetch's lock keeps the listing's predicate. A run
# over many mailboxes is long enough for a Disable to land inside it; re-reading with
# TO_TEST below fetched that mailbox once more, its provider-side deletions included.
TO_FETCH_ONE = COLUMNS + COLLECTED + " AND e.id = %s"
# ⛔ The password check selects BY ID WITH NO STATE PREDICATE. By the
# order of a new mailbox - saved disabled, tested, then enabled - every row a check is
# ever about is `deactivated`, which is exactly what TO_FETCH excludes. Filtering its
# result by id would do nothing, exit 0, write no status, and let the request report
# success having measured nothing.
TO_TEST = COLUMNS + " WHERE e.id = %s"
# the IMAP rows with a snapshot under way or asked for, collected as the fetch
# collects them; the one row is read again under the snapshot's lock, with the same predicate.
SNAPSHOTS = (COLUMNS + COLLECTED + f" AND e.protocol = '{render.IMAP}' AND " + snapshot.WANTED)
TO_SNAPSHOT = SNAPSHOTS + " ORDER BY e.id"
TO_SNAPSHOT_ONE = SNAPSHOTS + " AND e.id = %s"


def rows_to_fetch(cursor):
    cursor.execute(TO_FETCH)
    return [render.Mailbox(*row) for row in cursor.fetchall()]


def one_row(cursor, query, mailbox_id):
    cursor.execute(query, (mailbox_id,))
    row = cursor.fetchone()
    return render.Mailbox(*row) if row else None


def row_to_fetch(cursor, mailbox_id):
    """The row if a fetch still collects it, None if it is gone, unmapped or deactivated."""
    return one_row(cursor, TO_FETCH_ONE, mailbox_id)


def row_to_test(cursor, mailbox_id):
    """The row whatever its state: the password check is about deactivated rows."""
    return one_row(cursor, TO_TEST, mailbox_id)


# --- what goes on the row and in the journal --------------------------------------------------


# A stuck episode paused over the time since the row's last run: its start moves on by
# that time, so the run counts nothing toward the stuck hour. The right-hand
# `last_fetch_at` is the row's old value, and an episode not running stays NULL.
PAUSED = "stuck_since = stuck_since + (now() - coalesce(last_fetch_at, now()))"
# An IMAP row's episode at a run that stopped on its message: the time since the
# row's last run counts up to one run's bound, and the rest of a longer gap moves the
# start on, since no run reached the message in it. An episode not running starts now.
IMAP_COUNTED = ("stuck_since = coalesce(stuck_since + greatest(now() - coalesce(last_fetch_at, "
                "now()) - make_interval(secs => %s), interval '0'), now())")


def set_status(cursor, mailbox, result):
    """A run's outcome that is no message's failure. On an IMAP row it also pauses a stuck
    episode: the run did not reach the message, or the server did not refuse it."""
    paused = f", {PAUSED}" if mailbox.protocol == render.IMAP else ""
    cursor.execute(
        "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
        f"last_fetch_cause = %s, last_fetch_detail = %s{paused} WHERE id = %s",
        (result.status, result.cause, result.detail, mailbox.id))


def append_detail(cursor, mailbox, clause, cause=None):
    """Add to the detail what happened after the outcome was already recorded."""
    cursor.execute(
        "UPDATE external_mailbox SET last_fetch_detail = "
        "left(coalesce(last_fetch_detail || '; ', '') || %s, %s), "
        "last_fetch_cause = coalesce(%s, last_fetch_cause) WHERE id = %s",
        (clause, outcome.DETAIL_MAX, cause, mailbox.id))


def as_text(value):
    """`json.dumps` refuses a datetime, and a journal detail is timestamps and counts."""
    return value.isoformat() if isinstance(value, datetime.datetime) else value


def audit(cursor, action, target, detail):
    """One journal row as this runner.

    The target is the CANONICAL address, never a row id, so the journal can be searched
    by address and the screens link into it by one spelling. No secret can reach the
    detail because none is in hand here.
    """
    cursor.execute(
        "INSERT INTO audit (actor, action, target, detail) VALUES (%s, %s, %s, %s)",
        (ACTOR, action, target, json.dumps({k: as_text(v) for k, v in detail.items()})))


def deletion_date(skipped_at, window, kept=False):
    """When the provider deletes a skipped message, None if it never does.

    Computed from columns that already exist rather than stored: a stored copy is
    wrong the day the window changes. A mailbox kept at the provider deletes nothing.
    """
    if kept or window is None:
        return None
    return skipped_at + datetime.timedelta(days=int(window))


# --- the listing session that finds the stuck message -----------------------------------------


def stuck_identifier(args, path, mailbox, folder, number):
    """(identifier, None) or (None, complaint). The conversation never leaves this function.

    ⛔ `--keep=on` IS WHAT KEEPS THE SESSION LISTING-ONLY. `--skipsize=0`
    reaches only messages still in the NORMAL action; every identifier already in the
    state file was set to DELETE at UIDL time, so under the rendered `keep <n>d` a
    "listing-only" run would send DELE for every message past the window - against a
    copy of the state file that is then thrown away, so the real state would never
    record that it happened. The command line overrides the file, and the one flag
    restores the property.
    """
    known = state_file.known_identifiers(state_file.path_of(folder))
    with state_file.listing_copy(folder) as copy:
        argv = [args.mpop, "--file", str(path), "--skipsize=0", "--keep=on", "--debug",
                "--uidls-file", str(copy), render.account_name(mailbox.id)]
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=LISTING_TIMEOUT)
        except subprocess.TimeoutExpired:
            return None, f"listing session timed out after {LISTING_TIMEOUT} s"
    # ⛔ Never `fetch_detail` here: its fallback is the last line printed, which on a
    # `--debug` conversation is a line of the conversation.
    said = outcome.mpop_lines(done.stdout + done.stderr)
    if done.returncode != 0:
        return None, ("; ".join(said)[:outcome.DETAIL_MAX] if said
                      else "listing session failed without a message")
    return state_file.choose_stuck(state_file.parse_listing(done.stdout + done.stderr),
                                   known, number)


# --- the bounded retry ------------------------------------------------------------------------


def bounded_retry(conn, mailbox, args, folder, path, result):
    """Record the outcome and, on a message-level failure, count, skip or freeze."""
    with conn.cursor() as cur:
        if result.status in (outcome.OK, outcome.NO_NEW_MAIL):
            # the episode is cleared, the last skip is kept for the screen.
            # a delivery that succeeded is what ends a hold.
            cur.execute(
                "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
                "last_fetch_cause = NULL, last_fetch_detail = %s, stuck_since = NULL, "
                "stuck_runs = 0, skip_streak = 0, frozen_since = NULL, last_listing_at = NULL, "
                "held_since = NULL WHERE id = %s",
                (result.status, result.detail, mailbox.id))
            return result.status

        if result.held:
            # the antivirus is unreachable, the message waits at the provider and
            # NOTHING counts toward the stuck hour. `held_since` is this runner's column;
            # health reads it, and the next run renders it back to the filter.
            # ⛔ A stuck episode already running is PAUSED, not only left alone: its start moves on by the time since the run before this one, so an
            # outage longer than the hour does not skip the message at the first refusal
            # after it. The right-hand `last_fetch_at` is the row's old value.
            cur.execute(
                "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
                "last_fetch_cause = %s, last_fetch_detail = %s, "
                "held_since = coalesce(held_since, now()), "
                f"{PAUSED} "
                "WHERE id = %s",
                (result.status, result.cause, result.detail, mailbox.id))
            return result.status

        if result.store_held:
            # the store cannot take mail, the message waits at the provider and
            # nothing counts toward the stuck hour, which is paused as above. The scanner
            # answered, so an antivirus hold is over.
            cur.execute(
                "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
                "last_fetch_cause = %s, last_fetch_detail = %s, "
                "held_since = CASE WHEN %s THEN NULL ELSE held_since END, "
                f"{PAUSED} "
                "WHERE id = %s",
                (result.status, result.cause, result.detail, result.scanner_answered,
                 mailbox.id))
            return result.status

        if not result.message_level:
            # on an IMAP row this pauses a stuck episode too (`set_status`): a
            # provider unreachable for an hour is not an hour stopped on the message
            set_status(cur, mailbox, result)
            return result.status

        # ⛔ A hold that ends with a REFUSED message must clear `held_since`.
        # If the delivery filter answered with a real verdict (the scanner was up), the
        # antivirus is not down any more, whatever this message's fate; leaving the hold
        # set would keep health reporting an outage and start the next real outage already
        # past the hold's bound. A message the provider refused (no delivery verdict) does
        # not reach the scanner, so it says nothing about the hold and leaves it.
        # ⛔ AN IMAP ROW'S HOUR IS ONE OF RUNS THAT STOPPED ON THE MESSAGE. A POP3
        # row's clock starts at the first failure and runs by the wall, as it always has.
        # An IMAP row's counts the time since its last run only up to one run's bound: the
        # first run after a stopped timer or a backup's pause must not find the hour passed
        # because nobody ran.
        over_imap = mailbox.protocol == render.IMAP
        counted, bound = ((IMAP_COUNTED, (args.timeout,)) if over_imap else
                          ("stuck_since = coalesce(stuck_since, now())", ()))
        cur.execute(
            "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
            "last_fetch_cause = %s, last_fetch_detail = %s, "
            "held_since = CASE WHEN %s THEN NULL ELSE held_since END, "
            f"{counted}, stuck_runs = stuck_runs + 1 "
            "WHERE id = %s RETURNING stuck_since, stuck_runs, skip_streak, frozen_since, "
            "now() - stuck_since >= make_interval(secs => %s)",
            (result.status, result.cause, result.detail, result.scanner_answered, *bound,
             mailbox.id, args.stuck_after))
        stuck_since, stuck_runs, skip_streak, frozen_since, due = cur.fetchone()
        if not due or frozen_since is not None:
            return result.status
        if over_imap and stuck_runs < IMAP_STUCK_RUNS:
            # the floor on attempts: neither a skip nor a freeze under it
            return result.status

        if skip_streak >= 1:
            # never twice without a successful run between. One transaction
            # with its journal row, so a row that cannot be written leaves no half-frozen
            # mailbox behind.
            cur.execute("BEGIN")
            cur.execute("UPDATE external_mailbox SET frozen_since = now() WHERE id = %s "
                        "RETURNING frozen_since", (mailbox.id,))
            frozen_at = cur.fetchone()[0]
            audit(cur, "fetch_frozen", mailbox.target,
                  {"stuck_since": stuck_since, "stuck_runs": stuck_runs,
                   "frozen_at": frozen_at})
            cur.execute("COMMIT")
            return result.status

        # The skip itself is the protocol's: mpop's needs a listing session to name the
        # message and its state file to pass it, an IMAP run has named it already.
        if mailbox.protocol == render.IMAP:
            return skip_past_mark(cur, mailbox, result, stuck_since, stuck_runs)
        return skip_by_listing(cur, mailbox, args, folder, path, result, stuck_since,
                               stuck_runs)


def skip_by_listing(cur, mailbox, args, folder, path, result, stuck_since, stuck_runs):
    """mpop's skip: the stuck message found by a listing session, the database written first
    and mpop's state file second."""
    # one listing session an hour per mailbox, whatever it answers.
    cur.execute(
        "UPDATE external_mailbox SET last_listing_at = now() WHERE id = %s AND "
        "(last_listing_at IS NULL OR now() - last_listing_at >= make_interval(secs => %s)) "
        "RETURNING 1", (mailbox.id, args.stuck_after))
    if cur.fetchone() is None:
        return result.status

    identifier, complaint = stuck_identifier(args, path, mailbox, folder,
                                             result.retr_number)
    if identifier is None:
        append_detail(cur, mailbox, complaint)
        return result.status

    # the database first, in one transaction with its journal row, and
    # mpop's state file second.
    try:
        cur.execute("BEGIN")
        cur.execute(
            "UPDATE external_mailbox SET last_skip_at = now(), last_skip_uidl = %s, "
            "skip_streak = skip_streak + 1, stuck_since = NULL, stuck_runs = 0 "
            "WHERE id = %s RETURNING last_skip_at", (identifier, mailbox.id))
        skipped_at = cur.fetchone()[0]
        audit(cur, "auto_skip_message", mailbox.target,
              {"uidl": identifier, "stuck_since": stuck_since, "stuck_runs": stuck_runs,
               "skipped_at": skipped_at,
               "deletes_at": deletion_date(skipped_at, mailbox.window, mailbox.keep)})
        cur.execute("COMMIT")
    except Exception as err:  # noqa: BLE001 - the run continues with the next mailbox
        cur.execute("ROLLBACK")
        append_detail(cur, mailbox, f"skip not written: {type(err).__name__}",
                      cause=outcome.UNRECORDED)
        return outcome.ERROR
    try:
        state_file.record_skip(folder, identifier, mailbox.pop3_host,
                               render.login_of(mailbox))
    except Exception as err:  # noqa: BLE001 - the row already says what was intended
        append_detail(cur, mailbox, f"skip not written to the state file: {err}",
                      cause=outcome.UNRECORDED)
    return result.status


def skip_past_mark(cur, mailbox, result, stuck_since, stuck_runs):
    """An IMAP row's skip: the mark past the UID the run stopped on, in one
    transaction with the skip's columns and its journal row.

    There is no listing session, no extra login and no state file: the run named the
    message by UID, and the mark on the row is the whole of what was collected. The
    message stays at the provider, which nothing of ours changes, so the journal names no
    deletion date. A mark cleared or reset since the run started (its server or
    login changed) is never written over: nothing is skipped, and the detail says so.
    """
    uid = result.retr_number
    try:
        cur.execute("BEGIN")
        skipped = imap_collect.skip(cur, mailbox, uid)
        if skipped is None:
            cur.execute("ROLLBACK")
            append_detail(cur, mailbox, f"message {uid} not skipped: the row's mark changed "
                                        "during the run")
            return result.status
        identifier, skipped_at = skipped
        audit(cur, "auto_skip_message", mailbox.target,
              {"uidl": identifier, "stuck_since": stuck_since, "stuck_runs": stuck_runs,
               "skipped_at": skipped_at, "deletes_at": None})
        cur.execute("COMMIT")
    except Exception as err:  # noqa: BLE001 - the run continues with the next mailbox
        cur.execute("ROLLBACK")
        append_detail(cur, mailbox, f"skip not written: {type(err).__name__}",
                      cause=outcome.UNRECORDED)
        return outcome.ERROR
    return result.status


# --- one mailbox -------------------------------------------------------------------------------


def write_trace(folder, text):
    """0600 at creation: `mpop --debug` writes the credential in clear."""
    handle = os.open(Path(folder) / "trace", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as out:
        out.write(text)


class Killed(subprocess.TimeoutExpired):
    """mpop did not stop within the grace, and its process group was killed."""


def stop(process, grace):
    """SIGTERM to mpop alone, then SIGKILL to its whole group after `grace` seconds.

    ⛔ SIGTERM FIRST: SIGKILL LOSES A WHOLE RUN'S DELIVERIES. mpop 1.4.23 writes its state
    file once, after the retrieval loop; SIGTERM sets a flag that ends the loop and the
    state is still written, while SIGKILL writes nothing, so every message a killed run
    delivered was delivered again by the next, and a backlog longer than the timeout
    never converged. The signal goes to mpop and NOT to the delivery filter: a filter
    in the middle of a message finishes it, mpop waits for it (`pclose` retries on
    EINTR) and records it. A message mpop was still reading is abandoned with its pipe
    left open, and the filter stores nothing of it (the retrieval pipe below).
    """
    with contextlib.suppress(ProcessLookupError):
        process.send_signal(signal.SIGTERM)
    try:
        process.communicate(timeout=grace)
        return False
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        return True


def run_mpop(argv, timeout, grace=STOP_GRACE):
    """mpop under OUR wall-clock timeout, stopped when it expires.

    mpop loops for ever on a connection closed inside a message body and its own
    `--timeout` does not fire on a closed peer, so the bound has to be the caller's.
    It raises `TimeoutExpired` when mpop stopped and saved its state, `Killed` when it
    had to be killed.

    ⛔ THE KILL TAKES MPOP'S WHOLE PROCESS GROUP. Killing mpop alone left the
    delivery filter it had started running: it could still store a message mpop never
    recorded, which the next run retrieves and stores a second time. mpop runs in a
    session of its own, so the group is it and everything it started.

    ⛔ MPOP IS HANDED BOTH ENDS OF THE RETRIEVAL PIPE AND THIS PROCESS KEEPS NEITHER
    (`lib/retrieval.py`): a connection that ends inside a message body
    leaves the filter with half a message and no other sign of it, and the write end
    held by mpop alone is how the filter tells that from a message mpop finished.
    """
    read, write = os.pipe()
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True, pass_fds=(read, write),
                                   env=retrieval.environment(read, write))
    finally:
        os.close(read)
        os.close(write)
    with process:
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            if stop(process, grace):
                raise Killed(argv, timeout) from None
            raise
    return subprocess.CompletedProcess(argv, process.returncode, out, err)


def say_unchecked(target, text):
    """Each delivery the filter could not check against the retrieval pipe, into this
    run's own stderr, which is the fetch unit's journal: mpop's output is read and dropped
    on a success, so the filter's words would reach nobody."""
    for line in retrieval.unchecked(text):
        sys.stderr.write(f"maildivvy-fetch: {target}: {line}\n")


def say_store(target, text):
    """Why the filter found the store unable to take mail, into the fetch unit's
    journal: the row's detail is mpop's own line, which names the status alone. Only a
    line that begins with the filter's own words is copied."""
    for line in text.splitlines():
        if line.startswith(deliver_filter.STORE_SAID):
            sys.stderr.write(f"maildivvy-fetch: {target}: {line.strip()}\n")


def record(conn, mailbox, args, folder, path, result):
    """The outcome on the row through the bounded retry, and its status."""
    try:
        return bounded_retry(conn, mailbox, args, folder, path, result)
    except Exception as err:  # noqa: BLE001 - one guard, and it rolls back
        with conn.cursor() as cur:
            cur.execute("ROLLBACK")
            set_status(cur, mailbox, outcome.Outcome(
                outcome.ERROR, outcome.UNRECORDED,
                ((result.detail + "; ") if result.detail else "")
                + f"bounded retry failed: {type(err).__name__}"))
        return outcome.ERROR


def run_one(conn, mailbox, args):
    """Fetch one external mailbox; returns its status, BUSY when another run holds it,
    or None when its row is gone."""
    mailbox_id = mailbox.id
    folder = render.state_dir(args.state_dir, mailbox_id)

    with conn.cursor() as cur:
        if not locks.try_lock(cur, mailbox_id):
            sys.stderr.write(f"maildivvy-fetch: {mailbox.target} is already running - skipped\n")
            return BUSY
    try:
        # ⛔ RE-READ THE ROW NOW THE LOCK IS HELD. The run read every row at its
        # start; a deletion that committed since has taken the row and the state directory
        # away, and rendering from the stale copy would write the state directory straight
        # back. A row that is gone (deleted, or its domain unmapped) is skipped, and nothing
        # of it is recreated; so is a row deactivated since.
        with conn.cursor() as cur:
            mailbox = row_to_fetch(cur, mailbox_id)
        if mailbox is None:
            sys.stderr.write(f"maildivvy-fetch: external mailbox {mailbox_id} is gone, "
                             "unmapped or deactivated - skipped, nothing recreated\n")
            return None
        if mailbox.protocol == render.IMAP:
            # our own client, and no configuration file or state directory
            if args.trace:
                # ⛔ imaplib's debug output prints the login whole. Nothing is
                # collected and nothing is written on the row: a trace is a person's run.
                sys.stderr.write(f"maildivvy-fetch: {mailbox.target} is collected over IMAP, "
                                 "which has no trace: its client's debug output carries the "
                                 "password - not collected\n")
                return outcome.ERROR
            result = collect_imap(conn, mailbox, args)
            if result == imap_collect.FROZEN:
                # frozen, and tried within the hour; the row keeps that attempt's
                sys.stderr.write(f"maildivvy-fetch: {mailbox.target} is frozen and was tried "
                                 "within the hour - not asked again yet\n")
                return outcome.ERROR
            return record(conn, mailbox, args, folder, None, result)
        try:
            path = render.write_config(
                render.render(mailbox, args.state_dir, args.bindir, args.hold_bound_seconds),
                folder)
        except render.RenderError as err:
            with conn.cursor() as cur:
                set_status(cur, mailbox, outcome.Outcome(outcome.ERROR, outcome.TRANSIENT, str(err)))
            return outcome.ERROR

        argv = [args.mpop, "--file", str(path)]
        if args.trace:
            argv.append("--debug")
        argv.append(render.account_name(mailbox.id))
        try:
            done = run_mpop(argv, args.timeout)
        except subprocess.TimeoutExpired as expired:
            # ⛔ None of the child's output is kept: on this path it has no bound.
            with conn.cursor() as cur:
                set_status(cur, mailbox, outcome.timed_out(
                    args.timeout, killed=isinstance(expired, Killed)))
            return outcome.ERROR

        text = done.stdout + done.stderr
        say_unchecked(mailbox.target, text)
        say_store(mailbox.target, text)
        if args.trace:
            write_trace(folder, text)
        return record(conn, mailbox, args, folder, path, outcome.read(done.returncode, text))
    finally:
        with conn.cursor() as cur:
            locks.unlock(cur, mailbox_id)


def collect_imap(conn, mailbox, args):
    """An IMAP row's run (`imap_collect.collect`), and its fault the row's own `transient`:
    a filter that cannot be started or a statement that fails ends this row, and never the
    run. Only the fault's kind is kept, but for an OSError, whose words name
    the program or the path and never the password."""
    try:
        return imap_collect.collect(conn, mailbox, args, STOP_GRACE)
    except Exception as err:  # noqa: BLE001 - one mailbox's fault never ends the run for the others
        said = f"{type(err).__name__}: {err}" if isinstance(err, OSError) else type(err).__name__
        return outcome.Outcome(outcome.ERROR, outcome.TRANSIENT,
                               f"the run stopped on a fault of its own: {said}"[:outcome.DETAIL_MAX])


# --- the password check ----------------------------------------------------


def set_test_status(cursor, mailbox, result):
    """The check's own three columns, and NEVER a fetch column."""
    cursor.execute(
        "UPDATE external_mailbox SET last_test_at = now(), last_test_status = %s, "
        "last_test_detail = %s WHERE id = %s", (result.status, result.detail, mailbox.id))


def start_mark(conn, mailbox, start):
    """`--start-mark`: an empty mark set where the check found the INBOX, and one
    from another UIDVALIDITY reset there, each in one transaction with its journal row. A
    mark of the same UIDVALIDITY is kept: deactivation keeps it, so a mailbox activated
    again collects what arrived meanwhile. None, or why the mark was not written.

    The journal row carries the mark it replaced and the row's last fetch, its time and
    status (the row keeps no time of its last successful fetch apart): after a provider
    renumbered its INBOX, it is where a person starts looking for what arrived under the
    old numbering.
    """
    uidvalidity, last_uid = start
    if mailbox.imap_uidvalidity == uidvalidity and mailbox.imap_last_uid is not None:
        return None
    with conn.cursor() as cur:
        try:
            cur.execute("BEGIN")
            fetched = imap_collect.set_mark(cur, mailbox, uidvalidity, last_uid)
            if fetched is None:
                cur.execute("ROLLBACK")
                return "the row's server, login or mark changed during the check"
            audit(cur, "imap_mark_set" if mailbox.imap_uidvalidity is None else "imap_mark_reset",
                  mailbox.target,
                  {"uidvalidity": uidvalidity, "last_uid": last_uid,
                   "old_uidvalidity": mailbox.imap_uidvalidity,
                   "old_last_uid": mailbox.imap_last_uid,
                   "last_fetch_at": fetched[0], "last_fetch_status": fetched[1]})
            cur.execute("COMMIT")
        except Exception as err:  # noqa: BLE001 - the check's verdict says so, and nothing is half written
            cur.execute("ROLLBACK")
            return type(err).__name__
    return None


def check_imap(conn, mailbox, args):
    """An IMAP row's check: a login and EXAMINE INBOX by our own client, with no
    configuration file and no state directory, and with `--start-mark` the mark.

    ⛔ A MARK ASKED FOR AND NOT WRITTEN IS NOT AN `ok`: the activation reads this verdict,
    and would switch on a mailbox whose every run then collects nothing (`mark`).
    """
    result, start = imap_collect.check(conn, mailbox, args, args.start_mark)
    if start is None:
        return result
    why = start_mark(conn, mailbox, start)
    if why is None:
        return result
    return outcome.Outcome(outcome.ERROR, None,
                           f"the provider accepted the login, but the mark collection starts "
                           f"from was not set: {why}")


def run_auth_only(conn, mailbox, args):
    """Render, lock, `mpop --auth-only`, write the three columns.

    The same renderer, the same lock and the same credential path as a fetch: a second
    place that writes a client configuration is a second place that can put a credential
    on disk with the wrong mode, and a check must log in with the login the timed fetch
    will use or an *ok* verdict has tested something else. An IMAP row is checked by the
    client that collects it, under the same lock (`check_imap`).
    """
    folder = render.state_dir(args.state_dir, mailbox.id)
    with conn.cursor() as cur:
        if not locks.try_lock(cur, mailbox.id):
            # ⛔ NO STATUS IS WRITTEN here, and the caller exits non-zero. A check that
            # did not happen must not leave a verdict behind for a request to read.
            sys.stderr.write(
                f"maildivvy-fetch: {mailbox.target} is already running - not tested\n")
            return None
    try:
        if mailbox.protocol == render.IMAP:
            result = check_imap(conn, mailbox, args)
            with conn.cursor() as cur:
                set_test_status(cur, mailbox, result)
            return result.status
        path = render.write_config(
            render.render(mailbox, args.state_dir, args.bindir, args.hold_bound_seconds), folder)
        # ⛔ NO --debug HERE, whatever --trace says: this path's output goes into a
        # column the interface renders.
        argv = [args.mpop, "--file", str(path), "--auth-only", render.account_name(mailbox.id)]
        try:
            done = run_mpop(argv, args.timeout)
        except subprocess.TimeoutExpired as expired:
            ended = "killed" if isinstance(expired, Killed) else "stopped"
            result = outcome.Outcome(outcome.ERROR, None,
                                     f"timed out after {int(args.timeout)} s; mpop {ended}")
        else:
            result = outcome.read_test(done.returncode, done.stdout + done.stderr)
        with conn.cursor() as cur:
            set_test_status(cur, mailbox, result)
        return result.status
    finally:
        with conn.cursor() as cur:
            locks.unlock(cur, mailbox.id)


# --- the snapshot -------------------------------------------------------------------------


def snapshot_one(conn, mailbox_id, args):
    """One slice of one mailbox's snapshot: its status, BUSY when the snapshot's lock is held
    (a slice, a deletion or a discard), or None when the row no longer wants one.

    ⛔ THE SNAPSHOT'S LOCK, NEVER THE FETCH'S, and the row re-read under it with
    the listing's predicate: a deletion that committed since has taken the row
    and its snapshot away, and a discard has ended it; neither is written back.
    """
    with conn.cursor() as cur:
        if not locks.try_lock(cur, mailbox_id, locks.SNAPSHOT):
            sys.stderr.write(f"maildivvy-fetch: a slice of external mailbox {mailbox_id}'s "
                             "snapshot is already running, or it is being deleted - skipped\n")
            return BUSY
    try:
        with conn.cursor() as cur:
            mailbox = one_row(cur, TO_SNAPSHOT_ONE, mailbox_id)
        if mailbox is None:
            sys.stderr.write(f"maildivvy-fetch: external mailbox {mailbox_id} has no snapshot "
                             "to take any more - skipped, nothing recreated\n")
            return None
        status = snapshot.take(conn, mailbox, args)
        if status == snapshot.FAILED:
            sys.stderr.write(f"maildivvy-fetch: the snapshot of {mailbox.target} failed\n")
        return status
    finally:
        with conn.cursor() as cur:
            locks.unlock(cur, mailbox_id, locks.SNAPSHOT)


def run_snapshots(conn, args):
    """A slice of every snapshot to take, or of `--only`'s, the least recently advanced
    first and none that could end past SNAPSHOT_RUN_SECONDS; the exit code. A snapshot left
    for want of time is the first of the next run, since nothing advanced it."""
    began = time.monotonic()
    with conn.cursor() as cur:
        cur.execute(TO_SNAPSHOT)
        ids = [row[0] for row in cur.fetchall()]
    if args.only is not None:
        ids = [i for i in ids if i == args.only]
    statuses = []
    for mailbox_id in sorted(ids, key=snapshot.advanced_at):
        if time.monotonic() - began + args.slice_seconds + snapshot.GRACE > SNAPSHOT_RUN_SECONDS:
            sys.stderr.write(f"maildivvy-fetch: no time is left in this run for a slice of "
                             f"external mailbox {mailbox_id}'s snapshot - the next run takes it\n")
            continue
        statuses.append(snapshot_one(conn, mailbox_id, args))
    if args.only is not None:
        if BUSY in statuses:
            return EX_TEMPFAIL
        if not statuses or None in statuses:
            sys.stderr.write(f"maildivvy-fetch: external mailbox {args.only} has no snapshot "
                             "under way or asked for, or is not an active IMAP mailbox\n")
            return 1
    return 1 if snapshot.FAILED in statuses else 0


def collect_in_time(conn, mailboxes, args):
    """Each mailbox in turn, none started that could end past FETCH_RUN_SECONDS;
    their statuses. A run stopped by the unit's timeout started over at the first mailbox
    and never reached the last; the ones left here were collected least recently, and so
    are the next run's first."""
    began = time.monotonic()
    statuses = []
    for done, mailbox in enumerate(mailboxes):
        if (args.only is None and
                time.monotonic() - began + args.timeout + STOP_GRACE > FETCH_RUN_SECONDS):
            sys.stderr.write(f"maildivvy-fetch: no time is left in this run for "
                             f"{len(mailboxes) - done} mailbox(es) - the next run takes them "
                             "first\n")
            break
        statuses.append(run_one(conn, mailbox, args))
    return statuses


def seconds(value):
    """A whole number of seconds above 0."""
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError(f"{value!r} is not a whole number of seconds above 0")
    return int(value)


# --- the command line ---------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(description="collect mail from every external mailbox")
    parser.add_argument("--state-dir", default=str(render.DEFAULT_STATE_DIR))
    parser.add_argument("--bindir", default=str(render.DEFAULT_BINDIR))
    parser.add_argument("--mpop", default=DEFAULT_MPOP,
                        help="the POP3 client to run; there is exactly one on the machine")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="seconds before mpop is killed and the run recorded as an error")
    parser.add_argument("--stuck-after", type=float, default=DEFAULT_STUCK_AFTER,
                        help="seconds on one message before it is skipped")
    parser.add_argument("--hold-bound-seconds", type=float, default=render.DEFAULT_HOLD_BOUND,
                        help="how long the antivirus hold may last before mail is "
                             "delivered marked unavailable")
    parser.add_argument("--trace", action="store_true",
                        help="keep mpop's debug trace; it holds the credential in clear. "
                             "An IMAP mailbox has none and is not collected with it")
    parser.add_argument("--only", type=int, default=None, help="one external mailbox id")
    parser.add_argument("--auth-only", action="store_true",
                        help="check --only's credential and write last_test_*; retrieve nothing")
    # the one fetch column a check writes, and only an activation asks for it
    parser.add_argument("--start-mark", action="store_true",
                        help="with --auth-only, on an IMAP mailbox: set an empty mark where the "
                             "INBOX stands now, or reset one from another UIDVALIDITY. "
                             "Activation passes it; a POP3 mailbox has no mark")
    parser.add_argument("--snapshot", action="store_true",
                        help="take one slice of each IMAP mailbox's snapshot under way or asked "
                             "for, or of --only's, and collect nothing")
    parser.add_argument("--slice-seconds", type=seconds, default=snapshot.SLICE_SECONDS,
                        help="with --snapshot: how long one slice of a snapshot may take "
                             "messages for")
    parser.add_argument("--etc", default=str(config.ETC))
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    # ⛔ A password check is about ONE row. Answering a bare invocation
    # would spend a login on every mailbox, at providers that declare a LOGIN-DELAY,
    # for a question nobody asked about the others.
    if args.auth_only and args.only is None:
        sys.stderr.write("maildivvy-fetch: --auth-only needs --only <id>: a check is about "
                         "one row, and testing every row spends a login on each of them\n")
        return EX_USAGE
    if args.start_mark and not args.auth_only:
        # the mark is set by the activation's check, never by a run of collection
        sys.stderr.write("maildivvy-fetch: --start-mark is part of --auth-only: only the "
                         "check an activation runs sets a mark\n")
        return EX_USAGE
    if args.snapshot and (args.auth_only or args.trace):
        # a slice checks no password and has no trace
        sys.stderr.write("maildivvy-fetch: --snapshot takes a snapshot's slice and nothing "
                         "else: neither --auth-only nor --trace goes with it\n")
        return EX_USAGE

    try:
        conn = db.connect(CONSUMER, etc=args.etc, autocommit=True)
    except config.ConfigError as err:
        sys.stderr.write(f"maildivvy-fetch: {err}\n")
        return EX_CONFIG

    try:
        if args.snapshot:
            return run_snapshots(conn, args)
        if args.auth_only:
            with conn.cursor() as cur:
                mailbox = row_to_test(cur, args.only)
            if mailbox is None:
                sys.stderr.write(f"maildivvy-fetch: no external mailbox {args.only} with a "
                                 "domain in front of it\n")
                return 1
            # Only `ok` exits 0: a refused credential is a real answer, and a useful
            # one, but it is not a success.
            return 0 if run_auth_only(conn, mailbox, args) == outcome.OK else 1

        with conn.cursor() as cur:
            mailboxes = rows_to_fetch(cur)
        if args.only is not None:
            mailboxes = [m for m in mailboxes if m.id == args.only]
        statuses = collect_in_time(conn, mailboxes, args)
    finally:
        conn.close()
    if args.only is not None:
        if BUSY in statuses:
            return EX_TEMPFAIL
        if not statuses or None in statuses:
            sys.stderr.write(f"maildivvy-fetch: external mailbox {args.only} collected nothing: "
                             "it is deactivated, unmapped or gone\n")
            return 1
    return 1 if {outcome.ERROR, outcome.AUTH_FAILED} & set(statuses) else 0
