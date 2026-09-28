"""The fetch runner: one mpop per external mailbox, and the bounded retry around it.

    maildivvy-fetch [--only <id>] [--auth-only] [--trace]

For every external mailbox with a domain in front of it and not deactivated: take the
try-lock, render the client's configuration from the row, run mpop under our own
timeout, and record one of four outcomes with a structured cause.

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
freezes the mailbox for a person.

⛔ THE ANTIVIRUS HOLD IS NOT A STUCK MESSAGE. The delivery filter exits
EX_TEMPFAIL while ClamAV is unreachable, mpop leaves the message unretrieved, and the
runner records `held_since` instead of counting the run toward the stuck hour. It
renders that time back onto the delivery line, which is how the filter learns that the
hold has outlasted its bound and the message must be delivered marked *unavailable*.

⛔ A TRACE IS A SECRET. `mpop --debug` writes every command verbatim,
the one carrying the credential included, and whole message bodies. A trace is written
0600, the listing session's conversation is never written at all, and nothing but one
identifier or mpop's own `mpop:` lines leaves it.
"""

import argparse
import datetime
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

from maildivvy.fetch import locks, outcome, render
from maildivvy.fetch import state as state_file
from maildivvy.lib import config, db, retrieval

CONSUMER = "pipeline"
ACTOR = "maildivvy-fetch"  # the journal's actor for everything this writes

DEFAULT_MPOP = "/usr/local/bin/mpop"
DEFAULT_TIMEOUT = 900       # seconds
DEFAULT_STUCK_AFTER = 3600  # seconds on one message before it is skipped
LISTING_TIMEOUT = 300       # the listing session's own bound

EX_USAGE = 64
EX_CONFIG = 78

COLUMNS = """
    SELECT e.id, e.pop3_login, e.address, e.pop3_host, e.pop3_port,
           d.label, e.delete_window_days, e.address_canonical,
           d.spam_threshold, e.held_since
      FROM external_mailbox e
      JOIN domain d ON d.external_mailbox_id = e.id
"""
# The rows an ordinary run collects: a domain in front of it and not deactivated.
TO_FETCH = COLUMNS + " WHERE e.state <> 'deactivated' ORDER BY e.id"
# ⛔ The password check selects BY ID WITH NO STATE PREDICATE. By the
# order of a new mailbox - saved disabled, tested, then enabled - every row a check is
# ever about is `deactivated`, which is exactly what TO_FETCH excludes. Filtering its
# result by id would do nothing, exit 0, write no status, and let the request report
# success having measured nothing.
TO_TEST = COLUMNS + " WHERE e.id = %s"


def rows_to_fetch(cursor):
    cursor.execute(TO_FETCH)
    return [render.Mailbox(*row) for row in cursor.fetchall()]


def row_to_test(cursor, mailbox_id):
    cursor.execute(TO_TEST, (mailbox_id,))
    row = cursor.fetchone()
    return render.Mailbox(*row) if row else None


# --- what goes on the row and in the journal --------------------------------------------------


def set_status(cursor, mailbox, result):
    cursor.execute(
        "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
        "last_fetch_cause = %s, last_fetch_detail = %s WHERE id = %s",
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


def deletion_date(skipped_at, window):
    """When the provider deletes a skipped message.

    Computed from two columns that already exist rather than stored: a stored copy is
    wrong the day the window changes.
    """
    return None if window is None else skipped_at + datetime.timedelta(days=int(window))


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
                "stuck_since = stuck_since + (now() - coalesce(last_fetch_at, now())) "
                "WHERE id = %s",
                (result.status, result.cause, result.detail, mailbox.id))
            return result.status

        if not result.message_level:
            set_status(cur, mailbox, result)
            return result.status

        # ⛔ A hold that ends with a REFUSED message must clear `held_since`.
        # If the delivery filter answered with a real verdict (the scanner was up), the
        # antivirus is not down any more, whatever this message's fate; leaving the hold
        # set would keep health reporting an outage and start the next real outage already
        # past the hold's bound. A message the provider refused (no delivery verdict) does
        # not reach the scanner, so it says nothing about the hold and leaves it.
        cur.execute(
            "UPDATE external_mailbox SET last_fetch_at = now(), last_fetch_status = %s, "
            "last_fetch_cause = %s, last_fetch_detail = %s, "
            "held_since = CASE WHEN %s THEN NULL ELSE held_since END, "
            "stuck_since = coalesce(stuck_since, now()), stuck_runs = stuck_runs + 1 "
            "WHERE id = %s RETURNING stuck_since, stuck_runs, skip_streak, frozen_since, "
            "now() - stuck_since >= make_interval(secs => %s)",
            (result.status, result.cause, result.detail, result.scanner_answered,
             mailbox.id, args.stuck_after))
        stuck_since, stuck_runs, skip_streak, frozen_since, due = cur.fetchone()
        if not due or frozen_since is not None:
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
                   "deletes_at": deletion_date(skipped_at, mailbox.window)})
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


# --- one mailbox -------------------------------------------------------------------------------


def write_trace(folder, text):
    """0600 at creation: `mpop --debug` writes the credential in clear."""
    handle = os.open(Path(folder) / "trace", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as out:
        out.write(text)


def run_mpop(argv, timeout):
    """mpop under OUR wall-clock timeout, killed when it expires.

    mpop loops for ever on a connection closed inside a message body and its own
    `--timeout` does not fire on a closed peer, so the bound has to be the caller's.

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
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
    return subprocess.CompletedProcess(argv, process.returncode, out, err)


def say_unchecked(target, text):
    """Each delivery the filter could not check against the retrieval pipe, into this
    run's own stderr, which is the fetch unit's journal: mpop's output is read and dropped
    on a success, so the filter's words would reach nobody."""
    for line in retrieval.unchecked(text):
        sys.stderr.write(f"maildivvy-fetch: {target}: {line}\n")


def run_one(conn, mailbox, args):
    """Fetch one external mailbox; returns its status, or None when it was skipped."""
    mailbox_id = mailbox.id
    folder = render.state_dir(args.state_dir, mailbox_id)

    with conn.cursor() as cur:
        if not locks.try_lock(cur, mailbox_id):
            sys.stderr.write(f"maildivvy-fetch: {mailbox.target} is already running - skipped\n")
            return None
    try:
        # ⛔ RE-READ THE ROW NOW THE LOCK IS HELD. The run read every row at its
        # start; a deletion that committed since has taken the row and the state directory
        # away, and rendering from the stale copy would write the state directory straight
        # back. A row that is gone (deleted, or its domain unmapped) is skipped, and nothing
        # of it is recreated.
        with conn.cursor() as cur:
            mailbox = row_to_test(cur, mailbox_id)
        if mailbox is None:
            sys.stderr.write(f"maildivvy-fetch: external mailbox {mailbox_id} is gone or "
                             "unmapped - skipped, nothing recreated\n")
            return None
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
        except subprocess.TimeoutExpired:
            # ⛔ None of the child's output is kept: on this path it has no bound.
            with conn.cursor() as cur:
                set_status(cur, mailbox, outcome.timed_out(args.timeout))
            return outcome.ERROR

        text = done.stdout + done.stderr
        say_unchecked(mailbox.target, text)
        if args.trace:
            write_trace(folder, text)
        result = outcome.read(done.returncode, text)
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
    finally:
        with conn.cursor() as cur:
            locks.unlock(cur, mailbox_id)


# --- the password check ----------------------------------------------------


def set_test_status(cursor, mailbox, result):
    """The check's own three columns, and NEVER a fetch column."""
    cursor.execute(
        "UPDATE external_mailbox SET last_test_at = now(), last_test_status = %s, "
        "last_test_detail = %s WHERE id = %s", (result.status, result.detail, mailbox.id))


def run_auth_only(conn, mailbox, args):
    """Render, lock, `mpop --auth-only`, write the three columns.

    The same renderer, the same lock and the same credential path as a fetch: a second
    place that writes a client configuration is a second place that can put a credential
    on disk with the wrong mode, and a check must log in with the login the timed fetch
    will use or an *ok* verdict has tested something else.
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
        path = render.write_config(
            render.render(mailbox, args.state_dir, args.bindir, args.hold_bound_seconds), folder)
        # ⛔ NO --debug HERE, whatever --trace says: this path's output goes into a
        # column the interface renders.
        argv = [args.mpop, "--file", str(path), "--auth-only", render.account_name(mailbox.id)]
        try:
            done = run_mpop(argv, args.timeout)
        except subprocess.TimeoutExpired:
            result = outcome.Outcome(outcome.ERROR, None,
                                     f"timed out after {int(args.timeout)} s; mpop killed")
        else:
            result = outcome.read_test(done.returncode, done.stdout + done.stderr)
        with conn.cursor() as cur:
            set_test_status(cur, mailbox, result)
        return result.status
    finally:
        with conn.cursor() as cur:
            locks.unlock(cur, mailbox.id)


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
                        help="keep mpop's debug trace; it holds the credential in clear")
    parser.add_argument("--only", type=int, default=None, help="one external mailbox id")
    parser.add_argument("--auth-only", action="store_true",
                        help="check --only's credential and write last_test_*; retrieve nothing")
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

    try:
        conn = db.connect(CONSUMER, etc=args.etc, autocommit=True)
    except config.ConfigError as err:
        sys.stderr.write(f"maildivvy-fetch: {err}\n")
        return EX_CONFIG

    try:
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
        failed = False
        for mailbox in mailboxes:
            if run_one(conn, mailbox, args) in (outcome.ERROR, outcome.AUTH_FAILED):
                failed = True
    finally:
        conn.close()
    return 1 if failed else 0
