"""One incremental run of an IMAP mailbox's INBOX: every message above the row's
mark, in UID order, through the delivery filter, the mark advanced after each one filed.

    result = imap_collect.collect(conn, mailbox, args, grace)

The runner has taken the mailbox's try-lock and re-read the row; it records the outcome
through the bounded retry, as it does mpop's.

⛔ ONLY ACTIVATION SETS THE MARK. A run that finds no mark, or an INBOX whose
UIDVALIDITY is not the mark's, collects nothing and says `mark`: starting from "now" on
its own would silently skip whatever arrived since the last run. An empty mark is read
before anything is sent, so no login is spent on a run that cannot collect.

⛔ THE MARK IS ADVANCED AFTER EACH MESSAGE FILED, IN A STATEMENT OF ITS OWN, and only from
the mark this run started with: a run stopped at any point loses nothing and repeats at
most the message in hand, and a mark cleared or reset meanwhile (the row's server or
login changed) is never written over. A mark that could not be written ends the run as
`unrecorded`, since every message after it would be filed again by the next run. The
same statement ends the bounded retry's stuck episode: the mark moving past a
message is the end of being stuck on it, so a run that stops on a later one starts that
message's own episode, whatever this run's outcome.

⛔ THE FIRST MESSAGE NOT FILED ENDS THE RUN. The mark is one number, so nothing above a
message that still waits may be filed: the antivirus hold, the store's hold,
a refusal and the server's NO each stop the run there, the message left above
the mark for the next run or for the bounded retry. A message refused for the whole stuck
period is skipped by moving the mark past it (`skip`), from the runner's bounded retry,
in one transaction with its journal row; a hold never counts toward that period, and
neither does a run that never reached the message (`runner.bounded_retry`).

⛔ BUT A MESSAGE OVER `imap.MESSAGE_CAP` IS PASSED WITHOUT BEING DOWNLOADED. Its size
is asked before its body; over the cap, the mark moves past it in one transaction with its
journal row and the row's last skip (`pass_over`), and the run goes on. It is no stuck
episode and counts toward no freeze. It stays at the provider, which collection never
changes.

⛔ A CONNECTION THAT FAILS WHILE THE SERVER ANSWERS A MESSAGE IS THAT MESSAGE'S FAILURE, as
a BYE is ( as amended): the server took the login, the EXAMINE and the
search, and then closed or fell silent over this UID. Read as the network's, a message
that always does so would stop the INBOX behind it on every run for ever; counted, it is
skipped once the run has stopped on that same UID for the whole stuck period, which
absorbs a drop that happens once: a run that moved the mark before it stopped began the
episode afresh (`advance`), so drops spread over a backlog skip nothing. The period is
one of runs that reached the message, and at least `runner.IMAP_STUCK_RUNS` of them: the
bounded retry counts no time in which none did.

⛔ BUT A CONNECTION THAT FAILS BEFORE THE `UID FETCH` WAS WRITTEN IS THE SESSION'S
(`imap.NotSent`): the server was asked nothing about this UID, so the run ends
`unreachable` and no message is charged with it. A connection lost while the message
before was being filed would otherwise count against the next one.

⛔ THE MESSAGE IS WHOLE BEFORE THE FILTER STARTS. The session reads a literal to its
size, so the filter is never handed half a message and is not told it reads a
retrieval: that hazard is mpop's.

⛔ AT THE DEADLINE THE RUN STOPS BETWEEN MESSAGES. Every read
of the session is bounded by it; a filter already running is waited for up to the stop
grace past it, and then its whole process group is killed, as mpop's is. A run that filed
something is `ok`, with what still waits in its detail; one that filed nothing is
`error`/`timeout`. The next run goes on above the mark either way.

⛔ A MARK ABOVE THE INBOX'S LAST UID IS NO MARK TO TRUST. A provider that restored
a mailbox under the same UIDVALIDITY with lower UIDs (against the RFC, and seen) answers a
UIDNEXT at or under the mark: read as "no new mail", everything it holds would never be
collected, silently. It is the outcome `mark`, as a changed UIDVALIDITY is. Only UIDNEXT
says so: without it the last UID is the largest in use, which is under the mark whenever
the newest messages were expunged.

⛔ A RUN THAT COULD FILE NOTHING ASKS THE PROVIDER FOR NOTHING. A mailbox held for
the store, whose last run ended `store`, is fetched again only once the store's probe
(`deliver.filter.store_failure`) finds that it could take mail: until then every run
downloaded the same message whole and learned the same thing. A frozen mailbox is tried
once an hour (FROZEN_EVERY), not every run, but for a person's refetch (`--only`):
nothing ends a freeze but a person or the message going through, and every run until then
downloaded the message again. A stuck
message keeps every run of its bounded episode: spacing them out would delay its skip,
and every message behind it in the INBOX, by hours. An antivirus hold keeps them too,
bounded by the hold's own bound.

⛔ THE PASSWORD IS IN NO DETAIL: it is read on the runner's own
connection and handed to the session, whose errors never carry it.

The password check of an IMAP row is here too (`check`): a login and EXAMINE INBOX, and
nothing read. Asked by an activation, it also says where a mark set now starts, and
`set_mark` writes it only onto the row it checked ( one exception).
"""

import contextlib
import os
import signal
import subprocess
import time

from maildivvy.deliver import filter as deliver_filter
from maildivvy.fetch import imap, outcome, render
from maildivvy.fetch.credential import NO_SECRET, secret_of

NO_MARK = ("no mark to collect from: only activating the mailbox sets one, and a change of "
           "its server, login or protocol clears it; nothing was asked of the provider")
FROZEN_EVERY = 3600  # seconds between two runs of a frozen mailbox
FROZEN = "frozen"    # what `collect` returns for a frozen mailbox left for its hour
# the row's last cause, and whether it is frozen and was tried within FROZEN_EVERY
LAST_RUN = ("SELECT last_fetch_cause, frozen_since IS NOT NULL AND last_fetch_at > "
            "now() - make_interval(secs => %s) FROM external_mailbox WHERE id = %s")


def advance(cursor, mailbox, uid):
    """The mark past `uid`, from the mark the run started with, and the stuck episode ended
    with it: the next message to stop the INBOX starts its own. None, or why it was not."""
    try:
        cursor.execute(
            "UPDATE external_mailbox SET imap_last_uid = %s, stuck_since = NULL, "
            "stuck_runs = 0 WHERE id = %s AND imap_uidvalidity = %s AND imap_last_uid < %s "
            "RETURNING 1",
            (uid, mailbox.id, mailbox.imap_uidvalidity, uid))
        if cursor.fetchone() is None:
            return "the row's mark changed during the run"
    except Exception as err:  # noqa: BLE001 - the run's outcome says so, and it stops
        return type(err).__name__
    return None


def skip(cursor, mailbox, uid):
    """The bounded retry's skip of the message the run stopped on: the mark past `uid`, with
    the skip's own columns, under the same condition as `advance`. (the name it is skipped
    under, `<uidvalidity>/<uid>`, and the skip's time), or None when the mark changed since
    the run started. The caller holds the transaction, with its journal row."""
    name = f"{mailbox.imap_uidvalidity}/{uid}"
    cursor.execute(
        "UPDATE external_mailbox SET imap_last_uid = %s, last_skip_at = now(), "
        "last_skip_uidl = %s, skip_streak = skip_streak + 1, stuck_since = NULL, "
        "stuck_runs = 0 WHERE id = %s AND imap_uidvalidity = %s AND imap_last_uid < %s "
        "RETURNING last_skip_at",
        (uid, name, mailbox.id, mailbox.imap_uidvalidity, uid))
    row = cursor.fetchone()
    return (name, row[0]) if row else None


def pass_over(cursor, mailbox, uid, size):
    """A message over `imap.MESSAGE_CAP` passed without being downloaded: the mark
    past it as `skip` moves it, and the row's last skip and `oversize_skipped` naming it,
    but no stuck episode counted toward a freeze, in one transaction with its journal row.
    None, or why it was not passed."""
    from maildivvy.fetch import runner   # the runner imports this module

    name = f"{mailbox.imap_uidvalidity}/{uid}"
    try:
        cursor.execute("BEGIN")
        cursor.execute(
            "UPDATE external_mailbox SET imap_last_uid = %s, last_skip_at = now(), "
            "last_skip_uidl = %s, oversize_skipped = jsonb_build_object('uid', %s, "
            "'uidvalidity', imap_uidvalidity, 'size', %s, 'at', now()), stuck_since = NULL, "
            "stuck_runs = 0 WHERE id = %s AND imap_uidvalidity = %s AND imap_last_uid < %s "
            "RETURNING last_skip_at",
            (uid, name, uid, size, mailbox.id, mailbox.imap_uidvalidity, uid))
        row = cursor.fetchone()
        if row is None:
            cursor.execute("ROLLBACK")
            return "the row's mark changed during the run"
        runner.audit(cursor, "oversize_skip_message", mailbox.target,
                     {"uidl": name, "uid": uid, "size": size, "cap": imap.MESSAGE_CAP,
                      "skipped_at": row[0]})
        cursor.execute("COMMIT")
    except Exception as err:  # noqa: BLE001 - the run's outcome says so, and it stops
        with contextlib.suppress(Exception):
            cursor.execute("ROLLBACK")
        return type(err).__name__
    return None


def set_mark(cursor, mailbox, uidvalidity, last_uid):
    """An activation's mark, written only onto the row the check logged in to and only over
    the mark it read: the same protocol, server and login, so a mark is never carried to
    another numbering. The row's last fetch (its time and status), or None when the
    row changed since it was read. The caller holds the transaction, with its journal row."""
    cursor.execute(
        "UPDATE external_mailbox SET imap_uidvalidity = %s, imap_last_uid = %s "
        "WHERE id = %s AND protocol = %s AND pop3_host = %s "
        "AND pop3_login IS NOT DISTINCT FROM %s AND imap_uidvalidity IS NOT DISTINCT FROM %s "
        "AND imap_last_uid IS NOT DISTINCT FROM %s RETURNING last_fetch_at, last_fetch_status",
        (uidvalidity, last_uid, mailbox.id, render.IMAP, mailbox.pop3_host, mailbox.pop3_login,
         mailbox.imap_uidvalidity, mailbox.imap_last_uid))
    return cursor.fetchone()


def waiting(conn, mailbox, asked=False):
    """Why this run asks the provider for nothing: None to go ahead, `FROZEN` for a
    frozen mailbox tried within FROZEN_EVERY (nothing is recorded, so the next run's clock
    is still the last attempt's), or the store hold's `Outcome` while the store's probe
    still fails. A run a person `asked` for (`--only`) is never left for the hour."""
    with conn.cursor() as cur:
        cur.execute(LAST_RUN, (FROZEN_EVERY, mailbox.id))
        row = cur.fetchone()
    cause, frozen_lately = row if row else (None, False)
    if frozen_lately and not asked:
        return FROZEN
    if cause == outcome.STORE:
        why = deliver_filter.store_failure(mailbox.label, None, 0)
        if why is not None:
            return outcome.Outcome(outcome.ERROR, outcome.STORE, joined(
                f"the archive's store still cannot take mail ({why}); the provider was not "
                "asked, and the next run asks once the store can"), store_held=True)
    return None


def check(conn, mailbox, args, start_mark=False):
    """The password check of an IMAP row: log in and EXAMINE the INBOX, read nothing, log out.

    (its `Outcome`, of the check's three statuses and no cause, and with
    `start_mark` where a mark set now starts: the INBOX's (UIDVALIDITY, its last UID now,
    `imap.Session.last_uid`), or None). A message arriving after the check has a UID above
    it.
    """
    deadline = time.monotonic() + args.timeout
    with conn.cursor() as cur:
        secret = secret_of(cur, mailbox.id)
    if not secret:
        return outcome.Outcome(outcome.ERROR, None, NO_SECRET), None
    start = None
    try:
        with imap.connect(mailbox.pop3_host, mailbox.pop3_port, mailbox.pin, deadline) as session:
            session.login(render.login_of(mailbox), secret)
            examined = session.examine(imap.INBOX)
            if start_mark:
                start = (examined.uidvalidity, session.last_uid(examined))
    except imap.AuthFailed as err:
        return outcome.Outcome(outcome.AUTH_FAILED, None, joined(str(err))), None
    except imap.Failure as err:
        return outcome.Outcome(outcome.ERROR, None, joined(str(err))), None
    return outcome.Outcome(outcome.OK, None, None), start


def deliver(argv, body, deadline, grace):
    """The delivery filter on one message: (its exit code, its stderr), or None when it ran
    past the deadline by the grace and its process group was killed."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, start_new_session=True)
    with process:
        try:
            _, err = process.communicate(
                body, timeout=max(0.0, deadline - time.monotonic()) + grace)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            return None
    return process.returncode, err.decode("utf-8", "replace")


def filter_said(argv, err):
    """The filter's own lines, by the name it was started as, and nothing else it printed."""
    own = os.path.basename(argv[0]) + ":"
    return [line.strip() for line in err.splitlines() if line.startswith(own)]


def joined(*clauses):
    return "; ".join(c for c in clauses if c)[:outcome.DETAIL_MAX] or None


class Run:
    """What one run has done so far, and the outcome each way of ending it gives."""

    def __init__(self, conn, mailbox, argv, deadline, grace, seconds):
        self.conn, self.mailbox, self.argv = conn, mailbox, argv
        self.deadline, self.grace, self.seconds = deadline, grace, seconds
        self.filed = self.passed = 0
        self.waiting = 0  # messages above the mark not yet filed when the run stopped
        self.oversized = []  # (uid, size) of each message passed over the cap

    def tally(self):
        said = []
        if self.filed:
            said.append(f"{self.filed} filed")
        if self.passed:
            said.append(f"{self.passed} expunged at the provider before being read, passed")
        for uid, size in self.oversized:
            said.append(f"message {uid} of {size} bytes is over the {imap.MESSAGE_CAP}-byte cap: "
                        "skipped without being downloaded, and kept at the provider")
        if self.waiting:
            said.append(f"{self.waiting} still waiting above the mark")
        return said

    def failed(self, words, cause, **fields):
        return outcome.Outcome(outcome.ERROR, cause, joined(words, *self.tally()), **fields)

    def out_of_time(self, killed=None):
        bound = f"the run's bound of {int(self.seconds)} s"
        stopped = (f"the delivery filter had not finished message {killed} by {bound} and the "
                   "grace after it, and was killed" if killed is not None else
                   f"stopped between messages at {bound}")
        if self.filed:
            return outcome.Outcome(outcome.OK, None, joined(stopped, *self.tally(),
                                                            "the next run takes the rest"))
        return self.failed(f"timed out after {int(self.seconds)} s with nothing filed: "
                           f"{stopped}", outcome.TIMEOUT)

    def refused(self, uid, code, err):
        """The filter's answer on one message, other than filed."""
        words = joined(f"message {uid}: the delivery filter exited {code}",
                       *filter_said(self.argv, err))
        if code == outcome.EX_TEMPFAIL:
            return self.failed(words, outcome.TRANSIENT, held=True)
        if code == outcome.EX_CANTCREAT:
            return self.failed(words, outcome.STORE, store_held=True,
                               scanner_answered=True)
        return self.failed(words, outcome.STUCK_MESSAGE, message_level=True, retr_number=uid,
                           scanner_answered=True)

    def collect(self, session, secret):
        mailbox = self.mailbox
        session.login(render.login_of(mailbox), secret)
        examined = session.examine(imap.INBOX)
        if examined.uidvalidity != mailbox.imap_uidvalidity:
            return outcome.Outcome(outcome.ERROR, outcome.MARK, joined(
                f"the INBOX's UIDVALIDITY is {examined.uidvalidity}, not the mark's "
                f"{mailbox.imap_uidvalidity}: the provider renumbered it, and no UID under the "
                "mark can be trusted; nothing is collected until the mailbox is deactivated "
                "and activated again"))
        if examined.uidnext is not None and examined.uidnext - 1 < mailbox.imap_last_uid:
            return outcome.Outcome(outcome.ERROR, outcome.MARK, joined(
                f"the INBOX's next UID is {examined.uidnext}, at or under the mark's "
                f"{mailbox.imap_last_uid} of the same UIDVALIDITY: the provider numbered it "
                "again without saying so, and its messages under the mark would never be "
                "collected; nothing is collected until the mailbox is deactivated and "
                "activated again"))
        uids = session.uids_above(mailbox.imap_last_uid, session.last_uid(examined))
        for index, uid in enumerate(uids):
            self.waiting = len(uids) - index
            if time.monotonic() >= self.deadline:
                return self.out_of_time()
            try:
                size = session.size(uid)
                if size is not None and size > imap.MESSAGE_CAP:
                    with self.conn.cursor() as cur:
                        why = pass_over(cur, mailbox, uid, size)
                    if why is not None:
                        return self.failed(f"message {uid} of {size} bytes is over the cap and "
                                           f"the mark was not advanced past it: {why}",
                                           outcome.UNRECORDED)
                    self.oversized.append((uid, size))
                    continue
                message = session.fetch(uid)
            except imap.NotSent:
                raise  # the session's failure: nothing was asked about this message
            except (imap.MessageRefused, imap.Unreachable) as err:
                # the provider's refusal of this message, whatever its code, a BYE while it
                # answered, or a connection that failed over it: the scanner was never
                # reached, and the bounded retry bounds it
                return self.failed(str(err), outcome.STUCK_MESSAGE, message_level=True,
                                   retr_number=uid)
            if message is None:
                self.passed += 1  # expunged since the search: there is nothing to file
            else:
                done = deliver(self.argv, message.data, self.deadline, self.grace)
                if done is None:
                    return self.out_of_time(killed=uid)
                if done[0] != 0:
                    return self.refused(uid, *done)
                self.filed += 1
            with self.conn.cursor() as cur:
                why = advance(cur, mailbox, uid)
            if why is not None:
                what = "expunged at the provider" if message is None else "filed"
                return self.failed(f"message {uid} was {what} and the mark was not advanced "
                                   f"past it: {why}", outcome.UNRECORDED)
        self.waiting = 0
        return outcome.Outcome(outcome.OK if self.filed else outcome.NO_NEW_MAIL, None,
                               joined(*self.tally()) if self.passed or self.oversized else None)


def collect(conn, mailbox, args, grace):
    """One run of an IMAP row the runner has locked and re-read; its `Outcome`, or `FROZEN`
    when it waits for its hour (`waiting`) and nothing is to be recorded.

    `args` is the runner's command line: its `timeout`, `bindir` and `hold_bound_seconds`.
    `grace` is how long past the deadline a running filter is waited for.
    """
    deadline = time.monotonic() + args.timeout
    if mailbox.imap_uidvalidity is None or mailbox.imap_last_uid is None:
        return outcome.Outcome(outcome.ERROR, outcome.MARK, NO_MARK)
    held = waiting(conn, mailbox, asked=args.only is not None)
    if held is not None:
        return held
    try:
        argv = render.delivery_argv(mailbox, args.bindir, args.hold_bound_seconds)
    except render.RenderError as err:
        return outcome.Outcome(outcome.ERROR, outcome.TRANSIENT, str(err))
    with conn.cursor() as cur:
        secret = secret_of(cur, mailbox.id)
    if not secret:
        return outcome.Outcome(outcome.ERROR, outcome.TRANSIENT, NO_SECRET)

    run = Run(conn, mailbox, argv, deadline, grace, args.timeout)
    try:
        with imap.connect(mailbox.pop3_host, mailbox.pop3_port, mailbox.pin, deadline) as session:
            return run.collect(session, secret)
    except imap.AuthFailed as err:
        # a refused credential is its own status, never classified
        return outcome.Outcome(outcome.AUTH_FAILED, None, joined(str(err)))
    except imap.Deadline:
        return run.out_of_time()
    except imap.Unreachable as err:
        return run.failed(str(err), outcome.UNREACHABLE)
    except imap.ServerError as err:
        return run.failed(str(err), outcome.TRANSIENT)
