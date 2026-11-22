"""The queue the administration interface writes, performed here by the pass.

The interface changes rows; everything that touches a disk is a request row it queues
and this module performs. The pass drains the queue at the end of its own
run, after the fan-out and never before it.

⛔ A REQUEST THAT WAITS ON A PROVIDER NEVER HOLDS THE FAN-OUT. The kinds of
`PROVIDER` run the fetch runner or wait for its lock or a snapshot's, for up to half an
hour; the pass is a oneshot, so while it waited no domain was fanned out. They are drained
by `maildivvy-pass --provider-requests`, in a unit of its own beside the pass, and the pass
drains every other kind. None of them reads a message row, which is what
orders behind the fan-out.

⛔ ONE REQUEST PER TRANSACTION, IN THREE. The claim commits on its own, so a
handler that dies cannot un-claim a request and spin on it; the handler runs in a
transaction of its own; and the outcome is written in a further transaction, AFTER the
rollback, so the reason survives the failure that produced it. An unknown kind is a
failed request, never a silently skipped one.

⛔ A TOP-UP AND A CONNECT LINK IN BATCHES, EACH ITS OWN TRANSACTION. The selector
skips every message that already has a delivery row, so these two kinds go on from where
they stopped and gain nothing from being one transaction of any size: 500,000 names were
one of ten minutes, during which no domain fanned out (measured). A batch is its names,
their directories' fsync, its rows and its commit, with the count so far written on the
request in the same transaction. Between two batches the drain's budget is read: past
it the request goes back to `queued`, where its age keeps its place, and the next run
fans out before it goes on. A failure takes back the names of the batch under way and
nothing a commit accounts for. Every other kind stays one transaction.

⛔ THE NAMES GO WITH THE ROWS, WHATEVER THE CONNECTION DOES. When the
handler raised, nothing of its transaction is committed and the names it made go, though
the rollback itself raises on a connection that died. When the COMMIT raised, its
transaction may be there all the same: whether it is, is read off the request's row
(`landed`) before any name is touched, because a row whose name was taken back is the
defect nothing reports. The outcome is written on a second connection when the first
is lost, and the drain ends there.

⛔ A NAME GOES FIRST AND ITS ROW SECOND, where the names are taken out of a
mailbox that stays: the rows are the list of what to unlink, and a row deleted first
leaves a name nothing accounts for. A mailbox deleted WHOLE is the other way round,
below: its directory goes whole, so it needs no list.

⛔ A DELETED MAILBOX'S ROWS GO FIRST AND ITS DIRECTORIES AFTER THE COMMIT. A
client logged in while its mailbox is deleted carries on: its next command makes the
maildir and both index trees again, so a tree removed under it comes back belonging to
no row, and the next mailbox for that login would inherit it.
Dovecot lets nobody log in once the row is gone, but only once the deletion has
committed. So a deletion is one request in two steps: the handler deletes the rows and
lists in `Context.gone` what it leaves; that list is written on the request row in the
same transaction, and it commits. Then the drainer asks Dovecot to end every session of
those logins, waits until none is left, removes the directories and clears the list.
A list still on a failed request is what is left to remove, and every later drain
tries it again (`remove_left`).

⛔ A MESSAGE'S FILE IS LOOKED UP IN THE FOLDER IT IS IN. A withheld message's
file is in the quarantine folder, and a released message's still is - only a `delivered`
message's is in INBOX. Measured on the predecessor: a release that asked INBOX for the
quarantine's number found another message, hit EEXIST (success) and reported "released
to 3 mailboxes" having linked nothing; had the receivers not held that other message
already, it would have linked somebody else's mail into all three.

⛔ A HANDLER LINKS BY THE ROW'S BASE NAME, NEVER BY ITS UID (`0100`). A connect, a top-up, a
deliver-one and a release find a message's file from the base name its row carries,
which names that one file whatever Dovecot's numbering does: no `doveadm` is asked
and no numbering checked. A row the pass has not named yet (written by the previous
release, its folder not ticked since) fails the request, saying so.

⛔ THE RANGE'S END BOUND LIVES IN THE QUERY, SPELT ONCE. `SELECTOR` below is
shared word for word by the set a top-up delivers and by the number a screen states
beforehand (`count_for`). Measured on the predecessor:
with the bound left to the callers, the screen counted to the last second of the day
and the queued request to midnight, so *every* single-day range stated a number and
delivered nothing.

⛔ THE SPAM CONDITION IS THE BULK SELECTOR'S ALONE. A release and
a deliver-one are an administrator's per-message act, so neither reads the domain's
switch or the message's verdict: the one hands one named message to one named person,
the other overrules the antivirus for everybody and is the only way a withheld message
ever reaches anyone. `spam_reaches_people` is spelt in this file exactly once, inside
`SELECTOR`, and a unit test refuses a second spelling.

⛔ DELETING A PROVIDER MAILBOX TAKES THE FETCHER'S OWN LOCK, BLOCKING. The
runner renders every configuration from rows it read at the start of its run, so a
deletion that lands two seconds into a run has the state directory written back a
second later and the state outlives the row (measured on the predecessor). The
namespace is `fetch/locks.py`'s, imported, never spelt a second time. It
takes the snapshot's own lock after it, blocking too, and removes the mailbox's snapshot
with its fetch state; a discard of a snapshot takes that lock blocking as well,
so it waits for the slice in progress, and is a provider kind for it.

⛔ EVERY SUCH WAIT HAS A BOUND: the longest the holder may hold the lock, the
import's a minute. A holder past it is not running - an import suspended in a terminal, a
process stopped - and waiting on would hold the queue, and in the pass every domain's
fan-out, until the unit's timeout. The request fails saying who holds the lock, and the
queue goes on.

⛔ A MAILBOX'S OR A DOMAIN'S DIRECTORIES GO TOGETHER, FROM ONE PLACE: the store directory and both index trees, which are on another disk. A
second place that removes them is a second place to forget one, and fourteen index
trees belonging to no row were found on the predecessor's index disk.

⛔ THE JOURNAL ROW NAMES THE ADMINISTRATOR WHO ASKED, NOT THE DAEMON, carries
the request's own break-glass flag, and carries `request_id`, so the journal screen's
join finds the outcome this module wrote on the request row. A request naming nobody
fails rather than being journaled as the pipeline's own act.
"""

import datetime
import json
import os
import shutil
import subprocess
import sys
import time
from functools import partial
from pathlib import Path
from typing import NamedTuple

from maildivvy.backup import status as backup_status
from maildivvy.fanout import ledger
from maildivvy.fetch import locks, runner, snapshot
from maildivvy.lib import adminlock, doveadm, fetchpaths, store

INBOX = ledger.INBOX
REASON_MAX = 2000        # what `request.result` keeps of a failure
DETAIL_MAX = 300         # of another program's output, in a journal detail

# A withheld message has no delivery row for anybody, which is indistinguishable from
# one the pass has not reached yet - so the STATE is what keeps a top-up off it.
DELIVERABLE = ("delivered", "released")
# "All of it" is a wide pair, never an absent one, and a plain calendar date,
# because the selector's end bound casts to one.
WIDE_UNTIL = "9999-12-31"

AUTH_TIMEOUT = 600       # four commands with a provider that may answer slowly
REFETCH_TIMEOUT = 1800   # a whole mailbox may be retrieved
SESSIONS_END = 15        # seconds a deletion waits for the sessions it ended to go
# ⛔ The pass's drain claims no new request once it has drained this long: every
# domain's fan-out waits for the drain to end, since the next tick of the pass's timer
# starts only once this run is over. A top-up or a connect reads it between two batches
# and goes back in the queue past it; a request of any other kind runs to its end.
DRAIN_BUDGET = 120       # seconds
# ⛔ NO HANDLER WAITS FOR A LOCK WITHOUT A BOUND. Each lock another program holds is
# waited for no longer than that program may hold it; past that the holder is not running
# (an import suspended in a terminal, a process stopped) and the request fails saying so,
# and the queue goes on. The import stops within seconds of seeing a deletion asked for,
# and the interface holds the last-administrator lock for one statement or two; a
# collection holds the fetch's lock for its timeout and the delivery in hand after it, a
# slice the snapshot's for its length and the message in hand.
IMPORT_WAIT = 60         # seconds
ADMIN_WAIT = 60
FETCH_WAIT = runner.DEFAULT_TIMEOUT + runner.STOP_GRACE + 60
SNAPSHOT_WAIT = snapshot.SLICE_SECONDS + snapshot.GRACE + 60
LOCK_NOT_AVAILABLE = "55P03"   # the SQLSTATE of a wait past `lock_timeout`
# The messages a top-up or a connect links and commits at a time: what a failure
# takes back at most, what a run holds in memory, and how long past its budget a drain
# can hold the fan-out.
BATCH = 10_000
# The rows one reading of the selector brings: ten batches, about what a run
# links within its budget. A reading costs all that is left of the selection, whatever
# its limit, since the lowest ids are taken of the whole; a page of one batch would read
# it once a batch.
PAGE = 100_000

# The kinds that wait on a provider: they run the fetch runner, or take its lock or the
# snapshot's blocking. Drained beside the pass, never by it.
PROVIDER = frozenset({"refetch", "test_credential", "activate_external_mailbox",
                      "delete_external_mailbox", "discard_snapshot"})


class RequestFailed(Exception):
    """Ends the request `failed`, with this text as the reason the interface shows."""


class Context(NamedTuple):
    """Where the handlers work. The product fixes its layout; none of this is a setting."""

    store_root: Path = store.STORE_ROOT
    index_root: Path = store.INDEX_ROOT
    fetch_state_root: Path = fetchpaths.STATE_DIR
    snapshot_root: Path = store.SNAPSHOT_ROOT   # the IMAP mailboxes' snapshots
    fetch_runner: Path = fetchpaths.BINDIR / "maildivvy-fetch"
    # What the newest backup run left for the rest of the machine.
    backup_status: Path = backup_status.STATUS
    # The names THIS request made, each one new. `drain` gives every request
    # a list of its own and takes them back when the request fails; None is no record.
    made: list | None = None
    # What THIS request's deletion leaves to after its commit: `[label, account]`
    # for a mailbox's three directories, `[label, None]` for the domain's own, in the
    # order they go. `drain` gives every request a list of its own.
    gone: list | None = None
    # Called between two batches of a top-up or a connect with the cursor and the count so
    # far: `drain`'s commits the batch and reads its budget. None links
    # everything in the caller's one transaction.
    batch: object | None = None
    # The year folders THIS run of a request made and subscribed, `(login, folder)` each:
    # once a run, not once a message. `drain` gives every request a set of its
    # own; None asks Dovecot for each message.
    folders: set | None = None


class Request(NamedTuple):
    """One claimed row. `asked_by` and `break_glass` are columns, never payload."""

    id: int
    kind: str
    target: str | None
    payload: dict
    asked_by: str
    break_glass: bool


class Mailbox(NamedTuple):
    id: int
    account: str
    label: str
    as_of: datetime.datetime
    domain_id: int

    @property
    def login(self):
        return f"{self.account}@{self.label}"


# --- the queue itself ------------------------------------------------------------------

# SKIP LOCKED: a second drainer takes the next row rather than waiting for this one.
# The second condition picks the drainer's half of the kinds: `PROVIDER`'s, or every
# other kind, an unknown one included, so that one is claimed and failed.
CLAIM = """
    UPDATE request SET state = 'running'
     WHERE id = (SELECT id FROM request WHERE state = 'queued' AND (kind = ANY(%s)) = %s
                  ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1)
 RETURNING id, kind, target, payload, asked_by, break_glass
"""
FINISH = "UPDATE request SET state = %s, result = %s, finished_at = now() WHERE id = %s"

# ⛔ A RUN STOPPED INSIDE A HANDLER LEAVES ITS REQUEST `running`, AND NOTHING ELSE FINISHES
# IT: the claim commits first. Each drainer holds a session advisory lock of its
# own half while it drains, key 0 the pass's and 1 the provider drainer's, let go
# only when its connection closes. Holding it, the drainer knows no other run of it is
# performing anything, so every row of its kinds still `running` is one a stopped run left,
# and it is failed before anything is claimed. Not taken, another run of the same drainer
# is draining - a pass run by hand beside the timer's - and this one leaves the queue to it.
DRAINING = 0x6D72  # 'mr'
STOPPED = "the pass was stopped while performing it"
# What the row said is kept after the reason: for a top-up, how many messages its
# committed batches linked.
LEFT_RUNNING = """
    UPDATE request SET state = 'failed', finished_at = now(),
           result = %s || coalesce('; it had said: ' || nullif(result, ''), '')
     WHERE state = 'running' AND (kind = ANY(%s)) = %s
"""

# ⛔ WHAT A TRANSACTION OF A HANDLER SAYS OF ITSELF IS WRITTEN IN IT, ON THE REQUEST'S OWN
# ROW: a batch its count so far, as the number the next run goes on from and as
# the words the journal screen shows while the request runs or waits; the last transaction
# that it committed. Read back, either tells whether a COMMIT that raised is there
# (`landed`). No column and no grant is new: the pipeline writes this table's rows.
PROGRESS = ("UPDATE request SET result = %s, "
            "payload = payload || jsonb_build_object('linked', %s::bigint) WHERE id = %s")
COMMITTED = "UPDATE request SET payload = payload || jsonb_build_object('committed', true) WHERE id = %s"
# ⛔ FOR UPDATE: the transaction in doubt wrote this row, so it holds the row until it has
# ended one way or the other, and this reading waits for that instead of racing it.
SAID = "SELECT payload -> %s FROM request WHERE id = %s FOR UPDATE"
SAID_WAIT = "30s"        # how long that reading waits before it answers "not known"
# ⛔ Back to `queued`, never left `running`: a `running` row with no drainer is one a
# stopped run left, to the next drain and to health alike. `created_at` is untouched, so
# the claim, which takes the oldest, takes it up again first.
PUT_BACK = "UPDATE request SET state = 'queued' WHERE id = %s AND state = 'running'"

MAILBOX_ROW = """
    SELECT m.id, a.login, d.label, m.as_of, m.domain_id
      FROM mailbox m JOIN account a ON a.id = m.account_id JOIN domain d ON d.id = m.domain_id
     WHERE m.id = %s
"""
RECEIVERS = "SELECT mailbox_id, account FROM mailbox_receives WHERE domain_id = %s ORDER BY mailbox_id"
# ⛔ Only a targeted deliver-one relinks over a row that is already `linked` - a
# targeted undelete, and the one act allowed to put back what somebody threw away.
RELINK = """
    INSERT INTO delivery (message_id, mailbox_id, state, linked_at)
    VALUES (%s, %s, 'linked', now()) ON CONFLICT (message_id, mailbox_id)
    DO UPDATE SET state = 'linked', linked_at = now()
"""

# ⛔ ONE SELECTOR, ONE BOUND. The start is an instant or a bare date, and
# a bare date is already the first moment of its day; the END is cast to a calendar day
# and the bound is `< (that day + 1)`, so a range of one day is that day entire. Both
# the set that is delivered and the number a screen states beforehand read this text.
SELECTOR = """
      FROM message m JOIN domain d ON d.id = m.domain_id
     WHERE m.domain_id = %s
       AND m.state = ANY(%s)
       AND m.archive_uid IS NOT NULL
       AND m.received_at >= %s
       AND m.received_at < (%s::date + 1)
       AND (d.spam_reaches_people OR NOT m.is_spam)
       AND NOT EXISTS (SELECT 1 FROM delivery dl
                        WHERE dl.message_id = m.id AND dl.mailbox_id = %s)
       AND NOT EXISTS (SELECT 1 FROM message o
                        WHERE o.id = m.report_of AND o.state <> 'withheld')
"""
# ⛔ The last condition: a report is true only while the message it replaces
# is withheld. A release takes the report's names and rows away and leaves its own row
# `delivered` with an archive number, so without it every later top-up handed the report
# back out to anybody without a row.
# ⛔ A page at a time, after the last id of the page before: the selection of an
# archive of millions is never held whole. The conditions are still `SELECTOR`'s alone.
AFTER = " AND m.id > %s ORDER BY m.id LIMIT %s"
SELECT_FOR = "SELECT m.id, m.archive_base, m.state" + SELECTOR + AFTER
COUNT_FOR = "SELECT count(*)" + SELECTOR

# ⛔ NAMED, NOT WRITTEN INLINE, because the acceptance tests plan these exact texts at a
# year's volume: `delivery (mailbox_id)` serves the first two and
# `message (report_of)` the third. A copy in a test would prove nothing about these.
MAILBOX_NAMES = "SELECT count(*) FROM delivery WHERE mailbox_id = %s"
MAILBOX_UNLINK = "DELETE FROM delivery WHERE mailbox_id = %s"
REPORTS_OF = "SELECT id, archive_base, archive_uid FROM message WHERE report_of = %s ORDER BY id"


def selector_params(mailbox_id, domain_id, since, until):
    """The one parameter order both readings of `SELECTOR` use."""
    return (domain_id, list(DELIVERABLE), since, until, mailbox_id)


def select_for(cur, mailbox_id, domain_id, since, until, after=0):
    """The archived messages this mailbox has not been given yet, in range: one page of
    them, the `PAGE` with the lowest ids above `after`."""
    cur.execute(SELECT_FOR, (*selector_params(mailbox_id, domain_id, since, until), after,
                             PAGE))
    return cur.fetchall()


def count_for(cur, mailbox_id, domain_id, since, until):
    """How many `select_for` would deliver - the number a screen states beforehand.

    Written here, beside the selector, because the two must run the same bound: a
    condition in one that the other lacks is a screen stating a number it then does not
    deliver.
    """
    cur.execute(COUNT_FOR, selector_params(mailbox_id, domain_id, since, until))
    return cur.fetchone()[0]


# --- small readings ------------------------------------------------------------------------------


def need(payload, key):
    value = (payload or {}).get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise RequestFailed(f"the request names no {key}")
    return value


def need_int(payload, key):
    try:
        return int(need(payload, key))
    except (TypeError, ValueError):
        raise RequestFailed(f"{key} {(payload or {}).get(key)!r} is not a row id") from None


def need_date(payload, key):
    """One end of a top-up's range: a calendar date, never an instant."""
    value = need(payload, key)
    if isinstance(value, datetime.datetime):
        raise RequestFailed(f"{key} {value.isoformat()} is an instant; both ends of a "
                            "range are calendar days")
    if isinstance(value, datetime.date):
        return value
    try:
        return datetime.date.fromisoformat(str(value))
    except ValueError:
        raise RequestFailed(f"{key} {value!r} is not a calendar date") from None


def one(cur, sql, params, complaint):
    cur.execute(sql, params)
    row = cur.fetchone()
    if row is None:
        raise RequestFailed(complaint)
    return row


def mailbox_row(cur, mailbox_id):
    return Mailbox(*one(cur, MAILBOX_ROW, (mailbox_id,), f"no mailbox {mailbox_id}"))


def text(value):
    """A journal detail is timestamps, counts and words; `json.dumps` refuses a date."""
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    return value


def journal(cur, request, action, target, detail):
    """One journal row for what this request did.

    The actor is the administrator the request names, never this daemon, and the
    break-glass flag is the request's own: a flag dropped here records a break-glass act
    as an ordinary one. `request_id` is what the journal screen joins the outcome by.
    """
    actor = (request.asked_by or "").strip()
    if not actor:
        raise RequestFailed("the request names no administrator, and the journal row for "
                            "what it does must name the person who asked")
    cur.execute(
        "INSERT INTO audit (actor, action, target, detail, break_glass, request_id) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (actor, action, target, json.dumps({k: text(v) for k, v in detail.items()}),
         bool(request.break_glass), request.id))


# --- names on disk -------------------------------------------------------------------------------


def make_maildir(home, root):
    """A mailbox's maildir, made by the mail owner at 0700.

    Never `doveadm mailbox create INBOX`: to Dovecot the maildir IS the INBOX, so that
    create always answers "Mailbox already exists" and fails the request.
    """
    return store.make_maildir(store.maildir(home), root)


def unnamed(message_id, label):
    """A row with an archive number and no base name: the previous release's, in a folder
    the pass has not ticked since the upgrade (`0100`)."""
    return RequestFailed(f"message {message_id} of {label} has no archive name yet: the pass "
                         "gives it on its next tick of the folder; ask again after it")


def archive_file(label, folder, base, context):
    """One archived message's file, from its base name (`0100`): no `doveadm`, and the
    same file whatever Dovecot's numbering."""
    folder_maildir = store.maildir(store.archive_home(label, context.store_root), folder)
    path = store.resolve(folder_maildir, base)
    if path is None:
        raise RequestFailed(f"{base} is not in {store.ARCHIVE}@{label}'s {folder} any more")
    return path


def archive_files(label, folder, bases, root):
    """`{base name: file}` for many messages of one archive folder, each found by its
    name alone (`0100`). One whose name is not there is left out, and `link_name` asks for
    it alone, which looks again and fails the request with its reason."""
    folder_maildir = store.maildir(store.archive_home(label, root), folder)
    found = {}
    for base in bases:
        path = store.resolve(folder_maildir, base)
        if path is not None:
            found[base] = path
    return found


def year_folders(login, folder, context):
    """A person's `Archives` and its year `folder`, made through Dovecot and subscribed, each
    once a run of this request: a folder made by mkdir is never listed,
    and most clients show subscribed folders alone.

    ⛔ DOVECOT OPENS NO BLOCKED PERSON'S MAILBOX (`mailbox_opens` holds active accounts), so
    their top-up of imported mail fails here, saying so, and goes on once they are unblocked
    and it is asked again.
    """
    done = context.folders if context.folders is not None else set()
    for each in (store.ARCHIVES, folder):
        if (login, each) in done:
            continue
        try:
            doveadm.subscribed_folder(login, each)
        except doveadm.DoveadmError as err:
            raise RequestFailed(f"{login}'s {each} could not be made and subscribed: {err}; "
                                "Dovecot opens no blocked person's mailbox, so unblock them "
                                "and ask again") from None
        done.add((login, each))


def name_in(source, mailbox, context):
    """One archive file's name in one person's mailbox; returns the directories touched.

    An imported message is old mail: named in `cur/`, with the archive's `\\Seen`,
    in `Archives/<YYYY>` of the year its name carries, told by its file's name
    alone, so the selector needs no column of its own and nothing records the
    folder. Every other one is new mail in `new/` of INBOX.
    """
    base = store.base_name(source)
    home = store.home(mailbox.label, mailbox.account, context.store_root)
    if store.imported(base) is None:
        return store.link_into(source, [store.maildir(home)], context.store_root,
                               made=context.made)
    folder = store.year_folder(base, store.ARCHIVES)
    year_folders(mailbox.login, folder, context)
    return store.link_imported(source, [store.maildir(home, folder)], context.store_root,
                               made=context.made)


def link_name(row, mailbox, context, source=None):
    """One archived message's name in one mailbox; returns the directories touched.

    `source` is the file as a lookup of many found it; a name renamed since (a flag set
    on the archive copy) is asked for again, alone.
    """
    _, base, state = row
    touched = None
    if source is not None:
        try:
            touched = name_in(source, mailbox, context)
        except FileNotFoundError:
            touched = None
    if touched is None:
        source = archive_file(mailbox.label, ledger.folder_of(state), base, context)
        touched = name_in(source, mailbox, context)
    return touched


def link_message(cur, row, mailbox, context, relink=False, source=None):
    """One archived message into one mailbox: the name first, then the row."""
    store.fsync_dirs(link_name(row, mailbox, context, source))
    cur.execute(RELINK if relink else ledger.LINK, (row[0], mailbox.id))


def link_messages(cur, rows, mailbox, context):
    """One batch into one mailbox: every name, each folder's files looked up
    together by their base names, then their directories' fsync, then every row. The names
    are durable before a row says so."""
    bases = {}
    for message_id, base, state in rows:
        if base is None:
            raise unnamed(message_id, mailbox.label)
        bases.setdefault(ledger.folder_of(state), []).append(base)
    files = {folder: archive_files(mailbox.label, folder, names, context.store_root)
             for folder, names in bases.items()}
    touched = set()
    for row in rows:
        touched.update(link_name(row, mailbox, context,
                                 source=files[ledger.folder_of(row[2])].get(row[1])))
    store.fsync_dirs(sorted(touched))
    for row in rows:
        cur.execute(ledger.LINK, (row[0], mailbox.id))


def so_far(request):
    """How many messages this request's committed batches linked, in every run of it."""
    try:
        return int(request.payload.get("linked") or 0)
    except (TypeError, ValueError):
        return 0


def progress(linked):
    """What a request says while it runs or waits between two runs."""
    return f"{linked} message(s) linked so far"


def link_range(cur, request, mailbox, since, until, context):
    """Every selected message into one mailbox, a batch at a time; returns how many this
    request linked, in every run of it.

    ⛔ Each run reads from the first id again: what is linked has a delivery row, and the
    selector skips it, which is all that makes a request taken up again, or asked again
    after a failure, go on from where it stopped. The last batch is left to the caller's
    commit, with the journal row, so a top-up of no more than a batch is one transaction
    as it always was.
    """
    linked, after = so_far(request), 0
    while True:
        page = select_for(cur, mailbox.id, mailbox.domain_id, since, until, after)
        more = len(page) == PAGE
        for start in range(0, len(page), BATCH):
            rows = page[start:start + BATCH]
            link_messages(cur, rows, mailbox, context)
            linked += len(rows)
            if (more or start + BATCH < len(page)) and context.batch is not None:
                context.batch(cur, linked)
        if not more:
            return linked
        after = page[-1][0]


def take_back(made):
    """Remove the names a failed request made; returns a complaint, or None.

    The request's rows are rolled back, so a name it made accounts for nothing: for a
    release it is a withheld message in a person's mailbox. Only names this request
    created are here - one that was already there is somebody's, and stays - and, of a
    request that links in batches, only those no commit accounts for yet. A person
    may have read the message in the seconds between, which moves the name to `cur/`
    with flags after it, or flagged an imported one named in `cur/` already; only
    when the name is gone is it looked for there, by its base name.
    """
    left, touched = [], []
    for path in reversed(made):
        path = Path(path)
        read = path.parent.parent / "cur"
        try:
            try:
                path.unlink()
                touched.append(path.parent)
                continue
            except FileNotFoundError:
                pass
            for moved in sorted(read.iterdir() if read.is_dir() else ()):
                base, info = store.name_parts(moved)
                if base == store.base_name(path) and info is not None:
                    moved.unlink()
                    touched.append(read)
        except OSError as err:
            left.append(f"{path}: {err}")
    try:
        store.fsync_dirs(touched)
    except OSError as err:
        left.append(f"fsync: {err}")
    made.clear()
    return (f"{len(left)} name(s) it made could not be taken back: " + "; ".join(left)
            if left else None)


def remove_names(home, inode, base):
    """Remove one message's names from every folder of one mailbox; returns how many.

    ⚠️ THIS IS THE ONE PATH THAT SCANS FOR A BASE NAME. Everywhere else a
    name is resolved from Dovecot's own storage id: exactly, or, in a person's own Sent,
    that base name with whatever flags the client set (`store.resolve_own`). A report
    that a person has read, flagged or filed away has a name and a folder of the
    person's own choosing, and no resolution from a storage id covers that. A name
    added between the listing and the unlink is not removed - the same race
    `store.resolve` describes - and there is no second pass. The inode is what
    identifies the file; the base name catches a name whose file the
    archive no longer holds.
    """
    removed = 0
    for entry in store.mailbox_files(home):
        if store.base_name(entry) == base or (inode is not None and entry.stat().st_ino == inode):
            entry.unlink()
            removed += 1
    return removed


def remove_tree(path):
    """Remove a directory and everything under it; a path that is not there is done."""
    path = Path(path)
    if path.exists():
        shutil.rmtree(path)
        return True
    return False


def remove_mailbox_files(label, account, context):
    """A mailbox's store directory and BOTH its index trees, from one place.

    They are on two disks, and an index tree left behind belongs to nothing: it is a
    leftover, not a cache.
    """
    removed = [remove_tree(store.home(label, account, context.store_root))]
    for tree in store.index_paths(label, account, context.index_root):
        removed.append(remove_tree(tree))
    return sum(1 for each in removed if each)


def rmdir_left(path):
    """`rmdir` one directory; returns a complaint when it was not empty.

    A directory still holding something after every row of it is gone is a fault worth
    leaving where somebody can see it. A recursive delete would hide exactly the case
    that needs looking at.
    """
    try:
        Path(path).rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        return f"{path} was NOT empty and was left"
    return None


def wait_for(cur, take, bound, held):
    """`take(cur)` - one blocking lock - waited for `bound` seconds at most.

    `held` says who holds it and what to do, as the refusal's first words. The bound is
    this statement's alone: it is set back to the session's before anything else runs.
    """
    cur.execute("SET LOCAL lock_timeout = %s", (f"{int(bound)}s",))
    try:
        take(cur)
    except Exception as err:
        if getattr(err, "pgcode", None) == LOCK_NOT_AVAILABLE:
            raise RequestFailed(f"{held}; it was not let go within {int(bound)} s, and "
                                "nothing was changed") from None
        raise
    cur.execute("SET LOCAL lock_timeout TO DEFAULT")


def wait_for_import(cur, domain_id):
    """The import of this domain, waited for under its bound."""
    wait_for(cur, partial(locks.xact_lock, mailbox_id=domain_id, namespace=locks.IMPORT),
             IMPORT_WAIT, "an import of this domain holds its lock: stop it (or let it end), "
             "then ask again")


def unlink_mailbox(cur, mailbox, context):
    """One mailbox out of the ledger, its directories left to after the commit. The directory goes whole, so no name needs its row to be found.

    ⛔ The import of its domain is waited for first: a sent import writes into this
    mailbox. The lock is held until the drain commits, and the import stops as soon as it
    sees this deletion asked for; one that does not, suspended or stopped, fails this
    deletion after IMPORT_WAIT.
    """
    wait_for_import(cur, mailbox.domain_id)
    cur.execute(MAILBOX_NAMES, (mailbox.id,))
    names = cur.fetchone()[0]
    cur.execute(MAILBOX_UNLINK, (mailbox.id,))
    cur.execute("DELETE FROM mailbox WHERE id = %s", (mailbox.id,))
    context.gone.append([mailbox.label, mailbox.account])
    return names


# --- after a deletion's commit: the sessions end, then the directories go ---------

# Written in the handler's own transaction, so the list is there exactly when the rows
# are gone; cleared once the directories are.
LEAVE = "UPDATE request SET payload = payload || jsonb_build_object('gone', %s::jsonb) WHERE id = %s"
CLEAR = "UPDATE request SET payload = payload - 'gone' WHERE id = %s"
# What earlier deletions left: their rows are gone and their directories were not.
LEFT = """
    SELECT id, payload -> 'gone', coalesce(result, '') FROM request
     WHERE state = 'failed' AND payload ? 'gone' AND (kind = ANY(%s)) = %s ORDER BY id
"""
RETRIED = ("UPDATE request SET state = 'done', result = %s, finished_at = now(), "
           "payload = payload - 'gone' WHERE id = %s")
# What a retry could not remove because a row holds the slot again: the list is that, and
# the request stays failed, saying so.
KEPT = ("UPDATE request SET result = %s, "
        "payload = payload || jsonb_build_object('gone', %s::jsonb) WHERE id = %s")
# ⛔ A SLOT AN EARLIER DELETION HAS NOT CLEARED YET: its rows are gone and its
# directories are not, so a mailbox made there, or a domain given that label, would hold
# the deleted one's mail. A mailbox's slot is `[label, account]`; a domain's is every entry
# of its label. Read by the handlers that make a mailbox or a domain, and by the
# interface before it gives the slot a row again.
STILL_LISTED = """
    SELECT id FROM request
     WHERE state IN ('running', 'failed') AND payload ? 'gone'
       AND EXISTS (SELECT 1 FROM jsonb_array_elements(payload -> 'gone') AS entry
                    WHERE entry ->> 0 = %(label)s
                      AND (%(account)s::text IS NULL OR entry ->> 1 = %(account)s::text))
     ORDER BY id LIMIT 1
"""
# Whether a row holds a slot again: a mailbox for `[label, account]`, the domain for its
# archive and its own directories.
HELD = """
    SELECT EXISTS (SELECT 1 FROM domain d WHERE d.label = %(label)s
                   AND (%(account)s::text IS NULL OR %(account)s::text = %(archive)s OR EXISTS (
                      SELECT 1 FROM mailbox m JOIN account a ON a.id = m.account_id
                       WHERE m.domain_id = d.id AND a.login = %(account)s::text)))
"""


def mask_of(label, account):
    """The logins one entry of `gone` ends: one mailbox's, or every one of a domain's."""
    return f"*@{label}" if account is None else f"{account}@{label}"


def end_sessions(masks):
    """Ask Dovecot to end every session of these logins, and wait until none is left.

    Returns a complaint, or None once none is. ⛔ Never removes anything itself: a
    directory removed while a session is still going is made again by its next command.
    """
    bound = SESSIONS_END
    try:
        for mask in masks:
            doveadm.kick(mask)
        deadline = time.monotonic() + bound
        while True:
            still = [mask for mask in masks if doveadm.sessions(mask)]
            if not still:
                return None
            if time.monotonic() >= deadline:
                return (f"the sessions of {', '.join(still)} did not end within {bound} s "
                        "of being asked to")
            time.sleep(0.2)
    except doveadm.DoveadmError as err:
        return f"the sessions could not be ended: {err}"


def remove_gone(gone, context):
    """The second step: end the sessions, then remove what `gone` lists, in its order.

    Returns `(left, complaint)`: `left` the domain directories `rmdir` left in place and
    reported, which is not a failure; `complaint` why nothing, or not all,
    was removed, which is.
    """
    complaint = end_sessions(sorted({mask_of(label, account) for label, account in gone}))
    if complaint:
        return [], complaint + "; nothing was removed"
    left = []
    try:
        for label, account in gone:
            if account is not None:
                remove_mailbox_files(label, account, context)
                continue
            left += [found for found in (rmdir_left(Path(context.store_root) / label),
                                         rmdir_left(Path(context.index_root) / "idx" / label),
                                         rmdir_left(Path(context.index_root) / "ctl" / label))
                     if found]
    except OSError as err:
        return left, f"a directory could not be removed: {err}"
    return left, None


def after_commit(gone, context):
    """The outcome of a deletion whose rows committed: `(state, text to add)`."""
    left, complaint = remove_gone(gone, context)
    words = "; ".join(left)
    if complaint:
        return "failed", (f"its rows are deleted, but {complaint}; the next run tries "
                          "again" + (f"; {words}" if words else ""))
    return "done", words


def remove_left(conn, waiting, context):
    """Every directory an earlier deletion left (`LEFT`'s rows): tried again.

    ⛔ A slot a row holds again is not touched, and is not dropped either: the
    new row's directories are the same path, holding the deleted one's mail, which is a
    fault for somebody to look at, not a success. Its entry stays on the request, which
    stays failed, saying so.
    ⛔ Nothing here stops the drain: it runs before every claim, so a fault that raised
    would hold the whole queue for good. Each request's retry fails on its own, to stderr.
    """
    for request_id, gone, before in waiting:
        try:
            retry(conn, request_id, gone, before, context)
        except Exception as err:  # noqa: BLE001 - the queue goes on; the list stays for the next run
            conn.rollback()
            sys.stderr.write(f"maildivvy-pass: request {request_id}'s directories could not be "
                             f"tried again: {type(err).__name__}: {err}\n")


def retry(conn, request_id, gone, before, context):
    """One earlier deletion's list, tried again; the request is `done` once it is empty."""
    if isinstance(gone, str):
        gone = json.loads(gone)
    with conn.cursor() as cur:
        held = []
        for label, account in gone:
            cur.execute(HELD, {"label": label, "account": account, "archive": store.ARCHIVE})
            if cur.fetchone()[0]:
                held.append([label, account])
    conn.commit()
    free = [entry for entry in gone if entry not in held]
    left, complaint = remove_gone(free, context) if free else ([], None)
    if complaint:
        sys.stderr.write(f"maildivvy-pass: request {request_id} still leaves directories: "
                         f"{complaint}\n")
        return
    if held:
        masks = ", ".join(mask_of(*entry) for entry in held)
        said = (f"its rows are deleted, but {masks}'s directories were not removed before a "
                "row held that slot again: they hold the deleted mail and the new row's "
                "alike, and nothing removes them; delete what holds the slot, and the next "
                "run removes both")
        sys.stderr.write(f"maildivvy-pass: request {request_id}: {said}\n")
        with conn.cursor() as cur:
            cur.execute(KEPT, (said[:REASON_MAX], json.dumps(held), request_id))
        conn.commit()
        return
    words = ["the directories it left were removed by a later run",
             *left, f"it had said: {before}"]
    with conn.cursor() as cur:
        cur.execute(RETRIED, ("; ".join(words)[:REASON_MAX], request_id))
    conn.commit()


# --- the handlers --------------------------------------------------------------------------------


def not_listed(cur, label, account, what):
    """Fail the request when an earlier deletion has not cleared this slot."""
    cur.execute(STILL_LISTED, {"label": label, "account": account})
    found = cur.fetchone()
    if found is not None:
        raise RequestFailed(
            f"request {found[0]}, a deletion, has not finished removing the old directories "
            f"of {mask_of(label, account)}: {what} would hold the deleted mail. Delete it "
            "again; once the next run has removed both, make it again")


def create_domain(cur, request, context):
    """The archive's maildir, its quarantine folder, and its own read-only ACL.

    The ACL is on the archive's OWN INBOX, per mailbox, never a global or group rule
    matching `INBOX` by name - such a rule would open every person's INBOX to the
    administrators.
    """
    domain_id = need_int(request.payload, "domain_id")
    (label,) = one(cur, "SELECT label FROM domain WHERE id = %s", (domain_id,),
                   f"no domain {domain_id}")
    not_listed(cur, label, None, "this domain's archive")
    login = f"{store.ARCHIVE}@{label}"
    make_maildir(store.archive_home(label, context.store_root), context.store_root)
    try:
        doveadm.create_folder(login, store.QUARANTINE)
        doveadm.run(("acl", "set"), login, INBOX, *doveadm.ARCHIVE_ACL)
    except doveadm.DoveadmError as err:
        raise RequestFailed(str(err)) from None
    journal(cur, request, "create_domain", label, {"archive": login})
    return (f"made the archive for {label}, its {store.QUARANTINE} folder and the "
            "archive's own ACL on its INBOX")


def create_mailbox(cur, request, context):
    """The person's maildir. Giving them the mail that is already there is `connect`.

    ⛔ The two are separate units of work, and so two request rows: a mailbox
    is not complete until its connect has been QUEUED, and a connect that
    happened inside another kind would do disk work no row on the queue accounts for.
    """
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    not_listed(cur, mailbox.label, mailbox.account, "this mailbox")
    make_maildir(store.home(mailbox.label, mailbox.account, context.store_root),
                 context.store_root)
    journal(cur, request, "create_mailbox", mailbox.login, {"as_of": mailbox.as_of})
    return f"made the maildir for {mailbox.login}"


def connect(cur, request, context):
    """Everything archived since the mailbox was created.

    The wide end is the same plain far-future date a top-up's "all of it" spells;
    the start is the mailbox's own `as_of`, an instant, because mail that
    arrived earlier that day arrived before the mailbox existed. Linked in batches, as a
    top-up is.
    """
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    not_listed(cur, mailbox.label, mailbox.account, "this mailbox")
    linked = link_range(cur, request, mailbox, mailbox.as_of, WIDE_UNTIL, context)
    journal(cur, request, "connect", mailbox.login,
            {"messages": linked, "since": mailbox.as_of, "until": WIDE_UNTIL})
    return f"connected {linked} message(s) to {mailbox.login}"


def top_up(cur, request, context):
    """The messages that never reached a mailbox, over a stated range of calendar days.

    Both ends are required: "all of it" is a wide pair, never an absent one, so the size
    of what it will deliver is knowable before it runs. Linked in
    batches, each committed as it goes: the count it reports is every run's.
    """
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    since = need_date(request.payload, "since")
    until = need_date(request.payload, "until")
    linked = link_range(cur, request, mailbox, since, until, context)
    journal(cur, request, "top_up", mailbox.login,
            {"messages": linked, "since": since, "until": until})
    return f"topped up {linked} message(s) to {mailbox.login}, {since} to {until}"


def deliver_one(cur, request, context):
    """One named message to one named person. It may relink over a `linked` row.

    That is a targeted undelete, the only one, and it carries none of the bulk
    selector's spam condition: an administrator naming one message is not a bulk
    selector.
    """
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    message_id = need_int(request.payload, "message_id")
    row = one(cur, "SELECT id, archive_base, state, domain_id, archive_uid FROM message "
                   "WHERE id = %s", (message_id,), f"no message {message_id}")
    if row[3] != mailbox.domain_id:
        raise RequestFailed(f"message {message_id} is not a message of {mailbox.label}, "
                            f"which is the domain {mailbox.login}'s mailbox is in")
    if row[1] is None and row[4] is not None:
        raise unnamed(message_id, mailbox.label)
    if row[1] is None:
        raise RequestFailed(f"message {message_id} has no archive number: nothing of it "
                            "is in the archive to give a name to")
    if row[2] not in DELIVERABLE:
        # ⛔ The spam switch is not this act's to read, the STATE is. A
        # release is the only act that gives a withheld message to anybody.
        raise RequestFailed(f"message {message_id} is {row[2]}; only a release gives a "
                            "withheld message to anybody")
    link_message(cur, row[:3], mailbox, context, relink=True)
    journal(cur, request, "deliver_one", mailbox.login, {"message": message_id})
    return f"delivered message {message_id} to {mailbox.login}"


def release(cur, request, context):
    """The original to everyone who receives, its report away from every holder, in one go.

    Landing two of the three leaves a report contradicting a delivered message, or a
    message nobody can see beside a report saying it was blocked. The
    asymmetry is deliberate: the original goes to everyone who RECEIVES, the report goes
    from EVERYBODY WHO HOLDS IT whatever their state, because the report is false the
    moment the original is out. It carries no spam condition.
    """
    message_id = need_int(request.payload, "message_id")
    row = one(cur, "SELECT id, archive_base, state, domain_id, archive_uid FROM message "
                   "WHERE id = %s", (message_id,), f"no message {message_id}")
    _, base, state, domain_id, archive_uid = row
    if state != "withheld":
        raise RequestFailed(f"message {message_id} is {state}, not withheld; only a "
                            "withheld message is released")
    (label,) = one(cur, "SELECT label FROM domain WHERE id = %s", (domain_id,),
                   f"no domain {domain_id}")
    if base is None and archive_uid is not None:
        raise unnamed(message_id, label)
    if base is None:
        raise RequestFailed(f"message {message_id} has no archive number: nothing of it "
                            "is in the archive to release")
    cur.execute(REPORTS_OF, (message_id,))
    reports = cur.fetchall()
    # ⛔ Every report's file found before anything is linked or removed: a fault
    # finding one fails the release with nothing changed, never a report left standing.
    reports = [(report_id, report_file(report_id, report_base, report_uid, label, context))
               for report_id, report_base, report_uid in reports]

    cur.execute(RECEIVERS, (domain_id,))
    receivers = cur.fetchall()
    source = archive_file(label, ledger.folder_of(state), base, context) if receivers else None
    for mailbox_id, account in receivers:
        link_message(cur, (message_id, base, state),
                     Mailbox(mailbox_id, account, label, None, domain_id), context,
                     source=source)

    removed = 0
    for report_id, found in reports:
        removed += remove_report(cur, found, label, domain_id, context)
        cur.execute("DELETE FROM delivery WHERE message_id = %s", (report_id,))

    cur.execute("UPDATE message SET state = 'released' WHERE id = %s", (message_id,))
    journal(cur, request, "release", label,
            {"message": message_id, "mailboxes": len(receivers), "names_removed": removed})
    return (f"released message {message_id} to {len(receivers)} mailbox(es); "
            f"{removed} report name(s) removed")


def report_file(report_id, base, uid, label, context):
    """`(inode or None, base name)` of a report in the archive's INBOX, or None when its
    row has neither a base name nor a number: nothing of it was ever in the archive. A
    row with a number and no name yet fails the release (`0100`).

    ⛔ A FILE THAT IS NOT THERE STILL NAMES ITS BASE NAME, which is enough to find
    the names in people's mailboxes by; any failure reading it fails the release: read as
    gone, the release deleted the report's rows and the report stayed in every mailbox for
    good, saying the message is withheld beside the released message.
    """
    if base is None and uid is not None:
        raise unnamed(report_id, label)
    if base is None:
        sys.stderr.write(f"maildivvy-pass: the report {report_id} of {label} has no archive "
                         "name; its names could not be found\n")
        return None
    try:
        path = store.resolve(store.maildir(store.archive_home(label, context.store_root)), base)
        return (path.stat().st_ino if path is not None else None), base
    except (OSError, store.StoreError) as err:
        raise RequestFailed(f"the report {report_id} of {label} could not be read, so "
                            f"nothing was released: {err}") from None


def remove_report(cur, found, label, domain_id, context):
    """The report's names, from every mailbox of the domain, files first.
    `found` is `report_file`'s answer; None removes nothing."""
    if found is None:
        return 0
    inode, base = found
    cur.execute(RECEIVERS, (domain_id,))
    removed = 0
    for _, account in cur.fetchall():
        removed += remove_names(store.home(label, account, context.store_root), inode, base)
    return removed


def delete_mailbox(cur, request, context):
    """A person's mailbox in one domain: its rows, then, after the commit, its directories."""
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    names = unlink_mailbox(cur, mailbox, context)
    journal(cur, request, "delete_mailbox", mailbox.login, {"delivery_rows": names})
    return f"deleted {mailbox.login}: {names} delivery row(s), its maildir and both index trees"


OTHER_ACTIVE_ADMINS = ("SELECT count(*) FROM account "
                       "WHERE is_admin AND state = 'active' AND id <> %s")


def would_leave_no_administrator(cur, account_id):
    """True when deleting `account_id` would leave no active administrator.

    ⛔ Counted under the last-administrator lock the interface takes too, so
    two deletions of each other, performed one after the other or by two drainers at
    once, cannot both pass: the second waits for the lock, counts what the first left,
    and finds itself the last one. The interface checks this as well, but its reading
    is minutes old by the time the queue is drained, so the pipeline is the backstop.
    """
    cur.execute(OTHER_ACTIVE_ADMINS, (account_id,))
    return cur.fetchone()[0] == 0


def delete_account(cur, request, context):
    """A person and every mailbox they hold: the rows, then, after the commit, every
    mailbox's directories."""
    account_id = need_int(request.payload, "account_id")
    # ⛔ the lock FIRST, then the row: what is read after it is what the last decision left
    wait_for(cur, adminlock.lock, ADMIN_WAIT,
             "another decision about the administrators holds their lock")
    login, is_admin, state = one(cur, "SELECT login, is_admin, state FROM account WHERE id = %s",
                                 (account_id,), f"no account {account_id}")
    # ⛔ Re-checked here, not only when the deletion was queued: if two
    # administrators each queued the other's deletion, the second must find itself the last.
    if is_admin and state == "active" and would_leave_no_administrator(cur, account_id):
        raise RequestFailed(
            f"deleting {login} would leave no active administrator; it is the last one, and "
            "the last administrator stays. Give the flag to somebody else first.")
    cur.execute("SELECT id FROM mailbox WHERE account_id = %s ORDER BY id", (account_id,))
    boxes = [mailbox_row(cur, row[0]) for row in cur.fetchall()]
    names = sum(unlink_mailbox(cur, mailbox, context) for mailbox in boxes)
    cur.execute("DELETE FROM account WHERE id = %s", (account_id,))
    journal(cur, request, "delete_account", login,
            {"mailboxes": len(boxes), "delivery_rows": names})
    return f"deleted {login} and {len(boxes)} mailbox(es), {names} delivery row(s)"


def delete_external_mailbox(cur, request, context):
    """The provider mailbox in front of a domain; the domain and its archive stay.

    The domain's mapping is cleared FIRST: the key is ON DELETE RESTRICT, so a delete
    that has not unmapped is refused rather than cascaded. The fetcher's state
    lives outside the store, so no cascade reaches it and it is removed here, under the
    fetcher's own lock taken blocking. So is an IMAP mailbox's
    snapshot, under the snapshot's own lock, taken blocking after the fetcher's: a slice
    in progress is waited for, and none starts until this drain commits.
    """
    rid = need_int(request.payload, "external_mailbox_id")
    (canonical,) = one(cur, "SELECT address_canonical FROM external_mailbox WHERE id = %s",
                       (rid,), f"no external mailbox {rid}")
    # ⛔ HELD UNTIL THIS DRAIN COMMITS: a transaction-level advisory lock, so
    # the fetcher cannot take the lock back between the removal and the commit and rewrite
    # the state directory this handler is deleting. It is released by drain's commit or
    # rollback, never here.
    wait_for(cur, partial(locks.xact_lock, mailbox_id=rid), FETCH_WAIT,
             "a collection of this mailbox holds the fetch's lock for longer than one may run")
    wait_for(cur, partial(locks.xact_lock, mailbox_id=rid, namespace=locks.SNAPSHOT),
             SNAPSHOT_WAIT, "a slice of its snapshot holds the snapshot's lock for longer than "
             "one may run")
    cur.execute("UPDATE domain SET external_mailbox_id = NULL WHERE external_mailbox_id = %s",
                (rid,))
    unmapped = cur.rowcount
    cur.execute("DELETE FROM external_mailbox WHERE id = %s", (rid,))
    state = fetchpaths.state_dir(context.fetch_state_root, rid)
    removed = remove_tree(state)
    snapshot_removed = snapshot.discard(rid, context.snapshot_root)
    journal(cur, request, "delete_external_mailbox", canonical,
            {"domains_unmapped": unmapped, "fetch_state_removed": removed,
             "snapshot_removed": snapshot_removed})
    return (f"deleted the external mailbox {canonical} and its fetcher state"
            + (" and snapshot" if snapshot_removed else "")
            + f"; {unmapped} domain(s) unmapped, their archives kept")


# A discarded snapshot has no status, and ends now: the request it answered is not taken up
# again (`snapshot.WANTED`), and the next request starts a new one.
DISCARDED = ("UPDATE external_mailbox SET snapshot_status = NULL, snapshot_started_at = NULL, "
             "snapshot_finished_at = now(), snapshot_detail = NULL, snapshot_paused_since = NULL, "
             "snapshot_refused = NULL, snapshot_left_out = NULL WHERE id = %s")


def discard_snapshot(cur, request, context):
    """An IMAP mailbox's snapshot removed, and the row back to having none.

    ⛔ THE SNAPSHOT'S LOCK, TAKEN BLOCKING AND HELD UNTIL THIS DRAIN COMMITS: a slice in
    progress is waited for, up to its own bound, and none starts until the commit, so no
    slice writes the tree back while it goes. Slices run back to back, so a lock taken only
    if free would refuse almost every discard of a snapshot under way; the wait is why this
    is a `PROVIDER` kind, drained beside the pass. The row is read under the lock, so the
    journal names the status the discard ended.
    """
    rid = need_int(request.payload, "external_mailbox_id")
    wait_for(cur, partial(locks.xact_lock, mailbox_id=rid, namespace=locks.SNAPSHOT),
             SNAPSHOT_WAIT, "a slice of the snapshot holds its lock for longer than one may run")
    canonical, status = one(cur, "SELECT address_canonical, snapshot_status FROM "
                                 "external_mailbox WHERE id = %s", (rid,),
                            f"no external mailbox {rid}")
    removed = snapshot.discard(rid, context.snapshot_root)
    cur.execute(DISCARDED, (rid,))
    journal(cur, request, "discard_snapshot", canonical, {"status": status, "removed": removed})
    return (f"discarded the snapshot of {canonical}" if removed else
            f"{canonical} had no snapshot on disk; none is asked for any more")


def delete_domain(cur, request, context):
    """A domain, its mailboxes, its ledger rows and its directories; the archive last.

    ⛔ REFUSED WHILE AN EXTERNAL MAILBOX IS IN FRONT OF IT, and the refusal names that
    mailbox. The interface refuses this too, but its reading is
    minutes old by the time the queue is drained, and a request row can be replayed or
    queued before the mapping existed. Unmapping to get past the check would destroy the
    archive under a live external mailbox.
    """
    domain_id = need_int(request.payload, "domain_id")
    # ⛔ The import of this domain first, before the row lock below: an import
    # writes the domain's files and rows, and it never waits on this row while holding its
    # lock. Held until the drain commits; the import stops when it sees this request, and
    # one that does not fails this deletion after IMPORT_WAIT.
    wait_for_import(cur, domain_id)
    # ⛔ FOR UPDATE: the row is LOCKED while the mapping is read, so a concurrent
    # add_external cannot put a provider mailbox in front of this domain between the check
    # and the delete and have its archive destroyed under a live external mailbox. The
    # mapping write takes the same row lock, so the two serialize.
    label, mapped = one(cur, "SELECT label, external_mailbox_id FROM domain WHERE id = %s "
                        "FOR UPDATE", (domain_id,), f"no domain {domain_id}")
    if mapped is not None:
        cur.execute("SELECT address_canonical FROM external_mailbox WHERE id = %s", (mapped,))
        named = cur.fetchone()
        raise RequestFailed(
            f"{label} still has the external mailbox {named[0] if named else mapped} in "
            "front of it - delete that first; deleting the domain under it would take "
            "away the archive its mail is in")

    cur.execute("SELECT id FROM mailbox WHERE domain_id = %s ORDER BY id", (domain_id,))
    boxes = [mailbox_row(cur, row[0]) for row in cur.fetchall()]
    names = sum(unlink_mailbox(cur, mailbox, context) for mailbox in boxes)
    # ⛔ EVERY ROW BEFORE ANY FILE. The domain's row is locked above, so a Sent
    # hook's insert for it waits for this commit and then fails on the foreign key; and a
    # statement here that fails rolls everything back with every file still in place.
    cur.execute("DELETE FROM delivery WHERE message_id IN "
                "(SELECT id FROM message WHERE domain_id = %s)", (domain_id,))
    cur.execute("DELETE FROM message WHERE domain_id = %s", (domain_id,))
    cur.execute("DELETE FROM pass_cursor WHERE domain_id = %s", (domain_id,))
    cur.execute("DELETE FROM domain WHERE id = %s", (domain_id,))
    # ⛔ The archive LAST: while it stands, a deletion taken in error can
    # still be re-linked from it. Then the domain's own directories, by `rmdir`.
    context.gone.append([label, store.ARCHIVE])
    context.gone.append([label, None])
    journal(cur, request, "delete_domain", label,
            {"mailboxes": len(boxes), "delivery_rows": names})
    return f"deleted {label}, {len(boxes)} mailbox(es) and its archive last"


def transfer(cur, request, context):
    """A mailbox to another person in the same domain: three directories renamed, nothing copied.

    Refused before anything moves, because a half-done transfer is worse than none: an
    occupied slot would give one person two mailboxes in a domain, and renaming an index
    tree under a live session was measured to break things.
    """
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    to_account_id = need_int(request.payload, "to_account_id")
    (to_account,) = one(cur, "SELECT login FROM account WHERE id = %s", (to_account_id,),
                        f"no account {to_account_id}")
    cur.execute("SELECT 1 FROM mailbox WHERE account_id = %s AND domain_id = %s",
                (to_account_id, mailbox.domain_id))
    if cur.fetchone():
        raise RequestFailed(f"{to_account} already has a mailbox in {mailbox.label}; a "
                            "transfer into an occupied slot would make two")
    not_listed(cur, mailbox.label, to_account, "the transferred mailbox")
    try:
        open_sessions = doveadm.sessions(mailbox.login)
    except doveadm.DoveadmError as err:
        raise RequestFailed(str(err)) from None
    if open_sessions:
        raise RequestFailed(f"{len(open_sessions)} session(s) open on {mailbox.login} - "
                            "refusing to rename its index trees underneath them")

    moves = [(store.home(mailbox.label, mailbox.account, context.store_root),
              store.home(mailbox.label, to_account, context.store_root))]
    moves += list(zip(store.index_paths(mailbox.label, mailbox.account, context.index_root),
                      store.index_paths(mailbox.label, to_account, context.index_root)))
    done = []
    try:
        for source, destination in moves:
            if not Path(source).exists():
                continue
            if Path(destination).exists():
                raise RequestFailed(f"{destination} is already there")
            os.rename(source, destination)
            done.append((source, destination))
        for _, destination in done:
            if not Path(destination).exists():
                raise RequestFailed(f"{destination} is not there after the rename")
        # A rename is durable once both its directories are, before the row names the
        # new holder, as the pass does after linking.
        store.fsync_dirs(Path(path).parent for move in done for path in move)
        # ⛔ THE ROW UPDATE AND ITS JOURNAL ROW ARE INSIDE THE UNDO BLOCK. A
        # failure writing either undoes the renames too, so the files and the row never
        # disagree about who holds the mailbox. (drain's own commit is still outside; a
        # process killed between the last rename and that commit leaves the files moved,
        # the same residual risk P7 records.)
        cur.execute("UPDATE mailbox SET account_id = %s WHERE id = %s", (to_account_id, mailbox.id))
        journal(cur, request, "transfer", mailbox.login,
                {"to": f"{to_account}@{mailbox.label}", "directories": len(done)})
    except Exception as err:  # noqa: BLE001 - rolled back, then raised as the request's failure
        for source, destination in reversed(done):
            if Path(destination).exists():
                os.rename(destination, source)
        raise RequestFailed(f"the transfer was rolled back, nothing moved: {err}") from None

    return (f"transferred {mailbox.login} to {to_account}@{mailbox.label}, "
            f"{len(done)} directory(ies) moved")


def run_runner(context, argv, timeout, what):
    """The fetch runner, run as this process's own user. Its stderr is what a failure says."""
    try:
        return subprocess.run([str(context.fetch_runner), *argv], capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RequestFailed(f"{what} did not finish in {timeout} s") from None
    except OSError as err:
        raise RequestFailed(f"{what} could not be run: {err}") from None


def last_line(done):
    lines = (done.stderr or "").strip().splitlines() or ["no output"]
    return lines[-1][:DETAIL_MAX]


def refetch(cur, request, context):
    """Collect one external mailbox now, instead of waiting for the timer."""
    rid = need_int(request.payload, "external_mailbox_id")
    canonical, state = one(cur, "SELECT address_canonical, state FROM external_mailbox WHERE id = %s",
                           (rid,), f"no external mailbox {rid}")
    if state != "active":
        raise RequestFailed(f"{canonical} is {state}; a fetch of it would collect nothing")
    done = run_runner(context, ["--only", str(rid)], REFETCH_TIMEOUT, "the fetch")
    if done.returncode == runner.EX_TEMPFAIL:
        raise RequestFailed(f"a collection of {canonical} was already running, so this one "
                            "collected nothing; ask again")
    if done.returncode != 0:
        raise RequestFailed(f"the fetch of {canonical} failed: {last_line(done)}")
    journal(cur, request, "refetch", canonical, {"result": "ok"})
    return f"collected {canonical}"


# What a provider check logs in with: if any of it moves while the check runs,
# the verdict is about something no longer on the row. The pinned certificate is part of
# it: the check trusts the server by that pin. So is the protocol: the
# same host and login checked over the other one are another server's answer.
TESTED_AGAINST = ("SELECT credential, pop3_login, pop3_host, pop3_port, pop3_cert_fingerprint, "
                  "protocol FROM external_mailbox WHERE id = %s")


def check_credential(cur, rid, context, start_mark=False):
    """Run the password check and read its verdict BACK OFF THE ROW.

    ⛔ Never from the exit code: a credential the provider refused and a runner that
    could not reach the row at all both exit non-zero, and the first is a perfectly good
    measurement. ⚠️ The stamp is COMPARED, not merely checked for NULL - a row tested
    last week would otherwise read that verdict as this run's, which is "reported
    success having measured nothing" arriving by the other door. The runner writes the
    columns on its own connection, so they survive this handler's rollback.
    """
    # ⛔ THE VERDICT MUST BE ABOUT THE CREDENTIAL STILL ON THE ROW. The check
    # runs in a separate process on its own connection, so the test and whatever this
    # handler does next (the activation) are separate transactions, and the credential or
    # the POP3 server could change in between. What the check was about is read BEFORE it
    # runs; afterwards the row is LOCKED and read again, and any difference refuses the
    # request, so a mailbox is never switched on against a credential the provider was
    # never asked about. The lock is held until this handler commits, so nothing changes
    # between that comparison and the switch. ⚠️ Never locked BEFORE the check: the runner
    # writes its verdict to this same row, and would wait on the lock for ever.
    # `start_mark` is the activation's: the runner's check then also sets an IMAP row's mark
    # where the INBOX stands, on the row it logged in to, before this compares.
    canonical, before = one(cur, "SELECT address_canonical, last_test_at FROM external_mailbox "
                                 "WHERE id = %s", (rid,), f"no external mailbox {rid}")
    tested = one(cur, TESTED_AGAINST, (rid,), f"no external mailbox {rid}")
    done = run_runner(context, ["--auth-only", "--only", str(rid)]
                      + (["--start-mark"] if start_mark else []), AUTH_TIMEOUT,
                      "the credential check")
    status, detail, after = one(cur, "SELECT last_test_status, last_test_detail, last_test_at "
                                     "FROM external_mailbox WHERE id = %s FOR UPDATE", (rid,),
                                f"no external mailbox {rid}")
    if status is None or after == before:
        raise RequestFailed(f"the credential check of {canonical} measured nothing (the "
                            f"runner exited {done.returncode}): {last_line(done)}")
    if tuple(one(cur, TESTED_AGAINST, (rid,), f"no external mailbox {rid}")) != tuple(tested):
        raise RequestFailed(f"the password, the protocol or the server of {canonical} changed "
                            "while it was being checked, so the answer is about the old one; "
                            "nothing was switched on - check it again")
    return canonical, status, detail


def test_credential(cur, request, context):
    """What the provider says about a saved password - and a refusal IS an answer.

    This request ends `done` whatever the provider said, because the question was asked
    and answered; only a check that could not be performed fails.
    """
    rid = need_int(request.payload, "external_mailbox_id")
    canonical, status, detail = check_credential(cur, rid, context)
    journal(cur, request, "test_credential", canonical, {"status": status, "detail": detail})
    return f"the provider answered {status} for {canonical}"


def activate_external_mailbox(cur, request, context):
    """Enabling is ONE act, and the provider decides whether it happens.

    There is no test-then-switch-on pair: a switch that can be thrown without the
    provider agreeing is how a mailbox comes up active and collecting nothing. On
    anything but `ok` the row stays deactivated with the runner's reason on it, and this
    request finishes `failed`. ⚠️ Two journal rows on success, the check and the enable,
    so the journal can answer "was the password ever tried".

    ⚠️ AND NONE AT ALL ON A REFUSAL: this handler's transaction is rolled back, so a row
    written before the refusal would go with it. What records a refused enable is the
    request's own outcome and the three `last_test_*` columns, which the runner wrote on
    its own connection. A separate `test_credential` request ends `done`, and
    that one does journal what the provider said. An IMAP mailbox's mark is the runner's
    too: its check set it with a journal row of its own, so a refusal after it
    leaves the mark where the INBOX stood, and the next activation keeps it.
    """
    rid = need_int(request.payload, "external_mailbox_id")
    # ⛔ NO BACKUP, NO ENABLE. The window deletes at the provider from the
    # first run, so from here this machine is the only holder of the address's mail; the
    # source enabled deletion twice with no backup anywhere. Asked before the provider is,
    # since nothing would come of its answer.
    missing = backup_status.problem(context.backup_status)
    if missing:
        canonical, = one(cur, "SELECT address_canonical FROM external_mailbox WHERE id = %s",
                         (rid,), f"no external mailbox {rid}")
        raise RequestFailed(f"{canonical} is still deactivated: {missing}. Enabling it lets "
                            "the provider delete mail past its window, and nothing would "
                            "hold a copy")
    # the activation's check is the one that sets an IMAP mailbox's mark
    canonical, status, detail = check_credential(cur, rid, context, start_mark=True)
    if status != "ok":
        raise RequestFailed(f"the provider did not accept the credential for {canonical} "
                            f"({status}): {detail or 'no message'} - it is still deactivated")
    journal(cur, request, "test_credential", canonical, {"status": status, "detail": detail})
    cur.execute("UPDATE external_mailbox SET state = 'active', state_changed_at = now(), "
                "state_changed_by = %s WHERE id = %s", (request.asked_by, rid))
    journal(cur, request, "activate_external_mailbox", canonical, {"state": "active"})
    return f"the provider accepted the credential for {canonical}; it is active"


HANDLERS = {
    "create_domain": create_domain,
    "create_mailbox": create_mailbox,
    "connect": connect,
    "top_up": top_up,
    "deliver_one": deliver_one,
    "release": release,
    "delete_account": delete_account,
    "delete_mailbox": delete_mailbox,
    "delete_external_mailbox": delete_external_mailbox,
    "delete_domain": delete_domain,
    "transfer": transfer,
    "refetch": refetch,
    "test_credential": test_credential,
    "activate_external_mailbox": activate_external_mailbox,
    "discard_snapshot": discard_snapshot,
}


# --- draining ------------------------------------------------------------------------------------


def claim(conn, provider=False):
    """Take the oldest queued request of this drainer's kinds, or None. Its own
    transaction."""
    with conn.cursor() as cur:
        cur.execute(CLAIM, (sorted(PROVIDER), provider))
        row = cur.fetchone()
    conn.commit()
    if row is None:
        return None
    payload = row[3]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return Request(row[0], row[1], row[2], payload or {}, row[4], bool(row[5]))


def finish(conn, request, state, reason, removed=False):
    """Write the outcome, AFTER the handler's transaction ended, in one of its own.
    `removed`: the directories its deletion left are gone, and so is their list."""
    with conn.cursor() as cur:
        cur.execute(FINISH, (state, (reason or "")[:REASON_MAX], request.id))
        if removed:
            cur.execute(CLEAR, (request.id,))
    conn.commit()


def put_back(conn, request):
    """A request whose batches so far are committed, back in the queue in its place."""
    with conn.cursor() as cur:
        cur.execute(PUT_BACK, (request.id,))
    conn.commit()


class PutBack(Exception):
    """Not a failure: the drain's budget was spent between two batches, and the
    request goes back in the queue with everything it linked committed."""


class Unsettled(Exception):
    """A COMMIT raised. `key` and `value` are what its transaction wrote on the request's
    row, by which `landed` reads whether it is there after all."""

    def __init__(self, err, key, value):
        super().__init__(f"{type(err).__name__}: {err}")
        self.key, self.value = key, value


class Performing:
    """One claimed request while `drain` performs it: its own lists, and its commits."""

    def __init__(self, conn, request, context, spent):
        self.conn, self.request, self.spent = conn, request, spent
        self.context = context._replace(made=[], gone=[], batch=self.batch, folders=set())
        self.linked = so_far(request)   # what its committed batches linked

    def commit(self, key, value):
        """End the handler's transaction, which wrote `key` on the request's row."""
        try:
            self.conn.commit()
        except Exception as err:  # noqa: BLE001 - whether it is there is read, never assumed
            raise Unsettled(err, key, value) from err

    def batch(self, cur, linked):
        """Between two batches: this one commits with its count, its names are
        accounted for from here, and the drain's budget is read."""
        cur.execute(PROGRESS, (progress(linked), linked, self.request.id))
        self.commit("linked", linked)
        self.linked = linked
        self.context.made.clear()
        if self.spent():
            raise PutBack

    def end(self, cur):
        """The request's last transaction, or its only one."""
        cur.execute(COMMITTED, (self.request.id,))
        self.commit("committed", True)


def said(conn, request_id, key):
    """What the request's row holds under `key` once nothing else is writing it."""
    with conn.cursor() as cur:
        cur.execute("SET LOCAL lock_timeout = %s", (SAID_WAIT,))
        cur.execute(SAID, (key, request_id))
        row = cur.fetchone()
    conn.rollback()
    value = row[0] if row else None
    return json.loads(value) if isinstance(value, str) else value


def landed(conn, reconnect, request_id, unsure):
    """Whether the transaction whose COMMIT raised is there after all: `(True, False, or
    None when that could not be read; the connection to go on with)`.

    The connection it was sent on is asked first: a COMMIT the database refused leaves it
    usable, and the transaction rolled back. A lost one is replaced, once.
    """
    try:
        conn.rollback()
        return said(conn, request_id, unsure.key) == unsure.value, conn
    except Exception:  # noqa: BLE001 - the connection is lost: a second one is asked
        pass
    if reconnect is None:
        return None, conn
    fresh = None
    try:
        fresh = reconnect()
        return said(fresh, request_id, unsure.key) == unsure.value, fresh
    except Exception as err:  # noqa: BLE001 - not known is an answer, and the safe one
        sys.stderr.write(f"maildivvy-pass: request {request_id}'s row could not be read "
                         f"again: {type(err).__name__}: {err}\n")
        return None, fresh or conn


def written(live, conn, reconnect, write):
    """`write(connection)` on `live`, or, when that raises on the drain's own connection,
    once on a new one; returns the connection that wrote.

    A request whose outcome is not written stays `running` until the next drain, which
    fails it as a stopped run's; a database restarted under the pass is back by then.
    """
    try:
        write(live)
        return live
    except Exception:  # noqa: BLE001 - raised again unless a second connection may be tried
        if live is not conn or reconnect is None:
            raise
    try:
        conn.rollback()   # whatever it still holds of the row is let go
    except Exception:  # noqa: BLE001 - the connection is lost, and holds nothing
        pass
    fresh = reconnect()
    try:
        write(fresh)
    except Exception:
        fresh.close()
        raise
    return fresh


def perform(conn, request, context, spent, reconnect=None):
    """One claimed request, in transactions of its own; returns `(state, reason, removed,
    the connection its outcome is written on)`.

    `state` is `done`, `failed`, `queued` for a top-up or a connect put back between two
    batches, or None when a COMMIT raised and whether it is there could not be
    read: then no name is touched and nothing is written.
    """
    doing = Performing(conn, request, context, spent)
    mine, live, reason = doing.context, conn, None
    try:
        handler = HANDLERS.get(request.kind)
        if handler is None:
            raise RequestFailed(f"no handler for kind {request.kind!r}")
        with conn.cursor() as cur:
            reason = handler(cur, request, mine)
            if mine.gone:
                # ⛔ with the rows: a run stopped after this commit leaves the
                # list on the row, and the next drain removes what it names
                cur.execute(LEAVE, (json.dumps(mine.gone), request.id))
            doing.end(cur)
        state = "done"
    except PutBack:
        return "queued", None, False, live
    except Unsettled as unsure:
        # ⛔ NO NAME IS TOUCHED BEFORE THE ROW IS READ: the rows may be there.
        there, live = landed(conn, reconnect, request.id, unsure)
        if there is None:
            sys.stderr.write(
                f"maildivvy-pass: request {request.id} ({request.kind}): a COMMIT raised "
                f"({unsure}) and whether it is there could not be read; no name was taken "
                "back, and the request stays running until the next run fails it\n")
            return None, None, False, live
        if there and unsure.key == "committed":
            state = "done"
        else:
            state, reason = "failed", str(unsure)
            if there:
                # a batch that is there: its names have their rows, and stay
                doing.linked = unsure.value
                mine.made.clear()
    except Exception as err:  # noqa: BLE001 - this request alone fails, with its reason
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001 - a lost connection committed nothing either
            pass
        reason = str(err) if isinstance(err, RequestFailed) else f"{type(err).__name__}: {err}"
        state = "failed"
    if state == "failed":
        # ⛔ The names go with the rows: a name made before the failure
        # accounts for nothing once its row is rolled back. Of a top-up or a connect
        # these are the names of the batch under way alone.
        left = take_back(mine.made)
        if left:
            reason = f"{reason}; {left}"
        if doing.linked:
            reason = (f"{reason}; {doing.linked} message(s) were linked before it and stay: "
                      "asking again goes on from there")
        sys.stderr.write(f"maildivvy-pass: request {request.id} ({request.kind}) "
                         f"failed: {reason}\n")
    removed = False
    if state == "done" and mine.gone:
        # the second step: the rows are committed, so nobody logs in to these any more
        try:
            state, more = after_commit(mine.gone, mine)
        except Exception as err:  # noqa: BLE001 - the rows are committed; the list stays
            state, more = "failed", (f"its rows are deleted, but {type(err).__name__}: "
                                     f"{err}; the next run tries again")
        reason = "; ".join(part for part in (reason, more) if part)
        removed = state == "done"
        if state == "failed":
            sys.stderr.write(f"maildivvy-pass: request {request.id} ({request.kind}) "
                             f"failed: {reason}\n")
    return state, reason, removed, live


def drain(conn, context=Context(), limit=100, provider=False, budget=None,  # noqa: B008 - a Context is an immutable NamedTuple
          clock=time.monotonic, reconnect=None):
    """Perform the queued requests, oldest first, one transaction each, a
    top-up and a connect one for each batch.

    `budget`: seconds after which no further request is claimed, and after which a top-up
    or a connect goes back in the queue between two batches; the rest wait in the queue,
    in their order, for the next run (`DRAIN_BUDGET`, the pass's).

    `reconnect` makes a second connection when the first is lost under a request: its
    outcome is written there, and the drain ends, since the drainer's lock went with the
    first.

    `provider` drains the kinds of `PROVIDER`, and nothing else; without it, every other
    kind. A handler that raises leaves the rows it had not reached untouched,
    because the failure rolls back before its reason is written in a transaction of its
    own. An unknown kind fails rather than being skipped in silence.

    It drains under the lock of its half, and first fails what a stopped run left
    `running` (see `DRAINING`) and removes what earlier deletions left (`remove_left`);
    the lock goes with the connection, which the caller closes. A deletion's directories
    go after its own commit, and the request is done only once they are gone.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s, %s)", (DRAINING, int(provider)))
        (draining,) = cur.fetchone()
        if draining:
            cur.execute(LEFT_RUNNING, (STOPPED, sorted(PROVIDER), provider))
            left = cur.rowcount
            cur.execute(LEFT, (sorted(PROVIDER), provider))
            waiting = cur.fetchall()
    conn.commit()
    if not draining:
        sys.stderr.write("maildivvy-pass: another run is draining the request queue; "
                         "this one leaves it\n")
        return 0, 0
    if left:
        sys.stderr.write(f"maildivvy-pass: {left} request(s) a stopped run left running "
                         "marked failed\n")
    remove_left(conn, waiting, context)
    done = failed = 0
    started = clock()

    def spent():
        return budget is not None and clock() - started >= budget

    live = conn
    try:
        for _ in range(limit):
            if spent():
                sys.stderr.write(f"maildivvy-pass: the drain ran {budget} s; what is queued "
                                 "waits for the next run\n")
                break
            request = claim(conn, provider)
            if request is None:
                break
            state, reason, removed, live = perform(conn, request, context, spent, reconnect)
            done += state == "done"
            failed += state == "failed"
            if state == "queued":
                write = partial(put_back, request=request)
                sys.stderr.write(f"maildivvy-pass: the drain ran {budget} s; request "
                                 f"{request.id} ({request.kind}) goes on in the next run\n")
            else:
                write = partial(finish, request=request, state=state, reason=reason,
                                removed=removed)
            if state is not None:
                try:
                    live = written(live, conn, reconnect, write)
                except Exception as err:  # noqa: BLE001 - the next drain fails it as a stopped run's
                    sys.stderr.write(
                        f"maildivvy-pass: request {request.id} ({request.kind}) is "
                        f"{state}, which could not be written ({type(err).__name__}: {err}); "
                        "it stays running until the next run fails it\n")
                    break
            if state in (None, "queued") or live is not conn:
                break
    finally:
        if live is not conn:
            live.close()
    return done, failed
