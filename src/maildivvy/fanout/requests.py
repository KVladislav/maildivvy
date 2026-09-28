"""The queue the administration interface writes, performed here by the pass.

The interface changes rows; everything that touches a disk is a request row it queues
and this module performs. The pass drains the queue at the end of its own
run, after the fan-out and never before it.

⛔ ONE REQUEST PER TRANSACTION, IN THREE. The claim commits on its own, so a
handler that dies cannot un-claim a request and spin on it; the handler runs in a
transaction of its own; and the outcome is written in a further transaction, AFTER the
rollback, so the reason survives the failure that produced it. An unknown kind is a
failed request, never a silently skipped one.

⛔ THE FILES GO FIRST AND THE ROWS SECOND. Delivery rows cascade from the
mailbox: a handler that deletes the row first has thrown away the list of names it had
to unlink, and those names become files nothing accounts for.

⛔ A MESSAGE'S UID IS LOOKED UP IN THE MAILBOX IT COUNTS IN. UIDs are per
mailbox, so a withheld message's `archive_uid` is its number in the quarantine folder,
and a released message's still is - only a `delivered` message's counts in INBOX.
Measured on the predecessor: a release that asked INBOX for the number found
another message, hit EEXIST (success) and reported "released to 3 mailboxes" having
linked nothing; had the receivers not held that other message already, it would have
linked somebody else's mail into all three.

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
namespace is `fetch/locks.py`'s, imported, never spelt a second time.

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
from pathlib import Path
from typing import NamedTuple

from maildivvy.backup import status as backup_status
from maildivvy.fanout import pass_
from maildivvy.fetch import locks, render
from maildivvy.lib import adminlock, doveadm, store

INBOX = pass_.INBOX
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


class RequestFailed(Exception):
    """Ends the request `failed`, with this text as the reason the interface shows."""


class Context(NamedTuple):
    """Where the handlers work. The product fixes its layout; none of this is a setting."""

    store_root: Path = store.STORE_ROOT
    index_root: Path = store.INDEX_ROOT
    fetch_state_root: Path = render.DEFAULT_STATE_DIR
    fetch_runner: Path = render.DEFAULT_BINDIR / "maildivvy-fetch"
    # What the newest backup run left for the rest of the machine.
    backup_status: Path = backup_status.STATUS
    # The names THIS request made, each one new. `drain` gives every request
    # a list of its own and takes them back when the request fails; None is no record.
    made: list | None = None


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
CLAIM = """
    UPDATE request SET state = 'running'
     WHERE id = (SELECT id FROM request WHERE state = 'queued'
                  ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1)
 RETURNING id, kind, target, payload, asked_by, break_glass
"""
FINISH = "UPDATE request SET state = %s, result = %s, finished_at = now() WHERE id = %s"

MAILBOX_ROW = """
    SELECT m.id, a.login, d.label, m.as_of, m.domain_id
      FROM mailbox m JOIN account a ON a.id = m.account_id JOIN domain d ON d.id = m.domain_id
     WHERE m.id = %s
"""
RECEIVERS = "SELECT mailbox_id, account FROM mailbox_receives WHERE domain_id = %s ORDER BY mailbox_id"
LINK = """
    INSERT INTO delivery (message_id, mailbox_id, state, linked_at)
    VALUES (%s, %s, 'linked', now()) ON CONFLICT (message_id, mailbox_id) DO NOTHING
"""
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
SELECT_FOR = "SELECT m.id, m.archive_uid, m.state" + SELECTOR + " ORDER BY m.id"
COUNT_FOR = "SELECT count(*)" + SELECTOR

# ⛔ NAMED, NOT WRITTEN INLINE, because the acceptance tests plan these exact texts at a
# year's volume: `delivery (mailbox_id)` serves the first two and
# `message (report_of)` the third. A copy in a test would prove nothing about these.
MAILBOX_NAMES = "SELECT count(*) FROM delivery WHERE mailbox_id = %s"
MAILBOX_UNLINK = "DELETE FROM delivery WHERE mailbox_id = %s"
REPORTS_OF = "SELECT id, archive_uid FROM message WHERE report_of = %s ORDER BY id"


def selector_params(mailbox_id, domain_id, since, until):
    """The one parameter order both readings of `SELECTOR` use."""
    return (domain_id, list(DELIVERABLE), since, until, mailbox_id)


def select_for(cur, mailbox_id, domain_id, since, until):
    """The archived messages this mailbox has not been given yet, in range."""
    cur.execute(SELECT_FOR, selector_params(mailbox_id, domain_id, since, until))
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


def archive_folder(state):
    """The archive mailbox a message's UID counts in.

    A withheld message's number is the quarantine folder's, and a RELEASED message is a
    withheld message whose state changed - its file never moved, so its number still
    counts there. Only a `delivered` message's counts in INBOX.
    """
    return INBOX if state == "delivered" else store.QUARANTINE


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
    box = store.maildir(home)
    for part in ("cur", "new", "tmp"):
        store.make_dir(box / part, root)
    return box


def link_message(cur, row, mailbox, context, relink=False):
    """One archived message into one mailbox: the name first, then the row."""
    message_id, archive_uid, state = row
    folder = archive_folder(state)
    try:
        source = doveadm.message_file(mailbox.label, store.ARCHIVE, folder, archive_uid,
                                      root=context.store_root)
    except doveadm.DoveadmError as err:
        raise RequestFailed(f"UID {archive_uid} is not in {store.ARCHIVE}@{mailbox.label}'s "
                            f"{folder} any more: {err}") from None
    box = store.maildir(store.home(mailbox.label, mailbox.account, context.store_root))
    pass_.fsync_dirs(pass_.link_into(source, [box], context.store_root, made=context.made))
    cur.execute(RELINK if relink else LINK, (message_id, mailbox.id))


def take_back(made):
    """Remove the names a failed request made; returns a complaint, or None.

    The request's rows are rolled back, so a name it made accounts for nothing: for a
    release it is a withheld message in a person's mailbox. Only names this request
    created are here - one that was already there is somebody's, and stays. A person
    may have read the message in the seconds between, which moves the name to `cur/`
    with flags after it; only when the name is gone from `new/` is it looked for there.
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
                if moved.name.startswith(f"{path.name}:"):
                    moved.unlink()
                    touched.append(read)
        except OSError as err:
            left.append(f"{path}: {err}")
    try:
        pass_.fsync_dirs(touched)
    except OSError as err:
        left.append(f"fsync: {err}")
    made.clear()
    return (f"{len(left)} name(s) it made could not be taken back: " + "; ".join(left)
            if left else None)


def maildir_parts(home):
    """Every `new/` and `cur/` of one mailbox: its INBOX and each folder it holds."""
    box = store.maildir(home)
    if not box.is_dir():
        return []
    folders = [box] + sorted(d for d in box.iterdir() if d.is_dir() and d.name.startswith("."))
    return [d / part for d in folders for part in ("new", "cur") if (d / part).is_dir()]


def remove_names(home, inode, base):
    """Remove one message's names from every folder of one mailbox; returns how many.

    ⚠️ THIS IS THE ONE PATH THAT SCANS. Everywhere else a name is resolved
    exactly, from Dovecot's own storage id; a report that a person has read, flagged or
    filed away has a name and a folder of the person's own choosing, and no exact
    resolution covers that. A name added between the listing and the unlink is not
    removed - the same race `store.resolve` describes - and there is no second pass.
    The inode is what identifies the file; the base name catches a
    name whose file the archive no longer holds.
    """
    removed = 0
    for directory in maildir_parts(home):
        for entry in sorted(directory.iterdir()):
            if not entry.is_file():
                continue
            if pass_.base_name(entry) == base or (inode is not None
                                                  and entry.stat().st_ino == inode):
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


def unlink_mailbox(cur, mailbox, context):
    """One mailbox off the disks and out of the ledger, files first."""
    cur.execute(MAILBOX_NAMES, (mailbox.id,))
    names = cur.fetchone()[0]
    remove_mailbox_files(mailbox.label, mailbox.account, context)
    cur.execute(MAILBOX_UNLINK, (mailbox.id,))
    cur.execute("DELETE FROM mailbox WHERE id = %s", (mailbox.id,))
    return names


# --- the handlers --------------------------------------------------------------------------------


def create_domain(cur, request, context):
    """The archive's maildir, its quarantine folder, and its own read-only ACL.

    The ACL is on the archive's OWN INBOX, per mailbox, never a global or group rule
    matching `INBOX` by name - such a rule would open every person's INBOX to the
    administrators.
    """
    domain_id = need_int(request.payload, "domain_id")
    (label,) = one(cur, "SELECT label FROM domain WHERE id = %s", (domain_id,),
                   f"no domain {domain_id}")
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
    make_maildir(store.home(mailbox.label, mailbox.account, context.store_root),
                 context.store_root)
    journal(cur, request, "create_mailbox", mailbox.login, {"as_of": mailbox.as_of})
    return f"made the maildir for {mailbox.login}"


def connect(cur, request, context):
    """Everything archived since the mailbox was created.

    The wide end is the same plain far-future date a top-up's "all of it" spells;
    the start is the mailbox's own `as_of`, an instant, because mail that
    arrived earlier that day arrived before the mailbox existed.
    """
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    rows = select_for(cur, mailbox.id, mailbox.domain_id, mailbox.as_of, WIDE_UNTIL)
    for row in rows:
        link_message(cur, row, mailbox, context)
    journal(cur, request, "connect", mailbox.login,
            {"messages": len(rows), "since": mailbox.as_of, "until": WIDE_UNTIL})
    return f"connected {len(rows)} message(s) to {mailbox.login}"


def top_up(cur, request, context):
    """The messages that never reached a mailbox, over a stated range of calendar days.

    Both ends are required: "all of it" is a wide pair, never an absent one, so the size
    of what it will deliver is knowable before it runs.
    """
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    since = need_date(request.payload, "since")
    until = need_date(request.payload, "until")
    rows = select_for(cur, mailbox.id, mailbox.domain_id, since, until)
    for row in rows:
        link_message(cur, row, mailbox, context)
    journal(cur, request, "top_up", mailbox.login,
            {"messages": len(rows), "since": since, "until": until})
    return f"topped up {len(rows)} message(s) to {mailbox.login}, {since} to {until}"


def deliver_one(cur, request, context):
    """One named message to one named person. It may relink over a `linked` row.

    That is a targeted undelete, the only one, and it carries none of the bulk
    selector's spam condition: an administrator naming one message is not a bulk
    selector.
    """
    mailbox = mailbox_row(cur, need_int(request.payload, "mailbox_id"))
    message_id = need_int(request.payload, "message_id")
    row = one(cur, "SELECT id, archive_uid, state, domain_id FROM message WHERE id = %s",
              (message_id,), f"no message {message_id}")
    if row[3] != mailbox.domain_id:
        raise RequestFailed(f"message {message_id} is not a message of {mailbox.label}, "
                            f"which is the domain {mailbox.login}'s mailbox is in")
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
    row = one(cur, "SELECT id, archive_uid, state, domain_id FROM message WHERE id = %s",
              (message_id,), f"no message {message_id}")
    _, archive_uid, state, domain_id = row
    if state != "withheld":
        raise RequestFailed(f"message {message_id} is {state}, not withheld; only a "
                            "withheld message is released")
    (label,) = one(cur, "SELECT label FROM domain WHERE id = %s", (domain_id,),
                   f"no domain {domain_id}")

    cur.execute(RECEIVERS, (domain_id,))
    receivers = cur.fetchall()
    for mailbox_id, account in receivers:
        link_message(cur, (message_id, archive_uid, state),
                     Mailbox(mailbox_id, account, label, None, domain_id), context)

    removed = 0
    cur.execute(REPORTS_OF, (message_id,))
    reports = cur.fetchall()
    for report_id, report_uid in reports:
        removed += remove_report(cur, report_id, report_uid, label, domain_id, context)
        cur.execute("DELETE FROM delivery WHERE message_id = %s", (report_id,))

    cur.execute("UPDATE message SET state = 'released' WHERE id = %s", (message_id,))
    journal(cur, request, "release", label,
            {"message": message_id, "mailboxes": len(receivers), "names_removed": removed})
    return (f"released message {message_id} to {len(receivers)} mailbox(es); "
            f"{removed} report name(s) removed")


def remove_report(cur, report_id, report_uid, label, domain_id, context):
    """The report's names, from every mailbox of the domain, files first."""
    inode, base = None, None
    if report_uid is not None:
        try:
            path = doveadm.message_file(label, store.ARCHIVE, INBOX, report_uid,
                                        root=context.store_root)
            inode, base = path.stat().st_ino, pass_.base_name(path)
        except (doveadm.DoveadmError, OSError):
            inode, base = None, None
    if inode is None and base is None:
        sys.stderr.write(f"maildivvy-pass: the report {report_id} of {label} is not in the "
                         "archive any more; its names could not be found\n")
        return 0
    cur.execute(RECEIVERS, (domain_id,))
    removed = 0
    for _, account in cur.fetchall():
        removed += remove_names(store.home(label, account, context.store_root), inode, base)
    return removed


def delete_mailbox(cur, request, context):
    """A person's mailbox in one domain: its names, then its rows, then its directories."""
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
    """A person and every mailbox they hold, each one's names before its own rows.

    The rows are how the names are found, so no mailbox's delivery rows are deleted
    while its files are still there.
    """
    account_id = need_int(request.payload, "account_id")
    # ⛔ the lock FIRST, then the row: what is read after it is what the last decision left
    adminlock.lock(cur)
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
    fetcher's own lock taken blocking.
    """
    rid = need_int(request.payload, "external_mailbox_id")
    (canonical,) = one(cur, "SELECT address_canonical FROM external_mailbox WHERE id = %s",
                       (rid,), f"no external mailbox {rid}")
    # ⛔ HELD UNTIL THIS DRAIN COMMITS: a transaction-level advisory lock, so
    # the fetcher cannot take the lock back between the removal and the commit and rewrite
    # the state directory this handler is deleting. It is released by drain's commit or
    # rollback, never here.
    locks.xact_lock(cur, rid)
    cur.execute("UPDATE domain SET external_mailbox_id = NULL WHERE external_mailbox_id = %s",
                (rid,))
    unmapped = cur.rowcount
    cur.execute("DELETE FROM external_mailbox WHERE id = %s", (rid,))
    state = render.state_dir(context.fetch_state_root, rid)
    removed = remove_tree(state)
    journal(cur, request, "delete_external_mailbox", canonical,
            {"domains_unmapped": unmapped, "fetch_state_removed": removed})
    return (f"deleted the external mailbox {canonical} and its fetcher state; "
            f"{unmapped} domain(s) unmapped, their archives kept")


def delete_domain(cur, request, context):
    """A domain, its mailboxes, its ledger rows and its directories; the archive last.

    ⛔ REFUSED WHILE AN EXTERNAL MAILBOX IS IN FRONT OF IT, and the refusal names that
    mailbox. The interface refuses this too, but its reading is
    minutes old by the time the queue is drained, and a request row can be replayed or
    queued before the mapping existed. Unmapping to get past the check would destroy the
    archive under a live external mailbox.
    """
    domain_id = need_int(request.payload, "domain_id")
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
    cur.execute("DELETE FROM delivery WHERE message_id IN "
                "(SELECT id FROM message WHERE domain_id = %s)", (domain_id,))
    cur.execute("DELETE FROM message WHERE domain_id = %s", (domain_id,))
    cur.execute("DELETE FROM pass_cursor WHERE domain_id = %s", (domain_id,))
    cur.execute("DELETE FROM domain WHERE id = %s", (domain_id,))

    # ⛔ The archive LAST: while it stands, a deletion taken in error can
    # still be re-linked from it.
    remove_tree(store.archive_home(label, context.store_root))
    for tree in store.index_paths(label, store.ARCHIVE, context.index_root):
        remove_tree(tree)
    left = [rmdir_left(Path(context.store_root) / label),
            rmdir_left(Path(context.index_root) / "idx" / label),
            rmdir_left(Path(context.index_root) / "ctl" / label)]
    left = [complaint for complaint in left if complaint]
    journal(cur, request, "delete_domain", label,
            {"mailboxes": len(boxes), "delivery_rows": names, "left": left})
    return (f"deleted {label}, {len(boxes)} mailbox(es) and its archive last"
            + ("; " + "; ".join(left) if left else ""))


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
        # ⛔ THE ROW UPDATE AND ITS JOURNAL ROW ARE INSIDE THE UNDO BLOCK. A
        # failure writing either undoes the renames too, so the files and the row never
        # disagree about who holds the mailbox. (drain's own commit is still outside; a
        # process killed between the last rename and that commit leaves the files moved,
        # the same residual risk P7 records.)
        cur.execute("UPDATE mailbox SET account_id = %s WHERE id = %s", (to_account_id, mailbox.id))
        journal(cur, request, "transfer", mailbox.login,
                {"to": f"{to_account}@{mailbox.label}", "directories": len(done)})
    except Exception as err:
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
    if done.returncode != 0:
        raise RequestFailed(f"the fetch of {canonical} failed: {last_line(done)}")
    journal(cur, request, "refetch", canonical, {"result": "ok"})
    return f"collected {canonical}"


# What a provider check logs in with: if any of it moves while the check runs,
# the verdict is about something no longer on the row.
TESTED_AGAINST = ("SELECT credential, pop3_login, pop3_host, pop3_port FROM external_mailbox "
                  "WHERE id = %s")


def check_credential(cur, rid, context):
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
    canonical, before = one(cur, "SELECT address_canonical, last_test_at FROM external_mailbox "
                                 "WHERE id = %s", (rid,), f"no external mailbox {rid}")
    tested = one(cur, TESTED_AGAINST, (rid,), f"no external mailbox {rid}")
    done = run_runner(context, ["--auth-only", "--only", str(rid)], AUTH_TIMEOUT,
                      "the credential check")
    status, detail, after = one(cur, "SELECT last_test_status, last_test_detail, last_test_at "
                                     "FROM external_mailbox WHERE id = %s FOR UPDATE", (rid,),
                                f"no external mailbox {rid}")
    if status is None or after == before:
        raise RequestFailed(f"the credential check of {canonical} measured nothing (the "
                            f"runner exited {done.returncode}): {last_line(done)}")
    if tuple(one(cur, TESTED_AGAINST, (rid,), f"no external mailbox {rid}")) != tuple(tested):
        raise RequestFailed(f"the password or the POP3 server of {canonical} changed while it "
                            "was being checked, so the answer is about the old one; nothing "
                            "was switched on - check it again")
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
    that one does journal what the provider said.
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
    canonical, status, detail = check_credential(cur, rid, context)
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
}


# --- draining ------------------------------------------------------------------------------------


def claim(conn):
    """Take the oldest queued request, or None. Its own transaction."""
    with conn.cursor() as cur:
        cur.execute(CLAIM)
        row = cur.fetchone()
    conn.commit()
    if row is None:
        return None
    payload = row[3]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return Request(row[0], row[1], row[2], payload or {}, row[4], bool(row[5]))


def finish(conn, request, state, reason):
    """Write the outcome, AFTER the handler's transaction ended, in one of its own."""
    with conn.cursor() as cur:
        cur.execute(FINISH, (state, (reason or "")[:REASON_MAX], request.id))
    conn.commit()


def drain(conn, context=Context(), limit=100):
    """Perform the queued requests, oldest first, one transaction each.

    A handler that raises leaves the rows it had not reached untouched, because the
    failure rolls back before its reason is written in a transaction of its own. An
    unknown kind fails rather than being skipped in silence.
    """
    done = failed = 0
    for _ in range(limit):
        request = claim(conn)
        if request is None:
            break
        mine = context._replace(made=[])
        try:
            handler = HANDLERS.get(request.kind)
            if handler is None:
                raise RequestFailed(f"no handler for kind {request.kind!r}")
            with conn.cursor() as cur:
                reason = handler(cur, request, mine)
            conn.commit()
            state = "done"
            done += 1
        except Exception as err:  # noqa: BLE001 - this request alone fails, with its reason
            conn.rollback()
            reason = str(err) if isinstance(err, RequestFailed) else f"{type(err).__name__}: {err}"
            # ⛔ The names go with the rows: a name made before the failure
            # accounts for nothing once its row is rolled back.
            left = take_back(mine.made)
            if left:
                reason = f"{reason}; {left}"
            state = "failed"
            failed += 1
            sys.stderr.write(f"maildivvy-pass: request {request.id} ({request.kind}) "
                             f"failed: {reason}\n")
        finish(conn, request, state, reason)
    return done, failed
