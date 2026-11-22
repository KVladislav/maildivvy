"""What the product keeps: `collection`, `store`, `database` and `backup`.

The database is read as `maildivvy_health`, which reads and never writes. The store and
the fetch state are the mail owner's, `0700`, so their readings come from the store
helper, run as `vmail` (`helper.py`).

⛔ AN EMPTY READING IS ONLY TRUSTED BESIDE A POSITIVE CONTROL.
"Every provider row carries a window" is vacuous over zero rows, and a ledger check over a
machine that has linked nothing yet proves nothing: both read UNKNOWN until there is
something to read, and say so.
"""

import datetime
import json
import os
import shlex
from pathlib import Path

from maildivvy.backup import archive
from maildivvy.backup import run as backup_run
from maildivvy.backup import status as backup_status
from maildivvy.fanout import pass_
from maildivvy.fetch import imap, outcome, render, runner, snapshot
from maildivvy.health import helper, probe, settings
from maildivvy.health.context import check, passed
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import FAIL, PASS, UNKNOWN, WARN, Check
from maildivvy.lib import retrieval, schema, store, timer

FETCH_UNIT, FETCH_TIMER = "maildivvy-fetch.service", "maildivvy-fetch.timer"
PASS_UNIT, PASS_TIMER = "maildivvy-pass.service", "maildivvy-pass.timer"
# the requests that wait on a provider, which every pass starts beside it
REQUESTS_UNIT = "maildivvy-requests.service"
BACKUP_UNIT, BACKUP_TIMER = "maildivvy-backup.service", "maildivvy-backup.timer"
LEDGER_UNIT = "maildivvy-health-ledger.service"   # the daily pass
MPOP_MINIMUM = "1.4.23"   # 1.4.21 refuses `keep <n>d` at parse


def paused_for_backup():
    """A backup pauses collection and fan-out on purpose. ⛔ The backup is a
    oneshot: `activating` for the whole of its run and never `active`, which is why
    `is_active` never saw one."""
    return probe.state(BACKUP_UNIT) in probe.RUNNING


# maildivvy-install's record of an upgrade's pause (installer.upgrade.PAUSE_RECORD): there
# while an upgrade runs its steps, and after one that failed past its migrations
UPGRADE_PAUSE = Path("/etc/maildivvy/upgrade-paused.json")
# a backup's or a restore's record of its pause (backup.run.PAUSED), 0644 in a 0755 directory
BACKUP_PAUSE_RECORD = backup_status.STATUS.parent / backup_run.PAUSED


BACKUP_PAUSE = "paused while the backup runs"


def pause_reason():
    """Why collection and fan-out are paused on purpose, or "" when they are not.

    ⛔ A RECORD IS A PAUSE WHETHER OR NOT ITS TIMERS RUN. The fetch, the pass, the
    requests and the snapshots refuse to start while either record is there, so a timer
    started by a reboot or by hand still runs nothing: the record, not the timer, is read."""
    if paused_for_backup():
        return BACKUP_PAUSE
    if UPGRADE_PAUSE.exists():
        return f"paused by an upgrade ({UPGRADE_PAUSE}): maildivvy-install starts it again once one finishes"
    if BACKUP_PAUSE_RECORD.exists():
        return backup_run.unfinished_restore(BACKUP_PAUSE_RECORD) or (
            f"a backup's pause is still recorded ({BACKUP_PAUSE_RECORD}) and no backup runs: "
            "nothing is collected until a backup ends it; run `sudo systemctl start "
            f"{BACKUP_UNIT}`")
    return ""


def judge_timer(name, timer, active, paused):
    """`paused` is why the timer's runs are held on purpose (pause_reason), "" when they are
    not; an active timer under a recorded pause starts nothing."""
    reading = f"{timer} {'active' if active else 'inactive'}"
    if active and not paused:
        return passed(name, reading)
    if paused:
        return Check(name, WARN, reading, paused)
    return Check(name, FAIL, reading, f"{timer} is stopped: nothing runs it")


# --- collection ------------------------------------

MAILBOXES = """
    SELECT e.id, e.address, e.state, e.delete_window_days, e.last_fetch_at, e.last_fetch_status,
           e.last_fetch_cause, e.last_fetch_detail, e.frozen_since, e.last_skip_at,
           e.last_skip_uidl, d.label, e.keep_at_provider, e.protocol,
           (e.oversize_skipped ->> 'at')::timestamptz, (e.oversize_skipped ->> 'uid')::bigint,
           (e.oversize_skipped ->> 'size')::bigint
      FROM external_mailbox e LEFT JOIN domain d ON d.external_mailbox_id = e.id
     ORDER BY e.id
"""
COLUMNS = ("id", "address", "state", "window", "fetched_at", "status", "cause", "detail",
           "frozen_since", "skipped_at", "skipped_uidl", "domain", "kept", "protocol",
           "oversize_at", "oversize_uid", "oversize_size")


def rows_of(raw):
    return [dict(zip(COLUMNS, row)) for row in raw]


def collected(row):
    """The runner collects a mapped row that is not deactivated (runner.TO_FETCH)."""
    return row["domain"] is not None and row["state"] != "deactivated"


def collection_bound(conf, period):
    """How long collection may go without a finished run, or a collected row without a
    fetch: the setting, and at least three of the fetch timer's periods."""
    minutes = conf.collection_minutes
    if period is not None:
        minutes = max(minutes, 3 * period.total_seconds() / 60)
    return datetime.timedelta(minutes=minutes)


def minutes_of(bound):
    return int(bound.total_seconds() // 60)


def judge_mailbox(row, now, bound, quiet):
    """One external mailbox as its last fetch left it, with the detail that tells a stuck
    message from an unreachable server, and not fetched within `bound`;
    `quiet` while a backup pauses collection or a run is still going, when an old
    row is a WARN and not a stop."""
    name = row["address"]
    if not collected(row):
        why = "deactivated" if row["state"] == "deactivated" else "no domain in front of it"
        return passed(name, f"not collected: {why}")
    if row["frozen_since"] is not None:
        # the one state the bounded retry cannot end by itself
        return Check(name, FAIL, f"frozen since {row['frozen_since'].isoformat(timespec='seconds')}",
                     "only a person's resume on the fetch screen ends a freeze")
    if row["fetched_at"] is None:
        return Check(name, UNKNOWN, "not fetched yet", "the first fetch has not run")
    reading = (f"{row['status']} at {row['fetched_at'].isoformat(timespec='seconds')}"
               + (f" ({row['cause']}: {row['detail']})" if row["cause"] or row["detail"] else ""))
    if row["status"] == outcome.AUTH_FAILED:
        return Check(name, FAIL, reading, "the provider refused the stored credential: nothing is "
                                          "collected until it is entered again")
    if row["status"] == outcome.ERROR:
        return Check(name, FAIL, reading, "the last fetch failed")
    if now - row["fetched_at"] > bound:
        if quiet:
            return Check(name, WARN, reading, f"not fetched in {minutes_of(bound)} min, while the "
                                              "backup pauses collection or a fetch run is still going")
        return Check(name, FAIL, reading, f"not fetched in {minutes_of(bound)} min: collection has "
                                          "stopped for it, whatever its last status says")
    if row.get("oversize_at") is not None and now - row["oversize_at"] < imap.OVERSIZE_SHOWN:
        # not downloaded, and kept at the provider; a person reads it there
        return Check(name, WARN, reading + f"; message {row['oversize_uid']} of "
                                           f"{row['oversize_size']} bytes skipped "
                                           f"{row['oversize_at'].date().isoformat()}",
                     f"message {row['oversize_uid']} of {name} is {row['oversize_size']} bytes, "
                     f"over the {imap.MESSAGE_CAP}-byte cap: it was not collected and stays at "
                     "the provider; read it there")
    if row["skipped_at"] is not None and row["kept"]:
        # nothing deletes it at the provider, so there is no date to fetch it by
        return passed(name, reading + f"; message {row['skipped_uidl']} skipped "
                                      f"{row['skipped_at'].date().isoformat()}, kept at the provider")
    if row["skipped_at"] is not None:
        deletes_on = row["skipped_at"] + datetime.timedelta(days=int(row["window"]))
        if now < deletes_on:
            # a WARN from the skip until the provider deletes it, naming the date
            return Check(name, WARN, reading + f"; message {row['skipped_uidl']} skipped "
                                               f"{row['skipped_at'].date().isoformat()}",
                         f"a message was skipped after an hour of failures; the provider deletes it "
                         f"on {deletes_on.date().isoformat()}: fetch it by hand before then")
    return passed(name, reading)


def judge_mailboxes(rows, now, bound, quiet):
    if not rows:
        return [Check("external mailboxes", UNKNOWN, "0 rows",
                      "no external mailbox yet: there is no collection to read")]
    return [judge_mailbox(row, now, bound, quiet) for row in rows]


@check("external mailboxes")
def mailboxes(ctx):
    quiet = bool(pause_reason()) or probe.state(FETCH_UNIT) in probe.RUNNING
    return judge_mailboxes(rows_of(ctx.query(MAILBOXES)), ctx.now,
                           collection_bound(ctx.settings, timer.timer_period()), quiet)


def judge_fetch_runs(shown, now, bound, paused):
    """The fetch unit's own last run, as the fan-out's is read: a run that fails as a
    whole - a unit that will not start, a configuration the runner refuses, an exception
    before any row - touches no row, so the rows alone would keep their last `ok`."""
    ended = probe.timestamp(shown["ExecMainExitTimestamp"])
    reading = (f"last run {ended.isoformat(timespec='seconds') if ended else 'never since the boot'}: "
               f"{shown['Result']}, status {shown['ExecMainStatus']}")
    if shown["ActiveState"] in probe.RUNNING:
        started = probe.timestamp(shown["ExecMainStartTimestamp"])
        reading += f"; a run going since {started.isoformat(timespec='seconds') if started else '?'}"
        if started is not None and now - started > bound:
            return Check("fetch runs", WARN, reading, f"a run has been going for more than "
                                                      f"{minutes_of(bound)} min: read "
                                                      f"`journalctl -u {FETCH_UNIT}`")
        return passed("fetch runs", reading)
    if ended is None:
        return Check("fetch runs", UNKNOWN, reading, "the fetch has not run since the boot")
    if shown["Result"] != "success" or shown["ExecMainStatus"] != "0":
        return Check("fetch runs", FAIL, reading, f"the fetch's last run failed (a mailbox's own "
                                                  f"failure is named on its row): read "
                                                  f"`journalctl -u {FETCH_UNIT}`")
    if now - ended > bound:
        if paused:
            return Check("fetch runs", WARN, reading, paused)
        return Check("fetch runs", FAIL, reading, f"no fetch run finished in {minutes_of(bound)} min: "
                                                  "nothing is collected")
    return passed("fetch runs", reading)


def judge_retrieval(lines, hours):
    """Deliveries the filter stored without asking whether mpop still waited for them:
    the runner's journal carries the filter's words.
    ⛔ The control: the window holds the fetch unit's own lines at all."""
    if not lines:
        return Check("retrieval check", UNKNOWN, f"no fetch line in the last {hours} h",
                     "the fetch has not run in the window: there is nothing to read")
    unchecked = sum(1 for line in lines if retrieval.UNCHECKED in line)
    reading = f"{unchecked} delivery(ies) unchecked in the last {hours} h ({len(lines)} fetch lines read)"
    if unchecked:
        return Check("retrieval check", WARN, reading,
                     "messages were stored without the check that keeps a half-read one out: "
                     "the fetch's retrieval pipe did not reach the filter; read "
                     f"`journalctl -u {FETCH_UNIT} -g '{retrieval.UNCHECKED}'`")
    return passed("retrieval check", reading)


@check("retrieval check")
def retrieval_check(ctx):
    hours = ctx.settings.retrieval_failure_hours
    return judge_retrieval(probe.journal(ctx.ago(hours=hours), f"--unit={FETCH_UNIT}"), hours)


@check("fetch runs")
def fetch_runs(ctx):
    shown = probe.show(FETCH_UNIT, "ActiveState", "Result", "ExecMainStatus", "ExecMainExitTimestamp",
                       "ExecMainStartTimestamp")
    return judge_fetch_runs(shown, ctx.now, collection_bound(ctx.settings, timer.timer_period()),
                            pause_reason())


def judge_windows(rows, state):
    """Every row a window, and every collected row's rendered configuration carrying exactly
    its own `keep <n>d`, or `keep on` for a row kept at the provider:
    mpop's default with no `keep` line is DELETE. An IMAP row has no configuration by
    design: its client deletes nothing, whatever the row says."""
    if not rows:
        return Check("deletion windows", UNKNOWN, "0 rows",
                     "no external mailbox: every row carrying a window would be vacuous")
    if not state.get("listed"):
        raise Unreadable("the store helper could not list the fetch state")
    problems = []
    imap = 0
    for row in rows:
        if row["window"] is None:
            problems.append(f"{row['address']}: no window")
            continue
        if row["protocol"] == render.IMAP:
            imap += 1
            continue   # collected by our own client, which renders no file to hold
        if not collected(row) or row["fetched_at"] is None:
            continue   # never rendered, or no longer: nothing on disk to hold to its row
        rendered = state["configs"].get(str(row["id"]))
        if rendered is None:
            problems.append(f"{row['address']}: no-file")
        elif not rendered["keep"]:
            problems.append(f"{row['address']}: no-keep-line")
        elif row["kept"] and rendered["keep"] != ["on"]:
            problems.append(f"{row['address']}: keep {', '.join(rendered['keep'])} against "
                            "kept at the provider")
        elif not row["kept"] and rendered["keep"] != [f"{int(row['window'])}d"]:
            problems.append(f"{row['address']}: keep {', '.join(rendered['keep'])} against a window "
                            f"of {row['window']} days")
    over_imap = f" ({imap} over IMAP, which renders none)" if imap else ""
    reading = f"{len(rows)} rows{over_imap}, {len(state['configs'])} rendered configurations"
    if problems:
        return Check("deletion windows", FAIL, reading, "; ".join(problems))
    return passed("deletion windows", reading + ", each window as rendered")


@check("deletion windows")
def windows(ctx):
    rows = rows_of(ctx.query(MAILBOXES))
    return judge_windows(rows, ctx.helper("store", "fetch_state") if rows else {})


def mpop_path(exec_start):
    """The binary the fetch unit runs: its own `--mpop`, else the runner's default - never
    the reader's PATH."""
    argv = shlex.split(exec_start)
    if "--mpop" in argv[:-1]:
        return argv[argv.index("--mpop") + 1]
    for arg in argv:
        if arg.startswith("--mpop="):
            return arg.split("=", 1)[1]
    return runner.DEFAULT_MPOP


def judge_mpop(path, done):
    if done is None:
        return Check("fetcher", FAIL, f"{path}: will not run", "the fetcher binary is missing or "
                                                                "will not execute")
    first = done.stdout.splitlines()[0] if done.stdout else ""
    version = first.removeprefix("mpop version ").strip()
    reading = f"{path}: {first or 'printed nothing'}"
    if done.returncode != 0 or not version.replace(".", "").isdigit():
        return Check("fetcher", FAIL, reading, "the fetcher did not report a version")
    from maildivvy.lib.scan import older
    if older(version, MPOP_MINIMUM):
        return Check("fetcher", FAIL, reading, f"older than {MPOP_MINIMUM}, which refuses "
                                               "`keep <n>d`: every mailbox fails every run")
    return passed("fetcher", reading)


@check("fetcher")
def fetcher(ctx):
    exec_start = probe.show(FETCH_UNIT, "ExecStart")["ExecStart"]
    argv = exec_start.split("argv[]=", 1)[1].split(" ;", 1)[0] if "argv[]=" in exec_start else ""
    path = mpop_path(argv)
    try:
        done = probe.command([path, "--version"], timeout=20)
    except Unreadable:
        done = None
    return judge_mpop(path, done)


@check("collection timer")
def fetch_timer(ctx):
    return judge_timer("collection timer", FETCH_TIMER, probe.is_active(FETCH_TIMER),
                       pause_reason())


# every IMAP mailbox's snapshot asked for, begun or ended. `snapshot_paused_since` is
# when the slices began to leave it paused (`fetch/snapshot.py`), the last column when it
# began or, not begun yet, was asked for.
SNAPSHOTS = f"""SELECT e.address, e.snapshot_status, e.snapshot_finished_at, e.snapshot_paused_since,
                       e.snapshot_detail, e.snapshot_refused, e.snapshot_left_out,
                       coalesce(e.snapshot_started_at, e.snapshot_requested_at)
                  FROM external_mailbox e
                 WHERE e.snapshot_status IS NOT NULL OR {snapshot.WANTED} ORDER BY e.address"""
SNAPSHOT_PAUSED = datetime.timedelta(days=1)
# Far past what a slice every ten minutes takes to copy a mailbox, so a snapshot asked for or
# under way for longer is one no slice is taking: its mailbox disabled, unmapped or switched
# to POP3, or its timer stopped.
SNAPSHOT_SLOW = datetime.timedelta(days=7)


def judge_snapshots(rows, total, now):
    """WARN for a snapshot that failed, that ended done without messages the provider refused
    to send or folders it left out, that its slices have left paused for longer than a day,
    or that was asked for or began longer than SNAPSHOT_SLOW ago and is still not done.
    None ends by itself: a failed or incomplete one is never taken up again until
    a person discards it, a paused one is retried by every slice and still stopped, and a
    slow one is taken by no slice. Nothing of today's mail waits on any, so none is a FAIL.
    The count of rows read is the control that none was read at all."""
    reading = f"{len(rows)} snapshot(s) of {total} external mailbox(es)"
    late = []
    for address, status, finished, paused, detail, refused, left_out, since in rows:
        said = f": {detail}" if detail else ""
        if status == snapshot.FAILED:
            late.append(f"{address} failed at {finished.isoformat(timespec='seconds')}{said}")
        elif status == snapshot.DONE:
            missing = [f"{refused} message(s) the provider refused to send"] if refused else []
            if left_out:
                missing.append(f"{left_out} folder(s) it left out")
            if missing:
                late.append(f"{address} done without {' and '.join(missing)}{said}")
        elif status == snapshot.PAUSED and (paused is None or now - paused > SNAPSHOT_PAUSED):
            # no time only by an edit of the row: every slice that pauses it writes one
            when = ("a time not recorded" if paused is None
                    else paused.isoformat(timespec="seconds"))
            late.append(f"{address} paused since {when}{said}")
        elif now - since > SNAPSHOT_SLOW:
            late.append(f"{address} {'asked for' if status is None else 'under way'} since "
                        f"{since.isoformat(timespec='seconds')} and not done{said}")
    if late:
        return Check("snapshots", WARN, reading,
                     "a snapshot of an IMAP mailbox's folders failed or ended without messages "
                     "the provider refused or folders it left out, which nothing takes up again "
                     "until it is discarded "
                     "on the mailbox's page, or has been paused for longer than a day, or "
                     "under way for longer than a week, which its mailbox being disabled or "
                     "no longer IMAP, or its detail, explains: " + "; ".join(late))
    return passed("snapshots", reading + ", none failed, without messages or folders, paused "
                                         "for longer than a day or under way for longer than a "
                                         "week")


@check("snapshots")
def snapshots(ctx):
    return judge_snapshots(ctx.query(SNAPSHOTS), ctx.query(MAILBOX_COUNT)[0][0], ctx.now)


COLLECTION = [mailboxes, fetch_runs, retrieval_check, windows, fetcher, fetch_timer, snapshots]


# --- store ------------------------------------------


def unrecorded_folders(domains):
    """What each archive folder holds at or below the pass's cursor with no row,
    one text a folder: its first UIDs, how many more, and the command that
    records one, the pass's own skip line's. A result kept before the pass read these
    names none."""
    found, count = [], 0
    for label, domain in domains.items():
        for folder in domain.get("unrecorded", ()):
            more = folder["count"] - len(folder["uids"])
            count += folder["count"]
            found.append(
                f"{label} {folder['folder']} UID {', '.join(str(uid) for uid in folder['uids'])}"
                f"{f' and {more} more' if more else ''} (`runuser -u {store.MAIL_USER} -- "
                f"{pass_.BY_HAND} --only {label} --folder {folder['folder']} --uid <UID>`)")
    return found, count


def held_by_linking(linking):
    """ WARN, or None: the domains where a linking request was still making names
    whose rows it had not committed, and how many such names were read and not listed."""
    if not linking:
        return None
    named = "; ".join(f"{label}: {held['names']} name(s) beside request(s) "
                      f"{', '.join(str(r) for r in held['requests'])}"
                      for label, held in sorted(linking.items()))
    return (f"a request is linking, and the names it has made have no committed row yet "
            f"({named}): read again after it")


def judge_ledger(reading, name="daily ledger"):
    """a name pointing at an archive inode with no delivery row. Zero linked rows in
    total is UNKNOWN, since the check then measured nothing.

    ⛔ An archive message at or below the pass's cursor that no row holds FAILS whatever
    else is read: the pass skipped it, nobody has it, and its journal line is
    counted for a day only. It is a finding of its own, with no delivery row to wait for:
    a domain that only ever imported mail has none."""
    domains = reading["domains"]
    deliveries = sum(d["deliveries"] for d in domains.values())
    findings = [f for d in domains.values() for f in d["findings"]]
    unrecorded, count = unrecorded_folders(domains)
    reading_ = f"{len(domains)} domain(s), {deliveries} delivery rows, {len(findings)} unaccounted"
    if any("under_cursor" in d for d in domains.values()):
        under = sum(d.get("under_cursor", 0) for d in domains.values())
        reading_ += f", {count} of {under} archive message(s) under the pass's cursors unrecorded"
    renumbered = [f"{label} {folder}" for label, d in domains.items()
                  for folder in d.get("renumbered", ())]
    if renumbered:
        # the pass's next tick repairs it, and the fan-out check reads that (`0100`)
        reading_ += (f" ({'; '.join(renumbered)} not counted: its cursor is not what it was, "
                     "which the pass's next tick sets right)")
    if deliveries == 0 and not unrecorded:
        return Check(name, UNKNOWN, reading_, "no delivery row yet: the check has nothing to "
                                              "hold the store to")
    problems = []
    if findings:
        problems.append("names in people's mailboxes point at the archive with no delivery "
                        f"row: {'; '.join(findings[:5])}")
    if unrecorded:
        problems.append("the archive holds messages the pass moved past and no row records, "
                        f"so nobody has them: {'; '.join(unrecorded[:5])}")
    if problems:
        return Check(name, FAIL, reading_, "; ".join(problems))
    linking = held_by_linking({label: d["linking"] for label, d in domains.items()
                               if d.get("linking")})
    if linking:
        return Check(name, WARN, reading_, linking)
    return passed(name, reading_)


def judge_links(reading):
    """Both link-count classes present, or the check does not measure hardlinks."""
    several = sum(d["several_names"] for d in reading["domains"].values())
    one = sum(d["one_name"] for d in reading["domains"].values())
    text = f"{several} archive message(s) at several names, {one} at one"
    if not several or not one:
        return Check("link classes", UNKNOWN, text, "the store does not hold both a message fanned "
                                                    "out and one kept by the archive alone yet")
    return passed("link classes", text)


# --- the ledger's window, every run, and its daily pass ---------------------------------


def load_window(path=None):
    """What the last kept run's window carries to this one, or None: no scan yet, or a
    record that cannot be read, which starts the window again rather than stopping it."""
    try:
        found = probe.load_json(path or settings.LEDGER_WINDOW)
        helper.window_mark(found)
    except (Unreadable, ValueError, KeyError, TypeError):
        return None
    return found


def save_window(record, path=None):
    """Replace the record whole, health's alone (0600): a carried finding names an inode."""
    path = Path(path or settings.LEDGER_WINDOW)
    temporary = path.with_name(f".{path.name}.partial")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o600)   # a partial left by a stopped run keeps its mode
        json.dump(record, handle)
        handle.write("\n")
    os.replace(temporary, path)


def given(names):
    """What this run's readings are given: the store helper's window starts where the last
    kept run's began."""
    return {"store": {"ledger": load_window()}} if "store" in names else {}


def judge_window(reading):
    """The names changed since the last scan, held to the ledger."""
    findings = reading["findings"]
    if reading["since"] is None:
        return Check("ledger", UNKNOWN, "no earlier scan",
                     "the window starts with this run; every name before it is the daily "
                     "pass's to read")
    since = datetime.datetime.fromtimestamp(reading["since"], datetime.timezone.utc)
    text = (f"{reading['checked']} name(s) changed since {since:%Y-%m-%d %H:%M:%S}Z, "
            f"{reading['added']} delivery rows added, {len(findings)} unaccounted")
    if reading["deliveries"] == 0:
        return Check("ledger", UNKNOWN, text, "no delivery row yet: the check has nothing to "
                                              "hold the store to")
    if findings:
        return Check("ledger", FAIL, text,
                     f"names in people's mailboxes point at the archive with no delivery row: "
                     f"{'; '.join(findings[:5])}")
    linking = held_by_linking(reading.get("linking"))
    if linking:
        return Check("ledger", WARN, text, linking)
    return passed("ledger", text)


@check("ledger")
def ledger(ctx):
    reading = ctx.helper("store", "ledger")
    found = judge_window(reading)
    if ctx.keep:
        try:
            save_window(reading["next"])
        except OSError as err:
            # the next run's window then starts where this one did: wider, never narrower
            if found.state == PASS:
                found = Check("ledger", UNKNOWN, found.reading,
                              f"the window's mark could not be kept: {err}")
    return found


def take_ledger_pass(now, path=None):
    """The daily pass: the store helper's reading of every name, kept with its
    moment, or the reason it could not be taken."""
    try:
        reading = helper.ask("store", ["ledger_pass"], timeout=helper.LEDGER_PASS_WAIT)
        reading = reading["ledger_pass"]
    except Unreadable as err:
        reading = {"error": str(err)}
    record = {"taken_at": now.isoformat(), "reading": reading}
    save_window(record, path or settings.LEDGER_PASS)
    return record


def judge_pass(record, now, conf):
    """The daily pass's last result and age, UNKNOWN once older than its bound."""
    if record is None:
        problem = f"the daily pass has not run yet: `systemctl start {LEDGER_UNIT}`"
        return [Check("daily ledger", UNKNOWN, "no pass", problem),
                Check("link classes", UNKNOWN, "no pass", problem)]
    try:
        taken = datetime.datetime.fromisoformat(record["taken_at"])
        reading = record["reading"]
    except (KeyError, TypeError, ValueError):
        raise Unreadable(f"{settings.LEDGER_PASS} does not say when its pass was taken") from None
    hours = (now - taken).total_seconds() / 3600
    age = f"taken {hours:.0f} h ago"
    if not isinstance(reading, dict) or "error" in reading:
        problem = (f"the last pass could not read: {(reading or {}).get('error')}; "
                   f"read `journalctl -u {LEDGER_UNIT}`")
        return [Check("daily ledger", UNKNOWN, age, problem),
                Check("link classes", UNKNOWN, age, problem)]
    found = [judge_ledger(reading), judge_links(reading)]
    if hours > conf.ledger_pass_hours:
        problem = (f"the daily pass is older than {conf.ledger_pass_hours} h: "
                   f"read `journalctl -u {LEDGER_UNIT}`")
        return [Check(c.name, UNKNOWN, f"{c.reading}, {age}", problem) if c.state != FAIL
                else Check(c.name, FAIL, f"{c.reading}, {age}", c.problem) for c in found]
    first = found[0]
    if first.state == FAIL:
        problem = f"{first.problem}; once each is resolved, `systemctl start {LEDGER_UNIT}` reads them again"
        found[0] = Check(first.name, FAIL, f"{first.reading}, {age}", problem)
    elif first.state == WARN:
        found[0] = Check(first.name, WARN, f"{first.reading}, {age}",
                         f"{first.problem}, with `systemctl start {LEDGER_UNIT}`")
    else:
        found[0] = Check(first.name, first.state, f"{first.reading}, {age}", first.problem)
    return found


@check("daily ledger")
def daily_ledger(ctx):
    return judge_pass(probe.load_json(settings.LEDGER_PASS), ctx.now, ctx.settings)


def renumbered_folders(lines, marker=None):
    """The archive folders the pass named with `marker` (by default the stop of a folder
    renumbered before its rows were named, `0100`), from its own lines, each once, in the
    order first named."""
    marker = marker or pass_.UNNAMED
    folders = []
    for line in lines:
        if line.startswith(marker):
            folder = " ".join(line[len(marker):].split(":", 1)[0].split())
            if folder and folder not in folders:
                folders.append(folder)
    return folders


def running_since(shown, previous):
    """For a oneshot whose run is going (`ActiveState`): (its start, the reading, `shown`
    as its last FINISHED run left it); None when none is going.

    ⛔ systemd zeroes a unit's exit timestamp, result and status when it starts it:
    a pass running when health reads it read "has not run yet". The run before
    it is the journal's newest finished start job, `previous` ((moment, result) or None).
    """
    if shown.get("ActiveState") not in probe.RUNNING:
        return None
    started = probe.timestamp(shown.get("ExecMainStartTimestamp", ""))
    reading = f"a run going since {started.isoformat(timespec='seconds') if started else '?'}"
    if previous is None:
        return started, reading, {**shown, "ExecMainExitTimestamp": "", "Result": "success",
                                  "ExecMainStatus": "0"}
    moment, result = previous
    reading += f"; the one before ended {moment.isoformat(timespec='seconds')}: {result}"
    return started, reading, {**shown, "Result": "success" if result == "done" else result,
                              "ExecMainStatus": "0" if result == "done" else "?"}


def going_too_long(started, now, conf):
    return started is not None and now - started > datetime.timedelta(minutes=conf.fanout_minutes)


def judge_fanout(active, paused, shown, now, conf, lines=(), previous=None):
    """`lines` are the pass's own lines of the window, read when its last run failed;
    `previous` is the run before one going (`running_since`)."""
    found = [judge_timer("fan-out timer", PASS_TIMER, active, paused)]
    going = running_since(shown, previous)
    if going is not None:
        started, reading, shown = going
        ended = probe.timestamp(shown["ExecMainExitTimestamp"]) if previous is None else previous[0]
    else:
        ended, reading = last_run(shown)
    renumbered = renumbered_folders(lines)
    if going is not None and succeeded(shown):
        if going_too_long(started, now, conf) and not paused:
            found.append(Check("fan-out", WARN, reading,
                               f"a pass has been going for more than {conf.fanout_minutes} min, "
                               f"and nothing else is fanned out until it ends: read "
                               f"`journalctl -u {PASS_UNIT}`"))
        else:
            found.append(passed("fan-out", reading))
    elif ended is None:
        found.append(Check("fan-out", UNKNOWN, reading, "the pass has not run yet"))
    elif not succeeded(shown) and renumbered:
        found.append(Check("fan-out", FAIL, reading,
                           "the archive's numbering changed before the ledger's rows had their "
                           f"archive names, and nothing is linked from {'; '.join(renumbered)}: "
                           "go back to the previous release and run its `maildivvy-pass "
                           f"--renumber`, as `journalctl -u {PASS_UNIT} -g '{pass_.UNNAMED}'` "
                           "says, then upgrade again"))
    elif not succeeded(shown):
        found.append(Check("fan-out", FAIL, reading, f"the pass's last run failed: read "
                                                     f"`journalctl -u {PASS_UNIT}`"))
    elif now - ended > datetime.timedelta(minutes=conf.fanout_minutes) and not paused:
        found.append(Check("fan-out", FAIL, reading, f"no pass in {conf.fanout_minutes} min"))
    else:
        found.append(passed("fan-out", reading))
    return found


def last_run(shown):
    """When a oneshot's last run ended (None: never), and the reading that says so."""
    ended = probe.timestamp(shown["ExecMainExitTimestamp"])
    return ended, (f"last run {ended.isoformat(timespec='seconds') if ended else 'never'}: "
                   f"{shown['Result']}, status {shown['ExecMainStatus']}")


def succeeded(shown):
    return shown["Result"] == "success" and shown["ExecMainStatus"] == "0"


RUN = ("ActiveState", "Result", "ExecMainStatus", "ExecMainExitTimestamp", "ExecMainStartTimestamp")


def show_run(unit):
    """The unit's last run as `systemctl show` has it, and, while one is going, the run
    before it from the journal (`running_since`)."""
    shown = probe.show(unit, *RUN)
    previous = probe.last_start_job(unit) if shown["ActiveState"] in probe.RUNNING else None
    return shown, previous


@check("fan-out")
def fanout(ctx):
    shown, previous = show_run(PASS_UNIT)
    going = running_since(shown, previous)
    last = going[2] if going else shown
    lines = ()
    if not succeeded(last) and (going or probe.timestamp(shown["ExecMainExitTimestamp"])):
        lines = probe.journal(ctx.ago(minutes=ctx.settings.fanout_minutes), f"--unit={PASS_UNIT}")
    return judge_fanout(probe.is_active(PASS_TIMER), pause_reason(), shown, ctx.now, ctx.settings,
                        lines, previous)


def judge_provider_requests(shown, previous=None, now=None, conf=None):
    """The last run of the requests that wait on a provider, which every pass starts
    beside it: a run that failed leaves them `queued`. No staleness bound of its
    own: it runs with every pass, whose bound is the fan-out's, and so is a run's going."""
    going = running_since(shown, previous)
    if going is not None:
        started, reading, shown = going
        if succeeded(shown):
            if now is not None and going_too_long(started, now, conf):
                return Check("provider requests", WARN, reading,
                             f"a run has been going for more than {conf.fanout_minutes} min: "
                             f"read `journalctl -u {REQUESTS_UNIT}`")
            return passed("provider requests", reading)
        ended = previous[0]
    else:
        ended, reading = last_run(shown)
    if ended is None:
        return Check("provider requests", UNKNOWN, reading, f"{REQUESTS_UNIT} has not run yet")
    if not succeeded(shown):
        return Check("provider requests", FAIL, reading,
                     "the last run of the requests that wait on a provider failed, and they "
                     f"stay queued: read `journalctl -u {REQUESTS_UNIT}`")
    return passed("provider requests", reading)


@check("provider requests")
def provider_requests(ctx):
    shown, previous = show_run(REQUESTS_UNIT)
    return judge_provider_requests(shown, previous, ctx.now, ctx.settings)


def judge_skipped(lines, hours):
    """Messages the pass could not record and moved past: one line each,
    counted. Nobody has such a message until it is recorded by hand. And the archive
    folders whose numbering the pass found changed and set right (`0100`): nothing is
    lost by it, but an index tree went missing or was put back, which is the operator's
    to know of.
    ⛔ The control: the window holds the pass unit's own lines at all."""
    if not lines:
        return Check("fan-out skips", UNKNOWN, f"no pass line in the last {hours} h",
                     "the pass has not run in the window: there is nothing to read")
    skipped = sum(1 for line in lines if pass_.SKIPPED in line)
    renumbered = renumbered_folders(lines, pass_.RENUMBERED)
    reading = f"{skipped} message(s) skipped in the last {hours} h ({len(lines)} pass lines read)"
    if renumbered:
        reading += f", {len(renumbered)} archive folder(s) renumbered"
    problems = []
    if skipped:
        problems.append("the pass could not record these and reached nobody with them; each "
                        "line names the command that records it: read "
                        f"`journalctl -u {PASS_UNIT} -g '{pass_.SKIPPED}'`")
    if renumbered:
        problems.append(f"Dovecot numbered {'; '.join(renumbered)} again (an index tree lost or "
                        "put back) and the pass gave the rows their files' new numbers by base "
                        "name, recording any file no row named: read "
                        f"`journalctl -u {PASS_UNIT} -g '{pass_.RENUMBERED}'`")
    if problems:
        return Check("fan-out skips", WARN, reading, "; ".join(problems))
    return passed("fan-out skips", reading)


@check("fan-out skips")
def fanout_skips(ctx):
    hours = ctx.settings.fanout_skip_hours
    return judge_skipped(probe.journal(ctx.ago(hours=hours), f"--unit={PASS_UNIT}"), hours)


# the newest first: the check names five, and an operator wants the failure just seen
FAILED_REQUESTS = """
    SELECT kind, target FROM request
     WHERE state = 'failed' AND finished_at > %s ORDER BY finished_at DESC, id DESC
"""
ALL_REQUESTS = "SELECT count(*) FROM request"


def judge_requests(failed, total, hours):
    reading = f"{len(failed)} failed in the last {hours} h ({total} requests read)"
    if failed:
        return Check("requests", WARN, reading,
                     "the pipeline could not do what was asked: "
                     + "; ".join(f"{kind} {target}" for kind, target in failed[:5])
                     + " - the reason is on each request's row")
    return passed("requests", reading)


@check("requests")
def requests(ctx):
    hours = ctx.settings.request_failure_hours
    return judge_requests(ctx.query(FAILED_REQUESTS, (ctx.ago(hours=hours),)),
                          ctx.query(ALL_REQUESTS)[0][0], hours)


RUNNING_REQUESTS = "SELECT id, kind, target FROM request WHERE state = 'running' ORDER BY id"
# the units that drain the queue: a `running` row is held by one of them, or by nobody;
# the requests that wait on a provider drain beside the pass
DRAINERS = (PASS_UNIT, REQUESTS_UNIT)


def judge_left_running(first, second, drainer_alive):
    """A row `running` at both reads, with no drainer alive between them, is one a killed
    pass left: the claim commits before its handler runs, so nothing finishes it
    and only the next run of its drainer fails it. A drainer alive between the reads may hold
    it; one that was not cannot have taken it after the first read and still hold it."""
    left = [] if drainer_alive else [row for row in second if row in first]
    reading = f"{len(second)} running" + (", the pass is performing" if drainer_alive else "")
    if left:
        return Check("requests left running", FAIL, reading,
                     "the pass was stopped while performing "
                     + "; ".join(f"{kind} {target} (request {rid})" for rid, kind, target in left[:5])
                     + ": its next run marks each failed, then ask again "
                     "(administration guide, A request left running)")
    return passed("requests left running", reading)


@check("requests left running")
def left_running(ctx):
    first = ctx.query(RUNNING_REQUESTS)
    alive = any(probe.state(unit) in probe.RUNNING for unit in DRAINERS)
    return judge_left_running(first, ctx.query(RUNNING_REQUESTS), alive)


OLDEST_QUEUED = """
    SELECT kind, target, created_at, count(*) OVER () FROM request
     WHERE state = 'queued' ORDER BY created_at, id LIMIT 1
"""


def judge_queued(oldest, active, paused, now, conf):
    """The oldest queued request, against the bound, while the pass's timer runs: a timer
    stopped on purpose or not is the fan-out timer's own reading."""
    if oldest is None:
        return passed("request queue", "nothing queued")
    kind, target, created_at, count = oldest
    minutes = (now - created_at).total_seconds() / 60
    reading = f"{count} queued, the oldest {minutes:.0f} min ago"
    if not active or paused:
        return passed("request queue", f"{reading}, the pass's timer stopped")
    if minutes > conf.request_queued_minutes:
        return Check("request queue", WARN, reading,
                     f"{kind} {target} has waited over {conf.request_queued_minutes} min: the pass has "
                     f"not reached it; read `journalctl -u {PASS_UNIT}` and "
                     f"`journalctl -u {REQUESTS_UNIT}`")
    return passed("request queue", reading)


@check("request queue")
def request_queue(ctx):
    rows = ctx.query(OLDEST_QUEUED)
    return judge_queued(rows[0] if rows else None, probe.is_active(PASS_TIMER), pause_reason(),
                        ctx.now, ctx.settings)


# a mailbox whose last fetch was held because the archive's store could not take
# mail. Deactivated rows are not fetched, so their last cause is history.
STORE_HELD = f"""SELECT e.address, e.last_fetch_at FROM external_mailbox e
                  WHERE e.last_fetch_cause = '{outcome.STORE}' AND e.state = 'active'
                  ORDER BY e.address"""
MAILBOX_COUNT = "SELECT count(*) FROM external_mailbox"


def judge_store_hold(held, total):
    """FAIL from the first mailbox held for the store, naming when its fetch was held.
    The count of rows read is the control that "none held" was read at all."""
    if not held:
        return passed("store hold", f"no external mailbox held for the store ({total} read)")
    names = "; ".join(f"{address} at {at.isoformat(timespec='seconds')}" for address, at in held)
    return Check("store hold", FAIL, f"{len(held)} of {total} held",
                 "collection holds because the archive's store could not take mail, or the "
                 "delivery filter failed on any message, and the "
                 f"mail waits at the provider; read why in `journalctl -u {FETCH_UNIT}` for a "
                 "POP3 mailbox, and in the mailbox's detail on the fetch screen for an IMAP "
                 f"one: {names}")


@check("store hold")
def store_hold(ctx):
    return judge_store_hold(ctx.query(STORE_HELD), ctx.query(MAILBOX_COUNT)[0][0])


def judge_directories(reading):
    """a mailbox's or a domain's directory that no row holds belongs to
    nobody, and a mailbox made later for the same login would inherit it. One a failed
    deletion still lists is the next pass's to remove; any other is nobody's to remove but
    the operator's, after looking at it."""
    stray, left = reading["stray"], reading["left"]
    text = (f"{reading['listed']} directory(ies) under {reading['domains']} domain(s), "
            f"{len(stray) + len(left)} held by no row")
    if not reading["held"] and reading["domains"]:
        return Check("directories", UNKNOWN, text, "no directory any row names was found: the "
                                                   "store or the index disk is not what was read")
    problems = []
    if left:
        requests_ = sorted({entry["request"] for entry in left})
        problems.append(
            f"deleted, and left by the second step of request(s) {', '.join(map(str, requests_))}, "
            "which every run of the pass tries again (its reason is on its row): "
            + "; ".join(entry["path"] for entry in left[:5]))
    if stray:
        problems.append("no row and no deletion accounts for "
                        + "; ".join(stray[:5])
                        + ": a mailbox made for that login would inherit it; look at it, and "
                          "remove it as root once it is nobody's")
    if problems:
        return Check("directories", WARN, text, " - ".join(problems))
    return passed("directories", text)


@check("directories")
def directories(ctx):
    return judge_directories(ctx.helper("store", "directories"))


STORE = [store_hold, ledger, daily_ledger, directories, fanout, provider_requests, fanout_skips,
         requests, left_running, request_queue]


# --- database -------------------------------------------------------------------------------------


@check("answers")
def database_answers(ctx):
    version = ctx.query("SELECT current_setting('server_version')")[0][0]
    return passed("answers", f"PostgreSQL {version}, as maildivvy_health")


def judge_schema(applied, shipped):
    reading = f"applied {', '.join(applied) or 'none'}; shipped {', '.join(shipped)}"
    unknown = [v for v in applied if v not in shipped]
    missing = [v for v in shipped if v not in applied]
    if unknown:
        return Check("schema", FAIL, reading, f"applied migrations this code does not ship: "
                                              f"{', '.join(unknown)}")
    if missing:
        return Check("schema", FAIL, reading, f"not applied: {', '.join(missing)}")
    return passed("schema", reading)


@check("schema")
def schema_version(ctx):
    shipped = [m.version for m in schema.migrations()]
    applied = [row[0] for row in ctx.query("SELECT version FROM schema_version ORDER BY version")]
    return judge_schema(applied, shipped)


DATABASE = [database_answers, schema_version]


# --- backup -------------------------------------------------------


def judge_backup(record, now, conf):
    """The newest dump of the database and the fetch state, and whether the product's own run
    of the operator's store copy failed; never the store's copy itself."""
    if record is None:
        return Check("newest run", FAIL, f"{backup_status.STATUS} names no run",
                     "no backup of the database and the fetch state exists: run maildivvy-backup")
    try:
        taken = datetime.datetime.fromisoformat(record["taken_at"])
    except (KeyError, TypeError, ValueError):
        raise Unreadable(f"{backup_status.STATUS} does not say when its run was taken") from None
    hours = (now - taken).total_seconds() / 3600
    reading = (f"{record['stamp']}, {hours:.0f} h old, {record.get('tables')} tables, "
               f"{record.get('rows')} rows, {record.get('state_entries')} state entries")
    if hours > conf.backup_hours:
        return Check("newest run", FAIL, reading, f"older than {conf.backup_hours} h: the daily "
                                                  "backup has not run")
    copy = record.get("store_copy")
    if isinstance(copy, str) and copy.startswith("failed"):
        return Check("newest run", WARN, reading, f"its store copy {copy}: {restore_point(record, now)}; "
                                                  f"read `journalctl -u {BACKUP_UNIT}`")
    return passed("newest run", reading)


def restore_point(record, now):
    """The newest run the store can be restored with, as the backup recorded it beside the
    status: the runs themselves are root's alone."""
    if "newest_store_copied" not in record:   # a status written before the backup recorded it
        return f"`ls {backup_run.BACKUPS}/*/{archive.PAIRED}` names the runs that have one"
    paired = record["newest_store_copied"]
    if paired is None:
        return "no run kept has one, so no dump can be restored with the store"
    try:
        taken = datetime.datetime.strptime(paired, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise Unreadable(f"{backup_status.STATUS} names no run as the newest with a store copy") from None
    return (f"the newest run with a store copy to restore with is {paired}, "
            f"{(now - taken).total_seconds() / 3600:.0f} h old")


@check("newest run")
def newest_backup(ctx):
    return judge_backup(backup_status.read(), ctx.now, ctx.settings)


@check("backup timer")
def backup_timer(ctx):
    return judge_timer("backup timer", BACKUP_TIMER, probe.is_active(BACKUP_TIMER), "")


BACKUP = [newest_backup, backup_timer]

WANTS = {"collection": {"store": ["fetch_state"]}, "store": {"store": ["ledger", "directories"]}}
