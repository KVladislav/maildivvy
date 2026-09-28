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
import shlex
from pathlib import Path

from maildivvy.backup import status as backup_status
from maildivvy.fetch import outcome, runner
from maildivvy.health import probe
from maildivvy.health.context import check, passed
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import FAIL, UNKNOWN, WARN, Check
from maildivvy.lib import retrieval, schema, timer

FETCH_UNIT, FETCH_TIMER = "maildivvy-fetch.service", "maildivvy-fetch.timer"
PASS_UNIT, PASS_TIMER = "maildivvy-pass.service", "maildivvy-pass.timer"
BACKUP_UNIT, BACKUP_TIMER = "maildivvy-backup.service", "maildivvy-backup.timer"
MPOP_MINIMUM = "1.4.23"   # 1.4.21 refuses `keep <n>d` at parse


def paused_for_backup():
    """A backup pauses collection and fan-out on purpose. ⛔ The backup is a
    oneshot: `activating` for the whole of its run and never `active`, which is why
    `is_active` never saw one."""
    return probe.state(BACKUP_UNIT) in probe.RUNNING


# maildivvy-install's record of an upgrade's pause (installer.upgrade.PAUSE_RECORD): there
# while an upgrade runs its steps, and after one that failed past its migrations
UPGRADE_PAUSE = Path("/etc/maildivvy/upgrade-paused.json")


BACKUP_PAUSE = "paused while the backup runs"


def pause_reason():
    """Why collection and fan-out are paused on purpose, or "" when they are not."""
    if paused_for_backup():
        return BACKUP_PAUSE
    if UPGRADE_PAUSE.exists():
        return f"paused by an upgrade ({UPGRADE_PAUSE}): maildivvy-install starts it again once one finishes"
    return ""


def judge_timer(name, timer, active, paused):
    """`paused` is why the timer is stopped on purpose (pause_reason), "" when it is not."""
    reading = f"{timer} {'active' if active else 'inactive'}"
    if active:
        return passed(name, reading)
    if paused:
        return Check(name, WARN, reading, paused)
    return Check(name, FAIL, reading, f"{timer} is stopped: nothing runs it")


# --- collection ------------------------------------

MAILBOXES = """
    SELECT e.id, e.address, e.state, e.delete_window_days, e.last_fetch_at, e.last_fetch_status,
           e.last_fetch_cause, e.last_fetch_detail, e.frozen_since, e.last_skip_at,
           e.last_skip_uidl, d.label
      FROM external_mailbox e LEFT JOIN domain d ON d.external_mailbox_id = e.id
     ORDER BY e.id
"""
COLUMNS = ("id", "address", "state", "window", "fetched_at", "status", "cause", "detail",
           "frozen_since", "skipped_at", "skipped_uidl", "domain")


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
    its own `keep <n>d`: mpop's default with no `keep` line is DELETE."""
    if not rows:
        return Check("deletion windows", UNKNOWN, "0 rows",
                     "no external mailbox: every row carrying a window would be vacuous")
    if not state.get("listed"):
        raise Unreadable("the store helper could not list the fetch state")
    problems = []
    for row in rows:
        if row["window"] is None:
            problems.append(f"{row['address']}: no window")
            continue
        if not collected(row) or row["fetched_at"] is None:
            continue   # never rendered, or no longer: nothing on disk to hold to its row
        rendered = state["configs"].get(str(row["id"]))
        if rendered is None:
            problems.append(f"{row['address']}: no-file")
        elif not rendered["keep"]:
            problems.append(f"{row['address']}: no-keep-line")
        elif rendered["keep"] != [f"{int(row['window'])}d"]:
            problems.append(f"{row['address']}: keep {', '.join(rendered['keep'])} against a window "
                            f"of {row['window']} days")
    reading = f"{len(rows)} rows, {len(state['configs'])} rendered configurations"
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


COLLECTION = [mailboxes, fetch_runs, retrieval_check, windows, fetcher, fetch_timer]


# --- store ------------------------------------------


def judge_ledger(reading):
    """a name pointing at an archive inode with no delivery row. Zero linked rows in
    total is UNKNOWN, since the check then measured nothing."""
    domains = reading["domains"]
    deliveries = sum(d["deliveries"] for d in domains.values())
    findings = [f for d in domains.values() for f in d["findings"]]
    reading_ = f"{len(domains)} domain(s), {deliveries} delivery rows, {len(findings)} unaccounted"
    if deliveries == 0:
        return Check("ledger", UNKNOWN, reading_, "no delivery row yet: the check has nothing to "
                                                  "hold the store to")
    if findings:
        return Check("ledger", FAIL, reading_,
                     f"names in people's mailboxes point at the archive with no delivery row: "
                     f"{'; '.join(findings[:5])}")
    return passed("ledger", reading_)


def judge_links(reading):
    """Both link-count classes present, or the check does not measure hardlinks."""
    several = sum(d["several_names"] for d in reading["domains"].values())
    one = sum(d["one_name"] for d in reading["domains"].values())
    text = f"{several} archive message(s) at several names, {one} at one"
    if not several or not one:
        return Check("link classes", UNKNOWN, text, "the store does not hold both a message fanned "
                                                    "out and one kept by the archive alone yet")
    return passed("link classes", text)


@check("ledger")
def ledger(ctx):
    reading = ctx.helper("store", "ledger")
    return [judge_ledger(reading), judge_links(reading)]


def judge_fanout(active, paused, shown, now, conf):
    found = [judge_timer("fan-out timer", PASS_TIMER, active, paused)]
    ended = probe.timestamp(shown["ExecMainExitTimestamp"])
    reading = (f"last run {ended.isoformat(timespec='seconds') if ended else 'never'}: "
               f"{shown['Result']}, status {shown['ExecMainStatus']}")
    if ended is None:
        found.append(Check("fan-out", UNKNOWN, reading, "the pass has not run yet"))
    elif shown["Result"] != "success" or shown["ExecMainStatus"] != "0":
        found.append(Check("fan-out", FAIL, reading, f"the pass's last run failed: read "
                                                     f"`journalctl -u {PASS_UNIT}`"))
    elif now - ended > datetime.timedelta(minutes=conf.fanout_minutes) and not paused:
        found.append(Check("fan-out", FAIL, reading, f"no pass in {conf.fanout_minutes} min"))
    else:
        found.append(passed("fan-out", reading))
    return found


@check("fan-out")
def fanout(ctx):
    return judge_fanout(probe.is_active(PASS_TIMER), pause_reason(),
                        probe.show(PASS_UNIT, "Result", "ExecMainStatus", "ExecMainExitTimestamp"),
                        ctx.now, ctx.settings)


FAILED_REQUESTS = """
    SELECT kind, target FROM request
     WHERE state = 'failed' AND finished_at > %s ORDER BY finished_at
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


STORE = [ledger, fanout, requests]


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


# --- backup ----------------------------------------------------------------


def judge_backup(record, now, conf):
    """The newest dump of the database and the fetch state, never the store's copy."""
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
    return passed("newest run", reading)


@check("newest run")
def newest_backup(ctx):
    return judge_backup(backup_status.read(), ctx.now, ctx.settings)


@check("backup timer")
def backup_timer(ctx):
    return judge_timer("backup timer", BACKUP_TIMER, probe.is_active(BACKUP_TIMER), "")


BACKUP = [newest_backup, backup_timer]

WANTS = {"collection": {"store": ["fetch_state"]}, "store": {"store": ["ledger"]}}
