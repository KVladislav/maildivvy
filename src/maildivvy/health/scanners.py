"""The two scanners: `antivirus` and `spam`.

⛔ A SCANNER IS JUDGED FROM THE RUNNING DAEMON, NEVER FROM ITS FILES. The
spam scanner ran eleven days with a section it had refused, listed under its own error
with exit 0, every verdict wrong, while both socket probes read green. So the spam
subsystem scores a probe message and reads the sender-pinning rule's own line for it,
reads the enabled modules out of the daemon itself, and reads the daemon's log since its
last start for a configuration error - the start's own line being the control that the
window was read at all.
"""

import datetime
import re
import secrets
import time

from maildivvy.health import probe, upstream
from maildivvy.health.context import check, passed
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import FAIL, UNKNOWN, WARN, Check
from maildivvy.health.settings import SCANNER, UPSTREAM
from maildivvy.lib import scan

CLAMD_UNIT = "clamav-daemon.service"
RSPAMD_TAG = "maildivvy-rspamd"   # the journald driver's tag
# The modules this product's verdicts rest on: the sender's authentication and the
# message's own shape. `Modules disabled (failed)` must also be empty.
REQUIRED_MODULES = ("regexp", "hfilter", "mime_types", "phishing", "spf", "dkim", "dmarc", "arc")
CONFIG_ERRORS = re.compile(r"config schema error|unknown_field|cannot (?:open|read|parse) "
                           r"(?:config|file|the configuration)|syntax error|Permission denied",
                           re.IGNORECASE)
STARTED = "is loading configuration"
PIN_RULE = "rspamd.local.lua"


# --- antivirus -------------------------------------------------------------------------------------


def judge_clamd(active, version, now, conf):
    """Running, answering on its socket, and its signatures fresh."""
    if version is None:
        state = "active" if active else "inactive"
        return [Check("daemon", FAIL, f"{CLAMD_UNIT} {state}, the socket did not answer",
                      "the antivirus does not answer: mail is held at the provider")]
    found = [passed("daemon", f"ClamAV {version.engine} answering on {scan.CLAMD_SOCKET}")]
    if version.signatures_built is None:
        found.append(Check("signatures", UNKNOWN, f"set {version.signatures}",
                           "the daemon did not say when its signatures were built"))
        return found
    built = version.signatures_built.astimezone(datetime.timezone.utc)
    hours = (now - built).total_seconds() / 3600
    reading = f"set {version.signatures}, built {built.isoformat(timespec='minutes')} ({hours:.0f} h)"
    if hours > conf.signatures_fail_hours:
        found.append(Check("signatures", FAIL, reading, f"older than {conf.signatures_fail_hours} h: "
                                                        "the updater is not updating"))
    elif hours > conf.signatures_warn_hours:
        found.append(Check("signatures", WARN, reading, f"older than {conf.signatures_warn_hours} h"))
    else:
        found.append(passed("signatures", reading))
    return found


@check("daemon")
def clamd(ctx):
    return judge_clamd(probe.is_active(CLAMD_UNIT), scan.clamd_version(timeout=30), ctx.now,
                       ctx.settings)


HELD = """SELECT e.address, e.held_since FROM external_mailbox e
           WHERE e.held_since IS NOT NULL ORDER BY e.held_since"""
COUNT = "SELECT count(*) FROM external_mailbox"


def judge_held(held, total):
    """FAIL from the first hold, naming since when. The count of rows read is the
    control that "none held" was read from the table."""
    if not held:
        return passed("held mail", f"no external mailbox held ({total} read)")
    names = "; ".join(f"{address} since {since.isoformat(timespec='seconds')}" for address, since in held)
    return Check("held mail", FAIL, f"{len(held)} of {total} held",
                 f"mail waits at the provider because the antivirus did not answer: {names}")


@check("held mail")
def held_mail(ctx):
    return judge_held(ctx.query(HELD), ctx.query(COUNT)[0][0])


def judge_upstream(installed, latest, newer_since, now, conf):
    """FAIL once upstream has been newer for longer than the bound; UNKNOWN when it
    could not be read."""
    reading = f"installed {installed}, upstream recommends {latest}"
    if not scan.older(installed, latest):
        return passed("upstream release", reading)
    days = (now - newer_since).total_seconds() / 86400
    reading += f", newer since {newer_since.date().isoformat()}"
    if days > conf.clamav_upstream_days:
        return Check("upstream release", FAIL, reading,
                     f"upstream has been newer for {days:.0f} days, over the "
                     f"{conf.clamav_upstream_days}-day bound: the security pocket has not shipped it")
    return Check("upstream release", WARN, reading, "upstream has a newer ClamAV; the security "
                                                    "pocket usually ships it within days")


@check("upstream release")
def clamav_upstream(ctx):
    version = scan.clamd_version(timeout=30)
    if version is None:
        raise Unreadable("the running daemon did not say its version")
    latest, record = upstream.cached(UPSTREAM, "clamav", ctx.now,
                                     ctx.settings.upstream_refresh_hours, upstream.clamav_release)
    since = None
    if scan.older(version.engine, latest):
        mark = record.get("clamav_newer") or {}
        if mark.get("installed") == version.engine and mark.get("upstream") == latest:
            since = datetime.datetime.fromisoformat(mark["since"])
        else:
            since = ctx.now
            record["clamav_newer"] = {"installed": version.engine, "upstream": latest,
                                      "since": since.isoformat()}
            try:
                upstream.save(UPSTREAM, record)
            except OSError:
                pass
    return judge_upstream(version.engine, latest, since, ctx.now, ctx.settings)


ANTIVIRUS = [clamd, held_mail, clamav_upstream]


# --- spam ------------------------------------------------------------------------------------------


def probe_message(mid):
    return (f"From: maildivvy-health <health@health.invalid>\r\nTo: nobody@health.invalid\r\n"
            f"Subject: maildivvy-health probe\r\nMessage-ID: <{mid}>\r\n"
            f"Date: {datetime.datetime.now(datetime.timezone.utc):%a, %d %b %Y %H:%M:%S +0000}\r\n"
            "\r\nA probe of the spam scanner by maildivvy-health.\r\n").encode()


def task_tag(lines, mid):
    """The rspamd task tag (`<9acee6>`) of the log line that names this Message-ID."""
    for line in lines:
        if f"id: <{mid}>" in line:
            match = re.search(r"\(normal\) <(\w+)>;", line)
            if match:
                return match.group(1)
    return None


def judge_scored(score, tag, rule_ran):
    """A probe scored, and the product's sender-pinning rule ran on it: without its mount
    the daemon starts clean, logs nothing and scores against the wrong host."""
    if score.score is None:
        return [Check("scores", FAIL, f"{scan.RSPAMD_SOCKET}", f"the probe was not scored: {score.detail}")]
    found = [passed("scores", f"a probe scored {score.score:.2f}")]
    if tag is None:
        found.append(Check("sender pin rule", UNKNOWN, "the probe's log line was not found",
                           "the scanner's journal does not show the probe; the rule could not be read"))
    elif not rule_ran:
        found.append(Check("sender pin rule", FAIL, f"task <{tag}>: no line of {PIN_RULE}",
                           f"the product's own rule did not run on the probe: {PIN_RULE} is not "
                           "loaded, and every sender is judged against the provider's host"))
    else:
        found.append(passed("sender pin rule", f"task <{tag}>: {PIN_RULE} ran"))
    return found


@check("scores")
def scores(ctx):
    mid = f"health-{secrets.token_hex(8)}@health.invalid"
    before = ctx.now - datetime.timedelta(seconds=5)
    score = scan.scan_spam(probe_message(mid), timeout=30)
    if score.score is None:
        return judge_scored(score, None, False)
    tag, lines = None, []
    for _ in range(10):   # the journald driver writes the lines a moment later
        lines = probe.journal(before, f"SYSLOG_IDENTIFIER={RSPAMD_TAG}")
        tag = task_tag(lines, mid)
        if tag and any(f"<{tag}>" in line and PIN_RULE in line for line in lines):
            break
        time.sleep(1)
    rule_ran = tag is not None and any(f"<{tag}>" in line and PIN_RULE in line for line in lines)
    return judge_scored(score, tag, rule_ran)


def module_lines(dump):
    lines = {}
    for line in dump.splitlines():
        name, sep, rest = line.partition(":")
        if sep and name.startswith("Modules"):
            lines[name.strip()] = [m.strip() for m in rest.split(",") if m.strip()]
    if "Modules enabled" not in lines:
        raise Unreadable("rspamadm configdump -m printed no list of enabled modules")
    return lines


def judge_modules(dump):
    lines = module_lines(dump)
    enabled = lines["Modules enabled"]
    failed = lines.get("Modules disabled (failed)", [])
    missing = [name for name in REQUIRED_MODULES if name not in enabled]
    reading = f"{len(enabled)} enabled, {len(failed)} failed; required: {', '.join(REQUIRED_MODULES)}"
    problems = []
    if missing:
        problems.append(f"not enabled: {', '.join(missing)}")
    if failed:
        problems.append(f"failed: {', '.join(failed)}")
    if problems:
        return Check("modules", FAIL, reading, "; ".join(problems))
    return passed("modules", reading)


def judge_container(container):
    reading = (f"{container['name']} {'running' if container['running'] else 'not running'} since "
               f"{container['started_at']}, restarted {container['restarts']} times")
    if not container["running"]:
        return Check("container", FAIL, reading, "the spam scanner is not running")
    return passed("container", reading)


def judge_config_log(lines, started_at):
    """No configuration error since the daemon's last start. The start's own
    line is the control that the window reaches back to it."""
    if not any(STARTED in line for line in lines):
        raise Unreadable(f"the scanner's journal since {started_at} holds no `{STARTED}` line: "
                         "the window does not reach its start")
    errors = [line for line in lines if CONFIG_ERRORS.search(line)]
    reading = f"{len(lines)} lines since the start at {started_at}"
    if errors:
        return Check("configuration log", FAIL, reading,
                     f"{len(errors)} configuration error(s) since the start, the first: "
                     f"{errors[0][-200:]}")
    return passed("configuration log", reading + ", no configuration error")


def docker_time(value):
    """`2026-09-23T11:00:46.524796232Z`, as the runtime writes it, to the second."""
    match = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)$", value or "")
    if not match:
        raise Unreadable(f"the container's start time {value!r} is not one the runtime writes")
    return datetime.datetime.fromisoformat(match.group(1) + match.group(2).replace("Z", "+00:00"))


@check("container")
def container(ctx):
    return judge_container(ctx.helper("system", "rspamd")["container"])


def running_scanner(ctx):
    reading = ctx.helper("system", "rspamd")
    if not reading["container"]["running"]:
        raise Unreadable("the scanner is not running, so its daemon cannot be asked")
    return reading


@check("modules")
def modules(ctx):
    return judge_modules(running_scanner(ctx)["modules"])


@check("configuration log")
def configuration_log(ctx):
    started_at = running_scanner(ctx)["container"]["started_at"]
    lines = probe.journal(docker_time(started_at) - datetime.timedelta(seconds=2),
                          f"CONTAINER_NAME={running_scanner(ctx)['container']['name']}")
    return judge_config_log(lines, started_at)


def judge_repin(tag, newest):
    reading = f"pinned {tag}, newest on its line {newest or tag}"
    if newest and upstream.RELEASE.match(newest) and scan.older(tag, newest):
        return Check("repin", FAIL, reading, f"rspamd {newest} is released: repin through the "
                                             "install (ansible/README.md § The spam scanner step)")
    return passed("repin", reading)


@check("repin")
def repin(ctx):
    pin = probe.load_json(SCANNER)
    if not isinstance(pin, dict) or not pin.get("tag") or not pin.get("repository"):
        raise Unreadable(f"{SCANNER} names no pin")
    # keyed by the pinned line, so a repin to another line asks again
    key = f"rspamd {pin['repository']} {'.'.join(pin['tag'].split('.')[:2])}"
    tags, _ = upstream.cached(UPSTREAM, key, ctx.now, ctx.settings.upstream_refresh_hours,
                              lambda: upstream.rspamd_tags(pin["repository"], pin["tag"]))
    return judge_repin(pin["tag"], upstream.newest_patch(tags, pin["tag"]))


SPAM = [scores, container, modules, configuration_log, repin]

WANTS = {"spam": {"system": ["rspamd"]}}
