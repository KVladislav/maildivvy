"""The Health screen: the report health's timer last wrote, with its own time and age.

⛔ **THE REPORT IS SOMETHING WRITTEN EARLIER, AND THE SCREEN SAYS SO**. Health runs
as its own user, with helpers this interface must never reach, every few minutes; this
screen only reads the file it keeps. So the report's time and age are always shown, and a
report that has stopped being current is never shown as fine: a stale one - older than
health's own bound, or dated in the future - is judged with health's own UNKNOWN
`freshness` check in every subsystem, so a stale PASS reads UNKNOWN and a stale FAIL stays
FAIL, and the screen says so once, in a banner; a missing, unreadable, truncated or
incomplete one is no report at all, UNKNOWN, with its reason.

Every signed-in page carries the same reading, a few words in its header (`status()`),
read once per request with the screen's own reader.

The file is read by health's own reader with health's own settings, exactly as
`maildivvy-health --cached` reads it, so this screen and the operator's monitoring never
disagree about one file. The screen runs no check, writes nothing and
needs no privilege: the file is world-readable and the interface's unit hides nothing
under /var/lib.

The overview reads `reading()` too, for "needs attention" and its Health row.
"""

import datetime

from flask import current_app, g

from maildivvy.admin import app
from maildivvy.admin.screens.common import spell, timer_period
from maildivvy.health import report, settings

REPORT = settings.REPORT
# the timer health's install step writes; its period is read off it, never assumed
HEALTH_TIMER = "/etc/systemd/system/maildivvy-health.timer"

# the order a report's counts are said in, the worst last, as health orders its states
ORDER = report.STATES

PAGE = """
<h1>Health</h1>
{%- if health.condition == 'unreadable' %}
<p class="banner state-fail">No health report could be read: {{ health.why }}. Nothing on this screen
says the machine is well.</p>
<p>The report is <code>{{ path }}</code>, written by health's timer as its own user.</p>
{%- else %}
{%- if health.condition == 'stale' %}
<p class="banner state-warn">This report is {{ health.why }}. Every subsystem below reads UNKNOWN at
best; a FAIL in it is still a FAIL.</p>
{%- endif %}
<p>The whole reads <span class="badge state-{{ health.state|lower }}">{{ health.state }}</span> in the report of
{{ health.taken }}
{%- if health.condition == 'current' %}, {{ health.age }} old.
{%- if health.period %} The next is due by the health timer's own period ({{ health.period }}).
{%- else %} The health timer's period could not be read from the machine.{% endif %}
A report older than {{ health.bound }} is stale.
{%- else %}.{% endif %}</p>
<table>
<tr><th>Subsystem</th><th>State</th><th>Checks</th></tr>
{%- for subsystem in health.subsystems %}
<tr>
  <td><code>{{ subsystem.name }}</code></td>
  <td><span class="badge state-{{ subsystem.state|lower }}">{{ subsystem.state }}</span></td>
  <td>
  {%- for check in subsystem.checks %}
    <div class="check"><span class="badge state-{{ check.state|lower }}">{{ check.state }}</span>
      <code>{{ check.name }}</code>: {{ check.reading }}
      {%- if check.problem %}<div class="problem">{{ check.problem }}</div>{% endif %}</div>
  {%- endfor %}
  </td>
</tr>
{%- else %}
<tr><td colspan="3">The report holds no subsystem.</td></tr>
{%- endfor %}
</table>
{%- endif %}
<footer>This screen shows what health's timer last found, never a reading taken now; for
one, run <code>maildivvy-health</code> on the machine as its own user. A check is
<code>PASS</code>, <code>WARN</code>, <code>UNKNOWN</code> or <code>FAIL</code>, and a
subsystem takes its worst check. <code>UNKNOWN</code> means a reading could not be taken;
it is never a <code>PASS</code>.</footer>
"""


def age_words(age):
    """An age as the screen says it, in whole units: "3 minutes", "2 hours", "9 days"."""
    minutes = max(int(age.total_seconds() // 60), 0)
    if minutes < 1:
        return "under a minute"
    if minutes < 120:
        return f"{minutes} minute" + ("s" if minutes != 1 else "")
    if minutes < 48 * 60:
        return f"{minutes // 60} hours"
    return f"{minutes // (24 * 60)} days"


def counted(subsystems):
    """"11 PASS, 4 UNKNOWN": how many subsystems are in each state, the worst last."""
    found = [s.state for s in subsystems]
    return ", ".join(f"{found.count(state)} {state}" for state in ORDER if state in found)


def failing(subsystems):
    """Each FAIL subsystem, with its first FAIL check and health's own sentence for it."""
    named = []
    for subsystem in subsystems:
        if subsystem.state != report.FAIL:
            continue
        first = next(c for c in subsystem.checks if c.state == report.FAIL)
        named.append({"name": subsystem.name, "check": first.name, "problem": first.problem})
    return named


def reading(report_path=REPORT, conf_path=settings.CONF, timer_path=HEALTH_TIMER, now=None):
    """The report as this interface shows it: `condition` is current, stale or unreadable.

    ⛔ Never a check run here, and never a guess: what cannot be read is said to be so.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    period = timer_period(timer_path)
    said = {"condition": "unreadable", "state": report.UNKNOWN, "taken": None,
            "age": None, "bound": None, "period": spell(period), "why": None,
            "subsystems": [], "counts": None, "failing": []}
    try:
        conf = settings.read(conf_path)
    except settings.SettingsError as err:
        return {**said, "why": f"health's settings cannot be read: {err}"}
    bound = datetime.timedelta(minutes=conf.stale_minutes)
    whole = report.read_json(report_path, now, bound)
    said["bound"] = spell(bound)
    checks = [c for s in whole.subsystems for c in s.checks]
    unread = [c for c in checks if c.name == report.REPORT_FILE]
    if unread:
        return {**said, "why": unread[0].problem}
    stale = any(c.name == report.FRESHNESS for c in checks)
    age = now - whole.taken_at
    future = stale and age < datetime.timedelta(0)
    if future:
        why = "dated in the future, so the clock or the file is wrong"
    elif stale:
        why = f"{age_words(age)} old, older than {spell(bound)}, so the checks have stopped"
    else:
        why = None
    # ⚠️ The stale rule stays in the states - each subsystem was judged WITH health's
    # freshness check, so a stale PASS reads UNKNOWN and a FAIL stays FAIL - but the check
    # itself is said once, above the table, rather than fifteen times under every row.
    shown = []
    for subsystem in whole.subsystems:
        row = subsystem.as_dict()
        row["checks"] = [c for c in row["checks"] if c["name"] != report.FRESHNESS]
        shown.append(row)
    return {**said,
            "condition": "stale" if stale else "current",
            "state": whole.state,
            "taken": whole.taken_at.astimezone(datetime.timezone.utc)
                     .strftime("%Y-%m-%d %H:%M:%S UTC"),
            "age": "dated in the future" if future else age_words(age),
            "why": why,
            "subsystems": shown,
            "counts": counted(whole.subsystems),
            "failing": failing(whole.subsystems)}


def configured():
    """`reading()` of the paths the application names; the machine's own by default.

    Read once per request and kept for it: the header and the screen below it say the
    same thing about the same read of the file.
    """
    if "health_reading" not in g:
        config = current_app.config
        g.health_reading = reading(
            report_path=config.get("MAILDIVVY_HEALTH_REPORT", REPORT),
            conf_path=config.get("MAILDIVVY_HEALTH_CONF", settings.CONF),
            timer_path=config.get("MAILDIVVY_HEALTH_TIMER", HEALTH_TIMER),
            now=config.get("MAILDIVVY_HEALTH_NOW"))
    return g.health_reading


# --- the status in every signed-in page's header -----------------------------------------------

# ⚠️ `tone` is the header's colour and nothing else. With no report the state stays
# UNKNOWN, as on the screen, but the header alarms as a FAIL does: nothing is known, so
# every page must say so loudly. A stale report keeps its own state's colour.
NO_REPORT = {"state": report.UNKNOWN, "tone": report.FAIL, "words": "no report",
             "detail": None}


def status():
    """The header's few words: the whole state and the report's age, from `configured()`.

    ⛔ A page never fails because of this: whatever goes wrong reading the report is the
    unreadable state, "no report", and the page renders. And it never says PASS for a
    stale report, because a stale report's whole state is UNKNOWN or FAIL already.
    """
    try:
        said = configured()
    except Exception:  # noqa: BLE001 - the page stands whatever the reader did
        return NO_REPORT
    if said["condition"] == "unreadable":
        return NO_REPORT
    if said["condition"] == "stale":
        detail = ("dated in the future" if said["age"] == "dated in the future"
                  else f"stale, {said['age']} old")
    else:
        detail = f"{said['age']} ago"
    return {"state": said["state"], "tone": said["state"], "words": said["state"],
            "detail": detail}


def register(app_):
    @app_.get("/health")
    def health():
        return app.render("Health", PAGE, section="health", health=configured(),
                          path=current_app.config.get("MAILDIVVY_HEALTH_REPORT", REPORT))
