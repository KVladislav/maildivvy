"""The fetch screen: where a person learns that collection has stopped, and why.

Three things bring somebody here: a provider password was changed, so
the credential is refused and nothing arrives; a message is stuck, so the session stops
on it every run; or a mailbox is frozen, because it skipped once and would skip again.

⛔ **AN ERROR IS NEVER CLASSIFIED FROM ITS WORDING.** The source read the fetcher's free
text and guessed, so a change of wording silently reclassified errors. Here the fetch runner writes a CAUSE from a closed list
(`fetch/outcome.py`, `external_mailbox.last_fetch_cause`) and this screen only names it.
The raw detail is shown beneath, as text.

⛔ **THE LAST SKIP STAYS VISIBLE UNTIL ITS DELETION DATE PASSES, WHATEVER RETRY STATE IS
NEWER**. In the predecessor a skip line was hidden the moment a
new stuck episode began - so the one fact with a deadline attached, that the provider
deletes that message on a stated day and nothing will remind anyone, was the first to
disappear. The retry state and the skip are two separate readings here.

⚠️ **The period comes from the timer, not from a constant**. "Next by"
is the last run plus the fetch timer's own `OnCalendar`, read off the installed unit, so
an operator who changes the cadence does not get a screen quietly lying about it.
"""

from datetime import date, datetime, timedelta, timezone

from flask import g

from maildivvy.admin import app
from maildivvy.admin.screens import common, domains, external
from maildivvy.admin.screens.common import (EVERY_MINUTES, EVERY_SECONDS, FETCH_TIMER,
                                            spell, timer_period)
from maildivvy.fetch.runner import DEFAULT_STUCK_AFTER

# ⚠️ The timer reading lives in `common.py` now, because every screen with a waiting row
# needs it; the names are kept here so this screen still reads as one.
__all__ = ["EVERY_MINUTES", "EVERY_SECONDS", "FETCH_TIMER", "spell", "timer_period"]

# `external_mailbox.last_fetch_cause`'s closed list, in the schema's own order. A cause
# this screen does not know is named as itself rather than dropped.
CAUSES = {
    "unrecorded": "the fetcher could not record what it decided",
    "timeout": "killed at the runner's timeout",
    "stuck_message": "stuck on one message",
    "unreachable": "cannot reach the provider",
    "transient": "stopped by something transient",
}
NO_CAUSE = ("stopped by something transient. Nothing was recorded about it, so it "
            "cannot be told apart from anything else that stops a run")

REFUSED_SHORT = "credential refused"
REFUSED = (REFUSED_SHORT + " — the account's owner very likely changed the "
           "password. Ingest for this address has stopped.")
DISABLED = "disabled — not fetched"

ROWS = external.ROW + " ORDER BY e.address"

# ⚠️ The design's voices: a row's status is a word beside its icon - red for a
# refused credential, amber for what waits on the pipeline or on a person, green for a
# fetch that ran - or muted where nothing is fetched. The retry state beneath is amber.
PAGE = """
{%- set heading %}Fetch{% endset %}
{%- set lede %}Last run {{ last_run or 'never' }}.
{%- if next_by %} Next by {{ next_by }}, the fetch timer's own period ({{ period }}).
{%- else %} The fetch timer's period could not be read from the machine.{% endif %}{% endset %}
{{ refused(refusal) }}
<div class="stack">
<section class="box"><div class="table-wrap"><table>
<thead><tr><th>Address</th><th>Domain</th><th>Last fetched</th><th>Status</th>\
<th class="acts">Actions</th></tr></thead>
<tbody>
{%- for row in mailboxes %}
{%- set said = reading[row.id] %}
<tr>
  <td><a href="{{ url_for('external_mailbox', external_id=row.id) }}"><code>{{ row.address }}</code></a>
      {%- if row.comment %}<span class="row-sub">{{ row.comment }}</span>{% endif %}</td>
  <td>{% if row.domain_id %}<a href="{{ url_for('domain', domain_id=row.domain_id) }}"><code>{{ row.label }}</code></a>{% else %}&mdash;{% endif %}</td>
  <td>{% if row.last_fetch_at %}{{ row.last_fetch_at }}{% else %}<span class="muted">never</span>{% endif %}</td>
  <td class="wrap">
    {%- if said.tone == 'off' %}<span class="muted">{{ said.status }}</span>
    {%- else %}<span class="state-{{ said.tone }}"><svg class="icon {{ said.tone }}"><use href="#i-{{ said.icon }}"/></svg> {{ said.status }}</span>{% endif %}
    {%- if said.detail %}<span class="row-sub"><code>{{ said.detail }}</code></span>{% endif %}
    <span class="row-sub">{{ said.check }}</span>
    {%- if said.retry %}<span class="row-sub state-attn"><svg class="icon attn"><use href="#i-\
{{- 'alert' if row.frozen_since else 'clock' }}"/></svg> {{ said.retry }}</span>{% endif %}
    {%- if said.skip %}<span class="row-sub">{{ said.skip }}</span>{% endif %}
  </td>
  <td class="acts">
    {%- if row.state != 'active' %}<span class="muted">&mdash;</span>
    {%- else %}
      {%- if row.frozen_since %}
      <form method="post" action="{{ url_for('resume_fetch', external_id=row.id) }}">\
<button class="btn btn-sm" type="submit">Resume&hellip;</button></form>
      {%- endif %}
      <form method="post" action="{{ url_for('refetch', external_id=row.id) }}">\
<button class="btn btn-sm" type="submit">Refetch now</button></form>
    {%- endif -%}
  </td>
</tr>
{%- else %}
<tr><td colspan="5">No external mailbox yet, so nothing is collected.</td></tr>
{%- endfor %}
</tbody>
</table></div></section>
<p class="muted">A row reads one of: <code>credential refused</code>, <code>ok</code>,
<code>no new mail</code>, <code>has not run yet</code>, <code>disabled &mdash; not
fetched</code>, <code>asked to enable</code>, or an error described from what the
fetcher recorded: {{ causes }}.</p>
</div>
"""


# --- what one row reads ---------------------------------------------------

def reads(status, detail, tone, icon):
    return {"status": status, "detail": detail, "tone": tone, "icon": icon}


def status_of(row):
    """The row's own status line, the raw detail to print beneath it, and the voice the
    line speaks in with the icon beside its word - `off` and no icon for a row
    that is not fetched or has not run yet, whose word is muted, as `provider_of` has it."""
    if row["deleting"]:
        return reads("asked to delete", None, "attn", "clock")
    if row["state"] != "active":
        if row["enabling"]:
            return reads("asked to enable", None, "attn", "clock")
        return reads(DISABLED, None, "off", None)
    if row["held_since"]:
        # the antivirus could not be reached, so the mail waits at the provider
        return reads(f"held since {row['held_since']} — the antivirus could not be "
                     "reached, so the mail is waiting at the provider",
                     row["last_fetch_detail"], "attn", "alert")
    status = row["last_fetch_status"]
    if status == "auth_failed":
        # a refused credential never goes through a cause
        return reads(REFUSED, None, "bad", "alert")
    if status == "ok":
        return reads("ok", None, "ok", "check")
    if status == "no_new_mail":
        return reads("no new mail", None, "ok", "check")
    if status is None:
        return reads("has not run yet", None, "off", None)
    cause = row["last_fetch_cause"]
    return reads(CAUSES.get(cause, NO_CAUSE if cause is None else cause),
                 row["last_fetch_detail"], "attn", "alert")


def check_of(row):
    """What the last password check said, which is not the same question as the fetch."""
    if row["checking"]:
        return "asked to check the password"
    status = row["last_test_status"]
    if status == "ok":
        return f"the password was accepted when it was checked, {row['last_test_at']}"
    if status == "auth_failed":
        return f"the password was refused when it was checked, {row['last_test_at']}"
    if status == "error":
        return f"the check did not get an answer ({row['last_test_detail'] or 'no detail'})"
    return "the password has not been checked yet"


def retry_of(row, now=None):
    """The retry state, in precedence order: frozen, then stuck, then nothing.

    The minutes left are counted against the runner's own `--stuck-after`, imported so
    that the screen and the fetcher cannot disagree about when a skip becomes due.
    """
    if row["frozen_since"]:
        return (f"frozen since {row['frozen_since']}, after an automatic skip. Resume "
                "permits the next automatic skip.")
    if row["stuck_since"]:
        now = now or datetime.now(timezone.utc)
        left = DEFAULT_STUCK_AFTER - (now - row["stuck_since"]).total_seconds()
        due = (f"{int(left // 60)} minute(s) before the automatic skip"
               if left > 0 else "the automatic skip is due")
        return (f"stopped on one message since {row['stuck_since']}, {row['stuck_runs']} "
                f"run(s); {due}.")
    return None


def skip_of(row, today=None):
    """The last skip, while the provider has not deleted it yet - whatever else is newer."""
    if not row["last_skip_at"]:
        return None
    deletes_at = row["last_skip_at"].date() + timedelta(days=row["delete_window_days"])
    if deletes_at < (today or date.today()):
        return None
    return (f"skipped message {row['last_skip_uidl']} at {row['last_skip_at']}; the "
            f"provider deletes it on {deletes_at}. Nothing will remind anyone before "
            "that date.")


def reading_of(row, today=None):
    return {**status_of(row), "check": check_of(row), "retry": retry_of(row),
            "skip": skip_of(row, today)}


# --- the screen ---------------------------------------------------------------------------------

def register(app_):
    @app_.get("/fetch")
    def fetch():
        return page(app.connection())

    @app_.post("/fetch/<int:external_id>/resume")
    def resume_fetch(external_id):
        """the one act for a frozen mailbox, and the only one."""
        conn = app.connection()
        row = external.needed(conn, external_id)
        if not row["frozen_since"]:
            # not frozen: nothing to clear, nothing written, and nothing said
            return common.acted_at(common.origin("fetch"), "")
        with conn.cursor() as cursor:
            # ⛔ the stuck clock is LEFT: a mailbox still stuck past the hour skips again
            # on its next run, which is what "resume permits the next skip" means
            cursor.execute("UPDATE external_mailbox SET frozen_since = NULL, "
                           "skip_streak = 0 WHERE id = %s", (external_id,))
        domains.record(conn, "resume_fetch", row["address_canonical"],
                       {"frozen_since": row["frozen_since"]})
        return common.acted("fetch", "fetch_resumed")

    @app_.post("/fetch/<int:external_id>/refetch")
    def refetch(external_id):
        """Collect one mailbox now. A disabled mailbox is refused."""
        conn = app.connection()
        row = external.needed(conn, external_id)
        if row["state"] != "active":
            return page(conn, status=400, refusal=(
                f"{row['address']} is disabled, so a fetch of it would collect nothing. "
                "Enable it first."))
        common.ask(conn, "refetch", row["address_canonical"],
                   {"external_mailbox_id": external_id}, g.identity)
        return common.acted("fetch", "refetch_asked")


def page(conn, status=200, refusal=None):
    mailboxes = common.rows(conn, ROWS)
    last_run = max((row["last_fetch_at"] for row in mailboxes
                    if row["last_fetch_at"]), default=None)
    period = timer_period()
    return app.render("Fetch", PAGE, section="fetch", status=status,
                      mailboxes=mailboxes,
                      reading={row["id"]: reading_of(row) for row in mailboxes},
                      last_run=last_run, period=spell(period),
                      next_by=(last_run + period) if last_run and period else None,
                      causes=", ".join(sorted(CAUSES.values())), refusal=refusal)
