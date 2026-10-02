"""The overview: what needs a person now, and one line per section.

⛔ **IT IS TWO LISTS AND NO PRIMARY BUTTON**. "Needs attention" is read from
the database as the page renders, never from anything a screen wrote earlier, so it
cannot say a thing is fine because somebody once said so. "Sections" is one row per
sidebar section with a reading of its own, and the "Add one" links sit there rather than
as a button at the top: opening the overview is not an invitation to make something.

What brings somebody here is in the first list: a provider password that was refused, a
mailbox frozen after an automatic skip with the date its skipped message disappears,
messages waiting to be moderated, and requests the pipeline could not perform. When none
of those is true, a sentence says so, which is the reading that lets a person close the
tab.

The readings of a fetch row are `screens/fetch.py`'s own, imported: a second spelling of
"credential refused" here would drift from the one the fetch screen shows.

⚠️ **Health's report is the one reading here that was written earlier**: its
timer writes it every few minutes. So it is read as the page renders, with its own time
beside everything said from it, and a report that is stale or cannot be read is itself a
worry - never a quiet "nothing needs anybody". A FAIL in the report is listed; WARN and
UNKNOWN are counted on the Health row, because a fresh machine reads UNKNOWN until mail
flows and a WARN does not need a person now. The readings are `screens/health.py`'s own.
"""

from maildivvy.admin import app
from maildivvy.admin.screens import common, fetch, health

# ⚠️ One row of an external mailbox's own columns per worry: a refused credential is the
# fetch status OR the check status, because a password can be refused by either.
WORRIES = """
SELECT e.id, e.address, e.address_canonical, e.state, e.frozen_since,
       e.last_fetch_status, e.last_test_status, e.last_skip_at, e.last_skip_uidl,
       e.delete_window_days, d.label
  FROM external_mailbox e
  LEFT JOIN domain d ON d.external_mailbox_id = e.id
 WHERE e.last_fetch_status = 'auth_failed' OR e.last_test_status = 'auth_failed'
    OR e.frozen_since IS NOT NULL
 ORDER BY e.address
"""

WITHHELD = ("SELECT count(*) AS waiting, min(received_at) AS oldest "
            "FROM message WHERE state = 'withheld'")

FAILURES = ("SELECT count(*) AS failures FROM request "
            "WHERE state = 'failed' AND finished_at > now() - interval '24 hours'")
NEWEST_FAILURE = ("SELECT kind, target, finished_at, result FROM request "
                  "WHERE state = 'failed' AND finished_at > now() - interval '24 hours' "
                  "ORDER BY id DESC LIMIT 1")

EXTERNAL = """
SELECT count(*)                                            AS boxes,
       count(*) FILTER (WHERE state = 'active')            AS enabled,
       count(*) FILTER (WHERE state <> 'active')           AS disabled,
       count(*) FILTER (WHERE last_fetch_status = 'auth_failed'
                           OR last_test_status = 'auth_failed') AS refused,
       count(*) FILTER (WHERE frozen_since IS NOT NULL)    AS frozen,
       max(last_fetch_at)                                  AS last_run,
       (SELECT count(*) FROM request r
         WHERE r.kind = 'activate_external_mailbox'
           AND r.state IN ('queued', 'running'))           AS enabling
  FROM external_mailbox
"""

DOMAINS = ("SELECT count(*) AS domains, "
           "count(*) FILTER (WHERE external_mailbox_id IS NULL) AS free FROM domain")
FREE_LABELS = ("SELECT label FROM domain WHERE external_mailbox_id IS NULL "
               "ORDER BY label LIMIT 20")
PEOPLE = ("SELECT count(*) AS people, count(*) FILTER (WHERE state = 'blocked') AS blocked, "
          "count(*) FILTER (WHERE is_admin AND state = 'active') AS administrators "
          "FROM account")
BOXES = ("SELECT (SELECT count(*) FROM mailbox) AS mailboxes, "
         "(SELECT count(DISTINCT domain_id) FROM mailbox) AS domains, "
         "(SELECT count(*) FROM domain) AS archives")
LAST_ACT = "SELECT at, actor, action, target FROM audit ORDER BY id DESC LIMIT 1"

NOTHING = ("Nothing needs anybody right now: health's current report holds no FAIL, no "
           "provider password has been refused, no "
           "mailbox is frozen, nothing is withheld, and the pipeline has performed "
           "everything it was asked for in the last day.")

PAGE = """
{%- set heading %}Overview{% endset %}
{%- set worried = worries or withheld.waiting or failures.count or health.failing
                  or health.condition != 'current' %}
<div class="stack">
<section class="box{{ ' attn-box' if worried }}"><div class="box-head"><h2>Needs attention</h2></div>
{%- if worried %}
<ul class="list">
{%- if health.condition == 'unreadable' %}
<li><svg class="icon bad ico"><use href="#i-alert"/></svg><div><a href="{{ url_for('health') }}">No health report could be read</a>:
{{ health.why }}. Nothing here says the machine is well.</div></li>
{%- elif health.condition == 'stale' %}
<li><svg class="icon attn ico"><use href="#i-clock"/></svg><div><a href="{{ url_for('health') }}">Health's report of {{ health.taken }}</a> is
{{ health.why }}.</div></li>
{%- endif %}
{%- for failed in health.failing %}
<li><svg class="icon bad ico"><use href="#i-alert"/></svg><div><a href="{{ url_for('health') }}"><code>{{ failed.name }}</code> is <span class="badge bad">FAIL</span></a> in
health's report of {{ health.taken }}: <code>{{ failed.check }}</code> &mdash;
{{ failed.problem }}</div></li>
{%- endfor %}
{%- for worry in worries %}
<li><svg class="icon {{ 'attn' if worry.frozen else 'bad' }} ico"><use href="#i-alert"/></svg><div>{{ worry.words }}
  <a href="{{ url_for('external_mailbox', external_id=worry.id) }}"><code>{{ worry.address }}</code></a>
  {%- if worry.frozen %} &mdash; <a href="{{ url_for('fetch') }}">the fetch screen</a>{% endif %}
  {%- if worry.skip %}<div>{{ worry.skip }}</div>{% endif %}</div></li>
{%- endfor %}
{%- if withheld.waiting %}
<li><svg class="icon attn ico"><use href="#i-clock"/></svg><div><a href="{{ url_for('withheld') }}">{{ withheld.waiting }} withheld message(s)</a>,
the oldest from {{ withheld.oldest }}. Leaving them withheld needs no action.</div></li>
{%- endif %}
{%- if failures.count %}
<li><svg class="icon bad ico"><use href="#i-alert"/></svg><div><a href="{{ url_for('events') }}">{{ failures.count }} request(s) the pipeline could
not perform</a> in the last day. The newest: <code>{{ failures.kind }}</code> on
<code>{{ failures.target or '' }}</code> at {{ failures.at }} &mdash;
{{ failures.reason }}</div></li>
{%- endif %}
</ul>
{%- else %}
<div class="box-body"><p>{{ nothing }}</p></div>
{%- endif %}
</section>

<section class="box"><div class="box-head"><h2>Sections</h2></div>
<div class="table-wrap"><table>
<tbody>
<tr>
  <td><a href="{{ url_for('external') }}">External mailboxes</a></td>
  <td>{{ external.enabled }} enabled, {{ external.disabled }} disabled
      {%- if external.enabling %}, {{ external.enabling }} asked to enable{% endif %}.</td>
  <td class="acts"><a href="{{ url_for('add_external') }}">Add one</a></td>
</tr>
<tr>
  <td><a href="{{ url_for('domains') }}">Domains</a></td>
  <td>{{ domains.domains }} domain(s){% if domains.free %}, {{ domains.free }} free:
      {% for label in free_labels %}<code>{{ label }}</code>{% if not loop.last %}, {% endif %}{% endfor %}
      &mdash; nothing arrives for them and nothing leaves{% else %}, none free{% endif %}.</td>
  <td class="acts"><a href="{{ url_for('add_domain') }}">Add one</a></td>
</tr>
<tr>
  <td><a href="{{ url_for('accounts') }}">People</a></td>
  <td>{{ people.people }} person(s), {{ people.blocked }} blocked,
      {{ people.administrators }} administrator(s).</td>
  <td class="acts"><a href="{{ url_for('add_account') }}">Add one</a></td>
</tr>
<tr>
  <td><a href="{{ url_for('mailboxes') }}">Mailboxes</a></td>
  <td>{{ boxes.mailboxes }} across {{ boxes.domains }} domain(s), and
      {{ boxes.archives }} archive(s).</td>
  <td class="acts"><a href="{{ url_for('add_mailbox') }}">Give one</a></td>
</tr>
<tr>
  <td><a href="{{ url_for('fetch') }}">Fetch</a></td>
  <td>Last run {{ external.last_run or 'never' }}.
      {%- if next_by %} Next by {{ next_by }}, the fetch timer's own period ({{ period }}).
      {%- else %} The fetch timer's period could not be read from the machine.{% endif %}
      {{ external.refused }} refused, {{ external.frozen }} frozen.</td>
  <td class="acts"></td>
</tr>
<tr>
  <td><a href="{{ url_for('withheld') }}">Withheld messages</a></td>
  <td>{{ withheld.waiting }} waiting.</td>
  <td class="acts"></td>
</tr>
<tr>
  <td><a href="{{ url_for('events') }}">Journal</a></td>
  <td>{% if last_act %}Last act <code>{{ last_act.action }}</code> on
      <code>{{ last_act.target or '' }}</code> by <code>{{ last_act.actor }}</code>,
      {{ last_act.at }}.{% else %}Nothing written yet.{% endif %}</td>
  <td class="acts"></td>
</tr>
<tr>
  <td><a href="{{ url_for('health') }}">Health</a></td>
  <td>{% if health.condition == 'unreadable' %}No report could be read.
      {%- else %}{{ health.counts }} in the report of {{ health.taken }},
      {% if health.condition == 'stale' %}stale: {{ health.age }}
      {%- if health.age != 'dated in the future' %} old{% endif %}.
      {%- else %}{{ health.age }} old.{% endif %}{% endif %}</td>
  <td class="acts"></td>
</tr>
</tbody>
</table></div>
</section>
</div>
"""


# --- what needs a person now --------------------------------------------------------

def worry_of(row, today=None):
    """One line of "needs attention" for an external mailbox, or None.

    The wordings are the fetch screen's own, so this page and that one cannot drift
    apart about what "credential refused" means.
    """
    refused = row["last_fetch_status"] == "auth_failed" \
        or row["last_test_status"] == "auth_failed"
    if not refused and not row["frozen_since"]:
        return None
    words = fetch.REFUSED_SHORT if refused else "frozen after an automatic skip"
    return {"id": row["id"], "address": row["address"], "words": words,
            "frozen": bool(row["frozen_since"]),
            "skip": fetch.skip_of(row, today)}


def failures_of(count_row, newest):
    """The failed requests of the last day: how many, and the newest one in full."""
    return {"count": count_row["failures"] if count_row else 0,
            "kind": newest["kind"] if newest else None,
            "target": newest["target"] if newest else None,
            "at": f"{newest['finished_at']:%H:%M}" if newest else None,
            "reason": (newest["result"] or common.NO_REASON) if newest else None}


def register(app_):
    @app_.get("/")
    def overview():
        conn = app.connection()
        period = common.timer_period()
        external = common.one(conn, EXTERNAL)
        worries = [worry for worry in
                   (worry_of(row) for row in common.rows(conn, WORRIES)) if worry]
        last_run = external["last_run"]
        return app.render("Overview", PAGE, section="overview", worries=worries,
                          health=health.configured(),
                          withheld=common.one(conn, WITHHELD),
                          failures=failures_of(common.one(conn, FAILURES),
                                               common.one(conn, NEWEST_FAILURE)),
                          nothing=NOTHING, external=external,
                          domains=common.one(conn, DOMAINS),
                          free_labels=[row["label"] for row in
                                       common.rows(conn, FREE_LABELS)],
                          people=common.one(conn, PEOPLE),
                          boxes=common.one(conn, BOXES),
                          last_act=common.one(conn, LAST_ACT),
                          period=common.spell(period),
                          next_by=(last_run + period) if last_run and period else None)
