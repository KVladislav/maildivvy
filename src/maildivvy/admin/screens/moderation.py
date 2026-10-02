"""Withheld messages: what the filtering held back, why, and the one act there is.

Leaving a message withheld needs no action at all, which is why this screen has one
button and no others. Everyone who would have received the message holds a report
standing in for it; releasing gives the message to everyone who receives in the domain
and takes the report away from everyone who holds it, whatever their state, because the
report is false the moment the original is out.

⚠️ **The release is not guarded and has no confirmation page**:
it destroys nothing. It is journaled by MESSAGE ID, the one journal target in the product
that is a row id, because a message has no address of its own.

⛔ **The release overrides the domain's spam policy**, and that is the pipeline's rule,
not this screen's: the handler reads neither the switch nor the verdict. A
person asked for this message to go out.
"""

from flask import abort, g

from maildivvy.admin import app
from maildivvy.admin.screens import common

record = common.record

NO_REPORT = ("the filtering held it back and left no report saying why")

LIST = """
SELECT m.id, m.received_at, m.sender, m.subject, m.is_spam, m.spam_score,
       d.id AS domain_id, d.label,
       (SELECT p.subject FROM message p WHERE p.report_of = m.id
         ORDER BY p.id LIMIT 1) AS why,
       """ + common.newest_request(
    "r.kind = 'release' AND (r.payload ->> 'message_id')::bigint = m.id") + """
  FROM message m JOIN domain d ON d.id = m.domain_id
 WHERE m.state = 'withheld'
"""

# ⚠️ The design's voices: *Release* is a plain small button on its row, not the
# prototype's red one, because it destroys nothing and red stays inside the fence.
# A waiting release reads in the reason's cell, amber, and its row offers no control.
PAGE = """{%- set heading %}Withheld messages{% endset %}
{%- set lede %}Each of these was held back by the filtering. Everyone who would have received it
holds a report standing in for it instead, so nothing is missing without a trace, and
leaving a message here needs no action at all.
Releasing gives the message to everyone who receives in its domain &mdash; blocked
people included, since a blocked person still receives &mdash; and
removes the report from everyone holding it.
It overrides the domain's spam policy, deliberately: somebody asked for this message to
go out.{% endset %}
{{ refused(refusal) }}
<section class="box"><div class="table-wrap"><table>
<thead><tr><th>Arrived</th><th>Domain</th><th>From</th><th>Subject</th><th>Why it was held</th>\
<th class="acts">Actions</th></tr></thead>
<tbody>
{%- for row in messages %}
{%- set said = reading[row.id] %}
<tr>
  <td>{{ row.received_at }}</td>
  <td><a href="{{ url_for('domain', domain_id=row.domain_id) }}"><code>{{ row.label }}</code></a></td>
  <td><code>{{ row.sender or '(no sender)' }}</code></td>
  <td>{{ row.subject or '(no subject)' }}</td>
  <td class="wrap">{{ row.why or no_report }}
  {%- if said.waiting %}<span class="row-sub state-attn"><svg class="icon attn"><use href="#i-clock"/></svg> {{ said.waiting }}</span>\
<span class="row-sub">{{ said.look_again }}</span>
  {%- elif said.failed %}{{ pipeline_failed(said.failed) }}
  {%- endif %}</td>
  <td class="acts">
  {%- if said.waiting %}<span class="muted">waiting for the pipeline</span>
  {%- else %}<form method="post" action="{{ url_for('release_message', message_id=row.id) }}">\
<button class="btn btn-sm" type="submit">Release&hellip;</button></form>
  {%- endif %}</td>
</tr>
{%- else %}
<tr><td colspan="6">Nothing is withheld.</td></tr>
{%- endfor %}
</tbody>
</table></div></section>
"""


def register(app_):
    @app_.get("/withheld")
    def withheld():
        return page(app.connection())

    @app_.post("/withheld/<int:message_id>/release")
    def release_message(message_id):
        """one request, journaled by the message's own id."""
        conn = app.connection()
        row = common.one(conn, "SELECT id, state FROM message WHERE id = %s", (message_id,))
        if row is None:
            abort(404)
        if row["state"] != "withheld":
            # the act checks its row before writing anything: a message
            # already released, or never withheld, is not released a second time
            return page(conn, status=400, refusal=(
                f"Message {message_id} is {row['state']}, not withheld. Only a withheld "
                "message is released."))
        asked = common.ask(conn, "release", str(message_id), {"message_id": message_id},
                           g.identity)
        record(conn, "release", str(message_id), {"requested": True}, request_id=asked)
        return common.acted("withheld", "release_asked")


def page(conn, status=200, refusal=None):
    period = common.timer_period()
    messages = common.rows(conn, LIST + " ORDER BY m.received_at DESC, m.id DESC")
    return app.render("Withheld messages", PAGE, section="withheld", status=status,
                      messages=messages, no_report=NO_REPORT, refusal=refusal,
                      reading={row["id"]: common.reading_of(row, period)
                               for row in messages})
