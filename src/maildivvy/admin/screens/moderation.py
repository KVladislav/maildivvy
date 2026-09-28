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

PAGE = """
<h1>Withheld messages</h1>
<p>Each of these was held back by the filtering. Everyone who would have received it
holds a report standing in for it instead, so nothing is missing without a trace, and
leaving a message here needs no action at all.</p>
<p>Releasing gives the message to everyone who receives in its domain &mdash; blocked
people included, since a blocked person still receives &mdash; and
removes the report from everyone holding it.
It overrides the domain's spam policy, deliberately: somebody asked for this message to
go out.</p>
<table>
<tr><th>Arrived</th><th>Domain</th><th>From</th><th>Subject</th><th>Why it was held</th>
    <th>Actions</th></tr>
{%- for row in messages %}
<tr>
  <td>{{ row.received_at }}</td>
  <td><a href="{{ url_for('domain', domain_id=row.domain_id) }}"><code>{{ row.label }}</code></a></td>
  <td><code>{{ row.sender or '(no sender)' }}</code></td>
  <td>{{ row.subject or '(no subject)' }}</td>
  <td>{{ row.why or no_report }}</td>
  <td>
  {%- if reading[row.id].waiting -%}
  {{ reading[row.id].waiting }}<div class="look-again">{{ reading[row.id].look_again }}</div>
  <div>waiting for the pipeline</div>
  {%- else -%}
  {%- if reading[row.id].failed %}<div class="field-refusal">the pipeline could not do it:
  {{ reading[row.id].failed }}</div>{% endif -%}
  <form method="post" action="{{ url_for('release_message', message_id=row.id) }}">
    <button type="submit">Release&hellip;</button></form>
  {%- endif -%}
  </td>
</tr>
{%- else %}
<tr><td colspan="6">Nothing is withheld.</td></tr>
{%- endfor %}
</table>
{%- if refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
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
