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

from flask import abort, g, request

from maildivvy.admin import app
from maildivvy.admin.screens import common

record = common.record

NO_REPORT = ("the filtering held it back and left no report saying why")
NO_OLDER = "No older message is withheld."
CAPPED = ("Only the newest {limit} withheld messages are shown. Each still waits here; "
          "the older ones are on the next page.")

# ⚠️ A withheld message stays withheld until somebody releases it, so this list only grows:
# a page holds at most this many rows, newest first, and the next page starts after the
# last row shown. Every message stays reachable, because each one waits for an act.
LIMIT = 200

# ⚠️ The release lookup names its kind and target, the message's id as text, as the act
# writes them, so `request_kind_target_idx` finds the rows; the payload's id stays the test.
LIST = """
SELECT m.id, m.received_at, m.sender, m.subject, m.is_spam, m.spam_score,
       d.id AS domain_id, d.label,
       (SELECT p.subject FROM message p WHERE p.report_of = m.id
         ORDER BY p.id LIMIT 1) AS why,
       """ + common.newest_request(
    "r.kind = 'release' AND r.target = m.id::text "
    "AND (r.payload ->> 'message_id')::bigint = m.id") + """
  FROM message m JOIN domain d ON d.id = m.domain_id
 WHERE m.state = 'withheld'
"""
OLDER = (" AND (m.received_at, m.id) < "
         "(SELECT o.received_at, o.id FROM message o WHERE o.id = %s)")
NEWEST = " ORDER BY m.received_at DESC, m.id DESC LIMIT %s"

# ⚠️ The design's voices: *Release* is a plain small button on its row, not the
# prototype's red one, because it destroys nothing and red stays inside the fence.
# A waiting release reads in the reason's cell, amber, and its row offers no control.
PAGE = """{% extends "app.SHELL" %}
{%- from "common.SHAPES" import csrf, back, flash, refused, pipeline_failed %}{%- set heading %}Withheld messages{% endset %}
{%- set lede %}Each of these was held back by the filtering. Everyone who would have received it
holds a report standing in for it instead, so nothing is missing without a trace, and
leaving a message here needs no action at all.
Releasing gives the message to everyone who receives in its domain &mdash; blocked
people included, since a blocked person still receives &mdash; and
removes the report from everyone holding it.
It overrides the domain's spam policy, deliberately: somebody asked for this message to
go out.{% endset %}
{%- if older %}{% set actions %}<a class="btn" href="{{ url_for('withheld', before=older) }}">\
Older messages</a>{% endset %}{% endif %}
{%- if before is not none %}{% set crumbs %}<a href="{{ url_for('withheld') }}">{{ back() }} \
Newest withheld messages</a>{% endset %}{% endif %}{% block body %}
{{ refused(refusal) }}
{%- if capped %}
{{ flash('attn', 'alert', capped) }}
{%- endif %}
<section class="box"><div class="table-wrap"><table>
<thead><tr><th>Arrived</th><th>Domain</th><th>From</th><th>Subject</th><th>Why it was held</th>\
<th class="acts">Actions</th></tr></thead>
<tbody>
{%- for row in messages %}
{%- set said = reading[row.id] %}
<tr>
  <td>{{ row.received_at|moment }}</td>
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
  {%- else %}<form method="post" action="{{ url_for('release_message', message_id=row.id) }}">{{ csrf() }}\
<button class="btn btn-sm" type="submit">Release&hellip;</button></form>
  {%- endif %}</td>
</tr>
{%- else %}
<tr><td colspan="6">{{ no_older if before is not none else 'Nothing is withheld.' }}</td></tr>
{%- endfor %}
</tbody>
</table></div></section>{% endblock %}"""


def register(app_):
    @app_.get("/withheld")
    def withheld():
        return page(app.connection(), before=request.args.get("before", type=int))

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
        asked = common.ask_once(conn, "release", str(message_id),
                                {"message_id": message_id}, g.identity)
        if asked is None:
            return common.acted("withheld", "already_asked")
        record(conn, "release", str(message_id), {"requested": True}, request_id=asked)
        return common.acted("withheld", "release_asked")


def page(conn, status=200, refusal=None, before=None):
    """One page of the list: the newest `LIMIT` rows, or those older than `before`.

    One row more than the page shows is read, so the next page is offered only when
    there is one."""
    period = common.timer_period()
    if before is None:
        found = common.rows(conn, LIST + NEWEST, (LIMIT + 1,))
    else:
        found = common.rows(conn, LIST + OLDER + NEWEST, (before, LIMIT + 1))
    messages = found[:LIMIT]
    more = len(found) > LIMIT
    return app.render("Withheld messages", "moderation.PAGE", section="withheld", status=status,
                      messages=messages, no_report=NO_REPORT, refusal=refusal,
                      before=before, no_older=NO_OLDER,
                      older=messages[-1]["id"] if more else None,
                      capped=CAPPED.format(limit=LIMIT) if more and before is None else None,
                      reading={row["id"]: common.reading_of(row, period)
                               for row in messages})
