"""The journal: who did what, when, and to whom, newest first.

Opening it is not guarded and writes nothing. Views and refused attempts are not in it -
it records what changed state, from a closed declared list - and a provider
password never appears in it in any form, not even masked.

⛔ **EVERY ITEM AND ROW OPENS THIS SCREEN PRE-FILTERED TO ITSELF**, by the
spelling the journal writes: an external mailbox by its canonical address, a domain by its
label, a person by their login, a mailbox by `<login>@<label>`. The link carries the
section it came from and this screen shows a "Back to …" crumb, which survives
re-filtering. ⚠️ A `back` that is not one of the declared sections gives NO crumb, so a
crafted value cannot make this screen render an arbitrary link.

⛔ **EVERY FILTER IS A BOUND PARAMETER** (`journal.SELECT`), and a date
that is not a date is refused with a sentence rather than dropped: a dropped date would
answer with rows outside the range that was asked for, which reads as "those events are
not in the journal".

⛔ **THE DETAIL AND THE PIPELINE'S REASON ARE TEXT**: the detail is
rendered as escaped JSON and never as HTML, and a failed request's reason is `str(exc)`
from another program. Jinja escapes both; nothing here marks either safe.
"""

from flask import request

from maildivvy.admin import app, journal, validate

HELP = "Exact match — the address, the label or the login as the journal writes it."
NOTHING = "No journal row matches this filter."
CAPPED = ("Only the newest {limit} rows are shown. Narrow the filter - by who, by act, by "
          "target or by date - to see further back.")
OUTLIVES = ("Every row ever written for this target is shown, including rows written "
            "before it was deleted: the journal is append-only and outlives what it "
            "describes.")
ANY = "any"

PAGE = """
<h1>Journal</h1>
{%- if crumb %}
<p class="crumbs"><a href="{{ crumb.url }}">Back to {{ crumb.title }}</a></p>
{%- endif %}
<p>Who did what, when, and to whom. Views and refused attempts are not written here, and
a provider password never appears in it in any form. An act the pipeline performs carries
the outcome of the request that was asked for.</p>
{%- if refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
<form method="get" action="{{ url_for('events') }}">
  <label for="who">Who</label>
  <input id="who" name="who" value="{{ typed.who }}">
  <label for="action">Act</label>
  <select id="action" name="action">
    <option value="" {{ 'selected' if not typed.action }}>{{ any_act }}</option>
    {%- for act in acts %}
    <option value="{{ act }}" {{ 'selected' if typed.action == act }}>{{ act }}</option>
    {%- endfor %}
  </select>
  <label for="target">Target</label>
  <input id="target" name="target" value="{{ typed.target }}">
  <span>{{ help }}</span>
  {%- if field == 'target' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <label for="since">From</label>
  <input id="since" name="since" value="{{ typed.since }}">
  {%- if field == 'since' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <label for="until">To</label>
  <input id="until" name="until" value="{{ typed.until }}">
  {%- if field == 'until' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  {%- if crumb %}<input type="hidden" name="back" value="{{ crumb.section }}">{% endif %}
  <p><button type="submit">Filter</button>
     <a href="{{ url_for('events') }}">Show everything</a></p>
</form>
<table>
<tr><th>When</th><th>Who</th><th>Act</th><th>Target</th><th>Detail</th>
    <th>Break-glass</th></tr>
{%- for row in rows %}
<tr>
  <td>{{ row.at }}</td>
  <td><code>{{ row.actor }}</code></td>
  <td><code>{{ row.action }}</code></td>
  <td><code>{{ row.target or '' }}</code></td>
  <td><code>{{ detail[row.id] }}</code>
      {%- if row.request_id %}
      <div class="outcome">the request it asked for: {{ row.request_state }}
      {%- if row.request_result %} &mdash; {{ row.request_result }}{% endif %}</div>
      {%- endif %}</td>
  <td>{{ 'yes' if row.break_glass else 'no' }}</td>
</tr>
{%- else %}
<tr><td colspan="6">{{ nothing }}</td></tr>
{%- endfor %}
</table>
{%- if capped %}<p class="notice">{{ capped }}</p>{% endif %}
{%- if typed.target %}<footer>{{ outlives }}</footer>{% endif %}
"""


def acts_for(chosen):
    """Every declared act, plus an undeclared one typed into the URL so it stays chosen."""
    declared = sorted(journal.DECLARED)
    if chosen and chosen not in journal.DECLARED:
        return [*declared, chosen]
    return declared


def crumb_for(back):
    """`Back to <section>` for a declared section, and nothing at all for anything else."""
    from flask import url_for

    for endpoint, title, _, _ in app.SECTIONS:
        if endpoint == back and endpoint in current_endpoints():
            return {"url": url_for(endpoint), "title": title, "section": endpoint}
    # ⛔ a value that is not a declared section is not carried forward either: it is
    # dropped here, so nothing crafted reaches the next screen even as a hidden field
    return None


def current_endpoints():
    from flask import current_app

    return current_app.view_functions


def register(app_):
    @app_.get("/journal")
    def events():
        conn = app.connection()
        typed = {name: request.args.get(name, "") or ""
                 for name in ("who", "action", "target", "since", "until", "back")}
        field, refusal = None, None
        since = until = None
        try:
            since = journal.date_filter(typed["since"])
        except validate.Refused as refused:
            field, refusal = "since", str(refused)
        if refusal is None:
            try:
                until = journal.date_filter(typed["until"])
            except validate.Refused as refused:
                field, refusal = "until", str(refused)

        rows = ([] if refusal else
                journal.rows(conn, who=typed["who"], action=typed["action"],
                             target=typed["target"], since=since, until=until))
        return app.render("Journal", PAGE, section="events",
                          status=400 if refusal else 200, typed=typed,
                          acts=acts_for(typed["action"]), any_act=ANY, help=HELP,
                          rows=rows, nothing=NOTHING, outlives=OUTLIVES,
                          detail={row["id"]: journal.detail_text(row["detail"])
                                  for row in rows},
                          capped=(CAPPED.format(limit=journal.LIMIT)
                                  if len(rows) >= journal.LIMIT else None),
                          crumb=crumb_for(typed["back"]), field=field, refusal=refusal)
