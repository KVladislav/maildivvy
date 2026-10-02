"""External mailboxes: the provider mailbox in front of a domain, and everything about it.

This is the screen the product most exists for: a provider password changes, and
somebody has to put the new one in. Around that sit the four acts a provider mailbox
has - check, enable, disable, delete - and the two forms that change it.

⛔ **THE STORED CREDENTIAL IS WRITE-ONLY**. No screen, refusal, journal
row or request shows it, not even masked, and the password field has no value slot on
any form. That is not a habit of this file: the interface's database role holds INSERT
and UPDATE on the credential column and NO SELECT at all, so a defect here
could not return it.

⛔ **ENABLING IS ONE ACT AND THE PROVIDER DECIDES IT**. The interface
writes an `activate_external_mailbox` request; the pipeline logs in with the STORED
password and switches the row on only if the provider accepts it. There is no
test-then-switch-on pair, because a switch that can be thrown without the provider
agreeing is how a mailbox comes up active and collects nothing.

⛔ **A CHANGED PASSWORD ASKS FOR A CHECK**. In the predecessor a
changed login and changed servers each queued a `test_credential` and a changed password
did not - so the one field whose value the provider actually has to accept was the one
nobody checked. Here all three do.

⚠️ **The re-prompt is gone**, so the servers form, the settings form and the
switch act on their submission. What still goes through a confirmation page is the one
destructive act: deleting the mailbox.
"""

from flask import abort, g, request

from maildivvy.admin import app, validate
from maildivvy.admin.screens import common, domains

POP3_EXAMPLE = "pop.example.org"
SMTP_EXAMPLE = "smtp.example.org"
POP3_PORT = 995
SMTP_PORT = 587

ROW = """
SELECT e.id, e.address, e.address_canonical, e.pop3_login, e.pop3_host, e.pop3_port,
       e.smtp_host, e.smtp_port, e.delete_window_days, e.comment,
       e.state, e.state_changed_at, e.state_changed_by,
       e.last_fetch_at, e.last_fetch_status, e.last_fetch_cause, e.last_fetch_detail,
       e.last_test_at, e.last_test_status, e.last_test_detail,
       e.stuck_since, e.stuck_runs, e.skip_streak, e.frozen_since,
       e.last_skip_at, e.last_skip_uidl, e.held_since,
       d.id AS domain_id, d.label,
       EXISTS (SELECT 1 FROM request r WHERE r.kind = 'test_credential'
                AND r.state IN ('queued', 'running')
                AND (r.payload ->> 'external_mailbox_id')::bigint = e.id) AS checking,
       EXISTS (SELECT 1 FROM request r WHERE r.kind = 'activate_external_mailbox'
                AND r.state IN ('queued', 'running')
                AND (r.payload ->> 'external_mailbox_id')::bigint = e.id) AS enabling,
       EXISTS (SELECT 1 FROM request r WHERE r.kind = 'delete_external_mailbox'
                AND r.state IN ('queued', 'running')
                AND (r.payload ->> 'external_mailbox_id')::bigint = e.id) AS deleting,
       (SELECT r.created_at FROM request r WHERE r.kind = 'activate_external_mailbox'
          AND r.state IN ('queued', 'running')
          AND (r.payload ->> 'external_mailbox_id')::bigint = e.id
        ORDER BY r.id DESC LIMIT 1) AS enable_asked_at,
       """ + common.newest_request(
    "(r.payload ->> 'external_mailbox_id')::bigint = e.id") + """
  FROM external_mailbox e
  LEFT JOIN domain d ON d.external_mailbox_id = e.id
"""

FREE_DOMAINS = ("SELECT id, label FROM domain WHERE external_mailbox_id IS NULL "
                "ORDER BY label")


# --- the wordings the two screens share ------------------------------------------------------

# ⚠️ The design's voices: what the provider last said (`provider_of`) is a word
# beside its icon, in green, amber or red, or muted when nothing was ever checked; enabled,
# disabled and asked are the state switch, whose word beside the knob is the state. Its
# accessible name is the act it performs, as the button's word was before.
STATE_BOX = """
{%- macro provider_icon(said) -%}
{%- if said.icon %}<svg class="icon {{ said.tone }}"><use href="#i-{{ said.icon }}"/></svg> {% endif -%}
{%- endmacro -%}
{%- macro state_words(row) -%}
{%- if row.deleting %}asked to delete
{%- elif row.enabling %}asked to enable, {{ row.enable_asked_at.strftime('%H:%M') }} &mdash; {{ row.reading.look_again }}
{%- elif row.state == 'active' %}enabled since {{ row.state_changed_at }} by <code>{{ row.state_changed_by }}</code>
{%- elif row.state_changed_at %}disabled since {{ row.state_changed_at }} by <code>{{ row.state_changed_by }}</code>
{%- else %}saved disabled, never enabled{% endif -%}
{%- endmacro -%}
{%- macro switch(row) -%}
{%- if row.deleting %}<span class="muted">waiting for the pipeline</span>
{%- elif row.enabling %}<button class="switch asked" type="button" disabled>\
<span class="knob"></span>asked to enable, {{ row.enable_asked_at.strftime('%H:%M') }}</button>
{%- elif row.state == 'active' -%}
<form method="post" action="{{ url_for('external_disable', external_id=row.id) }}">\
<button class="switch on" type="submit" aria-label="Disable" title="Disable">\
<span class="knob"></span>enabled</button></form>
{%- else -%}
<form method="post" action="{{ url_for('external_enable', external_id=row.id) }}">\
<button class="switch" type="submit" aria-label="Enable" title="Enable">\
<span class="knob"></span>disabled</button></form>
{%- endif -%}
{%- endmacro -%}
{%- macro way() -%}<a href="{{ url_for('external') }}">External mailboxes</a>{%- endmacro -%}
"""

LIST_PAGE = STATE_BOX + """
{%- set heading %}External mailboxes{% endset %}
{%- set actions %}<a class="btn btn-primary" href="{{ url_for('add_external') }}">Add external mailbox</a>{% endset %}
<section class="box compact"><div class="table-wrap"><table>
<thead><tr><th>Address</th><th>In front of</th><th>State</th><th>At the provider</th>\
<th class="acts">Actions</th></tr></thead>
<tbody>
{%- for row in mailboxes %}
<tr>
  <td><a href="{{ url_for('external_mailbox', external_id=row.id) }}"><code>{{ row.address }}</code></a>\
<span class="row-sub">deleted at the provider {{ row.delete_window_days }} days after first seen</span></td>
  <td>{% if row.domain_id %}<a href="{{ url_for('domain', domain_id=row.domain_id) }}"><code>{{ row.label }}</code></a>{% else %}&mdash;{% endif %}</td>
  <td class="state">{{ switch(row) }}<span class="row-sub">{{ state_words(row) }}</span>
      {{- pipeline_failed(row.reading.failed) }}
      {%- if row.frozen_since %}<span class="row-sub"><a href="{{ url_for('fetch') }}"><span class="badge attn"><svg class="icon attn"><use href="#i-alert"/></svg> frozen</span></a></span>{% endif %}</td>
  <td>
      {%- if row.provider.tone == 'off' %}<span class="muted">{{ row.provider.words }}</span>
      {%- else %}<span class="state-{{ row.provider.tone }}">{{ provider_icon(row.provider) }}{{ row.provider.words }}</span>{% endif %}
      {%- if row.last_fetch_at %}<span class="row-sub">last fetch {{ row.last_fetch_at }}</span>{% endif %}</td>
  <td class="acts">{% if row.deleting %}<span class="muted">waiting for the pipeline</span>
      {%- else %}
        {%- if not row.checking and not row.enabling %}
        <form method="post" action="{{ url_for('external_check', external_id=row.id) }}">\
<button class="btn btn-sm" type="submit">Check password</button></form>
        {%- endif %}
        {%- if has_route('events') %} <a class="btn btn-sm btn-link" href="{{ url_for('events', target=row.address_canonical, back='external') }}">Journal</a>
        {%- else %} Journal{% endif %}
      {%- endif %}</td>
</tr>
{%- else %}
<tr><td colspan="5">No external mailbox yet. Add one: it is saved disabled, checked,
then enabled.</td></tr>
{%- endfor %}
</tbody>
</table></div></section>
"""

ADD_PAGE = STATE_BOX + """
{%- set heading %}Add external mailbox{% endset %}
{%- set crumbs %}{{ way() }} / Add{% endset %}
<form class="narrow" method="post" action="{{ url_for('add_external') }}">
{{ refused(refusal) }}
{%- set login_help %}Leave empty to log in with the address itself. Changing it later makes the
  fetcher treat the mailbox as new and collect its whole window again.{% endset %}
{%- set pop3_help %}POP3 is implicit TLS on its port, not STARTTLS.{% endset %}
{%- set smtp_help %}An SMTP port of 465 is sent with implicit TLS; any other port, such as 587, uses
  STARTTLS. Give both hosts by name, not by IP address: the provider's certificate is
  checked against the name. Nothing checks an SMTP host before it is used.{% endset %}
{%- set window_help %}Counted from when the fetcher first saw a message, not from the message's date.
  At a provider that offers only a recent window of messages, a window at or above that
  length deletes nothing.{% endset %}
<section class="box"><div class="box-body">
{{ field('Address', 'address', typed.address, class_='mono-input',
         warn=refusal if fault == 'address') }}
{{ field('POP3 login', 'pop3_login', typed.pop3_login, class_='mono-input', help=login_help,
         warn=refusal if fault == 'pop3_login') }}
{{ field('Provider password', 'credential', type='password', autocomplete='new-password',
         help='Stored write-only; never shown again.') }}
<div class="inline-fields">
{{ field('POP3 host', 'pop3_host', typed.pop3_host, class_='mono-input',
         warn=refusal if fault == 'pop3_host') }}
{{ field('POP3 port', 'pop3_port', typed.pop3_port, type='number', class_='short', min=1,
         max=65535, help=pop3_help, warn=refusal if fault == 'pop3_port') }}
</div>
<div class="inline-fields">
{{ field('SMTP host', 'smtp_host', typed.smtp_host, class_='mono-input',
         warn=refusal if fault == 'smtp_host') }}
{{ field('SMTP port', 'smtp_port', typed.smtp_port, type='number', class_='short', min=1,
         max=65535, help=smtp_help, warn=refusal if fault == 'smtp_port') }}
</div>
{{ field('Deletion at the provider, days', 'window', typed.window, type='number',
         class_='short', min=1, help=window_help, warn=refusal if fault == 'window') }}
{{ field('Comment', 'comment', typed.comment) }}
</div></section>

<section class="box"><div class="box-head"><h2>The domain in front of it</h2></div><div class="box-body">
<label class="choice"><input type="radio" name="domain_choice" value="free"
  {{ 'checked' if typed.domain_choice != 'new' }}><div><b>A free domain</b></div></label>
<div class="field"><select name="domain_id" class="mid">
  <option value="">&mdash;</option>
  {%- for free in free_domains %}
  <option value="{{ free.id }}" {{ 'selected' if typed.domain_id == free.id|string }}>{{ free.label }}</option>
  {%- endfor %}
</select></div>
<label class="choice"><input type="radio" name="domain_choice" value="new"
  {{ 'checked' if typed.domain_choice == 'new' }}><div><b>A new domain, created in the same step</b></div></label>
{{ field('New domain label', 'label', typed.label, class_='mono-input mid') }}
<div class="inline-fields">
{{ field('Its archive password', 'password', type='password', autocomplete='new-password',
         class_='mid') }}
{{ field('Its archive password again', 'password2', type='password',
         autocomplete='new-password', class_='mid', warn=refusal if fault == 'domain') }}
</div>
</div></section>
<div class="form-foot"><button class="btn btn-primary" type="submit">Save as disabled</button>\
<a class="btn" href="{{ url_for('external') }}">Cancel, nothing changes</a></div>
</form>
"""

ITEM_PAGE = STATE_BOX + """
{%- set heading %}<code>{{ row.address }}</code>{% endset %}
{%- set lede %}In front of
{%- if row.domain_id %} <a href="{{ url_for('domain', domain_id=row.domain_id) }}"><code>{{ row.label }}</code></a>
{%- else %} no domain{% endif %}. {{ state_words(row) }}.
Rotating the provider password here is the operation this interface most exists for.
The deletion window is counted from the fetcher's first sighting of a message. The
address itself is fixed: the canonical address derives from it, so changing it means
deleting this row and adding another.{% endset %}
{%- set actions %}{%- if has_route('events') -%}
<a class="btn" href="{{ url_for('events', target=row.address_canonical, back='external') }}">Journal for this mailbox</a>
{%- endif %}{% endset %}
{%- set crumbs %}{{ way() }} / <code>{{ row.address }}</code>{% endset %}
{%- if row.reading.failed %}
{{ pipeline_flash(row.reading) }}
{%- endif %}
<div class="stack">
<section class="box">
<div class="box-head"><h2>At the provider</h2><span class="badge {{ row.provider.tone }}">\
{{ provider_icon(row.provider) }}{{ row.provider.words }}</span></div>
{%- if row.last_test_status == 'auth_failed' %}
<div class="box-body"><p>The account's owner has very likely changed the password. Fetching for this address
has stopped, and nothing is sent as it until a check passes.</p></div>
{%- endif %}
<div class="box-body"><div class="btn-row">{{ switch(row) }}
{%- if row.state != 'active' %}<span class="muted">Everyone keeps what has already arrived; disabling stops new mail and stops sending
as this address.</span>{% endif %}</div></div>
<div class="box-body">
{%- if row.checking %}
<p class="muted">asked to check the password</p>
{%- else %}
<form class="btn-row" method="post" action="{{ url_for('external_check', external_id=row.id) }}">\
<button class="btn" type="submit">Check the password at the provider</button>
  <span class="muted">Checking changes nothing and asks for no password; the pipeline journals the
  result in your name.</span>
</form>
{%- endif %}
</div>
</section>

{%- set pop3_help %}POP3 is implicit TLS on its port, not STARTTLS. The fetcher logs in with the
  POP3 login, or with the address itself when the login is empty.{% endset %}
{%- set smtp_help %}An SMTP port of 465 is sent with implicit TLS; any other port, such as 587, uses
  STARTTLS. Give both hosts by name, not by IP address: the provider's certificate is
  checked against the name. Nothing checks an SMTP host before it is used, so a change
  takes effect at the next message sent.{% endset %}
<section class="box"><div class="box-head"><h2>Provider servers</h2></div><div class="box-body">
<form method="post" action="{{ url_for('external_servers', external_id=row.id) }}">
{{ refused(refusal if form == 'servers') }}
<div class="inline-fields">
{{ field('POP3 host', 'pop3_host', servers.pop3_host, class_='mono-input',
         warn=refusal if fault == 'pop3_host') }}
{{ field('POP3 port', 'pop3_port', servers.pop3_port, type='number', class_='short', min=1,
         max=65535, help=pop3_help, warn=refusal if fault == 'pop3_port') }}
</div>
<div class="inline-fields">
{{ field('SMTP host', 'smtp_host', servers.smtp_host, class_='mono-input',
         warn=refusal if fault == 'smtp_host') }}
{{ field('SMTP port', 'smtp_port', servers.smtp_port, type='number', class_='short', min=1,
         max=65535, help=smtp_help, warn=refusal if fault == 'smtp_port') }}
</div>
{%- set clears %}Changing either host clears the stored provider password,
  so it is never presented to a host you did not put it in for. Enter it again in
  Settings below; nothing is fetched or sent until you do (<code>0022</code>).{% endset %}
{{ flash('attn', 'alert', clears) }}
<div class="form-foot"><button class="btn" type="submit">Save the servers</button></div>
</form>
</div></section>

{%- set login_help %}Empty means the address itself. Changing a working login makes the fetcher treat
  the mailbox as new and collect its whole window again.{% endset %}
<section class="box"><div class="box-head"><h2>Settings</h2></div><div class="box-body">
<form method="post" action="{{ url_for('external_settings', external_id=row.id) }}">
{{ refused(refusal if form == 'settings') }}
{{ field('POP3 login', 'pop3_login', settings.pop3_login, class_='mono-input', help=login_help,
         warn=refusal if fault == 'pop3_login') }}
{{ field('New provider password', 'credential', type='password', autocomplete='new-password',
         help='Leave empty to keep the stored password. Stored write-only; never shown again.') }}
{{ field('Deletion at the provider, days', 'window', settings.window, type='number',
         class_='short', min=1, warn=refusal if fault == 'window') }}
{{ field('Comment', 'comment', settings.comment) }}
<div class="form-foot"><button class="btn btn-primary" type="submit">Save settings</button>\
<a class="btn" href="{{ url_for('external') }}">Cancel, nothing changes</a></div>
</form>
</div></section>

{%- set sentence %}Removes the row, the provider password and the fetcher's state. The domain
{%- if row.domain_id %} <code>{{ row.label }}</code>{% endif %}, its archive and every
message in it stay; you will be asked whether the domain goes too.{% endset %}
{%- set control %}<a class="btn btn-danger" href="{{ url_for('delete_external_mailbox', external_id=row.id) }}">\
Delete this external mailbox&hellip;</a>{% endset %}
{{ danger_zone(sentence, none, control) }}
</div>
"""

DELETE_PAGE = STATE_BOX + """
{%- set heading %}Delete <code>{{ row.address }}</code>?{% endset %}
{%- set lede %}What goes is this row, the provider password and the fetcher's state. Nobody's mail
is destroyed by this act.{% endset %}
{%- set crumbs %}{{ way() }} / <a href="{{ url_for('external_mailbox', external_id=row.id) }}">\
<code>{{ row.address }}</code></a> / Delete{% endset %}
<div class="stack narrow">
{%- if row.domain_id %}
<section class="danger-zone"><div class="box-head"><h2>Leave <code>{{ row.label }}</code> free</h2></div>
<div class="box-body">
<p>The domain, its archive and its mailboxes stay exactly as they are. Nothing arrives
for it and nothing leaves until another external mailbox is put in front of it.</p>
<form class="form-foot" method="post" action="{{ url_for('delete_external_mailbox', external_id=row.id) }}">
  <input type="hidden" name="branch" value="leave">
  <button class="btn btn-danger" type="submit">Delete the mailbox, leave <code>{{ row.label }}</code> free</button>
</form>
</div></section>
<section class="danger-zone"><div class="box-head"><h2>Delete the domain <code>{{ row.label }}</code> too</h2></div>
<div class="box-body">
<p>That is two requests, in order. If the second does not run, a free domain is left,
which is an ordinary state. Disk space is not stated: the store is hardlinked.</p>
<div class="kv"><div><b>{{ numbers.messages }}</b><span>Messages removed</span></div>\
<div><b>{{ numbers.mailboxes }}</b><span>Mailboxes removed</span></div>\
<div><b>{{ numbers.people }}</b><span>People who lose their only mailbox</span></div></div>
<form class="form-foot" method="post" action="{{ url_for('delete_external_mailbox', external_id=row.id) }}">
  <input type="hidden" name="branch" value="{{ delete_word }}">
  <button class="btn btn-danger-solid" type="submit">Delete the mailbox and <code>{{ row.label }}</code></button>
</form>
</div></section>
{%- else %}
<section class="danger-zone"><div class="box-body">
<form class="form-foot" method="post" action="{{ url_for('delete_external_mailbox', external_id=row.id) }}">
  <input type="hidden" name="branch" value="leave">
  <button class="btn btn-danger-solid" type="submit">Delete <code>{{ row.address }}</code></button>
</form>
</div></section>
{%- endif %}
<p><a href="{{ url_for('external_mailbox', external_id=row.id) }}">""" + common.BACK + """ Cancel, nothing changes</a></p>
</div>
"""

# ⚠️ Any branch value other than this literal counts as "leave": a typo, a truncated
# form or a crafted value all keep the domain.
DELETE_WORD = "delete-the-domain-too"


# --- readers -----------------------------------------------------------------------------------

def provider_of(row):
    """What the provider last said: its words, the voice they are said in, and the icon
    beside them - `off` and no icon when nothing was ever checked, whose words are muted."""
    status = row["last_test_status"]
    if row["checking"]:
        return {"words": "asked to check the password", "tone": "attn", "icon": "clock"}
    if status == "ok":
        return {"words": f"accepted, checked {row['last_test_at']}", "tone": "ok",
                "icon": "check"}
    if status == "auth_failed":
        return {"words": f"refused, since {row['last_test_at']}", "tone": "bad",
                "icon": "alert"}
    if status == "error":
        return {"words": f"check got no answer ({row['last_test_detail'] or 'no detail'})",
                "tone": "attn", "icon": "alert"}
    return {"words": "not checked yet", "tone": "off", "icon": None}


def with_reading(rows, period=None):
    """Each row carrying the reading of the newest request that names it,
    and what the provider last said.

    ⚠️ Any KIND, not only the enable: in the predecessor a failed enable put its reason on the
    row and a failed check or deletion put nothing anywhere.
    """
    for row in rows:
        row["reading"] = common.reading_of(row, period)
        row["provider"] = provider_of(row)
    return rows


def external_row(conn, external_id):
    rows = with_reading(common.rows(conn, ROW + " WHERE e.id = %s", (external_id,)),
                        common.timer_period())
    return rows[0] if rows else None


def needed(conn, external_id):
    row = external_row(conn, external_id)
    if row is None:
        abort(404)
    return row


def servers_of(row):
    return {"pop3_host": row["pop3_host"], "pop3_port": row["pop3_port"],
            "smtp_host": row["smtp_host"], "smtp_port": row["smtp_port"]}


def settings_of(row):
    """What the settings form shows: the stored login, never the password."""
    return {"pop3_login": row["pop3_login"] or "", "window": row["delete_window_days"],
            "comment": row["comment"] or ""}


def item(conn, row, status=200, form=None, refusal=None, fault=None,
         servers=None, settings=None):
    return app.render(row["address"], ITEM_PAGE, section="external", status=status,
                      row=row, form=form, refusal=refusal, fault=fault,
                      servers=servers or servers_of(row),
                      settings=settings or settings_of(row))


def check_servers(form, defaults=None):
    """The four server fields, first fault in field order."""
    defaults = defaults or {}
    return {
        "pop3_host": ("pop3_host", lambda: validate.host(form.get("pop3_host"), "POP3 host",
                                                         POP3_EXAMPLE)),
        "pop3_port": ("pop3_port", lambda: validate.port(form.get("pop3_port"), "POP3 port",
                                                         defaults.get("pop3_port"))),
        "smtp_host": ("smtp_host", lambda: validate.host(form.get("smtp_host"), "SMTP host",
                                                         SMTP_EXAMPLE)),
        "smtp_port": ("smtp_port", lambda: validate.port(form.get("smtp_port"), "SMTP port",
                                                         defaults.get("smtp_port"))),
    }


def read_servers(form, defaults=None):
    """Every server field or the first refusal, as (values, field at fault, sentence)."""
    values = {}
    for name, (field, read) in check_servers(form, defaults).items():
        try:
            values[name] = read()
        except validate.Refused as refused:
            return None, field, str(refused)
    return values, None, None


# --- the screens ----------------------------------------------------------------------------------

def register(app_):
    @app_.get("/external")
    def external():
        conn = app.connection()
        return app.render("External mailboxes", LIST_PAGE, section="external",
                          mailboxes=with_reading(
                              common.rows(conn, ROW + " ORDER BY e.address"),
                              common.timer_period()))

    @app_.route("/external/add", methods=["GET", "POST"])
    def add_external():
        conn = app.connection()
        free = common.rows(conn, FREE_DOMAINS)
        typed = {"address": "", "pop3_login": "", "pop3_host": "", "pop3_port": POP3_PORT,
                 "smtp_host": "", "smtp_port": SMTP_PORT, "window": validate.WINDOW_DEFAULT,
                 "comment": "", "domain_choice": "free", "domain_id": "", "label": ""}
        if request.method == "GET":
            return add_page(typed, free)
        typed.update({name: request.form.get(name, "") for name in
                      ("address", "pop3_login", "pop3_host", "pop3_port", "smtp_host",
                       "smtp_port", "comment", "domain_id", "label")})
        typed["window"] = request.form.get("window", "")
        typed["domain_choice"] = request.form.get("domain_choice", "")

        # ⛔ EVERY CHECK RUNS BEFORE ANYTHING IS WRITTEN, in the form's own order:
        # window, address, login, servers, domain choice.
        try:
            window = validate.window(request.form.get("window"))
        except validate.Refused as refused:
            return add_page(typed, free, str(refused), "window")
        try:
            display, canonical = validate.external_address(request.form.get("address"))
        except validate.Refused as refused:
            return add_page(typed, free, str(refused), "address")
        stored = common.one(conn, "SELECT address FROM external_mailbox WHERE "
                                  "address_canonical = %s", (canonical,))
        if stored:
            return add_page(typed, free, duplicate(stored["address"]), "address")
        try:
            login = validate.pop3_login(request.form.get("pop3_login"))
        except validate.Refused as refused:
            return add_page(typed, free, str(refused), "pop3_login")
        servers, field, refusal = read_servers(request.form,
                                               {"pop3_port": POP3_PORT, "smtp_port": SMTP_PORT})
        if servers is None:
            return add_page(typed, free, refusal, field)

        choice = typed["domain_choice"]
        new_label, new_password = None, None
        domain_id = None
        if choice == "new":
            try:
                new_password = validate.password_twice(request.form.get("password"),
                                                       request.form.get("password2"),
                                                       empty=domains.NO_PASSWORD)
                new_label = validate.domain_label(typed["label"])
            except validate.Refused as refused:
                return add_page(typed, free, str(refused), "domain")
            if common.one(conn, "SELECT 1 AS yes FROM domain WHERE label = %s", (new_label,)):
                return add_page(typed, free,
                                f"There is already a domain called {new_label}.", "domain")
        elif choice == "free":
            try:
                domain_id = common.want_int(typed["domain_id"], "domain")
            except validate.Refused:
                return add_page(typed, free, "Choose a free domain, or a new one.", "domain")
            if not common.one(conn, "SELECT 1 AS yes FROM domain WHERE id = %s AND "
                                    "external_mailbox_id IS NULL", (domain_id,)):
                return add_page(typed, free, "That domain is not there, or already has an "
                                             "external mailbox in front of it.", "domain")
        else:
            return add_page(typed, free, "Choose a free domain, or a new one.", "domain")

        credential = request.form.get("credential") or None
        try:
            with common.unique_violation(conn, duplicate(display)), conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO external_mailbox (address, address_canonical, pop3_login, "
                    "credential, pop3_host, pop3_port, smtp_host, smtp_port, "
                    "delete_window_days, comment) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (display, canonical, login, credential, servers["pop3_host"],
                     servers["pop3_port"], servers["smtp_host"], servers["smtp_port"],
                     window, typed["comment"] or None))
                external_id = cursor.fetchone()[0]
        except validate.Refused:
            # ⚠️ the concurrent winner committed between the check and this INSERT; its
            # spelling is readable now, and the person gets the same sentence the check
            # would have given rather than an error page
            won = common.one(conn, "SELECT address FROM external_mailbox WHERE "
                                   "address_canonical = %s", (canonical,))
            return add_page(typed, free, duplicate(won["address"] if won else display),
                            "address")

        if choice == "new":
            taken = f"There is already a domain called {new_label}."
            try:
                with common.unique_violation(conn, taken), conn.cursor() as cursor:
                    cursor.execute("INSERT INTO domain (label, archive_password_hash) "
                                   "VALUES (%s, %s) RETURNING id",
                                   (new_label, domains.auth_hash(new_password)))
                    domain_id = cursor.fetchone()[0]
            except validate.Refused as refused:
                return add_page(typed, free, str(refused), "domain")
            request_id = common.ask(conn, "create_domain", new_label,
                                    {"domain_id": domain_id}, g.identity)
            domains.record(conn, "create_domain", new_label,
                           {"archive": f"{domains.ARCHIVE}@{new_label}"},
                           request_id=request_id)
            domains.record(conn, "set_archive_password", new_label,
                           {"archive_password_set": True})

        label = new_label
        occupied = ("That domain is not there, or already has an external mailbox in "
                    "front of it.")
        try:
            with common.unique_violation(conn, occupied), conn.cursor() as cursor:
                cursor.execute("UPDATE domain SET external_mailbox_id = %s WHERE id = %s "
                               "AND external_mailbox_id IS NULL RETURNING label",
                               (external_id, domain_id))
                got = cursor.fetchone()
                if got is None:
                    raise validate.Refused(occupied)
                label = got[0]
        except validate.Refused as refused:
            return add_page(typed, free, str(refused), "domain")

        domains.record(conn, "add_external_mailbox", canonical,
                       {"credential_set": credential is not None, "window": window})
        # the link is written once, here, and there is no unlink and no move
        domains.record(conn, "map_domain", label, {"external_mailbox_id": external_id})
        return common.acted("external", "external_saved")

    @app_.get("/external/<int:external_id>")
    def external_mailbox(external_id):
        conn = app.connection()
        return item(conn, needed(conn, external_id))

    @app_.post("/external/<int:external_id>/settings")
    def external_settings(external_id):
        """the login, a new password, the window and the comment together."""
        conn = app.connection()
        row = needed(conn, external_id)
        settings = {"pop3_login": request.form.get("pop3_login",
                                                   row["pop3_login"] or ""),
                    "window": request.form.get("window", ""),
                    "comment": request.form.get("comment", row["comment"] or "")}
        try:
            window = validate.window(request.form.get("window"))
        except validate.Refused as refused:
            return item(conn, row, 400, "settings", str(refused), "window",
                        settings=settings)
        try:
            # ⚠️ A SUBMISSION THAT DOES NOT CARRY THE FIELD AT ALL KEEPS THE STORED
            # LOGIN. Clearing a working login makes the fetcher treat the mailbox as new
            # and collect its whole window again, and a form that did not carry the field
            # did not ask for that.
            typed_login = request.form.get("pop3_login")
            login = (row["pop3_login"] if typed_login is None
                     else validate.pop3_login(typed_login))
        except validate.Refused as refused:
            return item(conn, row, 400, "settings", str(refused), "pop3_login",
                        settings=settings)

        credential = request.form.get("credential") or None
        before_login = row["pop3_login"] or None
        login_changed = login != before_login
        comment = request.form.get("comment", row["comment"] or "") or None

        with conn.cursor() as cursor:
            if credential is not None:
                cursor.execute("UPDATE external_mailbox SET credential = %s WHERE id = %s",
                               (credential, external_id))
            cursor.execute("UPDATE external_mailbox SET pop3_login = %s, "
                           "delete_window_days = %s, comment = %s WHERE id = %s",
                           (login, window, comment, external_id))
        if credential is not None:
            domains.record(conn, "set_credential", row["address_canonical"],
                           {"credential_set": True})
        if login_changed:
            domains.record(conn, "set_pop3_login", row["address_canonical"],
                           {"before": before_login, "after": login})
        if window != row["delete_window_days"]:
            domains.record(conn, "set_delete_window", row["address_canonical"],
                           {"days": window})
        # ⛔ a changed login AND a changed password each ask the pipeline to try the
        # stored credential; the comment and the window change nothing at the provider
        if login_changed or credential is not None:
            common.ask(conn, "test_credential", row["address_canonical"],
                       {"external_mailbox_id": external_id}, g.identity)
        key = ("settings_saved_login" if login_changed else
               "settings_saved_password" if credential is not None else "settings_saved")
        return common.acted("external_mailbox", key, external_id=external_id)

    @app_.post("/external/<int:external_id>/servers")
    def external_servers(external_id):
        """four fields; an identical save writes nothing at all."""
        conn = app.connection()
        row = needed(conn, external_id)
        typed = {name: request.form.get(name, "") for name in
                 ("pop3_host", "pop3_port", "smtp_host", "smtp_port")}
        # ⚠️ no default here: on this form an empty port is refused, because nothing on
        # the screen shows what it would become
        values, field, refusal = read_servers(request.form)
        if values is None:
            return item(conn, row, 400, "servers", refusal, field, servers=typed)
        before = servers_of(row)
        if before == values:
            return common.acted("external_mailbox", "servers_same", external_id=external_id)
        # ⛔ A HOST CHANGE CLEARS THE STORED CREDENTIAL. The clearing
        # is a trigger on the table, so it holds for every writer; here it decides only
        # what to say and whether a check is worth queuing. A port-only change keeps it.
        host_changed = (before["pop3_host"] != values["pop3_host"]
                        or before["smtp_host"] != values["smtp_host"])
        with conn.cursor() as cursor:
            cursor.execute("UPDATE external_mailbox SET pop3_host = %s, pop3_port = %s, "
                           "smtp_host = %s, smtp_port = %s WHERE id = %s",
                           (values["pop3_host"], values["pop3_port"], values["smtp_host"],
                            values["smtp_port"], external_id))
        # hosts and ports are not secrets, so the row carries all four, before and after;
        # the journal records that the host change cleared the credential
        domains.record(conn, "set_provider_servers", row["address_canonical"],
                       {"before": before, "after": values, "credential_cleared": host_changed})
        if host_changed:
            # the credential is gone, so there is nothing to check; the settings form
            # below now asks for the password again
            return common.acted("external_mailbox", "servers_saved_password_cleared",
                                external_id=external_id)
        # a port-only change keeps the credential; try it, though the check is POP3 alone
        common.ask(conn, "test_credential", row["address_canonical"],
                   {"external_mailbox_id": external_id}, g.identity)
        return common.acted("external_mailbox", "servers_saved", external_id=external_id)

    @app_.post("/external/<int:external_id>/check")
    def external_check(external_id):
        """a request on the saved row, in any state, journaling nothing here."""
        conn = app.connection()
        row = needed(conn, external_id)
        common.ask(conn, "test_credential", row["address_canonical"],
                   {"external_mailbox_id": external_id}, g.identity)
        return common.acted_at(common.origin("external"), "check_asked")

    @app_.post("/external/<int:external_id>/enable")
    def external_enable(external_id):
        """the interface asks; the provider decides whether it happens."""
        conn = app.connection()
        row = needed(conn, external_id)
        common.ask(conn, "activate_external_mailbox", row["address_canonical"],
                   {"external_mailbox_id": external_id}, g.identity)
        return common.acted_at(common.origin("external"), "enable_asked")

    @app_.post("/external/<int:external_id>/disable")
    def external_disable(external_id):
        """at once, from the switch. It destroys nothing."""
        conn = app.connection()
        row = needed(conn, external_id)
        with conn.cursor() as cursor:
            cursor.execute("UPDATE external_mailbox SET state = 'deactivated', "
                           "state_changed_at = now(), state_changed_by = %s WHERE id = %s",
                           (g.identity.login, external_id))
        domains.record(conn, "deactivate_external_mailbox", row["address_canonical"],
                       {"state": "deactivated"})
        return common.acted_at(common.origin("external"), "disabled")

    @app_.route("/external/<int:external_id>/delete", methods=["GET", "POST"])
    def delete_external_mailbox(external_id):
        """two branches, and keeping the domain is the one anything else means."""
        conn = app.connection()
        row = needed(conn, external_id)
        if request.method == "GET":
            numbers = (common.one(conn, domains.NUMBERS, {"id": row["domain_id"]})
                       if row["domain_id"] else None)
            return app.render(f"Delete {row['address']}?", DELETE_PAGE, section="external",
                              row=row, numbers=numbers,
                              delete_word=DELETE_WORD)
        request_id = common.ask(conn, "delete_external_mailbox", row["address_canonical"],
                                {"external_mailbox_id": external_id}, g.identity)
        domains.record(conn, "delete_external_mailbox", row["address_canonical"],
                       {"requested": True}, request_id=request_id)
        if request.form.get("branch") == DELETE_WORD and row["domain_id"]:
            # ⚠️ the domain is NAMED in the request, and the pipeline refuses it if
            # another external mailbox is in front of it by then
            second = common.ask(conn, "delete_domain", row["label"],
                                {"domain_id": row["domain_id"]}, g.identity)
            domains.record(conn, "delete_domain", row["label"], {"requested": True},
                           request_id=second)
        return common.acted("external", "external_deletion_asked")


def duplicate(spelling):
    """The one sentence a second spelling of a mailbox already here is refused with.

    This is the ONLY thing that enforces one fetcher per provider mailbox: two rows
    would mean two fetchers on one account and deletion running in two places.
    """
    return (f"That provider mailbox is already here as {spelling}: two rows would mean "
            "two fetchers on one account and deletion running in two places.")


def add_page(typed, free_domains, refusal=None, fault=None):
    return app.render("Add external mailbox", ADD_PAGE, section="external",
                      status=400 if refusal else 200, typed=typed,
                      free_domains=free_domains, refusal=refusal, fault=fault)
