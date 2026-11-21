"""External mailboxes: the provider mailbox in front of a domain, and everything about it.

This is the screen the product most exists for: a provider password changes, and
somebody has to put the new one in. Around that sit the four acts a provider mailbox
has - check, enable, disable, delete - and the two forms that change it; and, for a
mailbox collected over IMAP, the snapshot of every folder and its discard.

⛔ **THE STORED CREDENTIAL IS WRITE-ONLY**. No screen, refusal, journal
row or request shows it, not even masked, and the password field has no value slot on
any form. That is not a habit of this file: the interface's database role holds INSERT
and UPDATE on the credential column and NO SELECT at all, so a defect here
could not return it. A database error could still quote it, since PostgreSQL's DETAIL
names every column a statement was given, so the password is written by a
statement of its own once the row stands.

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

import datetime

from flask import abort, g, request

from maildivvy.admin import app, validate
from maildivvy.admin.screens import common, domains
from maildivvy.fetch import imap, snapshot

record = common.record

POP3_EXAMPLE = "pop.example.org"
ADD_WORD = "POP3 or IMAP"   # names the provider's server fields on the add page
SMTP_EXAMPLE = "smtp.example.org"
SMTP_PORT = 587

# Every kind the interface asks for one external mailbox, each with its canonical address
# as the target. Each lookup below names its kinds and that target so
# `request_kind_target_idx` finds the rows; the payload's id stays the test, because an
# address can come back on a later external mailbox.
KINDS = ("test_credential", "activate_external_mailbox", "delete_external_mailbox", "refetch",
         "discard_snapshot")
THIS = ("r.target = e.address_canonical "
        "AND (r.payload ->> 'external_mailbox_id')::bigint = e.id")

# ⚠️ POSTFIX PINS A SERVER, NOT A MAILBOX (amendment of 2026-11-11): where the
# mailboxes sending to one `[host]:port` name different SMTP pins, or some none, the
# policy view answers a fingerprint no certificate has and nothing is relayed there. So
# each row names the OTHER sending mailboxes at its folded host and port whose pin is
# distinct from its own, grouped as postfix_tls_policy groups them. A row in front of no
# domain sends nothing and names nobody; a disabled one still names them, since enabling
# it stops the server for all. The interface cannot read whether a password is stored, so
# an enabled mailbox still waiting for its password counts: it sends once it is typed.
PINS_DIFFER = """ARRAY(SELECT o.address FROM external_mailbox o
              JOIN domain od ON od.external_mailbox_id = o.id
              WHERE d.id IS NOT NULL AND o.id <> e.id AND o.state = 'active'
                AND lower(o.smtp_host) = lower(e.smtp_host) AND o.smtp_port = e.smtp_port
                AND o.smtp_cert_fingerprint IS DISTINCT FROM e.smtp_cert_fingerprint
              ORDER BY o.address) AS pins_differ"""

ROW = """
SELECT e.id, e.address, e.address_canonical, e.protocol, e.pop3_login, e.pop3_host, e.pop3_port,
       e.smtp_host, e.smtp_port, e.delete_window_days, e.comment,
       e.smtp_login, e.keep_at_provider, e.pop3_cert_fingerprint, e.smtp_cert_fingerprint,
       e.state, e.state_changed_at, e.state_changed_by,
       e.last_fetch_at, e.last_fetch_status, e.last_fetch_cause, e.last_fetch_detail,
       e.last_test_at, e.last_test_status, e.last_test_detail,
       e.stuck_since, e.stuck_runs, e.skip_streak, e.frozen_since,
       e.last_skip_at, e.last_skip_uidl, e.held_since, e.imap_uidvalidity, e.imap_last_uid,
       e.snapshot_requested_at, e.snapshot_started_at, e.snapshot_finished_at,
       e.snapshot_status, e.snapshot_detail, e.snapshot_paused_since, e.snapshot_refused,
       e.snapshot_left_out, e.oversize_skipped, d.id AS domain_id, d.label,
       EXISTS (SELECT 1 FROM request r WHERE r.kind = 'test_credential'
                AND r.state IN ('queued', 'running') AND """ + THIS + """) AS checking,
       EXISTS (SELECT 1 FROM request r WHERE r.kind = 'activate_external_mailbox'
                AND r.state IN ('queued', 'running') AND """ + THIS + """) AS enabling,
       EXISTS (SELECT 1 FROM request r WHERE r.kind = 'delete_external_mailbox'
                AND r.state IN ('queued', 'running') AND """ + THIS + """) AS deleting,
       EXISTS (SELECT 1 FROM request r WHERE r.kind = 'discard_snapshot'
                AND r.state IN ('queued', 'running') AND """ + THIS + """) AS discarding,
       (SELECT r.created_at FROM request r WHERE r.kind = 'activate_external_mailbox'
          AND r.state IN ('queued', 'running') AND """ + THIS + """
        ORDER BY r.id DESC LIMIT 1) AS enable_asked_at,
       """ + PINS_DIFFER + """,
       """ + common.newest_request(
    "r.kind IN (" + ", ".join(f"'{kind}'" for kind in KINDS) + ") AND " + THIS) + """
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
STATE_BOX = """{%- from "common.SHAPES" import csrf %}
{%- macro provider_icon(said) -%}
{%- if said.icon %}<svg class="icon {{ said.tone }}"><use href="#i-{{ said.icon }}"/></svg> {% endif -%}
{%- endmacro -%}
{%- macro state_words(row) -%}
{%- if row.deleting %}asked to delete
{%- elif row.enabling %}asked to enable, {{ row.enable_asked_at|moment }} &mdash; {{ row.reading.look_again }}
{%- elif row.state == 'active' %}enabled since {{ row.state_changed_at|moment }} by <code>{{ row.state_changed_by }}</code>
{%- elif row.state_changed_at %}disabled since {{ row.state_changed_at|moment }} by <code>{{ row.state_changed_by }}</code>
{%- else %}saved disabled, never enabled{% endif -%}
{%- endmacro -%}
{%- macro switch(row) -%}
{%- if row.deleting %}<span class="muted">waiting for the pipeline</span>
{%- elif row.enabling %}<button class="switch asked" type="button" disabled>\
<span class="knob"></span>asked to enable, {{ row.enable_asked_at|moment }}</button>
{%- elif row.state == 'active' -%}
<form method="post" action="{{ url_for('external_disable', external_id=row.id) }}">{{ csrf() }}\
<button class="switch on" type="submit" aria-label="Disable" title="Disable">\
<span class="knob"></span>enabled</button></form>
{%- else -%}
<form method="post" action="{{ url_for('external_enable', external_id=row.id) }}">{{ csrf() }}\
<button class="switch" type="submit" aria-label="Enable" title="Enable">\
<span class="knob"></span>disabled</button></form>
{%- endif -%}
{%- endmacro -%}
{%- macro way() -%}<a href="{{ url_for('external') }}">External mailboxes</a>{%- endmacro -%}
{#- `word` labels the provider's server fields, which the `pop3_` columns hold for either
    protocol: the stored protocol's name on a mailbox's page, and on the add page `ADD_WORD`,
    since a page without scripts cannot follow the protocol chosen before it is sent -#}
{%- macro smtp_login_help(word) -%}Empty means the {{ word }} login, or the address when the {{ word }} login is
  empty or holds a colon{% if word != 'IMAP' %}, as a <code>recent:</code> login does{% endif %}. The password
  is the same one.{%- endmacro -%}
{%- set pin_help %}Only for a server whose certificate cannot be verified. Empty checks the
  certificate against the trusted authorities and the host name; a SHA-256 fingerprint
  trusts that one certificate instead, and fetching stops when the provider replaces
  it.{% endset -%}
{%- macro smtp_pin_help(word) -%}As for {{ word }}, but the relay pins a server, not a mailbox: every external
  mailbox that sends through the same SMTP host and port must name the same fingerprint, and
  while they differ, none of them sends there.{%- endmacro -%}
{#- the protocol, as two choice tiles; `fixed` (an enabled mailbox) names it and offers no
    choice, since it changes only while the mailbox is disabled -#}
{%- macro protocol_field(chosen, word, fixed=false, warn=none) -%}
{%- if fixed %}
<div class="field"><span class="lbl">Protocol</span><p>{{ word }}</p><p class="help">It changes only
while the mailbox is disabled: enabling it is what starts collection over a protocol.</p>
{%- else %}
<div class="field"><span class="lbl">Protocol</span>
<label class="choice"><input type="radio" name="protocol" value="pop3"{{ ' checked' if chosen != 'imap' }}><div><b>POP3</b><span>The INBOX is collected, and each message is deleted at the provider when the
window below ends, unless mail is kept there.</span></div></label>
<label class="choice"><input type="radio" name="protocol" value="imap"{{ ' checked' if chosen == 'imap' }}><div><b>IMAP</b><span>The INBOX is read from the moment the mailbox is enabled, and nothing at the
provider is ever deleted, moved or marked as read: it goes with keeping mail there, and no window
applies.</span></div></label>
{%- endif %}
{%- if warn %}<p class="help warn">{{ warn }}</p>{% endif -%}
</div>
{%- endmacro -%}
{#- what an IMAP mailbox's settings show in place of the window and the keep box: the box's
    value travels with the form, since the schema holds such a row to keeping its mail -#}
{%- macro imap_keeps() -%}
<input type="hidden" name="keep_at_provider" value="yes">
<div class="field"><span class="lbl">Deletion at the provider</span><p>None. Nothing collected over IMAP
is ever deleted, moved or marked as read at the provider: every message stays there until its owner
removes it.</p></div>
{%- endmacro -%}
{%- macro others(addresses) -%}
{%- for address in addresses %}{{ ', ' if not loop.first }}<code>{{ address }}</code>{% endfor -%}
{%- endmacro -%}
{%- macro keep_box(on) -%}
<div class="field"><label class="checkline"><input type="checkbox" name="keep_at_provider" value="yes"
{{- ' checked' if on }}><div><b>Keep mail at the provider</b><span>Nothing is ever deleted there,
whatever the window; the provider's mailbox fills up until its owner empties it.</span></div></label></div>
{%- endmacro -%}
"""

LIST_PAGE = """{% extends "app.SHELL" %}
{%- from "common.SHAPES" import csrf, pipeline_failed %}
{%- from "external.STATE_BOX" import provider_icon, state_words, switch, others %}
{%- set heading %}External mailboxes{% endset %}
{%- set actions %}<a class="btn btn-primary" href="{{ url_for('add_external') }}">Add external mailbox</a>{% endset %}{% block body %}
<section class="box compact"><div class="table-wrap"><table>
<thead><tr><th>Address</th><th>In front of</th><th>State</th><th>At the provider</th>\
<th class="acts">Actions</th></tr></thead>
<tbody>
{%- for row in mailboxes %}
<tr>
  <td><a href="{{ url_for('external_mailbox', external_id=row.id) }}"><code>{{ row.address }}</code></a>\
<span class="row-sub">{% if row.keep_at_provider %}kept at the provider{% else %}deleted at the provider {{ row.delete_window_days }} days after first seen{% endif %}</span></td>
  <td>{% if row.domain_id %}<a href="{{ url_for('domain', domain_id=row.domain_id) }}"><code>{{ row.label }}</code></a>{% else %}&mdash;{% endif %}</td>
  <td class="state">{{ switch(row) }}<span class="row-sub">{{ state_words(row) }}</span>
      {{- pipeline_failed(row.reading.failed) }}
      {%- if row.frozen_since %}<span class="row-sub"><a href="{{ url_for('fetch') }}"><span class="badge attn"><svg class="icon attn"><use href="#i-alert"/></svg> frozen</span></a></span>{% endif %}</td>
  <td>
      {%- if row.provider.tone == 'off' %}<span class="muted">{{ row.provider.words }}</span>
      {%- else %}<span class="state-{{ row.provider.tone }}">{{ provider_icon(row.provider) }}{{ row.provider.words }}</span>{% endif %}
      {%- if row.last_fetch_at %}<span class="row-sub">last fetch {{ row.last_fetch_at|moment }}</span>{% endif %}
      {%- if row.oversize %}<span class="row-sub state-attn"><svg class="icon attn"><use href="#i-alert"/></svg> {{ row.oversize }}</span>{% endif %}
      {%- if row.pins_differ %}<span class="row-sub state-attn"><svg class="icon attn"><use href="#i-alert"/></svg> SMTP pin differs from {{ others(row.pins_differ) }}: while they all send, nothing is relayed there</span>{% endif %}</td>
  <td class="acts">{% if row.deleting %}<span class="muted">waiting for the pipeline</span>
      {%- else %}
        {%- if not row.checking and not row.enabling %}
        <form method="post" action="{{ url_for('external_check', external_id=row.id) }}">{{ csrf() }}\
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
</table></div></section>{% endblock %}"""

ADD_PAGE = """{% extends "app.SHELL" %}
{%- from "common.SHAPES" import csrf, refused, field %}
{%- from "external.STATE_BOX" import way, smtp_login_help, pin_help, smtp_pin_help, keep_box,
    protocol_field %}
{%- set heading %}Add external mailbox{% endset %}
{%- set crumbs %}{{ way() }} / Add{% endset %}{% block body %}
<form class="narrow" method="post" action="{{ url_for('add_external') }}">{{ csrf() }}
{{ refused(refusal) }}
{%- set login_help %}Leave empty to log in with the address itself. Over POP3, changing it later
  makes the fetcher treat the mailbox as new and collect its whole window again.{% endset %}
{%- set pop3_help %}Both are implicit TLS on the port, not STARTTLS. Empty is the protocol's own
  port: 995 for POP3, 993 for IMAP.{% endset %}
{%- set smtp_help %}An SMTP port of 465 is sent with implicit TLS; any other port, such as 587, uses
  STARTTLS. Give both hosts by name, not by IP address: the provider's certificate is
  checked against the name. Nothing checks an SMTP host before it is used.{% endset %}
{%- set window_help %}Counted from when the fetcher first saw a message, not from the message's date.
  At a provider that offers only a recent window of messages, a window at or above that
  length deletes nothing.{% endset %}
<section class="box"><div class="box-body">
{{ field('Address', 'address', typed.address, class_='mono-input',
         warn=refusal if fault == 'address') }}
{{ protocol_field(typed.protocol, word, warn=refusal if fault == 'protocol') }}
{{ field(word ~ ' login', 'pop3_login', typed.pop3_login, class_='mono-input', help=login_help,
         warn=refusal if fault == 'pop3_login') }}
{{ field('SMTP login', 'smtp_login', typed.smtp_login, class_='mono-input',
         help=smtp_login_help(word), warn=refusal if fault == 'smtp_login') }}
{{ field('Provider password', 'credential', type='password', autocomplete='new-password',
         help='Stored write-only; never shown again.') }}
<div class="inline-fields">
{{ field(word ~ ' host', 'pop3_host', typed.pop3_host, class_='mono-input',
         warn=refusal if fault == 'pop3_host') }}
{{ field(word ~ ' port', 'pop3_port', typed.pop3_port, type='number', class_='short', min=1,
         max=65535, help=pop3_help, warn=refusal if fault == 'pop3_port') }}
</div>
<div class="inline-fields">
{{ field('SMTP host', 'smtp_host', typed.smtp_host, class_='mono-input',
         warn=refusal if fault == 'smtp_host') }}
{{ field('SMTP port', 'smtp_port', typed.smtp_port, type='number', class_='short', min=1,
         max=65535, help=smtp_help, warn=refusal if fault == 'smtp_port') }}
</div>
{{ field(word ~ ' certificate fingerprint', 'pop3_cert_fingerprint', typed.pop3_cert_fingerprint,
         class_='mono-input', help=pin_help, warn=refusal if fault == 'pop3_cert_fingerprint') }}
{{ field('SMTP certificate fingerprint', 'smtp_cert_fingerprint', typed.smtp_cert_fingerprint,
         class_='mono-input', help=smtp_pin_help(word),
         warn=refusal if fault == 'smtp_cert_fingerprint') }}
{{ field('Deletion at the provider, days', 'window', typed.window, type='number',
         class_='short', min=1, help=window_help, warn=refusal if fault == 'window') }}
{{ keep_box(typed.keep_at_provider) }}
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
</form>{% endblock %}"""

ITEM_PAGE = """{% extends "app.SHELL" %}
{%- from "common.SHAPES" import csrf, flash, refused, pipeline_flash, field, danger_zone %}
{%- from "external.STATE_BOX" import provider_icon, state_words, switch, way, smtp_login_help, pin_help, smtp_pin_help, others, keep_box,
    protocol_field, imap_keeps %}
{%- from "external.SNAPSHOT" import snapshot_box, discard_row %}
{%- set imap = row.protocol == 'imap' %}
{#- an enabled IMAP mailbox: a new host or login clears where its collection starts -#}
{%- set waits = imap and row.state == 'active' %}
{%- set heading %}<code>{{ row.address }}</code>{% endset %}
{%- set lede %}In front of
{%- if row.domain_id %} <a href="{{ url_for('domain', domain_id=row.domain_id) }}"><code>{{ row.label }}</code></a>
{%- else %} no domain{% endif %}. {{ state_words(row) }}.
Rotating the provider password here is the operation this interface most exists for.
{% if imap %}It is collected over IMAP, which changes nothing at the provider.
{%- else %}The deletion window is counted from the fetcher's first sighting of a message.{% endif %} The
address itself is fixed: the canonical address derives from it, so changing it means
deleting this row and adding another.{% endset %}
{%- set actions %}{%- if has_route('events') -%}
<a class="btn" href="{{ url_for('events', target=row.address_canonical, back='external') }}">Journal for this mailbox</a>
{%- endif %}{% endset %}
{%- set crumbs %}{{ way() }} / <code>{{ row.address }}</code>{% endset %}{% block body %}
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
{%- if row.oversize %}
<div class="box-body"><p class="state-attn">{{ row.oversize }}.</p></div>
{%- endif %}
<div class="box-body"><div class="btn-row">{{ switch(row) }}
{%- if row.state != 'active' %}<span class="muted">Everyone keeps what has already arrived; disabling stops new mail and stops sending
as this address.</span>{% endif %}</div></div>
<div class="box-body">
{%- if row.checking %}
<p class="muted">asked to check the password</p>
{%- else %}
<form class="btn-row" method="post" action="{{ url_for('external_check', external_id=row.id) }}">{{ csrf() }}\
<button class="btn" type="submit">Check the password at the provider</button>
  <span class="muted">Checking changes nothing and asks for no password; the pipeline journals the
  result in your name.</span>
</form>
{%- endif %}
</div>
</section>

{%- set pop3_help %}{{ word }} is implicit TLS on its port, not STARTTLS. The fetcher logs in with the
  {{ word }} login, or with the address itself when the login is empty.{% endset %}
{%- set smtp_help %}An SMTP port of 465 is sent with implicit TLS; any other port, such as 587, uses
  STARTTLS. Give both hosts by name, not by IP address: the provider's certificate is
  checked against the name. Nothing checks an SMTP host before it is used, so a change
  takes effect at the next message sent.{% endset %}
<section class="box"><div class="box-head"><h2>Provider servers</h2></div><div class="box-body">
<form method="post" action="{{ url_for('external_servers', external_id=row.id) }}">{{ csrf() }}
{{ refused(refusal if form == 'servers') }}
<div class="inline-fields">
{{ field(word ~ ' host', 'pop3_host', servers.pop3_host, class_='mono-input',
         warn=refusal if fault == 'pop3_host') }}
{{ field(word ~ ' port', 'pop3_port', servers.pop3_port, type='number', class_='short', min=1,
         max=65535, help=pop3_help, warn=refusal if fault == 'pop3_port') }}
</div>
<div class="inline-fields">
{{ field('SMTP host', 'smtp_host', servers.smtp_host, class_='mono-input',
         warn=refusal if fault == 'smtp_host') }}
{{ field('SMTP port', 'smtp_port', servers.smtp_port, type='number', class_='short', min=1,
         max=65535, help=smtp_help, warn=refusal if fault == 'smtp_port') }}
</div>
{{ field(word ~ ' certificate fingerprint', 'pop3_cert_fingerprint', servers.pop3_cert_fingerprint,
         class_='mono-input', help=pin_help, warn=refusal if fault == 'pop3_cert_fingerprint') }}
{%- set pins_differ %}{% if row.pins_differ %}Also sending through this SMTP host and port, with a
  different fingerprint or none: {{ others(row.pins_differ) }}. While this mailbox sends there too,
  nothing is relayed to that server for any of them.{% endif %}{% endset %}
{{ field('SMTP certificate fingerprint', 'smtp_cert_fingerprint', servers.smtp_cert_fingerprint,
         class_='mono-input', help=smtp_pin_help(word),
         warn=refusal if fault == 'smtp_cert_fingerprint' else pins_differ) }}
{%- set clears %}Changing either host, or setting or changing a fingerprint, clears the stored
  provider password, so it is never presented to a server you did not put it in for. Enter it
  again in Settings below; nothing is fetched or sent until you do (<code>0022</code>).
{%- if waits %} A new IMAP host also clears the starting point in the provider's INBOX: nothing is
  collected until the mailbox is disabled and enabled again.{% endif %}{% endset %}
{{ flash('attn', 'alert', clears) }}
<div class="form-foot"><button class="btn" type="submit">Save the servers</button></div>
</form>
</div></section>

{%- set login_help %}Empty means the address itself.
{%- if imap %} Changing it clears the starting point in the provider's INBOX, which enabling the
  mailbox sets{% if waits %}: nothing is collected until it is disabled and enabled again{% endif %}.
{%- else %} Changing a working login makes the fetcher treat the mailbox as new and collect its
  whole window again.{% endif %}{% endset %}
{#- a disabled IMAP mailbox: POP3 has no record of what IMAP collected -#}
{%- set back_to_pop3 %}{% if imap and row.state != 'active' %}Switching back to POP3 collects the
  INBOX again: once enabled, the first fetch takes every message the provider offers that POP3
  has not taken here before, mail already collected over IMAP included, and each reaches every
  person of the domain a second time.{% endif %}{% endset %}
<section class="box"><div class="box-head"><h2>Settings</h2></div><div class="box-body">
<form method="post" action="{{ url_for('external_settings', external_id=row.id) }}">{{ csrf() }}
{{ refused(refusal if form == 'settings') }}
{{ protocol_field(settings.protocol, word, fixed=row.state == 'active',
                  warn=refusal if fault == 'protocol' else back_to_pop3) }}
{{ field(word ~ ' login', 'pop3_login', settings.pop3_login, class_='mono-input', help=login_help,
         warn=refusal if fault == 'pop3_login') }}
{{ field('SMTP login', 'smtp_login', settings.smtp_login, class_='mono-input',
         help=smtp_login_help(word), warn=refusal if fault == 'smtp_login') }}
{{ field('New provider password', 'credential', type='password', autocomplete='new-password',
         help='Leave empty to keep the stored password. Stored write-only; never shown again.') }}
{%- if imap %}
{{ imap_keeps() }}
{%- else %}
{{ field('Deletion at the provider, days', 'window', settings.window, type='number',
         class_='short', min=1, warn=refusal if fault == 'window') }}
{{ keep_box(settings.keep_at_provider) }}
{%- endif %}
{{ field('Comment', 'comment', settings.comment) }}
<div class="form-foot"><button class="btn btn-primary" type="submit">Save settings</button>\
<a class="btn" href="{{ url_for('external') }}">Cancel, nothing changes</a></div>
</form>
</div></section>

{{ snapshot_box(row, refusal if form == 'snapshot') }}

{%- set sentence %}Removes the row, the provider password and the fetcher's state
{%- if row.snapshot.discard %}, and the snapshot{% endif %}. The domain
{%- if row.domain_id %} <code>{{ row.label }}</code>{% endif %}, its archive and every
message in it stay; you will be asked whether the domain goes too.{% endset %}
{%- set control %}<a class="btn btn-danger" href="{{ url_for('delete_external_mailbox', external_id=row.id) }}">\
Delete this external mailbox&hellip;</a>{% endset %}
{{ danger_zone(sentence, none, control, discard_row(row) if row.snapshot.discard else none) }}
</div>{% endblock %}"""

DELETE_PAGE = """{% extends "app.SHELL" %}
{%- from "common.SHAPES" import cancel, csrf %}
{%- from "external.STATE_BOX" import way %}
{%- set heading %}Delete <code>{{ row.address }}</code>?{% endset %}
{%- set lede %}What goes is this row, the provider password and the fetcher's state
{%- if row.snapshot.discard %}, and the snapshot of its folders{% endif %}. Nobody's mail
is destroyed by this act.{% endset %}
{%- set crumbs %}{{ way() }} / <a href="{{ url_for('external_mailbox', external_id=row.id) }}">\
<code>{{ row.address }}</code></a> / Delete{% endset %}{% block body %}
<div class="stack narrow">
{%- if row.domain_id %}
<section class="danger-zone"><div class="box-head"><h2>Leave <code>{{ row.label }}</code> free</h2></div>
<div class="box-body">
<p>The domain, its archive and its mailboxes stay exactly as they are. Nothing arrives
for it and nothing leaves until another external mailbox is put in front of it.</p>
<form class="form-foot" method="post" action="{{ url_for('delete_external_mailbox', external_id=row.id) }}">{{ csrf() }}
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
<form class="form-foot" method="post" action="{{ url_for('delete_external_mailbox', external_id=row.id) }}">{{ csrf() }}
  <input type="hidden" name="branch" value="{{ delete_word }}">
  <button class="btn btn-danger-solid" type="submit">Delete the mailbox and <code>{{ row.label }}</code></button>
</form>
</div></section>
{%- else %}
<section class="danger-zone"><div class="box-body">
<form class="form-foot" method="post" action="{{ url_for('delete_external_mailbox', external_id=row.id) }}">{{ csrf() }}
  <input type="hidden" name="branch" value="leave">
  <button class="btn btn-danger-solid" type="submit">Delete <code>{{ row.address }}</code></button>
</form>
</div></section>
{%- endif %}
{{ cancel(url_for('external_mailbox', external_id=row.id)) }}
</div>{% endblock %}"""

# ⚠️ Any branch value other than this literal counts as "leave": a typo, a truncated
# form or a crafted value all keep the domain.
DELETE_WORD = "delete-the-domain-too"

# --- the snapshot of every folder -----------------------------------------------------

# The section on an IMAP mailbox's page, and its row in the danger zone. `row.snapshot` is
# `snapshot_of`'s reading: the state, the badge, what the moments say, the store path, and
# why a snapshot cannot be asked for now. Where the snapshot stands - folders taken of the
# total, messages, bytes, what was left out - is the last slice's own sentence, the row's
# detail: the interface cannot read the snapshot's manifest, which is the mail owner's.
SNAPSHOT = """{%- from "common.SHAPES" import csrf, flash, refused, zone_row %}
{#- nothing bounds what a snapshot downloads in a day: the rule, beside the button -#}
{%- set daily_cap %}Nothing here limits what a snapshot downloads in a day. Some providers cap
what an account may download over IMAP in a day and lock the account past the cap, its web
sign-in included, for up to a day: this mailbox's collection and its owner's own mail programs
are refused too. At such a provider, ask for a snapshot only of a mailbox whose copy stays well
under the day's cap, counting the second copy of each message in All Mail.{% endset -%}
{%- macro snapshot_box(row, refusal) -%}
{%- set taken = row.snapshot -%}
{#- a refused request is said here even on a POP3 mailbox's page, which has no section -#}
{%- if taken.shown or refusal %}
<section class="box"><div class="box-head"><h2>Snapshot of every folder</h2><span class="badge {{ taken.tone }}">\
{%- if taken.icon %}<svg class="icon {{ taken.tone }}"><use href="#i-{{ taken.icon }}"/></svg> {% endif -%}
{{ taken.words }}</span></div>
<div class="box-body">
{{ refused(refusal) }}
<p>A read-only copy of every folder at the provider into the store, for an import to read later:
the INBOX up to where collection stands and every other folder up to its last message, when the
snapshot starts. Nothing at the provider changes, and nothing in the copy reaches anyone until it
is imported. Its own timer takes it in slices, so a large mailbox takes many.</p>
{%- if taken.state is none %}
{%- if refusal %}
{%- elif taken.refusal %}
<p class="muted">{{ taken.refusal }}</p>
{%- else %}
{{ flash('attn', 'alert', daily_cap) }}
<form class="btn-row" method="post" action="{{ url_for('external_snapshot', external_id=row.id) }}">{{ csrf() }}\
<button class="btn" type="submit">Take a snapshot of every folder</button></form>
{%- endif %}
{%- else %}
<p>{{ taken.when }}</p>
{%- if taken.path %}
{%- if row.snapshot_detail %}
<p>The last slice said: {{ row.snapshot_detail }}.</p>
{%- endif %}
<p>In the store at <code>{{ taken.path }}</code>: a Maildir++ tree and its manifest, which the
operator's copy of the store carries and no dump does.</p>
{%- endif %}
{%- if taken.ended %}
<p class="muted">Nothing takes it up again: discard it below to ask for another.</p>
{%- endif %}
{%- endif %}
</div></section>
{%- endif %}
{%- endmacro -%}
{#- the discard's row, above the deletion's: a link to its confirmation page, or the request
    waiting -#}
{%- macro discard_row(row) -%}
{%- set sentence %}Discard the snapshot: its copy in the store goes, and nothing at the provider
changes.{% endset -%}
{%- set about %}A slice that is running is let finish first, up to its ten minutes.{% endset -%}
{%- set control -%}
{%- if row.discarding %}<span class="muted">waiting for the pipeline</span>
{%- else %}<a class="btn btn-danger" href="{{ url_for('discard_snapshot', external_id=row.id) }}">\
Discard the snapshot&hellip;</a>{% endif -%}
{%- endset -%}
{{ zone_row(sentence, about, control) }}
{%- endmacro -%}
"""

DISCARD_PAGE = """{% extends "app.SHELL" %}
{%- from "common.SHAPES" import cancel, csrf, refused %}
{%- from "external.STATE_BOX" import way %}
{%- set heading %}Discard the snapshot of <code>{{ row.address }}</code>?{% endset %}
{%- set lede %}What goes is the copy of the provider's folders in the store. Nothing at the
provider changes, and a snapshot asked for afterwards starts again from nothing.{% endset %}
{%- set crumbs %}{{ way() }} / <a href="{{ url_for('external_mailbox', external_id=row.id) }}">\
<code>{{ row.address }}</code></a> / Discard the snapshot{% endset %}{% block body %}
<div class="stack narrow">
{%- if refusal %}
{{ refused(refusal) }}
{%- else %}
<section class="danger-zone"><div class="box-head"><h2>What goes</h2></div><div class="box-body">
<p>{{ row.snapshot.when }}</p>
{%- if row.snapshot.path %}
{%- if row.snapshot_detail %}
<p>The last slice said: {{ row.snapshot_detail }}.</p>
{%- endif %}
<p>All of <code>{{ row.snapshot.path }}</code> is removed. A slice that is running is let
finish first, up to its ten minutes.</p>
{%- endif %}
<form class="form-foot" method="post" action="{{ url_for('discard_snapshot', external_id=row.id) }}">{{ csrf() }}
  <button class="btn btn-danger-solid" type="submit">Discard the snapshot</button>
</form>
</div></section>
{%- endif %}
{{ cancel(url_for('external_mailbox', external_id=row.id)) }}
</div>{% endblock %}"""


# --- readers -----------------------------------------------------------------------------------

def provider_of(row):
    """What the provider last said: its words, the voice they are said in, and the icon
    beside them - `off` and no icon when nothing was ever checked, whose words are muted."""
    status = row["last_test_status"]
    if row["checking"]:
        return {"words": "asked to check the password", "tone": "attn", "icon": "clock"}
    if status == "ok":
        return {"words": f"accepted, checked {common.moment(row['last_test_at'])}", "tone": "ok",
                "icon": "check"}
    if status == "auth_failed":
        return {"words": f"refused, since {common.moment(row['last_test_at'])}", "tone": "bad",
                "icon": "alert"}
    if status == "error":
        return {"words": f"check got no answer ({row['last_test_detail'] or 'no detail'})",
                "tone": "attn", "icon": "alert"}
    return {"words": "not checked yet", "tone": "off", "icon": None}


# --- what the snapshot section reads ------------------------------------------------

# The section's states, as its badge says them: the word, its voice and its icon. `asked` is
# a request no slice has started yet; the rest are the pipeline's own closed list
# (`snapshot.STATUSES`), which a unit test holds these to.
ASKED = "asked"
SNAPSHOT_STATES = {
    None: ("none", "off", None),
    ASKED: ("asked", "attn", "clock"),
    snapshot.PENDING: ("under way", "attn", "clock"),
    snapshot.RUNNING: ("a slice running", "attn", "clock"),
    snapshot.PAUSED: ("paused", "attn", "alert"),
    snapshot.DONE: ("done", "ok", "check"),
    snapshot.FAILED: ("failed", "bad", "alert"),
}
# asked for, or under way: a second request is the same one, already asked
UNDER_WAY = (ASKED, snapshot.PENDING, snapshot.RUNNING, snapshot.PAUSED)

SNAPSHOT_NOT_IMAP = ("A snapshot is taken of a mailbox collected over IMAP only: POP3 cannot "
                     "list a mailbox's folders.")
SNAPSHOT_WHILE_DISABLED = "A snapshot is taken of an enabled mailbox only: enable it first."
SNAPSHOT_NO_MARK = ("This mailbox has no starting point in the provider's INBOX, which is where a "
                    "snapshot takes the INBOX up to: disable and enable it again first.")
SNAPSHOT_DISCARDING = ("The snapshot's discard is waiting for the pipeline: ask for another once "
                       "it is done.")
SNAPSHOT_THERE = "There is a snapshot already: discard it below before asking for another."
NO_SNAPSHOT = "There is no snapshot to discard, and none is asked for."

# ⛔ THE REQUEST IS WRITTEN ONLY WHERE THE ROW STILL ALLOWS IT, in the statement itself: a
# second POST, or one that crossed a disable, a discard or the pipeline starting the first,
# writes nothing. The interface writes the request's time and no other snapshot column; the
# pipeline takes a request that is later than the last snapshot ended (`snapshot.WANTED`).
ASK_SNAPSHOT = ("UPDATE external_mailbox e SET snapshot_requested_at = now() "
                "WHERE e.id = %s AND e.protocol = 'imap' AND e.state = 'active' "
                "AND e.imap_uidvalidity IS NOT NULL AND e.snapshot_status IS NULL "
                "AND NOT coalesce(" + snapshot.WANTED + ", false) "
                "AND NOT EXISTS (SELECT 1 FROM request r WHERE r.kind = 'discard_snapshot' "
                "AND r.state IN ('queued', 'running') AND " + THIS + ") RETURNING e.id")


def snapshot_state(row):
    """The pipeline's status, or `asked` for a request later than the last snapshot ended (as
    `snapshot.WANTED` reads one), or None."""
    if row["snapshot_status"] is not None:
        return row["snapshot_status"]
    asked, ended = row["snapshot_requested_at"], row["snapshot_finished_at"]
    if asked is not None and (ended is None or asked > ended):
        return ASKED
    return None


def snapshot_refusal(row):
    """Why a snapshot cannot be asked for now, or None: the one check the section and the
    act both read. A snapshot asked for or under way is not refused: it is already asked."""
    if row["protocol"] != "imap":
        return SNAPSHOT_NOT_IMAP
    if row["state"] != "active":
        return SNAPSHOT_WHILE_DISABLED
    if row["imap_uidvalidity"] is None:
        return SNAPSHOT_NO_MARK
    if row["discarding"]:
        return SNAPSHOT_DISCARDING
    if snapshot_state(row) in snapshot.ENDED:
        return SNAPSHOT_THERE
    return None


def snapshot_when(row, state):
    """The section's sentence of moments for a snapshot asked for or begun."""
    moment = common.moment
    if state == ASKED:
        return f"Asked {moment(row['snapshot_requested_at'])}: its first slice starts it."
    started = f"Started {moment(row['snapshot_started_at'])}"
    if state == snapshot.PENDING:
        return f"{started}; the next slice goes on from where the last one stopped."
    if state == snapshot.RUNNING:
        return f"{started}; a slice is taking it now."
    if state == snapshot.PAUSED:
        since = (f" since {moment(row['snapshot_paused_since'])}"
                 if row["snapshot_paused_since"] else "")
        return f"{started}; paused{since}, and every slice tries again."
    if state == snapshot.DONE:
        return f"{started}; done {moment(row['snapshot_finished_at'])}."
    return f"{started}; failed {moment(row['snapshot_finished_at'])}."


def snapshot_of(row):
    """What the snapshot section and the discard say of a row. The section is drawn
    for an IMAP mailbox, and for any other that still holds a snapshot, which a protocol
    changed while disabled leaves behind until it is discarded."""
    state = snapshot_state(row)
    words, tone, icon = SNAPSHOT_STATES[state]
    # done, but without what the provider refused to send through every slice that asked
    # again, or without folders it left out: a copy to discard and ask for again, or to
    # import as it is
    missing = [f"{row['snapshot_refused']} not copied"] if row["snapshot_refused"] else []
    if row["snapshot_left_out"]:
        folders = row["snapshot_left_out"]
        missing.append(f"{folders} folder{'' if folders == 1 else 's'} left out")
    if state == snapshot.DONE and missing:
        words, tone, icon = ", ".join(["done", *missing]), "attn", "alert"
    begun = state not in (None, ASKED)
    return {"shown": row["protocol"] == "imap" or state is not None, "state": state,
            "words": words, "tone": tone, "icon": icon,
            "when": snapshot_when(row, state) if state is not None else None,
            "path": str(snapshot.home(row["id"])) if begun else None,
            "ended": state in snapshot.ENDED, "discard": state is not None,
            "refusal": snapshot_refusal(row)}


def with_reading(rows, period=None):
    """Each row carrying the reading of the newest request that names it,
    what the provider last said, and where its snapshot stands.

    ⚠️ Any KIND, not only the enable: in the predecessor a failed enable put its reason on the
    row and a failed check or deletion put nothing anywhere.
    """
    for row in rows:
        row["reading"] = common.reading_of(row, period)
        row["provider"] = provider_of(row)
        row["snapshot"] = snapshot_of(row)
        row["oversize"] = oversize_of(row)
    return rows


def oversize_of(row, now=None):
    """The last message passed over the cap, for the week health warns of it, or
    None."""
    skipped = row.get("oversize_skipped")
    if not skipped:
        return None
    at = datetime.datetime.fromisoformat(skipped["at"])
    if (now or datetime.datetime.now(datetime.UTC)) - at >= imap.OVERSIZE_SHOWN:
        return None
    return (f"message {skipped['uid']} ({skipped['size']:,} bytes) was over the "
            f"{imap.MESSAGE_CAP:,}-byte cap and was not collected on {at.date().isoformat()}: "
            "it stays at the provider, where it can be read")


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
            "smtp_host": row["smtp_host"], "smtp_port": row["smtp_port"],
            "pop3_cert_fingerprint": row["pop3_cert_fingerprint"],
            "smtp_cert_fingerprint": row["smtp_cert_fingerprint"]}


def settings_of(row):
    """What the settings form shows: the stored logins, never the password."""
    return {"protocol": row["protocol"],
            "pop3_login": row["pop3_login"] or "", "smtp_login": row["smtp_login"] or "",
            "window": row["delete_window_days"], "keep_at_provider": row["keep_at_provider"],
            "comment": row["comment"] or ""}


def item(conn, row, status=200, form=None, refusal=None, fault=None,
         servers=None, settings=None):
    # ⚠️ the page is laid out by the STORED protocol, a refused form's included: a person
    # who chose IMAP for a POP3 mailbox still has the keep box to tick
    return app.render(row["address"], "external.ITEM_PAGE", section="external", status=status,
                      row=row, form=form, refusal=refusal, fault=fault,
                      word=validate.PROTOCOLS[row["protocol"]],
                      servers=servers or servers_of(row),
                      settings=settings or settings_of(row))


def check_servers(form, defaults, word):
    """The server fields, first fault in field order: the four of
    the hosts, then the two certificate pins. The provider's are named by its
    protocol, `word`."""
    return {
        "pop3_host": ("pop3_host", lambda: validate.host(form.get("pop3_host"), f"{word} host",
                                                         POP3_EXAMPLE)),
        "pop3_port": ("pop3_port", lambda: validate.port(form.get("pop3_port"), f"{word} port",
                                                         defaults.get("pop3_port"))),
        "smtp_host": ("smtp_host", lambda: validate.host(form.get("smtp_host"), "SMTP host",
                                                         SMTP_EXAMPLE)),
        "smtp_port": ("smtp_port", lambda: validate.port(form.get("smtp_port"), "SMTP port",
                                                         defaults.get("smtp_port"))),
        "pop3_cert_fingerprint": ("pop3_cert_fingerprint", lambda: validate.fingerprint(
            form.get("pop3_cert_fingerprint"), f"{word} certificate fingerprint")),
        "smtp_cert_fingerprint": ("smtp_cert_fingerprint", lambda: validate.fingerprint(
            form.get("smtp_cert_fingerprint"), "SMTP certificate fingerprint")),
    }


def read_servers(form, defaults, word):
    """Every server field or the first refusal, as (values, field at fault, sentence)."""
    values = {}
    for name, (field, read) in check_servers(form, defaults, word).items():
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
        return app.render("External mailboxes", "external.LIST_PAGE", section="external",
                          mailboxes=with_reading(
                              common.rows(conn, ROW + " ORDER BY e.address"),
                              common.timer_period()))

    @app_.route("/external/add", methods=["GET", "POST"])
    def add_external():
        conn = app.connection()
        free = common.rows(conn, FREE_DOMAINS)
        # ⚠️ the provider's port box starts empty: it is the chosen protocol's own unless
        # typed, which a box showing one protocol's number could not say
        typed = {"address": "", "protocol": "pop3", "pop3_login": "", "smtp_login": "",
                 "pop3_host": "", "pop3_port": "", "smtp_host": "", "smtp_port": SMTP_PORT,
                 "pop3_cert_fingerprint": "", "smtp_cert_fingerprint": "",
                 "window": validate.WINDOW_DEFAULT, "keep_at_provider": False,
                 "comment": "", "domain_choice": "free", "domain_id": "", "label": ""}
        if request.method == "GET":
            return add_page(typed, free)
        typed.update({name: request.form.get(name, "") for name in
                      ("address", "protocol", "pop3_login", "smtp_login", "pop3_host", "pop3_port",
                       "smtp_host", "smtp_port", "pop3_cert_fingerprint",
                       "smtp_cert_fingerprint", "comment", "domain_id", "label")})
        typed["window"] = request.form.get("window", "")
        typed["keep_at_provider"] = common.checked(request.form, "keep_at_provider")
        typed["domain_choice"] = request.form.get("domain_choice", "")
        try:
            add(conn, read_add(conn, request.form, typed))
        except Refusal as refused:
            # ⚠️ a refusal raised after `add` wrote is undone with the rest: the request
            # answers 400, and a 4xx commits nothing (`app.commit_or_undo`)
            return add_page(typed, free, str(refused), refused.fault)
        return common.acted("external", "external_saved")

    @app_.get("/external/<int:external_id>")
    def external_mailbox(external_id):
        conn = app.connection()
        return item(conn, needed(conn, external_id))

    @app_.post("/external/<int:external_id>/settings")
    def external_settings(external_id):
        """the protocol, the logins, a new password, the window,
        whether mail is kept at the provider and the comment together."""
        conn = app.connection()
        row = needed(conn, external_id)
        keep = common.checked(request.form, "keep_at_provider")
        settings = {"protocol": request.form.get("protocol", row["protocol"]),
                    "pop3_login": request.form.get("pop3_login",
                                                   row["pop3_login"] or ""),
                    "smtp_login": request.form.get("smtp_login", row["smtp_login"] or ""),
                    "window": request.form.get("window", row["delete_window_days"]),
                    "keep_at_provider": keep,
                    "comment": request.form.get("comment", row["comment"] or "")}
        try:
            # ⚠️ A FORM THAT DOES NOT CARRY THE PROTOCOL KEEPS THE STORED ONE, as for the
            # login below: an enabled mailbox's form offers none, since it changes only
            # while disabled. An IMAP mailbox keeps its mail at the provider, which the
            # schema holds too.
            chosen = validate.protocol_change(
                row["state"], row["protocol"],
                validate.protocol(request.form.get("protocol"), row["protocol"]))
            validate.keeps_at_provider(chosen, keep)
        except validate.Refused as refused:
            return item(conn, row, 400, "settings", str(refused), "protocol",
                        settings=settings)
        try:
            # an IMAP mailbox's form carries no window, and keeps the stored one
            typed_window = request.form.get("window")
            window = (row["delete_window_days"] if typed_window is None
                      else validate.window(typed_window))
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
        try:
            # a form that does not carry it keeps the stored one, as for the POP3 login
            typed_smtp = request.form.get("smtp_login")
            smtp_login = (row["smtp_login"] if typed_smtp is None
                          else validate.smtp_login(typed_smtp))
        except validate.Refused as refused:
            return item(conn, row, 400, "settings", str(refused), "smtp_login",
                        settings=settings)

        credential = request.form.get("credential") or None
        before_login = row["pop3_login"] or None
        login_changed = login != before_login
        before_smtp = row["smtp_login"] or None
        comment = request.form.get("comment", row["comment"] or "") or None
        protocol_changed = chosen != row["protocol"]
        # ⛔ a new protocol or login clears the row's mark (the schema's trigger),
        # in any state: journaled, so what arrived after it can be looked for
        cleared = mark_of(row) if protocol_changed or login_changed else None

        with conn.cursor() as cursor:
            # a new protocol or login clears an IMAP mailbox's mark: the schema's trigger,
            # for every writer
            cursor.execute("UPDATE external_mailbox SET protocol = %s, pop3_login = %s, "
                           "smtp_login = %s, delete_window_days = %s, keep_at_provider = %s, "
                           "comment = %s WHERE id = %s",
                           (chosen, login, smtp_login, window, keep, comment, external_id))
            # the password alone, after the row's own statement, as on the add
            if credential is not None:
                cursor.execute("UPDATE external_mailbox SET credential = %s WHERE id = %s",
                               (credential, external_id))
        if protocol_changed:
            record(conn, "set_protocol", row["address_canonical"],
                   {"before": row["protocol"], "after": chosen, **marked(cleared)})
        if credential is not None:
            record(conn, "set_credential", row["address_canonical"],
                   {"credential_set": True})
        if login_changed:
            record(conn, "set_pop3_login", row["address_canonical"],
                   {"before": before_login, "after": login, **marked(cleared)})
        if smtp_login != before_smtp:
            # a login is not a secret; nothing at the provider is asked, because
            # the password check is POP3 alone
            record(conn, "set_smtp_login", row["address_canonical"],
                   {"before": before_smtp, "after": smtp_login})
        if window != row["delete_window_days"] or keep != row["keep_at_provider"]:
            # the row records the policy, both halves even when one moved
            record(conn, "set_delete_window", row["address_canonical"],
                   {"days": window, "keep_at_provider": keep})
        # ⛔ a changed protocol, a changed login AND a changed password each ask the
        # pipeline to try the stored credential; the comment and the window change nothing
        # at the provider
        if protocol_changed or login_changed or credential is not None:
            common.ask(conn, "test_credential", row["address_canonical"],
                       {"external_mailbox_id": external_id}, g.identity)
        return common.acted("external_mailbox", settings_key(
            chosen, row["state"], protocol_changed, login_changed, cleared is not None,
            credential is not None), external_id=external_id)

    @app_.post("/external/<int:external_id>/servers")
    def external_servers(external_id):
        """the hosts, ports and certificate pins; an identical save writes
        nothing at all."""
        conn = app.connection()
        row = needed(conn, external_id)
        typed = {name: request.form.get(name, "") for name in
                 ("pop3_host", "pop3_port", "smtp_host", "smtp_port",
                  "pop3_cert_fingerprint", "smtp_cert_fingerprint")}
        # ⚠️ no default here: on this form an empty port is refused, because nothing on
        # the screen shows what it would become
        values, field, refusal = read_servers(request.form, {},
                                              validate.PROTOCOLS[row["protocol"]])
        if values is None:
            return item(conn, row, 400, "servers", refusal, field, servers=typed)
        before = servers_of(row)
        if before == values:
            return common.acted("external_mailbox", "servers_same", external_id=external_id)
        # ⛔ A HOST CHANGE CLEARS THE STORED CREDENTIAL, AND SO DOES A
        # PIN SET OR CHANGED: a pin replaces the trust store and the name check,
        # so a new one would hand the stored password to whoever holds that certificate.
        # The clearing is a trigger on the table, so it holds for every writer; here it
        # decides only what to say and whether a check is worth queuing. A port-only
        # change keeps it, and so does a pin removed: that returns to the trust store and
        # the name, the check every unpinned mailbox has.
        host_changed = (before["pop3_host"] != values["pop3_host"]
                        or before["smtp_host"] != values["smtp_host"])
        pin_set = any(values[pin] is not None and values[pin] != before[pin]
                      for pin in ("pop3_cert_fingerprint", "smtp_cert_fingerprint"))
        clears = host_changed or pin_set
        # ⛔ and a new host clears an IMAP mailbox's mark, which only enabling sets,
        # in any state: an enabled one collects nothing until a person disables and enables
        # it, and a disabled one, enabled, starts where the INBOX then stands
        cleared = mark_of(row) if before["pop3_host"] != values["pop3_host"] else None
        with conn.cursor() as cursor:
            cursor.execute("UPDATE external_mailbox SET pop3_host = %s, pop3_port = %s, "
                           "smtp_host = %s, smtp_port = %s, pop3_cert_fingerprint = %s, "
                           "smtp_cert_fingerprint = %s WHERE id = %s",
                           (values["pop3_host"], values["pop3_port"], values["smtp_host"],
                            values["smtp_port"], values["pop3_cert_fingerprint"],
                            values["smtp_cert_fingerprint"], external_id))
        # hosts, ports and certificate fingerprints are not secrets, so the row carries
        # them all, before and after; the journal records that the save cleared the
        # credential
        record(conn, "set_provider_servers", row["address_canonical"],
               {"before": before, "after": values, "credential_cleared": clears,
                **marked(cleared)})
        if clears:
            # the credential is gone, so there is nothing to check; the settings form
            # below now asks for the password again
            said = ("servers_saved_password_cleared" if cleared is None
                    else "servers_saved_mark_cleared" if row["state"] == "active"
                    else "servers_saved_mark_cleared_disabled")
            return common.acted("external_mailbox", said, external_id=external_id)
        # a port change or a pin removed keeps the credential; try it, though the check is
        # POP3 alone
        common.ask(conn, "test_credential", row["address_canonical"],
                   {"external_mailbox_id": external_id}, g.identity)
        return common.acted("external_mailbox", "servers_saved", external_id=external_id)

    @app_.post("/external/<int:external_id>/check")
    def external_check(external_id):
        """a request on the saved row, in any state, journaling nothing here."""
        conn = app.connection()
        row = needed(conn, external_id)
        if common.ask_once(conn, "test_credential", row["address_canonical"],
                           {"external_mailbox_id": external_id}, g.identity) is None:
            return common.acted_at(common.origin("external"), "already_asked")
        return common.acted_at(common.origin("external"), "check_asked")

    @app_.post("/external/<int:external_id>/enable")
    def external_enable(external_id):
        """the interface asks; the provider decides whether it happens."""
        conn = app.connection()
        row = needed(conn, external_id)
        if common.ask_once(conn, "activate_external_mailbox", row["address_canonical"],
                           {"external_mailbox_id": external_id}, g.identity) is None:
            return common.acted_at(common.origin("external"), "already_asked")
        return common.acted_at(common.origin("external"), "enable_asked")

    @app_.post("/external/<int:external_id>/disable")
    def external_disable(external_id):
        """at once, from the switch. It destroys nothing."""
        conn = app.connection()
        row = needed(conn, external_id)
        # a disabled mailbox stays as it was: no new stamp and no journal row for nothing
        with conn.cursor() as cursor:
            cursor.execute("UPDATE external_mailbox SET state = 'deactivated', "
                           "state_changed_at = now(), state_changed_by = %s "
                           "WHERE id = %s AND state <> 'deactivated'",
                           (g.identity.login, external_id))
            changed = cursor.rowcount
        if changed:
            record(conn, "deactivate_external_mailbox", row["address_canonical"],
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
            return app.render(f"Delete {row['address']}?", "external.DELETE_PAGE", section="external",
                              row=row, numbers=numbers,
                              delete_word=DELETE_WORD)
        request_id = common.ask_once(conn, "delete_external_mailbox",
                                     row["address_canonical"],
                                     {"external_mailbox_id": external_id}, g.identity)
        if request_id is None:
            return common.acted("external", "already_asked")
        record(conn, "delete_external_mailbox", row["address_canonical"],
               {"requested": True}, request_id=request_id)
        if request.form.get("branch") == DELETE_WORD and row["domain_id"]:
            # ⚠️ the domain is NAMED in the request, and the pipeline refuses it if
            # another external mailbox is in front of it by then
            second = common.ask_once(conn, "delete_domain", row["label"],
                                     {"domain_id": row["domain_id"]}, g.identity)
            if second is not None:
                record(conn, "delete_domain", row["label"], {"requested": True},
                       request_id=second)
        return common.acted("external", "external_deletion_asked")

    @app_.post("/external/<int:external_id>/snapshot")
    def external_snapshot(external_id):
        """a snapshot of every folder, asked for on an enabled IMAP mailbox that has
        its starting point and no snapshot. The interface writes when it was asked, and the
        snapshot's own timer takes it."""
        conn = app.connection()
        row = needed(conn, external_id)
        refusal = row["snapshot"]["refusal"]
        if refusal is not None:
            return item(conn, row, 400, "snapshot", refusal)
        if row["snapshot"]["state"] in UNDER_WAY:
            return common.acted("external_mailbox", "already_asked", external_id=external_id)
        with conn.cursor() as cursor:
            cursor.execute(ASK_SNAPSHOT, (external_id,))
            written = cursor.fetchone() is not None
        if not written:
            # an act that committed since the row was read: a second POST, most often
            return common.acted("external_mailbox", "already_asked", external_id=external_id)
        record(conn, "request_snapshot", row["address_canonical"], {"requested": True})
        return common.acted("external_mailbox", "snapshot_asked", external_id=external_id)

    @app_.route("/external/<int:external_id>/snapshot/discard", methods=["GET", "POST"])
    def discard_snapshot(external_id):
        """the snapshot's copy removed by the pipeline, which lets a slice
        that is running finish first. One check, read by the confirmation page and by the act
        alike."""
        conn = app.connection()
        row = needed(conn, external_id)
        refusal = None if row["snapshot"]["discard"] else NO_SNAPSHOT
        if request.method == "GET" or refusal:
            return app.render(f"Discard the snapshot of {row['address']}?",
                              "external.DISCARD_PAGE", section="external",
                              status=400 if refusal else 200, row=row, refusal=refusal)
        request_id = common.ask_once(conn, "discard_snapshot", row["address_canonical"],
                                     {"external_mailbox_id": external_id}, g.identity)
        if request_id is None:
            return common.acted("external_mailbox", "already_asked", external_id=external_id)
        record(conn, "discard_snapshot", row["address_canonical"], {"requested": True},
               request_id=request_id)
        return common.acted("external_mailbox", "snapshot_discard_asked",
                            external_id=external_id)


def mark_of(row):
    """The IMAP mark a row holds, or None."""
    if row["imap_uidvalidity"] is None:
        return None
    return {"uidvalidity": row["imap_uidvalidity"], "last_uid": row["imap_last_uid"]}


def marked(cleared):
    """A journal row's record of the mark its change cleared: after it, enabling
    sets a new one where the INBOX then stands, and what arrived between the two is looked
    for from here. Nothing when there was none."""
    return {} if cleared is None else {"mark_cleared": cleared}


def settings_key(chosen, state, protocol_changed, login_changed, mark_cleared, password_set):
    """The sentence a settings save returns with: what it asked of the provider, and a mark
    a new IMAP login cleared: an enabled mailbox collects nothing until it is
    disabled and enabled again, and a disabled one, enabled, starts where the INBOX then
    stands. The POP3 login's sentence is its own, and so is a switch back
    to POP3, whose first fetch takes again what IMAP collected."""
    if protocol_changed:
        return "settings_saved_protocol_pop3" if chosen == "pop3" else "settings_saved_protocol"
    if login_changed and chosen == "imap":
        if not mark_cleared:
            return "settings_saved_imap_login"
        return ("settings_saved_imap_login_waits" if state == "active"
                else "settings_saved_imap_login_cleared")
    if login_changed:
        return "settings_saved_login"
    return "settings_saved_password" if password_set else "settings_saved"


def duplicate(spelling):
    """The one sentence a second spelling of a mailbox already here is refused with.

    This is the ONLY thing that enforces one fetcher per provider mailbox: two rows
    would mean two fetchers on one account and deletion running in two places.
    """
    return (f"That provider mailbox is already here as {spelling}: two rows would mean "
            "two fetchers on one account and deletion running in two places.")


class Refusal(validate.Refused):
    """The add form's refusal: the sentence, and the field it is shown beside."""

    def __init__(self, sentence, fault):
        super().__init__(sentence)
        self.fault = fault


# the domain chosen is gone, or another external mailbox took it meanwhile
OCCUPIED = "That domain is not there, or already has an external mailbox in front of it."
NO_CHOICE = "Choose a free domain, or a new one."


def refused_as(fault, check, *args, **kwargs):
    """`check(*args, **kwargs)`, its refusal raised as the add form's, beside `fault`."""
    try:
        return check(*args, **kwargs)
    except validate.Refused as refused:
        raise Refusal(str(refused), fault) from None


def read_add(conn, form, typed):
    """The add form as a value to act on, or `Refusal`. Nothing is written here.

    ⛔ EVERY CHECK RUNS BEFORE ANYTHING IS WRITTEN, in the form's own order:
    window, address, protocol and the keeping it asks for,
    logins, servers, domain choice.
    """
    window = refused_as("window", validate.window, form.get("window"))
    display, canonical = refused_as("address", validate.external_address, form.get("address"))
    stored = common.one(conn, "SELECT address FROM external_mailbox WHERE "
                              "address_canonical = ANY(%s) ORDER BY id LIMIT 1",
                        (validate.legacy_spellings(canonical),))
    if stored:
        raise Refusal(duplicate(stored["address"]), "address")
    chosen = refused_as("protocol", validate.protocol, form.get("protocol"))
    refused_as("protocol", validate.keeps_at_provider, chosen, typed["keep_at_provider"])
    login = refused_as("pop3_login", validate.pop3_login, form.get("pop3_login"))
    smtp_login = refused_as("smtp_login", validate.smtp_login, form.get("smtp_login"))
    servers, field, refusal = read_servers(form, {"pop3_port": validate.PROVIDER_PORTS[chosen],
                                                  "smtp_port": SMTP_PORT},
                                           validate.PROTOCOLS[chosen])
    if servers is None:
        raise Refusal(refusal, field)

    choice = typed["domain_choice"]
    new_label, new_password, domain_id = None, None, None
    if choice == "new":
        new_password = refused_as("domain", validate.password_twice, form.get("password"),
                                  form.get("password2"), empty=domains.NO_PASSWORD)
        new_label = refused_as("domain", validate.domain_label, typed["label"])
        if domains.label_taken(conn, new_label):
            raise Refusal(domains.taken(new_label), "domain")
        refusal = common.not_cleared(conn, new_label)
        if refusal:
            raise Refusal(refusal, "domain")
    elif choice == "free":
        domain_id = common.as_int(typed["domain_id"])
        if domain_id is None:
            raise Refusal(NO_CHOICE, "domain")
        if not common.one(conn, "SELECT 1 AS yes FROM domain WHERE id = %s AND "
                                "external_mailbox_id IS NULL", (domain_id,)):
            raise Refusal(OCCUPIED, "domain")
    else:
        raise Refusal(NO_CHOICE, "domain")
    return {"display": display, "canonical": canonical, "protocol": chosen, "login": login,
            "smtp_login": smtp_login, "servers": servers, "window": window,
            "keep": typed["keep_at_provider"], "comment": typed["comment"] or None,
            "credential": form.get("credential") or None, "domain_id": domain_id,
            "new_label": new_label, "new_password": new_password}


def add(conn, new):
    """Save the mailbox `read_add` read, disabled, with the domain in front of it - made in
    the same step when it is a new one - and journal both. `Refusal` when a concurrent act
    took the address or the domain between the checks and the writes."""
    servers = new["servers"]
    try:
        with common.unique_violation(conn, duplicate(new["display"])), \
                conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO external_mailbox (address, address_canonical, protocol, "
                "pop3_login, smtp_login, pop3_host, pop3_port, smtp_host, smtp_port, "
                "pop3_cert_fingerprint, smtp_cert_fingerprint, delete_window_days, "
                "keep_at_provider, comment) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "RETURNING id",
                (new["display"], new["canonical"], new["protocol"], new["login"],
                 new["smtp_login"],
                 servers["pop3_host"], servers["pop3_port"], servers["smtp_host"],
                 servers["smtp_port"], servers["pop3_cert_fingerprint"],
                 servers["smtp_cert_fingerprint"], new["window"], new["keep"],
                 new["comment"]))
            external_id = cursor.fetchone()[0]
            # ⛔ THE PASSWORD IN A STATEMENT OF ITS OWN, AFTER THE ROW. A
            # failing statement's DETAIL quotes every column it was given, readable
            # or not, so the one statement that names the credential is one
            # whose row has already passed every CHECK.
            if new["credential"] is not None:
                cursor.execute("UPDATE external_mailbox SET credential = %s WHERE id = %s",
                               (new["credential"], external_id))
    except validate.Refused:
        # ⚠️ the concurrent winner committed between the check and this INSERT; its
        # spelling is readable now, and the person gets the same sentence the check
        # would have given rather than an error page
        won = common.one(conn, "SELECT address FROM external_mailbox WHERE "
                               "address_canonical = ANY(%s) ORDER BY id LIMIT 1",
                         (validate.legacy_spellings(new["canonical"]),))
        raise Refusal(duplicate(won["address"] if won else new["display"]),
                      "address") from None

    domain_id = new["domain_id"]
    if new["new_label"] is not None:
        domain_id = refused_as("domain", domains.create_domain, conn, new["new_label"],
                               new["new_password"])
    try:
        with common.unique_violation(conn, OCCUPIED), conn.cursor() as cursor:
            cursor.execute("UPDATE domain SET external_mailbox_id = %s WHERE id = %s "
                           "AND external_mailbox_id IS NULL RETURNING label",
                           (external_id, domain_id))
            got = cursor.fetchone()
            if got is None:
                raise validate.Refused(OCCUPIED)
            label = got[0]
    except validate.Refused as refused:
        raise Refusal(str(refused), "domain") from None

    record(conn, "add_external_mailbox", new["canonical"],
           {"credential_set": new["credential"] is not None, "protocol": new["protocol"],
            "window": new["window"], "keep_at_provider": new["keep"]})
    # the link is written once, here, and there is no unlink and no move
    record(conn, "map_domain", label, {"external_mailbox_id": external_id})


def add_page(typed, free_domains, refusal=None, fault=None):
    # ⚠️ the server's fields are labelled for either protocol, a refused form's included:
    # a label named by the protocol sent would stay "POP3 host" once IMAP is chosen in
    # the page, which has no script to follow the choice
    return app.render("Add external mailbox", "external.ADD_PAGE", section="external",
                      status=400 if refusal else 200, typed=typed, word=ADD_WORD,
                      free_domains=free_domains, refusal=refusal, fault=fault)
