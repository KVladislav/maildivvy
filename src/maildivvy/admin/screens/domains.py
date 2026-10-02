"""Domains: the list, one domain, its archive's card, its spam policy, its deletion.

A domain is a label and an archive, and nothing else. It has no state of its own,
and **the link to an external mailbox is written once**, when that
mailbox is created: no route here maps, unmaps or moves one.

⛔ **EVERY DOMAIN HAS AN ARCHIVE AND IT IS NEVER OPTIONAL**. The archive
is the canonical copy every person's mailbox is a hardlink into, and it has a read-only
login of its own. The creation form therefore takes the archive's password, typed twice,
and the two are one act: a domain whose archive has no password is a domain nobody can
read, and it looks exactly like a healthy one on every screen.

⛔ **THE ARCHIVE LISTING IS REFUSED ON THE ROUTE, NOT ONLY ON THE LINKS**.
While the domain's `create_domain` request is queued or
running, the four entry points read "waiting for the pipeline" - and the
route itself answers 400, because hiding a link is not a rule.

⛔ **THE CREATION WRITES ITS OWN JOURNAL ROW**. In the predecessor
a created domain was known only through `set_archive_password`, so the journal could not
answer "when was this domain made". Here the act writes `create_domain` against the
request that performs it, and `set_archive_password` beside it.

Two settings are screens or controls of their own rather than a form on this page: the
spam policy, because lowering the threshold and switching delivery off in two saves
would leave the domain in a state nobody chose in between; and what
happens to outgoing mail too large to scan.
"""

from flask import abort, g, request

from maildivvy.admin import app, auth, validate
from maildivvy.admin.screens import common, mailboxes

ARCHIVE = common.ARCHIVE     # every domain's own mailbox, never a person

# One journal writer for every screen, so none of them builds an INSERT of its own.
record = common.record

NO_PASSWORD = ("The archive needs a password. A domain whose archive has no password is "
               "a domain nobody can read, and it looks identical to a healthy one on "
               "every screen.")

LIST = """
SELECT d.id, d.label, d.spam_threshold, d.spam_reaches_people, d.outbound_unscanned,
       e.id AS external_id, e.address AS external_address, e.state AS external_state,
       (SELECT count(*) FROM mailbox m WHERE m.domain_id = d.id)  AS mailboxes,
       (SELECT count(*) FROM message g WHERE g.domain_id = d.id)  AS messages,
       (SELECT max(g.received_at) FROM message g WHERE g.domain_id = d.id) AS newest,
       EXISTS (SELECT 1 FROM request r
                WHERE r.kind = 'create_domain' AND r.state IN ('queued', 'running')
                  AND (r.payload ->> 'domain_id')::bigint = d.id) AS waiting,
       (SELECT r.created_at FROM request r
         WHERE r.kind = 'create_domain' AND r.state IN ('queued', 'running')
           AND (r.payload ->> 'domain_id')::bigint = d.id
         ORDER BY r.id DESC LIMIT 1) AS asked_at
  FROM domain d
  LEFT JOIN external_mailbox e ON e.id = d.external_mailbox_id
"""

# What deleting a domain removes, as numbers, before its button. Disk bytes
# are never among them: a hardlinked store has no honest per-domain byte count.
NUMBERS = """
SELECT (SELECT count(*) FROM message WHERE domain_id = %(id)s)  AS messages,
       (SELECT count(*) FROM mailbox WHERE domain_id = %(id)s)  AS mailboxes,
       (SELECT count(*) FROM account a
         WHERE EXISTS (SELECT 1 FROM mailbox m
                        WHERE m.account_id = a.id AND m.domain_id = %(id)s)
           AND NOT EXISTS (SELECT 1 FROM mailbox m
                            WHERE m.account_id = a.id AND m.domain_id <> %(id)s)) AS people
"""

LISTING = """
SELECT id, received_at, message_date, sender, subject, state, is_spam, spam_score,
       archive_uid
  FROM message WHERE domain_id = %s ORDER BY received_at DESC, id DESC LIMIT 500
"""


# --- the bits of markup the screens share (in the design's components) -------------

# Every domain page starts with these macros, so its page head and its body both call
# them: what sits in front of a domain, the links to its archive listing and its journal
# (each drawn with the classes it is given), and the way back to it in the crumbs.
IN_FRONT = """
{%- macro in_front(row) -%}
{%- if row.external_id -%}
  {%- if has_route('external_mailbox') -%}
  <a href="{{ url_for('external_mailbox', external_id=row.external_id) }}"><code>{{ row.external_address }}</code></a>
  {%- else -%}<code>{{ row.external_address }}</code>{%- endif -%}
  {%- if row.external_state != 'active' %} <span class="badge off">disabled</span>{% endif -%}
{%- elif row.waiting -%}
  asked to create
{%- else -%}
  <span class="muted">none &mdash; nothing arrives and nothing leaves</span>
{%- endif -%}
{%- endmacro -%}
{%- macro listing_link(row, class_) -%}
{%- if row.waiting -%}<span class="muted">waiting for the pipeline</span>
{%- else -%}<a class="{{ class_ }}" href="{{ url_for('archive_listing', domain_id=row.id) }}">Archive listing</a>
{%- endif -%}
{%- endmacro -%}
{%- macro journal_link(label, text, class_) -%}
{%- if has_route('events') -%}<a class="{{ class_ }}" href="{{ url_for('events', target=label, back='domains') }}">{{ text }}</a>
{%- else -%}{{ text }}{%- endif -%}
{%- endmacro -%}
{%- macro way(row) -%}
<a href="{{ url_for('domains') }}">Domains</a> / \
<a href="{{ url_for('domain', domain_id=row.id) }}"><code>{{ row.label }}</code></a>
{%- endmacro -%}
"""

LIST_PAGE = IN_FRONT + """
{%- set heading %}Domains{% endset %}
{%- set actions %}<a class="btn btn-primary" href="{{ url_for('add_domain') }}">Add domain</a>{% endset %}
<section class="box"><div class="table-wrap"><table>
<thead><tr><th>Label</th><th>External mailbox in front</th><th class="num">Mailboxes</th>\
<th class="num">In the archive</th><th class="acts">Actions</th></tr></thead>
<tbody>
{%- for row in domains %}
<tr>
  <td><a href="{{ url_for('domain', domain_id=row.id) }}"><code>{{ row.label }}</code></a></td>
  <td>{{ in_front(row) }}</td>
  <td class="num">{{ row.mailboxes }}</td>
  <td class="num">{{ row.messages }}</td>
  <td class="acts">{% if has_route('mailboxes') %}<a class="btn btn-sm" href="{{ url_for('mailboxes', domain=row.id) }}">Mailboxes</a>{% else %}Mailboxes{% endif %}
      {{ listing_link(row, 'btn btn-sm') }}
      {{ journal_link(row.label, 'Journal', 'btn btn-sm btn-link') }}</td>
</tr>
{%- else %}
<tr><td colspan="5">No domain yet. Every domain has an archive, made in the same act.</td></tr>
{%- endfor %}
</tbody>
</table></div></section>
"""

ADD_PAGE = IN_FRONT + """
{%- set heading %}Add domain{% endset %}
{%- set crumbs %}<a href="{{ url_for('domains') }}">Domains</a> / Add domain{% endset %}
{%- set about %}Every domain has an archive, the canonical copy of its mail, with a read-only
login of its own (<code>{{ archive }}@&lt;label&gt;</code>). It is made in this same act.{% endset %}
<form class="narrow" method="post" action="{{ url_for('add_domain') }}">
{{ refused(refusal) }}
<section class="box"><div class="box-body">
{{ field('Label', 'label', typed.label, class_='mono-input mid',
         warn=refusal if fault == 'label') }}
{{ field('Archive password', 'password', type='password', class_='mid',
         autocomplete='new-password', help=about) }}
{{ field('Archive password again', 'password2', type='password', class_='mid',
         autocomplete='new-password', warn=refusal if fault == 'password') }}
</div></section>
<div class="form-foot"><button class="btn btn-primary" type="submit">Add domain</button>\
<a class="btn" href="{{ url_for('domains') }}">Cancel, nothing changes</a></div>
</form>
"""

DOMAIN_PAGE = IN_FRONT + mailboxes.SHAPE + """
{%- set heading %}<code>{{ row.label }}</code>{% endset %}
{%- set lede %}In front of it: {{ in_front(row) }}.
{%- if not row.external_id and not row.waiting %}
Free &mdash; no external mailbox in front of it, so nothing arrives and nothing leaves.
{%- endif %}
{{ row.mailboxes }} mailbox(es).
{{ row.messages }} message(s) in the archive{% if row.newest %}, the newest at {{ row.newest }}{% endif %}.{% endset %}
{%- set actions %}{{ listing_link(row, 'btn') }} \
{{ journal_link(row.label, 'Journal for this domain', 'btn') }}{% endset %}
{%- set crumbs %}<a href="{{ url_for('domains') }}">Domains</a> / <code>{{ row.label }}</code>{% endset %}
<div class="stack">
<section class="box">
<div class="box-head"><h2>Mailboxes</h2><a class="btn btn-sm btn-primary" \
href="{{ url_for('add_mailbox', domain=row.id) }}">Give someone a mailbox here</a></div>
<div class="table-wrap"><table>
{{ mailbox_head(()) }}
<tbody>
{%- for box in boxes %}
{{ mailbox_row(box, ()) }}
{%- endfor %}
</tbody>
</table></div>
</section>

<section class="box">
<div class="box-head"><h2>Spam</h2><a class="btn btn-sm" \
href="{{ url_for('domain_spam', domain_id=row.id) }}">Spam policy&hellip;</a></div>
<div class="box-body"><p>{% if row.spam_reaches_people %}Spam reaches every mailbox here.{% else %}Spam is kept
in the archive alone and reaches nobody here.{% endif %}
A message scoring <strong>{{ row.spam_threshold }}</strong> or more is spam.</p></div>
</section>

{{ refused(outbound_refusal) }}
{%- set about %}The antivirus cannot scan a message over its own size limit. What leaves this
domain then is this setting; an infected message and one the antivirus could not answer about
are refused whatever it says.{% endset %}
{%- set choices -%}
<label class="choice"><input type="radio" name="outbound_unscanned" value="send"
{{- ' checked' if row.outbound_unscanned == 'send' }}><div><b>Send it unscanned</b></div></label>
<label class="choice"><input type="radio" name="outbound_unscanned" value="refuse"
{{- ' checked' if row.outbound_unscanned == 'refuse' }}><div><b>Refuse it</b></div></label>
{%- if outbound_refusal %}<div class="field"><p class="help warn">{{ outbound_refusal }}</p></div>{% endif -%}
{%- endset %}
<section class="box"><div class="box-body settings">
{{ setting(url_for('domain_outbound', domain_id=row.id), 'Outgoing mail too large to scan',
           about, choices, 'Save') }}
</div></section>

{%- set sentence %}Deleting <code>{{ row.label }}</code> removes its archive, every mailbox in it
and every name in them. It cannot be undone.{% endset %}
{%- if row.external_id %}
{%- set why %}Refused: <code>{{ row.external_address }}</code> sits in front of this domain.
Delete that external mailbox first; its deletion page offers to take the domain along.{% endset %}
{%- set control %}<span class="btn btn-danger" aria-disabled="true">Delete this domain</span>{% endset %}
{%- else %}
{%- set control %}<a class="btn btn-danger" href="{{ url_for('delete_domain', domain_id=row.id) }}">\
Delete this domain&hellip;</a>{% endset %}
{%- endif %}
{{ danger_zone(sentence, why, control) }}
</div>
"""

SPAM_PAGE = IN_FRONT + """
{%- set heading %}Spam at <code>{{ row.label }}</code>{% endset %}
{%- set crumbs %}{{ way(row) }} / Spam{% endset %}
<form class="narrow" method="post" action="{{ url_for('domain_spam', domain_id=row.id) }}">
{{ refused(refusal) }}
<section class="box"><div class="box-body">
<label class="choice"><input type="checkbox" name="reaches" value="yes"{{ ' checked' if typed.reaches }}>\
<div><b>Spam reaches people</b><span>With this off, a spam message stays in this domain's archive
and reaches nobody: no mailbox gets it, and a top-up does not bring it either. One message can
still be handed to one person by id.</span></div></label>
{%- set about %}A changed threshold governs only mail arriving after the change: the verdict is
taken once as a message arrives and is kept with it. A message already in the archive carries
no marks at all whatever the switch says, because the marks go into the bytes before delivery
and a stored message is never rewritten.{% endset %}
{{ field('A message is spam at this score', 'threshold', typed.threshold, type='number',
         min='1.00', max='150.00', step='0.01', class_='short', help=about,
         warn=refusal if fault == 'threshold') }}
</div></section>
<div class="form-foot"><button class="btn btn-primary" type="submit">Save spam policy</button>\
<a class="btn" href="{{ url_for('domain', domain_id=row.id) }}">Cancel, nothing changes</a></div>
</form>
"""

ARCHIVE_PAGE = IN_FRONT + """
{%- set heading %}<code>{{ archive }}@{{ row.label }}</code>{% endset %}
{%- set lede %}The archive is this domain's canonical copy: every person's mailbox here is a
hardlink into it. Its login is read-only and is shared by every administrator who reads this
domain, so it is what changes when one of them leaves. Nothing reminds anyone to rotate it.{% endset %}
{%- set actions %}{{ listing_link(row, 'btn') }}{% endset %}
{%- set crumbs %}{{ way(row) }} / Archive{% endset %}
<div class="stack">
<section class="box"><div class="box-body">
<p>Status: {% if reading.waiting %}{{ reading.waiting }}. {{ reading.look_again }}
{%- else %}<span class="badge ok">active</span>{% endif %}. {{ row.messages }} message(s).</p>
<p>Not a person: it cannot be removed, transferred or topped up. Every person's mailbox
here is a set of names on the archive's own files, and its login is read-only &mdash; an
ACL of look, read and mark-seen.</p>
</div></section>
{{ refused(refusal) }}
{%- set fields %}
{{ field('New archive password', 'password', type='password', class_='mid',
         autocomplete='new-password') }}
{{ field('New archive password again', 'password2', type='password', class_='mid',
         autocomplete='new-password', warn=refusal) }}
{%- endset %}
<section class="box"><div class="box-body settings">
{{ setting(url_for('archive_password', domain_id=row.id), 'Archive password', none, fields,
           'Replace the archive password', primary=true) }}
</div></section>
</div>
"""

LISTING_PAGE = IN_FRONT + """
{%- set heading %}Archive listing for <code>{{ row.label }}</code>{% endset %}
{%- set lede %}Four fields of each row: the date the message carries, when it arrived, who sent
it and its subject. Never a body: this screen reads those columns of the ledger and this
process cannot open a mail file at all. The id is what
<a href="{{ url_for('mailboxes', domain=row.id) }}">deliver one message by id</a> takes.
A message with no date of its own reads <em>arrived</em> and its arrival time; a date is
never invented.{% endset %}
{%- set crumbs %}{{ way(row) }} / Archive listing{% endset %}
<section class="box"><div class="table-wrap"><table>
<thead><tr><th>Date</th><th>From</th><th>Subject</th><th class="num">Id</th><th>State</th>\
<th class="num">Score</th></tr></thead>
<tbody>
{%- for message in messages %}
<tr><td>{% if message.message_date %}{{ message.message_date }}
    {%- else %}<span class="muted">arrived</span> {{ message.received_at }}
    <span class="row-sub"><span class="badge off">no date in the message</span></span>{% endif %}</td>
    <td><code>{{ message.sender or '' }}</code></td><td class="wrap">{{ message.subject or '' }}</td>
    <td class="num"><code class="message-id">{{ message.id }}</code></td>
    <td>{{ message.state }}{% if message.is_spam %} <span class="badge">spam</span>{% endif %}</td>
    <td class="num">{{ message.spam_score if message.spam_score is not none else '' }}</td></tr>
{%- else %}
<tr><td colspan="6">Nothing in the archive yet.</td></tr>
{%- endfor %}
</tbody>
</table></div></section>
"""

NOT_YET_PAGE = IN_FRONT + """
{%- set heading %}Waiting for the pipeline{% endset %}
{%- set crumbs %}{{ way(row) }} / Archive listing{% endset %}
<div class="narrow">
{%- set not_yet %}The archive of
<code>{{ row.label }}</code> is not there yet: its creation was asked for at
{{ row.asked_at.strftime('%H:%M') }} and the pipeline has not performed it. There is nothing
to list until it has.{% endset %}
{{ flash('attn', 'clock', not_yet) }}
<p><a href="{{ url_for('domain', domain_id=row.id) }}">""" + common.BACK + """ Back to the domain</a></p>
</div>
"""

DELETE_PAGE = IN_FRONT + """
{%- set heading %}Delete the domain <code>{{ row.label }}</code>?{% endset %}
{%- set crumbs %}{{ way(row) }} / Delete{% endset %}
<div class="stack narrow">
{%- if row.external_id %}
{%- set occupied %}<b>Refused: \
<code>{{ row.external_address }}</code> sits in front of this domain.</b> Deleting the domain
under it would take away the archive its mail is in. Delete that external mailbox first
{%- if has_route('delete_external_mailbox') %} &mdash;
<a href="{{ url_for('delete_external_mailbox', external_id=row.external_id) }}">its deletion
page</a> offers to take this domain along{% endif %}.{% endset %}
{{ refused(occupied) }}
{%- else %}
<section class="danger-zone">
<div class="box-head"><h2>What goes</h2></div>
<div class="box-body">
<p>This is the largest destructive act in the interface. It removes:</p>
<div class="kv"><div><b>{{ numbers.messages }}</b><span>Messages removed</span></div>\
<div><b>{{ numbers.mailboxes }}</b><span>Mailboxes removed</span></div>\
<div><b>{{ numbers.people }}</b><span>People who lose their only mailbox</span></div></div>
<p class="muted">Disk space is not stated: the store is hardlinked, so no per-domain byte
count would be an honest one.</p>
<form class="form-foot" method="post" action="{{ url_for('delete_domain', domain_id=row.id) }}">\
<button class="btn btn-danger-solid" type="submit">Delete <code>{{ row.label }}</code> and everything in it</button></form>
</div>
</section>
{%- endif %}
<p><a href="{{ url_for('domain', domain_id=row.id) }}">""" + common.BACK + """ Cancel, nothing changes</a></p>
</div>
"""


# --- readers ----------------------------------------------------------------------------------

def domain_row(conn, domain_id):
    """One domain with what is in front of it and its counts, or None."""
    return common.one(conn, LIST + " WHERE d.id = %s", (domain_id,))


def needed(conn, domain_id):
    """The domain, or a 404 inside the shell: every act checks its row exists."""
    row = domain_row(conn, domain_id)
    if row is None:
        abort(404)
    return row


# --- the screens --------------------------------------------------------------------------------

def register(app_):
    @app_.get("/domains")
    def domains():
        conn = app.connection()
        return app.render("Domains", LIST_PAGE, section="domains", archive=ARCHIVE,
                          domains=common.rows(conn, LIST + " ORDER BY d.label"))

    @app_.route("/domains/add", methods=["GET", "POST"])
    def add_domain():
        conn = app.connection()
        typed = {"label": request.form.get("label", "") if request.method == "POST" else ""}
        if request.method == "GET":
            return app.render("Add domain", ADD_PAGE, section="domains", archive=ARCHIVE,
                              typed=typed, refusal=None, fault=None)
        try:
            # ⛔ the order is the form's: the archive's password first, because a domain
            # created without one is the failure this act exists to prevent
            password = validate.password_twice(request.form.get("password"),
                                               request.form.get("password2"),
                                               empty=NO_PASSWORD)
        except validate.Refused as refused:
            return refuse_add(typed, str(refused), "password")
        try:
            label = validate.domain_label(typed["label"])
        except validate.Refused as refused:
            return refuse_add(typed, str(refused), "label")

        taken = f"There is already a domain called {label}."
        if common.one(conn, "SELECT 1 AS yes FROM domain WHERE label = %s", (label,)):
            return refuse_add(typed, taken, "label")
        try:
            with common.unique_violation(conn, taken), conn.cursor() as cursor:
                cursor.execute("INSERT INTO domain (label, archive_password_hash) "
                               "VALUES (%s, %s) RETURNING id",
                               (label, auth_hash(password)))
                domain_id = cursor.fetchone()[0]
        except validate.Refused as refused:
            return refuse_add(typed, str(refused), "label")

        # the disk work is the pipeline's; the row that asked names the request, so the
        # journal can answer whether it was performed and why not
        request_id = common.ask(conn, "create_domain", label, {"domain_id": domain_id},
                                g.identity)
        record(conn, "create_domain", label, {"archive": f"{ARCHIVE}@{label}"},
               request_id=request_id)
        record(conn, "set_archive_password", label, {"archive_password_set": True})
        return common.acted("domains", "domain_created")

    @app_.get("/domains/<int:domain_id>")
    def domain(domain_id):
        conn = app.connection()
        row = needed(conn, domain_id)
        return app.render(row["label"], DOMAIN_PAGE, section="domains", archive=ARCHIVE,
                          row=row, boxes=mailboxes.listing(conn, domain_id, common.timer_period()),
                          outbound_refusal=None)

    @app_.route("/domains/<int:domain_id>/spam", methods=["GET", "POST"])
    def domain_spam(domain_id):
        conn = app.connection()
        row = needed(conn, domain_id)
        if request.method == "GET":
            typed = {"reaches": row["spam_reaches_people"],
                     "threshold": f"{row['spam_threshold']:.2f}"}
            return app.render(f"Spam at {row['label']}", SPAM_PAGE, section="domains",
                              row=row, typed=typed, refusal=None, fault=None)

        # ⚠️ the switch comes back in the position it was LEFT IN, not as the column
        # stands: a refusal must not silently undo the half of the form that parsed
        typed = {"reaches": common.checked(request.form, "reaches"),
                 "threshold": request.form.get("threshold", "")}
        try:
            threshold = validate.spam_threshold(typed["threshold"])
        except validate.Refused as refused:
            return app.render(f"Spam at {row['label']}", SPAM_PAGE, section="domains",
                              status=400, row=row, typed=typed,
                              refusal=str(refused), fault="threshold")

        before = {"spam_reaches_people": row["spam_reaches_people"],
                  "spam_threshold": row["spam_threshold"]}
        after = {"spam_reaches_people": typed["reaches"], "spam_threshold": threshold}
        if before == after:
            return common.acted("domain_spam", "spam_same", domain_id=domain_id)
        with conn.cursor() as cursor:
            cursor.execute("UPDATE domain SET spam_reaches_people = %s, spam_threshold = %s "
                           "WHERE id = %s", (after["spam_reaches_people"],
                                             after["spam_threshold"], domain_id))
        # ⚠️ BOTH settings, before and after, including the one that did not move: the
        # policy is one thing and a row naming half of it cannot be read back
        record(conn, "set_spam_policy", row["label"], {"before": before, "after": after})
        return common.acted("domain_spam", "spam_saved", domain_id=domain_id)

    @app_.post("/domains/<int:domain_id>/outbound")
    def domain_outbound(domain_id):
        """what happens to outgoing mail too large for the antivirus to scan."""
        conn = app.connection()
        row = needed(conn, domain_id)
        chosen = request.form.get("outbound_unscanned")
        if chosen not in ("send", "refuse"):
            return app.render(row["label"], DOMAIN_PAGE, section="domains", status=400,
                              archive=ARCHIVE, row=row,
                              boxes=mailboxes.listing(conn, domain_id, common.timer_period()),
                              outbound_refusal="Outgoing mail too large to scan is either "
                                               "sent unscanned or refused.")
        if chosen == row["outbound_unscanned"]:
            return common.acted("domain", "outbound_same", domain_id=domain_id)
        with conn.cursor() as cursor:
            cursor.execute("UPDATE domain SET outbound_unscanned = %s WHERE id = %s",
                           (chosen, domain_id))
        record(conn, "set_outbound_unscanned", row["label"],
               {"before": row["outbound_unscanned"], "after": chosen})
        return common.acted("domain", "outbound_saved", domain_id=domain_id)

    @app_.get("/domains/<int:domain_id>/archive")
    def archive_card(domain_id):
        conn = app.connection()
        row = needed(conn, domain_id)
        return archive_page(conn, row)

    @app_.post("/domains/<int:domain_id>/archive/password")
    def archive_password(domain_id):
        """the rotation, on the archive's own card, typed twice."""
        conn = app.connection()
        row = needed(conn, domain_id)
        try:
            password = validate.password_twice(request.form.get("password"),
                                               request.form.get("password2"),
                                               empty=NO_PASSWORD)
        except validate.Refused as refused:
            return archive_page(conn, row, status=400, refusal=str(refused))
        with conn.cursor() as cursor:
            cursor.execute("UPDATE domain SET archive_password_hash = %s WHERE id = %s",
                           (auth_hash(password), domain_id))
        record(conn, "set_archive_password", row["label"], {"archive_password_set": True})
        return common.acted("archive_card", "archive_password_set", domain_id=domain_id)

    @app_.get("/domains/<int:domain_id>/archive/listing")
    def archive_listing(domain_id):
        """⛔ Refused while the archive is not there yet - on the ROUTE."""
        conn = app.connection()
        row = needed(conn, domain_id)
        if row["waiting"]:
            return app.render(f"{row['label']} archive listing", NOT_YET_PAGE,
                              section="domains", status=400, row=row)
        return app.render(f"{row['label']} archive listing", LISTING_PAGE,
                          section="domains", row=row,
                          messages=common.rows(conn, LISTING, (domain_id,)))

    @app_.route("/domains/<int:domain_id>/delete", methods=["GET", "POST"])
    def delete_domain(domain_id):
        """one check, read by the confirmation page and by the act alike."""
        conn = app.connection()
        row = needed(conn, domain_id)
        occupied = row["external_id"] is not None
        if request.method == "GET" or occupied:
            numbers = common.one(conn, NUMBERS, {"id": domain_id})
            return app.render(f"Delete {row['label']}?", DELETE_PAGE, section="domains",
                              status=400 if occupied else 200,
                              row=row, numbers=numbers)
        request_id = common.ask(conn, "delete_domain", row["label"],
                                {"domain_id": domain_id}, g.identity)
        record(conn, "delete_domain", row["label"], {"requested": True},
               request_id=request_id)
        return common.acted("domains", "domain_deletion_asked")


# --- writing --------------------------------------------------------------------------------

def refuse_add(typed, refusal, fault):
    return app.render("Add domain", ADD_PAGE, section="domains", status=400,
                      archive=ARCHIVE, typed=typed, refusal=refusal, fault=fault)


def archive_page(conn, row, status=200, refusal=None):
    """The archive's card, reading the queue exactly as every mailbox row reads it."""
    archives = mailboxes.listing(conn, row["id"], common.timer_period())
    reading = (archives[0]["reading"] if archives
               else common.queue_reading(None, None, None, None))
    return app.render(f"{ARCHIVE}@{row['label']}", ARCHIVE_PAGE, section="domains",
                      status=status, archive=ARCHIVE, row=row, refusal=refusal,
                      reading=reading)


def auth_hash(password):
    return auth.make_hash(password)
