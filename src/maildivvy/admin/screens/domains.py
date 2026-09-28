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


# --- the bits of markup the screens share ---------------------------------------------------

IN_FRONT = """
{%- macro in_front(row) -%}
{%- if row.external_id -%}
  {%- if has_route('external_mailbox') -%}
  <a href="{{ url_for('external_mailbox', external_id=row.external_id) }}"><code>{{ row.external_address }}</code></a>
  {%- else -%}<code>{{ row.external_address }}</code>{%- endif -%}
  {%- if row.external_state != 'active' %} <span class="badge">disabled</span>{% endif -%}
{%- elif row.waiting -%}
  asked to create
{%- else -%}
  none &mdash; nothing arrives and nothing leaves
{%- endif -%}
{%- endmacro -%}
{%- macro listing_link(row) -%}
{%- if row.waiting -%}waiting for the pipeline
{%- else -%}<a href="{{ url_for('archive_listing', domain_id=row.id) }}">Archive listing</a>
{%- endif -%}
{%- endmacro -%}
{%- macro journal_link(label, text) -%}
{%- if has_route('events') -%}<a href="{{ url_for('events', target=label, back='domains') }}">{{ text }}</a>
{%- else -%}{{ text }}{%- endif -%}
{%- endmacro -%}
"""

LIST_PAGE = IN_FRONT + """
<h1>Domains</h1>
<p><a class="primary" href="{{ url_for('add_domain') }}">Add domain</a></p>
<table>
<tr><th>Label</th><th>External mailbox in front</th><th>Mailboxes</th>
    <th>In the archive</th><th>Actions</th></tr>
{%- for row in domains %}
<tr>
  <td><a href="{{ url_for('domain', domain_id=row.id) }}"><code>{{ row.label }}</code></a></td>
  <td>{{ in_front(row) }}</td>
  <td>{{ row.mailboxes }}</td>
  <td>{{ row.messages }}</td>
  <td>{% if has_route('mailboxes') %}<a href="{{ url_for('mailboxes', domain=row.id) }}">Mailboxes</a>{% else %}Mailboxes{% endif %}
      &middot; {{ listing_link(row) }}
      &middot; {{ journal_link(row.label, 'Journal') }}</td>
</tr>
{%- else %}
<tr><td colspan="5">No domain yet. Every domain has an archive, made in the same act.</td></tr>
{%- endfor %}
</table>
"""

ADD_PAGE = """
<p class="crumbs"><a href="{{ url_for('domains') }}">Domains</a> / Add domain</p>
<h1>Add domain</h1>
{%- if refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
<form method="post" action="{{ url_for('add_domain') }}">
  <label for="label">Label</label>
  <input id="label" name="label" value="{{ typed.label }}">
  {%- if field == 'label' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <p>Every domain has an archive, the canonical copy of its mail, with a read-only login
  of its own (<code>{{ archive }}@&lt;label&gt;</code>). It is made in this same act.</p>
  <label for="password">Archive password</label>
  <input id="password" name="password" type="password" autocomplete="new-password">
  <label for="password2">Archive password again</label>
  <input id="password2" name="password2" type="password" autocomplete="new-password">
  {%- if field == 'password' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <p><button type="submit">Add domain</button>
     <a href="{{ url_for('domains') }}">Cancel, nothing changes</a></p>
</form>
"""

DOMAIN_PAGE = IN_FRONT + mailboxes.SHAPE + """
<p class="crumbs"><a href="{{ url_for('domains') }}">Domains</a> / <code>{{ row.label }}</code></p>
<h1><code>{{ row.label }}</code></h1>
<p>{{ listing_link(row) }} &middot; {{ journal_link(row.label, 'Journal for this domain') }}</p>
<p>In front of it: {{ in_front(row) }}.
{%- if not row.external_id and not row.waiting %}
Free &mdash; no external mailbox in front of it, so nothing arrives and nothing leaves.
{%- endif %}
{{ row.mailboxes }} mailbox(es).
{{ row.messages }} message(s) in the archive{% if row.newest %}, the newest at {{ row.newest }}{% endif %}.</p>

<h2>Mailboxes</h2>
<p><a href="{{ url_for('add_mailbox', domain=row.id) }}">Give someone a mailbox here</a></p>
<table>
{{ mailbox_head(()) }}
{%- for box in boxes %}
{{ mailbox_row(box, ()) }}
{%- endfor %}
</table>

<h2>Spam</h2>
<p>{% if row.spam_reaches_people %}Spam reaches every mailbox here.{% else %}Spam is kept
in the archive alone and reaches nobody here.{% endif %}
A message scoring <strong>{{ row.spam_threshold }}</strong> or more is spam.</p>
<p><a href="{{ url_for('domain_spam', domain_id=row.id) }}">Spam policy&hellip;</a></p>

<h2>Outgoing mail too large to scan</h2>
<p>The antivirus cannot scan a message over its own size limit. What leaves this domain
then is this setting; an infected message and one the antivirus could not answer about
are refused whatever it says.</p>
{%- if outbound_refusal %}<p class="refusal">{{ outbound_refusal }}</p>{% endif %}
<form method="post" action="{{ url_for('domain_outbound', domain_id=row.id) }}">
  <label><input type="radio" name="outbound_unscanned" value="send"
    {{ 'checked' if row.outbound_unscanned == 'send' }}> Send it unscanned</label>
  <label><input type="radio" name="outbound_unscanned" value="refuse"
    {{ 'checked' if row.outbound_unscanned == 'refuse' }}> Refuse it</label>
  <p><button type="submit">Save</button></p>
</form>

<div class="danger">
<h2>Danger zone</h2>
<p>Deleting <code>{{ row.label }}</code> removes its archive, every mailbox in it and
every name in them. It cannot be undone.</p>
{%- if row.external_id %}
<p>Refused: <code>{{ row.external_address }}</code> sits in front of this domain.
Delete that external mailbox first; its deletion page offers to take the domain along.</p>
<p><button type="button" disabled>Delete this domain</button></p>
{%- else %}
<p><a href="{{ url_for('delete_domain', domain_id=row.id) }}">Delete this domain&hellip;</a></p>
{%- endif %}
</div>
"""

SPAM_PAGE = """
<p class="crumbs"><a href="{{ url_for('domains') }}">Domains</a> /
  <a href="{{ url_for('domain', domain_id=row.id) }}"><code>{{ row.label }}</code></a> / Spam</p>
<h1>Spam at <code>{{ row.label }}</code></h1>
{%- if refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
<form method="post" action="{{ url_for('domain_spam', domain_id=row.id) }}">
  <label><input type="checkbox" name="reaches" value="yes" {{ 'checked' if typed.reaches }}>
    Spam reaches people</label>
  <p>With this off, a spam message stays in this domain's archive and reaches nobody: no
  mailbox gets it, and a top-up does not bring it either. One message can still be handed
  to one person by id.</p>
  <label for="threshold">A message is spam at this score</label>
  <input id="threshold" name="threshold" type="number" min="1.00" max="150.00" step="0.01"
         value="{{ typed.threshold }}">
  {%- if field == 'threshold' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <p>A changed threshold governs only mail arriving after the change: the verdict is
  taken once as a message arrives and is kept with it. A message already in the archive
  carries no marks at all whatever the switch says, because the marks go into the bytes
  before delivery and a stored message is never rewritten.</p>
  <p><button type="submit">Save spam policy</button>
     <a href="{{ url_for('domain', domain_id=row.id) }}">Cancel, nothing changes</a></p>
</form>
"""

ARCHIVE_PAGE = IN_FRONT + """
<p class="crumbs"><a href="{{ url_for('domains') }}">Domains</a> /
  <a href="{{ url_for('domain', domain_id=row.id) }}"><code>{{ row.label }}</code></a> / Archive</p>
<h1><code>{{ archive }}@{{ row.label }}</code></h1>
<p>{{ listing_link(row) }}</p>
<p>The archive is this domain's canonical copy: every person's mailbox here is a hardlink
into it. Its login is read-only and is shared by every administrator who reads this
domain, so it is what changes when one of them leaves. Nothing reminds anyone to rotate
it.</p>
<p>Status: {% if reading.waiting %}{{ reading.waiting }}. {{ reading.look_again }}
{%- else %}active{% endif %}. {{ row.messages }} message(s).</p>
<p>Not a person: it cannot be removed, transferred or topped up. Every person's mailbox
here is a set of names on the archive's own files, and its login is read-only &mdash; an
ACL of look, read and mark-seen.</p>
<h2>Archive password</h2>
{%- if refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
<form method="post" action="{{ url_for('archive_password', domain_id=row.id) }}">
  <label for="password">New archive password</label>
  <input id="password" name="password" type="password" autocomplete="new-password">
  <label for="password2">New archive password again</label>
  <input id="password2" name="password2" type="password" autocomplete="new-password">
  <p><button type="submit">Replace the archive password</button></p>
</form>
"""

LISTING_PAGE = """
<p class="crumbs"><a href="{{ url_for('domains') }}">Domains</a> /
  <a href="{{ url_for('domain', domain_id=row.id) }}"><code>{{ row.label }}</code></a> / Archive listing</p>
<h1>Archive listing for <code>{{ row.label }}</code></h1>
<p>Four fields of each row: the date the message carries, when it arrived, who sent it
and its subject. Never a body: this screen reads those columns of the ledger and this
process cannot open a mail file at all. The id is what
<a href="{{ url_for('mailboxes', domain=row.id) }}">deliver one message by id</a> takes.
A message with no date of its own reads <em>arrived</em> and its arrival time; a date is
never invented.</p>
<table>
<tr><th>Date</th><th>From</th><th>Subject</th><th>Id</th><th>State</th><th>Score</th></tr>
{%- for message in messages %}
<tr><td>{% if message.message_date %}{{ message.message_date }}
    {%- else %}arrived {{ message.received_at }}
    <span class="badge">no date in the message</span>{% endif %}</td>
    <td><code>{{ message.sender or '' }}</code></td><td>{{ message.subject or '' }}</td>
    <td><code class="message-id">{{ message.id }}</code></td>
    <td>{{ message.state }}{% if message.is_spam %} <span class="badge">spam</span>{% endif %}</td>
    <td>{{ message.spam_score if message.spam_score is not none else '' }}</td></tr>
{%- else %}
<tr><td colspan="6">Nothing in the archive yet.</td></tr>
{%- endfor %}
</table>
"""

NOT_YET_PAGE = """
<p class="crumbs"><a href="{{ url_for('domains') }}">Domains</a> /
  <a href="{{ url_for('domain', domain_id=row.id) }}"><code>{{ row.label }}</code></a> / Archive listing</p>
<h1>Waiting for the pipeline</h1>
<p>The archive of <code>{{ row.label }}</code> is not there yet: its creation was asked
for at {{ row.asked_at.strftime('%H:%M') }} and the pipeline has not performed it. There
is nothing to list until it has.</p>
<p><a href="{{ url_for('domain', domain_id=row.id) }}">Back to the domain</a></p>
"""

DELETE_PAGE = """
<h1>Delete the domain <code>{{ row.label }}</code>?</h1>
{%- if row.external_id %}
<p class="refusal">Refused: <code>{{ row.external_address }}</code> sits in front of this
domain. Deleting the domain under it would take away the archive its mail is in.</p>
<p>Delete that external mailbox first
{%- if has_route('delete_external_mailbox') %} &mdash;
<a href="{{ url_for('delete_external_mailbox', external_id=row.external_id) }}">its deletion
page</a> offers to take this domain along{% endif %}.</p>
<p><button type="button" disabled>Delete the domain</button></p>
<p><a href="{{ url_for('domain', domain_id=row.id) }}">Cancel, nothing changes</a></p>
{%- else %}
<p>This is the largest destructive act in the interface. It removes:</p>
<table>
<tr><th>Messages removed</th><td>{{ numbers.messages }}</td></tr>
<tr><th>Mailboxes removed</th><td>{{ numbers.mailboxes }}</td></tr>
<tr><th>People who lose their only mailbox</th><td>{{ numbers.people }}</td></tr>
</table>
<p>Disk space is not stated: the store is hardlinked, so no per-domain byte count would
be an honest one.</p>
<form method="post" action="{{ url_for('delete_domain', domain_id=row.id) }}">
  <p><button type="submit" class="danger">Delete <code>{{ row.label }}</code> and everything in it</button></p>
</form>
<p><a href="{{ url_for('domain', domain_id=row.id) }}">Cancel, nothing changes</a></p>
{%- endif %}
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
                              typed=typed, refusal=None, field=None)
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
                              row=row, typed=typed, refusal=None, field=None)

        # ⚠️ the switch comes back in the position it was LEFT IN, not as the column
        # stands: a refusal must not silently undo the half of the form that parsed
        typed = {"reaches": common.checked(request.form, "reaches"),
                 "threshold": request.form.get("threshold", "")}
        try:
            threshold = validate.spam_threshold(typed["threshold"])
        except validate.Refused as refused:
            return app.render(f"Spam at {row['label']}", SPAM_PAGE, section="domains",
                              status=400, row=row, typed=typed, refusal=str(refused),
                              field="threshold")

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
            return app.render(f"Delete {row['label']}?", DELETE_PAGE, status=400 if occupied else 200,
                              row=row, numbers=numbers)
        request_id = common.ask(conn, "delete_domain", row["label"],
                                {"domain_id": domain_id}, g.identity)
        record(conn, "delete_domain", row["label"], {"requested": True},
               request_id=request_id)
        return common.acted("domains", "domain_deletion_asked")


# --- writing --------------------------------------------------------------------------------

def refuse_add(typed, refusal, field):
    return app.render("Add domain", ADD_PAGE, section="domains", status=400,
                      archive=ARCHIVE, typed=typed, refusal=refusal, field=field)


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
