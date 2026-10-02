"""Mailboxes: one row shape, the card, giving one, transferring one, removing one.

⛔ **A MAILBOX ROW HAS ONE SHAPE WHEREVER IT APPEARS**: on this list, on
the domain page and on the person page. It is one macro here, used by all three, because
three tables written separately are three places for a status to stop being the same
fact. The list adds a Person and a Domain column; the other two do not, since every row
there is already about one person or one domain.

⛔ **A MAILBOX HAS NO STATE, NO ROLE AND NO PASSWORD OF ITS OWN**. It is
open exactly when its person is active, so the status cell links to the person rather
than offering a switch, and the word "role" is on no screen at all.

⛔ **EVERY DOMAIN'S ARCHIVE IS A MAILBOX-SHAPED ROW BUILT FROM THE DOMAIN**,
never a stored mailbox or account: `archive` is a login the schema
refuses, so removal and transfer can never reach the canonical copy. It comes first in
its domain, has no person, and offers no top-up, no transfer and no danger zone.

⛔ **GIVING A MAILBOX IS TWO REQUESTS**: `create_mailbox` makes the maildir and
`connect` gives it what the archive already holds. A mailbox whose connect was never
queued delivers nothing, silently, and looks healthy on every screen.

⚠️ The re-prompt is gone: the transfer acts on its submission, with its warning
and its message count on the card. What keeps a confirmation page is the
removal, which destroys names.
"""

from flask import abort, g, request

from maildivvy.admin import app, validate
from maildivvy.admin.screens import common

ARCHIVE = common.ARCHIVE
record = common.record

BOXES = """
SELECT m.id, m.as_of, a.id AS account_id, a.login, a.state AS account_state,
       a.comment, d.id AS domain_id, d.label,
       (SELECT count(*) FROM delivery dl WHERE dl.mailbox_id = m.id) AS total,
       """ + common.newest_request("(r.payload ->> 'mailbox_id')::bigint = m.id") + """
  FROM mailbox m
  JOIN account a ON a.id = m.account_id
  JOIN domain d ON d.id = m.domain_id
"""

ARCHIVES = """
SELECT d.id AS domain_id, d.label,
       (SELECT count(*) FROM message g WHERE g.domain_id = d.id) AS total,
       """ + common.newest_request(
    "r.kind IN ('create_domain', 'delete_domain') "
    "AND (r.payload ->> 'domain_id')::bigint = d.id") + """
  FROM domain d
"""

FREE_PEOPLE = """
SELECT a.id, a.login FROM account a
 WHERE NOT EXISTS (SELECT 1 FROM mailbox m
                    WHERE m.account_id = a.id AND m.domain_id = %s)
 ORDER BY a.login
"""
EVERYONE = "SELECT id, login FROM account ORDER BY login"
ALL_DOMAINS = "SELECT id, label FROM domain ORDER BY label"

# What removing one mailbox takes, as numbers, before its button. The archive
# keeps every message, so no message count appears among them.
REMOVAL = "SELECT count(*) AS names FROM delivery WHERE mailbox_id = %s"

BOTH = "A mailbox is a person in a domain: choose both."
OCCUPIED = ("That person already has a mailbox in this domain. The model allows exactly "
            "one per person per domain.")
NO_DOMAIN = "That domain is not there."
NO_PERSON = "That person is not there."


# --- the one row shape --------------------------------------------------------

SHAPE = """
{%- macro mailbox_head(columns) -%}
<thead><tr><th>Mailbox</th>
{%- if 'person' in columns %}<th>Person</th>{% endif %}
{%- if 'domain' in columns %}<th>Domain</th>{% endif -%}
<th>Status</th><th class="num">Total mails</th><th class="acts">Actions</th></tr></thead>
{%- endmacro -%}
{%- macro mailbox_status(box) -%}
{%- if box.reading.waiting -%}
{{ box.reading.waiting }}<span class="row-sub">{{ box.reading.look_again }}</span>
{%- else -%}
{%- if box.kind == 'archive' %}<span class="badge ok">active</span>
{%- elif box.account_state == 'blocked' %}<span class="badge attn">blocked</span><span class="row-sub"><a href="{{ url_for('account', account_id=box.account_id) }}">set on the person &mdash; mail still arrives</a></span>
{%- else %}<span class="badge ok">active</span>{% endif -%}
{{- pipeline_failed(box.reading.failed) -}}
{%- endif -%}
{%- endmacro -%}
{%- macro mailbox_acts(box) -%}
{%- if box.reading.waiting %}<span class="muted">waiting for the pipeline</span>
{%- elif box.kind == 'archive' -%}
<a class="btn btn-sm" href="{{ url_for('archive_listing', domain_id=box.domain_id) }}">Archive listing</a>
<a class="btn btn-sm btn-link" href="{{ url_for('events', target=box.label, back='mailboxes') }}">Journal</a>
{%- else -%}
<a class="btn btn-sm" href="{{ url_for('top_up', mailbox_id=box.id) }}">Top up</a>
<a class="btn btn-sm btn-link" href="{{ url_for('events', target=box.address, back='mailboxes') }}">Journal</a>
{%- endif -%}
{%- endmacro -%}
{%- macro mailbox_row(box, columns) -%}
<tr>
  <td>
  {%- if box.kind == 'archive' -%}
  <a href="{{ url_for('archive_card', domain_id=box.domain_id) }}"><code>{{ box.address }}</code></a>
  <span class="badge">archive</span>
  {%- else -%}
  <a href="{{ url_for('mailbox', mailbox_id=box.id) }}"><code>{{ box.address }}</code></a>
  {%- endif -%}
  </td>
  {%- if 'person' in columns %}
  <td>{% if box.account_id %}<a href="{{ url_for('account', account_id=box.account_id) }}"><code>{{ box.login }}</code></a>{% else %}&mdash;{% endif %}</td>
  {%- endif %}
  {%- if 'domain' in columns %}
  <td><a href="{{ url_for('domain', domain_id=box.domain_id) }}"><code>{{ box.label }}</code></a></td>
  {%- endif %}
  <td>{{ mailbox_status(box) }}</td>
  <td class="num">{{ box.total }}</td>
  <td class="acts">{{ mailbox_acts(box) }}</td>
</tr>
{%- endmacro -%}
"""

LIST_PAGE = SHAPE + """
{%- set heading %}Mailboxes{% endset %}
{%- set lede %}A mailbox is one person in one domain. It has no state, no password and no settings of
its own: it is open exactly when its person is active, and one password opens every
mailbox a person holds. Each domain's own archive appears first, as a row of the same
shape.{% endset %}
{%- set actions %}<a class="btn btn-primary" href="{{ url_for('add_mailbox') }}">Give someone a mailbox</a>{% endset %}
<section class="box"><div class="table-wrap"><table>
{{ mailbox_head(columns) }}
<tbody>
{%- for box in boxes %}
{{ mailbox_row(box, columns) }}
{%- else %}
<tr><td colspan="6">No domain yet, so there is nothing to give a mailbox in.</td></tr>
{%- endfor %}
</tbody>
</table></div></section>
"""

ADD_PAGE = """
{%- set heading %}Give someone a mailbox{% endset %}
{%- set lede %}It delivers only mail that arrives from now on. Earlier mail is a top-up afterwards.{% endset %}
{%- set crumbs %}<a href="{{ url_for('mailboxes') }}">Mailboxes</a> / Give someone a mailbox{% endset %}
<form class="narrow" method="post" action="{{ url_for('add_mailbox') }}">
{{ refused(refusal) }}
<section class="box"><div class="box-body">
<div class="field"><label for="domain_id">Domain</label>
  <select id="domain_id" name="domain_id" class="mid">
    <option value="">&mdash;</option>
    {%- for row in domains %}
    <option value="{{ row.id }}" {{ 'selected' if typed.domain_id == row.id|string }}>{{ row.label }}</option>
    {%- endfor %}
  </select>
  {%- if fault == 'domain_id' %}<p class="help warn">{{ refusal }}</p>{% endif %}</div>
<div class="field"><label for="account_id">Person</label>
  <select id="account_id" name="account_id" class="mid">
    <option value="">&mdash;</option>
    {%- for row in people %}
    <option value="{{ row.id }}" {{ 'selected' if typed.account_id == row.id|string }}>{{ row.login }}</option>
    {%- endfor %}
  </select>
  {%- if narrowed %}
  <p class="help">Only people with no mailbox in that domain are offered: the model allows exactly
  one per person per domain.</p>
  {%- endif %}
  {%- if fault == 'account_id' %}<p class="help warn">{{ refusal }}</p>{% endif %}</div>
</div></section>
<div class="form-foot"><button class="btn btn-primary" type="submit">Give the mailbox</button>\
<a class="btn" href="{{ url_for('mailboxes') }}">Cancel, nothing changes</a></div>
</form>
"""

CARD_PAGE = SHAPE + """
{%- set heading %}<code>{{ box.address }}</code>{% endset %}
{%- set lede %}<a href="{{ url_for('account', account_id=box.account_id) }}"><code>{{ box.login }}</code></a>
holds it; their password and their state are set on their own page.
{% if box.account_state == 'blocked' %}Closed &mdash; the person is blocked, mail still
arrives.{% else %}Open.{% endif %}
{{ box.total }} message(s) held. Connected at {{ box.as_of }}.{% endset %}
{%- set actions %}<a class="btn" href="{{ url_for('top_up', mailbox_id=box.id) }}">Top up</a> \
<a class="btn" href="{{ url_for('events', target=box.address, back='mailboxes') }}">Journal for this mailbox</a>{% endset %}
{%- set crumbs %}<a href="{{ url_for('mailboxes') }}">Mailboxes</a> / <code>{{ box.address }}</code>{% endset %}
{%- if box.reading.waiting or box.reading.failed %}
{{ pipeline_flash(box.reading) }}
{%- endif %}
<div class="stack">
{%- set title %}Comment on <code>{{ box.login }}</code>{% endset %}
{%- set note %}<div class="field"><textarea name="comment" rows="3" aria-label="Comment">\
{{ box.comment or '' }}</textarea></div>{% endset %}
{%- set deliver_about %}The one act that puts back a message the person deleted on purpose. The
<a href="{{ url_for('archive_listing', domain_id=box.domain_id) }}">archive listing</a>
shows the ids. <a href="{{ url_for('top_up', mailbox_id=box.id) }}">Top up over a range
instead</a>.{% endset %}
{%- set deliver %}
{{- refused(refusal if form == 'deliver') }}
{{ field('Message id', 'message_id', typed.message_id, class_='mono-input short',
         warn=refusal if form == 'deliver') }}
{%- endset %}
{%- set transfer_about %}This hands over every message <code>{{ box.login }}</code> holds in
<code>{{ box.label }}</code>, including what they sent: {{ box.total }} message(s).
Nothing is copied, and any open session on this mailbox is closed first. The person keeps
their other domains.{% endset %}
{%- set transfer %}
{{- refused(refusal if form == 'transfer') }}
<div class="field"><label for="to_account_id">To</label>
  <select id="to_account_id" name="to_account_id" class="mid">
    <option value="">&mdash;</option>
    {%- for row in free %}
    <option value="{{ row.id }}">{{ row.login }}</option>
    {%- endfor %}
  </select>
  {%- if form == 'transfer' and refusal %}<p class="help warn">{{ refusal }}</p>{% endif %}</div>
{%- endset %}
<section class="box"><div class="box-body settings">
{{ setting(url_for('account_comment', account_id=box.account_id), title,
           "The person's own note, shown wherever they are. Not journaled.", note,
           'Save comment') }}
{{ setting(url_for('deliver_one_message', mailbox_id=box.id), 'Deliver one message by id',
           deliver_about, deliver, 'Deliver it') }}
{%- if free %}
{{ setting(url_for('transfer_mailbox', mailbox_id=box.id), 'Transfer to another person',
           transfer_about, transfer, 'Transfer it') }}
{%- else %}
{%- set nobody %}{{ refused(refusal if form == 'transfer') }}<p>Nobody is free to take it: everybody with an
account already has a mailbox in <code>{{ box.label }}</code>.</p>{% endset %}
{{ setting(none, 'Transfer to another person', transfer_about, nobody, none) }}
{%- endif %}
</div></section>

{%- set sentence %}Removing this mailbox takes {{ box.total }} name(s) out of it. The archive keeps
every message.{% endset %}
{%- set control %}<a class="btn btn-danger" href="{{ url_for('delete_mailbox', mailbox_id=box.id) }}">\
Remove this mailbox&hellip;</a>{% endset %}
{{ danger_zone(sentence, none, control) }}
</div>
"""

ARCHIVE_CARD_HINT = """
<h2>The archive</h2>
<p>Not a person: it cannot be removed, transferred or topped up.</p>
"""

DELETE_PAGE = """
{%- set heading %}Remove <code>{{ box.address }}</code>?{% endset %}
{%- set lede %}The archive of <code>{{ box.label }}</code> keeps every message. What goes is this
person's copy of them.{% endset %}
{%- set crumbs %}<a href="{{ url_for('mailboxes') }}">Mailboxes</a> / \
<a href="{{ url_for('mailbox', mailbox_id=box.id) }}"><code>{{ box.address }}</code></a> / Remove{% endset %}
<div class="stack narrow">
<section class="danger-zone">
<div class="box-head"><h2>What goes</h2></div>
<div class="box-body">
<div class="kv"><div><b>{{ numbers.names }}</b><span>Names removed</span></div>\
<div><b>1</b><span>Mailboxes removed</span></div>\
<div><b>1</b><span>People who lose access here</span></div></div>
<p>Messages removed: 0 &mdash; the archive keeps everything.</p>
<p class="muted">It is recoverable by giving the mailbox again and topping up, but the folders this
person arranged do not come back.</p>
<form class="form-foot" method="post" action="{{ url_for('delete_mailbox', mailbox_id=box.id) }}">\
<button class="btn btn-danger-solid" type="submit">Remove <code>{{ box.address }}</code></button></form>
</div>
</section>
<p><a href="{{ url_for('mailbox', mailbox_id=box.id) }}">""" + common.BACK + """ Cancel, nothing changes</a></p>
</div>
"""


# --- readers -------------------------------------------------------------------------------------

def person_box(row, period=None):
    """One person's mailbox in the shape every table renders."""
    return {"kind": "person", "id": row["id"], "address": f"{row['login']}@{row['label']}",
            "login": row["login"], "account_id": row["account_id"],
            "account_state": row["account_state"], "comment": row["comment"],
            "domain_id": row["domain_id"], "label": row["label"], "as_of": row["as_of"],
            "total": row["total"], "reading": common.reading_of(row, period)}


def archive_box(row, period=None):
    """A domain's archive in the same shape, built from the domain."""
    return {"kind": "archive", "id": None, "address": f"{ARCHIVE}@{row['label']}",
            "login": None, "account_id": None, "account_state": None, "comment": None,
            "domain_id": row["domain_id"], "label": row["label"], "as_of": None,
            "total": row["total"], "reading": common.reading_of(row, period)}


def listing(conn, domain_id=None, period=None):
    """Every archive row and every person's mailbox, each archive first in its domain."""
    where = " WHERE d.id = %s" if domain_id else ""
    parameters = (domain_id,) if domain_id else ()
    archives = [archive_box(row, period)
                for row in common.rows(conn, ARCHIVES + where + " ORDER BY d.label",
                                       parameters)]
    boxes = [person_box(row, period)
             for row in common.rows(conn, BOXES + where + " ORDER BY d.label, a.login",
                                    parameters)]
    ordered = []
    for archive in archives:
        ordered.append(archive)
        ordered += [box for box in boxes if box["domain_id"] == archive["domain_id"]]
    return ordered


def of_account(conn, account_id, period=None):
    """One person's mailboxes, in the shared shape, for the person page."""
    return [person_box(row, period) for row in
            common.rows(conn, BOXES + " WHERE a.id = %s ORDER BY d.label", (account_id,))]


def box_row(conn, mailbox_id, period=None):
    row = common.one(conn, BOXES + " WHERE m.id = %s", (mailbox_id,))
    return person_box(row, period) if row else None


def needed(conn, mailbox_id, period=None):
    box = box_row(conn, mailbox_id, period)
    if box is None:
        abort(404)
    return box


def free_people(conn, domain_id, without=None):
    """People with no mailbox in that domain - the only ones a transfer may reach."""
    rows = common.rows(conn, FREE_PEOPLE, (domain_id,))
    return [row for row in rows if row["id"] != without]


def card(conn, box, status=200, form=None, refusal=None, typed=None):
    return app.render(box["address"], CARD_PAGE, section="mailboxes", status=status,
                      box=box, columns=(), form=form, refusal=refusal,
                      typed=typed or {"message_id": ""},
                      free=free_people(conn, box["domain_id"], without=box["account_id"]))


# --- the screens ----------------------------------------------------------------------------------

def register(app_):
    @app_.get("/mailboxes")
    def mailboxes():
        conn = app.connection()
        period = common.timer_period()
        domain_id = common.as_int(request.args.get("domain"))  # a bad filter is no filter
        return app.render("Mailboxes", LIST_PAGE, section="mailboxes",
                          columns=("person", "domain"),
                          boxes=listing(conn, domain_id, period))

    @app_.route("/mailboxes/add", methods=["GET", "POST"])
    def add_mailbox():
        """a person in a domain, one per person per domain."""
        conn = app.connection()
        if request.method == "GET":
            typed = {"domain_id": request.args.get("domain", ""),
                     "account_id": request.args.get("account", "")}
            return add_page(conn, typed)
        typed = {"domain_id": request.form.get("domain_id", ""),
                 "account_id": request.form.get("account_id", "")}
        # ⚠️ EACH HALF IS PARSED SEPARATELY, so the half that parsed comes back chosen
        # and only the half at fault is empty
        if not typed["domain_id"].strip() or not typed["account_id"].strip():
            return add_page(conn, typed, BOTH, None)
        try:
            domain_id = common.want_int(typed["domain_id"], "domain")
            account_id = common.want_int(typed["account_id"], "person")
        except validate.Refused:
            return add_page(conn, typed, BOTH, None)

        found = common.one(conn, "SELECT label FROM domain WHERE id = %s", (domain_id,))
        if found is None:
            return add_page(conn, typed, NO_DOMAIN, "domain_id")
        person = common.one(conn, "SELECT login FROM account WHERE id = %s", (account_id,))
        if person is None:
            return add_page(conn, typed, NO_PERSON, "account_id")
        if common.one(conn, "SELECT 1 AS yes FROM mailbox WHERE account_id = %s AND "
                            "domain_id = %s", (account_id, domain_id)):
            return add_page(conn, typed, OCCUPIED, "account_id")

        login = f"{person['login']}@{found['label']}"
        try:
            with common.unique_violation(conn, OCCUPIED), conn.cursor() as cursor:
                cursor.execute("INSERT INTO mailbox (account_id, domain_id) "
                               "VALUES (%s, %s) RETURNING id", (account_id, domain_id))
                mailbox_id = cursor.fetchone()[0]
        except validate.Refused as refused:
            return add_page(conn, typed, str(refused), "account_id")

        # ⛔ TWO UNITS OF WORK, SO TWO ROWS: the maildir, and then what
        # the archive already holds. A mailbox whose connect was never queued delivers
        # nothing and looks healthy.
        made = common.ask(conn, "create_mailbox", login, {"mailbox_id": mailbox_id},
                          g.identity)
        common.ask(conn, "connect", login, {"mailbox_id": mailbox_id}, g.identity)
        record(conn, "create_mailbox", login, {"domain": found["label"],
                                                       "login": person["login"]},
                       request_id=made)
        return common.acted("mailboxes", "mailbox_given")

    @app_.get("/mailboxes/<int:mailbox_id>")
    def mailbox(mailbox_id):
        conn = app.connection()
        return card(conn, needed(conn, mailbox_id, common.timer_period()))

    @app_.post("/mailboxes/<int:mailbox_id>/transfer")
    def transfer_mailbox(mailbox_id):
        """the owner changes, nothing is copied, the slot must be empty."""
        conn = app.connection()
        box = needed(conn, mailbox_id, common.timer_period())
        chosen = request.form.get("to_account_id", "")
        if not chosen.strip():
            return card(conn, box, 400, "transfer", "Choose the person it goes to.")
        try:
            to_account_id = common.want_int(chosen, "person")
        except validate.Refused as refused:
            return card(conn, box, 400, "transfer", str(refused))
        person = common.one(conn, "SELECT login FROM account WHERE id = %s",
                            (to_account_id,))
        if person is None:
            return card(conn, box, 400, "transfer", NO_PERSON)
        if common.one(conn, "SELECT 1 AS yes FROM mailbox WHERE account_id = %s AND "
                            "domain_id = %s", (to_account_id, box["domain_id"])):
            return card(conn, box, 400, "transfer", OCCUPIED)

        # ⛔ the row is not moved here: the store and both index trees move with it, and
        # only the pipeline may touch them
        asked = common.ask(conn, "transfer", box["address"],
                           {"mailbox_id": mailbox_id, "to_account_id": to_account_id},
                           g.identity)
        # ⚠️ the recipient's LOGIN beside their row id: a row naming an id alone stops
        # being readable the day that account is deleted (settled)
        record(conn, "transfer", box["address"],
                       {"to_account_id": to_account_id, "to_login": person["login"]},
                       request_id=asked)
        return common.acted("mailboxes", "transfer_asked")

    @app_.route("/mailboxes/<int:mailbox_id>/delete", methods=["GET", "POST"])
    def delete_mailbox(mailbox_id):
        """the names go, the archive does not."""
        conn = app.connection()
        box = needed(conn, mailbox_id, common.timer_period())
        if request.method == "GET":
            return app.render(f"Remove {box['address']}?", DELETE_PAGE, section="mailboxes",
                              box=box,
                              numbers=common.one(conn, REMOVAL, (mailbox_id,)))
        asked = common.ask(conn, "delete_mailbox", box["address"],
                           {"mailbox_id": mailbox_id}, g.identity)
        record(conn, "delete_mailbox", box["address"], {"requested": True},
                       request_id=asked)
        return common.acted("mailboxes", "mailbox_removal_asked")


def add_page(conn, typed, refusal=None, fault=None):
    """The add form, with the people narrowed to the chosen domain's free ones."""
    domain_id = common.as_int(typed["domain_id"])
    known = domain_id is not None and common.one(
        conn, "SELECT 1 AS yes FROM domain WHERE id = %s", (domain_id,))
    people = (common.rows(conn, FREE_PEOPLE, (domain_id,)) if known
              else common.rows(conn, EVERYONE))
    return app.render("Give someone a mailbox", ADD_PAGE, section="mailboxes",
                      status=400 if refusal else 200, typed=typed,
                      domains=common.rows(conn, ALL_DOMAINS), people=people,
                      narrowed=bool(known), refusal=refusal, fault=fault)
