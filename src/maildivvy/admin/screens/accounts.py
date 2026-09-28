"""People: the list, one person, their password, their flag, their state, their removal.

A person is a login and a password, and the password opens every mailbox they hold.
Nobody sets their own, so everything about one person is on that
person's page and nowhere else - above all the password, which a mailbox card only links
to, because setting it from one mailbox would silently change access to all of them.

⛔ **THE LAST ACTIVE ADMINISTRATOR STAYS, AND NOBODY DELETES THEMSELVES**.
Revoking the flag, blocking and deleting each read the count of active administrators
**in the act's own transaction, with those rows locked**, so two administrators revoking
each other at the same moment cannot both succeed: the second waits, re-reads, and finds
itself the last one.

⛔ **WITH BOTH PASSWORD FIELDS EMPTY, CREATION AND RESET GENERATE ONE**. It is
shown once, on the answer to the POST, together with the client settings, and it is
nowhere else: not in a redirect, not in a log line, not in the journal, which records
only that a password was set. A reload cannot bring it back, and that is the cost of
holding no state.

⚠️ No act here asks for the password again. The deletion keeps its confirmation
page, which states what it removes as numbers.
"""

import json
from pathlib import Path

from flask import abort, current_app, g, request

from maildivvy.admin import app, auth, validate
from maildivvy.admin.screens import common, mailboxes
from maildivvy.lib import adminlock

record = common.record

CERTIFICATE = "certificate.json"     # the machine's own published name lives here
IMAP_PORT = 993                      # implicit TLS
SUBMISSION_PORT = 465

# the empty pair is no longer a refusal on these two
# forms, so the only password refusals left are a mismatch, a line break and the length.
PEOPLE = """
SELECT a.id, a.login, a.is_admin, a.state, a.comment, a.created_at,
       (SELECT count(*) FROM mailbox m WHERE m.account_id = a.id) AS mailboxes,
       (SELECT v.at FROM audit v WHERE v.action = 'set_account_state'
         AND v.target = a.login ORDER BY v.id DESC LIMIT 1) AS state_at,
       (SELECT v.actor FROM audit v WHERE v.action = 'set_account_state'
         AND v.target = a.login ORDER BY v.id DESC LIMIT 1) AS state_by,
       (SELECT v.at FROM audit v WHERE v.action = 'grant_admin'
         AND v.target = a.login ORDER BY v.id DESC LIMIT 1) AS admin_since,
       """ + common.newest_request("(r.payload ->> 'account_id')::bigint = a.id") + """
  FROM account a
"""

# What deleting one person removes, as numbers, before its button. The
# archives keep every message, so the message count is a stated zero rather than absent.
NUMBERS = """
SELECT (SELECT count(*) FROM mailbox WHERE account_id = %(id)s) AS mailboxes,
       (SELECT count(*) FROM delivery dl JOIN mailbox m ON m.id = dl.mailbox_id
         WHERE m.account_id = %(id)s) AS names
"""

# ⛔ Locked as they are counted, in the act's own transaction. An administrator
# with a deletion already QUEUED or RUNNING is not counted: the pipeline will
# delete them, so they cannot be the one who keeps the door open. Without this, revoking or
# blocking oneself while another administrator's deletion is pending leaves nobody.
LOCK_ADMINS = ("SELECT a.id FROM account a WHERE a.is_admin AND a.state = 'active' "
               "AND NOT EXISTS (SELECT 1 FROM request r WHERE r.kind = 'delete_account' "
               "AND r.state IN ('queued', 'running') "
               "AND (r.payload ->> 'account_id')::bigint = a.id) "
               "ORDER BY a.id FOR UPDATE")

GRANTS = ("May open this interface and do everything in it — including reading any "
          "domain's archive and granting this flag. The list of administrators is the "
          "whole of the access control; keep it short.")
NO_THIRD = ("A person is active or blocked, and {value!r} is neither. There is no third "
            "state: a mailbox is open exactly when its person is active.")
LAST_ADMIN = ("{login} is the last active administrator. {act} would leave nobody who can "
              "open this interface; give the flag to somebody else first. Break-glass is "
              "for the day the accounts table is unusable, not a way back in after this.")
NOT_YOURSELF = ("Nobody deletes their own account: another administrator does it. That "
                "keeps one pair of hands off the act that ends their own access.")


# --- what a person's page and the list read ---------------------------------------------------

SETTINGS = """
{%- macro client_settings(logins) -%}
<h3>What to put in the mail client</h3>
{%- if machine %}
<p>IMAP and submission are both <code>{{ machine }}</code>, ports
<code>{{ imap }}</code> and <code>{{ submission }}</code>, implicit TLS on both - not
STARTTLS.</p>
{%- else %}
<p>The machine's published name could not be read from
<code>{{ certificate }}</code>, so it is not stated here rather than guessed.</p>
{%- endif %}
<p>The login is <code>&lt;login&gt;@&lt;domain&gt;</code>: one per mailbox, and the same
password for every one of them.</p>
{%- if logins %}
<ul>{% for login in logins %}<li><code>{{ login }}</code></li>{% endfor %}</ul>
{%- else %}
<p>This person holds no mailbox yet, so there is no login to give them until one is.</p>
{%- endif %}
{%- endmacro -%}
"""

LIST_PAGE = """
<h1>People</h1>
<p>A person is active or blocked, and that reaches every mailbox they hold at once.
Nobody can set their own password: an administrator sets it here.</p>
<p><a class="primary" href="{{ url_for('add_account') }}">Add person</a></p>
<table>
<tr><th>Login</th><th>State</th><th>Mailboxes</th><th>Comment</th><th>Actions</th></tr>
{%- for row in people %}
<tr>
  <td><a href="{{ url_for('account', account_id=row.id) }}"><code>{{ row.login }}</code></a>
      {%- if row.is_admin %} <span class="badge">&#128274; administrator</span>{% endif %}</td>
  <td>
  {%- if reading[row.id].waiting %}{{ reading[row.id].waiting }}
      <div class="look-again">{{ reading[row.id].look_again }}</div>
  {%- else %}
    {%- if reading[row.id].failed %}<div class="field-refusal">the pipeline could not do
    it: {{ reading[row.id].failed }}</div>{% endif %}
    {%- if row.state == 'blocked' %}<span class="badge">blocked</span>
      {%- if row.state_at %} since {{ row.state_at }} by <code>{{ row.state_by }}</code>{% endif %}
    {%- else %}<span class="badge">active</span>{% endif %}
  {%- endif %}</td>
  <td>{{ row.mailboxes }}</td>
  <td>{{ row.comment or '' }}</td>
  <td>{% if reading[row.id].waiting %}waiting for the pipeline
      {%- else %}<a href="{{ url_for('account', account_id=row.id) }}">Open</a>
      &middot; <a href="{{ url_for('events', target=row.login, back='accounts') }}">Journal</a>{% endif %}</td>
</tr>
{%- else %}
<tr><td colspan="5">Nobody yet. A person with no mailbox opens nothing.</td></tr>
{%- endfor %}
</table>
"""

ADD_PAGE = """
<p class="crumbs"><a href="{{ url_for('accounts') }}">People</a> / Add person</p>
<h1>Add person</h1>
{%- if refusal and not field %}<p class="refusal">{{ refusal }}</p>{% endif %}
<form method="post" action="{{ url_for('add_account') }}">
  <label for="login">Login</label>
  <input id="login" name="login" value="{{ typed.login }}">
  <span>The part before the <code>@</code>, the same in every domain.</span>
  {%- if field == 'login' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="new-password">
  <label for="password2">Password again</label>
  <input id="password2" name="password2" type="password" autocomplete="new-password">
  <span>Leave both empty and one is generated and shown once, on the next page, with the
  settings for their mail client. At least {{ minimum }} characters if you type one;
  nothing else is required of it.</span>
  {%- if field == 'password' %}<span class="field-refusal">{{ refusal }}</span>{% endif %}
  <label><input type="checkbox" name="is_admin" value="yes" {{ 'checked' if typed.is_admin }}>
    Administrator</label>
  <span>{{ grants }}</span>
  <p><button type="submit">Add person</button>
     <a href="{{ url_for('accounts') }}">Cancel, nothing changes</a></p>
</form>
"""

SHOWN_ONCE = SETTINGS + """
<p class="crumbs"><a href="{{ url_for('accounts') }}">People</a> / <code>{{ login }}</code></p>
<h1>{{ headline }}</h1>
<p class="banner">This is the only time this password is shown. It is stored as a hash,
it is in no log and in no journal row, and a reload of this page will not bring it back.
If it is lost, set a new one on the person's page.</p>
<table>
<tr><th>Login</th><td><code>{{ login }}</code></td></tr>
<tr><th>Password</th><td><code class="generated">{{ password }}</code></td></tr>
</table>
{{ client_settings(logins) }}
<p><a href="{{ url_for('account', account_id=account_id) }}">Done &mdash; open
<code>{{ login }}</code></a></p>
"""

PERSON_PAGE = SETTINGS + mailboxes.SHAPE + """
<p class="crumbs"><a href="{{ url_for('accounts') }}">People</a> / <code>{{ row.login }}</code></p>
<h1><code>{{ row.login }}</code></h1>
<p><a href="{{ url_for('events', target=row.login, back='accounts') }}">Journal for this person</a></p>
<p>{% if row.is_admin %}Administrator{% if row.admin_since %} since {{ row.admin_since }}
{%- endif %}.{% else %}Not an administrator.{% endif %}
One password opens every mailbox below.</p>
{%- if reading.waiting %}
<p class="notice">{{ reading.waiting }}. {{ reading.look_again }}.</p>
{%- elif reading.failed %}
<p class="refusal">the pipeline could not do it: {{ reading.failed }}</p>
{%- endif %}

<h2>State</h2>
{%- if form == 'state' and refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
<p><span class="badge">{{ row.state }}</span>
{%- if row.state_at %} since {{ row.state_at }} by <code>{{ row.state_by }}</code>{% endif %}.
{% if row.state == 'blocked' %}Every mailbox they hold is closed and the login is refused;
mail still arrives for them. Unblocking opens them all again.
{%- else %}Blocking closes every mailbox they hold at once, while mail keeps arriving.
{%- endif %}</p>
{%- if mine %}
<p class="notice">This is your own account. Blocking it ends this session at your next
request.</p>
{%- endif %}
<form method="post" action="{{ url_for('account_state', account_id=row.id) }}">
  <input type="hidden" name="state" value="{{ 'active' if row.state == 'blocked' else 'blocked' }}">
  <p><button type="submit">{{ 'Unblock' if row.state == 'blocked' else 'Block' }}
  <code>{{ row.login }}</code></button></p>
</form>

<h2>Mailboxes</h2>
<table>
{{ mailbox_head(()) }}
{%- for box in boxes %}
{{ mailbox_row(box, ()) }}
{%- else %}
<tr><td colspan="4">No mailbox yet, so this login opens nothing.</td></tr>
{%- endfor %}
</table>
<p><a href="{{ url_for('add_mailbox', account=row.id) }}">Give a mailbox in another domain</a></p>

<h2>Password</h2>
{%- if password_saved %}<p class="notice done">{{ password_saved }}</p>{% endif %}
{%- if form == 'password' and refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
<p>It opens every mailbox above, and this interface too for an administrator. Leave both
fields empty and one is generated and shown once.</p>
<form method="post" action="{{ url_for('account_password', account_id=row.id) }}">
  <label for="password">New password</label>
  <input id="password" name="password" type="password" autocomplete="new-password">
  <label for="password2">New password again</label>
  <input id="password2" name="password2" type="password" autocomplete="new-password">
  <p><button type="submit" class="primary">Set the password</button></p>
</form>

<h2>Administrator</h2>
{%- if form == 'admin' and refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
<form method="post" action="{{ url_for('account_admin', account_id=row.id) }}">
  <label><input type="checkbox" name="is_admin" value="yes" {{ 'checked' if row.is_admin }}>
    Administrator</label>
  <span>{{ grants }}</span>
  {%- if mine and row.is_admin %}
  <span>Taking it off your own account leaves another administrator, or break-glass, as
  the way back in.</span>
  {%- endif %}
  <p><button type="submit">Save the flag</button></p>
</form>

<h2>Comment</h2>
<p>A free note about this person, shown on their mailbox cards too. Not journaled.</p>
<form method="post" action="{{ url_for('account_comment', account_id=row.id) }}">
  <textarea name="comment" rows="3" cols="60">{{ row.comment or '' }}</textarea>
  <p><button type="submit">Save comment</button></p>
</form>

{{ client_settings(logins) }}

<div class="danger">
<h2>Danger zone</h2>
<p>Deleting <code>{{ row.login }}</code> removes every mailbox and every name they hold,
immediately. There is no grace period and no disabled-but-present state.</p>
{%- if form == 'delete' and refusal %}<p class="refusal">{{ refusal }}</p>{% endif %}
<p><a href="{{ url_for('delete_account', account_id=row.id) }}">Delete this person, immediately&hellip;</a></p>
</div>
"""

DELETE_PAGE = """
<h1>Delete <code>{{ row.login }}</code>?</h1>
{%- if refusal %}
<p class="refusal">{{ refusal }}</p>
<p><button type="button" disabled>Delete <code>{{ row.login }}</code></button></p>
{%- else %}
<table>
<tr><th>Mailboxes removed</th><td>{{ numbers.mailboxes }}</td></tr>
<tr><th>Names removed</th><td>{{ numbers.names }}</td></tr>
<tr><th>Messages removed</th><td>0 &mdash; the archives keep everything</td></tr>
</table>
<p>It is recoverable by making the person again and topping them up, but the folders they
arranged and what they had read do not come back.</p>
<form method="post" action="{{ url_for('delete_account', account_id=row.id) }}">
  <p><button type="submit" class="danger">Delete <code>{{ row.login }}</code> and
  everything they hold</button></p>
</form>
{%- endif %}
<p><a href="{{ url_for('account', account_id=row.id) }}">Cancel, nothing changes</a></p>
"""


# --- readers -------------------------------------------------------------------------------------

def machine_name(etc=None):
    """The machine's published name, for the client settings; None when unreadable.

    ⚠️ Read from `certificate.json`, which the installation writes, rather than spelt
    here: a name in the code would be right until somebody published another one.
    """
    root = etc or current_app.config["MAILDIVVY_ETC"]
    try:
        return json.loads((Path(root) / CERTIFICATE).read_text())["cert_name"]
    except (OSError, ValueError, KeyError):
        return None


def account_row(conn, account_id):
    return common.one(conn, PEOPLE + " WHERE a.id = %s", (account_id,))


def needed(conn, account_id):
    row = account_row(conn, account_id)
    if row is None:
        abort(404)
    return row


def logins_of(boxes):
    return [box["address"] for box in boxes]


def would_leave_no_administrator(conn, account_id):
    """True when this act would leave no active administrator at all.

    ⛔ The last-administrator lock first: the pipeline takes the same one when
    it performs a deletion, so an act here and a deletion there never count at once.
    """
    with conn.cursor() as cursor:
        adminlock.lock(cursor)
        cursor.execute(LOCK_ADMINS)
        holders = [row[0] for row in cursor.fetchall()]
    return not [holder for holder in holders if holder != account_id]


def person_page(conn, row, status=200, form=None, refusal=None):
    period = common.timer_period()
    boxes = mailboxes.of_account(conn, row["id"], period)
    key = request.args.get("done")
    in_row = common.done_sentence(key) if key == "password_set" else None
    return app.render(row["login"], PERSON_PAGE, section="accounts", status=status,
                      done=None if in_row else app.TOP, row=row, columns=(), boxes=boxes,
                      logins=logins_of(boxes), machine=machine_name(),
                      certificate=CERTIFICATE, imap=IMAP_PORT,
                      submission=SUBMISSION_PORT, grants=GRANTS,
                      mine=(g.identity.account_id == row["id"]),
                      reading=common.reading_of(row, period),
                      password_saved=in_row, form=form, refusal=refusal)


def shown_once(conn, row, password, headline):
    """The one page in the product that shows a secret, and it is a POST's answer."""
    boxes = mailboxes.of_account(conn, row["id"])
    response = app.render(row["login"], SHOWN_ONCE, section="accounts",
                          account_id=row["id"], login=row["login"], password=password,
                          headline=headline, logins=logins_of(boxes),
                          machine=machine_name(), certificate=CERTIFICATE,
                          imap=IMAP_PORT, submission=SUBMISSION_PORT)
    # not cacheable: a shared machine's browser must not hand it back from its store
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


def password_from(form):
    """The password to store and whether it was generated.

    Both fields empty generates one; anything else goes through the ordinary rule, so
    one field filled and the other empty is still a mismatch.
    """
    first, second = form.get("password") or "", form.get("password2") or ""
    if not first and not second:
        return auth.generate_password(), True
    return validate.password_twice(first, second), False


# --- the screens ----------------------------------------------------------------------------------

def register(app_):
    @app_.get("/people")
    def accounts():
        conn = app.connection()
        period = common.timer_period()
        people = common.rows(conn, PEOPLE + " ORDER BY a.login")
        return app.render("People", LIST_PAGE, section="accounts", people=people,
                          reading={row["id"]: common.reading_of(row, period)
                                   for row in people})

    @app_.route("/people/add", methods=["GET", "POST"])
    def add_account():
        """a login, a password typed twice, and the flag that says what it
        grants. With both fields empty the password is generated and shown once."""
        conn = app.connection()
        typed = {"login": "", "is_admin": False}
        if request.method == "GET":
            return add_page(typed)
        typed = {"login": request.form.get("login", ""),
                 "is_admin": common.checked(request.form, "is_admin")}
        try:
            login = validate.login(typed["login"])
        except validate.Refused as refused:
            return add_page(typed, str(refused), "login")
        taken = f"There is already a person called {login}."
        if common.one(conn, "SELECT 1 AS yes FROM account WHERE login = %s", (login,)):
            return add_page(typed, taken, "login")
        try:
            # ⛔ hashed from what was typed, and the value is referenced nowhere after
            # this line; an empty pair is a generated password, never an empty hash
            password, generated = password_from(request.form)
        except validate.Refused as refused:
            return add_page(typed, str(refused), "password")

        try:
            with common.unique_violation(conn, taken), conn.cursor() as cursor:
                cursor.execute("INSERT INTO account (login, password_hash, is_admin) "
                               "VALUES (%s, %s, %s) RETURNING id",
                               (login, auth.make_hash(password), typed["is_admin"]))
                account_id = cursor.fetchone()[0]
        except validate.Refused as refused:
            return add_page(typed, str(refused), "login")
        # ⛔ never the value, in any form: what is recorded is that one was set
        record(conn, "create_account", login,
               {"is_admin": typed["is_admin"], "password_generated": generated})
        if not generated:
            return common.acted("accounts", "account_created")
        return shown_once(conn, account_row(conn, account_id), password,
                          f"{login} created")

    @app_.get("/people/<int:account_id>")
    def account(account_id):
        conn = app.connection()
        return person_page(conn, needed(conn, account_id))

    @app_.post("/people/<int:account_id>/password")
    def account_password(account_id):
        """the only password route a person has, and it opens every mailbox."""
        conn = app.connection()
        row = needed(conn, account_id)
        try:
            password, generated = password_from(request.form)
        except validate.Refused as refused:
            return person_page(conn, row, 400, "password", str(refused))
        with conn.cursor() as cursor:
            cursor.execute("UPDATE account SET password_hash = %s WHERE id = %s",
                           (auth.make_hash(password), account_id))
        record(conn, "set_password", row["login"],
               {"password_set": True, "password_generated": generated})
        if not generated:
            return common.acted("account", "password_set", account_id=account_id)
        return shown_once(conn, row, password, f"A new password for {row['login']}")

    @app_.post("/people/<int:account_id>/admin")
    def account_admin(account_id):
        """one checkbox. An unchanged one writes nothing."""
        conn = app.connection()
        row = needed(conn, account_id)
        wanted = common.checked(request.form, "is_admin")
        if wanted == row["is_admin"]:
            # ⛔ the predecessor wrote a grant or a revoke row either way, so the journal said
            # an act happened where nothing had
            return common.acted("account", "admin_same", account_id=account_id)
        if not wanted and would_leave_no_administrator(conn, account_id):
            return person_page(conn, row, 400, "admin",
                               LAST_ADMIN.format(login=row["login"],
                                                 act="Taking the flag off them"))
        with conn.cursor() as cursor:
            cursor.execute("UPDATE account SET is_admin = %s WHERE id = %s",
                           (wanted, account_id))
        record(conn, "grant_admin" if wanted else "revoke_admin", row["login"],
               {"is_admin": wanted})
        return common.acted("account", "admin_saved", account_id=account_id)

    @app_.post("/people/<int:account_id>/state")
    def account_state(account_id):
        """two states, on the person, reaching every mailbox at once."""
        conn = app.connection()
        row = needed(conn, account_id)
        wanted = request.form.get("state", "")
        if wanted not in ("active", "blocked"):
            return person_page(conn, row, 400, "state", NO_THIRD.format(value=wanted))
        if wanted == row["state"]:
            return common.acted("account", "state_set", account_id=account_id)
        if wanted == "blocked" and row["is_admin"] \
                and would_leave_no_administrator(conn, account_id):
            return person_page(conn, row, 400, "state",
                               LAST_ADMIN.format(login=row["login"], act="Blocking them"))
        with conn.cursor() as cursor:
            cursor.execute("UPDATE account SET state = %s WHERE id = %s",
                           (wanted, account_id))
        record(conn, "set_account_state", row["login"],
               {"before": row["state"], "after": wanted})
        return common.acted("account", "state_set", account_id=account_id)

    @app_.post("/people/<int:account_id>/comment")
    def account_comment(account_id):
        """a free note, saved from the person page or a mailbox card, and
        never journaled - it changes no state, and the journal records state."""
        conn = app.connection()
        needed(conn, account_id)
        with conn.cursor() as cursor:
            cursor.execute("UPDATE account SET comment = %s WHERE id = %s",
                           (request.form.get("comment") or None, account_id))
        return common.acted_at(common.origin("account", account_id=account_id),
                               "comment_saved")

    @app_.route("/people/<int:account_id>/delete", methods=["GET", "POST"])
    def delete_account(account_id):
        """immediate, with its numbers first, and never one's own."""
        conn = app.connection()
        row = needed(conn, account_id)
        refusal = None
        if g.identity.account_id == account_id:
            refusal = NOT_YOURSELF
        elif row["is_admin"] and would_leave_no_administrator(conn, account_id):
            refusal = LAST_ADMIN.format(login=row["login"], act="Deleting them")
        if request.method == "GET" or refusal:
            return app.render(f"Delete {row['login']}?", DELETE_PAGE, section="accounts",
                              status=400 if refusal else 200, row=row, refusal=refusal,
                              numbers=common.one(conn, NUMBERS, {"id": account_id}))
        asked = common.ask(conn, "delete_account", row["login"],
                           {"account_id": account_id}, g.identity)
        record(conn, "delete_account", row["login"], {"requested": True},
               request_id=asked)
        return common.acted("accounts", "account_deletion_asked")


def add_page(typed, refusal=None, field=None):
    return app.render("Add person", ADD_PAGE, section="accounts",
                      status=400 if refusal else 200, typed=typed, refusal=refusal,
                      field=field, grants=GRANTS, minimum=validate.PASSWORD_MIN)
