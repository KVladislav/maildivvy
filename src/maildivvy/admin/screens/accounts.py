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


# --- what a person's page and the list read (in the design's components) ----------

# ⚠️ A refusal is a flash inside the row or box it belongs to (`common.refused`) and,
# where one field is at fault, the same sentence in that field's `help warn` line.
SETTINGS = """
{%- macro client_settings(logins) -%}
<section class="box"><div class="box-head"><h2>What to put in the mail client</h2></div>
<div class="box-body">
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
</div></section>
{%- endmacro -%}
{%- macro administrator(checked, mine, warn=none) -%}
<div class="field"><label class="checkline"><input type="checkbox" name="is_admin" value="yes"
{{- ' checked' if checked }}><div><b>Administrator</b><span>{{ grants }}</span>
{%- if mine %}<span>Taking it off your own account leaves another administrator, or break-glass, as
the way back in.</span>{% endif %}</div></label>
{%- if warn %}<p class="help warn">{{ warn }}</p>{% endif %}</div>
{%- endmacro -%}
{%- macro way() -%}<a href="{{ url_for('accounts') }}">People</a>{%- endmacro -%}
"""

LIST_PAGE = """
{%- set heading %}People{% endset %}
{%- set lede %}A person is active or blocked, and that reaches every mailbox they hold at once.
Nobody can set their own password: an administrator sets it here.{% endset %}
{%- set actions %}<a class="btn btn-primary" href="{{ url_for('add_account') }}">Add person</a>{% endset %}
<section class="box"><div class="table-wrap"><table>
<thead><tr><th>Login</th><th>State</th><th class="num">Mailboxes</th><th>Comment</th>\
<th class="acts">Actions</th></tr></thead>
<tbody>
{%- for row in people %}
<tr>
  <td><a href="{{ url_for('account', account_id=row.id) }}"><code>{{ row.login }}</code></a>
      {%- if row.is_admin %} <span class="badge"><svg class="icon"><use href="#i-lock"/></svg> administrator</span>{% endif %}</td>
  <td class="state">
  {%- if reading[row.id].waiting %}{{ reading[row.id].waiting }}<span class="row-sub">{{ reading[row.id].look_again }}</span>
  {%- else %}
    {%- if row.state == 'blocked' %}<span class="badge attn">blocked</span>
      {%- if row.state_at %}<span class="row-sub">since {{ row.state_at }} by <code>{{ row.state_by }}</code></span>{% endif %}
    {%- else %}<span class="badge ok">active</span>{% endif %}
    {{- pipeline_failed(reading[row.id].failed) }}
  {%- endif %}</td>
  <td class="num">{{ row.mailboxes }}</td>
  <td>{{ row.comment or '' }}</td>
  <td class="acts">{% if reading[row.id].waiting %}<span class="muted">waiting for the pipeline</span>
      {%- else %}<a class="btn btn-sm" href="{{ url_for('account', account_id=row.id) }}">Open</a>
      <a class="btn btn-sm btn-link" href="{{ url_for('events', target=row.login, back='accounts') }}">Journal</a>{% endif %}</td>
</tr>
{%- else %}
<tr><td colspan="5">Nobody yet. A person with no mailbox opens nothing.</td></tr>
{%- endfor %}
</tbody>
</table></div></section>
"""

ADD_PAGE = SETTINGS + """
{%- set heading %}Add person{% endset %}
{%- set crumbs %}{{ way() }} / Add person{% endset %}
{%- set login_help %}The part before the <code>@</code>, the same in every domain.{% endset %}
{%- set password_help %}Leave both empty and one is generated and shown once, on the next page, with
the settings for their mail client. At least {{ minimum }} characters if you type one; nothing else
is required of it.{% endset %}
<form class="narrow" method="post" action="{{ url_for('add_account') }}">
{{ refused(refusal) }}
<section class="box"><div class="box-body">
{{ field('Login', 'login', typed.login, class_='mono-input mid', help=login_help,
         warn=refusal if fault == 'login') }}
{{ field('Password', 'password', type='password', class_='mid', autocomplete='new-password') }}
{{ field('Password again', 'password2', type='password', class_='mid',
         autocomplete='new-password', help=password_help,
         warn=refusal if fault == 'password') }}
{{ administrator(typed.is_admin, false) }}
</div></section>
<div class="form-foot"><button class="btn btn-primary" type="submit">Add person</button>\
<a class="btn" href="{{ url_for('accounts') }}">Cancel, nothing changes</a></div>
</form>
"""

SHOWN_ONCE = SETTINGS + """
{%- set heading %}{{ headline }}{% endset %}
{%- set crumbs %}{{ way() }} / <code>{{ login }}</code>{% endset %}
<div class="stack narrow">
{%- set once %}This is the only time this password is shown. It is stored as a hash,
it is in no log and in no journal row, and a reload of this page will not bring it back.
If it is lost, set a new one on the person's page.{% endset %}
{{ flash('attn', 'lock', once) }}
<section class="box"><div class="box-body"><dl class="facts">\
<dt>Login</dt><dd><code>{{ login }}</code></dd>\
<dt>Password</dt><dd><code class="generated">{{ password }}</code></dd>\
</dl></div></section>
{{ client_settings(logins) }}
<div class="form-foot"><a class="btn btn-primary" href="{{ url_for('account', account_id=account_id) }}">\
Done &mdash; open <code>{{ login }}</code></a></div>
</div>
"""

PERSON_PAGE = SETTINGS + mailboxes.SHAPE + """
{%- set heading %}<code>{{ row.login }}</code>{% endset %}
{%- set lede %}{% if row.is_admin %}Administrator{% if row.admin_since %} since {{ row.admin_since }}
{%- endif %}.{% else %}Not an administrator.{% endif %}
One password opens every mailbox below.{% endset %}
{%- set actions %}<a class="btn" href="{{ url_for('events', target=row.login, back='accounts') }}">\
Journal for this person</a>{% endset %}
{%- set crumbs %}{{ way() }} / <code>{{ row.login }}</code>{% endset %}
{%- if reading.waiting or reading.failed %}
{{ pipeline_flash(reading) }}
{%- endif %}
<div class="stack">
<section class="box">
<div class="box-head"><h2>State</h2></div>
<div class="box-body">
{{ refused(refusal if form == 'state') }}
<p>{% if row.state == 'blocked' %}<span class="badge attn">blocked</span>{% else %}<span class="badge ok">active</span>{% endif %}
{%- if row.state_at %} since {{ row.state_at }} by <code>{{ row.state_by }}</code>{% endif %}.
{% if row.state == 'blocked' %}Every mailbox they hold is closed and the login is refused;
mail still arrives for them. Unblocking opens them all again.
{%- else %}Blocking closes every mailbox they hold at once, while mail keeps arriving.
{%- endif %}</p>
<form class="form-foot" method="post" action="{{ url_for('account_state', account_id=row.id) }}">
<input type="hidden" name="state" value="{{ 'active' if row.state == 'blocked' else 'blocked' }}">
<button class="btn" type="submit">{{ 'Unblock' if row.state == 'blocked' else 'Block' }} <code>{{ row.login }}</code></button>
{%- if mine %}<span class="muted">This is your own account. Blocking it ends this session at your
next request.</span>{% endif %}</form>
</div>
</section>

<section class="box">
<div class="box-head"><h2>Mailboxes</h2><a class="btn btn-sm" \
href="{{ url_for('add_mailbox', account=row.id) }}">Give a mailbox in another domain</a></div>
<div class="table-wrap"><table>
{{ mailbox_head(()) }}
<tbody>
{%- for box in boxes %}
{{ mailbox_row(box, ()) }}
{%- else %}
<tr><td colspan="4">No mailbox yet, so this login opens nothing.</td></tr>
{%- endfor %}
</tbody>
</table></div>
</section>

{%- set about %}It opens every mailbox above, and this interface too for an administrator. Leave
both fields empty and one is generated and shown once.{% endset %}
{%- set fields %}
{{- flash('ok', 'check', password_saved) }}
{{- refused(refusal if form == 'password') }}
{{ field('New password', 'password', type='password', class_='mid', autocomplete='new-password') }}
{{ field('New password again', 'password2', type='password', class_='mid',
         autocomplete='new-password', warn=refusal if form == 'password') }}
{%- endset %}
{%- set flag %}
{{- refused(refusal if form == 'admin') }}
{{ administrator(row.is_admin, mine and row.is_admin, refusal if form == 'admin') }}
{%- endset %}
{%- set note %}<div class="field"><textarea name="comment" rows="3" aria-label="Comment">\
{{ row.comment or '' }}</textarea></div>{% endset %}
<section class="box"><div class="box-body settings">
{{ setting(url_for('account_password', account_id=row.id), 'Password', about, fields,
           'Set the password', primary=true) }}
{{ setting(url_for('account_admin', account_id=row.id), 'Administrator', none, flag,
           'Save the flag') }}
{{ setting(url_for('account_comment', account_id=row.id), 'Comment',
           'A free note about this person, shown on their mailbox cards too. Not journaled.',
           note, 'Save comment') }}
</div></section>

{{ client_settings(logins) }}

{{ refused(refusal if form == 'delete') }}
{%- set sentence %}Deleting <code>{{ row.login }}</code> removes every mailbox and every name they
hold, immediately. There is no grace period and no disabled-but-present state.{% endset %}
{%- set control %}<a class="btn btn-danger" href="{{ url_for('delete_account', account_id=row.id) }}">\
Delete this person, immediately&hellip;</a>{% endset %}
{{ danger_zone(sentence, none, control) }}
</div>
"""

DELETE_PAGE = SETTINGS + """
{%- set heading %}Delete <code>{{ row.login }}</code>?{% endset %}
{%- set crumbs %}{{ way() }} / <a href="{{ url_for('account', account_id=row.id) }}">\
<code>{{ row.login }}</code></a> / Delete{% endset %}
<div class="stack narrow">
{%- if refusal %}
{{ refused(refusal) }}
{%- else %}
<section class="danger-zone">
<div class="box-head"><h2>What goes</h2></div>
<div class="box-body">
<div class="kv"><div><b>{{ numbers.mailboxes }}</b><span>Mailboxes removed</span></div>\
<div><b>{{ numbers.names }}</b><span>Names removed</span></div></div>
<p>Messages removed: 0 &mdash; the archives keep everything.</p>
<p class="muted">It is recoverable by making the person again and topping them up, but the folders
they arranged and what they had read do not come back.</p>
<form class="form-foot" method="post" action="{{ url_for('delete_account', account_id=row.id) }}">\
<button class="btn btn-danger-solid" type="submit">Delete <code>{{ row.login }}</code> and
everything they hold</button></form>
</div>
</section>
{%- endif %}
<p><a href="{{ url_for('account', account_id=row.id) }}">""" + common.BACK + """ Cancel, nothing changes</a></p>
</div>
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


def add_page(typed, refusal=None, fault=None):
    # ⚠️ `fault`, not `field`: a template value of that name would hide the `field()` shape
    return app.render("Add person", ADD_PAGE, section="accounts",
                      status=400 if refusal else 200, typed=typed, refusal=refusal,
                      fault=fault, grants=GRANTS, minimum=validate.PASSWORD_MIN)
