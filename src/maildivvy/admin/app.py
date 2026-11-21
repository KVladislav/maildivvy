"""The application: one shell, sign-in, sign-out, and the guard in front of everything.

Flask is the distribution's. The application serves plain HTTP on a unix socket; the
reverse proxy in front of it holds the certificate and the TLS rules, so no
Python process here handles TLS and the application opens no TCP port.

**Every endpoint is guarded at startup**, once per endpoint rather than once per rule,
with a short allow-list of public ones: a screen added later cannot be
left open by forgetting to decorate it. The guard re-reads the account behind the
session on every request and for every method, so an act sent after a block has
committed is not run.

**No act asks for the password again**. Acts that destroy data keep their own
confirmation page, which states the consequences as numbers; those pages are
the screens' own, in a later task. Nothing here keeps a confirmation stamp.

**One connection per request**. The session's own bookkeeping commits
by itself; after that, the act and its journal row share one transaction and commit
together or not at all.
"""

import functools
import hmac
import logging
import re
import sys

import jinja2
from flask import Flask, current_app, g, redirect, render_template, request, url_for
from markupsafe import Markup
from werkzeug.exceptions import HTTPException
from werkzeug.routing import IntegerConverter, RequestRedirect

from maildivvy.admin import auth, journal, throttle, validate
from maildivvy.admin.screens import common
from maildivvy.admin.style import STYLESHEET
from maildivvy.lib import db
from maildivvy.lib.config import ETC, ConfigError

# The endpoints anybody may reach. Everything else is guarded.
PUBLIC = frozenset({"sign_in"})

# ⚠️ THE SIDEBAR IS THE WHOLE OF THE NAVIGATION, AND IT IS DECLARED ONCE.
# `(endpoint, title, which count, separator after it)`. The title of a link is the title
# of the screen it opens, and the link is built from the ROUTE'S NAME, never a path, so a
# route that moves takes its links with it. A section whose route does not exist yet is
# rendered as its title and no link - nothing here can produce a dead one.
SECTIONS = (
    ("overview", "Overview", None, True),
    ("external", "External mailboxes", "external", False),
    ("domains", "Domains", "domains", False),
    ("accounts", "People", "people", False),
    ("mailboxes", "Mailboxes", "mailboxes", True),
    ("fetch", "Fetch", None, False),
    ("withheld", "Withheld messages", "withheld", False),
    ("events", "Journal", None, True),
    # the machine rather than its mail: health's last report, read as a file
    ("health", "Health", None, False),
)

# ⛔ ONE QUERY PER RENDER for all five counts: one per link would be five
# round trips on every page of the interface. Mailboxes counts people's mailboxes PLUS
# one per domain, because every domain's archive appears as a mailbox row.
COUNTS = """
SELECT (SELECT count(*) FROM external_mailbox)                       AS external,
       (SELECT count(*) FROM domain)                                 AS domains,
       (SELECT count(*) FROM account)                                AS people,
       (SELECT count(*) FROM mailbox) + (SELECT count(*) FROM domain) AS mailboxes,
       (SELECT count(*) FROM message WHERE state = 'withheld')       AS withheld
"""

# A return path is a bare path: one leading `/`, no scheme, no host, no `//`, no
# backslash, no whitespace, no query.
BARE_PATH = re.compile(r"^/(?!/)[^\\\s?#]*$")

class BoundedIntegerConverter(IntegerConverter):
    """`<int:id>` that refuses a value past a bigint, so the route 404s rather than the
    query overflowing to a 500."""

    def __init__(self, map_, *args, **kwargs):
        kwargs.setdefault("max", common.BIGINT_MAX)
        super().__init__(map_, *args, **kwargs)


# ⛔ Cross-site request forgery defence. Every unsafe request is checked for a
# same-origin `Origin`/`Sec-Fetch-Site` and a per-session token; every response forbids
# framing. The token is written into every POST form (`CSRF_FIELD`) by the `csrf()` macro of
# `common.SHAPES`, which each form calls after its opening tag; a unit test sweeps every
# template for a POST form that does not, so a form added later carries it too.
POLICY = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
          "frame-ancestors 'none'; base-uri 'none'")
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CSRF_FIELD = "_csrf"
# the sign-in POST has no session yet, so it carries no per-session token; the Origin
# check still guards it, and a login CSRF mints only the attacker's own session
CSRF_EXEMPT = frozenset({"sign_in"})

# The seven icons the design draws with, declared once per page and drawn by `<use>`: an
# icon always stands beside its word, never in its place.
ICONS = """<svg class="sprite" width="0" height="0" aria-hidden="true">
  <symbol id="i-alert" viewBox="0 0 16 16"><path d="M8 2.2 14.3 13H1.7L8 2.2Z"/><path d="M8 6.5v3M8 11.6v.2"/></symbol>
  <symbol id="i-check" viewBox="0 0 16 16"><path d="M3 8.5l3.2 3L13 4.5"/></symbol>
  <symbol id="i-x" viewBox="0 0 16 16"><path d="M4 4l8 8M12 4l-8 8"/></symbol>
  <symbol id="i-info" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.3"/><path d="M8 7.2v4M8 5v.2"/></symbol>
  <symbol id="i-lock" viewBox="0 0 16 16"><rect x="3.5" y="7" width="9" height="7" rx="1.2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></symbol>
  <symbol id="i-clock" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.3"/><path d="M8 4.5V8l2.3 1.5"/></symbol>
  <symbol id="i-back" viewBox="0 0 16 16"><path d="M9.5 3.5 5 8l4.5 4.5"/></symbol>
</svg>"""

# ⚠️ Two shapes of page. Signed in, the shell: the top bar, the sidebar, and
# `main` with the crumbs, the page head (its one `h1`, the lede, its actions - at most one
# of them the primary), the flashes, then the screen's body. Signed out, the card on the
# grey ground and nothing else.
#
# Every page extends it: the screen's template fills `body`, and its own top-level
# `{% set heading %}`, `lede`, `actions` and `crumbs` blocks are the page head the shell
# places. What the shell alone reads comes as `shell` (its title, the stylesheet, the icons,
# the sidebar, the `?done=` sentence and the header's health), so no screen's value of the
# same name can stand in for it.
SHELL = """{% from "common.SHAPES" import csrf, flash %}<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ shell.title }} - Maildivvy</title><style>{{ shell.style }}</style></head>
{%- if identity %}
<body>
{{ shell.icons }}
<header class="topbar">
  <a class="brand" href="{{ url_for('overview') }}">Maildivvy</a>
  <div class="session">
    {%- if shell.health %}
    <a class="health badge {{ shell.health.voice }}" href="{{ shell.health.url }}">Health: {{ shell.health.words }}{% if shell.health.detail %} &middot; {{ shell.health.detail }}{% endif %}</a>
    {%- endif %}
    <span>Signed in as {{ identity.login }}</span>
    <form method="post" action="{{ url_for('sign_out') }}">{{ csrf() }}<button class="btn btn-sm" type="submit">Sign out {{ identity.login }}</button></form>
  </div>
</header>
<div class="shell"><nav class="nav" aria-label="Sections">
<ul>
{%- for item in shell.nav or () %}
  <li>
    {%- set count %}{% if item.count is not none %} <span class="n">{{ item.count }}</span>{% endif %}{% endset %}
    {%- if item.url %}<a href="{{ item.url }}"{% if item.current %} aria-current="page"{% endif %}>{{ item.title }}{{ count }}</a>
    {%- else %}<span>{{ item.title }}{{ count }}</span>{% endif -%}
  </li>
  {%- if item.separator %}<li class="sep"></li>{% endif %}
{%- endfor %}
</ul>
</nav>
<main>
{%- if crumbs %}<div class="crumbs">{{ crumbs }}</div>{% endif %}
<div class="page-head"><div><h1>{{ heading }}</h1>{% if lede %}<p class="lede">{{ lede }}</p>{% endif %}</div>
{%- if actions %}<div class="actions">{{ actions }}</div>{% endif %}</div>
{%- if identity.break_glass %}
{{ flash('attn', 'alert', 'Signed in with the break-glass account. Its use is recorded in the
journal, and its password is rotated afterwards. Every act in this session is marked.') }}
{%- endif %}
{%- if shell.done %}
{{ flash('ok', 'check', shell.done) }}
{%- endif %}
{% block body %}{% endblock %}
</main>
</div>
</body>
{%- else %}
<body><div class="bare-wrap"><section class="card">
{{ self.body() }}
</section></div>
{{ shell.icons }}
</body>
{%- endif %}
</html>
"""

LOGIN = """{% extends "app.SHELL" %}{% from "common.SHAPES" import csrf, flash %}{% block body %}
<h1>Maildivvy</h1>
{%- if message %}
{{ flash(tone, 'x' if tone == 'bad' else 'info', message) }}
{%- endif %}
<form method="post" action="{{ url_for('sign_in') }}">{{ csrf() }}
  <div class="field"><label for="login">Login</label>
  <input id="login" name="login" type="text" class="mono-input" autocomplete="username" autofocus></div>
  <div class="field"><label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password"></div>
  {%- if next_path %}<input type="hidden" name="next" value="{{ next_path }}">{% endif %}
  <button class="btn btn-primary" type="submit">Sign in</button>
</form>
<p class="foot">A session ends after 15 minutes without a request, and 8 hours after it began.</p>{% endblock %}"""

# the not-found page: its page head alone
NOT_FOUND = """{% extends "app.SHELL" %}{% set heading %}Not found{% endset %}
{%- set lede %}There is nothing at this address. A removed route answers this too, because its
rule is gone from the map rather than left behind refusing methods.{% endset %}"""


# --- the request's connection ----------------------------------------------

# ⛔ A REQUEST WAITS ON THE DATABASE FOR A BOUNDED TIME. The interface serves
# from ten threads: a page whose query runs long, or waits on a lock the pipeline holds
# through a whole act, would hold a thread past the proxy's own timeout, and ten of them
# would keep everyone from signing in. The bounds are the interface's connections' alone,
# sent when each one starts: the pipeline's long transactions share the database and must
# not be cut short by them.
TIMEOUTS = {"statement_timeout": "10s", "lock_timeout": "3s"}


def connection():
    if "conn" not in g:
        g.conn = db.connect(current_app.config["MAILDIVVY_CONSUMER"],
                            etc=current_app.config["MAILDIVVY_ETC"], settings=TIMEOUTS)
    return g.conn


def secret():
    return current_app.config["MAILDIVVY_SECRET"]


def sign_in_throttle():
    """The one sign-in throttle for this process."""
    store = current_app.config.get("MAILDIVVY_THROTTLE")
    if store is None:
        store = throttle.Throttle()
        current_app.config["MAILDIVVY_THROTTLE"] = store
    return store


# --- pages ---------------------------------------------------------------------------------

def header_health():
    """The header's health status, or None where no Health screen is served.

    It is the Health screen's own reading of the report, read once per request, so the
    header and the screen cannot say two things; it costs one read of a small file.
    """
    if "health" not in current_app.view_functions:
        return None
    # imported here, not at the top: the screen module imports this one for the shell
    from maildivvy.admin.screens import health

    said = health.status()
    return {**said, "voice": health.voice_of(said["tone"]), "url": url_for("health")}


def page(title, template, identity=None, status=200, nav=None, done=None):
    """A whole page: `template` is the name of a screen's template, which extends the
    shell (`SHELL`) and is rendered once with the screen's values.

    The page head's parts are the template's own top-level `{% set heading %}`, `lede`,
    `actions` and `crumbs` blocks, so they are rendered with the screen's values and its
    macros, and the shell places them.
    """
    # ⛔ only a signed-in page has the shell's header, so only it reads the report; the
    # sign-in page has no shell and says nothing about the machine
    shell = {"title": title, "style": Markup(STYLESHEET), "icons": Markup(ICONS),
             "nav": nav, "done": done,
             "health": header_health() if identity else None}
    values = {"identity": identity, **g.get("render", {}), "shell": shell}
    return current_app.response_class(render_template(template, **values), status=status,
                                      mimetype="text/html")


# --- a database error: its code in the log, never its text -----------------------

# A form refused by a CHECK the screen's own validation did not foresee.
NOT_SAVED = """{% extends "app.SHELL" %}{% from "common.SHAPES" import refused %}
{%- set heading %}Not saved{% endset %}{% block body %}
{{ refused(sentence) }}{% endblock %}"""
CHECK_REFUSED = ("The database refused a value this form sent, so nothing was saved. Go "
                 "back, and look for a character or a number the field does not take.")
CHECK_VIOLATION = "23514"
# A statement past `statement_timeout`, and a lock not granted within `lock_timeout`:
# the database is busy, and the request answers so rather than a fault.
BUSY_CODES = frozenset({"57014", "55P03"})
BUSY = ("The database is busy, so this page could not be read or this act was not done. "
        "Nothing was saved. Try again in a minute.")
BUSY_PAGE = """{% extends "app.SHELL" %}{% from "common.SHAPES" import flash %}
{%- set heading %}The database is busy{% endset %}{% block body %}
{{ flash('attn', 'clock', sentence) }}{% endblock %}"""
BUSY_BARE = "<h1>The database is busy</h1><p>{{ message }}</p>"


def database_error(error):
    """The driver's error in `error`'s chain of causes, or None.

    A traceback prints every exception the chain holds, so an error raised while one of
    the driver's was being handled would still carry its text into the log.
    """
    # imported here, as `common.unique_violation` imports it: the unit suite runs where
    # the machine's driver is not installed
    try:
        import psycopg2
    except ImportError:
        return None
    seen = set()
    while error is not None and id(error) not in seen:
        if isinstance(error, psycopg2.Error):
            return error
        seen.add(id(error))
        error = error.__cause__ or error.__context__
    return None


class DatabaseErrorsByCode(logging.Filter):
    """Every record of the application's logger that carries a database error is
    rewritten to its SQLSTATE and its constraint's name, with no traceback.

    ⛔ PostgreSQL's message and DETAIL quote the values a statement carried ("Failing
    row contains ..."), and a form's statement may carry a password. Flask logs an
    unhandled error on this logger in two places (`log_exception`, and a hook that fails
    while the error page is made), each with the traceback; a filter on the logger is
    the one place both pass. Any other record passes as it was.
    """

    def filter(self, record):
        found = database_error(record.exc_info[1]) if record.exc_info else None
        if found is None:
            return True
        diag = getattr(found, "diag", None)
        said = record.getMessage()
        record.msg = ("%s: database error, SQLSTATE %s, constraint %s; its text is not "
                      "logged, because it may quote a value a form sent")
        record.args = (said, getattr(found, "pgcode", None),
                       getattr(diag, "constraint_name", None))
        record.exc_info = record.exc_text = None
        record.stack_info = None
        return True


def section_of(path):
    """The sidebar's section a path is under (`/external/9/settings` is `external`), or
    None."""
    first = path.strip("/").split("/", 1)[0]
    for endpoint, *_ in SECTIONS:
        if (first and endpoint in current_app.view_functions
                and url_for(endpoint).strip("/").split("/", 1)[0] == first):
            return endpoint
    return None


def server_error(error):
    """The 500 page, except where a form was refused by a CHECK: that is its refusal.

    Flask has logged the error already, by its code alone. A CHECK a form's values
    broke is a refusal the screen's own validation should have made first; nothing was
    written (the request rolls back at 400), and the page says so in a sentence.
    """
    found = database_error(getattr(error, "original_exception", None))
    if found is not None and getattr(found, "pgcode", None) in BUSY_CODES:
        return busy()
    if (found is None or getattr(found, "pgcode", None) != CHECK_VIOLATION
            or request.method not in UNSAFE_METHODS or "identity" not in g):
        return error
    conn = g.get("conn")
    try:
        if conn is not None:
            conn.rollback()          # the failed statement left the transaction aborted
        return render("Not saved", "app.NOT_SAVED", section=section_of(request.path), status=400,
                      sentence=CHECK_REFUSED)
    except Exception:                # noqa: BLE001 - the page must not raise past here
        # ⚠️ a second error raised in here would be printed by the server with the
        # first one as its context, text and all; this answer reads nothing
        return refusal_response(CHECK_REFUSED, 400)


def busy():
    """503 with a sentence, for a statement or a lock wait the bounds cut short.

    Nothing was written: the request rolls back. A signed-in person sees it in the shell;
    a request that stopped before the guard knew who it was (the guard reads the session
    over the same connection) gets the bare sentence, since the shell names the person.
    """
    conn = g.get("conn")
    try:
        if conn is not None:
            conn.rollback()          # the cancelled statement left the transaction aborted
        if "identity" in g:
            # the sidebar without its counts: they are queries, and the database is busy
            g.render = {"sentence": BUSY}
            return page("The database is busy", "app.BUSY_PAGE", identity=g.identity,
                        status=503, nav=navigation(None, section_of(request.path), counted=False))
    except Exception:                # noqa: BLE001 - the page must not raise past here
        pass
    return current_app.response_class(render_template("app.BUSY_BARE", message=BUSY),
                                      status=503, mimetype="text/html")


# --- the CSRF token and the Origin check --------------------------------------

def session_token():
    """The opaque session token behind this request's cookie, or None."""
    value = request.cookies.get(auth.COOKIE)
    return auth.unsign(secret(), value) if value else None


def form_token():
    """The per-session CSRF token for this request, or None when there is no session."""
    token = session_token()
    return auth.csrf_token(secret(), token) if token else None


def csrf_token():
    """The `csrf()` macro's token: the session's, or None on a page with no session."""
    return form_token()


def expected_origin():
    # the browser always reaches the interface over TLS by the proxy's name; the proxy
    # forwards the Host as the browser sent it, port included (a tunnel, NAT), so the
    # origin the browser must name is https://<that host>
    return f"https://{request.host}"


def same_origin():
    """True when an unsafe request looks same-origin by `Origin`/`Sec-Fetch-Site`.

    A header that is present must be same-origin; a sibling subdomain, which
    `SameSite=Strict` lets through, is `same-site` and is refused. Neither header present
    (an old client, or a non-browser) leaves the per-session token as the only proof.
    """
    site = request.headers.get("Sec-Fetch-Site")
    if site is not None and site not in ("same-origin", "none"):
        return False
    origin = request.headers.get("Origin")
    if origin is not None and origin != expected_origin():
        return False
    return True


# a refusal made before any screen is (a forged act, a NUL), or while a refusal's own page
# failed: a heading and the sentence, outside the shell
REFUSED = "<h1>Refused</h1><p>{{ message }}</p>"


def refusal_response(message, status):
    return current_app.response_class(render_template("app.REFUSED", message=message),
                                      status=status, mimetype="text/html")


def forbidden(message):
    return refusal_response(message, 403)


def nul_refusal():
    """A 400 when any field carries a NUL, else None.

    psycopg2 refuses a string containing NUL, so a NUL in a text field became a 500 the
    moment the value reached a query. It is refused up front, as a bad request.
    """
    for value in request.values.values():
        if isinstance(value, str) and "\x00" in value:
            return refusal_response("A field held a character that is not allowed.", 400)
    return None


def origin_refusal():
    """A 403 when an unsafe request is not same-origin, else None.

    The Origin/Sec-Fetch-Site check runs for EVERY unsafe request, before the session is
    even read, so a cross-origin POST is turned away whether or not it carries a session.
    """
    if request.method in UNSAFE_METHODS and not same_origin():
        return forbidden("This request did not come from the interface itself, so it was "
                         "refused. Nothing was changed.")
    return None


def csrf_refusal():
    """A 403 when a signed-in unsafe request carries no valid CSRF token, else None.

    Run inside the guard, AFTER the session is confirmed, so an ended or invalid session
    gets the sign-in page rather than this refusal, and only a live session's act needs a
    token. The sign-in POST has no session and never reaches here (it is public).
    """
    if request.method not in UNSAFE_METHODS or request.endpoint in CSRF_EXEMPT:
        return None
    token = form_token()
    submitted = request.form.get(CSRF_FIELD, "")
    if not token or not hmac.compare_digest(token, submitted):
        return forbidden("This form was not the one the interface issued, or the session "
                         "has ended. Reload the page and try again. Nothing was changed.")
    return None


# --- the one function every screen renders through ------------------------------

def counts(conn):
    """The five numbers the sidebar carries, read in one statement."""
    with conn.cursor() as cursor:
        cursor.execute(COUNTS)
        names = [column[0] for column in cursor.description]
        return dict(zip(names, cursor.fetchone()))


def navigation(conn, current=None, counted=True):
    """The sidebar: every section in order, its count, and a link where a route serves it.
    Not `counted`, it has no counts: the busy page asks the database nothing more."""
    numbers = counts(conn) if counted else {}
    items = []
    for endpoint, title, count, separator in SECTIONS:
        items.append({
            "title": title,
            "url": url_for(endpoint) if endpoint in current_app.view_functions else None,
            "count": numbers.get(count) if count else None,
            "current": endpoint == current,
            "separator": separator,
        })
    return items


TOP = object()          # "the sentence goes where the shell puts it, above the screen"


def render(title, template, section=None, status=200, done=TOP, **values):
    """A screen: the shell, the sidebar, the `?done=` sentence and the screen's own body.

    ⛔ A screen cannot exist without the shell, because this is the only way one is made.
    The sign-in page is the one page that is not a screen: it has no shell,
    no sidebar and no way into one.

    ⚠️ A destructive act's confirmation page IS a screen, with the shell around it. The
    page kept outside the shell is the RE-PROMPT page, which carried a password
    field and a `next` - it was removed. What is left is the confirmation page,
    which states
    consequences as numbers and cancels back to the item; hiding the navigation from it
    would only make a person who cancels click twice.

    ⚠️ `done=None` takes the sentence off the top of the screen, for the one act whose
    saved sentence belongs INSIDE the row it was saved from - the person page's password
    row, where that row's refusals also appear (measured on the
    predecessor's deployed machine). The screen then renders it itself.

    The template names its page head in `{% set %}` blocks: `heading`, the
    `h1`'s content, which every screen has; `lede`, the muted sentence under it;
    `actions`, its controls, at most one of them the primary; and `crumbs`, the way here.
    """
    g.render = values
    return page(title, template, identity=g.get("identity"), status=status,
                nav=navigation(connection(), section),
                done=(common.done_sentence(request.args.get("done"))
                      if done is TOP else done))


def login_page(message, next_path=None, status=200):
    """The login page, deleting the cookie the request carried: what a session that is
    over gets.

    ⚠️ Only a cookie that came with the request is deleted. `SameSite=Strict` withholds
    it on a link from another site, and deleting it there would sign every other tab of
    the browser out.
    """
    # a refused or throttled sign-in is a refusal; "please sign in" is information
    tone = "bad" if message in (auth.REFUSAL, auth.THROTTLED) else "info"
    g.render = {"message": message, "next_path": next_path, "tone": tone}
    response = page("Sign in", "app.LOGIN", status=status)
    if auth.COOKIE in request.cookies:
        clear_cookie(response)
    return response


def set_cookie(response, token):
    response.set_cookie(auth.COOKIE, auth.sign(secret(), token), path="/",
                        httponly=True, secure=True, samesite="Strict")
    g.cookie_written = True


def clear_cookie(response):
    response.delete_cookie(auth.COOKIE, path="/", httponly=True, secure=True, samesite="Strict")
    g.cookie_written = True


# --- the return path --------------------------------------------

def safe_path(value):
    """`value` when it is a bare path this application serves by GET, else None."""
    if not isinstance(value, str) or not BARE_PATH.match(value) or len(value) > 512:
        return None
    adapter = current_app.url_map.bind("maildivvy.invalid")
    try:
        adapter.match(value, method="GET")
    except (HTTPException, RequestRedirect):
        return None
    return value


def return_path():
    """Where to come back to after signing in: this request's own path, if it is one."""
    return safe_path(request.path) if request.method == "GET" else None


# --- the guard in front of every endpoint ----------------------------------

def signed_in(view):
    @functools.wraps(view)
    def guarded(*args, **kwargs):
        identity = current_identity()
        if identity is None:
            return login_page(auth.SIGN_IN, next_path=return_path())
        g.identity = identity
        refusal = csrf_refusal()          # a live session's unsafe act needs its token
        if refusal is not None:
            return refusal
        return view(*args, **kwargs)

    guarded.maildivvy_guarded = True
    return guarded


def current_identity():
    """Who this request is, re-reading the account behind the session."""
    value = request.cookies.get(auth.COOKIE)
    token = auth.unsign(secret(), value) if value else None
    if token is None:
        return None
    conn = connection()
    identity = auth.read_session(conn, token)
    conn.commit()            # the session's own bookkeeping stands apart from any act
    if identity is not None:
        g.token = token
    return identity


def guard_every_endpoint(app):
    for endpoint, view in list(app.view_functions.items()):
        if endpoint in PUBLIC or getattr(view, "maildivvy_guarded", False):
            continue
        app.view_functions[endpoint] = signed_in(view)


# --- the routes ------------------------------------------------------------------------------

def register(app):
    # ⛔ Every `<int:...>` route rejects a value past a bigint before the query
    # sees it. Set before any rule is added, since a converter is bound when a rule is.
    app.url_map.converters["int"] = BoundedIntegerConverter

    # ⚠️ EVERY TEMPLATE IS COMPILED ONCE, FROM THE LOADER: a template is a constant of
    # its module, held under `<module>.<NAME>` (`domains.LIST_PAGE`), so a page names the
    # shell it extends and the macros it imports, and no template is a file of its own.
    app.jinja_env.loader = jinja2.DictLoader(templates())
    # ⛔ AND EVERY ONE IS AUTOESCAPED. Flask escapes only a template whose name ends in
    # `.html` (or one made from a string), and these names do not: without this, every
    # value a person typed would reach the page as markup.
    app.jinja_env.autoescape = True
    # A screen links to a section another task has not built yet by NAME: the template
    # asks whether the route exists rather than writing a path that may never be served.
    app.jinja_env.globals["has_route"] = lambda name: name in current_app.view_functions
    # the session's forgery token, which the `csrf()` macro writes into every POST form
    app.jinja_env.globals["csrf_token"] = csrf_token
    # a field's attributes from its keywords (`common.SHAPES`)
    app.jinja_env.filters["attributes"] = common.attributes
    # every printed moment, one way: UTC, date and time, the zone said
    app.jinja_env.filters["moment"] = common.moment
    # ⛔ ONE PLACE LOGS A DATABASE ERROR, BY ITS CODE: Flask logs every error a
    # view or a hook let through on the application's logger
    if not any(isinstance(kept, DatabaseErrorsByCode) for kept in app.logger.filters):
        app.logger.addFilter(DatabaseErrorsByCode())
    app.register_error_handler(500, server_error)

    @app.errorhandler(404)
    def missing(_error):
        """An unknown id, and a route that was removed, answer 404 INSIDE the shell.

        A removed route has no rule in the map at all, so it is a 404 and not a 405.
        A signed-out visitor gets the sign-in page instead of a shell they
        cannot see anything in.
        """
        if "identity" not in g:
            # a path that matches no rule never reached the guard, so who this is has
            # not been read yet; an unknown path must not say more to a stranger
            identity = current_identity()
            if identity is None:
                return login_page(auth.SIGN_IN, next_path=None, status=404)
            g.identity = identity
        return render("Not found", "app.NOT_FOUND", status=404)

    @app.route("/sign-in", methods=["GET", "POST"])
    def sign_in():
        if request.method == "GET":
            return login_page(None, next_path=safe_path(request.args.get("next")))
        next_path = safe_path(request.form.get("next"))
        # ⛔ THE THROTTLE IS KEYED ON THE PROXY'S CLIENT ADDRESS AND THE LOGIN.
        # REMOTE_ADDR is what run.py put there from the address the proxy forwarded
        # over the socket, validated as an address; never a header read here. account_login
        # folds `ivan@x` and `ivan` to one login, so a spelling cannot slip the count.
        address = request.remote_addr or ""
        login = auth.account_login(request.form.get("login"))
        # a login no account could have is refused before it is kept as a key or costs a
        # connection or a hash: the throttle's keys stay the column's size at most
        if not validate.ACCOUNT_LOGIN.fullmatch(login):
            return login_page(auth.REFUSAL, next_path=next_path)
        # the attempt is counted before the password is checked, so a parallel burst
        # gets no more guesses than the limit; a right password clears the count
        # an administrator's login is never turned away by the address's cap of logins,
        # only by its own failures: the database is asked only once that cap is full
        if not sign_in_throttle().attempt(
                address, login,
                exists=lambda name: auth.is_administrators_login(connection(), name)):
            return login_page(auth.THROTTLED, next_path=next_path, status=429)
        conn = connection()
        identity = auth.authenticate(conn, request.form.get("login"),
                                     request.form.get("password") or "")
        if identity is None:
            conn.rollback()          # a refused sign-in writes nothing
            return login_page(auth.REFUSAL, next_path=next_path)
        sign_in_throttle().record_success(address, login)
        if identity.break_glass:
            # ⛔ written before the cookie, on this connection: an audit log that cannot
            # be written is an error, not a quieter success. Answering
            # with the refusal page instead would say the password was right.
            journal.record(conn, actor=identity.login, action="break_glass_use",
                           target=identity.login, break_glass=True)
        token = auth.open_session(conn, identity)
        conn.commit()
        auth.expire_sessions(conn)   # every session past its bounds goes with this one's start
        conn.commit()
        response = redirect(next_path or url_for("overview"), code=303)
        set_cookie(response, token)
        return response

    @app.post("/sign-out")
    def sign_out():
        conn = connection()
        auth.end_session(conn, g.get("token"))
        conn.commit()
        response = redirect(url_for("sign_in"), code=303)
        clear_cookie(response)
        return response

    @app.before_request
    def guard_request():
        # ⛔ before any view runs: no field may carry a NUL, and an unsafe
        # request must be same-origin. The per-session CSRF token is checked
        # inside the guard, once the session is confirmed.
        return nul_refusal() or origin_refusal()

    @app.after_request
    def security_headers(response):
        # Nothing this interface serves may sit in a shared browser's cache;
        # the shown-once password page already sets its own stronger value, kept here.
        response.headers.setdefault("Cache-Control", "no-store")
        # This interface is never framed, loads nothing and runs no script, on any
        # response: its one stylesheet is inlined (`page()`), and it ships no script
        response.headers["Content-Security-Policy"] = POLICY
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.after_request
    def keep_the_cookie(response):
        # HttpOnly, Secure and SameSite=Strict on every signed-in response
        if "identity" in g and not g.get("cookie_written") and "token" in g:
            set_cookie(response, g.token)
        return response

    @app.after_request
    def commit_or_undo(response):
        conn = g.get("conn")
        if conn is not None:
            conn.commit() if response.status_code < 400 else conn.rollback()
        return response

    @app.teardown_request
    def close(exception=None):
        conn = g.pop("conn", None)
        if conn is not None:
            conn.rollback()
            conn.close()


def templates():
    """Every template the interface renders, by `<module>.<NAME>`: each module's
    upper-case string constants that hold a Jinja tag."""
    # imported here, not at the top: a screen module imports this one for the shell
    from maildivvy.admin.screens import (accounts, domains, events, external, fetch, health,
                                         mailboxes, maintenance, moderation, overview)

    found = {}
    for module in (sys.modules[__name__], common, overview, domains, external, fetch,
                   accounts, mailboxes, moderation, maintenance, events, health):
        short = module.__name__.rsplit(".", 1)[1]
        for name, value in vars(module).items():
            if name.isupper() and isinstance(value, str) and ("{%" in value or "{{" in value):
                found[f"{short}.{name}"] = value
    return found


def create_app(etc=ETC, consumer=auth.CONSUMER):
    """The application, refusing to exist at all if a file it reads is not right."""
    problems = auth.preflight(etc, consumer)
    if problems:
        raise ConfigError("; ".join(problems))
    app = Flask(__name__, static_folder=None)      # no static route: it serves no files
    app.config.update(MAILDIVVY_ETC=etc, MAILDIVVY_CONSUMER=consumer,
                      MAILDIVVY_SECRET=auth.read_secret(auth.secret_path(etc)),
                      MAILDIVVY_THROTTLE=throttle.Throttle())
    register(app)
    # imported here, not at the top: a screen module imports this one for the shell
    from maildivvy.admin.screens import (accounts, domains, events, external, fetch, health,
                                         mailboxes, maintenance, moderation, overview)

    for screens in (overview, domains, external, fetch, accounts, mailboxes, moderation,
                    maintenance, events, health):
        screens.register(app)
    guard_every_endpoint(app)
    return app
