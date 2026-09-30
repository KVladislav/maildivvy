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
import re

from flask import Flask, current_app, g, redirect, render_template_string, request, url_for
from markupsafe import Markup
from werkzeug.exceptions import HTTPException
from werkzeug.routing import IntegerConverter, RequestRedirect

from maildivvy.admin import auth, journal, throttle
from maildivvy.admin.screens import common
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

# ⛔ Cross-site request forgery defence. Every unsafe request is checked for a
# same-origin `Origin`/`Sec-Fetch-Site` and a per-session token; every response forbids
# framing. The token is written into every POST form (`CSRF_FIELD`), by rewriting the
# rendered page rather than editing thirty templates, so a form added later carries it too.
BIGINT_MAX = 2 ** 63 - 1        # a row id in a URL never exceeds this


class BoundedIntegerConverter(IntegerConverter):
    """`<int:id>` that refuses a value past a bigint, so the route 404s rather than the
    query overflowing to a 500."""

    def __init__(self, map_, *args, **kwargs):
        kwargs.setdefault("max", BIGINT_MAX)
        super().__init__(map_, *args, **kwargs)


UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CSRF_FIELD = "_csrf"
# the sign-in POST has no session yet, so it carries no per-session token; the Origin
# check still guards it, and a login CSRF mints only the attacker's own session
CSRF_EXEMPT = frozenset({"sign_in"})
POST_FORM = re.compile(r'<form\b[^>]*\bmethod="post"[^>]*>', re.IGNORECASE)

STYLE = """
body { font-family: system-ui, sans-serif; margin: 0; color: #111; background: #fff; }
header { display: flex; gap: 1rem; align-items: baseline;
         padding: .75rem 1.5rem; border-bottom: 1px solid #ccc; }
header .who { margin-right: auto; }
.frame { display: flex; align-items: flex-start; }
nav { width: 16rem; padding: 1rem 0; border-right: 1px solid #ccc; }
nav ul { list-style: none; margin: 0; padding: 0; }
nav li { padding: .25rem 1.5rem; }
nav li.sep { border-top: 1px solid #ddd; margin: .5rem 0; padding: 0; }
nav li.current { font-weight: bold; }
nav .count { color: #444; }
main { padding: 1.5rem; max-width: 60rem; flex: 1; }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { border-bottom: 1px solid #ddd; padding: .35rem .75rem; text-align: left;
         vertical-align: top; }
.notice { border: 1px solid #999; padding: .75rem; margin: 0 0 1rem; }
.refusal { border: 2px solid #900; padding: .75rem; margin: 0 0 1rem; color: #900; }
.field-refusal { color: #900; display: block; margin: .25rem 0; }
.banner { border: 2px solid #111; padding: .75rem; margin: 0 0 1rem; font-weight: bold; }
.danger { border: 2px solid #900; padding: .75rem; margin: 2rem 0 0; }
.crumbs { color: #444; margin: 0 0 .5rem; }
.badge { border: 1px solid #666; padding: 0 .35rem; }
label { display: block; margin: .75rem 0 .25rem; }
footer { padding: 1.5rem; color: #444; }
header a.health { text-decoration: none; }
"""

# Health's four states in colour: (text, background, border), each pair readable
# at WCAG AA or better. The state's word is always printed too, so colour is never the
# only signal. FAIL is the one solid badge; PASS is calm; UNKNOWN is not PASS's colour.
# Only a badge that names a health state carries a `state-*` class: the People list's
# badges keep their plain look.
STATE_COLOURS = {
    "PASS": ("#14532d", "#dcfce7", "#15803d"),
    "WARN": ("#713f12", "#fef3c7", "#b45309"),
    "UNKNOWN": ("#3730a3", "#e0e7ff", "#4338ca"),
    "FAIL": ("#ffffff", "#b91c1c", "#7f1d1d"),
}
STYLE += "".join(
    f".badge.state-{state.lower()} {{ color: {text}; background: {background}; "
    f"border-color: {border};{' font-weight: bold;' if state == 'FAIL' else ''} }}\n"
    for state, (text, background, border) in STATE_COLOURS.items())
# The Health screen's two banners take the same palette: a stale report is WARN, and no
# report at all is FAIL. Only a banner that names a state is coloured; the break-glass
# and shown-once banners keep the plain `.banner`.
STYLE += "".join(
    f".banner.state-{state.lower()} {{ color: {text}; background: {background}; "
    f"border-color: {border}; }}\n"
    for state, (text, background, border) in STATE_COLOURS.items()
    if state in ("WARN", "FAIL"))

SHELL = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ title }} - Maildivvy</title><style>{{ style }}</style></head>
<body>
{%- if identity %}
<header>
  <a class="product" href="{{ url_for('overview') }}">Maildivvy</a>
  {%- if health %}
  <a class="health badge state-{{ health.tone|lower }}" href="{{ health.url }}">Health: {{ health.words }}{% if health.detail %} &middot; {{ health.detail }}{% endif %}</a>
  {%- endif %}
  <span class="who">Signed in as {{ identity.login }}</span>
  <form method="post" action="{{ url_for('sign_out') }}">
    <button type="submit">Sign out {{ identity.login }}</button>
  </form>
</header>
{%- endif %}
<div class="frame">
{%- if nav %}
<nav>
<ul>
{%- for item in nav %}
  <li class="{{ 'current' if item.current else '' }}">
    {%- if item.url %}<a href="{{ item.url }}">{{ item.title }}</a>
    {%- else %}<span>{{ item.title }}</span>{% endif %}
    {%- if item.count is not none %} <span class="count">{{ item.count }}</span>{% endif %}
  </li>
  {%- if item.separator %}<li class="sep"></li>{% endif %}
{%- endfor %}
</ul>
</nav>
{%- endif %}
<main>
{%- if identity and identity.break_glass %}
<p class="banner">Signed in with the break-glass account. Its use is recorded in the
journal, and its password is rotated afterwards. Every act in this session is marked.</p>
{%- endif %}
{%- if done %}<p class="notice done">{{ done }}</p>{% endif %}
{{ body }}
</main>
</div>
</body>
</html>
"""

LOGIN = """
<h1>Maildivvy</h1>
{%- if message %}<p class="notice">{{ message }}</p>{% endif %}
<form method="post" action="{{ url_for('sign_in') }}">
  <label for="login">Login</label>
  <input id="login" name="login" autocomplete="username" autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  {%- if next_path %}<input type="hidden" name="next" value="{{ next_path }}">{% endif %}
  <p><button type="submit">Sign in</button></p>
</form>
<footer>A session ends after 15 minutes without a request, and 8 hours after it began.</footer>
"""

NOT_FOUND = """
<h1>Not found</h1>
<p>There is nothing at this address. A removed route answers this too, because its rule
is gone from the map rather than left behind refusing methods.</p>
"""


# --- the request's connection ----------------------------------------------

def connection():
    if "conn" not in g:
        g.conn = db.connect(current_app.config["MAILDIVVY_CONSUMER"],
                            etc=current_app.config["MAILDIVVY_ETC"])
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

    return {**health.status(), "url": url_for("health")}


def page(title, body, identity=None, status=200, nav=None, done=None):
    inner = render_template_string(body, identity=identity, **g.get("render", {}))
    # ⛔ only a signed-in page has the shell's header, so only it reads the report; the
    # sign-in page has no shell and says nothing about the machine
    html = render_template_string(SHELL, title=title, style=STYLE, identity=identity,
                                  body=Markup(inner), nav=nav, done=done,
                                  health=header_health() if identity else None)
    return current_app.response_class(add_csrf_fields(html), status=status,
                                      mimetype="text/html")


# --- the CSRF token and the Origin check --------------------------------------

def session_token():
    """The opaque session token behind this request's cookie, or None."""
    value = request.cookies.get(auth.COOKIE)
    return auth.unsign(secret(), value) if value else None


def form_token():
    """The per-session CSRF token for this request, or None when there is no session."""
    token = session_token()
    return auth.csrf_token(secret(), token) if token else None


def add_csrf_fields(html):
    """Put the session's CSRF token into every POST form of a rendered page."""
    token = form_token()
    if not token:
        return html
    field = f'<input type="hidden" name="{CSRF_FIELD}" value="{token}">'
    return POST_FORM.sub(lambda match: match.group(0) + field, html)


def expected_origin():
    # the browser always reaches the interface over TLS by the proxy's name; the proxy
    # forwards the Host, so the origin the browser must name is https://<that host>
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


def refusal_response(message, status):
    return current_app.response_class(
        render_template_string("<h1>Refused</h1><p>{{ message }}</p>", message=message),
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


def navigation(conn, current=None):
    """The sidebar: every section in order, its count, and a link where a route serves it."""
    numbers = counts(conn)
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
    """
    g.render = values
    return page(title, template, identity=g.get("identity"), status=status,
                nav=navigation(connection(), section),
                done=(common.done_sentence(request.args.get("done"))
                      if done is TOP else done))


def login_page(message, next_path=None, status=200):
    """The login page, with the cookie deleted: what every session that is over gets."""
    g.render = {"message": message, "next_path": next_path}
    response = page("Sign in", LOGIN, status=status)
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

    # A screen links to a section another task has not built yet by NAME: the template
    # asks whether the route exists rather than writing a path that may never be served.
    app.jinja_env.globals["has_route"] = lambda name: name in current_app.view_functions

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
        return render("Not found", NOT_FOUND, status=404)

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
        if sign_in_throttle().blocked(address, login):
            return login_page(auth.THROTTLED, next_path=next_path, status=429)
        conn = connection()
        identity = auth.authenticate(conn, request.form.get("login"),
                                     request.form.get("password") or "")
        if identity is None:
            conn.rollback()          # a refused sign-in writes nothing
            sign_in_throttle().record_failure(address, login)
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
        # This interface is never framed, on any response
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
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
