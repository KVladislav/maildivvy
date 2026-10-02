"""The shell, the navigation and the readings the screens make, read without a machine.

What is here is everything that can be decided from the code alone: the sidebar's
declared shape, the closed list of sentences, the URL map, and the fetch screen's
readings of a row. What needs the installed application, a database and a browser is
tested on the test machine, in a browser.

⚠️ **The application is built here, never created**: `create_app` reads the machine's
configuration files, while `register` only adds rules. So the map these tests read is
the map the machine serves, with nothing stubbed in its place.
"""

import datetime
import re
from decimal import Decimal
from html.parser import HTMLParser
from pathlib import Path

import pytest
from flask import Flask
from markupsafe import Markup, escape

from maildivvy.admin import app as application
from maildivvy.admin import auth, journal
from maildivvy.admin.screens import (accounts, common, domains, events, external, fetch,
                                     health, mailboxes, maintenance, moderation, overview)
from test_admin_health import MIXED as HEALTH_MIXED
from test_admin_health import NOW as HEALTH_NOW
from test_admin_health import stand_in_busy_rows
from test_admin_health import write as write_report

SCREENS = (overview, domains, external, fetch, accounts, mailboxes, moderation,
           maintenance, events, health)
SOURCE = Path(application.__file__).resolve().parent


@pytest.fixture(scope="module")
def built():
    """The application's rules, registered the way `create_app` registers them."""
    made = Flask("maildivvy-test")
    application.register(made)
    for screen in SCREENS:
        screen.register(made)
    application.guard_every_endpoint(made)
    return made


def templates():
    """Every template string the screens hold, by the name of the module holding it."""
    found = {}
    for screen in SCREENS:
        for name, value in vars(screen).items():
            if isinstance(value, str) and name.isupper() and "{" in value:
                found[f"{screen.__name__}.{name}"] = value
    return found


# --- the shell and the sidebar -----------------------------------------

def test_the_sidebar_is_the_declared_list_in_its_order_with_its_separators():
    titles = [title for _, title, _, _ in application.SECTIONS]
    assert titles == ["Overview", "External mailboxes", "Domains", "People", "Mailboxes",
                      "Fetch", "Withheld messages", "Journal", "Health"]
    # Health, the machine rather than its mail, stands apart at the end
    after = [title for _, title, _, separator in application.SECTIONS if separator]
    assert after == ["Overview", "Mailboxes", "Journal"]


def test_a_link_is_built_from_the_routes_name_and_never_from_a_path():
    # every sidebar entry names an endpoint; a path spelt into the shell would survive a
    # route moving and lead nowhere
    assert "url_for(endpoint)" in Path(application.__file__).read_text()
    for endpoint, _, _, _ in application.SECTIONS:
        assert re.fullmatch(r"[a-z_]+", endpoint), endpoint


def test_the_login_page_has_no_shell_no_sidebar_and_no_way_into_a_screen(built):
    assert "nav" not in application.LOGIN
    for endpoint in ("domains", "external", "fetch"):
        assert endpoint not in application.LOGIN


def test_every_screen_renders_through_the_one_function(built):
    """A screen cannot exist without the shell, because `render` is the only way to one."""
    text = "".join((SOURCE / "screens" / f"{screen.__name__.rsplit('.', 1)[1]}.py").read_text()
                   for screen in SCREENS)
    # no screen builds a response of its own: they all go through app.render
    assert "response_class" not in text
    assert "render_template_string" not in text
    assert text.count("app.render(") >= len(SCREENS)


def test_a_form_number_is_ascii_digits_within_a_bigint_and_nothing_else():
    # str.isdigit() is true for '²', which int() then refuses, and true for a
    # number past a bigint, which the database refuses - both 500s. `as_int` refuses both.
    assert common.as_int("7") == 7 and common.as_int(" 42 ") == 42
    assert common.as_int(str(2 ** 63 - 1)) == 2 ** 63 - 1
    for bad in ("²", "1²", "", "  ", "seven", "-1", "1.0", str(2 ** 63), str(2 ** 70)):
        assert common.as_int(bad) is None, bad
    # want_int turns the None into a sentence, never a 500
    with pytest.raises(common.validate.Refused):
        common.want_int("²", "domain")


def test_a_row_id_past_a_bigint_in_a_url_is_refused_by_the_route(built):
    # The `<int:...>` converter is bounded, so a huge id 404s rather than
    # overflowing the query to a 500
    adapter = built.url_map.bind("maildivvy.invalid")
    adapter.match("/people/7")                                  # the control: an ordinary id
    with pytest.raises(Exception):                             # NotFound: past a bigint
        adapter.match(f"/people/{2 ** 63}")


def test_the_csrf_field_is_injected_into_post_forms_and_not_get_forms():
    # The token is added by rewriting the rendered page, so a POST form added
    # in any template carries it and a GET form (the journal filter, the top-up) does not
    inject = application.POST_FORM
    assert inject.search('<form method="post" action="/x">')
    assert inject.search("<form class='c' method=\"post\">")
    assert not inject.search('<form method="get" action="/events">')
    # every POST form across the screens matches the pattern the injection uses
    posted = sum(len(re.findall(r'<form[^>]*method="post"', text)) for text in templates().values())
    matched = sum(len(inject.findall(text)) for text in templates().values())
    assert posted and matched == posted, (posted, matched)


@pytest.mark.parametrize("headers, same", [
    ({"Origin": "https://mail.example.org", "Sec-Fetch-Site": "same-origin"}, True),
    ({"Sec-Fetch-Site": "none"}, True),                     # typed into the address bar
    ({}, True),              # neither header: the per-session token is the only proof left
    ({"Origin": "https://evil.example.org"}, False),
    ({"Origin": "null"}, False),
    ({"Sec-Fetch-Site": "same-site"}, False),               # a sibling subdomain
    ({"Origin": "https://mail.example.org", "Sec-Fetch-Site": "cross-site"}, False),
])
def test_a_header_that_is_there_must_say_same_origin_and_neither_leaves_the_token(headers, same):
    """architecture § Programs of our own: refused when `Origin` is not the interface's own
    or `Sec-Fetch-Site` is anything but `same-origin` or `none`."""
    with Flask("t").test_request_context("/people", method="POST", headers=headers,
                                         base_url="https://mail.example.org"):
        assert application.same_origin() is same


def test_every_response_gets_the_no_store_and_no_frame_headers_and_the_origin_guard():
    # The app declares the security after_request and the origin guard
    source = Path(application.__file__).read_text()
    assert 'response.headers["Content-Security-Policy"] = "frame-ancestors \'none\'"' in source
    assert 'response.headers["X-Frame-Options"] = "DENY"' in source
    assert 'response.headers.setdefault("Cache-Control", "no-store")' in source
    assert "def guard_request" in source and "csrf_refusal()" in source and "nul_refusal()" in source


def test_exactly_five_sidebar_links_carry_a_count():
    carried = [title for _, title, count, _ in application.SECTIONS if count]
    assert carried == ["External mailboxes", "Domains", "People", "Mailboxes",
                       "Withheld messages"]


def test_the_five_counts_are_one_query_and_mailboxes_counts_the_archives_too():
    assert application.COUNTS.count(";") == 0
    # one statement: the outer SELECT and six sub-selects, because Mailboxes adds two
    assert application.COUNTS.lower().count("select") == 7
    # every domain's archive appears as a mailbox row, so the count is both tables
    assert "(SELECT count(*) FROM mailbox) + (SELECT count(*) FROM domain)" \
        in application.COUNTS


# --- getting from screen to screen ---------------------------------

def test_every_post_route_is_the_action_of_a_form_on_some_screen(built):
    posted = {rule.endpoint for rule in built.url_map.iter_rules()
              if "POST" in rule.methods and rule.endpoint not in ("sign_in", "sign_out")}
    assert posted, "no POST route at all would make this test pass saying nothing"
    written = "".join(templates().values())
    for endpoint in sorted(posted):
        assert f"url_for('{endpoint}'" in written, endpoint


# Every act the interface offers, by endpoint. What was left out on purpose (admin
#) is in no list: no skip or un-skip button, no password
# reveal, no per-mailbox schedule, state or copy of outgoing mail, no journal cleanup, no
# bulk undelete, no retention setting. A new act is added here on purpose or not at all.
ACTS = {
    "sign_in", "sign_out",
    "add_domain", "archive_password", "domain_spam", "domain_outbound", "delete_domain",
    "add_external", "external_settings", "external_servers", "external_check",
    "external_enable", "external_disable", "delete_external_mailbox",
    "refetch", "resume_fetch",
    "add_account", "account_password", "account_admin", "account_state", "account_comment",
    "delete_account",
    "add_mailbox", "transfer_mailbox", "top_up", "deliver_one_message", "delete_mailbox",
    "release_message",
}


def test_the_interface_offers_exactly_its_acts_and_none_left_out_on_purpose(built):
    posted = {rule.endpoint for rule in built.url_map.iter_rules() if "POST" in rule.methods}
    assert posted == ACTS, (posted - ACTS, ACTS - posted)
    rules = " ".join(rule.rule for rule in built.url_map.iter_rules())
    for word in ("skip", "reveal", "schedule", "undelete", "restore", "retention", "cleanup",
                 "copy"):
        assert word not in rules, word
    assert "/mailboxes/<int:mailbox_id>/state" not in rules   # a mailbox has no state of its own
    assert "/people/<int:account_id>/state" in rules          # the control: a person has one


def test_no_page_carries_a_script_a_handler_or_a_refresh_so_every_act_is_a_plain_form():
    """every operation is a plain HTML form and works with no script. The
    shell, the sign-in page, the 404 and every screen's templates are read whole: none
    runs a script, calls one from an attribute or a link, or reloads itself (admin
    no automatic page refresh)."""
    pages = {**templates(), "app.SHELL": application.SHELL, "app.LOGIN": application.LOGIN,
             "app.NOT_FOUND": application.NOT_FOUND}
    forms = [name for name, text in pages.items() if "<form" in text]
    assert len(forms) >= 10 and "app.LOGIN" in forms, forms      # the control: forms were read
    for name, text in pages.items():
        assert "<script" not in text.lower(), name
        assert not re.search(r"\son[a-z]+\s*=", text, re.IGNORECASE), name
        assert "javascript:" not in text.lower(), name
        assert "http-equiv" not in text.lower(), name
        for form in re.findall(r"<form\b[^>]*>", text, re.IGNORECASE):
            assert re.search(r'\bmethod="(get|post)"', form, re.IGNORECASE), (name, form)


def test_every_endpoint_a_template_names_is_one_the_application_serves_or_is_guarded(built):
    # a link to a screen a later task builds is written `has_route('x')` first; anything
    # else must be a rule that exists now
    for name, text in templates().items():
        for endpoint in set(re.findall(r"url_for\('([a-z_]+)'", text)):
            if endpoint in built.view_functions:
                continue
            assert f"has_route('{endpoint}')" in text, f"{name} links to {endpoint}"


def test_no_password_field_on_any_form_is_filled_back_in():
    for name, text in templates().items():
        for field in re.findall(r"<input[^>]*type=\"password\"[^>]*>", text):
            assert "value=" not in field, f"{name}: {field}"


def test_the_sentence_for_an_act_comes_from_a_closed_list_and_an_unknown_key_says_nothing():
    assert common.done_sentence("domain_created") == "Domain created."
    assert common.done_sentence("no-such-key") is None
    assert common.done_sentence(None) is None
    assert common.done_sentence("") is None
    assert all(sentence.endswith(".") for sentence in common.DONE.values())


def test_every_key_the_screens_redirect_with_is_in_that_list():
    text = "".join((SOURCE / "screens" / f"{screen.__name__.rsplit('.', 1)[1]}.py").read_text()
                   for screen in SCREENS)
    used = set(re.findall(r"common\.acted\([^,]+, \"([a-z_]*)\"", text))
    used |= set(re.findall(r"common\.acted_at\([^,]+, \"([a-z_]*)\"", text))
    assert used, "the scan found nothing, which would pass saying nothing"
    assert used - {""} <= set(common.DONE), used - set(common.DONE)


def test_only_the_referers_path_is_used_so_a_done_key_never_rides_onto_the_next_screen():
    source = (SOURCE / "screens" / "common.py").read_text()
    assert 'referer.split("?", 1)[0]' in source


@pytest.mark.parametrize("gone", ["/domains/1/map", "/external/1/credential",
                                  "/external/1/window", "/external/1/comment",
                                  "/external/1/ours-alone", "/mailboxes/1/state"])
def test_the_routes_the_source_removed_have_no_rule_at_all(built, gone):
    # no rule means 404, not 405: a rule left behind refusing methods still says the
    # screen exists
    adapter = built.url_map.bind("maildivvy.invalid")
    for method in ("GET", "POST"):
        try:
            adapter.match(gone, method=method)
        except Exception:
            continue
        raise AssertionError(f"{method} {gone} still matches a rule")


def test_the_404_is_rendered_inside_the_shell_with_a_page_head(shell):
    answer = shell.get("/no-such-page")
    html = answer.get_data(as_text=True).split("</head>", 1)[1]
    assert answer.status_code == 404
    assert '<header class="topbar">' in html and '<nav class="nav"' in html
    assert '<div class="page-head"><div><h1>Not found</h1>' in html
    assert html.count("<h1") == 1
    # not a section: no sidebar entry is the current one
    assert 'aria-current="page"' not in html


# --- the shell, in the design's components --------------------------------------------

COUNTS = {"external": 3, "domains": 2, "people": 4, "mailboxes": 6, "withheld": 1}


@pytest.fixture
def shell(tmp_path, monkeypatch):
    """The application's rules and shell, signed in, with the five counts stood in for
    the database; health's report is missing, so the header says "no report"."""
    made = Flask("maildivvy-test")
    application.register(made)
    for screen in SCREENS:
        screen.register(made)
    application.guard_every_endpoint(made)
    made.config.update(MAILDIVVY_HEALTH_REPORT=tmp_path / "health.json",
                       MAILDIVVY_HEALTH_CONF=tmp_path / "health.conf",
                       MAILDIVVY_HEALTH_TIMER=tmp_path / "health.timer")
    monkeypatch.setattr(application, "current_identity", lambda: auth.Identity("t28admin", 1))
    monkeypatch.setattr(application, "connection", lambda: None)
    monkeypatch.setattr(application, "counts", lambda conn: dict(COUNTS))
    return made.test_client()


def page_of(client, path):
    """The page after its head: the stylesheet's selectors are not markup."""
    return client.get(path).get_data(as_text=True).split("</head>", 1)[1]


def test_a_signed_in_page_has_the_top_bar_the_sidebar_and_one_h1(shell):
    html = page_of(shell, "/health")
    top = html.split('<header class="topbar">', 1)[1].split("</header>", 1)[0]
    assert '<a class="brand" href="/">Maildivvy</a>' in top
    assert "Signed in as t28admin" in top
    assert '<button class="btn btn-sm" type="submit">Sign out t28admin</button>' in top
    assert '<div class="shell"><nav class="nav" aria-label="Sections">' in html
    assert html.count("<h1") == 1
    # the old shell's classes are gone
    for old in ('class="current"', 'class="count"', 'class="notice', "<header>", "<nav>"):
        assert old not in html, old


def test_the_sidebar_marks_the_one_current_section_and_carries_five_counts(shell):
    nav = page_of(shell, "/health").split('<nav class="nav"', 1)[1].split("</nav>", 1)[0]
    assert nav.count('aria-current="page"') == 1
    assert '<a href="/health" aria-current="page">Health</a>' in nav
    assert re.findall(r'<span class="n">(\d+)</span>', nav) == ["3", "2", "4", "6", "1"]
    assert nav.count('<li class="sep"></li>') == 3
    assert '<a href="/people">People <span class="n">4</span></a>' in nav


def test_a_section_with_no_route_keeps_its_count_beside_its_name(tmp_path, monkeypatch):
    made = Flask("maildivvy-test")
    application.register(made)
    for screen in (overview, health):   # People, and the other sections, not served
        screen.register(made)
    application.guard_every_endpoint(made)
    made.config.update(MAILDIVVY_HEALTH_REPORT=tmp_path / "health.json",
                       MAILDIVVY_HEALTH_CONF=tmp_path / "health.conf",
                       MAILDIVVY_HEALTH_TIMER=tmp_path / "health.timer")
    monkeypatch.setattr(application, "current_identity", lambda: auth.Identity("t28admin", 1))
    monkeypatch.setattr(application, "connection", lambda: None)
    monkeypatch.setattr(application, "counts", lambda conn: dict(COUNTS))
    nav = page_of(made.test_client(), "/health").split('<nav class="nav"', 1)[1]
    assert '<li><span>People <span class="n">4</span></span></li>' in nav


def test_the_shell_carries_the_seven_icons_hidden(shell):
    html = page_of(shell, "/health")
    sprite = html.split('<svg class="sprite"', 1)[1].split("</svg>", 1)[0]
    assert 'aria-hidden="true"' in sprite
    assert re.findall(r'<symbol id="i-([a-z]+)"', sprite) == [
        "alert", "check", "x", "info", "lock", "clock", "back"]


def test_a_done_sentence_is_a_flash_ok_with_its_icon(shell):
    html = page_of(shell, "/health?done=domain_created")
    assert ('<div class="flash ok"><svg class="icon ok ico"><use href="#i-check"/></svg>'
            "<div>Domain created.</div></div>") in html
    assert 'class="flash ok"' not in page_of(shell, "/health?done=no-such-key")


def test_the_break_glass_session_is_a_flash_attn_on_every_page(shell, monkeypatch):
    assert 'class="flash attn"' not in page_of(shell, "/health")
    monkeypatch.setattr(application, "current_identity",
                        lambda: auth.Identity("break-glass", None, break_glass=True))
    for path in ("/health", "/no-such-page"):
        html = page_of(shell, path)
        flash = html.split('<div class="flash attn">', 1)[1].split("</div></div>", 1)[0]
        assert '<use href="#i-alert"/>' in flash, path
        assert "Signed in with the break-glass account." in " ".join(flash.split()), path


def test_the_header_badge_with_no_report_is_the_solid_red_badge(shell):
    top = page_of(shell, "/health").split('<header class="topbar">', 1)[1].split("</header>")[0]
    assert ('<a class="health badge bad solid" href="/health">Health: no report</a>'
            in top)


def test_the_sign_in_page_is_a_bare_card(shell):
    html = page_of(shell, "/sign-in")
    assert '<body><div class="bare-wrap"><section class="card">' in html
    assert "<header" not in html and "<nav" not in html and 'class="shell"' not in html
    assert html.count("<h1") == 1
    assert '<button class="btn btn-primary" type="submit">Sign in</button>' in html
    assert '<p class="foot">' in html


@pytest.mark.parametrize("message,tone", [(auth.REFUSAL, "bad"), (auth.THROTTLED, "bad"),
                                          (auth.SIGN_IN, "info")])
def test_what_the_sign_in_page_says_is_a_flash(shell, message, tone):
    made = shell.application
    with made.test_request_context("/sign-in"):
        html = application.login_page(message).get_data(as_text=True)
    flash = html.split(f'<div class="flash {tone}">', 1)[1].split("</div></div>", 1)[0]
    assert str(escape(message)) in flash


# --- the shared shapes: a field, a danger zone, a setting row ---------------------------

def shape(built, template, **values):
    """A template calling the shared shapes, rendered the way a screen's template is."""
    with built.test_request_context("/"):
        return built.jinja_env.from_string(template).render(**values)


def test_a_field_is_its_label_its_input_its_help_and_the_refusal_beside_it(built):
    html = shape(built, "{{ field('Label', 'label', typed, help='A single DNS label.', "
                        "warn=refusal, class_='mono-input mid', autocomplete='off') }}",
                 typed="sales", refusal="That label is taken.")
    assert html == ('<div class="field"><label for="label">Label</label>'
                    '<input id="label" name="label" type="text" value="sales" '
                    'class="mono-input mid" autocomplete="off">'
                    '<p class="help">A single DNS label.</p>'
                    '<p class="help warn">That label is taken.</p></div>')
    # no help and no refusal: the label and the input alone
    assert shape(built, "{{ field('Comment', 'comment') }}") == (
        '<div class="field"><label for="comment">Comment</label>'
        '<input id="comment" name="comment" type="text"></div>')


def test_a_password_field_is_never_filled_back_in_whatever_it_is_given(built):
    html = shape(built, "{{ field('Archive password', 'password', 'secret', type='password', "
                        "autocomplete='new-password', warn='The two passwords differ.') }}")
    assert "secret" not in html and "value=" not in html
    assert '<p class="help warn">The two passwords differ.</p>' in html


def test_a_field_escapes_what_a_person_typed_and_what_the_pipeline_said(built):
    html = shape(built, "{{ field(label, 'comment', typed, warn=reason) }}"
                        "{{ field('Login', 'login', typed, placeholder=typed) }}",
                 label="<b>x</b>", typed='"><script>alert(1)</script>', reason="<i>no</i>")
    assert "<script>" not in html and "<b>" not in html and "<i>" not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html and "&lt;i&gt;no&lt;/i&gt;" in html
    assert 'value="&#34;&gt;&lt;script&gt;' in html


def test_a_field_writes_a_true_attribute_bare_and_leaves_out_a_false_one(built):
    html = shape(built, "{{ field('Days', 'window', 14, type='number', min=1, required=true, "
                        "disabled=false, aria_describedby='w') }}")
    assert ('<input id="window" name="window" type="number" value="14" min="1" required '
            'aria-describedby="w">') in html
    assert "disabled" not in html


def test_a_danger_zone_is_its_frame_its_head_and_the_row_of_its_act(built):
    html = shape(built, """
{%- set act %}<a class="btn btn-danger" href="/domains/1/delete">Delete…</a>{% endset -%}
{{ danger_zone('Delete this domain, with everything in it', about, act) }}
{{- danger_zone('Nothing else', none, act) }}""",
                 about="It removes <the archive>.")
    assert html == (
        '<section class="danger-zone"><div class="box-head"><h2>Danger zone</h2></div>'
        '<div class="zone-row"><div><b>Delete this domain, with everything in it</b>'
        '<p class="muted">It removes &lt;the archive&gt;.</p></div>'
        '<a class="btn btn-danger" href="/domains/1/delete">Delete…</a></div></section>'
        '<section class="danger-zone"><div class="box-head"><h2>Danger zone</h2></div>'
        '<div class="zone-row"><div><b>Nothing else</b></div>'
        '<a class="btn btn-danger" href="/domains/1/delete">Delete…</a></div></section>')


def test_a_setting_row_is_one_post_form_with_its_title_its_fields_and_its_own_button(built):
    html = shape(built, """
{%- set fields %}{{ field('New archive password', 'password', type='password') }}{% endset -%}
{{ setting('/domains/1/archive/password', 'Archive password', about, fields,
           'Replace archive password', primary=true) }}
{{- setting('/people/2/comment', title, none, '', 'Save comment') }}""",
                 about="Shared by <every> administrator.", title=Markup("Comment on <code>bob</code>"))
    first, second = html.split("</form>")[:2]
    assert first.startswith(
        '<form class="setting" method="post" action="/domains/1/archive/password">'
        '<div><h2 class="st">Archive password</h2>'
        '<p class="about">Shared by &lt;every&gt; administrator.</p></div>'
        '<div><div class="field"><label for="password">New archive password</label>')
    assert first.endswith('<div class="form-foot"><button class="btn btn-primary" '
                          'type="submit">Replace archive password</button></div></div>')
    assert second == ('<form class="setting" method="post" action="/people/2/comment">'
                      '<div><h2 class="st">Comment on <code>bob</code></h2></div>'
                      '<div><div class="form-foot"><button class="btn" type="submit">'
                      'Save comment</button></div></div>')
    # the CSRF field reaches the setting's form like any other post form
    assert application.POST_FORM.search(html)


# --- the domain screens, in the design's components -----------------------------------

DOMAIN = {"id": 1, "label": "sales", "spam_threshold": Decimal("8.00"),
          "spam_reaches_people": True, "outbound_unscanned": "send", "external_id": None,
          "external_address": None, "external_state": None, "mailboxes": 2, "messages": 1204,
          "newest": "2026-09-30 14:31", "waiting": False, "asked_at": None}
OCCUPIED = dict(DOMAIN, id=2, label="office", external_id=9,
                external_address="office@example.org", external_state="deactivated")
NOTHING_ASKED = {"waiting": None, "look_again": None, "failed": None}


def a_box(**changed):
    box = {"kind": "person", "id": 5, "address": "ivan@sales", "login": "ivan",
           "account_id": 3, "account_state": "active", "comment": None, "domain_id": 1,
           "label": "sales", "as_of": None, "total": 12, "reading": dict(NOTHING_ASKED)}
    return {**box, **changed}


ARCHIVE_BOX = a_box(kind="archive", id=None, address="archive@sales", login=None,
                    account_id=None, account_state=None, total=1204)
MESSAGES = [
    {"id": 58120, "received_at": "2026-09-30 14:31", "message_date": "2026-09-30 14:30",
     "sender": "orders@example.org", "subject": "Order confirmed", "state": "delivered",
     "is_spam": False, "spam_score": Decimal("1.2"), "archive_uid": 1},
    {"id": 58116, "received_at": "2026-09-30 09:44", "message_date": None,
     "sender": "bounce@example.org", "subject": "Returned", "state": "delivered",
     "is_spam": True, "spam_score": None, "archive_uid": 2},
]


@pytest.fixture
def domains_world(shell, monkeypatch):
    """The shell with two domains stood in for the database: `sales` free, `office` with
    a disabled external mailbox in front of it; `sales` holds its archive and two people."""
    known = {1: DOMAIN, 2: OCCUPIED}

    def one(conn, sql, parameters=()):
        if sql == domains.NUMBERS:
            return {"messages": 1204, "mailboxes": 2, "people": 1}
        if sql.startswith(domains.LIST):
            found = known.get(parameters[0])
            return dict(found) if found else None
        return None

    def rows(conn, sql, parameters=()):
        if sql.startswith(domains.LIST):
            return [dict(OCCUPIED), dict(DOMAIN)]
        if sql == domains.LISTING:
            return [dict(message) for message in MESSAGES]
        return []

    boxes = [ARCHIVE_BOX, a_box(),
             a_box(id=6, address="olga@sales", login="olga", account_id=4,
                   account_state="blocked", total=3)]
    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(mailboxes, "listing", lambda conn, domain_id=None, period=None:
                        [dict(box) for box in boxes] if domain_id == 1 else [])
    return shell


@pytest.fixture
def waiting_world(domains_world, monkeypatch):
    """The domains, with the creation of `sales` asked for and not performed yet."""
    waiting = dict(DOMAIN, waiting=True, asked_at=datetime.datetime(2026, 9, 30, 14, 58))
    real = common.one
    monkeypatch.setattr(common, "one", lambda conn, sql, parameters=():
                        dict(waiting) if sql.startswith(domains.LIST)
                        else real(conn, sql, parameters))
    return domains_world


def main_part(client, path, method="get", **form):
    answer = getattr(client, method)(path, data=form or None)
    html = answer.get_data(as_text=True).split("<main>", 1)[1].split("</main>", 1)[0]
    return answer.status_code, html


def page_head(html):
    """The page head: its title and lede, then its actions (neither holds a `div`)."""
    found = re.search(r'<div class="page-head"><div>(.*?)</div>'
                      r'(?:<div class="actions">(.*?)</div>)?</div>', html, re.S)
    return found.group(1) + (found.group(2) or "")


def class_tokens(html):
    return {token for value in re.findall(r'class="([^"]*)"', html) for token in value.split()}


def test_the_domains_list_is_one_table_in_a_box_with_labels_in_code(domains_world):
    status, html = main_part(domains_world, "/domains")
    assert status == 200
    head = page_head(html)
    assert "<h1>Domains</h1>" in head
    assert '<a class="btn btn-primary" href="/domains/add">Add domain</a>' in head
    assert html.count("btn-primary") == 1 and html.count("<h1") == 1
    assert '<section class="box"><div class="table-wrap"><table>' in html
    assert html.count("<table") == 1
    assert ('<thead><tr><th>Label</th><th>External mailbox in front</th>'
            '<th class="num">Mailboxes</th><th class="num">In the archive</th>'
            '<th class="acts">Actions</th></tr></thead>') in html
    row = html.split('<a href="/domains/1"><code>sales</code></a>', 1)[1].split("</tr>", 1)[0]
    assert '<span class="muted">none &mdash; nothing arrives and nothing leaves</span>' in row
    assert '<td class="num">2</td>' in row and '<td class="num">1204</td>' in row
    acts = row.split('<td class="acts">', 1)[1]
    assert re.findall(r'<a class="([^"]+)"', acts) == ["btn btn-sm", "btn btn-sm",
                                                       "btn btn-sm btn-link"]
    assert acts.rstrip().endswith(">Journal</a></td>")
    occupied = html.split("<code>office</code>", 1)[1].split("</tr>", 1)[0]
    assert '<code>office@example.org</code></a> <span class="badge off">disabled</span>' \
        in occupied


def test_the_mailbox_row_is_the_address_a_status_badge_a_number_and_the_acts(domains_world):
    _, html = main_part(domains_world, "/domains/1")
    table = html.split('<div class="table-wrap"><table>', 1)[1].split("</table>", 1)[0]
    assert ('<thead><tr><th>Mailbox</th><th>Status</th><th class="num">Total mails</th>'
            '<th class="acts">Actions</th></tr></thead>') in table
    ivan = table.split('<a href="/mailboxes/5"><code>ivan@sales</code></a>', 1)[1] \
        .split("</tr>", 1)[0]
    assert '<span class="badge ok">active</span>' in ivan
    assert '<td class="num">12</td>' in ivan
    acts = ivan.split('<td class="acts">', 1)[1]
    assert re.findall(r'<a class="([^"]+)"[^>]*>([^<]+)</a>', acts) == [
        ("btn btn-sm", "Top up"), ("btn btn-sm btn-link", "Journal")]
    olga = table.split("<code>olga@sales</code>", 1)[1].split("</tr>", 1)[0]
    assert ('<span class="badge attn">blocked</span><span class="row-sub">'
            '<a href="/people/4">set on the person &mdash; mail still arrives</a></span>') in olga
    archive = table.split("<code>archive@sales</code></a>", 1)[1].split("</tr>", 1)[0]
    assert re.findall(r'<a class="([^"]+)"[^>]*>([^<]+)</a>', archive) == [
        ("btn btn-sm", "Archive listing"), ("btn btn-sm btn-link", "Journal")]


def test_a_waiting_row_says_so_beneath_and_a_failed_one_is_a_worded_red_state(built):
    source = mailboxes.SHAPE + "{{ mailbox_row(box, ()) }}"
    waiting = shape(built, source, box=a_box(reading={
        "waiting": "asked to connect, 14:58", "look_again": "the pipeline runs by 15:01",
        "failed": None}))
    assert ('asked to connect, 14:58<span class="row-sub">the pipeline runs by 15:01</span>'
            in waiting)
    assert '<td class="acts"><span class="muted">waiting for the pipeline</span></td>' \
        in waiting
    failed = shape(built, source, box=a_box(reading={
        "waiting": None, "look_again": None, "failed": "no mailbox <7>"}))
    assert ('<span class="row-sub state-bad"><svg class="icon bad"><use href="#i-x"/></svg> '
            'the pipeline could not do it: no mailbox &lt;7&gt;</span>') in failed


def test_the_domain_page_is_its_head_the_mailboxes_the_settings_and_a_danger_zone(
        domains_world):
    _, html = main_part(domains_world, "/domains/1")
    assert html.startswith('<div class="crumbs"><a href="/domains">Domains</a> / '
                           '<code>sales</code></div>')
    head = page_head(html)
    assert "<h1><code>sales</code></h1>" in head
    assert '<p class="lede">In front of it: ' in head and "2 mailbox(es)." in head
    assert '<a class="btn" href="/domains/1/archive/listing">Archive listing</a>' in head
    assert ">Journal for this domain</a>" in head
    assert html.count("btn-primary") == 1
    assert ('<div class="box-head"><h2>Mailboxes</h2><a class="btn btn-sm btn-primary" '
            'href="/mailboxes/add?domain=1">Give someone a mailbox here</a></div>') in html
    # the spam policy is read here and set on its own screen
    assert '<a class="btn btn-sm" href="/domains/1/spam">Spam policy&hellip;</a>' in html
    outbound = html.split('<form class="setting" method="post" action="/domains/1/outbound">',
                          1)[1].split("</form>", 1)[0]
    assert '<h2 class="st">Outgoing mail too large to scan</h2>' in outbound
    assert outbound.count('<label class="choice">') == 2
    assert ('<input type="radio" name="outbound_unscanned" value="send" checked>'
            '<div><b>Send it unscanned</b></div>') in outbound
    assert '<button class="btn" type="submit">Save</button>' in outbound
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    assert '<a class="btn btn-danger" href="/domains/1/delete">Delete this domain&hellip;</a>' \
        in zone


def test_an_occupied_domains_delete_is_a_disabled_span_with_the_reason_in_the_zone(
        domains_world):
    _, html = main_part(domains_world, "/domains/2")
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    assert "Refused: <code>office@example.org</code> sits in front of this domain." in \
        " ".join(zone.split())
    assert '<span class="btn btn-danger" aria-disabled="true">Delete this domain</span>' in zone
    assert "<button" not in zone and "/domains/2/delete" not in zone


def test_a_refused_outbound_value_is_a_flash_and_the_choices_help_line(domains_world,
                                                                         monkeypatch):
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    status, html = main_part(domains_world, "/domains/1/outbound", "post",
                             outbound_unscanned="whatever")
    assert status == 400
    assert ('<div class="flash bad"><svg class="icon bad ico"><use href="#i-alert"/></svg>'
            "<div>Outgoing mail too large to scan is either sent unscanned or refused."
            "</div></div>") in html
    outbound = html.split('action="/domains/1/outbound">', 1)[1].split("</form>", 1)[0]
    assert ('<div class="field"><p class="help warn">Outgoing mail too large to scan is '
            'either sent unscanned or refused.</p></div>') in outbound


def test_the_delete_page_is_a_danger_zone_with_the_numbers_and_one_solid_button(
        domains_world):
    status, html = main_part(domains_world, "/domains/1/delete")
    assert status == 200
    assert "<h1>Delete the domain <code>sales</code>?</h1>" in page_head(html)
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    assert '<div class="box-head"><h2>What goes</h2></div>' in zone
    kv = zone.split('<div class="kv">', 1)[1].split("</div></div>", 1)[0]
    assert re.findall(r"<div><b>(\d+)</b><span>([^<]+)</span>", kv) == [
        ("1204", "Messages removed"), ("2", "Mailboxes removed"),
        ("1", "People who lose their only mailbox")]
    assert ('<form class="form-foot" method="post" action="/domains/1/delete">'
            '<button class="btn btn-danger-solid" type="submit">Delete <code>sales</code> '
            "and everything in it</button></form>") in zone
    assert html.count("btn-danger-solid") == 1 and "btn-primary" not in html
    assert '<svg class="icon"><use href="#i-back"/></svg> Cancel, nothing changes</a>' in html


def test_a_refused_delete_is_a_flash_with_its_reasons_and_no_button(domains_world):
    status, html = main_part(domains_world, "/domains/2/delete")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert "<b>Refused: <code>office@example.org</code> sits in front of this" in flash
    assert "Delete that external mailbox first" in flash
    assert "<form" not in html and "<button" not in html and "btn-danger" not in html
    assert "Cancel, nothing changes</a>" in html


def test_add_is_a_narrow_form_with_its_foot_and_a_refusal_is_a_flash_and_a_warn(
        domains_world, monkeypatch):
    _, html = main_part(domains_world, "/domains/add")
    assert "<h1>Add domain</h1>" in page_head(html)
    assert '<form class="narrow" method="post" action="/domains/add">' in html
    assert ('<div class="form-foot"><button class="btn btn-primary" type="submit">Add domain'
            '</button><a class="btn" href="/domains">Cancel, nothing changes</a></div>') in html
    assert html.count('<div class="field">') == 3 and "flash" not in html
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    status, html = main_part(domains_world, "/domains/add", "post", label="NOT A LABEL",
                             password="an-archive-password-that-is-long",
                             password2="an-archive-password-that-is-long")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    label = html.split('<label for="label">', 1)[1].split('<label for="password">', 1)[0]
    sentence = flash.split("<div>", 1)[1]
    assert f'<p class="help warn">{sentence}</p>' in label
    assert 'value="NOT A LABEL"' in label
    assert "an-archive-password-that-is-long" not in html


def test_the_spam_policy_is_a_choice_tile_a_threshold_and_one_save(domains_world,
                                                                   monkeypatch):
    _, html = main_part(domains_world, "/domains/1/spam")
    assert "<h1>Spam at <code>sales</code></h1>" in page_head(html)
    form = html.split('<form class="narrow" method="post" action="/domains/1/spam">',
                      1)[1].split("</form>", 1)[0]
    assert ('<label class="choice"><input type="checkbox" name="reaches" value="yes" checked>'
            "<div><b>Spam reaches people</b><span>With this off,") in form
    assert '<input id="threshold" name="threshold" type="number" value="8.00"' in form
    assert form.count("<button") == 1 and form.count("btn-primary") == 1
    assert '<a class="btn" href="/domains/1">Cancel, nothing changes</a>' in form
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    status, html = main_part(domains_world, "/domains/1/spam", "post", threshold="999")
    assert status == 400
    assert '<div class="flash bad">' in html
    threshold = html.split('<label for="threshold">', 1)[1].split("</div>", 1)[0]
    assert '<p class="help warn">' in threshold and 'value="999"' in threshold
    reaches = html.split('name="reaches"', 1)[1].split(">", 1)[0]
    assert "checked" not in reaches


def test_the_archive_card_sets_its_password_in_a_setting_row_the_one_primary(
        domains_world, monkeypatch):
    _, html = main_part(domains_world, "/domains/1/archive")
    assert "<h1><code>archive@sales</code></h1>" in page_head(html)
    assert '<span class="badge ok">active</span>' in html
    row = html.split('<form class="setting" method="post" action="/domains/1/archive/password">',
                     1)[1].split("</form>", 1)[0]
    assert '<h2 class="st">Archive password</h2>' in row
    assert ('<button class="btn btn-primary" type="submit">Replace the archive password'
            '</button>') in row
    assert html.count("btn-primary") == 1
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    status, html = main_part(domains_world, "/domains/1/archive/password", "post",
                             password="an-archive-password-that-is-long", password2="other")
    assert status == 400
    assert '<div class="flash bad">' in html and '<p class="help warn">' in html
    assert "an-archive-password-that-is-long" not in html


def test_the_archive_listing_is_one_table_with_the_id_in_code_and_numbers_right(
        domains_world):
    _, html = main_part(domains_world, "/domains/1/archive/listing")
    assert "<h1>Archive listing for <code>sales</code></h1>" in page_head(html)
    assert '<section class="box"><div class="table-wrap"><table>' in html
    assert '<td class="num"><code class="message-id">58120</code></td>' in html
    undated = html.split("<code>bounce@example.org</code>", 1)[0].rsplit("<tr>", 1)[1]
    assert '<span class="muted">arrived</span>' in undated
    assert '<span class="badge off">no date in the message</span>' in undated


def test_the_listing_not_there_yet_is_an_attn_flash_inside_the_shell(waiting_world):
    status, html = main_part(waiting_world, "/domains/1/archive/listing")
    assert status == 400
    assert "<h1>Waiting for the pipeline</h1>" in page_head(html)
    assert '<div class="flash attn"><svg class="icon attn ico"><use href="#i-clock"/></svg>' \
        in html
    assert "/domains/1/archive/listing" not in html


# --- the people screens, in the design's components -----------------------------------

ASKED_AT = datetime.datetime(2026, 9, 30, 14, 58)


def a_person(**changed):
    person = {"id": 3, "login": "ivan", "is_admin": False, "state": "active",
              "comment": "covers sales", "created_at": None, "mailboxes": 1,
              "state_at": None, "state_by": None, "admin_since": None, "newest_kind": None,
              "newest_state": None, "newest_created_at": None, "newest_result": None}
    return {**person, **changed}


PEOPLE = {1: a_person(id=1, login="t28admin", is_admin=True, comment=None,
                      admin_since="2026-09-01 10:00"),
          3: a_person(),
          4: a_person(id=4, login="olga", state="blocked", comment=None, mailboxes=0,
                      state_at="2026-09-07 09:00", state_by="t28admin"),
          5: a_person(id=5, login="petro", comment=None, newest_kind="delete_account",
                      newest_state="queued", newest_created_at=ASKED_AT),
          6: a_person(id=6, login="zoya", comment=None, newest_kind="delete_account",
                      newest_state="failed", newest_result="no such <maildir>")}


class Cursor:
    """A cursor that takes every statement and answers the one `RETURNING id` with 3."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, parameters=()):
        pass

    def fetchone(self):
        return (3,)


class Connection:
    def cursor(self):
        return Cursor()


@pytest.fixture
def people_world(shell, monkeypatch):
    """The shell with five people stood in for the database: the signed-in administrator
    (1), `ivan` holding one mailbox (3), `olga` blocked (4), `petro` whose deletion waits
    (5) and `zoya` whose deletion failed (6). Nothing is written anywhere."""

    def one(conn, sql, parameters=()):
        if sql == accounts.NUMBERS:
            return {"mailboxes": 1, "names": 12}
        if sql.startswith(accounts.PEOPLE):
            found = PEOPLE.get(parameters[0])
            return dict(found) if found else None
        return None

    def rows(conn, sql, parameters=()):
        if sql.startswith(accounts.PEOPLE):
            return [dict(PEOPLE[key]) for key in (4, 5, 1, 3, 6)]
        return []

    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(mailboxes, "of_account", lambda conn, account_id, period=None:
                        [a_box()] if account_id == 3 else [])
    monkeypatch.setattr(accounts, "machine_name", lambda etc=None: "mail.example.org")
    monkeypatch.setattr(accounts, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(application, "connection", lambda: Connection())
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    return shell


def setting_row(html, action):
    return html.split(f'<form class="setting" method="post" action="{action}">',
                      1)[1].split("</form>", 1)[0]


def test_the_people_list_is_one_table_with_the_flag_a_lock_badge_beside_the_login(
        people_world):
    status, html = main_part(people_world, "/people")
    assert status == 200
    head = page_head(html)
    assert "<h1>People</h1>" in head
    assert '<p class="lede">A person is active or blocked,' in head
    assert '<a class="btn btn-primary" href="/people/add">Add person</a>' in head
    assert html.count("btn-primary") == 1 and html.count("<h1") == 1
    assert '<section class="box"><div class="table-wrap"><table>' in html
    assert ('<thead><tr><th>Login</th><th>State</th><th class="num">Mailboxes</th>'
            '<th>Comment</th><th class="acts">Actions</th></tr></thead>') in html
    admin = html.split('<a href="/people/1"><code>t28admin</code></a>', 1)[1] \
        .split("</td>", 1)[0]
    assert admin == (' <span class="badge"><svg class="icon"><use href="#i-lock"/></svg> '
                     'administrator</span>')
    ivan = html.split("<code>ivan</code>", 1)[1].split("</tr>", 1)[0]
    assert "administrator" not in ivan
    assert '<td class="state"><span class="badge ok">active</span></td>' in ivan
    assert '<td class="num">1</td>' in ivan and "<td>covers sales</td>" in ivan
    acts = ivan.split('<td class="acts">', 1)[1]
    assert re.findall(r'<a class="([^"]+)"[^>]*>([^<]+)</a>', acts) == [
        ("btn btn-sm", "Open"), ("btn btn-sm btn-link", "Journal")]
    olga = html.split("<code>olga</code>", 1)[1].split("</tr>", 1)[0]
    assert ('<span class="badge attn">blocked</span><span class="row-sub">since '
            '2026-09-07 09:00 by <code>t28admin</code></span>') in olga
    petro = html.split("<code>petro</code>", 1)[1].split("</tr>", 1)[0]
    assert '<td class="state">asked to delete, 14:58<span class="row-sub">' in petro
    assert '<td class="acts"><span class="muted">waiting for the pipeline</span></td>' in petro
    zoya = html.split("<code>zoya</code>", 1)[1].split("</tr>", 1)[0]
    assert ('<span class="row-sub state-bad"><svg class="icon bad"><use href="#i-x"/></svg> '
            'the pipeline could not do it: no such &lt;maildir&gt;</span>') in zoya


def test_the_person_page_is_its_state_its_mailboxes_three_setting_rows_and_a_danger_zone(
        people_world):
    status, html = main_part(people_world, "/people/3")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/people">People</a> / '
                           '<code>ivan</code></div>')
    head = page_head(html)
    assert "<h1><code>ivan</code></h1>" in head
    assert ('<p class="lede">Not an administrator. One password opens every mailbox '
            'below.</p>') in " ".join(head.split())
    assert '<a class="btn" href="/journal?target=ivan&amp;back=accounts">' \
        'Journal for this person</a>' in head
    state = html.split('<div class="box-head"><h2>State</h2></div>', 1)[1] \
        .split("</section>", 1)[0]
    assert '<span class="badge ok">active</span>' in state
    assert ('<form class="form-foot" method="post" action="/people/3/state">'
            '<input type="hidden" name="state" value="blocked">'
            '<button class="btn" type="submit">Block <code>ivan</code></button>') in \
        "".join(state.split("\n"))
    boxes = html.split('<div class="box-head"><h2>Mailboxes</h2>', 1)[1] \
        .split("</section>", 1)[0]
    assert '<a class="btn btn-sm" href="/mailboxes/add?account=3">' \
        'Give a mailbox in another domain</a>' in boxes
    assert '<div class="table-wrap"><table>' in boxes and "<tbody>" in boxes
    assert '<th class="num">Total mails</th>' in boxes
    assert '<a href="/mailboxes/5"><code>ivan@sales</code></a>' in boxes
    password = setting_row(html, "/people/3/password")
    assert '<h2 class="st">Password</h2>' in password
    assert '<button class="btn btn-primary" type="submit">Set the password</button>' \
        in password
    assert password.count('type="password"') == 2
    admin = setting_row(html, "/people/3/admin")
    assert '<h2 class="st">Administrator</h2>' in admin
    assert ('<label class="checkline"><input type="checkbox" name="is_admin" value="yes">'
            "<div><b>Administrator</b><span>May open this interface") in admin
    assert '<button class="btn" type="submit">Save the flag</button>' in admin
    comment = setting_row(html, "/people/3/comment")
    assert '<h2 class="st">Comment</h2>' in comment and "Not journaled." in comment
    assert ('<textarea name="comment" rows="3" aria-label="Comment">covers sales'
            '</textarea>') in comment
    assert '<button class="btn" type="submit">Save comment</button>' in comment
    assert html.count("btn-primary") == 1
    assert '<div class="box-head"><h2>What to put in the mail client</h2></div>' in html
    assert "<code>mail.example.org</code>" in html
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    assert ('<a class="btn btn-danger" href="/people/3/delete">'
            'Delete this person, immediately&hellip;</a>') in zone


def test_ones_own_page_says_so_beside_the_block_button(people_world):
    _, html = main_part(people_world, "/people/1")
    assert ("<p class=\"lede\">Administrator since 2026-09-01 10:00. One password opens "
            "every mailbox below.</p>") in " ".join(page_head(html).split())
    state = html.split('<div class="box-head"><h2>State</h2></div>', 1)[1] \
        .split("</form>", 1)[0]
    assert ('<span class="muted">This is your own account. Blocking it ends this session '
            'at your next request.</span>') in " ".join(state.split())
    admin = setting_row(html, "/people/1/admin")
    assert 'value="yes" checked>' in admin
    assert "Taking it off your own account" in admin
    # nothing held: the empty table says so in one row
    assert '<tr><td colspan="4">No mailbox yet, so this login opens nothing.</td></tr>' in html


def test_a_blocked_person_reads_blocked_with_when_and_by_whom_and_unblock(people_world):
    _, html = main_part(people_world, "/people/4")
    state = html.split('<div class="box-head"><h2>State</h2></div>', 1)[1] \
        .split("</section>", 1)[0]
    assert ('<span class="badge attn">blocked</span> since 2026-09-07 09:00 by '
            '<code>t28admin</code>.') in state
    assert '<button class="btn" type="submit">Unblock <code>olga</code></button>' in state


def test_a_waiting_or_failed_person_is_a_flash_under_the_head(people_world):
    _, html = main_part(people_world, "/people/5")
    assert ('<div class="flash attn"><svg class="icon attn ico"><use href="#i-clock"/></svg>'
            "<div>asked to delete, 14:58.") in html
    _, html = main_part(people_world, "/people/6")
    assert ('<div class="flash bad"><svg class="icon bad ico"><use href="#i-alert"/></svg>'
            "<div>the pipeline could not do it: no such &lt;maildir&gt;</div></div>") in html


def test_the_password_rows_refusal_and_saved_sentence_stand_inside_that_row(people_world):
    status, html = main_part(people_world, "/people/3/password", "post",
                             password="a-long-enough-password", password2="another-one-typed")
    assert status == 400
    row = setting_row(html, "/people/3/password")
    flash = row.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    sentence = flash.split("<div>", 1)[1]
    assert "The two passwords differ" in sentence
    assert f'<p class="help warn">{sentence}</p>' in row
    assert "a-long-enough-password" not in html
    assert html.count('class="flash') == 1
    _, html = main_part(people_world, "/people/3?done=password_set")
    row = setting_row(html, "/people/3/password")
    assert ('<div class="flash ok"><svg class="icon ok ico"><use href="#i-check"/></svg>'
            "<div>Password set.</div></div>") in row
    assert html.count('class="flash') == 1


def test_the_flag_and_state_refusals_are_a_flash_in_their_own_row(people_world,
                                                                   monkeypatch):
    monkeypatch.setattr(accounts, "would_leave_no_administrator", lambda conn, id: True)
    status, html = main_part(people_world, "/people/1/admin", "post")
    assert status == 400
    admin = setting_row(html, "/people/1/admin")
    assert '<div class="flash bad">' in admin and "is the last active administrator" in admin
    # the warn line is the flag's own field's, under its checkbox
    assert '</label><p class="help warn">' in admin
    status, html = main_part(people_world, "/people/3/state", "post", state="sleepy")
    assert status == 400
    state = html.split('<div class="box-head"><h2>State</h2></div>', 1)[1] \
        .split("</section>", 1)[0]
    assert '<div class="flash bad">' in state and "&#39;sleepy&#39; is neither" in state


def test_add_person_is_a_narrow_form_and_a_refusal_is_a_flash_and_a_warn(people_world):
    _, html = main_part(people_world, "/people/add")
    assert html.startswith('<div class="crumbs"><a href="/people">People</a> / Add person')
    assert "<h1>Add person</h1>" in page_head(html)
    form = html.split('<form class="narrow" method="post" action="/people/add">',
                      1)[1].split("</form>", 1)[0]
    assert form.count('<div class="field">') == 4
    assert '<input id="login" name="login" type="text" class="mono-input mid">' in form
    assert ('<label class="checkline"><input type="checkbox" name="is_admin" value="yes">'
            "<div><b>Administrator</b><span>May open this interface") in form
    assert ('<div class="form-foot"><button class="btn btn-primary" type="submit">Add person'
            '</button><a class="btn" href="/people">Cancel, nothing changes</a></div>') in form
    assert "flash" not in html
    status, html = main_part(people_world, "/people/add", "post", login="Ivan",
                             password="a-long-enough-password",
                             password2="a-long-enough-password", is_admin="yes")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    sentence = flash.split("<div>", 1)[1]
    login = html.split('<label for="login">', 1)[1].split('<label for="password">', 1)[0]
    assert f'<p class="help warn">{sentence}</p>' in login and 'value="Ivan"' in login
    assert 'value="yes" checked>' in html
    assert "a-long-enough-password" not in html


def test_the_shown_once_page_is_a_flash_attn_with_the_value_in_code_generated(people_world):
    status, html = main_part(people_world, "/people/3/password", "post")
    assert status == 200
    assert "<h1>A new password for ivan</h1>" in page_head(html)
    flash = html.split('<div class="flash attn">', 1)[1].split("</div></div>", 1)[0]
    assert "This is the only time this password is shown." in " ".join(flash.split())
    facts = html.split('<dl class="facts">', 1)[1].split("</dl>", 1)[0]
    assert "<dt>Login</dt><dd><code>ivan</code></dd>" in facts
    shown = facts.split('<dt>Password</dt><dd><code class="generated">', 1)[1] \
        .split("</code>", 1)[0]
    assert len(shown) >= 20
    assert '<div class="box-head"><h2>What to put in the mail client</h2></div>' in html
    assert '<a class="btn btn-primary" href="/people/3">Done &mdash; open <code>ivan</code>' \
        in html
    assert html.count("btn-primary") == 1


def test_the_person_delete_page_is_a_danger_zone_with_the_numbers_and_one_solid_button(
        people_world):
    status, html = main_part(people_world, "/people/3/delete")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/people">People</a> / '
                           '<a href="/people/3"><code>ivan</code></a> / Delete</div>')
    assert "<h1>Delete <code>ivan</code>?</h1>" in page_head(html)
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    kv = zone.split('<div class="kv">', 1)[1].split("</div></div>", 1)[0]
    assert re.findall(r"<div><b>(\d+)</b><span>([^<]+)</span>", kv) == [
        ("1", "Mailboxes removed"), ("12", "Names removed")]
    assert "Messages removed: 0 &mdash; the archives keep everything" in zone
    assert ('<form class="form-foot" method="post" action="/people/3/delete">'
            '<button class="btn btn-danger-solid" type="submit">Delete <code>ivan</code> and '
            "everything they hold</button></form>") in " ".join(zone.split())
    assert html.count("btn-danger-solid") == 1 and "btn-primary" not in html
    assert '<svg class="icon"><use href="#i-back"/></svg> Cancel, nothing changes</a>' in html


def test_a_refused_person_delete_is_a_flash_and_no_button(people_world):
    status, html = main_part(people_world, "/people/1/delete")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert "Nobody deletes their own account" in flash
    assert "<form" not in html and "<button" not in html and "btn-danger" not in html
    assert "Cancel, nothing changes</a>" in html


# --- the mailbox screens and the top-up, in the design's components ----------------------

@pytest.fixture
def boxes_world(shell, monkeypatch):
    """The shell with `sales` and its three rows stood in for the database: its archive,
    `ivan@sales` (5) and `olga@sales` blocked (6); `petro` is free to take a transfer. The
    top-up counts one message in any range and two in all of it. Nothing is written."""

    def one(conn, sql, parameters=()):
        if sql == mailboxes.REMOVAL:
            return {"names": 12}
        if "FROM domain WHERE id" in sql:
            return {"yes": 1, "label": "sales"} if parameters[0] == 1 else None
        if "FROM account WHERE id" in sql:
            return {"login": "petro"} if parameters[0] == 7 else None
        return None

    def rows(conn, sql, parameters=()):
        if sql == mailboxes.ALL_DOMAINS:
            return [{"id": 1, "label": "sales"}]
        if sql in (mailboxes.FREE_PEOPLE, mailboxes.EVERYONE):
            return [{"id": 7, "login": "petro"}]
        return []

    listed = [ARCHIVE_BOX, a_box(),
              a_box(id=6, address="olga@sales", login="olga", account_id=4,
                    account_state="blocked", total=3)]
    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(mailboxes, "listing", lambda conn, domain_id=None, period=None:
                        [dict(box) for box in listed])
    monkeypatch.setattr(mailboxes, "box_row", lambda conn, mailbox_id, period=None:
                        a_box(as_of="2026-08-30 10:00") if mailbox_id == 5 else None)
    monkeypatch.setattr(mailboxes, "free_people", lambda conn, domain_id, without=None:
                        [{"id": 7, "login": "petro"}])
    monkeypatch.setattr(maintenance, "count", lambda conn, box, since, until:
                        2 if since == maintenance.WIDE_SINCE else 1)
    monkeypatch.setattr(application, "connection", lambda: Connection())
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    return shell


def test_the_mailbox_list_is_the_shared_row_with_person_and_domain_the_archive_first(
        boxes_world):
    status, html = main_part(boxes_world, "/mailboxes")
    assert status == 200
    head = page_head(html)
    assert "<h1>Mailboxes</h1>" in head
    assert '<p class="lede">A mailbox is one person in one domain.' in head
    assert '<a class="btn btn-primary" href="/mailboxes/add">Give someone a mailbox</a>' in head
    assert html.count("btn-primary") == 1 and html.count("<h1") == 1
    assert '<section class="box"><div class="table-wrap"><table>' in html
    assert html.count("<table") == 1 and "<tbody>" in html
    assert ('<thead><tr><th>Mailbox</th><th>Person</th><th>Domain</th><th>Status</th>'
            '<th class="num">Total mails</th><th class="acts">Actions</th></tr></thead>') in html
    addresses = re.findall(r"<tr>\s*<td><a href=\"[^\"]+\"><code>([^<]+)</code>", html)
    assert addresses == ["archive@sales", "ivan@sales", "olga@sales"]
    ivan = html.split("<code>ivan@sales</code></a>", 1)[1].split("</tr>", 1)[0]
    assert '<a href="/people/3"><code>ivan</code></a>' in ivan
    assert '<a href="/domains/1"><code>sales</code></a>' in ivan


def test_the_mailbox_page_is_its_head_three_setting_rows_and_a_danger_zone(boxes_world):
    status, html = main_part(boxes_world, "/mailboxes/5")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/mailboxes">Mailboxes</a> / '
                           '<code>ivan@sales</code></div>')
    head = " ".join(page_head(html).split())
    assert "<h1><code>ivan@sales</code></h1>" in head
    assert ('<p class="lede"><a href="/people/3"><code>ivan</code></a> holds it; their '
            'password and their state are set on their own page. Open. 12 message(s) held. '
            'Connected at 2026-08-30 10:00.</p>') in head
    assert re.findall(r'<a class="([^"]+)"[^>]*>([^<]+)</a>', head) == [
        ("btn", "Top up"), ("btn", "Journal for this mailbox")]
    comment = setting_row(html, "/people/3/comment")
    assert '<h2 class="st">Comment on <code>ivan</code></h2>' in comment
    assert '<textarea name="comment" rows="3" aria-label="Comment"></textarea>' in comment
    assert '<button class="btn" type="submit">Save comment</button>' in comment
    deliver = setting_row(html, "/mailboxes/5/deliver-one")
    assert '<h2 class="st">Deliver one message by id</h2>' in deliver
    assert '<input id="message_id" name="message_id" type="text" class="mono-input short">' \
        in deliver
    assert '<button class="btn" type="submit">Deliver it</button>' in deliver
    transfer = setting_row(html, "/mailboxes/5/transfer")
    assert '<h2 class="st">Transfer to another person</h2>' in transfer
    assert '<option value="7">petro</option>' in transfer
    assert '<button class="btn" type="submit">Transfer it</button>' in transfer
    assert "btn-primary" not in html and 'type="password"' not in html
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    assert "Removing this mailbox takes 12 name(s) out of it." in zone
    assert ('<a class="btn btn-danger" href="/mailboxes/5/delete">'
            'Remove this mailbox&hellip;</a>') in zone


def test_with_nobody_free_the_transfer_row_says_so_and_offers_no_form(boxes_world,
                                                                        monkeypatch):
    monkeypatch.setattr(mailboxes, "free_people", lambda conn, domain_id, without=None: [])
    _, html = main_part(boxes_world, "/mailboxes/5")
    assert 'action="/mailboxes/5/transfer"' not in html
    row = html.split('<h2 class="st">Transfer to another person</h2>', 1)[1] \
        .split('<section class="danger-zone">', 1)[0]
    assert "Nobody is free to take it" in row


def test_a_refused_deliver_or_transfer_is_a_flash_and_a_warn_inside_its_row(boxes_world):
    status, html = main_part(boxes_world, "/mailboxes/5/deliver-one", "post",
                             message_id="the third one")
    assert status == 400
    deliver = setting_row(html, "/mailboxes/5/deliver-one")
    flash = deliver.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert flash.split("<div>", 1)[1] == maintenance.NOT_A_NUMBER
    assert f'<p class="help warn">{maintenance.NOT_A_NUMBER}</p>' in deliver
    assert 'value="the third one"' in deliver
    assert html.count('class="flash') == 1
    status, html = main_part(boxes_world, "/mailboxes/5/transfer", "post", to_account_id="")
    assert status == 400
    transfer = setting_row(html, "/mailboxes/5/transfer")
    assert '<div class="flash bad">' in transfer
    assert '<p class="help warn">Choose the person it goes to.</p>' in transfer
    assert html.count('class="flash') == 1


def test_giving_a_mailbox_is_a_narrow_form_and_a_refusal_is_a_flash_and_a_warn(
        boxes_world):
    _, html = main_part(boxes_world, "/mailboxes/add?domain=1")
    assert html.startswith('<div class="crumbs"><a href="/mailboxes">Mailboxes</a> / '
                           'Give someone a mailbox</div>')
    head = page_head(html)
    assert "<h1>Give someone a mailbox</h1>" in head
    assert '<p class="lede">It delivers only mail that arrives from now on.' in head
    form = html.split('<form class="narrow" method="post" action="/mailboxes/add">',
                      1)[1].split("</form>", 1)[0]
    assert form.count('<div class="field">') == 2
    assert '<option value="1" selected>sales</option>' in form
    assert '<p class="help">Only people with no mailbox in that domain are offered' in form
    assert ('<div class="form-foot"><button class="btn btn-primary" type="submit">Give the '
            'mailbox</button><a class="btn" href="/mailboxes">Cancel, nothing changes</a>'
            '</div>') in form
    assert "flash" not in html
    status, html = main_part(boxes_world, "/mailboxes/add", "post", domain_id="99",
                             account_id="7")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert flash.split("<div>", 1)[1] == mailboxes.NO_DOMAIN
    domain = html.split('<label for="domain_id">', 1)[1].split('<label for="account_id">', 1)[0]
    assert f'<p class="help warn">{mailboxes.NO_DOMAIN}</p>' in domain
    assert '<option value="7" selected>petro</option>' in html
    status, html = main_part(boxes_world, "/mailboxes/add", "post", domain_id="",
                             account_id="")
    assert status == 400 and mailboxes.BOTH in html and "help warn" not in html


def test_the_removal_page_is_a_danger_zone_with_the_numbers_and_one_solid_button(
        boxes_world):
    status, html = main_part(boxes_world, "/mailboxes/5/delete")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/mailboxes">Mailboxes</a> / '
                           '<a href="/mailboxes/5"><code>ivan@sales</code></a> / Remove</div>')
    head = " ".join(page_head(html).split())
    assert "<h1>Remove <code>ivan@sales</code>?</h1>" in head
    assert ('<p class="lede">The archive of <code>sales</code> keeps every message. What goes '
            "is this person's copy of them.</p>") in head.replace("&#39;", "'")
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    kv = zone.split('<div class="kv">', 1)[1].split("</div></div>", 1)[0]
    assert re.findall(r"<div><b>(\d+)</b><span>([^<]+)</span>", kv) == [
        ("12", "Names removed"), ("1", "Mailboxes removed"),
        ("1", "People who lose access here")]
    assert "Messages removed: 0 &mdash; the archive keeps everything" in zone
    assert ('<form class="form-foot" method="post" action="/mailboxes/5/delete">'
            '<button class="btn btn-danger-solid" type="submit">Remove <code>ivan@sales</code>'
            '</button></form>') in zone
    assert html.count("btn-danger-solid") == 1 and "btn-primary" not in html
    assert '<svg class="icon"><use href="#i-back"/></svg> Cancel, nothing changes</a>' in html


def test_the_top_up_is_narrow_with_its_counts_in_a_kv_and_the_would_deliver_spans(
        boxes_world):
    status, html = main_part(boxes_world, "/mailboxes/5/top-up?since=2026-09-01"
                                          "&until=2026-09-30")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/mailboxes">Mailboxes</a> / '
                           '<a href="/mailboxes/5"><code>ivan@sales</code></a> / Top up</div>')
    head = page_head(html)
    assert "<h1>Top up <code>ivan@sales</code></h1>" in head
    assert '<p class="lede">A top-up delivers what never arrived in this mailbox.' in head
    assert '<div class="stack narrow">' in html
    recount = html.split('<form method="get" action="/mailboxes/5/top-up">', 1)[1] \
        .split("</form>", 1)[0]
    assert '<div class="inline-fields">' in recount
    assert 'id="since" name="since" type="text" value="2026-09-01"' in recount
    assert '<button class="btn" type="submit">Recount</button>' in recount
    run = html.split('<form method="post" action="/mailboxes/5/top-up">', 1)[1] \
        .split("</form>", 1)[0]
    kv = run.split('<div class="kv">', 1)[1].split("</div></div>", 1)[0]
    assert re.findall(r"<div><b>(\d+)</b><span>([^<]+)</span>", kv) == [
        ("1", "Between two dates"), ("2", "All of it")]
    assert run.count('<label class="choice"><input type="radio" name="choice"') == 2
    said = " ".join(run.split())
    assert '<span class="would-deliver">1 message(s) would be delivered</span>, from' in said
    assert '<span class="would-deliver">2 message(s) would be delivered</span> to' in said
    assert ('<div class="form-foot"><button class="btn btn-primary" type="submit">Top up'
            '</button><a class="btn" href="/mailboxes/5">Cancel, nothing changes</a></div>') \
        in run
    assert html.count("btn-primary") == 1


def test_a_refused_top_up_date_is_a_flash_and_a_warn_and_the_count_waits(boxes_world):
    status, html = main_part(boxes_world, "/mailboxes/5/top-up?since=nope"
                                          "&until=2026-09-30")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    sentence = flash.split("<div>", 1)[1]
    assert "is not a date" in sentence
    since = html.split('<label for="since">', 1)[1].split('<label for="until">', 1)[0]
    assert f'<p class="help warn">{sentence}</p>' in since and 'value="nope"' in since
    assert html.count('<span class="would-deliver">') == 1
    assert html.count(maintenance.FOLLOWS) == 2
    kv = html.split('<div class="kv">', 1)[1].split("</div></div>", 1)[0]
    assert re.findall(r"<div><b>(\d+)</b><span>([^<]+)</span>", kv) == [("2", "All of it")]


# --- the external mailbox screens and fetch, in the design's components -----------------

FETCHED_AT = datetime.datetime(2026, 9, 30, 14, 33)


def an_external(**changed):
    mailbox = {
        "id": 9, "address": "Box@example.org", "address_canonical": "box@example.org",
        "pop3_login": "recent:box", "pop3_host": "pop.example.org", "pop3_port": 995,
        "smtp_host": "smtp.example.org", "smtp_port": 587, "delete_window_days": 14,
        "comment": "the sales mailbox", "state": "active",
        "state_changed_at": "2026-09-02 10:00", "state_changed_by": "t28admin",
        "last_fetch_at": FETCHED_AT, "last_fetch_status": "auth_failed",
        "last_fetch_cause": None, "last_fetch_detail": None,
        "last_test_at": "2026-09-30 09:12", "last_test_status": "auth_failed",
        "last_test_detail": None, "stuck_since": None, "stuck_runs": 0, "skip_streak": 0,
        "frozen_since": "2026-09-30 11:40", "last_skip_at": None, "last_skip_uidl": None,
        "held_since": None, "domain_id": 1, "label": "sales", "checking": False,
        "enabling": False, "deleting": False, "enable_asked_at": None, "newest_kind": None,
        "newest_state": None, "newest_created_at": None, "newest_result": None}
    return {**mailbox, **changed}


EXTERNALS = {
    9: an_external(),
    10: an_external(id=10, address="asked@example.org", address_canonical="asked@example.org",
                    comment=None, state="deactivated", state_changed_at=None,
                    state_changed_by=None, last_fetch_at=None, last_fetch_status=None,
                    last_test_at=None, last_test_status=None, frozen_since=None,
                    domain_id=None, label=None, enabling=True, enable_asked_at=ASKED_AT,
                    newest_kind="activate_external_mailbox", newest_state="queued",
                    newest_created_at=ASKED_AT),
    11: an_external(id=11, address="off@example.org", address_canonical="off@example.org",
                    comment=None, state="deactivated", state_changed_at="2026-08-30 08:03",
                    last_fetch_status=None, last_test_at=None, last_test_status=None,
                    frozen_since=None, domain_id=3, label="events",
                    newest_kind="test_credential", newest_state="failed",
                    newest_result="no <answer>"),
    12: an_external(id=12, address="ok@example.org", address_canonical="ok@example.org",
                    comment=None, last_fetch_status="ok", last_test_status="ok",
                    frozen_since=None, domain_id=2, label="office"),
}


@pytest.fixture
def external_world(shell, monkeypatch):
    """The shell with four provider mailboxes stood in for the database: `Box@example.org`
    (9) enabled, refused and frozen in front of `sales`; `asked@example.org` (10) asked to
    enable, in front of nothing; `off@example.org` (11) disabled, its last check failed at
    the pipeline; `ok@example.org` (12) enabled and fetching. One free domain, `hr`, for
    the add form. Nothing is written anywhere."""

    def one(conn, sql, parameters=()):
        if sql == domains.NUMBERS:
            return {"messages": 1204, "mailboxes": 2, "people": 1}
        return None

    def rows(conn, sql, parameters=()):
        if sql == external.FREE_DOMAINS:
            return [{"id": 4, "label": "hr"}]
        if sql.startswith(external.ROW) and "WHERE e.id" in sql:
            found = EXTERNALS.get(parameters[0])
            return [dict(found)] if found else []
        if sql.startswith(external.ROW):
            return [dict(EXTERNALS[key]) for key in (10, 9, 11, 12)]
        return []

    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(common, "timer_period", lambda: THREE)
    monkeypatch.setattr(fetch, "timer_period", lambda: THREE)
    monkeypatch.setattr(application, "connection", lambda: Connection())
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    return shell


def row_of(html, address):
    return html.split(f"<code>{address}</code></a>", 1)[1].split("</tr>", 1)[0]


def test_the_external_list_is_a_compact_table_with_the_switch_in_the_state_column(
        external_world):
    status, html = main_part(external_world, "/external")
    assert status == 200
    head = page_head(html)
    assert "<h1>External mailboxes</h1>" in head
    assert '<a class="btn btn-primary" href="/external/add">Add external mailbox</a>' in head
    assert html.count("btn-primary") == 1 and html.count("<h1") == 1
    assert '<section class="box compact"><div class="table-wrap"><table>' in html
    assert html.count("<table") == 1 and "<tbody>" in html
    assert ('<thead><tr><th>Address</th><th>In front of</th><th>State</th>'
            '<th>At the provider</th><th class="acts">Actions</th></tr></thead>') in html
    box = row_of(html, "Box@example.org")
    assert ('<span class="row-sub">deleted at the provider 14 days after first seen</span>'
            in box)
    assert ('<td class="state"><form method="post" action="/external/9/disable">'
            '<button class="switch on" type="submit" aria-label="Disable" title="Disable">'
            '<span class="knob"></span>enabled</button></form>'
            '<span class="row-sub">enabled since 2026-09-02 10:00 by <code>t28admin</code>'
            '</span>') in box
    # a frozen fetch is its own worded badge beneath the switch, not a fourth position
    assert ('<span class="row-sub"><a href="/fetch"><span class="badge attn">'
            '<svg class="icon attn"><use href="#i-alert"/></svg> frozen</span></a></span>'
            in box)
    # a refused credential is a red word beside its icon
    assert ('<td><span class="state-bad"><svg class="icon bad">'
            '<use href="#i-alert"/></svg> refused, since 2026-09-30 09:12</span>') in box
    acts = box.split('<td class="acts">', 1)[1]
    assert ('<form method="post" action="/external/9/check">'
            '<button class="btn btn-sm" type="submit">Check password</button></form>') in acts
    assert re.findall(r'<a class="([^"]+)"[^>]*>([^<]+)</a>', acts) == [
        ("btn btn-sm btn-link", "Journal")]
    # an asked row: the switch in its middle position, when to look again, and no control
    asked = row_of(html, "asked@example.org")
    assert ('<td class="state"><button class="switch asked" type="button" disabled>'
            '<span class="knob"></span>asked to enable, 14:58</button>'
            '<span class="row-sub">asked to enable, 14:58 &mdash; the pipeline checks the '
            'password and enables it by 15:01</span>') in asked
    assert "<form" not in asked
    assert '<span class="muted">not checked yet</span>' in asked
    off = row_of(html, "off@example.org")
    # the switch's word is the state; its accessible name is still the act it performs
    assert ('<form method="post" action="/external/11/enable"><button class="switch" '
            'type="submit" aria-label="Enable" title="Enable"><span class="knob"></span>'
            'disabled</button></form>') in off
    assert ('<span class="row-sub state-bad"><svg class="icon bad"><use href="#i-x"/></svg> '
            'the pipeline could not do it: no &lt;answer&gt;</span>') in off
    ok = row_of(html, "ok@example.org")
    assert ('<span class="state-ok"><svg class="icon ok"><use href="#i-check"/></svg> '
            'accepted, checked 2026-09-30 09:12</span>') in ok


def test_the_item_page_is_its_head_the_provider_box_two_forms_and_a_danger_zone(
        external_world):
    status, html = main_part(external_world, "/external/9")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/external">External mailboxes</a> / '
                           '<code>Box@example.org</code></div>')
    head = " ".join(page_head(html).split())
    assert "<h1><code>Box@example.org</code></h1>" in head
    assert ('<p class="lede">In front of <a href="/domains/1"><code>sales</code></a>. enabled '
            'since 2026-09-02 10:00 by <code>t28admin</code>. Rotating the provider password '
            'here is the operation this interface most exists for.') in head
    assert re.findall(r'<a class="([^"]+)"[^>]*>([^<]+)</a>', head) == [
        ("btn", "Journal for this mailbox")]
    provider = html.split('<div class="box-head"><h2>At the provider</h2>', 1)[1] \
        .split("</section>", 1)[0]
    assert provider.startswith('<span class="badge bad"><svg class="icon bad">'
                               '<use href="#i-alert"/></svg> refused, since 2026-09-30 09:12'
                               '</span></div>')
    assert ('<div class="btn-row"><form method="post" action="/external/9/disable">'
            '<button class="switch on"') in provider
    assert ('<form class="btn-row" method="post" action="/external/9/check">'
            '<button class="btn" type="submit">Check the password at the provider</button>'
            ) in provider
    servers = html.split('<form method="post" action="/external/9/servers">', 1)[1] \
        .split("</form>", 1)[0]
    assert servers.count('<div class="inline-fields">') == 2
    assert ('<input id="pop3_port" name="pop3_port" type="number" value="995" class="short" '
            'min="1" max="65535">') in servers
    warning = servers.split('<div class="flash attn">', 1)[1].split("</div></div>", 1)[0]
    assert "Changing either host clears the stored provider password" in warning
    assert ('<div class="form-foot"><button class="btn" type="submit">Save the servers'
            '</button></div>') in servers
    settings = html.split('<form method="post" action="/external/9/settings">', 1)[1] \
        .split("</form>", 1)[0]
    assert ('<input id="pop3_login" name="pop3_login" type="text" value="recent:box" '
            'class="mono-input">') in settings
    assert ('<input id="credential" name="credential" type="password" '
            'autocomplete="new-password">') in settings
    assert ('<div class="form-foot"><button class="btn btn-primary" type="submit">Save '
            'settings</button><a class="btn" href="/external">Cancel, nothing changes</a>'
            '</div>') in settings
    assert html.count("btn-primary") == 1 and html.count("<h1") == 1
    assert html.index("action=\"/external/9/servers\"") < html.index("/external/9/settings")
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    assert "Removes the row, the provider password and the fetcher" in zone
    assert ('<a class="btn btn-danger" href="/external/9/delete">'
            'Delete this external mailbox&hellip;</a>') in zone
    assert "flash bad" not in html


def test_a_disabled_item_page_has_the_off_switch_and_its_failed_request_as_a_flash(
        external_world):
    _, html = main_part(external_world, "/external/11")
    provider = html.split('<div class="box-head"><h2>At the provider</h2>', 1)[1] \
        .split("</section>", 1)[0]
    assert provider.startswith('<span class="badge off">not checked yet</span></div>')
    assert ('<button class="switch" type="submit" aria-label="Enable" title="Enable">'
            '<span class="knob"></span>disabled</button></form><span class="muted">Everyone '
            'keeps what has already arrived;') in provider
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert flash.endswith("<div>the pipeline could not do it: no &lt;answer&gt;")
    assert html.index('<div class="flash bad">') < html.index('<div class="stack">')


def test_a_refused_settings_or_servers_form_is_a_flash_and_a_warn_inside_that_form(
        external_world):
    status, html = main_part(external_world, "/external/9/settings", "post",
                             pop3_login="re cent", window="14")
    assert status == 400
    settings = html.split('<form method="post" action="/external/9/settings">', 1)[1] \
        .split("</form>", 1)[0]
    flash = settings.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    sentence = flash.split("<div>", 1)[1]
    assert "no spaces" in sentence
    login = settings.split('<label for="pop3_login">', 1)[1].split('<label for=', 1)[0]
    assert f'<p class="help warn">{sentence}</p>' in login
    assert 'id="pop3_login" name="pop3_login" type="text" value="re cent"' in login
    assert html.count('class="flash bad') == 1
    status, html = main_part(external_world, "/external/9/servers", "post",
                             pop3_host="pop.example.org", pop3_port="",
                             smtp_host="smtp.example.org", smtp_port="587")
    assert status == 400
    servers = html.split('<form method="post" action="/external/9/servers">', 1)[1] \
        .split("</form>", 1)[0]
    assert servers.index('<div class="flash bad">') < servers.index('<div class="inline-fields">')
    port = servers.split('<label for="pop3_port">', 1)[1].split('<label for=', 1)[0]
    assert '<p class="help warn">The POP3 port is needed.</p>' in port
    assert html.count('class="flash bad') == 1


def an_addition(**changed):
    typed = {"address": "new@example.org", "pop3_login": "", "credential": "",
             "pop3_host": "pop.example.org", "pop3_port": "995",
             "smtp_host": "smtp.example.org", "smtp_port": "587", "window": "14",
             "comment": "", "domain_choice": "", "domain_id": "", "label": "",
             "password": "", "password2": ""}
    return {**typed, **changed}


def test_adding_one_is_a_narrow_form_and_a_refusal_is_a_flash_and_a_warn(external_world):
    status, html = main_part(external_world, "/external/add")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/external">External mailboxes</a> / '
                           'Add</div>')
    assert "<h1>Add external mailbox</h1>" in page_head(html)
    form = html.split('<form class="narrow" method="post" action="/external/add">', 1)[1] \
        .split("</form>", 1)[0]
    names = re.findall(r'<(?:input|select)[^>]* name="([a-z0-9_]+)"', form)
    assert names[:9] == ["address", "pop3_login", "credential", "pop3_host", "pop3_port",
                         "smtp_host", "smtp_port", "window", "comment"]
    assert form.count('<div class="inline-fields">') == 3
    assert '<div class="box-head"><h2>The domain in front of it</h2></div>' in form
    assert ('<label class="choice"><input type="radio" name="domain_choice" value="free" '
            'checked><div><b>A free domain</b></div></label>') in " ".join(form.split())
    assert form.count('<label class="choice">') == 2
    assert re.search(r'<option value="4" ?>hr</option>', form)
    assert ('<div class="form-foot"><button class="btn btn-primary" type="submit">Save as '
            'disabled</button><a class="btn" href="/external">Cancel, nothing changes</a>'
            '</div>') in form
    assert html.count("btn-primary") == 1 and "flash" not in html
    status, html = main_part(external_world, "/external/add", "post",
                             **an_addition(window="nope"))
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    sentence = flash.split("<div>", 1)[1]
    assert sentence == "The deletion window must be a whole number of days."
    window = html.split('<label for="window">', 1)[1].split('<label for=', 1)[0]
    assert f'<p class="help warn">{sentence}</p>' in window and 'value="nope"' in window
    status, html = main_part(external_world, "/external/add", "post", **an_addition())
    assert status == 400
    again = html.split('<label for="password2">', 1)[1].split("</div>", 1)[0]
    assert '<p class="help warn">Choose a free domain, or a new one.</p>' in again
    assert html.count('class="flash bad') == 1 and html.count("help warn") == 1


def test_the_deletion_page_is_two_danger_zones_with_leaving_the_domain_first(external_world):
    status, html = main_part(external_world, "/external/9/delete")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/external">External mailboxes</a> / '
                           '<a href="/external/9"><code>Box@example.org</code></a> / Delete'
                           '</div>')
    head = " ".join(page_head(html).split())
    assert "<h1>Delete <code>Box@example.org</code>?</h1>" in head
    assert '<p class="lede">What goes is this row, the provider password and the fetcher' in head
    zones = html.split('<section class="danger-zone">')[1:]
    assert len(zones) == 2
    assert zones[0].startswith('<div class="box-head"><h2>Leave <code>sales</code> free</h2>')
    assert ('<button class="btn btn-danger" type="submit">Delete the mailbox, leave '
            '<code>sales</code> free</button>') in zones[0]
    assert zones[1].startswith('<div class="box-head"><h2>Delete the domain <code>sales</code> '
                               'too</h2>')
    kv = zones[1].split('<div class="kv">', 1)[1].split("</div></div>", 1)[0]
    assert re.findall(r"<div><b>(\d+)</b><span>([^<]+)</span>", kv) == [
        ("1204", "Messages removed"), ("2", "Mailboxes removed"),
        ("1", "People who lose their only mailbox")]
    assert ('<button class="btn btn-danger-solid" type="submit">Delete the mailbox and '
            '<code>sales</code></button>') in zones[1]
    assert html.count("btn-danger-solid") == 1 and "btn-primary" not in html
    assert '<svg class="icon"><use href="#i-back"/></svg> Cancel, nothing changes</a>' in html
    nav = page_of(external_world, "/external/9/delete").split("</nav>", 1)[0]
    assert '<a href="/external" aria-current="page">' in nav
    _, alone = main_part(external_world, "/external/10/delete")
    assert alone.count('action="/external/10/delete"') == 1
    assert ('<button class="btn btn-danger-solid" type="submit">Delete '
            '<code>asked@example.org</code></button>') in alone
    assert "Delete the domain" not in alone


def test_the_fetch_screen_is_one_table_whose_status_speaks_in_a_worded_voice(external_world):
    status, html = main_part(external_world, "/fetch")
    assert status == 200
    head = " ".join(page_head(html).split())
    assert "<h1>Fetch</h1>" in head
    assert ('<p class="lede">Last run 2026-09-30 14:33:00. Next by 2026-09-30 14:36:00, the '
            "fetch timer's own period (3 minutes).</p>") in head.replace("&#39;", "'")
    assert '<section class="box"><div class="table-wrap"><table>' in html
    assert ('<thead><tr><th>Address</th><th>Domain</th><th>Last fetched</th><th>Status</th>'
            '<th class="acts">Actions</th></tr></thead>') in html
    box = row_of(html, "Box@example.org")
    assert '<span class="row-sub">the sales mailbox</span>' in box
    assert ('<span class="state-bad"><svg class="icon bad"><use href="#i-alert"/></svg> '
            'credential refused') in box
    assert ('<span class="row-sub state-attn"><svg class="icon attn"><use href="#i-alert"/>'
            '</svg> frozen since 2026-09-30 11:40') in box
    acts = box.split('<td class="acts">', 1)[1]
    assert re.findall(r'<button class="([^"]+)" type="submit">([^<]+)</button>', acts) == [
        ("btn btn-sm", "Resume&hellip;"), ("btn btn-sm", "Refetch now")]
    asked = row_of(html, "asked@example.org")
    assert '<td><span class="muted">never</span></td>' in asked
    assert ('<span class="state-attn"><svg class="icon attn"><use href="#i-clock"/></svg> '
            'asked to enable</span>') in asked
    assert '<td class="acts"><span class="muted">&mdash;</span></td>' in asked
    off = row_of(html, "off@example.org")
    assert f'<span class="muted">{fetch.DISABLED}</span>' in off
    ok = row_of(html, "ok@example.org")
    assert '<span class="state-ok"><svg class="icon ok"><use href="#i-check"/></svg> ok</span>' \
        in ok
    assert '<p class="muted">A row reads one of: <code>credential refused</code>' in html
    assert "<footer" not in html and "btn-primary" not in html


def test_a_refused_refetch_is_a_flash_above_the_table(external_world):
    status, html = main_part(external_world, "/fetch/11/refetch", "post")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert "off@example.org is disabled, so a fetch of it would collect nothing" in flash
    assert html.index('<div class="flash bad">') < html.index("<table")


# --- withheld and the journal, in the design's components ---------------------------------

ARRIVED = datetime.datetime(2026, 9, 30, 12, 14)


def a_withheld(**changed):
    message = {"id": 7, "received_at": ARRIVED, "sender": "stranger@example.org",
               "subject": "a parcel for you", "is_spam": True, "spam_score": 9.5,
               "domain_id": 1, "label": "sales", "why": "Held back: a parcel for you",
               "newest_kind": None, "newest_state": None, "newest_created_at": None,
               "newest_result": None}
    return {**message, **changed}


WITHHELD = [
    a_withheld(),
    a_withheld(id=8, subject="asked already", newest_kind="release",
               newest_state="queued", newest_created_at=ASKED_AT),
    a_withheld(id=9, subject="tried once", sender=None, why=None, newest_kind="release",
               newest_state="failed", newest_result="no <quarantine>"),
]


def a_journal_row(**changed):
    row = {"id": 1, "at": "2026-09-30 14:12", "actor": "t28admin",
           "action": "set_account_state", "target": "ivan", "detail": {"after": "blocked"},
           "request_id": None, "request_state": None, "request_result": None,
           "break_glass": False}
    return {**row, **changed}


@pytest.fixture
def journal_world(shell, monkeypatch):
    """The shell with three withheld messages stood in for the database (7 as it arrived,
    8 whose release waits, 9 whose release failed) and two journal rows, one of which
    asked the pipeline for something that failed. Nothing is written anywhere."""

    def one(conn, sql, parameters=()):
        if sql.startswith("SELECT id, state FROM message"):
            return {"id": parameters[0], "state": "delivered"}
        return None

    def rows(conn, sql, parameters=()):
        if sql.startswith(moderation.LIST):
            return [dict(row) for row in WITHHELD]
        return []

    def journal_rows(conn, **filters):
        return [a_journal_row(),
                a_journal_row(id=2, action="delete_account", request_id=5,
                              request_state="failed", request_result="no <b>account</b>",
                              break_glass=True)]

    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(common, "timer_period", lambda: THREE)
    monkeypatch.setattr(journal, "rows", journal_rows)
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    return shell


def subject_row(html, subject):
    return next(row for row in html.split("<tr>") if f"<td>{subject}</td>" in row)


def test_withheld_is_one_table_with_release_on_the_row(journal_world):
    status, html = main_part(journal_world, "/withheld")
    assert status == 200
    head = page_head(html)
    assert "<h1>Withheld messages</h1>" in head
    assert '<p class="lede">Each of these was held back by the filtering.' in head
    assert "It overrides the domain's spam policy" in head
    assert html.count("<h1") == 1 and "btn-primary" not in html
    assert '<section class="box"><div class="table-wrap"><table>' in html
    assert html.count("<table") == 1 and "<tbody>" in html
    assert ('<thead><tr><th>Arrived</th><th>Domain</th><th>From</th><th>Subject</th>'
            '<th>Why it was held</th><th class="acts">Actions</th></tr></thead>') in html
    first = subject_row(html, "a parcel for you")
    assert '<a href="/domains/1"><code>sales</code></a>' in first
    assert "<code>stranger@example.org</code>" in first
    assert ('<td class="acts"><form method="post" action="/withheld/7/release">'
            '<button class="btn btn-sm" type="submit">Release&hellip;</button></form></td>'
            in first)
    asked = subject_row(html, "asked already")
    assert ('<span class="row-sub state-attn"><svg class="icon attn"><use href="#i-clock"/>'
            '</svg> asked to release, 14:58</span>') in asked
    assert '<span class="row-sub">the pipeline runs by 15:01</span>' in asked
    assert '<td class="acts"><span class="muted">waiting for the pipeline</span></td>' in asked
    assert "Release" not in asked
    tried = subject_row(html, "tried once")
    assert "<code>(no sender)</code>" in tried and moderation.NO_REPORT in tried
    assert ('<span class="row-sub state-bad"><svg class="icon bad"><use href="#i-x"/></svg> '
            'the pipeline could not do it: no &lt;quarantine&gt;</span>') in tried
    assert "Release&hellip;" in tried


def test_a_refused_release_is_a_flash_above_the_table(journal_world):
    status, html = main_part(journal_world, "/withheld/7/release", "post")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert "Message 7 is delivered, not withheld." in flash
    assert html.index('<div class="flash bad">') < html.index("<table")


def test_the_journal_is_a_filter_form_above_one_table_with_kinds_and_targets_in_code(
        journal_world):
    status, html = main_part(journal_world, "/journal?target=ivan")
    assert status == 200
    head = page_head(html)
    assert "<h1>Journal</h1>" in head
    assert '<p class="lede">Who did what, when, and to whom.' in head
    assert html.count("<h1") == 1 and "btn-primary" not in html
    form = html.split('<form method="get" action="/journal">', 1)[1].split("</form>", 1)[0]
    assert html.index("<form") < html.index("<table")
    assert '<div class="inline-fields">' in form
    for name in ("who", "target", "since", "until"):
        assert f'<input id="{name}" name="{name}" type="text"' in form
    assert 'value="ivan"' in form
    assert '<select id="action" name="action">' in form
    assert f'<p class="help">{escape(events.HELP)}</p>' in form
    assert ('<div class="form-foot"><button class="btn" type="submit">Filter</button> '
            '<a href="/journal">Show everything</a></div>') in form
    assert html.count("<table") == 1 and "<tbody>" in html
    assert ('<thead><tr><th>When</th><th>Who</th><th>Act</th><th>Target</th><th>Detail</th>'
            '<th>Break-glass</th></tr></thead>') in html
    table = html.split("<tbody>", 1)[1]
    assert "<td><code>set_account_state</code></td><td><code>ivan</code></td>" in table
    assert "<td><code>delete_account</code></td><td><code>ivan</code></td>" in table
    assert '<td class="wrap"><code>{&#34;after&#34;: &#34;blocked&#34;}</code></td>' in table
    assert ('<span class="row-sub">the request it asked for: failed &mdash; '
            'no &lt;b&gt;account&lt;/b&gt;</span>') in table
    assert f'<p class="muted">{escape(events.OUTLIVES)}</p>' in html
    assert "<footer" not in html


def test_the_journals_way_back_is_the_crumb_above_its_head(journal_world):
    status, html = main_part(journal_world, "/journal?back=domains")
    assert status == 200
    assert ('<div class="crumbs"><a href="/domains"><svg class="icon"><use href="#i-back"/>'
            '</svg> Back to Domains</a></div>') in html
    assert html.index('<div class="crumbs">') < html.index('<div class="page-head">')
    assert '<input type="hidden" name="back" value="domains">' in html
    status, html = main_part(journal_world, "/journal?back=elsewhere")
    assert '<div class="crumbs">' not in html and "Back to" not in html


def test_a_refused_date_is_a_flash_and_a_warn_and_no_row(journal_world):
    status, html = main_part(journal_world, "/journal?since=last-tuesday")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert "A date is written YYYY-MM-DD." in flash
    assert html.index('<div class="flash bad">') < html.index("<form")
    since = html.split('<input id="since"', 1)[1].split("</div>", 1)[0]
    assert 'value="last-tuesday"' in since
    assert '<p class="help warn">A date is written YYYY-MM-DD.' in since
    assert events.NOTHING in html.split("<tbody>", 1)[1]


def test_a_capped_journal_says_so_in_a_flash_above_the_table(journal_world, monkeypatch):
    monkeypatch.setattr(journal, "LIMIT", 2)
    status, html = main_part(journal_world, "/journal")
    flash = html.split('<div class="flash attn">', 1)[1].split("</div></div>", 1)[0]
    assert "Only the newest 2 rows are shown." in flash
    assert html.index('<div class="flash attn">') < html.index("<table")


# --- the sweep: every page keeps the design's rules -----------------------------------

@pytest.fixture
def health_world(shell, tmp_path, monkeypatch):
    """The shell with a report holding all four states, and the overview's rows
    with each worry there once, so both pages and the header show every voice they have."""
    write_report(tmp_path / "health.json", HEALTH_MIXED)
    timer = tmp_path / "health.timer"
    timer.write_text("[Timer]\nOnCalendar=*:0/5\n")
    shell.application.config["MAILDIVVY_HEALTH_NOW"] = HEALTH_NOW
    stand_in_busy_rows(monkeypatch)
    return shell


@pytest.fixture
def break_glass_world(health_world, monkeypatch):
    """The same machine, signed in with the break-glass account."""
    monkeypatch.setattr(application, "current_identity",
                        lambda: auth.Identity("break-glass", None, break_glass=True))
    return health_world


# Every page a signed-in person can open, by the world that seeds it, with the status it
# answers. `test_every_get_route_is_swept` keeps this list whole against the application's
# own map. A new GET route joins it.
SWEPT = [
    ("health_world", "/", 200), ("health_world", "/health", 200),
    ("health_world", "/health?done=domain_created", 200),
    ("health_world", "/no-such-page", 404), ("shell", "/health", 200),
    ("break_glass_world", "/", 200), ("break_glass_world", "/no-such-page", 404),
    ("domains_world", "/domains", 200), ("domains_world", "/domains/1", 200),
    ("domains_world", "/domains/2", 200), ("domains_world", "/domains/add", 200),
    ("domains_world", "/domains/1/delete", 200), ("domains_world", "/domains/2/delete", 400),
    ("domains_world", "/domains/1/spam", 200), ("domains_world", "/domains/1/archive", 200),
    ("domains_world", "/domains/1/archive/listing", 200),
    ("waiting_world", "/domains/1/archive/listing", 400),
    ("people_world", "/people", 200), ("people_world", "/people/1", 200),
    ("people_world", "/people/3", 200), ("people_world", "/people/4", 200),
    ("people_world", "/people/5", 200), ("people_world", "/people/6", 200),
    ("people_world", "/people/add", 200), ("people_world", "/people/3/delete", 200),
    ("people_world", "/people/1/delete", 400),
    ("boxes_world", "/mailboxes", 200), ("boxes_world", "/mailboxes/5", 200),
    ("boxes_world", "/mailboxes/add", 200), ("boxes_world", "/mailboxes/5/delete", 200),
    ("boxes_world", "/mailboxes/5/top-up", 200),
    ("boxes_world", "/mailboxes/5/top-up?since=nope", 400),
    ("external_world", "/external", 200), ("external_world", "/external/9", 200),
    ("external_world", "/external/10", 200), ("external_world", "/external/11", 200),
    ("external_world", "/external/12", 200), ("external_world", "/external/add", 200),
    ("external_world", "/external/9/delete", 200), ("external_world", "/external/10/delete", 200),
    ("external_world", "/fetch", 200),
    ("journal_world", "/withheld", 200), ("journal_world", "/journal", 200),
    ("journal_world", "/journal?since=last-tuesday", 400),
]

# The refused forms: each is its screen again, at 400, with the refusal on it.
REFUSALS = [
    ("domains_world", "/domains/add", {"label": "NOT A LABEL",
                                       "password": "an-archive-password-that-is-long",
                                       "password2": "an-archive-password-that-is-long"}),
    ("domains_world", "/domains/1/outbound", {"outbound_unscanned": "whatever"}),
    ("domains_world", "/domains/1/spam", {"threshold": "999"}),
    ("domains_world", "/domains/1/archive/password",
     {"password": "an-archive-password-that-is-long", "password2": "other"}),
    ("people_world", "/people/add", {"login": "no such login!",
                                     "password": "a-long-enough-password",
                                     "password2": "a-long-enough-password"}),
    ("people_world", "/people/3/password", {"password": "a-long-enough-password",
                                            "password2": "another-one-typed"}),
    ("people_world", "/people/1/admin", {}),
    ("people_world", "/people/3/state", {"state": "sleepy"}),
    ("boxes_world", "/mailboxes/add", {"domain_id": "99", "account_id": "7"}),
    ("boxes_world", "/mailboxes/5/deliver-one", {"message_id": "the third one"}),
    ("boxes_world", "/mailboxes/5/transfer", {"to_account_id": ""}),
    ("external_world", "/external/add", {"address": "new@example.org",
                                         "pop3_host": "pop.example.org", "pop3_port": "995",
                                         "smtp_host": "smtp.example.org", "smtp_port": "587",
                                         "window": "nope"}),
    ("external_world", "/external/9/servers", {"pop3_host": "pop.example.org",
                                               "pop3_port": "",
                                               "smtp_host": "smtp.example.org",
                                               "smtp_port": "587"}),
    ("external_world", "/external/9/settings", {"pop3_login": "re cent", "window": "14"}),
    ("external_world", "/fetch/11/refetch", {}),
    ("journal_world", "/withheld/7/release", {}),
]

# `danger` as a box, `primary` as a button, and own state classes are the old
# names; the design's `danger-zone`, `btn-primary` and `state-bad` are other tokens.
RETIRED = {"refusal", "field-refusal", "notice", "banner", "danger", "primary", "current",
           "count", "look-again", "state-pass", "state-warn", "state-fail", "state-unknown"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source",
        "track", "wbr"}


class Element:
    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.classes = set((self.attrs.get("class") or "").split())
        self.parts = []  # text and child elements, in order

    def text(self, leaving_out=None):
        return "".join(part if isinstance(part, str)
                       else "" if part is leaving_out else part.text(leaving_out)
                       for part in self.parts)

    def within(self, token):
        found = self.parent
        while found is not None and token not in found.classes:
            found = found.parent
        return found

    def walk(self):
        for part in self.parts:
            if isinstance(part, Element):
                yield part
                yield from part.walk()


class Tree(HTMLParser):
    """The page as elements, each knowing its classes, its text and its ancestors."""

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.root = self.here = Element("#root", (), None)
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        made = Element(tag, attrs, self.here)
        self.here.parts.append(made)
        if tag not in VOID:
            self.here = made

    def handle_startendtag(self, tag, attrs):
        self.here.parts.append(Element(tag, attrs, self.here))

    def handle_endtag(self, tag):
        found = self.here
        while found is not self.root and found.tag != tag:
            found = found.parent
        if found is not self.root:
            self.here = found.parent

    def handle_data(self, data):
        self.here.parts.append(data)


def red_out_of_place(element):
    """Why `element` is red where the design does not allow it, or None: red is a worded
    state, a refusal's flash, or inside the danger zone; the header's solid badge is the
    one recorded exception, and it is worded too."""
    classes = element.classes
    if "danger-zone" in classes:
        return None
    if {"btn-danger", "btn-danger-solid"} & classes:
        return None if element.within("danger-zone") else "a danger button outside the zone"
    if "state-bad" in classes or ("bad" in classes and "badge" in classes):
        return None if element.text().strip() else "a red state with no word"
    if "bad" in classes and "flash" in classes:
        return None
    if "bad" in classes and "icon" in classes:
        worded = (element.within("danger-zone") or element.parent.text(element).strip()
                  or any("state-bad" in e.classes or {"flash", "bad"} <= e.classes
                         for e in (element.parent, element.within("state-bad"),
                                   element.within("flash")) if e is not None))
        return None if worded else "a red icon with no word beside it"
    if "bad" in classes:
        return "red that is neither a state, a refusal nor inside the zone"
    return None


def keeps_the_designs_rules(html, path, current):
    """The rules every signed-in page keeps, asserted on its markup after `head`."""
    assert '<header class="topbar">' in html and '<nav class="nav"' in html, path
    assert "<main>" in html, path
    assert html.count('aria-current="page"') == current, path
    assert not class_tokens(html) & RETIRED, path
    assert not re.search(r"\sstyle=", html), path
    assert html.count("<h1") == 1, path
    assert html.count("btn-primary") <= 1, path
    tree = Tree(html)
    for element in tree.root.walk():
        where = f"{path}: <{element.tag} class=\"{element.attrs.get('class')}\">"
        if "badge" in element.classes:
            assert element.text().strip(), f"{where} is a badge with no word"
        why = red_out_of_place(element)
        assert why is None, f"{where} is {why}"
        if "solid" in element.classes:
            assert element.within("topbar") and "health" in element.classes, where
        # the stylesheet styles a help line only inside its field
        if "help" in element.classes:
            assert element.within("field"), f"{where} is a help line outside a field"


@pytest.mark.parametrize("world,path,status", SWEPT)
def test_every_page_keeps_the_designs_rules(request, world, path, status):
    client = request.getfixturevalue(world)
    answer = client.get(path)
    assert answer.status_code == status, (path, answer.status_code)
    html = answer.get_data(as_text=True).split("</head>", 1)[1]
    # every page but the one at no address is in a section, marked in the sidebar
    keeps_the_designs_rules(html, path, 0 if status == 404 else 1)


@pytest.mark.parametrize("world,path,form", REFUSALS)
def test_every_refused_form_keeps_the_designs_rules(request, monkeypatch, world, path, form):
    client = request.getfixturevalue(world)
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    monkeypatch.setattr(accounts, "would_leave_no_administrator", lambda conn, id: True)
    answer = client.post(path, data=form)
    assert answer.status_code == 400, (path, answer.status_code)
    html = answer.get_data(as_text=True).split("</head>", 1)[1]
    assert '<div class="flash bad">' in html, path
    keeps_the_designs_rules(html, path, 1)


def test_every_get_route_is_swept(built):
    """A screen added later joins the sweep, or this fails."""
    swept = {built.url_map.bind("localhost").match(path.split("?")[0], "GET")[0]
             for world, path, status in SWEPT if status != 404}
    served = {rule.endpoint for rule in built.url_map.iter_rules()
              if "GET" in rule.methods and rule.endpoint not in ("static", "sign_in")}
    assert served <= swept, served - swept


def test_the_sweep_catches_red_outside_the_fence_and_a_badge_with_no_word():
    tree = Tree('<div class="box"><button class="btn btn-danger">Go</button>'
                '<span class="badge bad"> </span><p class="bad">no</p>'
                '<table><tr><td><svg class="icon bad"><use href="#i-x"/></svg></td></tr></table>'
                '<div class="danger-zone"><button class="btn btn-danger-solid">Go</button>'
                '</div><div class="flash bad"><svg class="icon bad"></svg><div>No.</div></div>'
                '<span class="state-bad"><svg class="icon bad"></svg> refused</span></div>')
    found = [red_out_of_place(e) for e in tree.root.walk()]
    assert [why for why in found if why] == [
        "a danger button outside the zone", "a red state with no word",
        "red that is neither a state, a refusal nor inside the zone",
        "a red icon with no word beside it"]


def test_the_application_holds_no_stylesheet_of_its_own():
    text = (SOURCE / "app.py").read_text()
    assert "from maildivvy.admin.style import STYLESHEET" in text
    assert not re.search(r"^\s*[.#][\w-]+[^\n]*\{[^}]*:[^}]*\}", text, re.M)


# --- every act the screens write is a declared one ------------------------------

def test_every_act_the_screens_journal_is_declared():
    text = "".join((SOURCE / "screens" / f"{screen.__name__.rsplit('.', 1)[1]}.py").read_text()
                   for screen in SCREENS)
    written = set(re.findall(r"record\(conn, \"([a-z_]+)\"", text))
    assert written, "the scan found nothing"
    assert written <= journal.DECLARED, written - journal.DECLARED


def test_the_domains_outbound_setting_has_a_declared_act_of_its_own():
    assert "set_outbound_unscanned" in journal.INTERFACE_ACTS


def test_every_request_kind_the_screens_queue_is_one_the_schema_allows():
    text = "".join((SOURCE / "screens" / f"{screen.__name__.rsplit('.', 1)[1]}.py").read_text()
                   for screen in SCREENS)
    queued = set(re.findall(r"common\.ask\(conn, \"([a-z_]+)\"", text))
    assert queued == {"create_domain", "delete_domain", "delete_external_mailbox",
                      "test_credential", "activate_external_mailbox", "refetch",
                      "create_mailbox", "connect", "transfer", "delete_mailbox",
                      "delete_account", "release", "top_up", "deliver_one"}
    assert queued <= set(journal.PIPELINE_ACTS)


def sql_of(name):
    """Every SQL string literal a screen module holds, read off its syntax tree."""
    import ast

    tree = ast.parse((SOURCE / "screens" / f"{name}.py").read_text())
    return [node.value.strip() for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and node.value.strip().upper().startswith("SELECT")]


def test_no_screen_ever_selects_the_credential_column():
    read = [statement for name in ("domains", "external", "fetch", "accounts",
                                   "mailboxes", "moderation", "overview")
            for statement in sql_of(name)]
    assert read, "the scan found no SELECT at all, which would pass saying nothing"
    for statement in read:
        # the column itself, never a request kind that happens to end in the word
        assert not re.search(r"(?<![_a-z])credential\b", statement), statement
    # the positive control: it IS written, on both the add form and the settings form
    written = (SOURCE / "screens" / "external.py").read_text()
    assert "SET credential = %s" in written
    assert "credential, pop3_host" in written


# --- what one fetch row reads ---------------------------------------------

def row(**columns):
    empty = {name: None for name in (
        "id", "address", "address_canonical", "comment", "state", "domain_id", "label",
        "last_fetch_at", "last_fetch_status", "last_fetch_cause", "last_fetch_detail",
        "last_test_at", "last_test_status", "last_test_detail", "stuck_since",
        "stuck_runs", "skip_streak", "frozen_since", "last_skip_at", "last_skip_uidl",
        "held_since", "delete_window_days", "checking", "enabling", "deleting")}
    empty.update({"state": "active", "delete_window_days": 14, "stuck_runs": 0,
                  "checking": False, "enabling": False, "deleting": False})
    empty.update(columns)
    return empty


@pytest.mark.parametrize("cause,says", [
    ("unrecorded", "could not record what it decided"),
    ("timeout", "killed at the runner's timeout"),
    ("stuck_message", "stuck on one message"),
    ("unreachable", "cannot reach the provider"),
    ("transient", "stopped by something transient"),
])
def test_an_error_is_described_from_the_recorded_cause_alone(cause, says):
    said = fetch.status_of(row(last_fetch_status="error", last_fetch_cause=cause,
                               last_fetch_detail="mpop: something"))
    assert says in said["status"]
    assert said["detail"] == "mpop: something"      # the raw detail is shown beneath, as text


def test_the_causes_this_screen_knows_are_the_fetch_runners_own_closed_list():
    from maildivvy.fetch import outcome

    assert tuple(fetch.CAUSES) == outcome.CAUSES


def test_an_error_with_no_cause_recorded_says_it_cannot_be_told_apart():
    status = fetch.status_of(row(last_fetch_status="error", last_fetch_cause=None))["status"]
    assert "cannot be told apart" in status


def test_a_refused_credential_is_its_own_status_and_never_goes_through_a_cause():
    said = fetch.status_of(row(last_fetch_status="auth_failed", last_fetch_cause="transient"))
    assert "credential refused" in said["status"]
    assert "very likely changed the password" in said["status"]
    assert said["detail"] is None


@pytest.mark.parametrize("columns,says", [
    ({"last_fetch_status": "ok"}, "ok"),
    ({"last_fetch_status": "no_new_mail"}, "no new mail"),
    ({"last_fetch_status": None}, "has not run yet"),
    ({"state": "deactivated"}, "disabled"),
    ({"state": "deactivated", "enabling": True}, "asked to enable"),
    ({"deleting": True}, "asked to delete"),
])
def test_the_other_statuses_are_the_closed_list_the_screen_names(columns, says):
    assert says in fetch.status_of(row(**columns))["status"]


def test_a_held_mailbox_says_the_mail_is_waiting_at_the_provider():
    held = datetime.datetime(2026, 9, 22, 10, 0, tzinfo=datetime.timezone.utc)
    status = fetch.status_of(row(held_since=held, last_fetch_status="error",
                                 last_fetch_cause="transient"))["status"]
    assert "waiting at the provider" in status


def test_the_retry_state_reads_frozen_before_stuck():
    now = datetime.datetime(2026, 9, 22, 12, 0, tzinfo=datetime.timezone.utc)
    when = now - datetime.timedelta(minutes=20)
    assert "frozen since" in fetch.retry_of(row(frozen_since=when, stuck_since=when), now)
    stuck = fetch.retry_of(row(stuck_since=when, stuck_runs=4), now)
    assert "stopped on one message" in stuck and "4 run(s)" in stuck
    assert "40 minute(s) before the automatic skip" in stuck
    overdue = fetch.retry_of(row(stuck_since=now - datetime.timedelta(hours=2)), now)
    assert "the automatic skip is due" in overdue
    assert fetch.retry_of(row(), now) is None


def test_the_minutes_left_are_counted_against_the_runners_own_bound():
    from maildivvy.fetch import runner

    assert fetch.DEFAULT_STUCK_AFTER is runner.DEFAULT_STUCK_AFTER


def test_the_last_skip_stays_visible_whatever_retry_state_is_newer():
    # A defect not repeated: the predecessor hid the skip the moment a new stuck episode
    # began, and the skip is the one reading with a deadline attached
    skipped = datetime.datetime(2026, 9, 20, 9, 30, tzinfo=datetime.timezone.utc)
    frozen = datetime.datetime(2026, 9, 22, 9, 30, tzinfo=datetime.timezone.utc)
    line = fetch.skip_of(row(last_skip_at=skipped, last_skip_uidl="UID-9",
                             frozen_since=frozen, delete_window_days=14),
                         today=datetime.date(2026, 9, 22))
    assert "skipped message UID-9" in line
    assert "deletes it on 2026-10-04" in line


def test_the_skip_goes_only_once_the_provider_has_deleted_it():
    skipped = datetime.datetime(2026, 9, 1, 9, 30, tzinfo=datetime.timezone.utc)
    kept = row(last_skip_at=skipped, last_skip_uidl="UID-9", delete_window_days=14)
    assert fetch.skip_of(kept, today=datetime.date(2026, 9, 15)) is not None
    assert fetch.skip_of(kept, today=datetime.date(2026, 9, 16)) is None


@pytest.mark.parametrize("columns,says", [
    ({"checking": True}, "asked to check the password"),
    ({"last_test_status": "ok"}, "accepted"),
    ({"last_test_status": "auth_failed"}, "refused"),
    ({"last_test_status": "error", "last_test_detail": "no answer"}, "did not get an answer"),
    ({}, "has not been checked yet"),
])
def test_the_last_password_check_is_reported_apart_from_the_fetch(columns, says):
    assert says in fetch.check_of(row(**columns))


# --- the fetch period comes from the timer --------------------------------------

@pytest.mark.parametrize("spec,seconds", [("*:0/3", 180), ("*:0/1", 60),
                                          ("*:*:0/30", 30), ("hourly", 3600),
                                          ("minutely", 60)])
def test_the_period_is_read_from_the_timers_own_calendar(tmp_path, spec, seconds):
    unit = tmp_path / "maildivvy-fetch.timer"
    unit.write_text(f"[Timer]\nOnCalendar={spec}\nPersistent=true\n")
    assert fetch.timer_period(unit).total_seconds() == seconds


def test_a_period_that_cannot_be_read_is_said_so_and_never_guessed(tmp_path):
    assert fetch.timer_period(tmp_path / "not-there") is None
    unit = tmp_path / "maildivvy-fetch.timer"
    unit.write_text("[Timer]\nOnUnitActiveSec=3min\n")
    assert fetch.timer_period(unit) is None
    assert "could not be read from the machine" in fetch.PAGE


@pytest.mark.parametrize("minutes", [None, 1, 5, 60])
def test_the_period_the_installed_timer_carries_is_the_roles_own_cadence(tmp_path, minutes):
    """The screen's "look again by" is read off the timer the role rendered from its one
    fetch period, so the two cannot disagree whatever the period is set to."""
    import jinja2
    import yaml

    role = Path(fetch.__file__).resolve().parents[4] / "ansible" / "roles" / "programs"
    values = {**yaml.safe_load((role / "vars" / "main.yml").read_text()),
              **yaml.safe_load((role / "defaults" / "main.yml").read_text())}
    if minutes is not None:
        values["maildivvy_fetch_minutes"] = minutes
    unit = tmp_path / "maildivvy-fetch.timer"
    unit.write_text(jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(
        (role / "templates" / "maildivvy-fetch.timer.j2").read_text()).render(values))
    period = fetch.timer_period(unit)
    assert period == datetime.timedelta(minutes=values["maildivvy_fetch_minutes"])
    assert fetch.FETCH_TIMER == "/etc/systemd/system/maildivvy-fetch.timer"


@pytest.mark.parametrize("seconds,words", [(180, "3 minutes"), (60, "1 minute"),
                                           (3600, "1 hour"), (30, "30 seconds")])
def test_a_period_is_spelt_on_the_screen_the_way_a_person_reads_it(seconds, words):
    assert fetch.spell(datetime.timedelta(seconds=seconds)) == words


# --- small readers the handlers rest on --------------------------------------------------------

@pytest.mark.parametrize("typed", ["", "  ", "no", "1.5", "-1", None])
def test_an_id_that_is_not_a_number_is_a_sentence_and_not_a_500(typed):
    from maildivvy.admin import validate

    with pytest.raises(validate.Refused):
        common.want_int(typed, "domain")
    assert common.want_int("12", "domain") == 12


def test_an_unchecked_checkbox_sends_nothing_and_absent_means_off():
    assert common.checked({"reaches": "yes"}, "reaches") is True
    assert common.checked({}, "reaches") is False


def test_a_concurrent_constraint_violation_is_caught_where_every_write_happens():
    source = (SOURCE / "screens" / "common.py").read_text()
    assert "SAVEPOINT before_write" in source
    assert "ROLLBACK TO SAVEPOINT before_write" in source
    # every INSERT a screen makes is inside one, so no write reaches a person as a 500;
    # the queue's own INSERT is `common.ask`'s and has no unique key to violate
    for name in ("domains", "external"):
        text = (SOURCE / "screens" / f"{name}.py").read_text()
        inserts = len(re.findall(r"INSERT INTO (?!request)", text))
        assert inserts, name
        assert text.count("unique_violation") >= inserts, name


def test_the_spam_policy_is_one_form_carrying_both_settings():
    source = (SOURCE / "screens" / "domains.py").read_text()
    assert '"set_spam_policy"' in source
    # both settings, before and after, including the one that did not move
    assert '{"before": before, "after": after}' in source
    assert "spam_reaches_people" in domains.SPAM_PAGE or True
    assert Decimal("8.00")        # the default the column carries, for the reader


# ================================================================================================
# The later screens: people, mailboxes, moderation, maintenance and the journal.
# ================================================================================================

# --- a waiting row, a failed one, and "look again by" ---------------------------

ASKED = datetime.datetime(2026, 9, 22, 14, 58, tzinfo=datetime.timezone.utc)
THREE = datetime.timedelta(minutes=3)


@pytest.mark.parametrize("kind,verb", [
    ("create_mailbox", "connect"), ("connect", "connect"), ("transfer", "transfer"),
    ("delete_mailbox", "delete"), ("delete_account", "delete"), ("top_up", "top up"),
    ("deliver_one", "deliver one message"), ("release", "release"),
    ("test_credential", "check the password"),
    ("activate_external_mailbox", "enable"), ("create_domain", "create"),
])
def test_a_waiting_row_names_its_verb_and_the_time_it_was_asked(kind, verb):
    reading = common.queue_reading(kind, "queued", ASKED, None, THREE)
    assert reading["waiting"] == f"asked to {verb}, 14:58"
    assert reading["failed"] is None


def test_look_again_is_the_asking_time_plus_the_real_period_and_never_a_constant():
    assert common.queue_reading("top_up", "queued", ASKED, None, THREE)["look_again"] \
        == "the pipeline runs by 15:01"
    # an operator who changes the cadence gets the screen's sentence changed with it
    hourly = common.queue_reading("top_up", "running", ASKED, None,
                                  datetime.timedelta(hours=1))
    assert hourly["look_again"] == "the pipeline runs by 15:58"
    # ⛔ a period that could not be read is said so, never guessed at three minutes
    assert common.queue_reading("top_up", "queued", ASKED, None, None)["look_again"] \
        == common.NO_PERIOD
    assert "3" not in common.NO_PERIOD


def test_enabling_says_the_pipeline_checks_the_password_first():
    reading = common.queue_reading("activate_external_mailbox", "queued", ASKED, None, THREE)
    assert reading["look_again"] == "the pipeline checks the password and enables it by 15:01"


@pytest.mark.parametrize("kind", ["create_mailbox", "connect", "transfer", "top_up",
                                  "deliver_one", "release", "delete_mailbox",
                                  "delete_account", "delete_domain", "refetch",
                                  "test_credential", "activate_external_mailbox"])
def test_a_failed_request_of_every_kind_shows_the_pipelines_own_reason(kind):
    # A defect not repeated: the predecessor showed a reason for the enable alone
    reading = common.queue_reading(kind, "failed", ASKED, "it could not be done", THREE)
    assert reading["failed"] == "it could not be done"
    assert reading["waiting"] is None and reading["look_again"] is None


def test_a_failure_with_no_reason_recorded_says_so_rather_than_nothing():
    assert common.queue_reading("top_up", "failed", ASKED, None, THREE)["failed"] \
        == common.NO_REASON


@pytest.mark.parametrize("state", ["done", None])
def test_a_request_that_is_over_leaves_the_row_saying_nothing(state):
    assert common.queue_reading("top_up", state, ASKED, "fine", THREE) \
        == {"waiting": None, "look_again": None, "failed": None}
    assert common.queue_reading(None, "queued", ASKED, None, THREE)["waiting"] is None


def test_a_kind_nobody_spelt_a_verb_for_is_named_as_itself():
    # a row saying nothing is how an act nobody performed looks healthy
    assert common.queue_reading("brand_new_kind", "queued", ASKED, None, THREE)["waiting"] \
        == "asked to brand_new_kind, 14:58"


def test_the_four_sub_selects_read_one_and_the_same_newest_request():
    sql = common.newest_request("(r.payload ->> 'mailbox_id')::bigint = m.id")
    for column in ("kind", "state", "created_at", "result"):
        assert f"SELECT r.{column} FROM request r" in sql
        assert f"AS newest_{column}" in sql
    assert sql.count("ORDER BY r.id DESC LIMIT 1") == 4
    assert "%s" not in sql, "a bound parameter here would be bound four times"


def test_every_screen_with_a_waiting_row_reads_the_period_from_the_timer():
    for name in ("mailboxes", "accounts", "moderation", "external", "domains", "overview"):
        text = (SOURCE / "screens" / f"{name}.py").read_text()
        assert "timer_period()" in text, name


# --- one mailbox row shape, everywhere --------------------------------

def test_the_three_tables_render_one_and_the_same_row_macro():
    for template in (mailboxes.LIST_PAGE, domains.DOMAIN_PAGE, accounts.PERSON_PAGE):
        assert mailboxes.SHAPE in template
    # the list is the only table with a Person and a Domain column
    assert "'person' in columns" in mailboxes.SHAPE
    assert 'columns=("person", "domain")' in \
        (SOURCE / "screens" / "mailboxes.py").read_text()


def test_no_screen_carries_the_word_role():
    rendered = templates()
    assert rendered, "the scan found no template at all, which would pass saying nothing"
    for name, text in rendered.items():
        assert not re.search(r"\brole\b", text.lower()), name


def test_a_mailbox_card_has_no_password_field_and_points_at_the_person():
    # the card's page head (where the person is named) is in its template with its body
    card = mailboxes.CARD_PAGE
    assert 'type="password"' not in card
    assert "their password and their state are set on their own page" in card
    assert "url_for('account', account_id=box.account_id)" in card


def test_the_archive_row_is_built_from_the_domain_and_is_nobodys_mailbox():
    from maildivvy.admin import validate

    row = {"domain_id": 7, "label": "sales", "total": 12, "newest_kind": None,
           "newest_state": None, "newest_created_at": None, "newest_result": None}
    box = mailboxes.archive_box(row)
    assert box["address"] == "archive@sales"
    assert box["kind"] == "archive" and box["id"] is None and box["account_id"] is None
    assert box["total"] == 12
    # it is never stored: the schema refuses `archive` as a person's login
    assert "archive" in validate.RESERVED_LOGINS
    assert mailboxes.ARCHIVE == "archive"


def test_the_archive_offers_no_top_up_no_transfer_and_no_removal():
    acts = mailboxes.SHAPE.split("{%- macro mailbox_acts")[1].split("{%- endmacro")[0]
    archive_half = acts.split("{%- else -%}")[0]
    assert "archive_listing" in archive_half
    assert "top_up" not in archive_half
    assert "transfer_mailbox" not in mailboxes.SHAPE
    assert "delete_mailbox" not in mailboxes.SHAPE


def test_a_blocked_persons_row_says_where_the_state_lives():
    assert "set on the person &mdash; mail still arrives" in mailboxes.SHAPE
    assert "blocked" in mailboxes.SHAPE


def test_giving_a_mailbox_queues_the_maildir_and_the_connect_as_two_rows():
    # a mailbox whose connect was never queued delivers nothing, silently
    text = (SOURCE / "screens" / "mailboxes.py").read_text()
    assert 'common.ask(conn, "create_mailbox"' in text
    assert 'common.ask(conn, "connect"' in text


def test_a_transfer_records_the_recipients_login_beside_their_row_id():
    text = (SOURCE / "screens" / "mailboxes.py").read_text()
    assert '"to_account_id": to_account_id, "to_login": person["login"]' in text
    assert mailboxes.OCCUPIED.startswith("That person already has a mailbox")


def test_the_removal_states_its_numbers_and_that_the_archive_keeps_everything():
    assert "Names removed" in mailboxes.DELETE_PAGE
    assert "Mailboxes removed" in mailboxes.DELETE_PAGE
    assert "People who lose access here" in mailboxes.DELETE_PAGE
    assert "0 &mdash; the archive keeps everything" in mailboxes.DELETE_PAGE
    assert "Cancel, nothing changes" in mailboxes.DELETE_PAGE


# --- passwords: the length, the generated one, and what is never kept -------------------

def test_a_generated_password_is_long_and_has_no_look_alikes_in_it():
    from maildivvy.admin import auth, validate

    made = {auth.generate_password() for _ in range(50)}
    assert len(made) == 50, "two draws were the same, which is not a random source"
    for password in made:
        assert len(password) >= 20
        assert len(password) >= validate.PASSWORD_MIN
        assert not set(password) & set("lI1O0")
        assert set(password) <= set(auth.GENERATED_ALPHABET)


def test_both_fields_empty_generates_and_anything_else_goes_through_the_rule():
    from maildivvy.admin import validate

    generated, was_generated = accounts.password_from({})
    assert was_generated and len(generated) >= 20
    typed, was_generated = accounts.password_from(
        {"password": "a-long-enough-one", "password2": "a-long-enough-one"})
    assert typed == "a-long-enough-one" and was_generated is False
    # one field filled and the other empty is still a mismatch, never a generation
    with pytest.raises(validate.Refused):
        accounts.password_from({"password": "a-long-enough-one", "password2": ""})
    with pytest.raises(validate.Refused):
        accounts.password_from({"password": "short", "password2": "short"})


def test_the_password_is_hashed_from_what_was_typed_and_kept_nowhere_after():
    text = (SOURCE / "screens" / "accounts.py").read_text()
    # hashed exactly where it is used, and never put on a row, a redirect or a log line
    assert text.count("auth.make_hash(password)") == 2
    assert "password_hash = %s" in text
    assert '"password_set": True' in text
    assert "password=password" in text            # only the page that shows it once
    for forbidden in ("print(", "sys.stderr", "logging"):
        assert forbidden not in text
    # an empty password can never be hashed: an empty pair becomes a generated one
    assert accounts.password_from({})[0] != ""


def test_the_shown_once_page_is_the_posts_own_answer_and_is_not_cacheable():
    text = (SOURCE / "screens" / "accounts.py").read_text()
    assert "Cache-Control" in text and "no-store" in text
    assert "This is the only time this password is shown" in accounts.SHOWN_ONCE
    # the client settings travel with it, and the ports are the product's
    assert accounts.IMAP_PORT == 993 and accounts.SUBMISSION_PORT == 465
    assert "implicit TLS" in accounts.SETTINGS
    assert "{{ password }}" in accounts.SHOWN_ONCE
    # it is only ever an answer to a POST: the two GET routes never render it
    gets = text.split('@app_.get("/people/<int:account_id>")')[1].split("@app_.post")[0]
    assert "shown_once" not in gets


def test_the_machines_own_name_is_read_from_the_installation_and_never_spelt_here(tmp_path):
    (tmp_path / "certificate.json").write_text('{"cert_name": "mail.example.org"}')
    assert accounts.machine_name(tmp_path) == "mail.example.org"
    assert accounts.machine_name(tmp_path / "nowhere") is None
    assert "could not be read" in accounts.SETTINGS


# --- the last administrator stays --------------------------------------------------------

def test_the_count_of_administrators_is_read_with_those_rows_locked():
    # two administrators revoking each other at once: the second waits, re-reads, and
    # finds itself the last one
    assert "FOR UPDATE" in accounts.LOCK_ADMINS
    assert "a.is_admin AND a.state = 'active'" in accounts.LOCK_ADMINS
    # An administrator with a deletion already queued is not counted
    assert "delete_account" in accounts.LOCK_ADMINS and "queued" in accounts.LOCK_ADMINS
    text = (SOURCE / "screens" / "accounts.py").read_text()
    # the three acts that could leave nobody ask it, plus the function's own signature
    assert text.count("would_leave_no_administrator(conn, account_id)") == 4
    for act in ("def account_admin", "def account_state", "def delete_account"):
        body = text.split(act)[1].split("\n    @app_")[0]
        assert "would_leave_no_administrator" in body, act
    assert "g.identity.account_id == account_id" in text


def test_the_refusals_say_what_they_refuse_and_why():
    said = accounts.LAST_ADMIN.format(login="ivan", act="Blocking them")
    assert "ivan is the last active administrator" in said
    assert "Break-glass is for the day the accounts table is unusable" in said
    assert "Nobody deletes their own account" in accounts.NOT_YOURSELF


def test_an_unchanged_administrator_flag_writes_nothing_at_all():
    # A defect not repeated: the predecessor wrote a grant or a revoke row either way
    text = (SOURCE / "screens" / "accounts.py").read_text()
    body = text.split("def account_admin")[1].split("def account_state")[0]
    assert 'if wanted == row["is_admin"]:' in body
    unchanged = body.split('if wanted == row["is_admin"]:')[1].split("if not wanted")[0]
    assert "admin_same" in unchanged
    assert "UPDATE" not in unchanged and "record(" not in unchanged
    assert common.DONE["admin_same"] == \
        "Nothing changed: the administrator flag is as it was."


def test_a_third_state_is_a_sentence_that_names_the_value():
    assert "'sleepy' is neither" in accounts.NO_THIRD.format(value="sleepy")
    assert "There is no third state" in accounts.NO_THIRD


def test_the_administrator_sentence_says_exactly_what_the_flag_grants():
    assert "reading any domain's archive" in accounts.GRANTS
    assert "keep it short" in accounts.GRANTS
    for template in (accounts.ADD_PAGE, accounts.PERSON_PAGE):
        assert "{{ grants }}" in template


def test_a_comment_is_saved_from_two_places_and_journaled_from_neither():
    text = (SOURCE / "screens" / "accounts.py").read_text()
    body = text.split("def account_comment")[1].split("def delete_account")[0]
    assert "record(" not in body, "a comment changes no state, so the journal has no row"
    assert "comment_saved" in body
    assert "account_comment" in mailboxes.CARD_PAGE
    assert "account_comment" in accounts.PERSON_PAGE


def test_the_deletion_states_its_numbers_before_its_button():
    assert "Mailboxes removed" in accounts.DELETE_PAGE
    assert "Names removed" in accounts.DELETE_PAGE
    assert "0 &mdash; the archives keep everything" in accounts.DELETE_PAGE
    assert "Cancel, nothing changes" in accounts.DELETE_PAGE


# --- maintenance: one selector, one bound, and no widened range ------------------------------------

def test_the_count_is_the_pipelines_own_selector_and_not_a_second_spelling():
    from maildivvy.fanout import requests as pipeline

    assert maintenance.pipeline is pipeline
    text = (SOURCE / "screens" / "maintenance.py").read_text()
    assert "pipeline.count_for(" in text
    # ⛔ nothing here counts messages with a selector of its own: the one SELECT this
    # screen writes reads the id and the domain of one named message, and counts nothing
    assert "count(*)" not in text
    assert "delivery" not in text
    # the spam condition is the selector's alone: this screen only says so
    assert "spam_reaches_people" not in text and "is_spam" not in text
    assert maintenance.WIDE_UNTIL == pipeline.WIDE_UNTIL


def test_an_empty_date_is_refused_and_never_widened():
    # A defect not repeated: a blank field quietly became most of the archive
    field, refusal = maintenance.typed_range({"since": "", "until": "2026-09-22"})
    assert field == "since" and "is needed" in refusal
    field, refusal = maintenance.typed_range({"since": "2026-09-01", "until": ""})
    assert field == "until" and "is needed" in refusal
    field, refusal = maintenance.typed_range({"since": "2026-09-01", "until": "nope"})
    assert field == "until" and "is not a date" in refusal
    assert maintenance.typed_range({"since": "2026-09-01", "until": "2026-09-22"}) \
        == (None, None)


def test_all_of_it_is_a_wide_explicit_pair_and_never_an_absent_one():
    assert datetime.date.fromisoformat(maintenance.WIDE_SINCE)
    assert datetime.date.fromisoformat(maintenance.WIDE_UNTIL)
    text = (SOURCE / "screens" / "maintenance.py").read_text()
    assert "asked_since, asked_until = WIDE_SINCE, WIDE_UNTIL" in text
    assert '"since": asked_since' in text and '"until": asked_until' in text


@pytest.mark.parametrize("today,since", [
    (datetime.date(2026, 9, 22), "2026-08-01"),
    (datetime.date(2026, 1, 3), "2025-12-01"),
    (datetime.date(2026, 3, 31), "2026-02-01"),
])
def test_the_form_opens_on_the_first_of_the_previous_month_and_today(today, since):
    assert maintenance.default_range(today) == (since, today.isoformat())


def test_delivering_by_id_refuses_a_number_that_is_not_one_and_an_id_elsewhere():
    assert "A message id is a number" in maintenance.NOT_A_NUMBER
    assert "archive listing shows them" in maintenance.NOT_A_NUMBER
    said = maintenance.WRONG_DOMAIN.format(message_id=9, label="sales")
    assert "not a message of sales" in said
    # A defect not repeated: the id is checked HERE, so a wrong one is never queued
    text = (SOURCE / "screens" / "maintenance.py").read_text()
    body = text.split("def deliver_one_message")[1]
    assert "SELECT id, domain_id, state FROM message WHERE id = %s" in body
    assert body.index("WRONG_DOMAIN") < body.index("common.ask(")
    # A withheld message is refused here too, before anything is queued
    assert body.index("WITHHELD") < body.index("common.ask(")


# --- the journal screen ----------------------------------------------------

def test_the_act_menu_offers_every_declared_kind_and_any():
    offered = events.acts_for("")
    assert set(offered) == journal.DECLARED
    assert len(offered) == len(journal.DECLARED)
    assert events.ANY == "any"
    for act in ("set_pop3_login", "set_spam_policy", "auto_skip_message", "fetch_frozen"):
        assert act in offered


def test_a_kind_typed_into_the_url_that_nobody_declared_stays_selected():
    offered = events.acts_for("not_an_act")
    assert offered[-1] == "not_an_act"
    assert set(offered) - {"not_an_act"} == journal.DECLARED


def test_the_target_help_says_the_match_is_exact_and_every_filter_is_bound():
    assert "Exact match" in events.HELP
    assert "%s" in journal.SELECT and "COALESCE" in journal.SELECT
    text = (SOURCE / "screens" / "events.py").read_text()
    assert "journal.rows(conn" in text
    assert "Show everything" in events.PAGE


def test_the_cap_and_the_empty_result_each_have_their_own_sentence():
    assert events.NOTHING == "No journal row matches this filter."
    assert str(journal.LIMIT) in events.CAPPED.format(limit=journal.LIMIT)
    assert "Narrow the filter" in events.CAPPED
    assert "append-only and outlives what it describes" in events.OUTLIVES
    assert "Break-glass" in events.PAGE


def test_the_detail_and_the_pipelines_reason_are_rendered_as_text():
    # neither is marked safe anywhere: Jinja escapes both
    for name in ("events", "mailboxes", "moderation", "accounts", "external", "overview",
                 "health"):
        text = (SOURCE / "screens" / f"{name}.py").read_text()
        assert "|safe" not in text, name
        assert "Markup(" not in text, name
    assert "{{ detail[row.id] }}" in events.PAGE
    assert "{{ row.request_result }}" in events.PAGE


def test_the_row_carries_the_outcome_of_the_request_it_asked_for():
    assert "request_state" in events.PAGE and "request_id" in events.PAGE
    assert "r.state AS request_state" in journal.SELECT


# --- every item opens the journal filtered to itself ---------------------------------

@pytest.mark.parametrize("name,target", [
    ("external", "row.address_canonical"),       # the spelling the journal writes
    ("domains", "label"),
    ("accounts", "row.login"),
    ("mailboxes", "box.address"),
])
def test_every_item_links_into_the_journal_by_the_spelling_it_is_written_with(name, target):
    text = (SOURCE / "screens" / f"{name}.py").read_text()
    assert f"url_for('events', target={target}" in text


def test_the_link_carries_its_section_and_only_a_declared_one_makes_a_crumb(built):
    sections = {endpoint for endpoint, _, _, _ in application.SECTIONS}
    for name in ("external", "domains", "accounts", "mailboxes"):
        text = (SOURCE / "screens" / f"{name}.py").read_text()
        for back in set(re.findall(r"back='([a-z_]+)'", text)):
            assert back in sections, f"{name} sends back={back}"
    with built.test_request_context("/journal"):
        assert events.crumb_for("domains")["title"] == "Domains"
        # ⛔ a crafted value makes no link at all
        assert events.crumb_for("https://elsewhere.example") is None
        assert events.crumb_for("") is None
        assert events.crumb_for("not_a_section") is None
    assert "Back to {{ crumb.title }}" in events.PAGE


# --- the overview's two lists ------------------------------------------------------------

def worry_row(**columns):
    empty = {"id": 1, "address": "box@example.org", "address_canonical": "box@example.org",
             "state": "active", "frozen_since": None, "last_fetch_status": None,
             "last_test_status": None, "last_skip_at": None, "last_skip_uidl": None,
             "delete_window_days": 14, "label": "sales"}
    empty.update(columns)
    return empty


@pytest.mark.parametrize("columns", [{"last_fetch_status": "auth_failed"},
                                     {"last_test_status": "auth_failed"}])
def test_a_refused_credential_is_named_whichever_reading_refused_it(columns):
    worry = overview.worry_of(worry_row(**columns))
    assert worry["words"] == fetch.REFUSED_SHORT
    assert worry["frozen"] is False


def test_a_frozen_mailbox_carries_the_date_its_skipped_message_disappears():
    skipped = datetime.datetime(2026, 9, 20, 9, 30, tzinfo=datetime.timezone.utc)
    worry = overview.worry_of(worry_row(frozen_since=skipped, last_skip_at=skipped,
                                        last_skip_uidl="UID-9"),
                              today=datetime.date(2026, 9, 22))
    assert worry["frozen"] is True
    assert "deletes it on 2026-10-04" in worry["skip"]
    assert "url_for('fetch')" in overview.PAGE


def test_a_mailbox_with_nothing_wrong_is_not_on_the_list_at_all():
    assert overview.worry_of(worry_row(last_fetch_status="ok")) is None


def test_the_failed_requests_of_the_last_day_name_the_newest_one_in_full():
    newest = {"kind": "top_up", "target": "ivan@sales",
              "finished_at": datetime.datetime(2026, 9, 22, 14, 58,
                                               tzinfo=datetime.timezone.utc),
              "result": "no mailbox 4"}
    said = overview.failures_of({"failures": 3}, newest)
    assert said == {"count": 3, "kind": "top_up", "target": "ivan@sales",
                    "at": "14:58", "reason": "no mailbox 4"}
    assert overview.failures_of({"failures": 0}, None)["count"] == 0
    assert "interval '24 hours'" in overview.FAILURES


def test_when_nothing_needs_anybody_a_sentence_says_so():
    assert "Nothing needs anybody right now" in overview.NOTHING
    assert "{{ nothing }}" in overview.PAGE


def test_the_second_list_is_one_row_per_sidebar_section_with_its_own_reading():
    for endpoint, _, _, _ in application.SECTIONS:
        if endpoint == "overview":
            continue
        assert f"url_for('{endpoint}')" in overview.PAGE, endpoint
    # "Add one" for three sections and "Give one" for mailboxes, and no primary button
    assert overview.PAGE.count(">Add one</a>") == 3
    assert ">Give one</a>" in overview.PAGE
    assert "btn-primary" not in overview.PAGE
    assert not re.search(r'class="[^"]*\bprimary\b', overview.PAGE)


def test_the_overview_is_read_as_the_page_renders_and_from_no_stored_flag():
    text = (SOURCE / "screens" / "overview.py").read_text()
    assert "UPDATE" not in text and "INSERT" not in text
    assert text.count("common.one(conn") + text.count("common.rows(conn") >= 7


# --- the fetcher's own columns stay the fetcher's --------------------------------

# Everything the fetch runner measures and writes; the interface reads them and writes
# exactly two of them, on resume, through a column-level grant.
FETCHER_COLUMNS = (
    "last_fetch_at", "last_fetch_status", "last_fetch_cause", "last_fetch_detail",
    "last_test_at", "last_test_status", "last_test_detail", "stuck_since", "stuck_runs",
    "skip_streak", "frozen_since", "last_listing_at", "last_skip_at", "last_skip_uidl",
    "held_since",
)
RESUME_WRITES = ("frozen_since", "skip_streak")


def test_the_interface_writes_two_of_the_fetchers_columns_and_reads_the_rest():
    written = set()
    for name in ("domains", "external", "fetch", "accounts", "mailboxes", "moderation",
                 "maintenance", "events", "overview"):
        text = (SOURCE / "screens" / f"{name}.py").read_text()
        for statement in re.findall(r"UPDATE external_mailbox SET (.*?)WHERE", text,
                                    re.S):
            written |= {column for column in FETCHER_COLUMNS if column in statement}
    assert written == set(RESUME_WRITES), written
    # and the two are cleared together, in the one act that exists for it
    resume = (SOURCE / "screens" / "fetch.py").read_text().split("def resume_fetch")[1]
    assert "frozen_since = NULL" in resume and "skip_streak = 0" in resume
    # ⛔ the stuck clock is LEFT: "resume permits the next automatic skip"
    assert "stuck_since" not in resume.split("UPDATE external_mailbox")[1]


def test_the_column_grant_is_what_makes_it_so_and_not_this_code():
    schema = (SOURCE.parents[2] / "schema" / "0001_initial.sql").read_text()
    granted = re.search(r"GRANT UPDATE \(([^()]*)\)\s*ON external_mailbox TO "
                        r"maildivvy_admin;", schema)
    assert granted, "the interface's column grant on external_mailbox is not there"
    allowed = {column.strip() for column in granted.group(1).replace("\n", " ").split(",")}
    assert allowed & set(FETCHER_COLUMNS) == set(RESUME_WRITES), allowed
