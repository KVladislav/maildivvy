"""The shell every screen renders in, and the sweep: every page and every refused form,
opened on the real database, keeps the design's rules.

`SWEPT` and `REFUSALS` live in `admin_pages.py`, where every screen's tests can read
them.
"""

import re

import pytest
from markupsafe import escape

from admin_db import ADMIN, counts, main_of
from admin_db import text as body_of
from maildivvy.admin import app as application
from admin_pages import (MOMENT, NUMERIC, REFUSALS, SWEPT, Tree, keeps_the_designs_rules,
                         open_state, red_out_of_place)
from maildivvy.admin.screens import common
from maildivvy.admin.style import STYLESHEET
import datetime
from flask import Flask
from markupsafe import Markup
from maildivvy.admin import auth
from maildivvy.admin.screens import (accounts, fetch,
                                     health, overview)
from admin_stand_in import ACTS, ASKED, COUNTS, HoldersConnection, POLICY, THREE, page_of, shape, templates, worry_row


@pytest.fixture
def opened(app_db, database, ids, monkeypatch):
    """`opened(state)`: a browser signed in on the scene in that sweep state."""
    return lambda state: open_state(state, app_db, database, ids, monkeypatch)


@pytest.mark.parametrize("state,path,status", SWEPT)
def test_every_page_keeps_the_designs_rules(opened, ids, state, path, status):
    browser = opened(state)
    path = path.format(**ids)
    answer = browser.get(path)
    assert answer.status_code == status, (path, answer.status_code)
    # the one stylesheet, `style.py`'s, inlined whole, and no other
    assert re.findall(r"<style>(.*?)</style>", body_of(answer), re.S) == [STYLESHEET], path
    html = body_of(answer).split("</head>", 1)[1]
    # every page but the one at no address is in a section, marked in the sidebar
    keeps_the_designs_rules(html, path, 0 if status == 404 else 1)
    # and every moment on it is printed the one way
    other = re.findall(r".{0,30}\d:\d\d.{0,10}", MOMENT.sub("", html))
    assert not other, (path, other)


@pytest.mark.parametrize("state,path,form", REFUSALS)
def test_every_refused_form_keeps_the_designs_rules_and_writes_nothing(
        opened, ids, database, state, path, form):
    browser = opened(state)
    path = path.format(**ids)
    form = {name: value.format(**ids) for name, value in form.items()}
    before = counts(database)
    answer = browser.post(path, form)
    assert answer.status_code == 400, (path, answer.status_code)
    html = body_of(answer).split("</head>", 1)[1]
    assert '<div class="flash bad">' in html, path
    keeps_the_designs_rules(html, path, 1)
    assert counts(database) == before, path


@pytest.mark.parametrize("state,path,form",
                         [(state, path, form) for state, path, form in REFUSALS
                          if NUMERIC & set(form)])
def test_a_number_too_long_to_read_in_any_refused_form_is_never_an_error_page(
        opened, ids, database, state, path, form):
    browser = opened(state)
    path = path.format(**ids)
    form = {name: value.format(**ids) for name, value in form.items()}
    before = counts(database)
    for name in NUMERIC & set(form):
        for typed in ("9" * 5000, "-" + "9" * 5000):
            answer = browser.post(path, {**form, name: typed})
            assert answer.status_code < 500, (path, name, answer.status_code)
    assert counts(database) == before


def test_every_get_route_is_swept(app_db):
    """A screen added later joins the sweep, or this fails."""
    adapter = app_db.url_map.bind("localhost")
    swept = {adapter.match(path.split("?")[0].format_map(Ids()), "GET")[0]
             for state, path, status in SWEPT if status != 404}
    served = {rule.endpoint for rule in app_db.url_map.iter_rules()
              if "GET" in rule.methods and rule.endpoint not in ("static", "sign_in")}
    assert served <= swept, served - swept


class Ids(dict):
    """Any id a path names, for matching the path against the map."""

    def __missing__(self, key):
        return 1


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


# --- the shell -------------------------------------------------------------------

def test_the_sidebar_links_each_section_by_its_route_and_counts_the_real_rows(app_db,
                                                                             browser):
    from flask import url_for

    from maildivvy.admin import app as application

    nav = body_of(browser.get("/")).split('<nav class="nav"', 1)[1].split("</nav>", 1)[0]
    with app_db.test_request_context():
        routes = [url_for(endpoint) for endpoint, *_ in application.SECTIONS]
    assert re.findall(r'href="([^"]+)"', nav) == routes
    # two external mailboxes, two domains, four people, two mailboxes and the two domains'
    # archives, one withheld message: the scene's own rows, read in one statement
    assert re.findall(r'<span class="n">(\d+)</span>', nav) == ["2", "2", "4", "4", "1"]


# --- a race the screen's own check cannot see -------------------------------------

def races(ids, made):
    """Each add form, and the same value written by a competitor whose transaction is
    still open when the form's own duplicate check runs."""
    long = "an-archive-password-that-is-long"
    return [
        ("/domains/add", {"label": "north", "password": long, "password2": long},
         "INSERT INTO domain (label, archive_password_hash) VALUES ('north', %s)", (made,),
         "There is already a domain called north."),
        ("/people/add", {"login": "anna", "password": long, "password2": long},
         "INSERT INTO account (login, password_hash) VALUES ('anna', %s)", (made,),
         "There is already a person called anna."),
        ("/mailboxes/add", {"domain_id": str(ids["sales"]), "account_id": str(ids["ivan"])},
         "INSERT INTO mailbox (account_id, domain_id) VALUES (%s, %s)",
         (ids["ivan"], ids["sales"]), "That person already has a mailbox in this domain."),
        ("/external/add", {"address": "desk@example.org", "pop3_host": "pop.example.org",
                           "pop3_port": "995", "smtp_host": "smtp.example.org",
                           "smtp_port": "587", "window": "14", "domain_choice": "free",
                           "domain_id": str(ids["sales"])},
         "INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host) "
         "VALUES ('Desk@example.org', 'desk@example.org', 'pop.example.org', "
         "'smtp.example.org')", (), "That provider mailbox is already here"),
    ]


@pytest.mark.parametrize("which", range(4))
def test_a_value_a_concurrent_submission_wrote_first_is_a_sentence_and_not_a_500(
        browser, ids, database, which):
    from admin_db import competitor, hashed, in_threads, main_of, waiting_on_a_lock

    path, form, statement, parameters, sentence = races(ids, hashed("x" * 20))[which]
    rival = competitor(database)
    rival.cursor().execute(statement, parameters)
    before = counts(database)
    join = in_threads(lambda: browser.post(path, form))
    try:
        # the form's check found nothing, and its INSERT now waits on the unique index
        assert waiting_on_a_lock(database, 1)
    finally:
        rival.commit()
        rival.close()
    answer, = join()
    assert answer.status_code == 400 and sentence in main_of(answer)
    after = counts(database)
    # the rival's one row, and nothing of the form's: no request, no journal row
    assert sum(after.values()) == sum(before.values()) + 1
    assert after["request"] == before["request"] and after["audit"] == before["audit"]


# --- a waiting row, and the time to look again by ------------------------------------

WAITING_SINCE = "2026-11-02 10:00+00"
WAITING = [  # (kind, target, payload, every page whose row reads it)
    ("create_mailbox", "olga@sales", '{{"mailbox_id": {olga_sales}}}',
     ["/mailboxes", "/domains/{sales}", "/people/{olga}", "/mailboxes/{olga_sales}"]),
    ("delete_account", "ivan", '{{"account_id": {ivan}}}', ["/people", "/people/{ivan}"]),
    ("test_credential", "office@example.org", '{{"external_mailbox_id": {office_external}}}',
     []),
    ("release", "{withheld}", '{{"message_id": {withheld}}}', ["/withheld"]),
    ("create_domain", "office", '{{"domain_id": {office}}}', ["/domains/{office}"]),
]


@pytest.mark.parametrize("period", [7, None])
def test_every_waiting_row_says_when_to_look_again_by_the_real_timers_period(
        browser, ids, database, tmp_path, monkeypatch, period):
    from maildivvy.lib import timer

    unit = tmp_path / "maildivvy-fetch.timer"
    if period:
        unit.write_text(f"[Timer]\nOnCalendar=*:0/{period}\n")
    # the screens read the installed timer; here the same reader reads this one
    monkeypatch.setattr(timer.timer_period, "__defaults__", (str(unit),))
    for kind, target, payload, _ in WAITING:
        database.sql("INSERT INTO request (kind, target, payload, asked_by, created_at) "
                     "VALUES (%s, %s, %s::jsonb, %s, %s)",
                     (kind, target.format(**ids), payload.format(**ids), ADMIN, WAITING_SINCE))
    says = ("by 2026-11-02 10:07 UTC" if period
            else str(escape(common.NO_PERIOD)))
    for kind, _, _, paths in WAITING:
        for path in paths:
            page = main_of(browser.get(path.format(**ids)))
            assert "2026-11-02 10:00 UTC" in page and says in page, (kind, path)
    # an external mailbox's rows name the wait alone: what comes of it is the provider's
    for path in ("/external", f"/external/{ids['office_external']}"):
        assert "asked to check the password" in main_of(browser.get(path)), path


# --- the overview, read as it renders ------------------------------------------------------

def test_the_overview_reads_the_rows_as_the_page_renders_and_writes_nothing(browser, ids,
                                                                          database):
    before = counts(database)
    first = main_of(browser.get("/"))
    assert "1 withheld message(s)" in first
    database.sql("UPDATE message SET state = 'released' WHERE id = %s", (ids["withheld"],))
    database.sql("UPDATE external_mailbox SET last_test_status = 'auth_failed', "
                 "last_test_at = now() WHERE id = %s", (ids["office_external"],))
    second = main_of(browser.get("/"))
    assert "withheld message(s)" not in second and "office@example.org" in second
    assert counts(database) == before



# ================================================================================================
# With the database stood in (admin_stand_in.py): what a screen renders for the rows it is handed.
# ================================================================================================

# --- the shell and the sidebar -----------------------------------------


def test_the_sidebar_is_the_declared_list_in_its_order_with_its_separators():
    titles = [title for _, title, _, _ in application.SECTIONS]
    assert titles == ["Overview", "External mailboxes", "Domains", "People", "Mailboxes",
                      "Fetch", "Withheld messages", "Journal", "Health"]
    # Health, the machine rather than its mail, stands apart at the end
    after = [title for _, title, _, separator in application.SECTIONS if separator]
    assert after == ["Overview", "Mailboxes", "Journal"]


def test_the_login_page_has_no_shell_no_sidebar_and_no_way_into_a_screen(built):
    assert "nav" not in application.LOGIN
    for endpoint in ("domains", "external", "fetch"):
        assert endpoint not in application.LOGIN


def test_a_form_number_is_ascii_digits_within_a_bigint_and_nothing_else():
    # str.isdigit() is true for '²', which int() then refuses, and true for a
    # number past a bigint, which the database refuses - both 500s. `as_int` refuses both.
    assert common.as_int("7") == 7 and common.as_int(" 42 ") == 42
    assert common.as_int(str(2 ** 63 - 1)) == 2 ** 63 - 1
    for bad in ("²", "1²", "", "  ", "seven", "-1", "1.0", str(2 ** 63), str(2 ** 70),
                "1" * 5000):                    # past the digits `int()` reads at all
        assert common.as_int(bad) is None, bad
    # want_int turns the None into a sentence, never a 500
    with pytest.raises(common.validate.Refused):
        common.want_int("²", "domain")


def test_a_row_id_past_a_bigint_in_a_url_is_refused_by_the_route(built):
    # The `<int:...>` converter is bounded, so a huge id 404s rather than
    # overflowing the query to a 500
    adapter = built.url_map.bind("maildivvy.invalid")
    adapter.match("/people/7")                                  # the control: an ordinary id
    with pytest.raises(Exception):                             # noqa: B017 - NotFound: past a bigint
        adapter.match(f"/people/{2 ** 63}")


FORM = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
SHAPE_MACROS = set(re.findall(r"macro (\w+)\(", common.SHAPES))


def test_every_post_form_in_every_template_calls_the_csrf_macro_first_and_no_get_form_does(
        built):
    """A POST form added to any template without `{{ csrf() }}` right after its opening
    tag fails here, before a page carrying it is ever served."""
    held = built.jinja_env.loader.mapping
    posts = 0
    for name, source in held.items():
        for form in FORM.finditer(source):
            after = source[form.end():form.end() + len("{{ csrf() }}")]
            if re.search(r"""method=["']?post""", form.group(0), re.IGNORECASE):
                posts += 1
                assert after == "{{ csrf() }}", (name, form.group(0))
            else:
                assert after != "{{ csrf() }}", (name, form.group(0))
    assert posts >= 20, posts     # the scan found the screens' forms, not none


def test_every_shape_a_template_calls_it_imports_so_no_branch_calls_nothing(built):
    """A shape is a macro of `common.SHAPES`, imported by name; one called but not
    imported would fail only on the branch that draws it, which no sweep may open."""
    for name, source in built.jinja_env.loader.mapping.items():
        if name == "common.SHAPES":
            continue
        imported = set()
        for names in re.findall(r'from "common\.SHAPES" import ([\w, ]+?)(?: with context)? %\}',
                                source):
            imported |= {each.strip() for each in names.split(",")}
        own = set(re.findall(r"macro (\w+)\(", source))
        called = {shape for shape in SHAPE_MACROS if re.search(rf"\b{shape}\(", source)}
        assert called - own <= imported, (name, called - own - imported)


def test_a_template_held_by_name_escapes_what_it_is_given(built):
    # Flask escapes by the template's file name, and these names are no file's
    with built.test_request_context("/"):
        html = built.jinja_env.from_string(
            '{% from "domains.IN_FRONT" import in_front %}{{ in_front(row) }}').render(
            row={"external_id": None, "waiting": False})
        assert "&mdash;" in html          # the template's own markup stays markup
        refused = built.jinja_env.get_template("app.REFUSED").render(message="<b>x</b>")
        assert refused == "<h1>Refused</h1><p>&lt;b&gt;x&lt;/b&gt;</p>"


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


@pytest.mark.parametrize("origin, same", [
    ("https://mail.example.org:8443", True),
    ("https://mail.example.org", False),
    ("https://mail.example.org:9443", False),
])
def test_an_interface_reached_on_another_port_is_its_own_origin_by_that_port(origin, same):
    # through a tunnel or NAT the browser names the port in `Host` and `Origin` alike
    with Flask("t").test_request_context("/people", method="POST", headers={"Origin": origin},
                                         base_url="https://mail.example.org:8443"):
        assert application.same_origin() is same


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
        except Exception:  # noqa: BLE001 - any refusal to match is what this wants
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


def test_a_setting_row_is_one_post_form_with_its_title_its_fields_and_its_own_button(
        built, monkeypatch):
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
    # the setting's form carries the session's token first, like every other post form
    monkeypatch.setattr(application, "form_token", lambda: "the-token")
    signed = shape(built, "{{ setting('/people/2/comment', 'Comment', none, '', 'Save') }}")
    assert signed.startswith('<form class="setting" method="post" action="/people/2/comment">'
                             '<input type="hidden" name="_csrf" value="the-token"><div>')


# --- the interface's small rules: lock order, the cookie, the policy, one time -----------------


@pytest.mark.parametrize("method,path,form", [("post", "/people/1/admin", {}),
                                              ("post", "/people/1/state", {"state": "blocked"}),
                                              ("get", "/people/1/delete", {})])
def test_the_last_administrator_decision_reads_the_person_after_taking_the_lock(
        people_world, monkeypatch, method, path, form):
    # the row a decision reads is the one the lock's holder left, never one read before it
    order = []
    reading = common.one

    def one(conn, sql, parameters=()):
        if sql.startswith(accounts.PEOPLE):
            order.append("read")
        return reading(conn, sql, parameters)

    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(accounts.adminlock, "lock", lambda cursor: order.append("lock"))
    monkeypatch.setattr(application, "connection", lambda: HoldersConnection())
    answer = getattr(people_world, method)(path, data=form)
    assert answer.status_code < 500, answer.status_code
    assert order[:2] == ["lock", "read"], order


def test_the_login_page_deletes_a_cookie_only_when_the_request_carried_one(signed_out):
    # a link from another site arrives without the cookie (SameSite=Strict): deleting it
    # there would sign out every other tab of this browser
    for path in ("/people", "/sign-in"):
        answer = signed_out.get(path)
        assert answer.status_code == 200 and "Set-Cookie" not in answer.headers, path
    # a cookie that did not open a session is deleted, as before
    signed_out.set_cookie(auth.COOKIE, "not-ours.0000")
    answer = signed_out.get("/people")
    assert answer.status_code == 200
    assert answer.headers["Set-Cookie"].startswith(f"{auth.COOKIE}=;"), answer.headers


def test_every_response_loads_nothing_runs_no_script_and_is_never_framed(shell):
    # the interface ships no script and loads nothing: its one stylesheet is inlined
    for path in ("/health", "/sign-in", "/no-such-page"):
        assert shell.get(path).headers["Content-Security-Policy"] == POLICY, path


def test_a_moment_is_printed_one_way_in_utc_to_the_minute_with_its_zone_said():
    kyiv = datetime.timezone(datetime.timedelta(hours=2))
    assert common.moment(datetime.datetime(2026, 9, 30, 16, 58, 41, 5, tzinfo=kyiv)) \
        == "2026-09-30 14:58 UTC"
    assert common.moment(datetime.datetime(2026, 9, 30, 14, 58)) == "2026-09-30 14:58 UTC"
    assert common.moment(None) == ""
    with pytest.raises(TypeError):
        common.moment("2026-09-30 14:58")         # a fixture's string is no moment


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


# --- a waiting row, a failed one, and "look again by" ---------------------------


@pytest.mark.parametrize("kind,verb", [
    ("create_mailbox", "connect"), ("connect", "connect"), ("transfer", "transfer"),
    ("delete_mailbox", "delete"), ("delete_account", "delete"), ("top_up", "top up"),
    ("deliver_one", "deliver one message"), ("release", "release"),
    ("test_credential", "check the password"),
    ("activate_external_mailbox", "enable"), ("create_domain", "create"),
])
def test_a_waiting_row_names_its_verb_and_the_time_it_was_asked(kind, verb):
    reading = common.queue_reading(kind, "queued", ASKED, None, THREE)
    assert reading["waiting"] == f"asked to {verb}, 2026-09-22 14:58 UTC"
    assert reading["failed"] is None


def test_look_again_is_the_asking_time_plus_the_real_period_and_never_a_constant():
    assert common.queue_reading("top_up", "queued", ASKED, None, THREE)["look_again"] \
        == "the pipeline runs by 2026-09-22 15:01 UTC"
    # an operator who changes the cadence gets the screen's sentence changed with it
    hourly = common.queue_reading("top_up", "running", ASKED, None,
                                  datetime.timedelta(hours=1))
    assert hourly["look_again"] == "the pipeline runs by 2026-09-22 15:58 UTC"
    # ⛔ a period that could not be read is said so, never guessed at three minutes
    assert common.queue_reading("top_up", "queued", ASKED, None, None)["look_again"] \
        == common.NO_PERIOD
    assert "3" not in common.NO_PERIOD


def test_enabling_says_the_pipeline_checks_the_password_first():
    reading = common.queue_reading("activate_external_mailbox", "queued", ASKED, None, THREE)
    assert reading["look_again"] \
        == "the pipeline checks the password and enables it by 2026-09-22 15:01 UTC"


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
        == "asked to brand_new_kind, 2026-09-22 14:58 UTC"


def test_the_four_sub_selects_read_one_and_the_same_newest_request():
    sql = common.newest_request("(r.payload ->> 'mailbox_id')::bigint = m.id")
    for column in ("kind", "state", "created_at", "result"):
        assert f"SELECT r.{column} FROM request r" in sql
        assert f"AS newest_{column}" in sql
    assert sql.count("ORDER BY r.id DESC LIMIT 1") == 4
    assert "%s" not in sql, "a bound parameter here would be bound four times"


# --- the overview's two lists ------------------------------------------------------------


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
                    "at": "2026-09-22 14:58 UTC", "reason": "no mailbox 4"}
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
