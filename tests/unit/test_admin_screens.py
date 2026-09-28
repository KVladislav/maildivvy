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
from pathlib import Path

import pytest
from flask import Flask

from maildivvy.admin import app as application
from maildivvy.admin import journal
from maildivvy.admin.screens import (accounts, common, domains, events, external, fetch,
                                     mailboxes, maintenance, moderation, overview)

SCREENS = (overview, domains, external, fetch, accounts, mailboxes, moderation,
           maintenance, events)
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

def test_the_sidebar_is_the_declared_list_in_its_order_with_its_two_separators():
    titles = [title for _, title, _, _ in application.SECTIONS]
    assert titles == ["Overview", "External mailboxes", "Domains", "People", "Mailboxes",
                      "Fetch", "Withheld messages", "Journal"]
    after = [title for _, title, _, separator in application.SECTIONS if separator]
    assert after == ["Overview", "Mailboxes"]


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


def test_the_404_is_rendered_inside_the_shell():
    assert "NOT_FOUND" in Path(application.__file__).read_text()
    assert "<h1>Not found</h1>" in application.NOT_FOUND


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
    status, detail = fetch.status_of(row(last_fetch_status="error", last_fetch_cause=cause,
                                         last_fetch_detail="mpop: something"))
    assert says in status
    assert detail == "mpop: something"      # the raw detail is shown beneath, as text


def test_the_causes_this_screen_knows_are_the_fetch_runners_own_closed_list():
    from maildivvy.fetch import outcome

    assert tuple(fetch.CAUSES) == outcome.CAUSES


def test_an_error_with_no_cause_recorded_says_it_cannot_be_told_apart():
    status, _ = fetch.status_of(row(last_fetch_status="error", last_fetch_cause=None))
    assert "cannot be told apart" in status


def test_a_refused_credential_is_its_own_status_and_never_goes_through_a_cause():
    status, detail = fetch.status_of(row(last_fetch_status="auth_failed",
                                         last_fetch_cause="transient"))
    assert "credential refused" in status
    assert "very likely changed the password" in status
    assert detail is None


@pytest.mark.parametrize("columns,says", [
    ({"last_fetch_status": "ok"}, "ok"),
    ({"last_fetch_status": "no_new_mail"}, "no new mail"),
    ({"last_fetch_status": None}, "has not run yet"),
    ({"state": "deactivated"}, "disabled"),
    ({"state": "deactivated", "enabling": True}, "asked to enable"),
    ({"deleting": True}, "asked to delete"),
])
def test_the_other_statuses_are_the_closed_list_the_screen_names(columns, says):
    assert says in fetch.status_of(row(**columns))[0]


def test_a_held_mailbox_says_the_mail_is_waiting_at_the_provider():
    held = datetime.datetime(2026, 9, 22, 10, 0, tzinfo=datetime.timezone.utc)
    status, _ = fetch.status_of(row(held_since=held, last_fetch_status="error",
                                    last_fetch_cause="transient"))
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
    assert 'type="password"' not in mailboxes.CARD_PAGE
    assert "their password and their state are set on their own page" in mailboxes.CARD_PAGE
    assert "url_for('account', account_id=box.account_id)" in mailboxes.CARD_PAGE


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
    for name in ("events", "mailboxes", "moderation", "accounts", "external", "overview"):
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
    assert 'class="primary"' not in overview.PAGE


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
