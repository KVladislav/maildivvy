"""The Health screen and the overview's reading of health's report, read without a machine.

The report is a file health's timer wrote earlier, so every reading here is of a file put
in place by the test: a current one, one with a FAIL and an UNKNOWN in it, a stale one,
one dated in the future, a missing one, a truncated one and one that does not say it is
complete. Each of the last five is its own state on the page, and none reads as fine.

The pages are rendered through the application's own shell with the Flask test client;
only the database behind the sidebar's counts and the overview's rows is stood in for.
"""

import datetime
import json
from pathlib import Path

import pytest
from flask import Flask

from maildivvy.admin import app as application
from maildivvy.admin import auth
from maildivvy.admin.screens import common
from maildivvy.admin.screens import health as screen
from maildivvy.admin.screens import (accounts, domains, events, external, fetch, mailboxes,
                                     maintenance, moderation, overview)
from maildivvy.health import report, settings

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 29, 14, 3, 20, tzinfo=UTC)
TAKEN = datetime.datetime(2026, 9, 29, 14, 0, 4, tzinfo=UTC)
SOURCE = Path(application.__file__).resolve().parent
SCREENS = (overview, domains, external, fetch, accounts, mailboxes, moderation, maintenance,
           events, screen)


def check(name, state, reading, problem=None):
    return {"name": name, "state": state, "reading": reading, "problem": problem}


def subsystem(name, *checks):
    return {"name": name, "state": report.worst(c["state"] for c in checks),
            "checks": list(checks)}


ALL_PASS = [
    subsystem("host", check("store mount", "PASS", "/srv/maildivvy/store mounted")),
    subsystem("tls", check("expiry", "PASS", "74 days left")),
    subsystem("database", check("answers", "PASS", "PostgreSQL 18.1 answered")),
]
MIXED = [
    subsystem("host", check("store mount", "PASS", "/srv/maildivvy/store mounted")),
    subsystem("antivirus",
              check("daemon", "FAIL", "no answer on /run/clamav/clamd.ctl",
                    "ClamAV is not answering: incoming mail waits at the provider"),
              check("signatures", "PASS", "3 h old")),
    subsystem("tls", check("expiry", "WARN", "18 days left",
                           "under 21 days left: the renewal has not happened")),
    subsystem("network", check("publication", "UNKNOWN", "no probe result recorded",
                               "no outside probe result is recorded: run the outside probe")),
]


def write(path, subsystems, taken_at=TAKEN, complete=True):
    path.write_text(json.dumps({"format": 1, "taken_at": taken_at.isoformat(),
                                "state": report.worst(s["state"] for s in subsystems),
                                "subsystems": subsystems, "complete": complete}))
    return path


@pytest.fixture
def files(tmp_path):
    """The report, the settings and the timer, where the screen is told to read them."""
    timer = tmp_path / "maildivvy-health.timer"
    timer.write_text("[Timer]\nOnCalendar=*:0/5\n")
    return {"report": tmp_path / "health.json", "conf": tmp_path / "health.conf",
            "timer": timer}


def read(files, now=NOW):
    return screen.reading(report_path=files["report"], conf_path=files["conf"],
                          timer_path=files["timer"], now=now)


# --- the reading -------------------------------------------------------------------------

def test_a_current_report_is_read_with_its_own_time_and_age(files):
    write(files["report"], ALL_PASS)
    said = read(files)
    assert said["condition"] == "current" and said["state"] == "PASS"
    assert said["taken"] == "2026-09-29 14:00:04 UTC"
    assert said["age"] == "3 minutes"
    assert said["bound"] == "15 minutes" and said["period"] == "5 minutes"
    assert [s["name"] for s in said["subsystems"]] == ["host", "tls", "database"]
    assert said["counts"] == "3 PASS"
    assert said["failing"] == []


def test_every_check_keeps_healths_own_sentence_and_only_fail_is_failing(files):
    write(files["report"], MIXED)
    said = read(files)
    assert said["condition"] == "current" and said["state"] == "FAIL"
    assert said["counts"] == "1 PASS, 1 WARN, 1 UNKNOWN, 1 FAIL"
    assert said["failing"] == [{"name": "antivirus", "check": "daemon", "problem":
                                "ClamAV is not answering: incoming mail waits at the provider"}]
    network = [s for s in said["subsystems"] if s["name"] == "network"][0]
    # UNKNOWN is shown with health's own message and is special-cased for nobody
    assert network["state"] == "UNKNOWN"
    assert network["checks"][0]["problem"] == \
        "no outside probe result is recorded: run the outside probe"


def test_a_stale_report_reads_unknown_and_a_fail_in_it_stays_a_fail(files):
    write(files["report"], MIXED, taken_at=NOW - datetime.timedelta(minutes=42))
    said = read(files)
    assert said["condition"] == "stale"
    assert said["age"] == "42 minutes"
    # the age said once, in one sentence, with the bound it is past
    assert said["why"] == "42 minutes old, older than 15 minutes, so the checks have stopped"
    states = {s["name"]: s["state"] for s in said["subsystems"]}
    assert states == {"host": "UNKNOWN", "antivirus": "FAIL", "tls": "UNKNOWN",
                      "network": "UNKNOWN"}
    # the stale rule keeps the states, but the freshness line is said once, not per row
    for found in said["subsystems"]:
        assert "freshness" not in [c["name"] for c in found["checks"]]
    # a FAIL in a stale report is still named, with the report's own time beside it
    assert [f["name"] for f in said["failing"]] == ["antivirus"]


def test_a_report_at_the_bound_is_current_and_one_second_past_it_is_stale(files):
    write(files["report"], ALL_PASS, taken_at=NOW - datetime.timedelta(minutes=15))
    assert read(files)["condition"] == "current"
    write(files["report"], ALL_PASS,
          taken_at=NOW - datetime.timedelta(minutes=15, seconds=1))
    assert read(files)["condition"] == "stale"


def test_a_report_dated_in_the_future_is_stale_and_says_why(files):
    write(files["report"], ALL_PASS, taken_at=NOW + datetime.timedelta(hours=2))
    said = read(files)
    assert said["condition"] == "stale" and said["state"] == "UNKNOWN"
    assert said["why"] == "dated in the future, so the clock or the file is wrong"
    assert said["age"] == "dated in the future"
    assert all("freshness" not in [c["name"] for c in s["checks"]]
               for s in said["subsystems"])


def test_the_bound_is_the_one_healths_own_settings_give_the_cached_command(files):
    # the screen and `maildivvy-health --cached` read one file with one bound
    assert settings.Settings().stale_minutes == 15
    files["conf"].write_text("stale_minutes=60\n")
    write(files["report"], ALL_PASS, taken_at=NOW - datetime.timedelta(minutes=42))
    said = read(files)
    assert said["condition"] == "current" and said["bound"] == "1 hour"


@pytest.mark.parametrize("damage, words", [
    (None, "cannot read the report"),
    ('{"format": 1, "taken_at": "2026-09-29T14:00', "not whole JSON"),
    ("incomplete", "does not say it is complete"),
    ('{"complete": true, "taken_at": "yesterday", "subsystems": []}',
     "not one this program writes"),
    # a time with no zone cannot be aged at all: the page would fail instead of saying so
    ('{"complete": true, "taken_at": "2026-09-29T14:00:04", "subsystems": []}',
     "not one this program writes"),
])
def test_a_missing_or_damaged_report_is_no_report_at_all_and_never_fine(files, damage, words):
    if damage == "incomplete":
        write(files["report"], ALL_PASS, complete=False)
    elif damage is not None:
        files["report"].write_text(damage)
    said = read(files)
    assert said["condition"] == "unreadable" and said["state"] == "UNKNOWN"
    assert words in said["why"]
    assert said["subsystems"] == [] and said["taken"] is None and said["age"] is None
    assert said["failing"] == []


def test_settings_that_cannot_be_read_leave_the_report_unjudged(files):
    files["conf"].write_text("stale_minuets=20\n")          # health itself refuses to run
    write(files["report"], ALL_PASS)
    said = read(files)
    assert said["condition"] == "unreadable" and said["state"] == "UNKNOWN"
    assert "stale_minuets" in said["why"]


def test_a_timer_that_cannot_be_read_is_a_sentence_and_not_a_guess(files):
    files["timer"].unlink()
    write(files["report"], ALL_PASS)
    assert read(files)["period"] is None


@pytest.mark.parametrize("minutes, words", [
    (0, "under a minute"), (1, "1 minute"), (119, "119 minutes"), (120, "2 hours"),
    (60 * 47, "47 hours"), (60 * 48, "2 days"), (60 * 24 * 9 + 5, "9 days"),
])
def test_an_age_is_said_in_whole_units(minutes, words):
    assert screen.age_words(datetime.timedelta(minutes=minutes, seconds=20)) == words


# --- read-only -----------------------------------------------------------------------------

def test_the_screen_runs_nothing_writes_nothing_and_has_no_act():
    text = (SOURCE / "screens" / "health.py").read_text()
    for forbidden in ("subprocess", "import checks", "checks.run", "write_json",
                      "replace_whole", "write_textfile", "open(",
                      "UPDATE", "INSERT", "method=\"post\"", "app_.post", "methods="):
        assert forbidden not in text, forbidden
    # it reads through health's own reader, so the two cannot disagree about a file
    assert "report.read_json(" in text and "settings.read(" in text
    assert screen.REPORT == settings.REPORT


# --- the pages, rendered --------------------------------------------------------------------------

NAV = []


@pytest.fixture
def client(files, monkeypatch):
    """The application's own rules and shell, signed in, with no database behind them."""
    made = Flask("maildivvy-test")
    application.register(made)
    for module in SCREENS:
        module.register(made)
    application.guard_every_endpoint(made)
    made.config.update(MAILDIVVY_HEALTH_REPORT=files["report"],
                       MAILDIVVY_HEALTH_CONF=files["conf"],
                       MAILDIVVY_HEALTH_TIMER=files["timer"], MAILDIVVY_HEALTH_NOW=NOW)
    monkeypatch.setattr(application, "current_identity", lambda: auth.Identity("t", 1))
    monkeypatch.setattr(application, "connection", lambda: None)
    monkeypatch.setattr(application, "navigation", lambda conn, current=None: NAV)
    return made.test_client()


def main_of(response):
    html = response.get_data(as_text=True)
    return html.split("<main>", 1)[1].split("</main>", 1)[0]


def test_the_screen_lists_every_subsystem_its_state_and_every_check(client, files):
    write(files["report"], MIXED)
    shown = main_of(client.get("/health"))
    assert "<h1>Health</h1>" in shown
    assert "2026-09-29 14:00:04 UTC" in shown and "3 minutes" in shown
    assert "the health timer's own period (5 minutes)" in shown
    for name in ("host", "antivirus", "tls", "network"):
        assert f"<code>{name}</code>" in shown, name
    for state in ("PASS", "WARN", "UNKNOWN", "FAIL"):
        assert f'<span class="badge state-{state.lower()}">{state}</span>' in shown, state
    assert "ClamAV is not answering: incoming mail waits at the provider" in shown
    assert "no outside probe result is recorded: run the outside probe" in shown
    assert 'class="banner"' not in shown


def test_a_stale_report_is_a_banner_above_the_table(client, files):
    write(files["report"], MIXED, taken_at=NOW - datetime.timedelta(minutes=42))
    shown = main_of(client.get("/health"))
    # a stale report is a warning: the WARN palette, on the banner itself
    banner = shown.split('<p class="banner state-warn">', 1)[1].split("</p>", 1)[0]
    assert " ".join(banner.split()) == (
        "This report is 42 minutes old, older than 15 minutes, so the checks have stopped. "
        "Every subsystem below reads UNKNOWN at best; a FAIL in it is still a FAIL.")
    # said once, above the table, and under no subsystem
    assert "<code>freshness</code>" not in shown and shown.count("42 minutes") == 1
    # and the lede does not say the bound and the period again beneath it
    lede = shown.split("</p>", 2)[1]
    assert "The whole reads" in lede
    assert "own period" not in lede and "is stale" not in lede


def test_a_future_dated_report_is_the_same_warning(client, files):
    write(files["report"], ALL_PASS, taken_at=NOW + datetime.timedelta(hours=2))
    shown = main_of(client.get("/health"))
    assert '<p class="banner state-warn">This report is dated in the future' in shown
    assert "own period" not in shown


def test_the_banner_colours_are_the_states_own_and_touch_no_other_banner():
    for state in ("warn", "fail"):
        assert f".banner.state-{state} {{" in application.STYLE, state
    # the plain `.banner` rule, which the break-glass and shown-once banners use, is as it was
    assert ".banner { border: 2px solid #111; padding: .75rem; margin: 0 0 1rem; " \
           "font-weight: bold; }" in application.STYLE
    assert '<p class="banner">Signed in with the break-glass account' in application.SHELL


def test_a_missing_report_is_a_banner_and_no_table(client, files):
    shown = main_of(client.get("/health"))
    # stronger than stale: nothing at all is known, so it is the FAIL palette
    assert '<p class="banner state-fail">No health report could be read' in shown
    assert str(files["report"]) in shown
    assert "<table>" not in shown
    assert '<span class="badge' not in shown


def test_a_check_is_rendered_as_text_never_as_markup(client, files):
    write(files["report"], [subsystem("host", check("x", "FAIL", "<b>r</b>", "<script>p"))])
    shown = main_of(client.get("/health"))
    assert "<script>" not in shown and "&lt;script&gt;p" in shown


def test_the_screen_needs_a_session_as_every_other_does(files):
    made = Flask("maildivvy-test")
    application.register(made)
    screen.register(made)
    application.guard_every_endpoint(made)
    assert getattr(made.view_functions["health"], "maildivvy_guarded", False)
    assert "health" not in application.PUBLIC


# --- the overview ------------------------------------------------------------------

ZEROES = {"enabled": 0, "disabled": 0, "enabling": 0, "refused": 0, "frozen": 0,
          "last_run": None, "waiting": 0, "oldest": None, "failures": 0, "domains": 0,
          "free": 0, "people": 1, "blocked": 0, "administrators": 1, "mailboxes": 0,
          "archives": 0}


@pytest.fixture
def quiet_database(monkeypatch):
    """The overview's rows, all saying nothing is wrong."""
    def one(conn, sql, parameters=()):
        return None if sql in (overview.NEWEST_FAILURE, overview.LAST_ACT) else dict(ZEROES)
    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", lambda conn, sql, parameters=(): [])


def attention_of(response):
    return main_of(response).split("<h2>Sections</h2>")[0]


def sections_of(response):
    return main_of(response).split("<h2>Sections</h2>")[1]


def test_with_a_current_report_and_no_fail_nothing_needs_anybody(client, files,
                                                                  quiet_database):
    write(files["report"], [s for s in MIXED if s["name"] != "antivirus"])
    response = client.get("/")
    assert "Nothing needs anybody right now" in attention_of(response)
    assert "holds no FAIL" in overview.NOTHING
    # WARN and UNKNOWN are counted in the section's row, not listed as worries
    row = sections_of(response)
    assert "1 PASS, 1 WARN, 1 UNKNOWN" in row and "2026-09-29 14:00:04 UTC" in row
    assert "3 minutes old" in row


def test_a_fail_in_the_report_needs_attention_with_the_reports_time(client, files,
                                                                    quiet_database):
    write(files["report"], MIXED)
    attention = attention_of(client.get("/"))
    assert "Nothing needs anybody" not in attention
    assert "<code>antivirus</code> is FAIL" in attention
    assert "ClamAV is not answering" in attention
    assert "2026-09-29 14:00:04 UTC" in attention
    assert "/health" in attention
    assert "<code>tls</code>" not in attention and "<code>network</code>" not in attention


def test_a_stale_report_needs_attention_and_nothing_says_all_is_well(client, files,
                                                                     quiet_database):
    write(files["report"], ALL_PASS, taken_at=NOW - datetime.timedelta(minutes=42))
    response = client.get("/")
    attention = attention_of(response)
    assert "Nothing needs anybody" not in attention
    assert "42 minutes old" in attention and "the checks have stopped" in attention
    assert attention.count("42 min") == 1
    assert "stale" in sections_of(response)


def test_a_missing_report_needs_attention_and_nothing_says_all_is_well(client, files,
                                                                       quiet_database):
    response = client.get("/")
    attention = attention_of(response)
    assert "Nothing needs anybody" not in attention
    assert "No health report could be read" in attention
    assert "No report could be read" in sections_of(response)


def test_the_overview_reads_the_report_as_the_page_renders():
    text = (SOURCE / "screens" / "overview.py").read_text()
    assert "health.configured()" in text.split("def register")[1]
    # kept for one request only, on `g`: never across requests, never in a module global
    assert "g.health_reading = reading(" in (SOURCE / "screens" / "health.py").read_text() \
        .split("def configured")[1]


# --- the states in colour ------------------------------------------------------------------

def luminance(hex_colour):
    channels = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(one, other):
    lighter, darker = sorted((luminance(one), luminance(other)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_every_state_has_a_colour_of_its_own_with_contrast_enough_to_read():
    colours = application.STATE_COLOURS
    assert set(colours) == set(report.STATES)
    # four different backgrounds: FAIL, WARN and UNKNOWN each look unlike PASS
    assert len({background for _, background, _ in colours.values()}) == 4
    for state, (text, background, _border) in colours.items():
        assert contrast(text, background) >= 4.5, state        # WCAG AA for body text
        assert f".badge.state-{state.lower()} {{" in application.STYLE, state
    # FAIL is the one that is solid: it stands out from everything else on a page
    assert contrast(colours["FAIL"][1], "#ffffff") >= 4.5


def test_the_people_lists_badges_keep_their_plain_look():
    from maildivvy.admin.screens import accounts
    assert '<span class="badge">blocked</span>' in accounts.LIST_PAGE
    assert "state-" not in accounts.LIST_PAGE


# --- the health status in every signed-in page's header --------------------------

def header_of(response):
    html = response.get_data(as_text=True)
    return html.split("<header>", 1)[1].split("</header>", 1)[0] if "<header>" in html else ""


def status_of(response):
    header = header_of(response)
    link = header.split('<a class="health', 1)[1].split("</a>", 1)[0]
    return '<a class="health' + link + "</a>"


def test_a_current_report_is_its_state_and_age_in_the_header(client, files):
    write(files["report"], [s for s in MIXED if s["name"] in ("host", "tls")])
    assert status_of(client.get("/health")) == (
        '<a class="health badge state-warn" href="/health">Health: WARN &middot; '
        '3 minutes ago</a>')


def test_a_fail_is_in_the_header_of_every_page_not_only_the_health_screen(client, files,
                                                                          quiet_database):
    write(files["report"], MIXED)
    for path in ("/", "/health", "/no-such-page"):
        said = status_of(client.get(path))
        assert "state-fail" in said and "Health: FAIL" in said, path


def test_a_stale_pass_is_never_pass_in_the_header(client, files):
    write(files["report"], ALL_PASS, taken_at=NOW - datetime.timedelta(minutes=42))
    said = status_of(client.get("/health"))
    assert "PASS" not in said and "state-pass" not in said
    assert "Health: UNKNOWN &middot; stale, 42 minutes old" in said


def test_a_missing_report_is_no_report_in_the_header_and_alarms_in_red(client, files):
    response = client.get("/health")
    # nothing is known, so the header alarms as a FAIL does, on every page
    assert status_of(response) == ('<a class="health badge state-fail" href="/health">'
                                   'Health: no report</a>')
    # while the screen's own state stays UNKNOWN: the colour is the header's alone
    assert "The whole reads" not in main_of(response)
    assert screen.NO_REPORT["state"] == "UNKNOWN"


def test_a_reader_that_fails_leaves_the_page_standing_and_says_no_report(client, files,
                                                                        monkeypatch):
    write(files["report"], ALL_PASS)

    def broken(**_):
        raise RuntimeError("the reader itself went wrong")
    monkeypatch.setattr(screen, "reading", broken)
    answer = client.get("/no-such-page")
    assert answer.status_code == 404 and "<h1>Not found</h1>" in main_of(answer)
    assert "Health: no report" in status_of(answer) and "state-fail" in status_of(answer)


def test_a_stale_or_future_report_keeps_its_states_colour_in_the_header(client, files):
    write(files["report"], ALL_PASS, taken_at=NOW - datetime.timedelta(minutes=42))
    assert "state-unknown" in status_of(client.get("/health"))
    write(files["report"], MIXED, taken_at=NOW - datetime.timedelta(minutes=42))
    assert "state-fail" in status_of(client.get("/health"))
    write(files["report"], ALL_PASS, taken_at=NOW + datetime.timedelta(hours=2))
    assert "state-unknown" in status_of(client.get("/health"))


def test_the_report_is_read_once_per_page(client, files, quiet_database, monkeypatch):
    write(files["report"], MIXED)
    calls = []
    real = screen.reading
    monkeypatch.setattr(screen, "reading", lambda **kw: calls.append(1) or real(**kw))
    for path in ("/", "/health"):
        calls.clear()
        client.get(path)
        assert calls == [1], path


def test_the_sign_in_page_has_no_shell_and_no_health(files):
    made = Flask("maildivvy-test")
    application.register(made)
    screen.register(made)
    application.guard_every_endpoint(made)
    made.config.update(MAILDIVVY_HEALTH_REPORT=files["report"], MAILDIVVY_SECRET="x" * 32)
    write(files["report"], ALL_PASS)
    page = made.test_client().get("/sign-in").get_data(as_text=True)
    assert "<header>" not in page and "Health:" not in page
