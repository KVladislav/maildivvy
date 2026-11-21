"""Signing in, the session, the forgery defence and the request's one transaction, on a
real database as `maildivvy_admin` (`admin_db.py`).

Every test here reads its outcome back from the rows: a session that was or was not
written, a journal row that was or was not committed.
"""

import pytest
from admin_db import (make_app, ADMIN, PASSWORD, Browser, add_person, counts, hashed, journal_rows,
                      main_of, requests, text)
from maildivvy.admin import app as application
from maildivvy.admin import auth, throttle
from maildivvy.admin.screens import common
from maildivvy.lib import db


def sessions(database):
    return database.value("SELECT count(*) FROM session")


def signed_out(answer):
    """The sign-in page: what every request without a live session gets."""
    return 'action="/sign-in"' in text(answer) and '<nav class="nav"' not in text(answer)


# --- signing in -------------------------------------------------------------------------------

def test_an_administrators_login_in_capitals_signs_in_as_the_stored_login(app_db, ids, database):
    # a mail client's spelling: Dovecot folds it, and so does the sign-in
    browser = Browser(app_db)
    assert browser.sign_in(ADMIN.upper()).status_code == 303
    assert f"Signed in as {ADMIN}" in text(browser.get("/"))


def test_an_administrators_password_opens_a_session_with_a_strict_cookie_and_no_journal_row(
        app_db, ids, database):
    browser = Browser(app_db)
    answer = browser.sign_in()
    assert answer.status_code == 303 and answer.headers["Location"] == "/"
    cookie = answer.headers["Set-Cookie"]
    for flag in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
        assert flag in cookie, cookie
    assert sessions(database) == 1
    # an ordinary administrator's sign-in is not an act: the journal holds the scene's row only
    assert [row[1] for row in journal_rows(database)] == ["create_mailbox"]
    page = browser.get("/")
    assert page.status_code == 200 and f"Signed in as {ADMIN}" in text(page)
    # every signed-in response carries the cookie again, with its flags
    assert "SameSite=Strict" in page.headers["Set-Cookie"]


@pytest.mark.parametrize("login, password", [
    (ADMIN, "not-the-password"),
    ("nobody-of-that-name", PASSWORD),
    ("olga", PASSWORD),               # the right password, no administrator flag
    ("blocked", PASSWORD),            # an administrator, blocked
    (ADMIN, ""),
    (ADMIN, "x" * 300),               # past what the hash takes
    ("no such login!", PASSWORD),
])
def test_every_refused_sign_in_is_one_page_at_200_and_writes_nothing(
        app_db, ids, database, login, password):
    add_person(database, "blocked", is_admin=True, state="blocked")
    before = counts(database)
    browser = Browser(app_db)
    answer = browser.sign_in(login, password)
    assert answer.status_code == 200
    assert auth.REFUSAL in text(answer) and signed_out(answer)
    assert browser.cookie() is None
    assert sessions(database) == 0 and counts(database) == before


def test_a_login_typed_with_its_domain_signs_in_as_the_login(app_db, ids, database):
    browser = Browser(app_db)
    assert browser.sign_in(f"{ADMIN}@sales.example.org").status_code == 303
    assert f"Signed in as {ADMIN}" in text(browser.get("/"))


def test_past_the_limit_even_the_right_password_is_throttled_and_opens_nothing(
        app_db, ids, database):
    browser = Browser(app_db)
    for _ in range(throttle.MAX_FAILURES):
        assert browser.sign_in(ADMIN, "wrong").status_code == 200
    answer = browser.sign_in()
    assert answer.status_code == 429 and auth.THROTTLED in text(answer)
    assert sessions(database) == 0
    # another login from the same address has a count of its own
    add_person(database, "second", is_admin=True)
    assert browser.sign_in("second").status_code == 303


def test_the_break_glass_sign_in_is_journaled_marked_on_every_page_and_on_every_request(
        app_db, ids, database):
    database.sql("INSERT INTO break_glass (password_hash) VALUES (%s)",
                 (hashed("break-the-glass")[len(auth.PREFIX):],))
    browser = Browser(app_db)
    assert browser.sign_in(auth.BREAK_GLASS_LOGIN, "break-the-glass").status_code == 303
    assert journal_rows(database, "break_glass_use") == [
        ("break-glass", "break_glass_use", "break-glass", {})]
    assert database.value("SELECT break_glass FROM audit WHERE action = 'break_glass_use'")
    for path in ("/", "/domains", f"/people/{ids['olga']}"):
        assert "Signed in with the break-glass account" in text(browser.get(path)), path
    # an act asked in that session carries the mark as a column, for the pipeline's row
    assert browser.post(f"/external/{ids['office_external']}/check").status_code == 303
    assert database.one("SELECT asked_by, break_glass FROM request WHERE kind = "
                        "'test_credential'") == ("break-glass", True)


# --- the guard and the way back ---------------------------------

def test_every_route_but_sign_in_answers_a_stranger_with_the_sign_in_page(app_db, ids,
                                                                           database):
    browser = Browser(app_db)
    for rule in app_db.url_map.iter_rules():
        if rule.endpoint in ("static", "sign_in"):
            continue
        path = rule.build({name: 1 for name in rule.arguments})[1]
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            answer = (browser.get(path) if method == "GET"
                      else browser.post(path, {"anything": "1"}))
            assert answer.status_code == 200 and signed_out(answer), (method, path)
    assert counts(database)["request"] == 1 and sessions(database) == 0


@pytest.mark.parametrize("asked, back", [
    ("/people", "/people"),
    ("/domains/1", "/domains/1"),
    ("https://evil.example.org/", "/"),
    ("//evil.example.org/", "/"),
    ("/sign-out", "/"),                # a POST route is not a way back
    ("/no-such-page", "/"),
])
def test_signing_in_returns_to_the_page_asked_for_only_when_it_is_one_of_ours(
        app_db, ids, asked, back):
    browser = Browser(app_db)
    answer = browser.sign_in(next=asked)
    assert answer.status_code == 303 and answer.headers["Location"] == back


def test_the_sign_in_page_a_guarded_page_answers_carries_that_page_back(app_db, ids):
    browser = Browser(app_db)
    page = text(browser.get("/people?x=1"))
    assert '<input type="hidden" name="next" value="/people">' in page


# --- the session's end ----------------------------------------------------

@pytest.mark.parametrize("change", [
    "UPDATE account SET state = 'blocked' WHERE login = %s",
    "UPDATE account SET is_admin = false WHERE login = %s",
    "DELETE FROM account WHERE login = %s",
    # a password change ends every session the person had before it
    "UPDATE account SET password_hash = password_hash || 'x' WHERE login = %s",
])
def test_a_change_to_the_account_ends_its_session_at_the_very_next_request(
        browser, database, change):
    database.sql(change, (ADMIN,))
    assert signed_out(browser.get("/"))
    # and a POST sent with the live page's token is not run either
    before = counts(database)
    assert signed_out(browser.post("/domains/add", {"label": "late"}))
    assert counts(database)["domain"] == before["domain"]


@pytest.mark.parametrize("column, age", [("last_seen_at", "15 minutes 1 second"),
                                         ("created_at", "8 hours 1 second")])
def test_a_session_ends_after_fifteen_idle_minutes_or_eight_hours(browser, database,
                                                                   column, age):
    database.sql(f"UPDATE session SET {column} = now() - interval '{age}'")
    assert signed_out(browser.get("/"))


def test_a_request_moves_the_sessions_last_seen_time(browser, database):
    database.sql("UPDATE session SET last_seen_at = now() - interval '14 minutes'")
    assert browser.get("/domains").status_code == 200
    assert database.value("SELECT now() - last_seen_at < interval '1 minute' FROM session")


def test_signing_out_ends_the_sessions_row_and_clears_the_cookie(browser, database):
    assert sessions(database) == 1
    answer = browser.post("/sign-out")
    assert answer.status_code == 303 and answer.headers["Location"] == "/sign-in"
    # the row goes through the schema's function: the interface's role holds no DELETE
    assert sessions(database) == 0
    assert browser.cookie() is None
    assert signed_out(browser.get("/"))


def test_a_cookie_with_a_bad_signature_is_no_session(browser, database):
    value = browser.cookie()
    browser.client.set_cookie(auth.COOKIE, value[:-2] + ("aa" if value[-2:] != "aa" else "bb"),
                              domain="mail.example.org", secure=True)
    assert signed_out(browser.get("/"))


# --- the forgery defence ----------------------------------------------

def test_every_post_form_a_signed_in_page_serves_carries_the_sessions_token(browser, ids):
    for path in ("/", f"/domains/{ids['sales']}", f"/people/{ids['olga']}",
                 f"/external/{ids['office_external']}", "/withheld"):
        html = text(browser.get(path))
        forms = html.count('method="post"')
        assert forms and html.count(f'name="_csrf" value="{browser.token}"') == forms, path


@pytest.mark.parametrize("change", [
    {"csrf": False},
    {"data_token": "a-token-from-another-session"},
    {"origin": "https://evil.example.org"},
    {"origin": "null"},
    {"headers": {"Sec-Fetch-Site": "same-site"}},
    {"headers": {"Sec-Fetch-Site": "cross-site"}},
])
def test_a_forged_act_is_refused_with_403_and_writes_nothing(browser, ids, database, change):
    before = counts(database)
    form = {"label": "forged", "password": "an-archive-password-that-is-long",
            "password2": "an-archive-password-that-is-long"}
    if "data_token" in change:
        browser.token = change.pop("data_token")
    answer = browser.post("/domains/add", form, **change)
    assert answer.status_code == 403 and "Nothing was changed" in text(answer)
    assert counts(database) == before
    # the same form with the page's own token and origin is the act
    browser.get("/domains/add")
    assert browser.post("/domains/add", form).status_code == 303
    assert counts(database)["domain"] == before["domain"] + 1


def test_no_origin_header_at_all_leaves_the_token_as_the_proof(browser, ids, database):
    answer = browser.post(f"/external/{ids['office_external']}/check", origin=None)
    assert answer.status_code == 303
    assert requests(database, "test_credential")


def test_every_answer_forbids_caching_framing_and_any_script(app_db, browser):
    for answer in (browser.get("/"), browser.get("/no-such-page"),
                   Browser(app_db).get("/domains"), browser.post("/domains/add", csrf=False)):
        assert answer.headers["Cache-Control"] == "no-store"
        assert answer.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in answer.headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in answer.headers["Content-Security-Policy"]


def test_a_nul_in_any_field_is_a_400_before_the_database_sees_it(browser, database):
    before = counts(database)
    answer = browser.post("/domains/add", {"label": "sa\x00les"})
    assert answer.status_code == 400 and counts(database) == before
    assert browser.get("/journal?target=a\x00b").status_code == 400


# --- one transaction per request --------------------------------------

def add_probe_routes(app):
    """An act the interface does not have: it writes a journal row, then answers 303 or
    400, or raises, as `/probe/<outcome>` says. The application's own hooks decide what
    is kept, and the guard covers it as it covers every screen."""

    @app.post("/probe/<outcome>")
    def probe(outcome):
        common.record(application.connection(), "set_account_state", "probe", {"written": True})
        if outcome == "raise":
            raise RuntimeError("after the write")
        return ("", 303) if outcome == "ok" else ("refused", 400)

    application.guard_every_endpoint(app)


def test_an_act_that_answers_4xx_or_fails_commits_nothing_it_wrote(ids, database, tmp_path):
    made = make_app(database, tmp_path)
    add_probe_routes(made)
    browser = Browser(made)
    browser.sign_in()
    browser.get("/")
    for outcome, status in (("refuse", 400), ("raise", 500)):
        assert browser.post(f"/probe/{outcome}").status_code == status
        assert journal_rows(database, "set_account_state") == [], outcome
    # the session's own bookkeeping stands apart: its last-seen time moved all the same
    assert database.value("SELECT now() - last_seen_at < interval '1 minute' FROM session")
    assert browser.post("/probe/ok").status_code == 303
    assert journal_rows(database, "set_account_state") == [(ADMIN, "set_account_state", "probe",
                                                 {"written": True})]


def test_a_request_holds_one_connection_and_closes_it(browser, monkeypatch):
    made = []
    real = db.connect

    def counting(*args, **kwargs):
        made.append(real(*args, **kwargs))
        return made[-1]

    monkeypatch.setattr(db, "connect", counting)
    for path in ("/", "/domains", "/people", "/journal"):
        made.clear()
        assert browser.get(path).status_code == 200
        assert len(made) == 1 and made[0].closed, path


def test_a_check_the_form_did_not_foresee_is_a_400_refusal_that_writes_nothing(
        browser, database, monkeypatch):
    from maildivvy.admin import validate

    # the screen's own check let through what the column's CHECK refuses: `office`'s
    # threshold past the column's bound, as a validator gone wrong would hand it on
    monkeypatch.setattr(validate, "spam_threshold", lambda typed: 999)
    before = counts(database)
    sales = database.value("SELECT id FROM domain WHERE label = 'sales'")
    answer = browser.post(f"/domains/{sales}/spam", {"threshold": "999", "reaches": "on"})
    assert answer.status_code == 400
    assert "The database refused a value this form sent" in main_of(answer)
    assert counts(database) == before
    assert database.value("SELECT spam_threshold FROM domain WHERE id = %s", (sales,)) == 8


# --- a bounded wait on the database ----------------------------------------------------

def held(database, statement):
    """A superuser connection with `statement` run in an open transaction: what it locks
    stays locked until the connection is closed."""
    conn = database.cluster.superuser(database.name).conn
    conn.autocommit = False
    with conn.cursor() as cursor:
        cursor.execute(statement)
    return conn


def test_the_interfaces_connections_carry_the_bounds_and_the_pipelines_do_not(app_db, database):
    with app_db.test_request_context("/"):
        conn = application.connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT current_setting('statement_timeout'), "
                           "current_setting('lock_timeout')")
            assert cursor.fetchone() == ("10s", "3s")
        conn.rollback()                  # a rolled-back transaction keeps them
        with conn.cursor() as cursor:
            cursor.execute("SHOW lock_timeout")
            assert cursor.fetchone() == ("3s",)
    pipeline = database.connect("pipeline")
    try:
        with pipeline.cursor() as cursor:
            cursor.execute("SELECT current_setting('statement_timeout'), "
                           "current_setting('lock_timeout')")
            assert cursor.fetchone() == ("0", "0")
    finally:
        pipeline.close()


def test_a_page_waiting_on_a_lock_answers_busy_within_the_bound_and_writes_nothing(
        browser, ids, database, monkeypatch):
    import time

    monkeypatch.setattr(application, "TIMEOUTS", {"statement_timeout": "10s",
                                                  "lock_timeout": "300ms"})
    blocker = held(database, "LOCK TABLE domain IN ACCESS EXCLUSIVE MODE")
    try:
        started = time.monotonic()
        answer = browser.get("/domains")
        took = time.monotonic() - started
    finally:
        blocker.close()
    assert answer.status_code == 503 and took < 5
    assert application.BUSY in text(answer)
    assert f"Signed in as {ADMIN}" in text(answer)          # inside the shell
    assert browser.get("/domains").status_code == 200       # and gone with the lock


def test_an_act_waiting_on_the_last_administrators_lock_answers_busy_and_does_nothing(
        browser, ids, database, monkeypatch):
    # the advisory lock the pipeline holds through a whole deletion is a lock
    # `lock_timeout` bounds; the act is cut short and its request rolls back
    monkeypatch.setattr(application, "TIMEOUTS", {"statement_timeout": "10s",
                                                  "lock_timeout": "300ms"})
    from maildivvy.lib import adminlock

    before = counts(database)
    blocker = held(database, f"SELECT pg_advisory_xact_lock({adminlock.NAMESPACE}, "
                             f"{adminlock.KEY})")
    try:
        answer = browser.post(f"/people/{ids['olga']}/state", {"state": "blocked"})
    finally:
        blocker.close()
    assert answer.status_code == 503 and application.BUSY in text(answer)
    assert database.value("SELECT state FROM account WHERE id = %s", (ids["olga"],)) == "active"
    assert counts(database) == before
