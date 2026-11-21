"""The external mailbox screens and the fetch screen: adding one, its two forms, its
switch, its deletion, a refetch and a resume; and the provider password, which the
interface writes and can never read back.

The acts run against the real schema as `maildivvy_admin` (`admin_db.py`), and each is
read back from the rows it wrote, or did not.
"""

import pytest

from admin_db import ADMIN, counts, journal_rows, main_of, redirected, requests, text
from maildivvy.admin.screens import external
import datetime
import logging
import re
from pathlib import Path
from maildivvy.admin import app as application
from maildivvy.admin import journal, validate
from maildivvy.admin.screens import (common, fetch)
from admin_pages import main_part, page_head
from admin_stand_in import CANARY, DatabaseError, EXTERNALS, FAILING_ROW, IntegrityError, OTHER_PIN, PIN, Queue, Recorder, SERVERS, an_addition, an_external, free_domain, page_of, row, row_of, smtp_pin_field

SAME_PIN = ":".join(["AB"] * 32)


def new_mailbox(**changed):
    return {"address": "Desk@Example.org", "pop3_login": "", "credential": "a-provider-password",
            **SERVERS, "window": "21", "comment": "the front desk", "domain_choice": "free",
            **changed}


def credential(database, external_id):
    return database.value("SELECT credential FROM external_mailbox WHERE id = %s",
                          (external_id,))


def test_adding_one_in_front_of_a_free_domain_writes_the_row_the_link_and_the_journal(
        browser, ids, database):
    answer = browser.post("/external/add", new_mailbox(domain_id=str(ids["sales"])))
    assert redirected(answer, "/external", "external_saved")
    row = database.one("SELECT id, address, address_canonical, delete_window_days, state, "
                       "comment FROM external_mailbox WHERE address_canonical = "
                       "'desk@example.org'")
    assert row[1:] == ("Desk@Example.org", "desk@example.org", 21, "deactivated",
                       "the front desk")
    assert credential(database, row[0]) == "a-provider-password"
    assert database.value("SELECT external_mailbox_id FROM domain WHERE id = %s",
                          (ids["sales"],)) == row[0]
    assert [entry[1:] for entry in journal_rows(database)[-2:]] == [
        ("add_external_mailbox", "desk@example.org",
         {"credential_set": True, "protocol": "pop3", "window": 21, "keep_at_provider": False}),
        ("map_domain", "sales", {"external_mailbox_id": row[0]})]
    written = database.sql("SELECT detail FROM audit") + database.sql("SELECT payload FROM request")
    assert written and "a-provider-password" not in str(written)


def test_adding_one_with_a_new_domain_creates_the_domain_and_asks_for_its_archive(
        browser, database):
    long = "an-archive-password-that-is-long"
    answer = browser.post("/external/add", new_mailbox(domain_choice="new", label="desk",
                                                       password=long, password2=long))
    assert redirected(answer, "/external", "external_saved")
    assert database.value("SELECT e.address_canonical FROM domain d JOIN external_mailbox e "
                          "ON e.id = d.external_mailbox_id WHERE d.label = 'desk'") \
        == "desk@example.org"
    assert [row[:2] for row in requests(database, "create_domain")] == [("create_domain", "desk")]


@pytest.mark.parametrize("changed, fault", [
    ({"address": "SHOP@example.org"}, "already here as Shop@Example.org"),
    ({"address": "not an address"}, "address"),
    ({"window": "0"}, "window"),
    ({"window": "fourteen"}, "window"),
    ({"pop3_host": "192.0.2.10"}, "host"),
    ({"pop3_host": "pop.example.org:995"}, "host"),
    ({"smtp_port": "0"}, "port"),
    ({"pop3_port": "65536"}, "port"),
    ({"pop3_login": "re cent"}, "login"),
    ({"pop3_cert_fingerprint": "AB:CD"}, "fingerprint"),
    ({"domain_choice": "free", "domain_id": "{office}"}, "already has an external mailbox"),
    ({"domain_choice": "free", "domain_id": ""}, "Choose a free domain"),
    ({"domain_choice": "elsewhere"}, "Choose a free domain"),
    ({"domain_choice": "new", "label": "sales", "password": "an-archive-password-that-is-long",
      "password2": "an-archive-password-that-is-long"}, "There is already a domain"),
])
def test_a_refused_external_mailbox_writes_nothing_and_says_why_beside_the_field(
        browser, ids, database, changed, fault):
    form = new_mailbox(domain_id=str(ids["sales"]))
    form.update({key: value.format(office=ids["office"]) for key, value in changed.items()})
    before = counts(database)
    answer = browser.post("/external/add", form)
    assert answer.status_code == 400
    assert fault.lower() in main_of(answer).lower()
    assert "a-provider-password" not in text(answer)
    assert counts(database) == before


def test_no_page_carries_the_provider_password_and_the_interfaces_role_cannot_read_it(
        browser, ids, database):
    for path in ("/", "/external", f"/external/{ids['office_external']}",
                 f"/external/{ids['office_external']}/delete", "/fetch", "/journal",
                 f"/domains/{ids['office']}"):
        answer = browser.get(path)
        assert answer.status_code == 200 and "provider-secret" not in text(answer), path
    conn = database.connect("admin")
    try:
        with conn.cursor() as cursor, pytest.raises(database.psycopg2.Error) as refused:
            cursor.execute("SELECT credential FROM external_mailbox")
        assert refused.value.pgcode == "42501"           # insufficient privilege
    finally:
        conn.close()


def test_the_settings_form_saves_together_and_asks_a_check_for_a_new_login_or_password(
        browser, ids, database):
    external_id = ids["office_external"]
    path = f"/external/{external_id}"
    unchanged = {"pop3_login": "", "smtp_login": "", "window": "14", "comment": ""}
    assert redirected(browser.post(f"{path}/settings", unchanged), path, "settings_saved")
    assert journal_rows(database)[-1][1] == "create_mailbox" and not requests(database,
                                                                          "test_credential")
    answer = browser.post(f"{path}/settings", {**unchanged, "pop3_login": "office-pop"})
    assert redirected(answer, path, "settings_saved_login")
    assert journal_rows(database, "set_pop3_login")[0][3] == {"before": None, "after": "office-pop"}
    answer = browser.post(f"{path}/settings", {**unchanged, "pop3_login": "office-pop",
                                               "credential": "a-new-one"})
    assert redirected(answer, path, "settings_saved_password")
    assert credential(database, external_id) == "a-new-one"
    assert journal_rows(database, "set_credential")[0][3] == {"credential_set": True}
    assert len(requests(database, "test_credential")) == 2
    answer = browser.post(f"{path}/settings", {"pop3_login": "office-pop", "window": "30",
                                               "keep_at_provider": "on"})
    assert journal_rows(database, "set_delete_window")[0][3] == {"days": 30, "keep_at_provider": True}
    # a form that does not carry a login at all keeps the stored one
    browser.post(f"{path}/settings", {"window": "30", "keep_at_provider": "on"})
    assert database.value("SELECT pop3_login FROM external_mailbox WHERE id = %s",
                          (external_id,)) == "office-pop"


def test_a_new_host_or_pin_clears_the_stored_password_and_a_port_keeps_it(browser, ids,
                                                                          database):
    external_id = ids["office_external"]
    path = f"/external/{external_id}"
    assert redirected(browser.post(f"{path}/servers", SERVERS), path, "servers_same")
    assert not journal_rows(database, "set_provider_servers")
    assert redirected(browser.post(f"{path}/servers", {**SERVERS, "smtp_port": "465"}),
                      path, "servers_saved")
    assert credential(database, external_id) == "provider-secret"
    assert len(requests(database, "test_credential")) == 1
    assert redirected(browser.post(f"{path}/servers", {**SERVERS, "smtp_port": "465",
                                                       "pop3_cert_fingerprint": SAME_PIN}),
                      path, "servers_saved_password_cleared")
    assert credential(database, external_id) is None
    database.sql("UPDATE external_mailbox SET credential = 'again' WHERE id = %s",
                 (external_id,))
    browser.post(f"{path}/servers", {**SERVERS, "smtp_port": "465",
                                     "pop3_cert_fingerprint": SAME_PIN,
                                     "pop3_host": "mail.example.net"})
    assert credential(database, external_id) is None
    # nothing to check once the password is gone
    assert len(requests(database, "test_credential")) == 1
    assert [row[3]["credential_cleared"] for row in journal_rows(database, "set_provider_servers")] \
        == [False, True, True]


def test_check_and_enable_are_requests_asked_once_and_disable_acts_at_once(browser, ids,
                                                                           database):
    external_id = ids["free_external"]
    referer = {"Referer": f"https://mail.example.org/external/{external_id}"}
    for act, kind, key in (("check", "test_credential", "check_asked"),
                           ("enable", "activate_external_mailbox", "enable_asked")):
        assert redirected(browser.post(f"/external/{external_id}/{act}", headers=referer),
                          f"/external/{external_id}", key)
        assert redirected(browser.post(f"/external/{external_id}/{act}", headers=referer),
                          f"/external/{external_id}", "already_asked")
        assert len(requests(database, kind)) == 1
    assert redirected(browser.post(f"/external/{external_id}/disable"), "/external", "disabled")
    assert database.one("SELECT state, state_changed_by FROM external_mailbox WHERE id = %s",
                        (external_id,)) == ("deactivated", ADMIN)
    assert journal_rows(database, "deactivate_external_mailbox")[0][3] == {"state": "deactivated"}
    # disabling it again changes nothing: no new stamp, no second journal row
    stamped = database.value("SELECT state_changed_at FROM external_mailbox WHERE id = %s",
                             (external_id,))
    assert redirected(browser.post(f"/external/{external_id}/disable"), "/external", "disabled")
    assert database.value("SELECT state_changed_at FROM external_mailbox WHERE id = %s",
                          (external_id,)) == stamped
    assert len(journal_rows(database, "deactivate_external_mailbox")) == 1


@pytest.mark.parametrize("branch, kinds", [
    ("keep", ["delete_external_mailbox"]),
    (external.DELETE_WORD, ["delete_external_mailbox", "delete_domain"]),
])
def test_a_deletion_keeps_the_domain_unless_asked_and_then_asks_two_requests_in_order(
        browser, ids, database, branch, kinds):
    path = f"/external/{ids['office_external']}/delete"
    assert "danger-zone" in main_of(browser.get(path))
    assert redirected(browser.post(path, {"branch": branch}), "/external",
                      "external_deletion_asked")
    assert [row[0] for row in requests(database) if row[0].startswith("delete")] == kinds
    assert database.value("SELECT count(*) FROM external_mailbox") == 2


# --- the fetch screen -------------------------------------

def test_the_fetch_screen_reads_every_mailbox_and_escapes_what_the_provider_said(browser):
    page = main_of(browser.get("/fetch"))
    assert "office@example.org" in page and "Shop@Example.org" in page
    assert "<b>stuck</b>" not in page


def test_resume_clears_the_freeze_and_the_skip_streak_and_leaves_the_stuck_clock(
        browser, ids, database):
    external_id = ids["free_external"]
    database.sql("UPDATE external_mailbox SET skip_streak = 3, stuck_since = now() "
                 "WHERE id = %s", (external_id,))
    assert redirected(browser.post(f"/fetch/{external_id}/resume"), "/fetch", "fetch_resumed")
    assert database.one("SELECT frozen_since, skip_streak, stuck_since IS NOT NULL FROM "
                        "external_mailbox WHERE id = %s", (external_id,)) == (None, 0, True)
    assert len(journal_rows(database, "resume_fetch")) == 1
    # not frozen: nothing written, nothing said
    assert browser.post(f"/fetch/{external_id}/resume").status_code == 303
    assert len(journal_rows(database, "resume_fetch")) == 1


# The columns the fetch runner writes; the interface writes two of them, on resume.
FETCHER_COLUMNS = (
    "last_fetch_at", "last_fetch_status", "last_fetch_cause", "last_fetch_detail",
    "last_test_at", "last_test_status", "last_test_detail", "stuck_since", "stuck_runs",
    "skip_streak", "frozen_since", "last_listing_at", "last_skip_at", "last_skip_uidl",
    "held_since",
)
RESUME_WRITES = ("frozen_since", "skip_streak")


def test_the_interfaces_role_may_write_two_of_the_fetchers_columns_and_no_other(database):
    conn = database.connect("admin")
    try:
        for column in FETCHER_COLUMNS:
            with conn.cursor() as cursor:
                try:
                    cursor.execute(f"UPDATE external_mailbox SET {column} = {column}")
                except database.psycopg2.Error as refused:
                    assert refused.pgcode == "42501", column        # insufficient privilege
                    assert column not in RESUME_WRITES, column
                else:
                    assert column in RESUME_WRITES, column
            conn.rollback()
    finally:
        conn.close()


def test_a_refetch_is_asked_once_for_an_active_mailbox_and_refused_for_a_disabled_one(
        browser, ids, database):
    assert redirected(browser.post(f"/fetch/{ids['free_external']}/refetch"), "/fetch",
                      "refetch_asked")
    assert redirected(browser.post(f"/fetch/{ids['free_external']}/refetch"), "/fetch",
                      "already_asked")
    assert len(requests(database, "refetch")) == 1
    answer = browser.post(f"/fetch/{ids['office_external']}/refetch")
    assert answer.status_code == 400 and "is disabled" in main_of(answer)
    assert len(requests(database, "refetch")) == 1



# ================================================================================================
# With the database stood in (admin_stand_in.py): what a screen renders for the rows it is handed.
# ================================================================================================

# --- the external mailbox screens and fetch, in the design's components -----------------


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
            '<span class="row-sub">enabled since 2026-09-02 10:00 UTC by <code>t28admin</code>'
            '</span>') in box
    # a frozen fetch is its own worded badge beneath the switch, not a fourth position
    assert ('<span class="row-sub"><a href="/fetch"><span class="badge attn">'
            '<svg class="icon attn"><use href="#i-alert"/></svg> frozen</span></a></span>'
            in box)
    # a refused credential is a red word beside its icon
    assert ('<td><span class="state-bad"><svg class="icon bad">'
            '<use href="#i-alert"/></svg> refused, since 2026-09-30 09:12 UTC</span>') in box
    acts = box.split('<td class="acts">', 1)[1]
    assert ('<form method="post" action="/external/9/check">'
            '<button class="btn btn-sm" type="submit">Check password</button></form>') in acts
    assert re.findall(r'<a class="([^"]+)"[^>]*>([^<]+)</a>', acts) == [
        ("btn btn-sm btn-link", "Journal")]
    # an asked row: the switch in its middle position, when to look again, and no control
    asked = row_of(html, "asked@example.org")
    assert ('<td class="state"><button class="switch asked" type="button" disabled>'
            '<span class="knob"></span>asked to enable, 2026-09-30 14:58 UTC</button>'
            '<span class="row-sub">asked to enable, 2026-09-30 14:58 UTC &mdash; '
            'the pipeline checks the password and enables it by 2026-09-30 15:01 UTC'
            '</span>') in asked
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
            'accepted, checked 2026-09-30 09:12 UTC</span>') in ok


def test_the_item_page_is_its_head_the_provider_box_two_forms_and_a_danger_zone(
        external_world):
    status, html = main_part(external_world, "/external/9")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/external">External mailboxes</a> / '
                           '<code>Box@example.org</code></div>')
    head = " ".join(page_head(html).split())
    assert "<h1><code>Box@example.org</code></h1>" in head
    assert ('<p class="lede">In front of <a href="/domains/1"><code>sales</code></a>. enabled '
            'since 2026-09-02 10:00 UTC by <code>t28admin</code>. Rotating the provider password '
            'here is the operation this interface most exists for.') in head
    assert re.findall(r'<a class="([^"]+)"[^>]*>([^<]+)</a>', head) == [
        ("btn", "Journal for this mailbox")]
    provider = html.split('<div class="box-head"><h2>At the provider</h2>', 1)[1] \
        .split("</section>", 1)[0]
    assert provider.startswith('<span class="badge bad"><svg class="icon bad">'
                               '<use href="#i-alert"/></svg> refused, since 2026-09-30 09:12 UTC'
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
    assert ("Changing either host, or setting or changing a fingerprint, clears the stored "
            "provider password") in " ".join(warning.split())
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


def test_adding_one_is_a_narrow_form_and_a_refusal_is_a_flash_and_a_warn(external_world):
    status, html = main_part(external_world, "/external/add")
    assert status == 200
    assert html.startswith('<div class="crumbs"><a href="/external">External mailboxes</a> / '
                           'Add</div>')
    assert "<h1>Add external mailbox</h1>" in page_head(html)
    form = html.split('<form class="narrow" method="post" action="/external/add">', 1)[1] \
        .split("</form>", 1)[0]
    names = re.findall(r'<(?:input|select)[^>]* name="([a-z0-9_]+)"', form)
    assert names[:15] == ["address", "protocol", "protocol", "pop3_login", "smtp_login",
                          "credential", "pop3_host", "pop3_port", "smtp_host", "smtp_port",
                          "pop3_cert_fingerprint", "smtp_cert_fingerprint", "window",
                          "keep_at_provider", "comment"]
    assert form.count('<div class="inline-fields">') == 3
    assert '<div class="box-head"><h2>The domain in front of it</h2></div>' in form
    assert ('<label class="choice"><input type="radio" name="domain_choice" value="free" '
            'checked><div><b>A free domain</b></div></label>') in " ".join(form.split())
    # the protocol's two tiles, then the domain's two
    assert form.count('<label class="choice">') == 4
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


# --- a provider password never in a statement that can fail, nor in the log -------


def test_the_password_is_written_alone_after_the_row_and_no_other_statement_names_it(
        external_world, driver, monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(application, "connection", lambda: recorder)
    monkeypatch.setattr(common, "one", free_domain)
    monkeypatch.setattr(journal, "record", lambda conn, **row: None)
    answer = external_world.post("/external/add", data=an_addition(
        credential=CANARY, domain_choice="free", domain_id="4"))
    assert answer.status_code == 303, answer.get_data(as_text=True)[-600:]
    said = [(sql, values) for sql, values in recorder.said if "external_mailbox" in sql]
    insert = next(at for at, (sql, _) in enumerate(said) if sql.startswith("INSERT"))
    assert "credential" not in said[insert][0] and CANARY not in said[insert][1]
    assert said[insert + 1] == ("UPDATE external_mailbox SET credential = %s WHERE id = %s",
                                (CANARY, 3))
    naming = [sql for sql, values in said if "credential" in sql or CANARY in values]
    assert naming == [said[insert + 1][0]]
    # the control: no password typed, no statement naming one
    recorder.said.clear()
    assert external_world.post("/external/add", data=an_addition(
        domain_choice="free", domain_id="4")).status_code == 303
    assert not [sql for sql, _ in recorder.said if "credential" in sql]
    # the settings form: the row's own UPDATE first, then the password alone
    queue = Queue()
    monkeypatch.setattr(application, "connection", lambda: queue)
    assert external_world.post("/external/9/settings", data={
        "pop3_login": "recent:box", "window": "14", "credential": CANARY}).status_code == 303
    updates = [sql for sql in queue.said if sql.startswith("UPDATE external_mailbox")]
    assert updates[-1] == "UPDATE external_mailbox SET credential = %s WHERE id = %s"
    assert all("credential" not in sql for sql in updates[:-1]) and len(updates) == 2


def test_a_check_a_form_broke_is_its_refusal_and_the_errors_text_is_in_no_log(
        check_world, caplog):
    with caplog.at_level(logging.ERROR):
        status, html = main_part(check_world, "/external/add", "post", **an_addition(
            credential=CANARY, domain_choice="free", domain_id="4"))
    assert status == 400
    assert "<h1>Not saved</h1>" in page_head(html)
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert flash.split("<div>", 1)[1] == application.CHECK_REFUSED
    assert CANARY not in html and "Failing row" not in html
    assert CANARY not in caplog.text and "Failing row" not in caplog.text
    assert "SQLSTATE 23514" in caplog.text
    assert "external_mailbox_address_canonical_check" in caplog.text


def test_a_database_errors_text_never_reaches_the_log_whatever_raised_it(
        shell, driver, caplog):
    """The log keeps the SQLSTATE and the constraint's name, never the error's text: not
    from a view, not as the cause of another error, not on an error page."""
    app = shell.application

    def raising():
        raise IntegrityError("23505", FAILING_ROW, "external_mailbox_address_canonical_key")

    def chained():
        try:
            raising()
        except DatabaseError:
            raise RuntimeError("raised while the first was handled") from None

    def caused():
        try:
            raising()
        except DatabaseError as err:
            raise RuntimeError("raised from it") from err

    def plain():
        raise ValueError("plain words")

    for name, view in (("chained", chained), ("caused", caused), ("raising", raising),
                       ("plain", plain)):
        app.add_url_rule(f"/t/{name}", f"t_{name}", view)
    with caplog.at_level(logging.ERROR):
        for name in ("raising", "chained", "caused"):
            assert shell.get(f"/t/{name}").status_code == 500, name
        assert CANARY not in caplog.text and "Failing row" not in caplog.text
        assert "Traceback" not in caplog.text
        assert caplog.text.count("SQLSTATE 23505, constraint "
                                 "external_mailbox_address_canonical_key") == 3
        # the control: an error with no database error in it is logged as Flask logs it
        caplog.clear()
        assert shell.get("/t/plain").status_code == 500
    assert "plain words" in caplog.text and "Traceback" in caplog.text


def test_any_other_database_error_on_a_form_is_still_the_error_page(external_world, driver,
                                                                   monkeypatch):
    monkeypatch.setattr(common, "one", free_domain)
    monkeypatch.setattr(application, "connection",
                        lambda: Recorder(refuse="INSERT INTO external_mailbox",
                                         pgcode="23502"))
    answer = external_world.post("/external/add", data=an_addition(
        credential=CANARY, domain_choice="free", domain_id="4"))
    assert answer.status_code == 500
    assert CANARY not in answer.get_data(as_text=True)


def test_the_item_page_carries_the_smtp_login_the_pins_and_the_keep_box(external_world, monkeypatch):
    monkeypatch.setitem(EXTERNALS, 12, an_external(
        id=12, address="ok@example.org", address_canonical="ok@example.org", comment=None,
        last_fetch_status="ok", last_test_status="ok", frozen_since=None, domain_id=2,
        label="office", smtp_login="box-smtp", keep_at_provider=True,
        pop3_cert_fingerprint=PIN, smtp_cert_fingerprint=PIN))
    for external_id, login, pin, checked in [(9, None, None, False), (12, "box-smtp", PIN, True)]:
        _, html = main_part(external_world, f"/external/{external_id}")
        servers = html.split(f'<form method="post" action="/external/{external_id}/servers">', 1)[1] \
            .split("</form>", 1)[0]
        for name in ("pop3_cert_fingerprint", "smtp_cert_fingerprint"):
            value = f' value="{pin}"' if pin else ""
            assert (f'<input id="{name}" name="{name}" type="text"{value} class="mono-input">'
                    ) in servers
        assert "the relay pins a server, not a mailbox" in servers
        settings = html.split(f'<form method="post" action="/external/{external_id}/settings">', 1)[1] \
            .split("</form>", 1)[0]
        value = f' value="{login}"' if login else ""
        assert (f'<input id="smtp_login" name="smtp_login" type="text"{value} class="mono-input">'
                ) in settings
        box = settings.split('<label class="checkline">', 1)[1].split("</label>", 1)[0]
        assert box.startswith('<input type="checkbox" name="keep_at_provider" value="yes"'
                              + (" checked>" if checked else ">"))
        assert "<b>Keep mail at the provider</b>" in box
    _, html = main_part(external_world, "/external")
    assert "kept at the provider" in row_of(html, "ok@example.org")
    assert "deleted at the provider 14 days after first seen" in row_of(html, "Box@example.org")


@pytest.mark.parametrize("path,form,fault,words", [
    ("/external/9/settings", {"smtp_login": "recent:box", "window": "14"}, "smtp_login",
     "no colon"),
    ("/external/9/settings", {"smtp_login": "box smtp", "window": "14"}, "smtp_login",
     "no spaces"),
    ("/external/9/servers", {"pop3_host": "pop.example.org", "pop3_port": "995",
                             "smtp_host": "smtp.example.org", "smtp_port": "587",
                             "pop3_cert_fingerprint": "AB:01"}, "pop3_cert_fingerprint",
     "SHA-256 fingerprint"),
    ("/external/9/servers", {"pop3_host": "pop.example.org", "pop3_port": "995",
                             "smtp_host": "smtp.example.org", "smtp_port": "587",
                             "smtp_cert_fingerprint": "zz" * 32}, "smtp_cert_fingerprint",
     "SHA-256 fingerprint"),
])
def test_a_refused_login_or_pin_is_said_beside_its_own_field(external_world, path, form, fault,
                                                              words):
    status, html = main_part(external_world, path, "post", **form)
    assert status == 400
    beside = html.split(f'<label for="{fault}">', 1)[1].split('<label for=', 1)[0]
    assert '<p class="help warn">' in beside and words in beside


def test_a_mailbox_whose_smtp_pin_differs_at_its_server_names_the_others_beside_the_field(
        external_world, monkeypatch):
    """`Box@example.org` (9) and `ok@example.org` (12) both send through
    `smtp.example.org:587`; the row's `pins_differ` is what the query groups as the
    policy view does. Pinned apart, each page names the other beside its SMTP pin, and so
    does the list; pinned alike, neither says a word."""
    ok = {"id": 12, "address": "ok@example.org", "address_canonical": "ok@example.org",
          "comment": None, "last_fetch_status": "ok", "last_test_status": "ok",
          "frozen_since": None, "domain_id": 2, "label": "office"}
    monkeypatch.setitem(EXTERNALS, 9, an_external(pins_differ=["ok@example.org"]))
    monkeypatch.setitem(EXTERNALS, 12, an_external(**ok, smtp_cert_fingerprint=PIN,
                                                   pins_differ=["Box@example.org"]))
    for external_id, other in [(9, "ok@example.org"), (12, "Box@example.org")]:
        _, html = main_part(external_world, f"/external/{external_id}")
        beside = smtp_pin_field(html)
        assert "the relay pins a server, not a mailbox" in beside
        warn = beside.split('<p class="help warn">', 1)[1].split("</p>", 1)[0]
        assert f"<code>{other}</code>" in warn and "nothing is relayed" in warn
    _, html = main_part(external_world, "/external")
    for address, other in [("Box@example.org", "ok@example.org"),
                           ("ok@example.org", "Box@example.org")]:
        line = row_of(html, address).split('<span class="row-sub state-attn">', 1)[1] \
            .split("</span>", 1)[0]
        assert '<svg class="icon attn"><use href="#i-alert"/></svg>' in line
        assert f"<code>{other}</code>" in line

    monkeypatch.setitem(EXTERNALS, 9, an_external(smtp_cert_fingerprint=PIN, pins_differ=[]))
    monkeypatch.setitem(EXTERNALS, 12, an_external(**ok, smtp_cert_fingerprint=PIN,
                                                   pins_differ=[]))
    for external_id in (9, 12):
        _, html = main_part(external_world, f"/external/{external_id}")
        assert "help warn" not in smtp_pin_field(html)
    _, html = main_part(external_world, "/external")
    assert "nothing is relayed" not in html


def test_a_refused_smtp_pin_is_said_beside_the_field_in_place_of_the_differing_pins(
        external_world, monkeypatch):
    monkeypatch.setitem(EXTERNALS, 9, an_external(pins_differ=["ok@example.org"]))
    status, html = main_part(external_world, "/external/9/servers", "post",
                             pop3_host="pop.example.org", pop3_port="995",
                             smtp_host="smtp.example.org", smtp_port="587",
                             smtp_cert_fingerprint="zz" * 32)
    assert status == 400
    beside = smtp_pin_field(html)
    assert beside.count("help warn") == 1 and "SHA-256 fingerprint" in beside


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
    assert ('<p class="lede">Last run 2026-09-30 14:33 UTC. Next by 2026-09-30 14:36 UTC, the '
            "fetch timer's own period (3 minutes).</p>") in head.replace("&#39;", "'")
    assert '<section class="box"><div class="table-wrap"><table>' in html
    assert ('<thead><tr><th>Address</th><th>Domain</th><th>Last fetched</th><th>Status</th>'
            '<th class="acts">Actions</th></tr></thead>') in html
    box = row_of(html, "Box@example.org")
    assert '<span class="row-sub">the sales mailbox</span>' in box
    assert ('<span class="state-bad"><svg class="icon bad"><use href="#i-alert"/></svg> '
            'credential refused') in box
    assert ('<span class="row-sub state-attn"><svg class="icon attn"><use href="#i-alert"/>'
            '</svg> frozen since 2026-09-30 11:40 UTC') in box
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


@pytest.mark.parametrize("world, path, form, done, asked", [
    ("external_world", "/external/9/check", {}, "check_asked",
     [("test_credential", "box@example.org")]),
    ("external_world", "/external/9/enable", {}, "enable_asked",
     [("activate_external_mailbox", "box@example.org")]),
    ("external_world", "/fetch/12/refetch", {}, "refetch_asked",
     [("refetch", "ok@example.org")]),
    ("external_world", "/external/9/delete", {"branch": external.DELETE_WORD},
     "external_deletion_asked",
     [("delete_external_mailbox", "box@example.org"), ("delete_domain", "sales")]),
    ("domains_world", "/domains/1/delete", {}, "domain_deletion_asked",
     [("delete_domain", "sales")]),
    ("boxes_world", "/mailboxes/5/delete", {}, "mailbox_removal_asked",
     [("delete_mailbox", "ivan@sales")]),
    ("people_world", "/people/3/delete", {}, "account_deletion_asked",
     [("delete_account", "ivan")]),
])
def test_the_same_act_posted_twice_queues_one_request_and_says_it_is_already_asked(
        request, monkeypatch, world, path, form, done, asked):
    # the button is hidden while a request waits; the route must look as well, or a
    # double click or a replayed POST queues the same work again
    client = request.getfixturevalue(world)
    queue = Queue()
    monkeypatch.setattr(application, "connection", lambda: queue)
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    monkeypatch.setattr(journal, "record", lambda conn, **row: None)
    first = client.post(path, data=form)
    second = client.post(path, data=form)
    assert first.status_code == second.status_code == 303
    assert f"done={done}" in first.headers["Location"]
    assert "done=already_asked" in second.headers["Location"]
    assert [(row["kind"], row["target"]) for row in queue.requests] == asked
    # the lock is taken before the look, or two POSTs at once both find nothing
    looks = [n for n, sql in enumerate(queue.said) if sql.startswith("SELECT id FROM request")]
    assert looks and all("pg_advisory_xact_lock" in queue.said[n - 1] for n in looks)


@pytest.mark.parametrize("stored, typed, cleared", [
    ({}, {"pop3_cert_fingerprint": PIN}, True),                      # a POP3 pin set
    ({}, {"smtp_cert_fingerprint": PIN}, True),                      # an SMTP pin set
    ({"pop3_cert_fingerprint": PIN}, {"pop3_cert_fingerprint": OTHER_PIN}, True),
    ({"smtp_cert_fingerprint": PIN}, {"smtp_cert_fingerprint": OTHER_PIN}, True),
    ({}, {"pop3_host": "pop2.example.org", "smtp_cert_fingerprint": PIN}, True),
    # back to the trust store and the host name, the check every unpinned mailbox has
    ({"pop3_cert_fingerprint": PIN, "smtp_cert_fingerprint": PIN}, {}, False),
    # the pins as they were, a port moved: the control
    ({"pop3_cert_fingerprint": PIN}, {"pop3_cert_fingerprint": PIN.lower(),
                                      "smtp_port": "2525"}, False),
])
def test_setting_or_changing_a_pin_clears_the_stored_password_and_removing_one_keeps_it(
        external_world, monkeypatch, stored, typed, cleared):
    """A pin replaces the trust store and the name check, so a new one could point the
    stored password at any certificate, as a new host could: the table's trigger
    clears the password in the same UPDATE, and the screen says so and queues no check.
    Removing a pin returns to the stricter check and keeps it."""
    monkeypatch.setitem(EXTERNALS, 9, an_external(**stored))
    queue, journaled = Queue(), []
    monkeypatch.setattr(application, "connection", lambda: queue)
    monkeypatch.setattr(journal, "record", lambda conn, **row: journaled.append(row))
    answer = external_world.post("/external/9/servers", data={**SERVERS, **typed})
    assert answer.status_code == 303
    done = "servers_saved_password_cleared" if cleared else "servers_saved"
    assert f"done={done}" in answer.headers["Location"]
    update, = [sql for sql in queue.said if sql.startswith("UPDATE external_mailbox")]
    # the trigger clears it, for every writer; the screen's UPDATE names no credential
    assert "credential" not in update
    assert [row["action"] for row in journaled] == ["set_provider_servers"]
    assert journaled[0]["detail"]["credential_cleared"] is cleared
    asked = [row["kind"] for row in queue.requests]
    assert asked == ([] if cleared else ["test_credential"])


# --- what one fetch row reads ---------------------------------------------


@pytest.mark.parametrize("cause,says", [
    ("unrecorded", "could not record what it decided"),
    ("timeout", "killed at the runner's timeout"),
    ("mark", "no starting point that matches the provider's INBOX"),
    ("stuck_message", "stuck on one message"),
    ("store", "the archive's store could not take mail"),
    ("unreachable", "cannot reach the provider"),
    ("transient", "stopped by something transient"),
])
def test_an_error_is_described_from_the_recorded_cause_alone(cause, says):
    said = fetch.status_of(row(last_fetch_status="error", last_fetch_cause=cause,
                               last_fetch_detail="mpop: something"))
    assert says in said["status"]
    assert said["detail"] == "mpop: something"      # the raw detail is shown beneath, as text


def test_a_store_hold_reads_as_a_hold_with_the_mail_at_the_provider():
    said = fetch.status_of(row(last_fetch_status="error", last_fetch_cause="store",
                               last_fetch_detail="mpop: ... returned exit status 73"))
    assert said["status"].startswith("held — the archive's store could not take mail")
    assert "waiting at the provider" in said["status"]
    assert (said["tone"], said["icon"]) == ("attn", "alert")  # amber: it waits on a person
    assert said["detail"] == "mpop: ... returned exit status 73"


def test_a_run_with_no_mark_it_can_trust_says_how_a_person_sets_one():
    said = fetch.status_of(row(last_fetch_status="error", last_fetch_cause="mark",
                               last_fetch_detail="no mark: the mailbox was not activated"))
    assert "nothing is collected until the mailbox is disabled and enabled again" in said["status"]
    assert (said["tone"], said["icon"]) == ("attn", "alert")  # amber: it waits on a person
    assert said["detail"] == "no mark: the mailbox was not activated"


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


def test_an_imap_row_past_the_hour_names_the_runs_still_to_stop_on_the_message():
    """Over IMAP nothing is skipped under the runner's floor of runs stopped on the message,
    so the screen does not call a skip due that the next run will not make."""
    now = datetime.datetime(2026, 11, 19, 12, 0, tzinfo=datetime.timezone.utc)
    since = now - datetime.timedelta(hours=2)
    few = fetch.retry_of(row(protocol="imap", stuck_since=since, stuck_runs=4), now)
    assert f"{fetch.IMAP_STUCK_RUNS - 4} more run(s) stopped on it before the automatic skip" in few
    enough = fetch.retry_of(row(protocol="imap", stuck_since=since,
                                stuck_runs=fetch.IMAP_STUCK_RUNS), now)
    assert "the automatic skip is due" in enough
    # a POP3 mailbox has no floor: past the hour its skip is due after any number of runs
    assert "the automatic skip is due" in fetch.retry_of(row(stuck_since=since, stuck_runs=4), now)


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


def test_a_skip_kept_at_the_provider_stays_and_names_no_deletion_date():
    skipped = datetime.datetime(2026, 9, 1, 9, 30, tzinfo=datetime.timezone.utc)
    kept = row(last_skip_at=skipped, last_skip_uidl="UID-9", keep_at_provider=True)
    said = fetch.skip_of(kept, today=datetime.date(2027, 9, 1))
    assert "UID-9" in said and "kept at the provider" in said and "deletes it on" not in said


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


# --- a mailbox collected over IMAP ----------------------------------------------------

LONG = "an-archive-password-that-is-long"


def an_imap_mailbox(database, address, state="deactivated", window=30, mark=None):
    """A provider mailbox collected over IMAP, as the interface and the runner leave one."""
    uidvalidity, last_uid = mark or (None, None)
    return database.value(
        "INSERT INTO external_mailbox (address, address_canonical, protocol, pop3_host, "
        "pop3_port, smtp_host, credential, keep_at_provider, delete_window_days, state, "
        "imap_uidvalidity, imap_last_uid) VALUES (%s, %s, 'imap', 'imap.example.net', 993, "
        "'smtp.example.net', 'provider-secret', true, %s, %s, %s, %s) RETURNING id",
        (address, address.lower(), window, state, uidvalidity, last_uid))


def stored(database, external_id, *columns):
    return database.one(f"SELECT {', '.join(columns)} FROM external_mailbox WHERE id = %s",
                        (external_id,))


def test_an_imap_mailbox_is_added_kept_at_the_provider_on_its_own_port_unless_one_is_typed(
        browser, ids, database):
    answer = browser.post("/external/add", new_mailbox(
        domain_id=str(ids["sales"]), protocol="imap", pop3_port="", keep_at_provider="yes"))
    assert redirected(answer, "/external", "external_saved")
    row = database.one("SELECT protocol, pop3_port, keep_at_provider, state, "
                       "imap_uidvalidity FROM external_mailbox WHERE address_canonical = "
                       "'desk@example.org'")
    assert row == ("imap", 993, True, "deactivated", None)
    assert journal_rows(database, "add_external_mailbox")[-1][3] == {
        "credential_set": True, "protocol": "imap", "window": 21, "keep_at_provider": True}
    # the control: an empty port on a POP3 mailbox is POP3's, and a typed one is kept
    browser.post("/external/add", new_mailbox(address="pop@example.org", pop3_port="",
                                              domain_choice="new", label="pop",
                                              password=LONG, password2=LONG))
    browser.post("/external/add", new_mailbox(address="odd@example.org", protocol="imap",
                                              pop3_port="10993", keep_at_provider="yes",
                                              domain_choice="new", label="odd",
                                              password=LONG, password2=LONG))
    assert database.sql("SELECT address_canonical, protocol, pop3_port FROM external_mailbox "
                        "WHERE address_canonical IN ('pop@example.org', 'odd@example.org') "
                        "ORDER BY id") == [("pop@example.org", "pop3", 995),
                                           ("odd@example.org", "imap", 10993)]



def test_an_imap_mailbox_that_would_not_keep_its_mail_is_refused_and_nothing_is_written(
        browser, ids, database):
    """The schema refuses such a row; the screen says why first, beside the protocol, on
    the add form and on the settings form, whose IMAP version always carries the box's
    value: a POST without it is a crafted one."""
    imap = an_imap_mailbox(database, "Inbox@example.net")
    before = counts(database)
    for path, form in [
            ("/external/add", new_mailbox(domain_id=str(ids["sales"]), protocol="imap")),
            (f"/external/{imap}/settings", {"window": "30"}),
            (f"/external/{imap}/settings", {"protocol": "imap", "window": "30"}),
            (f"/external/{ids['office_external']}/settings", {"protocol": "imap",
                                                              "window": "14"})]:
        answer = browser.post(path, form)
        assert answer.status_code == 400, path
        page = main_of(answer)
        assert page.count(validate.IMAP_KEEPS) == 2, path      # the flash, and beside it
        assert f'<p class="help warn">{validate.IMAP_KEEPS}</p>' in page, path
    assert counts(database) == before
    assert stored(database, imap, "protocol", "keep_at_provider") == ("imap", True)
    assert stored(database, ids["office_external"], "protocol") == ("pop3",)
    # a protocol that is neither is a sentence too
    answer = browser.post(f"/external/{ids['office_external']}/settings",
                          {"protocol": "smtp", "window": "14"})
    assert answer.status_code == 400 and validate.NOT_A_PROTOCOL in main_of(answer)


def test_the_protocol_changes_only_while_disabled_and_a_change_is_journaled_and_checked(
        browser, ids, database):
    enabled = ids["free_external"]                       # an enabled POP3 mailbox
    answer = browser.post(f"/external/{enabled}/settings",
                          {"protocol": "imap", "keep_at_provider": "yes", "window": "14"})
    assert answer.status_code == 400
    assert validate.PROTOCOL_WHILE_ENABLED in main_of(answer)
    assert stored(database, enabled, "protocol", "keep_at_provider") == ("pop3", False)
    assert not journal_rows(database, "set_protocol") and not requests(database,
                                                                      "test_credential")

    disabled = ids["office_external"]
    path = f"/external/{disabled}"
    answer = browser.post(f"{path}/settings", {"protocol": "imap", "keep_at_provider": "yes",
                                               "window": "14"})
    assert redirected(answer, path, "settings_saved_protocol")
    assert stored(database, disabled, "protocol", "keep_at_provider") == ("imap", True)
    assert journal_rows(database, "set_protocol")[-1][2:] == (
        "office@example.org", {"before": "pop3", "after": "imap"})
    assert journal_rows(database, "set_delete_window")[-1][3] == {"days": 14,
                                                                  "keep_at_provider": True}
    assert len(requests(database, "test_credential")) == 1
    # the IMAP form carries no protocol choice it did not change, and no window: a save
    # keeps both, writes no journal row about either and asks nothing of the provider
    database.sql("UPDATE external_mailbox SET delete_window_days = 30 WHERE id = %s",
                 (disabled,))
    assert redirected(browser.post(f"{path}/settings", {"keep_at_provider": "yes"}), path,
                      "settings_saved")
    assert stored(database, disabled, "protocol", "delete_window_days") == ("imap", 30)
    assert len(journal_rows(database, "set_protocol")) == 1
    assert len(journal_rows(database, "set_delete_window")) == 1
    assert len(requests(database, "test_credential")) == 1
    # and back: the form says, beside the protocol, that POP3 collects the INBOX again,
    # what IMAP collected included, and so does the saved sentence
    back = ("Switching back to POP3 collects the INBOX again: once enabled, the first fetch "
            "takes every message the provider offers that POP3 has not taken here before, mail "
            "already collected over IMAP included, and each reaches every person of the domain "
            "a second time.")
    choice = main_of(browser.get(path)).split('<span class="lbl">Protocol</span>', 1)[1]
    choice = " ".join(choice.split("</div>\n", 1)[0].split())
    assert f'<p class="help warn">{back}</p>' in choice
    # the box the IMAP form carried keeps the mail, as a person chose last; the starting
    # point an activation had set is cleared, and the journal keeps it
    database.sql("UPDATE external_mailbox SET imap_uidvalidity = 7, imap_last_uid = 3 "
                 "WHERE id = %s", (disabled,))
    assert redirected(browser.post(f"{path}/settings", {"protocol": "pop3",
                                                        "keep_at_provider": "yes"}),
                      path, "settings_saved_protocol_pop3")
    assert back.split(":")[0] not in main_of(browser.get(path))   # a POP3 mailbox's form
    assert stored(database, disabled, "protocol", "keep_at_provider", "imap_uidvalidity") == \
        ("pop3", True, None)
    assert journal_rows(database, "set_protocol")[-1][3] == {
        "before": "imap", "after": "pop3", "mark_cleared": {"uidvalidity": 7, "last_uid": 3}}


def test_a_new_login_or_host_on_an_imap_mailbox_says_what_its_cleared_starting_point_means(
        browser, database):
    """The schema's trigger clears the mark on a new login or host, in any state, and only
    enabling sets one. Enabled, the sentence after the save says the mailbox must be disabled
    and enabled again; disabled, that enabling starts where the INBOX then stands, so what
    arrived since the last fetch comes only through a snapshot. The journal keeps the mark
    each change cleared, and says nothing of one where there was none."""
    enabled = an_imap_mailbox(database, "Inbox@example.net", state="active", mark=(7, 3))
    path = f"/external/{enabled}"
    answer = browser.post(f"{path}/settings", {"pop3_login": "inbox-imap",
                                               "keep_at_provider": "yes"})
    assert redirected(answer, path, "settings_saved_imap_login_waits")
    assert stored(database, enabled, "imap_uidvalidity", "imap_last_uid") == (None, None)
    assert len(requests(database, "test_credential")) == 1

    database.sql("UPDATE external_mailbox SET imap_uidvalidity = 7, imap_last_uid = 3 "
                 "WHERE id = %s", (enabled,))
    servers = {"pop3_host": "imap.example.net", "pop3_port": "993",
               "smtp_host": "smtp.example.net", "smtp_port": "587"}
    # a port alone keeps the mark, as it keeps the password
    assert redirected(browser.post(f"{path}/servers", {**servers, "pop3_port": "10993"}),
                      path, "servers_saved")
    assert stored(database, enabled, "imap_uidvalidity") == (7,)
    # a new SMTP host clears the password and leaves the mark
    assert redirected(browser.post(f"{path}/servers", {**servers, "pop3_port": "10993",
                                                       "smtp_host": "smtp.example.org"}),
                      path, "servers_saved_password_cleared")
    assert stored(database, enabled, "imap_uidvalidity") == (7,)
    answer = browser.post(f"{path}/servers", {**servers, "pop3_port": "10993",
                                              "smtp_host": "smtp.example.org",
                                              "pop3_host": "mail.example.net"})
    assert redirected(answer, path, "servers_saved_mark_cleared")
    assert stored(database, enabled, "imap_uidvalidity", "credential") == (None, None)

    assert journal_rows(database, "set_provider_servers")[-1][3]["mark_cleared"] == {
        "uidvalidity": 7, "last_uid": 3}
    assert journal_rows(database, "set_pop3_login")[-1][3] == {
        "before": None, "after": "inbox-imap", "mark_cleared": {"uidvalidity": 7, "last_uid": 3}}

    # disabled: nothing waits, but enabling sets a new mark where the INBOX then stands
    disabled = an_imap_mailbox(database, "Spare@example.net", mark=(7, 3))
    answer = browser.post(f"/external/{disabled}/settings", {"pop3_login": "spare-imap",
                                                             "keep_at_provider": "yes"})
    assert redirected(answer, f"/external/{disabled}", "settings_saved_imap_login_cleared")
    assert journal_rows(database, "set_pop3_login")[-1][3]["mark_cleared"] == {
        "uidvalidity": 7, "last_uid": 3}
    database.sql("UPDATE external_mailbox SET imap_uidvalidity = 7, imap_last_uid = 4 "
                 "WHERE id = %s", (disabled,))
    answer = browser.post(f"/external/{disabled}/servers", {**servers,
                                                            "pop3_host": "mail.example.net"})
    assert redirected(answer, f"/external/{disabled}", "servers_saved_mark_cleared_disabled")
    assert stored(database, disabled, "imap_uidvalidity", "credential") == (None, None)
    assert journal_rows(database, "set_provider_servers")[-1][3]["mark_cleared"] == {
        "uidvalidity": 7, "last_uid": 4}

    # never enabled, it has no mark to clear: a new login is only a new login
    fresh = an_imap_mailbox(database, "Fresh@example.net")
    answer = browser.post(f"/external/{fresh}/settings", {"pop3_login": "fresh-imap",
                                                          "keep_at_provider": "yes"})
    assert redirected(answer, f"/external/{fresh}", "settings_saved_imap_login")
    assert "mark_cleared" not in journal_rows(database, "set_pop3_login")[-1][3]
    answer = browser.post(f"/external/{fresh}/servers", {**servers,
                                                         "pop3_host": "mail.example.net"})
    assert redirected(answer, f"/external/{fresh}", "servers_saved_password_cleared")


def an_imap_page(world, monkeypatch, **changed):
    monkeypatch.setitem(EXTERNALS, 12, an_external(
        id=12, address="Inbox@example.net", address_canonical="inbox@example.net",
        protocol="imap", pop3_login=None, pop3_host="imap.example.net", pop3_port=993,
        keep_at_provider=True, delete_window_days=30, frozen_since=None, **changed))
    return main_part(world, "/external/12")[1]


def settings_form(html, external_id):
    return html.split(f'<form method="post" action="/external/{external_id}/settings">',
                      1)[1].split("</form>", 1)[0]


def test_an_imap_mailbox_page_names_its_server_by_protocol_and_shows_no_window(
        external_world, monkeypatch):
    html = an_imap_page(external_world, monkeypatch)
    lede = " ".join(page_head(html).split())
    assert "It is collected over IMAP, which changes nothing at the provider." in lede
    assert "deletion window" not in lede
    servers = html.split('<form method="post" action="/external/12/servers">', 1)[1] \
        .split("</form>", 1)[0]
    labels = re.findall(r'<label for="([a-z0-9_]+)">([^<]+)</label>', servers)
    assert labels == [("pop3_host", "IMAP host"), ("pop3_port", "IMAP port"),
                      ("smtp_host", "SMTP host"), ("smtp_port", "SMTP port"),
                      ("pop3_cert_fingerprint", "IMAP certificate fingerprint"),
                      ("smtp_cert_fingerprint", "SMTP certificate fingerprint")]
    assert "As for IMAP, but the relay pins a server" in " ".join(servers.split())
    settings = settings_form(html, 12)
    assert '<label for="pop3_login">IMAP login</label>' in settings
    assert "Empty means the IMAP login" in " ".join(settings.split())
    # the window and the keep box give way to the sentence; the box's value travels
    assert 'name="window"' not in settings and 'type="checkbox"' not in settings
    assert '<input type="hidden" name="keep_at_provider" value="yes">' in settings
    keeps = settings.split('<span class="lbl">Deletion at the provider</span>', 1)[1] \
        .split("</div>", 1)[0]
    assert ("<p>None. Nothing collected over IMAP is ever deleted, moved or marked as read at "
            "the provider") in " ".join(keeps.split())
    # enabled: the protocol is named, not offered, and a new host or login says it waits
    assert ('<div class="field"><span class="lbl">Protocol</span><p>IMAP</p>'
            '<p class="help">It changes only while the mailbox is disabled') \
        in " ".join(settings.split()).replace("> <", "><")
    assert 'name="protocol"' not in settings
    waits = "nothing is collected until it is disabled and enabled again"
    assert waits in " ".join(settings.split())
    flash = servers.split('<div class="flash attn">', 1)[1].split("</div></div>", 1)[0]
    assert ("A new IMAP host also clears the starting point in the provider's INBOX: "
            "nothing is collected until the mailbox is disabled and enabled again.") \
        in " ".join(flash.split())

    # disabled: the protocol is two tiles, IMAP chosen, and nothing waits on a person
    html = an_imap_page(external_world, monkeypatch, state="deactivated")
    settings = settings_form(html, 12)
    tiles = re.findall(r'<input type="radio" name="protocol" value="([a-z0-9]+)"( checked)?>',
                       settings)
    assert tiles == [("pop3", ""), ("imap", " checked")]
    assert '<div class="field"><span class="lbl">Protocol</span>\n<label class="choice">' \
        in settings
    assert waits not in " ".join(settings.split())
    assert "A new IMAP host" not in html


def test_a_pop3_mailbox_page_keeps_its_window_and_its_protocol_tiles_only_while_disabled(
        external_world):
    _, html = main_part(external_world, "/external/9")             # enabled
    settings = settings_form(html, 9)
    assert '<label for="pop3_login">POP3 login</label>' in settings
    assert 'name="window"' in settings and 'name="keep_at_provider"' in settings
    assert 'type="hidden" name="keep_at_provider"' not in settings
    assert 'name="protocol"' not in settings and "<p>POP3</p>" in settings
    assert "A new IMAP host" not in html and "starting point" not in html
    _, html = main_part(external_world, "/external/11")            # disabled
    tiles = re.findall(r'<input type="radio" name="protocol" value="([a-z0-9]+)"( checked)?>',
                       settings_form(html, 11))
    assert tiles == [("pop3", " checked"), ("imap", "")]


def test_the_add_form_offers_the_protocol_and_labels_the_server_for_either(external_world):
    """The page has no script to relabel its fields when IMAP is chosen in it: named by the
    protocol sent, they said "POP3 host" beside the IMAP tile, sent or not."""
    either = [("pop3_login", "POP3 or IMAP login"), ("pop3_host", "POP3 or IMAP host"),
              ("pop3_port", "POP3 or IMAP port"),
              ("pop3_cert_fingerprint", "POP3 or IMAP certificate fingerprint")]
    _, html = main_part(external_world, "/external/add")
    form = html.split('<form class="narrow" method="post" action="/external/add">', 1)[1]
    assert re.findall(r'<label for="(pop3_[a-z_]+)">([^<]+)</label>', form) == either
    port = form.split('<label for="pop3_port">', 1)[1].split("</div>", 1)[0]
    assert 'name="pop3_port" type="number" class="short"' in port         # no value: empty
    assert "Empty is the protocol's own port: 995 for POP3, 993 for IMAP." \
        in " ".join(port.split())
    assert "Empty means the POP3 or IMAP login" in " ".join(form.split())
    status, html = main_part(external_world, "/external/add", "post", **an_addition(
        protocol="imap", domain_choice="free", domain_id="4"))
    assert status == 400
    form = html.split('<form class="narrow" method="post" action="/external/add">', 1)[1]
    assert re.findall(r'<label for="(pop3_[a-z_]+)">([^<]+)</label>', form) == either
    choice = form.split('<span class="lbl">Protocol</span>', 1)[1].split("</div>\n", 1)[0]
    assert '<input type="radio" name="protocol" value="imap" checked>' in choice
    assert f'<p class="help warn">{validate.IMAP_KEEPS}</p>' in choice
    assert html.count("help warn") == 1
    # a refusal of a server field still names the protocol sent
    status, html = main_part(external_world, "/external/add", "post", **an_addition(
        protocol="imap", keep_at_provider="yes", pop3_port="0", domain_choice="free",
        domain_id="4"))
    assert status == 400
    assert "The IMAP port must be a whole number from 1 to 65535." in html


# --- the snapshot of every folder -------------------------------------------------------


def said(sentence):
    """A sentence as a page carries it: escaped, its apostrophes included."""
    from markupsafe import escape
    return str(escape(sentence))


def snapshot_columns(database, external_id):
    return stored(database, external_id, "snapshot_requested_at", "snapshot_status")


def wanted(database, external_id):
    """Whether the pipeline's slice would take this row's snapshot: its own predicate."""
    from maildivvy.fetch import snapshot
    return database.value("SELECT count(*) FROM external_mailbox e WHERE e.id = %s AND "
                          + snapshot.WANTED, (external_id,)) == 1


def test_a_snapshot_is_asked_of_an_enabled_imap_mailbox_once_and_journaled(browser, database):
    """The interface writes when it was asked and nothing else of the snapshot; the slice's
    own predicate then reads it as wanted. A second ask is the same one."""
    enabled = an_imap_mailbox(database, "Inbox@example.net", state="active", mark=(7, 3))
    path = f"/external/{enabled}"
    queued = requests(database)
    assert redirected(browser.post(f"{path}/snapshot"), path, "snapshot_asked")
    asked, status = snapshot_columns(database, enabled)
    assert asked is not None and status is None and wanted(database, enabled)
    assert journal_rows(database, "request_snapshot") == [
        (ADMIN, "request_snapshot", "inbox@example.net", {"requested": True})]
    assert requests(database) == queued      # no request row: the snapshot's timer takes it
    assert redirected(browser.post(f"{path}/snapshot"), path, "already_asked")
    assert snapshot_columns(database, enabled) == (asked, None)
    assert len(journal_rows(database, "request_snapshot")) == 1
    # under way, it is the same snapshot too
    database.sql("UPDATE external_mailbox SET snapshot_status = 'paused' WHERE id = %s",
                 (enabled,))
    assert redirected(browser.post(f"{path}/snapshot"), path, "already_asked")
    # a finished one is discarded before another is asked for
    database.sql("UPDATE external_mailbox SET snapshot_status = 'done', "
                 "snapshot_finished_at = now() WHERE id = %s", (enabled,))
    before = counts(database)
    answer = browser.post(f"{path}/snapshot")
    assert answer.status_code == 400 and said(external.SNAPSHOT_THERE) in main_of(answer)
    assert counts(database) == before and snapshot_columns(database, enabled) == (asked, "done")


def test_a_snapshot_is_refused_where_it_could_not_be_taken_and_nothing_is_written(
        browser, ids, database):
    disabled = an_imap_mailbox(database, "Spare@example.net", mark=(7, 3))
    unmarked = an_imap_mailbox(database, "Fresh@example.net", state="active")
    discarding = an_imap_mailbox(database, "Done@example.net", state="active", mark=(7, 3))
    database.sql("UPDATE external_mailbox SET snapshot_requested_at = now() - interval '1 day', "
                 "snapshot_status = 'done', snapshot_finished_at = now() WHERE id = %s",
                 (discarding,))
    assert redirected(browser.post(f"/external/{discarding}/snapshot/discard"),
                      f"/external/{discarding}", "snapshot_discard_asked")
    before = counts(database)
    for external_id, sentence in ((ids["free_external"], external.SNAPSHOT_NOT_IMAP),
                                  (disabled, external.SNAPSHOT_WHILE_DISABLED),
                                  (unmarked, external.SNAPSHOT_NO_MARK),
                                  (discarding, external.SNAPSHOT_DISCARDING)):
        answer = browser.post(f"/external/{external_id}/snapshot")
        assert answer.status_code == 400, external_id
        page = main_of(answer)
        assert page.count(said(sentence)) == 1, external_id     # the flash, said once
        assert '<div class="flash bad">' in page.split("<h2>Snapshot of every folder</h2>", 1)[1]
    assert counts(database) == before
    assert database.value("SELECT count(*) FROM external_mailbox WHERE snapshot_requested_at "
                          "IS NOT NULL") == 1                    # the discarded one's alone


def test_the_request_is_written_only_where_the_row_still_allows_it(ids, database):
    """The statement holds the rule itself, as the interface's own role runs it, so a POST
    that crossed a disable, a discard or a slice starting writes nothing: the route's own
    check came before it."""
    allowed = an_imap_mailbox(database, "Inbox@example.net", state="active", mark=(7, 3))
    ruled_out = {
        "a pop3 mailbox": ids["free_external"],
        "disabled": an_imap_mailbox(database, "Spare@example.net", mark=(7, 3)),
        "no starting point": an_imap_mailbox(database, "Fresh@example.net", state="active"),
        "asked already": an_imap_mailbox(database, "Asked@example.net", state="active",
                                         mark=(7, 3)),
        "under way": an_imap_mailbox(database, "Going@example.net", state="active",
                                     mark=(7, 3)),
        "discard asked": an_imap_mailbox(database, "Gone@example.net", state="active",
                                         mark=(7, 3)),
    }
    database.sql("UPDATE external_mailbox SET snapshot_requested_at = now() WHERE id = %s",
                 (ruled_out["asked already"],))
    database.sql("UPDATE external_mailbox SET snapshot_requested_at = now(), "
                 "snapshot_status = 'running' WHERE id = %s", (ruled_out["under way"],))
    database.sql("INSERT INTO request (kind, target, payload, asked_by) VALUES "
                 "('discard_snapshot', 'gone@example.net', %s, %s)",
                 (f'{{"external_mailbox_id": {ruled_out["discard asked"]}}}', ADMIN))
    conn = database.connect("admin")
    try:
        with conn.cursor() as cursor:
            for why, external_id in ruled_out.items():
                cursor.execute(external.ASK_SNAPSHOT, (external_id,))
                assert cursor.fetchone() is None, why
            cursor.execute(external.ASK_SNAPSHOT, (allowed,))   # the control
            assert cursor.fetchone() == (allowed,)
        conn.commit()
    finally:
        conn.close()
    assert wanted(database, allowed)
    assert not wanted(database, ruled_out["a pop3 mailbox"])


def test_a_snapshot_is_discarded_through_its_confirmation_page_by_one_request(browser,
                                                                              database):
    failed = an_imap_mailbox(database, "Inbox@example.net", state="active", mark=(7, 3))
    database.sql("UPDATE external_mailbox SET snapshot_requested_at = now() - interval '1 day', "
                 "snapshot_started_at = now() - interval '1 day', snapshot_status = 'failed', "
                 "snapshot_finished_at = now(), snapshot_detail = 'the provider renumbered "
                 "the INBOX' WHERE id = %s", (failed,))
    path = f"/external/{failed}/snapshot/discard"
    page = main_of(browser.get(path))
    assert "danger-zone" in page and "the provider renumbered the INBOX" in page
    assert redirected(browser.post(path), f"/external/{failed}", "snapshot_discard_asked")
    assert requests(database, "discard_snapshot") == [
        ("discard_snapshot", "inbox@example.net", {"external_mailbox_id": failed}, ADMIN,
         "queued")]
    assert journal_rows(database, "discard_snapshot") == [
        (ADMIN, "discard_snapshot", "inbox@example.net", {"requested": True})]
    assert database.value("SELECT a.request_id = r.id FROM audit a, request r WHERE "
                          "a.action = 'discard_snapshot' AND r.kind = 'discard_snapshot'")
    # asked twice, it is the one request; the row itself is the pipeline's to change
    assert redirected(browser.post(path), f"/external/{failed}", "already_asked")
    assert len(requests(database, "discard_snapshot")) == 1
    assert stored(database, failed, "snapshot_status") == ("failed",)
    # the page while it waits: the discard's row says so, and offers no second link to it
    page = main_of(browser.get(f"/external/{failed}"))
    zone = page.split('<section class="danger-zone">', 1)[1]
    assert zone.split('<div class="zone-row">')[1].endswith(
        '<span class="muted">waiting for the pipeline</span></div>')
    assert 'href="' + path + '"' not in page

    # with nothing there, both the page and the act are the refusal, and nothing is written
    database.sql("UPDATE request SET state = 'done' WHERE kind = 'discard_snapshot'")
    database.sql("UPDATE external_mailbox SET snapshot_status = NULL, snapshot_started_at = "
                 "NULL, snapshot_finished_at = now(), snapshot_detail = NULL WHERE id = %s",
                 (failed,))
    before = counts(database)
    for answer in (browser.get(path), browser.post(path)):
        assert answer.status_code == 400
        page = main_of(answer)
        assert said(external.NO_SNAPSHOT) in page and "btn-danger-solid" not in page
    assert counts(database) == before


def a_snapshot_page(world, monkeypatch, path="/external/12", **changed):
    monkeypatch.setitem(EXTERNALS, 12, an_external(**{
        "id": 12, "address": "Inbox@example.net", "address_canonical": "inbox@example.net",
        "protocol": "imap", "pop3_login": None, "pop3_host": "imap.example.net",
        "pop3_port": 993, "keep_at_provider": True, "delete_window_days": 30,
        "frozen_since": None, "imap_uidvalidity": 7, **changed}))
    return main_part(world, path)[1]


def snapshot_box(html):
    return html.split("<h2>Snapshot of every folder</h2>", 1)[1].split("</section>", 1)[0]


ASKED_ON = datetime.datetime(2026, 11, 15, 9, 0, tzinfo=datetime.timezone.utc)
STARTED_ON = datetime.datetime(2026, 11, 15, 9, 10, tzinfo=datetime.timezone.utc)
ENDED_ON = datetime.datetime(2026, 11, 16, 8, 0, tzinfo=datetime.timezone.utc)
PROGRESS = "2 of 5 folders taken, 40 messages, 81920 bytes"


@pytest.mark.parametrize("columns, badge, says", [
    ({}, '<span class="badge off">none</span>', None),
    ({"snapshot_requested_at": ASKED_ON},
     '<span class="badge attn"><svg class="icon attn"><use href="#i-clock"/></svg> asked</span>',
     "Asked 2026-11-15 09:00 UTC: its first slice starts it."),
    ({"snapshot_requested_at": ASKED_ON, "snapshot_started_at": STARTED_ON,
      "snapshot_status": "pending", "snapshot_detail": PROGRESS},
     '<span class="badge attn"><svg class="icon attn"><use href="#i-clock"/></svg> under way'
     '</span>',
     "Started 2026-11-15 09:10 UTC; the next slice goes on from where the last one stopped."),
    ({"snapshot_requested_at": ASKED_ON, "snapshot_started_at": STARTED_ON,
      "snapshot_status": "running", "snapshot_detail": PROGRESS},
     '<span class="badge attn"><svg class="icon attn"><use href="#i-clock"/></svg> a slice '
     'running</span>', "Started 2026-11-15 09:10 UTC; a slice is taking it now."),
    ({"snapshot_requested_at": ASKED_ON, "snapshot_started_at": STARTED_ON,
      "snapshot_status": "paused", "snapshot_paused_since": ENDED_ON,
      "snapshot_detail": PROGRESS},
     '<span class="badge attn"><svg class="icon attn"><use href="#i-alert"/></svg> paused</span>',
     "Started 2026-11-15 09:10 UTC; paused since 2026-11-16 08:00 UTC, and every slice tries "
     "again."),
    ({"snapshot_requested_at": ASKED_ON, "snapshot_started_at": STARTED_ON,
      "snapshot_status": "done", "snapshot_finished_at": ENDED_ON,
      "snapshot_detail": "5 of 5 folders taken, 80 messages, 163840 bytes"},
     '<span class="badge ok"><svg class="icon ok"><use href="#i-check"/></svg> done</span>',
     "Started 2026-11-15 09:10 UTC; done 2026-11-16 08:00 UTC."),
    # done through every slice that asked again, without what the provider still refused
    ({"snapshot_requested_at": ASKED_ON, "snapshot_started_at": STARTED_ON,
      "snapshot_status": "done", "snapshot_finished_at": ENDED_ON, "snapshot_refused": 2,
      "snapshot_detail": "5 of 5 folders taken, 78 messages, 159744 bytes; 2 message(s) the "
                         "provider refused to send, not copied, asked for again 6 of 6 times"},
     '<span class="badge attn"><svg class="icon attn"><use href="#i-alert"/></svg> done, 2 not '
     'copied</span>',
     "Started 2026-11-15 09:10 UTC; done 2026-11-16 08:00 UTC."),
    # done without the folders it left out: a name the store cannot hold, or one EXAMINE refused
    ({"snapshot_requested_at": ASKED_ON, "snapshot_started_at": STARTED_ON,
      "snapshot_status": "done", "snapshot_finished_at": ENDED_ON, "snapshot_left_out": 1,
      "snapshot_detail": "4 of 4 folders taken, 80 messages, 163840 bytes; 1 left out: Private"},
     '<span class="badge attn"><svg class="icon attn"><use href="#i-alert"/></svg> done, 1 folder '
     'left out</span>',
     "Started 2026-11-15 09:10 UTC; done 2026-11-16 08:00 UTC."),
    ({"snapshot_requested_at": ASKED_ON, "snapshot_started_at": STARTED_ON,
      "snapshot_status": "done", "snapshot_finished_at": ENDED_ON, "snapshot_refused": 2,
      "snapshot_left_out": 3, "snapshot_detail": "4 of 4 folders taken, 78 messages"},
     '<span class="badge attn"><svg class="icon attn"><use href="#i-alert"/></svg> done, 2 not '
     'copied, 3 folders left out</span>',
     "Started 2026-11-15 09:10 UTC; done 2026-11-16 08:00 UTC."),
    ({"snapshot_requested_at": ASKED_ON, "snapshot_started_at": STARTED_ON,
      "snapshot_status": "failed", "snapshot_finished_at": ENDED_ON,
      "snapshot_detail": "the provider renumbered the <INBOX>"},
     '<span class="badge bad"><svg class="icon bad"><use href="#i-alert"/></svg> failed</span>',
     "Started 2026-11-15 09:10 UTC; failed 2026-11-16 08:00 UTC."),
])
def test_the_snapshot_section_says_its_state_its_progress_and_where_it_is(
        external_world, monkeypatch, columns, badge, says):
    html = a_snapshot_page(external_world, monkeypatch, **columns)
    box = snapshot_box(html)
    assert box.startswith(badge + "</div>")
    status = columns.get("snapshot_status")
    button = ('<form class="btn-row" method="post" action="/external/12/snapshot">'
              '<button class="btn" type="submit">Take a snapshot of every folder</button></form>')
    assert (button in box) == (not columns)
    # nothing bounds a day's download: the rule is said beside the button, in amber
    cap = "Nothing here limits what a snapshot downloads in a day."
    assert (cap in box) == (not columns)
    if not columns:
        flash = box.split('<div class="flash attn">', 1)[1]
        assert flash.index(cap) < flash.index(button)
        assert "ask for a snapshot only of a mailbox whose copy stays well under the day's cap, " \
               "counting the second copy of each message in All Mail." in " ".join(box.split())
    assert (says is None) or f"<p>{says}</p>" in box
    # where it stands is the last slice's own sentence, escaped; the copy's path is the store's
    if status:
        detail = columns["snapshot_detail"].replace("<", "&lt;").replace(">", "&gt;")
        assert f"<p>The last slice said: {detail}.</p>" in box
        assert "<code>/srv/maildivvy/store/_snapshots/12</code>" in box
    else:
        assert "The last slice said" not in box and "_snapshots" not in box
    assert ("Nothing takes it up again: discard it below" in box) == (status in ("done", "failed"))
    # the discard is a row of the danger zone above the deletion, once there is anything
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    rows = zone.split('<div class="zone-row">')[1:]
    assert len(rows) == (2 if columns else 1)
    assert rows[-1].endswith('<a class="btn btn-danger" href="/external/12/delete">Delete this '
                             'external mailbox&hellip;</a></div>')
    if columns:
        assert rows[0].startswith("<div><b>Discard the snapshot: its copy in the store goes")
        assert rows[0].endswith('<a class="btn btn-danger" href="/external/12/snapshot/discard">'
                                'Discard the snapshot&hellip;</a></div>')
        assert "the fetcher's state, and the snapshot." in rows[-1]


def test_a_snapshot_not_offered_says_why_and_a_pop3_mailbox_has_no_section(external_world,
                                                                          monkeypatch):
    for changed, sentence in (({"state": "deactivated"}, external.SNAPSHOT_WHILE_DISABLED),
                              ({"imap_uidvalidity": None}, external.SNAPSHOT_NO_MARK)):
        box = snapshot_box(a_snapshot_page(external_world, monkeypatch, **changed))
        assert f'<p class="muted">{said(sentence)}</p>' in box and "<form" not in box
    _, html = main_part(external_world, "/external/9")                  # POP3
    assert "Snapshot of every folder" not in html and "snapshot/discard" not in html
    # one that still holds a snapshot from before its protocol changed shows it, to discard
    monkeypatch.setitem(EXTERNALS, 9, an_external(snapshot_status="done",
                                                  snapshot_started_at=STARTED_ON,
                                                  snapshot_finished_at=ENDED_ON))
    _, html = main_part(external_world, "/external/9")
    box = snapshot_box(html)
    assert "<p>Started 2026-11-15 09:10 UTC; done 2026-11-16 08:00 UTC.</p>" in box
    assert "<form" not in box and 'href="/external/9/snapshot/discard"' in html


def test_the_discard_page_says_what_goes_before_its_one_solid_button(external_world,
                                                                     monkeypatch):
    html = a_snapshot_page(external_world, monkeypatch, "/external/12/snapshot/discard",
                           snapshot_requested_at=ASKED_ON, snapshot_started_at=STARTED_ON,
                           snapshot_status="done", snapshot_finished_at=ENDED_ON,
                           snapshot_detail=PROGRESS)
    assert html.startswith('<div class="crumbs"><a href="/external">External mailboxes</a> / '
                           '<a href="/external/12"><code>Inbox@example.net</code></a> / '
                           'Discard the snapshot</div>')
    head = " ".join(page_head(html).split())
    assert "<h1>Discard the snapshot of <code>Inbox@example.net</code>?</h1>" in head
    assert "Nothing at the provider changes" in head
    zone = html.split('<section class="danger-zone">', 1)[1].split("</section>", 1)[0]
    assert zone.startswith('<div class="box-head"><h2>What goes</h2></div>')
    assert f"<p>The last slice said: {PROGRESS}.</p>" in zone
    assert "<code>/srv/maildivvy/store/_snapshots/12</code>" in zone
    assert ('<form class="form-foot" method="post" action="/external/12/snapshot/discard">'
            ) in zone
    assert html.count("btn-danger-solid") == 1 and "btn-primary" not in html
    assert '<svg class="icon"><use href="#i-back"/></svg> Cancel, nothing changes</a>' in html
    # asked and not begun, there is no copy yet: the request alone is what goes
    html = a_snapshot_page(external_world, monkeypatch, "/external/12/snapshot/discard",
                           snapshot_requested_at=ASKED_ON)
    assert "Asked 2026-11-15 09:00 UTC" in html and "_snapshots" not in html
    assert html.count("btn-danger-solid") == 1


def test_the_snapshot_states_the_screen_names_are_the_pipelines_closed_list():
    from maildivvy.fetch import snapshot
    assert set(external.SNAPSHOT_STATES) - {None, external.ASKED} == set(snapshot.STATUSES)
    assert external.ASKED not in snapshot.STATUSES
    # every voice is one the design has, and red is the failure's alone
    assert {tone for _, tone, _ in external.SNAPSHOT_STATES.values()} == {"off", "attn", "ok",
                                                                         "bad"}
    assert [state for state, (_, tone, _) in external.SNAPSHOT_STATES.items()
            if tone == "bad"] == ["failed"]


def test_a_message_passed_over_the_cap_is_said_on_the_list_and_the_page_for_a_week(browser,
                                                                                    database):
    over = an_imap_mailbox(database, "Large@example.net", state="active", mark=(7, 3))
    database.sql("UPDATE external_mailbox SET oversize_skipped = jsonb_build_object('uid', 3, "
                 "'uidvalidity', 7, 'size', 60000000, 'at', now() - interval '2 days') "
                 "WHERE id = %s", (over,))
    said = "message 3 (60,000,000 bytes) was over the 52,428,800-byte cap and was not collected"
    assert said in main_of(browser.get(f"/external/{over}"))
    assert said in main_of(browser.get("/external"))
    database.sql("UPDATE external_mailbox SET oversize_skipped = jsonb_set(oversize_skipped, "
                 "'{at}', to_jsonb(now() - interval '8 days')) WHERE id = %s", (over,))
    assert "was over the" not in main_of(browser.get(f"/external/{over}"))
