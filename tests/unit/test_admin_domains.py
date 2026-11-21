"""The domain screens: the list, a domain, its spam policy, its archive and its deletion.

The acts run against the real schema as `maildivvy_admin` (`admin_db.py`), and each is
read back from the rows it wrote, or did not.
"""

from decimal import Decimal

import pytest

from admin_db import (ADMIN, counts, journal_rows, left_by_deletion, main_of, redirected,
                      requests, text, verifies)
import re
from maildivvy.admin import app as application
from maildivvy.admin.screens import (mailboxes)
from admin_pages import main_part, page_head
from admin_stand_in import a_box, shape

LONG = "an-archive-password-that-is-long"


def test_adding_a_domain_writes_its_row_its_request_and_two_journal_rows(browser, database):
    answer = browser.post("/domains/add", {"label": "north", "password": LONG,
                                           "password2": LONG})
    assert redirected(answer, "/domains", "domain_created")
    domain_id, stored = database.one("SELECT id, archive_password_hash FROM domain "
                                     "WHERE label = 'north'")
    assert verifies(stored, LONG)
    assert requests(database, "create_domain") == [
        ("create_domain", "north", {"domain_id": domain_id}, ADMIN, "queued")]
    assert journal_rows(database)[-2:] == [
        (ADMIN, "create_domain", "north", {"archive": "archive@north"}),
        (ADMIN, "set_archive_password", "north", {"archive_password_set": True})]
    # the create_domain row names its request, so the journal can say what came of it
    assert database.value("SELECT request_id IS NOT NULL FROM audit "
                          "WHERE action = 'create_domain' AND target = 'north'")
    # the sentence is the closed list's, and the new domain is on the list it lands on
    landed = main_of(browser.get(answer.headers["Location"]))
    assert "Domain created." in landed and "<code>north</code>" in landed


@pytest.mark.parametrize("form, says", [
    ({"label": "North", "password": LONG, "password2": LONG}, "label"),
    ({"label": "a" * 33, "password": LONG, "password2": LONG}, "label"),
    ({"label": "sales", "password": LONG, "password2": LONG}, "There is already a domain"),
    ({"label": "north", "password": LONG, "password2": LONG + "x"}, "password"),
    ({"label": "north", "password": "", "password2": ""}, "password"),
    ({"label": "north", "password": "short", "password2": "short"}, "password"),
])
def test_a_refused_domain_is_the_form_again_at_400_and_writes_nothing(browser, database,
                                                                      form, says):
    before = counts(database)
    answer = browser.post("/domains/add", form)
    assert answer.status_code == 400
    page = main_of(answer)
    assert '<div class="flash bad">' in page and says.lower() in page.lower()
    assert f'value="{form["label"][:40]}' in page          # the typed label is kept
    assert LONG not in page                                 # a password is never typed back
    assert counts(database) == before


def test_the_list_and_a_domain_page_read_the_real_rows(browser, ids):
    listing = main_of(browser.get("/domains"))
    for label in ("sales", "office"):
        assert f"<code>{label}</code>" in listing
    assert "office@example.org" in listing                 # what sits in front of office
    page = main_of(browser.get(f"/domains/{ids['sales']}"))
    for address in ("archive@sales", "olga@sales", "petr@sales"):
        assert address in page, address


def test_an_unknown_domain_is_a_404_inside_the_shell(browser):
    for path in ("/domains/999999", "/domains/999999/spam", "/domains/999999/archive",
                 "/domains/999999/delete"):
        answer = browser.get(path)
        assert answer.status_code == 404 and '<nav class="nav"' in text(answer), path


def test_the_spam_policy_saves_both_settings_and_journals_both_before_and_after(
        browser, ids, database):
    path = f"/domains/{ids['sales']}/spam"
    answer = browser.post(path, {"threshold": "6.455"})        # the switch left off
    assert redirected(answer, path, "spam_saved")
    assert database.one("SELECT spam_reaches_people, spam_threshold FROM domain WHERE id = %s",
                        (ids["sales"],)) == (False, Decimal("6.46"))
    assert journal_rows(database, "set_spam_policy") == [(ADMIN, "set_spam_policy", "sales", {
        "before": {"spam_reaches_people": True, "spam_threshold": "8.00"},
        "after": {"spam_reaches_people": False, "spam_threshold": "6.46"}})]
    # the same values again write nothing
    assert redirected(browser.post(path, {"threshold": "6.46"}), path, "spam_same")
    assert len(journal_rows(database, "set_spam_policy")) == 1


@pytest.mark.parametrize("typed", ["0.99", "150.01", "nan", "inf", "-1", "", "1e3", "eight"])
def test_a_threshold_out_of_bounds_is_refused_and_the_switch_stays_as_it_was_left(
        browser, ids, database, typed):
    answer = browser.post(f"/domains/{ids['sales']}/spam", {"threshold": typed})
    assert answer.status_code == 400 and '<div class="flash bad">' in main_of(answer)
    # the switch comes back in the position it was sent in: off
    assert 'name="reaches"' in main_of(answer) and "checked" not in \
        main_of(answer).split('name="reaches"', 1)[1].split(">", 1)[0]
    assert database.value("SELECT spam_threshold FROM domain WHERE id = %s",
                          (ids["sales"],)) == Decimal("8.00")
    assert journal_rows(database, "set_spam_policy") == []


def test_outbound_mail_too_large_to_scan_is_sent_or_refused_and_nothing_else(
        browser, ids, database):
    path = f"/domains/{ids['sales']}"
    assert redirected(browser.post(f"{path}/outbound", {"outbound_unscanned": "refuse"}),
                      path, "outbound_saved")
    assert journal_rows(database, "set_outbound_unscanned") == [
        (ADMIN, "set_outbound_unscanned", "sales", {"before": "send", "after": "refuse"})]
    assert redirected(browser.post(f"{path}/outbound", {"outbound_unscanned": "refuse"}),
                      path, "outbound_same")
    answer = browser.post(f"{path}/outbound", {"outbound_unscanned": "scan-it-anyway"})
    assert answer.status_code == 400
    assert database.value("SELECT outbound_unscanned FROM domain WHERE id = %s",
                          (ids["sales"],)) == "refuse"
    assert len(journal_rows(database, "set_outbound_unscanned")) == 1


def test_the_archive_password_is_rotated_from_its_card_typed_twice(browser, ids, database):
    path = f"/domains/{ids['sales']}/archive"
    assert browser.get(path).status_code == 200
    refused = browser.post(f"{path}/password", {"password": LONG, "password2": "other"})
    assert refused.status_code == 400
    assert not verifies(database.value("SELECT archive_password_hash FROM domain WHERE id = %s",
                                       (ids["sales"],)), LONG)
    answer = browser.post(f"{path}/password", {"password": LONG, "password2": LONG})
    assert redirected(answer, path, "archive_password_set")
    assert verifies(database.value("SELECT archive_password_hash FROM domain WHERE id = %s",
                                   (ids["sales"],)), LONG)
    assert journal_rows(database, "set_archive_password") == [
        (ADMIN, "set_archive_password", "sales", {"archive_password_set": True})]


def test_the_archive_listing_shows_sender_subject_and_date_and_waits_for_its_creation(
        browser, ids, database):
    path = f"/domains/{ids['sales']}/archive/listing"
    page = main_of(browser.get(path))
    assert "anna@example.org" in page and "Quarterly figures" in page
    # what a sender wrote is text, never markup
    assert "You &lt;i&gt;won&lt;/i&gt;" in page and "<i>won" not in page
    database.sql("INSERT INTO request (kind, target, payload, asked_by) VALUES "
                 "('create_domain', 'sales', %s, %s)", (f'{{"domain_id": {ids["sales"]}}}', ADMIN))
    assert browser.get(path).status_code == 400


def listed_ids(answer):
    return [int(found) for found in
            re.findall(r'<code class="message-id">(\d+)</code>', main_of(answer))]


@pytest.fixture
def many(ids, database):
    """250 more messages in `sales`, ten minutes apart from 2026-10-01 00:10 UTC, three of
    them sharing one arrival moment, so a page break can fall inside a tie."""
    database.sql(
        "INSERT INTO message (domain_id, received_at, sender, subject) "
        "SELECT %s, CASE WHEN n BETWEEN 100 AND 102 THEN timestamptz '2026-10-01 12:00+00' "
        "ELSE timestamptz '2026-10-01 00:00+00' + n * interval '10 minutes' END, "
        "CASE WHEN n %% 50 = 0 THEN 'boss_100%%@example.org' ELSE 'bulk@example.org' END, "
        "'number ' || n FROM generate_series(1, 250) AS n", (ids["sales"],))
    return database.sql("SELECT id FROM message WHERE domain_id = %s "
                        "ORDER BY received_at DESC, id DESC", (ids["sales"],))


# 178: the first page ends on the first of the three that arrived at one moment
@pytest.mark.parametrize("limit", [200, 178, 7])
def test_the_archive_listing_pages_through_every_message_newest_first(browser, ids, many,
                                                                     monkeypatch, limit):
    from maildivvy.admin.screens import domains

    monkeypatch.setattr(domains, "LIMIT", limit)
    every = [row[0] for row in many]
    path = f"/domains/{ids['sales']}/archive/listing"
    seen, page = [], browser.get(path)
    assert f"Only the newest {limit} messages are shown" in main_of(page)
    while True:
        assert page.status_code == 200
        shown = listed_ids(page)
        assert len(shown) <= domains.LIMIT
        seen += shown
        older = re.search(r'href="([^"]*before=\d+[^"]*)">\s*Older messages', text(page))
        if older is None:
            break
        page = browser.get(older.group(1).replace("&amp;", "&"))
        assert "Newest messages" in main_of(page) or "Newest messages" in text(page)
    assert seen == every                     # each once, in order, ties included


def test_the_archive_listing_narrows_by_sender_or_subject_and_by_the_day(browser, ids, many):
    path = f"/domains/{ids['sales']}/archive/listing"
    # a `%` or `_` typed is itself, not a wildcard
    boss = listed_ids(browser.get(path, query_string={"q": "BOSS_100%"}))
    assert len(boss) == 5
    assert listed_ids(browser.get(path, query_string={"q": "number 7"})) != []
    assert listed_ids(browser.get(path, query_string={"q": "%"})) == boss
    assert listed_ids(browser.get(path, query_string={"q": "b_ss"})) == []
    # on or before a day: the day entire, in UTC
    day = listed_ids(browser.get(path, query_string={"until": "2026-10-01"}))
    assert len(day) == 143                   # 00:10 to 23:50, the three at noon among them
    assert listed_ids(browser.get(path, query_string={"until": "2026-09-30"})) == []
    # and the narrowing is carried onto the next page
    page = browser.get(path, query_string={"q": "bulk"})
    assert "Only the newest 200 messages that match are shown" in main_of(page)
    assert "q=bulk" in re.search(r'href="([^"]*)">\s*Older messages', text(page)).group(1)


@pytest.mark.parametrize("until", ["yesterday", "2026-W45", "2026-02-30"])
def test_a_listing_day_that_is_not_a_date_is_refused_rather_than_dropped(browser, ids, until):
    answer = browser.get(f"/domains/{ids['sales']}/archive/listing",
                         query_string={"until": until})
    assert answer.status_code == 400 and '<div class="flash bad">' in main_of(answer)
    assert listed_ids(answer) == []


def test_a_free_domains_deletion_is_asked_once_and_an_occupied_one_is_refused(
        browser, ids, database):
    page = browser.get(f"/domains/{ids['sales']}/delete")
    assert page.status_code == 200 and "danger-zone" in main_of(page)
    assert redirected(browser.post(f"/domains/{ids['sales']}/delete"), "/domains",
                      "domain_deletion_asked")
    # the row stays: a deletion is the pipeline's, asked as a request
    assert database.value("SELECT count(*) FROM domain WHERE id = %s", (ids["sales"],)) == 1
    assert requests(database, "delete_domain") == [
        ("delete_domain", "sales", {"domain_id": ids["sales"]}, ADMIN, "queued")]
    # a replayed POST asks nothing more
    assert redirected(browser.post(f"/domains/{ids['sales']}/delete"), "/domains",
                      "already_asked")
    assert len(requests(database, "delete_domain")) == 1
    assert len(journal_rows(database, "delete_domain")) == 1
    before = counts(database)
    answer = browser.post(f"/domains/{ids['office']}/delete")
    assert answer.status_code == 400 and counts(database) == before



# ================================================================================================
# With the database stood in (admin_stand_in.py): what a screen renders for the rows it is handed.
# ================================================================================================

# --- the domain screens, in the design's components -----------------------------------


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


def test_a_label_is_not_used_again_while_its_deletion_has_not_removed_the_old_domain(
        browser, ids, database):
    """`north` was deleted and its directories are still on that deletion's list, a
    mailbox's among them: a new domain called north, on its own screen or as an external
    mailbox's new domain, would start its pass over the old archive. Both are refused
    naming the request, writing nothing; once the list is gone, the label is free."""
    long = "an-archive-password-that-is-long"
    left = left_by_deletion(database, "delete_domain", "north",
                            [["north", "ivan"], ["north", "archive"], ["north", None]])
    before = counts(database)
    for path, form in (
            ("/domains/add", {"label": "north", "password": long, "password2": long}),
            ("/external/add", {"address": "north@example.org", "pop3_host": "pop.example.org",
                               "pop3_port": "995", "smtp_host": "smtp.example.org",
                               "smtp_port": "587", "window": "14", "domain_choice": "new",
                               "label": "north", "password": long, "password2": long})):
        answer = browser.post(path, form)
        assert answer.status_code == 400, path
        assert f"Request {left}, a deletion, has not finished removing the old directories " \
            "of the domain north" in main_of(answer), path
    assert counts(database) == before
    database.sql("UPDATE request SET state = 'done', payload = payload - 'gone' WHERE id = %s",
                 (left,))
    answer = browser.post("/domains/add", {"label": "north", "password": long,
                                           "password2": long})
    assert redirected(answer, "/domains", "domain_created")
