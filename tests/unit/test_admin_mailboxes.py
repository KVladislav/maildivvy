"""The mailbox screens and the maintenance acts on a mailbox's card: giving one, its
card, a transfer, a removal, a top-up and one message delivered by id.

The acts run against the real schema as `maildivvy_admin` (`admin_db.py`), and each is
read back from the rows it wrote, or did not.
"""

import re

import pytest

from admin_db import (ADMIN, counts, journal_rows, left_by_deletion, main_of, redirected,
                      requests)
from maildivvy.admin.screens import maintenance, mailboxes
import datetime
from maildivvy.admin import app as application
from maildivvy.admin.screens import (common)
from admin_pages import main_part, page_head
from admin_stand_in import Connection, GoneConnection, IntegrityError, setting_row, templates


def test_giving_a_mailbox_writes_its_row_and_queues_the_maildir_and_the_connect(
        browser, ids, database):
    answer = browser.post("/mailboxes/add", {"domain_id": str(ids["sales"]),
                                             "account_id": str(ids["ivan"])})
    assert redirected(answer, "/mailboxes", "mailbox_given")
    mailbox_id = database.value("SELECT id FROM mailbox WHERE account_id = %s AND "
                                "domain_id = %s", (ids["ivan"], ids["sales"]))
    # two units of work, so two rows, in that order
    assert [row[:3] for row in requests(database)[-2:]] == [
        ("create_mailbox", "ivan@sales", {"mailbox_id": mailbox_id}),
        ("connect", "ivan@sales", {"mailbox_id": mailbox_id})]
    assert journal_rows(database)[-1] == (ADMIN, "create_mailbox", "ivan@sales",
                                     {"domain": "sales", "login": "ivan"})


@pytest.mark.parametrize("state", ["running", "failed"])
def test_a_mailbox_is_not_given_where_a_deletion_has_not_removed_the_old_one(
        browser, ids, database, state):
    """`ivan@sales` was deleted and its directories are still on that deletion's list:
    giving ivan a mailbox in sales, or transferring one to him there, would open the
    deleted mail. Both are refused naming the request, writing nothing; once the list is
    gone, the same form gives it."""
    left = left_by_deletion(database, "delete_mailbox", "ivan@sales", [["sales", "ivan"]],
                            state)
    # another login's entry and another domain's do not hold this slot
    left_by_deletion(database, "delete_mailbox", "olga@office", [["office", "olga"]])
    before = counts(database)
    for path, form in (("/mailboxes/add", {"domain_id": str(ids["sales"]),
                                           "account_id": str(ids["ivan"])}),
                       (f"/mailboxes/{ids['olga_sales']}/transfer",
                        {"to_account_id": str(ids["ivan"])})):
        answer = browser.post(path, form)
        assert answer.status_code == 400, path
        said = main_of(answer)
        assert f"Request {left}, a deletion, has not finished removing the old " \
            "directories of ivan@sales" in said, path
    assert counts(database) == before
    database.sql("UPDATE request SET state = 'done', payload = payload - 'gone' WHERE id = %s",
                 (left,))
    answer = browser.post("/mailboxes/add", {"domain_id": str(ids["sales"]),
                                             "account_id": str(ids["ivan"])})
    assert redirected(answer, "/mailboxes", "mailbox_given")


@pytest.mark.parametrize("form, says", [
    ({"domain_id": "", "account_id": ""}, mailboxes.BOTH),
    ({"domain_id": "sales", "account_id": "2"}, mailboxes.BOTH),
    ({"domain_id": "999999", "account_id": "{olga}"}, mailboxes.NO_DOMAIN),
    ({"domain_id": "{sales}", "account_id": "999999"}, mailboxes.NO_PERSON),
    ({"domain_id": "{sales}", "account_id": "{olga}"}, mailboxes.OCCUPIED),
    ({"domain_id": str(2 ** 63), "account_id": "{olga}"}, mailboxes.BOTH),
])
def test_a_refused_mailbox_is_the_form_again_and_writes_nothing(browser, ids, database,
                                                                form, says):
    form = {key: value.format(**{k: v for k, v in ids.items()}) for key, value in form.items()}
    before = counts(database)
    answer = browser.post("/mailboxes/add", form)
    assert answer.status_code == 400
    assert says.split(":")[0].split(".")[0] in main_of(answer)
    assert counts(database) == before


def test_the_list_holds_every_mailbox_and_each_domains_archive_built_from_the_domain(
        browser, ids):
    page = main_of(browser.get("/mailboxes"))
    for address in ("archive@sales", "archive@office", "olga@sales", "petr@sales"):
        assert address in page, address
    filtered = main_of(browser.get(f"/mailboxes?domain={ids['office']}"))
    assert "archive@office" in filtered and "olga@sales" not in filtered
    # a filter that is not a number is no filter, never an error
    assert browser.get("/mailboxes?domain=%C2%B2").status_code == 200


def test_a_mailbox_card_has_no_password_of_its_own_and_points_at_the_person(browser, ids):
    card = main_of(browser.get(f"/mailboxes/{ids['olga_sales']}"))
    assert 'type="password"' not in card
    assert f'href="/people/{ids["olga"]}"' in card
    assert browser.get("/mailboxes/999999").status_code == 404


def test_a_transfer_is_a_request_naming_the_recipient_by_id_and_login(browser, ids,
                                                                      database):
    path = f"/mailboxes/{ids['olga_sales']}/transfer"
    assert redirected(browser.post(path, {"to_account_id": str(ids["ivan"])}), "/mailboxes",
                      "transfer_asked")
    assert requests(database, "transfer") == [
        ("transfer", "olga@sales", {"mailbox_id": ids["olga_sales"],
                                    "to_account_id": ids["ivan"]}, ADMIN, "queued")]
    assert journal_rows(database, "transfer")[0][3] == {"to_account_id": ids["ivan"],
                                                   "to_login": "ivan"}
    # the row is not moved here: the store moves with it, and only the pipeline may
    assert database.value("SELECT account_id FROM mailbox WHERE id = %s",
                          (ids["olga_sales"],)) == ids["olga"]
    # a double click asks once, and journals once
    assert redirected(browser.post(path, {"to_account_id": str(ids["ivan"])}), "/mailboxes",
                      "already_asked")
    assert len(requests(database, "transfer")) == len(journal_rows(database, "transfer")) == 1


@pytest.mark.parametrize("chosen", ["", "nobody", "999999", "{petr}"])
def test_a_transfer_into_an_occupied_or_missing_slot_is_refused(browser, ids, database,
                                                                chosen):
    before = counts(database)
    answer = browser.post(f"/mailboxes/{ids['olga_sales']}/transfer",
                          {"to_account_id": chosen.format(petr=ids["petr"])})
    assert answer.status_code == 400 and '<div class="flash bad">' in main_of(answer)
    assert counts(database) == before


def test_a_removal_states_its_numbers_and_is_asked_once(browser, ids, database):
    path = f"/mailboxes/{ids['olga_sales']}/delete"
    page = browser.get(path)
    assert page.status_code == 200 and "danger-zone" in main_of(page)
    assert redirected(browser.post(path), "/mailboxes", "mailbox_removal_asked")
    assert redirected(browser.post(path), "/mailboxes", "already_asked")
    assert requests(database, "delete_mailbox") == [
        ("delete_mailbox", "olga@sales", {"mailbox_id": ids["olga_sales"]}, ADMIN, "queued")]
    assert database.value("SELECT count(*) FROM mailbox WHERE id = %s",
                          (ids["olga_sales"],)) == 1


# --- maintenance on the card --------------------------------------------

def test_a_top_up_shows_both_counts_then_asks_for_the_chosen_range(browser, ids, database):
    path = f"/mailboxes/{ids['olga_sales']}/top-up"
    page = browser.get(f"{path}?since=2026-11-01&until=2026-11-30")
    assert page.status_code == 200
    answer = browser.post(path, {"since": "2026-11-01", "until": "2026-11-30",
                                 "choice": "range"})
    assert redirected(answer, f"/mailboxes/{ids['olga_sales']}", "top_up_asked")
    assert browser.post(path, {"since": "", "until": "", "choice": "all"}).status_code == 303
    assert [row[2] for row in requests(database, "top_up")] == [
        {"mailbox_id": ids["olga_sales"], "since": "2026-11-01", "until": "2026-11-30"},
        {"mailbox_id": ids["olga_sales"], "since": maintenance.WIDE_SINCE,
         "until": maintenance.WIDE_UNTIL}]
    # the same range again, while the first waits, asks nothing more
    assert redirected(browser.post(path, {"since": "2026-11-01", "until": "2026-11-30",
                                          "choice": "range"}),
                      f"/mailboxes/{ids['olga_sales']}", "already_asked")
    assert len(requests(database, "top_up")) == len(journal_rows(database, "top_up")) == 2


@pytest.mark.parametrize("typed", [" 2026-11-01", "2026-11-01\xa0", "\t2026-11-01 "])
def test_a_top_up_date_with_spaces_around_it_goes_on_as_the_date_it_is(browser, ids, database,
                                                                      typed):
    path = f"/mailboxes/{ids['olga_sales']}/top-up"
    assert browser.get(path, query_string={"since": typed, "until": typed}).status_code == 200
    answer = browser.post(path, {"since": typed, "until": typed, "choice": "range"})
    assert redirected(answer, f"/mailboxes/{ids['olga_sales']}", "top_up_asked")
    assert requests(database, "top_up")[0][2] == {
        "mailbox_id": ids["olga_sales"], "since": "2026-11-01", "until": "2026-11-01"}


@pytest.mark.parametrize("since, until", [("", "2026-11-30"), ("2026-11-01", ""),
                                          ("2026-W45", "2026-11-30"),
                                          ("2026-02-30", "2026-03-01"),
                                          ("yesterday", "today")])
def test_a_top_up_date_that_is_not_a_calendar_date_is_refused_never_widened(
        browser, ids, database, since, until):
    before = counts(database)
    answer = browser.post(f"/mailboxes/{ids['olga_sales']}/top-up",
                          {"since": since, "until": until, "choice": "range"})
    assert answer.status_code == 400 and '<div class="flash bad">' in main_of(answer)
    assert counts(database) == before


def test_one_message_is_delivered_by_its_id(browser, ids, database):
    path = f"/mailboxes/{ids['olga_sales']}"
    assert redirected(browser.post(f"{path}/deliver-one",
                                   {"message_id": str(ids["delivered"])}),
                      path, "one_message_asked")
    assert requests(database, "deliver_one")[0][2] == {"mailbox_id": ids["olga_sales"],
                                                       "message_id": ids["delivered"]}
    assert journal_rows(database, "deliver_one")[0][3] == {"message": ids["delivered"]}
    # the same message twice asks once; another message of the mailbox is its own request
    assert redirected(browser.post(f"{path}/deliver-one",
                                   {"message_id": str(ids["delivered"])}),
                      path, "already_asked")
    other = database.value("INSERT INTO message (domain_id, subject) VALUES (%s, 'y') "
                           "RETURNING id", (ids["sales"],))
    assert redirected(browser.post(f"{path}/deliver-one", {"message_id": str(other)}),
                      path, "one_message_asked")
    assert [row[2]["message_id"] for row in requests(database, "deliver_one")] == [
        ids["delivered"], other]
    assert len(journal_rows(database, "deliver_one")) == 2


def test_a_message_that_is_not_one_of_the_domains_or_is_withheld_is_a_sentence(
        browser, ids, database):
    other = database.value("INSERT INTO message (domain_id, subject) VALUES (%s, 'x') "
                           "RETURNING id", (ids["office"],))
    path = f"/mailboxes/{ids['olga_sales']}/deliver-one"
    for typed, says in (("the third one", maintenance.NOT_A_NUMBER),
                        ("999999", "There is no message 999999"),
                        (str(other), f"Message {other} is not a message of sales"),
                        (str(ids["withheld"]), f"Message {ids['withheld']} is withheld")):
        before = counts(database)
        answer = browser.post(path, {"message_id": typed})
        assert answer.status_code == 400 and says in main_of(answer), typed
        assert counts(database) == before


def test_a_mailbox_row_is_one_shape_on_the_list_the_domain_and_the_person(browser, ids):
    def row(path):
        page = main_of(browser.get(path.format(**ids)))
        found, = [tr for tr in re.findall(r"<tr>.*?</tr>", page, re.S) if "olga@sales" in tr]
        return found

    listed = row("/mailboxes")
    # the list alone carries the person and the domain, as two cells of their own
    person = f'  <td><a href="/people/{ids["olga"]}"><code>olga</code></a></td>\n'
    domain = f'  <td><a href="/domains/{ids["sales"]}"><code>sales</code></a></td>\n'
    assert person in listed and domain in listed
    shape = listed.replace(person, "").replace(domain, "")
    assert row("/domains/{sales}") == shape == row("/people/{olga}")


def test_the_top_ups_counts_are_the_pipelines_own_selector_and_not_a_second_spelling(
        browser, ids, database):
    from maildivvy.fanout import requests as pipeline

    def message(**columns):
        names = ", ".join(columns)
        marks = ", ".join(["%s"] * len(columns))
        return database.value(f"INSERT INTO message (domain_id, {names}) VALUES "
                              f"(%s, {marks}) RETURNING id", (ids["sales"], *columns.values()))

    message(subject="in range", received_at="2026-10-05 09:00+00", archive_uid=10)
    message(subject="spam", received_at="2026-10-06 09:00+00", archive_uid=11, is_spam=True)
    message(subject="earlier", received_at="2025-01-05 09:00+00", archive_uid=12)
    message(subject="withheld", received_at="2026-10-07 09:00+00", archive_uid=13,
            state="withheld")
    database.sql("UPDATE domain SET spam_reaches_people = false WHERE id = %s", (ids["sales"],))
    path = f"/mailboxes/{ids['olga_sales']}/top-up?since=2026-10-01&until=2026-10-31"
    shown = re.findall(r"<b>(\d+)</b><span>(Between two dates|All of it)</span>",
                       main_of(browser.get(path)))
    conn = database.connect("pipeline")
    try:
        with conn.cursor() as cursor:
            counted = [str(pipeline.count_for(cursor, ids["olga_sales"], ids["sales"], since,
                                              until))
                       for since, until in (("2026-10-01", "2026-10-31"),
                                            (maintenance.WIDE_SINCE, maintenance.WIDE_UNTIL))]
    finally:
        conn.close()
    assert [number for number, _ in shown] == counted
    # and the selector did tell them apart: not every message is in either number
    assert counted[0] != "0" and int(counted[1]) < 6



# ================================================================================================
# With the database stood in (admin_stand_in.py): what a screen renders for the rows it is handed.
# ================================================================================================

# --- the mailbox screens and the top-up, in the design's components ----------------------


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
            'Connected at 2026-08-30 10:00 UTC.</p>') in head
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


def test_a_week_date_is_refused_by_the_top_up_rather_than_sent_on_to_the_query(boxes_world):
    # `date.fromisoformat` takes an ISO week date, and the text goes on to `%s::date`
    status, html = main_part(boxes_world, "/mailboxes/5/top-up?since=2026-W45-2"
                                          "&until=2026-09-30")
    assert status == 400 and "is not a date" in html


def test_a_person_removed_between_the_check_and_the_insert_is_a_sentence(boxes_world,
                                                                       monkeypatch, driver):
    monkeypatch.setattr(application, "connection", lambda: GoneConnection())
    status, html = main_part(boxes_world, "/mailboxes/add", "post", domain_id="1",
                             account_id="7")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    assert flash.split("<div>", 1)[1] == mailboxes.GONE


def test_only_a_unique_or_a_foreign_key_violation_becomes_a_sentence(driver):
    def raising(pgcode, gone=None):
        with common.unique_violation(Connection(), "taken", gone):
            raise IntegrityError(pgcode)

    for pgcode, gone, says in (("23505", None, "taken"), ("23505", "gone", "taken"),
                               ("23503", "gone", "gone")):
        with pytest.raises(common.validate.Refused) as refused:
            raising(pgcode, gone)
        assert str(refused.value) == says
    # a foreign key the form named no sentence for, and a CHECK, surface as themselves
    for pgcode, gone in (("23503", None), ("23514", "gone")):
        with pytest.raises(IntegrityError):
            raising(pgcode, gone)


# --- one mailbox row shape, everywhere --------------------------------


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


def test_the_removal_states_its_numbers_and_that_the_archive_keeps_everything(browser, ids):
    html = main_of(browser.get(f"/mailboxes/{ids['olga_sales']}/delete"))
    numbers = re.findall(r"<div><b>(\d+)</b><span>([^<]+)</span></div>", html)
    assert [what for _, what in numbers] == ["Names removed", "Mailboxes removed",
                                             "People who lose access here"]
    assert "Messages removed: 0 &mdash; the archive keeps everything." in html
    # the numbers come before the one button that removes it, and the way back after
    assert (html.index("Names removed") < html.index("btn-danger-solid")
            < html.rindex(f'<a href="/mailboxes/{ids["olga_sales"]}">'))
    assert "Cancel, nothing changes</a>" in html


# --- maintenance: one selector, one bound, and no widened range ------------------------------------


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


@pytest.mark.parametrize("today,since", [
    (datetime.date(2026, 9, 22), "2026-08-01"),
    (datetime.date(2026, 1, 3), "2025-12-01"),
    (datetime.date(2026, 3, 31), "2026-02-01"),
])
def test_the_form_opens_on_the_first_of_the_previous_month_and_today(today, since):
    assert maintenance.default_range(today) == (since, today.isoformat())
