"""The withheld list and the journal screen: releasing a message, and reading back who
did what through the filter.

The acts run against the real schema as `maildivvy_admin` (`admin_db.py`), and each is
read back from the rows it wrote, or did not.
"""

import re

import pytest

from admin_db import ADMIN, counts, journal_rows, main_of, redirected, requests
from markupsafe import escape
from maildivvy.admin import journal
from maildivvy.admin.screens import (accounts, events, external, mailboxes, moderation)
from admin_pages import main_part, page_head
from admin_stand_in import subject_row


def test_the_withheld_list_shows_what_was_held_back_as_text(browser, ids):
    page = main_of(browser.get("/withheld"))
    assert "spam@example.net" in page and "You &lt;i&gt;won&lt;/i&gt;" in page
    assert "Quarterly figures" not in page          # delivered, not withheld


def test_a_release_is_a_request_journaled_by_the_messages_id(browser, ids, database):
    message = ids["withheld"]
    assert redirected(browser.post(f"/withheld/{message}/release"), "/withheld",
                      "release_asked")
    assert requests(database, "release") == [
        ("release", str(message), {"message_id": message}, ADMIN, "queued")]
    assert journal_rows(database, "release") == [(ADMIN, "release", str(message),
                                             {"requested": True})]
    # the message stays withheld until the pipeline releases it
    assert database.value("SELECT state FROM message WHERE id = %s", (message,)) == "withheld"
    # and a double click asks once
    assert redirected(browser.post(f"/withheld/{message}/release"), "/withheld",
                      "already_asked")
    assert len(requests(database, "release")) == len(journal_rows(database, "release")) == 1


def test_a_message_that_is_not_withheld_is_not_released_and_an_unknown_one_is_a_404(
        browser, ids, database):
    before = counts(database)
    answer = browser.post(f"/withheld/{ids['delivered']}/release")
    assert answer.status_code == 400 and "is delivered, not withheld" in main_of(answer)
    assert browser.post("/withheld/999999/release").status_code == 404
    assert counts(database) == before


def test_the_journal_lists_the_acts_newest_first_with_the_outcome_of_their_request(
        browser, database):
    browser.post("/people/add", {"login": "anna", "password": "a-long-enough-password",
                                 "password2": "a-long-enough-password"})
    page = main_of(browser.get("/journal"))
    assert page.index("anna") < page.index("petr")         # newest first
    # the pipeline's own reason for the failed request, as text
    assert "the maildir &lt;could not&gt; be made" in page


@pytest.mark.parametrize("query, shown, hidden", [
    ("action=create_account", ["anna"], ["petr"]),
    ("target=petr", ["petr"], ["anna"]),
    ("target=pet", [], ["petr", "anna"]),                    # the match is exact
    (f"who={ADMIN}", ["anna", "petr"], []),
    ("who=nobody", [], ["anna", "petr"]),
    ("target=petr%27%20OR%20%271%27=%271", [], ["anna", "petr"]),
    ("since=2000-01-01&until=2000-01-02", [], ["anna", "petr"]),
])
def test_every_filter_is_bound_and_narrows_to_its_exact_value(browser, database, query,
                                                              shown, hidden):
    browser.post("/people/add", {"login": "anna", "password": "a-long-enough-password",
                                 "password2": "a-long-enough-password"})
    answer = browser.get(f"/journal?{query}")
    assert answer.status_code == 200
    rows = main_of(answer).split("<tbody>", 1)[-1]
    for login in shown:
        assert f"<code>{login}</code>" in rows, (query, login)
    for login in hidden:
        assert f"<code>{login}</code>" not in rows, (query, login)


@pytest.mark.parametrize("query", ["since=last-tuesday", "until=2026-13-01",
                                   "since=2026-W45", "until=2026-02-30"])
def test_a_date_that_is_not_a_calendar_date_is_a_400_and_no_rows(browser, query):
    answer = browser.get(f"/journal?{query}")
    assert answer.status_code == 400 and '<div class="flash bad">' in main_of(answer)
    assert "<code>petr</code>" not in main_of(answer)


# --- every item opens the journal filtered to itself ---------------------------------

@pytest.mark.parametrize("page, target, back", [
    ("/domains/{sales}", "sales", "Domains"),
    ("/people/{olga}", "olga", "People"),
    ("/mailboxes/{olga_sales}", "olga@sales", "Mailboxes"),
    ("/external/{free_external}", "shop@example.org", "External mailboxes"),
])
def test_every_item_opens_the_journal_by_the_spelling_its_rows_are_written_with(
        browser, ids, database, page, target, back):
    database.sql("INSERT INTO audit (actor, action, target) VALUES (%s, 'set_password', %s), "
                 "(%s, 'set_password', 'someone-else')", (ADMIN, target, ADMIN))
    links = re.findall(r'href="(/journal\?target=[^"]+)"', main_of(browser.get(page.format(**ids))))
    assert links, page
    journal_page = main_of(browser.get(links[0].replace("&amp;", "&")))
    rows = journal_page.split("<tbody>", 1)[1]
    assert f"<code>{target}</code>" in rows and "someone-else" not in rows
    assert f"Back to {back}" in journal_page


@pytest.mark.parametrize("back", ["https://elsewhere.example", "not_a_section", "sign_in", ""])
def test_a_way_back_that_is_not_a_section_makes_no_crumb(browser, back):
    page = main_of(browser.get(f"/journal?target=olga&back={back}"))
    assert "Back to" not in page and "elsewhere" not in page


def test_every_act_journals_a_declared_name_and_queues_a_kind_the_schema_allows(
        browser, ids, database):
    from maildivvy.admin import journal as acts

    long = "an-archive-password-that-is-long"
    for path, form in (
            ("/domains/add", {"label": "north", "password": long, "password2": long}),
            ("/domains/{sales}/spam", {"threshold": "9"}),
            ("/domains/{sales}/outbound", {"outbound_unscanned": "refuse"}),
            ("/domains/{sales}/archive/password", {"password": long, "password2": long}),
            ("/domains/{sales}/delete", {}),
            ("/people/add", {"login": "anna", "password": long, "password2": long}),
            ("/people/{olga}/password", {"password": long, "password2": long}),
            ("/people/{olga}/admin", {"is_admin": "on"}),
            ("/people/{olga}/admin", {}),
            ("/people/{petr}/state", {"state": "active"}),
            ("/people/{ivan}/delete", {}),
            ("/mailboxes/add", {"domain_id": "{sales}", "account_id": "{ivan}"}),
            ("/mailboxes/{olga_sales}/transfer", {"to_account_id": "{admin}"}),
            ("/mailboxes/{olga_sales}/top-up", {"choice": "all"}),
            ("/mailboxes/{olga_sales}/deliver-one", {"message_id": "{delivered}"}),
            ("/mailboxes/{petr_sales}/delete", {}),
            ("/external/{office_external}/settings", {"protocol": "imap",
                                                      "keep_at_provider": "yes",
                                                      "pop3_login": "o", "smtp_login": "s",
                                                      "credential": "c", "window": "20"}),
            ("/external/add", {"address": "desk@example.org", "pop3_host": "pop.example.org",
                               "pop3_port": "995", "smtp_host": "smtp.example.org",
                               "smtp_port": "587", "window": "14", "domain_choice": "new",
                               "label": "desk", "password": long, "password2": long}),
            ("/external/{office_external}/servers", {"pop3_host": "pop.example.org",
                                                     "pop3_port": "995",
                                                     "smtp_host": "smtp.example.net",
                                                     "smtp_port": "587"}),
            ("/external/{office_external}/check", {}),
            ("/external/{office_external}/enable", {}),
            ("/external/{free_external}/disable", {}),
            ("/fetch/{free_external}/resume", {}),
            ("/external/{office_external}/delete", {"branch": "delete-the-domain-too"}),
            ("/withheld/{withheld}/release", {})):
        answer = browser.post(path.format(**ids),
                              {name: value.format(**ids) for name, value in form.items()})
        assert answer.status_code == 303, (path, answer.status_code)
    browser.get("/")
    # enabled, as the pipeline enables it: over IMAP since its settings above, with the
    # starting point in its INBOX the activation sets, which a snapshot needs
    database.sql("UPDATE external_mailbox SET state = 'active', imap_uidvalidity = 7, "
                 "imap_last_uid = 3 WHERE id = %s", (ids["office_external"],))
    for path in ("/fetch/{office_external}/refetch", "/external/{office_external}/snapshot",
                 "/external/{office_external}/snapshot/discard"):
        assert browser.post(path.format(**ids)).status_code == 303, path
    journaled = {row[1] for row in journal_rows(database)}
    queued = {row[0] for row in requests(database)}
    assert journaled <= acts.DECLARED and queued <= set(acts.PIPELINE_ACTS)
    # every kind the pipeline performs was asked by some act, and every act of the
    # interface's own was journaled but the break-glass sign-in's
    assert queued == set(acts.PIPELINE_ACTS)
    assert set(acts.INTERFACE_ACTS) - journaled == {"break_glass_use"}



# ================================================================================================
# With the database stood in (admin_stand_in.py): what a screen renders for the rows it is handed.
# ================================================================================================

# --- withheld and the journal, in the design's components ---------------------------------


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
            '</svg> asked to release, 2026-09-30 14:58 UTC</span>') in asked
    assert '<span class="row-sub">the pipeline runs by 2026-09-30 15:01 UTC</span>' in asked
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


@pytest.mark.parametrize("screen, key, statement", [
    (mailboxes, "mailbox_id", "BOXES"), (accounts, "account_id", "PEOPLE"),
    (external, "external_mailbox_id", "ROW")])
def test_a_lists_request_lookups_name_every_kind_the_pipeline_performs_on_its_row(
        screen, key, statement):
    """A list finds a row's requests by kind and target, so `request_kind_target_idx`
    finds them instead of a walk along the whole queue; a kind missing from its list
    would hide that kind's waiting or failed request from the row.

    ⚠️ Kept as text on purpose: which kinds act on a row is the pipeline's handlers'
    code (the payload key each reads), and the lookup's shape is what lets the index
    serve it. Neither is a behaviour the interface shows on its own."""
    import inspect

    from maildivvy.fanout import requests as pipeline

    per_row = {kind for kind, handler in pipeline.HANDLERS.items()
               if f'"{key}"' in inspect.getsource(handler)}
    assert per_row == set(screen.KINDS)
    lookups = getattr(screen, statement).split("FROM request r WHERE")[1:]
    assert lookups
    for lookup in lookups:
        where = lookup.split(" AS ", 1)[0]
        assert "r.kind" in where and "r.target = " in where, where


def test_the_withheld_list_is_capped_and_its_older_rows_stay_reachable(withheld_pages,
                                                                      monkeypatch):
    client, sent = withheld_pages
    status, html = main_part(client, "/withheld")
    assert status == 200 and "before=" not in html and '<div class="flash' not in html
    assert sent[-1][0].endswith(" LIMIT %s")

    monkeypatch.setattr(moderation, "LIMIT", 2)
    status, html = main_part(client, "/withheld")
    assert status == 200
    # one more than the page shows is asked for, so the cap is known, not guessed
    assert sent[-1][1] == (3,)
    body = html.split("<tbody>", 1)[1]
    assert "a parcel for you" in body and "asked already" in body
    assert "tried once" not in body
    flash = html.split('<div class="flash attn">', 1)[1].split("</div></div>", 1)[0]
    assert "Only the newest 2 withheld messages are shown." in flash
    assert html.index('<div class="flash attn">') < html.index("<table")
    assert ('<div class="actions"><a class="btn" href="/withheld?before=8">'
            'Older messages</a></div>') in html

    # the next page starts after the last row shown and offers the way back
    status, html = main_part(client, "/withheld?before=8")
    assert status == 200 and sent[-1][1] == (8, 3)
    body = html.split("<tbody>", 1)[1]
    assert "tried once" in body and "asked already" not in body
    assert "before=" not in html and '<div class="flash' not in html
    assert ('<div class="crumbs"><a href="/withheld"><svg class="icon"><use href="#i-back"/>'
            '</svg> Newest withheld messages</a></div>') in html

    # a later page with nothing on it says so, not that nothing at all is withheld
    status, html = main_part(client, "/withheld?before=9")
    assert status == 200 and moderation.NO_OLDER in html
    assert "Nothing is withheld." not in html
    status, html = main_part(client, "/withheld?before=0")
    assert status == 200 and moderation.NO_OLDER in html
    # a `before` that is no row id is the first page
    status, html = main_part(client, "/withheld?before=x")
    assert status == 200 and sent[-1][1] == (3,)


# --- every act the screens write is a declared one ------------------------------


def test_the_domains_outbound_setting_has_a_declared_act_of_its_own():
    assert "set_outbound_unscanned" in journal.INTERFACE_ACTS


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


def test_the_cap_and_the_empty_result_each_have_their_own_sentence():
    assert events.NOTHING == "No journal row matches this filter."
    assert str(journal.LIMIT) in events.CAPPED.format(limit=journal.LIMIT)
    assert "Narrow the filter" in events.CAPPED
    assert "append-only and outlives what it describes" in events.OUTLIVES
    assert "Break-glass" in events.PAGE


def test_the_row_carries_the_outcome_of_the_request_it_asked_for():
    assert "request_state" in events.PAGE and "request_id" in events.PAGE
    assert "r.state AS request_state" in journal.SELECT
