"""The people screens: the list, a person, their password, flag, state, comment and
deletion, and the last administrator who always stays.

The acts run against the real schema as `maildivvy_admin` (`admin_db.py`), and each is
read back from the rows it wrote, or did not.
"""

import re

import pytest

from admin_db import (ADMIN, PASSWORD, add_person, counts, journal_rows, main_of, redirected,
                      requests, text, verifies)
from maildivvy.admin.screens import accounts
from maildivvy.admin import auth
from admin_pages import main_part, page_head
from admin_stand_in import setting_row

TYPED = "a-long-enough-password"


def stored(database, login):
    return database.value("SELECT password_hash FROM account WHERE login = %s", (login,))


@pytest.mark.parametrize("flag", [False, True])
def test_adding_a_person_hashes_what_was_typed_and_journals_that_a_password_was_set(
        browser, database, flag, caplog):
    caplog.set_level("DEBUG")
    form = {"login": "anna.k", "password": TYPED, "password2": TYPED}
    if flag:
        form["is_admin"] = "on"
    assert redirected(browser.post("/people/add", form), "/people", "account_created")
    assert verifies(stored(database, "anna.k"), TYPED)
    assert database.value("SELECT is_admin FROM account WHERE login = 'anna.k'") is flag
    assert journal_rows(database, "create_account") == [
        (ADMIN, "create_account", "anna.k", {"is_admin": flag, "password_generated": False})]
    assert TYPED not in str(database.sql("SELECT detail FROM audit"))
    # nor in anything logged while it was made
    assert TYPED not in caplog.text


def test_both_fields_empty_generates_a_password_shown_once_in_the_posts_own_answer(
        browser, database):
    # the machine's published name, as the installation writes it
    (database.etc / accounts.CERTIFICATE).write_text('{"cert_name": "mail.example.org"}')
    answer = browser.post("/people/add", {"login": "boris", "password": "", "password2": ""})
    assert answer.status_code == 200
    assert answer.headers["Cache-Control"] == "no-store, max-age=0"
    shown = re.findall(r"<code class=\"generated\">([^<]*)</code>", main_of(answer))
    assert len(shown) == 1 and len(shown[0]) >= 20 and not set(shown[0]) & set("lI1O0")
    assert verifies(stored(database, "boris"), shown[0])
    # with the client settings it is typed into: the machine's ports, over implicit TLS
    settings = main_of(answer)
    assert "<code>mail.example.org</code>, ports\n<code>993</code> and <code>465</code>, " \
        "implicit TLS" in settings
    assert journal_rows(database, "create_account")[0][3] == {"is_admin": False,
                                                         "password_generated": True}
    # it is never shown again: the person's own page holds no password
    person = database.value("SELECT id FROM account WHERE login = 'boris'")
    assert shown[0] not in text(browser.get(f"/people/{person}"))


@pytest.mark.parametrize("form", [
    {"login": "olga", "password": TYPED, "password2": TYPED},        # taken
    {"login": "Olga", "password": TYPED, "password2": TYPED},        # taken, folded (0095)
    {"login": "archive", "password": TYPED, "password2": TYPED},     # reserved
    {"login": "break-glass", "password": TYPED, "password2": TYPED},
    {"login": "anna", "password": TYPED, "password2": TYPED + "!"},
    {"login": "anna", "password": TYPED, "password2": ""},
    {"login": "anna", "password": "short", "password2": "short"},
    {"login": "anna", "password": "x" * 257, "password2": "x" * 257},
])
def test_a_refused_person_is_the_form_again_at_400_and_writes_nothing(browser, database,
                                                                      form):
    before = counts(database)
    answer = browser.post("/people/add", form)
    assert answer.status_code == 400 and '<div class="flash bad">' in main_of(answer)
    assert f'value="{form["login"]}"' in main_of(answer)
    assert TYPED not in main_of(answer)
    assert counts(database) == before


def test_a_persons_password_is_set_on_their_page_and_ends_their_sessions(browser, ids,
                                                                         database):
    path = f"/people/{ids['olga']}"
    assert browser.post(f"{path}/password", {"password": TYPED, "password2": "x"}) \
        .status_code == 400
    assert verifies(stored(database, "olga"), PASSWORD)
    answer = browser.post(f"{path}/password", {"password": TYPED, "password2": TYPED})
    assert redirected(answer, path, "password_set")
    assert verifies(stored(database, "olga"), TYPED)
    assert journal_rows(database, "set_password") == [
        (ADMIN, "set_password", "olga", {"password_set": True, "password_generated": False})]
    # the saved sentence stands inside the password row, not above the page
    landed = main_of(browser.get(answer.headers["Location"]))
    assert landed.count("Password set.") == 1


def test_the_flag_is_granted_and_revoked_and_an_unchanged_one_writes_nothing(
        browser, ids, database):
    path = f"/people/{ids['olga']}"
    assert redirected(browser.post(f"{path}/admin", {"is_admin": "on"}), path, "admin_saved")
    assert redirected(browser.post(f"{path}/admin", {"is_admin": "on"}), path, "admin_same")
    assert redirected(browser.post(f"{path}/admin", {}), path, "admin_saved")
    assert [row[1:] for row in journal_rows(database) if row[1].endswith("_admin")] == [
        ("grant_admin", "olga", {"is_admin": True}), ("revoke_admin", "olga", {"is_admin": False})]


@pytest.mark.parametrize("act, form", [("admin", {}), ("state", {"state": "blocked"})])
def test_the_last_active_administrator_cannot_lose_the_flag_or_be_blocked(
        browser, ids, database, act, form):
    before = counts(database)
    answer = browser.post(f"/people/{ids['admin']}/{act}", form)
    assert answer.status_code == 400
    assert "is the last active administrator" in main_of(answer)
    assert counts(database) == before
    assert database.one("SELECT is_admin, state FROM account WHERE id = %s",
                        (ids["admin"],)) == (True, "active")
    # with a second active administrator, the same act is done
    add_person(database, "second", is_admin=True)
    assert redirected(browser.post(f"/people/{ids['admin']}/{act}", form),
                      f"/people/{ids['admin']}", "admin_saved" if act == "admin" else "state_set")


def test_a_person_is_blocked_and_unblocked_and_there_is_no_third_state(browser, ids,
                                                                       database):
    path = f"/people/{ids['olga']}"
    assert redirected(browser.post(f"{path}/state", {"state": "blocked"}), path, "state_set")
    assert redirected(browser.post(f"{path}/state", {"state": "active"}), path, "state_set")
    assert [row[3] for row in journal_rows(database, "set_account_state")] == [
        {"before": "active", "after": "blocked"}, {"before": "blocked", "after": "active"}]
    answer = browser.post(f"{path}/state", {"state": "sleepy"})
    assert answer.status_code == 400 and "&#39;sleepy&#39; is neither" in main_of(answer)
    assert len(journal_rows(database, "set_account_state")) == 2


def test_a_comment_is_saved_from_the_page_it_was_sent_from_and_never_journaled(
        browser, ids, database):
    before = len(journal_rows(database))
    answer = browser.post(f"/people/{ids['olga']}/comment", {"comment": "moved to <b>sales</b>"})
    assert redirected(answer, f"/people/{ids['olga']}", "comment_saved")
    card = f"/mailboxes/{ids['olga_sales']}"
    answer = browser.post(f"/people/{ids['olga']}/comment", {"comment": ""},
                          headers={"Referer": f"https://mail.example.org{card}?done=x"})
    assert redirected(answer, card, "comment_saved")
    assert database.value("SELECT comment FROM account WHERE id = %s", (ids["olga"],)) is None
    # the two places are the person page and every card of a mailbox they hold
    for page in (f"/people/{ids['olga']}", card):
        assert f'action="/people/{ids["olga"]}/comment"' in main_of(browser.get(page)), page
    assert len(journal_rows(database)) == before


def test_a_persons_deletion_states_its_numbers_and_is_asked_once(browser, ids, database):
    page = browser.get(f"/people/{ids['olga']}/delete")
    assert page.status_code == 200 and "danger-zone" in main_of(page)
    assert redirected(browser.post(f"/people/{ids['olga']}/delete"), "/people",
                      "account_deletion_asked")
    assert requests(database, "delete_account") == [
        ("delete_account", "olga", {"account_id": ids["olga"]}, ADMIN, "queued")]
    assert redirected(browser.post(f"/people/{ids['olga']}/delete"), "/people", "already_asked")
    assert database.value("SELECT count(*) FROM account WHERE id = %s", (ids["olga"],)) == 1


def test_nobody_deletes_their_own_account(browser, ids, database):
    add_person(database, "second", is_admin=True)
    before = counts(database)
    answer = browser.post(f"/people/{ids['admin']}/delete")
    assert answer.status_code == 400 and accounts.NOT_YOURSELF[:40] in main_of(answer)
    assert counts(database) == before


def test_the_list_and_a_person_page_read_the_real_rows(browser, ids):
    listing = main_of(browser.get("/people"))
    for login in (ADMIN, "olga", "petr", "ivan"):
        assert login in listing
    assert "front desk" in listing
    page = main_of(browser.get(f"/people/{ids['olga']}"))
    assert "olga@sales" in page and "front desk" in page
    assert browser.get("/people/999999").status_code == 404


# --- the last administrator under two decisions at once -----------------------

def test_two_administrators_revoking_each_other_at_once_leave_one(app_db, ids, database):
    from admin_db import Browser, competitor, in_threads, waiting_on_a_lock
    from maildivvy.lib import adminlock

    other = add_person(database, "second", is_admin=True)
    first, second = Browser(app_db), Browser(app_db)
    for browser, login in ((first, ADMIN), (second, "second")):
        assert browser.sign_in(login).status_code == 303 and browser.get("/").status_code == 200
    # the lock held elsewhere, so both acts reach it and wait there together
    holder = competitor(database)
    holder.cursor().execute("SELECT pg_advisory_xact_lock(%s, %s)",
                            (adminlock.NAMESPACE, adminlock.KEY))
    join = in_threads(lambda: first.post(f"/people/{other}/admin", {}),
                      lambda: second.post(f"/people/{ids['admin']}/admin", {}))
    try:
        assert waiting_on_a_lock(database, 2)
    finally:
        holder.commit()
        holder.close()
    answers = sorted(answer.status_code for answer in join())
    # the second to take the lock counts what the first left, and finds itself the last
    assert answers == [303, 400]
    assert database.value("SELECT count(*) FROM account WHERE is_admin AND state = 'active'") == 1
    assert len([row for row in journal_rows(database) if row[1] == "revoke_admin"]) == 1


def test_an_administrator_whose_deletion_is_queued_counts_as_gone(browser, ids, database):
    other = add_person(database, "second", is_admin=True)
    database.sql("INSERT INTO request (kind, target, payload, asked_by) VALUES "
                 "('delete_account', 'second', %s, %s)", (f'{{"account_id": {other}}}', ADMIN))
    before = counts(database)
    answer = browser.post(f"/people/{ids['admin']}/state", {"state": "blocked"})
    assert answer.status_code == 400 and "is the last active administrator" in main_of(answer)
    assert counts(database) == before



# ================================================================================================
# With the database stood in (admin_stand_in.py): what a screen renders for the rows it is handed.
# ================================================================================================

# --- the people screens, in the design's components -----------------------------------


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
            '2026-09-07 09:00 UTC by <code>t28admin</code></span>') in olga
    petro = html.split("<code>petro</code>", 1)[1].split("</tr>", 1)[0]
    assert '<td class="state">asked to delete, 2026-09-30 14:58 UTC<span class="row-sub">' in petro
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
    assert ("<p class=\"lede\">Administrator since 2026-09-01 10:00 UTC. One password opens "
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
    assert ('<span class="badge attn">blocked</span> since 2026-09-07 09:00 UTC by '
            '<code>t28admin</code>.') in state
    assert '<button class="btn" type="submit">Unblock <code>olga</code></button>' in state


def test_a_waiting_or_failed_person_is_a_flash_under_the_head(people_world):
    _, html = main_part(people_world, "/people/5")
    assert ('<div class="flash attn"><svg class="icon attn ico"><use href="#i-clock"/></svg>'
            "<div>asked to delete, 2026-09-30 14:58 UTC.") in html
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
    status, html = main_part(people_world, "/people/add", "post", login="iv an",
                             password="a-long-enough-password",
                             password2="a-long-enough-password", is_admin="yes")
    assert status == 400
    flash = html.split('<div class="flash bad">', 1)[1].split("</div></div>", 1)[0]
    sentence = flash.split("<div>", 1)[1]
    login = html.split('<label for="login">', 1)[1].split('<label for="password">', 1)[0]
    assert f'<p class="help warn">{sentence}</p>' in login and 'value="iv an"' in login
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


# --- passwords: the length, the generated one, and what is never kept -------------------


def test_a_generated_password_is_long_and_has_no_look_alikes_in_it():
    from maildivvy.admin import validate

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


def test_the_machines_own_name_is_read_from_the_installation_and_never_spelt_here(tmp_path):
    (tmp_path / "certificate.json").write_text('{"cert_name": "mail.example.org"}')
    assert accounts.machine_name(tmp_path) == "mail.example.org"
    assert accounts.machine_name(tmp_path / "nowhere") is None
    assert "could not be read" in accounts.SETTINGS


# --- the last administrator stays --------------------------------------------------------


def test_the_refusals_say_what_they_refuse_and_why():
    said = accounts.LAST_ADMIN.format(login="ivan", act="Blocking them")
    assert "ivan is the last active administrator" in said
    assert "Break-glass is for the day the accounts table is unusable" in said
    assert "Nobody deletes their own account" in accounts.NOT_YOURSELF


def test_a_third_state_is_a_sentence_that_names_the_value():
    assert "'sleepy' is neither" in accounts.NO_THIRD.format(value="sleepy")
    assert "There is no third state" in accounts.NO_THIRD


def test_the_administrator_sentence_says_exactly_what_the_flag_grants():
    assert "reading any domain's archive" in accounts.GRANTS
    assert "keep it short" in accounts.GRANTS
    # the flag's checkbox says it, and both pages that offer the flag draw that checkbox
    assert "{{ grants }}" in accounts.SETTINGS.split("macro administrator", 1)[1]
    for template in (accounts.ADD_PAGE, accounts.PERSON_PAGE):
        assert "{{ administrator(" in template


def test_the_deletion_states_its_numbers_before_its_button(browser, ids):
    html = main_of(browser.get(f"/people/{ids['olga']}/delete"))
    numbers = re.findall(r"<div><b>(\d+)</b><span>([^<]+)</span></div>", html)
    assert [what for _, what in numbers] == ["Mailboxes removed", "Names removed"]
    assert "Messages removed: 0 &mdash; the archives keep everything." in html
    assert (html.index("Mailboxes removed") < html.index("btn-danger-solid")
            < html.rindex(f'<a href="/people/{ids["olga"]}">'))
    assert "Cancel, nothing changes</a>" in html
