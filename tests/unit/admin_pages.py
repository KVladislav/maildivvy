"""What every screen's tests share: the design's rules read off a page, and the sweep.

`SWEPT` is every page a signed-in person can open, and `REFUSALS` every refused form,
each opened on the real database (`admin_db.py`) in one of the states `open_state`
makes. `test_admin_shell.py` sweeps both through `keeps_the_designs_rules`, and
`test_every_get_route_is_swept` keeps `SWEPT` whole against the application's own map:
a new GET route joins `SWEPT`, and a new refused form `REFUSALS`.

A path is formatted with the scene's ids (`{sales}` is the id of the domain `sales`).
"""

import re
from html.parser import HTMLParser

from admin_db import ADMIN, Browser, left_by_deletion
from maildivvy.admin import auth, validate
from test_admin_health import MIXED as HEALTH_MIXED
from test_admin_health import NOW as HEALTH_NOW
from test_admin_health import write as write_report


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


MOMENT = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d UTC")


# --- the states a page is swept in ---------------------------------------------------------

def busy(database, ids, app):
    """Every voice the overview and the header have: health's report with all four
    states, a refused provider password held back, a request waiting and one failed."""
    write_report(app.config["MAILDIVVY_HEALTH_REPORT"], HEALTH_MIXED)
    app.config["MAILDIVVY_HEALTH_TIMER"].write_text("[Timer]\nOnCalendar=*:0/5\n")
    app.config["MAILDIVVY_HEALTH_NOW"] = HEALTH_NOW
    ids["held_external"] = database.value(
        "INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host, "
        "state, last_fetch_at, last_fetch_status, last_test_at, last_test_status, "
        "last_test_detail, held_since, last_skip_at, last_skip_uidl, stuck_since, stuck_runs) "
        "VALUES ('held@example.org', 'held@example.org', 'pop.example.org', "
        "'smtp.example.org', 'active', now(), 'auth_failed', now(), 'auth_failed', "
        "'-ERR [AUTH] <refused>', now(), now() - interval '1 day', 'uidl-7', now(), 2) "
        "RETURNING id")
    database.sql("INSERT INTO request (kind, target, payload, asked_by) VALUES "
                 "('create_mailbox', 'ivan@sales', '{}'::jsonb, %s)", (ADMIN,))
    database.sql("INSERT INTO request (kind, target, payload, asked_by, state, result, "
                 "finished_at) VALUES ('top_up', 'olga@sales', '{}'::jsonb, %s, 'failed', "
                 "'no mailbox 4', now())", (ADMIN,))


def open_state(state, app, database, ids, monkeypatch):
    """A browser signed in on the scene in one of the sweep's states:

    - `plain`: the scene alone, and no health report yet;
    - `busy`: every worry there once (`busy`);
    - `break_glass`: busy, signed in with the break-glass account;
    - `waiting`: the creation of `sales` asked for and not performed yet;
    - `gone`: deletions whose directories are not all removed yet: `ivan@sales`'s
      mailbox, and the domain `north` with its archive and `ivan`'s mailbox there;
    - `unforeseen`: a form's own check lets through a window the column refuses, as a
      validator gone wrong would;
    - `imap`: mailboxes collected over IMAP, in front of no domain: `imap_on`
      enabled and `imap_off` disabled, neither with a starting point in its INBOX; and
      three enabled ones with their snapshots, `imap_snap` with none, `imap_paused`
      with one paused and `imap_failed` with one failed.
    """
    login, password = ADMIN, "the-administrators-own-password"
    if state in ("busy", "break_glass"):
        busy(database, ids, app)
    if state == "break_glass":
        login, password = auth.BREAK_GLASS_LOGIN, "break-the-glass"
        database.sql("INSERT INTO break_glass (password_hash) VALUES (%s)",
                     (auth.make_hash(password)[len(auth.PREFIX):],))
    if state == "waiting":
        database.sql("INSERT INTO request (kind, target, payload, asked_by) VALUES "
                     "('create_domain', 'sales', %s, %s)",
                     (f'{{"domain_id": {ids["sales"]}}}', ADMIN))
    if state == "gone":
        left_by_deletion(database, "delete_mailbox", "ivan@sales", [["sales", "ivan"]])
        left_by_deletion(database, "delete_domain", "north",
                         [["north", "ivan"], ["north", "archive"], ["north", None]])
    if state == "unforeseen":
        monkeypatch.setattr(validate, "window", lambda typed: 0)
    if state == "imap":
        for name, address, active in (("imap_on", "inbox@example.net", "active"),
                                      ("imap_off", "spare@example.net", "deactivated")):
            ids[name] = database.value(
                "INSERT INTO external_mailbox (address, address_canonical, protocol, "
                "pop3_host, pop3_port, smtp_host, keep_at_provider, state) VALUES "
                "(%s, %s, 'imap', 'imap.example.net', 993, 'smtp.example.net', true, %s) "
                "RETURNING id", (address, address, active))
        for name, address, status, detail in (
                ("imap_snap", "snap@example.net", None, None),
                ("imap_paused", "paused@example.net", "paused",
                 "1 of 3 folders taken, 40 messages, 81920 bytes; the provider did not answer"),
                ("imap_failed", "failed@example.net", "failed",
                 "the provider renumbered the <INBOX>; 0 of 3 folders taken")):
            ids[name] = database.value(
                "INSERT INTO external_mailbox (address, address_canonical, protocol, pop3_host, "
                "pop3_port, smtp_host, keep_at_provider, state, imap_uidvalidity, imap_last_uid, "
                "snapshot_requested_at, snapshot_started_at, snapshot_finished_at, "
                "snapshot_status, snapshot_detail, snapshot_paused_since) VALUES "
                "(%s, %s, 'imap', 'imap.example.net', 993, 'smtp.example.net', true, 'active', "
                "7, 3, CASE WHEN %s::text IS NOT NULL THEN now() - interval '3 days' END, "
                "CASE WHEN %s::text IS NOT NULL THEN now() - interval '2 days' END, "
                "CASE WHEN %s = 'failed' THEN now() END, %s, %s, "
                "CASE WHEN %s = 'paused' THEN now() - interval '1 day' END) RETURNING id",
                (address, address, status, status, status, status, detail, status))
    browser = Browser(app)
    assert browser.sign_in(login, password).status_code == 303
    assert browser.get("/").status_code == 200
    return browser


# Every page a signed-in person can open, in the state that seeds it, with the status it
# answers. A new GET route joins it.
SWEPT = [
    ("busy", "/", 200), ("busy", "/health", 200), ("busy", "/health?done=domain_created", 200),
    ("busy", "/no-such-page", 404), ("plain", "/", 200), ("plain", "/health", 200),
    ("break_glass", "/", 200), ("break_glass", "/no-such-page", 404),
    ("plain", "/domains", 200), ("plain", "/domains/{sales}", 200),
    ("plain", "/domains/{office}", 200), ("plain", "/domains/add", 200),
    ("plain", "/domains/{sales}/delete", 200), ("plain", "/domains/{office}/delete", 400),
    ("plain", "/domains/{sales}/spam", 200), ("plain", "/domains/{sales}/archive", 200),
    ("plain", "/domains/{sales}/archive/listing", 200),
    ("plain", "/domains/{sales}/archive/listing?q=anna&until=2026-12-01", 200),
    ("plain", "/domains/{sales}/archive/listing?before={delivered}", 200),
    ("plain", "/domains/{sales}/archive/listing?until=nope", 400),
    ("waiting", "/domains/{sales}", 200), ("waiting", "/domains/{sales}/archive", 200),
    ("waiting", "/domains/{sales}/archive/listing", 400),
    ("busy", "/people", 200), ("plain", "/people/{admin}", 200),
    ("plain", "/people/{olga}", 200), ("plain", "/people/{petr}", 200),
    ("busy", "/people/{ivan}", 200), ("plain", "/people/add", 200),
    ("plain", "/people/{olga}/delete", 200), ("plain", "/people/{admin}/delete", 400),
    ("busy", "/mailboxes", 200), ("plain", "/mailboxes/{olga_sales}", 200),
    ("plain", "/mailboxes/{petr_sales}", 200), ("plain", "/mailboxes/add", 200),
    ("plain", "/mailboxes/add?domain={sales}", 200),
    ("plain", "/mailboxes/{olga_sales}/delete", 200),
    ("plain", "/mailboxes/{olga_sales}/top-up", 200),
    ("plain", "/mailboxes/{olga_sales}/top-up?since=nope", 400),
    ("busy", "/external", 200), ("plain", "/external/{office_external}", 200),
    ("plain", "/external/{free_external}", 200), ("busy", "/external/{held_external}", 200),
    ("plain", "/external/add", 200), ("plain", "/external/{office_external}/delete", 200),
    ("plain", "/external/{free_external}/delete", 200), ("busy", "/fetch", 200),
    ("imap", "/external", 200), ("imap", "/external/{imap_on}", 200),
    ("imap", "/external/{imap_off}", 200), ("imap", "/fetch", 200),
    # the snapshot of every folder: none, paused and failed, and its discard
    ("imap", "/external/{imap_snap}", 200), ("imap", "/external/{imap_paused}", 200),
    ("imap", "/external/{imap_failed}", 200),
    ("imap", "/external/{imap_failed}/snapshot/discard", 200),
    ("imap", "/external/{imap_snap}/snapshot/discard", 400),
    ("plain", "/withheld", 200), ("plain", "/withheld?before={withheld}", 200),
    ("busy", "/journal", 200), ("plain", "/journal?since=last-tuesday", 400),
]

# The refused forms: each is its screen again, at 400, with the refusal on it, and
# nothing written. A new refused form joins it.
LONG = "an-archive-password-that-is-long"
SERVERS = {"pop3_host": "pop.example.org", "pop3_port": "995",
           "smtp_host": "smtp.example.org", "smtp_port": "587"}
REFUSALS = [
    ("plain", "/domains/add", {"label": "NOT A LABEL", "password": LONG, "password2": LONG}),
    ("plain", "/domains/{sales}/outbound", {"outbound_unscanned": "whatever"}),
    ("plain", "/domains/{sales}/spam", {"threshold": "999"}),
    ("plain", "/domains/{sales}/archive/password", {"password": LONG, "password2": "other"}),
    ("plain", "/people/add", {"login": "no such login!", "password": "a-long-enough-password",
                              "password2": "a-long-enough-password"}),
    ("plain", "/people/{olga}/password", {"password": "a-long-enough-password",
                                          "password2": "another-one-typed"}),
    ("plain", "/people/{admin}/admin", {}),
    ("plain", "/people/{olga}/state", {"state": "sleepy"}),
    ("plain", "/mailboxes/add", {"domain_id": "999999", "account_id": "{ivan}"}),
    ("plain", "/mailboxes/{olga_sales}/deliver-one", {"message_id": "the third one"}),
    ("plain", "/mailboxes/{olga_sales}/transfer", {"to_account_id": ""}),
    ("plain", "/mailboxes/{olga_sales}/top-up", {"since": "2026-02-30", "until": "2026-03-01"}),
    ("plain", "/external/add", {"address": "new@example.org", **SERVERS, "window": "nope",
                                "domain_choice": "free", "domain_id": "{sales}"}),
    ("plain", "/external/{office_external}/servers", {**SERVERS, "pop3_port": ""}),
    # a label ending in a line break, which `$` let through to the column's CHECK, and an
    # address with two `@` or an empty host label
    ("plain", "/external/{office_external}/servers", {**SERVERS,
                                                      "pop3_host": "pop\n.example.org"}),
    ("plain", "/external/add", {"address": "a@b@c.d", **SERVERS, "window": "14",
                                "domain_choice": "free", "domain_id": "{sales}"}),
    ("plain", "/external/add", {"address": "x@.", **SERVERS, "window": "14",
                                "domain_choice": "free", "domain_id": "{sales}"}),
    ("plain", "/external/{office_external}/settings", {"pop3_login": "re cent",
                                                       "window": "14"}),
    # collection over IMAP: the protocol changed on an enabled mailbox, an IMAP
    # mailbox that does not keep its mail, and a protocol that is neither
    ("imap", "/external/{imap_on}/settings", {"protocol": "pop3", "keep_at_provider": "yes"}),
    ("imap", "/external/{imap_off}/settings", {"protocol": "imap", "window": "14"}),
    ("plain", "/external/{office_external}/settings", {"protocol": "imap", "window": "14"}),
    ("plain", "/external/{office_external}/settings", {"protocol": "smtp", "window": "14"}),
    ("plain", "/external/add", {"address": "new@example.org", "protocol": "imap", **SERVERS,
                                "window": "14", "domain_choice": "free",
                                "domain_id": "{sales}"}),
    # a snapshot asked of a POP3 mailbox, of a disabled one, of one with no starting
    # point in its INBOX and of one whose snapshot failed; and a discard with none there
    ("plain", "/external/{office_external}/snapshot", {}),
    ("imap", "/external/{imap_off}/snapshot", {}),
    ("imap", "/external/{imap_on}/snapshot", {}),
    ("imap", "/external/{imap_failed}/snapshot", {}),
    ("imap", "/external/{imap_snap}/snapshot/discard", {}),
    # a CHECK the screen's own validation let through
    ("unforeseen", "/external/add", {"address": "new@example.org", "credential": "secret",
                                     **SERVERS, "window": "14", "domain_choice": "free",
                                     "domain_id": "{sales}"}),
    # a slot a deletion has not cleared yet: a mailbox given, a transfer's
    # destination, a domain, and an external mailbox's new domain
    ("gone", "/mailboxes/add", {"domain_id": "{sales}", "account_id": "{ivan}"}),
    ("gone", "/mailboxes/{olga_sales}/transfer", {"to_account_id": "{ivan}"}),
    ("gone", "/domains/add", {"label": "north", "password": LONG, "password2": LONG}),
    ("gone", "/external/add", {"address": "new@example.org", **SERVERS, "window": "14",
                               "domain_choice": "new", "label": "north", "password": LONG,
                               "password2": LONG}),
    ("plain", "/fetch/{office_external}/refetch", {}),
    ("plain", "/withheld/{delivered}/release", {}),
]

# The numeric fields the refused forms carry, typed past the 4300 digits `int()` reads.
NUMERIC = {"domain_id", "account_id", "message_id", "to_account_id", "pop3_port",
           "smtp_port", "window", "threshold"}
