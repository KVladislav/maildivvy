"""The interface with the database stood in: what the markup tests share.

These tests read what a screen renders for rows it is handed: a state that is hard to
seed (a waiting request, a refused credential, a failed pass), the shell's markup, a
template's own shapes. `common.one` and `common.rows` are stood in, per world, by
the statement's first words. What the database itself decides - grants, transactions,
the session - is proved on the real one (`admin_db.py`). The fixtures here are made
visible to every test module by `conftest.py`.
"""

import datetime
import json
import sys
import types
from decimal import Decimal
import pytest
from flask import Flask
from maildivvy.admin import app as application
from maildivvy.admin import auth, journal
from maildivvy.admin.screens import (accounts, common, domains, events, external, fetch,
                                     health, mailboxes, maintenance, moderation, overview)


UTC = datetime.timezone.utc


def at(text):
    """A moment as the database hands it: a `timestamptz`, never a string."""
    return datetime.datetime.fromisoformat(text).replace(tzinfo=UTC)


SCREENS = (overview, domains, external, fetch, accounts, mailboxes, moderation,
           maintenance, events, health)


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


# Every act the interface offers, by endpoint. What was left out on purpose (admin
#) is in no list: no skip or un-skip button, no password
# reveal, no per-mailbox schedule, state or copy of outgoing mail, no journal cleanup, no
# bulk undelete, no retention setting. A new act is added here on purpose or not at all.
ACTS = {
    "sign_in", "sign_out",
    "add_domain", "archive_password", "domain_spam", "domain_outbound", "delete_domain",
    "add_external", "external_settings", "external_servers", "external_check",
    "external_enable", "external_disable", "delete_external_mailbox",
    "external_snapshot", "discard_snapshot",
    "refetch", "resume_fetch",
    "add_account", "account_password", "account_admin", "account_state", "account_comment",
    "delete_account",
    "add_mailbox", "transfer_mailbox", "top_up", "deliver_one_message", "delete_mailbox",
    "release_message",
}


COUNTS = {"external": 3, "domains": 2, "people": 4, "mailboxes": 6, "withheld": 1}


@pytest.fixture
def shell(tmp_path, monkeypatch):
    """The application's rules and shell, signed in, with the five counts stood in for
    the database; health's report is missing, so the header says "no report"."""
    made = Flask("maildivvy-test")
    application.register(made)
    for screen in SCREENS:
        screen.register(made)
    application.guard_every_endpoint(made)
    made.config.update(MAILDIVVY_HEALTH_REPORT=tmp_path / "health.json",
                       MAILDIVVY_HEALTH_CONF=tmp_path / "health.conf",
                       MAILDIVVY_HEALTH_TIMER=tmp_path / "health.timer")
    monkeypatch.setattr(application, "current_identity", lambda: auth.Identity("t28admin", 1))
    monkeypatch.setattr(application, "connection", lambda: None)
    monkeypatch.setattr(application, "counts", lambda conn: dict(COUNTS))
    return made.test_client()


def page_of(client, path):
    """The page after its head: the stylesheet's selectors are not markup."""
    return client.get(path).get_data(as_text=True).split("</head>", 1)[1]


# what `shape` imports from `common.SHAPES` for the template it is handed
SHAPE_NAMES = "csrf, flash, refused, pipeline_failed, pipeline_flash, field, danger_zone, setting"


def shape(built, template, **values):
    """A template calling the shared shapes, importing them as a screen's template does."""
    with built.test_request_context("/"):
        return built.jinja_env.from_string(
            '{%- from "common.SHAPES" import ' + SHAPE_NAMES + " %}" + template).render(**values)


DOMAIN = {"id": 1, "label": "sales", "spam_threshold": Decimal("8.00"),
          "spam_reaches_people": True, "outbound_unscanned": "send", "external_id": None,
          "external_address": None, "external_state": None, "mailboxes": 2, "messages": 1204,
          "newest": at("2026-09-30 14:31"), "waiting": False, "asked_at": None}


OCCUPIED = dict(DOMAIN, id=2, label="office", external_id=9,
                external_address="office@example.org", external_state="deactivated")


NOTHING_ASKED = {"waiting": None, "look_again": None, "failed": None}


def a_box(**changed):
    box = {"kind": "person", "id": 5, "address": "ivan@sales", "login": "ivan",
           "account_id": 3, "account_state": "active", "comment": None, "domain_id": 1,
           "label": "sales", "as_of": None, "total": 12, "reading": dict(NOTHING_ASKED)}
    return {**box, **changed}


ARCHIVE_BOX = a_box(kind="archive", id=None, address="archive@sales", login=None,
                    account_id=None, account_state=None, total=1204)


MESSAGES = [
    {"id": 58120, "received_at": at("2026-09-30 14:31"),
     "message_date": at("2026-09-30 14:30"),
     "sender": "orders@example.org", "subject": "Order confirmed", "state": "delivered",
     "is_spam": False, "spam_score": Decimal("1.2"), "archive_uid": 1},
    {"id": 58116, "received_at": at("2026-09-30 09:44"), "message_date": None,
     "sender": "bounce@example.org", "subject": "Returned", "state": "delivered",
     "is_spam": True, "spam_score": None, "archive_uid": 2},
]


@pytest.fixture
def domains_world(shell, monkeypatch):
    """The shell with two domains stood in for the database: `sales` free, `office` with
    a disabled external mailbox in front of it; `sales` holds its archive and two people."""
    known = {1: DOMAIN, 2: OCCUPIED}

    def one(conn, sql, parameters=()):
        if sql == domains.NUMBERS:
            return {"messages": 1204, "mailboxes": 2, "people": 1}
        if sql.startswith(domains.LIST):
            found = known.get(parameters[0])
            return dict(found) if found else None
        return None

    def rows(conn, sql, parameters=()):
        if sql.startswith(domains.LIST):
            return [dict(OCCUPIED), dict(DOMAIN)]
        if sql == domains.LISTING:
            return [dict(message) for message in MESSAGES]
        return []

    boxes = [ARCHIVE_BOX, a_box(),
             a_box(id=6, address="olga@sales", login="olga", account_id=4,
                   account_state="blocked", total=3)]
    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(mailboxes, "listing", lambda conn, domain_id=None, period=None:
                        [dict(box) for box in boxes] if domain_id == 1 else [])
    return shell


@pytest.fixture
def waiting_world(domains_world, monkeypatch):
    """The domains, with the creation of `sales` asked for and not performed yet."""
    waiting = dict(DOMAIN, waiting=True, asked_at=datetime.datetime(2026, 9, 30, 14, 58))
    real = common.one
    monkeypatch.setattr(common, "one", lambda conn, sql, parameters=():
                        dict(waiting) if sql.startswith(domains.LIST)
                        else real(conn, sql, parameters))
    return domains_world


ASKED_AT = datetime.datetime(2026, 9, 30, 14, 58)


def a_person(**changed):
    person = {"id": 3, "login": "ivan", "is_admin": False, "state": "active",
              "comment": "covers sales", "created_at": None, "mailboxes": 1,
              "state_at": None, "state_by": None, "admin_since": None, "newest_kind": None,
              "newest_state": None, "newest_created_at": None, "newest_result": None}
    return {**person, **changed}


PEOPLE = {1: a_person(id=1, login="t28admin", is_admin=True, comment=None,
                      admin_since=at("2026-09-01 10:00")),
          3: a_person(),
          4: a_person(id=4, login="olga", state="blocked", comment=None, mailboxes=0,
                      state_at=at("2026-09-07 09:00"), state_by="t28admin"),
          5: a_person(id=5, login="petro", comment=None, newest_kind="delete_account",
                      newest_state="queued", newest_created_at=ASKED_AT),
          6: a_person(id=6, login="zoya", comment=None, newest_kind="delete_account",
                      newest_state="failed", newest_result="no such <maildir>")}


class Cursor:
    """A cursor that takes every statement and answers the one `RETURNING id` with 3."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, parameters=()):
        pass

    def fetchone(self):
        return (3,)


class Connection:
    def cursor(self):
        return Cursor()


@pytest.fixture
def people_world(shell, monkeypatch):
    """The shell with five people stood in for the database: the signed-in administrator
    (1), `ivan` holding one mailbox (3), `olga` blocked (4), `petro` whose deletion waits
    (5) and `zoya` whose deletion failed (6). Nothing is written anywhere."""

    def one(conn, sql, parameters=()):
        if sql == accounts.NUMBERS:
            return {"mailboxes": 1, "names": 12}
        if sql.startswith(accounts.PEOPLE):
            found = PEOPLE.get(parameters[0])
            return dict(found) if found else None
        return None

    def rows(conn, sql, parameters=()):
        if sql.startswith(accounts.PEOPLE):
            return [dict(PEOPLE[key]) for key in (4, 5, 1, 3, 6)]
        return []

    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(mailboxes, "of_account", lambda conn, account_id, period=None:
                        [a_box()] if account_id == 3 else [])
    monkeypatch.setattr(accounts, "machine_name", lambda etc=None: "mail.example.org")
    monkeypatch.setattr(accounts, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(application, "connection", lambda: Connection())
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    return shell


def setting_row(html, action):
    return html.split(f'<form class="setting" method="post" action="{action}">',
                      1)[1].split("</form>", 1)[0]


@pytest.fixture
def boxes_world(shell, monkeypatch):
    """The shell with `sales` and its three rows stood in for the database: its archive,
    `ivan@sales` (5) and `olga@sales` blocked (6); `petro` is free to take a transfer. The
    top-up counts one message in any range and two in all of it. Nothing is written."""

    def one(conn, sql, parameters=()):
        if sql == mailboxes.REMOVAL:
            return {"names": 12}
        if "FROM domain WHERE id" in sql:
            return {"yes": 1, "label": "sales"} if parameters[0] == 1 else None
        if "FROM account WHERE id" in sql:
            return {"login": "petro"} if parameters[0] == 7 else None
        return None

    def rows(conn, sql, parameters=()):
        if sql == mailboxes.ALL_DOMAINS:
            return [{"id": 1, "label": "sales"}]
        if sql in (mailboxes.FREE_PEOPLE, mailboxes.EVERYONE):
            return [{"id": 7, "login": "petro"}]
        return []

    listed = [ARCHIVE_BOX, a_box(),
              a_box(id=6, address="olga@sales", login="olga", account_id=4,
                    account_state="blocked", total=3)]
    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(mailboxes, "listing", lambda conn, domain_id=None, period=None:
                        [dict(box) for box in listed])
    monkeypatch.setattr(mailboxes, "box_row", lambda conn, mailbox_id, period=None:
                        a_box(as_of=at("2026-08-30 10:00")) if mailbox_id == 5 else None)
    monkeypatch.setattr(mailboxes, "free_people", lambda conn, domain_id, without=None:
                        [{"id": 7, "login": "petro"}])
    monkeypatch.setattr(maintenance, "count", lambda conn, box, since, until:
                        2 if since == maintenance.WIDE_SINCE else 1)
    monkeypatch.setattr(application, "connection", lambda: Connection())
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    return shell


class DatabaseError(Exception):
    """psycopg2's shape: the base of every error the server raised."""


class IntegrityError(DatabaseError):
    """psycopg2's shape: the class `unique_violation` catches, carrying its SQLSTATE, its
    text and the name of the constraint it broke."""

    def __init__(self, pgcode, text=None, constraint=None):
        super().__init__(text or f"SQLSTATE {pgcode}")
        self.pgcode = pgcode
        self.diag = types.SimpleNamespace(constraint_name=constraint)


@pytest.fixture
def driver(monkeypatch):
    """psycopg2 as `unique_violation` and the application's error page import it; the unit
    suite runs without the driver."""
    monkeypatch.setitem(sys.modules, "psycopg2",
                        types.SimpleNamespace(IntegrityError=IntegrityError,
                                              Error=DatabaseError))


class GoneCursor(Cursor):
    """The pipeline deleted the person between the screen's check and its INSERT."""

    def execute(self, sql, parameters=()):
        if sql.startswith("INSERT"):
            raise IntegrityError("23503")             # foreign_key_violation


class GoneConnection:
    def cursor(self):
        return GoneCursor()


FETCHED_AT = datetime.datetime(2026, 9, 30, 14, 33)


def an_external(**changed):
    mailbox = {
        "id": 9, "address": "Box@example.org", "address_canonical": "box@example.org",
        "protocol": "pop3", "pop3_login": "recent:box", "pop3_host": "pop.example.org", "pop3_port": 995,
        "smtp_host": "smtp.example.org", "smtp_port": 587, "delete_window_days": 14,
        "smtp_login": None, "keep_at_provider": False, "pop3_cert_fingerprint": None,
        "smtp_cert_fingerprint": None, "comment": "the sales mailbox", "state": "active",
        "state_changed_at": at("2026-09-02 10:00"), "state_changed_by": "t28admin",
        "last_fetch_at": FETCHED_AT, "last_fetch_status": "auth_failed",
        "last_fetch_cause": None, "last_fetch_detail": None,
        "last_test_at": at("2026-09-30 09:12"), "last_test_status": "auth_failed",
        "last_test_detail": None, "stuck_since": None, "stuck_runs": 0, "skip_streak": 0,
        "frozen_since": at("2026-09-30 11:40"), "last_skip_at": None,
        "last_skip_uidl": None,
        "held_since": None, "domain_id": 1, "label": "sales", "checking": False,
        "enabling": False, "deleting": False, "enable_asked_at": None, "newest_kind": None,
        "newest_state": None, "newest_created_at": None, "newest_result": None,
        "imap_uidvalidity": None, "imap_last_uid": None, "snapshot_requested_at": None,
        "snapshot_started_at": None, "snapshot_finished_at": None, "snapshot_status": None,
        "snapshot_detail": None, "snapshot_paused_since": None, "snapshot_refused": None,
        "snapshot_left_out": None, "discarding": False}
    return {**mailbox, **changed}


EXTERNALS = {
    9: an_external(),
    10: an_external(id=10, address="asked@example.org", address_canonical="asked@example.org",
                    comment=None, state="deactivated", state_changed_at=None,
                    state_changed_by=None, last_fetch_at=None, last_fetch_status=None,
                    last_test_at=None, last_test_status=None, frozen_since=None,
                    domain_id=None, label=None, enabling=True, enable_asked_at=ASKED_AT,
                    newest_kind="activate_external_mailbox", newest_state="queued",
                    newest_created_at=ASKED_AT),
    11: an_external(id=11, address="off@example.org", address_canonical="off@example.org",
                    comment=None, state="deactivated", state_changed_at=at("2026-08-30 08:03"),
                    last_fetch_status=None, last_test_at=None, last_test_status=None,
                    frozen_since=None, domain_id=3, label="events",
                    newest_kind="test_credential", newest_state="failed",
                    newest_result="no <answer>"),
    12: an_external(id=12, address="ok@example.org", address_canonical="ok@example.org",
                    comment=None, last_fetch_status="ok", last_test_status="ok",
                    frozen_since=None, domain_id=2, label="office"),
}


@pytest.fixture
def external_world(shell, monkeypatch):
    """The shell with four provider mailboxes stood in for the database: `Box@example.org`
    (9) enabled, refused and frozen in front of `sales`; `asked@example.org` (10) asked to
    enable, in front of nothing; `off@example.org` (11) disabled, its last check failed at
    the pipeline; `ok@example.org` (12) enabled and fetching. One free domain, `hr`, for
    the add form. Nothing is written anywhere."""

    def one(conn, sql, parameters=()):
        if sql == domains.NUMBERS:
            return {"messages": 1204, "mailboxes": 2, "people": 1}
        return None

    def rows(conn, sql, parameters=()):
        if sql == external.FREE_DOMAINS:
            return [{"id": 4, "label": "hr"}]
        if sql.startswith(external.ROW) and "WHERE e.id" in sql:
            found = EXTERNALS.get(parameters[0])
            return [dict(found)] if found else []
        if sql.startswith(external.ROW):
            return [dict(EXTERNALS[key]) for key in (10, 9, 11, 12)]
        return []

    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(common, "timer_period", lambda: THREE)
    monkeypatch.setattr(fetch, "timer_period", lambda: THREE)
    monkeypatch.setattr(application, "connection", lambda: Connection())
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    return shell


def row_of(html, address):
    return html.split(f"<code>{address}</code></a>", 1)[1].split("</tr>", 1)[0]


def an_addition(**changed):
    typed = {"address": "new@example.org", "pop3_login": "", "credential": "",
             "pop3_host": "pop.example.org", "pop3_port": "995",
             "smtp_host": "smtp.example.org", "smtp_port": "587", "window": "14",
             "comment": "", "domain_choice": "", "domain_id": "", "label": "",
             "password": "", "password2": ""}
    return {**typed, **changed}


CANARY = "Zq7-canary-provider-password"


# what PostgreSQL said when a C1 control reached the column's CHECK, the canary
# standing where the measured password stood
FAILING_ROW = ('new row for relation "external_mailbox" violates check constraint '
               '"external_mailbox_address_canonical_check"\nDETAIL:  Failing row contains '
               f'(id, address, credential) = (13, t28box@t28.example.org, {CANARY}).')


class Recorder:
    """The database a free-domain addition writes to, every statement and its values in
    order; `refuse` names a statement start that raises what the server raised."""

    def __init__(self, refuse=None, pgcode="23514"):
        self.said, self.refuse, self.pgcode = [], refuse, pgcode

    def cursor(self):
        return RecorderCursor(self)


class RecorderCursor(Cursor):
    def __init__(self, recorder):
        self.recorder, self.answer = recorder, None

    def execute(self, sql, parameters=()):
        self.recorder.said.append((sql, tuple(parameters or ())))
        if self.recorder.refuse and sql.startswith(self.recorder.refuse):
            raise IntegrityError(self.recorder.pgcode, FAILING_ROW,
                                 "external_mailbox_address_canonical_check")
        self.answer = (("hr",) if "RETURNING label" in sql else
                       (3,) if "RETURNING id" in sql else None)

    def fetchone(self):
        return self.answer


def free_domain(conn, sql, parameters=()):
    """`common.one` for an addition in front of the free domain `hr` (4)."""
    if sql.startswith("SELECT 1 AS yes FROM domain WHERE id"):
        return {"yes": 1}
    return None


@pytest.fixture
def check_world(external_world, driver, monkeypatch):
    """The external screens over a database whose INSERT of a provider mailbox breaks a
    CHECK, as a C1 control did before the screen refused it."""
    monkeypatch.setattr(common, "one", free_domain)
    monkeypatch.setattr(application, "connection",
                        lambda: Recorder(refuse="INSERT INTO external_mailbox"))
    return external_world


PIN = ":".join(["AB", "01"] * 16)


def smtp_pin_field(html):
    return html.split('<label for="smtp_cert_fingerprint">', 1)[1].split("</div>", 1)[0]


class Queue:
    """The request table, and every statement said to it in order. It answers the three
    statements a queued act makes - the lock, the look for a pending one, the INSERT -
    and takes any other (a route's own UPDATE, a journal row) without answering."""

    def __init__(self):
        self.requests = []
        self.said = []

    def cursor(self):
        return QueueCursor(self)


class QueueCursor(Cursor):
    def __init__(self, queue):
        self.queue = queue
        self.answer = None

    def execute(self, sql, parameters=()):
        self.queue.said.append(sql)
        self.answer = None
        if sql.startswith("SELECT id FROM request"):
            kind, target, same = parameters
            same = json.loads(same).items()
            self.answer = next(((row["id"],) for row in self.queue.requests
                                if (row["kind"], row["target"]) == (kind, target)
                                and same <= row["payload"].items()
                                and row["state"] in ("queued", "running")), None)
        elif sql.startswith("INSERT INTO request"):
            kind, target, payload = parameters[:3]
            self.queue.requests.append({"id": len(self.queue.requests) + 1, "kind": kind,
                                        "target": target, "payload": json.loads(payload),
                                        "state": "queued"})
            self.answer = (len(self.queue.requests),)

    def fetchone(self):
        return self.answer


OTHER_PIN = ":".join(["CD", "02"] * 16)


SERVERS = {"pop3_host": "pop.example.org", "pop3_port": "995",
           "smtp_host": "smtp.example.org", "smtp_port": "587"}


ARRIVED = datetime.datetime(2026, 9, 30, 12, 14)


def a_withheld(**changed):
    message = {"id": 7, "received_at": ARRIVED, "sender": "stranger@example.org",
               "subject": "a parcel for you", "is_spam": True, "spam_score": 9.5,
               "domain_id": 1, "label": "sales", "why": "Held back: a parcel for you",
               "newest_kind": None, "newest_state": None, "newest_created_at": None,
               "newest_result": None}
    return {**message, **changed}


WITHHELD = [
    a_withheld(),
    a_withheld(id=8, subject="asked already", newest_kind="release",
               newest_state="queued", newest_created_at=ASKED_AT),
    a_withheld(id=9, subject="tried once", sender=None, why=None, newest_kind="release",
               newest_state="failed", newest_result="no <quarantine>"),
]


def a_journal_row(**changed):
    row = {"id": 1, "at": at("2026-09-30 14:12"), "actor": "t28admin",
           "action": "set_account_state", "target": "ivan", "detail": {"after": "blocked"},
           "request_id": None, "request_state": None, "request_result": None,
           "break_glass": False}
    return {**row, **changed}


@pytest.fixture
def journal_world(shell, monkeypatch):
    """The shell with three withheld messages stood in for the database (7 as it arrived,
    8 whose release waits, 9 whose release failed) and two journal rows, one of which
    asked the pipeline for something that failed. Nothing is written anywhere."""

    def one(conn, sql, parameters=()):
        if sql.startswith("SELECT id, state FROM message"):
            return {"id": parameters[0], "state": "delivered"}
        return None

    def rows(conn, sql, parameters=()):
        if sql.startswith(moderation.LIST):
            return [dict(row) for row in WITHHELD]
        return []

    def journal_rows(conn, **filters):
        return [a_journal_row(),
                a_journal_row(id=2, action="delete_account", request_id=5,
                              request_state="failed", request_result="no <b>account</b>",
                              break_glass=True)]

    monkeypatch.setattr(common, "one", one)
    monkeypatch.setattr(common, "rows", rows)
    monkeypatch.setattr(common, "timer_period", lambda: THREE)
    monkeypatch.setattr(journal, "rows", journal_rows)
    monkeypatch.setattr(application, "csrf_refusal", lambda: None)
    return shell


def subject_row(html, subject):
    return next(row for row in html.split("<tr>") if f"<td>{subject}</td>" in row)


@pytest.fixture
def withheld_pages(journal_world, monkeypatch):
    """The withheld list read the way the database would: newest first from where the
    page starts, at most as many rows as the statement asks for. Each statement sent is
    kept."""
    sent = []

    def rows(conn, sql, parameters=()):
        sent.append((sql, parameters))
        found = [dict(row) for row in WITHHELD]
        if moderation.OLDER in sql:
            ids = [row["id"] for row in found]
            found = (found[ids.index(parameters[0]) + 1:] if parameters[0] in ids else [])
        return found[:parameters[-1]]

    monkeypatch.setattr(common, "rows", rows)
    return journal_world, sent


class HoldersCursor(Cursor):
    """Two active administrators, whatever is counted."""

    def fetchall(self):
        return [(1,), (2,)]


class HoldersConnection:
    def cursor(self):
        return HoldersCursor()


@pytest.fixture
def signed_out():
    """The application as a stranger meets it: no session stood in, the real guard."""
    made = Flask("maildivvy-test")
    application.register(made)
    for screen in SCREENS:
        screen.register(made)
    application.guard_every_endpoint(made)
    made.config.update(MAILDIVVY_SECRET=b"a-secret")
    return made.test_client()


POLICY = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
          "frame-ancestors 'none'; base-uri 'none'")


def row(**columns):
    empty = {name: None for name in (
        "id", "address", "address_canonical", "comment", "state", "domain_id", "label",
        "last_fetch_at", "last_fetch_status", "last_fetch_cause", "last_fetch_detail",
        "last_test_at", "last_test_status", "last_test_detail", "stuck_since",
        "stuck_runs", "skip_streak", "frozen_since", "last_skip_at", "last_skip_uidl",
        "held_since", "delete_window_days", "checking", "enabling", "deleting")}
    empty.update({"state": "active", "delete_window_days": 14, "keep_at_provider": False,
                  "protocol": "pop3", "stuck_runs": 0, "checking": False, "enabling": False,
                  "deleting": False})
    empty.update(columns)
    return empty


ASKED = datetime.datetime(2026, 9, 22, 14, 58, tzinfo=datetime.timezone.utc)


THREE = datetime.timedelta(minutes=3)


def worry_row(**columns):
    empty = {"id": 1, "address": "box@example.org", "address_canonical": "box@example.org",
             "state": "active", "frozen_since": None, "last_fetch_status": None,
             "last_test_status": None, "last_skip_at": None, "last_skip_uidl": None,
             "delete_window_days": 14, "keep_at_provider": False, "label": "sales"}
    empty.update(columns)
    return empty
