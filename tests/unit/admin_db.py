"""The administration interface against the throwaway PostgreSQL: a browser and a scene.

The application is made by `create_app`, the way the machine makes it, from an
`/etc/maildivvy` of the test's own: `admin/db.conf` and its passfile name the role
`maildivvy_admin`, so every statement a screen runs meets the schema's real grants, and
`admin/secret` is the session key. Nothing in the application is stood in.

`Browser` is the Flask test client the way a browser uses the interface over the proxy:
over `https://` (the cookie is `Secure`), with the interface's own `Origin` on every
POST, and with the CSRF token the last page it read carried in its forms.

`scene` writes, as the superuser, what an installed machine with some history holds:
two domains, people, mailboxes, external mailboxes, messages, requests and journal rows.
"""

import functools
import json
import re
import threading
import time

import pytest

from maildivvy.admin import app as application
import postgres
from maildivvy.admin import auth, throttle
from maildivvy.admin.screens import common

ORIGIN = "https://mail.example.org"
ADMIN = "t28admin"
PASSWORD = "the-administrators-own-password"
TOKEN = re.compile(r'name="_csrf" value="([^"]+)"')


@functools.cache
def hashed(password):
    """`{SHA512-CRYPT}` of a password, made once per run: `openssl` is a process each."""
    return auth.make_hash(password)


def text(answer):
    return answer.get_data(as_text=True)


def main_of(answer):
    """The page's `main`, where a screen's own words are, without the shell around it."""
    html = text(answer)
    return html.split("<main>", 1)[1].split("</main>", 1)[0] if "<main>" in html else html


class Browser:
    def __init__(self, app):
        self.app = app
        self.client = app.test_client()
        self.token = None

    def keep(self, answer):
        found = TOKEN.search(text(answer))
        if found:
            self.token = found.group(1)
        return answer

    def get(self, path, **kwargs):
        return self.keep(self.client.get(path, base_url=ORIGIN, **kwargs))

    def post(self, path, data=None, csrf=True, origin=ORIGIN, headers=None):
        form = dict(data or {})
        if csrf and self.token:
            form[application.CSRF_FIELD] = self.token
        sent = {"Origin": origin} if origin else {}
        return self.keep(self.client.post(path, data=form, base_url=ORIGIN,
                                          headers={**sent, **(headers or {})}))

    def sign_in(self, login=ADMIN, password=PASSWORD, **extra):
        return self.post("/sign-in", {"login": login, "password": password, **extra},
                         csrf=False)

    def cookie(self):
        found = self.client.get_cookie(auth.COOKIE, domain="mail.example.org")
        return found.value if found else None


def make_app(database, tmp_path):
    """The application `create_app` makes from the test's own `/etc/maildivvy`."""
    secret = database.etc / "admin" / "secret"
    secret.write_text("a-session-key-for-one-test-only\n")
    secret.chmod(0o600)
    made = application.create_app(etc=database.etc)
    # health's report and timer are files of the machine; here they are absent, so the
    # header says there is no report, as on a machine before health's first run
    made.config.update(MAILDIVVY_HEALTH_REPORT=tmp_path / "health.json",
                       MAILDIVVY_HEALTH_CONF=tmp_path / "health.conf",
                       MAILDIVVY_HEALTH_TIMER=tmp_path / "health.timer")
    return made


def add_person(database, login, password=PASSWORD, is_admin=False, state="active",
               comment=None):
    return database.value(
        "INSERT INTO account (login, password_hash, is_admin, state, comment) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING id",
        (login, hashed(password), is_admin, state, comment))


def scene(database):
    """A machine with some history, written as the superuser; the ids by name."""
    ids = {}
    sql = database.value
    ids["admin"] = add_person(database, ADMIN, is_admin=True)
    ids["olga"] = add_person(database, "olga", comment="front desk")
    ids["petr"] = add_person(database, "petr", state="blocked")
    ids["ivan"] = add_person(database, "ivan")
    ids["office_external"] = sql(
        "INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host, "
        "credential, state, last_fetch_at, last_fetch_status) VALUES "
        "('office@example.org', 'office@example.org', 'pop.example.org', "
        "'smtp.example.org', 'provider-secret', 'deactivated', now() - interval '1 hour', 'ok') "
        "RETURNING id")
    ids["free_external"] = sql(
        "INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host, "
        "state, last_fetch_status, last_fetch_cause, last_fetch_detail, frozen_since) "
        "VALUES ('Shop@Example.org', 'shop@example.org', 'pop.example.org', "
        "'smtp.example.org', 'active', 'error', 'stuck_message', 'a message <b>stuck</b>', "
        "now() - interval '2 days') RETURNING id")
    ids["sales"] = sql("INSERT INTO domain (label, archive_password_hash) VALUES "
                       "('sales', %s) RETURNING id", (hashed("an-archive-password"),))
    ids["office"] = sql("INSERT INTO domain (label, archive_password_hash, external_mailbox_id) "
                        "VALUES ('office', %s, %s) RETURNING id",
                        (hashed("an-archive-password"), ids["office_external"]))
    ids["olga_sales"] = sql("INSERT INTO mailbox (account_id, domain_id) VALUES (%s, %s) "
                            "RETURNING id", (ids["olga"], ids["sales"]))
    ids["petr_sales"] = sql("INSERT INTO mailbox (account_id, domain_id) VALUES (%s, %s) "
                            "RETURNING id", (ids["petr"], ids["sales"]))
    ids["delivered"] = sql(
        "INSERT INTO message (domain_id, message_id_header, archive_uid, sender, subject, "
        "message_date) VALUES (%s, '<one@example.org>', 1, 'anna@example.org', "
        "'Quarterly figures', '2026-11-02 09:15+00') RETURNING id", (ids["sales"],))
    ids["withheld"] = sql(
        "INSERT INTO message (domain_id, message_id_header, archive_uid, state, withheld_id, "
        "sender, subject, is_spam, spam_score) VALUES (%s, '<two@example.org>', 2, "
        "'withheld', 'w-2', 'spam@example.net', 'You <i>won</i>', true, 12.5) RETURNING id",
        (ids["sales"],))
    database.sql("INSERT INTO delivery (message_id, mailbox_id, state, linked_at) "
                 "VALUES (%s, %s, 'linked', now())", (ids["delivered"], ids["olga_sales"]))
    ids["failed_request"] = sql(
        "INSERT INTO request (kind, target, payload, asked_by, state, result, finished_at) "
        "VALUES ('create_mailbox', 'petr', '{}'::jsonb, %s, 'failed', "
        "'the maildir <could not> be made', now()) RETURNING id", (ADMIN,))
    database.sql("INSERT INTO audit (actor, action, target, detail, request_id) VALUES "
                 "(%s, 'create_mailbox', 'petr', '{\"domain\": \"sales\"}', %s)",
                 (ADMIN, ids["failed_request"]))
    return ids


def left_by_deletion(database, kind, target, gone, state="failed"):
    """A deletion whose rows committed and whose directories were not all removed: its
    `gone` list on its own row, as the pipeline writes it (no request is inserted with one,
    migration 0010). Returns the request's id."""
    request_id = database.value(
        "INSERT INTO request (kind, target, payload, asked_by, state) VALUES "
        "(%s, %s, '{}'::jsonb, %s, 'running') RETURNING id", (kind, target, ADMIN))
    database.sql("UPDATE request SET state = %s, payload = payload || %s WHERE id = %s",
                 (state, json.dumps({"gone": gone}), request_id))
    return request_id


def counts(database):
    """How many rows the tables an act may write hold: what a refused act leaves alone."""
    return dict(database.sql(
        "SELECT 'request', count(*) FROM request UNION ALL "
        "SELECT 'audit', count(*) FROM audit UNION ALL "
        "SELECT 'domain', count(*) FROM domain UNION ALL "
        "SELECT 'account', count(*) FROM account UNION ALL "
        "SELECT 'mailbox', count(*) FROM mailbox UNION ALL "
        "SELECT 'external_mailbox', count(*) FROM external_mailbox"))


def journal_rows(database, action=None):
    """The journal rows, oldest first, as (actor, action, target, detail)."""
    where, parameters = ("WHERE action = %s", (action,)) if action else ("", ())
    return database.sql(f"SELECT actor, action, target, detail FROM audit {where} ORDER BY id",
                        parameters)


def requests(database, kind=None):
    """The queued requests, oldest first, as (kind, target, payload, asked_by, state)."""
    where, parameters = ("WHERE kind = %s", (kind,)) if kind else ("", ())
    return database.sql(f"SELECT kind, target, payload, asked_by, state FROM request {where} "
                        "ORDER BY id", parameters)


@pytest.fixture
def ids(database):
    return scene(database)


@pytest.fixture(scope="session")
def made_once(cluster, tmp_path_factory):
    """The application `create_app` makes, once per run: compiling its routes is most
    of what making one costs. Each test points it at its own database (`app_db`)."""
    etc = tmp_path_factory.mktemp("etc")
    postgres.write_consumer(etc, "admin", postgres.CONSUMERS["admin"], "unused",
                            cluster.root, postgres.DB_NAME)
    secret = etc / "admin" / "secret"
    secret.write_text("a-session-key-for-the-unit-tier\n")
    secret.chmod(0o600)
    return application.create_app(etc=etc)


@pytest.fixture
def app_db(made_once, database, tmp_path):
    """The application on this test's database, with a throttle and health files of its
    own. A test that adds routes makes its own with `make_app`."""
    made_once.config.update(MAILDIVVY_ETC=database.etc, MAILDIVVY_THROTTLE=throttle.Throttle(),
                            MAILDIVVY_HEALTH_REPORT=tmp_path / "health.json",
                            MAILDIVVY_HEALTH_CONF=tmp_path / "health.conf",
                            MAILDIVVY_HEALTH_TIMER=tmp_path / "health.timer")
    made_once.config.pop("MAILDIVVY_HEALTH_NOW", None)
    return made_once


@pytest.fixture
def browser(app_db, ids):
    """The scene, and an administrator signed in through the sign-in form, holding the
    session's CSRF token: the one every form of every page carries, which
    `test_every_post_form_a_signed_in_page_serves_carries_the_sessions_token` proves.
    It is read off the cookie here, so a test pays for no page it did not ask for."""
    made = Browser(app_db)
    assert made.sign_in().status_code == 303
    secret = app_db.config["MAILDIVVY_SECRET"]
    made.token = auth.csrf_token(secret, auth.unsign(secret, made.cookie()))
    return made


def redirected(answer, path, key=None):
    """True when an act answered 303 to `path`, saying `key`, which must be one of the
    closed list's: a key that is not says nothing on the next screen."""
    assert key is None or key in common.DONE, f"{key!r} is not in common.DONE"
    want = f"{path}?done={key}" if key else path
    return answer.status_code == 303 and answer.headers["Location"] == want


def waiting_on_a_lock(database, count, timeout=10.0):
    """Wait until `count` of the interface's connections wait on a lock; False on timeout.

    A request started in a thread has reached the statement under test exactly when its
    connection waits, so a race is arranged by the database's own state, not by a sleep.
    """
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if database.value("SELECT count(*) FROM pg_stat_activity WHERE usename = "
                          "'maildivvy_admin' AND wait_event_type = 'Lock'") >= count:
            return True
        time.sleep(0.01)
    return False


def in_threads(*calls):
    """Start each call in a thread; `join()` gives back their results in order."""
    results = [None] * len(calls)

    def run(index, call):
        results[index] = call()

    threads = [threading.Thread(target=run, args=(index, call), daemon=True)
               for index, call in enumerate(calls)]
    for thread in threads:
        thread.start()

    def join():
        for thread in threads:
            thread.join(timeout=30)
            assert not thread.is_alive(), "a request never came back"
        return results

    return join


def competitor(database):
    """A second connection, as the superuser, whose transaction stays open until it
    commits or rolls back: the other side of a race."""
    conn = database.cluster.superuser(database.name).conn
    conn.autocommit = False
    return conn


def verifies(stored, password):
    """True when a stored `{SHA512-CRYPT}` hash is the hash of `password`."""
    return auth.verify_password(password, stored)
