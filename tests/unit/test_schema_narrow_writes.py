"""What the interface's role may write, the request rows nobody may insert, and the
ledger's one row per archive UID, on the unit tier's database.

Each refusal is tried as the role the programs connect as, with the control beside it:
what a screen or the pipeline writes still goes through.
"""

import pytest

from maildivvy.fanout import ledger

HASH = "{SHA512-CRYPT}$6$x$" + "x" * 86


def refused(database, conn, statement, parameters=(), error="InsufficientPrivilege"):
    """Run one statement on `conn`, which must refuse it with `error`; then roll back."""
    with pytest.raises(getattr(database.psycopg2.errors, error)), conn.cursor() as cursor:
        cursor.execute(statement, parameters)
    conn.rollback()


def run(conn, statement, parameters=()):
    with conn.cursor() as cursor:
        cursor.execute(statement, parameters)
        rows = cursor.fetchall() if cursor.description else []
    conn.commit()
    return rows


@pytest.fixture
def admin(database):
    conn = database.connect("admin")
    yield conn
    conn.close()


@pytest.fixture
def pipeline(database):
    conn = database.connect("pipeline")
    yield conn
    conn.close()


# --- the queue: asked for, never given a state; `gone` is the pipeline's own --------------------

def test_the_interface_asks_for_a_request_and_cannot_give_it_a_state_or_a_result(database, admin):
    asked = run(admin, "INSERT INTO request (kind, target, payload, asked_by, break_glass) "
                       "VALUES ('refetch', 'a@example.org', '{}', 'ivan', false) RETURNING state")
    assert asked == [("queued",)]   # the control: what every screen writes
    for column, value in (("state", "failed"), ("result", "done"), ("created_at", "2020-01-01"),
                          ("finished_at", "2020-01-01")):
        refused(database, admin, f"INSERT INTO request (kind, asked_by, {column}) "
                                 "VALUES ('refetch', 'ivan', %s)", (value,))


def test_no_role_inserts_a_request_carrying_a_list_of_directories_to_remove(database, admin, pipeline):
    gone = '{"gone": [["_snapshots", "7"]]}'
    refused(database, admin, "INSERT INTO request (kind, payload, asked_by) "
                             "VALUES ('delete_mailbox', %s, 'ivan')", (gone,), "RaiseException")
    # not the owner either, nor a scene set as the superuser: an inserted list is never the pipeline's
    with pytest.raises(database.psycopg2.errors.RaiseException):
        database.sql("INSERT INTO request (kind, payload, asked_by, state) "
                     "VALUES ('delete_mailbox', %s, 'ivan', 'failed')", (gone,))
    database.conn.rollback()
    # the control: the pipeline writes the list on a row it runs, by UPDATE (`LEAVE`)
    request_id = run(admin, "INSERT INTO request (kind, target, payload, asked_by) "
                            "VALUES ('delete_mailbox', 'ivan@alpha', '{}', 'ivan') RETURNING id")[0][0]
    run(pipeline, "UPDATE request SET payload = payload || jsonb_build_object('gone', %s::jsonb) "
                  "WHERE id = %s", ('[["alpha", "ivan"]]', request_id))
    assert database.value("SELECT payload -> 'gone' FROM request WHERE id = %s", (request_id,)) \
        == [["alpha", "ivan"]]


# --- the journal and the sessions ------------------------------------------------------------------

def test_the_interface_writes_a_journal_row_but_never_its_moment(database, admin):
    run(admin, "INSERT INTO audit (actor, action, target, detail, break_glass, request_id) "
               "VALUES ('ivan', 'refetch', 'a@example.org', '{}', false, NULL)")
    refused(database, admin, "INSERT INTO audit (at, actor, action) VALUES ('2020-01-01', 'ivan', 'refetch')")


def test_the_interface_opens_a_session_and_moves_its_last_seen_time_and_nothing_else(database, admin):
    run(admin, "INSERT INTO session (token_hash, account_id, break_glass) VALUES ('probe', NULL, true)")
    run(admin, "UPDATE session SET last_seen_at = now() WHERE token_hash = 'probe'")
    refused(database, admin, "UPDATE session SET created_at = now() + interval '1 day' "
                             "WHERE token_hash = 'probe'")
    refused(database, admin, "INSERT INTO session (token_hash, break_glass, created_at) "
                             "VALUES ('probe-2', true, now() + interval '1 day')")


# --- an external mailbox: deactivated, never activated or readdressed, by the interface -----------

@pytest.fixture
def mailbox(database):
    return database.value(
        "INSERT INTO external_mailbox (address, address_canonical, pop3_login, pop3_host, pop3_port, "
        "smtp_host, smtp_port, delete_window_days, state) VALUES ('a@example.org', 'a@example.org', "
        "'a', 'pop.example.org', 995, 'smtp.example.org', 465, 7, 'active') RETURNING id")


def test_the_interface_deactivates_an_external_mailbox_and_cannot_activate_or_readdress_it(
        database, admin, pipeline, mailbox):
    for column in ("address", "address_canonical"):
        refused(database, admin, f"UPDATE external_mailbox SET {column} = 'b@example.org' WHERE id = %s",
                (mailbox,))
    # the control: the screen's own statement
    run(admin, "UPDATE external_mailbox SET state = 'deactivated', state_changed_at = now(), "
               "state_changed_by = 'ivan' WHERE id = %s", (mailbox,))
    refused(database, admin, "UPDATE external_mailbox SET state = 'active' WHERE id = %s", (mailbox,),
            "RaiseException")
    # a save that leaves the state as it is passes; activation is the pipeline's request
    run(admin, "UPDATE external_mailbox SET state = state, comment = 'x' WHERE id = %s", (mailbox,))
    run(pipeline, "UPDATE external_mailbox SET state = 'active' WHERE id = %s", (mailbox,))
    assert database.value("SELECT state FROM external_mailbox WHERE id = %s", (mailbox,)) == "active"


@pytest.mark.parametrize("change, named", [
    ("GRANT INSERT (state) ON request TO maildivvy_admin", "maildivvy_admin can INSERT request.state"),
    ("REVOKE INSERT (payload) ON request FROM maildivvy_admin", "maildivvy_admin cannot INSERT request.payload"),
    ("GRANT UPDATE ON session TO maildivvy_admin", "maildivvy_admin can UPDATE session.created_at"),
    ("GRANT UPDATE (address_canonical) ON external_mailbox TO maildivvy_admin",
     "maildivvy_admin can UPDATE external_mailbox.address_canonical"),
    ("ALTER TABLE external_mailbox DISABLE TRIGGER external_mailbox_the_interface_only_deactivates",
     "external_mailbox_the_interface_only_deactivates is missing or disabled"),
])
def test_the_grant_check_reads_the_interfaces_narrow_writes_back(database, change, named):
    assert database.value("SELECT check_grants()") is True   # the control
    database.sql(change)
    with pytest.raises(database.psycopg2.errors.RaiseException, match=named):
        database.sql("SELECT check_grants()")
    database.conn.rollback()


# --- the ledger: one row per archive folder and UID -----------------------------------------------

@pytest.fixture
def domain(database):
    return database.value("INSERT INTO domain (label, archive_password_hash) VALUES ('alpha', %s) "
                          "RETURNING id", (HASH,))


def test_an_archive_uid_has_one_row_per_folder(database, pipeline, domain):
    record = "INSERT INTO message (domain_id, archive_uid, state) VALUES (%s, %s, %s)"
    run(pipeline, record, (domain, 7, "delivered"))
    run(pipeline, record, (domain, 7, "withheld"))      # the quarantine's 7 is another message
    run(pipeline, record, (domain, None, "delivered"))  # the Sent hook's rows hold none
    run(pipeline, record, (domain, None, "delivered"))
    refused(database, pipeline, record, (domain, 7, "delivered"), "UniqueViolation")
    refused(database, pipeline, record, (domain, 7, "released"), "UniqueViolation")
    run(pipeline, "UPDATE message SET state = 'released' WHERE archive_uid = 7 AND state = 'withheld'")


def test_a_folder_renumbered_with_its_numbers_swapped_is_given_them_by_base_name(
        database, pipeline, domain):
    record = ("INSERT INTO message (domain_id, archive_uid, archive_base, state) "
              "VALUES (%s, %s, %s, %s) RETURNING id")
    first, second, gone = (run(pipeline, record, (domain, uid, f"b{uid}", "delivered"))[0][0]
                           for uid in (1, 2, 3))
    held = run(pipeline, record, (domain, 1, "q1", "withheld"))[0][0]   # the quarantine's own 1
    refused(database, pipeline, "UPDATE message SET archive_uid = 2 WHERE id = %s", (first,),
            "UniqueViolation")
    with pipeline.cursor() as cur:
        # b1 and b2 swapped, b3 gone, and a file no row names numbered 3
        rowless, without_file = ledger.renumber_rows(cur, domain, ledger.INBOX,
                                                     [(1, "b2"), (2, "b1"), (3, "new")])
    pipeline.commit()
    assert (rowless, without_file) == ([3], 1)
    assert database.sql("SELECT id, archive_uid FROM message ORDER BY id") == [
        (first, 2), (second, 1), (gone, None), (held, 1)]


def test_an_archive_base_name_is_one_row_per_domain_and_the_window_looks_it_up(
        database, pipeline, domain):
    record = ("INSERT INTO message (domain_id, archive_uid, archive_base, state) "
              "VALUES (%s, %s, %s, %s) RETURNING id")
    inbox = run(pipeline, record, (domain, 3, "1757.M3.host,S=1,W=1", "delivered"))[0][0]
    held = run(pipeline, record, (domain, 3, "1757.M9.host,S=1,W=1", "withheld"))[0][0]
    run(pipeline, record, (domain, None, None, "delivered"))   # the Sent hook's rows hold none
    run(pipeline, record, (domain, None, None, "delivered"))
    refused(database, pipeline, record, (domain, 4, "1757.M3.host,S=1,W=1", "withheld"),
            "UniqueViolation")
    for wrong in ("1757.M3.host:2,S", "../1757.M3.host", ""):
        refused(database, pipeline, record, (domain, 5, wrong, "delivered"), "CheckViolation")
    found = run(pipeline, ledger.MESSAGES_BY_BASE, ("alpha", ["1757.M9.host,S=1,W=1", "nothing"]))
    assert found == [(held, "1757.M9.host,S=1,W=1")] and inbox != held
