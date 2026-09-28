"""The schema applier: which migrations it finds, the order and the transactions it
applies them in, the rules it holds every migration file to, and how it connects.

The database is a recording fake here; the applier against a real PostgreSQL is
proved on the test VM.
"""

import hashlib
import re
from pathlib import Path

import pytest

from maildivvy.lib import schema, store
from maildivvy.lib.schema import SchemaError

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "schema"
PROGRAM = ROOT / "bin" / "maildivvy-schema"


class Cursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows = []

    def execute(self, sql, params=None):
        self.conn.log.append(("execute", sql.strip(), params))
        if self.conn.fail_on and self.conn.fail_on in sql:
            raise RuntimeError(f"statement failed: {self.conn.fail_on}")
        if sql.strip().startswith("SELECT version FROM schema_version"):
            self.rows = [(v,) for v in sorted(self.conn.applied)]
        elif sql.strip().startswith("INSERT INTO schema_version"):
            self.conn.pending.add(params[0])

    def fetchall(self):
        return self.rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Connection:
    """Records every statement, commit and rollback; applied versions survive a commit only."""

    def __init__(self, applied=(), fail_on=None):
        self.applied = set(applied)
        self.pending = set()
        self.fail_on = fail_on
        self.log = []

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.applied |= self.pending
        self.pending = set()
        self.log.append(("commit",))

    def rollback(self):
        self.pending = set()
        self.log.append(("rollback",))

    def close(self):
        self.log.append(("close",))


def write(directory, files):
    directory.mkdir(exist_ok=True)
    for name, text in files.items():
        (directory / name).write_text(text)
    return directory


def transactions(conn):
    """The statements of each committed or rolled-back transaction, in order."""
    out, current = [], []
    for entry in conn.log:
        if entry[0] == "execute":
            current.append(entry[1])
        elif entry[0] in ("commit", "rollback"):
            out.append((entry[0], current))
            current = []
    return out


def test_migrations_are_found_in_name_order(tmp_path):
    d = write(tmp_path / "m", {"0010_later.sql": "SELECT 10;", "0002_second.sql": "SELECT 2;",
                               "0001_initial.sql": "SELECT 1;"})
    assert [m.version for m in schema.migrations(d)] == ["0001", "0002", "0010"]


def test_an_empty_migration_set_is_refused_never_reported_as_success(tmp_path):
    empty = tmp_path / "m"
    empty.mkdir()
    with pytest.raises(SchemaError, match="no migration"):
        schema.migrations(empty)
    with pytest.raises(SchemaError, match="no migration"):
        schema.apply(Connection(), empty)
    with pytest.raises(SchemaError, match="does not exist"):
        schema.migrations(tmp_path / "missing")


@pytest.mark.parametrize("name", ["001_short.sql", "0001-dash.sql", "0001_initial.SQL", "initial.sql",
                                  "0001_Upper.sql"])
def test_a_file_that_is_not_a_migration_name_is_refused_not_skipped(tmp_path, name):
    d = write(tmp_path / "m", {"0001_initial.sql": "SELECT 1;", name: "SELECT 2;"})
    with pytest.raises(SchemaError, match=re.escape(name)):
        schema.migrations(d)


def test_two_migrations_with_one_number_are_refused(tmp_path):
    d = write(tmp_path / "m", {"0001_initial.sql": "SELECT 1;", "0001_again.sql": "SELECT 2;"})
    with pytest.raises(SchemaError, match="0001"):
        schema.migrations(d)


def test_each_migration_is_one_transaction_together_with_its_version_row(tmp_path):
    d = write(tmp_path / "m", {"0001_initial.sql": "CREATE TABLE a ();", "0002_more.sql": "CREATE TABLE b ();"})
    conn = Connection()
    assert schema.apply(conn, d) == ["0001", "0002"]
    committed = [stmts for kind, stmts in transactions(conn) if kind == "commit"]
    # the first transaction makes the version table; then one per migration, file and row together
    assert committed[1:] == [
        ["CREATE TABLE a ();", "INSERT INTO schema_version (version, name) VALUES (%s, %s)"],
        ["CREATE TABLE b ();", "INSERT INTO schema_version (version, name) VALUES (%s, %s)"],
    ]
    assert conn.applied == {"0001", "0002"}


def test_an_applied_migration_is_never_applied_twice(tmp_path):
    d = write(tmp_path / "m", {"0001_initial.sql": "CREATE TABLE a ();", "0002_more.sql": "CREATE TABLE b ();"})
    conn = Connection(applied={"0001"})
    assert schema.apply(conn, d) == ["0002"]
    assert not [e for e in conn.log if e[0] == "execute" and e[1] == "CREATE TABLE a ();"]
    again = Connection(applied={"0001", "0002"})
    assert schema.apply(again, d) == []


def test_a_failed_migration_leaves_no_row_and_stops_the_run(tmp_path):
    d = write(tmp_path / "m", {"0001_initial.sql": "CREATE TABLE a ();", "0002_bad.sql": "BROKEN;",
                               "0003_after.sql": "CREATE TABLE c ();"})
    conn = Connection(fail_on="BROKEN")
    with pytest.raises(SchemaError, match="0002_bad.sql"):
        schema.apply(conn, d)
    assert conn.applied == {"0001"}  # the control: the one before it committed
    assert transactions(conn)[-1][0] == "rollback"
    assert not [e for e in conn.log if e[0] == "execute" and "TABLE c" in e[1]]


def test_a_database_ahead_of_the_code_is_refused(tmp_path):
    d = write(tmp_path / "m", {"0001_initial.sql": "SELECT 1;"})
    with pytest.raises(SchemaError, match="0002"):
        schema.apply(Connection(applied={"0001", "0002"}), d)


# --- the rules every migration file is held to -------------------------------------

@pytest.mark.parametrize("text", ["COMMIT;", "BEGIN;", "begin transaction;", "ROLLBACK;",
                                  "START TRANSACTION;", "END;"])
def test_a_migration_that_ends_its_own_transaction_is_refused(tmp_path, text):
    d = write(tmp_path / "m", {"0001_initial.sql": f"CREATE TABLE a ();\n{text}\n"})
    with pytest.raises(SchemaError, match="transaction"):
        schema.migrations(d)


def test_a_function_body_with_begin_and_end_is_not_a_transaction(tmp_path):
    body = ("CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN\n  RETURN NEW;\nEND;\n$$;\n"
            "CREATE FUNCTION g() RETURNS int LANGUAGE plpgsql AS $body$ BEGIN COMMIT; END; $body$;\n")
    d = write(tmp_path / "m", {"0001_initial.sql": body})
    assert [m.version for m in schema.migrations(d)] == ["0001"]


def test_a_migration_that_drops_a_column_must_hold_its_rollback_in_a_comment(tmp_path):
    drop = "ALTER TABLE a DROP COLUMN old RESTRICT;\n"
    d = write(tmp_path / "m", {"0002_drop.sql": drop})
    with pytest.raises(SchemaError, match="rollback"):
        schema.migrations(d)
    write(d, {"0002_drop.sql": "-- rollback: ALTER TABLE a ADD COLUMN old text;\n" + drop})
    assert [m.version for m in schema.migrations(d)] == ["0002"]  # the control


@pytest.mark.parametrize("drop", ["ALTER TABLE a DROP COLUMN old;", "ALTER TABLE a DROP COLUMN old CASCADE;",
                                  "ALTER TABLE a DROP COLUMN IF EXISTS old RESTRICT;"])
def test_a_column_is_dropped_with_restrict_only(tmp_path, drop):
    d = write(tmp_path / "m", {"0002_drop.sql": f"-- rollback: ALTER TABLE a ADD COLUMN old text;\n{drop}\n"})
    with pytest.raises(SchemaError, match="RESTRICT"):
        schema.migrations(d)


def test_a_dropped_view_is_granted_again_in_the_same_migration(tmp_path):
    text = "DROP VIEW mailbox_receives;\nCREATE VIEW mailbox_receives AS SELECT 1;\n"
    d = write(tmp_path / "m", {"0002_view.sql": text})
    with pytest.raises(SchemaError, match="mailbox_receives"):
        schema.migrations(d)
    write(d, {"0002_view.sql": text + "GRANT SELECT ON mailbox_receives TO maildivvy_pipeline;\n"})
    assert [m.version for m in schema.migrations(d)] == ["0002"]  # the control


def test_the_rules_ignore_what_a_comment_says(tmp_path):
    d = write(tmp_path / "m", {"0001_initial.sql": "-- never COMMIT; here, nor DROP VIEW x;\nSELECT 1;\n"})
    assert [m.version for m in schema.migrations(d)] == ["0001"]


def test_the_shipped_migrations_pass_the_rules():
    assert [m.version for m in schema.migrations(SCHEMA_DIR)][0] == "0001"
    assert schema.DEFAULT_DIR == SCHEMA_DIR


# --- the initial schema is frozen ------------------------------------------
#
# 0.1.0 is the first release: from it on, `schema/0001_initial.sql` never changes, and every
# change to the schema is a migration of its own. Its statements are pinned here, which
# holds in the public tree too (the export takes comments out, never a statement).
INITIAL = SCHEMA_DIR / "0001_initial.sql"
INITIAL_STATEMENTS_SHA256 = "c776dd0f36ab3f70484ecf97575ee835aa4325509c0d168e75eb02e94dce958e"
# the file byte for byte, here and as the 0.1.0 release ships it (its comments stripped)
INITIAL_SHA256 = "909b3476518449d8c1afb0c2a2bb438d63b5d8905973b51dac4e17c8dcb173ca"
INITIAL_RELEASED_SHA256 = "89c41599e30384ad65087d3b7464328c5241d988e9f9524541ea7e5642e667a3"


def statements_digest(text):
    lines = [line.rstrip() for line in schema.statements_only(text).splitlines() if line.strip()]
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def test_the_initial_schemas_statements_are_frozen_as_0_1_0_released_them():
    assert statements_digest(INITIAL.read_text()) == INITIAL_STATEMENTS_SHA256, (
        "schema/0001_initial.sql changed: it is frozen since 0.1.0; put the change in a new migration")


def test_the_statements_digest_sees_a_statement_and_not_a_comment():
    text = INITIAL.read_text()
    assert statements_digest("-- a new comment\n" + text) == INITIAL_STATEMENTS_SHA256
    assert statements_digest(text.replace("DEFAULT 8.00", "DEFAULT 9.00", 1)) != INITIAL_STATEMENTS_SHA256




# --- how the applier connects --------------------------------------------

def test_the_applier_takes_no_password_and_no_connection_argument():
    options = {o for action in schema.parser()._actions for o in action.option_strings}
    assert options == {"-h", "--help", "--dir"}
    assert not re.search(r"pass|user|host|port|dsn|conninfo", " ".join(options))


def test_the_applier_connects_as_the_owner_through_the_one_helper(tmp_path, monkeypatch, capsys):
    d = write(tmp_path / "m", {"0001_initial.sql": "SELECT 1;"})
    conn = Connection()
    asked = []
    monkeypatch.setattr(schema.db, "connect", lambda consumer: asked.append(consumer) or conn)
    assert schema.main(["--dir", str(d)]) == 0
    assert asked == ["owner"]
    assert ("close",) in conn.log
    assert "applied 0001_initial.sql" in capsys.readouterr().out
    assert schema.main(["--dir", str(d)]) == 0
    assert "nothing to apply" in capsys.readouterr().out


def test_a_refusal_exits_nonzero_and_names_the_file(tmp_path, monkeypatch, capsys):
    d = write(tmp_path / "m", {"0001_initial.sql": "BROKEN;"})
    monkeypatch.setattr(schema.db, "connect", lambda consumer: Connection(fail_on="BROKEN"))
    assert schema.main(["--dir", str(d)]) == 1
    assert "0001_initial.sql" in capsys.readouterr().err


def test_the_program_runs_the_applier():
    text = PROGRAM.read_text()
    assert text.startswith("#!/usr/bin/python3\n")
    assert "from maildivvy.lib.schema import main" in text
    assert PROGRAM.stat().st_mode & 0o111


# --- ties between the schema and the code that shares its names ----------------------

def test_the_cursors_quarantine_name_is_the_stores():
    sql = (SCHEMA_DIR / "0001_initial.sql").read_text()
    check = re.search(r"mailbox\s+text NOT NULL DEFAULT 'INBOX'\s+CHECK \(mailbox IN \(([^)]*)\)\)", sql)
    assert check, "pass_cursor.mailbox's CHECK not found"
    assert check.group(1) == f"'INBOX', '{store.QUARANTINE}'"
