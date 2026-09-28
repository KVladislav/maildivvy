"""The one database connection helper: a consumer's `db.conf`, its named passfile, and
no connection string built anywhere else.

`psycopg2` is replaced by a recorder, so no server is needed here; the roles are
queried as themselves on the test VM.
"""

import ast
import os
import sys
import types
from pathlib import Path

import pytest

from maildivvy.lib import db
from maildivvy.lib.config import ConfigError

ROOT = Path(__file__).resolve().parents[2]
PROGRAM_TREES = [ROOT / "src", ROOT / "bin"]
DB_MODULE = ROOT / "src" / "maildivvy" / "lib" / "db.py"
# The connection library itself: the reader of db.conf and the one connect call.
LIBRARY = {DB_MODULE, ROOT / "src" / "maildivvy" / "lib" / "config.py"}


@pytest.fixture
def etc(tmp_path):
    """A stand-in for /etc/maildivvy with the pipeline's two files, as installed."""
    consumer = tmp_path / "pipeline"
    consumer.mkdir()
    passfile = consumer / "pgpass"
    passfile.write_text("127.0.0.1:5432:maildivvy:maildivvy_pipeline:hunter2hunter2\n")
    os.chmod(passfile, 0o600)
    conf = consumer / "db.conf"
    conf.write_text(
        f"host=127.0.0.1\ndbname=maildivvy\nuser=maildivvy_pipeline\npassfile={passfile}\n")
    os.chmod(conf, 0o640)
    return tmp_path


@pytest.fixture
def driver(monkeypatch):
    """A psycopg2 that records how it was asked to connect."""
    calls = []

    class Connection:
        autocommit = False

    def connect(*args, **kwargs):
        calls.append((args, kwargs))
        return Connection()

    monkeypatch.setitem(sys.modules, "psycopg2", types.SimpleNamespace(connect=connect))
    monkeypatch.delenv("PGPASSWORD", raising=False)
    monkeypatch.delenv("PGSERVICE", raising=False)
    return calls


def test_the_connection_names_the_passfile_and_carries_no_password(etc, driver):
    conn = db.connect("pipeline", etc=etc)
    assert conn.autocommit is False
    [(args, kwargs)] = driver
    assert args == ()
    assert kwargs == {
        "host": "127.0.0.1", "dbname": "maildivvy", "user": "maildivvy_pipeline",
        "passfile": str(etc / "pipeline" / "pgpass"),
    }
    assert "hunter2" not in repr(driver)


def test_each_consumer_connects_with_its_own_file(etc, driver):
    with pytest.raises(ConfigError, match=str(etc / "admin" / "db.conf")):
        db.connect("admin", etc=etc)
    assert driver == []


def test_a_world_readable_db_conf_stops_the_connection(etc, driver):
    os.chmod(etc / "pipeline" / "db.conf", 0o644)
    with pytest.raises(ConfigError, match="world-readable"):
        db.connect("pipeline", etc=etc)
    assert driver == []


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_a_passfile_libpq_would_ignore_is_refused_by_name(etc, driver, mode):
    passfile = etc / "pipeline" / "pgpass"
    os.chmod(passfile, mode)
    with pytest.raises(ConfigError, match="group or other") as refused:
        db.connect("pipeline", etc=etc)
    assert str(passfile) in str(refused.value)
    assert driver == []


def test_a_missing_passfile_is_refused_by_name(etc, driver):
    passfile = etc / "pipeline" / "pgpass"
    passfile.unlink()
    with pytest.raises(ConfigError, match=str(passfile)):
        db.connect("pipeline", etc=etc)
    assert driver == []


@pytest.mark.parametrize("variable", ["PGPASSWORD", "PGSERVICE"])
def test_a_password_from_the_environment_is_refused(etc, driver, monkeypatch, variable):
    monkeypatch.setenv(variable, "hunter2hunter2")
    with pytest.raises(ConfigError, match=variable) as refused:
        db.connect("pipeline", etc=etc)
    assert "hunter2" not in str(refused.value)
    assert driver == []


def test_autocommit_is_asked_for_explicitly(etc, driver):
    assert db.connect("pipeline", etc=etc, autocommit=True).autocommit is True


# ------------------------------------------- libpq's own tools, from the same db.conf


def test_a_libpq_tool_is_given_the_consumers_identity_and_nothing_the_caller_had(etc):
    """pg_dump and pg_restore are libpq programs: they are handed the same db.conf as an
    environment, and every PG* variable of the caller's is dropped - an inherited
    PGHOST or PGUSER would point the dump at another server or role."""
    caller = {"PATH": "/usr/bin", "PGHOST": "elsewhere", "PGUSER": "root", "LANG": "C.UTF-8"}
    env = db.libpq_environment("pipeline", etc=etc, base=caller)
    assert env == {"PATH": "/usr/bin", "LANG": "C.UTF-8", "PGHOST": "127.0.0.1",
                   "PGDATABASE": "maildivvy", "PGUSER": "maildivvy_pipeline",
                   "PGPASSFILE": str(etc / "pipeline" / "pgpass")}
    assert "hunter2" not in repr(env)


@pytest.mark.parametrize("variable", ["PGPASSWORD", "PGSERVICE"])
def test_a_libpq_tool_refuses_a_password_from_the_environment(etc, variable):
    with pytest.raises(ConfigError, match=variable):
        db.libpq_environment("pipeline", etc=etc, base={variable: "hunter2hunter2"})


def test_a_libpq_tool_refuses_a_passfile_libpq_would_ignore(etc):
    os.chmod(etc / "pipeline" / "pgpass", 0o640)
    with pytest.raises(ConfigError, match="group or other"):
        db.libpq_environment("pipeline", etc=etc, base={})


# ------------------------------------------------ no program builds its own connection

CONNINFO_WORDS = ("dbname=", "passfile=", "password=", "postgresql://", "postgres://")


def connection_builders(path):
    """Every place in one source file that connects or spells a connection string."""
    tree = ast.parse(path.read_text(), filename=str(path))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr == "connect"
                    and isinstance(func.value, ast.Name)
                    and func.value.id in ("psycopg2", "psycopg")):
                found.append((node.lineno, f"{func.value.id}.connect"))
        elif isinstance(node, ast.ImportFrom) and node.module in ("psycopg2", "psycopg"):
            if any(alias.name == "connect" for alias in node.names):
                found.append((node.lineno, f"from {node.module} import connect"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for word in CONNINFO_WORDS:
                if word in node.value.lower():
                    found.append((node.lineno, word))
    return found


def python_sources():
    for tree in PROGRAM_TREES:
        if tree.is_dir():
            for path in sorted(tree.rglob("*")):
                if path.is_file() and (path.suffix == ".py" or _is_python_script(path)):
                    yield path


def _is_python_script(path):
    with path.open("rb") as handle:
        first = handle.readline()
    return first.startswith(b"#!") and b"python" in first


def test_no_program_builds_its_own_connection_string():
    sources = list(python_sources())
    assert DB_MODULE in sources
    offenders = {
        str(path.relative_to(ROOT)): found
        for path in sources if path not in LIBRARY
        for found in [connection_builders(path)] if found
    }
    assert offenders == {}


def test_the_scan_sees_a_connection_where_there_is_one():
    # Positive control: the helper's own connect call is found by the same scan.
    assert (DB_MODULE.read_text().count("psycopg2.connect") >= 1
            and any(what == "psycopg2.connect" for _, what in connection_builders(DB_MODULE)))


def test_the_scan_sees_a_spelled_connection_string(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text('import psycopg2\nc = psycopg2.connect("dbname=x user=y password=z")\n')
    assert {what for _, what in connection_builders(planted)} == {
        "psycopg2.connect", "dbname=", "password="}
