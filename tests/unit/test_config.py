"""The per-consumer configuration layout and the database connection file (`db.conf`).

Every file here is written into a temporary directory standing in for
`/etc/maildivvy`, with the modes the installation gives the real ones.
"""

import os
from pathlib import Path

import pytest

from maildivvy.lib import config
from maildivvy.lib.config import ConfigError

GOOD = "# the pipeline's connection\nhost=127.0.0.1\ndbname=maildivvy\nuser=maildivvy_pipeline\npassfile=/etc/maildivvy/pipeline/pgpass\n"


def write(path, text, mode=0o640):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, mode)
    return path


def test_every_consumer_has_its_own_connection_file():
    paths = {c: config.db_conf_path(c) for c in config.CONSUMERS}
    assert set(config.CONSUMERS) == {"pipeline", "senthook", "milter", "admin", "health", "owner"}
    assert paths["admin"] == Path("/etc/maildivvy/admin/db.conf")
    assert len(set(paths.values())) == len(paths)


def test_an_unknown_consumer_has_no_connection_file_and_there_is_no_default():
    with pytest.raises(ConfigError, match="interface"):
        config.db_conf_path("interface")
    with pytest.raises(TypeError):
        config.db_conf_path()


def test_the_consumer_file_is_found_under_another_root(tmp_path):
    assert config.db_conf_path("milter", etc=tmp_path) == tmp_path / "milter" / "db.conf"


def test_a_group_readable_db_conf_is_read(tmp_path):
    conf = config.read_db_conf(write(tmp_path / "db.conf", GOOD, 0o640))
    assert conf == {
        "host": "127.0.0.1", "dbname": "maildivvy",
        "user": "maildivvy_pipeline", "passfile": "/etc/maildivvy/pipeline/pgpass",
    }


@pytest.mark.parametrize("mode", [0o644, 0o604, 0o666])
def test_a_world_readable_db_conf_is_refused(tmp_path, mode):
    path = write(tmp_path / "db.conf", GOOD, mode)
    with pytest.raises(ConfigError, match="world-readable") as refused:
        config.read_db_conf(path)
    assert str(path) in str(refused.value)


@pytest.mark.parametrize("line", [
    "password=hunter2hunter2",
    "PASSWORD=hunter2hunter2",
    "password = hunter2hunter2",
    "# password=hunter2hunter2",
    "options=-c password=hunter2hunter2",
])
def test_a_db_conf_containing_password_is_refused_wherever_it_is(tmp_path, line):
    path = write(tmp_path / "db.conf", GOOD + line + "\n")
    with pytest.raises(ConfigError, match="password=") as refused:
        config.read_db_conf(path)
    assert "hunter2" not in str(refused.value)


@pytest.mark.parametrize("missing", ["dbname", "user", "passfile"])
def test_a_db_conf_naming_no_passfile_database_or_user_is_refused(tmp_path, missing):
    text = "".join(l + "\n" for l in GOOD.splitlines() if not l.startswith(missing + "="))
    with pytest.raises(ConfigError, match=missing):
        config.read_db_conf(write(tmp_path / "db.conf", text))


def test_a_relative_passfile_is_refused(tmp_path):
    text = GOOD.replace("passfile=/etc/maildivvy/pipeline/pgpass", "passfile=pgpass")
    with pytest.raises(ConfigError, match="absolute"):
        config.read_db_conf(write(tmp_path / "db.conf", text))


@pytest.mark.parametrize("extra, why", [
    ("sslkey=/tmp/k\n", "unknown key"),
    ("user=someone_else\n", "twice"),
    ("just words\n", "key=value"),
])
def test_a_db_conf_that_says_something_unexpected_is_refused(tmp_path, extra, why):
    with pytest.raises(ConfigError, match=why):
        config.read_db_conf(write(tmp_path / "db.conf", GOOD + extra))


def test_a_missing_db_conf_is_refused_by_its_path(tmp_path):
    with pytest.raises(ConfigError, match=str(tmp_path / "nowhere.conf")):
        config.read_db_conf(tmp_path / "nowhere.conf")
