"""Where each consumer's configuration lives, and the reading of its `db.conf`.

Each consumer of the library has its own directory, `/etc/maildivvy/<consumer>/`,
holding `db.conf` and the `pgpass` it names (docs/architecture.md § Filesystems and
paths). There is no default consumer: a program names the one it is, so it can never
fall back on another role's file.

`db.conf` is `key=value`, one per line, `#` comments. It names the database, the role
and the libpq passfile; the password lives only in that passfile. Two
refusals are deliberate and loud:

- a `db.conf` any user can read;
- a `db.conf` containing `password=` anywhere, comments included. A password there
  would work, and would move the secret out of a `0600` passfile into a file that
  several programs read.
"""

import re
import stat
from pathlib import Path

ETC = Path("/etc/maildivvy")
CONSUMERS = ("pipeline", "senthook", "milter", "admin", "health", "owner")

REQUIRED = ("dbname", "user", "passfile")
OPTIONAL = ("host", "port", "sslmode", "connect_timeout", "application_name")
PASSWORD = re.compile(r"password\s*=", re.IGNORECASE)


class ConfigError(Exception):
    """A configuration file that must not be used. The message names the file."""


def consumer_dir(consumer, etc=ETC):
    if consumer not in CONSUMERS:
        raise ConfigError(
            f"no configuration for consumer {consumer!r}; one of: {', '.join(CONSUMERS)}")
    return Path(etc) / consumer


def db_conf_path(consumer, etc=ETC):
    return consumer_dir(consumer, etc) / "db.conf"


def read_db_conf(path):
    """The settings of one `db.conf`, or ConfigError. Never returns a bad one."""
    path = Path(path)
    try:
        mode = path.stat().st_mode
        text = path.read_text()
    except OSError as err:
        raise ConfigError(f"cannot read {path}: {err.strerror}") from None
    if mode & stat.S_IROTH:
        raise ConfigError(
            f"{path} is world-readable ({stat.S_IMODE(mode):04o}); refusing it")
    match = PASSWORD.search(text)
    if match:
        line = text.count("\n", 0, match.start()) + 1
        raise ConfigError(
            f"{path} contains password= at line {line}; refusing it. The password "
            "belongs in the passfile this file names")

    conf = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key:
            raise ConfigError(f"{path} line {number} is not key=value")
        if key not in REQUIRED + OPTIONAL:
            raise ConfigError(f"{path} line {number}: unknown key {key!r}")
        if key in conf:
            raise ConfigError(f"{path} line {number}: {key} given twice")
        conf[key] = value

    missing = [key for key in REQUIRED if not conf.get(key)]
    if missing:
        raise ConfigError(f"{path} names no {', '.join(missing)}")
    if not Path(conf["passfile"]).is_absolute():
        raise ConfigError(f"{path}: passfile must be an absolute path")
    return conf
