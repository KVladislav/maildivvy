"""The one way a program of ours connects to the database.

A program names the consumer it is; the connection is made from that consumer's
`db.conf` and the passfile it names, and from nothing else. No
other module calls the driver's connect or spells a connection string; a unit test
scans the programs for it.

The passfile is checked before libpq sees it: libpq ignores a passfile with any group
or other access without naming it, and reports only `no password supplied`.
A password from the environment (`PGPASSWORD`, or a service file through `PGSERVICE`)
is refused, so the named passfile is the only source.
"""

import os
import stat
from pathlib import Path

from maildivvy.lib.config import ETC, ConfigError, db_conf_path, read_db_conf

ENVIRONMENT_SOURCES = ("PGPASSWORD", "PGSERVICE")


def conninfo(consumer, etc=ETC):
    """The keyword arguments for the driver's connect, from the consumer's db.conf."""
    return read_db_conf(db_conf_path(consumer, etc))


def check_passfile(path):
    path = Path(path)
    try:
        mode = path.stat().st_mode
    except OSError as err:
        raise ConfigError(f"passfile {path}: {err.strerror}") from None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(
            f"passfile {path} has group or other access ({stat.S_IMODE(mode):04o}); "
            "libpq would ignore it. It must be 0600, owned by its reader")


# db.conf's keys as libpq's own programs read them from the environment.
LIBPQ_VARIABLES = {"dbname": "PGDATABASE", "user": "PGUSER", "passfile": "PGPASSFILE",
                   "host": "PGHOST", "port": "PGPORT", "sslmode": "PGSSLMODE",
                   "connect_timeout": "PGCONNECT_TIMEOUT", "application_name": "PGAPPNAME"}


def refuse_environment_password(environment):
    for variable in ENVIRONMENT_SOURCES:
        if variable in environment:
            raise ConfigError(
                f"{variable} is set in the environment; refusing, the password comes "
                "only from the passfile db.conf names")


def libpq_environment(consumer, etc=ETC, base=None):
    """The environment for one of libpq's own programs (pg_dump, pg_restore), from the
    consumer's `db.conf` and from nothing else.

    Every `PG*` variable of `base` is dropped, so a caller's `PGHOST` or `PGUSER` can
    never point the program at another server or role; the rest of `base` is kept.
    """
    base = os.environ if base is None else base
    refuse_environment_password(base)
    info = read_db_conf(db_conf_path(consumer, etc))
    check_passfile(info["passfile"])
    environment = {name: value for name, value in base.items() if not name.startswith("PG")}
    environment.update({LIBPQ_VARIABLES[key]: value for key, value in info.items()})
    return environment


def connect(consumer, etc=ETC, autocommit=False):
    return connect_at(db_conf_path(consumer, etc), autocommit=autocommit)


def connect_at(path, autocommit=False):
    """A connection made from one named `db.conf`, and from nothing else.

    A program whose unit points it explicitly at its own file connects this way:
    without the explicit path a milter running as its own user
    would fall back on another consumer's file, which it cannot read, and every
    submission would be deferred while its own files read exactly as expected.
    """
    refuse_environment_password(os.environ)
    info = read_db_conf(path)
    check_passfile(info["passfile"])

    import psycopg2

    conn = psycopg2.connect(**info)
    conn.autocommit = autocommit
    return conn
