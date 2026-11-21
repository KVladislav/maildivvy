"""A throwaway PostgreSQL for the unit tier: the real schema, the real roles and grants.

One cluster per test session: `initdb` in a temporary directory, the server started on
a unix socket in that directory and on no TCP port, every role the install creates made
the way it makes them (`maildivvy_owner`, the consumers with a login and a password,
the two daemons' roles `NOLOGIN`), and the schema applied by the product's own applier
(`maildivvy.lib.schema.apply`), connected as the owner through `lib/db.py` from a
`db.conf` and a passfile, as the machine connects. That database is the template; each
test gets a fresh copy of it, and the copy is dropped after the test.

A test then connects the way a program does, as its consumer (`Database.etc` is a
`/etc/maildivvy` of its own), so a grant the schema forgot fails here in seconds.

Where PostgreSQL's server programs or the driver cannot be found, every test that asks
for the database is skipped, saying which one is missing. The driver is the one the
machine runs: the virtual environment's if it has one, else the distribution's
`python3-psycopg2`, loaded alone, without the rest of the distribution's packages.
"""

import glob
import importlib.util
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from maildivvy.lib import schema

DB_NAME = "maildivvy"
OWNER = "maildivvy_owner"
# consumer -> role, as the install's postgresql role creates them, each with a login
CONSUMERS = {"pipeline": "maildivvy_pipeline", "senthook": "maildivvy_senthook",
             "milter": "maildivvy_milter", "admin": "maildivvy_admin",
             "health": "maildivvy_health"}
# made NOLOGIN by the install until the daemon's own step
DAEMON_ROLES = ("maildivvy_dovecot", "maildivvy_postfix")
SUPERUSER = "postgres"
DISTRIBUTION_PACKAGES = Path("/usr/lib/python3/dist-packages")


class Unavailable(Exception):
    """PostgreSQL or its driver is not here: the message says which, for the skip."""


def server_programs():
    """The directory holding `initdb`, `pg_ctl` and `postgres`, or Unavailable.

    Debian keeps them out of PATH, under `/usr/lib/postgresql/<major>/bin`, which
    `pg_config --bindir` names when the dev package is there. The newest major wins.
    """
    found = []
    if os.environ.get("MAILDIVVY_PG_BINDIR"):
        found.append(os.environ["MAILDIVVY_PG_BINDIR"])
    if shutil.which("pg_config"):
        said = subprocess.run(["pg_config", "--bindir"], capture_output=True, text=True,
                              check=False)
        if said.returncode == 0:
            found.append(said.stdout.strip())
    found += sorted(glob.glob("/usr/lib/postgresql/*/bin"),
                    key=lambda path: int(Path(path).parent.name)
                    if Path(path).parent.name.isdigit() else 0, reverse=True)
    on_path = shutil.which("initdb")
    if on_path:
        found.append(str(Path(on_path).parent))
    for directory in found:
        if all((Path(directory) / name).is_file() for name in ("initdb", "pg_ctl", "postgres")):
            return Path(directory)
    raise Unavailable("PostgreSQL's server programs (initdb, pg_ctl) were not found; "
                      "install the postgresql package, or name their directory in "
                      "MAILDIVVY_PG_BINDIR, to run the tests that need a database")


def driver():
    """psycopg2: the environment's own, else the distribution's, else Unavailable."""
    try:
        import psycopg2
        return psycopg2
    except ImportError:
        pass
    package = DISTRIBUTION_PACKAGES / "psycopg2"
    if (package / "__init__.py").is_file():
        spec = importlib.util.spec_from_file_location(
            "psycopg2", package / "__init__.py", submodule_search_locations=[str(package)])
        module = importlib.util.module_from_spec(spec)
        sys.modules["psycopg2"] = module
        try:
            spec.loader.exec_module(module)
        except ImportError:
            del sys.modules["psycopg2"]
        else:
            return module
    raise Unavailable("the PostgreSQL driver psycopg2 is not installed (pip install "
                      "psycopg2, or the distribution's python3-psycopg2), so the tests "
                      "that need a database cannot connect")


def run(argv, **kwargs):
    done = subprocess.run([str(part) for part in argv], capture_output=True, text=True,
                          check=False, **kwargs)
    if done.returncode != 0:
        raise RuntimeError(f"{argv[0]} failed ({done.returncode}): {done.stderr or done.stdout}")
    return done


def write_consumer(etc, consumer, role, password, socket, dbname):
    """`/etc/maildivvy/<consumer>/`: `db.conf` with no password, and its `pgpass` 0600."""
    directory = etc / consumer
    directory.mkdir(parents=True, exist_ok=True)
    passfile = directory / "pgpass"
    passfile.write_text(f"*:*:*:{role}:{password}\n")
    passfile.chmod(0o600)
    conf = directory / "db.conf"
    conf.write_text(f"dbname={dbname}\nuser={role}\npassfile={passfile}\nhost={socket}\n")
    conf.chmod(0o640)


class Cluster:
    """The session's server. `database()` hands each test a fresh copy of the schema."""

    def __init__(self):
        self.psycopg2 = driver()
        self.bin = server_programs()
        self.root = Path(tempfile.mkdtemp(prefix="maildivvy-pg-"))
        self.data = self.root / "data"
        self.passwords = {role: secrets.token_hex(16)
                          for role in (SUPERUSER, OWNER, *CONSUMERS.values())}
        self.copies = 0
        self.started = False

    def start(self):
        pwfile = self.root / "superuser"
        pwfile.write_text(self.passwords[SUPERUSER] + "\n")
        pwfile.chmod(0o600)
        run([self.bin / "initdb", "-D", self.data, "-U", SUPERUSER, "-A", "scram-sha-256",
             "--pwfile", pwfile, "-E", "UTF8", "--locale", "C.UTF-8", "--no-instructions"])
        # a unix socket in the private directory and no TCP port; durability is not
        # what these tests are about, so the server does not wait on the disk.
        # SCRAM stays the method the machine uses, at one iteration: every request
        # opens a connection, and the key stretching is not what these tests are about
        options = (f"-c listen_addresses='' -c unix_socket_directories='{self.root}' "
                   "-c fsync=off -c synchronous_commit=off -c full_page_writes=off "
                   "-c scram_iterations=1")
        run([self.bin / "pg_ctl", "-D", self.data, "-l", self.root / "server.log",
             "-o", options, "-w", "start"])
        self.started = True
        with self.superuser("postgres") as conn, conn.cursor() as cursor:
            # the install's roles, as its postgresql role creates them
            for role in (OWNER, *CONSUMERS.values()):
                cursor.execute(f"CREATE ROLE {role} LOGIN PASSWORD %s", (self.passwords[role],))
            for role in DAEMON_ROLES:
                cursor.execute(f"CREATE ROLE {role} NOLOGIN")
            cursor.execute(f"CREATE DATABASE {DB_NAME} OWNER {OWNER}")
        # the schema, applied by the product's applier as the owner, as the install does
        etc = self.root / "etc"
        write_consumer(etc, "owner", OWNER, self.passwords[OWNER], self.root, DB_NAME)
        from maildivvy.lib import db
        conn = db.connect("owner", etc=etc)
        try:
            schema.apply(conn)
        finally:
            conn.close()
        with self.superuser(DB_NAME) as conn, conn.cursor() as cursor:
            cursor.execute("SELECT check_grants()")
            assert cursor.fetchone()[0] is True
        return self

    def superuser(self, dbname):
        conn = self.psycopg2.connect(host=str(self.root), dbname=dbname, user=SUPERUSER,
                                     password=self.passwords[SUPERUSER])
        conn.autocommit = True
        return Closing(conn)

    def database(self, etc):
        """A fresh copy of the schema, and `etc` holding every consumer's files for it."""
        self.copies += 1
        name = f"test_{self.copies}"
        with self.superuser("postgres") as conn, conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE {name} TEMPLATE {DB_NAME} OWNER {OWNER} "
                           "STRATEGY FILE_COPY")
            # a database's own privileges are not copied from its template: the schema's
            # revoke of TEMPORARY is made again, and every grant read back as the schema does
            cursor.execute(f"REVOKE TEMPORARY ON DATABASE {name} FROM PUBLIC")
        with self.superuser(name) as conn, conn.cursor() as cursor:
            cursor.execute("SELECT check_grants()")
        write_consumer(etc, "owner", OWNER, self.passwords[OWNER], self.root, name)
        for consumer, role in CONSUMERS.items():
            write_consumer(etc, consumer, role, self.passwords[role], self.root, name)
        return Database(self, name, etc)

    def drop(self, name):
        with self.superuser("postgres") as conn, conn.cursor() as cursor:
            cursor.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")

    def stop(self):
        if self.started:
            subprocess.run([str(self.bin / "pg_ctl"), "-D", str(self.data), "-m", "immediate",
                            "-w", "stop"], capture_output=True, check=False)
        shutil.rmtree(self.root, ignore_errors=True)


class Closing:
    """A connection as a context manager that closes it (psycopg2's only ends a
    transaction)."""

    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self.conn

    def __exit__(self, *_):
        self.conn.close()


class Database:
    """One test's database. `sql` runs as the superuser, to set a scene or read it back;
    the code under test connects as its consumer through `etc`."""

    def __init__(self, cluster, name, etc):
        self.cluster, self.name, self.etc = cluster, name, Path(etc)
        self.psycopg2 = cluster.psycopg2
        self.conn = None

    def sql(self, statement, parameters=()):
        """Rows of one statement run as the superuser (an empty list when it returns none),
        committed at once."""
        if self.conn is None:
            self.conn = self.cluster.superuser(self.name).conn
        with self.conn.cursor() as cursor:
            cursor.execute(statement, parameters)
            return cursor.fetchall() if cursor.description else []

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def one(self, statement, parameters=()):
        rows = self.sql(statement, parameters)
        return rows[0] if rows else None

    def value(self, statement, parameters=()):
        row = self.one(statement, parameters)
        return row[0] if row else None

    def connect(self, consumer):
        """A connection as `consumer`, made by the product's own `db.connect`."""
        from maildivvy.lib import db
        return db.connect(consumer, etc=self.etc)
