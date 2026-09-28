#!/usr/bin/python3
"""Install step 6's helper, run on the machine as root by the postgresql role.

    maildivvy_pg.py password <role> <passfile> <reader> [--db <database>] [--host <host>]
    maildivvy_pg.py breakglass [--db <database>]      # the password on stdin

`password` gives a database role the password in its libpq passfile. The passfile is
`host:port:database:user:password`, five fields, `0600` and owned by the user
that reads it, written here in its own step. An existing passfile
for the role keeps its password; a missing or malformed one is written with a new one,
64 hex characters from the system's random source. The role is then asked to log in
with it over the unix socket, or over TCP to `--host` when its daemon connects that way
(libpq matches the passfile's first field against the host it is given, so a role read
by a chrooted daemon has `127.0.0.1` there, not `localhost`); only when that login fails
is its password set, as a
SCRAM-SHA-256 verifier computed here and sent to psql on stdin, so the password is in
no argv, no shell history and no server log.

`breakglass` stores the break-glass password's hash, computed on this machine by
`openssl passwd -6` with the password on stdin, and sends only the hash to the server.
A stored hash that the password still matches is kept, so a re-run changes
nothing; the row is read back by shape, never by content.

Each prints one JSON object, {"changed": true|false}.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import subprocess
import sys
from pathlib import Path

DATABASE = "maildivvy"
HOST = "localhost"  # the unix socket, as libpq names it in a passfile
PORT = 5432
ROLE = re.compile(r"maildivvy_[a-z]+")
BREAK_GLASS_HASH = re.compile(r"\$6\$([./0-9A-Za-z]{16})\$[./0-9A-Za-z]{86}")


class PgError(Exception):
    pass


def role_name(name):
    if not ROLE.fullmatch(name):
        raise PgError(f"{name!r} is not one of the product's roles (maildivvy_<name>)")
    return name


def scram_verifier(password, salt=None, iterations=4096):
    """PostgreSQL's stored form of a SCRAM-SHA-256 password (RFC 5802, RFC 7677)."""
    salt = salt or secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda raw: base64.b64encode(raw).decode()  # noqa: E731
    return (f"SCRAM-SHA-256${iterations}:{b64(salt)}"
            f"${b64(hashlib.sha256(client_key).digest())}:{b64(server_key)}")


def passfile_line(database, role, password, host=HOST):
    return f"{host}:{PORT}:{database}:{role}:{password}\n"


def ensure_passfile(path, database, role, uid, gid, host=HOST):
    """(password, written): the role's password from its passfile, writing one if needed."""
    path = Path(path)
    try:
        fields = path.read_text().rstrip("\n").split(":")
    except FileNotFoundError:
        fields = []
    if len(fields) == 5 and fields[:4] == [host, str(PORT), database, role] and fields[4]:
        os.chown(path, uid, gid)
        os.chmod(path, 0o600)
        return fields[4], False
    password = secrets.token_hex(32)
    new = path.with_name(path.name + ".new")
    fd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(passfile_line(database, role, password, host))
    os.chown(new, uid, gid)
    os.chmod(new, 0o600)
    os.replace(new, path)
    return password, True


def psql_as_postgres(sql, database):
    """Run SQL from stdin as the postgres superuser, over the socket by peer."""
    return subprocess.run(
        ["runuser", "-u", "postgres", "--", "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", database],
        input=sql, capture_output=True, text=True, check=True).stdout.strip()


def logs_in(role, passfile, database, host=HOST):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env["PGPASSFILE"] = str(passfile)
    # the passfile's first field is matched against the host libpq is given, so a role
    # whose daemon connects over TCP is proved over TCP and not over the socket
    where = [] if host == HOST else ["-h", host]
    result = subprocess.run(["psql", "-X", "-w", "-At", *where, "-U", role, "-d", database, "-c", "SELECT 1"],
                            env=env, capture_output=True, text=True)
    return result.returncode == 0 and result.stdout.strip() == "1"


def set_password(role, passfile, reader, database, host=HOST):
    role = role_name(role)
    entry = pwd.getpwnam(reader)
    password, written = ensure_passfile(passfile, database, role, entry.pw_uid, entry.pw_gid, host)
    if logs_in(role, passfile, database, host):
        return written
    psql_as_postgres(f"ALTER ROLE {role} PASSWORD '{scram_verifier(password)}';\n", "postgres")
    if not logs_in(role, passfile, database, host):
        raise PgError(f"{role} still cannot log in to {database} with {passfile} after its password was set")
    return True


def openssl_sha512_crypt(password, salt=None):
    argv = ["openssl", "passwd", "-6", "-stdin"] + (["-salt", salt] if salt else [])
    out = subprocess.run(argv, input=password + "\n", capture_output=True, text=True, check=True).stdout.strip()
    if not BREAK_GLASS_HASH.fullmatch(out):
        raise PgError("openssl passwd -6 did not answer a sha512-crypt hash of the expected shape")
    return out


def salt_of(stored):
    match = BREAK_GLASS_HASH.fullmatch(stored)
    return match.group(1) if match else None


def set_break_glass(password, database):
    stored = psql_as_postgres("SELECT password_hash FROM break_glass;\n", database)
    salt = salt_of(stored)
    if salt and openssl_sha512_crypt(password, salt) == stored:
        return False
    new = openssl_sha512_crypt(password)
    psql_as_postgres(
        f"INSERT INTO break_glass (password_hash) VALUES ('{new}')\n"
        "ON CONFLICT (only_row) DO UPDATE SET password_hash = EXCLUDED.password_hash, set_at = now();\n",
        database)
    shape = psql_as_postgres("SELECT length(password_hash) || ' ' || left(password_hash, 3) FROM break_glass;\n",
                             database)
    if shape != "106 $6$":
        raise PgError(f"the stored break-glass hash reads back as {shape!r}, not '106 $6$'")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("password")
    p.add_argument("role")
    p.add_argument("passfile", type=Path)
    p.add_argument("reader")
    p.add_argument("--db", default=DATABASE)
    p.add_argument("--host", default=HOST)
    b = sub.add_parser("breakglass")
    b.add_argument("--db", default=DATABASE)
    args = parser.parse_args(argv)
    try:
        if args.command == "password":
            changed = set_password(args.role, args.passfile, args.reader, args.db, args.host)
        else:
            password = sys.stdin.readline().rstrip("\n")
            if not password:
                raise PgError("no break-glass password on stdin")
            changed = set_break_glass(password, args.db)
    except (PgError, subprocess.CalledProcessError, KeyError) as err:
        detail = getattr(err, "stderr", "") or ""
        print(f"maildivvy_pg: {err} {detail}".strip(), file=sys.stderr)
        return 1
    print(json.dumps({"changed": changed}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
