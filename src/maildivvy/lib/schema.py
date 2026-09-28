"""The schema applier: the numbered SQL files of `schema/`, applied forward, as the owner.

    maildivvy-schema [--dir <migrations>]

Migrations are applied in name order, each in one transaction together with its row
in `schema_version`, so a failed file leaves no row and is retried, and an applied one
is never applied twice. An empty migration set is refused, never reported as success.
A database that has applied a version the code does not carry is
refused: it is newer than this code.

The applier connects as the owning role through `lib/db.py`, from the `owner`
consumer's `db.conf` (a unix socket, the password in the passfile it names). It takes
no password, user, host or port argument.

Every file is held to the migration rules before anything is applied:

- it never ends its own transaction (`BEGIN`, `COMMIT`, `ROLLBACK`, `END` as a
  statement), since the applier's transaction is what ties the file to its row;
- a column is dropped with `RESTRICT` only, never `CASCADE` or `IF EXISTS`, so a
  reader not replaced first fails the file instead of being dropped;
- a file that drops a column holds its rollback in a `-- rollback:` comment;
- a view that is dropped is granted again in the same file, since the drop takes its
  grants with it.
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from maildivvy.lib import db

DEFAULT_DIR = Path(__file__).resolve().parents[3] / "schema"
NAME = re.compile(r"(\d{4})_[a-z0-9_]+\.sql")

VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version    text PRIMARY KEY,
    name       text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)"""

_DOLLAR_QUOTED = re.compile(r"(\$[A-Za-z_]*\$).*?\1", re.DOTALL)
_COMMENT = re.compile(r"--[^\n]*")
_TRANSACTION = re.compile(
    r"(?:^|;)\s*(BEGIN|COMMIT|ROLLBACK|END|START\s+TRANSACTION|ABORT)\b\s*(?:TRANSACTION|WORK)?\s*;",
    re.IGNORECASE)
_DROP_COLUMN = re.compile(r"\bDROP\s+COLUMN\b([^;]*)", re.IGNORECASE)
_DROP_VIEW = re.compile(r"\bDROP\s+VIEW\s+(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)", re.IGNORECASE)
_ROLLBACK_COMMENT = re.compile(r"^\s*--\s*rollback:", re.IGNORECASE | re.MULTILINE)


class SchemaError(Exception):
    """A migration set or file refused, or a migration that failed. The message names it."""


@dataclass(frozen=True)
class Migration:
    version: str
    path: Path

    @property
    def name(self):
        return self.path.name


def statements_only(text):
    """The SQL with comments and dollar-quoted bodies removed: what runs at the top level."""
    return _DOLLAR_QUOTED.sub("$$", _COMMENT.sub("", text))


def check_migration(name, text):
    """Refuse a migration file that breaks one of the rules; returns nothing."""
    top = statements_only(text)
    ends = _TRANSACTION.search(top)
    if ends:
        raise SchemaError(f"{name}: {ends.group(1).upper()} ends the applier's transaction; "
                          "a migration never manages its own transaction")
    for match in _DROP_COLUMN.finditer(top):
        rest = match.group(1)
        if re.search(r"\b(CASCADE|IF\s+EXISTS)\b", rest, re.IGNORECASE) \
                or not re.search(r"\bRESTRICT\b", rest, re.IGNORECASE):
            raise SchemaError(f"{name}: DROP COLUMN{rest} must be RESTRICT, never CASCADE or IF EXISTS")
        if not _ROLLBACK_COMMENT.search(text):
            raise SchemaError(f"{name} drops a column and holds no '-- rollback:' comment")
    for match in _DROP_VIEW.finditer(top):
        view = match.group(1)
        if not re.search(rf"\bGRANT\b[^;]*\bON\s+(?:TABLE\s+)?{view}\b", top, re.IGNORECASE):
            raise SchemaError(f"{name} drops view {view} and does not grant it again")


def migrations(directory=DEFAULT_DIR):
    """Every migration in `directory`, in name order, each checked; never an empty list."""
    directory = Path(directory)
    if not directory.is_dir():
        raise SchemaError(f"migration directory {directory} does not exist")
    found = {}
    for path in sorted(directory.iterdir()):
        match = NAME.fullmatch(path.name)
        if not match or not path.is_file():
            raise SchemaError(f"{path.name} in {directory} is not a migration (NNNN_name.sql); "
                              "refusing rather than skipping it")
        version = match.group(1)
        if version in found:
            raise SchemaError(f"two migrations carry number {version}: {found[version].name}, {path.name}")
        check_migration(path.name, path.read_text())
        found[version] = Migration(version, path)
    if not found:
        raise SchemaError(f"no migration in {directory}; refusing to report an empty set as applied")
    return [found[v] for v in sorted(found)]


def apply(conn, directory=DEFAULT_DIR):
    """Apply every migration not yet applied; returns the versions applied, in order."""
    pending = migrations(directory)
    with conn.cursor() as cur:
        cur.execute(VERSION_TABLE)
        cur.execute("SELECT version FROM schema_version ORDER BY version")
        applied = {row[0] for row in cur.fetchall()}
    conn.commit()

    unknown = sorted(applied - {m.version for m in pending})
    if unknown:
        raise SchemaError(f"the database has applied {', '.join(unknown)}, which this code does not carry; "
                          "it is newer than the code")
    done = []
    for migration in pending:
        if migration.version in applied:
            continue
        try:
            with conn.cursor() as cur:
                cur.execute(migration.path.read_text())
                cur.execute("INSERT INTO schema_version (version, name) VALUES (%s, %s)",
                            (migration.version, migration.name))
            conn.commit()
        except Exception as err:
            conn.rollback()
            raise SchemaError(f"{migration.name} failed and was rolled back: {err}") from err
        done.append(migration.version)
    return done


def parser():
    p = argparse.ArgumentParser(prog="maildivvy-schema", description=__doc__.splitlines()[0])
    p.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="the migrations (default: %(default)s)")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        pending = migrations(args.dir)
        conn = db.connect("owner")
        try:
            done = apply(conn, args.dir)
        finally:
            conn.close()
    except Exception as err:
        print(f"maildivvy-schema: {err}", file=sys.stderr)
        return 1
    names = {m.version: m.name for m in pending}
    for version in done:
        print(f"applied {names[version]}")
    if not done:
        print(f"nothing to apply: {len(pending)} migration(s) already applied")
    return 0
