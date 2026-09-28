"""Print one external mailbox's provider credential on standard output, and nothing else.

This is what mpop runs through `passwordeval`, so the secret reaches it on a pipe: it
is never in the rendered configuration, never an argument and never in the process
table.

⛔ NOTHING ELSE IS EVER PRINTED ON STDOUT. mpop takes the WHOLE of stdout
as the secret, so a stray "connecting..." line becomes part of it and the login then
fails with an error that names nothing. Every diagnostic goes to stderr.

⛔ A MAILBOX WITH NO CREDENTIAL EXITS 1 WITH AN EMPTY STDOUT, AND THAT IS NOT A PROGRAM
ERROR: an external mailbox is legitimately added before its credential is
known. A usage error exits 64 and a configuration error 78, so each case is told apart.
"""

import sys

from maildivvy.lib import config, db

CONSUMER = "pipeline"

EX_USAGE = 64
EX_CONFIG = 78


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if len(argv) != 1 or not argv[0].isdigit():
        sys.stderr.write("usage: maildivvy-credential <external-mailbox-id>\n")
        return EX_USAGE

    try:
        conn = db.connect(CONSUMER)
    except config.ConfigError as err:
        sys.stderr.write(f"maildivvy-credential: {err}\n")
        return EX_CONFIG

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT credential FROM external_mailbox WHERE id = %s", (int(argv[0]),))
            row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        sys.stderr.write(f"maildivvy-credential: no external mailbox {argv[0]}\n")
        return 1
    if not row[0]:
        sys.stderr.write(f"maildivvy-credential: external mailbox {argv[0]} has no credential "
                         "yet; it is saved before one is known\n")
        return 1

    sys.stdout.write(row[0])
    sys.stdout.flush()
    return 0
