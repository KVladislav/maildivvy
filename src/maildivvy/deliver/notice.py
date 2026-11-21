"""A notice Postfix wrote to a sender, filed in that sender's domain archive.

    maildivvy-notice <recipient>

Postfix's pipe(8) runs this as the mail owner for every message with the null sender:
on this machine that is a notice Postfix itself wrote, since submission refuses the null
sender and nothing else submits. Its recipient is the envelope sender of the message it
is about, which is an external mailbox's address, so the notice is filed in the INBOX of
the archive of the domain that mailbox belongs to, and the fan-out brings it to the
domain's people like any incoming message.

⛔ NEITHER SCANNED NOR GIVEN A HEADER BLOCK OF OURS, as the filter's own report:
the notice is Postfix's words around the person's own message, which the
milter scanned at submission. It also could not be scanned here: pipe(8) gives a command
its user's primary group alone, and the scanners' sockets are reached through others.

Exit codes are what pipe(8) reads: 67 for a recipient that is no external mailbox of
ours (Postfix logs it and discards the notice), 75 while the database cannot be asked
(Postfix tries again), and otherwise the delivery agent's own.
"""

import argparse
import sys

from maildivvy.deliver.filter import LDA, run_lda
from maildivvy.lib import db, store

CONSUMER = "pipeline"
EX_NOUSER = 67
EX_TEMPFAIL = 75

# Postfix folds a sender before it looks it up, and the per-sender views are keyed by the
# folded address; the notice's recipient is the sender as the client spelled it.
DOMAIN_OF = """
    SELECT d.label
    FROM external_mailbox e
    JOIN domain d ON d.external_mailbox_id = e.id
    WHERE lower(e.address) = lower(%s)"""


def label_of(recipient):
    """The label of the domain whose external mailbox `recipient` is, or None."""
    conn = db.connect(CONSUMER, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute(DOMAIN_OF, (recipient,))
            row = cur.fetchone()
    finally:
        conn.close()
    return row[0] if row else None


def main(argv=None):
    parser = argparse.ArgumentParser(description="file a notice Postfix wrote in its domain archive")
    parser.add_argument("recipient")
    parser.add_argument("--lda", default=LDA)
    args = parser.parse_args(argv)
    raw = sys.stdin.buffer.read()
    try:
        label = label_of(args.recipient)
    except Exception as err:  # noqa: BLE001 - the database or its configuration: try again
        sys.stderr.write(f"maildivvy-notice: cannot look up {args.recipient}: {err}\n")
        return EX_TEMPFAIL
    if label is None:
        sys.stderr.write(f"maildivvy-notice: {args.recipient} is no external mailbox here; "
                         "the notice is not filed\n")
        return EX_NOUSER
    done = run_lda(args.lda, f"{store.ARCHIVE}@{label}", raw)
    if done.returncode != 0:
        sys.stderr.write(f"maildivvy-notice: the delivery agent refused the notice for "
                         f"{store.ARCHIVE}@{label} (exit {done.returncode}): "
                         f"{done.stderr.decode('utf-8', 'replace').strip()}\n")
    return done.returncode
