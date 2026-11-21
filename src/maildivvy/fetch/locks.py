"""The advisory lock namespaces the fetch, the snapshot and a deletion share.

⛔ ONE CONSTANT PER LOCK, IMPORTED BY EVERY SIDE. The fetcher takes its lock
with TRY-lock and skips a mailbox whose lock is held, because it runs from a timer and a
queue of waiting runners turns one slow provider into a pile of processes.
Deleting an external mailbox takes the SAME lock BLOCKING, before it removes the row
and the fetcher's state: the runner renders from rows it read at the start of its run,
so a delete that lands mid-run has the state directory recreated a second later and the
state outlives the row (measured on the predecessor). Two namespaces would mean
the two locks never meet, which is why neither side spells the number itself.

⛔ THE SNAPSHOT HAS A LOCK OF ITS OWN, `SNAPSHOT`, so a slice copying a mailbox
of many gigabytes never holds up the timed fetch of it or of any other. A slice takes it
with TRY-lock, as the fetch takes its own; a deletion takes it BLOCKING after the fetch's,
and a discard BLOCKING alone, so both wait for a slice in progress. Nothing takes the two
the other way round, so they never deadlock.

⛔ THE IMPORT HAS A LOCK OF ITS OWN TOO, `IMPORT`, keyed by the DOMAIN's id, not a
mailbox's: one import of a domain at a time, taken with TRY-lock by `maildivvy-import`.
Deleting the domain, a mailbox in it or a person holding one takes it BLOCKING, before
any row lock of its own, so the import's writes never wait on a row the deletion holds;
the import stops as soon as it sees such a deletion asked for, so the wait is short.
"""

NAMESPACE = 0x6D66  # 'mf': the fetch's
SNAPSHOT = 0x6D73   # 'ms': the snapshot's
IMPORT = 0x6D69     # 'mi': the import's, by domain id


def try_lock(cursor, mailbox_id, namespace=NAMESPACE):
    """Take the mailbox's lock if it is free; False when another runner holds it."""
    cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", (namespace, int(mailbox_id)))
    return bool(cursor.fetchone()[0])


def xact_lock(cursor, mailbox_id, namespace=NAMESPACE):
    """Wait for the mailbox's lock and hold it until this transaction ends:
    what a deletion and a discard take, and the only blocking take there is.

    ⛔ A deletion must keep the fetcher out until its own drain COMMITS, or the runner
    takes the freed lock and rewrites the state directory the deletion is about to remove,
    while the delete is still uncommitted (measured on the predecessor). A
    transaction-level advisory lock is released by the commit or rollback itself, never by
    a hand that runs before it; it shares the namespace with `try_lock`, so the fetcher's
    try-lock still fails while it is held.
    """
    cursor.execute("SELECT pg_advisory_xact_lock(%s, %s)", (namespace, int(mailbox_id)))


def unlock(cursor, mailbox_id, namespace=NAMESPACE):
    cursor.execute("SELECT pg_advisory_unlock(%s, %s)", (namespace, int(mailbox_id)))
    return bool(cursor.fetchone()[0])
