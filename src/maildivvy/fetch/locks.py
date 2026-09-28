"""The advisory lock namespace the fetch and a deletion share.

⛔ ONE CONSTANT, IMPORTED BY BOTH SIDES. The fetcher takes the lock with
TRY-lock and skips a mailbox whose lock is held, because it runs from a timer and a
queue of waiting runners turns one slow provider into a pile of processes.
Deleting an external mailbox takes the SAME lock BLOCKING, before it removes the row
and the fetcher's state: the runner renders from rows it read at the start of its run,
so a delete that lands mid-run has the state directory recreated a second later and the
state outlives the row (measured on the predecessor). Two namespaces would mean
the two locks never meet, which is why neither side spells the number itself.
"""

NAMESPACE = 0x6D66  # 'mf'


def try_lock(cursor, mailbox_id):
    """Take the mailbox's lock if it is free; False when another runner holds it."""
    cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", (NAMESPACE, int(mailbox_id)))
    return bool(cursor.fetchone()[0])


def lock(cursor, mailbox_id):
    """Wait for the mailbox's lock. What a deletion uses."""
    cursor.execute("SELECT pg_advisory_lock(%s, %s)", (NAMESPACE, int(mailbox_id)))


def xact_lock(cursor, mailbox_id):
    """Wait for the mailbox's lock and hold it until this transaction ends.

    ⛔ A deletion must keep the fetcher out until its own drain COMMITS, or the runner
    takes the freed lock and rewrites the state directory the deletion is about to remove,
    while the delete is still uncommitted (measured on the predecessor). A
    transaction-level advisory lock is released by the commit or rollback itself, never by
    a hand that runs before it; it shares the namespace with `try_lock`, so the fetcher's
    try-lock still fails while it is held.
    """
    cursor.execute("SELECT pg_advisory_xact_lock(%s, %s)", (NAMESPACE, int(mailbox_id)))


def unlock(cursor, mailbox_id):
    cursor.execute("SELECT pg_advisory_unlock(%s, %s)", (NAMESPACE, int(mailbox_id)))
    return bool(cursor.fetchone()[0])
