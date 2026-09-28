"""The one lock every last-administrator decision takes.

⛔ ONE KEY, IMPORTED BY BOTH SIDES. The interface counts the active administrators when it
revokes, blocks or queues a deletion; the pipeline counts them again when it performs a
deletion. Each takes this transaction-level advisory lock BEFORE it counts, so two such
decisions never read the same count: the second waits for the first to commit, then
counts what it left. An advisory lock needs no table privilege, so the pipeline - which
may read and delete a person but not update one - can take it; a row lock
(`FOR UPDATE`) would need UPDATE on `account`, which it deliberately does not hold.
It is released by the commit or the rollback itself.
"""

NAMESPACE = 0x6D61   # 'ma'
KEY = 7


def lock(cursor):
    """Wait for the last-administrator lock; held until this transaction ends."""
    cursor.execute("SELECT pg_advisory_xact_lock(%s, %s)", (NAMESPACE, KEY))
