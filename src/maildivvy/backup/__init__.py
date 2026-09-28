"""The backup: the database and the fetcher's state, taken together.

`maildivvy-backup` pauses collection and fan-out, dumps the database and archives the
fetch state in the same run, judges both by what they hold, renames the pair into place,
runs the operator's store-copy command if one is set, and resumes. The message store
itself is never copied here: that is the operator's, and it must keep hardlinks and be
no older than the dump it is restored with.
"""
