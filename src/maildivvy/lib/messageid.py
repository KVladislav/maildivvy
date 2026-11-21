"""The form the ledger stores a Message-ID in, for every program that writes or looks one up.

`message.message_id_header` sits under a btree index, and PostgreSQL refuses an index
entry over 2704 bytes: one incoming message with a longer Message-ID failed its row's
INSERT, and with it the domain's whole fan-out, every minute. Nothing reads the column
for its text, only to match one message's header against another's, so a header past
the bound is stored as a digest of the whole value: the same header always gives the
same stored form, and no stored form can exceed the index's limit.

⛔ EVERY WRITER AND EVERY LOOKUP BY VALUE GOES THROUGH `stored` (the pass and the Sent
hook). A lookup that used the header as it is would never match a digest. A row written
before this bound existed may hold a longer header as it is; the Sent hook's "already
recorded" check misses that one row, which can only record a sent message twice.
"""

import hashlib

# Characters: at four bytes each, 2048 bytes, under the index's 2704 with the domain's id.
BOUND = 512


def stored(header):
    """The header as it is up to BOUND characters, else `sha256:<hex>` of all of it; None
    for none."""
    if not header:
        return None
    if len(header) <= BOUND:
        return header
    return "sha256:" + hashlib.sha256(header.encode("utf-8", "surrogatepass")).hexdigest()
