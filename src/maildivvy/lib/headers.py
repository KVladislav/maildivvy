"""Reading a header's value, and the fields of the verdict block, for every program.

The delivery filter writes the block (`deliver/marks.py`), the pass reads it back
through Dovecot, and the pass and the Sent hook both turn a message's own headers into
a ledger row. Each reads through this module, so no two of them can come to disagree
about one message: the names of our own fields, how the first occurrence of a header is
told from a folded line, and what the sender and the date of a message are.

⛔ OF OUR OWN FIELDS ONLY THE FIRST LINE IS READ: the filter prepends its
block and strips nothing, so a sender's own copy of any of those names is still in the
message, below ours. doveadm hands a field back with its newlines inside it,
so both occurrences arrive in one string.
"""

import datetime
import email.utils

# The verdict block's fields that are read back, written by the filter into every
# message it files (`deliver/marks.py`).
SPAM_MARK_HEADER = "X-Maildivvy-Spam-Mark"
SPAM_SCORE_HEADER = "X-Maildivvy-Spam-Score"
WITHHELD_HEADER = "X-Maildivvy-Withheld-Id"
REASON_HEADER = "X-Maildivvy-Report-Reason"
# ⛔ What the filter's own block says in both fields when the message is not a report,
# or not withheld. A field the pass reads is trusted in its
# first occurrence, which is ours only if we wrote one; left out, the first occurrence
# was the sender's, and a sender's reason made clean mail a report.
NONE = "none"


def field(header):
    """A header as doveadm's fetch asks for it: `hdr.` and one lowercase word."""
    return f"hdr.{header.lower()}"


MARK_FIELD = field(SPAM_MARK_HEADER)
SCORE_FIELD = field(SPAM_SCORE_HEADER)
WITHHELD_FIELD = field(WITHHELD_HEADER)
REASON_FIELD = field(REASON_HEADER)


# ⛔ NO VALUE READ HERE CARRIES A NUL OR ANOTHER C0 CONTROL CHARACTER BUT THE TAB.
# PostgreSQL holds no NUL in a text, and the driver refuses a string holding one before
# the server is asked, with an error that has no SQLSTATE: one such byte in a subject made
# a message unrecordable for whoever read it raw, the Sent hook and the command that
# records a message by hand alike. A NUL becomes U+FFFD, which is what Dovecot hands the
# pass for one (measured on 2.4.2), so a program that reads the file itself, the Sent
# hook or the import looking for a Message-ID the ledger holds, reads what the pass
# stored. No header's meaning is in any other control character, and those are removed.
CONTROLS = {code: None for code in range(0x20) if code != 0x09} | {0x00: "\ufffd"}


def first_occurrence(value):
    """The first occurrence of a header, unfolded, without its control characters
    (`CONTROLS`); every later one is dropped.

    doveadm hands a field back with its newlines inside it, so both a
    folded value's continuation lines and a second occurrence of the name arrive in one
    string. A continuation line begins with whitespace and a second occurrence does
    not, which is what tells them apart: read of the lines as they came, before any
    character is removed from one.
    """
    lines = (value or "").split("\n")
    parts = [lines[0]] if lines else []
    for line in lines[1:]:
        if not line[:1].isspace():
            break
        parts.append(line)
    parts = [part.translate(CONTROLS).strip() for part in parts]
    return " ".join(part for part in parts if part)


def first_line(value):
    """The first line of one of OUR OWN headers, without its control
    characters (`CONTROLS`). Never the sender's second."""
    return (value or "").split("\n")[0].translate(CONTROLS).strip()


def ours_or_none(value):
    """The withheld id or the reason, where the filter's `none` means there is nothing.

    The filter writes both into every message it files with its block, so
    that a sender's copy is never the first occurrence.
    """
    value = first_line(value)
    return None if value in ("", NONE) else value


def sender_of(value):
    """The parsed address of the From header, lower-cased and never folded.

    In `From: acme@gmail.com <impostor@example.net>` the display name looks like the
    address, and the first address-shaped token is the display name. The
    library is asked first, because it reads quoting and comments properly; where it
    finds no address at all - which is what a display name holding an `@` makes of the
    field - the angle-addr is taken instead, because that is the address a reader sees.
    ⚠️ `email.message`'s own header parser answers `acme@gmail.com` for that field: the
    display name, which is precisely the value this rule exists to keep out of the
    ledger.

    A From that parses to no address at all stores nothing, and that is not an error:
    nothing that delivers reads this column.
    """
    value = first_occurrence(value)
    try:
        address = email.utils.parseaddr(value)[1]
    except Exception:  # noqa: BLE001 - reading is total
        address = ""
    if "@" not in address:
        start, end = value.find("<"), value.find(">", value.find("<") + 1)
        address = value[start + 1:end] if start != -1 and end != -1 else ""
    return address.lower() if "@" in address else None


def date_of(value):
    """The message's own date, or None for one that has none or will not parse.

    ⚠️ Every exception: the standard library's parser documents TypeError and ValueError,
    and raises OverflowError for an offset or a year it cannot hold.

    ⛔ A date with no zone, or with `-0000`, is UTC: the parser hands it back
    naive, and a naive value written to a timestamptz is read in the database's own zone,
    which is the machine's.
    """
    try:
        date = email.utils.parsedate_to_datetime(first_occurrence(value))
    except Exception:  # noqa: BLE001 - its failures are not a closed list
        return None
    return date if date.tzinfo else date.replace(tzinfo=datetime.timezone.utc)
