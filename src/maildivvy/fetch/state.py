"""mpop's UIDL state file: what it has already retrieved, and how a skip is written into it.

⛔ THE FILE IS MPOP'S, NOT OURS. It is what suppresses duplicates - a
provider that offers thirty days again on every poll shows the fetcher each message
dozens of times - so it is backed up with the database and never treated as a cache.
Every rule below copies mpop's own source rather than guessing at one, because mpop
rewrites the file on its next run and a disagreement is a message delivered twice.

⛔ A LINE IS SPLIT ON THE LAST SPACE. mpop 1.4.23 writes `<uid> <epoch>`
and 1.4.21 wrote the identifier alone, and a POP3 identifier may itself hold spaces
(`pop3.c:1059-1063`). `split()[0]` reads `has` out of `has a space 1757000000`, and the
runner then believes a message it has already seen is new. `uidls.c:313` splits with
`strrchr`, and this is that rule.

⛔ A FILE WITH NO HEADER LINE IS VALID: mpop that has retrieved nothing
writes the comment block and nothing else, which is exactly the mailbox stopped on its
very first message. The header is then written from the host and login the runner
rendered, never guessed. A missing file, or more than one header, is an error.

⛔ ONLY THE UIDL BLOCK OF A LISTING IS READ. LIST's answer has the same
`<-- n value` shape and comes first, so grepping the whole conversation mixes sizes in
with identifiers.
"""

import contextlib
import os
import re
import time
from pathlib import Path

LISTING_LINE = re.compile(r"^<-- (\d+) (\S.*)$")
UIDL_COMMAND = "--> UIDL"
END_OF_BLOCK = "<-- ."


class StateError(Exception):
    """A state file that cannot be written safely. The message names the file."""


def path_of(state):
    return Path(state) / "uidls"


def identifier_of(line):
    """The identifier in one state-file line, split on the LAST space."""
    identifier, space, _first_seen = line.rpartition(" ")
    return identifier if space else line


def known_identifiers(path):
    """Every identifier the file holds: neither a comment nor the header."""
    path = Path(path)
    if not path.exists():
        return set()
    return {identifier_of(line) for line in path.read_text().splitlines()
            if line and not line.startswith("#") and not line.startswith(" ")}


def parse_listing(text):
    """The (number, identifier) pairs of the UIDL block, and nothing outside it."""
    pairs, inside = [], False
    for line in text.splitlines():
        if line.startswith(UIDL_COMMAND):
            pairs, inside = [], True
            continue
        if not inside:
            continue
        if line == END_OF_BLOCK:
            inside = False
            continue
        found = LISTING_LINE.match(line)
        if found:
            pairs.append((int(found.group(1)), found.group(2)))
    return pairs


def choose_stuck(pairs, known, number):
    """(identifier, None) or (None, complaint): the message the mailbox is stuck on.

    It is the first offered identifier the state file does not hold. When mpop named a
    message number, the identifier must sit at that number: a message deleted at the
    provider between the failing run and the listing shifts the numbering, and a healthy
    neighbour's identifier would be skipped instead.
    """
    for offered, identifier in pairs:
        if identifier in known:
            continue
        if number is not None and offered != number:
            return None, "listing disagrees with the failing message number"
        return identifier, None
    return None, "listing offers nothing absent from the state file"


@contextlib.contextmanager
def listing_copy(state):
    """A 0600 copy of the state file for the listing session, removed on the way out.

    ⛔ The listing runs against the COPY, never the real file: mpop marks
    every identifier it already knows for deletion at UIDL time, and a session that
    nevertheless deleted something must not be able to record it.
    """
    real = path_of(state)
    copy = Path(state) / "uidls.listing"
    handle = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "wb") as out:
        out.write(real.read_bytes() if real.exists() else b"")
    try:
        yield copy
    finally:
        with contextlib.suppress(FileNotFoundError):
            copy.unlink()


def record_skip(state, identifier, host, user, now=None):
    """Write one identifier into the state file as if it had been retrieved.

    ⛔ THE TIME IS THE ORDINARY ONE. A skipped message is not sheltered:
    it is deleted at the provider when the window since this moment has passed, without
    ever having been delivered, and the row records the identifier so the operator can
    see which and when. A sentinel far in the future would spare it for ever and would
    put a value in mpop's state that is not a first-sighting time.

    The write is atomic: a 0600 temporary file in the same directory, fsynced, then
    renamed over the real one. Returns False when the file already held
    the identifier.
    """
    path = path_of(state)
    if not path.exists():
        raise StateError(f"{path} does not exist; mpop has never written it")
    lines = path.read_text().splitlines()
    headers = [i for i, line in enumerate(lines) if line.startswith(" ")]
    if len(headers) > 1:
        raise StateError(f"{path} carries {len(headers)} UID list headers, not one")
    entry = f"{identifier} {int(time.time() if now is None else now)}"

    if not headers:
        # the mailbox stopped on its very first message.
        comments = [line for line in lines if line.startswith("#")]
        _replace(state, path, [*comments, f" 1 {host} {user}", entry])
        return True

    at = headers[0]
    parts = lines[at].split()
    if len(parts) != 3 or not parts[0].isdigit():
        raise StateError(f"{path}: header {lines[at]!r} does not parse")
    identifiers = [line for line in lines[at + 1:] if line and not line.startswith("#")]
    if identifier in {identifier_of(line) for line in identifiers}:
        return False
    # Sorted by IDENTIFIER, which is how mpop's own qsort will rewrite the file.
    identifiers = sorted([*identifiers, entry], key=identifier_of)
    header = f" {len(identifiers)} {parts[1]} {parts[2]}"
    _replace(state, path, [*lines[:at], header, *identifiers])
    return True


def _replace(state, path, lines):
    temporary = Path(state) / f"uidls.tmp.{os.getpid()}"
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(handle, "w") as out:
            out.write("\n".join(lines) + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise
