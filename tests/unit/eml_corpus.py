"""A synthetic directory of message files for the import's tests.

Every address is under `example.org` or `example.net`, and every Message-ID is made up
here: nothing in it is anybody's mail. `corpus()` writes N messages with chosen
Message-IDs (repeated, missing), dates (zoned, unzoned, missing), CRLF and LF line ends
and a non-ASCII header, and, when asked, the files an import must refuse: an empty file,
a symlink, one with no header section. `line_ends()` is the messages that differ only in
how their lines end, for the size an imported name carries.
"""

import os
import re
from pathlib import Path
from typing import NamedTuple

ZONED = "Tue, 15 Mar 2016 09:00:00 +0300"        # 2016-03-15T06:00:00Z
ZONED_EPOCH = 1458021600
UNZONED = "Wed, 01 Jun 2016 12:00:00"            # read as UTC
UNZONED_EPOCH = 1464782400
# 2017-01-01T00:00:00Z, each file's mtime: after every Date here, as a file written out
# of an old store is, and the received moment of a message with no Date
MTIME = 1483228800


class Made(NamedTuple):
    path: Path
    message_id: str | None
    received: int | None   # the moment an import should read, or None for a refused file


def message(n, message_id="default", date=ZONED, crlf=True, subject=None, body=None):
    """One message's bytes. `message_id` "default" is `<n@example.org>`, None none."""
    if message_id == "default":
        message_id = f"<corpus-{n}@example.org>"
    lines = [f"From: Sender {n} <sender{n}@example.net>", "To: archive@example.org",
             f"Subject: {subject or f'Message {n}'}"]
    if date is not None:
        lines.append(f"Date: {date}")
    if message_id is not None:
        lines.append(f"Message-ID: {message_id}")
    lines += ["MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "",
              body or f"The body of message {n}.", ""]
    return ("\r\n" if crlf else "\n").join(lines).encode()


def virtual_size(data):
    """The size Dovecot gives a message over IMAP, where every line ends CR LF: its bytes
    plus one for each line feed no carriage return precedes. Said another way than the
    import counts it, to check that count."""
    return len(data) + len(re.findall(rb"(?<!\r)\n", data))


def line_ends(n=1, astride=None):
    """Messages that differ in their line ends, by what each is: every line CR LF, every
    line a bare LF, both in one body, carriage returns alone (in a CR LF message and in an
    LF one), no line end at the end, a carriage return as the last byte; and, with
    `astride`, one whose CR is the byte before that offset and its LF the byte at it, for
    a reader that takes the file in chunks of that size."""

    def one(name, **shape):
        return message(n, message_id=f"<ends-{name}-{n}@example.org>", **shape)

    made = {
        "crlf": one("crlf"),
        "lf": one("lf", crlf=False),
        "mixed": one("mixed", body="a bare line feed\nthen a whole line end\r\nthen a bare one\n"),
        "bare-cr": one("bare-cr", body="a carriage return\ralone, two\r\rtogether, one at the end\r"),
        "lf-bare-cr": one("lf-bare-cr", crlf=False, body="a carriage return\ralone among line feeds"),
        "no-final-newline": one("no-final-newline", crlf=False)[:-1],
        "ends-in-cr": one("ends-in-cr")[:-1],
    }
    if astride is not None:
        after = "\r\nand a line after it"
        at = one("astride", body="x" + after).index(b"x\r\nand")
        made["astride"] = one("astride", body="x" * (astride - 1 - at) + after)
        assert made["astride"][astride - 1:astride + 1] == b"\r\n"
    return made


def write(directory, name, data, mtime=MTIME):
    path = Path(directory) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.utime(path, (mtime, mtime))
    return path


def corpus(directory, n=6, refusals=True):
    """Write the corpus into `directory`; returns what each file is, in sorted path order.

    The first `n` messages cycle through the shapes below; then two copies of message 1
    (one with the same Message-ID and other bytes, one with the same bytes), and, with
    `refusals`, the three files an import must refuse.
    """
    directory = Path(directory)
    made = []
    shapes = [
        dict(date=ZONED, crlf=True),                               # the ordinary one
        dict(date=UNZONED, crlf=False),                            # LF, a date with no zone
        dict(date=None, crlf=True),                                # no Date: the mtime
        dict(message_id=None, date=ZONED, crlf=False),             # no Message-ID
        dict(date=ZONED, crlf=True, subject="Привет, мир"),        # a non-ASCII header
        dict(date="not a date at all", crlf=True),                 # an unreadable Date
    ]
    for i in range(n):
        shape = dict(shapes[i % len(shapes)])
        number = i + 1
        data = message(number, **shape)
        path = write(directory / f"box{number % 2}", f"{number:04d}.eml", data)
        message_id = shape.get("message_id", "default")
        message_id = f"<corpus-{number}@example.org>" if message_id == "default" else message_id
        date = shape.get("date")
        received = {ZONED: ZONED_EPOCH, UNZONED: UNZONED_EPOCH}.get(date, MTIME)
        made.append(Made(path, message_id, received))
    first = message(1)
    made.append(Made(write(directory / "copies", "same-bytes.eml", first),
                     "<corpus-1@example.org>", ZONED_EPOCH))
    made.append(Made(write(directory / "copies", "same-id.eml",
                           message(1, body="Other words, the same Message-ID.")),
                     "<corpus-1@example.org>", ZONED_EPOCH))
    if refusals:
        made.append(Made(write(directory, "empty.eml", b""), None, None))
        made.append(Made(write(directory, "mbox.eml", b"From someone Tue Mar 15 2016\n" + first),
                         None, None))
        link = directory / "link.eml"
        link.symlink_to(made[0].path)
        made.append(Made(link, None, None))
    return sorted(made, key=lambda m: m.path.relative_to(directory).as_posix())
