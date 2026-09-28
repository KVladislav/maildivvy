"""The thin pymilter shell. Every decision is `decision.py`'s.

⛔ THE SHELL HOLDS NO LOGIC. `@Milter.noreply` reads
`self._protocol`, which exists only once the library's harness has bound the instance,
so a decorated method called on a hand-built object raises AttributeError and a suite
that drives the class is testing the harness. The header collection therefore lives in
a plain method the decorated one delegates to, and the two decisions are module-level
functions elsewhere.

⚠️ The order is the design's: the sender is bound at end of headers, so a message refused
for its sender is never scanned and the client is refused before it sends a body. The
scan runs at end of data, before Postfix queues anything.

⚠️ THE MILTER ASKS FOR NO PERMISSION TO CHANGE ANYTHING: no flags
are negotiated, so the library cannot add, change or delete a header even by mistake.
"""

import sys

import Milter

from maildivvy.lib import scan
from maildivvy.milter.decision import CONTINUE, REJECT, decide, decide_scan, sender_lookup

NAME = "maildivvy-milter"
TIMEOUT = 300  # seconds libmilter waits on the MTA; Postfix's own content timeout


def text_of(value):
    """A header name or value as text, whichever the library hands over."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return "" if value is None else str(value)


class SenderBinding(Milter.Base):
    """One connection. Everything it collects is reset for each message it carries."""

    def __init__(self):
        self.login = None
        self.headers = []
        self.from_headers = []
        self.chunks = []
        self.sender = None

    @Milter.noreply
    def connect(self, hostname, family, hostaddr):
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, mailfrom, *parameters):
        # ⛔ one connection carries several messages, and one message's headers must not
        # leak into the next
        self.from_headers = []
        self.headers = []
        self.chunks = []
        self.sender = None
        self.login = self.getsymval("{auth_authen}") or ""
        return Milter.CONTINUE

    def note_header(self, name, value):
        """The collection, callable without the library's harness."""
        name, value = text_of(name), text_of(value)
        self.headers.append((name, value))
        if name.lower() == "from":
            self.from_headers.append(value)

    @Milter.noreply
    def header(self, name, value):
        self.note_header(name, value)
        return Milter.CONTINUE

    def eoh(self):
        return self.answer(decide(self.login, self.from_headers, LOOKUP))

    @Milter.noreply
    def body(self, chunk):
        self.chunks.append(bytes(chunk))
        return Milter.CONTINUE

    def eom(self):
        # our own server scans what a person submits, before it is queued
        verdict = scan.scan_virus(self.message(), path=CLAMD_SOCKET)
        unscanned = self.sender.outbound_unscanned if self.sender else None
        return self.answer(decide_scan(verdict, unscanned))

    def abort(self):
        return Milter.CONTINUE

    def close(self):
        return Milter.CONTINUE

    # --- the two plain helpers -------------------------------------------------------

    def message(self):
        """The bytes the antivirus is handed: the headers as they came, then the body."""
        head = "".join(f"{name}: {value}\r\n" for name, value in self.headers)
        return head.encode("utf-8", "replace") + b"\r\n" + b"".join(self.chunks)

    def answer(self, decided):
        if decided.action == CONTINUE:
            self.sender = decided.sender or self.sender
            return Milter.CONTINUE
        self.setreply(decided.code, decided.dsn, decided.text)
        return Milter.REJECT if decided.action == REJECT else Milter.TEMPFAIL


LOOKUP = None
CLAMD_SOCKET = scan.CLAMD_SOCKET


def serve(socket_path, db_conf, clamd_socket):
    """Bind the socket and answer until the machine stops us."""
    global LOOKUP, CLAMD_SOCKET
    LOOKUP = sender_lookup(db_conf)
    CLAMD_SOCKET = clamd_socket
    Milter.factory = SenderBinding
    # ⛔ no flags: this program may not change a message, and does not ask to
    Milter.set_flags(0)
    sys.stderr.write(f"{NAME}: listening on {socket_path}, sender directory {db_conf}\n")
    sys.stderr.flush()
    Milter.runmilter(NAME, str(socket_path), TIMEOUT)
    return 0
