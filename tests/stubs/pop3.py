"""A stub POP3 provider over implicit TLS, for the real mpop to fetch from.

The mailbox is a directory: each file is one message, its name the UIDL, its
modification time the moment it arrived at the provider. Files are offered sorted
by name; a name starting with `.` is ignored, so a test writes one and renames it.
A name may hold a space, as a real identifier may.

Control file (JSON, read again at every session):

- `user`, `password`: the one account. The login is compared byte for byte.
- `recent_days` (30): a login `recent:<user>` opens the same account in recent mode,
  which offers only the messages that arrived in the last N days, on every session,
  whatever was retrieved before. A plain `<user>` login offers every
  message until it is deleted.
- `login_delay`: advertised in CAPA as `LOGIN-DELAY n`. Only with
  `enforce_login_delay` is a login within n seconds of the last accepted one refused,
  with `-ERR [LOGIN-DELAY]`; a provider was measured declaring it and not enforcing it.
- `faults`: a list of `{"command", "uidl" (optional), "action"}`. The first one whose
  command matches, and whose uidl is the message the command's number names, acts:
  `err` answers `-ERR` (on PASS the same `-ERR [AUTH]` as a wrong password), `drop`
  closes without answering, `truncate` sends `+OK` and half the message then closes,
  `hang` does the same as truncate for RETR and sends nothing for any other command,
  then keeps the connection open, silent, until the client leaves or the stub stops.

DELE is done as RFC 1939 says: marked, undone by RSET, and the file removed only when
the client sends QUIT; a session that ends any other way deletes nothing. The log has
every command received, the PASS argument included, and the events `maildrop` (mode
and the UIDLs offered at login) and `deleted`.
"""

import time
from pathlib import Path

from stubserver import Stub, main

CRLF = b"\r\n"
RECENT = "recent:"


def served(body):
    """The message as sent: CRLF line ends. Its length is the size LIST and STAT report."""
    lines = body.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    return b"".join(line.rstrip(b"\r") + CRLF for line in lines)


def stuffed(message):
    return b"".join((b"." + line if line.startswith(b".") else line) + CRLF
                    for line in message.split(CRLF)[:-1])


class POP3Stub(Stub):
    name = "pop3"

    def __init__(self, mailbox, **kwargs):
        super().__init__(**kwargs)
        self.mailbox = Path(mailbox)
        self._last_login = None

    def messages(self, recent_days=None):
        """[(uidl, bytes as served)], every message or those of the last `recent_days`."""
        since = None if recent_days is None else time.time() - recent_days * 86400
        found = []
        for path in sorted(self.mailbox.iterdir(), key=lambda p: p.name):
            if path.name.startswith(".") or not path.is_file():
                continue
            if since is not None and path.stat().st_mtime < since:
                continue
            found.append((path.name, served(path.read_bytes())))
        return found

    def session(self, conn, number):
        conn.starttls(self.tls)
        control = self.control()
        conn.send(b"+OK maildivvy stub POP3 ready" + CRLF)
        session = _Session(self, conn, number, control)
        while True:
            line = conn.readline()
            if not line:
                return
            verb, argument = self.record(number, line)
            if not session.handle(verb, argument):
                return


class _Session:
    def __init__(self, stub, conn, number, control):
        self.stub, self.conn, self.number, self.control = stub, conn, number, control
        self.login = None
        self.maildrop = None  # [(uidl, bytes)] once logged in
        self.deleted = set()

    def reply(self, line):
        self.conn.send(line.encode() + CRLF)

    def message(self, argument):
        """The (index, uidl, bytes) a message number names, or None."""
        try:
            index = int(argument) - 1
        except ValueError:
            return None
        if self.maildrop is None or not 0 <= index < len(self.maildrop) or index in self.deleted:
            return None
        return (index, *self.maildrop[index])

    def fault(self, verb, argument):
        for fault in self.control.get("faults", []):
            if fault["command"].upper() != verb:
                continue
            if "uidl" in fault:
                found = self.message(argument)
                if found is None or found[1] != fault["uidl"]:
                    continue
            return fault["action"]
        return None

    def handle(self, verb, argument):
        """Answer one command; False ends the session."""
        action = self.fault(verb, argument)
        if action is not None:
            self.stub.log.write(stub="pop3", session=self.number, event="fault",
                                on=verb, action=action)
            if action == "err":
                self.reply("-ERR [AUTH] authentication failed" if verb == "PASS"
                           else "-ERR fault scripted by the stub")
                return True
            if action == "drop":
                return False
            found = self.message(argument) if verb == "RETR" else None
            if found is not None:
                body = found[2]
                self.reply(f"+OK {len(body)} octets")
                self.conn.send(body[:len(body) // 2])
            if action == "hang":
                self.conn.hold()
            return False
        if verb == "QUIT":
            return self.quit()
        handler = getattr(self, "do_" + verb.lower(), None)
        if handler is None:
            self.reply("-ERR unknown command")
        elif self.maildrop is None and verb not in ("CAPA", "USER", "PASS", "AUTH"):
            self.reply("-ERR not logged in")
        elif self.maildrop is not None and verb in ("USER", "PASS", "AUTH"):
            self.reply("-ERR already logged in")
        else:
            handler(argument)
        return True

    def do_capa(self, argument):
        lines = ["+OK capability list follows", "USER", "UIDL", "RESP-CODES"]
        if self.control.get("login_delay") is not None:
            lines.append(f"LOGIN-DELAY {self.control['login_delay']}")
        for line in [*lines, "."]:
            self.reply(line)

    def do_auth(self, argument):
        self.reply("-ERR no SASL mechanism; use USER and PASS")

    def do_user(self, argument):
        self.login = argument
        self.reply("+OK")

    def do_pass(self, argument):
        user = self.control["user"]
        recent = self.login == RECENT + user
        if self.login not in (user, RECENT + user) or argument != self.control["password"]:
            self.reply("-ERR [AUTH] authentication failed")
            return
        delay = self.control.get("login_delay")
        now = time.monotonic()
        last = self.stub._last_login
        if (self.control.get("enforce_login_delay") and delay is not None
                and last is not None and now - last < delay):
            self.reply("-ERR [LOGIN-DELAY] minimum time between logins not reached")
            return
        self.stub._last_login = now
        self.maildrop = self.stub.messages(self.control.get("recent_days", 30) if recent else None)
        self.stub.log.write(stub="pop3", session=self.number, event="maildrop",
                            mode="recent" if recent else "plain",
                            uidls=[uidl for uidl, _ in self.maildrop])
        self.reply(f"+OK {len(self.maildrop)} messages")

    def live(self):
        return [(i, uidl, body) for i, (uidl, body) in enumerate(self.maildrop)
                if i not in self.deleted]

    def do_stat(self, argument):
        live = self.live()
        self.reply(f"+OK {len(live)} {sum(len(body) for _, _, body in live)}")

    def listing(self, argument, value):
        if argument:
            found = self.message(argument)
            if found is None:
                self.reply("-ERR no such message")
            else:
                self.reply(f"+OK {found[0] + 1} {value(found)}")
            return
        self.reply("+OK listing follows")
        for found in self.live():
            self.reply(f"{found[0] + 1} {value(found)}")
        self.reply(".")

    def do_list(self, argument):
        self.listing(argument, lambda found: len(found[2]))

    def do_uidl(self, argument):
        self.listing(argument, lambda found: found[1])

    def do_retr(self, argument):
        found = self.message(argument)
        if found is None:
            self.reply("-ERR no such message")
            return
        self.reply(f"+OK {len(found[2])} octets")
        self.conn.send(stuffed(found[2]) + b"." + CRLF)

    def do_dele(self, argument):
        found = self.message(argument)
        if found is None:
            self.reply("-ERR no such message")
            return
        self.deleted.add(found[0])
        self.reply(f"+OK message {found[0] + 1} deleted")

    def do_rset(self, argument):
        self.deleted.clear()
        self.reply("+OK")

    def do_noop(self, argument):
        self.reply("+OK")

    def quit(self):
        if self.maildrop is not None and self.deleted:
            gone = sorted(self.maildrop[i][0] for i in self.deleted)
            for uidl in gone:
                (self.stub.mailbox / uidl).unlink(missing_ok=True)
            self.stub.log.write(stub="pop3", session=self.number, event="deleted", uidls=gone)
        self.reply("+OK bye")
        return False


def _arguments(parser):
    parser.add_argument("--mailbox", required=True, help="directory of messages")


if __name__ == "__main__":
    main("Stub POP3 provider over implicit TLS.",
         lambda args, **kw: POP3Stub(args.mailbox, **kw), _arguments)
