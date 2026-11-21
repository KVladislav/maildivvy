"""A stub IMAP provider over implicit TLS, which accepts only the commands that read.

The account is a directory. Each folder is a directory in it, its IMAP name the path
from the account with `/` as the delimiter (`INBOX`, `Archive/2025`), and each file in
a folder is one message: its name the UID, in decimal digits, and its modification time
the INTERNALDATE. A file whose name is not digits is ignored, so a test writes `.5` and
renames it. The INBOX is always there, with or without its directory. Files are read
when a command asks for them, so a message removed between `UID SEARCH` and `UID FETCH`
is expunged, as at a real server.

⛔ ONLY THE COMMANDS THAT READ ARE ACCEPTED: CAPABILITY, LOGIN, AUTHENTICATE PLAIN, LIST,
EXAMINE, UID SEARCH, UID FETCH, NOOP and LOGOUT, and in a FETCH only the items it serves,
none of which sets a flag: BODY.PEEK[], FLAGS, INTERNALDATE, RFC822.SIZE and UID (the
size the client asks before the body, a count the server keeps). Anything else is
answered BAD and logged as the event `refused`, so a test that finds no such event in the
log has proved that nothing able to change a mailbox reached the provider.

It serves what the client sends and no more: LIST `"" "*"`, and a UID set of one number,
one range (`2:4`) or `*`, either end of a range `*`; anything else is answered BAD.

Control file (JSON, read again at every session):

- `user`, `password`: the one account, compared byte for byte, by LOGIN or by
  AUTHENTICATE PLAIN.
- `plain` (true): whether AUTH=PLAIN is advertised; false leaves LOGIN alone.
- `uidvalidity`: {folder: number}, 1 for a folder it does not name, null for none said at
  all. Rewriting it between sessions is how a provider renumbers a folder.
- `attributes`: {folder: [attribute, ...]}, what LIST answers, `\\Noselect` or `\\All` for
  example. A folder named here is listed even with no directory; one marked `\\Noselect`
  or `\\NonExistent` cannot be examined.
- `delimiter` ("/"): the hierarchy delimiter LIST answers, null for NIL. Only what LIST
  says changes: a folder's name is still its directory's path joined by `/`, so under
  another delimiter a nested directory is one folder whose name holds `/`.
- `flags`: {folder: {uid: [flag, ...]}}, what FETCH answers for FLAGS.
- `faults`: a list of `{"command", "uid" (optional), "folder" (optional), "action"}`. The
  first one whose command matches the logged one (`UID FETCH` for a fetch), and whose uid
  and folder are the message's (for EXAMINE, the folder it opens), acts; a `UID FETCH`
  fault acts on a fetch that asks for the body, and the size asked before it is answered
  as asked, unless the fault says `"on_size": true`:
  `no` answers NO, on a login the same `[AUTHENTICATIONFAILED]` as a wrong password and
  elsewhere with no response code, with the fault's `text` instead when it has one;
  `bad` answers BAD, with the fault's `text` when it has one;
  `drop` closes without answering;
  `bye` sends `* BYE` with the fault's `text` and closes, as Dovecot answers by default a
  message it cannot read (`* BYE FETCH failed: ...`);
  `hang` sends nothing and keeps the connection until the client leaves or the stub stops;
  and for UID FETCH only:
  `truncate` sends the literal's size and half the message, then closes;
  `expunged` answers OK with nothing for the message, as for one expunged since the
  search, and lists it no more in that session;
  `trickle` sends the message a byte at a time, `delay` (0.5) seconds apart;
  `late` sends nothing for `delay` (0.5) seconds, then the message whole, as Gmail once
  answered a large one after a minute;
  `flags-first` sends the message's flags in a response of their own before the message;
  `nobody` sends its flags alone, and no body;
  `no-uid` sends the message in a response that leaves its UID out;
  `date` sends the fault's `text` as the message's INTERNALDATE, a date no calendar holds
  or a month nobody spells so;
  `size` answers the fault's `size` as the message's RFC822.SIZE, and sends the body as
  it is, as a server whose size is not its literal's.

The log has every command line received, `UID` with its sub-command (`UID FETCH`), and
the events `auth` (mechanism, user, password, accepted), `refused` and `fault`. A UID
SEARCH answers by the RFC, so `UID n:*` above the largest UID answers the largest one.
"""

import base64
import binascii
import os
import re
import time
from pathlib import Path

from pop3 import served
from stubserver import Stub, main, text

CRLF = b"\r\n"
INBOX = "INBOX"
DELIMITER = "/"
ACCEPTED = {"CAPABILITY", "LOGIN", "AUTHENTICATE", "LIST", "EXAMINE", "UID SEARCH",
            "UID FETCH", "NOOP", "LOGOUT"}
SERVED = {"BODY.PEEK[]", "FLAGS", "INTERNALDATE", "RFC822.SIZE", "UID"}
UID_SET = re.compile(r"^(\d+|\*)(?::(\d+|\*))?$")
UNSELECTABLE = {"\\NOSELECT", "\\NONEXISTENT"}
LOGINS = ("LOGIN", "AUTHENTICATE")
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def strings(argument):
    """A command's arguments as strings: atoms, and quoted strings unescaped."""
    found, i = [], 0
    while i < len(argument):
        if argument[i] == " ":
            i += 1
        elif argument[i] == '"':
            value, i = [], i + 1
            while i < len(argument) and argument[i] != '"':
                if argument[i] == "\\" and i + 1 < len(argument):
                    i += 1
                value.append(argument[i])
                i += 1
            found.append("".join(value))
            i += 1
        else:
            end = argument.find(" ", i)
            end = len(argument) if end < 0 else end
            found.append(argument[i:end])
            i = end
    return found


def quoted(name):
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def in_set(uid, spec, largest):
    """Whether a UID is in a set of UID_SET's, such as `3`, `2:4` or `5:*`, `*` being the
    largest UID.

    A range is read in either order, so `5:*` holds the largest UID when it is below 5.
    """
    low, high = UID_SET.match(spec).groups()
    low = largest if low == "*" else int(low)
    high = low if high is None else largest if high == "*" else int(high)
    return min(low, high) <= uid <= max(low, high)


def internaldate(stamp):
    t = time.gmtime(stamp)
    return (f"{t.tm_mday:02d}-{MONTHS[t.tm_mon - 1]}-{t.tm_year} "
            f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} +0000")


class IMAPStub(Stub):
    name = "imap"

    def __init__(self, mailbox, **kwargs):
        super().__init__(**kwargs)
        self.mailbox = Path(mailbox)

    def folders(self, control):
        """{IMAP name: directory, or None for one named only by the control}, sorted."""
        found = {INBOX: self.mailbox / INBOX}
        # os.walk reads each directory's entries once, and stats none of its files: a folder
        # of 100,000 messages is listed in a fraction of a second
        for top, directories, _ in os.walk(self.mailbox):
            for name in directories:
                path = Path(top) / name
                found[path.relative_to(self.mailbox).as_posix()] = path
        for name in control.get("attributes", {}):
            found.setdefault(name, None)
        return dict(sorted(found.items()))

    @staticmethod
    def messages(folder):
        """[(uid, path)], ascending."""
        if folder is None or not folder.is_dir():
            return []
        with os.scandir(folder) as entries:
            return sorted((int(e.name), Path(e.path)) for e in entries
                          if e.name.isascii() and e.name.isdigit() and e.is_file())

    def session(self, conn, number):
        conn.starttls(self.tls)
        session = _Session(self, conn, number, self.control())
        session.reply(f"* OK [CAPABILITY {session.capabilities()}] maildivvy stub IMAP ready")
        while True:
            line = conn.readline()
            if not line or not session.handle(line):
                return


class _Session:
    def __init__(self, stub, conn, number, control):
        self.stub, self.conn, self.number, self.control = stub, conn, number, control
        self.user = None      # the login, once accepted
        self.selected = None  # the folder EXAMINE opened
        self.expunged = set()  # (folder, uid) of each message an `expunged` fault took away

    def reply(self, line):
        self.conn.send(line.encode() + CRLF)

    def log(self, **record):
        self.stub.log.write(stub="imap", session=self.number, **record)

    def capabilities(self):
        return "IMAP4rev1" + (" AUTH=PLAIN" if self.control.get("plain", True) else "")

    def fault(self, verb, uid=None, folder=None):
        for fault in self.control.get("faults", []):
            if fault["command"].upper() != verb:
                continue
            if "uid" in fault and fault["uid"] != uid:
                continue
            if "folder" in fault and fault["folder"] != (folder or self.selected):
                continue
            return fault
        return None

    def handle(self, line):
        """Answer one command line; False ends the session."""
        tag, _, rest = text(line).partition(" ")
        verb, _, argument = rest.partition(" ")
        verb = verb.upper()
        if verb == "UID":
            sub, _, argument = argument.partition(" ")
            verb = f"UID {sub.upper()}"
        self.log(command=verb, argument=argument)
        if verb not in ACCEPTED or verb == "AUTHENTICATE" and argument.upper() != "PLAIN":
            return self.refuse(tag, verb, argument, "the stub accepts only commands that read")
        opens = strings(argument)[:1] if verb == "EXAMINE" else []
        fault = None if verb == "UID FETCH" else self.fault(verb, folder=opens[0] if opens else None)
        if fault is not None:
            return self.act(tag, verb, fault)
        if verb in ("LIST", "EXAMINE") and self.user is None:
            self.reply(f"{tag} BAD not logged in")
            return True
        if verb.startswith("UID ") and self.selected is None:
            self.reply(f"{tag} BAD no mailbox examined")
            return True
        return getattr(self, "do_" + verb.lower().replace(" ", "_"))(tag, argument)

    def refuse(self, tag, verb, argument, why):
        self.log(event="refused", command=verb, argument=argument)
        self.reply(f"{tag} BAD refused: {why}")
        return True

    def act(self, tag, verb, fault, uid=None):
        """A scripted fault; False when it ends the session."""
        action = fault["action"]
        self.log(event="fault", on=verb, action=action, **({} if uid is None else {"uid": uid}))
        if action == "no":
            default = ("[AUTHENTICATIONFAILED] Authentication failed." if verb in LOGINS
                       else "fault scripted by the stub")
            self.reply(f"{tag} NO {fault.get('text', default)}")
            return True
        if action == "bad":
            self.reply(f"{tag} BAD {fault.get('text', 'fault scripted by the stub')}")
            return True
        if action == "bye":
            self.reply(f"* BYE {fault.get('text', 'fault scripted by the stub')}")
            return False
        if action == "hang":
            self.conn.hold()
        return False

    # --- the accepted commands

    def do_capability(self, tag, argument):
        self.reply(f"* CAPABILITY {self.capabilities()}")
        self.reply(f"{tag} OK CAPABILITY completed")
        return True

    def do_noop(self, tag, argument):
        self.reply(f"{tag} OK NOOP completed")
        return True

    def do_logout(self, tag, argument):
        self.reply("* BYE logging out")
        self.reply(f"{tag} OK LOGOUT completed")
        return False

    def authenticated(self, tag, mechanism, user, password):
        accepted = user == self.control["user"] and password == self.control["password"]
        self.log(event="auth", mechanism=mechanism, user=user, password=password,
                 accepted=accepted)
        if accepted:
            self.user = user
            self.reply(f"{tag} OK [CAPABILITY IMAP4rev1] logged in")
        else:
            self.reply(f"{tag} NO [AUTHENTICATIONFAILED] Authentication failed.")
        return True

    def do_login(self, tag, argument):
        words = strings(argument)
        if len(words) != 2:
            self.reply(f"{tag} BAD LOGIN takes a login and a password")
            return True
        return self.authenticated(tag, "LOGIN", *words)

    def do_authenticate(self, tag, argument):
        self.conn.send(b"+ " + CRLF)
        line = self.conn.readline()
        if not line:
            return False
        response = text(line)
        if response == "*":
            self.reply(f"{tag} BAD authentication cancelled")
            return True
        try:
            _authzid, user, password = base64.b64decode(response, validate=True).decode().split("\0")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            self.reply(f"{tag} BAD not a PLAIN response")
            return True
        return self.authenticated(tag, "PLAIN", user, password)

    def do_list(self, tag, argument):
        words = strings(argument)
        if words != ["", "*"]:
            self.reply(f'{tag} BAD the stub lists "" "*" only')
            return True
        attributes = self.control.get("attributes", {})
        delimiter = self.control.get("delimiter", DELIMITER)
        delimiter = "NIL" if delimiter is None else quoted(delimiter)
        for name in self.stub.folders(self.control):
            said = " ".join(attributes.get(name, []))
            self.reply(f"* LIST ({said}) {delimiter} {quoted(name)}")
        self.reply(f"{tag} OK LIST completed")
        return True

    def listing(self):
        return [(uid, path) for uid, path in
                self.stub.messages(self.stub.folders(self.control).get(self.selected))
                if (self.selected, uid) not in self.expunged]

    def do_examine(self, tag, argument):
        words = strings(argument)
        name = words[0] if len(words) == 1 else None
        if name is not None and name.upper() == INBOX:
            name = INBOX
        attributes = {a.upper() for a in self.control.get("attributes", {}).get(name, [])}
        self.selected = None
        if name not in self.stub.folders(self.control) or attributes & UNSELECTABLE:
            self.reply(f"{tag} NO [NONEXISTENT] no such mailbox, or it cannot be opened")
            return True
        self.selected = name
        uids = [uid for uid, _ in self.listing()]
        validity = self.control.get("uidvalidity", {}).get(name, 1)
        self.reply("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
        self.reply("* OK [PERMANENTFLAGS ()] nothing can be changed")
        self.reply(f"* {len(uids)} EXISTS")
        self.reply("* 0 RECENT")
        if validity is not None:
            self.reply(f"* OK [UIDVALIDITY {validity}] UIDs valid")
        self.reply(f"* OK [UIDNEXT {max(uids, default=0) + 1}] predicted next UID")
        self.reply(f"{tag} OK [READ-ONLY] EXAMINE completed")
        return True

    def do_uid_search(self, tag, argument):
        words = argument.split()
        uids = [uid for uid, _ in self.listing()]
        if len(words) != 2 or words[0].upper() != "UID" or not UID_SET.match(words[1]):
            self.reply(f"{tag} BAD the stub searches by one UID range only")
            return True
        largest = max(uids, default=0)
        found = [uid for uid in uids if in_set(uid, words[1], largest)]
        self.reply(" ".join(["* SEARCH", *map(str, found)]))
        self.reply(f"{tag} OK SEARCH completed")
        return True

    def do_uid_fetch(self, tag, argument):
        spec, _, items = argument.partition(" ")
        wanted = items.strip()
        if wanted.startswith("(") and wanted.endswith(")"):
            wanted = wanted[1:-1]
        wanted = set(wanted.upper().split())
        if not wanted or wanted - SERVED:
            return self.refuse(tag, "UID FETCH", argument,
                               f"the stub serves only {' '.join(sorted(SERVED))}")
        if not UID_SET.match(spec):
            self.reply(f"{tag} BAD the stub fetches one UID range only")
            return True
        listing = self.listing()
        largest = max((uid for uid, _ in listing), default=0)
        for number, (uid, path) in enumerate(listing, 1):
            if not in_set(uid, spec, largest):
                continue
            fault = self.fault("UID FETCH", uid)
            if fault and "BODY.PEEK[]" not in wanted and not fault.get("on_size") \
                    and fault["action"] != "size":
                fault = None   # the size asked before the body is answered as asked
            action = fault["action"] if fault else None
            if action in ("no", "bad", "bye", "drop", "hang"):
                return self.act(tag, "UID FETCH", fault, uid)
            if fault:
                self.log(event="fault", on="UID FETCH", action=action, uid=uid)
            if action == "expunged":
                self.expunged.add((self.selected, uid))
                continue
            try:
                stamp, body = path.stat().st_mtime, served(path.read_bytes())
            except FileNotFoundError:
                continue  # expunged since the listing
            if not self.send(number, uid, stamp, body, wanted, fault):
                return False
        self.reply(f"{tag} OK FETCH completed")
        return True

    def send(self, number, uid, stamp, body, wanted, fault):
        """One FETCH response; False when a fault ends the session inside it."""
        action = fault["action"] if fault else None
        if action == "late" and self.stub.stopping.wait(fault.get("delay", 0.5)):
            return False
        flags = self.control.get("flags", {}).get(self.selected, {}).get(str(uid), [])
        if action in ("flags-first", "nobody"):
            self.reply(f"* {number} FETCH (UID {uid} FLAGS ({' '.join(flags)}))")
            if action == "nobody":
                return True
        parts = [] if action == "no-uid" else [f"UID {uid}"]
        if "FLAGS" in wanted:
            parts.append(f"FLAGS ({' '.join(flags)})")
        if "INTERNALDATE" in wanted:
            said = fault["text"] if action == "date" else internaldate(stamp)
            parts.append(f'INTERNALDATE "{said}"')
        if "RFC822.SIZE" in wanted:
            parts.append(f"RFC822.SIZE {fault['size'] if action == 'size' else len(body)}")
        head = f"* {number} FETCH ({' '.join(parts)}"
        if "BODY.PEEK[]" not in wanted:
            self.reply(head + ")")
            return True
        self.conn.send(f"{head} BODY[] {{{len(body)}}}".encode() + CRLF)
        if action == "truncate":
            self.conn.send(body[:len(body) // 2])
            return False
        if action == "trickle":
            for i in range(len(body)):
                self.conn.send(body[i:i + 1])
                if self.stub.stopping.wait(fault.get("delay", 0.5)):
                    return False
        else:
            self.conn.send(body)
        self.reply(")")
        return True


def _arguments(parser):
    parser.add_argument("--mailbox", required=True, help="directory of folders of messages")


if __name__ == "__main__":
    main("Stub IMAP provider over implicit TLS, accepting only the commands that read.",
         lambda args, **kw: IMAPStub(args.mailbox, **kw), _arguments)
