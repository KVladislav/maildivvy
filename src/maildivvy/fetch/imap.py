"""Our own IMAP client for collection: it reads a mailbox, and nothing else.

    session = imap.connect(host, port, pin, deadline)
    session.login(user, secret)
    examined = session.examine(imap.INBOX)
    for uid in session.uids_above(mark, session.last_uid(examined)):
        size = session.size(uid)          # RFC822.SIZE, None when the server says none
        message = session.fetch(uid)      # None: expunged since the search
    session.folders()                     # every folder that can be opened, for a snapshot
    session.logout()

⛔ NOTHING IS EVER CHANGED AT THE PROVIDER. A mailbox is opened with
EXAMINE, never SELECT, and a body is read with BODY.PEEK[], never BODY[], which sets the
Seen flag for every reader of the mailbox. The client class refuses, before a byte of it
is sent, any command outside READ_ONLY, a UID command outside READ_ONLY_UID, any FETCH
item that sets a flag, and any argument holding a line break or a NUL, which would end
the command early and start another (a folder's name is the server's own words): a
writing command cannot leave the process, whatever a caller asks for and against any
server. That refusal is `Forbidden`, a bug of ours and never an answer of the provider's.

⛔ IMPLICIT TLS AND NOTHING ELSE. The one client class is imaplib's IMAP4_SSL: there is
no plaintext session and no upgrade of one. The server is verified against the
machine's trust store and its name, or, with a pin, accepted by the SHA-256 of
its certificate alone, compared before the greeting is read.

⛔ EVERY READ AND WRITE IS BOUNDED BY THE RUN'S DEADLINE. The socket's
timeout is set before each of them to the smaller of READ_BOUND and the time left, so a
server that trickles a literal a byte at a time cannot outlast the run, which a bound per
read alone would let it do. Past the deadline the session raises `Deadline`.

⛔ THE PASSWORD IS IN NO ERROR: the details become a column the
interface shows. A login or password holding CR, LF or NUL is refused before anything
is sent, since LOGIN would carry it as a line break; a server's answer that repeats the
password is not kept; and imaplib's debug output, which prints every command LOGIN's
included, is never turned on.

A message is fetched whole before it is returned, its size held to the literal's, so a
caller never holds half a message (the retrieval pipe's hazard does not arise).

⛔ A MESSAGE'S SIZE IS ASKED BEFORE ITS BODY (`size`): `UID FETCH <uid>
(RFC822.SIZE)`, an item that reads and sets no flag, so a caller can pass a message over
MESSAGE_CAP without downloading it. ⛔ AND NO LITERAL OVER MESSAGE_CAP IS READ, whatever
the size said: a server that announces a larger one has the session closed under it, the
literal unread, and the command is refused (for a UID FETCH, that message's refusal, the
session ended). The client holds about twice a message while it parses it, and no unit
bounds the memory.

⛔ A UID SEARCH ASKS FOR AT MOST SEARCH_WINDOW UIDS. imaplib refuses an answer line over
1,000,000 bytes, and one `UID SEARCH UID n:*` of a folder of 100,000 messages is longer:
the search would fail on every run. A folder is searched window by window, up to its
last UID (`last_uid`), so no answer can grow past the bound.

The errors are typed by the outcome each becomes: `Unreachable` (no usable
connection), `AuthFailed`, `MessageRefused` (one UID the server will not hand over: that
message's failure, the scanner not reached), `ServerError` (any other answer the session
cannot use) and `Deadline`. Each one's text is a detail fit for the row.

⛔ ONLY A NO WITH NO CODE, OR WITH ONE OF PASSWORD'S, IS THE PASSWORD'S. A login
refused NO with `[AUTHENTICATIONFAILED]` or `[EXPIRED]` (RFC 5530), or with no code at all,
is `AuthFailed`; a NO with any other code (`[ALERT]`, `[UNAVAILABLE]`, `[INUSE]`, a code of
the provider's own) and a BAD are a `ServerError`: read as the password's, the screen said
it was refused and the check at activation refused the mailbox, for a provider that was
busy, at its limit of sessions or could not parse the command. ⛔ A BAD to a login keeps
none of the server's words: a server may answer it by repeating the command, the password
in it, escaped otherwise than the client sent it. A refusal of EXAMINE or UID SEARCH is a
`ServerError` whatever it says: a snapshot tells a folder's from the account's by asking
the INBOX (`snapshot`), and collection opens only the INBOX.

⛔ AN ANSWER THE CLIENT CANNOT READ IS A `Failure`, NEVER ANOTHER EXCEPTION. A date
no calendar holds, a month imaplib does not know or a response it cannot parse raised
`ValueError` or `KeyError` past every caller's handling: in collection the same UID's run
ended `transient` every time, which the bounded retry never counts. An INTERNALDATE that
cannot be read is None (the message is still filed, with the time it was collected); any
other answer that cannot be read is the command's refusal, through the one place
(`Session._answers`) that turns the session's exceptions into `Failure`s: a UID FETCH's is
that message's (`MessageRefused`), anything else's a `ServerError`. A `LIST` delimiter sent
as an empty string is read as NIL. Control characters in a server's words are dropped
before they reach a detail: a NUL there was refused by the database, and the runner's
record of that refusal raised again.

⛔ BUT EVERY REFUSAL OF A UID FETCH IS THAT MESSAGE'S (`MessageRefused`), WHATEVER ITS CODE,
and so is a BYE the server sends while answering it. Dovecot answers a message it cannot
read with `NO [SERVERBUG]` or, by default, `* BYE FETCH failed` and a closed connection:
read as the account's trouble, that one message would stop the INBOX and a snapshot
behind it on every run, for ever. One answer cannot tell a message's refusal from the
whole account's; collection's bounded retry bounds what such a refusal costs (one skip,
then a freeze for a person), and a snapshot tells the two apart by the other messages the
same session hands over (`snapshot`). A connection that fails while the server answers,
with no BYE, is `Unreachable` here, and its caller judges it: collection counts it as the
message's too, the login and EXAMINE having gone through (`imap_collect`), and a snapshot
as a cut-off. One that fails before the command was written (`NotSent`, an `Unreachable`)
asked the server nothing about the message: it is the session's failure, and no message's.
"""

import base64
import contextlib
import datetime
import hashlib
import imaplib
import re
import ssl
import time
from dataclasses import dataclass

INBOX = "INBOX"
READ_BOUND = 60          # seconds one read or write may wait, whatever the run has left
MAX_UID = 4294967295     # the largest UID (RFC 9051 § 2.3.1.1), and the mark's CHECK
ANSWER_MAX = 300         # characters of a server's answer kept in a detail
# UIDs one UID SEARCH may name: its answer, at most 11 bytes a UID, stays well under
# imaplib's bound of 1,000,000 bytes on a line
SEARCH_WINDOW = 50_000
# The largest message collected or copied, in bytes: the scan limit clamd is
# installed with and Postfix's message_size_limit, both 50 MiB. A larger one could be
# filed only withheld unscanned, and sent on by nobody.
MESSAGE_CAP = 50 * 1024 * 1024
# How long the last message passed over the cap is shown, and health warns of it
OVERSIZE_SHOWN = datetime.timedelta(days=7)

# The commands a session may send, and UID only with one of READ_ONLY_UID.
READ_ONLY = frozenset({"CAPABILITY", "LOGIN", "AUTHENTICATE", "LIST", "EXAMINE", "NOOP",
                       "LOGOUT"})
READ_ONLY_UID = frozenset({"SEARCH", "FETCH"})
# The FETCH items that set the Seen flag: BODY[...] and BINARY[...] without .PEEK, RFC822
# and RFC822.TEXT (RFC 9051 § 6.4.5, RFC 3516). RFC822.SIZE and RFC822.HEADER do not.
SETS_SEEN = re.compile(r"\b(?:BODY|BINARY)\[|\bRFC822(?:\.TEXT)?(?![.\w])", re.IGNORECASE)
FETCH_ITEMS = "(BODY.PEEK[] FLAGS INTERNALDATE)"
SIZE_ITEMS = "(RFC822.SIZE)"

UNSENDABLE = re.compile(r"[\r\n\x00]")
RESPONSE_START = re.compile(rb"^\d+ \(")
UID = re.compile(rb"\bUID (\d+)")
RFC822_SIZE = re.compile(rb"\bRFC822\.SIZE (\d+)")
BODY_LITERAL = re.compile(rb"\bBODY\[\] \{(\d+)\}$")
# a body sent as a quoted string, which RFC 9051 allows (`nstring`), and not as a literal
BODY_QUOTED = re.compile(rb'\bBODY\[\] "((?:[^"\\]|\\.)*)"', re.DOTALL)
# The response codes of a login's NO that are the password's (RFC 5530), beside a NO with no
# code; any other code, and a BAD, are the server's. Read on a login's refusal
# alone; any refusal of EXAMINE, SEARCH or UID FETCH is judged by its caller.
PASSWORD = frozenset({"AUTHENTICATIONFAILED", "EXPIRED"})
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# What a parser of the server's answer raises on words it cannot read
UNREADABLE = (ValueError, KeyError, IndexError, TypeError, OverflowError)
# One LIST response: its attributes, its delimiter (a quoted character or NIL) and its
# name (an atom, a quoted string, or a literal, whose `{size}` imaplib hands on beside it).
LISTED = re.compile(rb'^\((?P<attributes>[^)]*)\) (?P<delimiter>NIL|"(?:[^"\\]|\\.)*") '
                    rb'(?P<name>.+)$', re.IGNORECASE | re.DOTALL)
ESCAPED = re.compile(rb"\\(.)", re.DOTALL)
# The attributes of a folder that holds no messages and cannot be opened (RFC 9051 § 7.3.1).
UNSELECTABLE = frozenset({"\\NOSELECT", "\\NONEXISTENT"})

DEADLINE = "the run's time ran out before the server finished answering"
ECHOED = "(its answer repeated the password and is not kept)"
MALFORMED = ("the server answered BAD, that it could not read the command; its answer is "
             "not kept, since it may repeat the command and the password in it")


# --- what goes wrong ---------------------------------------------------------------------------


class Failure(Exception):
    """Something the provider did or failed to do, in words fit for the row's detail."""


class Unreachable(Failure):
    """No usable connection: refused, silent, closed, a certificate refused or not the pinned one."""


class NotSent(Unreachable):
    """The connection failed before the command was written to it: the server was asked
    nothing, so the failure is the session's and never that of the message the command
    names."""


class AuthFailed(Failure):
    """The login was refused, or could not be sent. Its text never holds the password."""


class MessageRefused(Failure):
    """The server will not hand over one UID: a NO or a BAD to its FETCH, whatever its code,
    the message sent without its body, nothing sent for a UID it still lists, or a BYE while
    it answers (`ended`: the session is over). That message's failure."""

    def __init__(self, uid, words, ended=False):
        super().__init__(f"the server refused message {uid}: {words}")
        self.uid, self.ended = uid, ended


class ServerError(Failure):
    """Any other answer the session cannot use: a NO to EXAMINE or SEARCH, a BAD, a malformed
    response, a mailbox with no UIDVALIDITY."""


class Deadline(Failure):
    """The run's deadline passed; the session is not usable any more."""


class Overlong(Exception):
    """The server announced a literal over the client's bound: it was not read, and
    the session is out of step with the server."""


class Forbidden(Exception):
    """A command outside the read-only set was asked for, and not sent.

    A bug of ours, never the provider's answer, so it is not a `Failure`."""


@dataclass(frozen=True)
class Examined:
    uidvalidity: int
    uidnext: int | None  # None when the server does not say


@dataclass(frozen=True)
class Message:
    uid: int
    data: bytes                  # the message whole, as the server holds it
    flags: tuple[str, ...]
    internaldate: int | None     # seconds since the epoch, None when the server does not say


@dataclass(frozen=True)
class Folder:
    name: str                    # as the provider sends it, in modified UTF-7: never decoded
    delimiter: str | None        # its hierarchy's delimiter, None for a flat name (NIL)
    attributes: tuple[str, ...]  # `\All`, `\Junk`, `\HasChildren`, as the provider spells them


# --- the guard and the bounded socket ----------------------------------------------------------


def refusal(name, args):
    """Why a command may not be sent, or None when it only reads."""
    words = [a.decode("ascii", "replace") if isinstance(a, bytes) else str(a)
             for a in args if a is not None]
    if any(UNSENDABLE.search(word) for word in words):
        return f"an argument of {name} holds a line break or a NUL, which would end it early"
    if name == "UID":
        sub = words[0].upper() if words else ""
        if sub not in READ_ONLY_UID:
            return f"UID {sub} is not a command that only reads"
        if sub == "FETCH" and SETS_SEEN.search(" ".join(words[1:])):
            return "this FETCH would set the Seen flag; only BODY.PEEK[] reads a body"
        return None
    if name not in READ_ONLY:
        return f"{name} is not a command that only reads"
    return None


def fingerprint(der):
    return hashlib.sha256(der or b"").hexdigest().upper()


class _Bounded:
    """The connected socket, each read and write bounded by the smaller of the per-read bound
    and the time left to the deadline."""

    def __init__(self, sock, deadline, bound):
        self._sock, self._deadline, self._bound = sock, deadline, bound

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def _within(self, call, *args):
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise Deadline(DEADLINE)
        self._sock.settimeout(min(self._bound, left))
        try:
            return call(*args)
        except TimeoutError:
            if left <= self._bound:  # the deadline was the nearer bound
                raise Deadline(DEADLINE) from None
            raise

    def recv(self, size):
        return self._within(self._sock.recv, size)

    def sendall(self, data):
        return self._within(self._sock.sendall, data)


class _ReadOnly(imaplib.IMAP4_SSL):
    """imaplib's client with the guard in its one command path and its socket bounded."""

    written = False  # whether the last command asked for was written whole to the socket
    completion = None  # the last tagged answer's kind (OK, NO, BAD), None before one came
    literal_max = MESSAGE_CAP  # the largest literal read

    def __init__(self, host, port, context, pin, deadline, bound, timeout):
        self._pin, self._deadline, self._bound = pin, deadline, bound
        super().__init__(host, port, ssl_context=context, timeout=timeout)

    def _create_socket(self, timeout):
        sock = super()._create_socket(timeout)
        if self._pin and fingerprint(sock.getpeercert(binary_form=True)) != \
                self._pin.replace(":", "").upper():
            sock.close()
            raise Unreachable("the server's certificate is not the pinned one; nothing was sent")
        return _Bounded(sock, self._deadline, self._bound)

    def _command(self, name, *args):
        why = refusal(name, args)
        if why is not None:
            self.literal = None
            raise Forbidden(why)
        # imaplib returns from here only once the command line has been sent; a socket
        # that fails under it raises, and the command never reached the server
        self.written, self.completion = False, None
        tag = super()._command(name, *args)
        self.written = True
        return tag

    def read(self, size):
        # imaplib reads a literal, and only a literal, through here, by its announced size
        if size > self.literal_max:
            raise Overlong(f"the server announced {size} bytes, over the {self.literal_max}-"
                           "byte cap; they were not read")
        return super().read(size)

    def _get_tagged_response(self, tag, expect_bye=False):
        # imaplib raises a BAD's text as the NO's, so the kind is kept here
        typ, data = super()._get_tagged_response(tag, expect_bye)
        self.completion = typ
        return typ, data


# --- the session -------------------------------------------------------------------------------


def connect(host, port, pin, deadline, read_bound=READ_BOUND):
    """A session with the server over implicit TLS, `deadline` being a `time.monotonic()` value.

    Verified by the machine's trust store and the host's name, or with a pin by
    the certificate's SHA-256 alone.
    """
    left = deadline - time.monotonic()
    if left <= 0:
        raise Deadline(DEADLINE)
    context = ssl.create_default_context()
    if pin:
        # the pin replaces the chain and the name; `_create_socket` compares it
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    where = f"{host}:{port}"
    try:
        return Session(_ReadOnly(host, port, context, pin, deadline, read_bound,
                                 timeout=min(read_bound, left)), read_bound)
    except TimeoutError:
        if left <= read_bound:
            raise Deadline(DEADLINE) from None
        raise Unreachable(f"{where}: no answer within {read_bound:g} s") from None
    except (OSError, imaplib.IMAP4.error) as err:
        raise Unreachable(f"{where}: {said(err)}") from None


def text_of(value):
    """A server's bytes decoded, anything else as `str` gives it."""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def words_of(value):
    """A server's words on one line, its control characters dropped, cut to ANSWER_MAX."""
    return " ".join(CONTROL.sub(" ", text_of(value)).split())[:ANSWER_MAX]


def raw(err):
    """An exception's words as they came, a server's bytes decoded. An OSError's `args` are
    a number and a sentence, which only its own `str` puts together."""
    return text_of(err.args[0] if len(err.args) == 1 else err)


def said(err):
    """An exception's words on one line, cut to ANSWER_MAX."""
    return words_of(raw(err)) or type(err).__name__


def answer(data):
    """The text of a tagged answer, as imaplib hands it back."""
    last = data[-1] if data else None
    return (words_of(last) if last else None) or "no reason given"


def quoted(text):
    """An IMAP quoted string."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def number(value):
    """A UID-sized number from the server, or None."""
    if isinstance(value, bytes) and value.isdigit() and 0 < int(value) <= MAX_UID:
        return int(value)
    return None


def unquoted(value):
    """An IMAP quoted string's bytes, its escapes undone; anything else as it is."""
    if len(value) >= 2 and value.startswith(b'"') and value.endswith(b'"'):
        return ESCAPED.sub(rb"\1", value[1:-1])
    return value


def listed(item):
    """One LIST response, as imaplib hands it (a line, or (its head, the name's literal)),
    as a `Folder`; None when it is not one."""
    head, literal = item if isinstance(item, tuple) else (item, None)
    found = LISTED.match(head)
    if found is None:
        return None
    delimiter = found["delimiter"]
    delimiter = b"" if delimiter.upper() == b"NIL" else unquoted(delimiter)
    name = literal if literal is not None else unquoted(found["name"])
    # an empty delimiter is a flat name, as NIL is: `split("")` raises
    return Folder(name.decode("utf-8", "replace"),
                  delimiter.decode("ascii", "replace") or None,
                  tuple(found["attributes"].decode("ascii", "replace").split()))


def date_of(words):
    """A FETCH response's INTERNALDATE in seconds since the epoch, or None when it has none
    or one no calendar holds: a date is never worth the message."""
    try:
        stamp = imaplib.Internaldate2tuple(words)
        return int(time.mktime(stamp)) if stamp else None
    except UNREADABLE:
        return None


def message_of(uid, data):
    """The message `uid` in imaplib's answer to its UID FETCH, or None when the answer holds
    no response for it.

    A response for another UID is another message's unsolicited update, and one for this
    UID with no body (its flags alone, sent before the body) is passed over for the next.
    The body is a literal or, as RFC 9051 allows, a quoted string. Raises `MessageRefused`
    when every response for the UID came without a usable body (none, or NIL), and
    `Unreachable` when its literal came short.
    """
    seen = False
    for words, literals in responses(data):
        found = UID.search(words)
        if found is None or int(found.group(1)) != uid:
            continue
        seen = True
        body = None
        for head, literal in literals:
            size = BODY_LITERAL.search(head)
            if size is not None:
                if len(literal) != int(size.group(1)):
                    raise Unreachable(f"UID FETCH {uid}: the connection ended inside the message")
                body = literal
                break
        if body is None and (quoted_body := BODY_QUOTED.search(words)) is not None:
            body = ESCAPED.sub(rb"\1", quoted_body.group(1))
        if body is None:
            continue
        return Message(uid, body,
                       tuple(f.decode("ascii", "replace") for f in imaplib.ParseFlags(words)),
                       date_of(words))
    if seen:
        raise MessageRefused(uid, "the server sent the message without its body")
    return None


def responses(data):
    """imaplib's flat FETCH list as [(the response's words, [(literal's head, literal)])]."""
    found = []
    for item in data:
        if item is None:
            continue
        head, literal = item if isinstance(item, tuple) else (item, None)
        if RESPONSE_START.match(head) or not found:
            found.append((bytearray(), []))
        found[-1][0].extend(b" " + head)
        if literal is not None:
            found[-1][1].append((head, literal))
    return [(bytes(words), literals) for words, literals in found]


class Session:
    """One logged-in conversation; a context manager that logs out."""

    def __init__(self, client, read_bound):
        self._client, self._read_bound = client, read_bound
        self._examined = None   # the mailbox the last EXAMINE opened, which a search names
        self._lost = False      # a read or write failed: the server's answers are out of step

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.logout()

    @contextlib.contextmanager
    def _answers(self, what, refused=ServerError, hidden=(), unreadable=ServerError,
                 overlong=ServerError):
        """imaplib's and the socket's exceptions as `Failure`s; `hidden` never kept in one.

        An answer the server sent that cannot be read (UNREADABLE, raised by imaplib or by
        a parser of ours inside the block) is `unreadable`'s, by its kind alone.
        A literal over the bound (`Overlong`) is `overlong`'s, and the session is lost: the
        literal is still on its way."""
        def kept(err):
            # ⛔ looked for in the words as they came: `said` folds spaces and cuts them
            return ECHOED if any(h and h in raw(err) for h in hidden) else said(err)

        try:
            yield
        except Overlong as err:
            self._lost = True
            raise overlong(f"{what}: {err}") from None
        except imaplib.IMAP4.abort as err:  # before `error`: an abort is one
            self._lost = True
            raise Unreachable(f"{what}: the connection failed: {kept(err)}") from None
        except imaplib.IMAP4.error as err:
            raise refused(f"{what}: {kept(err)}") from None
        except TimeoutError:
            self._lost = True
            raise Unreachable(f"{what}: the server sent nothing for "
                              f"{self._read_bound:g} s") from None
        except OSError as err:
            self._lost = True
            raise Unreachable(f"{what}: {kept(err)}") from None
        except UNREADABLE as err:
            raise unreadable(f"{what}: the server's answer could not be read "
                             f"({type(err).__name__})") from None

    def login(self, user, secret):
        """AUTHENTICATE PLAIN when the server offers it, which carries UTF-8; LOGIN otherwise.

        The login is sent as given: which one is in force is the caller's. A
        NO with no code, or with one of PASSWORD's, is `AuthFailed`; any other refusal is the
        server's, a `ServerError`, and a BAD's words are never kept.
        """
        for what, value in (("login", user), ("password", secret)):
            if UNSENDABLE.search(value):
                raise AuthFailed(f"the {what} holds a line break or a NUL, which cannot be sent "
                                 "to an IMAP server; nothing was sent")
        plain = "AUTH=PLAIN" in self._client.capabilities
        if not plain and not (user + secret).isascii():
            raise AuthFailed("the login or the password holds a character LOGIN cannot carry, "
                             "and the server does not offer AUTHENTICATE PLAIN; nothing was sent")
        blob = f"\x00{user}\x00{secret}"
        hidden = (secret, quoted(secret)[1:-1], base64.b64encode(blob.encode()).decode())
        what = "AUTHENTICATE PLAIN" if plain else "LOGIN"
        coded = re.compile(rf"^{re.escape(what)}: \[([^\]\s]+)")

        def refused(words):
            if self._client.completion == "BAD":
                return ServerError(f"{what}: {MALFORMED}")
            code = coded.match(words)
            if self._client.completion == "NO" and (code is None or
                                                     code.group(1).upper() in PASSWORD):
                return AuthFailed(words)
            return ServerError(words)

        with self._answers(what, refused, hidden):
            if plain:
                self._client.authenticate("PLAIN", lambda _challenge: blob)
            else:
                self._client.login(quoted(user), secret)

    def examine(self, name):
        """EXAMINE, the one way this module opens a mailbox: read-only for every reader.

        A NO, whatever its code, a BAD, or no UIDVALIDITY is a `ServerError`: whether the
        folder or the whole account is refused is the caller's to judge."""
        self._examined = None
        with self._answers(f"EXAMINE {name}"):
            typ, data = self._client.select(quoted(name), readonly=True)
        if typ != "OK":
            raise ServerError(f"EXAMINE {name}: {answer(data)}")
        with self._answers(f"EXAMINE {name}"):
            validity = number(self._client.response("UIDVALIDITY")[1][-1])
            uidnext = number(self._client.response("UIDNEXT")[1][-1])
        if validity is None:
            raise ServerError(f"EXAMINE {name}: the server gave no UIDVALIDITY, so its UIDs "
                              "cannot be relied on")
        self._examined = name
        return Examined(validity, uidnext)

    def _search(self, uids):
        """`UID SEARCH UID <uids>`: the UIDs the server answers, as it answers them. An error
        names the mailbox searched."""
        what = f"UID SEARCH in {self._examined}"
        with self._answers(what):
            typ, data = self._client.uid("SEARCH", "UID", uids)
        if typ != "OK":
            raise ServerError(f"{what}: {answer(data)}")
        words = b" ".join(item for item in data if item).split()
        if not all(word.isdigit() for word in words):
            raise ServerError(f"{what}: the server's answer is not a list of UIDs")
        return [int(word) for word in words]

    def last_uid(self, examined):
        """The examined mailbox's last UID now: UIDNEXT less one, or, when the server does not
        say UIDNEXT, the largest UID in use (`*`, RFC 9051 § 6.4.4), 0 for none. A message
        arriving later is above either."""
        if examined.uidnext is not None:
            return examined.uidnext - 1
        return max(self._search("*"), default=0)

    def uids_above(self, n, last):
        """The examined mailbox's UIDs above `n` and up to `last`, ascending, asked
        SEARCH_WINDOW UIDs at a time.

        A window names both its ends, never `*`, so it holds only the UIDs in it; anything
        else a server answers is dropped.
        """
        found = set()
        last = min(last, MAX_UID)
        for low in range(n + 1, last + 1, SEARCH_WINDOW):
            high = min(low + SEARCH_WINDOW - 1, last)
            found.update(uid for uid in self._search(f"{low}:{high}") if low <= uid <= high)
        return sorted(found)

    def fetch(self, uid):
        """The message whole with its flags and INTERNALDATE, or None when it was expunged
        since the search: the server sent nothing for the UID, and no longer lists it.

        ⛔ ANY ANSWER THAT DOES NOT HAND THE MESSAGE OVER IS THAT MESSAGE'S (`MessageRefused`):
        a NO or a BAD whatever its code, its body missing or NIL, nothing sent for a UID the
        server still lists (a server that leaves UID out of its answers, say), or a BYE that
        ends the session while it answers (`ended`), as Dovecot answers a message it cannot
        read. Read as anything else, one message the server never sends would stop the
        INBOX behind it on every run, and the bounded retry, which counts only a message's
        own failures, would never pass it. A connection that fails with no BYE, closed or
        silent past the per-read bound, is `Unreachable`, which the caller judges (see the
        module's docstring); one that fails before the command was written is `NotSent`:
        the server was asked nothing about this message.
        """
        return self._asked(uid, self._fetch)

    def size(self, uid):
        """The message's size in bytes as the server gives it (RFC822.SIZE), asked before its
        body; None when the server sends none for the UID (expunged since the
        search, or a size it does not say), which `fetch` then judges under the literal's
        bound. Its failures are `fetch`'s."""
        return self._asked(uid, self._size)

    def _asked(self, uid, call):
        """`call(uid)`, a UID FETCH, its failures judged as `fetch` says."""
        try:
            return call(uid)
        except Unreachable as err:
            if not self._client.written:
                raise NotSent(f"{err}; the command was not sent") from None
            bye = self._client.untagged_responses.get("BYE")
            if not bye:
                raise
            raise MessageRefused(uid, f"the server ended the session: {words_of(bye[-1])}",
                                 ended=True) from None

    def _size(self, uid):
        def refused(words):
            return MessageRefused(uid, words)

        with self._answers(f"UID FETCH {uid} RFC822.SIZE", refused, unreadable=refused):
            typ, data = self._client.uid("FETCH", str(uid), SIZE_ITEMS)
            if typ != "OK":
                raise MessageRefused(uid, answer(data))
            for words, _ in responses(data):
                found, size = UID.search(words), RFC822_SIZE.search(words)
                if found is not None and int(found.group(1)) == uid and size is not None:
                    return int(size.group(1))
        return None

    def _fetch(self, uid):
        def refused(words):
            return MessageRefused(uid, words)

        def overlong(words):
            return MessageRefused(uid, words, ended=True)

        with self._answers(f"UID FETCH {uid}", refused, unreadable=refused, overlong=overlong):
            typ, data = self._client.uid("FETCH", str(uid), FETCH_ITEMS)
            if typ != "OK":
                raise MessageRefused(uid, answer(data))
            message = message_of(uid, data)
        if message is None and uid in self._search(str(uid)):
            raise MessageRefused(uid, "the server sent nothing for it, and still lists it")
        return message

    def folders(self):
        """Every folder `LIST "" "*"` names that can be opened, with its delimiter and
        attributes, in the server's order.

        A `\\Noselect` or `\\NonExistent` folder holds no messages and cannot be EXAMINEd,
        so it is left out; `\\All`, `\\Junk` and `\\Trash` are not. The name is kept in the
        modified UTF-7 the server sends: Dovecot stores a folder under that same name, and
        cannot open one written in UTF-8.
        """
        with self._answers("LIST"):
            typ, data = self._client.list('""', '"*"')
            if typ != "OK":
                raise ServerError(f"LIST: {answer(data)}")
            found = []
            for item in data:
                if not item:
                    continue  # imaplib's [None] for no folder, or what followed a name's literal
                folder = listed(item)
                if folder is None:
                    raise ServerError("LIST: the server's answer is not a list of folders")
                if not {a.upper() for a in folder.attributes} & UNSELECTABLE:
                    found.append(folder)
        return found

    def logout(self):
        """LOGOUT, and the connection closed whatever the server answers or the time left.

        ⚠️ A SESSION WHOSE CONNECTION FAILED, OR WHOSE SERVER WENT SILENT PAST THE BOUND, IS
        CLOSED WITHOUT A LOGOUT. The server may still send the answer given up on, and a
        LOGOUT reads every byte of it before its own: Gmail sent a 12.5 MB message that way
        once, which the next slice then fetched again.
        """
        try:
            if not self._lost:
                with contextlib.suppress(Failure, OSError, imaplib.IMAP4.error):
                    self._client.logout()
        finally:
            with contextlib.suppress(OSError):
                self._client.shutdown()
