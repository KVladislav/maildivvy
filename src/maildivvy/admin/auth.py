"""Who is signed in: the password check, the session row, and the files it needs.

**The interface verifies the account hashes itself** and never speaks to the mail
server's authentication socket, which answers IMAP and submission: a web application
does not belong in the mail server's authentication path.
The hashes are the ones Dovecot reads, `{SHA512-CRYPT}$6$...`; the break-glass hash is
stored bare, in a table of its own, and is checked before and apart from the accounts
table, because the case it exists for is that table being unusable.

⚠️ **Python 3.14 has no `crypt` module**, so a hash is checked the way the machine
makes one: `openssl passwd -6` with the stored salt, the password on stdin, and a
constant-time comparison, as for the break-glass hash. `-stdin`
reads one line, so a password carrying a newline could only be checked truncated - and
a check that cannot be made whole is a refusal, never an acceptance.

**The session is a row, not a stamped cookie**. The source's
signed, server-stateless cookie could not be revoked, so signing out only deleted the
browser's copy. Here the cookie carries an opaque token and nothing else;
the table keeps a hash of it, and sign-out removes the row, which makes every copy of
that cookie useless at once. The cookie is signed with the machine's own secret as
well, so a forged or edited value is refused before the database is asked anything.

Every request re-reads the account behind an ordinary session, in the same statement
that touches it, so blocking an administrator, revoking the flag or deleting the
account ends their open sessions at the next request; a break-glass session is
deliberately not re-read.
"""

import hashlib
import hmac
import re
import secrets
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from maildivvy.lib import db
from maildivvy.lib.config import ETC, ConfigError, consumer_dir, db_conf_path, read_db_conf

CONSUMER = "admin"
SECRET_NAME = "secret"
COOKIE = "maildivvy_session"

PREFIX = "{SHA512-CRYPT}"
# `$6$<salt>$<86>`: what `openssl passwd -6` and `doveadm pw -s SHA512-CRYPT` both make.
# A `rounds=` hash is deliberately not matched: openssl cannot reproduce one.
CRYPT = re.compile(r"\$6\$([./A-Za-z0-9]{1,16})\$[./A-Za-z0-9]{86}")
PASSWORD_MAX = 1024
# A hash no password matches, so an unknown login costs the same check as a known one.
NOBODY = "$6$" + "n" * 16 + "$" + "." * 86

BREAK_GLASS_LOGIN = "break-glass"
IDLE_SECONDS = 15 * 60
ABSOLUTE_SECONDS = 8 * 60 * 60

REFUSAL = "That login and password were not accepted."
SIGN_IN = "Please sign in."
THROTTLED = ("Too many sign-in attempts for that login from here. Wait a few minutes and "
             "try again.")


@dataclass(frozen=True)
class Identity:
    """Who a request is. `login` is the account's own login, never the typed spelling."""

    login: str
    account_id: int | None = None
    break_glass: bool = False


# --- passwords ---------------------------------------------------------------------------

def account_login(typed):
    """The account a typed login names: the text before the first `@`.

    `ivan` and `ivan@example.org` open the same account. The account's own login is what
    is kept and journaled, so one person is one actor.
    """
    return str(typed or "").strip().split("@", 1)[0]


def sha512_crypt(password, salt):
    result = subprocess.run(["openssl", "passwd", "-6", "-stdin", "-salt", salt],
                            input=password + "\n", capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


SALT_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SALT_LENGTH = 16          # what `doveadm pw -s SHA512-CRYPT` uses, and $6$'s maximum


def make_hash(password):
    """`{SHA512-CRYPT}$6$<salt>$<86>` for a password: the hash Dovecot itself reads.

    The salt is new every time, so two people with one password have two hashes. The
    result is read back against the pattern `verify_password` accepts, because a hash
    this program could not check afterwards is a credential nobody can use.
    """
    if not isinstance(password, str) or not password or "\n" in password:
        raise ValueError("a password to hash is one non-empty line")
    if len(password) > PASSWORD_MAX:
        raise ValueError(f"a password is at most {PASSWORD_MAX} characters")
    salt = "".join(secrets.choice(SALT_ALPHABET) for _ in range(SALT_LENGTH))
    made = sha512_crypt(password, salt)
    if not CRYPT.fullmatch(made):
        raise ValueError("openssl did not produce an SHA512-CRYPT hash")
    return PREFIX + made


# a generated password is at least 20 characters from the operating system's own
# random source, over an alphabet with no look-alikes in it - no `l`, `I`, `1`, `O` or
# `0` - because it is read off a screen once and typed into a mail client by hand.
GENERATED_LENGTH = 20
GENERATED_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_password(length=GENERATED_LENGTH):
    """A password nobody typed, for a creation or a reset with both fields empty.

    `secrets.choice` draws from the operating system's cryptographic source. The result
    is returned and never stored: what is kept is its hash, and the one page that shows
    it is the answer to the POST that made it.
    """
    return "".join(secrets.choice(GENERATED_ALPHABET) for _ in range(length))


def verify_password(typed, stored):
    """True when `typed` is the password behind `stored`, for a hash we can check whole."""
    if not isinstance(typed, str) or not isinstance(stored, str):
        return False
    if not typed or "\n" in typed or len(typed) > PASSWORD_MAX:
        return False
    bare = stored[len(PREFIX):] if stored.startswith(PREFIX) else stored
    match = CRYPT.fullmatch(bare)
    if not match:
        return False
    return hmac.compare_digest(sha512_crypt(typed, match.group(1)), bare)


# --- the session's cookie -----------------------------------------------------------------

def new_token():
    return secrets.token_urlsafe(32)


def token_hash(token):
    """What the table keeps: never the token itself, so a stolen row mints no session."""
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token(secret, session_token):
    """A per-session form token, bound to the session's own token by the machine's secret.

    ⛔ Every state-changing form carries this, and an unsafe request is refused
    unless it presents the token that matches its session. It cannot be forged without the
    secret, and it dies with the session, so a stolen or guessed one from another session
    does not work. It is a second lock beside the Origin check, not a replacement for it.
    """
    return hmac.new(secret, (session_token + ":csrf").encode(), hashlib.sha256).hexdigest()


def sign(secret, token):
    mac = hmac.new(secret, token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{mac}"


def unsign(secret, value):
    """The token inside a cookie this machine signed, or None. Never trusted in part."""
    if not isinstance(value, str) or value.count(".") != 1:
        return None
    token, mac = value.split(".")
    if not token or not hmac.compare_digest(sign(secret, token), value):
        return None
    return token


# --- sign-in ------------------------------------------------------------------------------

def break_glass_hash(conn):
    with conn.cursor() as cursor:
        cursor.execute("SELECT password_hash FROM break_glass")
        row = cursor.fetchone()
    return row[0] if row else None


def authenticate(conn, typed, password):
    """The identity behind a typed login and password, or None. One refusal for every no.

    A wrong password, an unknown login, an account without the administrator flag and a
    blocked administrator are one answer, because distinct answers say which logins
    exist and which of them are administrators.
    """
    login = account_login(typed)
    if login == BREAK_GLASS_LOGIN:
        stored = break_glass_hash(conn)
        if stored and verify_password(password, stored):
            return Identity(BREAK_GLASS_LOGIN, None, True)
        return None
    with conn.cursor() as cursor:
        cursor.execute("SELECT id, login, password_hash, is_admin, state FROM account "
                       "WHERE login = %s", (login,))
        row = cursor.fetchone()
    if row is None:
        verify_password(password, NOBODY)     # the same work for a login that is not there
        return None
    account_id, found, stored, is_admin, state = row
    if not verify_password(password, stored):
        return None
    if not is_admin or state != "active":
        return None
    return Identity(found, account_id, False)


# --- the session row ----------------------------------------------------------------------

def open_session(conn, identity):
    """Write the session row and return the token that names it."""
    token = new_token()
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO session (token_hash, account_id, break_glass) VALUES (%s, %s, %s)",
            (token_hash(token), identity.account_id, identity.break_glass))
    return token


# ⛔ A SESSION ENDS WHEN ITS PERSON'S PASSWORD CHANGES. An ordinary session
# is valid only while it was created at or after its account's `password_set_at`, so a
# password change ends every session of that account (and no other's) at the next request.
# A break-glass session is valid only while it was created at or after `break_glass.set_at`,
# so rotating the break-glass password ends its sessions too - and it still reads no account
# row, so it works when the accounts table is unusable.
READ = """
UPDATE session s SET last_seen_at = now()
 WHERE s.token_hash = %s
   AND s.last_seen_at > now() - make_interval(secs => %s)
   AND s.created_at   > now() - make_interval(secs => %s)
   AND ((s.break_glass AND s.created_at >= (SELECT set_at FROM break_glass))
        OR EXISTS (SELECT 1 FROM account a
                    WHERE a.id = s.account_id AND a.is_admin AND a.state = 'active'
                      AND s.created_at >= a.password_set_at))
RETURNING s.account_id, s.break_glass,
          (SELECT a.login FROM account a WHERE a.id = s.account_id)
"""


def read_session(conn, token):
    """The identity behind a token, or None; the row's last-seen time moves in the same read.

    One statement: the session's two bounds and the account's own two columns.
    A break-glass session skips the account read entirely, because the case
    it exists for is the accounts table being unusable. A database error
    here is left to raise: failing closed is the point.
    """
    if not token:
        return None
    with conn.cursor() as cursor:
        cursor.execute(READ, (token_hash(token), IDLE_SECONDS, ABSOLUTE_SECONDS))
        row = cursor.fetchone()
    if row is None:
        return None
    account_id, glass, login = row
    return Identity(BREAK_GLASS_LOGIN if glass else login, account_id, glass)


def end_session(conn, token):
    """Remove the named session row. Returns how many rows went (0 or 1).

    ⚠️ The interface's role holds no DELETE on any table, so the row is
    removed by a function the schema owner owns, which deletes the one row whose token
    hash is handed to it and nothing else (`schema/0001_initial.sql`).
    """
    if not token:
        return 0
    with conn.cursor() as cursor:
        cursor.execute("SELECT end_session(%s)", (token_hash(token),))
        return cursor.fetchone()[0]


def expire_sessions(conn):
    """Remove every session past its idle or absolute bound. Returns how many went.

    ⚠️ The bounds are the function's own, not this caller's: a SECURITY
    DEFINER function that took its bounds as arguments let a caller delete every session
    at once. They are the rules of sign-in, the same the per-request `READ`
    above enforces.
    """
    with conn.cursor() as cursor:
        cursor.execute("SELECT expire_sessions()")
        return cursor.fetchone()[0]


# --- the files the service will not start without ---------------------

def secret_path(etc=ETC):
    return consumer_dir(CONSUMER, etc) / SECRET_NAME


def read_secret(path):
    """The session signing key: non-empty, mode 0600, or ConfigError naming the file.

    A leaked key mints a session as any administrator and shows none of the warning
    signs a password does. The rule is libpq's own rule for a passfile.
    """
    path = Path(path)
    try:
        mode = path.stat().st_mode
        text = path.read_bytes()
    except OSError as err:
        raise ConfigError(f"cannot read the session key {path}: {err.strerror}") from None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(
            f"the session key {path} has group or other access ({stat.S_IMODE(mode):04o}); "
            "it must be 0600, owned by the interface's user")
    key = text.strip()
    if not key:
        raise ConfigError(f"the session key {path} is empty")
    return key


def preflight(etc=ETC, consumer=CONSUMER):
    """Open every file the service reads, and answer with what is wrong, by name.

    A service that comes up and fails on its first request leaves nobody to read the
    message: systemd reports it active, the socket answers, and the failure reaches
    whoever tries to sign in. `exists()` says yes to a file this uid cannot read, so
    each one is actually opened. Every problem is reported, not the
    first.
    """
    problems = []
    conf = db_conf_path(consumer, etc)
    try:
        info = read_db_conf(conf)
    except ConfigError as err:
        problems.append(str(err))
        info = None
    if info is not None:
        try:
            db.check_passfile(info["passfile"])
            with open(info["passfile"], "rb") as handle:
                handle.read(1)
        except (ConfigError, OSError) as err:
            problems.append(str(err) if isinstance(err, ConfigError)
                            else f"cannot read the passfile {info['passfile']}: {err.strerror}")
    try:
        read_secret(secret_path(etc))
    except ConfigError as err:
        problems.append(str(err))
    return problems
