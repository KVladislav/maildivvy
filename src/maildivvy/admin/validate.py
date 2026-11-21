"""Values the interface checks itself, before any database constraint can fire.

A CHECK, UNIQUE or foreign-key violation raises, and an unhandled exception is HTTP
500 - a crash where a person deserved a sentence. So every typed value
is checked here first and the constraint stays as the second lock. A refusal carries
the sentence the screen shows beside the field.

Two rules live here because more than one reader needs exactly the same one:

- `is_host` is the provider-host field's rule, and it is also what exempts a host name
  from the journal's secret filter, so the two cannot drift. It
  parses an address with a real parser rather than matching hex and colons. The field
  is narrower than the filter: it takes a NAME only, never an address, so
  everything it stores the filter still passes as itself.
- `number_in_range` quantises to the column's own scale *before* it reads the bounds,
  and refuses a non-finite value before any comparison: comparing `NaN` with a bound
  raises rather than answering false (measured on the predecessor on
  2026-09-17).
"""

import ipaddress
import re
from datetime import date
from decimal import Decimal, DecimalException, ROUND_HALF_UP

from maildivvy.admin import auth

HOST_MAX = 253
LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
ALL_DIGITS = re.compile(r"^[0-9.]+$")

# ⛔ A PROVIDER HOST IS A NAME, NEVER AN IP ADDRESS. The relay checks the
# provider's certificate against the configured host, and a relay configured as an IP
# address never matches, even with a certificate naming that address; mpop matches
# an address only against a certificate naming it, which a provider's does not.
# A name's last label begins with a letter, as every top-level domain does, and nothing
# in it is a colon: that refuses every IPv4 spelling a resolver would take as an address
# (`0x7f.0.0.1` too) and every IPv6 one. The schema's CHECK on both host columns is this
# same expression and a colon rule; a unit test holds the two together.
HOST_ENDS_IN_A_NAME = re.compile(r"(^|[.])[A-Za-z][^.]*$")

# The domain label, spelt exactly as `schema/0001_initial.sql`'s CHECK spells it: one
# lowercase DNS label of at most 32 characters. A unit test holds the
# two together, because a screen that accepts what the column refuses is an error page.
DOMAIN_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$")

# A person's login, spelt as the `account` table's CHECK spells it.
# `archive` is every domain's own mailbox and `break-glass` is the interface's reserved
# administrator, so neither is a person.
ACCOUNT_LOGIN = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$")
RESERVED_LOGINS = frozenset({"archive", "break-glass"})

# ⛔ Whitespace or a control character ANYWHERE INSIDE a value the fetcher writes into
# its configuration file as it stands: the address when no login is
# set, and the POP3 login. That file is run as another user and a line break in it would
# be a second configuration line. Surrounding whitespace is stripped, not refused.
# ⛔ ONE CHARACTER CLASS ON BOTH SIDES. The columns' CHECK spells it
# `[:space:][:cntrl:]` (SCHEMA_CLASS), and in the machine's database that refuses the C1
# controls U+0080 to U+009F as well as C0, DEL and Unicode's spaces. A screen that
# let a C1 control through answered with an error page, so this class is every Unicode
# control (C0, DEL and C1) and every space Python knows, which is all the CHECK refuses
# and the no-break spaces besides; a unit test holds it against the schema's text.
SCHEMA_CLASS = "[:space:][:cntrl:]"
INNER = re.compile(r"[\s\x00-\x1f\x7f-\x9f]")

WHOLE_NUMBER = re.compile(r"^-?[0-9]+$")
# A SHA-256 certificate fingerprint in the one spelling stored, as the table's CHECK spells
# it (`schema/0002_provider_login_keep_and_pins.sql`), and what the form also takes: any
# case, colons or spaces or neither, after the label openssl or mpop prints.
FINGERPRINT = re.compile(r"^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$")
FINGERPRINT_LABEL = re.compile(r"^sha-?256(?:\s+fingerprint)?\s*[=:]\s*", re.IGNORECASE)
FINGERPRINT_HEX = re.compile(r"^[0-9A-Fa-f]{64}$")
PORT_NUMBER = re.compile(r"^[0-9]+$")
# Only these digits, and all of them: `date.fromisoformat` also takes a week date
# (`2026-W45-2`), a basic one (`20260922`) and a time, and a screen sends the date on to
# its query as typed, where PostgreSQL refuses them - an error page.
CALENDAR_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

# ⚠️ THE DOT-INSENSITIVE HOSTS ARE CODE, NOT A SETTING. Folding decides one
# thing: whether a second spelling of an address already here is refused, which is the
# only guard against two fetchers on one provider mailbox. It is a fact about a
# provider, so it ships with the product and changes with a release.
CONSUMER_HOSTS = frozenset({"gmail.com", "googlemail.com"})
# ⚠️ And one provider's two names are one host in the canonical form: `googlemail.com`
# is Google's other name for the same mailboxes, so `ivan@googlemail.com` compares as
# `ivan@gmail.com`. A row saved before this rule keeps its stored spelling, which the
# duplicate check also looks for (`legacy_spellings`).
SAME_HOST = {"googlemail.com": "gmail.com"}

# The two ways an external mailbox is collected: the column's value, and the word a
# screen labels the server's fields with, since the `pop3_` columns hold either server's.
PROTOCOLS = {"pop3": "POP3", "imap": "IMAP"}
# Each protocol's own port, implicit TLS for both: what an empty port on the add form is.
PROVIDER_PORTS = {"pop3": 995, "imap": 993}
NOT_A_PROTOCOL = "The protocol is POP3 or IMAP."
# ⛔ The schema's CHECK holds an IMAP row to keeping its mail at the provider;
# the screen says so first, rather than an error page.
IMAP_KEEPS = ("An IMAP mailbox keeps every message at the provider: nothing collected over "
              "IMAP is ever deleted or changed there. Tick Keep mail at the provider to "
              "collect it over IMAP.")
# Enabling is what starts collection over a protocol, an IMAP mark included.
PROTOCOL_WHILE_ENABLED = ("The protocol changes only while the mailbox is disabled: enabling "
                          "it is what starts collection over the new one. Disable it first.")

WINDOW_DEFAULT = 14
WINDOW_MAX = 1000000       # the date arithmetic's bound, not a policy
PASSWORD_MIN = 15          # a length, and no composition rule at all
# bytes, because that is what the hasher counts; the sentence says what that means in letters
TOO_LONG = (f"A password is at most {auth.PASSWORD_MAX} bytes: {auth.PASSWORD_MAX} plain letters "
            f"and digits, but only {auth.PASSWORD_MAX // 2} Cyrillic letters, which take two "
            "bytes each.")
SPAM_LOW = Decimal("1.00")
SPAM_HIGH = Decimal("150.00")
SPAM_NOT_A_NUMBER = "The spam score threshold must be a number, such as 8.00."
SPAM_OUT_OF_RANGE = "The spam score threshold must be a number from 1.00 to 150.00."


class Refused(Exception):
    """A typed value the screen refuses. Its text is the sentence shown to the person."""


def is_host(text):
    """True for a dotted DNS name or an IP literal: the journal filter's exemption, and the
    host field's rule once `host` has refused an address."""
    if not isinstance(text, str) or not text or len(text) > HOST_MAX:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    # a name made only of digits and dots is an address or nothing: `192.0.2.256` is
    # neither, and a regular expression that let it through would widen what the
    # journal's filter writes out as itself
    if ALL_DIGITS.fullmatch(text):
        return False
    # ⚠️ fullmatch: `$` also matches before a final newline, so `.match` let a host name
    # ending in one through to the column's CHECK and its error page
    labels = text.split(".")
    return len(labels) > 1 and all(LABEL.fullmatch(label) for label in labels)


def number_in_range(text, low, high, places=2, what="value",
                    not_a_number=None, out_of_range=None):
    """The typed number, rounded to `places` and inside [low, high], or Refused.

    The two sentences may be given by the caller, so a field's own wording and this one
    quantise-then-compare rule stay in one place.
    """
    not_a_number = not_a_number or f"The {what} must be a number."
    out_of_range = out_of_range or f"The {what} must be between {low} and {high}."
    if not isinstance(text, str):
        raise Refused(not_a_number)
    typed = text.strip()
    if not typed:
        raise Refused(f"The {what} is needed.")
    try:
        number = Decimal(typed)
    except DecimalException:
        raise Refused(not_a_number) from None
    if not number.is_finite():
        raise Refused(not_a_number)
    try:
        number = number.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)
    except DecimalException:
        # a magnitude too large to express at that scale is finite and is not a value
        raise Refused(out_of_range) from None
    if number < low or number > high:
        raise Refused(out_of_range)
    return number


# --- what each screen's fields are --------------------------------

def domain_label(text):
    """One lowercase DNS label of at most 32 characters, stripped."""
    typed = str(text or "").strip()
    if not typed or not DOMAIN_LABEL.fullmatch(typed):
        raise Refused(
            "A domain label is lowercase letters, digits and hyphens, 1 to 32 of them, "
            "not starting or ending with a hyphen and with no dot in it.")
    return typed


def login(text):
    """A person's login, by the schema's own rule, folded to lowercase.

    ⛔ FOLDED, NEVER REFUSED FOR A CAPITAL: Dovecot lowercases every login before
    it looks one up, so `Ivan` in a mail client already opens `ivan`; the column holds the
    lowercase spelling and the interface reads a typed one the way Dovecot does.
    The match is whole-string, because a pattern anchored with `$` in Python accepts a
    trailing newline that the column refuses.

    The screens that use it came later; the rule is here with the others so that
    one function serves every screen and the journal filter alike.
    """
    typed = str(text or "").strip().translate(auth.LOGIN_CASE)
    if not typed or not ACCOUNT_LOGIN.fullmatch(typed):
        raise Refused(
            "A login is letters, digits, dots, hyphens and underscores, at "
            "most 64 of them, starting and ending with a letter or a digit.")
    if typed in RESERVED_LOGINS:
        raise Refused(f"{typed} is reserved: it is not a person's login.")
    return typed


def calendar_date(text, what):
    """A date typed as YYYY-MM-DD, or Refused.

    An empty date is refused rather than widened to everything: a range nobody asked for
    is not the range they were shown.
    """
    typed = str(text or "").strip()
    if not typed:
        raise Refused(f"The {what} is needed. Give it as YYYY-MM-DD.")
    try:
        if not CALENDAR_DATE.fullmatch(typed):
            raise ValueError(typed)
        return date.fromisoformat(typed)
    except ValueError:
        raise Refused(f"The {what} is not a date. Give it as YYYY-MM-DD.") from None


def no_inner_whitespace(value, what):
    """Refuse whitespace or a control character inside `value`."""
    if INNER.search(value):
        raise Refused(f"The {what} must have no spaces, line breaks or control "
                      "characters in it.")


def pop3_login(text):
    """The login to store: the stripped text, or None meaning the address itself."""
    typed = str(text or "").strip()
    if not typed:
        return None
    no_inner_whitespace(typed, "POP3 login")
    return typed


def smtp_login(text):
    """The SMTP login to store: the stripped text, or None meaning the POP3 login.

    ⛔ No colon: Postfix splits its SASL value `login:password` at the first one, so the
    rest of such a login would be sent as part of the password.
    """
    typed = str(text or "").strip()
    if not typed:
        return None
    no_inner_whitespace(typed, "SMTP login")
    if ":" in typed:
        raise Refused("The SMTP login must have no colon in it: the relay would send what "
                      "follows the colon as part of the password.")
    return typed


def is_fingerprint(text):
    """A fingerprint as stored; what exempts one from the journal's secret filter."""
    return isinstance(text, str) and FINGERPRINT.fullmatch(text) is not None


def fingerprint(text, what):
    """A SHA-256 certificate fingerprint in the spelling stored, or None for none."""
    typed = FINGERPRINT_LABEL.sub("", str(text or "").strip())
    if not typed:
        return None
    digits = re.sub(r"[\s:]", "", typed)
    if not FINGERPRINT_HEX.fullmatch(digits):
        raise Refused(f"The {what} must be a SHA-256 fingerprint: 64 hexadecimal digits, "
                      "with or without colons, as openssl x509 -fingerprint -sha256 prints "
                      "it.")
    digits = digits.upper()
    return ":".join(digits[i:i + 2] for i in range(0, len(digits), 2))


def external_address(text):
    """(what is shown, what is compared) for a provider address.

    The display form is the typed text stripped; the canonical form is lower-cased, and
    at a dot-insensitive consumer host every dot of the local part and everything from
    `+` onward is dropped, because those spellings are one mailbox there.
    """
    typed = str(text or "").strip()
    if not typed:
        raise Refused("An address is needed.")
    no_inner_whitespace(typed, "address")
    local, at, host = typed.rpartition("@")
    # one `@`, and a host of dotted labels none of which is empty (`x@.` is not one)
    if (not at or not local or "@" in local or "." not in host
            or not all(host.split("."))):
        raise Refused(f"{typed} is not an address.")
    local, host = local.lower(), host.lower()
    if host in CONSUMER_HOSTS:
        local = local.split("+", 1)[0].replace(".", "")
    if not local:
        raise Refused(f"{typed} is not an address.")
    return typed, f"{local}@{SAME_HOST.get(host, host)}"


def legacy_spellings(canonical):
    """Every canonical spelling a row saved before `SAME_HOST` may hold for `canonical`."""
    local, _, host = canonical.rpartition("@")
    return [canonical] + [f"{local}@{other}" for other, same in SAME_HOST.items()
                          if same == host]


def host(text, what, example):
    """A dotted DNS name by `is_host`'s rule, and never an address."""
    typed = str(text or "").strip()
    if not typed:
        raise Refused(f"The {what} is needed.")
    # Refused for what is wrong with the name, never as an address
    if not typed.isascii():
        raise Refused(f"The {what} must be a host name such as {example}, written in its ASCII "
                      "form, the one that starts xn--.")
    if typed.endswith("."):
        raise Refused(f"The {what} must be a host name such as {example}, written without the "
                      "dot at its end.")
    if ":" in typed or not HOST_ENDS_IN_A_NAME.search(typed):
        raise Refused(f"The {what} must be a host name such as {example}, not an IP "
                      "address: the provider's certificate is checked against that name.")
    if not is_host(typed):
        raise Refused(f"The {what} must be a host name such as {example}: letters, "
                      "digits, hyphens and dots, with a dot in it and no spaces.")
    return typed


def whole_number(typed, high):
    """The int `typed` spells, already matched as ASCII digits after an optional minus.

    ⛔ `int()` RAISES past 4300 digits, so a field read with it answered five thousand
    typed digits with an error page. A number spelt with more digits
    than `high` has is past `high` whatever its digits are, so it reads as `high + 1`
    (or its negative) and the caller's own bound refuses it with its own sentence.
    """
    minus = typed.startswith("-")
    digits = typed[minus:].lstrip("0") or "0"
    if len(digits) > len(str(high)):
        return -(high + 1) if minus else high + 1
    return -int(digits) if minus else int(digits)


def port(text, what, default=None):
    """A whole number from 1 to 65535.

    Absent or empty takes `default` where the form shows one and is refused where it
    does not. Whitespace is not empty: it is refused, like any other non-number.
    """
    typed = "" if text is None else str(text)
    if typed == "":
        if default is None:
            raise Refused(f"The {what} is needed.")
        return default
    number = whole_number(typed, 65535) if PORT_NUMBER.fullmatch(typed) else 0
    if not 1 <= number <= 65535:
        raise Refused(f"The {what} must be a whole number from 1 to 65535.")
    return number


def protocol(text, default="pop3"):
    """`pop3` or `imap`. A form that does not carry the field keeps `default`: the
    add form's POP3, or the stored protocol on the settings form, as an absent login is kept."""
    typed = "" if text is None else str(text).strip()
    if not typed:
        return default
    if typed not in PROTOCOLS:
        raise Refused(NOT_A_PROTOCOL)
    return typed


def protocol_change(state, before, after):
    """`after`, refused when it differs from `before` on an enabled mailbox."""
    if after != before and state == "active":
        raise Refused(PROTOCOL_WHILE_ENABLED)
    return after


def keeps_at_provider(chosen, keep):
    """Refused when mail is not kept at the provider of an IMAP mailbox."""
    if chosen == "imap" and not keep:
        raise Refused(IMAP_KEEPS)


def window(text):
    """The provider-side deletion window in days; empty is the form's 14."""
    typed = str(text or "").strip()
    if not typed:
        return WINDOW_DEFAULT
    if not WHOLE_NUMBER.fullmatch(typed):
        raise Refused("The deletion window must be a whole number of days.")
    days = whole_number(typed, WINDOW_MAX)
    if days <= 0:
        raise Refused("The deletion window must be more than zero days.")
    if days > WINDOW_MAX:
        raise Refused(f"The deletion window must be at most {WINDOW_MAX} days.")
    return days


def spam_threshold(text):
    """A number from 1.00 to 150.00, quantised first.

    Empty is refused rather than defaulted: a threshold nobody typed is not a policy
    anybody chose.
    """
    if not isinstance(text, str) or not text.strip():
        raise Refused(SPAM_NOT_A_NUMBER)
    return number_in_range(text, SPAM_LOW, SPAM_HIGH, places=2, what="spam score threshold",
                           not_a_number=SPAM_NOT_A_NUMBER, out_of_range=SPAM_OUT_OF_RANGE)


def password_twice(first, second, empty=None):
    """The password an administrator typed into two fields.

    A line break is refused here, not at the hash: `openssl passwd -stdin` reads one
    line, so a password carrying one could only ever be hashed truncated (auth.py).
    """
    one, two = str(first or ""), str(second or "")
    if not one and not two:
        raise Refused(empty or "A password is needed, typed twice.")
    if one != two:
        raise Refused("The two passwords differ.")
    if "\n" in one or "\r" in one:
        raise Refused("A password cannot carry a line break.")
    if len(one) < PASSWORD_MIN:
        raise Refused(f"A password is at least {PASSWORD_MIN} characters. Nothing else "
                      "is required of it.")
    # ⛔ A password past what the hasher accepts is a sentence here, not a
    # ValueError from `make_hash` (a 500) after the screen has already accepted it.
    if auth.too_long(one):
        raise Refused(TOO_LONG)
    return one
