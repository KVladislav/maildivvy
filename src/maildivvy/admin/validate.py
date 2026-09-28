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
INNER = re.compile(r"[\s\x00-\x1f\x7f]")

WHOLE_NUMBER = re.compile(r"^-?[0-9]+$")
PORT_NUMBER = re.compile(r"^[0-9]+$")

# ⚠️ THE DOT-INSENSITIVE HOSTS ARE CODE, NOT A SETTING. Folding decides one
# thing: whether a second spelling of an address already here is refused, which is the
# only guard against two fetchers on one provider mailbox. It is a fact about a
# provider, so it ships with the product and changes with a release.
CONSUMER_HOSTS = frozenset({"gmail.com", "googlemail.com"})

WINDOW_DEFAULT = 14
WINDOW_MAX = 1000000       # the date arithmetic's bound, not a policy
PASSWORD_MIN = 15          # a length, and no composition rule at all
PASSWORD_MAX = 1024        # auth.PASSWORD_MAX: what `openssl passwd` will hash
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
    if ALL_DIGITS.match(text):
        return False
    labels = text.split(".")
    return len(labels) > 1 and all(LABEL.match(label) for label in labels)


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
    """A person's login, by the schema's own rule and as typed.

    ⚠️ NEVER LOWERCASED. A login is what a person types into their mail client, and a
    spelling nobody was told is one nobody can use; a capital is refused, not folded.
    The match is whole-string, because a pattern anchored with `$` in Python accepts a
    trailing newline that the column refuses.

    The screens that use it came later; the rule is here with the others so that
    one function serves every screen and the journal filter alike.
    """
    typed = str(text or "").strip()
    if not typed or not ACCOUNT_LOGIN.fullmatch(typed):
        raise Refused(
            "A login is lowercase letters, digits, dots, hyphens and underscores, at "
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
    if not at or not local or "." not in host:
        raise Refused(f"{typed} is not an address.")
    local, host = local.lower(), host.lower()
    if host in CONSUMER_HOSTS:
        local = local.split("+", 1)[0].replace(".", "")
    if not local:
        raise Refused(f"{typed} is not an address.")
    return typed, f"{local}@{host}"


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
    if not PORT_NUMBER.fullmatch(typed) or not 1 <= int(typed) <= 65535:
        raise Refused(f"The {what} must be a whole number from 1 to 65535.")
    return int(typed)


def window(text):
    """The provider-side deletion window in days; empty is the form's 14."""
    typed = str(text or "").strip()
    if not typed:
        return WINDOW_DEFAULT
    if not WHOLE_NUMBER.fullmatch(typed):
        raise Refused("The deletion window must be a whole number of days.")
    days = int(typed)
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
    if len(one) > PASSWORD_MAX:
        raise Refused(f"A password is at most {PASSWORD_MAX} characters.")
    return one
