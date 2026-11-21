"""Properties of the pure functions that face hostile input, over crafted cases in loops.

No property-testing library: a seeded generator of strings people and providers have
actually sent (control characters, look-alike digits and letters, Unicode spaces,
folded and repeated header lines, numbers past every bound) and a fixed list of the
cases that broke something before. Each test states one property and checks it for
every case; a failure names the case.

- every value a screen's validator accepts, the database's own column accepts too, so a
  refusal is always the screen's sentence and never an error page;
- the journal's filter never raises, keeps the structure, withholds every password-shaped
  string and is idempotent;
- reading a message's headers never raises and every field it yields is in the ledger's
  shape;
- the firewall planner asks nothing of rules already in place, whatever spelling ufw
  wrote them in, and turns any set of rules into the wanted one.
"""

import datetime
import ipaddress
import random
import string
from decimal import Decimal

import pytest

import maildivvy_ufw as ufw
from maildivvy.admin import auth, journal, validate
from maildivvy.fanout import pass_
from maildivvy.lib import headers

SEED = 20261117
CONTROL = [chr(c) for c in (*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0))]
UNICODE = [" ", " ", " ", "​", "﻿", "‮", "́", "а",
           "е", "²", "٣", "１", "․", "。", "\U0001f600", "ß",
           "İ", "K"]
CRAFTED = ["", " ", "\t", "-", ".", "..", "a", "a" * 64, "a" * 65, "a" * 300, "x" * 5000,
           "0", "-1", "+5", "1e3", "1E-2", "nan", "NaN", "inf", "-inf", "0x10", "1_000",
           "1,5", "1.005", "150.004", "150.005", "0.995", " 7 ", "７", "9" * 5000,
           "archive", "break-glass", "Olga", "olga.", ".olga", "o..lga", "olga-", "ol ga",
           "x@y", "@", "a@", "@b", "a@b@c", "pop.example.org.", "pop..example.org",
           "192.0.2.10", "[2001:db8::1]", "2001:db8::1", "pop.example.org:995", "-pop.org",
           "pop.1example", "localhost", "AB:" * 31 + "AB", "ab:" * 31 + "ab",
           "AB" * 32, "SHA256:" + "AB:" * 31 + "AB", "2026-02-30", "2026-W45", "20261101",
           "2026-11-01T00:00", "0000-01-01", "9999-12-31", "a\nb", "a\rb", "a\x00b",
           "аrchive", "Kelvin"]


def strings(count=400, seed=SEED):
    """`CRAFTED`, then `count` strings drawn from every alphabet a field may be sent."""
    pick = random.Random(seed)
    alphabets = [string.ascii_lowercase, string.ascii_letters + string.digits + "._-@:",
                 string.printable, "".join(CONTROL), "".join(UNICODE), "0123456789.-+e"]
    yield from CRAFTED
    for _ in range(count):
        size = pick.choice([1, 2, 5, 12, 31, 32, 33, 63, 64, 65, 120, 257])
        chosen = "".join(pick.choice(alphabets) for _ in range(3))
        yield "".join(pick.choice(chosen) for _ in range(size))


def accepted(read, typed):
    """What `read` makes of `typed`, or None when it refuses it by its sentence. Any
    other exception fails the test: a validator answers, it never raises past a screen."""
    try:
        return read(typed), True
    except validate.Refused:
        return None, False


# --- the screens' validators and the database's own checks ----

EXTERNAL = ("INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host, {}) "
            "VALUES ('a@example.org', 'a@example.org', 'pop.example.org', 'smtp.example.org', %s)")
HASH = "{SHA512-CRYPT}$6$x$" + "x" * 86
COLUMNS = {   # validator -> (the statement that stores what it accepted, how to read it)
    "domain_label": ("INSERT INTO domain (label, archive_password_hash) VALUES (%s, %s)",
                     validate.domain_label, lambda value: (value, HASH)),
    "login": ("INSERT INTO account (login, password_hash) VALUES (%s, %s)",
              validate.login, lambda value: (value, HASH)),
    "pop3_login": (EXTERNAL.format("pop3_login"), validate.pop3_login, lambda v: (v,)),
    "smtp_login": (EXTERNAL.format("smtp_login"), validate.smtp_login, lambda v: (v,)),
    "address": ("INSERT INTO external_mailbox (address, address_canonical, pop3_host, "
                "smtp_host) VALUES (%s, %s, 'pop.example.org', 'smtp.example.org')",
                validate.external_address, lambda pair: pair),
    "host": ("INSERT INTO external_mailbox (address, address_canonical, pop3_host, smtp_host) "
             "VALUES ('a@example.org', 'a@example.org', %s, %s)",
             lambda typed: validate.host(typed, "POP3 host", "pop.example.org"),
             lambda value: (value, value)),
    "port": (EXTERNAL.format("pop3_port"), lambda typed: validate.port(typed, "POP3 port"),
             lambda v: (v,)),
    "window": (EXTERNAL.format("delete_window_days"), validate.window, lambda v: (v,)),
    "fingerprint": (EXTERNAL.format("pop3_cert_fingerprint"),
                    lambda typed: validate.fingerprint(typed, "POP3 certificate fingerprint"),
                    lambda v: (v,)),
    "threshold": ("INSERT INTO domain (label, archive_password_hash, spam_threshold) "
                  "VALUES ('x', %s, %s)", validate.spam_threshold, lambda v: (HASH, v)),
}


@pytest.mark.parametrize("name", sorted(COLUMNS))
def test_every_value_a_screen_accepts_its_column_accepts_too(database, name):
    statement, read, parameters = COLUMNS[name]
    conn = database.cluster.superuser(database.name).conn
    conn.autocommit = False
    taken, refused = 0, []
    try:
        with conn.cursor() as cursor:
            for typed in strings():
                value, ok = accepted(read, typed)
                if not ok:
                    continue
                taken += 1
                cursor.execute("SAVEPOINT one")
                try:
                    cursor.execute(statement, parameters(value))
                except database.psycopg2.Error as error:
                    refused.append((typed, value, error.pgcode))
                cursor.execute("ROLLBACK TO SAVEPOINT one")
    finally:
        conn.rollback()
        conn.close()
    assert taken, f"{name} accepted nothing at all, which would prove nothing"
    assert not refused, refused[:5]


def test_every_password_a_form_accepts_can_be_hashed_and_checked():
    hashed = 0
    for typed in strings(count=60):
        value, ok = accepted(lambda text: validate.password_twice(text, text), typed)
        if ok:
            stored = auth.make_hash(value)
            assert auth.verify_password(value, stored), repr(typed)
            hashed += 1
        # a pair that differs is never a password, whatever it holds
        assert not accepted(lambda text: validate.password_twice(text, text + "x"), typed)[1]
    assert hashed


def test_a_date_is_accepted_only_as_the_calendar_date_typed(database):
    for typed in strings():
        value, ok = accepted(lambda text: validate.calendar_date(text, "date"), typed)
        if ok:
            assert isinstance(value, datetime.date) and value.isoformat() == typed.strip()
            assert database.value("SELECT %s::date", (typed.strip(),)) == value
        # the journal's filter takes what the form takes, and an empty one as no filter
        if typed.strip():
            filtered, taken = accepted(journal.date_filter, typed)
            assert taken == ok and filtered == value, repr(typed)


def test_a_threshold_is_two_places_and_within_its_bounds_whatever_was_typed():
    for typed in strings():
        value, ok = accepted(validate.spam_threshold, typed)
        if ok:
            assert isinstance(value, Decimal) and value.is_finite()
            assert Decimal("1.00") <= value <= Decimal("150.00")
            assert value == value.quantize(Decimal("0.01"))


# --- the journal's filter ------------------------------------------

def details(pick):
    """Nested journal details: what an act's detail may hold, with strings from `strings`."""
    values = list(strings(count=200))
    for _ in range(300):
        depth = pick.choice([0, 1, 2])
        yield build(pick, values, depth)


def build(pick, values, depth):
    leaf = pick.choice([True, False, None, 0, -7, 2 ** 63, 1.5, pick.choice(values)])
    if depth == 0:
        return leaf
    if pick.random() < 0.5:
        return [build(pick, values, depth - 1) for _ in range(pick.randint(0, 3))]
    return {pick.choice(["password", "login", "before", "after", "x", pick.choice(values)]):
            build(pick, values, depth - 1) for _ in range(pick.randint(0, 3))}


def same_shape(before, after):
    if isinstance(before, dict):
        assert isinstance(after, dict) and list(after) == list(before)
        for key in before:
            same_shape(before[key], after[key])
    elif isinstance(before, (list, tuple)):
        assert isinstance(after, list) and len(after) == len(before)
        for one, other in zip(before, after):
            same_shape(one, other)
    elif isinstance(before, str):
        assert after in (before, journal.WITHHELD)
    else:
        assert after == before and type(after) is type(before)


def test_the_filter_keeps_the_shape_judges_every_string_and_is_idempotent():
    for detail in details(random.Random(SEED)):
        once = journal.filtered(detail)
        same_shape(detail, once)
        assert journal.filtered(once) == once


def test_every_string_of_a_passwords_shape_and_every_long_one_is_withheld_under_any_key():
    """The rule as the filter states it: past `LONG` characters, or at least `SHAPED`
    with no space and no `@` and `CLASSES` kinds of character, unless it is a host."""
    pick = random.Random(SEED)
    kinds = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!#%&*+-_=?^~"]
    for _ in range(300):
        three = pick.sample(kinds, journal.CLASSES)
        shaped = [pick.choice(kind) for kind in three]
        shaped += [pick.choice("".join(three)) for _ in range(pick.randint(
            journal.SHAPED - len(shaped), 40))]
        pick.shuffle(shaped)
        password = "".join(shaped)
        long = "".join(pick.choice(string.printable) for _ in range(journal.LONG + 1))
        if validate.is_host(password):
            continue
        for key in ("password", "comment", "x", "before"):
            assert journal.filtered({key: [password, long]}) == {
                key: [journal.WITHHELD, journal.WITHHELD]}, (password, long)


def test_a_host_or_a_fingerprint_is_never_mistaken_for_a_password():
    pick = random.Random(SEED)
    for _ in range(300):
        labels = ["".join(pick.choice(string.ascii_lowercase + string.digits)
                          for _ in range(pick.randint(3, 12))) for _ in range(3)]
        host = ".".join(labels) + ".example.org"
        pin = ":".join(f"{pick.randrange(256):02X}" for _ in range(32))
        assert journal.filtered([host, pin]) == [host, pin]


# --- a message's headers, as the pass reads them ------------------------------

HEADER_PARTS = ["Anna <anna@example.org>", "acme@gmail.com <impostor@example.net>",
                '"a@b" <c@d>', "<>", "=?utf-8?b?0J/RgNC40LLQtdGC?= <x@y.z>", "x" * 3000,
                "\n continued", "\nX-Second: value", "\n\tfolded", "\r\n", "\x00", "yes",
                "YES", "no", "none", "  ", "12.5", "1e400", "-1e400", "NaN", "Infinity",
                "99999.99", "Mon, 1 Jan 2026 00:00:00 +0000", "Mon, 1 Jan 99999 00:00:00 +0000",
                "Mon, 1 Jan 2026 00:00:00 +9999", "Thu, 31 Feb 2026 25:61:61 GMT", "garbage",
                "<id@example.org>", "‮а@е.org"]
HEADERS = ("hdr.from", "hdr.subject", "hdr.date", "hdr.message-id", headers.MARK_FIELD,
           headers.SCORE_FIELD, headers.WITHHELD_FIELD, headers.REASON_FIELD)


def records(pick):
    for uid in range(1, 600):
        record = {"uid": str(uid)}
        for name in HEADERS:
            if pick.random() < 0.8:
                record[name] = "".join(pick.choice(HEADER_PARTS + list(strings(count=0)))
                                       for _ in range(pick.randint(0, 4)))
        yield record


def test_reading_any_message_never_raises_and_every_field_is_in_the_ledgers_shape():
    for record in records(random.Random(SEED)):
        message = pass_.read(record)
        assert message.uid == int(record["uid"])
        assert message.sender is None or (
            "@" in message.sender and message.sender == message.sender.lower())
        for text in (message.subject, message.message_id):
            assert text is None or ("\n" not in text and text == text.strip() and text)
        # a date with no zone, or `-0000`, is the standard library's naive one
        assert message.date is None or isinstance(message.date, datetime.datetime)
        assert message.spam is (headers.first_line(record.get(headers.MARK_FIELD))
                                .lower() == "yes")
        assert message.score is None or (message.score.is_finite()
                                         and abs(message.score) < pass_.SCORE_LIMIT)
        for ours in (message.withheld_id, message.reason):
            assert ours not in ("", headers.NONE) and (ours is None or "\n" not in ours)


def test_a_senders_own_copy_of_our_field_below_ours_is_never_read():
    pick = random.Random(SEED)
    for value in strings(count=200):
        ours = pick.choice(["yes", "no", "none", "w-17"])
        record = {"uid": "1", headers.MARK_FIELD: f"{ours}\n{value}",
                  headers.WITHHELD_FIELD: f"{ours}\n{value}"}
        message = pass_.read(record)
        assert message.spam is (ours == "yes")
        assert message.withheld_id == (None if ours == "none" else ours)


# --- the firewall planner ----------------------------------------------------

def networks(pick):
    """Administrator networks as the settings spell them, with the spelling ufw writes."""
    for _ in range(200):
        if pick.random() < 0.5:
            prefix = pick.choice([32, 32, 24, 16, 8])
            address = ipaddress.IPv4Address(pick.getrandbits(32))
            net = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            settings = str(net.network_address) if prefix == 32 else str(net)
            ufw_spelling = pick.choice([str(net.network_address) if prefix == 32 else str(net),
                                        f"{net.network_address}/{net.netmask}"])
        else:
            prefix = pick.choice([128, 64, 48])
            address = ipaddress.IPv6Address(pick.getrandbits(128))
            net = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            settings = (str(net.network_address) if prefix == 128 else str(net)).upper()
            ufw_spelling = str(net.network_address) if prefix == 128 else str(net)
        yield settings, ufw_spelling


def as_written(rule, spelling):
    """A wanted rule as ufw lists it in its rule file, its source in ufw's spelling."""
    return (*rule[:5], spelling, rule[6])


def test_rules_already_in_place_ask_for_nothing_whatever_spelling_ufw_wrote():
    pick = random.Random(SEED)
    for settings, spelling in networks(pick):
        wanted = ufw.desired([settings], [22, 443])
        current = [as_written(rule, spelling) for rule in wanted]
        assert ufw.plan(current, wanted) == ([], [], []), (settings, spelling)


def test_any_set_of_rules_is_turned_into_the_wanted_one_and_nothing_kept_is_touched():
    pick = random.Random(SEED)
    spelled = list(networks(pick))
    for _ in range(200):
        chosen = pick.sample(spelled, pick.randint(1, 4))
        wanted = ufw.desired([settings for settings, _ in chosen], [22, 443])
        stale = ufw.desired([settings for settings, _ in pick.sample(spelled, 2)], [22, 8080])
        kept = ufw.published_rules([("allow", "tcp", "993", "0.0.0.0/0", "any", "0.0.0.0/0",
                                     "in")], [993])
        current = pick.sample(wanted, pick.randint(0, len(wanted))) + stale + kept
        add, delete, errors = ufw.plan(current, wanted, kept)
        assert not errors
        # what is added is exactly what was missing, SSH before anything else
        missing = [rule for rule in wanted if rule not in current]
        assert len(add) == len(missing)
        ports = [argv[argv.index("port") + 1] for argv in add]
        assert ports == sorted(ports, key=lambda port: port != "22")
        # what is deleted is exactly what is neither wanted nor kept
        gone = {ufw._key(rule) for rule in current} - {ufw._key(rule) for rule in wanted + kept}
        assert len(delete) == len(gone)
        assert all(argv[1] == "delete" and "993" not in argv for argv in delete)
