"""The journal's writing half, and the two validators it shares with the screens.

The journal is one INSERT through one function, from a closed list of
act names, with every value judged by its shape before it is written.
None of that needs a database, so it is all here; the
row's transaction, its `request_id` join and the append-only grant are the VM suite's.
"""

import ast
import json
import re
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

from maildivvy.admin import journal, validate

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "maildivvy" / "admin"
SCHEMA = ROOT / "schema" / "0001_initial.sql"


class FakeCursor:
    def __init__(self, calls):
        self.calls = calls
        self.description = []
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return self.rows


class FakeConnection:
    """Enough of a driver connection to read back the statement and its parameters."""

    def __init__(self):
        self.calls = []

    def cursor(self):
        return FakeCursor(self.calls)


# --- the declared list -------------------------------------------------------

def test_the_acts_are_a_closed_declared_list_the_interface_the_pipeline_and_the_fetcher_share():
    # the three writers of a journal row, each declared apart, and the union is the list
    assert journal.DECLARED == frozenset(journal.INTERFACE_ACTS + journal.PIPELINE_ACTS
                                         + journal.FETCHER_ACTS)
    assert "break_glass_use" in journal.INTERFACE_ACTS       # its own row
    assert "test_credential" in journal.PIPELINE_ACTS        # asked for by the interface
    assert "auto_skip_message" in journal.FETCHER_ACTS
    # the product's names, not the predecessor's: an act the pipeline performs is named by
    # its request kind, so the declared `delete_real_mailbox`, `release_message` and
    # `transfer_mailbox` are `delete_external_mailbox`, `release` and `transfer` here
    assert "delete_external_mailbox" in journal.PIPELINE_ACTS
    for source_name in ("delete_real_mailbox", "release_message", "transfer_mailbox",
                        "run_top_up", "run_refetch", "deliver_one_message"):
        assert source_name not in journal.DECLARED, source_name


def test_the_pipelines_act_names_are_the_request_kinds_the_schema_declares():
    kinds = re.search(r"kind\s+text NOT NULL CHECK \(kind IN \((.*?)\)\)",
                      SCHEMA.read_text(), re.S).group(1)
    assert set(re.findall(r"'([a-z_]+)'", kinds)) == set(journal.PIPELINE_ACTS)


@pytest.mark.parametrize("module,writer,index,declared", [
    ("fanout/requests.py", "journal", 2, "PIPELINE_ACTS"),
    ("fetch/runner.py", "audit", 1, "FETCHER_ACTS"),
])
def test_what_the_other_two_writers_name_their_acts_is_declared_here(module, writer, index,
                                                                     declared):
    """The interface owns the list; the pipeline and the fetcher write rows of their own."""
    path = ROOT / "src" / "maildivvy" / module
    written = set()
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == writer \
                and len(node.args) > index and isinstance(node.args[index], ast.Constant):
            written.add(node.args[index].value)
    assert written, f"the control: no {writer}() call was found in {module}"
    assert written <= set(getattr(journal, declared)), written - set(getattr(journal, declared))


def test_an_act_nobody_declared_is_refused_where_it_is_written_not_stored():
    conn = FakeConnection()
    with pytest.raises(journal.UndeclaredAct) as raised:
        journal.record(conn, actor="ivan", action="tidy_up", target="alpha")
    assert "tidy_up" in str(raised.value)
    assert conn.calls == []                                   # nothing was sent


def test_every_act_the_interface_writes_by_name_is_declared():
    """The parsing test of the entry: every literal act name in the package is in the list."""
    names = set()
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "record":
                for keyword in node.keywords:
                    if keyword.arg == "action" and isinstance(keyword.value, ast.Constant):
                        names.add(keyword.value.value)
    assert names, "the control: the walk found no act at all"
    assert names <= set(journal.INTERFACE_ACTS), names - set(journal.INTERFACE_ACTS)


# The three writers and how each names its act: (the function, the argument that holds the
# act's name, the files that call it).
WRITERS = (
    ("record", 1, sorted((PACKAGE / "screens").glob("*.py"))),         # screens: record(conn, act)
    ("journal", 2, [ROOT / "src" / "maildivvy" / "fanout" / "requests.py"]),
    ("audit", 1, [ROOT / "src" / "maildivvy" / "fetch" / "runner.py"]),
)


def _act_names(node):
    """The literal act names an argument can hold: a constant, or either arm of an `if`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _act_names(node.body) | _act_names(node.orelse)
    return set()


def written_acts():
    """Every act name some writer of the product passes as a literal."""
    written = set()
    for function, index, paths in WRITERS:
        for path in paths:
            for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if name != function:
                    continue
                if len(node.args) > index:
                    written |= _act_names(node.args[index])
                written |= {n for k in node.keywords if k.arg == "action" for n in _act_names(k.value)}
    for path in sorted(PACKAGE.glob("*.py")):       # the application's own: break_glass_use
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "record":
                written |= {n for k in node.keywords if k.arg == "action" for n in _act_names(k.value)}
    return written


def test_every_declared_act_has_a_writer_and_every_written_act_is_declared():
    """The second half: the menu offers DECLARED, so an act
    declared with nothing writing it is a filter that always answers "none", which reads the
    same as "none happened" - the predecessor's `break_glass_use`, declared and never written."""
    written = written_acts()
    assert {"break_glass_use", "grant_admin", "revoke_admin", "fetch_frozen"} <= written, written
    assert journal.DECLARED - written == set(), "declared, and nothing writes it"
    assert written - journal.DECLARED == set(), "written, and not declared"


# --- one function writes the journal ---------------------------------------

def test_no_module_of_the_interface_writes_the_journal_except_journal_record():
    wrong = []
    for path in sorted(PACKAGE.glob("*.py")):
        text = path.read_text()
        if path.name != "journal.py" and "INSERT INTO audit" in text.upper():
            wrong.append(path.name)
    assert wrong == []
    assert "INSERT INTO audit" in journal.INSERT           # the control: it is there to find


def test_the_detail_is_written_and_shown_as_json_text():
    assert journal.detail_text({"before": "a", "after": "b"}) == '{"after": "b", "before": "a"}'
    # a hostile value stays text: it is escaped where it is shown, never built into HTML
    assert journal.detail_text({"who": "<script>"}) == '{"who": "<script>"}'


def test_a_row_carries_the_actor_the_action_the_target_and_the_request_it_asked_for():
    conn = FakeConnection()
    journal.record(conn, actor="ivan", action="release", target="<m1@example.org>",
                   detail={"count": 2}, break_glass=True, request_id=7)
    (sql, params), = conn.calls
    assert "INSERT INTO audit" in sql
    assert params == ("ivan", "release", "<m1@example.org>", '{"count": 2}', True, 7)


# --- the secret filter judges the value, never the key ---------

@pytest.mark.parametrize("value", [True, False, None, 0, 17, -3, 2.5,
                                   "short", "a sentence with spaces in it",
                                   "person@example.org", "pop.example.org", "192.0.2.1",
                                   "2001:db8::1", "Correct.Horse.Battery", "alllowercaselettersonly",
                                   "x" * 200])
def test_a_value_that_is_not_password_shaped_is_written_as_itself(value):
    assert journal.filtered(value) == value


@pytest.mark.parametrize("value", ["Tr0ub4dor&3xkcdPass", "S3cret-Passphrase!", "x" * 201,
                                   "aB3" * 4])
def test_a_password_shaped_value_is_withheld(value):
    assert journal.filtered(value) == journal.WITHHELD


def test_the_key_is_never_read_so_credential_set_true_survives():
    detail = {"credential_set": True, "password": 3, "secret": None}
    assert journal.filtered(detail) == detail


def test_the_filter_reaches_into_lists_and_objects():
    detail = {"servers": [{"host": "pop.example.org", "note": "Tr0ub4dor&3xkcdPass"}]}
    assert journal.filtered(detail) == {
        "servers": [{"host": "pop.example.org", "note": journal.WITHHELD}]}


def test_what_is_written_is_what_the_filter_returned():
    conn = FakeConnection()
    journal.record(conn, actor="ivan", action="set_credential", target="ivan.p@example.org",
                   detail={"credential_set": True, "typed": "Tr0ub4dor&3xkcdPass"})
    (_, params), = conn.calls
    assert json.loads(params[3]) == {"credential_set": True, "typed": journal.WITHHELD}


# --- the host rule the filter borrows ----------------------

@pytest.mark.parametrize("value", ["pop.example.org", "a.b", "192.0.2.1", "2001:db8::1",
                                   "::1", "xn--80ak6aa92e.com"])
def test_a_host_is_a_dotted_name_or_an_address_a_real_parser_reads(value):
    assert validate.is_host(value)


@pytest.mark.parametrize("value", ["", "nodotsatall", "-leading.example.org", "a..b",
                                   "pop.example.org:995", "2001:db8::zz", "192.0.2.256",
                                   "with space.example.org", "a" * 64 + ".example.org"])
def test_anything_else_is_not_a_host(value):
    assert not validate.is_host(value)


def test_real_provider_hosts_pass_the_filter_and_dotted_passwords_are_still_withheld():
    """The source's filter withheld a provider host with a digit in it, for some providers
    and not others; the exemption is judged by value. It must fail in both directions."""
    hosts = ["pop2.example.net", "outlook.office365.com", "pop3.mail.example.org",
             "imap.1und1.example", "smtp2go.example.com"]
    assert [journal.filtered(h) for h in hosts] == hosts
    passwords = ["Tr0ub4dor.&3xk", "p4ss.w0rd!x9Q", "a1.B2.c3.D4!e5", "X9y.8Z7!w6v5",
                 "Qw3.rt!y9Ui0p", "zX9.cV8_bN7mK", "L0ng.P4ss#word"]
    assert [journal.filtered(p) for p in passwords] == [journal.WITHHELD] * len(passwords)


def test_the_filters_exemption_is_that_same_rule_so_the_two_cannot_drift():
    # an IPv6 literal is password-shaped by every other test in the rule
    assert validate.is_host("2001:db8:85a3::8a2e:370:7334")
    assert journal.filtered("2001:db8:85a3::8a2e:370:7334") == "2001:db8:85a3::8a2e:370:7334"


# --- the journal's own filters are bound parameters -------------------------

def test_every_filter_value_is_a_bound_parameter_and_nothing_is_built_into_the_sql():
    conn = FakeConnection()
    journal.rows(conn, who="ivan';--", action="create_account", target="<m@x>",
                 since=date(2026, 9, 1), until=date(2026, 9, 30), limit=500)
    (sql, params), = conn.calls
    assert "ivan" not in sql and "create_account" not in sql
    assert list(params) == ["ivan';--", "create_account", "<m@x>", date(2026, 9, 1),
                            date(2026, 9, 30), 500]


def test_the_range_takes_the_whole_of_its_last_day():
    conn = FakeConnection()
    journal.rows(conn, until=date(2026, 9, 30))
    (sql, _), = conn.calls
    assert "+ interval '1 day'" in sql       # `at < to + 1 day`, not `at <= to`


def test_a_date_that_is_not_a_date_is_refused_with_a_sentence_never_ignored():
    assert journal.date_filter("") is None
    assert journal.date_filter("2026-09-30") == date(2026, 9, 30)
    with pytest.raises(validate.Refused) as raised:
        journal.date_filter("30.09.2026")
    assert "YYYY-MM-DD" in str(raised.value)


def test_the_outcome_of_the_request_that_was_asked_for_is_joined_to_the_row():
    conn = FakeConnection()
    journal.rows(conn)
    (sql, _), = conn.calls
    assert "LEFT JOIN request" in sql and "r.state" in sql and "r.result" in sql
    assert "a.break_glass" in sql            # its own column, not part of the detail


def test_at_most_five_hundred_rows_are_read_newest_first():
    assert journal.LIMIT == 500
    conn = FakeConnection()
    journal.rows(conn)
    (sql, params), = conn.calls
    assert "ORDER BY a.at DESC" in sql and params[-1] == 500


# --- the fixed-scale number ------------------------------------------------

@pytest.mark.parametrize("typed,stored", [("8", "8.00"), ("8.005", "8.01"), ("1", "1.00"),
                                          ("150", "150.00"), ("149.994", "149.99")])
def test_a_number_is_quantised_to_the_columns_scale_before_the_bounds_are_read(typed, stored):
    assert validate.number_in_range(typed, Decimal("1.00"), Decimal("150.00")) == Decimal(stored)


@pytest.mark.parametrize("typed", ["NaN", "nan", "Infinity", "-Infinity", "sNaN"])
def test_a_non_finite_number_is_refused_before_any_comparison(typed):
    with pytest.raises(validate.Refused):
        validate.number_in_range(typed, Decimal("1.00"), Decimal("150.00"))


@pytest.mark.parametrize("typed", ["", "  ", "abc", "0.99", "1e400", "-5"])
def test_anything_outside_the_bounds_or_not_a_number_is_a_sentence_not_an_error_page(typed):
    with pytest.raises(validate.Refused):
        validate.number_in_range(typed, Decimal("1.00"), Decimal("150.00"))


def test_the_value_just_past_the_top_is_refused_where_rounding_would_have_hidden_it():
    # 150.004 rounds to 150.00 and is accepted; 150.005 rounds to 150.01 and is refused,
    # which is the number the person would have been shown either way
    assert validate.number_in_range("150.004", Decimal("1.00"), Decimal("150.00")) \
        == Decimal("150.00")
    with pytest.raises(validate.Refused):
        validate.number_in_range("150.005", Decimal("1.00"), Decimal("150.00"))
