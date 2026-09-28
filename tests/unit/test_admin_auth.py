"""Sign-in, the session token and the files the service refuses to start without.

Flask is the distribution's and is not installed here, so what needs the application
object is driven on the test VM. Everything in
this file is the part that needs neither Flask nor a database: the hash check, the
login's shape, the cookie's signature, the session's two numbers and the preflight.
"""

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

from maildivvy.admin import auth
from maildivvy.lib.config import ConfigError

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "maildivvy" / "admin"
SCHEMA = ROOT / "schema" / "0001_initial.sql"

PASSWORD = "a-password-of-fifteen-and-more"


def sha512_crypt(password, salt="saltsaltsaltsalt"):
    """A `$6$` hash made the way the machine makes them (`openssl passwd -6`)."""
    return subprocess.run(["openssl", "passwd", "-6", "-stdin", "-salt", salt],
                          input=password + "\n", capture_output=True, text=True,
                          check=True).stdout.strip()


@pytest.fixture
def etc(tmp_path):
    """An `/etc/maildivvy` the preflight can read: the admin consumer's three files."""
    directory = tmp_path / "admin"
    directory.mkdir()
    passfile = directory / "pgpass"
    passfile.write_text("/var/run/postgresql:5432:maildivvy:maildivvy_admin:secret\n")
    passfile.chmod(0o600)
    (directory / "db.conf").write_text(
        f"dbname=maildivvy\nuser=maildivvy_admin\npassfile={passfile}\n")
    (directory / "db.conf").chmod(0o640)
    secret = directory / "secret"
    secret.write_text("0" * 64 + "\n")
    secret.chmod(0o600)
    return tmp_path


# --- the hashes the mail server uses, read by the interface itself --------------

def test_a_scheme_prefixed_account_hash_is_verified_by_the_interface_itself():
    stored = "{SHA512-CRYPT}" + sha512_crypt(PASSWORD)
    assert auth.verify_password(PASSWORD, stored)
    assert not auth.verify_password(PASSWORD + "x", stored)


def test_the_break_glass_hash_is_stored_bare_and_verified_the_same_way():
    stored = sha512_crypt(PASSWORD)
    assert not stored.startswith("{")
    assert auth.verify_password(PASSWORD, stored)
    assert not auth.verify_password("", stored)


@pytest.mark.parametrize("stored", ["", "{SHA512-CRYPT}", "{PLAIN}" + PASSWORD,
                                    "{SHA512-CRYPT}$5$salt$" + "a" * 43,
                                    "$6$salt$tooshort", "{SHA512-CRYPT}$6$rounds=9000$salt$"
                                    + "a" * 86, None, 17])
def test_a_hash_that_is_not_one_this_interface_can_check_admits_nobody(stored):
    # including a `rounds=` hash: `openssl passwd -6` cannot reproduce one, and a check
    # that cannot be made is a refusal, never an acceptance
    assert not auth.verify_password(PASSWORD, stored)


def test_a_password_this_openssl_cannot_be_handed_whole_is_refused_rather_than_truncated():
    stored = "{SHA512-CRYPT}" + sha512_crypt(PASSWORD)
    assert not auth.verify_password(PASSWORD + "\n" + PASSWORD, stored)  # -stdin reads one line
    assert not auth.verify_password("x" * (auth.PASSWORD_MAX + 1), stored)
    assert auth.verify_password(PASSWORD, stored)                        # the control


def test_a_password_of_the_decisions_length_and_of_sixty_four_both_verify():
    for length in (15, 64):
        password = "p" * length
        assert auth.verify_password(password, "{SHA512-CRYPT}" + sha512_crypt(password))


# --- the login as typed ----------------------------------------

@pytest.mark.parametrize("typed,login", [("ivan", "ivan"), ("ivan@example.org", "ivan"),
                                         ("ivan@a@b", "ivan"), ("  ivan  ", "ivan"),
                                         ("IVAN", "IVAN"), ("@example.org", ""), ("", "")])
def test_the_account_is_the_text_before_the_first_at_and_the_login_is_never_lowercased(typed, login):
    assert auth.account_login(typed) == login


def test_the_reserved_break_glass_login_is_the_one_the_schema_refuses_for_an_account():
    assert auth.BREAK_GLASS_LOGIN == "break-glass"
    assert f"'{auth.BREAK_GLASS_LOGIN}'" in SCHEMA.read_text()   # the account CHECK names it


# --- the session's cookie ---------------------------------------

def test_the_cookie_carries_an_opaque_token_and_none_of_the_sessions_stamps():
    token = auth.new_token()
    value = auth.sign(b"a-secret", token)
    assert token in value and value != token           # the token and its signature
    assert re.fullmatch(r"[A-Za-z0-9_.\-]+", value)
    # nothing about who, when issued or when last seen: those are the row's, not the holder's
    assert len(set(auth.new_token() for _ in range(50))) == 50


def test_what_the_database_keeps_is_a_hash_of_the_token_never_the_token():
    token = auth.new_token()
    assert auth.token_hash(token) != token
    assert len(auth.token_hash(token)) == 64
    assert auth.token_hash(token) == auth.token_hash(token)


@pytest.mark.parametrize("edit", [lambda v: v[:-1], lambda v: v + "x", lambda v: v.split(".")[0],
                                  lambda v: "", lambda v: v.replace(".", ".a"),
                                  lambda v: v.upper()])
def test_a_cookie_that_is_not_signed_by_this_key_is_no_session_and_is_never_read_in_part(edit):
    value = auth.sign(b"a-secret", auth.new_token())
    assert auth.unsign(b"a-secret", edit(value)) is None


def test_a_cookie_signed_by_another_key_is_refused_and_the_right_one_is_the_control():
    value = auth.sign(b"a-secret", "token-value")
    assert auth.unsign(b"another-secret", value) is None
    assert auth.unsign(b"a-secret", value) == "token-value"


def test_the_csrf_token_is_bound_to_the_session_and_the_secret_and_forgeable_by_neither():
    # A per-session token, a sha256 hex digest, that changes with the session
    # and with the machine's secret, so it cannot be forged from another session or machine
    token = auth.csrf_token(b"a-secret", "session-one")
    assert re.fullmatch(r"[0-9a-f]{64}", token)
    assert auth.csrf_token(b"a-secret", "session-one") == token          # deterministic
    assert auth.csrf_token(b"a-secret", "session-two") != token          # another session
    assert auth.csrf_token(b"another-secret", "session-one") != token    # another machine


# --- the two numbers that bound a session ------------------------

def test_a_session_idles_out_at_fifteen_minutes_and_ends_at_eight_hours():
    assert auth.IDLE_SECONDS == 15 * 60
    assert auth.ABSOLUTE_SECONDS == 8 * 60 * 60


def test_the_session_read_ends_a_session_when_its_password_changed():
    # An ordinary session is valid only from its account's password_set_at, and
    # a break-glass session only from the break-glass row's set_at, so a password change or
    # a rotation ends the sessions it should
    assert "s.created_at >= a.password_set_at" in auth.READ
    assert "s.created_at >= (SELECT set_at FROM break_glass)" in auth.READ
    # the break-glass branch still reads no account row
    glass = auth.READ.split("OR EXISTS")[0]
    assert "break_glass" in glass and "FROM account" not in glass


def test_no_third_number_and_no_confirmation_stamp_is_kept_anywhere():
    # no act asks for the password again, so there is no freshness to record
    source = "\n".join(path.read_text() for path in sorted(PACKAGE.glob("*.py")))
    for word in ("confirmed_at", "last_confirmed", "FRESHNESS", "reprompt", "re_prompt"):
        assert word not in source, word
    assert "confirmed_at" not in SCHEMA.read_text()


# --- the signing key and the files it will not start without ----------

def test_the_signing_key_is_read_only_when_it_is_0600_and_not_empty(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("0" * 64 + "\n")
    secret.chmod(0o600)
    assert auth.read_secret(secret) == b"0" * 64

    secret.chmod(0o640)
    with pytest.raises(ConfigError) as raised:
        auth.read_secret(secret)
    assert str(secret) in str(raised.value) and "0640" in str(raised.value)

    secret.chmod(0o600)
    secret.write_text("")
    with pytest.raises(ConfigError) as raised:
        auth.read_secret(secret)
    assert str(secret) in str(raised.value)


def test_a_signing_key_that_is_not_there_names_the_file_it_wanted(tmp_path):
    with pytest.raises(ConfigError) as raised:
        auth.read_secret(tmp_path / "nowhere")
    assert "nowhere" in str(raised.value)


def test_the_preflight_opens_every_file_the_service_reads_and_passes_when_they_are_there(etc):
    assert auth.preflight(etc=etc) == []


@pytest.mark.parametrize("name", ["db.conf", "pgpass", "secret"])
def test_a_file_the_service_reads_that_is_missing_is_named_and_the_service_does_not_start(etc, name):
    (etc / "admin" / name).unlink()
    problems = auth.preflight(etc=etc)
    assert len(problems) == 1 and name in problems[0]


def test_a_file_this_uid_cannot_read_is_a_refusal_not_a_yes_from_exists(etc):
    if os.geteuid() == 0:
        pytest.skip("root opens a 0000 file, so this measures nothing as root")
    (etc / "admin" / "secret").chmod(0o000)
    problems = auth.preflight(etc=etc)
    assert len(problems) == 1 and "secret" in problems[0]


def test_a_passfile_libpq_would_silently_ignore_is_refused_by_name(etc):
    (etc / "admin" / "pgpass").chmod(0o640)
    problems = auth.preflight(etc=etc)
    assert len(problems) == 1 and "pgpass" in problems[0]


def test_every_problem_is_reported_at_once_not_the_first(etc):
    (etc / "admin" / "secret").unlink()
    (etc / "admin" / "pgpass").unlink()
    assert len(auth.preflight(etc=etc)) == 2


# --- what the interface may never be ------------

def test_no_page_the_application_serves_carries_an_http_equiv_or_a_refresh():
    source = "\n".join(path.read_text() for path in sorted(PACKAGE.rglob("*.py")))
    assert "http-equiv" not in source.lower()
    assert "refresh" not in source.lower()


def test_the_interface_imports_itself_by_the_name_the_installed_tree_carries():
    # /opt/maildivvy/lib/maildivvy is the same package name as src/maildivvy, so the
    # tests' import path is the installed one. Nothing here imports a
    # top-level module that exists only in a checkout.
    for path in sorted(PACKAGE.glob("*.py")):
        for line in path.read_text().splitlines():
            if line.startswith(("import ", "from ")) and "maildivvy" in line:
                assert line.startswith(("from maildivvy", "import maildivvy")), f"{path.name}: {line}"


def test_nothing_in_the_interface_lets_a_person_change_their_own_password():
    source = "\n".join(path.read_text() for path in sorted(PACKAGE.rglob("*.py")))
    for word in ("old_password", "current_password", "change_own", "my-password"):
        assert word not in source, word


def test_there_is_one_refusal_sentence_and_the_timed_out_one_says_something_else():
    assert auth.REFUSAL == "That login and password were not accepted."
    assert auth.SIGN_IN == "Please sign in."


def test_the_installed_secret_is_the_one_the_role_writes():
    # the programs role writes /etc/maildivvy/admin/secret, 0600 by the interface's user
    role = (ROOT / "ansible" / "roles" / "programs" / "tasks" / "main.yml").read_text()
    assert "/admin/secret" in role.replace("{{ maildivvy_etc }}", "")
    assert str(auth.SECRET_NAME) == "secret"


def test_the_package_keeps_no_bytecode_where_the_deployed_tree_is_read():
    program = (ROOT / "bin" / "maildivvy-admin").read_text()
    assert "sys.dont_write_bytecode = True" in program
    assert oct(stat.S_IMODE((ROOT / "bin" / "maildivvy-admin").stat().st_mode)) == "0o755"
