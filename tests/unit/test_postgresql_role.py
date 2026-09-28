"""Install step 6's helper (`ansible/roles/postgresql/files/maildivvy_pg.py`): role
passwords set as SCRAM verifiers made on the machine, the libpq passfiles, and the
break-glass hash. PostgreSQL itself is proved on the test VM.
"""

import base64
import hashlib
import hmac
import importlib.util
import os
import stat
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
PROGRAM = ROOT / "ansible" / "roles" / "postgresql" / "files" / "maildivvy_pg.py"
spec = importlib.util.spec_from_file_location("maildivvy_pg", PROGRAM)
pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pg)

ME = (os.getuid(), os.getgid())


def test_the_scram_verifier_answers_rfc_7677s_exchange():
    # RFC 7677 § 3: user "user", password "pencil"; the server's signature over the
    # exchange must come out of the verifier's server key, and the client's proof must
    # recover a client key whose hash is the verifier's stored key.
    salt = base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ==")
    verifier = pg.scram_verifier("pencil", salt=salt, iterations=4096)
    method, rest = verifier.split("$", 1)
    params, keys = rest.split("$")
    assert method == "SCRAM-SHA-256" and params == "4096:W22ZaJ0SNY7soEsUEjb6gQ=="
    stored_key, server_key = (base64.b64decode(k) for k in keys.split(":"))
    auth = ("n=user,r=rOprNGfwEbeRWgbNEkqO,"
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,"
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0").encode()
    server_signature = hmac.new(server_key, auth, hashlib.sha256).digest()
    assert base64.b64encode(server_signature).decode() == "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    proof = base64.b64decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
    client_signature = hmac.new(stored_key, auth, hashlib.sha256).digest()
    client_key = bytes(a ^ b for a, b in zip(proof, client_signature))
    assert hashlib.sha256(client_key).digest() == stored_key


def test_each_verifier_has_its_own_salt():
    assert pg.scram_verifier("pencil") != pg.scram_verifier("pencil")


def test_a_passfile_line_is_five_colon_separated_fields():
    line = pg.passfile_line("maildivvy", "maildivvy_owner", "0123abcd")
    assert line == "localhost:5432:maildivvy:maildivvy_owner:0123abcd\n"
    assert len(line.strip().split(":")) == 5


def test_a_new_passfile_is_written_0600_by_its_reader_with_a_generated_password(tmp_path):
    path = tmp_path / "pgpass"
    password, written = pg.ensure_passfile(path, "maildivvy", "maildivvy_owner", *ME)
    assert written and len(password) == 64 and int(password, 16) >= 0
    st = path.stat()
    assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o600, *ME)
    assert path.read_text() == pg.passfile_line("maildivvy", "maildivvy_owner", password)


def test_a_role_whose_daemon_connects_over_tcp_has_that_address_in_its_passfile(tmp_path):
    # libpq matches the passfile's first field against the host it is given, so a role
    # read by a chrooted daemon (Postfix, step 9) needs the address it dials, not
    # `localhost`, which the chroot could not resolve anyway
    path = tmp_path / "pgpass"
    password, written = pg.ensure_passfile(path, "maildivvy", "maildivvy_postfix", *ME, "127.0.0.1")
    assert written and path.read_text().startswith("127.0.0.1:5432:maildivvy:maildivvy_postfix:")
    again, rewritten = pg.ensure_passfile(path, "maildivvy", "maildivvy_postfix", *ME, "127.0.0.1")
    assert (again, rewritten) == (password, False)
    # the same file read as a socket passfile is not this role's: it is written again
    _, over_socket = pg.ensure_passfile(path, "maildivvy", "maildivvy_postfix", *ME)
    assert over_socket


def test_an_existing_passfile_keeps_its_password(tmp_path):
    path = tmp_path / "pgpass"
    first, _ = pg.ensure_passfile(path, "maildivvy", "maildivvy_owner", *ME)
    again, written = pg.ensure_passfile(path, "maildivvy", "maildivvy_owner", *ME)
    assert (again, written) == (first, False)


@pytest.mark.parametrize("content", ["bare-secret\n", "localhost:5432:maildivvy:someone_else:pw\n",
                                     "localhost:5432:maildivvy:maildivvy_owner:\n", ""])
def test_a_passfile_that_is_not_the_roles_five_fields_is_written_again(tmp_path, content):
    path = tmp_path / "pgpass"
    path.write_text(content)
    password, written = pg.ensure_passfile(path, "maildivvy", "maildivvy_owner", *ME)
    assert written and path.read_text() == pg.passfile_line("maildivvy", "maildivvy_owner", password)


@pytest.mark.parametrize("role", ["maildivvy_owner", "maildivvy_pipeline"])
def test_a_role_name_is_accepted_only_in_the_products_shape(role):
    assert pg.role_name(role) == role


@pytest.mark.parametrize("role", ["postgres", "maildivvy-owner", "maildivvy_owner; DROP", "Maildivvy_x", ""])
def test_any_other_role_name_is_refused(role):
    with pytest.raises(pg.PgError):
        pg.role_name(role)


@pytest.mark.parametrize("value, ok", [
    ("$6$" + "a" * 16 + "$" + "b" * 86, True),
    ("$6$rounds=5000$" + "a" * 16 + "$" + "b" * 86, False),
    ("{SHA512-CRYPT}$6$" + "a" * 16 + "$" + "b" * 86, False),
    ("$6$" + "a" * 16 + "$" + "b" * 85, False),
    ("$6$" + "a" * 16 + "$" + "b" * 85 + "'", False),
    ("", False),
])
def test_the_break_glass_hash_is_bare_sha512_crypt_of_106_characters(value, ok):
    assert bool(pg.BREAK_GLASS_HASH.fullmatch(value)) is ok


def test_the_salt_is_read_from_a_stored_hash():
    assert pg.salt_of("$6$" + "Ab./" * 4 + "$" + "b" * 86) == "Ab./" * 4
