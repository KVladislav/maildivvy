"""Store paths and folder names: one derivation from (domain, account), and the
directories made below the store and index roots.

The roots are temporary directories here; the owner is the test's own user, so the
chown is real and its result can be read back.
"""

import os
import stat
from pathlib import Path

import pytest

from maildivvy.lib import store
from maildivvy.lib.store import StoreError

ROOT = Path(__file__).resolve().parents[2]
STORE_MODULE = ROOT / "src" / "maildivvy" / "lib" / "store.py"
ME = (os.getuid(), os.getgid())


def test_paths_derive_from_domain_and_account():
    assert store.home("example", "ivan") == Path("/srv/maildivvy/store/example/ivan")
    assert store.archive_home("example") == Path("/srv/maildivvy/store/example/archive")
    assert store.index_paths("example", "ivan") == (
        Path("/srv/maildivvy/index/idx/example/ivan"),
        Path("/srv/maildivvy/index/ctl/example/ivan"),
    )


def test_the_archive_and_the_index_trees_use_the_same_derivation(tmp_path):
    assert store.archive_home("example", root=tmp_path) == store.home(
        "example", store.ARCHIVE, root=tmp_path)
    idx, ctl = store.index_paths("example", "ivan", root=tmp_path)
    assert idx.relative_to(tmp_path / "idx") == ctl.relative_to(tmp_path / "ctl") \
        == store.home("example", "ivan", root=tmp_path).relative_to(tmp_path)


def test_no_other_module_spells_the_store_or_index_root():
    sources = sorted((ROOT / "src").rglob("*.py"))
    spelled = {
        str(path.relative_to(ROOT))
        for path in sources
        for root in ("/srv/maildivvy/store", "/srv/maildivvy/index")
        if root in path.read_text()
    }
    # Positive control: the one derivation does spell them.
    assert str(STORE_MODULE.relative_to(ROOT)) in spelled
    assert spelled == {str(STORE_MODULE.relative_to(ROOT))}


@pytest.mark.parametrize("domain, account", [
    ("", "ivan"), ("example", ""), (".", "ivan"), ("example", ".."),
    ("ex/ample", "ivan"), ("example", "iv/an"), ("example", "iv\0an"), (None, "ivan"),
])
def test_a_component_that_is_not_one_path_segment_is_refused(domain, account):
    with pytest.raises(StoreError):
        store.home(domain, account)
    with pytest.raises(StoreError):
        store.index_paths(domain, account)


@pytest.mark.parametrize("folder, on_disk", [
    (None, "Maildir"),
    ("INBOX", "Maildir"),
    ("Sent", "Maildir/.Sent"),
    ("Sent/u1", "Maildir/.Sent.u1"),
    ("Archive/2026/q3", "Maildir/.Archive.2026.q3"),
])
def test_a_folder_hierarchy_is_joined_by_dots_on_disk(folder, on_disk):
    home = store.home("example", "archive")
    assert store.maildir(home, folder) == home / on_disk


def test_a_folder_is_never_a_nested_directory():
    home = store.home("example", "archive")
    assert store.maildir(home, "Sent/u1") != home / "Maildir" / ".Sent" / "u1"


@pytest.mark.parametrize("folder", ["", "Sent/", "/Sent", "Sent//u1", "Sent/../x", "Sent/./x"])
def test_a_folder_name_that_does_not_map_to_one_maildir_is_refused(folder):
    with pytest.raises(StoreError):
        store.maildir(store.home("example", "archive"), folder)


def test_mailbox_names_are_joined_by_the_imap_separator():
    assert store.SEPARATOR == "/"
    assert store.mailbox_name("Sent", "u1") == "Sent/u1"
    assert store.mailbox_name("Sent") == "Sent"


@pytest.mark.parametrize("parts", [("Sent", "a/b"), ("Sent", ""), ("Sent", ".."), ()])
def test_a_mailbox_name_with_an_empty_or_separator_part_is_refused(parts):
    with pytest.raises(StoreError):
        store.mailbox_name(*parts)


def test_a_mailbox_name_may_hold_a_dot_so_a_dotted_login_has_its_sent_folder():
    assert store.mailbox_name("Sent", "ivan.p") == "Sent/ivan.p"
    assert store.mailbox_name("Project v1.2") == "Project v1.2"


@pytest.mark.parametrize("folder, on_disk", [
    ("Sent/ivan", "Maildir/.Sent.ivan"),         # the control: nothing to escape
    ("Sent/ivan.p", "Maildir/.Sent.ivan^2ep"),
    ("Project v1.2", "Maildir/.Project v1^2e2"),
    ("a^b", "Maildir/.a^5eb"),
    ("x^2e", "Maildir/.x^5e2e"),                 # the escape character itself is escaped first
    ("Sent/a.b^c", "Maildir/.Sent.a^2eb^5ec"),
])
def test_a_folder_on_disk_escapes_the_dot_and_the_escape_character(folder, on_disk):
    home = store.home("example", "archive")
    assert store.maildir(home, folder) == home / on_disk


def test_escaping_keeps_distinct_folders_in_distinct_directories():
    home = store.home("example", "archive")
    names = ["Sent/ivan.p", "Sent/ivan/p", "Sent/ivan^2ep", "Sent.ivan/p", "Sent/ivan"]
    assert len({store.maildir(home, name) for name in names}) == len(names)


def test_the_escape_character_is_dovecots_setting():
    assert store.ESCAPE == "^"


def modes(path, below):
    """(mode, uid, gid) of every directory from `below` (exclusive) down to `path`."""
    out = []
    while path != below:
        st = path.stat()
        out.append((stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid))
        path = path.parent
    return out


def test_every_missing_ancestor_is_made_0700_by_the_mail_owner(tmp_path):
    leaf = tmp_path / "example" / "ivan" / "Maildir" / "new"
    made = store.make_dir(leaf, root=tmp_path, uid=ME[0], gid=ME[1])
    assert made == [tmp_path / "example", tmp_path / "example" / "ivan",
                    tmp_path / "example" / "ivan" / "Maildir", leaf]
    assert modes(leaf, tmp_path) == [(0o700, *ME)] * 4


def test_the_mode_is_chmoded_after_mkdir_whatever_the_umask(tmp_path):
    old = os.umask(0o777)
    try:
        store.make_dir(tmp_path / "example" / "ivan", root=tmp_path, uid=ME[0], gid=ME[1])
    finally:
        os.umask(old)
    assert modes(tmp_path / "example" / "ivan", tmp_path) == [(0o700, *ME)] * 2


def test_an_existing_directory_is_left_as_it_is(tmp_path):
    existing = tmp_path / "example"
    existing.mkdir(mode=0o755)
    os.chmod(existing, 0o755)
    made = store.make_dir(existing / "ivan", root=tmp_path, uid=ME[0], gid=ME[1])
    assert made == [existing / "ivan"]
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755
    assert store.make_dir(existing / "ivan", root=tmp_path, uid=ME[0], gid=ME[1]) == []


@pytest.mark.parametrize("target", ["../elsewhere", "/etc/maildivvy-x"])
def test_a_directory_outside_the_root_is_refused(tmp_path, target):
    root = tmp_path / "store"
    root.mkdir()
    with pytest.raises(StoreError, match="outside"):
        store.make_dir(root / target, root=root, uid=ME[0], gid=ME[1])
    assert not (tmp_path / "elsewhere").exists()


def test_a_missing_root_is_refused_not_created(tmp_path):
    with pytest.raises(StoreError, match="root"):
        store.make_dir(tmp_path / "store" / "example", root=tmp_path / "store",
                       uid=ME[0], gid=ME[1])
    assert not (tmp_path / "store").exists()


def test_the_mail_owner_is_read_from_the_vmail_user(monkeypatch):
    import pwd
    entry = pwd.struct_passwd(("vmail", "x", 901, 902, "", "/nonexistent", "/usr/sbin/nologin"))
    monkeypatch.setattr(pwd, "getpwnam", lambda name: entry if name == "vmail" else None)
    assert store.mail_owner() == (901, 902)


# --- a message's file from its storage id ----------------------------------------------

BASE = "1789853107.M293776P70974.maildivvy-test,S=109,W=115"


@pytest.mark.parametrize("name", [f"new/{BASE}", f"cur/{BASE}:2,", f"cur/{BASE}:2,S",
                                  # doveadm's `flags` renames in place, in new/ (measured on 2.4.2)
                                  f"new/{BASE}:2,", f"new/{BASE}:2,S", f"cur/{BASE}"])
def test_each_name_a_seen_flag_can_give_resolves(tmp_path, name):
    for sub in ("new", "cur"):
        (tmp_path / sub).mkdir()
    (tmp_path / name).write_text("m")
    assert store.resolve(tmp_path, BASE) == tmp_path / name


@pytest.mark.parametrize("name", [f"cur/{BASE}:2,RS", f"cur/{BASE}:2,T", f"tmp/{BASE}", f"cur/{BASE}.copy"])
def test_any_other_name_is_not_found_since_the_directory_is_never_scanned(tmp_path, name):
    for sub in ("new", "cur", "tmp"):
        (tmp_path / sub).mkdir()
    (tmp_path / name).write_text("m")
    assert store.resolve(tmp_path, BASE) is None
    (tmp_path / "new" / BASE).write_text("m")  # the control: the same directory, a name it tries
    assert store.resolve(tmp_path, BASE) == tmp_path / "new" / BASE


@pytest.mark.parametrize("base", ["", ".", "..", "../x", "a/b", "a\0b", f"{BASE}:2,S"])
def test_a_storage_id_that_is_not_a_bare_base_name_is_refused(tmp_path, base):
    with pytest.raises(StoreError):
        store.resolve(tmp_path, base)
