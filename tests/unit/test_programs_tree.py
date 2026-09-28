"""The programs role's code tree: what is deployed to /opt/maildivvy, and how.

The module compares the deployed tree with the archive the install packs, and replaces
it by removing the destination first when they differ. Owners are the
test's own ids here; the role passes root's.
"""

import io
import os
import stat
import tarfile
from pathlib import Path

import pytest
import yaml

from maildivvy.lib import config
from maildivvy_tree import TreeError, actual_tree, differences, expected_tree, replace

OWNER = (os.getuid(), os.getgid())
ROLE_VARS = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "programs" / "vars" / "main.yml"


def pack(path, members):
    """A tar at `path` from {name: bytes | None (a directory) | ("symlink", target)}."""
    with tarfile.open(path, "w") as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            if content is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o700
                tar.addfile(info)
            elif isinstance(content, tuple):
                info.type, info.linkname = tarfile.SYMTYPE, content[1]
                tar.addfile(info)
            else:
                info.size, info.mode = len(content), 0o600  # the tree's modes come from the rule, not the archive
                tar.addfile(info, io.BytesIO(content))
    return path


SOURCE = {
    "lib/maildivvy/__init__.py": b"",
    "lib/maildivvy/lib/store.py": b"ROOT = '/srv/maildivvy/store'\n",
    "lib/maildivvy/lib/__pycache__/store.cpython-314.pyc": b"cache",
    "lib/maildivvy/stray.pyc": b"cache",
    "bin/maildivvy-fetch": b"#!/usr/bin/python3\n",
}


@pytest.fixture
def archive(tmp_path):
    return pack(tmp_path / "code.tar", SOURCE)


def mode(path):
    return stat.S_IMODE(path.lstat().st_mode)


def test_a_fresh_tree_has_code_0644_programs_0755_and_no_caches(tmp_path, archive):
    dest = tmp_path / "opt"
    replace(archive, dest, owner=OWNER)
    assert (dest / "lib/maildivvy/lib/store.py").read_bytes() == SOURCE["lib/maildivvy/lib/store.py"]
    assert mode(dest / "lib/maildivvy/lib/store.py") == 0o644
    assert mode(dest / "bin/maildivvy-fetch") == 0o755
    assert {mode(p) for p in dest.rglob("*") if p.is_dir()} | {mode(dest)} == {0o755}
    names = {str(p.relative_to(dest)) for p in dest.rglob("*")}
    assert "lib/maildivvy/__init__.py" in names  # the control: the tree was written
    assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc")], names
    assert differences(expected_tree(archive, owner=OWNER), actual_tree(dest)) == []


def test_every_program_in_the_archive_is_installed_and_bin_exists_without_one(tmp_path):
    with_program = pack(tmp_path / "a.tar", {"bin/one": b"1", "bin/two": b"2", "lib/x.py": b""})
    replace(with_program, tmp_path / "a", owner=OWNER)
    assert sorted(p.name for p in (tmp_path / "a/bin").iterdir()) == ["one", "two"]
    without = pack(tmp_path / "b.tar", {"lib/x.py": b""})
    replace(without, tmp_path / "b", owner=OWNER)
    assert (tmp_path / "b/bin").is_dir() and mode(tmp_path / "b/bin") == 0o755


def test_stale_files_and_a_nested_copy_are_differences_and_the_replacement_removes_them(tmp_path, archive):
    dest = tmp_path / "opt"
    replace(archive, dest, owner=OWNER)
    (dest / "lib/maildivvy/old.py").write_text("stale")
    (dest / "lib/lib").mkdir()
    (dest / "lib/lib/store.py").write_text("stale")
    found = differences(expected_tree(archive, owner=OWNER), actual_tree(dest))
    assert "unexpected lib/maildivvy/old.py" in found and "unexpected lib/lib" in found, found
    replace(archive, dest, owner=OWNER)
    assert not (dest / "lib/lib").exists() and not (dest / "lib/maildivvy/old.py").exists()
    assert (dest / "lib/maildivvy/lib/store.py").is_file()  # the control: the tree is back


def test_changed_content_a_missing_file_and_a_wrong_mode_are_differences(tmp_path, archive):
    dest = tmp_path / "opt"
    replace(archive, dest, owner=OWNER)
    expected = expected_tree(archive, owner=OWNER)
    assert differences(expected, actual_tree(dest)) == []  # the control
    (dest / "lib/maildivvy/lib/store.py").write_text("changed")
    (dest / "lib/maildivvy/__init__.py").unlink()
    (dest / "bin/maildivvy-fetch").chmod(0o644)
    assert differences(expected, actual_tree(dest)) == [
        "bin/maildivvy-fetch differs",
        "missing lib/maildivvy/__init__.py",
        "lib/maildivvy/lib/store.py differs",
    ]


def test_caches_written_at_run_time_are_not_differences(tmp_path, archive):
    dest = tmp_path / "opt"
    replace(archive, dest, owner=OWNER)
    (dest / "lib/maildivvy/__pycache__").mkdir()
    (dest / "lib/maildivvy/__pycache__/__init__.cpython-314.pyc").write_bytes(b"cache")
    assert differences(expected_tree(archive, owner=OWNER), actual_tree(dest)) == []
    (dest / "lib/maildivvy/new.py").write_text("")  # the control: a source file is one
    assert differences(expected_tree(archive, owner=OWNER), actual_tree(dest)) == ["unexpected lib/maildivvy/new.py"]


def test_another_owner_is_a_difference(tmp_path, archive):
    dest = tmp_path / "opt"
    replace(archive, dest, owner=OWNER)
    root_owned = expected_tree(archive, owner=(OWNER[0] + 1, OWNER[1]))
    assert "lib/maildivvy/__init__.py differs" in differences(root_owned, actual_tree(dest))


@pytest.mark.parametrize("member", [
    {"/etc/passwd": b"x"},
    {"lib/../../escape": b"x"},
    {"lib/link": ("symlink", "/etc")},
])
def test_an_unsafe_member_is_refused_and_nothing_is_written(tmp_path, member):
    bad = pack(tmp_path / "bad.tar", {"lib/x.py": b"", **member})
    with pytest.raises(TreeError, match=next(iter(member)).lstrip("/").split("/")[-1]):
        replace(bad, tmp_path / "opt", owner=OWNER)
    assert not (tmp_path / "opt").exists()


def test_the_role_makes_one_directory_per_consumer_the_library_knows():
    consumers = yaml.safe_load(ROLE_VARS.read_text())["maildivvy_consumers"]
    assert tuple(c["name"] for c in consumers) == config.CONSUMERS
