"""Install step 12's pure parts: the pinned mpop release and its build
switches, and `maildivvy_runtime`, which keeps a locally built binary's shared
libraries installed and removes what only its build needed.

The build itself, the library marks and the distribution package's removal are proved
on the test VM.
"""

from pathlib import Path

import pytest
import yaml

from maildivvy_runtime import (LibraryError, autoremovable, leftovers, library_paths, owners)

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "mpop"

LDD = """\tlinux-vdso.so.1 (0x000079689f51b000)
\tlibgnutls.so.30 => /usr/lib/x86_64-linux-gnu/libgnutls.so.30 (0x000079689f200000)
\tlibgsasl.so.18 => /usr/lib/x86_64-linux-gnu/libgsasl.so.18 (0x000079689f4c0000)
\tlibc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x000079689ee00000)
\t/lib64/ld-linux-x86-64.so.2 (0x000079689f51d000)
\tlibntlm.so.0 => /usr/lib/x86_64-linux-gnu/libntlm.so.0 (0x000079689f41e000)
"""


def defaults():
    return yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())


def test_the_release_is_pinned_to_1_4_23_by_a_sha256_literal():
    d = defaults()
    assert d["maildivvy_mpop_version"] == "1.4.23"
    assert d["maildivvy_mpop_sha256"] == "02fc2ff44f62b8fbf427ed6d8b16e0d374751198254fb1e6ad36eb6d9a938017"
    assert d["maildivvy_mpop"] == "/usr/local/bin/mpop"


def test_the_build_has_gnutls_sasl_and_idn_and_neither_keyring_nor_the_pop3_server():
    assert defaults()["maildivvy_mpop_configure"] == [
        "--with-tls=gnutls", "--with-libgsasl", "--with-libidn", "--without-libsecret", "--without-mpopd"]


def test_the_download_is_checked_against_the_pin_before_it_is_unpacked():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    build = next(t for t in tasks if "block" in t and t["name"].startswith("Build"))["block"]
    names = [t["name"] for t in build]
    download = next(t for t in build if "ansible.builtin.get_url" in t)
    assert download["ansible.builtin.get_url"]["checksum"] == "sha256:{{ maildivvy_mpop_sha256 }}"
    unpack = next(i for i, t in enumerate(build) if "ansible.builtin.unarchive" in t)
    assert names.index(download["name"]) < unpack  # get_url removes a mismatch, never leaves it to unpack


def test_ldd_gives_every_resolved_library_and_the_loader_but_not_the_vdso():
    paths, missing = library_paths(LDD)
    assert paths == ["/usr/lib/x86_64-linux-gnu/libgnutls.so.30", "/usr/lib/x86_64-linux-gnu/libgsasl.so.18",
                     "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2",
                     "/usr/lib/x86_64-linux-gnu/libntlm.so.0"]
    assert missing == []


def test_a_library_the_loader_cannot_find_is_named():
    paths, missing = library_paths(LDD + "\tlibidn.so.12 => not found\n")
    assert missing == ["libidn.so.12"]
    assert len(paths) == 5  # the control: the found ones are still read


def test_dpkg_search_owners_skip_diversions_and_strip_the_architecture():
    text = ("diversion by libc6 from: /lib64/ld-linux-x86-64.so.2\n"
            "diversion by libc6 to: /lib64/ld-linux-x86-64.so.2.usr-is-merged\n"
            "libc6:amd64: /usr/lib64/ld-linux-x86-64.so.2\n"
            "libgsasl18:amd64, libgsasl-dev:amd64: /usr/lib/x86_64-linux-gnu/libgsasl.so.18\n")
    assert owners(text) == {"libc6", "libgsasl18", "libgsasl-dev"}


def test_the_autoremove_simulation_is_read_line_by_line():
    text = ("Reading package lists...\nThe following packages will be REMOVED:\n  gcc-15 libntlm0\n"
            "0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n"
            "Remv gcc-15 [15.2.0-4ubuntu4]\nRemv libntlm0:amd64 [1.8-4]\n")
    assert autoremovable(text) == {"gcc-15", "libntlm0"}
    assert autoremovable("0 upgraded, 0 newly installed, 0 to remove and 17 not upgraded.\n") == set()


def test_only_what_the_build_brought_is_removed_never_what_was_there_before():
    before = {"libc6", "libgnutls30t64", "old-auto-package"}
    now = before | {"gcc-15", "make", "libgsasl18", "libgsasl-dev"}
    removable = {"gcc-15", "make", "libgsasl-dev", "old-auto-package"}
    assert leftovers(removable, now, before) == ["gcc-15", "libgsasl-dev", "make"]


def test_an_empty_package_list_before_the_build_is_refused():
    # an unread list would make every installed package look new
    with pytest.raises(LibraryError):
        leftovers({"gcc-15"}, {"gcc-15", "libc6"}, set())


def test_mpop_is_installed_before_the_step_that_renders_its_configuration():
    steps = yaml.safe_load((ROOT / "ansible" / "site.yml").read_text())[0]["tasks"]
    roles = [(s["ansible.builtin.import_role"]["name"], s["ansible.builtin.import_role"].get("tasks_from"))
             for s in steps]
    assert roles.index(("mpop", None)) < roles.index(("programs", "units"))
