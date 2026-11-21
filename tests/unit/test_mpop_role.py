"""Install step 12's pure parts: the pinned mpop release and its build
switches, and `maildivvy_runtime`, which keeps a locally built binary's shared
libraries installed, removes what only its build needed and proves on every run that
nothing of the build is left.

The build itself, the library marks and the distribution package's removal are proved
on the test VM.
"""

from pathlib import Path

import pytest
import yaml

import maildivvy_runtime
from maildivvy_runtime import (LibraryError, autoremovable, built_before, closure, leftovers, library_paths,
                              owners, strays)

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


DEPENDS = """build-essential
 |Depends: libc6-dev
  Depends: <libc-dev>
    libc6-dev
  Depends: gcc
  Depends: make
    make-guile
pkg-config
  Depends: pkgconf
libc6-dev
  Depends: libc6
gcc
  Depends: gcc-15
dpkg-dev
  Depends: <perl:any>
    perl
<libc-dev>
<perl:any>
make-guile
  Depends: libc6
"""
BUILD = ["build-essential", "pkg-config"]
BROUGHT = closure(DEPENDS)


def test_what_the_build_would_bring_is_every_heading_of_the_recursive_depends():
    assert BROUGHT == {"build-essential", "pkg-config", "libc6-dev", "gcc", "dpkg-dev", "libc-dev", "perl",
                       "make-guile"}
    assert closure("") == set()


def test_only_what_the_build_brought_is_removed_never_what_was_there_before():
    before = {"libc6", "libgnutls30t64", "perl", "old-auto-package"}
    now = before | {"build-essential", "gcc", "make", "libc6-dev"}
    brought = BROUGHT | {"make"}
    removable = {"build-essential", "gcc", "make", "libc6-dev", "perl", "old-auto-package"}
    assert leftovers(removable, now, brought, before) == ["build-essential", "gcc", "libc6-dev", "make"]


def test_a_stale_record_never_purges_what_became_removable_outside_the_build():
    # a record a failed rebuild left months ago: a superseded kernel came and went auto since
    before = {"libc6", "linux-image-7.0.0-40-generic"}
    now = before | {"gcc", "linux-image-7.0.0-41-generic"}
    removable = {"gcc", "linux-image-7.0.0-41-generic"}
    assert leftovers(removable, now, BROUGHT, before) == ["gcc"]  # the control: the build's own goes


def test_a_machine_built_with_no_record_takes_the_build_packages_for_leftovers_and_nothing_else():
    installed = {"libc6", "postfix", "build-essential", "gcc", "pkg-config", "linux-image-generic"}
    record = built_before(installed, BROUGHT)
    assert record == ["libc6", "linux-image-generic", "postfix"]
    assert strays(BUILD, installed, record) == ["build-essential", "pkg-config"]


def test_a_build_package_the_operator_had_before_the_first_build_is_kept():
    record = {"libc6", "pkg-config"}
    installed = record | {"build-essential", "gcc"}
    assert strays(BUILD, installed, record) == ["build-essential"]
    assert leftovers({"build-essential", "gcc", "pkg-config"}, installed, BROUGHT, record) == ["build-essential", "gcc"]


def test_an_empty_package_list_before_the_build_is_refused():
    # an unread list would make every installed package look new
    with pytest.raises(LibraryError):
        leftovers({"gcc-15"}, {"gcc-15", "libc6"}, {"gcc-15"}, set())


class FakeModule:
    check_mode = False

    def atomic_move(self, src, dest):
        Path(src).replace(dest)


class FakeApt:
    """A machine's packages: what is installed, what is marked automatic, and what an
    installed package depends on; autoremove takes what no manual package needs."""

    def __init__(self, installed, auto, needs):
        self.installed_, self.auto_, self.needs, self.purged = set(installed), set(auto), needs, []

    def installed(self):
        return set(self.installed_)

    def closure(self, packages):
        return BROUGHT

    def removable(self, strict=False):
        kept, todo = set(), list(self.installed_ - self.auto_)
        while todo:  # what a manually installed package needs, all the way down
            package = todo.pop()
            if package not in kept:
                kept.add(package)
                todo += self.needs.get(package, ())
        return self.installed_ - kept

    def run(self, argv, check=True):
        if argv[:2] == ["apt-mark", "auto"]:
            self.auto_ |= set(argv[2:])
        elif argv[:2] == ["apt-mark", "manual"]:
            self.auto_ -= set(argv[2:])
        elif argv[:3] == ["apt-get", "purge", "-y"]:
            self.purged += argv[3:]
            self.installed_ -= set(argv[3:])
        return 0, ""


def run_purge(tmp_path, apt, record=None):
    path = tmp_path / "mpop-build-before"
    if record is not None:
        path.write_text("".join(f"{p}\n" for p in record))
    params = {"build_packages": BUILD, "record": str(path)}
    return maildivvy_runtime.purge(FakeModule(), apt, params), path


def test_with_no_record_an_old_builds_compiler_is_purged_and_the_record_kept_for_good(tmp_path):
    apt = FakeApt({"libc6", "postfix", "build-essential", "gcc", "pkg-config", "hello"},
                  auto={"gcc", "hello"}, needs={"build-essential": {"gcc"}, "postfix": {"libc6"}})
    (purged, written), path = run_purge(tmp_path, apt)
    assert written and path.read_text().split() == ["hello", "libc6", "postfix"]
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert sorted(apt.purged) == ["build-essential", "gcc", "pkg-config"]
    assert "hello" in apt.installed()  # auto-removable, but nothing the build would bring
    (purged, written), _ = run_purge(tmp_path, apt)
    assert (purged, written) == ([], False)  # the every-run proof finds nothing more to do


def test_a_build_package_something_installed_since_needs_fails_the_proof_until_it_is_recorded(tmp_path):
    apt = FakeApt({"libc6", "pkg-config", "operators-tool"}, auto=set(), needs={"operators-tool": {"pkg-config"}})
    with pytest.raises(LibraryError, match="pkg-config stayed installed"):
        run_purge(tmp_path, apt, record=["libc6"])
    assert apt.purged == [] and "pkg-config" not in apt.auto_  # left as it was found
    (purged, _), _ = run_purge(tmp_path, apt, record=["libc6", "pkg-config"])
    assert purged == [] and "pkg-config" in apt.installed()


def test_mpop_is_installed_before_the_step_that_renders_its_configuration():
    steps = yaml.safe_load((ROOT / "ansible" / "site.yml").read_text())[0]["tasks"]
    roles = [(s["ansible.builtin.import_role"]["name"], s["ansible.builtin.import_role"].get("tasks_from"))
             for s in steps]
    assert roles.index(("mpop", None)) < roles.index(("programs", "units"))


def tasks():
    return yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())


def index(block, module):
    return next(i for i, t in enumerate(block) if module in t)


def test_nothing_is_installed_for_the_build_until_the_tarball_is_in_and_matches_the_pin():
    build = next(t for t in tasks() if "block" in t and t["name"].startswith("Build"))["block"]
    # an unreachable download host fails the step before the compiler comes in
    assert index(build, "ansible.builtin.get_url") < index(build, "ansible.builtin.apt")


def test_the_record_is_written_before_the_first_build_only_and_kept_for_good():
    record = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())["maildivvy_mpop_record"]
    assert record.startswith("/var/lib/maildivvy/")
    build = next(t for t in tasks() if "block" in t and t["name"].startswith("Build"))["block"]
    written = build[index(build, "ansible.builtin.copy")]
    assert written["ansible.builtin.copy"]["dest"] == "{{ maildivvy_mpop_record }}"
    assert written["ansible.builtin.copy"]["force"] is False  # a retry keeps the first record, compiler absent
    # a machine an earlier version built on is recorded by the purge, never as it stands now
    assert written["when"] == "not maildivvy_mpop_binary.stat.exists"
    assert index(build, "ansible.builtin.copy") < index(build, "ansible.builtin.apt")
    assert not [t for t in build if "maildivvy_runtime" in t]  # the purge waits on no build of this run
    purge = [t for t in tasks() if "maildivvy_runtime" in t and "record" in t["maildivvy_runtime"]]
    assert len(purge) == 1 and "when" not in purge[0]  # every run proves, whether it built or not
    assert purge[0]["maildivvy_runtime"]["record"] == "{{ maildivvy_mpop_record }}"
    text = (ROLE / "tasks" / "main.yml").read_text()
    assert "state: absent" in text  # the control: the search below can see a removal
    assert not [t for t in tasks() if t.get("ansible.builtin.file", {}).get("path") == "{{ maildivvy_mpop_record }}"]
