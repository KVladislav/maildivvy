#!/usr/bin/python
"""Install step 12: keep a locally built binary's shared libraries, and prove on every
run that nothing of its build is left on the machine.

A binary built outside the package manager declares no dependencies, so the
packages holding its libraries can become auto-removable and a later `apt autoremove`
takes them: the binary then dies in the loader. This module reads the
binary's libraries with `ldd`, refuses one the loader cannot find, finds each
library's package with `dpkg -S` and marks it manually installed.

Given `record`, it also removes what a build brought and nothing now needs, and proves
it gone. The record is permanent: the packages installed before the first
build, which are the operator's (or an earlier step's) and never touched. A machine an
earlier version built mpop on kept no such record, and what was there before its build
cannot be told from what the build left, so the record written for it is everything
installed except what the build would bring: there, a build package is taken for an
old build's leftover. What the build would bring is the build packages' dependency
closure as `apt-cache depends` reads it (dependencies only), and the purge never
reaches past it: an unrelated package that became auto-removable since the record was
written (a superseded kernel) is not the build's.

The build packages not in the record are marked automatic, apt's own autoremove is
*simulated* with recommendations and suggestions not counted (an installed perl
suggests make, dpkg-dev recommends build-essential), and of what it would remove only
the closure's packages not in the record are purged, by name. `apt autoremove` itself
never runs. A package of the closure that something still needs, or that is
marked manual and is not a build package, stays: someone else installed it. A build
package that something installed since the first build needs stays too, and fails the
proof: an operator who keeps one on purpose adds its name to the record.

It ends with the proofs: no build package outside the record is installed, nothing of
the closure outside the record is left for an autoremove, and the simulated autoremove
names none of the library packages.
"""

import os
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_runtime
short_description: Keep a built binary's libraries installed and prove its build left nothing
options:
  binary: {type: path, required: true, description: the built binary}
  build_packages: {type: list, elements: str, default: [], description: packages installed only for the build}
  record: {type: path, description: the permanent record of the packages installed before the first build; purge and prove}
"""

_LDD = re.compile(r"^\s*(?:(\S+) => )?(\S+)(?: \(0x[0-9a-f]+\))?\s*$")
_SIMULATED = re.compile(r"^(?:Remv|Purg) (\S+) ")
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}
DEPENDS_ONLY = ["--recurse", "--no-recommends", "--no-suggests", "--no-conflicts", "--no-breaks",
                "--no-replaces", "--no-enhances"]


class LibraryError(Exception):
    pass


def library_paths(ldd_output):
    """([library paths, the loader included], [names the loader cannot find]) from `ldd`'s output."""
    paths, missing = [], []
    for line in ldd_output.splitlines():
        if not line.strip():
            continue
        if line.strip().endswith("=> not found"):
            missing.append(line.split("=>")[0].strip())
            continue
        match = _LDD.match(line)
        if match and match.group(2).startswith("/"):
            paths.append(match.group(2))
    return paths, missing


def owners(dpkg_search_output):
    """The packages `dpkg -S` names, without their architecture; diversion lines skipped."""
    found = set()
    for line in dpkg_search_output.splitlines():
        if line.startswith("diversion by ") or ": " not in line:
            continue
        packages = line.split(": ", 1)[0]
        found.update(p.strip().split(":")[0] for p in packages.split(",") if p.strip())
    return found


def autoremovable(simulation_output):
    """The packages a simulated `apt-get -s autoremove` (or purge) would remove."""
    return {m.group(1).split(":")[0] for m in map(_SIMULATED.match, simulation_output.splitlines()) if m}


def closure(depends_output):
    """Every package a recursive `apt-cache depends` names as a heading: the packages
    asked about and all they depend on, alternatives and virtual names included."""
    return {line.strip().strip("<>").split(":")[0] for line in depends_output.splitlines()
            if line.strip() and not line[0].isspace()}


def built_before(installed_now, brought):
    """The record for a machine whose mpop an earlier version built and kept no record of:
    everything installed but what the build would bring, sorted."""
    return sorted(set(installed_now) - set(brought))


def strays(build_packages, installed_now, kept):
    """The build packages installed and not in the record, sorted."""
    return sorted((set(build_packages) & set(installed_now)) - set(kept))


def leftovers(removable, installed_now, brought, kept):
    """What apt would autoremove that the build would bring and the record does not
    name, sorted: never a package outside the build's closure, whenever it became
    removable."""
    if not kept:
        raise LibraryError("the record of the packages before the first build is empty: "
                           "refusing to guess what the build brought")
    return sorted((set(removable) & set(installed_now) & set(brought)) - set(kept))


def candidates(path):
    """The names dpkg may know a library by on a merged-/usr system."""
    names = [path]
    if not path.startswith("/usr/"):
        names.append("/usr" + path)
    names.append(os.path.realpath(path))
    return list(dict.fromkeys(names))


class Apt:
    def __init__(self, module):
        self.module = module

    def run(self, argv, check=True):
        rc, out, err = self.module.run_command(argv, environ_update=APT_ENV)
        if check and rc != 0:
            raise LibraryError(f"{' '.join(argv)} exited {rc}: {err.strip() or out.strip()}")
        return rc, out

    def installed(self):
        _, out = self.run(["dpkg-query", "-W", "-f", "${db:Status-Status} ${Package}\n"])
        return {line.split()[1] for line in out.splitlines() if line.startswith("installed ")}

    def auto(self):
        return set(self.run(["apt-mark", "showauto"])[1].split())

    def removable(self, strict=False):
        """What `apt-get autoremove` would remove; `strict` also counts what is only
        recommended or suggested as unneeded (an installed perl suggests make, for one)."""
        loose = ["-o", "APT::AutoRemove::RecommendsImportant=false",
                 "-o", "APT::AutoRemove::SuggestsImportant=false"] if strict else []
        return autoremovable(self.run(["apt-get", "-s", *loose, "autoremove"])[1])

    def closure(self, packages):
        return closure(self.run(["apt-cache", "depends", *DEPENDS_ONLY, *packages])[1])

    def owner(self, path):
        for name in candidates(path):
            rc, out = self.run(["dpkg", "-S", name], check=False)
            found = owners(out) if rc == 0 else set()
            if found:
                return found
        raise LibraryError(f"no package owns {path}")


def write_record(path, packages):
    """The record, written whole or not at all, 0600 root:root."""
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=".mpop-record-")
    with os.fdopen(fd, "w") as f:
        f.write("".join(f"{p}\n" for p in packages))
    os.chmod(temporary, 0o600)
    # not module.atomic_move: on a path that does not exist yet it sets the mode from the
    # umask (0644), after the chmod above; the rename in one directory is atomic as it is
    os.replace(temporary, path)


def purge(module, apt, p):
    """Purge what the build left, prove it gone; returns (purged, whether the record was written)."""
    installed = apt.installed()
    brought = apt.closure(p["build_packages"])
    written = not os.path.exists(p["record"])
    if written:
        kept = built_before(installed, brought)
        if not module.check_mode:
            write_record(p["record"], kept)
    else:
        with open(p["record"]) as f:
            kept = f.read().split()

    build = strays(p["build_packages"], installed, kept)
    if build and not module.check_mode:
        apt.run(["apt-mark", "auto", *build])
    # in check mode nothing is marked, so the simulation would not see the build packages go
    purged = leftovers(apt.removable(strict=True), installed, brought, kept) if not module.check_mode else build
    if purged and not module.check_mode:
        apt.run(["apt-get", "purge", "-y", *purged])
    if not module.check_mode:
        now = apt.installed()
        held = strays(p["build_packages"], now, kept)
        if held:  # as it was found: an autoremove must not take it once its holder goes
            apt.run(["apt-mark", "manual", *sorted(set(held) & set(build))])
        left = sorted(set(held) | set(leftovers(apt.removable(strict=True), now, brought, kept)))
        if left:
            raise LibraryError(f"the build's {', '.join(left)} stayed installed: something installed since "
                               f"the first build needs it; a package of yours goes into {p['record']} by name")
    return purged, written


def main():
    module = AnsibleModule(
        argument_spec={"binary": {"type": "path", "required": True},
                       "build_packages": {"type": "list", "elements": "str", "default": []},
                       "record": {"type": "path"}},
        supports_check_mode=True,
    )
    p = module.params
    apt = Apt(module)
    changed, purged, marked, recorded = False, [], [], False
    try:
        rc, out, err = module.run_command(["ldd", p["binary"]])
        if rc != 0:
            raise LibraryError(f"ldd {p['binary']} exited {rc}: {err.strip()}")
        paths, missing = library_paths(out)
        if missing:
            raise LibraryError(f"{p['binary']}: the loader cannot find {', '.join(missing)}")
        libraries = sorted(set().union(*(apt.owner(path) for path in paths)))

        marked = sorted(set(libraries) & apt.auto())
        if marked:
            changed = True
            if not module.check_mode:
                apt.run(["apt-mark", "manual", *marked])

        if p["record"] is not None:
            purged, recorded = purge(module, apt, p)
            changed = changed or bool(purged) or recorded

        kept = sorted(set(libraries) & apt.removable()) if not module.check_mode else []
        if kept:
            raise LibraryError(f"apt autoremove would remove {', '.join(kept)}, which {p['binary']} needs")
    except LibraryError as e:
        module.fail_json(msg=str(e))
    module.exit_json(changed=changed, libraries=libraries, marked=marked, purged=purged, recorded=recorded)


if __name__ == "__main__":
    main()
