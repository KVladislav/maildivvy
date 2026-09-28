#!/usr/bin/python
"""Install step 12: keep a locally built binary's shared libraries, and remove what
only its build needed.

A binary built outside the package manager declares no dependencies, so the
packages holding its libraries can become auto-removable and a later `apt autoremove`
takes them: the binary then dies in the loader. This module reads the
binary's libraries with `ldd`, refuses one the loader cannot find, finds each
library's package with `dpkg -S` and marks it manually installed.

Given `installed_before` (the packages installed before the build), it also removes
what the build brought and nothing now needs: the build packages are marked
automatic, apt's own autoremove is *simulated* with recommendations and suggestions
not counted (an installed perl suggests make, dpkg-dev recommends build-essential),
and of what it would remove only the packages that were not there before the build
are purged, by name. `apt autoremove`
itself never runs, and nothing that was on the machine before is touched.

It ends with the proof: the simulated autoremove names none of the library packages.
"""

import os
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_runtime
short_description: Keep a built binary's libraries installed and remove its build's leftovers
options:
  binary: {type: path, required: true, description: the built binary}
  build_packages: {type: list, elements: str, default: [], description: packages installed only for the build}
  installed_before: {type: list, elements: str, description: packages installed before the build; purge the build's leftovers}
"""

_LDD = re.compile(r"^\s*(?:(\S+) => )?(\S+)(?: \(0x[0-9a-f]+\))?\s*$")
_SIMULATED = re.compile(r"^(?:Remv|Purg) (\S+) ")
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}


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


def leftovers(removable, installed_now, installed_before):
    """What apt would autoremove that was not installed before the build, sorted."""
    if not installed_before:
        raise LibraryError("the package list before the build is empty: refusing to guess what the build brought")
    return sorted((set(removable) & set(installed_now)) - set(installed_before))


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

    def owner(self, path):
        for name in candidates(path):
            rc, out = self.run(["dpkg", "-S", name], check=False)
            found = owners(out) if rc == 0 else set()
            if found:
                return found
        raise LibraryError(f"no package owns {path}")


def main():
    module = AnsibleModule(
        argument_spec={"binary": {"type": "path", "required": True},
                       "build_packages": {"type": "list", "elements": "str", "default": []},
                       "installed_before": {"type": "list", "elements": "str"}},
        supports_check_mode=True,
    )
    p = module.params
    apt = Apt(module)
    changed, purged, marked = False, [], []
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

        if p["installed_before"] is not None:
            before = set(p["installed_before"])
            installed = apt.installed()
            build = sorted((set(p["build_packages"]) & installed) - before)
            if build and not module.check_mode:
                apt.run(["apt-mark", "auto", *build])
            purged = leftovers(apt.removable(strict=True), installed, before)
            if purged:
                changed = True
                if not module.check_mode:
                    apt.run(["apt-get", "purge", "-y", *purged])

        kept = sorted(set(libraries) & apt.removable()) if not module.check_mode else []
        if kept:
            raise LibraryError(f"apt autoremove would remove {', '.join(kept)}, which {p['binary']} needs")
    except LibraryError as e:
        module.fail_json(msg=str(e))
    module.exit_json(changed=changed, libraries=libraries, marked=marked, purged=purged)


if __name__ == "__main__":
    main()
