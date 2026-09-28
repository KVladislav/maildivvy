"""What the installer checks about the machine before anything changes."""

import re
import shlex

from maildivvy.installer import shown

OS_RELEASE = "/etc/os-release"
SYSTEM = ("ubuntu", "26.04")
# the ansible-core Ubuntu 26.04 ships (2.20.1, read on the test machine), which the roles
# are tested with; another version is run, and said to be untested
TESTED_ANSIBLE = (2, 20)
ANSIBLE_PACKAGE = "ansible-core"
ANSIBLE_PLAYBOOK = "/usr/bin/ansible-playbook"


def os_release(text):
    """/etc/os-release as {KEY: value}, quotes removed."""
    values = {}
    for line in text.splitlines():
        key, eq, value = line.partition("=")
        if eq and key.strip():
            try:
                values[key.strip()] = " ".join(shlex.split(value))
            except ValueError:
                values[key.strip()] = value.strip()
    return values


def machine_problems(os_release_text, euid):
    """[] on Ubuntu 26.04 as root, else one line per problem."""
    problems = []
    found = os_release(os_release_text)
    system = (found.get("ID", ""), found.get("VERSION_ID", ""))
    if system != SYSTEM:
        what = " ".join(p for p in system if p) or "unknown"
        problems.append(f"not Ubuntu 26.04: this machine runs {what}; Maildivvy installs on Ubuntu 26.04 only")
    if euid != 0:
        problems.append("not root: run it as root, with sudo ./maildivvy-install")
    return problems


def ansible_version(text):
    """(major, minor, patch) from `ansible-playbook --version`'s first line, or None."""
    match = re.search(r"\[core (\d+)\.(\d+)\.(\d+)", text.splitlines()[0] if text else "")
    return tuple(int(n) for n in match.groups()) if match else None


def ansible_note(version):
    """None for the ansible-core the roles are tested with, else the line saying it is not."""
    if version is not None and version[:2] == TESTED_ANSIBLE:
        return None
    running = shown(version) if version else "an unknown version"
    return (f"ansible-core is {running}, and the roles are tested with {shown(TESTED_ANSIBLE)}, "
            "Ubuntu 26.04's own: this run is untested")
