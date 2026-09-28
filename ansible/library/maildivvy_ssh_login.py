#!/usr/bin/python
"""Install steps 3 and 4, on a local run: wait for a new SSH login from the administrator.

A run over a local connection opens no session through the firewall, so its own
connection proves nothing about the rules it just wrote. This waits instead for sshd to
accept a login from the address the administrator stated, after the wait began, while
the step's revert timer is still armed. With no such login it waits for the timer to put
the rules back, and fails. It never cancels the timer itself: the role does, and only
once this has seen the login (docs/architecture.md § Installation, steps 3 and 4).

A login is read from the journal, from records journald itself attributes to sshd run
as root (`_UID`, `_EXE`), never from the message text alone, which any local user can
log under sshd's name.
"""

# The local run's proof, amending.

import ipaddress
import json
import os
import re
import time

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_ssh_login
short_description: Wait for a new SSH login from one address while a revert timer is armed
options:
  source: {type: str, required: true}
  unit: {type: str, required: true}
  seconds: {type: int, required: true}
"""

POLL = 2
# sshd itself, as OpenSSH 9.8 and later split it (the per-session process) and before
SSHD = ("sshd", "sshd-session")
ACCEPTED = re.compile(r"^Accepted \S+ for .+ from (\S+) port \d+")
# past the timer, how long the wait allows the revert to finish before it gives up anyway
GRACE = 120


def _address(text):
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped or address)


def accepted_logins(entries, since_usec):
    """The source addresses of the logins sshd accepted after `since_usec`, in order."""
    found = []
    for e in entries:
        if (e.get("_UID") != "0" or os.path.basename(e.get("_EXE", "")) not in SSHD
                or int(e.get("__REALTIME_TIMESTAMP", 0)) <= since_usec):
            continue
        match = ACCEPTED.match(e.get("MESSAGE") or "")
        address = match and _address(match.group(1))
        if address:
            found.append(address)
    return found


def wait_for_login(source, since_usec, entries, armed, reverting, clock, sleep, deadline):
    """("seen", source) once a login from `source` is read while the timer is armed;
    ("reverted", None) once the timer has fired and its revert finished with none;
    ("timeout", None) at `deadline` whatever else happened."""
    source = _address(source)
    while True:
        was_armed = armed()
        if was_armed and source in accepted_logins(entries(), since_usec):
            return "seen", source
        if not was_armed and not reverting():
            return "reverted", None
        if clock() >= deadline:
            return "timeout", None
        sleep(POLL)


def main():
    module = AnsibleModule(
        argument_spec={"source": {"type": "str", "required": True},
                       "unit": {"type": "str", "required": True},
                       "seconds": {"type": "int", "required": True}},
        supports_check_mode=False,
    )
    source, unit = module.params["source"], module.params["unit"]
    if _address(source) is None:
        module.fail_json(msg=f"not an address: {source}")
    started = time.time()
    since_usec = int(started * 1_000_000)

    def entries():
        rc, out, err = module.run_command(
            ["journalctl", "-o", "json", "--no-pager", f"--since=@{int(started)}",
             *(f"_COMM={name}" for name in SSHD)])
        if rc != 0:
            module.fail_json(msg=f"journalctl failed: {err.strip()}")
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def active(suffix):
        _, out, _ = module.run_command(["systemctl", "is-active", f"{unit}.{suffix}"])
        return out.strip() in ("active", "activating", "reloading")

    outcome, _ = wait_for_login(source, since_usec, entries, lambda: active("timer"),
                                lambda: active("service"), time.monotonic, time.sleep,
                                time.monotonic() + module.params["seconds"] + GRACE)
    waited = round(time.time() - started)
    if outcome == "seen":
        module.exit_json(changed=False, source=source, waited=waited,
                         msg=f"a new SSH login from {source} came through the new rules")
    if outcome == "reverted":
        module.fail_json(msg=f"no SSH login from {source} was seen before {unit}.timer ran out: it put "
                             "back the rules in force before this run. Log in from that address while "
                             "the step waits, then run again", waited=waited)
    module.fail_json(msg=f"no SSH login from {source} was seen, and {unit}.timer never ran out "
                         f"in {waited} s; read `systemctl status {unit}.timer`", waited=waited)


if __name__ == "__main__":
    main()
