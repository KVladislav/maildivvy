#!/usr/bin/python
"""Install step 3: what ufw must be told so that its rules are exactly the install's.

Changes nothing. It reads ufw's own rule files (`/etc/ufw/user.rules`,
`user6.rules`, each rule's `### tuple ###` line), `/etc/ufw/ufw.conf` and
`/etc/default/ufw`, and returns the `ufw` commands that add the missing rules, SSH
first, and delete the ones the settings no longer name. A rule of a
shape the install never writes (an application profile, a route) is refused rather
than guessed at. The role runs the commands under the self-reverting timer.

The mail ports are not this step's: step 19 opens them to anywhere once the
ban is proved. Those rules, exactly as step 19 writes them, are kept - never deleted,
never added here - and the kernel is expected to hold them, so a re-run of step 3 over a
published machine neither closes the ports nor publishes an unproved one.
"""

import ipaddress
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_ufw
short_description: Plan the ufw commands that make its rules exactly the install's
options:
  admin_networks: {type: list, elements: str, required: true}
  ports: {type: list, elements: int, required: true}
  published: {type: list, elements: int, default: []}
"""

RULE_FILES = ("/etc/ufw/user.rules", "/etc/ufw/user6.rules")
TUPLE = "### tuple ### "
ANY = {4: "0.0.0.0/0", 6: "::/0"}


def parse_tuples(text):
    """ufw's rules as tuples (action, proto, dport, dst, sport, src[, apps], direction), comment dropped."""
    rules = []
    for line in text.splitlines():
        if line.startswith(TUPLE):
            fields = [f for f in line[len(TUPLE):].split() if not f.startswith("comment=")]
            rules.append(tuple(fields))
    return rules


def desired(admin_networks, ports):
    """Every port allowed from every administrator network only, in port order (22 first)."""
    return [("allow", "tcp", str(port), ANY[ipaddress.ip_network(net).version], "any", net, "in")
            for port in ports for net in admin_networks]


CHAINS = {4: "ufw-user-input", 6: "ufw6-user-input"}


def published_rules(current, ports):
    """The rules step 19 wrote to publish `ports` (tcp from anywhere, per family) that are in
    `current`: kept by this step, in the order ufw lists them."""
    theirs = {("allow", "tcp", str(port), ANY[family], "any", ANY[family], "in")
              for port in ports for family in (4, 6)}
    return [rule for rule in current if rule in theirs]


def kernel_rules(admin_networks, ports, published=()):
    """What ufw's input chains must hold for those rules and the kept publication rules, per
    IP family, as `iptables -S` lines."""
    rules = {4: [], 6: []}
    for port in ports:
        for net in admin_networks:
            family = ipaddress.ip_network(net).version
            rules[family].append(f"-A {CHAINS[family]} -s {net} -p tcp --dport {port} -j ACCEPT")
    for rule in published:
        family = 4 if rule[3] == ANY[4] else 6
        rules[family].append(f"-A {CHAINS[family]} -p tcp --dport {rule[2]} -j ACCEPT")
    return rules


def _argv(rule, delete=False):
    action, proto, dport, dst, _sport, src, _direction = rule
    argv = ["ufw", *(["delete"] if delete else []), action]
    if proto != "any":
        argv += ["proto", proto]
    return argv + ["from", src, "to", "any" if dst in ANY.values() else dst, "port", dport]


def _expressible(rule):
    return len(rule) == 7 and rule[6] == "in" and rule[4] == "any" and rule[2] != "any"


def plan(current, wanted, kept=()):
    """(argv lists to add, argv lists to delete, errors) turning `current` into `wanted`, with
    the `kept` rules left as they are."""
    add = [_argv(rule) for rule in wanted if rule not in current]
    delete, errors = [], []
    for rule in current:
        if rule in wanted or rule in kept:
            continue
        if _expressible(rule):
            delete.append(_argv(rule, delete=True))
        else:
            errors.append(f"ufw has a rule this install does not write and will not guess how to remove: "
                          f"{' '.join(rule)}; remove it by hand")
    return add, delete, errors


def enabled(ufw_conf):
    return re.search(r"^ENABLED=yes\s*$", ufw_conf, re.MULTILINE) is not None


def input_policy(default_ufw):
    found = re.search(r'^DEFAULT_INPUT_POLICY="?(\w+)"?\s*$', default_ufw, re.MULTILINE)
    return found.group(1) if found else None


def _read(path):
    with open(path) as f:
        return f.read()


def main():
    module = AnsibleModule(
        argument_spec={"admin_networks": {"type": "list", "elements": "str", "required": True},
                       "ports": {"type": "list", "elements": "int", "required": True},
                       "published": {"type": "list", "elements": "int", "default": []}},
        supports_check_mode=True,
    )
    current = [rule for path in RULE_FILES for rule in parse_tuples(_read(path))]
    kept = published_rules(current, module.params["published"])
    add, delete, errors = plan(current, desired(module.params["admin_networks"], module.params["ports"]), kept)
    if errors:
        module.fail_json(msg="\n".join(errors), errors=errors)
    is_enabled = enabled(_read("/etc/ufw/ufw.conf"))
    policy = input_policy(_read("/etc/default/ufw"))
    kernel = kernel_rules(module.params["admin_networks"], module.params["ports"], kept)
    module.exit_json(changed=False, add=add, delete=delete, enabled=is_enabled, input_policy=policy,
                     kernel4=kernel[4], kernel6=kernel[6], published=[list(r) for r in kept],
                     in_place=not add and not delete and is_enabled and policy == "DROP")


if __name__ == "__main__":
    main()
