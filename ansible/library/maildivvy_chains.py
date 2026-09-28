#!/usr/bin/python
"""Read kernel chains back and compare them with what was written, rule by rule.

Changes nothing. The expected rules are either given (`rules`) or read from the
named block of a rules file (`file`, `block`), which is how `DOCKER-USER` is compared
with `/etc/ufw/after.rules`. iptables prints a rule's matches in its
own order and adds implicit ones (`-m tcp`), so each rule is compared in a canonical
form, never as a string. A chain that does not exist, or a block missing from its
file, is a failure: the container block fails open when it is lost.
"""

import ipaddress
import shlex

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_chains
short_description: Compare kernel chains with the rules written for them
options:
  chains: {type: list, elements: str, required: true}
  rules: {type: list, elements: str}
  file: {type: path}
  block: {type: str}
  ordered: {type: bool, default: true}
  family: {type: int, choices: [4, 6], default: 4}
"""

ADDRESS_OPTIONS = {"-s", "-d", "--source", "--destination"}
LIST_OPTIONS = {"--ctstate", "--state"}


def canonical(line):
    """One `-A` rule as (chain, its options and values sorted), matches as iptables normalises them."""
    tokens = shlex.split(line)
    if len(tokens) < 2 or tokens[0] != "-A":
        raise ValueError(f"not an -A rule: {line}")
    chain, pairs, i = tokens[1], [], 2
    while i < len(tokens):
        option, values = tokens[i], []
        i += 1
        while i < len(tokens) and not tokens[i].startswith("-"):
            values.append(tokens[i])
            i += 1
        if option in ADDRESS_OPTIONS:
            values = [str(ipaddress.ip_network(v, strict=False)) for v in values]
        elif option in LIST_OPTIONS:
            values = [",".join(sorted(v.split(","))) for v in values]
        pairs.append((option, tuple(values)))
    protocols = {v for o, vs in pairs if o in ("-p", "--protocol") for v in vs}
    # `-p tcp --dport N` is printed with the implicit `-m tcp` iptables adds
    pairs = [p for p in pairs if not (p[0] in ("-m", "--match") and p[1] and p[1][0] in protocols)]
    return chain, tuple(sorted(pairs))


def block_rules(text, block):
    """The `-A` lines between `# BEGIN <block>` and `# END <block>`; none if the block is absent."""
    rules, inside = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == f"# BEGIN {block}":
            inside = True
        elif stripped == f"# END {block}":
            inside = False
        elif inside and stripped.startswith("-A "):
            rules.append(stripped)
    return rules


def compare(expected, actual, ordered):
    """Every difference between the expected and the printed rules; empty when they are the same."""
    want = [canonical(r) for r in expected]
    have = [canonical(r) for r in actual]
    differences = [f"missing: {r}" for r, c in zip(expected, want) if c not in have]
    differences += [f"unexpected: {r}" for r, c in zip(actual, have) if c not in want]
    if not differences and ordered and want != have:
        differences.append("the rules are in another order than the file's")
    if not differences and sorted(want) != sorted(have):
        differences.append("a rule appears more often than it was written")
    return differences


def main():
    module = AnsibleModule(
        argument_spec={
            "chains": {"type": "list", "elements": "str", "required": True},
            "rules": {"type": "list", "elements": "str"},
            "file": {"type": "path"},
            "block": {"type": "str"},
            "ordered": {"type": "bool", "default": True},
            "family": {"type": "int", "choices": [4, 6], "default": 4},
        },
        mutually_exclusive=[("rules", "file")],
        required_together=[("file", "block")],
        supports_check_mode=True,
    )
    p = module.params
    errors = []
    if p["file"]:
        with open(p["file"]) as f:
            expected = block_rules(f.read(), p["block"])
        if not expected:
            errors.append(f"the block '{p['block']}' is missing from {p['file']}")
    else:
        expected = p["rules"] or []
    tool = "iptables" if p["family"] == 4 else "ip6tables"
    actual = []
    for chain in p["chains"]:
        rc, out, err = module.run_command([tool, "-w", "-S", chain])
        if rc != 0:
            errors.append(f"chain {chain} does not exist in {tool}: {err.strip()}")
            continue
        actual += [line for line in out.splitlines() if line.startswith("-A ")]
    expected = [r for r in expected if shlex.split(r)[1] in p["chains"]]
    errors += compare(expected, actual, p["ordered"])
    if errors:
        module.fail_json(msg=f"{', '.join(p['chains'])} differ from what was written:\n" + "\n".join(errors),
                         differences=errors, expected=expected, actual=actual)
    module.exit_json(changed=False, rules=actual)


if __name__ == "__main__":
    main()
