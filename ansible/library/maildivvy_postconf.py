#!/usr/bin/python
"""Set the main.cf parameters and master.cf services the product owns, with `postconf`.

⛔ Postfix has no include mechanism, and `main.cf.d` / `master.cf.d` are not directories
it reads. The old deployment appended fragments to both files: that cannot be undone by
deleting a file, and it makes every `postfix`, `postconf` and `postsuper` call print
`overriding earlier entry` for ever, which trains readers to ignore warnings.
This module states what the product owns and lets `postconf` edit
exactly those settings, leaving the rest of the distribution's files as they are.

⚠️ Measured on Postfix 3.10.6: `postconf -M '<service>=<definition>'` DROPS that
service's own `-o` lines. A definition that has to be rewritten therefore takes every
override with it, so this module writes the definition first and then writes every
override of that service again.

⚠️ `postconf -P` naming a service that has no overrides prints `warning: unmatched
request` on stderr and exits 0 - the same as a correctly absent override - so what the
machine holds is read from `postconf -M` and `postconf -P` without arguments, never by
asking after one name.

Nothing here carries a secret: the lookup maps name a passfile and hold no password,
so the actions are reported as they are run.
"""

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_postconf
short_description: Set main.cf parameters and master.cf services with postconf
options:
  main: {type: dict, default: {}}
  # {"<service>/<type>": {definition: str, overrides: dict, keep: [parameter, ...]}}
  # `keep` names overrides ANOTHER step owns: they are neither written nor removed here,
  # and a definition this module has to rewrite is followed by putting them back.
  services: {type: dict, default: {}}
  absent: {type: list, elements: str, default: []}
  postconf: {type: path, default: /usr/sbin/postconf}
"""

FIELDS = 8  # name type private unpriv chroot wakeup maxproc command


def value_of(value):
    """A setting as postconf is given it; YAML's booleans read as Postfix's words."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return "" if value is None else str(value)


def normalise(definition):
    """A master.cf service line compared by its fields, never by its spacing."""
    return " ".join(str(definition).split())


def parse_main(text):
    """`postconf -n` back as {parameter: value}; a continued value is one value."""
    values, name = {}, None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace():
            if name is not None:
                values[name] = f"{values[name]} {line.strip()}".strip()
            continue
        name, separator, value = line.partition("=")
        if not separator:
            continue
        name = name.strip()
        values[name] = value.strip()
    return values


def parse_master(text):
    """`postconf -M` back as {service key: definition}, without the `-o` overrides.

    postconf prints a service's overrides after its command on the same line; they are
    read from `postconf -P`, so what is compared here is the definition alone.
    """
    services = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if len(fields) < FIELDS:
            continue
        definition = list(fields[:FIELDS - 1])
        for token in fields[FIELDS - 1:]:
            if token == "-o":
                break
            definition.append(token)
        services[f"{fields[0]}/{fields[1]}"] = " ".join(definition)
    return services


def parse_overrides(text):
    """`postconf -P` back as {service key: {parameter: value}}."""
    overrides = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        parts = name.strip().split("/")
        if not separator or len(parts) != 3:
            continue
        overrides.setdefault(f"{parts[0]}/{parts[1]}", {})[parts[2]] = value.strip()
    return overrides


def actions(main, services, absent, have_main, have_services, have_overrides):
    """Every postconf edit the machine needs, in the order it has to be made."""
    todo = []
    for name in sorted(main or {}):
        wanted = value_of(main[name])
        if have_main.get(name) != wanted:
            todo.append(("main", f"{name}={wanted}"))
    for key in absent or []:
        if key in have_services:
            todo.append(("remove-service", key))
    for key in sorted(services or {}):
        entry = services[key] or {}
        definition = normalise(entry.get("definition", ""))
        rewritten = normalise(have_services.get(key, "")) != definition
        if rewritten:
            todo.append(("service", f"{key}={definition}"))
        # a rewritten definition took the service's own -o lines with it
        had = have_overrides.get(key, {})
        have = {} if rewritten else had
        overrides = {name: value_of(value) for name, value in (entry.get("overrides") or {}).items()}
        # ⚠️ overrides ANOTHER STEP owns, left exactly as they are: the milter binding is
        # written at install step 14, after the daemon is proved running, and a re-run of
        # this step must neither remove it nor claim its value.
        kept = [name for name in (entry.get("keep") or []) if name not in overrides]
        for name in sorted(overrides):
            if have.get(name) != overrides[name]:
                todo.append(("override", f"{key}/{name}={overrides[name]}"))
        for name in sorted(kept):
            if rewritten and name in had:
                todo.append(("override", f"{key}/{name}={had[name]}"))
        for name in sorted(have):
            if name not in overrides and name not in kept:
                todo.append(("remove-override", f"{key}/{name}"))
    return todo


ARGUMENTS = {"main": ["-e"], "service": ["-M"], "override": ["-P"],
             "remove-service": ["-M", "-X"], "remove-override": ["-P", "-X"]}


def main():
    module = AnsibleModule(
        argument_spec={
            "main": {"type": "dict", "default": {}},
            "services": {"type": "dict", "default": {}},
            "absent": {"type": "list", "elements": "str", "default": []},
            "postconf": {"type": "path", "default": "/usr/sbin/postconf"},
        },
        supports_check_mode=True,
    )
    p = module.params
    postconf = p["postconf"]

    def read(*arguments):
        rc, out, err = module.run_command([postconf, *arguments])
        if rc != 0:
            module.fail_json(msg=f"postconf {' '.join(arguments)} failed: {err.strip()}")
        return out

    todo = actions(p["main"], p["services"], p["absent"],
                   parse_main(read("-n")), parse_master(read("-M")), parse_overrides(read("-P")))
    if todo and not module.check_mode:
        for kind, argument in todo:
            rc, out, err = module.run_command([postconf, *ARGUMENTS[kind], argument])
            if rc != 0:
                module.fail_json(msg=f"postconf {kind} {argument} failed: {err.strip()}",
                                 actions=[f"{k}: {a}" for k, a in todo])
    module.exit_json(changed=bool(todo), actions=[f"{kind}: {argument}" for kind, argument in todo])


if __name__ == "__main__":
    main()
