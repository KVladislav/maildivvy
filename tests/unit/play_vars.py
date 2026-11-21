"""Values a role reads from another role of the play.

`import_role` exposes every role's defaults and vars to the whole play, earlier roles
included, so a value is named once, in the role whose step makes it, and the others read
it from there. A test rendering one role's files takes those values from the same place.
"""

from pathlib import Path

import yaml

ROLES = Path(__file__).resolve().parents[2] / "ansible" / "roles"


def play_vars(*names):
    """{name: value} for each name, from the one role's defaults or vars that defines it."""
    found = {}
    for path in sorted(ROLES.glob("*/*/main.yml")):
        if path.parent.name in ("defaults", "vars"):
            values = yaml.safe_load(path.read_text()) or {}
            found.update({name: values[name] for name in names if name in values})
    assert set(found) == set(names), f"defined by no role: {set(names) - set(found)}"
    return found
