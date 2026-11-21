#!/usr/bin/python
"""What of Maildivvy this machine's database holds: the migrations it records, and whether
anyone used it. Changes nothing.

One reading for both ways in: maildivvy-install imports `read`
(installer.upgrade), and step 1 of a run from a control machine calls this module. Each
answer is data, never an error's words, which the server and runuser translate: no psql
or no postgres account is nothing, then the `postgres` database is asked whether ours
exists, and ours which of its tables do. Only a database that does not answer is an
error, and the reader fails closed on it.
"""

import pwd
import subprocess
from pathlib import Path

DOCUMENTATION = r"""
module: maildivvy_installed
short_description: Read the migrations Maildivvy's database records and whether anyone used it
description: Returns versions (a list), used (a bool) and error (null, or why the database did not answer).
options: {}
"""

PSQL = Path("/usr/bin/psql")
DATABASE = "maildivvy"
# The interface alone makes accounts, domains and external mailboxes, and every message is
# a domain's: a row in any of them is a used installation.
USED_TABLES = ("account", "domain", "external_mailbox")

SCRIPT = rf"""
SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = '{DATABASE}') AS ours \gset
\if :ours
\connect {DATABASE}
SELECT to_regclass('public.schema_version') IS NOT NULL AS recorded,
       {" AND ".join(f"to_regclass('public.{t}') IS NOT NULL" for t in USED_TABLES)} AS tables \gset
\if :recorded
SELECT 'version ' || version FROM schema_version ORDER BY version;
\endif
\if :tables
SELECT 'used' WHERE {" OR ".join(f"EXISTS (SELECT 1 FROM {t})" for t in USED_TABLES)};
\endif
\endif
"""


def read(run=subprocess.run, psql=PSQL, account=pwd.getpwnam):
    """{"versions": [...], "used": bool, "error": None, or what psql said when the database did not answer}."""
    nothing = {"versions": [], "used": False, "error": None}
    if not Path(psql).exists():
        return nothing
    try:
        account("postgres")
    except KeyError:
        return nothing
    done = run(["runuser", "-u", "postgres", "--", str(psql), "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
                "-d", "postgres", "-f", "-"], input=SCRIPT, capture_output=True, text=True, cwd="/")
    if done.returncode != 0:
        return {**nothing, "error": " ".join(done.stderr.split()) or f"exit {done.returncode}"}
    lines = done.stdout.splitlines()
    return {"versions": [line.removeprefix("version ") for line in lines if line.startswith("version ")],
            "used": "used" in lines, "error": None}


def main():
    from ansible.module_utils.basic import AnsibleModule   # maildivvy-install imports read before ansible-core is installed

    module = AnsibleModule(argument_spec={}, supports_check_mode=True)
    module.exit_json(changed=False, **read())


if __name__ == "__main__":
    main()
