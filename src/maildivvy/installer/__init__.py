"""`maildivvy-install`: the installation run on the machine itself.

    checks     Ubuntu 26.04, root, the release's MANIFEST; ansible-core's version
    manifest   the release tree's SHA-256 sums, written by the release build and checked here
    settings   /etc/maildivvy/install.yml (non-secret settings) and the secrets on stdin
    prompts    the questions asked when there is no settings file, and the secrets
    run        the local ansible-playbook run, its screen lines, its log, what is left to do
    cli        the command itself, in that order
"""
# The record.

# the installer's exit codes: a refusal changes nothing; a failure stops a run that began
FAILED = 1
REFUSED = 2


class Refusal(Exception):
    """Why the installer will not go on, before it changes anything."""


def shown(version):
    """A version tuple as it is written: (0, 1, 0) is 0.1.0."""
    return ".".join(map(str, version))
