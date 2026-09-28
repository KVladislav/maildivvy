"""The local run: ansible-playbook on this machine, its screen lines, its log, what is left.

The whole output goes to the log under /var/log/maildivvy/. The screen gets one line per
step, what a step says to the operator (its messages, the wait for a new SSH login), a
failure's message and the recap.
"""

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from maildivvy.installer import settings
from maildivvy.installer.checks import ANSIBLE_PLAYBOOK

LOG_DIR = Path("/var/log/maildivvy")
RUN_DIR = Path("/run")   # a tmpfs: the secrets file never reaches a disk
# what the run keeps of the installer's environment (kept_environment), with LC_*
KEPT = ("PATH", "HOME", "LANG", "LANGUAGE", "TERM", "TZ")
PROXIES = ("http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")

TASK = re.compile(r"^(?:TASK|RUNNING HANDLER) \[(?:(?P<role>[^\]:]+) : )?(?P<name>.*)\] \**$")
FAILED_LINE = re.compile(r"^(?:fatal|failed): \[[^\]]*\]:?(?: (?P<item>\(item=.*?\)))?"
                         r"(?: FAILED!| UNREACHABLE!)? => (?P<body>.*)$")
SAID = re.compile(r"^ok: \[[^\]]*\](?: => \(item=.*?\)| \(item=.*?\))? => \{$")
ERROR = re.compile(r"^(?:\[ERROR\]|ERROR!)")
RECAP = re.compile(r"^\S+\s+: ok=\d+")
WAIT = re.compile(r"^Waiting for a new SSH login from (?P<source>\S+)")


def site_steps(text):
    """[(role, "N: title")] for each step of site.yml, in its order."""
    import yaml   # python3-yaml comes with ansible-core, installed after the checks

    play = yaml.safe_load(text)[0]
    return [(task["ansible.builtin.import_role"]["name"], task["name"]) for task in play["tasks"]]


def playbook_argv(root, values_path, preflight_only=False):
    """site.yml on this machine with the run's values file; nothing secret in it."""
    root = Path(root)
    return [ANSIBLE_PLAYBOOK, "-i", str(root / "ansible" / "local.yml"), "-e", f"@{values_path}",
            *(["--tags", "preflight"] if preflight_only else []), str(root / "ansible" / "site.yml")]


def kept_environment(base):
    """The locale, path and proxies of `base`, nothing else of it."""
    return {k: v for k, v in base.items() if k in KEPT or k in PROXIES or k.startswith("LC_")}


def environment(root, base):
    """The run's environment: `kept_environment`, and the release's ansible.cfg without colour."""
    return {**kept_environment(base), "ANSIBLE_CONFIG": str(Path(root) / "ansible" / "ansible.cfg"), "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_FORCE_COLOR": "0", "PYTHONUNBUFFERED": "1", "DEBIAN_FRONTEND": "noninteractive"}


def run_values(values, secrets, insecure, *, paused=False, base=None):
    """What the play is given: the settings, the secrets, and the run's own values: that
    maildivvy-install runs it, the test certificate flag and the upgrade's pause when they
    apply, and the proxies of this environment (sudo drops them before a module sees them)."""
    proxies = {k: v for k, v in (base or {}).items() if k in PROXIES and v}
    return {**values, **secrets, settings.INSTALLER_RUN: True,
            **({settings.TEST_CERTIFICATE: True} if insecure else {}),
            **({settings.COLLECTION_PAUSED: True} if paused else {}),
            **({settings.RUN_ENVIRONMENT: proxies} if proxies else {})}


class _Literal(str):
    """A string ansible must take as it is, never as a template."""


def _literal(value):
    if isinstance(value, str):
        return _Literal(value)
    if isinstance(value, dict):
        return {key: _literal(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_literal(item) for item in value]
    return value


def values_yaml(values):
    """The values as YAML with every string tagged `!unsafe`: ansible templates extra vars,
    so a password or a command holding `{{`, `{%` or `{#` would otherwise be changed or
    stop the run."""
    import yaml   # python3-yaml comes with ansible-core, installed after the checks

    class Dumper(yaml.SafeDumper):
        pass
    Dumper.add_representer(_Literal, lambda dumper, text: dumper.represent_scalar("!unsafe", str(text), style='"'))
    return yaml.dump(_literal(values), Dumper=Dumper, default_flow_style=False, sort_keys=False, allow_unicode=True)


@contextlib.contextmanager
def values_file(values, base=RUN_DIR):
    """The run's values as a 0600 file in a 0700 directory of its own, removed when the block ends."""
    directory = Path(tempfile.mkdtemp(prefix="maildivvy-install.", dir=base))
    path = directory / "values.yml"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(values_yaml(values))
        yield path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _message(body):
    try:
        value = json.loads(body)
    except ValueError:
        return body
    if isinstance(value, dict):
        msg = value.get("msg") or value.get("stderr") or value.get("stdout") or body
        return msg if isinstance(msg, str) else json.dumps(msg)
    return body


class Screen:
    """Turns ansible's output, line by line, into the few lines the operator reads."""

    def __init__(self, steps, write):
        self.steps, self.write = list(steps), write
        self.next, self.role, self.block = 0, None, None

    def _step(self, role):
        for i in range(self.next, len(self.steps)):
            if self.steps[i][0] == role:
                self.next = i + 1
                self.write(f"step {self.steps[i][1]}")
                return

    def feed(self, line):
        if self.block is not None:
            self.block.append(line)
            if line == "}":
                self.write("\n".join(self.block))
                self.block = None
            return
        task = TASK.match(line)
        if task:
            role, name = task.group("role"), task.group("name")
            if role and role != self.role:
                self.role = role
                self._step(role)
            wait = WAIT.match(name)
            if wait:
                self.write(f"  {name}:\n  open a NEW SSH session to this machine from {wait.group('source')} now, "
                           "and keep this one open. Without that login the old rules come back when the "
                           "timer runs out, and the run stops.")
            return
        failed = FAILED_LINE.match(line)
        if failed:
            item = f" {failed.group('item')}" if failed.group("item") else ""
            self.write(f"failed{item}: " + _message(failed.group("body")).replace("\n", "\n  "))
        elif SAID.match(line):
            self.block = [line]
        elif RECAP.match(line) or ERROR.match(line):
            self.write(line)

    def close(self):
        """The end of the output: a message it cut short is still shown."""
        if self.block is not None:
            self.write("\n".join(self.block))
            self.block = None


def run_playbook(argv, env, log, screen, started=None):
    """Run the play; every line to `log`, each to `screen`; returns the exit code.

    `started` is called once the play has begun, when ansible has read its extra vars.
    """
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
    for raw in process.stdout:
        log.write(raw)
        log.flush()
        line = raw.rstrip("\n")
        if started and line.startswith("PLAY ["):
            started()
            started = None
        screen.feed(line)
    screen.close()
    return process.wait()


def remaining(values, log_path):
    """What the operator still has to do once the run passed, in order."""
    name = values.get("maildivvy_cert_name", "<mail hostname>")
    mode = values.get("maildivvy_cert_mode", settings.DEFAULT_CERT_MODE)
    steps = []
    if mode == "self-signed":
        steps.append("THIS MACHINE HAS A SELF-SIGNED CERTIFICATE: it is for a test machine only, and no "
                     "mail client trusts it.")
    steps.append("Prove the publication from outside your network with the outside probe, as step 19 "
                 "printed (administration guide, the outside probe).")
    steps.append("If people read mail from outside, forward 993 and 465 from your router to this machine; "
                 "never 443 or 22.")
    steps.append(f"From an administrator network, open https://{name}/, sign in as break-glass and create "
                 "the first administrator (installation guide, first sign-in).")
    if not values.get("maildivvy_backup_store_copy"):
        steps.append(f"Before you enable the first external mailbox, set maildivvy_backup_store_copy in "
                     f"{settings.PATH} and run the installer again, then take a backup and check the copy.")
    else:
        steps.append("Before you enable the first external mailbox, take a backup and check the store copy "
                     "it made (installation guide, copy the store).")
    if mode == "provided":
        steps.append("Nothing renews your own certificate: replace it before it expires, with "
                     "maildivvy-cert install-provided.")
    provider = values.get("maildivvy_acme_dns_provider", settings.DEFAULT_DNS_PROVIDER)
    if mode in settings.ACME_MODES and provider not in settings.TESTED_DNS_CREDENTIALS:
        steps.append(f"Your DNS provider {provider} is untested: read the first renewal yourself "
                     "(health's tls subsystem).")
    steps.append(f"The full log of this run: {log_path}")
    return steps
