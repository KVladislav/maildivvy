"""The questions the installer asks when there is no settings file, and the secrets.

Answers are taken as given: step 1 of the installation checks every setting and lists
every problem at once, before anything changes. A required answer left empty is asked
again. Secrets are read without echo and never shown back.
"""

import getpass

from maildivvy.installer.settings import (ACME_MODES, DEFAULT_CERT_MODE, DEFAULT_DNS_PROVIDER, SECRETS,
                                          TESTED_DNS_CREDENTIALS)

VMAIL_ID = "900"
PASSWORD_MIN = 15


class Console:
    """The terminal: a question with its default, a secret without echo, a line said."""

    def ask(self, question, default=None):
        shown = f"{question} [{default}]: " if default else f"{question}: "
        return input(shown).strip() or (default or "")

    def secret(self, question):
        return getpass.getpass(f"{question}: ")

    def say(self, text):
        print(text, flush=True)


def _required(console, question, default=None):
    while True:
        answer = console.ask(question, default).strip()
        if answer:
            return answer
        console.say("  an answer is needed")


def _choice(console, question, choices, default):
    while True:
        answer = console.ask(f"{question} ({' or '.join(choices)})", default).strip()
        if answer in choices:
            return answer
        console.say(f"  one of: {', '.join(choices)}")


def _size(size):
    return f"{int(size) / 1024**3:.1f} GiB"


def _holds_root(device):
    stack = [device]
    while stack:
        dev = stack.pop()
        if "/" in (dev.get("mountpoints") or []):
            return True
        stack += dev.get("children") or []
    return False


def disk_choices(lsblk):
    """(path, size, model) of each whole disk but the one that holds /, from lsblk's JSON."""
    return [(d["path"], _size(d.get("size") or 0), (d.get("model") or "").strip())
            for d in lsblk.get("blockdevices", []) if d.get("type") == "disk" and not _holds_root(d)]


def ask_settings(console, hostname, lsblk, insecure):
    """Every non-secret setting, asked in the installation guide's order."""
    values = {"maildivvy_hostname": hostname}
    console.say(f"Settings for {hostname}. Each is explained in the installation guide.")
    values["maildivvy_cert_name"] = _required(
        console, "The mail name clients connect to, which the certificate carries (such as mail.example.org)")
    vmail = _required(console, "The mail store owner's fixed uid and gid, 100-999; keep it on every rebuild",
                      VMAIL_ID)
    values["maildivvy_vmail_uid"] = values["maildivvy_vmail_gid"] = int(vmail) if vmail.isdigit() else vmail
    mode = _choice(console, "Disks: a disk each for the store and the index, or one disk", ("separate", "single"),
                   "separate")
    values["maildivvy_disk_mode"] = mode
    if mode == "separate":
        console.say("Empty whole disks on this machine (the system disk is not offered):")
        for path, size, model in disk_choices(lsblk):
            console.say(f"  {path}  {size}  {model}".rstrip())
        values["maildivvy_store_disk"] = _required(console, "The store disk's device path")
        values["maildivvy_index_disk"] = _required(console, "The index disk's device path")
        swap = console.ask("A dedicated swap disk's device path, or empty for none").strip()
        if swap:
            values["maildivvy_swap_disk"] = swap
    networks = _required(console, "The administrator networks that may reach SSH and the interface, "
                                  "in CIDR form, comma-separated")
    values["maildivvy_admin_networks"] = [n.strip() for n in networks.split(",") if n.strip()]
    confirmation = _choice(console, "How the firewall steps learn you can still log in: a new SSH login "
                                    "from your address, or console-only", ("ssh-login", "console"), "ssh-login")
    values["maildivvy_firewall_confirmation"] = confirmation
    if confirmation == "ssh-login":
        values["maildivvy_admin_ssh_source"] = _required(console, "The address you log in from over SSH")
    modes = ("acme", "provided", "self-signed") if insecure else ("acme", "provided")
    cert_mode = _choice(console, "The certificate: issued by ACME, or your own", modes, DEFAULT_CERT_MODE)
    values["maildivvy_cert_mode"] = cert_mode
    if cert_mode == "acme":
        values["maildivvy_acme_dns_provider"] = _required(
            console, "Your DNS provider, as lego names it (https://go-acme.github.io/lego/dns/)",
            DEFAULT_DNS_PROVIDER)
        email = console.ask("The ACME account's contact address, or empty for none").strip()
        if email:
            values["maildivvy_acme_email"] = email
    elif cert_mode == "provided":
        for what in ("cert", "chain", "key"):
            values[f"maildivvy_provided_{what}"] = _required(
                console, f"The absolute path of the {'unencrypted key' if what == 'key' else what} file")
    copy = console.ask("Your one-line command that copies the mail store at each backup, or empty for "
                       "none yet").strip()
    if copy:
        values["maildivvy_backup_store_copy"] = copy
    textfile = console.ask("A directory for node_exporter's textfile collector, or empty for none").strip()
    if textfile:
        values["maildivvy_health_textfile_dir"] = textfile
    return values


def ask_secrets(console, values):
    """The break-glass password (twice) and, in the ACME modes, the DNS credentials."""
    secrets = {}
    while True:
        password = console.secret(f"The break-glass password, {PASSWORD_MIN} characters or more")
        if len(password) < PASSWORD_MIN:
            console.say(f"  it must be {PASSWORD_MIN} characters or more")
            continue
        if console.secret("The same password again") == password:
            break
        console.say("  the two did not match")
    secrets["maildivvy_breakglass_password"] = password
    if values.get("maildivvy_cert_mode", DEFAULT_CERT_MODE) in ACME_MODES:
        provider = values.get("maildivvy_acme_dns_provider", DEFAULT_DNS_PROVIDER)
        console.say(f"The credentials lego reads for {provider}, by lego's names "
                    f"(lego dnshelp -c {provider} lists them).")
        names = _required(console, "Their names, comma-separated", TESTED_DNS_CREDENTIALS.get(provider))
        secrets["maildivvy_acme_dns_credentials"] = {
            name: console.secret(name) for name in (n.strip() for n in names.split(",")) if name}
    assert set(secrets) <= set(SECRETS)
    return secrets


def summary(values):
    """The settings as lines to confirm before they are written."""
    return [f"{key}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
            for key, value in values.items()]
