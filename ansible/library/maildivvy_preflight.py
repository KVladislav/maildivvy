#!/usr/bin/python
"""Install step 1: check every setting and identify the data disks.

Changes nothing. Every missing, malformed or ambiguous value is refused in one
failure that lists them all (docs/architecture.md § Installation, step 1).

The disks: in separate mode the operator names each data disk by its current device
at the first install, and only an empty whole disk that is not the system disk is
taken, so `mkfs` can never land on the wrong device. After formatting,
step 2 records the filesystems' UUIDs in /etc/maildivvy/disks.json, and every later
run finds them by UUID alone, whatever the device settings say. A machine installed
before the record existed is recognised by what is mounted at the store and index.
In one-disk mode the store and index are directories on the filesystem that holds
/srv/maildivvy, which must be ext4, or xfs with reflink off unless the operator
consents.

The settings also name the machine they are for: `hostname` is compared with the
machine's own, so an install aimed at the wrong machine stops here with everything
else that is wrong.
"""

# The disks as chosen explicitly, recorded by UUID, or one disk.

import ipaddress
import json
import os
import pwd
import re
import socket
import stat

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_preflight
short_description: Check Maildivvy's install settings and identify its data disks
options:
  hostname: {type: raw}
  cert_name: {type: raw}
  vmail_uid: {type: raw}
  vmail_gid: {type: raw}
  disk_mode: {type: raw}
  store_disk: {type: raw}
  index_disk: {type: raw}
  swap_disk: {type: raw}
  single_disk_allow_reflink: {type: raw}
  admin_networks: {type: raw}
  firewall_confirmation: {type: raw}
  admin_ssh_source: {type: raw}
  connection: {type: str}
  container_pool: {type: raw}
  breakglass_password: {type: raw, no_log: true}
  cert_mode: {type: raw}
  insecure_test_certificate: {type: raw}
  acme_dns_provider: {type: raw}
  acme_dns_credentials: {type: raw, no_log: true}
  acme_email: {type: raw}
  provided_cert: {type: raw}
  provided_chain: {type: raw}
  provided_key: {type: raw}
  backup_keep: {type: raw}
  backup_store_copy: {type: raw}
  health_textfile_dir: {type: raw}
"""

GIB = 1024**3
# xfs labels hold at most 12 characters
LABELS = {"store": "mdiv-store", "index": "mdiv-index", "swap": "mdiv-swap"}
FSTYPES = {"store": "xfs", "index": "xfs", "swap": "swap"}
# written by step 2 once the filesystems exist; the only way a later run finds them
RECORD = "/etc/maildivvy/disks.json"
SRV = "/srv/maildivvy"
MOUNTS = {"store": f"{SRV}/store", "index": f"{SRV}/index"}
DISK_MODES = ("separate", "single")
SINGLE_FSTYPES = ("ext4", "xfs")
DEVICE = re.compile(r"^/dev/[A-Za-z0-9._/:-]+$")

HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
PASSWORD_MIN = 15
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# acme is the default; self-signed exists for a test machine with no DNS credential and
# is reached only by setting it with the test flag
CERT_MODES = ("acme", "acme-staging", "provided", "self-signed")
ACME_MODES = ("acme", "acme-staging")
PROVIDED = ("provided_cert", "provided_chain", "provided_key")
SECRETS = ("breakglass_password", "acme_dns_credentials")
PROVIDER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# a new session through the firewall (a control machine's), a new SSH login from
# the administrator's stated address (a local run), or an explicit console-only run
CONFIRMATIONS = ("new-session", "ssh-login", "console")
LOCAL = ("local", "ansible.builtin.local")
# the certificate program's own pattern: provided_problems, which both hold, reads the
# blocks with it (a unit test compares the two)
PEM = re.compile(r"-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----\r?\n?", re.DOTALL)


def _int(value, low, high):
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        value = int(value)
    return value if isinstance(value, int) and low <= value <= high else None


def _hostname(v):
    return v if isinstance(v, str) and HOSTNAME.match(v) else None


def _fqdn(v):
    if not isinstance(v, str) or len(v) > 253:
        return None
    labels = v.split(".")
    return v if len(labels) >= 2 and all(HOSTNAME.match(label) for label in labels) else None


def _networks(v):
    if not isinstance(v, list):
        return None
    try:
        return [str(ipaddress.ip_network(str(n), strict=True)) for n in v]
    except ValueError:
        return None


def _network(v):
    try:
        return str(ipaddress.ip_network(str(v), strict=True)) if isinstance(v, str) else None
    except ValueError:
        return None


def _address(v):
    try:
        return str(ipaddress.ip_address(v)) if isinstance(v, str) else None
    except ValueError:
        return None


def _credentials(v):
    """{NAME: one-line value} as lego names them; a *_FILE name is the install's to write, not given."""
    if not isinstance(v, dict) or not v:
        return None
    for name, value in v.items():
        if (not isinstance(name, str) or not VARIABLE.match(name) or name.endswith("_FILE")
                or not isinstance(value, str) or not value or re.search(r"[\x00-\x1f\x7f]", value)):
            return None
    return v


def _path(v):
    return v if isinstance(v, str) and v.startswith("/") and not re.search(r"[\x00-\x1f\x7f]", v) else None


def _directory(v):
    # one word: it is written into the health unit's ExecStart and ReadWritePaths lines
    ok = (isinstance(v, str) and re.fullmatch(r"(/[A-Za-z0-9._@+-]+)+/?", v)
          and not {".", ".."} & set(v.split("/")))
    return v if ok else None


def _email(v):
    return v if isinstance(v, str) and (v == "-" or EMAIL.match(v)) else None


def _password(v):
    return v if isinstance(v, str) and len(v) >= PASSWORD_MIN else None


def _device(v):
    return v if isinstance(v, str) and DEVICE.match(v) and "/../" not in v else None


def _bool(v):
    """True or False from a YAML boolean or its usual spellings; None for anything else."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return {"true": True, "yes": True, "false": False, "no": False}.get(v.strip().lower())
    return None


def _line(v):
    # one line of a settings file: a newline would start another setting (backup.conf)
    return v if isinstance(v, str) and not re.search(r"[\x00-\x1f\x7f]", v) else None


# name -> (required, what it must be, check returning the value or None)
SETTINGS = {
    "hostname": (True, "this machine's short hostname, [a-z0-9-]", _hostname),
    "cert_name": (True, "the fully qualified name clients connect to", _fqdn),
    "vmail_uid": (True, "the mail store's fixed uid, a system id 100-999", lambda v: _int(v, 100, 999)),
    "vmail_gid": (True, "the mail store's fixed gid, a system id 100-999", lambda v: _int(v, 100, 999)),
    "disk_mode": (False, f"the disk mode, one of {', '.join(DISK_MODES)}; separate when not set",
                  lambda v: v if v in DISK_MODES else None),
    # needed at the first install in separate mode; never read once the disks are recorded
    "store_disk": (False, "the store disk's current device path, such as /dev/sdb", _device),
    "index_disk": (False, "the index disk's current device path, such as /dev/sdc", _device),
    "swap_disk": (False, "the swap disk's current device path, if there is one", _device),
    "single_disk_allow_reflink": (False, "true or false: whether one-disk mode may keep mail on "
                                         "xfs with reflink on", _bool),
    "admin_networks": (True, "a list of administrator networks in CIDR form", _networks),
    # how steps 3 and 4 learn the administrator can still log in
    "firewall_confirmation": (False, f"how the firewall steps are confirmed, one of {', '.join(CONFIRMATIONS)}; "
                                     "new-session when not set",
                              lambda v: v if v in CONFIRMATIONS else None),
    "admin_ssh_source": (False, "the address the administrator logs in from over SSH, such as 192.0.2.7",
                         _address),
    "container_pool": (False, "the range the container block treats as containers, in CIDR form", _network),
    "breakglass_password": (True, f"the break-glass password, at least {PASSWORD_MIN} characters", _password),
    "cert_mode": (False, f"the certificate mode, one of {', '.join(CERT_MODES)}; acme when not set",
                  lambda v: v if v in CERT_MODES else None),
    # self-signed only with the test flag
    "insecure_test_certificate": (False, "true or false: whether a self-signed certificate is allowed, "
                                         "for a test machine", _bool),
    "acme_dns_provider": (False, "lego's code for the DNS provider, such as desec or cloudflare; desec "
                                 "when not set", lambda v: v if isinstance(v, str) and PROVIDER.match(v) else None),
    # required in the acme modes; checked below
    "acme_dns_credentials": (False, "a mapping of the provider's credential names, as `lego dnshelp -c "
                                    "<provider>` lists them, to one-line values", _credentials),
    "acme_email": (False, "the ACME account's contact address, or -", _email),
    # required in provided mode; the files are read on this machine
    "provided_cert": (False, "the absolute path of the certificate file, on this machine", _path),
    "provided_chain": (False, "the absolute path of the chain file (the issuing CA's certificates)", _path),
    "provided_key": (False, "the absolute path of the private key file, unencrypted", _path),
    "backup_keep": (False, "how many backup runs are kept, 1-1000", lambda v: _int(v, 1, 1000)),
    "backup_store_copy": (False, "the operator's store-copy command, one line", _line),
    "health_textfile_dir": (False, "the absolute path of a directory for node_exporter's textfile "
                                   "collector, without spaces", _directory),
}
DISKS = ("store", "index", "swap")


def _absent(value):
    return value is None or value == "" or value == []


# An administrator network is exempt from every ban and every rate limit (#): wider than this it must be a private range, and it is never wider than
# the widest private one (`0.0.0.0/1` would exempt half the internet).
WIDEST_PUBLIC = {4: 16, 6: 48}
WIDEST = {4: 8, 6: 7}


def too_wide(network):
    net = ipaddress.ip_network(network)
    return net.prefixlen < WIDEST[net.version] or (
        net.prefixlen < WIDEST_PUBLIC[net.version] and not net.is_private)


def setting_errors(params, connection=None):
    """Every problem with the settings, one line each, in the table's order. Values are never echoed.

    `connection` is the one the install runs over, as Ansible names it.
    """
    errors, parsed = [], {}
    for name, (required, what, check) in SETTINGS.items():
        value = params.get(name)
        if _absent(value):
            if required:
                errors.append(f"missing {name}: {what}")
            continue
        parsed[name] = check(value)
        if parsed[name] is None:
            errors.append(f"malformed {name}: expected {what}")
    errors += certificate_errors(params, parsed)
    errors += confirmation_errors(params, parsed, connection)
    if parsed.get("disk_mode") == "single":
        for role in DISKS:
            if not _absent(params.get(f"{role}_disk")):
                errors.append(f"ambiguous {role}_disk: disk_mode is single, which keeps mail on the root "
                              "filesystem; leave the disk settings out or set disk_mode separate")
    pool, networks = parsed.get("container_pool"), parsed.get("admin_networks")
    wide = [n for n in networks or [] if too_wide(n)]
    if wide:
        errors.append(f"too wide admin_networks: {', '.join(wide)} would exempt sources far beyond "
                      "your own from every ban and rate limit; a network wider than /16 (IPv4) or "
                      "/48 (IPv6) must be a private range, and none may be wider than /8")
    if pool and networks:
        overlapping = [n for n in networks if ipaddress.ip_network(n).overlaps(ipaddress.ip_network(pool))]
        if overlapping:
            errors.append(f"ambiguous container_pool: {pool} overlaps the administrator network "
                          f"{', '.join(overlapping)}, so the container block would drop its traffic")
    return errors


def confirmation_errors(params, parsed, connection):
    """How the firewall steps are confirmed: a local run cannot use its own session."""
    errors = []
    confirmation = parsed.get("firewall_confirmation") or (
        "new-session" if _absent(params.get("firewall_confirmation")) else None)
    source, networks = parsed.get("admin_ssh_source"), parsed.get("admin_networks")
    given = not _absent(params.get("admin_ssh_source"))
    if confirmation == "new-session" and connection in LOCAL:
        errors.append("refused firewall_confirmation: this run has a local connection, so no session of "
                      "its own crosses the firewall; set it to ssh-login with admin_ssh_source to wait "
                      "for your SSH login through the new rules, or to console if you work from the "
                      "console only")
    if confirmation == "ssh-login" and not given:
        errors.append(f"missing admin_ssh_source: {SETTINGS['admin_ssh_source'][1]}, needed by "
                      "firewall_confirmation ssh-login")
    elif confirmation in ("new-session", "console") and given:
        errors.append(f"ambiguous admin_ssh_source: firewall_confirmation is {confirmation}, which "
                      "does not read it; set firewall_confirmation to ssh-login to wait for that login")
    if confirmation == "ssh-login" and source and networks and not any(
            ipaddress.ip_address(source) in ipaddress.ip_network(n) for n in networks):
        errors.append(f"refused admin_ssh_source: {source} is outside the administrator networks, "
                      "so the firewall would never let its login through")
    return errors


def certificate_errors(params, parsed):
    """The certificate settings together: each mode's own, and none of another's."""
    errors = []
    mode = parsed.get("cert_mode") or ("acme" if _absent(params.get("cert_mode")) else None)
    credentials = not _absent(params.get("acme_dns_credentials"))
    paths = [name for name in PROVIDED if not _absent(params.get(name))]
    if mode in ACME_MODES:
        if not credentials:
            errors.append(f"missing acme_dns_credentials: {SETTINGS['acme_dns_credentials'][1]}, "
                          f"needed by cert_mode {mode}")
    elif mode in ("provided", "self-signed") and credentials:
        errors.append(f"ambiguous cert_mode: {mode}, yet a DNS credential is given; "
                      "set cert_mode to acme to issue with it")
    if mode == "provided":
        errors += [f"missing {name}: {SETTINGS[name][1]}, needed by cert_mode provided"
                   for name in PROVIDED if name not in paths]
    elif mode is not None:
        errors += [f"ambiguous {name}: cert_mode is {mode}, which does not read it; "
                   "set cert_mode to provided to use your own certificate" for name in paths]
    if mode == "self-signed" and parsed.get("insecure_test_certificate") is not True:
        errors.append("refused cert_mode: self-signed is for a test machine only, and needs "
                      "insecure_test_certificate set to true; no client trusts the certificate")
    return errors


def provided_problems(paths, name, run):
    """What is wrong with the operator's certificate, chain and key: [] when nothing is.

    Install step 1 (the preflight module) and `maildivvy-cert install-provided` hold this
    same function, word for word (a unit test compares them), so a certificate step 1
    passes is one the command publishes. `run(argv, data=None)` returns (exit code,
    stdout). The key is never printed; an encrypted key is refused rather than prompted for.
    """
    problems, text = [], {}
    for what in ("cert", "chain", "key"):
        try:
            with open(paths[what], "rb") as handle:
                text[what] = handle.read()
        except OSError as err:
            problems.append(f"the provided {what} {paths[what]} cannot be read: {err.strerror}")
    if problems:
        return problems
    blocks = {what: PEM.findall(text[what].decode(errors="replace")) for what in ("cert", "chain")}
    for what in ("cert", "chain"):
        if not blocks[what] or run(["openssl", "x509", "-noout"], (blocks[what][0] + "\n").encode())[0] != 0:
            problems.append(f"the provided {what} {paths[what]} is not a PEM certificate")
    if problems:
        return problems
    leaf = (blocks["cert"][0] + "\n").encode()
    rc, key_pub = run(["openssl", "pkey", "-pubout", "-passin", "pass:", "-in", paths["key"]])
    _, cert_pub = run(["openssl", "x509", "-noout", "-pubkey"], leaf)
    if rc != 0 or key_pub.strip() != cert_pub.strip():
        problems.append(f"the provided certificate {paths['cert']} does not match its key {paths['key']} "
                        "(or the key is encrypted)")
    if run(["openssl", "x509", "-noout", "-checkhost", name], leaf)[0] != 0:
        problems.append(f"the provided certificate {paths['cert']} does not cover {name}")
    if run(["openssl", "x509", "-noout", "-checkend", "0"], leaf)[0] != 0:
        problems.append(f"the provided certificate {paths['cert']} has expired")
    # a chain from another CA would be served, and every client would refuse it
    if run(["openssl", "verify", "-no-CAfile", "-no-CApath", "-partial_chain", "-no_check_time",
            "-trusted", paths["chain"]], leaf)[0] != 0:
        problems.append(f"the provided chain {paths['chain']} does not issue the certificate {paths['cert']}")
    return problems


# the health role's user (vars/main.yml; a unit test holds them equal)
HEALTH_USER = "maildivvy-health"


def textfile_dir_errors(path, lookup=os.stat, owner=lambda uid: pwd.getpwuid(uid).pw_name):
    """An existing textfile directory must already be the health user's: step 17 creates a
    new one, and never changes the owner of one that exists (it may be /var/lib, or
    node_exporter's own)."""
    try:
        info = lookup(path)
    except FileNotFoundError:
        return []
    except OSError as err:
        return [f"unreadable health_textfile_dir: {path}: {err.strerror}"]
    if not stat.S_ISDIR(info.st_mode):
        return [f"refused health_textfile_dir: {path} exists and is not a directory"]
    try:
        name = owner(info.st_uid)
    except KeyError:
        name = f"uid {info.st_uid}"
    if name == HEALTH_USER:
        return []
    return [f"refused health_textfile_dir: {path} exists and is {name}'s, and step 17 never changes an "
            f"existing directory's owner; name a directory that does not exist yet, or make this one "
            f"{HEALTH_USER}'s first if it holds nothing else"]


def hostname_errors(setting, actual):
    """[] when the machine is the one the settings name, else the one line saying it is not.

    The machine's name is its first label, in any case, as the kernel gives it. Hostnames
    are not secrets, so both are named: the operator has to see which machine this is.
    """
    here = actual.split(".", 1)[0].lower()
    if here == setting:
        return []
    return [f"wrong hostname: this machine is {here}, and the settings are for {setting}; "
            "run the install against the machine they name, or correct maildivvy_hostname"]


# --- a mail system that is not ours ------------------------------------------

# Mail systems this install never puts on a machine: a transfer agent, an IMAP or POP
# server, or rspamd outside its container. Found installed, they are refused on any run.
FOREIGN_MAIL = ("exim4-base", "exim4-daemon-light", "exim4-daemon-heavy", "sendmail-bin", "sendmail-base",
                "courier-mta", "courier-imap", "courier-pop", "opensmtpd", "cyrus-imapd", "cyrus-common",
                "uw-imapd", "citadel-server", "nullmailer", "dma", "ssmtp", "msmtp-mta", "masqmail",
                "rspamd")
# Ours once this install has run: step 13's first part makes /opt/maildivvy before step 7
# installs Postfix, and step 2 writes the disks' record, so a machine with Postfix or
# Dovecot and neither of those got them from someone else.
OUR_MAIL = ("dovecot-core", "postfix")
OURS = ("/opt/maildivvy", RECORD)


def installed_packages(text):
    """The installed packages from `dpkg-query -W -f '${db:Status-Abbrev}\\t${Package}\\n'`.

    A package removed with its configuration kept (`rc`) or never installed is not one.
    """
    found = set()
    for line in text.splitlines():
        status, _, name = line.partition("\t")
        if name and len(status) >= 2 and status[1] not in "nc":
            found.add(name.strip())
    return found


def foreign_mail_errors(packages, ours):
    """[] unless the machine carries a mail system that is not ours; `ours` is whether this
    install has run here before."""
    foreign = sorted(set(FOREIGN_MAIL) & packages)
    if not ours:
        foreign = sorted(set(foreign) | (set(OUR_MAIL) & packages))
    if not foreign:
        return []
    return [f"refused mail system: {', '.join(foreign)} installed, and this install did not put "
            f"{'it' if len(foreign) == 1 else 'them'} there; Maildivvy must be the only mail system on "
            f"the machine, so remove {'it' if len(foreign) == 1 else 'them'} or install on a fresh machine"]


# --- the disks ----------------------------------------------------------------------


def _flatten(devices):
    for dev in devices:
        yield dev
        yield from _flatten(dev.get("children") or [])


def _mountpoints(dev):
    """Every mount point on this device and everything below it (partitions, LVM)."""
    return {m for d in _flatten([dev]) for m in d.get("mountpoints") or [] if m}


def _is_empty(dev):
    # a partition table alone (a wiped but labelled disk) makes mkfs refuse at step 2
    return not dev.get("children") and not dev.get("fstype") and not dev.get("pttype") and not _mountpoints(dev)


def _is_ours(dev, role):
    return not dev.get("children") and dev.get("fstype") == FSTYPES[role] and dev.get("label") == LABELS[role]


def _found(dev, role, state):
    return {"path": dev["path"], "label": LABELS[role], "state": state,
            "uuid": dev.get("uuid") if state == "ours" else None}


def _record_uuids(record):
    """A separate-mode record's {role: uuid}, or None when it is not one."""
    uuids = record.get("uuids") if isinstance(record, dict) else None
    if (not isinstance(uuids, dict) or not {"store", "index"} <= set(uuids) or not set(uuids) <= set(DISKS)
            or not all(isinstance(u, str) and u for u in uuids.values())):
        return None
    return uuids


def _mode_errors(mode, record):
    """Why the record forbids this mode: a record that is not one, or another mode."""
    if record is None:
        return []
    if not isinstance(record, dict) or record.get("mode") not in DISK_MODES or (
            record["mode"] == "separate" and _record_uuids(record) is None):
        return [f"unreadable {RECORD}: not a record of the disks; restore it from the backup or "
                "correct it by hand"]
    if record["mode"] != mode:
        return [f"wrong disk_mode: this machine was installed in {record['mode']} mode ({RECORD}), "
                "and a re-run never changes it"]
    return []


def _chosen(role, path, devices):
    """A disk named by its device at the first install: an empty whole disk, never the system disk."""
    found = [d for d in devices if d.get("path") == path]
    if not found:
        return None, f"no {role} disk: {path} is no block device on this machine"
    dev = found[0]
    if dev.get("type") != "disk":
        return None, f"{role}_disk {path} is not a whole disk ({dev.get('type')}); name the disk itself"
    if "/" in _mountpoints(dev):
        return None, f"{role}_disk {path} is the system disk: it holds /; refusing to format it"
    if _is_ours(dev, role):
        return _found(dev, role, "ours"), None
    if _is_empty(dev):
        return _found(dev, role, "blank"), None
    return None, (f"{role}_disk {path} is not empty (a partition table, partitions, a filesystem or a "
                  "mount); refusing to format it")


def separate_disks(chosen, blockdevices, record, mounted):
    """Which device each data disk is on this run, or why not: ({role: disk}, errors).

    A recorded disk is found by its filesystem UUID and nothing else. Without a record,
    what is mounted at the store and index and carries this install's label is taken as
    it is (a first-version machine, or a run that stopped before the record), and so is
    a disk carrying the swap label; only then is a device setting read. `chosen` holds
    the device settings, resolved to the devices' own paths; `blockdevices` is lsblk's
    tree; `mounted` is what findmnt reads at each mount point. A disk is
    {path, label, state: blank|ours, uuid}.
    """
    errors = _mode_errors("separate", record)
    if errors:
        return {}, errors
    every = list(_flatten(blockdevices))
    whole = [d for d in every if d.get("type") == "disk"]
    uuids = _record_uuids(record) if record else {}
    picked = {}
    for role in DISKS:
        if role in uuids:
            found = [d for d in whole if d.get("uuid") == uuids[role]]
            if found:
                picked[role] = _found(found[0], role, "ours")
            else:
                errors.append(f"no {role} disk: no disk carries the filesystem {uuids[role]} recorded in {RECORD}")
            continue
        mount = mounted.get(role)
        if mount:
            source = [d for d in whole if d.get("path") == mount.get("source")]
            if source and _is_ours(source[0], role):
                picked[role] = _found(source[0], role, "ours")
            else:
                errors.append(f"{MOUNTS[role]} is already mounted from {mount.get('source')} "
                              f"({mount.get('fstype')}), which this install did not make; unmount it "
                              "and take it out of /etc/fstab first")
            continue
        labelled = [d for d in whole if role == "swap" and not record and _is_ours(d, role)]
        if labelled:
            picked[role] = _found(labelled[0], role, "ours")
        elif chosen.get(role):
            disk, error = _chosen(role, chosen[role], every)
            if error:
                errors.append(error)
            else:
                picked[role] = disk
        elif role != "swap":
            errors.append(f"missing {role}_disk: {SETTINGS[f'{role}_disk'][1]}, needed at the first install")
    seen = {}
    for role, disk in list(picked.items()):
        if disk["path"] in seen:
            errors.append(f"ambiguous {role}_disk: {disk['path']} is also the {seen[disk['path']]} disk")
            del picked[role]
        else:
            seen[disk["path"]] = role
    return picked, errors


def single_disk(filesystem, allow_reflink, record, mounted):
    """The filesystem one-disk mode keeps mail on, or why not: (filesystem, errors).

    `filesystem` is the one that holds /srv/maildivvy, {target, source, fstype, reflink},
    its reflink None when it is not xfs or could not be read.
    """
    errors = _mode_errors("single", record)
    if errors:
        return None, errors
    own = [MOUNTS[role] for role in ("store", "index") if mounted.get(role)]
    if own:
        return None, [f"wrong disk_mode: {own[0]} is a filesystem of its own, so this machine has "
                      "separate disks; set disk_mode separate"]
    fstype, target = filesystem["fstype"], filesystem["target"]
    if fstype not in SINGLE_FSTYPES:
        return None, [f"unsupported filesystem: one-disk mode keeps mail on {' or '.join(SINGLE_FSTYPES)}, "
                      f"and {target} is {fstype}"]
    if fstype == "xfs" and filesystem.get("reflink") is None:
        return None, [f"unreadable filesystem: {target} is xfs, and xfs_info could not say whether "
                      "reflink is on"]
    if fstype == "xfs" and filesystem["reflink"] and not allow_reflink:
        return None, [f"refused single_disk_allow_reflink: {target} is xfs with reflink on, and Dovecot's "
                      "in-place index rewrites then grow the store; set single_disk_allow_reflink true "
                      "to accept that, or use separate disks"]
    return filesystem, []


def _findmnt(module, *args):
    """findmnt's one filesystem for these arguments, or None when there is none."""
    rc, out, err = module.run_command(["findmnt", "--json", "-o", "TARGET,SOURCE,FSTYPE,UUID", *args])
    if rc == 1:
        return None
    if rc != 0:
        module.fail_json(msg=f"findmnt failed: {err.strip()}")
    found = json.loads(out)["filesystems"]
    return found[0] if found else None


def _holding(module):
    """The filesystem that holds /srv/maildivvy, made or not yet, with its reflink when xfs."""
    path = SRV
    while not os.path.exists(path):
        path = os.path.dirname(path)
    found = _findmnt(module, "--target", path)
    if found is None:
        module.fail_json(msg=f"findmnt found no filesystem holding {path}")
    reflink = None
    if found["fstype"] == "xfs":
        rc, out, _ = module.run_command(["xfs_info", found["target"]])
        match = re.search(r"reflink=([01])", out) if rc == 0 else None
        reflink = match.group(1) == "1" if match else None
    return {"target": found["target"], "source": found["source"], "fstype": found["fstype"],
            "reflink": reflink}


def _read_record():
    try:
        with open(RECORD) as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return "unreadable"   # not a record: refused as such


def main():
    module = AnsibleModule(
        argument_spec={**{name: {"type": "raw", "no_log": name in SECRETS} for name in SETTINGS},
                       "connection": {"type": "str"}},
        supports_check_mode=True,
    )
    params = module.params
    errors = setting_errors(params, connection=params.get("connection"))
    setting = _hostname(params.get("hostname"))
    if setting:
        errors += hostname_errors(setting, socket.gethostname())
    rc, out, err = module.run_command(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\n"])
    if rc != 0:
        module.fail_json(msg=f"dpkg-query failed: {err.strip()}", errors=errors)
    errors += foreign_mail_errors(installed_packages(out), any(os.path.exists(p) for p in OURS))
    if _directory(params.get("health_textfile_dir")):
        errors += textfile_dir_errors(params["health_textfile_dir"])
    mode ="separate" if _absent(params.get("disk_mode")) else params["disk_mode"]
    record = _read_record()
    mounted = {role: _findmnt(module, "--mountpoint", path) for role, path in MOUNTS.items()}
    disks, filesystem = {}, None
    if mode == "separate":
        chosen = {role: os.path.realpath(params[f"{role}_disk"]) for role in DISKS
                  if _device(params.get(f"{role}_disk"))}
        rc, out, err = module.run_command(
            ["lsblk", "--json", "--bytes", "--tree", "-o", "NAME,PATH,SIZE,TYPE,FSTYPE,PTTYPE,LABEL,UUID,MOUNTPOINTS"])
        if rc != 0:
            module.fail_json(msg=f"lsblk failed: {err.strip()}", errors=errors)
        disks, disk_errors = separate_disks(chosen, json.loads(out)["blockdevices"], record, mounted)
        errors += disk_errors
    elif mode == "single":
        filesystem, disk_errors = single_disk(_holding(module), _bool(params.get("single_disk_allow_reflink")),
                                              record, mounted)
        errors += disk_errors
    provided = {what: _path(params.get(f"provided_{what}")) for what in ("cert", "chain", "key")}
    if params.get("cert_mode") == "provided" and all(provided.values()) and _fqdn(params.get("cert_name")):
        def run(argv, data=None):
            rc, out, _ = module.run_command(argv, data=data, binary_data=True)
            return rc, out
        # refused here, before step 2 changes anything
        errors += [f"refused provided certificate: {problem}"
                   for problem in provided_problems(provided, params["cert_name"], run)]
    if errors:
        module.fail_json(msg="the install settings are incomplete or wrong:\n" + "\n".join(errors),
                         errors=errors, disks=disks)
    module.exit_json(changed=False, mode=mode, disks=disks, filesystem=filesystem)


if __name__ == "__main__":
    main()
