"""The machine itself: `host`, `network` and `ban`.

`network` and `ban` read the firewall, the container runtime and fail2ban, which only root
can read; the system helper takes those readings (`helper.py`). Install steps 18 and 19
make what they check, and read both subsystems as their own proof.
"""

import datetime
import hashlib
import ipaddress
import json
import os
import re

from maildivvy.health import probe, services
from maildivvy.health.context import check, passed
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import FAIL, PASS, UNKNOWN, WARN, Check
from maildivvy.health.settings import DISKS, PUBLICATION
from maildivvy.lib import store

GIB = 1024 ** 3
MIB = 1024 ** 2
FSTAB = "/etc/fstab"
SINGLE_FSTYPES = ("ext4", "xfs")


# --- host -----------------------------------------------------------------------------------------


def fstab_spec(path, text):
    """The device field of the fstab line that mounts `path`, or None."""
    for raw in text.splitlines():
        fields_ = raw.split("#", 1)[0].split()
        if len(fields_) >= 2 and fields_[1] == str(path):
            return fields_[0]
    return None


def disk_mode():
    """`separate` or `single`, as the disks step recorded it."""
    record = probe.load_json(DISKS)
    if record is None:
        raise Unreadable(f"{DISKS} is absent: no disk record, so the disk mode is not known")
    mode = record.get("mode") if isinstance(record, dict) else None
    if mode not in ("separate", "single"):
        raise Unreadable(f"{DISKS} names no disk mode")
    return mode


def findmnt(target, how="--mountpoint"):
    """The filesystem mounted at `target`, or with `--target` the one that holds it."""
    done = probe.command(["findmnt", "--json", how, str(target),
                          "--output", "TARGET,SOURCE,FSTYPE"])
    if done.returncode not in (0, 1):
        raise Unreadable(f"findmnt exited {done.returncode}")
    if done.returncode == 1 or not done.stdout.strip():
        return None
    found = json.loads(done.stdout)["filesystems"]
    return found[0] if found else None


def judge_mount(label, path, mounted, root_mounted, spec):
    """The data filesystem is its own xfs, mounted by UUID."""
    name = f"{label} mount"
    if root_mounted is None:
        # ⛔ the positive control: findmnt answered nothing for / either, so an empty
        # answer for the store says nothing about the store
        raise Unreadable("findmnt answered nothing for / either")
    if mounted is None:
        return Check(name, FAIL, f"{path}: not a mount point",
                     f"the {label} filesystem is not mounted: mail would be written to the "
                     "system disk")
    reading = f"{mounted['fstype']} from {mounted['source']}, fstab {spec or 'has no line'}"
    if mounted["fstype"] != "xfs":
        return Check(name, FAIL, reading, f"{path} is {mounted['fstype']}, not the xfs the "
                                          "install made")
    if not spec or not spec.startswith("UUID="):
        return Check(name, FAIL, reading, f"{path} is not mounted by UUID in {FSTAB}: a disk "
                                          "renamed at boot mounts the wrong filesystem")
    return passed(name, reading)


def judge_shared(label, path, holding):
    """One-disk mode: the data directory is on the filesystem it shares with the system,
    ext4 or xfs, and not a mount of its own."""
    name = f"{label} mount"
    if holding is None:
        raise Unreadable(f"findmnt found no filesystem holding {path}")
    reading = f"{holding['fstype']} from {holding['source']}, shared at {holding['target']}"
    if holding["target"] == str(path):
        return Check(name, FAIL, reading, f"{path} is a filesystem of its own, and the disk record "
                                          "says one-disk mode")
    if holding["fstype"] not in SINGLE_FSTYPES:
        return Check(name, FAIL, reading, f"{path} is on {holding['fstype']}; one-disk mode keeps "
                                          f"mail on {' or '.join(SINGLE_FSTYPES)}")
    return passed(name, reading)


def judge_free(label, path, stat, conf, mode="separate"):
    name = f"{label} free space"
    if stat.f_blocks == 0:
        raise Unreadable(f"statvfs {path} reported a filesystem of no size")
    free = 100.0 * stat.f_bavail / stat.f_blocks
    inodes = 100.0 * stat.f_favail / stat.f_files if stat.f_files else 100.0
    lowest = min(free, inodes)
    reading = (f"{free:.1f}% free of {stat.f_blocks * stat.f_frsize / GIB:.1f} GiB, "
               f"{inodes:.1f}% of inodes free")
    # one disk: mail and the system fill the same filesystem, so the bounds are higher
    fail, warn = ((conf.single_disk_fail_percent, conf.single_disk_warn_percent) if mode == "single"
                  else (conf.disk_fail_percent, conf.disk_warn_percent))
    if lowest < fail:
        return Check(name, FAIL, reading, f"{path} has less than {fail}% free: "
                                          "a full store refuses every message")
    if lowest < warn:
        return Check(name, WARN, reading, f"{path} has less than {warn}% free")
    return passed(name, reading)


def meminfo(text):
    """/proc/meminfo as {field: bytes}."""
    found = {}
    for line in text.splitlines():
        match = re.match(r"^(\w+):\s+(\d+)(?: kB)?$", line.strip())
        if match:
            found[match.group(1)] = int(match.group(2)) * 1024
    for needed in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
        if needed not in found:
            raise Unreadable(f"/proc/meminfo has no {needed}")
    return found


def judge_memory(info, conf):
    available = info["MemAvailable"]
    reading = f"{available / MIB:.0f} MiB available of {info['MemTotal'] / MIB:.0f} MiB"
    if available < conf.memory_fail_mib * MIB:
        return Check("memory", FAIL, reading, f"less than {conf.memory_fail_mib} MiB available: "
                                              "the antivirus's reload is the machine's peak")
    if available < conf.memory_warn_mib * MIB:
        return Check("memory", WARN, reading, f"less than {conf.memory_warn_mib} MiB available")
    return passed("memory", reading)


def judge_swap(info):
    total, free = info["SwapTotal"], info["SwapFree"]
    if total == 0:
        return Check("swap", WARN, "no swap", "the machine has no swap at all: a memory peak is "
                                              "met by the kernel killing a process")
    used = 100.0 * (total - free) / total
    reading = f"{used:.0f}% of {total / MIB:.0f} MiB used"
    if used > 50:
        return Check("swap", WARN, reading, "more than half the swap is in use: the machine is "
                                            "short of memory")
    return passed("swap", reading)


def mount_check(label, path):
    @check(f"{label} mount")
    def read(ctx):
        if disk_mode() == "single":
            return judge_shared(label, path, findmnt(path, "--target"))
        with open(FSTAB) as handle:
            spec = fstab_spec(path, handle.read())
        return judge_mount(label, path, findmnt(path), findmnt("/"), spec)
    return read


def free_check(label, path):
    @check(f"{label} free space")
    def read(ctx):
        mode = disk_mode()
        try:
            stat = os.statvfs(path)
        except OSError as err:
            raise Unreadable(f"statvfs {path}: {err.strerror}") from None
        return judge_free(label, path, stat, ctx.settings, mode)
    return read


def read_meminfo():
    try:
        with open("/proc/meminfo") as handle:
            return meminfo(handle.read())
    except OSError as err:
        raise Unreadable(f"/proc/meminfo: {err.strerror}") from None


@check("memory")
def memory(ctx):
    return judge_memory(read_meminfo(), ctx.settings)


@check("swap")
def swap(ctx):
    return judge_swap(read_meminfo())


HOST = [mount_check("store", store.STORE_ROOT), mount_check("index", store.INDEX_ROOT),
        free_check("store", store.STORE_ROOT), free_check("index", store.INDEX_ROOT),
        memory, swap]


# --- network ------------------------------------------------------------

# SSH, IMAPS, submissions and the interface; nothing else listens off loopback.
EXPECTED_PORTS = {22: "ssh", 993: "imaps", 465: "submissions", 443: "the interface"}
SCOPED_PORTS = (22, 443)      # administrator networks only
MAIL_PORTS = (993, 465)       # closed until publication
ANYWHERE = ("0.0.0.0/0", "::/0")


def listener_address(local):
    """`0.0.0.0:22`, `[::]:993`, `127.0.0.53%lo:53` -> (address, port)."""
    host, _, port = local.rpartition(":")
    host = host.strip("[]").split("%", 1)[0]
    return host, int(port)


def is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def judge_listeners(ss_output):
    """Every expected listener present and nothing else off loopback, loopback excluded by
    ADDRESS, never by port: the container runtime binds a random loopback port."""
    found, unexpected = set(), []
    for line in ss_output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        protocol, local = parts[0], parts[4]
        host, port = listener_address(local)
        if is_loopback(host):
            continue
        if protocol == "tcp" and port in EXPECTED_PORTS:
            found.add(port)
        else:
            unexpected.append(f"{protocol} {local}")
    missing = sorted(set(EXPECTED_PORTS) - found)
    reading = f"listening off loopback: {', '.join(str(p) for p in sorted(found)) or 'nothing'}"
    if not found:
        # ⛔ the parse control: an empty unexpected set is only trusted beside the expected
        # ones found in the same reading
        raise Unreadable("ss listed none of the expected listeners, so its answer says nothing")
    problems = []
    if missing:
        problems.append("not listening: " + ", ".join(f"{p} ({EXPECTED_PORTS[p]})" for p in missing))
    if unexpected:
        problems.append("unexpected off loopback: " + ", ".join(sorted(unexpected)))
    if problems:
        return Check("listeners", FAIL, reading, "; ".join(problems))
    return passed("listeners", reading)


@check("listeners")
def listeners(ctx):
    done = probe.command(["ss", "-H", "-l", "-n", "-t", "-u"], check=True)
    return judge_listeners(done.stdout)


def ufw_rules(text):
    """ufw's own records of its rules, `### tuple ### allow tcp 22 0.0.0.0/0 any 10.0.0.0/8 in`,
    as (action, protocol, port, source)."""
    found = []
    for line in text.splitlines():
        match = re.match(r"^### tuple ### (\w+(?:_\w+)?) (\w+) (\S+) (\S+) (\S+) (\S+)(?: in)?", line)
        if match:
            action, protocol, dport, _dst, _sport, source = match.groups()
            found.append((action, protocol, dport, source))
    return found


def port_sources(rules, port):
    return sorted({source for action, _p, dport, source in rules
                   if action.startswith(("allow", "limit")) and dport == str(port)})


def judge_firewall(reading, published):
    """ufw on, incoming denied, SSH and the interface scoped, the mail ports as publication
    left them, and the container block live."""
    rules = ufw_rules(reading["user_rules"])
    problems = []
    if reading["enabled"] != "yes":
        problems.append("ufw is not enabled")
    for family in ("4", "6"):
        policy = reading["input_policy"].get(family, "")
        if policy != "DROP":
            problems.append(f"IPv{family} incoming traffic is {policy or 'not denied'}, not DROP")
    for port in SCOPED_PORTS:
        sources = port_sources(rules, port)
        if not sources:
            problems.append(f"{port} is not accepted from any network")
        elif any(source in ANYWHERE for source in sources):
            problems.append(f"{port} is accepted from anywhere, not the administrator networks")
    for port in MAIL_PORTS:
        sources = port_sources(rules, port)
        if published and not sources:
            problems.append(f"{port} was published and is no longer accepted")
        if sources and not published:
            problems.append(f"{port} is open but publication was never proved")
    if not re.search(r"-j (DROP|REJECT)", reading["docker_block"]):
        problems.append("the container block carries no DROP or REJECT: a published container "
                        "port bypasses ufw")
    text = (f"ufw {'on' if reading['enabled'] == 'yes' else 'off'}, input "
            + " ".join(f"IPv{f} {reading['input_policy'].get(f) or '?'}" for f in ("4", "6")) + ", "
            + ", ".join(f"{p} from {', '.join(port_sources(rules, p)) or 'nowhere'}"
                        for p in SCOPED_PORTS + MAIL_PORTS))
    if problems:
        return Check("firewall", FAIL, text, "; ".join(problems))
    return passed("firewall", text)


def publication_record():
    record = probe.load_json(PUBLICATION)
    if record is not None and not isinstance(record, dict):
        raise Unreadable(f"{PUBLICATION} is not a record")
    return record


def published(record):
    """Whether step 19 opened the mail ports: it writes `published_at` once the ban is proved.
    An outside result alone is not a publication."""
    return bool(record) and "published_at" in record


@check("firewall")
def firewall(ctx):
    return judge_firewall(ctx.helper("system", "firewall"), published(publication_record()))


def judge_containers(containers):
    """No container publishes a host port or uses host networking."""
    if not containers:
        raise Unreadable("the container runtime listed no container, not even the scanner's")
    problems, names = [], []
    for container in containers:
        names.append(container["name"])
        if container["network_mode"] == "host":
            problems.append(f"{container['name']} uses host networking")
        if container["published"]:
            problems.append(f"{container['name']} publishes {', '.join(container['published'])}")
    reading = f"{len(names)} container(s): {', '.join(names)}"
    if problems:
        return Check("containers", FAIL, reading, "; ".join(problems))
    return passed("containers", reading + ", nothing published")


@check("containers")
def containers(ctx):
    return judge_containers(ctx.helper("system", "containers"))


def judge_publication(record, now, conf, cert_name, leaf):
    """Publication proved from outside, and recently, for this machine: the result's
    name and the leaf each mail port served are the current certificate's. After a move or
    a renewal the stored PASS is about something else."""
    if record is None or "proved_at" not in record:
        return Check("publication", UNKNOWN, "no outside probe result recorded",
                     "the mail ports are not proved from outside yet: run the outside probe "
                     "the publication step printed")
    try:
        at = datetime.datetime.fromisoformat(record["proved_at"])
        result = record["result"]
    except (KeyError, TypeError, ValueError):
        raise Unreadable(f"{PUBLICATION} is not a probe result") from None
    reading = f"outside probe {result} at {at.isoformat(timespec='seconds')}"
    if result != PASS:
        return Check("publication", FAIL, reading, "the outside probe did not pass")
    probed = record.get("probe") if isinstance(record.get("probe"), dict) else {}
    if probed.get("host") != cert_name:
        return Check("publication", FAIL, reading, f"the outside probe proved {probed.get('host')!r}, and "
                                                   f"this machine is now {cert_name!r}: run it again")
    served = probed.get("leaf_sha256") if isinstance(probed.get("leaf_sha256"), dict) else {}
    others = sorted(f"{port} {served.get(port) or 'none'}" for port in ("imaps", "submissions")
                    if served.get(port) != leaf)
    if others:
        return Check("publication", FAIL, reading,
                     f"the outside probe was served {', '.join(others)}, not the certificate published "
                     f"here ({leaf[:16]}): it proved another machine, or the certificate was renewed "
                     "since - run the probe again")
    if now - at > datetime.timedelta(days=conf.publication_days):
        return Check("publication", UNKNOWN, reading,
                     f"the outside probe is older than {conf.publication_days} days: run it again")
    return passed("publication", reading)


@check("publication")
def publication(ctx):
    cert = ctx.certificate()
    leaf = hashlib.sha256(services.published_der(cert["published_cert"])).hexdigest()
    return judge_publication(publication_record(), ctx.now, ctx.settings, cert["cert_name"], leaf)


NETWORK = [listeners, firewall, containers, publication]


# --- ban ------------------------------------------

JAILS = ("dovecot", "postfix")
FILTER = "/etc/fail2ban/filter.d/dovecot.conf"
# What Dovecot 2.4.2 writes for a failed login (measured 2026-09-23), from a documentation
# address; the control is the same server's line for a login that succeeded.
FAILURE_LINE = ("2026-09-23T11:49:35+00:00 mail dovecot[1]: imap-login: Login aborted: "
                "Connection closed (auth failed, 1 attempts in 2 secs) (auth_failed): "
                "user=<nobody@example.org>, method=PLAIN, rip=192.0.2.5, lip=192.0.2.1, TLS")
CONTROL_LINE = ("2026-09-23T11:49:35+00:00 mail dovecot[1]: imap-login: Login: "
                "user=<somebody@example.org>, method=PLAIN, rip=192.0.2.5, lip=192.0.2.1, TLS")


def jail_list(status):
    """The jails `fail2ban-client status` lists, read from its one anchored line: matching
    the whole answer once read `dovecot-local present` as the jail."""
    for line in status.splitlines():
        match = re.match(r"^\s*`- Jail list:\s*(.*)$", line)
        if match:
            return [jail.strip() for jail in match.group(1).split(",") if jail.strip()]
    raise Unreadable("fail2ban-client status printed no jail list")


def judge_fail2ban(reading):
    if not reading["installed"]:
        return [Check("fail2ban", FAIL, "not installed",
                      "no ban mechanism: the mail ports must not be published")]
    if not reading["answers"]:
        return [Check("fail2ban", FAIL, "installed, not answering", "fail2ban is not running")]
    jails = jail_list(reading["status"])
    missing = [jail for jail in JAILS if jail not in jails]
    found = [passed("fail2ban", "answering")]
    reading_ = f"loaded: {', '.join(jails) or 'none'}"
    if missing:
        found.append(Check("jails", FAIL, reading_, f"not loaded: {', '.join(missing)}"))
    else:
        found.append(passed("jails", reading_))
    return found


@check("fail2ban")
def fail2ban(ctx):
    return judge_fail2ban(ctx.helper("system", "fail2ban"))


def matched(output):
    match = re.search(r"^Lines: \d+ lines, \d+ ignored, (\d+) matched", output, re.MULTILINE)
    if not match:
        raise Unreadable("fail2ban-regex printed no count of matched lines")
    return int(match.group(1))


@check("filter")
def ban_filter(ctx):
    """The filter matches a real line of the installed Dovecot and not a control."""
    if not os.path.exists(FILTER):
        return Check("filter", FAIL, f"{FILTER} absent", "fail2ban's Dovecot filter is not there")
    real = matched(probe.command(["fail2ban-regex", FAILURE_LINE, FILTER], check=True).stdout)
    control = matched(probe.command(["fail2ban-regex", CONTROL_LINE, FILTER], check=True).stdout)
    reading = f"a Dovecot 2.4 failure line: {real} matched; a login: {control} matched"
    if real != 1 or control != 0:
        return Check("filter", FAIL, reading, "the filter does not match what this Dovecot "
                                              "writes: the jail is blind")
    return passed("filter", reading)


# Step 19's chain, reached from ufw's input chain of each family (ansible/roles/publish).
LIMIT_CHAIN = "maildivvy-mail-limit"
BEFORE_INPUT = {"4": "ufw-before-input", "6": "ufw6-before-input"}
FAMILY = {"4": "IPv4", "6": "IPv6"}


def judge_rate_limits(families, published):
    """A per-source limit on each published mail port, in each family: a hashlimit rule in
    step 19's chain, and that chain reached from ufw's input."""
    if not published:
        return passed("rate limits", "the mail ports are not published: nothing to limit yet")
    problems, limited = [], []
    for family, name in FAMILY.items():
        rules = families.get(family, "")
        if not re.search(rf"^-A {BEFORE_INPUT[family]} .*-j {LIMIT_CHAIN}$", rules, re.MULTILINE):
            problems.append(f"{name}: nothing jumps from {BEFORE_INPUT[family]} to {LIMIT_CHAIN}")
            continue
        missing = [str(port) for port in MAIL_PORTS
                   if not re.search(rf"^-A {LIMIT_CHAIN} .*--dport {port} .*-m hashlimit .*-j DROP$",
                                    rules, re.MULTILINE)]
        if missing:
            problems.append(f"{name}: no per-source limit on {', '.join(missing)}")
        else:
            limited.append(name)
    reading = (f"limited per source on {', '.join(map(str, MAIL_PORTS))} over "
               f"{', '.join(limited) or 'no family'}")
    if problems:
        return Check("rate limits", FAIL, reading, "; ".join(problems))
    return passed("rate limits", reading)


@check("rate limits")
def rate_limits(ctx):
    return judge_rate_limits(ctx.helper("system", "firewall")["families"],
                             published(publication_record()))


BAN = [fail2ban, ban_filter, rate_limits]

WANTS = {"network": {"system": ["firewall", "containers"]},
         "ban": {"system": ["fail2ban", "firewall"]}}
