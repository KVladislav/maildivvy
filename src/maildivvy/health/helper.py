"""The readings `maildivvy-health` cannot take as its own user, and how it asks for them.

`maildivvy-health` runs as `maildivvy-health`: a read-only database role and the groups
`clamav`, `maildivvy-rspamd` and `systemd-journal`. Two sets of readings need more:

- **store**, as `vmail`: the mail store and the fetch state are the mail owner's, `0700`.
  The ledger's consistency check (`fanout/ledger.py`) and the link counts, the
  rendered mpop configurations, and a body search against an archive's
  index. The ledger is read through the pipeline's role in a read-only
  session, since it is the mail owner's own view of the ledger that is held to the store.
- **system**, as root: the firewall's rules (`0640 root`) and the kernel's ruleset, the
  container runtime, fail2ban's socket, the outbound queue (showq sits behind Postfix's
  `public/`, `postdrop`'s, and `postqueue`'s set-group-id is gone under
  `NoNewPrivileges`), and the milter's socket in Postfix's queue
  (`2750 maildivvy-milter:postfix`).

⛔ AN UNPRIVILEGED PROBE READS A PRIVILEGED PLACE AS EMPTY. A glob
over a `0700` directory stays literal and a bare `test -S` cannot cross a socket
directory: the predecessor's check read UNKNOWN on a healthy store and "missing" for sockets
that were listening. So each reading is taken with the privilege its place needs, by a
helper that systemd starts per connection on its own socket (`maildivvy-health-store.socket`,
`maildivvy-health-system.socket`, `0660 root:maildivvy-health`). It takes no argument but
the names of the readings asked for, from a closed list, and answers one JSON document
that ends `"complete": true`, so a helper cut short reads UNKNOWN, never empty.

A reading names what it read: paths, counts, versions. Never a credential and never a
message's content: the search reads a word out of a message to look for it and does not
hand the word back.
"""

import grp
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

from maildivvy.health.probe import Unreadable
from maildivvy.health.settings import STORE_SOCKET, SYSTEM_SOCKET

SOCKETS = {"store": STORE_SOCKET, "system": SYSTEM_SOCKET}
TIMEOUT = 900    # the ledger reads every mailbox of every domain
REQUEST_LIMIT = 4096
MILTER_SOCKET = Path("/var/spool/postfix/maildivvy/milter.sock")
RSPAMD_CONTAINER = "maildivvy-rspamd-1"   # <project>-<service>-<n>
UFW = Path("/etc/ufw")
SEARCH_CANDIDATES = 20
WORD = re.compile(r"\b[a-z]{6,24}\b")


# --- the client: maildivvy-health asking ---------------------------------------------------


def ask(name, readings, path=None, timeout=TIMEOUT):
    """{reading: answer} from one helper, or Unreadable."""
    path = Path(path or SOCKETS[name])
    request = json.dumps({"want": sorted(readings)}).encode() + b"\n"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(str(path))
            conn.sendall(request)
            conn.shutdown(socket.SHUT_WR)
            raw = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                raw += chunk
    except OSError as err:
        raise Unreadable(f"the {name} helper at {path} did not answer: {err}") from None
    try:
        answer = json.loads(raw)
    except ValueError:
        raise Unreadable(f"the {name} helper's answer was cut short ({len(raw)} bytes)") from None
    if not isinstance(answer, dict) or answer.get("complete") is not True \
            or not isinstance(answer.get("readings"), dict):
        raise Unreadable(f"the {name} helper's answer is not complete: {str(answer)[:200]}")
    return answer["readings"]


# --- the helper: one connection, one answer -----------------------------------------------------


def serve(name, readers, stdin=None, stdout=None):
    """Read the request, take each reading asked for, write one JSON answer."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    raw = stdin.readline(REQUEST_LIMIT)
    try:
        wanted = json.loads(raw)["want"]
        if not isinstance(wanted, list) or not all(w in readers for w in wanted):
            raise ValueError(wanted)
    except (ValueError, KeyError, TypeError):
        stdout.write(json.dumps({"error": f"the {name} helper reads only: "
                                          f"{', '.join(sorted(readers))}", "complete": False}))
        return 2
    readings = {}
    for reading in wanted:
        try:
            readings[reading] = readers[reading]()
        except Exception as err:  # one reading's failure is that reading's, and only its
            readings[reading] = {"error": " ".join(f"{type(err).__name__}: {err}".split())[:400]}
    stdout.write(json.dumps({"readings": readings, "complete": True}, default=str))
    stdout.flush()
    return 0


def run(argv, timeout=120):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, errors="replace")
    return done


# --- store readings, as vmail -------------------------------------------------------------------


def pipeline_connection():
    from maildivvy.lib import db
    conn = db.connect("pipeline")
    conn.set_session(readonly=True, autocommit=True)
    return conn


def read_ledger():
    """Per domain: the ledger's own check, the delivery rows it held the store to,
    and the archive's messages by how many names they have."""
    from maildivvy.fanout import ledger
    from maildivvy.lib import store

    conn = pipeline_connection()
    domains = {}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT label FROM domain ORDER BY label")
            labels = [row[0] for row in cur.fetchall()]
        for label in labels:
            with conn.cursor() as cur:
                cur.execute(ledger.MESSAGES, (label,))
                by_uid = ledger.by_folder_and_uid(cur.fetchall())
                cur.execute(ledger.DELIVERIES, (label,))
                deliveries = {(m, b) for m, b in cur.fetchall()}
                cur.execute(ledger.MAILBOXES, (label,))
                mailboxes = list(cur.fetchall())
            inodes = ledger.archive_inodes(label, by_uid)
            findings = ledger.unaccounted(inodes, mailboxes, deliveries, label)
            several = one = 0
            for folder in ledger.FOLDERS:
                box = store.maildir(store.archive_home(label), folder)
                for path in ledger.message_files(box):
                    try:
                        found = path.stat()
                    except OSError:
                        continue   # read while a person deleted: the next run reads it
                    if found.st_ino in inodes:
                        if found.st_nlink > 1:
                            several += 1
                        else:
                            one += 1
            domains[label] = {"deliveries": len(deliveries), "mailboxes": len(mailboxes),
                              "findings": [f.public() for f in findings],   # no path
                              "several_names": several, "one_name": one}
    finally:
        conn.close()
    return {"domains": domains}


def read_fetch_state():
    """Each rendered mpop configuration's `keep` lines. `listed` is the
    control that the directory was read at all."""
    from maildivvy.fetch import render

    root = render.DEFAULT_STATE_DIR
    configs = {}
    for child in sorted(root.iterdir()):   # raises for a directory that cannot be read
        if not child.name.isdigit() or not child.is_dir():
            continue
        path = child / "mpoprc"
        try:
            text = path.read_text()
        except FileNotFoundError:
            continue
        configs[child.name] = {"keep": [line.split()[1] for line in text.splitlines()
                                        if line.startswith("keep ") and len(line.split()) == 2]}
    return {"listed": True, "configs": configs}


def search_word(body):
    """A whole word of the body whose inner part is not itself a word of it, or None."""
    every = set(re.findall(r"[a-z0-9]+", body.lower()))
    for word in sorted(set(WORD.findall(body.lower()))):
        part = word[1:-1]
        if len(part) >= 4 and part not in every:
            return word, part
    return None


def read_search():
    """A word a message holds found by the index, and a part of it not."""
    from maildivvy.lib import doveadm, store

    conn = pipeline_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT d.label, m.archive_uid FROM message m JOIN domain d ON d.id = m.domain_id"
                        " WHERE m.state = 'delivered' AND m.archive_uid IS NOT NULL"
                        " ORDER BY m.id DESC LIMIT %s", (SEARCH_CANDIDATES,))
            candidates = cur.fetchall()
    finally:
        conn.close()
    for label, uid in candidates:
        login = f"{store.ARCHIVE}@{label}"
        try:
            records = doveadm.fetch(login, "INBOX", ["body"], "uid", str(int(uid)))
        except doveadm.DoveadmError:
            continue   # a message the archive no longer holds: the next candidate
        chosen = search_word(records[0].get("body", "")) if records else None
        if chosen is None:
            continue
        word, part = chosen
        try:
            whole = doveadm.run(("search",), login, "mailbox", "INBOX", "body", word)
            partial = doveadm.run(("search",), login, "mailbox", "INBOX", "body", part)
        except doveadm.DoveadmError as err:
            return {"domain": label, "uid": int(uid), "error": str(err)}
        return {"domain": label, "uid": int(uid),
                "whole": any(int(r.get("uid", 0)) == int(uid) for r in whole),
                "part": any(int(r.get("uid", 0)) == int(uid) for r in partial)}
    return {"domain": None}


STORE_READERS = {"ledger": read_ledger, "fetch_state": read_fetch_state, "search": read_search}


# --- system readings, as root -------------------------------------------------------------------


def read_milter():
    """The socket's kind, group and mode, and a negotiation in the milter's own protocol."""
    from maildivvy.milter import probe as milter_probe

    reading = {"path": str(MILTER_SOCKET)}
    try:
        found = os.lstat(MILTER_SOCKET)
    except FileNotFoundError:
        reading["socket"] = {"exists": False}
    else:
        reading["socket"] = {"exists": True,
                             "kind": "socket" if stat.S_ISSOCK(found.st_mode) else "not a socket",
                             "group": grp.getgrgid(found.st_gid).gr_name,
                             "mode": f"{stat.S_IMODE(found.st_mode):04o}"}
    try:
        reading["negotiation"] = {"version": milter_probe.negotiate(MILTER_SOCKET).version}
    except milter_probe.NoAnswer as err:
        reading["negotiation"] = {"error": str(err)}
    return reading


def docker(*argv):
    done = run(["docker", *argv])
    if done.returncode != 0:
        raise RuntimeError(f"docker {argv[0]} exited {done.returncode}: {done.stderr.strip()[:200]}")
    return done.stdout


def published(inspected):
    """Every host port a container publishes, from both places the runtime records one."""
    ports = []
    for port, bindings in (inspected.get("NetworkSettings", {}).get("Ports") or {}).items():
        for binding in bindings or []:
            ports.append(f"{binding.get('HostIp') or '*'}:{binding.get('HostPort')}->{port}")
    for port, bindings in (inspected.get("HostConfig", {}).get("PortBindings") or {}).items():
        for binding in bindings or []:
            ports.append(f"{binding.get('HostIp') or '*'}:{binding.get('HostPort')}->{port}")
    return sorted(set(ports))


def read_containers():
    names = docker("ps", "--all", "--format", "{{.Names}}").split()
    found = []
    for name in names:
        inspected = json.loads(docker("inspect", name))[0]
        found.append({"name": name, "network_mode": inspected["HostConfig"].get("NetworkMode"),
                      "published": published(inspected)})
    return found


def read_rspamd():
    inspected = json.loads(docker("inspect", RSPAMD_CONTAINER))[0]
    container = {"name": RSPAMD_CONTAINER, "running": bool(inspected["State"].get("Running")),
                 "started_at": inspected["State"].get("StartedAt"),
                 "restarts": inspected.get("RestartCount", 0)}
    modules = docker("exec", RSPAMD_CONTAINER, "rspamadm", "configdump", "-m") \
        if container["running"] else ""
    return {"container": container, "modules": modules}


def input_policies(families):
    """{family: the INPUT chain's policy}, each read from its own family's rules: read from
    both run together, IPv6's was never seen."""
    found = {}
    for family, rules in families.items():
        policy = re.search(r"^-P INPUT (\w+)$", rules, re.MULTILINE)
        found[family] = policy.group(1) if policy else ""
    return found


def read_firewall():
    """ufw's own settings and rule records, and the kernel's ruleset as it stands."""
    conf = (UFW / "ufw.conf").read_text()
    enabled = re.search(r"^ENABLED=(\w+)", conf, re.MULTILINE)
    families = {}
    for family, tool in (("4", "iptables"), ("6", "ip6tables")):
        done = run([tool, "-S"])
        if done.returncode != 0:
            raise RuntimeError(f"{tool} -S exited {done.returncode}: {done.stderr.strip()[:200]}")
        families[family] = done.stdout
    rules = families["4"] + families["6"]
    block = "\n".join(line for line in rules.splitlines()
                      if line.startswith(("-A DOCKER-USER", "-A maildivvy-docker")))
    return {"enabled": enabled.group(1) if enabled else "",
            "input_policy": input_policies(families),
            "user_rules": (UFW / "user.rules").read_text() + (UFW / "user6.rules").read_text(),
            "docker_block": block, "families": families}


def read_fail2ban():
    if shutil.which("fail2ban-client") is None:
        return {"installed": False}
    ping = run(["fail2ban-client", "ping"], timeout=30)
    if ping.returncode != 0 or "pong" not in ping.stdout:
        return {"installed": True, "answers": False}
    status = run(["fail2ban-client", "status"], timeout=30)
    return {"installed": True, "answers": True, "status": status.stdout}


def read_queue():
    """The outbound queue as `postqueue -j` lists it, one JSON line per message."""
    done = run(["postqueue", "-j"], timeout=60)
    if done.returncode != 0:
        raise RuntimeError(f"postqueue -j exited {done.returncode}: {done.stderr.strip()[:200]}")
    return {"lines": [line for line in done.stdout.splitlines() if line.strip()]}


SYSTEM_READERS = {"milter": read_milter, "containers": read_containers, "rspamd": read_rspamd,
                  "firewall": read_firewall, "fail2ban": read_fail2ban, "queue": read_queue}
READERS = {"store": STORE_READERS, "system": SYSTEM_READERS}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] not in READERS:
        sys.stderr.write(f"usage: maildivvy-health-helper {{{'|'.join(READERS)}}}\n")
        return 64
    return serve(argv[0], READERS[argv[0]])
