"""The readings `maildivvy-health` cannot take as its own user, and how it asks for them.

`maildivvy-health` runs as `maildivvy-health`: a read-only database role and the groups
`clamav`, `maildivvy-rspamd` and `systemd-journal`. Two sets of readings need more:

- **store**, as `vmail`: the mail store and the fetch state are the mail owner's, `0700`.
  The ledger's consistency check (`fanout/ledger.py`): every five minutes over
  the names changed since the last scan, and once a day over every name with the link
  counts and each archive's listing held to its rows; the rendered mpop
  configurations, and a body search against an archive's index.
  The ledger is read through the pipeline's
  role in a read-only session, since it is the mail owner's own view of the ledger that
  is held to the store.
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
The one exception is the ledger's window, which is given where the last
scan ended: numbers, checked here, which choose only the names a reading health
makes of itself covers. A wrong one narrows it, or widens it: `since` 0 reads every name
in the store, as the daily pass does, and is bounded by DEADLINE as any reading is.

A reading names what it read: paths, counts, versions. Never a credential and never a
message's content: the search reads a word out of a message to look for it and does not
hand the word back.
"""

import contextlib
import grp
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

from maildivvy.health.probe import Unreadable
from maildivvy.health.settings import STORE_SOCKET, SYSTEM_SOCKET

SOCKETS = {"store": STORE_SOCKET, "system": SYSTEM_SOCKET}
# ⛔ A SLOW READING IS ITS OWN UNKNOWN, NEVER A REPORT LOST. A five-minute run is
# bounded by its unit, `maildivvy_health_run_timeout` (900 s), and asks the store helper,
# then the system helper, each serving its readings one after another. Each reading has
# DEADLINE, the readings of one answer BUDGET together, and the client waits a minute
# longer than the helper's budget: a reading cut off answers its error in an answer still
# whole, and the run writes its report before its unit would kill it.
DEADLINE = 300
BUDGET = {"store": 420, "system": 180}
# The daily pass reads every name of every mailbox. The role bounds its units by
# `maildivvy_health_ledger_timeout`, many times what a year's volume took; the
# reading stops five minutes under it, so the pass's result is kept, as its error.
LEDGER_PASS_TIMEOUT = 3600
DEADLINES = {"ledger_pass": LEDGER_PASS_TIMEOUT - 300}
LEDGER_PASS_WAIT = DEADLINES["ledger_pass"] + 60
REQUEST_LIMIT = 16384
MILTER_SOCKET = Path("/var/spool/postfix/maildivvy/milter.sock")
RSPAMD_CONTAINER = "maildivvy-rspamd-1"   # <project>-<service>-<n>
UFW = Path("/etc/ufw")
SEARCH_CANDIDATES = 20
WORD = re.compile(r"\b[a-z]{6,24}\b")


# --- the client: maildivvy-health asking ---------------------------------------------------


def waited(name):
    """How long the client waits for one helper's answer to a five-minute run."""
    return BUDGET[name] + 60


def ask(name, readings, path=None, timeout=None, given=None):
    """{reading: answer} from one helper, or Unreadable. `given` is {reading: argument}
    for a reading that takes one."""
    timeout = timeout or waited(name)
    path = Path(path or SOCKETS[name])
    request = {"want": sorted(readings)}
    if given:
        request["given"] = given
    request = json.dumps(request).encode() + b"\n"
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


class Overran(BaseException):
    """A reading past its deadline. Not an Exception: a reading's own `except Exception`
    must not take it for one of its errors and go on."""


@contextlib.contextmanager
def deadline(seconds):
    """Raise Overran in the reading once `seconds` have passed. A child it runs through
    `subprocess.run` is killed as the exception passes. Only the main thread receives
    signals: elsewhere (a test serving from a thread) the reading is not bounded."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def overran(*_):
        raise Overran()

    previous = signal.signal(signal.SIGALRM, overran)
    signal.setitimer(signal.ITIMER_REAL, max(seconds, 0.001))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def serve(name, readers, stdin=None, stdout=None):
    """Read the request, take each reading asked for, write one JSON answer."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    raw = stdin.readline(REQUEST_LIMIT)
    try:
        request = json.loads(raw)
        wanted, given = request["want"], request.get("given", {})
        if not isinstance(wanted, list) or not all(w in readers for w in wanted):
            raise ValueError(wanted)
        if not isinstance(given, dict) or not all(g in wanted and g in TAKES for g in given):
            raise ValueError(given)
    except (ValueError, KeyError, TypeError, AttributeError):
        stdout.write(json.dumps({"error": f"the {name} helper reads only: "
                                          f"{', '.join(sorted(readers))}", "complete": False}))
        return 2
    readings = {}
    started = time.monotonic()
    budget = max([BUDGET.get(name, DEADLINE)] + [DEADLINES[w] for w in wanted if w in DEADLINES])
    for reading in wanted:
        left = budget - (time.monotonic() - started)
        if left < 1:
            readings[reading] = {"error": f"not read: the readings before it took the "
                                          f"helper's {budget} s"}
            continue
        bound = min(DEADLINES.get(reading, DEADLINE), left)
        try:
            with deadline(bound):
                readings[reading] = readers[reading](given[reading]) if reading in given \
                    else readers[reading]()
        except Overran:
            readings[reading] = {"error": f"not read in {bound:.0f} s"}
        except Exception as err:  # noqa: BLE001 - one reading's failure is that reading's, and only its
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


# ⛔ One moment for a domain's cursors and its rows (`fanout/ledger.py`, `under_cursor`): the
# session commits each statement on its own, so the pass's reading of them is a
# transaction of its own, on one snapshot.
ONE_MOMENT = "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"


# One mailbox's rows at a time: a domain's every row held at once is millions
# of pairs for an archive given to ten people, over a gigabyte in this helper.
DELIVERY_COUNT = "SELECT count(*) FROM ({}) rows"   # of ledger.DELIVERIES
ROWS_OF_MAILBOX = "SELECT message_id FROM delivery WHERE mailbox_id = %s"

# The requests that make names in people's mailboxes and their rows, running for
# a domain: the mailbox's or the message's named in the payload. One whose domain cannot be
# read from it is taken for every domain's.
LINKING_KINDS = ["top_up", "connect", "transfer", "deliver_one", "release"]
LINKING = """
    SELECT r.id, d.label FROM request r
      LEFT JOIN mailbox mb ON mb.id = CASE WHEN r.payload ->> 'mailbox_id' ~ '^[0-9]{1,18}$'
                                           THEN (r.payload ->> 'mailbox_id')::bigint END
      LEFT JOIN message m ON m.id = CASE WHEN r.payload ->> 'message_id' ~ '^[0-9]{1,18}$'
                                         THEN (r.payload ->> 'message_id')::bigint END
      LEFT JOIN domain d ON d.id = coalesce(mb.domain_id, m.domain_id)
     WHERE r.state = 'running' AND r.kind = ANY(%s)
     ORDER BY r.id
"""
# Of the findings (message, mailbox), those whose mailbox is still there and still has no row.
STILL_UNACCOUNTED = """
    SELECT f.message_id, f.mailbox_id
      FROM unnest(%s::bigint[], %s::bigint[]) AS f (message_id, mailbox_id)
     WHERE EXISTS (SELECT 1 FROM mailbox mb WHERE mb.id = f.mailbox_id)
       AND NOT EXISTS (SELECT 1 FROM delivery dl
                        WHERE dl.message_id = f.message_id AND dl.mailbox_id = f.mailbox_id)
"""
# How long the daily pass waits, in all, for a linking request to commit the names it
# found with no row, read again every CONFIRM_POLL seconds.
CONFIRM_WAIT = 900
CONFIRM_POLL = 30


def linking(cur, label):
    """The ids of the linking requests running for this domain."""
    cur.execute(LINKING, (LINKING_KINDS,))
    return [request_id for request_id, of in cur.fetchall() if of is None or of == label]


def confirm(conn, label, findings):
    """(the findings still with no row, the linking requests running for the domain).

    ⛔ A NAME IS MADE BEFORE ITS ROW IS COMMITTED. A top-up or a connect commits
    a batch at a time, a transfer, a deliver-one and a release once at their end,
    and every name made since reads as one with no row. So a finding is read again: the
    requests running FIRST, then the rows, and one whose row was committed meanwhile, or
    whose mailbox is gone (a deletion commits its rows before it removes the files), is
    no finding. While no linking request runs, those left are."""
    with conn.cursor() as cur:
        running = linking(cur, label)
        if findings:
            cur.execute(STILL_UNACCOUNTED, ([f.message_id for f in findings],
                                            [f.mailbox_id for f in findings]))
            left = set(cur.fetchall())
            findings = [f for f in findings if (f.message_id, f.mailbox_id) in left]
    return findings, running


def read_ledger_pass(root=None):
    """The daily pass, per domain: the ledger's own check over every name, the
    delivery rows it held the store to, the archive's messages by how many names
    they have, and those at or below the pass's cursors that no row
    holds, from the one listing of the archive the check takes.

    A domain whose names with no row a linking request may still be committing is read
    again until it ends or CONFIRM_WAIT is spent; then its reading says `linking` and
    lists none of them."""
    from maildivvy.fanout import ledger
    from maildivvy.lib import store

    root = root or store.STORE_ROOT
    conn = pipeline_connection()
    domains, pending = {}, {}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT label FROM domain ORDER BY label")
            labels = [row[0] for row in cur.fetchall()]
        for label in labels:
            with conn.cursor() as cur:
                cur.execute(ONE_MOMENT)
                cur.execute(ledger.CURSORS, (label,))
                cursors = {folder: (last_uid, kept, base) for folder, last_uid, kept, base
                           in cur.fetchall()}
                cur.execute(ledger.MESSAGES, (label,))
                bases = ledger.by_base(cur.fetchall())
                cur.execute(DELIVERY_COUNT.format(ledger.DELIVERIES), (label,))
                deliveries = cur.fetchone()[0]
                cur.execute(ledger.MAILBOXES, (label,))
                mailboxes = list(cur.fetchall())
                cur.execute("COMMIT")
            listing = ledger.archive_listing(label, root)   # ⛔ after the rows, never before
            inodes = ledger.archive_inodes(label, bases, root, listing=listing)
            under = ledger.under_cursor(label, listing, bases, cursors)
            del listing, bases   # the archive's size each: what is held from here is its inodes
            findings = []
            for mailbox_id, account in mailboxes:
                # this mailbox's rows, read before its names as the domain's were
                with conn.cursor() as cur:
                    cur.execute(ROWS_OF_MAILBOX, (mailbox_id,))
                    held = {message_id for (message_id,) in cur}
                findings += ledger.unaccounted_in(inodes, mailbox_id, account, held.__contains__,
                                                  label, root)
                del held
            several = one = 0
            for folder in ledger.FOLDERS:
                box = store.maildir(store.archive_home(label, root), folder)
                for path in store.message_files(box):
                    try:
                        found = path.stat()
                    except OSError:
                        continue   # read while a person deleted: the next run reads it
                    if found.st_ino in inodes:
                        if found.st_nlink > 1:
                            several += 1
                        else:
                            one += 1
            del inodes
            if findings:
                findings, running = confirm(conn, label, findings)
                if findings and running:
                    pending[label] = findings
            domains[label] = {"deliveries": deliveries, "mailboxes": len(mailboxes),
                              "findings": [f.public() for f in findings],   # no path
                              "several_names": several, "one_name": one,
                              "under_cursor": under.read,
                              "unrecorded": [u._asdict() for u in under.unrecorded],
                              "renumbered": under.renumbered}
        deadline = time.monotonic() + CONFIRM_WAIT
        while pending:
            time.sleep(CONFIRM_POLL)
            for label in list(pending):
                findings, running = confirm(conn, label, pending[label])
                if findings and running and time.monotonic() < deadline:
                    pending[label] = findings
                    continue
                del pending[label]
                domains[label]["findings"] = [] if running else [f.public() for f in findings]
                if findings and running:
                    domains[label]["linking"] = {"requests": running, "names": len(findings)}
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


def window_mark(given):
    """(since, newest delivery row, carried) from what health kept of the last scan, each
    checked: the helper is given numbers, never a path."""
    if given is None:
        return None, 0, []
    since, newest, carried = given["since"], given["delivery"], given["carried"]
    if not isinstance(since, (int, float)) or isinstance(since, bool) or since < 0:
        raise ValueError(f"since {since!r} is not a time")
    if not isinstance(newest, int) or isinstance(newest, bool) or newest < 0:
        raise ValueError(f"delivery {newest!r} is not a row id")
    from maildivvy.fanout import ledger

    if not isinstance(carried, list) or len(carried) > ledger.CARRIED or not all(
            isinstance(c, list) and len(c) == 3
            and all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in c)
            for c in carried):
        raise ValueError("carried is not a list of [mailbox, message, inode]")
    return float(since), newest, [tuple(c) for c in carried]


def read_ledger(given=None):
    """The five-minute window: the ledger's check over the names changed since the
    last scan, and the findings it carried still held; with the delivery rows added since,
    and what the next scan is given. With no last scan, nothing is read: the window starts
    now, and what came before is the daily pass's."""
    from maildivvy.fanout import ledger

    started = time.time()
    since, newest_before, carried = window_mark(given)
    conn = pipeline_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT coalesce(max(id), 0) FROM delivery")
            newest = cur.fetchone()[0]
            reading = {"since": since, "deliveries": newest, "added": 0, "checked": 0,
                       "findings": [], "linking": {}}
            carry, carry_linking = [], []
            if since is not None:
                cur.execute("SELECT count(*) FROM delivery WHERE id > %s", (newest_before,))
                reading["added"] = cur.fetchone()[0]
                cur.execute("SELECT label FROM domain ORDER BY label")
                for (label,) in cur.fetchall():
                    found = ledger.window(cur, label, since - ledger.SLACK, carried)
                    reading["checked"] += found.checked
                    findings, running = confirm(conn, label, found.findings)
                    if findings and running:
                        # a request still linking there: its names are read again by
                        # the next scan, after the other domains' findings
                        reading["linking"][label] = {"requests": running, "names": len(findings)}
                        carry_linking += found.carry
                        continue
                    reading["findings"] += [f.public() for f in findings]   # no path
                    kept = {(f.mailbox_id, f.message_id) for f in findings}
                    carry += [c for c in found.carry if (c[0], c[1]) in kept]
    finally:
        conn.close()
    carry += carry_linking
    reading["next"] = {"since": started, "delivery": newest, "carried": carry[:ledger.CARRIED]}
    return reading


# The rows that hold a directory, and the deletions that still list theirs.
HOLDERS = """
    SELECT d.label, a.login FROM mailbox m JOIN account a ON a.id = m.account_id
      JOIN domain d ON d.id = m.domain_id
"""
DELETING = """
    SELECT id, state, payload -> 'gone' FROM request
     WHERE payload ? 'gone' AND state IN ('running', 'failed') ORDER BY id
"""


def read_directories():
    """Every `<domain>/<name>` directory of the store and both index trees, and those no
    row holds. The rows are read FIRST: a deletion that finishes
    between the two readings has its directories gone by the listing, and one still
    running is skipped by what it lists; a domain with no directory under it is one
    entry with no name. The store's `_snapshots` and `_imports` are no domain and are not
    read: the snapshots of IMAP mailboxes live in one, the import's staging files
    in the other, and a domain's label admits no `_`."""
    from maildivvy.lib import store

    conn = pipeline_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT label FROM domain")
            domains = {row[0] for row in cur.fetchall()}
            cur.execute(HOLDERS)
            held = {(label, login) for label, login in cur.fetchall()}
            held |= {(label, store.ARCHIVE) for label in domains}
            cur.execute(DELETING)
            deleting = cur.fetchall()
    finally:
        conn.close()
    running, waiting = set(), {}
    for request_id, state, gone in deleting:
        for label, account in (json.loads(gone) if isinstance(gone, str) else gone):
            if state == "running":
                running.add((label, account))
            else:
                waiting[(label, account)] = request_id
    listed, stray, left = 0, [], []
    for root in (store.STORE_ROOT, store.INDEX_ROOT / "idx", store.INDEX_ROOT / "ctl"):
        # Dovecot makes an index tree at its first open of a mailbox, so a fresh machine
        # has none yet; the store itself is the install's and must be there
        if root != store.STORE_ROOT and not root.exists():
            continue
        for domain in sorted(root.iterdir()):   # raises for a root that cannot be read
            if not domain.is_dir() or domain.name == "lost+found" or (
                    root == store.STORE_ROOT and domain.name in store.NOT_DOMAINS):
                continue
            names = [child.name for child in sorted(domain.iterdir()) if child.is_dir()]
            for name in names or [None]:
                listed += 1
                slot = (domain.name, name)
                if (name is None and domain.name in domains) or slot in held:
                    continue
                path = str(domain / name) if name else str(domain)
                if slot in running or (domain.name, None) in running:
                    continue
                request_id = waiting.get(slot, waiting.get((domain.name, None)))
                if request_id is not None:
                    left.append({"path": path, "request": request_id})
                else:
                    stray.append(path)
    return {"listed": listed, "domains": len(domains), "held": listed - len(stray) - len(left),
            "stray": stray, "left": left}


STORE_READERS = {"ledger": read_ledger, "ledger_pass": read_ledger_pass,
                 "fetch_state": read_fetch_state, "search": read_search,
                 "directories": read_directories}
# The readings that take an argument (`given`).
TAKES = {"ledger"}


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
