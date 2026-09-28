#!/usr/bin/python3
"""maildivvy-ban: prove the login-failure ban on the running jails (install step 18).

    maildivvy-ban prove --maxretry N --ignore NET [--ignore NET ...]

Installed by step 18 (ansible/roles/ban) as /usr/local/sbin/maildivvy-ban. The mail ports
are published only after this proof passes; if it fails, the step closes them and
the install stops. It prints one JSON report and says what it proved for each jail, the
four halves separately, because `attempt` bypasses the filter and the log:

- daemon: the jail is loaded in the running daemon, reads the journal (the backend read
  back from the daemon, never from the file), its `ignoreip` names loopback
  and every administrator network and nothing wider, and
  `maxretry` is the one written;
- filter: a real failed login made here, on this machine, is written by the installed server
  and read out of its journal; `fail2ban-regex` matches it once, and matches nothing in a
  real line of the same server that is not a failure;
- source: the live jail read that failure: it logs that it ignored the source (this
  machine's own address, `ignoreself`) for it;
- counter and action: `maxretry - 1` failures reported with `attempt` for a documentation
  address do not ban it; one more does, and the address is then counted in the jail's
  nftables set with a reject rule on it; the unban removes it.

The address is drawn from TEST-NET-1, a new one per jail and per run: failures reported
for an address stay counted for `findtime` even across a ban and an unban (measured
2026-09-23), so a run cut short must not leave a count the next run would trip over.
Nothing banned here is ever this machine's own address or an administrator network.

⚠️ Dovecot delays its answer to an address that has just failed (its auth penalty, read by
`doveadm penalty`), and Postfix gives up on its SASL answer after about ten seconds: a
Postfix failure right after two IMAP failures from the same address was logged as
`Connection lost to authentication server`, which the filter rightly ignores. So the
Postfix jail's filter is proved first, from this machine's own non-loopback address once
Dovecot holds no penalty for it, while the IMAP failures - and health's, every five
minutes - come from 127.0.0.1.

- guesser (the postfix jail): a real guesser on 465 meets that delay after two failures,
  and three of every five of its failures are then lost to the jail. So the same
  source, now under the penalty, keeps failing until the live jail has read `maxretry` of
  its failures; if it cannot within `4 * maxretry` attempts, a guesser would never be
  banned. The report says whether the delay was met.
"""

import argparse
import ast
import imaplib
import ipaddress
import json
import random
import re
import secrets
import smtplib
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

PROOF_NETWORK = ipaddress.ip_network("192.0.2.0/24")   # TEST-NET-1, RFC 5737
TABLE = ("inet", "f2b-table")
CHAIN = "f2b-chain"
MARKER_DOMAIN = "ban-proof.invalid"
SETTLE = 3          # seconds for the jail to act on what it was told
RETRY = 3           # seconds before a temporary refusal is asked again
WAIT = 30           # seconds for a ban, an unban or a log line to appear
CLEAN = 120         # seconds Dovecot's penalty for the proof's own address may take to lapse
GUESSES = 4         # a guesser's attempts, per `maxretry`, before it counts as never banned


class ProofError(Exception):
    """A reading the proof cannot take; the message says which."""


# --- readings (pure) -------------------------------------------------------------------------------


def jail_list(status):
    """The jails `fail2ban-client status` names, from its one anchored line."""
    for line in status.splitlines():
        match = re.match(r"^\s*`- Jail list:\s*(.*)$", line)
        if match:
            return [jail.strip() for jail in match.group(1).split(",") if jail.strip()]
    raise ProofError("fail2ban-client status printed no jail list")


def networks(values):
    return {ipaddress.ip_network(value, strict=False) for value in values}


def ignore_list(output):
    """`fail2ban-client get <jail> ignoreip`: one network per `|-` or `` `- `` line."""
    found = set()
    for line in output.splitlines():
        match = re.match(r"^\s*[|`]- (\S+)\s*$", line)
        if match:
            found.add(ipaddress.ip_network(match.group(1), strict=False))
    return found


def missing_ignores(found, wanted):
    """Every wanted network no ignored network covers, as text."""
    return sorted(str(net) for net in wanted
                  if not any(net.version == have.version and net.subnet_of(have) for have in found))


def extra_ignores(found, wanted):
    """Every ignored network no wanted network covers, as text: an exemption beyond loopback
    and the administrator networks, whose sources are never banned."""
    return sorted(str(have) for have in found
                  if not any(have.version == net.version and have.subnet_of(net) for net in wanted))


# as preflight's (ansible/library/maildivvy_preflight.py): wider than this a network must be
# private, and none is wider than the widest private range
WIDEST_PUBLIC = {4: 16, 6: 48}
WIDEST = {4: 8, 6: 7}


def too_wide(net):
    return net.prefixlen < WIDEST[net.version] or (
        net.prefixlen < WIDEST_PUBLIC[net.version] and not net.is_private)


def backends(dump):
    """{jail: backend} from `fail2ban-client -d`, the configuration the daemon was given."""
    found = {}
    for line in dump.splitlines():
        if line.startswith("['add',"):
            command = ast.literal_eval(line)
            found[command[1]] = command[2]
    return found


def regex_matched(output):
    match = re.search(r"^Lines: \d+ lines, \d+ ignored, (\d+) matched", output, re.MULTILINE)
    if not match:
        raise ProofError(f"fail2ban-regex printed no count of matched lines: {output.strip()[-200:]}")
    return int(match.group(1))


def set_elements(listed):
    """The addresses in a set, from `nft -j list set`."""
    for item in listed.get("nftables", []):
        if "set" in item:
            elements = item["set"].get("elem", [])
            return {elements} if isinstance(elements, str) else {str(e) for e in elements}
    return set()


def rejects(listed, set_name):
    """Whether the chain, from `nft -j list chain`, rejects every source in the set."""
    for item in listed.get("nftables", []):
        expr = item.get("rule", {}).get("expr", [])
        matches_set = any(e.get("match", {}).get("right") == f"@{set_name}" for e in expr)
        if matches_set and any("reject" in e or "drop" in e for e in expr):
            return True
    return False


def proof_address(rng, taken):
    """A documentation address not yet used: nobody's, and never an administrator's."""
    hosts = [str(h) for h in PROOF_NETWORK.hosts() if str(h) not in taken]
    return rng.choice(hosts)


def ignored_lines(log, jail, address):
    """How many times the live jail logged that it ignored `address`: it read a failure from it."""
    return len(re.findall(rf"\[{re.escape(jail)}\] Ignore {re.escape(address)} ", log))


def temporary(answer):
    """Whether a refusal was the server's temporary one - IMAP `[UNAVAILABLE]`, SMTP 454 -
    rather than the failed login the proof needs. After PostgreSQL restarts, Dovecot's first
    lookup answers so while its pool reconnects, and logs `temp_fail`, which is no
    failure to the filter."""
    if isinstance(answer, int):
        return answer == 454
    return b"[UNAVAILABLE]" in answer


def penalty(listing, address):
    """Dovecot's auth penalty for `address` from `doveadm penalty`, 0 when it is not listed."""
    for line in listing.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[0] == address and fields[1].isdigit():
            return int(fields[1])
    return 0


def line_with(lines, needle):
    for line in reversed(lines):
        if needle in line:
            return line
    raise ProofError(f"no journal line with {needle!r}: the server did not log it")


# --- the two servers' real lines --------------------------------------------------------------------


def loose_tls():
    """Loopback to this machine's own listener: the proof is about the log, not the certificate."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def own_address():
    """The address this machine reaches others from (a UDP connect sends nothing)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]


def imap_failures(marker, address):
    """A failed LOGIN ended by LOGOUT, then one ended by closing: Dovecot 2.4.2 writes them as
    `Logged out (auth failed, …)` and `Connection closed (auth failed, …)`. Then a session that logs out without a login: the control."""
    for suffix, close in (("a", "logout"), ("b", "shutdown")):
        for attempt in (1, 2):
            client = imaplib.IMAP4_SSL(address, 993, ssl_context=loose_tls(), timeout=60)
            try:
                client.login(f"{marker}-{suffix}@{MARKER_DOMAIN}", secrets.token_hex(8))
            except imaplib.IMAP4.error as err:
                refusal = err.args[0] if err.args and isinstance(err.args[0], bytes) else b""
            else:
                raise ProofError("Dovecot accepted a login that cannot exist")
            client.logout() if close == "logout" else client.shutdown()
            if not temporary(refusal):
                break
            time.sleep(RETRY)
    imaplib.IMAP4_SSL(address, 993, ssl_context=loose_tls(), timeout=60).logout()


def smtp_failures(marker, address):
    """A refused AUTH PLAIN, then, as the control, the refusal at RCPT TO that the outside
    probe itself meets: the jail must not count the probe."""
    for attempt in (1, 2):
        client = smtplib.SMTP_SSL(address, 465, context=loose_tls(), timeout=60)
        client.ehlo(MARKER_DOMAIN)
        try:
            client.auth("PLAIN", lambda challenge=None: f"\0{marker}@{MARKER_DOMAIN}\0{secrets.token_hex(8)}")
        except smtplib.SMTPAuthenticationError as err:
            code = err.smtp_code
        else:
            raise ProofError("Postfix accepted a login that cannot exist")
        client.quit()
        if not temporary(code):
            break
        time.sleep(RETRY)
    client = smtplib.SMTP_SSL(address, 465, context=loose_tls(), timeout=60)
    client.ehlo(MARKER_DOMAIN)
    client.mail(f"{marker}@{MARKER_DOMAIN}")
    code, _ = client.rcpt("postmaster@example.org")
    client.quit()
    if code < 500:
        raise ProofError(f"Postfix answered an unauthenticated RCPT TO with {code}")


def smtp_guess(marker, address):
    """One refused AUTH PLAIN, as a guesser makes it: the code it was answered with - 535 for a
    failure, 454 when Postfix lost Dovecot's delayed answer - or None if the session ended."""
    client = smtplib.SMTP_SSL(address, 465, context=loose_tls(), timeout=60)
    try:
        client.ehlo(MARKER_DOMAIN)
        client.auth("PLAIN", lambda challenge=None: f"\0{marker}@{MARKER_DOMAIN}\0{secrets.token_hex(8)}")
    except smtplib.SMTPAuthenticationError as err:
        return err.smtp_code
    except smtplib.SMTPServerDisconnected:
        return None
    else:
        raise ProofError("Postfix accepted a login that cannot exist")
    finally:
        try:
            client.quit()
        except (smtplib.SMTPException, OSError):
            pass


@dataclass
class Jail:
    name: str
    filter: str
    unit: str
    source: object      # the address the failures come from
    provoke: object
    failures: tuple     # the needles of the failure lines, given the marker
    control: object     # the needle of the control line, given the marker
    guesser: bool = False   # also proved for a source under Dovecot's delay


JAILS = [
    Jail("postfix", "/etc/fail2ban/filter.d/postfix.conf[mode=auth]", "postfix.service", own_address,
         smtp_failures, failures=(lambda m: f"sasl_username={m}@{MARKER_DOMAIN}",),
         control=lambda m: f"from=<{m}@{MARKER_DOMAIN}>", guesser=True),
    Jail("dovecot", "/etc/fail2ban/filter.d/dovecot.conf", "dovecot.service", lambda: "127.0.0.1",
         imap_failures,
         failures=(lambda m: f"user=<{m}-a@{MARKER_DOMAIN}>", lambda m: f"user=<{m}-b@{MARKER_DOMAIN}>"),
         control=lambda m: "(no auth attempts in "),
]


# --- the machine -----------------------------------------------------------------------------------


def run(argv, check=True):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if check and done.returncode != 0:
        raise ProofError(f"{' '.join(argv[:4])} exited {done.returncode}: {done.stderr.strip()[-300:]}")
    return done.stdout


def f2b(*args):
    return run(["fail2ban-client", *args])


def nft_set(jail):
    done = subprocess.run(["nft", "-j", "list", "set", *TABLE, f"addr-set-{jail}"],
                          capture_output=True, text=True, timeout=60)
    return set_elements(json.loads(done.stdout)) if done.returncode == 0 else set()


def nft_rejects(jail):
    done = subprocess.run(["nft", "-j", "list", "chain", *TABLE, CHAIN], capture_output=True, text=True,
                          timeout=60)
    return done.returncode == 0 and rejects(json.loads(done.stdout), f"addr-set-{jail}")


def banned(jail):
    return set(f2b("get", jail, "banip").split())


def until(predicate, seconds=WAIT):
    deadline = time.monotonic() + seconds
    while True:
        if predicate():
            return True
        if time.monotonic() > deadline:
            return False
        time.sleep(0.5)


def log_target():
    target = f2b("get", "logtarget").strip().splitlines()[-1].split()[-1]
    if not target.startswith("/"):
        raise ProofError(f"fail2ban logs to {target}, not a file this proof can read")
    return Path(target)


def journal(unit, since):
    return run(["journalctl", "-u", unit, "--since", f"@{since:.0f}", "-o", "short-iso",
                "--no-pager", "-q"]).splitlines()


def regex(line, filter_):
    return regex_matched(run(["fail2ban-regex", line, filter_]))


def prove_daemon(jail, loaded, dump, wanted_ignores, maxretry):
    problems = []
    if jail.name not in loaded:
        return {"loaded": False}, [f"{jail.name}: not loaded in the running daemon"]
    backend = backends(dump).get(jail.name)
    if backend != "systemd":
        problems.append(f"{jail.name}: reads {backend!r}, not the journal (systemd)")
    ignored = ignore_list(f2b("get", jail.name, "ignoreip"))
    missing = missing_ignores(ignored, wanted_ignores)
    if missing:
        problems.append(f"{jail.name}: ignoreip lacks {', '.join(missing)}: its bans would cut it off")
    extra = extra_ignores(ignored, wanted_ignores)
    if extra:
        problems.append(f"{jail.name}: ignoreip also exempts {', '.join(extra)}, which is no administrator "
                        "network: its sources are never banned")
    wide = sorted(str(net) for net in wanted_ignores if too_wide(net))
    if wide:
        problems.append(f"{jail.name}: the administrator network {', '.join(wide)} is too wide to exempt")
    read_maxretry = int(f2b("get", jail.name, "maxretry").strip())
    if read_maxretry != maxretry:
        problems.append(f"{jail.name}: maxretry is {read_maxretry}, not {maxretry}")
    return {"loaded": True, "backend": backend, "ignoreip_missing": missing, "ignoreip_extra": extra,
            "maxretry": read_maxretry}, problems


def prove_filter(jail, marker, source, since):
    jail.provoke(marker, source)
    time.sleep(1)                     # journald has the lines within a second
    lines = journal(jail.unit, since)
    failures = [line_with(lines, needle(marker)) for needle in jail.failures]
    control = line_with(lines, jail.control(marker))
    found = {"source": source, "failures": {line: regex(line, jail.filter) for line in failures},
             "control": {control: regex(control, jail.filter)}}
    problems = [f"{jail.name}: the filter matched {n} times, not once, a real failure: {line}"
                for line, n in found["failures"].items() if n != 1]
    problems += [f"{jail.name}: the filter matched a line that is not a failure: {line}"
                 for line, n in found["control"].items() if n != 0]
    return found, problems


def prove_ban(jail, address, maxretry):
    """`maxretry - 1` attempts do not ban; one more does, with a reject rule; the unban removes it."""
    if address in banned(jail.name) or address in nft_set(jail.name):
        raise ProofError(f"{address} is already banned in {jail.name}")
    for n in range(maxretry - 1):
        f2b("set", jail.name, "attempt", address, f"maildivvy-ban proof {n + 1}")
    time.sleep(SETTLE)
    found = {"address": address, "banned_one_fewer": address in banned(jail.name) | nft_set(jail.name)}
    f2b("set", jail.name, "attempt", address, f"maildivvy-ban proof {maxretry}")
    found["banned"] = until(lambda: address in banned(jail.name) and address in nft_set(jail.name))
    found["rule"] = nft_rejects(jail.name)
    found["counted"] = len(nft_set(jail.name) & {address})
    run(["fail2ban-client", "set", jail.name, "unbanip", address], check=False)
    found["unbanned"] = until(lambda: address not in banned(jail.name) and address not in nft_set(jail.name))
    problems = []
    if found["banned_one_fewer"]:
        problems.append(f"{jail.name}: {maxretry - 1} failures from {address} banned it, one fewer than maxretry")
    if not found["banned"] or found["counted"] != 1:
        problems.append(f"{jail.name}: {maxretry} failures from {address} did not put it in the jail's "
                        "nftables set")
    if not found["rule"]:
        problems.append(f"{jail.name}: no rule rejects the addresses in addr-set-{jail.name}")
    if not found["unbanned"]:
        problems.append(f"{jail.name}: the unban did not take {address} out of the set")
    return found, problems


def doveadm_penalty(address):
    return penalty(run(["doveadm", "penalty"]), address)


def prove_guesser(jail, marker, source, maxretry, log_path):
    """The source, already under Dovecot's delay from its first failure, keeps failing as a
    guesser does until the live jail has read `maxretry` of its failures."""
    offset = log_path.stat().st_size

    def read():
        with log_path.open() as handle:
            handle.seek(offset)
            return ignored_lines(handle.read(), jail.name, source)
    found = {"source": source, "penalty at the start": doveadm_penalty(source), "answers": []}
    for _ in range(GUESSES * maxretry):
        found["answers"].append(smtp_guess(marker, source))
        if until(lambda: read() >= maxretry, seconds=1):
            break
    found["read by the live jail"] = read()
    found["delay met"] = found["penalty at the start"] > 0 or any(a != 535 for a in found["answers"])
    problems = []
    if found["read by the live jail"] < maxretry:
        problems.append(f"{jail.name}: {len(found['answers'])} failures from a source under Dovecot's delay "
                        f"and the live jail read {found['read by the live jail']}, fewer than maxretry "
                        f"{maxretry}: a guesser would never be banned")
    return found, problems


def prove(wanted_ignores, maxretry, rng=None):
    rng = rng or random.SystemRandom()
    report, problems = {"jails": {}}, []
    loaded = jail_list(f2b("status"))
    dump = f2b("-d")
    log_path = log_target()
    offset = log_path.stat().st_size
    since = time.time() - 1
    taken = set()
    for jail in JAILS:
        entry = report["jails"][jail.name] = {}
        entry["daemon"], found = prove_daemon(jail, loaded, dump, wanted_ignores, maxretry)
        problems += found
        if not entry["daemon"]["loaded"]:
            continue
        marker = f"ban-proof-{secrets.token_hex(4)}"
        source = jail.source()
        if jail.guesser:
            # a clean source first: a penalty left by an earlier run would lose this failure
            until(lambda: doveadm_penalty(source) == 0, seconds=CLEAN)
        entry["filter"], found = prove_filter(jail, marker, source, since)
        problems += found

        def read_it(name=jail.name, address=source):
            with log_path.open() as handle:
                handle.seek(offset)
                return ignored_lines(handle.read(), name, address) > 0
        entry["source"] = {"read by the live jail": until(read_it)}
        if not entry["source"]["read by the live jail"]:
            problems.append(f"{jail.name}: the running jail never read the failure from the journal")
        if jail.guesser:
            entry["guesser"], found = prove_guesser(jail, marker, source, maxretry, log_path)
            problems += found
        address = proof_address(rng, taken)
        taken.add(address)
        entry["ban"], found = prove_ban(jail, address, maxretry)
        problems += found
    report["problems"] = problems
    return report


def main(argv=None):
    p = argparse.ArgumentParser(prog="maildivvy-ban", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    pr = sub.add_parser("prove", help="prove every jail: daemon, filter, source, counter and action")
    pr.add_argument("--maxretry", type=int, required=True)
    pr.add_argument("--ignore", action="append", required=True, help="a network ignoreip must cover")
    args = p.parse_args(argv)
    try:
        report = prove(networks(args.ignore), args.maxretry)
    except (ProofError, OSError, subprocess.SubprocessError, ssl.SSLError, smtplib.SMTPException,
            imaplib.IMAP4.error) as err:
        report = {"problems": [f"the proof could not run: {type(err).__name__}: {err}"]}
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    for problem in report["problems"]:
        sys.stderr.write(f"NOT PROVED: {problem}\n")
    return 1 if report["problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
