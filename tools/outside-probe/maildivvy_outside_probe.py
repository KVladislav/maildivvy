#!/usr/bin/env python3
"""maildivvy-outside-probe: prove a Maildivvy machine's publication from outside.

Run it from a machine OUTSIDE the installation's network, with nothing but Python 3's
standard library:

    python3 maildivvy_outside_probe.py <mail name> [--address <public address>]
                                       [--cafile <certificate.pem>] > probe-result.json

then hand the result to the machine, which records it and dates publication by it:

    sudo maildivvy-publication record < probe-result.json

It asserts, and prints as one dated JSON document:

- 993 and 465 complete a TLS handshake presenting the certificate for <mail name>,
  verified by the system's trust store, or by --cafile for a test machine whose
  certificate is self-signed or from a staging CA;
- the administration port (443) and every port not meant to be published are
  unreachable;
- an unauthenticated SMTP dialogue on 465 reaches RCPT TO and is refused THERE with
  554 5.7.1. A refusal at an earlier stage fails the expectation: it is not a pass.

The result also names the SHA-256 of the leaf certificate 993 and 465 each served
(`leaf_sha256`): the name says which name answered, the leaf which machine. The machine
refuses to record a result for any leaf but its own published one.

Result: PASS, FAIL, or INVALID when the vantage point is not a valid one: a network that
answers the probed ports itself - a connection accepted with no TLS, no banner, or a
certificate that is not ours. Its exit code is 0, 2 or 3. An INVALID result proves
nothing and the machine refuses to record it. A vantage point inside the machine's own
network is invalid too, and the probe cannot see that: without hairpin NAT it reads the
public address as closed whether or not publication works. Run it from elsewhere.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import socket
import ssl
import sys
from dataclasses import dataclass

NAME = "maildivvy-outside-probe"
VERSION = 2         # 2: the result names the leaf each mail port served (`leaf_sha256`)
PORTS = {"imaps": 993, "submissions": 465}
ADMIN_PORT = 443
# Every port something on the machine listens on or once did, and the usual mail ports
# the product does not serve; none must answer from outside.
CLOSED = (22, 25, 80, 110, 143, 587, 995, 3310, 4190, 5432, 11332, 11333, 11334)
EXIT = {"PASS": 0, "FAIL": 2, "INVALID": 3}
EHLO = "maildivvy-outside-probe.invalid"
SENDER = "maildivvy-outside-probe@example.org"


class Invalid(Exception):
    """What was reached is not the machine: the vantage point proves nothing."""


class Unreachable(Exception):
    """No connection could be made at all."""


@dataclass
class Check:
    name: str
    state: str
    reading: str
    leaf_sha256: str | None = None      # a mail port's: the leaf it served, if it served one


def trust(cafile=None):
    """The TLS context a published port must verify against: our name, our certificate."""
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def connect(address, port, timeout):
    try:
        return socket.create_connection((address, port), timeout=timeout)
    except OSError as err:
        raise Unreachable(f"{type(err).__name__}: {err.strerror or err}") from None


def handshake(address, port, host, context, timeout):
    """A TLS connection to our name, or why the other end is not us."""
    sock = connect(address, port, timeout)
    try:
        return context.wrap_socket(sock, server_hostname=host)
    except ssl.SSLCertVerificationError as err:
        sock.close()
        raise Invalid(f"presented a certificate that is not ours for {host}: {err.verify_message}") from None
    except (ssl.SSLError, OSError) as err:
        sock.close()
        raise Invalid(f"accepted a connection and completed no TLS handshake ({type(err).__name__})") from None


class Lines:
    def __init__(self, tls):
        self.tls, self.buffer = tls, b""

    def read(self):
        while b"\r\n" not in self.buffer:
            chunk = self.tls.recv(4096)
            if not chunk:
                raise EOFError("the connection was closed")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\r\n", 1)
        return line.decode("utf-8", "replace")

    def reply(self):
        """One SMTP reply, all its lines: (code, the last line's text)."""
        while True:
            line = self.read()
            if len(line) < 4 or not line[:3].isdigit():
                raise ValueError(f"not an SMTP reply: {line[:80]!r}")
            if line[3] != "-":
                return int(line[:3]), line[4:]

    def send(self, text):
        self.tls.sendall(text.encode() + b"\r\n")


def leaf_sha256(tls):
    """The SHA-256 of the leaf certificate this connection was served: which machine answered,
    where the name only says which name it answered for."""
    return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def check_imaps(address, port, host, context, timeout):
    leaf = None
    try:
        with handshake(address, port, host, context, timeout) as tls:
            leaf = leaf_sha256(tls)
            stream = Lines(tls)
            try:
                greeting = stream.read()
            except (OSError, EOFError):
                raise Invalid("completed the TLS handshake and sent no IMAP greeting") from None
            if not greeting.startswith("* OK"):
                raise Invalid(f"no IMAP greeting after the handshake: {greeting[:80]!r}")
            stream.send("a1 LOGOUT")
    except Unreachable as err:
        return Check("imaps", "FAIL", f"{port} not reachable: {err}")
    except Invalid as err:
        return Check("imaps", "INVALID", f"{port} {err}", leaf)
    return Check("imaps", "PASS", f"{port}: TLS with our certificate for {host}, and an IMAP greeting",
                 leaf)


def smtp_dialogue(stream, host):
    """Reach RCPT TO unauthenticated; the reading, and whether it is the refusal wants."""
    try:
        code, text = stream.reply()
    except (OSError, EOFError, ValueError):
        raise Invalid("completed the TLS handshake and sent no SMTP banner") from None
    if code != 220:
        raise Invalid(f"no SMTP banner after the handshake: {code} {text[:80]}")
    stream.send(f"EHLO {EHLO}")
    code, text = stream.reply()
    if code != 250:
        return False, f"EHLO answered {code} {text}"
    stream.send(f"MAIL FROM:<{SENDER}>")
    code, text = stream.reply()
    if code != 250:
        return False, (f"refused at MAIL FROM with {code} {text}, before RCPT TO: the "
                       "expectation (the refusal at RCPT TO) is not met")
    stream.send(f"RCPT TO:<postmaster@{host}>")
    code, text = stream.reply()
    stream.send("QUIT")
    reading = f"unauthenticated RCPT TO answered {code} {text}"
    return code == 554 and text.startswith("5.7.1"), reading


def check_submissions(address, port, host, context, timeout):
    leaf = None
    try:
        with handshake(address, port, host, context, timeout) as tls:
            leaf = leaf_sha256(tls)
            good, reading = smtp_dialogue(Lines(tls), host)
    except Unreachable as err:
        return Check("submissions", "FAIL", f"{port} not reachable: {err}")
    except Invalid as err:
        return Check("submissions", "INVALID", f"{port} {err}", leaf)
    except (OSError, EOFError, ValueError) as err:
        return Check("submissions", "FAIL", f"{port}: the SMTP dialogue broke off: {err}", leaf)
    if not good:
        return Check("submissions", "FAIL", f"{port}: {reading}; expected 554 5.7.1 at RCPT TO", leaf)
    return Check("submissions", "PASS", f"{port}: TLS with our certificate for {host}; {reading}", leaf)


def check_admin(address, port, host, context, timeout):
    """The administration port must not answer; if something does, it is either the machine
    (our certificate: the port is published) or the vantage network's own."""
    try:
        with handshake(address, port, host, context, timeout):
            pass
    except Unreachable as err:
        return Check("administration port", "PASS", f"{port} not reachable ({err})")
    except Invalid as err:
        return Check("administration port", "INVALID", f"{port} {err}")
    return Check("administration port", "FAIL", f"{port} answers with our certificate for {host}: "
                                                "the administration interface is published")


def reachable(address, port, timeout):
    try:
        connect(address, port, timeout).close()
    except Unreachable:
        return False
    return True


def check_closed(address, ports, timeout):
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        answers = dict(zip(ports, pool.map(lambda p: reachable(address, p, timeout), ports)))
    open_ = [str(p) for p, answered in answers.items() if answered]
    if open_:
        return Check("unpublished ports", "FAIL", f"reachable: {', '.join(open_)}; none of "
                                                  f"{', '.join(map(str, ports))} should be")
    return Check("unpublished ports", "PASS", f"none reachable: {', '.join(map(str, ports))}")


def verdict(checks):
    states = {check.state for check in checks}
    if not checks or "INVALID" in states:
        return "INVALID"
    return "FAIL" if "FAIL" in states else "PASS"


def result(host, address, checks):
    """The dated result. `leaf_sha256` names the leaf each mail port served (None where no
    handshake completed): the machine refuses to record a result for another's leaf."""
    return {"probe": NAME, "version": VERSION, "host": host, "address": address,
            "proved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "result": verdict(checks),
            "leaf_sha256": {check.name: check.leaf_sha256 for check in checks if check.name in PORTS},
            "checks": [{"name": check.name, "state": check.state, "reading": check.reading}
                       for check in checks]}


def probe(host, address, context, ports=PORTS, admin_port=ADMIN_PORT, closed=CLOSED, timeout=10.0):
    checks = [check_imaps(address, ports["imaps"], host, context, timeout),
              check_submissions(address, ports["submissions"], host, context, timeout),
              check_admin(address, admin_port, host, context, timeout),
              check_closed(address, list(closed), timeout)]
    return result(host, address, checks)


def resolve(host):
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror as err:
        raise SystemExit(f"{NAME}: {host} does not resolve ({err}); give --address") from None


def ports_list(text):
    return [int(p) for p in text.split(",") if p.strip()]


def main(argv=None):
    p = argparse.ArgumentParser(prog=NAME, description=__doc__.split("\n\n")[0])
    p.add_argument("host", help="the machine's mail name, the one its certificate carries")
    p.add_argument("--address", help="the public address to probe (default: the name resolved)")
    p.add_argument("--cafile", help="verify against this certificate instead of the system's store")
    p.add_argument("--closed", type=ports_list, default=list(CLOSED),
                   help="ports that must not answer, comma separated (default: %(default)s)")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds per connection")
    args = p.parse_args(argv)
    address = args.address or resolve(args.host)
    found = probe(args.host, address, trust(args.cafile), ports=dict(PORTS), admin_port=ADMIN_PORT,
                  closed=args.closed, timeout=args.timeout)
    json.dump(found, sys.stdout, indent=2)
    sys.stdout.write("\n")
    for check in found["checks"]:
        sys.stderr.write(f"{check['state']:8} {check['name']}: {check['reading']}\n")
    sys.stderr.write(f"{found['result']} at {found['proved_at']}\n")
    return EXIT[found["result"]]


if __name__ == "__main__":
    sys.exit(main())
