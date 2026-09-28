#!/usr/bin/python3
"""maildivvy-publication: record the outside probe's result on the published machine.

    maildivvy-publication record [FILE]     the probe's JSON, from FILE or stdin

Installed by step 19 (ansible/roles/publish) as /usr/local/sbin/maildivvy-publication.
Step 19 opens 993 and 465 and writes /var/lib/maildivvy/publication.json with the moment
it did, `{"published_at": ...}`. Only a probe run from OUTSIDE the machine's network can
say whether that publication works (tools/outside-probe/); the operator hands its result
to this command, which adds it to the same file: `proved_at`, `result` and the probe's
whole document. Health reads the file: publication is PASS only while a PASS result is
younger than its bound, FAIL on a FAIL, and UNKNOWN with none (src/maildivvy/health/system.py).

A result that proves nothing about this publication is refused and the file is left as it
was: an INVALID one (the vantage point answered the ports itself), one for another name
than this machine's certificate, one whose mail ports served another leaf than the one
published here (another machine for the same name), one dated
before the ports were opened or in the future, and any result while the ports are not
published.
"""
# The record behind it.

import argparse
import datetime
import hashlib
import json
import os
import re
import ssl
import sys
import tempfile
from pathlib import Path

PUBLICATION = Path("/var/lib/maildivvy/publication.json")
CERTIFICATE = Path("/etc/maildivvy/certificate.json")
PROBE = "maildivvy-outside-probe"
MAIL_PORTS = ("imaps", "submissions")    # the probe's names for 993 and 465
RESULTS = ("PASS", "FAIL")
SKEW = datetime.timedelta(minutes=5)


class Refused(Exception):
    """The result is not recorded; the message says why."""


def moment(value, what):
    try:
        at = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise Refused(f"{what} is not a probe result's time: {value!r}") from None
    if at.tzinfo is None:
        raise Refused(f"{what} {value} has no time zone")
    return at


def check_leaves(result, leaf):
    """Every mail port's served leaf is this machine's published one:
    the name alone is also another machine's during a move. A PASS names both; a FAIL may
    lack one where no handshake completed, but never names another machine's."""
    served = result.get("leaf_sha256")
    served = served if isinstance(served, dict) else {}
    for port in MAIL_PORTS:
        found = served.get(port)
        if found is None:
            if result.get("result") == "PASS":
                raise Refused(f"the result names no certificate {port} served: run this repository's "
                              "outside probe again, which names the leaf each port served")
        elif found != leaf:
            raise Refused(f"{port} served a certificate that is not this machine's (sha256 {found}, "
                          f"published here: {leaf}): the probe reached another machine for the "
                          "same name - DNS or the router still points elsewhere")


def recorded(result, record, cert_name, leaf, now):
    """The publication record with this probe result in it, or Refused. `leaf` is the SHA-256
    of the published leaf certificate."""
    if not record or "published_at" not in record:
        raise Refused("the mail ports are not published on this machine: a probe result proves "
                      "nothing until step 19 has opened them")
    published = moment(record["published_at"], "published_at")
    if not isinstance(result, dict) or result.get("probe") != PROBE:
        raise Refused(f"this is not a probe result: it does not come from {PROBE}")
    if result.get("result") == "INVALID":
        raise Refused("the probe ran from an invalid vantage point, which proves nothing: run it "
                      "from a network that does not answer the probed ports itself")
    if result.get("result") not in RESULTS:
        raise Refused(f"this is not a probe result: its result is {result.get('result')!r}")
    if result.get("host") != cert_name:
        raise Refused(f"the probe was run for {result.get('host')!r}, and this machine is {cert_name!r}")
    check_leaves(result, leaf)
    proved = moment(result.get("proved_at"), "proved_at")
    if proved < published:
        raise Refused(f"the probe ran at {proved.isoformat()}, before the ports were published at "
                      f"{published.isoformat()}: run it again")
    if proved > now + SKEW:
        raise Refused(f"the probe's time {proved.isoformat()} is in the future of this machine's clock")
    if "proved_at" in record and proved < moment(record["proved_at"], "the recorded proved_at"):
        # A result handed in late never replaces a newer one
        raise Refused(f"the probe ran at {proved.isoformat()}, older than the result already recorded "
                      f"({record['proved_at']}): run it again")
    return {"published_at": record["published_at"], "proved_at": result["proved_at"],
            "result": result["result"], "probe": result}


def write(path, record):
    """Atomically, 0644: health reads it as its own user."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(record, handle, indent=2)
            handle.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def published_leaf(path):
    """The SHA-256 of the published leaf: the first certificate of the file, which for an
    ACME certificate is lego's chain, the leaf first."""
    try:
        text = Path(path).read_text()
    except OSError as err:
        raise Refused(f"cannot read the published certificate {path}: {err.strerror}") from None
    first = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.DOTALL)
    if first is None:
        raise Refused(f"{path} holds no certificate to compare the probe's with")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(first.group(0))).hexdigest()


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return None


def main(argv=None):
    p = argparse.ArgumentParser(prog="maildivvy-publication", description=__doc__.split("\n\n")[0])
    p.add_argument("--publication", default=str(PUBLICATION), help=argparse.SUPPRESS)
    p.add_argument("--certificate", default=str(CERTIFICATE), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record", help="record the outside probe's JSON result")
    rec.add_argument("file", nargs="?", help="the probe's output (default: stdin)")
    args = p.parse_args(argv)
    try:
        text = Path(args.file).read_text() if args.file else sys.stdin.read()
        try:
            result = json.loads(text)
        except ValueError:
            raise Refused("this is not a probe result: it is not JSON") from None
        certificate = read_json(args.certificate)
        now = datetime.datetime.now(datetime.timezone.utc)
        record = recorded(result, read_json(args.publication), certificate["cert_name"],
                          published_leaf(certificate["published_cert"]), now)
    except Refused as err:
        sys.stderr.write(f"maildivvy-publication: not recorded: {err}\n")
        return 1
    write(args.publication, record)
    sys.stdout.write(f"recorded: the outside probe's {record['result']} at {record['proved_at']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
