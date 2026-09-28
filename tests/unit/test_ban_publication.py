"""Install steps 18 and 19 without a machine: the ban proof's readings of fail2ban and nftables
(`ansible/roles/ban/files/maildivvy_ban.py`, installed as `/usr/local/sbin/maildivvy-ban`),
and the recording of an outside probe's result
(`ansible/roles/publish/files/maildivvy_publication.py`, `/usr/local/sbin/maildivvy-publication`).

The readings are the shapes fail2ban 1.1.0-9 and nftables 1.1.6 print on Ubuntu 26.04
(measured 2026-09-23); the proof itself runs on the machine.
"""

import datetime
import hashlib
import importlib.util
import ipaddress
import json
import random
import ssl
import subprocess
from pathlib import Path

import pytest

from maildivvy.health import system
from maildivvy.health.report import PASS
from maildivvy.health.settings import Settings

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ban = load("maildivvy_ban", "ansible/roles/ban/files/maildivvy_ban.py")
publication = load("maildivvy_publication", "ansible/roles/publish/files/maildivvy_publication.py")
NOW = datetime.datetime(2026, 9, 23, 12, 0, tzinfo=datetime.timezone.utc)

# --- the ban proof's readings (step 18) ------------------------------------------------------------

STATUS = "Status\n|- Number of jail:\t3\n`- Jail list:\tdovecot, postfix, sshd\n"
IGNOREIP = ("These IP addresses/networks are ignored:\n|- 127.0.0.0/8\n|- 192.0.2.0/24\n"
            "`- ::1\n")
DUMP = """\
['set', 'syslogsocket', 'auto']
['add', 'sshd', 'systemd']
['set', 'sshd', 'addignoreip', '127.0.0.1/8', '::1', '192.0.2.0/24']
['add', 'postfix', 'systemd']
['set', 'postfix', 'maxretry', 5]
['add', 'dovecot', 'polling']
"""
SET = {"nftables": [{"metainfo": {"version": "1.1.6"}},
                    {"set": {"family": "inet", "name": "addr-set-dovecot", "table": "f2b-table",
                             "type": "ipv4_addr", "handle": 2, "elem": ["192.0.2.9", "192.0.2.10"]}}]}
CHAIN = {"nftables": [{"metainfo": {"version": "1.1.6"}},
                      {"chain": {"family": "inet", "table": "f2b-table", "name": "f2b-chain",
                                 "hook": "input", "prio": -1, "policy": "accept"}},
                      {"rule": {"family": "inet", "table": "f2b-table", "chain": "f2b-chain", "expr": [
                          {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                          {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                     "right": "@addr-set-dovecot"}},
                          {"reject": {"type": "icmp", "expr": "port-unreachable"}}]}}]}


def test_the_jails_are_read_from_the_anchored_jail_list_line():
    assert ban.jail_list(STATUS) == ["dovecot", "postfix", "sshd"]
    with pytest.raises(ban.ProofError):
        ban.jail_list("Status\n# dovecot-local present\n")


def test_the_ignore_list_is_read_back_as_networks_and_compared_as_networks():
    found = ban.ignore_list(IGNOREIP)
    assert found == {ipaddress.ip_network(n) for n in ("127.0.0.0/8", "192.0.2.0/24", "::1/128")}
    wanted = ban.networks(["127.0.0.1/8", "::1", "192.0.2.0/24"])
    assert ban.missing_ignores(found, wanted) == []
    # an administrator network the daemon does not ignore is named: its bans would cut it off
    assert ban.missing_ignores(found, ban.networks(["127.0.0.1/8", "10.0.0.0/8"])) == ["10.0.0.0/8"]


def test_the_proof_refuses_an_ignore_list_that_exempts_more_than_the_administrator_networks():
    """The proof checked only that `ignoreip` covers the wanted
    networks, so a jail.d file adding `0.0.0.0/1` exempted half the internet from the bans
    and the proof passed; and a wanted network that wide is refused by the proof too."""
    wanted = ban.networks(["127.0.0.1/8", "::1", "192.0.2.0/24"])
    assert ban.extra_ignores(ban.ignore_list(IGNOREIP), wanted) == []
    widened = ban.ignore_list(IGNOREIP + "|- 0.0.0.0/1\n|- 192.0.2.7\n")
    assert ban.extra_ignores(widened, wanted) == ["0.0.0.0/1"]      # a host inside a wanted one is fine
    assert ban.too_wide(ipaddress.ip_network("0.0.0.0/1")) and ban.too_wide(ipaddress.ip_network("8.0.0.0/8"))
    assert not ban.too_wide(ipaddress.ip_network("10.0.0.0/8"))
    assert not ban.too_wide(ipaddress.ip_network("127.0.0.0/8"))    # loopback is always ignored


def test_each_jails_backend_is_read_from_the_running_daemon_not_the_file():
    assert ban.backends(DUMP) == {"sshd": "systemd", "postfix": "systemd", "dovecot": "polling"}


def test_fail2ban_regex_is_read_for_its_matched_count_and_nothing_else():
    out = "Running tests\n=============\n\nLines: 1 lines, 0 ignored, 1 matched, 0 missed\n"
    assert ban.regex_matched(out) == 1
    with pytest.raises(ban.ProofError):
        ban.regex_matched("ERROR: No failure-regex is present")


def test_the_ban_is_counted_in_the_jails_set_and_needs_a_reject_rule_on_it():
    assert ban.set_elements(SET) == {"192.0.2.9", "192.0.2.10"}
    one = {"nftables": [{"set": {**SET["nftables"][1]["set"], "elem": "192.0.2.9"}}]}
    assert ban.set_elements(one) == {"192.0.2.9"}
    empty = {"nftables": [{"set": {k: v for k, v in SET["nftables"][1]["set"].items() if k != "elem"}}]}
    assert ban.set_elements(empty) == set()
    assert ban.rejects(CHAIN, "addr-set-dovecot") is True
    assert ban.rejects(CHAIN, "addr-set-postfix") is False
    accept = json.loads(json.dumps(CHAIN).replace('"reject": {"type": "icmp", "expr": "port-unreachable"}',
                                                  '"accept": null'))
    assert ban.rejects(accept, "addr-set-dovecot") is False


def test_the_proof_address_is_a_documentation_address_and_differs_per_jail():
    rng = random.Random(7)
    first = ban.proof_address(rng, taken=set())
    second = ban.proof_address(rng, taken={first})
    for address in (first, second):
        assert ipaddress.ip_address(address) in ipaddress.ip_network("192.0.2.0/24")
        assert address not in ("192.0.2.0", "192.0.2.255")
    assert first != second


def test_the_live_jail_is_seen_reading_the_journal_by_the_lines_it_logs():
    log = ("2026-09-23 14:05:03,422 fail2ban.filter [393262]: INFO    [dovecot] Ignore 127.0.0.1 by ignoreself rule\n"
           "2026-09-23 14:06:04,474 fail2ban.filter [393262]: INFO    [postfix] Ignore 192.0.2.60 by ignoreself rule\n"
           "2026-09-23 14:06:10,724 fail2ban.filter [393262]: INFO    [dovecot] Ignore 127.0.0.1 by ip\n")
    assert ban.ignored_lines(log, "dovecot", "127.0.0.1") == 2
    assert ban.ignored_lines(log, "postfix", "192.0.2.60") == 1
    assert ban.ignored_lines(log, "postfix", "127.0.0.1") == 0
    assert ban.ignored_lines(log, "dovecot", "127.0.0.10") == 0   # the address whole, not a prefix
    assert ban.ignored_lines(log, "sshd", "127.0.0.1") == 0


def test_a_temporary_refusal_is_told_from_a_failure_so_it_can_be_asked_again():
    """after PostgreSQL restarts, Dovecot's first lookup fails temporarily, and its line
    `(auth service reported temporary failure …) (temp_fail)` is rightly no failure to the
    filter; the proof asks once more rather than reading that line (measured by a gate run)."""
    assert ban.temporary(b"[UNAVAILABLE] Temporary authentication failure. [host:2026-09-23]")
    assert not ban.temporary(b"[AUTHENTICATIONFAILED] Authentication failed.")
    assert ban.temporary(454) and not ban.temporary(535)


def test_dovecots_penalty_for_an_address_is_read_from_doveadm_penalty():
    """The guesser half of the postfix proof waits for its own
    address to be clean first and reports whether the delay was met; both read this."""
    listing = ("IP penalty last_penalty last_update                      \n"
               "192.0.2.60 3       2026-09-24 12:52:03 12:52:03\n"
               "198.51.100.11 1       2026-09-24 12:52:28 12:52:28\n")
    assert ban.penalty(listing, "192.0.2.60") == 3
    assert ban.penalty(listing, "198.51.100.1") == 0       # the address whole, not a prefix
    assert ban.penalty("IP penalty last_penalty last_update\n", "192.0.2.60") == 0


def test_the_journal_line_is_found_by_the_proofs_own_marker():
    lines = ["2026-09-23T14:06:04+00:00 m dovecot[1]: imap-login: Login aborted: Logged out (auth failed, "
             "1 attempts in 2 secs) (auth_failed): user=<maildivvy-health@health.invalid>, rip=127.0.0.1",
             "2026-09-23T14:06:10+00:00 m dovecot[1]: imap-login: Login aborted: Connection closed (auth "
             "failed, 1 attempts in 6 secs) (auth_failed): user=<ban-proof-7@ban-proof.invalid>, rip=127.0.0.1"]
    assert ban.line_with(lines, "user=<ban-proof-7@ban-proof.invalid>") == lines[1]
    with pytest.raises(ban.ProofError):
        ban.line_with(lines, "user=<ban-proof-8@ban-proof.invalid>")


# --- recording the outside probe's result (step 19) -----------------------------------------

HOST = "mail.example.test"
PUBLISHED = {"published_at": "2026-09-20T08:00:00+00:00"}
LEAF = "a1" * 32            # the SHA-256 of this machine's published leaf
OTHER = "b2" * 32           # another machine's leaf for the same name


def probe_result(**changes):
    found = {"probe": "maildivvy-outside-probe", "version": 2, "host": HOST, "address": "203.0.113.25",
             "proved_at": "2026-09-23T11:00:00+00:00", "result": "PASS",
             "leaf_sha256": {"imaps": LEAF, "submissions": LEAF},
             "checks": [{"name": "imaps", "state": "PASS", "reading": "993: TLS"}]}
    found.update(changes)
    return found


def test_a_dated_probe_result_for_this_machine_is_recorded_beside_the_publication():
    record = publication.recorded(probe_result(), PUBLISHED, HOST, LEAF, NOW)
    assert record["published_at"] == PUBLISHED["published_at"]
    assert record["proved_at"] == "2026-09-23T11:00:00+00:00" and record["result"] == "PASS"
    assert record["probe"]["checks"][0]["name"] == "imaps"
    # what health then reads: PASS while it is fresh
    assert system.judge_publication(record, NOW, Settings(), HOST, LEAF).state == PASS


@pytest.mark.parametrize("served, why", [
    ({"imaps": LEAF, "submissions": OTHER}, "submissions served a certificate that is not this machine's"),
    ({"imaps": OTHER, "submissions": OTHER}, "imaps served a certificate that is not this machine's"),
    ({"imaps": LEAF}, "names no certificate submissions served"),
    ({"imaps": LEAF, "submissions": None}, "names no certificate submissions served"),
    (None, "names no certificate imaps served"),
])
def test_a_result_for_another_machines_certificate_is_refused(served, why):
    """The name alone proved the name, not the machine. A PASS must
    carry this machine's own published leaf for both mail ports."""
    with pytest.raises(publication.Refused, match=why):
        publication.recorded(probe_result(leaf_sha256=served), PUBLISHED, HOST, LEAF, NOW)


def test_a_failed_result_may_lack_a_leaf_but_never_carry_another_machines():
    unreached = probe_result(result="FAIL", leaf_sha256={"imaps": None, "submissions": LEAF})
    assert publication.recorded(unreached, PUBLISHED, HOST, LEAF, NOW)["result"] == "FAIL"
    with pytest.raises(publication.Refused, match="not this machine's"):
        publication.recorded(probe_result(result="FAIL", leaf_sha256={"imaps": OTHER, "submissions": None}),
                             PUBLISHED, HOST, LEAF, NOW)


def test_health_reads_a_recorded_result_as_fail_once_it_no_longer_names_this_certificate_or_name():
    """After a move or a renewal the stored PASS is about another leaf or name."""
    record = publication.recorded(probe_result(), PUBLISHED, HOST, LEAF, NOW)
    renewed = system.judge_publication(record, NOW, Settings(), HOST, OTHER)
    assert renewed.state == "FAIL" and "not the certificate published here" in renewed.problem
    renamed = system.judge_publication(record, NOW, Settings(), "mail.other.test", LEAF)
    assert renamed.state == "FAIL" and "mail.other.test" in renamed.problem
    unnamed = {**record, "probe": {**record["probe"], "leaf_sha256": None}}
    assert system.judge_publication(unnamed, NOW, Settings(), HOST, LEAF).state == "FAIL"


@pytest.mark.parametrize("change, why", [
    ({"result": "INVALID"}, "invalid vantage point"),
    ({"result": "MAYBE"}, "not a probe result"),
    ({"probe": "something-else"}, "not a probe result"),
    ({"host": "other.example.test"}, "other.example.test"),
    ({"proved_at": "2026-09-19T08:00:00+00:00"}, "before the ports were published"),
    ({"proved_at": "2026-09-23T13:00:00+00:00"}, "in the future"),
    ({"proved_at": "2026-09-23T11:00:00"}, "no time zone"),
    ({"proved_at": "yesterday"}, "not a probe result"),
])
def test_a_result_that_proves_nothing_about_this_publication_is_refused(change, why):
    with pytest.raises(publication.Refused, match=why):
        publication.recorded(probe_result(**change), PUBLISHED, HOST, LEAF, NOW)


def test_an_older_result_never_replaces_a_newer_one():
    """A result handed in late, older than the one recorded, overwrote
    it; a FAIL from last week could hide today's PASS, or a PASS a newer FAIL."""
    newer = publication.recorded(probe_result(proved_at="2026-09-23T11:00:00+00:00", result="FAIL"),
                                 PUBLISHED, HOST, LEAF, NOW)
    with pytest.raises(publication.Refused, match="older than the result already recorded"):
        publication.recorded(probe_result(proved_at="2026-09-22T11:00:00+00:00"), newer, HOST, LEAF, NOW)
    again = publication.recorded(probe_result(proved_at="2026-09-23T11:30:00+00:00"), newer, HOST, LEAF, NOW)
    assert again["result"] == "PASS" and again["published_at"] == PUBLISHED["published_at"]


def test_a_result_is_refused_while_the_ports_are_not_published():
    with pytest.raises(publication.Refused, match="not published"):
        publication.recorded(probe_result(), None, HOST, LEAF, NOW)
    with pytest.raises(publication.Refused, match="not published"):
        publication.recorded(probe_result(), {"proved_at": "x"}, HOST, LEAF, NOW)


def test_a_failed_result_is_recorded_too_so_health_reads_it_as_fail():
    record = publication.recorded(probe_result(result="FAIL"), PUBLISHED, HOST, LEAF, NOW)
    assert record["result"] == "FAIL"
    assert system.judge_publication(record, NOW, Settings(), HOST, LEAF).state == "FAIL"


def test_the_record_command_writes_the_file_whole_and_readable_by_health(tmp_path, monkeypatch, capsys):
    target, cert = tmp_path / "publication.json", tmp_path / "certificate.json"
    target.write_text(json.dumps(PUBLISHED))
    # the published certificate as lego writes it: the leaf, then the CA's certificate
    leaf, ca = (tmp_path / "leaf.pem", tmp_path / "ca.pem")
    for path, cn in ((leaf, HOST), (ca, "ca.example.test")):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-days", "2", "-subj", f"/CN={cn}", "-keyout", str(tmp_path / "k.pem"),
                        "-out", str(path)], check=True, capture_output=True)
    chain = tmp_path / "chain.pem"
    chain.write_text(leaf.read_text() + ca.read_text())
    ours = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.read_text())).hexdigest()
    cert.write_text(json.dumps({"cert_name": HOST, "published_cert": str(chain)}))
    source = tmp_path / "result.json"
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    # a result for another leaf is refused by the command, which reads the published leaf
    source.write_text(json.dumps(probe_result(proved_at=now)))
    code = publication.main(["--publication", str(target), "--certificate", str(cert), "record", str(source)])
    assert code == 1 and "not this machine's" in capsys.readouterr().err
    source.write_text(json.dumps(probe_result(proved_at=now, leaf_sha256={"imaps": ours, "submissions": ours})))
    code = publication.main(["--publication", str(target), "--certificate", str(cert), "record", str(source)])
    assert code == 0, capsys.readouterr()
    written = json.loads(target.read_text())
    assert written["result"] == "PASS" and written["published_at"] == PUBLISHED["published_at"]
    assert target.stat().st_mode & 0o777 == 0o644
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".")] == []   # no temporary left
    # refused: the file is left exactly as it was, and the reason is printed
    before = target.read_text()
    source.write_text(json.dumps(probe_result(result="INVALID")))
    code = publication.main(["--publication", str(target), "--certificate", str(cert), "record", str(source)])
    assert code != 0 and target.read_text() == before
    assert "invalid vantage point" in capsys.readouterr().err
