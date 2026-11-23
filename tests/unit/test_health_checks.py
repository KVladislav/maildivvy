"""The judgments of the fifteen subsystems, kept in plain functions and fed readings as the
machine gives them (measured on the test VM, 2026-09-23), and the machinery around them:
one check's failure is that check's UNKNOWN and never the run's, the helper's answer is
whole or UNKNOWN, a bound is refused rather than guessed.

Each subsystem is driven against the real machine, with its fault injected and removed,
on the test machine.
"""

import datetime
import io
import json
import os
import socket
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from maildivvy.backup import status as backup_status
from maildivvy.fanout import ledger, pass_
from maildivvy.health import (checks, context, data, helper, probe, report, run, scanners,
                              services, settings, system, upstream)
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import FAIL, PASS, UNKNOWN, WARN
from maildivvy.lib import doveadm, retrieval, scan, store
from maildivvy.lib.scan import Score, Verdict, Version

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
CONF = settings.Settings()

# `ss -H -l -n -t -u` on the installed test VM, 2026-09-23
SS = """\
udp UNCONN 0      0         127.0.0.54:53    0.0.0.0:*
udp UNCONN 0      0      127.0.0.53%lo:53    0.0.0.0:*
udp UNCONN 0      0          127.0.0.1:323   0.0.0.0:*
udp UNCONN 0      0              [::1]:323      [::]:*
tcp LISTEN 0      200        127.0.0.1:5432  0.0.0.0:*
tcp LISTEN 0      4096         0.0.0.0:22    0.0.0.0:*
tcp LISTEN 0      100          0.0.0.0:465   0.0.0.0:*
tcp LISTEN 0      4096       127.0.0.1:42077 0.0.0.0:*
tcp LISTEN 0      511          0.0.0.0:443   0.0.0.0:*
tcp LISTEN 0      4096   127.0.0.53%lo:53    0.0.0.0:*
tcp LISTEN 0      100          0.0.0.0:993   0.0.0.0:*
tcp LISTEN 0      4096            [::]:22       [::]:*
tcp LISTEN 0      100             [::]:993      [::]:*
tcp LISTEN 0      200            [::1]:5432     [::]:*
"""


def states(found):
    return [c.state for c in (found if isinstance(found, list) else [found])]


# --- the machinery: independent checks, whole answers -----------------


def test_a_check_that_cannot_read_is_unknown_and_the_next_one_still_runs():
    def broken(ctx):
        raise Unreadable("the socket did not answer")

    def crashing(ctx):
        raise KeyError("status")

    def fine(ctx):
        return context.passed("fine", "read")

    ctx = context.Context(now=NOW)
    found = [c for f in (broken, crashing, fine) for c in context.run_check(f, ctx)]
    assert [c.state for c in found] == [UNKNOWN, UNKNOWN, PASS]
    assert "the socket did not answer" in found[0].problem
    assert "the check itself failed: KeyError" in found[1].problem


def test_every_subsystem_of_the_decision_is_there_in_its_order():
    assert list(checks.SUBSYSTEMS) == ["host", "network", "ban", "tls", "dovecot", "postfix",
                                       "milter", "antivirus", "spam", "search", "collection",
                                       "store", "database", "interface", "backup"]
    assert all(checks.SUBSYSTEMS.values())


def test_the_helper_answers_every_reading_asked_in_one_document_ending_complete():
    def ok():
        return {"n": 1}

    def failing():
        raise PermissionError("denied")

    out = io.StringIO()
    code = helper.serve("store", {"ok": ok, "failing": failing},
                        stdin=io.BytesIO(b'{"want": ["ok", "failing"]}\n'), stdout=out)
    answer = json.loads(out.getvalue())
    assert code == 0 and answer["complete"] is True
    assert answer["readings"]["ok"] == {"n": 1}
    assert "PermissionError: denied" in answer["readings"]["failing"]["error"]


def test_the_helper_reads_nothing_but_the_readings_it_knows():
    out = io.StringIO()
    code = helper.serve("store", {"ok": lambda: 1},
                        stdin=io.BytesIO(b'{"want": ["/etc/shadow"]}\n'), stdout=out)
    assert code == 2 and json.loads(out.getvalue())["complete"] is False


def serve_once(path, payload):
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)

    def answer():
        conn, _ = server.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(payload)
        server.close()
    thread = threading.Thread(target=answer)
    thread.start()
    return thread


@pytest.mark.parametrize("payload", [b'{"readings": {"ledger": {}}', b"",
                                     b'{"readings": {}, "complete": false}'])
def test_a_helper_answer_cut_short_is_unreadable_never_empty(tmp_path, payload):
    path = tmp_path / "helper.sock"
    thread = serve_once(path, payload)
    with pytest.raises(Unreadable):
        helper.ask("store", ["ledger"], path=path, timeout=5)
    thread.join()


def test_a_whole_helper_answer_is_its_readings(tmp_path):
    path = tmp_path / "helper.sock"
    thread = serve_once(path, b'{"readings": {"ledger": {"domains": {}}}, "complete": true}')
    assert helper.ask("store", ["ledger"], path=path, timeout=5) == {"ledger": {"domains": {}}}
    thread.join()


def test_a_helper_nobody_listens_on_is_unreadable(tmp_path):
    with pytest.raises(Unreadable, match="did not answer"):
        helper.ask("system", ["milter"], path=tmp_path / "none.sock", timeout=5)


def test_a_reading_the_helper_could_not_take_makes_its_check_unknown(monkeypatch):
    monkeypatch.setattr(helper, "ask", lambda name, wanted, **_: {"ledger": {"error": "denied"}})
    ctx = context.Context(now=NOW, wants={"store": ["ledger"]})
    found = context.run_check(data.ledger, ctx)
    assert [c.state for c in found] == [UNKNOWN]
    assert "could not read ledger: denied" in found[0].problem


def test_one_run_asks_each_helper_once_for_everything_its_subsystems_need(monkeypatch):
    asked = []
    monkeypatch.setattr(helper, "ask", lambda name, wanted, **_: asked.append((name, wanted)) or
                        {w: {"error": "x"} for w in wanted})
    ctx = context.Context(now=NOW, wants=checks.wants_of(["collection", "store", "search"]))
    for reading in ("ledger", "fetch_state", "search", "directories"):
        with pytest.raises(Unreadable):
            ctx.helper("store", reading)
    assert asked == [("store", ["directories", "fetch_state", "ledger", "search"])]


# --- the settings ----------------------------------------------------------------------------------


def test_no_settings_file_is_the_defaults(tmp_path):
    assert settings.read(tmp_path / "none.conf") == settings.Settings()


def test_a_setting_moves_its_bound_and_a_misspelt_one_is_refused(tmp_path):
    path = tmp_path / "health.conf"
    path.write_text("# a longer bound\nbackup_hours = 72\n")
    assert settings.read(path).backup_hours == 72
    path.write_text("backup_hour = 72\n")
    with pytest.raises(settings.SettingsError, match="not a health setting"):
        settings.read(path)
    path.write_text("backup_hours = soon\n")
    with pytest.raises(settings.SettingsError):
        settings.read(path)


# --- host ------------------------------------------------------------------------------------------


def test_a_data_disk_is_its_own_xfs_mounted_by_uuid():
    mounted = {"target": "/srv/maildivvy/store", "source": "/dev/xvdc", "fstype": "xfs"}
    root = {"target": "/", "source": "/dev/xvda2", "fstype": "ext4"}
    spec = system.fstab_spec("/srv/maildivvy/store",
                             "UUID=f14 /srv/maildivvy/store xfs defaults 0 2\n# UUID=x /y\n")
    assert spec == "UUID=f14"
    assert system.judge_mount("store", "/srv/maildivvy/store", mounted, root, spec).state == PASS
    assert system.judge_mount("store", "/srv/maildivvy/store", None, root, spec).state == FAIL
    assert system.judge_mount("store", "/srv/maildivvy/store", mounted, root, "/dev/xvdc").state == FAIL


def test_an_empty_mount_reading_is_trusted_only_when_the_root_is_read_beside_it():
    with pytest.raises(Unreadable):
        system.judge_mount("store", "/srv/maildivvy/store", None, None, "UUID=x")


def statvfs(blocks, avail, files=1000, favail=900):
    return SimpleNamespace(f_blocks=blocks, f_bavail=avail, f_files=files, f_favail=favail,
                           f_frsize=4096)


@pytest.mark.parametrize("avail,state", [(50, PASS), (15, WARN), (5, FAIL)])
def test_free_space_is_judged_against_both_bounds(avail, state):
    assert system.judge_free("store", "/srv", statvfs(100, avail), CONF).state == state


def test_running_out_of_inodes_is_running_out_of_space():
    assert system.judge_free("store", "/srv", statvfs(100, 90, 1000, 20), CONF).state == FAIL


def test_memory_and_swap():
    info = system.meminfo("MemTotal: 3476344 kB\nMemAvailable: 1299936 kB\n"
                          "SwapTotal: 3847164 kB\nSwapFree: 3847164 kB\n")
    assert system.judge_memory(info, CONF).state == PASS
    assert system.judge_swap(info).state == PASS
    assert system.judge_memory({**info, "MemAvailable": 100 * 1024 ** 2}, CONF).state == FAIL
    assert system.judge_swap({**info, "SwapTotal": 0, "SwapFree": 0}).state == WARN


# --- network and ban (driven on the machine too) --------------------------------------------


def test_the_installed_listeners_pass_and_loopback_is_excluded_by_address_not_port():
    assert system.judge_listeners(SS).state == PASS   # the random containerd port is loopback


def test_a_missing_or_an_unexpected_listener_off_loopback_fails():
    missing = system.judge_listeners("\n".join(line for line in SS.splitlines() if ":465 " not in line))
    assert missing.state == FAIL and "465" in missing.problem
    extra = system.judge_listeners(SS + "tcp LISTEN 0 100 0.0.0.0:25 0.0.0.0:*\n")
    assert extra.state == FAIL and "0.0.0.0:25" in extra.problem


def test_an_empty_unexpected_set_is_trusted_only_beside_the_expected_ones_found():
    with pytest.raises(Unreadable):
        system.judge_listeners("tcp LISTEN 0 200 127.0.0.1:5432 0.0.0.0:*\n")


USER_RULES = """\
### tuple ### allow tcp 22 0.0.0.0/0 any 192.0.2.0/24 in
### tuple ### allow tcp 443 0.0.0.0/0 any 192.0.2.0/24 in
"""
FIREWALL = {"enabled": "yes", "input_policy": {"4": "DROP", "6": "DROP"}, "user_rules": USER_RULES,
            "docker_block": "-A DOCKER-USER -j maildivvy-docker-deny\n-A maildivvy-docker-deny -j DROP",
            "families": {"4": "", "6": ""}}


def test_the_input_policy_is_read_and_judged_for_each_family():
    """The policy was read from both families' rules run together,
    so only IPv4's first `-P INPUT` was ever seen: IPv6 accepting everything read PASS."""
    families = {"4": "-P INPUT DROP\n-P FORWARD DROP\n", "6": "-P INPUT ACCEPT\n-P FORWARD DROP\n"}
    assert helper.input_policies(families) == {"4": "DROP", "6": "ACCEPT"}
    found = system.judge_firewall({**FIREWALL, "input_policy": {"4": "DROP", "6": "ACCEPT"}}, published=False)
    assert found.state == FAIL and "IPv6 incoming traffic is ACCEPT" in found.problem
    assert system.judge_firewall({**FIREWALL, "input_policy": {"4": "DROP", "6": ""}}, published=False).state == FAIL


def test_the_firewall_scope_is_asserted_not_the_presence_of_a_rule():
    assert system.judge_firewall(FIREWALL, published=False).state == PASS
    open_ssh = {**FIREWALL, "user_rules": USER_RULES.replace("192.0.2.0/24 in\n### tuple ### allow tcp 443",
                                                             "0.0.0.0/0 in\n### tuple ### allow tcp 443", 1)}
    assert system.judge_firewall(open_ssh, published=False).state == FAIL
    assert system.judge_firewall({**FIREWALL, "enabled": "no"}, published=False).state == FAIL
    assert system.judge_firewall({**FIREWALL, "docker_block": "-A DOCKER-USER -j RETURN"},
                                 published=False).state == FAIL
    # the mail ports: closed until publication, and never closed again after it
    assert system.judge_firewall(FIREWALL, published=True).state == FAIL
    mail = USER_RULES + ("### tuple ### allow tcp 993 0.0.0.0/0 any 0.0.0.0/0 in\n"
                         "### tuple ### allow tcp 465 0.0.0.0/0 any 0.0.0.0/0 in\n")
    assert system.judge_firewall({**FIREWALL, "user_rules": mail}, published=True).state == PASS
    assert system.judge_firewall({**FIREWALL, "user_rules": mail}, published=False).state == FAIL


def test_a_container_publishing_a_port_or_on_host_networking_fails():
    good = [{"name": "maildivvy-rspamd-1", "network_mode": "maildivvy_default", "published": []}]
    assert system.judge_containers(good).state == PASS
    assert system.judge_containers([{**good[0], "published": ["*:11334->11334/tcp"]}]).state == FAIL
    assert system.judge_containers([{**good[0], "network_mode": "host"}]).state == FAIL


def test_publication_reads_unknown_until_the_outside_probe_is_recorded():
    name, leaf = "mail.example.test", "c3" * 32

    def judge(record):
        return system.judge_publication(record, NOW, CONF, name, leaf)
    assert judge(None).state == UNKNOWN
    # step 19 opened the ports and wrote when: still no result from outside
    opened = {"published_at": (NOW - datetime.timedelta(days=2)).isoformat()}
    found = judge(opened)
    assert found.state == UNKNOWN and "outside probe" in found.problem
    fresh = {**opened, "proved_at": (NOW - datetime.timedelta(days=1)).isoformat(), "result": PASS,
             "probe": {"host": name, "leaf_sha256": {"imaps": leaf, "submissions": leaf}}}
    assert judge(fresh).state == PASS
    assert judge({**fresh, "result": FAIL}).state == FAIL
    stale = {**fresh, "proved_at": (NOW - datetime.timedelta(days=CONF.publication_days + 1)).isoformat()}
    assert judge(stale).state == UNKNOWN


def test_the_mail_ports_count_as_published_only_once_step_19_has_written_so():
    assert system.published(None) is False
    assert system.published({"published_at": NOW.isoformat()}) is True
    # a result with no publication behind it does not make open ports legitimate
    assert system.published({"proved_at": NOW.isoformat(), "result": PASS}) is False


LIMITS4 = """\
-P INPUT DROP
-N maildivvy-mail-limit
-A ufw-before-input -p tcp -m multiport --dports 993,465 -m conntrack --ctstate NEW -j maildivvy-mail-limit
-A ufw-before-input -i lo -j ACCEPT
-A maildivvy-mail-limit -i lo -j RETURN
-A maildivvy-mail-limit -s 192.0.2.0/24 -j RETURN
-A maildivvy-mail-limit -p tcp -m tcp --dport 993 -m hashlimit --hashlimit-above 30/min --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name maildivvy-imaps -j DROP
-A maildivvy-mail-limit -p tcp -m tcp --dport 465 -m hashlimit --hashlimit-above 10/min --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name maildivvy-submissions -j DROP
"""
LIMITS = {"4": LIMITS4, "6": LIMITS4.replace("ufw-before-input", "ufw6-before-input")
                                    .replace("-A maildivvy-mail-limit -s 192.0.2.0/24 -j RETURN\n", "")}


def test_rate_limits_are_read_per_family_and_must_be_reached_from_ufws_input():
    assert system.judge_rate_limits(LIMITS, published=True).state == PASS
    # nothing jumps to the chain over IPv6: its rules limit nothing there
    unreached = {**LIMITS, "6": LIMITS["6"].replace("-j maildivvy-mail-limit\n", "-j RETURN\n", 1)}
    found = system.judge_rate_limits(unreached, published=True)
    assert found.state == FAIL and "IPv6" in found.problem and "IPv4" not in found.problem
    # 465 not limited over IPv4
    no_submissions = {**LIMITS, "4": "\n".join(line for line in LIMITS4.splitlines() if "--dport 465" not in line)}
    found = system.judge_rate_limits(no_submissions, published=True)
    assert found.state == FAIL and "465" in found.problem and "993" not in found.problem
    # a limit in a chain nothing on the mail ports' path reaches is not a limit
    elsewhere = {**LIMITS, "4": LIMITS4.replace("-A maildivvy-mail-limit -p tcp -m tcp --dport 993",
                                                "-A someone-else -p tcp -m tcp --dport 993")}
    assert system.judge_rate_limits(elsewhere, published=True).state == FAIL
    # not published: nothing to limit yet, whatever the ruleset says
    assert system.judge_rate_limits({"4": "", "6": ""}, published=False).state == PASS


def test_the_jail_list_is_read_from_its_anchored_line_alone():
    status = "Status\n|- Number of jail:\t1\n`- Jail list:\tpostfix\n# dovecot-local present\n"
    found = system.judge_fail2ban({"installed": True, "answers": True, "status": status})
    assert states(found) == [PASS, FAIL]
    assert "dovecot" in found[1].problem
    both = status.replace("postfix\n", "dovecot, postfix\n")
    assert states(system.judge_fail2ban({"installed": True, "answers": True, "status": both})) == [PASS, PASS]
    assert states(system.judge_fail2ban({"installed": False})) == [FAIL]


# --- tls ----------------------------------------------------------------------------


def test_the_expiry_is_unknown_not_fail_until_every_endpoint_serves(monkeypatch):
    monkeypatch.setattr(services, "not_after", lambda der: NOW + datetime.timedelta(days=300))
    found = services.judge_expiry({993: b"a", 465: b"a", 443: Unreadable("refused")}, b"a", NOW, CONF)
    assert found.state == UNKNOWN and "443" in found.problem
    assert services.judge_expiry({993: b"a", 465: b"a", 443: b"a"}, b"a", NOW, CONF).state == PASS


def test_an_endpoint_serving_another_certificate_fails(monkeypatch):
    monkeypatch.setattr(services, "not_after", lambda der: NOW + datetime.timedelta(days=300))
    found = services.judge_expiry({993: b"a", 465: b"old", 443: b"a"}, b"a", NOW, CONF)
    assert found.state == FAIL and "465" in found.problem


def test_the_published_certificate_is_the_leaf_of_a_published_chain(tmp_path):
    # lego's .crt, republished as is, is the leaf and then the CA's certificate: the leaf is
    # what the endpoints serve first. Found by the live staging issuance: the
    # whole file read as one certificate made every endpoint "another certificate".
    import ssl
    import subprocess
    pems = []
    for name in ("leaf.test", "ca.test"):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "1", "-subj", f"/CN={name}", "-keyout", str(tmp_path / f"{name}.key"),
                        "-out", str(tmp_path / f"{name}.crt")], check=True, capture_output=True)
        pems.append((tmp_path / f"{name}.crt").read_text())
    chain = tmp_path / "chain.crt"
    chain.write_text("".join(pems))
    single = tmp_path / "single.crt"
    single.write_text(pems[0])
    leaf = ssl.PEM_cert_to_DER_cert(pems[0])
    assert services.published_der(str(chain)) == leaf
    assert services.published_der(str(single)) == leaf  # the control: one certificate alone
    assert services.fingerprint(services.published_der(str(chain))) == services.fingerprint(leaf)
    empty = tmp_path / "empty.crt"
    empty.write_text("no certificate here\n")
    with pytest.raises(Unreadable):
        services.published_der(str(empty))


@pytest.mark.parametrize("days,state", [(60, PASS), (14, WARN), (3, FAIL)])
def test_the_days_left_are_judged_against_both_bounds(monkeypatch, days, state):
    monkeypatch.setattr(services, "not_after", lambda der: NOW + datetime.timedelta(days=days))
    assert services.judge_expiry({993: b"a", 465: b"a", 443: b"a"}, b"a", NOW, CONF).state == state


@pytest.mark.parametrize("days,state", [(40, PASS), (30, PASS), (29.9, WARN), (25, WARN), (8, WARN), (7, WARN),
                                        (6.9, FAIL), (5, FAIL)])
def test_a_provided_certificate_warns_30_days_and_fails_7_days_before_it_expires(monkeypatch, days, state):
    # nothing renews it: the operator is told a month ahead, not at lego's 21 days
    monkeypatch.setattr(services, "not_after", lambda der: NOW + datetime.timedelta(days=days))
    found = services.judge_expiry({993: b"a", 465: b"a", 443: b"a"}, b"a", NOW, CONF, mode="provided")
    assert found.state == state
    if state == WARN:
        assert "maildivvy-cert install-provided" in found.problem
    acme = services.judge_expiry({993: b"a", 465: b"a", 443: b"a"}, b"a", NOW, CONF).state
    assert acme == (PASS if days >= 21 else WARN if days >= 7 else FAIL)  # the control: acme's own bounds


def test_a_provided_certificate_is_a_pass_as_a_mode_and_says_who_renews_it():
    ctx = SimpleNamespace(certificate=lambda: {"mode": "provided", "cert_name": "mail.example.org"})
    found = services.certificate_mode(ctx)
    assert found.state == PASS and "renewed by the operator" in found.reading


def test_the_renewal_is_read_from_its_last_run_through_systemd():
    shown = {"Result": "success", "ExecMainStatus": "0",
             "ExecMainExitTimestamp": "Wed 2026-09-23 10:59:37 UTC"}
    assert services.judge_renewal(True, shown).state == PASS
    assert services.judge_renewal(True, {**shown, "Result": "exit-code", "ExecMainStatus": "1"}).state == FAIL
    assert services.judge_renewal(False, shown).state == FAIL
    assert services.judge_renewal(True, {**shown, "ExecMainExitTimestamp": ""}).state == UNKNOWN


# ⚠️ found by a reboot test: systemd forgets a oneshot's last run at every boot, so a
# daily renewal read only through `systemctl show` said "never run" - UNKNOWN - for up to a
# day after every reboot. The journal keeps the run across boots (read a unit's
# effect from its journal).
def test_after_a_reboot_the_renewals_last_run_is_read_from_the_journal():
    after_boot = {"Result": "success", "ExecMainStatus": "0", "ExecMainExitTimestamp": ""}
    moment = datetime.datetime(2026, 9, 23, 18, 36, 49, tzinfo=datetime.timezone.utc)
    found = services.judge_renewal(True, after_boot, (moment, "done"))
    assert found.state == PASS and "2026-09-23T18:36:49" in found.reading and "journal" in found.reading
    assert services.judge_renewal(True, after_boot, (moment, "failed")).state == FAIL
    assert services.judge_renewal(True, after_boot, (moment, "timeout")).state == FAIL
    assert services.judge_renewal(True, after_boot, None).state == UNKNOWN  # in neither: never run
    assert services.judge_renewal(False, after_boot, (moment, "done")).state == FAIL
    # a run since the boot is systemd's own reading, whatever an older journal line says
    ran = {**after_boot, "ExecMainExitTimestamp": "Wed 2026-09-23 19:59:37 UTC"}
    assert services.judge_renewal(True, ran, (moment, "failed")).state == PASS


def test_a_units_last_finished_start_job_is_read_from_the_journal_newest_first():
    # the shapes systemd 259 journals for a start job (measured 2026-09-23): the start line
    # has no JOB_RESULT, the end of the job has `done`, or `failed` for a failed oneshot
    starting = {"MESSAGE": "Starting maildivvy-cert-renew.service - ...", "JOB_TYPE": "start",
                "__REALTIME_TIMESTAMP": "1790188374351722"}
    done = {"MESSAGE": "Finished maildivvy-cert-renew.service - ...", "JOB_TYPE": "start",
            "JOB_RESULT": "done", "__REALTIME_TIMESTAMP": "1790188374407610"}
    failed = {**done, "JOB_RESULT": "failed", "__REALTIME_TIMESTAMP": "1790188609102649"}
    again = {**starting, "__REALTIME_TIMESTAMP": "1790188700000000"}  # a run still going
    lines = [json.dumps(entry) for entry in (starting, done, failed, again)]
    assert probe.finished_start_job(lines) == (
        datetime.datetime.fromtimestamp(1790188609.102649, datetime.timezone.utc), "failed")
    assert probe.finished_start_job(lines[:2])[1] == "done"
    assert probe.finished_start_job(lines[:1]) is None  # started and never finished
    assert probe.finished_start_job([]) is None


# --- dovecot ------------------------------------------------------------------------------------


def test_the_login_that_cannot_exist_proves_the_passdb_answered():
    caps = ["IMAP4REV1", "AUTH=PLAIN"]
    assert services.judge_imap(caps, "b'[AUTHENTICATIONFAILED] Authentication failed.'").state == PASS
    assert services.judge_imap(caps, "b'[UNAVAILABLE] Temporary authentication failure.'").state == FAIL
    assert services.judge_imap(caps, "OK").state == FAIL


DOVECONF = """\
mail_path = %{home}/Maildir
mail_plugins {
  acl = yes
  fts = yes
}
namespace inbox {
  mailbox Sent {
    special_use = "\\\\Sent"
  }
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}
fts flatcurve {
  substring_search = no
}
"""


def test_the_effective_configuration_is_asserted_with_mail_path_as_the_parse_control():
    assert services.judge_dovecot_config(DOVECONF).state == PASS
    opened = DOVECONF.replace("    port = 0\n", "    port = 143\n")
    assert services.judge_dovecot_config(opened).state == FAIL
    compressed = DOVECONF.replace("  fts = yes\n", "  fts = yes\n  mail_compress = yes\n")
    assert services.judge_dovecot_config(compressed).state == FAIL
    second = DOVECONF.replace("namespace inbox {", 'namespace inbox {\n  mailbox "Sent Messages" {\n'
                                                   '    special_use = "\\\\Sent"\n  }')
    assert services.judge_dovecot_config(second).state == FAIL
    with pytest.raises(Unreadable):
        services.judge_dovecot_config("")


def test_sent_hook_failures_are_counted_and_an_empty_window_needs_its_control():
    lines = ["imap-login: Login aborted: Connection closed (auth failed, 1 attempts in 2 secs)",
             "imap(ivan@alpha): Error: maildivvy-sent-hook: failed: cannot read db.conf"]
    found = services.judge_sent_failures(lines, 24)
    assert found.state == WARN and found.reading.startswith("1 failed")
    assert services.judge_sent_failures(lines[:1], 24).state == PASS
    with pytest.raises(Unreadable):
        services.judge_sent_failures([], 24)


# --- postfix and the milter -------------------------------------------------------


def test_both_transports_are_error():
    error = "error:no per-sender transport for this sender"
    assert services.judge_transports(error, error).state == PASS
    assert services.judge_transports("smtp", error).state == FAIL


def test_the_milter_is_bound_on_submissions_and_nowhere_globally():
    per_service = "submissions/inet/syslog_name = postfix/submissions\n" \
                  "submissions/inet/smtpd_milters = unix:maildivvy/milter.sock\n"
    assert services.judge_milter_binding(per_service, "", "").state == PASS
    assert services.judge_milter_binding("", "", "").state == FAIL
    assert services.judge_milter_binding(per_service, "unix:maildivvy/milter.sock", "").state == FAIL


def test_the_queue_is_judged_by_its_oldest_message():
    old = int((NOW - datetime.timedelta(hours=2)).timestamp())
    assert services.judge_queue([], NOW, CONF).state == PASS
    assert services.judge_queue([json.dumps({"arrival_time": old})], NOW, CONF).state == WARN
    ancient = int((NOW - datetime.timedelta(days=2)).timestamp())
    assert services.judge_queue([json.dumps({"arrival_time": ancient})], NOW, CONF).state == FAIL


def test_the_milter_is_running_its_socket_is_postfixs_and_it_negotiates():
    reading = {"path": "/var/spool/postfix/maildivvy/milter.sock",
               "socket": {"exists": True, "kind": "socket", "group": "postfix", "mode": "0770"},
               "negotiation": {"version": 6}}
    assert states(services.judge_milter(True, reading)) == [PASS, PASS, PASS]
    wrong = {**reading, "socket": {**reading["socket"], "group": "root"}}
    assert states(services.judge_milter(True, wrong)) == [PASS, FAIL, PASS]
    gone = {**reading, "socket": {"exists": False}, "negotiation": {"error": "no such file"}}
    assert states(services.judge_milter(False, gone)) == [FAIL, FAIL, FAIL]


# --- search ---------------------------------------------------------------------------


def test_a_search_answered_by_reading_messages_is_told_from_one_the_index_answered():
    base = {"domain": "alpha", "uid": 4}
    assert services.judge_search({**base, "whole": True, "part": False}).state == PASS
    assert services.judge_search({**base, "whole": True, "part": True}).state == FAIL
    assert services.judge_search({**base, "whole": False, "part": False}).state == FAIL
    assert services.judge_search({"domain": None}).state == UNKNOWN
    assert services.judge_plugins(["acl", "fts", "fts_flatcurve"], "no").state == PASS
    assert services.judge_plugins(["acl"], "no").state == FAIL
    assert services.judge_plugins(["fts", "fts_flatcurve"], "yes").state == FAIL


def test_the_word_searched_for_has_an_inner_part_that_is_no_word_of_the_message():
    assert helper.search_word("a body about rhubarb crumble") == ("crumble", "rumbl")
    # `bando` is a word of this body, so a search for it would find the message whether
    # or not the index answered: no word here tells the two apart
    assert helper.search_word("abandon bando") is None
    assert helper.search_word("short words only") is None


HTML_LETTER = """\
MIME-Version: 1.0
Subject: Pudding
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

QSBub3RlIGFib3V0IHJodWJhcmIgY3J1bWJsZS4K

--b1
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<html><head><style>.aardvarks { color: black }</style></head><body>
<p class=3D"aardvarks" style=3D"background:white">A note about rhubarb crum=
ble.</p><!-- abacuses --></body></html>

--b1--
"""


def test_the_word_searched_for_is_one_the_index_holds_not_one_of_the_markup():
    # The index holds the decoded text of a letter, its HTML as text: a word that sits only
    # in a tag, a style or a comment is rightly not found, and the check read FAIL on a
    # healthy index whenever the newest letter was HTML. Here the first such word of the
    # raw letter is `aardvarks`, and `crumble` is base64 in one part and split by a soft
    # line break in the other.
    assert helper.search_word(HTML_LETTER) == ("crumble", "rumbl")
    markup_only = HTML_LETTER.replace("A note about rhubarb crum=\nble.", "")
    assert helper.search_word(markup_only.replace("QSBub3RlIGFib3V0IHJodWJhcmIgY3J1bWJsZS4K", "")) is None
    # Dovecot puts a space where a tag was, so `crum` and `ble` are two words of the index,
    # and a word touching a digit, an underscore or an at sign is part of a longer one
    assert helper.search_word("Subject: x\n\n<b>crum</b>ble note_rhubarb rhubarb2 rhubarb@x.example\n") is None
    # a letter whose charset Python cannot read is skipped, never guessed at
    assert helper.search_word("Content-Type: text/plain; charset=x-unknown\n\nrhubarb crumble\n") is None


# --- antivirus ---------------------------------------------------------------------


CLEAN = Verdict(scan.CLEAN, "stream: OK")


def test_the_antivirus_answers_and_its_signatures_are_fresh():
    fresh = Version("1.5.4", 28132, datetime.datetime(2026, 9, 23, 6, 24, 42, tzinfo=UTC))
    assert states(scanners.judge_clamd(True, fresh, CLEAN, NOW, CONF)) == [PASS, PASS]
    old = Version("1.5.4", 28100, NOW - datetime.timedelta(days=10))
    assert states(scanners.judge_clamd(True, old, CLEAN, NOW, CONF)) == [PASS, FAIL]
    assert states(scanners.judge_clamd(True, None, None, NOW, CONF)) == [FAIL]


def test_an_antivirus_that_says_its_version_but_cannot_scan_a_clean_sample_fails():
    """`VERSION` is answered by a daemon whose scanning is broken: only a sample streamed
    through the product's own client shows that mail could not be scanned."""
    fresh = Version("1.5.4", 28132, NOW - datetime.timedelta(hours=3))
    for verdict in (Verdict(scan.UNAVAILABLE, "clamd: Can't allocate memory ERROR"),
                    Verdict(scan.INFECTED, "stream: Eicar-Test-Signature FOUND"),
                    Verdict(scan.UNSCANNED, "clamd: Heuristics.Limits.Exceeded.MaxScanTime FOUND")):
        found = scanners.judge_clamd(True, fresh, verdict, NOW, CONF)
        assert states(found) == [FAIL, PASS], verdict
        assert verdict.detail in found[0].problem
    assert scanners.judge_clamd(True, fresh, CLEAN, NOW, CONF)[0].state == PASS   # the control


def test_mail_held_at_the_provider_fails_from_the_first_hold_and_names_since_when():
    since = NOW - datetime.timedelta(minutes=4)
    found = scanners.judge_held([("Ivan.P@example.org", since)], 3)
    assert found.state == FAIL and since.isoformat(timespec="seconds") in found.problem
    assert scanners.judge_held([], 3).state == PASS


def test_a_newer_clamav_upstream_warns_and_fails_after_the_bound():
    assert scanners.judge_upstream("1.5.4", "1.4.6", None, NOW, CONF).state == PASS
    assert scanners.judge_upstream("1.5.4", "1.5.5", NOW - datetime.timedelta(days=2), NOW, CONF).state == WARN
    assert scanners.judge_upstream("1.5.4", "1.5.5", NOW - datetime.timedelta(days=9), NOW, CONF).state == FAIL


def test_an_upstream_answer_is_kept_while_fresh_and_asked_again_after(tmp_path):
    path = tmp_path / "upstream.json"
    asked = []

    def ask():
        asked.append(1)
        return "1.4.6"
    assert upstream.cached(path, "clamav", NOW, 6, ask)[0] == "1.4.6"
    assert upstream.cached(path, "clamav", NOW + datetime.timedelta(hours=5), 6, ask)[0] == "1.4.6"
    assert len(asked) == 1
    upstream.cached(path, "clamav", NOW + datetime.timedelta(hours=7), 6, ask)
    assert len(asked) == 2


def test_an_upstream_that_cannot_be_read_is_unknown_never_nothing_newer(tmp_path):
    def ask():
        raise Unreadable("the TXT record could not be read")
    with pytest.raises(Unreadable):
        upstream.cached(tmp_path / "upstream.json", "clamav", NOW, 6, ask)


def test_a_newer_rspamd_patch_on_the_pinned_line_is_a_repin_due():
    tags = ["asan-4.2.0", "4.2.0", "4.2.0-0", "4.2.1", "4.3.0", "latest"]
    assert upstream.newest_patch(tags, "4.2.0") == "4.2.1"
    assert scanners.judge_repin("4.2.0", "4.2.1").state == FAIL
    assert scanners.judge_repin("4.2.0", upstream.newest_patch(["4.2.0", "4.3.0"], "4.2.0")).state == PASS


# --- spam ----------------------------------------------------------------

WRITE_LOG = ("2026-09-23 11:27:15 #8(normal) <9acee6>; task; rspamd_task_write_log: id: "
             "<probe@health.invalid>, (default: T (add header): [7.50/150.00] [HFILTER(2.50){}])")
PIN_LINE = ("2026-09-23 11:27:15 #8(normal) <9acee6>; lua; rspamd.local.lua:85: sender not pinned: "
            "no Received header by a listed provider host")


def test_the_probe_is_scored_and_the_products_own_rule_ran_on_it():
    tag = scanners.task_tag([PIN_LINE, WRITE_LOG], "probe@health.invalid")
    assert tag == "9acee6"
    assert states(scanners.judge_scored(Score(7.5, "add header"), tag, True)) == [PASS, PASS]
    assert states(scanners.judge_scored(Score(7.5, "add header"), tag, False)) == [PASS, FAIL]
    assert states(scanners.judge_scored(Score(None, "unavailable", "refused"), None, False)) == [FAIL]


CONFIGDUMP = """\
Modules enabled: once_received, regexp, hfilter, mime_types, phishing, spf, dkim, dmarc, arc
Modules disabled (explicitly): external_relay, rbl
Modules disabled (failed): \n"""


def test_the_modules_are_read_out_of_the_daemon_and_a_refused_one_fails():
    assert scanners.judge_modules(CONFIGDUMP).state == PASS
    assert scanners.judge_modules(CONFIGDUMP.replace(", dmarc", "")).state == FAIL
    failed = CONFIGDUMP.replace("(failed): ", "(failed): multimap")
    assert scanners.judge_modules(failed).state == FAIL
    with pytest.raises(Unreadable):
        scanners.judge_modules("")


def test_a_configuration_error_since_the_start_fails_and_the_start_line_is_the_control():
    start = "#1(main) <2a2962>; main; main: rspamd 4.2.0 is loading configuration, build id: x"
    assert scanners.judge_config_log([start, PIN_LINE], "t").state == PASS
    error = "#1(main); cfg; rspamd_rcl_section_parse: config schema error: unknown_field `trust`"
    assert scanners.judge_config_log([start, error], "t").state == FAIL
    with pytest.raises(Unreadable):
        scanners.judge_config_log([PIN_LINE], "t")


def test_the_runtimes_start_time_is_read_to_the_second():
    assert scanners.docker_time("2026-09-23T11:00:46.524796232Z") == datetime.datetime(
        2026, 9, 23, 11, 0, 46, tzinfo=UTC)


# --- collection -------------------------------------


BOUND = datetime.timedelta(minutes=30)     # how long collection may go unfetched


def mailbox(**overrides):
    row = {"id": 6, "address": "Ivan.P@example.org", "state": "active", "window": 14,
           "fetched_at": NOW - datetime.timedelta(minutes=2), "status": "no_new_mail", "cause": None,
           "detail": None, "frozen_since": None, "skipped_at": None, "skipped_uidl": None,
           "domain": "alpha", "kept": False, "protocol": "pop3", "oversize_at": None,
           "oversize_uid": None, "oversize_size": None}
    row.update(overrides)
    return row


def test_a_frozen_or_refused_mailbox_fails_naming_it_and_its_detail():
    frozen = data.judge_mailbox(mailbox(frozen_since=NOW - datetime.timedelta(hours=3)), NOW, BOUND, False)
    assert frozen.state == FAIL and frozen.name == "Ivan.P@example.org"
    refused = data.judge_mailbox(mailbox(status="auth_failed", cause="transient",
                                         detail="mpop: authentication failed (method USER)"), NOW, BOUND, False)
    assert refused.state == FAIL and "authentication failed" in refused.reading
    assert data.judge_mailbox(mailbox(status="error", cause="unreachable"), NOW, BOUND, False).state == FAIL
    assert data.judge_mailbox(mailbox(), NOW, BOUND, False).state == PASS
    assert data.judge_mailbox(mailbox(state="deactivated", status="error"), NOW, BOUND, False).state == PASS


def test_collection_fails_when_no_fetch_run_completes_or_a_row_goes_unfetched():
    """Whole-run failures that touch no row - a unit that will not
    start, EX_CONFIG, an exception before any status - left the last `ok` standing, and
    collection read PASS while nothing was collected. The fetch unit's last run is read as
    the fan-out's is, and each collected row's age against the bound."""
    bound = datetime.timedelta(minutes=30)
    shown = {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0",
             "ExecMainExitTimestamp": "Wed 2026-09-23 11:58:02 UTC", "ExecMainStartTimestamp": ""}
    assert data.judge_fetch_runs(shown, NOW, bound, "").state == PASS
    failed = data.judge_fetch_runs({**shown, "Result": "exit-code", "ExecMainStatus": "78"}, NOW, bound, "")
    assert failed.state == FAIL and "journalctl -u maildivvy-fetch.service" in failed.problem
    old = {**shown, "ExecMainExitTimestamp": "Wed 2026-09-23 11:00:00 UTC"}
    assert data.judge_fetch_runs(old, NOW, bound, "").state == FAIL
    assert data.judge_fetch_runs(old, NOW, bound, data.BACKUP_PAUSE).state == WARN   # the backup's pause
    going = {**old, "ActiveState": "activating", "ExecMainStartTimestamp": "Wed 2026-09-23 11:50:00 UTC"}
    assert data.judge_fetch_runs(going, NOW, bound, "").state == PASS       # a run is going
    stuck = {**going, "ExecMainStartTimestamp": "Wed 2026-09-23 11:00:00 UTC"}
    assert data.judge_fetch_runs(stuck, NOW, bound, "").state == WARN
    never = {**shown, "ExecMainExitTimestamp": ""}
    assert data.judge_fetch_runs(never, NOW, bound, "").state == UNKNOWN
    # a collected row not fetched within the bound fails; paused or mid-run it warns
    stale = mailbox(fetched_at=NOW - datetime.timedelta(minutes=45))
    found = data.judge_mailbox(stale, NOW, bound, quiet=False)
    assert found.state == FAIL and "not fetched in 30 min" in found.problem
    assert data.judge_mailbox(stale, NOW, bound, quiet=True).state == WARN
    assert data.judge_mailbox(mailbox(), NOW, bound, quiet=False).state == PASS
    assert data.judge_mailbox(mailbox(state="deactivated", fetched_at=NOW - datetime.timedelta(days=9)),
                              NOW, bound, quiet=False).state == PASS


def test_deliveries_the_filter_could_not_check_warn_and_an_empty_window_is_no_reading():
    """A regressed wiring stores as before; the runner's
    journal carries the filter's words, and health counts them as a WARN."""
    lines = ["Starting maildivvy-fetch.service - Maildivvy: collect mail...",
             "maildivvy-fetch.service: Deactivated successfully."]
    assert data.judge_retrieval(lines, 24).state == PASS
    unchecked = lines + [f"maildivvy-fetch: a@example.org: maildivvy: {retrieval.UNCHECKED}: no pipe"]
    found = data.judge_retrieval(unchecked, 24)
    assert found.state == WARN and "1 deliver" in found.reading and "half-read one out" in found.problem
    assert data.judge_retrieval([], 24).state == UNKNOWN


def test_messages_the_pass_skipped_warn_and_an_empty_window_is_no_reading():
    """A skipped message is in the archive and reaches nobody until it is recorded by
    hand: health counts the pass's lines for it, over a window that must hold its runs."""
    lines = ["Starting maildivvy-pass.service - Maildivvy: record and fan out...",
             "maildivvy-pass: example INBOX: 2 recorded",
             "maildivvy-pass.service: Deactivated successfully."]
    assert data.judge_skipped(lines, 24).state == PASS
    found = data.judge_skipped(lines + [f"{pass_.SKIPPED} example INBOX UID 2: ..."], 24)
    assert found.state == WARN and found.reading.startswith("1 message")
    assert pass_.SKIPPED in found.problem
    assert data.judge_skipped([], 24).state == UNKNOWN
    import yaml
    health_vars = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health" / "vars" / "main.yml"
    assert "store/fan-out skips" in yaml.safe_load(health_vars.read_text())["maildivvy_health_no_data_yet"]


def test_the_collection_bound_is_three_fetch_periods_at_least():
    assert data.collection_bound(CONF, datetime.timedelta(minutes=3)) == datetime.timedelta(minutes=30)
    assert data.collection_bound(CONF, datetime.timedelta(minutes=60)) == datetime.timedelta(minutes=180)
    assert data.collection_bound(CONF, None) == datetime.timedelta(minutes=CONF.collection_minutes)


@pytest.mark.parametrize("word, paused", [("activating", True), ("deactivating", True), ("active", True),
                                          ("inactive", False), ("failed", False)])
def test_a_running_backup_is_read_as_the_pause_it_is(monkeypatch, word, paused):
    """The backup is a oneshot, `activating` for the whole of its run
    and never `active`, so the pause read `is-active` and never saw it: every backup read the
    collection timer, the fan-out timer and fan-out freshness as FAIL."""
    monkeypatch.setattr(probe, "command", lambda argv, **kw: SimpleNamespace(stdout=word + "\n", returncode=3))
    assert data.paused_for_backup() is paused


def test_an_upgrades_pause_is_read_as_the_pause_it_is(monkeypatch, tmp_path):
    """Through an upgrade's steps the timers are stopped on purpose, and stay so after one
    that failed past its migrations: install step 17 and the operator read WARN, not FAIL."""
    from maildivvy.installer import upgrade
    assert data.UPGRADE_PAUSE == upgrade.PAUSE_RECORD
    monkeypatch.setattr(probe, "command", lambda argv, **kw: SimpleNamespace(stdout="inactive\n", returncode=3))
    monkeypatch.setattr(data, "UPGRADE_PAUSE", tmp_path / "upgrade-paused.json")
    assert data.pause_reason() == ""
    data.UPGRADE_PAUSE.write_text("[]")
    why = data.pause_reason()
    assert why.startswith("paused by an upgrade")
    timer = data.judge_timer("collection timer", data.FETCH_TIMER, False, why)
    assert (timer.state, timer.problem) == (WARN, why)
    old = {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0",
           "ExecMainExitTimestamp": "Wed 2026-09-23 11:00:00 UTC",
           "ExecMainStartTimestamp": ""}
    runs = data.judge_fetch_runs(old, NOW, datetime.timedelta(minutes=30), why)
    assert (runs.state, runs.problem) == (WARN, why)


def test_a_recorded_pause_holds_collection_whatever_the_timer_reads(monkeypatch, tmp_path):
    """The units refuse to start while a pause is recorded, so a timer a reboot started runs
    nothing: an active timer reads WARN under the record, which names its holder."""
    from maildivvy.backup import pause
    assert data.BACKUP_PAUSE_RECORD == backup_status.STATUS.parent / "paused.json"
    monkeypatch.setattr(probe, "command", lambda argv, **kw: SimpleNamespace(stdout="inactive\n", returncode=3))
    monkeypatch.setattr(data, "UPGRADE_PAUSE", tmp_path / "upgrade-paused.json")
    monkeypatch.setattr(data, "BACKUP_PAUSE_RECORD", tmp_path / "paused.json")
    assert data.judge_timer("collection timer", data.FETCH_TIMER, True, data.pause_reason()).state == PASS
    data.UPGRADE_PAUSE.write_text("{}")
    timer = data.judge_timer("collection timer", data.FETCH_TIMER, True, data.pause_reason())
    assert timer.state == WARN and timer.reading.endswith(" active") and "upgrade" in timer.problem
    data.UPGRADE_PAUSE.unlink()
    pause.write_record(data.BACKUP_PAUSE_RECORD, [], {"by": "backup"})
    assert "no backup runs" in data.pause_reason()
    pause.write_record(data.BACKUP_PAUSE_RECORD, [], {"by": "restore", "stamp": "20261001T120000Z"})
    assert "--restore 20261001T120000Z" in data.pause_reason()
    assert data.BACKUP_PAUSE_RECORD.stat().st_mode & 0o777 == 0o644


def test_a_skipped_message_warns_until_its_provider_deletion_date_and_names_it():
    skipped = mailbox(skipped_at=NOW - datetime.timedelta(days=2), skipped_uidl="uidl-42")
    found = data.judge_mailbox(skipped, NOW, BOUND, False)
    assert found.state == WARN and "uidl-42" in found.reading
    assert (NOW + datetime.timedelta(days=12)).date().isoformat() in found.problem
    expired = mailbox(skipped_at=NOW - datetime.timedelta(days=15), skipped_uidl="uidl-42")
    assert data.judge_mailbox(expired, NOW, BOUND, False).state == PASS


def test_a_skipped_message_kept_at_the_provider_has_no_deletion_date_to_warn_of():
    kept = mailbox(skipped_at=NOW - datetime.timedelta(days=2), skipped_uidl="uidl-42", kept=True)
    found = data.judge_mailbox(kept, NOW, BOUND, False)
    assert found.state == PASS
    assert "uidl-42" in found.reading and "kept at the provider" in found.reading


def test_a_message_passed_over_the_cap_warns_for_a_week_naming_its_uid_and_size():
    over = dict(protocol="imap", kept=True, skipped_at=NOW - datetime.timedelta(days=2),
                skipped_uidl="7/3", oversize_uid=3, oversize_size=60_000_000)
    found = data.judge_mailbox(mailbox(oversize_at=NOW - datetime.timedelta(days=2), **over),
                               NOW, BOUND, False)
    assert found.state == WARN and found.name == "Ivan.P@example.org"
    assert "message 3 of 60000000 bytes" in found.reading
    assert "60000000 bytes, over the 52428800-byte cap" in found.problem
    assert "stays at the provider" in found.problem
    later = mailbox(oversize_at=NOW - datetime.timedelta(days=8), **over)
    assert data.judge_mailbox(later, NOW, BOUND, False).state == PASS
    # a failed run still fails: the warning never hides it
    failed = mailbox(oversize_at=NOW - datetime.timedelta(days=2), **{**over, "status": "error"})
    assert data.judge_mailbox(failed, NOW, BOUND, False).state == FAIL


def test_zero_provider_rows_is_unknown_not_a_vacuous_pass():
    assert states(data.judge_mailboxes([], NOW, BOUND, False)) == [UNKNOWN]
    assert data.judge_windows([], {}).state == UNKNOWN


def test_each_collected_rows_configuration_carries_exactly_its_own_window():
    rows = [mailbox(), mailbox(id=7, address="b@example.org", fetched_at=None)]
    state = {"listed": True, "configs": {"6": {"keep": ["14d"]}}}
    assert data.judge_windows(rows, state).state == PASS
    for configs, text in [({}, "no-file"), ({"6": {"keep": []}}, "no-keep-line"),
                          ({"6": {"keep": ["30d"]}}, "keep 30d")]:
        found = data.judge_windows(rows, {"listed": True, "configs": configs})
        assert found.state == FAIL and text in found.problem
    with pytest.raises(Unreadable):
        data.judge_windows(rows, {"listed": False})


def test_a_row_kept_at_the_provider_must_render_keep_on_and_never_its_window():
    rows = [mailbox(kept=True)]
    assert data.judge_windows(rows, {"listed": True, "configs": {"6": {"keep": ["on"]}}}).state == PASS
    found = data.judge_windows(rows, {"listed": True, "configs": {"6": {"keep": ["14d"]}}})
    assert found.state == FAIL and "kept at the provider" in found.problem
    found = data.judge_windows([mailbox()], {"listed": True, "configs": {"6": {"keep": ["on"]}}})
    assert found.state == FAIL and "keep on against a window of 14 days" in found.problem


def test_an_imap_row_has_no_configuration_to_hold_and_is_not_missing_one():
    """Its client deletes nothing and renders no file, so `no-file` would be a false FAIL;
    a POP3 row beside it is still held to its own."""
    rows = [mailbox(protocol="imap", kept=True), mailbox(id=7, address="b@example.org")]
    found = data.judge_windows(rows, {"listed": True, "configs": {"7": {"keep": ["14d"]}}})
    assert found.state == PASS
    assert found.reading.startswith("2 rows (1 over IMAP, which renders none), 1 rendered")
    found = data.judge_windows(rows, {"listed": True, "configs": {}})
    assert found.state == FAIL and found.problem == "b@example.org: no-file"


def test_the_fetcher_is_the_units_own_binary_and_at_least_the_minimum():
    assert data.mpop_path("/opt/maildivvy/bin/maildivvy-fetch") == "/usr/local/bin/mpop"
    assert data.mpop_path("/opt/maildivvy/bin/maildivvy-fetch --mpop /opt/mpop") == "/opt/mpop"
    done = SimpleNamespace(returncode=0, stdout="mpop version 1.4.23\nPlatform: x86_64\n")
    assert data.judge_mpop("/usr/local/bin/mpop", done).state == PASS
    older = SimpleNamespace(returncode=0, stdout="mpop version 1.4.21\n")
    assert data.judge_mpop("/usr/bin/mpop", older).state == FAIL
    odd = SimpleNamespace(returncode=0, stdout="mpop version 1.4.23-rc1\n")
    assert data.judge_mpop("/usr/local/bin/mpop", odd).state == FAIL
    assert data.judge_mpop("/usr/local/bin/mpop", None).state == FAIL


# --- store --------------------------------------------


def ledger_reading(deliveries=4, findings=(), several=3, one=1):
    return {"domains": {"alpha": {"deliveries": deliveries, "mailboxes": 2, "findings": list(findings),
                                  "several_names": several, "one_name": one}}}


def test_a_name_with_no_delivery_row_fails_and_no_delivery_at_all_is_unknown():
    assert data.judge_ledger(ledger_reading()).state == PASS
    found = data.judge_ledger(ledger_reading(findings=["ivan: cur/1 is the archive's message 9 ..."]))
    assert found.state == FAIL and "message 9" in found.problem
    assert data.judge_ledger(ledger_reading(deliveries=0)).state == UNKNOWN


def test_both_link_count_classes_or_unknown():
    assert data.judge_links(ledger_reading()).state == PASS
    assert data.judge_links(ledger_reading(one=0)).state == UNKNOWN
    assert data.judge_links(ledger_reading(several=0)).state == UNKNOWN


def test_the_fan_out_ran_recently_and_succeeded():
    shown = {"Result": "success", "ExecMainStatus": "0",
             "ExecMainExitTimestamp": "Wed 2026-09-23 11:59:02 UTC"}
    assert states(data.judge_fanout(True, "", shown, NOW, CONF)) == [PASS, PASS]
    failed = {**shown, "Result": "exit-code", "ExecMainStatus": "1"}
    assert states(data.judge_fanout(True, "", failed, NOW, CONF)) == [PASS, FAIL]
    assert states(data.judge_fanout(False, "", shown, NOW, CONF)) == [FAIL, PASS]
    assert states(data.judge_fanout(False, data.BACKUP_PAUSE, shown, NOW, CONF)) == [WARN, PASS]


def test_a_pass_stopped_by_a_folder_renumbered_before_its_rows_were_named_fails_naming_each_once():
    shown = {"Result": "exit-code", "ExecMainStatus": "1",
             "ExecMainExitTimestamp": "Wed 2026-09-23 11:59:02 UTC"}
    line = (f"{pass_.UNNAMED} alpha INBOX: the archive's UIDVALIDITY is 222, the ledger's "
            "UIDs are 111's, ...")
    repaired = f"{pass_.RENUMBERED} delta INBOX: its numbering changed (UIDVALIDITY 9); ..."
    lines = ["maildivvy-pass: beta: DoveadmError: ...", line, repaired,
             line.replace("alpha", "gamma"), line]
    _, found = data.judge_fanout(True, "", shown, NOW, CONF, lines)
    assert found.state == FAIL and "linked from alpha INBOX; gamma INBOX: go back" in found.problem
    assert "--renumber" in found.problem and pass_.UNNAMED in found.problem
    # any other failure reads as before, and a folder the pass set right is no stop
    for others in (lines[:1], lines[:1] + [repaired]):
        _, other = data.judge_fanout(True, "", shown, NOW, CONF, others)
        assert other.state == FAIL and "renumber" not in other.problem


def test_a_folder_the_pass_set_right_after_a_renumbering_warns_naming_it_once():
    """Nothing is lost, but an index tree went missing or was put back: the operator is
    told, beside the skips, for as long as the line is in the window."""
    line = (f"{pass_.RENUMBERED} example INBOX: its numbering changed (UIDVALIDITY 222); 3 row(s) "
            "given their files' new UIDs by base name, 1 file(s) with no row recorded, 0 row(s) "
            "with no file")
    found = data.judge_skipped(["maildivvy-pass: example INBOX: 1 recorded", line, line],
                               CONF.fanout_skip_hours)
    assert found.state == WARN and "1 archive folder(s) renumbered" in found.reading
    assert "Dovecot numbered example INBOX again" in found.problem
    assert pass_.RENUMBERED in found.problem and pass_.SKIPPED not in found.problem
    skipped = f"{pass_.SKIPPED} example INBOX UID 3: ...; record it with `...`"
    both = data.judge_skipped([line, skipped], CONF.fanout_skip_hours)
    assert both.state == WARN and pass_.SKIPPED in both.problem and pass_.RENUMBERED in both.problem


def test_the_provider_requests_unit_is_read_beside_the_pass():
    """The requests that wait on a provider drain in a unit of their own, which the pass
    starts. One whose queue cannot be drained at all, or that cannot start, leaves its
    requests `queued` while the pass reads PASS: its last run is read, as a check of its
    own, with no staleness bound of its own, since it runs with every pass."""
    shown = {"Result": "success", "ExecMainStatus": "0",
             "ExecMainExitTimestamp": "Wed 2026-09-23 11:59:02 UTC"}
    old = {**shown, "ExecMainExitTimestamp": "Tue 2026-09-22 11:59:02 UTC"}
    assert data.judge_provider_requests(old).state == PASS
    for result, status in (("exit-code", "1"), ("exit-code", "217"), ("timeout", "0")):
        found = data.judge_provider_requests({**shown, "Result": result, "ExecMainStatus": status})
        assert found.state == FAIL and found.name == "provider requests", (result, status)
        assert f"journalctl -u {data.REQUESTS_UNIT}" in found.problem
    never = {**shown, "ExecMainExitTimestamp": ""}
    assert data.judge_provider_requests(never).state == UNKNOWN
    # a fresh install's step 17 reads it before the first pass, as it reads the pass's own
    import yaml
    health_vars = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health" / "vars" / "main.yml"
    assert "store/provider requests" in yaml.safe_load(health_vars.read_text())["maildivvy_health_no_data_yet"]


def test_a_pass_that_has_not_run_yet_is_no_data_yet_and_step_17_accepts_it_as_such():
    """Seen on a full install: steps 13 to 17 ran inside 41 s, between two of the pass
    timer's minutes, so the first pass had not run when step 17 read health. That is no
    data yet, which step 17 accepts as UNKNOWN - not a fault, which would stop the install."""
    never = {"Result": "success", "ExecMainStatus": "0", "ExecMainExitTimestamp": ""}
    assert states(data.judge_fanout(True, "", never, NOW, CONF)) == [PASS, UNKNOWN]
    import yaml
    health_vars = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health" / "vars" / "main.yml"
    assert "store/fan-out" in yaml.safe_load(health_vars.read_text())["maildivvy_health_no_data_yet"]


def step_17_proof(tmp_path, readings):
    """Step 17's proof as the install runs it, over a whole report holding `readings`
    ({"subsystem/check": state}) and PASS everywhere else; its exit code and output."""
    import subprocess
    import sys

    import yaml
    health_vars = yaml.safe_load((Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health"
                                  / "vars" / "main.yml").read_text())
    subsystems = {name: [] for name in checks.SUBSYSTEMS}
    for key, state in readings.items():
        state, problem = state if isinstance(state, tuple) else (state, f"{key} said so")
        name, check = key.split("/", 1)
        subsystems[name].append({"name": check, "state": state, "reading": "read", "problem": problem})
    for held in subsystems.values():
        held.append({"name": "control", "state": PASS, "reading": "read", "problem": None})
    path = tmp_path / "health.json"
    path.write_text(json.dumps({"complete": True, "subsystems": [
        {"name": name, "checks": held} for name, held in subsystems.items()]}))
    done = subprocess.run([sys.executable, "-c", health_vars["maildivvy_health_proof"], str(path),
                           ",".join(health_vars["maildivvy_health_later_steps"]),
                           json.dumps(health_vars["maildivvy_health_no_data_yet"]),
                           ",".join(health_vars["maildivvy_health_not_stopping"])],
                          capture_output=True, text=True)
    return done.returncode, done.stdout


def test_step_17_prints_a_newer_rspamd_release_and_does_not_stop_on_it(tmp_path):
    """The day rspamd 4.2.1 was released, `spam/repin` read FAIL and every install stopped
    at step 17. It is printed beside the WARNs and accepted; health itself still FAILs."""
    assert scanners.judge_repin("4.2.0", "4.2.1").state == FAIL
    code, out = step_17_proof(tmp_path, {})
    assert code == 0 and out.endswith("readings accepted\n"), out   # the control: a whole PASS report
    code, out = step_17_proof(tmp_path, {"spam/repin": FAIL, "tls/certificate": WARN})
    assert code == 0, out
    assert "FAIL spam/repin" in out and "WARN tls/certificate" in out


def test_step_17_stops_on_every_other_fail_and_on_a_repin_it_cannot_read(tmp_path):
    for key in ("spam/container", "spam/scores", "antivirus/repin", "tls/certificate"):
        code, out = step_17_proof(tmp_path, {key: FAIL, "spam/repin": FAIL})
        assert code == 1 and f"FAIL {key}" in out, (key, out)
    code, out = step_17_proof(tmp_path, {"spam/repin": UNKNOWN})
    assert code == 1 and "UNKNOWN spam/repin" in out


def test_failed_requests_of_the_last_day_warn_naming_kind_and_target():
    found = data.judge_requests([("connect", "ivan@alpha")], 12, 24)
    assert found.state == WARN and "connect ivan@alpha" in found.problem
    assert data.judge_requests([], 12, 24).state == PASS


def test_the_requests_check_names_the_newest_failures_as_its_own_role(database):
    """It names five: the newest, so a failure just seen is named whatever older ones the
    day holds. The statement on the real schema, as `maildivvy_health`."""
    for hours in (6, 5, 4, 3, 2, 1):
        database.sql("INSERT INTO request (kind, target, asked_by, state, result, finished_at) "
                     "VALUES ('connect', %s, 'olga', 'failed', 'r', now() - %s * interval "
                     "'1 hour')", (f"{hours}h@alpha", hours))
    database.sql("INSERT INTO request (kind, target, asked_by, state, result, finished_at) "
                 "VALUES ('refetch', 'newest@alpha', 'olga', 'failed', 'r', now())")
    conn = database.connect("health")
    try:
        with conn.cursor() as cur:
            cur.execute(data.FAILED_REQUESTS,
                        (datetime.datetime.now(UTC) - datetime.timedelta(hours=24),))
            failed = cur.fetchall()
            cur.execute(data.ALL_REQUESTS)
            total = cur.fetchone()[0]
    finally:
        conn.close()
    found = data.judge_requests(failed, total, 24)
    assert found.state == WARN and found.reading == "7 failed in the last 24 h (7 requests read)"
    assert ("refetch newest@alpha; connect 1h@alpha; connect 2h@alpha; connect 3h@alpha; "
            "connect 4h@alpha - ") in found.problem
    assert "5h@alpha" not in found.problem and "6h@alpha" not in found.problem


def test_a_request_left_running_by_a_pass_no_longer_alive_fails_naming_it():
    """The claim commits before its handler runs, so a pass killed in a handler leaves
    the row `running` until the next run fails it. It is read twice with the
    pass's unit probed between: a row a live pass held at the first read is finished, or
    the pass is still alive, by the second."""
    left = [(7, "connect", "ivan@alpha")]
    found = data.judge_left_running(left, left, False)
    assert found.state == FAIL and "connect ivan@alpha" in found.problem and "7" in found.problem
    assert "its next run marks each failed" in found.problem
    # a pass alive between the two reads holds the row: it is being performed
    assert data.judge_left_running(left, left, True).state == PASS
    # a pass that finished it between the reads
    assert data.judge_left_running(left, [], False).state == PASS
    # a row a pass claimed after the first read
    assert data.judge_left_running([], left, False).state == PASS
    assert data.judge_left_running([], [], False).state == PASS


def test_every_unit_that_runs_the_pass_is_a_drainer():
    """A unit that drains the queue and is not in DRAINERS makes health read the row it
    holds as left running: the requests that wait on a provider run in a unit of their own."""
    templates = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "programs" / "templates"
    runners = {t.name.removesuffix(".j2") for t in templates.glob("*.service.j2")
               if "bin/maildivvy-pass" in t.read_text()}
    assert runners and runners == set(data.DRAINERS)


def test_a_queue_that_only_ages_warns_unless_the_pass_is_stopped_on_purpose():
    old = ("connect", "ivan@alpha", NOW - datetime.timedelta(minutes=CONF.request_queued_minutes + 1), 3)
    fresh = ("connect", "ivan@alpha", NOW - datetime.timedelta(minutes=2), 1)
    found = data.judge_queued(old, True, "", NOW, CONF)
    assert found.state == WARN and "connect ivan@alpha" in found.problem
    assert data.REQUESTS_UNIT in found.problem
    assert data.judge_queued(fresh, True, "", NOW, CONF).state == PASS
    assert data.judge_queued(None, True, "", NOW, CONF).state == PASS
    # paused for a backup, or the timer stopped (which the fan-out timer reads as FAIL)
    assert data.judge_queued(old, False, data.BACKUP_PAUSE, NOW, CONF).state == PASS
    assert data.judge_queued(old, False, "", NOW, CONF).state == PASS


def test_the_schema_is_every_shipped_migration_and_nothing_else():
    assert data.judge_schema(["0001"], ["0001"]).state == PASS
    assert data.judge_schema(["0001"], ["0001", "0002"]).state == FAIL
    assert data.judge_schema(["0001", "0009"], ["0001"]).state == FAIL


def test_the_newest_backup_is_younger_than_the_bound_or_absent_fails():
    record = {"stamp": "20260923T110344Z", "taken_at": "2026-09-23T11:03:44+00:00", "tables": 12,
              "rows": 34, "state_entries": 4}
    assert data.judge_backup(record, NOW, CONF).state == PASS
    assert data.judge_backup(record, NOW + datetime.timedelta(hours=49), CONF).state == FAIL
    assert data.judge_backup(None, NOW, CONF).state == FAIL


def test_a_failed_store_copy_warns_naming_the_newest_run_that_has_one():
    record = {"stamp": "20260923T110344Z", "taken_at": "2026-09-23T11:03:44+00:00", "tables": 12,
              "rows": 34, "state_entries": 4, "store_copy": "failed, exit 3",
              "newest_store_copied": "20260920T110000Z"}
    check = data.judge_backup(record, NOW, CONF)
    assert check.state == WARN
    assert check.reading.startswith("20260923T110344Z, 1 h old"), check.reading
    assert check.problem == ("its store copy failed, exit 3: the newest run with a store copy to "
                             "restore with is 20260920T110000Z, 73 h old; read "
                             "`journalctl -u maildivvy-backup.service`")

    never = data.judge_backup({**record, "newest_store_copied": None}, NOW, CONF)
    assert never.state == WARN
    assert never.problem == ("its store copy failed, exit 3: no run kept has one, so no dump can be "
                             "restored with the store; read `journalctl -u maildivvy-backup.service`")

    # a status a backup wrote before it recorded the newest pair: the operator is told where
    earlier = {k: v for k, v in record.items() if k != "newest_store_copied"}
    told = data.judge_backup(earlier, NOW, CONF)
    assert told.state == WARN and "`ls /var/backups/maildivvy/*/store-copied`" in told.problem

    # a copy that succeeded, or none configured, is PASS as before; a dump past the bound
    # is FAIL whatever its copy did
    for copied in ("ok", "none configured"):
        assert data.judge_backup({**record, "store_copy": copied}, NOW, CONF).state == PASS
    assert data.judge_backup(record, NOW + datetime.timedelta(hours=49), CONF).state == FAIL
    with pytest.raises(Unreadable):
        data.judge_backup({**record, "newest_store_copied": "yesterday"}, NOW, CONF)


def test_a_mailbox_held_for_the_store_fails_the_store_and_names_when():
    at = NOW - datetime.timedelta(minutes=3)
    found = data.judge_store_hold([("Ivan.P@example.org", at)], 3)
    assert found.state == FAIL and found.reading == "1 of 3 held"
    assert f"Ivan.P@example.org at {at.isoformat(timespec='seconds')}" in found.problem
    assert "store could not take mail" in found.problem
    # the filter's words: in the fetch unit's journal under mpop, on the row over IMAP
    assert "`journalctl -u maildivvy-fetch.service` for a POP3 mailbox" in found.problem
    assert "the mailbox's detail on the fetch screen for an IMAP one" in found.problem
    assert data.judge_store_hold([], 3).state == PASS  # the control
    assert "(3 read)" in data.judge_store_hold([], 3).reading
    assert data.store_hold in data.STORE and "'store'" in data.STORE_HELD


def test_a_snapshot_failed_incomplete_paused_or_stuck_warns_naming_it():
    hour, day = datetime.timedelta(hours=1), datetime.timedelta(days=1)
    began = NOW - 3 * day
    failed = ("Ivan.P@example.org", "failed", NOW - hour, None,
              "the provider renumbered the INBOX", 0, 0, began)
    paused = ("Olga@example.org", "paused", None, NOW - 25 * hour,
              "1 of 3 folders taken; <no answer>", 0, 0, began)
    short = ("Petr@example.org", "done", NOW - hour, None, "3 of 3 folders taken", 2, 0, began)
    folders = ("Lena@example.org", "done", NOW - hour, None,
               "3 of 3 folders taken; 1 left out: Private", 0, 1, began)
    stuck = ("Anna@example.org", "pending", None, None, "1 of 9 folders taken", 0, 0,
             NOW - 8 * day)
    waits = ("Rita@example.org", None, None, None, None, None, None, NOW - 8 * day)
    # paused with no time, which only an edit of the row leaves: warned of, not a crash
    edited = ("Vera@example.org", "paused", None, None, "d", 0, 0, NOW - hour)
    found = data.judge_snapshots([failed, paused, short, folders, stuck, waits, edited], 8, NOW)
    assert found.state == WARN and found.reading == "7 snapshot(s) of 8 external mailbox(es)"
    assert (f"Ivan.P@example.org failed at {(NOW - hour).isoformat(timespec='seconds')}: the "
            "provider renumbered the INBOX") in found.problem
    assert (f"Olga@example.org paused since {(NOW - 25 * hour).isoformat(timespec='seconds')}: "
            "1 of 3 folders taken; <no answer>") in found.problem
    assert "Petr@example.org done without 2 message(s) the provider refused to send" in found.problem
    assert ("Lena@example.org done without 1 folder(s) it left out: 3 of 3 folders taken; 1 left "
            "out: Private") in found.problem
    assert (f"Anna@example.org under way since {(NOW - 8 * day).isoformat(timespec='seconds')} "
            "and not done: 1 of 9 folders taken") in found.problem
    assert (f"Rita@example.org asked for since {(NOW - 8 * day).isoformat(timespec='seconds')} "
            "and not done") in found.problem
    assert "Vera@example.org paused since a time not recorded: d" in found.problem
    assert "discarded on the mailbox's page" in found.problem
    # paused for less than a day, under way or asked for less than a week, or done whole:
    # every slice goes on, or it is over
    for row in (("a@example.org", "paused", None, NOW - 23 * hour, "d", 0, 0, began),
                ("b@example.org", "pending", None, None, "d", 0, 0, NOW - 6 * day),
                ("c@example.org", "running", None, None, None, 0, 0, began),
                ("d@example.org", "done", NOW - 50 * hour, None, "d", 0, 0, began),
                ("e@example.org", None, None, None, None, None, None, NOW - hour)):
        assert data.judge_snapshots([row], 4, NOW).state == PASS, row
    control = data.judge_snapshots([], 3, NOW)          # the count read is the control
    assert control.state == PASS and control.reading.startswith("0 snapshot(s) of 3 external")
    assert data.snapshots in data.COLLECTION


def test_health_reads_every_snapshot_asked_begun_or_ended_as_its_own_role(database):
    """The check's statement on the real schema, as `maildivvy_health`, which reads and never
    writes: a snapshot asked for and not begun is one too, and one discarded is none."""
    for address, status, refused in (("a@example.org", "paused", 0), ("b@example.org", None, None),
                                     ("c@example.org", "failed", 0), ("d@example.org", "done", 2),
                                     ("f@example.org", "done", 0)):
        database.sql(
            "INSERT INTO external_mailbox (address, address_canonical, protocol, pop3_host, "
            "smtp_host, keep_at_provider, snapshot_requested_at, snapshot_started_at, "
            "snapshot_status, snapshot_paused_since, snapshot_finished_at, snapshot_detail, "
            "snapshot_refused, snapshot_left_out) VALUES (%s, %s, 'imap', 'imap.example.org', "
            "'smtp.example.org', true, now() - interval '8 days', CASE WHEN %s IS NOT NULL THEN "
            "now() END, %s, CASE WHEN %s = 'paused' THEN now() - interval '2 days' END, "
            "CASE WHEN %s IN ('failed', 'done') THEN now() END, 'said', %s, "
            "CASE WHEN %s = 'f@example.org' THEN 1 ELSE %s END)",
            (address, address, status, status, status, status, refused, address,
             None if refused is None else 0))
    # discarded: no status, and it ended after it was asked for
    database.sql(
        "INSERT INTO external_mailbox (address, address_canonical, protocol, pop3_host, "
        "smtp_host, keep_at_provider, snapshot_requested_at, snapshot_finished_at) VALUES "
        "('e@example.org', 'e@example.org', 'imap', 'imap.example.org', 'smtp.example.org', "
        "true, now() - interval '9 days', now())")
    conn = database.connect("health")
    try:
        with conn.cursor() as cur:
            cur.execute(data.SNAPSHOTS)
            rows = cur.fetchall()
            cur.execute(data.MAILBOX_COUNT)
            total = cur.fetchone()[0]
    finally:
        conn.close()
    assert [(row[0], row[1], row[5], row[6]) for row in rows] == [
        ("a@example.org", "paused", 0, 0), ("b@example.org", None, None, None),
        ("c@example.org", "failed", 0, 0), ("d@example.org", "done", 2, 0),
        ("f@example.org", "done", 0, 1)]
    found = data.judge_snapshots(rows, total, datetime.datetime.now(UTC))
    assert found.state == WARN and found.reading == "5 snapshot(s) of 6 external mailbox(es)"
    for address in ("a@", "b@", "c@", "d@", "f@"):
        assert address in found.problem


class Rows:
    """The pipeline connection the store helper reads rows on: answers in order."""

    def __init__(self, *answers):
        self.answers = list(answers)

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        pass

    def fetchall(self):
        return self.answers.pop(0)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def disks(tmp_path, monkeypatch, *paths):
    """The store and both index trees under tmp_path, with these directories in each."""
    from maildivvy.lib import store
    monkeypatch.setattr(store, "STORE_ROOT", tmp_path / "store")
    monkeypatch.setattr(store, "INDEX_ROOT", tmp_path / "index")
    for root in (tmp_path / "store", tmp_path / "index" / "idx", tmp_path / "index" / "ctl"):
        root.mkdir(parents=True)
        for path in paths:
            (root / path).mkdir(parents=True)


def test_a_directory_no_row_holds_is_read_and_one_a_deletion_still_lists_is_told_apart(
        tmp_path, monkeypatch):
    disks(tmp_path, monkeypatch, "alpha/archive", "alpha/ivan", "alpha/olga", "alpha/gone",
          "alpha/going", "beta/archive", "beta/x", "lost+found")
    monkeypatch.setattr(helper, "pipeline_connection", lambda: Rows(
        [("alpha",)], [("alpha", "ivan"), ("alpha", "olga")],
        [(4, "running", [["alpha", "going"]]), (3, "failed", [["beta", "x"], ["beta", "archive"],
                                                               ["beta", None]])]))
    reading = helper.read_directories()
    assert reading["listed"] == 21 and reading["domains"] == 1
    assert reading["stray"] == [str(tmp_path / root / "alpha" / "gone")
                                for root in ("store", "index/idx", "index/ctl")]
    assert {entry["request"] for entry in reading["left"]} == {3}
    assert len(reading["left"]) == 6, "a failed deletion's own directories were not told apart"
    assert not any("going" in entry for entry in reading["stray"]), "a running deletion was read"
    assert reading["held"] == 21 - 3 - 6


def test_the_stores_snapshots_are_no_domain_and_are_not_read_as_directories_no_row_holds(
        tmp_path, monkeypatch):
    """`_snapshots` sits beside the domains in the store, and no label can take it; the same
    name in an index tree is nothing of ours, and is read as any directory is."""
    from maildivvy.lib import store
    disks(tmp_path, monkeypatch, "alpha/archive")
    (tmp_path / "store" / store.SNAPSHOT_ROOT.name / "7" / "Maildir").mkdir(parents=True)
    monkeypatch.setattr(helper, "pipeline_connection", lambda: Rows([("alpha",)], [], []))
    reading = helper.read_directories()
    assert reading["listed"] == 3 and reading["stray"] == [] and reading["left"] == []
    # the control: in an index tree it is a directory no row holds
    (tmp_path / "index" / "idx" / store.SNAPSHOT_ROOT.name / "7").mkdir(parents=True)
    monkeypatch.setattr(helper, "pipeline_connection", lambda: Rows([("alpha",)], [], []))
    assert helper.read_directories()["stray"] == [
        str(tmp_path / "index" / "idx" / store.SNAPSHOT_ROOT.name / "7")]


def test_the_imports_staging_directory_is_no_domain_and_is_not_read_as_one_no_row_holds(
        tmp_path, monkeypatch):
    """`_imports` sits beside the domains in the store while it holds staged files."""
    from maildivvy.lib import store
    disks(tmp_path, monkeypatch, "alpha/archive")
    (tmp_path / "store" / store.IMPORTS_ROOT.name / "alpha").mkdir(parents=True)
    monkeypatch.setattr(helper, "pipeline_connection", lambda: Rows([("alpha",)], [], []))
    reading = helper.read_directories()
    assert reading["listed"] == 3 and reading["stray"] == [] and reading["left"] == []
    # the control: a domain directory no row holds is still found
    (tmp_path / "store" / "gone" / "ivan").mkdir(parents=True)
    monkeypatch.setattr(helper, "pipeline_connection", lambda: Rows([("alpha",)], [], []))
    assert helper.read_directories()["stray"] == [str(tmp_path / "store" / "gone" / "ivan")]


def test_an_index_tree_dovecot_has_not_made_yet_is_read_as_empty_and_a_missing_store_is_not(
        tmp_path, monkeypatch):
    """A fresh install has no `idx/` or `ctl/` until the first login opens a mailbox."""
    disks(tmp_path, monkeypatch, "alpha/archive")
    for tree in ("idx", "ctl"):
        (tmp_path / "index" / tree / "alpha" / "archive").rmdir()
        (tmp_path / "index" / tree / "alpha").rmdir()
        (tmp_path / "index" / tree).rmdir()
    monkeypatch.setattr(helper, "pipeline_connection", lambda: Rows([("alpha",)], [], []))
    reading = helper.read_directories()
    assert reading["listed"] == 1 and reading["stray"] == [] and reading["left"] == []
    # the control: the store is the install's own, and its absence is still an error
    (tmp_path / "store" / "alpha" / "archive").rmdir()
    (tmp_path / "store" / "alpha").rmdir()
    (tmp_path / "store").rmdir()
    monkeypatch.setattr(helper, "pipeline_connection", lambda: Rows([("alpha",)], [], []))
    with pytest.raises(FileNotFoundError):
        helper.read_directories()


def test_directories_no_row_holds_warn_and_name_who_removes_them():
    clean = {"listed": 9, "domains": 1, "held": 9, "stray": [], "left": []}
    assert data.judge_directories(clean).state == PASS
    stray = data.judge_directories({**clean, "held": 8, "stray": ["/srv/s/alpha/gone"]})
    assert stray.state == WARN and "/srv/s/alpha/gone" in stray.problem
    assert "would inherit it" in stray.problem
    left = data.judge_directories({**clean, "held": 8,
                                   "left": [{"path": "/srv/s/beta/x", "request": 3}]})
    assert left.state == WARN and "request(s) 3" in left.problem and "tries again" in left.problem
    # the control: rows name domains, and nothing any of them names was found
    assert data.judge_directories({**clean, "listed": 0, "held": 0}).state == UNKNOWN
    # and a machine with no domain yet and nothing on its disks is no fault
    empty = data.judge_directories({**clean, "listed": 0, "held": 0, "domains": 0})
    assert empty.state == PASS
    assert data.directories in data.STORE and "directories" in data.WANTS["store"]["store"]


# --- the command ------------------------------------------------------------------------------


def fake_run(names=None, conf=None, now=None, keep=False):
    chosen = names or list(checks.SUBSYSTEMS)
    return report.Report(NOW, [report.Subsystem(n, [report.Check("c", FAIL if n == "store" else PASS,
                                                                  "read", None if n != "store" else "bad")])
                               for n in chosen])


def test_a_whole_run_writes_the_file_and_one_subsystem_does_not(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(checks, "run", fake_run)
    path = tmp_path / "health.json"
    conf = tmp_path / "none.conf"
    assert run.main(["--report", str(path), "--conf", str(conf)]) == 2
    assert json.loads(path.read_text())["state"] == FAIL
    before = path.read_text()
    assert run.main(["--report", str(path), "--conf", str(conf), "--subsystem", "host"]) == 0
    assert path.read_text() == before
    out = capsys.readouterr().out
    assert "PASS host" in out


def test_the_cached_report_is_read_per_subsystem_and_a_stale_one_is_unknown(tmp_path, capsys):
    path = tmp_path / "health.json"
    args = ["--cached", "--report", str(path), "--conf", str(tmp_path / "none.conf")]
    fresh = fake_run()
    fresh.taken_at = datetime.datetime.now(UTC) - datetime.timedelta(minutes=2)
    report.write_json(path, fresh)
    assert run.main(args + ["--subsystem", "host"]) == 0
    assert run.main(args + ["--subsystem", "store"]) == 2
    stale = fake_run()   # dated NOW, long past by the clock this runs by
    stale.taken_at = datetime.datetime.now(UTC) - datetime.timedelta(minutes=16)
    report.write_json(path, stale)
    # every PASS reads UNKNOWN, and the FAIL already found stays FAIL
    assert run.main(args + ["--subsystem", "host"]) == 3
    assert run.main(args + ["--subsystem", "store"]) == 2


def test_a_run_that_cannot_run_is_unknown_and_writes_nothing(tmp_path, capsys):
    conf = tmp_path / "health.conf"
    conf.write_text("no_such_bound = 1\n")
    path = tmp_path / "health.json"
    assert run.main(["--conf", str(conf), "--report", str(path)]) == 3
    assert not path.exists()
    assert capsys.readouterr().out.startswith("UNKNOWN maildivvy-health could not run")


def test_health_connects_only_through_the_one_connection_helper():
    package = Path(checks.__file__).parent
    for path in package.glob("*.py"):
        assert "psycopg2.connect" not in path.read_text(), path.name
    assert 'db.connect("health")' in (package / "context.py").read_text()


# --- a service asked that does not answer is a FAIL, a reading not taken is UNKNOWN ------------------


class CertContext(context.Context):
    def certificate(self):
        return {"cert_name": "mail.example.org", "mode": "self-signed",
                "published_cert": "/etc/maildivvy/tls/mail.example.org.crt"}


def test_a_service_that_does_not_answer_its_port_fails_and_is_never_unknown(monkeypatch):
    def refused(name, anchor):
        raise services.NoAnswer("127.0.0.1:993 as mail.example.org: [Errno 111] Connection refused")
    monkeypatch.setattr(services, "imap_attempt", refused)
    found = context.run_check(services.imap_login, CertContext(now=NOW))
    assert states(found) == [FAIL] and "Connection refused" in found[0].reading


def test_a_scanner_that_is_not_running_fails_and_what_only_it_can_say_is_unknown(monkeypatch):
    stopped = {"container": {"name": "maildivvy-rspamd-1", "running": False, "restarts": 0,
                             "started_at": "2026-09-23T11:00:46.524796232Z"}, "modules": ""}
    monkeypatch.setattr(helper, "ask", lambda name, wanted, **_: {w: stopped for w in wanted})
    ctx = context.Context(now=NOW, wants={"system": ["rspamd"]})
    found = [c for f in (scanners.container, scanners.modules, scanners.configuration_log)
             for c in context.run_check(f, ctx)]
    assert states(found) == [FAIL, UNKNOWN, UNKNOWN]
    assert "not running" in found[1].problem


# --- the ledger: a five-minute window, and a daily pass ---------------------------------


MARK = {"since": 1790000000.5, "delivery": 40, "carried": [[5, 11, 123456]]}


def ask_store(request, readers):
    out = io.StringIO()
    code = helper.serve("store", readers, stdin=io.BytesIO(json.dumps(request).encode() + b"\n"),
                        stdout=out)
    return code, json.loads(out.getvalue())


def test_the_ledger_window_alone_is_given_where_the_last_scan_began_and_nothing_else_is():
    readers = {"ledger": lambda given=None: {"given": given}, "fetch_state": lambda: {"listed": True}}
    code, answer = ask_store({"want": ["ledger", "fetch_state"], "given": {"ledger": MARK}}, readers)
    assert code == 0 and answer["readings"]["ledger"] == {"given": MARK}
    # an argument for a reading that takes none, or one not asked for, is refused whole
    for given in ({"fetch_state": "/etc/shadow"}, {"search": MARK}, ["ledger"]):
        code, answer = ask_store({"want": ["ledger", "fetch_state"], "given": given}, readers)
        assert code == 2 and answer["complete"] is False, given


def test_the_window_the_helper_is_given_is_numbers_and_nothing_else():
    assert helper.window_mark(None) == (None, 0, [])
    assert helper.window_mark(MARK) == (1790000000.5, 40, [(5, 11, 123456)])
    for wrong in ({**MARK, "since": "/srv/maildivvy/store"}, {**MARK, "since": True},
                  {**MARK, "delivery": -1}, {**MARK, "carried": [[5, 11, "x"]]},
                  {**MARK, "carried": [[5, 11]]}, {**MARK, "carried": [[1, 2, 3]] * 101}):
        with pytest.raises(ValueError):
            helper.window_mark(wrong)


def window_reading(findings=(), since=MARK["since"], deliveries=40):
    return {"since": since, "deliveries": deliveries, "added": 2, "checked": 7,
            "findings": list(findings), "next": {**MARK, "since": 1790000300.0}}


def test_the_window_passes_fails_on_a_finding_and_is_unknown_before_its_first_scan():
    found = data.judge_window(window_reading())
    assert found.state == PASS and "7 name(s) changed since" in found.reading
    assert "2 delivery rows added" in found.reading
    found = data.judge_window(window_reading(["ivan: a name for the archive's message 11 ..."]))
    assert found.state == FAIL and "message 11" in found.problem
    assert data.judge_window(window_reading(since=None)).state == UNKNOWN
    assert data.judge_window(window_reading(deliveries=0)).state == UNKNOWN


def test_only_the_run_whose_report_is_kept_moves_the_window_and_keeps_it_as_healths_own(
        tmp_path, monkeypatch):
    path = tmp_path / "ledger-window.json"
    monkeypatch.setattr(settings, "LEDGER_WINDOW", path)
    asked = []
    monkeypatch.setattr(helper, "ask", lambda name, wanted, given=None, **_:
                        asked.append(given) or {"ledger": window_reading()})
    data.ledger(context.Context(now=NOW, wants={"store": ["ledger"]}, given=data.given(["store"])))
    assert not path.exists() and asked == [{"ledger": None}]   # a run of one subsystem keeps nothing
    data.ledger(context.Context(now=NOW, wants={"store": ["ledger"]}, given=data.given(["store"]),
                                keep=True))
    assert json.loads(path.read_text()) == {**MARK, "since": 1790000300.0}
    assert path.stat().st_mode & 0o777 == 0o600
    # the next run's window starts where that one began
    assert data.given(["store"]) == {"store": {"ledger": {**MARK, "since": 1790000300.0}}}
    assert data.given(["host"]) == {}
    # a record that cannot be read starts the window again, never stops it
    path.write_text('{"since": "yesterday"}')
    assert data.given(["store"]) == {"store": {"ledger": None}}


def pass_record(hours, findings=(), error=None):
    reading = {"error": error} if error else {"domains": {"alpha": {
        "deliveries": 10, "mailboxes": 2, "findings": list(findings),
        "several_names": 4, "one_name": 1}}}
    return {"taken_at": (NOW - datetime.timedelta(hours=hours)).isoformat(), "reading": reading}


def test_the_daily_pass_is_reported_with_its_age_and_unknown_once_stale_but_a_fail_stays():
    fresh = data.judge_pass(pass_record(3), NOW, CONF)
    assert states(fresh) == [PASS, PASS] and "taken 3 h ago" in fresh[0].reading
    assert [c.name for c in fresh] == ["daily ledger", "link classes"]
    stale = data.judge_pass(pass_record(CONF.ledger_pass_hours + 1), NOW, CONF)
    assert states(stale) == [UNKNOWN, UNKNOWN] and "older than 48 h" in stale[0].problem
    failed = data.judge_pass(pass_record(CONF.ledger_pass_hours + 1, ["ivan: message 11"]), NOW, CONF)
    assert states(failed) == [FAIL, UNKNOWN]
    found = data.judge_pass(pass_record(3, ["ivan: message 11"]), NOW, CONF)
    assert states(found) == [FAIL, PASS] and data.LEDGER_UNIT in found[0].problem
    assert states(data.judge_pass(None, NOW, CONF)) == [UNKNOWN, UNKNOWN]
    could_not = data.judge_pass(pass_record(3, error="the store helper did not answer"), NOW, CONF)
    assert states(could_not) == [UNKNOWN, UNKNOWN] and "did not answer" in could_not[0].problem


def test_the_daily_pass_keeps_its_result_or_why_it_could_not_read_and_exits_with_its_state(
        tmp_path, monkeypatch, capsys):
    path = tmp_path / "ledger-pass.json"
    monkeypatch.setattr(settings, "LEDGER_PASS", path)
    asked = []
    monkeypatch.setattr(helper, "ask", lambda name, wanted, timeout=None, **_:
                        asked.append((name, wanted, timeout)) or
                        {"ledger_pass": pass_record(0, ["ivan: message 11"])["reading"]})
    code = run.main(["--ledger-pass", "--conf", str(tmp_path / "none.conf"),
                     "--report", str(tmp_path / "health.json")])
    assert code == report.exit_code(FAIL) and "daily ledger" in capsys.readouterr().out
    assert asked == [("store", ["ledger_pass"], helper.LEDGER_PASS_WAIT)]
    assert json.loads(path.read_text())["reading"]["domains"]["alpha"]["findings"] == ["ivan: message 11"]
    assert not (tmp_path / "health.json").exists()   # the pass is no report of its own

    def unreadable(*_, **__):
        raise Unreadable("the store helper at /run/x did not answer")
    monkeypatch.setattr(helper, "ask", unreadable)
    assert run.main(["--ledger-pass", "--conf", str(tmp_path / "none.conf")]) == report.exit_code(UNKNOWN)
    assert "did not answer" in json.loads(path.read_text())["reading"]["error"]


# --- the daily pass: the archive's messages no row holds ----------------------------


HASH = "{SHA512-CRYPT}$6$x$" + "x" * 86


class Between:
    """The store helper's connection, with `then` run once right after one statement: what
    another program commits between two of the pass's readings."""

    def __init__(self, conn, after, then):
        self.conn, self.after, self.then = conn, after, then

    def cursor(self):
        return BetweenCursor(self, self.conn.cursor())

    def close(self):
        self.conn.close()


class BetweenCursor:
    def __init__(self, between, cursor):
        self.between, self.cursor = between, cursor

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.cursor.close()

    def execute(self, statement, parameters=None):
        self.cursor.execute(statement, parameters)
        if statement == self.between.after and self.between.then:
            then, self.between.then = self.between.then, None
            then()

    def fetchall(self):
        return self.cursor.fetchall()

    def fetchone(self):
        return self.cursor.fetchone()

    def __iter__(self):
        return iter(self.cursor)


def base(uid):
    return f"1757.M{uid}.host"


def recorded(database, domain, uid):
    """The delivered row the pass writes for the archive's file of this UID."""
    database.sql("INSERT INTO message (domain_id, archive_uid, archive_base) VALUES (%s, %s, %s) "
                 "ON CONFLICT DO NOTHING", (domain, uid, base(uid)))


def archive_scene(database, monkeypatch, listing, uidvalidity=77, cursor=0, rows=(),
                  while_listing=None, between=None):
    """The domain `example`, its INBOX cursor at `cursor` under UIDVALIDITY 77 and a
    delivered row for each UID of `rows`; the archive's directories hold `listing`
    ({folder: UIDs}), each file named `base(uid)`, and Dovecot numbers them so. The daily
    pass then reads the unit tier's real database as the store helper does: as the
    pipeline's role, in a read-only session. Returns the domain's id."""
    domain = database.value("INSERT INTO domain (label, archive_password_hash) VALUES "
                            "('example', %s) RETURNING id", (HASH,))
    database.sql("INSERT INTO pass_cursor (domain_id, mailbox, last_uid, uidvalidity, last_base) "
                 "VALUES (%s, 'INBOX', %s, 77, %s)", (domain, cursor, base(cursor) if cursor else None))
    for uid in rows:
        recorded(database, domain, uid)
    directories = ledger.archive_listing

    def archive_listing(label, root=None):
        """The real directories where the scene made them (`ledger_world`), else these."""
        if while_listing:
            while_listing()
        made = directories(label, root) if root is not None else {}
        return made or {folder: {base(uid): 1000 + uid for uid in uids}
                        for folder, uids in listing.items()}

    def fetch(login, folder, fields, *search):
        assert login == "archive@example" and search[0] == "uid", search
        first, _, last = search[1].partition(":")
        uids = listing.get(folder, [])
        top = max(uids, default=0) if last == "*" else int(last)
        return [{"uid": str(uid), "storageid": base(uid)} for uid in uids
                if int(first) <= uid <= top]

    def connection():
        conn = database.connect("pipeline")
        conn.set_session(readonly=True, autocommit=True)
        return Between(conn, *between) if between else conn

    monkeypatch.setattr(ledger, "archive_listing", archive_listing)
    monkeypatch.setattr(doveadm, "fetch", fetch)
    monkeypatch.setattr(doveadm, "mailbox_status", lambda *_: {"uidvalidity": str(uidvalidity)})
    monkeypatch.setattr(helper, "pipeline_connection", connection)
    return domain


def taken(reading, at):
    """The daily pass's record as health keeps it: through JSON, with its moment."""
    return json.loads(json.dumps({"taken_at": at.isoformat(), "reading": reading}))


def test_a_message_the_pass_skipped_fails_the_daily_pass_a_day_later_and_two_days_later(
        database, monkeypatch):
    """The pass's cursor is at 5 and UID 3 has no row: skipped. Its journal line is counted
    for a day; the daily pass names it for as long as the archive holds it with no row,
    with the command the skip line gave. UIDs 6 and 7 are the next tick's."""
    domain = archive_scene(database, monkeypatch, {"INBOX": [1, 2, 3, 4, 5, 6, 7]}, cursor=5,
                           rows=(1, 2, 4, 5))
    command = f"`runuser -u {store.MAIL_USER} -- {pass_.BY_HAND} --only example --folder INBOX --uid <UID>`"
    for days in (1, 2):
        at = NOW + datetime.timedelta(days=days)
        reading = helper.read_ledger_pass()
        assert reading["domains"]["example"]["unrecorded"] == [
            {"folder": "INBOX", "count": 1, "uids": [3]}]
        found = data.judge_pass(taken(reading, at), at + datetime.timedelta(hours=3), CONF)[0]
        assert found.state == FAIL and f"example INBOX UID 3 ({command})" in found.problem
        assert "1 of 5 archive message(s) under the pass's cursors unrecorded" in found.reading
        assert data.LEDGER_UNIT in found.problem   # how to read it again once recorded
        # by then the journal's window holds the pass's lines and no skip among them
        assert data.judge_skipped(["maildivvy-pass: example INBOX: 2 recorded"],
                                  CONF.fanout_skip_hours).state == PASS
    # a FAIL stays FAIL when the pass itself is stale
    stale = at + datetime.timedelta(hours=CONF.ledger_pass_hours + 1)
    assert data.judge_pass(taken(reading, at), stale, CONF)[0].state == FAIL
    # recorded by hand, the next pass reads it gone
    recorded(database, domain, 3)
    reading = helper.read_ledger_pass()
    assert reading["domains"]["example"]["unrecorded"] == []
    found = data.judge_pass(taken(reading, at), at, CONF)[0]
    assert found.state != FAIL and "0 of 5 archive message(s)" in found.reading


def test_mail_a_tick_recorded_while_the_daily_pass_read_is_no_finding(database, monkeypatch):
    """A tick commits its rows and its cursor together. One that lands after the pass read
    the rows put UIDs 2 and 3 in the listing with no row among those read: they are above
    the cursor of that same moment, so they are the next reading's."""
    def tick():   # run once per folder listed; the ledger holds a UID once
        domain = database.value("SELECT id FROM domain")
        recorded(database, domain, 2)
        recorded(database, domain, 3)
        database.sql("UPDATE pass_cursor SET last_uid = 3, last_base = %s", (base(3),))

    for between in ((ledger.CURSORS, tick), (ledger.MESSAGES, tick), None):
        archive_scene(database, monkeypatch, {"INBOX": [1, 2, 3]}, cursor=1, rows=(1,),
                      while_listing=None if between else tick, between=between)
        found = helper.read_ledger_pass()["domains"]["example"]
        assert found["unrecorded"] == [] and found["under_cursor"] == 1, between
        for table in ("message", "pass_cursor", "domain"):
            database.sql(f"DELETE FROM {table}")


def test_a_domain_deleted_while_the_daily_pass_read_it_leaves_no_finding(database, monkeypatch):
    """A deletion commits every row of the domain and removes its files afterwards. Rows
    read after it, under a cursor read before it, would name the whole archive: the
    cursors and the rows are read at one moment."""
    def delete_domain():
        for table in ("message", "pass_cursor", "domain"):
            database.sql(f"DELETE FROM {table}")

    archive_scene(database, monkeypatch, {"INBOX": [1, 2, 3]}, cursor=3, rows=(1, 2, 3),
                  between=(ledger.CURSORS, delete_domain))
    found = helper.read_ledger_pass()["domains"]["example"]
    assert found["unrecorded"] == [] and found["under_cursor"] == 3
    assert database.value("SELECT count(*) FROM domain") == 0   # it did go in between


def test_a_renumbered_folder_keeps_its_own_reading_and_adds_no_finding_to_the_daily_pass(
        database, monkeypatch):
    """Dovecot numbered the folder again (another UIDVALIDITY than the cursor's), and the
    pass has not set it right yet: "below the cursor" is another numbering's, and every
    file would read as unrecorded. The daily pass names the folder as not counted, and no
    UID of it; the pass's line, once it has, is the skips check's to warn of."""
    archive_scene(database, monkeypatch, {"INBOX": [1, 2, 3]}, uidvalidity=78, cursor=3)
    reading = helper.read_ledger_pass()
    assert reading["domains"]["example"]["unrecorded"] == []
    assert reading["domains"]["example"]["renumbered"] == ["INBOX"]
    found = data.judge_pass(taken(reading, NOW), NOW, CONF)[0]
    assert found.state == UNKNOWN and "UID" not in (found.problem or "")   # no delivery row here
    assert "(example INBOX not counted: its cursor is not what it was" in found.reading
    reading["domains"]["example"]["deliveries"] = 4
    assert data.judge_ledger(reading).state == PASS


def test_an_unrecorded_message_fails_with_no_delivery_row_at_all_and_beside_any_other_finding():
    """A domain that only ever imported mail links to nobody, so it has no delivery row:
    the names' check has nothing to hold the store to there, and the archive's has."""
    unrecorded = [{"folder": "INBOX", "count": 14, "uids": list(range(1, 11))},
                  {"folder": "Quarantine", "count": 1, "uids": [2]}]
    reading = ledger_reading(deliveries=0)
    reading["domains"]["alpha"].update(under_cursor=900, unrecorded=unrecorded, renumbered=[])
    found = data.judge_ledger(reading)
    assert found.state == FAIL and "14 of 900" not in found.reading and "15 of 900" in found.reading
    assert "alpha INBOX UID 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 and 4 more (" in found.problem
    assert "--only alpha --folder Quarantine --uid <UID>" in found.problem
    reading["domains"]["alpha"].update(deliveries=4, findings=["ivan: message 9"])
    found = data.judge_ledger(reading)
    assert found.state == FAIL and "ivan: message 9; the archive holds" in found.problem
    # a result kept before the pass read these says nothing of them, and reads as it did
    old = data.judge_ledger(ledger_reading())
    assert old.state == PASS and "unrecorded" not in old.reading


# --- the daily pass and the window beside a linking request; one mailbox's rows at a time ----


def ledger_world(database, monkeypatch, tmp_path, linked=(1,)):
    """`archive_scene`'s archive of UIDs 1 and 2, both recorded, its files in a store
    under `tmp_path`; ivan's mailbox holds a name for each, and a delivery row for the
    UIDs of `linked`. Returns (domain id, ivan's mailbox id)."""
    domain = archive_scene(database, monkeypatch, {"INBOX": [1, 2]}, cursor=2, rows=(1, 2))
    account = database.value("INSERT INTO account (login, password_hash) VALUES ('ivan', %s) "
                             "RETURNING id", (HASH,))
    mailbox = database.value("INSERT INTO mailbox (account_id, domain_id) VALUES (%s, %s) "
                             "RETURNING id", (account, domain))
    archive = store.maildir(store.archive_home("example", tmp_path))
    ivan = store.maildir(store.home("example", "ivan", tmp_path))
    for box in (archive, ivan):
        for part in store.PARTS:
            (box / part).mkdir(parents=True, exist_ok=True)
    for uid in (1, 2):
        held = archive / "cur" / f"1757.M{uid}.host:2,S"
        held.write_bytes(b"a message")
        os.link(held, ivan / "new" / f"1757.M{uid}.host")
    for uid in linked:
        database.sql("INSERT INTO delivery (message_id, mailbox_id, state, linked_at) "
                     "SELECT id, %s, 'linked', now() FROM message WHERE archive_uid = %s",
                     (mailbox, uid))
    return domain, mailbox


def running_request(database, kind, payload):
    return database.value("INSERT INTO request (kind, payload, asked_by, state) "
                          "VALUES (%s, %s, 'test', 'running') RETURNING id", (kind, json.dumps(payload)))


def test_the_daily_pass_reads_one_mailboxs_rows_at_a_time_and_finds_what_it_found_before(
        database, monkeypatch, tmp_path):
    """The pass held a domain's every delivery row in one set; it now reads them mailbox by
    mailbox. Ivan holds names for UIDs 1 and 2 and a row for 1 only: one finding, and the
    domain's row count as before."""
    _, mailbox = ledger_world(database, monkeypatch, tmp_path)
    asked = []
    original = ledger.unaccounted_in

    def counted(inodes, mailbox_id, *rest):
        asked.append(mailbox_id)
        return original(inodes, mailbox_id, *rest)
    monkeypatch.setattr(ledger, "unaccounted_in", counted)
    found = helper.read_ledger_pass(root=tmp_path)["domains"]["example"]
    assert asked == [mailbox]
    assert found["deliveries"] == 1 and found["mailboxes"] == 1
    assert len(found["findings"]) == 1 and f"with no delivery row for mailbox {mailbox}" in found["findings"][0]
    assert found["several_names"] == 2 and found["one_name"] == 0 and "linking" not in found
    assert data.judge_ledger(helper.read_ledger_pass(root=tmp_path)).state == FAIL


def test_names_a_request_is_still_linking_warn_and_are_named_once_it_ends(
        database, monkeypatch, tmp_path):
    """A top-up makes its names before it commits their rows: read beside it, they are not
    findings but a WARN naming the request, held while it runs; once it ends, the names
    still without a row are findings."""
    _, mailbox = ledger_world(database, monkeypatch, tmp_path)
    request = running_request(database, "top_up", {"mailbox_id": mailbox, "since": "2026-01-01",
                                                    "until": "2026-12-31"})
    monkeypatch.setattr(helper, "CONFIRM_WAIT", 0)
    monkeypatch.setattr(helper, "CONFIRM_POLL", 0)
    reading = helper.read_ledger_pass(root=tmp_path)
    found = reading["domains"]["example"]
    assert found["findings"] == [] and found["linking"] == {"requests": [request], "names": 1}
    judged = data.judge_pass(taken(reading, NOW), NOW, CONF)[0]
    assert judged.state == WARN and f"example: 1 name(s) beside request(s) {request}" in judged.problem
    assert data.LEDGER_UNIT in judged.problem
    # a request on another domain's mailbox does not hold this one's findings
    other = database.value("INSERT INTO domain (label, archive_password_hash) VALUES "
                           "('other', %s) RETURNING id", (HASH,))
    account = database.value("SELECT account_id FROM mailbox WHERE id = %s", (mailbox,))
    elsewhere = database.value("INSERT INTO mailbox (account_id, domain_id) VALUES (%s, %s) "
                               "RETURNING id", (account, other))
    database.sql("UPDATE request SET payload = jsonb_build_object('mailbox_id', %s::bigint)",
                 (elsewhere,))
    listing = ledger.archive_listing
    monkeypatch.setattr(ledger, "archive_listing", lambda label, root=None: {} if label == "other"
                        else listing(label, root))
    found = helper.read_ledger_pass(root=tmp_path)["domains"]["example"]
    assert len(found["findings"]) == 1 and "linking" not in found
    # the request ended: the name it left with no row is a finding
    database.sql("UPDATE request SET state = 'done', payload = jsonb_build_object('mailbox_id', %s::bigint)",
                 (mailbox,))
    found = helper.read_ledger_pass(root=tmp_path)["domains"]["example"]
    assert len(found["findings"]) == 1 and "linking" not in found


def test_a_row_committed_while_the_daily_pass_waited_is_no_finding(database, monkeypatch, tmp_path):
    """The pass reads the names, then the rows again while a request links: a batch that
    commits in between leaves nothing to report, and the pass stops waiting."""
    _, mailbox = ledger_world(database, monkeypatch, tmp_path)
    running_request(database, "connect", {"mailbox_id": mailbox})
    monkeypatch.setattr(helper, "CONFIRM_POLL", 0)
    slept = []

    def commit_batch(_):
        slept.append(1)
        database.sql("INSERT INTO delivery (message_id, mailbox_id, state, linked_at) "
                     "SELECT id, %s, 'linked', now() FROM message WHERE archive_uid = 2", (mailbox,))
    monkeypatch.setattr(helper.time, "sleep", commit_batch)
    found = helper.read_ledger_pass(root=tmp_path)["domains"]["example"]
    assert slept == [1] and found["findings"] == [] and "linking" not in found
    assert data.judge_ledger({"domains": {"example": found}}).state == PASS


def test_the_window_beside_a_linking_request_warns_and_carries_its_names_after_the_others(
        database, monkeypatch):
    """The five-minute window read during a top-up's batch: WARN naming the request, its
    names carried after any other domain's findings, never listed."""
    domain = archive_scene(database, monkeypatch, {"INBOX": [1]}, cursor=1, rows=(1,))
    account = database.value("INSERT INTO account (login, password_hash) VALUES ('ivan', %s) "
                             "RETURNING id", (HASH,))
    mailbox = database.value("INSERT INTO mailbox (account_id, domain_id) VALUES (%s, %s) "
                             "RETURNING id", (account, domain))
    message = database.value("SELECT id FROM message")
    finding = ledger.Finding(mailbox, "ivan", message, "/x")
    monkeypatch.setattr(ledger, "window", lambda cur, label, since, carried: ledger.Window(
        [finding], 1, [[mailbox, message, 99]]))
    mark = {"since": 1.0, "delivery": 0, "carried": []}
    alone = helper.read_ledger(mark)
    assert len(alone["findings"]) == 1 and alone["linking"] == {}   # the control: no request
    assert alone["next"]["carried"] == [[mailbox, message, 99]]
    request = running_request(database, "deliver_one", {"mailbox_id": mailbox, "message_id": message})
    beside = helper.read_ledger(mark)
    assert beside["findings"] == []
    assert beside["linking"] == {"example": {"requests": [request], "names": 1}}
    assert beside["next"]["carried"] == [[mailbox, message, 99]]
    beside["deliveries"] = 1
    judged = data.judge_window(beside)
    assert judged.state == WARN and f"request(s) {request}" in judged.problem


def test_a_finding_whose_row_is_there_or_whose_mailbox_is_gone_is_read_away(database, monkeypatch):
    """`confirm` reads the rows again: a row committed since, or a mailbox a deletion
    removed (its rows first, its files after), is no finding; one still with no row is."""
    domain = archive_scene(database, monkeypatch, {"INBOX": [1, 2]}, rows=(1, 2))
    account = database.value("INSERT INTO account (login, password_hash) VALUES ('ivan', %s) "
                             "RETURNING id", (HASH,))
    mailbox = database.value("INSERT INTO mailbox (account_id, domain_id) VALUES (%s, %s) "
                             "RETURNING id", (account, domain))
    one, two = (database.value("SELECT id FROM message WHERE archive_uid = %s", (u,)) for u in (1, 2))
    database.sql("INSERT INTO delivery (message_id, mailbox_id, state) VALUES (%s, %s, 'linked')",
                 (one, mailbox))
    findings = [ledger.Finding(mailbox, "ivan", one, "/a"), ledger.Finding(mailbox, "ivan", two, "/b"),
                ledger.Finding(mailbox + 1000, "gone", two, "/c")]
    conn = helper.pipeline_connection()
    try:
        left, running = helper.confirm(conn, "example", findings)
    finally:
        conn.close()
    assert left == [findings[1]] and running == []


def test_a_reading_past_its_deadline_is_its_own_error_in_an_answer_still_whole(monkeypatch):
    """One slow store reading lost the whole report: the client waited as long as the run's
    unit. Now a reading is cut at its deadline and answers its error; the others are read."""
    import time as clock
    monkeypatch.setattr(helper, "DEADLINE", 0.2)
    out = io.StringIO()
    readers = {"slow": lambda: clock.sleep(5), "quick": lambda: {"read": True}}
    started = clock.monotonic()
    helper.serve("store", readers, stdin=io.BytesIO(b'{"want": ["quick", "slow"]}\n'), stdout=out)
    assert clock.monotonic() - started < 3
    answer = json.loads(out.getvalue())
    assert answer["complete"] is True and answer["readings"]["quick"] == {"read": True}
    assert answer["readings"]["slow"] == {"error": "not read in 0 s"}
    # the helper's budget spent, a reading after it is not taken at all
    monkeypatch.setattr(helper, "BUDGET", {"store": 0.3})
    out = io.StringIO()
    helper.serve("store", {"a": lambda: clock.sleep(5), "b": lambda: 1},
                 stdin=io.BytesIO(b'{"want": ["a", "b"]}\n'), stdout=out)
    assert "not read: the readings before it took" in json.loads(out.getvalue())["readings"]["b"]["error"]


def test_every_wait_on_a_helper_sits_under_its_units_bound():
    """The client gives up before the unit is killed, so the run writes its report."""
    import yaml
    health_vars = yaml.safe_load((Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health"
                                  / "vars" / "main.yml").read_text())
    assert helper.waited("store") + helper.waited("system") < health_vars["maildivvy_health_run_timeout"]
    assert helper.BUDGET["store"] < helper.waited("store")
    assert helper.DEADLINES["ledger_pass"] < helper.LEDGER_PASS_WAIT < health_vars["maildivvy_health_ledger_timeout"]
    assert helper.LEDGER_PASS_TIMEOUT == health_vars["maildivvy_health_ledger_timeout"]
    assert helper.CONFIRM_WAIT < helper.DEADLINES["ledger_pass"]


def test_a_pass_running_when_health_reads_it_is_judged_by_its_run_and_the_one_before():
    """systemd zeroes a unit's exit time as it starts it: a pass running when health read
    it was UNKNOWN "has not run yet". Running, it is PASS; going longer than the bound,
    WARN; and a failed run before it is still the FAIL it was."""
    going = {"ActiveState": "activating", "Result": "success", "ExecMainStatus": "0",
             "ExecMainExitTimestamp": "", "ExecMainStartTimestamp": "Wed 2026-09-23 11:59:58 UTC"}
    before = (NOW - datetime.timedelta(seconds=62), "done")
    _, found = data.judge_fanout(True, "", going, NOW, CONF, (), before)
    assert found.state == PASS and "a run going since 2026-09-23T11:59:58+00:00" in found.reading
    _, found = data.judge_fanout(True, "", going, NOW, CONF, (), None)   # the first run ever
    assert found.state == PASS
    hung = {**going, "ExecMainStartTimestamp": "Wed 2026-09-23 11:00:00 UTC"}
    _, found = data.judge_fanout(True, "", hung, NOW, CONF, (), before)
    assert found.state == WARN and f"more than {CONF.fanout_minutes} min" in found.problem
    _, found = data.judge_fanout(True, "", going, NOW, CONF, (), (before[0], "failed"))
    assert found.state == FAIL and "last run failed" in found.problem
    _, found = data.judge_fanout(True, "", going, NOW, CONF,
                                 [f"{pass_.UNNAMED} example INBOX: ..."], (before[0], "failed"))
    assert found.state == FAIL and "linked from example INBOX: go back" in found.problem
    # the provider requests, beside every pass
    assert data.judge_provider_requests(going, before, NOW, CONF).state == PASS
    assert data.judge_provider_requests(hung, before, NOW, CONF).state == WARN
    assert data.judge_provider_requests(going, (before[0], "failed"), NOW, CONF).state == FAIL


def test_systemctl_show_is_asked_for_its_times_in_utc(monkeypatch):
    """In a zone with daylight saving, the repeated hour read a pass 20 s old as an hour old."""
    asked = []

    def command(argv, **_):
        asked.append(argv)
        return SimpleNamespace(stdout="ExecMainExitTimestamp=Sun 2026-10-25 01:30:00 UTC\n", returncode=0)
    monkeypatch.setattr(probe, "command", command)
    shown = probe.show("maildivvy-pass.service", "ExecMainExitTimestamp")
    assert "--timestamp=utc" in asked[0]
    assert probe.timestamp(shown["ExecMainExitTimestamp"]) == datetime.datetime(2026, 10, 25, 1, 30, tzinfo=UTC)


def test_step_17_accepts_an_unknown_only_when_it_says_there_is_no_data_yet(tmp_path):
    """The gate took every UNKNOWN of eleven checks for "no data yet", on an upgrade too:
    a daily pass that timed out passed it on a machine with years of mail. Each check's
    own words for no data are accepted, and nothing else it says."""
    import yaml
    no_data = yaml.safe_load((Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health"
                              / "vars" / "main.yml").read_text())["maildivvy_health_no_data_yet"]
    never = {"Result": "success", "ExecMainStatus": "0", "ExecMainExitTimestamp": ""}
    nothing = {"domains": {}}
    fresh = {
        "collection/external mailboxes": data.judge_mailboxes([], NOW, datetime.timedelta(minutes=30), False)[0],
        "collection/fetch runs": data.judge_fetch_runs({**never, "ActiveState": "inactive"}, NOW,
                                                       datetime.timedelta(minutes=30), ""),
        "collection/retrieval check": data.judge_retrieval([], 24),
        "collection/deletion windows": data.judge_windows([], {}),
        "store/ledger": data.judge_window({"since": None, "findings": []}),
        "store/daily ledger": data.judge_ledger(nothing),
        "store/link classes": data.judge_links(nothing),
        "search/search": services.judge_search({}),
        "store/fan-out": data.judge_fanout(True, "", never, NOW, CONF)[1],
        "store/provider requests": data.judge_provider_requests(never),
        "store/fan-out skips": data.judge_skipped([], 24),
    }
    assert set(fresh) == set(no_data)
    for key, found in fresh.items():
        assert found.state == UNKNOWN, key
        code, out = step_17_proof(tmp_path, {key: (UNKNOWN, found.problem)})
        assert code == 0, (key, out)
    # the same checks unable to read: the install stops
    failed = data.judge_pass({"taken_at": NOW.isoformat(), "reading": {"error": "timed out"}}, NOW, CONF)
    for key, found in (("store/daily ledger", failed[0]), ("store/link classes", failed[1]),
                       ("store/ledger", SimpleNamespace(problem="the store helper could not read ledger"))):
        code, out = step_17_proof(tmp_path, {key: (UNKNOWN, found.problem)})
        assert code == 1 and f"UNKNOWN {key}" in out, (key, out)


def test_the_root_and_backup_filesystems_are_read_unless_they_are_one_already_read(monkeypatch, tmp_path):
    """With separate disks the root holds PostgreSQL and the dumps, and nothing warned as
    it filled. With one disk it is the store's filesystem, read once."""
    devices = {str(system.ROOT): 1, str(store.STORE_ROOT): 2, str(store.INDEX_ROOT): 3,
               str(system.BACKUPS): 1}
    monkeypatch.setattr(system.os, "stat", lambda path: SimpleNamespace(st_dev=devices[str(path)]))
    full = SimpleNamespace(f_blocks=1000, f_bavail=50, f_frsize=4096, f_files=100, f_favail=90)
    monkeypatch.setattr(system.os, "statvfs", lambda path: full)
    monkeypatch.setattr(system, "disk_mode", lambda: "separate")
    by_name = {f.check_name: f for f in system.HOST}
    ctx = SimpleNamespace(settings=CONF)
    root = by_name["system free space"](ctx)
    assert root.state == FAIL and "stops PostgreSQL" in root.problem
    backups = by_name["backups free space"](ctx)
    assert backups.state == PASS and "read as system free space" in backups.reading
    devices[str(system.BACKUPS)] = 4
    assert by_name["backups free space"](ctx).state == FAIL
    devices[str(system.ROOT)] = 2   # one disk
    root = by_name["system free space"](ctx)
    assert root.state == PASS and "read as store free space" in root.reading
