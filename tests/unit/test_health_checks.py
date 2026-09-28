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
import socket
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from maildivvy.health import (checks, context, data, helper, probe, report, run, scanners,
                              services, settings, system, upstream)
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import FAIL, PASS, UNKNOWN, WARN
from maildivvy.lib import retrieval
from maildivvy.lib.scan import Score, Version

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
    monkeypatch.setattr(helper, "ask", lambda name, wanted: {"ledger": {"error": "denied"}})
    ctx = context.Context(now=NOW, wants={"store": ["ledger"]})
    found = context.run_check(data.ledger, ctx)
    assert [c.state for c in found] == [UNKNOWN]
    assert "could not read ledger: denied" in found[0].problem


def test_one_run_asks_each_helper_once_for_everything_its_subsystems_need(monkeypatch):
    asked = []
    monkeypatch.setattr(helper, "ask", lambda name, wanted: asked.append((name, wanted)) or
                        {w: {"error": "x"} for w in wanted})
    ctx = context.Context(now=NOW, wants=checks.wants_of(["collection", "store", "search"]))
    for reading in ("ledger", "fetch_state", "search"):
        with pytest.raises(Unreadable):
            ctx.helper("store", reading)
    assert asked == [("store", ["fetch_state", "ledger", "search"])]


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
    missing = system.judge_listeners("\n".join(l for l in SS.splitlines() if ":465 " not in l))
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
    no_submissions = {**LIMITS, "4": "\n".join(l for l in LIMITS4.splitlines() if "--dport 465" not in l)}
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


# --- antivirus ---------------------------------------------------------------------


def test_the_antivirus_answers_and_its_signatures_are_fresh():
    fresh = Version("1.5.4", 28132, datetime.datetime(2026, 9, 23, 6, 24, 42, tzinfo=UTC))
    assert states(scanners.judge_clamd(True, fresh, NOW, CONF)) == [PASS, PASS]
    old = Version("1.5.4", 28100, NOW - datetime.timedelta(days=10))
    assert states(scanners.judge_clamd(True, old, NOW, CONF)) == [PASS, FAIL]
    assert states(scanners.judge_clamd(True, None, NOW, CONF)) == [FAIL]


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
           "domain": "alpha"}
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


def test_a_skipped_message_warns_until_its_provider_deletion_date_and_names_it():
    skipped = mailbox(skipped_at=NOW - datetime.timedelta(days=2), skipped_uidl="uidl-42")
    found = data.judge_mailbox(skipped, NOW, BOUND, False)
    assert found.state == WARN and "uidl-42" in found.reading
    assert (NOW + datetime.timedelta(days=12)).date().isoformat() in found.problem
    expired = mailbox(skipped_at=NOW - datetime.timedelta(days=15), skipped_uidl="uidl-42")
    assert data.judge_mailbox(expired, NOW, BOUND, False).state == PASS


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


def test_a_pass_that_has_not_run_yet_is_no_data_yet_and_step_17_accepts_it_as_such():
    """Seen on a full install: steps 13 to 17 ran inside 41 s, between two of the pass
    timer's minutes, so the first pass had not run when step 17 read health. That is no
    data yet, which step 17 accepts as UNKNOWN - not a fault, which would stop the install."""
    never = {"Result": "success", "ExecMainStatus": "0", "ExecMainExitTimestamp": ""}
    assert states(data.judge_fanout(True, "", never, NOW, CONF)) == [PASS, UNKNOWN]
    import yaml
    health_vars = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health" / "vars" / "main.yml"
    assert "store/fan-out" in yaml.safe_load(health_vars.read_text())["maildivvy_health_no_data_yet"]


def test_failed_requests_of_the_last_day_warn_naming_kind_and_target():
    found = data.judge_requests([("connect", "ivan@alpha")], 12, 24)
    assert found.state == WARN and "connect ivan@alpha" in found.problem
    assert data.judge_requests([], 12, 24).state == PASS


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


# --- the command ------------------------------------------------------------------------------


def fake_run(names=None, conf=None, now=None):
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
                "published_cert": "/etc/ssl/certs/mail.example.org.crt"}


def test_a_service_that_does_not_answer_its_port_fails_and_is_never_unknown(monkeypatch):
    def refused(name, anchor):
        raise services.NoAnswer("127.0.0.1:993 as mail.example.org: [Errno 111] Connection refused")
    monkeypatch.setattr(services, "imap_attempt", refused)
    found = context.run_check(services.imap_login, CertContext(now=NOW))
    assert states(found) == [FAIL] and "Connection refused" in found[0].reading


def test_a_scanner_that_is_not_running_fails_and_what_only_it_can_say_is_unknown(monkeypatch):
    stopped = {"container": {"name": "maildivvy-rspamd-1", "running": False, "restarts": 0,
                             "started_at": "2026-09-23T11:00:46.524796232Z"}, "modules": ""}
    monkeypatch.setattr(helper, "ask", lambda name, wanted: {w: stopped for w in wanted})
    ctx = context.Context(now=NOW, wants={"system": ["rspamd"]})
    found = [c for f in (scanners.container, scanners.modules, scanners.configuration_log)
             for c in context.run_check(f, ctx)]
    assert states(found) == [FAIL, UNKNOWN, UNKNOWN]
    assert "not running" in found[1].problem
