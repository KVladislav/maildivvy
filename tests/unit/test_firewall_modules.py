"""Install steps 3 and 4 as pure functions: ufw's rule plan and the kernel chain comparison."""

from pathlib import Path

import pytest
import yaml

from maildivvy_chains import block_rules, canonical, compare
from maildivvy_preflight import setting_errors
from maildivvy_ssh_login import accepted_logins, wait_for_login
from maildivvy_ufw import (desired, enabled, input_policy, kernel_rules, parse_tuples, plan,
                           published_rules)

GOOD = {
    "hostname": "mail", "cert_name": "mail.example.test", "vmail_uid": 900, "vmail_gid": 900,
    "store_gib": 12, "index_gib": 6, "admin_networks": ["192.0.2.0/24", "2001:db8::/64"],
    "breakglass_password": "correct horse battery", "acme_dns_credentials": {"DESEC_TOKEN": "scoped-token"},
}

USER_RULES = """\
*filter
:ufw-user-input - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 192.0.2.0/24 in
-A ufw-user-input -p tcp --dport 22 -s 192.0.2.0/24 -j ACCEPT

### tuple ### allow tcp 443 0.0.0.0/0 any 198.51.100.0/24 in comment=6f6c64
-A ufw-user-input -p tcp --dport 443 -s 198.51.100.0/24 -j ACCEPT
COMMIT
"""


# --- the ufw rule plan (step 3) ---------------------------------------------


def test_tuples_are_read_from_ufws_rules_file_without_their_comment():
    assert parse_tuples(USER_RULES) == [
        ("allow", "tcp", "22", "0.0.0.0/0", "any", "192.0.2.0/24", "in"),
        ("allow", "tcp", "443", "0.0.0.0/0", "any", "198.51.100.0/24", "in"),
    ]


def test_ssh_comes_first_and_every_rule_is_scoped_to_an_administrator_network():
    rules = desired(["192.0.2.0/24", "2001:db8::/64"], [22, 443])
    assert rules == [
        ("allow", "tcp", "22", "0.0.0.0/0", "any", "192.0.2.0/24", "in"),
        ("allow", "tcp", "22", "::/0", "any", "2001:db8::/64", "in"),
        ("allow", "tcp", "443", "0.0.0.0/0", "any", "192.0.2.0/24", "in"),
        ("allow", "tcp", "443", "::/0", "any", "2001:db8::/64", "in"),
    ]
    assert all(src not in ("0.0.0.0/0", "::/0") for *_, src, _ in rules)


def test_the_mail_ports_are_never_in_the_firewall_steps_rules():
    ports = {int(rule[2]) for rule in desired(["192.0.2.0/24"], [22, 443])}
    assert ports == {22, 443}
    assert not ports & {993, 465, 143, 587}


def test_the_plan_adds_what_is_missing_ssh_first_and_deletes_the_rest():
    current = parse_tuples(USER_RULES)
    wanted = desired(["192.0.2.0/24", "203.0.113.0/24"], [22, 443])
    add, delete, errors = plan(current, wanted)
    assert errors == []
    assert add == [
        ["ufw", "allow", "proto", "tcp", "from", "203.0.113.0/24", "to", "any", "port", "22"],
        ["ufw", "allow", "proto", "tcp", "from", "192.0.2.0/24", "to", "any", "port", "443"],
        ["ufw", "allow", "proto", "tcp", "from", "203.0.113.0/24", "to", "any", "port", "443"],
    ]
    assert delete == [
        ["ufw", "delete", "allow", "proto", "tcp", "from", "198.51.100.0/24", "to", "any", "port", "443"],
    ]


def test_the_kernel_rules_expected_carry_a_source_in_their_own_family():
    rules = kernel_rules(["192.0.2.0/24", "2001:db8::/64"], [22, 443])
    assert rules == {
        4: ["-A ufw-user-input -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT",
            "-A ufw-user-input -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT"],
        6: ["-A ufw6-user-input -s 2001:db8::/64 -p tcp --dport 22 -j ACCEPT",
            "-A ufw6-user-input -s 2001:db8::/64 -p tcp --dport 443 -j ACCEPT"],
    }
    # IPv4 administrator networks only: nothing at all is expected over IPv6
    assert kernel_rules(["192.0.2.0/24"], [22])[6] == []


def test_a_firewall_in_place_plans_nothing():
    wanted = desired(["192.0.2.0/24"], [22])
    assert plan(wanted, wanted) == ([], [], [])


def test_a_rule_the_install_cannot_express_is_refused_not_guessed():
    app = ("allow", "tcp", "22", "0.0.0.0/0", "any", "0.0.0.0/0", "OpenSSH", "-", "in")
    add, delete, errors = plan([app], desired(["192.0.2.0/24"], [22]))
    assert delete == [] and len(errors) == 1 and "OpenSSH" in errors[0]
    assert len(add) == 1  # the control: the wanted rule is still planned


PUBLISHED = """\
### tuple ### allow tcp 993 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 993 -j ACCEPT
### tuple ### allow tcp 465 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 465 -j ACCEPT
### tuple ### allow tcp 993 ::/0 any ::/0 in
-A ufw6-user-input -p tcp --dport 993 -j ACCEPT
"""


def test_the_firewall_step_keeps_the_publications_rules_and_never_writes_them_itself():
    """Step 19 opens 993 and 465 to anywhere once the ban is proved; a re-run of step 3 over
    that machine must neither delete them (the ports would close until step 19 runs again)
    nor add them (step 3 never publishes)."""
    current = parse_tuples(USER_RULES + PUBLISHED)
    kept = published_rules(current, [993, 465])
    assert kept == [("allow", "tcp", "993", "0.0.0.0/0", "any", "0.0.0.0/0", "in"),
                    ("allow", "tcp", "465", "0.0.0.0/0", "any", "0.0.0.0/0", "in"),
                    ("allow", "tcp", "993", "::/0", "any", "::/0", "in")]
    wanted = desired(["192.0.2.0/24"], [22, 443])
    add, delete, errors = plan(current, wanted, kept)
    assert errors == [] and not any("993" in argv or "465" in argv for argv in add + delete)
    assert delete == [["ufw", "delete", "allow", "proto", "tcp", "from", "198.51.100.0/24", "to", "any",
                       "port", "443"]]   # the control: the step still deletes what is not its own
    # the kernel is expected to hold them, in their own family, from anywhere
    rules = kernel_rules(["192.0.2.0/24"], [22, 443], kept)
    assert "-A ufw-user-input -p tcp --dport 993 -j ACCEPT" in rules[4]
    assert "-A ufw-user-input -p tcp --dport 465 -j ACCEPT" in rules[4]
    assert rules[6] == ["-A ufw6-user-input -p tcp --dport 993 -j ACCEPT"]
    # a machine not published: nothing of the mail ports is kept, planned or expected
    assert published_rules(parse_tuples(USER_RULES), [993, 465]) == []


def test_the_firewall_step_keeps_the_very_ports_publication_opens():
    roles = Path(__file__).resolve().parents[2] / "ansible" / "roles"
    firewall = yaml.safe_load((roles / "firewall" / "defaults" / "main.yml").read_text())
    publish = yaml.safe_load((roles / "publish" / "defaults" / "main.yml").read_text())
    assert firewall["maildivvy_mail_ports"] == publish["maildivvy_publish_ports"] == [993, 465]
    assert set(publish["maildivvy_publish_rate_limits"]) == set(publish["maildivvy_publish_ports"])


def test_a_mail_port_rule_of_another_shape_is_not_the_publications_and_is_deleted():
    scoped = ("allow", "tcp", "993", "0.0.0.0/0", "any", "203.0.113.0/24", "in")
    assert published_rules([scoped], [993, 465]) == []
    add, delete, errors = plan([scoped], desired(["192.0.2.0/24"], [22]), [])
    assert delete == [["ufw", "delete", "allow", "proto", "tcp", "from", "203.0.113.0/24", "to", "any",
                       "port", "993"]]


@pytest.mark.parametrize("text, expected", [
    ("# comment\nENABLED=yes\nLOGLEVEL=low\n", True),
    ("ENABLED=no\n", False),
    ("", False),
])
def test_enabled_is_read_from_ufw_conf(text, expected):
    assert enabled(text) is expected


def test_the_input_policy_is_read_from_etc_default_ufw():
    assert input_policy('IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n') == "DROP"
    assert input_policy('DEFAULT_INPUT_POLICY="ACCEPT"\n') == "ACCEPT"
    assert input_policy("") is None


# --- the kernel chain against the file (steps 3 and 4) -----------------------

BLOCK = """\
*filter
:before - [0:0]
COMMIT
# BEGIN maildivvy DOCKER-USER
*filter
:DOCKER-USER - [0:0]
# a comment
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -m conntrack --ctstate NEW -d 172.16.0.0/12 -j maildivvy-docker-deny
-A maildivvy-docker-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[MAILDIVVY DOCKER BLOCK] "
-A maildivvy-docker-deny -j DROP
COMMIT
# END maildivvy DOCKER-USER
-A OTHER -j ACCEPT
"""


def test_the_block_rules_are_read_between_the_markers_only():
    rules = block_rules(BLOCK, "maildivvy DOCKER-USER")
    assert len(rules) == 5
    assert rules[0] == "-A DOCKER-USER -j ufw-user-forward"
    assert not any("OTHER" in rule for rule in rules)


def test_a_rule_printed_in_iptables_own_order_is_the_same_rule():
    written = "-A DOCKER-USER -m conntrack --ctstate NEW -d 172.16.0.0/12 -j maildivvy-docker-deny"
    printed = "-A DOCKER-USER -d 172.16.0.0/12 -m conntrack --ctstate NEW -j maildivvy-docker-deny"
    assert canonical(written) == canonical(printed)
    # ufw's own shape: iptables adds the implicit `-m tcp` and reorders
    assert canonical("-A ufw-user-input -p tcp --dport 22 -s 192.0.2.0/24 -j ACCEPT") == \
        canonical("-A ufw-user-input -s 192.0.2.0/24 -p tcp -m tcp --dport 22 -j ACCEPT")
    assert canonical("-A X -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN") == \
        canonical("-A X -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN")
    # the control: another destination or target is another rule
    assert canonical(written) != canonical(printed.replace("172.16.0.0/12", "10.0.0.0/8"))
    assert canonical(written) != canonical(printed.replace("-j maildivvy-docker-deny", "-j RETURN"))


def test_the_chain_is_compared_rule_by_rule():
    expected = block_rules(BLOCK, "maildivvy DOCKER-USER")
    printed = [
        "-A DOCKER-USER -j ufw-user-forward",
        "-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
        "-A DOCKER-USER -d 172.16.0.0/12 -m conntrack --ctstate NEW -j maildivvy-docker-deny",
        '-A maildivvy-docker-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[MAILDIVVY DOCKER BLOCK] "',
        "-A maildivvy-docker-deny -j DROP",
    ]
    assert compare(expected, printed, ordered=True) == []
    swapped = [printed[1], printed[0], *printed[2:]]
    assert compare(expected, swapped, ordered=True) == ["the rules are in another order than the file's"]
    assert compare(expected, swapped, ordered=False) == []
    differences = compare(expected, printed[:-1] + ["-A maildivvy-docker-deny -j ACCEPT"], ordered=True)
    assert differences == ["missing: -A maildivvy-docker-deny -j DROP",
                           "unexpected: -A maildivvy-docker-deny -j ACCEPT"]


def test_a_missing_block_or_an_empty_chain_is_a_failure():
    assert block_rules(BLOCK.replace("maildivvy DOCKER-USER", "someone else"), "maildivvy DOCKER-USER") == []
    expected = block_rules(BLOCK, "maildivvy DOCKER-USER")
    differences = compare(expected, [], ordered=True)
    assert len(differences) == 5 and all(d.startswith("missing: ") for d in differences)


# --- the container address pool (preflight) ----------------------------------


def test_the_container_pool_must_not_overlap_an_administrator_network():
    assert setting_errors({**GOOD, "container_pool": "172.16.0.0/12"}) == []
    errors = setting_errors({**GOOD, "admin_networks": ["172.17.0.0/16"], "container_pool": "172.16.0.0/12"})
    assert len(errors) == 1 and errors[0].startswith("ambiguous container_pool:"), errors
    errors = setting_errors({**GOOD, "container_pool": "172.16.0.1/12"})
    assert len(errors) == 1 and errors[0].startswith("malformed container_pool:"), errors


# --- a local run's confirmation: a new SSH login from the stated source ------

SINCE = 1_790_000_000_000_000   # the journal's microseconds, when the wait began


def entry(message, usec=SINCE + 1, uid="0", exe="/usr/lib/openssh/sshd-session"):
    """One journal record as `journalctl -o json` prints it; `_UID` and `_EXE` are journald's own."""
    return {"MESSAGE": message, "__REALTIME_TIMESTAMP": str(usec), "_UID": uid, "_EXE": exe,
            "SYSLOG_IDENTIFIER": "sshd-session"}


ACCEPTED = "Accepted publickey for ops from {} port 48204 ssh2: ED25519 SHA256:x"


def test_a_login_is_read_from_sshds_own_accepted_lines_after_the_wait_began():
    entries = [entry(ACCEPTED.format("192.0.2.7")),
               entry(ACCEPTED.format("192.0.2.8"), exe="/usr/sbin/sshd"),        # an older OpenSSH
               entry("Accepted password for ops from 192.0.2.9 port 1 ssh2"),
               entry(ACCEPTED.format("2001:DB8:0::7")),
               entry(ACCEPTED.format("::ffff:192.0.2.10"))]
    assert accepted_logins(entries, SINCE) == ["192.0.2.7", "192.0.2.8", "192.0.2.9", "2001:db8::7",
                                               "192.0.2.10"]


def test_an_old_login_a_refused_one_or_a_line_anyone_could_log_is_not_a_login():
    entries = [entry(ACCEPTED.format("192.0.2.7"), usec=SINCE - 1),            # before the rules
               entry("Failed publickey for ops from 192.0.2.7 port 1 ssh2"),
               entry("Connection closed by 192.0.2.7 port 1 [preauth]"),
               entry(ACCEPTED.format("192.0.2.7"), uid="1000", exe="/usr/bin/logger"),  # `logger -t sshd-session`
               entry(ACCEPTED.format("192.0.2.7"), exe="/usr/bin/python3.14"),
               entry("Accepted publickey for ops from not-an-address port 1 ssh2")]
    assert accepted_logins(entries, SINCE) == []


class Machine:
    """What the wait reads, scripted: the journal, the timer, the revert, a clock."""

    def __init__(self, logins=(), fires_at=None, revert_seconds=3):
        self.now, self.logins, self.fires_at, self.revert_seconds = 0.0, dict(logins), fires_at, revert_seconds

    def entries(self):
        return [entry(ACCEPTED.format(address), usec=SINCE + int(at * 1e6))
                for at, address in self.logins.items() if at <= self.now]

    def armed(self):
        return self.fires_at is None or self.now < self.fires_at

    def reverting(self):
        return not self.armed() and self.now < self.fires_at + self.revert_seconds

    def sleep(self, seconds):
        self.now += seconds

    def wait(self, source="192.0.2.7", deadline=600):
        return wait_for_login(source, SINCE, self.entries, self.armed, self.reverting,
                              lambda: self.now, self.sleep, deadline)


def test_the_timer_stays_armed_until_a_login_from_the_stated_source_is_seen():
    machine = Machine(logins={10: "192.0.2.8", 40: "192.0.2.7"}, fires_at=300)
    assert machine.wait() == ("seen", "192.0.2.7")
    assert 40 <= machine.now < 45    # it did not stop at the other address's login


def test_with_no_login_the_wait_ends_only_once_the_timer_has_put_the_rules_back():
    machine = Machine(logins={10: "192.0.2.8"}, fires_at=300)
    assert machine.wait() == ("reverted", None)
    assert machine.now >= 303 and not machine.reverting()   # the revert has finished


def test_a_login_after_the_timer_fired_confirms_nothing():
    machine = Machine(logins={301: "192.0.2.7"}, fires_at=300)
    assert machine.wait() == ("reverted", None)


def test_the_wait_is_bounded_even_if_the_timer_never_fires():
    machine = Machine(fires_at=None)
    assert machine.wait(deadline=120) == ("timeout", None)
    assert 120 <= machine.now < 125


def test_both_firewall_steps_are_confirmed_the_same_way():
    roles = Path(__file__).resolve().parents[2] / "ansible" / "roles"
    firewall = yaml.safe_load((roles / "firewall" / "defaults" / "main.yml").read_text())
    block = yaml.safe_load((roles / "docker_block" / "defaults" / "main.yml").read_text())
    for name in ("maildivvy_firewall_confirmation", "maildivvy_admin_ssh_source"):
        assert firewall[name] == block[name], name
    assert firewall["maildivvy_firewall_confirmation"] == "new-session"   # the control machine's
