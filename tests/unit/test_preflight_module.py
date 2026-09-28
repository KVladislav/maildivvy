"""Install step 1's checks, as pure functions: the settings (the disks: test_disk_settings.py)."""

import pytest

from maildivvy_preflight import foreign_mail_errors, hostname_errors, installed_packages, setting_errors

GOOD = {
    "hostname": "mail",
    "cert_name": "mail.example.test",
    "vmail_uid": 900,
    "vmail_gid": 900,
    "admin_networks": ["192.0.2.0/24", "2001:db8::/64"],
    "breakglass_password": "correct horse battery",
    "acme_dns_credentials": {"DESEC_TOKEN": "scoped-token"},
}


def test_complete_settings_are_accepted():
    assert setting_errors(GOOD) == []


def test_every_missing_setting_is_listed_at_once():
    errors = setting_errors({})
    for name in ("hostname", "cert_name", "vmail_uid", "vmail_gid", "admin_networks", "breakglass_password"):
        assert any(e.startswith(f"missing {name}:") for e in errors), name
    # the disks are asked for by the disk plan, only where a first install needs them
    assert not any("_disk" in e for e in errors)


def test_an_empty_value_counts_as_missing():
    errors = setting_errors({**GOOD, "hostname": "", "admin_networks": []})
    assert [e.split(":")[0] for e in errors] == ["missing hostname", "missing admin_networks"]


@pytest.mark.parametrize("name, value", [
    ("hostname", "Mail_01"),
    ("hostname", "mail.example.test"),
    ("cert_name", "mail"),
    ("cert_name", "-mail.example.test"),
    ("vmail_uid", 0),
    ("vmail_uid", 1000),
    ("vmail_gid", "nine hundred"),
    ("vmail_uid", True),
    ("store_disk", "/srv/store"),
    ("swap_disk", 3),
    ("admin_networks", "192.0.2.0/24"),
    ("admin_networks", ["192.0.2.1/24"]),
    ("admin_networks", ["not a network"]),
    ("backup_keep", 0),
    ("backup_keep", "all"),
    ("backup_store_copy", "rsync -aH /srv/maildivvy/store/ /copy/\nrm -rf /"),
    ("backup_store_copy", ["rsync"]),
])
def test_a_malformed_setting_is_refused(name, value):
    errors = setting_errors({**GOOD, name: value})
    assert len(errors) == 1 and errors[0].startswith(f"malformed {name}:"), errors


def test_numbers_may_arrive_as_strings():
    assert setting_errors({**GOOD, "vmail_uid": "900", "vmail_gid": "900"}) == []


def test_the_backup_settings_are_optional_and_a_store_copy_is_one_line():
    assert setting_errors({**GOOD, "backup_keep": 8, "backup_store_copy": ""}) == []
    assert setting_errors({**GOOD, "backup_keep": "14",
                           "backup_store_copy": "rsync -aH --delete /srv/maildivvy/store/ "
                                                "backup@copy.example.test:store/"}) == []


def test_a_break_glass_password_under_15_characters_is_refused():
    errors = setting_errors({**GOOD, "breakglass_password": "x" * 14})
    assert len(errors) == 1 and errors[0].startswith("malformed breakglass_password:")
    assert "x" * 14 not in errors[0]  # the refusal never echoes the password
    # the control: 15 characters, no composition rule, and 64 are accepted
    assert setting_errors({**GOOD, "breakglass_password": "x" * 15}) == []
    assert setting_errors({**GOOD, "breakglass_password": "y" * 64}) == []


@pytest.mark.parametrize("network, wide", [
    ("0.0.0.0/1", True), ("0.0.0.0/0", True), ("8.0.0.0/8", True), ("203.0.0.0/12", True),
    ("::/1", True), ("2000::/3", True), ("2001:db8::/32", False),
    ("10.0.0.0/8", False), ("172.16.0.0/12", False), ("8.8.0.0/16", False),
    ("198.51.100.0/24", False), ("203.0.113.0/28", False), ("fd00::/8", False), ("2a01:4f8::/48", False),
])
def test_an_administrator_network_wide_enough_to_exempt_the_internet_is_refused(network, wide):
    """An administrator network is exempt from every ban and every
    rate limit, so `0.0.0.0/1` exempted half the internet and preflight took it. A network
    wider than /16 (IPv4) or /48 (IPv6) must be a private range; none may be wider than /8."""
    errors = setting_errors({**GOOD, "admin_networks": [network]})
    if wide:
        assert len(errors) == 1 and errors[0].startswith("too wide admin_networks:") and network in errors[0]
    else:
        assert errors == []


# --- the machine the settings are for -------------------------------------------


@pytest.mark.parametrize("actual", ["mail", "MAIL", "mail.example.test"])
def test_the_settings_hostname_is_the_machines_own(actual):
    # the machine's name as the kernel gives it: its first label, in any case
    assert hostname_errors("mail", actual) == []


def test_settings_for_another_machine_are_refused_naming_both():
    errors = hostname_errors("mail", "backup01")
    assert errors == ["wrong hostname: this machine is backup01, and the settings are for mail; "
                      "run the install against the machine they name, or correct maildivvy_hostname"]


# --- how a firewall change is confirmed ---------------------------------


@pytest.mark.parametrize("changes", [
    {},                                                          # a control machine's new session
    {"firewall_confirmation": "new-session"},
    {"firewall_confirmation": "ssh-login", "admin_ssh_source": "192.0.2.7"},
    {"firewall_confirmation": "ssh-login", "admin_ssh_source": "2001:db8::7"},
    {"firewall_confirmation": "console"},
])
def test_each_way_of_confirming_the_firewall_is_accepted_with_what_it_needs(changes):
    assert setting_errors({**GOOD, **changes}) == []


def test_a_confirmation_by_ssh_login_needs_the_administrators_source_address():
    errors = setting_errors({**GOOD, "firewall_confirmation": "ssh-login"})
    assert len(errors) == 1 and errors[0].startswith("missing admin_ssh_source:"), errors


@pytest.mark.parametrize("source", ["198.51.100.7", "2001:db8:1::7", "203.0.113.9"])
def test_a_source_outside_the_administrator_networks_is_refused(source):
    errors = setting_errors({**GOOD, "firewall_confirmation": "ssh-login", "admin_ssh_source": source})
    assert len(errors) == 1 and errors[0].startswith("refused admin_ssh_source:"), errors
    assert source in errors[0]   # an address, not a secret: named so it can be corrected


@pytest.mark.parametrize("name, value", [
    ("firewall_confirmation", "ping"),
    ("firewall_confirmation", True),
    ("admin_ssh_source", "192.0.2.0/24"),
    ("admin_ssh_source", "mail.example.test"),
])
def test_a_malformed_confirmation_setting_is_refused(name, value):
    settings = {**GOOD, "firewall_confirmation": "ssh-login", "admin_ssh_source": "192.0.2.7", name: value}
    errors = setting_errors(settings)
    assert errors and errors[0].startswith(f"malformed {name}:"), errors


@pytest.mark.parametrize("confirmation", [None, "new-session", "console"])
def test_a_source_address_with_another_confirmation_is_ambiguous(confirmation):
    settings = {**GOOD, "admin_ssh_source": "192.0.2.7"}
    if confirmation:
        settings["firewall_confirmation"] = confirmation
    errors = setting_errors(settings)
    assert len(errors) == 1 and errors[0].startswith("ambiguous admin_ssh_source:"), errors


@pytest.mark.parametrize("connection", ["local", "ansible.builtin.local"])
def test_a_local_connection_can_never_confirm_the_firewall_by_its_own_session(connection):
    """Over a local connection nothing crosses the firewall, so a new session proves
    nothing: the run must wait for an SSH login or be told it is console-only."""
    for settings in ({**GOOD}, {**GOOD, "firewall_confirmation": "new-session"}):
        errors = setting_errors(settings, connection=connection)
        assert len(errors) == 1 and errors[0].startswith("refused firewall_confirmation:"), errors
    # the controls: the two ways a local run may take, and a control machine's session
    assert setting_errors({**GOOD, "firewall_confirmation": "console"}, connection=connection) == []
    assert setting_errors({**GOOD, "firewall_confirmation": "ssh-login", "admin_ssh_source": "192.0.2.7"},
                          connection=connection) == []
    assert setting_errors({**GOOD}, connection="ssh") == []


# --- a mail system that is not ours ---------------------------------------


DPKG = "ii \tpostfix\nii \tdovecot-core\nii \tnginx-core\nrc \texim4-daemon-light\nii \tcurl\n"


def test_a_fresh_machine_or_our_own_mail_system_passes():
    assert foreign_mail_errors(installed_packages("ii \tcurl\nii \tnginx-core\n"), ours=False) == []
    assert foreign_mail_errors(installed_packages(DPKG), ours=True) == []


def test_a_package_left_only_as_configuration_is_not_installed():
    assert "exim4-daemon-light" not in installed_packages(DPKG)
    assert {"postfix", "dovecot-core", "curl"} <= installed_packages(DPKG)


def test_postfix_or_dovecot_this_install_did_not_put_there_is_refused():
    errors = foreign_mail_errors(installed_packages(DPKG), ours=False)
    assert errors == ["refused mail system: dovecot-core, postfix installed, and this install did not "
                      "put them there; Maildivvy must be the only mail system on the machine, so remove "
                      "them or install on a fresh machine"]


@pytest.mark.parametrize("package", ["exim4-daemon-light", "sendmail-bin", "opensmtpd", "courier-imap",
                                     "cyrus-imapd", "nullmailer", "rspamd"])
def test_any_other_mail_system_is_refused_even_on_our_machine(package):
    errors = foreign_mail_errors(installed_packages(DPKG + f"ii \t{package}\n"), ours=True)
    assert len(errors) == 1 and errors[0].startswith(f"refused mail system: {package} installed"), errors
