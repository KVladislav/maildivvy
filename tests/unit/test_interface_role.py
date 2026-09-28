"""Install step 15's pure parts: the proxy's site and the interface's unit.

The proxy itself - a request answered over 443, the TLS floor, the socket only its group
opens - is proved on the test VM. What is proved here
is what a machine cannot say: the values written in two places at once, which drift in
silence. The socket path is in the role and in the program's own default; the proxy's
unit name is in the role and in the certificate's consumer list; the TLS floor
is one line in one file, and the whole of the interface's TLS floor.
"""

import importlib.util
import re
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from maildivvy.admin import run

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "interface"
PROGRAMS = ROOT / "ansible" / "roles" / "programs"
CERT_PROGRAM = ROOT / "ansible" / "roles" / "certificate" / "files" / "maildivvy_cert.py"
CERT_NAME = "mail.example.test"

spec = importlib.util.spec_from_file_location("maildivvy_cert", CERT_PROGRAM)
cert = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cert)


def variables(**changes):
    """The role's own variables, resolved as Ansible resolves them, with a run's settings."""
    values = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())
    values["maildivvy_cert_name"] = CERT_NAME
    values["maildivvy_cert_mode"] = "self-signed"
    values.update(changes)
    env = Environment(undefined=StrictUndefined)
    for _ in range(4):                      # the role's vars name one another
        values = {name: yaml.safe_load(env.from_string(value).render(values))
                  if isinstance(value, str) and "{{" in value else value
                  for name, value in values.items()}
    return values


def render(name, **changes):
    env = Environment(loader=FileSystemLoader(str(ROLE / "templates")), undefined=StrictUndefined,
                      keep_trailing_newline=True)
    return env.get_template(name).render(variables(**changes))


def site(**changes):
    return render("maildivvy-admin.nginx.conf.j2", **changes)


def unit(**changes):
    return render("maildivvy-admin.service.j2", **changes)


def directives(text, name):
    """Every value the site gives this directive, whatever block it is in."""
    return [value.strip() for value in
            re.findall(rf"^\s*{re.escape(name)}\s+(.*?);\s*$", text, re.MULTILINE)]


# --- the proxy's site -------------------------------------------------------------------------


def test_the_tls_minimum_is_1_2_and_it_is_written_out():
    # ⛔ the floor is stated, never inherited: a default minimum moves between releases,
    # and this configuration is the only place the interface's TLS is decided.
    assert directives(site(), "ssl_protocols") == ["TLSv1.2 TLSv1.3"]
    assert "TLSv1" not in site().replace("TLSv1.2", "").replace("TLSv1.3", "")


def test_the_certificate_and_key_are_named_explicitly_and_are_the_published_pair():
    values = variables()
    assert directives(site(), "ssl_certificate") == [f"/etc/ssl/certs/{CERT_NAME}.crt"]
    assert directives(site(), "ssl_certificate_key") == [f"/etc/ssl/private/{CERT_NAME}.key"]
    assert directives(site(), "server_name") == [CERT_NAME]
    assert values["maildivvy_interface_cert"] == f"/etc/ssl/certs/{CERT_NAME}.crt"


def test_the_proxy_listens_on_443_alone_and_talks_to_the_unix_socket():
    values = variables()
    assert directives(site(), "listen") == [f"{values['maildivvy_interface_port']} ssl"]
    assert "80" not in " ".join(directives(site(), "listen"))
    assert directives(site(), "proxy_pass") == [
        f"http://unix:{values['maildivvy_interface_socket']}:"]


def test_the_client_address_is_written_by_the_proxy_and_never_appended_to():
    # ⛔ `$proxy_add_x_forwarded_for` APPENDS to what the browser sent, so a person could
    # put any address in front of their own. `$remote_addr` alone overwrites it, and the
    # application trusts the header only because it arrives on the proxy's own socket.
    forwarded = [value for value in directives(site(), "proxy_set_header")
                 if value.split()[0].lower() == "x-forwarded-for"]
    assert forwarded == ["X-Forwarded-For $remote_addr"]
    written = [line for line in site().splitlines() if not line.strip().startswith("#")]
    assert "proxy_add_x_forwarded_for" not in "\n".join(written)
    assert "X-Forwarded-Proto https" in site()


# --- the interface's unit ---------------------------------------------------------------------


def test_the_unit_says_when_it_is_ready_and_runs_as_the_interfaces_own_user():
    values, text = variables(), unit()
    assert "Type=notify" in text                      # READY=1 after the bind, never a log line
    assert f"User={values['maildivvy_interface_user']}" in text
    assert f"Group={values['maildivvy_interface_user']}" in text


def test_the_whole_exec_start_names_the_socket_and_the_group_that_may_open_it():
    values = variables()
    line = [one for one in unit().splitlines() if one.startswith("ExecStart=")]
    assert line == [f"ExecStart={values['maildivvy_interface_program']} "
                    f"--socket {values['maildivvy_interface_socket']} "
                    f"--socket-group {values['maildivvy_interface_proxy_group']}"]
    # ⛔ the widening goes this way and no other: the interface takes the proxy's group so
    # it can hand its own socket over, and the proxy never takes the interface's, which
    # would open /etc/maildivvy/admin - the passfile and the session secret - to it.
    assert f"SupplementaryGroups={values['maildivvy_interface_proxy_group']}" in unit()


def test_the_unit_writes_its_socket_directory_and_nothing_else():
    values = variables()
    lines = [one for one in unit().splitlines() if one.startswith("ReadWritePaths=")]
    assert lines == [f"ReadWritePaths={values['maildivvy_interface_socket_dir']}"]
    assert "ProtectSystem=strict" in unit()
    assert "UMask=0077" in unit()


def test_the_interface_starts_after_the_database_and_before_the_proxy():
    values, text = variables(), unit()
    after = [one.removeprefix("After=").split() for one in text.splitlines() if one.startswith("After=")]
    assert {"postgresql.service", "network-online.target"} <= set(sum(after, []))
    # a proxy that came up first would answer 502 to the first person through the door
    assert f"Before={values['maildivvy_interface_proxy_unit']}" in text


# --- the same value in two places ---------------------------------------------------------------


def test_the_socket_the_role_installs_is_the_one_the_program_binds_by_default():
    assert variables()["maildivvy_interface_socket"] == run.SOCKET


def test_the_certificates_deploy_hook_names_this_proxy_and_reloads_it():
    # the hook's list carried this name as a placeholder from step 5;
    # the proxy is chosen here, so the two are held together.
    values = variables()
    unit_name = values["maildivvy_interface_proxy_unit"].removesuffix(".service")
    assert (unit_name, "reload") in cert.CONSUMERS
    assert [name for name, _ in cert.CONSUMERS if name == unit_name] == [unit_name]


def test_the_key_is_reached_by_the_proxys_user_and_by_nothing_of_ours():
    values = variables()
    # reversed the entry: our interface holds no certificate at all, so it is the
    # proxy's user that joins ssl-cert, and the interface's user stays in no group but its own.
    assert values["maildivvy_interface_proxy_groups"] == ["ssl-cert"]
    users = yaml.safe_load((PROGRAMS / "vars" / "main.yml").read_text())["maildivvy_program_users"]
    admin = [user for user in users if user["name"] == values["maildivvy_interface_user"]]
    assert admin and admin[0]["groups"] == []
