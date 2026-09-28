"""Install step 5 without issuing: the certificate program the role installs, the lego
release check, and the certificate settings of preflight.

The program (`ansible/roles/certificate/files/maildivvy_cert.py`, installed as
`/usr/local/sbin/maildivvy-cert`) is driven here with a configuration pointing into a
temporary directory, a fake `lego` that answers `dnshelp` as lego does and records what
`run` was given, and a fake `systemctl`.
"""

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from maildivvy_checksum import ChecksumError, anchored_checksum, verify
import maildivvy_preflight
from maildivvy_preflight import setting_errors

ROOT = Path(__file__).resolve().parents[2]
PROGRAM = ROOT / "ansible" / "roles" / "certificate" / "files" / "maildivvy_cert.py"
spec = importlib.util.spec_from_file_location("maildivvy_cert", PROGRAM)
cert = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cert)

TOKEN = "s3cr3t-T0KEN-value-for-one-record"
NAME = "mail.example.test"
GOOD = {
    "hostname": "mail", "cert_name": NAME, "vmail_uid": 900, "vmail_gid": 900,
    "store_gib": 12, "index_gib": 6, "admin_networks": ["192.0.2.0/24"],
    "breakglass_password": "correct horse battery", "acme_dns_credentials": {"DESEC_TOKEN": TOKEN},
}

# `lego dnshelp -c <provider>` as lego 5.4.1 prints it (read on the test VM, 2026-09-25),
# shortened to the lines the program reads
DNSHELP = {
    "desec": """Configuration for deSEC.io.
Code:   'desec'
Since:  'v3.7.0'

Credentials:
  - "DESEC_TOKEN":  Domain token

Additional Configuration:
  - "DESEC_HTTP_TIMEOUT":         API request timeout in seconds (Default: 30)
  - "DESEC_POLLING_INTERVAL":     Time between DNS propagation check in seconds (Default: 4)
  - "DESEC_PROPAGATION_TIMEOUT":  Maximum waiting time for DNS propagation in seconds (Default: 120)
  - "DESEC_TTL":                  The TTL of the TXT record used for the DNS challenge in seconds (Default: 3600)

More information: https://go-acme.github.io/lego/dns/desec
""",
    "cloudflare": """Configuration for Cloudflare.
Code:   'cloudflare'
Since:  'v0.3.0'

Credentials:
  - "CF_API_EMAIL":               Account email
  - "CF_API_KEY":                 API key
  - "CF_DNS_API_TOKEN":           API token with DNS:Edit permission (since v3.1.0)
  - "CF_ZONE_API_TOKEN":          API token with Zone:Read permission (since v3.1.0)
  - "CLOUDFLARE_DNS_API_TOKEN":   Alias to CF_DNS_API_TOKEN

Additional Configuration:
  - "CLOUDFLARE_BASE_URL":             API base URL (Default: https://api.cloudflare.com/client/v4)
  - "CLOUDFLARE_POLLING_INTERVAL":     Time between DNS propagation check in seconds (Default: 2)
  - "CLOUDFLARE_PROPAGATION_TIMEOUT":  Maximum waiting time for DNS propagation in seconds (Default: 120)
  - "CLOUDFLARE_TTL":                  The TTL of the TXT record used for the DNS challenge in seconds (Default: 120)

More information: https://go-acme.github.io/lego/dns/cloudflare
""",
    "route53": """Configuration for Amazon Route 53.
Code:   'route53'
Since:  'v0.3.0'

Credentials:
  - "AWS_ACCESS_KEY_ID":                 Managed by the AWS client. Access key ID ('AWS_ACCESS_KEY_ID_FILE' is not supported, use 'AWS_SHARED_CREDENTIALS_FILE' instead)
  - "AWS_HOSTED_ZONE_ID":                Override the hosted zone ID.
  - "AWS_SECRET_ACCESS_KEY":             Managed by the AWS client. Secret access key ('AWS_SECRET_ACCESS_KEY_FILE' is not supported, use 'AWS_SHARED_CREDENTIALS_FILE' instead)

Additional Configuration:
  - "AWS_POLLING_INTERVAL":         Time between DNS propagation check in seconds (Default: 4)
  - "AWS_PROPAGATION_TIMEOUT":      Maximum waiting time for DNS propagation in seconds (Default: 120)

More information: https://go-acme.github.io/lego/dns/route53
""",
    "exec": """Configuration for External program.
Code:   'exec'
Since:  'v0.5.0'


More information: https://go-acme.github.io/lego/dns/exec
""",
}

# a stand-in for lego: `dnshelp -c` answers from DNSHELP, as lego does (an unknown code
# exits 1); anything else records its argv and environment, as `lego run` would be given
FAKE_LEGO = """#!{python}
import json, os, sys
HELP = json.loads({help!r})
if sys.argv[1:3] == ["dnshelp", "-c"]:
    if sys.argv[3] not in HELP:
        print('ERROR Error error="%s is not yet supported"' % sys.argv[3], file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(HELP[sys.argv[3]])
    sys.exit(0)
with open({record!r}, "w") as f:
    json.dump({{"argv": sys.argv, "env": dict(os.environ)}}, f)
"""


def config(tmp_path, mode="acme", **extra):
    lego_path = tmp_path / "lego" / ("staging" if mode == "acme-staging" else "")
    values = {
        "mode": mode,
        "cert_name": NAME,
        "published_cert": str(tmp_path / "certs" / f"{NAME}.crt"),
        "published_key": str(tmp_path / "private" / f"{NAME}.key"),
        "cert_owner": os.getuid(), "cert_group": os.getgid(), "key_group": os.getgid(),
        "lego": str(tmp_path / "bin" / "lego"),
        "lego_path": str(lego_path),
        "server": "letsencrypt-staging" if mode == "acme-staging" else "letsencrypt",
        "email": "-",
        "dns_provider": "desec",
        "credentials_dir": str(tmp_path / "lego" / "credentials"),
        "credentials_env": str(tmp_path / "certificate.env"),
        "propagation_timeout": 3900,
        "polling_interval": 30,
        "resolvers": ["1.1.1.1:53", "8.8.8.8:53"],
        "provided_cert": None, "provided_chain": None, "provided_key": None,
        "deploy_hook": f"/usr/local/sbin/maildivvy-cert --config {tmp_path / 'certificate.json'} deploy",
        **extra,
    }
    for d in ("certs", "private", "bin", "lego"):
        (tmp_path / d).mkdir(exist_ok=True, mode=0o700)
    lego = tmp_path / "bin" / "lego"
    lego.write_text(FAKE_LEGO.format(python=sys.executable, help=json.dumps(DNSHELP),
                                     record=str(tmp_path / "lego-record.json")))
    lego.chmod(0o755)
    path = tmp_path / "certificate.json"
    path.write_text(json.dumps(values))
    return values, path


def run(path, *args, stdin="", env=None):
    return subprocess.run([sys.executable, str(PROGRAM), "--config", str(path), *args],
                          input=stdin, capture_output=True, text=True, env=env)


def store(path, provider=None, **given):
    """`store-credentials` with a provider set in the configuration and `given` on stdin."""
    if provider:
        values = json.loads(path.read_text())
        values["dns_provider"] = provider
        path.write_text(json.dumps(values))
    return run(path, "store-credentials", stdin=json.dumps(given))


def env_file(values):
    return dict(line.split("=", 1) for line in Path(values["credentials_env"]).read_text().splitlines()
                if line and not line.startswith("#"))


# --- the provider's credential names, read from lego ---------------------------


def test_the_credential_names_are_read_from_legos_dnshelp():
    read = cert.parse_dnshelp(DNSHELP["cloudflare"])
    assert read.credentials == ["CF_API_EMAIL", "CF_API_KEY", "CF_DNS_API_TOKEN", "CF_ZONE_API_TOKEN",
                                "CLOUDFLARE_DNS_API_TOKEN"]
    assert read.propagation == "CLOUDFLARE_PROPAGATION_TIMEOUT"
    assert read.polling == "CLOUDFLARE_POLLING_INTERVAL"
    assert read.no_file == []
    route53 = cert.parse_dnshelp(DNSHELP["route53"])
    assert route53.no_file == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]  # lego cannot read them from a file
    assert cert.parse_dnshelp(DNSHELP["exec"]).credentials == []


def test_each_credential_is_stored_0600_and_reaches_lego_as_a_file_variable(tmp_path):
    values, path = config(tmp_path)
    result = store(path, "cloudflare", credentials={"CF_DNS_API_TOKEN": TOKEN, "CF_ZONE_API_TOKEN": "zone-" + TOKEN})
    assert result.returncode == 0, result.stderr
    stored = Path(values["credentials_dir"]) / "CF_DNS_API_TOKEN"
    assert stored.read_text() == TOKEN + "\n"
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(values["credentials_dir"]).stat().st_mode) == 0o700
    assert env_file(values) == {
        "CF_DNS_API_TOKEN_FILE": str(stored),
        "CF_ZONE_API_TOKEN_FILE": str(Path(values["credentials_dir"]) / "CF_ZONE_API_TOKEN"),
        "CLOUDFLARE_PROPAGATION_TIMEOUT": "3900",
        "CLOUDFLARE_POLLING_INTERVAL": "30",
    }
    assert stat.S_IMODE(Path(values["credentials_env"]).stat().st_mode) == 0o600
    assert TOKEN not in result.stdout + result.stderr + Path(values["credentials_env"]).read_text()
    assert "stored CF_DNS_API_TOKEN" in result.stdout.splitlines()
    again = store(path, credentials={"CF_DNS_API_TOKEN": TOKEN, "CF_ZONE_API_TOKEN": "zone-" + TOKEN})
    assert "stored" not in again.stdout and "unchanged CF_DNS_API_TOKEN" in again.stdout.splitlines()


def test_desec_is_reported_as_tested_and_any_other_provider_as_untested(tmp_path):
    _, path = config(tmp_path)
    tested = store(path, credentials={"DESEC_TOKEN": TOKEN})
    assert "desec: tested with Maildivvy" in tested.stdout.splitlines()
    untested = store(path, "cloudflare", credentials={"CF_DNS_API_TOKEN": TOKEN})
    assert any(line.startswith("cloudflare: UNTESTED with Maildivvy") for line in untested.stdout.splitlines())
    assert "tested with Maildivvy" not in untested.stdout.replace("UNTESTED with Maildivvy", "")


@pytest.mark.parametrize("provider, given, words", [
    ("cloudflare", {"credentials": {"CF_API_TOKN": TOKEN}}, "not a credential cloudflare takes: CF_API_TOKN"),
    ("cloudflare", {"credentials": {}}, "no credential given"),
    ("route53", {"credentials": {"AWS_SECRET_ACCESS_KEY": TOKEN}}, "cannot read AWS_SECRET_ACCESS_KEY from a file"),
    ("nosuch", {"credentials": {"NOSUCH_TOKEN": TOKEN}}, "lego does not know the DNS provider nosuch"),
    ("exec", {"credentials": {"EXEC_PATH": TOKEN}}, "exec takes no credential"),
    ("desec", {"credentials": {"DESEC_TOKEN": "two\nlines"}}, "malformed DESEC_TOKEN"),
    ("desec", {"credentials": {"DESEC_TOKEN": TOKEN}, "token": TOKEN}, "expected {\"credentials\": {...}}"),
    ("desec", {"token": TOKEN}, "expected {\"credentials\": {...}}"),
])
def test_a_credential_lego_would_not_read_from_its_file_is_refused_and_nothing_stored(tmp_path, provider, given,
                                                                                       words):
    values, path = config(tmp_path)
    result = store(path, provider, **given)
    assert result.returncode == 2
    assert words in result.stderr
    assert TOKEN not in result.stdout + result.stderr
    assert not Path(values["credentials_env"]).exists()
    assert not Path(values["credentials_dir"]).exists() or not any(Path(values["credentials_dir"]).iterdir())


def test_desecs_token_is_its_one_credential(tmp_path):
    values, path = config(tmp_path)
    result = store(path, credentials={"DESEC_TOKEN": TOKEN})
    assert result.returncode == 0, result.stderr
    assert env_file(values)["DESEC_TOKEN_FILE"] == str(Path(values["credentials_dir"]) / "DESEC_TOKEN")


def test_a_credential_no_longer_given_is_removed(tmp_path):
    values, path = config(tmp_path)
    store(path, "cloudflare", credentials={"CF_API_EMAIL": "a@example.test", "CF_API_KEY": TOKEN})
    result = store(path, credentials={"CF_DNS_API_TOKEN": TOKEN})
    assert "removed CF_API_KEY" in result.stdout.splitlines()
    assert sorted(p.name for p in Path(values["credentials_dir"]).iterdir()) == ["CF_DNS_API_TOKEN"]
    assert "CF_API_KEY_FILE" not in env_file(values)


@pytest.mark.parametrize("stdin", ["", "not json", "[]", '{"credentials": ["DESEC_TOKEN"]}'])
def test_malformed_input_on_stdin_is_refused_and_not_echoed(tmp_path, stdin):
    values, path = config(tmp_path)
    result = run(path, "store-credentials", stdin=stdin)
    assert result.returncode == 2 and "stdin" in result.stderr
    assert not Path(values["credentials_env"]).exists()


def test_lego_is_run_with_the_credential_files_never_the_values(tmp_path):
    values, path = config(tmp_path)
    store(path, credentials={"DESEC_TOKEN": TOKEN})
    argv = cert.lego_argv(values)
    env = cert.lego_env(values, {"PATH": "/usr/bin", "DESEC_TOKEN": TOKEN, "DESEC_TOKEN_FILE": "/elsewhere"})
    assert argv == [
        values["lego"], "--log.format", "text", "run", "--accept-tos", "--server", "letsencrypt",
        "--dns", "desec", "--dns.resolvers", "1.1.1.1:53,8.8.8.8:53",
        "--domains", NAME, "--path", values["lego_path"],
        "--deploy-hook", values["deploy_hook"],
    ]
    assert env == {
        "PATH": "/usr/bin",  # an inherited credential variable is dropped
        "DESEC_TOKEN_FILE": str(Path(values["credentials_dir"]) / "DESEC_TOKEN"),
        "DESEC_PROPAGATION_TIMEOUT": "3900",
        "DESEC_POLLING_INTERVAL": "30",
    }
    assert "renew" not in argv  # lego 5 has no renew subcommand; run decides


def test_a_contact_address_is_passed_when_there_is_one(tmp_path):
    values, _ = config(tmp_path, email="hostmaster@example.test")
    argv = cert.lego_argv(values)
    assert argv[argv.index("--email") + 1] == "hostmaster@example.test"


def test_staging_has_its_own_server_and_storage_path(tmp_path):
    live, _ = config(tmp_path)
    staging, _ = config(tmp_path, mode="acme-staging")
    live_argv, staging_argv = cert.lego_argv(live), cert.lego_argv(staging)
    assert staging_argv[staging_argv.index("--server") + 1] == "letsencrypt-staging"
    assert staging_argv[staging_argv.index("--path") + 1] != live_argv[live_argv.index("--path") + 1]


@pytest.mark.parametrize("provider, credentials", [
    ("desec", {"DESEC_TOKEN": TOKEN}),
    ("cloudflare", {"CF_API_EMAIL": "a@example.test", "CF_API_KEY": TOKEN}),
])
def test_run_execs_lego_with_no_credential_in_its_argv_or_environment(tmp_path, provider, credentials):
    _, path = config(tmp_path)
    assert store(path, provider, credentials=credentials).returncode == 0
    env = {"PATH": os.environ["PATH"], **credentials}  # even when the caller had them
    result = run(path, "run", env=env)
    assert result.returncode == 0, result.stderr
    seen = json.loads((tmp_path / "lego-record.json").read_text())
    assert "run" in seen["argv"] and seen["argv"][seen["argv"].index("--dns") + 1] == provider  # the control
    assert not any(TOKEN in a for a in seen["argv"])
    assert not any(TOKEN in v for v in seen["env"].values())
    assert {f"{name}_FILE" for name in credentials} <= set(seen["env"])
    assert TOKEN not in result.stdout + result.stderr


def test_run_without_stored_credentials_names_the_missing_file(tmp_path):
    values, path = config(tmp_path)
    result = run(path, "run")
    assert result.returncode == 2
    assert values["credentials_env"] in result.stderr


# --- the deploy hook --------------------------------------------------


class Systemctl:
    def __init__(self, enabled, failing=()):
        self.enabled, self.failing, self.calls = set(enabled), set(failing), []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "is-enabled"]:
            return 0 if argv[-1] in self.enabled else 1
        return 1 if argv[-1] in self.failing else 0


def issued(values):
    base = Path(values["lego_path"]) / "certificates"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    (base / f"{NAME}.crt").write_text("CERT\n")
    (base / f"{NAME}.key").write_text("KEY\n")
    (base / f"{NAME}.key").chmod(0o600)


def test_one_list_names_every_consumer_and_how_it_rereads_its_certificate():
    assert cert.CONSUMERS == (("dovecot", "reload"), ("postfix", "reload"), ("nginx", "reload"))


def test_deploy_republishes_the_certificate_0644_and_the_key_0640(tmp_path):
    values, _ = config(tmp_path)
    issued(values)
    cert.deploy(values, Systemctl(enabled=()), out=lambda *_: None)
    crt, key = Path(values["published_cert"]), Path(values["published_key"])
    assert crt.read_text() == "CERT\n" and key.read_text() == "KEY\n"
    assert stat.S_IMODE(crt.stat().st_mode) == 0o644
    assert stat.S_IMODE(key.stat().st_mode) == 0o640
    assert (crt.stat().st_uid, key.stat().st_gid) == (values["cert_owner"], values["key_group"])


def test_deploy_reloads_the_installed_consumers_and_skips_the_others(tmp_path):
    values, _ = config(tmp_path)
    issued(values)
    systemctl, lines = Systemctl(enabled={"dovecot"}), []
    assert cert.deploy(values, systemctl, out=lines.append) == 0
    assert ["systemctl", "reload", "dovecot"] in systemctl.calls  # the control: one is reloaded
    assert not any(c[1] == "reload" and c[2] in ("postfix", "nginx") for c in systemctl.calls)
    assert "skipped postfix: not installed" in lines and "skipped nginx: not installed" in lines


def test_deploy_fails_after_trying_every_consumer_when_one_reload_fails(tmp_path):
    values, _ = config(tmp_path)
    issued(values)
    systemctl, lines = Systemctl(enabled={"dovecot", "postfix"}, failing={"dovecot"}), []
    assert cert.deploy(values, systemctl, out=lines.append) == 1
    assert ["systemctl", "reload", "postfix"] in systemctl.calls
    assert "reload dovecot failed" in lines


def test_deploy_names_the_missing_source_file(tmp_path):
    values, path = config(tmp_path)
    result = run(path, "deploy")
    assert result.returncode == 1
    assert str(Path(values["lego_path"]) / "certificates" / f"{NAME}.crt") in result.stderr
    assert not Path(values["published_cert"]).exists()


# --- self-signed mode (test machines only) ----------------------


def openssl(*args):
    return subprocess.run(["openssl", *args], capture_output=True, text=True, check=True).stdout


def test_self_signed_publishes_a_certificate_for_the_name_at_the_acme_paths(tmp_path):
    values, path = config(tmp_path, mode="self-signed")
    result = run(path, "self-sign")
    assert result.returncode == 0, result.stderr
    assert "self-signed" in result.stdout
    crt, key = Path(values["published_cert"]), Path(values["published_key"])
    assert f"DNS:{NAME}" in openssl("x509", "-noout", "-ext", "subjectAltName", "-in", str(crt))
    assert stat.S_IMODE(crt.stat().st_mode) == 0o644
    assert stat.S_IMODE(key.stat().st_mode) == 0o640
    assert openssl("x509", "-noout", "-pubkey", "-in", str(crt)) == openssl("pkey", "-pubout", "-in", str(key))
    before = crt.read_bytes()
    again = run(path, "self-sign")
    assert again.stdout.strip() == f"unchanged: {crt} names {NAME} and matches its key"
    assert crt.read_bytes() == before


def test_a_new_self_signed_certificate_is_reread_by_every_installed_consumer(tmp_path):
    # found by the provided-mode VM run: back in self-signed mode, the new pair was
    # published and nginx went on serving the provided one, so step 15's request failed
    values, _ = config(tmp_path, mode="self-signed")
    systemctl, lines = Systemctl(enabled={"dovecot", "postfix", "nginx"}), []
    assert cert.self_sign(values, systemctl, out=lines.append) == 0
    assert lines[0].startswith("created a self-signed certificate")
    assert ["systemctl", "reload", "nginx"] in systemctl.calls and "reload dovecot" in lines
    kept = Systemctl(enabled={"dovecot"})
    cert.self_sign(values, kept, out=lambda *_: None)
    assert kept.calls == []  # an unchanged certificate reloads nothing


@pytest.mark.parametrize("days", [1, 29])
def test_self_signed_replaces_its_own_certificate_that_ends_soon(tmp_path, days):
    """Nothing renews a self-signed certificate: a run within 30 days of its end makes a new one."""
    values, path = config(tmp_path, mode="self-signed")
    crt, key = values["published_cert"], values["published_key"]
    Path(crt).parent.mkdir(parents=True, exist_ok=True)
    Path(key).parent.mkdir(parents=True, exist_ok=True)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days",
            str(days), "-subj", f"/CN={NAME}", "-addext", f"subjectAltName=DNS:{NAME}", "-keyout", key, "-out", crt)
    before = Path(crt).read_bytes()
    result = run(path, "self-sign")
    assert result.returncode == 0 and "created a self-signed certificate" in result.stdout, result.stdout
    assert Path(crt).read_bytes() != before
    assert run(path, "self-sign").stdout.startswith("unchanged:")


def test_self_signed_replaces_a_certificate_for_another_name(tmp_path):
    values, path = config(tmp_path, mode="self-signed")
    run(path, "self-sign")
    values["cert_name"] = "other.example.test"
    path.write_text(json.dumps(values))
    run(path, "self-sign")
    assert "DNS:other.example.test" in openssl("x509", "-noout", "-ext", "subjectAltName",
                                               "-in", values["published_cert"])


def test_switching_to_self_signed_replaces_a_ca_issued_certificate_nothing_would_renew(tmp_path):
    """A certificate for the right name that matches its key was
    kept, so a machine switched from acme to self-signed kept its ACME or staging
    certificate - issued by a CA, renewed by nothing now - until it expired. Only a
    certificate this program made itself, issued by its own subject, is kept."""
    values, path = config(tmp_path, mode="self-signed")
    crt, key = values["published_cert"], values["published_key"]
    ca_key, ca_crt = tmp_path / "ca.key", tmp_path / "ca.crt"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
            "-subj", "/CN=(STAGING) Test Intermediate", "-keyout", str(ca_key), "-out", str(ca_crt))
    csr = tmp_path / "leaf.csr"
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-subj", f"/CN={NAME}", "-keyout", key, "-out", str(csr))
    ext = tmp_path / "ext"
    ext.write_text(f"subjectAltName=DNS:{NAME}\n")
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-days", "2",
            "-extfile", str(ext), "-out", crt)
    assert "(STAGING)" in openssl("x509", "-noout", "-issuer", "-in", crt)      # the ACME-like leaf
    result = run(path, "self-sign")
    assert result.returncode == 0 and "created a self-signed certificate" in result.stdout, result.stdout
    assert openssl("x509", "-noout", "-issuer", "-in", crt).split("=", 1)[1] == \
        openssl("x509", "-noout", "-subject", "-in", crt).split("=", 1)[1]
    assert run(path, "self-sign").stdout.startswith("unchanged:")          # and now it is kept


def test_renewal_in_self_signed_mode_runs_nothing_and_leaves_the_certificate(tmp_path):
    values, path = config(tmp_path, mode="self-signed")
    run(path, "self-sign")
    before = Path(values["published_cert"]).read_bytes()
    result = run(path, "run")
    assert result.returncode == 0
    assert "self-signed mode: no ACME renewal" in result.stdout
    assert Path(values["published_cert"]).read_bytes() == before


@pytest.mark.parametrize("mode, command", [
    ("self-signed", "store-credentials"), ("provided", "store-credentials"), ("provided", "self-sign"),
])
def test_commands_of_another_mode_are_refused(tmp_path, mode, command):
    _, path = config(tmp_path, mode=mode)
    result = run(path, command, stdin=json.dumps({"credentials": {"DESEC_TOKEN": TOKEN}}))
    assert result.returncode == 2
    expected = f"{mode} mode: no DNS credentials" if command == "store-credentials" else "is only for mode self-signed"
    assert expected in result.stderr


def test_deploy_is_refused_in_self_signed_mode(tmp_path):
    _, path = config(tmp_path, mode="self-signed")
    result = run(path, "deploy")
    assert result.returncode == 2 and "self-signed mode" in result.stderr


def test_self_sign_is_refused_in_acme_mode(tmp_path):
    values, path = config(tmp_path)
    result = run(path, "self-sign")
    assert result.returncode == 2 and "self-sign" in result.stderr
    assert not Path(values["published_cert"]).exists()


# --- a provided certificate ------------------------------------------------------


def ec_key(path):
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", str(path))
    return path


def make_ca(tmp_path):
    ca_key, ca_crt = ec_key(tmp_path / "ca.key"), tmp_path / "ca.crt"
    openssl("req", "-x509", "-new", "-key", str(ca_key), "-days", "400", "-subj", "/CN=Maildivvy Test CA",
            "-out", str(ca_crt))
    return ca_crt, ca_key


def leaf(tmp_path, tag, name=NAME, expired=False, key=None):
    """A certificate for `name` issued by the test CA, with its own key unless given one."""
    ca_crt, ca_key = (tmp_path / "ca.crt", tmp_path / "ca.key")
    if not ca_crt.exists():
        make_ca(tmp_path)
    key = key or ec_key(tmp_path / f"{tag}.key")
    csr, ext, crt = tmp_path / f"{tag}.csr", tmp_path / f"{tag}.ext", tmp_path / f"{tag}.crt"
    openssl("req", "-new", "-key", str(key), "-subj", f"/CN={name}", "-out", str(csr))
    ext.write_text(f"subjectAltName=DNS:{name}\n")
    period = ["-not_before", "20200101000000Z", "-not_after", "20200301000000Z"] if expired else ["-days", "90"]
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), *period,
            "-extfile", str(ext), "-out", str(crt))
    return {"cert": str(crt), "chain": str(ca_crt), "key": str(key)}


def bad_provided(tmp_path, case):
    good = leaf(tmp_path, "good")
    if case == "another key":
        return {**good, "key": str(ec_key(tmp_path / "other.key"))}
    if case == "another name":
        return leaf(tmp_path, "named", name="other.example.test")
    if case == "expired":
        return leaf(tmp_path, "old", expired=True)
    if case == "not a certificate":
        (tmp_path / "junk.crt").write_text("not a certificate\n")
        return {**good, "cert": str(tmp_path / "junk.crt")}
    if case == "a chain that is no certificate":
        (tmp_path / "junk.chain").write_text("not a certificate\n")
        return {**good, "chain": str(tmp_path / "junk.chain")}
    if case == "missing":
        return {**good, "key": str(tmp_path / "absent.key")}
    if case == "an encrypted key":
        encrypted = tmp_path / "encrypted.key"
        openssl("pkey", "-in", good["key"], "-aes256", "-passout", "pass:x", "-out", str(encrypted))
        return {**good, "key": str(encrypted)}
    if case == "a chain from another CA":
        other = tmp_path / "other-ca"
        other.mkdir()
        return {**leaf(other, "stranger"), "chain": good["chain"]}
    raise AssertionError(case)


PROVIDED_REFUSALS = {
    "another key": "does not match its key",
    "another name": f"does not cover {NAME}",
    "expired": "has expired",
    "not a certificate": "is not a PEM certificate",
    "a chain that is no certificate": "is not a PEM certificate",
    "missing": "cannot be read",
    "an encrypted key": "(or the key is encrypted)",
    "a chain from another CA": "does not issue the certificate",
}


def test_a_provided_certificate_is_published_with_its_chain_and_its_consumers_reloaded(tmp_path):
    given = leaf(tmp_path, "good")
    values, _ = config(tmp_path, mode="provided", provided_cert=given["cert"], provided_chain=given["chain"],
                       provided_key=given["key"])
    systemctl, lines = Systemctl(enabled={"dovecot", "postfix", "nginx"}), []
    assert cert.install_provided(values, {}, systemctl, out=lines.append) == 0
    crt, key = Path(values["published_cert"]), Path(values["published_key"])
    assert crt.read_text() == Path(given["cert"]).read_text() + Path(given["chain"]).read_text()
    assert key.read_bytes() == Path(given["key"]).read_bytes()
    assert (stat.S_IMODE(crt.stat().st_mode), stat.S_IMODE(key.stat().st_mode)) == (0o644, 0o640)
    assert lines[0] == f"published {crt} and {key}"
    assert ["systemctl", "reload", "nginx"] in systemctl.calls
    again = []
    assert cert.install_provided(values, {}, Systemctl(enabled=()), out=again.append) == 0
    assert again == [f"unchanged: {crt} is the provided certificate"]


@pytest.mark.parametrize("case", PROVIDED_REFUSALS)
def test_a_provided_certificate_that_is_wrong_is_refused_before_anything_is_published(tmp_path, case):
    given = bad_provided(tmp_path, case)
    values, path = config(tmp_path, mode="provided")
    result = run(path, "install-provided", "--cert", given["cert"], "--chain", given["chain"], "--key", given["key"])
    assert result.returncode == 2
    assert PROVIDED_REFUSALS[case] in result.stderr
    assert not Path(values["published_cert"]).exists() and not Path(values["published_key"]).exists()


@pytest.mark.parametrize("case", PROVIDED_REFUSALS)
def test_install_step_1_refuses_the_same_provided_certificates(tmp_path, case):
    given = bad_provided(tmp_path, case)

    def runner(argv, data=None):
        done = subprocess.run(argv, input=data, capture_output=True)
        return done.returncode, done.stdout.decode()

    errors = maildivvy_preflight.provided_problems(given, NAME, runner)
    assert errors and PROVIDED_REFUSALS[case] in "\n".join(errors)
    assert maildivvy_preflight.provided_problems(leaf(tmp_path, "fine"), NAME, runner) == []  # the control


def test_step_1_and_install_provided_check_a_certificate_with_the_same_code():
    """The preflight module runs on the machine before the certificate program is there, so
    each holds the checks; they are the same text, not two versions that drift."""
    import inspect
    assert inspect.getsource(maildivvy_preflight.provided_problems) == inspect.getsource(cert.provided_problems)
    assert maildivvy_preflight.PEM == cert.PEM  # the pattern the function reads the blocks with


def test_the_paths_of_a_later_replacement_default_to_the_settings(tmp_path):
    first, second = leaf(tmp_path, "first"), leaf(tmp_path, "second")
    values, path = config(tmp_path, mode="provided", provided_cert=first["cert"], provided_chain=first["chain"],
                          provided_key=first["key"])
    assert cert.install_provided(values, {}, Systemctl(enabled=()), out=lambda *_: None) == 0
    Path(first["cert"]).write_bytes(Path(second["cert"]).read_bytes())
    Path(first["key"]).write_bytes(Path(second["key"]).read_bytes())
    lines = []
    assert cert.install_provided(values, {}, Systemctl(enabled=()), out=lines.append) == 0
    assert lines[0].startswith("published")
    assert Path(values["published_cert"]).read_text().startswith(Path(second["cert"]).read_text())


def test_in_provided_mode_the_renewal_runs_nothing_and_deploy_only_reloads(tmp_path):
    given = leaf(tmp_path, "good")
    values, path = config(tmp_path, mode="provided", provided_cert=given["cert"], provided_chain=given["chain"],
                          provided_key=given["key"])
    cert.install_provided(values, {}, Systemctl(enabled=()), out=lambda *_: None)
    before = Path(values["published_cert"]).read_bytes()
    result = run(path, "run")
    assert result.returncode == 0 and "provided mode: no ACME renewal" in result.stdout
    systemctl, lines = Systemctl(enabled={"dovecot"}), []
    assert cert.deploy(values, systemctl, out=lines.append) == 0
    assert ["systemctl", "reload", "dovecot"] in systemctl.calls
    assert Path(values["published_cert"]).read_bytes() == before


def test_install_provided_is_refused_in_another_mode(tmp_path):
    given = leaf(tmp_path, "good")
    values, path = config(tmp_path)
    result = run(path, "install-provided", "--cert", given["cert"], "--chain", given["chain"], "--key", given["key"])
    assert result.returncode == 2 and "install-provided is only for mode provided" in result.stderr
    assert not Path(values["published_cert"]).exists()


# --- the lego release check ------------------------------------------------

SUMS = """\
ebb33f1bead5a7c99dd46f1c5734b44cf1eab5b5c12faf397cd14d50a5916419  lego_v5.4.1_linux_amd64.tar.gz
4656f91ef734337bbcce8528ff1a58c25ac065c147813fb3182bbc573ebbdf03  lego_v5.4.1_linux_amd64.tar.gz.sbom.json
8494c06bde449ac4d65c726b7ea50d67ac61f422e698c9b78b47778445b098f2  lego_v5.4.1_linux_arm64.tar.gz
"""
AMD64 = "ebb33f1bead5a7c99dd46f1c5734b44cf1eab5b5c12faf397cd14d50a5916419"


def test_the_checksum_is_matched_on_the_whole_file_name_not_the_sbom_beside_it():
    assert anchored_checksum(SUMS, "lego_v5.4.1_linux_amd64.tar.gz") == AMD64


@pytest.mark.parametrize("name", ["lego_v5.4.1_linux_386.tar.gz", "linux_amd64.tar.gz", "lego_v5.4.1_linux_amd64"])
def test_a_file_the_checksums_do_not_list_exactly_is_refused(name):
    with pytest.raises(ChecksumError, match="exactly one"):
        anchored_checksum(SUMS, name)


def test_a_file_listed_twice_is_refused():
    with pytest.raises(ChecksumError, match="exactly one"):
        anchored_checksum(SUMS + SUMS, "lego_v5.4.1_linux_amd64.tar.gz")


def test_the_download_must_match_both_the_release_and_the_pin(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(b"archive")
    import hashlib
    digest = hashlib.sha256(b"archive").hexdigest()
    sums = f"{digest}  lego_v5.4.1_linux_amd64.tar.gz\n"
    assert verify(sums, archive, "lego_v5.4.1_linux_amd64.tar.gz", digest) == digest  # control
    with pytest.raises(ChecksumError, match="pinned"):
        verify(sums, archive, "lego_v5.4.1_linux_amd64.tar.gz", "0" * 64)
    archive.write_bytes(b"tampered")
    with pytest.raises(ChecksumError, match="downloaded"):
        verify(sums, archive, "lego_v5.4.1_linux_amd64.tar.gz", digest)


# --- the certificate settings in preflight ----------------------------------------------


def kinds(errors):
    return [e.split(":")[0] for e in errors]


def test_acme_is_the_default_mode_and_needs_a_dns_credential():
    assert setting_errors(GOOD) == []
    errors = setting_errors({k: v for k, v in GOOD.items() if k != "acme_dns_credentials"})
    assert kinds(errors) == ["missing acme_dns_credentials"]


def test_self_signed_is_refused_without_the_test_certificate_flag():
    self_signed = {**GOOD, "cert_mode": "self-signed"}
    del self_signed["acme_dns_credentials"]
    errors = setting_errors(self_signed)
    assert kinds(errors) == ["refused cert_mode"]
    assert "insecure_test_certificate" in errors[0]
    assert setting_errors({**self_signed, "insecure_test_certificate": True}) == []
    assert kinds(setting_errors({**self_signed, "insecure_test_certificate": False})) == ["refused cert_mode"]
    errors = setting_errors({**self_signed, "insecure_test_certificate": True,
                             "acme_dns_credentials": {"DESEC_TOKEN": TOKEN}})
    assert kinds(errors) == ["ambiguous cert_mode"]


def test_any_provider_takes_its_credentials_as_a_mapping():
    given = {**GOOD, "acme_dns_provider": "cloudflare", "acme_dns_credentials": {"CF_DNS_API_TOKEN": TOKEN}}
    assert setting_errors(given) == []
    for bad in ({"cf_dns_api_token": TOKEN}, {"CF_DNS_API_TOKEN": "two\nlines"}, {"CF_DNS_API_TOKEN": ""},
                ["CF_DNS_API_TOKEN"], {"CF_DNS_API_TOKEN_FILE": "/path"}):
        errors = setting_errors({**given, "acme_dns_credentials": bad})
        assert kinds(errors) == ["malformed acme_dns_credentials"], bad
        assert TOKEN not in "\n".join(errors)
    assert kinds(setting_errors({**given, "acme_dns_provider": "Cloud Flare"})) == ["malformed acme_dns_provider"]


def test_provided_mode_needs_its_three_paths_and_no_dns_credential():
    provided = {k: v for k, v in GOOD.items() if k != "acme_dns_credentials"}
    provided.update(cert_mode="provided", provided_cert="/root/cert.pem", provided_chain="/root/chain.pem",
                    provided_key="/root/key.pem")
    assert setting_errors(provided) == []
    assert kinds(setting_errors({**provided, "provided_key": None})) == ["missing provided_key"]
    assert kinds(setting_errors({**provided, "provided_cert": "cert.pem"})) == ["malformed provided_cert"]
    assert kinds(setting_errors({**provided, "acme_dns_credentials": {"DESEC_TOKEN": TOKEN}})) == \
        ["ambiguous cert_mode"]
    acme_with_paths = {**GOOD, "provided_cert": "/root/cert.pem"}
    assert kinds(setting_errors(acme_with_paths)) == ["ambiguous provided_cert"]


@pytest.mark.parametrize("name, value", [
    ("cert_mode", "selfsigned"), ("cert_mode", "production"), ("acme_email", "not an address"),
])
def test_a_malformed_certificate_setting_is_refused_without_echoing_it(name, value):
    errors = setting_errors({**GOOD, name: value})
    assert kinds(errors) == [f"malformed {name}"]
    assert value not in "\n".join(errors)


def test_the_staging_mode_and_a_contact_address_are_accepted():
    assert setting_errors({**GOOD, "cert_mode": "acme-staging", "acme_email": "ops@example.test"}) == []
    assert setting_errors({**GOOD, "acme_email": "-"}) == []


# --- what the role renders and runs ----------------------------------------------------

ROLE = ROOT / "ansible" / "roles" / "certificate"


def _jinja():
    import jinja2
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["to_nice_json"] = lambda v, sort_keys=True, **_: json.dumps(v, indent=4, sort_keys=sort_keys)
    return env


def render(name, **values):
    return _jinja().from_string((ROLE / "templates" / name).read_text()).render(**values)


def role_yaml(*parts):
    import yaml
    return yaml.safe_load(ROLE.joinpath(*parts).read_text())


def role_values(mode, **settings):
    values = {**role_yaml("defaults", "main.yml"), "maildivvy_cert_mode": mode, "maildivvy_cert_name": NAME,
              **settings}
    derived = role_yaml("vars", "main.yml")
    for key in ("maildivvy_published_cert", "maildivvy_published_key", "maildivvy_lego_path",
                "maildivvy_acme_server", "maildivvy_acme_dns_api_url"):
        values[key] = _jinja().from_string(derived[key]).render(**values)
    return values


@pytest.mark.parametrize("mode", ["acme", "acme-staging", "self-signed", "provided"])
def test_the_rendered_configuration_has_what_the_program_reads_and_no_secret(tmp_path, mode):
    rendered = json.loads(render("certificate.json.j2", **role_values(mode)))
    expected, _ = config(tmp_path, mode=mode)
    assert set(rendered) == set(expected)
    assert rendered["mode"] == mode
    assert rendered["published_cert"] == f"/etc/ssl/certs/{NAME}.crt"
    assert rendered["published_key"] == f"/etc/ssl/private/{NAME}.key"
    assert (rendered["cert_owner"], rendered["cert_group"], rendered["key_group"]) == ("root", "root", "ssl-cert")
    assert rendered["deploy_hook"] == "/usr/local/sbin/maildivvy-cert deploy"
    assert rendered["credentials_dir"] == "/etc/lego/credentials"
    assert rendered["credentials_env"] == "/etc/maildivvy/certificate.env"
    assert (rendered["provided_cert"], rendered["provided_chain"], rendered["provided_key"]) == (None, None, None)


def test_the_provided_paths_are_recorded_for_a_later_replacement():
    values = role_values("provided", maildivvy_provided_cert="/root/c.pem", maildivvy_provided_chain="/root/ch.pem",
                         maildivvy_provided_key="/root/k.pem")
    rendered = json.loads(render("certificate.json.j2", **values))
    assert (rendered["provided_cert"], rendered["provided_chain"], rendered["provided_key"]) == (
        "/root/c.pem", "/root/ch.pem", "/root/k.pem")


def test_the_dns_api_is_checked_only_where_its_address_is_known():
    assert role_values("acme")["maildivvy_acme_dns_api_url"] == "https://desec.io/api/v1/"
    assert role_values("acme", maildivvy_acme_dns_provider="cloudflare")["maildivvy_acme_dns_api_url"] == ""
    tasks = [t for t in _tasks(role_yaml("tasks", "main.yml")) if "block" not in t]
    check = next(t for t in tasks if t.get("name") == "The DNS provider's API answers over HTTPS")
    assert check["when"] == "maildivvy_acme_dns_api_url != ''"


def test_staging_and_production_never_share_lego_storage():
    live, staging = role_values("acme"), role_values("acme-staging")
    assert (live["maildivvy_acme_server"], staging["maildivvy_acme_server"]) == ("letsencrypt", "letsencrypt-staging")
    assert live["maildivvy_lego_path"] == "/etc/lego"
    assert staging["maildivvy_lego_path"] == "/etc/lego/staging"


def test_the_renewal_is_a_daily_timer_running_lego_run_through_the_program():
    service = render("renew.service.j2", maildivvy_cert_program="/usr/local/sbin/maildivvy-cert")
    timer = render("renew.timer.j2")
    assert "ExecStart=/usr/local/sbin/maildivvy-cert run\n" in service
    assert "Type=oneshot" in service and "Environment" not in service  # no credential in the unit
    assert "OnCalendar=daily" in timer and "Persistent=true" in timer


def _tasks(tasks):
    for task in tasks:
        yield task
        for key in ("block", "always", "rescue"):
            yield from _tasks(task.get(key, []))


def test_the_role_hands_the_credentials_over_on_stdin_only_and_never_logs_them():
    tasks = list(_tasks(role_yaml("tasks", "main.yml")))
    using = [t for t in tasks if "block" not in t and "maildivvy_acme_dns_credentials" in json.dumps(t)]
    assert len(using) == 1  # the control: the one task that passes them is found
    task = using[0]
    assert task["no_log"] is True
    command = task["ansible.builtin.command"]
    assert "maildivvy_acme_dns_credentials" in command["stdin"]
    assert "maildivvy_acme_dns" not in json.dumps(command["argv"])
    assert "environment" not in task


def test_no_dns_credential_is_kept_on_a_machine_that_does_not_issue():
    tasks = [t for t in _tasks(role_yaml("tasks", "main.yml")) if "block" not in t]
    removal = next(t for t in tasks if t.get("name", "").startswith("Remove every DNS credential"))
    assert removal["when"] == "maildivvy_cert_mode not in ['acme', 'acme-staging']"
    paths = removal["ansible.builtin.file"]["path"]
    assert removal["ansible.builtin.file"]["state"] == "absent"
    assert "{{ item }}" == paths
    assert set(removal["loop"]) >= {"{{ maildivvy_credentials_dir }}", "{{ maildivvy_credentials_env }}"}


def test_the_hook_and_ssl_cert_are_in_place_before_the_first_issuance():
    names = [t.get("name", "") for t in _tasks(role_yaml("tasks", "main.yml"))]

    def first(prefix):
        return next(i for i, n in enumerate(names) if n.startswith(prefix))

    issue = first("Issue the certificate")
    assert first("The ssl-cert group exists") < issue
    assert first("Write the certificate configuration") < issue
    assert first("Install maildivvy-cert, the deploy hook") < issue


def test_the_first_issuance_reads_back_the_deploy_hooks_own_lines_not_only_legos_exit_code(tmp_path):
    # lego prints its deploy hook's output on its own; the step reads it, so an issuance
    # whose hook published nothing is seen, and the play says what each consumer got
    tasks = [t for t in _tasks(role_yaml("tasks", "main.yml")) if "block" not in t]
    names = [t.get("name", "") for t in tasks]
    issue = next(i for i, n in enumerate(names) if n.startswith("Issue the certificate"))
    assert tasks[issue]["register"] == "maildivvy_issuance"
    report = tasks[issue + 1]
    assert report["name"].startswith("The deploy hook published the pair")
    assert report["when"] == "maildivvy_issuance is not skipped"
    that = " ".join(report["ansible.builtin.assert"]["that"])
    assert "maildivvy_issuance.stdout_lines" in that and "maildivvy_published_cert" in that
    assert report["ansible.builtin.assert"]["quiet"] is False  # its lines are printed
    # the line the step looks for is the one the hook prints
    values, _ = config(tmp_path)
    issued(values)
    lines = []
    cert.deploy(values, Systemctl(enabled={"dovecot"}), out=lines.append)
    assert lines[0] == f"published {values['published_cert']} and {values['published_key']}"


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


