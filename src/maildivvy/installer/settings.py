"""The installer's settings: a root-only file of non-secret settings, and the secrets apart.

`/etc/maildivvy/install.yml` holds the `maildivvy_*` settings the installation reads,
written by the installer from its questions or by the operator, `0600` and root's: it
names a command the backup runs as root. It never holds a secret. The break-glass
password and the DNS credentials are asked for on each run, or read from standard
input, and handed to the run in a root-only file that is gone when it ends.
"""

import os
import stat
from pathlib import Path

from maildivvy.installer import Refusal

PATH = Path("/etc/maildivvy/install.yml")
# the settings step 1 checks, and nothing else: a misspelled one is refused rather than
# ignored, and none can override a role's own variables (extra vars outrank them)
SETTINGS = (
    "maildivvy_hostname", "maildivvy_cert_name", "maildivvy_vmail_uid", "maildivvy_vmail_gid",
    "maildivvy_disk_mode", "maildivvy_store_disk", "maildivvy_index_disk", "maildivvy_swap_disk",
    "maildivvy_single_disk_allow_reflink", "maildivvy_admin_networks", "maildivvy_firewall_confirmation",
    "maildivvy_admin_ssh_source", "maildivvy_container_pool", "maildivvy_cert_mode",
    "maildivvy_acme_dns_provider", "maildivvy_acme_email", "maildivvy_provided_cert", "maildivvy_provided_chain",
    "maildivvy_provided_key", "maildivvy_backup_keep", "maildivvy_backup_store_copy",
    "maildivvy_health_textfile_dir",
)
# the role defaults the roles' README lists as an operator's to override, and no other:
# the rest are the roles' own paths and programs
TUNABLES = (
    "maildivvy_acme_dns_propagation_timeout", "maildivvy_acme_dns_polling_interval", "maildivvy_acme_dns_resolvers",
    "maildivvy_acme_dns_api_urls", "maildivvy_lego_version", "maildivvy_lego_sha256",
    "maildivvy_clamav_stream_max", "maildivvy_clamav_file_max", "maildivvy_clamav_concurrent_reload",
    "maildivvy_clamav_community_feed", "maildivvy_clamav_sanesecurity_prefix", "maildivvy_clamav_database_wait",
    "maildivvy_fetch_minutes",
    "maildivvy_rspamd_repository", "maildivvy_rspamd_tag", "maildivvy_rspamd_digest", "maildivvy_rspamd_gid",
    "maildivvy_rspamd_user", "maildivvy_rspamd_reject_score", "maildivvy_rspamd_add_header_score",
    "maildivvy_rspamd_greylist_score", "maildivvy_rspamd_provider_hosts", "maildivvy_rspamd_rbls",
    "maildivvy_rspamd_rbl_listed_probe", "maildivvy_rspamd_rbl_clean_probe",
    "maildivvy_postfix_inet_protocols", "maildivvy_postfix_tls_protocols",
)
SECRETS = ("maildivvy_breakglass_password", "maildivvy_acme_dns_credentials")
# the run's own values (run.run_values), never kept: the test certificate is chosen on the
# command line alone, on each run
TEST_CERTIFICATE = "maildivvy_insecure_test_certificate"
TEST_CERTIFICATE_OPTION = "--insecure-test-certificate"
INSTALLER_RUN = "maildivvy_installer_run"
COLLECTION_PAUSED = "maildivvy_collection_paused"
RUN_ENVIRONMENT = "maildivvy_run_environment"
# the certificate role's defaults (certificate/defaults/main.yml), and the modes that issue
# through ACME, as step 1 (ACME_MODES) and the certificate program read them
DEFAULT_CERT_MODE = "acme"
ACME_MODES = ("acme", "acme-staging")
DEFAULT_DNS_PROVIDER = "desec"
# the DNS providers tested, each with the credential lego reads for it
TESTED_DNS_CREDENTIALS = {"desec": "DESEC_TOKEN"}


def _mapping(text, where):
    import yaml   # python3-yaml comes with ansible-core, installed after the checks

    try:
        values = yaml.safe_load(text)
    except yaml.YAMLError as err:
        mark = getattr(err, "problem_mark", None)
        at = f" at line {mark.line + 1}" if mark else ""
        raise Refusal(f"{where} is not YAML{at}") from None
    if values is None:
        values = {}
    if not isinstance(values, dict):
        raise Refusal(f"{where} is not a mapping of settings")
    return values


def parse(text, where):
    """The settings in `text`, or Refusal naming every key that may not be there (never a value)."""
    values = _mapping(text, where)
    problems = []
    for key in values:
        if key in SECRETS:
            problems.append(f"secret {key} in {where}: secrets are never kept in the settings file; "
                            "the installer asks for them on each run, or reads them with --secrets-on-stdin")
        elif key == TEST_CERTIFICATE:
            problems.append(f"{key} in {where}: a test certificate is chosen on the command line alone, "
                            f"with {TEST_CERTIFICATE_OPTION}")
        elif key not in SETTINGS and key not in TUNABLES:
            problems.append(f"not a Maildivvy setting: {key} in {where} (the installation guide lists the "
                            "settings, the roles' README the defaults an operator may override)")
    if problems:
        raise Refusal("\n".join(problems))
    return values


def load(path=None, owner=0):
    """The settings file, refused unless it is `owner`'s (root's) and 0600."""
    path = Path(path or PATH)
    info = path.stat()
    if info.st_uid != owner:
        raise Refusal(f"{path} must be root's: it names a command the backup runs as root")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise Refusal(f"{path} must be 0600: it names a command the backup runs as root "
                      f"(it is {stat.S_IMODE(info.st_mode):04o}; chmod 600 {path})")
    return parse(path.read_text(), str(path))


def save(path, values):
    """Write the settings file 0600; a secret among the values is a programming error."""
    unknown = [k for k in values if k not in SETTINGS and k not in TUNABLES]
    if unknown:
        raise ValueError(f"not a setting to keep: {', '.join(unknown)}")
    import yaml   # python3-yaml comes with ansible-core, installed after the checks

    path = Path(path)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    partial = path.with_name(f".{path.name}.partial")
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# Maildivvy's installation settings, read by maildivvy-install on each run.\n"
                "# No secret belongs here: the installer asks for them.\n")
        yaml.safe_dump(values, f, default_flow_style=False, sort_keys=False)
    os.chmod(partial, 0o600)
    os.replace(partial, path)


def parse_secrets(text):
    """The secrets given on standard input: a mapping of the secret settings and nothing else."""
    values = _mapping(text, "the secrets on standard input")
    others = [str(k) for k in values if k not in SECRETS]
    if others:
        raise Refusal(f"not a secret: {', '.join(others)} on standard input; put it in the settings file")
    return values
