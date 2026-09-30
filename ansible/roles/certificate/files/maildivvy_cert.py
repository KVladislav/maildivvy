#!/usr/bin/python3
"""maildivvy-cert: the machine's certificate, issued by lego over DNS-01 or provided by the operator.

    maildivvy-cert store-credentials   the DNS provider's credentials on stdin, kept root-only for renewal
    maildivvy-cert run                 lego run: issue, or renew when due (the daily timer)
    maildivvy-cert deploy              lego's deploy hook: republish, reload every consumer
    maildivvy-cert install-provided    publish the operator's certificate, chain and key, once checked
    maildivvy-cert self-sign           test machines only: a self-signed certificate at the same paths

Everything it needs is in one JSON file (/etc/maildivvy/certificate.json), written by
the install and holding no secret; the mode there is `acme`, `acme-staging`, `provided`
or `self-signed`. A credential is never in argv or an environment: each is kept in its
own root-only file, and lego is given the file's path in `<NAME>_FILE`, which lego reads
itself. Those variables are listed in /etc/maildivvy/certificate.env.
"""


import argparse
import grp
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

DEFAULT_CONFIG = "/etc/maildivvy/certificate.json"

# Every consumer of the certificate, and how it re-reads it. One list, here.
# Dovecot and Postfix re-read on reload; the interface's proxy terminates TLS
# itself and re-reads on reload. A consumer that is not installed yet is skipped.
CONSUMERS = (("dovecot", "reload"), ("postfix", "reload"), ("nginx", "reload"))

# The DNS providers Maildivvy's own tests issue through. Any other lego provider works
# the same way, and is reported as untested.
TESTED_PROVIDERS = ("desec",)
ACME_MODES = ("acme", "acme-staging")

SELF_SIGNED_DAYS = 365
# a self-signed certificate is made anew on a run within this many days of its end: the
# renewal timer renews only ACME certificates
SELF_SIGNED_RENEW_DAYS = 30
NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
PEM = re.compile(r"-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----\r?\n?", re.DOTALL)


class Refusal(Exception):
    """A refusal with its exit code: 2 for usage and missing inputs, 1 for a failed step."""

    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


def _only(config, modes, what):
    if config["mode"] not in modes:
        raise Refusal(f"{config['mode']} mode: no {what}; this machine has no ACME certificate")


# --- the provider's credentials ----------------------------------------------


@dataclass
class ProviderHelp:
    """What `lego dnshelp -c <provider>` says: its credential names, the ones lego cannot
    read from a file, and its propagation and polling variables."""

    credentials: list = field(default_factory=list)
    no_file: list = field(default_factory=list)
    propagation: str = None
    polling: str = None


ENTRY = re.compile(r'^\s+-\s+"([A-Z][A-Z0-9_]*)":\s*(.*)$')


def parse_dnshelp(text):
    found, section = ProviderHelp(), None
    for line in text.splitlines():
        if line.startswith("Credentials:"):
            section = "credentials"
            continue
        if line.startswith("Additional Configuration:"):
            section = "additional"
            continue
        entry = ENTRY.match(line)
        if not entry:
            if line.strip() and not line.startswith(" "):
                section = None
            continue
        name, description = entry.groups()
        if section == "credentials":
            found.credentials.append(name)
            if f"'{name}_FILE' is not supported" in description:
                found.no_file.append(name)
        elif section == "additional":
            if name.endswith("_PROPAGATION_TIMEOUT") and found.propagation is None:
                found.propagation = name
            if name.endswith("_POLLING_INTERVAL") and found.polling is None:
                found.polling = name
    return found


def provider_help(config):
    provider = config["dns_provider"]
    done = subprocess.run([config["lego"], "dnshelp", "-c", provider], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise Refusal(f"lego does not know the DNS provider {provider}: `lego dnshelp -c {provider}` "
                      f"failed; the providers lego knows are listed by `lego dnshelp`")
    return parse_dnshelp(done.stdout)


def _one_line(value):
    return isinstance(value, str) and value != "" and not re.search(r"[\x00-\x1f\x7f]", value)


def read_given(stream):
    """{"credentials": {NAME: value}}, as JSON on stdin; never echoed."""
    try:
        given = json.loads(stream.read())
    except ValueError:
        raise Refusal("no credentials on stdin: expected one JSON object") from None
    if not isinstance(given, dict) or set(given) != {"credentials"}:
        raise Refusal("no credentials on stdin: expected {\"credentials\": {...}}")
    if not isinstance(given["credentials"], dict):
        raise Refusal("malformed credentials on stdin: expected a mapping of names to values")
    return given


def resolve(config, given, help_):
    """The credentials by name, checked against what lego says the provider takes."""
    provider = config["dns_provider"]
    if not help_.credentials:
        raise Refusal(f"{provider} takes no credential lego reads from a file, so the install cannot "
                      "run it unattended; choose a provider with an API")
    credentials = given["credentials"]
    if not credentials:
        raise Refusal(f"no credential given: {provider} takes {', '.join(help_.credentials)}")
    problems = []
    for name, value in credentials.items():
        if not isinstance(name, str) or name not in help_.credentials:
            problems.append(f"not a credential {provider} takes: {name} (it takes {', '.join(help_.credentials)})")
        elif name in help_.no_file:
            problems.append(f"lego cannot read {name} from a file, and a credential never reaches lego any other "
                            f"way; {provider} cannot be used by this install")
        elif not _one_line(value):
            problems.append(f"malformed {name}: expected one line, not empty")
    if problems:
        raise Refusal("\n".join(problems))
    return credentials


def env_lines(config, credentials, help_):
    lines = ["# written by maildivvy-cert store-credentials: lego reads each credential from its file"]
    lines += [f"{name}_FILE={os.path.join(config['credentials_dir'], name)}" for name in sorted(credentials)]
    if help_.propagation:
        lines.append(f"{help_.propagation}={config['propagation_timeout']}")
    if help_.polling:
        lines.append(f"{help_.polling}={config['polling_interval']}")
    return "\n".join(lines) + "\n"


def provider_status(provider):
    if provider in TESTED_PROVIDERS:
        return f"{provider}: tested with Maildivvy"
    return (f"{provider}: UNTESTED with Maildivvy: lego supports it, and Maildivvy's own tests never "
            "issued through it; read the first issuance and the first renewal yourself")


def store_credentials(config, stream, out=print):
    """Write each credential 0600 into its own file and list them for lego; True when anything changed."""
    _only(config, ACME_MODES, "DNS credentials")
    given = read_given(stream)
    help_ = provider_help(config)
    credentials = resolve(config, given, help_)
    directory = config["credentials_dir"]
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    changed = False
    for name in sorted(credentials):
        path = os.path.join(directory, name)
        data = (credentials[name] + "\n").encode()
        try:
            with open(path, "rb") as f:
                same = f.read() == data and os.stat(path).st_mode & 0o777 == 0o600
        except FileNotFoundError:
            same = False
        if same:
            out(f"unchanged {name}")
        else:
            _write_atomic(path, data, 0o600, os.getuid(), os.getgid())
            out(f"stored {name}")
            changed = True
    for name in sorted(os.listdir(directory)):
        if name not in credentials:
            os.unlink(os.path.join(directory, name))
            out(f"removed {name}")
            changed = True
    text = env_lines(config, credentials, help_).encode()
    try:
        with open(config["credentials_env"], "rb") as f:
            same = f.read() == text
    except FileNotFoundError:
        same = False
    if not same:
        _write_atomic(config["credentials_env"], text, 0o600, os.getuid(), os.getgid())
        changed = True
    out(provider_status(config["dns_provider"]))
    return changed


def read_env(config):
    """The variables lego is given, from certificate.env: file paths and timings, never a value."""
    path = config["credentials_env"]
    try:
        with open(path) as f:
            text = f.read()
    except FileNotFoundError:
        text = ""
    found = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        if not NAME.match(name):
            raise Refusal(f"{path}: not a variable line: {name}", code=1)
        found[name] = value
    if not any(name.endswith("_FILE") for name in found):
        raise Refusal(f"no DNS credentials listed in {path}: store them first with "
                      "`maildivvy-cert store-credentials` (the credentials on stdin)")
    return found


# --- lego ---------------------------------------------------------------------------


def lego_argv(config):
    argv = [config["lego"], "--log.format", "text", "run", "--accept-tos", "--server", config["server"]]
    if config.get("email") and config["email"] != "-":
        argv += ["--email", config["email"]]
    # lego asks the resolvers for the zone and its nameservers, and the record's
    # propagation at the authoritative nameservers alone: a public resolver asked before
    # the provider publishes it caches the absence for the zone's negative TTL
    argv += ["--dns", config["dns_provider"], "--dns.resolvers", ",".join(config["resolvers"]),
             "--dns.propagation.disable-rns",
             "--domains", config["cert_name"], "--path", config["lego_path"],
             "--deploy-hook", config["deploy_hook"]]
    return argv


def lego_env(config, base):
    """The environment lego runs with: the credential files' paths, never a credential."""
    listed = read_env(config)
    credentials = {name[:-len("_FILE")] for name in listed if name.endswith("_FILE")}
    env = {k: v for k, v in base.items() if k not in credentials and k not in listed}
    env.update(listed)
    return env


def run(config, out=print):
    if config["mode"] in ("self-signed", "provided"):
        out(f"{config['mode']} mode: no ACME renewal; {config['published_cert']} is left as it is")
        return 0
    env = lego_env(config, dict(os.environ))
    sys.stdout.flush()
    os.execve(config["lego"], lego_argv(config), env)
    return 1  # not reached


# --- publishing ------------------------------------------------------------------------


def _id(value, lookup):
    return value if isinstance(value, int) else lookup(value)


def _write_atomic(path, data, mode, uid, gid):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".maildivvy-cert-")
    try:
        os.fchmod(fd, mode)
        if os.getuid() == 0:
            os.fchown(fd, uid, gid)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def source_files(config):
    base = os.path.join(config["lego_path"], "certificates")
    name = config["cert_name"].replace("*", "_").replace(":", "-")  # lego's own file naming
    return os.path.join(base, name + ".crt"), os.path.join(base, name + ".key")


def publish(config, crt_bytes, key_bytes):
    """Certificate 0644 root:root, key 0640 root:ssl-cert; the key first."""
    owner = _id(config["cert_owner"], lambda n: pwd.getpwnam(n).pw_uid)
    cert_group = _id(config["cert_group"], lambda n: grp.getgrnam(n).gr_gid)
    key_group = _id(config["key_group"], lambda n: grp.getgrnam(n).gr_gid)
    _write_atomic(config["published_key"], key_bytes, 0o640, owner, key_group)
    _write_atomic(config["published_cert"], crt_bytes, 0o644, owner, cert_group)


def systemctl(argv):
    return subprocess.run(argv, stdin=subprocess.DEVNULL).returncode


def reload_consumers(runner, out):
    failed = []
    for unit, action in CONSUMERS:
        if runner(["systemctl", "is-enabled", "--quiet", unit]) != 0:
            out(f"skipped {unit}: not installed")
            continue
        if runner(["systemctl", action, unit]) != 0:
            failed.append(unit)
            out(f"{action} {unit} failed")
        else:
            out(f"{action} {unit}")
    return 1 if failed else 0


def deploy(config, runner=systemctl, out=print):
    if config["mode"] == "provided":
        # the published pair is the operator's: there is nothing to republish, only to re-read
        out(f"provided mode: {config['published_cert']} is the operator's; reloading its consumers")
        return reload_consumers(runner, out)
    _only(config, ACME_MODES, "deploy")
    crt, key = source_files(config)
    for path in (crt, key):
        if not os.path.isfile(path):
            raise Refusal(f"deploy: no such file {path}: the certificate for {config['cert_name']} "
                          "is not issued yet, or the certificate name is wrong", code=1)
    with open(crt, "rb") as c, open(key, "rb") as k:
        publish(config, c.read(), k.read())
    out(f"published {config['published_cert']} and {config['published_key']}")
    return reload_consumers(runner, out)


# --- a provided certificate ----------------------------------------------------


def _openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def _check(argv, data=None):
    done = subprocess.run(argv, input=data, capture_output=True, stdin=None if data is not None else subprocess.DEVNULL)
    return done.returncode, done.stdout.decode(errors="replace")


def provided_problems(paths, name, run):
    """What is wrong with the operator's certificate, chain and key: [] when nothing is.

    Install step 1 (the preflight module) and `maildivvy-cert install-provided` hold this
    same function, word for word (a unit test compares them), so a certificate step 1
    passes is one the command publishes. `run(argv, data=None)` returns (exit code,
    stdout). The key is never printed; an encrypted key is refused rather than prompted for.
    """
    problems, text = [], {}
    for what in ("cert", "chain", "key"):
        try:
            with open(paths[what], "rb") as handle:
                text[what] = handle.read()
        except OSError as err:
            problems.append(f"the provided {what} {paths[what]} cannot be read: {err.strerror}")
    if problems:
        return problems
    blocks = {what: PEM.findall(text[what].decode(errors="replace")) for what in ("cert", "chain")}
    for what in ("cert", "chain"):
        if not blocks[what] or run(["openssl", "x509", "-noout"], (blocks[what][0] + "\n").encode())[0] != 0:
            problems.append(f"the provided {what} {paths[what]} is not a PEM certificate")
    if problems:
        return problems
    leaf = (blocks["cert"][0] + "\n").encode()
    rc, key_pub = run(["openssl", "pkey", "-pubout", "-passin", "pass:", "-in", paths["key"]])
    _, cert_pub = run(["openssl", "x509", "-noout", "-pubkey"], leaf)
    if rc != 0 or key_pub.strip() != cert_pub.strip():
        problems.append(f"the provided certificate {paths['cert']} does not match its key {paths['key']} "
                        "(or the key is encrypted)")
    if run(["openssl", "x509", "-noout", "-checkhost", name], leaf)[0] != 0:
        problems.append(f"the provided certificate {paths['cert']} does not cover {name}")
    if run(["openssl", "x509", "-noout", "-checkend", "0"], leaf)[0] != 0:
        problems.append(f"the provided certificate {paths['cert']} has expired")
    # a chain from another CA would be served, and every client would refuse it
    if run(["openssl", "verify", "-no-CAfile", "-no-CApath", "-partial_chain", "-no_check_time",
            "-trusted", paths["chain"]], leaf)[0] != 0:
        problems.append(f"the provided chain {paths['chain']} does not issue the certificate {paths['cert']}")
    return problems


def provided_bytes(paths):
    """What is published: the leaf, then every certificate of the chain; and the key as given."""
    with open(paths["cert"]) as c, open(paths["chain"]) as ch, open(paths["key"], "rb") as k:
        leaf = PEM.findall(c.read())[0]
        chain = PEM.findall(ch.read())
        key = k.read()
    return "".join(block if block.endswith("\n") else block + "\n" for block in [leaf, *chain]).encode(), key


def install_provided(config, given, runner=systemctl, out=print):
    if config["mode"] != "provided":
        raise Refusal(f"install-provided is only for mode provided, and this machine's mode is {config['mode']}")
    paths = {what: given.get(what) or config.get(f"provided_{what}") for what in ("cert", "chain", "key")}
    missing = [what for what, path in paths.items() if not path]
    if missing:
        raise Refusal(f"install-provided: no {', '.join(missing)} given, and none in the settings: "
                      "pass --cert, --chain and --key")
    problems = provided_problems(paths, config["cert_name"], _check)
    if problems:
        raise Refusal("the provided certificate is refused, and nothing was published:\n" + "\n".join(problems))
    crt, key = provided_bytes(paths)
    try:
        with open(config["published_cert"], "rb") as c, open(config["published_key"], "rb") as k:
            if c.read() == crt and k.read() == key:
                out(f"unchanged: {config['published_cert']} is the provided certificate")
                return 0
    except FileNotFoundError:
        pass
    publish(config, crt, key)
    out(f"published {config['published_cert']} and {config['published_key']}")
    return reload_consumers(runner, out)


# --- self-signed (test machines) ------------------------------------------------------


def _published_is_good(config):
    crt, key = config["published_cert"], config["published_key"]
    if not (os.path.isfile(crt) and os.path.isfile(key)):
        return False
    try:
        names = _openssl("x509", "-noout", "-ext", "subjectAltName", "-in", crt).decode()
        # Only a certificate this program made, issued by its own
        # subject, is kept; an ACME or staging one left by a switch of mode renews no more
        issuer = _openssl("x509", "-noout", "-issuer", "-nameopt", "RFC2253", "-in", crt).decode()
        subject = _openssl("x509", "-noout", "-subject", "-nameopt", "RFC2253", "-in", crt).decode()
        # fails (raises) when it ends within the margin, or has ended
        _openssl("x509", "-noout", "-checkend", str(SELF_SIGNED_RENEW_DAYS * 86400), "-in", crt)
        return (f"DNS:{config['cert_name']}" in names.replace(",", " ").split()
                and issuer.split("=", 1)[1] == subject.split("=", 1)[1]
                and _openssl("x509", "-noout", "-pubkey", "-in", crt) == _openssl("pkey", "-pubout", "-in", key))
    except subprocess.CalledProcessError:
        return False


def self_sign(config, runner=systemctl, out=print):
    if config["mode"] != "self-signed":
        raise Refusal(f"self-sign is only for mode self-signed, and this machine's mode is {config['mode']}")
    name = config["cert_name"]
    if _published_is_good(config):
        out(f"unchanged: {config['published_cert']} names {name} and matches its key")
        return 0
    with tempfile.TemporaryDirectory() as tmp:  # 0700
        crt, key = os.path.join(tmp, "crt"), os.path.join(tmp, "key")
        _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-days", str(SELF_SIGNED_DAYS), "-subj", f"/CN={name}",
                 "-addext", f"subjectAltName=DNS:{name}", "-keyout", key, "-out", crt)
        with open(crt, "rb") as c, open(key, "rb") as k:
            publish(config, c.read(), k.read())
    out(f"created a self-signed certificate for {name}: {config['published_cert']}")
    # a consumer already running still serves the certificate it read before
    return reload_consumers(runner, out)


# --- entry point ----------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(prog="maildivvy-cert")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("store-credentials", "run", "deploy", "self-sign"):
        sub.add_parser(command)
    provided = sub.add_parser("install-provided", help="check and publish the operator's certificate; "
                                                       "the paths default to the install settings'")
    for what in ("cert", "chain", "key"):
        provided.add_argument(f"--{what}")
    args = parser.parse_args(argv)
    try:
        with open(args.config) as f:
            config = json.load(f)
        if args.command == "store-credentials":
            store_credentials(config, sys.stdin)
            return 0
        if args.command == "run":
            return run(config)
        if args.command == "deploy":
            return deploy(config)
        if args.command == "install-provided":
            return install_provided(config, {"cert": args.cert, "chain": args.chain, "key": args.key})
        return self_sign(config)
    except Refusal as refusal:
        print(f"maildivvy-cert: {refusal}", file=sys.stderr)
        return refusal.code


if __name__ == "__main__":
    sys.exit(main())
