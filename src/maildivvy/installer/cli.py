"""Install Maildivvy on this machine, from the unpacked release, as root.

    sudo ./maildivvy-install
    sudo ./maildivvy-install --secrets-on-stdin < <secrets file>

It checks the machine and the release before anything changes, and reads which version
is installed: it installs, re-proves the same version, upgrades (step 1's checks, a backup, then
the new migrations and every step) or refuses (upgrade.py). It then installs ansible-core
from Ubuntu, takes the settings from /etc/maildivvy/install.yml or asks for them (and
writes the file), asks for the secrets, runs the installation steps on this machine,
records the version and ends with what is left to do. The whole output is logged under
/var/log/maildivvy/.
"""

import argparse
import datetime
import json
import os
import socket
import subprocess
import sys
import time
import traceback
from pathlib import Path

from maildivvy.backup.archive import stamp_of
from maildivvy.installer import FAILED, REFUSED, Refusal, checks, manifest, prompts, run, settings, shown, upgrade

APT_TRIES = 3        # a fresh machine's own apt run (cloud-init, the daily timers) may hold its locks
APT_WAIT = 30


def parse(argv):
    parser = argparse.ArgumentParser(
        prog="maildivvy-install", description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--secrets-on-stdin", action="store_true",
                        help="ask nothing: read the settings file, and the secrets (the break-glass password, "
                             "the DNS credentials) as a YAML mapping on standard input")
    parser.add_argument(settings.TEST_CERTIFICATE_OPTION, action="store_true",
                        help="allow cert_mode self-signed, for a test machine only: no mail client trusts it")
    return parser.parse_args(argv)


def say(text):
    print(text, flush=True)


def read_os_release():
    try:
        return Path(checks.OS_RELEASE).read_text()
    except OSError:
        return ""


def prepare_log():
    """This run's log file, 0600 in a root-only /var/log/maildivvy: (path, open file)."""
    run.LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = run.LOG_DIR / f"install-{stamp_of(datetime.datetime.now(datetime.UTC))}.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    return path, os.fdopen(fd, "a", buffering=1)


def _apt(argv, log, env, sleep=time.sleep):
    """One apt-get command, tried again while a lock may be the reason it failed."""
    for attempt in range(1, APT_TRIES + 1):
        log.write(f"$ {' '.join(argv)}\n")
        log.flush()
        if not subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env).returncode:
            return
        if attempt < APT_TRIES:
            sleep(APT_WAIT)
    raise upgrade.Failed(f"{' '.join(argv)} failed {APT_TRIES} times; its output is in the log")


def install_ansible(log, write):
    """ansible-core from the Ubuntu archive, unless it is installed; says which version runs."""
    state = subprocess.run(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}", checks.ANSIBLE_PACKAGE],
                           capture_output=True, text=True)
    if not state.stdout.startswith("ii"):
        write("installing ansible-core from the Ubuntu archive")
        env = {**run.kept_environment(os.environ), "DEBIAN_FRONTEND": "noninteractive"}
        lock = ["-o", "DPkg::Lock::Timeout=600"]
        _apt(["apt-get", "-q", *lock, "update"], log, env)
        _apt(["apt-get", "-q", "-y", *lock, "install", checks.ANSIBLE_PACKAGE], log, env)
    answer = subprocess.run([checks.ANSIBLE_PLAYBOOK, "--version"], capture_output=True, text=True)
    version = checks.ansible_version(answer.stdout)
    log.write(answer.stdout)
    write(f"ansible-core {shown(version) if version else '(version unreadable)'}")
    note = checks.ansible_note(version)
    if note:
        write(note)


def _interactive(stdin):
    return stdin is not None and stdin.isatty()


def _lsblk(tell):
    """lsblk's JSON, or none said to be missing: the disk question is then asked without a list."""
    answer = subprocess.run(["lsblk", "--json", "--bytes", "--tree", "-o", "PATH,SIZE,TYPE,MODEL,MOUNTPOINTS"],
                            capture_output=True, text=True)
    if answer.returncode == 0:
        return json.loads(answer.stdout)
    said = (answer.stderr.strip().splitlines() or [f"exit {answer.returncode}"])[-1]
    tell(f"lsblk failed ({said}): the disks cannot be listed; name them by their device paths")
    return {"blockdevices": []}


def load_or_ask(args, stdin, console, write):
    """(settings, secrets): the settings file when present, else the answers, written to it."""
    path = settings.PATH
    if path.exists():
        values = settings.load(path)
        write(f"settings: {path}")
    elif args.secrets_on_stdin:
        raise Refusal(f"no settings file: {path} is not there, and --secrets-on-stdin asks "
                      "nothing; write it first (installation guide), or run without the option")
    elif not _interactive(stdin):
        raise Refusal(f"no settings file: {path} is not there, and there is no terminal to ask on")
    else:
        hostname = socket.gethostname().split(".", 1)[0].lower()
        values = prompts.ask_settings(console, hostname, _lsblk(console.say), args.insecure_test_certificate)
        console.say("")
        for line in prompts.summary(values):
            console.say(f"  {line}")
        if console.ask(f"Write these settings to {path} and install? (yes or no)", "no") != "yes":
            raise Refusal("not confirmed: no settings were written")
        settings.save(path, values)
        write(f"settings written to {path}; edit it and run again to change any")
    if args.secrets_on_stdin:
        secrets = settings.parse_secrets(stdin.read())
    elif _interactive(stdin):
        secrets = prompts.ask_secrets(console, values)
    else:
        raise Refusal("no terminal to ask for the secrets on: give them with --secrets-on-stdin")
    return values, secrets


def run_install(root, args, values, secrets, log, log_path, write, plan):
    """The steps on this machine, as the plan says; 0 when every step passed, else FAILED."""
    if values.get("maildivvy_firewall_confirmation") == "ssh-login":
        write(f"Steps 3 and 4 wait, when they change the firewall, for a NEW SSH login from "
              f"{values.get('maildivvy_admin_ssh_source')}: keep a second terminal ready to log in from there.")
    elif values.get("maildivvy_firewall_confirmation") == "console":
        write("console-only: the firewall steps will not wait for an SSH login, as the settings chose.")

    given = run.run_values(values, secrets, args.insecure_test_certificate, paused=plan.action == "upgrade",
                           base=os.environ)

    def steps(preflight_only=False):
        screen = run.Screen(run.site_steps((Path(root) / "ansible" / "site.yml").read_text()), write)
        with run.values_file(given) as path:
            return run.run_playbook(run.playbook_argv(root, path, preflight_only), run.environment(root, os.environ),
                                    log, screen, started=lambda: path.unlink(missing_ok=True))

    if finish(plan, root, steps, write, log, store_copy=bool(values.get("maildivvy_backup_store_copy"))) != 0:
        write(f"The full log: {log_path}")
        return FAILED
    write(f"Maildivvy {shown(plan.release)} is installed. What is left to you:")
    for number, step in enumerate(run.remaining(values, log_path), 1):
        write(f"  {number}. {step}")
    return 0


def finish(plan, root, steps, write, log, store_copy=True):
    """Run `steps` as the plan says and record the version they installed; 0, or FAILED."""
    if plan.action == "upgrade":
        return upgrade.upgrade(plan, root, steps, write, log, store_copy=store_copy)
    if plan.action == "install":
        upgrade.mark_unfinished(plan.release)
    code = steps()
    if code != 0:
        write(f"The installation stopped (exit {code}): nothing after the failed step ran. Fix what it "
              "says and run ./maildivvy-install again.")
        return FAILED
    upgrade.finished(plan.release)
    return 0


def main(argv, root, write=say):
    args = parse(argv)
    root = Path(root)
    problems = checks.machine_problems(read_os_release(), os.geteuid()) + manifest.problems(root)
    if not problems:
        try:   # read-only: the version files and the database's schema_version
            release = upgrade.release_version(root)
            plan = upgrade.decide(upgrade.installed(), release)
        except Refusal as refusal:
            problems = str(refusal).splitlines()
    if problems:
        for problem in problems:
            write(f"refused: {problem}")
        write("nothing was changed")
        return REFUSED
    log_path, log = prepare_log()
    with log:
        log.write(f"maildivvy-install from {root}, {datetime.datetime.now(datetime.UTC).isoformat()}\n")
        write(f"the full log: {log_path}")
        write(plan.says())
        try:
            install_ansible(log, write)
        except upgrade.Failed as failure:
            write(f"failed: {failure}")
            write(f"The full log: {log_path}")
            return FAILED
        try:
            values, secrets = load_or_ask(args, sys.stdin, prompts.Console(), write)
        except Refusal as refusal:
            for line in str(refusal).splitlines():
                write(f"refused: {line}")
            write("the installation steps did not run")
            return REFUSED
        try:
            return run_install(root, args, values, secrets, log, log_path, write, plan)
        except Exception as failure:   # noqa: BLE001 - said on the screen, the traceback in the log
            log.write(traceback.format_exc())
            write(f"failed: {type(failure).__name__}: {failure}")
            write(f"The full log: {log_path}")
            return FAILED
