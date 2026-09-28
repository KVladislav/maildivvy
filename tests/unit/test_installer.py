"""`maildivvy-install`, the installer that runs on the machine itself.

Its parts as pure functions: the machine checks, the release's manifest, the settings
file and the secrets, the prompts, the command it runs, and what it shows. The run on a
machine is tested on the test machine.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from maildivvy.installer import checks, cli, manifest, prompts, run, settings, upgrade

REPO = Path(__file__).resolve().parents[2]
UBUNTU_2604 = 'NAME="Ubuntu"\nVERSION_ID="26.04"\nID=ubuntu\nID_LIKE=debian\n'
PASSWORD = "correct horse battery staple"
TOKEN = "scoped-dns-token-value"
GOOD = {
    "maildivvy_hostname": "mail",
    "maildivvy_cert_name": "mail.example.org",
    "maildivvy_vmail_uid": 900,
    "maildivvy_vmail_gid": 900,
    "maildivvy_disk_mode": "single",
    "maildivvy_admin_networks": ["192.0.2.0/24"],
    "maildivvy_firewall_confirmation": "ssh-login",
    "maildivvy_admin_ssh_source": "192.0.2.7",
    "maildivvy_cert_mode": "acme",
    "maildivvy_acme_dns_provider": "desec",
}


# --- the machine ------------------------------------------------------------------


def test_ubuntu_2604_as_root_passes_the_machine_checks():
    assert checks.machine_problems(UBUNTU_2604, euid=0) == []


@pytest.mark.parametrize("text, word", [
    ('NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n', "24.04"),
    ('NAME="Debian GNU/Linux"\nVERSION_ID="13"\nID=debian\n', "debian"),
    ("", "unknown"),
])
def test_any_other_system_is_refused_naming_what_it_is(text, word):
    problems = checks.machine_problems(text, euid=0)
    assert len(problems) == 1 and "Ubuntu 26.04" in problems[0] and word in problems[0], problems


def test_a_run_that_is_not_root_is_refused():
    problems = checks.machine_problems(UBUNTU_2604, euid=1000)
    assert problems == ["not root: run it as root, with sudo ./maildivvy-install"]


@pytest.mark.parametrize("text, version", [
    ("ansible-playbook [core 2.20.1]\n  config file = None\n", (2, 20, 1)),
    ("ansible-playbook [core 2.21.4]\n", (2, 21, 4)),
    ("something else\n", None),
])
def test_the_ansible_core_version_is_read_from_its_first_line(text, version):
    assert checks.ansible_version(text) == version


def test_the_ansible_core_ubuntu_ships_is_the_one_the_roles_are_tested_with():
    # Ubuntu 26.04's ansible-core, read on the test VM; public CI pins the same one
    workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    assert f"ansible-core=={'.'.join(map(str, checks.TESTED_ANSIBLE))}." in workflow
    assert checks.ansible_note((*checks.TESTED_ANSIBLE, 1)) is None
    note = checks.ansible_note((2, 22, 0))
    assert "2.22.0" in note and "2.20" in note and "untested" in note


# --- the release's manifest -------------------------------------------------------


def release(tmp_path):
    root = tmp_path / "release"
    (root / "ansible" / "roles").mkdir(parents=True)
    (root / "maildivvy-install").write_text("#!/usr/bin/python3\n")
    (root / "ansible" / "site.yml").write_text("- name: Install Maildivvy\n")
    (root / "ansible" / "roles" / "main.yml").write_text("x: 1\n")
    manifest.write(root)
    return root


def test_a_release_as_built_matches_its_manifest(tmp_path):
    root = release(tmp_path)
    lines = (root / "MANIFEST").read_text().splitlines()
    assert [line.split("  ")[1] for line in lines] == ["ansible/roles/main.yml", "ansible/site.yml",
                                                     "maildivvy-install"]
    assert all(len(line.split("  ")[0]) == 64 for line in lines)
    assert manifest.problems(root) == []


def test_a_changed_missing_or_added_file_is_named(tmp_path):
    root = release(tmp_path)
    (root / "ansible" / "site.yml").write_text("- name: Install something else\n")
    (root / "ansible" / "roles" / "main.yml").unlink()
    (root / "ansible" / "library").mkdir()
    (root / "ansible" / "library" / "planted.py").write_text("import os\n")
    assert manifest.problems(root) == [
        "changed: ansible/site.yml differs from the release's MANIFEST",
        "missing: ansible/roles/main.yml is in the release's MANIFEST and not here",
        "not in the release: ansible/library/planted.py",
    ]


def test_a_symlink_in_the_tree_is_refused_even_to_a_listed_file(tmp_path):
    root = release(tmp_path)
    (root / "ansible" / "site.yml").unlink()
    (root / "ansible" / "site.yml").symlink_to(root / "maildivvy-install")
    assert manifest.problems(root) == ["not a regular file: ansible/site.yml"]


def test_a_tree_without_a_manifest_is_not_a_release(tmp_path):
    root = release(tmp_path)
    (root / "MANIFEST").unlink()
    [problem] = manifest.problems(root)
    assert problem.startswith("no MANIFEST:")


def test_a_malformed_manifest_line_is_refused(tmp_path):
    root = release(tmp_path)
    with open(root / "MANIFEST", "a") as f:
        f.write("not a line\n")
    assert manifest.problems(root) == ["malformed MANIFEST line 4"]


def test_a_manifest_cannot_name_a_path_outside_the_tree(tmp_path):
    root = release(tmp_path)
    with open(root / "MANIFEST", "a") as f:
        f.write("0" * 64 + "  ../outside\n")
    assert manifest.problems(root) == ["malformed MANIFEST line 4"]


def test_the_installer_refuses_a_mismatch_before_anything_changes(tmp_path, monkeypatch):
    """The checks come first: no package is installed, no directory made, no prompt shown."""
    root = release(tmp_path)
    (root / "ansible" / "site.yml").write_text("changed\n")
    acted = []
    monkeypatch.setattr(cli, "read_os_release", lambda: UBUNTU_2604)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    for name in ("install_ansible", "prepare_log", "load_or_ask", "run_install"):
        monkeypatch.setattr(cli, name, lambda *a, _name=name, **k: acted.append(_name))
    out = []
    assert cli.main([], root=root, write=out.append) == 2
    assert acted == []
    assert "changed: ansible/site.yml differs from the release's MANIFEST" in "\n".join(out)
    assert "nothing was changed" in "\n".join(out)


# --- the settings file ------------------------------------------------------------


def settings_file(tmp_path, values, mode=0o600):
    path = tmp_path / "install.yml"
    path.write_text(json.dumps(values))
    path.chmod(mode)
    return path


def test_the_settings_file_is_read_when_present(tmp_path):
    path = settings_file(tmp_path, GOOD)
    assert settings.load(path, owner=os.getuid()) == GOOD


@pytest.mark.parametrize("key", ["maildivvy_breakglass_password", "maildivvy_acme_dns_credentials"])
def test_a_secret_in_the_settings_file_is_refused_without_echoing_it(tmp_path, key):
    path = settings_file(tmp_path, {**GOOD, key: TOKEN})
    with pytest.raises(settings.Refusal) as refusal:
        settings.load(path, owner=os.getuid())
    assert f"secret {key} in {path}" in str(refusal.value)
    assert TOKEN not in str(refusal.value)


def test_the_test_certificate_flag_is_the_command_lines_alone(tmp_path):
    path = settings_file(tmp_path, {**GOOD, "maildivvy_insecure_test_certificate": True})
    with pytest.raises(settings.Refusal, match="--insecure-test-certificate"):
        settings.load(path, owner=os.getuid())


@pytest.mark.parametrize("values, words", [
    (["maildivvy_hostname"], "not a mapping"),
    ({**GOOD, "ansible_connection": "ssh"}, "not a Maildivvy setting: ansible_connection"),
    # a misspelled setting is refused, not ignored
    ({**GOOD, "maildivvy_backup_store_cpy": "true"}, "not a Maildivvy setting: maildivvy_backup_store_cpy"),
    # a role's own variable: extra vars would outrank it
    ({**GOOD, "maildivvy_cert_program": "/tmp/x"}, "not a Maildivvy setting: maildivvy_cert_program"),
    ({**GOOD, "maildivvy_store_gib": 50}, "not a Maildivvy setting: maildivvy_store_gib"),
    ({**GOOD, "maildivvy_lego": "/usr/bin/true"}, "not a Maildivvy setting: maildivvy_lego"),
    ({**GOOD, "maildivvy_installer_run": False}, "not a Maildivvy setting: maildivvy_installer_run"),
])
def test_the_settings_file_holds_only_the_documented_settings(tmp_path, values, words):
    with pytest.raises(settings.Refusal, match=words):
        settings.load(settings_file(tmp_path, values), owner=os.getuid())


def test_the_settings_are_the_ones_step_1_checks():
    """Every option of the preflight module but the secrets, the run's own values and the
    connection is a setting, and nothing else is."""
    import yaml
    sys.path.insert(0, str(REPO / "ansible" / "library"))
    try:
        import maildivvy_preflight
    finally:
        sys.path.pop(0)
    options = yaml.safe_load(maildivvy_preflight.DOCUMENTATION)["options"]
    run_only = {"connection", "insecure_test_certificate", *maildivvy_preflight.SECRETS}
    assert set(settings.SETTINGS) == {f"maildivvy_{name}" for name in options if name not in run_only}
    # docs/public/ here, docs/ in the public tree
    guide = next(p for p in (REPO / "docs" / "public" / "installation.md", REPO / "docs" / "installation.md")
                 if p.exists())
    documented = guide.read_text()
    assert [name for name in settings.SETTINGS if f"`{name}`" not in documented] == []


def test_the_role_defaults_install_yml_takes_are_the_ones_the_roles_readme_offers():
    import yaml
    defaults = set()
    for path in (REPO / "ansible" / "roles").glob("*/defaults/main.yml"):
        defaults |= set(yaml.safe_load(path.read_text()) or {})
    readme = (REPO / "ansible" / "README.md").read_text()
    assert [name for name in settings.TUNABLES if name not in defaults or f"`{name}`" not in readme] == []
    path_like = {"maildivvy_lego", "maildivvy_cert_program", "maildivvy_credentials_dir", "maildivvy_ban_program"}
    assert path_like <= defaults and not path_like & set(settings.TUNABLES)


def test_every_setting_the_questions_write_is_a_setting():
    answers = ["mail.example.org", "", "separate", "/dev/vdb", "/dev/vdc", "/dev/vdd", "192.0.2.0/24",
               "ssh-login", "192.0.2.7", "acme", "desec", "hostmaster@example.org", "cp -a x y", "/var/lib/n"]
    values = prompts.ask_settings(Console(answers), "mail", {"blockdevices": []}, insecure=False)
    assert set(values) <= set(settings.SETTINGS)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o620])
def test_a_settings_file_others_can_read_or_write_is_refused(tmp_path, mode):
    """It names a command run as root (the store copy): only root may write it."""
    with pytest.raises(settings.Refusal, match="must be 0600"):
        settings.load(settings_file(tmp_path, GOOD, mode), owner=os.getuid())


def test_a_settings_file_owned_by_another_user_is_refused(tmp_path):
    with pytest.raises(settings.Refusal, match="must be root's"):
        settings.load(settings_file(tmp_path, GOOD), owner=os.getuid() + 1)


def test_a_role_default_the_roles_readme_offers_is_taken(tmp_path):
    values = {**GOOD, "maildivvy_fetch_minutes": 5, "maildivvy_acme_dns_propagation_timeout": 600}
    assert settings.load(settings_file(tmp_path, values), owner=os.getuid()) == values


def test_saved_settings_are_0600_and_carry_no_secret(tmp_path):
    path = tmp_path / "etc" / "install.yml"
    settings.save(path, GOOD)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert settings.load(path, owner=os.getuid()) == GOOD
    with pytest.raises(ValueError):
        settings.save(path, {**GOOD, "maildivvy_breakglass_password": PASSWORD})
    assert PASSWORD not in path.read_text()


# --- the secrets --------------------------------------------------------------------


def test_secrets_on_standard_input_are_the_secret_settings_only():
    values = settings.parse_secrets(json.dumps({"maildivvy_breakglass_password": PASSWORD,
                                                "maildivvy_acme_dns_credentials": {"DESEC_TOKEN": TOKEN}}))
    assert values == {"maildivvy_breakglass_password": PASSWORD,
                      "maildivvy_acme_dns_credentials": {"DESEC_TOKEN": TOKEN}}
    with pytest.raises(settings.Refusal, match="not a secret: maildivvy_cert_name"):
        settings.parse_secrets(json.dumps({"maildivvy_cert_name": "mail.example.org"}))
    with pytest.raises(settings.Refusal, match="not a mapping"):
        settings.parse_secrets("- " + PASSWORD)


class Literal(str):
    pass


def literal_loader():
    """A YAML loader that reads `!unsafe` as ansible does: the string, marked as never a template."""
    import yaml

    class Loader(yaml.SafeLoader):
        pass
    Loader.add_constructor("!unsafe", lambda loader, node: Literal(loader.construct_scalar(node)))
    return Loader


def strings(value):
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return [value] if isinstance(value, str) else []


def test_the_secrets_reach_ansible_in_a_root_only_file_that_is_gone_after_the_run(tmp_path):
    import yaml
    with run.values_file({"maildivvy_breakglass_password": PASSWORD}, base=tmp_path) as path:
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert yaml.load(path.read_text(), Loader=literal_loader()) == {"maildivvy_breakglass_password": PASSWORD}
    assert not path.exists() and not path.parent.exists()


TEMPLATE_LIKE = ["abc{{ 1+1 }}xyz", "abc{#defghijklmnop", "{% if x %}", "it's \"quoted\"\nand two lines", "ünï"]


def test_every_string_the_run_is_given_is_marked_never_a_template():
    """ansible templates extra vars: a password with `{{` would be stored changed, `{#` or `{%`
    would stop the run. Every string, nested ones too, is tagged `!unsafe`; numbers and
    booleans stay what they are."""
    import yaml
    values = {"maildivvy_breakglass_password": TEMPLATE_LIKE[0],
              "maildivvy_acme_dns_credentials": {"DESEC_TOKEN": TEMPLATE_LIKE[1], "OTHER": TEMPLATE_LIKE[2]},
              "maildivvy_admin_networks": ["192.0.2.0/24"], "maildivvy_backup_store_copy": TEMPLATE_LIKE[3],
              "maildivvy_cert_name": TEMPLATE_LIKE[4], "maildivvy_vmail_uid": 900, "maildivvy_installer_run": True}
    loaded = yaml.load(run.values_yaml(values), Loader=literal_loader())
    assert loaded == values
    assert all(isinstance(s, Literal) for s in strings(loaded))
    assert loaded["maildivvy_vmail_uid"] == 900 and loaded["maildivvy_installer_run"] is True


ANSIBLE_PLAYBOOK = Path(sys.executable).parent / "ansible-playbook"


@pytest.mark.skipif(not ANSIBLE_PLAYBOOK.exists(), reason="no ansible-playbook beside this python")
def test_ansible_passes_a_template_like_secret_on_unchanged(tmp_path):
    (tmp_path / "values.yml").write_text(run.values_yaml({"secret": {"k": TEMPLATE_LIKE[0] + TEMPLATE_LIKE[1]}}))
    (tmp_path / "play.yml").write_text(
        "- hosts: localhost\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.copy: {content: '{{ secret.k }}', dest: '" + str(tmp_path / "out") + "'}\n")
    done = subprocess.run([str(ANSIBLE_PLAYBOOK), "-i", "localhost,", "-c", "local", "-e", "@values.yml", "play.yml"],
                          cwd=tmp_path, capture_output=True, text=True, env={**os.environ, "ANSIBLE_NOCOLOR": "1"})
    assert done.returncode == 0, done.stdout + done.stderr
    assert (tmp_path / "out").read_text() == TEMPLATE_LIKE[0] + TEMPLATE_LIKE[1]


def test_no_secret_is_on_the_command_line_or_in_the_environment(tmp_path):
    argv = run.playbook_argv(REPO, tmp_path / "values.yml")
    env = run.environment(REPO, {"PATH": "/usr/bin", "MAILDIVVY_X": PASSWORD})
    assert argv == ["/usr/bin/ansible-playbook", "-i", str(REPO / "ansible" / "local.yml"),
                    "-e", f"@{tmp_path / 'values.yml'}", str(REPO / "ansible" / "site.yml")]
    assert PASSWORD not in " ".join(argv)
    assert PASSWORD not in json.dumps(env)
    assert env["ANSIBLE_CONFIG"] == str(REPO / "ansible" / "ansible.cfg")


def test_the_upgrades_check_runs_step_1_alone():
    argv = run.playbook_argv(REPO, "/run/x/values.yml", preflight_only=True)
    assert argv[-3:] == ["--tags", "preflight", str(REPO / "ansible" / "site.yml")]


def test_the_proxies_of_the_installers_environment_reach_apt_and_the_play():
    base = {"PATH": "/usr/bin", "https_proxy": "http://proxy:3128", "NO_PROXY": "localhost", "SECRET": "x"}
    env = run.environment(REPO, base)
    assert env["https_proxy"] == "http://proxy:3128" and env["NO_PROXY"] == "localhost" and "SECRET" not in env
    # sudo, which the play becomes root with, drops them: the play sets them itself
    given = run.run_values({}, {}, insecure=False, base=base)
    assert given[settings.RUN_ENVIRONMENT] == {"https_proxy": "http://proxy:3128", "NO_PROXY": "localhost"}
    assert settings.RUN_ENVIRONMENT not in run.run_values({}, {}, insecure=False, base={"PATH": "/usr/bin"})


def preflight_tasks():
    """Step 1's tasks in their order, each with its blocks' `when` conditions and its own, as a list."""
    import yaml

    def flat(tasks, when):
        for task in tasks:
            own = task.get("when", [])
            conditions = when + ([own] if isinstance(own, str) else list(own))
            if "block" in task:
                yield from flat(task["block"], conditions)
            else:
                yield {**task, "when": conditions}
    tasks = yaml.safe_load((REPO / "ansible" / "roles" / "preflight" / "tasks" / "main.yml").read_text())
    return list(flat(tasks, []))


def test_a_control_machines_run_records_its_version_and_the_installers_leaves_that_to_the_installer():
    """maildivvy-install records the version once every step passed, after an upgrade's
    backup; a run from a control machine records it at the end of a full run (untagged, so a
    run with --tags records nothing), and step 1 refuses it on a machine at another version."""
    import yaml
    play = yaml.safe_load((REPO / "ansible" / "site.yml").read_text())[0]
    record = [t for t in play["post_tasks"] if t["name"] == "Record the version this run installed"]
    assert len(record) == 1 and "tags" not in record[0]
    assert record[0]["ansible.builtin.copy"]["dest"] == str(upgrade.VERSION_FILE)
    assert record[0]["when"] == f"not {settings.INSTALLER_RUN} | default(false)"
    preflight = preflight_tasks()
    guard = [t for t in preflight if "never upgrades" in t["name"]]
    assert len(guard) == 1 and guard[0]["when"] == [f"not {settings.INSTALLER_RUN} | default(false)"]
    assert preflight.index(guard[0]) < [t["name"] for t in preflight].index(
        "Check every setting and identify the data disks")
    units = yaml.safe_load((REPO / "ansible" / "roles" / "programs" / "tasks" / "units.yml").read_text())
    start = next(t for t in units if t["name"] == "Enable and start the units that run")
    assert settings.COLLECTION_PAUSED in start["ansible.builtin.systemd_service"]["state"]


def test_a_control_machines_first_install_is_unfinished_until_its_version_and_leaves_no_upgrade_record():
    """A control machine's first install that stops past step 6 must not look like a machine
    from before 0.1.0 (schema, no version file) to maildivvy-install: step 1 records it as
    unfinished, as the installer does, and the version post_task removes that record and a
    failed upgrade's, which the old version's run is the way back from."""
    import yaml
    play = yaml.safe_load((REPO / "ansible" / "site.yml").read_text())[0]
    names = [t["name"] for t in play["post_tasks"]]
    cleanup = play["post_tasks"][names.index("Remove the unfinished install's and a failed upgrade's records")]
    assert names.index(cleanup["name"]) > names.index("Record the version this run installed")
    assert "tags" not in cleanup and cleanup["when"] == f"not {settings.INSTALLER_RUN} | default(false)"
    assert set(cleanup["loop"]) == {str(upgrade.UNFINISHED), str(upgrade.PAUSE_RECORD), str(upgrade.HELD)}
    preflight = preflight_tasks()
    record = next(t for t in preflight if t["name"].startswith("Record a first install from a control machine"))
    assert record["ansible.builtin.copy"]["dest"] == str(upgrade.UNFINISHED)
    read = next(t for t in preflight if t["name"].startswith("Read whether this machine has our schema"))
    assert f"not {settings.INSTALLER_RUN} | default(false)" in read["when"]
    assert "SELECT count(*) FROM schema_version" in read["ansible.builtin.command"]["argv"]
    # after every check of step 1: a refused run records nothing
    assert preflight.index(record) > [t["name"] for t in preflight].index(
        "Check every setting and identify the data disks")


def test_a_control_machine_never_takes_over_a_machine_from_before_0_1_0():
    """A machine with our schema, no version file and no unfinished install is one from
    before 0.1.0: only maildivvy-install moves it on, with a backup, a pause and its version
    rule. Step 1 of a control machine's run refuses it before anything changes."""
    import yaml
    preflight = preflight_tasks()
    names = [t["name"] for t in preflight]
    guard = next(t for t in preflight if t["name"].startswith("A run from a control machine never takes over"))
    read = next(t for t in preflight if t["name"].startswith("Read whether this machine has our schema"))
    unfinished = next(t for t in preflight if t["name"].startswith("Read whether a first install is unfinished"))
    assert unfinished["ansible.builtin.stat"]["path"] == str(upgrade.UNFINISHED)
    assert f"not {settings.INSTALLER_RUN} | default(false)" in guard["when"]
    that = guard["ansible.builtin.assert"]["that"]
    assert "maildivvy_schema_read" in that and "maildivvy_unfinished.stat.exists" in that
    assert "maildivvy-install" in guard["ansible.builtin.assert"]["fail_msg"]
    # read and refused before the first task that changes anything
    first_change = names.index("Preseed Postfix's mailer-type question, so its install never waits")
    assert names.index(read["name"]) < names.index(unfinished["name"]) < names.index(guard["name"]) < first_change


NOT_ANSWERING = ('psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" '
                 'failed: No such file or directory\n\tIs the server running locally and accepting '
                 'connections on that socket?')


@pytest.mark.parametrize("rc, stdout, stderr, unfinished, passes", [
    (127, "", "runuser: failed to execute psql: No such file or directory", False, True),  # no psql
    (1, "", "runuser: user postgres does not exist", False, True),        # no postgres account
    (2, "", 'psql: error: FATAL:  database "maildivvy" does not exist', False, True),
    (1, "", 'ERROR:  relation "schema_version" does not exist', False, True),
    (0, "0", "", False, True),                                             # our table, no rows
    (0, "1", "", False, False),                                            # from before 0.1.0
    (0, "1", "", True, True),                                              # an unfinished install
    (2, "", NOT_ANSWERING, False, False),                                  # cannot tell: refused
    (2, "", NOT_ANSWERING, True, True),
    (None, "", "", False, False),                                          # the read did not run
])
def test_a_control_machines_run_with_no_version_passes_only_where_the_installer_would_install(
        rc, stdout, stderr, unfinished, passes):
    """Step 1 of a control machine's run on a machine with no version file reads the schema as
    installer.upgrade.schema_versions does, and fails closed as it does: a database that does
    not answer cannot tell a machine from before 0.1.0 from a clean one, and is refused unless
    the install is recorded as unfinished."""
    import jinja2
    import yaml
    preflight = preflight_tasks()
    guards = [t for t in preflight if "ansible.builtin.assert" in t
              and "maildivvy_installed_version.content is not defined" in t.get("when", [])]
    assert len(guards) >= 1
    read = {"stdout": stdout, "stderr": stderr} | ({} if rc is None else {"rc": rc})
    names = {"maildivvy_schema_read": read, "maildivvy_unfinished": {"stat": {"exists": unfinished}}}
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)
    held = []
    for guard in guards:
        that = guard["ansible.builtin.assert"]["that"]
        for condition in [that] if isinstance(that, str) else that:
            held.append(bool(env.compile_expression(condition)(**names)))
    assert all(held) is passes
    if not passes and rc == 2:
        refusing = next(g for g in guards if not bool(env.compile_expression(
            g["ansible.builtin.assert"]["that"])(**names)))
        message = env.from_string(refusing["ansible.builtin.assert"]["fail_msg"]).render(**names)
        assert "did not answer" in message and "No such file or directory" in message
    if rc is None:
        return
    # the same read by the installer: step 1 refuses only what it refuses, and records a
    # first install only where it finds nothing there (no psql, no account, database or table)
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, rc, stdout, stderr)
    try:
        found = upgrade.schema_versions(run=run, psql="/nonexistent/psql" if rc == 127 else sys.executable)
    except settings.Refusal:
        found = None
    closed = next(g for g in guards if "[0, 127]" in g["ansible.builtin.assert"]["that"])
    assert bool(env.compile_expression(closed["ansible.builtin.assert"]["that"])(**names)) is (
        unfinished or found is not None)
    fact = next(t for t in preflight if t["name"] == "Tell whether this is a first install from a control machine")
    first = env.from_string(fact["ansible.builtin.set_fact"]["maildivvy_control_first_install"]).render(**names)
    assert (first == "True") is (rc != 0 and found == [])


def test_the_local_inventory_is_the_machine_itself_over_a_local_connection():
    import yaml
    inventory = yaml.safe_load((REPO / "ansible" / "local.yml").read_text())
    assert inventory == {"maildivvy": {"hosts": {"localhost": {
        "ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3"}}}}


def test_the_run_values_are_the_settings_the_secrets_and_the_flags_only_when_given():
    secrets = {"maildivvy_breakglass_password": PASSWORD}
    ours = {**GOOD, **secrets, "maildivvy_installer_run": True}
    assert run.run_values(GOOD, secrets, insecure=False) == ours
    assert run.run_values(GOOD, secrets, insecure=True) == {**ours, "maildivvy_insecure_test_certificate": True}
    assert run.run_values(GOOD, secrets, insecure=False, paused=True) == {**ours, "maildivvy_collection_paused": True}


class Child:
    """A stand-in for ansible-playbook: prints its lines, and records what was there at each."""

    def __init__(self, lines, seen, path):
        self.lines, self.seen, self.path = lines, seen, path
        self.stdout = self._lines()

    def _lines(self):
        for line in self.lines:
            self.seen.append((line, self.path.exists()))
            yield line + "\n"

    def wait(self):
        return 0


def test_the_values_file_is_gone_once_the_play_has_begun(tmp_path, monkeypatch):
    """ansible reads its extra vars before the play's first line: the secrets file is removed
    then, before anything the play prints next is read, and every line reaches the log."""
    path = tmp_path / "values.yml"
    path.write_text("secret")
    seen = []
    lines = ["[WARNING]: something", "PLAY [Install Maildivvy] ***", "TASK [preflight : Check every setting] ***",
             "ok: [localhost]"]
    monkeypatch.setattr(run.subprocess, "Popen", lambda *a, **k: Child(lines, seen, path))
    log = tmp_path / "log"
    shown = []
    with open(log, "w") as f:
        code = run.run_playbook(["ansible-playbook"], {}, f, run.Screen([("preflight", "1: preflight")], shown.append),
                                started=lambda: path.unlink())
    assert code == 0
    assert seen == [(lines[0], True), (lines[1], True), (lines[2], False), (lines[3], False)]
    assert log.read_text() == "".join(line + "\n" for line in lines)
    assert shown == ["step 1: preflight"]


# --- the prompts --------------------------------------------------------------------


class Console:
    """Answers given in order; `secret` answers come from their own list and never echo."""

    def __init__(self, answers, secrets=()):
        self.answers, self.secrets, self.shown, self.asked_secret = list(answers), list(secrets), [], []

    def ask(self, question, default=None):
        self.shown.append(question)
        answer = self.answers.pop(0)
        return answer if answer else (default or "")

    def secret(self, question):
        self.asked_secret.append(question)
        return self.secrets.pop(0)

    def say(self, text):
        self.shown.append(text)


LSBLK = {"blockdevices": [
    {"path": "/dev/xvda", "size": 21474836480, "type": "disk", "model": None, "mountpoints": [None],
     "children": [{"path": "/dev/xvda2", "type": "part", "mountpoints": ["/"]}]},
    {"path": "/dev/xvdc", "size": 10737418240, "type": "disk", "model": "fast", "mountpoints": [None]},
    {"path": "/dev/xvdd", "size": 5368709120, "type": "disk", "model": None, "mountpoints": [None]},
    {"path": "/dev/sr0", "size": 1073741824, "type": "rom", "model": "DVD", "mountpoints": [None]},
]}


def test_the_disks_offered_are_the_whole_disks_but_the_system_disk():
    assert prompts.disk_choices(LSBLK) == [("/dev/xvdc", "10.0 GiB", "fast"), ("/dev/xvdd", "5.0 GiB", "")]


def test_without_a_settings_file_every_setting_is_asked_for_disks_certificate_and_ssh_source():
    console = Console([
        "mail.example.org",       # the mail name
        "",                       # vmail id: the default
        "separate",               # disk mode
        "/dev/xvdc", "/dev/xvdd", "",   # store, index, no swap disk
        "192.0.2.0/24, 2001:db8::/64",  # administrator networks
        "ssh-login", "192.0.2.7",       # confirmation and the source
        "acme", "cloudflare", "",       # certificate: provider, no contact address
        "", "",                   # no store copy, no textfile directory
    ])
    values = prompts.ask_settings(console, hostname="mail", lsblk=LSBLK, insecure=False)
    assert values == {
        "maildivvy_hostname": "mail",
        "maildivvy_cert_name": "mail.example.org",
        "maildivvy_vmail_uid": 900, "maildivvy_vmail_gid": 900,
        "maildivvy_disk_mode": "separate",
        "maildivvy_store_disk": "/dev/xvdc", "maildivvy_index_disk": "/dev/xvdd",
        "maildivvy_admin_networks": ["192.0.2.0/24", "2001:db8::/64"],
        "maildivvy_firewall_confirmation": "ssh-login", "maildivvy_admin_ssh_source": "192.0.2.7",
        "maildivvy_cert_mode": "acme", "maildivvy_acme_dns_provider": "cloudflare",
    }
    shown = "\n".join(console.shown)
    assert "/dev/xvdc  10.0 GiB  fast" in shown and "/dev/xvda" not in shown   # size and model shown
    assert console.asked_secret == []                                         # no secret among them


def test_one_disk_mode_and_a_provided_certificate_ask_for_their_own_settings():
    console = Console(["mail.example.org", "901", "single", "192.0.2.0/24", "console",
                       "provided", "/root/cert.pem", "/root/chain.pem", "/root/key.pem",
                       "rsync -aH /srv/maildivvy/store/ /mnt/copy/", "/var/lib/node-exporter"])
    values = prompts.ask_settings(console, hostname="mail", lsblk=LSBLK, insecure=False)
    assert values == {
        "maildivvy_hostname": "mail", "maildivvy_cert_name": "mail.example.org",
        "maildivvy_vmail_uid": 901, "maildivvy_vmail_gid": 901, "maildivvy_disk_mode": "single",
        "maildivvy_admin_networks": ["192.0.2.0/24"], "maildivvy_firewall_confirmation": "console",
        "maildivvy_cert_mode": "provided", "maildivvy_provided_cert": "/root/cert.pem",
        "maildivvy_provided_chain": "/root/chain.pem", "maildivvy_provided_key": "/root/key.pem",
        "maildivvy_backup_store_copy": "rsync -aH /srv/maildivvy/store/ /mnt/copy/",
        "maildivvy_health_textfile_dir": "/var/lib/node-exporter",
    }


def test_self_signed_is_offered_only_with_the_test_flag():
    base = ["mail.example.org", "", "single", "192.0.2.0/24", "console"]
    console = Console([*base, "self-signed", "acme", "", "", "", ""])
    values = prompts.ask_settings(console, hostname="mail", lsblk=LSBLK, insecure=False)
    assert values["maildivvy_cert_mode"] == "acme"          # asked again: not a choice here
    console = Console([*base, "self-signed", "", ""])
    values = prompts.ask_settings(console, hostname="mail", lsblk=LSBLK, insecure=True)
    assert values["maildivvy_cert_mode"] == "self-signed"
    assert "maildivvy_insecure_test_certificate" not in values   # the flag, never the file


def test_a_required_answer_left_empty_is_asked_again():
    console = Console(["", "mail.example.org", "", "single", "", "192.0.2.0/24", "console",
                       "acme", "", "", "", ""])
    values = prompts.ask_settings(console, hostname="mail", lsblk=LSBLK, insecure=False)
    assert values["maildivvy_cert_name"] == "mail.example.org"
    assert values["maildivvy_admin_networks"] == ["192.0.2.0/24"]


def test_the_secrets_are_asked_without_echo_and_the_password_twice():
    console = Console(["DESEC_TOKEN"], secrets=[PASSWORD, PASSWORD, TOKEN])
    values = prompts.ask_secrets(console, {**GOOD})
    assert values == {"maildivvy_breakglass_password": PASSWORD,
                      "maildivvy_acme_dns_credentials": {"DESEC_TOKEN": TOKEN}}
    assert len(console.asked_secret) == 3
    assert PASSWORD not in "\n".join(console.shown) and TOKEN not in "\n".join(console.shown)


def test_a_password_that_differs_or_is_short_is_asked_again():
    console = Console([], secrets=["short", "short", PASSWORD, PASSWORD + "x", PASSWORD, PASSWORD])
    values = prompts.ask_secrets(console, {**GOOD, "maildivvy_cert_mode": "provided"})
    assert values == {"maildivvy_breakglass_password": PASSWORD}
    assert any("15 characters" in s for s in console.shown)
    assert any("did not match" in s for s in console.shown)


def test_the_summary_shows_every_setting_to_confirm():
    lines = prompts.summary(GOOD)
    assert "maildivvy_cert_name: mail.example.org" in lines
    assert "maildivvy_admin_networks: 192.0.2.0/24" in lines


# --- what the screen shows, and the log keeps ---------------------------------------


SITE = (REPO / "ansible" / "site.yml").read_text()

OUTPUT = """
PLAY [Install Maildivvy] *******************************************************

TASK [preflight : Check every setting and identify the data disks] *************
ok: [localhost]

TASK [disks : vmail has the fixed uid and gid] *********************************
ok: [localhost]

TASK [firewall : Arm the self-reverting timer] *********************************
changed: [localhost]

TASK [firewall : Waiting for a new SSH login from 192.0.2.7 through the new rules] ***
ok: [localhost]

TASK [certificate : Say which credentials are stored and whether the DNS provider is tested] ***
ok: [localhost] => {
    "msg": [
        "desec: TESTED"
    ]
}

TASK [programs : Each user is in its own group and exactly its others] *********
ok: [localhost] => (item=vmail)

TASK [postgresql : The server listens on loopback only] ************************
fatal: [localhost]: FAILED! => {"changed": false, "msg": "the server listens on 0.0.0.0:5432\\nand on [::]:5432"}

PLAY RECAP *********************************************************************
localhost                  : ok=5    changed=1    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
"""


def screen_of(text):
    shown = []
    screen = run.Screen(run.site_steps(SITE), shown.append)
    for line in text.splitlines():
        screen.feed(line)
    return shown


def test_the_steps_are_read_from_site_yml_in_its_order():
    steps = run.site_steps(SITE)
    assert steps[0] == ("preflight", "1: preflight")
    assert [role for role, _ in steps].count("programs") == 2
    assert steps[-1] == ("publish", "19: publication: 993 and 465 opened")
    assert len(steps) == 20


def test_the_screen_shows_one_line_per_step_what_needs_the_operator_and_the_failure():
    shown = screen_of(OUTPUT)
    text = "\n".join(shown)
    assert "step 1: preflight" in shown and "step 2: data disks and vmail" in shown
    assert "step 13, first part: users, layout, code" in shown
    assert "TASK [" not in text and "Arm the self-reverting timer" not in text   # the log's, not the screen's
    assert "open a NEW SSH session to this machine from 192.0.2.7 now" in text
    assert '"desec: TESTED"' in text                                          # a message a step says
    assert "failed: the server listens on 0.0.0.0:5432\n  and on [::]:5432" in text
    assert text.index("step 6: PostgreSQL") < text.index("failed: the server listens")
    assert "localhost                  : ok=5    changed=1    unreachable=0    failed=1" in text


def test_a_loop_item_failure_is_shown_with_its_message():
    shown = screen_of('TASK [disks : x] ***\nfailed: [localhost] (item=store) => {"msg": "no"}\n')
    assert "failed (item=store): no" in shown


def test_what_a_loop_item_says_is_shown_whole():
    shown = screen_of('TASK [certificate : x] ***\nok: [localhost] => (item=desec) => {\n    "msg": "desec: TESTED"\n}\n'
                      'ok: [localhost] (item=other) => {\n    "msg": "other: untested"\n}\n')
    assert shown[-2:] == ['ok: [localhost] => (item=desec) => {\n    "msg": "desec: TESTED"\n}',
                          'ok: [localhost] (item=other) => {\n    "msg": "other: untested"\n}']


def test_step_4s_wait_after_the_reload_asks_for_a_new_login_too():
    shown = screen_of("TASK [docker_block : Waiting for a new SSH login from 192.0.2.7 after the reload] ***\n")
    text = "\n".join(shown)
    assert "step 4: container firewall block" in text
    assert "open a NEW SSH session to this machine from 192.0.2.7 now" in text


def test_output_that_ends_inside_a_message_still_shows_it():
    shown = []
    screen = run.Screen(run.site_steps(SITE), shown.append)
    for line in ('ok: [localhost] => {', '    "msg": "cut short"'):
        screen.feed(line)
    screen.close()
    assert shown == ['ok: [localhost] => {\n    "msg": "cut short"']


# --- what is left to the operator ----------------------------------------------------


def test_the_closing_list_names_what_the_operator_still_has_to_do():
    steps = "\n".join(run.remaining({**GOOD, "maildivvy_acme_dns_provider": "cloudflare"}, "/var/log/x.log"))
    assert "https://mail.example.org/" in steps and "break-glass" in steps
    assert "outside probe" in steps
    assert "993 and 465" in steps
    assert "maildivvy_backup_store_copy" in steps          # not set yet: before the first external mailbox
    assert "cloudflare is untested" in steps
    assert "/var/log/x.log" in steps
    provided = "\n".join(run.remaining({**GOOD, "maildivvy_cert_mode": "provided",
                                        "maildivvy_backup_store_copy": "rsync"}, "/l"))
    assert "maildivvy-cert install-provided" in provided and "maildivvy_backup_store_copy" not in provided
    assert "SELF-SIGNED" in "\n".join(run.remaining({**GOOD, "maildivvy_cert_mode": "self-signed"}, "/l"))


# --- the command ---------------------------------------------------------------------


def test_secrets_on_stdin_need_the_settings_file(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PATH", tmp_path / "absent.yml")
    out = []
    with pytest.raises(settings.Refusal, match="no settings file"):
        cli.load_or_ask(cli.parse([ "--secrets-on-stdin"]), stdin=None, console=None, write=out.append)


class Terminal:
    def isatty(self):
        return True


def test_without_a_settings_file_the_answers_are_confirmed_written_and_the_secrets_kept_apart(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PATH", tmp_path / "etc" / "install.yml")
    monkeypatch.setattr(settings, "load", lambda path: settings.parse(Path(path).read_text(), str(path)))
    monkeypatch.setattr(cli, "_lsblk", lambda say: LSBLK)
    monkeypatch.setattr(cli.socket, "gethostname", lambda: "mail.example.org")
    answers = ["mail.example.org", "", "single", "192.0.2.0/24", "console", "acme", "", "", "", ""]
    console = Console([*answers, "yes", "DESEC_TOKEN"], secrets=[PASSWORD, PASSWORD, TOKEN])
    values, secrets = cli.load_or_ask(cli.parse([]), stdin=Terminal(), console=console, write=console.say)
    assert values["maildivvy_hostname"] == "mail" and values["maildivvy_cert_mode"] == "acme"
    assert secrets == {"maildivvy_breakglass_password": PASSWORD,
                       "maildivvy_acme_dns_credentials": {"DESEC_TOKEN": TOKEN}}
    written = settings.PATH.read_text()
    assert stat.S_IMODE(settings.PATH.stat().st_mode) == 0o600
    assert PASSWORD not in written and TOKEN not in written
    assert "maildivvy_cert_name: mail.example.org" in "\n".join(console.shown)   # shown before it is written
    # the next run reads the file and asks only for the secrets
    console = Console(["DESEC_TOKEN"], secrets=[PASSWORD, PASSWORD, TOKEN])
    again, _ = cli.load_or_ask(cli.parse([]), stdin=Terminal(), console=console, write=console.say)
    assert again == values and len(console.asked_secret) == 3


def test_a_disk_list_lsblk_could_not_give_is_said_not_left_empty(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(
        argv, 32, "", "lsblk: failed to access sysfs directory\n"))
    said = []
    assert cli._lsblk(said.append) == {"blockdevices": []}
    assert said == ["lsblk failed (lsblk: failed to access sysfs directory): the disks cannot be listed; "
                    "name them by their device paths"]


@pytest.mark.parametrize("codes, tried, failed", [([100, 0], 2, False), ([100, 100, 100], 3, True)])
def test_apt_get_is_tried_again_while_another_apt_may_hold_its_lock(monkeypatch, tmp_path, codes, tried, failed):
    calls = []

    def fake(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, codes[len(calls) - 1])
    monkeypatch.setattr(cli.subprocess, "run", fake)
    argv = ["apt-get", "-q", "-o", "DPkg::Lock::Timeout=600", "update"]
    with open(tmp_path / "log", "w") as log:
        if failed:
            with pytest.raises(upgrade.Failed, match="failed 3 times"):
                cli._apt(argv, log, {}, sleep=lambda s: None)
        else:
            cli._apt(argv, log, {}, sleep=lambda s: None)
    assert calls == [argv] * tried


def test_answers_not_confirmed_write_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PATH", tmp_path / "install.yml")
    monkeypatch.setattr(cli, "_lsblk", lambda say: LSBLK)
    console = Console(["mail.example.org", "", "single", "192.0.2.0/24", "console", "acme", "", "", "", "",
                       "no"])
    with pytest.raises(settings.Refusal, match="not confirmed"):
        cli.load_or_ask(cli.parse([]), stdin=Terminal(), console=console, write=console.say)
    assert not settings.PATH.exists()


def test_the_program_at_the_trees_root_runs_the_installer_without_bytecode():
    program = (REPO / "maildivvy-install").read_text()
    assert program.startswith("#!/usr/bin/python3\n")
    assert "sys.dont_write_bytecode = True" in program
    assert stat.S_IMODE((REPO / "maildivvy-install").stat().st_mode) & 0o111
    result = subprocess.run([sys.executable, str(REPO / "maildivvy-install"), "--help"],
                            capture_output=True, text=True)
    assert result.returncode == 0 and "--secrets-on-stdin" in result.stdout
    assert "--insecure-test-certificate" in result.stdout
