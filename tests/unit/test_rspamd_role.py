"""Install step 11's pure parts: the rspamd image's pin, the compose
project that must publish nothing, the override tree, and the one value that is both
the scanner's top band and a domain's threshold ceiling.

The running container, its socket and its scores are proved on the test VM.
"""

import re
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from maildivvy.lib import scan

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "rspamd"
SCHEMA = ROOT / "schema" / "0001_initial.sql"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def defaults():
    """The role's own variables: what an operator may override, and the paths it fixes."""
    values = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    for name, value in yaml.safe_load((ROLE / "vars" / "main.yml").read_text()).items():
        values[name] = value
    values["maildivvy_rspamd_image"] = (f"{values['maildivvy_rspamd_repository']}"
                                        f"@{values['maildivvy_rspamd_digest']}")
    return values


def render(name, **changes):
    """One of the role's templates, with the role's own variables."""
    env = Environment(loader=FileSystemLoader(str(ROLE / "templates")), undefined=StrictUndefined,
                      keep_trailing_newline=True)
    return env.get_template(name).render({**defaults(), **changes})


def compose(**changes):
    return yaml.safe_load(render("compose.yml.j2", **changes))


def service(**changes):
    return compose(**changes)["services"]["rspamd"]


def tasks():
    return yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())


def task_text():
    return (ROLE / "tasks" / "main.yml").read_text()


# --- the pin -------------------------------------------------------------


def test_the_image_is_pinned_by_a_digest_and_the_tag_it_was_read_from_is_beside_it():
    d = defaults()
    assert DIGEST.match(d["maildivvy_rspamd_digest"])
    assert d["maildivvy_rspamd_repository"] == "docker.io/rspamd/rspamd"
    assert re.match(r"^\d+\.\d+\.\d+$", str(d["maildivvy_rspamd_tag"]))
    # the pin, not the tag, is what the runtime is given: a tag moves, a digest does not
    env = render("env.j2")
    assert env.strip().endswith(f"{d['maildivvy_rspamd_repository']}@{d['maildivvy_rspamd_digest']}")
    assert str(d["maildivvy_rspamd_tag"]) not in env.split("RSPAMD_IMAGE=")[1]


def test_an_unset_image_variable_is_a_refusal_rather_than_a_silent_latest():
    image = service()["image"]
    assert image.startswith("${RSPAMD_IMAGE:?") and image.endswith("}")


def test_the_pin_is_recorded_where_health_reads_whether_a_newer_release_is_due():
    d = defaults()
    record = yaml.safe_load(render("scanner.json.j2"))  # JSON is YAML here
    assert record == {"repository": d["maildivvy_rspamd_repository"], "tag": str(d["maildivvy_rspamd_tag"]),
                      "digest": d["maildivvy_rspamd_digest"]}
    # no timestamp and no reading that moves: a re-run of the step changes nothing.
    # It lives beside certificate.json, outside the scanner's own 0750 directory, which
    # health does not enter.
    assert d["maildivvy_rspamd_record"] == "/etc/maildivvy/scanner.json"


def test_the_host_group_names_the_pinned_images_own_gid():
    programs = yaml.safe_load((ROOT / "ansible" / "roles" / "programs" / "vars" / "main.yml").read_text())
    assert programs["maildivvy_rspamd_gid"] == defaults()["maildivvy_rspamd_gid"] == 11333
    # and the step reads that number out of the image, so a repin that moved it stops
    assert "The pinned image's gid is the one the host group names" in task_text()


# --- what the container may not do -------------------------------------


def test_the_project_publishes_no_container_port_and_takes_no_host_networking():
    rspamd = service()
    assert "ports" not in rspamd and "network_mode" not in rspamd and "expose" not in rspamd
    # ⚠️ The check is on the file too, and not only on the parsed keys: a comment that
    # names the key puts the key in the file, so the words stay out of the template.
    raw = render("compose.yml.j2")
    assert "ports:" not in raw and "network_mode" not in raw and "host" not in raw


def test_the_images_own_healthcheck_is_disabled_because_it_probes_a_port_nothing_binds():
    assert service()["healthcheck"] == {"disable": True}


def test_the_container_drops_every_capability_and_can_gain_none():
    """The runtime's default capabilities were kept, and no-new-privileges was off."""
    rspamd = service()
    assert rspamd["cap_drop"] == ["ALL"]
    assert rspamd["security_opt"] == ["no-new-privileges:true"]
    assert "cap_add" not in rspamd and "privileged" not in rspamd


def test_the_container_is_read_only_with_tmp_on_tmpfs_and_a_state_directory_of_its_own():
    rspamd = service()
    assert rspamd["read_only"] is True
    assert rspamd["tmpfs"] == ["/tmp"]
    state = defaults()["maildivvy_rspamd_state"]
    assert f"{state}:/var/lib/rspamd" in rspamd["volumes"]
    # the host directory is the image's own uid's, or rspamd cannot write it
    made = next(t for t in tasks() if t["name"].startswith("Make the state directory"))
    assert made["ansible.builtin.file"]["owner"] == "{{ maildivvy_rspamd_gid }}"


def test_the_scanners_log_leaves_the_container_for_the_hosts_journal():
    logging = service()["logging"]
    assert logging["driver"] == "journald"
    assert logging["options"]["tag"] == defaults()["maildivvy_rspamd_log_tag"]
    # rspamd writes to its own stdout, which is what the driver forwards
    assert 'type = "console";' in render("local.d/logging.inc.j2")


# --- the override tree and the rule beside it -------------------------------


def test_the_override_tree_is_mounted_read_only_and_nothing_is_mounted_under_it():
    mounts = [v.split(":") for v in service()["volumes"]]
    tree = defaults()["maildivvy_rspamd_dir"] + "/local.d"
    assert [f"{tree}", "/etc/rspamd/local.d", "ro"] in mounts
    # a second mount inside it fails `mkdirat …: read-only file system`
    assert [m for m in mounts if m[1].startswith("/etc/rspamd/local.d/")] == []


def test_the_mounted_tree_is_the_image_gids_to_read_and_nobodys_else():
    """⚠️ A bind mount source keeps its own permissions inside the container: `0750
    root:root` reads as `Permission denied` there, rspamd falls back to its built-in
    defaults - `*:11333`, `reject = 15`, every module on - and says nothing about it."""
    written = next(t for t in tasks() if t["name"].startswith("Write the project"))["ansible.builtin.template"]
    assert written["group"] == "{{ maildivvy_rspamd_group }}" and written["mode"] == "0640"
    tree = next(t for t in tasks() if t["name"].startswith("The override tree"))["ansible.builtin.file"]
    assert tree["group"] == "{{ maildivvy_rspamd_group }}" and tree["mode"] == "0750"
    assert defaults()["maildivvy_rspamd_group"] == "maildivvy-rspamd"


def test_the_sender_rule_is_mounted_at_the_one_path_rspamd_loads_outside_the_tree():
    mounts = [v.split(":") for v in service()["volumes"]]
    rule = defaults()["maildivvy_rspamd_dir"] + "/rspamd.local.lua"
    assert [rule, "/etc/rspamd/rspamd.local.lua", "ro"] in mounts
    # ⛔ A missing mount is silent: the image starts clean and scores every message
    # against the provider's POP3 server. The step reads the container's mounts back.
    assert "Mounts" in task_text()


# --- the workers ------------------------------------------------------------


def test_the_normal_worker_binds_one_unix_socket_by_the_images_user_name():
    bind = render("local.d/worker-normal.inc.j2")
    assert 'bind_socket = "/run/rspamd/rspamd.sock mode=0660 owner=_rspamd group=_rspamd";' in bind
    # ⚠️ names, never numbers: a numeric id is not resolved, and rspamd restart-loops
    assert "owner=11333" not in bind and "group=11333" not in bind
    assert "*:" not in bind  # no TCP listener of any kind on the normal worker


def test_the_controller_and_the_milter_proxy_workers_run_no_copies():
    assert "count = 0;" in render("local.d/worker-controller.inc.j2")
    # measured 2026-09-20: with the proxy left at its default the container listens on
    # *:11332 and warns that the worker accepts privileged file inputs on a
    # non-loopback listener. Off, the container's namespace has no rspamd listener.
    assert "count = 0;" in render("local.d/worker-proxy.inc.j2")


# --- the bands, and the one value they share with the schema ----


def test_the_reject_band_is_kept_at_a_score_nothing_reaches_rather_than_removed():
    actions = render("local.d/actions.conf.j2")
    assert f"reject = {defaults()['maildivvy_rspamd_reject_score']};" in actions
    assert "add_header = 6;" in actions  # the bands stay as they are; nothing files by them


def test_the_threshold_ceiling_and_the_scanners_top_band_are_one_value():
    """The two cannot drift: the scanner's top score is the ceiling of every threshold."""
    bound = re.search(r"spam_threshold\s+numeric\(6,2\).*?BETWEEN\s+1\.00\s+AND\s+(\d+\.\d\d)",
                      SCHEMA.read_text(), re.S)
    assert bound, "the schema's spam_threshold CHECK was not found"
    assert float(bound.group(1)) == float(scan.TOP_SCORE)
    assert float(defaults()["maildivvy_rspamd_reject_score"]) == float(scan.TOP_SCORE)
    assert str(scan.TOP_SCORE) == "150.00"  # what the interface shows and the journal carries


# --- what is off, and said to be off by name ---------------------------


def test_the_superseded_module_is_turned_off_by_name_in_its_own_file():
    relay = render("local.d/external_relay.conf.j2")
    assert "enabled = false;" in relay
    # the file states the decision where the next reader looks for it, and the step
    # reads it back as a module disabled explicitly, never as an absence
    assert "Modules disabled" in task_text() and "'external_relay' in disabled" in task_text()


def test_bayes_stays_off_while_no_redis_backend_is_given():
    assert "enabled = false;" in render("local.d/classifier-bayes.conf.j2")


def test_dnsbls_are_off_until_a_resolver_that_answers_them_is_chosen():
    assert defaults()["maildivvy_rspamd_rbls"] is False
    assert "enabled = false;" in render("local.d/rbl.conf.j2")
    assert "enabled = false;" not in render("local.d/rbl.conf.j2", maildivvy_rspamd_rbls=True)
    # turning them on is refused while the machine's resolver answers a clean address:
    # through a forwarding resolver every list reads "listed" (127.255.255.254)
    assert "maildivvy_rspamd_rbl_clean_probe" in task_text()
    gate = next(t for t in tasks() if t["name"].startswith("Refuse DNSBLs"))
    assert gate["when"] == "maildivvy_rspamd_rbls | bool"


# --- the sender pin ----------------------------------------------------


def test_no_provider_is_pinned_until_its_chain_has_been_read():
    assert defaults()["maildivvy_rspamd_provider_hosts"] == {}
    rule = render("rspamd.local.lua.j2")
    assert "] = TRUST_LOGIN" not in rule and "] = JUDGE_PROVIDER" not in rule
    # and a policy is one of exactly two, per provider host, never a global default
    listed = render("rspamd.local.lua.j2", maildivvy_rspamd_provider_hosts={
        "mx.example.net": "trust_login", "mail.example.org": "judge_provider"})
    assert "['mx.example.net'] = TRUST_LOGIN" in listed
    assert "['mail.example.org'] = JUDGE_PROVIDER" in listed
    refusal = next(t for t in tasks() if t["name"].startswith("Every provider host"))
    assert "trust_login" in str(refusal) and "judge_provider" in str(refusal)


def test_the_rule_reads_the_provider_header_top_down_and_takes_the_address_from_its_text():
    rule = render("rspamd.local.lua.j2")
    assert "task:get_header_full('Received')" in rule
    # by the host the header names after `by`, and never by the hop's position
    assert "%sby%s+" in rule
    assert "PROVIDER_HOSTS[by:lower()]" in rule
    # the literal comes out of the header's text, not out of rspamd's parsed table
    assert "task:get_received_headers" not in rule
    body = rule.split("local function pin_sender", 1)[1]
    keep_looking = body.split("if literal then", 1)[0]
    assert "return" not in keep_looking  # a provider header with no address: keep looking below it
    # a submission is not a delivery, and what one means is per provider
    assert "local submission = text:match" in rule
    assert "policy == JUDGE_PROVIDER" in rule and "task:set_user(" in rule
    assert "sender not pinned" in rule  # a provider that is not listed says so in the log


# --- Docker itself ----------------------------------------------------------


def test_the_container_is_named_project_service_number():
    d = defaults()
    assert compose()["name"] == d["maildivvy_rspamd_project"]
    assert d["maildivvy_rspamd_container"] == f"{d['maildivvy_rspamd_project']}-rspamd-1"


def test_the_runtime_comes_from_the_distribution_and_is_read_for_a_tcp_api():
    assert defaults()["maildivvy_docker_packages"] == ["docker.io", "docker-compose-v2"]
    assert "2375" in task_text() and "2376" in task_text()


@pytest.mark.parametrize("name", ["compose.yml.j2", "env.j2", "scanner.json.j2", "rspamd.local.lua.j2",
                                  "local.d/actions.conf.j2", "local.d/worker-normal.inc.j2"])
def test_every_template_renders_with_the_roles_own_defaults(name):
    assert render(name).strip()
