"""Install step 4's load of the container block into the running firewall.

`ufw reload` is a stop and a start, with every policy ACCEPT in between, so the step and
its self-revert load the block's chains the way ufw loads the file, with
`iptables-restore --noflush`; here a stand-in `iptables-restore` records what it is given.
"""

import os
import subprocess
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined


ROLE = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "docker_block"
POOL = "172.16.0.0/12"
UFW_AFTER = """\
*filter
:ufw-after-input - [0:0]
:ufw-after-output - [0:0]
:ufw-after-forward - [0:0]
-A ufw-after-input -p udp --dport 137 -j ufw-skip-to-policy-input
COMMIT
"""


def defaults(after_rules):
    """The role's defaults, each rendered against the others, with after.rules at `after_rules`."""
    env = Environment(undefined=StrictUndefined)
    raw = {**yaml.safe_load((ROLE / "defaults" / "main.yml").read_text()),
           "maildivvy_after_rules": str(after_rules), "maildivvy_container_pool": POOL}
    return {k: env.from_string(v).render(raw) if isinstance(v, str) else v for k, v in raw.items()}


def after_rules_with_block(values):
    block = Environment(undefined=StrictUndefined).from_string(
        (ROLE / "templates" / "docker-user.rules.j2").read_text()).render(values)
    name = values["maildivvy_docker_block"]
    return f"{UFW_AFTER}# BEGIN {name}\n{block}\n# END {name}\n"


def load(tmp_path, text):
    """Run the role's loader on an after.rules holding `text`: the restore's argv and stdin."""
    after = tmp_path / "after.rules"
    values = defaults(after)
    after.write_text(text(values) if callable(text) else text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "iptables-restore"
    fake.write_text(f'#!/bin/sh\necho "$@" > {tmp_path}/argv\ncat > {tmp_path}/stdin\n')
    fake.chmod(0o755)
    subprocess.run(["bash", "-c", f"set -o pipefail\n{values['maildivvy_docker_block_load']}"],
                   env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}, check=True)
    return (tmp_path / "argv").read_text().split(), (tmp_path / "stdin").read_text()


def test_the_block_is_loaded_into_the_running_firewall_without_stopping_it(tmp_path):
    argv, document = load(tmp_path, after_rules_with_block)
    assert argv == ["-w", "--noflush"]
    lines = [line for line in document.splitlines() if line and not line.startswith("#")]
    assert lines[0] == "*filter" and lines[-1] == "COMMIT"
    assert ":DOCKER-USER - [0:0]" in lines and ":maildivvy-docker-deny - [0:0]" in lines
    assert f"-A DOCKER-USER -s {POOL} -j RETURN" in lines
    assert "-A DOCKER-USER -j ufw-user-forward" in lines   # still the jump to ufw's chain
    # declared, the chain would be emptied of the route rules in force: ufw fills it after
    # after.rules at boot, and nothing refills it live
    assert ":ufw-user-forward - [0:0]" not in lines
    assert not any("ufw-after" in line for line in lines)   # ufw's part of the file is not touched


def test_a_file_without_the_block_loads_no_rule(tmp_path):
    # the self-revert of a first install puts back a file without the block
    argv, document = load(tmp_path, UFW_AFTER)
    assert argv == ["-w", "--noflush"] and document == ""


def test_neither_the_step_nor_its_revert_reloads_ufw():
    steps = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    assert "ufw reload" not in str(steps)
    edit = next(t for t in steps if t["name"].startswith("Edit after.rules"))["block"]
    revert = next(t for t in edit if t["name"].startswith("Arm the self-revert"))
    loaded = next(t for t in edit if "{{ maildivvy_docker_block_load }}" in str(t.get("ansible.builtin.shell")))
    assert edit.index(loaded) == len(edit) - 1                  # once the block is written
    restores = revert["ansible.builtin.command"]["argv"][-1]
    copied = restores.index("cp -p {{ maildivvy_after_rules_copy }} {{ maildivvy_after_rules }}")
    assert copied < restores.index("{{ maildivvy_docker_block_load }}")   # the copy, then its block


def reload(tmp_path, chains, jump=False):
    """Run the step's re-load on a kernel holding `chains`: what it printed, and every
    iptables and iptables-restore call it made, in order."""
    tmp_path.mkdir(exist_ok=True)
    after = tmp_path / "after.rules"
    values = defaults(after)
    after.write_text(after_rules_with_block(values))
    steps = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    task = next(t for t in steps if t["name"].startswith("Load the block again"))
    script = Environment(undefined=StrictUndefined).from_string(task["ansible.builtin.shell"]).render(values)
    calls, bin_dir = tmp_path / "calls", tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "iptables").write_text(
        f'#!/bin/sh\necho "iptables $*" >> {calls}\n'
        f'case "$2" in -S) case " {" ".join(chains)} " in *" $3 "*) exit 0;; esac; exit 1;;\n'
        f'-C) exit {0 if jump else 1};; esac\n')
    (bin_dir / "iptables-restore").write_text(f'#!/bin/sh\necho "iptables-restore $*" >> {calls}\ncat > /dev/null\n')
    for tool in bin_dir.iterdir():
        tool.chmod(0o755)
    done = subprocess.run(["bash", "-c", script], env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
                          capture_output=True, text=True, check=True)
    return done.stdout, calls.read_text().splitlines() if calls.exists() else []


def test_a_lost_chain_is_loaded_again_and_reported_without_stopping_the_firewall(tmp_path):
    # before the runtime exists: the block's chains come back, and no FORWARD jump is made
    out, calls = reload(tmp_path / "a", chains=[])
    assert out == "loaded the block again\n"
    assert "iptables-restore -w --noflush" in calls and not any("-I FORWARD" in c for c in calls)
    # with the runtime's chains: its FORWARD jump comes back too, first
    out, calls = reload(tmp_path / "b", chains=["DOCKER"])
    assert out == "loaded the block again\nput the runtime's FORWARD jump back\n"
    assert calls[-1] == "iptables -w -I FORWARD 1 -j DOCKER-USER"
    assert calls.index("iptables-restore -w --noflush") < len(calls) - 1   # the chain exists before the jump
    # one of the two chains lost is enough; a jump still in place is not added twice
    out, calls = reload(tmp_path / "c", chains=["DOCKER", "DOCKER-USER"], jump=True)
    assert out == "loaded the block again\n" and not any("-I FORWARD" in c for c in calls)
    assert not any("ufw" in c for c in calls)   # never a stop and a start


def test_chains_in_place_are_left_alone_and_the_run_reports_nothing(tmp_path):
    out, calls = reload(tmp_path, chains=["DOCKER", "DOCKER-USER", "maildivvy-docker-deny"], jump=True)
    assert out == ""   # the step's changed_when reads this: an unchanged run says ok
    assert not any(c.startswith("iptables-restore") or "-I " in c for c in calls)
