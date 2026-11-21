"""The rule that restarts a daemon whose configuration is newer than its last read of it.

A run stopped between writing a daemon's files and restarting it leaves the files as the
step writes them and the daemon on the old ones: a restart decided by "this run wrote"
never comes. The restart on the machine, after a leftover of that kind, is proved on the
test VM; what is proved here is the comparison, and that the four daemons' roles restart
on it.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from maildivvy_stale import stale

ROLES = Path(__file__).resolve().parents[2] / "ansible" / "roles"
STARTED = 1_768_464_000.25                  # the daemon's last read, in the past: a removal is now


def answers(unit="", container="", journal=""):
    """A `run` that answers systemctl, docker and journalctl as a machine would."""
    def run(argv, **_):
        out = {"systemctl": unit, "docker": container, "journalctl": journal}[argv[0]]
        return subprocess.CompletedProcess(argv, 0 if out else 1, stdout=out + "\n" if out else "", stderr="")
    return run


UNIT = answers(unit="Thu 2026-01-15 08:00:00.250000 UTC")      # STARTED, as systemctl prints it


def configuration(tmp_path, *mtimes):
    paths = []
    for n, mtime in enumerate(mtimes):
        path = tmp_path / f"{n}.conf"
        path.write_text("x\n")
        os.utime(path, (mtime, mtime))
        paths.append(str(path))
    return paths


def test_a_file_written_after_the_daemon_started_makes_it_stale_and_none_does_not(tmp_path):
    older, newer = configuration(tmp_path, STARTED - 60, STARTED + 1)
    assert stale([older], unit="dovecot", run=UNIT) == {"stale": False, "newer": [], "loaded": STARTED}
    # the weekday is the machine's language's
    assert stale([older], unit="dovecot", run=answers(unit="Чт 2026-01-15 08:00:00.250000 UTC"))["loaded"] == STARTED
    assert stale([older, newer], unit="dovecot", run=UNIT)["newer"] == [newer]
    assert stale([older, newer], unit="dovecot", run=UNIT)["stale"] is True
    # the comparison is to the microsecond: a write in the same second, before the start, is not newer
    (tmp_path / "same").mkdir()
    same_second = configuration(tmp_path / "same", STARTED - 0.1)
    assert stale(same_second, unit="dovecot", run=UNIT)["stale"] is False


def test_a_daemon_that_never_started_is_stale_and_a_missing_path_is_not_newer(tmp_path):
    (path,) = configuration(tmp_path, STARTED - 60)
    assert stale([path], unit="dovecot", run=answers(unit="n/a"))["stale"] is True
    assert stale([path], container="maildivvy-rspamd-1", run=answers())["stale"] is True
    assert stale([str(tmp_path / "gone.conf")], unit="dovecot", run=UNIT)["stale"] is False


def test_a_directory_counts_with_what_is_in_it_and_a_removed_file_moves_it(tmp_path):
    tree = tmp_path / "local.d"
    (tree / "deep").mkdir(parents=True)
    (tree / "deep" / "rule.conf").write_text("x\n")
    for path in (tree / "deep" / "rule.conf", tree / "deep", tree):
        os.utime(path, (STARTED - 60, STARTED - 60))
    assert stale([str(tree)], unit="nginx.service", run=UNIT)["stale"] is False
    os.utime(tree / "deep" / "rule.conf", (STARTED + 1, STARTED + 1))
    assert stale([str(tree)], unit="nginx.service", run=UNIT)["newer"] == [str(tree / "deep" / "rule.conf")]
    (tree / "deep" / "rule.conf").unlink()                 # a file the step no longer writes, removed
    assert stale([str(tree)], unit="nginx.service", run=UNIT)["newer"] == [str(tree / "deep")]


def test_a_containers_start_is_read_to_the_nanosecond_docker_prints(tmp_path):
    started = answers(container="2026-01-15T08:00:00.250000123Z")
    older, newer = configuration(tmp_path, STARTED - 0.1, STARTED + 0.1)
    assert stale([older], container="maildivvy-rspamd-1", run=started)["stale"] is False
    assert stale([older, newer], container="maildivvy-rspamd-1", run=started)["newer"] == [newer]
    # Docker's zero time is a container created and never started
    assert stale([older], container="c", run=answers(container="0001-01-01T00:00:00Z"))["stale"] is True


def test_a_reload_the_daemon_logged_after_the_write_is_a_read_of_it(tmp_path):
    # Postfix: step 14 edits master.cf on every run and reloads after; its start alone would
    # read that as stale and step 9 would restart Postfix on every run
    (written,) = configuration(tmp_path, STARTED + 30)
    reload = {"identifier": "postfix/master", "match": "^(daemon started|reload) -- "}
    line = json.dumps({"__REALTIME_TIMESTAMP": str(int((STARTED + 31) * 1_000_000)), "MESSAGE": "reload -- ..."})
    both = answers(unit="Thu 2026-01-15 08:00:00.250000 UTC", journal=line)
    assert stale([written], unit="postfix", reloaded=reload, run=both) == {
        "stale": False, "newer": [], "loaded": STARTED + 31}
    # no such line in the journal: the start is all there is
    assert stale([written], unit="postfix", reloaded=reload, run=UNIT)["stale"] is True


# --- the four daemons' roles --------------------------------------------------------------------

def tasks(entries):
    for task in entries:
        yield task
        for part in ("block", "rescue", "always"):
            yield from tasks(task.get(part) or [])


def role_tasks(role):
    return list(tasks(yaml.safe_load((ROLES / role / "tasks" / "main.yml").read_text())))


# role: the name of the task that restarts (or recreates) its daemon
RESTARTS = {
    "dovecot": "Restart Dovecot for the new configuration",
    "postfix": "Restart Postfix for the new configuration",
    "rspamd": "Start the scanner, recreating it for a changed pin or a changed override tree",
    "interface": "Restart the proxy onto the new site",
}


# role: the task that restarts its own long-running program, which holds the code it
# imported at start (the timers' programs read new code at their next run)
CODE_RESTARTS = {
    "milter": "Restart the daemon for a unit or code that changed",
    "interface": "Restart the interface for a unit or code that changed",
}


def stale_check(found, restart):
    """The one maildivvy_stale task whose result the restart reads, and the restart's place."""
    names = [task.get("name") for task in found]
    checks = [task for task in found
              if "maildivvy_stale" in task and f"{task['register']}.stale" in restart["when"]]
    assert len(checks) == 1
    assert names.index(checks[0]["name"]) < names.index(restart["name"])
    return checks[0]["maildivvy_stale"]


@pytest.mark.parametrize("role", sorted(RESTARTS))
def test_each_daemon_is_restarted_when_its_configuration_is_newer_than_it(role):
    found = role_tasks(role)
    restart = next(task for task in found if task.get("name") == RESTARTS[role])
    stale_check(found, restart)
    # nothing else of this run's own writes decides it: a stopped run's write is as good
    assert " is changed" not in restart["when"] and "_written.changed" not in restart["when"]


@pytest.mark.parametrize("role", sorted(CODE_RESTARTS))
def test_our_long_running_programs_are_restarted_when_the_code_is_newer_than_them(role):
    found = role_tasks(role)
    restart = next(task for task in found if task.get("name") == CODE_RESTARTS[role])
    check = stale_check(found, restart)
    assert check["unit"] == restart["ansible.builtin.systemd_service"]["name"]
    assert "{{ maildivvy_opt }}/lib/maildivvy" in check["paths"]
    # the unit file is compared too, so a unit a stopped run wrote restarts it as well
    assert f"/etc/systemd/system/{check['unit']}" in check["paths"]
    assert " is changed" not in restart["when"] and "_written.changed" not in restart["when"]


def systemd(task):
    return task.get("ansible.builtin.systemd_service") or task.get("ansible.builtin.systemd") or {}


def unit_writers():
    """role/file: its tasks, for every tasks file that writes a unit file of ours."""
    found = {f"{path.parts[-3]}/{path.name}": list(tasks(yaml.safe_load(path.read_text()) or []))
             for path in sorted(ROLES.glob("*/tasks/*.yml"))}
    return {name: entries for name, entries in found.items()
            if any(str(task.get(module, {}).get("dest", "")).startswith("/etc/systemd/system/")
                   for task in entries for module in ("ansible.builtin.template", "ansible.builtin.copy"))}


WRITERS = unit_writers()


def test_the_roles_that_write_our_units_are_the_ones_read_below():
    assert {"backup/main.yml", "health/main.yml", "interface/main.yml", "milter/main.yml",
            "programs/units.yml"} <= set(WRITERS)


@pytest.mark.parametrize("writer", sorted(WRITERS))
def test_a_unit_written_and_never_loaded_is_loaded_by_the_next_run(writer):
    # a run stopped between writing a unit and reloading systemd leaves it written and
    # not loaded; the next run finds it written already, so only systemd can say
    found = WRITERS[writer]
    names = [task.get("name") for task in found]
    reads = {task["register"]: names.index(task["name"]) for task in found
             if "NeedDaemonReload" in json.dumps(task.get("ansible.builtin.command", ""))}
    reloads = [task for task in found if systemd(task).get("daemon_reload")]
    assert reloads
    for task in reloads:
        if systemd(task)["daemon_reload"] is True and "when" not in task:
            continue                                    # reloaded on every run
        decided_by = [register for register in reads if register in json.dumps(task)]
        assert decided_by, task["name"]
        assert all(reads[register] < names.index(task["name"]) for register in decided_by)


def test_a_helpers_socket_is_restarted_when_its_unit_is_newer_than_it():
    found = role_tasks("health")
    sockets = next(task for task in found if task.get("name") == "The helpers' sockets listen, and come back at boot")
    check = next(task for task in found
                 if "maildivvy_stale" in task and f"{task['register']}.results" in sockets["loop"])
    assert check["maildivvy_stale"] == {"unit": "{{ item }}", "paths": ["/etc/systemd/system/{{ item }}"]}
    state = systemd(sockets)["state"]
    assert "item.stale" in state and "is changed" not in state and "_written.changed" not in state


def test_dovecots_files_reach_the_live_tree_only_after_doveconf_parsed_them_elsewhere():
    found = role_tasks("dovecot")
    parse = next(i for i, task in enumerate(found)
                 if task.get("ansible.builtin.command", {}).get("argv", [None])[0] == "doveconf")
    assert found[parse]["ansible.builtin.command"]["argv"][1] == "-c"
    live = [i for i, task in enumerate(found)
            for module in ("ansible.builtin.template", "ansible.builtin.copy")
            if str(task.get(module, {}).get("dest", "")).startswith("/etc/dovecot/conf.d/")]
    assert live and min(live) > parse
    assert found[min(live)]["ansible.builtin.copy"]["remote_src"] is True
