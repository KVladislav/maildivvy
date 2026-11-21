"""Install step 14's rollback drill, read from the role: it is run on a submission
service of its own, so a re-run never takes the milter off the live one.

The drill's three readings, and the live service staying bound while the step runs,
are proved on the test VM.
"""

import re
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

from play_vars import play_vars

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "milter"


def variables():
    values = play_vars("maildivvy_opt", "maildivvy_etc", "maildivvy_postfix_queue", "maildivvy_clamav_socket")
    values.update(yaml.safe_load((ROLE / "vars" / "main.yml").read_text()))
    env = Environment(undefined=StrictUndefined)
    for _ in range(4):
        values = yaml.safe_load(env.from_string(yaml.safe_dump(values)).render(values))
    return values


def tasks(entries=None, section="main"):
    """Every task of the role, with the part of a block it sits in."""
    if entries is None:
        entries = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    for task in entries:
        if "block" in task:
            yield from tasks(task["block"], "block")
            yield from tasks(task.get("rescue") or [], "rescue")
            yield from tasks(task.get("always") or [], "always")
        else:
            yield section, task


def argv(task):
    """A command task's arguments as the machine is given them; None for any other task."""
    command = task.get("ansible.builtin.command")
    if not command:
        return None
    # a registered result or a loop item renders empty: only the role's own names matter
    env, values = Environment(), variables()
    return [env.from_string(str(item)).render(values) for item in command["argv"]]


def postconf_overrides():
    """Every `postconf -P` the role runs: (section, task, its last argument)."""
    for section, task in tasks():
        words = argv(task)
        if words and words[0] == "postconf" and "-P" in words and len(words) > 2:
            yield section, task, words[-1]


def test_the_live_submission_service_is_written_once_and_never_cleared():
    # ⛔ the drill used to bind `submissions` to a dead socket, clear it and bind it again
    # on every run: seconds of authenticated submission with no From check and no scan
    values = variables()
    live = values["maildivvy_milter_service"] + "/"
    touching = [(section, task, override) for section, task, override in postconf_overrides()
                if override.startswith(live)]
    assert [override for _, _, override in touching] == [
        f"{live}smtpd_milters={values['maildivvy_milter_binding']}"]
    section, task, _ = touching[0]
    # ⛔ written only when the machine does not already hold it, and whatever the drill did
    assert section == "always"
    assert "maildivvy_milter_bound_to" in task["when"]
    # the module that sets up and removes the drill's service never names the live one
    for _, task in tasks():
        module = task.get("maildivvy_postconf")
        if module and ("services" in module or "absent" in module):
            assert "maildivvy_milter_service" not in yaml.safe_dump(module), task["name"]


def test_the_drill_binds_its_dead_socket_on_a_loopback_service_it_removes_again():
    values = variables()
    drill = values["maildivvy_milter_drill_service"]
    address, port = drill.split("/")[0].rsplit(":", 1)
    assert address == "127.0.0.1" and drill.endswith("/inet")
    assert port == str(values["maildivvy_milter_drill_port"]) and port != "465"
    overrides = [(section, override) for section, _, override in postconf_overrides()
                 if override.startswith(drill + "/")]
    assert ("block", f"{drill}/smtpd_milters={values['maildivvy_milter_nonexistent']}") in overrides
    # the drill's service is gone again whatever happened in the drill
    removed = [task for section, task in tasks() if section == "always"
               and (task.get("maildivvy_postconf") or {}).get("absent")]
    assert len(removed) == 1
    # every reading in the drill is taken on its own service; the live one is only read
    probes = [(section, words) for section, task in tasks()
              if (words := argv(task)) and values["maildivvy_milter_probe_program"] in words]
    drilled = [words for section, words in probes if section == "block"]
    assert len(drilled) == 2
    assert all(words[-2:] == ["127.0.0.1", port] for words in drilled)


def test_the_global_binding_is_read_back_by_whole_line_not_inside_non_smtpd_milters():
    values = variables()
    task = next(task for _, task in tasks()
                if task.get("name") == "Submission names the socket, and the global value is empty")
    env = Environment()
    env.tests["search"] = lambda value, pattern: re.search(pattern, value) is not None

    def holds(main):
        read = {"results": [{"stdout_lines": [f"{values['maildivvy_milter_service']}/smtpd_milters = "
                                              f"{values['maildivvy_milter_binding']}"]},
                            {"stdout_lines": main}]}
        return all(env.compile_expression(that)(**values, maildivvy_milter_read=read)
                   for that in task["ansible.builtin.assert"]["that"])

    main = ["milter_default_action = tempfail", "milter_protocol = 6"]
    assert holds(["smtpd_milters =", "non_smtpd_milters =", *main])     # the control
    assert not holds(["non_smtpd_milters =", *main])                     # contains it, is not it
    assert not holds(["smtpd_milters = unix:/run/other.sock", "non_smtpd_milters =", *main])
