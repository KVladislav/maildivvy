"""The unit templates of install step 13, read locally before any machine is asked.

What the installed units carry is proved on the VM;
what is proved here is the two things a machine cannot say: that a unit ADDED LATER
carries the same set as the ones before it, and that the values written twice - the
cadence as words and as a calendar, the mail disks in the role and in the library -
still agree. Both are drift, and both are silent at runtime.
"""

import re
from pathlib import Path

import pytest
import yaml

from maildivvy.backup import run as backup_run
from maildivvy.backup import status as backup_status
from maildivvy.health import settings as health_settings
from maildivvy.lib import store

ROLES = Path(__file__).resolve().parents[2] / "ansible" / "roles"
PROGRAMS, MILTER, INTERFACE = ROLES / "programs", ROLES / "milter", ROLES / "interface"
BACKUP = ROLES / "backup"
HEALTH = ROLES / "health"

# Every hardening line one set. The mask is per unit: the milter's socket
# needs its group, so it is 0007 there and 0077 everywhere else.
HARDENING = ("ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true",
             "NoNewPrivileges=true", "CapabilityBoundingSet=", "RestrictSUIDSGID=true",
             "LockPersonality=true", "MemoryDenyWriteExecute=true",
             "SystemCallArchitectures=native")

# The address families are per unit: what the program and its children open, and nothing
# more. The milter, the interface and the backup reach the database, clamd, their own
# socket and systemd over unix sockets only, the store helper runs doveadm on local
# files, and the ledger's daily pass asks the store helper on its socket; `ss` and
# iptables read the kernel over netlink.
IP = "AF_UNIX AF_INET AF_INET6"
FAMILIES = {"maildivvy-milter.service.j2": "AF_UNIX",
            "maildivvy-admin.service.j2": "AF_UNIX",
            "maildivvy-backup.service.j2": "AF_UNIX",
            "maildivvy-health-store@.service.j2": "AF_UNIX",
            "maildivvy-health.service.j2": f"{IP} AF_NETLINK",
            "maildivvy-health-ledger.service.j2": "AF_UNIX",
            "maildivvy-health-system@.service.j2": f"{IP} AF_NETLINK"}

SPAN = {"s": 1, "min": 60, "h": 3600}


def service_templates():
    """Every program unit of ours, whichever role installs it."""
    return sorted(list(PROGRAMS.glob("templates/*.service.j2"))
                  + list(MILTER.glob("templates/*.service.j2"))
                  + list(INTERFACE.glob("templates/*.service.j2"))
                  + list(BACKUP.glob("templates/*.service.j2"))
                  + list(HEALTH.glob("templates/*.service.j2")))


def timer_templates():
    return sorted(list(PROGRAMS.glob("templates/*.timer.j2"))
                  + list(BACKUP.glob("templates/*.timer.j2"))
                  + list(HEALTH.glob("templates/*.timer.j2")))


def role_vars(role=PROGRAMS):
    return yaml.safe_load((role / "vars" / "main.yml").read_text())


def role_defaults(role=PROGRAMS):
    return yaml.safe_load((role / "defaults" / "main.yml").read_text())


def seconds(value):
    number, suffix = re.fullmatch(r"(\d+)([a-z]+)", value).groups()
    return int(number) * SPAN[suffix]


def minutes_of(calendar):
    """The period of `*:0/<n>`, the only calendar shape the timers here use."""
    return int(re.fullmatch(r"\*:0/(\d+)", calendar).group(1)) * 60


@pytest.mark.parametrize("template", service_templates(), ids=lambda p: p.name)
def test_every_program_unit_carries_the_whole_hardening_set(template):
    text = template.read_text()
    assert [line for line in HARDENING if line not in text] == []
    assert re.search(r"^UMask=00(77|07)$", text, re.MULTILINE), "a mask, and it is 0077 or 0007"
    assert re.search(r"^ReadWritePaths=", text, re.MULTILINE), \
        "strict with no list at all is a unit that writes nothing; say so explicitly"


@pytest.mark.parametrize("template", service_templates(), ids=lambda p: p.name)
def test_every_program_unit_allows_only_the_address_families_it_opens(template):
    stated = re.findall(r"^RestrictAddressFamilies=(.*)$", template.read_text(), re.MULTILINE)
    assert stated == [FAMILIES.get(template.name, IP)]


@pytest.mark.parametrize("name, fetch_state", [("maildivvy-fetch.service", True),
                                               ("maildivvy-requests.service", True),
                                               ("maildivvy-pass.service", False)])
def test_the_pipeline_units_name_the_mail_disks_the_library_uses(name, fetch_state):
    """The fetch runner's state is written by the fetch and by the unit a refetch runs
    it in; the pass runs no fetch any more and does not write it."""
    values = role_vars()
    assert values["maildivvy_store"] == str(store.STORE_ROOT)
    assert values["maildivvy_index"] == str(store.INDEX_ROOT)
    text = (PROGRAMS / "templates" / f"{name}.j2").read_text()
    line = [one for one in text.splitlines() if one.startswith("ReadWritePaths=")][0]
    written = set(re.findall(r"\{\{ *(\w+) *\}\}(\S*)", line.removeprefix("ReadWritePaths=")))
    assert written == {("maildivvy_store", ""), ("maildivvy_index", "")} | (
        {("maildivvy_var", "/fetch")} if fetch_state else set()), name


def test_the_snapshot_unit_writes_the_snapshots_root_alone_and_runs_every_ten_minutes():
    """A slice copies a provider's mailbox into the store's `_snapshots` and writes nothing
    else: no delivery, no index, no fetch state. Its root is the library's, made by the role."""
    values = role_vars()
    assert values["maildivvy_snapshots"] == str(store.SNAPSHOT_ROOT)
    assert store.SNAPSHOT_ROOT.parent == store.STORE_ROOT
    text = (PROGRAMS / "templates" / "maildivvy-snapshot.service.j2").read_text()
    assert re.findall(r"^ReadWritePaths=(.*)$", text, re.MULTILINE) == ["{{ maildivvy_snapshots }}"]
    assert re.findall(r"^ExecStart=(.*)$", text, re.MULTILINE) == [
        "{{ maildivvy_opt }}/bin/maildivvy-fetch --snapshot"]
    assert "User=vmail" in text and "Type=oneshot" in text
    assert re.findall(r"^TimeoutStartSec=(.*)$", text, re.MULTILINE) == [
        "{{ maildivvy_snapshot_run_timeout }}"]
    # wider than the run's own bound: a run starts no slice that could end past it, so
    # systemd never stops one mid-slice
    from maildivvy.fetch import runner
    assert values["maildivvy_snapshot_run_timeout"] >= runner.SNAPSHOT_RUN_SECONDS + 120
    # and so is the fetch's: a run starts no collection that could end past it
    assert values["maildivvy_fetch_run_timeout"] >= runner.FETCH_RUN_SECONDS + 120
    timer = (PROGRAMS / "templates" / "maildivvy-snapshot.timer.j2").read_text()
    assert minutes_of(timer_line(timer, "OnCalendar")) == 600
    assert timer_line(timer, "Unit") == "maildivvy-snapshot.service"
    units = {u["src"]: u for u in values["maildivvy_program_units"]}
    assert units["maildivvy-snapshot.timer.j2"]["enabled"] is True
    assert "enabled" not in units["maildivvy-snapshot.service.j2"]
    # made before the unit first starts, the mail owner's and no one else's
    tasks = yaml.safe_load((PROGRAMS / "tasks" / "main.yml").read_text())
    (made,) = [task["ansible.builtin.file"] for task in tasks
               if task.get("ansible.builtin.file", {}).get("path") == "{{ maildivvy_snapshots }}"]
    assert made == {"path": "{{ maildivvy_snapshots }}", "state": "directory", "owner": "vmail",
                    "group": "vmail", "mode": "0700"}


def test_the_imports_staging_directory_is_the_librarys_beside_the_snapshots_made_by_the_role():
    """Staged on the store's filesystem in either disk layout, so a file is renamed into the
    store, never copied; the mail owner's alone, as the import runs as the mail owner."""
    values = role_vars()
    assert values["maildivvy_imports"] == str(store.IMPORTS_ROOT)
    assert store.IMPORTS_ROOT.parent == store.STORE_ROOT == store.SNAPSHOT_ROOT.parent
    tasks = yaml.safe_load((PROGRAMS / "tasks" / "main.yml").read_text())
    (made,) = [task["ansible.builtin.file"] for task in tasks
               if task.get("ansible.builtin.file", {}).get("path") == "{{ maildivvy_imports }}"]
    assert made == {"path": "{{ maildivvy_imports }}", "state": "directory", "owner": "vmail",
                    "group": "vmail", "mode": "0700"}
    # no unit or timer runs the import: the operator does
    assert not any("import" in unit["src"] for unit in values["maildivvy_program_units"])


@pytest.mark.parametrize("name", ["fetch", "pass", "requests", "snapshot"])
def test_every_unit_the_pause_waits_for_refuses_to_start_under_either_record(name):
    from maildivvy.backup import pause
    from maildivvy.installer import upgrade
    assert f"maildivvy-{name}.service" in pause.SERVICES
    variables = yaml.safe_load((PROGRAMS / "vars" / "main.yml").read_text())
    assert variables["maildivvy_upgrade_pause_record"] == str(upgrade.PAUSE_RECORD)
    assert variables["maildivvy_backup_pause_record"] == str(backup_status.STATUS.parent / backup_run.PAUSED)
    unit = (PROGRAMS / "templates" / f"maildivvy-{name}.service.j2").read_text()
    section = unit.split("[Unit]", 1)[1].split("[Service]", 1)[0]
    assert re.findall(r"^ConditionPathExists=(.*)$", section, re.MULTILINE) == [
        "!{{ maildivvy_upgrade_pause_record }}", "!{{ maildivvy_backup_pause_record }}"]


def test_step_13_starts_no_timer_while_a_backups_pause_is_recorded():
    tasks = yaml.safe_load((PROGRAMS / "tasks" / "units.yml").read_text())
    names = [task["name"] for task in tasks]
    read = tasks[names.index("Read whether a backup's or a restore's pause is recorded")]
    assert read["ansible.builtin.stat"]["path"] == "{{ maildivvy_backup_pause_record }}"
    start = tasks[names.index("Enable and start the units that run")]
    assert names.index(read["name"]) < names.index(start["name"])
    assert "maildivvy_backup_pause.stat.exists" in start["ansible.builtin.systemd_service"]["state"]


def test_every_pass_starts_the_requests_unit_beside_it_which_has_no_timer_of_its_own():
    passes = (PROGRAMS / "templates" / "maildivvy-pass.service.j2").read_text()
    wants = re.findall(r"^Wants=(.*)$", passes, re.MULTILINE)
    assert wants == ["network-online.target maildivvy-requests.service"]
    # never ordered after it: the pass must not wait for a refetch
    assert "maildivvy-requests" not in "".join(re.findall(r"^After=(.*)$", passes, re.MULTILINE))
    text = (PROGRAMS / "templates" / "maildivvy-requests.service.j2").read_text()
    assert "ExecStart={{ maildivvy_opt }}/bin/maildivvy-pass --provider-requests" in text
    assert "User=vmail" in text and "Type=oneshot" in text
    units = {u["src"]: u for u in role_vars()["maildivvy_program_units"]}
    assert "enabled" not in units["maildivvy-requests.service.j2"]
    assert not (PROGRAMS / "templates" / "maildivvy-requests.timer.j2").exists()


@pytest.mark.parametrize("template", timer_templates(), ids=lambda p: p.name)
def test_every_timer_says_whether_it_catches_up_and_how_accurate_it_is(template):
    text = template.read_text()
    assert re.search(r"^Persistent=(true|false)$", text, re.MULTILINE), template.name
    assert "AccuracySec=10s" in text
    assert re.search(r"^OnCalendar=", text, re.MULTILINE), \
        "Persistent= has an effect on a calendar timer and on nothing else"


def fetch_timer(minutes):
    """The fetch timer as the role renders it with `maildivvy_fetch_minutes` set to `minutes`."""
    import jinja2

    text = (PROGRAMS / "templates" / "maildivvy-fetch.timer.j2").read_text()
    return jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(text).render(
        {**role_vars(), "maildivvy_fetch_minutes": minutes})


def timer_line(text, name):
    (value,) = re.findall(rf"^{name}=(.*)$", text, re.MULTILINE)
    return value


@pytest.mark.parametrize("minutes", [role_defaults()["maildivvy_fetch_minutes"], 1, 5, 60])
def test_the_cadence_written_as_words_and_as_a_calendar_are_the_same_period(minutes):
    # the fetch period is ONE value, and the timer renders both forms from it
    timer = fetch_timer(minutes)
    assert minutes_of(timer_line(timer, "OnCalendar")) == minutes * 60
    assert timer_line(timer, "Description") == f"Maildivvy: collect mail every {minutes} min"
    # the jitter spreads the mailboxes inside the slot; a jitter as wide as the slot
    # would let one run land in the next one, even at the shortest period the role takes
    assert 0 < seconds(timer_line(timer, "RandomizedDelaySec")) <= minutes * 60 / 3
    values = role_vars()
    assert minutes_of(values["maildivvy_pass_calendar"]) == seconds(values["maildivvy_pass_interval"])


def test_the_fetch_period_is_one_role_default_and_nothing_else_spells_it():
    assert role_defaults() == {"maildivvy_fetch_minutes": 3}
    assert not {"maildivvy_fetch_interval", "maildivvy_fetch_calendar"} & set(role_vars())
    tasks = (PROGRAMS / "tasks" / "main.yml").read_text()
    assert "maildivvy_fetch_minutes | int" in tasks  # the role refuses a period it cannot render


def test_the_backup_unit_keeps_one_capability_and_writes_only_where_the_program_does():
    """Root with an empty bounding set cannot read the mail owner's 0700 fetch state, and
    the predecessor's tar failed after the dump was already written. The one
    capability kept is the one that reads; the two writable paths are the program's own."""
    text = (BACKUP / "templates" / "maildivvy-backup.service.j2").read_text()
    assert re.findall(r"^CapabilityBoundingSet=.*$", text, re.MULTILINE) == [
        "CapabilityBoundingSet=CAP_DAC_READ_SEARCH"]
    assert re.findall(r"^User=.*$", text, re.MULTILINE) == ["User=root"]
    values = role_vars(BACKUP)
    assert values["maildivvy_backup_dir"] == str(backup_run.BACKUPS)
    assert values["maildivvy_backup_status_dir"] == str(backup_status.STATUS.parent)
    line = [one for one in text.splitlines() if one.startswith("ReadWritePaths=")][0]
    assert set(re.findall(r"\{\{ *(\w+) *\}\}", line)) == {"maildivvy_backup_dir",
                                                         "maildivvy_backup_status_dir"}


def test_the_backup_runs_daily_with_up_to_an_hour_of_jitter_and_catches_up():
    values = role_vars(BACKUP)
    text = (BACKUP / "templates" / "maildivvy-backup.timer.j2").read_text()
    assert values["maildivvy_backup_calendar"] == "daily"
    assert values["maildivvy_backup_jitter"] == "1h"
    assert "Persistent=true" in text.splitlines()
    assert "RandomizedDelaySec={{ maildivvy_backup_jitter }}" in text.splitlines()


# --- health (install step 17) ---------------------------------------------------------


def unit_lines(template, key):
    return re.findall(rf"^{key}=(.*)$", (HEALTH / "templates" / template).read_text(), re.MULTILINE)


def test_the_health_role_names_the_paths_and_sockets_the_program_reads():
    values = role_vars(HEALTH)
    assert values["maildivvy_health_dir"] == str(health_settings.STATE_DIR)
    assert values["maildivvy_health_report"] == "{{ maildivvy_health_dir }}/health.json"
    assert health_settings.REPORT == health_settings.STATE_DIR / "health.json"
    assert values["maildivvy_health_store_socket"] == str(health_settings.STORE_SOCKET)
    assert values["maildivvy_health_system_socket"] == str(health_settings.SYSTEM_SOCKET)
    # the stale bound is three runs of the timer
    assert minutes_of(values["maildivvy_health_calendar"]) * 3 == \
        health_settings.Settings().stale_minutes * 60


def test_the_health_unit_succeeds_for_every_report_state_and_writes_only_the_report():
    """The exit code is the report's state; the unit fails only when the program cannot run,
    and then no report is written and it goes stale."""
    assert unit_lines("maildivvy-health.service.j2", "SuccessExitStatus") == ["1 2 3"]
    assert unit_lines("maildivvy-health.service.j2", "User") == ["{{ maildivvy_health_user }}"]
    # and the textfile directory when one is set (test_health_prometheus.py renders both)
    assert unit_lines("maildivvy-health.service.j2", "ReadWritePaths") == [
        "{{ maildivvy_health_dir }}{{ (' ' ~ maildivvy_health_textfile_dir) "
        "if maildivvy_health_textfile_dir else '' }}"]
    assert unit_lines("maildivvy-health.service.j2", "CapabilityBoundingSet") == [""]


def test_each_helper_runs_as_the_owner_of_what_it_reads_and_the_system_one_keeps_two_reading_capabilities():
    assert unit_lines("maildivvy-health-store@.service.j2", "User") == ["vmail"]
    assert unit_lines("maildivvy-health-store@.service.j2", "CapabilityBoundingSet") == [""]
    assert unit_lines("maildivvy-health-system@.service.j2", "User") == ["root"]
    assert unit_lines("maildivvy-health-system@.service.j2", "CapabilityBoundingSet") == [
        "CAP_NET_ADMIN CAP_DAC_READ_SEARCH"]
    assert unit_lines("maildivvy-health-system@.service.j2", "ReadWritePaths") == [""]
    for name in ("maildivvy-health-store.socket.j2", "maildivvy-health-system.socket.j2"):
        assert unit_lines(name, "SocketMode") == ["0660"]
        assert unit_lines(name, "SocketGroup") == ["{{ maildivvy_health_user }}"]
        assert unit_lines(name, "Accept") == ["yes"]
