"""The installed version and the upgrade to a release: what the installer finds on
the machine, what it decides to do with this release, and the order an upgrade runs in.

systemctl, the backup's unit, the schema applier and the play are fakes here; the upgrade
of a real first-version machine, a re-run of the same version and an upgrade to a next
version with a migration are proved on the test VM.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from maildivvy.installer import cli, manifest, settings, upgrade
from maildivvy.installer.upgrade import Found

REPO = Path(__file__).resolve().parents[2]
UBUNTU_2604 = 'NAME="Ubuntu"\nVERSION_ID="26.04"\nID=ubuntu\nID_LIKE=debian\n'
TIMERS = ("maildivvy-fetch.timer", "maildivvy-pass.timer")


@pytest.fixture
def log(tmp_path):
    with open(tmp_path / "install.log", "w") as f:
        yield f


@pytest.fixture
def records(tmp_path, monkeypatch):
    """The installer's records under tmp_path: (version file, unfinished record)."""
    etc = tmp_path / "etc"
    etc.mkdir()
    monkeypatch.setattr(upgrade, "VERSION_FILE", etc / "version")
    monkeypatch.setattr(upgrade, "UNFINISHED", etc / "installing")
    monkeypatch.setattr(upgrade, "PAUSE_RECORD", etc / "upgrade-paused.json")
    monkeypatch.setattr(upgrade, "HELD", etc / "upgrade-held")
    monkeypatch.setattr(upgrade, "BACKUPS", tmp_path / "backups")
    return etc / "version", etc / "installing"


# --- versions ---------------------------------------------------------------------


@pytest.mark.parametrize("text, version", [("0.1.0\n", (0, 1, 0)), ("0.12.3", (0, 12, 3)),
                                           ("1.0.0\n", (1, 0, 0))])
def test_a_version_is_three_numbers(text, version):
    assert upgrade.parse_version(text, "VERSION") == version


@pytest.mark.parametrize("text", ["", "0.1", "v0.1.0", "0.1.0-rc1", "01.1.0", "0.1.0\n0.2.0\n", "0.1.0 x"])
def test_anything_else_is_refused_naming_the_file(text):
    with pytest.raises(settings.Refusal, match="VERSION"):
        upgrade.parse_version(text, "VERSION")


def test_the_release_carries_its_version_and_it_is_the_projects():
    version = upgrade.release_version(REPO)
    project = (REPO / "pyproject.toml").read_text()
    assert f'version = "{upgrade.shown(version)}"' in project
    assert (REPO / "VERSION").read_text() == upgrade.shown(version) + "\n"


def test_a_tree_without_a_version_is_not_a_release(tmp_path):
    with pytest.raises(settings.Refusal, match="no VERSION"):
        upgrade.release_version(tmp_path)


# --- what is installed ------------------------------------------------------------


def test_a_machine_with_no_maildivvy_has_nothing_installed(records):
    version, unfinished = records
    found = upgrade.installed(schema=lambda: [])
    assert found == Found()


def test_a_first_version_machine_is_our_schema_without_a_version_file(records):
    version, unfinished = records
    found = upgrade.installed(schema=lambda: ["0001"])
    assert found == Found(first_version=True)


def test_the_version_file_is_what_is_installed(records):
    version, unfinished = records
    version.write_text("0.1.0\n")
    assert upgrade.installed(schema=lambda: pytest.fail("not asked")) == Found(version=(0, 1, 0))


def test_a_first_install_that_did_not_finish_is_installed_again(records):
    """Its record is there, no version: the database it may have made holds no one's mail."""
    version, unfinished = records
    unfinished.write_text("0.1.0\n")
    assert upgrade.installed(schema=lambda: ["0001"]) == Found(unfinished=True)


def test_a_malformed_version_file_is_refused(records):
    version, unfinished = records
    version.write_text("latest\n")
    with pytest.raises(settings.Refusal, match=str(version)):
        upgrade.installed(schema=lambda: [])


def psql(returncode=0, stdout="", stderr=""):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
    return run, calls


def test_the_schema_is_read_as_postgres_from_our_database(tmp_path):
    program = tmp_path / "psql"
    program.write_text("")
    run, calls = psql(stdout="0001\n0002\n")
    assert upgrade.schema_versions(run=run, psql=program) == ["0001", "0002"]
    assert calls[0][:4] == ["runuser", "-u", "postgres", "--"]
    assert "maildivvy" in calls[0] and "SELECT version FROM schema_version ORDER BY version" in calls[0]


@pytest.mark.parametrize("stderr", ['psql: error: FATAL:  database "maildivvy" does not exist',
                                    'ERROR:  relation "schema_version" does not exist',
                                    "runuser: user postgres does not exist"])
def test_no_database_no_table_or_no_postgres_is_no_schema(tmp_path, stderr):
    program = tmp_path / "psql"
    program.write_text("")
    run, _ = psql(returncode=1, stderr=stderr)
    assert upgrade.schema_versions(run=run, psql=program) == []


def test_no_psql_is_no_schema(tmp_path):
    run, calls = psql()
    assert upgrade.schema_versions(run=run, psql=tmp_path / "absent") == []
    assert calls == []


def test_a_database_that_does_not_answer_is_refused_rather_than_taken_as_none(tmp_path):
    program = tmp_path / "psql"
    program.write_text("")
    run, _ = psql(returncode=2, stderr="psql: error: connection to server on socket failed: No such file")
    with pytest.raises(settings.Refusal, match="cannot tell whether Maildivvy is installed"):
        upgrade.schema_versions(run=run, psql=program)


# --- the version rule -------------------------------------------------------------


def test_no_maildivvy_installs():
    plan = upgrade.decide(Found(), (0, 1, 0))
    assert plan.action == "install"
    assert "installing Maildivvy 0.1.0" in plan.says()


def test_an_unfinished_first_install_is_installed_again():
    plan = upgrade.decide(Found(unfinished=True), (0, 1, 0))
    assert plan.action == "install"
    assert "did not finish" in plan.says()


def test_a_first_version_machine_is_upgraded_to_0_1_never_installed_afresh():
    plan = upgrade.decide(Found(first_version=True), (0, 1, 0))
    assert plan.action == "upgrade" and plan.installed is None
    assert "upgrading Maildivvy from before 0.1.0 to 0.1.0" in plan.says()
    assert upgrade.decide(Found(first_version=True), (0, 1, 4)).action == "upgrade"


def test_a_first_version_machine_goes_through_0_1_first():
    with pytest.raises(settings.Refusal, match="before 0.1.0.*0.1 release first"):
        upgrade.decide(Found(first_version=True), (0, 2, 0))


def test_the_same_version_re_proves():
    plan = upgrade.decide(Found(version=(0, 1, 0)), (0, 1, 0))
    assert plan.action == "reprove"
    assert "0.1.0 is installed: every step is run again" in plan.says()


@pytest.mark.parametrize("installed, release", [((0, 1, 0), (0, 2, 0)), ((0, 1, 0), (0, 1, 1)),
                                                ((0, 1, 3), (0, 2, 1)), ((1, 0, 0), (1, 3, 0))])
def test_a_newer_release_upgrades(installed, release):
    plan = upgrade.decide(Found(version=installed), release)
    assert plan.action == "upgrade" and plan.installed == installed and plan.release == release


@pytest.mark.parametrize("installed, release", [((0, 1, 0), (0, 3, 0)), ((0, 1, 0), (1, 0, 0)),
                                                ((1, 2, 0), (2, 0, 0))])
def test_a_jump_past_the_next_minor_in_0_x_or_to_another_major_is_refused(installed, release):
    with pytest.raises(settings.Refusal, match="past"):
        upgrade.decide(Found(version=installed), release)


@pytest.mark.parametrize("installed, release", [((0, 2, 0), (0, 1, 0)), ((0, 1, 1), (0, 1, 0))])
def test_an_older_release_is_refused(installed, release):
    with pytest.raises(settings.Refusal, match="older than"):
        upgrade.decide(Found(version=installed), release)


# --- the upgrade's order ----------------------------------------------------------


class Systemd:
    """The pause's systemctl, recording what it stopped and started."""

    def __init__(self, events, active=TIMERS):
        self.events, self.on = events, set(active)

    def active(self, unit):
        return unit in self.on

    def stop(self, unit):
        self.events.append(f"stop {unit}")
        self.on.discard(unit)

    def start(self, unit):
        self.events.append(f"start {unit}")
        self.on.add(unit)

    def busy_with(self, unit):
        return False


def taken(stamp):
    """A complete run, as maildivvy-backup leaves it."""
    run = upgrade.BACKUPS / stamp
    run.mkdir(parents=True, exist_ok=True)
    (run / "manifest.json").write_text("{}\n")
    return stamp


class Machine:
    """The upgrade's acts, each recorded in order; any of them may fail."""

    def __init__(self, records, log, fail=None, step_code=0, check_code=0, applied=1, active=TIMERS):
        self.events, self.fail, self.step_code, self.check_code, self.applied = [], fail, step_code, check_code, applied
        self.version, _ = records
        self.log, self.said = log, []
        self.systemd = Systemd(self.events, active)

    def backup(self, write, log):
        self.events.append("backup")
        if self.fail == "backup":
            raise upgrade.Failed("maildivvy-backup.service failed: the store copy exited 3")
        return taken("20261001T120000Z")

    def migrate(self, root, write, log):
        self.events.append("migrations")
        if self.fail == "migrations":
            raise upgrade.Failed("0002_new.sql failed and was rolled back: division by zero")
        if self.fail == "crash":
            raise OSError("No space left on device")
        return self.applied

    def steps(self, preflight_only=False):
        self.events.append("step 1" if preflight_only else "steps")
        return self.check_code if preflight_only else self.step_code

    def run(self, plan, **kwargs):
        return upgrade.upgrade(plan, Path("/release"), self.steps, self.said.append, self.log,
                               systemd=self.systemd, sleep=lambda s: None, backup=self.backup,
                               migrate=self.migrate, **kwargs)


PLAN = upgrade.Plan("upgrade", (0, 2, 0), (0, 1, 0))


def test_an_upgrade_checks_pauses_backs_up_migrates_runs_every_step_writes_the_version_then_resumes(records, log):
    machine = Machine(records, log)
    assert machine.run(PLAN) == 0
    assert machine.events == ["step 1", "stop maildivvy-fetch.timer", "stop maildivvy-pass.timer", "backup",
                              "migrations", "steps", "start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert machine.version.read_text() == "0.2.0\n"
    assert "backup 20261001T120000Z taken before the upgrade" in "\n".join(machine.said)
    assert not upgrade.PAUSE_RECORD.exists()


def test_the_version_is_written_before_collection_resumes(records, log, monkeypatch):
    machine = Machine(records, log)
    seen = []
    original = Systemd.start

    def start(self, unit):
        seen.append(machine.version.exists())
        original(self, unit)
    monkeypatch.setattr(Systemd, "start", start)
    machine.run(PLAN)
    assert seen == [True, True]


def test_a_timer_the_operator_had_stopped_stays_stopped(records, log):
    machine = Machine(records, log, active=("maildivvy-pass.timer",))
    machine.run(PLAN)
    assert "start maildivvy-fetch.timer" not in machine.events and "start maildivvy-pass.timer" in machine.events


def test_step_1_refusing_stops_the_upgrade_before_the_pause_and_the_backup(records, log):
    """A typo in the settings, a disk or an expired certificate is found before the new
    migrations could run under the old programs."""
    machine = Machine(records, log, check_code=2)
    assert machine.run(PLAN) == upgrade.FAILED
    assert machine.events == ["step 1"]
    assert not machine.version.exists()
    said = "\n".join(machine.said)
    assert "The upgrade stopped before any change: step 1 refused (exit 2)" in said
    assert "rollback" not in said.lower() and "--restore" not in said


def test_a_failed_backup_stops_the_upgrade_before_any_change(records, log):
    machine = Machine(records, log, fail="backup")
    assert machine.run(PLAN) == upgrade.FAILED
    assert "migrations" not in machine.events and "steps" not in machine.events
    assert not machine.version.exists()
    assert machine.events[-2:] == ["start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    said = "\n".join(machine.said)
    assert "the store copy exited 3" in said
    assert "The upgrade stopped before any change: Maildivvy 0.1.0 is installed as it was." in said
    assert "rollback" not in said.lower()


@pytest.mark.parametrize("fail, step_code, cause", [
    ("migrations", 0, "0002_new.sql failed and was rolled back: division by zero"),
    (None, 2, "an installation step failed (exit 2)"),
    ("crash", 0, "No space left on device")])
def test_a_later_failure_prints_the_backup_stamp_and_the_rollback_steps(records, log, fail, step_code, cause):
    machine = Machine(records, log, fail=fail, step_code=step_code)
    assert machine.run(PLAN) == upgrade.FAILED
    assert not machine.version.exists()
    said = "\n".join(machine.said)
    assert cause in said
    assert "The upgrade to 0.2.0 failed after backup 20261001T120000Z" in said
    assert "maildivvy-backup --restore 20261001T120000Z" in said
    assert "the installer of 0.1.0" in said
    assert "or fix what failed and run this installer again" in said.lower()


@pytest.mark.parametrize("fail, step_code", [("migrations", 0), (None, 2), ("crash", 0)])
def test_after_a_migration_collection_stays_paused_and_recorded_for_the_next_run(records, log, fail, step_code):
    """The database may be ahead of the programs still running: the timers are left stopped,
    and the record names them, so the next run's upgrade starts them once it finishes."""
    machine = Machine(records, log, fail=fail, step_code=step_code)
    machine.run(PLAN)
    assert not any(e.startswith("start ") for e in machine.events)
    assert "Collection and fan-out stay paused" in "\n".join(machine.said)
    assert json.loads(upgrade.PAUSE_RECORD.read_text()) == list(TIMERS)
    again = Machine(records, log, active=())    # the next run: the timers still stopped
    assert again.run(PLAN) == 0
    assert again.events[-2:] == ["start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert not upgrade.PAUSE_RECORD.exists()


class Retried(Machine):
    """The next run after one that failed past its migrations: they are applied already."""

    def backup(self, write, log):
        self.events.append("backup")
        if self.fail == "backup":
            raise upgrade.Failed("maildivvy-backup.service failed: the store copy exited 3")
        return taken("20261002T090000Z")


def failed_past_its_migrations(records, log):
    first = Machine(records, log, step_code=2)
    assert first.run(PLAN) == upgrade.FAILED
    return first


@pytest.mark.parametrize("fail, step_code, check_code", [
    (None, 2, 0), ("migrations", 0, 0), ("backup", 0, 0), (None, 0, 2)])
def test_a_retry_after_a_failure_past_the_migrations_keeps_collection_paused_whatever_fails(
        records, log, fail, step_code, check_code):
    """The retry applies no migration (they are there already), yet the database is still
    ahead of the programs: collection stays paused until an upgrade finishes."""
    failed_past_its_migrations(records, log)
    again = Retried(records, log, fail=fail, step_code=step_code, check_code=check_code, applied=0, active=())
    assert again.run(PLAN) == upgrade.FAILED
    assert not any(e.startswith("start ") for e in again.events)
    assert json.loads(upgrade.PAUSE_RECORD.read_text()) == list(TIMERS)
    assert "Collection and fan-out stay paused" in "\n".join(again.said)


@pytest.mark.parametrize("fail, step_code, check_code", [
    (None, 2, 0), ("migrations", 0, 0), ("backup", 0, 0), (None, 0, 2)])
def test_a_retry_names_the_backup_from_before_the_first_runs_migrations_as_the_way_back(
        records, log, fail, step_code, check_code):
    failed_past_its_migrations(records, log)
    again = Retried(records, log, fail=fail, step_code=step_code, check_code=check_code, applied=0, active=())
    again.run(PLAN)
    said = "\n".join(again.said)
    assert "maildivvy-backup --restore 20261001T120000Z" in said
    assert "--restore 20261002T090000Z" not in said
    assert "before any change" not in said


def test_a_retry_whose_held_run_is_gone_says_there_is_no_way_back_from_it(records, log):
    failed_past_its_migrations(records, log)
    import shutil
    shutil.rmtree(upgrade.BACKUPS / "20261001T120000Z")
    again = Retried(records, log, step_code=2, applied=0, active=())
    again.run(PLAN)
    said = "\n".join(again.said)
    assert f"run 20261001T120000Z is no longer in {upgrade.BACKUPS}" in said
    assert "Collection and fan-out stay paused" in said
    # the control: while the run is there, nothing says it is gone
    present = Retried(records, log, step_code=2, applied=0, active=())
    taken("20261001T120000Z")
    present.run(PLAN)
    assert "no longer in" not in "\n".join(present.said)


CARRY_OVER = upgrade.Plan("upgrade", (0, 1, 0), None)


def test_a_carry_over_keeps_its_held_run_where_the_first_versions_retention_does_not_reach(records, log):
    """Until step 13 installs the new maildivvy-backup, the first version's runs, and its
    retention counts every run: a hard-linked copy under a name no retention counts keeps
    the way back, and the retry says how to put it back."""
    first = Machine(records, log, step_code=2)
    assert first.run(CARRY_OVER) == upgrade.FAILED
    copy = upgrade.BACKUPS / ".held-20261001T120000Z"
    assert (copy / "manifest.json").samefile(upgrade.BACKUPS / "20261001T120000Z" / "manifest.json")
    import shutil
    shutil.rmtree(upgrade.BACKUPS / "20261001T120000Z")     # the first version's retention
    again = Retried(records, log, step_code=2, applied=0, active=())
    again.run(CARRY_OVER)
    said = "\n".join(again.said)
    assert f"sudo cp -al {copy} {upgrade.BACKUPS / '20261001T120000Z'}" in said
    assert "no way back to" not in said and f"sudo rm -rf {copy}" in said
    assert Retried(records, log, applied=0, active=()).run(CARRY_OVER) == 0
    assert not copy.exists()


def test_an_installed_machine_keeps_no_copy_its_backup_keeps_the_held_run(records, log):
    Machine(records, log, step_code=2).run(PLAN)
    assert upgrade.HELD.exists() and not list(upgrade.BACKUPS.glob(".held-*"))


def test_a_carry_over_that_applied_nothing_keeps_no_copy(records, log):
    Machine(records, log, step_code=2, applied=0).run(CARRY_OVER)
    assert not upgrade.HELD.exists() and not list(upgrade.BACKUPS.glob(".held-*"))


def test_a_retry_that_finishes_forgets_the_hold_and_resumes(records, log):
    failed_past_its_migrations(records, log)
    assert upgrade.HELD.exists()
    again = Retried(records, log, applied=0, active=())
    assert again.run(PLAN) == 0
    assert again.events[-2:] == ["start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert not upgrade.HELD.exists() and not upgrade.PAUSE_RECORD.exists()


def test_a_retry_after_a_failure_before_the_migrations_is_not_held(records, log):
    Machine(records, log, fail="backup").run(PLAN)
    again = Retried(records, log, step_code=2, applied=0)
    again.run(PLAN)
    assert again.events[-2:] == ["start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert "--restore 20261002T090000Z" in "\n".join(again.said)
    assert not upgrade.HELD.exists()


def test_a_step_that_fails_after_no_migration_resumes_collection(records, log):
    machine = Machine(records, log, step_code=2, applied=0)
    assert machine.run(PLAN) == upgrade.FAILED
    assert machine.events[-2:] == ["start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert "stay paused" not in "\n".join(machine.said)


def test_an_unexpected_failure_leaves_its_traceback_in_the_log(records, tmp_path):
    with open(tmp_path / "install.log", "w") as log:
        Machine(records, log, fail="crash").run(PLAN)
    assert "OSError: No space left on device" in (tmp_path / "install.log").read_text()


def test_the_rollback_from_before_0_1_0_names_the_first_versions_installation(records, log):
    machine = Machine(records, log, step_code=2)
    machine.run(upgrade.Plan("upgrade", (0, 1, 0), None))
    said = "\n".join(machine.said)
    assert "maildivvy-backup --restore 20261001T120000Z" in said
    assert "control machine" in said


def test_without_a_store_copy_the_upgrade_warns_and_the_way_back_says_whose_copy(records, log):
    machine = Machine(records, log, step_code=2)
    machine.run(PLAN, store_copy=False)
    said = "\n".join(machine.said)
    assert machine.said[0].startswith("warning: maildivvy_backup_store_copy is not set")
    assert "the store from your own copy of it" in said and "the copy that run made" not in said


def test_health_reads_the_pause_record_the_upgrade_writes():
    from maildivvy.health import data
    assert data.UPGRADE_PAUSE == upgrade.PAUSE_RECORD


def test_the_version_file_is_0644_and_the_unfinished_record_goes(records):
    version, unfinished = records
    upgrade.mark_unfinished((0, 1, 0))
    assert unfinished.read_text() == "0.1.0\n"
    upgrade.write_version((0, 1, 0))
    assert version.read_text() == "0.1.0\n" and oct(version.stat().st_mode & 0o777) == "0o644"
    assert not unfinished.exists()


# --- the backup and the migrations ------------------------------------------------


class Recorder:
    def __init__(self, answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        code, out = self.answers.pop(0) if self.answers else (0, "")
        return subprocess.CompletedProcess(argv, code, out, "")


def status_file(tmp_path, stamp):
    path = tmp_path / "status.json"
    path.write_text(json.dumps({"stamp": stamp, "store_copy": "none configured"}))
    return path


def test_the_backup_is_the_backup_units_run_and_its_stamp_a_new_one(tmp_path, log):
    path = status_file(tmp_path, "20260930T010000Z")
    run = Recorder([])

    def start(argv, **kwargs):
        run(argv)
        if argv[:2] == ["systemctl", "start"]:
            path.write_text(json.dumps({"stamp": "20261001T120000Z", "store_copy": "ok"}))
        return subprocess.CompletedProcess(argv, 0, "", "")
    said = []
    assert upgrade.take_backup(said.append, log, run=start, status_path=path) == "20261001T120000Z"
    assert ["systemctl", "start", "maildivvy-backup.service"] in run.calls


def test_a_backup_unit_that_fails_fails_the_backup_with_its_last_line(tmp_path, log):
    path = status_file(tmp_path, "20260930T010000Z")
    run = Recorder([(1, ""), (0, "backup 20261001T120000Z: 20 tables\nmaildivvy-backup: the store copy exited 3\n")])
    with pytest.raises(upgrade.Failed, match="the store copy exited 3"):
        upgrade.take_backup(lambda line: None, log, run=run, status_path=path)


def test_a_backup_that_left_no_new_run_is_no_backup(tmp_path, log):
    path = status_file(tmp_path, "20260930T010000Z")
    with pytest.raises(upgrade.Failed, match="no new run"):
        upgrade.take_backup(lambda line: None, log, run=Recorder([]), status_path=path)


def test_the_migrations_are_the_releases_applied_by_its_own_applier(tmp_path, log):
    run = Recorder([(0, "applied 0002_new.sql\n")])
    said = []
    assert upgrade.apply_migrations(Path("/release"), said.append, log, run=run) == 1
    assert run.calls == [["/usr/bin/python3", "/release/bin/maildivvy-schema", "--dir", "/release/schema"]]
    assert "  applied 0002_new.sql" in said


def test_a_migration_that_fails_is_a_failure_with_the_appliers_words(tmp_path, log):
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "maildivvy-schema: 0002_new.sql failed and was rolled back\n")
    with pytest.raises(upgrade.Failed, match="0002_new.sql failed and was rolled back"):
        upgrade.apply_migrations(Path("/release"), lambda line: None, log, run=run)


# --- the installer's run ----------------------------------------------------------


def release(tmp_path, version="0.2.0"):
    root = tmp_path / "release"
    (root / "ansible").mkdir(parents=True)
    (root / "maildivvy-install").write_text("#!/usr/bin/python3\n")
    (root / "VERSION").write_text(version + "\n")
    manifest.write(root)
    return root


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "read_os_release", lambda: UBUNTU_2604)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    acted = []
    monkeypatch.setattr(cli, "prepare_log", lambda: (tmp_path / "log", open(tmp_path / "log", "w")))
    monkeypatch.setattr(cli, "install_ansible", lambda log, write: acted.append("ansible"))
    monkeypatch.setattr(cli, "load_or_ask", lambda *a: (acted.append("settings") or ({}, {})))
    return acted


def test_an_older_release_is_refused_before_anything_changes(tmp_path, monkeypatch, machine):
    root = release(tmp_path, "0.1.0")
    monkeypatch.setattr(upgrade, "installed", lambda: Found(version=(0, 2, 0)))
    out = []
    assert cli.main([], root=root, write=out.append) == cli.REFUSED
    assert machine == []
    text = "\n".join(out)
    assert "refused: this release, 0.1.0, is older than the installed 0.2.0" in text
    assert "nothing was changed" in text


def test_a_release_without_its_version_is_refused(tmp_path, machine):
    root = release(tmp_path)
    (root / "VERSION").unlink()
    manifest.write(root)
    out = []
    assert cli.main([], root=root, write=out.append) == cli.REFUSED
    assert "refused: no VERSION" in "\n".join(out) and machine == []


def test_each_plan_takes_its_own_path_through_the_run(tmp_path, monkeypatch, machine):
    root = release(tmp_path)
    taken = []
    monkeypatch.setattr(cli, "run_install", lambda root, args, values, secrets, log, log_path, write, plan:
                        taken.append(plan.action) or 0)
    for found, action in ((Found(), "install"), (Found(version=(0, 2, 0)), "reprove"),
                          (Found(version=(0, 1, 0)), "upgrade")):
        monkeypatch.setattr(upgrade, "installed", lambda found=found: found)
        out = []
        assert cli.main([], root=root, write=out.append) == 0
    assert taken == ["install", "reprove", "upgrade"]


def test_an_apt_get_that_keeps_failing_is_a_failure_not_a_refusal(tmp_path, monkeypatch, machine):
    root = release(tmp_path)
    monkeypatch.setattr(upgrade, "installed", lambda: Found())

    def failing(log, write):
        raise upgrade.Failed("apt-get -q update failed 3 times; its output is in the log")
    monkeypatch.setattr(cli, "install_ansible", failing)
    out = []
    assert cli.main([], root=root, write=out.append) == cli.FAILED
    text = "\n".join(out)
    assert "failed: apt-get -q update failed 3 times" in text and "refused" not in text
    assert machine == []   # no settings asked for


def test_a_first_install_is_recorded_as_unfinished_until_its_steps_pass(records, log, monkeypatch):
    version, unfinished = records
    seen = []

    def steps(preflight_only=False):
        seen.append((unfinished.read_text(), version.exists()))
        return 0
    out = []
    assert cli.finish(upgrade.Plan("install", (0, 1, 0), None), Path("/release"), steps, out.append,
                      log) == 0
    assert seen == [("0.1.0\n", False)]
    assert version.read_text() == "0.1.0\n" and not unfinished.exists()


def test_a_first_install_that_fails_writes_no_version(records, log, monkeypatch):
    version, unfinished = records
    assert cli.finish(upgrade.Plan("install", (0, 1, 0), None), Path("/release"), lambda: 2, lambda line: None,
                      log) == cli.FAILED
    assert not version.exists() and unfinished.exists()


@pytest.mark.parametrize("action, installed", [("reprove", (0, 1, 0)), ("install", None)])
def test_an_installer_run_that_finishes_removes_a_failed_upgrades_records(records, log, action, installed):
    """The way back from a failed upgrade ends in the old version's installer: its step 13
    starts the timers, so the upgrade's pause record must not outlive it and read, in
    health, as a pause no one is holding."""
    upgrade.PAUSE_RECORD.write_text(json.dumps(list(TIMERS)))
    upgrade.HELD.write_text("20261001T120000Z\n")
    assert cli.finish(upgrade.Plan(action, (0, 1, 0), installed), Path("/release"), lambda: 0,
                      lambda line: None, log) == 0
    assert not upgrade.PAUSE_RECORD.exists() and not upgrade.HELD.exists()


def test_an_installer_run_that_fails_keeps_a_failed_upgrades_records(records, log):
    upgrade.PAUSE_RECORD.write_text(json.dumps(list(TIMERS)))
    upgrade.HELD.write_text("20261001T120000Z\n")
    assert cli.finish(upgrade.Plan("reprove", (0, 1, 0), (0, 1, 0)), Path("/release"), lambda: 2,
                      lambda line: None, log) == cli.FAILED
    assert upgrade.PAUSE_RECORD.exists() and upgrade.HELD.exists()


def test_the_rollback_says_the_old_versions_run_removes_the_upgrades_records(records, log):
    machine = Machine(records, log, step_code=2)
    machine.run(PLAN)
    assert "removes the upgrade's records" in "\n".join(machine.said)
    before = Machine(records, log, step_code=2)
    before.run(upgrade.Plan("upgrade", (0, 1, 0), None))
    said = "\n".join(before.said)
    assert f"rm -f {upgrade.PAUSE_RECORD} {upgrade.HELD}" in said


def test_a_re_run_of_the_same_version_takes_no_backup(records, log, monkeypatch):
    version, unfinished = records
    version.write_text("0.1.0\n")
    monkeypatch.setattr(upgrade, "upgrade", lambda *a, **k: pytest.fail("a re-run is no upgrade"))
    assert cli.finish(upgrade.Plan("reprove", (0, 1, 0), (0, 1, 0)), Path("/release"), lambda: 0,
                      lambda line: None, log) == 0
    assert version.read_text() == "0.1.0\n" and not unfinished.exists()
