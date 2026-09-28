"""The backup's own decisions, kept in plain functions: names, retention, judging a dump
and the fetch state by what they hold, the pause around them, and the order of a run.

The real pg_dump, pg_restore, systemd and the unit's sandbox are driven on the test VM;
here each of them is a recorder, so what is proved
is the logic between them.
"""

import datetime
import hashlib
import io
import json
import os
import stat
import tarfile

import pytest

from maildivvy.backup import archive, pause, run, status

UTC = datetime.timezone.utc

# What pg_restore --list printed for the installed schema (measured on the test VM,
# PostgreSQL 18.6): a TABLE line per table, and TABLE DATA and ACL lines that are not.
LISTING = """\
;
; Archive created at 2026-09-23 09:30:00 UTC
;
3726; 0 0 ACL public FUNCTION check_grants() maildivvy_owner
225; 1259 16480 TABLE public account maildivvy_owner
3729; 0 0 ACL public TABLE account maildivvy_owner
3730; 0 0 ACL public COLUMN account.id maildivvy_owner
235; 1259 16604 TABLE public audit maildivvy_owner
223; 1259 16448 TABLE public domain maildivvy_owner
3601; 0 16480 TABLE DATA public account maildivvy_owner
3602; 0 16604 TABLE DATA public audit maildivvy_owner
3603; 0 16448 TABLE DATA public domain maildivvy_owner
"""

SCRIPT = """\
--
-- PostgreSQL database dump
--
SET statement_timeout = 0;
COPY public.account (id, login, password_hash) FROM stdin;
1\tivan\t$6$x
2\tolga\t$6$y
\\.

COPY public.audit (id, at, detail) FROM stdin;
\\.

COPY public."domain" (id, label) FROM stdin;
1\tlittle\\nwith a newline, escaped
\\.

"""


# --- names: UTC, sortable, and nothing that only looks like a dump ----------


def test_a_run_is_named_by_its_utc_moment_whatever_the_machines_zone():
    kyiv = datetime.timezone(datetime.timedelta(hours=3))
    moment = datetime.datetime(2026, 9, 23, 3, 30, 5, tzinfo=kyiv)
    assert archive.stamp_of(moment) == "20260923T003005Z"
    assert archive.STAMP.fullmatch(archive.stamp_of(moment))


def test_a_moment_with_no_zone_is_refused_rather_than_guessed():
    with pytest.raises(ValueError, match="zone"):
        archive.stamp_of(datetime.datetime(2026, 9, 23, 3, 30, 5))


def test_only_complete_runs_count_as_runs():
    names = ["20260921T000000Z", ".20260923T000000Z.partial", ".lock", "20260922T000000Z",
             "notes.txt", "20260920T000000Z.old"]
    assert archive.complete_runs(names) == ["20260921T000000Z", "20260922T000000Z"]


# --- retention by count, never by age ---------------------------------------------


def test_the_newest_runs_are_kept_by_count_and_the_rest_named_for_removal():
    names = [f"202609{day:02d}T000000Z" for day in range(1, 12)] + [".x.partial", ".lock"]
    assert archive.beyond_keep(names, 8) == ["20260901T000000Z", "20260902T000000Z",
                                             "20260903T000000Z"]


def test_a_machine_that_stopped_for_a_fortnight_keeps_every_one_of_its_last_runs():
    """Age-based deletion would remove all of these on the same day; count keeps them."""
    old = [f"202608{day:02d}T000000Z" for day in range(1, 9)]
    assert archive.beyond_keep(old, 8) == []


def test_the_run_an_upgrade_holds_is_neither_counted_nor_named_for_removal():
    names = [f"202609{day:02d}T000000Z" for day in range(1, 5)]
    assert archive.beyond_keep(names, 1, held="20260901T000000Z") == ["20260902T000000Z", "20260903T000000Z"]
    assert archive.beyond_keep(names, 1, held=None) == names[:-1]


@pytest.mark.parametrize("keep", [0, -1])
def test_keeping_nothing_is_refused(keep):
    with pytest.raises(ValueError):
        archive.beyond_keep(["20260901T000000Z"], keep)


# --- the dump judged by content, never by size ------------------------------------


def test_the_tables_are_read_off_the_listing_and_nothing_else_counts_as_one():
    assert archive.tables_listed(LISTING) == {"account", "audit", "domain"}


def test_the_rows_are_counted_off_the_decoded_dump_one_line_each():
    counted = archive.rows_counted(io.StringIO(SCRIPT))
    assert counted == {"account": 2, "audit": 0, "domain": 1}


def test_a_copy_block_that_never_ends_is_a_dump_cut_short():
    cut = "COPY public.account (id) FROM stdin;\n1\n2\n"
    with pytest.raises(archive.BackupError, match="account"):
        archive.rows_counted(io.StringIO(cut))


def test_a_dump_holding_every_table_with_the_snapshots_rows_is_good():
    expected = {"account": 2, "audit": 0, "domain": 1}
    assert archive.dump_problems(expected, {"account", "audit", "domain"}, expected) == []


def test_a_dump_missing_a_table_or_a_row_is_refused_by_name():
    expected = {"account": 2, "audit": 0, "domain": 1}
    problems = archive.dump_problems(expected, {"account", "audit"},
                                     {"account": 1, "audit": 0})
    assert any("domain" in p and "not in the dump" in p for p in problems)
    assert any("account" in p and "2" in p and "1" in p for p in problems)


def test_a_database_with_no_tables_is_never_judged_a_good_dump():
    """An empty expectation compared with an empty dump agrees - and proves nothing."""
    assert archive.dump_problems({}, set(), {}) != []


# --- the fetch state: every file, byte for byte --------------------------


def state_tree(tmp_path):
    root = tmp_path / "fetch"
    (root / "5").mkdir(parents=True)
    (root / "5" / "uidls").write_text("# mpop\n 1 pop.example.org ivan\nabc 1757000000\n")
    (root / "5" / "mpoprc").write_text("account default\n")
    os.chmod(root, 0o700)
    os.chmod(root / "5", 0o700)
    for name in ("uidls", "mpoprc"):
        os.chmod(root / "5" / name, 0o600)
    return root


def test_the_state_archive_lists_every_file_of_the_state_with_its_owner_mode_and_bytes(tmp_path):
    root = state_tree(tmp_path)
    tar = tmp_path / "fetch.tar"
    archive.write_state(root, tar)
    entries = archive.tar_entries(tar)
    assert entries == archive.state_entries(root)
    by_name = {entry[0]: entry for entry in entries}
    assert set(by_name) == {"fetch", "fetch/5", "fetch/5/mpoprc", "fetch/5/uidls"}
    uidls = by_name["fetch/5/uidls"]
    assert uidls[1:4] == ("file", 0o600, os.getuid())
    assert uidls[-1] == hashlib.sha256((root / "5" / "uidls").read_bytes()).hexdigest()


def test_a_state_archive_short_of_a_file_is_told_apart_from_a_whole_one(tmp_path):
    """The source's failure: a 45-byte archive of nothing, after the dump was written."""
    root = state_tree(tmp_path)
    tar = tmp_path / "fetch.tar"
    with tarfile.open(tar, "w") as out:
        out.add(root, arcname="fetch", recursive=False)
    problems = archive.state_problems(archive.state_entries(root), archive.tar_entries(tar))
    assert any("fetch/5/uidls" in p for p in problems)


def test_a_changed_byte_in_the_state_is_a_problem(tmp_path):
    root = state_tree(tmp_path)
    tar = tmp_path / "fetch.tar"
    archive.write_state(root, tar)
    (root / "5" / "uidls").write_text("# mpop\n 1 pop.example.org ivan\nabd 1757000000\n")
    problems = archive.state_problems(archive.state_entries(root), archive.tar_entries(tar))
    assert problems and "fetch/5/uidls" in problems[0]


def test_a_missing_state_directory_fails_the_run_and_is_never_a_warning(tmp_path):
    with pytest.raises(archive.BackupError, match="no fetch state"):
        archive.state_entries(tmp_path / "fetch")
    with pytest.raises(archive.BackupError, match="no fetch state"):
        archive.write_state(tmp_path / "fetch", tmp_path / "fetch.tar")


def test_the_state_comes_back_as_it_was_taken(tmp_path):
    root = state_tree(tmp_path)
    tar = tmp_path / "fetch.tar"
    archive.write_state(root, tar)
    restored = archive.extract_state(tar, tmp_path / "staged")
    assert restored == tmp_path / "staged" / "fetch"
    assert archive.state_entries(restored) == archive.state_entries(root)
    assert stat.S_IMODE(os.stat(restored / "5" / "uidls").st_mode) == 0o600


def test_an_archive_reaching_outside_its_directory_is_refused(tmp_path):
    tar = tmp_path / "evil.tar"
    with tarfile.open(tar, "w") as out:
        data = b"x"
        info = tarfile.TarInfo("fetch/../../escaped")
        info.size = len(data)
        out.addfile(info, io.BytesIO(data))
    with pytest.raises(Exception):
        archive.extract_state(tar, tmp_path / "staged")
    assert not (tmp_path / "escaped").exists()


# --- the pause -----------------------------------------------------------------------------


class Systemd:
    """systemctl as a recorder: which timers are active, and what each service is doing."""

    def __init__(self, active=pause.TIMERS, busy=None, fail_start=()):
        self.timers = set(active)
        self.busy = dict(busy or {})     # service -> how many more polls it stays busy
        self.fail_start = set(fail_start)
        self.calls = []

    def active(self, unit):
        return unit in self.timers

    def stop(self, unit):
        self.calls.append(("stop", unit))
        self.timers.discard(unit)

    def start(self, unit):
        self.calls.append(("start", unit))
        if unit in self.fail_start:
            raise pause.SystemdError(f"could not start {unit}")
        self.timers.add(unit)

    def busy_with(self, unit):
        left = self.busy.get(unit, 0)
        if left:
            self.busy[unit] = left - 1
            self.calls.append(("busy", unit))
        return bool(left)


def quiet(*_):
    pass


def test_collection_and_fan_out_are_stopped_before_anything_is_taken_and_started_after():
    systemd, seen = Systemd(), []
    with pause.paused(systemd, sleep=quiet, say=quiet):
        seen.append(set(systemd.timers))
    assert seen == [set()]
    assert systemd.calls == [("stop", "maildivvy-fetch.timer"), ("stop", "maildivvy-pass.timer"),
                             ("start", "maildivvy-fetch.timer"), ("start", "maildivvy-pass.timer")]


def test_a_run_already_going_is_waited_for_and_never_cut_short():
    """A fetch holds its mailbox's lock and may run fifteen minutes: stopping the timer
    does not stop the run, so the dump waits until neither service is doing anything."""
    systemd = Systemd(busy={"maildivvy-fetch.service": 3, "maildivvy-pass.service": 1})
    slept, said = [], []
    with pause.paused(systemd, sleep=slept.append, say=said.append):
        assert systemd.busy == {"maildivvy-fetch.service": 0, "maildivvy-pass.service": 0}
    assert len(slept) == 3
    assert all(call[0] != "stop" or call[1].endswith(".timer") for call in systemd.calls)
    assert any("maildivvy-fetch.service" in line for line in said)


def test_a_timer_the_operator_had_stopped_stays_stopped():
    systemd = Systemd(active={"maildivvy-pass.timer"})
    with pause.paused(systemd, sleep=quiet, say=quiet):
        pass
    assert systemd.timers == {"maildivvy-pass.timer"}
    assert ("start", "maildivvy-fetch.timer") not in systemd.calls


def test_collection_resumes_even_when_what_ran_inside_the_pause_failed():
    systemd = Systemd()
    with pytest.raises(RuntimeError, match="the dump broke"):
        with pause.paused(systemd, sleep=quiet, say=quiet):
            raise RuntimeError("the dump broke")
    assert systemd.timers == set(pause.TIMERS)


def test_a_timer_refused_for_starting_too_often_is_cleared_and_started_again():
    """Measured on systemd 259: a unit started five times in ten seconds is refused
    `start-limit-hit`, and a timer refused that way stays stopped - collection with it.
    The limit protects nothing on a timer, so the resume clears it and tries once more."""
    calls = []

    def run(argv, **kwargs):
        calls.append(argv[1:])
        refused = argv[1] == "start" and calls.count(argv[1:]) == 1
        return type("Done", (), {"returncode": 1 if refused else 0, "stdout": "",
                                 "stderr": "Job failed." if refused else ""})()

    pause.Systemd(run=run).start("maildivvy-fetch.timer")
    assert calls == [["start", "maildivvy-fetch.timer"], ["reset-failed", "maildivvy-fetch.timer"],
                     ["start", "maildivvy-fetch.timer"]]


def test_one_timer_that_will_not_start_does_not_keep_the_other_stopped():
    systemd = Systemd(fail_start={"maildivvy-fetch.timer"})
    with pytest.raises(pause.SystemdError, match="maildivvy-fetch.timer"):
        with pause.paused(systemd, sleep=quiet, say=quiet):
            pass
    assert "maildivvy-pass.timer" in systemd.timers


def test_a_run_killed_inside_the_pause_leaves_a_record_its_units_stop_resumes_from(tmp_path):
    """A SIGKILLed backup never reaches its `finally`, so both timers
    stayed stopped, and later runs, finding them stopped, never started them. The pause
    records what it stopped before it stops it; the unit's ExecStopPost resumes from it."""
    systemd, record = Systemd(), tmp_path / "paused.json"
    killed = pause.paused(systemd, sleep=quiet, say=quiet, record=record)
    killed.__enter__()                       # ... and the process dies here: no __exit__
    assert systemd.timers == set() and json.loads(record.read_text()) == list(pause.TIMERS)
    assert pause.resume_recorded(systemd, record, say=quiet) == 0
    assert systemd.timers == set(pause.TIMERS) and not record.exists()
    # after an ordinary run there is nothing to resume, and nothing is started
    systemd.calls.clear()
    assert pause.resume_recorded(systemd, record, say=quiet) == 0 and systemd.calls == []


def test_the_next_run_resumes_what_a_killed_run_left_stopped_and_nothing_the_operator_stopped(tmp_path):
    """Without the unit's ExecStopPost (a run by hand, killed), the next run reads the
    record and resumes those timers too; a timer the operator had stopped is not in it."""
    record = tmp_path / "paused.json"
    record.write_text(json.dumps(["maildivvy-fetch.timer"]))
    systemd = Systemd(active=())
    with pause.paused(systemd, sleep=quiet, say=quiet, record=record):
        assert json.loads(record.read_text()) == ["maildivvy-fetch.timer"]
    assert systemd.timers == {"maildivvy-fetch.timer"} and not record.exists()


def test_a_resume_cut_short_keeps_its_record_for_the_units_stop(tmp_path):
    """A SIGTERM inside `resume()` leaves the record, so ExecStopPost finishes the job."""
    systemd, record = Systemd(fail_start={"maildivvy-pass.timer"}), tmp_path / "paused.json"
    with pytest.raises(pause.SystemdError):
        with pause.paused(systemd, sleep=quiet, say=quiet, record=record):
            pass
    assert json.loads(record.read_text()) == list(pause.TIMERS)
    systemd.fail_start.clear()
    assert pause.resume_recorded(systemd, record, say=quiet) == 0
    assert systemd.timers == set(pause.TIMERS) and not record.exists()


# --- one run, in order ----------------------------------------------------


class Database:
    """pg_dump and pg_restore as a recorder, writing files a judge can read."""

    def __init__(self, calls, rows=None, listed=None, fail=None):
        self.calls = calls
        self.rows = rows or {"account": 2, "audit": 0, "domain": 1}
        self.listed = listed
        self.fail = fail

    def dump(self, path):
        self.calls.append("dump")
        path.write_bytes(b"PGDMP")
        if self.fail == "dump":
            raise archive.BackupError("pg_dump exited 1")
        return dict(self.rows)

    def listing(self, path):
        tables = self.listed if self.listed is not None else self.rows
        return "".join(f"1; 1259 1 TABLE public {name} maildivvy_owner\n" for name in tables)

    def script(self, path):
        return io.StringIO("".join(
            f"COPY public.{name} (id) FROM stdin;\n" + "1\n" * rows + "\\.\n"
            for name, rows in self.rows.items()))

    def restore(self, path):
        self.calls.append("restore")
        if self.fail == "restore":
            raise archive.BackupError("pg_restore exited 1")


class Recorder(Systemd):
    def __init__(self, calls, **kwargs):
        super().__init__(**kwargs)
        self.log = calls

    def stop(self, unit):
        self.log.append(f"stop {unit}")
        super().stop(unit)

    def start(self, unit):
        self.log.append(f"start {unit}")
        super().start(unit)


def machine(tmp_path, calls, store_copy=None, copy_exit=0, keep=8, **database):
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o700)
    paths = run.Paths(backups=backups, fetch=state_tree(tmp_path),
                      status=tmp_path / "status" / "status.json", held=tmp_path / "upgrade-held")
    paths.status.parent.mkdir()

    def copy(command, stamp):
        calls.append(f"store copy {command} {stamp}")
        # the pair it makes: the dump it copies alongside is already in place
        calls.append(sorted(p.name for p in backups.iterdir() if not p.name.startswith(".")))
        return copy_exit

    moments = iter(datetime.datetime(2026, 9, 23, 0, 0, s, tzinfo=UTC) for s in range(60))
    return run.Backup(paths=paths, settings=run.Settings(keep=keep, store_copy=store_copy),
                      systemd=Recorder(calls), database=Database(calls, **database),
                      store_copy=copy, now=lambda: next(moments), sleep=quiet, say=quiet)


def test_a_run_pauses_takes_the_dump_and_the_state_then_the_store_copy_then_resumes(tmp_path):
    calls = []
    backup = machine(tmp_path, calls, store_copy="copy-the-store")
    assert backup.take() == 0
    assert calls == ["stop maildivvy-fetch.timer", "stop maildivvy-pass.timer", "dump",
                     "store copy copy-the-store 20260923T000000Z", ["20260923T000000Z"],
                     "start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    taken = backup.paths.backups / "20260923T000000Z"
    assert sorted(p.name for p in taken.iterdir()) == sorted(
        [archive.DUMP, archive.MANIFEST, archive.STATE])


def test_a_run_and_everything_in_it_is_readable_by_root_alone(tmp_path):
    backup = machine(tmp_path, [])
    assert backup.take() == 0
    taken = backup.paths.backups / "20260923T000000Z"
    assert stat.S_IMODE(taken.stat().st_mode) == 0o700
    assert {stat.S_IMODE(p.stat().st_mode) for p in taken.iterdir()} == {0o600}


def test_a_failed_dump_leaves_nothing_that_looks_like_one_and_collection_resumes(tmp_path):
    calls = []
    backup = machine(tmp_path, calls, fail="dump")
    assert backup.take() == 1
    assert list(backup.paths.backups.iterdir()) == [backup.paths.backups / ".lock"]
    assert calls[-2:] == ["start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert not backup.paths.status.exists()


def test_a_dump_short_of_a_table_is_not_renamed_into_place(tmp_path):
    backup = machine(tmp_path, [], listed={"account": 2, "audit": 0})
    assert backup.take() == 1
    assert archive.complete_runs(os.listdir(backup.paths.backups)) == []


def test_a_run_with_no_fetch_state_fails_after_the_dump_and_keeps_no_dump(tmp_path):
    calls = []
    backup = machine(tmp_path, calls)
    for child in sorted(backup.paths.fetch.rglob("*"), reverse=True):
        child.unlink() if child.is_file() else child.rmdir()
    backup.paths.fetch.rmdir()
    assert backup.take() == 1
    assert "dump" in calls
    assert archive.complete_runs(os.listdir(backup.paths.backups)) == []
    assert calls[-1] == "start maildivvy-pass.timer"


def test_a_store_copy_that_fails_fails_the_run_but_keeps_the_dump_and_resumes(tmp_path):
    calls = []
    backup = machine(tmp_path, calls, store_copy="false", copy_exit=3)
    assert backup.take() == 1
    assert archive.complete_runs(os.listdir(backup.paths.backups)) == ["20260923T000000Z"]
    assert calls[-2:] == ["start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert json.loads(backup.paths.status.read_text())["store_copy"] == "failed, exit 3"


def test_with_no_store_copy_configured_nothing_is_run_and_the_status_says_so(tmp_path):
    calls = []
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    assert not any(isinstance(c, str) and c.startswith("store copy") for c in calls)
    assert json.loads(backup.paths.status.read_text())["store_copy"] == "none configured"


def test_a_run_removes_the_runs_beyond_the_count_and_a_dead_runs_leftovers(tmp_path):
    backup = machine(tmp_path, [], keep=2)
    (backup.paths.backups / ".20260101T000000Z.partial").mkdir()
    for _ in range(3):
        assert backup.take() == 0
    left = sorted(os.listdir(backup.paths.backups))
    assert left == [".lock", "20260923T000001Z", "20260923T000002Z"]


def test_the_run_a_failed_upgrade_holds_as_its_way_back_outlives_the_count_until_the_hold_ends(tmp_path):
    """The backup from before an upgrade's migrations is the only one the old version can
    restore: the nightly runs and the retries taken while it is held never remove it."""
    backup = machine(tmp_path, [], keep=1)
    assert backup.take() == 0
    backup.paths.held.write_text("20260923T000000Z\n")
    for _ in range(2):
        assert backup.take() == 0
    assert sorted(os.listdir(backup.paths.backups)) == [".lock", "20260923T000000Z", "20260923T000002Z"]
    backup.paths.held.unlink()   # an upgrade finished
    assert backup.take() == 0
    assert sorted(os.listdir(backup.paths.backups)) == [".lock", "20260923T000003Z"]


def test_the_backup_and_the_upgrade_read_one_hold():
    from maildivvy.installer import upgrade
    assert run.Paths().held == upgrade.HELD


def test_the_status_names_the_newest_run_and_what_it_held(tmp_path):
    backup = machine(tmp_path, [])
    assert backup.take() == 0
    written = json.loads(backup.paths.status.read_text())
    assert written["stamp"] == "20260923T000000Z"
    assert (written["tables"], written["rows"], written["state_entries"]) == (3, 3, 4)
    assert stat.S_IMODE(backup.paths.status.stat().st_mode) == 0o644
    assert status.problem(backup.paths.status) is None


def test_a_restore_puts_back_the_database_and_the_state_of_one_run_together(tmp_path):
    calls = []
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    taken = archive.state_entries(backup.paths.fetch)
    (backup.paths.fetch / "5" / "uidls").write_text("moved on\n")
    (backup.paths.fetch / "9").mkdir()
    calls.clear()
    assert backup.restore("20260923T000000Z") == 0
    assert calls == ["stop maildivvy-fetch.timer", "stop maildivvy-pass.timer", "restore",
                     "start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert archive.state_entries(backup.paths.fetch) == taken


def test_a_database_restore_that_fails_leaves_the_state_as_it_was(tmp_path):
    calls = []
    backup = machine(tmp_path, calls, fail="restore")
    backup.database.fail = None
    assert backup.take() == 0
    (backup.paths.fetch / "5" / "uidls").write_text("moved on\n")
    now = archive.state_entries(backup.paths.fetch)
    backup.database.fail = "restore"
    assert backup.restore("20260923T000000Z") == 1
    assert archive.state_entries(backup.paths.fetch) == now
    assert calls[-2:] == ["start maildivvy-fetch.timer", "start maildivvy-pass.timer"]
    assert [p.name for p in backup.paths.fetch.parent.iterdir() if "restore" in p.name] == []


def test_a_restore_of_a_run_that_is_not_there_changes_nothing(tmp_path):
    calls = []
    backup = machine(tmp_path, calls)
    assert backup.restore("20260101T000000Z") == 1
    assert calls == []


# --- the settings ----------------------------------------------------------------------------------


def test_the_settings_default_to_eight_runs_and_no_store_copy(tmp_path):
    conf = tmp_path / "backup.conf"
    conf.write_text("# nothing set\n")
    assert run.read_settings(conf) == run.Settings(keep=8, store_copy=None)


def test_the_store_copy_is_the_whole_rest_of_its_line(tmp_path):
    conf = tmp_path / "backup.conf"
    conf.write_text("keep=3\nstore_copy=rsync -aH --delete /srv/maildivvy/store/ /copy/a=b/\n")
    assert run.read_settings(conf) == run.Settings(
        keep=3, store_copy="rsync -aH --delete /srv/maildivvy/store/ /copy/a=b/")


@pytest.mark.parametrize("text", ["keep=0\n", "keep=many\n", "retain=3\n", "keep=2\nkeep=3\n"])
def test_a_setting_that_cannot_be_meant_is_refused(tmp_path, text):
    conf = tmp_path / "backup.conf"
    conf.write_text(text)
    with pytest.raises(archive.BackupError):
        run.read_settings(conf)


# --- what the enable gate reads --------------------------------------------------------


def test_no_status_file_means_no_backup_has_been_taken(tmp_path):
    assert "no backup" in status.problem(tmp_path / "status.json")


@pytest.mark.parametrize("text", ["", "{", "[]", '{"taken_at": "2026-09-23T00:00:00+00:00"}'])
def test_a_status_file_that_names_no_run_is_no_backup(tmp_path, text):
    path = tmp_path / "status.json"
    path.write_text(text)
    assert status.problem(path) is not None
