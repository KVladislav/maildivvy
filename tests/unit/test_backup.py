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
import signal
import stat
import tarfile

import pytest

from maildivvy.backup import archive, pause, run, status
from maildivvy.lib import schema

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


def test_the_newest_run_marked_store_copied_is_the_pair(tmp_path):
    for name in ["20260901T000000Z", "20260902T000000Z", "20260903T000000Z", ".x.partial"]:
        (tmp_path / name).mkdir()
    assert archive.newest_paired(tmp_path) is None
    for name in ["20260901T000000Z", "20260902T000000Z", ".x.partial"]:
        (tmp_path / name / archive.PAIRED).touch()
    assert archive.newest_paired(tmp_path) == "20260902T000000Z"


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
    with pytest.raises(Exception):  # noqa: B017 - refused, whichever way the archive module says it
        archive.extract_state(tar, tmp_path / "staged")
    assert not (tmp_path / "escaped").exists()


# --- the pause -----------------------------------------------------------------------------


# Every timer started again, in the pause's order, after a run that stopped them all.
STARTED = ["start maildivvy-fetch.timer", "start maildivvy-pass.timer",
           "start maildivvy-snapshot.timer"]


class Systemd:
    """systemctl as a recorder: which timers are active, which are not installed at all,
    and what each service is doing."""

    def __init__(self, active=pause.TIMERS, busy=None, fail_start=(), missing=()):
        self.timers = set(active)
        self.busy = dict(busy or {})     # service -> how many more polls it stays busy
        self.fail_start = set(fail_start)
        self.missing = set(missing)      # units systemd has never been given
        self.calls = []

    def active(self, unit):
        return unit in self.timers

    def installed(self, unit):
        return unit not in self.missing

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
                             ("stop", "maildivvy-snapshot.timer"),
                             ("start", "maildivvy-fetch.timer"), ("start", "maildivvy-pass.timer"),
                             ("start", "maildivvy-snapshot.timer")]


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


def test_a_refetch_beside_the_pass_is_waited_for_and_no_timer_of_its_own_is_paused():
    """The pass's timer starts the requests unit too, and a refetch there writes the fetch
    state the backup takes: its run is waited out like the pass's. It has no timer, so an
    upgrade from a release without it starts again exactly what it stopped."""
    systemd = Systemd(busy={"maildivvy-requests.service": 2})
    slept = []
    with pause.paused(systemd, sleep=slept.append, say=quiet):
        assert systemd.busy == {"maildivvy-requests.service": 0}
    assert len(slept) == 2
    assert pause.TIMERS == ("maildivvy-fetch.timer", "maildivvy-pass.timer",
                            "maildivvy-snapshot.timer")


def test_a_snapshots_slice_is_paused_with_collection_and_waited_for():
    """A slice writes into the store and onto its row for up to ten minutes: its timer is
    stopped with collection's, and a slice already going is waited out, never cut short."""
    assert "maildivvy-snapshot.timer" in pause.TIMERS
    assert "maildivvy-snapshot.service" in pause.SERVICES
    systemd, said = Systemd(busy={"maildivvy-snapshot.service": 2}), []
    with pause.paused(systemd, sleep=quiet, say=said.append):
        assert "maildivvy-snapshot.timer" not in systemd.timers
        assert systemd.busy == {"maildivvy-snapshot.service": 0}
    assert ("stop", "maildivvy-snapshot.timer") in systemd.calls
    assert said == ["waiting for maildivvy-snapshot.service to finish its run"]
    assert systemd.timers == set(pause.TIMERS)


def test_a_timer_installed_inside_the_pause_is_started_with_the_rest_and_a_missing_one_passed():
    """An upgrade to the release that adds the snapshot's timer installs it, enabled and left
    stopped, inside its own pause: nobody stopped it, so the pause starts it with the
    others. One still not installed when the pause ends is passed without an error."""
    systemd = Systemd(active={"maildivvy-fetch.timer", "maildivvy-pass.timer"},
                      missing={"maildivvy-snapshot.timer"})
    with pause.paused(systemd, sleep=quiet, say=quiet):
        systemd.missing.clear()   # what ran inside installed it
    assert systemd.timers == set(pause.TIMERS)
    assert ("stop", "maildivvy-snapshot.timer") not in systemd.calls

    # an upgrade that failed before its install step: nothing installed it, nothing raised
    systemd = Systemd(active={"maildivvy-fetch.timer", "maildivvy-pass.timer"},
                      missing={"maildivvy-snapshot.timer"})
    with pause.paused(systemd, sleep=quiet, say=quiet):
        pass
    assert systemd.timers == {"maildivvy-fetch.timer", "maildivvy-pass.timer"}
    assert ("start", "maildivvy-snapshot.timer") not in systemd.calls
    # the control: one installed and stopped by the operator stays stopped
    systemd = Systemd(active={"maildivvy-fetch.timer", "maildivvy-pass.timer"})
    with pause.paused(systemd, sleep=quiet, say=quiet):
        pass
    assert "maildivvy-snapshot.timer" not in systemd.timers


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


def test_a_unit_systemd_reads_as_not_found_is_one_never_installed():
    shown = {"maildivvy-fetch.timer": "loaded\n", "maildivvy-snapshot.timer": "not-found\n"}
    asked = []

    def run(argv, **kwargs):
        asked.append(argv[1:])
        return type("Done", (), {"returncode": 0, "stdout": shown[argv[-1]], "stderr": ""})()

    systemd = pause.Systemd(run=run)
    assert systemd.installed("maildivvy-fetch.timer")
    assert not systemd.installed("maildivvy-snapshot.timer")
    assert asked[0] == ["show", "-p", "LoadState", "--value", "maildivvy-fetch.timer"]


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
    assert systemd.timers == set() and pause.read_record(record) == list(pause.TIMERS)
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
        assert pause.read_record(record) == ["maildivvy-fetch.timer"]
    assert systemd.timers == {"maildivvy-fetch.timer"} and not record.exists()


def test_a_resume_cut_short_keeps_its_record_for_the_units_stop(tmp_path):
    """A SIGTERM inside `resume()` leaves the record, so ExecStopPost finishes the job."""
    systemd, record = Systemd(fail_start={"maildivvy-pass.timer"}), tmp_path / "paused.json"
    with pytest.raises(pause.SystemdError):
        with pause.paused(systemd, sleep=quiet, say=quiet, record=record):
            pass
    assert pause.read_record(record) == list(pause.TIMERS)
    systemd.fail_start.clear()
    assert pause.resume_recorded(systemd, record, say=quiet) == 0
    assert systemd.timers == set(pause.TIMERS) and not record.exists()


# --- one run, in order ----------------------------------------------------


# what this tree's programs ship, which a restore compares a run's schema with (0098)
SHIPPED = [m.version for m in schema.migrations()]


class Database:
    """pg_dump and pg_restore as a recorder, writing files a judge can read."""

    def __init__(self, calls, rows=None, listed=None, fail=None, migrations=None):
        self.calls = calls
        self.rows = rows or {"account": 2, "audit": 0, "domain": 1}
        self.listed = listed
        self.fail = fail
        self.held_migrations = SHIPPED if migrations is None else migrations

    def migrations(self, path):
        return list(self.held_migrations)

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
            raise run.NotRestored("pg_restore exited 1, nothing was restored")


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
                      status=tmp_path / "status" / "status.json", held=tmp_path / "upgrade-held",
                      upgrade_paused=tmp_path / "upgrade-paused.json", version=tmp_path / "version")
    paths.status.parent.mkdir()
    paths.version.write_text("0.3.0\n")

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
    assert calls == ["stop maildivvy-fetch.timer", "stop maildivvy-pass.timer",
                     "stop maildivvy-snapshot.timer", "dump",
                     "store copy copy-the-store 20260923T000000Z", ["20260923T000000Z"], *STARTED]
    taken = backup.paths.backups / "20260923T000000Z"
    assert sorted(p.name for p in taken.iterdir()) == sorted(
        [archive.DUMP, archive.MANIFEST, archive.STATE, archive.PAIRED])


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
    assert calls[-3:] == STARTED
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
    assert calls[-3:] == STARTED


def test_a_store_copy_that_fails_fails_the_run_but_keeps_the_dump_and_resumes(tmp_path):
    calls = []
    backup = machine(tmp_path, calls, store_copy="false", copy_exit=3)
    assert backup.take() == 1
    assert archive.complete_runs(os.listdir(backup.paths.backups)) == ["20260923T000000Z"]
    assert calls[-3:] == STARTED
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


def test_days_of_a_failing_store_copy_never_remove_the_last_dump_that_has_one(tmp_path):
    """The dump is half of a pair: once the store copy fails every night, the runs that
    follow have no store to restore with, and the count alone would rotate out the last
    one that has."""
    backup = machine(tmp_path, [], store_copy="copy-the-store", keep=8)
    assert backup.take() == 0
    paired = archive.complete_runs(os.listdir(backup.paths.backups))[-1]
    assert (backup.paths.backups / paired / archive.PAIRED).is_file()
    copied = backup.store_copy
    backup.store_copy = lambda command, stamp: 3
    for _ in range(9):
        assert backup.take() == 1
    left = archive.complete_runs(os.listdir(backup.paths.backups))
    assert left[0] == paired and len(left) == 9
    assert [run for run in left if (backup.paths.backups / run / archive.PAIRED).exists()] == [paired]

    backup.store_copy = copied
    for _ in range(2):
        assert backup.take() == 0
    assert paired not in os.listdir(backup.paths.backups)   # a newer pair took its place


def test_the_status_names_the_newest_run_whose_store_copy_succeeded(tmp_path):
    """Health reads the restore point from the status: the runs are root's alone."""
    def newest():
        return json.loads(backup.paths.status.read_text())["newest_store_copied"]

    backup = machine(tmp_path, [], store_copy="copy-the-store")
    backup.store_copy = lambda command, stamp: 3
    assert backup.take() == 1
    assert newest() is None   # failed, and no run before it has a store copy
    backup.store_copy = lambda command, stamp: 0
    assert backup.take() == 0
    paired = json.loads(backup.paths.status.read_text())["stamp"]
    assert newest() == paired
    backup.store_copy = lambda command, stamp: 3
    assert backup.take() == 1
    assert json.loads(backup.paths.status.read_text())["stamp"] != paired
    assert newest() == paired


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


def test_the_backup_and_the_upgrade_read_one_hold_and_one_upgrade_pause():
    from maildivvy.installer import upgrade
    assert run.Paths().held == upgrade.HELD
    assert run.Paths().upgrade_paused == upgrade.PAUSE_RECORD


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
    assert calls == ["stop maildivvy-fetch.timer", "stop maildivvy-pass.timer",
                     "stop maildivvy-snapshot.timer", "restore", *STARTED]
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
    assert calls[-3:] == STARTED
    assert [p.name for p in backup.paths.fetch.parent.iterdir() if "restore" in p.name] == []


@pytest.mark.parametrize("signum", [signal.SIGHUP, signal.SIGINT, signal.SIGTERM],
                         ids=["SIGHUP", "SIGINT", "SIGTERM"])
def test_a_run_by_hand_told_to_stop_resumes_collection_on_its_way_out(tmp_path, signum):
    """Run from a shell, the program has no unit's ExecStopPost behind it: an SSH session
    that drops (SIGHUP) or a Ctrl-C (SIGINT) unwinds it through the pause's `finally` as
    systemd's SIGTERM does, instead of leaving collection stopped until the next run."""
    calls = []
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    (backup.paths.fetch / "5" / "uidls").write_text("moved on\n")
    now = archive.state_entries(backup.paths.fetch)
    backup.database = ClientDatabase(tmp_path, signal_from="pg_restore", signum=signum)
    handlers = {s: signal.getsignal(s) for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}
    try:
        run.stop_on_signals()
        assert backup.restore("20260923T000000Z") == 1
    finally:
        for s, handler in handlers.items():
            signal.signal(s, handler)
    assert calls[-3:] == STARTED
    assert not backup.paused_record.exists()
    assert archive.state_entries(backup.paths.fetch) == now


def test_the_state_is_the_runs_before_the_database_can_commit(tmp_path):
    """A restore stopped between its two steps must leave the state older than the
    database, never newer: an older state fetches mail again, a newer one skips it."""
    backup = machine(tmp_path, [])
    assert backup.take() == 0
    taken = archive.state_entries(backup.paths.fetch)
    (backup.paths.fetch / "5" / "uidls").write_text("moved on\n")
    seen = []
    backup.database.restore = lambda path: seen.append(archive.state_entries(backup.paths.fetch))
    assert backup.restore("20260923T000000Z") == 0
    assert seen == [taken]


def test_a_restore_stopped_inside_its_commit_leaves_collection_stopped_until_run_again(tmp_path):
    """psql told to stop after the COMMIT was sent: the database may hold either side. The
    state stays the run's, which at worst fetches again, and collection stays stopped until
    the restore is run again."""
    calls, said = [], []
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    taken = archive.state_entries(backup.paths.fetch)
    (backup.paths.fetch / "5" / "uidls").write_text("moved on\n")
    backup.database = ClientDatabase(tmp_path, signal_from="psql", signum=signal.SIGTERM)
    backup.say = said.append
    calls.clear()
    handlers = {s: signal.getsignal(s) for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}
    try:
        run.stop_on_signals()
        assert backup.restore("20260923T000000Z") == 1
    finally:
        for s, handler in handlers.items():
            signal.signal(s, handler)
    assert archive.state_entries(backup.paths.fetch) == taken
    assert not [c for c in calls if c.startswith("start ")]
    assert backup.paused_record.exists()
    assert any("--restore 20260923T000000Z" in line for line in said), said
    assert sorted(p.name for p in backup.paths.fetch.parent.iterdir() if p.name.startswith(".")) == []

    backup.database = Database(calls)
    assert backup.restore("20260923T000000Z") == 0
    assert archive.state_entries(backup.paths.fetch) == taken
    assert calls[-3:] == STARTED
    assert not backup.paused_record.exists()


def test_a_restore_stopped_inside_its_state_swap_is_completed_by_a_second_run(tmp_path, monkeypatch):
    calls = []
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    taken = archive.state_entries(backup.paths.fetch)
    (backup.paths.fetch / "5" / "uidls").write_text("moved on\n")
    (backup.paths.fetch / "9").mkdir()
    renames, rename = [], os.rename

    def stopped_at_the_second(source, target):
        renames.append(source)
        if len(renames) == 2:
            raise run.Terminated("told to stop (signal 15)")
        rename(source, target)

    monkeypatch.setattr(run.os, "rename", stopped_at_the_second)
    calls.clear()
    assert backup.restore("20260923T000000Z") == 1
    monkeypatch.undo()
    assert "restore" not in calls
    assert not [c for c in calls if c.startswith("start ")]

    assert backup.restore("20260923T000000Z") == 0
    assert archive.state_entries(backup.paths.fetch) == taken
    assert calls[-3:] == STARTED


def torn(tmp_path, calls):
    """A restore stopped after its COMMIT went out: collection left stopped, the record its."""
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    backup.database.restore = lambda path: (_ for _ in ()).throw(
        archive.BackupError("psql exited 2 after the COMMIT was sent"))
    assert backup.restore("20260923T000000Z") == 1
    backup.database = Database(calls)
    calls.clear()
    return backup


def test_a_backup_after_a_torn_restore_is_refused_and_leaves_collection_stopped(tmp_path):
    """Its dump would be the database a restore may not have reached, beside the run's
    state, as the newest run; and its resume would fetch over that pair. It refuses until
    the restore is run again, and names it."""
    calls, said = [], []
    backup = torn(tmp_path, calls)
    backup.say = said.append
    newest = backup.paths.status.read_text()
    assert backup.take() == 1
    assert calls == [] and backup.systemd.timers == set()
    assert backup.paths.status.read_text() == newest
    assert any("maildivvy-backup --restore 20260923T000000Z" in line for line in said), said
    assert sorted(p.name for p in backup.paths.backups.iterdir()) == [".lock", "20260923T000000Z"]

    assert backup.restore("20260923T000000Z") == 0
    assert not backup.paused_record.exists()
    assert backup.take() == 0
    assert backup.systemd.timers == set(pause.TIMERS)


def test_the_units_resume_starts_nothing_a_restore_left_stopped_or_is_still_holding(tmp_path):
    """The daily run fails on the lock while a restore by hand runs, and its ExecStopPost
    reads the restore's record; or the restore was torn. Neither is the unit's to start."""
    calls, said = [], []
    backup = torn(tmp_path, calls)
    assert run.resume(backup.systemd, backup.paths, said.append) == 1
    assert calls == [] and backup.paused_record.exists()
    assert any("maildivvy-backup --restore 20260923T000000Z" in line for line in said), said


def test_a_backup_inside_an_upgrades_pause_starts_no_timer_the_upgrade_holds(tmp_path):
    """The timers are the upgrade's while its record is there: a backup that would resume
    what a killed run of its own recorded, or the unit's stop after it, would start
    collection under the upgrade's migrations. Its record stays for a run after."""
    calls = []
    backup = machine(tmp_path, calls)
    backup.systemd.timers.clear()
    backup.paths.upgrade_paused.write_text(json.dumps({"by": "upgrade", "timers": list(pause.TIMERS)}))
    pause.write_record(backup.paused_record, ["maildivvy-fetch.timer"], {"by": "backup"})
    assert backup.take() == 0
    assert run.resume(backup.systemd, backup.paths, quiet) == 0
    assert not [c for c in calls if c.startswith("start ")]
    assert pause.read(backup.paused_record)["timers"] == ["maildivvy-fetch.timer"]

    backup.paths.upgrade_paused.unlink()     # the upgrade finished, and started its own
    backup.systemd.timers.update({"maildivvy-pass.timer", "maildivvy-snapshot.timer"})
    assert backup.take() == 0
    assert backup.systemd.timers == set(pause.TIMERS) and not backup.paused_record.exists()


def test_a_restore_that_completes_inside_an_upgrades_pause_leaves_the_timers_to_it(tmp_path):
    """The way back from a failed upgrade restores first: the restore must not start
    collection before the old version's installer runs, nor leave a record that refuses
    the next backup."""
    calls = []
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    backup.paths.upgrade_paused.write_text(json.dumps({"by": "upgrade", "timers": list(pause.TIMERS)}))
    calls.clear()
    assert backup.restore("20260923T000000Z") == 0
    assert not [c for c in calls if c.startswith("start ")]
    assert pause.read(backup.paused_record) == {"by": "backup", "timers": list(pause.TIMERS)}
    assert run.unfinished_restore(backup.paused_record) is None


def inside_an_upgrades_pause(tmp_path, calls):
    """A machine with one run taken, then every timer stopped by an upgrade and recorded as its."""
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    backup.systemd.timers.clear()
    backup.paths.upgrade_paused.write_text(json.dumps({"by": "upgrade", "timers": list(pause.TIMERS)}))
    calls.clear()
    return backup


@pytest.mark.parametrize("how", ["take", "restore"])
def test_a_run_that_stopped_no_timer_inside_an_upgrades_pause_leaves_no_record(tmp_path, how):
    """The upgrade's own backup, and the restore on the way back from a failed upgrade, find
    every timer stopped already: there is nothing to hand over. A record naming no timer
    would still read as a pause to whatever finds it (the import stops on it) until the
    next backup removed it."""
    calls = []
    backup = inside_an_upgrades_pause(tmp_path, calls)
    assert getattr(backup, how)(*(["20260923T000000Z"] if how == "restore" else [])) == 0
    assert not [c for c in calls if str(c).startswith(("stop ", "start "))]
    assert not backup.paused_record.exists()
    assert run.resume(backup.systemd, backup.paths, quiet) == 0 and backup.systemd.timers == set()


def test_a_torn_restore_inside_an_upgrades_pause_keeps_its_record_though_it_names_no_timer(
        tmp_path, monkeypatch):
    """The record is what refuses the next backup and names the restore to run again: it
    stays the restore's whether or not the restore stopped a timer, and a second run that
    could not even begin its pause does not take it away."""
    calls = []
    backup = inside_an_upgrades_pause(tmp_path, calls)
    backup.database.restore = lambda path: (_ for _ in ()).throw(
        archive.BackupError("psql exited 2 after the COMMIT was sent"))
    assert backup.restore("20260923T000000Z") == 1
    torn = {"by": "restore", "stamp": "20260923T000000Z", "timers": []}
    assert pause.read(backup.paused_record) == torn
    assert backup.take() == 1 and pause.read(backup.paused_record) == torn

    def full(record, timers, owner):
        raise OSError("No space left on device")
    monkeypatch.setattr(pause, "write_record", full)
    backup.database = Database(calls)
    assert backup.restore("20260923T000000Z") == 1
    assert pause.read(backup.paused_record) == torn and "restore" not in calls


@pytest.mark.parametrize("by, how", [("backup", "take"), ("restore", "restore")])
def test_the_pause_record_says_who_stopped_the_timers(tmp_path, by, how):
    backup = machine(tmp_path, [])
    assert backup.take() == 0
    seen = []
    backup.database.dump = backup.database.restore = lambda *a: seen.append(
        pause.read(backup.paused_record)) or {}
    getattr(backup, how)(*(["20260923T000000Z"] if how == "restore" else []))
    expected = {"by": by, "timers": list(pause.TIMERS)}
    assert seen == [expected | ({"stamp": "20260923T000000Z"} if by == "restore" else {})]


def test_a_record_written_before_it_named_its_owner_is_still_resumed(tmp_path):
    """A record left by the release before, a bare list of timers, is still read."""
    record = tmp_path / "paused.json"
    record.write_text(json.dumps(["maildivvy-fetch.timer"]))
    assert pause.read(record) == {"by": None, "timers": ["maildivvy-fetch.timer"]}


def test_a_restore_of_a_run_that_is_not_there_changes_nothing(tmp_path):
    calls = []
    backup = machine(tmp_path, calls)
    assert backup.restore("20260101T000000Z") == 1
    assert calls == []


# --- which release took a run, and whether this machine may restore it (0098) ----------------------


def manifest_of(backup, stamp):
    return json.loads((backup.paths.backups / stamp / archive.MANIFEST).read_text())


def test_a_runs_manifest_names_the_release_the_schema_and_a_hold_it_was_taken_under(tmp_path):
    backup = machine(tmp_path, [])
    assert backup.take() == 0
    found = manifest_of(backup, "20260923T000000Z")
    assert (found["release"], found["migrations"], found["upgrade_held"]) == ("0.3.0", SHIPPED, None)
    backup.paths.held.write_text("20260923T000000Z\n")
    assert backup.take() == 0
    assert manifest_of(backup, "20260923T000001Z")["upgrade_held"] == "20260923T000000Z"
    backup.paths.version.unlink()   # a first install that has not finished
    assert backup.take() == 0
    assert manifest_of(backup, "20260923T000002Z")["release"] is None


OLDER = SHIPPED[:-1]


@pytest.mark.parametrize("manifest, installed, refused", [
    # the schema the installed programs ship, whichever release took it
    ({"release": "0.3.0", "migrations": SHIPPED}, "0.3.1", None),
    ({"release": "0.3.0", "migrations": SHIPPED, "upgrade_held": "20260101T000000Z"}, "0.3.0", None),
    # the way back from a failed upgrade: its programs may be in place, its version is not
    ({"release": "0.2.1", "migrations": OLDER}, "0.2.1", None),
    # a rebuilt machine on the newest release, a run of an older one
    ({"release": "0.2.1", "migrations": OLDER}, "0.3.0", "install 0.2.1 first"),
    # taken while a failed upgrade held its way back: the new migrations are in it
    ({"release": "0.2.1", "migrations": OLDER, "upgrade_held": "20260101T000000Z"}, "0.2.1",
     "Restore that run"),
    ({"release": None, "migrations": OLDER}, None, "no finished install"),
])
def test_a_run_is_restored_only_on_its_own_schema_or_its_own_release(manifest, installed, refused):
    said = run.not_restorable("20260923T000000Z", manifest, installed, SHIPPED)
    assert said is None if refused is None else refused in said


def test_a_restore_on_another_release_and_schema_is_refused_before_it_pauses_anything(tmp_path):
    calls, said = [], []
    backup = machine(tmp_path, calls, migrations=OLDER)
    assert backup.take() == 0
    calls.clear()
    backup.paths.version.write_text("0.3.1\n")
    backup.say = said.append
    assert backup.restore("20260923T000000Z") == 1
    assert calls == [] and "taken by Maildivvy 0.3.0" in said[-1] and "install 0.3.0 first" in said[-1]
    backup.paths.version.write_text("0.3.0\n")   # the release that took it: restored
    assert backup.restore("20260923T000000Z") == 0 and "restore" in calls


def test_a_run_from_before_its_manifest_named_a_release_is_restored_with_a_warning(tmp_path):
    calls, said = [], []
    backup = machine(tmp_path, calls)
    assert backup.take() == 0
    found = backup.paths.backups / "20260923T000000Z" / archive.MANIFEST
    old = {k: v for k, v in json.loads(found.read_text()).items()
           if k not in ("release", "migrations", "upgrade_held")}
    found.write_text(json.dumps(old))
    backup.say = said.append
    assert backup.restore("20260923T000000Z") == 0
    assert "records neither the release nor the schema" in said[0]


def test_the_schema_is_read_from_the_dumps_own_rows():
    decoded = ["COPY public.account (id) FROM stdin;\n", "0002\tnot a version\n", "\\.\n",
               "COPY public.schema_version (version, name, applied_at) FROM stdin;\n",
               "0002\t0002_x.sql\t2026-01-01\n", "0001\t0001_initial.sql\t2026-01-01\n", "\\.\n"]
    assert archive.migrations_of(decoded) == ["0001", "0002"]
    assert archive.migrations_of([]) == []


def test_the_backup_reads_the_version_file_the_installer_writes():
    from maildivvy.installer import upgrade
    assert run.Paths().version == upgrade.VERSION_FILE


# --- the database restore: what pg_restore decodes goes to psql in one transaction --------------


class ClientDatabase(run.Database):
    """The real restore, with pg_restore and psql replaced by scripts that record."""

    def __init__(self, tmp_path, decode_exit=0, client_fails=False, psql_exit=0,
                 signal_from=None, signum=signal.SIGTERM):
        super().__init__()
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        self.sent = tmp_path / "psql-stdin"
        # the run told to stop while one of its two children works: the child signals us
        stop = {name: f"kill -s {signal.Signals(signum).name[3:]} $PPID\n" if name == signal_from
                else "" for name in ("pg_restore", "psql")}
        (bin_dir / "pg_restore").write_text(
            "#!/bin/sh\n"
            f"echo \"$@\" > {tmp_path / 'pg_restore-argv'}\n"
            "echo 'CREATE TABLE public.account ();'\n"
            + stop["pg_restore"] + f"exit {decode_exit}\n")
        (bin_dir / "psql").write_text(
            f"#!/bin/sh\necho \"$@\" > {tmp_path / 'psql-argv'}\n" + (
                "echo 'psql: error: connection refused' >&2\nexit 2\n" if client_fails
                else f"cat > {self.sent}\n" + stop["psql"] + f"exit {psql_exit}\n"))
        for name in ("pg_restore", "psql"):
            (bin_dir / name).chmod(0o755)
        self.path = f"{bin_dir}:{os.environ['PATH']}"

    def _environment(self):
        return {"PATH": self.path, "PGDATABASE": "maildivvy", "PGUSER": "maildivvy_owner"}


def test_a_restore_replaces_what_the_owner_holds_and_commits_only_a_checked_whole(tmp_path):
    """A migration's objects that the dump does not know (a view over a dumped table) would
    stop pg_restore's own clean: what the owner holds goes first, in the same transaction
    as the restore and the grants' check."""
    database = ClientDatabase(tmp_path)
    database.restore(tmp_path / "database.dump")
    assert "--file=-" in (tmp_path / "pg_restore-argv").read_text().split()
    assert "ON_ERROR_STOP=1" in (tmp_path / "psql-argv").read_text()
    sent = database.sent.read_text()
    order = ["BEGIN;", "DROP OWNED BY CURRENT_USER;", "CREATE TABLE public.account ();",
             "RESET search_path;", "SELECT check_grants();", "COMMIT;"]
    assert [line for line in sent.splitlines() if line] == order


def test_a_dump_that_does_not_decode_to_its_end_is_never_committed(tmp_path):
    database = ClientDatabase(tmp_path, decode_exit=1)
    with pytest.raises(run.NotRestored, match="nothing was restored"):
        database.restore(tmp_path / "database.dump")
    assert "COMMIT" not in database.sent.read_text()


def test_an_error_inside_the_transaction_is_known_to_have_restored_nothing(tmp_path):
    """psql's exit 3 is a statement that failed under ON_ERROR_STOP: the COMMIT never ran,
    or was the statement that failed."""
    with pytest.raises(run.NotRestored, match="psql exited 3"):
        ClientDatabase(tmp_path, psql_exit=3).restore(tmp_path / "database.dump")


def test_a_client_lost_after_the_commit_was_sent_is_not_known_to_have_restored_nothing(tmp_path):
    with pytest.raises(archive.BackupError, match="may or may not") as raised:
        ClientDatabase(tmp_path, psql_exit=2).restore(tmp_path / "database.dump")
    assert not isinstance(raised.value, run.NotRestored)


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


def test_a_client_that_cannot_connect_is_named_as_the_reason(tmp_path):
    with pytest.raises(archive.BackupError, match="psql exited 2.*connection refused"):
        ClientDatabase(tmp_path, client_fails=True).restore(tmp_path / "database.dump")
