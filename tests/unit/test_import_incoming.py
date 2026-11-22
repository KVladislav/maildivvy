"""`maildivvy-import incoming` on the unit tier's real database, with a store of its own:
the files, their names, the result, the slices and every way a run stops.

Dovecot stands in only for the INBOX's UIDNEXT, and the pass for the cursor it moves: a
slice is "recorded" when the test's pass writes a row for each imported name and moves
the cursor, as `maildivvy-pass` does.
"""

import hashlib
import json
import os
import stat
import threading
import time

import pytest

import eml_corpus
from maildivvy.fanout import requests
from maildivvy.fetch import locks
from maildivvy.importer import run, source
from maildivvy.lib import doveadm, store

HASH = "{SHA512-CRYPT}$6$x$" + "x" * 86


class World:
    """`alpha`'s archive, its rows, the pause records' paths, and a pass that records."""

    def __init__(self, database, tmp_path, monkeypatch):
        self.database = database
        self.tmp = tmp_path
        self.domain = database.value("INSERT INTO domain (label, archive_password_hash) "
                                     "VALUES ('alpha', %s) RETURNING id", (HASH,))
        self.root = tmp_path / "store"
        self.box = store.maildir(store.archive_home("alpha", self.root))
        for part in ("cur", "new", "tmp"):
            (self.box / part).mkdir(parents=True)
        self.paths = run.Paths(store_root=self.root, backup_paused=tmp_path / "paused.json",
                               upgrade_paused=tmp_path / "upgrade-paused.json")
        self.passes = True     # the pass records what the INBOX holds when it runs
        self.ticks = 0
        self.recorded = set()
        self.dovecot = {}      # each name's UID, given as Dovecot gives it: once, in order
        self.unrecordable = set()   # names the pass skips, moving its cursor past them
        monkeypatch.setattr(doveadm, "mailbox_status", self.status)
        monkeypatch.setattr(doveadm, "fetch", self.fetch)
        monkeypatch.setattr(run, "Reserve", lambda root: Room())
        self.source = tmp_path / "staging" / "alpha"
        self.source.mkdir(parents=True)

    def names(self):
        return sorted(os.listdir(self.box / "cur"))

    def numbered(self):
        for name in self.names():
            self.dovecot.setdefault(name, len(self.dovecot) + 1)

    def status(self, login, folder, *fields):
        assert (login, folder, fields) == ("archive@alpha", "INBOX", ("uidnext",))
        self.numbered()
        return {"uidnext": str(len(self.dovecot) + 1)}

    def fetch(self, login, folder, fields, *search):
        assert (login, folder, list(fields), search[0]) == (
            "archive@alpha", "INBOX", ["uid", "storageid"], "uid")
        first, last = (int(n) for n in search[1].split(":"))
        return [{"uid": str(uid), "storageid": store.name_parts(name)[0]}
                for name, uid in self.dovecot.items() if first <= uid <= last]

    def tick(self):
        """One run of the pass: a row for each name it has not recorded, the cursor last."""
        self.ticks += 1
        if not self.passes:
            return
        self.numbered()
        for name in self.names():
            if name in self.recorded or name in self.unrecordable:
                continue
            uid = self.dovecot[name]
            data = (self.box / "cur" / name).read_bytes()
            section = source.header_section(data[:4096])
            message_id = source.first_value(section, "message-id") or None
            self.database.sql("INSERT INTO message (domain_id, archive_uid, archive_base, "
                              "message_id_header, imported_at) VALUES (%s, %s, %s, %s, "
                              "clock_timestamp())",
                              (self.domain, uid, store.name_parts(name)[0], message_id))
            self.recorded.add(name)
        self.database.sql("INSERT INTO pass_cursor (domain_id, mailbox, last_uid) VALUES "
                          "(%s, 'INBOX', %s) ON CONFLICT (domain_id, mailbox) DO UPDATE SET "
                          "last_uid = excluded.last_uid", (self.domain, len(self.dovecot)))

    def args(self, *more, manifest=None):
        argv = ["incoming", "--domain", "alpha", "--source", str(self.source),
                "--etc", str(self.database.etc), *more]
        if manifest is not None:
            argv += ["--manifest", str(manifest)]
        return argv

    def main(self, *more, manifest=None, result_name="result.tsv"):
        out = self.tmp / result_name
        code = run.main(self.args("--result", str(out), *more, manifest=manifest), self.paths)
        return code, out.read_text().splitlines()

    def go(self, *more, clock=None, sleep=None, manifest=None):
        """`run.run` itself, with the test's pass ticking at each wait."""
        args = run.parse_args(self.args(*more, manifest=manifest))
        lines = []

        class Out:
            def write(self, text):
                lines.extend(text.splitlines())

            def flush(self):
                pass

        conn = self.database.connect("pipeline")
        try:
            code, stopped = run.run(conn, args, self.paths, Out(), clock=clock or time.monotonic,
                                    sleep=sleep or (lambda seconds: self.tick()))
        finally:
            conn.close()
        return code, stopped, lines


class Room:
    """The reserve with room for everything; a test that wants it short says so."""

    short = None

    def room(self, size):
        if Room.short:
            raise run.Stop(Room.short)


@pytest.fixture
def world(database, tmp_path, monkeypatch):
    Room.short = None
    monkeypatch.setattr(run, "POLL", 0)
    # the test's pass ticks inside the wait; a run's own ticks are the timer's
    made = World(database, tmp_path, monkeypatch)
    monkeypatch.setattr(run, "pause", lambda seconds: made.tick())
    monkeypatch.setattr(run, "SLICE_FILES", 3)
    return made


def statuses(lines):
    return {line.split("\t")[0]: (line.split("\t")[2], line.split("\t")[3])
            for line in lines if not line.startswith("#")}


def totals(lines):
    return [line for line in lines if line.startswith("#")]


# --- a full run, and a second one ---------------------------------------------------------------


def test_a_full_run_files_each_message_under_its_imported_name_and_says_so(world):
    made = eml_corpus.corpus(world.source, n=6)
    data = {m.path.relative_to(world.source).as_posix(): m.path.read_bytes()
            for m in made if m.received is not None}
    code, lines = world.main()
    assert code == run.EX_OK
    found = statuses(lines)
    assert found["copies/same-bytes.eml"][0] == source.DUPLICATE
    assert found["copies/same-id.eml"][0] == source.DUPLICATE
    assert {name for name, (status, _) in found.items() if status == source.REFUSED} == {
        "empty.eml", "mbox.eml", "link.eml"}
    imported = [name for name, (status, _) in found.items() if status == source.IMPORTED]
    assert len(imported) == 6
    assert totals(lines) == ["# total 11", "# imported 6", "# duplicate 2", "# refused 3",
                             "# held before 0"]
    names = world.names()
    assert len(names) == 6
    by_hash = {hashlib.sha256(d).hexdigest(): (name, d) for name, d in data.items()}
    for name in names:
        base, info = store.name_parts(name)
        epoch = store.imported(base)
        assert epoch is not None and info == "2,S", name
        held = (world.box / "cur" / name)
        sha = store.IMPORTED.match(base).group(2)
        assert held.read_bytes() == by_hash[sha][1]          # byte for byte
        assert int(held.stat().st_mtime) == epoch             # its mtime the received moment
        assert held.stat().st_nlink == 1                      # renamed, never linked
        assert base.endswith(f",S={len(by_hash[sha][1])},W={eml_corpus.virtual_size(by_hash[sha][1])}")
    # renamed out of the staging tree: what was imported is no longer there
    assert not (world.source / "box1" / "0001.eml").exists()
    assert (world.source / "copies" / "same-bytes.eml").exists()   # a duplicate stays
    # the slices: 6 files in slices of 3, the pass waited for after each
    assert world.ticks == 2


def test_a_second_run_over_the_same_source_imports_nothing_new(world, monkeypatch):
    monkeypatch.setattr(run, "same_filesystem", lambda *a: False)   # copied: the source stays
    eml_corpus.corpus(world.source, n=6, refusals=False)
    code, first = world.main(result_name="first.tsv")
    assert code == run.EX_OK and totals(first)[1] == "# imported 6"
    held = world.names()
    code, second = world.main(result_name="second.tsv")
    assert code == run.EX_OK and world.names() == held
    assert totals(second)[-1] == "# held before 6"
    assert {status for status, reason in statuses(second).values()} == {
        source.IMPORTED, source.DUPLICATE}
    assert all(reason == "in the store already: an earlier run took it"
               for status, reason in statuses(second).values() if status == source.IMPORTED)
    assert statuses(first)["box1/0001.eml"] == (source.IMPORTED, "copied")


@pytest.mark.parametrize("mode", ["renamed", "copied"])
def test_each_name_carries_its_files_size_and_its_size_over_imap_whatever_its_line_ends(
        world, monkeypatch, mode):
    if mode == "copied":
        monkeypatch.setattr(run, "same_filesystem", lambda *a: False)
    shapes = eml_corpus.line_ends(astride=run.CHUNK)
    for name, data in shapes.items():
        eml_corpus.write(world.source, f"{name}.eml", data)
    code, lines = world.main()
    assert code == run.EX_OK, lines
    assert {status for status, _ in statuses(lines).values()} == {source.IMPORTED}
    by_hash = {hashlib.sha256(data).hexdigest(): data for data in shapes.values()}
    names = world.names()
    assert len(names) == len(shapes)
    for name in names:
        epoch, sha, size, vsize = store.IMPORTED.match(store.name_parts(name)[0]).groups()
        data = by_hash[sha]
        assert (world.box / "cur" / name).read_bytes() == data
        assert (int(size), int(vsize)) == (len(data), eml_corpus.virtual_size(data))


def test_a_copy_whose_bytes_or_line_ends_are_not_those_read_is_refused_and_leaves_nothing(
        world, monkeypatch):
    monkeypatch.setattr(run, "same_filesystem", lambda *a: False)
    path = eml_corpus.write(world.source, "one.eml", eml_corpus.message(1, crlf=False))
    record = source.read(path, "one.eml", source.INCOMING)
    name = store.import_base(record.received, record.sha256, record.size, record.vsize) + ":2,S"
    # the size over IMAP the name would carry is not the copy's
    with pytest.raises(ValueError, match="it changed after it was read"):
        run.put(record._replace(vsize=record.vsize - 1), world.box, name, Room())
    # other bytes of the same length
    path.write_bytes(path.read_bytes().replace(b"body", b"BODY"))
    with pytest.raises(ValueError, match="it changed after it was read"):
        run.put(record, world.box, name, Room())
    assert world.names() == [] and os.listdir(world.box / "tmp") == []
    # the control: the bytes that were read are copied under that name
    path.write_bytes(path.read_bytes().replace(b"BODY", b"body"))
    assert run.put(record, world.box, name, Room()) == "copied" and world.names() == [name]


def test_incoming_flags_keep_seen_alone_and_an_unread_message_is_named_unread(world):
    made = eml_corpus.corpus(world.source, n=2, refusals=False)
    rows = []
    for m, flags in zip(made[:2], ("RFS", "")):
        data = m.path.read_bytes()
        rows.append(f"{m.path.relative_to(world.source)}\t{hashlib.sha256(data).hexdigest()}\t"
                    f"{len(data)}\t\t{flags}")
    manifest = world.tmp / "manifest.tsv"
    manifest.write_text("\n".join(rows) + "\n")
    code, lines = world.main(manifest=manifest)
    assert code == run.EX_OK
    assert sorted(store.name_parts(n)[1] for n in world.names()) == ["2,", "2,S"]
    reasons = [reason for status, reason in statuses(lines).values()]
    assert "flags F, R dropped: an archive's name carries S alone" in reasons


def test_a_message_dated_ahead_is_filed_at_its_files_mtime_and_a_manifest_moment_ahead_refused(
        world):
    ahead = eml_corpus.write(world.source, "ahead.eml", eml_corpus.message(
        1, date="Fri, 13 Feb 2099 12:00:00 +0000"))
    told = eml_corpus.write(world.source, "told.eml", eml_corpus.message(2))
    rows = [f"{path.name}\t{hashlib.sha256(path.read_bytes()).hexdigest()}\t"
            f"{path.stat().st_size}\t{received}\tS"
            for path, received in ((ahead, ""), (told, "2099-02-13T12:00:00Z"))]
    manifest = world.tmp / "manifest.tsv"
    manifest.write_text("\n".join(rows) + "\n")
    code, lines = world.main(manifest=manifest)
    assert code == run.EX_OK
    found = statuses(lines)
    assert found["ahead.eml"] == (
        source.IMPORTED, "its Date is more than a day after the file's mtime: the mtime is taken")
    assert found["told.eml"] == (
        source.REFUSED, "received '2099-02-13T12:00:00Z' is later than the start of this run")
    [name] = world.names()
    # the three places the moment goes for good: the name, the file's mtime, and through
    # the name the ledger's row
    assert store.imported(store.name_parts(name)[0]) == eml_corpus.MTIME
    assert int((world.box / "cur" / name).stat().st_mtime) == eml_corpus.MTIME
    assert told.exists() and not ahead.exists()


# --- a run stopped between a file and its line --------------------------------------------------


class Killed(BaseException):
    """The run killed: nothing of ours catches it."""


def killed_after(monkeypatch, imported):
    real = run.result.Result.line
    seen = []

    def line(self, record, status, reason=""):
        if status == source.IMPORTED:
            seen.append(record)
            if len(seen) == imported:
                raise Killed()   # the file is in the store, its line is not written
        return real(self, record, status, reason)

    monkeypatch.setattr(run.result.Result, "line", line)


@pytest.mark.parametrize("mode", ["rename", "rename with a manifest", "copy"])
def test_a_run_stopped_after_a_files_move_and_before_its_line_repeats_nothing(
        world, monkeypatch, mode):
    if mode == "copy":
        monkeypatch.setattr(run, "same_filesystem", lambda *a: False)
    made = eml_corpus.corpus(world.source, n=4, refusals=False)
    manifest = None
    if mode == "rename with a manifest":
        manifest = world.tmp / "manifest.tsv"
        manifest.write_text("".join(
            f"{m.path.relative_to(world.source)}\t{hashlib.sha256(m.path.read_bytes()).hexdigest()}"
            f"\t{m.path.stat().st_size}\t\t\n" for m in made))
    with monkeypatch.context() as patched:
        killed_after(patched, 2)
        with pytest.raises(Killed):
            world.main(manifest=manifest, result_name="killed.tsv")
    assert len(world.names()) == 2
    code, lines = world.main(manifest=manifest)
    assert code == run.EX_OK
    assert len(world.names()) == 4                    # nothing twice
    assert totals(lines)[-1] == "# held before 2"
    found = statuses(lines)
    again = {n for n, (s, r) in found.items() if r == "in the store already: an earlier run took it"}
    if mode == "rename":
        # renamed before the stop, the second without its line: the source no longer has
        # either, no line here names them, and the totals say the store held them
        assert again == set() and totals(lines)[1] == "# imported 2"
    else:
        # the manifest still names them, or the copy left them: an earlier run took them
        assert len(again) == 2 and totals(lines)[1] == "# imported 4"


def test_a_file_the_pass_moved_past_without_a_row_is_counted_unrecorded_in_the_result(world):
    """A file written is not a message recorded: the pass may skip one and move its cursor
    past it. The result says how many of the run's names have no row once the pass has
    passed them; a run whose names all have one says nothing of it."""
    eml_corpus.corpus(world.source, n=6, refusals=False)
    code, lines = world.main(result_name="whole.tsv")
    assert code == run.EX_OK and not any(t.startswith("# unrecorded") for t in totals(lines))

    for n in (11, 12, 13, 14):
        eml_corpus.write(world.source, f"more-{n}.eml", eml_corpus.message(n))
    world.numbered()
    before = set(world.names())
    skipped = []

    def tick():
        # the pass skips the first and the last name it finds new
        new = [name for name in world.names() if name not in before and name not in skipped]
        if new and not skipped:
            skipped.extend([new[0], new[-1]])
            world.unrecordable.update(skipped)
        World.tick(world)

    world.tick = tick
    code, lines = world.main(result_name="skipped.tsv")
    assert code == run.EX_OK
    assert all(statuses(lines)[f"more-{n}.eml"][0] == source.IMPORTED for n in (11, 12, 13, 14))
    assert totals(lines)[-1] == "# unrecorded 2"


def test_a_run_started_again_waits_for_the_pass_to_record_what_the_last_one_left(
        world, monkeypatch, capsys):
    """A run stopped after a file and before the pass recorded it leaves a name with no
    row: its hash is known to the next run, its Message-ID is not until the pass has been
    waited for."""
    eml_corpus.write(world.source, "first.eml", eml_corpus.message(1))
    with monkeypatch.context() as patched:
        killed_after(patched, 1)
        with pytest.raises(Killed):
            world.main(result_name="killed.tsv")
    assert len(world.names()) == 1 and world.ticks == 0
    assert world.database.value("SELECT count(*) FROM message") == 0    # the pass is behind
    # the same Message-ID in other bytes
    eml_corpus.write(world.source, "again.eml",
                     eml_corpus.message(1, body="Other words, the same Message-ID."))
    # a dry run waits for nothing, and so cannot know yet
    assert run.main(world.args("--dry-run"), world.paths) == run.EX_OK and world.ticks == 0
    assert "again.eml\t" in capsys.readouterr().out
    code, lines = world.main()
    assert code == run.EX_OK and world.ticks == 1       # waited for, once, before its first file
    row = world.database.value("SELECT id FROM message")
    assert statuses(lines)["again.eml"] == (source.DUPLICATE, f"the Message-ID of message {row}")
    assert len(world.names()) == 1 and totals(lines)[-1] == "# held before 1"


def test_a_run_started_again_during_a_pause_stops_for_the_pause_before_dovecot_is_asked(
        world, monkeypatch):
    eml_corpus.corpus(world.source, n=1, refusals=False)
    assert world.main(result_name="first.tsv")[0] == run.EX_OK
    eml_corpus.write(world.source, "more.eml", eml_corpus.message(7))
    world.paths.backup_paused.write_text("{}")

    def stopped_dovecot(*a):
        raise doveadm.DoveadmError("doveadm: Error: connect(/run/dovecot/doveadm-server) failed")

    monkeypatch.setattr(doveadm, "mailbox_status", stopped_dovecot)
    code, lines = world.main()
    assert code == run.EX_STOPPED and len(world.names()) == 1
    assert lines[-1].startswith("# stopped a backup or a restore paused the machine")
    assert [line for line in lines if not line.startswith("#")] == []   # before its first file


# --- the reserve, the lock, the pauses, the pass, a deletion ------------------------------------


def test_a_copy_that_would_take_the_store_under_its_reserve_stops_the_run(world, monkeypatch):
    monkeypatch.setattr(run, "same_filesystem", lambda *a: False)
    eml_corpus.corpus(world.source, n=2, refusals=False)
    Room.short = "a copy would take the store's filesystem under the 20% free health warns at"
    code, lines = world.main()
    assert code == run.EX_STOPPED and world.names() == []
    assert lines[-1].startswith("# stopped a copy would take")


def test_the_reserve_is_health_warn_level_read_as_the_snapshot_reads_it(tmp_path, monkeypatch):
    from maildivvy.fetch import snapshot
    monkeypatch.setattr(snapshot, "reserve", lambda: (30, "single"))
    reserve = run.Reserve(tmp_path)
    monkeypatch.setattr(snapshot, "short_of", lambda fs, percent, size: f"{percent} {size}")
    with pytest.raises(run.Stop, match="under the 30% free health warns at with single disks"):
        reserve.room(10)

    def unreadable():
        raise OSError("health.conf")

    monkeypatch.setattr(snapshot, "reserve", unreadable)
    with pytest.raises(run.Stop, match="the reserve cannot be read"):
        run.Reserve(tmp_path)


def test_a_second_import_of_the_domain_is_refused_while_one_runs(world):
    eml_corpus.corpus(world.source, n=1, refusals=False)
    other = world.database.connect("pipeline")
    try:
        with other.cursor() as cur:
            assert locks.try_lock(cur, world.domain, locks.IMPORT)
        other.commit()
        code = run.main(world.args("--result", str(world.tmp / "r.tsv")), world.paths)
        assert code == run.EX_STOPPED and world.names() == []
        assert not (world.tmp / "r.tsv").exists()
    finally:
        other.close()
    # the control: with the lock free it runs
    assert world.main()[0] == run.EX_OK and len(world.names()) == 1


@pytest.mark.parametrize("record", ["backup_paused", "upgrade_paused"])
def test_a_pause_recorded_before_a_file_stops_the_run_and_the_next_run_goes_on(
        world, monkeypatch, record):
    eml_corpus.corpus(world.source, n=2, refusals=False)
    real = run.put

    def put_then_pause(*a, **k):
        how = real(*a, **k)
        getattr(world.paths, record).write_text(json.dumps({"by": "backup", "timers": []}))
        return how

    monkeypatch.setattr(run, "put", put_then_pause)
    code, lines = world.main(result_name="first.tsv")
    assert code == run.EX_STOPPED and len(world.names()) == 1
    assert "paused the machine" in lines[-1]
    getattr(world.paths, record).unlink()
    monkeypatch.setattr(run, "put", real)
    code, lines = world.main()
    assert code == run.EX_OK and len(world.names()) == 2


def test_a_pause_recorded_while_the_run_waits_for_the_pass_stops_it(world):
    eml_corpus.corpus(world.source, n=3, refusals=False)
    world.passes = False

    def sleep(seconds):
        world.paths.backup_paused.write_text("{}")

    code, stopped, lines = world.go(sleep=sleep)
    assert code == run.EX_STOPPED and "a backup or a restore paused the machine" in stopped
    assert len(world.names()) == 3


def test_a_pass_that_does_not_record_a_slice_within_the_bound_stops_the_run(world):
    eml_corpus.corpus(world.source, n=4, refusals=False)
    world.passes = False
    now = [0.0]

    def sleep(seconds):
        now[0] += 600

    code, stopped, lines = world.go(clock=lambda: now[0], sleep=sleep)
    assert code == run.EX_STOPPED
    assert stopped.startswith(f"the pass did not record the slice within {run.WAIT_BOUND} s")
    assert len(world.names()) == 3      # one slice, and no more until the pass is back
    assert lines[-1].startswith("# stopped the pass did not record")


def test_the_ledgers_rows_recorded_while_the_run_waits_deduplicate_the_next_slice(world):
    """Live collection into the same INBOX: a row the pass records meanwhile is a duplicate
    for every later file."""
    made = eml_corpus.corpus(world.source, n=6, refusals=False)
    later = [m for m in made if m.path.name == "0005.eml"][0]   # in the second slice

    def tick(seconds):
        world.tick()
        # recorded once, however often the run waits: the ledger holds a UID once
        world.database.sql("INSERT INTO message (domain_id, archive_uid, message_id_header) "
                           "VALUES (%s, 9999, %s) ON CONFLICT DO NOTHING", (world.domain, later.message_id))

    code, stopped, lines = world.go(sleep=tick)
    assert code == run.EX_OK
    live = world.database.value("SELECT id FROM message WHERE archive_uid = 9999 ORDER BY id LIMIT 1")
    assert statuses(lines)["box1/0005.eml"] == (source.DUPLICATE, f"the Message-ID of message {live}")
    assert statuses(lines)["box0/0006.eml"][0] == source.IMPORTED   # the control: before it


def test_a_domain_deletion_waits_for_a_running_import_which_stops_for_it(world, tmp_path):
    eml_corpus.corpus(world.source, n=2, refusals=False)
    asked = world.database.value(
        "INSERT INTO request (kind, target, payload, asked_by) VALUES ('delete_domain', "
        "'alpha', %s, 'olga') RETURNING id", (json.dumps({"domain_id": world.domain}),))
    # the import stops before its first file: the deletion is asked for
    code, lines = world.main(result_name="stopped.tsv")
    assert code == run.EX_STOPPED and world.names() == []
    assert f"request {asked} (delete_domain)" in lines[-1]
    # and the deletion waits for an import that holds the lock
    importer, drainer = world.database.connect("pipeline"), world.database.connect("pipeline")
    waiting = ("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted "
               "AND classid = %s AND objid = %s")
    try:
        with importer.cursor() as cur:
            assert locks.try_lock(cur, world.domain, locks.IMPORT)
        importer.commit()
        drained = []
        context = requests.Context(store_root=world.root, index_root=tmp_path / "index")
        worker = threading.Thread(target=lambda: drained.append(requests.drain(drainer, context)))
        worker.start()
        for _ in range(100):
            if world.database.value(waiting, (locks.IMPORT, world.domain)):
                break
            time.sleep(0.1)
        assert world.database.value(waiting, (locks.IMPORT, world.domain)) == 1
        assert drained == [] and world.database.value("SELECT count(*) FROM domain") == 1
        with importer.cursor() as cur:
            assert locks.unlock(cur, world.domain, locks.IMPORT)
        importer.commit()
        worker.join(30)
        assert len(drained) == 1
    finally:
        importer.close()
        drainer.close()
    # its rows went once the import let go (removing its directories needs Dovecot)
    assert world.database.value("SELECT count(*) FROM domain") == 0


def test_a_domain_that_does_not_exist_or_has_no_archive_is_refused(world, tmp_path):
    assert run.main(["incoming", "--domain", "nowhere", "--source", str(world.source),
                     "--etc", str(world.database.etc), "--result", str(tmp_path / "x.tsv")],
                    world.paths) == run.EX_FAULT
    world.database.sql("INSERT INTO domain (label, archive_password_hash) VALUES ('beta', %s)",
                       (HASH,))
    assert run.main(["incoming", "--domain", "beta", "--source", str(world.source),
                     "--etc", str(world.database.etc), "--result", str(tmp_path / "y.tsv")],
                    world.paths) == run.EX_FAULT


def test_a_file_on_the_store_filesystem_that_is_not_the_mail_owners_alone_is_refused(world):
    made = eml_corpus.corpus(world.source, n=1, refusals=False)
    os.link(made[0].path, world.tmp / "second-name")
    code, lines = world.main()
    status, reason = statuses(lines)["box1/0001.eml"]
    assert status == source.REFUSED and "with one link (owner" in reason and "2 links" in reason
    assert (world.tmp / "second-name").stat().st_nlink == 2   # left where it was
    # the control: its copy with the same bytes and one link is renamed in its place
    assert code == run.EX_OK and statuses(lines)["copies/same-bytes.eml"][0] == source.IMPORTED
    assert len(world.names()) == 1


@pytest.mark.parametrize("mode", ["renamed", "copied"])
def test_a_file_is_the_mail_owners_alone_in_the_store_whatever_mode_it_had_in_staging(
        world, monkeypatch, mode):
    if mode == "copied":
        monkeypatch.setattr(run, "same_filesystem", lambda *a: False)
    made = eml_corpus.corpus(world.source, n=3, refusals=False)[:3]   # then come the copies
    for one, staged in zip(made, (0o644, 0o444, 0o660)):
        one.path.chmod(staged)
    code, lines = world.main()
    assert code == run.EX_OK
    found = statuses(lines)
    how = "" if mode == "renamed" else "copied"
    assert [found[one.path.relative_to(world.source).as_posix()] for one in made] == [
        (source.IMPORTED, how)] * 3
    names = world.names()
    assert len(names) == 3
    assert {stat.S_IMODE((world.box / "cur" / name).stat().st_mode) for name in names} == {0o600}
    # and the moment it arrived is still its mtime: the mode is set before, not instead
    assert {int((world.box / "cur" / name).stat().st_mtime) for name in names} == {
        one.received for one in made}


def test_a_dry_run_writes_nothing_and_prints_what_it_would_give(world, capsys):
    eml_corpus.corpus(world.source, n=3)
    code = run.main(world.args("--dry-run"), world.paths)
    assert code == run.EX_OK and world.names() == []
    printed = capsys.readouterr().out.splitlines()
    assert totals(printed)[:2] == ["# total 8", "# imported 3"]
    assert not list(world.tmp.glob("*.tsv")) and not list((world.tmp / "staging").glob("*.tsv"))
    assert (world.source / "box1" / "0001.eml").exists()


def test_a_run_with_scan_refuses_the_infected_and_stops_when_clamd_is_gone(world, monkeypatch):
    eml_corpus.corpus(world.source, n=3, refusals=False)
    asked = []

    class Scanner:
        def judge(self, record):
            asked.append(record.shown)
            if record.shown == "box0/0002.eml":
                return (source.REFUSED, "infected: stream: Eicar-Signature FOUND"), record
            if record.shown == "box1/0003.eml":
                raise source.Unavailable("clamd is unavailable: closed without answering")
            return None, record

    monkeypatch.setattr(source, "Scanner", Scanner)
    code, lines = world.main("--scan")
    assert code == run.EX_STOPPED
    assert statuses(lines)["box0/0002.eml"] == (source.REFUSED,
                                                "infected: stream: Eicar-Signature FOUND")
    assert statuses(lines)["box1/0001.eml"][0] == source.IMPORTED
    assert lines[-1] == "# stopped clamd is unavailable: closed without answering"
    assert len(world.names()) == 1 and asked == ["box0/0002.eml", "box1/0001.eml", "box1/0003.eml"]


# --- the database goes away ---------------------------------------------------------------------


def drop(world, conn):
    """PostgreSQL ends the run's own session, as its restart does, and is seen to have."""
    pid = conn.get_backend_pid()
    world.database.sql("SELECT pg_terminate_backend(%s)", (pid,))
    for _ in range(200):
        if not world.database.value("SELECT count(*) FROM pg_stat_activity WHERE pid = %s", (pid,)):
            return
        time.sleep(0.05)
    raise AssertionError(f"session {pid} did not end")


@pytest.mark.parametrize("where", ["before a file", "while it waits for the pass"])
def test_a_database_that_goes_away_stops_the_run_with_75_and_the_next_run_goes_on(
        world, monkeypatch, where):
    eml_corpus.corpus(world.source, n=4, refusals=False)
    sessions = []
    connect = run.db.connect
    with monkeypatch.context() as patched:
        patched.setattr(run.db, "connect",
                        lambda *a, **k: sessions.append(connect(*a, **k)) or sessions[-1])
        if where == "before a file":
            put = run.put

            def put_then_drop(*a, **k):
                how = put(*a, **k)
                drop(world, sessions[0])   # the next file's check finds the session gone
                return how

            patched.setattr(run, "put", put_then_drop)
            held = 1
        else:
            world.passes = False
            patched.setattr(run, "pause", lambda seconds: drop(world, sessions[0]))
            held = 3                       # the slice it was waiting for
        code, lines = world.main(result_name="dropped.tsv")
    assert code == run.EX_STOPPED, lines
    assert lines[-1].startswith("# stopped the database went away (")
    assert lines[-1].endswith("): run the import again")
    assert len(world.names()) == held and totals(lines)[1] == f"# imported {held}"
    world.passes = True
    code, lines = world.main()
    assert code == run.EX_OK and len(world.names()) == 4
    assert totals(lines)[-1] == f"# held before {held}"


def test_a_database_gone_before_the_runs_first_line_stops_it_with_75_too(
        world, monkeypatch, capsys):
    eml_corpus.corpus(world.source, n=1, refusals=False)
    sessions = []
    connect = run.db.connect
    monkeypatch.setattr(run.db, "connect",
                        lambda *a, **k: sessions.append(connect(*a, **k)) or sessions[-1])
    stage_of = run.stage_of

    def dropped_first(*a, **k):
        drop(world, sessions[0])
        return stage_of(*a, **k)

    monkeypatch.setattr(run, "stage_of", dropped_first)
    code, lines = world.main()
    assert code == run.EX_STOPPED and world.names() == []
    assert lines == []       # nothing was judged: the result holds no line
    said = capsys.readouterr().err.splitlines()[-1]
    assert said.startswith("maildivvy-import: stopped: the database went away (")
    assert said.endswith("): run the import again")


def test_only_a_database_error_with_no_sqlstate_or_of_class_08_or_57_is_the_database_gone():
    class Database(Exception):
        def __init__(self, pgcode, text="the server said so\nand more"):
            super().__init__(text)
            self.pgcode = pgcode

    for pgcode in (None, "", "08006", "08P01", "57P01", "57014"):
        assert run.went_away(Database(pgcode)) == (
            "the database went away (Database: the server said so): run the import again"), pgcode
    assert run.went_away(Database(None, "")) == (
        "the database went away (Database): run the import again")
    # a statement of ours the database refused, or no database error at all: a fault
    for pgcode in ("42703", "23505", "22021", "40001", "53300", "XX000"):
        assert run.went_away(Database(pgcode)) is None, pgcode
    for other in (RuntimeError("a bug of ours"), OSError(5, "Input/output error"), KeyError("x")):
        assert run.went_away(other) is None


def test_a_statement_the_database_refuses_is_a_fault_of_ours_and_exits_1(world, monkeypatch):
    eml_corpus.corpus(world.source, n=2, refusals=False)

    class UndefinedColumn(Exception):
        pgcode = "42703"

    calls = []

    def deletion(cur, domain_id):
        calls.append(domain_id)
        if len(calls) == 2:
            raise UndefinedColumn("column \"payload\" does not exist")

    monkeypatch.setattr(run, "deletion", deletion)
    code, lines = world.main()
    assert code == run.EX_FAULT and len(world.names()) == 1
    assert lines[-1] == '# stopped a fault: UndefinedColumn: column "payload" does not exist'


def test_a_fault_of_ours_ends_the_run_with_1_and_keeps_what_it_finished(world, monkeypatch):
    eml_corpus.corpus(world.source, n=2, refusals=False)
    real = run.put
    calls = []

    def fails_second(*a, **k):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("a bug of ours")
        return real(*a, **k)

    monkeypatch.setattr(run, "put", fails_second)
    code, lines = world.main()
    assert code == run.EX_FAULT and len(world.names()) == 1
    assert lines[0].split("\t")[2] == source.IMPORTED
    assert lines[-1] == "# stopped a fault: RuntimeError: a bug of ours"
