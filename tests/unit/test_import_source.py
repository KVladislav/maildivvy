"""The import's source: reading a directory of message files or its manifest, the checks,
the received moment, the flags, deduplication and the result file.

Synthetic mail only, from `eml_corpus.py`.
"""

import hashlib
import io
import os
from pathlib import Path

import pytest

import eml_corpus
import test_scan
from maildivvy.importer import result, source
from maildivvy.lib import messageid, store

INCOMING, SENT = source.INCOMING, source.SENT


def by_name(records):
    return {r.shown: r for r in records}


# --- the directory ------------------------------------------------------------------------------


def test_a_directory_is_read_sorted_and_recursively_each_file_whole(tmp_path):
    made = eml_corpus.corpus(tmp_path / "src", n=6, refusals=False)
    records = list(source.records(tmp_path / "src", INCOMING))
    assert [r.shown for r in records] == [m.path.relative_to(tmp_path / "src").as_posix() for m in made]
    for record, file in zip(records, made):
        data = file.path.read_bytes()
        assert (record.sha256, record.size) == (hashlib.sha256(data).hexdigest(), len(data))
        assert record.refused is None, record
        assert record.received == file.received, record.shown
        assert record.message_id == file.message_id


def test_each_file_an_import_cannot_take_is_refused_with_its_reason(tmp_path):
    eml_corpus.corpus(tmp_path / "src", n=1)
    (tmp_path / "src" / "fifo").mkdir()
    os.mkfifo(tmp_path / "src" / "fifo" / "pipe")
    unreadable = eml_corpus.write(tmp_path / "src", "unreadable.eml", eml_corpus.message(9))
    unreadable.chmod(0)
    (tmp_path / "src" / "dirlink").symlink_to(tmp_path / "src" / "box1")
    found = by_name(source.records(tmp_path / "src", INCOMING))
    assert found["empty.eml"].refused == "empty"
    assert found["mbox.eml"].refused == "no header section"
    assert found["link.eml"].refused == "a symlink, which is never followed"
    assert found["dirlink"].refused == "a symlink, which is never followed"
    assert found["fifo/pipe"].refused == "not a regular file"
    if os.geteuid() != 0:   # root reads it anyway
        assert found["unreadable.eml"].refused.startswith("unreadable:")
    assert found["box1/0001.eml"].refused is None   # the control


def test_a_header_section_starts_the_file_and_ends_at_its_first_empty_line():
    assert source.header_section(b"Subject: a\r\n folded\r\n\r\nbody: not a header") == \
        [b"Subject: a", b" folded"]
    assert source.header_section(b"Subject: no body at all") == [b"Subject: no body at all"]
    for head in (b"\r\nSubject: after a blank line", b"From x Tue\nSubject: mbox", b"just text"):
        assert source.header_section(head) is None, head


def test_the_message_id_is_its_first_occurrence_unfolded_as_the_pass_stores_it():
    section = source.header_section(
        b"message-id:\r\n  <folded@example.org>\r\nMessage-ID: <second@example.org>\r\n")
    assert source.first_value(section, "Message-ID") == "<folded@example.org>"
    assert source.first_value(section, "Date") == ""
    # a Message-ID past the ledger's bound is deduplicated in the form the ledger stores
    long = "<" + "x" * 600 + "@example.org>"
    record = source.read(eml_corpus.write(Path(os.environ.get("TMPDIR", "/tmp")) / "eml-long",
                                          "long.eml", eml_corpus.message(1, message_id=long)),
                         "long.eml", INCOMING)
    assert record.message_id == messageid.stored(long) and record.message_id.startswith("sha256:")


# --- the size over IMAP -------------------------------------------------------------------------


def test_the_size_over_imap_is_the_files_with_every_bare_line_feed_counted_twice(
        tmp_path, monkeypatch):
    # the count this test checks the import's against, on bytes whose answer is plain
    for data, bare in ((b"a\r\nb\r\n", 0), (b"a\nb\n", 2), (b"a\rb\r", 0), (b"\n", 1),
                       (b"\r\n\n\r", 1), (b"a\r\r\nb", 0), (b"no line end", 0)):
        assert eml_corpus.virtual_size(data) == len(data) + bare, data
    shapes = eml_corpus.line_ends(astride=source.CHUNK)
    for name, data in shapes.items():
        record = source.read(eml_corpus.write(tmp_path, f"{name}.eml", data), name, INCOMING)
        assert record.refused is None, (name, record.refused)
        assert (record.size, record.vsize) == (len(data), eml_corpus.virtual_size(data)), name
    sizes = {name: (len(data), eml_corpus.virtual_size(data)) for name, data in shapes.items()}
    assert sizes["crlf"][0] == sizes["crlf"][1] and sizes["astride"][0] == sizes["astride"][1]
    assert sizes["lf"][1] == sizes["lf"][0] + shapes["lf"].count(b"\n") > sizes["lf"][0]
    assert sizes["bare-cr"][0] == sizes["bare-cr"][1]         # a carriage return alone adds nothing
    assert sizes["mixed"][1] == sizes["mixed"][0] + 2              # its two bare line feeds
    # whatever the chunks it is read in: a CR that ends one and the LF that starts the next
    # are one line end
    del shapes["astride"]
    for chunk in (1, 2, 3, 7):
        monkeypatch.setattr(source, "CHUNK", chunk)
        for name, data in shapes.items():
            record = source.read(tmp_path / f"{name}.eml", name, INCOMING)
            assert (record.sha256, record.vsize) == (
                hashlib.sha256(data).hexdigest(), eml_corpus.virtual_size(data)), (chunk, name)


def test_a_line_feed_that_starts_a_chunk_is_bare_unless_the_chunk_before_ended_in_cr():
    assert source.bare_line_feeds(b"\nabc\n", after_cr=False) == 2
    assert source.bare_line_feeds(b"\nabc\n", after_cr=True) == 1
    assert source.bare_line_feeds(b"abc\r", after_cr=True) == 0
    assert source.bare_line_feeds(b"\r\n\r", after_cr=True) == 0


def test_the_imported_name_carries_the_files_size_and_its_size_over_imap():
    sha = "a" * 64
    base = store.import_base(1458000000, sha, 2023, 2053)
    assert base == f"1458000000.{sha}.import,S=2023,W=2053"
    assert store.IMPORTED.match(base).groups() == ("1458000000", sha, "2023", "2053")
    assert store.imported(base) == 1458000000
    # a line feed adds one byte at most and takes none: no other size is a message's
    for size, vsize in ((10, 9), (10, 21)):
        with pytest.raises(store.StoreError):
            store.import_base(1458000000, sha, size, vsize)


# --- the received moment ------------------------------------------------------------------------


def test_the_received_moment_is_the_manifests_else_the_date_else_the_mtime():
    mtime = eml_corpus.MTIME   # after both dates, as a file written out of an old store is
    assert source.received_of("2016-03-15T06:00:00Z", eml_corpus.UNZONED, 0) == (
        eml_corpus.ZONED_EPOCH, None, ())
    assert source.received_of("2016-03-15T09:00:00+03:00", None, 0) == (
        eml_corpus.ZONED_EPOCH, None, ())
    assert source.received_of(None, eml_corpus.ZONED, mtime) == (eml_corpus.ZONED_EPOCH, None, ())
    assert source.received_of(None, eml_corpus.UNZONED, mtime) == (
        eml_corpus.UNZONED_EPOCH, None, ())
    assert source.received_of(None, "not a date", 5.7) == (5, None, ())
    assert source.received_of(None, "Thu, 01 Jan 1960 00:00:00 +0000", 5) == (5, None, ())
    assert source.received_of(None, None, mtime) == (mtime, None, ())


def test_a_received_moment_that_cannot_be_read_refuses_the_file():
    for given in ("2016-03-15T06:00:00", "yesterday", "1960-01-01T00:00:00Z"):
        seconds, refused, notes = source.received_of(given, eml_corpus.ZONED, 5)
        assert seconds is None and "cannot be read" in refused and notes == (), given
    seconds, refused, notes = source.received_of(None, None, -5)
    assert seconds is None and "before 1970" in refused


NOT_BELIEVED = "its Date is more than a day after the file's mtime: the mtime is taken"


def test_a_date_header_later_than_the_files_mtime_plus_a_day_is_not_believed():
    mtime = eml_corpus.ZONED_EPOCH + 3 * 3600      # written three hours after its Date
    # a sender's date years ahead, as old spam carries: the mtime, and the line says so
    assert source.received_of(None, "Fri, 13 Feb 2099 12:00:00 +0000", mtime) == (
        mtime, None, (NOT_BELIEVED,))
    # a few hours ahead of the mtime, a zone slip: kept, as is one a day ahead to the second
    ahead = "Tue, 15 Mar 2016 14:00:00 +0000"       # five hours after the mtime
    assert source.received_of(None, ahead, mtime) == (eml_corpus.ZONED_EPOCH + 8 * 3600, None, ())
    assert source.received_of(None, eml_corpus.ZONED, eml_corpus.ZONED_EPOCH - source.DAY) == (
        eml_corpus.ZONED_EPOCH, None, ())
    assert source.received_of(None, eml_corpus.ZONED, eml_corpus.ZONED_EPOCH - source.DAY - 1) == (
        eml_corpus.ZONED_EPOCH - source.DAY - 1, None, (NOT_BELIEVED,))
    # a date before the mtime is believed however old
    assert source.received_of(None, "Thu, 01 Jan 1970 00:00:01 +0000", mtime) == (1, None, ())
    # no mtime to take in its place: no received moment
    seconds, refused, notes = source.received_of(None, "Fri, 13 Feb 2099 12:00:00 +0000", -5)
    assert seconds is None and "before 1970" in refused


def test_a_manifests_received_moment_later_than_the_runs_start_refuses_the_file():
    started = 1763510400                             # 2025-11-19T00:00:00Z
    assert source.received_of("2025-11-19T00:00:00Z", None, 0, started) == (started, None, ())
    seconds, refused, notes = source.received_of("2025-11-19T00:00:01Z", None, 0, started)
    assert seconds is None and notes == ()
    assert refused == "received '2025-11-19T00:00:01Z' is later than the start of this run"
    # with no start given it is now: a moment years ahead is refused, yesterday's is taken
    assert source.received_of("2099-02-13T12:00:00Z", eml_corpus.ZONED, 0)[0] is None
    assert source.received_of("2016-03-15T06:00:00Z", None, 0)[0] == eml_corpus.ZONED_EPOCH


def test_a_file_dated_ahead_takes_its_mtime_and_its_line_says_so_beside_the_dropped_flags(tmp_path):
    ahead = eml_corpus.message(1, date="Fri, 13 Feb 2099 12:00:00 +0000")
    path = eml_corpus.write(tmp_path / "src", "ahead.eml", ahead)
    digest = hashlib.sha256(ahead).hexdigest()
    record = source.read(path, "ahead.eml", INCOMING)
    assert (record.received, record.refused, record.notes) == (eml_corpus.MTIME, None, (NOT_BELIEVED,))
    # through a manifest with no moment of its own, the same, before the flags' note
    rows = [("ahead.eml", digest, len(ahead), "", "FS")]
    [record] = source.records(tmp_path / "src", INCOMING, manifest(tmp_path, rows))
    assert record.received == eml_corpus.MTIME and record.notes == (
        NOT_BELIEVED, "flags F dropped: an archive's name carries S alone")
    out = io.StringIO()
    result.Result(out).line(record, source.IMPORTED)
    assert out.getvalue() == (f"ahead.eml\t{digest}\timported\t{NOT_BELIEVED}; flags F dropped: "
                              "an archive's name carries S alone\n")
    # the manifest's own moment is believed over the Date, unless it is ahead of the run
    rows = [("ahead.eml", digest, len(ahead), "2016-03-15T06:00:00Z", "S")]
    [record] = source.records(tmp_path / "src", INCOMING, manifest(tmp_path, rows))
    assert (record.received, record.notes) == (eml_corpus.ZONED_EPOCH, ())
    rows = [("ahead.eml", digest, len(ahead), "2099-02-13T12:00:00Z", "S")]
    [record] = source.records(tmp_path / "src", INCOMING, manifest(tmp_path, rows))
    assert record.received is None and "later than the start of this run" in record.refused
    [record] = source.records(tmp_path / "src", INCOMING, manifest(tmp_path, rows),
                              started=4102444800)   # a run in 2100 takes it
    assert record.refused is None and record.received == 4074667200


# --- the flags ----------------------------------------------------------------------------------


def test_incoming_mail_keeps_seen_alone_and_says_which_flags_it_dropped():
    assert source.flags_of(None, INCOMING) == ("S", None, ())
    assert source.flags_of("", INCOMING) == ("", None, ())
    flags, refused, notes = source.flags_of("SRF", INCOMING)
    assert (flags, refused) == ("S", None) and notes == (
        "flags F, R dropped: an archive's name carries S alone",)
    assert source.flags_of("DR", INCOMING)[0] == ""


def test_a_sent_message_keeps_every_flag_in_name_order():
    assert source.flags_of("SRFD", SENT) == ("DFRS", None, ())


def test_a_deleted_flag_or_a_letter_maildir_has_not_refuses_the_file():
    for stage in (INCOMING, SENT):
        assert "deleted" in source.flags_of("ST", stage)[1]
        assert "not Maildir's" in source.flags_of("SX", stage)[1]
        assert "not Maildir's" in source.flags_of("s", stage)[1]


# --- the manifest -------------------------------------------------------------------------------


def manifest(tmp_path, rows, header=True):
    path = tmp_path / "manifest.tsv"
    lines = ["path\tsha256\tsize\treceived\tflags"] if header else []
    lines += ["# a comment", ""] + ["\t".join(str(f) for f in row) for row in rows]
    path.write_text("\n".join(lines) + "\n")
    return path


def test_a_manifest_row_names_the_file_its_hash_its_size_its_moment_and_flags(tmp_path):
    made = eml_corpus.corpus(tmp_path / "src", n=2, refusals=False)
    first, second = made[0].path, made[1].path
    rows = [(first.relative_to(tmp_path / "src"), hashlib.sha256(first.read_bytes()).hexdigest(),
             first.stat().st_size, "2001-09-09T01:46:40Z", "RS"),
            (second.relative_to(tmp_path / "src"), hashlib.sha256(second.read_bytes()).hexdigest(),
             second.stat().st_size, "", "")]
    records = list(source.records(tmp_path / "src", SENT, manifest(tmp_path, rows)))
    assert [r.shown for r in records] == [str(row[0]) for row in rows]
    assert (records[0].received, records[0].flags, records[0].refused) == (1000000000, "RS", None)
    # an empty received is the message's own Date, an empty flags field no flag
    assert (records[1].received, records[1].flags) == (made[1].received, "")


def test_a_manifest_row_that_disagrees_with_its_file_or_is_malformed_refuses_that_file(tmp_path):
    made = eml_corpus.corpus(tmp_path / "src", n=2, refusals=False)
    first = made[0].path
    good = hashlib.sha256(first.read_bytes()).hexdigest()
    rel = first.relative_to(tmp_path / "src")
    rows = [(rel, "0" * 64, first.stat().st_size, "", "S"),        # another hash
            (made[1].path.relative_to(tmp_path / "src"),
             hashlib.sha256(made[1].path.read_bytes()).hexdigest(), 1, "", "S"),   # another size
            ("../outside.eml", good, 1, "", "S"),
            ("missing.eml", good, 1, "", "S"),
            ("x.eml", "not-a-hash", 1, "", "S"),
            ("too", "few")]
    found = list(source.records(tmp_path / "src", INCOMING, manifest(tmp_path, rows)))
    reasons = [r.refused for r in found]
    assert "not the manifest's" in reasons[0] and "not the manifest's" in reasons[1]
    assert reasons[2] == "outside the source"
    assert found[3].gone and reasons[3] == "the manifest names it and it is not there"
    assert "malformed" in reasons[4] and "has 2 fields" in reasons[5]
    # named twice: the second row is refused
    twice = list(source.records(tmp_path / "src", INCOMING, manifest(
        tmp_path, [(rel, good, first.stat().st_size, "", "S")] * 2)))
    assert twice[0].refused is None and "named twice" in twice[1].refused


def test_a_source_or_manifest_that_cannot_be_read_stops_the_run_before_any_file(tmp_path):
    with pytest.raises(source.SourceError, match="not a directory"):
        source.records(tmp_path / "nothing", INCOMING)
    (tmp_path / "src").mkdir()
    with pytest.raises(source.SourceError, match="cannot be read"):
        list(source.records(tmp_path / "src", INCOMING, tmp_path / "no-manifest"))


# --- deduplication ------------------------------------------------------------------------------


def test_duplicates_in_the_source_and_against_the_ledger_and_the_store(tmp_path):
    made = eml_corpus.corpus(tmp_path / "src", n=6, refusals=False)
    records = by_name(source.records(tmp_path / "src", INCOMING))
    ledger_held = records["box1/0005.eml"]
    store_held = records["box0/0004.eml"]   # no Message-ID: its hash in the store
    seen = source.Seen(held={store_held.sha256})
    seen.add_ids([(ledger_held.message_id, 77), (None, 78)])
    judged = {}
    for name, record in sorted(records.items()):
        verdict = seen.judge(record)
        if verdict is None:
            seen.took(record)
        judged[name] = verdict
    assert judged["box1/0005.eml"] == (source.DUPLICATE, "the Message-ID of message 77")
    assert judged["box0/0004.eml"] == (source.IMPORTED, "in the store already: an earlier run took it")
    assert judged["box1/0001.eml"] is None
    assert judged["copies/same-bytes.eml"] == (source.DUPLICATE, "the same bytes as box1/0001.eml")
    assert judged["copies/same-id.eml"] == (source.DUPLICATE, "the Message-ID of box1/0001.eml")
    assert [n for n, v in judged.items() if v is None] == [
        "box0/0002.eml", "box0/0006.eml", "box1/0001.eml", "box1/0003.eml"]
    assert len(made) == 8


def test_a_manifest_row_whose_file_was_renamed_by_an_earlier_run_is_imported(tmp_path):
    gone = source.Record(tmp_path / "x.eml", "x.eml", sha256="a" * 64, size=3, gone=True,
                         refused="the manifest names it and it is not there")
    assert source.Seen(held={"a" * 64}).judge(gone) == (
        source.IMPORTED, "in the store already: an earlier run took it")
    assert source.Seen().judge(gone) == (source.REFUSED, "the manifest names it and it is not there")


# --- the result ---------------------------------------------------------------------------------


def test_the_result_is_a_line_per_file_then_the_totals(tmp_path):
    out = io.StringIO()
    run = result.Result(out, held_before=3)
    a = source.Record(Path("a"), "dir/a\tb.eml", sha256="a" * 64,
                      notes=("flags R dropped: an archive's name carries S alone",))
    run.line(a, source.IMPORTED)
    run.line(source.Record(Path("b"), "b.eml"), source.REFUSED, "empty")
    run.line(source.Record(Path("c"), "c.eml", sha256="c" * 64), source.DUPLICATE,
             "the Message-ID of message 9")
    run.totals(stopped="a backup paused the machine")
    assert out.getvalue().splitlines() == [
        f"dir/a\\tb.eml\t{'a' * 64}\timported\tflags R dropped: an archive's name carries S alone",
        "b.eml\t\trefused\tempty",
        f"c.eml\t{'c' * 64}\tduplicate\tthe Message-ID of message 9",
        "# total 3", "# imported 1", "# duplicate 1", "# refused 1", "# held before 3",
        "# stopped a backup paused the machine"]
    assert all(len(line.split("\t")) == 4 for line in out.getvalue().splitlines()[:3])


def test_the_result_file_is_beside_the_source_and_never_one_that_is_there(tmp_path):
    import datetime
    path = result.path_for(tmp_path / "src", datetime.datetime(2026, 11, 19, 1, 2, 3,
                                                               tzinfo=datetime.UTC))
    assert path == tmp_path / "src.import-20261119T010203Z.tsv"
    with result.open_new(path) as out:
        out.write("x\n")
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        result.open_new(path)


def refuse_writes(monkeypatch):
    """Every open for writing fails the test: what a dry run must never do."""
    real = os.open

    def opened(path, flags, *a, **k):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC), (path, flags)
        return real(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", opened)


def test_a_dry_run_reads_a_read_only_tree_and_prints_its_results(tmp_path, monkeypatch):
    eml_corpus.corpus(tmp_path / "src", n=6)
    for directory in [tmp_path / "src", *(p for p in (tmp_path / "src").rglob("*")
                                          if p.is_dir() and not p.is_symlink())]:
        directory.chmod(0o555)
    out = io.StringIO()
    try:
        with monkeypatch.context() as patched:
            refuse_writes(patched)
            run = result.Result(out)
            seen = source.Seen()
            for record in source.records(tmp_path / "src", INCOMING):
                verdict = seen.judge(record)
                if verdict is None:
                    seen.took(record)
                    verdict = (source.IMPORTED, "")
                run.line(record, *verdict)
            run.totals()
    finally:
        for directory in [tmp_path / "src", *(tmp_path / "src").rglob("*")]:
            if directory.is_dir() and not directory.is_symlink():
                directory.chmod(0o755)
    assert out.getvalue().splitlines()[-5:] == [
        "# total 11", "# imported 6", "# duplicate 2", "# refused 3", "# held before 0"]


# --- `--scan`: clamd's answers, against the stand-in daemon of `test_scan.py` -------------------

@pytest.fixture
def daemon(tmp_path):
    """A stand-in clamd on a socket of its own, as `test_scan.py` starts one."""
    made = []

    def start(serve, name="daemon.sock"):
        made.append(test_scan.Daemon(tmp_path / name, serve))
        return made[-1]

    yield start
    for one in made:
        one.close()


answering, failing = test_scan.answering, test_scan.failing


def scanner_on(path, limit=1 << 20):
    from maildivvy.lib import scan
    return source.Scanner(scan=lambda body, max_bytes: scan.scan_virus(
        body, path=path, max_bytes=max_bytes, ping_timeout=2), limit=limit)


def one_record(tmp_path, data=None):
    path = eml_corpus.write(tmp_path / "src", "one.eml", data or eml_corpus.message(1))
    return source.read(path, "one.eml", INCOMING)


def test_a_clean_file_goes_on_and_an_infected_one_is_refused_with_its_detection(tmp_path, daemon):
    record = one_record(tmp_path)
    clean = daemon(answering("stream: OK"), "clean.sock")
    assert scanner_on(clean.path).judge(record) == (None, record)
    assert clean.seen == [("zINSTREAM", record.path.read_bytes())]   # the bytes it imports
    found = daemon(answering("stream: Eicar-Signature FOUND"), "found.sock")
    verdict, _ = scanner_on(found.path).judge(record)
    assert verdict == (source.REFUSED, "infected: stream: Eicar-Signature FOUND")


def test_a_file_over_the_scan_limit_is_imported_and_its_line_says_nobody_looked(tmp_path, daemon):
    record = one_record(tmp_path)
    nobody = daemon(answering("stream: OK"), "nobody.sock")
    verdict, noted = scanner_on(nobody.path, limit=10).judge(record)
    assert verdict is None and nobody.seen == []          # the socket never contacted
    assert noted.notes == (f"not scanned: {record.size} bytes is over the 10-byte scan limit",)
    # cut short at one of the daemon's own limits: the same, in its words
    limits = daemon(answering("stream: Heuristics.Limits.Exceeded.MaxScanTime FOUND"), "lim.sock")
    verdict, noted = scanner_on(limits.path).judge(record)
    assert verdict is None and noted.notes[0].startswith("not scanned: clamd: stream: Heuristics")


def test_a_file_the_daemon_fails_on_while_it_answers_ping_is_refused(tmp_path, daemon):
    record = one_record(tmp_path)
    one = daemon(failing("Error processing command. ERROR"), "fail.sock")
    verdict, _ = scanner_on(one.path).judge(record)
    assert verdict[0] == source.REFUSED and verdict[1].startswith("the scanner failed on it")
    assert one.seen == ["zINSTREAM", "zPING"]


def test_clamd_unavailable_stops_the_run(tmp_path, daemon):
    record = one_record(tmp_path)
    gone = daemon(failing("Error processing command. ERROR", pong=False), "gone.sock")
    with pytest.raises(source.Unavailable, match="clamd is unavailable"):
        scanner_on(gone.path).judge(record)
    with pytest.raises(source.Unavailable):
        scanner_on(tmp_path / "nobody-listens.sock").judge(record)


def test_a_file_changed_since_it_was_read_is_not_scanned_but_refused(tmp_path, daemon):
    record = one_record(tmp_path)
    record.path.write_bytes(b"Subject: other bytes\r\n\r\nnow\r\n")
    clean = daemon(answering("stream: OK"), "clean.sock")
    assert scanner_on(clean.path).judge(record)[0] == (source.REFUSED, "it changed after it was read")
    assert clean.seen == []
