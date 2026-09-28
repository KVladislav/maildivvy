"""The health report's own rules, kept in plain functions: the four states and their order,
a subsystem taking its worst check, the three outputs of one run agreeing, and a JSON that
has gone stale reading UNKNOWN.

The checks themselves are driven on the test VM;
what is proved here is what every check is reported through.
"""

import datetime
import json
import os
import stat

import pytest

from maildivvy.health import report
from maildivvy.health.report import FAIL, PASS, UNKNOWN, WARN, Check, Subsystem

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 23, 12, 0, tzinfo=UTC)


def subsystem(name, *states):
    return Subsystem(name, [Check(f"c{i}", state, f"read {i}",
                                  None if state == PASS else f"wrong {i}")
                            for i, state in enumerate(states)])


# --- the states and their order ------------------------------------------


def test_a_subsystem_takes_its_worst_check_and_the_whole_its_worst_subsystem():
    assert subsystem("a", PASS, PASS).state == PASS
    assert subsystem("a", PASS, WARN).state == WARN
    assert subsystem("a", WARN, UNKNOWN, PASS).state == UNKNOWN
    assert report.worst([subsystem("a", PASS).state, subsystem("b", WARN).state]) == WARN


@pytest.mark.parametrize("order", [(UNKNOWN, FAIL), (FAIL, UNKNOWN)])
def test_one_unknown_never_hides_a_fail_whichever_is_read_first(order):
    assert subsystem("a", *order).state == FAIL
    whole = report.Report(NOW, [subsystem("a", UNKNOWN), subsystem("b", FAIL)])
    assert whole.state == FAIL
    assert report.exit_code(whole.state) == 2
    # and the UNKNOWN is still reported beside it, never dropped for the FAIL
    assert "UNKNOWN" in report.text(whole)


def test_unknown_is_its_own_state_and_is_never_read_as_pass():
    assert subsystem("a", UNKNOWN).state == UNKNOWN
    assert report.exit_code(UNKNOWN) == 3
    assert report.worst([]) == UNKNOWN  # nothing read at all is not a pass


def test_a_subsystem_with_no_check_at_all_is_unknown():
    assert Subsystem("a", []).state == UNKNOWN


def test_the_exit_code_is_the_plugin_convention():
    assert [report.exit_code(s) for s in (PASS, WARN, FAIL, UNKNOWN)] == [0, 1, 2, 3]


def test_a_state_that_is_not_one_of_the_four_is_refused():
    with pytest.raises(ValueError):
        Check("x", "OK", "read")


def test_a_check_that_is_not_pass_says_what_is_wrong():
    with pytest.raises(ValueError):
        Check("x", FAIL, "read", None)


# --- the outputs of one run agree ---------------------------------------------------


def test_text_json_and_exit_code_of_one_run_say_the_same():
    whole = report.Report(NOW, [subsystem("host", PASS, PASS), subsystem("tls", WARN),
                                subsystem("store", FAIL, UNKNOWN)])
    text = report.text(whole)
    data = json.loads(report.to_json(whole))
    assert report.exit_code(whole.state) == 2
    assert data["state"] == FAIL and text.splitlines()[0].startswith("FAIL")
    assert [(s["name"], s["state"]) for s in data["subsystems"]] == [
        ("host", PASS), ("tls", WARN), ("store", FAIL)]
    for block in data["subsystems"]:
        assert f"{block['state']} {block['name']}" in text
        for check in block["checks"]:
            assert check["reading"] in text
            if check["state"] != PASS:
                assert check["problem"] in text
    assert data["taken_at"] == "2026-09-23T12:00:00+00:00"
    assert data["complete"] is True


def test_the_text_gives_every_check_its_reading_and_a_sentence_when_not_pass():
    whole = report.Report(NOW, [Subsystem("backup", [
        Check("newest run", FAIL, "20260920T000000Z, 84 h old", "older than the 48 h bound")])])
    text = report.text(whole)
    assert "FAIL backup" in text
    assert "newest run: 20260920T000000Z, 84 h old" in text
    assert "older than the 48 h bound" in text


def test_quiet_text_names_only_what_is_not_pass():
    whole = report.Report(NOW, [subsystem("host", PASS), subsystem("tls", WARN)])
    quiet = report.text(whole, quiet=True)
    assert "tls" in quiet and "host" not in quiet
    assert quiet.splitlines()[0].startswith("WARN")


def test_the_json_file_is_written_whole_and_readable_by_the_collector(tmp_path):
    path = tmp_path / "health.json"
    whole = report.Report(NOW, [subsystem("host", PASS)])
    report.write_json(path, whole)
    assert json.loads(path.read_text())["state"] == PASS
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
    assert not list(tmp_path.glob(".*"))  # nothing half-written left beside it


# --- a stale JSON reads UNKNOWN -----------------------------------------------


def written(tmp_path, taken_at, *subsystems):
    path = tmp_path / "health.json"
    report.write_json(path, report.Report(taken_at, list(subsystems)))
    return path


def test_a_fresh_json_reads_as_it_was_written(tmp_path):
    path = written(tmp_path, NOW - datetime.timedelta(minutes=4), subsystem("host", PASS))
    read = report.read_json(path, NOW, stale_after=datetime.timedelta(minutes=15))
    assert read.state == PASS
    assert [s.name for s in read.subsystems] == ["host"]


def test_a_stale_json_reads_unknown_in_every_subsystem(tmp_path):
    path = written(tmp_path, NOW - datetime.timedelta(minutes=16), subsystem("host", PASS),
                   subsystem("tls", WARN))
    read = report.read_json(path, NOW, stale_after=datetime.timedelta(minutes=15))
    assert read.state == UNKNOWN
    assert [s.state for s in read.subsystems] == [UNKNOWN, UNKNOWN]
    assert "the checks have stopped" in report.text(read)


def test_a_stale_fail_is_still_a_fail_and_says_it_is_stale(tmp_path):
    """A problem already found is not unfound by the checks stopping."""
    path = written(tmp_path, NOW - datetime.timedelta(hours=2), subsystem("store", FAIL))
    read = report.read_json(path, NOW, stale_after=datetime.timedelta(minutes=15))
    assert read.state == FAIL
    assert [c.state for c in read.subsystems[0].checks] == [FAIL, UNKNOWN]


@pytest.mark.parametrize("content", [None, "", "{", "[]", '{"state": "PASS"}',
                                     '{"taken_at": "2026-09-23T11:59:00+00:00", "state": "PASS", '
                                     '"subsystems": [], "complete": false}'])
def test_a_json_that_is_missing_truncated_or_incomplete_reads_unknown_never_pass(tmp_path, content):
    path = tmp_path / "health.json"
    if content is not None:
        path.write_text(content)
    read = report.read_json(path, NOW, stale_after=datetime.timedelta(minutes=15))
    assert read.state == UNKNOWN
    assert report.exit_code(read.state) == 3


def test_a_json_from_the_future_is_not_fresh(tmp_path):
    path = written(tmp_path, NOW + datetime.timedelta(hours=1), subsystem("host", PASS))
    read = report.read_json(path, NOW, stale_after=datetime.timedelta(minutes=15))
    assert read.state == UNKNOWN


def test_one_subsystem_is_read_out_of_the_json_on_its_own(tmp_path):
    path = written(tmp_path, NOW, subsystem("host", PASS), subsystem("tls", FAIL))
    read = report.read_json(path, NOW, stale_after=datetime.timedelta(minutes=15))
    assert read.only("tls").state == FAIL
    assert read.only("host").state == PASS
    assert read.only("backup").state == UNKNOWN  # a subsystem the file does not hold
