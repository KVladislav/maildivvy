"""Health's Prometheus rendering and its textfile-collector file.

A third rendering of one run beside the text and the JSON: every check and subsystem
with the JSON's state as 0 PASS, 1 WARN, 2 FAIL, 3 UNKNOWN, and the run's time; written
into a directory only when one is configured, by a whole run alone, and replaced whole.
"""

import datetime
import json
import os
import re
import stat
from pathlib import Path

import jinja2
import pytest
import yaml

from maildivvy.health import checks, report, run
from maildivvy.health.report import FAIL, PASS, UNKNOWN, WARN, Check, Subsystem
from maildivvy_preflight import HEALTH_USER, setting_errors, textfile_dir_errors

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 23, 12, 0, 30, 250000, tzinfo=UTC)
HEALTH = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health"
VALUE = {PASS: 0, WARN: 1, FAIL: 2, UNKNOWN: 3}

LINE = re.compile(r'^(?P<name>[a-z_]+)(?:\{(?P<labels>.*)\})? (?P<value>\S+)$')
LABEL = re.compile(r'([a-z_]+)="((?:[^"\\\n]|\\[\\"n])*)"(?:,|$)')


def unescape(value):
    return re.sub(r'\\([\\"n])', lambda m: "\n" if m.group(1) == "n" else m.group(1), value)


def parse(text):
    """The exposition text as {metric: {labels as a sorted tuple: value}}, strictly: every
    line a comment, a HELP or TYPE, or a sample whose labels parse whole; no series twice."""
    found, helps, types = {}, set(), {}
    for line in text.splitlines():
        if line.startswith("# HELP "):
            name = line.split(" ", 3)[2]
            assert name not in helps, f"HELP twice for {name}"
            helps.add(name)
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            types[name] = kind
            continue
        if line.startswith("#") or not line:
            continue
        sample = LINE.match(line)
        assert sample, f"not a sample line: {line!r}"
        labels = sample["labels"] or ""
        pairs = LABEL.findall(labels)
        assert "".join(f'{k}="{v}",' for k, v in pairs).rstrip(",") == labels, f"labels: {line!r}"
        key = tuple(sorted((k, unescape(v)) for k, v in pairs))
        series = found.setdefault(sample["name"], {})
        assert key not in series, f"series twice: {line!r}"
        series[key] = float(sample["value"])
    for name in found:
        assert name in helps and types.get(name) == "gauge", name
    return found


def subsystem(name, *states):
    return Subsystem(name, [Check(f"c{i}", state, f"read {i}", None if state == PASS else f"wrong {i}")
                            for i, state in enumerate(states)])


def sample_report():
    return report.Report(NOW, [subsystem("host", PASS, WARN), subsystem("tls", PASS),
                               subsystem("store", FAIL, UNKNOWN), subsystem("search", UNKNOWN)])


# --- the rendering ------------------------------------------------------------------------------


def test_every_subsystem_and_check_carries_the_state_the_json_gives_it():
    whole = sample_report()
    data = json.loads(report.to_json(whole))
    metrics = parse(report.to_prometheus(whole))
    checks_seen = metrics["maildivvy_check_state"]
    subsystems_seen = metrics["maildivvy_subsystem_state"]
    expected_checks = {(("check", c["name"]), ("subsystem", s["name"])): VALUE[c["state"]]
                       for s in data["subsystems"] for c in s["checks"]}
    assert checks_seen == expected_checks
    assert subsystems_seen == {(("subsystem", s["name"]),): VALUE[s["state"]]
                               for s in data["subsystems"]}


def test_the_values_are_the_plugin_exit_codes_of_the_same_states():
    assert {state: report.exit_code(state) for state in VALUE} == VALUE
    whole = report.Report(NOW, [subsystem(f"s{v}", state) for state, v in VALUE.items()])
    found = parse(report.to_prometheus(whole))["maildivvy_subsystem_state"]
    assert found == {(("subsystem", f"s{v}"),): v for v in VALUE.values()}


def test_the_last_run_timestamp_is_the_reports_own_time_in_seconds():
    found = parse(report.to_prometheus(sample_report()))
    assert found["maildivvy_health_last_run_timestamp_seconds"] == {(): NOW.timestamp()}


@pytest.mark.parametrize("name", ['a "quoted" name', "back\\slash", "two\nlines", 'all \\ " \n', "ümlaut ok"])
def test_label_values_are_escaped_as_the_exposition_format_requires(name):
    whole = report.Report(NOW, [Subsystem(name, [Check(name, WARN, "read", "wrong")])])
    text = report.to_prometheus(whole)
    assert "\n\n" not in text.strip("\n")   # a newline in a label never breaks a line
    found = parse(text)
    assert found["maildivvy_check_state"] == {(("check", name), ("subsystem", name)): 1}
    assert found["maildivvy_subsystem_state"] == {(("subsystem", name),): 1}


def test_a_report_with_no_subsystem_still_says_when_it_ran():
    found = parse(report.to_prometheus(report.Report(NOW, [])))
    assert found == {"maildivvy_health_last_run_timestamp_seconds": {(): NOW.timestamp()}}


# --- the textfile-collector file ----------------------------------------------------------------


def test_the_textfile_is_written_whole_and_readable_by_the_collector(tmp_path):
    report.write_textfile(tmp_path, sample_report())
    path = tmp_path / report.TEXTFILE
    assert path.name.endswith(".prom")   # the collector reads *.prom and nothing else
    assert parse(path.read_text()) == parse(report.to_prometheus(sample_report()))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
    assert sorted(p.name for p in tmp_path.iterdir()) == [report.TEXTFILE]  # nothing half-written


def fake_run(names=None, conf=None, now=None):
    chosen = names or list(checks.SUBSYSTEMS)
    return report.Report(NOW, [subsystem(n, FAIL if n == "store" else PASS) for n in chosen])


def test_the_command_prints_prometheus_and_exits_with_the_worst_state(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(checks, "run", fake_run)
    args = ["--report", str(tmp_path / "health.json"), "--conf", str(tmp_path / "none.conf")]
    assert run.main(args + ["--format", "prometheus"]) == 2
    found = parse(capsys.readouterr().out)
    data = json.loads((tmp_path / "health.json").read_text())
    assert found["maildivvy_subsystem_state"] == {(("subsystem", s["name"]),): VALUE[s["state"]]
                                                  for s in data["subsystems"]}
    # and the cached report renders the same, with its own time
    assert run.main(args + ["--format", "prometheus", "--cached"]) == 2   # stale, and the FAIL stays
    cached = parse(capsys.readouterr().out)
    assert cached["maildivvy_health_last_run_timestamp_seconds"] == {(): NOW.timestamp()}
    assert cached["maildivvy_subsystem_state"][(("subsystem", "store"),)] == 2   # a stale FAIL stays


def test_only_a_whole_run_writes_the_textfile_and_only_when_a_directory_is_given(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(checks, "run", fake_run)
    metrics = tmp_path / "metrics"
    metrics.mkdir()
    args = ["--report", str(tmp_path / "health.json"), "--conf", str(tmp_path / "none.conf")]
    assert run.main(args) == 2
    assert not list(metrics.iterdir())
    assert run.main(args + ["--subsystem", "host", "--textfile-dir", str(metrics)]) == 0
    assert run.main(args + ["--cached", "--textfile-dir", str(metrics)]) == 2
    assert not list(metrics.iterdir())
    assert run.main(args + ["--quiet", "--textfile-dir", str(metrics)]) == 2
    written = parse((metrics / report.TEXTFILE).read_text())
    assert written == parse(report.to_prometheus(report.read_json(
        tmp_path / "health.json", NOW, datetime.timedelta(minutes=15))))
    assert capsys.readouterr().out.startswith("FAIL maildivvy-health")   # the text still printed


def test_a_run_that_cannot_run_prints_a_comment_in_prometheus_format_and_writes_nothing(tmp_path, capsys):
    conf = tmp_path / "health.conf"
    conf.write_text("no_such_bound = 1\n")
    metrics = tmp_path / "metrics"
    metrics.mkdir()
    assert run.main(["--conf", str(conf), "--report", str(tmp_path / "health.json"),
                     "--format", "prometheus", "--textfile-dir", str(metrics)]) == 3
    out = capsys.readouterr().out
    assert out.startswith("# UNKNOWN maildivvy-health could not run") and parse(out) == {}
    assert not list(metrics.iterdir())


def test_an_error_of_several_lines_is_a_comment_on_every_line(monkeypatch, tmp_path, capsys):
    def fails(*args, **kwargs):
        raise RuntimeError("first line\nsecond line\nthird line")
    monkeypatch.setattr(checks, "run", fails)
    assert run.main(["--conf", str(tmp_path / "none.conf"), "--report", str(tmp_path / "health.json"),
                     "--format", "prometheus"]) == 3
    out = capsys.readouterr().out
    assert out.splitlines() == ["# UNKNOWN maildivvy-health could not run: RuntimeError: first line",
                                "# second line", "# third line"]
    assert parse(out) == {}


def test_a_textfile_directory_it_cannot_write_is_unknown_and_the_report_is_still_kept(monkeypatch, tmp_path,
                                                                                      capsys):
    """The JSON report is written first; a textfile that cannot be replaced leaves the old one,
    whose last-run timestamp then ages, and the run says why with UNKNOWN."""
    monkeypatch.setattr(checks, "run", fake_run)

    def read_only(directory, whole):
        raise PermissionError(13, "Permission denied", str(Path(directory) / report.TEXTFILE))
    monkeypatch.setattr(report, "write_textfile", read_only)
    metrics = tmp_path / "metrics"
    metrics.mkdir()
    (metrics / report.TEXTFILE).write_text("old\n")
    assert run.main(["--conf", str(tmp_path / "none.conf"), "--report", str(tmp_path / "health.json"),
                     "--textfile-dir", str(metrics)]) == 3
    assert "could not run: PermissionError" in capsys.readouterr().out
    assert (tmp_path / "health.json").exists() and (metrics / report.TEXTFILE).read_text() == "old\n"


# --- the unit and the setting -------------------------------------------------------------------


def rendered_unit(textfile_dir):
    values = {**yaml.safe_load((HEALTH / "vars" / "main.yml").read_text()),
              **yaml.safe_load((HEALTH / "defaults" / "main.yml").read_text())}
    if textfile_dir is not None:
        values["maildivvy_health_textfile_dir"] = textfile_dir
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, trim_blocks=True)  # as Ansible's
    for _ in range(3):   # the vars refer to one another
        values = {k: env.from_string(v).render(values) if isinstance(v, str) else v
                  for k, v in values.items()}
    text = env.from_string((HEALTH / "templates" / "maildivvy-health.service.j2").read_text()).render(values)
    return {key: value for key, _, value in (line.partition("=") for line in text.splitlines())
            if key in ("ExecStart", "ReadWritePaths")}


def test_the_timer_writes_the_textfile_only_where_a_directory_is_configured():
    off = rendered_unit(None)
    assert off == {"ExecStart": "/opt/maildivvy/bin/maildivvy-health --quiet",
                   "ReadWritePaths": "/var/lib/maildivvy/health"}
    on = rendered_unit("/var/lib/node-exporter")
    assert on == {"ExecStart": "/opt/maildivvy/bin/maildivvy-health --quiet --textfile-dir /var/lib/node-exporter",
                  "ReadWritePaths": "/var/lib/maildivvy/health /var/lib/node-exporter"}


GOOD = {"hostname": "mail", "cert_name": "mail.example.test", "vmail_uid": 900, "vmail_gid": 900,
        "admin_networks": ["192.0.2.0/24"], "breakglass_password": "correct horse battery",
        "acme_dns_credentials": {"DESEC_TOKEN": "scoped-token"}}


def test_an_existing_textfile_directory_must_already_be_the_health_users(tmp_path):
    """Step 17 never re-owns a directory that exists: /var/lib or node_exporter's own would
    change owner. A new one it makes; one that is the health user's already is taken."""
    theirs = tmp_path / "theirs"
    theirs.mkdir()
    (tmp_path / "file").write_text("")
    assert textfile_dir_errors(str(tmp_path / "absent")) == []
    assert textfile_dir_errors(str(theirs), owner=lambda uid: HEALTH_USER) == []
    errors = textfile_dir_errors(str(theirs), owner=lambda uid: "root")
    assert len(errors) == 1 and errors[0].startswith(f"refused health_textfile_dir: {theirs} exists and is root's")
    assert "not a directory" in textfile_dir_errors(str(tmp_path / "file"), owner=lambda uid: HEALTH_USER)[0]


def test_step_1_knows_the_health_roles_user():
    role = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "health"
    role_vars = yaml.safe_load((role / "vars" / "main.yml").read_text())
    assert role_vars["maildivvy_health_user"] == HEALTH_USER


def test_the_textfile_directory_is_an_absolute_path_of_one_word():
    assert setting_errors({**GOOD, "health_textfile_dir": "/var/lib/node-exporter"}) == []
    for bad in ("relative/dir", "/with space", "/", "/two\nlines", "/var/../etc", ["/a"]):
        errors = setting_errors({**GOOD, "health_textfile_dir": bad})
        assert len(errors) == 1 and errors[0].startswith("malformed health_textfile_dir:"), (bad, errors)
