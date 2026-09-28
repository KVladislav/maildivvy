"""What the fetch runner writes for mpop, and what it refuses to write.

The rendered file is the one place a provider credential could land on disk, and the
one place a stored string becomes a directive mpop obeys. Both are tested here rather
than on the VM, because both are properties of the text.
"""

import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from maildivvy.fetch import render

ROW = dict(id=7, pop3_login="recent:ivan.p@example.org", address="Ivan.P@example.org",
           pop3_host="pop.example.org", pop3_port=995, label="alpha", window=14,
           target="ivan.p@example.org", threshold=8.00, held_since=None)

BINDIR = "/opt/maildivvy/bin"
STATE = "/var/lib/maildivvy/fetch"


def mailbox(**changes):
    return render.Mailbox(**{**ROW, **changes})


def rendered(**changes):
    return render.render(mailbox(**changes), STATE, BINDIR)


def lines(text):
    return text.splitlines()


def line_starting(text, word):
    found = [line for line in lines(text) if line.split(" ")[0] == word]
    assert len(found) == 1, f"{word}: {found}"
    return found[0]


# --- the credential is never in the file ------------------------------------


def test_the_rendered_file_names_a_command_and_carries_no_password():
    text = rendered()
    assert line_starting(text, "passwordeval") == \
        f'passwordeval "{BINDIR}/maildivvy-credential 7"'
    assert "password" not in text.replace("passwordeval", "")


def test_no_line_of_the_renderer_can_write_a_password_directive():
    """mpop's own `password` directive is what a credential on disk would look like."""
    source = Path(render.__file__).read_text().replace("passwordeval", "")
    assert "password" not in source


def test_the_file_is_created_0600_and_never_chmodded_afterwards(tmp_path, monkeypatch):
    opened = []
    real_open = os.open

    def watched(path, flags, mode=0o777, **kwargs):
        opened.append((str(path), flags, mode))
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", watched)
    monkeypatch.setattr(os, "chmod", lambda *a, **k: pytest.fail("chmod after the fact"))
    path = render.write_config("account em7\n", tmp_path / "7")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [entry for entry in opened if entry[0] == str(path)][0][2] == 0o600
    assert stat.S_IMODE((tmp_path / "7").stat().st_mode) == 0o700


def test_the_state_directory_is_the_mailboxs_own(tmp_path):
    assert render.state_dir(tmp_path, 7) == Path(tmp_path) / "7"


# --- the transport has no switch -------------------------------------------------


def test_transport_security_is_two_literal_lines():
    text = rendered()
    assert "tls on" in lines(text)
    assert "tls_starttls off" in lines(text)


def test_no_other_line_of_the_fetch_package_carries_the_token():
    """A slot in either transport line would be the switch this rule keeps out."""
    package = Path(render.__file__).parent
    carrying = []
    for path in sorted(package.glob("*.py")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if "tls" in line:
                carrying.append((path.name, number, line.strip().rstrip(",")))
    assert [line for _, _, line in carrying] == ['"tls on"', '"tls_starttls off"'], carrying


# --- the login reaches the provider as stored ---------------------------


def test_the_login_is_the_stored_one_with_nothing_added():
    assert line_starting(rendered(), "user") == "user recent:ivan.p@example.org"


@pytest.mark.parametrize("empty", [None, ""])
def test_an_empty_login_renders_the_address_as_typed_never_the_folded_form(empty):
    text = rendered(pop3_login=empty)
    assert line_starting(text, "user") == "user Ivan.P@example.org"
    assert "ivan.p@example.org" not in line_starting(text, "user")


def test_the_state_key_lines_are_the_host_and_the_login_alone():
    """mpop keys its state by host and login, so those two lines carry nothing else."""
    text = rendered(held_since=datetime(2026, 9, 20, 6, tzinfo=timezone.utc), threshold=1.25)
    assert line_starting(text, "host") == "host pop.example.org"
    assert line_starting(text, "user") == "user recent:ivan.p@example.org"


@pytest.mark.parametrize("bad", ["ivan p@example.org", "ivan\n@example.org", "ivan\t@example.org",
                                 "ivan\x00@example.org", "ivan\x7f@example.org", " ivan@example.org", ""])
@pytest.mark.parametrize("field", ["pop3_login", "address"])
def test_whitespace_and_control_characters_are_refused_in_both_fields(field, bad):
    if field == "pop3_login" and bad == "":
        return  # an empty login is the address; the address itself is tested
    with pytest.raises(render.RenderError) as raised:
        rendered(**{field: bad, **({"pop3_login": bad} if field == "address" else {})})
    assert field.replace("pop3_", "") in str(raised.value).lower()


def test_one_rule_serves_the_login_and_the_address():
    assert render.check_field.__doc__  # the shared rule, named once
    source = Path(render.__file__).read_text()
    assert source.count("FIELD.match") == 1


def test_the_host_is_held_to_the_same_rule():
    with pytest.raises(render.RenderError):
        rendered(pop3_host="pop.example.org\nkeep off")


# --- the deletion window -------------------------------------------


@pytest.mark.parametrize("window, keep", [(14, "keep 14d"), (1, "keep 1d"), (365, "keep 365d")])
def test_the_window_is_rendered_as_mpops_keep_duration(window, keep):
    assert line_starting(rendered(window=window), "keep") == keep


def test_keep_and_only_new_are_rendered_for_every_account():
    text = rendered()
    assert line_starting(text, "keep") == "keep 14d"
    assert line_starting(text, "only_new") == "only_new on"


def test_a_window_the_query_lost_raises_here_and_renders_nothing():
    with pytest.raises(render.RenderError) as raised:
        rendered(window=None)
    assert "delete_window_days" in str(raised.value)


# --- the threshold, on the delivery line alone ------------------------------------


def test_the_domains_threshold_is_rendered_on_the_delivery_line():
    text = rendered(threshold=12.5)
    assert line_starting(text, "delivery") == \
        f'delivery mda "exec {BINDIR}/maildivvy-deliver --retrieval --domain alpha --spam-threshold 12.50"'
    assert "12.50" not in text.replace(line_starting(text, "delivery"), "")


def test_the_shell_mpop_starts_is_replaced_by_the_filter_and_holds_no_pipe_of_its_own():
    """mpop runs the line through `sh -c`, and dash 0.5.12 forks for it rather than
    exec (measured): a shell left waiting would hold the retrieval pipe's write end and
    make an abandoned message look like one mpop still waits for."""
    command = line_starting(rendered(), "delivery").split('"')[1]
    assert command.startswith(f"exec {BINDIR}/maildivvy-deliver ")
    # The filter is told it belongs to a retrieval, so a pipe that
    # never reached it is said in words the runner records, never passed over in silence
    assert command.split()[2] == "--retrieval"


def test_a_threshold_the_query_lost_raises_on_the_first_mailbox():
    with pytest.raises(render.RenderError) as raised:
        rendered(threshold=None)
    assert "spam_threshold" in str(raised.value)


def test_the_delivery_line_is_the_only_invocation_of_the_filter():
    package = Path(render.__file__).parent
    naming = [line.strip() for path in package.glob("*.py")
              for line in path.read_text().splitlines() if "maildivvy-deliver" in line]
    assert len(naming) == 1, naming


# --- the hold's other half ------------------------------------------------------------


def test_a_mailbox_with_no_hold_renders_no_held_since():
    text = rendered()
    assert "--held-since" not in text and "--hold-bound-seconds" not in text


def test_a_held_mailbox_renders_the_time_and_the_bound_on_the_delivery_line():
    began = datetime(2026, 9, 20, 6, 24, tzinfo=timezone.utc)
    text = render.render(mailbox(held_since=began), STATE, BINDIR, hold_bound=1800)
    assert line_starting(text, "delivery") == (
        f'delivery mda "exec {BINDIR}/maildivvy-deliver --retrieval --domain alpha --spam-threshold 8.00'
        f' --held-since 2026-09-20T06:24:00+00:00 --hold-bound-seconds 1800"')


def test_the_held_time_never_carries_a_space_into_the_command():
    began = datetime(2026, 9, 20, 6, 24, 30, 5000, tzinfo=timezone.utc)
    text = render.render(mailbox(held_since=began), STATE, BINDIR)
    command = line_starting(text, "delivery").split('"')[1]
    assert command.split(" ").count("--held-since") == 1
    assert " " not in command.split("--held-since ")[1].split(" ")[0]


# --- the rest of the file --------------------------------------------------------------------


def test_the_account_name_and_the_state_file_are_the_mailboxs_own():
    text = rendered()
    assert line_starting(text, "account") == "account em7"
    assert render.account_name(7) == "em7"
    assert line_starting(text, "uidls_file") == f"uidls_file {STATE}/7/uidls"


def test_the_port_is_the_rows():
    assert line_starting(rendered(pop3_port=110), "port") == "port 110"


def test_every_template_slot_is_filled():
    assert "{" not in rendered() and "}" not in rendered()


def test_the_row_is_unpacked_by_name_so_a_lost_column_never_shifts_another():
    assert render.Mailbox._fields == (
        "id", "pop3_login", "address", "pop3_host", "pop3_port", "label", "window",
        "target", "threshold", "held_since")
    with pytest.raises(TypeError):
        render.Mailbox(*range(len(render.Mailbox._fields) - 1))
