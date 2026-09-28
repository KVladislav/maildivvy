"""mpop's own state file, and the listing that finds the message the mailbox is stuck on.

The file is mpop's format, not ours: a comment block, one header line ` N host user`,
and one line per identifier. Everything here copies a rule of mpop's own source rather
than guessing at one, because a file mpop then rewrites has to agree with it.
"""

import os
import stat

import pytest

from maildivvy.fetch import state

HEADER = " 2 pop.example.org ivan@example.org"
COMMENT = ("# This file was written by mpop version 1.4.23.",
           "# Use 'mpop --help' for more information.")


def write(path, *lines):
    path.write_text("\n".join(lines) + "\n")
    return path


def uidls(tmp_path, *lines):
    return write(tmp_path / "uidls", *COMMENT, *lines)


# --- reading a line ---------------------------------------------------------------


@pytest.mark.parametrize("line, identifier", [
    ("abc123 1757000000", "abc123"),                  # 1.4.23: identifier and first sighting
    ("abc123", "abc123"),                             # 1.4.21: the identifier alone
    ("has a space 1757000000", "has a space"),        # POP3 permits a space in one
    ("  1757000000", " "),
    # a 1.4.21 line whose identifier holds a space is ambiguous, and mpop's own
    # `strrchr` reads it exactly this way; the rule is copied, not improved on
    ("has a space", "has a"),
])
def test_a_line_is_split_on_the_last_space(line, identifier):
    assert state.identifier_of(line) == identifier


def test_splitting_on_the_first_space_would_read_a_message_as_new():
    """`split()[0]` reads `has` out of `has a space 1757000000` - the defect this repairs."""
    assert state.identifier_of("has a space 1757000000") != "has a space 1757000000".split()[0]


def test_the_identifiers_known_are_the_lines_that_are_neither_comment_nor_header(tmp_path):
    path = uidls(tmp_path, HEADER, "abc 1757000000", "has a space 1757000001")
    assert state.known_identifiers(path) == {"abc", "has a space"}


def test_a_state_file_that_does_not_exist_knows_nothing(tmp_path):
    assert state.known_identifiers(tmp_path / "nothing") == set()


# --- the listing's UIDL block -----------------------------------------------------

LISTING = """\
--> CAPA
<-- +OK
--> LIST
<-- +OK
<-- 1 4096
<-- 2 8192
<-- .
--> UIDL
<-- +OK
<-- 1 abc
<-- 2 has a space
<-- .
--> QUIT
"""


def test_only_the_uidl_block_is_read():
    assert state.parse_listing(LISTING) == [(1, "abc"), (2, "has a space")]


def test_the_list_answer_alone_yields_nothing():
    without = LISTING.split("--> UIDL")[0]
    assert state.parse_listing(without) == []


def test_a_second_uidl_block_replaces_the_first():
    assert state.parse_listing(LISTING + "--> UIDL\n<-- +OK\n<-- 1 zzz\n<-- .\n") == [(1, "zzz")]


# --- choosing the stuck message ---------------------------------------------------


def test_the_stuck_message_is_the_first_offered_identifier_the_file_does_not_hold():
    chosen, complaint = state.choose_stuck([(1, "abc"), (2, "def")], {"abc"}, 2)
    assert (chosen, complaint) == ("def", None)


def test_a_listing_that_disagrees_with_the_failing_number_is_refused():
    """A message deleted at the provider between the two sessions shifts the numbering."""
    chosen, complaint = state.choose_stuck([(1, "abc"), (2, "def")], {}, 2)
    assert chosen is None and "disagrees" in complaint


def test_a_listing_with_nothing_new_is_refused():
    chosen, complaint = state.choose_stuck([(1, "abc")], {"abc"}, None)
    assert chosen is None and "nothing" in complaint


def test_the_first_message_of_all_can_be_the_stuck_one():
    assert state.choose_stuck([(1, "abc")], set(), 1) == ("abc", None)


def test_a_failure_that_named_no_number_takes_the_first_one_not_held():
    assert state.choose_stuck([(1, "abc"), (2, "def")], {"abc"}, None) == ("def", None)


# --- writing the skip --------------------------------------------------------


def test_a_skip_is_added_with_the_ordinary_time_and_the_count_raised(tmp_path):
    path = uidls(tmp_path, HEADER, "abc 1757000000", "def 1757000001")
    assert state.record_skip(tmp_path, "zzz", "pop.example.org", "ivan@example.org", now=1757000099)
    lines = path.read_text().splitlines()
    assert lines[2] == " 3 pop.example.org ivan@example.org"
    assert lines[3:] == ["abc 1757000000", "def 1757000001", "zzz 1757000099"]


def test_the_skip_carries_the_ordinary_time_so_the_provider_deletes_it_on_schedule(tmp_path):
    uidls(tmp_path, HEADER, "abc 1757000000")
    state.record_skip(tmp_path, "zzz", "pop.example.org", "ivan@example.org", now=1757000099)
    written = (tmp_path / "uidls").read_text().splitlines()[-1]
    assert written == "zzz 1757000099"  # not a sentinel far in the future


def test_the_identifiers_are_sorted_by_identifier_as_mpops_own_sort_will_rewrite_them(tmp_path):
    uidls(tmp_path, " 2 h u", "bbb 1", "ccc 2")
    state.record_skip(tmp_path, "aaa", "h", "u", now=3)
    assert [state.identifier_of(line) for line in
            (tmp_path / "uidls").read_text().splitlines()[3:]] == ["aaa", "bbb", "ccc"]


def test_an_identifier_already_in_the_file_is_not_written_twice(tmp_path):
    uidls(tmp_path, HEADER, "abc 1757000000", "def 1757000001")
    assert state.record_skip(tmp_path, "abc", "pop.example.org", "ivan@example.org") is False
    assert (tmp_path / "uidls").read_text().count("abc") == 1


def test_a_file_with_no_header_is_valid_and_the_header_is_written_from_what_was_rendered(tmp_path):
    """mpop that retrieved nothing writes the comment block and nothing else."""
    path = uidls(tmp_path)
    assert state.record_skip(tmp_path, "zzz", "pop.example.org", "ivan@example.org", now=5)
    assert path.read_text().splitlines() == [*COMMENT, " 1 pop.example.org ivan@example.org",
                                             "zzz 5"]


def test_a_missing_state_file_is_an_error_naming_it(tmp_path):
    with pytest.raises(state.StateError) as raised:
        state.record_skip(tmp_path, "zzz", "h", "u")
    assert str(tmp_path / "uidls") in str(raised.value)


def test_more_than_one_header_is_an_error(tmp_path):
    uidls(tmp_path, HEADER, "abc 1", " 1 other other", "def 2")
    with pytest.raises(state.StateError) as raised:
        state.record_skip(tmp_path, "zzz", "h", "u")
    assert "2 UID list headers" in str(raised.value)


def test_a_header_that_does_not_parse_is_an_error(tmp_path):
    uidls(tmp_path, " not a header", "abc 1")
    with pytest.raises(state.StateError):
        state.record_skip(tmp_path, "zzz", "h", "u")


def test_the_write_is_atomic_and_leaves_no_temporary_file_behind(tmp_path, monkeypatch):
    uidls(tmp_path, HEADER, "abc 1")
    replaced = []
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (replaced.append((a, b)), real(a, b))[1])
    state.record_skip(tmp_path, "zzz", "h", "u", now=2)
    assert len(replaced) == 1 and str(replaced[0][1]) == str(tmp_path / "uidls")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["uidls"]


def test_the_temporary_file_is_created_0600(tmp_path, monkeypatch):
    uidls(tmp_path, HEADER, "abc 1")
    modes = []
    real = os.open
    monkeypatch.setattr(os, "open", lambda p, f, m=0o777, **k: (modes.append(m), real(p, f, m, **k))[1])
    state.record_skip(tmp_path, "zzz", "h", "u", now=2)
    assert modes == [0o600]


def test_the_listings_copy_of_the_state_file_is_0600_and_is_removed(tmp_path):
    uidls(tmp_path, HEADER, "abc 1")
    with state.listing_copy(tmp_path) as copy:
        assert stat.S_IMODE(copy.stat().st_mode) == 0o600
        assert copy.read_text() == (tmp_path / "uidls").read_text()
        assert copy != tmp_path / "uidls"
    assert not copy.exists()


def test_the_copy_is_removed_even_when_the_listing_raises(tmp_path):
    uidls(tmp_path, HEADER, "abc 1")
    with pytest.raises(ZeroDivisionError):
        with state.listing_copy(tmp_path) as copy:
            1 / 0
    assert not copy.exists()


def test_a_copy_is_made_even_when_there_is_no_state_file_yet(tmp_path):
    with state.listing_copy(tmp_path) as copy:
        assert copy.read_bytes() == b""
    assert not (tmp_path / "uidls").exists()  # the real one is never created by this
