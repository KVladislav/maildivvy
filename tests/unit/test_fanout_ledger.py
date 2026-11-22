"""The ledger's consistency check, against a store built in a temporary directory.

The design says what a defect is and what is not: a name in a person's mailbox
pointing at an archive inode with no delivery row is the defect; every other file in
their mailbox, in any folder, is the person's own and the check ignores it. A delivery
row that outlived its file is normal - that is how a top-up avoids restoring mail
somebody deliberately deleted.

The archive's side of the reading is its directories, keyed by base name (`0100`); only
what is above the pass's cursor comes from Dovecot, here a stand-in, so the finding
itself, the counting by inode and the keying on the base name are driven without a
machine.
"""

import os
import time
from pathlib import Path

import pytest

from maildivvy.fanout import ledger
from maildivvy.lib import doveadm, store


DOMAIN = "alpha"


def maildir(root, account, folder=None):
    """One mailbox's INBOX or folder maildir, with its cur/ and new/, as the store lays it out."""
    box = store.maildir(store.home(DOMAIN, account, root), folder)
    for part in ("cur", "new"):
        (box / part).mkdir(parents=True, exist_ok=True)
    return box


def put(box, part, name, body=b"a message"):
    path = box / part / name
    path.write_bytes(body)
    return path


def world(tmp_path):
    """An archive with two messages, and one person holding a link to the first."""
    archive = maildir(tmp_path, store.ARCHIVE)
    one = put(archive, "cur", "1757.M1.host:2,S")
    two = put(archive, "new", "1757.M2.host")
    ivan = maildir(tmp_path, "ivan")
    os.link(one, ivan / "new" / "1757.M1.host")
    # (folder, uid) -> the ledger's message id, and the file the archive holds for it
    held = {(ledger.INBOX, 1): (11, one), (ledger.INBOX, 2): (12, two)}
    return archive, ivan, held


def inodes(held):
    return {path.stat().st_ino: message for (_, _), (message, path) in held.items()}


# --- the defect: a link into the archive with no row -------------------------------------


def test_an_archive_link_with_no_delivery_row_is_reported(tmp_path):
    _, _, held = world(tmp_path)
    found = ledger.unaccounted(inodes(held), [(5, "ivan")], set(), DOMAIN, root=tmp_path)
    assert len(found) == 1
    assert found[0].mailbox_id == 5 and found[0].message_id == 11


def test_the_finding_health_reports_names_no_path_and_so_no_folder_a_person_named():
    """The finding went into the world-readable health.json with
    its maildir path, and a folder's name in it is a person's own words."""
    found = ledger.Finding(5, "ivan", 11, "/srv/maildivvy/store/alpha/ivan/Maildir/.Salary talks/cur/1:2,S")
    public = found.public()
    assert "ivan" in public and "11" in public and "mailbox 5" in public
    assert "Salary" not in public and "/srv/" not in public
    assert "Salary" in str(found)            # the full finding is still there for root's own tools


def test_the_same_link_with_its_row_is_reported_by_nothing(tmp_path):
    _, _, held = world(tmp_path)
    assert ledger.unaccounted(inodes(held), [(5, "ivan")], {(11, 5)}, DOMAIN, root=tmp_path) == []


def test_a_file_the_person_put_there_themselves_is_ignored_in_any_folder(tmp_path):
    _, ivan, held = world(tmp_path)
    put(ivan, "new", "own-draft")
    for folder in ("Drafts", "Templates", "Old mail/2019"):
        put(maildir(tmp_path, "ivan", folder), "cur", "dragged-in:2,S")
    assert ledger.unaccounted(inodes(held), [(5, "ivan")], {(11, 5)}, DOMAIN, root=tmp_path) == []


def test_a_draft_the_client_appended_has_no_row_by_construction_and_is_not_a_defect(tmp_path):
    _, _, held = world(tmp_path)
    put(maildir(tmp_path, "ivan", "Drafts"), "new", "1757.M9.host")
    assert ledger.unaccounted(inodes(held), [(5, "ivan")], {(11, 5)}, DOMAIN, root=tmp_path) == []


def test_an_archive_link_in_a_folder_of_the_persons_own_choosing_is_still_accounted_for(tmp_path):
    archive, _, held = world(tmp_path)
    moved = maildir(tmp_path, "olga", "Projects")
    os.link(archive / "new" / "1757.M2.host", moved / "cur" / "1757.M2.host:2,S")
    found = ledger.unaccounted(inodes(held), [(6, "olga")], set(), DOMAIN, root=tmp_path)
    assert [(f.mailbox_id, f.message_id) for f in found] == [(6, 12)]
    assert ledger.unaccounted(inodes(held), [(6, "olga")], {(12, 6)}, DOMAIN, root=tmp_path) == []


# --- what is normal ------------------------------------------------------------


def test_a_delivery_row_that_outlived_its_file_is_normal(tmp_path):
    _, ivan, held = world(tmp_path)
    (ivan / "new" / "1757.M1.host").unlink()  # the person deleted their copy
    assert ledger.unaccounted(inodes(held), [(5, "ivan")], {(11, 5)}, DOMAIN, root=tmp_path) == []


def test_a_second_name_for_one_inode_in_one_mailbox_is_counted_once(tmp_path):
    _, ivan, held = world(tmp_path)
    # an IMAP COPY inside one mailbox: another name, the same inode, no new row
    os.link(ivan / "new" / "1757.M1.host", ivan / "cur" / "1757.M1.host:2,S")
    found = ledger.unaccounted(inodes(held), [(5, "ivan")], set(), DOMAIN, root=tmp_path)
    assert len(found) == 1  # one message, not two names
    assert ledger.unaccounted(inodes(held), [(5, "ivan")], {(11, 5)}, DOMAIN, root=tmp_path) == []


def test_maildir_bookkeeping_files_are_never_read_as_messages(tmp_path):
    _, ivan, held = world(tmp_path)
    (ivan / "dovecot.index").write_bytes(b"not a message")
    (ivan / "maildirfolder").write_bytes(b"")
    assert ledger.unaccounted(inodes(held), [(5, "ivan")], {(11, 5)}, DOMAIN, root=tmp_path) == []


# --- a message is its file's base name, in whichever folder (`0100`) ----------------


def test_a_row_is_keyed_by_its_files_base_name_and_never_by_a_uid():
    """One UID in two folders is two messages, and so are their two base names: the base
    name tells them apart without a folder."""
    keyed = ledger.by_base([(21, "1757.M1.host"), (22, "1757.M7.host")])
    assert keyed == {"1757.M1.host": 21, "1757.M7.host": 22}
    for statement in (ledger.MESSAGES, ledger.MESSAGES_BY_BASE):
        assert "archive_base" in statement and "archive_uid" not in statement


def test_the_folder_of_a_row_is_its_own_state_and_never_guessed_from_the_uid():
    assert ledger.folder_of("delivered") == ledger.INBOX
    assert ledger.folder_of("withheld") == store.QUARANTINE
    assert ledger.folder_of("released") == store.QUARANTINE


# --- what the check selects on ------------------------------------------------------


def test_the_check_selects_on_columns_the_product_wrote_and_never_on_a_stored_header():
    sql = ledger.MESSAGES.lower()
    assert "archive_base" in sql
    for header_column in ("subject", "sender", "message_id_header"):
        assert header_column not in sql, header_column


def test_nothing_in_the_check_matches_a_subject_or_a_sender():
    text = Path(ledger.__file__).read_text().lower()
    assert " like " not in text and "ilike" not in text


# --- the five-minute window: the names changed since the last scan --------------------


class Rows:
    """The ledger as the window reads it: one cursor answering its three statements."""

    def __init__(self, deliveries=(), mailboxes=((5, "ivan"),)):
        self.mailboxes = list(mailboxes)
        self.messages = [(11, "1757.M1.host"), (12, "1757.M2.host")]
        self.deliveries = set(deliveries)
        self.asked = []
        self.rows = []

    def execute(self, sql, params):
        self.asked.append(sql)
        if sql == ledger.MAILBOXES:
            self.rows = self.mailboxes
        elif sql == ledger.MESSAGES_BY_BASE:
            self.rows = [m for m in self.messages if m[1] in params[1]]
        elif sql == ledger.DELIVERIES_OF:
            self.rows = [d for d in self.deliveries if d[0] in params[0]]
        else:
            raise AssertionError(sql)

    def fetchall(self):
        return self.rows


@pytest.fixture
def archive_answers(monkeypatch):
    """Dovecot, which the window and the archive's listing never ask (`0100`): what was
    asked of it."""
    asked = []

    def fetch(login, folder, fields, *search):
        asked.append(folder)
        raise AssertionError(f"Dovecot asked for {folder} {search}")

    monkeypatch.setattr(doveadm, "fetch", fetch)
    return asked


def test_a_link_made_since_the_last_scan_with_no_row_is_found_and_carried(tmp_path, archive_answers):
    world(tmp_path)
    since = time.time() - ledger.SLACK
    found = ledger.window(Rows(), DOMAIN, since, root=tmp_path)
    assert [(f.mailbox_id, f.message_id) for f in found.findings] == [(5, 11)]
    inode = (tmp_path / DOMAIN / "ivan" / "Maildir" / "new" / "1757.M1.host").stat().st_ino
    assert found.carry == [[5, 11, inode]] and found.checked == 1
    # the same name with its row is no defect
    assert ledger.window(Rows({(11, 5)}), DOMAIN, since, root=tmp_path).findings == []
    assert archive_answers == []


def test_the_window_counts_a_second_name_for_one_inode_once(tmp_path, archive_answers):
    _, ivan, _ = world(tmp_path)
    os.link(ivan / "new" / "1757.M1.host", ivan / "cur" / "1757.M1.host:2,S")
    found = ledger.window(Rows(), DOMAIN, time.time() - ledger.SLACK, root=tmp_path)
    assert [(f.mailbox_id, f.message_id) for f in found.findings] == [(5, 11)]


def test_a_name_older_than_the_window_is_the_daily_passs_and_nothing_else_is_asked(tmp_path, archive_answers):
    world(tmp_path)
    rows = Rows()
    found = ledger.window(rows, DOMAIN, time.time() + 3600, root=tmp_path)
    assert found == ledger.Window([], 0, [])
    # neither Dovecot nor the ledger is asked about a window nothing changed in
    assert archive_answers == [] and rows.asked == [ledger.MAILBOXES]


def test_a_directory_no_name_entered_since_the_last_scan_is_not_listed(tmp_path, archive_answers):
    _, ivan, _ = world(tmp_path)
    before = time.time() - 3600
    os.utime(ivan / "new", (before, before))   # its mtime: no name added or renamed since
    found = ledger.window(Rows(), DOMAIN, time.time() - ledger.SLACK, root=tmp_path)
    assert found.checked == 0 and found.findings == []


def test_a_carried_finding_stays_until_its_row_or_its_name_is_there_no_more(tmp_path, archive_answers):
    _, ivan, _ = world(tmp_path)
    carried = ledger.window(Rows(), DOMAIN, time.time() - ledger.SLACK, root=tmp_path).carry
    later = time.time() + 3600   # its ctime is out of every later window
    again = ledger.window(Rows(), DOMAIN, later, carried, root=tmp_path)
    assert [(f.mailbox_id, f.message_id) for f in again.findings] == [(5, 11)]
    assert again.carry == carried
    # its row recorded: gone
    assert ledger.window(Rows({(11, 5)}), DOMAIN, later, carried, root=tmp_path).findings == []
    # its name removed: gone, and nothing more is carried
    (ivan / "new" / "1757.M1.host").unlink()
    assert ledger.window(Rows(), DOMAIN, later, carried, root=tmp_path) == ledger.Window([], 0, [])
    # a carried finding of a mailbox no longer in the domain is dropped
    assert ledger.window(Rows(mailboxes=[]), DOMAIN, later, carried, root=tmp_path).carry == []


# --- the archive's messages no row holds --------------------------------------------


def base(uid):
    return f"1757.M{uid}.host"


def listed(*uids):
    """A folder as `archive_listing` reads it: `{base name: inode}`."""
    return {base(uid): 1000 + uid for uid in uids}


class Numbers:
    """Dovecot's numbering of the archive's folders: `{folder: {uid: base name}}`, its
    UIDVALIDITY, and what was asked."""

    def __init__(self, monkeypatch):
        self.numbering, self.uidvalidity, self.asked = {}, 77, []
        monkeypatch.setattr(doveadm, "fetch", self.fetch)
        monkeypatch.setattr(doveadm, "mailbox_status", self.status)

    def status(self, login, folder, *fields):
        self.asked.append((folder, "uidvalidity"))
        return {"uidvalidity": str(self.uidvalidity)}

    def fetch(self, login, folder, fields, *search):
        assert search[0] == "uid" and fields == ["uid", "storageid"]
        self.asked.append((folder, search[1]))
        first, _, last = search[1].partition(":")
        held = self.numbering.get(folder, {})
        top = max(held, default=0) if last == "*" else int(last)
        return [{"uid": str(uid), "storageid": held[uid]} for uid in sorted(held)
                if int(first) <= uid <= top]

    def number(self, folder, *uids):
        """The folder numbering the files of these UIDs as their base names say."""
        self.numbering[folder] = {uid: base(uid) for uid in uids}


@pytest.fixture
def numbers(monkeypatch):
    return Numbers(monkeypatch)


def test_a_message_at_or_below_the_cursor_with_no_row_is_found_and_one_above_it_never(numbers):
    """The pass moved its cursor past UID 3 without a row: skipped. UIDs 6 and 7 are above
    the cursor, mail the next tick records. Dovecot is asked for the UIDs from the cursor
    up, and only because a file has no row, for those below it."""
    numbers.number(ledger.INBOX, *range(1, 8))
    bases = {base(uid): 10 + uid for uid in (1, 2, 4, 5)}
    found = ledger.under_cursor(DOMAIN, {ledger.INBOX: listed(*range(1, 8))}, bases,
                                {ledger.INBOX: (5, 77, base(5))})
    assert found == ledger.UnderCursor(5, [ledger.Unrecorded(ledger.INBOX, 1, [3])], [])
    assert numbers.asked == [(ledger.INBOX, "5:*"), (ledger.INBOX, "uidvalidity"),
                             (ledger.INBOX, "1:5")]
    # nothing with no row: Dovecot is asked for the cursor's UID up alone
    numbers.asked.clear()
    bases[base(3)] = 13
    found = ledger.under_cursor(DOMAIN, {ledger.INBOX: listed(*range(1, 8))}, bases,
                                {ledger.INBOX: (5, 77, base(5))})
    assert found == ledger.UnderCursor(5, [], []) and len(numbers.asked) == 2


def test_each_folder_is_held_to_its_own_cursor_and_its_own_rows(numbers):
    """The quarantine's file has a row, a released one whose file never moved; INBOX's
    first has none. A folder nothing was read of yet has nothing at or below its cursor."""
    numbers.number(ledger.INBOX, 1, 2)
    numbers.numbering[store.QUARANTINE] = {1: base(9)}
    bases = {base(9): 21, base(2): 22}
    listing = {ledger.INBOX: listed(1, 2), store.QUARANTINE: listed(9)}
    cursors = {ledger.INBOX: (2, 77, base(2)), store.QUARANTINE: (1, 77, base(9))}
    found = ledger.under_cursor(DOMAIN, listing, bases, cursors)
    assert found == ledger.UnderCursor(3, [ledger.Unrecorded(ledger.INBOX, 1, [1])], [])
    for nothing_read in ({}, {ledger.INBOX: (0, None, None)}):
        assert ledger.under_cursor(DOMAIN, listing, {}, nothing_read) == ledger.UnderCursor(0, [], [])
    # a cursor row whose folder is not there holds nothing either
    assert ledger.under_cursor(DOMAIN, {}, {}, cursors) == ledger.UnderCursor(0, [], [])


def test_a_folders_finding_names_its_first_uids_and_counts_them_all(numbers):
    numbers.number(ledger.INBOX, *range(1, 5001))
    found = ledger.under_cursor(DOMAIN, {ledger.INBOX: listed(*range(1, 5001))},
                                {base(5000): 1}, {ledger.INBOX: (5000, 77, base(5000))})
    assert found.read == 5000
    assert found.unrecorded == [ledger.Unrecorded(ledger.INBOX, 4999, list(range(1, ledger.NAMED + 1)))]


def test_a_folder_whose_cursor_means_something_else_is_named_apart_and_none_of_its_files_is_a_finding(
        numbers):
    """Until the pass's next tick sets it right, "at or below the cursor" is another
    numbering's: holding the listing to it would name files whose rows are there."""
    listing = {ledger.INBOX: listed(1, 2, 3)}
    numbers.number(ledger.INBOX, 1, 2, 3)
    # another UIDVALIDITY than the cursor row keeps
    found = ledger.under_cursor(DOMAIN, listing, {}, {ledger.INBOX: (3, 76, base(3))})
    assert found == ledger.UnderCursor(0, [], [ledger.INBOX])
    # the cursor's own UID is gone: every file was numbered again above it
    numbers.numbering[ledger.INBOX] = {8: base(1), 9: base(2)}
    found = ledger.under_cursor(DOMAIN, listing, {}, {ledger.INBOX: (3, 77, base(3))})
    assert found == ledger.UnderCursor(0, [], [ledger.INBOX])
    # the cursor's UID names another file: an older uidlist put back
    numbers.numbering[ledger.INBOX] = {1: base(3), 2: base(1), 3: base(2)}
    found = ledger.under_cursor(DOMAIN, listing, {}, {ledger.INBOX: (3, 77, base(3))})
    assert found == ledger.UnderCursor(0, [], [ledger.INBOX])
    # a cursor no tick of this release gave a base name yet
    numbers.number(ledger.INBOX, 1, 2, 3)
    found = ledger.under_cursor(DOMAIN, listing, {}, {ledger.INBOX: (3, 77, None)})
    assert found == ledger.UnderCursor(0, [], [ledger.INBOX])


def test_the_archive_is_listed_from_its_directories_once_and_a_missing_folder_holds_nothing(
        tmp_path, archive_answers):
    _, _, held = world(tmp_path)
    listing = ledger.archive_listing(DOMAIN, tmp_path)
    assert list(listing) == [ledger.INBOX]
    assert listing[ledger.INBOX] == {path.name.partition(":")[0]: path.stat().st_ino
                                     for _, path in held.values()}
    bases = {path.name.partition(":")[0]: message for message, path in held.values()}
    assert ledger.archive_inodes(DOMAIN, bases, tmp_path, listing=listing) == inodes(held)
    assert archive_answers == [], "Dovecot was asked for the archive's names"
