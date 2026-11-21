"""The ledger's consistency check, against a store built in a temporary directory.

The design says what a defect is and what is not: a name in a person's mailbox
pointing at an archive inode with no delivery row is the defect; every other file in
their mailbox, in any folder, is the person's own and the check ignores it. A delivery
row that outlived its file is normal - that is how a top-up avoids restoring mail
somebody deliberately deleted.

The archive's side of the reading comes from Dovecot in the real check;
here it is passed in, so the finding itself, the
counting by inode and the keying on (folder, UID) can be driven without a machine.
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


# --- a UID names a message only inside its folder -----------------------------------


def test_one_uid_in_two_folders_of_one_archive_is_two_messages(tmp_path):
    rows = [(21, 1, "delivered"), (22, 1, "withheld"), (23, 2, "released")]
    keyed = ledger.by_folder_and_uid(rows)
    assert keyed == {(ledger.INBOX, 1): 21,
                     (store.QUARANTINE, 1): 22,
                     (store.QUARANTINE, 2): 23}


def test_the_folder_of_a_row_is_its_own_state_and_never_guessed_from_the_uid():
    assert ledger.folder_of("delivered") == ledger.INBOX
    assert ledger.folder_of("withheld") == store.QUARANTINE
    assert ledger.folder_of("released") == store.QUARANTINE


# --- what the check selects on ------------------------------------------------------


def test_the_check_selects_on_columns_the_product_wrote_and_never_on_a_stored_header():
    sql = ledger.MESSAGES.lower()
    assert "archive_uid" in sql and "state" in sql
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
        self.messages = [(11, 1, "delivered"), (12, 2, "delivered")]
        self.deliveries = set(deliveries)
        self.asked = []
        self.rows = []

    def execute(self, sql, params):
        self.asked.append(sql)
        if sql == ledger.MAILBOXES:
            self.rows = self.mailboxes
        elif sql == ledger.MESSAGES_BY_UID:
            asked = set(zip(params[0], params[1]))
            self.rows = [m for m in self.messages if ((m[2] == "delivered"), m[1]) in asked]
        elif sql == ledger.DELIVERIES_OF:
            self.rows = [d for d in self.deliveries if d[0] in params[0]]
        else:
            raise AssertionError(sql)

    def fetchall(self):
        return self.rows


@pytest.fixture
def archive_answers(monkeypatch):
    """Dovecot's answer for the world's archive: INBOX holds UIDs 1 and 2, no quarantine."""
    asked = []

    def fetch(login, folder, fields, *search):
        asked.append(folder)
        if folder != ledger.INBOX:
            raise doveadm.DoveadmError("no such folder", doveadm.EX_NOUSER)
        return [{"uid": "1", "storageid": "1757.M1.host"}, {"uid": "2", "storageid": "1757.M2.host"}]

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


def listed(*uids):
    return [{"uid": str(uid), "storageid": f"1757.M{uid}.host"} for uid in uids]


@pytest.fixture
def dovecot_numbers(monkeypatch):
    """Dovecot's UIDVALIDITY for the archive's folders, and which were asked for it."""
    asked = []

    def status(login, folder, *fields):
        asked.append(folder)
        return {"uidvalidity": "77"}

    monkeypatch.setattr(doveadm, "mailbox_status", status)
    return asked


def test_a_message_at_or_below_the_cursor_with_no_row_is_found_and_one_above_it_never(dovecot_numbers):
    """The pass moved its cursor past UID 3 without a row: skipped. UIDs 6 and 7 are above
    the cursor, mail the next tick records."""
    by_uid = {(ledger.INBOX, uid): 10 + uid for uid in (1, 2, 4, 5)}
    found = ledger.under_cursor(DOMAIN, {ledger.INBOX: listed(1, 2, 3, 4, 5, 6, 7)}, by_uid,
                                {ledger.INBOX: (5, 77)})
    assert found == ledger.UnderCursor(5, [ledger.Unrecorded(ledger.INBOX, 1, [3])], [])
    # the cursor's own UID is at it, and counts
    found = ledger.under_cursor(DOMAIN, {ledger.INBOX: listed(1, 2, 3)}, {(ledger.INBOX, 1): 11},
                                {ledger.INBOX: (3, 77)})
    assert found.unrecorded == [ledger.Unrecorded(ledger.INBOX, 2, [2, 3])]


def test_each_folder_is_held_to_its_own_cursor_and_its_own_rows(dovecot_numbers):
    """UID 1 of the quarantine has a row, a released one whose file never moved; UID 1 of
    INBOX has none. A folder nothing was read of yet has nothing at or below its cursor."""
    by_uid = ledger.by_folder_and_uid([(21, 1, "released"), (22, 2, "delivered")])
    listing = {ledger.INBOX: listed(1, 2), store.QUARANTINE: listed(1)}
    cursors = {ledger.INBOX: (2, 77), store.QUARANTINE: (1, 77)}
    found = ledger.under_cursor(DOMAIN, listing, by_uid, cursors)
    assert found == ledger.UnderCursor(3, [ledger.Unrecorded(ledger.INBOX, 1, [1])], [])
    for nothing_read in ({}, {ledger.INBOX: (0, None)}):
        assert ledger.under_cursor(DOMAIN, listing, {}, nothing_read) == ledger.UnderCursor(0, [], [])
    # a cursor row whose folder is not there holds nothing either
    assert ledger.under_cursor(DOMAIN, {}, {}, cursors) == ledger.UnderCursor(0, [], [])


def test_a_folders_finding_names_its_first_uids_and_counts_them_all(dovecot_numbers):
    found = ledger.under_cursor(DOMAIN, {ledger.INBOX: listed(*range(1, 5001))},
                                {(ledger.INBOX, 5000): 1}, {ledger.INBOX: (5000, 77)})
    assert found.read == 5000
    assert found.unrecorded == [ledger.Unrecorded(ledger.INBOX, 4999, list(range(1, ledger.NAMED + 1)))]


def test_a_folder_dovecot_numbered_again_is_named_apart_and_none_of_its_uids_is_a_finding(dovecot_numbers):
    """The rows' UIDs are another numbering's: holding the listing to them would name
    files that have rows. Both of the pass's tests, and nothing is written to adopt."""
    listing = {ledger.INBOX: listed(1, 2, 3)}
    # another UIDVALIDITY than the cursor row keeps
    found = ledger.under_cursor(DOMAIN, listing, {}, {ledger.INBOX: (3, 76)})
    assert found == ledger.UnderCursor(0, [], [ledger.INBOX])
    # the cursor's own UID is gone: every file was numbered again above it
    found = ledger.under_cursor(DOMAIN, {ledger.INBOX: listed(8, 9)}, {}, {ledger.INBOX: (3, 77)})
    assert found == ledger.UnderCursor(0, [], [ledger.INBOX])
    # a row no tick gave a UIDVALIDITY yet takes Dovecot's, which is not asked for
    del dovecot_numbers[:]
    found = ledger.under_cursor(DOMAIN, listing, {}, {ledger.INBOX: (3, None)})
    assert found.unrecorded == [ledger.Unrecorded(ledger.INBOX, 3, [1, 2, 3])] and dovecot_numbers == []


def test_the_archive_is_listed_once_for_both_readings_and_a_missing_folder_holds_nothing(
        tmp_path, archive_answers):
    _, _, held = world(tmp_path)
    listing = ledger.archive_listing(DOMAIN)
    assert list(listing) == [ledger.INBOX] and archive_answers == [ledger.INBOX, store.QUARANTINE]
    by_uid = {key: message for key, (message, _) in held.items()}
    assert ledger.archive_inodes(DOMAIN, by_uid, tmp_path, listing=listing) == inodes(held)
    assert len(archive_answers) == 2   # no second listing was taken
