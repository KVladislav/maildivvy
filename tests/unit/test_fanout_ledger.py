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
from pathlib import Path

from maildivvy.fanout import ledger
from maildivvy.lib import store


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
