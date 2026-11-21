"""Store paths and folder names, derived from (domain, account) in one place.

Every reader turns a (domain, account) pair into the same paths through this module:
the home `<store>/<domain>/<account>` and the index trees
`<index>/{idx,ctl}/<domain>/<account>`. The SQL views Dovecot reads
carry the same expressions; the schema's tests hold them to this module. A snapshot of
an IMAP mailbox is a Maildir++ tree under `SNAPSHOT_ROOT`, named through `maildir` as
a home's folders are.

Two separators, never mixed:

- in IMAP a hierarchy is joined by `/`;
- on disk, Maildir++ flattens it into one directory joined by `.`: `.Sent.u1`, never
  `.Sent/u1`, a directory Dovecot never looks in.

A folder name may itself hold a `.`, as `Sent/ivan.p` does for a dotted login.
Dovecot runs with `mailbox_list_storage_escape_char = ^`, so on disk
each name part has `^` written as `^5e` and then `.` as `^2e`: `Sent/ivan.p` is
`.Sent.ivan^2ep`, beside `.Sent.ivan`. Anything that reads the store directly goes
through `maildir` here, since a directory name is no longer the IMAP name with `/`
turned into `.`.

Directories are made by the mail owner with mode 0700, every missing ancestor
included, the mode set by chmod after mkdir, since mkdir's is masked by the umask and
`os.makedirs` sets only the last component's.

Every maildir file name is read and made here too, for the pass, the request queue, the
ledger's check and the Sent hook alike: a message's file from its storage id (`resolve`
in the archive, `resolve_own` in a person's folder), its base name and the parts of its
name, every file of a mailbox, and a new name for a message (`link_into`).
"""

import datetime
import os
import pwd
import re
from pathlib import Path

STORE_ROOT = Path("/srv/maildivvy/store")
# The snapshots of IMAP mailboxes, one `<external mailbox id>/` each, beside the domains'
# homes: a domain's label admits no `_`, so no domain can take this name.
SNAPSHOT_ROOT = STORE_ROOT / "_snapshots"
# The import's staging directory: files put here, on the store's filesystem, are
# renamed into the store rather than copied. Beside the snapshots, and no domain either.
IMPORTS_ROOT = STORE_ROOT / "_imports"
# The store's directories that are no domain's, which health's check of directories no row
# holds passes over.
NOT_DOMAINS = (SNAPSHOT_ROOT.name, IMPORTS_ROOT.name)
INDEX_ROOT = Path("/srv/maildivvy/index")
MAIL_USER = "vmail"
ARCHIVE = "archive"
QUARANTINE = "Quarantine"  # the archive's folder for withheld mail; pass_cursor's CHECK names it
SEPARATOR = "/"
ESCAPE = "^"  # Dovecot's mailbox_list_storage_escape_char, set from the first install
DIR_MODE = 0o700


class StoreError(Exception):
    """A name that cannot be turned into a path or folder, or a directory refused."""


def _segment(what, value):
    if not isinstance(value, str) or value in ("", ".", "..") or "/" in value or "\0" in value:
        raise StoreError(f"{what} {value!r} is not one path segment")
    return value


def home(domain, account, root=STORE_ROOT):
    return Path(root) / _segment("domain", domain) / _segment("account", account)


def archive_home(domain, root=STORE_ROOT):
    """The archive is an ordinary mailbox with the reserved account name."""
    return home(domain, ARCHIVE, root)


def index_paths(domain, account, root=INDEX_ROOT):
    """(index tree, control tree) of one mailbox."""
    relative = home(domain, account, root="/").relative_to("/")
    return Path(root) / "idx" / relative, Path(root) / "ctl" / relative


def mailbox_name(*parts):
    """An IMAP mailbox name from its hierarchy, joined by `/`."""
    if not parts:
        raise StoreError("a mailbox name needs at least one part")
    for part in parts:
        if not part or SEPARATOR in part or "\0" in part or part in (".", ".."):
            raise StoreError(f"mailbox name part {part!r} is empty, '.' or '..', or holds '/'")
    return SEPARATOR.join(parts)


def escape(part):
    """One name part as Dovecot stores it: the escape character first, then the dot."""
    return part.replace(ESCAPE, f"{ESCAPE}{ord(ESCAPE):02x}").replace(".", f"{ESCAPE}{ord('.'):02x}")


def maildir(box_home, folder=None):
    """The maildir of a mailbox's INBOX, or of one folder given by its IMAP name."""
    box = Path(box_home) / "Maildir"
    if folder is None or folder.upper() == "INBOX":
        return box
    return box / ("." + ".".join(escape(part) for part in _folder_parts(folder)))


def _folder_parts(folder):
    parts = folder.split(SEPARATOR)
    mailbox_name(*parts)
    return parts


# The names a message's file can have in a maildir, from its base name: Dovecot moves it
# from new/ to cur/ and appends the flags. The archive's ACL lets an administrator set
# \Seen alone, so these are every name it can take. IMAP gives the first
# three; doveadm's own `flags` renames in place, in new/ (measured on 2.4.2), which gives
# the next two; `cur/<base>` is plain Maildir.
MESSAGE_NAMES = ("new/{}", "cur/{}:2,", "cur/{}:2,S", "new/{}:2,", "new/{}:2,S", "cur/{}")


def _check_base(base):
    if not isinstance(base, str) or base in ("", ".", "..") or any(c in base for c in "/\0:"):
        raise StoreError(f"storage id {base!r} is not a maildir base name")


def resolve(folder_maildir, base):
    """The file of a message in one ARCHIVE folder's maildir, from its storage id, or None.

    Only the names of MESSAGE_NAMES are tried, never a listing of the directory: the
    file can be renamed between Dovecot's answer and our use of it, and a scan races
    that same rename. A caller that gets None asks Dovecot again.

    ⚠️ Exact because the archive's ACL allows \\Seen alone. A person's own folder carries
    any flag its client sets: that is `resolve_own`, and the two stay apart.
    """
    _check_base(base)
    for name in MESSAGE_NAMES:
        candidate = Path(folder_maildir) / name.format(base)
        if candidate.exists():
            return candidate
    return None


def resolve_own(folder_maildir, base):
    """The file of a message in a PERSON's own folder, from its storage id, or None.

    ⚠️ NOT THE ARCHIVE'S RESOLVER, and not to be merged into it. A client sets any flag
    or keyword on its own folder, on the APPEND itself: `APPEND Sent (\\Seen \\Flagged)`
    is `cur/<base>:2,FS`, a keyword adds a lowercase letter after the flags, and no fixed
    set of names covers that. So after the exact names, `cur/` and `new/` of this one folder
    are listed for the base name followed by `:2,`. The base name is still Dovecot's
    answer, and a file Dovecot reports has left `tmp/`, so this never picks a file by
    listing and never sees one still being written. The listing races a rename as the
    exact names do; a caller that gets None says so.
    """
    found = resolve(folder_maildir, base)
    if found is not None:
        return found
    prefix = f"{base}:2,"
    for sub in ("cur", "new"):
        try:
            with os.scandir(Path(folder_maildir) / sub) as entries:
                for entry in entries:
                    if entry.name.startswith(prefix):
                        return Path(entry.path)
        except FileNotFoundError:
            continue
    return None


# A message the import filed into an archive's INBOX is told by its storage id,
# its file's whole base name: `<received epoch>.<sha256 hex>.import,S=<bytes>,W=<vsize>`.
# A delivery agent's name, `<sec>.M<usec>P<pid>.<host>,S=<n>,W=<n>`, cannot match it, nor
# can a snapshot's `<uidvalidity>.<uid>.snapshot,S=<n>`. The epoch is the moment the
# message arrived in the store it came from, which the pass records as its `received_at`.
#
# ⛔ `W=` IS THE SIZE EVERY CLIENT IS TOLD, AND NOTHING CHECKS IT AFTERWARDS. `S=` is the
# file's size; `W=` is the size Dovecot answers `RFC822.SIZE` with, the file's with every
# line end made CR LF: its size plus one for each line feed no carriage return precedes.
# With both in the name Dovecot never reads a file to learn its size, which the first
# synchronisation of a client asks of every message; a `W=` that is wrong is a wrong size
# at every client, since `maildir_broken_filename_sizes` covers `S=` alone. A file keeps
# its name for good, so the name is this one from the first import on.
IMPORTED = re.compile(r"^(\d+)\.([0-9a-f]{64})\.import,S=(\d+),W=(\d+)$")


def imported(base):
    """The received epoch an imported message's storage id carries, or None for any other.

    ⛔ The WHOLE base name, matched as one: `.import` anywhere else in a name is not an
    imported message.
    """
    found = IMPORTED.match(base) if isinstance(base, str) else None
    return int(found.group(1)) if found else None


def import_base(epoch, sha256, size, vsize):
    """The storage id the import gives a message: what `imported` reads back.

    `size` is the file's and `vsize` the one Dovecot gives it over IMAP, which is never
    under the file's nor over twice it: a line feed adds one byte at most.
    """
    size, vsize = int(size), int(vsize)
    base = f"{int(epoch)}.{sha256}.import,S={size},W={vsize}"
    if imported(base) != int(epoch) or not size <= vsize <= 2 * size:
        raise StoreError(f"{base!r} is not an imported message's name")
    return base


# The folders a person is given imported history in, one a year: incoming under
# `Archives`, sent under `Sent`. Live mail keeps INBOX and `Sent`; the domain archive's own
# folders are not these.
ARCHIVES = "Archives"
SENT = "Sent"


def year_folder(base, top):
    """`<top>/<YYYY>` for an imported message's storage id: the UTC year of the received
    epoch its name carries.

    ⛔ TOLD BY THE NAME ALONE, and in UTC as the name's epoch is: a second top-up, a
    deliver-one and the import compute the same folder, and nothing records it.
    """
    epoch = imported(base)
    if epoch is None:
        raise StoreError(f"{base!r} is not an imported message's name")
    year = datetime.datetime.fromtimestamp(epoch, datetime.UTC).year
    return mailbox_name(top, f"{year:04d}")


def name_parts(path):
    """(base name, info) of a message file's name: `<base>:2,FS` is (`<base>`, `2,FS`).

    The info is None for a name with no `:` at all, the name a message has in `new/`
    before anybody reads it, and `""` for one that ends in the `:`.
    """
    base, colon, info = Path(path).name.partition(":")
    return base, (info if colon else None)


def base_name(path):
    """The name a message's other names are derived from: its file's base name.

    A retry then produces the same name, so a repeated tick is idempotent instead of
    minting a second copy. The archive's own flags are not the receiver's: a message an
    administrator read is still new to everybody else.
    """
    return name_parts(path)[0]


# A maildir's message directories; its bookkeeping files are elsewhere, and `tmp/` holds
# files still being written.
PARTS = ("cur", "new")


def message_files(box):
    """Every message file of one maildir directory: `cur/` and `new/`, nothing else."""
    for part in PARTS:
        directory = Path(box) / part
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.is_file():
                yield path


def message_dirs(box_home):
    """Every message directory of a mailbox: `cur/` and `new/` of its INBOX and of each
    of its folders."""
    box = maildir(box_home)
    if not box.is_dir():
        return
    folders = [box] + [child for child in sorted(box.iterdir())
                       if child.is_dir() and child.name.startswith(".")]
    for folder in folders:
        for part in PARTS:
            directory = folder / part
            if directory.is_dir():
                yield directory


def mailbox_files(box_home):
    """Every message file of a mailbox: its INBOX and each of its folders.

    ⚠️ A LISTING, so for a whole mailbox and never to find one message: a name is found
    from Dovecot's storage id (`resolve`, `resolve_own`). Each directory is listed in full
    before its first file is handed back, so a caller may unlink as it goes.
    """
    for directory in message_dirs(box_home):
        for path in sorted(directory.iterdir()):
            if path.is_file():
                yield path


def mail_owner():
    """(uid, gid) of the mail owner, read from the system, never assumed."""
    entry = pwd.getpwnam(MAIL_USER)
    return entry.pw_uid, entry.pw_gid


def make_dir(path, root, uid=None, gid=None, mode=DIR_MODE):
    """Make `path` and every missing directory between `root` and it.

    Each one made is chowned to the mail owner and chmoded to `mode` after mkdir.
    Directories that exist are left as they are. Returns the directories made.
    """
    root = Path(root)
    path = Path(os.path.normpath(root / path))
    if not root.is_dir():
        raise StoreError(f"store root {root} does not exist")
    if path == root or root not in path.parents:
        raise StoreError(f"{path} is outside {root}")
    if uid is None or gid is None:
        uid, gid = mail_owner()

    made = []
    for step in reversed([path, *path.parents[: len(path.relative_to(root).parts) - 1]]):
        try:
            step.mkdir(mode=mode)
        except FileExistsError:
            continue
        os.chown(step, uid, gid)
        os.chmod(step, mode)
        made.append(step)
    return made


def make_maildir(box, root, uid=None, gid=None):
    """A maildir's `cur/`, `new/` and `tmp/`, made as `make_dir` makes any directory."""
    for part in ("cur", "new", "tmp"):
        make_dir(Path(box) / part, root, uid, gid)
    return Path(box)


def link_into(source, maildirs, root=STORE_ROOT, made=None):
    """Add one name for `source` in the `new/` of each maildir; returns the directories touched.

    The name is the source's base name, and EEXIST is success. A person who
    has never logged in has no maildir yet, so it is made here, by the mail owner, 0700.
    `made`, when given, gets every name this call created, and no
    name that was there already: a request takes back what it made when it fails.
    """
    name = base_name(source)
    touched = []
    for box in maildirs:
        directory = Path(box) / "new"
        if not directory.is_dir():
            make_maildir(box, root)
        try:
            os.link(source, directory / name)
        except FileExistsError:
            pass  # the name this tick would make is already there: the retry is done
        else:
            if made is not None:
                made.append(directory / name)
        touched.append(directory)
    return touched


def link_imported(source, maildirs, root=STORE_ROOT, made=None):
    """Add one name for an IMPORTED archive message in the `cur/` of each maildir.

    The person is given old mail as they had it: `cur/<base>:2,S` when the archive's own
    name is seen, `cur/<base>:2,` otherwise, so `\\Seen` reaches them; a message named in
    `new/` would be new mail to their client. Otherwise as `link_into`: EEXIST is success,
    a missing maildir is made, and `made` gets every name this call created. Only a
    request's top-up, connect, deliver-one or release names an imported message; the pass,
    the Sent hook and a release of live mail keep `link_into`.
    """
    base, info = name_parts(source)
    if imported(base) is None:
        raise StoreError(f"{base!r} is not an imported message's name")
    name = f"{base}:2,S" if info is not None and "S" in info.partition(",")[2] else f"{base}:2,"
    touched = []
    for box in maildirs:
        directory = Path(box) / "cur"
        if not directory.is_dir():
            make_maildir(box, root)
        try:
            os.link(source, directory / name)
        except FileExistsError:
            pass
        else:
            if made is not None:
                made.append(directory / name)
        touched.append(directory)
    return touched


def fsync_dirs(directories):
    """fsync each directory once, after the last link and before the ledger commits."""
    for directory in dict.fromkeys(str(d) for d in directories):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
