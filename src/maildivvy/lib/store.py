"""Store paths and folder names, derived from (domain, account) in one place.

Every reader turns a (domain, account) pair into the same paths through this module:
the home `<store>/<domain>/<account>` and the index trees
`<index>/{idx,ctl}/<domain>/<account>`. The SQL views Dovecot reads
carry the same expressions; the schema's tests hold them to this module.

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
"""

import os
import pwd
from pathlib import Path

STORE_ROOT = Path("/srv/maildivvy/store")
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


def resolve(folder_maildir, base):
    """The file of a message in one folder's maildir, from its storage id, or None.

    Only the names of MESSAGE_NAMES are tried, never a listing of the directory: the
    file can be renamed between Dovecot's answer and our use of it, and a scan races
    that same rename. A caller that gets None asks Dovecot again.
    """
    if not isinstance(base, str) or base in ("", ".", "..") or any(c in base for c in "/\0:"):
        raise StoreError(f"storage id {base!r} is not a maildir base name")
    for name in MESSAGE_NAMES:
        candidate = Path(folder_maildir) / name.format(base)
        if candidate.exists():
            return candidate
    return None


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
