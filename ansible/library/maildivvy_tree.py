#!/usr/bin/python
"""The programs role: deploy the code tree to /opt/maildivvy from the archive the install packs.

The deployed tree is compared with the archive: every path, its type, owner, mode and
content. When they match, nothing changes. When they differ, the destination is
removed first and the tree written again whole, so a copy can never nest into an
existing directory (`lib/lib`) or leave old code beside the new.

The modes are the product's, never the archive's: directories and programs (anything
under `bin/`) `0755`, every other file `0644`, all owned by root. Caches
(`__pycache__`, `*.pyc`) are never deployed, and a cache the interpreter writes at run
time is not a difference. An archive member that is absolute, climbs out with `..`,
or is anything but a file or a directory is refused before anything is written.
"""

import hashlib
import os
import shutil
import stat
import tarfile
from pathlib import Path, PurePosixPath

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_tree
short_description: Replace a code tree from an archive when it differs, removing the destination first
options:
  archive: {type: path, required: true, description: the packed tree, on the host}
  dest: {type: path, required: true, description: the directory the tree is deployed to}
  executable_dirs: {type: list, elements: str, default: [bin], description: top-level directories whose files are programs (0755)}
"""

DIR_MODE, FILE_MODE, PROGRAM_MODE = 0o755, 0o644, 0o755


class TreeError(Exception):
    pass


def is_cache(relpath):
    parts = PurePosixPath(relpath).parts
    return "__pycache__" in parts or relpath.endswith((".pyc", ".pyo"))


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise TreeError(f"the archive holds an unsafe path: {name}")
    return str(path)


def _file_mode(relpath, executable_dirs):
    return PROGRAM_MODE if PurePosixPath(relpath).parts[0] in executable_dirs else FILE_MODE


def _read_archive(archive, executable_dirs):
    """{relpath: (kind, mode, content or None)}, parents included; refuses unsafe members."""
    members = {d: ("dir", DIR_MODE, None) for d in executable_dirs}
    with tarfile.open(archive) as tar:
        for info in tar:
            name = safe_name(info.name)
            if not (info.isfile() or info.isdir()):
                raise TreeError(f"the archive holds {name}, which is neither a file nor a directory")
            if is_cache(name) or name == ".":
                continue
            for parent in list(PurePosixPath(name).parents)[:-1]:
                members.setdefault(str(parent), ("dir", DIR_MODE, None))
            if info.isdir():
                members[name] = ("dir", DIR_MODE, None)
            else:
                members[name] = ("file", _file_mode(name, executable_dirs), tar.extractfile(info).read())
    return members


def expected_tree(archive, owner=(0, 0), executable_dirs=("bin",)):
    """What the deployed tree must be: {relpath: (kind, mode, uid, gid[, sha256])}."""
    tree = {}
    for name, (kind, mode, content) in _read_archive(archive, executable_dirs).items():
        entry = (kind, mode, *owner)
        tree[name] = entry + (hashlib.sha256(content).hexdigest(),) if kind == "file" else entry
    return tree


def actual_tree(dest):
    """The deployed tree in the same shape; caches written at run time are left out."""
    dest = Path(dest)
    tree = {}
    if not dest.is_dir():
        return tree
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in dirs + files:
            path = Path(root) / name
            rel = str(path.relative_to(dest))
            if is_cache(rel):
                continue
            st = path.lstat()
            entry = (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
            if stat.S_ISDIR(st.st_mode):
                tree[rel] = ("dir", *entry)
            elif stat.S_ISREG(st.st_mode):
                tree[rel] = ("file", *entry, hashlib.sha256(path.read_bytes()).hexdigest())
            else:
                tree[rel] = ("other", *entry)
    return tree


def differences(expected, actual):
    """Every difference, one line per path in path order; an unexpected directory hides its contents."""
    found, unexpected_dirs = [], []
    for rel in sorted(expected.keys() | actual.keys(), key=lambda r: PurePosixPath(r).parts):
        if any(PurePosixPath(rel).is_relative_to(d) for d in unexpected_dirs):
            continue
        if rel not in actual:
            found.append(f"missing {rel}")
        elif rel not in expected:
            found.append(f"unexpected {rel}")
            if actual[rel][0] == "dir":
                unexpected_dirs.append(rel)
        elif expected[rel] != actual[rel]:
            found.append(f"{rel} differs")
    return found


def replace(archive, dest, owner=(0, 0), executable_dirs=("bin",)):
    """Write the tree beside `dest`, remove `dest`, move the new tree in, and read it back."""
    dest = Path(dest)
    members = _read_archive(archive, executable_dirs)  # refuses before anything is written
    new = dest.with_name(dest.name + ".new")
    if new.exists():
        shutil.rmtree(new)
    new.mkdir(mode=0o700)
    for name, (kind, mode, content) in sorted(members.items(), key=lambda m: PurePosixPath(m[0]).parts):
        path = new / name
        if kind == "dir":
            path.mkdir(mode=0o700)
        else:
            path.write_bytes(content)
        os.chown(path, *owner)
        path.chmod(mode)
    os.chown(new, *owner)
    new.chmod(DIR_MODE)
    if dest.exists():
        shutil.rmtree(dest)
    new.rename(dest)
    left = differences(expected_tree(archive, owner, executable_dirs), actual_tree(dest))
    if left:
        raise TreeError(f"{dest} differs from the archive after replacing it: {', '.join(left)}")


def main():
    module = AnsibleModule(
        argument_spec={"archive": {"type": "path", "required": True}, "dest": {"type": "path", "required": True},
                       "executable_dirs": {"type": "list", "elements": "str", "default": ["bin"]}},
        supports_check_mode=True,
    )
    p = module.params
    dirs = tuple(p["executable_dirs"])
    try:
        found = differences(expected_tree(p["archive"], executable_dirs=dirs), actual_tree(p["dest"]))
        if found and not module.check_mode:
            replace(p["archive"], p["dest"], executable_dirs=dirs)
    except (TreeError, OSError, tarfile.TarError) as e:
        module.fail_json(msg=str(e))
    module.exit_json(changed=bool(found), differences=found[:50])


if __name__ == "__main__":
    main()
