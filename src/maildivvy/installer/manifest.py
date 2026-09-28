"""The release tree's MANIFEST: the SHA-256 of every file in it.

One line per file, `<sha256>  <path>` as sha256sum writes it, paths relative to the tree's
root and sorted. The release build writes it; the installer checks the unpacked tree
against it before anything changes, and refuses a file changed, missing or added, and
anything that is not a regular file.
"""

import hashlib
import os
import re
from pathlib import Path

NAME = "MANIFEST"
LINE = re.compile(r"^([0-9a-f]{64})  (\S(?:.*\S)?)$")


def digest(path):
    """The file's SHA-256, as hex."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _entries(root):
    """Every path under `root` but the MANIFEST, relative, with whether it is a regular file."""
    root = Path(root)
    for directory, dirs, files in os.walk(root):
        dirs.sort()
        here = Path(directory)
        for name in sorted(files) + [d for d in dirs if (here / d).is_symlink()]:
            path = here / name
            relative = path.relative_to(root).as_posix()
            if relative != NAME:
                yield relative, path.is_file() and not path.is_symlink()


def write(root):
    """Write `root`/MANIFEST for the tree as it is."""
    root = Path(root)
    lines = [f"{digest(root / relative)}  {relative}\n" for relative, regular in sorted(_entries(root))
             if regular]
    (root / NAME).write_text("".join(lines))


def _listed(text):
    listed, problems = {}, []
    for number, line in enumerate(text.splitlines(), 1):
        match = LINE.match(line)
        parts = match.group(2).split("/") if match else []
        if not match or match.group(2).startswith("/") or {"..", ".", ""} & set(parts):
            problems.append(f"malformed {NAME} line {number}")
            continue
        listed[match.group(2)] = match.group(1)
    return listed, problems


def problems(root):
    """Why the tree at `root` is not the release its MANIFEST lists; [] when it is."""
    root = Path(root)
    try:
        text = (root / NAME).read_text()
    except FileNotFoundError:
        return [f"no {NAME}: {root} is not an unpacked release; unpack the release tarball and "
                "run ./maildivvy-install from it"]
    listed, found = _listed(text)
    if found:
        return found
    present = dict(_entries(root))
    for relative in sorted(present):
        if not present[relative]:
            found.append(f"not a regular file: {relative}")
        elif relative not in listed:
            found.append(f"not in the release: {relative}")
    changed = [r for r in sorted(listed) if present.get(r) and digest(root / r) != listed[r]]
    missing = [r for r in sorted(listed) if r not in present]
    return ([f"changed: {r} differs from the release's {NAME}" for r in changed]
            + [f"missing: {r} is in the release's {NAME} and not here" for r in missing]
            + found)
