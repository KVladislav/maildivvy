#!/usr/bin/python
"""Install step 5: check a downloaded release against its checksums file and a pin.

The file's line is found by an anchored match on the whole file name, so the
`<file>.sbom.json` line beside it never counts; exactly one line must
match. The listed digest must equal the pinned one, and the downloaded file's digest
must equal both. Changes nothing.
"""

import hashlib

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: maildivvy_checksum
short_description: Verify a downloaded release against its checksums file and a pinned sha256
options:
  checksums: {type: path, required: true, description: the release's checksums file, on the host}
  file: {type: path, required: true, description: the downloaded archive, on the host}
  name: {type: str, required: true, description: the archive's name as the checksums file lists it}
  sha256: {type: str, required: true, description: the pinned sha256}
"""


class ChecksumError(Exception):
    pass


def anchored_checksum(text, name):
    """The digest of the one line `<sha256>  <name>`, matched on the whole name."""
    found = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name:
            found.append(parts[0].lower())
    if len(found) != 1:
        raise ChecksumError(f"the checksums file must have exactly one line for {name}, and has {len(found)}")
    return found[0]


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(text, path, name, pinned):
    listed = anchored_checksum(text, name)
    pinned = pinned.lower().removeprefix("sha256:")
    if listed != pinned:
        raise ChecksumError(f"{name}: the release lists sha256 {listed}, not the pinned {pinned}")
    actual = file_sha256(path)
    if actual != listed:
        raise ChecksumError(f"{name}: the downloaded file's sha256 is {actual}, not the release's {listed}")
    return actual


def main():
    module = AnsibleModule(
        argument_spec={"checksums": {"type": "path", "required": True}, "file": {"type": "path", "required": True},
                       "name": {"type": "str", "required": True}, "sha256": {"type": "str", "required": True}},
        supports_check_mode=True,
    )
    p = module.params
    try:
        with open(p["checksums"]) as f:
            digest = verify(f.read(), p["file"], p["name"], p["sha256"])
    except (ChecksumError, OSError) as e:
        module.fail_json(msg=str(e))
    module.exit_json(changed=False, sha256=digest)


if __name__ == "__main__":
    main()
