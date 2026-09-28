"""The scanners' upstream releases, for the update signals, asked at most every
few hours.

- ClamAV: the TXT record `current.cvd.clamav.net`, the one freshclam itself reads
  (`maildivvy.lib.scan.current_cvd`); it names the release ClamAV recommends.
- rspamd: the image registry's tags for the pinned repository, the newest patch release
  on the pinned line.

⛔ The timer runs every five minutes and nobody should ask a registry that often, so the
last answer is kept in `/var/lib/maildivvy/health/upstream.json` with the moment it was
read, and asked again once it is older than `upstream_refresh_hours`. An answer that
cannot be read is UNKNOWN, never "nothing newer", and a kept answer is used only
while it is fresh.

The same file keeps the moment a newer ClamAV was first seen, since the design bounds how long
upstream may have been newer, not whether it is.
"""

import datetime
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from maildivvy.health.probe import Unreadable
from maildivvy.lib import scan

REGISTRY = "https://hub.docker.com/v2/repositories/{repository}/tags?page_size=100&name={line}."
RELEASE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def load(path):
    try:
        found = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}   # a cache that cannot be read is asked for again, never trusted
    return found if isinstance(found, dict) else {}


def save(path, record):
    path = Path(path)
    temporary = path.with_name(f".{path.name}.partial")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o644)
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def fresh(entry, now, hours):
    try:
        read_at = datetime.datetime.fromisoformat(entry["read_at"])
    except (KeyError, TypeError, ValueError):
        return False
    return datetime.timedelta(0) <= now - read_at <= datetime.timedelta(hours=hours)


def cached(path, key, now, hours, ask):
    """`ask()`'s answer, or the kept one while it is fresh. `ask` raises Unreadable."""
    record = load(path)
    entry = record.get(key)
    if isinstance(entry, dict) and fresh(entry, now, hours) and "answer" in entry:
        return entry["answer"], record
    answer = ask()
    record[key] = {"read_at": now.isoformat(), "answer": answer}
    try:
        save(path, record)
    except OSError:
        pass   # a cache that cannot be written only means asking again next run
    return answer, record


def clamav_release():
    found = scan.current_cvd()
    if found is None:
        raise Unreadable(f"the TXT record {scan.CURRENT_CVD} could not be read")
    return found.engine


def newest_patch(names, tag):
    """The newest `X.Y.Z` among `names` on the line of `tag` (`X.Y`), or None."""
    pinned = RELEASE.match(tag)
    if not pinned:
        raise Unreadable(f"the pinned tag {tag!r} is not a release X.Y.Z")
    same_line = [tuple(int(p) for p in m.groups()) for m in map(RELEASE.match, names)
                 if m and m.group(1) == pinned.group(1) and m.group(2) == pinned.group(2)]
    if not same_line:
        return None
    return ".".join(map(str, max(same_line)))


def rspamd_tags(repository, tag, timeout=20):
    """The registry's release tags on the pinned line."""
    name = repository.removeprefix("docker.io/")
    line = ".".join(tag.split(".")[:2])
    url = REGISTRY.format(repository=name, line=line)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as answer:
            data = json.load(answer)
    except (OSError, urllib.error.URLError, ValueError) as err:
        raise Unreadable(f"the registry {url.split('/v2/')[0]} could not be read: {err}") from None
    try:
        return [result["name"] for result in data["results"]]
    except (KeyError, TypeError):
        raise Unreadable("the registry's answer holds no list of tags") from None
