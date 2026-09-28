"""The bounds the checks judge by, and where each reading lives.

Every bound has a default here; `/etc/maildivvy/health.conf`, when it exists, overrides
any of them (`key=value`, `#` comments). The install writes no such file: an operator
adds one to move a bound, and a key this program does not know is refused rather than
ignored, so a misspelt bound is never a silent default.
"""

from dataclasses import dataclass, fields, replace
from pathlib import Path

CONF = Path("/etc/maildivvy/health.conf")
STATE_DIR = Path("/var/lib/maildivvy/health")
REPORT = STATE_DIR / "health.json"
UPSTREAM = STATE_DIR / "upstream.json"
CERTIFICATE = Path("/etc/maildivvy/certificate.json")
SCANNER = Path("/etc/maildivvy/scanner.json")
# Written by the disks step (install step 2): the disk mode, and the filesystems by UUID.
DISKS = Path("/etc/maildivvy/disks.json")
# Written by the publication step (install step 19) when it opens 993 and 465
# (`published_at`); the outside probe's result is added by maildivvy-publication.
# Absent while the ports are closed.
PUBLICATION = Path("/var/lib/maildivvy/publication.json")
STORE_SOCKET = Path("/run/maildivvy/health-store.sock")
SYSTEM_SOCKET = Path("/run/maildivvy/health-system.sock")


class SettingsError(Exception):
    """A health.conf this program must not run with. The message names the line."""


@dataclass(frozen=True)
class Settings:
    # the JSON file: the timer runs every five minutes, so three missed runs
    stale_minutes: int = 15
    # the store and index filesystems
    disk_warn_percent: int = 20
    disk_fail_percent: int = 10
    # the same in one-disk mode, stricter: mail and the system fill one filesystem
    single_disk_warn_percent: int = 30
    single_disk_fail_percent: int = 15
    # memory available to programs (the antivirus's reload is the peak)
    memory_warn_mib: int = 512
    memory_fail_mib: int = 256
    # the certificate: lego renews 30 days before expiry, so 21 days left is a renewal
    # that has not happened
    certificate_warn_days: int = 21
    certificate_fail_days: int = 7
    # a provided certificate: nothing renews it, so the operator is told a month ahead
    provided_certificate_warn_days: int = 30
    provided_certificate_fail_days: int = 7
    # the antivirus's signatures: the updater checks every hour
    signatures_warn_hours: int = 48
    signatures_fail_hours: int = 168
    # how long upstream may have a newer ClamAV than the installed one
    clamav_upstream_days: int = 7
    # how often upstream is asked at most; between asks the last answer is used
    upstream_refresh_hours: int = 6
    # the outbound queue
    queue_warn_minutes: int = 60
    queue_fail_minutes: int = 1440
    # the windows the journal and the request queue are read over
    sent_failure_hours: int = 24
    retrieval_failure_hours: int = 24     # deliveries the filter could not check
    request_failure_hours: int = 24
    # the fan-out runs every minute
    fanout_minutes: int = 10
    # no finished fetch run, or a collected row not fetched, for this long is FAIL; the
    # bound is at least three of the fetch timer's periods
    collection_minutes: int = 30
    # the newest dump of the database and the fetch state (48 h)
    backup_hours: int = 48
    # how old the outside probe's result may be
    publication_days: int = 30


def read(path=CONF):
    """The settings: the defaults, with a health.conf's values over them if one exists."""
    path = Path(path)
    try:
        text = path.read_text()
    except FileNotFoundError:
        return Settings()
    except OSError as err:
        raise SettingsError(f"cannot read {path}: {err.strerror}") from None
    known = {f.name for f in fields(Settings)}
    values = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = (part.strip() for part in line.partition("="))
        if not sep or key not in known:
            raise SettingsError(f"{path} line {number}: {key!r} is not a health setting")
        if key in values:
            raise SettingsError(f"{path} line {number}: {key} given twice")
        if not value.isdigit() or int(value) < 1:
            raise SettingsError(f"{path} line {number}: {key}={value}: a whole number above 0")
        values[key] = int(value)
    return replace(Settings(), **values)
