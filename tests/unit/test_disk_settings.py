"""The disks chosen by device at the first install and known by filesystem UUID after it, or
one disk: install step 1's disk plan and health's filesystem checks, as pure functions."""

from types import SimpleNamespace

import pytest

from maildivvy.health import settings, system
from maildivvy.health.probe import Unreadable
from maildivvy.health.report import FAIL, PASS, WARN
from maildivvy_preflight import GIB, LABELS, separate_disks, setting_errors, single_disk

GOOD = {
    "hostname": "mail",
    "cert_name": "mail.example.test",
    "vmail_uid": 900,
    "vmail_gid": 900,
    "admin_networks": ["192.0.2.0/24"],
    "breakglass_password": "correct horse battery",
    "acme_dns_credentials": {"DESEC_TOKEN": "scoped-token"},
}


def disk(name, gib=8, **extra):
    return {"name": name, "path": f"/dev/{name}", "size": gib * GIB, "type": "disk",
            "fstype": None, "label": None, "uuid": None, "mountpoints": [None], **extra}


def ours(name, role, uuid, **extra):
    return disk(name, fstype="xfs" if role != "swap" else "swap", label=LABELS[role], uuid=uuid, **extra)


# lsblk --tree on an Ubuntu install with LVM: the root is two levels below the disk
SYSTEM = disk("xvda", 20, children=[
    {"name": "xvda1", "path": "/dev/xvda1", "type": "part", "size": GIB, "mountpoints": ["/boot"]},
    {"name": "xvda2", "path": "/dev/xvda2", "type": "part", "size": 19 * GIB, "mountpoints": [None],
     "fstype": "LVM2_member",
     "children": [{"name": "vg-root", "path": "/dev/mapper/vg-root", "type": "lvm", "fstype": "ext4",
                   "mountpoints": ["/"]}]}])
BLANK_C, BLANK_D, BLANK_E = disk("xvdc"), disk("xvdd"), disk("xvde")
CHOSEN = {"store": "/dev/xvdc", "index": "/dev/xvdd"}
NOT_MOUNTED = {"store": None, "index": None}


def plan(chosen=CHOSEN, devices=(SYSTEM, BLANK_C, BLANK_D, BLANK_E), record=None, mounted=NOT_MOUNTED):
    return separate_disks(chosen, list(devices), record, mounted)


# --- the settings ----------------------------------------------------------------


def test_separate_mode_is_the_default_and_the_device_settings_are_checked_for_shape():
    assert setting_errors({**GOOD, "store_disk": "/dev/xvdc", "index_disk": "/dev/xvdd",
                           "swap_disk": "/dev/xvde"}) == []
    assert setting_errors({**GOOD, "disk_mode": "separate"}) == []  # the devices are the disk plan's to ask for
    for name, value in (("disk_mode", "raid"), ("store_disk", "xvdc"), ("index_disk", "/dev/xvd d"),
                        ("single_disk_allow_reflink", "maybe")):
        errors = setting_errors({**GOOD, name: value})
        assert len(errors) == 1 and errors[0].startswith(f"malformed {name}:"), errors


def test_one_disk_mode_refuses_a_disk_setting_rather_than_ignoring_it():
    assert setting_errors({**GOOD, "disk_mode": "single"}) == []
    errors = setting_errors({**GOOD, "disk_mode": "single", "store_disk": "/dev/xvdc", "swap_disk": "/dev/xvde"})
    assert [e.split(":")[0] for e in errors] == ["ambiguous store_disk", "ambiguous swap_disk"]
    assert "disk_mode is single" in errors[0]


def test_the_old_size_settings_are_no_longer_read():
    # a first version's settings file still carries them; they neither pass nor fail anything
    assert setting_errors({**GOOD, "store_gib": 12, "index_gib": "twelve"}) == []


# --- separate mode: the first install, by device ---------------------------------


def test_empty_whole_disks_named_by_device_are_taken_blank():
    disks, errors = plan()
    assert errors == []
    assert disks == {"store": {"path": "/dev/xvdc", "label": LABELS["store"], "state": "blank", "uuid": None},
                     "index": {"path": "/dev/xvdd", "label": LABELS["index"], "state": "blank", "uuid": None}}


def test_a_disk_with_only_a_partition_table_is_not_blank():
    """mkfs.xfs without -f refuses a disk that still carries a partition table: step 1 says so."""
    disks, errors = plan(devices=(SYSTEM, disk("xvdc", pttype="gpt"), BLANK_D, BLANK_E))
    assert errors == ["store_disk /dev/xvdc is not empty (a partition table, partitions, a filesystem or a mount); "
                      "refusing to format it"]


def test_the_system_disk_is_refused_by_name():
    disks, errors = plan({**CHOSEN, "store": "/dev/xvda"})
    assert errors == ["store_disk /dev/xvda is the system disk: it holds /; refusing to format it"]
    assert "store" not in disks and "index" in disks  # the control: the other one is taken


def test_a_partition_or_something_that_is_no_disk_is_refused():
    _, errors = plan({**CHOSEN, "store": "/dev/xvda1"})
    assert errors == ["store_disk /dev/xvda1 is not a whole disk (part); name the disk itself"]
    _, errors = plan({**CHOSEN, "index": "/dev/sdz"})
    assert errors == ["no index disk: /dev/sdz is no block device on this machine"]


@pytest.mark.parametrize("extra", [
    {"fstype": "ext4", "uuid": "u-1"},
    {"fstype": "xfs", "label": LABELS["index"], "uuid": "u-2"},    # ours, but for the other role
    {"children": [{"name": "xvdc1", "path": "/dev/xvdc1", "type": "part"}]},
    {"mountpoints": ["/mnt"]},
])
def test_a_disk_that_is_not_empty_is_never_formatted(extra):
    _, errors = plan(devices=(SYSTEM, disk("xvdc", **extra), BLANK_D))
    assert errors == ["store_disk /dev/xvdc is not empty (a partition table, partitions, a filesystem or a mount); "
                      "refusing to format it"]


def test_one_disk_named_for_two_roles_is_refused():
    _, errors = plan({"store": "/dev/xvdc", "index": "/dev/xvdc"})
    assert errors == ["ambiguous index_disk: /dev/xvdc is also the store disk"]
    _, errors = plan({**CHOSEN, "swap": "/dev/xvdd"})
    assert errors == ["ambiguous swap_disk: /dev/xvdd is also the index disk"]


def test_the_store_and_index_disks_are_required_at_the_first_install_and_swap_is_not():
    _, errors = plan({})
    assert [e.split(":")[0] for e in errors] == ["missing store_disk", "missing index_disk"]
    disks, errors = plan({**CHOSEN, "swap": "/dev/xvde"})
    assert errors == [] and disks["swap"]["state"] == "blank"


def test_a_disk_this_install_formatted_before_its_record_was_written_is_ours():
    # a first run that stopped between mkfs and the record: the re-run finds its own label
    disks, errors = plan(devices=(SYSTEM, ours("xvdc", "store", "u-3"), BLANK_D))
    assert errors == []
    assert disks["store"] == {"path": "/dev/xvdc", "label": LABELS["store"], "state": "ours", "uuid": "u-3"}
    assert disks["index"]["state"] == "blank"


# --- separate mode: every later run, by UUID only -------------------------------------


RECORD = {"mode": "separate", "uuids": {"store": "u-store", "index": "u-index"}}


def test_recorded_disks_are_found_by_uuid_whatever_their_device_is_called_now():
    # the letters moved at boot: the store is now xvdd, the index xvdc, and the settings
    # still name the first install's devices
    swapped = (SYSTEM, ours("xvdc", "index", "u-index"), ours("xvdd", "store", "u-store"))
    disks, errors = plan(devices=swapped, record=RECORD)
    assert errors == []
    assert disks["store"] == {"path": "/dev/xvdd", "label": LABELS["store"], "state": "ours", "uuid": "u-store"}
    assert disks["index"]["path"] == "/dev/xvdc"
    # the device settings are not read at all: absent, or naming the system disk
    assert plan({}, swapped, RECORD) == (disks, [])
    assert plan({"store": "/dev/xvda", "index": "/dev/xvda"}, swapped, RECORD) == (disks, [])


def test_a_recorded_filesystem_that_no_disk_carries_is_refused():
    _, errors = plan(devices=(SYSTEM, ours("xvdd", "index", "u-index"), BLANK_C), record=RECORD)
    assert errors == ["no store disk: no disk carries the filesystem u-store recorded in "
                      "/etc/maildivvy/disks.json"]


def test_a_swap_disk_can_be_added_after_the_first_install():
    devices = (SYSTEM, ours("xvdc", "store", "u-store"), ours("xvdd", "index", "u-index"), BLANK_E)
    disks, errors = plan({"swap": "/dev/xvde"}, devices, RECORD)
    assert errors == [] and disks["swap"]["state"] == "blank"


@pytest.mark.parametrize("record", [{"mode": "separate"}, {"mode": "separate", "uuids": {"store": 3}},
                                    ["separate"], {"uuids": {}}])
def test_a_record_that_is_not_one_is_refused(record):
    _, errors = plan(record=record)
    assert errors == ["unreadable /etc/maildivvy/disks.json: not a record of the disks; "
                      "restore it from the backup or correct it by hand"]


def test_a_machine_installed_in_one_disk_mode_is_not_turned_into_separate_disks():
    _, errors = plan(record={"mode": "single"})
    assert errors == ["wrong disk_mode: this machine was installed in single mode "
                      "(/etc/maildivvy/disks.json), and a re-run never changes it"]


# --- separate mode: a first-version machine --------------------------------------------


def mount(source, uuid):
    return {"source": source, "uuid": uuid, "fstype": "xfs"}


FIRST_VERSION = (SYSTEM, ours("xvdc", "store", "u-store", mountpoints=["/srv/maildivvy/store"]),
                 ours("xvdd", "index", "u-index", mountpoints=["/srv/maildivvy/index"]),
                 ours("xvde", "swap", "u-swap", mountpoints=["[SWAP]"]))
FIRST_MOUNTS = {"store": mount("/dev/xvdc", "u-store"), "index": mount("/dev/xvdd", "u-index")}


def test_a_first_version_machine_is_recognised_by_its_mounted_uuids_and_carried_over():
    # its settings name sizes, which are not read: no device setting at all
    disks, errors = plan({}, FIRST_VERSION, None, FIRST_MOUNTS)
    assert errors == []
    assert {role: (d["path"], d["state"], d["uuid"]) for role, d in disks.items()} == {
        "store": ("/dev/xvdc", "ours", "u-store"), "index": ("/dev/xvdd", "ours", "u-index"),
        "swap": ("/dev/xvde", "ours", "u-swap")}


def test_what_is_mounted_wins_over_a_device_setting_that_names_another_disk():
    # formatting the named blank disk would hide the mounted store behind a new filesystem
    devices = (*FIRST_VERSION, disk("xvdf"))
    disks, errors = plan({"store": "/dev/xvdf", "index": "/dev/xvdd"}, devices, None, FIRST_MOUNTS)
    assert errors == [] and disks["store"]["path"] == "/dev/xvdc" and disks["store"]["state"] == "ours"


def test_a_mount_point_holding_a_filesystem_this_install_did_not_make_is_refused():
    foreign = disk("xvdf", fstype="ext4", uuid="u-f", mountpoints=["/srv/maildivvy/store"])
    mounted = {"store": {"source": "/dev/xvdf", "uuid": "u-f", "fstype": "ext4"}, "index": None}
    _, errors = plan(CHOSEN, (SYSTEM, BLANK_C, BLANK_D, foreign), None, mounted)
    assert errors == ["/srv/maildivvy/store is already mounted from /dev/xvdf (ext4), which this install "
                      "did not make; unmount it and take it out of /etc/fstab first"]


# --- one-disk mode -------------------------------------------------------------------


def root(fstype="ext4", reflink=None, target="/"):
    return {"target": target, "source": "/dev/mapper/vg-root", "fstype": fstype, "reflink": reflink}


@pytest.mark.parametrize("filesystem", [root(), root("xfs", False), root("ext4", target="/srv")])
def test_one_disk_mode_keeps_the_store_and_index_on_the_filesystem_that_holds_them(filesystem):
    found, errors = single_disk(filesystem, False, None, NOT_MOUNTED)
    assert errors == [] and found == filesystem


def test_an_xfs_root_with_reflink_on_needs_the_explicit_consent():
    _, errors = single_disk(root("xfs", True), False, None, NOT_MOUNTED)
    assert len(errors) == 1 and errors[0].startswith("refused single_disk_allow_reflink: / is xfs with reflink on")
    found, errors = single_disk(root("xfs", True), True, None, NOT_MOUNTED)
    assert errors == [] and found["reflink"] is True


def test_one_disk_mode_refuses_a_filesystem_it_does_not_support_or_cannot_read():
    _, errors = single_disk(root("btrfs"), True, None, NOT_MOUNTED)
    assert errors == ["unsupported filesystem: one-disk mode keeps mail on ext4 or xfs, and / is btrfs"]
    _, errors = single_disk(root("xfs", None), True, None, NOT_MOUNTED)
    assert errors == ["unreadable filesystem: / is xfs, and xfs_info could not say whether reflink is on"]


def test_a_machine_with_separate_disks_is_not_turned_into_one_disk():
    _, errors = single_disk(root(), False, RECORD, NOT_MOUNTED)
    assert errors == ["wrong disk_mode: this machine was installed in separate mode "
                      "(/etc/maildivvy/disks.json), and a re-run never changes it"]
    # a first-version machine: no record, the store mounted on a disk of its own
    _, errors = single_disk(root(), False, None, FIRST_MOUNTS)
    assert errors == ["wrong disk_mode: /srv/maildivvy/store is a filesystem of its own, so this machine "
                      "has separate disks; set disk_mode separate"]


# --- health ------------------------------------------------------------------------


def test_in_one_disk_mode_a_data_directory_on_the_root_filesystem_passes():
    holding = {"target": "/", "source": "/dev/mapper/vg-root", "fstype": "ext4"}
    check = system.judge_shared("store", "/srv/maildivvy/store", holding)
    assert check.state == PASS and "ext4" in check.reading and "shared" in check.reading
    assert system.judge_shared("store", "/srv/maildivvy/store", {**holding, "fstype": "xfs"}).state == PASS


def test_in_one_disk_mode_a_data_directory_mounted_on_its_own_or_on_another_filesystem_fails():
    own = {"target": "/srv/maildivvy/store", "source": "/dev/xvdc", "fstype": "xfs"}
    assert system.judge_shared("store", "/srv/maildivvy/store", own).state == FAIL
    other = {"target": "/", "source": "/dev/sda1", "fstype": "btrfs"}
    assert system.judge_shared("store", "/srv/maildivvy/store", other).state == FAIL
    with pytest.raises(Unreadable):   # findmnt said nothing, so nothing is known
        system.judge_shared("store", "/srv/maildivvy/store", None)


def statvfs(avail, blocks=100):
    return SimpleNamespace(f_blocks=blocks, f_bavail=avail, f_files=1000, f_favail=900, f_frsize=4096)


@pytest.mark.parametrize("avail, separate, single", [(50, PASS, PASS), (25, PASS, WARN),
                                                     (18, WARN, WARN), (12, WARN, FAIL), (5, FAIL, FAIL)])
def test_one_disk_mode_is_judged_by_stricter_free_space_bounds(avail, separate, single):
    conf = settings.Settings()
    assert system.judge_free("store", "/srv", statvfs(avail), conf).state == separate
    assert system.judge_free("store", "/srv", statvfs(avail), conf, "single").state == single


def test_health_reads_the_mode_from_the_disk_record(tmp_path, monkeypatch):
    record = tmp_path / "disks.json"
    monkeypatch.setattr(system, "DISKS", record)
    with pytest.raises(Unreadable, match="no disk record"):
        system.disk_mode()
    record.write_text('{"mode": "single"}')
    assert system.disk_mode() == "single"
    record.write_text('{"mode": "separate", "uuids": {"store": "u", "index": "v"}}')
    assert system.disk_mode() == "separate"
    record.write_text('{"mode": "raid"}')
    with pytest.raises(Unreadable):
        system.disk_mode()
