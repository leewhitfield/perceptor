from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from forensic_orchestrator.db import Database
from forensic_orchestrator.mounting.workflow import mount_image, unmount_image
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import EncryptedImageError


def test_dry_run_mount_records_jobs_without_dependencies(tmp_path):
    paths = WorkspacePaths(tmp_path)
    db = Database(paths.db_path())
    case_id = "case-1"
    image_id = "image-1"
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"not a real e01")

    paths.ensure_case_tree(case_id)
    db.create_case(case_id, paths.case_dir(case_id))
    image = db.add_image(image_id, case_id, e01)

    volume = mount_image(db=db, paths=paths, case_id=case_id, image=image, dry_run=True)

    assert volume is None
    rows = db.conn.execute("SELECT tool_name, command_json, dry_run FROM jobs ORDER BY start_time").fetchall()
    assert [row["tool_name"] for row in rows] == ["fsstat", "mmls"]
    assert all(row["dry_run"] == 1 for row in rows)
    mount_row = db.latest_mount(case_id, image_id)
    assert mount_row is not None
    assert mount_row["raw_path"] == str(e01)
    assert mount_row["source_type"] == "direct-e01"
    assert mount_row["volume_mount_path"] is None


def test_mount_falls_back_to_ewfmount_when_direct_mmls_fails(tmp_path):
    paths = WorkspacePaths(tmp_path)
    db = Database(paths.db_path())
    case_id = "case-1"
    image_id = "image-1"
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"not a real e01")
    paths.ensure_case_tree(case_id)
    raw = paths.ewf_raw_path(case_id)
    raw.write_bytes(b"raw")
    db.create_case(case_id, paths.case_dir(case_id))
    image = db.add_image(image_id, case_id, e01)
    mmls_stdout = """
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
002:  000:000   0000000063   0020948759   0020948697   NTFS / exFAT (0x07)
"""

    fsstat_fail = subprocess.CompletedProcess(["fsstat", str(e01)], 1, "", "unsupported")
    direct_fail = subprocess.CompletedProcess(["mmls", str(e01)], 1, "", "unsupported")
    fallback_ok = subprocess.CompletedProcess(["mmls", str(raw)], 0, mmls_stdout, "")
    partition_fsstat_ok = subprocess.CompletedProcess(
        ["fsstat", "-o", "63", str(raw)], 0, "FILE SYSTEM INFORMATION\nFile System Type: NTFS\n", ""
    )

    with patch("forensic_orchestrator.mounting.workflow.validate_mmls_available"), patch(
        "forensic_orchestrator.mounting.workflow.validate_ewfmount_available"
    ), patch("forensic_orchestrator.mounting.workflow.JobRunner.run") as job_run, patch(
        "forensic_orchestrator.mounting.workflow.subprocess.run",
        side_effect=[fsstat_fail, direct_fail, fallback_ok, partition_fsstat_ok],
    ):
        job_run.return_value.exit_code = 0

        mount_image(db=db, paths=paths, case_id=case_id, image=image, dry_run=False)

    mount_row = db.latest_mount(case_id, image_id)
    assert mount_row["raw_path"] == str(raw)
    assert mount_row["source_type"] == "ewfmount"
    assert job_run.call_args.kwargs["tool_name"] == "ewfmount"
    rows = db.conn.execute("SELECT tool_name FROM jobs ORDER BY start_time").fetchall()
    assert [row["tool_name"] for row in rows] == ["fsstat", "mmls", "mmls", "fsstat"]
    assert mount_row["volume_mount_path"] is None


def test_direct_mount_records_e01_source_when_mmls_succeeds(tmp_path):
    paths = WorkspacePaths(tmp_path)
    db = Database(paths.db_path())
    case_id = "case-1"
    image_id = "image-1"
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"not a real e01")

    paths.ensure_case_tree(case_id)
    db.create_case(case_id, paths.case_dir(case_id))
    image = db.add_image(image_id, case_id, e01)
    mmls_stdout = """
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
002:  000:000   0000000063   0020948759   0020948697   NTFS / exFAT (0x07)
"""

    fsstat_fail = subprocess.CompletedProcess(["fsstat", str(e01)], 1, "", "unsupported")
    mmls_ok = subprocess.CompletedProcess(["mmls", str(e01)], 0, mmls_stdout, "")
    partition_fsstat_ok = subprocess.CompletedProcess(
        ["fsstat", "-o", "63", str(e01)], 0, "FILE SYSTEM INFORMATION\nFile System Type: NTFS\n", ""
    )

    with patch("forensic_orchestrator.mounting.workflow.validate_mmls_available"), patch(
        "forensic_orchestrator.mounting.workflow.subprocess.run"
    ) as run:
        run.side_effect = [fsstat_fail, mmls_ok, partition_fsstat_ok]

        mount_image(db=db, paths=paths, case_id=case_id, image=image, dry_run=False)

    mount_row = db.latest_mount(case_id, image_id)
    assert mount_row["raw_path"] == str(e01)
    assert mount_row["source_type"] == "direct-e01"
    assert mount_row["offset_bytes"] == 63 * 512
    rows = db.conn.execute("SELECT tool_name FROM jobs ORDER BY start_time").fetchall()
    assert [row["tool_name"] for row in rows] == ["fsstat", "mmls", "fsstat"]


def test_fsstat_ntfs_volume_records_offset_zero(tmp_path):
    paths = WorkspacePaths(tmp_path)
    db = Database(paths.db_path())
    case_id = "case-1"
    image_id = "image-1"
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"not a real e01")

    paths.ensure_case_tree(case_id)
    db.create_case(case_id, paths.case_dir(case_id))
    image = db.add_image(image_id, case_id, e01)
    fsstat_ok = subprocess.CompletedProcess(
        ["fsstat", str(e01)],
        0,
        "FILE SYSTEM INFORMATION\nFile System Type: NTFS\n",
        "",
    )

    with patch("forensic_orchestrator.mounting.workflow.validate_mmls_available"), patch(
        "forensic_orchestrator.mounting.workflow.subprocess.run", return_value=fsstat_ok
    ):
        mount_image(db=db, paths=paths, case_id=case_id, image=image, dry_run=False)

    mount_row = db.latest_mount(case_id, image_id)
    assert mount_row["raw_path"] == str(e01)
    assert mount_row["source_type"] == "direct-e01-volume"
    assert mount_row["partition_id"] == "volume-ntfs"
    assert mount_row["offset_bytes"] == 0
    rows = db.conn.execute("SELECT tool_name FROM jobs ORDER BY start_time").fetchall()
    assert [row["tool_name"] for row in rows] == ["fsstat"]


def test_mount_stops_when_direct_volume_fsstat_detects_encryption(tmp_path):
    paths = WorkspacePaths(tmp_path)
    db = Database(paths.db_path())
    case_id = "case-1"
    image_id = "image-1"
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"not a real e01")

    paths.ensure_case_tree(case_id)
    db.create_case(case_id, paths.case_dir(case_id))
    image = db.add_image(image_id, case_id, e01)
    fsstat_bitlocker = subprocess.CompletedProcess(
        ["fsstat", str(e01)],
        0,
        "FILE SYSTEM INFORMATION\nFile System Type: BitLocker\n",
        "",
    )

    with patch("forensic_orchestrator.mounting.workflow.validate_mmls_available"), patch(
        "forensic_orchestrator.mounting.workflow.subprocess.run", return_value=fsstat_bitlocker
    ):
        with pytest.raises(EncryptedImageError):
            mount_image(db=db, paths=paths, case_id=case_id, image=image, dry_run=False)

    assert db.latest_mount(case_id, image_id) is None
    activity = db.conn.execute(
        "SELECT event, level, message FROM activity_log WHERE case_id = ? AND image_id = ?",
        (case_id, image_id),
    ).fetchall()
    assert any(row["event"] == "image.encryption_detected" and row["level"] == "error" for row in activity)


def test_mount_stops_when_fsstat_detects_sophos_safeguard(tmp_path):
    paths = WorkspacePaths(tmp_path)
    db = Database(paths.db_path())
    case_id = "case-1"
    image_id = "image-1"
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"not a real e01")

    paths.ensure_case_tree(case_id)
    db.create_case(case_id, paths.case_dir(case_id))
    image = db.add_image(image_id, case_id, e01)
    fsstat_sophos = subprocess.CompletedProcess(
        ["fsstat", str(e01)],
        0,
        "FILE SYSTEM INFORMATION\nFile System Type: Sophos SafeGuard encrypted volume\n",
        "",
    )

    with patch("forensic_orchestrator.mounting.workflow.validate_mmls_available"), patch(
        "forensic_orchestrator.mounting.workflow.subprocess.run", return_value=fsstat_sophos
    ):
        with pytest.raises(EncryptedImageError, match="Sophos SafeGuard"):
            mount_image(db=db, paths=paths, case_id=case_id, image=image, dry_run=False)

    activity = db.conn.execute(
        "SELECT details_json FROM activity_log WHERE event = 'image.encryption_detected'"
    ).fetchone()
    assert "Sophos SafeGuard" in activity["details_json"]


def test_mount_stops_when_selected_partition_fsstat_detects_encryption(tmp_path):
    paths = WorkspacePaths(tmp_path)
    db = Database(paths.db_path())
    case_id = "case-1"
    image_id = "image-1"
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"not a real e01")
    paths.ensure_case_tree(case_id)
    db.create_case(case_id, paths.case_dir(case_id))
    image = db.add_image(image_id, case_id, e01)
    mmls_stdout = """
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
002:  000:000   0000000063   0020948759   0020948697   NTFS / exFAT (0x07)
"""

    fsstat_fail = subprocess.CompletedProcess(["fsstat", str(e01)], 1, "", "unsupported")
    mmls_ok = subprocess.CompletedProcess(["mmls", str(e01)], 0, mmls_stdout, "")
    partition_fsstat_bitlocker = subprocess.CompletedProcess(
        ["fsstat", "-o", "63", str(e01)],
        0,
        "FILE SYSTEM INFORMATION\nFile System Type: BitLocker\n",
        "",
    )

    with patch("forensic_orchestrator.mounting.workflow.validate_mmls_available"), patch(
        "forensic_orchestrator.mounting.workflow.subprocess.run",
        side_effect=[fsstat_fail, mmls_ok, partition_fsstat_bitlocker],
    ):
        with pytest.raises(EncryptedImageError):
            mount_image(db=db, paths=paths, case_id=case_id, image=image, dry_run=False)

    assert db.latest_mount(case_id, image_id) is None
    rows = db.conn.execute("SELECT tool_name FROM jobs ORDER BY start_time").fetchall()
    assert [row["tool_name"] for row in rows] == ["fsstat", "mmls", "fsstat"]


def test_unmount_records_sudo_command_in_dry_run(tmp_path):
    paths = WorkspacePaths(tmp_path)
    db = Database(paths.db_path())
    case_id = "case-1"
    image_id = "image-1"
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"not a real e01")
    volume_path = paths.volume_mount_dir(case_id, "volume-ntfs")

    paths.ensure_case_tree(case_id)
    volume_path.mkdir(parents=True)
    db.create_case(case_id, paths.case_dir(case_id))
    image = db.add_image(image_id, case_id, e01)
    db.insert_mount(
        {
            "id": "mount-1",
            "case_id": case_id,
            "image_id": image_id,
            "partition_id": "volume-ntfs",
            "ewf_mount_path": paths.ewf_mount_dir(case_id),
            "raw_path": paths.ewf_raw_path(case_id),
            "source_type": "ewfmount-volume",
            "volume_mount_path": volume_path,
            "offset_bytes": 0,
        }
    )

    returned = unmount_image(
        db=db,
        paths=paths,
        case_id=case_id,
        image=image,
        dry_run=True,
        use_sudo_mount=True,
    )

    assert returned == volume_path
    row = db.conn.execute("SELECT tool_name, command_json, dry_run FROM jobs").fetchone()
    assert row["tool_name"] == "umount"
    assert row["dry_run"] == 1
    assert "sudo" in row["command_json"]
    assert str(volume_path) in row["command_json"]
