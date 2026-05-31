from pathlib import Path
import subprocess

from forensic_orchestrator.db import Database
from forensic_orchestrator.deleted_file_recovery import recover_deleted_files


def _setup_case(tmp_path: Path) -> tuple[Database, str]:
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="HOST01")
    return db, case.id


def test_recover_deleted_fat_entry_resolves_inode_with_fls_and_icat(monkeypatch, tmp_path):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")
    db, case_id = _setup_case(tmp_path)
    image_path = tmp_path / "usb.E01"
    image_path.write_bytes(b"image")
    db.add_image("image-1", case_id, image_path, computer_id="computer-1")
    db.insert_filesystem_entries(
        [
            {
                "id": "fs-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "tool-1",
                "tool_name": "MountedFilesystemInventory",
                "source_csv": "filesystem_entries.csv",
                "row_number": 1,
                "partition_id": "part-1",
                "filesystem_type": "fat32",
                "source_root": f"{image_path}:offset=240",
                "file_path": "timestamps.docx",
                "parent_path": "",
                "file_name": "timestamps.docx",
                "extension": "docx",
                "file_size": "4",
                "is_directory": "false",
                "scan_status": "deleted",
                "created_at": "2026-05-31T00:00:00Z",
            }
        ]
    )

    def fake_run(command, **kwargs):
        if command[0] == "fls":
            return subprocess.CompletedProcess(command, 0, stdout="r/r * 9:\ttimestamps.docx\n", stderr="")
        if command[0] == "icat":
            kwargs["stdout"].write(b"docx")
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        raise AssertionError(command)

    monkeypatch.setattr("forensic_orchestrator.deleted_file_recovery.require_dependency", lambda name: None)
    monkeypatch.setattr("forensic_orchestrator.deleted_file_recovery.subprocess.run", fake_run)

    report = recover_deleted_files(
        db,
        case_id=case_id,
        image_id="image-1",
        name="timestamps.docx",
        output_dir=tmp_path / "recovered",
    )

    row = report["files"][0]
    assert row["status"] == "recovered"
    assert row["inode"] == "9"
    assert row["filesystem_type"] == "fat"
    assert row["offset_sectors"] == 240
    assert Path(row["output_path"]).read_bytes() == b"docx"
    assert Path(report["manifest_csv"]).exists()
    assert Path(report["manifest_json"]).exists()


def test_recover_deleted_ntfs_entry_uses_mft_entry_number(monkeypatch, tmp_path):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")
    db, case_id = _setup_case(tmp_path)
    image_path = tmp_path / "disk.E01"
    image_path.write_bytes(b"image")
    db.add_image("image-1", case_id, image_path, computer_id="computer-1")
    db.insert_mft_entries(
        [
            {
                "id": "mft-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "tool-1",
                "tool_name": "MFTECmd",
                "source_csv": "mft.csv",
                "row_number": 1,
                "entry_number": "42",
                "in_use": "False",
                "parent_path": "Users/Maya/Documents",
                "file_name": "report.docx",
                "file_size": "6",
                "is_directory": "False",
                "created_at": "2026-05-31T00:00:00Z",
            }
        ]
    )

    seen_commands = []

    def fake_run(command, **kwargs):
        seen_commands.append(command)
        kwargs["stdout"].write(b"report")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr("forensic_orchestrator.deleted_file_recovery.require_dependency", lambda name: None)
    monkeypatch.setattr("forensic_orchestrator.deleted_file_recovery.subprocess.run", fake_run)

    report = recover_deleted_files(
        db,
        case_id=case_id,
        image_id="image-1",
        name="report.docx",
        source="mft_entries",
        output_dir=tmp_path / "recovered",
    )

    row = report["files"][0]
    assert row["status"] == "recovered"
    assert row["inode"] == "42"
    assert row["filesystem_type"] == "ntfs"
    assert seen_commands == [["icat", "-f", "ntfs", "-o", "0", str(image_path), "42"]]
    assert Path(row["output_path"]).read_bytes() == b"report"


def test_recover_deleted_files_dry_run_does_not_call_icat(monkeypatch, tmp_path):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")
    db, case_id = _setup_case(tmp_path)
    image_path = tmp_path / "disk.E01"
    image_path.write_bytes(b"image")
    db.add_image("image-1", case_id, image_path, computer_id="computer-1")
    db.insert_mft_entries(
        [
            {
                "id": "mft-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "tool-1",
                "tool_name": "MFTECmd",
                "source_csv": "mft.csv",
                "row_number": 1,
                "entry_number": "42",
                "in_use": "False",
                "parent_path": "Users/Maya/Documents",
                "file_name": "report.docx",
                "is_directory": "False",
                "created_at": "2026-05-31T00:00:00Z",
            }
        ]
    )

    def fail_run(command, **kwargs):
        raise AssertionError(command)

    monkeypatch.setattr("forensic_orchestrator.deleted_file_recovery.subprocess.run", fail_run)

    report = recover_deleted_files(
        db,
        case_id=case_id,
        source="mft_entries",
        output_dir=tmp_path / "recovered",
        dry_run=True,
    )

    assert report["files"][0]["status"] == "would_recover"
