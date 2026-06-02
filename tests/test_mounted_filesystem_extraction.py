from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.filesystem_inventory import scan_mounted_filesystem, scan_tsk_filesystem
from forensic_orchestrator.filesystem_review import rebuild_filesystem_review
from forensic_orchestrator.models import ArtifactDefinition
from forensic_orchestrator.mounting.filesystem import extract_artifact_from_mount
from forensic_orchestrator.mounting.tsk import FlsEntry
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.reports import files_report, filesystem_review_report


def _case_db(tmp_path: Path) -> tuple[Database, str]:
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    return db, case.id


def test_mounted_recursive_extraction_preserves_sqlite_sidecars(tmp_path):
    db, case_id = _case_db(tmp_path)
    mount = tmp_path / "mount"
    package = mount / "Users" / "Jane" / "AppData" / "Local" / "Packages" / "AppleInc.iCloud" / "LocalCache"
    package.mkdir(parents=True)
    database = package / "client.db"
    database.write_text("db")
    database.with_name("client.db-wal").write_text("wal")
    database.with_name("client.db-shm").write_text("shm")
    database.with_name("client.db-journal").write_text("journal")

    extract_artifact_from_mount(
        db=db,
        case_id=case_id,
        image_id="image-1",
        computer_id="computer-1",
        mount_path=mount,
        artifact=ArtifactDefinition(
            name="package_databases",
            source="Users",
            destination="packages",
            recursive=True,
            patterns=("*.db",),
            include_path_patterns=("Users/*/AppData/Local/Packages/*",),
        ),
        artifacts_root=tmp_path / "artifacts",
        dry_run=False,
        mounted_files=[database],
    )

    copied = (
        tmp_path
        / "artifacts"
        / "packages"
        / "Jane"
        / "AppData"
        / "Local"
        / "Packages"
        / "AppleInc.iCloud"
        / "LocalCache"
        / "client.db"
    )
    assert copied.read_text() == "db"
    assert copied.with_name("client.db-wal").read_text() == "wal"
    assert copied.with_name("client.db-shm").read_text() == "shm"
    assert copied.with_name("client.db-journal").read_text() == "journal"


def test_mounted_filesystem_inventory_feeds_files_and_review_reports(tmp_path):
    paths = WorkspacePaths(tmp_path / "analysis")
    db = Database(paths.db_path())
    paths.ensure_case_tree("case-1")
    case = db.create_case("case-1", paths.case_dir("case-1"))
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/sample-usb.E01"), computer_id="computer-1")
    mount = tmp_path / "mount"
    folder = mount / "Docs"
    folder.mkdir(parents=True)
    target = folder / "The end.docx"
    target.write_text("bye", encoding="utf-8")

    result = scan_mounted_filesystem(
        db=db,
        paths=paths,
        case_id=case.id,
        image=image,
        mount_path=mount,
        partition_id="part-001",
        filesystem_type="exfat",
    )
    count = rebuild_filesystem_review(db, case_id=case.id, image_id=image.id)
    files = files_report(db, case.id, limit=10)["files"]
    review = filesystem_review_report(db, case.id, contains="The end", source_table="filesystem_entries", limit=10)

    assert result["row_count"] == 2
    assert count == 2
    assert any(row["source_table"] == "filesystem_entries" and row["file_name"] == "The end.docx" for row in files)
    assert review["total_matching_rows"] == 1
    assert review["filesystem_review"][0]["details"]["filesystem_type"] == "exfat"


def test_tsk_filesystem_inventory_purge_replaces_previous_rows(tmp_path):
    paths = WorkspacePaths(tmp_path / "analysis")
    db = Database(paths.db_path())
    paths.ensure_case_tree("case-1")
    case = db.create_case("case-1", paths.case_dir("case-1"))
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/usb.E01"), computer_id=computer.id)
    db.insert_tool_output(
        {
            "id": "tool-1",
            "case_id": case.id,
            "computer_id": computer.id,
            "image_id": image.id,
            "tool_name": "TskFilesystemInventory",
            "output_type": "csv",
            "path": tmp_path / "filesystem_entries.csv",
            "content_sha256": "old",
            "row_count": 1,
        }
    )
    db.insert_filesystem_entries(
        [
            {
                "id": "fs-old",
                "case_id": case.id,
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "tool-1",
                "tool_name": "TskFilesystemInventory",
                "source_csv": "filesystem_entries.csv",
                "row_number": 1,
                "partition_id": "000:000",
                "filesystem_type": "fat32",
                "source_root": "/evidence/usb.E01@240",
                "file_path": "old.docx",
                "parent_path": "",
                "file_name": "old.docx",
                "extension": "docx",
                "file_size": "",
                "is_directory": "false",
                "created_utc": None,
                "modified_utc": None,
                "accessed_utc": None,
                "metadata_changed_utc": None,
                "mode": "",
                "uid": "",
                "gid": "",
                "scan_status": "ok",
                "error": "",
                "created_at": "2026-05-30T00:00:00Z",
            }
        ]
    )

    assert db.purge_tool_data(case_id=case.id, image_id=image.id, tool_names=["TskFilesystemInventory"]) == 1

    remaining = db.conn.execute("SELECT COUNT(*) AS count FROM filesystem_entries").fetchone()["count"]
    assert remaining == 0


def test_tsk_filesystem_inventory_enriches_fat_file_sizes(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")
    paths = WorkspacePaths(tmp_path / "analysis")
    db = Database(paths.db_path())
    paths.ensure_case_tree("case-1")
    case = db.create_case("case-1", paths.case_dir("case-1"))
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/usb.E01"), computer_id=computer.id)

    monkeypatch.setattr(
        "forensic_orchestrator.filesystem_inventory.list_files",
        lambda **_kwargs: [
            FlsEntry(inode="9", path="The end.docx", is_directory=False, deleted=True),
            FlsEntry(inode="484438276", path="$FAT1", is_directory=False, kind="v/v", system=True),
        ],
    )

    def fake_metadata(**kwargs):
        assert kwargs["filesystem_type"] == "fat32"
        assert kwargs["inode"] == "9"
        return {"file_size": "31055"}

    monkeypatch.setattr("forensic_orchestrator.filesystem_inventory.read_file_metadata", fake_metadata)

    scan_tsk_filesystem(
        db=db,
        paths=paths,
        case_id=case.id,
        image=image,
        raw_image=Path("/evidence/usb.E01"),
        offset_sectors=240,
        partition_id="000:000",
        filesystem_type="fat32",
    )

    rows = db.conn.execute(
        "SELECT file_name, file_size, scan_status FROM filesystem_entries ORDER BY row_number"
    ).fetchall()
    assert [dict(row) for row in rows] == [
        {"file_name": "The end.docx", "file_size": "31055", "scan_status": "deleted"},
        {"file_name": "$FAT1", "file_size": "", "scan_status": "system"},
    ]
