import csv
import zipfile
from pathlib import Path

import pytest

from forensic_orchestrator.db import Database
from forensic_orchestrator.nested_evidence import rebuild_nested_evidence_inventory
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.tools.archive_inventory import parse_archive_inventory_to_csv
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.registry import ToolRegistry
from forensic_orchestrator.tools.runner import run_tool


@pytest.fixture(autouse=True)
def sqlite_analytics_mode(monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")


def _base_db(tmp_path: Path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id="computer-1")
    return db, case, image


def test_archive_inventory_lists_zip_members_and_nested_disk_candidates(tmp_path):
    root = tmp_path / "mount"
    archive = root / "Users" / "lee" / "Desktop" / "case.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("docs/readme.txt", "hello")
        zf.writestr("vm/disk.vhdx", "not a real disk")

    csv_path = parse_archive_inventory_to_csv(root, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open()))

    assert {row["member_path"] for row in rows} == {"docs/readme.txt", "vm/disk.vhdx"}
    disk_row = next(row for row in rows if row["member_path"] == "vm/disk.vhdx")
    assert disk_row["archive_path"] == "/Users/lee/Desktop/case.zip"
    assert disk_row["archive_status"] == "parsed"
    assert disk_row["nested_evidence_format"] == "vhdx"


def test_archive_inventory_gracefully_records_damaged_zip(tmp_path):
    root = tmp_path / "mount"
    archive = root / "Users" / "lee" / "Downloads" / "broken.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"not a valid zip")

    csv_path = parse_archive_inventory_to_csv(root, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open()))

    assert len(rows) == 1
    assert rows[0]["archive_path"] == "/Users/lee/Downloads/broken.zip"
    assert rows[0]["archive_status"] == "damaged"
    assert rows[0]["archive_error"]


def test_archive_inventory_flags_split_zip_without_reading_members(tmp_path):
    root = tmp_path / "mount"
    archive_dir = root / "Users" / "lee" / "Downloads"
    archive_dir.mkdir(parents=True)
    (archive_dir / "evidence.z01").write_bytes(b"part one")
    (archive_dir / "evidence.zip").write_bytes(b"central directory elsewhere")

    csv_path = parse_archive_inventory_to_csv(root, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open()))

    zip_row = next(row for row in rows if row["archive_file_name"] == "evidence.zip")
    assert zip_row["archive_status"] == "multipart_archive"
    assert zip_row["multipart_part_count"] == "2"
    assert zip_row["multipart_is_first_part"] == "true"
    assert zip_row["member_path"] == ""


def test_archive_inventory_flags_split_7z_parts(tmp_path):
    root = tmp_path / "mount"
    archive_dir = root / "Users" / "lee" / "Downloads"
    archive_dir.mkdir(parents=True)
    (archive_dir / "logs.7z.001").write_bytes(b"part one")
    (archive_dir / "logs.7z.002").write_bytes(b"part two")

    csv_path = parse_archive_inventory_to_csv(root, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open()))

    assert {row["archive_status"] for row in rows} == {"unsupported_multipart_archive"}
    assert {row["multipart_part_count"] for row in rows} == {"2"}


def test_archive_inventory_skips_unreadable_mounted_paths(monkeypatch, tmp_path):
    root = tmp_path / "mount"
    archive = root / "Users" / "lee" / "Downloads" / "case.zip"
    bad_link = root / "Documents and Settings"
    archive.parent.mkdir(parents=True)
    bad_link.write_text("mounted compatibility path")
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("report.txt", "hello")

    original_is_file = Path.is_file

    def flaky_is_file(path):
        if path == bad_link:
            raise OSError(5, "Input/output error")
        return original_is_file(path)

    monkeypatch.setattr(Path, "is_file", flaky_is_file)

    csv_path = parse_archive_inventory_to_csv(root, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open()))

    assert len(rows) == 1
    assert rows[0]["archive_path"] == "/Users/lee/Downloads/case.zip"
    assert rows[0]["member_path"] == "report.txt"


def test_archive_inventory_ingests_member_metadata_without_content(tmp_path):
    db, case, image = _base_db(tmp_path)
    csv_path = tmp_path / "ArchiveInventory.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "archive_path",
                "archive_file_name",
                "archive_extension",
                "archive_file_size",
                "archive_modified_time_utc",
                "archive_status",
                "archive_error",
                "member_path",
                "member_file_name",
                "member_extension",
                "member_size",
                "member_compressed_size",
                "member_crc",
                "member_modified_time_utc",
                "member_is_dir",
                "member_is_encrypted",
                "nested_evidence_format",
                "multipart_set_id",
                "multipart_part_number",
                "multipart_part_count",
                "multipart_is_first_part",
                "multipart_related_parts",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "archive_path": "/Users/lee/Desktop/case.zip",
                "archive_file_name": "case.zip",
                "archive_extension": ".zip",
                "archive_file_size": "100",
                "archive_modified_time_utc": "2020-01-01T00:00:00+00:00",
                "archive_status": "parsed",
                "member_path": "vm/disk.vmdk",
                "member_file_name": "disk.vmdk",
                "member_extension": ".vmdk",
                "member_size": "50",
                "member_compressed_size": "40",
                "member_crc": "abcdef01",
                "member_modified_time_utc": "2020-01-01T00:00:00+00:00",
                "member_is_dir": "false",
                "member_is_encrypted": "false",
                "nested_evidence_format": "vmdk",
                "multipart_set_id": "",
                "multipart_part_number": "",
                "multipart_part_count": "",
                "multipart_is_first_part": "",
                "multipart_related_parts": "",
            }
        )

    count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id=image.id,
        tool_output_id="archive-output-1",
        tool_name="ArchiveInventoryParser",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM archive_entries").fetchone()
    assert count == 1
    assert row["member_path"] == "vm/disk.vmdk"
    assert row["nested_evidence_format"] == "vmdk"
    assert "not a real disk" not in dict(row).values()


def test_nested_evidence_inventory_lists_disk_images_from_mft(tmp_path):
    db, case, image = _base_db(tmp_path)
    db.insert_mft_entries(
        [
            {
                "id": "mft-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": image.id,
                "tool_output_id": "mft-output-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 1,
                "entry_number": "42",
                "sequence_number": "1",
                "in_use": "True",
                "parent_path": "Users/lee/VMs",
                "file_name": "lab.vmdk",
                "extension": ".vmdk",
                "file_size": "4096",
                "is_directory": "False",
                "created_si": "2020-01-01T00:00:00Z",
                "modified_si": "2020-01-02T00:00:00Z",
                "accessed_si": "2020-01-03T00:00:00Z",
                "record_changed_si": "2020-01-04T00:00:00Z",
                "source_file": "/$MFT",
            },
            {
                "id": "mft-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": image.id,
                "tool_output_id": "mft-output-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 2,
                "parent_path": "Users/lee/Documents",
                "file_name": "notes.txt",
                "extension": ".txt",
                "is_directory": "False",
            },
        ]
    )

    count = rebuild_nested_evidence_inventory(db, case_id=case.id, image_id=image.id)

    rows = db.conn.execute("SELECT * FROM nested_evidence_items").fetchall()
    assert count == 1
    assert rows[0]["original_path"] == "/Users/lee/VMs/lab.vmdk"
    assert rows[0]["detected_format"] == "vmdk"
    assert rows[0]["parser_status"] == "candidate"


def test_nested_evidence_inventory_groups_multipart_ewf(tmp_path):
    db, case, image = _base_db(tmp_path)
    rows = []
    for idx, name in enumerate(("nested.E01", "nested.E02"), start=1):
        rows.append(
            {
                "id": f"mft-ewf-{idx}",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": image.id,
                "tool_output_id": "mft-output-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": idx,
                "entry_number": str(100 + idx),
                "sequence_number": "1",
                "in_use": "True",
                "parent_path": "Users/lee/Evidence",
                "file_name": name,
                "extension": Path(name).suffix.lower(),
                "file_size": "4096",
                "is_directory": "False",
                "source_file": "/$MFT",
            }
        )
    db.insert_mft_entries(rows)

    count = rebuild_nested_evidence_inventory(db, case_id=case.id, image_id=image.id)

    items = db.conn.execute("SELECT * FROM nested_evidence_items ORDER BY file_name").fetchall()
    assert count == 2
    assert {item["detected_format"] for item in items} == {"ewf"}
    assert {item["multipart_part_count"] for item in items} == {"2"}
    assert items[0]["multipart_is_first_part"] == "true"
    assert "all parts present" in items[0]["recommendation"]


def test_archive_inventory_tool_runs_through_registry_and_ingest(tmp_path):
    db, case, image = _base_db(tmp_path)
    paths = WorkspacePaths(tmp_path / "workspace")
    root = tmp_path / "mount"
    archive = root / "Users" / "lee" / "Desktop" / "case.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("report.csv", "a,b\n1,2\n")
    registry = ToolRegistry.from_files([Path("forensic_orchestrator/plugins/eztools.yaml")])

    run_tool(
        db=db,
        paths=paths,
        case_id=case.id,
        image_id=image.id,
        tool=registry.get_tool("ArchiveInventoryParser"),
        mount=root,
        artifacts={"archive_inventory_root": root},
        computer_id="computer-1",
        dry_run=False,
        rebuild_correlations=False,
    )

    row = db.conn.execute("SELECT archive_path, member_path FROM archive_entries").fetchone()
    assert row["archive_path"] == "/Users/lee/Desktop/case.zip"
    assert row["member_path"] == "report.csv"
