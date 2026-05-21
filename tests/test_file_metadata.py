from __future__ import annotations

import csv
import json
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.reports import (
    file_metadata_report,
    file_metadata_deleted_skipped_report,
    file_metadata_folders_report,
    file_metadata_live_orphan_report,
    file_metadata_skipped_report,
    file_metadata_summary_report,
    file_metadata_unresolved_report,
)
from forensic_orchestrator.tools.file_metadata import parse_file_metadata_to_csv
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.registry import ToolRegistry


def test_file_metadata_profiles_are_configured():
    registry = ToolRegistry.from_files([Path("forensic_orchestrator/plugins/eztools.yaml")])

    assert [tool.name for tool in registry.profile_tools("file-metadata-office")] == ["FileMetadataOffice"]
    assert [tool.name for tool in registry.profile_tools("file-metadata-pictures")] == [
        "FileMetadataPicturesUserContent"
    ]
    assert [tool.name for tool in registry.profile_tools("file-metadata-pictures-deep")] == ["FileMetadataPictures"]
    assert [tool.name for tool in registry.profile_tools("file-metadata-pictures-user-content")] == [
        "FileMetadataPicturesUserContent"
    ]
    assert [tool.name for tool in registry.profile_tools("file-metadata-all")] == ["FileMetadataExtractor"]

    office = registry.get_tool("FileMetadataOffice")
    assert office.type == "internal_file_metadata"
    assert office.artifacts[0].recursive is True
    assert "*.docx" in office.artifacts[0].patterns
    assert "*.xlsx" in office.artifacts[0].patterns
    assert "Windows.old/*" in office.artifacts[0].exclude_patterns
    user_pictures = registry.get_tool("FileMetadataPicturesUserContent")
    assert "Users/*/Pictures/*" in user_pictures.artifacts[0].include_path_patterns
    assert "Users/*/Google Drive/*" in user_pictures.artifacts[0].exclude_patterns
    assert "Users/*/AppData/*" in user_pictures.artifacts[0].exclude_patterns


def test_exiftool_json_is_converted_to_internal_metadata_csv(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    document = source / "report.docx"
    document.write_bytes(b"test")
    (source / "_artifact_manifest.csv").write_text(
        "artifact_path,original_path,mft_created,mft_modified\n"
        f"{document},Users/Jean/Documents/report.docx,2026-05-01T00:00:00Z,2026-05-02T00:00:00Z\n"
    )

    def fake_run(command, capture_output, text, check):
        assert command[:5] == ["exiftool", "-j", "-G1", "-a", "-s"]
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(
                    [
                        {
                            "SourceFile": str(document),
                            "File:FileName": "report.docx",
                            "XMP:Creator": "Jean",
                            "DocProps:LastModifiedBy": "Devon",
                        }
                    ]
                ),
                "stderr": "",
            },
        )()

    monkeypatch.setattr("forensic_orchestrator.tools.file_metadata.subprocess.run", fake_run)

    csv_path = parse_file_metadata_to_csv(source, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open()))

    assert {row["property_name"] for row in rows} == {"FileName", "Creator", "LastModifiedBy"}
    creator = next(row for row in rows if row["property_name"] == "Creator")
    assert creator["metadata_group"] == "XMP"
    assert creator["property_value"] == "Jean"
    assert creator["original_path"] == "Users/Jean/Documents/report.docx"
    assert creator["live_orphan"] == ""


def test_file_internal_metadata_is_ingested(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "FileMetadata.csv"
    csv_path.write_text(
        "source_file,original_path,file_name,extension,parser,metadata_group,property_name,"
        "property_value,raw_property_name,file_size,mft_created,mft_modified,mft_accessed,mft_record_modified,"
        "mft_in_use,path_unresolved,deleted_mft_entry,live_orphan,extraction_method\n"
        "/tmp/report.docx,Users/Jean/Documents/report.docx,report.docx,.docx,exiftool,XMP,"
        "Creator,Jean,XMP:Creator,42,2026-05-01T00:00:00Z,2026-05-02T00:00:00Z,,,"
        "true,false,false,false,mounted_in_place\n"
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-file-metadata",
        tool_name="FileMetadataOffice",
        path=csv_path,
    ) == 1

    row = db.conn.execute(
        "SELECT original_path, property_name, property_value FROM file_internal_metadata"
    ).fetchone()
    assert dict(row) == {
        "original_path": "Users/Jean/Documents/report.docx",
        "property_name": "Creator",
        "property_value": "Jean",
    }
    report = file_metadata_report(
        db,
        case.id,
        extension=".docx",
        property_name="Creator",
        path_contains="Jean/Documents",
    )
    assert report["total_returned"] == 1
    assert report["file_internal_metadata"][0]["property_value"] == "Jean"


def test_file_internal_metadata_ingests_large_metadata_fields(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    large_value = "A" * 150_000
    csv_path = tmp_path / "FileMetadata.csv"
    csv_path.write_text(
        "source_file,original_path,file_name,extension,parser,metadata_group,property_name,"
        "property_value,raw_property_name,file_size,mft_created,mft_modified,mft_accessed,mft_record_modified,"
        "mft_in_use,path_unresolved,deleted_mft_entry,live_orphan,extraction_method\n"
        f"/tmp/file.txt,Users/Jean/Documents/file.txt,file.txt,.txt,exiftool,File,Text,{large_value},"
        "File:Text,,,,,,true,false,false,false,mounted_in_place\n"
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-file-metadata",
        tool_name="FileMetadataDocuments",
        path=csv_path,
    ) == 1

    row = db.conn.execute("SELECT length(property_value) AS value_length FROM file_internal_metadata").fetchone()
    assert row["value_length"] == 150_000


def test_file_metadata_report_filters_user_paths_and_system_noise(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    rows = [
        {
            "id": "meta-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-1",
            "tool_name": "FileMetadataOffice",
            "source_csv": "/tmp/FileMetadata.csv",
            "row_number": 1,
            "source_file": "/mnt/Users/Jean/report.docx",
            "original_path": "Users/Jean/Documents/report.docx",
            "file_name": "report.docx",
            "extension": ".docx",
            "parser": "exiftool",
            "metadata_group": "XMP",
            "property_name": "Creator",
            "property_value": "Jean",
            "raw_property_name": "XMP:Creator",
        },
        {
            "id": "meta-2",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-1",
            "tool_name": "FileMetadataOffice",
            "source_csv": "/tmp/FileMetadata.csv",
            "row_number": 2,
            "source_file": "/mnt/Windows/help.rtf",
            "original_path": "Windows/Help/help.rtf",
            "file_name": "help.rtf",
            "extension": ".rtf",
            "parser": "exiftool",
            "metadata_group": "File",
            "property_name": "FileName",
            "property_value": "help.rtf",
            "raw_property_name": "File:FileName",
        },
    ]
    db.insert_file_internal_metadata(rows)

    user_report = file_metadata_report(db, case.id, user_only=True)
    clean_report = file_metadata_report(db, case.id, exclude_system=True)
    folder_report = file_metadata_report(db, case.id, source_folder="Users/Jean")
    tool_report = file_metadata_report(db, case.id, tool_name="FileMetadataOffice")
    folder_summary = file_metadata_folders_report(db, case.id, depth=2, tool_name="FileMetadataOffice")

    assert [row["original_path"] for row in user_report["file_internal_metadata"]] == [
        "Users/Jean/Documents/report.docx"
    ]
    assert [row["original_path"] for row in clean_report["file_internal_metadata"]] == [
        "Users/Jean/Documents/report.docx"
    ]
    assert [row["original_path"] for row in folder_report["file_internal_metadata"]] == [
        "Users/Jean/Documents/report.docx"
    ]
    assert tool_report["total_returned"] == 2
    assert folder_summary["folders"][0]["folder"] == "Users/Jean"


def test_file_metadata_skipped_and_summary_reports(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.log_activity(
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        event="artifact.skipped_reparse",
        message="Skipped 2 reparse-point candidate files for metadata_files",
        details={"tool_name": "FileMetadataOffice", "count": 2, "sample": ["Users/Jean/OneDrive/a.docx"]},
    )
    db.log_activity(
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        event="artifact.skipped_deleted_mft",
        message="Skipped 4 deleted MFT candidate files for metadata_files",
        details={"tool_name": "FileMetadataOffice", "count": 4, "sample": ["PathUnknown/a.docx"]},
    )
    db.log_activity(
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        event="artifact.skipped_live_orphan",
        message="Skipped 7 allocated MFT records missing from active INDX for metadata_files",
        details={"tool_name": "FileMetadataOffice", "count": 7, "sample": ["Users/Jean/Pictures/orphan.jpg"]},
    )
    db.log_activity(
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        event="artifact.path_unresolved",
        message="Found 3 MFT-selected files with unresolved paths for metadata_files",
        details={
            "tool_name": "FileMetadataOffice",
            "count": 3,
            "deleted_count": 3,
            "sample": [{"path": "PathUnknown/Directory with ID 1/a.docx", "in_use": "False"}],
        },
    )
    db.insert_file_metadata_extraction_summary(
        {
            "id": "summary-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_name": "FileMetadataOffice",
            "artifact_name": "metadata_files",
            "artifact_path": "/tmp/FileMetadata/Office",
            "selected_count": 10,
            "extracted_count": 8,
                "failed_count": 1,
                "skipped_reparse_count": 2,
                "skipped_deleted_count": 4,
                "skipped_live_orphan_count": 7,
                "live_orphan_count": 0,
                "mounted_in_place_count": 5,
            "mft_icat_count": 3,
            "source": "mft_entries",
        }
    )

    skipped = file_metadata_skipped_report(db, case.id)
    skipped_deleted = file_metadata_deleted_skipped_report(db, case.id, tool_name="FileMetadataOffice")
    skipped_live_orphans = file_metadata_live_orphan_report(db, case.id, tool_name="FileMetadataOffice")
    skipped_latest = file_metadata_skipped_report(db, case.id, tool_name="FileMetadataOffice", latest=True)
    unresolved = file_metadata_unresolved_report(db, case.id, tool_name="FileMetadataOffice")
    summary = file_metadata_summary_report(db, case.id)

    assert skipped["skipped_reparse"][0]["count"] == 2
    assert skipped_deleted["skipped_deleted_mft"][0]["count"] == 4
    assert skipped_live_orphans["skipped_live_orphans"][0]["count"] == 7
    assert skipped_latest["skipped_reparse"][0]["tool_name"] == "FileMetadataOffice"
    assert skipped["skipped_reparse"][0]["sample"] == ["Users/Jean/OneDrive/a.docx"]
    assert skipped_live_orphans["skipped_live_orphans"][0]["sample"] == ["Users/Jean/Pictures/orphan.jpg"]
    assert unresolved["path_unresolved"][0]["deleted_count"] == 3
    assert unresolved["path_unresolved"][0]["sample"][0]["in_use"] == "False"
    assert summary["file_metadata_extraction_summaries"][0]["selected_count"] == 10
    assert summary["file_metadata_extraction_summaries"][0]["mounted_in_place_count"] == 5
    assert summary["file_metadata_extraction_summaries"][0]["skipped_deleted_count"] == 4
    assert summary["file_metadata_extraction_summaries"][0]["skipped_live_orphan_count"] == 7
    assert summary["file_metadata_extraction_summaries"][0]["tool_name"] == "FileMetadataOffice"
