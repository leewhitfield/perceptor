import csv
import json
from pathlib import Path

import pytest

from forensic_orchestrator.db import Database
from forensic_orchestrator.evidence import add_image
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.reports import (
    process_timing_report,
    recovery_coverage_report,
    shortcut_droid_changes_report,
    shortcut_object_tracking_report,
    usb_breakdown_report,
)
import forensic_orchestrator.tools.ingest as ingest_module
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.usb_summary import rebuild_usb_storage_devices


@pytest.fixture(autouse=True)
def sqlite_analytics_mode(monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")


def test_project_computer_image_relationship(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(
        computer_id="computer-1",
        case_id=case.id,
        label="Laptop 1",
        hostname="LAPTOP-1",
    )
    image = db.add_image("image-1", case.id, Path("/evidence/laptop.E01"), computer_id=computer.id)

    assert image.computer_id == "computer-1"
    status = db.case_status(case.id)
    assert status["project"]["id"] == "case-1"
    assert status["computers"][0]["label"] == "Laptop 1"
    assert status["images"][0]["computer_id"] == "computer-1"


def test_add_image_records_sqlite_image_metadata(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    paths = WorkspacePaths(tmp_path / "workspace")
    case = db.create_case("case-1", paths.case_dir("case-1"))
    image_path = tmp_path / "evidence.E01"
    image_path.write_bytes(b"not a real ewf")

    image = add_image(db, paths, case.id, image_path)

    metadata = db.image_metadata(case_id=case.id, image_id=image.id)
    values = {(row["source"], row["key"]): row["value"] for row in metadata}
    assert values[("filesystem", "file_name")] == "evidence.E01"
    assert values[("filesystem", "size_bytes")] == str(len(b"not a real ewf"))
    assert db.conn.execute("SELECT COUNT(*) AS count FROM image_metadata").fetchone()["count"] >= 2
    assert db.case_status(case.id)["image_metadata"]


def test_process_timings_record_start_end_and_report(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    profile_timing = db.start_process_timing(
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        scope="profile",
        phase="profile",
        name="windows-full",
        details={"profile": "windows-full"},
    )
    artifact_timing = db.start_process_timing(
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        parent_id=profile_timing,
        scope="artifact",
        phase="extract",
        name="lnk_files",
        artifact_name="lnk_files",
    )
    db.finish_process_timing(artifact_timing, details={"file_count": 2})
    db.finish_process_timing(profile_timing)

    rows = db.conn.execute("SELECT * FROM process_timings ORDER BY start_time").fetchall()
    assert len(rows) == 2
    assert rows[0]["status"] == "completed"
    assert rows[1]["parent_id"] == profile_timing
    assert rows[1]["duration_ms"] >= 0

    report = process_timing_report(db, case.id)
    assert report["total_returned"] == 2
    assert report["timings"][0]["details"]["file_count"] == 2
    assert {row["scope"] for row in report["summary"]} == {"artifact", "profile"}


def test_recovery_coverage_report_summarizes_tsk_recovery_artifacts(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    timing_id = db.start_process_timing(
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        scope="artifact",
        phase="extract",
        name="lnk_files",
        tool_name="LECmd",
        artifact_name="lnk_files",
        details={
            "profile": "windows-basic-evtx-balanced-recovery",
            "method": "tsk",
            "source": "Users",
            "destination": "lnk_files",
            "recovery": {"deleted_files": True, "orphaned_files": True, "cost": "medium", "noise": "low"},
        },
    )
    db.finish_process_timing(timing_id, details={"count": 3, "extracted_count": 2, "failed_count": 1})

    report = recovery_coverage_report(db, case.id)

    assert report["summary"]["tsk_recovery_artifacts"] == 1
    assert report["summary"]["matched_count"] == 3
    assert report["summary"]["extracted_count"] == 2
    assert report["summary"]["failed_count"] == 1
    assert report["summary"]["limited_count"] == 0
    assert report["by_artifact"][0]["artifact_name"] == "lnk_files"


def test_recovery_coverage_report_surfaces_limited_recovery(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    timing_id = db.start_process_timing(
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        scope="artifact",
        phase="extract",
        name="office_backstage",
        tool_name="OfficeBackstageParser",
        artifact_name="office_backstage",
        details={
            "profile": "windows-basic-evtx-deep-recovery",
            "method": "tsk",
            "source": "Users",
            "destination": "office",
            "recovery": {
                "deleted_files": True,
                "orphaned_files": True,
                "cost": "medium",
                "noise": "medium",
                "max_files": 5000,
            },
        },
    )
    db.finish_process_timing(
        timing_id,
        status="partial_limited",
        details={
            "count": 6000,
            "extracted_count": 5000,
            "failed_count": 0,
            "recovery_limited": True,
            "limit_reason": "max_files",
            "limit_max_files": 5000,
        },
    )

    report = recovery_coverage_report(db, case.id)

    assert report["summary"]["limited_count"] == 1
    status_counts = {row["value"]: row["count"] for row in report["summary"]["status_counts"]}
    limit_reason_counts = {row["value"]: row["count"] for row in report["summary"]["limit_reason_counts"]}
    assert status_counts["partial_limited"] == 1
    assert limit_reason_counts["max_files"] == 1
    assert report["by_artifact"][0]["limited_count"] == 1
    assert report["by_artifact"][0]["limit_reasons"]["max_files"] == 1


def test_tool_outputs_are_recorded_per_computer(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "MFTECmd",
            "output_type": "csv",
            "path": tmp_path / "out.csv",
            "row_count": 10,
        }
    )

    outputs = db.case_status(case.id)["outputs"]
    assert outputs == [
        {
            "id": "output-1",
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "MFTECmd",
            "output_type": "csv",
            "path": str(tmp_path / "out.csv"),
            "content_sha256": None,
            "row_count": 10,
            "created_at": outputs[0]["created_at"],
        }
    ]


def test_csv_output_rows_are_ingested(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "EntryNumber,FileName,ParentPath,Created0x10,LastModified0x10\n"
        "0,$MFT,.,2026-05-12 13:14:15,2026-05-12 13:14:16\n"
        "1,$MFTMirr,.,2026-05-12 13:14:17,2026-05-12 13:14:18\n"
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="MFTECmd",
        path=csv_path,
    )
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "MFTECmd",
            "output_type": "csv",
            "path": csv_path,
            "row_count": row_count,
        }
    )

    assert row_count == 2
    rows = db.conn.execute("SELECT row_number, file_name FROM mft_entries ORDER BY row_number").fetchall()
    assert rows[0]["row_number"] == 1
    assert rows[0]["file_name"] == "$MFT"
    assert db.conn.execute("SELECT COUNT(*) AS count FROM parsed_rows").fetchone()["count"] == 0
    counts = db.case_status(case.id)["parsed_row_counts"]
    assert counts[0]["tool_name"] == "MFTECmd"
    assert counts[0]["row_count"] == 2


def test_usn_journal_rows_are_ingested(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "USNJrnl.csv"
    csv_path.write_text(
        "SourceFile,UpdateSequenceNumber,UpdateTimestamp,FileName,Extension,"
        "FileReferenceNumber,FileReferenceSequenceNumber,ParentFileReferenceNumber,"
        "ParentFileReferenceSequenceNumber,Reason,FileAttributes,Offset\n"
        "/artifacts/$Extend/$J,12345,2026-05-12 13:14:15,file.txt,txt,"
        "900,3,100,2,FILE_CREATE;CLOSE,Archive,4096\n"
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-usn",
        tool_name="MFTECmdUSN",
        path=csv_path,
    )

    assert row_count == 1
    row = db.conn.execute("SELECT * FROM usn_journal_entries").fetchone()
    assert row["file_name"] == "file.txt"
    assert row["update_sequence_number"] == "12345"
    assert row["reason"] == "FILE_CREATE;CLOSE"
    counts = db.case_status(case.id)["parsed_row_counts"]
    assert counts[0]["tool_name"] == "MFTECmdUSN"
    assert counts[0]["row_count"] == 1


def test_usn_paths_are_enriched_from_mft_parent_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    mft_csv = tmp_path / "mft.csv"
    mft_csv.write_text(
        "EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,IsDirectory\n"
        "100,2,50,1,.\\\\Users\\\\Maya,Desktop,True\n",
        encoding="utf-8",
    )
    usn_csv = tmp_path / "USNJrnl.csv"
    usn_csv.write_text(
        "SourceFile,UpdateSequenceNumber,UpdateTimestamp,FileName,Extension,"
        "FileReferenceNumber,FileReferenceSequenceNumber,ParentFileReferenceNumber,"
        "ParentFileReferenceSequenceNumber,ParentPath,Reason,FileAttributes,Offset\n"
        "/artifacts/$Extend/$J,12345,2026-05-12 13:14:15,note.txt,txt,"
        "900,3,100,2,.\\\\PathUnknown\\\\Directory with ID 0x00000064-00000002,FILE_CREATE,Archive,4096\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-mft",
        tool_name="MFTECmd",
        path=mft_csv,
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-usn",
        tool_name="MFTECmdUSN",
        path=usn_csv,
    )
    updated = db.enrich_usn_paths_from_mft(case_id=case.id, image_id="image-1")

    row = db.conn.execute("SELECT full_path FROM usn_journal_entries").fetchone()
    assert updated == 1
    assert row["full_path"] == ".\\Users\\Maya\\Desktop\\note.txt"


def test_ntfs_logfile_rows_are_ingested(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "LogFile.csv"
    csv_path.write_text(
        "SourceFile,Timestamp,FileName,FullPath,RedoOperation,UndoOperation,"
        "FileReferenceNumber,FileReferenceSequenceNumber,LogSequenceNumber,TransactionId\n"
        "/artifacts/$LogFile,2026-05-12 13:14:15,file.txt,.\\\\Users\\\\Jean\\\\Desktop\\\\file.txt,"
        "DeleteFile,CreateFile,900,3,12345,tx-1\n"
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-logfile",
        tool_name="MFTECmdLogFile",
        path=csv_path,
    )

    assert row_count == 1
    row = db.conn.execute("SELECT * FROM ntfs_logfile_entries").fetchone()
    assert row["file_name"] == "file.txt"
    assert row["redo_operation"] == "DeleteFile"
    assert row["log_sequence_number"] == "12345"
    counts = db.case_status(case.id)["parsed_row_counts"]
    assert counts[0]["tool_name"] == "MFTECmdLogFile"
    assert counts[0]["row_count"] == 1


def test_ntfsparse_logfile_rows_are_ingested(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "LogFile.csv"
    csv_path.write_text(
        "this LSN,previous LSN,transaction id,derived record type,deriv redo,deriv undo,"
        "target attribute,deriv inum,em_MFT seq value,em_ATTR filename,record offset\n"
        "134,120,24,transaction,Delete Index Entry Allocation,Add Index Entry Allocation,"
        "48,900,3,report.docx,4096\n"
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-ntfsparse-logfile",
        tool_name="NTFSParseLogFile",
        path=csv_path,
    )

    assert row_count == 1
    row = db.conn.execute("SELECT * FROM ntfs_logfile_entries").fetchone()
    assert row["file_name"] == "report.docx"
    assert row["redo_operation"] == "Delete Index Entry Allocation"
    assert row["log_sequence_number"] == "134"
    assert row["file_reference_number"] == "900"


def test_srum_rows_are_ingested(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "20260515130000_SrumECmd_NetworkUsages_Output.csv"
    csv_path.write_text(
        "Id,Timestamp,AppId,UserId,BytesReceived,BytesSent,InterfaceLuid,L2ProfileId,L2ProfileName\n"
        "1,2026-05-12 13:14:15,9,3,1024,2048,123,456,CorpWifi\n"
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-srum",
        tool_name="SrumECmd",
        path=csv_path,
    )

    assert row_count == 1
    row = db.conn.execute("SELECT * FROM srum_records").fetchone()
    assert row["record_type"] == "network_usage"
    assert row["provider_guid"] == "973f5d5c-1d90-4944-be8e-24b94231a174"
    assert row["provider_name"] == "Windows Network Data Usage Monitor"
    assert row["bytes_sent"] == "2048"
    assert row["l2_profile_name"] == "CorpWifi"


def test_internal_srum_parser_rows_are_ingested_with_deep_fields(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "SrumRecords.csv"
    csv_path.write_text(
        "provider_guid,provider_name,record_type,source_table,srum_id,timestamp,app_id,app_name,"
        "app_path,app_description,exe_timestamp,user_id,user_sid,user_name,notification_type,"
        "payload_size,network_type,foreground_context_switches,background_context_switches,"
        "event_timestamp,charge_level,metadata,binary_data,row_json\n"
        "d10ca2fe-6fcf-4f6d-848e-b2e99266fa86,Windows Push Notifications Provider,"
        "push_notifications,{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}.15,1,"
        "2020-10-20T17:06:59Z,718,Teams,Teams.exe,,2020-10-20T16:00:00Z,576,"
        "S-1-5-21-1,Jean,1,1116,0,7,2,2020-10-20T17:00:00Z,95,,,{\"\"PayloadSize\"\":\"\"1116\"\"}\n"
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-srum",
        tool_name="SrumParser",
        path=csv_path,
    )

    assert row_count == 1
    row = db.conn.execute("SELECT * FROM srum_records").fetchone()
    assert row["record_type"] == "push_notifications"
    assert row["notification_type"] == "1"
    assert row["payload_size"] == "1116"
    assert row["foreground_context_switches"] == "7"


class _FakeContentIndexer:
    documents: list[dict[str, object]] = []

    def __init__(self, config, *, batch_size=500):
        self.config = config

    def add(self, document):
        if document:
            self.documents.append(document)

    def close(self, db, *, case_id):
        return None


def test_sidr_reports_are_ingested_into_search_tables(tmp_path, monkeypatch):
    _FakeContentIndexer.documents = []
    monkeypatch.setattr(ingest_module, "IngestContentIndexer", _FakeContentIndexer)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    file_csv = tmp_path / "HOST_File_Report_20260515.csv"
    file_csv.write_text(
        "WorkId,System_Search_GatherTime,System_ItemPathDisplay,System_FileName,System_DateModified\n"
        "1,2026-05-12T13:14:15Z,C:\\Users\\Jean\\Desktop\\jean@example.com\\note.txt,note.txt,"
        "2026-05-12T13:00:00Z,42,DESKTOP,Jean,Indexed document text mentioning project@example.com\n"
    )
    internet_csv = tmp_path / "HOST_Internet_History_Report_20260515.csv"
    internet_csv.write_text(
        "WorkId,System_Search_GatherTime,System_Link_TargetUrl,System_Link_TargetUrlHostName,System_Title\n"
        "2,2026-05-12T13:15:15Z,https://example.com/,example.com,Example\n"
    )
    activity_csv = tmp_path / "HOST_Activity_History_Report_20260515.csv"
    activity_csv.write_text(
        "WorkId,System_Activity_AppDisplayName,System_Activity_DisplayText,System_ActivityHistory_StartTime\n"
        "3,Notepad,Email jean@example.com,2026-05-12T13:16:15Z\n"
    )

    for idx, path in enumerate([file_csv, internet_csv, activity_csv], start=1):
        assert ingest_csv_output(
            db=db,
            case_id=case.id,
            computer_id="computer-1",
            image_id="image-1",
            tool_output_id=f"output-sidr-{idx}",
            tool_name="SIDR",
            path=path,
        ) == 1

    assert db.conn.execute("SELECT file_name FROM windows_search_files").fetchone()["file_name"] == "note.txt"
    file_row = db.conn.execute(
        "SELECT size, computer_name, owner FROM windows_search_files"
    ).fetchone()
    assert dict(file_row) == {"size": "42", "computer_name": "DESKTOP", "owner": "Jean"}
    content_row = db.conn.execute(
        "SELECT item_path, content_field, content_text, content_sha256, content_length FROM windows_search_indexed_content"
    ).fetchone()
    assert content_row["content_field"] == "_extra[3]"
    assert content_row["content_text"] == ""
    assert content_row["content_sha256"]
    assert content_row["content_length"] == len("Indexed document text mentioning project@example.com")
    assert any("Indexed document text mentioning project@example.com" in str(document["content"]) for document in _FakeContentIndexer.documents)
    content_ref = db.conn.execute(
        """
        SELECT source_table, content_role, opensearch_document_id, content_sha256, content_length
        FROM content_references
        WHERE source_table = 'windows_search_indexed_content'
        """
    ).fetchone()
    assert content_ref["content_role"] == "indexed_content"
    assert content_ref["opensearch_document_id"] == _FakeContentIndexer.documents[0]["id"]
    assert content_ref["content_sha256"] == content_row["content_sha256"]
    assert content_ref["content_length"] == content_row["content_length"]
    property_rows = db.conn.execute(
        """
        SELECT property_name, property_value, normalized_name
        FROM windows_search_properties
        WHERE source_table = 'windows_search_files'
        ORDER BY property_name
        """
    ).fetchall()
    assert ("_extra[3]", "Indexed document text mentioning project@example.com", "IndexedContent") not in [
        tuple(row) for row in property_rows
    ]
    assert (
        db.conn.execute("SELECT target_host FROM windows_search_internet_history").fetchone()["target_host"]
        == "example.com"
    )
    assert (
        db.conn.execute("SELECT app_display_name FROM windows_search_activity_history").fetchone()["app_display_name"]
        == "Notepad"
    )
    email_rows = db.conn.execute(
        "SELECT email, domain, source_table, context_path FROM windows_search_email_indicators ORDER BY email"
    ).fetchall()
    assert [row["email"] for row in email_rows] == [
        "jean@example.com",
        "jean@example.com",
    ]
    assert {row["source_table"] for row in email_rows} == {
        "windows_search_files",
        "windows_search_activity_history",
    }
    assert email_rows[0]["domain"] == "example.com"


def test_sam_and_evtx_outputs_are_normalized(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    sam_csv = tmp_path / "SAMParser.csv"
    sam_csv.write_text(
        "source_path,username,rid,rid_hex,account_category,last_login_utc,logon_count,"
        "bad_password_count,account_flags_hex,account_flags,account_flags_unknown_hex,registry_path\n"
        "/artifacts/SAM,Jean,1004,0x000003EC,local,2026-05-12T13:14:15Z,80,0,"
        "0x00000210,normal_account;password_does_not_expire,,SAM/SAM/Domains/Account/Users/Names/Jean\n"
    )
    evtx_csv = tmp_path / "EvtxECmd.csv"
    evtx_csv.write_text(
        "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,Computer,"
        "UserName,MapDescription,PayloadData1,SourceFile\n"
        "1,2,2026-05-12T13:14:15Z,4624,Info,Microsoft-Windows-Security-Auditing,"
        "Security,HOST,Jean,An account was successfully logged on,LogonType 2,/artifacts/Security.evtx\n"
    )

    sam_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-sam",
        tool_name="SAMParser",
        path=sam_csv,
    )
    evtx_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-evtx",
        tool_name="EvtxECmd",
        path=evtx_csv,
    )

    assert sam_count == 1
    assert evtx_count == 1
    assert db.conn.execute("SELECT username FROM sam_accounts").fetchone()["username"] == "Jean"
    assert db.conn.execute("SELECT event_id FROM evtx_events").fetchone()["event_id"] == "4624"
    assert db.conn.execute("SELECT COUNT(*) AS count FROM parsed_rows").fetchone()["count"] == 0


def test_partition_diagnostic_evtx_enriches_usb_volume_fields(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    vbr = bytearray(512)
    vbr[3:11] = b"MSDOS5.0"
    vbr[0x43:0x47] = bytes.fromhex("FD610CB8")
    vbr[0x47:0x52] = b"CASEUSB    "
    vbr[0x52:0x5A] = b"FAT32   "
    partition_table = bytes.fromhex("010000000200000033221100554477668899AABBCCDDEEFF")
    payload = {
        "EventData": {
            "Data": [
                {"@Name": "ParentId", "#text": "USB\\VID_13FE&PID_4300\\90008B5EA6FFFF27"},
                {"@Name": "Manufacturer", "#text": "USB"},
                {"@Name": "Model", "#text": "DISK 2.0"},
                {"@Name": "Revision", "#text": "PMAP"},
                {"@Name": "SerialNumber", "#text": "9F0F020780B0"},
                {"@Name": "DiskNumber", "#text": "1"},
                {"@Name": "BusType", "#text": "7"},
                {"@Name": "UserRemovalPolicy", "#text": "True"},
                {"@Name": "BytesPerSector", "#text": "512"},
                {"@Name": "BytesPerLogicalSector", "#text": "512"},
                {"@Name": "BytesPerPhysicalSector", "#text": "512"},
                {"@Name": "PartitionStyle", "#text": "1"},
                {"@Name": "PartitionCount", "#text": "2"},
                {"@Name": "PartitionTableBytes", "#text": str(len(partition_table))},
                {"@Name": "PartitionTable", "#text": "-".join(f"{byte:02X}" for byte in partition_table)},
                {"@Name": "StorageIdCodeSet", "#text": "2"},
                {"@Name": "StorageIdType", "#text": "1"},
                {"@Name": "StorageIdAssociation", "#text": "0"},
                {"@Name": "StorageIdBytes", "#text": "4"},
                {"@Name": "StorageId", "#text": "41-42-43-44"},
                {"@Name": "RegistryId", "#text": "4dbf10e4-1305-11eb-aa08-985fd34317f9"},
                {"@Name": "AdapterId", "#text": "00000000-0000-0000-0000-000000000001"},
                {"@Name": "PoolId", "#text": "00000000-0000-0000-0000-000000000000"},
                {"@Name": "Location", "#text": "Integrated : Bus 0 : Device 0 : Function 1 : Adapter 0 : Port 0"},
                {"@Name": "Flags", "#text": "8208"},
                {"@Name": "Characteristics", "#text": "262401"},
                {"@Name": "DiskId", "#text": "45af8b97-5331-48aa-9516-288c0e0bca01"},
                {"@Name": "VolumeSerialNumber", "#text": "DEAD-BEEF"},
                {"@Name": "Vbr0Bytes", "#text": "512"},
                {"@Name": "Vbr0", "#text": "-".join(f"{byte:02X}" for byte in vbr)},
            ]
        }
    }
    evtx_csv = tmp_path / "EvtxECmd.csv"
    with evtx_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "RecordNumber",
                "EventRecordId",
                "TimeCreated",
                "EventId",
                "Level",
                "Provider",
                "Channel",
                "MapDescription",
                "Payload",
                "SourceFile",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "RecordNumber": "1",
                "EventRecordId": "100",
                "TimeCreated": "2020-11-10T14:21:38Z",
                "EventId": "1006",
                "Level": "Info",
                "Provider": "Microsoft-Windows-Partition",
                "Channel": "Microsoft-Windows-Partition/Diagnostic",
                "MapDescription": "USB Insertion/Removal",
                "Payload": json.dumps(payload),
                "SourceFile": "/artifacts/Microsoft-Windows-Partition%4Diagnostic.evtx",
            }
        )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-evtx",
        tool_name="EvtxECmd",
        path=evtx_csv,
    ) == 1
    row = db.conn.execute(
        """
        SELECT artifact, device_type, vendor_id, product_id, vendor, product, revision,
               serial, instance_id, volume_guid, volume_serial_number, volume_name,
               capacity_bytes, file_system, key_last_write_utc, vbr_index, vbr_bytes,
               vbr_oem_name, vbr_file_system, vbr_volume_serial_number,
               vbr_volume_serial_number_full, vbr_volume_name, vbr_parse_status,
               vbr_serial_match, partition_disk_number, partition_bus_type,
               partition_bus_type_code, partition_user_removal_policy,
               partition_bytes_per_sector, partition_bytes_per_logical_sector,
               partition_bytes_per_physical_sector, partition_style, partition_style_code,
               partition_count, partition_table_bytes, partition_table_sha256,
               partition_table_summary, partition_table_disk_guid, storage_id_code_set,
               storage_id_type, storage_id_association, storage_id_bytes, storage_id_hex,
               storage_id_ascii, storage_id_sha256, partition_registry_id,
               partition_adapter_id, partition_pool_id, partition_location,
               partition_flags, partition_characteristics
        FROM usb_devices
        """
    ).fetchone()
    assert dict(row) == {
        "artifact": "partition_diagnostic",
        "device_type": "usb_partition_diagnostic",
        "vendor_id": "13FE",
        "product_id": "4300",
        "vendor": "USB",
        "product": "DISK 2.0",
        "revision": "PMAP",
        "serial": "90008B5EA6FFFF27",
        "instance_id": "90008B5EA6FFFF27",
        "volume_guid": "45af8b97-5331-48aa-9516-288c0e0bca01",
        "volume_serial_number": "B80C-61FD",
        "volume_name": "CASEUSB",
        "capacity_bytes": None,
        "file_system": "FAT32",
        "key_last_write_utc": "2020-11-10T14:21:38Z",
        "vbr_index": "0",
        "vbr_bytes": "512",
        "vbr_oem_name": "MSDOS5.0",
        "vbr_file_system": "FAT32",
        "vbr_volume_serial_number": "B80C-61FD",
        "vbr_volume_serial_number_full": "B80C-61FD",
        "vbr_volume_name": "CASEUSB",
        "vbr_parse_status": "parsed",
        "vbr_serial_match": "mismatch",
        "partition_disk_number": "1",
        "partition_bus_type": "USB",
        "partition_bus_type_code": "7",
        "partition_user_removal_policy": "True",
        "partition_bytes_per_sector": "512",
        "partition_bytes_per_logical_sector": "512",
        "partition_bytes_per_physical_sector": "512",
        "partition_style": "GPT",
        "partition_style_code": "1",
        "partition_count": "2",
        "partition_table_bytes": "24",
        "partition_table_sha256": "b20df038abc822cb83daf58520b360ccc684908eeeaf992cde04385b269bfad1",
        "partition_table_summary": "style=GPT count=2 bytes=24 disk_guid=00112233-4455-6677-8899-aabbccddeeff",
        "partition_table_disk_guid": "00112233-4455-6677-8899-aabbccddeeff",
        "storage_id_code_set": "2",
        "storage_id_type": "1",
        "storage_id_association": "0",
        "storage_id_bytes": "4",
        "storage_id_hex": "41-42-43-44",
        "storage_id_ascii": "ABCD",
        "storage_id_sha256": "e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677",
        "partition_registry_id": "4dbf10e4-1305-11eb-aa08-985fd34317f9",
        "partition_adapter_id": "00000000-0000-0000-0000-000000000001",
        "partition_pool_id": "00000000-0000-0000-0000-000000000000",
        "partition_location": "Integrated : Bus 0 : Device 0 : Function 1 : Adapter 0 : Port 0",
        "partition_flags": "8208",
        "partition_characteristics": "262401",
    }


def test_partition_diagnostic_ntfs_uses_four_byte_volume_serial(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    vbr = bytearray(512)
    vbr[3:11] = b"NTFS    "
    vbr[0x48:0x50] = bytes.fromhex("30EAD88E12D98E98")
    payload = {
        "EventData": {
            "Data": [
                {"@Name": "ParentId", "#text": "USB\\VID_058F&PID_6366\\058F63666438"},
                {"@Name": "Manufacturer", "#text": "Multiple"},
                {"@Name": "Model", "#text": "Card Reader"},
                {"@Name": "SerialNumber", "#text": "058F63666438"},
                {"@Name": "Vbr0Bytes", "#text": "512"},
                {"@Name": "Vbr0", "#text": "-".join(f"{byte:02X}" for byte in vbr)},
            ]
        }
    }
    evtx_csv = tmp_path / "EvtxECmd.csv"
    with evtx_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["RecordNumber", "TimeCreated", "EventId", "Provider", "Channel", "Payload"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "RecordNumber": "1",
                "TimeCreated": "2020-11-10T14:21:38Z",
                "EventId": "1006",
                "Provider": "Microsoft-Windows-Partition",
                "Channel": "Microsoft-Windows-Partition/Diagnostic",
                "Payload": json.dumps(payload),
            }
        )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-evtx",
        tool_name="EvtxECmd",
        path=evtx_csv,
    )
    row = db.conn.execute(
        """
        SELECT volume_serial_number, file_system, vbr_volume_serial_number,
               vbr_volume_serial_number_full, vbr_file_system, vbr_parse_status
        FROM usb_devices
        """
    ).fetchone()
    assert dict(row) == {
        "volume_serial_number": "8ED8-EA30",
        "file_system": "NTFS",
        "vbr_volume_serial_number": "8ED8-EA30",
        "vbr_volume_serial_number_full": "988ED912-8ED8EA30",
        "vbr_file_system": "NTFS",
        "vbr_parse_status": "parsed",
    }


def test_partition_diagnostic_uses_mbr_partition_type_when_vbr_is_absent(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    mbr = bytearray(512)
    mbr[0x1BE + 4] = 0x0C
    mbr[0x1BE + 8 : 0x1BE + 12] = (240).to_bytes(4, "little")
    mbr[0x1BE + 12 : 0x1BE + 16] = (30310160).to_bytes(4, "little")
    mbr[510:512] = b"\x55\xaa"
    payload = {
        "EventData": {
            "Data": [
                {"@Name": "ParentId", "#text": "USB\\VID_125F&PID_DC1A\\29B1109550240002"},
                {"@Name": "Manufacturer", "#text": "CB"},
                {"@Name": "Model", "#text": "Cellebrite"},
                {"@Name": "SerialNumber", "#text": "AA00000000000489"},
                {"@Name": "MbrBytes", "#text": "512"},
                {"@Name": "Mbr", "#text": "-".join(f"{byte:02X}" for byte in mbr)},
            ]
        }
    }
    evtx_csv = tmp_path / "EvtxECmd.csv"
    with evtx_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["RecordNumber", "TimeCreated", "EventId", "Provider", "Channel", "Payload"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "RecordNumber": "1",
                "TimeCreated": "2025-11-17T20:52:10Z",
                "EventId": "1006",
                "Provider": "Microsoft-Windows-Partition",
                "Channel": "Microsoft-Windows-Partition/Diagnostic",
                "Payload": json.dumps(payload),
            }
        )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-evtx",
        tool_name="EvtxECmd",
        path=evtx_csv,
    )
    row = db.conn.execute(
        """
        SELECT serial, alternate_scsi_serial, file_system, vbr_parse_status,
               vbr_file_system, mbr_partition_type, partition_start_lba,
               partition_sector_count
        FROM usb_devices
        """
    ).fetchone()
    assert dict(row) == {
        "serial": "29B1109550240002",
        "alternate_scsi_serial": "AA00000000000489",
        "file_system": "FAT32",
        "vbr_parse_status": "mbr_fallback",
        "vbr_file_system": "FAT32",
        "mbr_partition_type": "0x0C",
        "partition_start_lba": "240",
        "partition_sector_count": "30310160",
    }


def test_recmd_detail_outputs_are_normalized_to_artifact_tables(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    recentdocs_csv = tmp_path / "RECmd_WindowsActivity_RecentDocs.csv"
    recentdocs_csv.write_text(
        "Extension,BatchKeyPath,ValueName,BatchValueName,TargetName,LnkName,MruPosition,OpenedOn,ExtensionLastOpened\n"
        "RecentDocs,ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs,83,83,"
        "TEST-SYSTEM,TEST-SYSTEM.lnk,0,2020-11-16 02:32:19.6348205,2020-11-16 02:32:19.6348205\n"
    )
    wordwheel_csv = tmp_path / "RECmd_WindowsActivity_WordWheelQuery.csv"
    wordwheel_csv.write_text(
        "SearchTerm,BatchKeyPath,MruPosition,BatchValueName,KeyName,LastWriteTimestamp\n"
        "backup.pst,ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery,0,9,"
        "WordWheelQuery,2020-11-14 14:04:07.5468437\n"
    )
    runmru_csv = tmp_path / "RECmd_WindowsActivity_RunMRU.csv"
    runmru_csv.write_text(
        "ValueName,BatchKeyPath,MruPosition,BatchValueName,Executable,OpenedOn\n"
        "d,ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU,0,d,"
        "winver,2020-11-01 22:17:08.0822608\n"
    )
    summary_csv = tmp_path / "RECmd_WindowsActivity.csv"
    summary_csv.write_text(
        "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,"
        "LastWriteTimestamp,PluginDetailFile\n"
        f"/cases/registry/users/fredr/NTUSER.DAT,NtUser,RecentDocs,User Activity,"
        f"ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs,83,(plugin),ignored,"
        f"2020-11-16 02:32:19.6348205,{recentdocs_csv}\n"
        f"/cases/registry/users/fredr/NTUSER.DAT,NtUser,WordWheelQuery,User Activity,"
        f"ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery,9,(plugin),ignored,"
        f"2020-11-14 14:04:07.5468437,{wordwheel_csv}\n"
        f"/cases/registry/users/srl-h/NTUSER.DAT,NtUser,RunMRU,User Activity,"
        f"ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU,d,(plugin),ignored,"
        f"2020-11-01 22:17:08.0822608,{runmru_csv}\n"
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-recentdocs",
        tool_name="RECmd",
        path=recentdocs_csv,
    ) == 1
    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-wordwheel",
        tool_name="RECmd",
        path=wordwheel_csv,
    ) == 1
    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-runmru",
        tool_name="RECmd",
        path=runmru_csv,
    ) == 1
    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-summary",
        tool_name="RECmd",
        path=summary_csv,
    ) == 3

    recentdocs = db.conn.execute("SELECT user_profile, hive_type, value_name, target_name, mru_position FROM registry_recentdocs").fetchone()
    wordwheel = db.conn.execute("SELECT search_term, mru_position FROM registry_wordwheel_query").fetchone()
    runmru = db.conn.execute("SELECT user_profile, value_name, executable, mru_position, opened_on FROM registry_runmru").fetchone()
    assert dict(recentdocs) == {
        "user_profile": "fredr",
        "hive_type": "NtUser",
        "value_name": "83",
        "target_name": "TEST-SYSTEM",
        "mru_position": "0",
    }
    assert dict(wordwheel) == {"search_term": "backup.pst", "mru_position": "0"}
    assert dict(runmru) == {
        "user_profile": "srl-h",
        "value_name": "d",
        "executable": "winver",
        "mru_position": "0",
        "opened_on": "2020-11-01 22:17:08.0822608",
    }
    assert db.conn.execute("SELECT COUNT(*) AS count FROM registry_artifacts WHERE tool_name = 'RECmd'").fetchone()["count"] == 0
    assert db.conn.execute("SELECT COUNT(*) AS count FROM parsed_rows WHERE tool_name = 'RECmd'").fetchone()["count"] == 0


def test_common_dialog_guid_executable_resolves_from_jumplist_paths(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    recmd_csv = tmp_path / "RECmd_WindowsActivity_LastVisitedPidlMRU.csv"
    recmd_csv.write_text(
        "ValueName,BatchKeyPath,MruPosition,BatchValueName,Executable,AbsolutePath,OpenedOn,Details\n"
        "0,ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU,0,0,"
        "{11111111-2222-3333-4444-555555555555},This PC\\G:\\Case Work\\Exports,,\n"
    )
    summary_csv = tmp_path / "RECmd_WindowsActivity.csv"
    summary_csv.write_text(
        "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,"
        "LastWriteTimestamp,PluginDetailFile\n"
        f"/cases/registry/users/fredr/NTUSER.DAT,NtUser,LastVisitedPidlMRU,User Activity,"
        f"ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU,"
        f"0,(plugin),ignored,2020-11-14 14:01:34,{recmd_csv}\n"
    )
    jumplist_csv = tmp_path / "JLECmd_AutomaticDestinations.csv"
    jumplist_csv.write_text(
        "SourceFile,AppId,AppIdDescription,Path,Created,Modified,LastModified\n"
        "6d2bac8f1edf6668.automaticDestinations-ms,6d2bac8f1edf6668,Microsoft Outlook 2016 64-bit,"
        "G:\\Case Work\\Exports\\mail.pst,2020-11-14 14:00:54,2020-11-14 13:39:22,2020-11-14 14:01:34\n"
        "5f7b5f1e01b83767.automaticDestinations-ms,5f7b5f1e01b83767,Quick Access,"
        "G:\\Case Work\\Exports\\mail.pst,2020-11-14 14:00:54,2020-11-14 13:39:22,2020-11-14 14:01:35\n"
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-recmd",
        tool_name="RECmd",
        path=recmd_csv,
    )
    row = db.conn.execute(
        "SELECT executable_is_guid, resolved_executable FROM registry_common_dialog_mru"
    ).fetchone()
    assert dict(row) == {"executable_is_guid": "true", "resolved_executable": None}

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-jlecmd",
        tool_name="JLECmd",
        path=jumplist_csv,
    )

    row = db.conn.execute(
        """
        SELECT executable, executable_is_guid, resolved_executable,
               executable_resolution_source, executable_resolution_confidence
        FROM registry_common_dialog_mru
        """
    ).fetchone()
    assert dict(row) == {
        "executable": "{11111111-2222-3333-4444-555555555555}",
        "executable_is_guid": "true",
        "resolved_executable": "Microsoft Outlook 2016 64-bit",
        "executable_resolution_source": "jumplist_path_match",
        "executable_resolution_confidence": "high",
    }


def test_purge_tool_data_removes_normalized_rows_and_outputs(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text("EntryNumber,FileName\n0,$MFT\n")
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="MFTECmd",
        path=csv_path,
    )
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "MFTECmd",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 1,
        }
    )

    purged = db.purge_tool_data(case_id=case.id, image_id="image-1", tool_names=["MFTECmd"])

    assert purged == 1
    assert db.conn.execute("SELECT COUNT(*) AS count FROM mft_entries").fetchone()["count"] == 0
    assert db.conn.execute("SELECT COUNT(*) AS count FROM tool_outputs").fetchone()["count"] == 0


def test_duplicate_tool_output_is_detected_by_content_hash(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "MFTECmd",
            "output_type": "csv",
            "path": tmp_path / "mft.csv",
            "content_sha256": "abc123",
            "row_count": 1,
        }
    )

    duplicate = db.duplicate_tool_output(
        case_id=case.id,
        image_id="image-1",
        tool_name="MFTECmd",
        content_sha256="abc123",
    )

    assert duplicate is not None
    assert duplicate["id"] == "output-1"


def test_lnk_and_prefetch_rows_correlate_to_mft_entries(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    mft_csv = tmp_path / "MFTECmd.csv"
    mft_csv.write_text(
        "EntryNumber,FileName,ParentPath\n"
        "10,cmd.exe,Windows/System32\n"
        "11,notepad.exe,Windows/System32\n"
    )
    lnk_csv = tmp_path / "LECmd.csv"
    lnk_csv.write_text(
        "SourceFile,LocalPath,TargetCreated,TargetModified\n"
        "/artifacts/app.lnk,C:\\Windows\\System32\\cmd.exe,2026-05-12T13:14:15Z,2026-05-12T13:14:15Z\n"
    )
    prefetch_csv = tmp_path / "PrefetchParser.csv"
    prefetch_csv.write_text(
        "source_path,prefetch_name,executable_name,referenced_strings,last_run_times_utc\n"
        '/artifacts/NOTEPAD.EXE-12345678.pf,NOTEPAD.EXE-12345678.pf,NOTEPAD.EXE,'
        '"[""\\\\DEVICE\\\\HARDDISKVOLUME3\\\\WINDOWS\\\\SYSTEM32\\\\notepad.exe""]",'
        '"[""2026-05-12T13:14:15Z""]"\n'
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="mft-output",
        tool_name="MFTECmd",
        path=mft_csv,
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="lnk-output",
        tool_name="LECmd",
        path=lnk_csv,
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="prefetch-output",
        tool_name="PrefetchParser",
        path=prefetch_csv,
    )

    rows = db.conn.execute(
        "SELECT source_tool, match_type, confidence, source_path, mft_path FROM file_correlations ORDER BY source_tool, mft_path"
    ).fetchall()
    assert [row["source_tool"] for row in rows] == ["LECmd", "PrefetchParser"]
    assert rows[0]["match_type"] == "lnk_target_path"
    assert rows[0]["confidence"] == "high"
    assert rows[0]["mft_path"] == "Windows/System32/cmd.exe"
    assert rows[1]["match_type"] == "prefetch_referenced_path"
    assert rows[1]["confidence"] == "high"
    assert rows[1]["mft_path"] == "Windows/System32/notepad.exe"


def test_shortcut_droid_fields_correlate_to_mft_object_ids(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    object_id = "{33333333-3333-3333-3333-333333333333}"
    mft_csv = tmp_path / "MFTECmd.csv"
    mft_csv.write_text(
        "EntryNumber,SequenceNumber,ParentPath,FileName,ObjectId,BirthVolumeId,BirthObjectId,BirthDomainId\n"
        f"42,5,C:\\Docs,report.docx,{object_id},"
        "{22222222-2222-2222-2222-222222222222},"
        "{44444444-4444-4444-4444-444444444444},"
        "{00000000-0000-0000-0000-000000000000}\n"
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="mft-output",
        tool_name="MFTECmd",
        path=mft_csv,
    )
    lnk_csv = tmp_path / "LECmd.csv"
    lnk_csv.write_text(
        "SourceFile,LocalPath,DroidFileId,BirthDroidFileId\n"
        f"/artifacts/recent/report.lnk,C:\\Docs\\report.docx,{object_id},"
        "{44444444-4444-4444-4444-444444444444}\n"
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="lnk-output",
        tool_name="LECmd",
        path=lnk_csv,
    )

    mft = db.conn.execute("SELECT object_id, birth_volume_id, birth_object_id, birth_domain_id FROM mft_entries").fetchone()
    assert dict(mft) == {
        "object_id": object_id,
        "birth_volume_id": "{22222222-2222-2222-2222-222222222222}",
        "birth_object_id": "{44444444-4444-4444-4444-444444444444}",
        "birth_domain_id": "{00000000-0000-0000-0000-000000000000}",
    }
    report = shortcut_object_tracking_report(db, case.id)
    assert report["total_returned"] == 1
    match = report["matches"][0]
    assert match["match_basis"] == "current_droid_file_id_to_mft_object_id"
    assert match["mft_full_path"] == "C:\\Docs\\report.docx"


def test_lecmd_rows_are_normalized_to_shortcut_items(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "LECmd.csv"
    csv_path.write_text(
        "SourceFile,SourceCreated,SourceModified,TargetCreated,TargetModified,TargetAccessed,"
        "DriveType,VolumeSerialNumber,VolumeLabel,LocalPath,CommonPath,TargetPath,RelativePath,"
        "NetworkPath,TargetIDAbsolutePath,TargetMFTEntryNumber,TargetMFTSequenceNumber,"
        "Arguments,WorkingDirectory,IconLocation,HotKey,WindowStyle,HeaderFlags,LinkFlags,"
        "MachineID,MachineMACAddress,TrackerCreatedOn,TrackerID,"
        "DroidVolumeId,DroidFileId,BirthDroidVolumeId,BirthDroidFileId\n"
        "/artifacts/lnk_files/Desktop/app.lnk,2026-05-13 10:00:00,2026-05-13 10:01:00,"
        "2026-05-11 09:00:00,2026-05-11 09:01:00,2026-05-11 09:02:00,"
        "Fixed storage media (Hard drive),744FC21F,OS,C:\\Windows\\System32\\cmd.exe,"
        "C:\\Windows\\System32\\cmd.exe,C:\\Windows\\System32\\cmd.exe,..\\System32\\cmd.exe,"
        "\\\\server\\share\\cmd.exe,C:\\Windows\\System32\\cmd.exe,123,4,"
        "/c whoami,C:\\Windows,C:\\Windows\\System32\\cmd.exe,0,SW_SHOWMINNOACTIVE,"
        "HasLinkInfo|HasArguments,0x000000A5,WORKSTATION01,00-11-22-33-44-55,2026-05-10 08:00:00,"
        "{11111111-1111-1111-1111-111111111111},{22222222-2222-2222-2222-222222222222},"
        "{33333333-3333-3333-3333-333333333333},{22222222-2222-2222-2222-222222222222},"
        "{44444444-4444-4444-4444-444444444444}\n"
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="LECmd",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM shortcut_items").fetchone()
    assert db.conn.execute("SELECT COUNT(*) AS count FROM parsed_rows").fetchone()["count"] == 0
    assert row["artifact_type"] == "lnk"
    assert row["artifact_name"] == "app.lnk"
    assert row["artifact_path"] == "/artifacts/lnk_files/Desktop/app.lnk"
    assert row["file_name"] == "cmd.exe"
    assert row["file_location"] == "C:\\Windows\\System32\\cmd.exe"
    assert row["target_created"] == "2026-05-11 09:00:00"
    assert row["target_modified"] == "2026-05-11 09:01:00"
    assert row["target_accessed"] == "2026-05-11 09:02:00"
    assert row["device_type"] == "Fixed storage media (Hard drive)"
    assert row["volume_serial_number"] == "744FC21F"
    assert row["volume_name"] == "OS"
    assert row["local_path"] == "C:\\Windows\\System32\\cmd.exe"
    assert row["common_path"] == "C:\\Windows\\System32\\cmd.exe"
    assert row["target_path"] == "C:\\Windows\\System32\\cmd.exe"
    assert row["relative_path"] == "..\\System32\\cmd.exe"
    assert row["network_path"] == "\\\\server\\share\\cmd.exe"
    assert row["icon_location"] == "C:\\Windows\\System32\\cmd.exe"
    assert row["hot_key"] == "0"
    assert row["window_style"] == "SW_SHOWMINNOACTIVE"
    assert row["header_flags"] == "HasLinkInfo|HasArguments"
    assert row["link_flags"] == "0x000000A5"
    assert row["target_id_absolute_path"] == "C:\\Windows\\System32\\cmd.exe"
    assert row["target_mft_entry_number"] == "123"
    assert row["target_mft_sequence_number"] == "4"
    assert row["command_line_arguments"] == "/c whoami"
    assert row["working_directory"] == "C:\\Windows"
    assert row["machine_name"] == "WORKSTATION01"
    assert row["machine_mac_address"] == "00-11-22-33-44-55"
    assert row["tracker_created_on"] == "2026-05-10 08:00:00"
    assert row["tracker_id"] == "{11111111-1111-1111-1111-111111111111}"
    assert row["droid_volume_id"] == "{22222222-2222-2222-2222-222222222222}"
    assert row["droid_file_id"] == "{33333333-3333-3333-3333-333333333333}"
    assert row["birth_droid_volume_id"] == "{22222222-2222-2222-2222-222222222222}"
    assert row["birth_droid_file_id"] == "{44444444-4444-4444-4444-444444444444}"
    assert row["lnk_created"] == "2026-05-13 10:00:00"
    assert row["lnk_modified"] == "2026-05-13 10:01:00"
    droid_report = shortcut_droid_changes_report(db, case.id)
    assert droid_report["total_returned"] == 1
    assert droid_report["droid_changes"][0]["droid_change_basis"] == "file_id_changed"
    assert "moved" in droid_report["droid_changes"][0]["interpretation"]


def test_lecmd_rows_use_artifact_manifest_for_lnk_mft_timestamps(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    lnk_dir = tmp_path / "artifacts" / "lnk_files" / "Desktop"
    lnk_dir.mkdir(parents=True)
    lnk_path = lnk_dir / "app.lnk"
    csv_path = tmp_path / "artifacts" / "lnk_files" / "LECmd.csv"
    (tmp_path / "artifacts" / "lnk_files" / "_artifact_manifest.csv").write_text(
        "artifact_path,original_path,inode,mft_created,mft_modified,mft_accessed,mft_record_modified\n"
        f"{lnk_path},Desktop/app.lnk,200,2008-01-01 01:00:00 (UTC),"
        "2008-01-01 02:00:00 (UTC),2008-01-01 03:00:00 (UTC),2008-01-01 04:00:00 (UTC)\n"
    )
    csv_path.write_text(
        "SourceFile,SourceCreated,SourceModified,SourceAccessed,LocalPath\n"
        f"{lnk_path},2026-05-13 10:00:00,2026-05-13 10:01:00,2026-05-13 10:02:00,"
        "C:\\Windows\\System32\\cmd.exe\n"
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="LECmd",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM shortcut_items").fetchone()
    assert row["lnk_created"] == "2008-01-01 01:00:00 (UTC)"
    assert row["lnk_modified"] == "2008-01-01 02:00:00 (UTC)"
    assert row["lnk_accessed"] == "2008-01-01 03:00:00 (UTC)"


def test_jlecmd_rows_are_normalized_to_shortcut_items(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "JLECmd.csv"
    csv_path.write_text(
        "SourceFile,EntryNumber,Target Created,Target Modified,Drive Type,Volume Serial Number,Volume Name,Path,AppId,AppIdDescription,DestListVersion,EntryId\n"
        "/artifacts/jumplists/abc.automaticDestinations-ms,7,2026-05-11 09:00:00,"
        "2026-05-11 09:01:00,Removable storage media,ABCD1234,USB,C:\\Docs\\file.txt,abc123,Explorer,4,entry-7\n"
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="JLECmd",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM shortcut_items").fetchone()
    assert db.conn.execute("SELECT COUNT(*) AS count FROM parsed_rows").fetchone()["count"] == 0
    assert row["artifact_type"] == "jumplist"
    assert row["artifact_name"] == "abc.automaticDestinations-ms"
    assert row["file_name"] == "file.txt"
    assert row["jumplist_item_number"] == "7"
    assert row["app_id"] == "abc123"
    assert row["app_id_description"] == "Explorer"
    assert row["destlist_version"] == "4"
    assert row["entry_id"] == "entry-7"
    assert row["lnk_created"] is None


def test_prefetch_rows_are_normalized_with_artifact_manifest_timestamps(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    prefetch_dir = tmp_path / "artifacts" / "Windows" / "Prefetch"
    prefetch_dir.mkdir(parents=True)
    pf_path = prefetch_dir / "CMD.EXE-12345678.pf"
    csv_path = tmp_path / "outputs" / "PrefetchParser.csv"
    csv_path.parent.mkdir()
    (prefetch_dir / "_artifact_manifest.csv").write_text(
        "artifact_path,original_path,inode,mft_created,mft_modified,mft_accessed,mft_record_modified\n"
        f"{pf_path},Windows/Prefetch/CMD.EXE-12345678.pf,400,"
        "2008-01-01 01:00:00 (UTC),2008-01-01 02:00:00 (UTC),"
        "2008-01-01 03:00:00 (UTC),2008-01-01 04:00:00 (UTC)\n"
    )
    csv_path.write_text(
        "source_path,prefetch_name,executable_name,prefetch_hash,run_count,last_run_times_utc\n"
        f'{pf_path},CMD.EXE-12345678.pf,CMD.EXE,12345678,5,"[""2026-05-12T13:14:15Z""]"\n'
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="PrefetchParser",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM prefetch_items").fetchone()
    assert row_count == 1
    assert db.conn.execute("SELECT COUNT(*) AS count FROM parsed_rows").fetchone()["count"] == 0
    assert row["prefetch_name"] == "CMD.EXE-12345678.pf"
    assert row["artifact_path"] == str(pf_path)
    assert row["original_path"] == "Windows/Prefetch/CMD.EXE-12345678.pf"
    assert row["executable_name"] == "CMD.EXE"
    assert row["pf_created"] == "2008-01-01 01:00:00 (UTC)"
    assert row["pf_modified"] == "2008-01-01 02:00:00 (UTC)"
    assert row["pf_accessed"] == "2008-01-01 03:00:00 (UTC)"


def test_recycle_and_firefox_outputs_are_normalized(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    recycle_csv = tmp_path / "RecycleParser.csv"
    recycle_csv.write_text(
        "record_type,recycle_format,source_path,top_level_name,recycled_path,child_relative_path,"
        "display_name,original_path,deletion_time_utc,file_size,is_directory\n"
        "item,modern,/artifacts/$RABC,$RABC,$RABC,,Folder,C:\\Users\\Jean\\Desktop\\Folder,"
        "2026-05-12T13:14:15Z,0,1\n"
        "child,modern,/artifacts/$RABC/file.txt,$RABC,$RABC/file.txt,file.txt,file.txt,,,"
        "12,0\n"
    )
    history_csv = tmp_path / "FirefoxHistory.csv"
    history_csv.write_text(
        "source_path,profile_path,url,title,visit_time_utc,visit_type,visit_count,typed,hidden,frecency\n"
        "/artifacts/places.sqlite,Jean/profile,https://example.com/,Example,2026-05-12T13:14:15Z,1,3,1,0,100\n"
    )
    cookies_csv = tmp_path / "FirefoxCookies.csv"
    cookies_csv.write_text(
        "source_path,profile_path,host,name,value,path,created_utc,last_accessed_utc,expires_utc,is_secure,is_http_only\n"
        "/artifacts/cookies.sqlite,Jean/profile,.example.com,session,abc,/,2026-05-12T13:14:15Z,"
        "2026-05-12T13:15:15Z,2027-05-12T13:14:15Z,0,1\n"
    )
    downloads_csv = tmp_path / "BrowserDownloads.csv"
    downloads_csv.write_text(
        "browser,source_path,profile_path,target_path,tab_url,site_url,referrer,start_time_utc,end_time_utc,"
        "received_bytes,total_bytes,state,danger_type,interrupt_reason\n"
        "firefox,/artifacts/places.sqlite,Jean/profile,C:\\Users\\Jean\\Downloads\\file.pdf,"
        "https://example.com/file.pdf,https://example.com/,,2026-05-12T13:14:15Z,2026-05-12T13:14:16Z,"
        "123,123,complete,,\n"
    )

    recycle_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="recycle-output",
        tool_name="RecycleParser",
        path=recycle_csv,
    )
    history_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="firefox-history-output",
        tool_name="FirefoxParser",
        path=history_csv,
    )
    cookie_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="firefox-cookie-output",
        tool_name="FirefoxParser",
        path=cookies_csv,
    )
    download_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="firefox-download-output",
        tool_name="FirefoxParser",
        path=downloads_csv,
    )

    assert recycle_count == 2
    assert history_count == 1
    assert cookie_count == 1
    assert download_count == 1
    assert db.conn.execute("SELECT COUNT(*) AS count FROM recycle_items").fetchone()["count"] == 1
    assert db.conn.execute("SELECT COUNT(*) AS count FROM recycle_children").fetchone()["count"] == 1
    assert db.conn.execute("SELECT url FROM firefox_history").fetchone()["url"] == "https://example.com/"
    assert db.conn.execute("SELECT host FROM firefox_cookies").fetchone()["host"] == ".example.com"
    assert db.conn.execute("SELECT target_path FROM browser_downloads").fetchone()["target_path"] == "C:\\Users\\Jean\\Downloads\\file.pdf"
    event_types = [
        row["event_type"]
        for row in db.conn.execute("SELECT event_type FROM timeline_events ORDER BY event_type")
    ]
    assert event_types == ["firefox_visit", "recycle_deleted"]


def test_browser_session_site_settings_and_notifications_are_normalized(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    sessions_csv = tmp_path / "BrowserSessionEntries.csv"
    sessions_csv.write_text(
        "browser,source_path,profile_path,session_type,window_id,tab_id,tab_index,navigation_index,"
        "url,title,referrer_url,timestamp_utc,last_active_time_utc,is_current,is_pinned,parser,details_json\n"
        "chrome,/artifacts/Session_1,Default,session,1,7,0,2,https://session.example,Session,"
        "https://referrer.example,2024-03-09T16:00:00Z,2024-03-09T16:01:00Z,true,false,snss_command,{}\n"
    )
    settings_csv = tmp_path / "BrowserSiteSettings.csv"
    settings_csv.write_text(
        "browser,source_path,profile_path,setting_type,origin,host,setting_name,setting_value,"
        "last_modified_utc,expiration_utc,details_json\n"
        "chrome,/artifacts/Preferences,Default,media_stream_camera,\"https://meet.example,*\",meet.example,"
        "content_setting,1,2024-03-09T16:00:00Z,,{}\n"
    )
    notifications_csv = tmp_path / "BrowserNotifications.csv"
    notifications_csv.write_text(
        "browser,source_path,profile_path,origin,host,notification_id,title,body,tag,icon,badge,"
        "created_utc,notification_timestamp_utc,first_click_utc,last_click_utc,closed_utc,num_clicks,"
        "closed_reason,details_json\n"
        "chrome,/artifacts/Platform Notifications,Default,https://notify.example,notify.example,notif-1,"
        "Notice,Body,tag-1,,,2024-03-09T16:00:00Z,2024-03-09T16:00:00Z,,,,2,user,{}\n"
    )

    for csv_path in (sessions_csv, settings_csv, notifications_csv):
        assert ingest_csv_output(
            db=db,
            case_id=case.id,
            computer_id="computer-1",
            image_id="image-1",
            tool_output_id=f"{csv_path.stem}-output",
            tool_name="ChromiumParser",
            path=csv_path,
        ) == 1

    assert db.conn.execute("SELECT url FROM browser_session_entries").fetchone()["url"] == "https://session.example"
    assert db.conn.execute("SELECT setting_type FROM browser_site_settings").fetchone()["setting_type"] == "media_stream_camera"
    assert db.conn.execute("SELECT title FROM browser_notifications").fetchone()["title"] == "Notice"


def test_activity_log_records_and_filters_events(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.log_activity(case_id=case.id, event="test.info", message="Info event")
    db.log_activity(case_id=case.id, event="test.warning", message="Warning event", level="warning")
    db.log_activity(case_id=case.id, event="test.error", message="Error event", level="error")

    all_activity = db.activity_for_case(case.id)
    warnings = db.activity_for_case(case.id, level="warning")

    assert [row["event"] for row in reversed(all_activity)] == [
        "test.info",
        "test.warning",
        "test.error",
    ]
    assert len(warnings) == 1
    assert warnings[0]["message"] == "Warning event"
    assert db.case_status(case.id)["activity"][-1]["event"] == "test.error"


def test_dedicated_registry_tool_outputs_are_normalized(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    amcache_csv = tmp_path / "20260514_Amcache_UnassociatedFileEntries.csv"
    amcache_csv.write_text(
        "Path,SHA1,Publisher,ProductName,FileVersion,ModifiedUTC\n"
        "C:\\Windows\\System32\\cmd.exe,ABCDEF,Microsoft,Windows,10.0,2020-11-01 01:02:03\n"
    )
    shimcache_csv = tmp_path / "AppCompatCache.csv"
    shimcache_csv.write_text(
        "EntryNumber,Path,LastModifiedTimeUTC,Executed,ControlSet\n"
        "1,C:\\Temp\\tool.exe,2020-11-02 03:04:05,True,ControlSet001\n"
    )
    shellbags_csv = tmp_path / "ShellBags.csv"
    shellbags_csv.write_text(
        "SourceFile,AbsolutePath,ShellType,MruPosition,CreatedOn,ModifiedOn,AccessedOn,HasExplored\n"
        "/cases/registry/users/Jean/UsrClass.dat,C:\\Users\\Jean\\Documents,Directory,0,"
        "2020-11-03 01:00:00,2020-11-03 02:00:00,2020-11-03 03:00:00,True\n"
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="amcache-output",
        tool_name="AmcacheParser",
        path=amcache_csv,
    ) == 1
    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="shimcache-output",
        tool_name="AppCompatCacheParser",
        path=shimcache_csv,
    ) == 1
    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="shellbag-output",
        tool_name="SBECmd",
        path=shellbags_csv,
    ) == 1

    amcache = db.conn.execute("SELECT entry_type, path, sha1 FROM amcache_entries").fetchone()
    shimcache = db.conn.execute("SELECT path, last_modified_utc, executed FROM shimcache_entries").fetchone()
    shellbag = db.conn.execute("SELECT user_profile, absolute_path, has_explored FROM shellbag_entries").fetchone()
    assert dict(amcache) == {
        "entry_type": "UnassociatedFileEntries",
        "path": "C:\\Windows\\System32\\cmd.exe",
        "sha1": "ABCDEF",
    }
    assert dict(shimcache) == {
        "path": "C:\\Temp\\tool.exe",
        "last_modified_utc": "2020-11-02 03:04:05",
        "executed": "True",
    }
    assert dict(shellbag) == {
        "user_profile": "Jean",
        "absolute_path": "C:\\Users\\Jean\\Documents",
        "has_explored": "True",
    }
    counts = {
        (row["tool_name"], row["row_count"])
        for row in db.parsed_row_counts(case.id)
    }
    assert ("AmcacheParser", 1) in counts
    assert ("AppCompatCacheParser", 1) in counts
    assert ("SBECmd", 1) in counts


def test_usb_registry_artifacts_populate_usb_devices(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    usb_csv = tmp_path / "RegistryArtifactParser.csv"
    usb_csv.write_text(
        "source_path,hive_type,user_profile,artifact,category,key_path,key_last_write_utc,"
        "value_name,value_type,value_data,display_name,value_data_hex\n"
        "/cases/registry/SYSTEM,system,,usb_device_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001230101101234,"
        "2020-11-01T01:02:03+00:00,FriendlyName,REG_SZ,SanDisk Ultra USB Device,SanDisk Ultra USB Device,\n"
        "/cases/registry/SYSTEM,system,,usb_device_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\USB\\VID_0781&PID_5581\\4C530001230101101234,"
        "2020-11-01T01:02:04+00:00,ContainerID,REG_SZ,{abc},{abc},\n"
        "/cases/registry/SYSTEM,system,,mounted_devices,usb,"
        "ROOT\\MountedDevices,"
        "2020-11-01T01:02:05+00:00,\\DosDevices\\F:,REG_BINARY,"
        "_??_USBSTOR#Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00#4C530001230101101234&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b},"
        "_??_USBSTOR#Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00#4C530001230101101234&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b},\n"
        "/cases/registry/SYSTEM,system,,usb_volume_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\SWD\\WPDBUSENUM\\_??_USBSTOR#Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00#4C530001230101101234&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b},"
        "2020-11-01T01:02:06+00:00,FriendlyName,REG_SZ,CASEUSB,CASEUSB,\n"
        "/cases/registry/SOFTWARE,software,,usb_volume_name,usb,"
        "ROOT\\Microsoft\\Windows Portable Devices\\Devices\\SWD#WPDBUSENUM#_??_USBSTOR#Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00#4C530001230101101234&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b},"
        "2020-11-01T01:02:07+00:00,FriendlyName,REG_SZ,MYUSB,MYUSB,\n"
        "/cases/registry/users/Jean/NTUSER.DAT,ntuser,Jean,usb_mountpoints2,usb,"
        "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##?#Volume{21750f1c-1fea-11eb-aa0f-985fd34317f9},"
        "2020-11-01T01:02:08+00:00,_LabelFromReg,REG_SZ,MYUSB,MYUSB,\n"
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="registry-output",
        tool_name="RegistryArtifactParser",
        path=usb_csv,
    ) == 6
    rows = db.conn.execute(
        """
        SELECT device_type, vendor_id, product_id, vendor, product, revision, friendly_name, serial,
               parent_id_prefix, device_service, user_profile, drive_letter, volume_guid,
               volume_serial_number, volume_name, property_name
        FROM usb_devices
        ORDER BY row_number
        """
    ).fetchall()
    assert dict(rows[0]) == {
        "device_type": "usb_storage",
        "vendor_id": None,
        "product_id": None,
        "vendor": "SanDisk",
        "product": "Ultra",
        "revision": "1.00",
        "friendly_name": "SanDisk Ultra USB Device",
        "serial": "4C530001230101101234",
        "parent_id_prefix": None,
        "device_service": None,
        "user_profile": None,
        "drive_letter": None,
        "volume_guid": None,
        "volume_serial_number": None,
        "volume_name": None,
        "property_name": "FriendlyName",
    }
    assert dict(rows[1]) == {
        "device_type": "usb_device",
        "vendor_id": "0781",
        "product_id": "5581",
        "vendor": None,
        "product": None,
        "revision": None,
        "friendly_name": None,
        "serial": "4C530001230101101234",
        "parent_id_prefix": None,
        "device_service": None,
        "user_profile": None,
        "drive_letter": None,
        "volume_guid": None,
        "volume_serial_number": None,
        "volume_name": None,
        "property_name": "ContainerID",
    }
    assert dict(rows[2]) == {
        "device_type": "mounted_device",
        "vendor_id": None,
        "product_id": None,
        "vendor": "SanDisk",
        "product": "Ultra",
        "revision": "1.00",
        "friendly_name": None,
        "serial": "4C530001230101101234",
        "parent_id_prefix": None,
        "device_service": None,
        "user_profile": None,
        "drive_letter": "F:",
        "volume_guid": None,
        "volume_serial_number": None,
        "volume_name": None,
        "property_name": "\\DosDevices\\F:",
    }
    assert dict(rows[3]) == {
        "device_type": "usb_volume",
        "vendor_id": None,
        "product_id": None,
        "vendor": "SanDisk",
        "product": "Ultra",
        "revision": "1.00",
        "friendly_name": None,
        "serial": "4C530001230101101234",
        "parent_id_prefix": None,
        "device_service": None,
        "user_profile": None,
        "drive_letter": None,
        "volume_guid": None,
        "volume_serial_number": None,
        "volume_name": "CASEUSB",
        "property_name": "FriendlyName",
    }
    assert dict(rows[4]) == {
        "device_type": "portable_device_volume",
        "vendor_id": None,
        "product_id": None,
        "vendor": "SanDisk",
        "product": "Ultra",
        "revision": "1.00",
        "friendly_name": None,
        "serial": "4C530001230101101234",
        "parent_id_prefix": None,
        "device_service": None,
        "user_profile": None,
        "drive_letter": None,
        "volume_guid": None,
        "volume_serial_number": None,
        "volume_name": "MYUSB",
        "property_name": "FriendlyName",
    }
    assert dict(rows[5]) == {
        "device_type": "user_mountpoint",
        "vendor_id": None,
        "product_id": None,
        "vendor": None,
        "product": None,
        "revision": None,
        "friendly_name": None,
        "serial": None,
        "parent_id_prefix": None,
        "device_service": None,
        "user_profile": "Jean",
        "drive_letter": None,
        "volume_guid": "{21750f1c-1fea-11eb-aa0f-985fd34317f9}",
        "volume_serial_number": None,
        "volume_name": None,
        "property_name": "_LabelFromReg",
    }
    summary = db.conn.execute(
        """
        SELECT serial, vendor, product, friendly_name, drive_letter, volume_name, evidence_row_count
        FROM usb_storage_devices
        WHERE serial = '4C530001230101101234'
        """
    ).fetchone()
    assert dict(summary) == {
        "serial": "4C530001230101101234",
        "vendor": "SanDisk",
        "product": "Ultra",
        "friendly_name": "SanDisk Ultra USB Device",
        "drive_letter": "F:",
        "volume_name": "CASEUSB, MYUSB",
        "evidence_row_count": 5,
    }
    breakdown = usb_breakdown_report(db, case.id)
    assert breakdown["raw_usb_evidence_rows"] == 6
    assert breakdown["summarized_usb_storage_devices"] == 1
    assert {"artifact": "usb_device_history", "row_count": 2} in breakdown["artifact_counts"]


def test_usb_storage_summary_enriches_missing_volume_serial_from_shortcut_label(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_devices(
        [
            {
                "id": "usb-device",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "usb-output",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "usb.csv",
                "row_number": 1,
                "source_path": "SYSTEM",
                "artifact": "usb_device_history",
                "device_type": "usb_storage",
                "vendor": "CB",
                "product": "Cellebrite",
                "friendly_name": "CB Cellebrite USB Device",
                "serial": "29B1109550240002",
                "volume_name": None,
                "volume_serial_number": None,
                "property_name": "FriendlyName",
                "property_value": "CB Cellebrite USB Device",
            },
            {
                "id": "usb-volume",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "usb-output",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "usb.csv",
                "row_number": 2,
                "source_path": "SOFTWARE",
                "artifact": "usb_volume_history",
                "device_type": "portable_device_volume",
                "vendor": "CB",
                "product": "Cellebrite",
                "serial": "29B1109550240002",
                "volume_name": "SAMPLEVOL",
                "volume_serial_number": None,
                "property_name": "FriendlyName",
                "property_value": "SAMPLEVOL",
            },
        ]
    )
    db.insert_shortcut_items(
        [
            {
                "id": "shortcut-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "shortcut-output",
                "tool_name": "JLECmd",
                "source_csv": tmp_path / "JLECmd.csv",
                "row_number": 1,
                "artifact_type": "jumplist",
                "artifact_name": "autoDestinations-ms",
                "artifact_path": "/artifacts/jumplists/mayas/autoDestinations-ms",
                "file_name": "The end.docx",
                "file_location": "D:\\The end.docx",
                "device_type": "removable",
                "volume_serial_number": "A1B2C3D4",
                "volume_name": "SAMPLEVOL",
                "jumplist_item_number": "1",
            }
        ]
    )

    assert rebuild_usb_storage_devices(db, case_id=case.id) == 1

    summary = db.conn.execute(
        """
        SELECT serial, product, volume_name, volume_serial_number, source_artifacts
        FROM usb_storage_devices
        WHERE serial = '29B1109550240002'
        """
    ).fetchone()
    assert dict(summary) == {
        "serial": "29B1109550240002",
        "product": "Cellebrite",
        "volume_name": "SAMPLEVOL",
        "volume_serial_number": "A1B2C3D4",
        "source_artifacts": "usb_device_history, usb_volume_history, shortcut_volume_label_enrichment",
    }


def test_usb_report_bundle_rows_unpack_mounted_devices_and_volume_cache(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    usb_csv = tmp_path / "RegistryArtifactParser.csv"
    usb_csv.write_text(
        "source_path,hive_type,user_profile,artifact,category,key_path,key_last_write_utc,"
        "value_name,value_type,value_data,display_name,value_data_hex\n"
        "/cases/registry/SYSTEM,system,,mounted_devices,usb,ROOT\\MountedDevices,"
        "2020-11-01T01:02:05+00:00,,,"
        "DeviceName=\\DosDevices\\D:; DeviceData=_??_USBSTOR#Disk&Ven_&Prod_USB_DISK_2.0&Rev_PMAP#90008B5EB5FFFF64&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b},,\n"
        "/cases/registry/SOFTWARE,software,,usb_volume_info_cache,usb,"
        "ROOT\\Microsoft\\Windows Search\\VolumeInfoCache,"
        "2020-11-01T01:02:06+00:00,,,"
        "DriveName=E:; VolumeLabel=Homework; DriveType=Fixed,,\n"
        "/cases/registry/SYSTEM,system,,usb_device_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\USBSTOR,"
        "2020-11-01T01:02:07+00:00,,,"
        "SerialNumber=90008B5EB5FFFF64&0; DeviceName=USB DISK 2.0; DiskId={4dbf10e4-1305-11eb-aa08-985fd34317f9}; LastConnected=2020-11-02T03:04:05Z,,\n"
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="registry-output",
        tool_name="RegistryArtifactParser",
        path=usb_csv,
    ) == 3
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT artifact, device_type, serial, product, friendly_name, drive_letter,
                   volume_guid, volume_name, last_present_date_utc
            FROM usb_devices
            ORDER BY row_number
            """
        ).fetchall()
    ]
    assert rows[0]["drive_letter"] == "D:"
    assert rows[0]["serial"] == "90008B5EB5FFFF64"
    assert rows[0]["product"] == "USB DISK 2.0"
    assert rows[1]["device_type"] == "volume_info_cache"
    assert rows[1]["drive_letter"] == "E:"
    assert rows[1]["volume_name"] == "Homework"
    assert rows[2]["serial"] == "90008B5EB5FFFF64"
    assert rows[2]["friendly_name"] == "USB DISK 2.0"
    assert rows[2]["volume_guid"] == "{4dbf10e4-1305-11eb-aa08-985fd34317f9}"
    assert rows[2]["last_present_date_utc"] == "2020-11-02T03:04:05Z"


def test_uasp_scsi_registry_artifacts_merge_with_usb_parent_id_prefix(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    usb_csv = tmp_path / "RegistryArtifactParser.csv"
    usb_csv.write_text(
        "source_path,hive_type,user_profile,artifact,category,key_path,key_last_write_utc,"
        "value_name,value_type,value_data,display_name,value_data_hex\n"
        "/cases/registry/SYSTEM,system,,usb_device_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\USB\\VID_174C&PID_55AA\\UASP123456,"
        "2020-11-01T01:00:00+00:00,ParentIdPrefix,REG_SZ,7&2abc123&0,7&2abc123&0,\n"
        "/cases/registry/SYSTEM,system,,usb_device_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\USB\\VID_174C&PID_55AA\\UASP123456,"
        "2020-11-01T01:00:01+00:00,Service,REG_SZ,UASPStor,UASPStor,\n"
        "/cases/registry/SYSTEM,system,,usb_device_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_ASMT&Prod_2115&Rev_0\\7&2abc123&0,"
        "2020-11-01T01:00:02+00:00,FriendlyName,REG_SZ,ASMT 2115 SCSI Disk Device,ASMT 2115 SCSI Disk Device,\n"
        "/cases/registry/SYSTEM,system,,usb_device_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_ASMT&Prod_2115&Rev_0\\7&2abc123&0,"
        "2020-11-01T01:00:03+00:00,Service,REG_SZ,disk,disk,\n"
        "/cases/registry/SYSTEM,system,,usb_device_history,usb,"
        "ROOT\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_ASMT&Prod_2115&Rev_0\\7&2abc123&0\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064,"
        "2020-11-01T01:00:04+00:00,(default),REG_SZ,2020-11-01T01:00:04Z,2020-11-01T01:00:04Z,\n"
        "/cases/registry/SYSTEM,system,,mounted_devices,usb,"
        "ROOT\\MountedDevices,"
        "2020-11-01T01:00:05+00:00,\\DosDevices\\G:,REG_BINARY,"
        "_??_SCSI#Disk&Ven_ASMT&Prod_2115&Rev_0#7&2abc123&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b},"
        "_??_SCSI#Disk&Ven_ASMT&Prod_2115&Rev_0#7&2abc123&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b},\n"
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="registry-output",
        tool_name="RegistryArtifactParser",
        path=usb_csv,
    ) == 6

    scsi_row = db.conn.execute(
        """
        SELECT device_type, vendor, product, parent_id_prefix, instance_id
        FROM usb_devices
        WHERE device_type = 'scsi_storage' AND property_name = 'FriendlyName'
        """
    ).fetchone()
    assert dict(scsi_row) == {
        "device_type": "scsi_storage",
        "vendor": "ASMT",
        "product": "2115",
        "parent_id_prefix": "7&2abc123&0",
        "instance_id": "7&2abc123&0",
    }

    summary = db.conn.execute(
        """
        SELECT serial, vendor_id, product_id, vendor, product, friendly_name,
               parent_id_prefix, device_service, drive_letter, first_install_date_utc,
               evidence_row_count
        FROM usb_storage_devices
        WHERE serial = 'UASP123456'
        """
    ).fetchone()
    assert dict(summary) == {
        "serial": "UASP123456",
        "vendor_id": "174C",
        "product_id": "55AA",
        "vendor": "ASMT",
        "product": "2115",
        "friendly_name": "ASMT 2115 SCSI Disk Device",
        "parent_id_prefix": "7&2abc123&0",
        "device_service": "UASPStor, disk",
        "drive_letter": "G:",
        "first_install_date_utc": "2020-11-01T01:00:04Z",
        "evidence_row_count": 6,
    }


def test_usb_device_migration_fields_populate_usb_devices(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    usb_csv = tmp_path / "RegistryArtifactParser.csv"
    usb_csv.write_text(
        "source_path,hive_type,user_profile,artifact,category,key_path,key_last_write_utc,"
        "value_name,value_type,value_data,display_name,value_data_hex\n"
        "/cases/registry/SYSTEM,system,,usb_device_migration,usb,"
        "ROOT\\Setup\\Upgrade\\PnP\\CurrentControlSet\\Control\\DeviceMigration\\Devices\\USB\\VID_0781&PID_5581\\4C530001230101101234,"
        "2020-11-10T01:02:00+00:00,ParentIdPrefix,REG_SZ,7&abc123&0,7&abc123&0,\n"
        "/cases/registry/SYSTEM,system,,usb_device_migration,usb,"
        "ROOT\\Setup\\Upgrade\\PnP\\CurrentControlSet\\Control\\DeviceMigration\\Devices\\USB\\VID_0781&PID_5581\\4C530001230101101234,"
        "2020-11-10T01:02:01+00:00,Service,REG_SZ,USBSTOR,USBSTOR,\n"
        "/cases/registry/SYSTEM,system,,usb_device_migration,usb,"
        "ROOT\\Setup\\Upgrade\\PnP\\CurrentControlSet\\Control\\DeviceMigration\\Devices\\USB\\VID_0781&PID_5581\\4C530001230101101234,"
        "2020-11-10T01:02:02+00:00,LastPresentDate,REG_SZ,2020-11-10T01:02:03Z,2020-11-10T01:02:03Z,\n"
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="registry-output",
        tool_name="RegistryArtifactParser",
        path=usb_csv,
    ) == 3
    rows = db.conn.execute(
        """
        SELECT device_type, vendor_id, product_id, serial, parent_id_prefix,
               device_service, last_present_date_utc, property_name
        FROM usb_devices
        ORDER BY row_number
        """
    ).fetchall()

    assert dict(rows[0]) == {
        "device_type": "usb_device",
        "vendor_id": "0781",
        "product_id": "5581",
        "serial": "4C530001230101101234",
        "parent_id_prefix": "7&abc123&0",
        "device_service": None,
        "last_present_date_utc": None,
        "property_name": "ParentIdPrefix",
    }
    assert dict(rows[1])["device_service"] == "USBSTOR"
    assert dict(rows[2])["last_present_date_utc"] == "2020-11-10T01:02:03Z"

    summary = db.conn.execute(
        """
        SELECT serial, vendor_id, product_id, parent_id_prefix, device_service,
               last_migration_present_utc, source_artifacts
        FROM usb_storage_devices
        WHERE serial = '4C530001230101101234'
        """
    ).fetchone()
    assert dict(summary) == {
        "serial": "4C530001230101101234",
        "vendor_id": "0781",
        "product_id": "5581",
        "parent_id_prefix": "7&abc123&0",
        "device_service": "USBSTOR",
        "last_migration_present_utc": "2020-11-10T01:02:03Z",
        "source_artifacts": "usb_device_migration",
    }

    connection = db.conn.execute(
        """
        SELECT serial, event_type, event_source, event_id, event_time_utc
        FROM usb_connection_events
        WHERE serial = '4C530001230101101234'
        """
    ).fetchone()
    assert dict(connection) == {
        "serial": "4C530001230101101234",
        "event_type": "last_present",
        "event_source": "usb_device_migration",
        "event_id": "LastPresentDate",
        "event_time_utc": "2020-11-10T01:02:03Z",
    }
