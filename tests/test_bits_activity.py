from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.reports import bits_activity_report
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.normalized import (
    normalized_bits_activity_row_from_evtx,
    normalized_evtx_event_row,
)


def test_bits_activity_normalizes_evtx_payload_and_timeline(tmp_path):
    evtx_row = normalized_evtx_event_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="EvtxECmd",
        source_csv=tmp_path / "evtx.csv",
        row_number=1,
        row={
            "TimeCreated": "2025-11-17T13:13:51.765977Z",
            "EventId": "59",
            "Provider": "Microsoft-Windows-Bits-Client",
            "Channel": "Microsoft-Windows-Bits-Client/Operational",
            "Computer": "MayaS",
            "PayloadData1": "jobTitle: UpdateBinary",
            "PayloadData2": "jobId: 549e5bbd-e7f3-46b7-821b-dd48f374c985",
            "PayloadData3": "URL: https://oneclient.sfx.ms/Win/Installers/OneDriveSetup.exe",
            "PayloadData4": "Peer:",
            "PayloadData5": "Total Bytes: 86959504 (Transferred: 0)",
        },
    )
    bits_row = normalized_bits_activity_row_from_evtx(evtx_row)

    assert bits_row is not None
    assert bits_row["event_type"] == "bits_transfer_started"
    assert bits_row["job_name"] == "UpdateBinary"
    assert bits_row["job_id"] == "549e5bbd-e7f3-46b7-821b-dd48f374c985"
    assert bits_row["url"] == "https://oneclient.sfx.ms/Win/Installers/OneDriveSetup.exe"
    assert bits_row["total_bytes"] == "86959504"
    assert bits_row["bytes_transferred"] == "0"

    events = timeline_events_from_rows([bits_row])
    assert len(events) == 1
    assert events[0]["event_type"] == "bits_transfer_started"
    assert events[0]["timestamp_utc"] == "2025-11-17T13:13:51.765977Z"
    assert events[0]["source_table"] == "bits_activity"


def test_bits_activity_report_correlates_evtx_to_qmgr_url(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    computer_id = "computer-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id=computer_id, case_id=case_id, label="Sterling")
    db.add_image(image_id, case_id, Path("/evidence/sterling.E01"), computer_id=computer_id)

    shared = {
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": "output-1",
        "source_csv": tmp_path / "bits.csv",
        "row_number": 1,
    }
    db.insert_bits_jobs(
        [
            {
                **shared,
                "id": "bits-job-1",
                "tool_name": "BITSParser",
                "database_file": "qmgr.db",
                "record_type": "carved_url",
                "url": "https://oneclient.sfx.ms/Win/Installers/OneDriveSetup.exe",
                "parser_status": "strings_carved",
                "raw_row_json": "{}",
            }
        ]
    )
    db.insert_bits_activity(
        [
            {
                **shared,
                "id": "bits-activity-1",
                "tool_name": "EvtxECmd",
                "source_table": "evtx_events",
                "source_row_id": "evtx-1",
                "event_time_utc": "2025-11-17T13:13:51.765977Z",
                "event_id": "59",
                "event_type": "bits_transfer_started",
                "provider": "Microsoft-Windows-Bits-Client",
                "channel": "Microsoft-Windows-Bits-Client/Operational",
                "computer": "MayaS",
                "job_name": "UpdateBinary",
                "url": "https://oneclient.sfx.ms/Win/Installers/OneDriveSetup.exe",
                "correlation_basis": "evtx_bits_client",
                "raw_fields_json": "{}",
            }
        ]
    )

    report = bits_activity_report(db, case_id, limit=10)

    assert report["total_returned"] == 1
    assert report["total_available"] == 1
    assert report["limited"] is False
    row = report["bits_activity"][0]
    assert row["matched_bits_job_row_id"] == "bits-job-1"
    assert row["matched_database_file"] == "qmgr.db"
    assert row["matched_parser_status"] == "strings_carved"
    assert row["match_basis"] == "url"
    assert row["computer_label"] == "Sterling"
    db.close()


def test_bits_activity_report_flags_limited_results(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.insert_bits_activity(
        [
            {
                "case_id": case_id,
                "id": f"bits-activity-{index}",
                "tool_output_id": "output-1",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "bits.csv",
                "row_number": index,
                "source_table": "evtx_events",
                "source_row_id": f"evtx-{index}",
                "event_time_utc": f"2025-11-17T13:13:5{index}Z",
                "event_id": "59",
                "event_type": "bits_transfer_started",
                "provider": "Microsoft-Windows-Bits-Client",
                "channel": "Microsoft-Windows-Bits-Client/Operational",
                "correlation_basis": "evtx_bits_client",
                "raw_fields_json": "{}",
            }
            for index in range(3)
        ]
    )

    report = bits_activity_report(db, case_id, limit=2)

    assert report["total_returned"] == 2
    assert report["total_available"] == 3
    assert report["limited"] is True
    db.close()
