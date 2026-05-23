import csv
import json
from pathlib import Path

from forensic_orchestrator.analytics_query import query_one
from forensic_orchestrator.db import Database
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.etl import _event_row, parse_etl_artifacts_to_csv
from forensic_orchestrator.tools.ingest import ingest_csv_output


class FakeEvent:
    def ts(self):
        from datetime import datetime, timezone

        return datetime(2020, 11, 14, 13, 45, 45, tzinfo=timezone.utc)

    def provider_id(self):
        return "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"

    def provider_name(self):
        return "Microsoft-Windows-Kernel-Process"

    def symbol(self):
        return "ProcessStart"

    def event_values(self):
        return {
            "ProcessID": 1234,
            "ParentProcessID": 456,
            "SessionID": 1,
            "ImageName": r"C:\Users\fredr\Downloads\SDelete\sdelete.exe",
            "CommandLine": r"sdelete.exe -p 1 C:\Users\fredr\Desktop\secret.docx",
            "UserSID": "S-1-5-21-1-2-3-1002",
            "PackageFullName": "",
            "Flags": "0x0",
        }


def test_etl_event_row_extracts_process_fields(tmp_path):
    row = _event_row(tmp_path / "AutoLogger-Diagtrack-Listener.etl", FakeEvent(), 1)

    assert row["parser_status"] == "parsed"
    assert row["provider_name"] == "Microsoft-Windows-Kernel-Process"
    assert row["provider_label"] == "Microsoft-Windows-Kernel-Process"
    assert row["event_category"] == "process_execution"
    assert row["event_name"] == "ProcessStart"
    assert row["timestamp_utc"] == "2020-11-14T13:45:45+00:00"
    assert row["process_id"] == "1234"
    assert row["parent_process_id"] == "456"
    assert row["image_name"] == r"C:\Users\fredr\Downloads\SDelete\sdelete.exe"
    assert "secret.docx" in row["command_line"]
    assert json.loads(row["payload_strings_json"])[0] == r"C:\Users\fredr\Downloads\SDelete\sdelete.exe"


def test_etl_ingest_populates_table_and_timeline(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id=computer.id)
    csv_path = tmp_path / "EtlEvents.csv"
    fields = [
        "source_file", "source_name", "parser_status", "parser_error", "timestamp_utc",
        "provider_name", "provider_id", "provider_label", "event_category",
        "event_name", "event_id", "opcode", "version",
        "process_id", "parent_process_id", "session_id", "image_name", "command_line",
        "user_sid", "package_full_name", "flags", "payload_strings_json",
        "event_values_json", "file_size", "sha256_first_mb",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(_event_row(tmp_path / "AutoLogger-Diagtrack-Listener.etl", FakeEvent(), 1))

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-etl",
        tool_name="EtlParser",
        path=csv_path,
    )

    row = query_one(db, "etl_events", "SELECT * FROM etl_events")
    event = query_one(db, "timeline_events", "SELECT * FROM timeline_events")
    assert row_count == 1
    assert row["source_name"] == "AutoLogger-Diagtrack-Listener.etl"
    assert row["provider_label"] == "Microsoft-Windows-Kernel-Process"
    assert row["event_category"] == "process_execution"
    assert row["image_name"].endswith("sdelete.exe")
    assert event["source_table"] == "etl_events"
    assert event["event_type"] == "etl_process_event"


def test_etl_event_row_labels_cldflt_source(tmp_path):
    row = _event_row(tmp_path / "CldFlt0.etl", FakeEvent(), 1)

    assert row["provider_label"] == "Microsoft-Windows-Kernel-Process"
    assert row["event_category"] == "process_execution"


def test_etl_inventory_labels_cldflt_source(tmp_path):
    source = tmp_path / "CldFlt0.etl"
    source.write_bytes(b"")
    csv_path = parse_etl_artifacts_to_csv(source, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
    inventory = next(row for row in rows if row["parser_status"] == "inventory")

    assert inventory["provider_label"] == "Microsoft Cloud Files Filter (CldFlt)"
    assert inventory["event_category"] == "cloud_files"


def test_etl_parser_records_invalid_etl_error(tmp_path):
    source = tmp_path / "Windows" / "System32" / "LogFiles" / "WMI"
    source.mkdir(parents=True)
    (source / "AutoLogger-Diagtrack-Listener.etl").write_bytes(
        b"not an etl C:\\Users\\fredr\\Downloads\\SDelete\\sdelete.exe -p 1 C:\\Temp\\x.docx"
    )

    csv_path = parse_etl_artifacts_to_csv(tmp_path / "Windows", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))

    assert any(row["parser_status"] == "inventory" for row in rows)
    assert any(row["parser_status"] == "error" for row in rows)
    assert any(row["parser_status"] == "strings" and "sdelete.exe" in row["image_name"].lower() for row in rows)
