import csv
import sqlite3
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.reports import telemetry_artifacts_report
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.telemetry import parse_telemetry_artifacts_to_csv


def test_telemetry_parser_extracts_wmi_notifications_apprepository_and_wdac(tmp_path):
    root = tmp_path / "volume"
    wmi = root / "Windows" / "System32" / "wbem" / "Repository"
    wmi.mkdir(parents=True)
    (wmi / "OBJECTS.DATA").write_bytes(
        b"prefix __EventFilter CommandLineEventConsumer __FilterToConsumerBinding "
        b"C:\\Users\\Jane\\AppData\\Local\\Temp\\payload.ps1 suffix"
    )
    cloudstore = root / "Users" / "Jane" / "AppData" / "Local" / "Microsoft" / "Windows" / "CloudStore"
    cloudstore.mkdir(parents=True)
    (cloudstore / "store.dat").write_bytes(
        "CloudStore setting value https://contoso.example/sync S-1-5-21-1-2-3-1001".encode("utf-16-le")
    )
    notifications = root / "Users" / "Jane" / "AppData" / "Local" / "Microsoft" / "Windows" / "Notifications"
    notifications.mkdir(parents=True)
    notif_db = notifications / "wpndatabase.db"
    conn = sqlite3.connect(notif_db)
    conn.execute("CREATE TABLE Notification (NotificationId TEXT, HandlerId TEXT, Payload TEXT, CreatedTime INTEGER)")
    conn.execute("INSERT INTO Notification VALUES ('notif-1', 'App.Handler', 'Toast body file:///C:/Users/Jane/Documents/a.docx', 133485408000000000)")
    conn.commit()
    conn.close()
    apprepo = root / "ProgramData" / "Microsoft" / "Windows" / "AppRepository"
    apprepo.mkdir(parents=True)
    apprepo_db = apprepo / "StateRepository-Machine.srd"
    conn = sqlite3.connect(apprepo_db)
    conn.execute("CREATE TABLE Package (PackageFullName TEXT, DisplayName TEXT, InstallTime INTEGER)")
    conn.execute("INSERT INTO Package VALUES ('Contoso.App_1.0_x64__abc', 'Contoso App', 133485408000000000)")
    conn.commit()
    conn.close()
    wdac = root / "Windows" / "System32" / "CodeIntegrity" / "CiPolicies" / "Active"
    wdac.mkdir(parents=True)
    (wdac / "policy.cip").write_bytes(b"WDAC policy bytes")

    csv_path = parse_telemetry_artifacts_to_csv(root, tmp_path / "out")
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    groups = {row["artifact_group"] for row in rows}
    assert {"wmi", "cloudstore", "notifications", "apprepository", "wdac"} <= groups
    assert any(row["record_type"] == "wmi_repository_strings" for row in rows)
    assert any(row["record_type"] == "wmi_windows_path" and row["path"].startswith("C:\\Users\\Jane") for row in rows)
    assert any(row["record_type"] == "cloudstore_url" and row["host"] == "contoso.example" for row in rows)
    assert any(row["record_type"] == "cloudstore_sid" and row["identifier"].endswith("-1001") for row in rows)
    assert any(row["record_type"] == "notifications_notification" and row["identifier"] == "notif-1" for row in rows)
    assert any(row["record_type"] == "notifications_notification" and row["event_time_utc"] == "2024-01-01T00:00:00Z" for row in rows)
    assert any(row["artifact_group"] == "apprepository" and "Contoso.App" in row["value_data"] for row in rows)


def test_telemetry_artifacts_ingest_and_report(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "TelemetryArtifacts.csv"
    csv_path.write_text(
        "record_type,artifact_group,user_profile,application,source_path,source_name,file_name,file_extension,file_size,"
        "modified_utc,event_time_utc,identifier,path,url,host,title,value_name,value_data,artifact_text,sha256_first_mb,details_json,error\n"
        "wdac_policy_artifact,wdac,,,/Windows/System32/CodeIntegrity/SiPolicy.p7b,Windows Defender Application Control,"
        "SiPolicy.p7b,.p7b,10,2026-01-01T00:00:00Z,,policy-1,,,,Policy,,Enabled,Policy text,abc123,{},\n",
        encoding="utf-8",
    )
    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="TelemetryParser",
        path=csv_path,
    )
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "TelemetryParser",
            "output_type": "csv",
            "path": csv_path,
            "row_count": row_count,
        }
    )

    report = telemetry_artifacts_report(db, case.id, artifact_group="wdac")

    assert row_count == 1
    assert report["total_returned"] == 1
    assert report["telemetry_artifacts"][0]["artifact_group"] == "wdac"


def test_telemetry_artifacts_create_timeline_events():
    row = {
        "id": 42,
        "case_id": "case-1",
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "tool_name": "TelemetryParser",
        "record_type": "notifications_notification",
        "artifact_group": "notifications",
        "user_profile": "Jane",
        "application": "Contoso.App",
        "source_path": "/Users/Jane/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db",
        "source_name": "Windows Notifications",
        "file_name": "wpndatabase.db",
        "modified_utc": "2026-01-02T03:04:05Z",
        "event_time_utc": None,
        "identifier": "notif-1",
        "title": "Toast title",
        "value_data": "Toast body",
        "sha256_first_mb": "abc123",
    }

    events = timeline_events_from_rows([row])

    assert len(events) == 1
    assert events[0]["source_table"] == "telemetry_artifacts"
    assert events[0]["event_type"] == "notifications_notifications_notification"
    assert events[0]["timestamp_utc"] == "2026-01-02T03:04:05Z"
    assert events[0]["description"] == "Toast title"
