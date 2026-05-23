import csv
import sqlite3
from pathlib import Path

from forensic_orchestrator.analytics_query import query_one, query_rows
from forensic_orchestrator.db import Database
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.activities import parse_windows_activities_to_csv
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.normalized import normalized_windows_activity_row


def test_windows_activities_parser_extracts_activity_rows(tmp_path):
    db_path = (
        tmp_path
        / "Users"
        / "Devon"
        / "AppData"
        / "Local"
        / "ConnectedDevicesPlatform"
        / "L.Devon"
        / "ActivitiesCache.db"
    )
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE Activity (
          Id TEXT, AppId TEXT, AppDisplayName TEXT, ActivityType INTEGER,
          StartTime INTEGER, EndTime INTEGER, LastModifiedTime INTEGER,
          PlatformDeviceId TEXT, Payload TEXT
        );
        INSERT INTO Activity VALUES (
          'activity-1', 'Microsoft.Windows.Explorer', 'File Explorer', 5,
          1704164645, 1704164700, 1704164800, 'device-1',
          '{"displayText":"report.docx","contentUri":"file:///C:/Users/Devon/Documents/report.docx","activationUri":"ms-word:ofe|u|https://example.com/report.docx"}'
        );
        """
    )
    conn.close()

    [csv_path] = parse_windows_activities_to_csv(tmp_path / "Users", tmp_path / "out")

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["user_profile"] == "Devon"
    assert rows[0]["app_display_name"] == "File Explorer"
    assert rows[0]["display_text"] == "report.docx"
    assert rows[0]["file_name"] == "report.docx"
    assert rows[0]["content_uri"] == "file:///C:/Users/Devon/Documents/report.docx"
    assert rows[0]["start_time_utc"] == "2024-01-02T03:04:05Z"
    assert "report.docx" in rows[0]["payload_json"]


def test_windows_activity_rows_feed_timeline_events(tmp_path):
    row = normalized_windows_activity_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="WindowsActivitiesParser",
        source_csv=tmp_path / "WindowsActivities.csv",
        row_number=1,
        row={
            "user_profile": "Devon",
            "app_display_name": "File Explorer",
            "file_name": "report.docx",
            "content_uri": "file:///C:/Users/Devon/Documents/report.docx",
            "start_time_utc": "2024-01-02T03:04:05Z",
        },
    )

    events = timeline_events_from_rows([row])

    assert events[0]["event_type"] == "windows_activity_started"
    assert events[0]["source_table"] == "windows_activities"


def test_windows_activities_ingest_populates_db(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id=computer.id)
    csv_path = tmp_path / "WindowsActivities.csv"
    csv_path.write_text(
        "source_path,user_profile,source_table,activity_id,app_id,app_display_name,activity_type,display_text,file_name,content_uri,activation_uri,fallback_uri,start_time_utc,end_time_utc,last_modified_utc,expiration_time_utc,platform_device_id,payload_json,raw_json\n"
        "/ActivitiesCache.db,Devon,Activity,activity-1,app-id,File Explorer,5,report.docx,report.docx,file:///C:/Users/Devon/Documents/report.docx,,,2024-01-02T03:04:05Z,,2024-01-02T03:05:05Z,,device-1,{},{}\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-activities",
        tool_name="WindowsActivitiesParser",
        path=csv_path,
    )

    row = query_one(db, "windows_activities", "SELECT * FROM windows_activities")
    assert row["app_display_name"] == "File Explorer"
    assert row["file_name"] == "report.docx"
    assert row["content_uri"] == "file:///C:/Users/Devon/Documents/report.docx"
    event_types = {
        row["event_type"]
        for row in query_rows(db, "timeline_events", "SELECT event_type FROM timeline_events")
    }
    assert "windows_activity_started" in event_types
