import csv
import sqlite3
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.reports import clipboard_report, timeline_report
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.clipboard import parse_clipboard_artifacts_to_csv
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.normalized import normalized_clipboard_item_row


def test_clipboard_parser_reads_sqlite_store(tmp_path):
    store_dir = tmp_path / "Users" / "maya" / "AppData" / "Local" / "Microsoft" / "Clipboard"
    store_dir.mkdir(parents=True)
    db_path = store_dir / "clipboard.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE ClipboardItems (
          Id TEXT,
          CreatedTime INTEGER,
          FormatName TEXT,
          Text TEXT,
          CloudSyncId TEXT,
          IsSynced INTEGER
        )
        """
    )
    conn.execute(
        "INSERT INTO ClipboardItems VALUES (?, ?, ?, ?, ?, ?)",
        ("clip-1", 1735689600, "Text", "Copied investigation note", "sync-1", 1),
    )
    conn.commit()
    conn.close()

    csv_path = parse_clipboard_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))

    assert len(rows) == 1
    assert rows[0]["user_profile"] == "maya"
    assert rows[0]["source_table"] == "ClipboardItems"
    assert rows[0]["text_content"] == "Copied investigation note"
    assert rows[0]["cloud_sync_id"] == "sync-1"
    assert rows[0]["item_time_utc"] == "2025-01-01T00:00:00Z"


def test_clipboard_parser_reads_windows_historydata_payload_file(tmp_path):
    payload_dir = (
        tmp_path
        / "Users"
        / "maya"
        / "AppData"
        / "Local"
        / "Microsoft"
        / "Windows"
        / "Clipboard"
        / "HistoryData"
        / "{6F683FE4-8911-4714-9C4D-B3D40BCF7DD3}"
    )
    payload_dir.mkdir(parents=True)
    payload = payload_dir / "payload"
    payload.write_text("Copied from Windows clipboard history", encoding="utf-16le")

    csv_path = parse_clipboard_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))

    assert len(rows) == 1
    assert rows[0]["user_profile"] == "maya"
    assert rows[0]["source_type"] == "file"
    assert rows[0]["source_table"] == "HistoryData"
    assert rows[0]["row_identifier"] == "{6F683FE4-8911-4714-9C4D-B3D40BCF7DD3}"
    assert rows[0]["text_content"] == "Copied from Windows clipboard history"


def test_clipboard_ingest_report_and_timeline(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id=computer.id)
    csv_path = tmp_path / "ClipboardItems.csv"
    csv_path.write_text(
        "source_path,user_profile,source_type,source_table,row_identifier,item_time_utc,created_time_utc,modified_time_utc,last_used_time_utc,sequence_number,format_name,content_type,text_content,file_uri,html_content,image_present,payload_size,cloud_sync_state,cloud_sync_id,device_id,raw_payload_json,parser_status,parser_error\n"
        "/Users/maya/AppData/Local/Microsoft/Clipboard/clipboard.db,maya,sqlite,ClipboardItems,clip-1,2025-01-01T00:00:00Z,2025-01-01T00:00:00Z,,,1,Text,text/plain,Copied investigation note,,,false,25,1,sync-1,device-1,{},parsed,\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-clipboard",
        tool_name="ClipboardParser",
        path=csv_path,
    )

    report = clipboard_report(db, case.id, contains="investigation", limit=10)
    assert report["total_returned"] == 1
    assert report["total_available"] == 1
    assert report["clipboard_items"][0]["text_content"] == "Copied investigation note"

    timeline = timeline_report(db, case.id, contains="Copied investigation note", limit=10)
    assert {row["event_type"] for row in timeline["events"]} >= {"clipboard_item", "clipboard_item_created"}
    db.close()


def test_clipboard_normalized_row_creates_timeline_event(tmp_path):
    row = normalized_clipboard_item_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="ClipboardParser",
        source_csv=tmp_path / "ClipboardItems.csv",
        row_number=1,
        row={
            "source_path": "/Users/maya/AppData/Local/Microsoft/Clipboard/clipboard.db",
            "user_profile": "maya",
            "source_type": "sqlite",
            "source_table": "ClipboardItems",
            "row_identifier": "clip-1",
            "item_time_utc": "2025-01-01T00:00:00Z",
            "format_name": "Text",
            "text_content": "Copied investigation note",
            "cloud_sync_state": "1",
        },
    )

    events = timeline_events_from_rows([row])

    assert events[0]["event_type"] == "clipboard_item"
    assert events[0]["source_table"] == "clipboard_items"
    assert events[0]["details"]["text_preview"] == "Copied investigation note"
