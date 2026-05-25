from pathlib import Path

from forensic_orchestrator.analytics_query import query_rows
from forensic_orchestrator.db import Database
from forensic_orchestrator.timeline_dedupe import rebuild_timeline_windows_old_dedupe


def test_timeline_windows_old_dedupe_updates_duckdb_timeline_events(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "tool-output-current",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": image.id,
            "job_id": None,
            "tool_name": "Parser",
            "output_type": "csv",
            "path": tmp_path / "current.csv",
            "content_sha256": "current",
            "row_count": 1,
        }
    )
    db.insert_tool_output(
        {
            "id": "tool-output-old",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": image.id,
            "job_id": None,
            "tool_name": "Parser",
            "output_type": "csv",
            "path": tmp_path / "Windows.old" / "old.csv",
            "content_sha256": "old",
            "row_count": 1,
        }
    )
    db.insert_timeline_events(
        [
            {
                "id": "event-current",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": image.id,
                "tool_output_id": "tool-output-current",
                "source_tool": "Parser",
                "source_table": "parsed",
                "source_row_id": "1",
                "event_type": "file_open",
                "timestamp_utc": "2020-01-01T00:00:00Z",
                "description": "opened file",
                "details": {"path": "/Users/lee/file.txt"},
            },
            {
                "id": "event-old",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": image.id,
                "tool_output_id": "tool-output-old",
                "source_tool": "Parser",
                "source_table": "parsed",
                "source_row_id": "1",
                "event_type": "file_open",
                "timestamp_utc": "2020-01-01T00:00:00Z",
                "description": "opened file",
                "details": {"path": "/Users/lee/file.txt"},
            },
        ]
    )

    stats = rebuild_timeline_windows_old_dedupe(db, case_id=case.id, image_id=image.id)

    assert stats["duplicate_rows"] == 1
    rows = query_rows(
        db,
        "timeline_events",
        "SELECT id, dedupe_status, primary_event_id, is_windows_old FROM timeline_events ORDER BY id",
    )
    assert rows == [
        {"id": "event-current", "dedupe_status": "primary", "primary_event_id": None, "is_windows_old": "0"},
        {"id": "event-old", "dedupe_status": "duplicate", "primary_event_id": "event-current", "is_windows_old": "1"},
    ]
    sources = db.conn.execute("SELECT source_scope FROM timeline_event_sources ORDER BY source_scope").fetchall()
    assert [row["source_scope"] for row in sources] == ["current", "windows_old"]


def test_timeline_windows_old_dedupe_skips_missing_duckdb_timeline_table(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id="computer-1")
    db.analytics._connect(case.id)

    stats = rebuild_timeline_windows_old_dedupe(db, case_id=case.id, image_id=image.id)

    assert stats["timeline_rows"] == 0
    assert stats["duplicate_rows"] == 0
    row = db.conn.execute("SELECT event FROM activity_log WHERE case_id = ? ORDER BY created_at DESC LIMIT 1", (case.id,)).fetchone()
    assert row["event"] == "timeline.windows_old_dedupe_skipped"
