from __future__ import annotations

import json

import duckdb

from forensic_orchestrator.artifact_distinct import rebuild_distinct_artifact_tables
from forensic_orchestrator.db import Database


def test_rebuild_distinct_artifact_tables_keeps_sources_and_collapses_duplicates(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": image.id,
        "tool_output_id": "output-1",
        "tool_name": "MFTECmd",
    }
    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                **base,
                "id": "mft-live",
                "source_csv": "/e/live_$MFT.csv",
                "row_number": 1,
                "entry_number": "42",
                "sequence_number": "3",
                "parent_path": "C:/Users/Analyst",
                "file_name": "note.txt",
                "created_si": "2020-01-01 00:00:00",
            },
            {
                **base,
                "id": "mft-vsc",
                "source_csv": "/e/ShadowCopy52_$MFT.csv",
                "row_number": 9,
                "entry_number": "42",
                "sequence_number": "3",
                "parent_path": "C:/Users/Analyst",
                "file_name": "note.txt",
                "created_si": "2020-02-02 00:00:00",
            },
        ],
    )

    stats = rebuild_distinct_artifact_tables(db, case_id=case.id, image_id=image.id)

    assert stats["tables"]["mft_entries"] == {"source_rows": 2, "distinct_rows": 1, "duplicate_rows": 1}
    db.close()
    conn = duckdb.connect(str(tmp_path / "cases" / "case-1" / "analytics" / "events.duckdb"), read_only=True)
    try:
        row = conn.execute(
            """
            SELECT id, distinct_source_count, distinct_source_csvs_json, distinct_source_row_ids_json
            FROM distinct_mft_entries
            """
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == "mft-live"
    assert row[1] == 2
    assert json.loads(row[2]) == ["/e/ShadowCopy52_$MFT.csv", "/e/live_$MFT.csv"]
    assert json.loads(row[3]) == ["mft-live", "mft-vsc"]
