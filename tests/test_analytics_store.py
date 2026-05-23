import duckdb

from forensic_orchestrator.db import Database
from forensic_orchestrator.filesystem_review import rebuild_filesystem_review
from forensic_orchestrator.reports import image_analysis_report, rdp_cache_report, rdp_visual_observations_report
from forensic_orchestrator.tools.ingest import ingest_csv_output


def test_duckdb_analytics_mode_is_default(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    assert db.analytics_mode == "duckdb"
    db.close()


def test_default_duckdb_routes_generic_normalized_rows(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")

    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                "id": "mft-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 1,
                "file_name": "$MFT",
            }
        ],
    )
    db.close()

    duck = duckdb.connect(str(tmp_path / "cases" / case_id / "analytics" / "events.duckdb"))
    assert duck.execute("SELECT file_name FROM mft_entries").fetchone() == ("$MFT",)
    duck.close()
    sqlite_db = Database(tmp_path / "orchestrator.sqlite3")
    assert sqlite_db.conn.execute("SELECT COUNT(*) FROM mft_entries").fetchone()[0] == 0
    sqlite_db.close()


def test_default_duckdb_routes_common_artifact_insert_helpers(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")
    base = {
        "case_id": case_id,
        "computer_id": "computer-1",
        "image_id": image_id,
        "tool_output_id": "output-1",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_shortcut_items([
        {
            **base,
            "id": "shortcut-1",
            "tool_name": "LECmd",
            "artifact_type": "lnk",
            "file_name": "report.docx",
        }
    ])
    db.insert_prefetch_items([
        {
            **base,
            "id": "prefetch-1",
            "tool_name": "PECmd",
            "prefetch_name": "NOTEPAD.EXE-12345678.pf",
        }
    ])
    db.insert_registry_artifacts([
        {
            **base,
            "id": "registry-1",
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/SOFTWARE",
            "artifact": "autostart",
            "key_path": "Run",
        }
    ])
    db.close()

    duck = duckdb.connect(str(tmp_path / "cases" / case_id / "analytics" / "events.duckdb"))
    assert duck.execute("SELECT COUNT(*) FROM shortcut_items").fetchone() == (1,)
    assert duck.execute("SELECT COUNT(*) FROM prefetch_items").fetchone() == (1,)
    assert duck.execute("SELECT COUNT(*) FROM registry_artifacts").fetchone() == (1,)
    duck.close()
    sqlite_db = Database(tmp_path / "orchestrator.sqlite3")
    assert sqlite_db.conn.execute("SELECT COUNT(*) FROM shortcut_items").fetchone()[0] == 0
    assert sqlite_db.conn.execute("SELECT COUNT(*) FROM prefetch_items").fetchone()[0] == 0
    assert sqlite_db.conn.execute("SELECT COUNT(*) FROM registry_artifacts").fetchone()[0] == 0
    sqlite_db.close()


def test_default_duckdb_ingest_routes_normalized_rows(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "EntryNumber,FileName,ParentPath,Created0x10,LastModified0x10\n"
        "0,$MFT,.,2026-05-12 13:14:15,2026-05-12 13:14:16\n",
        encoding="utf-8",
    )

    assert ingest_csv_output(
        db=db,
        case_id=case_id,
        computer_id="computer-1",
        image_id=image_id,
        tool_output_id="output-1",
        tool_name="MFTECmd",
        path=csv_path,
    ) == 1
    db.close()

    duck = duckdb.connect(str(tmp_path / "cases" / case_id / "analytics" / "events.duckdb"))
    assert duck.execute("SELECT file_name FROM mft_entries").fetchone() == ("$MFT",)
    duck.close()
    sqlite_db = Database(tmp_path / "orchestrator.sqlite3")
    assert sqlite_db.conn.execute("SELECT COUNT(*) FROM mft_entries").fetchone()[0] == 0
    sqlite_db.close()


def test_default_duckdb_purge_removes_normalized_rows(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")
    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                "id": "mft-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 1,
                "file_name": "$MFT",
            }
        ],
    )

    db.purge_tool_data(case_id=case_id, image_id=image_id, tool_names=["MFTECmd"])
    db.close()

    duck = duckdb.connect(str(tmp_path / "cases" / case_id / "analytics" / "events.duckdb"))
    assert duck.execute("SELECT COUNT(*) FROM mft_entries").fetchone() == (0,)
    duck.close()


def test_default_duckdb_routes_rdp_cache_and_image_analysis_reports(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")
    cache_file = tmp_path / "Cache0000.bin"
    cache_file.write_bytes(b"rdp")

    db.insert_rdp_cache_items(
        [
            {
                "id": "rdp-cache-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-rdp",
                "tool_name": "RdpCacheParser",
                "source_csv": tmp_path / "RdpCacheItems.csv",
                "row_number": 1,
                "record_type": "cache_file",
                "user_profile": "fredr",
                "source_cache_path": cache_file,
                "file_name": "Cache0000.bin",
                "parser_status": "found",
            }
        ]
    )
    db.insert_image_analysis_items(
        [
            {
                "id": "image-analysis-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-rdp",
                "tool_name": "RdpCacheParser",
                "source_csv": tmp_path / "ImageAnalysisItems.csv",
                "row_number": 1,
                "source_artifact_type": "rdp_cache_fragment",
                "source_path": cache_file,
                "output_path": tmp_path / "fragment-1.png",
                "file_name": "fragment-1.png",
                "analysis_type": "image_metadata",
                "ocr_status": "not_requested",
            }
        ]
    )
    db.insert_rdp_visual_observations(
        [
            {
                "id": "rdp-visual-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-rdp",
                "tool_name": "ManualVisualReview",
                "source_csv": None,
                "row_number": 1,
                "user_profile": "fredr",
                "source_cache_path": cache_file,
                "contact_sheet_path": tmp_path / "contact-sheet.jpg",
                "observation_time_utc": "2026-05-19 00:00:00",
                "observation_type": "application_visible",
                "observed_application": "File Explorer",
                "observed_text": "Documents",
            }
        ]
    )

    assert db.conn.execute("SELECT COUNT(*) FROM rdp_cache_items").fetchone()[0] == 0
    assert db.conn.execute("SELECT COUNT(*) FROM image_analysis_items").fetchone()[0] == 0
    assert db.conn.execute("SELECT COUNT(*) FROM rdp_visual_observations").fetchone()[0] == 0
    assert rdp_cache_report(db, case_id)["rdp_cache"][0]["file_name"] == "Cache0000.bin"
    assert image_analysis_report(db, case_id)["image_analysis"][0]["source_artifact_type"] == "rdp_cache_fragment"
    assert rdp_visual_observations_report(db, case_id)["rdp_visual_observations"][0]["observed_application"] == "File Explorer"
    db.close()


def test_default_duckdb_purge_removes_rdp_cache_and_image_analysis_rows(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")

    db.insert_rdp_cache_items(
        [
            {
                "id": "rdp-cache-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-rdp",
                "tool_name": "RdpCacheParser",
                "source_csv": tmp_path / "RdpCacheItems.csv",
                "row_number": 1,
                "record_type": "cache_file",
                "user_profile": "fredr",
                "source_cache_path": tmp_path / "Cache0000.bin",
            }
        ]
    )
    db.insert_image_analysis_items(
        [
            {
                "id": "image-analysis-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-rdp",
                "tool_name": "RdpCacheParser",
                "source_csv": tmp_path / "ImageAnalysisItems.csv",
                "row_number": 1,
                "source_artifact_type": "rdp_cache_fragment",
                "source_path": tmp_path / "Cache0000.bin",
            }
        ]
    )

    db.purge_tool_data(case_id=case_id, image_id=image_id, tool_names=["RdpCacheParser"])
    db.close()

    duck = duckdb.connect(str(tmp_path / "cases" / case_id / "analytics" / "events.duckdb"))
    assert duck.execute("SELECT COUNT(*) FROM rdp_cache_items").fetchone() == (0,)
    assert duck.execute("SELECT COUNT(*) FROM image_analysis_items").fetchone() == (0,)
    duck.close()


def test_default_duckdb_does_not_materialize_filesystem_review_in_sqlite(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")
    db.conn.execute(
        """
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, event_type,
          details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("review-1", case_id, "computer-1", image_id, "mft_entries", "mft-1", "mft_record", "{}", "now"),
    )
    db.conn.commit()

    assert rebuild_filesystem_review(db, case_id=case_id, image_id=image_id) == 0
    assert db.conn.execute("SELECT COUNT(*) FROM filesystem_review WHERE case_id = ?", [case_id]).fetchone()[0] == 0
    db.close()


def test_duckdb_analytics_mode_routes_high_volume_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    output_id = "output-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")

    db.insert_evtx_events(
        [
            {
                "id": "event-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": output_id,
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 1,
                "event_id": "4624",
                "time_created": "2026-05-19T00:00:00Z",
            }
        ]
    )
    db.close()

    assert duckdb.connect(str(tmp_path / "cases" / case_id / "analytics" / "events.duckdb")).execute(
        "SELECT event_id FROM evtx_events"
    ).fetchone() == ("4624",)
    sqlite_db = Database(tmp_path / "orchestrator.sqlite3")
    assert sqlite_db.conn.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0] == 0
    sqlite_db.close()


def test_mirror_analytics_mode_keeps_sqlite_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "mirror")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")

    db.insert_onedrive_log_entries(
        [
            {
                "id": "log-1",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-1",
                "tool_name": "OneDriveOdlParser",
                "source_csv": tmp_path / "odl.csv",
                "row_number": 1,
                "timestamp_utc": "2026-05-19T00:00:00Z",
                "event_type": "sync",
            }
        ]
    )
    db.close()

    assert duckdb.connect(str(tmp_path / "cases" / case_id / "analytics" / "events.duckdb")).execute(
        "SELECT event_type FROM onedrive_log_entries"
    ).fetchone() == ("sync",)
    sqlite_db = Database(tmp_path / "orchestrator.sqlite3")
    assert sqlite_db.conn.execute("SELECT COUNT(*) FROM onedrive_log_entries").fetchone()[0] == 1
    sqlite_db.close()
