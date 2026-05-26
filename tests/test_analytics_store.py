import fcntl
import multiprocessing
import time
from pathlib import Path

import duckdb

from forensic_orchestrator import analytics_query
from forensic_orchestrator.db import Database
from forensic_orchestrator.filesystem_review import rebuild_filesystem_review
from forensic_orchestrator.reports import image_analysis_report, rdp_cache_report, rdp_visual_observations_report
from forensic_orchestrator.tools.ingest import ingest_csv_output


def _insert_mft_row_worker(db_path: str, case_id: str, image_id: str, queue: multiprocessing.Queue) -> None:
    try:
        db = Database(Path(db_path), migrate=False)
        db.insert_normalized_artifact_rows(
            "mft_entries",
            [
                {
                    "id": "mft-worker",
                    "case_id": case_id,
                    "computer_id": "computer-1",
                    "image_id": image_id,
                    "tool_output_id": "output-1",
                    "tool_name": "MFTECmd",
                    "source_csv": "mft.csv",
                    "row_number": 1,
                    "file_name": "$MFT",
                }
            ],
        )
        db.close()
        queue.put("ok")
    except Exception as exc:  # pragma: no cover - reported through parent assertion
        queue.put(f"error: {exc}")


def sqlite_table_exists(db: Database, table: str) -> bool:
    return db.conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone() is not None


def test_duckdb_analytics_mode_is_default(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    assert db.analytics_mode == "duckdb"
    db.close()


def test_duckdb_write_connections_apply_temp_settings(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    temp_dir = tmp_path / "duck-temp"
    monkeypatch.setenv("FORENSIC_DUCKDB_TEMP_DIRECTORY", str(temp_dir))
    monkeypatch.setenv("FORENSIC_DUCKDB_MAX_TEMP_DIRECTORY_SIZE", "12GB")
    monkeypatch.setenv("FORENSIC_DUCKDB_MEMORY_LIMIT", "1GB")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case_id = "case-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)

    assert db.analytics is not None
    with db.analytics._write_connection(case_id) as conn:
        assert conn.execute("SELECT current_setting('temp_directory')").fetchone()[0] == str(temp_dir)
        assert conn.execute("SELECT current_setting('max_temp_directory_size')").fetchone()[0] == "11.1 GiB"
        assert conn.execute("SELECT current_setting('memory_limit')").fetchone()[0] == "953.6 MiB"
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
    assert not sqlite_table_exists(sqlite_db, "mft_entries")
    sqlite_db.close()


def test_duckdb_analytics_writes_wait_for_case_lock(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db_path = tmp_path / "orchestrator.sqlite3"
    db = Database(db_path)
    case_id = "case-1"
    image_id = "image-1"
    db.create_case(case_id, tmp_path / "cases" / case_id)
    db.create_computer(computer_id="computer-1", case_id=case_id, label="ROCBA")
    db.add_image(image_id, case_id, tmp_path / "image.e01", computer_id="computer-1")
    db.close()

    duckdb_path = tmp_path / "cases" / case_id / "analytics" / "events.duckdb"
    lock_path = duckdb_path.with_suffix(duckdb_path.suffix + ".write.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    context = multiprocessing.get_context("spawn")
    queue: multiprocessing.Queue = context.Queue()
    with lock_path.open("w") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        worker = context.Process(
            target=_insert_mft_row_worker,
            args=(str(db_path), case_id, image_id, queue),
        )
        worker.start()
        time.sleep(0.5)
        assert queue.empty()
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    worker.join(10)
    assert worker.exitcode == 0
    assert queue.get(timeout=1) == "ok"

    duck = duckdb.connect(str(duckdb_path), read_only=True)
    try:
        assert duck.execute("SELECT file_name FROM mft_entries").fetchone() == ("$MFT",)
    finally:
        duck.close()


def test_duckdb_read_only_connection_retries_transient_lock(tmp_path, monkeypatch):
    db_path = tmp_path / "events.duckdb"
    real_connect = duckdb.connect
    real_connect(str(db_path)).close()
    attempts = {"count": 0}

    def flaky_connect(path, read_only=False):
        if read_only:
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise duckdb.IOException("transient lock")
        return real_connect(path, read_only=read_only)

    monkeypatch.setenv("FORENSIC_DUCKDB_READ_LOCK_TIMEOUT", "2")
    monkeypatch.setattr("forensic_orchestrator.analytics_query.duckdb.connect", flaky_connect)

    conn = analytics_query._connect_duckdb_read_only(db_path)
    try:
        assert attempts["count"] == 2
    finally:
        conn.close()


def test_default_duckdb_can_drop_empty_sqlite_analytics_tables(tmp_path, monkeypatch):
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

    assert not sqlite_table_exists(db, "mft_entries")
    result = db.cleanup_empty_sqlite_analytics_tables()

    assert "mft_entries" not in result["skipped_non_empty"]
    assert db.conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mft_entries'"
    ).fetchone() is None
    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                "id": "mft-2",
                "case_id": case_id,
                "computer_id": "computer-1",
                "image_id": image_id,
                "tool_output_id": "output-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 2,
                "file_name": "$MFTMirr",
            }
        ],
    )
    db.close()

    duck = duckdb.connect(str(tmp_path / "cases" / case_id / "analytics" / "events.duckdb"))
    assert duck.execute("SELECT file_name FROM mft_entries ORDER BY row_number").fetchall() == [
        ("$MFT",),
        ("$MFTMirr",),
    ]
    duck.close()


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
    assert not sqlite_table_exists(sqlite_db, "shortcut_items")
    assert not sqlite_table_exists(sqlite_db, "prefetch_items")
    assert not sqlite_table_exists(sqlite_db, "registry_artifacts")
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
    assert not sqlite_table_exists(sqlite_db, "mft_entries")
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

    assert not sqlite_table_exists(db, "rdp_cache_items")
    assert not sqlite_table_exists(db, "image_analysis_items")
    assert not sqlite_table_exists(db, "rdp_visual_observations")
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
    assert rebuild_filesystem_review(db, case_id=case_id, image_id=image_id) == 0
    assert not sqlite_table_exists(db, "filesystem_review")
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
    assert not sqlite_table_exists(sqlite_db, "evtx_events")
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
