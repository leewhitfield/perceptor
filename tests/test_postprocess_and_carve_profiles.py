import json
import sqlite3
from pathlib import Path

from forensic_orchestrator.cli import main as cli_main
from forensic_orchestrator.db import Database
from forensic_orchestrator.paths import WorkspacePaths


def test_rebuild_postprocess_cli_runs_empty_case(tmp_path, capsys):
    paths = WorkspacePaths(tmp_path / "workspace")
    db = Database(paths.db_path())
    case = db.create_case("case-1", paths.case_dir("case-1"))
    db.close()

    status = cli_main(["--root", str(paths.root), "case", "rebuild-postprocess", case.id])

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["case_id"] == case.id
    assert "derived_sessions" in payload["steps"]
    assert any(item["step"] == "file_correlations" for item in payload["skipped"])


def test_carve_profile_preview_exposes_external_stage(tmp_path, capsys):
    paths = WorkspacePaths(tmp_path / "workspace")

    status = cli_main(["--root", str(paths.root), "tools", "profile-preview", "--profile", "windows-search-carve"])

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["extraction_policy"] == "carve"
    assert payload["carve_stage"] == "explicit_external"
    assert "SearchIndexer SQLite memory carves" in payload["carve_targets"]


def test_carve_profile_run_fails_with_staging_guidance(tmp_path, capsys):
    paths = WorkspacePaths(tmp_path / "workspace")
    db = Database(paths.db_path())
    case = db.create_case("case-1", paths.case_dir("case-1"))
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Laptop")
    image_path = tmp_path / "image.E01"
    image_path.write_text("not a real image", encoding="utf-8")
    image = db.add_image("image-1", case.id, image_path, computer_id=computer.id)
    db.close()

    status = cli_main(
        [
            "--root",
            str(paths.root),
            "run",
            "--case",
            case.id,
            "--image",
            image.id,
            "--profile",
            "windows-search-carve",
        ]
    )

    assert status == 1
    assert "Stage carved outputs separately" in capsys.readouterr().err


def test_sqlite_carve_command_stages_and_reports_carves(tmp_path, capsys):
    paths = WorkspacePaths(tmp_path / "workspace")
    db = Database(paths.db_path())
    case = db.create_case("case-1", paths.case_dir("case-1"))
    db.close()
    sqlite_path = tmp_path / "places.sqlite"
    conn = sqlite3.connect(sqlite_path)
    conn.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, hidden INTEGER, frecency INTEGER)")
    conn.execute("CREATE TABLE moz_historyvisits (place_id INTEGER, visit_date INTEGER, visit_type INTEGER)")
    conn.execute("INSERT INTO moz_places VALUES (1, 'https://example.test/', 'Example', 1, 0, 0, 10)")
    conn.execute("INSERT INTO moz_historyvisits VALUES (1, 1700000000000000, 1)")
    conn.commit()
    conn.close()

    status = cli_main(["--root", str(paths.root), "carve", "sqlite", "--case", case.id, "--path", str(sqlite_path), "--import-artifacts"])

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["staged_carves"] == 1
    assert payload["scan_ranges"] == 1
    assert payload["artifact_imported"]["tools"]["FirefoxParser"] == 1

    status = cli_main(["--root", str(paths.root), "report", "carve-coverage", "--case", case.id, "--format", "json"])

    assert status == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["carve_count"] == 1
    assert report["summary"]["scan_range_count"] == 1
    assert report["carves"][0]["detected_format"] == "sqlite"
    assert report["carves"][0]["parser_status"] in {"parsed", "schema_only"}

    status = cli_main(["--root", str(paths.root), "report", "sqlite-inventory", "--case", case.id, "--format", "json"])

    assert status == 0
    inventory = json.loads(capsys.readouterr().out)
    assert inventory["summary"]["sqlite_carves"] == 1
    assert inventory["inventories"][0]["tables"][0]["name"] == "moz_historyvisits"

    status = cli_main(["--root", str(paths.root), "report", "timeline", "--case", case.id])

    assert status == 0
    timeline = json.loads(capsys.readouterr().out)
    assert any(event["event_type"] == "database_carve_validated" for event in timeline["events"])


def test_ese_carve_command_stages_header_candidate(tmp_path, capsys):
    paths = WorkspacePaths(tmp_path / "workspace")
    db = Database(paths.db_path())
    case = db.create_case("case-1", paths.case_dir("case-1"))
    db.close()
    ese_path = tmp_path / "Windows.edb"
    ese_path.write_bytes(b"\x00\x00\x00\x00\xef\xcd\xab\x89" + b"\x00" * 4096)

    status = cli_main(["--root", str(paths.root), "carve", "ese", "--case", case.id, "--path", str(ese_path)])

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["staged_carves"] == 1
    assert payload["scan_ranges"] == 1

    status = cli_main(["--root", str(paths.root), "report", "carve-coverage", "--case", case.id, "--format", "json"])

    assert status == 0
    report = json.loads(capsys.readouterr().out)
    assert {"value": "ese", "count": 1} in report["summary"]["type_counts"]
    assert report["carves"][0]["detected_format"] == "ese"


def test_sqlite_carve_records_empty_chunk_scan_coverage(tmp_path, capsys):
    paths = WorkspacePaths(tmp_path / "workspace")
    db = Database(paths.db_path())
    case = db.create_case("case-1", paths.case_dir("case-1"))
    db.close()
    raw = tmp_path / "pagefile.sys"
    raw.write_bytes(b"A" * 4096 + b"B" * 4096)

    status = cli_main(
        [
            "--root",
            str(paths.root),
            "carve",
            "sqlite",
            "--case",
            case.id,
            "--path",
            str(raw),
            "--max-bytes",
            "8192",
            "--chunk-size",
            "4096",
        ]
    )

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["staged_carves"] == 0
    assert payload["scan_ranges"] == 2
    assert payload["scanned_bytes"] == 8192
    assert payload["next_start_offset"] == 8192

    status = cli_main(["--root", str(paths.root), "report", "carve-coverage", "--case", case.id, "--format", "json"])

    assert status == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["scan_range_count"] == 2
    assert report["summary"]["scanned_bytes"] == 8192
    assert report["summary"]["total_source_bytes"] == 8192


def test_sqlite_carve_start_offset_supports_resumable_scan(tmp_path, capsys):
    paths = WorkspacePaths(tmp_path / "workspace")
    db = Database(paths.db_path())
    case = db.create_case("case-1", paths.case_dir("case-1"))
    db.close()
    raw = tmp_path / "pagefile.sys"
    raw.write_bytes(b"A" * 4096 + b"B" * 4096)

    status = cli_main(
        [
            "--root",
            str(paths.root),
            "carve",
            "sqlite",
            "--case",
            case.id,
            "--path",
            str(raw),
            "--start-offset",
            "4096",
            "--max-bytes",
            "4096",
            "--chunk-size",
            "4096",
        ]
    )

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["scan_ranges"] == 1
    assert payload["scanned_bytes"] == 4096
    assert payload["next_start_offset"] == 8192

    status = cli_main(["--root", str(paths.root), "report", "carve-coverage", "--case", case.id, "--format", "json"])

    assert status == 0
    report = json.loads(capsys.readouterr().out)
    coverage = report["summary"]["source_coverage"][0]
    assert coverage["next_start_offset"] == ""
    assert coverage["coverage_percent"] == 50.0
