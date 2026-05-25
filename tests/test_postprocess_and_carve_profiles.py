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
    conn.execute("CREATE TABLE moz_places (url TEXT)")
    conn.execute("INSERT INTO moz_places VALUES ('https://example.test/')")
    conn.commit()
    conn.close()

    status = cli_main(["--root", str(paths.root), "carve", "sqlite", "--case", case.id, "--path", str(sqlite_path)])

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["staged_carves"] == 1

    status = cli_main(["--root", str(paths.root), "report", "carve-coverage", "--case", case.id, "--format", "json"])

    assert status == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["carve_count"] == 1
    assert report["carves"][0]["detected_format"] == "sqlite"
    assert report["carves"][0]["parser_status"] in {"parsed", "schema_only"}
