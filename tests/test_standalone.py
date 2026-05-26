from pathlib import Path

from forensic_orchestrator.config import load_config
from forensic_orchestrator.db import Database
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.standalone import (
    artifact_capability_report,
    backup_case_databases,
    doctor_report,
    job_status_report,
    profile_catalog_report,
    schema_status_report,
    standalone_backlog_report,
)
from forensic_orchestrator.tools.registry import ToolRegistry


def test_config_file_supplies_root_and_plugins(tmp_path):
    plugin = tmp_path / "plugin.yaml"
    plugin.write_text("tools: {}\nprofiles: {}\n", encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(f"root: {tmp_path / 'workspace'}\nplugins:\n  - {plugin}\n", encoding="utf-8")

    loaded = load_config(config_path=str(config))

    assert loaded.root == tmp_path / "workspace"
    assert loaded.plugin_paths == [plugin]


def test_standalone_reports_cover_profiles_schema_jobs_and_backups(tmp_path):
    db_path = tmp_path / "orchestrator.sqlite3"
    db = Database(db_path)
    paths = WorkspacePaths(tmp_path)
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.create_job(
        {
            "id": "job-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_name": "ExampleTool",
            "command": ["example"],
            "start_time": "2026-05-26T00:00:00+00:00",
            "end_time": "2026-05-26T00:00:01+00:00",
            "exit_code": 0,
            "stdout_path": tmp_path / "stdout.txt",
            "stderr_path": tmp_path / "stderr.txt",
            "output_folder": tmp_path / "out",
        }
    )
    registry = ToolRegistry.from_files([Path("forensic_orchestrator/plugins/eztools.yaml")])

    assert profile_catalog_report(registry)["summary"]["profile_count"] > 0
    assert artifact_capability_report(registry, profile="windows-full")["summary"]["artifact_count"] > 0
    assert schema_status_report(db)["schema_version"]["version"] >= 4
    assert job_status_report(db, case_id=case.id)["summary"]["completed"] == 1
    assert doctor_report(db, paths, registry)["summary"]["check_count"] >= 7
    backup = backup_case_databases(db, paths, case_id=case.id, output_dir=tmp_path / "backups")
    assert Path(backup["manifest"]).exists()
    assert standalone_backlog_report()["summary"]["item_count"] == 28
