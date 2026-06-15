from pathlib import Path
import hashlib
import zipfile

from forensic_orchestrator import standalone as standalone_module
import forensic_orchestrator.cli as cli_module
from forensic_orchestrator.config import load_config
from forensic_orchestrator.cli import main as cli_main, standalone_smoke_regression_report
from forensic_orchestrator.db import Database
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.standalone import (
    artifact_capability_report,
    backup_case_databases,
    benchmark_report,
    create_sample_report_bundle_fixture,
    doctor_report,
    _extract_eztools_urls,
    _extract_archive,
    _normalized_sha1,
    _sha1_file,
    _parse_rustc_version,
    install_third_party_tool,
    job_status_report,
    profile_catalog_report,
    repair_dependencies,
    schema_status_report,
    standalone_backlog_report,
    tool_status_report,
    version_report,
)
from forensic_orchestrator.tools.registry import ToolRegistry


def test_config_file_supplies_root_and_plugins(tmp_path):
    plugin = tmp_path / "plugin.yaml"
    plugin.write_text("tools: {}\nprofiles: {}\n", encoding="utf-8")
    config = tmp_path / "config.yaml"
    tools_root = tmp_path / "tools"
    eztools_root = tools_root / "eztools"
    config.write_text(
        f"root: {tmp_path / 'workspace'}\ntools_root: {tools_root}\neztools_root: {eztools_root}\nplugins:\n  - {plugin}\n",
        encoding="utf-8",
    )

    loaded = load_config(config_path=str(config))

    assert loaded.root == tmp_path / "workspace"
    assert loaded.plugin_paths == [plugin]
    assert loaded.tools_root == tools_root
    assert loaded.eztools_root == eztools_root


def test_standalone_doctor_reports_unwritable_default_root_without_crashing(tmp_path, monkeypatch, capsys):
    blocked_root = tmp_path / "blocked-root"
    blocked_db_path = blocked_root / "orchestrator.sqlite3"
    real_database = cli_module.Database

    def database_factory(path, *args, **kwargs):
        if Path(path) == blocked_db_path:
            raise PermissionError("blocked root")
        return real_database(path, *args, **kwargs)

    monkeypatch.setattr(cli_module, "Database", database_factory)

    status = cli_main(["--root", str(blocked_root), "standalone", "doctor", "--format", "table"])

    captured = capsys.readouterr()
    assert status == 1
    assert "Standalone doctor" in captured.out
    assert "workspace_root_exists" in captured.out
    assert "PermissionError" not in captured.err


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
    timing_id = db.start_process_timing(case_id=case.id, scope="test", phase="fixture", name="timed")
    db.finish_process_timing(timing_id, details={"fixture": True})
    registry = ToolRegistry.from_files([Path("forensic_orchestrator/plugins/eztools.yaml")])

    assert profile_catalog_report(registry)["summary"]["profile_count"] > 0
    assert version_report(paths.root, [])["application"] == "Perceptor"
    assert "perceptor" in version_report(paths.root, [])["cli_aliases"]
    assert "perceptor" in version_report(paths.root, [])["cli_aliases"]
    assert version_report(paths.root, [])["platform_support"]["supported_platform"] == "Ubuntu 24.04 LTS x86_64"
    assert artifact_capability_report(registry, profile="windows-full")["summary"]["artifact_count"] > 0
    assert schema_status_report(db)["schema_version"]["version"] >= 4
    assert job_status_report(db, case_id=case.id)["summary"]["completed"] == 1
    doctor = doctor_report(db, paths, registry, smoke=True)
    assert doctor["summary"]["check_count"] >= 8
    assert any(row["name"] == "platform_supported" for row in doctor["checks"])
    assert doctor["smoke"]["passed"] is True
    backup = backup_case_databases(db, paths, case_id=case.id, output_dir=tmp_path / "backups")
    assert Path(backup["manifest"]).exists()
    benchmark = benchmark_report(db, case_id=case.id)
    baseline_path = tmp_path / "benchmark.json"
    baseline_path.write_text('{"summary":{"returned_duration_seconds":0}}', encoding="utf-8")
    compared = benchmark_report(db, case_id=case.id, baseline_path=baseline_path)
    assert benchmark["summary"]["timing_count_returned"] == 1
    assert compared["baseline"]["status"] == "compared"
    fixture = create_sample_report_bundle_fixture(tmp_path / "sample.zip")
    assert Path(fixture["path"]).exists()
    assert fixture["computer_count"] == 2
    assert standalone_backlog_report()["summary"]["item_count"] == 28
    smoke_regression = standalone_smoke_regression_report(registry, [Path("forensic_orchestrator/plugins/eztools.yaml")])
    assert smoke_regression["passed"] is True
    assert {row["name"] for row in smoke_regression["checks"]} >= {"sample_fixture_imported", "report_bundle_written", "mcp_tool_listing"}


def test_repair_dependencies_writes_local_tool_env(monkeypatch, tmp_path):
    tools = tmp_path / "tools"
    bstrings = tools / "bstrings" / "bstrings.dll"
    sidr = tools / "sidr" / "sidr"
    memprocfs = tools / "MemProcFS" / "memprocfs"
    for path in (bstrings, sidr, memprocfs):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("tool", encoding="utf-8")
    for key in ("BSTRINGS_BIN", "SIDR_BIN", "MEMPROCFS_BIN"):
        monkeypatch.delenv(key, raising=False)

    report = repair_dependencies(tools_dir=tools, env_file=tmp_path / "tools.env", include_default_coverage=False)

    env_text = (tmp_path / "tools.env").read_text(encoding="utf-8")
    assert report["applied"] is True
    assert "BSTRINGS_BIN" in env_text
    assert "SIDR_BIN" in env_text
    assert "sidr/sidr" in env_text
    assert "MEMPROCFS_BIN" in env_text
    for key in ("BSTRINGS_BIN", "SIDR_BIN", "MEMPROCFS_BIN", "EZTOOLS_ROOT"):
        standalone_module.os.environ.pop(key, None)


def test_tool_status_and_install_dry_run_use_managed_tools_dir(tmp_path):
    report = tool_status_report(tools_dir=tmp_path / "managed")
    sidr = next(row for row in report["tools"] if row["tool"] == "sidr")
    ual_timeliner = next(row for row in report["tools"] if row["tool"] == "ual-timeliner")
    dry_run = install_third_party_tool("dotnet", tools_dir=tmp_path / "managed", apply=False)
    sidr_dry_run = install_third_party_tool("sidr", tools_dir=tmp_path / "managed", apply=False, force=True)
    ual_dry_run = install_third_party_tool("ual", tools_dir=tmp_path / "managed", apply=False)
    bitlocker_dry_run = install_third_party_tool("bdemount", tools_dir=tmp_path / "managed", apply=False)
    all_dry_run = install_third_party_tool("all", tools_dir=tmp_path / "managed", apply=False)

    assert sidr["managed_path"].endswith("managed/sidr/sidr")
    assert ual_timeliner["installable"] is True
    assert dry_run["tools"][0]["status"] == "would_download_and_run"
    assert sidr_dry_run["tools"][0]["status"] == "would_build_from_source"
    assert sidr_dry_run["tools"][0]["repo"] == "https://github.com/strozfriedberg/sidr.git"
    assert ual_dry_run["tools"][0]["status"] == "would_run"
    assert "kev365/ual-timeliner" in " ".join(ual_dry_run["tools"][0]["command"])
    assert bitlocker_dry_run["tools"][0]["command"][-3:] == ["install", "-y", "libbde-utils"]
    assert {"dislocker", "bdemount"}.issubset({row["tool"] for row in all_dry_run["tools"]})


def test_install_tool_reports_progress(tmp_path):
    messages = []

    report = install_third_party_tool("ual", tools_dir=tmp_path / "managed", apply=False, progress=messages.append)

    assert report["status"] == "completed"
    assert any("starting ual-timeliner" in message for message in messages)
    assert any("finished ual-timeliner: would_run" in message for message in messages)
    assert messages[-1] == "install pass complete"


def test_sidr_install_reports_manual_without_build_tools(monkeypatch, tmp_path):
    monkeypatch.setattr(standalone_module.shutil, "which", lambda name: None)

    report = install_third_party_tool("sidr", tools_dir=tmp_path / "managed", apply=True, force=True)

    assert report["tools"][0]["status"] == "manual"
    assert "cargo" in report["tools"][0]["reason"]


def test_usnjrnl_install_reports_old_rustc(monkeypatch, tmp_path):
    monkeypatch.setattr(standalone_module.shutil, "which", lambda name: f"/usr/bin/{name}" if name in {"cargo", "rustc"} else None)

    def fake_run(command, capture_output=None, text=None, check=None, timeout=None):
        return standalone_module.subprocess.CompletedProcess(command, 0, stdout="rustc 1.87.0 (abc 2025-01-01)\n", stderr="")

    monkeypatch.setattr(standalone_module.subprocess, "run", fake_run)

    report = install_third_party_tool("usnjrnl-forensic", tools_dir=tmp_path / "managed", apply=True, force=True)

    assert report["tools"][0]["status"] == "missing_installer"
    assert "requires rustc 1.88.0 or newer" in report["tools"][0]["reason"]


def test_parse_rustc_version():
    assert _parse_rustc_version("rustc 1.95.0 (59807616e 2026-04-14)") == (1, 95, 0)
    assert _parse_rustc_version("not rust") is None


def test_eztools_catalog_url_parser_filters_net9():
    html = """
    https://f001.backblazeb2.com/file/EricZimmermanTools/AmcacheParser.zip
    https://f001.backblazeb2.com/file/EricZimmermanTools/net9/AmcacheParser_6.zip
    https://download.ericzimmermanstools.com/net9/bstrings.zip
    https://download.ericzimmermanstools.com/All_9.zip
    https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip
    """

    urls = _extract_eztools_urls(html, net_version=9)

    assert urls == [
        "https://download.ericzimmermanstools.com/net9/AmcacheParser_6.zip",
        "https://download.ericzimmermanstools.com/net9/bstrings.zip",
    ]


def test_managed_tool_archive_extract_rejects_traversal(tmp_path):
    archive = tmp_path / "tool.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../outside.txt", "bad")

    try:
        _extract_archive(archive, tmp_path / "tools")
    except ValueError as exc:
        assert "Unsafe archive member path" in str(exc)
    else:
        raise AssertionError("unsafe archive member was accepted")


def test_sha1_helpers_normalize_and_hash(tmp_path):
    payload = tmp_path / "payload.zip"
    payload.write_bytes(b"payload")
    expected = hashlib.sha1(b"payload").hexdigest()

    assert _normalized_sha1(f'"{expected}"') == expected
    assert _sha1_file(payload) == expected
