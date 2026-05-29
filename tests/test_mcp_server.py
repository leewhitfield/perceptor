from __future__ import annotations

import json
import sys
import time
import zipfile
from io import StringIO
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.mcp_server import RelicMcpServer, run_mcp_server


def test_mcp_initialize_and_list_tools(tmp_path):
    server = RelicMcpServer(root=tmp_path)

    initialized = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        }
    )
    assert initialized["result"]["protocolVersion"] == "2025-03-26"
    assert initialized["result"]["capabilities"]["tools"]["listChanged"] is False

    listed = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = listed["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert "relic_workspace_summary" in names
    assert "relic_case_summary" in names
    assert "relic_ingest_triage_zip_preflight" in names
    assert "relic_import_triage_zip" in names
    assert "relic_query_suspicious_executions" in names
    assert "relic_query_external_storage" in names
    assert "relic_case_review" in names
    assert "relic_case_evidence_map" in names
    assert "relic_workspace_map" in names
    assert "relic_mcp_workflow_guide" in names
    assert "relic_case_readiness" in names
    assert "relic_discover_reports" in names
    assert "relic_discover_report_exports" in names
    assert "relic_file_dossier" in names
    assert "relic_usb_dossier" in names
    assert "relic_user_activity" in names
    assert "relic_timeline_window" in names
    assert "relic_lead_search" in names
    assert "relic_case_activity_digest" in names
    assert "relic_case_next_actions" in names
    assert "relic_write_review_packet" in names
    assert "relic_search_artifacts" in names
    assert "relic_artifact_search_sources" in names
    assert "relic_list_review_packets" in names
    assert "relic_read_review_packet" in names
    assert "relic_write_search_packet" in names
    assert "relic_list_search_packets" in names
    assert "relic_read_search_packet" in names
    assert "relic_rerun_search_packet" in names
    assert "relic_list_progress_manifests" in names
    assert "relic_list_mcp_jobs" in names
    assert "relic_get_mcp_job_progress" in names
    assert "relic_mcp_tool_reference" in names
    assert any(tool["annotations"]["readOnlyHint"] is False for tool in tools)


def test_mcp_workspace_and_case_summary_tools(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path)
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="HOST01")
    db.add_image("image-1", case.id, tmp_path / "host.E01", computer_id=computer.id)
    db.close()

    server = RelicMcpServer(root=tmp_path)
    workspace = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "relic_workspace_summary", "arguments": {}},
        }
    )
    structured = workspace["result"]["structuredContent"]
    assert structured["db_exists"] is True
    assert structured["counts"]["cases"] == 1
    assert structured["counts"]["images"] == 1

    summary = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "relic_case_summary", "arguments": {"case_id": "case-1"}},
        }
    )
    case_summary = summary["result"]["structuredContent"]
    assert case_summary["counts"]["computers"] == 1
    assert case_summary["images"][0]["id"] == "image-1"

    evidence_map = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "relic_case_evidence_map", "arguments": {"case_id": "case-1"}},
        }
    )
    mapped = evidence_map["result"]["structuredContent"]
    assert mapped["summary"]["computer_count"] == 1
    assert mapped["images"][0]["computer_label"] == "HOST01"


def test_mcp_stdio_server_roundtrip(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    db.create_case("case-1", tmp_path)
    db.close()

    stdin = StringIO(
        "\n".join(
            [
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "relic_list_cases", "arguments": {"limit": 5}},
                    }
                ),
                "",
            ]
        )
    )
    stdout = StringIO()

    assert run_mcp_server(root=tmp_path, stdin=stdin, stdout=stdout) == 0
    responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [response["id"] for response in responses] == [1, 2]
    assert responses[1]["result"]["structuredContent"]["cases"][0]["id"] == "case-1"


def test_mcp_processing_tool_requires_opt_in(tmp_path):
    server = RelicMcpServer(root=tmp_path)

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "relic_import_triage_zip", "arguments": {"path": str(tmp_path / "case.zip")}},
        }
    )

    assert response["error"]["code"] == -32602
    assert "--allow-processing" in response["error"]["message"]


def test_mcp_triage_zip_preflight(tmp_path):
    zip_path = tmp_path / "case.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("HOST01/Registry.csv", "a,b\n1,2\n")
    server = RelicMcpServer(root=tmp_path)

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "relic_ingest_triage_zip_preflight", "arguments": {"path": str(zip_path)}},
        }
    )

    result = response["result"]["structuredContent"]
    assert result["summary"]["computer_count"] == 1
    assert result["computers"][0]["label"] == "HOST01"


def test_mcp_artifact_queries_and_case_review_are_structured(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    db.create_case("case-1", tmp_path)
    db.close()
    server = RelicMcpServer(root=tmp_path)

    suspicious = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "relic_query_suspicious_executions", "arguments": {"case_id": "case-1"}},
        }
    )
    assert suspicious["result"]["structuredContent"]["case_id"] == "case-1"

    review = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "relic_case_review", "arguments": {"case_id": "case-1", "limit": 5}},
        }
    )
    structured = review["result"]["structuredContent"]
    assert structured["case_id"] == "case-1"
    assert "dashboard" in structured
    assert "external_storage" in structured


def test_mcp_job_persists_and_output_can_be_read(tmp_path):
    server = RelicMcpServer(root=tmp_path)
    started = server._start_mcp_process("test", [sys.executable, "-c", "import json; print(json.dumps({'ok': True}))"])
    job_id = started["mcp_job_id"]

    for _ in range(50):
        status = server.get_mcp_job({"mcp_job_id": job_id})
        if status["status"] != "running":
            break
        time.sleep(0.05)

    reloaded = RelicMcpServer(root=tmp_path)
    persisted = reloaded.get_mcp_job({"mcp_job_id": job_id})
    assert persisted["mcp_job_id"] == job_id
    output = reloaded.get_mcp_job_output({"mcp_job_id": job_id})
    assert output["json"] == {"ok": True}
    listed = reloaded.list_mcp_jobs({})
    assert listed["jobs"][0]["mcp_job_id"] == job_id


def test_mcp_job_progress_parses_report_bundle_many_lines(tmp_path):
    server = RelicMcpServer(root=tmp_path)
    started = server._start_mcp_process(
        "progress",
        [
            sys.executable,
            "-c",
            "import sys; print('report-bundle-many progress computers_done=2 computers_total=3 imported_computers=2 rows=42 elapsed=1s', file=sys.stderr)",
        ],
    )
    job_id = started["mcp_job_id"]
    for _ in range(50):
        status = server.get_mcp_job({"mcp_job_id": job_id})
        if status["status"] != "running":
            break
        time.sleep(0.05)

    progress = server.get_mcp_job_progress({"mcp_job_id": job_id})

    assert progress["summary"]["computers_done"] == 2
    assert progress["summary"]["computer_count"] == 3
    assert progress["summary"]["rows"] == 42


def test_mcp_cancel_job_requires_processing_and_records_cancelled(tmp_path):
    server = RelicMcpServer(root=tmp_path, allow_processing=True)
    started = server._start_mcp_process("sleep", [sys.executable, "-c", "import time; time.sleep(30)"])

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "relic_cancel_mcp_job", "arguments": {"mcp_job_id": started["mcp_job_id"]}},
        }
    )

    result = response["result"]["structuredContent"]
    assert result["cancelled"] is True
    assert result["status"] == "cancelled"


def test_mcp_resources_list_and_read_workspace_reports(tmp_path):
    report = tmp_path / "cases" / "case-1" / "reports" / "summary.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Summary\n", encoding="utf-8")
    server = RelicMcpServer(root=tmp_path)

    listed = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {"case_id": "case-1", "kind": "report"}})
    resources = listed["result"]["resources"]
    uri = resources[0]["uri"]
    assert uri.startswith("relic://workspace/")

    read = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": uri}})
    assert read["result"]["contents"][0]["text"] == "# Summary\n"


def test_mcp_discover_reports_returns_resource_uris(tmp_path):
    report = tmp_path / "cases" / "case-1" / "reports" / "usb-bundle" / "opened-from-removable-media.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Opened\n", encoding="utf-8")
    (report.parent / "report-index.json").write_text(
        '{"purpose":"usb","reports":[{"name":"opened-from-removable-media","filename":"opened-from-removable-media.md","tags":["usb","review"]}]}',
        encoding="utf-8",
    )
    server = RelicMcpServer(root=tmp_path)

    discovered = server.discover_reports({"case_id": "case-1", "purpose": "usb"})
    exports = server.discover_report_exports({"case_id": "case-1", "purpose": "usb", "tags": ["usb"]})

    assert discovered["summary"]["resource_count"] >= 2
    assert any(item["uri"].startswith("relic://workspace/") for item in discovered["resources"])
    assert any(item["name"] == "opened-from-removable-media" for item in discovered["resources"])
    assert any(item["name"] == "opened-from-removable-media" for item in exports["resources"])


def test_mcp_write_review_packet_creates_resources(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.close()
    server = RelicMcpServer(root=tmp_path)

    packet = server.write_review_packet(
        {
            "case_id": "case-1",
            "title": "Lead Review",
            "notes": "Review this lead.",
            "findings": [{"title": "Finding"}],
            "report_uris": ["relic://workspace/cases/case-1/reports/index.md"],
        }
    )

    assert Path(packet["json_path"]).exists()
    assert Path(packet["markdown_path"]).exists()
    assert any(uri.endswith(".md") for uri in packet["resource_uris"])

    listed = server.list_review_packets({"case_id": "case-1"})
    assert listed["summary"]["packet_count"] == 1
    read = server.read_review_packet({"uri": listed["packets"][0]["json_uri"]})
    assert read["packet"]["title"] == "Lead Review"


def test_mcp_artifact_search_and_progress_manifests(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")
    db = Database(tmp_path / "orchestrator.sqlite3")
    db.create_case("case-1", tmp_path)
    computer = db.create_computer(computer_id="computer-1", case_id="case-1", label="HOST01")
    image = db.add_image("image-1", "case-1", tmp_path / "host.E01", computer_id=computer.id)
    db.conn.execute(
        """
        INSERT INTO shellbag_entries (
          id, case_id, computer_id, image_id, tool_output_id, tool_name, source_csv,
          row_number, user_profile, absolute_path, drive_letter, volume_serial_number,
          last_write_time, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "shellbag-1",
            "case-1",
            computer.id,
            image.id,
            "tool-1",
            "SBECmd",
            "shellbags.csv",
            1,
            "Users/Alice",
            "E:/Cases/powershell notes",
            "E:",
            "ABCD-1234",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
        ),
    )
    db.conn.commit()
    db.close()
    progress_dir = tmp_path / "progress"
    progress_dir.mkdir()
    (progress_dir / "report-bundle-many-test.json").write_text(
        json.dumps({"stage": "completed", "case_id": "case-1", "computers_total": 2, "computers_done": 2, "imported_rows": 42}),
        encoding="utf-8",
    )
    server = RelicMcpServer(root=tmp_path)

    found = server.search_artifacts({"case_id": "case-1", "query": "powershell", "computer": "HOST01"})
    assert found["summary"]["result_count"] == 1
    assert found["results"][0]["computer_label"] == "HOST01"
    assert found["results"][0]["matched_fields"] == ["absolute_path"]
    assert found["results"][0]["drilldown"]["tool"] == "relic_file_dossier"
    assert found["results"][0]["score"] > 0

    manifests = server.list_progress_manifests({})
    assert manifests["summary"]["manifest_count"] == 1
    assert manifests["manifests"][0]["imported_rows"] == 42

    lead = server.lead_search({"case_id": "case-1", "preset": "usb", "query": "powershell"})
    assert lead["summary"]["result_count"] == 1
    sources = server.artifact_search_sources({"case_id": "case-1"})
    shellbag_source = next(row for row in sources["sources"] if row["table"] == "shellbag_entries")
    assert shellbag_source["populated"] is True
    digest = server.case_activity_digest({"case_id": "case-1"})
    assert digest["case_id"] == "case-1"
    packet = server.write_search_packet({"case_id": "case-1", "preset": "usb", "query": "powershell", "title": "USB lead"})
    listed = server.list_search_packets({"case_id": "case-1"})
    read = server.read_search_packet({"uri": listed["packets"][0]["json_uri"]})
    rerun = server.rerun_search_packet({"uri": listed["packets"][0]["json_uri"]})
    exports = server.discover_report_exports({"case_id": "case-1", "purpose": "triage", "tags": ["packet"]})
    workspace = server.workspace_map({"case_id": "case-1"})
    guide = server.mcp_workflow_guide({})
    assert Path(packet["json_path"]).exists()
    assert listed["summary"]["packet_count"] == 1
    assert read["packet"]["title"] == "USB lead"
    assert rerun["comparison"]["unchanged_count"] == 1
    assert rerun["comparison"]["changed_count"] == 0
    assert any(row["kind"] == "packet" for row in exports["resources"])
    assert workspace["summary"]["case_count"] == 1
    assert guide["summary"]["step_count"] >= 8


def test_mcp_tool_reference_and_audit_log(tmp_path):
    server = RelicMcpServer(root=tmp_path)
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "relic_mcp_tool_reference", "arguments": {}},
        }
    )

    tools = response["result"]["structuredContent"]["tools"]
    assert any(tool["name"] == "relic_process_image" and tool["permission"] == "processing" for tool in tools)
    audit = tmp_path / "mcp-jobs" / "audit.jsonl"
    assert audit.exists()
    row = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert row["tool"] == "relic_mcp_tool_reference"


def test_mcp_process_image_dry_run_command(tmp_path):
    server = RelicMcpServer(root=tmp_path, allow_processing=True)
    captured = {}

    def fake_start(name, command):
        captured["name"] = name
        captured["command"] = command
        return {"mcp_job_id": "job-1", "name": name, "command": command}

    server._start_mcp_process = fake_start
    started = server.process_image({"path": str(tmp_path / "disk.E01"), "dry_run": True, "profile": "windows-basic"})

    assert "--dry-run" in started["command"]
    assert captured["name"] == "process_image"
