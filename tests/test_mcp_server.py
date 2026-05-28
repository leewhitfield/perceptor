from __future__ import annotations

import json
import sys
import time
import zipfile
from io import StringIO

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
    assert "relic_list_mcp_jobs" in names
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
