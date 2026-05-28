from __future__ import annotations

import json
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
