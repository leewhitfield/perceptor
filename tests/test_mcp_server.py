from __future__ import annotations

import json
import sys
import time
import zipfile
from io import StringIO
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.mcp_server import RelicMcpServer, _tool_result, run_mcp_server
from forensic_orchestrator.search.opensearch import OpenSearchRestClient


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
    assert "relic_query_wifi_activity" in names
    assert "relic_case_review" in names
    assert "relic_case_evidence_map" in names
    assert "relic_workspace_map" in names
    assert "relic_mcp_workflow_guide" in names
    assert "relic_route_question" in names
    assert "relic_case_readiness" in names
    assert "relic_discover_reports" in names
    assert "relic_discover_report_exports" in names
    assert "relic_read_existing_report" in names
    assert "relic_file_dossier" in names
    assert "relic_query_filesystem_listings" in names
    assert "relic_query_evidence_contents" in names
    assert "relic_query_usb_contents" in names
    assert "relic_usb_dossier" in names
    assert "relic_user_activity" in names
    assert "relic_query_system_users" in names
    assert "relic_timeline_window" in names
    assert "relic_activity_windows" in names
    assert "relic_lead_search" in names
    assert "relic_case_activity_digest" in names
    assert "relic_case_next_actions" in names
    assert "relic_case_runbook" in names
    assert "relic_write_review_packet" in names
    assert "relic_search_artifacts" in names
    assert "relic_artifact_search_sources" in names
    assert "relic_list_review_packets" in names
    assert "relic_read_review_packet" in names
    assert "relic_write_search_packet" in names
    assert "relic_list_search_packets" in names
    assert "relic_read_search_packet" in names
    assert "relic_rerun_search_packet" in names
    assert "relic_search_content" in names
    assert "relic_get_indexed_content" in names
    assert "relic_list_progress_manifests" in names
    assert "relic_list_mcp_jobs" in names
    assert "relic_get_mcp_job_progress" in names
    assert "relic_recover_deleted_files" in names
    assert "relic_mcp_tool_reference" in names
    assert any(tool["annotations"]["readOnlyHint"] is False for tool in tools)
    report_tool = next(tool for tool in tools if tool["name"] == "relic_read_existing_report")
    assert "first source of truth" in report_tool["description"]
    fs_tool = next(tool for tool in tools if tool["name"] == "relic_query_filesystem_listings")
    assert "first source of truth" in fs_tool["description"]
    contents_tool = next(tool for tool in tools if tool["name"] == "relic_query_evidence_contents")
    assert "stored filesystem_entries only" in contents_tool["description"]
    usb_contents_tool = next(tool for tool in tools if tool["name"] == "relic_query_usb_contents")
    assert "stored filesystem_entries" in usb_contents_tool["description"]
    assert "volume_name" in usb_contents_tool["inputSchema"]["properties"]
    usb_files_tool = next(tool for tool in tools if tool["name"] == "relic_query_usb_files")
    assert "volume name" in usb_files_tool["description"]
    assert "contains" in usb_files_tool["inputSchema"]["properties"]
    assert "volume_name" in usb_files_tool["inputSchema"]["properties"]
    wifi_tool = next(tool for tool in tools if tool["name"] == "relic_query_wifi_activity")
    assert wifi_tool["metadata"]["category"] == "network"
    assert "ssid" in wifi_tool["inputSchema"]["properties"]
    assert "connection_sessions" in wifi_tool["description"]
    assert "session_activity_plan" in wifi_tool["description"]
    user_activity_tool = next(tool for tool in tools if tool["name"] == "relic_user_activity")
    assert "not the source of truth for bounded activity-window questions" in user_activity_tool["description"]
    timeline_window_tool = next(tool for tool in tools if tool["name"] == "relic_timeline_window")
    assert "start" in timeline_window_tool["inputSchema"]["properties"]
    assert "end" in timeline_window_tool["inputSchema"]["properties"]
    assert "filter_within_window" in timeline_window_tool["inputSchema"]["properties"]
    assert "contains is only applied when filter_within_window is true" in timeline_window_tool["description"]
    activity_windows_tool = next(tool for tool in tools if tool["name"] == "relic_activity_windows")
    assert "multiple resolved time windows" in activity_windows_tool["description"]
    assert "windows" in activity_windows_tool["inputSchema"]["properties"]
    content_search_tool = next(tool for tool in tools if tool["name"] == "relic_search_content")
    assert "OpenSearch" in content_search_tool["description"]
    assert "password" not in content_search_tool["inputSchema"]["properties"]
    assert content_search_tool["metadata"]["category"] == "search"
    indexed_content_tool = next(tool for tool in tools if tool["name"] == "relic_get_indexed_content")
    assert "opensearch_document_id" in indexed_content_tool["inputSchema"]["properties"]
    assert "password" not in indexed_content_tool["inputSchema"]["properties"]
    route_tool = next(tool for tool in tools if tool["name"] == "relic_route_question")
    assert "source-of-truth order" in route_tool["description"]
    process_tool = next(tool for tool in tools if tool["name"] == "relic_process_image")
    assert process_tool["metadata"]["version"] == "1.0"
    assert "relic CLI" in process_tool["metadata"]["dependencies"]
    assert process_tool["metadata"]["examples"]
    assert process_tool["metadata"]["category"] == "processing"
    assert process_tool["metadata"]["error_handling"]["error_shape"]["retryable"] == "boolean"


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


def test_mcp_timeline_window_uses_master_timeline_for_time_bounds(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_name": "TestTool",
            "output_type": "csv",
            "path": tmp_path / "source.csv",
            "row_count": 1,
        }
    )
    db.insert_timeline_events(
        [
            {
                "id": "timeline-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "source_tool": "TestTool",
                "source_table": "test_rows",
                "source_row_id": "row-1",
                "event_type": "long_activity",
                "raw_timestamp": "2025-11-17T13:00:00Z",
                "timestamp_utc": "2025-11-17T13:00:00Z",
                "end_timestamp_utc": "2025-11-17T13:20:00Z",
                "duration_ms": 1_200_000,
                "description": "Long activity",
                "details": {},
            },
            {
                "id": "timeline-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "source_tool": "BrowserParser",
                "source_table": "browser_history",
                "source_row_id": "row-2",
                "event_type": "browser_history",
                "raw_timestamp": "2025-11-17T13:14:00Z",
                "timestamp_utc": "2025-11-17T13:14:00Z",
                "end_timestamp_utc": "",
                "duration_ms": None,
                "description": "YouTube watch page",
                "details": {},
            }
        ]
    )
    db.insert_filesystem_entries(
        [
            {
                "id": "fs-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "MountedFilesystemInventory",
                "source_csv": "filesystem_entries.csv",
                "row_number": 1,
                "partition_id": "partition-1",
                "filesystem_type": "fat32",
                "source_root": "/mnt/usb",
                "file_path": "The end.docx",
                "parent_path": "",
                "file_name": "The end.docx",
                "extension": ".docx",
                "file_size": "1234",
                "is_directory": "false",
                "created_utc": "2025-11-17T12:00:00Z",
                "modified_utc": "2025-11-17T13:14:30Z",
                "accessed_utc": "",
                "metadata_changed_utc": "",
                "mode": "",
                "uid": "",
                "gid": "",
                "scan_status": "live",
                "error": "",
                "created_at": "2026-05-30T00:00:00Z",
            }
        ]
    )
    db.close()

    server = RelicMcpServer(root=tmp_path)
    result = server.timeline_window(
        {
            "case_id": "case-1",
            "start": "2025-11-17T13:13:36Z",
            "end": "2025-11-17T13:15:00Z",
            "limit": 10,
            "contains": "Hyatt",
        }
    )

    assert result["source_of_truth"] == "normalized_master_timeline"
    assert result["ignored_contains"] == "Hyatt"
    assert result["events"][0]["event_type"] == "long_activity"
    assert result["window_summary"]["total_events"] == 2
    assert result["window_summary"]["notable_events"][0]["event_type"] == "browser_history"
    assert "Browser/web activity is present" in result["activity_answer"]["summary"]
    assert result["activity_answer"]["browser_examples"][0]["description"] == "YouTube watch page"
    assert result["browser_activity_count"] == 1
    assert result["browser_activity"][0]["description"] == "YouTube watch page"
    assert result["file_activity_count"] >= 1
    assert result["direct_activity_counts"]["file_activity"] >= 1
    filesystem_modified = result["direct_activity"]["sources"]["filesystem_modified"]["rows"]
    assert filesystem_modified[0]["file_name"] == "The end.docx"
    assert filesystem_modified[0]["modified_utc"] == "2025-11-17T13:14:30Z"

    filtered = server.timeline_window(
        {
            "case_id": "case-1",
            "start": "2025-11-17T13:13:36Z",
            "end": "2025-11-17T13:15:00Z",
            "limit": 10,
            "contains": "Hyatt",
            "filter_within_window": True,
        }
    )

    assert filtered["filter_within_window"] is True
    assert filtered["events"] == []


def test_mcp_tool_result_decodes_escaped_unicode_without_rewriting_paths():
    result = _tool_result(
        {
            "title": "\\ud83d\\udd34RARE Throwing Knives (LIVE Test) - YouTube",
            "path": "C:\\Users\\mayas\\Desktop",
        }
    )

    structured = result["structuredContent"]
    assert structured["title"] == "🔴RARE Throwing Knives (LIVE Test) - YouTube"
    assert structured["path"] == "C:\\Users\\mayas\\Desktop"
    assert "\\ud83d\\udd34" not in result["content"][0]["text"]


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


def test_mcp_usb_files_filters_existing_report_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path)
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, tmp_path / "desktop.E01", computer_id="computer-1")
    db.insert_usb_file_correlations(
        [
            {
                "id": "usb-corr-root",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_serial": "USB123",
                "usb_volume_serial_number": "",
                "usb_volume_name": "ANYVOL",
                "usb_drive_letter": "D:",
                "usb_vendor_id": "",
                "usb_product_id": "",
                "usb_vendor": "",
                "usb_product": "Example USB",
                "usb_friendly_name": "",
                "usb_first_install_date_utc": "",
                "usb_last_arrival_utc": "",
                "usb_last_removal_utc": "",
                "source_artifact_type": "lnk",
                "source_artifact_id": "lnk-root",
                "source_artifact_name": "ANYVOL (D).lnk",
                "source_artifact_path": "Users/example/Recent/ANYVOL (D).lnk",
                "user_profile": "example",
                "jumplist_item_number": "",
                "file_name": "D:",
                "file_location": "D:\\",
                "target_created": "",
                "target_modified": "",
                "target_accessed": "",
                "device_type": "removable",
                "artifact_volume_serial_number": "1122AABB",
                "artifact_volume_name": "ANYVOL",
                "artifact_volume_guid": "",
                "artifact_drive_letter": "D:",
                "volume_serial_match": "volume_name",
                "confidence": "medium",
            },
            {
                "id": "usb-corr-doc",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_serial": "USB123",
                "usb_volume_serial_number": "",
                "usb_volume_name": "ANYVOL",
                "usb_drive_letter": "D:",
                "usb_vendor_id": "",
                "usb_product_id": "",
                "usb_vendor": "",
                "usb_product": "Example USB",
                "usb_friendly_name": "",
                "usb_first_install_date_utc": "",
                "usb_last_arrival_utc": "",
                "usb_last_removal_utc": "",
                "source_artifact_type": "lnk",
                "source_artifact_id": "lnk-doc",
                "source_artifact_name": "Report.docx.lnk",
                "source_artifact_path": "Users/example/Recent/Report.docx.lnk",
                "user_profile": "example",
                "jumplist_item_number": "",
                "file_name": "Report.docx",
                "file_location": "D:\\Report.docx",
                "target_created": "2025-01-01T00:00:00Z",
                "target_modified": "2025-01-01T00:00:01Z",
                "target_accessed": "",
                "device_type": "removable",
                "artifact_volume_serial_number": "1122AABB",
                "artifact_volume_name": "ANYVOL",
                "artifact_volume_guid": "",
                "artifact_drive_letter": "D:",
                "volume_serial_match": "volume_name",
                "confidence": "medium",
            },
        ]
    )
    db.close()

    server = RelicMcpServer(root=tmp_path)
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "relic_query_usb_files",
                "arguments": {"case_id": case.id, "contains": "ANYVOL", "volume_name": "ANYVOL"},
            },
        }
    )

    structured = response["result"]["structuredContent"]
    assert structured["source_of_truth"] == "usb_file_correlations"
    assert structured["total_returned"] == 1
    assert structured["items"][0]["file_name"] == "Report.docx"
    assert structured["items"][0]["artifact_volume_serial_number"] == "1122AABB"


def test_mcp_usb_contents_resolves_volume_label_to_filesystem_listing(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path)
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "usb.E01", computer_id=computer.id)

    def fs_row(row_id: str, path: str, name: str, status: str, size: int | None = None) -> dict[str, object]:
        return {
            "id": row_id,
            "case_id": case.id,
            "computer_id": computer.id,
            "image_id": image.id,
            "tool_output_id": "tool-1",
            "tool_name": "MountedFilesystemInventory",
            "source_csv": "filesystem_entries.csv",
            "row_number": int(row_id.rsplit("-", 1)[-1]),
            "partition_id": "part-1",
            "filesystem_type": "fat32",
            "source_root": "/mnt/usb",
            "file_path": path,
            "parent_path": "",
            "file_name": name,
            "extension": Path(name).suffix,
            "file_size": size,
            "is_directory": "false",
            "created_utc": "2025-11-17T15:47:02Z",
            "modified_utc": "2025-11-17T15:47:04Z",
            "accessed_utc": None,
            "metadata_changed_utc": None,
            "mode": None,
            "uid": None,
            "gid": None,
            "scan_status": status,
            "error": "",
            "created_at": "2026-05-30T00:00:00Z",
        }

    db.insert_filesystem_entries(
        [
            fs_row("fs-1", "BYEBYE      (Volume Label Entry)", "BYEBYE      (Volume Label Entry)", "system", None),
            fs_row("fs-2", "The end.docx", "The end.docx", "live", 0),
            fs_row("fs-3", "Alex.docx", "Alex.docx", "deleted", 31055),
        ]
    )
    db.close()

    server = RelicMcpServer(root=tmp_path)
    result = server.query_usb_contents({"case_id": case.id, "volume_name": "BYEBYE"})

    assert result["source_of_truth"] == "filesystem_entries_and_usb_file_correlations"
    assert result["filters"]["resolved_image_ids"] == ["image-1"]
    assert result["summary"]["listing_available"] is True
    assert result["summary"]["filesystem_status_counts"] == {"live": 1, "deleted": 1}
    assert {row["file_name"] for row in result["filesystem_entries"]} == {"The end.docx", "Alex.docx"}

    with_system = server.query_usb_contents({"case_id": case.id, "volume_name": "BYEBYE", "include_system": True})
    assert "BYEBYE      (Volume Label Entry)" in [row["file_name"] for row in with_system["filesystem_entries"]]


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
    read_existing = server.read_existing_report(
        {"case_id": "case-1", "purpose": "usb", "report_name": "opened-from-removable-media"}
    )
    assert read_existing["source_of_truth"] == "existing_reports"
    assert read_existing["matched"] is True
    assert read_existing["selected_report"]["name"] == "opened-from-removable-media"
    assert read_existing["content"]["text"] == "# Opened\n"


def test_mcp_generate_report_prefers_existing_report(tmp_path):
    report = tmp_path / "cases" / "case-1" / "reports" / "usb-bundle" / "usb-files.md"
    report.parent.mkdir(parents=True)
    report.write_text("# Existing USB Files\n", encoding="utf-8")
    (report.parent / "report-index.json").write_text(
        '{"purpose":"usb","reports":[{"name":"usb-files","filename":"usb-files.md","tags":["usb"]}]}',
        encoding="utf-8",
    )
    db = Database(tmp_path / "orchestrator.sqlite3")
    db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.close()
    server = RelicMcpServer(root=tmp_path)

    generated = server.generate_report({"case_id": "case-1", "report_name": "usb-files"})

    assert generated["status"] == "existing_report_returned"
    assert generated["regenerated"] is False
    assert generated["content"]["text"] == "# Existing USB Files\n"


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
    runbook = server.case_runbook({"case_id": "case-1"})
    assert digest["case_id"] == "case-1"
    assert any("review-status" in row["command"] for row in runbook["commands"])
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
    assert read["packet"]["metadata"]["result_count"] == 1
    assert read["packet"]["metadata"]["result_hash_algorithm"] == "sha256"
    assert rerun["comparison"]["unchanged_count"] == 1
    assert rerun["comparison"]["changed_count"] == 0
    assert any(row["kind"] == "packet" for row in exports["resources"])
    assert workspace["summary"]["case_count"] == 1
    assert guide["summary"]["step_count"] >= 8
    assert any(step["tool"] == "relic_artifact_search_sources" for step in guide["steps"])
    assert guide["route_first_tool"] == "relic_route_question"
    assert guide["reports_first_tool"] == "relic_read_existing_report"
    assert guide["evidence_contents_first_tool"] == "relic_query_evidence_contents"
    assert guide["filesystem_first_tool"] == "relic_query_filesystem_listings"
    assert guide["wifi_activity_tool"] == "relic_query_wifi_activity"
    assert guide["content_search_tool"] == "relic_search_content"


def test_mcp_route_question_enforces_truth_order(tmp_path):
    server = RelicMcpServer(root=tmp_path)

    contents = server.route_question({"case_id": "case-1", "question": "Can you pull a list of contents for the USB drive?"})
    assert contents["intent"] == "evidence_contents"
    assert contents["first_source"] == "generated_usb_filesystem_listings"
    assert contents["recommended_tool"] == "relic_query_usb_contents"
    assert contents["source_order"][0]["tools"] == ["relic_query_usb_contents"]
    assert contents["processing_allowed"] is False

    usb_else = server.route_question({"case_id": "case-1", "question": "What else was on the USB drive?"})
    assert usb_else["intent"] == "evidence_contents"
    assert usb_else["recommended_tool"] == "relic_query_usb_contents"
    assert usb_else["source_order"][0]["source"] == "generated_usb_filesystem_listings"

    suspicious = server.route_question({"case_id": "case-1", "question": "Show me suspicious executables"})
    assert suspicious["intent"] == "execution"
    assert suspicious["first_source"] == "existing_reports"
    assert suspicious["recommended_tool"] == "relic_read_existing_report"
    assert "suspicious-executions" in suspicious["report_names"]
    assert "relic_query_suspicious_executions" in suspicious["fallback_tools"]

    content = server.route_question({"case_id": "case-1", "question": "Search file contents for confidential notes"})
    assert content["intent"] == "content_search"
    assert content["recommended_tool"] == "relic_search_content"
    assert content["source_order"][1]["source"] == "opensearch_content_index"

    file_info = server.route_question({"case_id": "case-1", "question": "What can you tell me about _WRD0001.tmp filesystem and internal metadata?"})
    assert file_info["intent"] == "file_information"
    assert file_info["recommended_tool"] == "relic_file_dossier"
    assert file_info["source_order"][0]["source"] == "file_dossier"

    file_content = server.route_question({"case_id": "case-1", "question": "What is the content of _WRD0001.tmp?"})
    assert file_content["intent"] == "file_content_and_information"
    assert file_content["recommended_tool"] == "relic_file_dossier"
    assert file_content["source_order"][2]["source"] == "opensearch_content_index"
    assert "do not stop at metadata" in file_content["reason"]
    assert file_content["source_order"][2]["followup"].startswith("If a hit is returned")

    wifi = server.route_question({"case_id": "case-1", "question": "Were wifi networks connected on November 17?"})
    assert wifi["intent"] == "wifi_network_activity"
    assert wifi["first_source"] == "parsed_network_artifact_tables"
    assert wifi["recommended_tool"] == "relic_query_wifi_activity"
    assert wifi["source_order"][0]["tools"] == ["relic_query_wifi_activity"]

    wifi_activity = server.route_question({"case_id": "case-1", "question": "What activity occurred while the computer was connected to Hyatt wifi?"})
    assert wifi_activity["intent"] == "wifi_network_activity"
    assert wifi_activity["recommended_tool"] == "relic_query_wifi_activity"
    assert wifi_activity["source_order"][1]["source"] == "normalized_master_timeline"
    assert wifi_activity["source_order"][1]["tools"] == ["relic_activity_windows", "relic_timeline_window"]
    assert "session_activity_plan.aggregate_tool" in wifi_activity["source_order"][1]["requires"]

    users = server.route_question({"case_id": "case-1", "question": "Who are the users on this computer and what are their SIDs?"})
    assert users["intent"] == "system_users"
    assert users["recommended_tool"] == "relic_query_system_users"
    assert users["source_order"][0]["source"] == "consolidated_user_inventory"

    recovery = server.route_question({"case_id": "case-1", "question": "Recover the deleted timeline.docx file"})
    assert recovery["intent"] == "deleted_file_recovery"
    assert recovery["recommended_tool"] == "relic_query_evidence_contents"
    assert recovery["processing_requested"] is True
    assert recovery["processing_allowed"] is False
    assert recovery["blocked_actions"][0]["action"] == "processing_or_recovery"

    recovery_allowed = RelicMcpServer(root=tmp_path, allow_processing=True).route_question(
        {
            "case_id": "case-1",
            "question": "Recover the deleted timeline.docx file",
            "allow_processing": True,
        }
    )
    assert recovery_allowed["processing_allowed"] is True
    assert "relic_recover_deleted_files" in recovery_allowed["fallback_tools"]

def test_mcp_search_content_wraps_opensearch_without_password_argument(tmp_path, monkeypatch):
    captured = {}

    def fake_search_case_content(**kwargs):
        captured.update(kwargs)
        return {
            "case_id": kwargs["case_id"],
            "index": kwargs["config"].index,
            "query": kwargs["query"],
            "synonym_expansions": ["confidential"],
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "score": 2.5,
                    "source_type": "indexed_file_content",
                    "source_table": "windows_search_indexed_content",
                    "storage_table": "windows_search_indexed_content",
                    "forensic_source_table": "user_file_content",
                    "evidence_nature": "direct_file_content_extraction",
                    "direct_file_content_extraction": True,
                    "windows_search_artifact_content": False,
                    "source_record_id": "wic-1",
                    "opensearch_document_id": "os-doc-1",
                    "computer_id": "computer-1",
                    "image_id": "image-1",
                    "content_hash": "abc",
                    "content_length": 123,
                    "highlight": {"content": ["...confidential notes..."]},
                }
            ],
            "total_returned": 1,
        }

    monkeypatch.setattr("forensic_orchestrator.mcp_server.search_case_content", fake_search_case_content)
    server = RelicMcpServer(root=tmp_path)

    result = server.search_content(
        {
            "case_id": "case-1",
            "query": "confidential",
            "url": "http://localhost:9200",
            "index": "case-content",
            "limit": 5,
            "no_synonyms": True,
        }
    )

    assert captured["case_id"] == "case-1"
    assert captured["query"] == "confidential"
    assert captured["limit"] == 5
    assert captured["synonym_groups"] == []
    assert captured["config"].url == "http://localhost:9200"
    assert captured["config"].index == "case-content"
    assert result["source_of_truth"] == "opensearch_content_index"
    assert "snippets only" in result["guidance"]
    assert result["hits"][0]["drilldown"]["source_table"] == "windows_search_indexed_content"
    assert result["hits"][0]["snippet_note"] == "OpenSearch highlight fields are matching snippets, not the full indexed content."
    assert result["hits"][0]["forensic_source_table"] == "user_file_content"
    assert result["hits"][0]["evidence_nature"] == "direct_file_content_extraction"
    assert "direct file-content extraction" in result["hits"][0]["provenance_summary"]
    assert result["hits"][0]["full_content_available"] is True
    assert result["hits"][0]["full_content_tool"]["tool"] == "relic_get_indexed_content"
    assert result["hits"][0]["full_content_tool"]["arguments"] == {
        "case_id": "case-1",
        "opensearch_document_id": "os-doc-1",
    }


def test_mcp_get_indexed_content_returns_full_opensearch_document(tmp_path, monkeypatch):
    captured = {}

    def fake_request(self, method, path, body=None):
        captured["method"] = method
        captured["path"] = path
        captured["body"] = body
        return {
            "_id": "os-doc-1",
            "found": True,
            "_source": {
                "case_id": "case-1",
                "title": "_WRD0001.tmp",
                "source_path": "/_WRD0001.tmp",
                "container_path": "",
                "source_type": "indexed_file_content",
                "source_table": "windows_search_indexed_content",
                "source_record_id": "wic-1",
                "computer_id": "computer-1",
                "image_id": "image-1",
                "timestamp": "2026-06-02T16:08:57Z",
                "user_profile": "",
                "content_hash": "abc",
                "content_length": 34,
                "content": "You did not have to be so pompous.",
                "metadata": {
                    "storage_table": "windows_search_indexed_content",
                    "forensic_source_table": "user_file_content",
                    "evidence_nature": "direct_file_content_extraction",
                },
            },
        }

    monkeypatch.setattr(OpenSearchRestClient, "request", fake_request)
    server = RelicMcpServer(root=tmp_path)

    result = server.get_indexed_content(
        {
            "case_id": "case-1",
            "opensearch_document_id": "os-doc-1",
            "url": "http://localhost:9200",
            "index": "case-content",
            "max_chars": 12,
        }
    )

    assert captured["method"] == "GET"
    assert captured["path"] == "/case-content/_doc/os-doc-1"
    assert result["source_of_truth"] == "opensearch_content_index"
    assert result["retrieval_backend"] == "OpenSearch"
    assert result["title"] == "_WRD0001.tmp"
    assert result["source_record_id"] == "wic-1"
    assert result["storage_table"] == "windows_search_indexed_content"
    assert result["forensic_source_table"] == "user_file_content"
    assert result["evidence_nature"] == "direct_file_content_extraction"
    assert result["direct_file_content_extraction"] is True
    assert result["windows_search_artifact_content"] is False
    assert "direct file-content extraction" in result["provenance_summary"]
    assert result["content"] == "You did not "
    assert result["returned_content_length"] == 12
    assert result["content_length"] == 34
    assert result["truncated"] is True


def test_mcp_filesystem_listing_uses_generated_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")
    db = Database(tmp_path / "orchestrator.sqlite3")
    db.create_case("case-1", tmp_path)
    computer = db.create_computer(computer_id="computer-1", case_id="case-1", label="HOST01")
    image = db.add_image("image-1", "case-1", tmp_path / "usb.E01", computer_id=computer.id)
    db.insert_filesystem_entries(
        [
            {
                "id": "fs-1",
                "case_id": "case-1",
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "tool-1",
                "tool_name": "MountedFilesystemInventory",
                "source_csv": "filesystem_entries.csv",
                "row_number": 1,
                "partition_id": "part-1",
                "filesystem_type": "fat32",
                "source_root": "/mnt/usb",
                "file_path": "Alex.docx",
                "parent_path": "",
                "file_name": "Alex.docx",
                "extension": ".docx",
                "file_size": 31055,
                "is_directory": "false",
                "created_utc": "2025-11-17T15:47:02Z",
                "modified_utc": "2025-11-17T15:47:04Z",
                "accessed_utc": "2025-11-17T00:00:00Z",
                "metadata_changed_utc": None,
                "mode": None,
                "uid": None,
                "gid": None,
                "scan_status": "deleted",
                "error": "",
                "created_at": "2026-05-30T00:00:00Z",
            },
            {
                "id": "fs-2",
                "case_id": "case-1",
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "tool-1",
                "tool_name": "MountedFilesystemInventory",
                "source_csv": "filesystem_entries.csv",
                "row_number": 2,
                "partition_id": "part-1",
                "filesystem_type": "fat32",
                "source_root": "/mnt/usb",
                "file_path": "$FAT1",
                "parent_path": "",
                "file_name": "$FAT1",
                "extension": "",
                "file_size": 1024,
                "is_directory": "false",
                "created_utc": None,
                "modified_utc": None,
                "accessed_utc": None,
                "metadata_changed_utc": None,
                "mode": None,
                "uid": None,
                "gid": None,
                "scan_status": "virtual",
                "error": "",
                "created_at": "2026-05-30T00:00:00Z",
            },
        ]
    )
    db.close()
    server = RelicMcpServer(root=tmp_path)

    result = server.query_filesystem_listings({"case_id": "case-1", "contains": "Alex"})

    assert result["source_of_truth"] == "filesystem_entries"
    assert result["summary"]["returned_rows"] == 1
    assert result["filesystem_entries"][0]["file_path"] == "Alex.docx"
    assert result["filesystem_entries"][0]["computer_label"] == "HOST01"
    assert result["filesystem_entries"][0]["image_path"].endswith("usb.E01")

    default_result = server.query_filesystem_listings({"case_id": "case-1"})
    assert [row["file_name"] for row in default_result["filesystem_entries"]] == ["Alex.docx"]

    contents = server.query_evidence_contents({"case_id": "case-1", "image_id": "image-1"})
    assert contents["intent"] == "evidence_contents"
    assert contents["source_of_truth"] == "filesystem_entries"
    assert [row["file_name"] for row in contents["filesystem_entries"]] == ["Alex.docx"]

    dossier = server.file_dossier({"case_id": "case-1", "name": "Alex.docx"})
    assert dossier["content_followup"]["tool"] == "relic_search_content"
    assert dossier["content_followup"]["arguments"]["query"] == "Alex.docx"
    assert "relic_get_indexed_content" in dossier["content_followup"]["next_step"]


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
    process_tool = next(tool for tool in tools if tool["name"] == "relic_process_image")
    assert process_tool["permission"] == "processing"
    assert process_tool["category"] == "processing"
    assert process_tool["dependencies"]
    assert response["result"]["structuredContent"]["summary"]["categories"]
    assert response["result"]["structuredContent"]["_mcp"]["status"] == "ok"
    audit = tmp_path / "mcp-jobs" / "audit.jsonl"
    assert audit.exists()
    row = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert row["tool"] == "relic_mcp_tool_reference"
    assert row["correlation_id"]
    assert row["category"] == "operations"
    assert row["duration_ms"] >= 0
    assert row["arguments_redacted"] == {}


def test_mcp_error_payload_and_audit_redacts_sensitive_arguments(tmp_path):
    server = RelicMcpServer(root=tmp_path)
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "relic_case_summary",
                "arguments": {"case_id": "missing-case", "api_key": "secret-value"},
            },
        }
    )

    structured = response["result"]["structuredContent"]
    assert response["result"]["isError"] is True
    assert structured["error_code"] == "not_found"
    assert structured["retryable"] is False
    assert structured["_mcp"]["status"] == "error"
    audit = tmp_path / "mcp-jobs" / "audit.jsonl"
    row = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert row["status"] == "error"
    assert row["arguments_redacted"]["api_key"] == "<redacted>"
    assert row["error_details"]["error_code"] == "not_found"


def test_mcp_policy_blocks_tool_category_and_case(tmp_path):
    (tmp_path / "mcp-policy.json").write_text(
        json.dumps({"blocked_tools": ["relic_list_cases"], "blocked_categories": ["processing"], "blocked_case_ids": ["case-blocked"]}),
        encoding="utf-8",
    )
    server = RelicMcpServer(root=tmp_path, allow_processing=True)

    blocked_tool = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "relic_list_cases", "arguments": {}},
        }
    )
    assert blocked_tool["error"]["code"] == -32602
    assert "policy blocks tool" in blocked_tool["error"]["message"]

    blocked_category = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "relic_process_image", "arguments": {"path": str(tmp_path / "disk.E01")}},
        }
    )
    assert blocked_category["error"]["code"] == -32602
    assert "policy blocks category" in blocked_category["error"]["message"]

    blocked_case = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "relic_case_summary", "arguments": {"case_id": "case-blocked"}},
        }
    )
    assert blocked_case["error"]["code"] == -32602
    assert "policy blocks case_id" in blocked_case["error"]["message"]


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


def test_mcp_recover_deleted_files_requires_processing_and_builds_command(tmp_path):
    locked = RelicMcpServer(root=tmp_path)
    denied = locked.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "relic_recover_deleted_files", "arguments": {"case_id": "case-1", "name": "report.docx"}},
        }
    )
    assert denied["error"]["code"] == -32602
    assert "--allow-processing" in denied["error"]["message"]

    server = RelicMcpServer(root=tmp_path, allow_processing=True)
    captured = {}

    def fake_start(name, command):
        captured["name"] = name
        captured["command"] = command
        return {"mcp_job_id": "job-1", "name": name, "command": command}

    server._start_mcp_process = fake_start
    started = server.recover_deleted_files(
        {
            "case_id": "case-1",
            "image_id": "image-1",
            "name": "report.docx",
            "source": "mft_entries",
            "limit": 5,
            "max_bytes": 1000,
            "output_dir": "cases/case-1/outputs/recovered-files/test",
        }
    )

    assert started["mcp_job_id"] == "job-1"
    assert captured["name"] == "recover_deleted_files"
    assert captured["command"][captured["command"].index("recover") : captured["command"].index("--case")] == ["recover", "deleted-files"]
    assert "--image" in captured["command"]
    assert "image-1" in captured["command"]
    assert "--name" in captured["command"]
    assert "report.docx" in captured["command"]
    assert "--max-bytes" in captured["command"]
