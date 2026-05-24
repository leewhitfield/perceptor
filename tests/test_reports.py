import uuid
import os
from pathlib import Path

import duckdb

from forensic_orchestrator.common_dialog import rebuild_common_dialog_items
from forensic_orchestrator.copied_indicators import rebuild_copied_file_indicators
from forensic_orchestrator.analytics_query import query_one, query_rows
from forensic_orchestrator.db import Database
from forensic_orchestrator.filesystem_review import rebuild_filesystem_review
from forensic_orchestrator.reports import (
    accounts_report,
    account_compromise_markdown,
    account_compromise_report,
    artifact_correlations_report,
    autostarts_markdown,
    autostarts_report,
    brute_force_markdown,
    brute_force_report,
    case_summary_report,
    correlations_report,
    copied_file_groups_report,
    copied_file_indicators_report,
    copied_usb_files_report,
    common_dialog_items_report,
    artifact_completeness_report,
    data_exfiltration_markdown,
    data_exfiltration_report,
    file_dossier_report,
    communication_review_report,
    cloud_artifacts_report,
    cloud_configuration_report,
    cloud_files_report,
    communications_report,
    computer_inventory_report,
    device_inventory_report,
    email_artifacts_report,
    evidence_gaps_markdown,
    evidence_gaps_report,
    encrypted_volume_indicators_report,
    event_interpretation_report,
    evidence_quality_report,
    external_storage_markdown,
    external_storage_report,
    interesting_executables_markdown,
    interesting_executables_report,
    investigation_triage_dashboard_markdown,
    investigation_triage_dashboard_report,
    execution_markdown,
    execution_report,
    execution_correlation_report,
    file_history_markdown,
    file_history_report,
    file_intelligence_report,
    file_name_drilldown_report,
    file_names_report,
    filesystem_review_report,
    files_report,
    issues_report,
    mailbox_attachment_copies_report,
    mailbox_attachment_coverage_report,
    malware_hiding_places_markdown,
    malware_hiding_places_report,
    memory_analysis_markdown,
    memory_analysis_report,
    memory_artifacts_markdown,
    memory_artifacts_report,
    messaging_artifacts_report,
    mft_report,
    office_trust_report,
    phone_link_report,
    sdelete_report,
    srum_app_network_usage_report,
    srum_context_report,
    srum_networks_report,
    storage_policy_report,
    suspicious_executions_markdown,
    suspicious_executions_report,
    suspicious_timeline_windows_markdown,
    suspicious_timeline_windows_report,
    shortcuts_report,
    usn_path_report,
    usn_reasons_report,
    usn_bursts_report,
    usn_rename_pairs_report,
    usn_summary_report,
    usn_suspicious_report,
    usn_timeline_report,
    usn_usb_candidates_report,
    usn_user_files_report,
    usn_user_report,
    usb_file_correlation_report,
    usb_timeline_report,
    usb_verbose_report,
    browser_deep_storage_report,
    browser_profile_activity_report,
    cd_burning_activity_markdown,
    cd_burning_activity_report,
    persistence_report,
    program_provenance_markdown,
    program_provenance_report,
    registry_activity_report,
    registry_artifacts_report,
    remote_access_attribution_markdown,
    remote_access_attribution_report,
    rdp_remote_access_markdown,
    remote_access_sessions_report,
    vpn_activity_report,
    vpn_config_report,
    vpn_connections_report,
    vpn_execution_report,
    vpn_local_activity_markdown,
    vpn_local_activity_report,
    vpn_session_evidence_report,
    tool_run_summary_report,
    timeline_review_report,
    taskbar_feature_usage_report,
    taskbar_pins_report,
    tor_usage_report,
    ual_report,
    uninstalled_application_artifacts_report,
    user_activity_report,
    virtualization_indicators_report,
    web_cloud_correlations_report,
    windows_search_report,
)
from forensic_orchestrator.report_specs import list_report_specs, run_report_spec
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.timeline import timeline_events_from_rows


def test_summary_report_counts_outputs_artifacts_and_issues(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_artifact(
        {
            "id": "artifact-1",
            "case_id": case.id,
            "image_id": "image-1",
            "name": "prefetch_files",
            "source": "Windows/Prefetch",
            "path": tmp_path / "Prefetch",
            "kind": "directory",
            "metadata": {"count": 3},
        }
    )
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "PrefetchParser",
            "output_type": "csv",
            "path": tmp_path / "PrefetchParser.csv",
            "row_count": 3,
        }
    )
    db.log_activity(case_id=case.id, event="tool.no_output", message="No output", level="warning")

    report = case_summary_report(db, case.id)

    assert report["counts"]["computers"] == 1
    assert report["counts"]["images"] == 1
    assert report["counts"]["artifacts"] == 1
    assert report["counts"]["outputs"] == 1
    assert report["counts"]["warnings"] == 1
    assert report["artifact_counts"] == [
        {"image_id": "image-1", "artifact": "prefetch_files", "count": 3}
    ]


def test_high_level_investigation_reports_smoke_on_empty_case(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    suspicious = suspicious_timeline_windows_report(db, case.id, limit=5)
    triage = investigation_triage_dashboard_report(db, case.id, limit=5)
    exfiltration = data_exfiltration_report(db, case.id, limit=5)
    account = account_compromise_report(db, case.id, limit=5)
    provenance = program_provenance_report(db, case.id, limit=5)
    suspicious_exec = suspicious_executions_report(db, case.id, limit=5)

    assert suspicious["summary"]["window_count"] == 0
    assert triage["summary"]["cards"] >= 5
    assert exfiltration["summary"]["finding_count"] == 0
    assert account["summary"]["finding_count"] == 0
    assert provenance["summary"]["finding_count"] == 0
    assert suspicious_exec["summary"]["finding_count"] == 0
    assert "Suspicious Timeline Windows" in suspicious_timeline_windows_markdown(suspicious)
    assert "Investigation Triage Dashboard" in investigation_triage_dashboard_markdown(triage)
    assert "Data Exfiltration Report" in data_exfiltration_markdown(exfiltration)
    assert "Account Compromise Report" in account_compromise_markdown(account)
    assert "Program Provenance Report" in program_provenance_markdown(provenance)


def test_windows_search_report_surfaces_encrypted_sqlite_status(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    output_dir = tmp_path / "outputs" / "WindowsSearchESEParser"
    output_dir.mkdir(parents=True)
    csv_path = output_dir / "WindowsSearchESEParser.csv"
    csv_path.write_text("WorkId,System_Search_GatherTime,System_ItemPathDisplay\n", encoding="utf-8")
    (output_dir / "WindowsSearchParserInventory.json").write_text(
        """[
  {
    "detected_format": "encrypted_sqlite",
    "parser_note": "Windows 11 Search database uses AesGcm1 SQLite3 format; contents are encrypted and were not parsed.",
    "parser_status": "unsupported_encrypted_sqlite",
    "source_path": "/cases/11111111-1111-1111-1111-111111111111/artifacts/image-id/WindowsSearch/Applications/Windows/Windows.db"
  }
]""",
        encoding="utf-8",
    )
    db.insert_tool_output(
        {
            "id": "search-output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "WindowsSearchESEParser",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 0,
        }
    )

    report = windows_search_report(db, case.id, report_type="files", limit=10)

    assert report["files"] == []
    assert report["parser_status"]["summary_status"] == "partial_unsupported_encrypted_sqlite"
    assert report["parser_status"]["detected_formats"] == ["encrypted_sqlite"]
    assert report["parser_status"]["inventories"][0]["source_path"] == "/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db"


def test_memory_artifacts_report_inventories_mounted_files(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    volume = case.root / "mounts" / "volumes" / "part-001"
    volume.mkdir(parents=True)
    (volume / "hiberfil.sys").write_bytes(b"h" * 10)
    (volume / "pagefile.sys").write_bytes(b"p" * 20)
    (volume / "swapfile.sys").write_bytes(b"s" * 30)

    report = memory_artifacts_report(db, case.id)

    assert report["summary"]["artifact_count"] == 3
    assert report["summary"]["total_bytes"] == 60
    assert {row["artifact_type"] for row in report["artifacts"]} == {"hiberfil", "pagefile", "swapfile"}
    assert "Memory Artifact Inventory" in memory_artifacts_markdown(report)


def test_evidence_gaps_report_surfaces_windows_search_and_memory_limitations(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    volume = case.root / "mounts" / "volumes" / "part-001"
    volume.mkdir(parents=True)
    (volume / "hiberfil.sys").write_bytes(b"h")
    output_dir = tmp_path / "outputs" / "WindowsSearchESEParser"
    output_dir.mkdir(parents=True)
    csv_path = output_dir / "WindowsSearchESEParser.csv"
    csv_path.write_text("WorkId,System_Search_GatherTime,System_ItemPathDisplay\n", encoding="utf-8")
    (output_dir / "WindowsSearchParserInventory.json").write_text(
        """[
  {
    "detected_format": "encrypted_sqlite",
    "parser_note": "Windows 11 Search database uses AesGcm1 SQLite3 format; contents are encrypted and were not parsed.",
    "parser_status": "unsupported_encrypted_sqlite",
    "source_path": "/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db"
  }
]""",
        encoding="utf-8",
    )
    db.insert_tool_output(
        {
            "id": "search-output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "WindowsSearchESEParser",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 0,
        }
    )

    report = evidence_gaps_report(db, case.id)

    categories = {row["category"] for row in report["gaps"]}
    assert {"windows_search", "memory_artifacts"} <= categories
    assert report["summary"]["windows_search_status"] == "partial_unsupported_encrypted_sqlite"
    assert "Evidence Gaps and Limitations" in evidence_gaps_markdown(report)


def test_memory_analysis_report_combines_workflow_hits_and_search_limitation(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    volume = case.root / "mounts" / "volumes" / "part-001"
    volume.mkdir(parents=True)
    pagefile = volume / "pagefile.sys"
    pagefile.write_bytes(b"token=abc windows.db SearchIndexer c:\\users\\maya\\documents\\note.txt")
    output_dir = tmp_path / "outputs" / "WindowsSearchESEParser"
    output_dir.mkdir(parents=True)
    csv_path = output_dir / "WindowsSearchESEParser.csv"
    csv_path.write_text("WorkId,System_Search_GatherTime,System_ItemPathDisplay\n", encoding="utf-8")
    (output_dir / "WindowsSearchParserInventory.json").write_text(
        """[
  {
    "detected_format": "encrypted_sqlite",
    "parser_note": "Windows 11 Search database uses AesGcm1 SQLite3 format; contents are encrypted and were not parsed.",
    "parser_status": "unsupported_encrypted_sqlite",
    "source_path": "/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db"
  }
]""",
        encoding="utf-8",
    )
    db.insert_tool_output(
        {
            "id": "search-output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "WindowsSearchESEParser",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 0,
        }
    )
    db.insert_tool_output(
        {
            "id": "memory-output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "MemoryStringScanner",
            "output_type": "csv",
            "path": tmp_path / "MemoryStringScanner.csv",
            "row_count": 2,
        }
    )
    db.insert_memory_string_hits(
        [
            {
                "id": "mem-hit-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "memory-output-1",
                "tool_name": "MemoryStringScanner",
                "source_csv": str(tmp_path / "MemoryStringScanner.csv"),
                "row_number": 1,
                "source_artifact_type": "pagefile",
                "source_path": str(pagefile),
                "scanned_path": str(pagefile),
                "scanner": "strings",
                "encoding": "utf-8/utf-16le",
                "hit_category": "search",
                "matched_term": "windows.db",
                "string_value": "windows.db SearchIndexer",
                "string_sha256": "sha1",
                "string_length": 24,
                "offset": "12",
                "context_hint": "path",
            },
            {
                "id": "mem-hit-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "memory-output-1",
                "tool_name": "MemoryStringScanner",
                "source_csv": str(tmp_path / "MemoryStringScanner.csv"),
                "row_number": 2,
                "source_artifact_type": "pagefile",
                "source_path": str(pagefile),
                "scanned_path": str(pagefile),
                "scanner": "strings",
                "encoding": "utf-8/utf-16le",
                "hit_category": "credentials",
                "matched_term": "token",
                "string_value": "token=abc",
                "string_sha256": "sha2",
                "string_length": 9,
                "offset": "1",
                "context_hint": "",
            },
        ]
    )

    report = memory_analysis_report(db, case.id, limit=10)
    markdown = memory_analysis_markdown(report)

    assert report["summary"]["memory_artifact_count"] == 1
    assert report["summary"]["memory_string_hit_count"] == 2
    assert report["windows_search_assessment"]["result"] == "encrypted_sqlite_memory_leads_only"
    assert any(step["step"] == "memprocfs_mount" for step in report["workflow"])
    assert any(step["step"] == "dpapi_lsa_validation" for step in report["workflow"])
    assert any(row["category"] == "windows_search" for row in report["findings"])
    assert "Memory Processing and Analysis" in markdown
    assert "collect RAM while the user is logged in" in markdown


def test_storage_policy_report_counts_content_heavy_tables_and_output_files(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    output = tmp_path / "mail.csv"
    output.write_text("message body output", encoding="utf-8")
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "MailboxParser",
            "output_type": "csv",
            "path": output,
            "row_count": 1,
        }
    )
    db.insert_mailbox_messages(
        [
            {
                "id": "mail-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "MailboxParser",
                "source_csv": output,
                "row_number": 1,
                "source_path": "/mail/test.pst",
                "container_path": "/mail/test.pst",
                "message_path": "/mail/test.pst/message-1",
                "source_format": "pst",
                "parser_status": "parsed",
                "parser_error": "",
                "user_profile": "Jane",
                "user_sid": "",
                "message_id": "message-1",
                "in_reply_to": "",
                "subject": "Storage policy",
                "sender": "sender@example.com",
                "recipients": "recipient@example.com",
                "cc": "",
                "bcc": "",
                "message_date_utc": "2026-01-01T00:00:00Z",
                "body_text": "This is searchable message body text.",
                "body_html": "",
                "attachment_names": "",
                "attachment_count": 0,
                "search_date_created": "",
                "search_date_modified": "",
                "search_date_accessed": "",
                "search_date_imported": "",
                "details_json": "{}",
                "dedupe_key": "mail-1",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )

    report = storage_policy_report(db, case.id)

    mailbox = next(row for row in report["content_heavy_tables"] if row["table"] == "mailbox_messages")
    assert mailbox["row_count"] == 1
    assert mailbox["non_empty_large_rows"] == 0
    assert mailbox["referenced_large_rows"] == 1
    assert mailbox["estimated_large_text_bytes"] == 0
    assert report["artifact_files"]["estimated_bytes"] == output.stat().st_size
    assert report["opensearch"]["latest_status"] == "not_indexed"
    assert any(item["storage"] == "opensearch" for item in report["policy"])


def test_brute_force_report_classifies_spray_and_bad_passwords(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    rows = []
    for index in range(12):
        rows.append(
            {
                "id": f"spray-{index}",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": index + 1,
                "time_created": f"2020-11-14T13:{index:02d}:00Z",
                "event_id": "4625",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "HOST",
                "remote_host": "mstsc (85.14.242.76)",
                "payload_data1": f"Target: \\USER{index:02d}",
                "payload_data2": "LogonType 3",
                "payload_data3": "FailureReason1: the cause is either a bad username or authentication information",
                "payload_data4": "FailureReason2: user name is correct but the password is wrong",
                "source_file": "/Windows/System32/winevt/Logs/Security.evtx",
            }
        )
    for index in range(25):
        rows.append(
            {
                "id": f"brute-{index}",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": index + 100,
                "time_created": f"2020-11-14T14:{index:02d}:00Z",
                "event_id": "4625",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "HOST",
                "remote_host": "FreeRDP (10.10.10.5)",
                "payload_data1": "Target: \\ADMINISTRATOR",
                "payload_data2": "LogonType 10",
                "payload_data3": "FailureReason1: the cause is either a bad username or authentication information",
                "payload_data4": "FailureReason2: user name is correct but the password is wrong",
                "source_file": "/Windows/System32/winevt/Logs/Security.evtx",
            }
        )
    db.insert_evtx_events(rows)

    report = brute_force_report(db, case.id, min_failures=10, spray_account_threshold=5)
    markdown = brute_force_markdown(report)

    by_ip = {row["source_ip"]: row for row in report["source_ips"]}
    assert by_ip["10.10.10.5"]["classification"] == "brute_force"
    assert by_ip["10.10.10.5"]["credential_results"][0] == {
        "value": "valid_username_bad_password",
        "count": 25,
    }
    assert by_ip["85.14.242.76"]["classification"] == "password_spraying"
    assert "Remote valid username, bad password indications: `37`" in markdown
    assert "Source table: `evtx_events`" in markdown


def test_srum_context_report_classifies_cloud_vpn_and_rdp_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "srum-output",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "SrumECmd",
            "output_type": "csv",
            "path": tmp_path / "srum.csv",
            "row_count": 3,
        }
    )
    db.insert_srum_records(
        [
            {
                "id": "srum-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "srum-output",
                "tool_name": "SrumECmd",
                "source_csv": tmp_path / "srum.csv",
                "row_number": 1,
                "record_type": "network_usage",
                "timestamp": "2020-11-14T10:00:00Z",
                "app_name": "OneDrive.exe",
                "bytes_received": "10",
                "bytes_sent": "20",
                "row_json": "{}",
            },
            {
                "id": "srum-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "srum-output",
                "tool_name": "SrumECmd",
                "source_csv": tmp_path / "srum.csv",
                "row_number": 2,
                "record_type": "network_connectivity",
                "timestamp": "2020-11-14T11:00:00Z",
                "interface_type": "23",
                "vpn_profile_name": "Corp VPN",
                "connected_time": "3600",
                "row_json": "{}",
            },
            {
                "id": "srum-3",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "srum-output",
                "tool_name": "SrumECmd",
                "source_csv": tmp_path / "srum.csv",
                "row_number": 3,
                "record_type": "network_usage",
                "timestamp": "2020-11-14T12:00:00Z",
                "app_name": "mstsc.exe",
                "row_json": "{}",
            },
        ]
    )

    report = srum_context_report(db, case.id)

    contexts = {row["context"] for row in report["items"]}
    assert {"cloud_sync_context", "vpn_context", "rdp_context"} <= contexts
    assert next(row for row in report["items"] if row["app_name"] == "OneDrive.exe")["total_bytes"] == 30


def test_browser_deep_storage_report_inventories_parsed_storage_sources(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "browser-output",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "BrowserParser",
            "output_type": "csv",
            "path": tmp_path / "browser.csv",
            "row_count": 2,
        }
    )
    common = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "browser-output",
        "tool_name": "BrowserParser",
        "source_csv": tmp_path / "browser.csv",
    }
    db.insert_browser_artifacts(
        [
            {
                **common,
                "id": "browser-artifact-1",
                "row_number": 1,
                "browser": "Chrome",
                "artifact_type": "sync_leveldb",
                "profile_path": "/Users/fredr/AppData/Local/Google/Chrome/User Data/Default",
                "source_path": "/Users/fredr/AppData/Local/Google/Chrome/User Data/Default/Sync Data/LevelDB",
                "name": "sync device",
                "timestamp_utc": "2020-11-14T10:00:00Z",
                "details_json": "{}",
            }
        ]
    )
    db.insert_browser_notifications(
        [
            {
                **common,
                "id": "browser-notification-1",
                "row_number": 2,
                "browser": "Chrome",
                "profile_path": "/Users/fredr/AppData/Local/Google/Chrome/User Data/Default",
                "origin": "https://example.test",
                "host": "example.test",
                "title": "Alert",
                "created_utc": "2020-11-14T11:00:00Z",
                "details_json": "{}",
            }
        ]
    )

    report = browser_deep_storage_report(db, case.id)

    classifications = {row["classification"] for row in report["items"]}
    assert "leveldb_candidate" in classifications
    assert "notification" in classifications


def test_device_inventory_report_includes_non_storage_devices(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "usb-output",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "UsbParser",
            "output_type": "csv",
            "path": tmp_path / "usb.csv",
            "row_count": 1,
        }
    )
    db.insert_usb_devices(
        [
            {
                "id": "usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "usb-output",
                "tool_name": "UsbParser",
                "source_csv": tmp_path / "usb.csv",
                "row_number": 1,
                "source_path": "/Windows/System32/config/SYSTEM",
                "artifact": "hid_device",
                "device_type": "hid_device",
                "vendor": "Example",
                "product": "Keyboard",
                "serial": "ABC123",
                "instance_id": "HID\\VID_1234&PID_5678\\ABC123",
                "key_last_write_utc": "2020-11-14T10:00:00Z",
            }
        ]
    )

    report = device_inventory_report(db, case.id)

    assert report["devices"][0]["device_type"] == "hid_device"
    assert report["devices"][0]["device_identifier"] == "ABC123"


def test_issues_report_returns_warnings_and_errors_in_time_order(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.log_activity(case_id=case.id, event="test.info", message="Info")
    db.log_activity(case_id=case.id, event="test.warning", message="Warning", level="warning")
    db.log_activity(case_id=case.id, event="test.error", message="Error", level="error")

    report = issues_report(db, case.id)

    assert [issue["event"] for issue in report["issues"]] == ["test.warning", "test.error"]


def test_mft_report_reads_duckdb_artifact_rows_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                "id": "mft-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 1,
                "file_name": "report.docx",
                "parent_path": "Users/Fred/Documents",
                "created_at": "2026-05-19T00:00:00Z",
            }
        ],
    )

    report = mft_report(db, case.id)

    assert report["total_returned"] == 1
    assert report["mft_entries"][0]["file_name"] == "report.docx"
    assert report["mft_entries"][0]["computer_label"] == "Desktop"
    assert report["mft_entries"][0]["image_path"] == "/evidence/desktop.E01"
    assert db.conn.execute("SELECT COUNT(*) FROM mft_entries WHERE case_id = ?", (case.id,)).fetchone()[0] == 0


def test_report_specs_load_and_run_duckdb_sql(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    spec_dir = tmp_path / "specs"
    spec_dir.mkdir()
    (spec_dir / "custom.yaml").write_text(
        """
reports:
  - name: custom-mft
    title: Custom MFT
    store: duckdb
    parameters: [case_id, limit]
    columns: [file_name, parent_path]
    query: |
      SELECT file_name, parent_path
      FROM mft_entries
      WHERE case_id = ?
      ORDER BY row_number
      LIMIT ?
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("FORENSIC_REPORT_SPEC_DIRS", str(spec_dir))
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                "id": "mft-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 1,
                "entry_number": "7",
                "sequence_number": "1",
                "in_use": "True",
                "file_name": "plugin.docx",
                "parent_path": "Users/Fred/Documents",
                "created_at": "2026-05-19T00:00:00Z",
            }
        ],
    )

    specs = list_report_specs()
    report = run_report_spec(db, case.id, "custom-mft")
    built_in = run_report_spec(db, case.id, "mft-recent")

    assert any(spec.name == "custom-mft" for spec in specs)
    assert report["rows"] == [{"file_name": "plugin.docx", "parent_path": "Users/Fred/Documents"}]
    assert built_in["rows"][0]["file_name"] == "plugin.docx"


def test_cd_burning_activity_report_finds_staging_and_temp_indicators(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                "id": "mft-burn-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-1",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 1,
                "parent_path": "Users/Jane/AppData/Local/Microsoft/Windows/Burn/Burn",
                "file_name": "plan.docx",
                "record_changed_si": "2026-05-20T10:00:00Z",
            }
        ],
    )
    db.insert_normalized_artifact_rows(
        "usn_journal_entries",
        [
            {
                "id": "usn-burn-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-2",
                "tool_name": "MFTECmdUSN",
                "source_csv": tmp_path / "usn.csv",
                "row_number": 1,
                "update_timestamp": "2026-05-20T10:05:00Z",
                "file_name": "DAT12345.tmp",
                "full_path": "Users/Jane/AppData/Local/Temp/DAT12345.tmp",
                "reason": "FILE_CREATE",
            }
        ],
    )

    report = cd_burning_activity_report(db, case.id)

    assert report["summary"]["items_returned"] == 2
    assert report["summary"]["indicator_counts"]["burn_staging_folder"] == 1
    assert report["summary"]["indicator_counts"]["burn_temp_file"] == 1
    text = cd_burning_activity_markdown(report)
    assert "CD/DVD Burning Activity Report" in text
    assert "plan.docx" in text


def test_cloud_configuration_report_summarizes_registry_cloud_context(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_normalized_artifact_rows(
        "registry_artifacts",
        [
            {
                "id": "cloud-reg-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-reg",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "RegistryArtifactParser.csv",
                "row_number": 1,
                "source_path": "Users/Jane/NTUSER.DAT",
                "hive_type": "ntuser",
                "user_profile": "Jane",
                "artifact": "cloud_onedrive_sync_engine",
                "category": "cloud",
                "key_path": "Software/Microsoft/SyncEngines/Providers/OneDrive/site",
                "key_last_write_utc": "2026-05-20T10:00:00Z",
                "value_name": "UrlNamespace",
                "value_type": "REG_SZ",
                "value_data": "https://example.sharepoint.com/sites/Finance",
            },
            {
                "id": "cloud-reg-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-reg",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "RegistryArtifactParser.csv",
                "row_number": 2,
                "source_path": "Users/Jane/NTUSER.DAT",
                "hive_type": "ntuser",
                "user_profile": "Jane",
                "artifact": "cloud_google_drivefs",
                "category": "cloud",
                "key_path": "Software/Google/DriveFS/Share",
                "value_name": "MountPoint",
                "value_type": "REG_SZ",
                "value_data": "G:",
            },
        ],
    )

    report = cloud_configuration_report(db, case.id)

    assert report["summary"]["items_returned"] == 2
    assert {row["provider"] for row in report["cloud_configuration"]} == {"OneDrive", "Google Drive"}
    assert next(row for row in report["cloud_configuration"] if row["provider"] == "OneDrive")["config_type"] == "sync_engine"
    assert report["summary"]["provider_counts"] == [
        {"provider": "Google Drive", "count": 1},
        {"provider": "OneDrive", "count": 1},
    ]


def test_report_specs_load_from_plugin_yaml(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_REPORT_SPEC_DIRS", raising=False)
    plugin_path = tmp_path / "plugin.yaml"
    plugin_path.write_text(
        """
tools: {}
profiles: {}
reports:
  - name: plugin-inline-report
    title: Plugin Inline Report
    store: sqlite
    parameters: [case_id, limit]
    columns: [case_id]
    query: |
      SELECT id AS case_id
      FROM cases
      WHERE id = ?
      LIMIT ?
""",
        encoding="utf-8",
    )
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")

    specs = list_report_specs(plugin_paths=[plugin_path])
    report = run_report_spec(db, case.id, "plugin-inline-report", plugin_paths=[plugin_path])

    assert any(spec.name == "plugin-inline-report" for spec in specs)
    assert report["rows"] == [{"case_id": "case-1"}]


def test_file_history_uses_duckdb_mft_and_usn_when_filesystem_review_is_not_materialized(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                "id": "mft-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-mft",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 1,
                "entry_number": "42",
                "sequence_number": "3",
                "file_name": "history.docx",
                "parent_path": "Users/Fred/Documents",
                "in_use": "True",
                "is_directory": "False",
                "created_si": "2026-05-18T10:00:00Z",
                "modified_si": "2026-05-18T11:00:00Z",
                "accessed_si": "2026-05-18T12:00:00Z",
                "created_at": "2026-05-19T00:00:00Z",
            }
        ],
    )
    db.insert_normalized_artifact_rows(
        "usn_journal_entries",
        [
            {
                "id": "usn-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-usn",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "usn.csv",
                "row_number": 1,
                "file_name": "history.docx",
                "full_path": "Users/Fred/Documents/history.docx",
                "reason": "FileCreate",
                "update_timestamp": "2026-05-18T09:00:00Z",
                "file_reference_number": "42",
                "file_reference_sequence_number": "3",
                "created_at": "2026-05-19T00:00:00Z",
            }
        ],
    )

    report = file_history_report(db, case.id, name="history.docx", include_artifacts=False)

    assert report["summary"]["filesystem_event_count"] == 2
    assert [event["source_table"] for event in report["events"]] == ["usn_journal_entries", "mft_entries"]
    assert report["events"][0]["reason"] == "FileCreate"


def test_file_history_can_include_vsc_sidecar_events(tmp_path, monkeypatch):
    monkeypatch.delenv("FORENSIC_ANALYTICS_MODE", raising=False)
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_normalized_artifact_rows(
        "mft_entries",
        [
            {
                "id": "mft-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-mft",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "mft.csv",
                "row_number": 1,
                "entry_number": "42",
                "sequence_number": "3",
                "file_name": "report.docx",
                "parent_path": "Users/Jane/Documents",
                "in_use": "True",
                "is_directory": "False",
                "created_si": "2020-01-01T10:00:00Z",
                "modified_si": "2020-01-01T11:00:00Z",
                "accessed_si": "2020-01-01T12:00:00Z",
                "created_at": "2020-01-01T00:00:00Z",
            }
        ],
    )
    main_path = case.root / "analytics" / "events.duckdb"
    main_path.parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(main_path))
    try:
        conn.execute(
            """
            CREATE TABLE vsc_mft_deltas (
                case_id VARCHAR, snapshot_id VARCHAR, snapshot_index VARCHAR,
                snapshot_created_utc VARCHAR, id VARCHAR, entry_number VARCHAR,
                sequence_number VARCHAR, file_name VARCHAR,
                file_size VARCHAR, in_use VARCHAR, is_directory VARCHAR,
                normalized_path VARCHAR, created_si VARCHAR, modified_si VARCHAR,
                record_changed_si VARCHAR, accessed_si VARCHAR, path_key VARCHAR,
                delta_type VARCHAR, source_scope VARCHAR
            )
            """
        )
        conn.execute(
            """
            INSERT INTO vsc_mft_deltas VALUES (
                ?, 'vss1', '1', '2020-01-02T00:00:00Z', 'vss1-mft-1', '42',
                '3', 'report.docx', '12', 'True',
                'False', '/Users/Jane/Documents/report.docx',
                '2019-12-31T10:00:00Z', '2019-12-31T11:00:00Z',
                '2019-12-31T12:00:00Z', '2019-12-31T13:00:00Z',
                '/users/jane/documents/report.docx', 'not_live', 'VSC'
            )
            """,
            [case.id],
        )
    finally:
        conn.close()

    default_report = file_history_report(db, case.id, name="report.docx", include_artifacts=False)
    report = file_history_report(db, case.id, name="report.docx", include_artifacts=False, include_vsc=True)

    assert default_report["vsc_events"] == []
    assert report["summary"]["vsc_event_count"] == 4
    assert {event["source_scope"] for event in report["vsc_events"]} == {"vsc"}
    assert {event["snapshot_id"] for event in report["vsc_events"]} == {"vss1"}
    assert "VSC history events: `4`" in file_history_markdown(report)


def test_communications_report_does_not_read_body_content_from_sqlite(tmp_path):
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
            "job_id": None,
            "tool_name": "WindowsMailParser",
            "output_type": "csv",
            "path": "/tmp/MailboxMessages.csv",
            "row_count": 1,
        }
    )
    db.insert_mailbox_messages(
        [
            {
                "id": "mail-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "WindowsMailParser",
                "source_csv": "/tmp/MailboxMessages.csv",
                "row_number": 1,
                "source_path": "/Users/Jane/AppData/Local/Packages/mail/EFMData/1.dat",
                "container_path": "/Users/Jane/AppData/Local/Packages/mail/EFMData/1.dat",
                "message_path": "/Users/Jane/AppData/Local/Packages/mail/EFMData/1.dat",
                "source_format": "windows_mail_efmdata_html",
                "parser_status": "body_file_extracted",
                "parser_error": "path attributed",
                "user_profile": "Jane",
                "user_sid": "",
                "message_id": "",
                "in_reply_to": "",
                "subject": "",
                "sender": "",
                "recipients": "",
                "cc": "",
                "bcc": "",
                "message_date_utc": "2020-01-01T00:00:00+00:00",
                "body_text": "Falcon validation communication body.",
                "body_html": "",
                "attachment_names": "",
                "attachment_count": 0,
                "has_attachments": "0",
                "dedupe_key": "wm-1",
                "created_at": "2020-01-01T00:00:00+00:00",
            }
        ]
    )
    db.insert_windows_search_indexed_content(
        [
            {
                "id": "search-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "SIDR",
                "source_csv": "/tmp/Search.csv",
                "source_table": "windows_search_files",
                "source_record_id": "file-1",
                "row_number": 2,
                "work_id": "10",
                "gather_time": "2020-01-01T00:01:00+00:00",
                "item_path": r"\\{S-1-5-21-1-2-3-1001}\\LS\\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\\5\\item",
                "item_name": "item",
                "item_type": "email",
                "content_field": "body",
                "content_text": "Falcon validation communication body.",
                "content_length": 37,
                "timestamp": "2020-01-01T00:01:00+00:00",
                "created_at": "2020-01-01T00:00:00+00:00",
            }
        ]
    )

    report = communications_report(db, case.id, contains="Falcon", limit=10)

    assert report["communications"] == []
    windows_mail = query_one(
        db,
        "mailbox_messages",
        "SELECT body_text, body_text_sha256, TRY_CAST(body_text_length AS BIGINT) AS body_text_length FROM mailbox_messages",
    )
    indexed = query_one(
        db,
        "windows_search_indexed_content",
        "SELECT content_text, content_sha256, TRY_CAST(content_length AS BIGINT) AS content_length FROM windows_search_indexed_content",
    )
    assert windows_mail is not None
    assert indexed is not None
    assert windows_mail["body_text"] == ""
    assert windows_mail["body_text_sha256"]
    assert windows_mail["body_text_length"] == len("Falcon validation communication body.")
    assert indexed["content_text"] == ""
    assert indexed["content_sha256"]
    assert indexed["content_length"] == len("Falcon validation communication body.")


def test_mailbox_attachment_and_communication_review_reports(tmp_path):
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
            "job_id": None,
            "tool_name": "MailboxParser",
            "output_type": "csv",
            "path": "/tmp/MailboxMessages.csv",
            "row_count": 2,
        }
    )
    base_message = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "tool_name": "MailboxParser",
        "source_csv": "/tmp/MailboxMessages.csv",
        "source_path": "/tmp/1.eml",
        "container_path": "/tmp/mail.ost",
        "source_format": "ost",
        "parser_status": "parsed",
        "parser_error": "",
        "user_profile": "Jane",
        "user_sid": "",
        "message_id": "",
        "in_reply_to": "",
        "cc": "",
        "bcc": "",
        "body_html": "",
        "attachment_names": "plan.docx",
        "attachment_count": 1,
        "has_attachments": "1",
        "created_at": "2020-01-01T00:00:00+00:00",
    }
    db.insert_mailbox_messages(
        [
            {
                **base_message,
                "id": "mail-1",
                "row_number": 1,
                "message_path": "/tmp/1.eml",
                "subject": "Re: Project Falcon",
                "sender": "alice@example.test",
                "recipients": "bob@example.test; carol@example.test",
                "message_date_utc": "2020-01-01T00:00:00+00:00",
                "body_text": "Project Falcon first message.",
                "dedupe_key": "message-1",
            },
            {
                **base_message,
                "id": "mail-2",
                "row_number": 2,
                "message_path": "/tmp/2.eml",
                "subject": "Fwd: Project Falcon",
                "sender": "bob@example.test",
                "recipients": "alice@example.test",
                "message_date_utc": "2020-01-02T00:00:00+00:00",
                "body_text": "Project Falcon second message.",
                "dedupe_key": "message-2",
            },
        ]
    )
    base_attachment = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "tool_name": "MailboxParser",
        "source_csv": "/tmp/MailboxAttachments.csv",
        "source_path": "/tmp/1.eml",
        "container_path": "/tmp/mail.ost",
        "user_profile": "Jane",
        "user_sid": "",
        "message_id": "",
        "subject": "Project Falcon",
        "sender": "alice@example.test",
        "recipients": "bob@example.test",
        "message_date_utc": "2020-01-01T00:00:00+00:00",
        "attachment_name": "plan.docx",
        "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "size": 123,
        "sha256": "same-hash",
        "metadata_json": '{"FileType": "DOCX"}',
        "created_at": "2020-01-01T00:00:00+00:00",
    }
    db.insert_mailbox_attachments(
        [
            {
                **base_attachment,
                "id": "attachment-1",
                "row_number": 1,
                "message_path": "/tmp/1.eml",
                "attachment_path": "/tmp/1_attachments/plan.docx",
                "extracted_text": "Falcon plan text.",
                "extraction_status": "text_extracted",
                "parser_error": "",
                "dedupe_key": "attachment-1",
            },
            {
                **base_attachment,
                "id": "attachment-2",
                "row_number": 2,
                "message_path": "/tmp/2.eml",
                "attachment_path": "/tmp/2_attachments/plan.docx",
                "extracted_text": "",
                "extraction_status": "stored_binary",
                "parser_error": "",
                "dedupe_key": "attachment-2",
            },
        ]
    )

    coverage = mailbox_attachment_coverage_report(db, case.id)
    copies = mailbox_attachment_copies_report(db, case.id)
    conversations = communication_review_report(db, case.id, view="conversations")
    pairs = communication_review_report(db, case.id, view="pairs")
    attachments = communication_review_report(db, case.id, view="attachments")

    assert coverage["totals"]["attachment_count"] == 2
    assert {row["extraction_status"] for row in coverage["by_status"]} == {"stored_binary", "text_extracted"}
    assert copies["mailbox_attachment_copies"][0]["attachment_count"] == 2
    assert conversations["communication_review"][0]["message_count"] == 2
    assert {row["recipient"] for row in pairs["communication_review"]} >= {"alice@example.test", "bob@example.test"}
    assert attachments["communication_review"][0]["attachment_name"] == "plan.docx"


def test_operator_review_reports_cover_timeline_file_user_and_completeness(tmp_path):
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
            "job_id": None,
            "tool_name": "MFTECmd",
            "output_type": "csv",
            "path": "/tmp/MFT.csv",
            "row_count": 1,
        }
    )
    db.insert_mft_entries(
        [
            {
                "id": "mft-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "MFTECmd",
                "source_csv": "/tmp/MFT.csv",
                "row_number": 1,
                "entry_number": "42",
                "sequence_number": "1",
                "in_use": "True",
                "parent_path": "/Users/Jane/Documents",
                "file_name": "plan.docx",
                "created_si": "2020-01-01T00:00:00+00:00",
                "modified_si": "2020-01-02T00:00:00+00:00",
                "accessed_si": "",
                "record_changed_si": "",
                "created_at": "2020-01-03T00:00:00+00:00",
            }
        ]
    )
    db.log_activity(
        case_id=case.id,
        level="warning",
        event="artifact.skipped",
        message="Skipped test artifact",
        details={"tool_name": "MFTECmd"},
    )

    timeline = timeline_review_report(db, case.id, user="Jane", contains="plan", limit=10)
    dossier = file_dossier_report(db, case.id, name="plan.docx", limit=10)
    activity = user_activity_report(db, case.id, user="Jane", limit=10)
    completeness = artifact_completeness_report(db, case.id, limit=10)

    assert {event["event_type"] for event in timeline["events"]} >= {"file_created", "file_modified"}
    assert dossier["summary"]["evidence_rows"] >= 1
    assert activity["counts"]["communications"] == 0
    assert completeness["summary"]["tools_with_output"] == 1
    assert completeness["tools"][0]["warning_count"] == 1


def test_artifact_completeness_can_scope_to_latest_profile_run(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.conn.execute(
        """
        INSERT INTO process_timings (
          id, case_id, computer_id, image_id, parent_id, job_id, scope, phase,
          name, tool_name, artifact_name, status, start_time, end_time,
          duration_ms, details_json, created_at
        ) VALUES (?, ?, ?, ?, NULL, NULL, 'profile', 'profile', ?, NULL, NULL,
          'completed', ?, ?, 1000, '{}', ?)
        """,
        (
            "timing-latest",
            case.id,
            "computer-1",
            "image-1",
            "windows-full",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:01Z",
            "2026-01-02T00:00:00Z",
        ),
    )
    db.conn.commit()
    db.create_job(
        {
            "id": "old-failed-job",
            "case_id": case.id,
            "image_id": "image-1",
            "computer_id": "computer-1",
            "tool_name": "OldParser",
            "command": ["old"],
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-01T00:00:01Z",
            "exit_code": 1,
            "stdout_path": tmp_path / "old.out",
            "stderr_path": tmp_path / "old.err",
            "output_folder": tmp_path / "old",
        }
    )
    db.log_activity(
        case_id=case.id,
        level="warning",
        event="artifact.skipped",
        message="Old skipped artifact",
        details={"tool_name": "OldParser"},
    )
    db.conn.execute("UPDATE activity_log SET created_at = ? WHERE event = ?", ("2026-01-01T00:00:02Z", "artifact.skipped"))
    db.conn.commit()
    db.create_job(
        {
            "id": "new-success-job",
            "case_id": case.id,
            "image_id": "image-1",
            "computer_id": "computer-1",
            "tool_name": "MFTECmd",
            "command": ["mft"],
            "start_time": "2026-01-02T00:00:00Z",
            "end_time": "2026-01-02T00:00:01Z",
            "exit_code": 0,
            "stdout_path": tmp_path / "new.out",
            "stderr_path": tmp_path / "new.err",
            "output_folder": tmp_path / "new",
        }
    )
    db.insert_tool_output(
        {
            "id": "output-new",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "new-success-job",
            "tool_name": "MFTECmd",
            "output_type": "csv",
            "path": tmp_path / "new" / "MFT.csv",
            "row_count": 10,
        }
    )

    scoped = artifact_completeness_report(db, case.id, latest_profile_only=True)
    historical = artifact_completeness_report(db, case.id)

    assert scoped["run_scope"]["mode"] == "latest_profile"
    assert scoped["summary"]["failed_jobs"] == 0
    assert scoped["summary"]["skipped_issue_groups"] == 0
    assert [row["tool_name"] for row in scoped["tools"]] == ["MFTECmd"]
    assert historical["summary"]["failed_jobs"] == 1
    assert {row["tool_name"] for row in historical["tools"]} == {"MFTECmd", "OldParser"}


def test_artifact_completeness_separates_icat_extraction_caveats(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    stderr_path = tmp_path / "artifacts" / "Windows" / "System32" / "winevt" / "Logs" / "_extract_jobs" / "Security.evtx" / "stderr.txt"
    stderr_path.parent.mkdir(parents=True)
    stderr_path.write_text(
        "Error extracting file from image (ntfs_uncompress_compunit: Shift is too large: 60)\n",
        encoding="utf-8",
    )
    stdout_path = stderr_path.with_name("stdout.txt")
    stdout_path.write_text("", encoding="utf-8")
    db.create_job(
        {
            "id": "icat-job",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_name": "icat",
            "command": ["icat", "image.E01", "123"],
            "start_time": "2026-01-02T00:00:00Z",
            "end_time": "2026-01-02T00:00:01Z",
            "exit_code": 1,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "output_folder": stderr_path.parent,
        }
    )

    completeness = artifact_completeness_report(db, case.id, limit=10)
    quality = evidence_quality_report(db, case.id, limit=10)

    assert completeness["summary"]["failed_jobs"] == 0
    assert completeness["summary"]["extraction_caveats"] == 1
    assert completeness["tools"][0]["failed_jobs"] == 0
    assert completeness["tools"][0]["extraction_caveat_jobs"] == 1
    assert completeness["extraction_caveats"][0]["target"] == "Security.evtx"
    assert completeness["extraction_caveats"][0]["caveat_type"] == "ntfs_decompression"
    assert not any(finding["category"] == "tool_job" for finding in quality["findings"])
    assert any(finding["category"] == "extraction_caveat" for finding in quality["findings"])


def test_external_storage_report_combines_devices_activity_and_event_logs(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_storage_devices(
        [
            {
                "id": "usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "SER123",
                "vendor_id": "0781",
                "product_id": "5581",
                "vendor": "SanDisk",
                "product": "Ultra",
                "revision": "1.00",
                "friendly_name": "SanDisk Ultra",
                "parent_id_prefix": "7&abc",
                "device_service": "USBSTOR",
                "drive_letter": "E:",
                "volume_guid": "{11111111-1111-1111-1111-111111111111}",
                "volume_serial_number": "A1B2-C3D4",
                "volume_name": "EVIDENCE",
                "capacity_bytes": "32000000000",
                "file_system": "FAT32",
                "alternate_scsi_serial": "",
                "user_profiles": "fredr",
                "first_install_date_utc": "2020-11-10T10:00:00Z",
                "last_arrival_utc": "2020-11-14T10:00:00Z",
                "last_removal_utc": "2020-11-14T11:00:00Z",
                "first_volume_serial_event_utc": "2020-11-10T10:01:00Z",
                "last_partition_event_utc": "2020-11-14T10:01:00Z",
                "last_migration_present_utc": "2020-11-10T10:02:00Z",
                "evidence_row_count": 3,
                "source_artifacts": "usbstor,mounted_devices",
                "created_at": "2026-01-01T00:00:00Z",
            },
            {
                "id": "uasp-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "UASP123456",
                "vendor_id": "174C",
                "product_id": "55AA",
                "vendor": "ASMT",
                "product": "2115",
                "revision": "0",
                "friendly_name": "ASMT 2115 SCSI Disk Device",
                "parent_id_prefix": "7&2abc123&0",
                "device_service": "UASPStor, disk",
                "drive_letter": "F:",
                "volume_guid": "{22222222-2222-2222-2222-222222222222}",
                "volume_serial_number": "E5F6-A7B8",
                "volume_name": "UASP",
                "capacity_bytes": "1000000000000",
                "file_system": "NTFS",
                "alternate_scsi_serial": "7&2abc123&0",
                "user_profiles": "fredr",
                "first_install_date_utc": "2020-11-10T12:00:00Z",
                "last_arrival_utc": "2020-11-14T12:00:00Z",
                "last_removal_utc": "",
                "first_volume_serial_event_utc": "2020-11-10T12:01:00Z",
                "last_partition_event_utc": "2020-11-14T12:01:00Z",
                "last_migration_present_utc": "2020-11-10T12:02:00Z",
                "evidence_row_count": 4,
                "source_artifacts": "usb_device_migration,scsi_storage,mounted_devices",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )
    db.insert_usb_devices(
        [
            {
                "id": "usb-raw-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-usb",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "usb.csv",
                "row_number": 1,
                "source_path": "/Windows/System32/config/SYSTEM",
                "artifact": "mounted_devices",
                "device_type": "mounted_device",
                "vendor_id": "0781",
                "product_id": "5581",
                "vendor": "SanDisk",
                "product": "Ultra",
                "revision": "1.00",
                "friendly_name": "SanDisk Ultra",
                "serial": "SER123",
                "instance_id": "USBSTOR\\DISK&VEN_SANDISK",
                "parent_id_prefix": "7&abc",
                "device_service": "USBSTOR",
                "user_profile": "",
                "drive_letter": "E:",
                "volume_guid": "{11111111-1111-1111-1111-111111111111}",
                "volume_serial_number": "A1B2-C3D4",
                "volume_name": "EVIDENCE",
                "capacity_bytes": "32000000000",
                "file_system": "FAT32",
                "alternate_scsi_serial": "",
                "key_path": "MountedDevices",
                "key_last_write_utc": "2020-11-14T10:01:00Z",
                "last_present_date_utc": "",
                "property_name": "\\DosDevices\\E:",
                "property_value": "",
                "value_data_hex": "",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )
    db.insert_usb_connection_events(
        [
            {
                "id": "usb-event-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_device_id": "usb-1",
                "serial": "SER123",
                "volume_serial_number": "A1B2-C3D4",
                "volume_guid": "{11111111-1111-1111-1111-111111111111}",
                "drive_letter": "E:",
                "event_time_utc": "2020-11-14T10:00:00Z",
                "event_type": "arrival",
                "event_source": "registry",
                "event_id": "",
                "record_number": "",
                "source_path": "/Windows/System32/config/SYSTEM",
                "key_path": "USBSTOR",
                "property_name": "",
                "property_value": "",
                "capacity_bytes": "32000000000",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )
    shortcut_base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "file_name": "Budget.xlsx",
        "file_location": "E:\\Finance\\Budget.xlsx",
        "target_created": "2020-11-14T10:05:00Z",
        "target_modified": "2020-11-14T10:06:00Z",
        "target_accessed": "2020-11-14T10:07:00Z",
        "device_type": "Removable",
        "volume_serial_number": "A1B2-C3D4",
        "volume_name": "EVIDENCE",
        "command_line_arguments": "",
        "working_directory": "",
        "network_path": "",
        "machine_name": "",
        "app_id": "",
        "entry_id": "",
        "destlist_version": "",
        "lnk_created": "",
        "lnk_modified": "",
        "lnk_accessed": "",
        "created_at": "2026-01-01T00:00:00Z",
    }
    db.insert_shortcut_items(
        [
            {
                **shortcut_base,
                "id": "lnk-1",
                "tool_output_id": "out-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "lnk.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "Budget.lnk",
                "artifact_path": "/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/Budget.lnk",
                "app_id_description": "",
                "jumplist_item_number": "",
            },
            {
                **shortcut_base,
                "id": "jump-1",
                "tool_output_id": "out-jump",
                "tool_name": "JLECmd",
                "source_csv": tmp_path / "jump.csv",
                "row_number": 1,
                "artifact_type": "jumplist",
                "artifact_name": "Excel.destinations-ms",
                "artifact_path": "/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/Excel.destinations-ms",
                "app_id_description": "Excel",
                "jumplist_item_number": "1",
            },
        ]
    )
    db.insert_evtx_events(
        [
            {
                "id": "evtx-usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 1,
                "time_created": "2020-11-14T10:00:01Z",
                "event_id": "20001",
                "provider": "Microsoft-Windows-DriverFrameworks-UserMode",
                "channel": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
                "map_description": "USB storage device started",
                "payload_data1": "USBSTOR\\Disk&Ven_SanDisk UASPStor SCSI\\SER123",
                "source_file": "/Windows/System32/winevt/Logs/DriverFrameworks.evtx",
            },
            {
                "id": "evtx-usb-generic",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 2,
                "time_created": "2020-11-14T10:00:02Z",
                "event_id": "410",
                "provider": "Microsoft-Windows-Kernel-PnP",
                "channel": "Microsoft-Windows-Kernel-PnP/Configuration",
                "map_description": "Device driver error",
                "payload_data1": "ServiceName: USBSTOR",
                "payload_data2": "Problem: 0x0",
                "source_file": "/Windows/System32/winevt/Logs/Kernel-PnP.evtx",
            },
        ]
    )

    report = external_storage_report(db, case.id, limit=50)
    markdown = external_storage_markdown(report)

    assert report["summary"]["device_count"] == 2
    assert any(device["device_service"] == "UASPStor, disk" for device in report["devices"])
    assert report["summary"]["timeline_event_count"] >= 1
    assert report["summary"]["file_activity_count"] == 1
    assert report["file_activity"][0]["artifact_count"] == 2
    assert report["file_activity"][0]["source_artifact_types"] == "jumplist, lnk"
    assert report["event_log_observations"][0]["event_id"] == "20001"
    assert {row["event_id"] for row in report["event_log_observations"]} == {"20001"}
    assert "SanDisk Ultra" in markdown
    assert "Attributable file/folder activity: `detected" in markdown


def test_external_storage_report_lists_unattributed_removable_volume_activity(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_shortcut_items(
        [
            {
                "id": "lnk-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "lnk.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "Homework.lnk",
                "artifact_path": "/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/Homework.lnk",
                "file_name": "Homework.docx",
                "file_location": "E:\\New Homework\\Homework.docx",
                "target_created": "2020-11-14T10:05:00Z",
                "target_modified": "2020-11-14T10:06:00Z",
                "target_accessed": "2020-11-14T10:07:00Z",
                "device_type": "Removable",
                "volume_serial_number": "5E93-8BFB",
                "volume_name": "Homework",
                "command_line_arguments": "",
                "working_directory": "",
                "network_path": "",
                "machine_name": "",
                "app_id": "",
                "app_id_description": "",
                "entry_id": "",
                "destlist_version": "",
                "lnk_created": "",
                "lnk_modified": "",
                "lnk_accessed": "",
                "jumplist_item_number": "",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )

    report = external_storage_report(db, case.id, limit=50)
    markdown = external_storage_markdown(report)

    assert report["summary"]["file_activity_count"] == 0
    assert report["summary"]["unattributed_removable_volume_count"] == 1
    assert report["summary"]["unattributed_removable_file_activity_count"] == 1
    volume = report["unattributed_removable_volume_activity"][0]
    assert volume["volume_name"] == "Homework"
    assert volume["drive_letter"] == "E:"
    assert volume["source_artifact_types"] == "lnk"
    assert "Removable Volumes Not Tied To A Physical Device" in markdown
    assert "E:\\New Homework\\Homework.docx" in markdown


def test_external_storage_report_correlates_files_when_storage_summary_is_absent(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_connection_events(
        [
            {
                "id": "usb-event-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_device_id": "",
                "serial": "SER123",
                "volume_serial_number": "A1B2-C3D4",
                "volume_guid": "",
                "drive_letter": "E:",
                "event_time_utc": "2020-11-14T10:00:00Z",
                "event_type": "arrival",
                "event_source": "partition_diagnostic",
                "event_id": "",
                "record_number": "",
                "source_path": "/Windows/System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx",
                "key_path": "",
                "property_name": "",
                "property_value": "",
                "capacity_bytes": "32000000000",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )
    db.insert_usb_devices(
        [
            {
                "id": "usb-raw-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-usb",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "usb.csv",
                "row_number": 1,
                "source_path": "/Windows/System32/config/SYSTEM",
                "artifact": "partition_diagnostic",
                "device_type": "usb_partition_diagnostic",
                "vendor_id": "0781",
                "product_id": "5581",
                "vendor": "SanDisk",
                "product": "Ultra",
                "revision": "1.00",
                "friendly_name": "SanDisk Ultra",
                "serial": "SER123",
                "instance_id": "SER123",
                "parent_id_prefix": "",
                "device_service": "",
                "user_profile": "",
                "drive_letter": "E:",
                "volume_guid": "",
                "volume_serial_number": "A1B2-C3D4",
                "volume_name": "EVIDENCE",
                "capacity_bytes": "32000000000",
                "file_system": "FAT32",
                "alternate_scsi_serial": "",
                "key_path": "USB\\VID_0781&PID_5581\\SER123",
                "key_last_write_utc": "2020-11-14T10:00:00Z",
                "property_name": "",
                "property_value": "",
                "value_data_hex": "",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )
    db.insert_shortcut_items(
        [
            {
                "id": "lnk-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "lnk.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "Budget.lnk",
                "artifact_path": "/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/Budget.lnk",
                "file_name": "Budget.xlsx",
                "file_location": "E:\\Finance\\Budget.xlsx",
                "target_created": "2020-11-14T10:05:00Z",
                "target_modified": "2020-11-14T10:06:00Z",
                "target_accessed": "2020-11-14T10:07:00Z",
                "device_type": "Removable",
                "volume_serial_number": "A1B2-C3D4",
                "volume_name": "EVIDENCE",
                "command_line_arguments": "",
                "working_directory": "",
                "network_path": "",
                "machine_name": "",
                "app_id": "",
                "app_id_description": "",
                "entry_id": "",
                "destlist_version": "",
                "lnk_created": "",
                "lnk_modified": "",
                "lnk_accessed": "",
                "jumplist_item_number": "",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )

    report = external_storage_report(db, case.id, limit=50)

    assert report["summary"]["file_activity_count"] == 1
    assert report["file_activity"][0]["usb_serial"] == "SER123"
    assert report["file_activity"][0]["file_location"] == "E:\\Finance\\Budget.xlsx"


def test_external_storage_report_synthesizes_devices_from_connection_events(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_connection_events(
        [
            {
                "id": "usb-event-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_device_id": "",
                "serial": "SER123",
                "volume_serial_number": "A1B2-C3D4",
                "volume_guid": "",
                "drive_letter": "E:",
                "event_time_utc": "2020-11-14T10:00:00Z",
                "event_type": "arrival",
                "event_source": "partition_diagnostic",
                "event_id": "",
                "record_number": "",
                "source_path": "/Windows/System32/config/SYSTEM",
                "key_path": "USBSTOR",
                "property_name": "",
                "property_value": "",
                "capacity_bytes": "32000000000",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )

    report = external_storage_report(db, case.id, limit=50)

    assert report["summary"]["device_count"] == 1
    assert report["devices"][0]["serial"] == "SER123"
    assert report["devices"][0]["synthesized_from"] == "usb_connection_events"
    assert report["devices"][0]["source_artifacts"] == "partition_diagnostic"


def test_file_dossier_groups_dedupes_and_translates_evidence(tmp_path):
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
            "job_id": None,
            "tool_name": "WindowsSearchESEParser",
            "output_type": "csv",
            "path": tmp_path / "WindowsSearch.csv",
            "row_count": 3,
        }
    )
    now = "2026-01-01T00:00:00Z"
    db.insert_windows_search_files(
        [
            {
                "id": "ws-file-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "WindowsSearchESEParser",
                "source_csv": tmp_path / "WindowsSearch.csv",
                "row_number": 1,
                "work_id": "6452",
                "gather_time": now,
                "item_path": r"C:\Users\fredr\Google Drive\BusinessPlan.docx",
                "item_url": "",
                "folder_path": r"C:\Users\fredr\Google Drive",
                "file_name": "BusinessPlan.docx",
                "file_extension": "docx",
                "item_type": "File",
                "date_created": "2020-11-02T15:03:23Z",
                "date_modified": "2020-11-05T02:16:11Z",
                "date_accessed": "2020-11-10T14:01:40Z",
                "date_imported": "",
                "size": "33462",
                "owner": "SRL-FORGE\\fredr",
                "computer_name": "SRL-FORGE",
                "row_json": "{}",
                "created_at": now,
            }
        ]
    )
    db.insert_windows_search_properties(
        [
            {
                "id": "ws-prop-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "WindowsSearchESEParser",
                "source_csv": tmp_path / "WindowsSearch.csv",
                "source_table": "windows_search_files",
                "source_record_id": "ws-file-1",
                "row_number": 2,
                "work_id": "6452",
                "item_path": r"C:\Users\fredr\Google Drive\BusinessPlan.docx",
                "property_name": "4397-System_FilePlaceholderStatus",
                "property_value": "6",
                "normalized_name": "System_FilePlaceholderStatus",
                "timestamp": now,
                "created_at": now,
            },
            {
                "id": "ws-prop-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "WindowsSearchESEParser",
                "source_csv": tmp_path / "WindowsSearch.csv",
                "source_table": "windows_search_files",
                "source_record_id": "ws-file-1",
                "row_number": 3,
                "work_id": "6452",
                "item_path": r"C:\Users\fredr\Google Drive\BusinessPlan.docx",
                "property_name": "4456-System_Kind",
                "property_value": "646f63756d656e74",
                "normalized_name": "System_Kind",
                "timestamp": now,
                "created_at": now,
            },
        ]
    )
    db.insert_google_drive_cache_map(
        [
            {
                "id": "gdrive-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "GoogleDriveParser",
                "source_csv": tmp_path / "GoogleDrive.csv",
                "row_number": 1,
                "account_id": "acct",
                "stable_id": "stable",
                "file_id": "file",
                "virtual_path": "/My Drive/BusinessPlan.docx",
                "file_name": "BusinessPlan.docx",
                "cache_id": "cache",
                "cache_path": r"C:\Users\fredr\AppData\Local\Google\DriveFS\cache\content_cache\cache",
                "windows_cache_path": r"C:\Users\fredr\AppData\Local\Google\DriveFS\cache\content_cache\cache",
                "cache_file_size": "33462",
                "mapping_method": "protobuf",
                "evidence_basis": "stable_id",
                "details_json": "{}",
                "created_at": now,
            }
        ]
    )

    report = file_dossier_report(db, case.id, name="BusinessPlan.docx", limit=25)

    assert report["sections"]["windows_search"]
    assert report["sections"]["cloud_sync"]
    placeholder = next(
        row for row in report["sections"]["windows_search"]
        if row["details"].get("normalized_name") == "System_FilePlaceholderStatus"
    )
    assert "placeholder" in placeholder["details"]["translated"]["translated"]
    kind = next(
        row for row in report["sections"]["windows_search"]
        if row["details"].get("normalized_name") == "System_Kind"
    )
    assert kind["details"]["translated"]["translated"] == "document"
    assert report["summary"]["source_type_counts"]
    assert any(item["rule"] == "cloud_placeholder_status" for item in report["interpretation"])


def test_malware_hiding_places_report_flags_unusual_locations_and_encoded_registry_values(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_prefetch_items([
        {
            **base,
            "id": "prefetch-1",
            "tool_output_id": "output-prefetch",
            "tool_name": "PrefetchParser",
            "prefetch_name": "EVIL.EXE-12345678.pf",
            "executable_name": "evil.exe",
            "artifact_path": "C:/Users/Jane/AppData/Roaming/evil.exe",
            "last_run_time_utc": "2020-01-02T10:00:00Z",
            "last_run_times_utc": '["2020-01-02T10:00:00Z"]',
            "run_count": "1",
        }
    ])
    encoded = (
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        "LgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAnACkA"
    )
    db.insert_registry_artifacts([
        {
            **base,
            "id": "registry-1",
            "tool_output_id": "output-registry",
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/NTUSER.DAT",
            "hive_type": "ntuser",
            "artifact": "runmru",
            "category": "execution",
            "key_path": "Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU",
            "key_last_write_utc": "2020-01-02T11:00:00Z",
            "value_name": "a",
            "value_type": "REG_SZ",
            "value_data": encoded,
        }
    ])

    report = malware_hiding_places_report(db, case.id, long_value_threshold=80)
    markdown = malware_hiding_places_markdown(report)

    assert report["summary"]["unusual_execution_location_count"] == 1
    assert report["summary"]["long_or_encoded_registry_value_count"] == 1
    assert report["unusual_execution_locations"][0]["location_category"] == "user_roaming_profile"
    assert "base64_decodable" in report["registry_value_indicators"][0]["flags"]
    assert "Potential Malware Hiding Places" in markdown


def test_malware_hiding_places_report_suppresses_known_legitimate_noise(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_prefetch_items([
        {
            **base,
            "id": "prefetch-defender",
            "tool_output_id": "output-prefetch",
            "tool_name": "PrefetchParser",
            "prefetch_name": "MSMPENG.EXE-12345678.pf",
            "executable_name": "MsMpEng.exe",
            "artifact_path": "C:/ProgramData/Microsoft/Windows Defender/Platform/4.18.1/MsMpEng.exe",
            "last_run_time_utc": "2020-01-02T10:00:00Z",
            "last_run_times_utc": '["2020-01-02T10:00:00Z"]',
            "run_count": "1",
        }
    ])
    long_value = "A" * 200
    encoded = (
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        "LgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAnACkA"
    )
    registry_rows = []
    for index, artifact in enumerate(("shellbags", "userassist", "common_dialog"), start=1):
        registry_rows.append(
            {
                **base,
                "id": f"registry-noise-{index}",
                "tool_output_id": "output-registry",
                "tool_name": "RegistryArtifactParser",
                "source_path": "/registry/NTUSER.DAT",
                "hive_type": "ntuser",
                "artifact": artifact,
                "category": "user_activity",
                "key_path": f"Software/Microsoft/Windows/CurrentVersion/Explorer/{artifact}",
                "key_last_write_utc": "2020-01-02T11:00:00Z",
                "value_name": "a",
                "value_type": "REG_SZ",
                "value_data": encoded if artifact == "userassist" else long_value,
            }
        )
    registry_rows.append(
        {
            **base,
            "id": "registry-autostart",
            "tool_output_id": "output-registry",
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/NTUSER.DAT",
            "hive_type": "ntuser",
            "artifact": "autostart",
            "category": "execution",
            "key_path": "Software/Microsoft/Windows/CurrentVersion/Run",
            "key_last_write_utc": "2020-01-02T11:00:00Z",
            "value_name": "Update",
            "value_type": "REG_SZ",
            "value_data": encoded,
        }
    )
    registry_rows.append(
        {
            **base,
            "id": "registry-benign-task",
            "tool_output_id": "output-registry",
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/SOFTWARE",
            "hive_type": "software",
            "artifact": "scheduled_task_cache",
            "category": "persistence",
            "key_path": "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tasks/{TASK}",
            "key_last_write_utc": "2020-01-02T12:00:00Z",
            "value_name": "Actions",
            "value_type": "REG_BINARY",
            "value_data": r"%windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask",
        }
    )
    db.insert_registry_artifacts(registry_rows)

    report = malware_hiding_places_report(db, case.id, long_value_threshold=80)

    assert report["summary"]["unusual_execution_location_count"] == 0
    assert report["summary"]["long_or_encoded_registry_value_count"] == 1
    assert report["registry_value_indicators"][0]["artifact"] == "autostart"
    assert report["registry_value_indicators"][0]["autostart_location"] == "Run/RunOnce"
    suppressed = {
        row["reason"]: row["count"]
        for row in report["summary"]["suppressed_registry_value_counts"]
    }
    assert suppressed["known_windows_scheduled_task_action"] == 1


def test_autostarts_report_lists_autostart_and_scheduled_task_locations(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-registry",
        "tool_name": "RegistryArtifactParser",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_registry_artifacts([
        {
            **base,
            "id": "registry-run",
            "source_path": "/registry/NTUSER.DAT",
            "hive_type": "ntuser",
            "artifact": "autostart",
            "category": "execution",
            "key_path": "Software/Microsoft/Windows/CurrentVersion/Run",
            "key_last_write_utc": "2020-01-02T11:00:00Z",
            "value_name": "Updater",
            "value_type": "REG_SZ",
            "value_data": "C:/Users/Jane/AppData/Roaming/updater.exe",
            "normalized_path": "C:/Users/Jane/AppData/Roaming/updater.exe",
        },
        {
            **base,
            "id": "registry-task",
            "source_path": "/registry/SOFTWARE",
            "hive_type": "software",
            "artifact": "scheduled_task_cache",
            "category": "persistence",
            "key_path": "Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache/Tasks/{TASK}",
            "key_last_write_utc": "2020-01-02T12:00:00Z",
            "value_name": "Actions",
            "value_type": "REG_BINARY",
            "value_data": r"%windir%\system32\rundll32.exe test.dll,Run",
        },
        {
            **base,
            "id": "registry-userassist",
            "source_path": "/registry/NTUSER.DAT",
            "hive_type": "ntuser",
            "artifact": "userassist",
            "category": "execution",
            "key_path": "Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist",
            "key_last_write_utc": "2020-01-02T13:00:00Z",
            "value_name": "a",
            "value_type": "REG_SZ",
            "value_data": "C:/Users/Jane/AppData/Roaming/updater.exe",
        },
    ])

    report = autostarts_report(db, case.id)
    markdown = autostarts_markdown(report)

    assert report["summary"]["total_items"] == 2
    assert report["summary"]["scheduled_task_items"] == 1
    assert {row["autostart_location"] for row in report["autostarts"]} == {"Run/RunOnce", "Scheduled Task Cache"}
    assert "Autostarts And Scheduled Tasks" in markdown


def test_accounts_report_returns_sam_parser_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_sam_accounts(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "SAMParser",
                "source_csv": tmp_path / "SAMParser.csv",
                "row_number": 1,
                "source_path": "/artifacts/SAM",
                "username": "Jean",
                "rid": "1004",
                "rid_hex": "0x000003EC",
                "account_category": "local",
                "last_login_utc": None,
                "password_last_set_utc": None,
                "last_bad_password_utc": None,
                "account_expires_utc": None,
                "logon_count": None,
                "bad_password_count": None,
                "account_flags_hex": None,
                "account_flags": None,
                "account_flags_unknown_hex": None,
                "registry_path": "SAM/SAM/Domains/Account/Users/Names/Jean",
            }
        ]
    )

    report = accounts_report(db, case.id)

    assert report["total_accounts"] == 1
    assert report["accounts"][0]["username"] == "Jean"
    assert report["accounts"][0]["computer_label"] == "Desktop"


def test_evidence_quality_flags_sam_timestamp_cluster_near_install_metadata(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base_sam = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "sam-output",
        "tool_name": "SAMParser",
        "source_csv": tmp_path / "SAMParser.csv",
        "source_path": "/artifacts/SAM",
        "account_category": "local",
        "last_login_utc": None,
        "password_last_set_utc": None,
        "last_bad_password_utc": None,
        "account_expires_utc": None,
        "logon_count": None,
        "bad_password_count": None,
        "account_flags_hex": None,
        "account_flags": None,
        "account_flags_unknown_hex": None,
    }
    db.insert_sam_accounts(
        [
            {
                **base_sam,
                "id": str(uuid.uuid4()),
                "row_number": index,
                "username": username,
                "rid": str(1000 + index),
                "rid_hex": f"0x{1000 + index:08X}",
                "registry_path": f"SAM/SAM/Domains/Account/Users/Names/{username}",
                "account_key_last_write_utc": f"2020-11-14T10:00:{index:02d}Z",
            }
            for index, username in enumerate(["Jean", "Devon", "Jane"], start=1)
        ]
    )
    db.insert_registry_artifacts(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "registry-output",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "RegistryArtifactParser.csv",
                "row_number": 1,
                "source_path": "/artifacts/SOFTWARE",
                "hive_type": "software",
                "artifact": "install_time_software",
                "category": "system",
                "key_path": "Microsoft/Windows NT/CurrentVersion",
                "key_last_write_utc": "2020-11-14T10:03:00Z",
                "event_time_utc": None,
                "value_name": "InstallDate",
                "value_type": "REG_DWORD",
                "value_data": "",
                "notes": "",
            }
        ]
    )

    report = evidence_quality_report(db, case.id, limit=500)
    finding = next(item for item in report["findings"] if item["category"] == "registry_timestamp_cluster")

    assert finding["details"]["source_table"] == "sam_accounts"
    assert finding["details"]["item_count"] == 3
    assert finding["details"]["nearest_install_time"]["artifact"] == "install_time_software"
    assert "should not be treated as precise account creation times" in finding["details"]["explanation"]


def test_registry_artifact_ingest_populates_office_trust_and_taskbar_tables(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "RegistryArtifactParser.csv"
    csv_path.write_text(
        "source_path,hive_type,user_profile,user_sid,artifact,category,key_path,key_last_write_utc,"
        "event_time_utc,recentdocs_time_utc,recentdocs_extension_time_utc,mru_position,"
        "recentdocs_mru_position,recentdocs_extension_mru_position,is_most_recent,value_name,"
        "value_type,value_data,display_name,normalized_path,value_data_hex,transaction_logs_detected,"
        "transaction_logs_applied,transaction_log_paths,notes\n"
        "/Users/Jane/NTUSER.DAT,ntuser,Jane,,office_trusted_locations,user_activity,"
        "Software/Microsoft/Office/16.0/Word/Security/Trusted Locations/Location0,2020-11-14T10:00:00Z,"
        ",,,,,,,Path,REG_SZ,C:\\Trusted,C:\\Trusted,,,false,false,,\n"
        "/Users/Jane/NTUSER.DAT,ntuser,Jane,,office_trusted_locations,user_activity,"
        "Software/Microsoft/Office/16.0/Word/Security/Trusted Locations/Location0,2020-11-14T10:00:00Z,"
        ",,,,,,,AllowSubfolders,REG_DWORD,1,1,,,false,false,,\n"
        "/Users/Jane/NTUSER.DAT,ntuser,Jane,,office_trusted_documents,user_activity,"
        "Software/Microsoft/Office/16.0/Word/Security/Trusted Documents/TrustRecords,2020-11-14T10:05:00Z,"
        ",,,,,,,C:\\Users\\Jane\\Downloads\\macro.docm,REG_BINARY,Enable Editing Macros,,0102,false,false,,\n"
        "/Users/Jane/NTUSER.DAT,ntuser,Jane,,taskbar_feature_usage,user_activity,"
        "Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/AppSwitched,2020-11-14T10:06:00Z,"
        ",,,,,,,WINWORD.EXE,REG_DWORD,5,5,,,false,false,,\n"
        "/Users/Jane/NTUSER.DAT,ntuser,Jane,,taskbar_feature_usage,user_activity,"
        "Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/AppLaunch,2020-11-14T10:07:00Z,"
        ",,,,,,,KeyCreationTime,REG_QWORD,132482410239315464,132482410239315464,,,false,false,,\n",
        encoding="utf-8",
    )
    output_id = db.insert_tool_output(
        {
            "id": "registry-output",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "RegistryArtifactParser",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 5,
        }
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id=output_id,
        tool_name="RegistryArtifactParser",
        path=csv_path,
    )

    office = office_trust_report(db, case.id, user="Jane")
    taskbar = taskbar_feature_usage_report(db, case.id, user="Jane")
    pins = taskbar_pins_report(db, case.id, user="Jane")

    assert {row["trust_type"] for row in office["office_trust_records"]} == {
        "office_trusted_documents",
        "office_trusted_locations",
    }
    location = next(row for row in office["office_trust_records"] if row["value_name"] == "Path")
    trusted_doc = next(row for row in office["office_trust_records"] if row["trust_type"] == "office_trusted_documents")
    assert location["path_or_file"] == "C:\\Trusted"
    assert trusted_doc["permitted_editing"] == "true"
    assert trusted_doc["permitted_macros_or_scripts"] == "true"
    app_switched = next(row for row in taskbar["taskbar_feature_usage"] if row["feature"] == "AppSwitched")
    assert app_switched["usage_count"] == 5
    assert app_switched["value_semantics"] == "feature_specific_counter_not_launch_count"
    key_creation = next(row for row in taskbar["taskbar_feature_usage"] if row["value_name"] == "KeyCreationTime")
    assert key_creation["usage_count"] is None
    assert key_creation["value_semantics"] == "metadata_key_creation_time"
    assert any("subkeys have different meanings" in caveat for caveat in taskbar["caveats"])
    assert pins["taskbar_pins"] == []


def test_evidence_quality_flags_common_registry_artifact_timestamp_clusters(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "registry-output",
        "tool_name": "RegistryArtifactParser",
        "source_csv": tmp_path / "RegistryArtifactParser.csv",
        "source_path": "/Users/Jane/NTUSER.DAT",
        "hive_type": "ntuser",
        "user_profile": "Jane",
        "artifact": "recentdocs",
        "category": "user_activity",
        "value_type": "REG_BINARY",
        "value_data": "doc",
    }
    rows = []
    for index in range(3):
        rows.append(
            {
                **base,
                "id": str(uuid.uuid4()),
                "row_number": index + 1,
                "key_path": f"Software/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs/.docx/{index}",
                "key_last_write_utc": f"2020-11-14T10:00:0{index}Z",
                "value_name": str(index),
            }
        )
    rows.append(
        {
            **base,
            "id": str(uuid.uuid4()),
            "row_number": 10,
            "source_path": "/artifacts/SOFTWARE",
            "hive_type": "software",
            "user_profile": None,
            "artifact": "install_time_software",
            "category": "system",
            "key_path": "Microsoft/Windows NT/CurrentVersion",
            "key_last_write_utc": "2020-11-14T10:04:00Z",
            "value_name": "InstallDate",
            "value_data": "",
        }
    )
    db.insert_registry_artifacts(rows)

    report = evidence_quality_report(db, case.id, limit=500)
    finding = next(
        item
        for item in report["findings"]
        if item["category"] == "registry_timestamp_cluster"
        and item["details"].get("source_table") == "registry_artifacts"
    )

    assert finding["details"]["artifact"] == "recentdocs"
    assert finding["details"]["item_count"] == 3
    assert finding["details"]["nearest_install_time"]["artifact"] == "install_time_software"


def test_taskband_favorites_are_parsed_as_pinned_taskbar_state(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    csv_path = tmp_path / "RegistryArtifactParser.csv"
    raw = "Outlook.lnk\x00Chrome.lnk\x00".encode("utf-16-le").hex()
    csv_path.write_text(
        "source_path,hive_type,user_profile,user_sid,artifact,category,key_path,key_last_write_utc,"
        "event_time_utc,recentdocs_time_utc,recentdocs_extension_time_utc,mru_position,"
        "recentdocs_mru_position,recentdocs_extension_mru_position,is_most_recent,value_name,"
        "value_type,value_data,display_name,normalized_path,value_data_hex,transaction_logs_detected,"
        "transaction_logs_applied,transaction_log_paths,notes\n"
        "/Users/Jane/NTUSER.DAT,ntuser,Jane,,taskbar_usage,user_activity,"
        "Software/Microsoft/Windows/CurrentVersion/Explorer/Taskband,2020-11-14T10:00:00Z,"
        f",,,,,,,Favorites,REG_BINARY,{raw},,,{raw},false,false,,\n",
        encoding="utf-8",
    )
    output_id = db.insert_tool_output(
        {
            "id": "registry-output",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "RegistryArtifactParser",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 1,
        }
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id=output_id,
        tool_name="RegistryArtifactParser",
        path=csv_path,
    )

    report = taskbar_pins_report(db, case.id, user="Jane")

    assert [row["pin_name"] for row in report["taskbar_pins"]] == ["Outlook.lnk", "Chrome.lnk"]
    assert report["caveats"]
    assert report["taskbar_pins"][0]["target_hint"] == "Outlook"


def test_copied_file_indicators_table_combines_mft_shortcuts_shellbags_and_registry(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    mft_base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-mft",
        "tool_name": "MFTECmd",
        "source_csv": tmp_path / "MFT.csv",
        "sequence_number": "1",
        "in_use": "True",
        "parent_entry_number": "1",
        "parent_sequence_number": "1",
        "extension": ".docx",
        "file_size": "100",
        "is_directory": "False",
        "has_ads": "False",
        "is_ads": "False",
        "si_flags": None,
        "reparse_target": None,
        "si_fn_copied": None,
        "created_fn": None,
        "modified_fn": None,
        "record_changed_si": None,
        "record_changed_fn": None,
        "accessed_si": None,
        "accessed_fn": None,
        "source_file": "/artifacts/$MFT",
    }
    db.insert_mft_entries(
        [
            {
                **mft_base,
                "id": "mft-copied",
                "row_number": 1,
                "entry_number": "10",
                "parent_path": "Users/fredr/Documents",
                "file_name": "copied.docx",
                "created_si": "2020-01-02 10:00:00",
                "modified_si": "2020-01-01 10:00:00",
            },
            {
                **mft_base,
                "id": "mft-registry",
                "row_number": 2,
                "entry_number": "11",
                "parent_path": "Users/fredr/Documents",
                "file_name": "office.docx",
                "created_si": "2020-01-03 10:00:00",
                "modified_si": "2020-01-01 10:00:00",
            },
            {
                **mft_base,
                "id": "mft-normal",
                "row_number": 3,
                "entry_number": "12",
                "parent_path": "Users/fredr/Documents",
                "file_name": "normal.docx",
                "created_si": "2020-01-01 10:00:00",
                "modified_si": "2020-01-02 10:00:00",
            },
        ]
    )
    db.insert_shortcut_items(
        [
            {
                "id": "shortcut-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "copied.lnk",
                "artifact_path": "Users/fredr/Recent/copied.lnk",
                "file_name": "copied.docx",
                "file_location": "C:\\Users\\fredr\\Documents\\copied.docx",
                "target_created": "2020-01-02T10:00:00Z",
                "target_modified": "2020-01-01T10:00:00Z",
                "target_accessed": None,
                "device_type": "fixed",
                "volume_serial_number": None,
                "volume_name": None,
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": None,
            }
        ]
    )
    db.insert_shellbag_entries(
        [
            {
                "id": "shellbag-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-shellbag",
                "tool_name": "SBECmd",
                "source_csv": tmp_path / "SBECmd.csv",
                "row_number": 1,
                "source_file": "NTUSER.DAT",
                "hive_path": "Users/fredr/NTUSER.DAT",
                "user_profile": "fredr",
                "absolute_path": "C:\\Users\\fredr\\Documents\\Copied Folder",
                "shell_type": "Directory",
                "value_name": None,
                "mru_position": None,
                "slot": None,
                "node_slot": None,
                "created_on": "2020-01-02T10:00:00Z",
                "modified_on": "2020-01-01T10:00:00Z",
                "accessed_on": None,
                "last_write_time": None,
                "first_interacted": None,
                "last_interacted": None,
                "has_explored": "true",
                "drive_letter": "C:",
                "volume_guid": None,
                "volume_serial_number": None,
                "volume_name": None,
            }
        ]
    )
    db.insert_recmd_artifact_rows(
        {
            "registry_office_mru": [
                {
                    "id": "office-1",
                    "case_id": case.id,
                    "computer_id": "computer-1",
                    "image_id": "image-1",
                    "tool_output_id": "output-recmd",
                    "tool_name": "RECmd",
                    "source_csv": str(tmp_path / "RECmd.csv"),
                    "row_number": 1,
                    "hive_path": "NTUSER.DAT",
                    "hive_type": "ntuser",
                    "user_profile": "fredr",
                    "category": "user_activity",
                    "key_path": "Software\\Microsoft\\Office",
                    "value_name": "Item 1",
                    "batch_key_path": "Office",
                    "last_opened": "2020-01-04T10:00:00Z",
                    "file_name": "C:\\Users\\fredr\\Documents\\office.docx",
                    "created_at": "2020-01-05T00:00:00Z",
                }
            ]
        }
    )

    count = rebuild_copied_file_indicators(db, case_id=case.id, image_id="image-1")
    report = copied_file_indicators_report(db, case.id)
    full_report = copied_file_indicators_report(db, case.id, include_mft_only=True)
    source_types = {row["source_artifact_type"] for row in report["copied_file_indicators"]}
    full_source_types = {row["source_artifact_type"] for row in full_report["copied_file_indicators"]}

    assert count == 3
    assert source_types == {"lnk", "shellbag", "office_mru"}
    assert full_source_types == {"lnk", "shellbag", "office_mru"}
    assert all(row["created_timestamp_utc"] > row["modified_timestamp_utc"] for row in report["copied_file_indicators"])
    assert "normal.docx" not in {row["file_name"] for row in report["copied_file_indicators"]}


def test_common_dialog_pidl_shell_timestamps_feed_copied_file_indicators(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    raw = _pidl_item_with_times(
        "copied.docx",
        created=(2020, 1, 2, 10, 0, 0),
        modified=(2020, 1, 1, 10, 0, 0),
        accessed=(2020, 1, 3, 10, 0, 0),
    )
    db.insert_registry_artifacts(
        [
            {
                "id": "artifact-pidl",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-registry",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "RegistryArtifactParser.csv",
                "row_number": 1,
                "source_path": "NTUSER.DAT",
                "hive_type": "ntuser",
                "user_profile": "fredr",
                "artifact": "common_dialog",
                "category": "user_activity",
                "key_path": r"ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/OpenSavePidlMRU/docx",
                "key_last_write_utc": "2020-01-04T10:00:00Z",
                "event_time_utc": "2020-01-04T10:00:00Z",
                "recentdocs_time_utc": None,
                "recentdocs_extension_time_utc": None,
                "mru_position": "1",
                "recentdocs_mru_position": None,
                "recentdocs_extension_mru_position": None,
                "is_most_recent": "true",
                "value_name": "0",
                "value_type": "REG_BINARY",
                "value_data": raw.hex(),
                "display_name": None,
                "value_data_hex": raw.hex(),
                "transaction_logs_detected": "false",
                "transaction_logs_applied": "false",
                "transaction_log_paths": None,
                "notes": None,
            }
        ]
    )

    parsed_count = rebuild_common_dialog_items(db, case_id=case.id, image_id="image-1")
    indicator_count = rebuild_copied_file_indicators(db, case_id=case.id, image_id="image-1")
    common_dialog = common_dialog_items_report(db, case.id)
    copied = copied_file_indicators_report(db, case.id, source_artifact_type="opensavepidlmru")

    assert parsed_count == 1
    assert indicator_count == 1
    assert common_dialog["common_dialog_items"][0]["shell_item_name"] == "copied.docx"
    assert common_dialog["common_dialog_items"][0]["shell_created"] == "2020-01-02T10:00:00Z"
    assert copied["copied_file_indicators"][0]["file_name"] == "copied.docx"
    assert copied["copied_file_indicators"][0]["details"]["timestamp_source"] == "pidl_shell_item"


def test_copied_file_group_and_usb_reports(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_shortcut_items(
        [
            {
                "id": "shortcut-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "copied.lnk",
                "artifact_path": r"Users\fredr\Recent\copied.lnk",
                "file_name": "copied.docx",
                "file_location": r"E:\copied.docx",
                "target_created": "2020-01-02T10:00:00Z",
                "target_modified": "2020-01-01T10:00:00Z",
                "target_accessed": "2020-01-03T10:00:00Z",
                "device_type": "removable",
                "volume_serial_number": "2CB9F845",
                "volume_name": "USB",
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": None,
            },
            {
                "id": "shortcut-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-jump",
                "tool_name": "JLECmd",
                "source_csv": tmp_path / "JLECmd.csv",
                "row_number": 2,
                "artifact_type": "jumplist",
                "artifact_name": "app.automaticDestinations-ms",
                "artifact_path": r"Users\fredr\Recent\AutomaticDestinations\app.automaticDestinations-ms",
                "file_name": "copied.docx",
                "file_location": r"E:\copied.docx",
                "target_created": "2020-01-02T10:00:00Z",
                "target_modified": "2020-01-01T10:00:00Z",
                "target_accessed": "2020-01-04T10:00:00Z",
                "device_type": "removable",
                "volume_serial_number": "2CB9F845",
                "volume_name": "USB",
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": "7",
            },
        ]
    )
    db.insert_usb_storage_devices(
        [
            {
                "id": "usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "SERIAL1",
                "vendor_id": "13FE",
                "product_id": "4300",
                "vendor": "Vendor",
                "product": "USB DISK",
                "revision": None,
                "friendly_name": "USB DISK USB Device",
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": "E:",
                "volume_guid": None,
                "volume_serial_number": "2CB9-F845",
                "volume_name": "USB",
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": "fredr",
                "first_install_date_utc": "2020-01-01T09:00:00Z",
                "last_arrival_utc": "2020-01-03T09:00:00Z",
                "last_removal_utc": "2020-01-04T09:00:00Z",
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
                "created_at": "2020-01-05T00:00:00Z",
            }
        ]
    )

    rebuild_copied_file_indicators(db, case_id=case.id, image_id="image-1")
    grouped = copied_file_groups_report(db, case.id)
    usb = copied_usb_files_report(db, case.id, grouped=True)

    assert grouped["groups"][0]["indicator_count"] == 2
    assert set(grouped["groups"][0]["source_artifact_types"]) == {"lnk", "jumplist"}
    assert usb["devices"][0]["usb_serial"] == "SERIAL1"
    assert usb["groups"][0]["indicator_count"] == 2
    assert "consistent" not in usb["items"][0]["association_wording"].lower()


def test_file_names_report_groups_file_signals_across_artifacts(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_shortcut_items(
        [
            {
                "id": "shortcut-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "report.lnk",
                "artifact_path": r"Users\Jane\Recent\report.lnk",
                "file_name": "Report.docx",
                "file_location": r"C:\Users\Jane\Documents\Report.docx",
                "target_created": "2020-01-01T10:00:00Z",
                "target_modified": "2020-01-01T09:00:00Z",
                "target_accessed": "2020-01-02T10:00:00Z",
                "device_type": "fixed",
                "volume_serial_number": None,
                "volume_name": None,
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": None,
            }
        ]
    )
    db.insert_windows_activities(
        [
            {
                "id": "activity-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-activity",
                "tool_name": "WindowsActivitiesParser",
                "source_csv": tmp_path / "Activities.csv",
                "row_number": 1,
                "source_path": "Users/Jane/AppData/Local/ConnectedDevicesPlatform/ActivitiesCache.db",
                "user_profile": "Jane",
                "source_table": "Activity",
                "activity_id": "1",
                "app_id": "Word",
                "app_display_name": "Microsoft Word",
                "activity_type": "Open",
                "display_text": "Report.docx",
                "file_name": "Report.docx",
                "content_uri": "file:///C:/Users/Jane/Documents/Report.docx",
                "activation_uri": None,
                "fallback_uri": None,
                "start_time_utc": "2020-01-02T11:00:00Z",
                "end_time_utc": None,
                "last_modified_utc": None,
                "expiration_time_utc": None,
                "platform_device_id": None,
                "payload_json": "{}",
                "raw_json": "{}",
            }
        ]
    )
    db.insert_browser_downloads(
        [
            {
                "id": "download-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-browser",
                "tool_name": "ChromiumParser",
                "source_csv": tmp_path / "Downloads.csv",
                "row_number": 1,
                "browser": "Chrome",
                "source_path": "History",
                "profile_path": r"Users\Jane\AppData\Local\Google\Chrome\User Data\Default",
                "target_path": r"C:\Users\Jane\Downloads\Report.docx",
                "tab_url": "https://example.test/report",
                "site_url": "https://example.test/",
                "referrer": None,
                "start_time_utc": "2020-01-02T09:00:00Z",
                "end_time_utc": "2020-01-02T09:01:00Z",
                "received_bytes": "100",
                "total_bytes": "100",
                "state": "complete",
                "danger_type": None,
                "interrupt_reason": None,
            }
        ]
    )

    report = file_names_report(db, case.id, contains="report")

    assert report["total_file_names"] == 1
    item = report["file_names"][0]
    assert item["file_name"] == "Report.docx"
    assert item["evidence_count"] == 3
    assert item["source_count"] == 3
    assert set(item["sources"]) == {"browser_download:Chrome", "lnk", "windows_activities"}
    assert item["users"] == ["Jane"]
    assert "activity_cache_present" in item["evidence_tags"]
    assert "browser_download_present" in item["evidence_tags"]
    drilldown = file_name_drilldown_report(db, case.id, name="Report.docx", include_mft=False)
    assert drilldown["total_evidence_rows"] == 3
    assert set(drilldown["evidence_by_source"]) == {"shortcut_items", "windows_activities", "browser_downloads"}


def test_cloud_messaging_email_and_event_reports_use_existing_normalized_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-mft",
        "tool_name": "MFTECmd",
        "source_csv": tmp_path / "MFT.csv",
        "sequence_number": "1",
        "in_use": "True",
        "parent_entry_number": "1",
        "parent_sequence_number": "1",
        "file_size": "100",
        "is_directory": "False",
        "has_ads": "False",
        "is_ads": "False",
        "si_flags": None,
        "reparse_target": None,
        "si_fn_copied": None,
        "created_fn": None,
        "modified_fn": None,
        "record_changed_si": None,
        "record_changed_fn": None,
        "accessed_si": None,
        "accessed_fn": None,
        "source_file": "/artifacts/$MFT",
    }
    db.insert_mft_entries(
        [
            {
                **base,
                "id": "mft-cloud",
                "row_number": 1,
                "entry_number": "10",
                "parent_path": "Users/Jane/iCloudDrive/Documents",
                "file_name": "cloud.docx",
                "extension": "docx",
                "created_si": "2020-01-01T10:00:00Z",
                "modified_si": "2020-01-02T10:00:00Z",
            },
            {
                **base,
                "id": "mft-leveldb",
                "row_number": 2,
                "entry_number": "11",
                "parent_path": "Users/Jane/AppData/Roaming/Slack/Local Storage/leveldb",
                "file_name": "000003.ldb",
                "extension": "ldb",
                "created_si": "2020-01-01T10:00:00Z",
                "modified_si": "2020-01-02T10:00:00Z",
            },
            {
                **base,
                "id": "mft-email",
                "row_number": 3,
                "entry_number": "12",
                "parent_path": "Users/Jane/Documents",
                "file_name": "mail.pst",
                "extension": "pst",
                "created_si": "2020-01-01T10:00:00Z",
                "modified_si": "2020-01-02T10:00:00Z",
            },
        ]
    )
    db.insert_windows_search_email_indicators(
        [
            {
                "id": "email-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-search",
                "tool_name": "SIDR",
                "source_csv": tmp_path / "search.csv",
                "source_table": "SystemIndex",
                "source_record_id": "1",
                "row_number": 1,
                "email": "jane@example.test",
                "domain": "example.test",
                "evidence_field": "from",
                "evidence_value": "jane@example.test",
                "timestamp": "2020-01-02T10:00:00Z",
                "context_path": "mapi://message",
                "context_title": "Project Update",
            }
        ]
    )
    db.insert_windows_search_indexed_content(
        [
            {
                "id": "indexed-email-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-search",
                "tool_name": "SIDR",
                "source_csv": tmp_path / "search.csv",
                "source_table": "windows_search_files",
                "source_record_id": "search-file-1",
                "row_number": 2,
                "work_id": "100",
                "gather_time": "2020-01-02T11:00:00Z",
                "item_path": "/jane@example.test/Inbox/Azure/Get the most from your new virtual machine",
                "item_name": "",
                "item_type": "MAPI/IPM.Note.Read",
                "content_field": "_extra[3]",
                "content_text": "Get the most from your new virtual machine.",
                "content_length": 43,
                "timestamp": "2020-01-02T11:00:00Z",
                "created_at": "2020-01-02T11:00:00Z",
            }
        ]
    )
    db.insert_evtx_events(
        [
            {
                "id": "evtx-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 1,
                "record_number": "1",
                "event_record_id": "1",
                "time_created": "2020-01-02T11:00:00Z",
                "event_id": "1006",
                "level": "Information",
                "provider": "Microsoft-Windows-Partition/Diagnostic",
                "channel": "Microsoft-Windows-Partition/Diagnostic",
                "process_id": None,
                "thread_id": None,
                "computer": "HOST",
                "user_id": None,
                "map_description": "USB partition diagnostic",
                "user_name": None,
                "remote_host": None,
                "payload_data1": "USBSTOR",
                "payload_data2": None,
                "payload_data3": None,
                "executable_info": None,
                "source_file": "Microsoft-Windows-Partition%4Diagnostic.evtx",
                "payload": "{}",
            },
            {
                "id": "evtx-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 2,
                "record_number": "2",
                "event_record_id": "2",
                "time_created": "2020-01-02T12:00:00Z",
                "event_id": "20226",
                "level": "Information",
                "provider": "Microsoft-Windows-RasClient",
                "channel": "Microsoft-Windows-RasClient/Operational",
                "process_id": None,
                "thread_id": None,
                "computer": "HOST",
                "user_id": None,
                "map_description": "VPN connection disconnected",
                "user_name": None,
                "remote_host": None,
                "payload_data1": "vpn.example.test",
                "payload_data2": None,
                "payload_data3": None,
                "executable_info": None,
                "source_file": "Microsoft-Windows-RasClient%4Operational.evtx",
                "payload": "{}",
            }
        ]
    )

    cloud = cloud_artifacts_report(db, case.id)
    messaging = messaging_artifacts_report(db, case.id)
    email = email_artifacts_report(db, case.id)
    events = event_interpretation_report(db, case.id, category="usb")
    vpn_events = event_interpretation_report(db, case.id, category="vpn")

    assert cloud["cloud_artifacts"][0]["provider"] == "iCloud"
    assert messaging["messaging_artifacts"][0]["application"] == "Slack"
    assert "leveldb_candidate" in messaging["messaging_artifacts"][0]["evidence_tags"]
    assert {row["source"] for row in email["email_artifacts"]} == {
        "mft",
        "windows_search_email",
        "windows_search_indexed_email_content",
    }
    assert any(row["name"] == "Get the most from your new virtual machine" for row in email["email_artifacts"])
    assert email["deduplicated"]
    assert events["events"][0]["category"] == "usb"
    assert vpn_events["events"][0]["category"] == "vpn"
    assert "disconnected" in vpn_events["events"][0]["evidence_tags"]


def test_tool_run_summary_report_includes_outputs_and_activity(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.create_job(
        {
            "id": "job-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_name": "LECmd",
            "tool_version": "1.0",
            "command": ["LECmd", "-d", "Recent"],
            "start_time": "2020-01-01T00:00:00Z",
            "end_time": "2020-01-01T00:01:00Z",
            "exit_code": 0,
            "stdout_path": tmp_path / "stdout.txt",
            "stderr_path": tmp_path / "stderr.txt",
            "output_folder": tmp_path / "out",
        }
    )
    db.create_job(
        {
            "id": "job-2",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_name": "WindowsSearchESEParser",
            "tool_version": "1.0",
            "command": [
                "internal-windows-search-ese-parser",
                str(tmp_path / "artifacts" / "Windows.old" / "WindowsSearch" / "Applications" / "Windows"),
            ],
            "start_time": "2020-01-01T00:02:00Z",
            "end_time": "2020-01-01T00:02:01Z",
            "exit_code": 1,
            "stdout_path": tmp_path / "old.stdout.txt",
            "stderr_path": tmp_path / "old.stderr.txt",
            "output_folder": tmp_path / "outputs" / "Windows.old" / "WindowsSearchESEParser",
        }
    )
    (tmp_path / "old.stderr.txt").write_text(
        f"Windows.edb not found under {tmp_path / 'artifacts' / 'Windows.old' / 'WindowsSearch' / 'Applications' / 'Windows'}\n"
    )
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "LECmd",
            "output_type": "csv",
            "path": tmp_path / "LECmd.csv",
            "row_count": 2,
        }
    )
    db.log_activity(
        case_id=case.id,
        image_id="image-1",
        computer_id="computer-1",
        job_id="job-1",
        event="tool.warning",
        message="warning",
        level="warning",
        details={"source": "test"},
    )

    report = tool_run_summary_report(db, case.id)

    assert report["status_counts"] == {"completed": 1, "source_not_present": 1}
    assert report["tools"][0]["tool_name"] == "LECmd"
    assert report["tools"][1]["source_scopes"] == "Windows.old"
    assert report["tool_scopes"][1]["source_scope"] == "Windows.old"
    run_by_id = {row["id"]: row for row in report["runs"]}
    assert run_by_id["job-1"]["output_count"] == 1
    assert run_by_id["job-1"]["imported_row_count"] == 2
    assert {row["id"]: row["source_scope"] for row in report["runs"]} == {"job-1": "live", "job-2": "Windows.old"}
    assert run_by_id["job-1"]["warnings"][0]["event"] == "tool.warning"


def _pidl_item_with_times(
    name: str,
    *,
    created: tuple[int, int, int, int, int, int],
    modified: tuple[int, int, int, int, int, int],
    accessed: tuple[int, int, int, int, int, int],
) -> bytes:
    body = (
        b"\x31\x00"
        + b"\x04\x00\xef\xbe"
        + _fat_datetime(*created)
        + _fat_datetime(*modified)
        + _fat_datetime(*accessed)
        + name.encode("utf-16le")
        + b"\x00\x00"
    )
    return (len(body) + 2).to_bytes(2, "little") + body + b"\x00\x00"


def _fat_datetime(year: int, month: int, day: int, hour: int, minute: int, second: int) -> bytes:
    date = ((year - 1980) << 9) | (month << 5) | day
    time = (hour << 11) | (minute << 5) | (second // 2)
    return time.to_bytes(2, "little") + date.to_bytes(2, "little")


def test_usn_investigator_reports_filter_and_summarize_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-usn",
        "tool_name": "MFTECmdUSN",
        "source_csv": tmp_path / "USNJrnl.csv",
        "source_file": "/artifacts/$Extend/$J",
        "file_reference_sequence_number": "1",
        "parent_file_reference_sequence_number": "1",
        "reason_flags": None,
        "file_attributes": "Archive",
        "file_attributes_flags": None,
        "source_info": None,
        "security_id": None,
        "major_version": None,
        "minor_version": None,
        "record_length": None,
        "offset": None,
    }
    db.insert_usn_journal_entries(
        [
            {
                **base,
                "id": str(uuid.uuid4()),
                "row_number": 1,
                "update_sequence_number": "100",
                "update_timestamp": "2020-01-01 10:00:00",
                "file_name": "report.docx",
                "extension": "docx",
                "file_reference_number": "10",
                "parent_file_reference_number": "1",
                "full_path": ".\\Users\\fredr\\Documents",
                "reason": "FileCreate|Close",
            },
            {
                **base,
                "id": str(uuid.uuid4()),
                "row_number": 2,
                "update_sequence_number": "101",
                "update_timestamp": "2020-01-01 10:01:00",
                "file_name": "payload.exe",
                "extension": "exe",
                "file_reference_number": "11",
                "parent_file_reference_number": "1",
                "full_path": ".\\Users\\fredr\\Downloads",
                "reason": "DataExtend|FileCreate|Close",
            },
            {
                **base,
                "id": str(uuid.uuid4()),
                "row_number": 3,
                "update_sequence_number": "102",
                "update_timestamp": "2020-01-01 10:02:00",
                "file_name": "cache.tmp",
                "extension": "tmp",
                "file_reference_number": "12",
                "parent_file_reference_number": "2",
                "full_path": ".\\Users\\jean\\AppData\\Local\\Temp",
                "reason": "FileDelete|Close",
            },
        ]
    )

    summary = usn_summary_report(db, case.id)
    path = usn_path_report(db, case.id, contains="Downloads")
    user = usn_user_report(db, case.id, user="fredr")
    reasons = usn_reasons_report(db, case.id, reason="Delete")
    timeline = usn_timeline_report(db, case.id, user="fredr")
    suspicious = usn_suspicious_report(db, case.id)

    assert summary["total_rows"] == 3
    assert summary["time_range"]["first_update_timestamp"] == "2020-01-01 10:00:00"
    assert path["items"][0]["file_name"] == "payload.exe"
    assert {row["file_name"] for row in user["items"]} == {"report.docx", "payload.exe"}
    assert reasons["items"][0]["file_name"] == "cache.tmp"
    assert [row["file_name"] for row in timeline["timeline"]] == ["report.docx", "payload.exe"]
    assert {row["file_name"] for row in suspicious["items"]} == {"payload.exe", "cache.tmp"}


def test_sdelete_report_detects_repeated_letter_usn_rename_chain(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-usn",
        "tool_name": "MFTECmdUSN",
        "source_csv": tmp_path / "USNJrnl.csv",
        "source_file": "/artifacts/$Extend/$J",
        "file_reference_number": "42",
        "file_reference_sequence_number": "7",
        "parent_file_reference_number": "5",
        "parent_file_reference_sequence_number": "1",
        "reason_flags": None,
        "file_attributes": "Archive",
        "file_attributes_flags": None,
        "source_info": None,
        "security_id": None,
        "major_version": None,
        "minor_version": None,
        "record_length": None,
        "offset": None,
    }
    rows = [
        {
            **base,
            "id": str(uuid.uuid4()),
            "row_number": 1,
            "update_sequence_number": "100",
            "update_timestamp": "2020-01-01 10:00:00.0000000",
            "file_name": "secret.docx",
            "extension": ".docx",
            "full_path": ".\\Users\\Jean\\Desktop",
            "reason": "DataOverwrite|Close",
        }
    ]
    for index, letter in enumerate("ABCDEF", start=2):
        name = f"O{letter * 8}.{letter * 3}"
        rows.extend(
            [
                {
                    **base,
                    "id": str(uuid.uuid4()),
                    "row_number": index * 10,
                    "update_sequence_number": str(100 + index * 2),
                    "update_timestamp": f"2020-01-01 10:00:0{index}.0000000",
                    "file_name": name,
                    "extension": f".{letter * 3}",
                    "full_path": ".\\Users\\Jean",
                    "reason": "RenameNewName",
                },
                {
                    **base,
                    "id": str(uuid.uuid4()),
                    "row_number": index * 10 + 1,
                    "update_sequence_number": str(101 + index * 2),
                    "update_timestamp": f"2020-01-01 10:00:0{index}.0000000",
                    "file_name": name,
                    "extension": f".{letter * 3}",
                    "full_path": ".\\Users\\Jean",
                    "reason": "FileDelete|Close" if letter == "F" else "RenameOldName",
                },
            ]
        )
    db.insert_usn_journal_entries(rows)
    db.insert_onedrive_log_entries(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-odl",
                "tool_name": "OneDriveOdlParser",
                "source_csv": tmp_path / "odl.csv",
                "row_number": 1,
                "user_profile": "Jean",
                "account": "Personal",
                "source_path": "/logs/SyncEngine.odl",
                "source_name": "SyncEngine.odl",
                "log_type": "SyncEngine",
                "record_index": "1",
                "odl_version": "2",
                "one_drive_version": "",
                "windows_version": "",
                "timestamp_utc": "2020-01-01T10:00:07+00:00",
                "code_file": "Watcher.cpp",
                "function": "Watcher::ExamineChange",
                "flags": "",
                "context_data": "",
                "event_type": "delete",
                "local_path": "",
                "url": "",
                "resource_id": "abc!123",
                "params_text": r"FILE_ACTION_REMOVED: | %MountPoint%[abc!1]\Desktop\secret.docx",
                "params_json": "{}",
                "raw_strings_json": "[]",
                "parser_status": "parsed",
                "error": "",
            }
        ]
    )
    db.insert_prefetch_items(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-prefetch",
                "tool_name": "PrefetchParser",
                "source_csv": tmp_path / "PrefetchParser.csv",
                "row_number": 1,
                "prefetch_name": "SDELETE.EXE-0E837E93.pf",
                "artifact_path": "/artifacts/Prefetch/SDELETE.EXE-0E837E93.pf",
                "original_path": "Windows/Prefetch/SDELETE.EXE-0E837E93.pf",
                "executable_name": "SDELETE.EXE",
                "prefetch_hash": "0E837E93",
                "prefetch_version": "30",
                "prefetch_version_label": "Windows 10/11",
                "compression": "MAM",
                "run_count": "1",
                "last_run_time_utc": "2020-01-01T10:00:06Z",
                "last_run_times_utc": '["2020-01-01T10:00:06Z", "2020-01-01T09:59:00Z"]',
                "referenced_string_count": "2",
                "referenced_strings": '["SDELETE.EXE", "\\\\VOLUME{abc}\\\\USERS\\\\JEAN\\\\DESKTOP\\\\SECRET.DOCX"]',
                "parser_note": "Parsed",
                "pf_created": "2020-01-01T09:58:00Z",
                "pf_modified": "2020-01-01T10:00:06Z",
                "pf_accessed": "2020-01-01T10:00:06Z",
                "pf_mft_record_modified": "2020-01-01T10:00:06Z",
            }
        ]
    )
    db.insert_windows_search_gather_logs(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-gather",
                "tool_name": "WindowsSearchGatherParser",
                "source_csv": tmp_path / "WindowsSearchGatherLogs.csv",
                "row_number": 1,
                "source_file": "/Search/GatherLogs/SystemIndex/SystemIndex.1.gthr",
                "source_name": "SystemIndex.1.gthr",
                "log_type": "gthr",
                "line_number": 1,
                "timestamp_utc": "2020-01-01T10:00:05Z",
                "filetime_hex": "01d5c0a85d7d0000",
                "time_low_hex": "5d7d0000",
                "time_high_hex": "01d5c0a8",
                "item_url": "file:C:/Users/Jean/Desktop/secret.docx",
                "item_path": r"C:\Users\Jean\Desktop\secret.docx",
                "item_scheme": "file",
                "is_deleted_path": "false",
                "status_hex": "8000000c",
                "crawl_code_hex": "80041201",
                "scope_id": "8",
                "document_id": "10",
                "raw_fields_json": "[]",
                "created_at": "2020-01-01T10:00:05Z",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-gather",
                "tool_name": "WindowsSearchGatherParser",
                "source_csv": tmp_path / "WindowsSearchGatherLogs.csv",
                "row_number": 2,
                "source_file": "/Search/GatherLogs/SystemIndex/SystemIndex.1.gthr",
                "source_name": "SystemIndex.1.gthr",
                "log_type": "gthr",
                "line_number": 2,
                "timestamp_utc": "2020-01-01T10:00:06Z",
                "filetime_hex": "01d5c0a85e15ca00",
                "time_low_hex": "5e15ca00",
                "time_high_hex": "01d5c0a8",
                "item_url": "file:C:/Users/Jean/OZZZZZZZZ.ZZZ",
                "item_path": r"C:\Users\Jean\OZZZZZZZZ.ZZZ",
                "item_scheme": "file",
                "is_deleted_path": "false",
                "status_hex": "8000000c",
                "crawl_code_hex": "80041201",
                "scope_id": "8",
                "document_id": "11",
                "raw_fields_json": "[]",
                "created_at": "2020-01-01T10:00:06Z",
            },
        ]
    )

    report = sdelete_report(db, case.id)

    assert report["total_returned"] == 2
    item = next(row for row in report["items"] if row["classification"] == "sdelete_style_wipe_delete")
    assert item["original_file_name"] == "secret.docx"
    assert item["letters_seen"] == "ABCDEF"
    assert item["classification"] == "sdelete_style_wipe_delete"
    assert item["odl_correlation_count"] == 1
    assert item["odl_correlations"][0]["function"] == "Watcher::ExamineChange"
    assert item["deletion_timestamps"]
    assert item["recovered_timestamps"]
    assert item["filesystem_metadata"]["associated_artifacts"]
    sdelete_prefetch = item["filesystem_metadata"]["associated_artifacts"]["sdelete_prefetch"]
    assert sdelete_prefetch[0]["prefetch_name"] == "SDELETE.EXE-0E837E93.pf"
    assert sdelete_prefetch[0]["basis"] == "SDELETE prefetch execution within five minutes of USN wipe window"
    assert any(event["source"] == "sdelete_prefetch" and event["time_type"] == "prefetch_run_time" for event in item["recovered_timestamps"])
    assert item["filesystem_metadata"]["windows_search_gather_logs"][0]["item_path"] == r"C:\Users\Jean\Desktop\secret.docx"
    assert any(event["source"] == "windows_search_gather_logs" for event in item["recovered_timestamps"])
    possible = next(row for row in report["items"] if row["classification"].startswith("possible_sdelete"))
    assert possible["first_wipe_name"] == "OZZZZZZZZ.ZZZ"
    assert possible["basis"].startswith("Windows Search gather log observed")


def test_filesystem_review_combines_ntfs_sources(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "source_csv": tmp_path / "source.csv",
    }
    db.insert_mft_entries(
        [
            {
                **base,
                "id": str(uuid.uuid4()),
                "tool_name": "MFTECmd",
                "row_number": 1,
                "entry_number": "10",
                "sequence_number": "2",
                "in_use": "True",
                "parent_entry_number": "5",
                "parent_sequence_number": "1",
                "parent_path": ".\\Users\\Jean\\Desktop",
                "file_name": "report.docx",
                "extension": "docx",
                "file_size": "123",
                "is_directory": "False",
                "has_ads": "False",
                "is_ads": "False",
                "si_flags": "",
                "reparse_target": "",
                "si_fn_copied": "",
                "created_si": "2020-01-01 10:00:00",
                "created_fn": "2020-01-01 10:00:00",
                "modified_si": "2020-01-01 10:05:00",
                "modified_fn": "2020-01-01 10:05:00",
                "record_changed_si": "2020-01-01 10:06:00",
                "record_changed_fn": "2020-01-01 10:06:00",
                "accessed_si": "",
                "accessed_fn": "",
                "source_file": "/artifacts/$MFT",
            }
        ]
    )
    db.insert_usn_journal_entries(
        [
            {
                **base,
                "id": str(uuid.uuid4()),
                "tool_name": "MFTECmdUSN",
                "row_number": 1,
                "source_file": "/artifacts/$J",
                "update_sequence_number": "100",
                "update_timestamp": "2020-01-01 10:07:00",
                "file_name": "report.docx",
                "extension": "docx",
                "file_reference_number": "10",
                "file_reference_sequence_number": "2",
                "parent_file_reference_number": "5",
                "parent_file_reference_sequence_number": "1",
                "full_path": ".\\Users\\Jean\\Desktop",
                "reason": "FileDelete|Close",
                "reason_flags": "",
                "file_attributes": "Archive",
                "file_attributes_flags": "",
                "source_info": "",
                "security_id": "",
                "major_version": "",
                "minor_version": "",
                "record_length": "",
                "offset": "",
            }
        ]
    )
    db.insert_ntfs_logfile_entries(
        [
            {
                **base,
                "id": str(uuid.uuid4()),
                "tool_name": "MFTECmdLogFile",
                "row_number": 1,
                "source_file": "/artifacts/$LogFile",
                "event_time": "2020-01-01 10:08:00",
                "operation": "",
                "redo_operation": "DeleteFile",
                "undo_operation": "CreateFile",
                "target_attribute": "",
                "file_name": "report.docx",
                "file_path": ".\\Users\\Jean\\Desktop\\report.docx",
                "file_reference_number": "10",
                "file_reference_sequence_number": "2",
                "parent_file_reference_number": "5",
                "parent_file_reference_sequence_number": "1",
                "log_sequence_number": "200",
                "previous_log_sequence_number": "",
                "transaction_id": "tx-1",
                "client_id": "",
                "record_offset": "",
                "row_json": "{}",
            }
        ]
    )

    count = rebuild_filesystem_review(db, case_id=case.id, image_id="image-1")
    report = filesystem_review_report(db, case.id, contains="report.docx", limit=10)

    assert count == 3
    assert report["total_matching_rows"] == 3
    event_types = {row["event_type"] for row in report["filesystem_review"]}
    assert {"mft_record", "usn_delete", "logfile_delete"} == event_types


def test_filesystem_review_projects_windows_search_properties(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_windows_search_files(
        [
            {
                "id": "search-file-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "search-output-1",
                "tool_name": "WindowsSearchESEParser",
                "source_csv": tmp_path / "WindowsSearchESEParser.csv",
                "row_number": 1,
                "work_id": "10",
                "gather_time": "2020-01-01T10:04:00Z",
                "item_path": r"C:\Users\Jane\Pictures\photo.jpg",
                "item_url": "file:///C:/Users/Jane/Pictures/photo.jpg",
                "folder_path": r"C:\Users\Jane\Pictures",
                "file_name": "photo.jpg",
                "file_extension": ".jpg",
                "item_type": ".jpg",
                "date_created": "2020-01-01T10:00:00Z",
                "date_modified": "2020-01-01T10:01:00Z",
                "date_accessed": "2020-01-01T10:02:00Z",
                "date_imported": "",
                "size": "123",
                "owner": "Jane",
                "computer_name": "DESKTOP",
                "row_json": '{"System_IsFolder": "false"}',
            }
        ]
    )
    db.insert_windows_search_properties(
        [
            {
                "id": "search-prop-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "search-output-1",
                "tool_name": "WindowsSearchESEParser",
                "source_csv": tmp_path / "WindowsSearchESEParser.csv",
                "source_table": "windows_search_files",
                "source_record_id": "search-file-1",
                "row_number": 1,
                "work_id": "10",
                "item_path": r"C:\Users\Jane\Pictures\photo.jpg",
                "property_name": "4570-System_Photo_DateTaken",
                "property_value": "2020-01-01T09:59:00Z",
                "normalized_name": "",
                "timestamp": "2020-01-01T10:04:00Z",
            },
            {
                "id": "search-prop-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "search-output-1",
                "tool_name": "WindowsSearchESEParser",
                "source_csv": tmp_path / "WindowsSearchESEParser.csv",
                "source_table": "windows_search_files",
                "source_record_id": "search-file-1",
                "row_number": 1,
                "work_id": "10",
                "item_path": r"C:\Users\Jane\Pictures\photo.jpg",
                "property_name": "4406-System_GPS_LatitudeDecimal",
                "property_value": "51.5007",
                "normalized_name": "",
                "timestamp": "2020-01-01T10:04:00Z",
            },
            {
                "id": "search-prop-3",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "search-output-1",
                "tool_name": "WindowsSearchESEParser",
                "source_csv": tmp_path / "WindowsSearchESEParser.csv",
                "source_table": "windows_search_files",
                "source_record_id": "search-file-1",
                "row_number": 1,
                "work_id": "10",
                "item_path": r"C:\Users\Jane\Pictures\photo.jpg",
                "property_name": "4430-System_IsDeleted",
                "property_value": "true",
                "normalized_name": "",
                "timestamp": "2020-01-01T10:04:00Z",
            },
        ]
    )

    count = rebuild_filesystem_review(db, case_id=case.id, image_id="image-1")
    rows = query_rows(
        db,
        "filesystem_review",
        """
        SELECT event_type, event_time, file_name, file_path, operation, status, details_json
        FROM filesystem_review
        WHERE case_id = ? AND source_table = 'windows_search_properties'
        ORDER BY event_type
        """,
        [case.id],
    )
    history = file_history_report(db, case.id, name="photo.jpg", limit=10)

    assert count == 3
    assert {row["event_type"] for row in rows} == {
        "windows_search_deleted_state",
        "windows_search_gps_metadata",
        "windows_search_photo_metadata",
    }
    deleted = next(row for row in rows if row["event_type"] == "windows_search_deleted_state")
    assert deleted["status"] == "windows_search_deleted_path"
    assert deleted["file_path"] == r"C:\Users\Jane\Pictures\photo.jpg"
    assert any(event["source_table"] == "windows_search_properties" for event in history["events"])


def test_file_history_report_merges_filesystem_and_artifact_events(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.replace_filesystem_review(
        case_id=case.id,
        image_id="image-1",
        rows=[
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "source_table": "mft_entries",
                "source_id": "mft-1",
                "source_tool": "MFTECmd",
                "source_row_number": 1,
                "event_type": "mft_record",
                "event_time": "2020-01-01 10:00:00",
                "file_name": "report.docx",
                "file_path": ".\\Users\\Jean\\Desktop\\report.docx",
                "parent_path": ".\\Users\\Jean\\Desktop",
                "mft_entry_number": "10",
                "mft_sequence_number": "2",
                "parent_entry_number": "5",
                "parent_sequence_number": "1",
                "in_use": "True",
                "is_directory": "False",
                "operation": "",
                "reason": "mft_record_present",
                "status": "mft_in_use",
                "details_json": "{}",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "source_table": "usn_journal_entries",
                "source_id": "usn-1",
                "source_tool": "MFTECmdUSN",
                "source_row_number": 2,
                "event_type": "usn_delete",
                "event_time": "2020-01-01 10:05:00",
                "file_name": "report.docx",
                "file_path": ".\\Users\\Jean\\Desktop\\report.docx",
                "parent_path": ".\\Users\\Jean\\Desktop",
                "mft_entry_number": "10",
                "mft_sequence_number": "2",
                "parent_entry_number": "5",
                "parent_sequence_number": "1",
                "in_use": "",
                "is_directory": "False",
                "operation": "FileDelete|Close",
                "reason": "FileDelete|Close",
                "status": "filesystem_journal_event",
                "details_json": "{}",
            },
        ],
    )
    db.insert_shortcut_items(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "report.lnk",
                "artifact_path": ".\\Users\\Jean\\Recent\\report.lnk",
                "file_name": "report.docx",
                "file_location": ".\\Users\\Jean\\Desktop",
                "target_created": "2020-01-01 09:59:00",
                "target_modified": "2020-01-01 09:58:00",
                "target_accessed": "2020-01-01 10:04:00",
                "device_type": "",
                "volume_serial_number": "",
                "volume_name": "",
                "lnk_created": "",
                "lnk_modified": "",
                "lnk_accessed": "",
                "jumplist_item_number": "",
            }
        ]
    )
    db.insert_prefetch_items(
        [
            {
                "id": "prefetch-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-prefetch",
                "tool_name": "PrefetchParser",
                "source_csv": tmp_path / "PrefetchParser.csv",
                "row_number": 1,
                "prefetch_name": "WINWORD.EXE-12345678.pf",
                "artifact_path": ".\\Windows\\Prefetch\\WINWORD.EXE-12345678.pf",
                "executable_name": "WINWORD.EXE",
                "prefetch_hash": "12345678",
                "run_count": "3",
                "last_run_time_utc": "2020-01-01 10:03:00",
                "last_run_times_utc": '["2020-01-01 10:03:00"]',
                "referenced_strings": '["C:\\\\Users\\\\Jean\\\\Desktop\\\\report.docx"]',
            }
        ]
    )

    report = file_history_report(db, case.id, name="report.docx", limit=10)

    assert report["summary"]["filesystem_event_count"] == 2
    assert report["summary"]["artifact_event_count"] == 4
    assert [event["event_type"] for event in report["events"]] == [
        "target_modified",
        "target_created",
        "mft_record",
        "prefetch_file_reference",
        "target_accessed",
        "usn_delete",
    ]
    prefetch = next(event for event in report["events"] if event["event_type"] == "prefetch_file_reference")
    assert prefetch["details"]["prefetch_name"] == "WINWORD.EXE-12345678.pf"
    assert "file use context" in prefetch["reason"]
    assert report["events"][-1]["operation"] == "FileDelete|Close"


def test_file_history_report_ties_email_attachments_and_webcache_file_urls(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_mailbox_attachments([
        {
            "id": "attachment-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-mail",
            "tool_name": "MailboxParser",
            "source_csv": tmp_path / "MailboxAttachments.csv",
            "row_number": 1,
            "source_path": "mail/export.eml",
            "container_path": "/Users/Jane/AppData/Local/Microsoft/Outlook/mail.ost",
            "message_path": "/Users/Jane/Mail/message.eml",
            "user_profile": "Jane",
            "user_sid": "",
            "message_id": "<1@example.test>",
            "subject": "Here is the plan",
            "sender": "alice@example.test",
            "recipients": "jane@example.test",
            "message_date_utc": "2020-01-01T12:00:00Z",
            "attachment_name": "report.docx",
            "attachment_path": "/Users/Jane/AppData/Local/Temp/report.docx",
            "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "size": 100,
            "sha256": "abc",
            "extraction_status": "text_extracted",
            "dedupe_key": "attachment-1",
        }
    ])
    db.insert_webcache_file_accesses([
        {
            "id": "webcache-file-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-webcache",
            "tool_name": "WebCacheParser",
            "source_csv": tmp_path / "WebCacheEntries.csv",
            "row_number": 1,
            "source_webcache_entry_id": "webcache-entry-1",
            "source_database": "WebCacheV01.dat",
            "source_table": "Container_1",
            "user_name": "Jane",
            "application": "Microsoft Edge",
            "url": "file:///C:/Users/Jane/Documents/report.docx",
            "local_path": "C:\\Users\\Jane\\Documents\\report.docx",
            "normalized_path": "c:/users/jane/documents/report.docx",
            "file_name": "report.docx",
            "accessed_utc": "2020-01-02T12:00:00Z",
        }
    ])

    report = file_history_report(db, case.id, name="report.docx", limit=10)
    event_types = {event["event_type"] for event in report["events"]}

    assert "email_attachment_origin" in event_types
    assert "webcache_file_access" in event_types
    attachment = next(event for event in report["events"] if event["event_type"] == "email_attachment_origin")
    webcache = next(event for event in report["events"] if event["event_type"] == "webcache_file_access")
    assert attachment["details"]["subject"] == "Here is the plan"
    assert attachment["display_path"] == "/Users/Jane/AppData/Local/Temp/report.docx"
    assert webcache["display_path"] == "/Users/Jane/Documents/report.docx"


def test_usn_candidate_reports_explain_rules_mft_renames_bursts_and_usb(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-usn",
        "tool_name": "MFTECmdUSN",
        "source_csv": tmp_path / "USNJrnl.csv",
        "source_file": "/artifacts/$Extend/$J",
        "file_reference_sequence_number": "7",
        "parent_file_reference_sequence_number": "1",
        "reason_flags": None,
        "file_attributes": "Archive",
        "file_attributes_flags": None,
        "source_info": None,
        "security_id": None,
        "major_version": None,
        "minor_version": None,
        "record_length": None,
        "offset": None,
    }
    rows = [
        {
            **base,
            "id": str(uuid.uuid4()),
            "row_number": index,
            "update_sequence_number": str(100 + index),
            "update_timestamp": "2020-01-01 10:00:00",
            "file_name": f"burst-{index}.tmp",
            "extension": "tmp",
            "file_reference_number": str(1000 + index),
            "parent_file_reference_number": "1",
            "full_path": ".\\Users\\fredr\\Downloads",
            "reason": "FileCreate",
        }
        for index in range(1, 12)
    ]
    rows.extend(
        [
            {
                **base,
                "id": str(uuid.uuid4()),
                "row_number": 20,
                "update_sequence_number": "200",
                "update_timestamp": "2020-01-01 11:00:00",
                "file_name": "old.docx",
                "extension": "docx",
                "file_reference_number": "42",
                "parent_file_reference_number": "1",
                "full_path": ".\\Users\\fredr\\Documents",
                "reason": "RenameOldName",
            },
            {
                **base,
                "id": str(uuid.uuid4()),
                "row_number": 21,
                "update_sequence_number": "201",
                "update_timestamp": "2020-01-01 11:00:00",
                "file_name": "new.docx",
                "extension": "docx",
                "file_reference_number": "42",
                "parent_file_reference_number": "1",
                "full_path": ".\\Users\\fredr\\Documents",
                "reason": "RenameNewName",
            },
            {
                **base,
                "id": str(uuid.uuid4()),
                "row_number": 22,
                "update_sequence_number": "202",
                "update_timestamp": "2020-01-01 11:05:00",
                "file_name": "usbfile.docx",
                "extension": "docx",
                "file_reference_number": "99",
                "parent_file_reference_number": "1",
                "full_path": ".\\Users\\fredr\\Documents",
                "reason": "FileCreate|Close",
            },
            {
                **base,
                "id": str(uuid.uuid4()),
                "row_number": 23,
                "update_sequence_number": "203",
                "update_timestamp": "2020-01-01 11:06:00",
                "file_name": "cache.db-wal",
                "extension": "db-wal",
                "file_reference_number": "100",
                "parent_file_reference_number": "1",
                "full_path": ".\\Users\\fredr\\AppData\\Local\\Google\\Drive\\user_default",
                "reason": "FileDelete|Close",
            },
        ]
    )
    db.insert_usn_journal_entries(rows)
    db.insert_mft_entries(
        [
            {
                "id": "mft-99",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-mft",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "MFT.csv",
                "row_number": 1,
                "entry_number": "99",
                "sequence_number": "7",
                "in_use": "True",
                "parent_entry_number": "1",
                "parent_sequence_number": "1",
                "parent_path": "Users/fredr/Documents",
                "file_name": "usbfile.docx",
                "extension": ".docx",
                "file_size": "1234",
                "is_directory": "False",
                "has_ads": "False",
                "is_ads": "False",
                "si_flags": None,
                "reparse_target": None,
                "si_fn_copied": None,
                "created_si": "2020-01-01 11:05:00",
                "created_fn": None,
                "modified_si": "2020-01-01 11:05:00",
                "modified_fn": None,
                "record_changed_si": "2020-01-01 11:05:00",
                "record_changed_fn": None,
                "accessed_si": "2020-01-01 11:05:00",
                "accessed_fn": None,
                "source_file": "/artifacts/$MFT",
            }
        ]
    )
    db.insert_usb_file_correlations(
        [
            {
                "id": "usb-corr-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_serial": "SERIAL1",
                "usb_volume_serial_number": "A1B2-C3D4",
                "usb_volume_name": "USB",
                "usb_drive_letter": "E:",
                "usb_vendor_id": None,
                "usb_product_id": None,
                "usb_vendor": None,
                "usb_product": None,
                "usb_friendly_name": None,
                "usb_first_install_date_utc": None,
                "usb_last_arrival_utc": None,
                "usb_last_removal_utc": None,
                "source_artifact_type": "LNK",
                "source_artifact_id": "shortcut-1",
                "source_artifact_name": "usbfile.lnk",
                "source_artifact_path": "Users/fredr/Recent/usbfile.lnk",
                "user_profile": "fredr",
                "jumplist_item_number": None,
                "file_name": "usbfile.docx",
                "file_location": "E:\\Docs",
                "target_created": None,
                "target_modified": None,
                "target_accessed": None,
                "device_type": "removable",
                "artifact_volume_serial_number": "A1B2-C3D4",
                "artifact_volume_name": "USB",
                "artifact_volume_guid": None,
                "artifact_drive_letter": "E:",
                "volume_serial_match": "exact",
                "confidence": "high",
            }
        ]
    )

    user_files = usn_user_files_report(db, case.id, limit=10)
    user_files_suppressed = usn_user_files_report(db, case.id, limit=20, include_suppressed=True)
    renames = usn_rename_pairs_report(db, case.id)
    bursts = usn_bursts_report(db, case.id, minutes=5)
    usb = usn_usb_candidates_report(db, case.id)

    usbfile = next(row for row in user_files["items"] if row["file_name"] == "usbfile.docx")
    assert "common_document_extension" in usbfile["matched_rules"]
    assert usbfile["classification"] == "candidate_user_file_activity"
    assert usbfile["mft"]["id"] == "mft-99"
    assert any(row["file_name"] == "cache.db-wal" and row["suppressed_rules"] for row in user_files_suppressed["items"])
    assert renames["rename_pairs"][0]["old_name"] == "old.docx"
    assert renames["rename_pairs"][0]["new_name"] == "new.docx"
    assert bursts["bursts"][0]["count"] == 11
    assert usb["items"][0]["file_name"] == "usbfile.docx"
    assert usb["items"][0]["usb"]["volume_serial_number"] == "A1B2-C3D4"


def test_execution_report_extracts_prefetch_and_lnk_events(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    prefetch_rows = [
        {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "PrefetchParser",
                "source_csv": tmp_path / "PrefetchParser.csv",
                "row_number": 1,
                "prefetch_name": "CMD.EXE-12345678.pf",
                "artifact_path": "/artifacts/Prefetch/CMD.EXE-12345678.pf",
                "original_path": "Windows/Prefetch/CMD.EXE-12345678.pf",
                "executable_name": "CMD.EXE",
                "prefetch_hash": "12345678",
                "prefetch_version": "30",
                "prefetch_version_label": "Windows 10/11",
                "compression": "none",
                "run_count": "5",
                "last_run_time_utc": "2026-05-12T13:14:15Z",
                "last_run_times_utc": '["2026-05-12T13:14:15Z"]',
                "referenced_string_count": "1",
                "parser_note": "Parsed",
                "pf_created": "2026-05-12T12:00:00Z",
                "pf_modified": "2026-05-12T12:01:00Z",
                "pf_accessed": "2026-05-12T12:02:00Z",
                "pf_mft_record_modified": "2026-05-12T12:03:00Z",
        },
    ]
    shortcut_rows = [
        {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-2",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "app.lnk",
                "artifact_path": "/artifacts/lnk_files/Desktop/app.lnk",
                "file_name": "cmd.exe",
                "file_location": "C:/Windows/System32/cmd.exe",
                "target_created": "2026-05-11T10:00:00Z",
                "target_modified": None,
                "target_accessed": None,
                "device_type": None,
                "volume_serial_number": None,
                "volume_name": None,
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": None,
        }
    ]
    db.insert_prefetch_items(prefetch_rows)
    db.insert_shortcut_items(shortcut_rows)
    db.insert_timeline_events(timeline_events_from_rows(prefetch_rows + shortcut_rows))

    report = execution_report(db, case.id)

    assert report["total_events"] == 1
    assert [event["event_type"] for event in report["events"]] == [
        "prefetch_last_run",
    ]
    assert report["events"][0]["description"] == "CMD.EXE"
    assert report["events"][0]["details"]["pf_created"] == "2026-05-12T12:00:00Z"


def test_execution_report_labels_vsc_prefetch_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_prefetch_items([
        {
            "id": "vsc-prefetch-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "vss1-PrefetchParser",
            "tool_name": "PrefetchParser",
            "source_csv": tmp_path / "vss1" / "PrefetchParser.csv",
            "row_number": 1,
            "prefetch_name": "SDELETE.EXE-12345678.pf",
            "artifact_path": "snapshots/vss1/extract/Windows/Prefetch/SDELETE.EXE-12345678.pf",
            "original_path": "/Windows/Prefetch/SDELETE.EXE-12345678.pf",
            "executable_name": "SDELETE.EXE",
            "prefetch_hash": "12345678",
            "run_count": "1",
            "last_run_time_utc": "2020-11-10T10:00:00Z",
            "last_run_times_utc": '["2020-11-10T10:00:00Z"]',
            "source_scope": "VSC",
            "snapshot_id": "vss1",
            "snapshot_index": "1",
            "snapshot_created_utc": "2020-11-10T12:00:00Z",
        },
        {
            "id": "vsc-prefetch-2",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "vss2-PrefetchParser",
            "tool_name": "PrefetchParser",
            "source_csv": tmp_path / "vss2" / "PrefetchParser.csv",
            "row_number": 2,
            "prefetch_name": "SDELETE.EXE-12345678.pf",
            "artifact_path": "snapshots/vss2/extract/Windows/Prefetch/SDELETE.EXE-12345678.pf",
            "original_path": "/Windows/Prefetch/SDELETE.EXE-12345678.pf",
            "executable_name": "SDELETE.EXE",
            "prefetch_hash": "12345678",
            "run_count": "1",
            "last_run_time_utc": "2020-11-10T10:00:00Z",
            "last_run_times_utc": '["2020-11-10T10:00:00Z"]',
            "source_scope": "VSC",
            "snapshot_id": "vss2",
            "snapshot_index": "2",
            "snapshot_created_utc": "2020-11-10T13:00:00Z",
        }
    ])

    report = execution_report(db, case.id)
    markdown = execution_markdown(report)

    assert report["total_events"] == 1
    assert report["events"][0]["details"]["source_scope"] == "VSC"
    assert report["events"][0]["details"]["snapshot_id"] == "vss1"
    assert report["events"][0]["details"]["snapshots"] == ["vss1", "vss2"]
    assert "source_scope=VSC" in markdown
    assert "snapshots=vss1, vss2" in markdown


def test_suspicious_executions_report_combines_unusual_paths_commands_and_rules(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    prefetch_rows = [
        {
            "id": "pf-temp",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-1",
            "tool_name": "PrefetchParser",
            "source_csv": tmp_path / "PrefetchParser.csv",
            "row_number": 1,
            "prefetch_name": "PAYLOAD.EXE-12345678.pf",
            "artifact_path": "/artifacts/Prefetch/PAYLOAD.EXE-12345678.pf",
            "original_path": "Windows/Prefetch/PAYLOAD.EXE-12345678.pf",
            "executable_name": "PAYLOAD.EXE",
            "prefetch_hash": "12345678",
            "run_count": "1",
            "last_run_time_utc": "2026-05-12T13:14:15Z",
            "last_run_times_utc": '["2026-05-12T13:14:15Z"]',
            "resolved_reference_path": "C:/Users/mayas/AppData/Local/Temp/payload.exe",
        },
        {
            "id": "pf-sdelete",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-1",
            "tool_name": "PrefetchParser",
            "source_csv": tmp_path / "PrefetchParser.csv",
            "row_number": 2,
            "prefetch_name": "SDELETE.EXE-87654321.pf",
            "artifact_path": "/artifacts/Prefetch/SDELETE.EXE-87654321.pf",
            "original_path": "Windows/Prefetch/SDELETE.EXE-87654321.pf",
            "executable_name": "SDELETE.EXE",
            "prefetch_hash": "87654321",
            "run_count": "1",
            "last_run_time_utc": "2026-05-12T13:20:00Z",
            "last_run_times_utc": '["2026-05-12T13:20:00Z"]',
        },
    ]
    evtx_rows = [
        {
            "id": "evtx-powershell",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-2",
            "tool_name": "EvtxECmd",
            "source_csv": tmp_path / "Security.csv",
            "row_number": 1,
            "time_created": "2026-05-12T13:21:00Z",
            "event_id": "4688",
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "computer": "DESKTOP",
            "map_description": "A new process has been created",
            "executable_info": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "payload_data1": "powershell.exe -NoP -EncodedCommand SQBFAFgA",
        }
    ]
    db.insert_prefetch_items(prefetch_rows)
    db.insert_evtx_events(evtx_rows)
    db.insert_timeline_events(timeline_events_from_rows(prefetch_rows + evtx_rows))

    report = suspicious_executions_report(db, case.id, limit=10)

    categories = {row["category"] for row in report["findings"]}
    assert "unusual_execution_location" in categories
    assert "secure_deletion_wiping" in categories
    assert "suspicious_command_or_lolbin" in categories
    assert any(row["application"] == "PAYLOAD.EXE" for row in report["findings"])
    assert any("sdelete" in row["matched_rules"] for row in report["findings"])
    assert any("-encodedcommand" in row["matched_rules"] for row in report["findings"])
    assert any(row.get("nearby_context") for row in report["findings"])
    assert "Suspicious Executions" in suspicious_executions_markdown(report)

    triage = investigation_triage_dashboard_report(db, case.id, limit=10)
    triage_card_ids = {card["id"] for card in triage["cards"]}
    triage_markdown = investigation_triage_dashboard_markdown(triage)
    assert "suspicious_executions" in triage_card_ids
    assert triage["summary"]["suspicious_execution_findings"] >= 3
    assert any(row["category"] == "unusual_execution_location" for row in triage["top_suspicious_executions"])
    assert "Top Suspicious Executions" in triage_markdown


def test_userassist_reports_include_corroboration_caveat(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "tool_name": "RegistryArtifactParser",
        "source_csv": str(tmp_path / "RegistryArtifactParser.csv"),
        "row_number": 1,
    }
    db.insert_registry_artifacts([
        {
            **base,
            "id": "reg-userassist-1",
            "source_path": "/registry/NTUSER.DAT",
            "hive_type": "ntuser",
            "user_profile": "Jane",
            "artifact": "userassist",
            "category": "execution",
            "key_path": "Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist",
            "key_last_write_utc": "2020-01-02T10:00:00Z",
            "event_time_utc": "2020-01-02T10:00:00Z",
            "value_name": "P:/Gbbyncc/ncc.rkr",
            "value_type": "REG_BINARY",
            "value_data": "app.exe",
            "notes": "rot13_name=C:/Toolapp/app.exe",
        }
    ])
    db.insert_recmd_artifact_rows(
        {
            "registry_userassist": [
                {
                    **base,
                    "id": "ua-1",
                    "hive_path": "/registry/NTUSER.DAT",
                    "hive_type": "ntuser",
                    "user_profile": "Jane",
                    "category": "UserAssist",
                    "key_path": "Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist",
                    "key_last_write_timestamp": "2020-01-02T10:00:00Z",
                    "program_name": "app.exe",
                    "run_counter": "1",
                    "last_executed": "2020-01-02T10:00:00Z",
                }
            ]
        }
    )
    db.insert_timeline_events(timeline_events_from_rows([{
        **base,
        "id": "reg-userassist-1",
        "artifact": "userassist",
        "category": "execution",
        "event_time_utc": "2020-01-02T10:00:00Z",
        "display_name": "app.exe",
        "key_path": "Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist",
        "value_name": "P:/Gbbyncc/ncc.rkr",
        "value_data": "app.exe",
        "normalized_path": None,
        "notes": "rot13_name=C:/Toolapp/app.exe",
    }]))

    raw_report = registry_artifacts_report(db, case.id, artifact="userassist")
    activity_report = registry_activity_report(db, case.id, artifact="userassist")
    execution = execution_report(db, case.id)

    assert raw_report["caveats"]
    assert "corroborate" in raw_report["registry_artifacts"][0]["evidence_caveat"]
    assert "requires_corroboration" in raw_report["registry_artifacts"][0]["evidence_tags"]
    assert activity_report["caveats"]
    assert "corroborate" in activity_report["userassist"][0]["evidence_caveat"]
    assert execution["caveats"]
    assert execution["events"][0]["details"]["requires_corroboration"] is True


def test_execution_report_does_not_treat_amcache_as_execution(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-amcache",
        "tool_name": "AmcacheParser",
        "source_csv": tmp_path / "Amcache.csv",
        "row_number": 1,
    }
    db.insert_amcache_entries([
        {
            **base,
            "id": "amcache-1",
            "entry_type": "DriveBinary",
            "source_file": "Amcache.hve",
            "path": "C:/Tools/app.exe",
            "name": "app.exe",
            "modified_utc": "2020-01-02T10:00:00Z",
        }
    ])

    report = execution_report(db, case.id)

    assert report["total_events"] == 0
    assert report["summary"]["presence_indicator_returned"] == 1
    assert report["presence_indicators"][0]["source_table"] == "amcache_entries"
    assert "not standalone execution" in report["presence_indicators"][0]["details"]["evidence_caveat"]


def test_execution_report_lists_shimcache_as_presence_not_execution(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-shimcache",
        "tool_name": "AppCompatCacheParser",
        "source_csv": tmp_path / "AppCompatCache.csv",
        "source_file": "SYSTEM",
    }
    db.insert_shimcache_entries([
        {
            **base,
            "id": "shimcache-1",
            "row_number": 1,
            "path": "C:/Tools/seen-only.exe",
            "last_modified_utc": "2020-01-02T09:00:00Z",
            "executed": "False",
        },
        {
            **base,
            "id": "shimcache-2",
            "row_number": 2,
            "path": "C:/Tools/ran.exe",
            "last_modified_utc": "2020-01-02T10:00:00Z",
            "executed": "True",
        },
    ])

    report = execution_report(db, case.id)

    assert report["total_events"] == 0
    assert report["summary"]["presence_indicator_returned"] == 2
    paths = {row["path"] for row in report["presence_indicators"]}
    assert paths == {"C:/Tools/seen-only.exe", "C:/Tools/ran.exe"}
    assert {row["source_table"] for row in report["presence_indicators"]} == {"shimcache_entries"}


def test_execution_report_cleans_shimcache_and_sorts_deduped_app_summary(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_shimcache_entries([
        {
            **base,
            "id": "shimcache-1",
            "tool_output_id": "output-shimcache",
            "tool_name": "AppCompatCacheParser",
            "source_file": "SYSTEM",
            "path": "00000000\t000f0041004e0000\t000a000047ba0000\t014c\tMicrosoft.SkypeApp\tkzf8qxf38zg5c",
            "last_modified_utc": "2020-01-02T10:00:00Z",
            "executed": "True",
        }
    ])
    db.insert_prefetch_items([
        {
            **base,
            "id": "prefetch-1",
            "tool_output_id": "output-prefetch",
            "tool_name": "PrefetchParser",
            "prefetch_name": "BETA.EXE-12345678.pf",
            "executable_name": "BETA.EXE",
            "last_run_time_utc": "2020-01-02T10:00:00Z",
            "last_run_times_utc": '["2020-01-02T10:00:00Z", "2020-01-02T10:00:00Z"]',
            "run_count": "9",
        }
    ])

    report = execution_report(db, case.id)

    shimcache = next(event for event in report["presence_indicators"] if event["source_table"] == "shimcache_entries")
    assert shimcache["description"] == "Microsoft.SkypeApp"
    applications = {row["application"]: row for row in report["applications"]}
    assert list(applications) == sorted(applications, key=str.casefold)
    assert applications["BETA.EXE"]["event_count"] == 1
    assert applications["BETA.EXE"]["execution_count"] == 1


def test_interesting_executables_report_matches_editable_rules_across_run_and_presence(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    rules_path = tmp_path / "interesting.yaml"
    rules_path.write_text(
        """
interesting_executables:
  - id: sdelete
    label: SDelete Test Rule
    category: secure_deletion_wiping
    severity: high
    filenames: [sdelete64.exe]
    name_contains: [sdelete]
  - id: ccleaner
    label: CCleaner Test Rule
    category: cleanup_privacy
    severity: medium
    filenames: [ccleaner64.exe]
    name_contains: [ccleaner]
""",
        encoding="utf-8",
    )
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_prefetch_items([
        {
            **base,
            "id": "prefetch-sdelete",
            "tool_output_id": "output-prefetch",
            "tool_name": "PrefetchParser",
            "prefetch_name": "SDELETE64.EXE-12345678.pf",
            "artifact_path": "/artifacts/Windows/Prefetch/SDELETE64.EXE-12345678.pf",
            "executable_name": "SDELETE64.EXE",
            "last_run_time_utc": "2020-01-02T10:00:00Z",
            "last_run_times_utc": '["2020-01-02T10:00:00Z"]',
            "run_count": "1",
        }
    ])
    db.insert_amcache_entries([
        {
            **base,
            "id": "amcache-ccleaner",
            "tool_output_id": "output-amcache",
            "tool_name": "AmcacheParser",
            "source_file": "Amcache.hve",
            "path": "C:/Program Files/CCleaner/CCleaner64.exe",
            "name": "CCleaner64.exe",
            "modified_utc": "2020-01-01T12:00:00Z",
        }
    ])
    db.insert_registry_artifacts([
        {
            **base,
            "id": "reg-ccleaner-name",
            "tool_output_id": "output-registry",
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/SOFTWARE",
            "hive_type": "software",
            "artifact": "installed_applications",
            "category": "software",
            "key_path": "Microsoft/Windows/CurrentVersion/Uninstall/CCleaner",
            "key_last_write_utc": "2020-01-01T11:00:00Z",
            "value_name": "DisplayName",
            "value_type": "REG_SZ",
            "value_data": "CCleaner",
        },
        {
            **base,
            "id": "reg-ccleaner-path",
            "tool_output_id": "output-registry",
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/SOFTWARE",
            "hive_type": "software",
            "artifact": "installed_applications",
            "category": "software",
            "key_path": "Microsoft/Windows/CurrentVersion/Uninstall/CCleaner",
            "key_last_write_utc": "2020-01-01T11:00:00Z",
            "value_name": "DisplayIcon",
            "value_type": "REG_SZ",
            "value_data": "C:/Program Files/CCleaner/CCleaner64.exe",
        },
    ])
    db.insert_mft_entries([
        {
            **base,
            "id": "mft-sdelete",
            "tool_output_id": "output-mft",
            "tool_name": "MFTECmd",
            "file_name": "sdelete64.exe",
            "parent_path": "C:/Users/Jane/Downloads",
            "in_use": "True",
            "is_directory": "False",
            "created_si": "2020-01-01T09:00:00Z",
            "modified_si": "2020-01-01T09:05:00Z",
        }
    ])

    report = interesting_executables_report(db, case.id, rules_path=str(rules_path))
    markdown = interesting_executables_markdown(report)
    by_rule = {row["rule_id"]: row for row in report["applications"]}

    assert set(by_rule) == {"sdelete", "ccleaner"}
    assert by_rule["sdelete"]["has_run_evidence"] is True
    assert by_rule["sdelete"]["execution_evidence_count"] == 1
    assert by_rule["sdelete"]["file_system_count"] == 1
    assert by_rule["ccleaner"]["has_run_evidence"] is False
    assert by_rule["ccleaner"]["presence_count"] == 1
    assert by_rule["ccleaner"]["installed_application_count"] == 1
    assert "SDelete Test Rule" in markdown
    assert "run/process evidence `yes`" in markdown


def test_usb_file_correlation_matches_shortcuts_by_volume_serial(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_storage_devices(
        [
            {
                "id": "usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "USB123",
                "vendor_id": "1234",
                "product_id": "5678",
                "vendor": "Vendor",
                "product": "Thumb Drive",
                "revision": None,
                "friendly_name": "Vendor Thumb Drive",
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": "F:",
                "volume_guid": "{11111111-2222-3333-4444-555555555555}",
                "volume_serial_number": "ABCD-1234",
                "volume_name": "CASEUSB",
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": None,
                "first_install_date_utc": "2020-01-01T00:00:00Z",
                "last_arrival_utc": None,
                "last_removal_utc": None,
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
            },
            {
                "id": "usb-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "USB456",
                "vendor_id": None,
                "product_id": None,
                "vendor": "Vendor",
                "product": "Large Drive",
                "revision": None,
                "friendly_name": None,
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": "G:",
                "volume_guid": None,
                "volume_serial_number": "11111111-22222222",
                "volume_name": None,
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": None,
                "first_install_date_utc": None,
                "last_arrival_utc": None,
                "last_removal_utc": None,
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
            },
        ]
    )
    db.insert_shortcut_items(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "doc.lnk",
                "artifact_path": "/artifacts/lnk_files/fredr/AppData/Roaming/Microsoft/Windows/Recent/doc.lnk",
                "file_name": "doc.txt",
                "file_location": "F:\\doc.txt",
                "target_created": None,
                "target_modified": None,
                "target_accessed": None,
                "device_type": "removable",
                "volume_serial_number": "ABCD1234",
                "volume_name": "CASEUSB",
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": None,
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-2",
                "tool_name": "JLECmd",
                "source_csv": tmp_path / "JLECmd.csv",
                "row_number": 2,
                "artifact_type": "jumplist",
                "artifact_name": "autoDestinations-ms",
                "artifact_path": "/artifacts/jumplists/jean/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/autoDestinations-ms",
                "file_name": "image.jpg",
                "file_location": "G:\\image.jpg",
                "target_created": None,
                "target_modified": None,
                "target_accessed": None,
                "device_type": "removable",
                "volume_serial_number": "22222222",
                "volume_name": None,
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": "1",
            },
        ]
    )
    db.insert_shellbag_entries(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-3",
                "tool_name": "SBECmd",
                "source_csv": tmp_path / "SBECmd.csv",
                "row_number": 1,
                "source_file": "C:\\Users\\fredr\\NTUSER.DAT",
                "hive_path": "C:\\Users\\fredr\\NTUSER.DAT",
                "user_profile": "fredr",
                "absolute_path": "F:\\Folder",
                "shell_type": "Directory",
                "value_name": "Folder",
                "mru_position": "0",
                "slot": "1",
                "node_slot": "2",
                "created_on": "2020-01-02T00:00:00Z",
                "modified_on": None,
                "accessed_on": None,
                "last_write_time": None,
                "has_explored": "True",
                "drive_letter": None,
                "volume_guid": "{11111111-2222-3333-4444-555555555555}",
                "volume_serial_number": None,
                "volume_name": None,
            }
        ]
    )

    report = usb_file_correlation_report(db, case.id)

    assert report["total_returned"] == 3
    assert {row["file_name"] for row in report["items"] if row["file_name"]} == {"doc.txt", "image.jpg"}
    match_methods = {row["file_name"]: row["volume_serial_match"] for row in report["items"] if row["file_name"]}
    assert match_methods == {"doc.txt": "exact", "image.jpg": "suffix"}
    shellbag = [row for row in report["items"] if row["source_artifact_type"] == "shellbag"][0]
    assert shellbag["file_location"] == "F:\\Folder"
    assert shellbag["volume_serial_match"] == "volume_guid"
    assert shellbag["confidence"] == "high"
    users = {row["file_name"]: row["user_profile"] for row in report["items"]}
    assert users == {"doc.txt": "fredr", "image.jpg": "jean", None: "fredr"}
    grouped = usb_file_correlation_report(db, case.id, grouped=True)
    assert grouped["total_files"] == 3
    assert {row["user_profiles"] for row in grouped["files"]} == {"fredr", "jean"}
    timeline = usb_timeline_report(db, case.id)
    assert [event for event in timeline["events"] if event["event_type"] == "usb_first_connected"]


def test_shellbag_folder_tree_confidence_uses_corroborating_shortcuts(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_storage_devices(
        [
            {
                "id": "usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "USB123",
                "vendor_id": None,
                "product_id": None,
                "vendor": "Vendor",
                "product": "Thumb Drive",
                "revision": None,
                "friendly_name": None,
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": "AAAA-1111",
                "volume_name": "PRIMARY",
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": None,
                "first_install_date_utc": None,
                "last_arrival_utc": None,
                "last_removal_utc": None,
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
            },
            {
                "id": "usb-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "USB456",
                "vendor_id": None,
                "product_id": None,
                "vendor": "Vendor",
                "product": "Other Drive",
                "revision": None,
                "friendly_name": None,
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": "BBBB-2222",
                "volume_name": "OTHER",
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": None,
                "first_install_date_utc": None,
                "last_arrival_utc": None,
                "last_removal_utc": None,
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
            },
        ]
    )
    shortcut_rows = []
    for index, path in enumerate(["F:\\Cases\\a.docx", "F:\\Cases\\b.docx"], start=1):
        shortcut_rows.append(
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "JLECmd",
                "source_csv": tmp_path / "JLECmd.csv",
                "row_number": index,
                "artifact_type": "jumplist",
                "artifact_name": "autoDestinations-ms",
                "artifact_path": "/artifacts/jumplists/fredr/autoDestinations-ms",
                "file_name": Path(path).name,
                "file_location": path,
                "target_created": None,
                "target_modified": None,
                "target_accessed": None,
                "device_type": "removable",
                "volume_serial_number": "AAAA1111",
                "volume_name": "PRIMARY",
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": str(index),
            }
        )
    db.insert_shortcut_items(shortcut_rows)
    db.insert_shellbag_entries(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-2",
                "tool_name": "SBECmd",
                "source_csv": tmp_path / "SBECmd.csv",
                "row_number": 1,
                "source_file": "C:\\Users\\fredr\\UsrClass.dat",
                "hive_path": "C:\\Users\\fredr\\UsrClass.dat",
                "user_profile": "fredr",
                "absolute_path": "Desktop\\F:\\Cases",
                "shell_type": "Directory",
                "value_name": "Cases",
                "mru_position": "0",
                "slot": "1",
                "node_slot": "2",
                "created_on": None,
                "modified_on": None,
                "accessed_on": None,
                "last_write_time": None,
                "has_explored": "True",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": None,
                "volume_name": None,
            }
        ]
    )

    rows = [
        row
        for row in usb_file_correlation_report(db, case.id)["items"]
        if row["source_artifact_type"] == "shellbag"
    ]

    assert {(row["usb_volume_serial_number"], row["volume_serial_match"], row["confidence"]) for row in rows} == {
        ("AAAA-1111", "folder_tree", "high"),
        ("BBBB-2222", "drive_letter", "low"),
    }


def test_shellbag_interaction_time_upgrades_matching_usb_connection_window(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_storage_devices(
        [
            {
                "id": "usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "USB123",
                "vendor_id": None,
                "product_id": None,
                "vendor": None,
                "product": "Current Drive",
                "revision": None,
                "friendly_name": None,
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": "AAAA-1111",
                "volume_name": None,
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": None,
                "first_install_date_utc": "2020-01-02T10:00:00Z",
                "last_arrival_utc": "2020-01-02T10:00:00Z",
                "last_removal_utc": "2020-01-02T12:00:00Z",
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
            },
            {
                "id": "usb-2",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "USB456",
                "vendor_id": None,
                "product_id": None,
                "vendor": None,
                "product": "Old Drive",
                "revision": None,
                "friendly_name": None,
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": "BBBB-2222",
                "volume_name": None,
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": None,
                "first_install_date_utc": "2020-01-01T10:00:00Z",
                "last_arrival_utc": "2020-01-01T10:00:00Z",
                "last_removal_utc": "2020-01-01T12:00:00Z",
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
            },
        ]
    )
    db.insert_shellbag_entries(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "SBECmd",
                "source_csv": tmp_path / "SBECmd.csv",
                "row_number": 1,
                "source_file": "C:\\Users\\fredr\\UsrClass.dat",
                "hive_path": "C:\\Users\\fredr\\UsrClass.dat",
                "user_profile": "fredr",
                "absolute_path": "Desktop\\F:\\Cases",
                "shell_type": "Directory",
                "value_name": "Cases",
                "mru_position": "0",
                "slot": "1",
                "node_slot": "2",
                "created_on": None,
                "modified_on": None,
                "accessed_on": None,
                "last_write_time": None,
                "first_interacted": "2020-01-02 10:30:00",
                "last_interacted": "2020-01-02 10:45:00",
                "has_explored": "True",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": None,
                "volume_name": None,
            }
        ]
    )

    rows = [
        row
        for row in usb_file_correlation_report(db, case.id)["items"]
        if row["source_artifact_type"] == "shellbag"
    ]

    assert {(row["usb_volume_serial_number"], row["volume_serial_match"], row["confidence"]) for row in rows} == {
        ("AAAA-1111", "time_overlap", "medium"),
        ("BBBB-2222", "drive_letter", "low"),
    }


def test_shellbag_time_overlap_prefers_discrete_usb_sessions(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_storage_devices(
        [
            {
                "id": "usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "USB123",
                "vendor_id": None,
                "product_id": None,
                "vendor": None,
                "product": "Session Drive",
                "revision": None,
                "friendly_name": None,
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": "AAAA-1111",
                "volume_name": None,
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": None,
                "first_install_date_utc": "2020-01-01T00:00:00Z",
                "last_arrival_utc": "2020-01-10T00:00:00Z",
                "last_removal_utc": "2020-01-10T00:00:00Z",
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
            }
        ]
    )
    db.insert_usb_connection_events(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_device_id": "usb-1",
                "serial": "USB123",
                "volume_serial_number": "AAAA-1111",
                "volume_guid": None,
                "drive_letter": "F:",
                "event_time_utc": "2020-01-02T10:00:00Z",
                "event_type": "arrival",
                "event_source": "partition_diagnostic",
                "event_id": "1006",
                "record_number": "1",
                "source_path": "Partition Diagnostic",
                "key_path": None,
                "property_name": "PartitionDiagnostic:1006:VBR1",
                "property_value": None,
                "capacity_bytes": "1000",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_device_id": "usb-1",
                "serial": "USB123",
                "volume_serial_number": "AAAA-1111",
                "volume_guid": None,
                "drive_letter": "F:",
                "event_time_utc": "2020-01-02T12:00:00Z",
                "event_type": "removal",
                "event_source": "partition_diagnostic",
                "event_id": "1006",
                "record_number": "2",
                "source_path": "Partition Diagnostic",
                "key_path": None,
                "property_name": "PartitionDiagnostic:1006:VBR1",
                "property_value": None,
                "capacity_bytes": "0",
            },
        ]
    )
    db.insert_shellbag_entries(
        [
            {
                "id": "shellbag-in-session",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "SBECmd",
                "source_csv": tmp_path / "SBECmd.csv",
                "row_number": 1,
                "source_file": "C:\\Users\\fredr\\UsrClass.dat",
                "hive_path": "C:\\Users\\fredr\\UsrClass.dat",
                "user_profile": "fredr",
                "absolute_path": "Desktop\\F:\\During",
                "shell_type": "Directory",
                "value_name": "During",
                "mru_position": "0",
                "slot": "1",
                "node_slot": "2",
                "created_on": None,
                "modified_on": None,
                "accessed_on": None,
                "last_write_time": None,
                "first_interacted": "2020-01-02 10:30:00",
                "last_interacted": "2020-01-02 10:45:00",
                "has_explored": "True",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": None,
                "volume_name": None,
            },
            {
                "id": "shellbag-out-session",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "SBECmd",
                "source_csv": tmp_path / "SBECmd.csv",
                "row_number": 2,
                "source_file": "C:\\Users\\fredr\\UsrClass.dat",
                "hive_path": "C:\\Users\\fredr\\UsrClass.dat",
                "user_profile": "fredr",
                "absolute_path": "Desktop\\F:\\After",
                "shell_type": "Directory",
                "value_name": "After",
                "mru_position": "1",
                "slot": "1",
                "node_slot": "3",
                "created_on": None,
                "modified_on": None,
                "accessed_on": None,
                "last_write_time": None,
                "first_interacted": "2020-01-03 10:30:00",
                "last_interacted": "2020-01-03 10:45:00",
                "has_explored": "True",
                "drive_letter": "F:",
                "volume_guid": None,
                "volume_serial_number": None,
                "volume_name": None,
            },
        ]
    )

    rows = {
        row["source_artifact_name"]: row
        for row in usb_file_correlation_report(db, case.id)["items"]
        if row["source_artifact_type"] == "shellbag"
    }

    assert rows["During"]["volume_serial_match"] == "time_overlap"
    assert rows["During"]["confidence"] == "medium"
    assert rows["During"]["temporal_status"] == "within_known_connection"
    assert rows["After"]["volume_serial_match"] == "drive_letter"
    assert rows["After"]["confidence"] == "low"
    assert rows["After"]["temporal_status"] == "after_last_known_connection"


def test_usb_file_temporal_status_marks_ambiguous_when_multiple_devices_connected(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    storage_rows = []
    connection_rows = []
    for serial, vsn, drive in (("USB123", "AAAA-1111", "E:"), ("USB456", "BBBB-2222", "F:")):
        storage_rows.append(
            {
                "id": f"storage-{serial}",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": serial,
                "vendor_id": None,
                "product_id": None,
                "vendor": None,
                "product": "Thumb Drive",
                "revision": None,
                "friendly_name": None,
                "parent_id_prefix": None,
                "device_service": "USBSTOR",
                "drive_letter": drive,
                "volume_guid": None,
                "volume_serial_number": vsn,
                "volume_name": None,
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "user_profiles": None,
                "first_install_date_utc": "2020-01-02T09:00:00Z",
                "last_arrival_utc": "2020-01-02T10:00:00Z",
                "last_removal_utc": "2020-01-02T12:00:00Z",
                "first_volume_serial_event_utc": None,
                "last_partition_event_utc": None,
                "evidence_row_count": 1,
                "source_artifacts": "test",
            }
        )
        for event_type, timestamp, capacity in (("arrival", "2020-01-02T10:00:00Z", "1000"), ("removal", "2020-01-02T12:00:00Z", "0")):
            connection_rows.append(
                {
                    "id": str(uuid.uuid4()),
                    "case_id": case.id,
                    "computer_id": "computer-1",
                    "image_id": "image-1",
                    "usb_device_id": f"storage-{serial}",
                    "serial": serial,
                    "volume_serial_number": vsn,
                    "volume_guid": None,
                    "drive_letter": drive,
                    "event_time_utc": timestamp,
                    "event_type": event_type,
                    "event_source": "partition_diagnostic",
                    "event_id": "1006",
                    "record_number": "",
                    "source_path": "Partition Diagnostic",
                    "key_path": None,
                    "property_name": "PartitionDiagnostic:1006:VBR1",
                    "property_value": None,
                    "capacity_bytes": capacity,
                }
            )
    db.insert_usb_storage_devices(storage_rows)
    db.insert_usb_connection_events(connection_rows)
    db.insert_shortcut_items(
        [
            {
                "id": "lnk-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "out-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "Budget.lnk",
                "artifact_path": "/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/Budget.lnk",
                "file_name": "Budget.xlsx",
                "file_location": "E:\\Budget.xlsx",
                "target_created": "2020-01-02T10:30:00Z",
                "target_modified": "2020-01-02T10:31:00Z",
                "target_accessed": "2020-01-02T10:32:00Z",
                "device_type": "Removable",
                "volume_serial_number": "AAAA-1111",
                "volume_name": "",
                "command_line_arguments": "",
                "working_directory": "",
                "network_path": "",
                "machine_name": "",
                "app_id": "",
                "app_id_description": "",
                "entry_id": "",
                "destlist_version": "",
                "lnk_created": "",
                "lnk_modified": "",
                "lnk_accessed": "",
                "jumplist_item_number": "",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ]
    )

    row = usb_file_correlation_report(db, case.id)["items"][0]

    assert row["volume_serial_match"] == "exact"
    assert row["temporal_status"] == "ambiguous_multiple_devices_connected"
    assert "multiple external-storage sessions overlap" in row["temporal_basis"]


def test_usb_verbose_report_combines_device_evidence_and_files(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_usb_storage_devices(
        [
            {
                "id": "usb-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "serial": "USB123",
                "vendor_id": "1234",
                "product_id": "5678",
                "vendor": "Vendor",
                "product": "Thumb Drive",
                "revision": None,
                "friendly_name": "Vendor Thumb Drive",
                "parent_id_prefix": "PARENT",
                "device_service": "USBSTOR",
                "drive_letter": "F:",
                "volume_guid": "{11111111-2222-3333-4444-555555555555}",
                "volume_serial_number": "ABCD-1234",
                "volume_name": "CASEUSB",
                "capacity_bytes": "12345",
                "alternate_scsi_serial": None,
                "user_profiles": "fredr",
                "first_install_date_utc": "2020-01-01T00:00:00Z",
                "last_arrival_utc": "2020-01-02T00:00:00Z",
                "last_removal_utc": "2020-01-03T00:00:00Z",
                "first_volume_serial_event_utc": "2020-01-01T00:00:01Z",
                "last_partition_event_utc": "2020-01-03T00:00:01Z",
                "evidence_row_count": 2,
                "source_artifacts": "usb_device_history, partition_diagnostic",
            }
        ]
    )
    db.insert_usb_devices(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-usb",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "RegistryArtifactParser.csv",
                "row_number": 1,
                "source_path": "SYSTEM",
                "artifact": "usb_device_history",
                "device_type": "usb_storage",
                "vendor_id": "1234",
                "product_id": "5678",
                "vendor": "Vendor",
                "product": "Thumb Drive",
                "revision": None,
                "friendly_name": "Vendor Thumb Drive",
                "serial": "USB123",
                "instance_id": None,
                "parent_id_prefix": "PARENT",
                "device_service": "USBSTOR",
                "user_profile": None,
                "drive_letter": None,
                "volume_guid": None,
                "volume_serial_number": None,
                "volume_name": None,
                "capacity_bytes": None,
                "alternate_scsi_serial": None,
                "key_path": "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_Vendor&Prod_Thumb\\USB123",
                "key_last_write_utc": "2020-01-01T00:00:00Z",
                "property_name": None,
                "property_value": None,
                "value_data_hex": None,
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-usb",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "EvtxECmd.csv",
                "row_number": 2,
                "source_path": "Partition Diagnostic",
                "artifact": "partition_diagnostic",
                "device_type": "usb_partition_diagnostic",
                "vendor_id": None,
                "product_id": None,
                "vendor": None,
                "product": None,
                "revision": None,
                "friendly_name": None,
                "serial": "USB123",
                "instance_id": None,
                "parent_id_prefix": None,
                "device_service": None,
                "user_profile": None,
                "drive_letter": "F:",
                "volume_guid": "{11111111-2222-3333-4444-555555555555}",
                "volume_serial_number": "ABCD-1234",
                "volume_name": "CASEUSB",
                "capacity_bytes": "12345",
                "alternate_scsi_serial": None,
                "key_path": None,
                "key_last_write_utc": "2020-01-03T00:00:00Z",
                "property_name": "0067",
                "property_value": "last removal",
                "value_data_hex": None,
            },
        ]
    )
    db.insert_shortcut_items(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-lnk",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "doc.lnk",
                "artifact_path": "/artifacts/lnk/fredr/doc.lnk",
                "file_name": "doc.txt",
                "file_location": "F:\\doc.txt",
                "target_created": None,
                "target_modified": "2020-01-02T12:00:00Z",
                "target_accessed": None,
                "device_type": "removable",
                "volume_serial_number": "ABCD1234",
                "volume_name": "CASEUSB",
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": None,
            }
        ]
    )

    report = usb_verbose_report(db, case.id, serial="USB123")

    assert report["device"]["serial"] == "USB123"
    assert report["description_attributes"]["vid"] == "1234"
    assert report["volume_attributes"]["volume_serial_number"] == "ABCD-1234"
    assert report["mbr_vbr_details"]["available"] is True
    assert report["files_opened_accessed"][0]["file_location"] == "F:\\doc.txt"
    assert {row["artifact"] for row in report["raw_evidence_counts"]} == {
        "usb_device_history",
        "partition_diagnostic",
    }


def test_execution_report_extracts_evtx_events(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    evtx_rows = [
        {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "EvtxECmd.csv",
                "row_number": 1,
                "record_number": "1",
                "event_record_id": "2",
                "time_created": "2026-05-12T13:14:15Z",
                "event_id": "4688",
                "level": "Info",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "process_id": None,
                "thread_id": None,
                "computer": "HOST",
                "user_id": None,
                "map_description": "A new process has been created",
                "user_name": "Jean",
                "remote_host": None,
                "payload_data1": "Parent process: C:\\Windows\\explorer.exe",
                "payload_data2": None,
                "payload_data3": None,
                "executable_info": "C:\\Windows\\System32\\cmd.exe",
                "source_file": "/artifacts/Security.evtx",
                "payload": None,
        }
    ]
    db.insert_evtx_events(evtx_rows)
    db.insert_timeline_events(timeline_events_from_rows(evtx_rows))

    report = execution_report(db, case.id)

    assert report["total_events"] == 0
    assert len(report["process_activity"]) == 1
    assert report["process_activity"][0]["event_type"] == "windows_process_event"
    assert report["process_activity"][0]["description"] == "C:\\Windows\\System32\\cmd.exe"
    assert report["process_activity"][0]["details"]["event_id"] == "4688"


def test_shortcuts_report_returns_normalized_shortcut_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    shortcut_rows = [
        {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "app.lnk",
                "artifact_path": "/artifacts/lnk_files/Desktop/app.lnk",
                "file_name": "cmd.exe",
                "file_location": "C:/Windows/System32/cmd.exe",
                "target_created": "2026-05-11 09:00:00",
                "target_modified": "2026-05-11 09:01:00",
                "target_accessed": "2026-05-11 09:02:00",
                "device_type": "Fixed storage media (Hard drive)",
                "volume_serial_number": "744FC21F",
                "volume_name": "OS",
                "lnk_created": "2026-05-13 10:00:00",
                "lnk_modified": "2026-05-13 10:01:00",
                "lnk_accessed": "2026-05-13 10:02:00",
                "jumplist_item_number": None,
        }
    ]
    db.insert_shortcut_items(shortcut_rows)
    db.insert_timeline_events(timeline_events_from_rows(shortcut_rows))

    report = shortcuts_report(db, case.id, artifact_type="lnk")

    assert report["total_returned"] == 1
    assert report["shortcuts"][0]["artifact_name"] == "app.lnk"
    assert report["shortcuts"][0]["computer_label"] == "Desktop"


def test_files_report_includes_correlations(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_mft_entries(
        [
            {
                "id": "mft-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "mft-output",
                "tool_name": "MFTECmd",
                "source_csv": tmp_path / "MFTECmd.csv",
                "row_number": 1,
                "entry_number": "10",
                "sequence_number": None,
                "in_use": "True",
                "parent_entry_number": None,
                "parent_sequence_number": None,
                "parent_path": "Users/Devon/Desktop",
                "file_name": "report.docx",
                "extension": ".docx",
                "file_size": "100",
                "is_directory": "False",
                "has_ads": None,
                "is_ads": None,
                "si_fn_copied": None,
                "created_si": None,
                "created_fn": None,
                "modified_si": None,
                "modified_fn": None,
                "record_changed_si": None,
                "record_changed_fn": None,
                "accessed_si": None,
                "accessed_fn": None,
                "source_file": None,
            }
        ]
    )
    db.insert_file_correlations(
        [
            {
                "id": "corr-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "source_tool": "LECmd",
                "source_table": "shortcut_items",
                "source_row_id": "shortcut-1",
                "mft_entry_id": "mft-1",
                "match_type": "lnk_target_path",
                "confidence": "high",
                "source_path": "C:/Users/Devon/Desktop/report.docx",
                "mft_path": "Users/Devon/Desktop/report.docx",
            }
        ]
    )

    files = files_report(db, case.id, user="Devon")
    correlations = correlations_report(db, case.id)

    assert files["total_returned"] == 1
    assert files["files"][0]["correlations"][0]["source_tool"] == "LECmd"
    assert correlations["correlations"][0]["match_type"] == "lnk_target_path"


def test_execution_report_flags_lnk_target_created_after_modified_as_copied_file(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    shortcut_rows = [
        {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "copied.lnk",
                "artifact_path": "/artifacts/lnk_files/Desktop/copied.lnk",
                "file_name": "report.docx",
                "file_location": "C:/Users/Lee/Desktop/report.docx",
                "target_created": "2026-05-12T13:14:15Z",
                "target_modified": "2026-05-11T10:00:00Z",
                "target_accessed": None,
                "device_type": None,
                "volume_serial_number": None,
                "volume_name": None,
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": None,
        }
    ]
    db.insert_shortcut_items(shortcut_rows)
    db.insert_timeline_events(timeline_events_from_rows(shortcut_rows))

    report = execution_report(db, case.id)

    copied = [event for event in report["events"] if event["event_type"] == "copied_file_indicator"]
    assert len(copied) == 1
    assert copied[0]["details"]["classification"] == "copied_file"
    assert copied[0]["details"]["reason"] == "target creation time is after target modification time"


def test_execution_report_does_not_flag_normal_target_dates(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_shortcut_items(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-1",
                "tool_name": "JLECmd",
                "source_csv": tmp_path / "JLECmd.csv",
                "row_number": 1,
                "artifact_type": "jumplist",
                "artifact_name": "abc.automaticDestinations-ms",
                "artifact_path": "/artifacts/jumplists/abc.automaticDestinations-ms",
                "file_name": "report.docx",
                "file_location": "C:/Users/Lee/Desktop/report.docx",
                "target_created": "2026-05-11 10:00:00",
                "target_modified": "2026-05-12 13:14:15",
                "target_accessed": None,
                "device_type": None,
                "volume_serial_number": None,
                "volume_name": None,
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": "1",
            }
        ]
    )

    report = execution_report(db, case.id)

    assert not [event for event in report["events"] if event["event_type"] == "copied_file_indicator"]


def test_srum_network_reports_show_networks_vpns_and_app_usage(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-srum",
        "tool_name": "SrumParser",
        "source_csv": tmp_path / "SrumRecords.csv",
        "row_json": "{}",
    }
    db.insert_srum_records(
        [
            {
                **base,
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "row_number": 1,
                "record_type": "network_connectivity",
                "timestamp": "2020-10-20T17:39:00Z",
                "interface_type": "71",
                "interface_luid": "19985273102270464",
                "l2_profile_id": "268435457",
                "l2_profile_name": "FALCON",
                "connected_time": "3648",
                "connect_start_time": "2020-10-20T16:38:11Z",
                "user_name": "C:\\Users\\srl-h",
            },
            {
                **base,
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "row_number": 2,
                "record_type": "network_connectivity",
                "timestamp": "2020-10-20T18:00:00Z",
                "interface_type": "23",
                "interface_luid": "6473924464345088",
                "l2_profile_id": "0",
                "l2_profile_name": "",
                "connected_time": "600",
                "connect_start_time": "2020-10-20T17:50:00Z",
                "user_name": "C:\\Users\\srl-h",
                "vpn_profile_name": "Stark Research Labs",
                "vpn_server": "vpn.stark-research-labs.com:8443",
                "vpn_device": "WAN Miniport (SSTP)",
                "vpn_protocol": "SSTP",
                "vpn_phonebook_path": "Users/srl-h/AppData/Roaming/Microsoft/Network/Connections/Pbk/rasphone.pbk",
                "vpn_match_method": "single_profile",
            },
            {
                **base,
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "row_number": 3,
                "record_type": "network_usage",
                "timestamp": "2020-10-20T18:10:00Z",
                "app_name": "onedrive.exe",
                "app_path": "C:\\Users\\srl-h\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
                "user_name": "C:\\Users\\srl-h",
                "user_sid": "S-1-5-21-1-2-3-1001",
                "l2_profile_name": "FALCON",
                "bytes_received": "100",
                "bytes_sent": "40",
            },
            {
                **base,
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "row_number": 4,
                "record_type": "network_usage",
                "timestamp": "2020-10-20T18:20:00Z",
                "app_name": "onedrive.exe",
                "app_path": "C:\\Users\\srl-h\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
                "user_name": "C:\\Users\\srl-h",
                "user_sid": "S-1-5-21-1-2-3-1001",
                "l2_profile_name": "FALCON",
                "bytes_received": "200",
                "bytes_sent": "60",
            },
        ]
    )

    networks = srum_networks_report(db, case.id)
    assert [row["connection_type"] for row in networks["networks"]] == ["Wi-Fi", "PPP/VPN"]
    assert networks["networks"][0]["network_name"] == "FALCON"
    assert networks["networks"][1]["connection_type"] == "PPP/VPN"
    assert networks["networks"][1]["network_name"] == "Stark Research Labs"
    assert networks["networks"][1]["vpn_server"] == "vpn.stark-research-labs.com:8443"
    assert networks["networks"][1]["vpn_protocol"] == "SSTP"

    usage = srum_app_network_usage_report(db, case.id)
    assert usage["applications"][0]["application"] == "onedrive.exe"
    assert usage["applications"][0]["total_bytes_received"] == 300
    assert usage["applications"][0]["total_bytes_sent"] == 100
    assert usage["applications"][0]["total_bytes"] == 400


def test_ual_report_returns_logging_timeline_and_grouped_access(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Server")
    db.add_image("image-1", case.id, Path("/evidence/server.E01"), computer_id="computer-1")
    db.insert_tool_output(
        {
            "id": "output-ual",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "UalParser",
            "output_type": "csv",
            "path": tmp_path / "UalRecords.csv",
            "row_count": 1,
        }
    )
    db.insert_ual_records(
        [
            {
                "id": "ual-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-ual",
                "tool_name": "UalParser",
                "source_csv": tmp_path / "UalRecords.csv",
                "row_number": 1,
                "database_file": "Current.mdb",
                "source_table": "CLIENTS.4",
                "record_id": "1",
                "role_guid": "",
                "role_name": "File Server",
                "product_name": "",
                "tenant_id": "",
                "user_sid": "S-1-5-21-1",
                "user_name": "fredr",
                "client_name": "WORKSTATION01",
                "client_ip": "10.0.0.5",
                "client_id": "",
                "first_seen": "2020-10-20T17:06:59Z",
                "last_seen": "2020-10-21T18:00:00Z",
                "insert_date": "",
                "last_access": "",
                "access_count": "42",
                "activity_count": "",
                "day_count": "",
                "raw_time_bucket": "",
                "created_at": "2020-10-21T18:00:01Z",
            }
        ]
    )

    report = ual_report(db, case.id)

    assert [row["event_type"] for row in report["timeline"]] == ["ual_first_seen", "ual_last_seen"]
    assert report["timeline"][0]["role_name"] == "File Server"
    assert report["timeline"][0]["client_ip"] == "10.0.0.5"
    assert report["grouped_access"][0]["total_access_count"] == 42
    assert "per-access event logs" in report["summary"]["caveats"][0]


def test_vpn_activity_report_combines_network_config_events_and_execution(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output",
        "tool_name": "tool",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_srum_records([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "SrumParser",
            "record_type": "network_connectivity",
            "timestamp": "2020-10-20T18:00:00Z",
            "interface_type": "23",
            "connected_time": "600",
            "vpn_profile_name": "Stark Research Labs",
            "vpn_server": "vpn.stark-research-labs.com:8443",
            "vpn_protocol": "SSTP",
            "row_json": "{}",
        }
    ])
    db.insert_evtx_events([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "EvtxECmd",
            "time_created": "2020-10-20T18:01:00Z",
            "event_id": "20226",
            "provider": "Microsoft-Windows-RasClient",
            "channel": "Microsoft-Windows-RasClient/Operational",
            "map_description": "VPN connection established",
            "payload": "The user connected to vpn.stark-research-labs.com:8443",
            "source_file": "Microsoft-Windows-RasClient%4Operational.evtx",
        }
    ])
    db.insert_registry_artifacts([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/NTUSER.DAT",
            "hive_type": "ntuser",
            "user_profile": "fredr",
            "artifact": "ras_phonebook_registry",
            "category": "network",
            "key_path": "Software/Microsoft/RAS Phonebook/Stark Research Labs",
            "key_last_write_utc": "2020-10-20T17:59:00Z",
            "value_name": "PhoneNumber",
            "value_type": "REG_SZ",
            "value_data": "vpn.stark-research-labs.com:8443",
        }
    ])
    db.insert_prefetch_items([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "PrefetchParser",
            "prefetch_name": "RASPHONE.EXE-12345678.pf",
            "executable_name": "RASPHONE.EXE",
            "last_run_time_utc": "2020-10-20T17:58:00Z",
            "run_count": "1",
            "referenced_strings": "vpn.stark-research-labs.com",
        }
    ])

    report = vpn_activity_report(db, case.id, limit=20)

    source_types = {row["source_type"] for row in report["vpn_activity"]}
    assert {"srum_network_connectivity", "event_log", "registry_ras_phonebook_registry", "prefetch"} <= source_types
    assert any(row["server"] == "vpn.stark-research-labs.com:8443" for row in report["vpn_activity"])
    event_rows = [row for row in report["vpn_activity"] if row["source_type"] == "event_log"]
    assert event_rows[0]["activity_type"] == "disconnected"
    assert event_rows[0]["event"] == "VPN connection disconnected"

    connections = vpn_connections_report(db, case.id, limit=20)
    assert {"srum_network_connectivity", "event_log"} <= {row["source_type"] for row in connections["vpn_connections"]}

    config = vpn_config_report(db, case.id, limit=20)
    assert [row["source_type"] for row in config["vpn_config"]] == ["registry_ras_phonebook_registry"]

    execution = vpn_execution_report(db, case.id, limit=20)
    assert [row["source_type"] for row in execution["vpn_execution"]] == ["prefetch"]

    sessions = vpn_session_evidence_report(db, case.id, limit=20)
    assert sessions["summary"]["group_count"] >= 1
    assert any("event_log" in row["source_types"] for row in sessions["vpn_sessions"])


def test_operator_consolidation_reports(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_browser_history([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "ChromiumParser",
            "browser": "Chrome",
            "profile_path": "Users/Jane/AppData/Local/Google/Chrome/User Data/Default",
            "url": "https://example.test/report",
            "title": "Report",
            "visit_time_utc": "2020-01-02T10:00:00Z",
        }
    ])
    db.insert_browser_downloads([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "ChromiumParser",
            "browser": "Chrome",
            "profile_path": "Users/Jane/AppData/Local/Google/Chrome/User Data/Default",
            "target_path": "C:/Users/Jane/Downloads/report.docx",
            "start_time_utc": "2020-01-02T10:05:00Z",
        }
    ])
    db.insert_cloud_sync_artifacts([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "CloudSyncParser",
            "provider": "Google Drive",
            "artifact_type": "cloud_file",
            "user_profile": "Jane",
            "event_time_utc": "2020-01-02T10:10:00Z",
            "local_path": "C:/Users/Jane/Google Drive/report.docx",
            "cloud_path": "/Projects/report.docx",
            "file_name": "report.docx",
            "file_id": "file-1",
            "stable_id": "stable-1",
            "is_deleted": "false",
            "sync_status": "synced",
        }
    ])
    db.insert_google_drive_cache_map([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "CloudSyncParser",
            "account_id": "Jane",
            "stable_id": "stable-1",
            "file_id": "file-1",
            "virtual_path": "/Projects/report.docx",
            "file_name": "report.docx",
            "cache_id": "cache-1",
            "cache_path": "/cache/cache-1",
            "windows_cache_path": "C:/Users/Jane/AppData/Local/Google/DriveFS/cache/cache-1",
            "mapping_method": "stable_id",
        }
    ])
    db.insert_prefetch_items([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "PrefetchParser",
            "prefetch_name": "APP.EXE-12345678.pf",
            "executable_name": "APP.EXE",
            "last_run_time_utc": "2020-01-02T10:15:00Z",
            "run_count": "2",
            "artifact_path": "Windows/Prefetch/APP.EXE-12345678.pf",
        }
    ])
    db.insert_registry_artifacts([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/SOFTWARE",
            "hive_type": "software",
            "artifact": "autostart",
            "category": "execution",
            "key_path": "Microsoft/Windows/CurrentVersion/Run",
            "key_last_write_utc": "2020-01-02T10:16:00Z",
            "value_name": "App",
            "value_type": "REG_SZ",
            "value_data": "C:/Tools/app.exe",
            "normalized_path": "C:/Tools/app.exe",
        },
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/SYSTEM",
            "hive_type": "system",
            "artifact": "services",
            "category": "persistence",
            "key_path": "CurrentControlSet/Services/TestSvc",
            "key_last_write_utc": "2020-01-02T10:17:00Z",
            "value_name": "ImagePath",
            "value_type": "REG_SZ",
            "value_data": "C:/Tools/service.exe",
        },
    ])

    browser_profiles = browser_profile_activity_report(db, case.id)
    cloud_files = cloud_files_report(db, case.id)
    execution = execution_correlation_report(db, case.id)
    persistence = persistence_report(db, case.id)
    quality = evidence_quality_report(db, case.id)
    file_intel = file_intelligence_report(db, case.id, name="report.docx")

    assert browser_profiles["profiles"][0]["history_count"] == 1
    assert browser_profiles["profiles"][0]["download_count"] == 1
    assert {row["source_table"] for row in cloud_files["cloud_files"]} == {"cloud_sync_artifacts", "google_drive_cache_map"}
    assert any(row["source_count"] >= 1 for row in execution["execution_correlations"])
    assert {row["artifact"] for row in persistence["persistence_items"]} == {"autostart", "services"}
    assert "summary" in quality and "findings" in quality
    assert file_intel["summary"]["source_counts"]


def test_artifact_correlations_and_computer_inventory_reports(tmp_path):
    from forensic_orchestrator.artifact_correlations import rebuild_artifact_correlations
    from forensic_orchestrator.computer_inventory import rebuild_computer_inventory

    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_registry_artifacts([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/SOFTWARE",
            "hive_type": "software",
            "artifact": "install_time_software",
            "category": "system",
            "key_path": "ROOT/Microsoft/Windows NT/CurrentVersion",
            "value_name": "ProductName",
            "value_type": "REG_SZ",
            "value_data": "Windows 10 Pro",
        },
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/SOFTWARE",
            "hive_type": "software",
            "artifact": "install_time_software",
            "category": "system",
            "key_path": "ROOT/Microsoft/Windows NT/CurrentVersion",
            "value_name": "CurrentBuild",
            "value_type": "REG_SZ",
            "value_data": "19042",
        },
    ])
    db.insert_telemetry_artifacts([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "TelemetryParser",
            "record_type": "notifications_notification",
            "artifact_group": "notifications",
            "user_profile": "Jane",
            "application": "Contoso.App_123!App",
            "event_time_utc": "2020-01-02T10:00:00Z",
            "artifact_text": "Contoso notification",
        }
    ])
    db.insert_windows_activities([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "WindowsActivitiesParser",
            "source_path": "/ActivitiesCache.db",
            "user_profile": "Jane",
            "source_table": "Activity",
            "activity_id": "activity-1",
            "app_id": "Contoso.App_123!App",
            "start_time_utc": "2020-01-02T10:00:30Z",
        }
    ])

    inventory_count = rebuild_computer_inventory(db, case_id=case.id, image_id="image-1")
    correlation_count = rebuild_artifact_correlations(db, case_id=case.id, image_id="image-1")
    inventory = computer_inventory_report(db, case.id, category="os")
    correlations = artifact_correlations_report(db, case.id)

    assert inventory_count >= 3
    assert correlation_count == 1
    assert any(row["name"] == "windows_generation" and row["value"] == "Windows 10" for row in inventory["computer_inventory"])
    assert correlations["artifact_correlations"][0]["correlation_type"] == "notification_windows_activity_time_app"


def test_web_cloud_correlations_report_groups_webmail_and_cloud_sources(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "source_csv": tmp_path / "source.csv",
        "row_number": 1,
    }
    db.insert_browser_history([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "ChromiumParser",
            "browser": "Chrome",
            "profile_path": "Users/Jane/AppData/Local/Google/Chrome/User Data/Default",
            "url": "https://mail.google.com/mail/u/0/#inbox",
            "title": "Inbox",
            "visit_time_utc": "2020-01-02T10:00:00Z",
        }
    ])
    db.insert_webcache_entries([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "WebCacheParser",
            "source_database": "WebCacheV01.dat",
            "source_table": "Container_1",
            "table_row_number": "1",
            "url": "https://drive.google.com/file/d/abc/view",
            "host": "drive.google.com",
            "accessed_utc": "2020-01-02T10:01:00Z",
            "application": "Edge",
        }
    ])
    db.insert_shortcut_items([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "LECmd",
            "artifact_type": "lnk",
            "artifact_name": "report.lnk",
            "artifact_path": "Users/Jane/Desktop/report.lnk",
            "file_name": "report.docx",
            "file_location": "C:/Users/Jane/OneDrive/Documents/report.docx",
            "target_accessed": "2020-01-02T10:02:00Z",
        }
    ])
    db.insert_shellbag_entries([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "SBECmd",
            "source_file": "USRCLASS.DAT",
            "hive_path": "BagMRU",
            "user_profile": "Jane",
            "absolute_path": "C:/Users/Jane/Dropbox/Projects",
            "shell_type": "Directory",
            "last_interacted": "2020-01-02T10:03:00Z",
        }
    ])
    db.insert_registry_artifacts([
        {
            **base,
            "id": str(uuid.uuid4()),
            "tool_name": "RegistryArtifactParser",
            "source_path": "/registry/NTUSER.DAT",
            "hive_type": "ntuser",
            "user_profile": "Jane",
            "artifact": "typed_paths",
            "category": "user_activity",
            "key_path": "Explorer/TypedPaths",
            "key_last_write_utc": "2020-01-02T10:04:00Z",
            "value_name": "url1",
            "value_type": "REG_SZ",
            "value_data": "https://outlook.office.com/mail/",
        }
    ])

    report = web_cloud_correlations_report(db, case.id, limit=20)

    providers = {row["provider"] for row in report["web_cloud_correlations"]}
    sources = {row["source_table"] for row in report["web_cloud_correlations"]}
    assert {"Google Mail", "Google Drive", "OneDrive", "Dropbox", "Outlook Web"} <= providers
    assert {"browser_history", "webcache_entries", "shortcut_items", "shellbag_entries", "registry_artifacts"} <= sources
    assert any(group["provider"] == "Google Mail" and group["category"] == "webmail" for group in report["grouped"])


def test_application_security_and_virtualization_reports_use_general_indicators(tmp_path):
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
            "job_id": "job-1",
            "tool_name": "RegistryArtifactParser",
            "output_type": "csv",
            "path": tmp_path / "registry.csv",
            "row_count": 1,
        }
    )
    base = {
        "case_id": case.id,
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "tool_name": "RegistryArtifactParser",
        "source_csv": tmp_path / "registry.csv",
        "source_path": "/registry/SOFTWARE",
        "hive_type": "software",
        "category": "software",
        "key_path": "Microsoft/Windows/CurrentVersion/Uninstall",
    }
    db.insert_registry_artifacts([
        {
            **base,
            "id": str(uuid.uuid4()),
            "row_number": 1,
            "artifact": "installed_applications",
            "display_name": "Google Chrome",
            "value_name": "DisplayName",
            "value_data": "Google Chrome",
        }
    ])
    db.insert_prefetch_items([
        {
            "id": str(uuid.uuid4()),
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-1",
            "tool_name": "PrefetchParser",
            "source_csv": tmp_path / "prefetch.csv",
            "row_number": 1,
            "prefetch_name": "FIREFOX.EXE-ABCDEF01.pf",
            "executable_name": "firefox.exe",
            "original_path": r"C:\Users\Jane\Desktop\Tor Browser\Browser\firefox.exe",
            "referenced_strings": r"C:\Users\Jane\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\tor.exe",
            "last_run_time_utc": "2020-01-02T03:04:05Z",
        },
        {
            "id": str(uuid.uuid4()),
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-1",
            "tool_name": "PrefetchParser",
            "source_csv": tmp_path / "prefetch.csv",
            "row_number": 2,
            "prefetch_name": "VERACRYPT.EXE-ABCDEF02.pf",
            "executable_name": "veracrypt.exe",
            "original_path": r"C:\Program Files\VeraCrypt\VeraCrypt.exe",
            "last_run_time_utc": "2020-01-03T03:04:05Z",
        },
        {
            "id": str(uuid.uuid4()),
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-1",
            "tool_name": "PrefetchParser",
            "source_csv": tmp_path / "prefetch.csv",
            "row_number": 3,
            "prefetch_name": "VMWARE.EXE-ABCDEF03.pf",
            "executable_name": "vmware.exe",
            "original_path": r"C:\Program Files\VMware\VMware Workstation\vmware.exe",
            "last_run_time_utc": "2020-01-04T03:04:05Z",
        },
    ])

    uninstalled = uninstalled_application_artifacts_report(db, case.id, application="VeraCrypt")
    tor = tor_usage_report(db, case.id)
    encrypted = encrypted_volume_indicators_report(db, case.id)
    virtualization = virtualization_indicators_report(db, case.id)

    assert uninstalled["uninstalled_application_artifacts"][0]["application"] == "VeraCrypt"
    assert tor["tor_usage"][0]["source_table"] == "prefetch_items"
    assert encrypted["encrypted_volume_indicators"][0]["indicator_type"] == "VeraCrypt"
    assert virtualization["virtualization_indicators"][0]["platform"] == "VMware"


def test_phone_link_report_reads_package_artifacts(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_package_artifacts([
        {
            "id": str(uuid.uuid4()),
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "tool_output_id": "output-1",
            "tool_name": "PackageArtifactsParser",
            "source_csv": tmp_path / "PackageArtifacts.csv",
            "row_number": 1,
            "record_type": "phone_link_message",
            "user_profile": "Jane",
            "application_package": "Microsoft.YourPhone_8wekyb3d8bbwe",
            "source_path": r"C:\Users\Jane\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bbwe\LocalState\phone.db",
            "source_name": "Microsoft Phone Link",
            "file_name": "phone.db",
            "file_extension": ".db",
            "event_time_utc": "2020-01-02T03:04:05Z",
            "title": "+15551234567",
            "artifact_text": "Meet at 10",
            "details_json": "{}",
        }
    ])

    report = phone_link_report(db, case.id, record_type="phone_link_message", user="Jane")

    assert report["summary"]["record_counts"] == [{"record_type": "phone_link_message", "count": 1}]
    assert report["phone_link_artifacts"][0]["artifact_text"] == "Meet at 10"


def test_remote_access_report_correlates_vpn_rdp_and_cache(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    cache_file = tmp_path / "Users" / "fredr" / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache" / "Cache0000.bin"
    cache_file.parent.mkdir(parents=True)
    cache_file.write_bytes(b"cache")
    os.utime(cache_file, (1605330287.0, 1605330287.0))
    empty_cache_file = cache_file.with_name("bcache24.bmc")
    empty_cache_file.write_bytes(b"")
    os.utime(empty_cache_file, (1605330051.0, 1605330051.0))
    db.insert_evtx_events(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 1,
                "record_number": "1",
                "event_record_id": "1",
                "time_created": "2020-11-14 05:00:15.3753157",
                "event_id": "20221",
                "level": "Information",
                "provider": "RasClient",
                "channel": "Application",
                "process_id": None,
                "thread_id": None,
                "computer": "SRL-FORGE",
                "user_id": None,
                "map_description": "VPN connecting",
                "user_name": None,
                "remote_host": None,
                "payload_data1": "vpn.stark-research-labs.com:8443",
                "payload_data2": None,
                "payload_data3": None,
                "executable_info": None,
                "source_file": "Application.evtx",
                "payload": "vpn.stark-research-labs.com:8443 SSTP",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 2,
                "record_number": "2",
                "event_record_id": "2",
                "time_created": "2020-11-14 05:00:44.4090609",
                "event_id": "1024",
                "level": "Information",
                "provider": "Microsoft-Windows-TerminalServices-ClientActiveXCore",
                "channel": "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                "process_id": None,
                "thread_id": None,
                "computer": "SRL-FORGE",
                "user_id": None,
                "map_description": "RDP Client is trying to connect to the server",
                "user_name": None,
                "remote_host": None,
                "payload_data1": "Dest: base-rd-08.shieldbase.lan",
                "payload_data2": None,
                "payload_data3": None,
                "executable_info": None,
                "source_file": "RDPClient.evtx",
                "payload": "{}",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 3,
                "record_number": "3",
                "event_record_id": "3",
                "time_created": "2020-11-14 05:00:50.7768569",
                "event_id": "1102",
                "level": "Information",
                "provider": "Microsoft-Windows-TerminalServices-ClientActiveXCore",
                "channel": "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                "process_id": None,
                "thread_id": None,
                "computer": "SRL-FORGE",
                "user_id": None,
                "map_description": "RDP client has initiated a multi-transport connection to the server",
                "user_name": None,
                "remote_host": None,
                "payload_data1": "Address: 172.16.6.18",
                "payload_data2": None,
                "payload_data3": None,
                "executable_info": None,
                "source_file": "RDPClient.evtx",
                "payload": "{}",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 4,
                "record_number": "4",
                "event_record_id": "4",
                "time_created": "2020-11-14 05:00:51.2495735",
                "event_id": "1025",
                "level": "Information",
                "provider": "Microsoft-Windows-TerminalServices-ClientActiveXCore",
                "channel": "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                "process_id": None,
                "thread_id": None,
                "computer": "SRL-FORGE",
                "user_id": None,
                "map_description": "RDP ClientActiveX has connected to the server",
                "user_name": None,
                "remote_host": None,
                "payload_data1": None,
                "payload_data2": None,
                "payload_data3": None,
                "executable_info": None,
                "source_file": "RDPClient.evtx",
                "payload": "{}",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 5,
                "record_number": "5",
                "event_record_id": "5",
                "time_created": "2020-11-14 05:04:47.6244196",
                "event_id": "1026",
                "level": "Information",
                "provider": "Microsoft-Windows-TerminalServices-ClientActiveXCore",
                "channel": "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                "process_id": None,
                "thread_id": None,
                "computer": "SRL-FORGE",
                "user_id": None,
                "map_description": "RDP ClientActiveX has been disconnected",
                "user_name": None,
                "remote_host": None,
                "payload_data1": "Disconnect Reason: User-initiated client logoff",
                "payload_data2": None,
                "payload_data3": None,
                "executable_info": None,
                "source_file": "RDPClient.evtx",
                "payload": "{}",
            },
        ]
    )
    db.insert_rdp_cache_items(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-rdp",
                "tool_name": "RdpCacheParser",
                "source_csv": tmp_path / "rdp.csv",
                "row_number": 1,
                "record_type": "cache_file",
                "user_profile": "fredr",
                "source_cache_path": str(cache_file),
                "file_name": "Cache0000.bin",
                "parser_status": "found",
                "details_json": "{}",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-rdp",
                "tool_name": "RdpCacheParser",
                "source_csv": tmp_path / "rdp.csv",
                "row_number": 2,
                "record_type": "cache_file",
                "user_profile": "fredr",
                "source_cache_path": str(empty_cache_file),
                "file_name": "bcache24.bmc",
                "file_size": "0",
                "parser_status": "found",
                "details_json": "{}",
            }
        ]
    )
    db.insert_rdp_visual_observations(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-rdp",
                "tool_name": "ManualVisualReview",
                "source_csv": None,
                "row_number": 1,
                "user_profile": "fredr",
                "source_cache_path": str(cache_file),
                "contact_sheet_path": str(tmp_path / "contact-sheet.jpg"),
                "observation_time_utc": "2020-11-14 05:04:47.734438",
                "time_basis": "source_cache_file_mtime",
                "observation_type": "application_visible",
                "observed_application": "File Explorer",
                "observed_text": "OneDrive - Stark Research Labs",
                "observed_path": "",
                "certainty": "visual_observation_not_execution_proof",
                "caveat": "RDP bitmap cache shows remote screen content, not execution by itself.",
                "details_json": "{}",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-rdp",
                "tool_name": "ManualVisualReview",
                "source_csv": None,
                "row_number": 2,
                "user_profile": "fredr",
                "source_cache_path": str(empty_cache_file),
                "contact_sheet_path": str(tmp_path / "empty-contact-sheet.jpg"),
                "observation_time_utc": "2020-11-14 05:00:51",
                "time_basis": "source_cache_file_mtime",
                "observation_type": "application_visible",
                "observed_application": "Should Not Appear",
                "observed_text": "This stale row came from a zero-byte cache file",
                "observed_path": "",
                "certainty": "stale_bad_attribution",
                "caveat": "This row should be ignored because the source cache file is empty.",
                "details_json": "{}",
            }
        ]
    )
    db.insert_shortcut_items(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-jlecmd",
                "tool_name": "JLECmd",
                "source_csv": tmp_path / "JLECmd.csv",
                "row_number": 1,
                "artifact_type": "jumplist",
                "artifact_name": "1bc392b8e104a00e.automaticDestinations-ms",
                "artifact_path": "/Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/1bc392b8e104a00e.automaticDestinations-ms",
                "file_name": "base-rd-08.rdp",
                "file_location": "C:\\Users\\fredr\\Documents\\base-rd-08.rdp",
                "target_accessed": "2020-11-14 05:00:45",
                "app_id": "1bc392b8e104a00e",
                "app_id_description": "Remote Desktop Connection",
                "jumplist_item_number": "3",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-lecmd",
                "tool_name": "LECmd",
                "source_csv": tmp_path / "LECmd.csv",
                "row_number": 1,
                "artifact_type": "lnk",
                "artifact_name": "CorpVPN.lnk",
                "artifact_path": "/Users/fredr/Desktop/CorpVPN.lnk",
                "file_name": "CorpVPN.exe",
                "file_location": "C:\\Program Files\\CorpVPN\\CorpVPN.exe",
                "target_accessed": "2020-11-14 05:00:20",
                "command_line_arguments": "connect vpn.stark-research-labs.com",
            },
        ]
    )
    db.insert_registry_artifacts(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-registry",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "registry.csv",
                "row_number": 1,
                "source_path": "registry/SOFTWARE",
                "hive_type": "software",
                "artifact": "connected_networks",
                "category": "network",
                "key_path": "ROOT/Microsoft/Windows NT/CurrentVersion/NetworkList/Profiles/{A01072CF-A032-4CE1-B453-0A99AEB511EA}",
                "key_last_write_utc": "2020-11-14T05:00:17.050898Z",
                "event_time_utc": None,
                "value_name": "ProfileName",
                "value_type": "REG_SZ",
                "value_data": "Stark Research Labs",
                "display_name": "Stark Research Labs",
                "notes": "registry transaction logs detected but not applied by the internal parser",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-registry",
                "tool_name": "RegistryArtifactParser",
                "source_csv": tmp_path / "registry.csv",
                "row_number": 2,
                "source_path": "registry/SOFTWARE",
                "hive_type": "software",
                "artifact": "connected_networks",
                "category": "network",
                "key_path": "ROOT/Microsoft/Windows NT/CurrentVersion/NetworkList/Profiles/{5C71858D-BB16-4509-8460-FCC66717F24E}",
                "key_last_write_utc": "2020-11-07T21:32:02.176034Z",
                "event_time_utc": None,
                "value_name": "ProfileName",
                "value_type": "REG_SZ",
                "value_data": "xfinitywifi",
                "display_name": "xfinitywifi",
                "notes": "registry transaction logs detected but not applied by the internal parser",
            }
        ]
    )

    report = remote_access_sessions_report(db, case.id)

    assert report["summary"]["rdp_session_count"] == 1
    assert {"source_type": "registry_connected_networks", "count": 1} in report["summary"]["vpn_context_source_counts"]
    session = report["remote_access_sessions"][0]
    assert session["remote_host"] == "base-rd-08.shieldbase.lan"
    assert session["remote_ip"] == "172.16.6.18"
    assert session["vpn_event_count"] == 3
    assert session["rdp_cache_file_count"] == 1
    assert session["rdp_cache_files"][0]["file_name"] == "Cache0000.bin"
    assert session["rdp_shortcut_file_count"] == 1
    assert session["rdp_shortcut_files"][0]["file_name"] == "base-rd-08.rdp"
    assert session["rdp_visual_observation_count"] == 1
    assert session["rdp_visual_observations"][0]["observed_application"] == "File Explorer"
    assert "vpn_activity_time_overlap" in session["correlation_basis"]
    assert "rdp_visual_observation" in session["correlation_basis"]
    assert "rdp_shortcut_or_jumplist_time_overlap" in session["correlation_basis"]
    markdown = rdp_remote_access_markdown(report)
    assert "Should Not Appear" not in markdown
    assert "# RDP Remote Access Report" in markdown
    assert "## Evidence Model" in markdown
    assert "### RDP Event Log Evidence" in markdown
    assert "Source table: `evtx_events`" in markdown
    assert "RDPClient.evtx" in markdown
    assert "### VPN Overlap Evidence" in markdown
    assert "Application.evtx" in markdown
    assert "shortcut_items_lnk" in markdown
    assert "CorpVPN.exe" in markdown
    assert "Stark Research Labs" in markdown
    assert "registry_connected_networks" in markdown
    assert "xfinitywifi" not in markdown
    assert "### RDP Bitmap Cache Evidence" in markdown
    assert "Cache0000.bin" in markdown
    assert "### RDP Shortcut and Jump List Evidence" in markdown
    assert "base-rd-08.rdp" in markdown
    assert "Remote Desktop Connection" in markdown
    assert "### Visual Observations" in markdown
    assert session["rdp_visual_observations"][0]["interpretation_level"] == "semantic"
    assert "Semantic visual interpretations" in markdown
    assert "contact-sheet.jpg" in markdown


def test_remote_access_attribution_report_correlates_incoming_auth_usb_and_cloud_context(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_evtx_events(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 1,
                "record_number": "1",
                "event_record_id": "1",
                "time_created": "2020-11-14 05:10:00.0000000",
                "event_id": "4625",
                "level": "Information",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "SRL-FORGE",
                "user_name": "-\\-",
                "remote_host": "cobra (52.249.198.56)",
                "payload_data1": "Target: SRL-FORGE\\fredr",
                "payload_data2": "LogonType 10",
                "payload_data3": "FailureReason1: the cause is either a bad username or authentication information",
                "payload_data4": "FailureReason2: user name is correct but the password is wrong",
                "map_description": "Failed logon",
                "source_file": "Security.evtx",
                "payload": "{}",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 2,
                "record_number": "2",
                "event_record_id": "2",
                "time_created": "2020-11-14 05:12:00.0000000",
                "event_id": "4624",
                "level": "Information",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "SRL-FORGE",
                "user_name": "SRL-FORGE\\fredr",
                "remote_host": "cobra (52.249.198.56)",
                "payload_data1": "Target: SRL-FORGE\\fredr",
                "payload_data2": "LogonType 10",
                "payload_data3": "LogonId: 0x123",
                "map_description": "Successful logon",
                "source_file": "Security.evtx",
                "payload": "{}",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 3,
                "record_number": "3",
                "event_record_id": "3",
                "time_created": "2020-11-14 05:30:00.0000000",
                "event_id": "4779",
                "level": "Information",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "computer": "SRL-FORGE",
                "user_name": "SRL-FORGE\\fredr",
                "remote_host": "cobra (52.249.198.56)",
                "payload_data1": "RDP-Tcp#7",
                "payload_data3": "LogonId: 0x123",
                "map_description": "RDP disconnecting",
                "source_file": "Security.evtx",
                "payload": "{}",
            },
        ]
    )
    db.insert_usb_connection_events(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "usb_device_id": "usb-1",
                "serial": "USB123",
                "volume_serial_number": "ABCD-1234",
                "volume_guid": "{volume-guid}",
                "drive_letter": "E:",
                "event_time_utc": "2020-11-14 05:00:00",
                "event_type": "arrival",
                "event_source": "partition_diagnostic",
                "event_id": "1006",
                "source_path": "Partition.evtx",
            }
        ]
    )
    db.insert_windows_search_indexed_content(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-search",
                "tool_name": "WindowsSearchParser",
                "source_csv": tmp_path / "search.csv",
                "source_table": "SystemIndex_0A",
                "source_record_id": "77",
                "row_number": 77,
                "work_id": "77",
                "gather_time": "2020-11-14 05:15:00",
                "timestamp": "2020-11-14 05:15:00",
                "item_path": "/fred.rocba@outlook.com/Inbox/Azure/Get the most from your new virtual machine",
                "item_name": "Get the most from your new virtual machine",
                "item_type": "MAPI/IPM.Note.Read",
                "content_field": "Body",
                "content_text": "Azure VM setup",
                "content_sha256": "abc",
                "content_length": 14,
                "opensearch_document_id": "case-1:search:77",
            }
        ]
    )

    report = remote_access_attribution_report(db, case.id, remote="52.249.198.56", limit=10)

    assert report["summary"]["window_count"] == 1
    window = report["remote_access_windows"][0]
    assert window["remote_ip"] == "52.249.198.56"
    assert window["successful_logon_count"] == 1
    assert window["failed_logon_count"] == 1
    assert window["usb_device_count"] == 1
    assert window["cloud_context_count"] == 1
    markdown = remote_access_attribution_markdown(report)
    assert "valid credentials" in markdown
    assert "USB123" in markdown
    assert "Azure" in markdown


def test_vpn_local_activity_report_summarizes_endpoint_activity_during_vpn(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    db.insert_evtx_events(
        [
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 1,
                "record_number": "1",
                "event_record_id": "1",
                "time_created": "2020-11-14 05:00:00",
                "event_id": "20223",
                "level": "Information",
                "provider": "RasClient",
                "channel": "Application",
                "map_description": "VPN connected",
                "payload": "vpn.example.test SSTP",
                "payload_data1": "vpn.example.test",
                "source_file": "Application.evtx",
            },
            {
                "id": str(uuid.uuid4()),
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-evtx",
                "tool_name": "EvtxECmd",
                "source_csv": tmp_path / "evtx.csv",
                "row_number": 2,
                "record_number": "2",
                "event_record_id": "2",
                "time_created": "2020-11-14 05:10:00",
                "event_id": "20226",
                "level": "Information",
                "provider": "RasClient",
                "channel": "Application",
                "map_description": "VPN disconnected",
                "payload": "vpn.example.test",
                "payload_data1": "vpn.example.test",
                "source_file": "Application.evtx",
            },
        ]
    )
    db.insert_prefetch_items(
        [
            {
                "id": "prefetch-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-prefetch",
                "tool_name": "PECmd",
                "source_csv": tmp_path / "prefetch.csv",
                "row_number": 1,
                "prefetch_name": "NOTEPAD.EXE-12345678.pf",
                "artifact_path": "/artifacts/prefetch/NOTEPAD.EXE-12345678.pf",
                "original_path": "Windows/Prefetch/NOTEPAD.EXE-12345678.pf",
                "executable_name": "notepad.exe",
                "run_count": "1",
                "last_run_time_utc": "2020-11-14 05:05:00",
            }
        ]
    )
    db.insert_shortcut_items(
        [
            {
                "id": "shortcut-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-jlecmd",
                "tool_name": "JLECmd",
                "source_csv": tmp_path / "JLECmd.csv",
                "row_number": 1,
                "artifact_type": "jumplist",
                "artifact_name": "abc.automaticDestinations-ms",
                "artifact_path": "/Users/Jane/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/abc.automaticDestinations-ms",
                "file_name": "notes.txt",
                "file_location": "C:\\Users\\Jane\\Documents\\notes.txt",
                "target_accessed": "2020-11-14 05:06:00",
                "jumplist_item_number": "7",
            }
        ]
    )
    db.insert_browser_downloads(
        [
            {
                "id": "download-1",
                "case_id": case.id,
                "computer_id": "computer-1",
                "image_id": "image-1",
                "tool_output_id": "output-browser",
                "tool_name": "BrowserParser",
                "source_csv": tmp_path / "browser.csv",
                "row_number": 1,
                "browser": "Chrome",
                "target_path": "C:\\Users\\Jane\\Downloads\\tool.exe",
                "tab_url": "https://example.test/tool.exe",
                "start_time_utc": "2020-11-14 05:07:00",
            }
        ]
    )

    report = vpn_local_activity_report(db, case.id)

    assert report["summary"]["vpn_window_count"] == 1
    window = report["vpn_windows"][0]
    assert window["activity_count"] == 3
    categories = {item["activity_category"] for item in window["activity_counts"]}
    assert {"application_execution", "shortcut_or_jumplist_file_use", "browser_download"} <= categories
    markdown = vpn_local_activity_markdown(report)
    assert "# VPN Local Activity Report" in markdown
    assert "notepad.exe" in markdown
    assert "notes.txt" in markdown
    assert "tool.exe" in markdown
