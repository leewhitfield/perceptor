from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import load_config
from .analytics_query import query_one as analytics_query_one
from .db import Database
from .evidence import add_image, create_case, create_computer
from .logging_config import configure_logging
from .mounting.workflow import mount_image, unmount_image
from .mounting.vshadow import discover_vsc_snapshots, extract_vsc_artifact, mount_vsc_snapshot, unmount_vsc
from .mounting.vsc_prefetch import run_vsc_prefetch_scan
from .mounting.vsc_registry import run_vsc_registry_scan
from .mounting.vsc_browser import run_vsc_browser_scan
from .mounting.vsc_appcompat import run_vsc_appcompat_scan
from .mounting.vsc_srum import run_vsc_srum_scan
from .mounting.vsc_evtx import run_vsc_evtx_triage_scan
from .mounting.vsc_ntfs import run_vsc_ntfs_delta_scan
from .mounting.vsc_recycle import run_vsc_recycle_scan
from .mounting.vsc_search import run_vsc_windows_search_scan
from .mounting.vsc_file_history import build_vsc_file_history_report
from .mounting.vsc_profile import VSC_PROFILES, run_vsc_profile_scan
from .paths import WorkspacePaths
from .processing_scheduler import ProcessingTask, run_processing_tasks
from .report_paths import sanitize_report_paths, sanitize_report_text
from .common_dialog import rebuild_common_dialog_items
from .copied_indicators import rebuild_copied_file_indicators
from .correlation import rebuild_file_correlations
from .filesystem_review import rebuild_filesystem_review
from .nested_evidence import rebuild_nested_evidence_inventory
from .user_file_references import rebuild_user_controlled_file_references
from .reports import (
    accounts_report,
    account_compromise_markdown,
    account_compromise_report,
    amcache_report,
    artifact_sources_report,
    artifact_completeness_report,
    artifact_processing_status_report,
    artifact_summary_report,
    autostarts_markdown,
    autostarts_report,
    browser_profile_activity_report,
    browser_deep_storage_report,
    browser_downloads_report,
    browser_artifacts_report,
    browser_cache_report,
    browser_activity_report,
    browser_cache_correlations_report,
    browser_hosts_report,
    browser_report,
    case_review_report,
    carve_coverage_markdown,
    carve_coverage_report,
    cd_burning_activity_markdown,
    cd_burning_activity_report,
    cloud_artifacts_report,
    cloud_configuration_report,
    cloud_files_report,
    cloud_server_events_report,
    copied_files_report,
    copied_file_drilldown_report,
    copied_file_groups_report,
    copied_file_indicators_report,
    copied_usb_files_report,
    common_dialog_items_report,
    combined_artifact_family_markdown,
    combined_artifact_family_report,
    communication_groups_report,
    communications_report,
    case_summary_report,
    case_executive_summary_markdown,
    case_executive_summary_report,
    case_overview_markdown,
    case_overview_report,
    cleanup_candidates_report,
    correlations_report,
    correlation_group_detail_report,
    correlation_groups_report,
    crash_dump_analysis_markdown,
    crash_dump_analysis_report,
    deleted_folders_report,
    downloaded_files_report,
    database_storage_report,
    data_exfiltration_markdown,
    data_exfiltration_report,
    deep_recovery_status_markdown,
    deep_recovery_status_report,
    email_artifacts_report,
    encrypted_volume_indicators_report,
    event_interpretation_report,
    evidence_gaps_markdown,
    evidence_gaps_report,
    evidence_quality_report,
    evtx_report,
    evtx_recovery_report,
    brute_force_markdown,
    brute_force_report,
    external_storage_markdown,
    external_storage_report,
    execution_markdown,
    execution_report,
    execution_correlation_report,
    file_metadata_deleted_skipped_report,
    file_metadata_folders_report,
    file_metadata_live_orphan_report,
    file_metadata_report,
    file_metadata_skipped_report,
    file_metadata_summary_report,
    file_dossier_report,
    file_intelligence_report,
    file_history_markdown,
    file_history_overview_markdown,
    file_history_report,
    file_metadata_unresolved_report,
    file_name_drilldown_report,
    file_names_report,
    filesystem_review_report,
    firefox_report,
    image_analysis_report,
    investigation_triage_dashboard_markdown,
    investigation_triage_dashboard_report,
    interesting_executables_markdown,
    interesting_executables_report,
    activity_summary_report,
    artifact_correlations_report,
    issues_report,
    mft_report,
    mailbox_attachment_copies_report,
    mailbox_attachment_coverage_report,
    mailbox_message_copies_report,
    mailbox_attachments_report,
    mailbox_messages_report,
    malware_hiding_places_markdown,
    malware_hiding_places_report,
    memory_analysis_markdown,
    memory_analysis_report,
    memory_artifacts_markdown,
    memory_artifacts_report,
    memory_credentials_markdown,
    memory_credentials_report,
    memory_disk_correlations_markdown,
    memory_disk_correlations_report,
    memory_support_files_markdown,
    memory_support_files_report,
    memory_string_hits_report,
    windows_search_combined_markdown,
    windows_search_combined_report,
    communication_review_report,
    computer_inventory_report,
    device_inventory_report,
    messaging_artifacts_report,
    messaging_messages_report,
    ntfs_index_report,
    ntfs_logfile_report,
    ntfs_namespace_report,
    office_backstage_report,
    operation_manifest_report,
    office_trust_report,
    phone_link_report,
    user_dictionaries_report,
    prefetch_report,
    persistence_report,
    process_timing_markdown,
    process_timing_report,
    processing_decision_markdown,
    processing_decision_report,
    processing_readiness_markdown,
    processing_readiness_report,
    program_provenance_markdown,
    program_provenance_report,
    recycle_report,
    rdp_cache_report,
    recovery_coverage_report,
    remote_access_attribution_markdown,
    remote_access_attribution_report,
    rdp_remote_access_markdown,
    regression_smoke_report,
    rdp_visual_observations_report,
    registry_artifacts_report,
    registry_activity_report,
    registry_report,
    remote_access_sessions_report,
    search_index_runs_report,
    session_detail_report,
    sessions_report,
    storage_policy_report,
    suspicious_executions_markdown,
    suspicious_executions_report,
    suspicious_timeline_windows_markdown,
    suspicious_timeline_windows_report,
    sqlite_inventory_markdown,
    sqlite_inventory_report,
    sdelete_report,
    srum_app_network_usage_report,
    srum_context_report,
    srum_networks_report,
    shellbags_report,
    shortcuts_report,
    shimcache_report,
    taskbar_pins_report,
    taskbar_feature_usage_report,
    telemetry_artifacts_report,
    thumbcache_report,
    files_report,
    srum_report,
    tool_run_summary_report,
    timeline_report,
    timeline_review_report,
    timeline_sources_report,
    tor_usage_report,
    ual_report,
    uninstalled_application_artifacts_report,
    user_activity_report,
    user_file_reference_source_report,
    user_file_references_report,
    user_timeline_report,
    usb_dossier_report,
    users_report,
    usn_report,
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
    usb_breakdown_report,
    usb_file_correlation_report,
    usb_report,
    usb_timeline_report,
    usb_verbose_report,
    validation_report,
    virtualization_indicators_report,
    vpn_activity_report,
    vpn_config_report,
    vpn_connections_report,
    vpn_execution_report,
    vpn_local_activity_markdown,
    vpn_local_activity_report,
    vpn_session_evidence_report,
    webcache_files_report,
    web_cloud_correlations_report,
    webcache_report,
    windows_search_report,
    windows_activities_report,
)
from .search.opensearch import (
    OpenSearchConfig,
    load_synonym_groups,
    search_case_content,
    search_result_drilldown,
)
from .report_specs import list_report_specs, run_report_spec
from .report_bundle import import_report_bundle
from .safety import OrchestratorError
from .artifact_dedupe import rebuild_artifact_windows_old_dedupe
from .correlation_framework import rebuild_correlation_framework
from .sessions import rebuild_sessions
from .standalone import (
    artifact_capability_report,
    backup_case_databases,
    benchmark_report,
    dependency_report,
    doctor_report,
    job_status_report,
    profile_catalog_report,
    schema_status_report,
    standalone_backlog_report,
    version_report,
)
from .timeline_dedupe import rebuild_timeline_windows_old_dedupe
from .tools.profiles import profile_extraction_preview, run_profile
from .tools.registry import ToolRegistry
from .tools.cloud_server_import import import_cloud_server_logs_to_csv
from .tools.ingest import ingest_csv_output
from .tools.carve import (
    scan_range_row,
    stage_ese_carves,
    stage_sqlite_carves,
    staged_carve_row,
    summarize_ese_carve,
    summarize_sqlite_carve,
)
from .tools.chromium import parse_chromium_artifacts_to_csv
from .tools.firefox import parse_firefox_artifacts_to_csv
from .tools.activities import parse_windows_activities_to_csv
from .tools.memory_strings import scan_memory_strings_to_csv
from .timeline import timeline_events_from_rows
from .tools.windows_search_memory import parse_windows_search_memory_carves

logger = logging.getLogger(__name__)


def print_json(value: object) -> None:
    print(json.dumps(sanitize_report_paths(value), indent=2, default=str))


def _count_csv_rows(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        return max(0, sum(1 for _ in csv.DictReader(handle)))


def _cloud_or_memory_evidence_ids(
    db: Database,
    *,
    case_id: str,
    evidence_path: Path,
    computer_id: str | None,
    image_id: str | None = None,
) -> tuple[str, str]:
    db.get_case(case_id)
    if image_id is not None and computer_id is None:
        image = db.get_image(image_id, case_id)
        if image.computer_id:
            computer_id = image.computer_id
    if computer_id is None:
        computer_id = str(uuid.uuid4())
        db.create_computer(
            computer_id=computer_id,
            case_id=case_id,
            label="Non-image supplemental evidence",
            notes="Created automatically for server-side cloud or memory-adjacent supplemental evidence.",
        )
    else:
        db.get_computer(computer_id, case_id)
    if image_id is None:
        image_id = str(uuid.uuid4())
        db.add_image(image_id, case_id, evidence_path, computer_id=computer_id)
    else:
        db.get_image(image_id, case_id)
    return computer_id, image_id


def write_text_output(text: str, output: str | None = None) -> None:
    text = sanitize_report_text(text)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text)


def write_csv_rows(rows: list[dict[str, object]], output: str | None = None) -> None:
    rows = [_flatten_row(sanitize_report_paths(row)) for row in rows]
    fieldnames = list(rows[0].keys()) if rows else []
    if output:
        with Path(output).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)


def _flatten_row(row: dict[str, object]) -> dict[str, object]:
    flattened: dict[str, object] = {}
    for key, value in row.items():
        if isinstance(value, (dict, list, set, tuple)):
            flattened[key] = json.dumps(value, default=str)
        else:
            flattened[key] = value
    return flattened


def generic_table(title: str, rows: list[dict[str, object]], columns: list[str]) -> str:
    rows = sanitize_report_paths(rows)
    lines = [title, f"Rows shown: {len(rows)}", ""]
    for row in rows:
        parts = [f"{column}={row.get(column)}" for column in columns if row.get(column) not in (None, "")]
        lines.append(" | ".join(parts) if parts else "(blank row)")
    return "\n".join(lines).rstrip()


def write_report_output(report: dict[str, object], rows: list[dict[str, object]], fmt: str, output: str | None, *, title: str, columns: list[str]) -> None:
    report = sanitize_report_paths(report)
    rows = sanitize_report_paths(rows)
    if fmt == "csv":
        write_csv_rows(rows, output)
    elif fmt == "table":
        write_text_output(generic_table(title, rows, columns), output)
    else:
        write_text_output(json.dumps(report, indent=2, default=str), output)


def _mount_path_state(path: Path) -> tuple[str, str]:
    try:
        if not path.exists():
            return "missing", "Path does not exist."
        if path.is_dir():
            next(path.iterdir(), None)
        return "accessible", ""
    except OSError as exc:
        return "stale", str(exc)


def _unmount_command(path: Path, *, use_sudo_mount: bool) -> list[str]:
    umount = shutil.which("umount") or "umount"
    command = [umount, str(path)]
    if use_sudo_mount:
        command = ["sudo", "-n", *command]
    return command


def cleanup_stale_mounts(
    db: Database,
    *,
    case_id: str,
    apply: bool = False,
    use_sudo_mount: bool = False,
) -> dict[str, object]:
    db.get_case(case_id)
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT id, image_id, volume_mount_path, ewf_mount_path, raw_path, created_at
            FROM mounts
            WHERE case_id = ?
            ORDER BY created_at DESC
            """,
            (case_id,),
        ).fetchall()
    ]
    results: list[dict[str, object]] = []
    for row in rows:
        for path_key in ("volume_mount_path", "ewf_mount_path"):
            value = row.get(path_key)
            if not value:
                continue
            path = Path(str(value))
            state, error = _mount_path_state(path)
            command = _unmount_command(path, use_sudo_mount=use_sudo_mount)
            result: dict[str, object] = {
                "mount_id": row.get("id"),
                "image_id": row.get("image_id"),
                "path_type": path_key,
                "path": str(path),
                "state": state,
                "action": "none",
                "command": command,
            }
            if error:
                result["error"] = error
            if state == "stale":
                if apply:
                    completed = subprocess.run(command, capture_output=True, text=True, check=False)
                    result.update(
                        {
                            "action": "unmount",
                            "returncode": completed.returncode,
                            "stdout": completed.stdout.strip(),
                            "stderr": completed.stderr.strip(),
                            "status": "unmounted" if completed.returncode == 0 else "failed",
                        }
                    )
                else:
                    result.update({"action": "dry_run", "status": "would_unmount"})
            else:
                result["status"] = state
            results.append(result)
    return {
        "case_id": case_id,
        "apply": apply,
        "mount_path_count": len(results),
        "stale_count": sum(1 for row in results if row.get("state") == "stale"),
        "unmounted_count": sum(1 for row in results if row.get("status") == "unmounted"),
        "failed_count": sum(1 for row in results if row.get("status") == "failed"),
        "results": results,
    }


def _readiness_gate_summary(report: dict[str, object], failed: list[dict[str, object]]) -> dict[str, object]:
    return {
        "case_id": report.get("case_id"),
        "profile": report.get("profile"),
        "passed": not failed,
        "summary": report.get("summary") if isinstance(report.get("summary"), dict) else {},
        "failed_required": failed,
    }


def _parse_case_ref(value: str) -> tuple[str, Path, str]:
    parts = value.split(":", 2)
    if len(parts) != 3 or not all(parts):
        raise ValueError("--case-ref must use LABEL:ROOT:CASE_ID")
    return parts[0], Path(parts[1]), parts[2]


def case_comparison_report(case_refs: list[str], *, limit: int = 100) -> dict[str, object]:
    cases: list[dict[str, object]] = []
    for value in case_refs:
        label, root, case_id = _parse_case_ref(value)
        paths = WorkspacePaths(root)
        case_db = Database(paths.db_path())
        try:
            memory_gate = processing_readiness_report(case_db, case_id, limit=limit, profile="memory")
            full_gate = processing_readiness_report(case_db, case_id, limit=limit, profile="windows-full")
            deep_gate = processing_readiness_report(case_db, case_id, limit=limit, profile="windows-full-deep-recovery")
            credentials = memory_credentials_report(case_db, case_id, limit=limit)
            support = memory_support_files_report(case_db, case_id, limit=limit)
            suspicious = suspicious_executions_report(case_db, case_id, limit=limit)
            gaps = evidence_gaps_report(case_db, case_id, limit=limit)
            deep_status = deep_recovery_status_report(case_db, case_id, limit=limit)
            cases.append(
                {
                    "label": label,
                    "root": str(root),
                    "case_id": case_id,
                    "memory_required_gaps": (memory_gate.get("summary") or {}).get("required_needs_action_count", 0),
                    "windows_full_required_gaps": (full_gate.get("summary") or {}).get("required_needs_action_count", 0),
                    "deep_recovery_required_gaps": (deep_gate.get("summary") or {}).get("required_needs_action_count", 0),
                    "memory_support_files": (support.get("summary") or {}).get("support_file_count", 0),
                    "memory_processed": (support.get("summary") or {}).get("processed_count", 0),
                    "memory_string_hits": (support.get("summary") or {}).get("hit_count", 0),
                    "high_value_credentials": (credentials.get("summary") or {}).get("high_value_candidate_count", 0),
                    "validated_credentials": (credentials.get("summary") or {}).get("validated_count", 0),
                    "suspicious_executions": (suspicious.get("summary") or {}).get("finding_count", 0),
                    "evidence_gaps": (gaps.get("summary") or {}).get("gap_count", 0),
                    "deep_recovery_passed": bool(deep_status.get("passed")),
                    "carve_scan_ranges": (deep_status.get("summary") or {}).get("carve_scan_range_count", 0),
                    "tsk_recovery_artifacts": (deep_status.get("summary") or {}).get("tsk_recovery_artifacts", 0),
                }
            )
        finally:
            case_db.close()
    return {
        "case_count": len(cases),
        "cases": cases,
        "summary": {
            "memory_ready_count": sum(1 for row in cases if not row.get("memory_required_gaps")),
            "windows_full_ready_count": sum(1 for row in cases if not row.get("windows_full_required_gaps")),
            "deep_recovery_ready_count": sum(1 for row in cases if not row.get("deep_recovery_required_gaps")),
            "total_suspicious_executions": sum(int(row.get("suspicious_executions") or 0) for row in cases),
            "total_high_value_credentials": sum(int(row.get("high_value_credentials") or 0) for row in cases),
        },
    }


def case_comparison_markdown(report: dict[str, object]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    lines = [
        "# Case Comparison",
        "",
        f"- Cases: `{report.get('case_count', 0)}`",
        f"- Memory ready: `{summary.get('memory_ready_count', 0)}`",
        f"- Windows-full ready: `{summary.get('windows_full_ready_count', 0)}`",
        f"- Deep-recovery ready: `{summary.get('deep_recovery_ready_count', 0)}`",
        f"- Suspicious executions: `{summary.get('total_suspicious_executions', 0)}`",
        f"- High-value credential candidates: `{summary.get('total_high_value_credentials', 0)}`",
        "",
        "| Case | Memory Gaps | Full Gaps | Deep Gaps | Memory Files | Hits | Suspicious Execs | High-Value Creds |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report.get("cases") or []:
        lines.append(
            f"| {row.get('label') or row.get('case_id')} | {row.get('memory_required_gaps') or 0} | "
            f"{row.get('windows_full_required_gaps') or 0} | {row.get('deep_recovery_required_gaps') or 0} | "
            f"{row.get('memory_support_files') or 0} | {row.get('memory_string_hits') or 0} | "
            f"{row.get('suspicious_executions') or 0} | {row.get('high_value_credentials') or 0} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _memory_hit_count(db: Database, case_id: str, hit_id: str) -> int:
    row = analytics_query_one(
        db,
        "memory_string_hits",
        """
        SELECT COUNT(*) AS count
        FROM memory_string_hits
        WHERE case_id = ?
          AND id = ?
          AND hit_category = 'credentials'
        """,
        (case_id, hit_id),
    )
    return int((row or {}).get("count") or 0)


def rebuild_case_postprocess(
    db: Database,
    *,
    case_id: str,
    image_id: str | None = None,
    max_windows_old_output_rows: int = 100_000,
) -> dict[str, object]:
    db.get_case(case_id)
    if image_id:
        db.get_image(image_id, case_id)
    stats: dict[str, object] = {
        "case_id": case_id,
        "image_id": image_id,
        "steps": {},
        "skipped": [],
    }

    def run_step(name: str, callback):
        result = callback()
        stats["steps"][name] = result
        return result

    if image_id:
        run_step("file_correlations", lambda: rebuild_file_correlations(db, case_id=case_id, image_id=image_id))
    else:
        stats["skipped"].append(
            {
                "step": "file_correlations",
                "reason": "file correlations are image-scoped; pass --image to rebuild them",
            }
        )
    run_step("common_dialog_items", lambda: rebuild_common_dialog_items(db, case_id=case_id, image_id=image_id))
    run_step("copied_file_indicators", lambda: rebuild_copied_file_indicators(db, case_id=case_id, image_id=image_id))
    run_step("filesystem_review", lambda: rebuild_filesystem_review(db, case_id=case_id, image_id=image_id))
    run_step("nested_evidence_inventory", lambda: rebuild_nested_evidence_inventory(db, case_id=case_id, image_id=image_id))
    run_step(
        "timeline_windows_old_dedupe",
        lambda: rebuild_timeline_windows_old_dedupe(
            db,
            case_id=case_id,
            image_id=image_id,
            max_windows_old_output_rows=max_windows_old_output_rows,
        ),
    )
    run_step("artifact_windows_old_dedupe", lambda: rebuild_artifact_windows_old_dedupe(db, case_id=case_id, image_id=image_id))
    run_step("derived_sessions", lambda: rebuild_sessions(db, case_id=case_id, image_id=image_id))
    run_step("correlation_framework", lambda: rebuild_correlation_framework(db, case_id=case_id, image_id=image_id))
    run_step("user_file_references", lambda: rebuild_user_controlled_file_references(db, case_id=case_id, image_id=image_id))
    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        event="postprocess.rebuilt",
        message="Rebuilt derived post-processing outputs",
        details={
            "image_id": image_id,
            "steps": list((stats.get("steps") or {}).keys()),
            "skipped": stats.get("skipped"),
        },
    )
    return stats


def import_recognized_sqlite_carves(
    db: Database,
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    source: Path,
    staged_rows: list[dict[str, object]],
    output_dir: Path,
) -> dict[str, object]:
    imported: dict[str, object] = {"tools": {}, "csv_files": 0, "rows": 0, "skipped": 0}
    if not source.is_file():
        imported["skipped"] = len(staged_rows)
        return imported
    route = _sqlite_artifact_route(source.name)
    if route is None:
        imported["skipped"] = len(staged_rows)
        return imported
    tool_name, parser, staged_name = route
    for index, row in enumerate(staged_rows, start=1):
        staged_path = Path(str(row.get("staged_path") or ""))
        if not staged_path.exists():
            imported["skipped"] = int(imported["skipped"]) + 1
            continue
        parser_root = output_dir / "artifact-import" / str(index)
        parser_root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged_path, parser_root / staged_name)
        csv_root = output_dir / "artifact-csv" / str(index)
        csv_paths = parser(parser_root, csv_root)
        for csv_path in csv_paths:
            output_id = str(uuid.uuid4())
            db.insert_tool_output(
                {
                    "id": output_id,
                    "case_id": case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "job_id": None,
                    "tool_name": tool_name,
                    "output_type": "csv",
                    "path": csv_path,
                    "row_count": _count_csv_rows(csv_path),
                }
            )
            count = ingest_csv_output(
                db=db,
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=output_id,
                tool_name=tool_name,
                path=csv_path,
            )
            imported["csv_files"] = int(imported["csv_files"]) + 1
            imported["rows"] = int(imported["rows"]) + count
            tools = imported["tools"]
            if isinstance(tools, dict):
                tools[tool_name] = int(tools.get(tool_name, 0)) + count
    return imported


def _write_scan_ranges_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fieldnames = ["source_path", "source_size", "range_start", "range_end", "scanned_bytes", "hits_found"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _looks_like_windows_search_sqlite_source(source: Path) -> bool:
    text = str(source).casefold()
    return (
        "windows.search" in text
        or "searchindexer" in text
        or "windows-search" in text
        or source.name.casefold() in {"windows-search.db", "windows.db", "search.db"}
    )


def _sqlite_artifact_route(name: str):
    lower = name.casefold()
    if lower in {"places.sqlite", "cookies.sqlite", "formhistory.sqlite", "permissions.sqlite"}:
        return "FirefoxParser", parse_firefox_artifacts_to_csv, name
    if lower in {"history", "cookies", "login data", "web data", "shortcuts", "top sites", "network action predictor"}:
        return "ChromiumParser", parse_chromium_artifacts_to_csv, name
    if lower == "activitiescache.db":
        return "WindowsActivitiesParser", parse_windows_activities_to_csv, name
    return None


def write_case_report_bundle(db: Database, case_id: str, output_dir: Path, *, limit: int = 100) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    memory_disk = memory_disk_correlations_report(db, case_id, limit=max(limit * 10, 500))
    overview = case_overview_report(db, case_id, limit=limit, memory_disk_report=memory_disk)
    credentials = memory_credentials_report(db, case_id, limit=limit)
    memory_support = memory_support_files_report(db, case_id, limit=limit)
    readiness = processing_readiness_report(db, case_id, limit=limit)
    gaps = evidence_gaps_report(db, case_id, limit=limit)
    suspicious = suspicious_executions_report(db, case_id, limit=limit)
    deep_recovery = deep_recovery_status_report(db, case_id, limit=limit)
    specs: list[tuple[str, str, str, object]] = [
        ("executive-summary", "md", "Executive summary", case_executive_summary_markdown(case_executive_summary_report(db, case_id, limit=limit, memory_disk_report=memory_disk))),
        ("case-overview", "md", "Case overview", case_overview_markdown(overview)),
        ("evidence-gaps", "md", "Evidence gaps", evidence_gaps_markdown(gaps)),
        ("memory-analysis", "md", "Memory analysis", memory_analysis_markdown(memory_analysis_report(db, case_id, limit=limit))),
        ("memory-credentials", "md", "Memory credentials", memory_credentials_markdown(credentials)),
        ("memory-disk-correlations", "md", "Memory/disk correlations", memory_disk_correlations_markdown(memory_disk)),
        ("memory-support-files", "md", "Memory support files", memory_support_files_markdown(memory_support)),
        ("combined-artifacts", "md", "Combined artifact families", combined_artifact_family_markdown(combined_artifact_family_report(db, case_id, limit=limit, memory_disk_report=memory_disk))),
        ("crash-dump-analysis", "md", "Crash dump analysis", crash_dump_analysis_markdown(crash_dump_analysis_report(db, case_id, limit=limit))),
        ("suspicious-executions", "md", "Suspicious executions", suspicious_executions_markdown(suspicious)),
        ("memory-artifacts", "md", "Memory artifact inventory", memory_artifacts_markdown(memory_artifacts_report(db, case_id, limit=limit))),
        ("deep-recovery-status", "md", "Deep recovery status", deep_recovery_status_markdown(deep_recovery)),
        ("recovery-coverage", "json", "Recovery coverage", recovery_coverage_report(db, case_id, limit=max(limit, 250))),
        ("carve-coverage", "md", "Carve coverage", carve_coverage_markdown(carve_coverage_report(db, case_id, limit=max(limit, 250)))),
        ("sqlite-inventory", "md", "SQLite carve inventory", sqlite_inventory_markdown(sqlite_inventory_report(db, case_id, limit=limit))),
        ("artifact-processing-status", "json", "Artifact processing status", artifact_processing_status_report(db, case_id, limit=limit)),
        ("processing-decisions", "md", "Processing decisions", processing_decision_markdown(processing_decision_report(db, case_id, limit=limit))),
        ("processing-readiness", "md", "Processing readiness", processing_readiness_markdown(readiness)),
        ("browser-activity", "json", "Browser activity", browser_activity_report(db, case_id, limit=limit, memory_disk_report=memory_disk)),
        ("cloud-artifacts", "json", "Cloud artifacts", cloud_artifacts_report(db, case_id, limit=limit, memory_disk_report=memory_disk)),
        ("email-artifacts", "json", "Email artifacts", email_artifacts_report(db, case_id, limit=limit, memory_disk_report=memory_disk)),
        ("remote-access", "json", "Remote access", remote_access_sessions_report(db, case_id, limit=limit, memory_disk_report=memory_disk)),
        ("regression-smoke", "json", "Regression smoke", regression_smoke_report(db, case_id, limit=min(limit, 25))),
    ]
    written: list[dict[str, object]] = []
    for stem, extension, title, payload in specs:
        path = output_dir / f"{stem}.{extension}"
        if extension == "md":
            write_text_output(str(payload), str(path))
        else:
            write_text_output(json.dumps(sanitize_report_paths(payload), indent=2, default=str), str(path))
        written.append({"name": stem, "title": title, "path": str(path), "format": extension})
    overview_summary = overview.get("summary") if isinstance(overview.get("summary"), dict) else {}
    credential_summary = credentials.get("summary") if isinstance(credentials.get("summary"), dict) else {}
    support_summary = memory_support.get("summary") if isinstance(memory_support.get("summary"), dict) else {}
    readiness_summary = readiness.get("summary") if isinstance(readiness.get("summary"), dict) else {}
    gaps_summary = gaps.get("summary") if isinstance(gaps.get("summary"), dict) else {}
    suspicious_summary = suspicious.get("summary") if isinstance(suspicious.get("summary"), dict) else {}
    index_lines = [
        "# Case Report Bundle",
        "",
        f"Case: `{case_id}`",
        "",
        "## At-a-Glance",
        "",
        f"- Suspicious executions: `{suspicious_summary.get('finding_count', overview_summary.get('suspicious_executions', 0))}`",
        f"- Memory support files processed: `{support_summary.get('processed_count', 0)}` / `{support_summary.get('support_file_count', 0)}`",
        f"- Memory string hits: `{support_summary.get('hit_count', overview_summary.get('memory_string_hits', 0))}`",
        f"- High-value credential candidates: `{credential_summary.get('high_value_candidate_count', 0)}`",
        f"- Evidence gaps: `{gaps_summary.get('gap_count', overview_summary.get('evidence_gaps', 0))}`",
        f"- Readiness required needs action: `{readiness_summary.get('required_needs_action_count', readiness_summary.get('needs_action_count', 0))}`",
        "",
        "## Reports",
        "",
    ]
    for item in written:
        index_lines.append(f"- [{item['title']}]({Path(str(item['path'])).name})")
    index_path = output_dir / "index.md"
    write_text_output("\n".join(index_lines).rstrip() + "\n", str(index_path))
    return {
        "case_id": case_id,
        "output_dir": str(output_dir),
        "index": str(index_path),
        "reports": written,
        "total_written": len(written) + 1,
    }


def run_memory_processing_profile(
    db: Database,
    paths: WorkspacePaths,
    *,
    case_id: str,
    computer_id: str | None = None,
    image_id: str | None = None,
    min_length: int = 6,
    include_crash_dumps: bool = True,
    extract_fallback: bool = True,
    workers: int = 1,
) -> dict[str, object]:
    timing_id = db.start_process_timing(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        scope="profile",
        phase="memory",
        name="memory-profile",
        details={
            "profile": "memory-profile",
            "include_crash_dumps": include_crash_dumps,
            "extract_fallback": extract_fallback,
            "requested_workers": workers,
            "effective_workers": max(1, workers),
            "parallel_scope": "memory_artifact_string_scans" if workers > 1 else "serial",
            "parallel_note": (
                "Memory artifact string scans can run in parallel; database ingest remains serialized."
                if workers > 1
                else ""
            ),
        },
    )
    artifacts = memory_artifacts_report(db, case_id, limit=5000).get("artifacts") or []
    scans: list[dict[str, object]] = []
    output_base = paths.case_dir(case_id) / "supplemental" / "memory-profile" / str(uuid.uuid4())
    total_imported = 0
    scan_tasks: list[ProcessingTask] = []
    for index, artifact in enumerate(artifacts, 1):
        artifact_type = str(artifact.get("artifact_type") or "")
        if artifact_type in {"crash_dump", "process_dump", "full_memory_dump"} and not include_crash_dumps:
            continue
        source = Path(str(artifact.get("actual_path") or artifact.get("path") or ""))
        if not source.exists() or not source.is_file():
            extracted = (
                _extract_memory_artifact_fallback(
                    db,
                    paths,
                    case_id=case_id,
                    artifact=artifact,
                    computer_id=computer_id,
                    image_id=image_id,
                )
                if extract_fallback
                else {"status": "disabled", "reason": "Extraction fallback disabled."}
            )
            if extracted.get("status") != "extracted":
                scans.append(
                    {
                        "artifact_path": artifact.get("path"),
                        "artifact_type": artifact_type,
                        "status": "skipped",
                        "reason": extracted.get("reason") or "No accessible file path.",
                        "extract_status": extracted.get("status"),
                    }
                )
                continue
            source = Path(str(extracted["path"]))
        task_output_dir = output_base / f"{index:04d}"
        scan_tasks.append(
            ProcessingTask(
                name=f"memory-profile:{index}",
                payload={"artifact": artifact, "artifact_type": artifact_type, "source": source},
                worker=lambda source=source, task_output_dir=task_output_dir: scan_memory_strings_to_csv(
                    source,
                    task_output_dir,
                    min_length=min_length,
                ),
            )
        )

    try:
        for result in run_processing_tasks(scan_tasks, workers=workers):
            artifact = result.payload["artifact"]
            artifact_type = str(result.payload["artifact_type"])
            source = Path(result.payload["source"])
            local_computer_id, local_image_id = _cloud_or_memory_evidence_ids(
                db,
                case_id=case_id,
                evidence_path=source,
                computer_id=computer_id,
                image_id=image_id,
            )
            if result.status == "failed":
                db.log_activity(
                    case_id=case_id,
                    computer_id=local_computer_id,
                    image_id=local_image_id,
                    event="memory.profile_scan_failed",
                    level="warning",
                    message=f"Memory profile scan failed for {source}",
                    details={"path": str(source), "error": result.error, "duration_seconds": result.duration_seconds},
                )
                scans.append(
                    {
                        "artifact_path": artifact.get("path"),
                        "artifact_type": artifact_type,
                        "status": "failed",
                        "error": result.error,
                        "duration_seconds": result.duration_seconds,
                    }
                )
                continue
            csv_path, metadata = result.value
            output_id = str(uuid.uuid4())
            db.insert_tool_output(
                {
                    "id": output_id,
                    "case_id": case_id,
                    "computer_id": local_computer_id,
                    "image_id": local_image_id,
                    "job_id": None,
                    "tool_name": "MemoryStringScanner",
                    "output_type": "csv",
                    "path": csv_path,
                    "row_count": _count_csv_rows(csv_path),
                }
            )
            imported = ingest_csv_output(
                db=db,
                case_id=case_id,
                computer_id=local_computer_id,
                image_id=local_image_id,
                tool_output_id=output_id,
                tool_name="MemoryStringScanner",
                path=csv_path,
            )
            total_imported += imported
            db.log_activity(
                case_id=case_id,
                computer_id=local_computer_id,
                image_id=local_image_id,
                event="memory.profile_artifact_scanned",
                message="Scanned memory-profile artifact for targeted strings",
                details={
                    "artifact_path": artifact.get("path"),
                    "artifact_type": artifact_type,
                    "source_path": str(source),
                    "output": str(csv_path),
                    "imported_rows": imported,
                    **metadata,
                },
            )
            scans.append(
                {
                    "artifact_path": artifact.get("path"),
                    "artifact_type": artifact_type,
                    "status": "scanned",
                    "output": str(csv_path),
                    "imported_rows": imported,
                    "duration_seconds": result.duration_seconds,
                    **metadata,
                }
            )
        result_payload = {
            "case_id": case_id,
            "artifact_count": len(artifacts),
            "worker_count": max(1, workers),
            "scan_task_count": len(scan_tasks),
            "scanned_count": sum(1 for row in scans if row.get("status") == "scanned"),
            "skipped_count": sum(1 for row in scans if row.get("status") == "skipped"),
            "failed_count": sum(1 for row in scans if row.get("status") == "failed"),
            "imported_rows": total_imported,
            "output_dir": str(output_base),
            "scans": scans,
        }
        status = "completed" if result_payload["failed_count"] == 0 else "partial"
        db.finish_process_timing(timing_id, status=status, details={key: value for key, value in result_payload.items() if key != "scans"})
        return result_payload
    except Exception as exc:
        db.finish_process_timing(timing_id, status="failed", details={"error": str(exc)})
        raise


def _extract_memory_artifact_fallback(
    db: Database,
    paths: WorkspacePaths,
    *,
    case_id: str,
    artifact: dict[str, object],
    computer_id: str | None = None,
    image_id: str | None = None,
) -> dict[str, object]:
    icat = shutil.which("icat")
    if not icat:
        return {"status": "unavailable", "reason": "icat is not available on PATH."}
    entry_number = str(artifact.get("entry_number") or "").strip()
    if not entry_number:
        return {"status": "missing_entry", "reason": "MFT entry number is unavailable for extraction."}
    local_image_id = str(artifact.get("image_id") or image_id or "").strip()
    image = _image_row_for_memory_artifact(db, case_id, local_image_id)
    if not image:
        return {"status": "missing_image", "reason": "No image path is available for MFT extraction."}
    source_image = Path(str(image["path"]))
    if not source_image.exists():
        return {"status": "missing_image_file", "reason": f"Image path is not accessible: {source_image}"}
    artifact_type = str(artifact.get("artifact_type") or "memory")
    name = _safe_memory_extract_name(str(artifact.get("path") or artifact_type))
    output_dir = paths.case_dir(case_id) / "supplemental" / "extracted-memory-support"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / name
    if output_path.exists() and output_path.stat().st_size:
        return {"status": "extracted", "path": str(output_path), "reason": "Existing extracted copy reused."}
    offset = _icat_offset_for_image(db, case_id, str(image["id"]))
    command = [icat, "-o", str(offset), str(source_image), entry_number]
    try:
        with output_path.open("wb") as handle:
            completed = subprocess.run(command, stdout=handle, stderr=subprocess.PIPE, text=False, check=False, timeout=3600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        output_path.unlink(missing_ok=True)
        return {"status": "failed", "reason": str(exc)}
    if completed.returncode != 0:
        output_path.unlink(missing_ok=True)
        return {"status": "failed", "reason": completed.stderr.decode("utf-8", errors="replace").strip()}
    if not output_path.exists() or output_path.stat().st_size == 0:
        output_path.unlink(missing_ok=True)
        return {"status": "empty", "reason": "icat produced an empty output file."}
    db.log_activity(
        case_id=case_id,
        computer_id=str(artifact.get("computer_id") or computer_id or image.get("computer_id") or "") or None,
        image_id=str(image["id"]),
        event="memory.support_file_extracted",
        message="Extracted memory support file from image using MFT entry fallback",
        details={
            "artifact_path": artifact.get("path"),
            "artifact_type": artifact_type,
            "entry_number": entry_number,
            "image_path": str(source_image),
            "output_path": str(output_path),
            "icat_offset": offset,
        },
    )
    return {"status": "extracted", "path": str(output_path)}


def _image_row_for_memory_artifact(db: Database, case_id: str, image_id: str | None) -> dict[str, object] | None:
    if image_id:
        row = db.conn.execute("SELECT id, computer_id, path FROM images WHERE case_id = ? AND id = ?", (case_id, image_id)).fetchone()
        if row:
            return dict(row)
    row = db.conn.execute("SELECT id, computer_id, path FROM images WHERE case_id = ? ORDER BY created_at LIMIT 1", (case_id,)).fetchone()
    return dict(row) if row else None


def _icat_offset_for_image(db: Database, case_id: str, image_id: str) -> int:
    env_offset = os.environ.get("FORENSIC_ICAT_OFFSET")
    if env_offset:
        try:
            return int(env_offset, 0)
        except ValueError:
            return 0
    try:
        row = db.conn.execute(
            """
            SELECT offset_bytes
            FROM mounts
            WHERE case_id = ? AND image_id = ? AND offset_bytes IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (case_id, image_id),
        ).fetchone()
    except Exception:
        row = None
    return int(row["offset_bytes"]) if row and row["offset_bytes"] is not None else 0


def _safe_memory_extract_name(value: str) -> str:
    name = Path(value.replace("\\", "/")).name or "memory.bin"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def _profile_should_run_memory(profile: str, *, include_memory_profile: bool = False, no_memory_profile: bool = False) -> bool:
    if no_memory_profile:
        return False
    if include_memory_profile:
        return True
    normalized = profile.casefold()
    return normalized.startswith("windows-full") or normalized.endswith("-memory") or "memory" in normalized


def _run_memory_after_profile(
    db: Database,
    paths: WorkspacePaths,
    *,
    case_id: str,
    computer_id: str | None,
    image_id: str | None,
    profile: str,
    workers: int,
    include_memory_profile: bool = False,
    no_memory_profile: bool = False,
    dry_run: bool = False,
) -> dict[str, object] | None:
    if not _profile_should_run_memory(profile, include_memory_profile=include_memory_profile, no_memory_profile=no_memory_profile):
        return None
    if dry_run:
        return {"status": "dry_run", "profile": profile, "would_run": True}
    return run_memory_processing_profile(
        db,
        paths,
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        workers=workers,
    )


def usb_files_table(report: dict[str, object]) -> str:
    devices = report.get("devices", [])
    items = report.get("items", [])
    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    device_meta: dict[tuple[str, str, str], dict[str, object]] = {}
    display_items = report.get("files") if report.get("files") else items
    for item in display_items if isinstance(display_items, list) else []:
        key = (
            str(item.get("usb_volume_name") or item.get("usb_drive_letter") or item.get("usb_serial") or ""),
            str(item.get("usb_volume_serial_number") or ""),
            str(item.get("usb_serial") or ""),
        )
        grouped.setdefault(key, []).append(item)
    for device in devices if isinstance(devices, list) else []:
        key = (
            str(device.get("usb_volume_name") or device.get("usb_drive_letter") or device.get("usb_serial") or ""),
            str(device.get("usb_volume_serial_number") or ""),
            str(device.get("usb_serial") or ""),
        )
        device_meta[key] = device
    grouped_output = bool(report.get("files"))
    total_label = "Total unique files" if grouped_output else "Total matched artifacts"
    total_value = report.get("total_files") if grouped_output else report.get("total_returned")
    lines = [
        f"USB file correlations for case {report.get('case_id')}",
        f"Correlation key: {report.get('correlation_key')}",
        f"{total_label}: {total_value}",
        f"Shellbag rows available: {report.get('shellbag_rows_available')}",
        "",
    ]
    for key in sorted(grouped):
        label, vsn, serial = key
        meta = device_meta.get(key, {})
        lines.append(f"{label} | VSN {vsn} | serial {serial} | {meta.get('usb_product') or ''}")
        lines.append(
            f"  matches: {meta.get('file_artifact_matches', len(grouped[key]))} "
            f"(lnk {meta.get('lnk_matches', 0)}, jumplist {meta.get('jumplist_matches', 0)}, "
            f"shellbag {meta.get('shellbag_matches', 0)})"
        )
        seen_paths = set()
        for item in grouped[key]:
            path = str(item.get("file_location") or item.get("file_name") or "")
            if path in seen_paths:
                continue
            seen_paths.add(path)
            source = item.get("source_artifact_type") or item.get("source_artifact_types")
            confidence = item.get("confidence") or item.get("best_confidence")
            match = item.get("volume_serial_match") or item.get("match_types")
            users = item.get("user_profile") or item.get("user_profiles")
            user_text = f" users={users}" if users else ""
            count_text = f" count={item.get('artifact_count')}" if item.get("artifact_count") else ""
            lines.append(f"  - [{source}/{confidence}/{match}{user_text}{count_text}] {path}")
        lines.append("")
    return "\n".join(lines).rstrip()


def usb_timeline_table(report: dict[str, object]) -> str:
    lines = [f"USB timeline for case {report.get('case_id')}", f"Total events shown: {report.get('total_returned')}", ""]
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        label = event.get("usb_volume_name") or event.get("usb_drive_letter") or event.get("usb_serial")
        user = f" user={event.get('user_profile')}" if event.get("user_profile") else ""
        path = f" {event.get('file_location')}" if event.get("file_location") else ""
        lines.append(
            f"{event.get('timestamp')} | {event.get('event_type')} | {label} | "
            f"VSN {event.get('usb_volume_serial_number')} | {event.get('source_artifact_type')}"
            f"{user} | {event.get('confidence')}{path}"
        )
    return "\n".join(lines).rstrip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forensic-orchestrator")
    parser.add_argument("--root", help="Workspace root directory")
    parser.add_argument("--config", help="YAML config file with root and plugins values")
    parser.add_argument("--plugin", action="append", help="Tool plugin YAML path")
    parser.add_argument("--dry-run", action="store_true", help="Record and print commands without executing")

    subparsers = parser.add_subparsers(dest="resource", required=True)

    case = subparsers.add_parser("case")
    case_sub = case.add_subparsers(dest="action", required=True)
    case_sub.add_parser("create")
    case_status = case_sub.add_parser("status")
    case_status.add_argument("case_id")
    case_activity = case_sub.add_parser("activity")
    case_activity.add_argument("case_id")
    case_activity.add_argument("--level", choices=["info", "warning", "error"])
    case_activity.add_argument("--limit", type=int, default=100)
    case_purge = case_sub.add_parser("purge-output")
    case_purge.add_argument("--case", required=True, dest="case_id")
    case_purge.add_argument("--image", dest="image_id")
    case_purge.add_argument("--tool", action="append", dest="tool_names")
    case_purge.add_argument("--yes", action="store_true", help="Required confirmation for deleting DB output rows")
    case_rebuild_timeline_dedupe = case_sub.add_parser("rebuild-timeline-dedupe")
    case_rebuild_timeline_dedupe.add_argument("case_id")
    case_rebuild_timeline_dedupe.add_argument("--image", dest="image_id")
    case_rebuild_timeline_dedupe.add_argument("--max-windows-old-output-rows", type=int, default=100_000)
    case_rebuild_artifact_dedupe = case_sub.add_parser("rebuild-artifact-dedupe")
    case_rebuild_artifact_dedupe.add_argument("case_id")
    case_rebuild_artifact_dedupe.add_argument("--image", dest="image_id")
    case_rebuild_correlations = case_sub.add_parser("rebuild-correlations")
    case_rebuild_correlations.add_argument("case_id")
    case_rebuild_correlations.add_argument("--image", dest="image_id")
    case_rebuild_sessions = case_sub.add_parser("rebuild-sessions")
    case_rebuild_sessions.add_argument("case_id")
    case_rebuild_sessions.add_argument("--image", dest="image_id")
    case_rebuild_postprocess = case_sub.add_parser("rebuild-postprocess")
    case_rebuild_postprocess.add_argument("case_id")
    case_rebuild_postprocess.add_argument("--image", dest="image_id")
    case_rebuild_postprocess.add_argument("--max-windows-old-output-rows", type=int, default=100_000)

    project = subparsers.add_parser("project")
    project_sub = project.add_subparsers(dest="action", required=True)
    project_sub.add_parser("create")
    project_status = project_sub.add_parser("status")
    project_status.add_argument("case_id")
    project_activity = project_sub.add_parser("activity")
    project_activity.add_argument("case_id")
    project_activity.add_argument("--level", choices=["info", "warning", "error"])
    project_activity.add_argument("--limit", type=int, default=100)
    project_purge = project_sub.add_parser("purge-output")
    project_purge.add_argument("--case", required=True, dest="case_id")
    project_purge.add_argument("--image", dest="image_id")
    project_purge.add_argument("--tool", action="append", dest="tool_names")
    project_purge.add_argument("--yes", action="store_true", help="Required confirmation for deleting DB output rows")
    project_rebuild_timeline_dedupe = project_sub.add_parser("rebuild-timeline-dedupe")
    project_rebuild_timeline_dedupe.add_argument("case_id")
    project_rebuild_timeline_dedupe.add_argument("--image", dest="image_id")
    project_rebuild_timeline_dedupe.add_argument("--max-windows-old-output-rows", type=int, default=100_000)
    project_rebuild_artifact_dedupe = project_sub.add_parser("rebuild-artifact-dedupe")
    project_rebuild_artifact_dedupe.add_argument("case_id")
    project_rebuild_artifact_dedupe.add_argument("--image", dest="image_id")
    project_rebuild_correlations = project_sub.add_parser("rebuild-correlations")
    project_rebuild_correlations.add_argument("case_id")
    project_rebuild_correlations.add_argument("--image", dest="image_id")
    project_rebuild_sessions = project_sub.add_parser("rebuild-sessions")
    project_rebuild_sessions.add_argument("case_id")
    project_rebuild_sessions.add_argument("--image", dest="image_id")
    project_rebuild_postprocess = project_sub.add_parser("rebuild-postprocess")
    project_rebuild_postprocess.add_argument("case_id")
    project_rebuild_postprocess.add_argument("--image", dest="image_id")
    project_rebuild_postprocess.add_argument("--max-windows-old-output-rows", type=int, default=100_000)

    carve = subparsers.add_parser("carve")
    carve_sub = carve.add_subparsers(dest="action", required=True)
    carve_sqlite = carve_sub.add_parser("sqlite")
    carve_sqlite.add_argument("--case", required=True, dest="case_id")
    carve_sqlite.add_argument("--path", required=True, help="Raw source file, staged carve directory, or candidate SQLite file")
    carve_sqlite.add_argument("--computer", dest="computer_id")
    carve_sqlite.add_argument("--image", dest="image_id")
    carve_sqlite.add_argument("--profile", default="windows-database-carve")
    carve_sqlite.add_argument("--max-carves", type=int, default=1000)
    carve_sqlite.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024 * 1024)
    carve_sqlite.add_argument("--max-carve-size", type=int, default=256 * 1024 * 1024)
    carve_sqlite.add_argument("--start-offset", type=int, default=0)
    carve_sqlite.add_argument("--chunk-size", type=int, default=64 * 1024 * 1024)
    carve_sqlite.add_argument("--max-rows-per-table", type=int, default=25)
    carve_sqlite.add_argument(
        "--import-artifacts",
        action="store_true",
        help="Route recognized staged SQLite files through Firefox, Chromium, or Activities parsers",
    )
    carve_sqlite.add_argument(
        "--import-windows-search-memory",
        action="store_true",
        help="Also parse staged SQLite carves into the Windows Search memory carve tables",
    )
    carve_ese = carve_sub.add_parser("ese")
    carve_ese.add_argument("--case", required=True, dest="case_id")
    carve_ese.add_argument("--path", required=True, help="Raw source file, staged carve directory, or candidate ESE file")
    carve_ese.add_argument("--computer", dest="computer_id")
    carve_ese.add_argument("--image", dest="image_id")
    carve_ese.add_argument("--profile", default="windows-database-carve")
    carve_ese.add_argument("--max-carves", type=int, default=1000)
    carve_ese.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024 * 1024)
    carve_ese.add_argument("--max-carve-size", type=int, default=512 * 1024 * 1024)
    carve_ese.add_argument("--start-offset", type=int, default=0)
    carve_ese.add_argument("--chunk-size", type=int, default=64 * 1024 * 1024)

    computer = subparsers.add_parser("computer")
    computer_sub = computer.add_subparsers(dest="action", required=True)
    computer_add = computer_sub.add_parser("add")
    computer_add.add_argument("--case", required=True, dest="case_id")
    computer_add.add_argument("--label", required=True)
    computer_add.add_argument("--hostname")
    computer_add.add_argument("--notes")
    computer_list = computer_sub.add_parser("list")
    computer_list.add_argument("--case", required=True, dest="case_id")

    image = subparsers.add_parser("image")
    image_sub = image.add_subparsers(dest="action", required=True)
    image_add = image_sub.add_parser("add")
    image_add.add_argument("--case", required=True, dest="case_id")
    image_add.add_argument("--path", required=True)
    image_add.add_argument("--computer", dest="computer_id")
    image_mount = image_sub.add_parser("mount")
    image_mount.add_argument("--case", required=True, dest="case_id")
    image_mount.add_argument("--image", required=True, dest="image_id")
    image_mount.add_argument(
        "--filesystem",
        action="store_true",
        help="Mount the selected NTFS volume read-only after image preparation",
    )
    image_mount.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for the read-only NTFS mount command",
    )
    image_unmount = image_sub.add_parser("unmount")
    image_unmount.add_argument("--case", required=True, dest="case_id")
    image_unmount.add_argument("--image", required=True, dest="image_id")
    image_unmount.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for the unmount command",
    )
    image_stale = image_sub.add_parser("cleanup-stale-mounts")
    image_stale.add_argument("--case", required=True, dest="case_id")
    image_stale.add_argument("--apply", action="store_true", help="Unmount stale mount paths; default is dry-run")
    image_stale.add_argument("--sudo", action="store_true", dest="use_sudo_mount")

    cloud = subparsers.add_parser("cloud")
    cloud_sub = cloud.add_subparsers(dest="action", required=True)
    cloud_import = cloud_sub.add_parser("import-logs")
    cloud_import.add_argument("--case", required=True, dest="case_id")
    cloud_import.add_argument("--path", required=True)
    cloud_import.add_argument("--computer", dest="computer_id")
    cloud_import.add_argument("--provider")
    cloud_import.add_argument("--service")

    memory = subparsers.add_parser("memory")
    memory_sub = memory.add_subparsers(dest="action", required=True)
    memory_strings = memory_sub.add_parser("strings")
    memory_strings.add_argument("--case", required=True, dest="case_id")
    memory_strings.add_argument("--path", required=True)
    memory_strings.add_argument("--computer", dest="computer_id")
    memory_strings.add_argument("--image", dest="image_id")
    memory_strings.add_argument("--min-length", type=int, default=6)
    memory_strings.add_argument("--no-decompress-hiberfil", action="store_true")
    memory_crash_dumps = memory_sub.add_parser("crash-dumps")
    memory_crash_dumps.add_argument("--case", required=True, dest="case_id")
    memory_crash_dumps.add_argument("--computer", dest="computer_id")
    memory_crash_dumps.add_argument("--image", dest="image_id")
    memory_crash_dumps.add_argument("--min-length", type=int, default=6)
    memory_crash_dumps.add_argument("--workers", type=int, default=1, help="Run dump string scanning with this many workers; database ingest remains serialized")
    memory_crash_dumps.add_argument("--copy", action="store_true", help="Copy accessible crash dumps into the case supplemental folder before scanning")
    memory_profile = memory_sub.add_parser("profile")
    memory_profile.add_argument("--case", required=True, dest="case_id")
    memory_profile.add_argument("--computer", dest="computer_id")
    memory_profile.add_argument("--image", dest="image_id")
    memory_profile.add_argument("--min-length", type=int, default=6)
    memory_profile.add_argument("--workers", type=int, default=1, help="Run file scanning with this many workers; database ingest remains serialized")
    memory_profile.add_argument("--no-crash-dumps", action="store_true")
    memory_profile.add_argument("--no-extract-fallback", action="store_true", help="Do not extract MFT-discovered memory support files with icat when mounts are unavailable")
    memory_search_carves = memory_sub.add_parser("windows-search-carves")
    memory_search_carves.add_argument("--case", required=True, dest="case_id")
    memory_search_carves.add_argument("--path", required=True, help="Directory or file containing SearchIndexer SQLite memory carves")
    memory_search_carves.add_argument("--computer", dest="computer_id")
    memory_search_carves.add_argument("--image", dest="image_id")
    memory_search_carves.add_argument("--max-rows-per-table", type=int, default=100)

    vsc = subparsers.add_parser("vsc")
    vsc_sub = vsc.add_subparsers(dest="action", required=True)
    vsc_list = vsc_sub.add_parser("list")
    vsc_list.add_argument("--case", required=True, dest="case_id")
    vsc_list.add_argument("--image", required=True, dest="image_id")
    vsc_mount = vsc_sub.add_parser("mount")
    vsc_mount.add_argument("--case", required=True, dest="case_id")
    vsc_mount.add_argument("--image", required=True, dest="image_id")
    vsc_mount.add_argument("--snapshot", required=True, type=int, dest="snapshot_index")
    vsc_mount.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for the read-only NTFS mount command",
    )
    vsc_extract = vsc_sub.add_parser("extract")
    vsc_extract.add_argument("--case", required=True, dest="case_id")
    vsc_extract.add_argument("--snapshot", required=True, dest="snapshot_id")
    vsc_extract.add_argument("--path", required=True, dest="relative_path")
    vsc_prefetch = vsc_sub.add_parser("prefetch-scan")
    vsc_prefetch.add_argument("--case", required=True, dest="case_id")
    vsc_prefetch.add_argument("--image", required=True, dest="image_id")
    vsc_prefetch.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_prefetch.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_registry = vsc_sub.add_parser("registry-scan")
    vsc_registry.add_argument("--case", required=True, dest="case_id")
    vsc_registry.add_argument("--image", required=True, dest="image_id")
    vsc_registry.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_registry.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_browser = vsc_sub.add_parser("browser-scan")
    vsc_browser.add_argument("--case", required=True, dest="case_id")
    vsc_browser.add_argument("--image", required=True, dest="image_id")
    vsc_browser.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_browser.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_appcompat = vsc_sub.add_parser("appcompat-scan")
    vsc_appcompat.add_argument("--case", required=True, dest="case_id")
    vsc_appcompat.add_argument("--image", required=True, dest="image_id")
    vsc_appcompat.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_appcompat.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_srum = vsc_sub.add_parser("srum-scan")
    vsc_srum.add_argument("--case", required=True, dest="case_id")
    vsc_srum.add_argument("--image", required=True, dest="image_id")
    vsc_srum.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_srum.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_evtx = vsc_sub.add_parser("evtx-triage-scan")
    vsc_evtx.add_argument("--case", required=True, dest="case_id")
    vsc_evtx.add_argument("--image", required=True, dest="image_id")
    vsc_evtx.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_evtx.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_ntfs = vsc_sub.add_parser("ntfs-delta-scan")
    vsc_ntfs.add_argument("--case", required=True, dest="case_id")
    vsc_ntfs.add_argument("--image", required=True, dest="image_id")
    vsc_ntfs.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_ntfs.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_recycle = vsc_sub.add_parser("recycle-scan")
    vsc_recycle.add_argument("--case", required=True, dest="case_id")
    vsc_recycle.add_argument("--image", required=True, dest="image_id")
    vsc_recycle.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_recycle.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_search = vsc_sub.add_parser("windows-search-scan")
    vsc_search.add_argument("--case", required=True, dest="case_id")
    vsc_search.add_argument("--image", required=True, dest="image_id")
    vsc_search.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_search.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_file_history = vsc_sub.add_parser("file-history-report")
    vsc_file_history.add_argument("--case", required=True, dest="case_id")
    vsc_file_history.add_argument("--image", required=True, dest="image_id")
    vsc_profile = vsc_sub.add_parser("profile-scan")
    vsc_profile.add_argument("--case", required=True, dest="case_id")
    vsc_profile.add_argument("--image", required=True, dest="image_id")
    vsc_profile.add_argument("--profile", choices=sorted(VSC_PROFILES), default="history")
    vsc_profile.add_argument(
        "--snapshot",
        action="append",
        type=int,
        dest="snapshot_indexes",
        help="Snapshot index to scan; repeat for multiple snapshots. Defaults to all discovered snapshots.",
    )
    vsc_profile.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for each read-only VSC NTFS mount",
    )
    vsc_profile.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop profile execution after the first failed scan",
    )
    vsc_unmount = vsc_sub.add_parser("unmount")
    vsc_unmount.add_argument("--case", required=True, dest="case_id")
    vsc_unmount.add_argument("--snapshot", dest="snapshot_id")
    vsc_unmount.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for VSC NTFS unmount commands",
    )

    tools = subparsers.add_parser("tools")
    tools_sub = tools.add_subparsers(dest="action", required=True)
    tools_sub.add_parser("list")
    tools_profile_preview = tools_sub.add_parser("profile-preview")
    tools_profile_preview.add_argument("--profile", required=True)

    run = subparsers.add_parser("run")
    run.add_argument("--case", required=True, dest="case_id")
    run.add_argument("--image", required=True, dest="image_id")
    run.add_argument("--profile", required=True)
    run.add_argument(
        "--include-start-menu-lnk",
        action="store_true",
        help="Include Start Menu .lnk files in LECmd parsing; excluded by default",
    )
    run.add_argument(
        "--replace-existing",
        action="store_true",
        help="Delete existing DB output rows for this image/profile before importing fresh results",
    )
    run.add_argument(
        "--accept-duplicate",
        action="store_true",
        help="Import output even when the same content hash already exists for this image/tool",
    )
    run.add_argument(
        "--include-deleted-mft",
        action="store_true",
        help="Include deleted/orphaned MFT entries in MFT-driven artifact extraction; default is live MFT entries only",
    )
    run.add_argument(
        "--include-live-orphans",
        action="store_true",
        help="Include allocated MFT records missing from active INDX entries; default is mounted/active namespace only",
    )
    run.add_argument(
        "--include-windows-old",
        action="store_true",
        help="Run the selected profile against Windows.old artifacts only, storing output under a Windows.old namespace",
    )
    run.add_argument("--include-memory-profile", action="store_true", help="Run memory support-file processing after the selected profile")
    run.add_argument("--no-memory-profile", action="store_true", help="Skip automatic memory support-file processing for profiles that normally include it")
    run.add_argument("--workers", type=int, default=1, help="Worker slots for external tool output generation; database ingest and internal parsers remain serialized")

    process = subparsers.add_parser("process")
    process.add_argument("--case", dest="case_id", help="Existing case/project ID; creates one when omitted")
    process.add_argument("--path", required=True, help="Path to the source E01 image")
    process.add_argument("--computer", dest="computer_id", help="Existing computer ID for this case")
    process.add_argument("--computer-label", help="Computer label to create when --computer is not supplied")
    process.add_argument("--hostname")
    process.add_argument("--profile", default="windows-basic", help="Tool profile to run")
    process.add_argument(
        "--filesystem",
        action="store_true",
        help="Mount the selected NTFS volume read-only before running tools",
    )
    process.add_argument(
        "--sudo",
        action="store_true",
        dest="use_sudo_mount",
        help="Use non-interactive sudo for read-only mount/unmount commands",
    )
    process.add_argument(
        "--keep-mounted",
        action="store_true",
        help="Leave the read-only filesystem mount active after processing",
    )
    process.add_argument(
        "--include-start-menu-lnk",
        action="store_true",
        help="Include Start Menu .lnk files in LECmd parsing; excluded by default",
    )
    process.add_argument(
        "--replace-existing",
        action="store_true",
        help="Delete existing DB output rows for this image/profile before importing fresh results",
    )
    process.add_argument(
        "--accept-duplicate",
        action="store_true",
        help="Import output even when the same content hash already exists for this image/tool",
    )
    process.add_argument(
        "--include-deleted-mft",
        action="store_true",
        help="Include deleted/orphaned MFT entries in MFT-driven artifact extraction; default is live MFT entries only",
    )
    process.add_argument(
        "--include-live-orphans",
        action="store_true",
        help="Include allocated MFT records missing from active INDX entries; default is mounted/active namespace only",
    )
    process.add_argument(
        "--include-windows-old",
        action="store_true",
        help="Run the selected profile against Windows.old artifacts only, storing output under a Windows.old namespace",
    )
    process.add_argument("--include-memory-profile", action="store_true", help="Run memory support-file processing after the selected profile")
    process.add_argument("--no-memory-profile", action="store_true", help="Skip automatic memory support-file processing for profiles that normally include it")
    process.add_argument("--workers", type=int, default=1, help="Worker slots for external tool output generation; database ingest and internal parsers remain serialized")

    report_bundle = subparsers.add_parser("report-bundle")
    report_bundle_sub = report_bundle.add_subparsers(dest="action", required=True)
    report_bundle_import = report_bundle_sub.add_parser("import")
    report_bundle_import.add_argument("--case", dest="case_id", help="Existing case/project ID; creates one when omitted")
    report_bundle_import.add_argument("--path", required=True, help="Directory containing pre-generated report CSVs")
    report_bundle_import.add_argument("--computer", dest="computer_id", help="Existing computer ID for this case")
    report_bundle_import.add_argument("--computer-label", help="Computer label to create when --computer is not supplied")
    report_bundle_import.add_argument(
        "--accept-duplicate",
        action="store_true",
        help="Import output even when the same content hash already exists for this evidence source/tool",
    )

    report = subparsers.add_parser("report")
    report_sub = report.add_subparsers(dest="action", required=True)
    report_summary = report_sub.add_parser("summary")
    report_summary.add_argument("--case", required=True, dest="case_id")
    report_specs = report_sub.add_parser("specs")
    report_specs.add_argument("--format", choices=["json", "table", "csv"], default="table")
    report_specs.add_argument("--output")
    report_spec = report_sub.add_parser("spec")
    report_spec.add_argument("--case", required=True, dest="case_id")
    report_spec.add_argument("--name", required=True)
    report_spec.add_argument("--limit", type=int, default=100)
    report_spec.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_spec.add_argument("--output")
    report_storage_policy = report_sub.add_parser("storage-policy")
    report_storage_policy.add_argument("--case", required=True, dest="case_id")
    report_storage_policy.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_storage_policy.add_argument("--output")
    report_issues = report_sub.add_parser("issues")
    report_issues.add_argument("--case", required=True, dest="case_id")
    report_issues.add_argument("--limit", type=int, default=100)
    report_execution = report_sub.add_parser("execution")
    report_execution.add_argument("--case", required=True, dest="case_id")
    report_execution.add_argument("--limit", type=int, default=100)
    report_execution.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_execution.add_argument("--output")
    report_execution_correlation = report_sub.add_parser("execution-correlation")
    report_execution_correlation.add_argument("--case", required=True, dest="case_id")
    report_execution_correlation.add_argument("--limit", type=int, default=100)
    report_execution_correlation.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_execution_correlation.add_argument("--output")
    report_persistence = report_sub.add_parser("persistence")
    report_persistence.add_argument("--case", required=True, dest="case_id")
    report_persistence.add_argument("--limit", type=int, default=100)
    report_persistence.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_persistence.add_argument("--output")
    report_autostarts = report_sub.add_parser("autostarts")
    report_autostarts.add_argument("--case", required=True, dest="case_id")
    report_autostarts.add_argument("--limit", type=int, default=1000)
    report_autostarts.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_autostarts.add_argument("--output")
    report_bruteforce = report_sub.add_parser("brute-force")
    report_bruteforce.add_argument("--case", required=True, dest="case_id")
    report_bruteforce.add_argument("--limit", type=int, default=100)
    report_bruteforce.add_argument("--min-failures", type=int, default=20)
    report_bruteforce.add_argument("--spray-account-threshold", type=int, default=10)
    report_bruteforce.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_bruteforce.add_argument("--output")
    report_malware_hiding = report_sub.add_parser("malware-hiding-places")
    report_malware_hiding.add_argument("--case", required=True, dest="case_id")
    report_malware_hiding.add_argument("--limit", type=int, default=100)
    report_malware_hiding.add_argument("--long-value-threshold", type=int, default=300)
    report_malware_hiding.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_malware_hiding.add_argument("--output")
    report_interesting_executables = report_sub.add_parser("interesting-executables")
    report_interesting_executables.add_argument("--case", required=True, dest="case_id")
    report_interesting_executables.add_argument("--limit", type=int, default=100)
    report_interesting_executables.add_argument("--rules", help="Path to an editable interesting executables YAML rule file")
    report_interesting_executables.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_interesting_executables.add_argument("--output")
    report_suspicious_executions = report_sub.add_parser("suspicious-executions")
    report_suspicious_executions.add_argument("--case", required=True, dest="case_id")
    report_suspicious_executions.add_argument("--limit", type=int, default=100)
    report_suspicious_executions.add_argument("--rules", help="Path to an editable interesting executables YAML rule file")
    report_suspicious_executions.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_suspicious_executions.add_argument("--output")
    report_suspicious_windows = report_sub.add_parser("suspicious-timeline-windows")
    report_suspicious_windows.add_argument("--case", required=True, dest="case_id")
    report_suspicious_windows.add_argument("--limit", type=int, default=100)
    report_suspicious_windows.add_argument("--window-minutes", type=int, default=30)
    report_suspicious_windows.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_suspicious_windows.add_argument("--output")
    report_triage_dashboard = report_sub.add_parser("triage-dashboard")
    report_triage_dashboard.add_argument("--case", required=True, dest="case_id")
    report_triage_dashboard.add_argument("--limit", type=int, default=25)
    report_triage_dashboard.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_triage_dashboard.add_argument("--output")
    report_data_exfiltration = report_sub.add_parser("data-exfiltration")
    report_data_exfiltration.add_argument("--case", required=True, dest="case_id")
    report_data_exfiltration.add_argument("--limit", type=int, default=100)
    report_data_exfiltration.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_data_exfiltration.add_argument("--output")
    report_account_compromise = report_sub.add_parser("account-compromise")
    report_account_compromise.add_argument("--case", required=True, dest="case_id")
    report_account_compromise.add_argument("--limit", type=int, default=100)
    report_account_compromise.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_account_compromise.add_argument("--output")
    report_program_provenance = report_sub.add_parser("program-provenance")
    report_program_provenance.add_argument("--case", required=True, dest="case_id")
    report_program_provenance.add_argument("--limit", type=int, default=100)
    report_program_provenance.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_program_provenance.add_argument("--output")
    report_cd_burning = report_sub.add_parser("cd-burning")
    report_cd_burning.add_argument("--case", required=True, dest="case_id")
    report_cd_burning.add_argument("--limit", type=int, default=250)
    report_cd_burning.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_cd_burning.add_argument("--output")
    report_accounts = report_sub.add_parser("accounts")
    report_accounts.add_argument("--case", required=True, dest="case_id")
    report_prefetch = report_sub.add_parser("prefetch")
    report_prefetch.add_argument("--case", required=True, dest="case_id")
    report_prefetch.add_argument("--limit", type=int, default=100)
    report_mft = report_sub.add_parser("mft")
    report_mft.add_argument("--case", required=True, dest="case_id")
    report_mft.add_argument("--limit", type=int, default=100)
    report_ntfs_index = report_sub.add_parser("ntfs-index")
    report_ntfs_index.add_argument("--case", required=True, dest="case_id")
    report_ntfs_index.add_argument("--limit", type=int, default=100)
    report_ntfs_logfile = report_sub.add_parser("ntfs-logfile")
    report_ntfs_logfile.add_argument("--case", required=True, dest="case_id")
    report_ntfs_logfile.add_argument("--limit", type=int, default=100)
    report_ntfs_namespace = report_sub.add_parser("ntfs-namespace")
    report_ntfs_namespace.add_argument("--case", required=True, dest="case_id")
    report_ntfs_namespace.add_argument("--limit", type=int, default=100)
    report_filesystem_review = report_sub.add_parser("filesystem-review")
    report_filesystem_review.add_argument("--case", required=True, dest="case_id")
    report_filesystem_review.add_argument("--contains")
    report_filesystem_review.add_argument("--event-type")
    report_filesystem_review.add_argument("--status")
    report_filesystem_review.add_argument("--source-table")
    report_filesystem_review.add_argument("--limit", type=int, default=100)
    report_user_file_refs = report_sub.add_parser("user-file-references")
    report_user_file_refs.add_argument("--case", required=True, dest="case_id")
    report_user_file_refs.add_argument("--provider")
    report_user_file_refs.add_argument("--scope")
    report_user_file_refs.add_argument("--user")
    report_user_file_refs.add_argument("--contains")
    report_user_file_refs.add_argument("--limit", type=int, default=100)
    report_user_file_refs.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_user_file_refs.add_argument("--output")
    report_user_file_ref_source = report_sub.add_parser("user-file-reference-source")
    report_user_file_ref_source.add_argument("--case", required=True, dest="case_id")
    report_user_file_ref_source.add_argument("--id", required=True, dest="reference_id")
    report_user_file_ref_source.add_argument("--output")
    report_evtx = report_sub.add_parser("evtx")
    report_evtx.add_argument("--case", required=True, dest="case_id")
    report_evtx.add_argument("--limit", type=int, default=100)
    report_evtx_recovery = report_sub.add_parser("evtx-recovery")
    report_evtx_recovery.add_argument("--case", required=True, dest="case_id")
    report_evtx_recovery.add_argument("--limit", type=int, default=100)
    report_recovery_coverage = report_sub.add_parser("recovery-coverage")
    report_recovery_coverage.add_argument("--case", required=True, dest="case_id")
    report_recovery_coverage.add_argument("--limit", type=int, default=500)
    report_recovery_coverage.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_recovery_coverage.add_argument("--output")
    report_carve_coverage = report_sub.add_parser("carve-coverage")
    report_carve_coverage.add_argument("--case", required=True, dest="case_id")
    report_carve_coverage.add_argument("--limit", type=int, default=500)
    report_carve_coverage.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_carve_coverage.add_argument("--output")
    report_sqlite_inventory = report_sub.add_parser("sqlite-inventory")
    report_sqlite_inventory.add_argument("--case", required=True, dest="case_id")
    report_sqlite_inventory.add_argument("--limit", type=int, default=100)
    report_sqlite_inventory.add_argument("--sample-rows", type=int, default=0)
    report_sqlite_inventory.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_sqlite_inventory.add_argument("--output")
    report_telemetry = report_sub.add_parser("telemetry-artifacts")
    report_telemetry.add_argument("--case", required=True, dest="case_id")
    report_telemetry.add_argument("--artifact-group")
    report_telemetry.add_argument("--contains")
    report_telemetry.add_argument("--limit", type=int, default=100)
    report_telemetry.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_telemetry.add_argument("--output")
    report_artifact_correlations = report_sub.add_parser("artifact-correlations")
    report_artifact_correlations.add_argument("--case", required=True, dest="case_id")
    report_artifact_correlations.add_argument("--type", dest="correlation_type")
    report_artifact_correlations.add_argument("--confidence")
    report_artifact_correlations.add_argument("--limit", type=int, default=100)
    report_artifact_correlations.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_artifact_correlations.add_argument("--output")
    report_correlation_groups = report_sub.add_parser("correlation-groups")
    report_correlation_groups.add_argument("--case", required=True, dest="case_id")
    report_correlation_groups.add_argument("--category")
    report_correlation_groups.add_argument("--rule-id")
    report_correlation_groups.add_argument("--contains")
    report_correlation_groups.add_argument("--limit", type=int, default=100)
    report_correlation_groups.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_correlation_groups.add_argument("--output")
    report_correlation_group = report_sub.add_parser("correlation-group")
    report_correlation_group.add_argument("--case", required=True, dest="case_id")
    report_correlation_group.add_argument("--id", required=True, dest="group_id")
    report_correlation_group.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_correlation_group.add_argument("--output")
    report_sessions = report_sub.add_parser("sessions")
    report_sessions.add_argument("--case", required=True, dest="case_id")
    report_sessions.add_argument("--type", dest="session_type", choices=["vpn", "rdp", "logon"])
    report_sessions.add_argument("--user")
    report_sessions.add_argument("--contains")
    report_sessions.add_argument("--limit", type=int, default=100)
    report_sessions.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_sessions.add_argument("--output")
    report_session = report_sub.add_parser("session")
    report_session.add_argument("--case", required=True, dest="case_id")
    report_session.add_argument("--id", required=True, dest="session_id")
    report_session.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_session.add_argument("--output")
    report_computer_inventory = report_sub.add_parser("computer-inventory")
    report_computer_inventory.add_argument("--case", required=True, dest="case_id")
    report_computer_inventory.add_argument("--category")
    report_computer_inventory.add_argument("--limit", type=int, default=500)
    report_computer_inventory.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_computer_inventory.add_argument("--output")
    report_recycle = report_sub.add_parser("recycle")
    report_recycle.add_argument("--case", required=True, dest="case_id")
    report_recycle.add_argument("--user")
    report_recycle.add_argument("--limit", type=int, default=100)
    report_deleted = report_sub.add_parser("deleted-folders")
    report_deleted.add_argument("--case", required=True, dest="case_id")
    report_deleted.add_argument("--limit", type=int, default=100)
    report_firefox = report_sub.add_parser("firefox")
    report_firefox.add_argument("--case", required=True, dest="case_id")
    report_firefox.add_argument("--limit", type=int, default=100)
    report_browser = report_sub.add_parser("browser")
    report_browser.add_argument("--case", required=True, dest="case_id")
    report_browser.add_argument(
        "--type",
        choices=["history", "downloads", "cookies", "artifacts", "sessions", "site-settings", "notifications"],
        default="history",
        dest="report_type",
    )
    report_browser.add_argument("--limit", type=int, default=100)
    report_browser_artifacts = report_sub.add_parser("browser-artifacts")
    report_browser_artifacts.add_argument("--case", required=True, dest="case_id")
    report_browser_artifacts.add_argument("--artifact-type")
    report_browser_artifacts.add_argument("--browser")
    report_browser_artifacts.add_argument("--contains")
    report_browser_artifacts.add_argument("--limit", type=int, default=100)
    report_browser_artifacts.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_browser_artifacts.add_argument("--output")
    report_office_backstage = report_sub.add_parser("office-backstage")
    report_office_backstage.add_argument("--case", required=True, dest="case_id")
    report_office_backstage.add_argument("--artifact-type")
    report_office_backstage.add_argument("--contains")
    report_office_backstage.add_argument("--limit", type=int, default=100)
    report_office_backstage.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_office_backstage.add_argument("--output")
    report_user_dictionaries = report_sub.add_parser("user-dictionaries")
    report_user_dictionaries.add_argument("--case", required=True, dest="case_id")
    report_user_dictionaries.add_argument("--user")
    report_user_dictionaries.add_argument("--contains")
    report_user_dictionaries.add_argument("--limit", type=int, default=100)
    report_user_dictionaries.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_user_dictionaries.add_argument("--output")
    report_downloaded_files = report_sub.add_parser("downloaded-files")
    report_downloaded_files.add_argument("--case", required=True, dest="case_id")
    report_downloaded_files.add_argument("--user")
    report_downloaded_files.add_argument("--contains")
    report_downloaded_files.add_argument("--limit", type=int, default=100)
    report_downloaded_files.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_downloaded_files.add_argument("--output")
    report_uninstalled_apps = report_sub.add_parser("uninstalled-app-artifacts")
    report_uninstalled_apps.add_argument("--case", required=True, dest="case_id")
    report_uninstalled_apps.add_argument("--application")
    report_uninstalled_apps.add_argument("--limit", type=int, default=100)
    report_uninstalled_apps.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_uninstalled_apps.add_argument("--output")
    report_tor_usage = report_sub.add_parser("tor-usage")
    report_tor_usage.add_argument("--case", required=True, dest="case_id")
    report_tor_usage.add_argument("--limit", type=int, default=100)
    report_tor_usage.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_tor_usage.add_argument("--output")
    report_encrypted_volumes = report_sub.add_parser("encrypted-volumes")
    report_encrypted_volumes.add_argument("--case", required=True, dest="case_id")
    report_encrypted_volumes.add_argument("--limit", type=int, default=100)
    report_encrypted_volumes.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_encrypted_volumes.add_argument("--output")
    report_phone_link = report_sub.add_parser("phone-link")
    report_phone_link.add_argument("--case", required=True, dest="case_id")
    report_phone_link.add_argument("--record-type")
    report_phone_link.add_argument("--user")
    report_phone_link.add_argument("--limit", type=int, default=100)
    report_phone_link.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_phone_link.add_argument("--output")
    report_virtualization = report_sub.add_parser("virtualization")
    report_virtualization.add_argument("--case", required=True, dest="case_id")
    report_virtualization.add_argument("--limit", type=int, default=100)
    report_virtualization.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_virtualization.add_argument("--output")
    report_thumbcache = report_sub.add_parser("thumbcache")
    report_thumbcache.add_argument("--case", required=True, dest="case_id")
    report_thumbcache.add_argument("--user")
    report_thumbcache.add_argument("--confidence", choices=["high", "low"])
    report_thumbcache.add_argument("--limit", type=int, default=100)
    report_thumbcache.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_thumbcache.add_argument("--output")
    report_rdp_cache = report_sub.add_parser("rdp-cache")
    report_rdp_cache.add_argument("--case", required=True, dest="case_id")
    report_rdp_cache.add_argument("--user")
    report_rdp_cache.add_argument("--record-type", choices=["cache_file", "fragment", "contact_sheet", "extraction_status"])
    report_rdp_cache.add_argument("--limit", type=int, default=100)
    report_rdp_cache.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_rdp_cache.add_argument("--output")
    report_rdp_visual = report_sub.add_parser("rdp-visual-observations")
    report_rdp_visual.add_argument("--case", required=True, dest="case_id")
    report_rdp_visual.add_argument("--user")
    report_rdp_visual.add_argument("--limit", type=int, default=100)
    report_rdp_visual.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_rdp_visual.add_argument("--output")
    report_image_analysis = report_sub.add_parser("image-analysis")
    report_image_analysis.add_argument("--case", required=True, dest="case_id")
    report_image_analysis.add_argument("--source-artifact-type")
    report_image_analysis.add_argument("--contains")
    report_image_analysis.add_argument("--ocr-only", action="store_true")
    report_image_analysis.add_argument("--limit", type=int, default=100)
    report_image_analysis.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_image_analysis.add_argument("--output")
    report_browser_downloads = report_sub.add_parser("browser-downloads")
    report_browser_downloads.add_argument("--case", required=True, dest="case_id")
    report_browser_downloads.add_argument("--limit", type=int, default=100)
    report_browser_downloads.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_browser_downloads.add_argument("--output")
    report_browser_cache = report_sub.add_parser("browser-cache")
    report_browser_cache.add_argument("--case", required=True, dest="case_id")
    report_browser_cache.add_argument("--browser")
    report_browser_cache.add_argument("--host")
    report_browser_cache.add_argument("--exclude-noise", action="store_true")
    report_browser_cache.add_argument("--limit", type=int, default=100)
    report_browser_cache.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_browser_cache.add_argument("--output")
    report_browser_hosts = report_sub.add_parser("browser-hosts")
    report_browser_hosts.add_argument("--case", required=True, dest="case_id")
    report_browser_hosts.add_argument("--browser")
    report_browser_hosts.add_argument("--exclude-noise", action="store_true")
    report_browser_hosts.add_argument("--limit", type=int, default=100)
    report_browser_hosts.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_browser_hosts.add_argument("--output")
    report_browser_activity = report_sub.add_parser("browser-activity")
    report_browser_activity.add_argument("--case", required=True, dest="case_id")
    report_browser_activity.add_argument("--browser")
    report_browser_activity.add_argument("--user")
    report_browser_activity.add_argument("--include-noise", action="store_true")
    report_browser_activity.add_argument("--limit", type=int, default=100)
    report_browser_activity.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_browser_activity.add_argument("--output")
    report_browser_profile_activity = report_sub.add_parser("browser-profile-activity")
    report_browser_profile_activity.add_argument("--case", required=True, dest="case_id")
    report_browser_profile_activity.add_argument("--limit", type=int, default=100)
    report_browser_profile_activity.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_browser_profile_activity.add_argument("--output")
    report_browser_deep_storage = report_sub.add_parser("browser-deep-storage")
    report_browser_deep_storage.add_argument("--case", required=True, dest="case_id")
    report_browser_deep_storage.add_argument("--limit", type=int, default=250)
    report_browser_deep_storage.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_browser_deep_storage.add_argument("--output")
    report_browser_cache_correlations = report_sub.add_parser("browser-cache-correlations")
    report_browser_cache_correlations.add_argument("--case", required=True, dest="case_id")
    report_browser_cache_correlations.add_argument("--browser")
    report_browser_cache_correlations.add_argument("--include-noise", action="store_true")
    report_browser_cache_correlations.add_argument("--limit", type=int, default=100)
    report_browser_cache_correlations.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_browser_cache_correlations.add_argument("--output")
    report_windows_activities = report_sub.add_parser("windows-activities")
    report_windows_activities.add_argument("--case", required=True, dest="case_id")
    report_windows_activities.add_argument("--user")
    report_windows_activities.add_argument("--app")
    report_windows_activities.add_argument("--include-auxiliary", action="store_true")
    report_windows_activities.add_argument("--files-only", action="store_true")
    report_windows_activities.add_argument("--limit", type=int, default=100)
    report_windows_activities.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_windows_activities.add_argument("--output")
    report_webcache = report_sub.add_parser("webcache")
    report_webcache.add_argument("--case", required=True, dest="case_id")
    report_webcache.add_argument("--limit", type=int, default=100)
    report_webcache.add_argument("--application")
    report_webcache.add_argument("--user")
    report_webcache.add_argument("--local-files-only", action="store_true")
    report_webcache.add_argument("--exclude-metadata", action="store_true")
    report_webcache.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_webcache.add_argument("--output")
    report_webcache_files = report_sub.add_parser("webcache-files")
    report_webcache_files.add_argument("--case", required=True, dest="case_id")
    report_webcache_files.add_argument("--limit", type=int, default=100)
    report_webcache_files.add_argument("--application")
    report_webcache_files.add_argument("--user")
    report_webcache_files.add_argument("--usb-overlap", action="store_true")
    report_webcache_files.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_webcache_files.add_argument("--output")
    report_cloud = report_sub.add_parser("cloud-artifacts")
    report_cloud.add_argument("--case", required=True, dest="case_id")
    report_cloud.add_argument("--limit", type=int, default=100)
    report_cloud.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_cloud.add_argument("--output")
    report_cloud_files = report_sub.add_parser("cloud-files")
    report_cloud_files.add_argument("--case", required=True, dest="case_id")
    report_cloud_files.add_argument("--provider")
    report_cloud_files.add_argument("--exclude-deleted", action="store_true")
    report_cloud_files.add_argument("--limit", type=int, default=100)
    report_cloud_files.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_cloud_files.add_argument("--output")
    report_cloud_configuration = report_sub.add_parser("cloud-configuration")
    report_cloud_configuration.add_argument("--case", required=True, dest="case_id")
    report_cloud_configuration.add_argument("--provider")
    report_cloud_configuration.add_argument("--user")
    report_cloud_configuration.add_argument("--limit", type=int, default=250)
    report_cloud_configuration.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_cloud_configuration.add_argument("--output")
    report_web_cloud = report_sub.add_parser("web-cloud-correlations")
    report_web_cloud.add_argument("--case", required=True, dest="case_id")
    report_web_cloud.add_argument("--provider")
    report_web_cloud.add_argument("--category", choices=["cloud_storage", "webmail"])
    report_web_cloud.add_argument("--user")
    report_web_cloud.add_argument("--contains")
    report_web_cloud.add_argument("--limit", type=int, default=250)
    report_web_cloud.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_web_cloud.add_argument("--output")
    report_email = report_sub.add_parser("email-artifacts")
    report_email.add_argument("--case", required=True, dest="case_id")
    report_email.add_argument("--limit", type=int, default=100)
    report_email.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_email.add_argument("--output")
    report_mailbox_messages = report_sub.add_parser("mailbox-messages")
    report_mailbox_messages.add_argument("--case", required=True, dest="case_id")
    report_mailbox_messages.add_argument("--limit", type=int, default=100)
    report_mailbox_messages.add_argument("--user")
    report_mailbox_messages.add_argument("--status")
    report_mailbox_messages.add_argument("--contains")
    report_mailbox_messages.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_mailbox_messages.add_argument("--output")
    report_mailbox_attachments = report_sub.add_parser("mailbox-attachments")
    report_mailbox_attachments.add_argument("--case", required=True, dest="case_id")
    report_mailbox_attachments.add_argument("--limit", type=int, default=100)
    report_mailbox_attachments.add_argument("--user")
    report_mailbox_attachments.add_argument("--status")
    report_mailbox_attachments.add_argument("--content-type")
    report_mailbox_attachments.add_argument("--sha256")
    report_mailbox_attachments.add_argument("--contains")
    report_mailbox_attachments.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_mailbox_attachments.add_argument("--output")
    report_mailbox_attachment_coverage = report_sub.add_parser("mailbox-attachment-coverage")
    report_mailbox_attachment_coverage.add_argument("--case", required=True, dest="case_id")
    report_mailbox_attachment_coverage.add_argument("--limit", type=int, default=100)
    report_mailbox_attachment_coverage.add_argument("--user")
    report_mailbox_attachment_coverage.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_mailbox_attachment_coverage.add_argument("--output")
    report_mailbox_attachment_copies = report_sub.add_parser("mailbox-attachment-copies")
    report_mailbox_attachment_copies.add_argument("--case", required=True, dest="case_id")
    report_mailbox_attachment_copies.add_argument("--limit", type=int, default=100)
    report_mailbox_attachment_copies.add_argument("--user")
    report_mailbox_attachment_copies.add_argument("--contains")
    report_mailbox_attachment_copies.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_mailbox_attachment_copies.add_argument("--output")
    report_mailbox_copies = report_sub.add_parser("mailbox-copies")
    report_mailbox_copies.add_argument("--case", required=True, dest="case_id")
    report_mailbox_copies.add_argument("--limit", type=int, default=100)
    report_mailbox_copies.add_argument("--user")
    report_mailbox_copies.add_argument("--contains")
    report_mailbox_copies.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_mailbox_copies.add_argument("--output")
    report_communications = report_sub.add_parser("communications")
    report_communications.add_argument("--case", required=True, dest="case_id")
    report_communications.add_argument("--limit", type=int, default=100)
    report_communications.add_argument("--user")
    report_communications.add_argument("--contains")
    report_communications.add_argument("--source-type")
    report_communications.add_argument("--include-low-value", action="store_true")
    report_communications.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_communications.add_argument("--output")
    report_communication_groups = report_sub.add_parser("communication-groups")
    report_communication_groups.add_argument("--case", required=True, dest="case_id")
    report_communication_groups.add_argument("--limit", type=int, default=100)
    report_communication_groups.add_argument("--user")
    report_communication_groups.add_argument("--contains")
    report_communication_groups.add_argument("--source-type")
    report_communication_groups.add_argument("--include-low-value", action="store_true")
    report_communication_groups.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_communication_groups.add_argument("--output")
    report_communication_review = report_sub.add_parser("communication-review")
    report_communication_review.add_argument("--case", required=True, dest="case_id")
    report_communication_review.add_argument(
        "--view",
        required=True,
        choices=["conversations", "pairs", "attachments", "indexed-only", "recovered-fragments"],
    )
    report_communication_review.add_argument("--limit", type=int, default=100)
    report_communication_review.add_argument("--user")
    report_communication_review.add_argument("--contains")
    report_communication_review.add_argument("--include-low-value", action="store_true")
    report_communication_review.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_communication_review.add_argument("--output")
    report_messaging = report_sub.add_parser("messaging-artifacts")
    report_messaging.add_argument("--case", required=True, dest="case_id")
    report_messaging.add_argument("--limit", type=int, default=100)
    report_messaging.add_argument("--application")
    report_messaging.add_argument("--type", dest="artifact_type")
    report_messaging.add_argument("--user")
    report_messaging.add_argument("--contains")
    report_messaging.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_messaging.add_argument("--output")
    report_messaging_messages = report_sub.add_parser("messaging-messages")
    report_messaging_messages.add_argument("--case", required=True, dest="case_id")
    report_messaging_messages.add_argument("--limit", type=int, default=100)
    report_messaging_messages.add_argument("--application")
    report_messaging_messages.add_argument("--user")
    report_messaging_messages.add_argument("--contains")
    report_messaging_messages.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_messaging_messages.add_argument("--output")
    report_search_runs = report_sub.add_parser("search-index-runs")
    report_search_runs.add_argument("--case", required=True, dest="case_id")
    report_search_runs.add_argument("--limit", type=int, default=100)
    report_search_runs.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_search_runs.add_argument("--output")
    report_event_interpretation = report_sub.add_parser("event-interpretation")
    report_event_interpretation.add_argument("--case", required=True, dest="case_id")
    report_event_interpretation.add_argument("--category", choices=["usb", "wifi", "cloud", "file_activity", "logon"])
    report_event_interpretation.add_argument("--limit", type=int, default=100)
    report_event_interpretation.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_event_interpretation.add_argument("--output")
    report_timeline = report_sub.add_parser("timeline")
    report_timeline.add_argument("--case", required=True, dest="case_id")
    report_timeline.add_argument("--limit", type=int, default=100)
    report_timeline.add_argument("--event-type")
    report_timeline.add_argument("--source-tool")
    report_timeline.add_argument("--contains")
    report_timeline_sources = report_sub.add_parser("timeline-sources")
    report_timeline_sources.add_argument("--case", required=True, dest="case_id")
    report_timeline_sources.add_argument("--limit", type=int, default=100)
    report_timeline_sources.add_argument("--source-scope", choices=["current", "windows_old"])
    report_timeline_sources.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_timeline_sources.add_argument("--output")
    report_artifact_sources = report_sub.add_parser("artifact-sources")
    report_artifact_sources.add_argument("--case", required=True, dest="case_id")
    report_artifact_sources.add_argument("--limit", type=int, default=100)
    report_artifact_sources.add_argument("--artifact-family")
    report_artifact_sources.add_argument("--source-scope", choices=["current", "windows_old"])
    report_artifact_sources.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_artifact_sources.add_argument("--output")
    report_timeline_review = report_sub.add_parser("timeline-review")
    report_timeline_review.add_argument("--case", required=True, dest="case_id")
    report_timeline_review.add_argument("--limit", type=int, default=500)
    report_timeline_review.add_argument("--user")
    report_timeline_review.add_argument("--contains")
    report_timeline_review.add_argument("--source")
    report_timeline_review.add_argument("--preset", choices=["memory", "suspicious", "cloud", "usb", "remote_access"])
    report_timeline_review.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_timeline_review.add_argument("--output")
    report_user_timeline = report_sub.add_parser("user-timeline")
    report_user_timeline.add_argument("--case", required=True, dest="case_id")
    report_user_timeline.add_argument("--user", required=True)
    report_user_timeline.add_argument("--limit", type=int, default=250)
    report_user_timeline.add_argument("--include-expiry", action="store_true")
    report_user_timeline.add_argument("--include-metadata", action="store_true")
    report_user_timeline.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_user_timeline.add_argument("--output")
    report_validate = report_sub.add_parser("validate")
    report_validate.add_argument("--case", required=True, dest="case_id")
    report_registry = report_sub.add_parser("registry")
    report_registry.add_argument("--case", required=True, dest="case_id")
    report_registry.add_argument("--limit", type=int, default=100)
    report_amcache = report_sub.add_parser("amcache")
    report_amcache.add_argument("--case", required=True, dest="case_id")
    report_amcache.add_argument("--limit", type=int, default=100)
    report_shimcache = report_sub.add_parser("shimcache")
    report_shimcache.add_argument("--case", required=True, dest="case_id")
    report_shimcache.add_argument("--limit", type=int, default=100)
    report_shellbags = report_sub.add_parser("shellbags")
    report_shellbags.add_argument("--case", required=True, dest="case_id")
    report_shellbags.add_argument("--limit", type=int, default=100)
    report_usn = report_sub.add_parser("usn")
    report_usn.add_argument("--case", required=True, dest="case_id")
    report_usn.add_argument("--limit", type=int, default=100)
    report_usn_summary = report_sub.add_parser("usn-summary")
    report_usn_summary.add_argument("--case", required=True, dest="case_id")
    report_usn_summary.add_argument("--limit", type=int, default=25)
    report_usn_path = report_sub.add_parser("usn-path")
    report_usn_path.add_argument("--case", required=True, dest="case_id")
    report_usn_path.add_argument("--contains", required=True)
    report_usn_path.add_argument("--limit", type=int, default=100)
    report_usn_user = report_sub.add_parser("usn-user")
    report_usn_user.add_argument("--case", required=True, dest="case_id")
    report_usn_user.add_argument("--user", required=True)
    report_usn_user.add_argument("--limit", type=int, default=100)
    report_usn_reasons = report_sub.add_parser("usn-reasons")
    report_usn_reasons.add_argument("--case", required=True, dest="case_id")
    report_usn_reasons.add_argument("--reason", required=True)
    report_usn_reasons.add_argument("--limit", type=int, default=100)
    report_usn_timeline = report_sub.add_parser("usn-timeline")
    report_usn_timeline.add_argument("--case", required=True, dest="case_id")
    report_usn_timeline.add_argument("--user")
    report_usn_timeline.add_argument("--contains")
    report_usn_timeline.add_argument("--reason")
    report_usn_timeline.add_argument("--limit", type=int, default=100)
    report_usn_suspicious = report_sub.add_parser("usn-suspicious")
    report_usn_suspicious.add_argument("--case", required=True, dest="case_id")
    report_usn_suspicious.add_argument("--limit", type=int, default=100)
    report_usn_user_files = report_sub.add_parser("usn-user-files")
    report_usn_user_files.add_argument("--case", required=True, dest="case_id")
    report_usn_user_files.add_argument("--limit", type=int, default=100)
    report_usn_user_files.add_argument("--rules")
    report_usn_user_files.add_argument("--include-suppressed", action="store_true")
    report_usn_renames = report_sub.add_parser("usn-renames")
    report_usn_renames.add_argument("--case", required=True, dest="case_id")
    report_usn_renames.add_argument("--limit", type=int, default=100)
    report_usn_bursts = report_sub.add_parser("usn-bursts")
    report_usn_bursts.add_argument("--case", required=True, dest="case_id")
    report_usn_bursts.add_argument("--minutes", type=int, default=5)
    report_usn_bursts.add_argument("--limit", type=int, default=100)
    report_usn_usb = report_sub.add_parser("usn-usb-candidates")
    report_usn_usb.add_argument("--case", required=True, dest="case_id")
    report_usn_usb.add_argument("--limit", type=int, default=100)
    report_sdelete = report_sub.add_parser("sdelete")
    report_sdelete.add_argument("--case", required=True, dest="case_id")
    report_sdelete.add_argument("--limit", type=int, default=100)
    report_srum = report_sub.add_parser("srum")
    report_srum.add_argument("--case", required=True, dest="case_id")
    report_srum.add_argument("--limit", type=int, default=100)
    report_ual = report_sub.add_parser("ual")
    report_ual.add_argument("--case", required=True, dest="case_id")
    report_ual.add_argument("--limit", type=int, default=100)
    report_ual.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_ual.add_argument("--output")
    report_srum_networks = report_sub.add_parser("srum-networks")
    report_srum_networks.add_argument("--case", required=True, dest="case_id")
    report_srum_networks.add_argument("--include-zero", action="store_true")
    report_srum_networks.add_argument("--limit", type=int, default=100)
    report_srum_networks.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_srum_networks.add_argument("--output")
    report_srum_app_usage = report_sub.add_parser("srum-app-usage")
    report_srum_app_usage.add_argument("--case", required=True, dest="case_id")
    report_srum_app_usage.add_argument("--limit", type=int, default=100)
    report_srum_app_usage.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_srum_app_usage.add_argument("--output")
    report_srum_context = report_sub.add_parser("srum-context")
    report_srum_context.add_argument("--case", required=True, dest="case_id")
    report_srum_context.add_argument("--limit", type=int, default=250)
    report_srum_context.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_srum_context.add_argument("--output")
    report_vpn = report_sub.add_parser("vpn-activity")
    report_vpn.add_argument("--case", required=True, dest="case_id")
    report_vpn.add_argument("--limit", type=int, default=100)
    report_vpn.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_vpn.add_argument("--output")
    report_vpn_local_activity = report_sub.add_parser("vpn-local-activity")
    report_vpn_local_activity.add_argument("--case", required=True, dest="case_id")
    report_vpn_local_activity.add_argument("--limit", type=int, default=500)
    report_vpn_local_activity.add_argument("--padding-minutes", type=int, default=0)
    report_vpn_local_activity.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_vpn_local_activity.add_argument("--output")
    report_remote_access = report_sub.add_parser("remote-access")
    report_remote_access.add_argument("--case", required=True, dest="case_id")
    report_remote_access.add_argument("--limit", type=int, default=100)
    report_remote_access.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_remote_access.add_argument("--output")
    report_remote_access_attribution = report_sub.add_parser("remote-access-attribution")
    report_remote_access_attribution.add_argument("--case", required=True, dest="case_id")
    report_remote_access_attribution.add_argument("--start")
    report_remote_access_attribution.add_argument("--end")
    report_remote_access_attribution.add_argument("--label")
    report_remote_access_attribution.add_argument("--remote")
    report_remote_access_attribution.add_argument("--contains")
    report_remote_access_attribution.add_argument("--limit", type=int, default=100)
    report_remote_access_attribution.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_remote_access_attribution.add_argument("--output")
    report_rdp = report_sub.add_parser("rdp")
    report_rdp.add_argument("--case", required=True, dest="case_id")
    report_rdp.add_argument("--limit", type=int, default=100)
    report_rdp.add_argument("--format", choices=["md", "json"], default="md")
    report_rdp.add_argument("--output")
    for name in ("vpn-connections", "vpn-config", "vpn-execution", "vpn-sessions"):
        report_vpn_detail = report_sub.add_parser(name)
        report_vpn_detail.add_argument("--case", required=True, dest="case_id")
        report_vpn_detail.add_argument("--limit", type=int, default=100)
        report_vpn_detail.add_argument("--format", choices=["json", "table", "csv"], default="json")
        report_vpn_detail.add_argument("--output")
    report_search = report_sub.add_parser("windows-search")
    report_search.add_argument("--case", required=True, dest="case_id")
    report_search.add_argument(
        "--type",
        choices=["files", "internet", "activity", "emails", "content", "properties"],
        default="files",
        dest="report_type",
    )
    report_search.add_argument("--limit", type=int, default=100)
    report_search_combined = report_sub.add_parser("windows-search-combined")
    report_search_combined.add_argument("--case", required=True, dest="case_id")
    report_search_combined.add_argument("--limit", type=int, default=100)
    report_search_combined.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_search_combined.add_argument("--output")
    report_file_metadata = report_sub.add_parser("file-metadata")
    report_file_metadata.add_argument("--case", required=True, dest="case_id")
    report_file_metadata.add_argument("--limit", type=int, default=100)
    report_file_metadata.add_argument("--extension", help="Filter by file extension, for example .docx")
    report_file_metadata.add_argument("--property", dest="property_name", help="Filter by embedded metadata property name")
    report_file_metadata.add_argument("--path", dest="path_contains", help="Filter by substring in original evidence path")
    report_file_metadata.add_argument("--source-folder", help="Filter by original evidence folder prefix")
    report_file_metadata.add_argument("--tool", dest="tool_name", help="Filter by metadata tool/profile name")
    report_file_metadata.add_argument("--user-only", action="store_true", help="Only show files under Users/")
    report_file_metadata.add_argument(
        "--exclude-system",
        action="store_true",
        help="Hide common OS/application paths such as Windows, Program Files, and ProgramData",
    )
    report_file_metadata_skipped = report_sub.add_parser("file-metadata-skipped")
    report_file_metadata_skipped.add_argument("--case", required=True, dest="case_id")
    report_file_metadata_skipped.add_argument("--limit", type=int, default=100)
    report_file_metadata_skipped.add_argument("--tool", dest="tool_name")
    report_file_metadata_skipped.add_argument("--since", help="Only show activity at or after this ISO timestamp")
    report_file_metadata_skipped.add_argument("--latest", action="store_true", help="Show only the latest skipped event per tool")
    report_file_metadata_unresolved = report_sub.add_parser("file-metadata-unresolved")
    report_file_metadata_unresolved.add_argument("--case", required=True, dest="case_id")
    report_file_metadata_unresolved.add_argument("--limit", type=int, default=100)
    report_file_metadata_unresolved.add_argument("--tool", dest="tool_name")
    report_file_metadata_unresolved.add_argument("--since", help="Only show activity at or after this ISO timestamp")
    report_file_metadata_unresolved.add_argument("--latest", action="store_true", help="Show only the latest unresolved-path event per tool")
    report_file_metadata_deleted = report_sub.add_parser("file-metadata-skipped-deleted")
    report_file_metadata_deleted.add_argument("--case", required=True, dest="case_id")
    report_file_metadata_deleted.add_argument("--limit", type=int, default=100)
    report_file_metadata_deleted.add_argument("--tool", dest="tool_name")
    report_file_metadata_deleted.add_argument("--since", help="Only show activity at or after this ISO timestamp")
    report_file_metadata_deleted.add_argument("--latest", action="store_true", help="Show only the latest deleted-MFT skipped event per tool")
    report_file_metadata_orphans = report_sub.add_parser("file-metadata-skipped-orphans")
    report_file_metadata_orphans.add_argument("--case", required=True, dest="case_id")
    report_file_metadata_orphans.add_argument("--limit", type=int, default=100)
    report_file_metadata_orphans.add_argument("--tool", dest="tool_name")
    report_file_metadata_orphans.add_argument("--since", help="Only show activity at or after this ISO timestamp")
    report_file_metadata_orphans.add_argument("--latest", action="store_true", help="Show only the latest live-orphan skipped event per tool")
    report_file_metadata_folders = report_sub.add_parser("file-metadata-folders")
    report_file_metadata_folders.add_argument("--case", required=True, dest="case_id")
    report_file_metadata_folders.add_argument("--limit", type=int, default=100)
    report_file_metadata_folders.add_argument("--depth", type=int, default=3)
    report_file_metadata_folders.add_argument("--tool", dest="tool_name")
    report_file_metadata_folders.add_argument("--extension")
    report_file_metadata_folders.add_argument("--user-only", action="store_true")
    report_file_metadata_folders.add_argument("--exclude-system", action="store_true")
    report_file_metadata_summary = report_sub.add_parser("file-metadata-summary")
    report_file_metadata_summary.add_argument("--case", required=True, dest="case_id")
    report_file_metadata_summary.add_argument("--limit", type=int, default=100)
    report_usb = report_sub.add_parser("usb")
    report_usb.add_argument("--case", required=True, dest="case_id")
    report_usb.add_argument("--limit", type=int, default=100)
    report_usb.add_argument("--raw", action="store_true", help="Show raw USB evidence rows instead of storage-device summary")
    report_usb.add_argument("--breakdown", action="store_true", help="Show USB evidence row counts by source and device type")
    report_external_storage = report_sub.add_parser("external-storage")
    report_external_storage.add_argument("--case", required=True, dest="case_id")
    report_external_storage.add_argument("--limit", type=int, default=500)
    report_external_storage.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_external_storage.add_argument("--output", help="Write report output to a file")
    report_device_inventory = report_sub.add_parser("device-inventory")
    report_device_inventory.add_argument("--case", required=True, dest="case_id")
    report_device_inventory.add_argument("--limit", type=int, default=250)
    report_device_inventory.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_device_inventory.add_argument("--output")
    report_usb_files = report_sub.add_parser("usb-files")
    report_usb_files.add_argument("--case", required=True, dest="case_id")
    report_usb_files.add_argument("--limit", type=int, default=500)
    report_usb_files.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_usb_files.add_argument("--output", help="Write report output to a file")
    report_usb_files.add_argument("--grouped", action="store_true", help="Return/export one row per USB file path instead of every artifact hit")
    report_usb_timeline = report_sub.add_parser("usb-timeline")
    report_usb_timeline.add_argument("--case", required=True, dest="case_id")
    report_usb_timeline.add_argument("--limit", type=int, default=500)
    report_usb_timeline.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_usb_timeline.add_argument("--output", help="Write report output to a file")
    report_usb_verbose = report_sub.add_parser("usb-verbose")
    report_usb_verbose.add_argument("--case", required=True, dest="case_id")
    report_usb_verbose.add_argument("--serial")
    report_usb_verbose.add_argument("--vsn", dest="volume_serial_number")
    report_usb_verbose.add_argument("--volume-guid")
    report_usb_verbose.add_argument("--limit", type=int, default=250)
    report_export = report_sub.add_parser("export")
    report_export.add_argument("--case", required=True, dest="case_id")
    report_export.add_argument("--preset", required=True, choices=["usb-summary", "usb-file-correlations", "usb-timeline"])
    report_export.add_argument("--output", required=True, help="CSV output path")
    report_export.add_argument("--limit", type=int, default=10000)
    report_registry_artifacts = report_sub.add_parser("registry-artifacts")
    report_registry_artifacts.add_argument("--case", required=True, dest="case_id")
    report_registry_artifacts.add_argument("--artifact")
    report_registry_artifacts.add_argument("--user")
    report_registry_artifacts.add_argument("--limit", type=int, default=100)
    report_registry_activity = report_sub.add_parser("registry-activity")
    report_registry_activity.add_argument("--case", required=True, dest="case_id")
    report_registry_activity.add_argument(
        "--artifact",
        required=True,
        choices=[
            "recentdocs",
            "runmru",
            "typedpaths",
            "wordwheel",
            "wordwheelquery",
            "userassist",
            "office-mru",
            "officemru",
            "common-dialog",
            "trusted-documents",
        ],
    )
    report_registry_activity.add_argument("--user")
    report_registry_activity.add_argument("--limit", type=int, default=100)
    report_office_trust = report_sub.add_parser("office-trust")
    report_office_trust.add_argument("--case", required=True, dest="case_id")
    report_office_trust.add_argument("--user")
    report_office_trust.add_argument("--type", dest="trust_type", choices=["office_trusted_locations", "office_trusted_documents"])
    report_office_trust.add_argument("--limit", type=int, default=100)
    report_office_trust.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_office_trust.add_argument("--output")
    report_taskbar_feature = report_sub.add_parser("taskbar-feature-usage")
    report_taskbar_feature.add_argument("--case", required=True, dest="case_id")
    report_taskbar_feature.add_argument("--user")
    report_taskbar_feature.add_argument("--feature")
    report_taskbar_feature.add_argument("--limit", type=int, default=100)
    report_taskbar_feature.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_taskbar_feature.add_argument("--output")
    report_taskbar_pins = report_sub.add_parser("taskbar-pins")
    report_taskbar_pins.add_argument("--case", required=True, dest="case_id")
    report_taskbar_pins.add_argument("--user")
    report_taskbar_pins.add_argument("--limit", type=int, default=100)
    report_taskbar_pins.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_taskbar_pins.add_argument("--output")
    report_common_dialog_items = report_sub.add_parser("common-dialog-items")
    report_common_dialog_items.add_argument("--case", required=True, dest="case_id")
    report_common_dialog_items.add_argument("--limit", type=int, default=100)
    report_activity_summary = report_sub.add_parser("activity-summary")
    report_activity_summary.add_argument("--case", required=True, dest="case_id")
    report_activity_summary.add_argument("--user")
    report_activity_summary.add_argument("--limit", type=int, default=25)
    report_user_activity = report_sub.add_parser("user-activity")
    report_user_activity.add_argument("--case", required=True, dest="case_id")
    report_user_activity.add_argument("--user", required=True)
    report_user_activity.add_argument("--limit", type=int, default=100)
    report_user_activity.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_user_activity.add_argument("--output")
    report_users = report_sub.add_parser("users")
    report_users.add_argument("--case", required=True, dest="case_id")
    report_files = report_sub.add_parser("files")
    report_files.add_argument("--case", required=True, dest="case_id")
    report_files.add_argument("--user")
    report_files.add_argument("--limit", type=int, default=100)
    report_file_names = report_sub.add_parser("file-names")
    report_file_names.add_argument("--case", required=True, dest="case_id")
    report_file_names.add_argument("--contains")
    report_file_names.add_argument("--include-mft", action="store_true")
    report_file_names.add_argument("--limit", type=int, default=100)
    report_file_names.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_file_names.add_argument("--output")
    report_file_name_drilldown = report_sub.add_parser("file-name-drilldown")
    report_file_name_drilldown.add_argument("--case", required=True, dest="case_id")
    report_file_name_drilldown.add_argument("--name", required=True)
    report_file_name_drilldown.add_argument("--include-mft", action="store_true")
    report_file_name_drilldown.add_argument("--limit", type=int, default=500)
    report_file_name_drilldown.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_file_name_drilldown.add_argument("--output")
    report_file_dossier = report_sub.add_parser("file-dossier")
    report_file_dossier.add_argument("--case", required=True, dest="case_id")
    report_file_dossier.add_argument("--path")
    report_file_dossier.add_argument("--name")
    report_file_dossier.add_argument("--limit", type=int, default=100)
    report_file_dossier.add_argument("--format", choices=["json", "table"], default="json")
    report_file_dossier.add_argument("--output")
    report_file_intelligence = report_sub.add_parser("file-intelligence")
    report_file_intelligence.add_argument("--case", required=True, dest="case_id")
    report_file_intelligence.add_argument("--path")
    report_file_intelligence.add_argument("--name")
    report_file_intelligence.add_argument("--limit", type=int, default=100)
    report_file_intelligence.add_argument("--format", choices=["json", "table"], default="json")
    report_file_intelligence.add_argument("--output")
    report_file_history = report_sub.add_parser("file-history")
    report_file_history.add_argument("--case", required=True, dest="case_id")
    report_file_history.add_argument("--name")
    report_file_history.add_argument("--path")
    report_file_history.add_argument("--mft-entry")
    report_file_history.add_argument("--filesystem-only", action="store_true")
    report_file_history.add_argument("--include-vsc", action="store_true")
    report_file_history.add_argument("--limit", type=int, default=500)
    report_file_history.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_file_history.add_argument("--output")
    report_copied = report_sub.add_parser("copied-files")
    report_copied.add_argument("--case", required=True, dest="case_id")
    report_copied.add_argument("--limit", type=int, default=100)
    report_copied_indicators = report_sub.add_parser("copied-file-indicators")
    report_copied_indicators.add_argument("--case", required=True, dest="case_id")
    report_copied_indicators.add_argument("--limit", type=int, default=100)
    report_copied_indicators.add_argument("--source-artifact-type")
    report_copied_indicators.add_argument("--user-only", action="store_true")
    report_copied_indicators.add_argument("--include-system", action="store_true")
    report_copied_indicators.add_argument("--include-mft-only", action="store_true")
    report_copied_groups = report_sub.add_parser("copied-file-groups")
    report_copied_groups.add_argument("--case", required=True, dest="case_id")
    report_copied_groups.add_argument("--limit", type=int, default=100)
    report_copied_groups.add_argument("--include-system", action="store_true")
    report_copied_groups.add_argument("--include-mft-only", action="store_true")
    report_copied_groups.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_copied_groups.add_argument("--output")
    report_copied_usb = report_sub.add_parser("copied-usb-files")
    report_copied_usb.add_argument("--case", required=True, dest="case_id")
    report_copied_usb.add_argument("--limit", type=int, default=250)
    report_copied_usb.add_argument("--grouped", action="store_true")
    report_copied_usb.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_copied_usb.add_argument("--output")
    report_tool_runs = report_sub.add_parser("tool-runs")
    report_tool_runs.add_argument("--case", required=True, dest="case_id")
    report_tool_runs.add_argument("--limit", type=int, default=250)
    report_tool_runs.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_tool_runs.add_argument("--output")
    report_timings = report_sub.add_parser("process-timings")
    report_timings.add_argument("--case", required=True, dest="case_id")
    report_timings.add_argument("--limit", type=int, default=500)
    report_timings.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_timings.add_argument("--output")
    report_case_review = report_sub.add_parser("case-review")
    report_case_review.add_argument("--case", required=True, dest="case_id")
    report_case_review.add_argument("--limit", type=int, default=25)
    report_case_review.add_argument("--format", choices=["json", "table"], default="json")
    report_case_review.add_argument("--output")
    report_executive_summary = report_sub.add_parser("executive-summary")
    report_executive_summary.add_argument("--case", required=True, dest="case_id")
    report_executive_summary.add_argument("--limit", type=int, default=25)
    report_executive_summary.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_executive_summary.add_argument("--output")
    report_case_overview = report_sub.add_parser("case-overview")
    report_case_overview.add_argument("--case", required=True, dest="case_id")
    report_case_overview.add_argument("--limit", type=int, default=25)
    report_case_overview.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_case_overview.add_argument("--output")
    report_regression_smoke = report_sub.add_parser("regression-smoke")
    report_regression_smoke.add_argument("--case", required=True, dest="case_id")
    report_regression_smoke.add_argument("--limit", type=int, default=10)
    report_regression_smoke.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_regression_smoke.add_argument("--output")
    report_regression_smoke.add_argument("--write-reports", action="store_true")
    report_regression_smoke.add_argument("--output-dir")
    report_write_bundle = report_sub.add_parser("write-bundle")
    report_write_bundle.add_argument("--case", required=True, dest="case_id")
    report_write_bundle.add_argument("--limit", type=int, default=100)
    report_write_bundle.add_argument("--output-dir", required=True)
    report_combined = report_sub.add_parser("combined-artifacts")
    report_combined.add_argument("--case", required=True, dest="case_id")
    report_combined.add_argument("--family", default="all")
    report_combined.add_argument("--limit", type=int, default=100)
    report_combined.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_combined.add_argument("--output")
    report_artifact_processing = report_sub.add_parser("artifact-processing-status")
    report_artifact_processing.add_argument("--case", required=True, dest="case_id")
    report_artifact_processing.add_argument("--limit", type=int, default=250)
    report_artifact_processing.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_artifact_processing.add_argument("--output")
    report_processing_decisions = report_sub.add_parser("processing-decisions")
    report_processing_decisions.add_argument("--case", required=True, dest="case_id")
    report_processing_decisions.add_argument("--limit", type=int, default=100)
    report_processing_decisions.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_processing_decisions.add_argument("--output")
    report_processing_readiness = report_sub.add_parser("processing-readiness")
    report_processing_readiness.add_argument("--case", required=True, dest="case_id")
    report_processing_readiness.add_argument("--limit", type=int, default=100)
    report_processing_readiness.add_argument("--profile", help="Evaluate readiness against a specific workflow profile")
    report_processing_readiness.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_processing_readiness.add_argument("--output")
    report_readiness_gate = report_sub.add_parser("readiness-gate")
    report_readiness_gate.add_argument("--case", required=True, dest="case_id")
    report_readiness_gate.add_argument("--limit", type=int, default=100)
    report_readiness_gate.add_argument("--profile", help="Evaluate readiness against a specific workflow profile")
    report_readiness_gate.add_argument("--summary-only", action="store_true")
    report_readiness_gate.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_readiness_gate.add_argument("--output")
    report_deep_recovery = report_sub.add_parser("deep-recovery-status")
    report_deep_recovery.add_argument("--case", required=True, dest="case_id")
    report_deep_recovery.add_argument("--limit", type=int, default=100)
    report_deep_recovery.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_deep_recovery.add_argument("--output")
    report_case_comparison = report_sub.add_parser("case-comparison")
    report_case_comparison.add_argument("--case-ref", action="append", required=True, help="LABEL:ROOT:CASE_ID")
    report_case_comparison.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_case_comparison.add_argument("--output")
    report_evidence_gaps = report_sub.add_parser("evidence-gaps")
    report_evidence_gaps.add_argument("--case", required=True, dest="case_id")
    report_evidence_gaps.add_argument("--limit", type=int, default=100)
    report_evidence_gaps.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_evidence_gaps.add_argument("--output")
    report_memory_artifacts = report_sub.add_parser("memory-artifacts")
    report_memory_artifacts.add_argument("--case", required=True, dest="case_id")
    report_memory_artifacts.add_argument("--limit", type=int, default=100)
    report_memory_artifacts.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_memory_artifacts.add_argument("--output")
    report_memory_support = report_sub.add_parser("memory-support-files")
    report_memory_support.add_argument("--case", required=True, dest="case_id")
    report_memory_support.add_argument("--limit", type=int, default=100)
    report_memory_support.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_memory_support.add_argument("--output")
    report_memory_analysis = report_sub.add_parser("memory-analysis")
    report_memory_analysis.add_argument("--case", required=True, dest="case_id")
    report_memory_analysis.add_argument("--limit", type=int, default=100)
    report_memory_analysis.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_memory_analysis.add_argument("--output")
    report_memory_credentials = report_sub.add_parser("memory-credentials")
    report_memory_credentials.add_argument("--case", required=True, dest="case_id")
    report_memory_credentials.add_argument("--limit", type=int, default=100)
    report_memory_credentials.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_memory_credentials.add_argument("--output")
    report_memory_credentials.add_argument("--reveal", action="store_true", help="Include unredacted memory strings in the report output")
    report_memory_credential_review = report_sub.add_parser("memory-credential-review")
    report_memory_credential_review.add_argument("--case", required=True, dest="case_id")
    report_memory_credential_review.add_argument("--hit", required=True, dest="hit_id")
    report_memory_credential_review.add_argument("--status", required=True, choices=["false_positive", "candidate", "validated", "out_of_scope"])
    report_memory_credential_review.add_argument("--reviewer")
    report_memory_credential_review.add_argument("--note", default="")
    report_memory_disk = report_sub.add_parser("memory-disk-correlations")
    report_memory_disk.add_argument("--case", required=True, dest="case_id")
    report_memory_disk.add_argument("--limit", type=int, default=100)
    report_memory_disk.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_memory_disk.add_argument("--output")
    report_crash_dumps = report_sub.add_parser("crash-dump-analysis")
    report_crash_dumps.add_argument("--case", required=True, dest="case_id")
    report_crash_dumps.add_argument("--limit", type=int, default=100)
    report_crash_dumps.add_argument("--format", choices=["md", "json", "table", "csv"], default="md")
    report_crash_dumps.add_argument("--output")
    report_cloud_server = report_sub.add_parser("cloud-server-events")
    report_cloud_server.add_argument("--case", required=True, dest="case_id")
    report_cloud_server.add_argument("--limit", type=int, default=100)
    report_cloud_server.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_cloud_server.add_argument("--output")
    report_memory_strings = report_sub.add_parser("memory-string-hits")
    report_memory_strings.add_argument("--case", required=True, dest="case_id")
    report_memory_strings.add_argument("--limit", type=int, default=100)
    report_memory_strings.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_memory_strings.add_argument("--output")
    report_manifest = report_sub.add_parser("operation-manifest")
    report_manifest.add_argument("--case", required=True, dest="case_id")
    report_manifest.add_argument("--limit", type=int, default=500)
    report_storage = report_sub.add_parser("db-storage")
    report_storage.add_argument("--case", dest="case_id")
    report_storage.add_argument("--limit", type=int, default=100)
    report_storage.add_argument("--include-object-sizes", action="store_true")
    report_cleanup = report_sub.add_parser("cleanup-candidates")
    report_cleanup.add_argument("--case", required=True, dest="case_id")
    report_cleanup.add_argument("--limit", type=int, default=100)
    report_copied_drilldown = report_sub.add_parser("copied-file-drilldown")
    report_copied_drilldown.add_argument("--case", required=True, dest="case_id")
    report_copied_drilldown.add_argument("--path", required=True)
    report_copied_drilldown.add_argument("--limit", type=int, default=100)
    report_copied_drilldown.add_argument("--format", choices=["json", "table"], default="json")
    report_copied_drilldown.add_argument("--output")
    report_usb_dossier = report_sub.add_parser("usb-dossier")
    report_usb_dossier.add_argument("--case", required=True, dest="case_id")
    report_usb_dossier.add_argument("--serial")
    report_usb_dossier.add_argument("--volume-serial-number")
    report_usb_dossier.add_argument("--volume-guid")
    report_usb_dossier.add_argument("--limit", type=int, default=250)
    report_usb_dossier.add_argument("--format", choices=["json", "table"], default="json")
    report_usb_dossier.add_argument("--output")
    report_correlations = report_sub.add_parser("correlations")
    report_correlations.add_argument("--case", required=True, dest="case_id")
    report_correlations.add_argument("--limit", type=int, default=100)
    report_artifacts = report_sub.add_parser("artifact-summary")
    report_artifacts.add_argument("--case", required=True, dest="case_id")
    report_artifact_completeness = report_sub.add_parser("artifact-completeness")
    report_artifact_completeness.add_argument("--case", required=True, dest="case_id")
    report_artifact_completeness.add_argument("--limit", type=int, default=100)
    report_artifact_completeness.add_argument("--all-history", action="store_true")
    report_artifact_completeness.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_artifact_completeness.add_argument("--output")
    report_evidence_quality = report_sub.add_parser("evidence-quality")
    report_evidence_quality.add_argument("--case", required=True, dest="case_id")
    report_evidence_quality.add_argument("--limit", type=int, default=100)
    report_evidence_quality.add_argument("--all-history", action="store_true")
    report_evidence_quality.add_argument("--format", choices=["json", "table", "csv"], default="json")
    report_evidence_quality.add_argument("--output")
    report_shortcuts = report_sub.add_parser("shortcuts")
    report_shortcuts.add_argument("--case", required=True, dest="case_id")
    report_shortcuts.add_argument("--type", choices=["lnk", "jumplist"], dest="artifact_type")
    report_shortcuts.add_argument("--limit", type=int, default=100)

    search = subparsers.add_parser("search")
    search_sub = search.add_subparsers(dest="action", required=True)
    search_query = search_sub.add_parser("query")
    search_query.add_argument("--case", required=True, dest="case_id")
    search_query.add_argument("--query", required=True)
    search_query.add_argument("--url")
    search_query.add_argument("--index")
    search_query.add_argument("--username")
    search_query.add_argument("--password")
    search_query.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    search_query.add_argument("--limit", type=int, default=25)
    search_query.add_argument("--no-synonyms", action="store_true", help="Disable explicit query-time synonym expansion")
    search_query.add_argument("--synonyms", help="Comma-separated synonym groups file, one group per line")
    search_query.add_argument("--format", choices=["json", "table"], default="json")
    search_query.add_argument("--output")
    search_show = search_sub.add_parser("show")
    search_show.add_argument("--case", required=True, dest="case_id")
    search_show.add_argument("--source-table", required=True)
    search_show.add_argument("--source-id", required=True)
    search_show.add_argument("--format", choices=["json", "table"], default="json")
    search_show.add_argument("--output")

    standalone = subparsers.add_parser("standalone")
    standalone_sub = standalone.add_subparsers(dest="action", required=True)
    standalone_doctor = standalone_sub.add_parser("doctor")
    standalone_doctor.add_argument("--case", dest="case_id")
    standalone_doctor.add_argument("--profile")
    standalone_doctor.add_argument("--format", choices=["json", "table"], default="json")
    standalone_doctor.add_argument("--output")
    standalone_version = standalone_sub.add_parser("version")
    standalone_version.add_argument("--format", choices=["json", "table"], default="json")
    standalone_version.add_argument("--output")
    standalone_dependencies = standalone_sub.add_parser("dependencies")
    standalone_dependencies.add_argument("--format", choices=["json", "table", "csv"], default="json")
    standalone_dependencies.add_argument("--output")
    standalone_profiles = standalone_sub.add_parser("profile-catalog")
    standalone_profiles.add_argument("--format", choices=["json", "table", "csv"], default="json")
    standalone_profiles.add_argument("--output")
    standalone_capabilities = standalone_sub.add_parser("artifact-capability")
    standalone_capabilities.add_argument("--profile")
    standalone_capabilities.add_argument("--format", choices=["json", "table", "csv"], default="json")
    standalone_capabilities.add_argument("--output")
    standalone_schema = standalone_sub.add_parser("schema-status")
    standalone_schema.add_argument("--format", choices=["json", "table", "csv"], default="json")
    standalone_schema.add_argument("--output")
    standalone_backup = standalone_sub.add_parser("backup")
    standalone_backup.add_argument("--case", required=True, dest="case_id")
    standalone_backup.add_argument("--output-dir", required=True)
    standalone_jobs = standalone_sub.add_parser("jobs")
    standalone_jobs.add_argument("--case", required=True, dest="case_id")
    standalone_jobs.add_argument("--limit", type=int, default=100)
    standalone_jobs.add_argument("--format", choices=["json", "table", "csv"], default="json")
    standalone_jobs.add_argument("--output")
    standalone_benchmark = standalone_sub.add_parser("benchmark")
    standalone_benchmark.add_argument("--case", required=True, dest="case_id")
    standalone_benchmark.add_argument("--limit", type=int, default=100)
    standalone_benchmark.add_argument("--format", choices=["json", "table", "csv"], default="json")
    standalone_benchmark.add_argument("--output")
    standalone_backlog = standalone_sub.add_parser("backlog")
    standalone_backlog.add_argument("--format", choices=["json", "table", "csv"], default="json")
    standalone_backlog.add_argument("--output")

    return parser


def command_preview(db: Database, case_id: str) -> list[dict[str, object]]:
    rows = db.conn.execute(
        """
        SELECT tool_name, command_json, output_folder
        FROM jobs WHERE case_id = ?
        ORDER BY start_time
        """,
        (case_id,),
    ).fetchall()
    return [
        {
            "tool": row["tool_name"],
            "command": json.loads(row["command_json"]),
            "output_folder": row["output_folder"],
        }
        for row in rows
    ]


def run(args: argparse.Namespace) -> int:
    configure_logging()
    config = load_config(root=args.root, plugins=args.plugin, config_path=args.config)
    paths = WorkspacePaths(config.root)
    paths.ensure_root()
    db = Database(paths.db_path())
    registry = ToolRegistry.from_files(config.plugin_paths)

    try:
        if args.resource == "standalone" and args.action == "doctor":
            report = doctor_report(db, paths, registry, case_id=args.case_id, profile=args.profile)
            if args.format == "table":
                write_report_output(
                    report,
                    report["checks"],
                    "table",
                    args.output,
                    title="Standalone doctor",
                    columns=["name", "passed", "details"],
                )
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0 if report.get("passed") else 1

        if args.resource == "standalone" and args.action == "version":
            report = version_report(paths.root, config.plugin_paths)
            if args.format == "table":
                write_report_output(report, [report], "table", args.output, title="Standalone version", columns=["application", "version", "python", "platform", "root"])
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0

        if args.resource == "standalone" and args.action == "dependencies":
            report = dependency_report()
            rows = [*report["required"], *report["optional"]]
            write_report_output(report, rows, args.format, args.output, title="Standalone dependencies", columns=["tool", "required", "available", "path", "purpose"])
            return 1 if report["summary"]["required_missing"] else 0

        if args.resource == "standalone" and args.action == "profile-catalog":
            report = profile_catalog_report(registry)
            write_report_output(report, report["profiles"], args.format, args.output, title="Profile catalog", columns=["profile", "tool_count", "extraction_policy", "recovery_tier", "carve_stage", "description"])
            return 0

        if args.resource == "standalone" and args.action == "artifact-capability":
            report = artifact_capability_report(registry, profile=args.profile)
            write_report_output(report, report["artifacts"], args.format, args.output, title="Artifact capability matrix", columns=["profile", "tool_name", "artifact_name", "method", "optional", "recursive", "source", "destination"])
            return 0

        if args.resource == "standalone" and args.action == "schema-status":
            report = schema_status_report(db)
            write_report_output(report, report["objects"], args.format, args.output, title="Schema status", columns=["table", "type"])
            return 0

        if args.resource == "standalone" and args.action == "backup":
            print_json(backup_case_databases(db, paths, case_id=args.case_id, output_dir=Path(args.output_dir)))
            return 0

        if args.resource == "standalone" and args.action == "jobs":
            report = job_status_report(db, case_id=args.case_id, limit=args.limit)
            write_report_output(report, report["jobs"], args.format, args.output, title=f"Jobs for case {args.case_id}", columns=["status", "tool_name", "source_scope", "exit_code", "start_time", "end_time", "output_folder"])
            return 0

        if args.resource == "standalone" and args.action == "benchmark":
            report = benchmark_report(db, case_id=args.case_id, limit=args.limit)
            write_report_output(report, report["timings"], args.format, args.output, title=f"Benchmark timings for case {args.case_id}", columns=["duration_ms", "scope", "phase", "name", "tool_name", "artifact_name", "status"])
            return 0

        if args.resource == "standalone" and args.action == "backlog":
            report = standalone_backlog_report()
            write_report_output(report, report["items"], args.format, args.output, title="Standalone pre-UI backlog", columns=["number", "status", "item"])
            return 0

        if args.resource == "process":
            case_id = args.case_id or create_case(db, paths)
            db.get_case(case_id)
            computer_id = args.computer_id
            computer_payload = None
            if computer_id:
                computer = db.get_computer(computer_id, case_id)
                computer_payload = {
                    "computer_id": computer.id,
                    "label": computer.label,
                    "hostname": computer.hostname,
                }
            else:
                computer_label = args.computer_label or Path(args.path).stem
                computer = create_computer(
                    db,
                    paths,
                    case_id,
                    label=computer_label,
                    hostname=args.hostname,
                )
                computer_id = computer.id
                computer_payload = {
                    "computer_id": computer.id,
                    "label": computer.label,
                    "hostname": computer.hostname,
                }
            image = add_image(
                db,
                paths,
                case_id,
                Path(args.path),
                computer_id=computer_id,
            )
            volume = mount_image(
                db=db,
                paths=paths,
                case_id=case_id,
                image=image,
                dry_run=args.dry_run,
                mount_filesystem=args.filesystem,
                use_sudo_mount=args.use_sudo_mount,
            )
            run_error: Exception | None = None
            memory_profile_result: dict[str, object] | None = None
            unmounted_path = None
            try:
                run_profile(
                    db=db,
                    paths=paths,
                    registry=registry,
                    case_id=case_id,
                    image_id=image.id,
                    profile=args.profile,
                    dry_run=args.dry_run,
                    include_start_menu_lnk=args.include_start_menu_lnk,
                    include_deleted_mft=args.include_deleted_mft,
                    include_live_orphans=args.include_live_orphans,
                    replace_existing=args.replace_existing,
                    accept_duplicate=args.accept_duplicate,
                    include_windows_old=args.include_windows_old,
                    workers=args.workers,
                )
                memory_profile_result = _run_memory_after_profile(
                    db,
                    paths,
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image.id,
                    profile=args.profile,
                    workers=args.workers,
                    include_memory_profile=args.include_memory_profile,
                    no_memory_profile=args.no_memory_profile,
                    dry_run=args.dry_run,
                )
            except Exception as exc:  # pragma: no cover - exercised through CLI behavior
                run_error = exc
            finally:
                if args.filesystem and not args.keep_mounted:
                    try:
                        unmounted_path = unmount_image(
                            db=db,
                            paths=paths,
                            case_id=case_id,
                            image=image,
                            dry_run=args.dry_run,
                            use_sudo_mount=args.use_sudo_mount,
                        )
                    except Exception as exc:
                        if run_error is None:
                            raise
                        db.log_activity(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image.id,
                            level="warning",
                            event="volume.unmount_after_error_failed",
                            message="Processing failed and automatic unmount also failed",
                            details={"error": str(exc)},
                        )
            if run_error is not None:
                raise run_error
            warnings = db.activity_for_case(case_id, level="warning", limit=1000)
            errors = db.activity_for_case(case_id, level="error", limit=1000)
            status = db.case_status(case_id)
            payload = {
                "case_id": case_id,
                "project_id": case_id,
                "computer": computer_payload,
                "image_id": image.id,
                "image_path": str(image.path),
                "profile": args.profile,
                "dry_run": args.dry_run,
                "requested_workers": args.workers,
                "effective_workers": max(1, args.workers),
                "parallel_scope": "artifact_extraction_and_external_tools" if args.workers > 1 else "serial",
                "filesystem_mount_requested": args.filesystem,
                "volume_mount_path": str(volume) if volume else None,
                "unmounted_path": str(unmounted_path) if unmounted_path else None,
                "kept_mounted": bool(args.filesystem and args.keep_mounted),
                "memory_profile": memory_profile_result,
                "warning_count": len(warnings),
                "error_count": len(errors),
                "counts": {
                    "computers": len(status["computers"]),
                    "images": len(status["images"]),
                    "jobs": len(status["jobs"]),
                    "artifacts": len(status["artifacts"]),
                    "outputs": len(status["outputs"]),
                },
                "parsed_row_counts": status["parsed_row_counts"],
            }
            if args.dry_run:
                payload["commands"] = command_preview(db, case_id)
            print_json(payload)
            return 0

        if args.resource == "report-bundle" and args.action == "import":
            result = import_report_bundle(
                db=db,
                paths=paths,
                report_root=Path(args.path),
                case_id=args.case_id,
                computer_id=args.computer_id,
                computer_label=args.computer_label,
                accept_duplicate=args.accept_duplicate,
            )
            print_json(
                {
                    "case_id": result.case_id,
                    "project_id": result.case_id,
                    "computer_id": result.computer_id,
                    "image_id": result.image_id,
                    "report_root": result.report_root,
                    "imported_files": result.imported_files,
                    "imported_rows": result.imported_rows,
                    "skipped_files": result.skipped_files,
                    "failed_files": result.failed_files,
                    "markdown_path": result.markdown_path,
                }
            )
            return 0

        if args.resource in {"case", "project"} and args.action == "create":
            case_id = create_case(db, paths)
            print_json({"project_id": case_id, "case_id": case_id, "root": str(paths.case_dir(case_id))})
            return 0

        if args.resource in {"case", "project"} and args.action == "status":
            print_json(db.case_status(args.case_id))
            return 0

        if args.resource in {"case", "project"} and args.action == "activity":
            db.get_case(args.case_id)
            rows = db.activity_for_case(args.case_id, limit=args.limit, level=args.level)
            print_json({"case_id": args.case_id, "activity": [dict(row) for row in reversed(rows)]})
            return 0

        if args.resource in {"case", "project"} and args.action == "purge-output":
            db.get_case(args.case_id)
            if not args.yes:
                raise OrchestratorError("Refusing to purge output rows without --yes")
            purged = db.purge_tool_data(
                case_id=args.case_id,
                image_id=args.image_id,
                tool_names=args.tool_names,
            )
            db.log_activity(
                case_id=args.case_id,
                image_id=args.image_id,
                level="warning",
                event="tool.output_purged",
                message="Purged tool output records",
                details={"image_id": args.image_id, "tool_names": args.tool_names, "outputs": purged},
            )
            print_json(
                {
                    "case_id": args.case_id,
                    "image_id": args.image_id,
                    "tool_names": args.tool_names,
                    "purged_outputs": purged,
                }
            )
            return 0

        if args.resource in {"case", "project"} and args.action == "rebuild-timeline-dedupe":
            stats = rebuild_timeline_windows_old_dedupe(
                db,
                case_id=args.case_id,
                image_id=args.image_id,
                max_windows_old_output_rows=args.max_windows_old_output_rows,
            )
            print_json({"case_id": args.case_id, "image_id": args.image_id, **stats})
            return 0

        if args.resource in {"case", "project"} and args.action == "rebuild-artifact-dedupe":
            stats = rebuild_artifact_windows_old_dedupe(db, case_id=args.case_id, image_id=args.image_id)
            print_json(stats)
            return 0

        if args.resource in {"case", "project"} and args.action == "rebuild-correlations":
            stats = rebuild_correlation_framework(db, case_id=args.case_id, image_id=args.image_id)
            print_json(stats)
            return 0

        if args.resource in {"case", "project"} and args.action == "rebuild-sessions":
            stats = rebuild_sessions(db, case_id=args.case_id, image_id=args.image_id)
            print_json(stats)
            return 0

        if args.resource in {"case", "project"} and args.action == "rebuild-postprocess":
            stats = rebuild_case_postprocess(
                db,
                case_id=args.case_id,
                image_id=args.image_id,
                max_windows_old_output_rows=args.max_windows_old_output_rows,
            )
            print_json(stats)
            return 0

        if args.resource == "carve" and args.action == "sqlite":
            source = Path(args.path)
            if not source.exists():
                raise OrchestratorError(f"Carve source does not exist: {source}")
            computer_id, image_id = _cloud_or_memory_evidence_ids(
                db,
                case_id=args.case_id,
                evidence_path=source,
                computer_id=args.computer_id,
                image_id=args.image_id,
            )
            output_dir = paths.case_dir(args.case_id) / "supplemental" / "carves" / str(uuid.uuid4())
            manifest = stage_sqlite_carves(
                source,
                output_dir,
                max_carves=args.max_carves,
                max_bytes=args.max_bytes,
                max_carve_size=args.max_carve_size,
                start_offset=args.start_offset,
                chunk_size=args.chunk_size,
            )
            manifest_path = output_dir / "staged-carves.csv"
            ranges_path = output_dir / "scan-ranges.csv"
            manifest_rows: list[dict[str, object]] = []
            staged_rows: list[dict[str, object]] = []
            for row_number, staged in enumerate(manifest["carves"], start=1):
                staged_path = Path(str(staged["path"]))
                summary = summarize_sqlite_carve(staged_path, max_rows_per_table=args.max_rows_per_table)
                manifest_row = {
                    "row_number": row_number,
                    "profile": args.profile,
                    "source_path": str(source),
                    "source_offset": staged.get("source_offset"),
                    "staged_path": str(staged_path),
                    "staged_name": staged_path.name,
                    "staged_size": staged.get("size"),
                    "staged_sha256": staged.get("sha256"),
                    **summary,
                }
                manifest_rows.append(manifest_row)
            if manifest_rows:
                with manifest_path.open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=list(manifest_rows[0].keys()))
                    writer.writeheader()
                    writer.writerows(manifest_rows)
            else:
                manifest_path.write_text("row_number,profile,source_path,source_offset,staged_path\n", encoding="utf-8")
            _write_scan_ranges_csv(ranges_path, manifest.get("scan_ranges") or [])
            output_id = str(uuid.uuid4())
            db.insert_tool_output(
                {
                    "id": output_id,
                    "case_id": args.case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "job_id": None,
                    "tool_name": "CarveStageRunner",
                    "output_type": "csv",
                    "path": manifest_path,
                    "row_count": len(manifest_rows),
                }
            )
            for manifest_row, staged in zip(manifest_rows, manifest["carves"]):
                staged_row = staged_carve_row(
                    case_id=args.case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=output_id,
                    source_csv=manifest_path,
                    row_number=int(manifest_row["row_number"]),
                    profile=args.profile,
                    source_path=str(source),
                    staged=staged,
                    summary=manifest_row,
                )
                staged_row["created_at"] = datetime.now(timezone.utc).isoformat()
                staged_rows.append(staged_row)
            db.insert_staged_carves(staged_rows)
            scan_rows = [
                scan_range_row(
                    case_id=args.case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=output_id,
                    source_csv=ranges_path,
                    row_number=index,
                    profile=args.profile,
                    carve_type="sqlite",
                    range_info=range_info,
                    limited=bool(manifest.get("limited")),
                    limit_reason=str(manifest.get("limit_reason") or ""),
                )
                for index, range_info in enumerate(manifest.get("scan_ranges") or [], start=1)
            ]
            db.insert_carve_scan_ranges(scan_rows)
            db.insert_timeline_events(timeline_events_from_rows(staged_rows))
            artifact_imported = {"tools": {}, "csv_files": 0, "rows": 0, "skipped": len(staged_rows)}
            if args.import_artifacts and staged_rows:
                artifact_imported = import_recognized_sqlite_carves(
                    db,
                    case_id=args.case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    source=source,
                    staged_rows=staged_rows,
                    output_dir=output_dir,
                )
            windows_search_imported = {"carves": 0, "objects": 0, "rows": 0}
            should_import_search = (
                args.import_windows_search_memory
                or args.profile == "windows-search-carve"
                or _looks_like_windows_search_sqlite_source(source)
            )
            if should_import_search and staged_rows:
                parsed = parse_windows_search_memory_carves(
                    output_dir,
                    case_id=args.case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=output_id,
                    source_csv=manifest_path,
                    max_rows_per_table=args.max_rows_per_table,
                )
                db.insert_windows_search_memory_carves(parsed["carves"])
                db.insert_windows_search_memory_objects(parsed["objects"])
                db.insert_windows_search_memory_rows(parsed["rows"])
                windows_search_imported = {
                    "carves": len(parsed["carves"]),
                    "objects": len(parsed["objects"]),
                    "rows": len(parsed["rows"]),
                }
            db.log_activity(
                case_id=args.case_id,
                computer_id=computer_id,
                image_id=image_id,
                event="carve.sqlite_staged",
                message="Staged SQLite carve outputs",
                details={
                    "profile": args.profile,
                    "source": str(source),
                    "output_dir": str(output_dir),
                    "carve_count": len(staged_rows),
                    "limited": manifest.get("limited"),
                    "limit_reason": manifest.get("limit_reason"),
                    "artifact_imported": artifact_imported,
                    "windows_search_imported": windows_search_imported,
                },
            )
            print_json(
                {
                    "case_id": args.case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "profile": args.profile,
                    "source": str(source),
                    "output_dir": str(output_dir),
                    "manifest_path": str(manifest_path),
                    "scan_ranges_path": str(ranges_path),
                    "start_offset": args.start_offset,
                    "chunk_size": args.chunk_size,
                    "scan_ranges": len(scan_rows),
                    "scanned_bytes": manifest.get("scanned_bytes"),
                    "next_start_offset": args.start_offset + int(manifest.get("scanned_bytes") or 0),
                    "staged_carves": len(staged_rows),
                    "limited": manifest.get("limited"),
                    "limit_reason": manifest.get("limit_reason"),
                    "artifact_imported": artifact_imported,
                    "windows_search_imported": windows_search_imported,
                }
            )
            return 0

        if args.resource == "carve" and args.action == "ese":
            source = Path(args.path)
            if not source.exists():
                raise OrchestratorError(f"Carve source does not exist: {source}")
            computer_id, image_id = _cloud_or_memory_evidence_ids(
                db,
                case_id=args.case_id,
                evidence_path=source,
                computer_id=args.computer_id,
                image_id=args.image_id,
            )
            output_dir = paths.case_dir(args.case_id) / "supplemental" / "carves" / str(uuid.uuid4())
            manifest = stage_ese_carves(
                source,
                output_dir,
                max_carves=args.max_carves,
                max_bytes=args.max_bytes,
                max_carve_size=args.max_carve_size,
                start_offset=args.start_offset,
                chunk_size=args.chunk_size,
            )
            manifest_path = output_dir / "staged-carves.csv"
            ranges_path = output_dir / "scan-ranges.csv"
            manifest_rows: list[dict[str, object]] = []
            for row_number, staged in enumerate(manifest["carves"], start=1):
                staged_path = Path(str(staged["path"]))
                summary = summarize_ese_carve(staged_path)
                manifest_rows.append(
                    {
                        "row_number": row_number,
                        "profile": args.profile,
                        "source_path": str(source),
                        "source_offset": staged.get("source_offset"),
                        "staged_path": str(staged_path),
                        "staged_name": staged_path.name,
                        "staged_size": staged.get("size"),
                        "staged_sha256": staged.get("sha256"),
                        **summary,
                    }
                )
            if manifest_rows:
                with manifest_path.open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=list(manifest_rows[0].keys()))
                    writer.writeheader()
                    writer.writerows(manifest_rows)
            else:
                manifest_path.write_text("row_number,profile,source_path,source_offset,staged_path\n", encoding="utf-8")
            _write_scan_ranges_csv(ranges_path, manifest.get("scan_ranges") or [])
            output_id = str(uuid.uuid4())
            db.insert_tool_output(
                {
                    "id": output_id,
                    "case_id": args.case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "job_id": None,
                    "tool_name": "CarveStageRunner",
                    "output_type": "csv",
                    "path": manifest_path,
                    "row_count": len(manifest_rows),
                }
            )
            staged_rows = []
            for manifest_row, staged in zip(manifest_rows, manifest["carves"]):
                staged_row = staged_carve_row(
                    case_id=args.case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=output_id,
                    source_csv=manifest_path,
                    row_number=int(manifest_row["row_number"]),
                    profile=args.profile,
                    source_path=str(source),
                    staged=staged,
                    summary=manifest_row,
                    carve_type="ese",
                    notes="ESE carve staged; parse with Windows Search, SRUM, or WebCache tooling when structurally complete.",
                )
                staged_row["created_at"] = datetime.now(timezone.utc).isoformat()
                staged_rows.append(staged_row)
            db.insert_staged_carves(staged_rows)
            scan_rows = [
                scan_range_row(
                    case_id=args.case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=output_id,
                    source_csv=ranges_path,
                    row_number=index,
                    profile=args.profile,
                    carve_type="ese",
                    range_info=range_info,
                    limited=bool(manifest.get("limited")),
                    limit_reason=str(manifest.get("limit_reason") or ""),
                )
                for index, range_info in enumerate(manifest.get("scan_ranges") or [], start=1)
            ]
            db.insert_carve_scan_ranges(scan_rows)
            db.insert_timeline_events(timeline_events_from_rows(staged_rows))
            db.log_activity(
                case_id=args.case_id,
                computer_id=computer_id,
                image_id=image_id,
                event="carve.ese_staged",
                message="Staged ESE carve outputs",
                details={
                    "profile": args.profile,
                    "source": str(source),
                    "output_dir": str(output_dir),
                    "carve_count": len(staged_rows),
                    "limited": manifest.get("limited"),
                    "limit_reason": manifest.get("limit_reason"),
                },
            )
            print_json(
                {
                    "case_id": args.case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "profile": args.profile,
                    "source": str(source),
                    "output_dir": str(output_dir),
                    "manifest_path": str(manifest_path),
                    "scan_ranges_path": str(ranges_path),
                    "start_offset": args.start_offset,
                    "chunk_size": args.chunk_size,
                    "scan_ranges": len(scan_rows),
                    "scanned_bytes": manifest.get("scanned_bytes"),
                    "next_start_offset": args.start_offset + int(manifest.get("scanned_bytes") or 0),
                    "staged_carves": len(staged_rows),
                    "limited": manifest.get("limited"),
                    "limit_reason": manifest.get("limit_reason"),
                }
            )
            return 0

        if args.resource == "cloud" and args.action == "import-logs":
            source = Path(args.path)
            computer_id, image_id = _cloud_or_memory_evidence_ids(
                db,
                case_id=args.case_id,
                evidence_path=source,
                computer_id=args.computer_id,
            )
            output_dir = paths.case_dir(args.case_id) / "supplemental" / "cloud-server-logs" / str(uuid.uuid4())
            csv_path = import_cloud_server_logs_to_csv(source, output_dir, provider=args.provider, service=args.service)
            output_id = str(uuid.uuid4())
            db.insert_tool_output(
                {
                    "id": output_id,
                    "case_id": args.case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "job_id": None,
                    "tool_name": "CloudServerLogImporter",
                    "output_type": "csv",
                    "path": csv_path,
                    "row_count": _count_csv_rows(csv_path),
                }
            )
            imported = ingest_csv_output(
                db=db,
                case_id=args.case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=output_id,
                tool_name="CloudServerLogImporter",
                path=csv_path,
            )
            print_json({"case_id": args.case_id, "computer_id": computer_id, "image_id": image_id, "output": csv_path, "imported_rows": imported})
            return 0

        if args.resource == "memory" and args.action == "strings":
            source = Path(args.path)
            computer_id, image_id = _cloud_or_memory_evidence_ids(
                db,
                case_id=args.case_id,
                evidence_path=source,
                computer_id=args.computer_id,
                image_id=args.image_id,
            )
            output_dir = paths.case_dir(args.case_id) / "supplemental" / "memory-strings" / str(uuid.uuid4())
            csv_path, metadata = scan_memory_strings_to_csv(
                source,
                output_dir,
                min_length=args.min_length,
                decompress_hiberfil=not args.no_decompress_hiberfil,
            )
            output_id = str(uuid.uuid4())
            db.insert_tool_output(
                {
                    "id": output_id,
                    "case_id": args.case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "job_id": None,
                    "tool_name": "MemoryStringScanner",
                    "output_type": "csv",
                    "path": csv_path,
                    "row_count": _count_csv_rows(csv_path),
                }
            )
            imported = ingest_csv_output(
                db=db,
                case_id=args.case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=output_id,
                tool_name="MemoryStringScanner",
                path=csv_path,
            )
            db.log_activity(
                case_id=args.case_id,
                computer_id=computer_id,
                image_id=image_id,
                event="memory.strings_scanned",
                message="Scanned memory-adjacent artifact for targeted strings",
                details={"source_path": str(source), **metadata},
            )
            print_json({"case_id": args.case_id, "computer_id": computer_id, "image_id": image_id, "output": csv_path, "imported_rows": imported, **metadata})
            return 0

        if args.resource == "memory" and args.action == "crash-dumps":
            db.get_case(args.case_id)
            artifacts = [
                row for row in memory_artifacts_report(db, args.case_id, limit=5000).get("artifacts") or []
                if row.get("artifact_type") in {"crash_dump", "process_dump", "full_memory_dump"}
            ]
            base_output_dir = paths.case_dir(args.case_id) / "supplemental" / "crash-dump-strings" / str(uuid.uuid4())
            scans: list[dict[str, object]] = []
            total_imported = 0
            scan_tasks: list[ProcessingTask] = []
            for index, artifact in enumerate(artifacts, 1):
                source_value = artifact.get("actual_path") or artifact.get("path")
                source = Path(str(source_value or ""))
                if not source.exists() or not source.is_file():
                    scans.append(
                        {
                            "artifact_path": artifact.get("path"),
                            "artifact_type": artifact.get("artifact_type"),
                            "status": "skipped",
                            "reason": "Dump was inventoried from metadata but no accessible file path is available.",
                        }
                    )
                    continue
                output_dir = base_output_dir / f"{index:04d}"
                def scan_dump(source: Path = source, output_dir: Path = output_dir) -> dict[str, object]:
                    scan_source = source
                    if args.copy:
                        output_dir.mkdir(parents=True, exist_ok=True)
                        copied = output_dir / source.name
                        shutil.copy2(source, copied)
                        scan_source = copied
                    csv_path, metadata = scan_memory_strings_to_csv(
                        scan_source,
                        output_dir,
                        min_length=args.min_length,
                        decompress_hiberfil=False,
                    )
                    return {"csv_path": csv_path, "metadata": metadata, "scan_source": scan_source}

                scan_tasks.append(
                    ProcessingTask(
                        name=f"crash-dump:{index}",
                        payload={"artifact": artifact, "source": source},
                        worker=scan_dump,
                    )
                )

            for result in run_processing_tasks(scan_tasks, workers=args.workers):
                artifact = result.payload["artifact"]
                source = Path(result.payload["source"])
                scan_source = source
                computer_id, image_id = _cloud_or_memory_evidence_ids(
                    db,
                    case_id=args.case_id,
                    evidence_path=scan_source,
                    computer_id=args.computer_id,
                    image_id=args.image_id,
                )
                if result.status == "failed":
                    db.log_activity(
                        case_id=args.case_id,
                        computer_id=computer_id,
                        image_id=image_id,
                        event="memory.crash_dump_scan_failed",
                        level="warning",
                        message=f"Crash dump string scan failed for {source}",
                        details={"path": str(source), "error": result.error, "duration_seconds": result.duration_seconds},
                    )
                    scans.append(
                        {
                            "artifact_path": artifact.get("path"),
                            "artifact_type": artifact.get("artifact_type"),
                            "source": str(scan_source),
                            "status": "failed",
                            "error": result.error,
                            "duration_seconds": result.duration_seconds,
                        }
                    )
                    continue
                value = result.value
                csv_path = Path(value["csv_path"])
                metadata = value["metadata"]
                scan_source = Path(value["scan_source"])
                output_id = str(uuid.uuid4())
                db.insert_tool_output(
                    {
                        "id": output_id,
                        "case_id": args.case_id,
                        "computer_id": computer_id,
                        "image_id": image_id,
                        "job_id": None,
                        "tool_name": "MemoryStringScanner",
                        "output_type": "csv",
                        "path": csv_path,
                        "row_count": _count_csv_rows(csv_path),
                    }
                )
                imported = ingest_csv_output(
                    db=db,
                    case_id=args.case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=output_id,
                    tool_name="MemoryStringScanner",
                    path=csv_path,
                )
                total_imported += imported
                db.log_activity(
                    case_id=args.case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    event="memory.crash_dump_scanned",
                    message="Scanned crash dump for targeted strings",
                    details={
                        "artifact_path": artifact.get("path"),
                        "artifact_type": artifact.get("artifact_type"),
                        "source_path": str(scan_source),
                        "original_source_path": str(source),
                        "output": str(csv_path),
                        "imported_rows": imported,
                        **metadata,
                    },
                )
                scans.append(
                    {
                        "artifact_path": artifact.get("path"),
                        "artifact_type": artifact.get("artifact_type"),
                        "source": str(scan_source),
                        "output": str(csv_path),
                        "imported_rows": imported,
                        "status": "scanned",
                        "duration_seconds": result.duration_seconds,
                        **metadata,
                    }
                )
            print_json(
                {
                    "case_id": args.case_id,
                    "artifact_count": len(artifacts),
                    "worker_count": max(1, args.workers),
                    "scan_task_count": len(scan_tasks),
                    "scanned_count": sum(1 for row in scans if row.get("status") == "scanned"),
                    "skipped_count": sum(1 for row in scans if row.get("status") == "skipped"),
                    "failed_count": sum(1 for row in scans if row.get("status") == "failed"),
                    "imported_rows": total_imported,
                    "output_dir": str(base_output_dir),
                    "scans": scans,
                }
            )
            return 0

        if args.resource == "memory" and args.action == "profile":
            print_json(
                run_memory_processing_profile(
                    db,
                    paths,
                    case_id=args.case_id,
                    computer_id=args.computer_id,
                    image_id=args.image_id,
                    min_length=args.min_length,
                    include_crash_dumps=not args.no_crash_dumps,
                    extract_fallback=not args.no_extract_fallback,
                    workers=args.workers,
                )
            )
            return 0

        if args.resource == "memory" and args.action == "windows-search-carves":
            source = Path(args.path)
            computer_id, image_id = _cloud_or_memory_evidence_ids(
                db,
                case_id=args.case_id,
                evidence_path=source,
                computer_id=args.computer_id,
                image_id=args.image_id,
            )
            output_dir = paths.case_dir(args.case_id) / "supplemental" / "windows-search-memory-carves" / str(uuid.uuid4())
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / "WindowsSearchMemoryCarveParser.json"
            output_id = str(uuid.uuid4())
            parsed = parse_windows_search_memory_carves(
                source,
                case_id=args.case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=output_id,
                source_csv=output_path,
                max_rows_per_table=args.max_rows_per_table,
            )
            output_payload = {
                "source": str(source),
                "carves": len(parsed["carves"]),
                "objects": len(parsed["objects"]),
                "rows": len(parsed["rows"]),
            }
            output_path.write_text(json.dumps(output_payload, indent=2, sort_keys=True), encoding="utf-8")
            db.insert_tool_output(
                {
                    "id": output_id,
                    "case_id": args.case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "job_id": None,
                    "tool_name": "WindowsSearchMemoryCarveParser",
                    "output_type": "json",
                    "path": output_path,
                    "row_count": len(parsed["carves"]) + len(parsed["objects"]) + len(parsed["rows"]),
                }
            )
            db.insert_windows_search_memory_carves(parsed["carves"])
            db.insert_windows_search_memory_objects(parsed["objects"])
            db.insert_windows_search_memory_rows(parsed["rows"])
            db.log_activity(
                case_id=args.case_id,
                computer_id=computer_id,
                image_id=image_id,
                event="memory.windows_search_carves_imported",
                message="Imported Windows Search SQLite memory carves",
                details=output_payload,
            )
            print_json({"case_id": args.case_id, "computer_id": computer_id, "image_id": image_id, "output": output_path, **output_payload})
            return 0

        if args.resource == "search" and args.action == "query":
            db.get_case(args.case_id)
            search_config = OpenSearchConfig.from_values(
                url=args.url,
                index=args.index,
                username=args.username,
                password=args.password,
                insecure=args.insecure,
            )
            synonym_groups = [] if args.no_synonyms else (load_synonym_groups(args.synonyms) if args.synonyms else None)
            result = search_case_content(
                case_id=args.case_id,
                query=args.query,
                config=search_config,
                limit=args.limit,
                synonym_groups=synonym_groups,
            )
            if args.format == "table":
                write_report_output(
                    result,
                    result["hits"],
                    "table",
                    args.output,
                    title=f"OpenSearch content results for case {args.case_id}",
                    columns=[
                        "score",
                        "source_type",
                        "timestamp",
                        "user_profile",
                        "title",
                        "sender",
                        "source_path",
                        "container_path",
                    ],
                )
            else:
                write_text_output(json.dumps(result, indent=2, default=str), args.output)
            return 0

        if args.resource == "search" and args.action == "show":
            result = search_result_drilldown(
                db,
                case_id=args.case_id,
                source_table=args.source_table,
                source_record_id=args.source_id,
            )
            if args.format == "table":
                rows = []
                for key in ("message", "attachment", "indexed_content", "source_record", "record"):
                    if isinstance(result.get(key), dict):
                        rows.append({"section": key, **result[key]})
                for key in (
                    "attachments",
                    "copies",
                    "sibling_attachments",
                    "duplicate_attachments",
                    "related_windows_search",
                    "related_mailbox_messages",
                ):
                    for row in result.get(key, []) if isinstance(result.get(key), list) else []:
                        rows.append({"section": key, **row})
                write_report_output(
                    result,
                    rows,
                    "table",
                    args.output,
                    title=f"Search drilldown for {args.source_table}:{args.source_id}",
                    columns=[
                        "section",
                        "match_type",
                        "overlap",
                        "message_date_utc",
                        "timestamp",
                        "subject",
                        "sender",
                        "attachment_name",
                        "item_path",
                        "source_path",
                        "container_path",
                        "message_path",
                    ],
                )
            else:
                write_text_output(json.dumps(result, indent=2, default=str), args.output)
            return 0

        if args.resource == "computer" and args.action == "add":
            computer = create_computer(
                db,
                paths,
                args.case_id,
                label=args.label,
                hostname=args.hostname,
                notes=args.notes,
            )
            print_json(
                {
                    "computer_id": computer.id,
                    "case_id": computer.case_id,
                    "label": computer.label,
                    "hostname": computer.hostname,
                }
            )
            return 0

        if args.resource == "computer" and args.action == "list":
            status = db.case_status(args.case_id)
            print_json({"case_id": args.case_id, "computers": status["computers"]})
            return 0

        if args.resource == "image" and args.action == "add":
            image = add_image(
                db,
                paths,
                args.case_id,
                Path(args.path),
                computer_id=args.computer_id,
            )
            print_json(
                {
                    "image_id": image.id,
                    "case_id": image.case_id,
                    "computer_id": image.computer_id,
                    "path": str(image.path),
                }
            )
            return 0

        if args.resource == "image" and args.action == "mount":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            volume = mount_image(
                db=db,
                paths=paths,
                case_id=case.id,
                image=image,
                dry_run=args.dry_run,
                mount_filesystem=args.filesystem,
                use_sudo_mount=args.use_sudo_mount,
            )
            payload = {
                "case_id": case.id,
                "image_id": image.id,
                "dry_run": args.dry_run,
                "volume_mount_path": str(volume) if volume else None,
                "processing_mode": (
                    "read-only-filesystem-mount-with-direct-tsk-fallback"
                    if args.filesystem
                    else "direct-tsk-with-ewfmount-fallback"
                ),
            }
            if args.dry_run:
                payload["commands"] = command_preview(db, case.id)
                payload["note"] = (
                    "Dry-run recorded fsstat/mmls preparation commands. Real runs try fsstat "
                    "first, then mmls, and fall back to ewfmount when direct E01 access is not enough."
                )
            print_json(payload)
            return 0

        if args.resource == "image" and args.action == "unmount":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            mount_path = unmount_image(
                db=db,
                paths=paths,
                case_id=case.id,
                image=image,
                dry_run=args.dry_run,
                use_sudo_mount=args.use_sudo_mount,
            )
            payload = {
                "case_id": case.id,
                "image_id": image.id,
                "dry_run": args.dry_run,
                "volume_mount_path": str(mount_path),
            }
            if args.dry_run:
                payload["commands"] = command_preview(db, case.id)
            print_json(payload)
            return 0

        if args.resource == "image" and args.action == "cleanup-stale-mounts":
            print_json(
                cleanup_stale_mounts(
                    db,
                    case_id=args.case_id,
                    apply=args.apply,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "list":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(discover_vsc_snapshots(db=db, paths=paths, case_id=case.id, image=image))
            return 0

        if args.resource == "vsc" and args.action == "mount":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                mount_vsc_snapshot(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_index=args.snapshot_index,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "extract":
            db.get_case(args.case_id)
            print_json(
                extract_vsc_artifact(
                    paths=paths,
                    case_id=args.case_id,
                    snapshot_id=args.snapshot_id,
                    relative_path=args.relative_path,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "prefetch-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_prefetch_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "registry-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_registry_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "browser-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_browser_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "appcompat-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_appcompat_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "srum-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_srum_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "evtx-triage-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_evtx_triage_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "ntfs-delta-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_ntfs_delta_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "recycle-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_recycle_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "windows-search-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_windows_search_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "file-history-report":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            report = build_vsc_file_history_report(
                db=db,
                paths=paths,
                case_id=case.id,
                image_id=image.id,
            )
            print_json(
                {
                    "case_id": report["case_id"],
                    "image_id": report["image_id"],
                    "started_at": report["started_at"],
                    "ended_at": report["ended_at"],
                    "summary": report["summary"],
                    "report_path": report["report_path"],
                    "json_path": report["json_path"],
                }
            )
            return 0

        if args.resource == "vsc" and args.action == "profile-scan":
            case = db.get_case(args.case_id)
            image = db.get_image(args.image_id, args.case_id)
            print_json(
                run_vsc_profile_scan(
                    db=db,
                    paths=paths,
                    case_id=case.id,
                    image=image,
                    profile=args.profile,
                    snapshot_indexes=args.snapshot_indexes,
                    use_sudo_mount=args.use_sudo_mount,
                    continue_on_error=not args.stop_on_error,
                )
            )
            return 0

        if args.resource == "vsc" and args.action == "unmount":
            db.get_case(args.case_id)
            print_json(
                unmount_vsc(
                    paths=paths,
                    case_id=args.case_id,
                    snapshot_id=args.snapshot_id,
                    use_sudo_mount=args.use_sudo_mount,
                )
            )
            return 0

        if args.resource == "tools" and args.action == "list":
            profile_previews = {
                name: profile_extraction_preview(registry, name)
                for name in registry.profiles
            }
            print_json(
                {
                    "tools": [
                        {
                            "name": tool.name,
                            "enabled": tool.enabled,
                            "type": tool.type,
                            "executable": tool.executable,
                        }
                        for tool in registry.tools.values()
                    ],
                    "profiles": registry.profiles,
                    "profile_previews": {
                        name: {
                            "extraction_policy": preview["extraction_policy"],
                            "policy_tsk_artifact_count": preview["policy_tsk_artifact_count"],
                        }
                        for name, preview in profile_previews.items()
                    },
                }
            )
            return 0

        if args.resource == "tools" and args.action == "profile-preview":
            print_json(profile_extraction_preview(registry, args.profile))
            return 0

        if args.resource == "run":
            db.get_case(args.case_id)
            db.get_image(args.image_id, args.case_id)
            run_profile(
                db=db,
                paths=paths,
                registry=registry,
                case_id=args.case_id,
                image_id=args.image_id,
                profile=args.profile,
                dry_run=args.dry_run,
                include_start_menu_lnk=args.include_start_menu_lnk,
                include_deleted_mft=args.include_deleted_mft,
                include_live_orphans=args.include_live_orphans,
                replace_existing=args.replace_existing,
                accept_duplicate=args.accept_duplicate,
                include_windows_old=args.include_windows_old,
                workers=args.workers,
            )
            memory_profile_result = _run_memory_after_profile(
                db,
                paths,
                case_id=args.case_id,
                computer_id=None,
                image_id=args.image_id,
                profile=args.profile,
                workers=args.workers,
                include_memory_profile=args.include_memory_profile,
                no_memory_profile=args.no_memory_profile,
                dry_run=args.dry_run,
            )
            payload = {
                "case_id": args.case_id,
                "image_id": args.image_id,
                "profile": args.profile,
                "dry_run": args.dry_run,
                "requested_workers": args.workers,
                "effective_workers": max(1, args.workers),
                "parallel_scope": "artifact_extraction_and_external_tools" if args.workers > 1 else "serial",
                "memory_profile": memory_profile_result,
            }
            if args.dry_run:
                payload["commands"] = command_preview(db, args.case_id)
            print_json(payload)
            return 0

        if args.resource == "report" and args.action == "summary":
            print_json(case_summary_report(db, args.case_id))
            return 0

        if args.resource == "report" and args.action == "case-overview":
            report = case_overview_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(case_overview_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["top_suspicious_executions"],
                    args.format,
                    args.output,
                    title=f"Case overview for case {args.case_id}",
                    columns=["severity", "category", "application", "display_path", "reason"],
                )
            return 0

        if args.resource == "report" and args.action == "regression-smoke":
            report = regression_smoke_report(db, args.case_id, limit=args.limit)
            if args.write_reports:
                output_dir = Path(args.output_dir) if args.output_dir else paths.case_dir(args.case_id) / "reports" / "regression-smoke-bundle"
                report["written_reports"] = write_case_report_bundle(db, args.case_id, output_dir, limit=max(args.limit, 100))
            write_report_output(
                report,
                report["checks"],
                args.format,
                args.output,
                title=f"Regression smoke report for case {args.case_id}",
                columns=["name", "status", "error"],
            )
            return 0

        if args.resource == "report" and args.action == "write-bundle":
            print_json(write_case_report_bundle(db, args.case_id, Path(args.output_dir), limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "combined-artifacts":
            report = combined_artifact_family_report(db, args.case_id, family=args.family, limit=args.limit)
            if args.format == "md":
                write_text_output(combined_artifact_family_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["families"],
                    args.format,
                    args.output,
                    title=f"Combined artifact family report for case {args.case_id}",
                    columns=["family", "disk_reference_count", "memory_correlation_count", "evidence_strength"],
                )
            return 0

        if args.resource == "report" and args.action == "artifact-processing-status":
            report = artifact_processing_status_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["items"],
                args.format,
                args.output,
                title=f"Artifact processing status for case {args.case_id}",
                columns=["artifact_family", "artifact_type", "status", "path", "row_count", "source", "notes"],
            )
            return 0

        if args.resource == "report" and args.action == "processing-decisions":
            report = processing_decision_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(processing_decision_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["decisions"],
                    args.format,
                    args.output,
                    title=f"Processing decisions for case {args.case_id}",
                    columns=["severity", "decision_type", "status", "item", "summary", "followup"],
                )
            return 0

        if args.resource == "report" and args.action == "processing-readiness":
            report = processing_readiness_report(db, args.case_id, limit=args.limit, profile=args.profile)
            if args.format == "md":
                write_text_output(processing_readiness_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["items"],
                    args.format,
                    args.output,
                    title=f"Processing readiness for case {args.case_id}",
                    columns=["key", "title", "status", "next_step"],
                )
            return 0

        if args.resource == "report" and args.action == "specs":
            specs = list_report_specs(plugin_paths=config.plugin_paths)
            rows = [
                {
                    "name": spec.name,
                    "title": spec.title,
                    "store": spec.store,
                    "description": spec.description,
                    "source": str(spec.source),
                }
                for spec in specs
            ]
            write_report_output(
                {"report_specs": rows, "total_returned": len(rows)},
                rows,
                args.format,
                args.output,
                title="Report specs",
                columns=["name", "store", "title", "description", "source"],
            )
            return 0

        if args.resource == "report" and args.action == "spec":
            report = run_report_spec(db, args.case_id, args.name, limit=args.limit, plugin_paths=config.plugin_paths)
            write_report_output(
                report,
                report["rows"],
                args.format,
                args.output,
                title=report["spec"]["title"],
                columns=report["columns"],
            )
            return 0

        if args.resource == "report" and args.action == "storage-policy":
            report = storage_policy_report(db, args.case_id)
            rows = [
                {
                    "table": row["table"],
                    "policy": row["policy"],
                    "row_count": row["row_count"],
                    "non_empty_large_rows": row["non_empty_large_rows"],
                    "estimated_large_text_bytes": row["estimated_large_text_bytes"],
                    "sqlite_role": row["sqlite_role"],
                }
                for row in report["content_heavy_tables"]
            ]
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"Storage policy for case {args.case_id}",
                columns=["table", "policy", "row_count", "non_empty_large_rows", "estimated_large_text_bytes", "sqlite_role"],
            )
            return 0

        if args.resource == "report" and args.action == "issues":
            print_json(issues_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "execution":
            report = execution_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(execution_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["events"],
                args.format,
                args.output,
                title=f"Execution evidence for case {args.case_id}",
                columns=["timestamp_utc", "source_table", "event_type", "description", "path"],
            )
            return 0

        if args.resource == "report" and args.action == "execution-correlation":
            report = execution_correlation_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["execution_correlations"],
                args.format,
                args.output,
                title=f"Execution correlations for case {args.case_id}",
                columns=["path", "executable", "evidence_count", "source_count", "sources", "users", "first_seen_utc", "last_seen_utc", "max_run_count"],
            )
            return 0

        if args.resource == "report" and args.action == "persistence":
            report = persistence_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["persistence_items"],
                args.format,
                args.output,
                title=f"Persistence and autorun items for case {args.case_id}",
                columns=["artifact", "category", "key_last_write_utc", "event_time_utc", "user_profile", "key_path", "value_name", "value_data", "normalized_path", "source_path"],
            )
            return 0

        if args.resource == "report" and args.action == "autostarts":
            report = autostarts_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(autostarts_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["autostarts"],
                args.format,
                args.output,
                title=f"Autostarts and scheduled tasks for case {args.case_id}",
                columns=[
                    "timestamp_utc",
                    "autostart_location",
                    "artifact",
                    "category",
                    "user_profile",
                    "key_path",
                    "value_name",
                    "value_preview",
                    "normalized_path",
                    "source_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "brute-force":
            report = brute_force_report(
                db,
                args.case_id,
                limit=args.limit,
                min_failures=args.min_failures,
                spray_account_threshold=args.spray_account_threshold,
            )
            if args.format == "md":
                write_text_output(brute_force_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["source_ips"],
                args.format,
                args.output,
                title=f"Brute force and password spraying report for case {args.case_id}",
                columns=[
                    "severity",
                    "classification",
                    "source_ip",
                    "failure_count",
                    "target_account_count",
                    "first_seen_utc",
                    "last_seen_utc",
                    "credential_results",
                    "top_targets",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "malware-hiding-places":
            report = malware_hiding_places_report(
                db,
                args.case_id,
                limit=args.limit,
                long_value_threshold=args.long_value_threshold,
            )
            rows = [*report["unusual_execution_locations"], *report["registry_value_indicators"]]
            if args.format == "md":
                write_text_output(malware_hiding_places_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"Potential malware hiding places for case {args.case_id}",
                columns=[
                    "severity",
                    "source_table",
                    "timestamp_utc",
                    "location_category",
                    "application",
                    "display_path",
                    "artifact",
                    "key_path",
                    "value_name",
                    "value_length",
                    "flags",
                    "reason",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "interesting-executables":
            report = interesting_executables_report(
                db,
                args.case_id,
                limit=args.limit,
                rules_path=args.rules,
            )
            if args.format == "md":
                write_text_output(interesting_executables_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["applications"],
                args.format,
                args.output,
                title=f"Interesting executables and applications for case {args.case_id}",
                columns=[
                    "severity",
                    "category",
                    "label",
                    "has_run_evidence",
                    "execution_evidence_count",
                    "process_activity_count",
                    "presence_count",
                    "installed_application_count",
                    "file_system_count",
                    "first_seen_utc",
                    "last_seen_utc",
                    "sources",
                    "applications",
                    "paths",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "suspicious-executions":
            report = suspicious_executions_report(
                db,
                args.case_id,
                limit=args.limit,
                rules_path=args.rules,
            )
            if args.format == "md":
                write_text_output(suspicious_executions_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["findings"],
                args.format,
                args.output,
                title=f"Suspicious executions for case {args.case_id}",
                columns=[
                    "severity",
                    "confidence",
                    "category",
                    "timestamp_utc",
                    "source_table",
                    "event_type",
                    "application",
                    "display_path",
                    "matched_rules",
                    "reason",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "suspicious-timeline-windows":
            report = suspicious_timeline_windows_report(
                db,
                args.case_id,
                window_minutes=args.window_minutes,
                limit=args.limit,
            )
            if args.format == "md":
                write_text_output(suspicious_timeline_windows_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["windows"],
                args.format,
                args.output,
                title=f"Suspicious timeline windows for case {args.case_id}",
                columns=["start_utc", "end_utc", "score", "event_count", "categories", "rationale"],
            )
            return 0

        if args.resource == "report" and args.action == "triage-dashboard":
            report = investigation_triage_dashboard_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(investigation_triage_dashboard_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["cards"],
                args.format,
                args.output,
                title=f"Investigation triage dashboard for case {args.case_id}",
                columns=["id", "title", "severity", "score", "summary_text"],
            )
            return 0

        if args.resource == "report" and args.action == "data-exfiltration":
            report = data_exfiltration_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(data_exfiltration_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["findings"],
                args.format,
                args.output,
                title=f"Data exfiltration report for case {args.case_id}",
                columns=["severity", "category", "source", "description"],
            )
            return 0

        if args.resource == "report" and args.action == "account-compromise":
            report = account_compromise_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(account_compromise_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["findings"],
                args.format,
                args.output,
                title=f"Account compromise report for case {args.case_id}",
                columns=["severity", "category", "source", "description"],
            )
            return 0

        if args.resource == "report" and args.action == "program-provenance":
            report = program_provenance_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(program_provenance_markdown(report), args.output)
                return 0
            write_report_output(
                report,
                report["findings"],
                args.format,
                args.output,
                title=f"Program provenance report for case {args.case_id}",
                columns=["severity", "category", "source", "description"],
            )
            return 0

        if args.resource == "report" and args.action == "accounts":
            print_json(accounts_report(db, args.case_id))
            return 0

        if args.resource == "report" and args.action == "users":
            print_json(users_report(db, args.case_id))
            return 0

        if args.resource == "report" and args.action == "files":
            print_json(files_report(db, args.case_id, user=args.user, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "file-names":
            report = file_names_report(
                db,
                args.case_id,
                limit=args.limit,
                contains=args.contains,
                include_mft=args.include_mft,
            )
            write_report_output(
                report,
                report["file_names"],
                args.format,
                args.output,
                title=f"File-name evidence for case {args.case_id}",
                columns=["file_name", "evidence_count", "source_count", "evidence_tags", "sources", "users", "applications", "first_seen_utc", "last_seen_utc", "path_count"],
            )
            return 0

        if args.resource == "report" and args.action == "file-name-drilldown":
            report = file_name_drilldown_report(
                db,
                args.case_id,
                name=args.name,
                include_mft=args.include_mft,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["evidence"],
                args.format,
                args.output,
                title=f"File-name drilldown for {args.name}",
                columns=["file_name", "source", "source_table", "timestamp", "user_profile", "application", "evidence_tags", "path"],
            )
            return 0

        if args.resource == "report" and args.action == "file-dossier":
            report = file_dossier_report(
                db,
                args.case_id,
                path=args.path,
                name=args.name,
                limit=args.limit,
            )
            if args.format == "table":
                rows = [
                    {"section": "summary", "item": key, "value": value}
                    for key, value in report["summary"].items()
                ]
                write_report_output(
                    report,
                    rows,
                    "table",
                    args.output,
                    title=f"File dossier for case {args.case_id}",
                    columns=["section", "item", "value"],
                )
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0

        if args.resource == "report" and args.action == "file-intelligence":
            report = file_intelligence_report(
                db,
                args.case_id,
                path=args.path,
                name=args.name,
                limit=args.limit,
            )
            if args.format == "table":
                rows = [
                    {"section": "summary", "item": key, "value": value}
                    for key, value in report["summary"].items()
                    if key != "source_counts"
                ]
                rows.extend(
                    {"section": "source", "item": row["source"], "value": row["count"]}
                    for row in report["summary"]["source_counts"]
                )
                write_report_output(
                    report,
                    rows,
                    "table",
                    args.output,
                    title=f"File intelligence for case {args.case_id}",
                    columns=["section", "item", "value"],
                )
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0

        if args.resource == "report" and args.action == "file-history":
            if not any((args.name, args.path, args.mft_entry)):
                report = file_names_report(db, args.case_id, include_mft=False, limit=args.limit)
                if args.format == "md":
                    write_text_output(file_history_overview_markdown(report), args.output)
                    return 0
                rows = report["file_names"]
                write_report_output(
                    report,
                    rows,
                    args.format,
                    args.output,
                    title=f"File history overview for case {args.case_id}",
                    columns=[
                        "file_name",
                        "evidence_count",
                        "source_count",
                        "path_count",
                        "sources",
                        "users",
                        "first_seen_utc",
                        "last_seen_utc",
                    ],
                )
                return 0
            report = file_history_report(
                db,
                args.case_id,
                name=args.name,
                path=args.path,
                mft_entry=args.mft_entry,
                include_artifacts=not args.filesystem_only,
                include_vsc=args.include_vsc,
                limit=args.limit,
            )
            if args.format == "md":
                write_text_output(file_history_markdown(report), args.output)
                return 0
            rows = report["events"]
            if args.include_vsc:
                rows = [*rows, *report.get("vsc_events", [])]
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"File history for case {args.case_id}",
                columns=[
                    "timestamp",
                    "source",
                    "event_type",
                    "status",
                    "operation",
                    "reason",
                    "file_name",
                    "path",
                    "mft_entry_number",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "copied-files":
            print_json(copied_files_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "copied-file-indicators":
            print_json(
                copied_file_indicators_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    source_artifact_type=args.source_artifact_type,
                    user_only=args.user_only,
                    exclude_system=not args.include_system,
                    include_mft_only=args.include_mft_only,
                )
            )
            return 0

        if args.resource == "report" and args.action == "copied-file-groups":
            report = copied_file_groups_report(
                db,
                args.case_id,
                limit=args.limit,
                include_system=args.include_system,
                include_mft_only=args.include_mft_only,
            )
            write_report_output(
                report,
                report["groups"],
                args.format,
                args.output,
                title=f"Copied file groups for case {args.case_id}",
                columns=["indicator_count", "source_artifact_types", "file_location", "created_timestamp_utc", "modified_timestamp_utc"],
            )
            return 0

        if args.resource == "report" and args.action == "copied-usb-files":
            report = copied_usb_files_report(db, args.case_id, limit=args.limit, grouped=args.grouped)
            rows = report["groups"] if args.grouped else report["items"]
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"Copied USB files for case {args.case_id}",
                columns=["usb_volume_serial_number", "usb_volume_name", "file_location", "created_timestamp_utc", "modified_timestamp_utc", "source_artifact_types", "source_artifact_type", "association_basis"],
            )
            return 0

        if args.resource == "report" and args.action == "tool-runs":
            report = tool_run_summary_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["runs"],
                args.format,
                args.output,
                title=f"Tool runs for case {args.case_id}",
                columns=[
                    "start_time",
                    "tool_name",
                    "source_scope",
                    "status",
                    "exit_code",
                    "output_count",
                    "imported_row_count",
                    "warning_count",
                    "error_count",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "process-timings":
            report = process_timing_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(process_timing_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["timings"],
                    args.format,
                    args.output,
                    title=f"Process timings for case {args.case_id}",
                    columns=[
                        "start_time",
                        "end_time",
                        "duration_seconds",
                        "source_scope",
                        "scope",
                        "phase",
                        "name",
                        "status",
                        "tool_name",
                        "artifact_name",
                    ],
                )
            return 0

        if args.resource == "report" and args.action == "recovery-coverage":
            report = recovery_coverage_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["artifacts"],
                args.format,
                args.output,
                title=f"Recovery coverage for case {args.case_id}",
                columns=[
                    "profile",
                    "artifact_name",
                    "tool_name",
                    "method",
                    "status",
                    "duration_seconds",
                    "matched_count",
                    "extracted_count",
                    "failed_count",
                    "recovery_limited",
                    "limit_reason",
                    "recovery_scope",
                    "cost",
                    "noise",
                    "start_time",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "carve-coverage":
            report = carve_coverage_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(carve_coverage_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["carves"],
                    args.format,
                    args.output,
                    title=f"Carve coverage for case {args.case_id}",
                    columns=[
                        "profile",
                        "carve_type",
                        "detected_format",
                        "parser_status",
                        "import_status",
                        "source_offset",
                        "staged_size",
                        "staged_path",
                    ],
                )
            return 0

        if args.resource == "report" and args.action == "sqlite-inventory":
            report = sqlite_inventory_report(db, args.case_id, limit=args.limit, sample_rows=args.sample_rows)
            if args.format == "md":
                write_text_output(sqlite_inventory_markdown(report), args.output)
            else:
                rows = []
                for inventory in report["inventories"]:
                    rows.append(
                        {
                            "status": inventory.get("status"),
                            "staged_path": inventory.get("staged_path"),
                            "source_path": inventory.get("source_path"),
                            "source_offset": inventory.get("source_offset"),
                            "table_count": len(inventory.get("tables") or []),
                            "error": inventory.get("error"),
                        }
                    )
                write_report_output(
                    report,
                    rows,
                    args.format,
                    args.output,
                    title=f"SQLite carve inventory for case {args.case_id}",
                    columns=["status", "table_count", "source_offset", "staged_path", "error"],
                )
            return 0

        if args.resource == "report" and args.action == "case-review":
            report = case_review_report(db, args.case_id, limit=args.limit)
            if args.format == "table":
                rows = [
                    {"section": "summary", "item": key, "value": value}
                    for key, value in report["summary"].items()
                ]
                write_report_output(
                    report,
                    rows,
                    "table",
                    args.output,
                    title=f"Case review for {args.case_id}",
                    columns=["section", "item", "value"],
                )
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0

        if args.resource == "report" and args.action == "executive-summary":
            report = case_executive_summary_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(case_executive_summary_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["conclusions"],
                    args.format,
                    args.output,
                    title=f"Executive summary for case {args.case_id}",
                    columns=["priority", "evidence_strength", "topic", "summary"],
                )
            return 0

        if args.resource == "report" and args.action == "readiness-gate":
            report = processing_readiness_report(db, args.case_id, limit=args.limit, profile=args.profile)
            failed = [row for row in report.get("items", []) if row.get("required", True) and row.get("status") != "complete"]
            if args.summary_only:
                summary = _readiness_gate_summary(report, failed)
                write_report_output(
                    summary,
                    summary["failed_required"],
                    args.format,
                    args.output,
                    title=f"Processing readiness gate summary for case {args.case_id}",
                    columns=["key", "title", "status", "next_step"],
                )
                return 1 if failed else 0
            write_report_output(
                report,
                report["items"],
                args.format,
                args.output,
                title=f"Processing readiness gate for case {args.case_id}",
                columns=["key", "title", "status", "next_step"],
            )
            return 1 if failed else 0

        if args.resource == "report" and args.action == "deep-recovery-status":
            report = deep_recovery_status_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(deep_recovery_status_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["required_gaps"],
                    args.format,
                    args.output,
                    title=f"Deep recovery status for case {args.case_id}",
                    columns=["key", "title", "status", "next_step"],
                )
            return 0 if report.get("passed") else 1

        if args.resource == "report" and args.action == "case-comparison":
            report = case_comparison_report(args.case_ref)
            if args.format == "md":
                write_text_output(case_comparison_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["cases"],
                    args.format,
                    args.output,
                    title="Case comparison",
                    columns=[
                        "label",
                        "memory_required_gaps",
                        "windows_full_required_gaps",
                        "deep_recovery_required_gaps",
                        "memory_support_files",
                        "memory_string_hits",
                        "suspicious_executions",
                        "high_value_credentials",
                    ],
                )
            return 0

        if args.resource == "report" and args.action == "evidence-gaps":
            report = evidence_gaps_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(evidence_gaps_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["gaps"],
                    args.format,
                    args.output,
                    title=f"Evidence gaps and limitations for case {args.case_id}",
                    columns=["severity", "category", "title", "summary", "recommendation"],
                )
            return 0

        if args.resource == "report" and args.action == "memory-artifacts":
            report = memory_artifacts_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(memory_artifacts_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["artifacts"],
                    args.format,
                    args.output,
                    title=f"Memory artifacts for case {args.case_id}",
                    columns=["artifact_type", "path", "size_bytes", "source", "processed_status", "hiberfil_status", "notes"],
                )
            return 0

        if args.resource == "report" and args.action == "memory-support-files":
            report = memory_support_files_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(memory_support_files_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["support_files"],
                    args.format,
                    args.output,
                    title=f"Memory support file processing for case {args.case_id}",
                    columns=[
                        "artifact_type",
                        "processed_status",
                        "scan_status",
                        "hit_count",
                        "decompress_status",
                        "hiberfil_status",
                        "path",
                    ],
                )
            return 0

        if args.resource == "report" and args.action == "memory-analysis":
            report = memory_analysis_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(memory_analysis_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["findings"],
                    args.format,
                    args.output,
                    title=f"Memory processing and analysis for case {args.case_id}",
                    columns=["severity", "category", "title", "summary"],
                )
            return 0

        if args.resource == "report" and args.action == "memory-credentials":
            report = memory_credentials_report(db, args.case_id, limit=args.limit, reveal=args.reveal)
            if args.format == "md":
                write_text_output(memory_credentials_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["credentials"],
                    args.format,
                    args.output,
                    title=f"Memory credential review for case {args.case_id}",
                    columns=["credential_triage", "credential_score", "credential_status", "matched_term", "display_value", "source_artifact_type", "offset", "credential_reason"],
                )
            return 0

        if args.resource == "report" and args.action == "memory-credential-review":
            hit_count = _memory_hit_count(db, args.case_id, args.hit_id)
            if not hit_count:
                raise OrchestratorError(f"Memory credential hit not found for case {args.case_id}: {args.hit_id}")
            db.upsert_memory_credential_review(
                {
                    "case_id": args.case_id,
                    "memory_hit_id": args.hit_id,
                    "review_status": args.status,
                    "reviewer": args.reviewer,
                    "note": args.note,
                }
            )
            print_json(
                {
                    "case_id": args.case_id,
                    "memory_hit_id": args.hit_id,
                    "review_status": args.status,
                    "reviewer": args.reviewer,
                }
            )
            return 0

        if args.resource == "report" and args.action == "memory-disk-correlations":
            report = memory_disk_correlations_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(memory_disk_correlations_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["correlations"],
                    args.format,
                    args.output,
                    title=f"Memory and disk correlations for case {args.case_id}",
                    columns=["disk_artifact_family", "match_type", "match_value", "confidence", "source_artifact_type", "disk_table", "disk_path", "disk_url", "disk_email"],
                )
            return 0

        if args.resource == "report" and args.action == "crash-dump-analysis":
            report = crash_dump_analysis_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(crash_dump_analysis_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["dumps"],
                    args.format,
                    args.output,
                    title=f"Crash dump analysis for case {args.case_id}",
                    columns=["artifact_type", "path", "size_bytes", "source", "processed_status"],
                )
            return 0

        if args.resource == "report" and args.action == "cloud-server-events":
            report = cloud_server_events_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["events"],
                args.format,
                args.output,
                title=f"Cloud server events for case {args.case_id}",
                columns=["event_time_utc", "provider", "service", "event_type", "actor", "actor_ip", "target", "operation", "result", "opensearch_document_id"],
            )
            return 0

        if args.resource == "report" and args.action == "memory-string-hits":
            report = memory_string_hits_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["hits"],
                args.format,
                args.output,
                title=f"Memory string hits for case {args.case_id}",
                columns=["hit_category", "matched_term", "string_value", "source_artifact_type", "source_path", "offset", "context_hint"],
            )
            return 0

        if args.resource == "report" and args.action == "copied-file-drilldown":
            report = copied_file_drilldown_report(db, args.case_id, path=args.path, limit=args.limit)
            if args.format == "table":
                rows = [
                    {"section": key, "count": value}
                    for key, value in report["counts"].items()
                ]
                write_report_output(
                    report,
                    rows,
                    "table",
                    args.output,
                    title=f"Copied file drilldown for {args.path}",
                    columns=["section", "count"],
                )
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0

        if args.resource == "report" and args.action == "usb-dossier":
            report = usb_dossier_report(
                db,
                args.case_id,
                serial=args.serial,
                volume_serial_number=args.volume_serial_number,
                volume_guid=args.volume_guid,
                limit=args.limit,
            )
            if args.format == "table":
                rows = [
                    {"section": "device", "item": key, "value": value}
                    for key, value in report["device"].items()
                    if key in {"serial", "volume_serial_number", "volume_name", "drive_letter", "vendor_id", "product_id", "product", "friendly_name"}
                ]
                rows.extend({"section": "totals", "item": key, "value": value} for key, value in report["totals"].items())
                write_report_output(
                    report,
                    rows,
                    "table",
                    args.output,
                    title=f"USB dossier for case {args.case_id}",
                    columns=["section", "item", "value"],
                )
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0

        if args.resource == "report" and args.action == "device-inventory":
            report = device_inventory_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["devices"],
                args.format,
                args.output,
                title=f"Device inventory for case {args.case_id}",
                columns=[
                    "device_type",
                    "device_identifier",
                    "vendor",
                    "product",
                    "friendly_name",
                    "serial",
                    "instance_id",
                    "device_service",
                    "user_profile",
                    "drive_letter",
                    "volume_name",
                    "first_observed_utc",
                    "last_observed_utc",
                    "evidence_row_count",
                    "source_artifacts",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "correlations":
            print_json(correlations_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "artifact-summary":
            print_json(artifact_summary_report(db, args.case_id))
            return 0

        if args.resource == "report" and args.action == "artifact-completeness":
            report = artifact_completeness_report(
                db,
                args.case_id,
                limit=args.limit,
                latest_profile_only=not args.all_history,
            )
            if args.format == "table":
                rows = []
                rows.extend({"section": "tool", **row} for row in report["tools"])
                rows.extend({"section": "skipped", **row} for row in report["skipped"])
                rows.extend({"section": "failed_job", **row} for row in report["failed_jobs"])
                rows.extend({"section": "extraction_caveat", **row} for row in report["extraction_caveats"])
            else:
                rows = report["tools"]
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"Artifact completeness for case {args.case_id}",
                columns=[
                    "section",
                    "tool_name",
                    "source_scopes",
                    "failed_source_scopes",
                    "not_present_source_scopes",
                    "extraction_caveat_source_scopes",
                    "job_count",
                    "successful_jobs",
                    "failed_jobs",
                    "not_present_jobs",
                    "extraction_caveat_jobs",
                    "output_count",
                    "imported_row_count",
                    "warning_count",
                    "error_count",
                    "skipped_count",
                    "event",
                    "message",
                    "count",
                    "source_scope",
                    "target",
                    "caveat_type",
                    "error",
                    "exit_code",
                    "stderr_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "evidence-quality":
            report = evidence_quality_report(
                db,
                args.case_id,
                limit=args.limit,
                latest_profile_only=not args.all_history,
            )
            write_report_output(
                report,
                report["findings"],
                args.format,
                args.output,
                title=f"Evidence quality findings for case {args.case_id}",
                columns=["severity", "category", "title", "details"],
            )
            return 0

        if args.resource == "report" and args.action == "prefetch":
            print_json(prefetch_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "cd-burning":
            report = cd_burning_activity_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(cd_burning_activity_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["items"],
                    args.format,
                    args.output,
                    title=f"CD/DVD burning activity for case {args.case_id}",
                    columns=[
                        "timestamp_utc",
                        "indicator",
                        "source_table",
                        "operation",
                        "reason",
                        "file_name",
                        "display_path",
                        "source_file",
                        "row_number",
                    ],
                )
            return 0

        if args.resource == "report" and args.action == "mft":
            print_json(mft_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "ntfs-index":
            print_json(ntfs_index_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "ntfs-logfile":
            print_json(ntfs_logfile_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "ntfs-namespace":
            print_json(ntfs_namespace_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "filesystem-review":
            print_json(
                filesystem_review_report(
                    db,
                    args.case_id,
                    contains=args.contains,
                    event_type=args.event_type,
                    status=args.status,
                    source_table=args.source_table,
                    limit=args.limit,
                )
            )
            return 0

        if args.resource == "report" and args.action == "user-file-references":
            report = user_file_references_report(
                db,
                args.case_id,
                provider=args.provider,
                scope=args.scope,
                user=args.user,
                contains=args.contains,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["user_file_references"],
                args.format,
                args.output,
                title=f"User-controlled file references for case {args.case_id}",
                columns=[
                    "event_time_utc",
                    "storage_provider",
                    "path_scope",
                    "owning_user",
                    "artifact_meaning",
                    "display_path",
                    "resolved_provider_path",
                    "resolution_status",
                    "normalized_path",
                    "source_table",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "user-file-reference-source":
            write_text_output(
                json.dumps(
                    user_file_reference_source_report(
                        db,
                        args.case_id,
                        reference_id=args.reference_id,
                    ),
                    indent=2,
                    default=str,
                ),
                args.output,
            )
            return 0

        if args.resource == "report" and args.action == "usn":
            print_json(usn_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usn-summary":
            print_json(usn_summary_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usn-path":
            print_json(usn_path_report(db, args.case_id, contains=args.contains, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usn-user":
            print_json(usn_user_report(db, args.case_id, user=args.user, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usn-reasons":
            print_json(usn_reasons_report(db, args.case_id, reason=args.reason, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usn-timeline":
            print_json(
                usn_timeline_report(
                    db,
                    args.case_id,
                    user=args.user,
                    path_contains=args.contains,
                    reason=args.reason,
                    limit=args.limit,
                )
            )
            return 0

        if args.resource == "report" and args.action == "usn-suspicious":
            print_json(usn_suspicious_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usn-user-files":
            print_json(
                usn_user_files_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    rules_path=args.rules,
                    include_suppressed=args.include_suppressed,
                )
            )
            return 0

        if args.resource == "report" and args.action == "usn-renames":
            print_json(usn_rename_pairs_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usn-bursts":
            print_json(usn_bursts_report(db, args.case_id, minutes=args.minutes, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usn-usb-candidates":
            print_json(usn_usb_candidates_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "sdelete":
            print_json(sdelete_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "srum":
            print_json(srum_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "ual":
            report = ual_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["timeline"],
                args.format,
                args.output,
                title=f"UAL/SUM access timeline for case {args.case_id}",
                columns=[
                    "event_time_utc",
                    "event_type",
                    "role_name",
                    "product_name",
                    "user_name",
                    "user_sid",
                    "client_name",
                    "client_ip",
                    "access_count",
                    "activity_count",
                    "database_file",
                    "source_table",
                    "source_csv",
                    "row_number",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "srum-networks":
            report = srum_networks_report(db, args.case_id, include_zero=args.include_zero, limit=args.limit)
            write_report_output(
                report,
                report["networks"],
                args.format,
                args.output,
                title=f"SRUM connected networks for case {args.case_id}",
                columns=[
                    "network_name",
                    "connection_type",
                    "vpn_server",
                    "vpn_device",
                    "vpn_protocol",
                    "first_connected_utc",
                    "last_observed_utc",
                    "max_connected_seconds",
                    "observation_count",
                    "users",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "srum-app-usage":
            report = srum_app_network_usage_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["applications"],
                args.format,
                args.output,
                title=f"SRUM application network usage for case {args.case_id}",
                columns=[
                    "application",
                    "user_name",
                    "network_name",
                    "total_bytes_received",
                    "total_bytes_sent",
                    "total_bytes",
                    "first_observed_utc",
                    "last_observed_utc",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "srum-context":
            report = srum_context_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["items"],
                args.format,
                args.output,
                title=f"SRUM contextual activity for case {args.case_id}",
                columns=[
                    "event_time_utc",
                    "context",
                    "record_type",
                    "app_name",
                    "app_path",
                    "user_name",
                    "l2_profile_name",
                    "vpn_profile_name",
                    "vpn_server",
                    "total_bytes",
                    "connected_time",
                    "source_table",
                    "source_csv",
                    "row_number",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "vpn-activity":
            report = vpn_activity_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["vpn_activity"],
                args.format,
                args.output,
                title=f"VPN activity for case {args.case_id}",
                columns=[
                    "event_time_utc",
                    "source_type",
                    "activity_type",
                    "profile_name",
                    "server",
                    "protocol",
                    "event",
                    "user",
                    "path_or_process",
                    "source_file",
                ],
            )
            return 0

        if args.resource == "report" and args.action in {"vpn-connections", "vpn-config", "vpn-execution"}:
            report_fn = {
                "vpn-connections": vpn_connections_report,
                "vpn-config": vpn_config_report,
                "vpn-execution": vpn_execution_report,
            }[args.action]
            key = args.action.replace("-", "_")
            report = report_fn(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report[key],
                args.format,
                args.output,
                title=f"{args.action} for case {args.case_id}",
                columns=[
                    "event_time_utc",
                    "source_type",
                    "activity_type",
                    "profile_name",
                    "server",
                    "protocol",
                    "event",
                    "user",
                    "path_or_process",
                    "source_file",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "vpn-local-activity":
            report = vpn_local_activity_report(
                db,
                args.case_id,
                limit=args.limit,
                padding_minutes=args.padding_minutes,
            )
            if args.format == "md":
                write_text_output(vpn_local_activity_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["activity_rows"],
                    args.format,
                    args.output,
                    title=f"Local activity during VPN windows for case {args.case_id}",
                    columns=[
                        "vpn_window_index",
                        "event_time_utc",
                        "activity_category",
                        "source_table",
                        "description",
                        "application",
                        "path",
                        "source_file",
                        "row_number",
                    ],
                )
            return 0

        if args.resource == "report" and args.action == "vpn-sessions":
            report = vpn_session_evidence_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["vpn_sessions"],
                args.format,
                args.output,
                title=f"VPN session evidence for case {args.case_id}",
                columns=[
                    "first_observed_utc",
                    "last_observed_utc",
                    "profile_name",
                    "server",
                    "protocol",
                    "activity_types",
                    "source_types",
                    "evidence_count",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "remote-access":
            report = remote_access_sessions_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["remote_access_sessions"],
                args.format,
                args.output,
                title=f"Remote access sessions for case {args.case_id}",
                columns=[
                    "start_time_utc",
                    "connected_time_utc",
                    "end_time_utc",
                    "client_computer",
                    "remote_host",
                    "remote_ip",
                    "domain",
                    "disconnect_reason",
                    "vpn_event_count",
                    "vpn_servers",
                    "vpn_profiles",
                    "rdp_cache_file_count",
                    "rdp_visual_observation_count",
                    "correlation_basis",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "remote-access-attribution":
            report = remote_access_attribution_report(
                db,
                args.case_id,
                start=args.start,
                end=args.end,
                label=args.label,
                remote=args.remote,
                contains=args.contains,
                limit=args.limit,
            )
            if args.format == "md":
                write_text_output(remote_access_attribution_markdown(report), args.output)
            else:
                write_report_output(
                    report,
                    report["remote_access_windows"],
                    args.format,
                    args.output,
                    title=f"Remote access attribution windows for case {args.case_id}",
                    columns=[
                        "window_number",
                        "window_start_utc",
                        "window_end_utc",
                        "window_type",
                        "remote_source",
                        "remote_ip",
                        "successful_logon_count",
                        "failed_logon_count",
                        "explicit_credential_count",
                        "usb_device_count",
                        "cloud_context_count",
                        "local_activity_count",
                        "attribution_assessment",
                    ],
                )
            return 0

        if args.resource == "report" and args.action == "rdp":
            report = remote_access_sessions_report(db, args.case_id, limit=args.limit)
            if args.format == "json":
                print_json(report)
            else:
                write_text_output(rdp_remote_access_markdown(report), args.output)
            return 0

        if args.resource == "report" and args.action == "windows-search":
            print_json(windows_search_report(db, args.case_id, report_type=args.report_type, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "windows-search-combined":
            report = windows_search_combined_report(db, args.case_id, limit=args.limit)
            if args.format == "md":
                write_text_output(windows_search_combined_markdown(report), args.output)
                return 0
            if args.format == "json":
                print_json(report)
                return 0
            write_report_output(
                report,
                report["combined_artifacts"],
                args.format,
                args.output,
                title=f"Combined Windows Search artifacts for case {args.case_id}",
                columns=["source", "artifact_type", "timestamp", "path", "name", "status", "details"],
            )
            return 0

        if args.resource == "report" and args.action == "file-metadata":
            print_json(
                file_metadata_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    extension=args.extension,
                    property_name=args.property_name,
                    path_contains=args.path_contains,
                    source_folder=args.source_folder,
                    tool_name=args.tool_name,
                    user_only=args.user_only,
                    exclude_system=args.exclude_system,
                )
            )
            return 0

        if args.resource == "report" and args.action == "file-metadata-skipped":
            print_json(
                file_metadata_skipped_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    tool_name=args.tool_name,
                    since=args.since,
                    latest=args.latest,
                )
            )
            return 0

        if args.resource == "report" and args.action == "file-metadata-unresolved":
            print_json(
                file_metadata_unresolved_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    tool_name=args.tool_name,
                    since=args.since,
                    latest=args.latest,
                )
            )
            return 0

        if args.resource == "report" and args.action == "file-metadata-skipped-deleted":
            print_json(
                file_metadata_deleted_skipped_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    tool_name=args.tool_name,
                    since=args.since,
                    latest=args.latest,
                )
            )
            return 0

        if args.resource == "report" and args.action == "file-metadata-skipped-orphans":
            print_json(
                file_metadata_live_orphan_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    tool_name=args.tool_name,
                    since=args.since,
                    latest=args.latest,
                )
            )
            return 0

        if args.resource == "report" and args.action == "file-metadata-folders":
            print_json(
                file_metadata_folders_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    depth=args.depth,
                    tool_name=args.tool_name,
                    extension=args.extension,
                    user_only=args.user_only,
                    exclude_system=args.exclude_system,
                )
            )
            return 0

        if args.resource == "report" and args.action == "file-metadata-summary":
            print_json(file_metadata_summary_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "evtx":
            print_json(evtx_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "evtx-recovery":
            print_json(evtx_recovery_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "telemetry-artifacts":
            report = telemetry_artifacts_report(
                db,
                args.case_id,
                artifact_group=args.artifact_group,
                contains=args.contains,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["telemetry_artifacts"],
                args.format,
                args.output,
                title=f"Telemetry artifacts for case {args.case_id}",
                columns=["artifact_group", "record_type", "modified_utc", "event_time_utc", "user_profile", "application", "title", "value_data", "source_path"],
            )
            return 0

        if args.resource == "report" and args.action == "artifact-correlations":
            report = artifact_correlations_report(
                db,
                args.case_id,
                correlation_type=args.correlation_type,
                confidence=args.confidence,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["artifact_correlations"],
                args.format,
                args.output,
                title=f"Artifact correlations for case {args.case_id}",
                columns=[
                    "correlation_type", "confidence", "correlation_key",
                    "left_source_table", "right_source_table", "summary",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "correlation-groups":
            report = correlation_groups_report(
                db,
                args.case_id,
                category=args.category,
                rule_id=args.rule_id,
                contains=args.contains,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["correlation_groups"],
                args.format,
                args.output,
                title=f"Correlation groups for case {args.case_id}",
                columns=[
                    "category",
                    "rule_id",
                    "review_value",
                    "primary_time_utc",
                    "title",
                    "summary",
                    "member_count",
                    "source_tables",
                    "interpretation",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "correlation-group":
            report = correlation_group_detail_report(db, args.case_id, args.group_id)
            rows = []
            if report.get("group"):
                rows.append({"section": "group", **report["group"]})
            rows.extend({"section": "member", **row} for row in report["members"])
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"Correlation group {args.group_id}",
                columns=[
                    "section",
                    "category",
                    "rule_id",
                    "title",
                    "interpretation",
                    "role",
                    "source_table",
                    "source_row_id",
                    "event_time_utc",
                    "user_profile",
                    "path",
                    "application",
                    "description",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "sessions":
            report = sessions_report(
                db,
                args.case_id,
                session_type=args.session_type,
                user=args.user,
                contains=args.contains,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["sessions"],
                args.format,
                args.output,
                title=f"Derived sessions for case {args.case_id}",
                columns=[
                    "session_type",
                    "status",
                    "user_profile",
                    "profile_name",
                    "remote_host",
                    "remote_ip",
                    "start_time_utc",
                    "end_time_utc",
                    "duration_seconds",
                    "evidence_count",
                    "source_tables",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "session":
            report = session_detail_report(db, args.case_id, args.session_id)
            rows = []
            if report.get("session"):
                rows.append({"section": "session", **report["session"]})
            rows.extend({"section": "member", **row} for row in report["members"])
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"Derived session {args.session_id}",
                columns=[
                    "section",
                    "session_type",
                    "status",
                    "source_table",
                    "event_time_utc",
                    "event_type",
                    "description",
                    "user_profile",
                    "remote_host",
                    "remote_ip",
                    "duration_seconds",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "computer-inventory":
            report = computer_inventory_report(
                db,
                args.case_id,
                category=args.category,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["computer_inventory"],
                args.format,
                args.output,
                title=f"Computer inventory for case {args.case_id}",
                columns=["computer_label", "category", "name", "value", "confidence", "source_table"],
            )
            return 0

        if args.resource == "report" and args.action == "recycle":
            print_json(recycle_report(db, args.case_id, user=args.user, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "deleted-folders":
            print_json(deleted_folders_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "firefox":
            print_json(firefox_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "browser":
            print_json(browser_report(db, args.case_id, report_type=args.report_type, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "browser-artifacts":
            report = browser_artifacts_report(
                db,
                args.case_id,
                artifact_type=args.artifact_type,
                browser=args.browser,
                contains=args.contains,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["browser_artifacts"],
                args.format,
                args.output,
                title=f"Browser artifacts for case {args.case_id}",
                columns=[
                    "browser",
                    "artifact_type",
                    "timestamp_utc",
                    "profile_path",
                    "name",
                    "value",
                    "url",
                    "host",
                    "source_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "office-backstage":
            report = office_backstage_report(
                db,
                args.case_id,
                contains=args.contains,
                artifact_type=args.artifact_type,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["office_backstage_items"],
                args.format,
                args.output,
                title=f"Office Backstage artifacts for case {args.case_id}",
                columns=[
                    "artifact_type",
                    "timestamp_utc",
                    "user_profile",
                    "application",
                    "name",
                    "path",
                    "url",
                    "source_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "user-dictionaries":
            report = user_dictionaries_report(
                db,
                args.case_id,
                user=args.user,
                contains=args.contains,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["user_dictionary_words"],
                args.format,
                args.output,
                title=f"User dictionary words for case {args.case_id}",
                columns=[
                    "user_profile",
                    "application",
                    "office_version",
                    "proofing_id",
                    "dictionary_name",
                    "word_index",
                    "word",
                    "timestamp_utc",
                    "source_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "downloaded-files":
            report = downloaded_files_report(
                db,
                args.case_id,
                user=args.user,
                contains=args.contains,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["downloaded_files"],
                args.format,
                args.output,
                title=f"Downloaded files for case {args.case_id}",
                columns=[
                    "user_profile",
                    "timestamp_utc",
                    "file_path",
                    "zone_id",
                    "host_url",
                    "host",
                    "referrer_url",
                    "referrer_host",
                    "source_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "uninstalled-app-artifacts":
            report = uninstalled_application_artifacts_report(
                db,
                args.case_id,
                application=args.application,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["uninstalled_application_artifacts"],
                args.format,
                args.output,
                title=f"Possible uninstalled application artifacts for case {args.case_id}",
                columns=["application", "status", "source_table", "event_time_utc", "user_profile", "name", "path", "matched_token"],
            )
            return 0

        if args.resource == "report" and args.action == "tor-usage":
            report = tor_usage_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["tor_usage"],
                args.format,
                args.output,
                title=f"Tor Browser usage indicators for case {args.case_id}",
                columns=["source_table", "event_time_utc", "user_profile", "name", "path", "matched_token", "evidence_caveat"],
            )
            return 0

        if args.resource == "report" and args.action == "encrypted-volumes":
            report = encrypted_volume_indicators_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["encrypted_volume_indicators"],
                args.format,
                args.output,
                title=f"Encrypted volume indicators for case {args.case_id}",
                columns=["indicator_type", "source_table", "event_time_utc", "user_profile", "name", "path", "matched_token"],
            )
            return 0

        if args.resource == "report" and args.action == "phone-link":
            report = phone_link_report(
                db,
                args.case_id,
                record_type=args.record_type,
                user=args.user,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["phone_link_artifacts"],
                args.format,
                args.output,
                title=f"Microsoft Phone Link artifacts for case {args.case_id}",
                columns=[
                    "record_type", "user_profile", "event_time_utc", "title",
                    "artifact_value", "artifact_text", "source_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "virtualization":
            report = virtualization_indicators_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["virtualization_indicators"],
                args.format,
                args.output,
                title=f"Virtualization indicators for case {args.case_id}",
                columns=["platform", "source_table", "event_time_utc", "user_profile", "name", "path", "matched_token"],
            )
            return 0

        if args.resource == "report" and args.action == "rdp-cache":
            report = rdp_cache_report(
                db,
                args.case_id,
                user=args.user,
                record_type=args.record_type,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["rdp_cache"],
                args.format,
                args.output,
                title=f"RDP bitmap cache entries for case {args.case_id}",
                columns=[
                    "user_profile",
                    "record_type",
                    "file_name",
                    "parser_status",
                    "fragment_index",
                    "width",
                    "height",
                    "image_format",
                    "source_cache_path",
                    "fragment_path",
                    "contact_sheet_path",
                    "parser_note",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "rdp-visual-observations":
            report = rdp_visual_observations_report(
                db,
                args.case_id,
                user=args.user,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["rdp_visual_observations"],
                args.format,
                args.output,
                title=f"RDP visual observations for case {args.case_id}",
                columns=[
                    "observation_time_utc",
                    "user_profile",
                    "observed_application",
                    "observation_type",
                    "observed_text",
                    "observed_path",
                    "certainty",
                    "time_basis",
                    "source_cache_path",
                    "contact_sheet_path",
                    "caveat",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "image-analysis":
            report = image_analysis_report(
                db,
                args.case_id,
                source_artifact_type=args.source_artifact_type,
                contains=args.contains,
                ocr_only=args.ocr_only,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["image_analysis"],
                args.format,
                args.output,
                title=f"Image analysis items for case {args.case_id}",
                columns=[
                    "source_artifact_type",
                    "analysis_type",
                    "file_name",
                    "width",
                    "height",
                    "image_format",
                    "ocr_status",
                    "classifier_status",
                    "source_path",
                    "output_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "browser-downloads":
            report = browser_downloads_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["downloads"],
                args.format,
                args.output,
                title=f"Browser downloads for case {args.case_id}",
                columns=["browser", "profile_path", "start_time_utc", "end_time_utc", "target_path", "tab_url", "site_url", "mft_matches", "usb_file_matches"],
            )
            return 0

        if args.resource == "report" and args.action == "browser-cache":
            report = browser_cache_report(
                db,
                args.case_id,
                limit=args.limit,
                browser=args.browser,
                host=args.host,
                exclude_noise=args.exclude_noise,
            )
            write_report_output(
                report,
                report["cache_entries"],
                args.format,
                args.output,
                title=f"Browser cache URL references for case {args.case_id}",
                columns=["browser", "profile_path", "cache_type", "cache_file_modified_utc", "host", "url", "cache_file_size"],
            )
            return 0

        if args.resource == "report" and args.action == "browser-hosts":
            report = browser_hosts_report(
                db,
                args.case_id,
                limit=args.limit,
                browser=args.browser,
                exclude_noise=args.exclude_noise,
            )
            write_report_output(
                report,
                report["hosts"],
                args.format,
                args.output,
                title=f"Browser hosts for case {args.case_id}",
                columns=["browser", "profile_path", "host", "reference_count", "first_seen_utc", "last_seen_utc", "sources"],
            )
            return 0

        if args.resource == "report" and args.action == "browser-cache-correlations":
            report = browser_cache_correlations_report(
                db,
                args.case_id,
                limit=args.limit,
                browser=args.browser,
                exclude_noise=not args.include_noise,
            )
            write_report_output(
                report,
                report["correlations"],
                args.format,
                args.output,
                title=f"Browser cache correlations for case {args.case_id}",
                columns=["browser", "profile_path", "host", "interpretation", "cache_reference_count", "history_count", "download_count", "first_cache_utc", "last_cache_utc"],
            )
            return 0

        if args.resource == "report" and args.action == "browser-activity":
            report = browser_activity_report(
                db,
                args.case_id,
                limit=args.limit,
                browser=args.browser,
                user=args.user,
                exclude_noise=not args.include_noise,
            )
            rows = report["top_hosts"]
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"Browser activity summary for case {args.case_id}",
                columns=["browser", "profile_path", "host", "reference_count", "first_seen_utc", "last_seen_utc", "sources"],
            )
            return 0

        if args.resource == "report" and args.action == "browser-profile-activity":
            report = browser_profile_activity_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["profiles"],
                args.format,
                args.output,
                title=f"Browser profile activity for case {args.case_id}",
                columns=["browser", "profile_path", "artifact_count", "history_count", "download_count", "session_count", "site_setting_count", "notification_count", "cache_count", "first_seen_utc", "last_seen_utc", "artifact_types"],
            )
            return 0

        if args.resource == "report" and args.action == "browser-deep-storage":
            report = browser_deep_storage_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["items"],
                args.format,
                args.output,
                title=f"Browser deep-storage inventory for case {args.case_id}",
                columns=[
                    "event_time_utc",
                    "classification",
                    "source_table",
                    "storage_type",
                    "browser",
                    "profile_path",
                    "host",
                    "url",
                    "name",
                    "source_path",
                    "source_csv",
                    "row_number",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "windows-activities":
            report = windows_activities_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
                app=args.app,
                include_auxiliary=args.include_auxiliary,
                files_only=args.files_only,
            )
            write_report_output(
                report,
                report["activities"],
                args.format,
                args.output,
                title=f"Windows Activities for case {args.case_id}",
                columns=["user_profile", "app_display_name", "activity_type", "start_time_utc", "end_time_utc", "file_name", "display_text", "content_uri", "activation_uri", "fallback_uri"],
            )
            return 0

        if args.resource == "report" and args.action == "webcache":
            report = webcache_report(
                db,
                args.case_id,
                limit=args.limit,
                application=args.application,
                user=args.user,
                local_files_only=args.local_files_only,
                exclude_metadata=args.exclude_metadata,
            )
            rows = report["file_accesses"] if args.local_files_only else report["webcache_entries"]
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"WebCache entries for case {args.case_id}",
                columns=["user_name", "application", "attribution_method", "accessed_utc", "modified_utc", "container_name", "url", "host"],
            )
            return 0

        if args.resource == "report" and args.action == "webcache-files":
            report = webcache_files_report(
                db,
                args.case_id,
                limit=args.limit,
                application=args.application,
                user=args.user,
                usb_overlap=args.usb_overlap,
            )
            write_report_output(
                report,
                report["file_accesses"],
                args.format,
                args.output,
                title=f"WebCache local file accesses for case {args.case_id}",
                columns=["user_name", "application", "accessed_utc", "modified_utc", "local_path", "container_name", "usb_overlaps"],
            )
            return 0

        if args.resource == "report" and args.action == "cloud-artifacts":
            report = cloud_artifacts_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["cloud_artifacts"],
                args.format,
                args.output,
                title=f"Cloud artifacts for case {args.case_id}",
                columns=["provider", "source", "artifact_path", "file_name", "application", "accessed_utc", "modified_utc", "evidence_tags"],
            )
            return 0

        if args.resource == "report" and args.action == "cloud-files":
            report = cloud_files_report(
                db,
                args.case_id,
                provider=args.provider,
                include_deleted=not args.exclude_deleted,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["cloud_files"],
                args.format,
                args.output,
                title=f"Cloud files for case {args.case_id}",
                columns=["provider", "source_table", "user_profile", "event_time_utc", "cloud_path", "local_path", "file_name", "file_id", "stable_id", "file_size", "is_deleted", "sync_status", "event_type"],
            )
            return 0

        if args.resource == "report" and args.action == "cloud-configuration":
            report = cloud_configuration_report(
                db,
                args.case_id,
                provider=args.provider,
                user=args.user,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["cloud_configuration"],
                args.format,
                args.output,
                title=f"Cloud configuration for case {args.case_id}",
                columns=["provider", "config_type", "user_profile", "artifact", "key_path", "value_name", "value_preview", "key_last_write_utc", "source_path", "source_csv", "row_number"],
            )
            return 0

        if args.resource == "report" and args.action == "web-cloud-correlations":
            report = web_cloud_correlations_report(
                db,
                args.case_id,
                provider=args.provider,
                category=args.category,
                user=args.user,
                contains=args.contains,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["web_cloud_correlations"],
                args.format,
                args.output,
                title=f"Web/cloud correlations for case {args.case_id}",
                columns=[
                    "provider", "category", "evidence_type", "source_table",
                    "user_profile", "timestamp", "host", "title", "path", "summary",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "email-artifacts":
            report = email_artifacts_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["email_artifacts"],
                args.format,
                args.output,
                title=f"Email artifacts for case {args.case_id}",
                columns=["source", "name", "email", "timestamp", "extension", "path", "dedupe_key"],
            )
            return 0

        if args.resource == "report" and args.action == "mailbox-messages":
            report = mailbox_messages_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
                status=args.status,
                contains=args.contains,
            )
            write_report_output(
                report,
                report["mailbox_messages"],
                args.format,
                args.output,
                title=f"Mailbox messages for case {args.case_id}",
                columns=[
                    "message_date_utc",
                    "parser_status",
                    "user_profile",
                    "user_sid",
                    "source_format",
                    "subject",
                    "sender",
                    "recipients",
                    "container_path",
                    "attachment_count",
                    "dedupe_key",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "mailbox-attachments":
            report = mailbox_attachments_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
                status=args.status,
                content_type=args.content_type,
                sha256=args.sha256,
                contains=args.contains,
            )
            write_report_output(
                report,
                report["mailbox_attachments"],
                args.format,
                args.output,
                title=f"Mailbox attachments for case {args.case_id}",
                columns=[
                    "message_date_utc",
                    "user_profile",
                    "subject",
                    "sender",
                    "attachment_name",
                    "content_type",
                    "size",
                    "sha256",
                    "extraction_status",
                    "attachment_path",
                    "container_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "mailbox-attachment-coverage":
            report = mailbox_attachment_coverage_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
            )
            if args.format == "table":
                rows = []
                rows.extend({"section": "status", **row} for row in report["by_status"])
                rows.extend({"section": "content_type", **row} for row in report["by_content_type"])
                rows.extend({"section": "issue", **row} for row in report["issues"])
            else:
                rows = report["issues"]
            write_report_output(
                report,
                rows,
                args.format,
                args.output,
                title=f"Mailbox attachment coverage for case {args.case_id}",
                columns=[
                    "section",
                    "extraction_status",
                    "content_type",
                    "attachment_count",
                    "with_extracted_text",
                    "with_metadata",
                    "with_errors",
                    "message_date_utc",
                    "user_profile",
                    "subject",
                    "attachment_name",
                    "parser_error",
                    "attachment_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "mailbox-attachment-copies":
            report = mailbox_attachment_copies_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
                contains=args.contains,
            )
            write_report_output(
                report,
                report["mailbox_attachment_copies"],
                args.format,
                args.output,
                title=f"Mailbox attachment copies for case {args.case_id}",
                columns=[
                    "attachment_count",
                    "message_count",
                    "container_count",
                    "first_seen",
                    "last_seen",
                    "attachment_name",
                    "content_type",
                    "size",
                    "sha256",
                    "users",
                    "subjects",
                    "container_paths",
                    "attachment_copy_key",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "mailbox-copies":
            report = mailbox_message_copies_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
                contains=args.contains,
            )
            write_report_output(
                report,
                report["mailbox_message_copies"],
                args.format,
                args.output,
                title=f"Mailbox message copies for case {args.case_id}",
                columns=[
                    "message_date_utc",
                    "subject",
                    "sender",
                    "recipients",
                    "message_count",
                    "container_count",
                    "users",
                    "user_sids",
                    "container_paths",
                    "dedupe_key",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "communications":
            report = communications_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
                contains=args.contains,
                source_type=args.source_type,
                include_low_value=args.include_low_value,
            )
            write_report_output(
                report,
                report["communications"],
                args.format,
                args.output,
                title=f"Communications for case {args.case_id}",
                columns=[
                    "timestamp",
                    "source_type",
                    "user_profile",
                    "sender",
                    "recipients",
                    "title",
                    "preview",
                    "review_value",
                    "related_windows_search_count",
                    "related_mailbox_message_count",
                    "communication_key",
                    "source_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "communication-groups":
            report = communication_groups_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
                contains=args.contains,
                source_type=args.source_type,
                include_low_value=args.include_low_value,
            )
            write_report_output(
                report,
                report["communication_groups"],
                args.format,
                args.output,
                title=f"Communication groups for case {args.case_id}",
                columns=[
                    "count",
                    "source_types",
                    "users",
                    "first_seen",
                    "last_seen",
                    "titles",
                    "communication_key",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "communication-review":
            report = communication_review_report(
                db,
                args.case_id,
                view=args.view,
                limit=args.limit,
                user=args.user,
                contains=args.contains,
                include_low_value=args.include_low_value,
            )
            columns_by_view = {
                "conversations": [
                    "message_count",
                    "attachment_count",
                    "first_seen",
                    "last_seen",
                    "subject",
                    "users",
                    "senders",
                    "recipients",
                    "source_formats",
                    "container_paths",
                    "conversation_key",
                ],
                "pairs": [
                    "message_count",
                    "first_seen",
                    "last_seen",
                    "sender",
                    "recipient",
                    "users",
                    "subjects",
                    "container_paths",
                ],
                "attachments": [
                    "message_date_utc",
                    "user_profile",
                    "subject",
                    "sender",
                    "recipients",
                    "attachment_name",
                    "content_type",
                    "size",
                    "sha256",
                    "extraction_status",
                    "has_extracted_text",
                    "has_metadata",
                    "attachment_path",
                ],
                "indexed-only": [
                    "timestamp",
                    "user_profile",
                    "item_name",
                    "item_type",
                    "content_field",
                    "preview",
                    "item_path",
                ],
                "recovered-fragments": [
                    "timestamp",
                    "source_type",
                    "user_profile",
                    "title",
                    "preview",
                    "review_value",
                    "related_windows_search_count",
                    "related_mailbox_message_count",
                    "source_path",
                ],
            }
            write_report_output(
                report,
                report["communication_review"],
                args.format,
                args.output,
                title=f"Communication {args.view} review for case {args.case_id}",
                columns=columns_by_view[args.view],
            )
            return 0

        if args.resource == "report" and args.action == "search-index-runs":
            report = search_index_runs_report(db, args.case_id, limit=args.limit)
            write_report_output(
                report,
                report["search_index_runs"],
                args.format,
                args.output,
                title=f"Search index runs for case {args.case_id}",
                columns=[
                    "started_at",
                    "status",
                    "backend",
                    "backend_url",
                    "index_name",
                    "backend_version",
                    "document_count",
                    "batch_count",
                    "source_counts_json",
                    "error",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "messaging-artifacts":
            report = messaging_artifacts_report(
                db,
                args.case_id,
                limit=args.limit,
                application=args.application,
                artifact_type=args.artifact_type,
                user=args.user,
                contains=args.contains,
            )
            write_report_output(
                report,
                report["messaging_artifacts"],
                args.format,
                args.output,
                title=f"Messaging artifacts for case {args.case_id}",
                columns=[
                    "application",
                    "user_profile",
                    "artifact_type",
                    "record_type",
                    "record_key",
                    "timestamp_utc",
                    "email",
                    "host",
                    "url",
                    "message_text",
                    "artifact_path",
                    "evidence_tags",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "messaging-messages":
            report = messaging_messages_report(
                db,
                args.case_id,
                limit=args.limit,
                application=args.application,
                user=args.user,
                contains=args.contains,
            )
            write_report_output(
                report,
                report["messaging_messages"],
                args.format,
                args.output,
                title=f"Structured messaging messages for case {args.case_id}",
                columns=[
                    "application",
                    "timestamp_utc",
                    "user_profile",
                    "sender_name",
                    "sender_email",
                    "conversation_id",
                    "channel_id",
                    "message_type",
                    "message_text",
                    "url",
                    "parser_confidence",
                    "source_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "event-interpretation":
            report = event_interpretation_report(
                db,
                args.case_id,
                category=args.category,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["events"],
                args.format,
                args.output,
                title=f"Event interpretation for case {args.case_id}",
                columns=["time_created", "category", "event_id", "channel", "provider", "user_name", "summary", "evidence_tags"],
            )
            return 0

        if args.resource == "report" and args.action == "timeline":
            print_json(
                timeline_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    event_type=args.event_type,
                    source_tool=args.source_tool,
                    contains=args.contains,
                )
            )
            return 0

        if args.resource == "report" and args.action == "timeline-sources":
            report = timeline_sources_report(
                db,
                args.case_id,
                limit=args.limit,
                source_scope=args.source_scope,
            )
            write_report_output(
                report,
                report["sources"],
                args.format,
                args.output,
                title=f"Timeline dedupe sources for case {args.case_id}",
                columns=[
                    "primary_timestamp_utc",
                    "primary_event_type",
                    "primary_description",
                    "source_scope",
                    "source_tool",
                    "source_table",
                    "source_timestamp_utc",
                    "source_description",
                    "tool_output_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "artifact-sources":
            report = artifact_sources_report(
                db,
                args.case_id,
                limit=args.limit,
                artifact_family=args.artifact_family,
                source_scope=args.source_scope,
            )
            write_report_output(
                report,
                report["sources"],
                args.format,
                args.output,
                title=f"Artifact dedupe sources for case {args.case_id}",
                columns=[
                    "artifact_family",
                    "primary_table",
                    "primary_row_id",
                    "source_scope",
                    "duplicate_table",
                    "duplicate_row_id",
                    "source_tool",
                    "source_output_path",
                    "match_key",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "timeline-review":
            report = timeline_review_report(
                db,
                args.case_id,
                limit=args.limit,
                user=args.user,
                contains=args.contains,
                source=args.source,
                preset=args.preset,
            )
            write_report_output(
                report,
                report["events"],
                args.format,
                args.output,
                title=f"Timeline review for case {args.case_id}",
                columns=[
                    "timestamp",
                    "user",
                    "source",
                    "event_type",
                    "file_path",
                    "artifact",
                    "summary",
                    "confidence_basis",
                    "source_table",
                    "source_record_id",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "user-timeline":
            report = user_timeline_report(
                db,
                args.case_id,
                user=args.user,
                limit=args.limit,
                include_expiry=args.include_expiry,
                include_metadata=args.include_metadata,
            )
            write_report_output(
                report,
                report["events"],
                args.format,
                args.output,
                title=f"User timeline for {args.user} in case {args.case_id}",
                columns=["timestamp_utc", "event_type", "source_tool", "source_table", "description", "details"],
            )
            return 0

        if args.resource == "report" and args.action == "validate":
            print_json(validation_report(db, args.case_id))
            return 0

        if args.resource == "report" and args.action == "operation-manifest":
            print_json(operation_manifest_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "db-storage":
            print_json(
                database_storage_report(
                    db,
                    args.case_id,
                    limit=args.limit,
                    include_object_sizes=args.include_object_sizes,
                )
            )
            return 0

        if args.resource == "report" and args.action == "cleanup-candidates":
            print_json(cleanup_candidates_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "registry":
            print_json(registry_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "amcache":
            print_json(amcache_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "shimcache":
            print_json(shimcache_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "shellbags":
            print_json(shellbags_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "usb":
            if args.breakdown:
                print_json(usb_breakdown_report(db, args.case_id))
                return 0
            print_json(usb_report(db, args.case_id, limit=args.limit, raw=args.raw))
            return 0

        if args.resource == "report" and args.action == "external-storage":
            report = external_storage_report(db, args.case_id, limit=args.limit)
            rows = (
                [{"section": "device", **row} for row in report["devices"]]
                + [{"section": "file_activity", **row} for row in report["file_activity"]]
                + [{"section": "timeline", **row} for row in report["timeline"]]
                + [{"section": "event_log", **row} for row in report["event_log_observations"]]
            )
            if args.format == "md":
                write_text_output(external_storage_markdown(report), args.output)
            elif args.format == "json":
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            elif args.format == "csv":
                write_csv_rows(rows, args.output)
            else:
                write_report_output(
                    report,
                    rows,
                    args.format,
                    args.output,
                    title=f"External storage report for case {args.case_id}",
                    columns=[
                        "section",
                        "serial",
                        "friendly_name",
                        "product",
                        "volume_serial_number",
                        "capacity_bytes",
                        "file_system",
                        "drive_letter",
                        "first_install_date_utc",
                        "last_arrival_utc",
                        "last_removal_utc",
                        "source_artifact_types",
                        "file_location",
                        "first_target_time",
                        "last_target_time",
                        "timestamp",
                        "event_type",
                        "time_created",
                        "provider",
                        "event_id",
                        "description",
                        "confidence",
                    ],
                )
            return 0

        if args.resource == "report" and args.action == "usb-files":
            report = usb_file_correlation_report(db, args.case_id, limit=args.limit, grouped=args.grouped)
            rows = report["files"] if args.grouped else report["items"]
            if args.format == "csv":
                write_csv_rows(rows, args.output)
            elif args.format == "table":
                write_text_output(usb_files_table(report), args.output)
            else:
                text = json.dumps(report, indent=2, default=str)
                write_text_output(text, args.output)
            return 0

        if args.resource == "report" and args.action == "usb-verbose":
            print_json(
                usb_verbose_report(
                    db,
                    args.case_id,
                    serial=args.serial,
                    volume_serial_number=args.volume_serial_number,
                    volume_guid=args.volume_guid,
                    limit=args.limit,
                )
            )
            return 0

        if args.resource == "report" and args.action == "usb-timeline":
            report = usb_timeline_report(db, args.case_id, limit=args.limit)
            if args.format == "csv":
                write_csv_rows(report["events"], args.output)
            elif args.format == "table":
                write_text_output(usb_timeline_table(report), args.output)
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0

        if args.resource == "report" and args.action == "export":
            if args.preset == "usb-summary":
                report = usb_report(db, args.case_id, limit=args.limit)
                write_csv_rows(report["usb_storage_devices"], args.output)
            elif args.preset == "usb-file-correlations":
                report = usb_file_correlation_report(db, args.case_id, limit=args.limit)
                write_csv_rows(report["items"], args.output)
            elif args.preset == "usb-timeline":
                report = usb_timeline_report(db, args.case_id, limit=args.limit)
                write_csv_rows(report["events"], args.output)
            return 0

        if args.resource == "report" and args.action == "registry-artifacts":
            print_json(
                registry_artifacts_report(
                    db,
                    args.case_id,
                    artifact=args.artifact,
                    user=args.user,
                    limit=args.limit,
                )
            )
            return 0

        if args.resource == "report" and args.action == "registry-activity":
            print_json(
                registry_activity_report(
                    db,
                    args.case_id,
                    artifact=args.artifact,
                    user=args.user,
                    limit=args.limit,
                )
            )
            return 0

        if args.resource == "report" and args.action == "office-trust":
            report = office_trust_report(
                db,
                args.case_id,
                user=args.user,
                trust_type=args.trust_type,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["office_trust_records"],
                args.format,
                args.output,
                title=f"Office trust records for case {args.case_id}",
                columns=[
                    "user_profile",
                    "trust_type",
                    "application",
                    "office_version",
                    "path_or_file",
                    "allow_subfolders",
                    "allow_network_location",
                    "permitted_editing",
                    "permitted_macros_or_scripts",
                    "event_time_utc",
                    "key_path",
                    "value_name",
                    "value_data",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "taskbar-feature-usage":
            report = taskbar_feature_usage_report(
                db,
                args.case_id,
                user=args.user,
                feature=args.feature,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["taskbar_feature_usage"],
                args.format,
                args.output,
                title=f"Taskbar feature usage for case {args.case_id}",
                columns=[
                    "user_profile",
                    "feature",
                    "value_name",
                    "usage_count",
                    "event_time_utc",
                    "key_path",
                    "value_data",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "taskbar-pins":
            report = taskbar_pins_report(db, args.case_id, user=args.user, limit=args.limit)
            write_report_output(
                report,
                report["taskbar_pins"],
                args.format,
                args.output,
                title=f"Taskbar pins for case {args.case_id}",
                columns=[
                    "user_profile",
                    "pin_order",
                    "pin_name",
                    "target_hint",
                    "key_last_write_utc",
                    "key_path",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "thumbcache":
            report = thumbcache_report(
                db,
                args.case_id,
                user=args.user,
                confidence=args.confidence,
                limit=args.limit,
            )
            write_report_output(
                report,
                report["thumbcache"],
                args.format,
                args.output,
                title=f"Thumbcache entries for case {args.case_id}",
                columns=[
                    "user_profile",
                    "source_name",
                    "entry_index",
                    "thumbnail_type",
                    "thumbnail_size",
                    "cache_id",
                    "correlation_basis",
                    "confidence",
                    "search_file_name",
                    "search_item_path",
                    "search_date_created",
                    "search_date_modified",
                    "search_date_accessed",
                    "source_mtime_utc",
                ],
            )
            return 0

        if args.resource == "report" and args.action == "common-dialog-items":
            print_json(common_dialog_items_report(db, args.case_id, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "activity-summary":
            print_json(activity_summary_report(db, args.case_id, user=args.user, limit=args.limit))
            return 0

        if args.resource == "report" and args.action == "user-activity":
            report = user_activity_report(db, args.case_id, user=args.user, limit=args.limit)
            if args.format == "table":
                rows = [
                    {"section": "count", "item": key, "value": value}
                    for key, value in report["counts"].items()
                ]
                write_report_output(
                    report,
                    rows,
                    "table",
                    args.output,
                    title=f"User activity for {args.user} in case {args.case_id}",
                    columns=["section", "item", "value"],
                )
            else:
                write_text_output(json.dumps(report, indent=2, default=str), args.output)
            return 0

        if args.resource == "report" and args.action == "shortcuts":
            print_json(shortcuts_report(db, args.case_id, artifact_type=args.artifact_type, limit=args.limit))
            return 0

        raise OrchestratorError("Unsupported command")
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OrchestratorError, KeyError, ValueError) as exc:
        logger.error("command_failed", extra={"error": str(exc)})
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
