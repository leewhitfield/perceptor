from __future__ import annotations

import csv
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.config import default_plugin_path
from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError
from forensic_orchestrator.tools.registry import ToolRegistry, build_tool_command

from .vshadow import VscSnapshot, discover_vsc_snapshots, mount_vsc_snapshot, unmount_vsc
from .vsc_promote import add_vsc_provenance, clear_vsc_rows, promote_deduped_rows


VSC_EVTX_TRIAGE_LOGS = (
    "Application.evtx",
    "Security.evtx",
    "System.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-PowerShell%4Admin.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
    "Microsoft-Windows-RasClient%4Operational.evtx",
    "Microsoft-Windows-VPN%4Operational.evtx",
    "Microsoft-Windows-SMBClient%4Operational.evtx",
    "Microsoft-Windows-SmbClient%4Security.evtx",
    "Microsoft-Windows-SMBServer%4Audit.evtx",
    "Microsoft-Windows-SMBServer%4Security.evtx",
    "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
    "Microsoft-Windows-Bits-Client%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-CodeIntegrity%4Operational.evtx",
    "Microsoft-Windows-AppLocker%4EXE and DLL.evtx",
    "Microsoft-Windows-AppLocker%4MSI and Script.evtx",
    "Microsoft-Windows-Kernel-ShimEngine%4Operational.evtx",
    "Microsoft-Windows-Application-Experience%4Program-Telemetry.evtx",
    "Microsoft-Windows-Application-Experience%4Program-Inventory.evtx",
    "Microsoft-Windows-Partition%4Diagnostic.evtx",
    "Microsoft-Windows-Ntfs%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-WinRM%4Operational.evtx",
    "Microsoft-Windows-GroupPolicy%4Operational.evtx",
    "OAlerts.evtx",
)

EVTX_COLUMNS = [
    "case_id",
    "image_id",
    "snapshot_id",
    "snapshot_index",
    "snapshot_created_utc",
    "id",
    "computer_id",
    "tool_output_id",
    "tool_name",
    "source_csv",
    "row_number",
    "record_number",
    "event_record_id",
    "time_created",
    "event_id",
    "level",
    "provider",
    "channel",
    "process_id",
    "thread_id",
    "computer",
    "user_id",
    "map_description",
    "user_name",
    "remote_host",
    "payload_data1",
    "payload_data2",
    "payload_data3",
    "payload_data4",
    "payload_data5",
    "payload_data6",
    "executable_info",
    "source_file",
    "event_category",
    "record_signature",
    "parsed_at",
]


def run_vsc_evtx_triage_scan(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    snapshot_indexes: list[int] | None = None,
    use_sudo_mount: bool = False,
) -> dict[str, Any]:
    paths.ensure_case_tree(case_id)
    started_at = utc_now()
    inventory = discover_vsc_snapshots(db=db, paths=paths, case_id=case_id, image=image)
    snapshots = [_snapshot_from_payload(item) for item in inventory.get("snapshots", [])]
    if snapshot_indexes:
        wanted = set(snapshot_indexes)
        snapshots = [snapshot for snapshot in snapshots if snapshot.index in wanted]
    if not snapshots:
        raise MountError("No VSC snapshots selected for EVTX triage scan")

    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_evtx_table(conn)
        snapshot_ids = [f"vss{snapshot.index}" for snapshot in snapshots]
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="evtx_events", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        registry = ToolRegistry.from_files([default_plugin_path()])
        snapshot_results: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        for snapshot in snapshots:
            snapshot_id = f"vss{snapshot.index}"
            step_started_at = utc_now()
            try:
                mount = mount_vsc_snapshot(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    snapshot_index=snapshot.index,
                    use_sudo_mount=use_sudo_mount,
                )
                parsed = parse_vsc_evtx_triage_snapshot(
                    paths=paths,
                    registry=registry,
                    case_id=case_id,
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                    mount_path=Path(mount["volume_mount_path"]),
                )
                inserted_rows = _insert_csv_rows(conn, parsed)
                warnings = parsed.get("warnings", [])
                if parsed.get("row_count", 0) and inserted_rows == 0:
                    warnings = [*warnings, f"parser produced {parsed['row_count']} rows but no rows were inserted"]
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "logs_found": parsed["logs_found"],
                        "evtx_rows": inserted_rows,
                        "parser_rows": parsed.get("row_count", 0),
                        "warnings": warnings,
                        "started_at": step_started_at,
                        "ended_at": utc_now(),
                    }
                )
            except Exception as exc:
                failures.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "error": str(exc),
                        "started_at": step_started_at,
                        "ended_at": utc_now(),
                    }
                )
            finally:
                unmount_vsc(paths=paths, case_id=case_id, snapshot_id=snapshot_id, use_sudo_mount=use_sudo_mount)

        sidecar_rows = _snapshot_rows(conn, case_id=case_id, image_id=image.id)
        for row in sidecar_rows:
            row["computer_id"] = image.computer_id or row.get("computer_id") or "vsc"
        promote_deduped_rows(
            db,
            table="evtx_events",
            rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/EvtxECmd") for row in sidecar_rows],
            key_func=lambda row: str(row.get("record_signature") or ""),
        )
        comparison = compare_evtx_snapshots_from_db(
            conn=conn,
            db=db,
            case_id=case_id,
            image_id=image.id,
        )
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "evtx-triage-vsc-comparison.md"
        report_path.write_text(
            _comparison_markdown(comparison, snapshot_results, failures, started_at=started_at, ended_at=ended_at),
            encoding="utf-8",
        )
        authentication = compare_evtx_authentication_from_db(
            conn=conn,
            db=db,
            case_id=case_id,
            image_id=image.id,
        )
        auth_report_path = paths.vsc_reports_dir(case_id) / "evtx-authentication-vsc-comparison.md"
        auth_report_path.write_text(
            _authentication_markdown(authentication, started_at=started_at, ended_at=ended_at),
            encoding="utf-8",
        )
        payload = {
            "case_id": case_id,
            "image_id": image.id,
            "started_at": started_at,
            "ended_at": ended_at,
            "vsc_db_path": str(db_path),
            "report_path": str(report_path),
            "authentication_report_path": str(auth_report_path),
            "snapshot_count": len(snapshots),
            "successful_snapshots": len(snapshot_results),
            "failed_snapshots": len(failures),
            "snapshot_results": snapshot_results,
            "failures": failures,
            "comparison_summary": comparison["summary"],
            "authentication_summary": authentication["summary"],
        }
        _write_json(paths.vsc_work_dir(case_id) / "evtx-triage-scan.json", payload)
        return payload
    finally:
        conn.close()


def parse_vsc_evtx_triage_snapshot(
    *,
    paths: WorkspacePaths,
    registry: ToolRegistry,
    case_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
    mount_path: Path,
) -> dict[str, Any]:
    extract_dir = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / "evtx-triage"
    output = paths.vsc_work_dir(case_id) / "outputs" / snapshot_id / "EvtxECmdTriage"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    if output.exists():
        shutil.rmtree(output)
    extract_dir.mkdir(parents=True, exist_ok=True)
    logs_root = _find_case_insensitive(mount_path, "Windows/System32/winevt/Logs")
    logs_found = 0
    if logs_root is not None:
        lookup = _casefold_children(logs_root)
        for log_name in VSC_EVTX_TRIAGE_LOGS:
            source = lookup.get(log_name.casefold())
            if source is None or not source.is_file():
                continue
            destination = extract_dir / source.name
            try:
                shutil.copyfile(source, destination)
            except OSError:
                continue
            logs_found += 1
    csv_path: Path | None = None
    row_count = 0
    warnings: list[str] = []
    if logs_found:
        tool = registry.get_tool("EvtxECmdTriage")
        output.mkdir(parents=True, exist_ok=True)
        command = build_tool_command(tool, mount=Path("/unused"), output=output, artifacts={"evtx_triage_logs": extract_dir})
        _run_command(command, output)
        csvs = sorted(output.glob("*.csv"))
        if csvs:
            csv_path = csvs[0]
            row_count = _csv_data_row_count(csv_path)
            if row_count == 0:
                warnings.append("EvtxECmd produced an output CSV with zero data rows")
        else:
            warnings.append("EvtxECmd completed but produced no CSV output")
    return {
        "csv_path": csv_path,
        "row_count": row_count,
        "logs_found": len(list(extract_dir.glob("*.evtx"))),
        "warnings": warnings,
        "snapshot": snapshot,
        "snapshot_id": snapshot_id,
        "case_id": case_id,
        "image_id": image_id,
    }


def compare_evtx_snapshots_from_db(
    *,
    conn: duckdb.DuckDBPyConnection,
    db: Database,
    case_id: str,
    image_id: str,
) -> dict[str, Any]:
    case = db.get_case(case_id)
    live_db = case.root / "analytics" / "events.duckdb"
    conn.execute(f"ATTACH IF NOT EXISTS '{str(live_db).replace("'", "''")}' AS live (READ_ONLY)")
    live_signature = _evtx_signature_sql(table_alias="live_row")
    conn.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE live_evtx_signatures AS
        SELECT DISTINCT {live_signature} AS record_signature
        FROM live.evtx_events live_row
        WHERE live_row.case_id = ?
        """,
        [case_id],
    )
    snapshot_counts = conn.execute(
        """
        SELECT snapshot_id, snapshot_index, snapshot_created_utc, COUNT(*) AS row_count
        FROM vsc_evtx_events
        WHERE case_id = ? AND image_id = ?
        GROUP BY snapshot_id, snapshot_index, snapshot_created_utc
        ORDER BY CAST(snapshot_index AS INTEGER)
        """,
        [case_id, image_id],
    ).fetchall()
    by_snapshot = {
        row[0]: {
            "snapshot_id": row[0],
            "snapshot_index": row[1],
            "snapshot_created_utc": row[2] or "",
            "row_count": row[3],
            "unique_not_live_count": 0,
        }
        for row in snapshot_counts
    }
    rows = conn.execute(
        """
        SELECT v.snapshot_id, v.snapshot_index, v.snapshot_created_utc,
               v.event_category, v.time_created, v.event_id, v.provider, v.channel,
               v.map_description, v.user_name, v.remote_host, v.payload_data1,
               v.payload_data2, v.payload_data3, v.executable_info, v.source_file,
               v.record_signature
        FROM vsc_evtx_events v
        WHERE v.case_id = ? AND v.image_id = ? AND COALESCE(v.record_signature, '') != ''
          AND NOT EXISTS (
            SELECT 1 FROM live_evtx_signatures l
            WHERE l.record_signature = v.record_signature
          )
        """,
        [case_id, image_id],
    ).fetchall()
    columns = [desc[0] for desc in conn.description]
    unique: dict[str, dict[str, Any]] = {}
    for values in rows:
        row = dict(zip(columns, values, strict=False))
        summary = by_snapshot.setdefault(
            row["snapshot_id"],
            {
                "snapshot_id": row["snapshot_id"],
                "snapshot_index": row["snapshot_index"],
                "snapshot_created_utc": row.get("snapshot_created_utc") or "",
                "row_count": 0,
                "unique_not_live_count": 0,
            },
        )
        summary["unique_not_live_count"] += 1
        unique.setdefault(row["record_signature"], row)
    unique_findings = sorted(
        unique.values(),
        key=lambda item: (item.get("event_category") or "", item.get("time_created") or "", item.get("event_id") or ""),
    )
    category_counts = Counter(row.get("event_category") or "other" for row in unique_findings)
    channel_counts = Counter(row.get("channel") or _short_evtx_name(row.get("source_file")) for row in unique_findings)
    return {
        "summary": {
            "vsc_evtx_rows": sum(int(row["row_count"]) for row in by_snapshot.values()),
            "unique_vsc_records_not_live": len(unique_findings),
            "category_count": len(category_counts),
            "category_counts": dict(sorted(category_counts.items())),
            "top_channel_counts": dict(channel_counts.most_common(20)),
        },
        "snapshots": sorted(by_snapshot.values(), key=lambda item: int(item["snapshot_index"])),
        "findings": unique_findings,
    }


def compare_evtx_authentication_from_db(
    *,
    conn: duckdb.DuckDBPyConnection,
    db: Database,
    case_id: str,
    image_id: str,
) -> dict[str, Any]:
    case = db.get_case(case_id)
    live_db = case.root / "analytics" / "events.duckdb"
    conn.execute(f"ATTACH IF NOT EXISTS '{str(live_db).replace("'", "''")}' AS live (READ_ONLY)")
    live_signature = _evtx_signature_sql(table_alias="live_row")
    conn.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE live_evtx_signatures AS
        SELECT DISTINCT {live_signature} AS record_signature
        FROM live.evtx_events live_row
        WHERE live_row.case_id = ?
        """,
        [case_id],
    )
    predicate = _authentication_event_predicate("v")
    signature = _evtx_signature_sql(table_alias="v")
    all_counts = conn.execute(
        f"""
        SELECT {_authentication_event_class_sql("v")} AS auth_class,
               v.event_id, COALESCE(NULLIF(v.channel, ''), {_source_log_identity_sql("v")}) AS source_log,
               COUNT(*) AS row_count,
               MIN(v.time_created) AS first_seen_utc,
               MAX(v.time_created) AS last_seen_utc
        FROM vsc_evtx_events v
        WHERE v.case_id = ? AND v.image_id = ? AND ({predicate})
        GROUP BY 1, 2, 3
        ORDER BY row_count DESC, auth_class, event_id
        """,
        [case_id, image_id],
    ).fetchall()
    post_snapshot_rows = conn.execute(
        f"""
        SELECT v.snapshot_id, v.snapshot_created_utc, v.time_created, v.event_id,
               COALESCE(NULLIF(v.channel, ''), {_source_log_identity_sql("v")}) AS source_log,
               v.map_description, v.payload_data1, v.source_file
        FROM vsc_evtx_events v
        WHERE v.case_id = ? AND v.image_id = ? AND ({predicate})
        ORDER BY v.time_created
        """,
        [case_id, image_id],
    ).fetchall()
    post_snapshot_examples: list[dict[str, Any]] = []
    post_snapshot_count = 0
    for row in post_snapshot_rows:
        snapshot_time = _parse_vsc_datetime(row[1])
        event_time = _parse_evtx_datetime(row[2])
        if snapshot_time is None or event_time is None or event_time <= snapshot_time:
            continue
        post_snapshot_count += 1
        if len(post_snapshot_examples) < 8:
            post_snapshot_examples.append(
                {
                    "snapshot_id": row[0],
                    "snapshot_created_utc": row[1],
                    "time_created": row[2],
                    "event_id": row[3],
                    "source_log": row[4],
                    "detail": row[5] or row[6] or "",
                    "source_file": row[7],
                }
            )
    post_snapshot_source_counts = Counter(str(row["source_log"] or "") for row in post_snapshot_examples)
    rows = conn.execute(
        f"""
        SELECT v.snapshot_id, v.snapshot_index, v.snapshot_created_utc,
               {_authentication_event_class_sql("v")} AS auth_class,
               v.time_created, v.event_id, v.provider, v.channel,
               v.map_description, v.user_name, v.remote_host, v.payload_data1,
               v.payload_data2, v.payload_data3, v.payload_data4, v.payload_data5,
               v.payload_data6, v.executable_info, v.source_file, v.record_signature
        FROM vsc_evtx_events v
        WHERE v.case_id = ? AND v.image_id = ? AND ({predicate})
          AND COALESCE(v.record_signature, '') != ''
          AND NOT EXISTS (
            SELECT 1 FROM live_evtx_signatures live_sig
            WHERE live_sig.record_signature = {signature}
          )
        ORDER BY v.time_created, v.snapshot_index, v.event_id
        """,
        [case_id, image_id],
    ).fetchall()
    columns = [desc[0] for desc in conn.description]
    unique: dict[str, dict[str, Any]] = {}
    for values in rows:
        row = dict(zip(columns, values, strict=False))
        unique.setdefault(str(row.get("record_signature") or ""), row)
    findings = sorted(
        unique.values(),
        key=lambda row: (_timestamp_key(row.get("time_created")), str(row.get("event_id") or "")),
    )
    class_counts = Counter(row.get("auth_class") or "other" for row in findings)
    source_counts = Counter(row.get("channel") or _short_evtx_name(row.get("source_file")) for row in findings)
    all_columns = ["auth_class", "event_id", "source_log", "row_count", "first_seen_utc", "last_seen_utc"]
    return {
        "summary": {
            "vsc_auth_session_rows": sum(int(row[3] or 0) for row in all_counts),
            "unique_vsc_auth_session_records_not_live": len(findings),
            "unique_vsc_successful_logon_records_not_live": sum(
                1 for row in findings if row.get("auth_class") in {"successful_logon", "credential_validation", "privileged_logon"}
            ),
            "unique_vsc_rdp_session_records_not_live": sum(
                1 for row in findings if str(row.get("auth_class") or "").startswith("rdp_")
            ),
            "class_counts": dict(sorted(class_counts.items())),
            "top_source_counts": dict(source_counts.most_common(20)),
            "post_snapshot_timestamp_count": post_snapshot_count,
            "post_snapshot_source_counts": dict(post_snapshot_source_counts.most_common(8)),
        },
        "all_vsc_counts": [dict(zip(all_columns, row, strict=False)) for row in all_counts],
        "post_snapshot_timestamp_examples": post_snapshot_examples,
        "findings": findings,
    }


def _insert_csv_rows(conn: duckdb.DuckDBPyConnection, parsed: dict[str, Any]) -> int:
    csv_path = parsed.get("csv_path")
    if not csv_path or parsed.get("row_count", 0) == 0:
        return 0
    snapshot: VscSnapshot = parsed["snapshot"]
    snapshot_id = str(parsed["snapshot_id"])
    csv_literal = str(csv_path).replace("'", "''")
    source_csv = str(csv_path).replace("'", "''")
    case_id = str(parsed["case_id"]).replace("'", "''")
    image_id = str(parsed["image_id"]).replace("'", "''")
    snapshot_created = str(snapshot.created_utc).replace("'", "''")
    parsed_at = utc_now().replace("'", "''")
    record_signature = _evtx_signature_sql(table_alias="normalized")
    event_category = _evtx_category_sql()
    before = conn.execute(
        "SELECT COUNT(*) FROM vsc_evtx_events WHERE case_id = ? AND image_id = ? AND snapshot_id = ?",
        [parsed["case_id"], parsed["image_id"], parsed["snapshot_id"]],
    ).fetchone()[0]
    conn.execute(
        f"""
        INSERT INTO vsc_evtx_events ({', '.join(EVTX_COLUMNS)})
        WITH source AS (
          SELECT row_number() OVER () AS csv_row_number, *
          FROM read_csv_auto('{csv_literal}', header=true, all_varchar=true, ignore_errors=true)
        ),
        normalized_base AS (
          SELECT
            '{case_id}' AS case_id,
            '{image_id}' AS image_id,
            '{snapshot_id}' AS snapshot_id,
            '{snapshot.index}' AS snapshot_index,
            '{snapshot_created}' AS snapshot_created_utc,
            '{snapshot_id}-' || CAST(csv_row_number AS VARCHAR) AS id,
            'vsc' AS computer_id,
            '{snapshot_id}-EvtxECmdTriage' AS tool_output_id,
            'EvtxECmd' AS tool_name,
            '{source_csv}' AS source_csv,
            CAST(csv_row_number AS VARCHAR) AS row_number,
            COALESCE(RecordNumber, '') AS record_number,
            COALESCE(EventRecordId, '') AS event_record_id,
            COALESCE(TimeCreated, '') AS time_created,
            COALESCE(EventId, '') AS event_id,
            COALESCE(Level, '') AS level,
            COALESCE(Provider, '') AS provider,
            COALESCE(Channel, '') AS channel,
            COALESCE(ProcessId, '') AS process_id,
            COALESCE(ThreadId, '') AS thread_id,
            COALESCE(Computer, '') AS computer,
            COALESCE(UserId, '') AS user_id,
            COALESCE(MapDescription, '') AS map_description,
            COALESCE(UserName, '') AS user_name,
            COALESCE(RemoteHost, '') AS remote_host,
            COALESCE(PayloadData1, '') AS payload_data1,
            COALESCE(PayloadData2, '') AS payload_data2,
            COALESCE(PayloadData3, '') AS payload_data3,
            COALESCE(PayloadData4, '') AS payload_data4,
            COALESCE(PayloadData5, '') AS payload_data5,
            COALESCE(PayloadData6, '') AS payload_data6,
            COALESCE(ExecutableInfo, '') AS executable_info,
            COALESCE(SourceFile, '') AS source_file,
            {event_category} AS event_category,
            '{parsed_at}' AS parsed_at
          FROM source
        ),
        normalized AS (
          SELECT *,
                 {record_signature} AS record_signature
          FROM normalized_base normalized
        )
        SELECT {', '.join(EVTX_COLUMNS)} FROM normalized
        """
    )
    after = conn.execute(
        "SELECT COUNT(*) FROM vsc_evtx_events WHERE case_id = ? AND image_id = ? AND snapshot_id = ?",
        [parsed["case_id"], parsed["image_id"], parsed["snapshot_id"]],
    ).fetchone()[0]
    return int(after) - int(before)


def _ensure_evtx_table(conn: duckdb.DuckDBPyConnection) -> None:
    column_defs = ", ".join(f"{column} VARCHAR" for column in EVTX_COLUMNS)
    conn.execute(f"CREATE TABLE IF NOT EXISTS vsc_evtx_events ({column_defs})")
    existing = {row[1] for row in conn.execute("PRAGMA table_info('vsc_evtx_events')").fetchall()}
    for column in EVTX_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE vsc_evtx_events ADD COLUMN {column} VARCHAR")


def _clear_snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str, snapshot_ids: list[str]) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    conn.execute(
        f"DELETE FROM vsc_evtx_events WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
        [case_id, image_id, *snapshot_ids],
    )


def _snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM vsc_evtx_events WHERE case_id = ? AND image_id = ?",
        [case_id, image_id],
    ).fetchall()
    columns = [desc[0] for desc in conn.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def _comparison_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC EVTX Triage Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC EVTX rows parsed: {summary['vsc_evtx_rows']}",
        f"- Unique VSC records not present live: {summary['unique_vsc_records_not_live']}",
        f"- Categories with VSC-only records: {summary['category_count']}",
        "- This scan uses a targeted EVTX allowlist, not every event log.",
        "",
        "## Category Counts",
        "",
        "| Category | Unique not live |",
        "| --- | ---: |",
    ]
    for category, count in summary["category_counts"].items():
        lines.append(f"| `{category}` | {count} |")
    lines.extend(["", "## Top Channels", "", "| Channel | Unique not live |", "| --- | ---: |"])
    for channel, count in summary["top_channel_counts"].items():
        lines.append(f"| `{_md(channel)}` | {count} |")
    lines.extend(["", "## Snapshot Counts", "", "| Snapshot | Created | Logs | Rows | Unique not live |", "| --- | --- | ---: | ---: | ---: |"])
    unique_by_snapshot = {row["snapshot_id"]: row["unique_not_live_count"] for row in comparison["snapshots"]}
    for result in snapshot_results:
        lines.append(
            f"| {result['snapshot_id']} | {result['snapshot_created_utc']} | {result['logs_found']} | "
            f"{result['evtx_rows']} | {unique_by_snapshot.get(result['snapshot_id'], 0)} |"
        )
    lines.extend(["", "## Examples", "", "| Category | Snapshot | Time | Event | Source | Detail |", "| --- | --- | --- | --- | --- | --- |"])
    for finding in comparison["findings"][:80]:
        event = f"{finding.get('event_id') or ''} {finding.get('provider') or ''}".strip()
        source = finding.get("channel") or _short_evtx_name(finding.get("source_file"))
        detail = finding.get("map_description") or finding.get("payload_data1") or finding.get("executable_info") or finding.get("remote_host") or ""
        lines.append(
            f"| `{finding.get('event_category') or 'other'}` | {finding['snapshot_id']} | {finding.get('time_created') or ''} | "
            f"`{_md(event)}` | `{_md(source)}` | `{_md(detail)}` |"
        )
    if failures:
        lines.extend(["", "## Failures", "", "| Snapshot | Error |", "| --- | --- |"])
        for failure in failures:
            lines.append(f"| {failure['snapshot_id']} | `{_md(failure['error'])}` |")
    warnings = [
        (result["snapshot_id"], warning)
        for result in snapshot_results
        for warning in result.get("warnings", [])
    ]
    if warnings:
        lines.extend(["", "## Warnings", "", "| Snapshot | Warning |", "| --- | --- |"])
        for snapshot_id, warning in warnings:
            lines.append(f"| {snapshot_id} | `{_md(warning)}` |")
    lines.extend(["", "## Processing", ""])
    for result in snapshot_results:
        lines.append(
            f"- `{result['snapshot_id']}` inserted {result['evtx_rows']} rows from {result['logs_found']} logs "
            f"(parser rows: {result.get('parser_rows', result['evtx_rows'])}) "
            f"from {result['started_at']} to {result['ended_at']}"
        )
    return "\n".join(lines) + "\n"


def _authentication_markdown(
    authentication: dict[str, Any],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = authentication["summary"]
    lines = [
        "# VSC Authentication And Session Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC authentication/session rows parsed: {summary['vsc_auth_session_rows']}",
        f"- Unique VSC authentication/session records not present live: {summary['unique_vsc_auth_session_records_not_live']}",
        f"- Unique VSC successful-logon/credential-validation records not present live: {summary['unique_vsc_successful_logon_records_not_live']}",
        f"- Unique VSC RDP connection/session records not present live: {summary['unique_vsc_rdp_session_records_not_live']}",
        f"- Authentication/session rows with timestamps after their VSC creation time: {summary['post_snapshot_timestamp_count']}",
        "- Live comparison uses event log identity, event ID, record number, timestamp, and computer name.",
        "",
        "## VSC-Only Class Counts",
        "",
        "| Class | Unique not live |",
        "| --- | ---: |",
    ]
    if summary["class_counts"]:
        for event_class, count in summary["class_counts"].items():
            lines.append(f"| `{_md(event_class)}` | {count} |")
    else:
        lines.append("| `(none)` | 0 |")
    post_snapshot_examples = authentication.get("post_snapshot_timestamp_examples", [])
    if post_snapshot_examples:
        lines.extend(
            [
                "",
                "## Timestamp Sanity Notes",
                "",
                "Some authentication/session rows parsed from VSC EVTX files have event times after the VSC creation time. They are retained in the parsed-row inventory, but they are not VSC-only findings unless they also fail the live-record comparison.",
                "",
                "| Snapshot | Snapshot created | Event time | Event | Source | Detail |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for row in post_snapshot_examples:
            lines.append(
                f"| {row.get('snapshot_id') or ''} | {row.get('snapshot_created_utc') or ''} | {row.get('time_created') or ''} | "
                f"`{_md(row.get('event_id'))}` | `{_md(row.get('source_log'))}` | `{_md(row.get('detail'))}` |"
            )
    lines.extend(["", "## VSC Authentication/Session Rows Parsed", "", "| Class | Event | Source | Rows | First | Last |", "| --- | --- | --- | ---: | --- | --- |"])
    for row in authentication.get("all_vsc_counts", []):
        lines.append(
            f"| `{_md(row.get('auth_class'))}` | `{_md(row.get('event_id'))}` | `{_md(row.get('source_log'))}` | "
            f"{row.get('row_count') or 0} | {row.get('first_seen_utc') or ''} | {row.get('last_seen_utc') or ''} |"
        )
    lines.extend(["", "## VSC-Only Findings", "", "| Class | Snapshot | Time | Event | Source | Detail |", "| --- | --- | --- | --- | --- | --- |"])
    findings = authentication.get("findings", [])
    if not findings:
        lines.append("| `(none)` |  |  |  |  | No VSC-only authentication/session records found. |")
    for finding in findings:
        event = f"{finding.get('event_id') or ''} {finding.get('provider') or ''}".strip()
        source = finding.get("channel") or _short_evtx_name(finding.get("source_file"))
        detail = (
            "; ".join(
                part
                for part in (
                    finding.get("map_description"),
                    finding.get("remote_host"),
                    finding.get("payload_data1"),
                    finding.get("payload_data2"),
                )
                if part
            )
            or finding.get("user_name")
            or finding.get("executable_info")
            or ""
        )
        lines.append(
            f"| `{_md(finding.get('auth_class'))}` | {finding.get('snapshot_id') or ''} | {finding.get('time_created') or ''} | "
            f"`{_md(event)}` | `{_md(source)}` | `{_md(detail)}` |"
        )
    return "\n".join(lines) + "\n"


def _evtx_signature_sql(*, table_alias: str) -> str:
    prefix = f"{table_alias}."
    source_name = _evtx_signature_text_sql(
        f"replace(regexp_replace(lower(regexp_extract(COALESCE({prefix}source_file, ''), '[^/\\\\\\\\]+$')), '\\.evtx$', '', 'g'), '%4', '/')"
    )
    channel = _evtx_signature_text_sql(f"{prefix}channel")
    log_identity = f"COALESCE(NULLIF({channel}, ''), {source_name})"
    event_record = f"COALESCE(NULLIF({_evtx_signature_text_sql(f'{prefix}event_record_id')}, ''), {_evtx_signature_text_sql(f'{prefix}record_number')})"
    return f"""
    concat_ws('|',
      'evtx',
      {log_identity},
      {_evtx_signature_text_sql(f'{prefix}event_id')},
      {event_record},
      {_evtx_signature_text_sql(f'{prefix}time_created')},
      {_evtx_signature_text_sql(f'{prefix}computer')}
    )
    """


def _evtx_signature_text_sql(expression: str) -> str:
    return f"lower(trim(regexp_replace(COALESCE({expression}, ''), '[[:space:]]+', ' ', 'g')))"


def _evtx_category_sql() -> str:
    text = "lower(COALESCE(Channel, '') || ' ' || COALESCE(Provider, '') || ' ' || COALESCE(EventId, ''))"
    source_text = "lower(COALESCE(SourceFile, ''))"
    missing_channel = "COALESCE(Channel, '') = ''"
    return f"""
    CASE
      WHEN {text} LIKE '%terminalservices%' OR {text} LIKE '%rdp%' OR {text} LIKE '%remoteconnectionmanager%' OR ({missing_channel} AND {source_text} LIKE '%rdp%') THEN 'rdp'
      WHEN {text} LIKE '%rasclient%' OR {text} LIKE '%vpn%' OR {text} LIKE '%ike%' OR ({missing_channel} AND {source_text} LIKE '%vpn%') THEN 'vpn_network'
      WHEN {text} LIKE '%powershell%' OR ({missing_channel} AND {source_text} LIKE '%powershell%') THEN 'powershell'
      WHEN {text} LIKE '%taskscheduler%' OR ({missing_channel} AND {source_text} LIKE '%taskscheduler%') THEN 'scheduled_tasks'
      WHEN {text} LIKE '%defender%' OR ({missing_channel} AND {source_text} LIKE '%defender%') THEN 'defender'
      WHEN {text} LIKE '%firewall%' OR {text} LIKE '%smb%' OR {text} LIKE '%bits-client%' OR ({missing_channel} AND ({source_text} LIKE '%firewall%' OR {source_text} LIKE '%smb%' OR {source_text} LIKE '%bits-client%')) THEN 'network_file_transfer'
      WHEN {text} LIKE '%wmi-activity%' OR ({missing_channel} AND {source_text} LIKE '%wmi-activity%') THEN 'wmi'
      WHEN {text} LIKE '%codeintegrity%' OR {text} LIKE '%applocker%' OR ({missing_channel} AND ({source_text} LIKE '%codeintegrity%' OR {source_text} LIKE '%applocker%')) THEN 'code_policy'
      WHEN {text} LIKE '%shimengine%' OR {text} LIKE '%application-experience%' OR ({missing_channel} AND ({source_text} LIKE '%shimengine%' OR {source_text} LIKE '%application-experience%')) THEN 'program_inventory'
      WHEN {text} LIKE '%partition%diagnostic%' OR {text} LIKE '%ntfs%' OR ({missing_channel} AND ({source_text} LIKE '%partition%diagnostic%' OR {source_text} LIKE '%ntfs%')) THEN 'storage_filesystem'
      WHEN {text} LIKE '%oalerts%' OR {text} LIKE '%office%alerts%' OR ({missing_channel} AND {source_text} LIKE '%oalerts%') THEN 'office_alerts'
      WHEN {text} LIKE '%security%' THEN 'security'
      WHEN {text} LIKE '%system%' THEN 'system'
      WHEN {text} LIKE '%application%' THEN 'application'
      ELSE 'other'
    END
    """


def _authentication_event_predicate(table_alias: str) -> str:
    prefix = f"{table_alias}."
    channel = f"lower(COALESCE({prefix}channel, ''))"
    provider = f"lower(COALESCE({prefix}provider, ''))"
    event_id = f"COALESCE({prefix}event_id, '')"
    source_file = f"lower(COALESCE({prefix}source_file, ''))"
    return f"""
    (
      {event_id} IN ('4624', '4627', '4634', '4647', '4648', '4672', '4776', '4778', '4779', '1149')
      OR (({channel} LIKE '%terminalservices%' OR {provider} LIKE '%terminalservices%' OR {source_file} LIKE '%terminalservices%')
          AND {event_id} IN ('21', '22', '23', '24', '25', '39', '40'))
      OR (({channel} LIKE '%rdpcorets%' OR {provider} LIKE '%rdpcorets%' OR {source_file} LIKE '%rdpcorets%')
          AND {event_id} IN ('131', '140'))
    )
    """


def _authentication_event_class_sql(table_alias: str) -> str:
    prefix = f"{table_alias}."
    channel = f"lower(COALESCE({prefix}channel, ''))"
    provider = f"lower(COALESCE({prefix}provider, ''))"
    source_file = f"lower(COALESCE({prefix}source_file, ''))"
    event_id = f"COALESCE({prefix}event_id, '')"
    return f"""
    CASE
      WHEN {event_id} = '4624' THEN 'successful_logon'
      WHEN {event_id} = '4627' THEN 'logon_group_membership'
      WHEN {event_id} IN ('4634', '4647') THEN 'logoff'
      WHEN {event_id} = '4648' THEN 'explicit_credentials'
      WHEN {event_id} = '4672' THEN 'privileged_logon'
      WHEN {event_id} = '4776' THEN 'credential_validation'
      WHEN {event_id} = '1149' THEN 'rdp_authentication'
      WHEN ({channel} LIKE '%terminalservices%' OR {provider} LIKE '%terminalservices%' OR {source_file} LIKE '%terminalservices%')
           AND {event_id} IN ('21', '22') THEN 'rdp_session_start'
      WHEN ({channel} LIKE '%terminalservices%' OR {provider} LIKE '%terminalservices%' OR {source_file} LIKE '%terminalservices%')
           AND {event_id} IN ('23', '24', '25', '39', '40') THEN 'rdp_session_end_or_state_change'
      WHEN ({channel} LIKE '%rdpcorets%' OR {provider} LIKE '%rdpcorets%' OR {source_file} LIKE '%rdpcorets%')
           AND {event_id} = '131' THEN 'rdp_tcp_connection_accepted'
      WHEN ({channel} LIKE '%rdpcorets%' OR {provider} LIKE '%rdpcorets%' OR {source_file} LIKE '%rdpcorets%')
           AND {event_id} = '140' THEN 'rdp_connection_failed'
      ELSE 'other_auth_session'
    END
    """


def _source_log_identity_sql(table_alias: str) -> str:
    prefix = f"{table_alias}."
    return f"replace(regexp_replace(lower(regexp_extract(COALESCE({prefix}source_file, ''), '[^/\\\\\\\\]+$')), '\\\\.evtx$', '', 'g'), '%4', '/')"


def _find_case_insensitive(root: Path, relative_path: str) -> Path | None:
    current = root
    for part in Path(relative_path).parts:
        candidate = current / part
        if candidate.exists():
            current = candidate
            continue
        lowered = part.casefold()
        try:
            matches = [child for child in current.iterdir() if child.name.casefold() == lowered]
        except OSError:
            return None
        if not matches:
            return None
        current = matches[0]
    return current


def _casefold_children(path: Path) -> dict[str, Path]:
    try:
        return {child.name.casefold(): child for child in path.iterdir()}
    except OSError:
        return {}


def _run_command(command: list[str], output: Path) -> None:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    (output / "_stdout.txt").write_text(result.stdout or "", encoding="utf-8")
    (output / "_stderr.txt").write_text(result.stderr or "", encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} failed with exit code {result.returncode}: {(result.stderr or '').strip()}")


def _csv_data_row_count(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for _ in reader)


def _snapshot_from_payload(payload: dict[str, Any]) -> VscSnapshot:
    return VscSnapshot(
        index=int(payload["index"]),
        snapshot_id=str(payload.get("snapshot_id") or ""),
        identifier=str(payload.get("identifier") or ""),
        shadow_copy_set_id=str(payload.get("shadow_copy_set_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
    )


def _short_evtx_name(value: object) -> str:
    return Path(_text(value).replace("\\", "/")).name


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    import json

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _md(value: object, limit: int = 120) -> str:
    text = _text(value).replace("|", "\\|").replace("\n", " ")
    if len(text) > limit:
        return text[: limit - 1] + "..."
    return text


def _timestamp_key(value: object) -> str:
    text = _text(value)
    return text if text else "9999-99-99"


def _parse_evtx_datetime(value: object) -> datetime | None:
    text = _text(value).replace("T", " ").replace("Z", "")
    if not text:
        return None
    if "." in text:
        head, fraction = text.split(".", 1)
        fraction = re.sub(r"\D.*$", "", fraction)[:6]
        text = f"{head}.{fraction}"
        fmt = "%Y-%m-%d %H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%d %H:%M:%S"
    try:
        return datetime.strptime(text, fmt)
    except ValueError:
        return None


def _parse_vsc_datetime(value: object) -> datetime | None:
    text = _text(value).replace(" UTC", "")
    if not text:
        return None
    if "." in text:
        head, fraction = text.split(".", 1)
        fraction = re.sub(r"\D.*$", "", fraction)[:6]
        text = f"{head}.{fraction}"
        fmt = "%b %d, %Y %H:%M:%S.%f"
    else:
        fmt = "%b %d, %Y %H:%M:%S"
    try:
        return datetime.strptime(text, fmt)
    except ValueError:
        return None
