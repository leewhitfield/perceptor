from __future__ import annotations

import csv
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError
from forensic_orchestrator.tools.normalized import normalized_srum_record_row
from forensic_orchestrator.tools.srum import parse_srum_artifacts_to_csv

from .vshadow import VscSnapshot, discover_vsc_snapshots, mount_vsc_snapshot, unmount_vsc
from .vsc_promote import add_vsc_provenance, clear_vsc_rows, promote_deduped_rows


SRUM_COLUMNS = [
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
    "provider_guid",
    "provider_name",
    "source_table",
    "record_type",
    "srum_id",
    "timestamp",
    "app_id",
    "app_name",
    "app_path",
    "app_description",
    "exe_timestamp",
    "user_id",
    "user_sid",
    "user_name",
    "bytes_received",
    "bytes_sent",
    "interface_luid",
    "interface_type",
    "l2_profile_id",
    "l2_profile_name",
    "l2_profile_flags",
    "connected_time",
    "connect_start_time",
    "connect_end_time",
    "notification_type",
    "payload_size",
    "network_type",
    "foreground_bytes_read",
    "foreground_bytes_written",
    "background_bytes_read",
    "background_bytes_written",
    "foreground_cycle_time",
    "background_cycle_time",
    "face_time",
    "foreground_context_switches",
    "background_context_switches",
    "foreground_read_operations",
    "foreground_write_operations",
    "background_read_operations",
    "background_write_operations",
    "foreground_flushes",
    "background_flushes",
    "flags",
    "start_time",
    "end_time",
    "duration_ms",
    "span_ms",
    "timeline_end",
    "event_timestamp",
    "state_transition",
    "charge_level",
    "cycle_count",
    "designed_capacity",
    "full_charged_capacity",
    "active_ac_time",
    "active_dc_time",
    "active_discharge_time",
    "active_energy",
    "cs_ac_time",
    "cs_dc_time",
    "cs_discharge_time",
    "cs_energy",
    "configuration_hash",
    "metadata",
    "energy_data",
    "tag",
    "binary_data",
    "vpn_profile_name",
    "vpn_server",
    "vpn_device",
    "vpn_protocol",
    "vpn_phonebook_path",
    "vpn_match_method",
    "record_signature",
    "parsed_at",
]


def run_vsc_srum_scan(
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
        raise MountError("No VSC snapshots selected for SRUM scan")

    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_srum_table(conn)
        snapshot_ids = [f"vss{snapshot.index}" for snapshot in snapshots]
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="srum_records", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        live_signatures = _live_srum_signatures(db, case_id=case_id)
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
                rows = parse_vsc_srum_snapshot(
                    paths=paths,
                    case_id=case_id,
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                    mount_path=Path(mount["volume_mount_path"]),
                )
                _insert_csv_rows(conn, rows)
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "srum_rows": rows["row_count"],
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
            table="srum_records",
            rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/SrumParser") for row in sidecar_rows],
            key_func=srum_signature,
        )
        comparison = compare_srum_snapshots_from_db(
            conn=conn,
            case_id=case_id,
            image_id=image.id,
            live_signatures=live_signatures,
        )
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "srum-vsc-comparison.md"
        report_path.write_text(
            _comparison_markdown(comparison, snapshot_results, failures, started_at=started_at, ended_at=ended_at),
            encoding="utf-8",
        )
        payload = {
            "case_id": case_id,
            "image_id": image.id,
            "started_at": started_at,
            "ended_at": ended_at,
            "vsc_db_path": str(db_path),
            "report_path": str(report_path),
            "snapshot_count": len(snapshots),
            "successful_snapshots": len(snapshot_results),
            "failed_snapshots": len(failures),
            "snapshot_results": snapshot_results,
            "failures": failures,
            "comparison_summary": comparison["summary"],
        }
        _write_json(paths.vsc_work_dir(case_id) / "srum-scan.json", payload)
        return payload
    finally:
        conn.close()


def parse_vsc_srum_snapshot(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
    mount_path: Path,
) -> dict[str, Any]:
    srum_dir = _find_case_insensitive(mount_path, "Windows/System32/sru")
    if srum_dir is None or not (srum_dir / "SRUDB.dat").exists():
        return {"csv_path": None, "row_count": 0, "snapshot": snapshot, "snapshot_id": snapshot_id, "case_id": case_id, "image_id": image_id}
    extract_dir = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / "srum"
    software_hive = _copy_optional(mount_path, "Windows/System32/config/SOFTWARE", extract_dir / "SOFTWARE")
    for suffix in (".LOG1", ".LOG2"):
        _copy_optional(mount_path, f"Windows/System32/config/SOFTWARE{suffix}", extract_dir / f"SOFTWARE{suffix}")
    phonebooks = _find_case_insensitive(mount_path, "Users")
    output = paths.vsc_work_dir(case_id) / "outputs" / snapshot_id / "SrumParser"
    if output.exists():
        shutil.rmtree(output)
    csv_path = parse_srum_artifacts_to_csv(srum_dir, output, software_hive=software_hive, phonebooks=phonebooks)
    row_count = max(0, sum(1 for _ in csv_path.open("r", encoding="utf-8", errors="replace")) - 1)
    return {
        "csv_path": csv_path,
        "row_count": row_count,
        "snapshot": snapshot,
        "snapshot_id": snapshot_id,
        "case_id": case_id,
        "image_id": image_id,
    }


def compare_srum_snapshots_from_db(
    *,
    conn: duckdb.DuckDBPyConnection,
    case_id: str,
    image_id: str,
    live_signatures: set[str],
) -> dict[str, Any]:
    count_rows = conn.execute(
        """
        SELECT snapshot_id, snapshot_index, snapshot_created_utc, COUNT(*) AS row_count
        FROM vsc_srum_records
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
        for row in count_rows
    }
    rows = conn.execute(
        """
        SELECT snapshot_id, snapshot_index, snapshot_created_utc, record_type, timestamp,
               app_name, app_path, l2_profile_name, vpn_profile_name, source_table,
               bytes_received, bytes_sent, foreground_bytes_read, foreground_bytes_written,
               record_signature
        FROM vsc_srum_records
        WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
        """,
        [case_id, image_id],
    ).fetchall()
    columns = [desc[0] for desc in conn.description]
    unique: dict[str, dict[str, Any]] = {}
    for values in rows:
        row = dict(zip(columns, values, strict=False))
        signature = row.get("record_signature") or ""
        if signature in live_signatures:
            continue
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
        unique.setdefault(signature, row)
    unique_findings = sorted(unique.values(), key=lambda item: (item.get("timestamp") or "", item.get("record_type") or "", item.get("app_name") or item.get("app_path") or ""))
    type_counts = Counter(finding.get("record_type") or "srum" for finding in unique_findings)
    return {
        "summary": {
            "vsc_srum_rows": sum(int(row["row_count"]) for row in by_snapshot.values()),
            "unique_vsc_records_not_live": len(unique_findings),
            "record_type_count": len(type_counts),
            "record_type_counts": dict(sorted(type_counts.items())),
        },
        "snapshots": sorted(by_snapshot.values(), key=lambda item: int(item["snapshot_index"])),
        "findings": unique_findings,
    }


def compare_srum_snapshots(*, live_signatures: set[str], snapshot_rows: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    by_snapshot: dict[str, dict[str, Any]] = {}
    for row in snapshot_rows:
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
        summary["row_count"] += 1
        signature = row.get("record_signature") or ""
        if not signature or signature in live_signatures:
            continue
        summary["unique_not_live_count"] += 1
        findings.append(row)
    unique: dict[str, dict[str, Any]] = {}
    for finding in findings:
        unique.setdefault(finding["record_signature"], finding)
    unique_findings = sorted(unique.values(), key=lambda item: (item.get("timestamp") or "", item.get("record_type") or "", item.get("app_name") or item.get("app_path") or ""))
    type_counts = Counter(finding.get("record_type") or "srum" for finding in unique_findings)
    return {
        "summary": {
            "vsc_srum_rows": len(snapshot_rows),
            "unique_vsc_records_not_live": len(unique_findings),
            "record_type_count": len(type_counts),
            "record_type_counts": dict(sorted(type_counts.items())),
        },
        "snapshots": sorted(by_snapshot.values(), key=lambda item: int(item["snapshot_index"])),
        "findings": unique_findings,
    }


def srum_signature(row: dict[str, Any]) -> str:
    timestamp = _text(row.get("timestamp"))
    record_type = _text(row.get("record_type")).casefold()
    if not timestamp and not _text(row.get("srum_id")):
        return ""
    parts = [
        "srum",
        record_type,
        _text(row.get("source_table")).casefold(),
        _text(row.get("srum_id")),
        timestamp,
        _text(row.get("app_id")).casefold(),
        _text(row.get("app_name")).casefold(),
        _normalize_windows_path(row.get("app_path")),
        _text(row.get("user_sid")).casefold(),
        _text(row.get("l2_profile_name")).casefold(),
        _text(row.get("vpn_profile_name")).casefold(),
        _text(row.get("bytes_received")),
        _text(row.get("bytes_sent")),
        _text(row.get("foreground_bytes_read")),
        _text(row.get("foreground_bytes_written")),
        _text(row.get("background_bytes_read")),
        _text(row.get("background_bytes_written")),
    ]
    return "|".join(parts)


def _live_srum_signatures(db: Database, *, case_id: str) -> set[str]:
    case = db.get_case(case_id)
    duckdb_path = case.root / "analytics" / "events.duckdb"
    signatures: set[str] = set()
    if not duckdb_path.exists():
        return signatures
    conn = duckdb.connect(str(duckdb_path), read_only=True)
    try:
        columns = [column for column in SRUM_COLUMNS if column not in {"snapshot_id", "snapshot_index", "snapshot_created_utc", "record_signature", "parsed_at"}]
        rows = conn.execute(f"SELECT {', '.join(columns)} FROM srum_records WHERE case_id = ?", [case_id]).fetchall()
        for row in rows:
            signatures.add(srum_signature(dict(zip(columns, row, strict=False))))
    finally:
        conn.close()
    signatures.discard("")
    return signatures


def _ensure_srum_table(conn: duckdb.DuckDBPyConnection) -> None:
    column_defs = ", ".join(f"{column} VARCHAR" for column in SRUM_COLUMNS)
    conn.execute(f"CREATE TABLE IF NOT EXISTS vsc_srum_records ({column_defs})")
    existing = {row[1] for row in conn.execute("PRAGMA table_info('vsc_srum_records')").fetchall()}
    for column in SRUM_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE vsc_srum_records ADD COLUMN {column} VARCHAR")


def _clear_snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str, snapshot_ids: list[str]) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    conn.execute(
        f"DELETE FROM vsc_srum_records WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
        [case_id, image_id, *snapshot_ids],
    )


def _insert_csv_rows(conn: duckdb.DuckDBPyConnection, parsed: dict[str, Any]) -> None:
    csv_path = parsed.get("csv_path")
    if not csv_path or parsed.get("row_count", 0) == 0:
        return
    snapshot: VscSnapshot = parsed["snapshot"]
    snapshot_id = str(parsed["snapshot_id"])
    csv_literal = str(csv_path).replace("'", "''")
    source_csv = str(csv_path).replace("'", "''")
    case_id = str(parsed["case_id"]).replace("'", "''")
    image_id = str(parsed["image_id"]).replace("'", "''")
    snapshot_created = str(snapshot.created_utc).replace("'", "''")
    tool_output_id = f"{snapshot_id}-SrumParser".replace("'", "''")
    parsed_at = utc_now().replace("'", "''")
    columns_without_snapshot = [
        column
        for column in SRUM_COLUMNS
        if column
        not in {
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
            "record_signature",
            "parsed_at",
        }
    ]
    select_columns = ",\n               ".join(f"COALESCE({column}, '') AS {column}" for column in columns_without_snapshot)
    record_signature = _srum_signature_sql()
    conn.execute(
        f"""
        INSERT INTO vsc_srum_records ({', '.join(SRUM_COLUMNS)})
        WITH source AS (
            SELECT row_number() OVER () AS row_number, *
            FROM read_csv_auto('{csv_literal}', header=true, all_varchar=true, ignore_errors=true)
        ),
        normalized AS (
            SELECT
               '{case_id}' AS case_id,
               '{image_id}' AS image_id,
               '{snapshot_id}' AS snapshot_id,
               '{snapshot.index}' AS snapshot_index,
               '{snapshot_created}' AS snapshot_created_utc,
               '{snapshot_id}-' || CAST(row_number AS VARCHAR) AS id,
               'vsc' AS computer_id,
               '{tool_output_id}' AS tool_output_id,
               'SrumParser' AS tool_name,
               '{source_csv}' AS source_csv,
               CAST(row_number AS VARCHAR) AS row_number,
               {select_columns},
               {record_signature} AS record_signature,
               '{parsed_at}' AS parsed_at
            FROM source
        )
        SELECT {', '.join(SRUM_COLUMNS)} FROM normalized
        """
    )


def _snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM vsc_srum_records WHERE case_id = ? AND image_id = ?", [case_id, image_id]).fetchall()
    columns = [desc[0] for desc in conn.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def _srum_signature_sql() -> str:
    normalized_path = """
    lower(
      ltrim(
        CASE
          WHEN substr(replace(COALESCE(app_path, ''), chr(92), '/'), 2, 1) = ':'
            THEN substr(replace(COALESCE(app_path, ''), chr(92), '/'), 3)
          ELSE replace(COALESCE(app_path, ''), chr(92), '/')
        END,
        '/'
      )
    )
    """
    return f"""
    concat_ws('|',
      'srum',
      lower(COALESCE(record_type, '')),
      lower(COALESCE(source_table, '')),
      COALESCE(srum_id, ''),
      COALESCE(timestamp, ''),
      lower(COALESCE(app_id, '')),
      lower(COALESCE(app_name, '')),
      {normalized_path},
      lower(COALESCE(user_sid, '')),
      lower(COALESCE(l2_profile_name, '')),
      lower(COALESCE(vpn_profile_name, '')),
      COALESCE(bytes_received, ''),
      COALESCE(bytes_sent, ''),
      COALESCE(foreground_bytes_read, ''),
      COALESCE(foreground_bytes_written, ''),
      COALESCE(background_bytes_read, ''),
      COALESCE(background_bytes_written, '')
    )
    """


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
        "# VSC SRUM Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC SRUM rows parsed: {summary['vsc_srum_rows']}",
        f"- Unique VSC records not present live: {summary['unique_vsc_records_not_live']}",
        f"- SRUM record types with VSC-only records: {summary['record_type_count']}",
        "- SRUM timestamps and counters are contextual telemetry, not precise process execution times.",
        "",
        "## Record Type Counts",
        "",
        "| Record type | Unique not live |",
        "| --- | ---: |",
    ]
    for record_type, count in summary["record_type_counts"].items():
        lines.append(f"| `{record_type}` | {count} |")
    lines.extend(["", "## Snapshot Counts", "", "| Snapshot | Created | Rows | Unique not live |", "| --- | --- | ---: | ---: |"])
    unique_by_snapshot = {row["snapshot_id"]: row["unique_not_live_count"] for row in comparison["snapshots"]}
    for result in snapshot_results:
        lines.append(f"| {result['snapshot_id']} | {result['snapshot_created_utc']} | {result['srum_rows']} | {unique_by_snapshot.get(result['snapshot_id'], 0)} |")
    lines.extend(["", "## Examples", "", "| Type | Snapshot | Time | App / Network | Counters |", "| --- | --- | --- | --- | --- |"])
    for finding in comparison["findings"][:50]:
        subject = finding.get("app_name") or finding.get("app_path") or finding.get("l2_profile_name") or finding.get("vpn_profile_name") or finding.get("source_table") or ""
        counters = f"rx={finding.get('bytes_received') or finding.get('foreground_bytes_read') or ''} tx={finding.get('bytes_sent') or finding.get('foreground_bytes_written') or ''}"
        lines.append(f"| `{finding.get('record_type') or 'srum'}` | {finding['snapshot_id']} | {finding.get('timestamp') or ''} | `{_md(subject)}` | `{_md(counters)}` |")
    if failures:
        lines.extend(["", "## Failures", "", "| Snapshot | Error |", "| --- | --- |"])
        for failure in failures:
            lines.append(f"| {failure['snapshot_id']} | `{_md(failure['error'])}` |")
    lines.extend(["", "## Processing", ""])
    for result in snapshot_results:
        lines.append(f"- `{result['snapshot_id']}` parsed {result['srum_rows']} SRUM rows from {result['started_at']} to {result['ended_at']}")
    return "\n".join(lines) + "\n"


def _copy_optional(mount_path: Path, relative_path: str, destination: Path) -> Path | None:
    source = _find_case_insensitive(mount_path, relative_path)
    try:
        if source is None or not source.is_file():
            return None
    except OSError:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)

    try:
        shutil.copy2(source, destination)
    except OSError:
        return None
    return destination


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


def _read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _add_snapshot_fields(row: dict[str, Any], *, snapshot: VscSnapshot, snapshot_id: str) -> None:
    row["snapshot_id"] = snapshot_id
    row["snapshot_index"] = str(snapshot.index)
    row["snapshot_created_utc"] = snapshot.created_utc
    row["parsed_at"] = utc_now()


def _normalize_windows_path(value: object) -> str:
    text = _text(value).replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    return text.strip("/").casefold()


def _snapshot_from_payload(payload: dict[str, Any]) -> VscSnapshot:
    return VscSnapshot(
        index=int(payload["index"]),
        snapshot_id=str(payload.get("snapshot_id") or ""),
        identifier=str(payload.get("identifier") or ""),
        shadow_copy_set_id=str(payload.get("shadow_copy_set_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
    )


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
