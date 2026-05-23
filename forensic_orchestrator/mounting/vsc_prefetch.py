from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError
from forensic_orchestrator.tools.prefetch import parse_prefetch_file
from forensic_orchestrator.tools.prefetch_items import normalized_prefetch_row, normalized_prefetch_run_time_rows

from .vshadow import (
    VscSnapshot,
    discover_vsc_snapshots,
    extract_vsc_artifact,
    mount_vsc_snapshot,
    unmount_vsc,
)


PREFETCH_RELATIVE_PATH = "Windows/Prefetch"


def run_vsc_prefetch_scan(
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
        raise MountError("No VSC snapshots selected for Prefetch scan")

    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_prefetch_table(conn)
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image.id, snapshot_ids=[f"vss{s.index}" for s in snapshots])
        _clear_promoted_prefetch_rows(
            db,
            case_id=case_id,
            image_id=image.id,
            snapshot_ids=[f"vss{s.index}" for s in snapshots],
        )
        live_rows = _live_prefetch_rows(db, case_id=case_id)
        snapshot_results: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        all_rows: list[dict[str, Any]] = []
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
                manifest = extract_vsc_artifact(
                    paths=paths,
                    case_id=case_id,
                    snapshot_id=snapshot_id,
                    relative_path=PREFETCH_RELATIVE_PATH,
                )
                rows = parse_vsc_prefetch_snapshot(
                    paths=paths,
                    case_id=case_id,
                    computer_id=image.computer_id or "vsc",
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                )
                _insert_prefetch_rows(conn, rows)
                all_rows.extend(rows)
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "mount": mount,
                        "manifest": _manifest_summary(manifest),
                        "parsed_rows": len(rows),
                        "usable_rows": sum(1 for row in rows if _usable_for_delta(row)),
                        "unusable_rows": sum(1 for row in rows if not _usable_for_delta(row)),
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

        _promote_prefetch_rows(db, all_rows)
        snapshot_rows = _snapshot_rows(conn, case_id=case_id, image_id=image.id)
        comparison = compare_prefetch_snapshots(live_rows=live_rows, snapshot_rows=snapshot_rows)
        report_path = paths.vsc_reports_dir(case_id) / "prefetch-vsc-comparison.md"
        report_path.write_text(_prefetch_comparison_markdown(comparison, snapshot_results, failures), encoding="utf-8")
        run_payload = {
            "case_id": case_id,
            "image_id": image.id,
            "started_at": started_at,
            "ended_at": utc_now(),
            "vsc_db_path": str(db_path),
            "report_path": str(report_path),
            "snapshot_count": len(snapshots),
            "successful_snapshots": len(snapshot_results),
            "failed_snapshots": len(failures),
            "live_prefetch_rows": len(live_rows),
            "snapshot_results": snapshot_results,
            "failures": failures,
            "comparison_summary": comparison["summary"],
        }
        _write_json(paths.vsc_work_dir(case_id) / "prefetch-scan.json", run_payload)
        return run_payload
    finally:
        conn.close()


def parse_vsc_prefetch_snapshot(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    computer_id: str = "vsc",
    snapshot: VscSnapshot,
    snapshot_id: str,
) -> list[dict[str, Any]]:
    prefetch_dir = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / PREFETCH_RELATIVE_PATH
    rows: list[dict[str, Any]] = []
    for row_number, pf_path in enumerate(sorted(prefetch_dir.rglob("*.pf")), start=1):
        if not pf_path.is_file():
            continue
        stat = pf_path.stat()
        parsed = parse_prefetch_file(pf_path)
        parsed["source_path"] = str(pf_path)
        normalized = normalized_prefetch_row(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            tool_output_id=f"{snapshot_id}-PrefetchParser",
            tool_name="PrefetchParser",
            source_csv=prefetch_dir / "PrefetchParser.csv",
            row_number=row_number,
            row=parsed,
            artifact_manifest={
                str(pf_path): {
                    "original_path": f"/Windows/Prefetch/{pf_path.name}",
                    "mft_modified": _ns_to_iso(stat.st_mtime_ns),
                    "mft_accessed": _ns_to_iso(stat.st_atime_ns),
                    "mft_created": _ns_to_iso(stat.st_ctime_ns),
                }
            },
        )
        normalized.update(
            {
                "snapshot_id": snapshot_id,
                "snapshot_index": snapshot.index,
                "snapshot_created_utc": snapshot.created_utc,
                "source_scope": "VSC",
                "source_csv": f"vsc://{snapshot_id}/Windows/Prefetch/PrefetchParser.csv",
                "artifact_path": _relative_to_work(paths.vsc_work_dir(case_id), pf_path),
                "file_size": stat.st_size,
                "modified_time_utc": _ns_to_iso(stat.st_mtime_ns),
                "modified_time_ns": stat.st_mtime_ns,
                "md5": _md5(pf_path),
                "parser_status": _parser_status(pf_path, parsed),
                "parsed_at": utc_now(),
            }
        )
        rows.append(normalized)
    return rows


def compare_prefetch_snapshots(*, live_rows: list[dict[str, Any]], snapshot_rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    usable_snapshot_rows = [row for row in snapshot_rows if _usable_for_delta(row)]
    unusable_snapshot_rows = [row for row in snapshot_rows if not _usable_for_delta(row)]
    for row in live_rows:
        groups.setdefault(str(row.get("prefetch_name") or ""), []).append({"source": "live", **row})
    for row in usable_snapshot_rows:
        groups.setdefault(str(row.get("prefetch_name") or ""), []).append({"source": row["snapshot_id"], **row})

    by_snapshot: dict[str, dict[str, Any]] = {}
    for row in snapshot_rows:
        summary = by_snapshot.setdefault(
            row["snapshot_id"],
            {
                "snapshot_id": row["snapshot_id"],
                "snapshot_index": row["snapshot_index"],
                "snapshot_created_utc": row.get("snapshot_created_utc") or "",
                "prefetch_count": 0,
                "only_in_snapshot_count": 0,
                "changed_from_live_count": 0,
                "historical_run_time_count": 0,
                "usable_prefetch_count": 0,
                "unusable_prefetch_count": 0,
            },
        )
        summary["prefetch_count"] += 1
        if not _usable_for_delta(row):
            summary["unusable_prefetch_count"] += 1
            continue
        summary["usable_prefetch_count"] += 1
        live_candidates = _live_rows_for_name(groups, row["prefetch_name"])
        if not live_candidates:
            summary["only_in_snapshot_count"] += 1
        elif _differs_from_live_rows(row, live_candidates):
            summary["changed_from_live_count"] += 1
            summary["historical_run_time_count"] += _historical_run_time_count(row, live_candidates)

    findings: list[dict[str, Any]] = []
    for name, rows in groups.items():
        if not name:
            continue
        live_candidates = [row for row in rows if row["source"] == "live"]
        live = _representative_live_row(live_candidates)
        snapshots = sorted(
            [row for row in rows if row["source"] != "live"],
            key=lambda row: int(row.get("snapshot_index") or 0),
        )
        if snapshots and not live_candidates:
            findings.append(
                {
                    "type": "not_present_live",
                    "prefetch_name": name,
                    "executable_name": snapshots[-1].get("executable_name"),
                    "snapshots": [row["snapshot_id"] for row in snapshots],
                    "last_snapshot": snapshots[-1]["snapshot_id"],
                    "last_run_time_utc": snapshots[-1].get("last_run_time_utc"),
                    "run_count": snapshots[-1].get("run_count"),
                }
            )
            continue
        if not live_candidates:
            continue
        changed = [row for row in snapshots if _differs_from_live_rows(row, live_candidates)]
        if changed:
            historical_times = _historical_run_times(changed, live_candidates)
            findings.append(
                {
                    "type": "differs_from_live",
                    "prefetch_name": name,
                    "executable_name": (live or {}).get("executable_name") or changed[-1].get("executable_name"),
                    "snapshots": [row["snapshot_id"] for row in changed],
                    "live_last_run_time_utc": (live or {}).get("last_run_time_utc"),
                    "snapshot_last_run_times": {
                        row["snapshot_id"]: row.get("last_run_time_utc")
                        for row in changed
                        if row.get("last_run_time_utc")
                    },
                    "historical_run_times": historical_times,
                    "historical_run_time_count": len(historical_times),
                }
            )

    return {
        "summary": {
            "live_prefetch_count": len(live_rows),
            "vsc_prefetch_count": len(snapshot_rows),
            "usable_vsc_prefetch_count": len(usable_snapshot_rows),
            "unusable_vsc_prefetch_count": len(unusable_snapshot_rows),
            "snapshot_count": len(by_snapshot),
            "finding_count": len(findings),
            "only_in_vsc_count": sum(1 for item in findings if item["type"] == "not_present_live"),
            "changed_from_live_count": sum(1 for item in findings if item["type"] == "differs_from_live"),
            "unique_historical_run_time_count": len(
                {
                    (item["prefetch_name"], run_time)
                    for item in findings
                    if item["type"] == "differs_from_live"
                    for run_time in item.get("historical_run_times", [])
                }
            ),
        },
        "snapshots": sorted(by_snapshot.values(), key=lambda item: int(item["snapshot_index"])),
        "findings": sorted(findings, key=lambda item: (item["type"], item["prefetch_name"])),
        "unusable_rows": sorted(
            [
                {
                    "snapshot_id": row["snapshot_id"],
                    "prefetch_name": row["prefetch_name"],
                    "parser_status": row.get("parser_status"),
                    "parser_note": row.get("parser_note"),
                }
                for row in unusable_snapshot_rows
            ],
            key=lambda item: (item["snapshot_id"], item["prefetch_name"]),
        ),
    }


def _ensure_prefetch_table(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vsc_prefetch_items (
          id VARCHAR,
          case_id VARCHAR,
          image_id VARCHAR,
          snapshot_id VARCHAR,
          snapshot_index INTEGER,
          snapshot_created_utc VARCHAR,
          prefetch_name VARCHAR,
          original_path VARCHAR,
          artifact_path VARCHAR,
          file_size BIGINT,
          modified_time_utc VARCHAR,
          modified_time_ns BIGINT,
          md5 VARCHAR,
          executable_name VARCHAR,
          prefetch_hash VARCHAR,
          prefetch_version VARCHAR,
          prefetch_version_label VARCHAR,
          compression VARCHAR,
          run_count VARCHAR,
          last_run_time_utc VARCHAR,
          last_run_times_utc VARCHAR,
          referenced_string_count VARCHAR,
          referenced_strings VARCHAR,
          parser_status VARCHAR,
          parser_note VARCHAR,
          resolved_reference_path VARCHAR,
          resolved_reference_device_path VARCHAR,
          resolved_reference_command_line VARCHAR,
          resolved_reference_os VARCHAR,
          resolved_reference_description VARCHAR,
          resolved_reference_source VARCHAR,
          resolved_reference_match_count VARCHAR,
          pf_created VARCHAR,
          pf_modified VARCHAR,
          pf_accessed VARCHAR,
          pf_mft_record_modified VARCHAR,
          parsed_at VARCHAR
        )
        """
    )
    for column in (
        "id",
        "parser_status",
        "compression",
        "referenced_strings",
        "resolved_reference_path",
        "resolved_reference_device_path",
        "resolved_reference_command_line",
        "resolved_reference_os",
        "resolved_reference_description",
        "resolved_reference_source",
        "resolved_reference_match_count",
        "pf_created",
        "pf_modified",
        "pf_accessed",
        "pf_mft_record_modified",
    ):
        _add_column_if_missing(conn, "vsc_prefetch_items", column, "VARCHAR")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vsc_prefetch_run_times (
          id VARCHAR,
          case_id VARCHAR,
          image_id VARCHAR,
          snapshot_id VARCHAR,
          snapshot_index VARCHAR,
          snapshot_created_utc VARCHAR,
          prefetch_item_id VARCHAR,
          prefetch_name VARCHAR,
          executable_name VARCHAR,
          prefetch_hash VARCHAR,
          artifact_path VARCHAR,
          original_path VARCHAR,
          run_index VARCHAR,
          run_time_utc VARCHAR,
          is_last_run VARCHAR,
          parsed_at VARCHAR
        )
        """
    )


def _sidecar_table_exists(conn: duckdb.DuckDBPyConnection, table: str) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1",
            [table],
        ).fetchone()
    )


def _clear_snapshot_rows(
    conn: duckdb.DuckDBPyConnection,
    *,
    case_id: str,
    image_id: str,
    snapshot_ids: list[str],
) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    conn.execute(
        f"DELETE FROM vsc_prefetch_items WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
        [case_id, image_id, *snapshot_ids],
    )
    conn.execute(
        f"DELETE FROM vsc_prefetch_run_times WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
        [case_id, image_id, *snapshot_ids],
    )


def _insert_prefetch_rows(conn: duckdb.DuckDBPyConnection, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    columns = [
        "id",
        "case_id",
        "image_id",
        "snapshot_id",
        "snapshot_index",
        "snapshot_created_utc",
        "prefetch_name",
        "original_path",
        "artifact_path",
        "file_size",
        "modified_time_utc",
        "modified_time_ns",
        "md5",
        "executable_name",
        "prefetch_hash",
        "prefetch_version",
        "prefetch_version_label",
        "compression",
        "run_count",
        "last_run_time_utc",
        "last_run_times_utc",
        "referenced_string_count",
        "referenced_strings",
        "parser_status",
        "parser_note",
        "resolved_reference_path",
        "resolved_reference_device_path",
        "resolved_reference_command_line",
        "resolved_reference_os",
        "resolved_reference_description",
        "resolved_reference_source",
        "resolved_reference_match_count",
        "pf_created",
        "pf_modified",
        "pf_accessed",
        "pf_mft_record_modified",
        "parsed_at",
    ]
    placeholders = ", ".join("?" for _ in columns)
    conn.executemany(
        f"INSERT INTO vsc_prefetch_items ({', '.join(columns)}) VALUES ({placeholders})",
        [[row.get(column) for column in columns] for row in rows],
    )
    run_time_columns = [
        "id",
        "case_id",
        "image_id",
        "snapshot_id",
        "snapshot_index",
        "snapshot_created_utc",
        "prefetch_item_id",
        "prefetch_name",
        "executable_name",
        "prefetch_hash",
        "artifact_path",
        "original_path",
        "run_index",
        "run_time_utc",
        "is_last_run",
        "parsed_at",
    ]
    run_time_rows: list[dict[str, Any]] = []
    for row in rows:
        for run_row in normalized_prefetch_run_time_rows(row):
            run_row.update(
                {
                    "snapshot_id": row.get("snapshot_id"),
                    "snapshot_index": row.get("snapshot_index"),
                    "snapshot_created_utc": row.get("snapshot_created_utc"),
                    "prefetch_item_id": row.get("id"),
                    "parsed_at": row.get("parsed_at"),
                }
            )
            run_time_rows.append(run_row)
    if run_time_rows:
        run_time_placeholders = ", ".join("?" for _ in run_time_columns)
        conn.executemany(
            f"INSERT INTO vsc_prefetch_run_times ({', '.join(run_time_columns)}) VALUES ({run_time_placeholders})",
            [[row.get(column) for column in run_time_columns] for row in run_time_rows],
        )


def _promote_prefetch_rows(db: Database, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    promoted_rows = _dedupe_promoted_prefetch_items([
        {
            **row,
            "source_scope": "VSC",
            "last_run_times_utc": row.get("last_run_times_utc") or row.get("_run_times_utc"),
        }
        for row in rows
    ])
    run_time_rows: list[dict[str, Any]] = []
    for row in promoted_rows:
        for run_row in normalized_prefetch_run_time_rows(row):
            run_row.update(
                {
                    "source_scope": "VSC",
                    "snapshot_id": row.get("snapshot_id"),
                    "snapshot_index": row.get("snapshot_index"),
                    "snapshot_created_utc": row.get("snapshot_created_utc"),
                }
            )
            run_time_rows.append(run_row)
    run_time_rows = _dedupe_promoted_prefetch_run_times(run_time_rows)
    db.insert_prefetch_items(promoted_rows)
    db.insert_normalized_artifact_rows("prefetch_run_times", run_time_rows)


def _dedupe_promoted_prefetch_items(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in rows:
        run_times = _canonical_json_list(_run_times(row))
        key = (
            str(row.get("case_id") or ""),
            str(row.get("image_id") or ""),
            str(row.get("computer_id") or ""),
            str(row.get("prefetch_name") or ""),
            str(row.get("prefetch_hash") or ""),
            run_times,
        )
        existing = grouped.get(key)
        if existing is None or _prefetch_snapshot_sort_key(row) < _prefetch_snapshot_sort_key(existing):
            merged = dict(row)
            if existing:
                merged["_snapshot_ids"] = set(existing.get("_snapshot_ids") or [])
            else:
                merged["_snapshot_ids"] = set()
            grouped[key] = merged
            existing = merged
        snapshot_id = str(row.get("snapshot_id") or "").strip()
        if snapshot_id:
            existing.setdefault("_snapshot_ids", set()).add(snapshot_id)
    result: list[dict[str, Any]] = []
    for row in grouped.values():
        snapshot_ids = sorted(row.pop("_snapshot_ids", set()), key=_snapshot_id_sort_key)
        row["snapshot_ids"] = json.dumps(snapshot_ids)
        row["snapshot_count"] = str(len(snapshot_ids)) if snapshot_ids else None
        if snapshot_ids:
            row["snapshot_id"] = snapshot_ids[0]
        result.append(row)
    return sorted(result, key=lambda row: (str(row.get("prefetch_name") or ""), str(row.get("snapshot_id") or "")))


def _dedupe_promoted_prefetch_run_times(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("case_id") or ""),
            str(row.get("image_id") or ""),
            str(row.get("computer_id") or ""),
            str(row.get("prefetch_name") or ""),
            str(row.get("prefetch_hash") or ""),
            str(row.get("run_time_utc") or ""),
        )
        existing = grouped.get(key)
        if existing is None or _prefetch_snapshot_sort_key(row) < _prefetch_snapshot_sort_key(existing):
            merged = dict(row)
            if existing:
                merged["_snapshot_ids"] = set(existing.get("_snapshot_ids") or [])
            else:
                merged["_snapshot_ids"] = set()
            grouped[key] = merged
            existing = merged
        snapshot_id = str(row.get("snapshot_id") or "").strip()
        if snapshot_id:
            existing.setdefault("_snapshot_ids", set()).add(snapshot_id)
    result: list[dict[str, Any]] = []
    for row in grouped.values():
        snapshot_ids = sorted(row.pop("_snapshot_ids", set()), key=_snapshot_id_sort_key)
        row["snapshot_ids"] = json.dumps(snapshot_ids)
        row["snapshot_count"] = str(len(snapshot_ids)) if snapshot_ids else None
        if snapshot_ids:
            row["snapshot_id"] = snapshot_ids[0]
        result.append(row)
    return sorted(result, key=lambda row: (str(row.get("prefetch_name") or ""), str(row.get("run_time_utc") or "")))


def _clear_promoted_prefetch_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    snapshot_ids: list[str],
) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    params: list[object] = [case_id, image_id, "VSC", *snapshot_ids]
    where = f"case_id = ? AND image_id = ? AND source_scope = ? AND snapshot_id IN ({placeholders})"
    if db.analytics is not None:
        conn = db.analytics._connect(case_id)
        for table in ("prefetch_run_times", "prefetch_items"):
            if db.analytics._table_exists(conn, table):
                _ensure_promoted_prefetch_columns(conn, table)
        db.analytics.delete_where("prefetch_run_times", where, params)
        db.analytics.delete_where("prefetch_items", where, params)
    if not db.analytics_only:
        db.conn.execute(f"DELETE FROM prefetch_run_times WHERE {where}", params)
        db.conn.execute(f"DELETE FROM prefetch_items WHERE {where}", params)
        db.conn.commit()


def _ensure_promoted_prefetch_columns(conn: duckdb.DuckDBPyConnection, table: str) -> None:
    columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
    for column in ("source_scope", "snapshot_id", "snapshot_ids", "snapshot_count", "snapshot_index", "snapshot_created_utc"):
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR")


def _snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> list[dict[str, Any]]:
    run_times_by_item: dict[str, list[str]] = {}
    tables = {row[0] for row in conn.execute("SHOW TABLES").fetchall()}
    if "vsc_prefetch_run_times" in tables:
        for item_id, run_time in conn.execute(
            """
            SELECT prefetch_item_id, run_time_utc
            FROM vsc_prefetch_run_times
            WHERE case_id = ? AND image_id = ?
            ORDER BY run_time_utc
            """,
            [case_id, image_id],
        ).fetchall():
            if item_id and run_time:
                run_times_by_item.setdefault(str(item_id), []).append(str(run_time))
    rows = conn.execute(
        """
        SELECT * FROM vsc_prefetch_items
        WHERE case_id = ? AND image_id = ?
        ORDER BY snapshot_index, prefetch_name
        """,
        [case_id, image_id],
    ).fetchall()
    columns = [item[0] for item in conn.description]
    result = [dict(zip(columns, row)) for row in rows]
    for row in result:
        row["last_run_times_utc"] = json.dumps(run_times_by_item.get(str(row.get("id")), []))
    return result


def _live_prefetch_rows(db: Database, *, case_id: str) -> list[dict[str, Any]]:
    case = db.get_case(case_id)
    duckdb_path = case.root / "analytics" / "events.duckdb"
    if duckdb_path.exists():
        conn = duckdb.connect(str(duckdb_path), read_only=True)
        try:
            tables = {row[0] for row in conn.execute("SHOW TABLES").fetchall()}
            if "prefetch_items" in tables:
                run_times_by_item: dict[str, list[str]] = {}
                if "prefetch_run_times" in tables:
                    for item_id, run_time in conn.execute(
                        """
                        SELECT prefetch_item_id, run_time_utc
                        FROM prefetch_run_times
                        WHERE case_id = ?
                        ORDER BY run_time_utc
                        """,
                        [case_id],
                    ).fetchall():
                        if item_id and run_time:
                            run_times_by_item.setdefault(str(item_id), []).append(str(run_time))
                rows = conn.execute(
                    """
                    SELECT id, prefetch_name, executable_name, prefetch_hash, run_count,
                           last_run_time_utc, artifact_path, original_path
                    FROM prefetch_items
                    WHERE case_id = ?
                    """,
                    [case_id],
                ).fetchall()
                columns = [item[0] for item in conn.description]
                normalized_rows = [dict(zip(columns, row)) for row in rows]
                for row in normalized_rows:
                    row["last_run_times_utc"] = json.dumps(run_times_by_item.get(str(row.get("id")), []))
                return _dedupe_prefetch_rows(normalized_rows)
        finally:
            conn.close()
    sqlite_rows = db.conn.execute(
        """
        SELECT id, prefetch_name, executable_name, prefetch_hash, run_count,
               last_run_time_utc, artifact_path, original_path
        FROM prefetch_items
        WHERE case_id = ?
        """,
        [case_id],
    ).fetchall()
    run_time_rows = db.conn.execute(
        """
        SELECT prefetch_item_id, run_time_utc
        FROM prefetch_run_times
        WHERE case_id = ?
        ORDER BY run_time_utc
        """,
        [case_id],
    ).fetchall()
    run_times_by_item: dict[str, list[str]] = {}
    for row in run_time_rows:
        if row["prefetch_item_id"] and row["run_time_utc"]:
            run_times_by_item.setdefault(str(row["prefetch_item_id"]), []).append(str(row["run_time_utc"]))
    normalized_rows = [dict(row) for row in sqlite_rows]
    for row in normalized_rows:
        row["last_run_times_utc"] = json.dumps(run_times_by_item.get(str(row.get("id")), []))
    return _dedupe_prefetch_rows(normalized_rows)


def _prefetch_comparison_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC Prefetch Comparison",
        "",
        "## Summary",
        "",
        f"- Live Prefetch rows: {summary['live_prefetch_count']}",
        f"- VSC Prefetch rows parsed: {summary['vsc_prefetch_count']}",
        f"- Usable VSC Prefetch rows: {summary['usable_vsc_prefetch_count']}",
        f"- Unusable/filename-only VSC Prefetch rows: {summary['unusable_vsc_prefetch_count']}",
        f"- Snapshots parsed: {summary['snapshot_count']}",
        f"- Findings: {summary['finding_count']}",
        f"- Present in VSC but absent live: {summary['only_in_vsc_count']}",
        f"- Changed from live: {summary['changed_from_live_count']}",
        f"- Unique historical run-time slots not present live: {summary['unique_historical_run_time_count']}",
        "",
        "## Snapshot Counts",
        "",
        "| Snapshot | Created | Prefetch files | Usable | Unusable | Only in snapshot | Changed from live | Historical run-time slots |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in comparison["snapshots"]:
        lines.append(
            "| {snapshot_id} | {created} | {prefetch_count} | {usable} | {unusable} | {only} | {changed} | {run_count} |".format(
                snapshot_id=item["snapshot_id"],
                created=item.get("snapshot_created_utc") or "",
                prefetch_count=item["prefetch_count"],
                usable=item["usable_prefetch_count"],
                unusable=item["unusable_prefetch_count"],
                only=item["only_in_snapshot_count"],
                changed=item["changed_from_live_count"],
                run_count=item["historical_run_time_count"],
            )
        )
    if comparison.get("unusable_rows"):
        lines.extend(["", "## Unusable Prefetch Rows", ""])
        lines.append(
            "These files were extracted but did not contain parseable Prefetch content, so they were not used for delta findings."
        )
        lines.extend(["", "| Snapshot | Prefetch | Status | Note |", "| --- | --- | --- | --- |"])
        for item in comparison["unusable_rows"][:100]:
            lines.append(
                f"| {item['snapshot_id']} | `{item['prefetch_name']}` | "
                f"{item.get('parser_status') or ''} | {item.get('parser_note') or ''} |"
            )
        if len(comparison["unusable_rows"]) > 100:
            lines.append(f"| ... | {len(comparison['unusable_rows']) - 100} more rows omitted |  |  |")
    if failures:
        lines.extend(["", "## Failures", ""])
        for failure in failures:
            lines.append(f"- `{failure['snapshot_id']}`: {failure['error']}")
    lines.extend(["", "## Not Present In Live Prefetch", ""])
    missing = [item for item in comparison["findings"] if item["type"] == "not_present_live"]
    if missing:
        lines.extend(["| Prefetch | Executable | Snapshots | Last run | Run count |", "| --- | --- | --- | --- | ---: |"])
        for item in missing:
            lines.append(
                f"| `{item['prefetch_name']}` | `{item.get('executable_name') or ''}` | "
                f"{', '.join(item['snapshots'])} | {item.get('last_run_time_utc') or ''} | {item.get('run_count') or ''} |"
            )
    else:
        lines.append("No Prefetch files were found only in VSC snapshots.")
    lines.extend(["", "## Changed From Live Prefetch", ""])
    changed = [item for item in comparison["findings"] if item["type"] == "differs_from_live"]
    if changed:
        lines.extend(
            [
                "| Prefetch | Executable | Snapshots | Live last run | Historical run-time slots recovered | Snapshot last runs |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in changed:
            lines.append(
                f"| `{item['prefetch_name']}` | `{item.get('executable_name') or ''}` | "
                f"{', '.join(item['snapshots'])} | "
                f"{item.get('live_last_run_time_utc') or ''} | "
                f"{', '.join(item.get('historical_run_times') or [])} | "
                f"{_compact_mapping(item.get('snapshot_last_run_times') or {})} |"
            )
    else:
        lines.append("No parsed Prefetch differences were found against live Prefetch.")
    lines.extend(["", "## Processing", ""])
    for result in snapshot_results:
        lines.append(
            f"- `{result['snapshot_id']}` parsed {result['parsed_rows']} Prefetch files "
            f"({result.get('usable_rows', 0)} usable, {result.get('unusable_rows', 0)} unusable) "
            f"from `{result['manifest'].get('destination_path')}`"
        )
    return "\n".join(lines) + "\n"


def _snapshot_from_payload(payload: dict[str, Any]) -> VscSnapshot:
    return VscSnapshot(
        index=int(payload["index"]),
        snapshot_id=str(payload.get("snapshot_id") or ""),
        identifier=str(payload.get("identifier") or ""),
        shadow_copy_set_id=str(payload.get("shadow_copy_set_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
    )


def _differs_from_live(snapshot_row: dict[str, Any], live_row: dict[str, Any]) -> bool:
    snapshot_times = set(_run_times(snapshot_row))
    live_times = set(_run_times(live_row))
    return bool(snapshot_times - live_times)


def _differs_from_live_rows(snapshot_row: dict[str, Any], live_rows: list[dict[str, Any]]) -> bool:
    return bool(set(_run_times(snapshot_row)) - _all_run_times(live_rows))


def _historical_run_time_count(snapshot_row: dict[str, Any], live_rows: list[dict[str, Any]]) -> int:
    return len(set(_run_times(snapshot_row)) - _all_run_times(live_rows))


def _historical_run_times(snapshot_rows: list[dict[str, Any]], live_rows: list[dict[str, Any]]) -> list[str]:
    live_times = _all_run_times(live_rows)
    times: set[str] = set()
    for row in snapshot_rows:
        times.update(set(_run_times(row)) - live_times)
    return sorted(times)


def _all_run_times(rows: list[dict[str, Any]]) -> set[str]:
    times: set[str] = set()
    for row in rows:
        times.update(_run_times(row))
    return times


def _live_rows_for_name(groups: dict[str, list[dict[str, Any]]], prefetch_name: str) -> list[dict[str, Any]]:
    return [candidate for candidate in groups.get(prefetch_name, []) if candidate.get("source") == "live"]


def _representative_live_row(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    return sorted(rows, key=lambda row: _run_times(row)[-1] if _run_times(row) else "")[-1]


def _run_times(row: dict[str, Any]) -> list[str]:
    values: list[str] = []
    raw_many = row.get("last_run_times_utc")
    if raw_many:
        if isinstance(raw_many, list):
            values.extend(str(value) for value in raw_many if value)
        else:
            try:
                parsed = json.loads(str(raw_many))
                if isinstance(parsed, list):
                    values.extend(str(value) for value in parsed if value)
            except json.JSONDecodeError:
                pass
    single = _text(row.get("last_run_time_utc"))
    if single:
        values.append(single)
    return sorted(set(values))


def _usable_for_delta(row: dict[str, Any]) -> bool:
    return bool(row.get("prefetch_hash") or row.get("last_run_time_utc") or row.get("run_count") is not None)


def _parser_status(path: Path, parsed: dict[str, Any]) -> str:
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        sample = b""
    if sample and not any(sample):
        return "zero_filled"
    note = str(parsed.get("parser_note") or "")
    if "filename metadata only" in note:
        return "filename_only"
    if "decompression failed" in note:
        return "parse_failed"
    return "parsed"


def _manifest_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in manifest.items()
        if key in {"relative_path", "source_path", "destination_path", "file_count", "byte_count", "created_at"}
    }


def _dedupe_prefetch_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = str(row.get("prefetch_name") or "")
        if not name:
            continue
        existing = by_name.get(name)
        if existing is None or _prefetch_sort_key(row) > _prefetch_sort_key(existing):
            by_name[name] = row
    return [by_name[name] for name in sorted(by_name)]


def _prefetch_sort_key(row: dict[str, Any]) -> tuple[str, int]:
    return (_text(row.get("last_run_time_utc")) or "", _int_or_none(row.get("run_count")) or -1)


def _prefetch_snapshot_sort_key(row: dict[str, Any]) -> tuple[int, str]:
    snapshot_index = _int_or_none(row.get("snapshot_index"))
    if snapshot_index is None:
        snapshot_index = _snapshot_id_sort_key(str(row.get("snapshot_id") or ""))
    return (snapshot_index, str(row.get("snapshot_id") or ""))


def _snapshot_id_sort_key(value: object) -> int:
    text = str(value or "")
    match = re.search(r"(\d+)", text)
    if not match:
        return 0
    return int(match.group(1))


def _canonical_json_list(values: list[str]) -> str:
    return json.dumps(sorted({str(value) for value in values if value}))


def _add_column_if_missing(conn: duckdb.DuckDBPyConnection, table: str, column: str, column_type: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")


def _md5(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ns_to_iso(value: int) -> str:
    dt = datetime.fromtimestamp(value / 1_000_000_000, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int_or_none(value: object) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _relative_to_work(work_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(work_dir)).replace("\\", "/")
    except ValueError:
        return str(path)


def _compact_mapping(value: dict[str, Any]) -> str:
    return ", ".join(f"{key}: {item}" for key, item in value.items())


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
