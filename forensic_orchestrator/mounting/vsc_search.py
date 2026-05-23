from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError
from forensic_orchestrator.tools.normalized import normalized_windows_search_file_row, normalized_windows_search_gather_log_row
from forensic_orchestrator.tools.windows_search_ese import parse_windows_search_ese_to_csv
from forensic_orchestrator.tools.windows_search_gather import parse_windows_search_gather_logs_to_csv

from .vshadow import VscSnapshot, discover_vsc_snapshots, mount_vsc_snapshot, unmount_vsc


SEARCH_FILE_COLUMNS = [
    "case_id", "image_id", "snapshot_id", "snapshot_index", "snapshot_created_utc",
    "id", "computer_id", "tool_output_id", "tool_name", "source_csv", "row_number",
    "work_id", "gather_time", "item_path", "item_url", "folder_path", "file_name",
    "file_extension", "item_type", "date_created", "date_modified", "date_accessed",
    "date_imported", "size", "owner", "computer_name", "is_deleted", "is_folder",
    "record_signature", "parsed_at",
]

SEARCH_GATHER_COLUMNS = [
    "case_id", "image_id", "snapshot_id", "snapshot_index", "snapshot_created_utc",
    "id", "computer_id", "tool_output_id", "tool_name", "source_csv", "row_number",
    "source_file", "source_name", "log_type", "line_number", "timestamp_utc",
    "filetime_hex", "time_low_hex", "time_high_hex", "item_url", "item_path",
    "item_scheme", "is_deleted_path", "status_hex", "crawl_code_hex", "scope_id",
    "document_id", "record_signature", "parsed_at",
]

SEARCH_SOURCE_COLUMNS = [
    "case_id", "image_id", "snapshot_id", "snapshot_index", "snapshot_created_utc",
    "source_root", "source_root_exists", "windows_edb_path", "windows_edb_exists",
    "windows_edb_size", "ese_support_file_count", "gather_source",
    "gather_log_count", "windows11_sqlite_count", "windows11_sqlite_paths",
    "notes", "parsed_at",
]


def run_vsc_windows_search_scan(
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
        raise MountError("No VSC snapshots selected for Windows Search scan")

    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_tables(conn)
        snapshot_ids = [f"vss{snapshot.index}" for snapshot in snapshots]
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
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
                rows = parse_vsc_windows_search_snapshot(
                    paths=paths,
                    case_id=case_id,
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                    mount_path=Path(mount["volume_mount_path"]),
                )
                _insert_rows(conn, "vsc_windows_search_files", SEARCH_FILE_COLUMNS, rows["files"])
                _insert_rows(conn, "vsc_windows_search_gather_logs", SEARCH_GATHER_COLUMNS, rows["gather_logs"])
                _insert_rows(conn, "vsc_windows_search_sources", SEARCH_SOURCE_COLUMNS, rows["sources"])
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "file_rows": len(rows["files"]),
                        "gather_rows": len(rows["gather_logs"]),
                        "warnings": rows["warnings"],
                        "mount_path": mount["volume_mount_path"],
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

        comparison = compare_windows_search_snapshots_from_db(conn=conn, db=db, case_id=case_id, image_id=image.id)
        promotion = promote_vsc_windows_search_rows(
            db=db,
            sidecar_db_path=db_path,
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id or "vsc",
        )
        comparison["summary"]["promoted_vsc_file_rows"] = promotion["windows_search_files"]
        comparison["summary"]["promoted_vsc_gather_rows"] = promotion["windows_search_gather_logs"]
        comparison["summary"]["promoted_vsc_file_duplicate_signatures"] = promotion["file_duplicate_signatures"]
        comparison["summary"]["promoted_vsc_gather_duplicate_signatures"] = promotion["gather_duplicate_signatures"]
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "windows-search-vsc-comparison.md"
        report_path.write_text(
            _search_markdown(comparison, snapshot_results, failures, started_at=started_at, ended_at=ended_at),
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
        _write_json(paths.vsc_work_dir(case_id) / "windows-search-scan.json", payload)
        return payload
    finally:
        conn.close()


def parse_vsc_windows_search_snapshot(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
    mount_path: Path,
) -> dict[str, Any]:
    source_root = mount_path / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows"
    output_root = paths.vsc_work_dir(case_id) / "outputs" / snapshot_id
    rows: dict[str, list[dict[str, Any]]] = {"files": [], "gather_logs": [], "sources": []}
    warnings: list[str] = []
    source_inventory = _inventory_search_sources(
        case_id=case_id,
        image_id=image_id,
        snapshot=snapshot,
        snapshot_id=snapshot_id,
        mount_path=mount_path,
    )
    rows["sources"].append(source_inventory)

    if source_inventory["windows_edb_exists"] == "true":
        ese_out = output_root / "WindowsSearchESEParser"
        try:
            csv_path = parse_windows_search_ese_to_csv(source_root, ese_out)
            rows["files"].extend(_parse_search_file_csv(case_id, image_id, snapshot, snapshot_id, csv_path))
        except Exception as exc:
            warnings.append(f"Windows Search ESE parse failed: {exc}")
    elif source_inventory["source_root_exists"] == "true":
        warnings.append("Windows.edb absent from this VSC snapshot; ESE parse skipped")
    else:
        warnings.append(f"Windows Search index path not found: {source_root}")

    gather_source = source_root / "GatherLogs" / "SystemIndex"
    gather_out = output_root / "WindowsSearchGatherParser"
    csv_path = parse_windows_search_gather_logs_to_csv(gather_source, gather_out)
    rows["gather_logs"].extend(_parse_gather_csv(case_id, image_id, snapshot, snapshot_id, csv_path))
    rows["warnings"] = warnings
    return rows


def _inventory_search_sources(
    *,
    case_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
    mount_path: Path,
) -> dict[str, Any]:
    source_root = mount_path / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows"
    windows_edb = source_root / "Windows.edb"
    gather_source = source_root / "GatherLogs" / "SystemIndex"
    sqlite_candidates = _windows11_sqlite_candidates(mount_path)
    notes: list[str] = []
    if source_root.exists() and not windows_edb.exists():
        notes.append("Windows Search ESE database absent from snapshot")
    if sqlite_candidates:
        notes.append("Windows Search SQLite candidate(s) found; not parsed yet")
    if not source_root.exists():
        notes.append("Windows Search ESE source path absent from snapshot")
    return {
        "case_id": case_id,
        "image_id": image_id,
        "snapshot_id": snapshot_id,
        "snapshot_index": str(snapshot.index),
        "snapshot_created_utc": snapshot.created_utc,
        "source_root": str(source_root),
        "source_root_exists": _bool_text(source_root.exists()),
        "windows_edb_path": str(windows_edb),
        "windows_edb_exists": _bool_text(windows_edb.exists()),
        "windows_edb_size": str(windows_edb.stat().st_size) if windows_edb.exists() else "",
        "ese_support_file_count": str(_count_ese_support_files(source_root)),
        "gather_source": str(gather_source),
        "gather_log_count": str(_count_gather_logs(gather_source)),
        "windows11_sqlite_count": str(len(sqlite_candidates)),
        "windows11_sqlite_paths": json.dumps([str(path) for path in sqlite_candidates[:50]]),
        "notes": "; ".join(notes),
        "parsed_at": utc_now(),
    }


def _count_ese_support_files(source_root: Path) -> int:
    if not source_root.exists():
        return 0
    suffixes = {".jcp", ".jfm", ".jrs", ".jtx", ".log"}
    return sum(1 for path in source_root.iterdir() if path.is_file() and path.suffix.lower() in suffixes)


def _count_gather_logs(gather_source: Path) -> int:
    if not gather_source.exists():
        return 0
    return sum(1 for path in gather_source.rglob("*") if path.is_file() and path.suffix.lower() in {".gthr", ".crwl"})


def _windows11_sqlite_candidates(mount_path: Path) -> list[Path]:
    roots = [mount_path / "ProgramData" / "Microsoft" / "Search" / "Data"]
    users_root = mount_path / "Users"
    if users_root.exists():
        for user_dir in _safe_iterdir(users_root):
            package_root = user_dir / "AppData" / "Local" / "Packages"
            if not package_root.exists():
                continue
            for package_dir in _safe_iterdir(package_root):
                if package_dir.name.lower().startswith("microsoft.windows.search_"):
                    roots.append(package_dir)
    candidates: list[Path] = []
    suffixes = {".db", ".sqlite", ".sqlite3"}
    for root in roots:
        if not root.exists():
            continue
        for path in _safe_rglob(root):
            if path.is_file() and path.suffix.lower() in suffixes and _looks_like_windows_search_sqlite(path):
                candidates.append(path)
    return sorted(candidates)


def _safe_iterdir(root: Path) -> list[Path]:
    try:
        return list(root.iterdir())
    except OSError:
        return []


def _safe_rglob(root: Path) -> list[Path]:
    try:
        return list(root.rglob("*"))
    except OSError:
        return []


def _looks_like_windows_search_sqlite(path: Path) -> bool:
    text = str(path).replace("\\", "/").lower()
    return "/microsoft/search/" in text or "/microsoft.windows.search_" in text


def compare_windows_search_snapshots_from_db(
    *,
    conn: duckdb.DuckDBPyConnection,
    db: Database,
    case_id: str,
    image_id: str,
) -> dict[str, Any]:
    case = db.get_case(case_id)
    live_db = case.root / "analytics" / "events.duckdb"
    conn.execute(f"ATTACH IF NOT EXISTS '{str(live_db).replace("'", "''")}' AS live (READ_ONLY)")
    conn.execute(
        """
        CREATE OR REPLACE TEMP TABLE live_search_file_signatures AS
        SELECT DISTINCT lower(concat_ws('|',
          COALESCE(work_id, ''),
          COALESCE(gather_time, ''),
          lower(replace(COALESCE(item_path, ''), chr(92), '/')),
          lower(COALESCE(item_url, '')),
          COALESCE(date_modified, ''),
          COALESCE(size, ''),
          COALESCE(is_deleted, '')
        )) AS record_signature
        FROM live.windows_search_files
        WHERE case_id = ?
        """,
        [case_id],
    )
    conn.execute(
        """
        CREATE OR REPLACE TEMP TABLE live_search_gather_signatures AS
        SELECT DISTINCT lower(concat_ws('|',
          COALESCE(timestamp_utc, ''),
          lower(replace(COALESCE(item_path, ''), chr(92), '/')),
          lower(COALESCE(item_url, '')),
          COALESCE(status_hex, ''),
          COALESCE(crawl_code_hex, ''),
          COALESCE(document_id, '')
        )) AS record_signature
        FROM live.windows_search_gather_logs
        WHERE case_id = ?
        """,
        [case_id],
    )
    file_examples = conn.execute(
        """
        SELECT snapshot_id, snapshot_created_utc, gather_time, item_path, item_url,
               file_name, date_modified, size, is_deleted
        FROM vsc_windows_search_files v
        WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
          AND NOT EXISTS (
            SELECT 1 FROM live_search_file_signatures live
            WHERE live.record_signature = v.record_signature
          )
        ORDER BY gather_time, item_path, item_url
        LIMIT 100
        """,
        [case_id, image_id],
    ).fetchall()
    gather_examples = conn.execute(
        """
        SELECT snapshot_id, snapshot_created_utc, timestamp_utc, item_path, item_url,
               log_type, status_hex, crawl_code_hex, document_id
        FROM vsc_windows_search_gather_logs v
        WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
          AND NOT EXISTS (
            SELECT 1 FROM live_search_gather_signatures live
            WHERE live.record_signature = v.record_signature
          )
        ORDER BY timestamp_utc, item_path, item_url
        LIMIT 100
        """,
        [case_id, image_id],
    ).fetchall()
    summary = {
        "vsc_windows_search_file_rows": _count_sql(conn, "SELECT COUNT(*) FROM vsc_windows_search_files WHERE case_id = ? AND image_id = ?", [case_id, image_id]),
        "vsc_windows_search_gather_rows": _count_sql(conn, "SELECT COUNT(*) FROM vsc_windows_search_gather_logs WHERE case_id = ? AND image_id = ?", [case_id, image_id]),
        "snapshots_with_windows_edb": _count_sql(conn, "SELECT COUNT(*) FROM vsc_windows_search_sources WHERE case_id = ? AND image_id = ? AND windows_edb_exists = 'true'", [case_id, image_id]),
        "snapshots_with_gather_logs": _count_sql(conn, "SELECT COUNT(*) FROM vsc_windows_search_sources WHERE case_id = ? AND image_id = ? AND CAST(COALESCE(NULLIF(gather_log_count, ''), '0') AS INTEGER) > 0", [case_id, image_id]),
        "snapshots_with_windows11_sqlite_candidates": _count_sql(conn, "SELECT COUNT(*) FROM vsc_windows_search_sources WHERE case_id = ? AND image_id = ? AND CAST(COALESCE(NULLIF(windows11_sqlite_count, ''), '0') AS INTEGER) > 0", [case_id, image_id]),
        "unique_vsc_file_records_not_live": _count_sql(
            conn,
            """
            SELECT COUNT(DISTINCT record_signature)
            FROM vsc_windows_search_files v
            WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
              AND NOT EXISTS (
                SELECT 1 FROM live_search_file_signatures live
                WHERE live.record_signature = v.record_signature
              )
            """,
            [case_id, image_id],
        ),
        "unique_vsc_gather_records_not_live": _count_sql(
            conn,
            """
            SELECT COUNT(DISTINCT record_signature)
            FROM vsc_windows_search_gather_logs v
            WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
              AND NOT EXISTS (
                SELECT 1 FROM live_search_gather_signatures live
                WHERE live.record_signature = v.record_signature
              )
            """,
            [case_id, image_id],
        ),
    }
    return {
        "summary": summary,
        "snapshot_counts": _counts_by_snapshot(conn, case_id, image_id),
        "source_rows": _source_rows(conn, case_id, image_id),
        "file_examples": [_row(["snapshot_id", "snapshot_created_utc", "gather_time", "item_path", "item_url", "file_name", "date_modified", "size", "is_deleted"], row) for row in file_examples],
        "gather_examples": [_row(["snapshot_id", "snapshot_created_utc", "timestamp_utc", "item_path", "item_url", "log_type", "status_hex", "crawl_code_hex", "document_id"], row) for row in gather_examples],
    }


def promote_vsc_windows_search_rows(
    *,
    db: Database,
    sidecar_db_path: Path,
    case_id: str,
    image_id: str,
    computer_id: str,
) -> dict[str, int]:
    case = db.get_case(case_id)
    live_db = case.root / "analytics" / "events.duckdb"
    if not sidecar_db_path.is_file():
        raise MountError(f"VSC sidecar database not found: {sidecar_db_path}")
    now = utc_now().replace("'", "''")
    conn = duckdb.connect(str(live_db))
    try:
        _ensure_main_windows_search_columns(conn)
        conn.execute("DELETE FROM windows_search_files WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'", [case_id, image_id])
        conn.execute("DELETE FROM windows_search_gather_logs WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'", [case_id, image_id])
        _create_live_search_signature_tables(conn, case_id=case_id)
        sidecar_literal = str(sidecar_db_path).replace("'", "''")
        conn.execute(f"ATTACH IF NOT EXISTS '{sidecar_literal}' AS sidecar (READ_ONLY)")
        conn.execute(
            f"""
            INSERT INTO windows_search_files (
              id, case_id, computer_id, image_id, tool_output_id, tool_name, source_csv,
              row_number, work_id, gather_time, item_path, item_url, folder_path,
              file_name, file_extension, item_type, date_created, date_modified,
              date_accessed, date_imported, size, owner, computer_name, is_deleted,
              is_folder, source_scope, snapshot_id, snapshot_ids, snapshot_count,
              snapshot_index, snapshot_created_utc, row_json, created_at
            )
            WITH candidates AS (
              SELECT *
              FROM sidecar.vsc_windows_search_files v
              WHERE v.case_id = ? AND v.image_id = ?
                AND COALESCE(v.record_signature, '') != ''
                AND NOT EXISTS (
                  SELECT 1 FROM live_search_file_signatures live
                  WHERE live.record_signature = v.record_signature
                )
            ),
            grouped AS (
              SELECT
                record_signature,
                to_json(list_sort(list_distinct(list(snapshot_id)))) AS snapshot_ids,
                CAST(COUNT(DISTINCT snapshot_id) AS VARCHAR) AS snapshot_count
              FROM candidates
              GROUP BY record_signature
            ),
            ranked AS (
              SELECT
                c.*,
                g.snapshot_ids AS grouped_snapshot_ids,
                g.snapshot_count AS grouped_snapshot_count,
                row_number() OVER (
                  PARTITION BY c.record_signature
                  ORDER BY try_cast(c.snapshot_index AS INTEGER), c.snapshot_id, gather_time, try_cast(c.row_number AS INTEGER)
                ) AS rn
              FROM candidates c
              JOIN grouped g USING (record_signature)
            )
            SELECT
              'vsc-search-file-' || md5(case_id || '|' || image_id || '|' || record_signature) AS id,
              case_id,
              ? AS computer_id,
              image_id,
              'vsc-WindowsSearchESEParser' AS tool_output_id,
              tool_name,
              'vsc://windows-search/files' AS source_csv,
              try_cast(row_number AS INTEGER) AS row_number,
              work_id,
              gather_time,
              item_path,
              item_url,
              folder_path,
              file_name,
              file_extension,
              item_type,
              date_created,
              date_modified,
              date_accessed,
              date_imported,
              size,
              owner,
              computer_name,
              is_deleted,
              is_folder,
              'VSC' AS source_scope,
              snapshot_id,
              grouped_snapshot_ids AS snapshot_ids,
              grouped_snapshot_count AS snapshot_count,
              snapshot_index,
              snapshot_created_utc,
              '{{}}' AS row_json,
              '{now}' AS created_at
            FROM ranked
            WHERE rn = 1
            """,
            [case_id, image_id, computer_id],
        )
        conn.execute(
            f"""
            INSERT INTO windows_search_gather_logs (
              id, case_id, computer_id, image_id, tool_output_id, tool_name, source_csv,
              row_number, source_file, source_name, log_type, line_number,
              timestamp_utc, filetime_hex, time_low_hex, time_high_hex, item_url,
              item_path, item_scheme, is_deleted_path, status_hex, crawl_code_hex,
              scope_id, document_id, source_scope, snapshot_id, snapshot_ids,
              snapshot_count, snapshot_index, snapshot_created_utc, raw_fields_json,
              created_at
            )
            WITH candidates AS (
              SELECT *
              FROM sidecar.vsc_windows_search_gather_logs v
              WHERE v.case_id = ? AND v.image_id = ?
                AND COALESCE(v.record_signature, '') != ''
                AND NOT EXISTS (
                  SELECT 1 FROM live_search_gather_signatures live
                  WHERE live.record_signature = v.record_signature
                )
            ),
            grouped AS (
              SELECT
                record_signature,
                to_json(list_sort(list_distinct(list(snapshot_id)))) AS snapshot_ids,
                CAST(COUNT(DISTINCT snapshot_id) AS VARCHAR) AS snapshot_count
              FROM candidates
              GROUP BY record_signature
            ),
            ranked AS (
              SELECT
                c.*,
                g.snapshot_ids AS grouped_snapshot_ids,
                g.snapshot_count AS grouped_snapshot_count,
                row_number() OVER (
                  PARTITION BY c.record_signature
                  ORDER BY try_cast(c.snapshot_index AS INTEGER), c.snapshot_id, timestamp_utc, try_cast(c.row_number AS INTEGER)
                ) AS rn
              FROM candidates c
              JOIN grouped g USING (record_signature)
            )
            SELECT
              'vsc-search-gather-' || md5(case_id || '|' || image_id || '|' || record_signature) AS id,
              case_id,
              ? AS computer_id,
              image_id,
              'vsc-WindowsSearchGatherParser' AS tool_output_id,
              tool_name,
              'vsc://windows-search/gather' AS source_csv,
              try_cast(row_number AS INTEGER) AS row_number,
              source_file,
              source_name,
              log_type,
              try_cast(line_number AS INTEGER) AS line_number,
              timestamp_utc,
              filetime_hex,
              time_low_hex,
              time_high_hex,
              item_url,
              item_path,
              item_scheme,
              is_deleted_path,
              status_hex,
              crawl_code_hex,
              scope_id,
              document_id,
              'VSC' AS source_scope,
              snapshot_id,
              grouped_snapshot_ids AS snapshot_ids,
              grouped_snapshot_count AS snapshot_count,
              snapshot_index,
              snapshot_created_utc,
              '[]' AS raw_fields_json,
              '{now}' AS created_at
            FROM ranked
            WHERE rn = 1
            """,
            [case_id, image_id, computer_id],
        )
        return {
            "windows_search_files": _count_sql(
                conn,
                "SELECT COUNT(*) FROM windows_search_files WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'",
                [case_id, image_id],
            ),
            "windows_search_gather_logs": _count_sql(
                conn,
                "SELECT COUNT(*) FROM windows_search_gather_logs WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'",
                [case_id, image_id],
            ),
            "file_duplicate_signatures": _count_sql(
                conn,
                """
                SELECT COUNT(*) - COUNT(DISTINCT lower(concat_ws('|',
                  COALESCE(work_id, ''), COALESCE(gather_time, ''),
                  lower(replace(COALESCE(item_path, ''), chr(92), '/')),
                  lower(COALESCE(item_url, '')), COALESCE(date_modified, ''),
                  COALESCE(size, ''), COALESCE(is_deleted, '')
                )))
                FROM windows_search_files
                WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'
                """,
                [case_id, image_id],
            ),
            "gather_duplicate_signatures": _count_sql(
                conn,
                """
                SELECT COUNT(*) - COUNT(DISTINCT lower(concat_ws('|',
                  COALESCE(timestamp_utc, ''),
                  lower(replace(COALESCE(item_path, ''), chr(92), '/')),
                  lower(COALESCE(item_url, '')), COALESCE(status_hex, ''),
                  COALESCE(crawl_code_hex, ''), COALESCE(document_id, '')
                )))
                FROM windows_search_gather_logs
                WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'
                """,
                [case_id, image_id],
            ),
        }
    finally:
        conn.close()


def _parse_search_file_csv(case_id: str, image_id: str, snapshot: VscSnapshot, snapshot_id: str, csv_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), start=1):
            normalized = normalized_windows_search_file_row(
                case_id=case_id,
                computer_id="vsc",
                image_id=image_id,
                tool_output_id=f"{snapshot_id}-WindowsSearchESEParser",
                tool_name="WindowsSearchESEParser",
                source_csv=csv_path,
                row_number=row_number,
                row=dict(row),
            )
            _add_snapshot(normalized, snapshot=snapshot, snapshot_id=snapshot_id)
            normalized["record_signature"] = _file_signature(normalized)
            normalized["parsed_at"] = utc_now()
            rows.append(normalized)
    return rows


def _parse_gather_csv(case_id: str, image_id: str, snapshot: VscSnapshot, snapshot_id: str, csv_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), start=1):
            normalized = normalized_windows_search_gather_log_row(
                case_id=case_id,
                computer_id="vsc",
                image_id=image_id,
                tool_output_id=f"{snapshot_id}-WindowsSearchGatherParser",
                tool_name="WindowsSearchGatherParser",
                source_csv=csv_path,
                row_number=row_number,
                row=dict(row),
            )
            _add_snapshot(normalized, snapshot=snapshot, snapshot_id=snapshot_id)
            normalized["record_signature"] = _gather_signature(normalized)
            normalized["parsed_at"] = utc_now()
            rows.append(normalized)
    return rows


def _ensure_tables(conn: duckdb.DuckDBPyConnection) -> None:
    for table, columns in (
        ("vsc_windows_search_files", SEARCH_FILE_COLUMNS),
        ("vsc_windows_search_gather_logs", SEARCH_GATHER_COLUMNS),
        ("vsc_windows_search_sources", SEARCH_SOURCE_COLUMNS),
    ):
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(f'{column} VARCHAR' for column in columns)})")
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
        for column in columns:
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR")


def _clear_snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str, snapshot_ids: list[str]) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    for table in ("vsc_windows_search_files", "vsc_windows_search_gather_logs", "vsc_windows_search_sources"):
        conn.execute(
            f"DELETE FROM {table} WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
            [case_id, image_id, *snapshot_ids],
        )


def _create_live_search_signature_tables(conn: duckdb.DuckDBPyConnection, *, case_id: str) -> None:
    conn.execute(
        """
        CREATE OR REPLACE TEMP TABLE live_search_file_signatures AS
        SELECT DISTINCT lower(concat_ws('|',
          COALESCE(work_id, ''),
          COALESCE(gather_time, ''),
          lower(replace(COALESCE(item_path, ''), chr(92), '/')),
          lower(COALESCE(item_url, '')),
          COALESCE(date_modified, ''),
          COALESCE(size, ''),
          COALESCE(is_deleted, '')
        )) AS record_signature
        FROM windows_search_files
        WHERE case_id = ? AND COALESCE(source_scope, 'live') != 'VSC'
        """,
        [case_id],
    )
    conn.execute(
        """
        CREATE OR REPLACE TEMP TABLE live_search_gather_signatures AS
        SELECT DISTINCT lower(concat_ws('|',
          COALESCE(timestamp_utc, ''),
          lower(replace(COALESCE(item_path, ''), chr(92), '/')),
          lower(COALESCE(item_url, '')),
          COALESCE(status_hex, ''),
          COALESCE(crawl_code_hex, ''),
          COALESCE(document_id, '')
        )) AS record_signature
        FROM windows_search_gather_logs
        WHERE case_id = ? AND COALESCE(source_scope, 'live') != 'VSC'
        """,
        [case_id],
    )


def _ensure_main_windows_search_columns(conn: duckdb.DuckDBPyConnection) -> None:
    table_columns = {
        "windows_search_files": {
            "source_scope": "VARCHAR DEFAULT 'live'",
            "snapshot_id": "VARCHAR",
            "snapshot_ids": "VARCHAR",
            "snapshot_count": "VARCHAR",
            "snapshot_index": "VARCHAR",
            "snapshot_created_utc": "VARCHAR",
        },
        "windows_search_gather_logs": {
            "source_scope": "VARCHAR DEFAULT 'live'",
            "snapshot_id": "VARCHAR",
            "snapshot_ids": "VARCHAR",
            "snapshot_count": "VARCHAR",
            "snapshot_index": "VARCHAR",
            "snapshot_created_utc": "VARCHAR",
        },
    }
    for table, columns in table_columns.items():
        existing = {str(row[1]) for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
        for column, definition in columns.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _insert_rows(conn: duckdb.DuckDBPyConnection, table: str, columns: list[str], rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    placeholders = ", ".join("?" for _ in columns)
    values = [[str(row.get(column) or "") for column in columns] for row in rows]
    conn.executemany(f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})", values)


def _counts_by_snapshot(conn: duckdb.DuckDBPyConnection, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT s.snapshot_id,
               s.snapshot_index,
               s.snapshot_created_utc,
               COALESCE(f.file_rows, 0) AS file_rows,
               COALESCE(g.gather_rows, 0) AS gather_rows
        FROM vsc_windows_search_sources s
        LEFT JOIN (
          SELECT snapshot_id, COUNT(*) AS file_rows
          FROM vsc_windows_search_files
          WHERE case_id = ? AND image_id = ?
          GROUP BY 1
        ) f USING (snapshot_id)
        LEFT JOIN (
          SELECT snapshot_id, COUNT(*) AS gather_rows
          FROM vsc_windows_search_gather_logs
          WHERE case_id = ? AND image_id = ?
          GROUP BY 1
        ) g USING (snapshot_id)
        WHERE s.case_id = ? AND s.image_id = ?
        ORDER BY CAST(s.snapshot_index AS INTEGER)
        """,
        [case_id, image_id, case_id, image_id, case_id, image_id],
    ).fetchall()
    if rows:
        return [_row(["snapshot_id", "snapshot_index", "snapshot_created_utc", "file_rows", "gather_rows"], row) for row in rows]
    rows = conn.execute(
        """
        SELECT COALESCE(f.snapshot_id, g.snapshot_id) AS snapshot_id,
               COALESCE(f.snapshot_index, g.snapshot_index) AS snapshot_index,
               COALESCE(f.snapshot_created_utc, g.snapshot_created_utc) AS snapshot_created_utc,
               COALESCE(f.file_rows, 0) AS file_rows,
               COALESCE(g.gather_rows, 0) AS gather_rows
        FROM (
          SELECT snapshot_id, snapshot_index, snapshot_created_utc, COUNT(*) AS file_rows
          FROM vsc_windows_search_files
          WHERE case_id = ? AND image_id = ?
          GROUP BY 1, 2, 3
        ) f
        FULL OUTER JOIN (
          SELECT snapshot_id, snapshot_index, snapshot_created_utc, COUNT(*) AS gather_rows
          FROM vsc_windows_search_gather_logs
          WHERE case_id = ? AND image_id = ?
          GROUP BY 1, 2, 3
        ) g USING (snapshot_id)
        ORDER BY CAST(COALESCE(f.snapshot_index, g.snapshot_index) AS INTEGER)
        """,
        [case_id, image_id, case_id, image_id],
    ).fetchall()
    return [_row(["snapshot_id", "snapshot_index", "snapshot_created_utc", "file_rows", "gather_rows"], row) for row in rows]


def _source_rows(conn: duckdb.DuckDBPyConnection, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT snapshot_id, snapshot_index, snapshot_created_utc,
               source_root_exists, windows_edb_exists, windows_edb_size,
               ese_support_file_count, gather_log_count, windows11_sqlite_count,
               notes
        FROM vsc_windows_search_sources
        WHERE case_id = ? AND image_id = ?
        ORDER BY CAST(snapshot_index AS INTEGER)
        """,
        [case_id, image_id],
    ).fetchall()
    return [
        _row(
            [
                "snapshot_id", "snapshot_index", "snapshot_created_utc",
                "source_root_exists", "windows_edb_exists", "windows_edb_size",
                "ese_support_file_count", "gather_log_count",
                "windows11_sqlite_count", "notes",
            ],
            row,
        )
        for row in rows
    ]


def _add_snapshot(row: dict[str, Any], *, snapshot: VscSnapshot, snapshot_id: str) -> None:
    row["snapshot_id"] = snapshot_id
    row["snapshot_index"] = str(snapshot.index)
    row["snapshot_created_utc"] = snapshot.created_utc


def _file_signature(row: dict[str, Any]) -> str:
    return "|".join(
        [
            _text(row.get("work_id")),
            _text(row.get("gather_time")),
            _path_key(row.get("item_path")),
            _text(row.get("item_url")).lower(),
            _text(row.get("date_modified")),
            _text(row.get("size")),
            _text(row.get("is_deleted")),
        ]
    ).lower()


def _gather_signature(row: dict[str, Any]) -> str:
    return "|".join(
        [
            _text(row.get("timestamp_utc")),
            _path_key(row.get("item_path")),
            _text(row.get("item_url")).lower(),
            _text(row.get("status_hex")),
            _text(row.get("crawl_code_hex")),
            _text(row.get("document_id")),
        ]
    ).lower()


def _path_key(value: object) -> str:
    text = _text(value).replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    return "/" + text.strip("/").lower() if text else ""


def _count_sql(conn: duckdb.DuckDBPyConnection, sql: str, params: list[Any]) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def _row(columns: list[str], values: tuple[Any, ...]) -> dict[str, Any]:
    return dict(zip(columns, values, strict=False))


def _text(value: object) -> str:
    return "" if value is None else str(value)


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _snapshot_from_payload(payload: dict[str, Any]) -> VscSnapshot:
    return VscSnapshot(
        index=int(payload["index"]),
        snapshot_id=str(payload.get("snapshot_id") or ""),
        identifier=str(payload.get("identifier") or ""),
        shadow_copy_set_id=str(payload.get("shadow_copy_set_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
    )


def _search_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC Windows Search Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC Windows Search file rows parsed: {summary['vsc_windows_search_file_rows']}",
        f"- VSC Windows Search gather rows parsed: {summary['vsc_windows_search_gather_rows']}",
        f"- Snapshots with Windows.edb: {summary['snapshots_with_windows_edb']}",
        f"- Snapshots with Gather logs: {summary['snapshots_with_gather_logs']}",
        f"- Snapshots with Windows 11 SQLite candidates: {summary['snapshots_with_windows11_sqlite_candidates']}",
        f"- Unique VSC file records not present live: {summary['unique_vsc_file_records_not_live']}",
        f"- Unique VSC gather records not present live: {summary['unique_vsc_gather_records_not_live']}",
        f"- Promoted VSC Windows Search file rows in main DuckDB: {summary.get('promoted_vsc_file_rows', 0)}",
        f"- Promoted VSC Windows Search gather rows in main DuckDB: {summary.get('promoted_vsc_gather_rows', 0)}",
        f"- Promoted VSC Windows Search file duplicate signatures: {summary.get('promoted_vsc_file_duplicate_signatures', 0)}",
        f"- Promoted VSC Windows Search gather duplicate signatures: {summary.get('promoted_vsc_gather_duplicate_signatures', 0)}",
        "- Indexed body/content text is not stored in DuckDB by this scan.",
        "",
        "## Source Presence",
        "",
        "| Snapshot | Created | Search path present | Windows.edb | ESE support files | Gather logs | Win11 SQLite candidates | Notes |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | --- |",
    ]
    for row in comparison["source_rows"]:
        edb = "yes"
        if row.get("windows_edb_exists") != "true":
            edb = "no"
        elif row.get("windows_edb_size"):
            edb = f"yes ({row['windows_edb_size']} bytes)"
        lines.append(
            f"| {row['snapshot_id']} | {row.get('snapshot_created_utc') or ''} | {row.get('source_root_exists') or 'false'} | {edb} | "
            f"{row.get('ese_support_file_count') or 0} | {row.get('gather_log_count') or 0} | {row.get('windows11_sqlite_count') or 0} | {_md(row.get('notes'))} |"
        )
    lines.extend(
        [
            "",
        "## Snapshot Counts",
        "",
        "| Snapshot | Created | File rows | Gather rows |",
        "| --- | --- | ---: | ---: |",
        ]
    )
    for row in comparison["snapshot_counts"]:
        lines.append(f"| {row['snapshot_id']} | {row.get('snapshot_created_utc') or ''} | {row.get('file_rows') or 0} | {row.get('gather_rows') or 0} |")
    lines.extend(["", "## VSC-Only File Index Examples", "", "| Snapshot | Gather time | Path | URL | Deleted | Size |", "| --- | --- | --- | --- | --- | ---: |"])
    for row in comparison["file_examples"][:80]:
        lines.append(
            f"| {row['snapshot_id']} | {row.get('gather_time') or ''} | `{_md(row.get('item_path'))}` | `{_md(row.get('item_url'))}` | {row.get('is_deleted') or ''} | {row.get('size') or ''} |"
        )
    lines.extend(["", "## VSC-Only Gather Log Examples", "", "| Snapshot | Time | Path | URL | Status | Crawl |", "| --- | --- | --- | --- | --- | --- |"])
    for row in comparison["gather_examples"][:80]:
        lines.append(
            f"| {row['snapshot_id']} | {row.get('timestamp_utc') or ''} | `{_md(row.get('item_path'))}` | `{_md(row.get('item_url'))}` | `{_md(row.get('status_hex'))}` | `{_md(row.get('crawl_code_hex'))}` |"
        )
    warnings = [warning for item in snapshot_results for warning in item.get("warnings", [])]
    if warnings:
        lines.extend(["", "## Warnings", ""])
        for warning in warnings[:20]:
            lines.append(f"- `{_md(warning)}`")
    if failures:
        lines.extend(["", "## Failures", "", "| Snapshot | Error |", "| --- | --- |"])
        for failure in failures:
            lines.append(f"| {failure['snapshot_id']} | `{_md(failure['error'])}` |")
    lines.extend(["", "## Processing", ""])
    for item in snapshot_results:
        lines.append(
            f"- `{item['snapshot_id']}` parsed {item['file_rows']} file rows and {item['gather_rows']} gather rows from {item['started_at']} to {item['ended_at']}"
        )
    return "\n".join(lines).rstrip() + "\n"


def _md(value: object, limit: int = 160) -> str:
    text = _text(value).replace("|", "\\|").replace("\n", " ")
    if len(text) > limit:
        return text[: limit - 1] + "..."
    return text


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
