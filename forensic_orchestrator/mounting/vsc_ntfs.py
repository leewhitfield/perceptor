from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError, require_dependency
from forensic_orchestrator.tools.registry import resolve_dotnet_runtime

from .vshadow import VscSnapshot, discover_vsc_snapshots, extract_vsc_artifact, mount_vsc_snapshot, unmount_vsc


MFT_COLUMNS = [
    "case_id", "image_id", "snapshot_id", "snapshot_index", "snapshot_created_utc",
    "id", "computer_id", "tool_output_id", "tool_name", "source_csv", "row_number",
    "entry_number", "sequence_number", "in_use", "parent_entry_number",
    "parent_sequence_number", "parent_path", "file_name", "extension", "file_size",
    "is_directory", "has_ads", "is_ads", "si_flags", "reparse_target", "si_fn_copied",
    "created_si", "created_fn", "modified_si", "modified_fn", "record_changed_si",
    "record_changed_fn", "accessed_si", "accessed_fn", "source_file", "normalized_path",
    "path_key", "record_signature", "parsed_at",
]

USN_COLUMNS = [
    "case_id", "image_id", "snapshot_id", "snapshot_index", "snapshot_created_utc",
    "id", "computer_id", "tool_output_id", "tool_name", "source_csv", "row_number",
    "source_file", "update_sequence_number", "update_timestamp", "file_name", "extension",
    "file_reference_number", "file_reference_sequence_number", "parent_file_reference_number",
    "parent_file_reference_sequence_number", "full_path", "reason", "reason_flags",
    "file_attributes", "file_attributes_flags", "source_info", "security_id",
    "major_version", "minor_version", "record_length", "record_offset", "normalized_path",
    "path_key", "record_signature", "parsed_at",
]


def run_vsc_ntfs_delta_scan(
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
        raise MountError("No VSC snapshots selected for NTFS delta scan")

    require_dependency("icat")
    require_dependency("fls")
    mftecmd = _resolve_eztool("MFTECmd", "MFTECmd.dll")
    if not mftecmd:
        raise MountError("MFTECmd.dll not found. Set EZTOOLS_ROOT or install EZ Tools under /opt/perceptor-tools/eztools.")
    dotnet = Path(resolve_dotnet_runtime())

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
                parsed = parse_vsc_ntfs_snapshot(
                    paths=paths,
                    case_id=case_id,
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                    mftecmd=mftecmd,
                    dotnet=dotnet,
                )
                mft_rows = _insert_mft_csv(conn, parsed["mft_csv"], case_id=case_id, image_id=image.id, snapshot=snapshot, snapshot_id=snapshot_id)
                usn_rows = _insert_usn_csv(conn, parsed["usn_csv"], case_id=case_id, image_id=image.id, snapshot=snapshot, snapshot_id=snapshot_id)
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "mft_rows": mft_rows,
                        "usn_rows": usn_rows,
                        "mount": mount,
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

        comparison = compare_ntfs_snapshots_from_db(conn=conn, db=db, case_id=case_id, image_id=image.id)
        promotion = promote_vsc_ntfs_deltas(
            db=db,
            sidecar_db_path=db_path,
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id or "vsc",
        )
        comparison["summary"]["promoted_vsc_mft_deltas"] = promotion["vsc_mft_deltas"]
        comparison["summary"]["promoted_vsc_usn_deltas"] = promotion["vsc_usn_deltas"]
        comparison["summary"]["promoted_vsc_mft_duplicate_signatures"] = promotion["mft_duplicate_signatures"]
        comparison["summary"]["promoted_vsc_usn_duplicate_signatures"] = promotion["usn_duplicate_signatures"]
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "ntfs-vsc-delta.md"
        report_path.write_text(
            _ntfs_delta_markdown(comparison, snapshot_results, failures, started_at=started_at, ended_at=ended_at),
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
        _write_json(paths.vsc_work_dir(case_id) / "ntfs-delta-scan.json", payload)
        return payload
    finally:
        conn.close()


def parse_vsc_ntfs_snapshot(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
    mftecmd: Path,
    dotnet: Path,
) -> dict[str, Path]:
    extract_root = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / "ntfs"
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True, exist_ok=True)
    mft_manifest = extract_vsc_artifact(paths=paths, case_id=case_id, snapshot_id=snapshot_id, relative_path="$MFT")
    usn_manifest = extract_vsc_artifact(paths=paths, case_id=case_id, snapshot_id=snapshot_id, relative_path="$Extend/$UsnJrnl:$J")
    mft_path = Path(mft_manifest["destination_path"])
    usn_path = Path(usn_manifest["destination_path"])
    output_root = paths.vsc_work_dir(case_id) / "outputs" / snapshot_id / "NTFS"
    if output_root.exists():
        shutil.rmtree(output_root)
    mft_out = output_root / "MFTECmd"
    usn_out = output_root / "MFTECmdUSN"
    mft_out.mkdir(parents=True, exist_ok=True)
    usn_out.mkdir(parents=True, exist_ok=True)
    _run_command([str(dotnet), str(mftecmd), "-f", str(mft_path), "--csv", str(mft_out)], output_root / "jobs" / "MFTECmd")
    _run_command(
        [str(dotnet), str(mftecmd), "-f", str(usn_path), "-m", str(mft_path), "--csv", str(usn_out), "--csvf", "USNJrnl.csv"],
        output_root / "jobs" / "MFTECmdUSN",
    )
    mft_csvs = sorted(mft_out.glob("*.csv"))
    usn_csv = usn_out / "USNJrnl.csv"
    if not mft_csvs:
        raise MountError(f"MFTECmd produced no MFT CSV for {snapshot_id}")
    if not usn_csv.is_file():
        raise MountError(f"MFTECmd produced no USN CSV for {snapshot_id}")
    return {"mft_csv": mft_csvs[0], "usn_csv": usn_csv}


def compare_ntfs_snapshots_from_db(
    *,
    conn: duckdb.DuckDBPyConnection,
    db: Database,
    case_id: str,
    image_id: str,
) -> dict[str, Any]:
    case = db.get_case(case_id)
    live_db = case.root / "analytics" / "events.duckdb"
    conn.execute(f"ATTACH IF NOT EXISTS '{str(live_db).replace("'", "''")}' AS live (READ_ONLY)")
    live_mft_path_key = _mft_path_key_sql("live_mft")
    live_mft_signature = _mft_signature_sql("live_mft", path_expr=live_mft_path_key)
    live_mft_windows_old_alias = _windows_old_alias_path_sql(live_mft_path_key)
    live_mft_windows_old_signature = _mft_signature_sql("live_mft", path_expr=live_mft_windows_old_alias)
    conn.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE live_mft_keys AS
        SELECT DISTINCT {live_mft_path_key} AS path_key, {live_mft_signature} AS record_signature
        FROM live.mft_entries live_mft
        WHERE live_mft.case_id = ? AND COALESCE(live_mft.file_name, '') != ''
        UNION
        SELECT DISTINCT {live_mft_windows_old_alias} AS path_key, {live_mft_windows_old_signature} AS record_signature
        FROM live.mft_entries live_mft
        WHERE live_mft.case_id = ? AND COALESCE(live_mft.file_name, '') != ''
          AND {live_mft_path_key} LIKE '/windows.old/%'
        """,
        [case_id, case_id],
    )
    live_usn_signature = _usn_signature_sql("live_usn", path_expr=_live_usn_path_key_sql("live_usn"))
    conn.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE live_usn_signatures AS
        SELECT DISTINCT {live_usn_signature} AS record_signature
        FROM live.usn_journal_entries live_usn
        WHERE live_usn.case_id = ?
        """,
        [case_id],
    )
    mft_snapshot_counts = _counts_by_snapshot(conn, "vsc_mft_entries", case_id, image_id)
    usn_snapshot_counts = _counts_by_snapshot(conn, "vsc_usn_journal_entries", case_id, image_id)
    mft_only = conn.execute(
        """
        SELECT snapshot_id, snapshot_index, snapshot_created_utc, normalized_path, file_name,
               file_size, in_use, is_directory, created_si, modified_si, record_changed_si,
               accessed_si, entry_number, sequence_number
        FROM vsc_mft_entries
        WHERE case_id = ? AND image_id = ? AND COALESCE(path_key, '') != ''
          AND NOT EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = vsc_mft_entries.path_key)
        ORDER BY snapshot_index, normalized_path
        LIMIT 500
        """,
        [case_id, image_id],
    ).fetchall()
    vsc_mft_signature = _mft_signature_sql("v", path_expr="v.path_key")
    mft_changed = conn.execute(
        f"""
        SELECT v.snapshot_id, v.snapshot_index, v.snapshot_created_utc, v.normalized_path, v.file_name,
               v.file_size, v.in_use, v.is_directory, v.created_si, v.modified_si,
               v.record_changed_si, v.accessed_si, v.entry_number, v.sequence_number
        FROM vsc_mft_entries v
        WHERE v.case_id = ? AND v.image_id = ? AND COALESCE(v.path_key, '') != ''
          AND EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = v.path_key)
          AND NOT EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = v.path_key AND live.record_signature = {vsc_mft_signature})
        ORDER BY v.snapshot_index, v.normalized_path
        LIMIT 500
        """,
        [case_id, image_id],
    ).fetchall()
    usn_only = conn.execute(
        """
        SELECT snapshot_id, snapshot_index, snapshot_created_utc, update_timestamp, normalized_path,
               file_name, reason, update_sequence_number, file_reference_number,
               file_reference_sequence_number
        FROM vsc_usn_journal_entries
        WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
          AND NOT EXISTS (
            SELECT 1 FROM live_usn_signatures live
            WHERE live.record_signature = vsc_usn_journal_entries.record_signature
          )
        ORDER BY update_timestamp, update_sequence_number
        LIMIT 500
        """,
        [case_id, image_id],
    ).fetchall()
    summary = {
        "vsc_mft_rows": sum(row["row_count"] for row in mft_snapshot_counts),
        "vsc_usn_rows": sum(row["row_count"] for row in usn_snapshot_counts),
        "vsc_mft_unique_paths": _count_sql(
            conn,
            "SELECT COUNT(DISTINCT path_key) FROM vsc_mft_entries WHERE case_id = ? AND image_id = ? AND COALESCE(path_key, '') != ''",
            [case_id, image_id],
        ),
        "vsc_mft_unique_signatures": _count_sql(
            conn,
            f"SELECT COUNT(DISTINCT {_mft_signature_sql('v', path_expr='v.path_key')}) FROM vsc_mft_entries v WHERE case_id = ? AND image_id = ? AND COALESCE(path_key, '') != ''",
            [case_id, image_id],
        ),
        "vsc_usn_unique_records": _count_sql(
            conn,
            "SELECT COUNT(DISTINCT record_signature) FROM vsc_usn_journal_entries WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''",
            [case_id, image_id],
        ),
        "mft_rows_not_live": _count_sql(
            conn,
            "SELECT COUNT(*) FROM vsc_mft_entries WHERE case_id = ? AND image_id = ? AND COALESCE(path_key, '') != '' AND NOT EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = vsc_mft_entries.path_key)",
            [case_id, image_id],
        ),
        "mft_unique_paths_not_live": _count_sql(
            conn,
            "SELECT COUNT(DISTINCT path_key) FROM vsc_mft_entries WHERE case_id = ? AND image_id = ? AND COALESCE(path_key, '') != '' AND NOT EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = vsc_mft_entries.path_key)",
            [case_id, image_id],
        ),
        "mft_changed_rows_from_live": _count_sql(
            conn,
            f"SELECT COUNT(*) FROM vsc_mft_entries v WHERE v.case_id = ? AND v.image_id = ? AND COALESCE(v.path_key, '') != '' AND EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = v.path_key) AND NOT EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = v.path_key AND live.record_signature = {_mft_signature_sql('v', path_expr='v.path_key')})",
            [case_id, image_id],
        ),
        "mft_changed_unique_paths_from_live": _count_sql(
            conn,
            f"SELECT COUNT(DISTINCT path_key) FROM vsc_mft_entries v WHERE v.case_id = ? AND v.image_id = ? AND COALESCE(v.path_key, '') != '' AND EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = v.path_key) AND NOT EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = v.path_key AND live.record_signature = {_mft_signature_sql('v', path_expr='v.path_key')})",
            [case_id, image_id],
        ),
        "usn_rows_not_live": _count_sql(
            conn,
            "SELECT COUNT(*) FROM vsc_usn_journal_entries WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != '' AND NOT EXISTS (SELECT 1 FROM live_usn_signatures live WHERE live.record_signature = vsc_usn_journal_entries.record_signature)",
            [case_id, image_id],
        ),
        "usn_unique_records_not_live": _count_sql(
            conn,
            "SELECT COUNT(DISTINCT record_signature) FROM vsc_usn_journal_entries WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != '' AND NOT EXISTS (SELECT 1 FROM live_usn_signatures live WHERE live.record_signature = vsc_usn_journal_entries.record_signature)",
            [case_id, image_id],
        ),
        "usn_reason_counts": _reason_counts(conn, case_id, image_id),
        "usn_timestamp_sanity": _usn_timestamp_sanity(conn, case_id, image_id),
    }
    return {
        "summary": summary,
        "mft_snapshot_counts": mft_snapshot_counts,
        "usn_snapshot_counts": usn_snapshot_counts,
        "mft_only": [_row(MFT_ONLY_COLUMNS, row) for row in mft_only],
        "mft_changed": [_row(MFT_ONLY_COLUMNS, row) for row in mft_changed],
        "usn_only": [_row(USN_ONLY_COLUMNS, row) for row in usn_only],
    }


def promote_vsc_ntfs_deltas(
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
        _ensure_main_delta_tables(conn)
        sidecar_literal = str(sidecar_db_path).replace("'", "''")
        conn.execute(f"ATTACH IF NOT EXISTS '{sidecar_literal}' AS sidecar (READ_ONLY)")
        _create_live_ntfs_comparison_tables(conn, case_id=case_id)
        conn.execute(
            "DELETE FROM vsc_mft_deltas WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'",
            [case_id, image_id],
        )
        conn.execute(
            "DELETE FROM vsc_usn_deltas WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'",
            [case_id, image_id],
        )
        conn.execute(
            f"""
            INSERT INTO vsc_mft_deltas (
              id, case_id, computer_id, image_id, source_scope, snapshot_id, snapshot_ids,
              snapshot_count, snapshot_index, snapshot_created_utc, delta_type,
              entry_number, sequence_number, in_use, parent_entry_number,
              parent_sequence_number, normalized_path, path_key, file_name, extension,
              file_size, is_directory, has_ads, is_ads, si_flags, reparse_target,
              created_si, modified_si, record_changed_si, accessed_si,
              record_signature, created_at
            )
            WITH base AS (
              SELECT
                v.*,
                {_mft_signature_sql('v', path_expr='v.path_key')} AS delta_signature
              FROM sidecar.vsc_mft_entries v
              WHERE v.case_id = ? AND v.image_id = ?
                AND COALESCE(v.path_key, '') != ''
            ),
            candidates AS (
              SELECT
                base.*,
                CASE
                  WHEN NOT EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = base.path_key)
                    THEN 'not_live'
                  ELSE 'changed_from_live'
                END AS delta_type
              FROM base
              WHERE COALESCE(base.delta_signature, '') != ''
                AND (
                  NOT EXISTS (SELECT 1 FROM live_mft_keys live WHERE live.path_key = base.path_key)
                  OR NOT EXISTS (
                    SELECT 1 FROM live_mft_keys live
                    WHERE live.path_key = base.path_key
                      AND live.record_signature = base.delta_signature
                  )
                )
            ),
            grouped AS (
              SELECT
                delta_signature,
                to_json(list_sort(list_distinct(list(snapshot_id)))) AS snapshot_ids,
                CAST(COUNT(DISTINCT snapshot_id) AS VARCHAR) AS snapshot_count
              FROM candidates
              GROUP BY delta_signature
            ),
            ranked AS (
              SELECT
                c.*,
                g.snapshot_ids AS grouped_snapshot_ids,
                g.snapshot_count AS grouped_snapshot_count,
                row_number() OVER (
                  PARTITION BY c.delta_signature
                  ORDER BY try_cast(c.snapshot_index AS INTEGER), c.snapshot_id, try_cast(c.row_number AS INTEGER)
                ) AS rn
              FROM candidates c
              JOIN grouped g USING (delta_signature)
            )
            SELECT
              'vsc-mft-' || md5(case_id || '|' || image_id || '|' || delta_signature) AS id,
              case_id,
              ? AS computer_id,
              image_id,
              'VSC' AS source_scope,
              snapshot_id,
              grouped_snapshot_ids AS snapshot_ids,
              grouped_snapshot_count AS snapshot_count,
              snapshot_index,
              snapshot_created_utc,
              delta_type,
              entry_number,
              sequence_number,
              in_use,
              parent_entry_number,
              parent_sequence_number,
              normalized_path,
              path_key,
              file_name,
              extension,
              file_size,
              is_directory,
              has_ads,
              is_ads,
              si_flags,
              reparse_target,
              created_si,
              modified_si,
              record_changed_si,
              accessed_si,
              delta_signature AS record_signature,
              '{now}' AS created_at
            FROM ranked
            WHERE rn = 1
            """,
            [case_id, image_id, computer_id],
        )
        conn.execute(
            f"""
            INSERT INTO vsc_usn_deltas (
              id, case_id, computer_id, image_id, source_scope, snapshot_id, snapshot_ids,
              snapshot_count, snapshot_index, snapshot_created_utc, delta_type,
              update_sequence_number, update_timestamp, file_name, extension,
              file_reference_number, file_reference_sequence_number,
              parent_file_reference_number, parent_file_reference_sequence_number,
              normalized_path, path_key, reason, file_attributes, record_signature, created_at
            )
            WITH candidates AS (
              SELECT v.*, 'not_live' AS delta_type
              FROM sidecar.vsc_usn_journal_entries v
              WHERE v.case_id = ? AND v.image_id = ?
                AND COALESCE(v.record_signature, '') != ''
                AND NOT EXISTS (
                  SELECT 1 FROM live_usn_signatures live
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
                  ORDER BY try_cast(c.snapshot_index AS INTEGER), c.snapshot_id, update_timestamp, try_cast(c.update_sequence_number AS BIGINT), try_cast(c.row_number AS INTEGER)
                ) AS rn
              FROM candidates c
              JOIN grouped g USING (record_signature)
            )
            SELECT
              'vsc-usn-' || md5(case_id || '|' || image_id || '|' || record_signature) AS id,
              case_id,
              ? AS computer_id,
              image_id,
              'VSC' AS source_scope,
              snapshot_id,
              grouped_snapshot_ids AS snapshot_ids,
              grouped_snapshot_count AS snapshot_count,
              snapshot_index,
              snapshot_created_utc,
              delta_type,
              update_sequence_number,
              update_timestamp,
              file_name,
              extension,
              file_reference_number,
              file_reference_sequence_number,
              parent_file_reference_number,
              parent_file_reference_sequence_number,
              normalized_path,
              path_key,
              reason,
              file_attributes,
              record_signature,
              '{now}' AS created_at
            FROM ranked
            WHERE rn = 1
            """,
            [case_id, image_id, computer_id],
        )
        return {
            "vsc_mft_deltas": _count_sql(
                conn,
                "SELECT COUNT(*) FROM vsc_mft_deltas WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'",
                [case_id, image_id],
            ),
            "vsc_usn_deltas": _count_sql(
                conn,
                "SELECT COUNT(*) FROM vsc_usn_deltas WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'",
                [case_id, image_id],
            ),
            "mft_duplicate_signatures": _count_sql(
                conn,
                "SELECT COUNT(*) - COUNT(DISTINCT record_signature) FROM vsc_mft_deltas WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'",
                [case_id, image_id],
            ),
            "usn_duplicate_signatures": _count_sql(
                conn,
                "SELECT COUNT(*) - COUNT(DISTINCT record_signature) FROM vsc_usn_deltas WHERE case_id = ? AND image_id = ? AND source_scope = 'VSC'",
                [case_id, image_id],
            ),
        }
    finally:
        conn.close()


MFT_ONLY_COLUMNS = [
    "snapshot_id", "snapshot_index", "snapshot_created_utc", "normalized_path", "file_name",
    "file_size", "in_use", "is_directory", "created_si", "modified_si", "record_changed_si",
    "accessed_si", "entry_number", "sequence_number",
]
USN_ONLY_COLUMNS = [
    "snapshot_id", "snapshot_index", "snapshot_created_utc", "update_timestamp", "normalized_path",
    "file_name", "reason", "update_sequence_number", "file_reference_number", "file_reference_sequence_number",
]


def _insert_mft_csv(
    conn: duckdb.DuckDBPyConnection,
    csv_path: Path,
    *,
    case_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
) -> int:
    before = _table_count(conn, "vsc_mft_entries", case_id, image_id, snapshot_id)
    csv_literal = str(csv_path).replace("'", "''")
    parsed_at = utc_now().replace("'", "''")
    conn.execute(
        f"""
        INSERT INTO vsc_mft_entries ({', '.join(MFT_COLUMNS)})
        WITH source AS (
          SELECT row_number() OVER () AS csv_row_number, * FROM read_csv('{csv_literal}', header=true, all_varchar=true, ignore_errors=true)
        ),
        base AS (
          SELECT
            ? AS case_id, ? AS image_id, ? AS snapshot_id, ? AS snapshot_index, ? AS snapshot_created_utc,
            ? || '-mft-' || CAST(csv_row_number AS VARCHAR) AS id,
            'vsc' AS computer_id, ? || '-MFTECmd' AS tool_output_id, 'MFTECmd' AS tool_name,
            ? AS source_csv, csv_row_number AS row_number,
            COALESCE(EntryNumber, '') AS entry_number, COALESCE(SequenceNumber, '') AS sequence_number,
            COALESCE(InUse, '') AS in_use, COALESCE(ParentEntryNumber, '') AS parent_entry_number,
            COALESCE(ParentSequenceNumber, '') AS parent_sequence_number, COALESCE(ParentPath, '') AS parent_path,
            COALESCE(FileName, '') AS file_name, COALESCE(Extension, '') AS extension,
            COALESCE(FileSize, '') AS file_size, COALESCE(IsDirectory, '') AS is_directory,
            COALESCE(HasAds, '') AS has_ads, COALESCE(IsAds, '') AS is_ads,
            COALESCE(SiFlags, '') AS si_flags, COALESCE(ReparseTarget, '') AS reparse_target,
            COALESCE("SI<FN", Copied, '') AS si_fn_copied, COALESCE(Created0x10, '') AS created_si,
            COALESCE(Created0x30, '') AS created_fn, COALESCE(LastModified0x10, '') AS modified_si,
            COALESCE(LastModified0x30, '') AS modified_fn, COALESCE(LastRecordChange0x10, '') AS record_changed_si,
            COALESCE(LastRecordChange0x30, '') AS record_changed_fn, COALESCE(LastAccess0x10, '') AS accessed_si,
            COALESCE(LastAccess0x30, '') AS accessed_fn, COALESCE(SourceFile, '') AS source_file,
            { _mft_normalized_path_sql() } AS normalized_path,
            lower({ _mft_normalized_path_sql() }) AS path_key,
            '' AS record_signature, '{parsed_at}' AS parsed_at
          FROM source
        )
        SELECT * REPLACE ({_mft_signature_sql('base', path_expr='base.path_key')} AS record_signature) FROM base
        """,
        [case_id, image_id, snapshot_id, str(snapshot.index), snapshot.created_utc, snapshot_id, snapshot_id, str(csv_path)],
    )
    return _table_count(conn, "vsc_mft_entries", case_id, image_id, snapshot_id) - before


def _insert_usn_csv(
    conn: duckdb.DuckDBPyConnection,
    csv_path: Path,
    *,
    case_id: str,
    image_id: str,
    snapshot: VscSnapshot,
    snapshot_id: str,
) -> int:
    before = _table_count(conn, "vsc_usn_journal_entries", case_id, image_id, snapshot_id)
    csv_literal = str(csv_path).replace("'", "''")
    parsed_at = utc_now().replace("'", "''")
    conn.execute(
        f"""
        INSERT INTO vsc_usn_journal_entries ({', '.join(USN_COLUMNS)})
        WITH source AS (
          SELECT row_number() OVER () AS csv_row_number, * FROM read_csv('{csv_literal}', header=true, all_varchar=true, ignore_errors=true)
        ),
        base AS (
          SELECT
            ? AS case_id, ? AS image_id, ? AS snapshot_id, ? AS snapshot_index, ? AS snapshot_created_utc,
            ? || '-usn-' || CAST(csv_row_number AS VARCHAR) AS id,
            'vsc' AS computer_id, ? || '-MFTECmdUSN' AS tool_output_id, 'MFTECmdUSN' AS tool_name,
            ? AS source_csv, csv_row_number AS row_number,
            COALESCE(SourceFile, '') AS source_file, COALESCE(UpdateSequenceNumber, '') AS update_sequence_number,
            COALESCE(UpdateTimestamp, '') AS update_timestamp,
            COALESCE(Name, '') AS file_name, COALESCE(Extension, '') AS extension,
            COALESCE(EntryNumber, '') AS file_reference_number,
            COALESCE(SequenceNumber, '') AS file_reference_sequence_number,
            COALESCE(ParentEntryNumber, '') AS parent_file_reference_number,
            COALESCE(ParentSequenceNumber, '') AS parent_file_reference_sequence_number,
            '' AS full_path, COALESCE(UpdateReasons, '') AS reason,
            '' AS reason_flags, COALESCE(FileAttributes, '') AS file_attributes,
            '' AS file_attributes_flags, '' AS source_info,
            '' AS security_id, '' AS major_version,
            '' AS minor_version, '' AS record_length,
            COALESCE(OffsetToData, '') AS record_offset,
            { _usn_normalized_path_sql() } AS normalized_path,
            lower({ _usn_normalized_path_sql() }) AS path_key,
            '' AS record_signature, '{parsed_at}' AS parsed_at
          FROM source
        )
        SELECT * REPLACE ({_usn_signature_sql('base', path_expr='base.path_key')} AS record_signature) FROM base
        """,
        [case_id, image_id, snapshot_id, str(snapshot.index), snapshot.created_utc, snapshot_id, snapshot_id, str(csv_path)],
    )
    return _table_count(conn, "vsc_usn_journal_entries", case_id, image_id, snapshot_id) - before


def _ensure_tables(conn: duckdb.DuckDBPyConnection) -> None:
    for table, columns in (("vsc_mft_entries", MFT_COLUMNS), ("vsc_usn_journal_entries", USN_COLUMNS)):
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(f'{column} VARCHAR' for column in columns)})")
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
        for column in columns:
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR")


def _clear_snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str, snapshot_ids: list[str]) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    for table in ("vsc_mft_entries", "vsc_usn_journal_entries"):
        conn.execute(
            f"DELETE FROM {table} WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
            [case_id, image_id, *snapshot_ids],
        )


def _create_live_ntfs_comparison_tables(conn: duckdb.DuckDBPyConnection, *, case_id: str) -> None:
    live_mft_path_key = _mft_path_key_sql("live_mft")
    live_mft_signature = _mft_signature_sql("live_mft", path_expr=live_mft_path_key)
    live_mft_windows_old_alias = _windows_old_alias_path_sql(live_mft_path_key)
    live_mft_windows_old_signature = _mft_signature_sql("live_mft", path_expr=live_mft_windows_old_alias)
    conn.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE live_mft_keys AS
        SELECT DISTINCT {live_mft_path_key} AS path_key, {live_mft_signature} AS record_signature
        FROM mft_entries live_mft
        WHERE live_mft.case_id = ? AND COALESCE(live_mft.file_name, '') != ''
        UNION
        SELECT DISTINCT {live_mft_windows_old_alias} AS path_key, {live_mft_windows_old_signature} AS record_signature
        FROM mft_entries live_mft
        WHERE live_mft.case_id = ? AND COALESCE(live_mft.file_name, '') != ''
          AND {live_mft_path_key} LIKE '/windows.old/%'
        """,
        [case_id, case_id],
    )
    live_usn_signature = _usn_signature_sql("live_usn", path_expr=_live_usn_path_key_sql("live_usn"))
    conn.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE live_usn_signatures AS
        SELECT DISTINCT {live_usn_signature} AS record_signature
        FROM usn_journal_entries live_usn
        WHERE live_usn.case_id = ?
        """,
        [case_id],
    )


def _ensure_main_delta_tables(conn: duckdb.DuckDBPyConnection) -> None:
    schemas = {
        "vsc_mft_deltas": {
            "id": "VARCHAR PRIMARY KEY",
            "case_id": "VARCHAR",
            "computer_id": "VARCHAR",
            "image_id": "VARCHAR",
            "source_scope": "VARCHAR",
            "snapshot_id": "VARCHAR",
            "snapshot_ids": "VARCHAR",
            "snapshot_count": "VARCHAR",
            "snapshot_index": "VARCHAR",
            "snapshot_created_utc": "VARCHAR",
            "delta_type": "VARCHAR",
            "entry_number": "VARCHAR",
            "sequence_number": "VARCHAR",
            "in_use": "VARCHAR",
            "parent_entry_number": "VARCHAR",
            "parent_sequence_number": "VARCHAR",
            "normalized_path": "VARCHAR",
            "path_key": "VARCHAR",
            "file_name": "VARCHAR",
            "extension": "VARCHAR",
            "file_size": "VARCHAR",
            "is_directory": "VARCHAR",
            "has_ads": "VARCHAR",
            "is_ads": "VARCHAR",
            "si_flags": "VARCHAR",
            "reparse_target": "VARCHAR",
            "created_si": "VARCHAR",
            "modified_si": "VARCHAR",
            "record_changed_si": "VARCHAR",
            "accessed_si": "VARCHAR",
            "record_signature": "VARCHAR",
            "created_at": "VARCHAR",
        },
        "vsc_usn_deltas": {
            "id": "VARCHAR PRIMARY KEY",
            "case_id": "VARCHAR",
            "computer_id": "VARCHAR",
            "image_id": "VARCHAR",
            "source_scope": "VARCHAR",
            "snapshot_id": "VARCHAR",
            "snapshot_ids": "VARCHAR",
            "snapshot_count": "VARCHAR",
            "snapshot_index": "VARCHAR",
            "snapshot_created_utc": "VARCHAR",
            "delta_type": "VARCHAR",
            "update_sequence_number": "VARCHAR",
            "update_timestamp": "VARCHAR",
            "file_name": "VARCHAR",
            "extension": "VARCHAR",
            "file_reference_number": "VARCHAR",
            "file_reference_sequence_number": "VARCHAR",
            "parent_file_reference_number": "VARCHAR",
            "parent_file_reference_sequence_number": "VARCHAR",
            "normalized_path": "VARCHAR",
            "path_key": "VARCHAR",
            "reason": "VARCHAR",
            "file_attributes": "VARCHAR",
            "record_signature": "VARCHAR",
            "created_at": "VARCHAR",
        },
    }
    for table, columns in schemas.items():
        column_sql = ", ".join(f"{name} {definition}" for name, definition in columns.items())
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({column_sql})")
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
        for name, definition in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition.replace(' PRIMARY KEY', '')}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vsc_mft_deltas_case_path ON vsc_mft_deltas(case_id, image_id, path_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vsc_mft_deltas_case_snapshot ON vsc_mft_deltas(case_id, image_id, snapshot_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vsc_usn_deltas_case_time ON vsc_usn_deltas(case_id, image_id, update_timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vsc_usn_deltas_case_snapshot ON vsc_usn_deltas(case_id, image_id, snapshot_id)")


def _mft_normalized_path_sql() -> str:
    return """
    replace(CASE
      WHEN COALESCE(ParentPath, '') IN ('', '.') THEN '/' || COALESCE(FileName, '')
      ELSE '/' || regexp_replace(
        regexp_replace(replace(COALESCE(ParentPath, ''), chr(92), '/'), '^([A-Za-z]:)?[./\\\\]*', ''),
        '/+$', ''
      ) || '/' || COALESCE(FileName, '')
    END, chr(92), '/')
    """


def _usn_normalized_path_sql() -> str:
    return """
    replace(CASE
      WHEN COALESCE(ParentPath, '') IN ('', '.') THEN '/' || COALESCE(Name, '')
      ELSE '/' || regexp_replace(
        regexp_replace(replace(COALESCE(ParentPath, ''), chr(92), '/'), '^([A-Za-z]:)?[./\\\\]*', ''),
        '/+$', ''
      ) || '/' || COALESCE(Name, '')
    END, chr(92), '/')
    """


def _mft_path_key_sql(alias: str) -> str:
    return f"""
    lower(CASE
      WHEN COALESCE({alias}.parent_path, '') IN ('', '.') THEN '/' || COALESCE({alias}.file_name, '')
      ELSE replace('/' || regexp_replace(regexp_replace(replace(COALESCE({alias}.parent_path, ''), chr(92), '/'), '^([A-Za-z]:)?[./\\\\]*', ''), '/+$', '') || '/' || COALESCE({alias}.file_name, ''), chr(92), '/')
    END)
    """


def _mft_signature_sql(alias: str, *, path_expr: str) -> str:
    return f"""
    lower(concat_ws('|',
      {path_expr},
      COALESCE({alias}.file_size, ''),
      COALESCE({alias}.in_use, ''),
      COALESCE({alias}.is_directory, ''),
      COALESCE({alias}.created_si, ''),
      COALESCE({alias}.modified_si, ''),
      COALESCE({alias}.record_changed_si, ''),
      COALESCE({alias}.entry_number, ''),
      COALESCE({alias}.sequence_number, '')
    ))
    """


def _windows_old_alias_path_sql(path_expr: str) -> str:
    return f"regexp_replace({path_expr}, '^/windows\\.old', '')"


def _live_usn_path_key_sql(alias: str) -> str:
    return f"lower('/' || regexp_replace(replace(COALESCE({alias}.full_path, {alias}.file_name, ''), chr(92), '/'), '^([A-Za-z]:)?[./\\\\]*', ''))"


def _usn_signature_sql(alias: str, *, path_expr: str) -> str:
    return f"""
    lower(concat_ws('|',
      COALESCE({alias}.update_sequence_number, ''),
      COALESCE({alias}.update_timestamp, ''),
      COALESCE({alias}.file_reference_number, ''),
      COALESCE({alias}.file_reference_sequence_number, ''),
      COALESCE({alias}.parent_file_reference_number, ''),
      COALESCE({alias}.parent_file_reference_sequence_number, ''),
      {path_expr},
      COALESCE({alias}.reason, '')
    ))
    """


def _counts_by_snapshot(conn: duckdb.DuckDBPyConnection, table: str, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"""
        SELECT snapshot_id, snapshot_index, snapshot_created_utc, COUNT(*) AS row_count
        FROM {table}
        WHERE case_id = ? AND image_id = ?
        GROUP BY 1, 2, 3
        ORDER BY CAST(snapshot_index AS INTEGER)
        """,
        [case_id, image_id],
    ).fetchall()
    return [_row(["snapshot_id", "snapshot_index", "snapshot_created_utc", "row_count"], row) for row in rows]


def _reason_counts(conn: duckdb.DuckDBPyConnection, case_id: str, image_id: str) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT reason, COUNT(*) AS count
        FROM vsc_usn_journal_entries
        WHERE case_id = ? AND image_id = ?
        GROUP BY 1
        ORDER BY count DESC
        LIMIT 20
        """,
        [case_id, image_id],
    ).fetchall()
    return dict(Counter({str(reason or ""): int(count) for reason, count in rows}))


def _usn_timestamp_sanity(conn: duckdb.DuckDBPyConnection, case_id: str, image_id: str) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT snapshot_id, snapshot_created_utc, update_timestamp, normalized_path, reason
        FROM vsc_usn_journal_entries
        WHERE case_id = ? AND image_id = ? AND COALESCE(update_timestamp, '') != ''
        """,
        [case_id, image_id],
    ).fetchall()
    after_snapshot = 0
    at_or_before_snapshot = 0
    unparsable = 0
    after_signatures: set[str] = set()
    at_or_before_signatures: set[str] = set()
    examples: list[dict[str, str]] = []
    signature_rows = conn.execute(
        """
        SELECT snapshot_id, update_timestamp, record_signature
        FROM vsc_usn_journal_entries
        WHERE case_id = ? AND image_id = ? AND COALESCE(update_timestamp, '') != ''
          AND COALESCE(record_signature, '') != ''
        """,
        [case_id, image_id],
    ).fetchall()
    snapshot_created_by_id = {
        str(snapshot_id): str(snapshot_created or "")
        for snapshot_id, snapshot_created, *_ in rows
    }
    for snapshot_id, update_timestamp, record_signature in signature_rows:
        snapshot_dt = _parse_datetime(snapshot_created_by_id.get(str(snapshot_id), ""), vsc_created=True)
        update_dt = _parse_datetime(str(update_timestamp or ""), vsc_created=False)
        if not snapshot_dt or not update_dt:
            continue
        if update_dt > snapshot_dt:
            after_signatures.add(str(record_signature))
        else:
            at_or_before_signatures.add(str(record_signature))
    for snapshot_id, snapshot_created, update_timestamp, normalized_path, reason in rows:
        snapshot_dt = _parse_datetime(str(snapshot_created or ""), vsc_created=True)
        update_dt = _parse_datetime(str(update_timestamp or ""), vsc_created=False)
        if not snapshot_dt or not update_dt:
            unparsable += 1
            continue
        if update_dt > snapshot_dt:
            after_snapshot += 1
            if len(examples) < 10:
                examples.append(
                    {
                        "snapshot_id": str(snapshot_id or ""),
                        "snapshot_created_utc": str(snapshot_created or ""),
                        "update_timestamp": str(update_timestamp or ""),
                        "normalized_path": str(normalized_path or ""),
                        "reason": str(reason or ""),
                    }
                )
        else:
            at_or_before_snapshot += 1
    return {
        "at_or_before_snapshot_rows": at_or_before_snapshot,
        "at_or_before_snapshot_unique_records": len(at_or_before_signatures),
        "after_snapshot_rows": after_snapshot,
        "after_snapshot_unique_records": len(after_signatures),
        "unparsable_rows": unparsable,
        "examples": examples,
    }


def _parse_datetime(value: str, *, vsc_created: bool) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    if vsc_created:
        value = value.removesuffix(" UTC").strip()
        if "." in value:
            head, tail = value.split(".", 1)
            value = f"{head}.{tail[:6]}"
            fmt = "%b %d, %Y %H:%M:%S.%f"
        else:
            fmt = "%b %d, %Y %H:%M:%S"
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            return None
    value = value.replace("T", " ").removesuffix("Z")
    if "." in value:
        head, tail = value.split(".", 1)
        value = f"{head}.{tail[:6]}"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _ntfs_delta_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC NTFS Delta Report",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC MFT rows parsed: {summary['vsc_mft_rows']}",
        f"- VSC MFT unique paths parsed: {summary['vsc_mft_unique_paths']}",
        f"- VSC MFT unique row signatures parsed: {summary['vsc_mft_unique_signatures']}",
        f"- VSC USN rows parsed: {summary['vsc_usn_rows']}",
        f"- VSC USN unique records parsed: {summary['vsc_usn_unique_records']}",
        f"- VSC MFT rows not present live: {summary['mft_rows_not_live']}",
        f"- VSC MFT unique paths not present live: {summary['mft_unique_paths_not_live']}",
        f"- VSC MFT rows changed from live path match: {summary['mft_changed_rows_from_live']}",
        f"- VSC MFT unique paths changed from live path match: {summary['mft_changed_unique_paths_from_live']}",
        f"- VSC USN rows not present live: {summary['usn_rows_not_live']}",
        f"- VSC USN unique records not present live: {summary['usn_unique_records_not_live']}",
        f"- Promoted VSC MFT delta rows in main DuckDB: {summary.get('promoted_vsc_mft_deltas', 0)}",
        f"- Promoted VSC USN delta rows in main DuckDB: {summary.get('promoted_vsc_usn_deltas', 0)}",
        f"- Promoted VSC MFT duplicate signatures: {summary.get('promoted_vsc_mft_duplicate_signatures', 0)}",
        f"- Promoted VSC USN duplicate signatures: {summary.get('promoted_vsc_usn_duplicate_signatures', 0)}",
        "",
        "## Snapshot Counts",
        "",
        "| Snapshot | Created | MFT rows | USN rows |",
        "| --- | --- | ---: | ---: |",
    ]
    usn_counts = {row["snapshot_id"]: row["row_count"] for row in comparison["usn_snapshot_counts"]}
    for row in comparison["mft_snapshot_counts"]:
        lines.append(
            f"| {row['snapshot_id']} | {row.get('snapshot_created_utc') or ''} | {row.get('row_count') or 0} | {usn_counts.get(row['snapshot_id'], 0)} |"
        )
    sanity = summary.get("usn_timestamp_sanity") or {}
    if sanity.get("after_snapshot_rows") or sanity.get("unparsable_rows"):
        lines.extend(
            [
                "",
                "## Timestamp Sanity",
                "",
                "VSC USN rows are parsed as supporting file-system activity. Rows newer than the VSC creation time are retained, but reported separately because they may reflect later image modification/sanitization activity or the raw `$J` journal boundary rather than original activity inside that snapshot.",
                "",
                f"- USN rows at or before VSC creation time: {sanity.get('at_or_before_snapshot_rows') or 0}",
                f"- USN unique records at or before VSC creation time: {sanity.get('at_or_before_snapshot_unique_records') or 0}",
                f"- USN rows with timestamps after their VSC creation time: {sanity.get('after_snapshot_rows') or 0}",
                f"- USN unique records with timestamps after their VSC creation time: {sanity.get('after_snapshot_unique_records') or 0}",
                f"- USN rows with unparsable timestamps: {sanity.get('unparsable_rows') or 0}",
            ]
        )
        if sanity.get("examples"):
            lines.extend(["", "| Snapshot | Snapshot created | USN time | Path | Reason |", "| --- | --- | --- | --- | --- |"])
            for row in sanity["examples"]:
                lines.append(
                    f"| {row['snapshot_id']} | {row['snapshot_created_utc']} | {row['update_timestamp']} | `{_md(row['normalized_path'])}` | `{_md(row['reason'])}` |"
                )
    lines.extend(["", "## VSC-Only MFT Paths", "", "| Snapshot | Path | Size | In use | Modified | Record changed |", "| --- | --- | ---: | --- | --- | --- |"])
    for row in comparison["mft_only"][:80]:
        lines.append(
            f"| {row['snapshot_id']} | `{_md(row.get('normalized_path'))}` | {row.get('file_size') or ''} | {row.get('in_use') or ''} | {row.get('modified_si') or ''} | {row.get('record_changed_si') or ''} |"
        )
    lines.extend(["", "## Changed MFT Rows For Live Paths", "", "| Snapshot | Path | Size | Modified | Record changed | Accessed |", "| --- | --- | ---: | --- | --- | --- |"])
    for row in comparison["mft_changed"][:80]:
        lines.append(
            f"| {row['snapshot_id']} | `{_md(row.get('normalized_path'))}` | {row.get('file_size') or ''} | {row.get('modified_si') or ''} | {row.get('record_changed_si') or ''} | {row.get('accessed_si') or ''} |"
        )
    lines.extend(["", "## VSC-Only USN Records", "", "| Snapshot | Time | Path | Reason | USN |", "| --- | --- | --- | --- | ---: |"])
    for row in comparison["usn_only"][:120]:
        lines.append(
            f"| {row['snapshot_id']} | {row.get('update_timestamp') or ''} | `{_md(row.get('normalized_path'))}` | `{_md(row.get('reason'))}` | {row.get('update_sequence_number') or ''} |"
        )
    if failures:
        lines.extend(["", "## Failures", "", "| Snapshot | Error |", "| --- | --- |"])
        for failure in failures:
            lines.append(f"| {failure['snapshot_id']} | `{_md(failure['error'])}` |")
    return "\n".join(lines).rstrip() + "\n"


def _run_command(command: list[str], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    ended_at = utc_now()
    stdout = output_dir / "stdout.txt"
    stderr = output_dir / "stderr.txt"
    stdout.write_text(result.stdout, encoding="utf-8", errors="replace")
    stderr.write_text(result.stderr, encoding="utf-8", errors="replace")
    payload = {"command": command, "started_at": started_at, "ended_at": ended_at, "exit_code": result.returncode, "stdout_path": str(stdout), "stderr_path": str(stderr)}
    _write_json(output_dir / "command.json", payload)
    if result.returncode != 0:
        raise MountError(f"{command[0]} failed with exit code {result.returncode}; see {stderr}")
    return payload


def _snapshot_from_payload(payload: dict[str, Any]) -> VscSnapshot:
    return VscSnapshot(
        index=int(payload["index"]),
        snapshot_id=str(payload.get("snapshot_id") or ""),
        identifier=str(payload.get("identifier") or ""),
        shadow_copy_set_id=str(payload.get("shadow_copy_set_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
    )


def _table_count(conn: duckdb.DuckDBPyConnection, table: str, case_id: str, image_id: str, snapshot_id: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE case_id = ? AND image_id = ? AND snapshot_id = ?", [case_id, image_id, snapshot_id]).fetchone()[0])


def _count_sql(conn: duckdb.DuckDBPyConnection, sql: str, params: list[Any]) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def _row(columns: list[str], values: tuple[Any, ...]) -> dict[str, Any]:
    return dict(zip(columns, values, strict=False))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _resolve_eztool(tool_dir: str, dll_name: str) -> Path | None:
    roots = [
        Path(os.environ["EZTOOLS_ROOT"]).expanduser() if os.environ.get("EZTOOLS_ROOT") else None,
        Path(os.environ["PERCEPTOR_TOOLS_ROOT"]).expanduser() / "eztools"
        if os.environ.get("PERCEPTOR_TOOLS_ROOT")
        else None,
        Path(os.environ["FORENSIC_ORCHESTRATOR_TOOLS_ROOT"]).expanduser() / "eztools"
        if os.environ.get("FORENSIC_ORCHESTRATOR_TOOLS_ROOT")
        else None,
        Path("/opt/perceptor-tools/eztools"),
        Path("/opt/eztools"),
        Path.home() / "tools" / "eztools",
    ]
    for root in roots:
        if not root:
            continue
        candidate = root / tool_dir / dll_name
        if candidate.is_file():
            return candidate
    return None


def _md(value: object, limit: int = 160) -> str:
    text = "" if value is None else str(value)
    text = text.replace("|", "\\|").replace("\n", " ")
    if len(text) > limit:
        return text[: limit - 1] + "..."
    return text
