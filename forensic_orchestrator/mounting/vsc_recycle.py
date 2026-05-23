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
from forensic_orchestrator.tools.normalized import normalized_recycle_row
from forensic_orchestrator.tools.recycle import parse_recycle_artifacts_to_csv

from .vshadow import VscSnapshot, discover_vsc_snapshots, mount_vsc_snapshot, unmount_vsc
from .vsc_promote import add_vsc_provenance, clear_vsc_rows, promote_deduped_rows


RECYCLE_COLUMNS = [
    "case_id", "image_id", "snapshot_id", "snapshot_index", "snapshot_created_utc",
    "id", "computer_id", "tool_output_id", "tool_name", "source_csv", "row_number",
    "record_type", "recycle_format", "source_path", "source_vsc_path", "top_level_name",
    "recycled_path", "child_relative_path", "display_name", "original_path",
    "deletion_time_utc", "file_size", "is_directory", "mft_created",
    "mft_modified", "mft_accessed", "mft_record_modified", "record_signature",
    "parsed_at",
]


def run_vsc_recycle_scan(
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
        raise MountError("No VSC snapshots selected for Recycle Bin scan")

    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_tables(conn)
        snapshot_ids = [f"vss{snapshot.index}" for snapshot in snapshots]
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="recycle_items", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
        clear_vsc_rows(db, table="recycle_children", case_id=case_id, image_id=image.id, snapshot_ids=snapshot_ids)
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
                rows = parse_vsc_recycle_snapshot(
                    paths=paths,
                    case_id=case_id,
                    computer_id=image.computer_id or "vsc",
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                    mount_path=Path(mount["volume_mount_path"]),
                )
                _insert_rows(conn, rows)
                all_rows.extend(rows)
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "parsed_rows": len(rows),
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

        promote_deduped_rows(
            db,
            table="recycle_items",
            rows=[
                add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/RecycleParser")
                for row in all_rows
                if str(row.get("record_type") or "").casefold() != "child"
            ],
            key_func=_recycle_signature,
        )
        promote_deduped_rows(
            db,
            table="recycle_children",
            rows=[
                add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/RecycleParser")
                for row in all_rows
                if str(row.get("record_type") or "").casefold() == "child"
            ],
            key_func=_recycle_signature,
        )
        comparison = compare_recycle_snapshots_from_db(conn=conn, db=db, case_id=case_id, image_id=image.id)
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "recycle-vsc-comparison.md"
        report_path.write_text(
            _recycle_markdown(comparison, snapshot_results, failures, started_at=started_at, ended_at=ended_at),
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
        _write_json(paths.vsc_work_dir(case_id) / "recycle-scan.json", payload)
        return payload
    finally:
        conn.close()


def parse_vsc_recycle_snapshot(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    computer_id: str = "vsc",
    snapshot: VscSnapshot,
    snapshot_id: str,
    mount_path: Path,
) -> list[dict[str, Any]]:
    sources = [mount_path / "$Recycle.Bin", mount_path / "RECYCLER", mount_path / "Recycled"]
    output = paths.vsc_work_dir(case_id) / "outputs" / snapshot_id / "RecycleParser"
    csv_path = parse_recycle_artifacts_to_csv(sources, output)
    rows: list[dict[str, Any]] = []
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), start=1):
            normalized = normalized_recycle_row(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=f"{snapshot_id}-RecycleParser",
                tool_name="RecycleParser",
                source_csv=csv_path,
                row_number=row_number,
                row=dict(row),
            )
            normalized["snapshot_id"] = snapshot_id
            normalized["snapshot_index"] = str(snapshot.index)
            normalized["snapshot_created_utc"] = snapshot.created_utc
            normalized["source_vsc_path"] = _root_relative_path(normalized.get("source_path"), mount_path)
            normalized["record_signature"] = _recycle_signature(normalized)
            normalized["parsed_at"] = utc_now()
            rows.append(normalized)
    return rows


def compare_recycle_snapshots_from_db(
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
        CREATE OR REPLACE TEMP TABLE live_recycle_signatures AS
        SELECT DISTINCT lower(concat_ws('|',
          'item',
          COALESCE(recycle_format, ''),
          COALESCE(top_level_name, ''),
          COALESCE(deletion_time_utc, ''),
          COALESCE(file_size, '')
        )) AS record_signature
        FROM live.recycle_items
        WHERE case_id = ?
        UNION
        SELECT DISTINCT lower(concat_ws('|',
          'child',
          COALESCE(recycle_format, ''),
          COALESCE(top_level_name, ''),
          COALESCE(child_relative_path, ''),
          COALESCE(file_size, '')
        )) AS record_signature
        FROM live.recycle_children
        WHERE case_id = ?
        """,
        [case_id, case_id],
    )
    by_snapshot = _counts_by_snapshot(conn, case_id, image_id)
    examples = conn.execute(
        """
        SELECT snapshot_id, snapshot_created_utc, record_type, deletion_time_utc,
               original_path, source_vsc_path, file_size, recycle_format
        FROM vsc_recycle_items v
        WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
          AND NOT EXISTS (
            SELECT 1 FROM live_recycle_signatures live
            WHERE live.record_signature = v.record_signature
          )
        ORDER BY deletion_time_utc, snapshot_id, original_path, source_vsc_path
        LIMIT 200
        """,
        [case_id, image_id],
    ).fetchall()
    artifact_counts = dict(
        Counter(
            {
                str(record_type or ""): int(count)
                for record_type, count in conn.execute(
                    """
                    SELECT record_type, COUNT(DISTINCT record_signature)
                    FROM vsc_recycle_items v
                    WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
                      AND NOT EXISTS (
                        SELECT 1 FROM live_recycle_signatures live
                        WHERE live.record_signature = v.record_signature
                      )
                    GROUP BY 1
                    ORDER BY 2 DESC
                    """,
                    [case_id, image_id],
                ).fetchall()
            }
        )
    )
    summary = {
        "vsc_recycle_rows": _count_sql(conn, "SELECT COUNT(*) FROM vsc_recycle_items WHERE case_id = ? AND image_id = ?", [case_id, image_id]),
        "unique_vsc_records_not_live": _count_sql(
            conn,
            """
            SELECT COUNT(DISTINCT record_signature)
            FROM vsc_recycle_items v
            WHERE case_id = ? AND image_id = ? AND COALESCE(record_signature, '') != ''
              AND NOT EXISTS (
                SELECT 1 FROM live_recycle_signatures live
                WHERE live.record_signature = v.record_signature
              )
            """,
            [case_id, image_id],
        ),
        "record_type_counts": artifact_counts,
    }
    columns = ["snapshot_id", "snapshot_created_utc", "record_type", "deletion_time_utc", "original_path", "source_vsc_path", "file_size", "recycle_format"]
    return {
        "summary": summary,
        "snapshot_counts": by_snapshot,
        "examples": [_row(columns, row) for row in examples],
    }


def _ensure_tables(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute(f"CREATE TABLE IF NOT EXISTS vsc_recycle_items ({', '.join(f'{column} VARCHAR' for column in RECYCLE_COLUMNS)})")
    existing = {row[1] for row in conn.execute("PRAGMA table_info('vsc_recycle_items')").fetchall()}
    for column in RECYCLE_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE vsc_recycle_items ADD COLUMN {column} VARCHAR")


def _clear_snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str, snapshot_ids: list[str]) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    conn.execute(
        f"DELETE FROM vsc_recycle_items WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
        [case_id, image_id, *snapshot_ids],
    )


def _insert_rows(conn: duckdb.DuckDBPyConnection, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    placeholders = ", ".join("?" for _ in RECYCLE_COLUMNS)
    values = [[str(row.get(column) or "") for column in RECYCLE_COLUMNS] for row in rows]
    conn.executemany(f"INSERT INTO vsc_recycle_items ({', '.join(RECYCLE_COLUMNS)}) VALUES ({placeholders})", values)


def _counts_by_snapshot(conn: duckdb.DuckDBPyConnection, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT snapshot_id, snapshot_index, snapshot_created_utc, COUNT(*) AS row_count,
               COUNT(DISTINCT record_signature) AS unique_count
        FROM vsc_recycle_items
        WHERE case_id = ? AND image_id = ?
        GROUP BY 1, 2, 3
        ORDER BY CAST(snapshot_index AS INTEGER)
        """,
        [case_id, image_id],
    ).fetchall()
    return [_row(["snapshot_id", "snapshot_index", "snapshot_created_utc", "row_count", "unique_count"], row) for row in rows]


def _recycle_signature(row: dict[str, Any]) -> str:
    record_type = _text(row.get("record_type")).lower()
    if record_type == "child":
        parts = [
            record_type,
            _text(row.get("recycle_format")).lower(),
            _text(row.get("top_level_name")).lower(),
            _text(row.get("child_relative_path")).lower(),
            _text(row.get("file_size")),
        ]
    else:
        parts = [
            record_type,
            _text(row.get("recycle_format")).lower(),
            _text(row.get("top_level_name")).lower(),
            _text(row.get("deletion_time_utc")),
            _text(row.get("file_size")),
        ]
    return "|".join(parts).lower()


def _root_relative_path(value: object, mount_path: Path) -> str:
    text = _text(value)
    if not text:
        return ""
    path = Path(text)
    try:
        return "/" + str(path.relative_to(mount_path)).replace("\\", "/")
    except ValueError:
        return text.replace("\\", "/")


def _path_key(value: object) -> str:
    text = _text(value).replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    return "/" + text.strip("/").lower() if text else ""


def _text(value: object) -> str:
    return "" if value is None else str(value)


def _count_sql(conn: duckdb.DuckDBPyConnection, sql: str, params: list[Any]) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def _row(columns: list[str], values: tuple[Any, ...]) -> dict[str, Any]:
    return dict(zip(columns, values, strict=False))


def _snapshot_from_payload(payload: dict[str, Any]) -> VscSnapshot:
    return VscSnapshot(
        index=int(payload["index"]),
        snapshot_id=str(payload.get("snapshot_id") or ""),
        identifier=str(payload.get("identifier") or ""),
        shadow_copy_set_id=str(payload.get("shadow_copy_set_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
    )


def _recycle_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC Recycle Bin Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC Recycle rows parsed: {summary['vsc_recycle_rows']}",
        f"- Unique VSC Recycle records not present live: {summary['unique_vsc_records_not_live']}",
        "",
        "## Record Type Counts",
        "",
        "| Record type | Unique not live |",
        "| --- | ---: |",
    ]
    for record_type, count in (summary.get("record_type_counts") or {}).items():
        lines.append(f"| `{_md(record_type)}` | {count} |")
    lines.extend(["", "## Snapshot Counts", "", "| Snapshot | Created | Rows | Unique rows |", "| --- | --- | ---: | ---: |"])
    for row in comparison["snapshot_counts"]:
        lines.append(f"| {row['snapshot_id']} | {row.get('snapshot_created_utc') or ''} | {row.get('row_count') or 0} | {row.get('unique_count') or 0} |")
    lines.extend(["", "## Examples", "", "| Type | Snapshot | Deleted | Original path | Recycle path | Size |", "| --- | --- | --- | --- | --- | ---: |"])
    for row in comparison["examples"][:100]:
        lines.append(
            f"| `{_md(row.get('record_type'))}` | {row.get('snapshot_id') or ''} | {row.get('deletion_time_utc') or ''} | {_code_or_dash(row.get('original_path'))} | {_code_or_dash(row.get('source_vsc_path'))} | {row.get('file_size') or ''} |"
        )
    if failures:
        lines.extend(["", "## Failures", "", "| Snapshot | Error |", "| --- | --- |"])
        for failure in failures:
            lines.append(f"| {failure['snapshot_id']} | `{_md(failure['error'])}` |")
    lines.extend(["", "## Processing", ""])
    for item in snapshot_results:
        lines.append(f"- `{item['snapshot_id']}` parsed {item['parsed_rows']} rows from {item['started_at']} to {item['ended_at']}")
    return "\n".join(lines).rstrip() + "\n"


def _md(value: object, limit: int = 160) -> str:
    text = _text(value).replace("|", "\\|").replace("\n", " ").replace("`", "&#96;")
    if len(text) > limit:
        return text[: limit - 1] + "..."
    return text


def _code_or_dash(value: object) -> str:
    text = _md(value)
    return f"`{text}`" if text else "-"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
