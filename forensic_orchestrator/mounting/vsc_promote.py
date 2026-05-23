from __future__ import annotations

import json
import re
from typing import Any, Callable

import duckdb

from forensic_orchestrator.db import Database


VSC_PROVENANCE_COLUMNS = ("source_scope", "snapshot_id", "snapshot_ids", "snapshot_count", "snapshot_index", "snapshot_created_utc")


def clear_vsc_rows(
    db: Database,
    *,
    table: str,
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
        if db.analytics._table_exists(conn, table):
            ensure_vsc_columns(conn, table)
            db.analytics.delete_where(table, where, params)
    if not db.analytics_only:
        db.conn.execute(f"DELETE FROM {table} WHERE {where}", params)
        db.conn.commit()


def ensure_vsc_columns(conn: duckdb.DuckDBPyConnection, table: str) -> None:
    columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
    for column in VSC_PROVENANCE_COLUMNS:
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR")


def promote_deduped_rows(
    db: Database,
    *,
    table: str,
    rows: list[dict[str, Any]],
    key_func: Callable[[dict[str, Any]], str],
    keep_blank_keys: bool = False,
) -> list[dict[str, Any]]:
    promoted = dedupe_vsc_rows(rows, key_func=key_func, keep_blank_keys=keep_blank_keys)
    db.insert_normalized_artifact_rows(table, promoted)
    return promoted


def dedupe_vsc_rows(
    rows: list[dict[str, Any]],
    *,
    key_func: Callable[[dict[str, Any]], str],
    keep_blank_keys: bool = False,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = key_func(row)
        if not key:
            if not keep_blank_keys:
                continue
            key = "\x1f".join(str(row.get(value) or "") for value in ("id", "snapshot_id"))
        existing = grouped.get(key)
        if existing is None or _snapshot_sort_key(row) < _snapshot_sort_key(existing):
            merged = dict(row)
            merged["_snapshot_ids"] = set(existing.get("_snapshot_ids") or []) if existing else set()
            grouped[key] = merged
            existing = merged
        snapshot_id = str(row.get("snapshot_id") or "").strip()
        if snapshot_id:
            existing.setdefault("_snapshot_ids", set()).add(snapshot_id)
    result: list[dict[str, Any]] = []
    for row in grouped.values():
        snapshot_ids = sorted(row.pop("_snapshot_ids", set()), key=snapshot_id_sort_key)
        row["source_scope"] = "VSC"
        row["snapshot_ids"] = json.dumps(snapshot_ids)
        row["snapshot_count"] = str(len(snapshot_ids)) if snapshot_ids else None
        if snapshot_ids:
            row["snapshot_id"] = snapshot_ids[0]
        result.append(row)
    return sorted(result, key=lambda item: (str(item.get("snapshot_id") or ""), str(item.get("id") or "")))


def add_vsc_provenance(row: dict[str, Any], *, source_csv: str | None = None) -> dict[str, Any]:
    snapshot_id = str(row.get("snapshot_id") or "").strip()
    snapshot_ids = [snapshot_id] if snapshot_id else []
    result = {
        **row,
        "source_scope": "VSC",
        "snapshot_ids": json.dumps(snapshot_ids),
        "snapshot_count": str(len(snapshot_ids)) if snapshot_ids else None,
    }
    if source_csv is not None:
        result["source_csv"] = source_csv
    return result


def snapshot_id_sort_key(value: object) -> int:
    text = str(value or "")
    match = re.search(r"(\d+)", text)
    if not match:
        return 0
    return int(match.group(1))


def _snapshot_sort_key(row: dict[str, Any]) -> tuple[int, str]:
    raw_index = row.get("snapshot_index")
    try:
        index = int(str(raw_index))
    except (TypeError, ValueError):
        index = snapshot_id_sort_key(row.get("snapshot_id"))
    return (index, str(row.get("snapshot_id") or ""))
