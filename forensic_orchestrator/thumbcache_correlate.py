from __future__ import annotations

import json
import re
import uuid
from typing import Any

from forensic_orchestrator.db import Database
from forensic_orchestrator.timestamps import normalize_timestamp


THUMBNAIL_PROPERTY_HINTS = ("thumb", "thumbnail", "cacheid", "cache_id")
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".tif", ".tiff"}
THUMBNAIL_CACHE_PROPERTY_NAMES = {
    "system_thumbnailcacheid",
    "system_thumbnail_cache_id",
    "system_thumbnail cache id",
    "thumbnailcacheid",
    "thumbnail_cache_id",
    "thumbnail cache id",
}


def rebuild_thumbcache_search_correlations(
    db: Database,
    *,
    case_id: str,
    image_id: str | None = None,
) -> int:
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id:
        where.append("image_id = ?")
        params.append(image_id)
    db.conn.execute(f"DELETE FROM thumbcache_search_correlations WHERE {' AND '.join(where)}", params)
    db.conn.execute(
        f"DELETE FROM timeline_events WHERE {' AND '.join(where)} AND source_table = ?",
        [*params, "thumbcache_search_correlations"],
    )
    direct_rows = _direct_property_matches(db, case_id=case_id, image_id=image_id)
    rows = direct_rows
    db.insert_thumbcache_search_correlations(rows)
    timeline_rows = _timeline_rows(rows)
    db.insert_timeline_events(timeline_rows)
    return len(rows)


def _direct_property_matches(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    entry_where = ["case_id = ?", "parser_status = 'parsed'", "COALESCE(cache_id, '') != ''"]
    params: list[Any] = [case_id]
    if image_id:
        entry_where.append("image_id = ?")
        params.append(image_id)
    entries = db.conn.execute(
        f"""
        SELECT id AS thumbcache_entry_id, case_id, computer_id, image_id,
               tool_output_id, cache_id, user_profile AS thumbcache_user,
               source_path AS thumbcache_path, source_name AS thumbcache_name,
               source_mtime_utc, thumbnail_sha256, thumbnail_type
        FROM thumbcache_entries
        WHERE {' AND '.join(entry_where)}
        """,
        params,
    ).fetchall()
    by_cache_id: dict[str, list[dict[str, Any]]] = {}
    for row in entries:
        key = _cache_key(row["cache_id"])
        if key:
            by_cache_id.setdefault(key, []).append(dict(row))
    if not by_cache_id:
        return []

    prop_where = ["wsp.case_id = ?"]
    prop_params: list[Any] = [case_id]
    if image_id:
        prop_where.append("wsp.image_id = ?")
        prop_params.append(image_id)
    prop_rows = db.conn.execute(
        f"""
        SELECT wsp.source_record_id AS windows_search_file_id, wsp.property_name,
               wsp.property_value, wsp.item_path AS search_item_path,
               wsp.timestamp AS search_timestamp,
               wsf.file_name, wsf.item_path, wsf.item_url, wsf.folder_path,
               wsf.date_created, wsf.date_modified, wsf.date_accessed,
               wsf.date_imported, wsf.size, wsf.owner
        FROM windows_search_properties AS wsp
        LEFT JOIN windows_search_files AS wsf
          ON wsf.id = wsp.source_record_id
        WHERE {' AND '.join(prop_where)}
          AND COALESCE(wsp.property_value, '') != ''
          AND (
            LOWER(REPLACE(COALESCE(wsp.property_name, ''), '.', '_')) IN ({",".join("?" for _ in THUMBNAIL_CACHE_PROPERTY_NAMES)})
            OR LOWER(REPLACE(COALESCE(wsp.normalized_name, ''), '.', '_')) IN ({",".join("?" for _ in THUMBNAIL_CACHE_PROPERTY_NAMES)})
            OR LOWER(COALESCE(wsp.property_name, '')) LIKE '%thumbnail%cache%id%'
            OR LOWER(COALESCE(wsp.normalized_name, '')) LIKE '%thumbnail%cache%id%'
          )
        """,
        [*prop_params, *sorted(THUMBNAIL_CACHE_PROPERTY_NAMES), *sorted(THUMBNAIL_CACHE_PROPERTY_NAMES)],
    ).fetchall()
    rows: list[dict[str, Any]] = []
    for prop in prop_rows:
        for entry in by_cache_id.get(_cache_key(prop["property_value"]), []):
            rows.append({**entry, **dict(prop)})
    return [_correlation_row(row, "windows_search_thumbnail_cache_id", "high") for row in rows]


def _cache_key(value: object) -> str:
    text = str(value or "").strip().replace("-", "").lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        if not re.search(r"[a-f]", text) and text:
            return f"{int(text):016x}"
    except ValueError:
        pass
    return text


def _context_image_candidates(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where = ["te.case_id = ?"]
    params: list[Any] = [case_id]
    if image_id:
        where.append("te.image_id = ?")
        params.append(image_id)
    rows = db.conn.execute(
        f"""
        SELECT te.id AS thumbcache_entry_id, te.case_id, te.computer_id, te.image_id,
               te.tool_output_id, te.cache_id, te.user_profile AS thumbcache_user,
               te.source_path AS thumbcache_path, te.source_name AS thumbcache_name,
               te.source_mtime_utc, te.thumbnail_sha256, te.thumbnail_type,
               wsf.id AS windows_search_file_id, wsf.file_name, wsf.item_path,
               wsf.item_url, wsf.folder_path, wsf.date_created, wsf.date_modified,
               wsf.date_accessed, wsf.date_imported, wsf.size, wsf.owner
        FROM thumbcache_entries AS te
        JOIN windows_search_files AS wsf
          ON wsf.case_id = te.case_id
         AND wsf.image_id = te.image_id
        WHERE {' AND '.join(where)}
          AND te.parser_status = 'parsed'
          AND (
            LOWER(COALESCE(wsf.file_extension, '')) IN ({",".join("?" for _ in IMAGE_EXTENSIONS)})
            OR {" OR ".join("LOWER(COALESCE(wsf.item_path, '')) LIKE ?" for _ in IMAGE_EXTENSIONS)}
          )
          AND (
            te.user_profile = ''
            OR LOWER(COALESCE(wsf.item_path, '')) LIKE LOWER('%\\Users\\' || te.user_profile || '\\%')
            OR LOWER(COALESCE(wsf.item_path, '')) LIKE LOWER('%/Users/' || te.user_profile || '/%')
          )
        LIMIT 5000
        """,
        [*params, *sorted(IMAGE_EXTENSIONS), *(f"%{extension}" for extension in sorted(IMAGE_EXTENSIONS))],
    ).fetchall()
    return [_correlation_row(dict(row), "same_user_windows_search_image_candidate", "low") for row in rows]


def _correlation_row(row: dict[str, Any], basis: str, confidence: str) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": row["case_id"],
        "computer_id": row["computer_id"],
        "image_id": row["image_id"],
        "tool_output_id": row["tool_output_id"],
        "tool_name": "ThumbcacheParser",
        "thumbcache_entry_id": row["thumbcache_entry_id"],
        "windows_search_file_id": row.get("windows_search_file_id"),
        "correlation_basis": basis,
        "confidence": confidence,
        "cache_id": row.get("cache_id"),
        "thumbcache_user": row.get("thumbcache_user"),
        "thumbcache_path": row.get("thumbcache_path"),
        "thumbcache_name": row.get("thumbcache_name"),
        "thumbnail_sha256": row.get("thumbnail_sha256"),
        "thumbnail_type": row.get("thumbnail_type"),
        "search_item_path": row.get("item_path") or row.get("search_item_path"),
        "search_file_name": row.get("file_name") or _basename(row.get("item_path") or row.get("search_item_path")),
        "search_date_created": row.get("date_created"),
        "search_date_modified": row.get("date_modified"),
        "search_date_accessed": row.get("date_accessed"),
        "search_date_imported": row.get("date_imported"),
        "details_json": json.dumps(
            {
                "search_size": row.get("size"),
                "search_owner": row.get("owner"),
                "search_item_url": row.get("item_url"),
                "search_folder_path": row.get("folder_path"),
                "search_property_name": row.get("property_name"),
                "search_property_value": row.get("property_value"),
                "thumbcache_source_mtime_utc": row.get("source_mtime_utc"),
            },
            sort_keys=True,
        ),
    }


def _basename(value: object) -> str:
    text = str(value or "").replace("/", "\\").rstrip("\\")
    return text.rsplit("\\", 1)[-1] if text else ""


def _timeline_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in rows:
        for field, event_type in (
            ("search_date_created", "thumbcache_search_file_created"),
            ("search_date_modified", "thumbcache_search_file_modified"),
            ("search_date_accessed", "thumbcache_search_file_accessed"),
            ("search_date_imported", "thumbcache_search_file_imported"),
        ):
            timestamp = normalize_timestamp(row.get(field))
            if not timestamp:
                continue
            events.append(
                {
                    "id": str(uuid.uuid4()),
                    "case_id": row["case_id"],
                    "computer_id": row["computer_id"],
                    "image_id": row["image_id"],
                    "tool_output_id": row["tool_output_id"],
                    "source_tool": "ThumbcacheParser",
                    "source_table": "thumbcache_search_correlations",
                    "source_row_id": row["id"],
                    "event_type": event_type,
                    "raw_timestamp": row.get(field),
                    "timestamp_utc": timestamp,
                    "description": row.get("search_item_path") or row.get("search_file_name"),
                    "details": {
                        "correlation_basis": row.get("correlation_basis"),
                        "confidence": row.get("confidence"),
                        "thumbcache_entry_id": row.get("thumbcache_entry_id"),
                        "windows_search_file_id": row.get("windows_search_file_id"),
                    },
                }
            )
    return events
