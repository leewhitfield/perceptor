from __future__ import annotations

import json
import re
import uuid
from pathlib import PurePosixPath
from typing import Any

from .db import Database


def rebuild_file_correlations(db: Database, *, case_id: str, image_id: str) -> int:
    db.conn.execute(
        "DELETE FROM file_correlations WHERE case_id = ? AND image_id = ?",
        (case_id, image_id),
    )
    mft_entries = _mft_entries(db, case_id, image_id)
    exact_index: dict[str, list[dict[str, Any]]] = {}
    name_index: dict[str, list[dict[str, Any]]] = {}
    for entry in mft_entries:
        normalized = normalize_windows_path(entry["mft_path"])
        if normalized:
            exact_index.setdefault(normalized, []).append(entry)
        if entry["file_name"]:
            name_index.setdefault(entry["file_name"].lower(), []).append(entry)

    rows = []
    rows.extend(_shortcut_correlations(db, case_id, image_id, exact_index, name_index))
    rows.extend(_prefetch_correlations(db, case_id, image_id, exact_index, name_index))
    db.insert_file_correlations(_dedupe(rows))
    return len(rows)


def normalize_windows_path(value: str | None) -> str | None:
    if not value:
        return None
    path = value.strip().replace("\\", "/")
    path = re.sub(r"^/*device/+harddiskvolume\d+/", "", path, flags=re.IGNORECASE)
    path = re.sub(r"^[a-z]:/", "", path, flags=re.IGNORECASE)
    path = path.lstrip("/")
    path = re.sub(r"/+", "/", path)
    return path.lower() or None


def _mft_entries(db: Database, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT id, case_id, computer_id, image_id, file_name, parent_path
        FROM mft_entries
        WHERE case_id = ? AND image_id = ?
        """,
        (case_id, image_id),
    ).fetchall()
    entries = []
    for row in rows:
        path = _mft_path(row["parent_path"], row["file_name"])
        entries.append({**dict(row), "mft_path": path})
    return entries


def _mft_path(parent_path: str | None, file_name: str | None) -> str | None:
    if not file_name:
        return None
    if not parent_path or parent_path == ".":
        return file_name
    return str(PurePosixPath(parent_path.replace("\\", "/")) / file_name)


def _shortcut_correlations(
    db: Database,
    case_id: str,
    image_id: str,
    exact_index: dict[str, list[dict[str, Any]]],
    name_index: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT * FROM shortcut_items
        WHERE case_id = ? AND image_id = ?
        """,
        (case_id, image_id),
    ).fetchall()
    correlations = []
    for row in rows:
        correlations.extend(
            _correlate_source(
                row=dict(row),
                source_table="shortcut_items",
                source_tool=row["tool_name"],
                source_path=row["file_location"],
                fallback_name=row["file_name"],
                exact_index=exact_index,
                name_index=name_index,
                exact_match_type=f"{row['artifact_type']}_target_path",
                name_match_type=f"{row['artifact_type']}_target_name",
            )
        )
    return correlations


def _prefetch_correlations(
    db: Database,
    case_id: str,
    image_id: str,
    exact_index: dict[str, list[dict[str, Any]]],
    name_index: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT * FROM prefetch_items
        WHERE case_id = ? AND image_id = ?
        """,
        (case_id, image_id),
    ).fetchall()
    correlations = []
    for row in rows:
        referenced = _coerce_list(row["referenced_strings"])
        path_candidates = [value for value in referenced if isinstance(value, str) and _looks_like_path(value)]
        matched = False
        for candidate in path_candidates:
            matches = _exact_matches(candidate, exact_index)
            for match in matches:
                matched = True
                correlations.append(
                    _row(
                        source=dict(row),
                        source_table="prefetch_items",
                        source_tool="PrefetchParser",
                        mft_entry=match,
                        match_type="prefetch_referenced_path",
                        confidence="high",
                        source_path=candidate,
                    )
                )
        if not matched:
            correlations.extend(
                _correlate_source(
                    row=dict(row),
                    source_table="prefetch_items",
                    source_tool="PrefetchParser",
                    source_path=None,
                    fallback_name=row["executable_name"],
                    exact_index=exact_index,
                    name_index=name_index,
                    exact_match_type="prefetch_path",
                    name_match_type="prefetch_executable_name",
                )
            )
    return correlations


def _correlate_source(
    *,
    row: dict[str, Any],
    source_table: str,
    source_tool: str,
    source_path: str | None,
    fallback_name: str | None,
    exact_index: dict[str, list[dict[str, Any]]],
    name_index: dict[str, list[dict[str, Any]]],
    exact_match_type: str,
    name_match_type: str,
) -> list[dict[str, Any]]:
    matches = _exact_matches(source_path, exact_index)
    if matches:
        return [
            _row(row, source_table, source_tool, match, exact_match_type, "high", source_path)
            for match in matches
        ]
    if not fallback_name:
        return []
    candidates = name_index.get(fallback_name.lower(), [])
    confidence = "medium" if len(candidates) == 1 else "low"
    return [
        _row(row, source_table, source_tool, match, name_match_type, confidence, source_path or fallback_name)
        for match in candidates
    ]


def _exact_matches(
    source_path: str | None, exact_index: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    normalized = normalize_windows_path(source_path)
    if not normalized:
        return []
    return exact_index.get(normalized, [])


def _row(
    source: dict[str, Any],
    source_table: str,
    source_tool: str,
    mft_entry: dict[str, Any],
    match_type: str,
    confidence: str,
    source_path: str | None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": source["case_id"],
        "computer_id": source["computer_id"],
        "image_id": source["image_id"],
        "source_tool": source_tool,
        "source_table": source_table,
        "source_row_id": source["id"],
        "mft_entry_id": mft_entry["id"],
        "match_type": match_type,
        "confidence": confidence,
        "source_path": source_path,
        "mft_path": mft_entry["mft_path"],
    }


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped = []
    seen = set()
    for row in rows:
        key = (
            row["source_table"],
            row["source_row_id"],
            row["mft_entry_id"],
            row["match_type"],
            row.get("source_path"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return [value]
        return parsed if isinstance(parsed, list) else [parsed]
    return [value]


def _looks_like_path(value: str) -> bool:
    return "\\" in value or "/" in value
