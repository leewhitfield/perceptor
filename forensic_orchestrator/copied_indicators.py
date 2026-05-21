from __future__ import annotations

import uuid
import json
import re
from pathlib import PureWindowsPath
from typing import Any

from forensic_orchestrator.db import Database
from forensic_orchestrator.timestamps import parse_timestamp


def rebuild_copied_file_indicators(db: Database, *, case_id: str, image_id: str | None = None) -> int:
    rows: list[dict[str, Any]] = []
    rows.extend(_mft_indicators(db, case_id=case_id, image_id=image_id))
    rows.extend(_shortcut_indicators(db, case_id=case_id, image_id=image_id))
    rows.extend(_shellbag_indicators(db, case_id=case_id, image_id=image_id))
    rows.extend(_registry_indicators(db, case_id=case_id, image_id=image_id))
    db.replace_copied_file_indicators(case_id=case_id, image_id=image_id, rows=rows)
    return len(rows)


def _mft_indicators(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where, params = _case_image_where("mft_entries", case_id, image_id)
    rows = db.conn.execute(
        f"""
        SELECT mft_entries.*, computers.label AS computer_label
        FROM mft_entries
        LEFT JOIN computers ON mft_entries.computer_id = computers.id
        WHERE {where}
        """,
        params,
    ).fetchall()
    indicators = []
    for row in rows:
        indicators.extend(
            _indicator_from_times(
                row=row,
                source_table="mft_entries",
                source_artifact_type="mft_si",
                source_artifact_name=row["source_file"],
                file_name=row["file_name"],
                file_location=_join_path(row["parent_path"], row["file_name"]),
                created=row["created_si"],
                modified=row["modified_si"],
                extra={"mft_entry_number": row["entry_number"], "mft_sequence_number": row["sequence_number"]},
            )
        )
        indicators.extend(
            _indicator_from_times(
                row=row,
                source_table="mft_entries",
                source_artifact_type="mft_fn",
                source_artifact_name=row["source_file"],
                file_name=row["file_name"],
                file_location=_join_path(row["parent_path"], row["file_name"]),
                created=row["created_fn"],
                modified=row["modified_fn"],
                extra={"mft_entry_number": row["entry_number"], "mft_sequence_number": row["sequence_number"]},
            )
        )
    return indicators


def _shortcut_indicators(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where, params = _case_image_where("shortcut_items", case_id, image_id)
    rows = db.conn.execute(f"SELECT * FROM shortcut_items WHERE {where}", params).fetchall()
    indicators = []
    for row in rows:
        indicators.extend(
            _indicator_from_times(
                row=row,
                source_table="shortcut_items",
                source_artifact_type=row["artifact_type"],
                source_artifact_name=row["artifact_name"],
                file_name=row["file_name"],
                file_location=row["file_location"],
                created=row["target_created"],
                modified=row["target_modified"],
                extra={
                    "artifact_path": row["artifact_path"],
                    "target_accessed": row["target_accessed"],
                    "volume_serial_number": row["volume_serial_number"],
                    "volume_name": row["volume_name"],
                    "jumplist_item_number": row["jumplist_item_number"],
                },
            )
        )
    return indicators


def _shellbag_indicators(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where, params = _case_image_where("shellbag_entries", case_id, image_id)
    rows = db.conn.execute(f"SELECT * FROM shellbag_entries WHERE {where}", params).fetchall()
    indicators = []
    for row in rows:
        indicators.extend(
            _indicator_from_times(
                row=row,
                source_table="shellbag_entries",
                source_artifact_type="shellbag",
                source_artifact_name=row["source_file"],
                file_name=_basename(row["absolute_path"]),
                file_location=row["absolute_path"],
                created=row["created_on"],
                modified=row["modified_on"],
                extra={
                    "user_profile": row["user_profile"],
                    "last_interacted": row["last_interacted"],
                    "volume_serial_number": row["volume_serial_number"],
                    "volume_name": row["volume_name"],
                    "volume_guid": row["volume_guid"],
                },
            )
        )
    return indicators


def _registry_indicators(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    indicators.extend(
        _common_dialog_item_indicators(db, case_id=case_id, image_id=image_id)
    )
    indicators.extend(
        _registry_table_indicators(
            db,
            table="registry_office_mru",
            case_id=case_id,
            image_id=image_id,
            path_column="file_name",
            event_time_column="last_opened",
            artifact_type="office_mru",
        )
    )
    indicators.extend(
        _registry_table_indicators(
            db,
            table="registry_common_dialog_mru",
            case_id=case_id,
            image_id=image_id,
            path_column="absolute_path",
            event_time_column="opened_on",
            artifact_type="common_dialog_mru",
        )
    )
    indicators.extend(
        _registry_table_indicators(
            db,
            table="registry_recentdocs",
            case_id=case_id,
            image_id=image_id,
            path_column="target_name",
            event_time_column="opened_on",
            artifact_type="recentdocs",
        )
    )
    return indicators


def _common_dialog_item_indicators(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where, params = _case_image_where("registry_common_dialog_items", case_id, image_id)
    rows = db.conn.execute(f"SELECT * FROM registry_common_dialog_items WHERE {where}", params).fetchall()
    indicators = []
    for row in rows:
        if not _is_common_dialog_copied_candidate(row):
            continue
        indicators.extend(
            _indicator_from_times(
                row={
                    **dict(row),
                    "tool_name": "RegistryArtifactParser",
                },
                source_table="registry_common_dialog_items",
                source_artifact_type=row["artifact"],
                source_artifact_name=row["key_path"],
                file_name=row["shell_item_name"],
                file_location=row["shell_item_name"],
                created=row["shell_created"],
                modified=row["shell_modified"],
                extra={
                    "source_registry_artifact_id": row["source_registry_artifact_id"],
                    "value_name": row["value_name"],
                    "item_index": row["item_index"],
                    "shell_accessed": row["shell_accessed"],
                    "raw_fat_times_json": row["raw_fat_times_json"],
                    "timestamp_source": "pidl_shell_item",
                },
            )
        )
    return indicators


def _is_common_dialog_copied_candidate(row: Any) -> bool:
    name = str(row["shell_item_name"] or "").strip()
    key_path = str(row["key_path"] or "").lower()
    if not name or name in {".", ".."}:
        return False
    if row["shell_created"] is None or row["shell_modified"] is None:
        return False
    if "cidizemru" in key_path or "cidsizemru" in key_path:
        return False
    if row["artifact"] == "lastvisitedpidlmru":
        return False
    if re.fullmatch(r"[A-Za-z]:\\?", name):
        return False
    if re.fullmatch(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?", name):
        return False
    return True


def _registry_table_indicators(
    db: Database,
    *,
    table: str,
    case_id: str,
    image_id: str | None,
    path_column: str,
    event_time_column: str,
    artifact_type: str,
) -> list[dict[str, Any]]:
    where, params = _case_image_where(table, case_id, image_id)
    source_rows = db.conn.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchall()
    indicators = []
    for source in source_rows:
        path_value = source[path_column]
        if not path_value:
            continue
        mft = _find_mft_match(db, case_id=case_id, image_id=source["image_id"], path=path_value)
        if mft is None:
            continue
        indicators.extend(
            _indicator_from_times(
                row=source,
                source_table=table,
                source_artifact_type=artifact_type,
                source_artifact_name=source["key_path"] if "key_path" in source.keys() else source["batch_key_path"],
                file_name=mft["file_name"],
                file_location=_join_path(mft["parent_path"], mft["file_name"]),
                created=mft["created_si"],
                modified=mft["modified_si"],
                extra={
                    "registry_path_value": path_value,
                    "registry_event_time": source[event_time_column],
                    "mft_entry_number": mft["entry_number"],
                    "mft_sequence_number": mft["sequence_number"],
                },
                matched_mft=mft,
            )
        )
    return indicators


def _indicator_from_times(
    *,
    row: Any,
    source_table: str,
    source_artifact_type: str,
    source_artifact_name: str | None,
    file_name: str | None,
    file_location: str | None,
    created: str | None,
    modified: str | None,
    extra: dict[str, Any],
    matched_mft: Any | None = None,
) -> list[dict[str, Any]]:
    created_dt = parse_timestamp(created)
    modified_dt = parse_timestamp(modified)
    if created_dt is None or modified_dt is None or created_dt <= modified_dt:
        return []
    return [
        {
            "id": str(uuid.uuid4()),
            "case_id": row["case_id"],
            "computer_id": row["computer_id"],
            "image_id": row["image_id"],
            "tool_output_id": row["tool_output_id"],
            "source_tool": row["tool_name"],
            "source_table": source_table,
            "source_row_id": row["id"],
            "source_artifact_type": source_artifact_type,
            "source_artifact_name": source_artifact_name,
            "file_name": file_name,
            "file_location": file_location,
            "created_time": created,
            "modified_time": modified,
            "created_timestamp_utc": created_dt.isoformat().replace("+00:00", "Z"),
            "modified_timestamp_utc": modified_dt.isoformat().replace("+00:00", "Z"),
            "indicator": "created_after_modified",
            "reason": "file creation timestamp is after file modification timestamp",
            "confidence": "indicator",
            "matched_mft_entry_number": matched_mft["entry_number"] if matched_mft is not None else extra.get("mft_entry_number"),
            "matched_mft_sequence_number": matched_mft["sequence_number"] if matched_mft is not None else extra.get("mft_sequence_number"),
            "details_json": json.dumps(extra, default=str),
        }
    ]


def _find_mft_match(db: Database, *, case_id: str, image_id: str, path: str) -> Any | None:
    normalized = _normalize_path(path)
    basename = _basename(normalized)
    if not basename:
        return None
    parent_hint = _parent_path(normalized)
    if parent_hint:
        row = db.conn.execute(
            """
            SELECT *
            FROM mft_entries
            WHERE case_id = ? AND image_id = ? AND LOWER(file_name) = LOWER(?)
              AND LOWER(REPLACE(parent_path, '/', '\\')) LIKE '%' || LOWER(?) || '%'
            ORDER BY row_number
            LIMIT 1
            """,
            (case_id, image_id, basename, parent_hint),
        ).fetchone()
        if row is not None:
            return row
    return db.conn.execute(
        """
        SELECT *
        FROM mft_entries
        WHERE case_id = ? AND image_id = ? AND LOWER(file_name) = LOWER(?)
        ORDER BY row_number
        LIMIT 1
        """,
        (case_id, image_id, basename),
    ).fetchone()


def _case_image_where(table: str, case_id: str, image_id: str | None) -> tuple[str, list[Any]]:
    where = [f"{table}.case_id = ?"]
    params: list[Any] = [case_id]
    if image_id is not None:
        where.append(f"{table}.image_id = ?")
        params.append(image_id)
    return " AND ".join(where), params


def _join_path(parent: str | None, name: str | None) -> str | None:
    if not parent and not name:
        return None
    if not parent:
        return name
    if not name:
        return parent
    return f"{parent.rstrip('\\/')}/{name}"


def _normalize_path(value: str | None) -> str:
    return str(value or "").strip().replace("/", "\\")


def _basename(value: str | None) -> str | None:
    text = _normalize_path(value)
    if not text:
        return None
    return PureWindowsPath(text).name


def _parent_path(value: str | None) -> str | None:
    text = _normalize_path(value)
    if not text:
        return None
    parent = str(PureWindowsPath(text).parent)
    if parent in {".", ""}:
        return None
    return parent
