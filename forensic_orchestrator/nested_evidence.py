from __future__ import annotations

import uuid
import re
from pathlib import Path
from typing import Any

from .analytics_query import query_rows
from .db import Database


NESTED_DISK_FORMATS = {
    ".e01": "ewf",
    ".ex01": "ewf",
    ".l01": "ewf",
    ".lx01": "ewf",
    ".dd": "raw",
    ".raw": "raw",
    ".img": "raw",
    ".001": "raw",
    ".vhd": "vhd",
    ".vhdx": "vhdx",
    ".vmdk": "vmdk",
}


def rebuild_nested_evidence_inventory(db: Database, *, case_id: str, image_id: str | None = None) -> int:
    _delete_existing(db, case_id=case_id, image_id=image_id)
    rows = _mft_nested_disk_rows(db, case_id=case_id, image_id=image_id)
    multipart = _multipart_groups(rows)
    nested_rows = [_nested_row(row, multipart.get(str(row.get("source_id") or ""))) for row in rows]
    db.insert_nested_evidence_items(nested_rows)
    return len(nested_rows)


def _delete_existing(db: Database, *, case_id: str, image_id: str | None) -> None:
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id:
        where.append("image_id = ?")
        params.append(image_id)
    db.conn.execute(f"DELETE FROM nested_evidence_items WHERE {' AND '.join(where)}", params)
    if getattr(db, "analytics", None) is not None:
        db.analytics.delete_case_image("nested_evidence_items", case_id=case_id, image_id=image_id)
    db.conn.commit()


def _mft_nested_disk_rows(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    filters = ["case_id = ?", "COALESCE(is_directory, '') NOT IN ('True', 'true', '1')"]
    params: list[Any] = [case_id]
    if image_id:
        filters.append("image_id = ?")
        params.append(image_id)
    placeholders = ", ".join("?" for _ in NESTED_DISK_FORMATS)
    filters.append(
        f"""(
            LOWER(COALESCE(extension, '')) IN ({placeholders})
            OR LOWER(COALESCE(file_name, '')) LIKE '%.e__'
            OR LOWER(COALESCE(file_name, '')) LIKE '%.e___'
            OR LOWER(COALESCE(file_name, '')) LIKE '%.0__'
        )"""
    )
    params.extend(NESTED_DISK_FORMATS)
    sql = f"""
        SELECT id AS source_id, case_id, computer_id, image_id, 'mft_entries' AS source_table,
               parent_path, file_name, extension, file_size, created_si, modified_si,
               accessed_si, record_changed_si, entry_number, sequence_number, source_file
        FROM mft_entries
        WHERE {' AND '.join(filters)}
        ORDER BY image_id, parent_path, file_name
    """
    return query_rows(db, "mft_entries", sql, params)


def _nested_row(row: dict[str, Any], multipart: dict[str, Any] | None) -> dict[str, Any]:
    extension = str(row.get("extension") or Path(str(row.get("file_name") or "")).suffix).lower()
    detected_format = _detected_format(row)
    parent_path = _normalize_root_path(row.get("parent_path"))
    file_name = str(row.get("file_name") or "")
    original_path = f"{parent_path.rstrip('/')}/{file_name}" if parent_path else f"/{file_name}"
    return {
        "id": str(uuid.uuid4()),
        "case_id": row.get("case_id"),
        "computer_id": row.get("computer_id"),
        "image_id": row.get("image_id"),
        "source_table": row.get("source_table"),
        "source_id": row.get("source_id"),
        "source_file": row.get("source_file"),
        "original_path": original_path,
        "parent_path": parent_path,
        "file_name": file_name,
        "extension": extension,
        "file_size": row.get("file_size"),
        "detected_format": detected_format,
        "created_time_utc": row.get("created_si"),
        "modified_time_utc": row.get("modified_si"),
        "accessed_time_utc": row.get("accessed_si"),
        "record_changed_time_utc": row.get("record_changed_si"),
        "mft_entry_number": row.get("entry_number"),
        "mft_sequence_number": row.get("sequence_number"),
        "multipart_set_id": (multipart or {}).get("set_id"),
        "multipart_part_number": (multipart or {}).get("part_number"),
        "multipart_part_count": (multipart or {}).get("part_count"),
        "multipart_is_first_part": str(bool((multipart or {}).get("is_first_part"))).lower() if multipart else "",
        "multipart_related_parts": (multipart or {}).get("related_parts"),
        "parser_status": "candidate",
        "recommendation": _recommendation(detected_format, multipart),
    }


def _normalize_root_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if not text:
        return ""
    text = "/" + text.lstrip("/")
    return text.rstrip("/") or "/"


def _detected_format(row: dict[str, Any]) -> str:
    extension = str(row.get("extension") or Path(str(row.get("file_name") or "")).suffix).lower()
    if extension in NESTED_DISK_FORMATS:
        return NESTED_DISK_FORMATS[extension]
    name = str(row.get("file_name") or "").lower()
    if re.search(r"\.e\d{2,3}$", name):
        return "ewf"
    if re.search(r"\.\d{3}$", name):
        return "raw"
    return "unknown"


def _multipart_groups(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[tuple[dict[str, Any], int, bool]]] = {}
    for row in rows:
        group_key, part_number, is_first = _multipart_key(row)
        if not group_key:
            continue
        groups.setdefault(group_key, []).append((row, part_number, is_first))
    result: dict[str, dict[str, Any]] = {}
    for group_key, parts in groups.items():
        if len(parts) <= 1:
            continue
        related = ",".join(sorted(str(part[0].get("file_name") or "") for part in parts))
        for row, part_number, is_first in parts:
            result[str(row.get("source_id") or "")] = {
                "set_id": group_key,
                "part_number": part_number,
                "part_count": len(parts),
                "is_first_part": is_first,
                "related_parts": related,
            }
    return result


def _multipart_key(row: dict[str, Any]) -> tuple[str | None, int, bool]:
    parent = _normalize_root_path(row.get("parent_path")).lower()
    name = str(row.get("file_name") or "").lower()
    ewf = re.match(r"(?P<stem>.+)\.e(?P<number>\d{2,3})$", name)
    if ewf:
        part = int(ewf.group("number"))
        return f"{parent}/{ewf.group('stem')}.ewf", part, part == 1
    raw = re.match(r"(?P<stem>.+)\.(?P<number>\d{3})$", name)
    if raw:
        part = int(raw.group("number"))
        return f"{parent}/{raw.group('stem')}.raw-split", part, part == 1
    vmdk_extent = re.match(r"(?P<stem>.+)-s(?P<number>\d{3})\.vmdk$", name)
    if vmdk_extent:
        part = int(vmdk_extent.group("number"))
        return f"{parent}/{vmdk_extent.group('stem')}.vmdk-set", part, part == 1
    if name.endswith("-flat.vmdk"):
        return f"{parent}/{name.removesuffix('-flat.vmdk')}.vmdk-set", 1, False
    if name.endswith(".vmdk"):
        return f"{parent}/{name.removesuffix('.vmdk')}.vmdk-set", 0, True
    return None, 0, False


def _recommendation(detected_format: str, multipart: dict[str, Any] | None) -> str:
    if multipart and int(multipart.get("part_count") or 0) > 1:
        return "Multipart nested disk set; parse from the first/descriptor segment with all parts present"
    return "Parse with nested evidence profile if relevant"
