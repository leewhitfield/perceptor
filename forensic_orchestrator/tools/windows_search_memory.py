from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from pathlib import Path
from typing import Any


SQLITE_HEADER = b"SQLite format 3\x00"
AESGCM_HEADER = b"AesGcm1 SQLite3\x00"


def parse_windows_search_memory_carves(
    source: Path,
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    source_csv: Path,
    max_rows_per_table: int = 100,
) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {
        "carves": [],
        "objects": [],
        "rows": [],
    }
    summary = _load_summary(source)
    row_number = 0
    object_row_number = 0
    table_row_number = 0
    for carve_path in _iter_carves(source):
        row_number += 1
        carve_id = _stable_id(case_id, "windows-search-memory-carve", str(carve_path))
        meta = summary.get(str(carve_path), {})
        parsed = _parse_carve_sqlite(carve_path, max_rows_per_table=max_rows_per_table)
        object_rows = []
        for obj in parsed["objects"]:
            object_row_number += 1
            object_rows.append(
                {
                    "id": _stable_id(carve_id, "object", object_row_number, obj.get("type"), obj.get("name")),
                    "case_id": case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "tool_output_id": tool_output_id,
                    "tool_name": "WindowsSearchMemoryCarveParser",
                    "source_csv": source_csv,
                    "row_number": object_row_number,
                    "carve_id": carve_id,
                    "carve_path": str(carve_path),
                    "object_type": obj.get("type") or "",
                    "object_name": obj.get("name") or "",
                    "table_name": obj.get("tbl_name") or "",
                    "rootpage": obj.get("rootpage") or "",
                    "sql_text": obj.get("sql") or "",
                    "parser_status": parsed["parser_status"],
                    "parser_error": parsed["parser_error"],
                }
            )
        data_rows = []
        for data_row in parsed["rows"]:
            table_row_number += 1
            row_json = json.dumps(data_row.get("row") or {}, ensure_ascii=False, default=str, sort_keys=True)
            data_rows.append(
                {
                    "id": _stable_id(carve_id, "row", table_row_number, data_row.get("table"), row_json),
                    "case_id": case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "tool_output_id": tool_output_id,
                    "tool_name": "WindowsSearchMemoryCarveParser",
                    "source_csv": source_csv,
                    "row_number": table_row_number,
                    "carve_id": carve_id,
                    "carve_path": str(carve_path),
                    "table_name": data_row.get("table") or "",
                    "table_row_number": str(data_row.get("table_row_number") or ""),
                    "row_json": row_json,
                    "row_text": _row_text(data_row.get("row") or {}),
                    "row_sha256": hashlib.sha256(row_json.encode("utf-8", errors="replace")).hexdigest(),
                    "parser_status": data_row.get("parser_status") or "parsed",
                    "parser_error": data_row.get("parser_error") or "",
                }
            )
        rows["carves"].append(
            {
                "id": carve_id,
                "case_id": case_id,
                "computer_id": computer_id,
                "image_id": image_id,
                "tool_output_id": tool_output_id,
                "tool_name": "WindowsSearchMemoryCarveParser",
                "source_csv": source_csv,
                "row_number": row_number,
                "carve_path": str(carve_path),
                "carve_name": carve_path.name,
                "carve_size": str(_size(carve_path)),
                "carve_sha256": _sha256_file(carve_path),
                "source_process": meta.get("process") or "SearchIndexer.exe",
                "source_pid": str(meta.get("pid") or ""),
                "virtual_address": meta.get("virtual_address") or _address_from_name(carve_path.name),
                "detected_format": parsed["detected_format"],
                "page_size": parsed["page_size"],
                "reserved_bytes": parsed["reserved_bytes"],
                "parser_status": parsed["parser_status"],
                "parser_error": parsed["parser_error"],
                "table_count": str(sum(1 for obj in parsed["objects"] if obj.get("type") == "table")),
                "object_count": str(len(parsed["objects"])),
                "extractable_row_count": str(sum(1 for row in data_rows if row.get("parser_status") == "parsed")),
                "matched_disk_db": meta.get("matched_disk_db") or "",
                "matched_disk_page": str(meta.get("matched_disk_page") or ""),
                "matched_tail_hex": meta.get("matched_tail_hex") or "",
                "notes": meta.get("notes") or "",
            }
        )
        rows["objects"].extend(object_rows)
        rows["rows"].extend(data_rows)
    return rows


def _iter_carves(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    return sorted(
        path
        for path in source.glob("*.sqlite")
        if path.is_file()
    )


def _parse_carve_sqlite(path: Path, *, max_rows_per_table: int) -> dict[str, Any]:
    detected_format, page_size, reserved_bytes = _detect_format(path)
    objects: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    if detected_format != "sqlite":
        return {
            "detected_format": detected_format,
            "page_size": page_size,
            "reserved_bytes": reserved_bytes,
            "parser_status": "unsupported_format",
            "parser_error": "",
            "objects": objects,
            "rows": rows,
        }
    parser_status = "parsed"
    parser_error = ""
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        _register_windows_search_collations(conn)
        conn.execute("PRAGMA query_only=ON")
        object_rows = conn.execute(
            """
            SELECT type, name, tbl_name, rootpage, sql
            FROM sqlite_master
            WHERE type IN ('table', 'index', 'view', 'trigger')
            ORDER BY type, name
            """
        ).fetchall()
        for row in object_rows:
            objects.append(
                {
                    "type": row[0] or "",
                    "name": row[1] or "",
                    "tbl_name": row[2] or "",
                    "rootpage": "" if row[3] is None else str(row[3]),
                    "sql": row[4] or "",
                }
            )
        for obj in objects:
            if obj.get("type") != "table":
                continue
            table_rows, table_error = _extract_table_rows(conn, obj["name"], max_rows_per_table)
            if table_error:
                rows.append(
                    {
                        "table": obj["name"],
                        "table_row_number": 0,
                        "row": {},
                        "parser_status": "row_extract_failed",
                        "parser_error": table_error,
                    }
                )
                continue
            rows.extend(table_rows)
        conn.close()
    except Exception as exc:
        parser_status = "schema_extract_failed"
        parser_error = str(exc)
    if parser_status == "parsed" and not rows and objects:
        parser_status = "schema_only"
    if not objects and parser_status == "parsed":
        parser_status = "no_schema_objects"
    return {
        "detected_format": detected_format,
        "page_size": page_size,
        "reserved_bytes": reserved_bytes,
        "parser_status": parser_status,
        "parser_error": parser_error,
        "objects": objects,
        "rows": rows,
    }


def _extract_table_rows(
    conn: sqlite3.Connection,
    table: str,
    limit: int,
) -> tuple[list[dict[str, Any]], str]:
    try:
        cursor = conn.execute(f'SELECT * FROM "{table}" LIMIT ?', (limit,))
        columns = [column[0] for column in cursor.description or []]
        rows = []
        for index, values in enumerate(cursor.fetchall(), start=1):
            rows.append(
                {
                    "table": table,
                    "table_row_number": index,
                    "row": {column: _json_value(value) for column, value in zip(columns, values)},
                    "parser_status": "parsed",
                    "parser_error": "",
                }
            )
        return rows, ""
    except Exception as exc:
        return [], str(exc)


def _detect_format(path: Path) -> tuple[str, str, str]:
    try:
        header = path.read_bytes()[:100]
    except OSError:
        return "unreadable", "", ""
    if header.startswith(SQLITE_HEADER):
        page_size = int.from_bytes(header[16:18], "big")
        reserved = header[20] if len(header) > 20 else 0
        return "sqlite", str(page_size), str(reserved)
    if header.startswith(AESGCM_HEADER):
        return "encrypted_sqlite", "", ""
    return "unknown", "", ""


def _register_windows_search_collations(conn: sqlite3.Connection) -> None:
    def compare(left: str, right: str) -> int:
        return (left.casefold() > right.casefold()) - (left.casefold() < right.casefold())

    for name in (
        "UNICODE_en-US_LINGUISTIC_IGNORECASE",
        "UNICODE_en-US_LINGUISTIC_IGNOREKANATYPE",
        "UNICODE_en-US_LINGUISTIC_IGNOREWIDTH",
    ):
        conn.create_collation(name, compare)


def _load_summary(source: Path) -> dict[str, dict[str, Any]]:
    summary_path = source / "summary.json" if source.is_dir() else source.parent / "summary.json"
    if not summary_path.exists():
        return {}
    try:
        parsed = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    rows = parsed if isinstance(parsed, list) else parsed.get("carves") if isinstance(parsed, dict) else []
    summary: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        carve = row.get("carve") or row.get("path") or row.get("carve_path")
        if not carve:
            continue
        matches = row.get("matches") or row.get("page_matches") or []
        meta = dict(row)
        if isinstance(matches, list) and matches:
            first = matches[0]
            if isinstance(first, dict):
                meta["matched_disk_db"] = first.get("db") or first.get("path") or ""
                meta["matched_disk_page"] = first.get("page") or first.get("page_number") or ""
                meta["matched_tail_hex"] = first.get("tail_hex") or first.get("page_tail_hex") or ""
        summary[str(carve)] = meta
    return summary


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _address_from_name(name: str) -> str:
    match = re.search(r"_([0-9a-fA-F]{8,16})\.sqlite$", name)
    return f"0x{match.group(1)}" if match else ""


def _stable_id(*parts: object) -> str:
    digest = hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8", errors="replace")).hexdigest()
    return str(uuid.UUID(digest[:32]))


def _row_text(row: dict[str, Any]) -> str:
    values = [str(value) for value in row.values() if value not in (None, "")]
    return " | ".join(values)[:4000]


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    return value
