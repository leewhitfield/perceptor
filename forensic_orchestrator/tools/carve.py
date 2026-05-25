from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import uuid
from pathlib import Path
from typing import Any


SQLITE_HEADER = b"SQLite format 3\x00"
AESGCM_HEADER = b"AesGcm1 SQLite3\x00"
ESE_MAGIC = b"\xef\xcd\xab\x89"


def stage_sqlite_carves(
    source: Path,
    output_dir: Path,
    *,
    max_carves: int = 1000,
    max_bytes: int = 2 * 1024 * 1024 * 1024,
    max_carve_size: int = 256 * 1024 * 1024,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    scanned_bytes = 0
    limit_reason = ""
    for candidate in _iter_candidates(source):
        if len(rows) >= max_carves:
            limit_reason = "max_carves"
            break
        try:
            size = candidate.stat().st_size
        except OSError:
            continue
        remaining = max_bytes - scanned_bytes
        if remaining <= 0:
            limit_reason = "max_bytes"
            break
        scanned_bytes += min(size, remaining)
        if _is_sqlite(candidate) or _is_aesgcm(candidate):
            rows.append(_stage_existing_file(candidate, output_dir))
            continue
        for offset in _sqlite_offsets(candidate, max_bytes=remaining):
            if len(rows) >= max_carves:
                limit_reason = "max_carves"
                break
            staged = _carve_sqlite_at_offset(candidate, output_dir, offset, max_carve_size=max_carve_size)
            if staged:
                rows.append(staged)
        if limit_reason:
            break
    return {
        "source": str(source),
        "output_dir": str(output_dir),
        "carves": rows,
        "scanned_bytes": scanned_bytes,
        "carve_count": len(rows),
        "limited": bool(limit_reason),
        "limit_reason": limit_reason,
    }


def stage_ese_carves(
    source: Path,
    output_dir: Path,
    *,
    max_carves: int = 1000,
    max_bytes: int = 2 * 1024 * 1024 * 1024,
    max_carve_size: int = 512 * 1024 * 1024,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    scanned_bytes = 0
    limit_reason = ""
    for candidate in _iter_candidates(source):
        if len(rows) >= max_carves:
            limit_reason = "max_carves"
            break
        try:
            size = candidate.stat().st_size
        except OSError:
            continue
        remaining = max_bytes - scanned_bytes
        if remaining <= 0:
            limit_reason = "max_bytes"
            break
        scanned_bytes += min(size, remaining)
        if _is_ese(candidate):
            rows.append(_stage_existing_file(candidate, output_dir, default_suffix=".edb"))
            continue
        for offset in _ese_offsets(candidate, max_bytes=remaining):
            if len(rows) >= max_carves:
                limit_reason = "max_carves"
                break
            staged = _carve_bytes_at_offset(candidate, output_dir, offset, max_carve_size=max_carve_size, suffix=".edb")
            if staged:
                rows.append(staged)
        if limit_reason:
            break
    return {
        "source": str(source),
        "output_dir": str(output_dir),
        "carves": rows,
        "scanned_bytes": scanned_bytes,
        "carve_count": len(rows),
        "limited": bool(limit_reason),
        "limit_reason": limit_reason,
    }


def summarize_sqlite_carve(path: Path, *, max_rows_per_table: int = 25) -> dict[str, Any]:
    detected_format, page_size, reserved_bytes = detect_carve_format(path)
    if detected_format != "sqlite":
        return {
            "detected_format": detected_format,
            "page_size": page_size,
            "reserved_bytes": reserved_bytes,
            "parser_status": "unsupported_format" if detected_format != "unreadable" else "unreadable",
            "parser_error": "",
            "table_count": 0,
            "object_count": 0,
            "extractable_row_count": 0,
        }
    parser_status = "parsed"
    parser_error = ""
    object_count = 0
    table_count = 0
    extractable_rows = 0
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.execute("PRAGMA query_only=ON")
        objects = conn.execute(
            """
            SELECT type, name
            FROM sqlite_master
            WHERE type IN ('table', 'index', 'view', 'trigger')
            ORDER BY type, name
            """
        ).fetchall()
        object_count = len(objects)
        tables = [row[1] for row in objects if row[0] == "table"]
        table_count = len(tables)
        for table in tables:
            try:
                extractable_rows += int(conn.execute(f'SELECT COUNT(*) FROM (SELECT 1 FROM "{table}" LIMIT ?) AS limited_rows', (max_rows_per_table,)).fetchone()[0])
            except Exception:
                continue
        conn.close()
    except Exception as exc:
        parser_status = "schema_extract_failed"
        parser_error = str(exc)
    if parser_status == "parsed" and object_count and not extractable_rows:
        parser_status = "schema_only"
    if parser_status == "parsed" and not object_count:
        parser_status = "no_schema_objects"
    return {
        "detected_format": detected_format,
        "page_size": page_size,
        "reserved_bytes": reserved_bytes,
        "parser_status": parser_status,
        "parser_error": parser_error,
        "table_count": table_count,
        "object_count": object_count,
        "extractable_row_count": extractable_rows,
    }


def summarize_ese_carve(path: Path) -> dict[str, Any]:
    detected_format, page_size, reserved_bytes = detect_carve_format(path)
    parser_status = "staged" if detected_format == "ese" else "unsupported_format"
    return {
        "detected_format": detected_format,
        "page_size": page_size,
        "reserved_bytes": reserved_bytes,
        "parser_status": parser_status,
        "parser_error": "",
        "table_count": 0,
        "object_count": 0,
        "extractable_row_count": 0,
    }


def detect_carve_format(path: Path) -> tuple[str, str, str]:
    try:
        with path.open("rb") as handle:
            header = handle.read(512)
    except OSError:
        return "unreadable", "", ""
    if header.startswith(SQLITE_HEADER):
        page_size = int.from_bytes(header[16:18], "big")
        reserved = header[20] if len(header) > 20 else 0
        return "sqlite", str(page_size), str(reserved)
    if header.startswith(AESGCM_HEADER):
        return "encrypted_sqlite", "", ""
    if len(header) >= 8 and header[4:8] == ESE_MAGIC:
        page_size = _ese_page_size(header)
        return "ese", str(page_size) if page_size else "", ""
    return "unknown", "", ""


def staged_carve_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    source_csv: Path,
    row_number: int,
    profile: str,
    source_path: str,
    staged: dict[str, Any],
    summary: dict[str, Any],
    carve_type: str = "sqlite",
    notes: str | None = None,
) -> dict[str, Any]:
    staged_path = str(staged["path"])
    return {
        "id": _stable_id(case_id, "staged-carve", staged_path, staged.get("source_offset")),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": "CarveStageRunner",
        "source_csv": source_csv,
        "row_number": row_number,
        "profile": profile,
        "source_path": source_path,
        "source_offset": str(staged.get("source_offset") or ""),
        "staged_path": staged_path,
        "staged_name": Path(staged_path).name,
        "staged_size": str(staged.get("size") or ""),
        "staged_sha256": staged.get("sha256") or "",
        "carve_type": carve_type,
        "detected_format": summary.get("detected_format") or "",
        "parser_status": summary.get("parser_status") or "",
        "parser_error": summary.get("parser_error") or "",
        "table_count": str(summary.get("table_count") or 0),
        "object_count": str(summary.get("object_count") or 0),
        "extractable_row_count": str(summary.get("extractable_row_count") or 0),
        "import_status": "staged",
        "notes": notes or f"{carve_type.upper()} carve staged for artifact-specific import.",
    }


def _iter_candidates(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    return sorted(path for path in source.rglob("*") if path.is_file())


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    except OSError:
        return False


def _is_aesgcm(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(AESGCM_HEADER)) == AESGCM_HEADER
    except OSError:
        return False


def _is_ese(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
        return len(header) >= 8 and header[4:8] == ESE_MAGIC
    except OSError:
        return False


def _sqlite_offsets(path: Path, *, max_bytes: int | None = None) -> list[int]:
    return _find_offsets(path, SQLITE_HEADER, max_bytes=max_bytes)


def _ese_offsets(path: Path, *, max_bytes: int | None = None) -> list[int]:
    offsets = []
    for offset in _find_offsets(path, ESE_MAGIC, max_bytes=max_bytes):
        candidate = offset - 4
        if candidate >= 0:
            offsets.append(candidate)
    return offsets


def _find_offsets(path: Path, needle: bytes, *, max_bytes: int | None = None) -> list[int]:
    offsets = []
    overlap = len(needle) - 1
    absolute = 0
    tail = b""
    with path.open("rb") as handle:
        while True:
            if max_bytes is not None and absolute >= max_bytes:
                break
            read_size = 1024 * 1024
            if max_bytes is not None:
                read_size = min(read_size, max_bytes - absolute)
            chunk = handle.read(read_size)
            if not chunk:
                break
            data = tail + chunk
            search_from = 0
            while True:
                found = data.find(needle, search_from)
                if found < 0:
                    break
                offset = absolute - len(tail) + found
                if offset >= 0:
                    offsets.append(offset)
                search_from = found + len(needle)
            tail = data[-overlap:] if len(data) >= overlap else data
            absolute += len(chunk)
    return offsets


def _stage_existing_file(path: Path, output_dir: Path, *, default_suffix: str = ".sqlite") -> dict[str, Any]:
    digest = _sha256_file(path)
    destination = output_dir / f"{path.stem}_{digest[:16]}{path.suffix or default_suffix}"
    if destination.resolve() != path.resolve():
        shutil.copy2(path, destination)
    return {
        "path": str(destination),
        "source_offset": 0,
        "size": destination.stat().st_size,
        "sha256": digest,
    }


def _carve_sqlite_at_offset(path: Path, output_dir: Path, offset: int, *, max_carve_size: int) -> dict[str, Any] | None:
    with path.open("rb") as handle:
        handle.seek(offset)
        header = handle.read(100)
        if not header.startswith(SQLITE_HEADER):
            return None
        page_size = int.from_bytes(header[16:18], "big") or 4096
        page_count = int.from_bytes(header[28:32], "big") or 1
        carve_size = min(max(page_size * page_count, page_size), max_carve_size)
        handle.seek(offset)
        payload = handle.read(carve_size)
    digest = hashlib.sha256(payload).hexdigest()
    destination = output_dir / f"{path.stem}_offset_{offset:012x}_{digest[:16]}.sqlite"
    destination.write_bytes(payload)
    return {
        "path": str(destination),
        "source_offset": offset,
        "size": len(payload),
        "sha256": digest,
    }


def _carve_bytes_at_offset(path: Path, output_dir: Path, offset: int, *, max_carve_size: int, suffix: str) -> dict[str, Any] | None:
    with path.open("rb") as handle:
        handle.seek(offset)
        payload = handle.read(max_carve_size)
    if not payload:
        return None
    digest = hashlib.sha256(payload).hexdigest()
    destination = output_dir / f"{path.stem}_offset_{offset:012x}_{digest[:16]}{suffix}"
    destination.write_bytes(payload)
    return {
        "path": str(destination),
        "source_offset": offset,
        "size": len(payload),
        "sha256": digest,
    }


def _ese_page_size(header: bytes) -> int:
    for start in (8, 236):
        if len(header) >= start + 4:
            value = int.from_bytes(header[start:start + 4], "little")
            if value in {2048, 4096, 8192, 16384, 32768}:
                return value
    return 0


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_id(*parts: object) -> str:
    digest = hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8", errors="replace")).hexdigest()
    return str(uuid.UUID(digest[:32]))
