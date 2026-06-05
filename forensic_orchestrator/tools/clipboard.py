from __future__ import annotations

import csv
import json
import re
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from forensic_orchestrator.timestamps import normalize_timestamp


CLIPBOARD_FIELDS = [
    "source_path",
    "user_profile",
    "source_type",
    "source_table",
    "row_identifier",
    "item_time_utc",
    "created_time_utc",
    "modified_time_utc",
    "last_used_time_utc",
    "sequence_number",
    "format_name",
    "content_type",
    "text_content",
    "file_uri",
    "html_content",
    "image_present",
    "payload_size",
    "cloud_sync_state",
    "cloud_sync_id",
    "device_id",
    "raw_payload_json",
    "parser_status",
    "parser_error",
]

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
MAX_TEXT_LENGTH = 16_384
MAX_RAW_JSON_LENGTH = 32_768


def parse_clipboard_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "ClipboardItems.csv"
    rows: list[dict[str, object]] = []
    stores = _clipboard_stores(source)
    for store in stores:
        if store.suffix.lower() in {".json", ".jsonl"}:
            rows.extend(_json_rows(store, source))
        elif _looks_like_sqlite_name(store):
            rows.extend(_sqlite_rows(_sqlite_working_copy(store, output), source, original_path=store))
        else:
            rows.extend(_file_rows(store, source))
    _write_csv(csv_path, rows)
    return csv_path


def _clipboard_stores(source: Path) -> list[Path]:
    if not source.exists():
        return []
    if source.is_file() and _is_clipboard_store(source):
        return [source]
    if not source.is_dir():
        return []
    return sorted(path for path in source.rglob("*") if path.is_file() and _is_clipboard_store(path))


def _is_clipboard_store(path: Path) -> bool:
    parts = [part.casefold() for part in path.parts]
    name = path.name.casefold()
    in_clipboard_dir = "microsoft" in parts and "clipboard" in parts
    if not in_clipboard_dir:
        return False
    if {"windows", "clipboard"}.issubset(set(parts)) and ("historydata" in parts or "pinned" in parts):
        return True
    if name in {"clipboard.db", "clipboard.sqlite", "clipboard.json"}:
        return True
    if path.suffix.casefold() in {".db", ".sqlite", ".sqlite3", ".json", ".jsonl"}:
        return True
    return False


def _looks_like_sqlite_name(path: Path) -> bool:
    name = path.name.casefold()
    return name in {"clipboard.db", "clipboard.sqlite"} or path.suffix.casefold() in {".db", ".sqlite", ".sqlite3"}


def _sqlite_rows(db_path: Path, source_root: Path, *, original_path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        tables = [
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            if not str(row["name"]).casefold().startswith("sqlite_")
        ]
    except sqlite3.Error as exc:
        return [_error_row(original_path, source_root, "sqlite", str(exc))]
    try:
        for table in tables:
            try:
                table_rows = conn.execute(f"SELECT rowid AS __rowid__, * FROM {_quote_identifier(table)}").fetchall()
            except sqlite3.Error as exc:
                rows.append(_error_row(original_path, source_root, "sqlite", f"{table}: {exc}", source_table=table))
                continue
            for row in table_rows:
                rows.append(_normalize_mapping(dict(row), original_path, source_root, source_type="sqlite", source_table=table))
    finally:
        conn.close()
    if not rows:
        rows.append(_inventory_row(original_path, source_root, "sqlite"))
    return rows


def _json_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        return [_error_row(path, source_root, "json", str(exc))]
    rows: list[dict[str, object]] = []
    if path.suffix.casefold() == ".jsonl":
        for index, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                rows.append(_error_row(path, source_root, "jsonl", f"line {index}: {exc}"))
                continue
            rows.extend(_normalize_json_value(parsed, path, source_root, source_table=f"jsonl:{index}"))
    else:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            return [_error_row(path, source_root, "json", str(exc))]
        rows.extend(_normalize_json_value(parsed, path, source_root, source_table="json"))
    return rows or [_inventory_row(path, source_root, "json")]


def _file_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [_error_row(path, source_root, "file", str(exc))]
    stat = _safe_stat(path)
    row = {
        "id": _clipboard_guid_from_path(path),
        "created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat().replace("+00:00", "Z") if stat else "",
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z") if stat else "",
        "accessed": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat().replace("+00:00", "Z") if stat else "",
        "format": _format_from_file(path, data),
        "contenttype": _content_type_from_file(path, data),
        "payloadsize": str(len(data)),
        "data": _readable_payload_text(data),
    }
    normalized = _normalize_mapping(row, path, source_root, source_type="file", source_table=_clipboard_file_source_table(path))
    normalized["parser_status"] = "parsed_file" if normalized.get("text_content") else "binary_payload"
    return [normalized]


def _normalize_json_value(value: Any, path: Path, source_root: Path, *, source_table: str) -> list[dict[str, object]]:
    if isinstance(value, list):
        return [
            _normalize_mapping(item if isinstance(item, dict) else {"value": item}, path, source_root, source_type="json", source_table=source_table)
            for item in value
        ]
    if isinstance(value, dict):
        if any(isinstance(item, dict) for item in value.values()):
            rows = []
            for key, item in value.items():
                mapping = dict(item) if isinstance(item, dict) else {"value": item}
                mapping.setdefault("id", key)
                rows.append(_normalize_mapping(mapping, path, source_root, source_type="json", source_table=source_table))
            return rows
        return [_normalize_mapping(value, path, source_root, source_type="json", source_table=source_table)]
    return [_normalize_mapping({"value": value}, path, source_root, source_type="json", source_table=source_table)]


def _normalize_mapping(
    row: dict[str, Any],
    path: Path,
    source_root: Path,
    *,
    source_type: str,
    source_table: str,
) -> dict[str, object]:
    compact = {_compact_key(key): value for key, value in row.items()}
    text_content = _best_text(compact, ("text", "plaintext", "plain", "content", "value", "string", "payload", "data"))
    html_content = _best_text(compact, ("html", "htmlcontent", "richtext"))
    file_uri = _best_text(compact, ("fileuri", "fileurl", "filepath", "path", "uri", "sourceuri"))
    format_name = _first_text(compact, "formatname", "format", "type", "kind", "mimetype", "contenttype")
    content_type = _first_text(compact, "contenttype", "mimetype", "mime", "formatname", "format")
    blob_size = _blob_payload_size(row)
    item_time = _first_time(compact, "itemtime", "timestamp", "time", "createdtime", "created", "lastmodifiedtime", "modifiedtime", "lastusedtime")
    created_time = _first_time(compact, "createdtime", "created", "creationtime")
    modified_time = _first_time(compact, "modifiedtime", "lastmodifiedtime", "modified", "updatedtime", "updated")
    last_used_time = _first_time(compact, "lastusedtime", "lastused", "lastaccesstime", "accessedtime")
    return {
        "source_path": str(path),
        "user_profile": _user_profile(path, source_root),
        "source_type": source_type,
        "source_table": source_table,
        "row_identifier": _first_text(compact, "id", "rowid", "__rowid__", "itemid", "guid", "clipid"),
        "item_time_utc": item_time or created_time or modified_time or last_used_time,
        "created_time_utc": created_time,
        "modified_time_utc": modified_time,
        "last_used_time_utc": last_used_time,
        "sequence_number": _first_text(compact, "sequencenumber", "sequence", "seq", "ordernumber", "sortorder"),
        "format_name": format_name,
        "content_type": content_type,
        "text_content": _truncate(text_content),
        "file_uri": file_uri,
        "html_content": _truncate(html_content),
        "image_present": _bool_text(_looks_like_image(format_name, content_type) or (blob_size > 0 and not text_content and not html_content)),
        "payload_size": str(blob_size) if blob_size else _first_text(compact, "payloadsize", "size", "length", "bytes"),
        "cloud_sync_state": _first_text(compact, "cloudsyncstate", "syncstate", "synced", "issynced", "roamingstate", "isroaming"),
        "cloud_sync_id": _first_text(compact, "cloudsyncid", "syncid", "roamingid", "accountid"),
        "device_id": _first_text(compact, "deviceid", "sourcedeviceid", "platformdeviceid", "sourceid"),
        "raw_payload_json": _raw_json(row),
        "parser_status": "parsed",
        "parser_error": "",
    }


def _sqlite_working_copy(db_path: Path, output: Path) -> Path:
    work_root = output / "_sqlite_work"
    work_db = work_root / Path(*db_path.parts[-8:])
    work_db.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(db_path, work_db)
        for suffix in ("-wal", "-shm"):
            companion = Path(f"{db_path}{suffix}")
            if companion.exists():
                shutil.copy2(companion, Path(f"{work_db}{suffix}"))
    except OSError:
        return db_path
    return work_db


def _first_text(compact: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = compact.get(_compact_key(key))
        text = _value_to_text(value)
        if text:
            return text
    return ""


def _best_text(compact: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = compact.get(_compact_key(key))
        text = _decode_payload_text(value)
        if text:
            return text
    for key, value in compact.items():
        if any(token in key for token in keys):
            text = _decode_payload_text(value)
            if text:
                return text
    return ""


def _decode_payload_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        for encoding in ("utf-8", "utf-16le", "utf-16be"):
            try:
                text = value.decode(encoding, errors="ignore").strip("\x00\r\n\t ")
            except UnicodeError:
                continue
            if _looks_readable(text):
                return text
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return _value_to_text(value)


def _value_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return _decode_payload_text(value)
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"}:
        return ""
    return text


def _first_time(compact: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = compact.get(_compact_key(key))
        timestamp = _timestamp(value)
        if timestamp:
            return timestamp
    for key, value in compact.items():
        if any(token in key for token in ("time", "date", "created", "modified", "updated", "used")):
            timestamp = _timestamp(value)
            if timestamp:
                return timestamp
    return ""


def _timestamp(value: Any) -> str:
    if value in (None, ""):
        return ""
    normalized = normalize_timestamp(value)
    if normalized:
        return normalized
    text = str(value).strip()
    if not re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return ""
    number = float(text)
    candidates: list[float] = []
    if number > 11_644_473_600_000_000:
        candidates.append((number / 10_000_000) - 11_644_473_600)
    if number > 11_644_473_600_000:
        candidates.append((number / 10_000) - 11_644_473_600)
    if number > 10_000_000_000_000:
        candidates.append(number / 1_000_000)
    if number > 10_000_000_000:
        candidates.append(number / 1000)
    candidates.append(number)
    for epoch_seconds in candidates:
        if 946684800 <= epoch_seconds <= 4102444800:
            return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return ""


def _blob_payload_size(row: dict[str, Any]) -> int:
    total = 0
    for value in row.values():
        if isinstance(value, bytes):
            total += len(value)
    return total


def _clipboard_file_source_table(path: Path) -> str:
    parts = [part.casefold() for part in path.parts]
    if "historydata" in parts:
        return "HistoryData"
    if "pinned" in parts:
        return "Pinned"
    return "ClipboardFile"


def _clipboard_guid_from_path(path: Path) -> str:
    guid_re = re.compile(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
    for part in reversed(path.parts):
        if guid_re.match(part):
            return part
    return path.name


def _format_from_file(path: Path, data: bytes) -> str:
    suffix = path.suffix.casefold().lstrip(".")
    if suffix:
        return suffix
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"BM"):
        return "bitmap"
    text = _readable_payload_text(data)
    return "text" if text else "binary"


def _content_type_from_file(path: Path, data: bytes) -> str:
    fmt = _format_from_file(path, data)
    return {
        "png": "image/png",
        "jpeg": "image/jpeg",
        "jpg": "image/jpeg",
        "bitmap": "image/bmp",
        "json": "application/json",
        "text": "text/plain",
    }.get(fmt, "application/octet-stream")


def _readable_payload_text(data: bytes) -> str:
    candidates: list[str] = []
    for encoding in ("utf-8", "utf-16le", "utf-16be"):
        try:
            text = data.decode(encoding, errors="ignore")
        except UnicodeError:
            continue
        if _looks_readable(text):
            candidates.append(text.strip("\x00\r\n\t "))
    for pattern, encoding in ((rb"[\x20-\x7e]{4,}", "ascii"),):
        hits = [match.group(0).decode(encoding, errors="replace") for match in re.finditer(pattern, data)]
        if hits:
            candidates.append("\n".join(hits))
    for text in candidates:
        cleaned = _clean_text(text)
        if cleaned:
            return cleaned
    return ""


def _clean_text(value: str) -> str:
    text = value.replace("\x00", "")
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _safe_stat(path: Path):
    try:
        return path.stat()
    except OSError:
        return None


def _looks_like_image(*values: str | None) -> bool:
    text = " ".join(value or "" for value in values).casefold()
    return any(token in text for token in ("image", "bitmap", "png", "jpeg", "jpg", "dib"))


def _looks_readable(text: str) -> bool:
    stripped = text.strip("\x00\r\n\t ")
    if len(stripped) < 2:
        return False
    printable = sum(1 for char in stripped if char.isprintable() or char in "\r\n\t")
    return printable / max(len(stripped), 1) > 0.85


def _raw_json(row: dict[str, Any]) -> str:
    def normalize(value: Any) -> Any:
        if isinstance(value, bytes):
            return {"blob_length": len(value)}
        return value

    text = json.dumps({str(key): normalize(value) for key, value in row.items()}, ensure_ascii=False, default=str, sort_keys=True)
    return text[:MAX_RAW_JSON_LENGTH]


def _inventory_row(path: Path, source_root: Path, source_type: str) -> dict[str, object]:
    return _blank_row(path, source_root, source_type) | {"parser_status": "found_no_rows"}


def _error_row(path: Path, source_root: Path, source_type: str, error: str, *, source_table: str = "") -> dict[str, object]:
    return _blank_row(path, source_root, source_type) | {
        "source_table": source_table,
        "parser_status": "error",
        "parser_error": error[:2000],
    }


def _blank_row(path: Path, source_root: Path, source_type: str) -> dict[str, object]:
    return {
        field: ""
        for field in CLIPBOARD_FIELDS
    } | {
        "source_path": str(path),
        "user_profile": _user_profile(path, source_root),
        "source_type": source_type,
    }


def _user_profile(path: Path, source_root: Path) -> str:
    try:
        rel = path.relative_to(source_root)
    except ValueError:
        rel = path
    parts = list(rel.parts)
    for index, part in enumerate(parts):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    if parts and parts[0].lower() not in {"appdata", "microsoft", "clipboard"}:
        return parts[0]
    return ""


def _compact_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).casefold())


def _truncate(value: str) -> str:
    return value[:MAX_TEXT_LENGTH] if value else ""


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CLIPBOARD_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in CLIPBOARD_FIELDS})
