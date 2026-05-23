from __future__ import annotations

import csv
import base64
import binascii
import hashlib
import json
import re
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from forensic_orchestrator.timestamps import normalize_timestamp


ACTIVITY_FIELDS = [
    "source_path",
    "user_profile",
    "source_table",
    "activity_id",
    "app_id",
    "app_display_name",
    "activity_type",
    "display_text",
    "file_name",
    "content_uri",
    "activation_uri",
    "fallback_uri",
    "start_time_utc",
    "end_time_utc",
    "last_modified_utc",
    "expiration_time_utc",
    "platform_device_id",
    "payload_json",
    "raw_json",
]

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_windows_activities_to_csv(source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    if source.exists():
        for db_path in sorted(source.rglob("ActivitiesCache.db")):
            if db_path.is_file():
                rows.extend(_activity_rows(_sqlite_working_copy(db_path, output), source, original_db_path=db_path))
    csv_path = output / "WindowsActivities.csv"
    _write_csv(csv_path, ACTIVITY_FIELDS, rows)
    return [csv_path]


def _activity_rows(db_path: Path, source_root: Path, *, original_db_path: Path | None = None) -> list[dict[str, object]]:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        tables = [row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    except sqlite3.Error:
        return _recovered_clipboard_rows(original_db_path or db_path, source_root, [])
    rows: list[dict[str, object]] = []
    try:
        for table in tables:
            if not _looks_like_activity_table(table):
                continue
            try:
                table_rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
            except sqlite3.Error:
                continue
            for row in table_rows:
                rows.append(_normalize_activity_row(row, original_db_path or db_path, source_root, table))
    finally:
        conn.close()
    rows.extend(_recovered_clipboard_rows(original_db_path or db_path, source_root, rows))
    return rows


def _looks_like_activity_table(table: str) -> bool:
    lower = table.lower()
    return "activit" in lower or lower in {"activity", "activityoperation", "activity_packageid"}


def _normalize_activity_row(row: sqlite3.Row, db_path: Path, source_root: Path, table: str) -> dict[str, object]:
    raw = {key: row[key] for key in row.keys()}
    compact = {_compact_key(key): raw[key] for key in raw}
    payload = _first(compact, "payload", "visualelements", "adaptivecardpayload")
    payload_data = _loads_json(payload)
    app_id = _first(compact, "appid", "applicationid", "packageid")
    display_text = _payload_value(payload_data, "displayText")
    clipboard_text = _clipboard_text(_first(compact, "clipboardpayload"))
    content_uri = _payload_value(payload_data, "contentUri")
    activation_uri = _payload_value(payload_data, "activationUri")
    fallback_uri = _payload_value(payload_data, "fallbackUri")
    file_name = _activity_file_name(display_text, content_uri, activation_uri, fallback_uri, _first(compact, "appactivityid"))
    return {
        "source_path": str(db_path),
        "user_profile": _user_profile(db_path, source_root),
        "source_table": table,
        "activity_id": _first(compact, "appactivityid", "activityid", "id"),
        "app_id": app_id,
        "app_display_name": (
            _first(compact, "appdisplayname", "displayname", "packagename")
            or _payload_value(payload_data, "appDisplayName")
            or display_text
            or _display_name_from_app_id(app_id)
        ),
        "activity_type": _first(compact, "activitytype", "type"),
        "display_text": display_text or clipboard_text,
        "file_name": file_name,
        "content_uri": content_uri,
        "activation_uri": activation_uri,
        "fallback_uri": fallback_uri,
        "start_time_utc": _first_time(compact, "starttime", "starttimestamp", "activationtime"),
        "end_time_utc": _first_time(compact, "endtime", "endtimestamp"),
        "last_modified_utc": _first_time(compact, "lastmodifiedtime", "lastmodified", "modifiedtime"),
        "expiration_time_utc": _first_time(compact, "expirationtime", "expirytime"),
        "platform_device_id": _first(compact, "platformdeviceid", "deviceid"),
        "payload_json": _json_or_text(payload),
        "raw_json": json.dumps(raw, default=str, sort_keys=True),
    }


def _sqlite_working_copy(db_path: Path, output: Path) -> Path:
    work_root = output / "_sqlite_work"
    try:
        rel = db_path.relative_to(output.parent)
    except ValueError:
        rel = Path(*db_path.parts[-6:])
    work_db = work_root / rel
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


def _clipboard_text(value: str | None) -> str | None:
    parsed = _loads_json(value)
    candidates = _clipboard_candidates(parsed) if parsed is not None else [_value_to_text(value)]
    decoded: list[str] = []
    for candidate in candidates:
        text = _maybe_base64_text(candidate)
        if text and text not in decoded:
            decoded.append(text)
    if not decoded:
        return None
    return "; ".join(decoded)[:1024]


def _recovered_clipboard_rows(
    db_path: Path,
    source_root: Path,
    existing_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    try:
        data = db_path.read_bytes()
    except OSError:
        return []
    existing = {
        str(row.get("display_text") or "")
        for row in existing_rows
        if str(row.get("source_table") or "").lower() in {"activity", "activityoperation", "recoveredclipboardpayload"}
    }
    recovered: list[dict[str, object]] = []
    seen_payloads: set[str] = set()
    for match in re.finditer(rb'\[\{"content":"[^"\]\}]{8,}","formatName":"[^"\]\}]{1,80}"(?:,\{"content":"[^"\]\}]{8,}","formatName":"[^"\]\}]{1,80}")*\}\]', data):
        payload = match.group(0).decode("ascii", errors="ignore")
        if payload in seen_payloads:
            continue
        seen_payloads.add(payload)
        clipboard_text = _clipboard_text(payload)
        if not clipboard_text or clipboard_text in existing:
            continue
        recovered.append(
            {
                "source_path": str(db_path),
                "user_profile": _user_profile(db_path, source_root),
                "source_table": "RecoveredClipboardPayload",
                "activity_id": "recovered-clipboard-" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16],
                "app_id": "Microsoft.Windows.Clipboard",
                "app_display_name": "Windows Clipboard",
                "activity_type": "clipboard_recovered",
                "display_text": clipboard_text,
                "file_name": None,
                "content_uri": None,
                "activation_uri": None,
                "fallback_uri": None,
                "start_time_utc": None,
                "end_time_utc": None,
                "last_modified_utc": None,
                "expiration_time_utc": None,
                "platform_device_id": None,
                "payload_json": _json_or_text(payload),
                "raw_json": json.dumps(
                    {
                        "recovery_method": "sqlite_raw_clipboard_payload",
                        "byte_offset": match.start(),
                        "payload": payload,
                    },
                    sort_keys=True,
                ),
            }
        )
    return recovered


def _clipboard_candidates(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, bytes):
        text = _value_to_text(value)
        return [text] if text else []
    if isinstance(value, list):
        candidates: list[str] = []
        for item in value:
            candidates.extend(_clipboard_candidates(item))
        return candidates
    if isinstance(value, dict):
        candidates = []
        preferred_keys = (
            "text", "content", "value", "data", "payload", "clipboardText",
            "Text", "Content", "Value", "Data", "Payload", "ClipboardText",
        )
        for key in preferred_keys:
            if key in value:
                candidates.extend(_clipboard_candidates(value[key]))
        return candidates
    return []


def _maybe_base64_text(value: str | None) -> str | None:
    text = _value_to_text(value)
    if not text or text in {"[]", "{}"}:
        return None
    if 2 <= len(text) and text[0] == "b" and text[1] in {"'", '"'} and text[-1:] == text[1]:
        text = text[2:-1]
    for candidate in (text, text.strip("\"'")):
        if len(candidate) % 4:
            continue
        try:
            data = base64.b64decode(candidate, validate=True)
        except (ValueError, binascii.Error):
            continue
        for encoding in ("utf-8", "utf-16-le", "utf-16"):
            try:
                decoded = data.decode(encoding).strip("\x00\r\n\t ")
            except UnicodeDecodeError:
                continue
            if _looks_printable(decoded):
                return decoded
    return text if _looks_printable(text) else None


def _looks_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for char in text if char.isprintable() or char.isspace())
    return printable / max(len(text), 1) > 0.9


def _first(row: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        text = _value_to_text(value)
        if text:
            return text
    return None


def _first_time(row: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        timestamp = _normalize_time(value)
        if timestamp:
            return timestamp
    return None


def _normalize_time(value: object) -> str | None:
    if value in (None, "", 0, "0"):
        return None
    parsed = normalize_timestamp(str(value))
    if parsed:
        return parsed
    try:
        number = int(float(str(value)))
    except ValueError:
        return None
    candidates = []
    if 10_000_000_000_000_000 <= number <= 300_000_000_000_000_000:
        candidates.append(FILETIME_EPOCH + timedelta(microseconds=number / 10))
    if 1_000_000_000 <= number <= 4_102_444_800:
        candidates.append(UNIX_EPOCH + timedelta(seconds=number))
    if 1_000_000_000_000 <= number <= 4_102_444_800_000:
        candidates.append(UNIX_EPOCH + timedelta(milliseconds=number))
    for candidate in candidates:
        if 1990 <= candidate.year <= 2100:
            return candidate.isoformat().replace("+00:00", "Z")
    return None


def _json_or_text(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return json.dumps(json.loads(value), sort_keys=True)
    except (TypeError, ValueError):
        return value


def _loads_json(value: str | None) -> object | None:
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def _payload_value(payload: object | None, key: str) -> str | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get(key)
    return _value_to_text(value)


def _display_name_from_app_id(app_id: str | None) -> str | None:
    data = _loads_json(app_id)
    if not isinstance(data, list):
        return None
    preferred = None
    for item in data:
        if not isinstance(item, dict):
            continue
        application = _value_to_text(item.get("application"))
        platform = (_value_to_text(item.get("platform")) or "").lower()
        if not application:
            continue
        if platform in {"windows_win32", "windows_universal", "packageid"}:
            preferred = application
            if platform == "windows_win32":
                break
    if not preferred:
        return None
    clean = preferred.replace("\\", "/").rsplit("/", 1)[-1]
    if "!" in clean:
        clean = clean.split("!", 1)[-1]
    return clean or preferred


def _activity_file_name(*values: str | None) -> str | None:
    for value in values:
        text = _value_to_text(value)
        if not text:
            continue
        text = text.split("?", 1)[0].rstrip("/\\")
        if "|" in text and "://" in text:
            text = text.rsplit("|", 1)[-1]
        candidate = text.replace("\\", "/").rsplit("/", 1)[-1]
        if "." in candidate and not candidate.startswith("."):
            return candidate
    return None


def _value_to_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            value = value.hex()
    text = str(value).strip()
    return text or None


def _compact_key(key: str) -> str:
    return "".join(char for char in key.lower() if char.isalnum())


def _user_profile(path: Path, source_root: Path) -> str | None:
    try:
        rel = path.relative_to(source_root).as_posix()
    except ValueError:
        rel = path.as_posix()
    parts = rel.split("/")
    return parts[0] if parts else None


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
