from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse
from xml.etree import ElementTree


TELEMETRY_FIELDS = [
    "record_type",
    "artifact_group",
    "user_profile",
    "application",
    "source_path",
    "source_name",
    "file_name",
    "file_extension",
    "file_size",
    "modified_utc",
    "event_time_utc",
    "identifier",
    "path",
    "url",
    "host",
    "title",
    "value_name",
    "value_data",
    "artifact_text",
    "sha256_first_mb",
    "details_json",
    "error",
]

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
TELEMETRY_PATH_MARKERS = (
    "/windows/system32/wbem/repository/",
    "/appdata/local/microsoft/windows/cloudstore/",
    "/appdata/local/microsoft/windows/notifications/",
    "/programdata/microsoft/windows/apprepository/",
    "/windows/system32/applocker/",
    "/windows/system32/codeintegrity/",
)
WMI_NAMES = {"objects.data", "index.btr", "mapping1.map", "mapping2.map", "mapping3.map"}
NOTIFICATION_DBS = {"wpndatabase.db", "appdb.dat"}
APP_REPOSITORY_NAMES = {"staterepository-machine.srd", "staterepository-deployment.srd", "packagerepository.edb"}
INTERESTING_WMI_STRINGS = (
    "__eventfilter",
    "__eventconsumer",
    "commandlineeventconsumer",
    "activescripteventconsumer",
    "__filtertoconsumerbinding",
    "scrcons.exe",
    "wmiprvse.exe",
    "powershell",
    "cmd.exe",
    "regsvr32",
    "rundll32",
)
URL_RE = re.compile(r"\b(?:https?|file)://[^\s\"'<>()]+", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\[^\x00\r\n\t\"<>|]{4,}")
DEVICE_PATH_RE = re.compile(r"\\Device\\[^\x00\r\n\t\"<>|]{4,}", re.IGNORECASE)
SID_RE = re.compile(r"\bS-\d-\d+(?:-\d+){2,}\b")
GUID_RE = re.compile(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}")
FILETIME_MIN = 116444736000000000
FILETIME_MAX = 190000000000000000


def parse_telemetry_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    sqlite_copies = output / "_sqlite_copies"
    rows: list[dict[str, object]] = []
    for path, error in _walk_telemetry_files(source):
        if error:
            rows.append(_error_row(source, path, error))
            continue
        if path is None:
            continue
        rows.append(_inventory_row(source, path))
        try:
            lower = _normalized(path)
            name = path.name.lower()
            if "/windows/system32/wbem/repository/" in lower:
                rows.extend(_wmi_rows(source, path))
            elif "/appdata/local/microsoft/windows/cloudstore/" in lower:
                rows.extend(_cloudstore_rows(source, path))
            elif "/appdata/local/microsoft/windows/notifications/" in lower:
                rows.extend(_notification_rows(source, path, sqlite_copies))
            elif "/programdata/microsoft/windows/apprepository/" in lower:
                rows.extend(_apprepository_rows(source, path, sqlite_copies))
            elif "/windows/system32/applocker/" in lower:
                rows.extend(_text_or_binary_policy_rows(source, path, "applocker"))
            elif "/windows/system32/codeintegrity/" in lower:
                rows.extend(_text_or_binary_policy_rows(source, path, "wdac"))
            elif name in WMI_NAMES | NOTIFICATION_DBS | APP_REPOSITORY_NAMES:
                rows.extend(_string_summary_rows(source, path, _artifact_group(path)))
        except Exception as exc:  # pragma: no cover - per-file isolation
            rows.append(_error_row(source, path, f"{type(exc).__name__}: {exc}"))
    csv_path = output / "TelemetryArtifacts.csv"
    _write_csv(csv_path, rows)
    return csv_path


def _walk_telemetry_files(source: Path) -> Iterable[tuple[Path | None, str]]:
    if not source.exists():
        yield source, "source path does not exist"
        return
    if source.is_file():
        yield source, ""
        return
    for root, dirnames, filenames in os.walk(source, onerror=lambda _exc: None):
        root_path = Path(root)
        root_lower = _normalized(root_path)
        if not _could_contain_telemetry(root_lower):
            continue
        kept = []
        for dirname in dirnames:
            candidate = root_path / dirname
            try:
                candidate.stat()
            except OSError as exc:
                yield candidate, str(exc)
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            path = root_path / filename
            lower = _normalized(path)
            if not _is_telemetry_file(path, lower):
                continue
            try:
                path.stat()
            except OSError as exc:
                yield path, str(exc)
                continue
            yield path, ""


def _could_contain_telemetry(root_lower: str) -> bool:
    return any(marker.rsplit("/", 1)[0] in root_lower or root_lower in marker for marker in TELEMETRY_PATH_MARKERS)


def _is_telemetry_file(path: Path, lower: str) -> bool:
    name = path.name.lower()
    if any(marker in lower for marker in TELEMETRY_PATH_MARKERS):
        if "/cloudstore/" in lower:
            return path.suffix.lower() in {"", ".dat", ".log", ".json"} or name.endswith(".dat")
        if "/notifications/" in lower:
            return name in NOTIFICATION_DBS or path.suffix.lower() in {".db", ".dat", ".log"}
        if "/apprepository/" in lower:
            return name in APP_REPOSITORY_NAMES or path.suffix.lower() in {".srd", ".edb", ".xml", ".log"}
        if "/applocker/" in lower:
            return path.suffix.lower() in {"", ".policy", ".xml", ".log"}
        if "/codeintegrity/" in lower:
            return path.suffix.lower() in {"", ".cip", ".p7b", ".xml", ".log"} or name.lower().endswith(".cip")
        return name in WMI_NAMES or path.suffix.lower() in {".data", ".btr", ".map"}
    return name in WMI_NAMES | NOTIFICATION_DBS | APP_REPOSITORY_NAMES


def _inventory_row(source: Path, path: Path) -> dict[str, object]:
    stat = path.stat()
    return {
        **_base_row(source, path, "telemetry_file", _artifact_group(path)),
        "file_size": stat.st_size,
        "modified_utc": _unix_to_iso(stat.st_mtime),
        "sha256_first_mb": _sha256_first_mb(path),
    }


def _wmi_rows(source: Path, path: Path) -> list[dict[str, object]]:
    strings = _interesting_strings(path, needles=INTERESTING_WMI_STRINGS)
    rows: list[dict[str, object]] = []
    if strings:
        row = _base_row(source, path, "wmi_repository_strings", "wmi")
        row.update(
            {
                "artifact_text": "\n".join(strings[:25]),
                "details_json": _json({"string_count": len(strings), "strings": strings[:100]}),
            }
        )
        rows.append(row)
    rows.extend(_structured_string_rows(source, path, "wmi", _strings(path, limit=1000), record_prefix="wmi"))
    return rows


def _cloudstore_rows(source: Path, path: Path) -> list[dict[str, object]]:
    strings = _strings(path, limit=100)
    rows: list[dict[str, object]] = []
    if strings:
        row = _base_row(source, path, "cloudstore_strings", "cloudstore")
        row.update(
            {
                "artifact_text": "\n".join(strings[:20]),
                "details_json": _json({"string_count": len(strings), "strings": strings[:100]}),
            }
        )
        rows.append(row)
    rows.extend(_structured_string_rows(source, path, "cloudstore", strings, record_prefix="cloudstore"))
    return rows


def _notification_rows(source: Path, path: Path, sqlite_copies: Path) -> list[dict[str, object]]:
    if path.name.lower() not in NOTIFICATION_DBS:
        rows = _string_summary_rows(source, path, "notifications")
        rows.extend(_structured_string_rows(source, path, "notifications", _strings(path, limit=500), record_prefix="notifications"))
        return rows
    return _sqlite_rows(
        source,
        path,
        sqlite_copies,
        artifact_group="notifications",
        preferred_tables=("Notification", "Notifications", "Handler", "WNSPushChannel"),
        include_tables_with_tokens=("notification", "handler", "channel", "app", "setting"),
    )


def _apprepository_rows(source: Path, path: Path, sqlite_copies: Path) -> list[dict[str, object]]:
    if path.suffix.lower() != ".srd":
        return _string_summary_rows(source, path, "apprepository")
    return _sqlite_rows(
        source,
        path,
        sqlite_copies,
        artifact_group="apprepository",
        preferred_tables=("Package", "Application", "PackageIdentity", "DeploymentHistory"),
        include_tables_with_tokens=("package", "application", "identity", "deployment", "extension", "capability", "user"),
    )


def _sqlite_rows(
    source: Path,
    path: Path,
    sqlite_copies: Path,
    *,
    artifact_group: str,
    preferred_tables: tuple[str, ...],
    include_tables_with_tokens: tuple[str, ...] = (),
    per_table_limit: int = 200,
) -> list[dict[str, object]]:
    copy = _copy_sqlite(path, sqlite_copies)
    rows: list[dict[str, object]] = []
    try:
        conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        return [{**_base_row(source, path, f"{artifact_group}_sqlite_error", artifact_group), "error": str(exc)}]
    try:
        tables = [row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        rows.append(
            {
                **_base_row(source, path, f"{artifact_group}_sqlite_inventory", artifact_group),
                "details_json": _json({"tables": tables, "copied_database": str(copy)}),
            }
        )
        selected = [
            table
            for table in tables
            if table in preferred_tables
            or any(token.lower() in table.lower() for token in preferred_tables)
            or any(token.lower() in table.lower() for token in include_tables_with_tokens)
        ]
        for table in selected[:20]:
            table_rows = conn.execute(f'SELECT * FROM "{table}" LIMIT ?', (per_table_limit,)).fetchall()
            context = _sqlite_table_context(conn, artifact_group, table)
            for index, row in enumerate(table_rows, start=1):
                record = dict(row)
                out = _base_row(source, path, f"{artifact_group}_{table.lower()[:40]}", artifact_group)
                url = _extract_url(record) or _first_text(record, ("Url", "URI", "LaunchUri", "Arguments"))
                title = _first_text(record, ("Title", "DisplayName", "Name", "PackageFullName", "AppUserModelId"))
                event_time = _first_timestamp(record)
                decoded_payload = _notification_payload_text(record) if artifact_group == "notifications" else ""
                handler = _notification_handler(record, context)
                out.update(
                    {
                        "application": handler or _first_text(record, ("ApplicationUserModelId", "AppUserModelId", "PackageFullName", "PackageFamilyName", "PrimaryId", "WNSId")),
                        "event_time_utc": event_time,
                        "identifier": _first_text(record, ("Id", "RecordId", "NotificationId", "PackageId", "PackageFullName", "AppUserModelId")),
                        "path": _extract_path(record),
                        "url": url or _extract_url({"payload": decoded_payload}),
                        "host": urlparse(url).netloc.lower(),
                        "host": urlparse(url or _extract_url({"payload": decoded_payload})).netloc.lower(),
                        "title": title or _notification_title(decoded_payload),
                        "value_name": table,
                        "value_data": _first_text(record, ("PackageFullName", "ApplicationUserModelId", "AppUserModelId", "HandlerId", "Type", "Name")),
                        "artifact_text": decoded_payload or _record_text(record),
                        "details_json": _json(
                            {
                                "table": table,
                                "row_number": index,
                                "event_time_source": event_time[1] if isinstance(event_time, tuple) else "",
                                "decoded_payload": decoded_payload,
                                "record": _jsonable_record(record),
                            }
                        ),
                    }
                )
                if isinstance(event_time, tuple):
                    out["event_time_utc"] = event_time[0]
                rows.append(out)
    finally:
        conn.close()
    return rows


def _text_or_binary_policy_rows(source: Path, path: Path, artifact_group: str) -> list[dict[str, object]]:
    text = ""
    if path.suffix.lower() in {".xml", ".log"}:
        text = path.read_text(encoding="utf-8", errors="replace")[:4000]
    strings = _strings(path, limit=100) if not text else []
    row = _base_row(source, path, f"{artifact_group}_policy_artifact", artifact_group)
    row.update(
        {
            "artifact_text": text or "\n".join(strings[:25]),
            "details_json": _json({"strings": strings[:100]} if strings else {"text_preview": text[:1000]}),
        }
    )
    rows = [row]
    policy_strings = text.splitlines() if text else strings
    rows.extend(_structured_string_rows(source, path, artifact_group, policy_strings, record_prefix=f"{artifact_group}_policy"))
    return rows


def _string_summary_rows(source: Path, path: Path, artifact_group: str) -> list[dict[str, object]]:
    strings = _strings(path, limit=100)
    if not strings:
        return []
    row = _base_row(source, path, f"{artifact_group}_strings", artifact_group)
    row.update({"artifact_text": "\n".join(strings[:25]), "details_json": _json({"strings": strings[:100]})})
    return [row]


def _base_row(source: Path, path: Path, record_type: str, artifact_group: str) -> dict[str, object]:
    return {
        "record_type": record_type,
        "artifact_group": artifact_group,
        "user_profile": _user_profile_from_path(path),
        "application": _application_from_path(path),
        "source_path": str(path),
        "source_name": _source_name(path),
        "file_name": path.name,
        "file_extension": path.suffix.lower(),
        "file_size": "",
        "modified_utc": "",
        "event_time_utc": "",
        "identifier": "",
        "path": "",
        "url": "",
        "host": "",
        "title": "",
        "value_name": "",
        "value_data": "",
        "artifact_text": "",
        "sha256_first_mb": "",
        "details_json": "",
        "error": "",
    }


def _error_row(source: Path, path: Path | None, error: str) -> dict[str, object]:
    return {**_base_row(source, path or source, "telemetry_scan_error", _artifact_group(path or source)), "error": error}


def _artifact_group(path: Path) -> str:
    lower = _normalized(path)
    if "/wbem/repository/" in lower:
        return "wmi"
    if "/cloudstore/" in lower:
        return "cloudstore"
    if "/notifications/" in lower:
        return "notifications"
    if "/apprepository/" in lower:
        return "apprepository"
    if "/applocker/" in lower:
        return "applocker"
    if "/codeintegrity/" in lower:
        return "wdac"
    return "telemetry"


def _source_name(path: Path) -> str:
    group = _artifact_group(path)
    if group == "wdac":
        return "Windows Defender Application Control"
    if group == "wmi":
        return "WMI repository"
    if group == "apprepository":
        return "AppRepository"
    return group


def _application_from_path(path: Path) -> str:
    text = path.as_posix()
    match = re.search(r"/Packages/([^/]+)", text, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def _user_profile_from_path(path: Path) -> str:
    text = path.as_posix()
    match = re.search(r"/Users/([^/]+)", text, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def _strings(path: Path, *, limit: int) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    values = [match.group(0).decode("ascii", errors="ignore") for match in ASCII_RE.finditer(data)]
    for match in UTF16_RE.finditer(data):
        try:
            values.append(match.group(0).decode("utf-16-le", errors="ignore"))
        except UnicodeDecodeError:
            continue
    return _dedupe([value.strip("\x00\r\n\t ") for value in values if value.strip("\x00\r\n\t ")])[:limit]


def _interesting_strings(path: Path, *, needles: tuple[str, ...]) -> list[str]:
    lowered_needles = tuple(needle.lower() for needle in needles)
    return [value for value in _strings(path, limit=500) if any(needle in value.lower() for needle in lowered_needles)]


def _copy_sqlite(path: Path, sqlite_copies: Path) -> Path:
    sqlite_copies.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(path.as_posix().encode("utf-8", errors="replace")).hexdigest()[:16]
    target = sqlite_copies / f"{digest}_{path.name}"
    shutil.copy2(path, target)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            shutil.copy2(sidecar, target.with_name(target.name + suffix))
    return target


def _first_text(record: dict[str, Any], names: tuple[str, ...]) -> str:
    lowered = {str(key).lower(): value for key, value in record.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value)
    return ""


def _extract_url(record: dict[str, Any]) -> str:
    for value in record.values():
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="ignore")
        else:
            text = str(value) if value not in (None, "") else ""
        match = URL_RE.search(text)
        if match:
            return match.group(0).rstrip(".,;")
    return ""


def _extract_path(record: dict[str, Any]) -> str:
    for value in record.values():
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="ignore")
        else:
            text = str(value) if value not in (None, "") else ""
        match = WINDOWS_PATH_RE.search(text) or DEVICE_PATH_RE.search(text)
        if match:
            return match.group(0).rstrip(".,;")
    return ""


def _sqlite_table_context(conn: sqlite3.Connection, artifact_group: str, table: str) -> dict[str, Any]:
    if artifact_group != "notifications" or table.lower() != "notification":
        return {}
    try:
        rows = conn.execute("SELECT RecordId, PrimaryId, WNSId FROM NotificationHandler").fetchall()
    except sqlite3.Error:
        return {}
    return {
        "notification_handlers": {
            str(row["RecordId"]): row["PrimaryId"] or row["WNSId"] or ""
            for row in rows
        }
    }


def _notification_handler(record: dict[str, Any], context: dict[str, Any]) -> str:
    handlers = context.get("notification_handlers")
    if not isinstance(handlers, dict):
        return ""
    handler_id = record.get("HandlerId")
    if handler_id in (None, ""):
        return ""
    return str(handlers.get(str(handler_id), ""))


def _notification_payload_text(record: dict[str, Any]) -> str:
    payload = record.get("Payload")
    if payload in (None, ""):
        return ""
    if isinstance(payload, bytes):
        text = payload.decode("utf-8", errors="ignore")
    else:
        text = str(payload)
    text = text.strip("\x00\r\n\t ")
    if not text:
        return ""
    return _compact_xml_text(text) or text[:2000]


def _compact_xml_text(text: str) -> str:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return ""
    values: list[str] = []
    for element in root.iter():
        if element.text and element.text.strip():
            values.append(element.text.strip())
        for attr_name, attr_value in sorted(element.attrib.items()):
            if attr_name.lower() in {"src", "uri", "launch", "arguments", "title", "id"} and attr_value:
                values.append(f"{attr_name}={attr_value}")
    return " | ".join(_dedupe([unescape(value) for value in values]))[:2000]


def _notification_title(decoded_payload: str) -> str:
    for part in decoded_payload.split(" | "):
        if part and "=" not in part:
            return part[:300]
    return ""


def _first_timestamp(record: dict[str, Any]) -> tuple[str, str] | str:
    priority = ("ArrivalTime", "CreatedTime", "ModifiedTime", "LastModifiedTime", "ExpiryTime", "Expires")
    items = sorted(record.items(), key=lambda item: priority.index(str(item[0])) if str(item[0]) in priority else len(priority))
    for key, value in items:
        if value in (None, ""):
            continue
        key_lower = str(key).lower()
        if not any(token in key_lower for token in ("time", "date", "created", "modified", "updated", "expires")):
            continue
        timestamp = _coerce_timestamp(value)
        if timestamp:
            return timestamp, str(key)
    return ""


def _coerce_timestamp(value: Any) -> str:
    if isinstance(value, bytes):
        if len(value) in {8, 16}:
            integer = int.from_bytes(value[:8], "little", signed=False)
            return _coerce_timestamp(integer)
        return ""
    if isinstance(value, str):
        text = value.strip()
        if re.match(r"^\d{4}-\d{2}-\d{2}[ T]", text):
            return text.replace(" ", "T").replace("+00:00", "Z")
        if not text.isdigit():
            return ""
        value = int(text)
    if isinstance(value, float):
        value = int(value)
    if not isinstance(value, int):
        return ""
    if FILETIME_MIN <= value <= FILETIME_MAX:
        unix = (value - FILETIME_MIN) / 10_000_000
        return _unix_to_iso(unix)
    if 946684800 <= value <= 4102444800:
        return _unix_to_iso(float(value))
    if 946684800000 <= value <= 4102444800000:
        return _unix_to_iso(value / 1000)
    return ""


def _structured_string_rows(
    source: Path,
    path: Path,
    artifact_group: str,
    strings: list[str],
    *,
    record_prefix: str,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for text in strings:
        for record_type, value in _interesting_values_from_text(text):
            key = (record_type, value.lower())
            if key in seen:
                continue
            seen.add(key)
            row = _base_row(source, path, f"{record_prefix}_{record_type}", artifact_group)
            row.update(
                {
                    "identifier": value if record_type in {"sid", "guid"} else "",
                    "path": value if record_type in {"windows_path", "device_path"} else "",
                    "url": value if record_type == "url" else "",
                    "host": urlparse(value).netloc.lower() if record_type == "url" else "",
                    "value_name": record_type,
                    "value_data": value,
                    "artifact_text": text[:2000],
                    "details_json": _json({"source_string": text[:4000]}),
                }
            )
            rows.append(row)
            if len(rows) >= 200:
                return rows
    return rows


def _interesting_values_from_text(text: str) -> Iterable[tuple[str, str]]:
    cleaned = unquote(text).replace("\x00", "")
    for match in URL_RE.finditer(cleaned):
        yield "url", match.group(0).rstrip(".,;")
    for match in WINDOWS_PATH_RE.finditer(cleaned):
        yield "windows_path", match.group(0).rstrip(".,;")
    for match in DEVICE_PATH_RE.finditer(cleaned):
        yield "device_path", match.group(0).rstrip(".,;")
    for match in SID_RE.finditer(cleaned):
        yield "sid", match.group(0)
    for match in GUID_RE.finditer(cleaned):
        yield "guid", match.group(0)


def _record_text(record: dict[str, Any]) -> str:
    parts = []
    for key, value in record.items():
        if value in (None, b"", ""):
            continue
        if isinstance(value, bytes):
            continue
        text = str(value)
        if len(text) > 300:
            text = text[:300]
        parts.append(f"{key}={text}")
    return " | ".join(parts)[:2000]


def _jsonable_record(record: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, value in record.items():
        if isinstance(value, bytes):
            result[str(key)] = {"bytes_hex_prefix": value[:64].hex(), "size": len(value)}
        else:
            result[str(key)] = value
    return result


def _sha256_first_mb(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            digest.update(handle.read(1024 * 1024))
    except OSError:
        return ""
    return digest.hexdigest()


def _unix_to_iso(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _normalized(path: Path) -> str:
    return path.as_posix().replace("\\", "/").lower()


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=TELEMETRY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
