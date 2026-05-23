from __future__ import annotations

import csv
import json
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


PACKAGE_ARTIFACT_FIELDS = [
    "record_type",
    "user_profile",
    "application_package",
    "source_path",
    "source_name",
    "file_name",
    "file_extension",
    "file_size",
    "modified_utc",
    "event_time_utc",
    "url",
    "host",
    "title",
    "artifact_value",
    "artifact_text",
    "details_json",
    "error",
]

HIGH_VALUE_EXTENSIONS = {
    ".db",
    ".sqlite",
    ".edb",
    ".hxd",
    ".json",
    ".log",
    ".ldb",
    ".mov",
    ".jpeg",
    ".jpg",
    ".png",
    ".eml",
    ".pdf",
    ".xls",
}
HIGH_VALUE_NAMES = {
    ".bash_history",
    ".fish_history",
    ".mysql_history",
    ".node_repl_history",
    ".psql_history",
    ".python_history",
    ".rediscli_history",
    ".sqlite_history",
    ".viminfo",
    ".wget-hsts",
    ".zsh_history",
    "typedurls.json",
    "notifications.json",
    "hxstore.hxd",
    "browser.log",
    "webapp-console.log",
    "mediadb.v1.sqlite",
    "client.db",
    "iclouddrive.db",
    "ckcachedatabase.db",
    "recentfilecache.bcf",
}
SQLITE_SUFFIXES = {".db", ".sqlite"}
LOG_KEYWORDS = re.compile(
    r"(?i)(upload|download|sync|error|fail|icloud|onedrive|sharepoint|photo|file|outlook|drive)"
)
SLACK_KEYWORDS = re.compile(
    r"(?i)(MagicLogin|Added team|Synced .*workspaces|launchUri|START_DOWNLOAD|"
    r"UPDATE_DOWNLOAD|Download completed|initiateDownload|will-download|validatedUrl|workspaces)"
)
MAIL_FRAGMENT_KEYWORDS = re.compile(r"(?i)(subject|from:|to:|mailto:|password|microsoft account|<!doctype|<html|http)")
PHONE_LINK_TABLE_KEYWORDS = {
    "message": ("message", "sms", "mms", "chat", "conversation"),
    "contact": ("contact", "people", "address"),
    "call": ("call", "phonecall", "voicemail"),
    "photo": ("photo", "image", "media", "camera", "thumbnail"),
}
PHONE_LINK_COLUMN_KEYWORDS = {
    "message": ("body", "message", "text", "sms", "mms", "conversation"),
    "contact": ("contact", "displayname", "phone", "email", "address"),
    "call": ("call", "duration", "phone", "number", "voicemail"),
    "photo": ("photo", "image", "media", "thumbnail", "filename", "path"),
}


def parse_package_artifacts_to_csv(source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    sqlite_copies = output / "_sqlite_copies"
    for path, error in _walk_package_files(source):
        if error:
            rows.append(_error_row(source, path, error))
            continue
        if path is None:
            continue
        rows.append(_inventory_row(source, path))
        lower_name = path.name.lower()
        lower_path = path.as_posix().lower()
        try:
            if _is_wsl_history_file(path):
                rows.extend(_wsl_history_rows(source, path))
            elif _is_outlook_attachment_cache_file(path):
                rows.append(_outlook_attachment_cache_row(source, path))
            elif lower_name == "recentfilecache.bcf":
                rows.extend(_recent_file_cache_rows(source, path))
            elif _is_teams_filesystem_paths_log(path):
                rows.extend(_teams_filesystem_path_rows(source, path))
            elif lower_name == "typedurls.json":
                rows.extend(_edge_typed_urls(source, path))
            elif lower_name == "notifications.json":
                rows.extend(_json_rows(source, path, "officehub_notification"))
            elif lower_name in {"browser.log", "webapp-console.log"} and "slack_" in lower_path:
                rows.extend(_slack_log_rows(source, path))
            elif lower_name == "hxstore.hxd" and "windowscommunicationsapps" in lower_path:
                rows.extend(_mail_hxstore_fragments(source, path))
            elif lower_name == "mediadb.v1.sqlite":
                rows.extend(_photos_sqlite_rows(source, path, sqlite_copies))
            elif "microsoft.yourphone_" in lower_path and path.suffix.lower() in SQLITE_SUFFIXES:
                rows.extend(_phone_link_sqlite_rows(source, path, sqlite_copies))
            elif "appleinc.icloud_" in lower_path:
                rows.extend(_icloud_rows(source, path, sqlite_copies))
        except Exception as exc:  # pragma: no cover - defensive per-artifact isolation
            rows.append(_error_row(source, path, f"{type(exc).__name__}: {exc}"))
    csv_path = output / "PackageArtifacts.csv"
    _write_csv(csv_path, PACKAGE_ARTIFACT_FIELDS, rows)
    return [csv_path]


def _is_teams_filesystem_paths_log(path: Path) -> bool:
    lower = path.as_posix().lower()
    return (
        path.name.lower().endswith(".log")
        and "msteams_" in lower
        and "/file system/" in lower
        and "/paths/" in lower
    )


def _teams_filesystem_path_rows(source: Path, path: Path) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    text = data.decode("utf-8", errors="replace")
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for match in re.finditer(r"CHILD_OF:\d+:(1[5-9]\d{11,12})(?:\.crswap)?", text):
        epoch_ms = match.group(1)
        window = text[match.start(): match.start() + 700]
        name_match = re.search(r"(Teams_diagnostics-event-logs-[A-Za-z0-9_.@-]+)", window)
        if not name_match:
            continue
        file_name = name_match.group(1).rstrip("@")
        key = (epoch_ms, file_name)
        if key in seen:
            continue
        seen.add(key)
        event_time = _epoch_ms_to_iso(epoch_ms)
        row = _base_row(source, path, "teams_filesystem_diagnostic_log")
        stat = path.stat()
        row.update(
            {
                "application_package": "MSTeams",
                "file_name": file_name,
                "file_extension": "",
                "file_size": stat.st_size,
                "modified_utc": _unix_to_iso(stat.st_mtime),
                "event_time_utc": event_time,
                "title": "Teams diagnostic event log file",
                "artifact_value": file_name,
                "artifact_text": "",
                "details_json": json.dumps(
                    {
                        "epoch_ms": epoch_ms,
                        "filesystem_scope": "temporary",
                        "source": "Chromium/WebView File System Paths LevelDB log",
                    },
                    sort_keys=True,
                ),
            }
        )
        rows.append(row)
    return rows


def _walk_package_files(source: Path) -> Iterable[tuple[Path | None, str]]:
    if not source.exists():
        return
    for root, dirnames, filenames in os.walk(source, onerror=lambda exc: None):
        root_path = Path(root)
        root_lower = root_path.as_posix().lower()
        if not _is_interesting_user_artifact_dir(root_lower):
            continue
        kept_dirs = []
        for dirname in dirnames:
            candidate = root_path / dirname
            try:
                candidate.stat()
            except OSError as exc:
                yield candidate, str(exc)
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in filenames:
            path = root_path / filename
            try:
                path.stat()
            except OSError as exc:
                yield path, str(exc)
                continue
            suffix = path.suffix.lower()
            if (
                _is_outlook_attachment_cache_file(path)
                or suffix in HIGH_VALUE_EXTENSIONS
                or filename.lower() in HIGH_VALUE_NAMES
            ):
                yield path, ""


def _is_interesting_user_artifact_dir(root_lower: str) -> bool:
    return (
        "/appdata/local/packages/" in root_lower
        or "/appdata/local/microsoft/windows/inetcache/content.outlook/" in root_lower
        or root_lower.endswith("/windows/appcompat/programs")
    )


def _is_wsl_history_file(path: Path) -> bool:
    lower_path = path.as_posix().lower()
    return (
        "/appdata/local/packages/" in lower_path
        and "/localstate/rootfs/" in lower_path
        and path.name.lower() in {
            ".bash_history",
            ".fish_history",
            ".mysql_history",
            ".node_repl_history",
            ".psql_history",
            ".python_history",
            ".rediscli_history",
            ".sqlite_history",
            ".zsh_history",
        }
    )


def _is_outlook_attachment_cache_file(path: Path) -> bool:
    return "/appdata/local/microsoft/windows/inetcache/content.outlook/" in path.as_posix().lower()


def _outlook_attachment_cache_row(source: Path, path: Path) -> dict[str, object]:
    stat = path.stat()
    row = _base_row(source, path, "outlook_attachment_cache_file")
    row.update(
        {
            "file_size": stat.st_size,
            "modified_utc": _unix_to_iso(stat.st_mtime),
            "event_time_utc": _unix_to_iso(stat.st_mtime),
            "artifact_value": str(path),
            "artifact_text": path.name,
            "details_json": _json_dumps({"cache": "Content.Outlook", "time_basis": "file_modified_time"}),
        }
    )
    return row


def _wsl_history_rows(source: Path, path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    stat = path.stat()
    commands = _read_history_commands(path)
    for index, command in enumerate(commands, start=1):
        row = _base_row(source, path, "wsl_shell_history")
        row.update(
            {
                "event_time_utc": _unix_to_iso(stat.st_mtime),
                "modified_utc": _unix_to_iso(stat.st_mtime),
                "artifact_value": command,
                "artifact_text": command,
                "details_json": _json_dumps(
                    {
                        "history_file": path.name,
                        "command_index": index,
                        "time_basis": "history_file_modified_time",
                    }
                ),
            }
        )
        rows.append(row)
    return rows


def _read_history_commands(path: Path, *, limit: int = 5000) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    commands: list[str] = []
    pending_zsh_time = False
    for line in text.splitlines():
        value = line.strip()
        if not value:
            continue
        if value.startswith(": ") and ";" in value:
            pending_zsh_time = True
            value = value.split(";", 1)[1].strip()
        elif pending_zsh_time:
            pending_zsh_time = False
        if value and not value.startswith("#"):
            commands.append(value[:1000])
        if len(commands) >= limit:
            break
    return commands


def _recent_file_cache_rows(source: Path, path: Path) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    stat = path.stat()
    seen: set[str] = set()
    rows: list[dict[str, object]] = []
    for value in _utf16_strings(data, min_chars=4):
        if "\\" not in value and "/" not in value:
            continue
        if value.lower() in seen:
            continue
        seen.add(value.lower())
        row = _base_row(source, path, "recent_file_cache_entry")
        row.update(
            {
                "modified_utc": _unix_to_iso(stat.st_mtime),
                "event_time_utc": _unix_to_iso(stat.st_mtime),
                "artifact_value": value,
                "artifact_text": value,
                "details_json": _json_dumps({"time_basis": "RecentFileCache.bcf modified time"}),
            }
        )
        rows.append(row)
    return rows


def _utf16_strings(data: bytes, *, min_chars: int) -> Iterable[str]:
    pattern = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_chars))
    for match in pattern.finditer(data):
        try:
            text = match.group(0).decode("utf-16-le", errors="ignore").strip("\x00")
        except UnicodeDecodeError:
            continue
        if text:
            yield text


def _inventory_row(source: Path, path: Path) -> dict[str, object]:
    stat = path.stat()
    return {
        **_base_row(source, path, "package_file"),
        "file_size": stat.st_size,
        "modified_utc": _unix_to_iso(stat.st_mtime),
    }


def _error_row(source: Path, path: Path | None, error: str) -> dict[str, object]:
    real_path = path or source
    return {**_base_row(source, real_path, "package_scan_error"), "error": error}


def _base_row(source: Path, path: Path, record_type: str) -> dict[str, object]:
    package = _package_from_path(path)
    return {
        "record_type": record_type,
        "user_profile": _user_profile_from_path(path),
        "application_package": package,
        "source_path": str(path),
        "source_name": _friendly_source_name(package),
        "file_name": path.name,
        "file_extension": path.suffix.lower(),
        "file_size": "",
        "modified_utc": "",
        "event_time_utc": "",
        "url": "",
        "host": "",
        "title": "",
        "artifact_value": "",
        "artifact_text": "",
        "details_json": "",
        "error": "",
    }


def _edge_typed_urls(source: Path, path: Path) -> list[dict[str, object]]:
    data = _read_json(path)
    rows: list[dict[str, object]] = []
    for item in data.get("TypedUrls", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("URL") or "")
        row = _base_row(source, path, "edge_typed_url")
        row.update(
            {
                "event_time_utc": _filetime_parts_to_iso(item.get("DateUpdatedHigh"), item.get("DateUpdatedLow")),
                "url": url,
                "host": urlparse(url).netloc.lower(),
                "artifact_value": url,
                "details_json": _json_dumps(item),
            }
        )
        rows.append(row)
    return rows


def _json_rows(source: Path, path: Path, record_type: str) -> list[dict[str, object]]:
    data = _read_json(path)
    objects = data if isinstance(data, list) else [data]
    rows: list[dict[str, object]] = []
    for index, item in enumerate(objects, start=1):
        row = _base_row(source, path, record_type)
        if isinstance(item, dict):
            text = _first_text(item, ("title", "text", "message", "body", "name", "description"))
            url = _first_text(item, ("url", "link", "uri"))
            row.update(
                {
                    "event_time_utc": _first_timestamp(item),
                    "url": url,
                    "host": urlparse(url).netloc.lower(),
                    "title": _first_text(item, ("title", "name")),
                    "artifact_text": text,
                    "details_json": _json_dumps(item),
                }
            )
        else:
            row.update({"artifact_value": str(index), "artifact_text": str(item), "details_json": _json_dumps(item)})
        rows.append(row)
    return rows


def _slack_log_rows(source: Path, path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    last_time = ""
    for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        parsed_time = _slack_time(line)
        if parsed_time:
            last_time = parsed_time
        if not SLACK_KEYWORDS.search(line):
            continue
        text = line.strip()
        url = _first_url(text)
        slack_uri = _first_slack_uri(text)
        row = _base_row(source, path, "slack_package_activity")
        row.update(
            {
                "event_time_utc": parsed_time or last_time,
                "url": url or slack_uri,
                "host": urlparse(url).netloc.lower() if url else "",
                "artifact_value": _slack_value(text),
                "artifact_text": text,
                "details_json": _json_dumps({"line_number": line_number}),
            }
        )
        rows.append(row)
    return rows


def _mail_hxstore_fragments(source: Path, path: Path) -> list[dict[str, object]]:
    data = path.read_bytes()
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for offset, fragment in _printable_fragments(data, min_len=24):
        if not MAIL_FRAGMENT_KEYWORDS.search(fragment):
            continue
        cleaned = re.sub(r"\s+", " ", fragment).strip()
        if len(cleaned) > 1000:
            cleaned = cleaned[:1000]
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        row = _base_row(source, path, "windows_mail_hxstore_fragment")
        row.update(
            {
                "artifact_text": cleaned,
                "details_json": _json_dumps(
                    {
                        "offset": offset,
                        "decoded_state": "carved_printable_fragment",
                        "caution": "HxStore fragment carved from printable bytes; not a full structured message.",
                    }
                ),
            }
        )
        rows.append(row)
        if len(rows) >= 250:
            break
    return rows


def _photos_sqlite_rows(source: Path, path: Path, sqlite_copies: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in (
        "Item",
        "Photo",
        "Video",
        "Folder",
        "UserActionView",
        "UserActionSearch",
        "UserActionShare",
        "OCRItem",
        "OCRItemTextView",
        "ExtractedText",
    ):
        for item in _sqlite_table_rows(path, sqlite_copies, table, limit=5000):
            row = _base_row(source, path, "windows_photos_" + table.lower())
            url = _first_text(item, ("uri", "url", "itemuri", "thumbnailuri"))
            row.update(
                {
                    "event_time_utc": _first_timestamp(item),
                    "url": url,
                    "host": urlparse(url).netloc.lower(),
                    "title": _first_text(item, ("title", "displayname", "name", "filename")),
                    "artifact_value": _first_text(item, ("filename", "name", "path", "folderpath", "fileextension")),
                    "artifact_text": _first_text(item, ("text", "ocrtext", "searchtext", "displayname", "name")),
                    "details_json": _json_dumps(item),
                }
            )
            rows.append(row)
    return rows


def _phone_link_sqlite_rows(source: Path, path: Path, sqlite_copies: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in _sqlite_tables(path, sqlite_copies):
        category = _phone_link_category(path, table, sqlite_copies)
        if not category:
            continue
        for item in _sqlite_table_rows(path, sqlite_copies, table, limit=10000):
            row = _base_row(source, path, f"phone_link_{category}")
            url = _first_text(item, ("url", "uri", "contenturi", "thumbnailuri", "photouri"))
            title = _first_text(item, ("title", "subject", "displayname", "name", "filename", "normalizedname"))
            value = _first_text(
                item,
                (
                    "phone", "phonenumber", "address", "sender", "recipient", "from", "to",
                    "phone_number",
                    "filename", "path", "filepath", "uri", "conversationid", "threadid",
                ),
            )
            text = _first_text(item, ("body", "message", "text", "preview", "snippet", "displayname", "name"))
            row.update(
                {
                    "event_time_utc": _first_timestamp(item),
                    "url": url,
                    "host": urlparse(url).netloc.lower(),
                    "title": title,
                    "artifact_value": value,
                    "artifact_text": text,
                    "details_json": _json_dumps({"source_table": table, "category": category, "row": item}),
                }
            )
            rows.append(row)
    return rows


def _phone_link_category(path: Path, table: str, sqlite_copies: Path) -> str:
    table_lower = table.lower()
    for category, tokens in PHONE_LINK_TABLE_KEYWORDS.items():
        if any(token in table_lower for token in tokens):
            return category
    columns = _sqlite_columns(path, sqlite_copies, table)
    column_text = " ".join(columns).lower()
    for category, tokens in PHONE_LINK_COLUMN_KEYWORDS.items():
        if any(token in column_text for token in tokens):
            return category
    return ""


def _icloud_rows(source: Path, path: Path, sqlite_copies: Path) -> list[dict[str, object]]:
    lower = path.name.lower()
    if lower.endswith(".log"):
        return _icloud_log_rows(source, path)
    if path.suffix.lower() in SQLITE_SUFFIXES:
        return _icloud_sqlite_rows(source, path, sqlite_copies)
    return []


def _icloud_log_rows(source: Path, path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        if not LOG_KEYWORDS.search(line):
            continue
        text = line.strip()
        row = _base_row(source, path, "icloud_log_activity")
        url = _first_url(text)
        row.update(
            {
                "event_time_utc": _parse_timestamp_value(text),
                "url": url,
                "host": urlparse(url).netloc.lower(),
                "artifact_text": text[:2000],
                "details_json": _json_dumps({"line_number": line_number}),
            }
        )
        rows.append(row)
    return rows


def _icloud_sqlite_rows(source: Path, path: Path, sqlite_copies: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in _sqlite_tables(path, sqlite_copies):
        table_lower = table.lower()
        if not any(token in table_lower for token in ("file", "item", "asset", "photo", "drive", "bookmark", "sync", "transfer")):
            continue
        for item in _sqlite_table_rows(path, sqlite_copies, table, limit=5000):
            row = _base_row(source, path, "icloud_" + table_lower[:50])
            url = _first_text(item, ("url", "uri", "downloadurl", "cloudkiturl"))
            row.update(
                {
                    "event_time_utc": _first_timestamp(item),
                    "url": url,
                    "host": urlparse(url).netloc.lower(),
                    "title": _first_text(item, ("title", "name", "filename")),
                    "artifact_value": _first_text(item, ("filename", "name", "path", "relativepath", "itemname")),
                    "artifact_text": _first_text(item, ("text", "description", "status", "error")),
                    "details_json": _json_dumps(item),
                }
            )
            rows.append(row)
    return rows


def _sqlite_tables(path: Path, sqlite_copies: Path) -> list[str]:
    try:
        with _sqlite_connection(path, sqlite_copies) as conn:
            return [
                str(row[0])
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            ]
    except sqlite3.Error:
        return []


def _sqlite_table_rows(path: Path, sqlite_copies: Path, table: str, *, limit: int) -> list[dict[str, object]]:
    try:
        with _sqlite_connection(path, sqlite_copies) as conn:
            names = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            if table not in names:
                return []
            cursor = conn.execute(f'SELECT * FROM "{table.replace(chr(34), chr(34) + chr(34))}" LIMIT ?', (limit,))
            return [{key: _sqlite_value(value) for key, value in dict(row).items()} for row in cursor]
    except sqlite3.Error:
        return []


def _sqlite_columns(path: Path, sqlite_copies: Path, table: str) -> list[str]:
    try:
        with _sqlite_connection(path, sqlite_copies) as conn:
            escaped = table.replace('"', '""')
            return [str(row[1]) for row in conn.execute(f'PRAGMA table_info("{escaped}")')]
    except sqlite3.Error:
        return []


def _sqlite_connection(path: Path, sqlite_copies: Path) -> sqlite3.Connection:
    copied = _copy_sqlite_with_sidecars(path, sqlite_copies)
    conn = sqlite3.connect(f"file:{copied.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _copy_sqlite_with_sidecars(path: Path, sqlite_copies: Path) -> Path:
    sqlite_copies.mkdir(parents=True, exist_ok=True)
    destination = sqlite_copies / re.sub(r"[^A-Za-z0-9_.-]+", "_", path.as_posix()).strip("_")[-180:]
    if not destination.exists():
        shutil.copy2(path, destination)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists():
                shutil.copy2(sidecar, Path(str(destination) + suffix))
    return destination


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))


def _printable_fragments(data: bytes, *, min_len: int) -> Iterable[tuple[int, str]]:
    start: int | None = None
    current = bytearray()
    for index, byte in enumerate(data):
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            if start is None:
                start = index
            current.append(byte)
            continue
        if start is not None and len(current) >= min_len:
            yield start, current.decode("utf-8", errors="replace")
        start = None
        current.clear()
    if start is not None and len(current) >= min_len:
        yield start, current.decode("utf-8", errors="replace")


def _first_text(obj: object, names: tuple[str, ...]) -> str:
    wanted = {name.lower() for name in names}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in wanted and value not in (None, ""):
                return _value_to_text(value)
            found = _first_text(value, names)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _first_text(value, names)
            if found:
                return found
    return ""


def _first_timestamp(obj: object) -> str:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).lower()
            if any(token in key_lower for token in ("time", "date", "created", "modified", "updated")):
                parsed = _parse_timestamp_value(value)
                if parsed:
                    return parsed
            found = _first_timestamp(value)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _first_timestamp(value)
            if found:
                return found
    return ""


def _parse_timestamp_value(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 11_644_473_600_000_000:
            return _filetime_to_iso(int(numeric))
        if numeric > 10_000_000_000:
            return _unix_to_iso(numeric / 1000)
        if 100_000_000 <= numeric < 1_000_000_000:
            return _apple_absolute_to_iso(numeric)
        if numeric > 100_000_000:
            return _unix_to_iso(numeric)
    text = str(value).strip()
    if not text:
        return ""
    log_match = re.search(
        r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
        r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?",
        text,
    )
    if log_match:
        month_name, day, year, hour, minute, second, fraction = log_match.groups()
        month = {
            "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
        }[month_name]
        microsecond = int((fraction or "0").ljust(6, "0")[:6])
        return datetime(
            int(year), month, int(day), int(hour), int(minute), int(second), microsecond, tzinfo=timezone.utc
        ).isoformat().replace("+00:00", "Z")
    if re.fullmatch(r"\d{17,}", text):
        return _filetime_to_iso(int(text))
    if re.fullmatch(r"\d{13,16}", text):
        return _unix_to_iso(int(text[:13]) / 1000)
    if re.fullmatch(r"\d{10}", text):
        return _unix_to_iso(int(text))
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _filetime_parts_to_iso(high: object, low: object) -> str:
    try:
        value = (int(high) << 32) + int(low)
    except (TypeError, ValueError):
        return ""
    return _filetime_to_iso(value)


def _filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    try:
        return (epoch + timedelta(microseconds=value / 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return ""


def _unix_to_iso(value: float) -> str:
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError):
        return ""


def _epoch_ms_to_iso(value: str) -> str:
    try:
        return _unix_to_iso(int(value) / 1000)
    except (TypeError, ValueError):
        return ""


def _apple_absolute_to_iso(value: float) -> str:
    try:
        epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
        return (epoch + timedelta(seconds=value)).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return ""


def _sqlite_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_sha256": __import__("hashlib").sha256(value).hexdigest(), "bytes_length": len(value)}
    return value


def _value_to_text(value: object) -> str:
    if isinstance(value, (str, int, float)):
        return str(value)
    return _json_dumps(value)


def _first_url(text: str) -> str:
    match = re.search(r"https?://[^\s\"'<>]+", text)
    return match.group(0).rstrip(",)") if match else ""


def _first_slack_uri(text: str) -> str:
    match = re.search(r"slack://[^\s\"'<>]+", text)
    return match.group(0).rstrip(",)") if match else ""


def _slack_time(text: str) -> str:
    match = re.search(r"\[(\d{1,2})/(\d{1,2})/(\d{2}),\s+(\d{2}):(\d{2}):(\d{2}):(\d{3})\]", text)
    if not match:
        return ""
    month, day, year, hour, minute, second, milli = [int(part) for part in match.groups()]
    return datetime(2000 + year, month, day, hour, minute, second, milli * 1000, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _slack_value(text: str) -> str:
    for pattern in (r"team\s+([A-Z0-9]+)", r"IDs\s+\[([A-Z0-9, ]+)\]", r'"channel":\s*"([^"]+)"'):
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return ""


def _json_dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)


def _user_profile_from_path(path: Path) -> str:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _package_from_path(path: Path) -> str:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "packages" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _friendly_source_name(package: str) -> str:
    lower = package.lower()
    if "microsoft.yourphone" in lower:
        return "Microsoft Phone Link"
    if "slack" in lower:
        return "Slack"
    if "windowscommunicationsapps" in lower:
        return "Windows Mail"
    if "icloud" in lower:
        return "iCloud"
    if "photos" in lower:
        return "Windows Photos"
    if "edge" in lower:
        return "Microsoft Edge"
    if "officehub" in lower or lower.startswith("oice_"):
        return "Microsoft Office"
    return package


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
