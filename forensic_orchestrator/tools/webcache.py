from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from forensic_orchestrator.timestamps import normalize_timestamp


WEBCACHE_FIELDS = [
    "source_database",
    "source_table",
    "table_row_number",
    "user_name",
    "application",
    "application_package",
    "container_directory",
    "attribution_method",
    "container_id",
    "container_name",
    "entry_id",
    "entry_type",
    "url",
    "host",
    "cache_file",
    "file_name",
    "content_type",
    "http_status",
    "created_utc",
    "accessed_utc",
    "modified_utc",
    "expires_utc",
    "synced_utc",
    "request_headers",
    "response_headers",
    "raw_metadata_json",
]
csv.field_size_limit(1024 * 1024 * 1024)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
WEBKIT_EPOCH = FILETIME_EPOCH
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_webcache_artifacts_to_csv(source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "WebCacheEntries.csv"
    inventory_path = output / "WebCacheParserInventory.json"
    rows: list[dict[str, object]] = []
    inventory_rows: list[dict[str, object]] = []
    if source.exists():
        exported_root = output / "_esedbexport"
        rows.extend(_parse_exported_tables(source))
        for database in _iter_files(source, "WebCache*.dat"):
            if _is_file(database):
                parsed_rows, status = _parse_database(database, exported_root)
                rows.extend(parsed_rows)
                inventory_rows.append(status)
    _write_csv(csv_path, WEBCACHE_FIELDS, rows)
    inventory_path.write_text(json.dumps(inventory_rows, indent=2, sort_keys=True), encoding="utf-8")
    return [csv_path]


def _parse_database(database: Path, exported_root: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    exported_dir = exported_root / _safe_name(database)
    exported_actual = Path(str(exported_dir) + ".export")
    parse_dir = exported_actual if exported_actual.exists() else exported_dir
    if not any(_iter_files(parse_dir)):
        binary = shutil.which("esedbexport")
        if binary is None:
            return [], _webcache_inventory_row(
                database,
                "missing_dependency",
                "ese",
                "esedbexport not found. Install libesedb-utils or provide exported WebCache tables as CSV/TSV.",
            )
        exported_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                [binary, "-t", str(exported_dir), str(database)],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            error_text = (exc.stderr or exc.stdout or str(exc)).strip()
            return [], _webcache_inventory_row(database, "export_failed", "ese", error_text)
        parse_dir = exported_actual if exported_actual.exists() else exported_dir
    rows = _parse_exported_tables(parse_dir, source_database=database)
    return rows, _webcache_inventory_row(database, "parsed", "ese", "", row_count=len(rows))


def _webcache_inventory_row(
    database: Path,
    parser_status: str,
    detected_format: str,
    parser_error: str,
    *,
    row_count: int = 0,
) -> dict[str, object]:
    return {
        "source_database": str(database),
        "parser_status": parser_status,
        "detected_format": detected_format,
        "row_count": row_count,
        "parser_error": parser_error,
    }


def _parse_exported_tables(root: Path, source_database: Path | None = None) -> list[dict[str, object]]:
    files = [
        item
        for item in _iter_files(root)
        if item.is_file()
        and item.name != "WebCacheEntries.csv"
        and not item.name.startswith(".")
        and item.suffix.lower() not in {".dat", ".log", ".edb"}
    ]
    table_rows: dict[str, list[dict[str, str]]] = {}
    for path in files:
        rows = _read_table(path)
        if rows:
            table_rows[_table_name(path)] = rows
    containers = _container_map(table_rows)
    normalized_rows: list[dict[str, object]] = []
    for table_name, rows in table_rows.items():
        for index, row in enumerate(rows, start=1):
            normalized = _normalize_row(
                row,
                source_database=source_database or root,
                source_table=table_name,
                row_number=index,
                containers=containers,
            )
            if _has_webcache_evidence(normalized):
                normalized_rows.append(normalized)
    return normalized_rows


def _iter_files(root: Path, pattern: str = "*") -> list[Path]:
    matches: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root, onerror=lambda _exc: None):
        dirnames.sort()
        filenames.sort()
        for filename in filenames:
            path = Path(current_root) / filename
            if path.match(pattern):
                matches.append(path)
    return matches


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _read_table(path: Path) -> list[dict[str, str]]:
    try:
        sample = path.read_text(encoding="utf-8-sig", errors="replace")[:4096]
    except OSError:
        return []
    first_line = sample.splitlines()[0] if sample.splitlines() else ""
    delimiter = "\t" if "\t" in first_line or path.suffix.lower() in {".tsv", ".txt"} else ","
    try:
        if "\t" not in first_line:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t")
            delimiter = dialect.delimiter
    except csv.Error:
        pass
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        return [dict(row) for row in reader if row]


def _normalize_row(
    row: dict[str, str],
    *,
    source_database: Path,
    source_table: str,
    row_number: int,
    containers: dict[str, dict[str, str | None]],
) -> dict[str, object]:
    compact = {_compact_key(key): value for key, value in row.items() if key is not None}
    request_headers = _first(compact, "requestheaders", "requestheader")
    response_headers = _first(compact, "responseheaders", "responseheader", "headers")
    url = _first(compact, "url", "uri", "location", "redirecturl")
    if not url:
        url = _url_from_text(" ".join(str(value) for value in row.values() if value))
    host = _first(compact, "host", "hostname", "domain")
    if not host and url:
        host = urlparse(url).netloc
    container_id = _first(compact, "containerid", "container", "containeridindex")
    if not container_id:
        match = re.fullmatch(r"Container_(\d+)", source_table, re.IGNORECASE)
        container_id = match.group(1) if match else None
    container = containers.get(str(container_id or ""), {})
    container_name = (
        _first(compact, "containername", "name")
        if source_table.lower() == "containers"
        else container.get("name")
    )
    container_directory = (
        _first(compact, "directory", "path")
        if source_table.lower() == "containers"
        else container.get("directory")
    )
    app = _attribute_application(
        container_directory=container_directory,
        container_name=container_name,
        source_table=source_table,
    )
    return {
        "source_database": str(source_database),
        "source_table": source_table,
        "table_row_number": row_number,
        "user_name": _user_name_from_source_database(source_database) or _user_name_from_windows_path(container_directory),
        "application": app["application"],
        "application_package": app["application_package"],
        "container_directory": container_directory,
        "attribution_method": app["attribution_method"],
        "container_id": container_id,
        "container_name": container_name,
        "entry_id": _first(compact, "entryid", "id", "recordid"),
        "entry_type": _first(compact, "type", "entrytype", "cacheentrytype"),
        "url": url,
        "host": host,
        "cache_file": _first(compact, "filename", "filepath", "cachefile", "localfilename", "localpath"),
        "file_name": _first(compact, "file", "name", "displayname"),
        "content_type": _content_type(response_headers) or _first(compact, "contenttype", "mimetype"),
        "http_status": _http_status(response_headers) or _first(compact, "status", "httpstatus", "responsestatus"),
        "created_utc": _first_timestamp(compact, "created", "creationtime", "createdtime", "insertedtime"),
        "accessed_utc": _first_timestamp(compact, "accessed", "accessedtime", "accesstime", "lastaccessed", "lastaccesstime", "lastaccessedtime"),
        "modified_utc": _first_timestamp(compact, "modified", "modifiedtime", "lastmodified", "lastmodifiedtime", "updatetime"),
        "expires_utc": _first_timestamp(compact, "expires", "expirytime", "expiretime", "expirationtime"),
        "synced_utc": _first_timestamp(compact, "synctime", "syncedtime", "lastsynctime"),
        "request_headers": request_headers,
        "response_headers": response_headers,
        "raw_metadata_json": json.dumps(row, default=str, sort_keys=True),
    }


def _container_map(table_rows: dict[str, list[dict[str, str]]]) -> dict[str, dict[str, str | None]]:
    containers: dict[str, dict[str, str | None]] = {}
    for table, rows in table_rows.items():
        if table.lower() != "containers":
            continue
        for row in rows:
            compact = {_compact_key(key): value for key, value in row.items() if key is not None}
            container_id = _first(compact, "containerid", "id")
            name = _first(compact, "name", "containername")
            directory = _first(compact, "directory", "path")
            if container_id:
                containers[str(container_id)] = {
                    "name": name,
                    "directory": directory,
                }
    return containers


def _user_name_from_source_database(source_database: Path) -> str | None:
    text = str(source_database)
    normalized = text.replace("\\", "/")
    match = re.search(r"/WebCache/([^/]+)/AppData/Local/Microsoft/Windows/WebCache/", normalized, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"/Users/([^/]+)/AppData/Local/Microsoft/Windows/WebCache/", normalized, re.IGNORECASE)
    return match.group(1) if match else None


def _user_name_from_windows_path(path: str | None) -> str | None:
    if not path:
        return None
    path = re.sub(r"\\{2,}", r"\\", path)
    match = re.search(r"(?i)(?:^|[\\/])Users[\\/]([^\\/]+)[\\/]", path)
    return match.group(1) if match else None


def _attribute_application(
    *,
    container_directory: str | None,
    container_name: str | None,
    source_table: str,
) -> dict[str, str | None]:
    directory = container_directory or ""
    directory = re.sub(r"\\{2,}", r"\\", directory)
    directory_lower = directory.lower()
    container_lower = (container_name or "").lower()
    package_match = re.search(r"\\packages\\([^\\]+)\\", directory, re.IGNORECASE)
    package = package_match.group(1) if package_match else None
    package_lower = package.lower() if package else ""
    known_packages = {
        "microsoft.microsoftedge_8wekyb3d8bbwe": "Microsoft Edge",
        "microsoft.windowsstore_8wekyb3d8bbwe": "Microsoft Store",
        "microsoft.windows.search_cw5n1h2txyewy": "Windows Search",
        "microsoft.windows.cloudexperiencehost_cw5n1h2txyewy": "Cloud Experience Host",
        "microsoft.windows.contentdeliverymanager_cw5n1h2txyewy": "Content Delivery Manager",
    }
    if package:
        return {
            "application": known_packages.get(package_lower, package),
            "application_package": package,
            "attribution_method": "container_directory_package",
        }
    if "microsoftedge" in directory_lower or container_lower.startswith("microsoftedge"):
        return {
            "application": "Microsoft Edge",
            "application_package": None,
            "attribution_method": "container_directory_or_name",
        }
    if "\\feeds cache\\" in directory_lower:
        return {
            "application": "Windows Feeds Platform",
            "application_package": None,
            "attribution_method": "container_directory",
        }
    if any(token in directory_lower for token in ("\\inetcache\\ie\\", "\\history\\history.ie5\\", "\\inetcookies\\")):
        return {
            "application": "WinINet/Internet Explorer shared cache",
            "application_package": None,
            "attribution_method": "container_directory_shared_wininet",
        }
    if source_table.lower().startswith(("blobentry", "cookieentry", "appcacheentry", "dependencyentry")):
        return {
            "application": "Unknown/WinINet consumer",
            "application_package": None,
            "attribution_method": "shared_webcache_table",
        }
    return {
        "application": "Unknown/WinINet consumer",
        "application_package": None,
        "attribution_method": "unknown",
    }


def _has_webcache_evidence(row: dict[str, object]) -> bool:
    return any(row.get(key) for key in ("url", "host", "cache_file", "file_name", "created_utc", "accessed_utc", "modified_utc"))


def _first(row: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _first_timestamp(row: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        timestamp = _normalize_webcache_time(value)
        if timestamp:
            return timestamp
    return None


def _normalize_webcache_time(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("\x00")
    if not text or text in {"0", "-1"}:
        return None
    parsed = normalize_timestamp(text)
    if parsed:
        return parsed
    try:
        dt = parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        pass
    for fmt in ("%b %d, %Y %H:%M:%S.%f", "%b %d, %Y %H:%M:%S"):
        try:
            dt = datetime.strptime(text[:26], fmt).replace(tzinfo=timezone.utc)
            if dt.year <= 1901:
                return None
            return dt.isoformat().replace("+00:00", "Z")
        except ValueError:
            continue
    try:
        number = int(float(text))
    except ValueError:
        return None
    candidates = []
    if 10_000_000_000_000_000 <= number <= 300_000_000_000_000_000:
        candidates.append(FILETIME_EPOCH + timedelta(microseconds=number / 10))
    if 10_000_000_000_000 <= number <= 30_000_000_000_000:
        candidates.append(WEBKIT_EPOCH + timedelta(microseconds=number))
    if 1_000_000_000 <= number <= 4_102_444_800:
        candidates.append(UNIX_EPOCH + timedelta(seconds=number))
    if 1_000_000_000_000 <= number <= 4_102_444_800_000:
        candidates.append(UNIX_EPOCH + timedelta(milliseconds=number))
    for candidate in candidates:
        if 1990 <= candidate.year <= 2100:
            return candidate.isoformat().replace("+00:00", "Z")
    return None


def _content_type(headers: str | None) -> str | None:
    return _header_value(headers, "content-type")


def _http_status(headers: str | None) -> str | None:
    if not headers:
        return None
    match = re.search(r"\bHTTP/\d(?:\.\d)?\s+(\d{3})\b", headers, re.IGNORECASE)
    return match.group(1) if match else None


def _header_value(headers: str | None, name: str) -> str | None:
    if not headers:
        return None
    pattern = re.compile(rf"(?im)^{re.escape(name)}\s*:\s*(.+)$")
    match = pattern.search(headers.replace("\\r\\n", "\n"))
    return match.group(1).strip() if match else None


def _url_from_text(text: str) -> str | None:
    match = URL_RE.search(text)
    return match.group(0) if match else None


def _compact_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _table_name(path: Path) -> str:
    stem = path.stem
    for prefix in ("WebCacheV01.dat.", "WebCacheV01."):
        if stem.startswith(prefix):
            return stem.removeprefix(prefix)
    return stem


def _safe_name(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(path))


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
