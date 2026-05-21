from __future__ import annotations

import csv
import hashlib
import os
import re
import shutil
import subprocess
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse


PACKAGE_CACHE_FIELDS = [
    "user_profile",
    "application_package",
    "source_database",
    "source_table",
    "table_row_number",
    "cache_name",
    "site_origin",
    "request_url",
    "host",
    "response_status",
    "response_type",
    "response_headers",
    "response_date_utc",
    "content_type",
    "content_length",
    "source_body_path",
    "stored_body_path",
    "body_file_name",
    "body_size",
    "body_sha256",
    "body_encrypted",
    "encryption_version",
    "decoded_state",
]


def parse_package_cache_artifacts_to_csv(source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    exports_root = output / "_ese_exports"
    bodies_root = output / "opaque_bodies"
    for database in _cache_storage_databases(source):
        export_dir = _export_cache_storage(database, exports_root)
        rows.extend(_cache_rows_from_export(export_dir, database, source, bodies_root))
    csv_path = output / "PackageCacheEntries.csv"
    _write_csv(csv_path, PACKAGE_CACHE_FIELDS, rows)
    return [csv_path]


def _cache_storage_databases(source: Path) -> list[Path]:
    databases: list[Path] = []
    if not source.exists():
        return databases
    for root, dirnames, filenames in os.walk(source, onerror=lambda _exc: None):
        root_path = Path(root)
        root_lower = root_path.as_posix().lower()
        if "/appdata/local/packages/" not in root_lower:
            continue
        if "CacheStorage.edb" in filenames:
            databases.append(root_path / "CacheStorage.edb")
        dirnames[:] = [name for name in dirnames if name.lower() not in {"temp", "tmp"}]
    return sorted(databases)


def _export_cache_storage(database: Path, exports_root: Path) -> Path:
    exports_root.mkdir(parents=True, exist_ok=True)
    target = exports_root / _safe_export_name(database)
    export_dir = target.with_name(target.name + ".export")
    if export_dir.exists():
        shutil.rmtree(export_dir)
    result = subprocess.run(
        ["esedbexport", "-t", str(target), str(database)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"esedbexport failed for {database}: {result.stderr.strip() or result.stdout.strip()}")
    return export_dir


def _safe_export_name(database: Path) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", database.as_posix()).strip("_")
    return text[-180:] or "CacheStorage"


def _cache_rows_from_export(
    export_dir: Path,
    database: Path,
    source_root: Path,
    bodies_root: Path,
) -> list[dict[str, object]]:
    cache_names = _cache_storage_names(export_dir)
    rows: list[dict[str, object]] = []
    for table in sorted(export_dir.glob("Cache*.*")):
        if table.name.startswith("CacheStorages"):
            continue
        with table.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            for row_number, row in enumerate(reader, start=1):
                request_url = row.get("RequestUrl") or ""
                body_filename = row.get("ResponseBodyFilename") or ""
                if not request_url and not body_filename:
                    continue
                response_headers = row.get("ResponseHeader") or ""
                header_map = _parse_headers(response_headers)
                source_body = _resolve_windows_path(body_filename, source_root)
                body_info = _store_body(source_body, bodies_root, request_url, header_map)
                body_parent = _normalize_windows_path(body_filename.rsplit("\\", 1)[0]) if "\\" in body_filename else ""
                rows.append(
                    {
                        "user_profile": _user_profile_from_path(database),
                        "application_package": _package_from_path(database),
                        "source_database": str(database),
                        "source_table": table.name,
                        "table_row_number": row_number,
                        "cache_name": cache_names.get(body_parent, ""),
                        "site_origin": _site_origin_from_cache_name(cache_names.get(body_parent, "")),
                        "request_url": request_url,
                        "host": urlparse(request_url).netloc.lower(),
                        "response_status": row.get("ResponseStatus") or "",
                        "response_type": row.get("ResponseType") or "",
                        "response_headers": response_headers,
                        "response_date_utc": _http_date_to_utc(header_map.get("date", "")),
                        "content_type": header_map.get("content-type", ""),
                        "content_length": header_map.get("content-length", ""),
                        "source_body_path": str(source_body) if source_body else body_filename,
                        "stored_body_path": body_info["stored_body_path"],
                        "body_file_name": Path(body_filename).name if body_filename else "",
                        "body_size": body_info["body_size"],
                        "body_sha256": body_info["body_sha256"],
                        "body_encrypted": body_info["body_encrypted"],
                        "encryption_version": body_info["encryption_version"],
                        "decoded_state": body_info["decoded_state"],
                    }
                )
    return rows


def _cache_storage_names(export_dir: Path) -> dict[str, str]:
    names: dict[str, str] = {}
    for table in export_dir.glob("CacheStorages*"):
        with table.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle, delimiter="\t"):
                file_path = row.get("FilePath") or ""
                cache_name = row.get("CacheName") or ""
                if file_path:
                    names[_normalize_windows_path(file_path)] = cache_name
    return names


def _parse_headers(headers: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in headers.replace("\\r\\n", "\n").replace("\r\n", "\n").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip().lower()] = value.strip()
    return parsed


def _http_date_to_utc(value: str) -> str:
    if not value:
        return ""
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve_windows_path(value: str, source_root: Path) -> Path | None:
    if not value:
        return None
    normalized = value.replace("\\", "/")
    marker = "/Users/"
    if marker in normalized:
        relative = normalized.split(marker, 1)[1].lstrip("/")
        return source_root / Path(relative)
    path = Path(normalized)
    if path.exists():
        return path
    return None


def _store_body(
    source_body: Path | None,
    bodies_root: Path,
    request_url: str,
    headers: dict[str, str],
) -> dict[str, str]:
    if source_body is None or not source_body.is_file():
        return {
            "stored_body_path": "",
            "body_size": "",
            "body_sha256": "",
            "body_encrypted": "",
            "encryption_version": "",
            "decoded_state": "body_missing",
        }
    data = source_body.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    bodies_root.mkdir(parents=True, exist_ok=True)
    destination = bodies_root / f"{digest}.bin"
    if not destination.exists():
        shutil.copy2(source_body, destination)
    encryption_version = str(data[0]) if data else ""
    encrypted = _looks_encrypted(data, request_url, headers)
    return {
        "stored_body_path": str(destination),
        "body_size": str(len(data)),
        "body_sha256": digest,
        "body_encrypted": "true" if encrypted else "false",
        "encryption_version": encryption_version if encrypted else "",
        "decoded_state": "encrypted_opaque" if encrypted else "stored_opaque",
    }


def _looks_encrypted(data: bytes, request_url: str, headers: dict[str, str]) -> bool:
    if not data:
        return False
    host = urlparse(request_url).netloc.lower()
    content_type = headers.get("content-type", "").lower()
    if content_type != "application/octet-stream":
        return False
    return data[0] in range(1, 10) and any(token in host for token in ("officeapps", "office.com", "onedrive"))


def _normalize_windows_path(value: str) -> str:
    return value.replace("/", "\\").rstrip("\\").lower()


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


def _site_origin_from_cache_name(cache_name: str) -> str:
    if cache_name.endswith("-https://www.office.com/"):
        return "https://www.office.com/"
    if "-" in cache_name:
        return cache_name.rsplit("-", 1)[-1]
    return ""


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
