from __future__ import annotations

import csv
import gzip
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CLOUD_SYNC_FIELDS = [
    "provider",
    "artifact_type",
    "user_profile",
    "source_path",
    "source_name",
    "database_name",
    "table_name",
    "event_time_utc",
    "local_path",
    "cloud_path",
    "file_name",
    "file_id",
    "parent_id",
    "stable_id",
    "server_path",
    "url",
    "mime_type",
    "file_size",
    "is_folder",
    "is_deleted",
    "sync_status",
    "event_type",
    "direction",
    "owner",
    "shared",
    "protobuf_fields_json",
    "details_json",
    "error",
]

SQLITE_NAMES = {
    "microsoft.listsync.db",
    "aggregation.dbx",
    "config.dbx",
    "filecache.dbx",
    "icon.dbx",
    "instance.dbx",
    "nonlocalresources.dbx",
    "recentitems.dbx",
    "sfjresources.dbx",
    "starreditems.dbx",
    "sync_history.db",
    "traythumbnails.dbx",
    "global.db",
    "sync_config.db",
    "snapshot.db",
    "cloud_graph.db",
    "metadata_sqlite_db",
    "chunks.db",
    "account_db_sqlite.db",
}
SQLITE_SUFFIXES = {".db", ".dbx", ".sqlite", ".sqlite3"}
ONEDRIVE_SUFFIXES = {".dat", ".dat.previous", ".odl", ".odlgz", ".odlsent", ".aold"}
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_PRINTABLE_RE = re.compile((rb"(?:[\x20-\x7e]\x00){4,}"))
PATHISH_RE = re.compile(r"(?i)([a-z]:\\[^<>:\"|?*\r\n]+|/[^<>:\"|?*\r\n]+|https?://\S+)")


def parse_cloud_sync_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    sqlite_copies = output / "_sqlite_copies"
    for path, error in _walk_cloud_files(source):
        if error:
            rows.append(_error_row(source, path, error))
            continue
        if path is None:
            continue
        rows.append(_inventory_row(source, path))
        try:
            if _is_sqlite_candidate(path):
                rows.extend(_sqlite_rows(source, path, sqlite_copies))
            elif _is_onedrive_candidate(path):
                rows.extend(_onedrive_opaque_rows(source, path))
        except Exception as exc:  # pragma: no cover - defensive per-artifact isolation
            rows.append(_error_row(source, path, f"{type(exc).__name__}: {exc}"))
    csv_path = output / "CloudSyncArtifacts.csv"
    _write_csv(csv_path, CLOUD_SYNC_FIELDS, rows)
    return csv_path


def _walk_cloud_files(source: Path) -> Iterable[tuple[Path | None, str]]:
    if not source.exists():
        return
    for root, dirnames, filenames in os.walk(source, onerror=lambda exc: None):
        root_path = Path(root)
        root_lower = root_path.as_posix().lower()
        if not any(token in root_lower for token in ("dropbox", "google/drive", "google\\drive", "drivefs", "onedrive")):
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
            try:
                path.stat()
            except OSError as exc:
                yield path, str(exc)
                continue
            if _is_sqlite_candidate(path) or _is_onedrive_candidate(path) or _is_google_log(path):
                yield path, ""


def _is_sqlite_candidate(path: Path) -> bool:
    name = path.name.lower()
    return name in SQLITE_NAMES or path.suffix.lower() in SQLITE_SUFFIXES


def _is_onedrive_candidate(path: Path) -> bool:
    lower = path.as_posix().lower()
    name = path.name.lower()
    return "onedrive" in lower and (name.endswith(".dat.previous") or path.suffix.lower() in ONEDRIVE_SUFFIXES)


def _is_google_log(path: Path) -> bool:
    lower = path.as_posix().lower()
    return ("google/drive" in lower or "drivefs" in lower) and path.suffix.lower() in {".log", ".txt"}


def _base_row(source: Path, path: Path, artifact_type: str) -> dict[str, object]:
    return {
        "provider": _provider(path),
        "artifact_type": artifact_type,
        "user_profile": _user_profile_from_path(path),
        "source_path": str(path),
        "source_name": path.name,
        "database_name": path.name if _is_sqlite_candidate(path) else "",
        "table_name": "",
        "event_time_utc": "",
        "local_path": "",
        "cloud_path": "",
        "file_name": "",
        "file_id": "",
        "parent_id": "",
        "stable_id": "",
        "server_path": "",
        "url": "",
        "mime_type": "",
        "file_size": "",
        "is_folder": "",
        "is_deleted": "",
        "sync_status": "",
        "event_type": "",
        "direction": "",
        "owner": "",
        "shared": "",
        "protobuf_fields_json": "",
        "details_json": "",
        "error": "",
    }


def _inventory_row(source: Path, path: Path) -> dict[str, object]:
    row = _base_row(source, path, "cloud_artifact_file")
    try:
        stat = path.stat()
        row["file_size"] = str(stat.st_size)
        row["event_time_utc"] = _unix_to_iso(stat.st_mtime)
        row["details_json"] = _json({"sha256_first_mb": _sha256_first_mb(path)})
    except OSError as exc:
        row["error"] = str(exc)
    return row


def _error_row(source: Path, path: Path | None, error: str) -> dict[str, object]:
    return {**_base_row(source, path or source, "cloud_scan_error"), "error": error}


def _sqlite_rows(source: Path, path: Path, sqlite_copies: Path) -> list[dict[str, object]]:
    copied = _copy_sqlite_family(path, sqlite_copies)
    rows: list[dict[str, object]] = []
    connection = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        tables = [
            item["name"]
            for item in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            if not str(item["name"]).startswith("sqlite_")
        ]
        rows.append(_sqlite_inventory_row(source, path, copied, tables))
        provider = _provider(path)
        if provider == "Dropbox":
            rows.extend(_dropbox_rows(source, path, connection, tables))
        elif provider == "Google Drive":
            rows.extend(_google_drive_rows(source, path, connection, tables))
            rows.extend(_google_drive_cache_rows(source, path, connection, tables))
        elif provider == "OneDrive":
            rows.extend(_onedrive_sqlite_rows(source, path, connection, tables))
        rows.extend(_protobuf_rows(source, path, connection, tables))
    finally:
        connection.close()
    return rows


def _sqlite_inventory_row(source: Path, path: Path, copied: Path, tables: list[str]) -> dict[str, object]:
    row = _base_row(source, path, "sqlite_inventory")
    row["details_json"] = _json({"copied_database": str(copied), "tables": tables})
    return row


def _dropbox_rows(source: Path, path: Path, connection: sqlite3.Connection, tables: list[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    lower_tables = {table.lower(): table for table in tables}
    for wanted in ("sync_history", "recent_items", "starred_items", "nonlocal_resources", "sfj_resources"):
        table = lower_tables.get(wanted)
        if not table:
            continue
        for record in _select_rows(connection, table, limit=10000):
            row = _record_to_cloud_row(source, path, table, record, artifact_type=f"dropbox_{wanted}")
            row["event_time_utc"] = _first_timestamp(record)
            row["local_path"] = _first_text(record, "local_path", "path", "local_file", "local_file_path")
            row["cloud_path"] = _first_text(record, "server_path", "cloud_path", "display_path", "path")
            row["file_name"] = _name_like(row["local_path"] or row["cloud_path"]) or _first_text(record, "name", "filename")
            row["file_id"] = _first_text(record, "file_id", "id", "item_id", "resource_id")
            row["event_type"] = _first_text(record, "event_type", "file_event_type", "action", "operation")
            row["direction"] = _first_text(record, "direction", "sync_direction")
            rows.append(row)
    return rows


def _google_drive_rows(source: Path, path: Path, connection: sqlite3.Connection, tables: list[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    lower_tables = {table.lower(): table for table in tables}
    if {"cloud_entry", "cloud_relations"} <= set(lower_tables):
        rows.extend(_google_snapshot_rows(source, path, connection, lower_tables["cloud_entry"], lower_tables["cloud_relations"]))
    if "items" in lower_tables:
        rows.extend(_google_items_rows(source, path, connection, lower_tables["items"]))
    for wanted in ("changes", "cloud_graph_entry", "local_entry", "mapping"):
        table = lower_tables.get(wanted)
        if not table:
            continue
        for record in _select_rows(connection, table, limit=10000):
            rows.append(_record_to_cloud_row(source, path, table, record, artifact_type=f"google_drive_{wanted}"))
    return rows


def _google_drive_cache_rows(source: Path, path: Path, connection: sqlite3.Connection, tables: list[str]) -> list[dict[str, object]]:
    if path.name.lower() != "chunks.db" or "ranges" not in {table.lower() for table in tables}:
        return []
    account_root = path.parent.parent if path.parent.name.lower() in {"content_cache", "thumbnails_cache"} else path.parent
    metadata_db = account_root / "metadata_sqlite_db"
    content_cache_root = account_root / "content_cache"
    chunk_rows = _google_chunk_rows(connection)
    item_map = _google_chunk_item_map(metadata_db, set(chunk_rows))
    rows: list[dict[str, object]] = []
    for chunk_id, chunk_details in chunk_rows.items():
        cache_path = _find_google_cache_file(content_cache_root, chunk_id)
        item = item_map.get(chunk_id, {})
        row = _base_row(source, path, "google_drive_cache_mapping" if item else "google_drive_cache_file")
        row["table_name"] = "ranges"
        row["stable_id"] = str(item.get("stable_id") or "")
        row["file_id"] = str(item.get("file_id") or "")
        row["parent_id"] = str(item.get("parent_id") or "")
        row["file_name"] = str(item.get("file_name") or (cache_path.name if cache_path else chunk_id))
        row["cloud_path"] = str(item.get("cloud_path") or "")
        row["local_path"] = str(cache_path) if cache_path else ""
        row["file_size"] = str(cache_path.stat().st_size) if cache_path and cache_path.exists() else ""
        row["event_time_utc"] = _timestamp_value(item.get("modified_date")) or (
            _unix_to_iso(cache_path.stat().st_mtime) if cache_path and cache_path.exists() else ""
        )
        row["details_json"] = _json(
            {
                "cache_id": chunk_id,
                "ranges_proto": chunk_details,
                "cache_path": str(cache_path) if cache_path else "",
                "windows_cache_path": _windows_path_from_mounted_path(cache_path) if cache_path else "",
                "metadata_db": str(metadata_db),
                "mapping_method": "chunks.ranges.id equals metadata items.proto varint"
                if item
                else "content_cache numeric cache file only",
                "evidence_basis": "Google DriveFS chunk id matched item protobuf varint"
                if item
                else "No item protobuf varint matched this chunk id",
            }
        )
        rows.append(row)
    return rows


def _google_chunk_rows(connection: sqlite3.Connection) -> dict[str, dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    try:
        cursor = connection.execute("SELECT id, ranges_proto FROM ranges")
    except sqlite3.DatabaseError:
        return rows
    for row in cursor:
        chunk_id = str(row["id"])
        proto = row["ranges_proto"]
        rows[chunk_id] = _decode_protobuf_like(proto) if isinstance(proto, bytes) else {}
    return rows


def _google_chunk_item_map(metadata_db: Path, chunk_ids: set[str]) -> dict[str, dict[str, object]]:
    if not metadata_db.exists() or not chunk_ids:
        return {}
    with tempfile.TemporaryDirectory(prefix="fo-google-drive-metadata-") as copied_parent:
        copied = _copy_sqlite_family(metadata_db, Path(copied_parent))
        connection = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            tables = [
                item["name"].lower()
                for item in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            ]
            if "items" not in tables:
                return {}
            records = [dict(row) for row in _select_rows(connection, "items", limit=100000)]
            by_id = {str(_first_text(row, "stable_id", "id", "doc_id")): row for row in records if _first_text(row, "stable_id", "id", "doc_id")}
            parent_map = _google_stable_parent_map(connection)
            stable_id_map = _google_stable_ids(connection)
            mapped: dict[str, dict[str, object]] = {}
            for record in records:
                proto = record.get("proto")
                if not isinstance(proto, bytes):
                    continue
                decoded = _decode_protobuf_like(proto)
                values = {str(item.get("value")) for item in decoded.get("varints", []) if isinstance(item, dict) and "value" in item}
                for chunk_id in chunk_ids & values:
                    stable_id = _first_text(record, "stable_id", "id", "doc_id")
                    mapped[chunk_id] = {
                        "stable_id": stable_id,
                        "file_id": _first_text(record, "cloud_identifier", "doc_id", "id") or stable_id_map.get(stable_id) or stable_id,
                        "parent_id": parent_map.get(stable_id) or _first_text(record, "parent_stable_id", "parent_id", "parent_doc_id"),
                        "file_name": _first_text(record, "local_title", "filename", "name", "title"),
                        "cloud_path": _build_parent_path(stable_id, by_id, parent_map),
                        "modified_date": _first_text(record, "modified_date", "modified", "created"),
                    }
        finally:
            connection.close()
    return mapped


def _find_google_cache_file(content_cache_root: Path, chunk_id: str) -> Path | None:
    if not content_cache_root.exists():
        return None
    for root, _, filenames in os.walk(content_cache_root, onerror=lambda exc: None):
        if chunk_id not in filenames:
            continue
        candidate = Path(root) / chunk_id
        if candidate.is_file():
            return candidate
    return None


def _windows_path_from_mounted_path(path: Path | None) -> str:
    if path is None:
        return ""
    parts = path.parts
    lowered = [part.lower() for part in parts]
    if "users" not in lowered:
        return ""
    index = lowered.index("users")
    return "C:\\" + "\\".join(parts[index:])


def _google_snapshot_rows(
    source: Path,
    path: Path,
    connection: sqlite3.Connection,
    entry_table: str,
    relations_table: str,
) -> list[dict[str, object]]:
    entries = {str(row["doc_id"]): dict(row) for row in _select_rows(connection, entry_table, limit=50000) if row.get("doc_id") is not None}
    parents: dict[str, str] = {}
    for row in _select_rows(connection, relations_table, limit=50000):
        if row.get("child_doc_id") is not None and row.get("parent_doc_id") is not None:
            parents[str(row["child_doc_id"])] = str(row["parent_doc_id"])
    rows: list[dict[str, object]] = []
    for doc_id, record in entries.items():
        row = _record_to_cloud_row(source, path, entry_table, record, artifact_type="google_drive_snapshot_entry")
        row["file_id"] = doc_id
        row["parent_id"] = parents.get(doc_id, "")
        row["file_name"] = _first_text(record, "filename", "name", "local_title")
        row["cloud_path"] = _build_parent_path(doc_id, entries, parents)
        row["event_time_utc"] = _timestamp_value(_first_text(record, "modified", "created"))
        row["file_size"] = _first_text(record, "size", "original_size")
        row["is_deleted"] = _first_text(record, "removed", "deleted", "is_deleted")
        row["shared"] = _first_text(record, "shared")
        rows.append(row)
    return rows


def _google_items_rows(source: Path, path: Path, connection: sqlite3.Connection, table: str) -> list[dict[str, object]]:
    records = [dict(row) for row in _select_rows(connection, table, limit=50000)]
    by_id = {str(_first_text(row, "stable_id", "id", "doc_id")): row for row in records if _first_text(row, "stable_id", "id", "doc_id")}
    parent_map = _google_stable_parent_map(connection)
    property_map = _google_item_properties(connection)
    stable_id_map = _google_stable_ids(connection)
    rows: list[dict[str, object]] = []
    for record in records:
        row = _record_to_cloud_row(source, path, table, record, artifact_type="google_drive_metadata_item")
        stable_id = _first_text(record, "stable_id", "id", "doc_id")
        parent_id = parent_map.get(stable_id) or _first_text(record, "parent_stable_id", "parent_id", "parent_doc_id")
        item_properties = property_map.get(stable_id, {})
        proto = record.get("proto")
        proto_summary = _decode_protobuf_like(proto) if isinstance(proto, bytes) else {}
        row["stable_id"] = stable_id
        row["file_id"] = _first_text(record, "cloud_identifier", "doc_id", "id") or stable_id_map.get(stable_id) or stable_id
        row["parent_id"] = parent_id
        row["file_name"] = _first_text(record, "local_title", "filename", "name", "title") or str(item_properties.get("local-title") or "")
        row["cloud_path"] = _build_parent_path(stable_id, by_id, parent_map)
        row["event_time_utc"] = (
            _timestamp_value(item_properties.get("local-content-modified-date"))
            or _timestamp_value(_first_text(record, "modified_date", "modified", "created"))
            or _first_timestamp(record)
        )
        row["mime_type"] = _first_text(record, "mime_type")
        row["file_size"] = _first_text(record, "file_size", "size")
        row["is_folder"] = _first_text(record, "is_folder", "folder")
        row["is_deleted"] = _first_text(record, "is_deleted", "deleted", "trashed", "is_tombstone")
        row["owner"] = _first_text(record, "owner", "owner_email", "owner_display_name")
        row["shared"] = _first_text(record, "shared", "is_shared")
        row["protobuf_fields_json"] = _json(proto_summary) if proto_summary else ""
        row["details_json"] = _json(
            {
                "row": _jsonable_record(record),
                "item_properties": item_properties,
                "cloud_id_from_stable_ids": stable_id_map.get(stable_id, ""),
            }
        )
        rows.append(row)
    return rows


def _google_stable_parent_map(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        return {
            str(row["item_stable_id"]): str(row["parent_stable_id"])
            for row in connection.execute("SELECT item_stable_id, parent_stable_id FROM stable_parents")
            if row["item_stable_id"] is not None and row["parent_stable_id"] is not None
        }
    except sqlite3.DatabaseError:
        return {}


def _google_item_properties(connection: sqlite3.Connection) -> dict[str, dict[str, object]]:
    properties: dict[str, dict[str, object]] = {}
    try:
        for row in connection.execute("SELECT item_stable_id, key, value FROM item_properties"):
            stable_id = str(row["item_stable_id"])
            properties.setdefault(stable_id, {})[str(row["key"])] = row["value"]
    except sqlite3.DatabaseError:
        return {}
    return properties


def _google_stable_ids(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        return {
            str(row["stable_id"]): str(row["cloud_id"])
            for row in connection.execute("SELECT stable_id, cloud_id FROM stable_ids")
            if row["stable_id"] is not None and row["cloud_id"] is not None
        }
    except sqlite3.DatabaseError:
        return {}


def _onedrive_sqlite_rows(source: Path, path: Path, connection: sqlite3.Connection, tables: list[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    rows.extend(_onedrive_listsync_rows(source, path, connection, tables))
    for table in tables:
        if _is_onedrive_listsync_row_table(path, table):
            continue
        for record in _select_rows(connection, table, limit=10000):
            row = _record_to_cloud_row(source, path, table, record, artifact_type=f"onedrive_sqlite_{table.lower()[:40]}")
            row["event_time_utc"] = _first_timestamp(record)
            rows.append(row)
    return rows


def _onedrive_listsync_rows(source: Path, path: Path, connection: sqlite3.Connection, tables: list[str]) -> list[dict[str, object]]:
    if path.name.lower() != "microsoft.listsync.db":
        return []
    rows: list[dict[str, object]] = []
    for table in tables:
        table_lower = table.lower()
        if not (table_lower.startswith("list_") and table_lower.endswith("_rows")):
            continue
        columns = _table_columns(connection, table)
        if "mediaserviceocr" not in {column.lower() for column in columns}:
            continue
        list_id, site_id = _onedrive_listsync_ids(table)
        for record in _select_rows(connection, table, limit=100000):
            row = _record_to_cloud_row(source, path, table, record, artifact_type="onedrive_listsync_row")
            row["event_time_utc"] = _first_timestamp(record)
            row["file_name"] = (
                _first_text(record, "FileLeafRef", "fileLeafRef", "Name", "name", "Title", "title")
                or row["file_name"]
            )
            row["cloud_path"] = (
                _first_text(record, "FileRef", "fileRef", "FileDirRef", "fileDirRef", "Path", "path")
                or row["cloud_path"]
            )
            row["file_id"] = _first_text(record, "UniqueId", "uniqueId", "GUID", "Id", "id") or row["file_id"]
            row["parent_id"] = _first_text(record, "ParentUniqueId", "parentUniqueId", "ParentId", "parentId") or row["parent_id"]
            row["mime_type"] = _first_text(record, "ContentType", "contentType", "File_x0020_Type", "FileType") or row["mime_type"]
            row["file_size"] = _first_text(record, "File_x0020_Size", "SMTotalFileStreamSize", "Size", "size") or row["file_size"]
            row["is_folder"] = _onedrive_listsync_is_folder(record) or row["is_folder"]
            row["is_deleted"] = _first_text(record, "IsDeleted", "isDeleted", "Deleted", "deleted") or row["is_deleted"]
            row["sync_status"] = "offline_metadata"
            row["event_type"] = "onedrive_offline_metadata"
            row["owner"] = _first_text(record, "Author", "CreatedBy", "Editor", "ModifiedBy") or row["owner"]
            row["details_json"] = _json(
                {
                    "list_id": list_id,
                    "site_id": site_id,
                    "media_service_ocr": _first_text(record, "MediaServiceOCR"),
                    "row": _jsonable_record(record),
                    "artifact_note": "OneDrive for Business Offline Mode Microsoft.ListSync.db row",
                }
            )
            rows.append(row)
    return rows


def _is_onedrive_listsync_row_table(path: Path, table: str) -> bool:
    table_lower = table.lower()
    return path.name.lower() == "microsoft.listsync.db" and table_lower.startswith("list_") and table_lower.endswith("_rows")


def _table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    try:
        return [str(row["name"]) for row in connection.execute(f"PRAGMA table_info({_quote_identifier(table)})")]
    except sqlite3.DatabaseError:
        return []


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _onedrive_listsync_ids(table: str) -> tuple[str, str]:
    match = re.match(r"(?i)^list_(?P<list>.+)_(?P<site>.+)_rows$", table)
    if not match:
        return "", ""
    return match.group("list"), match.group("site")


def _onedrive_listsync_is_folder(record: dict[str, Any]) -> str:
    fs_obj_type = _first_text(record, "FSObjType", "fsObjType")
    if fs_obj_type == "1":
        return "true"
    if fs_obj_type == "0":
        return "false"
    content_type = _first_text(record, "ContentType", "contentType")
    if "folder" in content_type.lower():
        return "true"
    return ""


def _protobuf_rows(source: Path, path: Path, connection: sqlite3.Connection, tables: list[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in tables:
        for record in _select_rows(connection, table, limit=5000):
            for key, value in record.items():
                if not isinstance(value, bytes) or len(value) < 8:
                    continue
                decoded = _decode_protobuf_like(value)
                strings = decoded.get("strings") or []
                if not strings:
                    continue
                row = _record_to_cloud_row(source, path, table, record, artifact_type="protobuf_blob_strings")
                row["file_name"] = _first_filename_string(strings)
                row["local_path"] = _first_path_string(strings)
                row["cloud_path"] = _first_cloud_path_string(strings)
                row["protobuf_fields_json"] = _json({"column": key, **decoded})
                rows.append(row)
    return rows


def _record_to_cloud_row(
    source: Path,
    path: Path,
    table: str,
    record: dict[str, Any],
    *,
    artifact_type: str,
) -> dict[str, object]:
    row = _base_row(source, path, artifact_type)
    row["table_name"] = table
    row["event_time_utc"] = _first_timestamp(record)
    row["local_path"] = _first_text(record, "local_path", "path", "filename", "local_filename", "local_uri")
    row["cloud_path"] = _first_text(record, "cloud_path", "server_path", "display_path", "remote_path", "full_path")
    row["file_name"] = _first_text(record, "file_name", "filename", "name", "local_title", "title")
    row["file_id"] = _first_text(record, "file_id", "id", "doc_id", "resource_id", "cloud_identifier")
    row["parent_id"] = _first_text(record, "parent_id", "parent_doc_id", "parent_stable_id")
    row["stable_id"] = _first_text(record, "stable_id")
    row["server_path"] = _first_text(record, "server_path")
    row["url"] = _first_text(record, "url", "web_url", "alternate_link")
    row["mime_type"] = _first_text(record, "mime_type", "mimetype")
    row["file_size"] = _first_text(record, "file_size", "size", "bytes")
    row["is_folder"] = _first_text(record, "is_folder", "folder")
    row["is_deleted"] = _first_text(record, "is_deleted", "deleted", "removed", "trashed")
    row["sync_status"] = _first_text(record, "sync_status", "status", "state")
    row["event_type"] = _first_text(record, "event_type", "file_event_type", "action", "operation")
    row["direction"] = _first_text(record, "direction")
    row["owner"] = _first_text(record, "owner", "owner_email", "owner_display_name")
    row["shared"] = _first_text(record, "shared", "is_shared")
    row["details_json"] = _json(_jsonable_record(record))
    return row


def _onedrive_opaque_rows(source: Path, path: Path) -> list[dict[str, object]]:
    data = _read_maybe_gzip(path)
    if path.name.lower().endswith((".dat", ".dat.previous")):
        return _onedrive_dat_rows(source, path, data)
    return _onedrive_log_rows(source, path, data)


def _onedrive_dat_rows(source: Path, path: Path, data: bytes) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    names = _extract_utf16_strings(data)
    seen_names: set[str] = set()
    for index, name in enumerate(names, start=1):
        if not _looks_like_onedrive_item_name(name):
            continue
        key = name.lower()
        if key in seen_names:
            continue
        seen_names.add(key)
        row = _base_row(source, path, "onedrive_dat_item_name")
        row["event_time_utc"] = _unix_to_iso(path.stat().st_mtime)
        row["file_name"] = name
        row["is_folder"] = "false" if "." in name else ""
        row["details_json"] = _json({"string_index": index, "source_format": path.suffix.lower()})
        rows.append(row)
    rows.extend(_onedrive_dat_identifier_rows(source, path, data))
    return rows


def _onedrive_dat_identifier_rows(source: Path, path: Path, data: bytes) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    ascii_strings = _extract_ascii_strings(data)
    seen: set[str] = set()
    metadata_re = re.compile(
        r"(?P<scope>\d+);%23(?P<a>\d+);%23(?P<b>\d+);(?P<kind>\d+);"
        r"(?P<id>[0-9a-fA-F]{32});(?P<filetime>\d+);(?P<size>\d+)"
    )
    relation_re = re.compile(r'^\{(?P<id>[0-9A-Fa-f-]{36})\},(?P<kind>\d+)$')
    for text in ascii_strings:
        metadata = metadata_re.search(text)
        relation = relation_re.search(text)
        if not metadata and not relation:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        row = _base_row(source, path, "onedrive_dat_identifier")
        row["event_time_utc"] = _timestamp_value(metadata.group("filetime")) if metadata else _unix_to_iso(path.stat().st_mtime)
        row["file_id"] = _format_guid(metadata.group("id")) if metadata else relation.group("id").upper()
        row["file_size"] = metadata.group("size") if metadata else ""
        row["is_folder"] = "true" if relation and relation.group("kind") == "1" else ""
        row["details_json"] = _json(
            {
                "raw": text,
                "record_kind": metadata.group("kind") if metadata else relation.group("kind"),
                "source_format": path.suffix.lower(),
            }
        )
        rows.append(row)
    return rows


def _onedrive_log_rows(source: Path, path: Path, data: bytes) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    event_time = _onedrive_log_time(path) or _unix_to_iso(path.stat().st_mtime)
    strings = _extract_strings(data)
    seen: set[str] = set()
    for text in strings:
        if not _looks_interesting_onedrive_log_string(text):
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        row = _base_row(source, path, "onedrive_log_entry")
        row["event_time_utc"] = event_time
        row["local_path"] = _first_path_string([text])
        row["url"] = text if text.lower().startswith(("http://", "https://")) else ""
        row["file_name"] = _name_like(row["local_path"]) if row["local_path"] else _name_like(text)
        row["event_type"] = _classify_onedrive_log_string(text)
        row["details_json"] = _json({"value": text, "source_format": path.suffix.lower()})
        rows.append(row)
        if len(rows) >= 5000:
            break
    return rows


def _copy_sqlite_family(path: Path, output: Path) -> Path:
    digest = hashlib.sha1(str(path).encode("utf-8", errors="replace")).hexdigest()[:12]
    target_dir = output / f"{path.name}_{digest}"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / path.name
    shutil.copy2(path, target)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            shutil.copy2(sidecar, target_dir / sidecar.name)
    return target


def _select_rows(connection: sqlite3.Connection, table: str, *, limit: int) -> list[dict[str, Any]]:
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {quoted} LIMIT ?", (limit,))]
    except sqlite3.DatabaseError:
        return []


def _build_parent_path(item_id: str, entries: dict[str, dict[str, Any]], parents: dict[str, str]) -> str:
    if not item_id:
        return ""
    parts: list[str] = []
    current = item_id
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        item = entries.get(current)
        if item:
            name = _first_text(item, "filename", "local_title", "name", "title")
            if name and name.lower() != "root":
                parts.append(name)
        current = parents.get(current, "")
    return "/" + "/".join(reversed(parts)) if parts else ""


def _decode_protobuf_like(data: bytes) -> dict[str, object]:
    strings = _extract_strings(data)
    path_strings = [item for item in strings if "\\" in item or "/" in item or item.startswith("http")]
    varints = _protobuf_varints(data, limit=40)
    return {
        "strings": strings[:50],
        "path_strings": path_strings[:25],
        "varints": varints,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _protobuf_varints(data: bytes, *, limit: int) -> list[dict[str, int]]:
    values: list[dict[str, int]] = []
    index = 0
    while index < len(data) and len(values) < limit:
        start = index
        key, index = _read_varint(data, index)
        if key is None:
            break
        field = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, index = _read_varint(data, index)
            if value is None:
                break
            values.append({"offset": start, "field": field, "wire_type": wire_type, "value": value})
        elif wire_type == 2:
            size, index = _read_varint(data, index)
            if size is None or index + size > len(data):
                break
            values.append({"offset": start, "field": field, "wire_type": wire_type, "length": size})
            index += size
        elif wire_type == 1:
            index += 8
        elif wire_type == 5:
            index += 4
        else:
            break
    return values


def _read_varint(data: bytes, index: int) -> tuple[int | None, int]:
    shift = 0
    value = 0
    while index < len(data) and shift < 70:
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
        shift += 7
    return None, index


def _extract_strings(data: bytes) -> list[str]:
    return _dedupe_keep_order(_extract_ascii_strings(data) + _extract_utf16_strings(data))


def _extract_ascii_strings(data: bytes) -> list[str]:
    strings: list[str] = []
    for match in PRINTABLE_RE.finditer(data):
        strings.append(match.group(0).decode("utf-8", errors="replace"))
    return strings


def _extract_utf16_strings(data: bytes) -> list[str]:
    strings: list[str] = []
    for match in UTF16_PRINTABLE_RE.finditer(data):
        strings.append(match.group(0).decode("utf-16le", errors="replace"))
    return strings


def _first_filename_string(strings: list[str]) -> str:
    for item in strings:
        candidate = _name_like(item)
        if candidate and "." in candidate and not candidate.lower().startswith("vnd."):
            return candidate
    return ""


def _first_path_string(strings: list[str]) -> str:
    for item in strings:
        match = PATHISH_RE.search(item)
        if not match:
            continue
        candidate = match.group(1).rstrip(".,;")
        lower = candidate.lower()
        if lower.startswith("http"):
            continue
        if re.match(r"^[a-z]:\\", candidate, flags=re.I):
            return candidate
        if candidate.startswith("/") and candidate.count("/") >= 2 and not lower.startswith("/vnd."):
            return candidate
    return ""


def _first_cloud_path_string(strings: list[str]) -> str:
    for item in strings:
        if item.startswith("/") and item.count("/") >= 2 and not item.lower().startswith("/vnd."):
            return item
    return ""


def _looks_interesting_onedrive_log_string(text: str) -> bool:
    lower = text.lower()
    if lower.startswith(("http://", "https://")) or "sharepoint" in lower:
        return True
    if re.search(r"(?i)[a-z]:\\[^<>:\"|?*\r\n]*(onedrive|sharepoint)[^<>:\"|?*\r\n]*", text):
        return True
    if not any(token in lower for token in ("upload", "download", "delete", "hydrate", "dehydrate", "error", "fail")):
        return False
    if re.search(r"(?i)\.(docx?|xlsx?|pptx?|pdf|jpe?g|png|gif|txt|csv|zip|7z|pst|ost|one|vsd[xm]?)(?:\b|$)", text):
        return True
    return False


def _looks_like_onedrive_item_name(text: str) -> bool:
    if not text or len(text) > 255:
        return False
    lower = text.lower()
    if lower in {"desktop", "documents", "pictures", "camera roll", "screenshots"}:
        return True
    if re.fullmatch(r"[0-9a-f]{32}", lower) or re.fullmatch(r"[0-9a-f-]{36}", lower):
        return False
    if any(char in text for char in "\\/:*?\"<>|"):
        return False
    return bool(re.search(r"\.[A-Za-z0-9]{1,8}$", text)) or bool(re.search(r"[A-Za-z].*[A-Za-z]", text))


def _classify_onedrive_log_string(text: str) -> str:
    lower = text.lower()
    for event in ("download", "upload", "delete", "hydrate", "dehydrate", "sync", "error", "fail"):
        if event in lower:
            return event
    if lower.startswith(("http://", "https://")):
        return "url"
    return "log_reference"


def _onedrive_log_time(path: Path) -> str:
    match = re.search(r"(?P<date>\d{4}-\d{2}-\d{2})\.(?P<hour>\d{2})(?P<minute>\d{2})", path.name)
    if not match:
        return ""
    return f"{match.group('date')}T{match.group('hour')}:{match.group('minute')}:00+00:00"


def _format_guid(value: str) -> str:
    clean = value.replace("-", "").upper()
    if len(clean) != 32:
        return value
    return f"{clean[0:8]}-{clean[8:12]}-{clean[12:16]}-{clean[16:20]}-{clean[20:32]}"


def _read_maybe_gzip(path: Path) -> bytes:
    if path.suffix.lower() in {".gz", ".odlgz"}:
        try:
            with gzip.open(path, "rb") as handle:
                return handle.read()
        except OSError:
            return path.read_bytes()
    return path.read_bytes()


def _provider(path: Path) -> str:
    lower = path.as_posix().lower()
    if "dropbox" in lower:
        return "Dropbox"
    if "google/drive" in lower or "google\\drive" in lower or "drivefs" in lower:
        return "Google Drive"
    if "onedrive" in lower:
        return "OneDrive"
    return "Cloud"


def _user_profile_from_path(path: Path) -> str:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    for marker in ("users", "documents and settings"):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1]
    return ""


def _first_text(row: dict[str, Any], *names: str) -> str:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None and value != "":
            if isinstance(value, bytes):
                return value.hex()
            return str(value)
    return ""


def _first_timestamp(row: dict[str, Any]) -> str:
    for key, value in row.items():
        lower = str(key).lower()
        if value in (None, ""):
            continue
        if any(token in lower for token in ("time", "date", "modified", "created", "accessed", "updated")):
            converted = _timestamp_value(value)
            if converted:
                return converted
    return ""


def _timestamp_value(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bytes):
        return ""
    text = str(value)
    if re.match(r"^\d{4}-\d{2}-\d{2}", text):
        return text
    try:
        number = float(text)
    except ValueError:
        return ""
    if number <= 0:
        return ""
    if number > 10_000_000_000_000_000:
        # Windows FILETIME.
        seconds = (number - 116444736000000000) / 10_000_000
    elif number > 10_000_000_000_000:
        seconds = number / 1_000_000
    elif number > 10_000_000_000:
        seconds = number / 1000
    elif number > 1_000_000_000:
        seconds = number
    else:
        return ""
    try:
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _unix_to_iso(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _name_like(text: object) -> str:
    if not text:
        return ""
    item = str(text).strip().rstrip("\\/")
    if not item:
        return ""
    if "\\" in item or "/" in item:
        item = re.split(r"[\\/]", item)[-1]
    match = re.search(r"[^\\/\s]+?\.[A-Za-z0-9]{1,8}", item)
    if match:
        return match.group(0)
    if len(item) <= 255 and re.search(r"\.[A-Za-z0-9]{1,8}$", item):
        return item
    return ""


def _jsonable_record(row: dict[str, Any]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in row.items():
        if isinstance(value, bytes):
            result[str(key)] = {"bytes_hex_prefix": value[:64].hex(), "size": len(value)}
        else:
            result[str(key)] = value
    return result


def _sha256_first_mb(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        digest.update(handle.read(1024 * 1024))
    return digest.hexdigest()


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = re.sub(r"\s+", " ", value).strip()
        if not cleaned or cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        result.append(cleaned)
    return result


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
