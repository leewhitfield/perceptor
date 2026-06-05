from __future__ import annotations

import os
import json
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None


ANALYTICS_TABLE_COLUMNS: dict[str, list[str]] = {
    "evtx_events": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
        "source_csv", "row_number", "record_number", "event_record_id", "time_created",
        "event_id", "level", "provider", "channel", "process_id", "thread_id", "computer",
        "user_id", "map_description", "user_name", "remote_host", "payload_data1",
        "payload_data2", "payload_data3", "payload_data4", "payload_data5",
        "payload_data6", "executable_info", "source_file", "payload", "created_at",
    ],
    "timeline_events": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "source_tool",
        "source_table", "source_row_id", "event_type", "raw_timestamp", "timestamp_utc",
        "end_timestamp_utc", "duration_ms", "description", "details_json", "created_at",
    ],
    "onedrive_log_entries": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
        "source_csv", "row_number", "user_profile", "account", "source_path",
        "source_name", "log_type", "record_index", "odl_version", "one_drive_version",
        "windows_version", "timestamp_utc", "code_file", "function", "flags",
        "event_type", "local_path", "url", "resource_id", "parser_status", "error",
        "created_at",
    ],
    "windows_search_properties": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
        "source_csv", "source_table", "source_record_id", "row_number", "work_id",
        "item_path", "property_name", "normalized_name", "timestamp",
        "created_at",
    ],
    "bits_jobs": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "source_path",
        "database_file", "source_table", "record_id", "record_type",
        "job_id", "job_name", "job_owner", "job_state", "job_type",
        "priority", "created_utc", "modified_utc", "completed_utc",
        "expiration_utc", "url", "local_path", "remote_name", "file_size",
        "bytes_transferred", "raw_row_json", "parser_status",
        "parser_error", "created_at",
    ],
    "bits_activity": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "source_table",
        "source_row_id", "event_time_utc", "event_id", "event_type",
        "provider", "channel", "computer", "job_id", "job_name",
        "job_owner", "url", "peer", "file_count", "total_bytes",
        "bytes_transferred", "local_path", "matched_bits_job_id",
        "correlation_basis", "raw_fields_json", "created_at",
    ],
    "clipboard_items": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "source_path",
        "user_profile", "source_type", "source_table", "row_identifier",
        "item_time_utc", "created_time_utc", "modified_time_utc",
        "last_used_time_utc", "sequence_number", "format_name",
        "content_type", "text_content", "file_uri", "html_content",
        "image_present", "payload_size", "cloud_sync_state",
        "cloud_sync_id", "device_id", "raw_payload_json", "parser_status",
        "parser_error", "created_at",
    ],
    "file_internal_metadata": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
        "source_csv", "row_number", "source_file", "original_path", "file_name",
        "extension", "parser", "metadata_group", "property_name", "raw_property_name",
        "file_size", "mft_created", "mft_modified", "mft_accessed",
        "mft_record_modified", "mft_in_use", "path_unresolved", "deleted_mft_entry",
        "live_orphan", "extraction_method", "created_at",
    ],
    "archive_entries": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
        "source_csv", "row_number", "archive_path", "archive_file_name",
        "archive_extension", "archive_file_size", "archive_modified_time_utc",
        "archive_status", "archive_error", "member_path", "member_file_name",
        "member_extension", "member_size", "member_compressed_size", "member_crc",
        "member_modified_time_utc", "member_is_dir", "member_is_encrypted",
        "nested_evidence_format", "multipart_set_id", "multipart_part_number",
        "multipart_part_count", "multipart_is_first_part",
        "multipart_related_parts", "created_at",
    ],
    "content_references": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "source_tool", "source_table", "source_row_id", "content_role",
        "opensearch_document_id", "content_sha256", "content_length",
        "source_path", "created_at",
    ],
    "nested_evidence_items": [
        "id", "case_id", "computer_id", "image_id", "source_table", "source_id",
        "source_file", "original_path", "parent_path", "file_name", "extension",
        "file_size", "detected_format", "created_time_utc", "modified_time_utc",
        "accessed_time_utc", "record_changed_time_utc", "mft_entry_number",
        "mft_sequence_number", "multipart_set_id", "multipart_part_number",
        "multipart_part_count", "multipart_is_first_part",
        "multipart_related_parts", "parser_status", "recommendation",
        "created_at",
    ],
    "cloud_server_events": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "provider", "service",
        "event_type", "event_time_utc", "actor", "actor_id", "actor_ip",
        "target", "target_id", "target_type", "operation", "result",
        "user_agent", "client_app", "file_name", "file_path", "url",
        "message_id", "conversation_id", "content_sha256", "content_length",
        "opensearch_document_id", "source_log_type", "source_record_id",
        "raw_fields_json", "created_at",
    ],
    "memory_string_hits": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "source_artifact_type",
        "source_path", "scanned_path", "decompressed_path", "scanner",
        "encoding", "hit_category", "matched_term", "string_value",
        "string_sha256", "string_length", "offset", "context_hint",
        "created_at",
    ],
    "carve_scan_ranges": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "profile", "carve_type",
        "source_path", "source_size", "range_start", "range_end",
        "scanned_bytes", "hits_found", "limited", "limit_reason", "status",
        "notes", "created_at",
    ],
    "staged_carves": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "profile", "source_path",
        "source_offset", "staged_path", "staged_name", "staged_size",
        "staged_sha256", "carve_type", "detected_format", "parser_status",
        "parser_error", "table_count", "object_count", "extractable_row_count",
        "import_status", "notes", "created_at",
    ],
    "windows_search_memory_carves": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "carve_path",
        "carve_name", "carve_size", "carve_sha256", "source_process",
        "source_pid", "virtual_address", "detected_format", "page_size",
        "reserved_bytes", "parser_status", "parser_error", "table_count",
        "object_count", "extractable_row_count", "matched_disk_db",
        "matched_disk_page", "matched_tail_hex", "notes", "created_at",
    ],
    "windows_search_memory_objects": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "carve_id",
        "carve_path", "object_type", "object_name", "table_name",
        "rootpage", "sql_text", "parser_status", "parser_error",
        "created_at",
    ],
    "windows_search_memory_rows": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "carve_id",
        "carve_path", "table_name", "table_row_number", "row_json",
        "row_text", "row_sha256", "parser_status", "parser_error",
        "created_at",
    ],
    "filesystem_entries": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "partition_id",
        "filesystem_type", "source_root", "file_path", "parent_path",
        "file_name", "extension", "file_size", "is_directory",
        "created_utc", "modified_utc", "accessed_utc",
        "metadata_changed_utc", "mode", "uid", "gid", "scan_status",
        "error", "created_at",
    ],
}


class AnalyticsStore:
    def __init__(self, sqlite_conn: sqlite3.Connection) -> None:
        self.sqlite_conn = sqlite_conn
        self._connections: dict[str, duckdb.DuckDBPyConnection] = {}
        self.write_lock_timeout_seconds = float(os.environ.get("FORENSIC_DUCKDB_WRITE_LOCK_TIMEOUT", "600"))

    def close(self) -> None:
        for conn in self._connections.values():
            conn.close()
        self._connections.clear()

    def insert_rows(self, table: str, columns: list[str], rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        for case_id, case_rows in self._group_by_case(rows).items():
            with self._write_connection(case_id) as conn:
                self._ensure_table(conn, table, columns)
                column_sql = ", ".join(_quote_identifier(column) for column in columns)
                frame = pd.DataFrame.from_records(
                    [
                        {column: _normalize_value(row.get(column)) for column in columns}
                        for row in case_rows
                    ],
                    columns=columns,
                )
                view_name = f"_analytics_insert_{id(frame)}"
                conn.register(view_name, frame)
                try:
                    if "id" in columns:
                        conn.execute(
                            f"DELETE FROM {_quote_identifier(table)} "
                            f"WHERE id IN (SELECT id FROM {_quote_identifier(view_name)} WHERE id IS NOT NULL)"
                        )
                    conn.execute(
                        f"INSERT INTO {_quote_identifier(table)} ({column_sql}) "
                        f"SELECT {column_sql} FROM {_quote_identifier(view_name)}"
                    )
                finally:
                    conn.unregister(view_name)

    def delete_case_image(
        self,
        table: str,
        *,
        case_id: str,
        image_id: str | None = None,
        tool_names: list[str] | None = None,
    ) -> None:
        with self._write_connection(case_id) as conn:
            if not self._table_exists(conn, table):
                return
            where = ["case_id = ?"]
            params: list[object] = [case_id]
            if image_id is not None:
                where.append("image_id = ?")
                params.append(image_id)
            if tool_names:
                tool_column = self._tool_column(conn, table)
                if tool_column is None:
                    return
                placeholders = ", ".join("?" for _ in tool_names)
                where.append(f"{_quote_identifier(tool_column)} IN ({placeholders})")
                params.extend(tool_names)
            conn.execute(f"DELETE FROM {_quote_identifier(table)} WHERE {' AND '.join(where)}", params)

    def delete_where(self, table: str, where: str, params: list[object] | tuple[object, ...]) -> None:
        if not params:
            return
        with self._write_connection(str(params[0])) as conn:
            if not self._table_exists(conn, table):
                return
            conn.execute(f"DELETE FROM {_quote_identifier(table)} WHERE {where}", list(params))

    def _group_by_case(self, rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            case_id = str(row["case_id"])
            grouped.setdefault(case_id, []).append(row)
        return grouped

    def _connect(self, case_id: str) -> duckdb.DuckDBPyConnection:
        db_path = self._analytics_db_path(case_id)
        key = str(db_path)
        if key not in self._connections:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._connections[key] = duckdb.connect(str(db_path), config=_duckdb_connection_config(db_path))
        return self._connections[key]

    def _analytics_db_path(self, case_id: str) -> Path:
        row = self.sqlite_conn.execute("SELECT root FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown case_id for analytics storage: {case_id}")
        return Path(row["root"]) / "analytics" / "events.duckdb"

    @contextmanager
    def _write_connection(self, case_id: str):
        db_path = self._analytics_db_path(case_id)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._case_write_lock(db_path):
            conn = duckdb.connect(str(db_path), config=_duckdb_connection_config(db_path))
            try:
                yield conn
            finally:
                conn.close()

    @contextmanager
    def _case_write_lock(self, db_path: Path):
        if fcntl is None:  # pragma: no cover - Windows fallback
            yield
            return
        lock_path = db_path.with_suffix(db_path.suffix + ".write.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.write_lock_timeout_seconds
        with lock_path.open("w") as handle:
            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"Timed out waiting for DuckDB analytics write lock: {lock_path}"
                        )
                    time.sleep(0.25)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _ensure_table(self, conn: duckdb.DuckDBPyConnection, table: str, columns: list[str]) -> None:
        column_defs = ", ".join(f"{_quote_identifier(column)} {_duckdb_type(column)}" for column in columns)
        conn.execute(f"CREATE TABLE IF NOT EXISTS {_quote_identifier(table)} ({column_defs})")
        table_literal = table.replace("'", "''")
        existing = {
            str(row[1])
            for row in conn.execute(f"PRAGMA table_info('{table_literal}')").fetchall()
        }
        for column in columns:
            if column not in existing:
                conn.execute(
                    f"ALTER TABLE {_quote_identifier(table)} "
                    f"ADD COLUMN {_quote_identifier(column)} {_duckdb_type(column)}"
                )

    def _table_exists(self, conn: duckdb.DuckDBPyConnection, table: str) -> bool:
        return bool(
            conn.execute(
                "SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1",
                [table],
            ).fetchone()
        )

    def _tool_column(self, conn: duckdb.DuckDBPyConnection, table: str) -> str | None:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = ?",
            [table],
        ).fetchall()
        columns = {str(row[0]) for row in rows}
        if "tool_name" in columns:
            return "tool_name"
        if "source_tool" in columns:
            return "source_tool"
        return None


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _duckdb_type(column: str) -> str:
    if column in {"row_number", "source_row_number"}:
        return "BIGINT"
    return "VARCHAR"


def _normalize_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, default=str)
    return value


def _duckdb_connection_config(db_path: Path) -> dict[str, str]:
    temp_directory = os.environ.get("FORENSIC_DUCKDB_TEMP_DIRECTORY")
    if temp_directory:
        temp_path = Path(temp_directory).expanduser()
    else:
        temp_path = db_path.with_suffix(db_path.suffix + ".tmp")
    temp_path.mkdir(parents=True, exist_ok=True)
    config = {
        "temp_directory": str(temp_path),
        "max_temp_directory_size": _duckdb_memory_setting(
            os.environ.get("FORENSIC_DUCKDB_MAX_TEMP_DIRECTORY_SIZE", "80GB")
        ),
    }
    memory_limit = os.environ.get("FORENSIC_DUCKDB_MEMORY_LIMIT")
    if memory_limit:
        config["memory_limit"] = _duckdb_memory_setting(memory_limit)
    return config


def _duckdb_memory_setting(value: str) -> str:
    cleaned = str(value).strip()
    if not re.match(r"^\d+(?:\.\d+)?\s*(?:KB|MB|GB|TB|KiB|MiB|GiB|TiB)$", cleaned, re.IGNORECASE):
        raise ValueError(
            "DuckDB memory/temp settings must include a size unit, e.g. 16GB or 64GiB"
        )
    return cleaned.replace("'", "")
