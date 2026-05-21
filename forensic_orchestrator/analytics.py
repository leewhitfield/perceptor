from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd


ANALYTICS_TABLE_COLUMNS: dict[str, list[str]] = {
    "evtx_events": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
        "source_csv", "row_number", "record_number", "event_record_id", "time_created",
        "event_id", "level", "provider", "channel", "process_id", "thread_id", "computer",
        "user_id", "map_description", "user_name", "remote_host", "payload_data1",
        "payload_data2", "payload_data3", "executable_info", "source_file", "created_at",
    ],
    "timeline_events": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "source_tool",
        "source_table", "source_row_id", "event_type", "raw_timestamp", "timestamp_utc",
        "description", "created_at",
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
    "file_internal_metadata": [
        "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
        "source_csv", "row_number", "source_file", "original_path", "file_name",
        "extension", "parser", "metadata_group", "property_name", "raw_property_name",
        "file_size", "mft_created", "mft_modified", "mft_accessed",
        "mft_record_modified", "mft_in_use", "path_unresolved", "deleted_mft_entry",
        "live_orphan", "extraction_method", "created_at",
    ],
}


class AnalyticsStore:
    def __init__(self, sqlite_conn: sqlite3.Connection) -> None:
        self.sqlite_conn = sqlite_conn
        self._connections: dict[str, duckdb.DuckDBPyConnection] = {}

    def close(self) -> None:
        for conn in self._connections.values():
            conn.close()
        self._connections.clear()

    def insert_rows(self, table: str, columns: list[str], rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        for case_id, case_rows in self._group_by_case(rows).items():
            conn = self._connect(case_id)
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
        conn = self._connect(case_id)
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
            self._connections[key] = duckdb.connect(str(db_path))
        return self._connections[key]

    def _analytics_db_path(self, case_id: str) -> Path:
        row = self.sqlite_conn.execute("SELECT root FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown case_id for analytics storage: {case_id}")
        return Path(row["root"]) / "analytics" / "events.duckdb"

    def _ensure_table(self, conn: duckdb.DuckDBPyConnection, table: str, columns: list[str]) -> None:
        column_defs = ", ".join(f"{_quote_identifier(column)} {_duckdb_type(column)}" for column in columns)
        conn.execute(f"CREATE TABLE IF NOT EXISTS {_quote_identifier(table)} ({column_defs})")

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
