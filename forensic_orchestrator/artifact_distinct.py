from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from forensic_orchestrator.artifact_dedupe import SPECS as WINDOWS_OLD_SPECS
from forensic_orchestrator.db import Database, utc_now


@dataclass(frozen=True)
class DistinctSpec:
    family: str
    table: str
    columns: tuple[str, ...]


EXTRA_SPECS: tuple[DistinctSpec, ...] = (
    DistinctSpec(
        "mft_entries",
        "mft_entries",
        (
            "entry_number",
            "sequence_number",
            "parent_path",
            "file_name",
        ),
    ),
    DistinctSpec(
        "evtx_events",
        "evtx_events",
        (
            "event_record_id",
            "time_created",
            "event_id",
            "level",
            "provider",
            "channel",
            "computer",
            "user_id",
            "payload_data1",
            "payload_data2",
            "payload_data3",
            "payload_data4",
            "payload_data5",
            "payload_data6",
            "payload",
        ),
    ),
    DistinctSpec(
        "shortcuts",
        "shortcut_items",
        (
            "tool_name",
            "artifact_path",
            "file_location",
            "target_modified",
        ),
    ),
    DistinctSpec(
        "execution_prefetch",
        "prefetch_items",
        ("prefetch_name", "prefetch_hash", "executable_name", "last_run_time_utc"),
    ),
    DistinctSpec(
        "shimcache",
        "shimcache_entries",
        ("path", "last_modified_utc", "executed"),
    ),
    DistinctSpec(
        "shellbags",
        "shellbag_entries",
        ("hive_path", "absolute_path", "last_write_time"),
    ),
    DistinctSpec(
        "usb_devices",
        "usb_devices",
        (
            "artifact",
            "device_type",
            "vendor_id",
            "product_id",
            "vendor",
            "product",
            "revision",
            "friendly_name",
            "serial",
            "instance_id",
            "parent_id_prefix",
            "device_service",
            "user_profile",
            "drive_letter",
            "volume_guid",
            "volume_serial_number",
            "volume_name",
            "capacity_bytes",
            "alternate_scsi_serial",
            "key_last_write_utc",
            "last_present_date_utc",
            "property_name",
            "property_value",
        ),
    ),
    DistinctSpec(
        "recycle_items",
        "recycle_items",
        (
            "original_path",
            "deletion_time_utc",
            "file_size",
        ),
    ),
)


def _non_overlapping_windows_old_specs() -> list[DistinctSpec]:
    extra_tables = {spec.table for spec in EXTRA_SPECS}
    return [
        DistinctSpec(spec.family, spec.table, spec.columns)
        for spec in WINDOWS_OLD_SPECS
        if spec.table not in extra_tables
    ]


DISTINCT_SPECS: tuple[DistinctSpec, ...] = tuple([*EXTRA_SPECS, *_non_overlapping_windows_old_specs()])


def rebuild_distinct_artifact_tables(db: Database, *, case_id: str, image_id: str | None = None) -> dict[str, Any]:
    db.get_case(case_id)
    if getattr(db, "analytics_only", False) and getattr(db, "analytics", None) is not None:
        return _rebuild_duckdb(db, case_id=case_id, image_id=image_id)
    return _rebuild_sqlite(db, case_id=case_id, image_id=image_id)


def _rebuild_duckdb(db: Database, *, case_id: str, image_id: str | None) -> dict[str, Any]:
    analytics = getattr(db, "analytics", None)
    if analytics is None:
        return {"case_id": case_id, "image_id": image_id, "tables": {}, "distinct_rows": 0, "source_rows": 0}
    stats: dict[str, dict[str, int]] = {}
    with analytics._write_connection(case_id) as conn:
        for spec in DISTINCT_SPECS:
            if not _duckdb_table_exists(conn, spec.table):
                continue
            columns = _duckdb_columns(conn, spec.table)
            key_columns = [column for column in spec.columns if column in columns]
            if not key_columns:
                continue
            distinct_table = f"distinct_{spec.table}"
            conn.execute(f"DROP TABLE IF EXISTS {_quote(distinct_table)}")
            where = ["case_id = ?"]
            params: list[Any] = [case_id]
            if image_id is not None and "image_id" in columns:
                where.append("image_id = ?")
                params.append(image_id)
            where_sql = " AND ".join(where)
            key_sql = _duckdb_key_sql(key_columns)
            order_sql = _duckdb_primary_order(columns)
            source_csv_sql = _duckdb_source_list_sql("source_csv", columns)
            output_id_sql = _duckdb_source_list_sql("tool_output_id", columns)
            source_row_sql = _duckdb_source_list_sql("id", columns)
            conn.execute(
                f"""
                CREATE TABLE {_quote(distinct_table)} AS
                WITH keyed AS (
                  SELECT *,
                         md5({key_sql}) AS distinct_dedupe_key
                  FROM {_quote(spec.table)}
                  WHERE {where_sql}
                ),
                grouped AS (
                  SELECT distinct_dedupe_key,
                         COUNT(*) AS distinct_source_count,
                         {source_csv_sql} AS distinct_source_csvs_json,
                         {source_row_sql} AS distinct_source_row_ids_json,
                         {output_id_sql} AS distinct_tool_output_ids_json
                  FROM keyed
                  GROUP BY distinct_dedupe_key
                ),
                ranked AS (
                  SELECT *,
                         ROW_NUMBER() OVER (
                           PARTITION BY distinct_dedupe_key
                           ORDER BY {order_sql}
                         ) AS distinct_primary_rank
                  FROM keyed
                )
                SELECT ranked.* EXCLUDE (distinct_primary_rank),
                       grouped.distinct_source_count,
                       grouped.distinct_source_csvs_json,
                       grouped.distinct_source_row_ids_json,
                       grouped.distinct_tool_output_ids_json
                FROM ranked
                JOIN grouped USING (distinct_dedupe_key)
                WHERE ranked.distinct_primary_rank = 1
                """,
                params,
            )
            source_rows = int(conn.execute("SELECT COUNT(*) FROM keyed").fetchone()[0]) if False else int(
                conn.execute(f"SELECT COUNT(*) FROM {_quote(spec.table)} WHERE {where_sql}", params).fetchone()[0]
            )
            distinct_rows = int(conn.execute(f"SELECT COUNT(*) FROM {_quote(distinct_table)}").fetchone()[0])
            stats[spec.table] = {"source_rows": source_rows, "distinct_rows": distinct_rows, "duplicate_rows": max(0, source_rows - distinct_rows)}
    _log_rebuild(db, case_id=case_id, image_id=image_id, stats=stats)
    return _result(case_id, image_id, stats)


def _rebuild_sqlite(db: Database, *, case_id: str, image_id: str | None) -> dict[str, Any]:
    stats: dict[str, dict[str, int]] = {}
    for spec in DISTINCT_SPECS:
        if not _sqlite_table_exists(db, spec.table):
            continue
        columns = _sqlite_columns(db, spec.table)
        key_columns = [column for column in spec.columns if column in columns]
        if not key_columns:
            continue
        distinct_table = f"distinct_{spec.table}"
        db.conn.execute(f"DROP TABLE IF EXISTS {distinct_table}")
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None and "image_id" in columns:
            where.append("image_id = ?")
            params.append(image_id)
        where_sql = " AND ".join(where)
        key_sql = _sqlite_key_sql(key_columns)
        order_sql = _sqlite_primary_order(columns)
        source_csv_sql = _sqlite_source_list_sql("source_csv", columns)
        output_id_sql = _sqlite_source_list_sql("tool_output_id", columns)
        source_row_sql = _sqlite_source_list_sql("id", columns)
        db.conn.execute(
            f"""
            CREATE TABLE {distinct_table} AS
            WITH keyed AS (
              SELECT *,
                     {key_sql} AS distinct_dedupe_key
              FROM {spec.table}
              WHERE {where_sql}
            ),
            grouped AS (
              SELECT distinct_dedupe_key,
                     COUNT(*) AS distinct_source_count,
                     {source_csv_sql} AS distinct_source_csvs_json,
                     {source_row_sql} AS distinct_source_row_ids_json,
                     {output_id_sql} AS distinct_tool_output_ids_json
              FROM keyed
              GROUP BY distinct_dedupe_key
            ),
            ranked AS (
              SELECT *,
                     ROW_NUMBER() OVER (
                       PARTITION BY distinct_dedupe_key
                       ORDER BY {order_sql}
                     ) AS distinct_primary_rank
              FROM keyed
            )
            SELECT ranked.*,
                   grouped.distinct_source_count,
                   grouped.distinct_source_csvs_json,
                   grouped.distinct_source_row_ids_json,
                   grouped.distinct_tool_output_ids_json
            FROM ranked
            JOIN grouped USING (distinct_dedupe_key)
            WHERE ranked.distinct_primary_rank = 1
            """,
            params,
        )
        source_rows = int(db.conn.execute(f"SELECT COUNT(*) FROM {spec.table} WHERE {where_sql}", params).fetchone()[0])
        distinct_rows = int(db.conn.execute(f"SELECT COUNT(*) FROM {distinct_table}").fetchone()[0])
        stats[spec.table] = {"source_rows": source_rows, "distinct_rows": distinct_rows, "duplicate_rows": max(0, source_rows - distinct_rows)}
    db.conn.commit()
    _log_rebuild(db, case_id=case_id, image_id=image_id, stats=stats)
    return _result(case_id, image_id, stats)


def _result(case_id: str, image_id: str | None, stats: dict[str, dict[str, int]]) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "image_id": image_id,
        "tables": stats,
        "source_rows": sum(item["source_rows"] for item in stats.values()),
        "distinct_rows": sum(item["distinct_rows"] for item in stats.values()),
        "duplicate_rows": sum(item["duplicate_rows"] for item in stats.values()),
    }


def _log_rebuild(db: Database, *, case_id: str, image_id: str | None, stats: dict[str, dict[str, int]]) -> None:
    result = _result(case_id, image_id, stats)
    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        event="artifact.distinct_tables_rebuilt",
        message=f"Rebuilt distinct artifact tables: {result['duplicate_rows']} duplicate rows collapsed",
        details=result,
    )


def _duckdb_key_sql(columns: list[str]) -> str:
    return " || '|' || ".join(f"LOWER(TRIM(COALESCE(CAST({_quote(column)} AS VARCHAR), '')))" for column in columns)


def _sqlite_key_sql(columns: list[str]) -> str:
    return " || '|' || ".join(f"LOWER(TRIM(COALESCE(CAST({column} AS TEXT), '')))" for column in columns)


def _duckdb_primary_order(columns: list[str]) -> str:
    parts = []
    if "source_csv" in columns:
        parts.extend(
            [
                "CASE WHEN LOWER(COALESCE(CAST(source_csv AS VARCHAR), '')) LIKE '%shadowcopy%' THEN 1 ELSE 0 END",
                "CASE WHEN LOWER(COALESCE(CAST(source_csv AS VARCHAR), '')) LIKE '%.winreg%' THEN 1 ELSE 0 END",
                "CAST(source_csv AS VARCHAR)",
            ]
        )
    if "row_number" in columns:
        parts.append("TRY_CAST(row_number AS BIGINT)")
    if "id" in columns:
        parts.append("id")
    return ", ".join(parts) if parts else "distinct_dedupe_key"


def _sqlite_primary_order(columns: list[str]) -> str:
    parts = []
    if "source_csv" in columns:
        parts.extend(
            [
                "CASE WHEN LOWER(COALESCE(CAST(source_csv AS TEXT), '')) LIKE '%shadowcopy%' THEN 1 ELSE 0 END",
                "CASE WHEN LOWER(COALESCE(CAST(source_csv AS TEXT), '')) LIKE '%.winreg%' THEN 1 ELSE 0 END",
                "CAST(source_csv AS TEXT)",
            ]
        )
    if "row_number" in columns:
        parts.append("CAST(row_number AS INTEGER)")
    if "id" in columns:
        parts.append("id")
    return ", ".join(parts) if parts else "distinct_dedupe_key"


def _duckdb_source_list_sql(column: str, columns: list[str]) -> str:
    if column not in columns:
        return "'[]'"
    return f"to_json(list_sort(list_distinct(list(COALESCE(CAST({_quote(column)} AS VARCHAR), '')))))"


def _sqlite_source_list_sql(column: str, columns: list[str]) -> str:
    if column not in columns:
        return "'[]'"
    return f"json_group_array(DISTINCT COALESCE(CAST({column} AS TEXT), ''))"


def _duckdb_table_exists(conn: Any, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1", [table]).fetchone())


def _sqlite_table_exists(db: Database, table: str) -> bool:
    return db.conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone() is not None


def _duckdb_columns(conn: Any, table: str) -> list[str]:
    table_literal = table.replace("'", "''")
    return [str(row[1]) for row in conn.execute(f"PRAGMA table_info('{table_literal}')").fetchall()]


def _sqlite_columns(db: Database, table: str) -> list[str]:
    return [str(row["name"]) for row in db.conn.execute(f"PRAGMA table_info({table})").fetchall()]


def _quote(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'
