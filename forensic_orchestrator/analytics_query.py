from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb

from .db import ANALYTICS_TABLES, Database


def query_rows(
    db: Database,
    table: str,
    sql: str,
    params: tuple[Any, ...] | list[Any] = (),
) -> list[dict[str, Any]]:
    if table in ANALYTICS_TABLES and db.analytics_mode != "sqlite":
        conn = _duckdb_connection(db, table)
        if conn is not None:
            result = conn.execute(sql, list(params))
            names = [column[0] for column in result.description or []]
            return [dict(zip(names, row, strict=False)) for row in result.fetchall()]
        if _sqlite_table_empty(db, table):
            return []
    rows = db.conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def query_one(
    db: Database,
    table: str,
    sql: str,
    params: tuple[Any, ...] | list[Any] = (),
) -> dict[str, Any] | None:
    rows = query_rows(db, table, sql, params)
    return rows[0] if rows else None


def table_columns(db: Database, table: str, case_id: str | None = None) -> set[str]:
    if table in ANALYTICS_TABLES and db.analytics_mode != "sqlite":
        conn = _duckdb_connection(db, table, case_id=case_id)
        if conn is None:
            return set()
        return {str(row[1]) for row in conn.execute(f"PRAGMA table_info('{_literal(table)}')").fetchall()}
    return {str(row["name"]) for row in db.conn.execute(f"PRAGMA table_info({table})").fetchall()}


def table_count(
    db: Database,
    table: str,
    *,
    case_id: str | None = None,
    where: str | None = None,
    params: tuple[Any, ...] | list[Any] = (),
) -> int:
    filters = []
    values: list[Any] = []
    if case_id is not None:
        filters.append("case_id = ?")
        values.append(case_id)
    if where:
        filters.append(where)
        values.extend(params)
    where_sql = f" WHERE {' AND '.join(filters)}" if filters else ""
    row = query_one(db, table, f"SELECT COUNT(*) AS count FROM {table}{where_sql}", values)
    return int((row or {}).get("count") or 0)


def _duckdb_connection(
    db: Database,
    table: str,
    *,
    case_id: str | None = None,
) -> duckdb.DuckDBPyConnection | None:
    analytics = getattr(db, "analytics", None)
    if analytics is not None and hasattr(analytics, "_connections"):
        saw_open_connection = False
        if case_id:
            try:
                conn = analytics._connect(case_id)
            except Exception:
                conn = None
            if conn is not None and _duckdb_table_exists(conn, table):
                return conn
            if conn is not None:
                saw_open_connection = True
        for conn in getattr(analytics, "_connections", {}).values():
            saw_open_connection = True
            if _duckdb_table_exists(conn, table):
                return conn
        if saw_open_connection:
            return None
    case_id = case_id or _first_case_id(db)
    if not case_id:
        return None
    case = db.get_case(case_id)
    db_path = Path(case.root) / "analytics" / "events.duckdb"
    if not db_path.exists():
        return None
    conn = duckdb.connect(str(db_path), read_only=True)
    if not _duckdb_table_exists(conn, table):
        conn.close()
        return None
    return conn


def _first_case_id(db: Database) -> str | None:
    row = db.conn.execute("SELECT id FROM cases ORDER BY id LIMIT 1").fetchone()
    return str(row["id"]) if row else None


def _duckdb_table_exists(conn: duckdb.DuckDBPyConnection, table: str) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1",
            [table],
        ).fetchone()
    )


def _sqlite_table_empty(db: Database, table: str) -> bool:
    exists = db.conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if not exists:
        return True
    try:
        row = db.conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
    except Exception:
        return True
    return row is None


def _literal(value: str) -> str:
    return value.replace("'", "''")
