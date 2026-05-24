from __future__ import annotations

import json
import uuid
from typing import Any

from forensic_orchestrator.db import Database, utc_now


def rebuild_timeline_windows_old_dedupe(
    db: Database,
    *,
    case_id: str,
    image_id: str | None = None,
    max_windows_old_output_rows: int = 100_000,
) -> dict[str, int]:
    """Mark duplicate timeline rows, preferring current OS rows over Windows.old rows."""
    if getattr(db, "analytics_only", False) and getattr(db, "analytics", None) is not None:
        return _rebuild_timeline_windows_old_dedupe_duckdb(
            db,
            case_id=case_id,
            image_id=image_id,
            max_windows_old_output_rows=max_windows_old_output_rows,
        )

    where = ["timeline_events.case_id = ?"]
    params: list[Any] = [case_id]
    if image_id:
        where.append("timeline_events.image_id = ?")
        params.append(image_id)
    clause = " AND ".join(where)
    update_clause = clause.replace("timeline_events.", "")

    if image_id:
        db.conn.execute(
            "DELETE FROM timeline_event_sources WHERE case_id = ? AND image_id = ?",
            (case_id, image_id),
        )
    else:
        db.conn.execute("DELETE FROM timeline_event_sources WHERE case_id = ?", (case_id,))

    db.conn.execute(
        f"""
        UPDATE timeline_events
        SET is_windows_old = 0,
            dedupe_key = NULL,
            dedupe_status = 'primary',
            primary_event_id = NULL
        WHERE {update_clause}
          AND (
            is_windows_old != 0
            OR dedupe_key IS NOT NULL
            OR dedupe_status != 'primary'
            OR primary_event_id IS NOT NULL
          )
        """,
        params,
    )
    db.conn.execute("DROP TABLE IF EXISTS temp.timeline_dedupe_old_outputs")
    db.conn.execute("DROP TABLE IF EXISTS temp.timeline_dedupe_current_outputs")
    db.conn.execute("CREATE TEMP TABLE timeline_dedupe_old_outputs (id TEXT PRIMARY KEY)")
    db.conn.execute("CREATE TEMP TABLE timeline_dedupe_current_outputs (id TEXT PRIMARY KEY)")
    output_where = ["case_id = ?"]
    output_params: list[Any] = [case_id]
    if image_id:
        output_where.append("image_id = ?")
        output_params.append(image_id)
    output_clause = " AND ".join(output_where)
    db.conn.execute(
        f"""
        INSERT INTO timeline_dedupe_old_outputs (id)
        SELECT id
        FROM tool_outputs
        WHERE {output_clause}
          AND LOWER(path) LIKE '%windows.old%'
          AND COALESCE(row_count, 0) <= ?
        """,
        [*output_params, max_windows_old_output_rows],
    )
    db.conn.execute(
        f"""
        INSERT INTO timeline_dedupe_current_outputs (id)
        SELECT id
        FROM tool_outputs
        WHERE {output_clause}
          AND LOWER(path) NOT LIKE '%windows.old%'
        """,
        output_params,
    )
    total = int(
        db.conn.execute(f"SELECT COUNT(*) FROM timeline_events WHERE {clause}", params).fetchone()[0]
    )
    windows_old = int(
        db.conn.execute(
            f"""
            SELECT COUNT(*)
            FROM timeline_events
            WHERE {clause}
              AND tool_output_id IN (SELECT id FROM timeline_dedupe_old_outputs)
            """,
            params,
        ).fetchone()[0]
    )
    eligible_windows_old = int(
        db.conn.execute(
            f"""
            SELECT COUNT(*)
            FROM timeline_events
            WHERE {clause}
              AND tool_output_id IN (SELECT id FROM timeline_dedupe_old_outputs)
            """,
            params,
        ).fetchone()[0]
    )

    db.conn.execute("DROP TABLE IF EXISTS temp.timeline_dedupe_matches")
    db.conn.execute(
        f"""
        CREATE TEMP TABLE timeline_dedupe_matches AS
        SELECT MIN(current_event.id) AS primary_event_id,
               old_event.id AS duplicate_event_id
        FROM timeline_events AS old_event
        JOIN timeline_events AS current_event
          ON current_event.case_id = old_event.case_id
         AND current_event.source_tool = old_event.source_tool
         AND current_event.source_table = old_event.source_table
         AND current_event.event_type = old_event.event_type
         AND current_event.timestamp_utc = old_event.timestamp_utc
         AND COALESCE(current_event.description, '') = COALESCE(old_event.description, '')
         AND COALESCE(current_event.details_json, '') = COALESCE(old_event.details_json, '')
        WHERE old_event.case_id = ?
          AND old_event.tool_output_id IN (SELECT id FROM timeline_dedupe_old_outputs)
          AND current_event.tool_output_id IN (SELECT id FROM timeline_dedupe_current_outputs)
          {"AND old_event.image_id = ?" if image_id else ""}
        GROUP BY old_event.id
        """,
        [case_id, image_id] if image_id else [case_id],
    )
    db.conn.execute("CREATE INDEX IF NOT EXISTS temp.idx_timeline_dedupe_matches_primary ON timeline_dedupe_matches(primary_event_id)")
    db.conn.execute("CREATE INDEX IF NOT EXISTS temp.idx_timeline_dedupe_matches_duplicate ON timeline_dedupe_matches(duplicate_event_id)")
    duplicate_groups = int(db.conn.execute("SELECT COUNT(DISTINCT primary_event_id) FROM timeline_dedupe_matches").fetchone()[0])
    duplicate_count = int(db.conn.execute("SELECT COUNT(*) FROM timeline_dedupe_matches").fetchone()[0])
    created_at = utc_now()
    db.conn.execute(
        """
        UPDATE timeline_events
        SET dedupe_status = 'duplicate',
            primary_event_id = (
              SELECT primary_event_id
              FROM timeline_dedupe_matches
              WHERE duplicate_event_id = timeline_events.id
            ),
            is_windows_old = 1,
            dedupe_key = 'timeline:' || (
              SELECT primary_event_id
              FROM timeline_dedupe_matches
              WHERE duplicate_event_id = timeline_events.id
            )
        WHERE id IN (SELECT duplicate_event_id FROM timeline_dedupe_matches)
        """
    )
    db.conn.execute(
        """
        UPDATE timeline_events
        SET dedupe_key = 'timeline:' || id
        WHERE id IN (SELECT primary_event_id FROM timeline_dedupe_matches)
        """
    )
    db.conn.execute(
        """
        INSERT INTO timeline_event_sources (
          id, case_id, computer_id, image_id, primary_event_id, duplicate_event_id,
          source_scope, source_tool, source_table, source_row_id, tool_output_id,
          tool_output_path, details_json, created_at
        )
        SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(6))) AS id,
               primary_event.case_id,
               primary_event.computer_id,
               primary_event.image_id,
               primary_event.id,
               primary_event.id,
               'current',
               primary_event.source_tool,
               primary_event.source_table,
               primary_event.source_row_id,
               primary_event.tool_output_id,
               tool_outputs.path,
               json_object(
                 'dedupe_key', 'timeline:' || primary_event.id,
                 'description', primary_event.description,
                 'event_type', primary_event.event_type,
                 'timestamp_utc', primary_event.timestamp_utc,
                 'dedupe_preference', 'current_os_preferred'
               ),
               ?
        FROM timeline_events AS primary_event
        JOIN tool_outputs ON tool_outputs.id = primary_event.tool_output_id
        WHERE primary_event.id IN (SELECT DISTINCT primary_event_id FROM timeline_dedupe_matches)
        """,
        (created_at,),
    )
    db.conn.execute(
        """
        INSERT INTO timeline_event_sources (
          id, case_id, computer_id, image_id, primary_event_id, duplicate_event_id,
          source_scope, source_tool, source_table, source_row_id, tool_output_id,
          tool_output_path, details_json, created_at
        )
        SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(6))) AS id,
               old_event.case_id,
               old_event.computer_id,
               old_event.image_id,
               matches.primary_event_id,
               old_event.id,
               'windows_old',
               old_event.source_tool,
               old_event.source_table,
               old_event.source_row_id,
               old_event.tool_output_id,
               tool_outputs.path,
               json_object(
                 'dedupe_key', 'timeline:' || matches.primary_event_id,
                 'description', old_event.description,
                 'event_type', old_event.event_type,
                 'timestamp_utc', old_event.timestamp_utc,
                 'dedupe_preference', 'current_os_preferred'
               ),
               ?
        FROM timeline_dedupe_matches AS matches
        JOIN timeline_events AS old_event ON old_event.id = matches.duplicate_event_id
        JOIN tool_outputs ON tool_outputs.id = old_event.tool_output_id
        """,
        (created_at,),
    )

    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        event="timeline.windows_old_dedupe_rebuilt",
        message=f"Rebuilt Windows.old timeline dedupe: {duplicate_count} duplicate rows mapped",
        details={
            "timeline_rows": total,
            "windows_old_rows": windows_old,
            "eligible_windows_old_rows": eligible_windows_old,
            "skipped_windows_old_rows": max(windows_old - eligible_windows_old, 0),
            "max_windows_old_output_rows": max_windows_old_output_rows,
            "duplicate_groups": duplicate_groups,
            "duplicate_rows": duplicate_count,
        },
    )
    db.conn.commit()
    return {
        "timeline_rows": total,
        "windows_old_rows": windows_old,
        "eligible_windows_old_rows": eligible_windows_old,
        "skipped_windows_old_rows": max(windows_old - eligible_windows_old, 0),
        "max_windows_old_output_rows": max_windows_old_output_rows,
        "duplicate_groups": duplicate_groups,
        "duplicate_rows": duplicate_count,
    }


def _rebuild_timeline_windows_old_dedupe_duckdb(
    db: Database,
    *,
    case_id: str,
    image_id: str | None,
    max_windows_old_output_rows: int,
) -> dict[str, int]:
    conn = db.analytics._connect(case_id)
    if image_id:
        db.conn.execute(
            "DELETE FROM timeline_event_sources WHERE case_id = ? AND image_id = ?",
            (case_id, image_id),
        )
    else:
        db.conn.execute("DELETE FROM timeline_event_sources WHERE case_id = ?", (case_id,))

    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id:
        where.append("image_id = ?")
        params.append(image_id)
    clause = " AND ".join(where)

    conn.execute(
        f"""
        UPDATE timeline_events
        SET is_windows_old = '0',
            dedupe_key = NULL,
            dedupe_status = 'primary',
            primary_event_id = NULL
        WHERE {clause}
        """,
        params,
    )

    output_where = ["case_id = ?"]
    output_params: list[Any] = [case_id]
    if image_id:
        output_where.append("image_id = ?")
        output_params.append(image_id)
    output_clause = " AND ".join(output_where)
    old_outputs = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT id, path
            FROM tool_outputs
            WHERE {output_clause}
              AND LOWER(path) LIKE '%windows.old%'
              AND COALESCE(row_count, 0) <= ?
            """,
            [*output_params, max_windows_old_output_rows],
        ).fetchall()
    ]
    current_outputs = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT id, path
            FROM tool_outputs
            WHERE {output_clause}
              AND LOWER(path) NOT LIKE '%windows.old%'
            """,
            output_params,
        ).fetchall()
    ]
    output_paths = {str(row["id"]): str(row["path"]) for row in old_outputs + current_outputs}

    conn.execute("DROP TABLE IF EXISTS timeline_dedupe_old_outputs")
    conn.execute("DROP TABLE IF EXISTS timeline_dedupe_current_outputs")
    conn.execute("CREATE TEMP TABLE timeline_dedupe_old_outputs (id VARCHAR)")
    conn.execute("CREATE TEMP TABLE timeline_dedupe_current_outputs (id VARCHAR)")
    if old_outputs:
        conn.executemany("INSERT INTO timeline_dedupe_old_outputs VALUES (?)", [(row["id"],) for row in old_outputs])
    if current_outputs:
        conn.executemany("INSERT INTO timeline_dedupe_current_outputs VALUES (?)", [(row["id"],) for row in current_outputs])

    total = int(conn.execute(f"SELECT COUNT(*) FROM timeline_events WHERE {clause}", params).fetchone()[0])
    windows_old = int(
        conn.execute(
            f"""
            SELECT COUNT(*)
            FROM timeline_events
            WHERE {clause}
              AND tool_output_id IN (SELECT id FROM timeline_dedupe_old_outputs)
            """,
            params,
        ).fetchone()[0]
    )
    eligible_windows_old = windows_old

    conn.execute("DROP TABLE IF EXISTS timeline_dedupe_matches")
    conn.execute(
        f"""
        CREATE TEMP TABLE timeline_dedupe_matches AS
        SELECT MIN(current_event.id) AS primary_event_id,
               old_event.id AS duplicate_event_id
        FROM timeline_events AS old_event
        JOIN timeline_events AS current_event
          ON current_event.case_id = old_event.case_id
         AND current_event.source_tool = old_event.source_tool
         AND current_event.source_table = old_event.source_table
         AND current_event.event_type = old_event.event_type
         AND current_event.timestamp_utc = old_event.timestamp_utc
         AND COALESCE(current_event.description, '') = COALESCE(old_event.description, '')
         AND COALESCE(current_event.details_json, '') = COALESCE(old_event.details_json, '')
        WHERE old_event.case_id = ?
          AND old_event.tool_output_id IN (SELECT id FROM timeline_dedupe_old_outputs)
          AND current_event.tool_output_id IN (SELECT id FROM timeline_dedupe_current_outputs)
          {"AND old_event.image_id = ?" if image_id else ""}
        GROUP BY old_event.id
        """,
        [case_id, image_id] if image_id else [case_id],
    )
    duplicate_groups = int(conn.execute("SELECT COUNT(DISTINCT primary_event_id) FROM timeline_dedupe_matches").fetchone()[0])
    duplicate_count = int(conn.execute("SELECT COUNT(*) FROM timeline_dedupe_matches").fetchone()[0])
    created_at = utc_now()

    conn.execute(
        """
        UPDATE timeline_events
        SET dedupe_status = 'duplicate',
            primary_event_id = (
              SELECT primary_event_id
              FROM timeline_dedupe_matches
              WHERE duplicate_event_id = timeline_events.id
            ),
            is_windows_old = '1',
            dedupe_key = 'timeline:' || (
              SELECT primary_event_id
              FROM timeline_dedupe_matches
              WHERE duplicate_event_id = timeline_events.id
            )
        WHERE id IN (SELECT duplicate_event_id FROM timeline_dedupe_matches)
        """
    )
    conn.execute(
        """
        UPDATE timeline_events
        SET dedupe_key = 'timeline:' || id
        WHERE id IN (SELECT primary_event_id FROM timeline_dedupe_matches)
        """
    )

    source_rows = conn.execute(
        """
        SELECT primary_event.case_id, primary_event.computer_id, primary_event.image_id,
               primary_event.id AS primary_event_id, primary_event.id AS duplicate_event_id,
               'current' AS source_scope, primary_event.source_tool, primary_event.source_table,
               primary_event.source_row_id, primary_event.tool_output_id,
               primary_event.description, primary_event.event_type, primary_event.timestamp_utc
        FROM timeline_events AS primary_event
        WHERE primary_event.id IN (SELECT DISTINCT primary_event_id FROM timeline_dedupe_matches)
        UNION ALL
        SELECT old_event.case_id, old_event.computer_id, old_event.image_id,
               matches.primary_event_id, old_event.id AS duplicate_event_id,
               'windows_old' AS source_scope, old_event.source_tool, old_event.source_table,
               old_event.source_row_id, old_event.tool_output_id,
               old_event.description, old_event.event_type, old_event.timestamp_utc
        FROM timeline_dedupe_matches AS matches
        JOIN timeline_events AS old_event ON old_event.id = matches.duplicate_event_id
        """
    ).fetchall()
    if source_rows:
        db.conn.executemany(
            """
            INSERT INTO timeline_event_sources (
              id, case_id, computer_id, image_id, primary_event_id, duplicate_event_id,
              source_scope, source_tool, source_table, source_row_id, tool_output_id,
              tool_output_path, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    str(uuid.uuid4()),
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                    row[6],
                    row[7],
                    row[8],
                    row[9],
                    output_paths.get(str(row[9]), ""),
                    json.dumps(
                        {
                            "dedupe_key": f"timeline:{row[3]}",
                            "description": row[10],
                            "event_type": row[11],
                            "timestamp_utc": row[12],
                            "dedupe_preference": "current_os_preferred",
                        },
                        default=str,
                    ),
                    created_at,
                )
                for row in source_rows
            ],
        )

    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        event="timeline.windows_old_dedupe_rebuilt",
        message=f"Rebuilt Windows.old timeline dedupe: {duplicate_count} duplicate rows mapped",
        details={
            "timeline_rows": total,
            "windows_old_rows": windows_old,
            "eligible_windows_old_rows": eligible_windows_old,
            "skipped_windows_old_rows": max(windows_old - eligible_windows_old, 0),
            "max_windows_old_output_rows": max_windows_old_output_rows,
            "duplicate_groups": duplicate_groups,
            "duplicate_rows": duplicate_count,
        },
    )
    db.conn.commit()
    return {
        "timeline_rows": total,
        "windows_old_rows": windows_old,
        "eligible_windows_old_rows": eligible_windows_old,
        "skipped_windows_old_rows": max(windows_old - eligible_windows_old, 0),
        "max_windows_old_output_rows": max_windows_old_output_rows,
        "duplicate_groups": duplicate_groups,
        "duplicate_rows": duplicate_count,
    }
