from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from forensic_orchestrator.db import Database, utc_now


@dataclass(frozen=True)
class DedupeSpec:
    family: str
    table: str
    columns: tuple[str, ...]
    path_columns: tuple[str, ...] = ()


SPECS: tuple[DedupeSpec, ...] = (
    DedupeSpec("browser_history", "browser_history", ("browser", "profile_path", "url", "title", "visit_time_utc")),
    DedupeSpec("browser_downloads", "browser_downloads", ("browser", "profile_path", "target_path", "tab_url", "site_url", "start_time_utc", "end_time_utc")),
    DedupeSpec("browser_artifacts", "browser_artifacts", ("browser", "artifact_type", "profile_path", "name", "value", "url", "title", "timestamp_utc")),
    DedupeSpec("browser_sessions", "browser_session_entries", ("browser", "profile_path", "session_type", "url", "title", "timestamp_utc", "last_active_time_utc")),
    DedupeSpec("browser_site_settings", "browser_site_settings", ("browser", "profile_path", "setting_type", "origin", "setting_name", "setting_value", "last_modified_utc")),
    DedupeSpec("browser_notifications", "browser_notifications", ("browser", "profile_path", "origin", "notification_id", "title", "created_utc", "notification_timestamp_utc")),
    DedupeSpec("webcache", "webcache_entries", ("user_name", "application", "source_table", "entry_id", "url", "accessed_utc", "modified_utc")),
    DedupeSpec("webcache_files", "webcache_file_accesses", ("user_name", "application", "url", "normalized_path", "accessed_utc", "modified_utc")),
    DedupeSpec("execution_prefetch", "prefetch_items", ("executable_name", "prefetch_hash", "last_run_time_utc", "run_count")),
    DedupeSpec("registry_artifacts", "registry_artifacts", ("hive_type", "user_profile", "user_sid", "artifact", "category", "key_path", "value_name", "value_data", "event_time_utc", "key_last_write_utc")),
    DedupeSpec("registry_recentdocs", "registry_recentdocs", ("user_profile", "category", "key_path", "extension", "value_name", "target_name", "mru_position", "opened_on", "extension_last_opened")),
    DedupeSpec("registry_runmru", "registry_runmru", ("user_profile", "key_path", "value_name", "mru_position", "executable", "opened_on")),
    DedupeSpec("registry_typedpaths", "registry_typedpaths", ("user_profile", "key_path", "value_name", "mru_position", "path", "opened_on")),
    DedupeSpec("registry_wordwheel", "registry_wordwheel_query", ("user_profile", "key_path", "search_term", "mru_position", "last_write_timestamp")),
    DedupeSpec("registry_userassist", "registry_userassist", ("user_profile", "key_path", "program_name", "run_counter", "last_executed")),
    DedupeSpec("registry_office_mru", "registry_office_mru", ("user_profile", "key_path", "value_name", "file_name", "last_opened", "last_closed")),
    DedupeSpec("registry_common_dialog", "registry_common_dialog_mru", ("user_profile", "key_path", "artifact", "extension", "value_name", "executable", "absolute_path", "opened_on")),
    DedupeSpec("registry_trusted_documents", "registry_trusted_documents", ("user_profile", "key_path", "event_type", "file_name", "timestamp")),
    DedupeSpec("shellbags", "shellbag_entries", ("user_profile", "absolute_path", "created_on", "modified_on", "accessed_on", "last_write_time", "first_interacted", "last_interacted")),
    DedupeSpec("windows_search_files", "windows_search_files", ("work_id", "item_path", "item_url", "file_name", "gather_time", "date_modified")),
    DedupeSpec("windows_search_internet", "windows_search_internet_history", ("work_id", "item_url", "target_url", "title", "gather_time")),
    DedupeSpec("windows_search_activity", "windows_search_activity_history", ("work_id", "item_url", "content_uri", "app_display_name", "display_text", "start_time", "end_time")),
    DedupeSpec("file_metadata", "file_internal_metadata", ("original_path", "metadata_group", "property_name", "property_value"), path_columns=("original_path",)),
)


def rebuild_artifact_windows_old_dedupe(db: Database, *, case_id: str, image_id: str | None = None) -> dict[str, Any]:
    db.get_case(case_id)
    params: list[Any] = [case_id]
    where = ["case_id = ?"]
    if image_id:
        where.append("image_id = ?")
        params.append(image_id)
    clause = " AND ".join(where)
    db.conn.execute(f"DELETE FROM artifact_record_sources WHERE {clause}", params)
    _create_output_scope_tables(db, case_id=case_id, image_id=image_id)
    stats: dict[str, int] = {}
    total_duplicates = 0
    for spec in SPECS:
        if not _table_exists(db, spec.table):
            continue
        count = _dedupe_tool_output_table(db, spec, case_id=case_id, image_id=image_id)
        stats[spec.family] = count
        total_duplicates += count
    if _table_exists(db, "filesystem_review"):
        count = _dedupe_filesystem_review(db, case_id=case_id, image_id=image_id)
        stats["filesystem_review"] = count
        total_duplicates += count
    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        event="artifact.windows_old_dedupe_rebuilt",
        message=f"Rebuilt Windows.old artifact dedupe: {total_duplicates} duplicate rows mapped",
        details={"image_id": image_id, "duplicates": total_duplicates, "families": stats},
    )
    db.conn.commit()
    return {"case_id": case_id, "image_id": image_id, "duplicate_rows": total_duplicates, "families": stats}


def _create_output_scope_tables(db: Database, *, case_id: str, image_id: str | None) -> None:
    db.conn.execute("DROP TABLE IF EXISTS temp.artifact_dedupe_old_outputs")
    db.conn.execute("DROP TABLE IF EXISTS temp.artifact_dedupe_current_outputs")
    db.conn.execute("CREATE TEMP TABLE artifact_dedupe_old_outputs (id TEXT PRIMARY KEY)")
    db.conn.execute("CREATE TEMP TABLE artifact_dedupe_current_outputs (id TEXT PRIMARY KEY)")
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id:
        where.append("image_id = ?")
        params.append(image_id)
    clause = " AND ".join(where)
    db.conn.execute(
        f"INSERT INTO artifact_dedupe_old_outputs SELECT id FROM tool_outputs WHERE {clause} AND LOWER(path) LIKE '%windows.old%'",
        params,
    )
    db.conn.execute(
        f"INSERT INTO artifact_dedupe_current_outputs SELECT id FROM tool_outputs WHERE {clause} AND LOWER(path) NOT LIKE '%windows.old%'",
        params,
    )


def _dedupe_tool_output_table(db: Database, spec: DedupeSpec, *, case_id: str, image_id: str | None) -> int:
    image_filter = "AND old_row.image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    match_key = _match_key_sql("old_row", spec.columns, spec.path_columns)
    current_key = _match_key_sql("current_row", spec.columns, ())
    db.conn.execute("DROP TABLE IF EXISTS temp.artifact_dedupe_matches")
    db.conn.execute("DROP TABLE IF EXISTS temp.artifact_dedupe_old_keys")
    db.conn.execute("DROP TABLE IF EXISTS temp.artifact_dedupe_current_keys")
    db.conn.execute(
        f"""
        CREATE TEMP TABLE artifact_dedupe_old_keys AS
        SELECT old_row.id AS row_id, {match_key} AS match_key
        FROM {spec.table} AS old_row
        WHERE old_row.case_id = ?
          {image_filter}
          AND old_row.tool_output_id IN (SELECT id FROM artifact_dedupe_old_outputs)
        """,
        params,
    )
    db.conn.execute("CREATE INDEX temp.idx_artifact_dedupe_old_keys_key ON artifact_dedupe_old_keys(match_key)")
    db.conn.execute(
        f"""
        CREATE TEMP TABLE artifact_dedupe_current_keys AS
        SELECT current_row.id AS row_id, {current_key} AS match_key
        FROM {spec.table} AS current_row
        WHERE current_row.case_id = ?
          {"AND current_row.image_id = ?" if image_id else ""}
          AND current_row.tool_output_id IN (SELECT id FROM artifact_dedupe_current_outputs)
        """,
        params,
    )
    db.conn.execute("CREATE INDEX temp.idx_artifact_dedupe_current_keys_key ON artifact_dedupe_current_keys(match_key)")
    db.conn.execute(
        f"""
        CREATE TEMP TABLE artifact_dedupe_matches AS
        SELECT MIN(current_keys.row_id) AS primary_row_id,
               old_keys.row_id AS duplicate_row_id,
               old_keys.match_key AS match_key
        FROM artifact_dedupe_old_keys AS old_keys
        JOIN artifact_dedupe_current_keys AS current_keys
          ON current_keys.match_key = old_keys.match_key
        WHERE old_keys.match_key != ''
        GROUP BY old_keys.row_id
        """,
    )
    return _insert_sources_for_matches(db, spec.family, spec.table)


def _dedupe_filesystem_review(db: Database, *, case_id: str, image_id: str | None) -> int:
    image_filter = "AND old_row.image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    db.conn.execute("DROP TABLE IF EXISTS temp.artifact_dedupe_matches")
    db.conn.execute("DROP TABLE IF EXISTS temp.artifact_dedupe_old_keys")
    db.conn.execute("DROP TABLE IF EXISTS temp.artifact_dedupe_current_keys")
    db.conn.execute(
        f"""
        CREATE TEMP TABLE artifact_dedupe_old_keys AS
        SELECT old_row.id AS row_id,
               COALESCE(old_row.event_type, '') || '|' ||
               COALESCE(old_row.event_time, '') || '|' ||
               {_normalized_windows_old_sql('old_row.file_path')} || '|' ||
               COALESCE(old_row.operation, '') || '|' ||
               COALESCE(old_row.reason, '') || '|' ||
               COALESCE(old_row.status, '') AS match_key
        FROM filesystem_review AS old_row
        WHERE old_row.case_id = ?
          {image_filter}
          AND (
            LOWER(COALESCE(old_row.file_path, '')) LIKE 'windows.old/%'
            OR LOWER(COALESCE(old_row.file_path, '')) LIKE '.\\windows.old\\%'
            OR LOWER(COALESCE(old_row.file_path, '')) LIKE './windows.old/%'
          )
        """,
        params,
    )
    db.conn.execute("CREATE INDEX temp.idx_artifact_dedupe_old_keys_key ON artifact_dedupe_old_keys(match_key)")
    db.conn.execute(
        f"""
        CREATE TEMP TABLE artifact_dedupe_current_keys AS
        SELECT current_row.id AS row_id,
               COALESCE(current_row.event_type, '') || '|' ||
               COALESCE(current_row.event_time, '') || '|' ||
               LOWER(TRIM(REPLACE(COALESCE(current_row.file_path, ''), '\\', '/'), '/')) || '|' ||
               COALESCE(current_row.operation, '') || '|' ||
               COALESCE(current_row.reason, '') || '|' ||
               COALESCE(current_row.status, '') AS match_key
        FROM filesystem_review AS current_row
        WHERE current_row.case_id = ?
          {"AND current_row.image_id = ?" if image_id else ""}
          AND LOWER(COALESCE(current_row.file_path, '')) NOT LIKE 'windows.old/%'
          AND LOWER(COALESCE(current_row.file_path, '')) NOT LIKE '.\\windows.old\\%'
          AND LOWER(COALESCE(current_row.file_path, '')) NOT LIKE './windows.old/%'
        """,
        params,
    )
    db.conn.execute("CREATE INDEX temp.idx_artifact_dedupe_current_keys_key ON artifact_dedupe_current_keys(match_key)")
    db.conn.execute(
        """
        CREATE TEMP TABLE artifact_dedupe_matches AS
        SELECT MIN(current_keys.row_id) AS primary_row_id,
               old_keys.row_id AS duplicate_row_id,
               old_keys.match_key AS match_key
        FROM artifact_dedupe_old_keys AS old_keys
        JOIN artifact_dedupe_current_keys AS current_keys
          ON current_keys.match_key = old_keys.match_key
        WHERE old_keys.match_key != ''
        GROUP BY old_keys.row_id
        """
    )
    return _insert_filesystem_sources_for_matches(db)


def _insert_sources_for_matches(db: Database, family: str, table: str) -> int:
    created_at = utc_now()
    duplicate_count = int(db.conn.execute("SELECT COUNT(*) FROM artifact_dedupe_matches").fetchone()[0])
    if duplicate_count == 0:
        return 0
    db.conn.execute(
        """
        INSERT INTO artifact_record_sources (
          id, case_id, computer_id, image_id, artifact_family, primary_table,
          primary_row_id, duplicate_table, duplicate_row_id, source_scope,
          source_tool, source_output_id, source_output_path, match_key,
          details_json, created_at
        )
        SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(6))),
               primary_row.case_id, primary_row.computer_id, primary_row.image_id,
               ?, ?, primary_row.id, ?, primary_row.id, 'current',
               primary_row.tool_name,
               primary_row.tool_output_id, tool_outputs.path, matches.match_key,
               json_object('dedupe_preference', 'current_os_preferred', 'table', ?),
               ?
        FROM artifact_dedupe_matches AS matches
        JOIN {table} AS primary_row ON primary_row.id = matches.primary_row_id
        LEFT JOIN tool_outputs ON tool_outputs.id = primary_row.tool_output_id
        GROUP BY primary_row.id
        """.format(table=table),
        (family, table, table, table, created_at),
    )
    db.conn.execute(
        """
        INSERT INTO artifact_record_sources (
          id, case_id, computer_id, image_id, artifact_family, primary_table,
          primary_row_id, duplicate_table, duplicate_row_id, source_scope,
          source_tool, source_output_id, source_output_path, match_key,
          details_json, created_at
        )
        SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(6))),
               old_row.case_id, old_row.computer_id, old_row.image_id,
               ?, ?, matches.primary_row_id, ?, old_row.id, 'windows_old',
               old_row.tool_name,
               old_row.tool_output_id, tool_outputs.path, matches.match_key,
               json_object('dedupe_preference', 'current_os_preferred', 'table', ?),
               ?
        FROM artifact_dedupe_matches AS matches
        JOIN {table} AS old_row ON old_row.id = matches.duplicate_row_id
        LEFT JOIN tool_outputs ON tool_outputs.id = old_row.tool_output_id
        """.format(table=table),
        (family, table, table, table, created_at),
    )
    return duplicate_count


def _insert_filesystem_sources_for_matches(db: Database) -> int:
    created_at = utc_now()
    duplicate_count = int(db.conn.execute("SELECT COUNT(*) FROM artifact_dedupe_matches").fetchone()[0])
    if duplicate_count == 0:
        return 0
    db.conn.execute(
        """
        INSERT INTO artifact_record_sources (
          id, case_id, computer_id, image_id, artifact_family, primary_table,
          primary_row_id, duplicate_table, duplicate_row_id, source_scope,
          source_tool, source_output_id, source_output_path, match_key,
          details_json, created_at
        )
        SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(6))),
               primary_row.case_id, primary_row.computer_id, primary_row.image_id,
               'filesystem_review', 'filesystem_review', primary_row.id,
               'filesystem_review', primary_row.id, 'current',
               primary_row.source_tool, NULL, NULL, matches.match_key,
               json_object('dedupe_preference', 'current_os_preferred', 'table', 'filesystem_review'),
               ?
        FROM artifact_dedupe_matches AS matches
        JOIN filesystem_review AS primary_row ON primary_row.id = matches.primary_row_id
        GROUP BY primary_row.id
        """,
        (created_at,),
    )
    db.conn.execute(
        """
        INSERT INTO artifact_record_sources (
          id, case_id, computer_id, image_id, artifact_family, primary_table,
          primary_row_id, duplicate_table, duplicate_row_id, source_scope,
          source_tool, source_output_id, source_output_path, match_key,
          details_json, created_at
        )
        SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
               lower(hex(randomblob(6))),
               old_row.case_id, old_row.computer_id, old_row.image_id,
               'filesystem_review', 'filesystem_review', matches.primary_row_id,
               'filesystem_review', old_row.id, 'windows_old',
               old_row.source_tool, NULL, NULL, matches.match_key,
               json_object('dedupe_preference', 'current_os_preferred', 'table', 'filesystem_review'),
               ?
        FROM artifact_dedupe_matches AS matches
        JOIN filesystem_review AS old_row ON old_row.id = matches.duplicate_row_id
        """,
        (created_at,),
    )
    return duplicate_count


def _match_key_sql(alias: str, columns: tuple[str, ...], path_columns: tuple[str, ...]) -> str:
    parts = []
    for column in columns:
        if column in path_columns:
            parts.append(_normalized_windows_old_sql(f"{alias}.{column}"))
        else:
            parts.append(f"COALESCE({alias}.{column}, '')")
    return " || '|' || ".join(parts) if parts else "''"


def _normalized_windows_old_sql(expression: str) -> str:
    return (
        "TRIM("
        f"REPLACE(REPLACE(LOWER(REPLACE(COALESCE({expression}, ''), '\\\\', '/')), "
        "'./windows.old/', ''), 'windows.old/', ''), "
        "'/'"
        ")"
    )


def _table_exists(db: Database, table: str) -> bool:
    return db.conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone() is not None
