from __future__ import annotations

from typing import Any

from forensic_orchestrator.db import Database


def rebuild_filesystem_review(db: Database, *, case_id: str, image_id: str | None = None) -> int:
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id is not None:
        where.append("image_id = ?")
        params.append(image_id)
    db.conn.execute(f"DELETE FROM filesystem_review WHERE {' AND '.join(where)}", params)
    if db.analytics_only:
        db.conn.commit()
        return 0
    _insert_mft_rows(db, case_id=case_id, image_id=image_id)
    _insert_usn_rows(db, case_id=case_id, image_id=image_id)
    _insert_logfile_rows(db, case_id=case_id, image_id=image_id)
    _insert_index_rows(db, case_id=case_id, image_id=image_id)
    _insert_namespace_rows(db, case_id=case_id, image_id=image_id)
    _insert_windows_search_gather_rows(db, case_id=case_id, image_id=image_id)
    _insert_windows_search_property_rows(db, case_id=case_id, image_id=image_id)
    _insert_thumbcache_search_rows(db, case_id=case_id, image_id=image_id)
    db.conn.commit()
    return db.conn.execute(
        f"SELECT COUNT(*) AS count FROM filesystem_review WHERE {' AND '.join(where)}",
        params,
    ).fetchone()["count"]


def _insert_mft_rows(db: Database, *, case_id: str, image_id: str | None) -> None:
    where, params = _case_image_where("mft_entries", case_id, image_id)
    db.conn.execute(
        f"""
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, source_tool,
          source_row_number, event_type, event_time, file_name, file_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, operation, reason, status, details_json, created_at
        )
        SELECT
          lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(6))),
          case_id, computer_id, image_id, 'mft_entries', id, tool_name,
          row_number, 'mft_record',
          COALESCE(NULLIF(record_changed_si, ''), NULLIF(modified_si, ''), NULLIF(created_si, '')),
          file_name, {PATH_JOIN_SQL.format(parent='parent_path', name='file_name')}, parent_path,
          entry_number, sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, NULL, 'mft_record_present',
          CASE WHEN lower(COALESCE(in_use, '')) = 'true' THEN 'mft_in_use' ELSE 'mft_not_in_use' END,
          '{{}}', datetime('now')
        FROM mft_entries
        WHERE {where}
        """,
        params,
    )


def _insert_usn_rows(db: Database, *, case_id: str, image_id: str | None) -> None:
    where, params = _case_image_where("usn_journal_entries", case_id, image_id)
    db.conn.execute(
        f"""
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, source_tool,
          source_row_number, event_type, event_time, file_name, file_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, operation, reason, status, details_json, created_at
        )
        SELECT
          lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(6))),
          case_id, computer_id, image_id, 'usn_journal_entries', id, tool_name,
          row_number,
          CASE
            WHEN lower(COALESCE(reason, '')) LIKE '%delete%' THEN 'usn_delete'
            WHEN lower(COALESCE(reason, '')) LIKE '%rename%' THEN 'usn_rename'
            WHEN lower(COALESCE(reason, '')) LIKE '%create%' THEN 'usn_create'
            WHEN lower(COALESCE(reason, '')) LIKE '%dataextend%'
              OR lower(COALESCE(reason, '')) LIKE '%datatruncation%'
              OR lower(COALESCE(reason, '')) LIKE '%overwrite%' THEN 'usn_content_change'
            WHEN lower(COALESCE(reason, '')) LIKE '%close%' THEN 'usn_close'
            ELSE 'usn_event'
          END,
          update_timestamp, file_name, {PATH_JOIN_SQL.format(parent='full_path', name='file_name')}, full_path,
          file_reference_number, file_reference_sequence_number,
          parent_file_reference_number, parent_file_reference_sequence_number,
          NULL,
          CASE WHEN lower(COALESCE(file_attributes, '')) LIKE '%director%' THEN 'true' ELSE 'false' END,
          reason, reason, 'filesystem_journal_event', '{{}}', datetime('now')
        FROM usn_journal_entries
        WHERE {where}
        """,
        params,
    )


def _insert_logfile_rows(db: Database, *, case_id: str, image_id: str | None) -> None:
    where, params = _case_image_where("ntfs_logfile_entries", case_id, image_id)
    db.conn.execute(
        f"""
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, source_tool,
          source_row_number, event_type, event_time, file_name, file_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, operation, reason, status, details_json, created_at
        )
        SELECT
          lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(6))),
          case_id, computer_id, image_id, 'ntfs_logfile_entries', id, tool_name,
          row_number,
          CASE
            WHEN lower(COALESCE(operation, '') || ' ' || COALESCE(redo_operation, '') || ' ' || COALESCE(undo_operation, '')) LIKE '%delete%'
              OR lower(COALESCE(operation, '') || ' ' || COALESCE(redo_operation, '') || ' ' || COALESCE(undo_operation, '')) LIKE '%dealloc%' THEN 'logfile_delete'
            WHEN lower(COALESCE(operation, '') || ' ' || COALESCE(redo_operation, '') || ' ' || COALESCE(undo_operation, '')) LIKE '%rename%' THEN 'logfile_rename'
            WHEN lower(COALESCE(operation, '') || ' ' || COALESCE(redo_operation, '') || ' ' || COALESCE(undo_operation, '')) LIKE '%create%'
              OR lower(COALESCE(operation, '') || ' ' || COALESCE(redo_operation, '') || ' ' || COALESCE(undo_operation, '')) LIKE '%alloc%' THEN 'logfile_create'
            ELSE 'logfile_event'
          END,
          event_time, file_name, file_path, NULL,
          file_reference_number, file_reference_sequence_number,
          parent_file_reference_number, parent_file_reference_sequence_number,
          NULL, NULL, COALESCE(NULLIF(operation, ''), NULLIF(redo_operation, '')),
          COALESCE(NULLIF(operation, ''), NULLIF(redo_operation, ''), NULLIF(undo_operation, '')),
          'ntfs_transaction_log_event', row_json, datetime('now')
        FROM ntfs_logfile_entries
        WHERE {where}
        """,
        params,
    )


def _insert_index_rows(db: Database, *, case_id: str, image_id: str | None) -> None:
    where, params = _case_image_where("ntfs_index_entries", case_id, image_id)
    db.conn.execute(
        f"""
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, source_tool,
          source_row_number, event_type, event_time, file_name, file_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, operation, reason, status, details_json, created_at
        )
        SELECT
          lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(6))),
          case_id, computer_id, image_id, 'ntfs_index_entries', id, tool_name,
          row_number, 'ntfs_i30_entry',
          COALESCE(NULLIF(record_changed_fn, ''), NULLIF(modified_fn, ''), NULLIF(created_fn, '')),
          file_name, {PATH_JOIN_SQL.format(parent='directory_path', name='file_name')}, directory_path,
          referenced_entry_number, referenced_sequence_number, directory_entry_number, NULL,
          NULL,
          CASE WHEN lower(COALESCE(file_flags, '')) LIKE '%director%' THEN 'true' ELSE 'false' END,
          NULL, 'directory_index_entry',
          CASE WHEN lower(COALESCE(from_slack, '')) IN ('true', '1', 'yes') THEN 'i30_slack_entry' ELSE 'i30_active_entry' END,
          '{{}}', datetime('now')
        FROM ntfs_index_entries
        WHERE {where}
        """,
        params,
    )


def _insert_namespace_rows(db: Database, *, case_id: str, image_id: str | None) -> None:
    where, params = _case_image_where("ntfs_namespace_reconciliation", case_id, image_id)
    db.conn.execute(
        f"""
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, source_tool,
          source_row_number, event_type, event_time, file_name, file_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, operation, reason, status, details_json, created_at
        )
        SELECT
          lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(6))),
          case_id, computer_id, image_id, 'ntfs_namespace_reconciliation', id, NULL,
          NULL, 'ntfs_namespace_reconciliation', created_at, file_name, original_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, NULL,
          mft_in_use, NULL, index_status, reason,
          CASE WHEN legit_active_file = 'true' THEN 'active_namespace' ELSE 'namespace_anomaly' END,
          '{{}}', datetime('now')
        FROM ntfs_namespace_reconciliation
        WHERE {where}
        """,
        params,
    )


def _insert_windows_search_gather_rows(db: Database, *, case_id: str, image_id: str | None) -> None:
    where, params = _case_image_where("windows_search_gather_logs", case_id, image_id)
    db.conn.execute(
        f"""
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, source_tool,
          source_row_number, event_type, event_time, file_name, file_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, operation, reason, status, details_json, created_at
        )
        SELECT
          lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(6))),
          case_id, computer_id, image_id, 'windows_search_gather_logs', id, tool_name,
          row_number,
          CASE WHEN lower(COALESCE(is_deleted_path, '')) = 'true'
            THEN 'windows_search_deleted_path'
            ELSE 'windows_search_gather'
          END,
          timestamp_utc,
          item_path,
          item_path,
          NULL,
          NULL, NULL, NULL, NULL,
          NULL,
          CASE WHEN rtrim(COALESCE(item_path, ''), '\\') != COALESCE(item_path, '') THEN 'true' ELSE NULL END,
          crawl_code_hex,
          CASE WHEN lower(COALESCE(is_deleted_path, '')) = 'true'
            THEN 'Windows Search gather log observed $Extend/$Deleted path'
            ELSE 'Windows Search gather log observed indexed path'
          END,
          CASE WHEN lower(COALESCE(is_deleted_path, '')) = 'true'
            THEN 'windows_search_deleted_path'
            ELSE 'windows_search_gather_observation'
          END,
          json_object(
            'source_name', source_name,
            'log_type', log_type,
            'item_url', item_url,
            'status_hex', status_hex,
            'crawl_code_hex', crawl_code_hex,
            'scope_id', scope_id,
            'document_id', document_id
          ),
          datetime('now')
        FROM windows_search_gather_logs
        WHERE {where}
        """,
        params,
    )


def _insert_windows_search_property_rows(db: Database, *, case_id: str, image_id: str | None) -> None:
    where, params = _case_image_where("wsp", case_id, image_id)
    property_names = tuple(sorted(WINDOWS_SEARCH_REVIEW_PROPERTIES))
    placeholders = ",".join("?" for _ in property_names)
    db.conn.execute(
        f"""
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, source_tool,
          source_row_number, event_type, event_time, file_name, file_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, operation, reason, status, details_json, created_at
        )
        SELECT
          lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(6))),
          wsp.case_id, wsp.computer_id, wsp.image_id, 'windows_search_properties', wsp.id, wsp.tool_name,
          wsp.row_number,
          CASE
            WHEN wsp.property_name IN ('4430-System_IsDeleted', 'System_IsDeleted') THEN 'windows_search_deleted_state'
            WHEN wsp.property_name IN ('4397-System_FilePlaceholderStatus', 'System_FilePlaceholderStatus') THEN 'windows_search_cloud_placeholder_state'
            WHEN wsp.property_name LIKE '%System_Document_%' THEN 'windows_search_document_metadata'
            WHEN wsp.property_name LIKE '%System_Photo_%' THEN 'windows_search_photo_metadata'
            WHEN wsp.property_name LIKE '%System_GPS_%' THEN 'windows_search_gps_metadata'
            WHEN wsp.property_name LIKE '%System_Message_%' THEN 'windows_search_message_metadata'
            WHEN wsp.property_name IN (
              '4429-System_IsAttachment', 'System_IsAttachment',
              '4431-System_IsEncrypted', 'System_IsEncrypted',
              '4434-System_IsFolder', 'System_IsFolder'
            ) THEN 'windows_search_file_state'
            ELSE 'windows_search_property'
          END,
          CASE
            WHEN wsp.property_name LIKE '%Date%'
              OR wsp.property_name IN ('4371-System_Document_DateCreated', '4373-System_Document_DateSaved',
                                       '4372-System_Document_DatePrinted',
                                       '4519-System_Message_DateReceived', '4520-System_Message_DateSent',
                                       '4570-System_Photo_DateTaken', '4404-System_GPS_Date')
              THEN wsp.property_value
            ELSE COALESCE(NULLIF(wsp.timestamp, ''), NULLIF(wsf.date_accessed, ''),
                          NULLIF(wsf.date_modified, ''), NULLIF(wsf.gather_time, ''),
                          NULLIF(wsf.date_created, ''))
          END,
          COALESCE(
            NULLIF(wsf.file_name, ''),
            CASE
              WHEN instr(COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path), '\\') > 0
                THEN substr(COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path),
                            length(rtrim(COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path), replace(COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path), '\\', ''))) + 1)
              WHEN instr(COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path), '/') > 0
                THEN substr(COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path),
                            length(rtrim(COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path), replace(COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path), '/', ''))) + 1)
              ELSE COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path)
            END
          ),
          COALESCE(NULLIF(wsf.item_path, ''), wsp.item_path),
          wsf.folder_path,
          NULL, NULL, NULL, NULL,
          NULL,
          CASE
            WHEN lower(COALESCE(wsf.is_folder, '')) IN ('true', '1', 'yes') THEN 'true'
            ELSE NULL
          END,
          wsp.property_name,
          'Windows Search property corroboration: ' || wsp.property_name,
          CASE
            WHEN wsp.property_name IN ('4430-System_IsDeleted', 'System_IsDeleted')
             AND lower(COALESCE(wsp.property_value, '')) IN ('true', '1', 'yes') THEN 'windows_search_deleted_path'
            WHEN wsp.property_name IN ('4430-System_IsDeleted', 'System_IsDeleted') THEN 'windows_search_not_deleted'
            WHEN wsp.property_name IN ('4397-System_FilePlaceholderStatus', 'System_FilePlaceholderStatus') THEN 'windows_search_cloud_placeholder'
            ELSE 'windows_search_property_observation'
          END,
          json_object(
            'work_id', wsp.work_id,
            'property_name', wsp.property_name,
            'normalized_name', wsp.normalized_name,
            'property_value', wsp.property_value,
            'windows_search_file_id', wsf.id,
            'windows_search_gather_time', wsf.gather_time,
            'windows_search_item_url', wsf.item_url,
            'windows_search_item_type', wsf.item_type,
            'windows_search_size', wsf.size,
            'windows_search_owner', wsf.owner
          ),
          datetime('now')
        FROM windows_search_properties AS wsp
        LEFT JOIN windows_search_files AS wsf
          ON wsf.id = wsp.source_record_id
        WHERE {where}
          AND COALESCE(wsp.property_value, '') != ''
          AND wsp.property_name IN ({placeholders})
          AND COALESCE(NULLIF(wsf.item_path, ''), NULLIF(wsp.item_path, '')) IS NOT NULL
          AND (
            (
              wsp.property_name = '4430-System_IsDeleted'
              AND lower(COALESCE(wsp.property_value, '')) IN ('true', '1', 'yes')
            )
            OR wsp.property_name = '4397-System_FilePlaceholderStatus'
            OR (
              wsp.property_name IN (
                '4371-System_Document_DateCreated',
                '4372-System_Document_DatePrinted',
                '4373-System_Document_DateSaved'
              )
              AND lower(COALESCE(wsf.file_extension, '')) IN (
                '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.rtf', '.txt'
              )
            )
            OR (
              wsp.property_name IN (
                '4570-System_Photo_DateTaken',
                '4404-System_GPS_Date',
                '4406-System_GPS_LatitudeDecimal',
                '4409-System_GPS_LongitudeDecimal'
              )
              AND lower(COALESCE(wsf.file_extension, '')) IN (
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.heic', '.jfif'
              )
            )
            OR wsp.property_name IN ('4519-System_Message_DateReceived', '4520-System_Message_DateSent')
            OR (
              wsp.property_name IN ('4429-System_IsAttachment', '4431-System_IsEncrypted')
              AND lower(COALESCE(wsp.property_value, '')) IN ('true', '1', 'yes')
            )
          )
        """,
        [*params, *property_names],
    )


def _insert_thumbcache_search_rows(db: Database, *, case_id: str, image_id: str | None) -> None:
    where, params = _case_image_where("tsc", case_id, image_id)
    db.conn.execute(
        f"""
        INSERT INTO filesystem_review (
          id, case_id, computer_id, image_id, source_table, source_id, source_tool,
          source_row_number, event_type, event_time, file_name, file_path, parent_path,
          mft_entry_number, mft_sequence_number, parent_entry_number, parent_sequence_number,
          in_use, is_directory, operation, reason, status, details_json, created_at
        )
        SELECT
          lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
          lower(hex(randomblob(6))),
          tsc.case_id, tsc.computer_id, tsc.image_id,
          'thumbcache_search_correlations', tsc.id, tsc.tool_name,
          NULL,
          CASE
            WHEN lower(COALESCE(wsf.is_deleted, '')) IN ('true', '1', 'yes')
              THEN 'windows_search_thumbcache_deleted_path'
            ELSE 'thumbcache_search_path_correlation'
          END,
          COALESCE(NULLIF(tsc.search_date_accessed, ''), NULLIF(tsc.search_date_modified, ''),
                   NULLIF(tsc.search_date_created, ''), NULLIF(tsc.search_date_imported, '')),
          tsc.search_file_name,
          tsc.search_item_path,
          json_extract(tsc.details_json, '$.search_folder_path'),
          NULL, NULL, NULL, NULL,
          NULL,
          CASE
            WHEN lower(COALESCE(wsf.is_folder, '')) IN ('true', '1', 'yes') THEN 'true'
            ELSE NULL
          END,
          tsc.correlation_basis,
          'Thumbcache Cache Entry Hash matched Windows Search System_ThumbnailCacheId',
          CASE
            WHEN lower(COALESCE(wsf.is_deleted, '')) IN ('true', '1', 'yes')
              THEN 'windows_search_deleted_path'
            ELSE 'thumbcache_search_observation'
          END,
          json_object(
            'cache_id', tsc.cache_id,
            'confidence', tsc.confidence,
            'thumbcache_entry_id', tsc.thumbcache_entry_id,
            'thumbcache_name', tsc.thumbcache_name,
            'thumbcache_user', tsc.thumbcache_user,
            'thumbnail_sha256', tsc.thumbnail_sha256,
            'thumbnail_type', tsc.thumbnail_type,
            'windows_search_file_id', tsc.windows_search_file_id,
            'windows_search_is_deleted', wsf.is_deleted,
            'windows_search_is_folder', wsf.is_folder
          ),
          datetime('now')
        FROM thumbcache_search_correlations AS tsc
        LEFT JOIN windows_search_files AS wsf
          ON wsf.id = tsc.windows_search_file_id
        WHERE {where}
          AND COALESCE(tsc.search_item_path, '') != ''
        """,
        params,
    )


WINDOWS_SEARCH_REVIEW_PROPERTIES = {
    "4430-System_IsDeleted",
    "4429-System_IsAttachment",
    "4431-System_IsEncrypted",
    "4397-System_FilePlaceholderStatus",
    "4371-System_Document_DateCreated",
    "4372-System_Document_DatePrinted",
    "4373-System_Document_DateSaved",
    "4570-System_Photo_DateTaken",
    "4404-System_GPS_Date",
    "4406-System_GPS_LatitudeDecimal",
    "4409-System_GPS_LongitudeDecimal",
    "4519-System_Message_DateReceived",
    "4520-System_Message_DateSent",
}


PATH_JOIN_SQL = """
CASE
  WHEN COALESCE({parent}, '') = '' THEN {name}
  WHEN COALESCE({name}, '') = '' THEN {parent}
  WHEN instr({parent}, '\\') > 0 THEN rtrim({parent}, '\\/') || '\\' || {name}
  ELSE rtrim({parent}, '\\/') || '/' || {name}
END
"""




def _case_image_where(table: str, case_id: str, image_id: str | None) -> tuple[str, list[Any]]:
    where = [f"{table}.case_id = ?"]
    params: list[Any] = [case_id]
    if image_id is not None:
        where.append(f"{table}.image_id = ?")
        params.append(image_id)
    return " AND ".join(where), params
