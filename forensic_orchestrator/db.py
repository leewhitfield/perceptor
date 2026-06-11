from __future__ import annotations

import json
import hashlib
import logging
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .analytics import ANALYTICS_TABLE_COLUMNS, AnalyticsStore
from .models import Case, Computer, EvidenceImage

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None


LOGGER = logging.getLogger(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _duration_ms(start_time: str, end_time: str) -> int:
    try:
        return max(0, int((_parse_iso_datetime(end_time) - _parse_iso_datetime(start_time)).total_seconds() * 1000))
    except Exception:
        return 0


def _source_scope_from_values(*values: object) -> str:
    text = "\n".join(str(value) for value in values if value not in (None, ""))
    lowered = text.lower().replace("\\", "/")
    if "windows.old" in lowered or "windows_old" in lowered:
        return "Windows.old"
    if (
        "volume shadow" in lowered
        or "shadow copy" in lowered
        or re.search(r"(^|[/_. -])vsc([0-9]+|[/_. -]|$)", lowered)
        or re.search(r"(^|[/_. -])snapshot([0-9]+|[/_. -]|$)", lowered)
    ):
        return "VSC"
    return "live"


def _host_from_url(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    if "@" in text and "://" in text:
        text = text.split("@", 1)[1]
    return urlparse(text).netloc.lower()


def _text_hash(value: object) -> str:
    text = "" if value is None else str(value)
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _json_bool_text(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes"}:
        return "true"
    if text in {"false", "0", "no"}:
        return "false"
    return ""


def _content_document_id(case_id: object, content: str) -> str:
    content_hash = _text_hash(content)
    return hashlib.sha256(f"{case_id}|content|{content_hash}".encode("utf-8", errors="replace")).hexdigest()


def _usn_path_updates(rows: list[Any]) -> list[tuple[str, str]]:
    updates: list[tuple[str, str]] = []
    for row in rows:
        row_id = str(row["id"] if isinstance(row, sqlite3.Row) else row[0])
        file_name = str((row["file_name"] if isinstance(row, sqlite3.Row) else row[1]) or "")
        current = str((row["full_path"] if isinstance(row, sqlite3.Row) else row[2]) or "")
        parent_path = str((row["parent_path"] if isinstance(row, sqlite3.Row) else row[3]) or "")
        parent_name = str((row["parent_name"] if isinstance(row, sqlite3.Row) else row[4]) or "")
        resolved = _compose_usn_full_path(parent_path, parent_name, file_name)
        if not resolved:
            continue
        normalized_current = current.replace("/", "\\").rstrip("\\").lower()
        normalized_resolved = resolved.replace("/", "\\").rstrip("\\").lower()
        if normalized_current == normalized_resolved:
            continue
        if "pathunknown" in normalized_current or not normalized_current.endswith("\\" + file_name.lower()):
            updates.append((resolved, row_id))
    return updates


def _compose_usn_full_path(parent_path: str, parent_name: str, file_name: str) -> str:
    parts = []
    parent_path = parent_path.replace("/", "\\").strip("\\")
    if parent_path and parent_path != ".":
        parts.extend(part for part in parent_path.split("\\") if part and part != ".")
    parent_name = parent_name.strip("\\/")
    if parent_name and (not parts or parts[-1].lower() != parent_name.lower()):
        parts.append(parent_name)
    file_name = file_name.strip("\\/")
    if file_name:
        parts.append(file_name)
    return ".\\" + "\\".join(parts) if parts else file_name


DEFAULT_PURGE_TABLES = (
    "parsed_rows",
    "shortcut_items",
    "prefetch_items",
    "prefetch_run_times",
    "sam_accounts",
    "registry_hives",
    "registry_artifacts",
    "registry_recentdocs",
    "registry_runmru",
    "registry_typedpaths",
    "registry_wordwheel_query",
    "registry_userassist",
    "registry_office_mru",
    "registry_common_dialog_mru",
    "registry_trusted_documents",
    "registry_office_trust_records",
    "registry_taskbar_feature_usage",
    "registry_taskbar_pins",
    "amcache_entries",
    "shimcache_entries",
    "shellbag_entries",
    "usb_devices",
    "setupapi_device_events",
    "filesystem_entries",
    "mft_entries",
    "usn_journal_entries",
    "ntfs_logfile_entries",
    "ntfs_index_entries",
    "ntfs_index_bitmaps",
    "srum_records",
    "ual_records",
    "bits_jobs",
    "bits_activity",
    "clipboard_items",
    "windows_search_files",
    "windows_search_internet_history",
    "windows_search_activity_history",
    "windows_search_gather_logs",
    "windows_search_email_indicators",
    "windows_search_indexed_content",
    "windows_search_properties",
    "windows_search_memory_carves",
    "windows_search_memory_objects",
    "windows_search_memory_rows",
    "windows_error_reports",
    "windows_defender_events",
    "browser_history",
    "browser_downloads",
    "browser_cookies",
    "browser_cache_entries",
    "browser_artifacts",
    "browser_session_entries",
    "browser_site_settings",
    "browser_notifications",
    "office_backstage_items",
    "user_dictionary_words",
    "zone_identifier_ads",
    "image_analysis_items",
    "rdp_cache_items",
    "rdp_visual_observations",
    "thumbcache_search_correlations",
    "thumbcache_entries",
    "cloud_sync_artifacts",
    "google_drive_cache_map",
    "onedrive_items",
    "onedrive_log_entries",
    "package_cache_entries",
    "package_artifacts",
    "spotify_artifacts",
    "telemetry_artifacts",
    "windows_activities",
    "webcache_entries",
    "webcache_file_accesses",
    "file_internal_metadata",
    "archive_entries",
    "nested_evidence_items",
    "mailbox_messages",
    "mailbox_attachments",
    "windows_mail_store_rows",
    "messaging_records",
    "messaging_messages",
    "file_metadata_extraction_summaries",
    "evtx_events",
    "etl_events",
    "tool_outputs",
    "content_references",
    "cloud_server_events",
    "memory_string_hits",
    "structured_memory_records",
    "carve_scan_ranges",
    "staged_carves",
)

SQLITE_ONLY_PURGE_TABLES = {
    "tool_outputs",
    "file_metadata_extraction_summaries",
}

ANALYTICS_TABLES = (set(DEFAULT_PURGE_TABLES) - SQLITE_ONLY_PURGE_TABLES) | {
    "copied_file_indicators",
    "filesystem_review",
    "firefox_cookies",
    "firefox_history",
    "recycle_children",
    "recycle_items",
    "timeline_events",
    "usb_connection_events",
    "usb_file_correlations",
    "usb_storage_devices",
}


TOOL_PURGE_TABLES = {
    "ChromiumParser": {
        "parsed_rows",
        "browser_history",
        "browser_downloads",
        "browser_cookies",
        "browser_artifacts",
        "browser_session_entries",
        "browser_site_settings",
        "browser_notifications",
        "tool_outputs",
    },
    "PrefetchParser": {"prefetch_items", "prefetch_run_times", "tool_outputs"},
    "MFTECmd": {"parsed_rows", "mft_entries", "tool_outputs"},
    "MountedFilesystemInventory": {"filesystem_entries", "tool_outputs"},
    "TskFilesystemInventory": {"filesystem_entries", "tool_outputs"},
    "MFTECmdUSN": {"usn_journal_entries", "tool_outputs"},
    "USNRewind": {"usn_journal_entries", "tool_outputs"},
    "MFTECmdI30": {"ntfs_index_entries", "ntfs_index_bitmaps", "tool_outputs"},
    "EvtxECmd": {"evtx_events", "bits_activity", "tool_outputs"},
    "EvtxECmdTriage": {"evtx_events", "bits_activity", "tool_outputs"},
    "BITSParser": {"bits_jobs", "tool_outputs"},
    "ClipboardParser": {"clipboard_items", "tool_outputs"},
    "MailboxParser": {"mailbox_messages", "mailbox_attachments", "tool_outputs"},
    "ZoneIdentifierParser": {"zone_identifier_ads", "tool_outputs"},
    "RdpCacheParser": {
        "image_analysis_items",
        "rdp_cache_items",
        "rdp_visual_observations",
        "tool_outputs",
    },
    "RdpVisionReview": {
        "rdp_visual_observations",
        "tool_outputs",
    },
    "SAMParser": {"sam_accounts", "tool_outputs"},
    "RegistryParser": {"registry_hives", "tool_outputs"},
    "RegistryArtifactParser": {
        "registry_artifacts",
        "registry_office_trust_records",
        "registry_taskbar_feature_usage",
        "registry_taskbar_pins",
        "usb_devices",
        "tool_outputs",
    },
    "SetupApiParser": {"setupapi_device_events", "tool_outputs"},
    "RECmd": {
        "registry_recentdocs",
        "registry_runmru",
        "registry_typedpaths",
        "registry_wordwheel_query",
        "registry_userassist",
        "registry_office_mru",
        "registry_common_dialog_mru",
        "registry_trusted_documents",
        "tool_outputs",
    },
    "AmcacheParser": {"amcache_entries", "tool_outputs"},
    "AppCompatCacheParser": {"shimcache_entries", "tool_outputs"},
    "SBECmd": {"shellbag_entries", "tool_outputs"},
    "ArchiveInventoryParser": {"archive_entries", "tool_outputs"},
    "SpotifyParser": {"spotify_artifacts", "tool_outputs"},
    "UserFileContentParser": {
        "windows_search_indexed_content",
        "content_references",
        "tool_outputs",
    },
    "CloudServerLogImporter": {"cloud_server_events", "content_references", "tool_outputs"},
    "MemoryStringScanner": {"memory_string_hits", "tool_outputs"},
    "StructuredMemoryAnalyzer": {"structured_memory_records", "tool_outputs"},
    "CarveStageRunner": {"carve_scan_ranges", "staged_carves", "tool_outputs"},
    "WindowsSearchMemoryCarveParser": {
        "windows_search_memory_carves",
        "windows_search_memory_objects",
        "windows_search_memory_rows",
        "tool_outputs",
    },
}


class Database:
    def __init__(self, path: Path, *, migrate: bool = True) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=60)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=60000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.create_function("host_from_url", 1, _host_from_url)
        self._defer_commit_depth = 0
        self._transaction_lock = threading.RLock()
        self.analytics_mode = os.environ.get("FORENSIC_ANALYTICS_MODE", "duckdb").lower()
        if self.analytics_mode not in {"sqlite", "duckdb", "mirror"}:
            raise ValueError("FORENSIC_ANALYTICS_MODE must be one of: sqlite, duckdb, mirror")
        self.analytics = AnalyticsStore(self.conn) if self.analytics_mode in {"duckdb", "mirror"} else None
        self._sqlite_table_columns: dict[str, list[str]] = {}
        if migrate:
            with self._migration_lock():
                self.migrate()

    def close(self) -> None:
        if self.analytics is not None:
            self.analytics.close()
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @contextmanager
    def _migration_lock(self):
        if fcntl is None:
            yield
            return
        lock_path = self.path.with_suffix(self.path.suffix + ".migrate.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("w") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @contextmanager
    def bulk_transaction(self):
        with self._transaction_lock:
            self._defer_commit_depth += 1
            try:
                yield
                if self._defer_commit_depth == 1:
                    self.conn.commit()
            except Exception:
                if self._defer_commit_depth == 1:
                    self.conn.rollback()
                raise
            finally:
                self._defer_commit_depth -= 1

    def _commit(self) -> None:
        if self._defer_commit_depth == 0:
            self.conn.commit()

    def _analytics_insert(self, table: str, columns: list[str], rows: list[dict[str, Any]]) -> bool:
        if self.analytics is None:
            return False
        if table not in ANALYTICS_TABLES:
            return False
        allowed_columns = self._table_columns(table)
        analytics_columns = list(allowed_columns)
        analytics_rows = [
            {column: row.get(column) for column in analytics_columns}
            for row in rows
        ]
        try:
            self.analytics.insert_rows(table, analytics_columns, analytics_rows)
        except Exception as exc:
            self._log_database_write_failure(f"duckdb:{table}", rows, exc)
            raise
        return self.analytics_mode == "duckdb"

    @property
    def analytics_only(self) -> bool:
        return self.analytics_mode == "duckdb"

    def migrate(self) -> None:
        if self.analytics_mode == "duckdb":
            self._drop_sqlite_analytics_views()
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
              id TEXT PRIMARY KEY,
              root TEXT NOT NULL,
              description TEXT,
              notes_path TEXT,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS schema_version (
              id INTEGER PRIMARY KEY CHECK (id = 1),
              version INTEGER NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL UNIQUE REFERENCES cases(id),
              name TEXT NOT NULL,
              root TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS computers (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              label TEXT NOT NULL,
              hostname TEXT,
              notes TEXT,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS images (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT REFERENCES computers(id),
              path TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS image_metadata (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              source TEXT NOT NULL,
              key TEXT NOT NULL,
              value TEXT,
              created_at TEXT NOT NULL,
              UNIQUE(case_id, image_id, source, key)
            );

            CREATE INDEX IF NOT EXISTS idx_image_metadata_image
              ON image_metadata(case_id, image_id);

            CREATE TABLE IF NOT EXISTS image_hashes (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              algorithm TEXT NOT NULL,
              digest TEXT,
              size_bytes INTEGER,
              source_path TEXT NOT NULL,
              status TEXT NOT NULL,
              error TEXT,
              computed_at TEXT NOT NULL,
              UNIQUE(case_id, image_id, algorithm)
            );

            CREATE INDEX IF NOT EXISTS idx_image_hashes_image
              ON image_hashes(case_id, image_id);

            CREATE TABLE IF NOT EXISTS image_verifications (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              algorithm TEXT NOT NULL,
              expected_digest TEXT,
              actual_digest TEXT,
              source_path TEXT NOT NULL,
              size_bytes INTEGER,
              status TEXT NOT NULL,
              error TEXT,
              verified_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_image_verifications_image_time
              ON image_verifications(case_id, image_id, verified_at);

            CREATE TABLE IF NOT EXISTS evidence_file_extractions (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT NOT NULL REFERENCES images(id),
              artifact_name TEXT,
              source_path TEXT,
              extracted_path TEXT NOT NULL,
              inode TEXT,
              extraction_method TEXT NOT NULL,
              sha256 TEXT,
              size_bytes INTEGER,
              created_utc TEXT,
              modified_utc TEXT,
              accessed_utc TEXT,
              metadata_changed_utc TEXT,
              status TEXT NOT NULL,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_file_extractions_case
              ON evidence_file_extractions(case_id, image_id, artifact_name);
            CREATE INDEX IF NOT EXISTS idx_evidence_file_extractions_hash
              ON evidence_file_extractions(case_id, sha256);

            CREATE TABLE IF NOT EXISTS mounts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              partition_id TEXT,
              ewf_mount_path TEXT NOT NULL,
              raw_path TEXT NOT NULL,
              source_type TEXT NOT NULL DEFAULT 'ewfmount',
              filesystem_type TEXT,
              volume_mount_path TEXT,
              offset_bytes INTEGER,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS artifacts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              name TEXT NOT NULL,
              source TEXT NOT NULL,
              path TEXT NOT NULL,
              kind TEXT NOT NULL,
              metadata_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL,
              image_id TEXT NOT NULL,
              computer_id TEXT,
              source_scope TEXT NOT NULL DEFAULT 'live',
              tool_name TEXT NOT NULL,
              tool_version TEXT,
              command_json TEXT NOT NULL,
              start_time TEXT NOT NULL,
              end_time TEXT,
              exit_code INTEGER,
              stdout_path TEXT NOT NULL,
              stderr_path TEXT NOT NULL,
              output_folder TEXT NOT NULL,
              dry_run INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS process_timings (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT REFERENCES computers(id),
              image_id TEXT REFERENCES images(id),
              parent_id TEXT REFERENCES process_timings(id),
              job_id TEXT REFERENCES jobs(id),
              source_scope TEXT NOT NULL DEFAULT 'live',
              scope TEXT NOT NULL,
              phase TEXT NOT NULL,
              name TEXT NOT NULL,
              tool_name TEXT,
              artifact_name TEXT,
              status TEXT NOT NULL,
              start_time TEXT NOT NULL,
              end_time TEXT,
              duration_ms INTEGER,
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_process_timings_case_start
              ON process_timings(case_id, start_time);
            CREATE INDEX IF NOT EXISTS idx_process_timings_case_scope
              ON process_timings(case_id, scope, phase, status);
            CREATE INDEX IF NOT EXISTS idx_process_timings_parent
              ON process_timings(parent_id);

            CREATE TABLE IF NOT EXISTS tool_outputs (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              job_id TEXT REFERENCES jobs(id),
              tool_name TEXT NOT NULL,
              output_type TEXT NOT NULL,
              path TEXT NOT NULL,
              content_sha256 TEXT,
              row_count INTEGER,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS carve_scan_ranges (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              profile TEXT,
              carve_type TEXT,
              source_path TEXT NOT NULL,
              source_size TEXT,
              range_start TEXT,
              range_end TEXT,
              scanned_bytes TEXT,
              hits_found TEXT,
              limited TEXT,
              limit_reason TEXT,
              status TEXT,
              notes TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_carve_scan_ranges_case
              ON carve_scan_ranges(case_id, carve_type, source_path);

            CREATE TABLE IF NOT EXISTS staged_carves (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              profile TEXT,
              source_path TEXT NOT NULL,
              source_offset TEXT,
              staged_path TEXT NOT NULL,
              staged_name TEXT,
              staged_size TEXT,
              staged_sha256 TEXT,
              carve_type TEXT,
              detected_format TEXT,
              parser_status TEXT,
              parser_error TEXT,
              table_count TEXT,
              object_count TEXT,
              extractable_row_count TEXT,
              import_status TEXT,
              notes TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_staged_carves_case
              ON staged_carves(case_id, carve_type, parser_status);

            CREATE TABLE IF NOT EXISTS parsed_rows (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_path TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              row_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_parsed_rows_case_tool
              ON parsed_rows(case_id, tool_name);
            CREATE INDEX IF NOT EXISTS idx_parsed_rows_computer_tool
              ON parsed_rows(computer_id, tool_name);
            CREATE INDEX IF NOT EXISTS idx_parsed_rows_output
              ON parsed_rows(tool_output_id);

            CREATE TABLE IF NOT EXISTS shortcut_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              artifact_type TEXT NOT NULL,
              artifact_name TEXT,
              artifact_path TEXT,
              file_name TEXT,
              file_location TEXT,
              target_created TEXT,
              target_modified TEXT,
              target_accessed TEXT,
              device_type TEXT,
              volume_serial_number TEXT,
              volume_name TEXT,
              local_path TEXT,
              common_path TEXT,
              target_path TEXT,
              relative_path TEXT,
              command_line_arguments TEXT,
              working_directory TEXT,
              network_path TEXT,
              icon_location TEXT,
              hot_key TEXT,
              window_style TEXT,
              header_flags TEXT,
              link_flags TEXT,
              target_id_absolute_path TEXT,
              target_mft_entry_number TEXT,
              target_mft_sequence_number TEXT,
              machine_name TEXT,
              machine_mac_address TEXT,
              tracker_created_on TEXT,
              tracker_id TEXT,
              droid_volume_id TEXT,
              droid_file_id TEXT,
              birth_droid_volume_id TEXT,
              birth_droid_file_id TEXT,
              app_id TEXT,
              app_id_description TEXT,
              entry_id TEXT,
              destlist_version TEXT,
              lnk_created TEXT,
              lnk_modified TEXT,
              lnk_accessed TEXT,
              jumplist_item_number TEXT,
              source_scope TEXT DEFAULT 'live',
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_shortcut_items_case_type
              ON shortcut_items(case_id, artifact_type);
            CREATE INDEX IF NOT EXISTS idx_shortcut_items_computer_type
              ON shortcut_items(computer_id, artifact_type);
            CREATE INDEX IF NOT EXISTS idx_shortcut_items_output
              ON shortcut_items(tool_output_id);

            CREATE TABLE IF NOT EXISTS usb_file_correlations (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              usb_serial TEXT NOT NULL,
              usb_volume_serial_number TEXT NOT NULL,
              usb_volume_name TEXT,
              usb_drive_letter TEXT,
              usb_vendor_id TEXT,
              usb_product_id TEXT,
              usb_vendor TEXT,
              usb_product TEXT,
              usb_friendly_name TEXT,
              usb_file_system TEXT,
              usb_vbr_file_system TEXT,
              usb_first_install_date_utc TEXT,
              usb_last_arrival_utc TEXT,
              usb_last_removal_utc TEXT,
              source_artifact_type TEXT NOT NULL,
              source_artifact_id TEXT,
              source_artifact_name TEXT,
              source_artifact_path TEXT,
              user_profile TEXT,
              jumplist_item_number TEXT,
              file_name TEXT,
              file_location TEXT,
              target_created TEXT,
              target_modified TEXT,
              target_accessed TEXT,
              target_accessed_original TEXT,
              target_accessed_precision TEXT,
              target_accessed_note TEXT,
              device_type TEXT,
              artifact_volume_serial_number TEXT,
              artifact_volume_name TEXT,
              artifact_volume_guid TEXT,
              artifact_drive_letter TEXT,
              temporal_status TEXT,
              temporal_basis TEXT,
              first_known_connection_utc TEXT,
              last_known_connection_utc TEXT,
              nearest_connection_before_utc TEXT,
              nearest_removal_after_utc TEXT,
              volume_serial_match TEXT NOT NULL,
              confidence TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_usb_file_correlations_case
              ON usb_file_correlations(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_usb_file_correlations_usb
              ON usb_file_correlations(case_id, usb_serial, usb_volume_serial_number);

            CREATE TABLE IF NOT EXISTS prefetch_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              prefetch_name TEXT,
              artifact_path TEXT,
              original_path TEXT,
              executable_name TEXT,
              prefetch_hash TEXT,
              prefetch_version TEXT,
              prefetch_version_label TEXT,
              compression TEXT,
              run_count TEXT,
              last_run_time_utc TEXT,
              last_run_times_utc TEXT,
              referenced_string_count TEXT,
              referenced_strings TEXT,
              parser_note TEXT,
              resolved_reference_path TEXT,
              resolved_reference_device_path TEXT,
              resolved_reference_command_line TEXT,
              resolved_reference_os TEXT,
              resolved_reference_description TEXT,
              resolved_reference_source TEXT,
              resolved_reference_match_count TEXT,
              pf_created TEXT,
              pf_modified TEXT,
              pf_accessed TEXT,
              pf_mft_record_modified TEXT,
              source_scope TEXT DEFAULT 'live',
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_prefetch_items_case
              ON prefetch_items(case_id);
            CREATE INDEX IF NOT EXISTS idx_prefetch_items_computer
              ON prefetch_items(computer_id);
            CREATE INDEX IF NOT EXISTS idx_prefetch_items_output
              ON prefetch_items(tool_output_id);
            CREATE INDEX IF NOT EXISTS idx_prefetch_items_case_exe_time
              ON prefetch_items(case_id, executable_name, last_run_time_utc);

            CREATE TABLE IF NOT EXISTS prefetch_run_times (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              prefetch_item_id TEXT NOT NULL,
              prefetch_name TEXT,
              executable_name TEXT,
              prefetch_hash TEXT,
              artifact_path TEXT,
              original_path TEXT,
              run_index TEXT,
              run_time_utc TEXT NOT NULL,
              is_last_run TEXT,
              source_scope TEXT DEFAULT 'live',
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_prefetch_run_times_case_time
              ON prefetch_run_times(case_id, run_time_utc);
            CREATE INDEX IF NOT EXISTS idx_prefetch_run_times_item
              ON prefetch_run_times(prefetch_item_id);

            CREATE TABLE IF NOT EXISTS sam_accounts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              username TEXT,
              rid TEXT,
              rid_hex TEXT,
              account_category TEXT,
              last_login_utc TEXT,
              password_last_set_utc TEXT,
              last_bad_password_utc TEXT,
              account_expires_utc TEXT,
              logon_count TEXT,
              bad_password_count TEXT,
              account_flags_hex TEXT,
              account_flags TEXT,
              account_flags_unknown_hex TEXT,
              registry_path TEXT,
              account_key_last_write_utc TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sam_accounts_case
              ON sam_accounts(case_id);
            CREATE INDEX IF NOT EXISTS idx_sam_accounts_computer
              ON sam_accounts(computer_id);
            CREATE INDEX IF NOT EXISTS idx_sam_accounts_output
              ON sam_accounts(tool_output_id);

            CREATE TABLE IF NOT EXISTS registry_hives (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              original_path TEXT,
              hive_name TEXT,
              hive_type TEXT,
              size TEXT,
              sha256 TEXT,
              header_valid TEXT,
              key_count TEXT,
              value_count TEXT,
              parser_error TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_registry_hives_case
              ON registry_hives(case_id);
            CREATE INDEX IF NOT EXISTS idx_registry_hives_output
              ON registry_hives(tool_output_id);

            CREATE TABLE IF NOT EXISTS registry_artifacts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              hive_type TEXT,
              user_profile TEXT,
              user_sid TEXT,
              artifact TEXT,
              category TEXT,
              key_path TEXT,
              key_last_write_utc TEXT,
              event_time_utc TEXT,
              recentdocs_time_utc TEXT,
              recentdocs_extension_time_utc TEXT,
              mru_position TEXT,
              recentdocs_mru_position TEXT,
              recentdocs_extension_mru_position TEXT,
              is_most_recent TEXT,
              value_name TEXT,
              value_type TEXT,
              value_data TEXT,
              display_name TEXT,
              normalized_path TEXT,
              run_counter TEXT,
              focus_count TEXT,
              focus_time TEXT,
              last_executed TEXT,
              value_data_hex TEXT,
              transaction_logs_detected TEXT,
              transaction_logs_applied TEXT,
              transaction_log_paths TEXT,
              source_scope TEXT DEFAULT 'live',
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              notes TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_registry_artifacts_case
              ON registry_artifacts(case_id, artifact);
            CREATE INDEX IF NOT EXISTS idx_registry_artifacts_user
              ON registry_artifacts(case_id, user_profile);
            CREATE INDEX IF NOT EXISTS idx_registry_artifacts_output
              ON registry_artifacts(tool_output_id);
            CREATE INDEX IF NOT EXISTS idx_registry_artifacts_case_artifact_time
              ON registry_artifacts(case_id, artifact, event_time_utc, key_last_write_utc);

            CREATE TABLE IF NOT EXISTS registry_common_dialog_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL,
              source_registry_artifact_id TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              source_path TEXT,
              hive_type TEXT,
              user_profile TEXT,
              artifact TEXT,
              key_path TEXT,
              key_last_write_utc TEXT,
              mru_position TEXT,
              value_name TEXT,
              item_index INTEGER,
              shell_item_name TEXT,
              shell_created TEXT,
              shell_modified TEXT,
              shell_accessed TEXT,
              raw_fat_times_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_registry_common_dialog_items_case
              ON registry_common_dialog_items(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_registry_common_dialog_items_source
              ON registry_common_dialog_items(source_registry_artifact_id);

            CREATE TABLE IF NOT EXISTS registry_recentdocs (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              hive_path TEXT, hive_type TEXT, user_profile TEXT, category TEXT, key_path TEXT,
              key_last_write_timestamp TEXT, recmd_description TEXT,
              extension TEXT, batch_key_path TEXT, value_name TEXT, batch_value_name TEXT,
              target_name TEXT, lnk_name TEXT, mru_position TEXT, opened_on TEXT,
              extension_last_opened TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_runmru (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              hive_path TEXT, hive_type TEXT, user_profile TEXT, category TEXT, key_path TEXT,
              key_last_write_timestamp TEXT, recmd_description TEXT,
              value_name TEXT, batch_key_path TEXT, mru_position TEXT, batch_value_name TEXT,
              executable TEXT, opened_on TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_typedpaths (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              hive_path TEXT, hive_type TEXT, user_profile TEXT, category TEXT, key_path TEXT,
              key_last_write_timestamp TEXT, recmd_description TEXT,
              value_name TEXT, batch_key_path TEXT, mru_position TEXT, batch_value_name TEXT,
              path TEXT, opened_on TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_wordwheel_query (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              hive_path TEXT, hive_type TEXT, user_profile TEXT, category TEXT, key_path TEXT,
              key_last_write_timestamp TEXT, recmd_description TEXT,
              search_term TEXT, batch_key_path TEXT, mru_position TEXT, batch_value_name TEXT,
              key_name TEXT, last_write_timestamp TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_userassist (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              hive_path TEXT, hive_type TEXT, user_profile TEXT, category TEXT, key_path TEXT,
              key_last_write_timestamp TEXT, recmd_description TEXT,
              batch_key_path TEXT, batch_value_name TEXT, program_name TEXT, run_counter TEXT,
              focus_count TEXT, focus_time TEXT, last_executed TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_office_mru (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              hive_path TEXT, hive_type TEXT, user_profile TEXT, category TEXT, key_path TEXT,
              key_last_write_timestamp TEXT, recmd_description TEXT,
              value_name TEXT, batch_key_path TEXT, last_opened TEXT, batch_value_name TEXT,
              last_closed TEXT, file_name TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_common_dialog_mru (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              hive_path TEXT, hive_type TEXT, user_profile TEXT, category TEXT, key_path TEXT,
              key_last_write_timestamp TEXT, recmd_description TEXT,
              artifact TEXT, extension TEXT, value_name TEXT, batch_key_path TEXT,
              mru_position TEXT, batch_value_name TEXT, executable TEXT, absolute_path TEXT,
              opened_on TEXT, details TEXT, executable_is_guid TEXT, resolved_executable TEXT,
              executable_resolution_source TEXT, executable_resolution_confidence TEXT,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_trusted_documents (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              hive_path TEXT, hive_type TEXT, user_profile TEXT, category TEXT, key_path TEXT,
              key_last_write_timestamp TEXT, recmd_description TEXT,
              event_type TEXT, batch_key_path TEXT, timestamp TEXT, batch_value_name TEXT,
              file_name TEXT, username TEXT, created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS registry_office_trust_records (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              source_path TEXT, hive_type TEXT, user_profile TEXT, trust_type TEXT,
              office_version TEXT, application TEXT, location_id TEXT, key_path TEXT,
              key_last_write_utc TEXT, event_time_utc TEXT, value_name TEXT,
              value_type TEXT, value_data TEXT, path_or_file TEXT,
              allow_subfolders TEXT, allow_network_location TEXT, permission_flags TEXT,
              permitted_editing TEXT, permitted_macros_or_scripts TEXT,
              details_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_office_trust_case_user
              ON registry_office_trust_records(case_id, user_profile);
            CREATE INDEX IF NOT EXISTS idx_office_trust_case_type
              ON registry_office_trust_records(case_id, trust_type);

            CREATE TABLE IF NOT EXISTS registry_taskbar_feature_usage (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              source_path TEXT, hive_type TEXT, user_profile TEXT, artifact TEXT,
              feature TEXT, key_path TEXT, key_last_write_utc TEXT, event_time_utc TEXT,
              value_name TEXT, value_type TEXT, value_data TEXT, usage_count INTEGER,
              details_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_taskbar_feature_case_user
              ON registry_taskbar_feature_usage(case_id, user_profile);
            CREATE INDEX IF NOT EXISTS idx_taskbar_feature_case_feature
              ON registry_taskbar_feature_usage(case_id, feature);

            CREATE TABLE IF NOT EXISTS registry_taskbar_pins (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              source_path TEXT, hive_type TEXT, user_profile TEXT, pin_order INTEGER,
              pin_name TEXT, target_hint TEXT, key_path TEXT, key_last_write_utc TEXT,
              details_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_taskbar_pins_case_user
              ON registry_taskbar_pins(case_id, user_profile);

            CREATE INDEX IF NOT EXISTS idx_registry_recentdocs_case
              ON registry_recentdocs(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_registry_runmru_case
              ON registry_runmru(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_registry_wordwheel_case
              ON registry_wordwheel_query(case_id, image_id);

            CREATE TABLE IF NOT EXISTS amcache_entries (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              entry_type TEXT, source_file TEXT, path TEXT, name TEXT, publisher TEXT,
              product_name TEXT, product_version TEXT, file_version TEXT, sha1 TEXT,
              sha256 TEXT, binary_type TEXT, size TEXT, created_utc TEXT, modified_utc TEXT,
              link_date TEXT, compile_time TEXT, program_id TEXT, install_date TEXT,
              unassociated TEXT, source_scope TEXT DEFAULT 'live', snapshot_id TEXT,
              snapshot_ids TEXT, snapshot_count TEXT, snapshot_index TEXT,
              snapshot_created_utc TEXT, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_amcache_entries_case
              ON amcache_entries(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_amcache_entries_path
              ON amcache_entries(case_id, path);

            CREATE TABLE IF NOT EXISTS shimcache_entries (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              source_file TEXT, control_set TEXT, entry_number TEXT, path TEXT,
              last_modified_utc TEXT, executed TEXT, source_key TEXT,
              source_scope TEXT DEFAULT 'live', snapshot_id TEXT, snapshot_ids TEXT,
              snapshot_count TEXT, snapshot_index TEXT, snapshot_created_utc TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_shimcache_entries_case
              ON shimcache_entries(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_shimcache_entries_path
              ON shimcache_entries(case_id, path);

            CREATE TABLE IF NOT EXISTS shellbag_entries (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              source_file TEXT, hive_path TEXT, user_profile TEXT, absolute_path TEXT,
              shell_type TEXT, value_name TEXT, mru_position TEXT, slot TEXT, node_slot TEXT,
              created_on TEXT, modified_on TEXT, accessed_on TEXT, last_write_time TEXT,
              first_interacted TEXT, last_interacted TEXT,
              has_explored TEXT, drive_letter TEXT, volume_guid TEXT,
              volume_serial_number TEXT, volume_name TEXT, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_shellbag_entries_case
              ON shellbag_entries(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_shellbag_entries_user
              ON shellbag_entries(case_id, user_profile);

            CREATE TABLE IF NOT EXISTS usb_devices (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, tool_output_id TEXT NOT NULL, tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL, row_number INTEGER NOT NULL,
              source_path TEXT, artifact TEXT, device_type TEXT, vendor_id TEXT,
              product_id TEXT, vendor TEXT, product TEXT, revision TEXT, friendly_name TEXT, serial TEXT,
              instance_id TEXT, parent_id_prefix TEXT, device_service TEXT,
              user_profile TEXT, drive_letter TEXT, volume_guid TEXT,
              volume_serial_number TEXT, volume_name TEXT, capacity_bytes TEXT,
              file_system TEXT, alternate_scsi_serial TEXT,
              partition_disk_number TEXT, partition_bus_type TEXT, partition_bus_type_code TEXT,
              partition_user_removal_policy TEXT, partition_bytes_per_sector TEXT,
              partition_bytes_per_logical_sector TEXT, partition_bytes_per_physical_sector TEXT,
              partition_style TEXT, partition_style_code TEXT, partition_count TEXT,
              partition_table_bytes TEXT, partition_table_sha256 TEXT,
              partition_table_summary TEXT, partition_table_disk_guid TEXT,
              storage_id_code_set TEXT, storage_id_type TEXT, storage_id_association TEXT,
              storage_id_bytes TEXT, storage_id_hex TEXT, storage_id_ascii TEXT,
              storage_id_sha256 TEXT, partition_registry_id TEXT, partition_adapter_id TEXT,
              partition_pool_id TEXT, partition_location TEXT, partition_flags TEXT,
              partition_characteristics TEXT,
              vbr_index TEXT, vbr_bytes TEXT, vbr_oem_name TEXT,
              vbr_file_system TEXT, vbr_volume_serial_number TEXT,
              vbr_volume_serial_number_full TEXT, vbr_volume_name TEXT,
              vbr_parse_status TEXT, vbr_serial_match TEXT,
              mbr_partition_type TEXT, partition_start_lba TEXT, partition_sector_count TEXT,
              key_path TEXT, key_last_write_utc TEXT, last_present_date_utc TEXT,
              property_name TEXT, property_value TEXT, value_data_hex TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_usb_devices_case
              ON usb_devices(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_usb_devices_serial
              ON usb_devices(case_id, serial);

            CREATE TABLE IF NOT EXISTS setupapi_device_events (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL,
              computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL,
              tool_output_id TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              line_number INTEGER,
              section_title TEXT,
              operation TEXT,
              device_instance_id TEXT,
              device_class TEXT,
              vendor_id TEXT,
              product_id TEXT,
              serial TEXT,
              service TEXT,
              inf_path TEXT,
              driver_package TEXT,
              start_time_utc TEXT,
              end_time_utc TEXT,
              event_time_utc TEXT,
              status TEXT,
              confidence TEXT,
              details_json TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_setupapi_device_events_case_time
              ON setupapi_device_events(case_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_setupapi_device_events_case_serial
              ON setupapi_device_events(case_id, serial);

            CREATE TABLE IF NOT EXISTS usb_storage_devices (
              id TEXT PRIMARY KEY, case_id TEXT NOT NULL, computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL, serial TEXT NOT NULL,
              vendor_id TEXT, product_id TEXT, vendor TEXT, product TEXT, revision TEXT,
              friendly_name TEXT, parent_id_prefix TEXT, device_service TEXT,
              drive_letter TEXT, volume_guid TEXT, volume_serial_number TEXT,
              volume_name TEXT, capacity_bytes TEXT, file_system TEXT, alternate_scsi_serial TEXT,
              partition_disk_number TEXT, partition_bus_type TEXT, partition_bus_type_code TEXT,
              partition_user_removal_policy TEXT, partition_bytes_per_sector TEXT,
              partition_bytes_per_logical_sector TEXT, partition_bytes_per_physical_sector TEXT,
              partition_style TEXT, partition_style_code TEXT, partition_count TEXT,
              partition_table_bytes TEXT, partition_table_sha256 TEXT,
              partition_table_summary TEXT, partition_table_disk_guid TEXT,
              storage_id_code_set TEXT, storage_id_type TEXT, storage_id_association TEXT,
              storage_id_bytes TEXT, storage_id_hex TEXT, storage_id_ascii TEXT,
              storage_id_sha256 TEXT, partition_registry_id TEXT, partition_adapter_id TEXT,
              partition_pool_id TEXT, partition_location TEXT, partition_flags TEXT,
              partition_characteristics TEXT,
              vbr_oem_name TEXT, vbr_file_system TEXT, vbr_volume_serial_number TEXT,
              vbr_volume_serial_number_full TEXT, vbr_volume_name TEXT,
              vbr_parse_status TEXT, vbr_serial_match TEXT,
              mbr_partition_type TEXT, partition_start_lba TEXT, partition_sector_count TEXT,
              user_profiles TEXT, first_install_date_utc TEXT,
              last_arrival_utc TEXT, last_removal_utc TEXT, first_volume_serial_event_utc TEXT,
              last_partition_event_utc TEXT, last_migration_present_utc TEXT,
              evidence_row_count INTEGER NOT NULL DEFAULT 0,
              source_artifacts TEXT, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_usb_storage_devices_case
              ON usb_storage_devices(case_id, image_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_usb_storage_devices_unique
              ON usb_storage_devices(case_id, image_id, serial);

            CREATE TABLE IF NOT EXISTS usb_connection_events (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL,
              computer_id TEXT NOT NULL,
              image_id TEXT NOT NULL,
              usb_device_id TEXT,
              serial TEXT NOT NULL,
              volume_serial_number TEXT,
              volume_guid TEXT,
              drive_letter TEXT,
              event_time_utc TEXT NOT NULL,
              event_type TEXT NOT NULL,
              event_source TEXT,
              event_id TEXT,
              record_number TEXT,
              source_path TEXT,
              key_path TEXT,
              property_name TEXT,
              property_value TEXT,
              capacity_bytes TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_usb_connection_events_case
              ON usb_connection_events(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_usb_connection_events_serial_time
              ON usb_connection_events(case_id, serial, event_time_utc);

            CREATE TABLE IF NOT EXISTS mft_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              entry_number TEXT,
              sequence_number TEXT,
              in_use TEXT,
              parent_entry_number TEXT,
              parent_sequence_number TEXT,
              parent_path TEXT,
              file_name TEXT,
              extension TEXT,
              file_size TEXT,
              is_directory TEXT,
              has_ads TEXT,
              is_ads TEXT,
              si_flags TEXT,
              reparse_target TEXT,
              object_id TEXT,
              birth_volume_id TEXT,
              birth_object_id TEXT,
              birth_domain_id TEXT,
              si_fn_copied TEXT,
              created_si TEXT,
              created_fn TEXT,
              modified_si TEXT,
              modified_fn TEXT,
              record_changed_si TEXT,
              record_changed_fn TEXT,
              accessed_si TEXT,
              accessed_fn TEXT,
              source_file TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_mft_entries_case_name
              ON mft_entries(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_mft_entries_computer
              ON mft_entries(computer_id);
            CREATE INDEX IF NOT EXISTS idx_mft_entries_output
              ON mft_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS filesystem_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              partition_id TEXT,
              filesystem_type TEXT,
              source_root TEXT,
              file_path TEXT,
              parent_path TEXT,
              file_name TEXT,
              extension TEXT,
              file_size TEXT,
              is_directory TEXT,
              created_utc TEXT,
              modified_utc TEXT,
              accessed_utc TEXT,
              metadata_changed_utc TEXT,
              mode TEXT,
              uid TEXT,
              gid TEXT,
              scan_status TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_filesystem_entries_case_path
              ON filesystem_entries(case_id, file_path);
            CREATE INDEX IF NOT EXISTS idx_filesystem_entries_case_name
              ON filesystem_entries(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_filesystem_entries_output
              ON filesystem_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS usn_journal_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_file TEXT,
              update_sequence_number TEXT,
              update_timestamp TEXT,
              file_name TEXT,
              extension TEXT,
              file_reference_number TEXT,
              file_reference_sequence_number TEXT,
              parent_file_reference_number TEXT,
              parent_file_reference_sequence_number TEXT,
              full_path TEXT,
              reason TEXT,
              reason_flags TEXT,
              file_attributes TEXT,
              file_attributes_flags TEXT,
              source_info TEXT,
              security_id TEXT,
              major_version TEXT,
              minor_version TEXT,
              record_length TEXT,
              offset TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_usn_journal_entries_case_time
              ON usn_journal_entries(case_id, update_timestamp);
            CREATE INDEX IF NOT EXISTS idx_usn_journal_entries_case_name
              ON usn_journal_entries(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_usn_journal_entries_output
              ON usn_journal_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS vsc_mft_deltas (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              source_scope TEXT,
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              delta_type TEXT NOT NULL,
              entry_number TEXT,
              sequence_number TEXT,
              in_use TEXT,
              parent_entry_number TEXT,
              parent_sequence_number TEXT,
              normalized_path TEXT,
              path_key TEXT,
              file_name TEXT,
              extension TEXT,
              file_size TEXT,
              is_directory TEXT,
              has_ads TEXT,
              is_ads TEXT,
              si_flags TEXT,
              reparse_target TEXT,
              created_si TEXT,
              modified_si TEXT,
              record_changed_si TEXT,
              accessed_si TEXT,
              record_signature TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vsc_mft_deltas_case_path
              ON vsc_mft_deltas(case_id, image_id, path_key);
            CREATE INDEX IF NOT EXISTS idx_vsc_mft_deltas_case_snapshot
              ON vsc_mft_deltas(case_id, image_id, snapshot_id);

            CREATE TABLE IF NOT EXISTS vsc_usn_deltas (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              source_scope TEXT,
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              delta_type TEXT NOT NULL,
              update_sequence_number TEXT,
              update_timestamp TEXT,
              file_name TEXT,
              extension TEXT,
              file_reference_number TEXT,
              file_reference_sequence_number TEXT,
              parent_file_reference_number TEXT,
              parent_file_reference_sequence_number TEXT,
              normalized_path TEXT,
              path_key TEXT,
              reason TEXT,
              file_attributes TEXT,
              record_signature TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vsc_usn_deltas_case_time
              ON vsc_usn_deltas(case_id, image_id, update_timestamp);
            CREATE INDEX IF NOT EXISTS idx_vsc_usn_deltas_case_snapshot
              ON vsc_usn_deltas(case_id, image_id, snapshot_id);

            CREATE TABLE IF NOT EXISTS ntfs_index_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              directory_entry_number TEXT,
              directory_path TEXT,
              source TEXT,
              block_vcn TEXT,
              block_active TEXT,
              entry_offset TEXT,
              index_entry_length TEXT,
              index_entry_flags TEXT,
              referenced_entry_number TEXT,
              referenced_sequence_number TEXT,
              parent_entry_number TEXT,
              parent_sequence_number TEXT,
              file_name TEXT,
              name_type TEXT,
              name_type_label TEXT,
              created_fn TEXT,
              modified_fn TEXT,
              record_changed_fn TEXT,
              accessed_fn TEXT,
              allocated_size TEXT,
              real_size TEXT,
              file_flags TEXT,
              from_slack TEXT,
              source_file TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ntfs_index_entries_case_dir
              ON ntfs_index_entries(case_id, directory_entry_number);
            CREATE INDEX IF NOT EXISTS idx_ntfs_index_entries_case_ref
              ON ntfs_index_entries(case_id, referenced_entry_number);
            CREATE INDEX IF NOT EXISTS idx_ntfs_index_entries_output
              ON ntfs_index_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS ntfs_index_bitmaps (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              directory_entry_number TEXT,
              directory_path TEXT,
              index_root_attr TEXT,
              index_allocation_attr TEXT,
              bitmap_attr TEXT,
              bitmap_hex TEXT,
              active_block_count TEXT,
              active_blocks TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ntfs_index_bitmaps_case_dir
              ON ntfs_index_bitmaps(case_id, directory_entry_number);
            CREATE INDEX IF NOT EXISTS idx_ntfs_index_bitmaps_output
              ON ntfs_index_bitmaps(tool_output_id);

            CREATE TABLE IF NOT EXISTS ntfs_namespace_reconciliation (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              mft_entry_number TEXT NOT NULL,
              mft_sequence_number TEXT,
              parent_entry_number TEXT,
              parent_path TEXT,
              file_name TEXT,
              original_path TEXT,
              mft_in_use TEXT,
              mounted_present TEXT,
              parent_mounted_exists TEXT,
              parent_access_status TEXT,
              index_status TEXT NOT NULL,
              legit_active_file TEXT NOT NULL,
              index_entry_id TEXT,
              index_from_slack TEXT,
              index_block_active TEXT,
              index_bitmap_error TEXT,
              icat_recovered TEXT,
              recovered_size TEXT,
              recovered_sha256 TEXT,
              header_type TEXT,
              zero_prefix TEXT,
              reason TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ntfs_namespace_reconciliation_case
              ON ntfs_namespace_reconciliation(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_ntfs_namespace_reconciliation_mft
              ON ntfs_namespace_reconciliation(case_id, mft_entry_number);

            CREATE TABLE IF NOT EXISTS ntfs_logfile_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_file TEXT,
              event_time TEXT,
              operation TEXT,
              redo_operation TEXT,
              undo_operation TEXT,
              target_attribute TEXT,
              file_name TEXT,
              file_path TEXT,
              file_reference_number TEXT,
              file_reference_sequence_number TEXT,
              parent_file_reference_number TEXT,
              parent_file_reference_sequence_number TEXT,
              log_sequence_number TEXT,
              previous_log_sequence_number TEXT,
              transaction_id TEXT,
              client_id TEXT,
              record_offset TEXT,
              row_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ntfs_logfile_entries_case_time
              ON ntfs_logfile_entries(case_id, event_time);
            CREATE INDEX IF NOT EXISTS idx_ntfs_logfile_entries_case_name
              ON ntfs_logfile_entries(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_ntfs_logfile_entries_output
              ON ntfs_logfile_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS filesystem_review (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              source_table TEXT NOT NULL,
              source_id TEXT NOT NULL,
              source_tool TEXT,
              source_row_number INTEGER,
              event_type TEXT NOT NULL,
              event_time TEXT,
              file_name TEXT,
              file_path TEXT,
              parent_path TEXT,
              mft_entry_number TEXT,
              mft_sequence_number TEXT,
              parent_entry_number TEXT,
              parent_sequence_number TEXT,
              in_use TEXT,
              is_directory TEXT,
              operation TEXT,
              reason TEXT,
              status TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_filesystem_review_case_time
              ON filesystem_review(case_id, event_time);
            CREATE INDEX IF NOT EXISTS idx_filesystem_review_case_path
              ON filesystem_review(case_id, file_path);
            CREATE INDEX IF NOT EXISTS idx_filesystem_review_case_mft
              ON filesystem_review(case_id, image_id, mft_entry_number);
            CREATE INDEX IF NOT EXISTS idx_filesystem_review_source
              ON filesystem_review(source_table, source_id);

            CREATE TABLE IF NOT EXISTS srum_records (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              provider_guid TEXT,
              provider_name TEXT,
              source_table TEXT,
              record_type TEXT,
              srum_id TEXT,
              timestamp TEXT,
              app_id TEXT,
              app_name TEXT,
              app_path TEXT,
              app_description TEXT,
              exe_timestamp TEXT,
              user_id TEXT,
              user_sid TEXT,
              user_name TEXT,
              bytes_received TEXT,
              bytes_sent TEXT,
              interface_luid TEXT,
              interface_type TEXT,
              l2_profile_id TEXT,
              l2_profile_name TEXT,
              l2_profile_flags TEXT,
              connected_time TEXT,
              connect_start_time TEXT,
              connect_end_time TEXT,
              notification_type TEXT,
              payload_size TEXT,
              network_type TEXT,
              foreground_bytes_read TEXT,
              foreground_bytes_written TEXT,
              background_bytes_read TEXT,
              background_bytes_written TEXT,
              foreground_cycle_time TEXT,
              background_cycle_time TEXT,
              face_time TEXT,
              foreground_context_switches TEXT,
              background_context_switches TEXT,
              foreground_read_operations TEXT,
              foreground_write_operations TEXT,
              background_read_operations TEXT,
              background_write_operations TEXT,
              foreground_flushes TEXT,
              background_flushes TEXT,
              flags TEXT,
              start_time TEXT,
              end_time TEXT,
              duration_ms TEXT,
              span_ms TEXT,
              timeline_end TEXT,
              event_timestamp TEXT,
              state_transition TEXT,
              charge_level TEXT,
              cycle_count TEXT,
              designed_capacity TEXT,
              full_charged_capacity TEXT,
              active_ac_time TEXT,
              active_dc_time TEXT,
              active_discharge_time TEXT,
              active_energy TEXT,
              cs_ac_time TEXT,
              cs_dc_time TEXT,
              cs_discharge_time TEXT,
              cs_energy TEXT,
              configuration_hash TEXT,
              metadata TEXT,
              energy_data TEXT,
              tag TEXT,
              binary_data TEXT,
              vpn_profile_name TEXT,
              vpn_server TEXT,
              vpn_device TEXT,
              vpn_protocol TEXT,
              vpn_phonebook_path TEXT,
              vpn_match_method TEXT,
              source_scope TEXT DEFAULT 'live',
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              row_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_srum_records_case_type_time
              ON srum_records(case_id, record_type, timestamp);
            CREATE INDEX IF NOT EXISTS idx_srum_records_output
              ON srum_records(tool_output_id);

            CREATE TABLE IF NOT EXISTS ual_records (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              database_file TEXT,
              source_table TEXT,
              record_id TEXT,
              role_guid TEXT,
              role_name TEXT,
              product_name TEXT,
              tenant_id TEXT,
              user_sid TEXT,
              user_name TEXT,
              client_name TEXT,
              client_ip TEXT,
              client_id TEXT,
              first_seen TEXT,
              last_seen TEXT,
              insert_date TEXT,
              last_access TEXT,
              access_count TEXT,
              activity_count TEXT,
              day_count TEXT,
              raw_time_bucket TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ual_records_case_client
              ON ual_records(case_id, client_name, client_ip);
            CREATE INDEX IF NOT EXISTS idx_ual_records_case_time
              ON ual_records(case_id, first_seen, last_seen, last_access);
            CREATE INDEX IF NOT EXISTS idx_ual_records_output
              ON ual_records(tool_output_id);

            CREATE TABLE IF NOT EXISTS bits_jobs (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              database_file TEXT,
              source_table TEXT,
              record_id TEXT,
              record_type TEXT,
              job_id TEXT,
              job_name TEXT,
              job_owner TEXT,
              job_state TEXT,
              job_type TEXT,
              priority TEXT,
              created_utc TEXT,
              modified_utc TEXT,
              completed_utc TEXT,
              expiration_utc TEXT,
              url TEXT,
              local_path TEXT,
              remote_name TEXT,
              file_size TEXT,
              bytes_transferred TEXT,
              raw_row_json TEXT NOT NULL DEFAULT '{}',
              parser_status TEXT,
              parser_error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bits_jobs_case_time
              ON bits_jobs(case_id, created_utc, modified_utc, completed_utc);
            CREATE INDEX IF NOT EXISTS idx_bits_jobs_case_job
              ON bits_jobs(case_id, job_id);
            CREATE INDEX IF NOT EXISTS idx_bits_jobs_case_url
              ON bits_jobs(case_id, url);
            CREATE INDEX IF NOT EXISTS idx_bits_jobs_output
              ON bits_jobs(tool_output_id);

            CREATE TABLE IF NOT EXISTS bits_activity (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_table TEXT NOT NULL,
              source_row_id TEXT,
              event_time_utc TEXT,
              event_id TEXT,
              event_type TEXT,
              provider TEXT,
              channel TEXT,
              computer TEXT,
              job_id TEXT,
              job_name TEXT,
              job_owner TEXT,
              url TEXT,
              peer TEXT,
              file_count TEXT,
              total_bytes TEXT,
              bytes_transferred TEXT,
              local_path TEXT,
              matched_bits_job_id TEXT,
              correlation_basis TEXT,
              raw_fields_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bits_activity_case_time
              ON bits_activity(case_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_bits_activity_case_job
              ON bits_activity(case_id, job_id);
            CREATE INDEX IF NOT EXISTS idx_bits_activity_case_url
              ON bits_activity(case_id, url);
            CREATE INDEX IF NOT EXISTS idx_bits_activity_output
              ON bits_activity(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_files (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              work_id TEXT,
              gather_time TEXT,
              item_path TEXT,
              item_url TEXT,
              folder_path TEXT,
              file_name TEXT,
              file_extension TEXT,
              item_type TEXT,
              date_created TEXT,
              date_modified TEXT,
              date_accessed TEXT,
              date_imported TEXT,
              size TEXT,
              owner TEXT,
              computer_name TEXT,
              is_deleted TEXT,
              is_folder TEXT,
              source_scope TEXT DEFAULT 'live',
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              row_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_files_case_time
              ON windows_search_files(case_id, gather_time);
            CREATE INDEX IF NOT EXISTS idx_windows_search_files_path
              ON windows_search_files(case_id, item_path);
            CREATE INDEX IF NOT EXISTS idx_windows_search_files_output
              ON windows_search_files(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_internet_history (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              work_id TEXT,
              gather_time TEXT,
              item_url TEXT,
              target_url TEXT,
              target_host TEXT,
              target_path TEXT,
              title TEXT,
              file_name TEXT,
              item_path TEXT,
              folder_path TEXT,
              date_created TEXT,
              date_modified TEXT,
              date_accessed TEXT,
              date_imported TEXT,
              owner TEXT,
              row_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_internet_case_time
              ON windows_search_internet_history(case_id, gather_time);
            CREATE INDEX IF NOT EXISTS idx_windows_search_internet_host
              ON windows_search_internet_history(case_id, target_host);
            CREATE INDEX IF NOT EXISTS idx_windows_search_internet_output
              ON windows_search_internet_history(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_activity_history (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              work_id TEXT,
              gather_time TEXT,
              item_url TEXT,
              content_uri TEXT,
              app_display_name TEXT,
              display_text TEXT,
              description TEXT,
              app_id TEXT,
              app_activity_id TEXT,
              device_id TEXT,
              start_time TEXT,
              end_time TEXT,
              local_start_time TEXT,
              local_end_time TEXT,
              active_duration TEXT,
              item_path TEXT,
              file_name TEXT,
              row_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_activity_case_time
              ON windows_search_activity_history(case_id, start_time);
            CREATE INDEX IF NOT EXISTS idx_windows_search_activity_app
              ON windows_search_activity_history(case_id, app_display_name);
            CREATE INDEX IF NOT EXISTS idx_windows_search_activity_output
              ON windows_search_activity_history(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_gather_logs (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_file TEXT,
              source_name TEXT,
              log_type TEXT,
              line_number INTEGER,
              timestamp_utc TEXT,
              filetime_hex TEXT,
              time_low_hex TEXT,
              time_high_hex TEXT,
              item_url TEXT,
              item_path TEXT,
              item_scheme TEXT,
              is_deleted_path TEXT,
              status_hex TEXT,
              crawl_code_hex TEXT,
              scope_id TEXT,
              document_id TEXT,
              source_scope TEXT DEFAULT 'live',
              snapshot_id TEXT,
              snapshot_ids TEXT,
              snapshot_count TEXT,
              snapshot_index TEXT,
              snapshot_created_utc TEXT,
              raw_fields_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_gather_case_time
              ON windows_search_gather_logs(case_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_windows_search_gather_path
              ON windows_search_gather_logs(case_id, item_path);
            CREATE INDEX IF NOT EXISTS idx_windows_search_gather_output
              ON windows_search_gather_logs(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_email_indicators (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_record_id TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              email TEXT NOT NULL,
              domain TEXT NOT NULL,
              evidence_field TEXT,
              evidence_value TEXT,
              timestamp TEXT,
              context_path TEXT,
              context_title TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_email_case_email
              ON windows_search_email_indicators(case_id, email);
            CREATE INDEX IF NOT EXISTS idx_windows_search_email_case_domain
              ON windows_search_email_indicators(case_id, domain);
            CREATE INDEX IF NOT EXISTS idx_windows_search_email_output
              ON windows_search_email_indicators(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_indexed_content (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_record_id TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              work_id TEXT,
              gather_time TEXT,
              item_path TEXT,
              item_name TEXT,
              item_type TEXT,
              content_field TEXT NOT NULL,
              content_text TEXT NOT NULL,
              content_sha256 TEXT NOT NULL DEFAULT '',
              content_length INTEGER NOT NULL DEFAULT 0,
              opensearch_document_id TEXT,
              timestamp TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_content_case_path
              ON windows_search_indexed_content(case_id, item_path);
            CREATE INDEX IF NOT EXISTS idx_windows_search_content_output
              ON windows_search_indexed_content(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_properties (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_record_id TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              work_id TEXT,
              item_path TEXT,
              property_name TEXT NOT NULL,
              property_value TEXT NOT NULL,
              normalized_name TEXT,
              timestamp TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_properties_case_name
              ON windows_search_properties(case_id, property_name);
            CREATE INDEX IF NOT EXISTS idx_windows_search_properties_output
              ON windows_search_properties(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_memory_carves (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              carve_path TEXT NOT NULL,
              carve_name TEXT,
              carve_size TEXT,
              carve_sha256 TEXT,
              source_process TEXT,
              source_pid TEXT,
              virtual_address TEXT,
              detected_format TEXT,
              page_size TEXT,
              reserved_bytes TEXT,
              parser_status TEXT,
              parser_error TEXT,
              table_count TEXT,
              object_count TEXT,
              extractable_row_count TEXT,
              matched_disk_db TEXT,
              matched_disk_page TEXT,
              matched_tail_hex TEXT,
              notes TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_memory_carves_case
              ON windows_search_memory_carves(case_id, parser_status);
            CREATE INDEX IF NOT EXISTS idx_windows_search_memory_carves_output
              ON windows_search_memory_carves(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_memory_objects (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              carve_id TEXT NOT NULL,
              carve_path TEXT NOT NULL,
              object_type TEXT,
              object_name TEXT,
              table_name TEXT,
              rootpage TEXT,
              sql_text TEXT,
              parser_status TEXT,
              parser_error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_memory_objects_case
              ON windows_search_memory_objects(case_id, object_type, object_name);
            CREATE INDEX IF NOT EXISTS idx_windows_search_memory_objects_output
              ON windows_search_memory_objects(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_search_memory_rows (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              carve_id TEXT NOT NULL,
              carve_path TEXT NOT NULL,
              table_name TEXT,
              table_row_number TEXT,
              row_json TEXT NOT NULL,
              row_text TEXT,
              row_sha256 TEXT,
              parser_status TEXT,
              parser_error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_search_memory_rows_case
              ON windows_search_memory_rows(case_id, table_name);
            CREATE INDEX IF NOT EXISTS idx_windows_search_memory_rows_output
              ON windows_search_memory_rows(tool_output_id);

            CREATE TABLE IF NOT EXISTS file_internal_metadata (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_file TEXT,
              original_path TEXT,
              file_name TEXT,
              extension TEXT,
              parser TEXT,
              metadata_group TEXT,
              property_name TEXT,
              property_value TEXT,
              raw_property_name TEXT,
              file_size TEXT,
              mft_created TEXT,
              mft_modified TEXT,
              mft_accessed TEXT,
              mft_record_modified TEXT,
              mft_in_use TEXT,
              path_unresolved TEXT,
              deleted_mft_entry TEXT,
              live_orphan TEXT,
              extraction_method TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_file_internal_metadata_case_path
              ON file_internal_metadata(case_id, original_path);
            CREATE INDEX IF NOT EXISTS idx_file_internal_metadata_case_property
              ON file_internal_metadata(case_id, property_name);
            CREATE INDEX IF NOT EXISTS idx_file_internal_metadata_output
              ON file_internal_metadata(tool_output_id);

            CREATE TABLE IF NOT EXISTS file_metadata_extraction_summaries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_name TEXT,
              artifact_name TEXT NOT NULL,
              artifact_path TEXT NOT NULL,
              selected_count INTEGER NOT NULL DEFAULT 0,
              extracted_count INTEGER NOT NULL DEFAULT 0,
              failed_count INTEGER NOT NULL DEFAULT 0,
              skipped_reparse_count INTEGER NOT NULL DEFAULT 0,
              skipped_deleted_count INTEGER NOT NULL DEFAULT 0,
              skipped_live_orphan_count INTEGER NOT NULL DEFAULT 0,
              live_orphan_count INTEGER NOT NULL DEFAULT 0,
              path_unresolved_count INTEGER NOT NULL DEFAULT 0,
              deleted_path_unresolved_count INTEGER NOT NULL DEFAULT 0,
              mounted_in_place_count INTEGER NOT NULL DEFAULT 0,
              mft_icat_count INTEGER NOT NULL DEFAULT 0,
              source TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_file_metadata_summary_case
              ON file_metadata_extraction_summaries(case_id, created_at);

            CREATE TABLE IF NOT EXISTS archive_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              archive_path TEXT,
              archive_file_name TEXT,
              archive_extension TEXT,
              archive_file_size TEXT,
              archive_modified_time_utc TEXT,
              archive_status TEXT,
              archive_error TEXT,
              member_path TEXT,
              member_file_name TEXT,
              member_extension TEXT,
              member_size TEXT,
              member_compressed_size TEXT,
              member_crc TEXT,
              member_modified_time_utc TEXT,
              member_is_dir TEXT,
              member_is_encrypted TEXT,
              nested_evidence_format TEXT,
              multipart_set_id TEXT,
              multipart_part_number TEXT,
              multipart_part_count TEXT,
              multipart_is_first_part TEXT,
              multipart_related_parts TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_archive_entries_case_archive
              ON archive_entries(case_id, archive_path);
            CREATE INDEX IF NOT EXISTS idx_archive_entries_case_member
              ON archive_entries(case_id, member_file_name);
            CREATE INDEX IF NOT EXISTS idx_archive_entries_nested_format
              ON archive_entries(case_id, nested_evidence_format);

            CREATE TABLE IF NOT EXISTS nested_evidence_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT NOT NULL REFERENCES images(id),
              source_table TEXT,
              source_id TEXT,
              source_file TEXT,
              original_path TEXT,
              parent_path TEXT,
              file_name TEXT,
              extension TEXT,
              file_size TEXT,
              detected_format TEXT,
              created_time_utc TEXT,
              modified_time_utc TEXT,
              accessed_time_utc TEXT,
              record_changed_time_utc TEXT,
              mft_entry_number TEXT,
              mft_sequence_number TEXT,
              multipart_set_id TEXT,
              multipart_part_number TEXT,
              multipart_part_count TEXT,
              multipart_is_first_part TEXT,
              multipart_related_parts TEXT,
              parser_status TEXT,
              recommendation TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_nested_evidence_case_path
              ON nested_evidence_items(case_id, original_path);
            CREATE INDEX IF NOT EXISTS idx_nested_evidence_case_format
              ON nested_evidence_items(case_id, detected_format);

            CREATE TABLE IF NOT EXISTS evtx_events (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              record_number TEXT,
              event_record_id TEXT,
              time_created TEXT,
              event_id TEXT,
              level TEXT,
              provider TEXT,
              channel TEXT,
              process_id TEXT,
              thread_id TEXT,
              computer TEXT,
              user_id TEXT,
              map_description TEXT,
              user_name TEXT,
              remote_host TEXT,
              payload_data1 TEXT,
              payload_data2 TEXT,
              payload_data3 TEXT,
              payload_data4 TEXT,
              payload_data5 TEXT,
              payload_data6 TEXT,
              executable_info TEXT,
              source_file TEXT,
              payload TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_evtx_events_case_time
              ON evtx_events(case_id, time_created);
            CREATE INDEX IF NOT EXISTS idx_evtx_events_case_event
              ON evtx_events(case_id, event_id);
            CREATE INDEX IF NOT EXISTS idx_evtx_events_case_event_time
              ON evtx_events(case_id, event_id, time_created);
            CREATE INDEX IF NOT EXISTS idx_evtx_events_case_provider_channel
              ON evtx_events(case_id, provider, channel, event_id, time_created);
            CREATE INDEX IF NOT EXISTS idx_evtx_events_output
              ON evtx_events(tool_output_id);

            CREATE TABLE IF NOT EXISTS etl_events (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_file TEXT,
              source_name TEXT,
              parser_status TEXT,
              parser_error TEXT,
              timestamp_utc TEXT,
              provider_name TEXT,
              provider_id TEXT,
              provider_label TEXT,
              event_category TEXT,
              event_name TEXT,
              event_id TEXT,
              opcode TEXT,
              version TEXT,
              process_id TEXT,
              parent_process_id TEXT,
              session_id TEXT,
              image_name TEXT,
              command_line TEXT,
              user_sid TEXT,
              package_full_name TEXT,
              flags TEXT,
              payload_strings_json TEXT,
              event_values_json TEXT,
              file_size TEXT,
              sha256_first_mb TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_etl_events_case_time
              ON etl_events(case_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_etl_events_source
              ON etl_events(case_id, source_name);
            CREATE INDEX IF NOT EXISTS idx_etl_events_output
              ON etl_events(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_error_reports (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_file TEXT,
              source_name TEXT,
              report_folder TEXT,
              event_type TEXT,
              event_time_utc TEXT,
              upload_time_utc TEXT,
              report_type TEXT,
              consent TEXT,
              report_status TEXT,
              report_identifier TEXT,
              integrator_report_identifier TEXT,
              app_name TEXT,
              original_filename TEXT,
              target_app_id TEXT,
              target_app_version TEXT,
              fault_module_name TEXT,
              fault_module_version TEXT,
              exception_code TEXT,
              exception_offset TEXT,
              is_fatal TEXT,
              bucket_id TEXT,
              legacy_bucket_id TEXT,
              ui_path TEXT,
              loaded_modules_json TEXT,
              signatures_json TEXT,
              dynamic_signatures_json TEXT,
              ui_json TEXT,
              raw_json TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_windows_error_reports_case_time
              ON windows_error_reports(case_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_windows_error_reports_app
              ON windows_error_reports(case_id, app_name);
            CREATE INDEX IF NOT EXISTS idx_windows_error_reports_output
              ON windows_error_reports(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_defender_events (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_file TEXT,
              source_name TEXT,
              artifact_type TEXT,
              line_number TEXT,
              event_time_utc TEXT,
              event_type TEXT,
              component TEXT,
              severity TEXT,
              threat_name TEXT,
              action TEXT,
              path TEXT,
              resource TEXT,
              message TEXT,
              file_size TEXT,
              modified_time_utc TEXT,
              sha256_first_mb TEXT,
              raw_json TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_windows_defender_events_case_time
              ON windows_defender_events(case_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_windows_defender_events_type
              ON windows_defender_events(case_id, event_type);
            CREATE INDEX IF NOT EXISTS idx_windows_defender_events_output
              ON windows_defender_events(tool_output_id);

            CREATE TABLE IF NOT EXISTS user_controlled_file_references (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              source_tool TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              source_row_number INTEGER,
              event_time_utc TEXT,
              raw_path TEXT NOT NULL,
              normalized_path TEXT NOT NULL,
              display_path TEXT,
              volume_device TEXT,
              owning_user TEXT,
              file_name TEXT,
              extension TEXT,
              path_scope TEXT NOT NULL,
              storage_provider TEXT NOT NULL,
              artifact_meaning TEXT NOT NULL,
              confidence_basis TEXT NOT NULL,
              resolved_provider_path TEXT,
              resolved_file_name TEXT,
              resolved_cache_path TEXT,
              resolution_status TEXT,
              resolution_basis TEXT,
              context TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_user_file_refs_case_time
              ON user_controlled_file_references(case_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_user_file_refs_scope
              ON user_controlled_file_references(case_id, path_scope, storage_provider);
            CREATE INDEX IF NOT EXISTS idx_user_file_refs_source
              ON user_controlled_file_references(source_table, source_row_id);

            CREATE TABLE IF NOT EXISTS evtx_recovery (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT NOT NULL REFERENCES images(id),
              artifact_path TEXT NOT NULL,
              original_path TEXT NOT NULL,
              file_name TEXT NOT NULL,
              extraction_method TEXT NOT NULL,
              status TEXT NOT NULL,
              original_size INTEGER,
              recovered_size INTEGER,
              readable_bytes INTEGER,
              failed_block_count INTEGER NOT NULL DEFAULT 0,
              failed_offsets_json TEXT NOT NULL,
              header_valid INTEGER,
              parser_tool_output_id TEXT,
              parser_rows_recovered INTEGER,
              parser_errors TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(case_id, image_id, artifact_path)
            );

            CREATE INDEX IF NOT EXISTS idx_evtx_recovery_case_status
              ON evtx_recovery(case_id, status);
            CREATE INDEX IF NOT EXISTS idx_evtx_recovery_output
              ON evtx_recovery(parser_tool_output_id);

            CREATE TABLE IF NOT EXISTS timeline_events (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              source_tool TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              event_type TEXT NOT NULL,
              raw_timestamp TEXT,
              timestamp_utc TEXT NOT NULL,
              end_timestamp_utc TEXT,
              duration_ms INTEGER,
              description TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_timeline_events_case_time
              ON timeline_events(case_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_timeline_events_computer_time
              ON timeline_events(computer_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_timeline_events_output
              ON timeline_events(tool_output_id);

            CREATE TABLE IF NOT EXISTS timeline_event_sources (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              primary_event_id TEXT NOT NULL,
              duplicate_event_id TEXT NOT NULL,
              source_scope TEXT NOT NULL,
              source_tool TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_output_path TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_timeline_event_sources_case_primary
              ON timeline_event_sources(case_id, primary_event_id);
            CREATE INDEX IF NOT EXISTS idx_timeline_event_sources_case_duplicate
              ON timeline_event_sources(case_id, duplicate_event_id);

            CREATE TABLE IF NOT EXISTS artifact_record_sources (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              artifact_family TEXT NOT NULL,
              primary_table TEXT NOT NULL,
              primary_row_id TEXT NOT NULL,
              duplicate_table TEXT NOT NULL,
              duplicate_row_id TEXT NOT NULL,
              source_scope TEXT NOT NULL,
              source_tool TEXT,
              source_output_id TEXT,
              source_output_path TEXT,
              match_key TEXT NOT NULL,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_artifact_record_sources_case_primary
              ON artifact_record_sources(case_id, primary_table, primary_row_id);
            CREATE INDEX IF NOT EXISTS idx_artifact_record_sources_case_duplicate
              ON artifact_record_sources(case_id, duplicate_table, duplicate_row_id);
            CREATE INDEX IF NOT EXISTS idx_artifact_record_sources_case_family
              ON artifact_record_sources(case_id, artifact_family);

            CREATE TABLE IF NOT EXISTS file_correlations (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              source_tool TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              mft_entry_id TEXT NOT NULL,
              match_type TEXT NOT NULL,
              confidence TEXT NOT NULL,
              source_path TEXT,
              mft_path TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_file_correlations_case
              ON file_correlations(case_id);
            CREATE INDEX IF NOT EXISTS idx_file_correlations_source
              ON file_correlations(source_table, source_row_id);
            CREATE INDEX IF NOT EXISTS idx_file_correlations_mft
              ON file_correlations(mft_entry_id);

            CREATE TABLE IF NOT EXISTS copied_file_indicators (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL,
              source_tool TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              source_artifact_type TEXT NOT NULL,
              source_artifact_name TEXT,
              file_name TEXT,
              file_location TEXT,
              created_time TEXT NOT NULL,
              modified_time TEXT NOT NULL,
              created_timestamp_utc TEXT NOT NULL,
              modified_timestamp_utc TEXT NOT NULL,
              indicator TEXT NOT NULL,
              reason TEXT NOT NULL,
              confidence TEXT NOT NULL,
              matched_mft_entry_number TEXT,
              matched_mft_sequence_number TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_copied_file_indicators_case
              ON copied_file_indicators(case_id, image_id);
            CREATE INDEX IF NOT EXISTS idx_copied_file_indicators_source
              ON copied_file_indicators(source_table, source_row_id);

            CREATE TABLE IF NOT EXISTS recycle_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              recycle_format TEXT,
              source_path TEXT,
              top_level_name TEXT,
              recycled_path TEXT,
              display_name TEXT,
              original_path TEXT,
              deletion_time_utc TEXT,
              file_size TEXT,
              is_directory TEXT,
              mft_created TEXT,
              mft_modified TEXT,
              mft_accessed TEXT,
              mft_record_modified TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_recycle_items_case
              ON recycle_items(case_id);
            CREATE INDEX IF NOT EXISTS idx_recycle_items_output
              ON recycle_items(tool_output_id);

            CREATE TABLE IF NOT EXISTS recycle_children (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              recycle_format TEXT,
              source_path TEXT,
              top_level_name TEXT,
              recycled_path TEXT,
              child_relative_path TEXT,
              display_name TEXT,
              file_size TEXT,
              mft_created TEXT,
              mft_modified TEXT,
              mft_accessed TEXT,
              mft_record_modified TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_recycle_children_case
              ON recycle_children(case_id);
            CREATE INDEX IF NOT EXISTS idx_recycle_children_output
              ON recycle_children(tool_output_id);

            CREATE TABLE IF NOT EXISTS firefox_history (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              profile_path TEXT,
              url TEXT,
              title TEXT,
              visit_time_utc TEXT,
              visit_type TEXT,
              visit_count TEXT,
              typed TEXT,
              hidden TEXT,
              frecency TEXT,
              visit_source TEXT,
              visit_source_label TEXT,
              local_vs_synced TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_firefox_history_case_time
              ON firefox_history(case_id, visit_time_utc);
            CREATE INDEX IF NOT EXISTS idx_firefox_history_output
              ON firefox_history(tool_output_id);

            CREATE TABLE IF NOT EXISTS firefox_cookies (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              profile_path TEXT,
              host TEXT,
              name TEXT,
              value TEXT,
              path TEXT,
              created_utc TEXT,
              last_accessed_utc TEXT,
              expires_utc TEXT,
              is_secure TEXT,
              is_http_only TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_firefox_cookies_case_host
              ON firefox_cookies(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_firefox_cookies_output
              ON firefox_cookies(tool_output_id);

            CREATE TABLE IF NOT EXISTS browser_history (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              browser TEXT,
              source_path TEXT,
              profile_path TEXT,
              url TEXT,
              title TEXT,
              visit_time_utc TEXT,
              visit_count TEXT,
              typed_count TEXT,
              visit_source TEXT,
              visit_source_label TEXT,
              local_vs_synced TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_browser_history_case_time
              ON browser_history(case_id, visit_time_utc);
            CREATE INDEX IF NOT EXISTS idx_browser_history_output
              ON browser_history(tool_output_id);

            CREATE TABLE IF NOT EXISTS browser_downloads (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              browser TEXT,
              source_path TEXT,
              profile_path TEXT,
              target_path TEXT,
              tab_url TEXT,
              site_url TEXT,
              referrer TEXT,
              start_time_utc TEXT,
              end_time_utc TEXT,
              received_bytes TEXT,
              total_bytes TEXT,
              state TEXT,
              danger_type TEXT,
              interrupt_reason TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_browser_downloads_case_time
              ON browser_downloads(case_id, start_time_utc);
            CREATE INDEX IF NOT EXISTS idx_browser_downloads_output
              ON browser_downloads(tool_output_id);

            CREATE TABLE IF NOT EXISTS browser_cookies (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              browser TEXT,
              source_path TEXT,
              profile_path TEXT,
              host TEXT,
              name TEXT,
              path TEXT,
              created_utc TEXT,
              last_accessed_utc TEXT,
              expires_utc TEXT,
              is_secure TEXT,
              is_http_only TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_browser_cookies_case_host
              ON browser_cookies(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_browser_cookies_output
              ON browser_cookies(tool_output_id);

            CREATE TABLE IF NOT EXISTS browser_cache_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              browser TEXT,
              source_path TEXT,
              profile_path TEXT,
              cache_type TEXT,
              url TEXT,
              host TEXT,
              cache_file TEXT,
              cache_file_size TEXT,
              cache_file_modified_utc TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_browser_cache_entries_case_host
              ON browser_cache_entries(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_browser_cache_entries_case_time
              ON browser_cache_entries(case_id, cache_file_modified_utc);
            CREATE INDEX IF NOT EXISTS idx_browser_cache_entries_output
              ON browser_cache_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS browser_artifacts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              browser TEXT,
              artifact_type TEXT NOT NULL,
              source_path TEXT,
              profile_path TEXT,
              name TEXT,
              value TEXT,
              url TEXT,
              title TEXT,
              host TEXT,
              local_path TEXT,
              timestamp_utc TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_browser_artifacts_case_type
              ON browser_artifacts(case_id, artifact_type);
            CREATE INDEX IF NOT EXISTS idx_browser_artifacts_case_time
              ON browser_artifacts(case_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_browser_artifacts_output
              ON browser_artifacts(tool_output_id);

            CREATE TABLE IF NOT EXISTS browser_session_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              browser TEXT,
              source_path TEXT,
              profile_path TEXT,
              session_type TEXT,
              window_id TEXT,
              tab_id TEXT,
              tab_index TEXT,
              navigation_index TEXT,
              url TEXT,
              title TEXT,
              referrer_url TEXT,
              host TEXT,
              timestamp_utc TEXT,
              last_active_time_utc TEXT,
              is_current TEXT,
              is_pinned TEXT,
              parser TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_browser_session_entries_case_time
              ON browser_session_entries(case_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_browser_session_entries_case_host
              ON browser_session_entries(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_browser_session_entries_output
              ON browser_session_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS browser_site_settings (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              browser TEXT,
              source_path TEXT,
              profile_path TEXT,
              setting_type TEXT,
              origin TEXT,
              host TEXT,
              setting_name TEXT,
              setting_value TEXT,
              last_modified_utc TEXT,
              expiration_utc TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_browser_site_settings_case_type
              ON browser_site_settings(case_id, setting_type);
            CREATE INDEX IF NOT EXISTS idx_browser_site_settings_case_host
              ON browser_site_settings(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_browser_site_settings_output
              ON browser_site_settings(tool_output_id);

            CREATE TABLE IF NOT EXISTS browser_notifications (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              browser TEXT,
              source_path TEXT,
              profile_path TEXT,
              origin TEXT,
              host TEXT,
              notification_id TEXT,
              title TEXT,
              body TEXT,
              tag TEXT,
              icon TEXT,
              badge TEXT,
              created_utc TEXT,
              notification_timestamp_utc TEXT,
              first_click_utc TEXT,
              last_click_utc TEXT,
              closed_utc TEXT,
              num_clicks TEXT,
              closed_reason TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_browser_notifications_case_time
              ON browser_notifications(case_id, created_utc);
            CREATE INDEX IF NOT EXISTS idx_browser_notifications_case_host
              ON browser_notifications(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_browser_notifications_output
              ON browser_notifications(tool_output_id);

            CREATE TABLE IF NOT EXISTS office_backstage_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              artifact_type TEXT NOT NULL,
              source_path TEXT,
              user_profile TEXT,
              application TEXT,
              name TEXT,
              value TEXT,
              path TEXT,
              url TEXT,
              host TEXT,
              timestamp_utc TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_office_backstage_case_type
              ON office_backstage_items(case_id, artifact_type);
            CREATE INDEX IF NOT EXISTS idx_office_backstage_case_time
              ON office_backstage_items(case_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_office_backstage_output
              ON office_backstage_items(tool_output_id);

            CREATE TABLE IF NOT EXISTS user_dictionary_words (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              user_profile TEXT,
              application TEXT,
              office_version TEXT,
              proofing_id TEXT,
              dictionary_name TEXT,
              word TEXT,
              word_index INTEGER,
              timestamp_utc TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_user_dictionary_case_user
              ON user_dictionary_words(case_id, user_profile);
            CREATE INDEX IF NOT EXISTS idx_user_dictionary_case_word
              ON user_dictionary_words(case_id, word);
            CREATE INDEX IF NOT EXISTS idx_user_dictionary_output
              ON user_dictionary_words(tool_output_id);

            CREATE TABLE IF NOT EXISTS zone_identifier_ads (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              file_path TEXT,
              user_profile TEXT,
              stream_name TEXT,
              zone_id TEXT,
              classification TEXT,
              referrer_url TEXT,
              referrer_host TEXT,
              host_url TEXT,
              host TEXT,
              timestamp_utc TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_zone_identifier_case_zone
              ON zone_identifier_ads(case_id, zone_id);
            CREATE INDEX IF NOT EXISTS idx_zone_identifier_case_file
              ON zone_identifier_ads(case_id, file_path);
            CREATE INDEX IF NOT EXISTS idx_zone_identifier_output
              ON zone_identifier_ads(tool_output_id);

            CREATE TABLE IF NOT EXISTS thumbcache_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              source_name TEXT,
              user_profile TEXT,
              cache_file_type TEXT,
              cache_id TEXT,
              entry_index TEXT,
              entry_offset TEXT,
              entry_size TEXT,
              thumbnail_offset TEXT,
              thumbnail_size TEXT,
              thumbnail_type TEXT,
              thumbnail_sha256 TEXT,
              source_mtime_utc TEXT,
              parser_status TEXT,
              parser_note TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_thumbcache_entries_case_user
              ON thumbcache_entries(case_id, user_profile);
            CREATE INDEX IF NOT EXISTS idx_thumbcache_entries_case_cache
              ON thumbcache_entries(case_id, cache_id);
            CREATE INDEX IF NOT EXISTS idx_thumbcache_entries_output
              ON thumbcache_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS image_analysis_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_artifact_type TEXT,
              source_artifact_id TEXT,
              source_path TEXT,
              output_path TEXT,
              file_name TEXT,
              file_extension TEXT,
              sha256 TEXT,
              file_size TEXT,
              width TEXT,
              height TEXT,
              image_format TEXT,
              analysis_type TEXT,
              ocr_status TEXT,
              ocr_engine TEXT,
              ocr_text TEXT,
              classifier_status TEXT,
              classifier_label TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_image_analysis_case_type
              ON image_analysis_items(case_id, source_artifact_type);
            CREATE INDEX IF NOT EXISTS idx_image_analysis_case_sha
              ON image_analysis_items(case_id, sha256);
            CREATE INDEX IF NOT EXISTS idx_image_analysis_output
              ON image_analysis_items(tool_output_id);

            CREATE TABLE IF NOT EXISTS rdp_cache_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              record_type TEXT,
              user_profile TEXT,
              source_cache_path TEXT,
              fragment_path TEXT,
              contact_sheet_path TEXT,
              file_name TEXT,
              sha256 TEXT,
              file_size TEXT,
              width TEXT,
              height TEXT,
              image_format TEXT,
              fragment_index TEXT,
              parser_status TEXT,
              parser_note TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rdp_cache_items_case_user
              ON rdp_cache_items(case_id, user_profile);
            CREATE INDEX IF NOT EXISTS idx_rdp_cache_items_case_type
              ON rdp_cache_items(case_id, record_type);
            CREATE INDEX IF NOT EXISTS idx_rdp_cache_items_output
              ON rdp_cache_items(tool_output_id);

            CREATE TABLE IF NOT EXISTS rdp_visual_observations (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT,
              tool_name TEXT NOT NULL,
              source_csv TEXT,
              row_number INTEGER NOT NULL,
              user_profile TEXT,
              source_cache_path TEXT,
              contact_sheet_path TEXT,
              observation_time_utc TEXT,
              time_basis TEXT,
              observation_type TEXT,
              observed_application TEXT,
              observed_text TEXT,
              observed_path TEXT,
              certainty TEXT,
              caveat TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rdp_visual_observations_case_time
              ON rdp_visual_observations(case_id, observation_time_utc);
            CREATE INDEX IF NOT EXISTS idx_rdp_visual_observations_case_cache
              ON rdp_visual_observations(case_id, source_cache_path);

            CREATE TABLE IF NOT EXISTS thumbcache_search_correlations (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              thumbcache_entry_id TEXT NOT NULL REFERENCES thumbcache_entries(id),
              windows_search_file_id TEXT,
              correlation_basis TEXT NOT NULL,
              confidence TEXT NOT NULL,
              cache_id TEXT,
              thumbcache_user TEXT,
              thumbcache_path TEXT,
              thumbcache_name TEXT,
              thumbnail_sha256 TEXT,
              thumbnail_type TEXT,
              search_item_path TEXT,
              search_file_name TEXT,
              search_date_created TEXT,
              search_date_modified TEXT,
              search_date_accessed TEXT,
              search_date_imported TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_thumbcache_search_case_confidence
              ON thumbcache_search_correlations(case_id, confidence);
            CREATE INDEX IF NOT EXISTS idx_thumbcache_search_entry
              ON thumbcache_search_correlations(thumbcache_entry_id);

            CREATE TABLE IF NOT EXISTS cloud_sync_artifacts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              provider TEXT,
              artifact_type TEXT,
              user_profile TEXT,
              source_path TEXT,
              source_name TEXT,
              database_name TEXT,
              table_name TEXT,
              event_time_utc TEXT,
              local_path TEXT,
              cloud_path TEXT,
              file_name TEXT,
              file_id TEXT,
              parent_id TEXT,
              stable_id TEXT,
              server_path TEXT,
              url TEXT,
              mime_type TEXT,
              file_size TEXT,
              is_folder TEXT,
              is_deleted TEXT,
              sync_status TEXT,
              event_type TEXT,
              direction TEXT,
              owner TEXT,
              shared TEXT,
              protobuf_fields_json TEXT,
              details_json TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cloud_sync_artifacts_case_provider
              ON cloud_sync_artifacts(case_id, provider);
            CREATE INDEX IF NOT EXISTS idx_cloud_sync_artifacts_case_time
              ON cloud_sync_artifacts(case_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_cloud_sync_artifacts_output
              ON cloud_sync_artifacts(tool_output_id);

            CREATE TABLE IF NOT EXISTS google_drive_cache_map (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              account_id TEXT,
              stable_id TEXT,
              file_id TEXT,
              virtual_path TEXT,
              file_name TEXT,
              cache_id TEXT,
              cache_path TEXT,
              windows_cache_path TEXT,
              cache_file_size TEXT,
              mapping_method TEXT,
              evidence_basis TEXT,
              details_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_google_drive_cache_map_case_file
              ON google_drive_cache_map(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_google_drive_cache_map_cache_id
              ON google_drive_cache_map(case_id, cache_id);

            CREATE TABLE IF NOT EXISTS onedrive_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              artifact_type TEXT,
              user_profile TEXT,
              account TEXT,
              source_path TEXT,
              source_ode_csv TEXT,
              source_ode_row_number TEXT,
              record_type TEXT,
              name TEXT,
              path TEXT,
              parent_resource_id TEXT,
              resource_id TEXT,
              etag TEXT,
              status TEXT,
              spo_permissions TEXT,
              volume_id TEXT,
              item_index TEXT,
              last_change_utc TEXT,
              disk_last_access_utc TEXT,
              disk_creation_utc TEXT,
              size TEXT,
              local_hash_digest TEXT,
              local_hash_algorithm TEXT,
              shared_item TEXT,
              media_json TEXT,
              hydration_json TEXT,
              metadata_json TEXT,
              is_deleted TEXT,
              delete_time_utc TEXT,
              deleting_process TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_onedrive_items_case_name
              ON onedrive_items(case_id, name);
            CREATE INDEX IF NOT EXISTS idx_onedrive_items_case_resource
              ON onedrive_items(case_id, resource_id);
            CREATE INDEX IF NOT EXISTS idx_onedrive_items_case_deleted
              ON onedrive_items(case_id, is_deleted);

            CREATE TABLE IF NOT EXISTS onedrive_log_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              user_profile TEXT,
              account TEXT,
              source_path TEXT,
              source_name TEXT,
              log_type TEXT,
              record_index TEXT,
              odl_version TEXT,
              one_drive_version TEXT,
              windows_version TEXT,
              timestamp_utc TEXT,
              code_file TEXT,
              function TEXT,
              flags TEXT,
              context_data TEXT,
              event_type TEXT,
              local_path TEXT,
              url TEXT,
              resource_id TEXT,
              params_text TEXT,
              params_json TEXT,
              raw_strings_json TEXT,
              parser_status TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_onedrive_log_entries_case_time
              ON onedrive_log_entries(case_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_onedrive_log_entries_case_event
              ON onedrive_log_entries(case_id, event_type);

            CREATE TABLE IF NOT EXISTS package_cache_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              user_profile TEXT,
              application_package TEXT,
              source_database TEXT,
              source_table TEXT,
              table_row_number TEXT,
              cache_name TEXT,
              site_origin TEXT,
              request_url TEXT,
              host TEXT,
              response_status TEXT,
              response_type TEXT,
              response_headers TEXT,
              response_date_utc TEXT,
              content_type TEXT,
              content_length TEXT,
              source_body_path TEXT,
              stored_body_path TEXT,
              body_file_name TEXT,
              body_size TEXT,
              body_sha256 TEXT,
              body_encrypted TEXT,
              encryption_version TEXT,
              decoded_state TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_package_cache_entries_case_host
              ON package_cache_entries(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_package_cache_entries_case_date
              ON package_cache_entries(case_id, response_date_utc);
            CREATE INDEX IF NOT EXISTS idx_package_cache_entries_output
              ON package_cache_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS package_artifacts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              record_type TEXT,
              user_profile TEXT,
              application_package TEXT,
              source_path TEXT,
              source_name TEXT,
              file_name TEXT,
              file_extension TEXT,
              file_size TEXT,
              modified_utc TEXT,
              event_time_utc TEXT,
              url TEXT,
              host TEXT,
              title TEXT,
              artifact_value TEXT,
              artifact_text TEXT,
              details_json TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_package_artifacts_case_type
              ON package_artifacts(case_id, record_type);
            CREATE INDEX IF NOT EXISTS idx_package_artifacts_case_time
              ON package_artifacts(case_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_package_artifacts_case_host
              ON package_artifacts(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_package_artifacts_output
              ON package_artifacts(tool_output_id);

            CREATE TABLE IF NOT EXISTS spotify_artifacts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              artifact_type TEXT,
              user_profile TEXT,
              source_path TEXT,
              source_name TEXT,
              source_file TEXT,
              file_size TEXT,
              modified_utc TEXT,
              account_user_id TEXT,
              spotify_user_id TEXT,
              spotify_user_uri TEXT,
              display_name TEXT,
              key_name TEXT,
              value TEXT,
              evidence TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_spotify_artifacts_case_type
              ON spotify_artifacts(case_id, artifact_type);
            CREATE INDEX IF NOT EXISTS idx_spotify_artifacts_case_user
              ON spotify_artifacts(case_id, spotify_user_id);
            CREATE INDEX IF NOT EXISTS idx_spotify_artifacts_output
              ON spotify_artifacts(tool_output_id);

            CREATE TABLE IF NOT EXISTS telemetry_artifacts (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              record_type TEXT,
              artifact_group TEXT,
              user_profile TEXT,
              application TEXT,
              source_path TEXT,
              source_name TEXT,
              file_name TEXT,
              file_extension TEXT,
              file_size TEXT,
              modified_utc TEXT,
              event_time_utc TEXT,
              identifier TEXT,
              path TEXT,
              url TEXT,
              host TEXT,
              title TEXT,
              value_name TEXT,
              value_data TEXT,
              artifact_text TEXT,
              sha256_first_mb TEXT,
              details_json TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_telemetry_artifacts_case_group
              ON telemetry_artifacts(case_id, artifact_group);
            CREATE INDEX IF NOT EXISTS idx_telemetry_artifacts_case_time
              ON telemetry_artifacts(case_id, event_time_utc, modified_utc);
            CREATE INDEX IF NOT EXISTS idx_telemetry_artifacts_output
              ON telemetry_artifacts(tool_output_id);

            CREATE TABLE IF NOT EXISTS artifact_correlations (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              left_source_tool TEXT,
              left_source_table TEXT NOT NULL,
              left_source_row_id TEXT NOT NULL,
              right_source_tool TEXT,
              right_source_table TEXT NOT NULL,
              right_source_row_id TEXT NOT NULL,
              correlation_type TEXT NOT NULL,
              correlation_key TEXT,
              confidence TEXT NOT NULL,
              summary TEXT,
              details_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_artifact_correlations_case
              ON artifact_correlations(case_id, correlation_type);
            CREATE INDEX IF NOT EXISTS idx_artifact_correlations_left
              ON artifact_correlations(left_source_table, left_source_row_id);
            CREATE INDEX IF NOT EXISTS idx_artifact_correlations_right
              ON artifact_correlations(right_source_table, right_source_row_id);

            CREATE TABLE IF NOT EXISTS correlation_rules (
              id TEXT PRIMARY KEY,
              category TEXT NOT NULL,
              name TEXT NOT NULL,
              description TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              review_value TEXT NOT NULL DEFAULT 'normal',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_correlation_rules_category
              ON correlation_rules(category, enabled);

            CREATE TABLE IF NOT EXISTS correlation_groups (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              rule_id TEXT NOT NULL REFERENCES correlation_rules(id),
              category TEXT NOT NULL,
              correlation_key TEXT NOT NULL,
              title TEXT NOT NULL,
              summary TEXT NOT NULL,
              review_value TEXT NOT NULL DEFAULT 'normal',
              primary_time_utc TEXT,
              primary_path TEXT,
              primary_user TEXT,
              primary_application TEXT,
              member_count INTEGER NOT NULL DEFAULT 0,
              source_tables TEXT NOT NULL DEFAULT '',
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_correlation_groups_case_category
              ON correlation_groups(case_id, category, review_value);
            CREATE INDEX IF NOT EXISTS idx_correlation_groups_case_key
              ON correlation_groups(case_id, correlation_key);

            CREATE TABLE IF NOT EXISTS correlation_members (
              id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL REFERENCES correlation_groups(id),
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              source_tool TEXT,
              role TEXT NOT NULL,
              event_time_utc TEXT,
              user_profile TEXT,
              path TEXT,
              application TEXT,
              description TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_correlation_members_group
              ON correlation_members(group_id);
            CREATE INDEX IF NOT EXISTS idx_correlation_members_source
              ON correlation_members(source_table, source_row_id);

            CREATE TABLE IF NOT EXISTS correlation_interpretations (
              id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL REFERENCES correlation_groups(id),
              rule_id TEXT NOT NULL REFERENCES correlation_rules(id),
              interpretation TEXT NOT NULL,
              caveats TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_correlation_interpretations_group
              ON correlation_interpretations(group_id);

            CREATE TABLE IF NOT EXISTS derived_sessions (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              session_type TEXT NOT NULL,
              session_key TEXT NOT NULL,
              user_profile TEXT,
              source_host TEXT,
              remote_host TEXT,
              remote_ip TEXT,
              profile_name TEXT,
              protocol TEXT,
              start_time_utc TEXT,
              end_time_utc TEXT,
              duration_seconds INTEGER,
              status TEXT,
              evidence_count INTEGER NOT NULL DEFAULT 0,
              source_tables TEXT NOT NULL DEFAULT '',
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_derived_sessions_case_type_time
              ON derived_sessions(case_id, session_type, start_time_utc);
            CREATE INDEX IF NOT EXISTS idx_derived_sessions_case_key
              ON derived_sessions(case_id, session_key);

            CREATE TABLE IF NOT EXISTS derived_session_members (
              id TEXT PRIMARY KEY,
              session_id TEXT NOT NULL REFERENCES derived_sessions(id),
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              source_table TEXT NOT NULL,
              source_row_id TEXT,
              source_tool TEXT,
              event_time_utc TEXT,
              event_type TEXT,
              description TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_derived_session_members_session
              ON derived_session_members(session_id);
            CREATE INDEX IF NOT EXISTS idx_derived_session_members_source
              ON derived_session_members(source_table, source_row_id);

            CREATE TABLE IF NOT EXISTS investigation_entities (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              entity_type TEXT NOT NULL,
              entity_key TEXT NOT NULL,
              display_name TEXT NOT NULL,
              normalized_value TEXT,
              source_table TEXT,
              source_row_id TEXT,
              confidence TEXT NOT NULL DEFAULT 'derived',
              first_seen_utc TEXT,
              last_seen_utc TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL,
              UNIQUE(case_id, entity_type, entity_key)
            );
            CREATE INDEX IF NOT EXISTS idx_investigation_entities_case_type
              ON investigation_entities(case_id, entity_type);
            CREATE INDEX IF NOT EXISTS idx_investigation_entities_case_key
              ON investigation_entities(case_id, entity_key);

            CREATE TABLE IF NOT EXISTS investigation_relationships (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              relationship_type TEXT NOT NULL,
              subject_entity_id TEXT NOT NULL REFERENCES investigation_entities(id),
              object_entity_id TEXT NOT NULL REFERENCES investigation_entities(id),
              source_table TEXT NOT NULL,
              source_row_id TEXT,
              event_time_utc TEXT,
              confidence TEXT NOT NULL DEFAULT 'derived',
              summary TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_investigation_relationships_case_type
              ON investigation_relationships(case_id, relationship_type, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_investigation_relationships_subject
              ON investigation_relationships(subject_entity_id);
            CREATE INDEX IF NOT EXISTS idx_investigation_relationships_object
              ON investigation_relationships(object_entity_id);

            CREATE TABLE IF NOT EXISTS investigation_findings (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              finding_type TEXT NOT NULL,
              title TEXT NOT NULL,
              summary TEXT NOT NULL,
              severity TEXT NOT NULL DEFAULT 'low',
              confidence TEXT NOT NULL DEFAULT 'low',
              confidence_score INTEGER NOT NULL DEFAULT 0,
              rule_id TEXT NOT NULL,
              rule_name TEXT NOT NULL,
              start_time_utc TEXT,
              end_time_utc TEXT,
              primary_entity_id TEXT REFERENCES investigation_entities(id),
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_investigation_findings_case_type
              ON investigation_findings(case_id, finding_type, severity);
            CREATE INDEX IF NOT EXISTS idx_investigation_findings_case_time
              ON investigation_findings(case_id, start_time_utc);

            CREATE TABLE IF NOT EXISTS investigation_finding_evidence (
              id TEXT PRIMARY KEY,
              finding_id TEXT NOT NULL REFERENCES investigation_findings(id),
              case_id TEXT NOT NULL REFERENCES cases(id),
              source_table TEXT NOT NULL,
              source_row_id TEXT,
              relationship_id TEXT REFERENCES investigation_relationships(id),
              role TEXT NOT NULL,
              event_time_utc TEXT,
              summary TEXT,
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_investigation_finding_evidence_finding
              ON investigation_finding_evidence(finding_id);
            CREATE INDEX IF NOT EXISTS idx_investigation_finding_evidence_source
              ON investigation_finding_evidence(source_table, source_row_id);

            CREATE TABLE IF NOT EXISTS computer_inventory (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              category TEXT NOT NULL,
              name TEXT NOT NULL,
              value TEXT,
              source_table TEXT,
              source_row_id TEXT,
              confidence TEXT NOT NULL DEFAULT 'derived',
              details_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_computer_inventory_case
              ON computer_inventory(case_id, computer_id, image_id, category);
            CREATE INDEX IF NOT EXISTS idx_computer_inventory_name
              ON computer_inventory(case_id, name);

            CREATE TABLE IF NOT EXISTS windows_activities (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              user_profile TEXT,
              source_table TEXT,
              activity_id TEXT,
              app_id TEXT,
              app_display_name TEXT,
              activity_type TEXT,
              display_text TEXT,
              file_name TEXT,
              content_uri TEXT,
              activation_uri TEXT,
              fallback_uri TEXT,
              start_time_utc TEXT,
              end_time_utc TEXT,
              last_modified_utc TEXT,
              expiration_time_utc TEXT,
              platform_device_id TEXT,
              payload_json TEXT,
              raw_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_activities_case_time
              ON windows_activities(case_id, start_time_utc);
            CREATE INDEX IF NOT EXISTS idx_windows_activities_case_app
              ON windows_activities(case_id, app_display_name);
            CREATE INDEX IF NOT EXISTS idx_windows_activities_output
              ON windows_activities(tool_output_id);

            CREATE TABLE IF NOT EXISTS clipboard_items (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              user_profile TEXT,
              source_type TEXT,
              source_table TEXT,
              row_identifier TEXT,
              item_time_utc TEXT,
              created_time_utc TEXT,
              modified_time_utc TEXT,
              last_used_time_utc TEXT,
              sequence_number TEXT,
              format_name TEXT,
              content_type TEXT,
              text_content TEXT,
              file_uri TEXT,
              html_content TEXT,
              image_present TEXT,
              payload_size TEXT,
              cloud_sync_state TEXT,
              cloud_sync_id TEXT,
              device_id TEXT,
              raw_payload_json TEXT,
              parser_status TEXT,
              parser_error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_clipboard_items_case_time
              ON clipboard_items(case_id, item_time_utc);
            CREATE INDEX IF NOT EXISTS idx_clipboard_items_case_user
              ON clipboard_items(case_id, user_profile);
            CREATE INDEX IF NOT EXISTS idx_clipboard_items_output
              ON clipboard_items(tool_output_id);

            CREATE TABLE IF NOT EXISTS webcache_entries (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_database TEXT,
              source_table TEXT,
              table_row_number TEXT,
              user_name TEXT,
              application TEXT,
              application_package TEXT,
              container_directory TEXT,
              attribution_method TEXT,
              container_id TEXT,
              container_name TEXT,
              entry_id TEXT,
              entry_type TEXT,
              url TEXT,
              host TEXT,
              cache_file TEXT,
              file_name TEXT,
              content_type TEXT,
              http_status TEXT,
              created_utc TEXT,
              accessed_utc TEXT,
              modified_utc TEXT,
              expires_utc TEXT,
              synced_utc TEXT,
              request_headers TEXT,
              response_headers TEXT,
              raw_metadata_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_webcache_entries_case_accessed
              ON webcache_entries(case_id, accessed_utc);
            CREATE INDEX IF NOT EXISTS idx_webcache_entries_case_host
              ON webcache_entries(case_id, host);
            CREATE INDEX IF NOT EXISTS idx_webcache_entries_output
              ON webcache_entries(tool_output_id);

            CREATE TABLE IF NOT EXISTS webcache_file_accesses (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_webcache_entry_id TEXT NOT NULL,
              source_database TEXT,
              source_table TEXT,
              user_name TEXT,
              application TEXT,
              application_package TEXT,
              container_directory TEXT,
              attribution_method TEXT,
              container_name TEXT,
              entry_id TEXT,
              url TEXT NOT NULL,
              local_path TEXT,
              normalized_path TEXT,
              cache_file TEXT,
              file_name TEXT,
              created_utc TEXT,
              accessed_utc TEXT,
              modified_utc TEXT,
              expires_utc TEXT,
              synced_utc TEXT,
              raw_metadata_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_webcache_file_accesses_case_accessed
              ON webcache_file_accesses(case_id, accessed_utc);
            CREATE INDEX IF NOT EXISTS idx_webcache_file_accesses_case_path
              ON webcache_file_accesses(case_id, normalized_path);
            CREATE INDEX IF NOT EXISTS idx_webcache_file_accesses_output
              ON webcache_file_accesses(tool_output_id);

            CREATE TABLE IF NOT EXISTS mailbox_messages (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              container_path TEXT,
              message_path TEXT,
              source_format TEXT,
              parser_status TEXT,
              parser_error TEXT,
              user_profile TEXT,
              user_sid TEXT,
              message_id TEXT,
              in_reply_to TEXT,
              references_header TEXT,
              reply_to TEXT,
              conversation_index TEXT,
              conversation_topic TEXT,
              importance TEXT,
              priority TEXT,
              sensitivity TEXT,
              x_originating_ip TEXT,
              message_flags TEXT,
              message_status TEXT,
              message_status_flags TEXT,
              disposition_notification_to TEXT,
              subject TEXT,
              sender TEXT,
              recipients TEXT,
              cc TEXT,
              bcc TEXT,
              message_date_utc TEXT,
              body_text TEXT,
              body_html TEXT,
              body_text_sha256 TEXT,
              body_html_sha256 TEXT,
              body_text_length INTEGER,
              body_html_length INTEGER,
              opensearch_document_id TEXT,
              attachment_names TEXT,
              attachment_count INTEGER,
              has_attachments TEXT,
              dedupe_key TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mailbox_messages_case_date
              ON mailbox_messages(case_id, message_date_utc);
            CREATE INDEX IF NOT EXISTS idx_mailbox_messages_dedupe
              ON mailbox_messages(case_id, dedupe_key);
            CREATE INDEX IF NOT EXISTS idx_mailbox_messages_output
              ON mailbox_messages(tool_output_id);

            CREATE TABLE IF NOT EXISTS mailbox_attachments (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_path TEXT,
              container_path TEXT,
              message_path TEXT,
              user_profile TEXT,
              user_sid TEXT,
              message_id TEXT,
              conversation_index TEXT,
              conversation_topic TEXT,
              subject TEXT,
              sender TEXT,
              recipients TEXT,
              message_date_utc TEXT,
              attachment_name TEXT,
              attachment_path TEXT,
              content_type TEXT,
              size INTEGER,
              sha256 TEXT,
              metadata_json TEXT,
              metadata_json_sha256 TEXT,
              metadata_json_length INTEGER,
              extracted_text TEXT,
              extracted_text_sha256 TEXT,
              extracted_text_length INTEGER,
              opensearch_document_id TEXT,
              extraction_status TEXT,
              parser_error TEXT,
              dedupe_key TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mailbox_attachments_case_sha
              ON mailbox_attachments(case_id, sha256);
            CREATE INDEX IF NOT EXISTS idx_mailbox_attachments_output
              ON mailbox_attachments(tool_output_id);

            CREATE TABLE IF NOT EXISTS windows_mail_store_rows (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_database TEXT,
              source_table TEXT,
              table_file TEXT,
              table_row_number TEXT,
              user_profile TEXT,
              source_record_id TEXT,
              parent_record_id TEXT,
              display_name TEXT,
              primary_time_utc TEXT,
              secondary_time_utc TEXT,
              row_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_windows_mail_store_case_table
              ON windows_mail_store_rows(case_id, source_table);
            CREATE INDEX IF NOT EXISTS idx_windows_mail_store_case_time
              ON windows_mail_store_rows(case_id, primary_time_utc);
            CREATE INDEX IF NOT EXISTS idx_windows_mail_store_output
              ON windows_mail_store_rows(tool_output_id);

            CREATE TABLE IF NOT EXISTS search_index_runs (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              backend TEXT NOT NULL,
              backend_url TEXT NOT NULL,
              index_name TEXT NOT NULL,
              backend_version TEXT,
              status TEXT NOT NULL,
              document_count INTEGER NOT NULL,
              batch_count INTEGER NOT NULL,
              source_counts_json TEXT NOT NULL,
              query_synonyms_json TEXT NOT NULL,
              started_at TEXT NOT NULL,
              ended_at TEXT,
              error TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_search_index_runs_case_started
              ON search_index_runs(case_id, started_at);

            CREATE TABLE IF NOT EXISTS content_references (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              tool_output_id TEXT,
              source_tool TEXT,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              content_role TEXT NOT NULL,
              opensearch_document_id TEXT NOT NULL,
              content_sha256 TEXT,
              content_length INTEGER,
              source_path TEXT,
              created_at TEXT NOT NULL,
              UNIQUE(source_table, source_row_id, content_role)
            );
            CREATE INDEX IF NOT EXISTS idx_content_refs_case_doc
              ON content_references(case_id, opensearch_document_id);
            CREATE INDEX IF NOT EXISTS idx_content_refs_source
              ON content_references(source_table, source_row_id);
            CREATE INDEX IF NOT EXISTS idx_content_refs_output
              ON content_references(tool_output_id);

            CREATE TABLE IF NOT EXISTS cloud_server_events (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT REFERENCES computers(id),
              image_id TEXT REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              provider TEXT,
              service TEXT,
              event_type TEXT,
              event_time_utc TEXT,
              actor TEXT,
              actor_id TEXT,
              actor_ip TEXT,
              target TEXT,
              target_id TEXT,
              target_type TEXT,
              operation TEXT,
              result TEXT,
              user_agent TEXT,
              client_app TEXT,
              file_name TEXT,
              file_path TEXT,
              url TEXT,
              message_id TEXT,
              conversation_id TEXT,
              content_sha256 TEXT,
              content_length INTEGER,
              opensearch_document_id TEXT,
              source_log_type TEXT,
              source_record_id TEXT,
              raw_fields_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cloud_server_events_case_time
              ON cloud_server_events(case_id, event_time_utc);
            CREATE INDEX IF NOT EXISTS idx_cloud_server_events_case_provider
              ON cloud_server_events(case_id, provider, service);

            CREATE TABLE IF NOT EXISTS memory_string_hits (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT REFERENCES computers(id),
              image_id TEXT REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_artifact_type TEXT,
              source_path TEXT,
              scanned_path TEXT,
              decompressed_path TEXT,
              scanner TEXT,
              encoding TEXT,
              hit_category TEXT,
              matched_term TEXT,
              string_value TEXT,
              string_sha256 TEXT,
              string_length INTEGER,
              offset TEXT,
              context_hint TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_memory_string_hits_case_category
              ON memory_string_hits(case_id, hit_category);
            CREATE INDEX IF NOT EXISTS idx_memory_string_hits_output
              ON memory_string_hits(tool_output_id);

            CREATE TABLE IF NOT EXISTS structured_memory_records (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT REFERENCES computers(id),
              image_id TEXT REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              source_artifact_type TEXT,
              source_path TEXT,
              analysis_engine TEXT,
              plugin TEXT,
              category TEXT,
              record_type TEXT,
              pid TEXT,
              ppid TEXT,
              process_name TEXT,
              command_line TEXT,
              local_address TEXT,
              local_port TEXT,
              foreign_address TEXT,
              foreign_port TEXT,
              protocol TEXT,
              state TEXT,
              object_type TEXT,
              object_name TEXT,
              path TEXT,
              module_base TEXT,
              module_size TEXT,
              offset TEXT,
              virtual_address TEXT,
              created_utc TEXT,
              exited_utc TEXT,
              suspicious TEXT,
              summary TEXT,
              raw_record_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_structured_memory_case_category
              ON structured_memory_records(case_id, category);
            CREATE INDEX IF NOT EXISTS idx_structured_memory_case_process
              ON structured_memory_records(case_id, pid, process_name);

            CREATE TABLE IF NOT EXISTS memory_credential_reviews (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              memory_hit_id TEXT NOT NULL,
              review_status TEXT NOT NULL,
              reviewer TEXT,
              note TEXT,
              reviewed_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              UNIQUE(case_id, memory_hit_id)
            );
            CREATE INDEX IF NOT EXISTS idx_memory_credential_reviews_case
              ON memory_credential_reviews(case_id, review_status);

            CREATE TABLE IF NOT EXISTS messaging_records (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              application TEXT,
              user_profile TEXT,
              artifact_type TEXT,
              source_path TEXT,
              store_path TEXT,
              record_key TEXT,
              record_type TEXT,
              url TEXT,
              host TEXT,
              email TEXT,
              timestamp_utc TEXT,
              message_text TEXT,
              raw_text TEXT,
              message_text_sha256 TEXT,
              message_text_length INTEGER,
              raw_text_sha256 TEXT,
              raw_text_length INTEGER,
              opensearch_document_id TEXT,
              dedupe_key TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messaging_records_case_app
              ON messaging_records(case_id, application);
            CREATE INDEX IF NOT EXISTS idx_messaging_records_output
              ON messaging_records(tool_output_id);

            CREATE TABLE IF NOT EXISTS messaging_messages (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT NOT NULL REFERENCES computers(id),
              image_id TEXT NOT NULL REFERENCES images(id),
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_name TEXT NOT NULL,
              source_csv TEXT NOT NULL,
              row_number INTEGER NOT NULL,
              application TEXT,
              user_profile TEXT,
              source_path TEXT,
              store_path TEXT,
              record_key TEXT,
              platform_message_id TEXT,
              conversation_id TEXT,
              channel_id TEXT,
              thread_id TEXT,
              sender_id TEXT,
              sender_name TEXT,
              sender_email TEXT,
              recipient TEXT,
              timestamp_utc TEXT,
              message_type TEXT,
              message_text TEXT,
              message_html TEXT,
              url TEXT,
              parser_confidence TEXT,
              raw_json TEXT,
              message_text_sha256 TEXT,
              message_text_length INTEGER,
              message_html_sha256 TEXT,
              message_html_length INTEGER,
              raw_json_sha256 TEXT,
              raw_json_length INTEGER,
              opensearch_document_id TEXT,
              dedupe_key TEXT,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messaging_messages_case_app
              ON messaging_messages(case_id, application, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_messaging_messages_output
              ON messaging_messages(tool_output_id);

            CREATE TABLE IF NOT EXISTS activity_log (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              job_id TEXT,
              level TEXT NOT NULL,
              event TEXT NOT NULL,
              message TEXT NOT NULL,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_activity_case_time
              ON activity_log(case_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_activity_case_level
              ON activity_log(case_id, level);
            """
        )
        self._add_column_if_missing("cases", "description", "TEXT")
        self._add_column_if_missing("cases", "notes_path", "TEXT")
        self._add_column_if_missing("images", "computer_id", "TEXT REFERENCES computers(id)")
        self._add_column_if_missing("mounts", "source_type", "TEXT NOT NULL DEFAULT 'ewfmount'")
        self._add_column_if_missing("mounts", "filesystem_type", "TEXT")
        self._add_column_if_missing("jobs", "computer_id", "TEXT")
        self._add_column_if_missing("tool_outputs", "content_sha256", "TEXT")
        self._add_column_if_missing("timeline_events", "is_windows_old", "INTEGER NOT NULL DEFAULT 0")
        self._add_column_if_missing("timeline_events", "end_timestamp_utc", "TEXT")
        self._add_column_if_missing("timeline_events", "duration_ms", "INTEGER")
        self._add_column_if_missing("timeline_events", "dedupe_key", "TEXT")
        self._add_column_if_missing("timeline_events", "primary_event_id", "TEXT")
        self._add_column_if_missing("timeline_events", "dedupe_status", "TEXT NOT NULL DEFAULT 'primary'")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timeline_events_case_dedupe ON timeline_events(case_id, dedupe_key)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timeline_events_case_status_time ON timeline_events(case_id, dedupe_status, timestamp_utc)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timeline_events_case_match ON timeline_events(case_id, is_windows_old, source_tool, source_table, event_type, timestamp_utc)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timeline_events_case_source_time_output ON timeline_events(case_id, source_tool, source_table, event_type, timestamp_utc, tool_output_id)"
        )
        self._add_column_if_missing("prefetch_items", "last_run_times_utc", "TEXT")
        self._add_column_if_missing("prefetch_items", "referenced_strings", "TEXT")
        self._add_column_if_missing("prefetch_items", "resolved_reference_path", "TEXT")
        self._add_column_if_missing("prefetch_items", "resolved_reference_device_path", "TEXT")
        self._add_column_if_missing("prefetch_items", "resolved_reference_command_line", "TEXT")
        self._add_column_if_missing("prefetch_items", "resolved_reference_os", "TEXT")
        self._add_column_if_missing("prefetch_items", "resolved_reference_description", "TEXT")
        self._add_column_if_missing("prefetch_items", "resolved_reference_source", "TEXT")
        self._add_column_if_missing("prefetch_items", "resolved_reference_match_count", "TEXT")
        for table in ("prefetch_items", "prefetch_run_times"):
            self._add_column_if_missing(table, "source_scope", "TEXT DEFAULT 'live'")
            self._add_column_if_missing(table, "snapshot_id", "TEXT")
            self._add_column_if_missing(table, "snapshot_ids", "TEXT")
            self._add_column_if_missing(table, "snapshot_count", "TEXT")
            self._add_column_if_missing(table, "snapshot_index", "TEXT")
            self._add_column_if_missing(table, "snapshot_created_utc", "TEXT")
        for table in (
            "shortcut_items",
            "registry_artifacts",
            "amcache_entries",
            "shimcache_entries",
            "srum_records",
            "browser_history",
            "browser_downloads",
            "firefox_history",
            "recycle_items",
            "recycle_children",
            "evtx_events",
            "windows_search_files",
            "windows_search_gather_logs",
        ):
            self._add_column_if_missing(table, "source_scope", "TEXT DEFAULT 'live'")
            self._add_column_if_missing(table, "snapshot_id", "TEXT")
            self._add_column_if_missing(table, "snapshot_ids", "TEXT")
            self._add_column_if_missing(table, "snapshot_count", "TEXT")
            self._add_column_if_missing(table, "snapshot_index", "TEXT")
            self._add_column_if_missing(table, "snapshot_created_utc", "TEXT")
        for column in (
            "references_header",
            "reply_to",
            "conversation_index",
            "conversation_topic",
            "importance",
            "priority",
            "sensitivity",
            "x_originating_ip",
            "message_flags",
            "message_status",
            "message_status_flags",
            "disposition_notification_to",
        ):
            self._add_column_if_missing("mailbox_messages", column, "TEXT")
        for column in ("conversation_index", "conversation_topic"):
            self._add_column_if_missing("mailbox_attachments", column, "TEXT")
        self._add_column_if_missing("registry_artifacts", "event_time_utc", "TEXT")
        self._add_column_if_missing("registry_artifacts", "recentdocs_time_utc", "TEXT")
        self._add_column_if_missing("registry_artifacts", "recentdocs_extension_time_utc", "TEXT")
        self._add_column_if_missing("registry_artifacts", "mru_position", "TEXT")
        self._add_column_if_missing("registry_artifacts", "recentdocs_mru_position", "TEXT")
        self._add_column_if_missing("registry_artifacts", "recentdocs_extension_mru_position", "TEXT")
        self._add_column_if_missing("registry_artifacts", "is_most_recent", "TEXT")
        self._add_column_if_missing("registry_artifacts", "display_name", "TEXT")
        self._add_column_if_missing("registry_artifacts", "user_sid", "TEXT")
        self._add_column_if_missing("registry_artifacts", "normalized_path", "TEXT")
        self._add_column_if_missing("registry_artifacts", "transaction_logs_detected", "TEXT")
        self._add_column_if_missing("registry_artifacts", "transaction_logs_applied", "TEXT")
        self._add_column_if_missing("registry_artifacts", "transaction_log_paths", "TEXT")
        self._add_column_if_missing("sam_accounts", "account_key_last_write_utc", "TEXT")
        for column, definition in {
            "source_file": "TEXT", "source_name": "TEXT", "parser_status": "TEXT",
            "parser_error": "TEXT", "timestamp_utc": "TEXT", "provider_name": "TEXT",
            "provider_id": "TEXT", "provider_label": "TEXT", "event_category": "TEXT",
            "event_name": "TEXT", "event_id": "TEXT",
            "opcode": "TEXT", "version": "TEXT", "process_id": "TEXT",
            "parent_process_id": "TEXT", "session_id": "TEXT", "image_name": "TEXT",
            "command_line": "TEXT", "user_sid": "TEXT", "package_full_name": "TEXT",
            "flags": "TEXT", "payload_strings_json": "TEXT", "event_values_json": "TEXT",
            "file_size": "TEXT", "sha256_first_mb": "TEXT",
        }.items():
            self._add_column_if_missing("etl_events", column, definition)
        for table in (
            "registry_recentdocs",
            "registry_runmru",
            "registry_typedpaths",
            "registry_wordwheel_query",
            "registry_userassist",
            "registry_office_mru",
            "registry_common_dialog_mru",
            "registry_trusted_documents",
            "registry_office_trust_records",
            "registry_taskbar_feature_usage",
        ):
            self._add_column_if_missing(table, "hive_path", "TEXT")
            self._add_column_if_missing(table, "hive_type", "TEXT")
            self._add_column_if_missing(table, "user_profile", "TEXT")
            self._add_column_if_missing(table, "category", "TEXT")
            self._add_column_if_missing(table, "key_path", "TEXT")
            self._add_column_if_missing(table, "key_last_write_timestamp", "TEXT")
            self._add_column_if_missing(table, "recmd_description", "TEXT")
        for column in (
            "executable_is_guid",
            "resolved_executable",
            "executable_resolution_source",
            "executable_resolution_confidence",
        ):
            self._add_column_if_missing("registry_common_dialog_mru", column, "TEXT")
        for column in (
            "multipart_set_id",
            "multipart_part_number",
            "multipart_part_count",
            "multipart_is_first_part",
            "multipart_related_parts",
        ):
            self._add_column_if_missing("archive_entries", column, "TEXT")
            self._add_column_if_missing("nested_evidence_items", column, "TEXT")
        for table, columns in {
            "amcache_entries": {
                "entry_type": "TEXT", "source_file": "TEXT", "path": "TEXT", "name": "TEXT",
                "publisher": "TEXT", "product_name": "TEXT", "product_version": "TEXT",
                "file_version": "TEXT", "sha1": "TEXT", "sha256": "TEXT", "binary_type": "TEXT",
                "size": "TEXT", "created_utc": "TEXT", "modified_utc": "TEXT", "link_date": "TEXT",
                "compile_time": "TEXT", "program_id": "TEXT", "install_date": "TEXT",
                "unassociated": "TEXT",
            },
            "shimcache_entries": {
                "source_file": "TEXT", "control_set": "TEXT", "entry_number": "TEXT",
                "path": "TEXT", "last_modified_utc": "TEXT", "executed": "TEXT", "source_key": "TEXT",
            },
            "shortcut_items": {
                "local_path": "TEXT", "common_path": "TEXT", "target_path": "TEXT",
                "relative_path": "TEXT", "target_id_absolute_path": "TEXT",
                "target_mft_entry_number": "TEXT", "target_mft_sequence_number": "TEXT",
                "icon_location": "TEXT", "hot_key": "TEXT", "window_style": "TEXT",
                "header_flags": "TEXT", "link_flags": "TEXT",
                "machine_mac_address": "TEXT", "tracker_created_on": "TEXT",
                "tracker_id": "TEXT", "droid_volume_id": "TEXT", "droid_file_id": "TEXT",
                "birth_droid_volume_id": "TEXT", "birth_droid_file_id": "TEXT",
                "command_line_arguments": "TEXT", "working_directory": "TEXT",
                "network_path": "TEXT", "machine_name": "TEXT", "app_id": "TEXT",
                "app_id_description": "TEXT", "entry_id": "TEXT",
                "destlist_version": "TEXT",
            },
            "shellbag_entries": {
                "source_file": "TEXT", "hive_path": "TEXT", "user_profile": "TEXT",
                "absolute_path": "TEXT", "shell_type": "TEXT", "value_name": "TEXT",
                "mru_position": "TEXT", "slot": "TEXT", "node_slot": "TEXT",
                "created_on": "TEXT", "modified_on": "TEXT", "accessed_on": "TEXT",
                "last_write_time": "TEXT", "first_interacted": "TEXT", "last_interacted": "TEXT",
                "has_explored": "TEXT",
                "drive_letter": "TEXT", "volume_guid": "TEXT",
                "volume_serial_number": "TEXT", "volume_name": "TEXT",
            },
            "usb_devices": {
                "source_path": "TEXT", "artifact": "TEXT", "device_type": "TEXT",
                "vendor_id": "TEXT", "product_id": "TEXT", "vendor": "TEXT",
                "product": "TEXT", "revision": "TEXT", "friendly_name": "TEXT", "serial": "TEXT",
                "instance_id": "TEXT", "parent_id_prefix": "TEXT", "device_service": "TEXT",
                "user_profile": "TEXT", "drive_letter": "TEXT", "volume_guid": "TEXT",
                "volume_serial_number": "TEXT", "volume_name": "TEXT", "capacity_bytes": "TEXT",
                "file_system": "TEXT", "alternate_scsi_serial": "TEXT", "key_path": "TEXT",
                "partition_disk_number": "TEXT", "partition_bus_type": "TEXT",
                "partition_bus_type_code": "TEXT", "partition_user_removal_policy": "TEXT",
                "partition_bytes_per_sector": "TEXT", "partition_bytes_per_logical_sector": "TEXT",
                "partition_bytes_per_physical_sector": "TEXT", "partition_style": "TEXT",
                "partition_style_code": "TEXT", "partition_count": "TEXT",
                "partition_table_bytes": "TEXT", "partition_table_sha256": "TEXT",
                "partition_table_summary": "TEXT", "partition_table_disk_guid": "TEXT",
                "storage_id_code_set": "TEXT", "storage_id_type": "TEXT",
                "storage_id_association": "TEXT", "storage_id_bytes": "TEXT",
                "storage_id_hex": "TEXT", "storage_id_ascii": "TEXT",
                "storage_id_sha256": "TEXT", "partition_registry_id": "TEXT",
                "partition_adapter_id": "TEXT", "partition_pool_id": "TEXT",
                "partition_location": "TEXT", "partition_flags": "TEXT",
                "partition_characteristics": "TEXT",
                "vbr_index": "TEXT", "vbr_bytes": "TEXT", "vbr_oem_name": "TEXT",
                "vbr_file_system": "TEXT", "vbr_volume_serial_number": "TEXT",
                "vbr_volume_serial_number_full": "TEXT", "vbr_volume_name": "TEXT",
                "vbr_parse_status": "TEXT", "vbr_serial_match": "TEXT",
                "mbr_partition_type": "TEXT", "partition_start_lba": "TEXT",
                "partition_sector_count": "TEXT",
                "key_last_write_utc": "TEXT", "last_present_date_utc": "TEXT",
                "property_name": "TEXT", "property_value": "TEXT", "value_data_hex": "TEXT",
            },
            "usb_storage_devices": {
                "vendor_id": "TEXT", "product_id": "TEXT", "vendor": "TEXT",
                "product": "TEXT", "revision": "TEXT", "friendly_name": "TEXT",
                "parent_id_prefix": "TEXT", "device_service": "TEXT", "drive_letter": "TEXT",
                "volume_guid": "TEXT", "volume_serial_number": "TEXT", "volume_name": "TEXT",
                "capacity_bytes": "TEXT", "file_system": "TEXT", "alternate_scsi_serial": "TEXT", "user_profiles": "TEXT",
                "partition_disk_number": "TEXT", "partition_bus_type": "TEXT",
                "partition_bus_type_code": "TEXT", "partition_user_removal_policy": "TEXT",
                "partition_bytes_per_sector": "TEXT", "partition_bytes_per_logical_sector": "TEXT",
                "partition_bytes_per_physical_sector": "TEXT", "partition_style": "TEXT",
                "partition_style_code": "TEXT", "partition_count": "TEXT",
                "partition_table_bytes": "TEXT", "partition_table_sha256": "TEXT",
                "partition_table_summary": "TEXT", "partition_table_disk_guid": "TEXT",
                "storage_id_code_set": "TEXT", "storage_id_type": "TEXT",
                "storage_id_association": "TEXT", "storage_id_bytes": "TEXT",
                "storage_id_hex": "TEXT", "storage_id_ascii": "TEXT",
                "storage_id_sha256": "TEXT", "partition_registry_id": "TEXT",
                "partition_adapter_id": "TEXT", "partition_pool_id": "TEXT",
                "partition_location": "TEXT", "partition_flags": "TEXT",
                "partition_characteristics": "TEXT",
                "vbr_oem_name": "TEXT", "vbr_file_system": "TEXT",
                "vbr_volume_serial_number": "TEXT", "vbr_volume_serial_number_full": "TEXT",
                "vbr_volume_name": "TEXT", "vbr_parse_status": "TEXT",
                "vbr_serial_match": "TEXT", "mbr_partition_type": "TEXT",
                "partition_start_lba": "TEXT", "partition_sector_count": "TEXT",
                "first_install_date_utc": "TEXT", "last_arrival_utc": "TEXT", "last_removal_utc": "TEXT",
                "first_volume_serial_event_utc": "TEXT", "last_partition_event_utc": "TEXT",
                "last_migration_present_utc": "TEXT", "evidence_row_count": "INTEGER NOT NULL DEFAULT 0",
                "source_artifacts": "TEXT",
            },
            "usb_connection_events": {
                "usb_device_id": "TEXT", "serial": "TEXT", "volume_serial_number": "TEXT",
                "volume_guid": "TEXT", "drive_letter": "TEXT", "event_time_utc": "TEXT",
                "event_type": "TEXT", "event_source": "TEXT", "event_id": "TEXT",
                "record_number": "TEXT", "source_path": "TEXT", "key_path": "TEXT",
                "property_name": "TEXT", "property_value": "TEXT", "capacity_bytes": "TEXT",
            },
            "cloud_server_events": {
                "provider": "TEXT", "service": "TEXT", "event_type": "TEXT",
                "event_time_utc": "TEXT", "actor": "TEXT", "actor_id": "TEXT",
                "actor_ip": "TEXT", "target": "TEXT", "target_id": "TEXT",
                "target_type": "TEXT", "operation": "TEXT", "result": "TEXT",
                "user_agent": "TEXT", "client_app": "TEXT", "file_name": "TEXT",
                "file_path": "TEXT", "url": "TEXT", "message_id": "TEXT",
                "conversation_id": "TEXT", "content_sha256": "TEXT",
                "content_length": "INTEGER", "opensearch_document_id": "TEXT",
                "source_log_type": "TEXT", "source_record_id": "TEXT",
                "raw_fields_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "memory_string_hits": {
                "source_artifact_type": "TEXT", "source_path": "TEXT",
                "scanned_path": "TEXT", "decompressed_path": "TEXT",
                "scanner": "TEXT", "encoding": "TEXT", "hit_category": "TEXT",
                "matched_term": "TEXT", "string_value": "TEXT",
                "string_sha256": "TEXT", "string_length": "INTEGER",
                "offset": "TEXT", "context_hint": "TEXT",
            },
            "structured_memory_records": {
                "source_artifact_type": "TEXT", "source_path": "TEXT",
                "analysis_engine": "TEXT", "plugin": "TEXT", "category": "TEXT",
                "record_type": "TEXT", "pid": "TEXT", "ppid": "TEXT",
                "process_name": "TEXT", "command_line": "TEXT",
                "local_address": "TEXT", "local_port": "TEXT",
                "foreign_address": "TEXT", "foreign_port": "TEXT",
                "protocol": "TEXT", "state": "TEXT", "object_type": "TEXT",
                "object_name": "TEXT", "path": "TEXT", "module_base": "TEXT",
                "module_size": "TEXT", "offset": "TEXT", "virtual_address": "TEXT",
                "created_utc": "TEXT", "exited_utc": "TEXT", "suspicious": "TEXT",
                "summary": "TEXT", "raw_record_json": "TEXT",
            },
            "usn_journal_entries": {
                "source_file": "TEXT", "update_sequence_number": "TEXT",
                "update_timestamp": "TEXT", "file_name": "TEXT", "extension": "TEXT",
                "file_reference_number": "TEXT", "file_reference_sequence_number": "TEXT",
                "parent_file_reference_number": "TEXT",
                "parent_file_reference_sequence_number": "TEXT", "full_path": "TEXT",
                "reason": "TEXT", "reason_flags": "TEXT", "file_attributes": "TEXT",
                "file_attributes_flags": "TEXT", "source_info": "TEXT", "security_id": "TEXT",
                "major_version": "TEXT", "minor_version": "TEXT", "record_length": "TEXT",
                "offset": "TEXT",
            },
            "srum_records": {
                "provider_guid": "TEXT", "provider_name": "TEXT", "source_table": "TEXT",
                "record_type": "TEXT", "srum_id": "TEXT", "timestamp": "TEXT",
                "app_id": "TEXT", "app_name": "TEXT", "app_path": "TEXT",
                "app_description": "TEXT", "exe_timestamp": "TEXT",
                "user_id": "TEXT", "user_sid": "TEXT", "user_name": "TEXT",
                "bytes_received": "TEXT", "bytes_sent": "TEXT", "interface_luid": "TEXT",
                "interface_type": "TEXT", "l2_profile_id": "TEXT", "l2_profile_name": "TEXT",
                "l2_profile_flags": "TEXT",
                "connected_time": "TEXT", "connect_start_time": "TEXT",
                "connect_end_time": "TEXT", "notification_type": "TEXT",
                "payload_size": "TEXT", "network_type": "TEXT",
                "foreground_bytes_read": "TEXT",
                "foreground_bytes_written": "TEXT", "background_bytes_read": "TEXT",
                "background_bytes_written": "TEXT", "foreground_cycle_time": "TEXT",
                "background_cycle_time": "TEXT", "face_time": "TEXT",
                "foreground_context_switches": "TEXT", "background_context_switches": "TEXT",
                "foreground_read_operations": "TEXT", "foreground_write_operations": "TEXT",
                "background_read_operations": "TEXT", "background_write_operations": "TEXT",
                "foreground_flushes": "TEXT", "background_flushes": "TEXT",
                "flags": "TEXT", "start_time": "TEXT", "end_time": "TEXT",
                "duration_ms": "TEXT", "span_ms": "TEXT", "timeline_end": "TEXT",
                "event_timestamp": "TEXT", "state_transition": "TEXT",
                "charge_level": "TEXT", "cycle_count": "TEXT",
                "designed_capacity": "TEXT", "full_charged_capacity": "TEXT",
                "active_ac_time": "TEXT", "active_dc_time": "TEXT",
                "active_discharge_time": "TEXT", "active_energy": "TEXT",
                "cs_ac_time": "TEXT", "cs_dc_time": "TEXT",
                "cs_discharge_time": "TEXT", "cs_energy": "TEXT",
                "configuration_hash": "TEXT", "metadata": "TEXT", "energy_data": "TEXT",
                "tag": "TEXT", "binary_data": "TEXT",
                "vpn_profile_name": "TEXT", "vpn_server": "TEXT", "vpn_device": "TEXT",
                "vpn_protocol": "TEXT", "vpn_phonebook_path": "TEXT",
                "vpn_match_method": "TEXT",
                "row_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "mft_entries": {
                "si_flags": "TEXT",
                "reparse_target": "TEXT",
                "object_id": "TEXT",
                "birth_volume_id": "TEXT",
                "birth_object_id": "TEXT",
                "birth_domain_id": "TEXT",
            },
            "filesystem_entries": {
                "partition_id": "TEXT", "filesystem_type": "TEXT", "source_root": "TEXT",
                "file_path": "TEXT", "parent_path": "TEXT", "file_name": "TEXT",
                "extension": "TEXT", "file_size": "TEXT", "is_directory": "TEXT",
                "created_utc": "TEXT", "modified_utc": "TEXT", "accessed_utc": "TEXT",
                "metadata_changed_utc": "TEXT", "mode": "TEXT", "uid": "TEXT",
                "gid": "TEXT", "scan_status": "TEXT", "error": "TEXT",
            },
            "ntfs_index_entries": {
                "directory_entry_number": "TEXT", "directory_path": "TEXT",
                "source": "TEXT", "block_vcn": "TEXT", "block_active": "TEXT",
                "entry_offset": "TEXT", "index_entry_length": "TEXT",
                "index_entry_flags": "TEXT", "referenced_entry_number": "TEXT",
                "referenced_sequence_number": "TEXT", "parent_entry_number": "TEXT",
                "parent_sequence_number": "TEXT", "file_name": "TEXT",
                "name_type": "TEXT", "name_type_label": "TEXT",
                "created_fn": "TEXT", "modified_fn": "TEXT",
                "record_changed_fn": "TEXT", "accessed_fn": "TEXT",
                "allocated_size": "TEXT", "real_size": "TEXT", "file_flags": "TEXT",
                "from_slack": "TEXT", "source_file": "TEXT",
            },
            "ntfs_index_bitmaps": {
                "directory_entry_number": "TEXT", "directory_path": "TEXT",
                "index_root_attr": "TEXT", "index_allocation_attr": "TEXT",
                "bitmap_attr": "TEXT", "bitmap_hex": "TEXT",
                "active_block_count": "TEXT", "active_blocks": "TEXT", "error": "TEXT",
            },
            "ntfs_namespace_reconciliation": {
                "mft_entry_number": "TEXT NOT NULL DEFAULT ''",
                "mft_sequence_number": "TEXT", "parent_entry_number": "TEXT",
                "parent_path": "TEXT", "file_name": "TEXT", "original_path": "TEXT",
                "mft_in_use": "TEXT", "mounted_present": "TEXT",
                "parent_mounted_exists": "TEXT", "parent_access_status": "TEXT",
                "index_status": "TEXT NOT NULL DEFAULT ''",
                "legit_active_file": "TEXT NOT NULL DEFAULT 'false'",
                "index_entry_id": "TEXT", "index_from_slack": "TEXT",
                "index_block_active": "TEXT", "index_bitmap_error": "TEXT",
                "icat_recovered": "TEXT", "recovered_size": "TEXT",
                "recovered_sha256": "TEXT", "header_type": "TEXT", "zero_prefix": "TEXT",
                "reason": "TEXT",
            },
            "ntfs_logfile_entries": {
                "source_file": "TEXT", "event_time": "TEXT", "operation": "TEXT",
                "redo_operation": "TEXT", "undo_operation": "TEXT",
                "target_attribute": "TEXT", "file_name": "TEXT", "file_path": "TEXT",
                "file_reference_number": "TEXT", "file_reference_sequence_number": "TEXT",
                "parent_file_reference_number": "TEXT",
                "parent_file_reference_sequence_number": "TEXT",
                "log_sequence_number": "TEXT", "previous_log_sequence_number": "TEXT",
                "transaction_id": "TEXT", "client_id": "TEXT", "record_offset": "TEXT",
                "row_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "filesystem_review": {
                "source_table": "TEXT NOT NULL DEFAULT ''", "source_id": "TEXT NOT NULL DEFAULT ''",
                "source_tool": "TEXT", "source_row_number": "INTEGER",
                "event_type": "TEXT NOT NULL DEFAULT ''", "event_time": "TEXT",
                "file_name": "TEXT", "file_path": "TEXT", "parent_path": "TEXT",
                "mft_entry_number": "TEXT", "mft_sequence_number": "TEXT",
                "parent_entry_number": "TEXT", "parent_sequence_number": "TEXT",
                "in_use": "TEXT", "is_directory": "TEXT", "operation": "TEXT",
                "reason": "TEXT", "status": "TEXT",
                "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "windows_search_files": {
                "work_id": "TEXT", "gather_time": "TEXT", "item_path": "TEXT",
                "item_url": "TEXT", "folder_path": "TEXT", "file_name": "TEXT",
                "file_extension": "TEXT", "item_type": "TEXT", "date_created": "TEXT",
                "date_modified": "TEXT", "date_accessed": "TEXT", "date_imported": "TEXT",
                "size": "TEXT", "owner": "TEXT", "computer_name": "TEXT",
                "is_deleted": "TEXT", "is_folder": "TEXT",
                "source_scope": "TEXT DEFAULT 'live'", "snapshot_id": "TEXT",
                "snapshot_ids": "TEXT", "snapshot_count": "TEXT",
                "snapshot_index": "TEXT", "snapshot_created_utc": "TEXT",
                "row_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "bits_jobs": {
                "source_path": "TEXT", "database_file": "TEXT", "source_table": "TEXT",
                "record_id": "TEXT", "record_type": "TEXT", "job_id": "TEXT",
                "job_name": "TEXT", "job_owner": "TEXT", "job_state": "TEXT",
                "job_type": "TEXT", "priority": "TEXT", "created_utc": "TEXT",
                "modified_utc": "TEXT", "completed_utc": "TEXT",
                "expiration_utc": "TEXT", "url": "TEXT", "local_path": "TEXT",
                "remote_name": "TEXT", "file_size": "TEXT",
                "bytes_transferred": "TEXT", "raw_row_json": "TEXT NOT NULL DEFAULT '{}'",
                "parser_status": "TEXT", "parser_error": "TEXT",
            },
            "bits_activity": {
                "source_table": "TEXT NOT NULL DEFAULT 'evtx_events'",
                "source_row_id": "TEXT", "event_time_utc": "TEXT",
                "event_id": "TEXT", "event_type": "TEXT", "provider": "TEXT",
                "channel": "TEXT", "computer": "TEXT", "job_id": "TEXT",
                "job_name": "TEXT", "job_owner": "TEXT", "url": "TEXT",
                "peer": "TEXT", "file_count": "TEXT", "total_bytes": "TEXT",
                "bytes_transferred": "TEXT", "local_path": "TEXT",
                "matched_bits_job_id": "TEXT", "correlation_basis": "TEXT",
                "raw_fields_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "windows_search_internet_history": {
                "work_id": "TEXT", "gather_time": "TEXT", "item_url": "TEXT",
                "target_url": "TEXT", "target_host": "TEXT", "target_path": "TEXT",
                "title": "TEXT", "file_name": "TEXT", "item_path": "TEXT",
                "folder_path": "TEXT", "date_created": "TEXT", "date_modified": "TEXT",
                "date_accessed": "TEXT", "date_imported": "TEXT", "owner": "TEXT",
                "row_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "windows_search_activity_history": {
                "work_id": "TEXT", "gather_time": "TEXT", "item_url": "TEXT",
                "content_uri": "TEXT", "app_display_name": "TEXT", "display_text": "TEXT",
                "description": "TEXT", "app_id": "TEXT", "app_activity_id": "TEXT",
                "device_id": "TEXT", "start_time": "TEXT", "end_time": "TEXT",
                "local_start_time": "TEXT", "local_end_time": "TEXT",
                "active_duration": "TEXT", "item_path": "TEXT", "file_name": "TEXT",
                "row_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "windows_search_gather_logs": {
                "source_file": "TEXT", "source_name": "TEXT", "log_type": "TEXT",
                "line_number": "INTEGER", "timestamp_utc": "TEXT", "filetime_hex": "TEXT",
                "time_low_hex": "TEXT", "time_high_hex": "TEXT", "item_url": "TEXT",
                "item_path": "TEXT", "item_scheme": "TEXT", "is_deleted_path": "TEXT",
                "status_hex": "TEXT", "crawl_code_hex": "TEXT", "scope_id": "TEXT",
                "document_id": "TEXT", "raw_fields_json": "TEXT NOT NULL DEFAULT '[]'",
                "source_scope": "TEXT DEFAULT 'live'", "snapshot_id": "TEXT",
                "snapshot_ids": "TEXT", "snapshot_count": "TEXT",
                "snapshot_index": "TEXT", "snapshot_created_utc": "TEXT",
            },
            "windows_search_email_indicators": {
                "source_table": "TEXT NOT NULL DEFAULT ''",
                "source_record_id": "TEXT NOT NULL DEFAULT ''",
                "email": "TEXT NOT NULL DEFAULT ''",
                "domain": "TEXT NOT NULL DEFAULT ''",
                "evidence_field": "TEXT",
                "evidence_value": "TEXT",
                "timestamp": "TEXT",
                "context_path": "TEXT",
                "context_title": "TEXT",
            },
            "windows_search_indexed_content": {
                "source_table": "TEXT NOT NULL DEFAULT ''",
                "source_record_id": "TEXT NOT NULL DEFAULT ''",
                "work_id": "TEXT",
                "gather_time": "TEXT",
                "item_path": "TEXT",
                "item_name": "TEXT",
                "item_type": "TEXT",
                "content_field": "TEXT NOT NULL DEFAULT ''",
                "content_text": "TEXT NOT NULL DEFAULT ''",
                "content_sha256": "TEXT NOT NULL DEFAULT ''",
                "content_length": "INTEGER NOT NULL DEFAULT 0",
                "opensearch_document_id": "TEXT",
                "timestamp": "TEXT",
            },
            "windows_search_properties": {
                "source_table": "TEXT NOT NULL DEFAULT ''",
                "source_record_id": "TEXT NOT NULL DEFAULT ''",
                "work_id": "TEXT",
                "item_path": "TEXT",
                "property_name": "TEXT NOT NULL DEFAULT ''",
                "property_value": "TEXT NOT NULL DEFAULT ''",
                "normalized_name": "TEXT",
                "timestamp": "TEXT",
            },
            "carve_scan_ranges": {
                "profile": "TEXT",
                "carve_type": "TEXT",
                "source_path": "TEXT NOT NULL DEFAULT ''",
                "source_size": "TEXT",
                "range_start": "TEXT",
                "range_end": "TEXT",
                "scanned_bytes": "TEXT",
                "hits_found": "TEXT",
                "limited": "TEXT",
                "limit_reason": "TEXT",
                "status": "TEXT",
                "notes": "TEXT",
            },
            "staged_carves": {
                "profile": "TEXT",
                "source_path": "TEXT NOT NULL DEFAULT ''",
                "source_offset": "TEXT",
                "staged_path": "TEXT NOT NULL DEFAULT ''",
                "staged_name": "TEXT",
                "staged_size": "TEXT",
                "staged_sha256": "TEXT",
                "carve_type": "TEXT",
                "detected_format": "TEXT",
                "parser_status": "TEXT",
                "parser_error": "TEXT",
                "table_count": "TEXT",
                "object_count": "TEXT",
                "extractable_row_count": "TEXT",
                "import_status": "TEXT",
                "notes": "TEXT",
            },
            "windows_search_memory_carves": {
                "carve_path": "TEXT NOT NULL DEFAULT ''",
                "carve_name": "TEXT",
                "carve_size": "TEXT",
                "carve_sha256": "TEXT",
                "source_process": "TEXT",
                "source_pid": "TEXT",
                "virtual_address": "TEXT",
                "detected_format": "TEXT",
                "page_size": "TEXT",
                "reserved_bytes": "TEXT",
                "parser_status": "TEXT",
                "parser_error": "TEXT",
                "table_count": "TEXT",
                "object_count": "TEXT",
                "extractable_row_count": "TEXT",
                "matched_disk_db": "TEXT",
                "matched_disk_page": "TEXT",
                "matched_tail_hex": "TEXT",
                "notes": "TEXT",
            },
            "windows_search_memory_objects": {
                "carve_id": "TEXT NOT NULL DEFAULT ''",
                "carve_path": "TEXT NOT NULL DEFAULT ''",
                "object_type": "TEXT",
                "object_name": "TEXT",
                "table_name": "TEXT",
                "rootpage": "TEXT",
                "sql_text": "TEXT",
                "parser_status": "TEXT",
                "parser_error": "TEXT",
            },
            "windows_search_memory_rows": {
                "carve_id": "TEXT NOT NULL DEFAULT ''",
                "carve_path": "TEXT NOT NULL DEFAULT ''",
                "table_name": "TEXT",
                "table_row_number": "TEXT",
                "row_json": "TEXT NOT NULL DEFAULT '{}'",
                "row_text": "TEXT",
                "row_sha256": "TEXT",
                "parser_status": "TEXT",
                "parser_error": "TEXT",
            },
            "file_internal_metadata": {
                "source_file": "TEXT", "original_path": "TEXT", "file_name": "TEXT",
                "extension": "TEXT", "parser": "TEXT", "metadata_group": "TEXT",
                "property_name": "TEXT", "property_value": "TEXT",
                "raw_property_name": "TEXT", "file_size": "TEXT",
                "mft_created": "TEXT", "mft_modified": "TEXT",
                "mft_accessed": "TEXT", "mft_record_modified": "TEXT",
                "mft_in_use": "TEXT", "path_unresolved": "TEXT",
                "deleted_mft_entry": "TEXT", "live_orphan": "TEXT",
                "extraction_method": "TEXT",
            },
            "file_metadata_extraction_summaries": {
                "tool_name": "TEXT",
                "artifact_name": "TEXT NOT NULL DEFAULT ''",
                "artifact_path": "TEXT NOT NULL DEFAULT ''",
                "selected_count": "INTEGER NOT NULL DEFAULT 0",
                "extracted_count": "INTEGER NOT NULL DEFAULT 0",
                "failed_count": "INTEGER NOT NULL DEFAULT 0",
                "skipped_reparse_count": "INTEGER NOT NULL DEFAULT 0",
                "skipped_deleted_count": "INTEGER NOT NULL DEFAULT 0",
                "skipped_live_orphan_count": "INTEGER NOT NULL DEFAULT 0",
                "live_orphan_count": "INTEGER NOT NULL DEFAULT 0",
                "path_unresolved_count": "INTEGER NOT NULL DEFAULT 0",
                "deleted_path_unresolved_count": "INTEGER NOT NULL DEFAULT 0",
                "mounted_in_place_count": "INTEGER NOT NULL DEFAULT 0",
                "mft_icat_count": "INTEGER NOT NULL DEFAULT 0",
                "source": "TEXT",
            },
            "usb_file_correlations": {
                "computer_id": "TEXT", "image_id": "TEXT", "usb_serial": "TEXT",
                "usb_volume_serial_number": "TEXT", "usb_volume_name": "TEXT",
                "usb_drive_letter": "TEXT", "usb_vendor_id": "TEXT", "usb_product_id": "TEXT",
                "usb_vendor": "TEXT", "usb_product": "TEXT", "usb_friendly_name": "TEXT",
                "usb_file_system": "TEXT", "usb_vbr_file_system": "TEXT",
                "usb_first_install_date_utc": "TEXT", "usb_last_arrival_utc": "TEXT",
                "usb_last_removal_utc": "TEXT", "source_artifact_type": "TEXT",
                "source_artifact_id": "TEXT", "source_artifact_name": "TEXT",
                "source_artifact_path": "TEXT", "user_profile": "TEXT",
                "jumplist_item_number": "TEXT", "file_name": "TEXT", "file_location": "TEXT",
                "target_created": "TEXT",
                "target_modified": "TEXT", "target_accessed": "TEXT", "device_type": "TEXT",
                "target_accessed_original": "TEXT", "target_accessed_precision": "TEXT",
                "target_accessed_note": "TEXT",
                "artifact_volume_serial_number": "TEXT", "artifact_volume_name": "TEXT",
                "artifact_volume_guid": "TEXT", "artifact_drive_letter": "TEXT",
                "temporal_status": "TEXT", "temporal_basis": "TEXT",
                "first_known_connection_utc": "TEXT", "last_known_connection_utc": "TEXT",
                "nearest_connection_before_utc": "TEXT", "nearest_removal_after_utc": "TEXT",
                "volume_serial_match": "TEXT", "confidence": "TEXT",
            },
            "copied_file_indicators": {
                "tool_output_id": "TEXT NOT NULL DEFAULT ''",
                "source_tool": "TEXT NOT NULL DEFAULT ''",
                "source_table": "TEXT NOT NULL DEFAULT ''",
                "source_row_id": "TEXT NOT NULL DEFAULT ''",
                "source_artifact_type": "TEXT NOT NULL DEFAULT ''",
                "source_artifact_name": "TEXT",
                "file_name": "TEXT",
                "file_location": "TEXT",
                "created_time": "TEXT NOT NULL DEFAULT ''",
                "modified_time": "TEXT NOT NULL DEFAULT ''",
                "created_timestamp_utc": "TEXT NOT NULL DEFAULT ''",
                "modified_timestamp_utc": "TEXT NOT NULL DEFAULT ''",
                "indicator": "TEXT NOT NULL DEFAULT ''",
                "reason": "TEXT NOT NULL DEFAULT ''",
                "confidence": "TEXT NOT NULL DEFAULT ''",
                "matched_mft_entry_number": "TEXT",
                "matched_mft_sequence_number": "TEXT",
                "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "registry_common_dialog_items": {
                "tool_output_id": "TEXT NOT NULL DEFAULT ''",
                "source_registry_artifact_id": "TEXT NOT NULL DEFAULT ''",
                "source_csv": "TEXT NOT NULL DEFAULT ''",
                "source_path": "TEXT",
                "hive_type": "TEXT",
                "user_profile": "TEXT",
                "artifact": "TEXT",
                "key_path": "TEXT",
                "key_last_write_utc": "TEXT",
                "mru_position": "TEXT",
                "value_name": "TEXT",
                "item_index": "INTEGER",
                "shell_item_name": "TEXT",
                "shell_created": "TEXT",
                "shell_modified": "TEXT",
                "shell_accessed": "TEXT",
                "raw_fat_times_json": "TEXT NOT NULL DEFAULT '[]'",
            },
            "browser_history": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "browser": "TEXT",
                "source_path": "TEXT", "profile_path": "TEXT", "url": "TEXT",
                "title": "TEXT", "visit_time_utc": "TEXT", "visit_count": "TEXT",
                "typed_count": "TEXT", "visit_source": "TEXT",
                "visit_source_label": "TEXT", "local_vs_synced": "TEXT",
            },
            "firefox_history": {
                "visit_source": "TEXT", "visit_source_label": "TEXT",
                "local_vs_synced": "TEXT",
            },
            "browser_downloads": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "browser": "TEXT",
                "source_path": "TEXT", "profile_path": "TEXT", "target_path": "TEXT",
                "tab_url": "TEXT", "site_url": "TEXT", "referrer": "TEXT",
                "start_time_utc": "TEXT", "end_time_utc": "TEXT",
                "received_bytes": "TEXT", "total_bytes": "TEXT", "state": "TEXT",
                "danger_type": "TEXT", "interrupt_reason": "TEXT",
            },
            "browser_cookies": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "browser": "TEXT",
                "source_path": "TEXT", "profile_path": "TEXT", "host": "TEXT",
                "name": "TEXT", "path": "TEXT", "created_utc": "TEXT",
                "last_accessed_utc": "TEXT", "expires_utc": "TEXT",
                "is_secure": "TEXT", "is_http_only": "TEXT",
            },
            "browser_cache_entries": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "browser": "TEXT",
                "source_path": "TEXT", "profile_path": "TEXT", "cache_type": "TEXT",
                "url": "TEXT", "host": "TEXT", "cache_file": "TEXT",
                "cache_file_size": "TEXT", "cache_file_modified_utc": "TEXT",
            },
            "browser_artifacts": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "browser": "TEXT",
                "artifact_type": "TEXT NOT NULL DEFAULT ''", "source_path": "TEXT",
                "profile_path": "TEXT", "name": "TEXT", "value": "TEXT", "url": "TEXT",
                "title": "TEXT", "host": "TEXT", "local_path": "TEXT",
                "timestamp_utc": "TEXT", "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "browser_session_entries": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "browser": "TEXT",
                "source_path": "TEXT", "profile_path": "TEXT", "session_type": "TEXT",
                "window_id": "TEXT", "tab_id": "TEXT", "tab_index": "TEXT",
                "navigation_index": "TEXT", "url": "TEXT", "title": "TEXT",
                "referrer_url": "TEXT", "host": "TEXT", "timestamp_utc": "TEXT",
                "last_active_time_utc": "TEXT", "is_current": "TEXT",
                "is_pinned": "TEXT", "parser": "TEXT",
                "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "browser_site_settings": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "browser": "TEXT",
                "source_path": "TEXT", "profile_path": "TEXT", "setting_type": "TEXT",
                "origin": "TEXT", "host": "TEXT", "setting_name": "TEXT",
                "setting_value": "TEXT", "last_modified_utc": "TEXT",
                "expiration_utc": "TEXT", "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "browser_notifications": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "browser": "TEXT",
                "source_path": "TEXT", "profile_path": "TEXT", "origin": "TEXT",
                "host": "TEXT", "notification_id": "TEXT", "title": "TEXT",
                "body": "TEXT", "tag": "TEXT", "icon": "TEXT", "badge": "TEXT",
                "created_utc": "TEXT", "notification_timestamp_utc": "TEXT",
                "first_click_utc": "TEXT", "last_click_utc": "TEXT",
                "closed_utc": "TEXT", "num_clicks": "TEXT", "closed_reason": "TEXT",
                "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "office_backstage_items": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "artifact_type": "TEXT NOT NULL DEFAULT ''",
                "source_path": "TEXT", "user_profile": "TEXT", "application": "TEXT",
                "name": "TEXT", "value": "TEXT", "path": "TEXT", "url": "TEXT",
                "host": "TEXT", "timestamp_utc": "TEXT",
                "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "user_dictionary_words": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "source_path": "TEXT",
                "user_profile": "TEXT", "application": "TEXT", "office_version": "TEXT",
                "proofing_id": "TEXT", "dictionary_name": "TEXT", "word": "TEXT",
                "word_index": "INTEGER", "timestamp_utc": "TEXT",
                "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "zone_identifier_ads": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "source_path": "TEXT",
                "file_path": "TEXT", "user_profile": "TEXT", "stream_name": "TEXT",
                "zone_id": "TEXT", "classification": "TEXT", "referrer_url": "TEXT",
                "referrer_host": "TEXT", "host_url": "TEXT", "host": "TEXT",
                "timestamp_utc": "TEXT", "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "thumbcache_entries": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "source_path": "TEXT",
                "source_name": "TEXT", "user_profile": "TEXT", "cache_file_type": "TEXT",
                "cache_id": "TEXT", "entry_index": "TEXT", "entry_offset": "TEXT",
                "entry_size": "TEXT", "thumbnail_offset": "TEXT", "thumbnail_size": "TEXT",
                "thumbnail_type": "TEXT", "thumbnail_sha256": "TEXT", "source_mtime_utc": "TEXT",
                "parser_status": "TEXT", "parser_note": "TEXT",
                "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "thumbcache_search_correlations": {
                "tool_name": "TEXT NOT NULL DEFAULT 'ThumbcacheParser'",
                "thumbcache_entry_id": "TEXT NOT NULL DEFAULT ''", "windows_search_file_id": "TEXT",
                "correlation_basis": "TEXT NOT NULL DEFAULT ''", "confidence": "TEXT NOT NULL DEFAULT ''",
                "cache_id": "TEXT", "thumbcache_user": "TEXT", "thumbcache_path": "TEXT",
                "thumbcache_name": "TEXT", "thumbnail_sha256": "TEXT", "thumbnail_type": "TEXT",
                "search_item_path": "TEXT", "search_file_name": "TEXT",
                "search_date_created": "TEXT", "search_date_modified": "TEXT",
                "search_date_accessed": "TEXT", "search_date_imported": "TEXT",
                "details_json": "TEXT NOT NULL DEFAULT '{}'",
            },
            "cloud_sync_artifacts": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "provider": "TEXT",
                "artifact_type": "TEXT", "user_profile": "TEXT", "source_path": "TEXT",
                "source_name": "TEXT", "database_name": "TEXT", "table_name": "TEXT",
                "event_time_utc": "TEXT", "local_path": "TEXT", "cloud_path": "TEXT",
                "file_name": "TEXT", "file_id": "TEXT", "parent_id": "TEXT",
                "stable_id": "TEXT", "server_path": "TEXT", "url": "TEXT",
                "mime_type": "TEXT", "file_size": "TEXT", "is_folder": "TEXT",
                "is_deleted": "TEXT", "sync_status": "TEXT", "event_type": "TEXT",
                "direction": "TEXT", "owner": "TEXT", "shared": "TEXT",
                "protobuf_fields_json": "TEXT", "details_json": "TEXT", "error": "TEXT",
            },
            "google_drive_cache_map": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "account_id": "TEXT",
                "stable_id": "TEXT", "file_id": "TEXT", "virtual_path": "TEXT",
                "file_name": "TEXT", "cache_id": "TEXT", "cache_path": "TEXT",
                "windows_cache_path": "TEXT", "cache_file_size": "TEXT", "mapping_method": "TEXT",
                "evidence_basis": "TEXT", "details_json": "TEXT",
            },
            "user_controlled_file_references": {
                "display_path": "TEXT", "volume_device": "TEXT",
                "resolved_provider_path": "TEXT", "resolved_file_name": "TEXT",
                "resolved_cache_path": "TEXT", "resolution_status": "TEXT",
                "resolution_basis": "TEXT",
            },
            "onedrive_items": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "artifact_type": "TEXT",
                "user_profile": "TEXT", "account": "TEXT", "source_path": "TEXT",
                "source_ode_csv": "TEXT", "source_ode_row_number": "TEXT",
                "record_type": "TEXT", "name": "TEXT", "path": "TEXT",
                "parent_resource_id": "TEXT", "resource_id": "TEXT", "etag": "TEXT",
                "status": "TEXT", "spo_permissions": "TEXT", "volume_id": "TEXT",
                "item_index": "TEXT", "last_change_utc": "TEXT",
                "disk_last_access_utc": "TEXT", "disk_creation_utc": "TEXT",
                "size": "TEXT", "local_hash_digest": "TEXT",
                "local_hash_algorithm": "TEXT", "shared_item": "TEXT",
                "media_json": "TEXT", "hydration_json": "TEXT", "metadata_json": "TEXT",
                "is_deleted": "TEXT", "delete_time_utc": "TEXT",
                "deleting_process": "TEXT", "error": "TEXT",
            },
            "onedrive_log_entries": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "user_profile": "TEXT",
                "account": "TEXT", "source_path": "TEXT", "source_name": "TEXT",
                "log_type": "TEXT", "record_index": "TEXT", "odl_version": "TEXT",
                "one_drive_version": "TEXT", "windows_version": "TEXT",
                "timestamp_utc": "TEXT", "code_file": "TEXT", "function": "TEXT",
                "flags": "TEXT", "context_data": "TEXT", "event_type": "TEXT",
                "local_path": "TEXT", "url": "TEXT", "resource_id": "TEXT",
                "params_text": "TEXT", "params_json": "TEXT", "raw_strings_json": "TEXT",
                "parser_status": "TEXT", "error": "TEXT",
            },
            "package_cache_entries": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "user_profile": "TEXT",
                "application_package": "TEXT", "source_database": "TEXT",
                "source_table": "TEXT", "table_row_number": "TEXT",
                "cache_name": "TEXT", "site_origin": "TEXT", "request_url": "TEXT",
                "host": "TEXT", "response_status": "TEXT", "response_type": "TEXT",
                "response_headers": "TEXT", "response_date_utc": "TEXT",
                "content_type": "TEXT", "content_length": "TEXT",
                "source_body_path": "TEXT", "stored_body_path": "TEXT",
                "body_file_name": "TEXT", "body_size": "TEXT", "body_sha256": "TEXT",
                "body_encrypted": "TEXT", "encryption_version": "TEXT",
                "decoded_state": "TEXT",
            },
            "package_artifacts": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "record_type": "TEXT",
                "user_profile": "TEXT", "application_package": "TEXT",
                "source_path": "TEXT", "source_name": "TEXT", "file_name": "TEXT",
                "file_extension": "TEXT", "file_size": "TEXT", "modified_utc": "TEXT",
                "event_time_utc": "TEXT", "url": "TEXT", "host": "TEXT", "title": "TEXT",
                "artifact_value": "TEXT", "artifact_text": "TEXT", "details_json": "TEXT",
                "error": "TEXT",
            },
            "telemetry_artifacts": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "record_type": "TEXT",
                "artifact_group": "TEXT", "user_profile": "TEXT", "application": "TEXT",
                "source_path": "TEXT", "source_name": "TEXT", "file_name": "TEXT",
                "file_extension": "TEXT", "file_size": "TEXT", "modified_utc": "TEXT",
                "event_time_utc": "TEXT", "identifier": "TEXT", "path": "TEXT",
                "url": "TEXT", "host": "TEXT", "title": "TEXT", "value_name": "TEXT",
                "value_data": "TEXT", "artifact_text": "TEXT", "sha256_first_mb": "TEXT",
                "details_json": "TEXT", "error": "TEXT",
            },
            "artifact_correlations": {
                "left_source_tool": "TEXT", "right_source_tool": "TEXT",
                "correlation_key": "TEXT", "summary": "TEXT", "details_json": "TEXT",
            },
            "computer_inventory": {
                "source_table": "TEXT", "source_row_id": "TEXT",
                "confidence": "TEXT NOT NULL DEFAULT 'derived'", "details_json": "TEXT",
            },
            "windows_activities": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_path": "TEXT",
                "user_profile": "TEXT", "source_table": "TEXT", "activity_id": "TEXT",
                "app_id": "TEXT", "app_display_name": "TEXT", "activity_type": "TEXT",
                "display_text": "TEXT", "file_name": "TEXT", "content_uri": "TEXT",
                "activation_uri": "TEXT", "fallback_uri": "TEXT",
                "start_time_utc": "TEXT", "end_time_utc": "TEXT",
                "last_modified_utc": "TEXT", "expiration_time_utc": "TEXT",
                "platform_device_id": "TEXT", "payload_json": "TEXT", "raw_json": "TEXT",
            },
            "clipboard_items": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_path": "TEXT",
                "user_profile": "TEXT", "source_type": "TEXT", "source_table": "TEXT",
                "row_identifier": "TEXT", "item_time_utc": "TEXT", "created_time_utc": "TEXT",
                "modified_time_utc": "TEXT", "last_used_time_utc": "TEXT",
                "sequence_number": "TEXT", "format_name": "TEXT", "content_type": "TEXT",
                "text_content": "TEXT", "file_uri": "TEXT", "html_content": "TEXT",
                "image_present": "TEXT", "payload_size": "TEXT",
                "cloud_sync_state": "TEXT", "cloud_sync_id": "TEXT", "device_id": "TEXT",
                "raw_payload_json": "TEXT", "parser_status": "TEXT", "parser_error": "TEXT",
            },
            "webcache_entries": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_database": "TEXT",
                "source_table": "TEXT", "table_row_number": "TEXT", "container_id": "TEXT",
                "user_name": "TEXT", "application": "TEXT", "application_package": "TEXT",
                "container_directory": "TEXT", "attribution_method": "TEXT",
                "container_name": "TEXT", "entry_id": "TEXT", "entry_type": "TEXT",
                "url": "TEXT", "host": "TEXT", "cache_file": "TEXT", "file_name": "TEXT",
                "content_type": "TEXT", "http_status": "TEXT", "created_utc": "TEXT",
                "accessed_utc": "TEXT", "modified_utc": "TEXT", "expires_utc": "TEXT",
                "synced_utc": "TEXT", "request_headers": "TEXT", "response_headers": "TEXT",
                "raw_metadata_json": "TEXT",
            },
            "webcache_file_accesses": {
                "tool_name": "TEXT NOT NULL DEFAULT ''",
                "source_webcache_entry_id": "TEXT NOT NULL DEFAULT ''",
                "source_database": "TEXT", "source_table": "TEXT", "container_name": "TEXT",
                "user_name": "TEXT", "application": "TEXT", "application_package": "TEXT",
                "container_directory": "TEXT", "attribution_method": "TEXT",
                "entry_id": "TEXT", "url": "TEXT NOT NULL DEFAULT ''", "local_path": "TEXT",
                "normalized_path": "TEXT", "cache_file": "TEXT", "file_name": "TEXT",
                "created_utc": "TEXT", "accessed_utc": "TEXT", "modified_utc": "TEXT",
                "expires_utc": "TEXT", "synced_utc": "TEXT", "raw_metadata_json": "TEXT",
            },
            "mailbox_messages": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "source_path": "TEXT",
                "container_path": "TEXT", "message_path": "TEXT", "source_format": "TEXT",
                "parser_status": "TEXT", "parser_error": "TEXT", "user_profile": "TEXT",
                "user_sid": "TEXT",
                "message_id": "TEXT", "in_reply_to": "TEXT", "subject": "TEXT",
                "sender": "TEXT", "recipients": "TEXT", "cc": "TEXT", "bcc": "TEXT",
                "message_date_utc": "TEXT", "body_text": "TEXT", "body_html": "TEXT",
                "body_text_sha256": "TEXT", "body_html_sha256": "TEXT",
                "body_text_length": "INTEGER", "body_html_length": "INTEGER",
                "opensearch_document_id": "TEXT",
                "attachment_names": "TEXT", "attachment_count": "INTEGER",
                "has_attachments": "TEXT", "dedupe_key": "TEXT",
            },
            "mailbox_attachments": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "source_path": "TEXT",
                "container_path": "TEXT", "message_path": "TEXT", "user_profile": "TEXT",
                "user_sid": "TEXT", "message_id": "TEXT", "subject": "TEXT",
                "sender": "TEXT", "recipients": "TEXT", "message_date_utc": "TEXT",
                "attachment_name": "TEXT", "attachment_path": "TEXT", "content_type": "TEXT",
                "size": "INTEGER", "sha256": "TEXT", "metadata_json": "TEXT",
                "metadata_json_sha256": "TEXT", "metadata_json_length": "INTEGER",
                "extracted_text": "TEXT", "extracted_text_sha256": "TEXT",
                "extracted_text_length": "INTEGER", "opensearch_document_id": "TEXT",
                "extraction_status": "TEXT", "parser_error": "TEXT", "dedupe_key": "TEXT",
            },
            "windows_mail_store_rows": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "source_database": "TEXT",
                "source_table": "TEXT", "table_file": "TEXT", "table_row_number": "TEXT",
                "user_profile": "TEXT", "source_record_id": "TEXT", "parent_record_id": "TEXT",
                "display_name": "TEXT", "primary_time_utc": "TEXT", "secondary_time_utc": "TEXT",
                "row_json": "TEXT",
            },
            "search_index_runs": {
                "backend": "TEXT NOT NULL DEFAULT 'opensearch'",
                "backend_url": "TEXT NOT NULL DEFAULT ''",
                "index_name": "TEXT NOT NULL DEFAULT ''",
                "backend_version": "TEXT",
                "status": "TEXT NOT NULL DEFAULT ''",
                "document_count": "INTEGER NOT NULL DEFAULT 0",
                "batch_count": "INTEGER NOT NULL DEFAULT 0",
                "source_counts_json": "TEXT NOT NULL DEFAULT '{}'",
                "query_synonyms_json": "TEXT NOT NULL DEFAULT '[]'",
                "started_at": "TEXT NOT NULL DEFAULT ''",
                "ended_at": "TEXT",
                "error": "TEXT",
            },
            "content_references": {
                "computer_id": "TEXT", "image_id": "TEXT", "tool_output_id": "TEXT",
                "source_tool": "TEXT", "source_table": "TEXT NOT NULL DEFAULT ''",
                "source_row_id": "TEXT NOT NULL DEFAULT ''", "content_role": "TEXT NOT NULL DEFAULT 'content'",
                "opensearch_document_id": "TEXT NOT NULL DEFAULT ''",
                "content_sha256": "TEXT", "content_length": "INTEGER", "source_path": "TEXT",
            },
            "messaging_records": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "application": "TEXT",
                "user_profile": "TEXT",
                "artifact_type": "TEXT", "source_path": "TEXT", "store_path": "TEXT",
                "record_key": "TEXT", "record_type": "TEXT", "url": "TEXT",
                "host": "TEXT", "email": "TEXT", "timestamp_utc": "TEXT",
                "message_text": "TEXT", "raw_text": "TEXT",
                "message_text_sha256": "TEXT", "message_text_length": "INTEGER",
                "raw_text_sha256": "TEXT", "raw_text_length": "INTEGER",
                "opensearch_document_id": "TEXT", "dedupe_key": "TEXT",
            },
            "messaging_messages": {
                "tool_name": "TEXT NOT NULL DEFAULT ''", "source_csv": "TEXT NOT NULL DEFAULT ''",
                "row_number": "INTEGER NOT NULL DEFAULT 0", "application": "TEXT",
                "user_profile": "TEXT", "source_path": "TEXT", "store_path": "TEXT",
                "record_key": "TEXT", "platform_message_id": "TEXT", "conversation_id": "TEXT",
                "channel_id": "TEXT", "thread_id": "TEXT", "sender_id": "TEXT",
                "sender_name": "TEXT", "sender_email": "TEXT", "recipient": "TEXT",
                "timestamp_utc": "TEXT", "message_type": "TEXT", "message_text": "TEXT",
                "message_html": "TEXT", "url": "TEXT", "parser_confidence": "TEXT",
                "raw_json": "TEXT", "message_text_sha256": "TEXT",
                "message_text_length": "INTEGER", "message_html_sha256": "TEXT",
                "message_html_length": "INTEGER", "raw_json_sha256": "TEXT",
                "raw_json_length": "INTEGER", "opensearch_document_id": "TEXT",
                "dedupe_key": "TEXT",
            },
        }.items():
            for column, definition in columns.items():
                self._add_column_if_missing(table, column, definition)
        self.conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_webcache_entries_case_app
              ON webcache_entries(case_id, application);
            CREATE INDEX IF NOT EXISTS idx_webcache_file_accesses_case_app
              ON webcache_file_accesses(case_id, application);
            CREATE INDEX IF NOT EXISTS idx_windows_activities_case_file
              ON windows_activities(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_mft_entries_case_file_name
              ON mft_entries(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_shortcut_items_case_file_name
              ON shortcut_items(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_windows_search_files_case_file_name
              ON windows_search_files(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_thumbcache_search_case_file_name
              ON thumbcache_search_correlations(case_id, search_file_name);
            CREATE INDEX IF NOT EXISTS idx_file_internal_metadata_case_file_name
              ON file_internal_metadata(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_filesystem_review_case_file_name
              ON filesystem_review(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_copied_file_indicators_case_file_name
              ON copied_file_indicators(case_id, file_name);
            CREATE INDEX IF NOT EXISTS idx_cloud_sync_artifacts_case_file_name
              ON cloud_sync_artifacts(case_id, file_name);
            """
        )
        self.conn.execute(
            """
            INSERT INTO schema_version (id, version, updated_at)
            VALUES (1, 4, ?)
            ON CONFLICT(id) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at
            """,
            (utc_now(),),
        )
        for column in ("run_counter", "focus_count", "focus_time", "last_executed"):
            self._add_column_if_missing("registry_artifacts", column, "TEXT")
        for column in ("payload_data4", "payload_data5", "payload_data6"):
            self._add_column_if_missing("evtx_events", column, "TEXT")
        self._add_column_if_missing("jobs", "source_scope", "TEXT NOT NULL DEFAULT 'live'")
        self._add_column_if_missing("process_timings", "source_scope", "TEXT NOT NULL DEFAULT 'live'")
        self.conn.commit()
        self._rebuild_legacy_invalid_foreign_key_tables()
        self._refresh_sqlite_table_column_cache()
        self.conn.commit()
        if self.analytics_mode == "duckdb":
            self.cleanup_empty_sqlite_analytics_tables()

    def _rebuild_legacy_invalid_foreign_key_tables(self) -> None:
        if self._foreign_key_targets("file_correlations") & {"mft_entries"}:
            self._rebuild_file_correlations_without_invalid_fk()
        if self._foreign_key_targets("timeline_event_sources") & {"timeline_events"}:
            self._rebuild_timeline_event_sources_without_invalid_fk()

    def _foreign_key_targets(self, table: str) -> set[str]:
        if not self._sqlite_table_exists(table):
            return set()
        rows = self.conn.execute(f"PRAGMA foreign_key_list({self._quote_identifier(table)})").fetchall()
        return {str(row["table"]) for row in rows}

    def _rebuild_file_correlations_without_invalid_fk(self) -> None:
        self._rebuild_table_without_foreign_keys(
            "file_correlations",
            """
            CREATE TABLE file_correlations (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              mft_entry_id TEXT,
              confidence TEXT NOT NULL,
              reason TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """,
            [
                "id", "case_id", "computer_id", "image_id", "source_table",
                "source_row_id", "mft_entry_id", "confidence", "reason", "created_at",
            ],
            """
            CREATE INDEX IF NOT EXISTS idx_file_correlations_case
              ON file_correlations(case_id);
            CREATE INDEX IF NOT EXISTS idx_file_correlations_source
              ON file_correlations(source_table, source_row_id);
            CREATE INDEX IF NOT EXISTS idx_file_correlations_mft
              ON file_correlations(mft_entry_id);
            """,
        )

    def _rebuild_timeline_event_sources_without_invalid_fk(self) -> None:
        self._rebuild_table_without_foreign_keys(
            "timeline_event_sources",
            """
            CREATE TABLE timeline_event_sources (
              id TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id),
              computer_id TEXT,
              image_id TEXT,
              primary_event_id TEXT NOT NULL,
              duplicate_event_id TEXT NOT NULL,
              source_scope TEXT NOT NULL,
              source_tool TEXT NOT NULL,
              source_table TEXT NOT NULL,
              source_row_id TEXT NOT NULL,
              tool_output_id TEXT NOT NULL REFERENCES tool_outputs(id),
              tool_output_path TEXT,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """,
            [
                "id", "case_id", "computer_id", "image_id", "primary_event_id",
                "duplicate_event_id", "source_scope", "source_tool", "source_table",
                "source_row_id", "tool_output_id", "tool_output_path", "details_json",
                "created_at",
            ],
            """
            CREATE INDEX IF NOT EXISTS idx_timeline_event_sources_case_primary
              ON timeline_event_sources(case_id, primary_event_id);
            CREATE INDEX IF NOT EXISTS idx_timeline_event_sources_case_duplicate
              ON timeline_event_sources(case_id, duplicate_event_id);
            """,
        )

    def _rebuild_table_without_foreign_keys(
        self,
        table: str,
        create_sql: str,
        columns: list[str],
        index_sql: str,
    ) -> None:
        if not self._sqlite_table_exists(table):
            return
        temp_table = f"{table}__legacy_fk"
        quoted_table = self._quote_identifier(table)
        quoted_temp = self._quote_identifier(temp_table)
        common = [
            column
            for column in columns
            if self._sqlite_table_has_column(table, column)
        ]
        if not common:
            return
        column_sql = ", ".join(self._quote_identifier(column) for column in common)
        self.conn.commit()
        self.conn.execute("PRAGMA foreign_keys=OFF")
        try:
            self.conn.execute(f"DROP TABLE IF EXISTS {quoted_temp}")
            self.conn.execute(f"ALTER TABLE {quoted_table} RENAME TO {quoted_temp}")
            self.conn.execute(create_sql)
            self.conn.execute(
                f"INSERT INTO {quoted_table} ({column_sql}) "
                f"SELECT {column_sql} FROM {quoted_temp}"
            )
            self.conn.execute(f"DROP TABLE {quoted_temp}")
            self.conn.executescript(index_sql)
            self.conn.commit()
        finally:
            self.conn.execute("PRAGMA foreign_keys=ON")

    def _drop_sqlite_analytics_views(self) -> None:
        for table in sorted(ANALYTICS_TABLES):
            exists = self.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'view' AND name = ?",
                (table,),
            ).fetchone()
            if exists:
                self.conn.execute(f"DROP VIEW {self._quote_identifier(table)}")
        self.conn.commit()

    def _add_column_if_missing(self, table: str, column: str, definition: str) -> None:
        table_sql = self._quote_identifier(table)
        column_sql = self._quote_identifier(column)
        columns = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table_sql})")}
        if column not in columns:
            self.conn.execute(f"ALTER TABLE {table_sql} ADD COLUMN {column_sql} {definition}")

    def _refresh_sqlite_table_column_cache(self) -> None:
        tables = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        ).fetchall()
        self._sqlite_table_columns = {
            str(row["name"]): [
                str(column["name"])
                for column in self.conn.execute(f"PRAGMA table_info({self._quote_identifier(str(row['name']))})").fetchall()
            ]
            for row in tables
        }

    def cleanup_empty_sqlite_analytics_tables(self, *, vacuum: bool = False) -> dict[str, Any]:
        """Drop empty analytics-owned SQLite tables in DuckDB mode.

        Normal operation writes parsed artifact rows directly to DuckDB. Older
        schema migrations still materialized empty SQLite artifact tables so
        inserts could discover column names. The column cache above removes that
        dependency; this method removes empty leftover tables without touching
        orchestration/control tables or non-empty tables.
        """
        if self.analytics_mode != "duckdb":
            return {"dropped_tables": [], "skipped_non_empty": [], "vacuumed": False}
        dropped: list[str] = []
        skipped_non_empty: list[dict[str, Any]] = []
        for table in sorted(ANALYTICS_TABLES):
            exists = self.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            if not exists:
                continue
            try:
                count = int(self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            except sqlite3.Error:
                continue
            if count:
                skipped_non_empty.append({"table": table, "row_count": count})
                continue
            self.conn.execute(f"DROP TABLE {table}")
            self._create_empty_analytics_view(table)
            dropped.append(table)
        self.conn.commit()
        vacuumed = False
        if vacuum and dropped:
            self.conn.execute("VACUUM")
            vacuumed = True
        return {"dropped_tables": dropped, "skipped_non_empty": skipped_non_empty, "vacuumed": vacuumed}

    def _create_empty_analytics_view(self, table: str) -> None:
        columns = self._sqlite_table_columns.get(table)
        if not columns:
            return
        select_list = ", ".join(f"NULL AS {self._quote_identifier(column)}" for column in columns)
        self.conn.execute(f"CREATE VIEW IF NOT EXISTS {self._quote_identifier(table)} AS SELECT {select_list} WHERE 0")

    @staticmethod
    def _quote_identifier(value: str) -> str:
        return '"' + value.replace('"', '""') + '"'

    def create_case(self, case_id: str, root: Path) -> Case:
        created_at = utc_now()
        self.conn.execute(
            "INSERT INTO cases (id, root, description, notes_path, created_at) VALUES (?, ?, ?, ?, ?)",
            (case_id, str(root), None, None, created_at),
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO projects (id, case_id, name, root, created_at) VALUES (?, ?, ?, ?, ?)",
            (case_id, case_id, case_id, str(root), created_at),
        )
        self.conn.commit()
        return Case(id=case_id, root=root, created_at=created_at)

    def get_case(self, case_id: str) -> Case:
        row = self.conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise KeyError(f"Case not found: {case_id}")
        return Case(
            id=row["id"],
            root=Path(row["root"]),
            created_at=row["created_at"],
            description=row["description"],
            notes_path=row["notes_path"],
        )

    def update_case_description(
        self,
        case_id: str,
        *,
        description: str | None = None,
        notes_path: str | None = None,
    ) -> Case:
        case = self.get_case(case_id)
        next_description = description if description is not None else case.description
        next_notes_path = notes_path if notes_path is not None else case.notes_path
        self.conn.execute(
            "UPDATE cases SET description = ?, notes_path = ? WHERE id = ?",
            (next_description, next_notes_path, case_id),
        )
        self.conn.commit()
        return self.get_case(case_id)

    def create_computer(
        self,
        *,
        computer_id: str,
        case_id: str,
        label: str,
        hostname: str | None = None,
        notes: str | None = None,
    ) -> Computer:
        self.get_case(case_id)
        created_at = utc_now()
        self.conn.execute(
            """
            INSERT INTO computers (id, case_id, label, hostname, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (computer_id, case_id, label, hostname, notes, created_at),
        )
        self.conn.commit()
        return Computer(computer_id, case_id, label, hostname, notes, created_at)

    def get_computer(self, computer_id: str, case_id: str) -> Computer:
        row = self.conn.execute(
            "SELECT * FROM computers WHERE id = ? AND case_id = ?", (computer_id, case_id)
        ).fetchone()
        if row is None:
            raise KeyError(f"Computer not found: {computer_id} for case {case_id}")
        return Computer(
            id=row["id"],
            case_id=row["case_id"],
            label=row["label"],
            hostname=row["hostname"],
            notes=row["notes"],
            created_at=row["created_at"],
        )

    def add_image(
        self, image_id: str, case_id: str, path: Path, computer_id: str | None = None
    ) -> EvidenceImage:
        created_at = utc_now()
        if computer_id is not None:
            self.get_computer(computer_id, case_id)
        self.conn.execute(
            "INSERT INTO images (id, case_id, computer_id, path, created_at) VALUES (?, ?, ?, ?, ?)",
            (image_id, case_id, computer_id, str(path), created_at),
        )
        self.conn.commit()
        return EvidenceImage(
            id=image_id,
            case_id=case_id,
            computer_id=computer_id,
            path=path,
            created_at=created_at,
        )

    def replace_image_metadata(self, *, case_id: str, image_id: str, rows: list[dict[str, Any]]) -> None:
        self.get_image(image_id, case_id)
        self.conn.execute("DELETE FROM image_metadata WHERE case_id = ? AND image_id = ?", (case_id, image_id))
        if rows:
            created_at = utc_now()
            self.conn.executemany(
                """
                INSERT INTO image_metadata (id, case_id, image_id, source, key, value, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        row.get("id") or str(uuid.uuid4()),
                        case_id,
                        image_id,
                        str(row["source"]),
                        str(row["key"]),
                        None if row.get("value") is None else str(row.get("value")),
                        created_at,
                    )
                    for row in rows
                ],
            )
        self._commit()

    def replace_image_hashes(self, *, case_id: str, image_id: str, rows: list[dict[str, Any]]) -> None:
        self.get_image(image_id, case_id)
        self.conn.execute("DELETE FROM image_hashes WHERE case_id = ? AND image_id = ?", (case_id, image_id))
        if rows:
            computed_at = utc_now()
            self.conn.executemany(
                """
                INSERT INTO image_hashes (
                  id, case_id, image_id, algorithm, digest, size_bytes, source_path,
                  status, error, computed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        row.get("id") or str(uuid.uuid4()),
                        case_id,
                        image_id,
                        str(row["algorithm"]).lower(),
                        row.get("digest"),
                        row.get("size_bytes"),
                        str(row.get("source_path") or ""),
                        str(row.get("status") or "computed"),
                        row.get("error"),
                        str(row.get("computed_at") or computed_at),
                    )
                    for row in rows
                ],
            )
        self._commit()

    def image_hashes(self, *, case_id: str, image_id: str | None = None) -> list[dict[str, Any]]:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id:
            where.append("image_id = ?")
            params.append(image_id)
        rows = self.conn.execute(
            f"""
            SELECT *
            FROM image_hashes
            WHERE {' AND '.join(where)}
            ORDER BY image_id, algorithm
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def record_image_verification(self, row: dict[str, Any]) -> None:
        self.get_image(str(row["image_id"]), str(row["case_id"]))
        self.conn.execute(
            """
            INSERT INTO image_verifications (
              id, case_id, image_id, algorithm, expected_digest, actual_digest,
              source_path, size_bytes, status, error, verified_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row.get("id") or str(uuid.uuid4()),
                row["case_id"],
                row["image_id"],
                str(row["algorithm"]).lower(),
                row.get("expected_digest"),
                row.get("actual_digest"),
                str(row.get("source_path") or ""),
                row.get("size_bytes"),
                str(row.get("status") or "unknown"),
                row.get("error"),
                str(row.get("verified_at") or utc_now()),
            ),
        )
        self._commit()

    def image_verifications(self, *, case_id: str, image_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id:
            where.append("image_id = ?")
            params.append(image_id)
        params.append(max(1, int(limit)))
        rows = self.conn.execute(
            f"""
            SELECT *
            FROM image_verifications
            WHERE {' AND '.join(where)}
            ORDER BY verified_at DESC, image_id, algorithm
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def insert_evidence_file_extractions(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        created_at = utc_now()
        self.conn.executemany(
            """
            INSERT INTO evidence_file_extractions (
              id, case_id, computer_id, image_id, artifact_name, source_path,
              extracted_path, inode, extraction_method, sha256, size_bytes,
              created_utc, modified_utc, accessed_utc, metadata_changed_utc,
              status, details_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row.get("id") or str(uuid.uuid4()),
                    row["case_id"],
                    row.get("computer_id"),
                    row["image_id"],
                    row.get("artifact_name"),
                    row.get("source_path"),
                    str(row["extracted_path"]),
                    row.get("inode"),
                    str(row.get("extraction_method") or "unknown"),
                    row.get("sha256"),
                    row.get("size_bytes"),
                    row.get("created_utc"),
                    row.get("modified_utc"),
                    row.get("accessed_utc"),
                    row.get("metadata_changed_utc"),
                    str(row.get("status") or "extracted"),
                    json.dumps(row.get("details") or {}, sort_keys=True),
                    str(row.get("created_at") or created_at),
                )
                for row in rows
            ],
        )
        self._commit()

    def evidence_file_extractions(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
        artifact_name: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id:
            where.append("image_id = ?")
            params.append(image_id)
        if artifact_name:
            where.append("artifact_name = ?")
            params.append(artifact_name)
        params.append(max(1, int(limit)))
        rows = self.conn.execute(
            f"""
            SELECT *
            FROM evidence_file_extractions
            WHERE {' AND '.join(where)}
            ORDER BY created_at DESC, artifact_name, source_path
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def image_metadata(self, *, case_id: str, image_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT source, key, value, created_at
            FROM image_metadata
            WHERE case_id = ? AND image_id = ?
            ORDER BY source, key
            """,
            (case_id, image_id),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_image(self, image_id: str, case_id: str) -> EvidenceImage:
        row = self.conn.execute(
            "SELECT * FROM images WHERE id = ? AND case_id = ?", (image_id, case_id)
        ).fetchone()
        if row is None:
            raise KeyError(f"Image not found: {image_id} for case {case_id}")
        return EvidenceImage(
            id=row["id"],
            case_id=row["case_id"],
            computer_id=row["computer_id"],
            path=Path(row["path"]),
            created_at=row["created_at"],
        )

    def insert_mount(self, values: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO mounts (
              id, case_id, image_id, partition_id, ewf_mount_path, raw_path,
              source_type, filesystem_type, volume_mount_path, offset_bytes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                values["id"],
                values["case_id"],
                values["image_id"],
                values.get("partition_id"),
                str(values["ewf_mount_path"]),
                str(values["raw_path"]),
                values.get("source_type", "ewfmount"),
                values.get("filesystem_type"),
                str(values.get("volume_mount_path")) if values.get("volume_mount_path") else None,
                values.get("offset_bytes"),
                utc_now(),
            ),
        )
        self.conn.commit()

    def latest_mount(self, case_id: str, image_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT * FROM mounts WHERE case_id = ? AND image_id = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (case_id, image_id),
        ).fetchone()

    def insert_artifact(self, values: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO artifacts (
              id, case_id, image_id, name, source, path, kind, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                values["id"],
                values["case_id"],
                values["image_id"],
                values["name"],
                values["source"],
                str(values["path"]),
                values["kind"],
                json.dumps(values.get("metadata", {})),
                utc_now(),
            ),
        )
        self.conn.commit()

    def upsert_evtx_recovery(self, values: dict[str, Any]) -> None:
        now = utc_now()
        self.conn.execute(
            """
            INSERT INTO evtx_recovery (
              id, case_id, computer_id, image_id, artifact_path, original_path,
              file_name, extraction_method, status, original_size, recovered_size,
              readable_bytes, failed_block_count, failed_offsets_json, header_valid,
              parser_tool_output_id, parser_rows_recovered, parser_errors,
              details_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id, image_id, artifact_path) DO UPDATE SET
              computer_id = excluded.computer_id,
              original_path = excluded.original_path,
              file_name = excluded.file_name,
              extraction_method = excluded.extraction_method,
              status = excluded.status,
              original_size = excluded.original_size,
              recovered_size = excluded.recovered_size,
              readable_bytes = excluded.readable_bytes,
              failed_block_count = excluded.failed_block_count,
              failed_offsets_json = excluded.failed_offsets_json,
              header_valid = excluded.header_valid,
              parser_tool_output_id = excluded.parser_tool_output_id,
              parser_rows_recovered = excluded.parser_rows_recovered,
              parser_errors = excluded.parser_errors,
              details_json = excluded.details_json,
              updated_at = excluded.updated_at
            """,
            (
                values.get("id", str(uuid.uuid4())),
                values["case_id"],
                values.get("computer_id"),
                values["image_id"],
                str(values["artifact_path"]),
                values["original_path"],
                values["file_name"],
                values["extraction_method"],
                values["status"],
                values.get("original_size"),
                values.get("recovered_size"),
                values.get("readable_bytes"),
                values.get("failed_block_count", 0),
                json.dumps(values.get("failed_offsets", [])),
                None if values.get("header_valid") is None else 1 if values.get("header_valid") else 0,
                values.get("parser_tool_output_id"),
                values.get("parser_rows_recovered"),
                values.get("parser_errors"),
                json.dumps(values.get("details", {}), default=str),
                now,
                now,
            ),
        )
        self._commit()

    def update_evtx_recovery_parser_counts(self, case_id: str, image_id: str, tool_output_id: str) -> None:
        rows = self.conn.execute(
            """
            SELECT source_file, COUNT(*) AS recovered
            FROM evtx_events
            WHERE case_id = ? AND image_id = ? AND tool_output_id = ?
            GROUP BY source_file
            """,
            (case_id, image_id, tool_output_id),
        ).fetchall()
        for row in rows:
            self.conn.execute(
                """
                UPDATE evtx_recovery
                SET parser_tool_output_id = ?,
                    parser_rows_recovered = ?,
                    updated_at = ?
                WHERE case_id = ? AND image_id = ? AND artifact_path = ?
                """,
                (tool_output_id, row["recovered"], utc_now(), case_id, image_id, row["source_file"]),
            )
        self._commit()

    def update_evtx_recovery_parser_errors(
        self,
        case_id: str,
        image_id: str,
        tool_output_id: str,
        parser_errors: dict[str, Any],
    ) -> None:
        for file_name, error in parser_errors.items():
            self.conn.execute(
                """
                UPDATE evtx_recovery
                SET parser_tool_output_id = ?,
                    parser_errors = ?,
                    updated_at = ?
                WHERE case_id = ?
                  AND image_id = ?
                  AND file_name = ?
                """,
                (tool_output_id, json.dumps(error, default=str), utc_now(), case_id, image_id, file_name),
            )
        self._commit()

    def artifacts_for_image(self, case_id: str, image_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT * FROM artifacts WHERE case_id = ? AND image_id = ?
            ORDER BY created_at, name, path
            """,
            (case_id, image_id),
        ).fetchall()

    def create_job(self, values: dict[str, Any]) -> None:
        source_scope = values.get("source_scope") or _source_scope_from_values(
            values.get("output_folder"),
            values.get("stdout_path"),
            values.get("stderr_path"),
            " ".join(str(part) for part in values.get("command") or []),
        )
        self.conn.execute(
            """
            INSERT INTO jobs (
              id, case_id, image_id, source_scope, tool_name, tool_version,
              command_json, computer_id, start_time, end_time, exit_code,
              stdout_path, stderr_path, output_folder, dry_run
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                values["id"],
                values["case_id"],
                values["image_id"],
                source_scope,
                values["tool_name"],
                values.get("tool_version"),
                json.dumps(values["command"]),
                values.get("computer_id"),
                values["start_time"],
                values.get("end_time"),
                values.get("exit_code"),
                str(values["stdout_path"]),
                str(values["stderr_path"]),
                str(values["output_folder"]),
                1 if values.get("dry_run") else 0,
            ),
        )
        self.conn.commit()

    def insert_tool_output(self, values: dict[str, Any]) -> str:
        job_id = values.get("job_id")
        if job_id:
            self._ensure_job_parent(
                job_id=str(job_id),
                case_id=str(values["case_id"]),
                image_id=str(values["image_id"]),
                computer_id=str(values["computer_id"]),
                tool_name=str(values["tool_name"]),
            )
        self.conn.execute(
            """
            INSERT INTO tool_outputs (
              id, case_id, computer_id, image_id, job_id, tool_name,
              output_type, path, content_sha256, row_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              case_id = excluded.case_id,
              computer_id = excluded.computer_id,
              image_id = excluded.image_id,
              job_id = excluded.job_id,
              tool_name = excluded.tool_name,
              output_type = excluded.output_type,
              path = excluded.path,
              content_sha256 = excluded.content_sha256,
              row_count = excluded.row_count
            """,
            (
                values["id"],
                values["case_id"],
                values["computer_id"],
                values["image_id"],
                job_id,
                values["tool_name"],
                values["output_type"],
                str(values["path"]),
                values.get("content_sha256"),
                values.get("row_count"),
                utc_now(),
            ),
        )
        self.conn.commit()
        return values["id"]

    def ensure_tool_output_parent(
        self,
        *,
        tool_output_id: str,
        case_id: str,
        computer_id: str,
        image_id: str,
        tool_name: str,
        path: Path | str,
    ) -> None:
        created_at = utc_now()
        self.conn.execute(
            """
            INSERT OR IGNORE INTO tool_outputs (
              id, case_id, computer_id, image_id, job_id, tool_name, output_type,
              path, content_sha256, row_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tool_output_id,
                case_id,
                computer_id,
                image_id,
                None,
                tool_name,
                "synthetic_parent",
                str(path),
                None,
                None,
                created_at,
            ),
        )

    def _ensure_job_parent(self, *, job_id: str, case_id: str, image_id: str, computer_id: str | None, tool_name: str) -> None:
        if self.conn.execute("SELECT 1 FROM jobs WHERE id = ?", (job_id,)).fetchone() is not None:
            return
        now = utc_now()
        self.conn.execute(
            """
            INSERT INTO jobs (
              id, case_id, image_id, computer_id, source_scope, tool_name, tool_version,
              command_json, start_time, end_time, exit_code, stdout_path, stderr_path,
              output_folder, dry_run
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                case_id,
                image_id,
                computer_id,
                "live",
                tool_name,
                None,
                "[]",
                now,
                now,
                0,
                "",
                "",
                "",
                0,
            ),
        )

    def duplicate_tool_output(
        self, *, case_id: str, image_id: str, tool_name: str, content_sha256: str
    ) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT * FROM tool_outputs
            WHERE case_id = ? AND image_id = ? AND tool_name = ? AND content_sha256 = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (case_id, image_id, tool_name, content_sha256),
        ).fetchone()

    def insert_parsed_rows(self, rows: list[dict[str, Any]]) -> None:
        if not rows or self.analytics_only:
            return
        created_at = utc_now()
        self.conn.executemany(
            """
            INSERT INTO parsed_rows (
              id, case_id, computer_id, image_id, tool_output_id, tool_name,
              source_path, row_number, row_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["id"],
                    row["case_id"],
                    row["computer_id"],
                    row["image_id"],
                    row["tool_output_id"],
                    row["tool_name"],
                    str(row["source_path"]),
                    row["row_number"],
                    json.dumps(row["row"], ensure_ascii=False),
                    created_at,
                )
                for row in rows
            ],
        )
        self._commit()

    def insert_normalized_artifact_rows(self, table: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        if table == "onedrive_items":
            rows = self._strip_columns(rows, ("media_json", "hydration_json", "metadata_json"))
            for row in rows:
                row["media_json"] = ""
                row["hydration_json"] = ""
                row["metadata_json"] = ""
        self._insert_rows(table, self._table_columns(table), rows)

    def insert_normalized_artifact_row_groups(self, table_rows: dict[str, list[dict[str, Any]]]) -> None:
        for table, rows in table_rows.items():
            self.insert_normalized_artifact_rows(table, rows)

    def _table_columns(self, table: str) -> list[str]:
        if table in self._sqlite_table_columns:
            return list(self._sqlite_table_columns[table])
        if table in ANALYTICS_TABLE_COLUMNS:
            return list(ANALYTICS_TABLE_COLUMNS[table])
        rows = self.conn.execute(f"PRAGMA table_info({self._quote_identifier(table)})").fetchall()
        if not rows:
            raise ValueError(f"Unknown normalized artifact table: {table}")
        columns = [row["name"] for row in rows]
        self._sqlite_table_columns[table] = columns
        return columns

    def insert_shortcut_items(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "shortcut_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "artifact_type",
                "artifact_name", "artifact_path", "file_name", "file_location",
                "target_created", "target_modified", "target_accessed",
                "device_type", "volume_serial_number", "volume_name",
                "local_path", "common_path", "target_path", "relative_path",
                "command_line_arguments", "working_directory", "network_path",
                "icon_location", "hot_key", "window_style", "header_flags", "link_flags",
                "target_id_absolute_path", "target_mft_entry_number", "target_mft_sequence_number",
                "machine_name", "machine_mac_address", "tracker_created_on", "tracker_id",
                "droid_volume_id", "droid_file_id", "birth_droid_volume_id", "birth_droid_file_id",
                "app_id", "app_id_description", "entry_id",
                "destlist_version", "lnk_created", "lnk_modified",
                "lnk_accessed", "jumplist_item_number", "source_scope",
                "snapshot_id", "snapshot_ids", "snapshot_count", "snapshot_index",
                "snapshot_created_utc", "created_at",
            ],
            rows,
        )

    def insert_prefetch_items(self, rows: list[dict[str, Any]]) -> None:
        prepared_rows = [
            {
                **row,
                "source_scope": row.get("source_scope") or _source_scope_from_values(
                    row.get("source_csv"),
                    row.get("artifact_path"),
                    row.get("original_path"),
                    row.get("tool_output_id"),
                    row.get("snapshot_id"),
                ),
            }
            for row in rows
        ]
        self._insert_rows(
            "prefetch_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "prefetch_name",
                "artifact_path", "original_path", "executable_name",
                "prefetch_hash", "prefetch_version", "prefetch_version_label",
                "compression", "run_count", "last_run_time_utc",
                "last_run_times_utc", "referenced_string_count", "referenced_strings", "parser_note",
                "resolved_reference_path", "resolved_reference_device_path",
                "resolved_reference_command_line", "resolved_reference_os",
                "resolved_reference_description", "resolved_reference_source",
                "resolved_reference_match_count", "pf_created", "pf_modified",
                "pf_accessed", "pf_mft_record_modified", "source_scope",
                "snapshot_id", "snapshot_ids", "snapshot_count", "snapshot_index",
                "snapshot_created_utc", "created_at",
            ],
            prepared_rows,
        )

    def insert_file_correlations(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        created_at = utc_now()
        self.conn.executemany(
            """
            INSERT INTO file_correlations (
              id, case_id, computer_id, image_id, source_tool, source_table,
              source_row_id, mft_entry_id, match_type, confidence, source_path,
              mft_path, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["id"],
                    row["case_id"],
                    row["computer_id"],
                    row["image_id"],
                    row["source_tool"],
                    row["source_table"],
                    row["source_row_id"],
                    row["mft_entry_id"],
                    row["match_type"],
                    row["confidence"],
                    row.get("source_path"),
                    row.get("mft_path"),
                    created_at,
                )
                for row in rows
            ],
        )
        self._commit()

    def insert_recycle_items(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "recycle_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "source_csv", "row_number", "recycle_format", "source_path",
                "top_level_name", "recycled_path", "display_name", "original_path",
                "deletion_time_utc", "file_size", "is_directory", "mft_created",
                "mft_modified", "mft_accessed", "mft_record_modified", "created_at",
            ],
            rows,
        )

    def insert_recycle_children(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "recycle_children",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "source_csv", "row_number", "recycle_format", "source_path",
                "top_level_name", "recycled_path", "child_relative_path",
                "display_name", "file_size", "mft_created", "mft_modified",
                "mft_accessed", "mft_record_modified", "created_at",
            ],
            rows,
        )

    def insert_firefox_history(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "firefox_history",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "source_csv", "row_number", "source_path", "profile_path", "url",
                "title", "visit_time_utc", "visit_type", "visit_count", "typed",
                "hidden", "frecency", "visit_source", "visit_source_label",
                "local_vs_synced", "created_at",
            ],
            rows,
        )

    def insert_firefox_cookies(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "firefox_cookies",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "source_csv", "row_number", "source_path", "profile_path", "host",
                "name", "value", "path", "created_utc", "last_accessed_utc",
                "expires_utc", "is_secure", "is_http_only", "created_at",
            ],
            rows,
        )

    def insert_browser_history(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "browser_history",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "browser", "source_path",
                "profile_path", "url", "title", "visit_time_utc", "visit_count",
                "typed_count", "visit_source", "visit_source_label",
                "local_vs_synced", "created_at",
            ],
            rows,
        )

    def insert_browser_downloads(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "browser_downloads",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "browser", "source_path",
                "profile_path", "target_path", "tab_url", "site_url", "referrer",
                "start_time_utc", "end_time_utc", "received_bytes", "total_bytes",
                "state", "danger_type", "interrupt_reason", "created_at",
            ],
            rows,
        )

    def insert_browser_cookies(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "browser_cookies",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "browser", "source_path",
                "profile_path", "host", "name", "path", "created_utc",
                "last_accessed_utc", "expires_utc", "is_secure", "is_http_only",
                "created_at",
            ],
            rows,
        )

    def insert_browser_cache_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "browser_cache_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "browser", "source_path",
                "profile_path", "cache_type", "url", "host", "cache_file",
                "cache_file_size", "cache_file_modified_utc", "created_at",
            ],
            rows,
        )

    def insert_browser_artifacts(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "browser_artifacts",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "browser",
                "artifact_type", "source_path", "profile_path", "name", "value",
                "url", "title", "host", "local_path", "timestamp_utc",
                "details_json", "created_at",
            ],
            rows,
        )

    def insert_browser_session_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "browser_session_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "browser",
                "source_path", "profile_path", "session_type", "window_id",
                "tab_id", "tab_index", "navigation_index", "url", "title",
                "referrer_url", "host", "timestamp_utc", "last_active_time_utc",
                "is_current", "is_pinned", "parser", "details_json", "created_at",
            ],
            rows,
        )

    def insert_browser_site_settings(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "browser_site_settings",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "browser",
                "source_path", "profile_path", "setting_type", "origin", "host",
                "setting_name", "setting_value", "last_modified_utc",
                "expiration_utc", "details_json", "created_at",
            ],
            rows,
        )

    def insert_browser_notifications(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "browser_notifications",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "browser",
                "source_path", "profile_path", "origin", "host", "notification_id",
                "title", "body", "tag", "icon", "badge", "created_utc",
                "notification_timestamp_utc", "first_click_utc", "last_click_utc",
                "closed_utc", "num_clicks", "closed_reason", "details_json",
                "created_at",
            ],
            rows,
        )

    def insert_office_backstage_items(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "office_backstage_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "artifact_type",
                "source_path", "user_profile", "application", "name", "value",
                "path", "url", "host", "timestamp_utc", "details_json",
                "created_at",
            ],
            rows,
        )

    def insert_package_cache_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "package_cache_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "user_profile",
                "application_package", "source_database", "source_table",
                "table_row_number", "cache_name", "site_origin", "request_url",
                "host", "response_status", "response_type", "response_headers",
                "response_date_utc", "content_type", "content_length",
                "source_body_path", "stored_body_path", "body_file_name",
                "body_size", "body_sha256", "body_encrypted",
                "encryption_version", "decoded_state", "created_at",
            ],
            rows,
        )

    def insert_package_artifacts(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "package_artifacts",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "record_type",
                "user_profile", "application_package", "source_path",
                "source_name", "file_name", "file_extension", "file_size",
                "modified_utc", "event_time_utc", "url", "host", "title",
                "artifact_value", "artifact_text", "details_json", "error",
                "created_at",
            ],
            rows,
        )

    def insert_spotify_artifacts(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "spotify_artifacts",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "artifact_type",
                "user_profile", "source_path", "source_name", "source_file",
                "file_size", "modified_utc", "account_user_id",
                "spotify_user_id", "spotify_user_uri", "display_name",
                "key_name", "value", "evidence", "error", "created_at",
            ],
            rows,
        )

    def insert_user_dictionary_words(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "user_dictionary_words",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "user_profile", "application", "office_version", "proofing_id",
                "dictionary_name", "word", "word_index", "timestamp_utc",
                "details_json", "created_at",
            ],
            rows,
        )

    def insert_zone_identifier_ads(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "zone_identifier_ads",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "file_path", "user_profile", "stream_name", "zone_id",
                "classification", "referrer_url", "referrer_host", "host_url",
                "host", "timestamp_utc", "details_json", "created_at",
            ],
            rows,
        )

    def insert_thumbcache_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "thumbcache_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "source_name", "user_profile", "cache_file_type", "cache_id",
                "entry_index", "entry_offset", "entry_size", "thumbnail_offset",
                "thumbnail_size", "thumbnail_type", "thumbnail_sha256",
                "source_mtime_utc", "parser_status", "parser_note",
                "details_json", "created_at",
            ],
            rows,
        )

    def insert_image_analysis_items(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "image_analysis_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_artifact_type",
                "source_artifact_id", "source_path", "output_path", "file_name",
                "file_extension", "sha256", "file_size", "width", "height",
                "image_format", "analysis_type", "ocr_status", "ocr_engine",
                "ocr_text", "classifier_status", "classifier_label",
                "details_json", "created_at",
            ],
            rows,
        )

    def insert_rdp_cache_items(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "rdp_cache_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "record_type",
                "user_profile", "source_cache_path", "fragment_path",
                "contact_sheet_path", "file_name", "sha256", "file_size",
                "width", "height", "image_format", "fragment_index",
                "parser_status", "parser_note", "details_json", "created_at",
            ],
            rows,
        )

    def insert_rdp_visual_observations(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "rdp_visual_observations",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "user_profile",
                "source_cache_path", "contact_sheet_path", "observation_time_utc",
                "time_basis", "observation_type", "observed_application",
                "observed_text", "observed_path", "certainty", "caveat",
                "details_json", "created_at",
            ],
            rows,
        )

    def insert_thumbcache_search_correlations(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "thumbcache_search_correlations",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "thumbcache_entry_id", "windows_search_file_id",
                "correlation_basis", "confidence", "cache_id", "thumbcache_user",
                "thumbcache_path", "thumbcache_name", "thumbnail_sha256",
                "thumbnail_type", "search_item_path", "search_file_name",
                "search_date_created", "search_date_modified",
                "search_date_accessed", "search_date_imported",
                "details_json", "created_at",
            ],
            rows,
        )

    def insert_cloud_sync_artifacts(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "cloud_sync_artifacts",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "provider",
                "artifact_type", "user_profile", "source_path", "source_name",
                "database_name", "table_name", "event_time_utc", "local_path",
                "cloud_path", "file_name", "file_id", "parent_id", "stable_id",
                "server_path", "url", "mime_type", "file_size", "is_folder",
                "is_deleted", "sync_status", "event_type", "direction", "owner",
                "shared", "protobuf_fields_json", "details_json", "error",
                "created_at",
            ],
            rows,
        )

    def insert_google_drive_cache_map(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "google_drive_cache_map",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "account_id",
                "stable_id", "file_id", "virtual_path", "file_name",
                "cache_id", "cache_path", "windows_cache_path", "cache_file_size", "mapping_method",
                "evidence_basis", "details_json", "created_at",
            ],
            rows,
        )

    def insert_telemetry_artifacts(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "telemetry_artifacts",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "record_type",
                "artifact_group", "user_profile", "application", "source_path",
                "source_name", "file_name", "file_extension", "file_size",
                "modified_utc", "event_time_utc", "identifier", "path", "url",
                "host", "title", "value_name", "value_data", "artifact_text",
                "sha256_first_mb", "details_json", "error", "created_at",
            ],
            rows,
        )

    def replace_artifact_correlations(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
        rows: list[dict[str, Any]],
    ) -> None:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        with self.bulk_transaction():
            self.conn.execute(f"DELETE FROM artifact_correlations WHERE {' AND '.join(where)}", params)
            if rows:
                created_at = utc_now()
                self.conn.executemany(
                    """
                    INSERT INTO artifact_correlations (
                      id, case_id, computer_id, image_id,
                      left_source_tool, left_source_table, left_source_row_id,
                      right_source_tool, right_source_table, right_source_row_id,
                      correlation_type, correlation_key, confidence, summary, details_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            row["id"], row["case_id"], row["computer_id"], row["image_id"],
                            row.get("left_source_tool"), row["left_source_table"], row["left_source_row_id"],
                            row.get("right_source_tool"), row["right_source_table"], row["right_source_row_id"],
                            row["correlation_type"], row.get("correlation_key"), row["confidence"],
                            row.get("summary"), json.dumps(row.get("details", {}), default=str), created_at,
                        )
                        for row in rows
                    ],
                )

    def replace_computer_inventory(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
        rows: list[dict[str, Any]],
    ) -> None:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        with self.bulk_transaction():
            self.conn.execute(f"DELETE FROM computer_inventory WHERE {' AND '.join(where)}", params)
            if rows:
                created_at = utc_now()
                self.conn.executemany(
                    """
                    INSERT INTO computer_inventory (
                      id, case_id, computer_id, image_id, category, name, value,
                      source_table, source_row_id, confidence, details_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            row["id"], row["case_id"], row["computer_id"], row["image_id"],
                            row["category"], row["name"], row.get("value"), row.get("source_table"),
                            row.get("source_row_id"), row.get("confidence", "derived"),
                            json.dumps(row.get("details", {}), default=str), created_at,
                        )
                        for row in rows
                    ],
                )

    def insert_onedrive_items(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("media_json", "hydration_json", "metadata_json"))
        for row in rows:
            row["media_json"] = ""
            row["hydration_json"] = ""
            row["metadata_json"] = ""
        self._insert_rows(
            "onedrive_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "artifact_type",
                "user_profile", "account", "source_path", "source_ode_csv",
                "source_ode_row_number", "record_type", "name", "path",
                "parent_resource_id", "resource_id", "etag", "status",
                "spo_permissions", "volume_id", "item_index", "last_change_utc",
                "disk_last_access_utc", "disk_creation_utc", "size",
                "local_hash_digest", "local_hash_algorithm", "shared_item",
                "media_json", "hydration_json", "metadata_json", "is_deleted",
                "delete_time_utc", "deleting_process", "error", "created_at",
            ],
            rows,
        )

    def insert_onedrive_log_entries(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("context_data", "params_json", "raw_strings_json"))
        self._insert_rows(
            "onedrive_log_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "user_profile",
                "account", "source_path", "source_name", "log_type",
                "record_index", "odl_version", "one_drive_version",
                "windows_version", "timestamp_utc", "code_file", "function",
                "flags", "context_data", "event_type", "local_path", "url",
                "resource_id", "params_text", "params_json", "raw_strings_json",
                "parser_status", "error", "created_at",
            ],
            rows,
        )

    def insert_windows_activities(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("payload_json", "raw_json"))
        self._insert_rows(
            "windows_activities",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "user_profile", "source_table", "activity_id", "app_id",
                "app_display_name", "activity_type", "display_text", "file_name",
                "content_uri", "activation_uri", "fallback_uri", "start_time_utc",
                "end_time_utc", "last_modified_utc", "expiration_time_utc",
                "platform_device_id", "payload_json", "raw_json", "created_at",
            ],
            rows,
        )

    def insert_clipboard_items(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("raw_payload_json",))
        self._insert_rows(
            "clipboard_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "user_profile", "source_type", "source_table", "row_identifier",
                "item_time_utc", "created_time_utc", "modified_time_utc",
                "last_used_time_utc", "sequence_number", "format_name",
                "content_type", "text_content", "file_uri", "html_content",
                "image_present", "payload_size", "cloud_sync_state",
                "cloud_sync_id", "device_id", "raw_payload_json",
                "parser_status", "parser_error", "created_at",
            ],
            rows,
        )

    def insert_webcache_entries(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("raw_metadata_json",))
        self._insert_rows(
            "webcache_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_database",
                "source_table", "table_row_number", "user_name", "application",
                "application_package", "container_directory", "attribution_method",
                "container_id", "container_name", "entry_id", "entry_type",
                "url", "host", "cache_file", "file_name",
                "content_type", "http_status", "created_utc", "accessed_utc",
                "modified_utc", "expires_utc", "synced_utc", "request_headers",
                "response_headers", "raw_metadata_json", "created_at",
            ],
            rows,
        )

    def insert_webcache_file_accesses(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("raw_metadata_json",))
        self._insert_rows(
            "webcache_file_accesses",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_webcache_entry_id",
                "source_database", "source_table", "user_name", "application",
                "application_package", "container_directory", "attribution_method",
                "container_name", "entry_id", "url", "local_path",
                "normalized_path", "cache_file", "file_name",
                "created_utc", "accessed_utc", "modified_utc", "expires_utc",
                "synced_utc", "raw_metadata_json", "created_at",
            ],
            rows,
        )

    def insert_sam_accounts(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "sam_accounts",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path", "username",
                "rid", "rid_hex", "account_category", "last_login_utc",
                "password_last_set_utc", "last_bad_password_utc", "account_expires_utc",
                "logon_count", "bad_password_count", "account_flags_hex",
                "account_flags", "account_flags_unknown_hex", "registry_path",
                "account_key_last_write_utc", "created_at",
            ],
            rows,
        )

    def insert_registry_hives(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        created_at = utc_now()
        self.conn.executemany(
            """
            INSERT INTO registry_hives (
              id, case_id, computer_id, image_id, tool_output_id, tool_name,
              source_csv, row_number, source_path, original_path, hive_name,
              hive_type, size, sha256, header_valid, key_count, value_count,
              parser_error, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["id"],
                    row["case_id"],
                    row["computer_id"],
                    row["image_id"],
                    row["tool_output_id"],
                    row["tool_name"],
                    str(row["source_csv"]),
                    row["row_number"],
                    row.get("source_path"),
                    row.get("original_path"),
                    row.get("hive_name"),
                    row.get("hive_type"),
                    row.get("size"),
                    row.get("sha256"),
                    row.get("header_valid"),
                    row.get("key_count"),
                    row.get("value_count"),
                    row.get("parser_error"),
                    created_at,
                )
                for row in rows
            ],
        )
        self._commit()

    def insert_registry_artifacts(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "registry_artifacts",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "hive_type", "user_profile", "user_sid", "artifact", "category",
                "key_path", "key_last_write_utc", "event_time_utc",
                "recentdocs_time_utc", "recentdocs_extension_time_utc",
                "mru_position", "recentdocs_mru_position",
                "recentdocs_extension_mru_position", "is_most_recent",
                "value_name", "value_type", "value_data", "display_name",
                "normalized_path", "run_counter", "focus_count", "focus_time",
                "last_executed", "value_data_hex", "transaction_logs_detected",
                "transaction_logs_applied", "transaction_log_paths", "source_scope",
                "snapshot_id", "snapshot_ids", "snapshot_count", "snapshot_index",
                "snapshot_created_utc", "notes",
                "created_at",
            ],
            rows,
        )

    def insert_office_trust_records(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "registry_office_trust_records",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "hive_type", "user_profile", "trust_type", "office_version",
                "application", "location_id", "key_path", "key_last_write_utc",
                "event_time_utc", "value_name", "value_type", "value_data",
                "path_or_file", "allow_subfolders", "allow_network_location",
                "permission_flags", "permitted_editing", "permitted_macros_or_scripts",
                "details_json", "created_at",
            ],
            rows,
        )

    def insert_taskbar_feature_usage(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "registry_taskbar_feature_usage",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "hive_type", "user_profile", "artifact", "feature", "key_path",
                "key_last_write_utc", "event_time_utc", "value_name", "value_type",
                "value_data", "usage_count", "details_json", "created_at",
            ],
            rows,
        )

    def insert_taskbar_pins(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "registry_taskbar_pins",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "hive_type", "user_profile", "pin_order", "pin_name",
                "target_hint", "key_path", "key_last_write_utc", "details_json",
                "created_at",
            ],
            rows,
        )

    def enrich_registry_artifact_users(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
    ) -> None:
        if self.analytics is not None:
            self._enrich_duckdb_registry_artifact_users(case_id=case_id, image_id=image_id)
            if self.analytics_only:
                return
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        account_rows = self.conn.execute(
            f"SELECT id, user_sid FROM registry_artifacts WHERE {' AND '.join(where)} AND artifact IN ('bam', 'dam') AND COALESCE(user_sid, '') != ''",
            params,
        ).fetchall()
        if not account_rows:
            return
        sam_rows = self.conn.execute(
            "SELECT username, rid FROM sam_accounts WHERE case_id = ? AND (? IS NULL OR image_id = ?)",
            (case_id, image_id, image_id),
        ).fetchall()
        by_rid = {str(row["rid"]): row["username"] for row in sam_rows if row["rid"] and row["username"]}
        updates = []
        for row in account_rows:
            rid = str(row["user_sid"]).rsplit("-", 1)[-1]
            username = by_rid.get(rid)
            if username:
                updates.append((username, row["id"]))
        if updates:
            self.conn.executemany("UPDATE registry_artifacts SET user_profile = ? WHERE id = ?", updates)
            self._commit()

    def _enrich_duckdb_registry_artifact_users(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
    ) -> None:
        assert self.analytics is not None
        conn = self.analytics._connect(case_id)
        if not self.analytics._table_exists(conn, "registry_artifacts") or not self.analytics._table_exists(conn, "sam_accounts"):
            return
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        account_rows = conn.execute(
            f"""
            SELECT id, user_sid
            FROM registry_artifacts
            WHERE {' AND '.join(where)}
              AND artifact IN ('bam', 'dam')
              AND COALESCE(user_sid, '') != ''
            """,
            params,
        ).fetchall()
        if not account_rows:
            return
        sam_params: list[Any] = [case_id]
        sam_where = ["case_id = ?"]
        if image_id is not None:
            sam_where.append("image_id = ?")
            sam_params.append(image_id)
        sam_rows = conn.execute(
            f"SELECT username, rid FROM sam_accounts WHERE {' AND '.join(sam_where)}",
            sam_params,
        ).fetchall()
        by_rid = {str(row[1]): row[0] for row in sam_rows if row[1] and row[0]}
        updates = []
        for row in account_rows:
            rid = str(row[1]).rsplit("-", 1)[-1]
            username = by_rid.get(rid)
            if username:
                updates.append((username, row[0]))
        for username, row_id in updates:
            conn.execute("UPDATE registry_artifacts SET user_profile = ? WHERE id = ?", [username, row_id])

    def insert_recmd_artifact_rows(self, table_rows: dict[str, list[dict[str, Any]]]) -> None:
        ownership_columns = [
            "hive_path", "hive_type", "user_profile", "category", "key_path",
            "key_last_write_timestamp", "recmd_description",
        ]
        allowed = {
            "registry_recentdocs": [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", *ownership_columns, "extension", "batch_key_path", "value_name",
                "batch_value_name", "target_name", "lnk_name", "mru_position", "opened_on",
                "extension_last_opened", "created_at",
            ],
            "registry_runmru": [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", *ownership_columns, "value_name", "batch_key_path", "mru_position",
                "batch_value_name", "executable", "opened_on", "created_at",
            ],
            "registry_typedpaths": [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", *ownership_columns, "value_name", "batch_key_path", "mru_position",
                "batch_value_name", "path", "opened_on", "created_at",
            ],
            "registry_wordwheel_query": [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", *ownership_columns, "search_term", "batch_key_path", "mru_position",
                "batch_value_name", "key_name", "last_write_timestamp", "created_at",
            ],
            "registry_userassist": [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", *ownership_columns, "batch_key_path", "batch_value_name",
                "program_name", "run_counter", "focus_count", "focus_time", "last_executed",
                "created_at",
            ],
            "registry_office_mru": [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", *ownership_columns, "value_name", "batch_key_path", "last_opened",
                "batch_value_name", "last_closed", "file_name", "created_at",
            ],
            "registry_common_dialog_mru": [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", *ownership_columns, "artifact", "extension", "value_name",
                "batch_key_path", "mru_position", "batch_value_name", "executable",
                "absolute_path", "opened_on", "details", "executable_is_guid", "resolved_executable",
                "executable_resolution_source", "executable_resolution_confidence", "created_at",
            ],
            "registry_trusted_documents": [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", *ownership_columns, "event_type", "batch_key_path", "timestamp",
                "batch_value_name", "file_name", "username", "created_at",
            ],
        }
        created_at = utc_now()
        for table, rows in table_rows.items():
            if not rows:
                continue
            columns = allowed[table]
            normalized_rows = [
                {
                    column: created_at if column == "created_at" else row.get(column)
                    for column in columns
                }
                for row in rows
            ]
            self._insert_rows(table, columns, normalized_rows)
        self._commit()

    def insert_amcache_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "amcache_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", "entry_type", "source_file", "path", "name",
                "publisher", "product_name", "product_version", "file_version", "sha1",
                "sha256", "binary_type", "size", "created_utc", "modified_utc",
                "link_date", "compile_time", "program_id", "install_date",
                "unassociated", "source_scope", "snapshot_id", "snapshot_ids",
                "snapshot_count", "snapshot_index", "snapshot_created_utc", "created_at",
            ],
            rows,
        )

    def insert_shimcache_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "shimcache_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", "source_file", "control_set", "entry_number",
                "path", "last_modified_utc", "executed", "source_key", "source_scope",
                "snapshot_id", "snapshot_ids", "snapshot_count", "snapshot_index",
                "snapshot_created_utc", "created_at",
            ],
            rows,
        )

    def insert_shellbag_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "shellbag_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", "source_file", "hive_path", "user_profile",
                "absolute_path", "shell_type", "value_name", "mru_position", "slot",
                "node_slot", "created_on", "modified_on", "accessed_on", "last_write_time",
                "first_interacted", "last_interacted", "has_explored",
                "drive_letter", "volume_guid", "volume_serial_number",
                "volume_name", "created_at",
            ],
            rows,
        )

    def insert_usb_devices(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "usb_devices",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id", "tool_name",
                "source_csv", "row_number", "source_path", "artifact", "device_type",
                "vendor_id", "product_id", "vendor", "product", "revision", "friendly_name", "serial",
                "instance_id", "parent_id_prefix", "device_service", "user_profile",
                "drive_letter", "volume_guid", "volume_serial_number", "volume_name",
                "capacity_bytes", "file_system", "alternate_scsi_serial", "key_path", "key_last_write_utc",
                "last_present_date_utc", "partition_disk_number", "partition_bus_type",
                "partition_bus_type_code", "partition_user_removal_policy",
                "partition_bytes_per_sector", "partition_bytes_per_logical_sector",
                "partition_bytes_per_physical_sector", "partition_style", "partition_style_code",
                "partition_count", "partition_table_bytes", "partition_table_sha256",
                "partition_table_summary", "partition_table_disk_guid", "storage_id_code_set",
                "storage_id_type", "storage_id_association", "storage_id_bytes", "storage_id_hex",
                "storage_id_ascii", "storage_id_sha256", "partition_registry_id",
                "partition_adapter_id", "partition_pool_id", "partition_location",
                "partition_flags", "partition_characteristics", "vbr_index", "vbr_bytes", "vbr_oem_name",
                "vbr_file_system", "vbr_volume_serial_number", "vbr_volume_serial_number_full",
                "vbr_volume_name", "vbr_parse_status", "vbr_serial_match", "mbr_partition_type",
                "partition_start_lba", "partition_sector_count", "property_name", "property_value", "value_data_hex",
                "created_at",
            ],
            rows,
        )

    def insert_setupapi_device_events(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "setupapi_device_events",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path", "line_number",
                "section_title", "operation", "device_instance_id", "device_class",
                "vendor_id", "product_id", "serial", "service", "inf_path",
                "driver_package", "start_time_utc", "end_time_utc", "event_time_utc",
                "status", "confidence", "details_json", "error", "created_at",
            ],
            rows,
        )

    def delete_usb_storage_devices(self, *, case_id: str, image_id: str | None = None) -> None:
        params: list[Any] = [case_id]
        where = "case_id = ?"
        if image_id is not None:
            where += " AND image_id = ?"
            params.append(image_id)
        self._delete_sqlite_if_exists("usb_storage_devices", where, params)
        if self.analytics is not None:
            self.analytics.delete_case_image("usb_storage_devices", case_id=case_id, image_id=image_id)
        self._commit()

    def insert_usb_storage_devices(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "usb_storage_devices",
            [
                "id", "case_id", "computer_id", "image_id", "serial",
                "vendor_id", "product_id", "vendor", "product", "revision",
                "friendly_name", "parent_id_prefix", "device_service", "drive_letter",
                "volume_guid", "volume_serial_number", "volume_name", "capacity_bytes",
                "file_system", "alternate_scsi_serial", "partition_disk_number", "partition_bus_type",
                "partition_bus_type_code", "partition_user_removal_policy",
                "partition_bytes_per_sector", "partition_bytes_per_logical_sector",
                "partition_bytes_per_physical_sector", "partition_style", "partition_style_code",
                "partition_count", "partition_table_bytes", "partition_table_sha256",
                "partition_table_summary", "partition_table_disk_guid", "storage_id_code_set",
                "storage_id_type", "storage_id_association", "storage_id_bytes", "storage_id_hex",
                "storage_id_ascii", "storage_id_sha256", "partition_registry_id",
                "partition_adapter_id", "partition_pool_id", "partition_location",
                "partition_flags", "partition_characteristics", "vbr_oem_name", "vbr_file_system",
                "vbr_volume_serial_number", "vbr_volume_serial_number_full", "vbr_volume_name",
                "vbr_parse_status", "vbr_serial_match", "mbr_partition_type",
                "partition_start_lba", "partition_sector_count", "user_profiles", "first_install_date_utc",
                "last_arrival_utc", "last_removal_utc",
                "first_volume_serial_event_utc", "last_partition_event_utc",
                "last_migration_present_utc", "evidence_row_count", "source_artifacts", "created_at",
            ],
            rows,
        )

    def delete_usb_connection_events(self, *, case_id: str, image_id: str | None = None) -> None:
        params: list[Any] = [case_id]
        where = "case_id = ?"
        if image_id is not None:
            where += " AND image_id = ?"
            params.append(image_id)
        self._delete_sqlite_if_exists("usb_connection_events", where, params)
        if "usb_connection_events" in ANALYTICS_TABLES and self.analytics is not None:
            self.analytics.delete_case_image("usb_connection_events", case_id=case_id, image_id=image_id)
        self._commit()

    def insert_usb_connection_events(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "usb_connection_events",
            [
                "id", "case_id", "computer_id", "image_id", "usb_device_id",
                "serial", "volume_serial_number", "volume_guid", "drive_letter",
                "event_time_utc", "event_type", "event_source", "event_id",
                "record_number", "source_path", "key_path", "property_name",
                "property_value", "capacity_bytes", "created_at",
            ],
            rows,
        )

    def delete_usb_file_correlations(self, *, case_id: str, image_id: str | None = None) -> None:
        params: list[Any] = [case_id]
        where = "case_id = ?"
        if image_id is not None:
            where += " AND image_id = ?"
            params.append(image_id)
        self._delete_sqlite_if_exists("usb_file_correlations", where, params)
        if "usb_file_correlations" in ANALYTICS_TABLES and self.analytics is not None:
            self.analytics.delete_case_image("usb_file_correlations", case_id=case_id, image_id=image_id)
        self._commit()

    def insert_usb_file_correlations(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "usb_file_correlations",
            [
                "id", "case_id", "computer_id", "image_id", "usb_serial",
                "usb_volume_serial_number", "usb_volume_name", "usb_drive_letter",
                "usb_vendor_id", "usb_product_id", "usb_vendor", "usb_product",
                "usb_friendly_name", "usb_file_system", "usb_vbr_file_system",
                "usb_first_install_date_utc", "usb_last_arrival_utc",
                "usb_last_removal_utc", "source_artifact_type", "source_artifact_id",
                "source_artifact_name", "source_artifact_path", "user_profile",
                "jumplist_item_number", "file_name", "file_location", "target_created", "target_modified",
                "target_accessed", "target_accessed_original", "target_accessed_precision",
                "target_accessed_note", "device_type", "artifact_volume_serial_number",
                "artifact_volume_name", "artifact_volume_guid", "artifact_drive_letter",
                "temporal_status", "temporal_basis", "first_known_connection_utc",
                "last_known_connection_utc", "nearest_connection_before_utc",
                "nearest_removal_after_utc",
                "volume_serial_match", "confidence", "created_at",
            ],
            rows,
        )

    def dedupe_usb_devices(self, *, case_id: str, image_id: str | None = None) -> int:
        if self.analytics_only and self.analytics is not None:
            return self._dedupe_duckdb_usb_devices(case_id=case_id, image_id=image_id)
        params: list[Any] = [case_id]
        where = "case_id = ?"
        if image_id is not None:
            where += " AND image_id = ?"
            params.append(image_id)
        before = self.conn.execute(f"SELECT COUNT(*) AS count FROM usb_devices WHERE {where}", params).fetchone()["count"]
        self.conn.execute(
            f"""
            DELETE FROM usb_devices
            WHERE rowid NOT IN (
              SELECT MIN(rowid)
              FROM usb_devices
              WHERE {where}
              GROUP BY artifact, device_type, COALESCE(serial, ''), COALESCE(instance_id, ''),
                       COALESCE(key_path, ''), COALESCE(property_name, ''),
                       COALESCE(property_value, ''), COALESCE(key_last_write_utc, '')
            )
            AND {where}
            """,
            params + params,
        )
        after = self.conn.execute(f"SELECT COUNT(*) AS count FROM usb_devices WHERE {where}", params).fetchone()["count"]
        self._commit()
        return int(before) - int(after)

    def _dedupe_duckdb_usb_devices(self, *, case_id: str, image_id: str | None = None) -> int:
        assert self.analytics is not None
        conn = self.analytics._connect(case_id)
        if not self.analytics._table_exists(conn, "usb_devices"):
            return 0
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        rows = conn.execute(
            f"""
            SELECT id, artifact, device_type, serial, instance_id, key_path,
                   property_name, property_value, key_last_write_utc
            FROM usb_devices
            WHERE {' AND '.join(where)}
            ORDER BY row_number, id
            """,
            params,
        ).fetchall()
        seen: set[tuple[Any, ...]] = set()
        duplicate_ids: list[str] = []
        for row in rows:
            key = tuple("" if value is None else str(value) for value in row[1:])
            if key in seen:
                duplicate_ids.append(str(row[0]))
            else:
                seen.add(key)
        if not duplicate_ids:
            return 0
        placeholders = ", ".join("?" for _ in duplicate_ids)
        conn.execute(f"DELETE FROM usb_devices WHERE id IN ({placeholders})", duplicate_ids)
        return len(duplicate_ids)

    def _insert_rows(self, table: str, columns: list[str], rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        created_at = utc_now()
        self._ensure_tool_output_parents(columns, rows)
        analytics_rows = [
            {
                column: created_at if column == "created_at"
                else str(row[column]) if column == "source_csv" and row.get(column) is not None
                else row.get(column)
                for column in columns
            }
            for row in rows
        ]
        if self._analytics_insert(table, columns, analytics_rows):
            return
        placeholders = ", ".join("?" for _ in columns)
        table_sql = self._quote_identifier(table)
        column_sql = ", ".join(self._quote_identifier(column) for column in columns)
        try:
            self.conn.executemany(
                f"INSERT INTO {table_sql} ({column_sql}) VALUES ({placeholders})",
                [tuple(row.get(column) for column in columns) for row in analytics_rows],
            )
            self._commit()
        except Exception as exc:
            self._log_database_write_failure(table, analytics_rows, exc)
            raise

    def _ensure_tool_output_parents(self, columns: list[str], rows: list[dict[str, Any]]) -> None:
        if "tool_output_id" not in columns:
            return
        candidate_ids = sorted({str(row.get("tool_output_id") or "") for row in rows if row.get("tool_output_id")})
        if not candidate_ids:
            return
        placeholders = ", ".join("?" for _ in candidate_ids)
        existing = {
            str(row["id"])
            for row in self.conn.execute(f"SELECT id FROM tool_outputs WHERE id IN ({placeholders})", candidate_ids).fetchall()
        }
        missing = set(candidate_ids) - existing
        if not missing:
            return
        emitted: set[str] = set()
        for row in rows:
            tool_output_id = str(row.get("tool_output_id") or "")
            if tool_output_id not in missing or tool_output_id in emitted:
                continue
            case_id = row.get("case_id")
            computer_id = row.get("computer_id")
            image_id = row.get("image_id")
            if not case_id or not computer_id or not image_id:
                continue
            self.ensure_tool_output_parent(
                tool_output_id=tool_output_id,
                case_id=str(case_id),
                computer_id=str(computer_id),
                image_id=str(image_id),
                tool_name=str(row.get("tool_name") or "SyntheticImport"),
                path=str(row.get("source_csv") or ""),
            )
            emitted.add(tool_output_id)

    def _log_database_write_failure(self, table: str, rows: list[dict[str, Any]], exc: Exception) -> None:
        row = rows[0] if rows else {}
        case_id = row.get("case_id")
        details = {
            "table": table,
            "row_count": len(rows),
            "case_id": case_id,
            "computer_id": row.get("computer_id"),
            "image_id": row.get("image_id"),
            "tool_output_id": row.get("tool_output_id"),
            "tool_name": row.get("tool_name"),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        LOGGER.exception("Database write failed for table %s", table, extra={"details": details})
        if not case_id or table == "activity_log" or self._defer_commit_depth:
            return
        try:
            self.conn.rollback()
            self.log_activity(
                case_id=str(case_id),
                computer_id=str(row.get("computer_id")) if row.get("computer_id") else None,
                image_id=str(row.get("image_id")) if row.get("image_id") else None,
                level="error",
                event="database.write_failed",
                message=f"Database write failed for {table}",
                details=details,
            )
        except Exception:
            LOGGER.exception("Failed to write database failure activity log for table %s", table)

    def insert_mft_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "mft_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "entry_number",
                "sequence_number", "in_use", "parent_entry_number",
                "parent_sequence_number", "parent_path", "file_name", "extension",
                "file_size", "is_directory", "has_ads", "is_ads", "si_flags",
                "reparse_target", "object_id", "birth_volume_id", "birth_object_id",
                "birth_domain_id", "si_fn_copied", "created_si", "created_fn",
                "modified_si", "modified_fn", "record_changed_si",
                "record_changed_fn", "accessed_si", "accessed_fn", "source_file",
                "created_at",
            ],
            rows,
        )

    def insert_filesystem_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "filesystem_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "partition_id",
                "filesystem_type", "source_root", "file_path", "parent_path",
                "file_name", "extension", "file_size", "is_directory",
                "created_utc", "modified_utc", "accessed_utc",
                "metadata_changed_utc", "mode", "uid", "gid", "scan_status",
                "error", "created_at",
            ],
            rows,
        )

    def insert_usn_journal_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "usn_journal_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_file",
                "update_sequence_number", "update_timestamp", "file_name",
                "extension", "file_reference_number", "file_reference_sequence_number",
                "parent_file_reference_number", "parent_file_reference_sequence_number",
                "full_path", "reason", "reason_flags", "file_attributes",
                "file_attributes_flags", "source_info", "security_id",
                "major_version", "minor_version", "record_length", "offset",
                "created_at",
            ],
            rows,
        )

    def enrich_usn_paths_from_mft(self, *, case_id: str, image_id: str | None = None) -> int:
        if self.analytics_only and self.analytics is not None:
            conn = self.analytics._connect(case_id)
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_name IN ('usn_journal_entries', 'mft_entries')"
                ).fetchall()
            }
            if {"usn_journal_entries", "mft_entries"} - tables:
                return 0
            params: list[object] = [case_id]
            where = "u.case_id = ?"
            if image_id is not None:
                where += " AND u.image_id = ?"
                params.append(image_id)
            rows = conn.execute(
                f"""
                SELECT u.id, u.file_name, u.full_path, m.parent_path, m.file_name AS parent_name
                FROM usn_journal_entries u
                JOIN mft_entries m
                  ON m.case_id = u.case_id
                 AND COALESCE(m.image_id, '') = COALESCE(u.image_id, '')
                 AND m.entry_number = u.parent_file_reference_number
                 AND COALESCE(m.sequence_number, '') = COALESCE(u.parent_file_reference_sequence_number, '')
                WHERE {where}
                  AND LOWER(COALESCE(u.full_path, '')) LIKE '%pathunknown%'
                """,
                params,
            ).fetchall()
            updates = _usn_path_updates(rows)
            if updates:
                conn.executemany("UPDATE usn_journal_entries SET full_path = ? WHERE id = ?", updates)
            return len(updates)

        params = [case_id]
        where = "u.case_id = ?"
        if image_id is not None:
            where += " AND u.image_id = ?"
            params.append(image_id)
        rows = self.conn.execute(
            f"""
            SELECT u.id, u.file_name, u.full_path, m.parent_path, m.file_name AS parent_name
            FROM usn_journal_entries u
            JOIN mft_entries m
              ON m.case_id = u.case_id
             AND COALESCE(m.image_id, '') = COALESCE(u.image_id, '')
             AND m.entry_number = u.parent_file_reference_number
             AND COALESCE(m.sequence_number, '') = COALESCE(u.parent_file_reference_sequence_number, '')
            WHERE {where}
              AND LOWER(COALESCE(u.full_path, '')) LIKE '%pathunknown%'
            """,
            params,
        ).fetchall()
        updates = _usn_path_updates(rows)
        if updates:
            self.conn.executemany("UPDATE usn_journal_entries SET full_path = ? WHERE id = ?", updates)
            self._commit()
        return len(updates)

    def insert_ntfs_index_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "ntfs_index_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "directory_entry_number",
                "directory_path", "source", "block_vcn", "block_active",
                "entry_offset", "index_entry_length", "index_entry_flags",
                "referenced_entry_number", "referenced_sequence_number",
                "parent_entry_number", "parent_sequence_number", "file_name",
                "name_type", "name_type_label", "created_fn", "modified_fn",
                "record_changed_fn", "accessed_fn", "allocated_size", "real_size",
                "file_flags", "from_slack", "source_file", "created_at",
            ],
            rows,
        )

    def insert_ntfs_index_bitmaps(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "ntfs_index_bitmaps",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "directory_entry_number",
                "directory_path", "index_root_attr", "index_allocation_attr",
                "bitmap_attr", "bitmap_hex", "active_block_count", "active_blocks",
                "error", "created_at",
            ],
            rows,
        )

    def insert_ntfs_logfile_entries(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("row_json",))
        self._insert_rows(
            "ntfs_logfile_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_file",
                "event_time", "operation", "redo_operation", "undo_operation",
                "target_attribute", "file_name", "file_path",
                "file_reference_number", "file_reference_sequence_number",
                "parent_file_reference_number", "parent_file_reference_sequence_number",
                "log_sequence_number", "previous_log_sequence_number",
                "transaction_id", "client_id", "record_offset", "row_json",
                "created_at",
            ],
            rows,
        )

    def replace_filesystem_review(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
        rows: list[dict[str, Any]],
    ) -> None:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        if self.analytics is not None:
            self.analytics.delete_case_image("filesystem_review", case_id=case_id, image_id=image_id)
        elif self._sqlite_table_exists("filesystem_review"):
            self.conn.execute(f"DELETE FROM filesystem_review WHERE {' AND '.join(where)}", params)
        self._insert_rows(
            "filesystem_review",
            [
                "id", "case_id", "computer_id", "image_id", "source_table",
                "source_id", "source_tool", "source_row_number", "event_type",
                "event_time", "file_name", "file_path", "parent_path",
                "mft_entry_number", "mft_sequence_number", "parent_entry_number",
                "parent_sequence_number", "in_use", "is_directory", "operation",
                "reason", "status", "details_json", "created_at",
            ],
            rows,
        )

    def replace_ntfs_namespace_reconciliation(
        self,
        *,
        case_id: str,
        image_id: str,
        rows: list[dict[str, Any]],
    ) -> None:
        self.conn.execute(
            "DELETE FROM ntfs_namespace_reconciliation WHERE case_id = ? AND image_id = ?",
            (case_id, image_id),
        )
        self._insert_rows(
            "ntfs_namespace_reconciliation",
            [
                "id", "case_id", "computer_id", "image_id", "mft_entry_number",
                "mft_sequence_number", "parent_entry_number", "parent_path",
                "file_name", "original_path", "mft_in_use", "mounted_present",
                "parent_mounted_exists", "parent_access_status", "index_status",
                "legit_active_file", "index_entry_id",
                "index_from_slack", "index_block_active", "index_bitmap_error",
                "icat_recovered", "recovered_size", "recovered_sha256",
                "header_type", "zero_prefix", "reason", "created_at",
            ],
            rows,
        )

    def insert_srum_records(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("row_json",))
        self._insert_rows(
            "srum_records",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "provider_guid",
                "provider_name", "source_table", "record_type", "srum_id",
                "timestamp", "app_id", "app_name", "app_path", "app_description",
                "exe_timestamp", "user_id", "user_sid", "user_name",
                "bytes_received", "bytes_sent", "interface_luid", "interface_type",
                "l2_profile_id", "l2_profile_name", "l2_profile_flags",
                "connected_time", "connect_start_time", "connect_end_time",
                "notification_type", "payload_size", "network_type",
                "foreground_bytes_read", "foreground_bytes_written",
                "background_bytes_read", "background_bytes_written",
                "foreground_cycle_time", "background_cycle_time", "face_time",
                "foreground_context_switches", "background_context_switches",
                "foreground_read_operations", "foreground_write_operations",
                "background_read_operations", "background_write_operations",
                "foreground_flushes", "background_flushes", "flags", "start_time",
                "end_time", "duration_ms", "span_ms", "timeline_end",
                "event_timestamp", "state_transition", "charge_level", "cycle_count",
                "designed_capacity", "full_charged_capacity", "active_ac_time",
                "active_dc_time", "active_discharge_time", "active_energy",
                "cs_ac_time", "cs_dc_time", "cs_discharge_time", "cs_energy",
                "configuration_hash", "metadata", "energy_data", "tag",
                "binary_data", "vpn_profile_name", "vpn_server", "vpn_device",
                "vpn_protocol", "vpn_phonebook_path", "vpn_match_method",
                "source_scope", "snapshot_id", "snapshot_ids", "snapshot_count",
                "snapshot_index", "snapshot_created_utc", "row_json",
                "created_at",
            ],
            rows,
        )

    def insert_ual_records(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "ual_records",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "database_file",
                "source_table", "record_id", "role_guid", "role_name",
                "product_name", "tenant_id", "user_sid", "user_name",
                "client_name", "client_ip", "client_id", "first_seen",
                "last_seen", "insert_date", "last_access", "access_count",
                "activity_count", "day_count", "raw_time_bucket", "created_at",
            ],
            rows,
        )

    def insert_bits_jobs(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "bits_jobs",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "database_file", "source_table", "record_id", "record_type",
                "job_id", "job_name", "job_owner", "job_state", "job_type",
                "priority", "created_utc", "modified_utc", "completed_utc",
                "expiration_utc", "url", "local_path", "remote_name", "file_size",
                "bytes_transferred", "raw_row_json", "parser_status",
                "parser_error", "created_at",
            ],
            rows,
        )

    def insert_bits_activity(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "bits_activity",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_table",
                "source_row_id", "event_time_utc", "event_id", "event_type",
                "provider", "channel", "computer", "job_id", "job_name",
                "job_owner", "url", "peer", "file_count", "total_bytes",
                "bytes_transferred", "local_path", "matched_bits_job_id",
                "correlation_basis", "raw_fields_json", "created_at",
            ],
            rows,
        )

    def insert_windows_search_files(self, rows: list[dict[str, Any]]) -> None:
        rows = [self._with_windows_search_file_flags(row) for row in rows]
        rows = self._strip_columns(rows, ("row_json",))
        self._insert_rows(
            "windows_search_files",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "work_id", "gather_time",
                "item_path", "item_url", "folder_path", "file_name", "file_extension",
                "item_type", "date_created", "date_modified", "date_accessed",
                "date_imported", "size", "owner", "computer_name", "is_deleted",
                "is_folder", "source_scope", "snapshot_id", "snapshot_ids",
                "snapshot_count", "snapshot_index", "snapshot_created_utc",
                "row_json", "created_at",
            ],
            rows,
        )

    def insert_windows_search_internet_history(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("row_json",))
        self._insert_rows(
            "windows_search_internet_history",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "work_id", "gather_time",
                "item_url", "target_url", "target_host", "target_path", "title",
                "file_name", "item_path", "folder_path", "date_created",
                "date_modified", "date_accessed", "date_imported", "owner",
                "row_json", "created_at",
            ],
            rows,
        )

    def insert_windows_search_activity_history(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("row_json",))
        self._insert_rows(
            "windows_search_activity_history",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "work_id", "gather_time",
                "item_url", "content_uri", "app_display_name", "display_text",
                "description", "app_id", "app_activity_id", "device_id",
                "start_time", "end_time", "local_start_time", "local_end_time",
                "active_duration", "item_path", "file_name", "row_json",
                "created_at",
            ],
            rows,
        )

    def insert_windows_search_gather_logs(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("raw_fields_json",))
        self._insert_rows(
            "windows_search_gather_logs",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_file", "source_name",
                "log_type", "line_number", "timestamp_utc", "filetime_hex",
                "time_low_hex", "time_high_hex", "item_url", "item_path",
                "item_scheme", "is_deleted_path", "status_hex", "crawl_code_hex",
                "scope_id", "document_id", "source_scope", "snapshot_id",
                "snapshot_ids", "snapshot_count", "snapshot_index",
                "snapshot_created_utc", "raw_fields_json", "created_at",
            ],
            rows,
        )

    def insert_windows_search_email_indicators(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "windows_search_email_indicators",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "source_table", "source_record_id",
                "row_number", "email", "domain", "evidence_field",
                "evidence_value", "timestamp", "context_path", "context_title",
                "created_at",
            ],
            rows,
        )

    def _metadata_only_content_row(
        self,
        row: dict[str, Any],
        source_table: str,
        content_columns: tuple[str, ...],
    ) -> dict[str, Any]:
        sanitized = dict(row)
        content_parts: list[str] = []
        indexed_columns = {
            "windows_search_indexed_content": {"content_text"},
            "mailbox_messages": {"body_text", "body_html"},
            "mailbox_attachments": {"extracted_text"},
            "messaging_records": {"message_text"},
            "messaging_messages": {"message_text", "message_html"},
        }.get(source_table, set(content_columns))
        for column in content_columns:
            value = "" if sanitized.get(column) is None else str(sanitized.get(column))
            if value and column in indexed_columns:
                content_parts.append(value)
            hash_column = "content_sha256" if column == "content_text" else f"{column}_sha256"
            length_column = "content_length" if column == "content_text" else f"{column}_length"
            sanitized.setdefault(hash_column, _text_hash(value))
            sanitized.setdefault(length_column, len(value))
            sanitized[column] = ""
        sanitized.setdefault("opensearch_document_id", _content_document_id(sanitized.get("case_id"), "\n".join(content_parts)))
        return sanitized

    def _strip_columns(self, rows: list[dict[str, Any]], columns: tuple[str, ...]) -> list[dict[str, Any]]:
        stripped = []
        for row in rows:
            sanitized = dict(row)
            for column in columns:
                sanitized[column] = "[]" if column in {"raw_fields_json", "raw_strings_json", "payload_strings_json", "event_values_json"} else "{}"
            stripped.append(sanitized)
        return stripped

    def _with_windows_search_file_flags(self, row: dict[str, Any]) -> dict[str, Any]:
        sanitized = dict(row)
        raw = sanitized.get("row_json")
        parsed: dict[str, Any] = {}
        if raw:
            try:
                parsed = json.loads(str(raw))
            except json.JSONDecodeError:
                parsed = {}
        sanitized.setdefault("is_deleted", _json_bool_text(parsed.get("System_IsDeleted")))
        sanitized.setdefault("is_folder", _json_bool_text(parsed.get("System_IsFolder")))
        return sanitized

    def insert_windows_search_indexed_content(self, rows: list[dict[str, Any]]) -> None:
        rows = [self._metadata_only_content_row(row, "windows_search_indexed_content", ("content_text",)) for row in rows]
        self._insert_rows(
            "windows_search_indexed_content",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "source_table", "source_record_id",
                "row_number", "work_id", "gather_time", "item_path", "item_name",
                "item_type", "content_field", "content_text", "content_sha256",
                "content_length", "opensearch_document_id", "timestamp", "created_at",
            ],
            rows,
        )

    def insert_windows_search_properties(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "windows_search_properties",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "source_table", "source_record_id",
                "row_number", "work_id", "item_path", "property_name",
                "property_value", "normalized_name", "timestamp", "created_at",
            ],
            rows,
        )

    def insert_staged_carves(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "staged_carves",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "profile",
                "source_path", "source_offset", "staged_path", "staged_name",
                "staged_size", "staged_sha256", "carve_type", "detected_format",
                "parser_status", "parser_error", "table_count", "object_count",
                "extractable_row_count", "import_status", "notes", "created_at",
            ],
            rows,
        )

    def insert_carve_scan_ranges(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "carve_scan_ranges",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "profile", "carve_type",
                "source_path", "source_size", "range_start", "range_end",
                "scanned_bytes", "hits_found", "limited", "limit_reason",
                "status", "notes", "created_at",
            ],
            rows,
        )

    def insert_windows_search_memory_carves(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "windows_search_memory_carves",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "carve_path",
                "carve_name", "carve_size", "carve_sha256", "source_process",
                "source_pid", "virtual_address", "detected_format", "page_size",
                "reserved_bytes", "parser_status", "parser_error", "table_count",
                "object_count", "extractable_row_count", "matched_disk_db",
                "matched_disk_page", "matched_tail_hex", "notes", "created_at",
            ],
            rows,
        )

    def insert_windows_search_memory_objects(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "windows_search_memory_objects",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "carve_id",
                "carve_path", "object_type", "object_name", "table_name",
                "rootpage", "sql_text", "parser_status", "parser_error",
                "created_at",
            ],
            rows,
        )

    def insert_windows_search_memory_rows(self, rows: list[dict[str, Any]]) -> None:
        rows = [
            {
                **row,
                "row_json": row.get("row_json") or "{}",
                "row_sha256": row.get("row_sha256") or _text_hash(row.get("row_json") or ""),
            }
            for row in rows
        ]
        self._insert_rows(
            "windows_search_memory_rows",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "carve_id",
                "carve_path", "table_name", "table_row_number", "row_json",
                "row_text", "row_sha256", "parser_status", "parser_error",
                "created_at",
            ],
            rows,
        )

    def insert_file_internal_metadata(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "file_internal_metadata",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_file",
                "original_path", "file_name", "extension", "parser",
                "metadata_group", "property_name", "property_value",
                "raw_property_name", "file_size", "mft_created", "mft_modified",
                "mft_accessed", "mft_record_modified", "mft_in_use",
                "path_unresolved", "deleted_mft_entry", "live_orphan",
                "extraction_method", "created_at",
            ],
            rows,
        )

    def insert_archive_entries(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "archive_entries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "archive_path",
                "archive_file_name", "archive_extension", "archive_file_size",
                "archive_modified_time_utc", "archive_status", "archive_error",
                "member_path", "member_file_name", "member_extension",
                "member_size", "member_compressed_size", "member_crc",
                "member_modified_time_utc", "member_is_dir", "member_is_encrypted",
                "nested_evidence_format", "multipart_set_id", "multipart_part_number",
                "multipart_part_count", "multipart_is_first_part",
                "multipart_related_parts", "created_at",
            ],
            rows,
        )

    def insert_nested_evidence_items(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "nested_evidence_items",
            [
                "id", "case_id", "computer_id", "image_id", "source_table",
                "source_id", "source_file", "original_path", "parent_path",
                "file_name", "extension", "file_size", "detected_format",
                "created_time_utc", "modified_time_utc", "accessed_time_utc",
                "record_changed_time_utc", "mft_entry_number", "mft_sequence_number",
                "multipart_set_id", "multipart_part_number", "multipart_part_count",
                "multipart_is_first_part", "multipart_related_parts",
                "parser_status", "recommendation", "created_at",
            ],
            rows,
        )

    def insert_mailbox_messages(self, rows: list[dict[str, Any]]) -> None:
        rows = [self._metadata_only_content_row(row, "mailbox_messages", ("body_text", "body_html")) for row in rows]
        self._insert_rows(
            "mailbox_messages",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "container_path", "message_path", "source_format",
                "parser_status", "parser_error", "user_profile", "user_sid", "message_id",
                "in_reply_to", "references_header", "reply_to",
                "conversation_index", "conversation_topic", "importance",
                "priority", "sensitivity", "x_originating_ip", "subject", "sender",
                "message_flags", "message_status", "message_status_flags",
                "disposition_notification_to",
                "recipients", "cc", "bcc", "message_date_utc", "body_text",
                "body_html", "body_text_sha256", "body_html_sha256",
                "body_text_length", "body_html_length", "opensearch_document_id",
                "attachment_names", "attachment_count", "has_attachments",
                "dedupe_key", "created_at",
            ],
            rows,
        )

    def insert_mailbox_attachments(self, rows: list[dict[str, Any]]) -> None:
        rows = [self._metadata_only_content_row(row, "mailbox_attachments", ("metadata_json", "extracted_text")) for row in rows]
        self._insert_rows(
            "mailbox_attachments",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_path",
                "container_path", "message_path", "user_profile", "user_sid",
                "message_id", "conversation_index", "conversation_topic",
                "subject", "sender", "recipients", "message_date_utc",
                "attachment_name", "attachment_path", "content_type", "size", "sha256",
                "metadata_json", "metadata_json_sha256", "metadata_json_length",
                "extracted_text", "extracted_text_sha256", "extracted_text_length",
                "opensearch_document_id", "extraction_status", "parser_error",
                "dedupe_key", "created_at",
            ],
            rows,
        )

    def insert_windows_mail_store_rows(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("row_json",))
        self._insert_rows(
            "windows_mail_store_rows",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_database",
                "source_table", "table_file", "table_row_number", "user_profile",
                "source_record_id", "parent_record_id", "display_name",
                "primary_time_utc", "secondary_time_utc", "row_json", "created_at",
            ],
            rows,
        )

    def insert_search_index_run(self, row: dict[str, Any]) -> None:
        self._insert_rows(
            "search_index_runs",
            [
                "id", "case_id", "backend", "backend_url", "index_name",
                "backend_version", "status", "document_count", "batch_count",
                "source_counts_json", "query_synonyms_json", "started_at",
                "ended_at", "error", "created_at",
            ],
            [
                {
                    **row,
                    "source_counts_json": json.dumps(row.get("source_counts") or {}, sort_keys=True),
                    "query_synonyms_json": json.dumps(row.get("query_synonyms") or [], sort_keys=True),
                }
            ],
        )

    def insert_content_references(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "content_references",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "source_tool", "source_table", "source_row_id", "content_role",
                "opensearch_document_id", "content_sha256", "content_length",
                "source_path", "created_at",
            ],
            rows,
        )

    def insert_cloud_server_events(self, rows: list[dict[str, Any]]) -> None:
        rows = [self._metadata_only_content_row(row, "cloud_server_events", ("_opensearch_content_text",)) for row in rows]
        self._insert_rows(
            "cloud_server_events",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "provider", "service",
                "event_type", "event_time_utc", "actor", "actor_id", "actor_ip",
                "target", "target_id", "target_type", "operation", "result",
                "user_agent", "client_app", "file_name", "file_path", "url",
                "message_id", "conversation_id", "content_sha256",
                "content_length", "opensearch_document_id", "source_log_type",
                "source_record_id", "raw_fields_json", "created_at",
            ],
            rows,
        )

    def insert_memory_string_hits(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "memory_string_hits",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_artifact_type",
                "source_path", "scanned_path", "decompressed_path", "scanner",
                "encoding", "hit_category", "matched_term", "string_value",
                "string_sha256", "string_length", "offset", "context_hint",
                "created_at",
            ],
            rows,
        )

    def insert_structured_memory_records(self, rows: list[dict[str, Any]]) -> None:
        self._insert_rows(
            "structured_memory_records",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_artifact_type",
                "source_path", "analysis_engine", "plugin", "category", "record_type",
                "pid", "ppid", "process_name", "command_line", "local_address",
                "local_port", "foreign_address", "foreign_port", "protocol", "state",
                "object_type", "object_name", "path", "module_base", "module_size",
                "offset", "virtual_address", "created_utc", "exited_utc", "suspicious",
                "summary", "raw_record_json", "created_at",
            ],
            rows,
        )

    def upsert_memory_credential_review(self, row: dict[str, Any]) -> None:
        now = utc_now()
        payload = {
            "id": row.get("id") or str(uuid.uuid4()),
            "case_id": row["case_id"],
            "memory_hit_id": row["memory_hit_id"],
            "review_status": row["review_status"],
            "reviewer": row.get("reviewer"),
            "note": row.get("note"),
            "reviewed_at": row.get("reviewed_at") or now,
            "created_at": row.get("created_at") or now,
        }
        self.conn.execute(
            """
            INSERT INTO memory_credential_reviews
              (id, case_id, memory_hit_id, review_status, reviewer, note, reviewed_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id, memory_hit_id) DO UPDATE SET
              review_status = excluded.review_status,
              reviewer = excluded.reviewer,
              note = excluded.note,
              reviewed_at = excluded.reviewed_at
            """,
            (
                payload["id"],
                payload["case_id"],
                payload["memory_hit_id"],
                payload["review_status"],
                payload["reviewer"],
                payload["note"],
                payload["reviewed_at"],
                payload["created_at"],
            ),
        )

    def insert_messaging_records(self, rows: list[dict[str, Any]]) -> None:
        rows = [self._metadata_only_content_row(row, "messaging_records", ("message_text", "raw_text")) for row in rows]
        self._insert_rows(
            "messaging_records",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "application",
                "user_profile", "artifact_type", "source_path", "store_path",
                "record_key", "record_type", "url", "host", "email",
                "timestamp_utc", "message_text", "raw_text", "message_text_sha256",
                "message_text_length", "raw_text_sha256", "raw_text_length",
                "opensearch_document_id", "dedupe_key", "created_at",
            ],
            rows,
        )

    def insert_messaging_messages(self, rows: list[dict[str, Any]]) -> None:
        rows = [self._metadata_only_content_row(row, "messaging_messages", ("message_text", "message_html", "raw_json")) for row in rows]
        self._insert_rows(
            "messaging_messages",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "application",
                "user_profile", "source_path", "store_path", "record_key",
                "platform_message_id", "conversation_id", "channel_id",
                "thread_id", "sender_id", "sender_name", "sender_email",
                "recipient", "timestamp_utc", "message_type", "message_text",
                "message_html", "url", "parser_confidence", "raw_json",
                "message_text_sha256", "message_text_length", "message_html_sha256",
                "message_html_length", "raw_json_sha256", "raw_json_length",
                "opensearch_document_id", "dedupe_key", "created_at",
            ],
            rows,
        )

    def insert_file_metadata_extraction_summary(self, row: dict[str, Any]) -> None:
        row = {
            "path_unresolved_count": 0,
            "deleted_path_unresolved_count": 0,
            "skipped_deleted_count": 0,
            "skipped_live_orphan_count": 0,
            "live_orphan_count": 0,
            **row,
        }
        self._insert_rows(
            "file_metadata_extraction_summaries",
            [
                "id", "case_id", "computer_id", "image_id", "tool_name", "artifact_name",
                "artifact_path", "selected_count", "extracted_count",
                "failed_count", "skipped_reparse_count", "skipped_deleted_count",
                "skipped_live_orphan_count", "live_orphan_count", "path_unresolved_count",
                "deleted_path_unresolved_count", "mounted_in_place_count", "mft_icat_count",
                "source", "created_at",
            ],
            [row],
        )

    def insert_evtx_events(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        created_at = utc_now()
        columns = ANALYTICS_TABLE_COLUMNS["evtx_events"]
        analytics_rows = [
            {
                "id": row["id"],
                "case_id": row["case_id"],
                "computer_id": row["computer_id"],
                "image_id": row["image_id"],
                "tool_output_id": row["tool_output_id"],
                "tool_name": row["tool_name"],
                "source_csv": str(row["source_csv"]),
                "row_number": row["row_number"],
                "record_number": row.get("record_number"),
                "event_record_id": row.get("event_record_id"),
                "time_created": row.get("time_created"),
                "event_id": row.get("event_id"),
                "level": row.get("level"),
                "provider": row.get("provider"),
                "channel": row.get("channel"),
                "process_id": row.get("process_id"),
                "thread_id": row.get("thread_id"),
                "computer": row.get("computer"),
                "user_id": row.get("user_id"),
                "map_description": row.get("map_description"),
                "user_name": row.get("user_name"),
                "remote_host": row.get("remote_host"),
                "payload_data1": row.get("payload_data1"),
                "payload_data2": row.get("payload_data2"),
                "payload_data3": row.get("payload_data3"),
                "payload_data4": row.get("payload_data4"),
                "payload_data5": row.get("payload_data5"),
                "payload_data6": row.get("payload_data6"),
                "executable_info": row.get("executable_info"),
                "source_file": row.get("source_file"),
                "payload": row.get("payload"),
                "created_at": created_at,
            }
            for row in rows
        ]
        if self._analytics_insert("evtx_events", columns, analytics_rows):
            return
        self.conn.executemany(
            """
            INSERT INTO evtx_events (
              id, case_id, computer_id, image_id, tool_output_id, tool_name,
              source_csv, row_number, record_number, event_record_id, time_created,
              event_id, level, provider, channel, process_id, thread_id, computer,
              user_id, map_description, user_name, remote_host, payload_data1,
              payload_data2, payload_data3, payload_data4, payload_data5,
              payload_data6, executable_info, source_file, payload,
              created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["id"],
                    row["case_id"],
                    row["computer_id"],
                    row["image_id"],
                    row["tool_output_id"],
                    row["tool_name"],
                    str(row["source_csv"]),
                    row["row_number"],
                    row.get("record_number"),
                    row.get("event_record_id"),
                    row.get("time_created"),
                    row.get("event_id"),
                    row.get("level"),
                    row.get("provider"),
                    row.get("channel"),
                    row.get("process_id"),
                    row.get("thread_id"),
                    row.get("computer"),
                    row.get("user_id"),
                    row.get("map_description"),
                    row.get("user_name"),
                    row.get("remote_host"),
                    row.get("payload_data1"),
                    row.get("payload_data2"),
                    row.get("payload_data3"),
                    row.get("payload_data4"),
                    row.get("payload_data5"),
                    row.get("payload_data6"),
                    row.get("executable_info"),
                    row.get("source_file"),
                    row.get("payload"),
                    created_at,
                )
                for row in rows
            ],
        )
        self._commit()

    def insert_etl_events(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        rows = self._strip_columns(rows, ("payload_strings_json", "event_values_json"))
        self._insert_rows(
            "etl_events",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_file", "source_name",
                "parser_status", "parser_error", "timestamp_utc", "provider_name",
                "provider_id", "provider_label", "event_category", "event_name",
                "event_id", "opcode", "version",
                "process_id", "parent_process_id", "session_id", "image_name",
                "command_line", "user_sid", "package_full_name", "flags",
                "payload_strings_json", "event_values_json", "file_size",
                "sha256_first_mb", "created_at",
            ],
            rows,
        )

    def insert_windows_error_reports(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(
            rows,
            ("loaded_modules_json", "signatures_json", "dynamic_signatures_json", "ui_json", "raw_json"),
        )
        self._insert_rows(
            "windows_error_reports",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_file",
                "source_name", "report_folder", "event_type", "event_time_utc",
                "upload_time_utc", "report_type", "consent", "report_status",
                "report_identifier", "integrator_report_identifier", "app_name",
                "original_filename", "target_app_id", "target_app_version",
                "fault_module_name", "fault_module_version", "exception_code",
                "exception_offset", "is_fatal", "bucket_id", "legacy_bucket_id",
                "ui_path", "loaded_modules_json", "signatures_json",
                "dynamic_signatures_json", "ui_json", "raw_json", "created_at",
            ],
            rows,
        )

    def insert_windows_defender_events(self, rows: list[dict[str, Any]]) -> None:
        rows = self._strip_columns(rows, ("raw_json",))
        self._insert_rows(
            "windows_defender_events",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "tool_name", "source_csv", "row_number", "source_file",
                "source_name", "artifact_type", "line_number", "event_time_utc",
                "event_type", "component", "severity", "threat_name", "action",
                "path", "resource", "message", "file_size", "modified_time_utc",
                "sha256_first_mb", "raw_json", "created_at",
            ],
            rows,
        )

    def replace_user_controlled_file_references(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
        rows: list[dict[str, Any]],
    ) -> None:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        self.conn.execute(
            f"DELETE FROM user_controlled_file_references WHERE {' AND '.join(where)}",
            params,
        )
        self._insert_rows(
            "user_controlled_file_references",
            [
                "id", "case_id", "computer_id", "image_id", "source_tool",
                "source_table", "source_row_id", "source_row_number",
                "event_time_utc", "raw_path", "normalized_path", "display_path",
                "volume_device", "owning_user", "file_name", "extension",
                "path_scope", "storage_provider", "artifact_meaning",
                "confidence_basis", "resolved_provider_path", "resolved_file_name",
                "resolved_cache_path", "resolution_status", "resolution_basis", "context",
                "details_json", "created_at",
            ],
            rows,
        )

    def insert_timeline_events(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        created_at = utc_now()
        columns = ANALYTICS_TABLE_COLUMNS["timeline_events"]
        analytics_rows = [
            {
                "id": row["id"],
                "case_id": row["case_id"],
                "computer_id": row["computer_id"],
                "image_id": row["image_id"],
                "tool_output_id": row["tool_output_id"],
                "source_tool": row["source_tool"],
                "source_table": row["source_table"],
                "source_row_id": row["source_row_id"],
                "event_type": row["event_type"],
                "raw_timestamp": row.get("raw_timestamp"),
                "timestamp_utc": row["timestamp_utc"],
                "end_timestamp_utc": row.get("end_timestamp_utc"),
                "duration_ms": row.get("duration_ms"),
                "description": row.get("description"),
                "details_json": json.dumps(row.get("details", {}), default=str),
                "created_at": created_at,
            }
            for row in rows
        ]
        if self._analytics_insert("timeline_events", columns, analytics_rows):
            return
        self.conn.executemany(
            """
            INSERT INTO timeline_events (
              id, case_id, computer_id, image_id, tool_output_id, source_tool,
              source_table, source_row_id, event_type, raw_timestamp, timestamp_utc,
              end_timestamp_utc, duration_ms, description, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["id"],
                    row["case_id"],
                    row["computer_id"],
                    row["image_id"],
                    row["tool_output_id"],
                    row["source_tool"],
                    row["source_table"],
                    row["source_row_id"],
                    row["event_type"],
                    row.get("raw_timestamp"),
                    row["timestamp_utc"],
                    row.get("end_timestamp_utc"),
                    row.get("duration_ms"),
                    row.get("description"),
                    json.dumps(row.get("details", {}), default=str),
                    created_at,
                )
                for row in rows
            ],
        )
        self._commit()

    def replace_copied_file_indicators(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
        rows: list[dict[str, Any]],
    ) -> None:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        if self.analytics is not None:
            self.analytics.delete_case_image(
                "copied_file_indicators",
                case_id=case_id,
                image_id=image_id,
            )
        self._delete_sqlite_if_exists("copied_file_indicators", " AND ".join(where), params)
        self._insert_rows(
            "copied_file_indicators",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "source_tool", "source_table", "source_row_id", "source_artifact_type",
                "source_artifact_name", "file_name", "file_location", "created_time",
                "modified_time", "created_timestamp_utc", "modified_timestamp_utc",
                "indicator", "reason", "confidence", "matched_mft_entry_number",
                "matched_mft_sequence_number", "details_json", "created_at",
            ],
            rows,
        )

    def replace_common_dialog_items(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
        rows: list[dict[str, Any]],
    ) -> None:
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if image_id is not None:
            where.append("image_id = ?")
            params.append(image_id)
        self.conn.execute(f"DELETE FROM registry_common_dialog_items WHERE {' AND '.join(where)}", params)
        self._insert_rows(
            "registry_common_dialog_items",
            [
                "id", "case_id", "computer_id", "image_id", "tool_output_id",
                "source_registry_artifact_id", "source_csv", "source_path", "hive_type",
                "user_profile", "artifact", "key_path", "key_last_write_utc",
                "mru_position", "value_name", "item_index", "shell_item_name",
                "shell_created", "shell_modified", "shell_accessed",
                "raw_fat_times_json", "created_at",
            ],
            rows,
        )

    def purge_tool_data(
        self,
        *,
        case_id: str,
        image_id: str | None = None,
        tool_names: list[str] | None = None,
    ) -> int:
        output_clause, output_params = self._purge_where_for_table(
            "tool_outputs",
            case_id=case_id,
            image_id=image_id,
            tool_names=tool_names,
        )
        output_count = self.conn.execute(
            f"SELECT COUNT(*) AS count FROM tool_outputs WHERE {output_clause}", output_params
        ).fetchone()["count"]
        if tool_names and all(name in TOOL_PURGE_TABLES for name in tool_names):
            purge_tables = tuple(
                table
                for table in DEFAULT_PURGE_TABLES
                if any(table in TOOL_PURGE_TABLES[name] for name in tool_names)
            )
        else:
            purge_tables = DEFAULT_PURGE_TABLES
        for table in purge_tables:
            clause, params = self._purge_where_for_table(
                table,
                case_id=case_id,
                image_id=image_id,
                tool_names=tool_names,
            )
            if not clause:
                continue
            if self._sqlite_table_exists(table):
                self.conn.execute(f"DELETE FROM {table} WHERE {clause}", params)
            if self.analytics is not None and table not in SQLITE_ONLY_PURGE_TABLES:
                self.analytics.delete_case_image(
                    table,
                    case_id=case_id,
                    image_id=image_id,
                    tool_names=tool_names,
                )

        content_ref_where = ["case_id = ?"]
        content_ref_params: list[Any] = [case_id]
        if image_id is not None:
            content_ref_where.append("image_id = ?")
            content_ref_params.append(image_id)
        if tool_names:
            placeholders = ", ".join("?" for _ in tool_names)
            content_ref_where.append(f"source_tool IN ({placeholders})")
            content_ref_params.extend(tool_names)
        self._delete_sqlite_if_exists("content_references", " AND ".join(content_ref_where), content_ref_params)
        if self.analytics is not None:
            self.analytics.delete_case_image(
                "content_references",
                case_id=case_id,
                image_id=image_id,
                tool_names=tool_names,
            )

        user_ref_where = ["case_id = ?"]
        user_ref_params: list[Any] = [case_id]
        if image_id is not None:
            user_ref_where.append("image_id = ?")
            user_ref_params.append(image_id)
        if tool_names:
            placeholders = ", ".join("?" for _ in tool_names)
            user_ref_where.append(f"source_tool IN ({placeholders})")
            user_ref_params.extend(tool_names)
        self._delete_sqlite_if_exists("user_controlled_file_references", " AND ".join(user_ref_where), user_ref_params)
        if not tool_names or any(name in {"MFTECmd", "LECmd", "JLECmd", "SBECmd", "RECmd"} for name in tool_names):
            copied_where = ["case_id = ?"]
            copied_params: list[Any] = [case_id]
            if image_id is not None:
                copied_where.append("image_id = ?")
                copied_params.append(image_id)
            if self.analytics is not None:
                self.analytics.delete_case_image(
                    "copied_file_indicators",
                    case_id=case_id,
                    image_id=image_id,
                )
            self._delete_sqlite_if_exists("copied_file_indicators", " AND ".join(copied_where), copied_params)
        if not tool_names or "RegistryArtifactParser" in tool_names:
            common_dialog_where = ["case_id = ?"]
            common_dialog_params: list[Any] = [case_id]
            if image_id is not None:
                common_dialog_where.append("image_id = ?")
                common_dialog_params.append(image_id)
            self._delete_sqlite_if_exists("registry_common_dialog_items", " AND ".join(common_dialog_where), common_dialog_params)
        if not tool_names or "MFTECmdI30" in tool_names:
            reconciliation_where = ["case_id = ?"]
            reconciliation_params: list[Any] = [case_id]
            if image_id is not None:
                reconciliation_where.append("image_id = ?")
                reconciliation_params.append(image_id)
            self._delete_sqlite_if_exists("ntfs_namespace_reconciliation", " AND ".join(reconciliation_where), reconciliation_params)
        if not tool_names or any(
            name
            in {
                "MFTECmd",
                "MFTECmdUSN",
                "MFTECmdLogFile",
                "NTFSParseLogFile",
                "MFTECmdI30",
                "WindowsSearchGatherParser",
                "MountedFilesystemInventory",
                "TskFilesystemInventory",
            }
            for name in tool_names
        ):
            filesystem_where = ["case_id = ?"]
            filesystem_params: list[Any] = [case_id]
            if image_id is not None:
                filesystem_where.append("image_id = ?")
                filesystem_params.append(image_id)
            if tool_names:
                placeholders = ", ".join("?" for _ in tool_names)
                filesystem_where.append(f"source_tool IN ({placeholders})")
                filesystem_params.extend(tool_names)
            self._delete_sqlite_if_exists("filesystem_review", " AND ".join(filesystem_where), filesystem_params)
            if self.analytics is not None:
                self.analytics.delete_case_image("filesystem_review", case_id=case_id, image_id=image_id)
        if not tool_names or any(name in {"RegistryArtifactParser", "EvtxECmd", "EvtxECmdTriage"} for name in tool_names):
            usb_where = ["case_id = ?"]
            usb_params: list[Any] = [case_id]
            if image_id is not None:
                usb_where.append("image_id = ?")
                usb_params.append(image_id)
            self._delete_sqlite_if_exists("usb_storage_devices", " AND ".join(usb_where), usb_params)
            if self.analytics is not None:
                self.analytics.delete_case_image("usb_storage_devices", case_id=case_id, image_id=image_id)
        if not tool_names or any(
            name in {"LECmd", "JLECmd", "SBECmd", "RegistryArtifactParser", "EvtxECmd", "EvtxECmdTriage"}
            for name in tool_names
        ):
            correlation_where = ["case_id = ?"]
            correlation_params: list[Any] = [case_id]
            if image_id is not None:
                correlation_where.append("image_id = ?")
                correlation_params.append(image_id)
            self._delete_sqlite_if_exists("usb_file_correlations", " AND ".join(correlation_where), correlation_params)
        if not tool_names or "RecycleParser" in tool_names:
            recycle_where = ["case_id = ?"]
            recycle_params: list[Any] = [case_id]
            if image_id is not None:
                recycle_where.append("image_id = ?")
                recycle_params.append(image_id)
            for table in ("recycle_items", "recycle_children"):
                self._delete_sqlite_if_exists(table, " AND ".join(recycle_where), recycle_params)
                if self.analytics is not None:
                    self.analytics.delete_case_image(table, case_id=case_id, image_id=image_id)
        if not tool_names or "FirefoxParser" in tool_names:
            firefox_where = ["case_id = ?"]
            firefox_params: list[Any] = [case_id]
            if image_id is not None:
                firefox_where.append("image_id = ?")
                firefox_params.append(image_id)
            for table in ("firefox_history", "firefox_cookies"):
                self._delete_sqlite_if_exists(table, " AND ".join(firefox_where), firefox_params)
                if self.analytics is not None:
                    self.analytics.delete_case_image(table, case_id=case_id, image_id=image_id)
        timeline_where = ["case_id = ?"]
        timeline_params: list[Any] = [case_id]
        if image_id is not None:
            timeline_where.append("image_id = ?")
            timeline_params.append(image_id)
        if tool_names:
            placeholders = ", ".join("?" for _ in tool_names)
            timeline_where.append(f"source_tool IN ({placeholders})")
            timeline_params.extend(tool_names)
        self._delete_sqlite_if_exists("timeline_events", " AND ".join(timeline_where), timeline_params)
        if self.analytics is not None:
            self.analytics.delete_case_image("timeline_events", case_id=case_id, image_id=image_id)
        file_correlation_where = ["case_id = ?"]
        file_correlation_params: list[Any] = [case_id]
        if image_id is not None:
            file_correlation_where.append("image_id = ?")
            file_correlation_params.append(image_id)
        if tool_names:
            source_tables = sorted(
                {
                    table
                    for tool_name in tool_names
                    for table in TOOL_PURGE_TABLES.get(tool_name, set())
                    if table != "tool_outputs"
                }
            )
            if source_tables:
                placeholders = ", ".join("?" for _ in source_tables)
                file_correlation_where.append(f"source_table IN ({placeholders})")
                file_correlation_params.extend(source_tables)
            else:
                file_correlation_where = []
                file_correlation_params = []
        if file_correlation_where:
            self._delete_sqlite_if_exists(
                "file_correlations",
                " AND ".join(file_correlation_where),
                file_correlation_params,
            )
        artifact_correlation_where = ["case_id = ?"]
        artifact_correlation_params: list[Any] = [case_id]
        if image_id is not None:
            artifact_correlation_where.append("image_id = ?")
            artifact_correlation_params.append(image_id)
        if tool_names:
            placeholders = ", ".join("?" for _ in tool_names)
            artifact_correlation_where.append(
                f"(left_source_tool IN ({placeholders}) OR right_source_tool IN ({placeholders}))"
            )
            artifact_correlation_params.extend(tool_names)
            artifact_correlation_params.extend(tool_names)
        self._delete_sqlite_if_exists("artifact_correlations", " AND ".join(artifact_correlation_where), artifact_correlation_params)
        if not tool_names or any(
            name in {"RegistryArtifactParser", "TelemetryParser", "OneDriveOdlParser", "OneDriveExplorer"}
            for name in tool_names
        ):
            inventory_where = ["case_id = ?"]
            inventory_params: list[Any] = [case_id]
            if image_id is not None:
                inventory_where.append("image_id = ?")
                inventory_params.append(image_id)
            self._delete_sqlite_if_exists("computer_inventory", " AND ".join(inventory_where), inventory_params)
        self.conn.commit()
        return int(output_count)

    def _delete_sqlite_if_exists(self, table: str, where: str, params: list[Any]) -> None:
        if self._sqlite_table_exists(table):
            self.conn.execute(f"DELETE FROM {self._quote_identifier(table)} WHERE {where}", params)

    def _purge_where_for_table(
        self,
        table: str,
        *,
        case_id: str,
        image_id: str | None,
        tool_names: list[str] | None,
    ) -> tuple[str, list[Any]]:
        columns = set(self._table_columns(table)) if table in self._sqlite_table_columns else {
            str(row["name"]) for row in self.conn.execute(f"PRAGMA table_info({self._quote_identifier(table)})").fetchall()
        }
        if not columns:
            return "", []
        where: list[str] = []
        params: list[Any] = []
        if "case_id" in columns:
            where.append("case_id = ?")
            params.append(case_id)
        if image_id is not None and "image_id" in columns:
            where.append("image_id = ?")
            params.append(image_id)
        if tool_names:
            placeholders = ", ".join("?" for _ in tool_names)
            if "tool_name" in columns:
                where.append(f"tool_name IN ({placeholders})")
                params.extend(tool_names)
            elif "source_tool" in columns:
                where.append(f"source_tool IN ({placeholders})")
                params.extend(tool_names)
            elif "tool_output_id" in columns:
                output_where = ["case_id = ?"]
                output_params: list[Any] = [case_id]
                if image_id is not None:
                    output_where.append("image_id = ?")
                    output_params.append(image_id)
                output_where.append(f"tool_name IN ({placeholders})")
                output_params.extend(tool_names)
                where.append(
                    "tool_output_id IN ("
                    f"SELECT id FROM tool_outputs WHERE {' AND '.join(output_where)}"
                    ")"
                )
                params.extend(output_params)
            else:
                return "", []
        if not where:
            return "", []
        return " AND ".join(where), params

    def _sqlite_table_exists(self, table: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone() is not None

    def _sqlite_table_has_column(self, table: str, column: str) -> bool:
        rows = self.conn.execute(f"PRAGMA table_info({self._quote_identifier(table)})").fetchall()
        return any(str(row["name"]) == column for row in rows)

    def log_activity(
        self,
        *,
        case_id: str,
        event: str,
        message: str,
        level: str = "info",
        computer_id: str | None = None,
        image_id: str | None = None,
        job_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO activity_log (
              id, case_id, computer_id, image_id, job_id, level, event,
              message, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                case_id,
                computer_id,
                image_id,
                job_id,
                level,
                event,
                message,
                json.dumps(details or {}, default=str),
                utc_now(),
            ),
        )
        self.conn.commit()

    def start_process_timing(
        self,
        *,
        case_id: str,
        scope: str,
        phase: str,
        name: str,
        computer_id: str | None = None,
        image_id: str | None = None,
        parent_id: str | None = None,
        job_id: str | None = None,
        tool_name: str | None = None,
        artifact_name: str | None = None,
        source_scope: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        timing_id = str(uuid.uuid4())
        now = utc_now()
        timing_source_scope = source_scope or _source_scope_from_values(name, artifact_name, json.dumps(details or {}, default=str))
        self.conn.execute(
            """
            INSERT INTO process_timings (
              id, case_id, computer_id, image_id, parent_id, job_id,
              source_scope, scope, phase, name, tool_name, artifact_name,
              status, start_time, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timing_id,
                case_id,
                computer_id,
                image_id,
                parent_id,
                job_id,
                timing_source_scope,
                scope,
                phase,
                name,
                tool_name,
                artifact_name,
                "running",
                now,
                json.dumps(details or {}, default=str),
                now,
            ),
        )
        self._commit()
        return timing_id

    def finish_process_timing(
        self,
        timing_id: str | None,
        *,
        status: str = "completed",
        details: dict[str, Any] | None = None,
    ) -> None:
        if not timing_id:
            return
        row = self.conn.execute(
            "SELECT start_time, details_json FROM process_timings WHERE id = ?",
            (timing_id,),
        ).fetchone()
        if row is None:
            return
        end_time = utc_now()
        existing_details = json.loads(row["details_json"] or "{}")
        if details:
            existing_details.update(details)
        self.conn.execute(
            """
            UPDATE process_timings
            SET status = ?, end_time = ?, duration_ms = ?, details_json = ?
            WHERE id = ?
            """,
            (
                status,
                end_time,
                _duration_ms(row["start_time"], end_time),
                json.dumps(existing_details, default=str),
                timing_id,
            ),
        )
        self._commit()

    def activity_for_case(
        self,
        case_id: str,
        *,
        limit: int = 100,
        level: str | None = None,
    ) -> list[sqlite3.Row]:
        if level:
            return self.conn.execute(
                """
                SELECT * FROM activity_log
                WHERE case_id = ? AND level = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (case_id, level, limit),
            ).fetchall()
        return self.conn.execute(
            """
            SELECT * FROM activity_log
            WHERE case_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()

    def parsed_row_counts(self, case_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT computer_id, image_id, tool_name, tool_output_id, COUNT(*) AS row_count
            FROM (
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM parsed_rows
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM shortcut_items
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM prefetch_items
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM sam_accounts
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_hives
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_artifacts
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_recentdocs
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_runmru
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_typedpaths
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_wordwheel_query
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_userassist
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_office_mru
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_common_dialog_mru
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM registry_trusted_documents
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM amcache_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM shimcache_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM shellbag_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM usb_devices
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM filesystem_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM mft_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM usn_journal_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM ntfs_logfile_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM ntfs_index_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM ntfs_index_bitmaps
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM srum_records
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM windows_search_files
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM windows_search_internet_history
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM windows_search_activity_history
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM windows_search_email_indicators
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM windows_search_indexed_content
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM windows_search_properties
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM file_internal_metadata
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM archive_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM evtx_events
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM etl_events
              UNION ALL
              SELECT case_id, computer_id, image_id, 'RecycleParser' AS tool_name, tool_output_id FROM recycle_items
              UNION ALL
              SELECT case_id, computer_id, image_id, 'RecycleParser' AS tool_name, tool_output_id FROM recycle_children
              UNION ALL
              SELECT case_id, computer_id, image_id, 'FirefoxParser' AS tool_name, tool_output_id FROM firefox_history
              UNION ALL
              SELECT case_id, computer_id, image_id, 'FirefoxParser' AS tool_name, tool_output_id FROM firefox_cookies
              UNION ALL
              SELECT case_id, computer_id, image_id, 'ChromiumParser' AS tool_name, tool_output_id FROM browser_history
              UNION ALL
              SELECT case_id, computer_id, image_id, 'ChromiumParser' AS tool_name, tool_output_id FROM browser_downloads
              UNION ALL
              SELECT case_id, computer_id, image_id, 'ChromiumParser' AS tool_name, tool_output_id FROM browser_cookies
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM browser_cache_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM cloud_sync_artifacts
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM google_drive_cache_map
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM onedrive_items
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM onedrive_log_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM package_cache_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM package_artifacts
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM spotify_artifacts
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM telemetry_artifacts
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM windows_activities
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM webcache_entries
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM webcache_file_accesses
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM windows_mail_store_rows
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM image_analysis_items
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM rdp_cache_items
              UNION ALL
              SELECT case_id, computer_id, image_id, tool_name, tool_output_id FROM rdp_visual_observations
            )
            WHERE case_id = ?
            GROUP BY computer_id, image_id, tool_name, tool_output_id
            ORDER BY tool_name, tool_output_id
            """,
            (case_id,),
        ).fetchall()

    def finish_job(self, job_id: str, end_time: str, exit_code: int) -> None:
        self.conn.execute(
            "UPDATE jobs SET end_time = ?, exit_code = ? WHERE id = ?",
            (end_time, exit_code, job_id),
        )
        self.conn.commit()

    def case_status(self, case_id: str) -> dict[str, Any]:
        case = self.get_case(case_id)
        images = self.conn.execute(
            "SELECT id, computer_id, path, created_at FROM images WHERE case_id = ? ORDER BY created_at",
            (case_id,),
        ).fetchall()
        image_metadata = self.conn.execute(
            """
            SELECT image_id, source, key, value, created_at
            FROM image_metadata
            WHERE case_id = ?
            ORDER BY image_id, source, key
            """,
            (case_id,),
        ).fetchall()
        image_hashes = self.conn.execute(
            """
            SELECT image_id, algorithm, digest, size_bytes, source_path, status, error, computed_at
            FROM image_hashes
            WHERE case_id = ?
            ORDER BY image_id, algorithm
            """,
            (case_id,),
        ).fetchall()
        computers = self.conn.execute(
            "SELECT id, label, hostname, notes, created_at FROM computers WHERE case_id = ? ORDER BY created_at",
            (case_id,),
        ).fetchall()
        jobs = self.conn.execute(
            """
            SELECT id, image_id, computer_id, tool_name, exit_code, dry_run, start_time, end_time, output_folder
            FROM jobs WHERE case_id = ? ORDER BY start_time
            """,
            (case_id,),
        ).fetchall()
        mounts = self.conn.execute(
            "SELECT * FROM mounts WHERE case_id = ? ORDER BY created_at", (case_id,)
        ).fetchall()
        artifacts = self.conn.execute(
            """
            SELECT id, image_id, name, source, path, kind, metadata_json, created_at
            FROM artifacts WHERE case_id = ? ORDER BY created_at, name
            """,
            (case_id,),
        ).fetchall()
        outputs = self.conn.execute(
            """
            SELECT id, computer_id, image_id, job_id, tool_name, output_type, path, content_sha256, row_count, created_at
            FROM tool_outputs WHERE case_id = ? ORDER BY created_at, tool_name, path
            """,
            (case_id,),
        ).fetchall()
        parsed_counts = self.parsed_row_counts(case_id)
        activity = self.activity_for_case(case_id, limit=50)
        return {
            "case": {
                "id": case.id,
                "root": str(case.root),
                "description": case.description,
                "notes_path": case.notes_path,
                "created_at": case.created_at,
            },
            "project": {
                "id": case.id,
                "root": str(case.root),
                "description": case.description,
                "notes_path": case.notes_path,
                "created_at": case.created_at,
            },
            "computers": [dict(row) for row in computers],
            "images": [dict(row) for row in images],
            "image_metadata": [dict(row) for row in image_metadata],
            "image_hashes": [dict(row) for row in image_hashes],
            "mounts": [dict(row) for row in mounts],
            "artifacts": [dict(row) for row in artifacts],
            "outputs": [dict(row) for row in outputs],
            "parsed_row_counts": [dict(row) for row in parsed_counts],
            "activity": [dict(row) for row in reversed(activity)],
            "jobs": [dict(row) for row in jobs],
        }
