from __future__ import annotations

import csv
import hashlib
import logging
import os
import uuid
from pathlib import Path

from forensic_orchestrator.artifact_correlations import rebuild_artifact_correlations
from forensic_orchestrator.common_dialog_resolution import rebuild_common_dialog_application_resolutions
from forensic_orchestrator.computer_inventory import rebuild_computer_inventory
from forensic_orchestrator.correlation import rebuild_file_correlations
from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.search.opensearch import (
    IngestContentIndexer,
    OpenSearchConfig,
    generic_content_document,
    mailbox_attachment_document,
    mailbox_message_document,
    messaging_message_document,
    messaging_record_document,
    windows_search_content_document,
)
from forensic_orchestrator.thumbcache_correlate import rebuild_thumbcache_search_correlations
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.ez_registry import (
    normalized_amcache_row,
    normalized_shellbag_row,
    normalized_shimcache_row,
)
from forensic_orchestrator.tools.normalized import (
    normalized_etl_event_row,
    normalized_evtx_event_row,
    normalized_file_internal_metadata_row,
    normalized_image_analysis_item_row,
    normalized_mailbox_attachment_row,
    normalized_mailbox_message_row,
    normalized_windows_mail_store_row,
    normalized_messaging_message_row,
    normalized_messaging_record_row,
    normalized_memory_string_hit_row,
    normalized_package_artifact_row,
    normalized_package_cache_entry_row,
    normalized_rdp_cache_item_row,
    normalized_rdp_visual_observation_row,
    normalized_browser_cookie_row,
    normalized_browser_artifact_row,
    normalized_bits_activity_row_from_evtx,
    normalized_bits_job_row,
    normalized_clipboard_item_row,
    normalized_browser_cache_entry_row,
    normalized_browser_download_row,
    normalized_browser_history_row,
    normalized_browser_notification_row,
    normalized_browser_session_entry_row,
    normalized_browser_site_setting_row,
    normalized_cloud_server_event_row,
    normalized_cloud_sync_artifact_row,
    normalized_google_drive_cache_map_row,
    normalized_onedrive_item_row,
    normalized_onedrive_log_entry_row,
    normalized_office_backstage_row,
    normalized_office_trust_row_from_registry_artifact,
    normalized_taskbar_feature_usage_row_from_registry_artifact,
    normalized_user_dictionary_word_row,
    normalized_firefox_cookie_row,
    normalized_firefox_history_row,
    normalized_mft_entry_row,
    normalized_ntfs_logfile_entry_row,
    normalized_ntfs_index_bitmap_row,
    normalized_ntfs_index_entry_row,
    normalized_registry_artifact_row,
    normalized_recycle_row,
    normalized_registry_hive_row,
    normalized_sam_account_row,
    normalized_setupapi_device_event_row,
    normalized_srum_record_row,
    normalized_spotify_artifact_row,
    normalized_telemetry_artifact_row,
    normalized_thumbcache_entry_row,
    normalized_ual_record_row,
    normalized_usn_journal_entry_row,
    normalized_webcache_entry_row,
    normalized_windows_search_activity_history_row,
    normalized_windows_defender_event_row,
    normalized_windows_error_report_row,
    normalized_windows_search_gather_log_row,
    normalized_windows_activity_row,
    normalized_archive_entry_row,
    normalized_windows_search_file_row,
    normalized_windows_search_internet_history_row,
    normalized_zone_identifier_ads_row,
    windows_search_email_indicator_rows,
    windows_search_indexed_content_rows,
    windows_search_property_rows,
    webcache_file_access_row_from_entry,
)
from forensic_orchestrator.tools.prefetch_items import normalized_prefetch_row, normalized_prefetch_run_time_rows
from forensic_orchestrator.tools.recmd import normalized_recmd_detail_row, recmd_ownership_rows
from forensic_orchestrator.tools.shortcuts import normalized_shortcut_rows
from forensic_orchestrator.tools.taskband import taskband_pin_rows_from_registry_artifact
from forensic_orchestrator.tools.usb import usb_rows_from_registry_artifact
from forensic_orchestrator.tools.usb_partition import usb_rows_from_partition_diagnostic_event
from forensic_orchestrator.tools.usb_summary import rebuild_usb_connection_events, rebuild_usb_storage_devices
from forensic_orchestrator.tools.usp import normalized_usp_row


LOGGER = logging.getLogger(__name__)
INGEST_BATCH_SIZE = 5000
DEFAULT_CSV_FIELD_SIZE_LIMIT = 100 * 1024 * 1024
csv.field_size_limit(
    int(os.environ.get("PERCEPTOR_CSV_FIELD_SIZE_LIMIT", DEFAULT_CSV_FIELD_SIZE_LIMIT))
)


def load_artifact_manifest(path: Path) -> dict[str, dict[str, str]]:
    manifest_path = _find_artifact_manifest(path)
    if manifest_path is None:
        return {}
    with manifest_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        return {
            row["artifact_path"]: dict(row)
            for row in csv.DictReader(handle)
            if row.get("artifact_path")
        }


def _find_artifact_manifest(path: Path) -> Path | None:
    for parent in path.parents:
        candidate = parent / "_artifact_manifest.csv"
        if candidate.exists():
            return candidate
    return None


def ingest_csv_output(
    *,
    db: Database,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    path: Path,
    rebuild_correlations: bool = True,
) -> int:
    db.ensure_tool_output_parent(
        tool_output_id=tool_output_id,
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        tool_name=tool_name,
        path=path,
    )
    rows = []
    shortcut_rows = []
    prefetch_rows = []
    prefetch_run_time_rows = []
    sam_rows = []
    registry_hive_rows = []
    registry_artifact_rows = []
    office_trust_rows = []
    taskbar_feature_rows = []
    taskbar_pin_rows = []
    recmd_artifact_rows: dict[str, list[dict[str, object]]] = {}
    amcache_rows = []
    shimcache_rows = []
    shellbag_rows = []
    usb_rows = []
    setupapi_rows = []
    mft_rows = []
    usn_rows = []
    ntfs_logfile_rows = []
    ntfs_index_entry_rows = []
    ntfs_index_bitmap_rows = []
    srum_rows = []
    ual_rows = []
    bits_job_rows = []
    bits_activity_rows = []
    windows_search_file_rows = []
    windows_search_internet_rows = []
    windows_search_activity_rows = []
    windows_search_gather_rows = []
    windows_error_report_rows = []
    windows_defender_event_rows = []
    windows_search_email_rows = []
    windows_search_content_rows = []
    windows_search_property_rows_buffer = []
    evtx_rows = []
    etl_rows = []
    recycle_item_rows = []
    recycle_child_rows = []
    firefox_history_rows = []
    firefox_cookie_rows = []
    browser_history_rows = []
    browser_download_rows = []
    browser_cookie_rows = []
    browser_cache_rows = []
    browser_artifact_rows = []
    browser_session_rows = []
    browser_site_setting_rows = []
    browser_notification_rows = []
    office_backstage_rows = []
    user_dictionary_rows = []
    zone_identifier_rows = []
    thumbcache_rows = []
    image_analysis_rows = []
    rdp_cache_rows = []
    rdp_visual_rows = []
    cloud_sync_rows = []
    google_drive_cache_map_rows = []
    onedrive_item_rows = []
    onedrive_log_rows = []
    package_cache_rows = []
    package_artifact_rows = []
    spotify_artifact_rows = []
    telemetry_artifact_rows = []
    clipboard_item_rows = []
    windows_activity_rows = []
    webcache_rows = []
    webcache_file_access_rows = []
    file_internal_metadata_rows = []
    archive_entry_rows = []
    cloud_server_event_rows = []
    memory_string_hit_rows = []
    mailbox_message_rows = []
    mailbox_attachment_rows = []
    windows_mail_store_rows = []
    messaging_record_rows = []
    messaging_message_rows = []
    content_reference_rows = []
    content_indexer = IngestContentIndexer(OpenSearchConfig.from_values())
    correlation_inputs_seen = False
    usb_evidence_seen = False
    normalize_only = tool_name in {
        "LECmd",
        "JLECmd",
        "PrefetchParser",
        "SAMParser",
        "MFTECmd",
        "MFTECmdUSN",
        "MFTECmdLogFile",
        "NTFSParseLogFile",
        "MFTECmdI30",
        "SrumECmd",
        "SrumParser",
        "UalParser",
        "SIDR",
        "WindowsSearchESEParser",
        "WindowsSearchGatherParser",
        "WindowsErrorReportingParser",
        "WindowsDefenderParser",
        "EvtxECmd",
        "EtlParser",
        "RecycleParser",
        "FirefoxParser",
        "ChromiumParser",
        "BrowserCacheParser",
        "CloudSyncParser",
        "OneDriveExplorer",
        "OneDriveOdlParser",
        "SQLECmd",
        "PackageArtifactsParser",
        "TelemetryParser",
        "ClipboardParser",
        "WindowsActivitiesParser",
        "WebCacheParser",
        "FileMetadataExtractor",
        "FileMetadataOffice",
        "FileMetadataPictures",
        "FileMetadataPicturesUserContent",
        "FileMetadataVideos",
        "FileMetadataExecutables",
        "FileMetadataDocuments",
        "ArchiveInventoryParser",
        "MailboxParser",
        "OfficeBackstageParser",
        "UserFileContentParser",
        "UserDictionaryParser",
        "ZoneIdentifierParser",
        "ThumbcacheParser",
        "RdpCacheParser",
        "RdpVisionReview",
        "WindowsMailParser",
        "MessagingParser",
        "RegistryParser",
        "RegistryArtifactParser",
        "SetupApiParser",
        "USPParser",
        "RECmd",
        "AmcacheParser",
        "AppCompatCacheParser",
        "SBECmd",
        "CloudServerLogImporter",
        "MemoryStringScanner",
    }
    manifest_cache: dict[Path, dict[str, dict[str, str]]] = {}
    recmd_ownership_cache: dict[Path, list[dict[str, object]]] = {}
    row_count = 0
    write_phase = "database"

    def flush() -> None:
        nonlocal write_phase
        nonlocal rows
        nonlocal shortcut_rows
        nonlocal prefetch_rows
        nonlocal sam_rows
        nonlocal registry_hive_rows
        nonlocal registry_artifact_rows
        nonlocal office_trust_rows
        nonlocal taskbar_feature_rows
        nonlocal taskbar_pin_rows
        nonlocal recmd_artifact_rows
        nonlocal amcache_rows
        nonlocal shimcache_rows
        nonlocal shellbag_rows
        nonlocal usb_rows
        nonlocal setupapi_rows
        nonlocal mft_rows
        nonlocal usn_rows
        nonlocal ntfs_logfile_rows
        nonlocal ntfs_index_entry_rows
        nonlocal ntfs_index_bitmap_rows
        nonlocal srum_rows
        nonlocal ual_rows
        nonlocal bits_job_rows
        nonlocal bits_activity_rows
        nonlocal windows_search_file_rows
        nonlocal windows_search_internet_rows
        nonlocal windows_search_activity_rows
        nonlocal windows_search_gather_rows
        nonlocal windows_error_report_rows
        nonlocal windows_defender_event_rows
        nonlocal windows_search_email_rows
        nonlocal windows_search_content_rows
        nonlocal windows_search_property_rows_buffer
        nonlocal evtx_rows
        nonlocal etl_rows
        nonlocal recycle_item_rows
        nonlocal recycle_child_rows
        nonlocal firefox_history_rows
        nonlocal firefox_cookie_rows
        nonlocal browser_history_rows
        nonlocal browser_download_rows
        nonlocal browser_cookie_rows
        nonlocal browser_cache_rows
        nonlocal browser_artifact_rows
        nonlocal browser_session_rows
        nonlocal browser_site_setting_rows
        nonlocal browser_notification_rows
        nonlocal office_backstage_rows
        nonlocal user_dictionary_rows
        nonlocal zone_identifier_rows
        nonlocal thumbcache_rows
        nonlocal image_analysis_rows
        nonlocal rdp_cache_rows
        nonlocal rdp_visual_rows
        nonlocal cloud_sync_rows
        nonlocal google_drive_cache_map_rows
        nonlocal onedrive_item_rows
        nonlocal onedrive_log_rows
        nonlocal package_cache_rows
        nonlocal package_artifact_rows
        nonlocal spotify_artifact_rows
        nonlocal telemetry_artifact_rows
        nonlocal clipboard_item_rows
        nonlocal windows_activity_rows
        nonlocal webcache_rows
        nonlocal webcache_file_access_rows
        nonlocal file_internal_metadata_rows
        nonlocal archive_entry_rows
        nonlocal cloud_server_event_rows
        nonlocal memory_string_hit_rows
        nonlocal mailbox_message_rows
        nonlocal mailbox_attachment_rows
        nonlocal windows_mail_store_rows
        nonlocal messaging_record_rows
        nonlocal messaging_message_rows
        nonlocal content_reference_rows
        nonlocal usb_evidence_seen
        write_phase = "opensearch"
        for row in mailbox_message_rows:
            document = mailbox_message_document(
                row,
                body_text=str(row.get("_opensearch_body_text") or ""),
                body_html=str(row.get("_opensearch_body_html") or ""),
            )
            content_indexer.add(document)
            if document:
                content_reference_rows.append(_content_reference_from_document(row, document, "message_body"))
        for row in mailbox_attachment_rows:
            document = mailbox_attachment_document(
                row,
                extracted_text=str(row.get("_opensearch_extracted_text") or ""),
            )
            content_indexer.add(document)
            if document:
                content_reference_rows.append(_content_reference_from_document(row, document, "attachment_text"))
        for row in windows_search_content_rows:
            document = windows_search_content_document(
                row,
                content_text=str(row.get("_opensearch_content_text") or ""),
            )
            content_indexer.add(document)
            if document:
                content_reference_rows.append(_content_reference_from_document(row, document, "indexed_content"))
        for row in messaging_record_rows:
            document = messaging_record_document(
                row,
                message_text=str(row.get("_opensearch_message_text") or ""),
            )
            content_indexer.add(document)
            if document:
                content_reference_rows.append(_content_reference_from_document(row, document, "message_text"))
        for row in messaging_message_rows:
            document = messaging_message_document(
                row,
                message_text=str(row.get("_opensearch_message_text") or ""),
                message_html=str(row.get("_opensearch_message_html") or ""),
            )
            content_indexer.add(document)
            if document:
                content_reference_rows.append(_content_reference_from_document(row, document, "chat_message"))
        for row in cloud_server_event_rows:
            document = generic_content_document(
                row,
                source_type="cloud_server_log",
                source_table="cloud_server_events",
                content=str(row.get("_opensearch_content_text") or ""),
                title=str(row.get("event_type") or row.get("operation") or row.get("provider") or ""),
                timestamp=row.get("event_time_utc"),
                source_path=row.get("source_csv"),
            )
            content_indexer.add(document)
            if document:
                content_reference_rows.append(_content_reference_from_document(row, document, "cloud_log_content"))
        for row in clipboard_item_rows:
            content_text = "\n".join(
                str(row.get(key) or "")
                for key in ("text_content", "html_content", "file_uri")
                if row.get(key)
            )
            document = generic_content_document(
                row,
                source_type="clipboard",
                source_table="clipboard_items",
                content=content_text,
                title=str(row.get("format_name") or row.get("content_type") or "Clipboard item"),
                timestamp=row.get("item_time_utc") or row.get("created_time_utc"),
                source_path=row.get("source_path") or row.get("source_csv"),
            )
            content_indexer.add(document)
            if document:
                content_reference_rows.append(_content_reference_from_document(row, document, "clipboard_content"))
        write_phase = "database"
        def insert_normalized(table: str, table_rows: list[dict[str, object]], legacy_insert) -> None:
            if db.analytics_only:
                db.insert_normalized_artifact_rows(table, table_rows)
            else:
                legacy_insert(table_rows)

        def insert_normalized_groups(table_rows: dict[str, list[dict[str, object]]]) -> None:
            if db.analytics_only:
                db.insert_normalized_artifact_row_groups(table_rows)
            else:
                db.insert_recmd_artifact_rows(table_rows)

        insert_normalized("shortcut_items", shortcut_rows, db.insert_shortcut_items)
        insert_normalized("prefetch_items", prefetch_rows, db.insert_prefetch_items)
        insert_normalized(
            "prefetch_run_times",
            prefetch_run_time_rows,
            lambda rows: db.insert_normalized_artifact_rows("prefetch_run_times", rows),
        )
        insert_normalized("sam_accounts", sam_rows, db.insert_sam_accounts)
        insert_normalized("registry_hives", registry_hive_rows, db.insert_registry_hives)
        insert_normalized("registry_artifacts", registry_artifact_rows, db.insert_registry_artifacts)
        insert_normalized("registry_office_trust_records", office_trust_rows, db.insert_office_trust_records)
        insert_normalized("registry_taskbar_feature_usage", taskbar_feature_rows, db.insert_taskbar_feature_usage)
        insert_normalized("registry_taskbar_pins", taskbar_pin_rows, db.insert_taskbar_pins)
        if registry_artifact_rows and not db.analytics_only:
            db.enrich_registry_artifact_users(case_id=case_id, image_id=image_id)
        insert_normalized_groups(recmd_artifact_rows)
        insert_normalized("amcache_entries", amcache_rows, db.insert_amcache_entries)
        insert_normalized("shimcache_entries", shimcache_rows, db.insert_shimcache_entries)
        insert_normalized("shellbag_entries", shellbag_rows, db.insert_shellbag_entries)
        insert_normalized("usb_devices", usb_rows, db.insert_usb_devices)
        insert_normalized("setupapi_device_events", setupapi_rows, db.insert_setupapi_device_events)
        usb_evidence_seen = usb_evidence_seen or bool(usb_rows)
        insert_normalized("mft_entries", mft_rows, db.insert_mft_entries)
        insert_normalized("usn_journal_entries", usn_rows, db.insert_usn_journal_entries)
        if mft_rows and usn_rows:
            db.enrich_usn_paths_from_mft(case_id=case_id, image_id=image_id)
        insert_normalized("ntfs_logfile_entries", ntfs_logfile_rows, db.insert_ntfs_logfile_entries)
        insert_normalized("ntfs_index_entries", ntfs_index_entry_rows, db.insert_ntfs_index_entries)
        insert_normalized("ntfs_index_bitmaps", ntfs_index_bitmap_rows, db.insert_ntfs_index_bitmaps)
        insert_normalized("srum_records", srum_rows, db.insert_srum_records)
        insert_normalized("ual_records", ual_rows, db.insert_ual_records)
        insert_normalized("bits_jobs", bits_job_rows, db.insert_bits_jobs)
        insert_normalized("bits_activity", bits_activity_rows, db.insert_bits_activity)
        insert_normalized("windows_search_files", windows_search_file_rows, db.insert_windows_search_files)
        insert_normalized("windows_search_internet_history", windows_search_internet_rows, db.insert_windows_search_internet_history)
        insert_normalized("windows_search_activity_history", windows_search_activity_rows, db.insert_windows_search_activity_history)
        insert_normalized("windows_search_gather_logs", windows_search_gather_rows, db.insert_windows_search_gather_logs)
        insert_normalized("windows_error_reports", windows_error_report_rows, db.insert_windows_error_reports)
        insert_normalized("windows_defender_events", windows_defender_event_rows, db.insert_windows_defender_events)
        insert_normalized("windows_search_email_indicators", windows_search_email_rows, db.insert_windows_search_email_indicators)
        insert_normalized("windows_search_indexed_content", windows_search_content_rows, db.insert_windows_search_indexed_content)
        insert_normalized("windows_search_properties", windows_search_property_rows_buffer, db.insert_windows_search_properties)
        db.insert_evtx_events(evtx_rows)
        insert_normalized("etl_events", etl_rows, db.insert_etl_events)
        insert_normalized("recycle_items", recycle_item_rows, db.insert_recycle_items)
        insert_normalized("recycle_children", recycle_child_rows, db.insert_recycle_children)
        insert_normalized("firefox_history", firefox_history_rows, db.insert_firefox_history)
        insert_normalized("firefox_cookies", firefox_cookie_rows, db.insert_firefox_cookies)
        insert_normalized("browser_history", browser_history_rows, db.insert_browser_history)
        insert_normalized("browser_downloads", browser_download_rows, db.insert_browser_downloads)
        insert_normalized("browser_cookies", browser_cookie_rows, db.insert_browser_cookies)
        insert_normalized("browser_cache_entries", browser_cache_rows, db.insert_browser_cache_entries)
        insert_normalized("browser_artifacts", browser_artifact_rows, db.insert_browser_artifacts)
        insert_normalized("browser_session_entries", browser_session_rows, db.insert_browser_session_entries)
        insert_normalized("browser_site_settings", browser_site_setting_rows, db.insert_browser_site_settings)
        insert_normalized("browser_notifications", browser_notification_rows, db.insert_browser_notifications)
        insert_normalized("office_backstage_items", office_backstage_rows, db.insert_office_backstage_items)
        insert_normalized("user_dictionary_words", user_dictionary_rows, db.insert_user_dictionary_words)
        insert_normalized("zone_identifier_ads", zone_identifier_rows, db.insert_zone_identifier_ads)
        insert_normalized("thumbcache_entries", thumbcache_rows, db.insert_thumbcache_entries)
        insert_normalized("image_analysis_items", image_analysis_rows, db.insert_image_analysis_items)
        insert_normalized("rdp_cache_items", rdp_cache_rows, db.insert_rdp_cache_items)
        insert_normalized("rdp_visual_observations", rdp_visual_rows, db.insert_rdp_visual_observations)
        insert_normalized("cloud_sync_artifacts", cloud_sync_rows, db.insert_cloud_sync_artifacts)
        insert_normalized("google_drive_cache_map", google_drive_cache_map_rows, db.insert_google_drive_cache_map)
        insert_normalized("onedrive_items", onedrive_item_rows, db.insert_onedrive_items)
        insert_normalized("onedrive_log_entries", onedrive_log_rows, db.insert_onedrive_log_entries)
        insert_normalized("package_cache_entries", package_cache_rows, db.insert_package_cache_entries)
        insert_normalized("package_artifacts", package_artifact_rows, db.insert_package_artifacts)
        insert_normalized("spotify_artifacts", spotify_artifact_rows, db.insert_spotify_artifacts)
        insert_normalized("telemetry_artifacts", telemetry_artifact_rows, db.insert_telemetry_artifacts)
        insert_normalized("clipboard_items", clipboard_item_rows, db.insert_clipboard_items)
        insert_normalized("windows_activities", windows_activity_rows, db.insert_windows_activities)
        insert_normalized("webcache_entries", webcache_rows, db.insert_webcache_entries)
        insert_normalized("webcache_file_accesses", webcache_file_access_rows, db.insert_webcache_file_accesses)
        insert_normalized("file_internal_metadata", file_internal_metadata_rows, db.insert_file_internal_metadata)
        insert_normalized("archive_entries", archive_entry_rows, db.insert_archive_entries)
        insert_normalized("cloud_server_events", cloud_server_event_rows, db.insert_cloud_server_events)
        insert_normalized("memory_string_hits", memory_string_hit_rows, db.insert_memory_string_hits)
        insert_normalized("mailbox_messages", mailbox_message_rows, db.insert_mailbox_messages)
        insert_normalized("mailbox_attachments", mailbox_attachment_rows, db.insert_mailbox_attachments)
        insert_normalized("windows_mail_store_rows", windows_mail_store_rows, db.insert_windows_mail_store_rows)
        db.insert_content_references(content_reference_rows)
        insert_normalized("messaging_records", messaging_record_rows, db.insert_messaging_records)
        insert_normalized("messaging_messages", messaging_message_rows, db.insert_messaging_messages)
        db.insert_timeline_events(
            timeline_events_from_rows(
                shortcut_rows
                + prefetch_rows
                + sam_rows
                + evtx_rows
                + bits_activity_rows
                + etl_rows
                + recycle_item_rows
                + firefox_history_rows
                + browser_history_rows
                + browser_download_rows
                + browser_cache_rows
                + package_cache_rows
                + package_artifact_rows
                + bits_job_rows
                + telemetry_artifact_rows
                + clipboard_item_rows
                + windows_activity_rows
                + windows_search_gather_rows
                + windows_error_report_rows
                + windows_defender_event_rows
                + memory_string_hit_rows
                + registry_artifact_rows
                + webcache_rows
                + webcache_file_access_rows
            )
        )
        rows = []
        shortcut_rows = []
        prefetch_rows = []
        sam_rows = []
        registry_hive_rows = []
        registry_artifact_rows = []
        office_trust_rows = []
        taskbar_feature_rows = []
        taskbar_pin_rows = []
        recmd_artifact_rows = {}
        amcache_rows = []
        shimcache_rows = []
        shellbag_rows = []
        usb_rows = []
        setupapi_rows = []
        mft_rows = []
        usn_rows = []
        ntfs_logfile_rows = []
        ntfs_index_entry_rows = []
        ntfs_index_bitmap_rows = []
        srum_rows = []
        ual_rows = []
        bits_job_rows = []
        bits_activity_rows = []
        windows_search_file_rows = []
        windows_search_internet_rows = []
        windows_search_activity_rows = []
        windows_search_gather_rows = []
        windows_error_report_rows = []
        windows_defender_event_rows = []
        windows_search_email_rows = []
        windows_search_content_rows = []
        windows_search_property_rows_buffer = []
        evtx_rows = []
        etl_rows = []
        recycle_item_rows = []
        recycle_child_rows = []
        firefox_history_rows = []
        firefox_cookie_rows = []
        browser_history_rows = []
        browser_download_rows = []
        browser_cookie_rows = []
        browser_cache_rows = []
        browser_artifact_rows = []
        browser_session_rows = []
        browser_site_setting_rows = []
        browser_notification_rows = []
        office_backstage_rows = []
        user_dictionary_rows = []
        zone_identifier_rows = []
        thumbcache_rows = []
        image_analysis_rows = []
        rdp_cache_rows = []
        rdp_visual_rows = []
        cloud_sync_rows = []
        google_drive_cache_map_rows = []
        onedrive_item_rows = []
        onedrive_log_rows = []
        package_cache_rows = []
        package_artifact_rows = []
        spotify_artifact_rows = []
        telemetry_artifact_rows = []
        clipboard_item_rows = []
        windows_activity_rows = []
        webcache_rows = []
        webcache_file_access_rows = []
        file_internal_metadata_rows = []
        archive_entry_rows = []
        cloud_server_event_rows = []
        memory_string_hit_rows = []
        mailbox_message_rows = []
        mailbox_attachment_rows = []
        windows_mail_store_rows = []
        messaging_record_rows = []
        messaging_message_rows = []
        content_reference_rows = []

    try:
        with db.bulk_transaction():
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                reader = csv.DictReader(line for line in handle if not line.startswith("#"))
                for row_number, row in enumerate(reader, start=1):
                    row_count += 1
                    artifact_manifest: dict[str, dict[str, str]] = {}
                    if tool_name in {"LECmd", "PrefetchParser"}:
                        source_file = row.get("SourceFile") or row.get("Source File")
                        if tool_name == "PrefetchParser":
                            source_file = row.get("source_path") or row.get("SourcePath") or source_file
                        if source_file:
                            source_path = Path(source_file)
                            manifest_root = source_path.parent
                            if manifest_root not in manifest_cache:
                                manifest_cache[manifest_root] = load_artifact_manifest(source_path)
                            artifact_manifest = manifest_cache[manifest_root]
                    if tool_name in {"LECmd", "JLECmd"}:
                        normalized_rows = normalized_shortcut_rows(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=dict(row),
                            artifact_manifest=artifact_manifest,
                        )
                        shortcut_rows.extend(normalized_rows)
                        correlation_inputs_seen = correlation_inputs_seen or bool(normalized_rows)
                    if tool_name == "PrefetchParser":
                        prefetch_row = normalized_prefetch_row(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=dict(row),
                            artifact_manifest=artifact_manifest,
                        )
                        prefetch_rows.append(prefetch_row)
                        prefetch_run_time_rows.extend(normalized_prefetch_run_time_rows(prefetch_row))
                        correlation_inputs_seen = True
                    if tool_name == "SAMParser":
                        sam_rows.append(
                            normalized_sam_account_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "RegistryParser":
                        registry_hive_rows.append(
                            normalized_registry_hive_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "RegistryArtifactParser":
                        registry_row = normalized_registry_artifact_row(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=dict(row),
                        )
                        registry_artifact_rows.append(registry_row)
                        office_trust_row = normalized_office_trust_row_from_registry_artifact(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=registry_row,
                        )
                        if office_trust_row is not None:
                            office_trust_rows.append(office_trust_row)
                        taskbar_feature_row = normalized_taskbar_feature_usage_row_from_registry_artifact(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=registry_row,
                        )
                        if taskbar_feature_row is not None:
                            taskbar_feature_rows.append(taskbar_feature_row)
                        taskbar_pin_rows.extend(
                            taskband_pin_rows_from_registry_artifact(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=registry_row,
                            )
                        )
                        usb_rows.extend(usb_rows_from_registry_artifact(registry_row))
                    if tool_name == "SetupApiParser":
                        setupapi_rows.append(
                            normalized_setupapi_device_event_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "USPParser":
                        usb_rows.append(
                            normalized_usp_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "RECmd":
                        if path not in recmd_ownership_cache:
                            recmd_ownership_cache[path] = recmd_ownership_rows(path)
                        ownership_rows = recmd_ownership_cache[path]
                        ownership = ownership_rows[row_number - 1] if row_number - 1 < len(ownership_rows) else None
                        normalized = normalized_recmd_detail_row(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=dict(row),
                            ownership=ownership,
                        )
                        if normalized is not None:
                            table, normalized_row = normalized
                            recmd_artifact_rows.setdefault(table, []).append(normalized_row)
                    if tool_name == "AmcacheParser":
                        amcache_rows.append(
                            normalized_amcache_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "AppCompatCacheParser":
                        shimcache_rows.append(
                            normalized_shimcache_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "SBECmd":
                        shellbag_rows.append(
                            normalized_shellbag_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "MFTECmd":
                        mft_rows.append(
                            normalized_mft_entry_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                        correlation_inputs_seen = True
                    if tool_name in {"MFTECmdUSN", "USNRewind"}:
                        usn_rows.append(
                            normalized_usn_journal_entry_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name in {"MFTECmdLogFile", "NTFSParseLogFile"}:
                        ntfs_logfile_rows.append(
                            normalized_ntfs_logfile_entry_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "MFTECmdI30":
                        if "bitmap_hex" in row:
                            ntfs_index_bitmap_rows.append(
                                normalized_ntfs_index_bitmap_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        else:
                            ntfs_index_entry_rows.append(
                                normalized_ntfs_index_entry_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                    if tool_name in {"SrumECmd", "SrumParser"}:
                        srum_rows.append(
                            normalized_srum_record_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "UalParser":
                        ual_rows.append(
                            normalized_ual_record_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "BITSParser":
                        bits_job_rows.append(
                            normalized_bits_job_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name in {"SIDR", "WindowsSearchESEParser"}:
                        lower_name = path.name.lower()
                        if "file_report" in lower_name or tool_name == "WindowsSearchESEParser":
                            normalized = normalized_windows_search_file_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                            windows_search_file_rows.append(normalized)
                            windows_search_content_rows.extend(
                                windows_search_indexed_content_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_files",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                            windows_search_property_rows_buffer.extend(
                                windows_search_property_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_files",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                            windows_search_email_rows.extend(
                                windows_search_email_indicator_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_files",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                        elif "internet_history_report" in lower_name:
                            normalized = normalized_windows_search_internet_history_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                            windows_search_internet_rows.append(normalized)
                            windows_search_content_rows.extend(
                                windows_search_indexed_content_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_internet_history",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                            windows_search_property_rows_buffer.extend(
                                windows_search_property_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_internet_history",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                            windows_search_email_rows.extend(
                                windows_search_email_indicator_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_internet_history",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                        elif "activity_history_report" in lower_name:
                            normalized = normalized_windows_search_activity_history_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                            windows_search_activity_rows.append(normalized)
                            windows_search_content_rows.extend(
                                windows_search_indexed_content_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_activity_history",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                            windows_search_property_rows_buffer.extend(
                                windows_search_property_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_activity_history",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                            windows_search_email_rows.extend(
                                windows_search_email_indicator_rows(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    source_table="windows_search_activity_history",
                                    source_record_id=normalized["id"],
                                    row_number=row_number,
                                    normalized_row=normalized,
                                    row=dict(row),
                                )
                            )
                    if tool_name.startswith("FileMetadata"):
                        file_internal_metadata_rows.append(
                            normalized_file_internal_metadata_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "UserFileContentParser":
                        content = str(row.get("content_text") or "").strip()
                        if content:
                            content_id = str(uuid.uuid4())
                            item_path = str(row.get("item_path") or row.get("source_file") or "")
                            windows_search_content_rows.append(
                                {
                                    "id": content_id,
                                    "case_id": case_id,
                                    "computer_id": computer_id,
                                    "image_id": image_id,
                                    "tool_output_id": tool_output_id,
                                    "tool_name": tool_name,
                                    "source_csv": path,
                                    "source_table": "user_file_content",
                                    "source_record_id": content_id,
                                    "row_number": row_number,
                                    "work_id": "",
                                    "gather_time": "",
                                    "item_path": item_path,
                                    "item_name": str(row.get("item_name") or Path(item_path).name),
                                    "item_type": str(row.get("item_type") or ""),
                                    "content_field": str(row.get("content_field") or "extracted_text"),
                                    "content_text": "",
                                    "_opensearch_content_text": content,
                                    "content_sha256": hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest(),
                                    "content_length": len(content),
                                    "opensearch_document_id": hashlib.sha256(f"{case_id}|content|{hashlib.sha256(content.encode('utf-8', errors='replace')).hexdigest()}".encode("utf-8", errors="replace")).hexdigest(),
                                    "timestamp": str(row.get("modified_utc") or ""),
                                    "created_at": utc_now(),
                                }
                            )
                    if tool_name == "ArchiveInventoryParser":
                        archive_entry_rows.append(
                            normalized_archive_entry_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "CloudServerLogImporter":
                        cloud_server_event_rows.append(
                            normalized_cloud_server_event_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "MemoryStringScanner":
                        memory_string_hit_rows.append(
                            normalized_memory_string_hit_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name in {"MailboxParser", "WindowsMailParser"}:
                        if path.name == "WindowsMailStoreRows.csv":
                            windows_mail_store_rows.append(
                                normalized_windows_mail_store_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif "attachment_path" in row:
                            mailbox_attachment_rows.append(
                                _resolve_mailbox_user_scope(
                                    db,
                                    case_id,
                                    normalized_mailbox_attachment_row(
                                        case_id=case_id,
                                        computer_id=computer_id,
                                        image_id=image_id,
                                        tool_output_id=tool_output_id,
                                        tool_name=tool_name,
                                        source_csv=path,
                                        row_number=row_number,
                                        row=dict(row),
                                    ),
                                )
                            )
                        else:
                            mailbox_message_rows.append(
                                _resolve_mailbox_user_scope(
                                    db,
                                    case_id,
                                    normalized_mailbox_message_row(
                                        case_id=case_id,
                                        computer_id=computer_id,
                                        image_id=image_id,
                                        tool_output_id=tool_output_id,
                                        tool_name=tool_name,
                                        source_csv=path,
                                        row_number=row_number,
                                        row=dict(row),
                                    ),
                                )
                            )
                    if tool_name == "MessagingParser":
                        if path.name == "MessagingMessages.csv":
                            messaging_message_rows.append(
                                normalized_messaging_message_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        else:
                            messaging_record_rows.append(
                                normalized_messaging_record_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                    if tool_name == "WindowsSearchGatherParser":
                        windows_search_gather_rows.append(
                            normalized_windows_search_gather_log_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "WindowsErrorReportingParser":
                        windows_error_report_rows.append(
                            normalized_windows_error_report_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "WindowsDefenderParser":
                        windows_defender_event_rows.append(
                            normalized_windows_defender_event_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "EvtxECmd":
                        evtx_row = normalized_evtx_event_row(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=dict(row),
                        )
                        evtx_rows.append(evtx_row)
                        bits_activity_row = normalized_bits_activity_row_from_evtx(evtx_row)
                        if bits_activity_row:
                            bits_activity_rows.append(bits_activity_row)
                        usb_rows.extend(usb_rows_from_partition_diagnostic_event(evtx_row))
                    if tool_name == "EtlParser":
                        etl_rows.append(
                            normalized_etl_event_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "RecycleParser":
                        recycle_row = normalized_recycle_row(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=dict(row),
                        )
                        if recycle_row.get("record_type") == "child":
                            recycle_child_rows.append(recycle_row)
                        else:
                            recycle_item_rows.append(recycle_row)
                    if tool_name == "FirefoxParser":
                        if path.name == "FirefoxSessionEntries.csv":
                            browser_session_rows.append(
                                normalized_browser_session_entry_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif row.get("artifact_type"):
                            browser_artifact_rows.append(
                                normalized_browser_artifact_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif "visit_time_utc" in row:
                            firefox_history_rows.append(
                                normalized_firefox_history_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif "target_path" in row:
                            browser_download_rows.append(
                                normalized_browser_download_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif "host" in row:
                            firefox_cookie_rows.append(
                                normalized_firefox_cookie_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                    if tool_name == "ChromiumParser":
                        if path.name == "BrowserSessionEntries.csv":
                            browser_session_rows.append(
                                normalized_browser_session_entry_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif path.name == "BrowserSiteSettings.csv":
                            browser_site_setting_rows.append(
                                normalized_browser_site_setting_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif path.name == "BrowserNotifications.csv":
                            browser_notification_rows.append(
                                normalized_browser_notification_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif row.get("artifact_type"):
                            browser_artifact_rows.append(
                                normalized_browser_artifact_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif "visit_time_utc" in row:
                            browser_history_rows.append(
                                normalized_browser_history_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif "target_path" in row:
                            browser_download_rows.append(
                                normalized_browser_download_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif "host" in row:
                            browser_cookie_rows.append(
                                normalized_browser_cookie_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                    if tool_name == "BrowserCacheParser":
                        browser_cache_rows.append(
                            normalized_browser_cache_entry_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "OfficeBackstageParser":
                        office_backstage_rows.append(
                            normalized_office_backstage_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "UserDictionaryParser":
                        user_dictionary_rows.append(
                            normalized_user_dictionary_word_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "ZoneIdentifierParser":
                        zone_identifier_rows.append(
                            normalized_zone_identifier_ads_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "ThumbcacheParser":
                        thumbcache_rows.append(
                            normalized_thumbcache_entry_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name in {"RdpCacheParser", "RdpVisionReview"}:
                        if path.name == "ImageAnalysisItems.csv":
                            image_analysis_rows.append(
                                normalized_image_analysis_item_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif path.name == "RdpVisualObservations.csv":
                            rdp_visual_rows.append(
                                normalized_rdp_visual_observation_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                        elif tool_name == "RdpCacheParser":
                            rdp_cache_rows.append(
                                normalized_rdp_cache_item_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                    if tool_name in {"CloudSyncParser", "SQLECmd"}:
                        cloud_sync_rows.append(
                            normalized_cloud_sync_artifact_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                        if row.get("artifact_type") in {"google_drive_cache_mapping", "google_drive_cache_file"}:
                            google_drive_cache_map_rows.append(
                                normalized_google_drive_cache_map_row(
                                    case_id=case_id,
                                    computer_id=computer_id,
                                    image_id=image_id,
                                    tool_output_id=tool_output_id,
                                    tool_name=tool_name,
                                    source_csv=path,
                                    row_number=row_number,
                                    row=dict(row),
                                )
                            )
                    if tool_name == "OneDriveExplorer":
                        onedrive_item_rows.append(
                            normalized_onedrive_item_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "OneDriveOdlParser":
                        onedrive_log_rows.append(
                            normalized_onedrive_log_entry_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "PackageCacheParser":
                        package_cache_rows.append(
                            normalized_package_cache_entry_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "PackageArtifactsParser":
                        package_artifact_rows.append(
                            normalized_package_artifact_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "SpotifyParser":
                        spotify_artifact_rows.append(
                            normalized_spotify_artifact_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "TelemetryParser":
                        telemetry_artifact_rows.append(
                            normalized_telemetry_artifact_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "ClipboardParser":
                        clipboard_item_rows.append(
                            normalized_clipboard_item_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "WindowsActivitiesParser":
                        windows_activity_rows.append(
                            normalized_windows_activity_row(
                                case_id=case_id,
                                computer_id=computer_id,
                                image_id=image_id,
                                tool_output_id=tool_output_id,
                                tool_name=tool_name,
                                source_csv=path,
                                row_number=row_number,
                                row=dict(row),
                            )
                        )
                    if tool_name == "WebCacheParser":
                        webcache_row = normalized_webcache_entry_row(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            tool_output_id=tool_output_id,
                            tool_name=tool_name,
                            source_csv=path,
                            row_number=row_number,
                            row=dict(row),
                        )
                        webcache_rows.append(webcache_row)
                        webcache_file_access = webcache_file_access_row_from_entry(webcache_row)
                        if webcache_file_access:
                            webcache_file_access_rows.append(webcache_file_access)
                    if row_count % INGEST_BATCH_SIZE == 0:
                        flush()
            flush()
        write_phase = "opensearch"
        content_indexer.close(db, case_id=case_id)
        write_phase = "database"
    except Exception as exc:
        _log_ingest_write_failure(
            db,
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            tool_name=tool_name,
            path=path,
            phase=write_phase,
            exc=exc,
        )
        raise
    if tool_name in {"RECmd", "JLECmd"}:
        rebuild_common_dialog_application_resolutions(db, case_id=case_id, image_id=image_id)
    if rebuild_correlations and tool_name in {"ThumbcacheParser", "SIDR", "WindowsSearchESEParser"}:
        rebuild_thumbcache_search_correlations(db, case_id=case_id, image_id=image_id)
    if db.analytics_only:
        return row_count
    if rebuild_correlations and correlation_inputs_seen:
        rebuild_file_correlations(db, case_id=case_id, image_id=image_id)
    if rebuild_correlations and tool_name in {
        "RegistryArtifactParser",
        "TelemetryParser",
        "WindowsActivitiesParser",
        "CloudSyncParser",
        "OneDriveExplorer",
        "MessagingParser",
        "OneDriveOdlParser",
    }:
        rebuild_computer_inventory(db, case_id=case_id, image_id=image_id)
        rebuild_artifact_correlations(db, case_id=case_id, image_id=image_id)
    if usb_evidence_seen:
        db.dedupe_usb_devices(case_id=case_id, image_id=image_id)
        rebuild_usb_storage_devices(db, case_id=case_id, image_id=image_id)
        rebuild_usb_connection_events(db, case_id=case_id, image_id=image_id)
    return row_count


def _resolve_mailbox_user_scope(db: Database, case_id: str, row: dict[str, object]) -> dict[str, object]:
    sid = str(row.get("user_sid") or "")
    if not sid.upper().startswith("S-1-"):
        return row
    rid = sid.rsplit("-", 1)[-1]
    account = db.conn.execute(
        """
        SELECT username
        FROM sam_accounts
        WHERE case_id = ? AND rid = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (case_id, rid),
    ).fetchone()
    if account and account["username"]:
        row["user_profile"] = account["username"]
    return row


def _log_ingest_write_failure(
    db: Database,
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_name: str,
    path: Path,
    phase: str,
    exc: Exception,
) -> None:
    event = "search.opensearch_write_failed" if phase == "opensearch" else "database.write_failed"
    message = "OpenSearch write failed during ingest" if phase == "opensearch" else "Database write failed during ingest"
    details = {
        "phase": phase,
        "tool_name": tool_name,
        "source_csv": str(path),
        "error_type": type(exc).__name__,
        "error": str(exc),
    }
    LOGGER.exception(message, extra={"details": details})
    try:
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level="error",
            event=event,
            message=message,
            details=details,
        )
    except Exception:
        LOGGER.exception("Failed to write ingest failure activity log", extra={"details": details})


def _content_reference_from_document(row: dict[str, object], document: dict[str, object], role: str) -> dict[str, object]:
    content = str(document.get("content") or "")
    content_hash = str(document.get("content_hash") or "")
    if not content_hash and content:
        content_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    return {
        "id": _content_reference_id(row, role),
        "case_id": row.get("case_id"),
        "computer_id": row.get("computer_id"),
        "image_id": row.get("image_id"),
        "tool_output_id": row.get("tool_output_id"),
        "source_tool": row.get("tool_name"),
        "source_table": document.get("source_table"),
        "source_row_id": row.get("id"),
        "content_role": role,
        "opensearch_document_id": document.get("id"),
        "content_sha256": content_hash,
        "content_length": document.get("content_length") or len(content),
        "source_path": document.get("source_path") or row.get("source_path"),
    }


def _content_reference_id(row: dict[str, object], role: str) -> str:
    value = f"{row.get('case_id')}|{row.get('id')}|{role}"
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
