from __future__ import annotations

import json
import uuid
from typing import Any

from .timestamps import normalize_timestamp, parse_timestamp


def timeline_events_from_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in rows:
        tool_name = row.get("tool_name")
        if tool_name == "PrefetchParser":
            events.extend(_prefetch_events(row))
        elif tool_name in {"LECmd", "JLECmd"}:
            events.extend(_shortcut_events(row))
        elif tool_name == "EvtxECmd":
            events.extend(_evtx_events(row))
        elif tool_name == "EtlParser":
            events.extend(_etl_events(row))
        elif tool_name == "SAMParser":
            events.extend(_sam_events(row))
        elif row.get("record_type") and row.get("deletion_time_utc"):
            events.extend(_recycle_events(row))
        elif tool_name == "ChromiumParser" and row.get("visit_time_utc") and row.get("url"):
            events.extend(_browser_history_events(row))
        elif tool_name == "ChromiumParser" and row.get("target_path"):
            events.extend(_browser_download_events(row))
        elif tool_name == "BrowserCacheParser":
            events.extend(_browser_cache_events(row))
        elif tool_name == "PackageCacheParser":
            events.extend(_package_cache_events(row))
        elif tool_name == "PackageArtifactsParser":
            events.extend(_package_artifact_events(row))
        elif tool_name == "TelemetryParser":
            events.extend(_telemetry_artifact_events(row))
        elif tool_name == "WindowsActivitiesParser":
            events.extend(_windows_activity_events(row))
        elif tool_name == "WindowsSearchGatherParser":
            events.extend(_windows_search_gather_events(row))
        elif tool_name == "WindowsErrorReportingParser":
            events.extend(_windows_error_report_events(row))
        elif tool_name == "WindowsDefenderParser":
            events.extend(_windows_defender_events(row))
        elif tool_name == "MemoryStringScanner":
            events.extend(_memory_string_events(row))
        elif tool_name == "WebCacheParser" and row.get("local_path"):
            events.extend(_webcache_file_events(row))
        elif tool_name == "WebCacheParser":
            events.extend(_webcache_events(row))
        elif tool_name == "RegistryArtifactParser":
            events.extend(_registry_artifact_events(row))
        elif row.get("visit_time_utc") and row.get("url"):
            events.extend(_firefox_history_events(row))
    return events


def _base(row: dict[str, Any], event_type: str, raw_timestamp: str | None, description: str | None, details: dict[str, Any]) -> dict[str, Any] | None:
    timestamp_utc = normalize_timestamp(raw_timestamp)
    if timestamp_utc is None:
        return None
    details = dict(details or {})
    source_scope = _source_scope(row)
    source_origin = _source_origin(row, source_scope)
    details.setdefault("source_scope", source_scope)
    details.setdefault("source_origin", source_origin)
    return {
        "id": str(uuid.uuid4()),
        "case_id": row["case_id"],
        "computer_id": row["computer_id"],
        "image_id": row["image_id"],
        "tool_output_id": row["tool_output_id"],
        "source_tool": row["tool_name"],
        "source_table": _source_table(row),
        "source_row_id": row["id"],
        "event_type": event_type,
        "raw_timestamp": raw_timestamp,
        "timestamp_utc": timestamp_utc,
        "description": description,
        "details": details,
    }


def _source_scope(row: dict[str, Any]) -> str:
    if row.get("tool_name") == "MemoryStringScanner":
        artifact_type = str(row.get("source_artifact_type") or "memory").strip().lower()
        return artifact_type or "memory"
    value = str(row.get("source_scope") or "").strip()
    if value:
        return value
    source_path = " ".join(str(row.get(key) or "") for key in ("source_path", "source_file", "original_path"))
    lowered = source_path.lower()
    if "pagefile.sys" in lowered:
        return "pagefile"
    if "hiberfil.sys" in lowered:
        return "hiberfil"
    if "swapfile.sys" in lowered:
        return "swapfile"
    if lowered.endswith((".dmp", ".mdmp", ".dump")) or "crashdumps" in lowered or "minidump" in lowered:
        return "crash_dump"
    return "live"


def _source_origin(row: dict[str, Any], source_scope: str) -> str:
    if row.get("tool_name") == "MemoryStringScanner":
        return "memory"
    lowered = str(source_scope or "").lower()
    if lowered in {"pagefile", "hiberfil", "swapfile", "crash_dump", "process_dump", "full_memory_dump", "memory"}:
        return "memory"
    if lowered in {"windows.old", "windows_old", "vsc"}:
        return lowered
    return "disk"


def _source_table(row: dict[str, Any]) -> str:
    tool_name = row["tool_name"]
    if tool_name == "ChromiumParser":
        if row.get("target_path"):
            return "browser_downloads"
        if row.get("host"):
            return "browser_cookies"
        return "browser_history"
    if tool_name == "BrowserCacheParser":
        return "browser_cache_entries"
    if tool_name == "PackageCacheParser":
        return "package_cache_entries"
    if tool_name == "PackageArtifactsParser":
        return "package_artifacts"
    if tool_name == "TelemetryParser":
        return "telemetry_artifacts"
    if tool_name == "WindowsActivitiesParser":
        return "windows_activities"
    if tool_name == "WindowsSearchGatherParser":
        return "windows_search_gather_logs"
    if tool_name == "WindowsErrorReportingParser":
        return "windows_error_reports"
    if tool_name == "WindowsDefenderParser":
        return "windows_defender_events"
    if tool_name == "MemoryStringScanner":
        return "memory_string_hits"
    if tool_name == "WebCacheParser":
        if row.get("local_path"):
            return "webcache_file_accesses"
        return "webcache_entries"
    if tool_name == "RegistryArtifactParser":
        return "registry_artifacts"
    if tool_name == "EtlParser":
        return "etl_events"
    return {
        "PrefetchParser": "prefetch_items",
        "LECmd": "shortcut_items",
        "JLECmd": "shortcut_items",
        "EvtxECmd": "evtx_events",
        "SAMParser": "sam_accounts",
        "RecycleParser": "recycle_items",
        "FirefoxParser": "firefox_history",
    }.get(tool_name, "parsed_rows")


def _etl_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    if not row.get("timestamp_utc"):
        return []
    description = row.get("command_line") or row.get("image_name") or row.get("event_name") or row.get("source_name")
    event_type = "etl_process_event" if row.get("image_name") or row.get("command_line") else row.get("event_category") or "etl_event"
    event = _base(
        row,
        event_type,
        row.get("timestamp_utc"),
        description,
        {
            "source_file": row.get("source_file"),
            "source_name": row.get("source_name"),
            "provider_name": row.get("provider_name"),
            "provider_id": row.get("provider_id"),
            "provider_label": row.get("provider_label"),
            "event_category": row.get("event_category"),
            "event_name": row.get("event_name"),
            "event_id": row.get("event_id"),
            "process_id": row.get("process_id"),
            "parent_process_id": row.get("parent_process_id"),
            "session_id": row.get("session_id"),
            "image_name": row.get("image_name"),
            "command_line": row.get("command_line"),
            "user_sid": row.get("user_sid"),
            "package_full_name": row.get("package_full_name"),
            "flags": row.get("flags"),
        },
    )
    return [event] if event else []


def _windows_search_gather_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    if not row.get("timestamp_utc"):
        return []
    description = row.get("item_path") or row.get("item_url") or row.get("source_name")
    event = _base(
        row,
        "windows_search_gather",
        row.get("timestamp_utc"),
        description,
        {
            "source_file": row.get("source_file"),
            "source_name": row.get("source_name"),
            "log_type": row.get("log_type"),
            "item_url": row.get("item_url"),
            "item_path": row.get("item_path"),
            "item_scheme": row.get("item_scheme"),
            "is_deleted_path": row.get("is_deleted_path"),
            "status_hex": row.get("status_hex"),
            "crawl_code_hex": row.get("crawl_code_hex"),
            "scope_id": row.get("scope_id"),
            "document_id": row.get("document_id"),
        },
    )
    return [event] if event else []


def _windows_error_report_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    if not row.get("event_time_utc"):
        return []
    description = row.get("app_name") or row.get("event_type") or row.get("report_folder")
    event = _base(
        row,
        "windows_error_report",
        row.get("event_time_utc"),
        description,
        {
            "source_file": row.get("source_file"),
            "report_folder": row.get("report_folder"),
            "event_type": row.get("event_type"),
            "app_name": row.get("app_name"),
            "fault_module_name": row.get("fault_module_name"),
            "exception_code": row.get("exception_code"),
            "bucket_id": row.get("bucket_id"),
            "ui_path": row.get("ui_path"),
        },
    )
    return [event] if event else []


def _windows_defender_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    if not row.get("event_time_utc"):
        return []
    description = row.get("message") or row.get("path") or row.get("source_name")
    event = _base(
        row,
        row.get("event_type") or "windows_defender_event",
        row.get("event_time_utc"),
        description,
        {
            "source_file": row.get("source_file"),
            "source_name": row.get("source_name"),
            "artifact_type": row.get("artifact_type"),
            "component": row.get("component"),
            "severity": row.get("severity"),
            "threat_name": row.get("threat_name"),
            "action": row.get("action"),
            "path": row.get("path"),
            "resource": row.get("resource"),
        },
    )
    return [event] if event else []


def _memory_string_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    if not row.get("created_at"):
        return []
    source_type = row.get("source_artifact_type") or "memory"
    hit_category = row.get("hit_category") or "string"
    matched_term = row.get("matched_term") or ""
    description = f"Memory {source_type} string hit: {hit_category} {matched_term}".strip()
    event = _base(
        row,
        "memory_string_hit",
        row.get("created_at"),
        description,
        {
            "evidence_strength": "lead",
            "source_artifact_type": source_type,
            "source_path": row.get("source_path"),
            "scanned_path": row.get("scanned_path"),
            "hit_category": hit_category,
            "matched_term": matched_term,
            "string_sha256": row.get("string_sha256"),
            "string_length": row.get("string_length"),
            "offset": row.get("offset"),
            "context_hint": row.get("context_hint"),
            "caveat": "Memory string timeline timestamp is import time, not occurrence time.",
        },
    )
    return [event] if event else []


def _prefetch_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    timestamps = _coerce_list(row.get("last_run_times_utc"))
    if not timestamps and row.get("last_run_time_utc"):
        timestamps = [row["last_run_time_utc"]]
    events = []
    for index, timestamp in enumerate(timestamps, start=1):
        event = _base(
            row,
            "prefetch_last_run",
            timestamp,
            row.get("executable_name") or row.get("prefetch_name"),
            {
                "run_count": row.get("run_count"),
                "prefetch_name": row.get("prefetch_name"),
                "prefetch_hash": row.get("prefetch_hash"),
                "timestamp_index": index,
                "timestamp_count": len(timestamps),
                "pf_created": row.get("pf_created"),
                "pf_modified": row.get("pf_modified"),
                "pf_accessed": row.get("pf_accessed"),
            },
        )
        if event:
            events.append(event)
    return events


def _registry_artifact_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    timestamp = row.get("event_time_utc")
    if not timestamp:
        return []
    artifact = row.get("artifact") or "registry"
    description = row.get("display_name") or row.get("value_name") or row.get("value_data") or row.get("key_path")
    event = _base(
        row,
        f"registry_{artifact}",
        timestamp,
        description,
        {
            "artifact": artifact,
            "category": row.get("category"),
            "hive_type": row.get("hive_type"),
            "user_profile": row.get("user_profile"),
            "user_sid": row.get("user_sid"),
            "key_path": row.get("key_path"),
            "value_name": row.get("value_name"),
            "value_data": row.get("value_data"),
            "normalized_path": row.get("normalized_path"),
            "notes": row.get("notes"),
        },
    )
    return [event] if event else []


def _shortcut_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    event_type = "lnk_timestamp" if row.get("artifact_type") == "lnk" else "jumplist_timestamp"
    events = []
    for field in ("target_created", "target_modified", "target_accessed"):
        event = _base(
            row,
            event_type,
            row.get(field),
            row.get("file_location") or row.get("file_name") or row.get("artifact_name"),
            {"timestamp_field": field},
        )
        if event:
            events.append(event)
    created = parse_timestamp(row.get("target_created"))
    modified = parse_timestamp(row.get("target_modified"))
    if created is not None and modified is not None and created > modified:
        event = _base(
            row,
            "copied_file_indicator",
            row.get("target_created"),
            row.get("file_location") or row.get("file_name") or row.get("artifact_name"),
            {
                "classification": "copied_file",
                "reason": "target creation time is after target modification time",
                "target_created": row.get("target_created"),
                "target_modified": row.get("target_modified"),
            },
        )
        if event:
            events.append(event)
    return events


def _evtx_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    event = _base(
        row,
        "windows_event_log",
        row.get("time_created"),
        row.get("map_description") or row.get("provider") or row.get("event_id"),
        {
            "event_id": row.get("event_id"),
            "level": row.get("level"),
            "provider": row.get("provider"),
            "channel": row.get("channel"),
            "computer": row.get("computer"),
            "user_name": row.get("user_name"),
            "remote_host": row.get("remote_host"),
            "payload_data1": row.get("payload_data1"),
            "payload_data2": row.get("payload_data2"),
            "payload_data3": row.get("payload_data3"),
        },
    )
    return [event] if event else []


def _sam_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    events = []
    for field, event_type in (
        ("last_login_utc", "sam_last_login"),
        ("password_last_set_utc", "sam_password_last_set"),
        ("last_bad_password_utc", "sam_last_bad_password"),
    ):
        event = _base(
            row,
            event_type,
            row.get(field),
            row.get("username"),
            {"username": row.get("username"), "rid": row.get("rid"), "timestamp_field": field},
        )
        if event:
            events.append(event)
    return events


def _recycle_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    event = _base(
        row,
        "recycle_deleted",
        row.get("deletion_time_utc"),
        row.get("original_path") or row.get("display_name") or row.get("top_level_name"),
        {
            "recycle_format": row.get("recycle_format"),
            "top_level_name": row.get("top_level_name"),
            "original_path": row.get("original_path"),
            "recycled_path": row.get("recycled_path"),
        },
    )
    return [event] if event else []


def _firefox_history_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    event = _base(
        row,
        "firefox_visit",
        row.get("visit_time_utc"),
        row.get("title") or row.get("url"),
        {
            "url": row.get("url"),
            "title": row.get("title"),
            "profile_path": row.get("profile_path"),
            "visit_type": row.get("visit_type"),
        },
    )
    return [event] if event else []


def _browser_history_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    event = _base(
        row,
        "browser_visit",
        row.get("visit_time_utc"),
        row.get("title") or row.get("url"),
        {
            "browser": row.get("browser"),
            "url": row.get("url"),
            "title": row.get("title"),
            "visit_count": row.get("visit_count"),
            "typed_count": row.get("typed_count"),
            "profile_path": row.get("profile_path"),
        },
    )
    return [event] if event else []


def _browser_download_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for field, event_type in (
        ("start_time_utc", "browser_download_started"),
        ("end_time_utc", "browser_download_completed"),
    ):
        event = _base(
            row,
            event_type,
            row.get(field),
            row.get("target_path") or row.get("tab_url"),
            {
                "browser": row.get("browser"),
                "timestamp_field": field,
                "target_path": row.get("target_path"),
                "tab_url": row.get("tab_url"),
                "site_url": row.get("site_url"),
                "received_bytes": row.get("received_bytes"),
                "total_bytes": row.get("total_bytes"),
                "state": row.get("state"),
                "profile_path": row.get("profile_path"),
            },
        )
        if event:
            events.append(event)
    return events


def _browser_cache_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    event = _base(
        row,
        "browser_cache_file_modified",
        row.get("cache_file_modified_utc"),
        row.get("url") or row.get("cache_file"),
        {
            "browser": row.get("browser"),
            "profile_path": row.get("profile_path"),
            "cache_type": row.get("cache_type"),
            "url": row.get("url"),
            "host": row.get("host"),
            "cache_file": row.get("cache_file"),
            "cache_file_size": row.get("cache_file_size"),
        },
    )
    return [event] if event else []


def _package_cache_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    event = _base(
        row,
        "package_cache_response",
        row.get("response_date_utc"),
        row.get("request_url") or row.get("body_file_name"),
        {
            "application_package": row.get("application_package"),
            "user_profile": row.get("user_profile"),
            "cache_name": row.get("cache_name"),
            "request_url": row.get("request_url"),
            "host": row.get("host"),
            "response_status": row.get("response_status"),
            "content_type": row.get("content_type"),
            "body_sha256": row.get("body_sha256"),
            "body_encrypted": row.get("body_encrypted"),
            "encryption_version": row.get("encryption_version"),
            "decoded_state": row.get("decoded_state"),
        },
    )
    return [event] if event else []


def _package_artifact_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    event = _base(
        row,
        "package_artifact_activity",
        row.get("event_time_utc") or row.get("modified_utc"),
        row.get("title") or row.get("artifact_value") or row.get("url") or row.get("file_name"),
        {
            "record_type": row.get("record_type"),
            "source_name": row.get("source_name"),
            "application_package": row.get("application_package"),
            "user_profile": row.get("user_profile"),
            "source_path": row.get("source_path"),
            "url": row.get("url"),
            "host": row.get("host"),
        },
    )
    return [event] if event else []


def _telemetry_artifact_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    artifact_group = row.get("artifact_group") or "telemetry"
    record_type = row.get("record_type") or "artifact"
    description = (
        row.get("title")
        or row.get("value_data")
        or row.get("artifact_text")
        or row.get("url")
        or row.get("path")
        or row.get("file_name")
        or row.get("source_name")
    )
    event = _base(
        row,
        f"{artifact_group}_{record_type}",
        row.get("event_time_utc") or row.get("modified_utc"),
        description,
        {
            "artifact_group": artifact_group,
            "record_type": record_type,
            "user_profile": row.get("user_profile"),
            "application": row.get("application"),
            "source_path": row.get("source_path"),
            "source_name": row.get("source_name"),
            "identifier": row.get("identifier"),
            "path": row.get("path"),
            "url": row.get("url"),
            "host": row.get("host"),
            "value_name": row.get("value_name"),
            "value_data": row.get("value_data"),
            "sha256_first_mb": row.get("sha256_first_mb"),
            "error": row.get("error"),
        },
    )
    return [event] if event else []


def _windows_activity_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for field, event_type in (
        ("start_time_utc", "windows_activity_started"),
        ("end_time_utc", "windows_activity_ended"),
        ("last_modified_utc", "windows_activity_modified"),
    ):
        event = _base(
            row,
            event_type,
            row.get(field),
            row.get("app_display_name") or row.get("app_id") or row.get("activity_id"),
            {
                "timestamp_field": field,
                "user_profile": row.get("user_profile"),
                "source_table": row.get("source_table"),
                "activity_id": row.get("activity_id"),
                "app_id": row.get("app_id"),
                "app_display_name": row.get("app_display_name"),
                "activity_type": row.get("activity_type"),
                "display_text": row.get("display_text"),
                "file_name": row.get("file_name"),
                "content_uri": row.get("content_uri"),
                "activation_uri": row.get("activation_uri"),
                "fallback_uri": row.get("fallback_uri"),
                "platform_device_id": row.get("platform_device_id"),
                "payload_json": row.get("payload_json"),
            },
        )
        if event:
            events.append(event)
    return events


def _webcache_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for field, event_type in (
        ("created_utc", "webcache_created"),
        ("accessed_utc", "webcache_accessed"),
        ("modified_utc", "webcache_modified"),
        ("synced_utc", "webcache_synced"),
        ("expires_utc", "webcache_expires"),
    ):
        event = _base(
            row,
            event_type,
            row.get(field),
            row.get("url") or row.get("cache_file") or row.get("file_name") or row.get("host"),
            {
                "timestamp_field": field,
                "url": row.get("url"),
                "host": row.get("host"),
                "user_name": row.get("user_name"),
                "application": row.get("application"),
                "application_package": row.get("application_package"),
                "attribution_method": row.get("attribution_method"),
                "container_name": row.get("container_name"),
                "source_table": row.get("source_table"),
                "cache_file": row.get("cache_file"),
                "content_type": row.get("content_type"),
                "http_status": row.get("http_status"),
            },
        )
        if event:
            events.append(event)
    return events


def _webcache_file_events(row: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for field, event_type in (
        ("created_utc", "webcache_file_created"),
        ("accessed_utc", "webcache_file_accessed"),
        ("modified_utc", "webcache_file_modified"),
        ("synced_utc", "webcache_file_synced"),
        ("expires_utc", "webcache_file_expires"),
    ):
        event = _base(
            row,
            event_type,
            row.get(field),
            row.get("local_path") or row.get("url"),
            {
                "timestamp_field": field,
                "url": row.get("url"),
                "local_path": row.get("local_path"),
                "normalized_path": row.get("normalized_path"),
                "user_name": row.get("user_name"),
                "application": row.get("application"),
                "application_package": row.get("application_package"),
                "attribution_method": row.get("attribution_method"),
                "container_name": row.get("container_name"),
                "source_table": row.get("source_table"),
                "source_webcache_entry_id": row.get("source_webcache_entry_id"),
            },
        )
        if event:
            events.append(event)
    return events


def _coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return [value]
        return parsed if isinstance(parsed, list) else [parsed]
    return [value]
