from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .db import Database


def rebuild_artifact_correlations(db: Database, *, case_id: str, image_id: str) -> int:
    rows: list[dict[str, Any]] = []
    rows.extend(_notification_to_windows_activity(db, case_id, image_id))
    rows.extend(_notification_to_messaging(db, case_id, image_id))
    rows.extend(_cloud_to_onedrive_items(db, case_id, image_id))
    rows.extend(_google_cache_to_cloud_rows(db, case_id, image_id))
    rows = _dedupe(rows)
    db.replace_artifact_correlations(case_id=case_id, image_id=image_id, rows=rows)
    return len(rows)


def _notification_to_windows_activity(db: Database, case_id: str, image_id: str) -> list[dict[str, Any]]:
    telemetry = _rows(
        db,
        """
        SELECT id, case_id, computer_id, image_id, tool_name, application,
               event_time_utc, title, artifact_text
        FROM telemetry_artifacts
        WHERE case_id = ? AND image_id = ? AND artifact_group = 'notifications'
          AND application <> '' AND event_time_utc <> ''
        """,
        (case_id, image_id),
    )
    activities = _rows(
        db,
        """
        SELECT id, case_id, computer_id, image_id, tool_name, app_id, app_display_name,
               start_time_utc, end_time_utc, last_modified_utc, display_text
        FROM windows_activities
        WHERE case_id = ? AND image_id = ?
          AND (app_id <> '' OR app_display_name <> '')
        """,
        (case_id, image_id),
    )
    by_app: dict[str, list[dict[str, Any]]] = {}
    for activity in activities:
        for key in _app_keys(activity.get("app_id"), activity.get("app_display_name")):
            by_app.setdefault(key, []).append(activity)
    correlations: list[dict[str, Any]] = []
    for item in telemetry:
        timestamp = _parse_time(item.get("event_time_utc"))
        if timestamp is None:
            continue
        for key in _app_keys(item.get("application")):
            for activity in by_app.get(key, []):
                activity_time = _parse_time(
                    activity.get("start_time_utc")
                    or activity.get("last_modified_utc")
                    or activity.get("end_time_utc")
                )
                if activity_time is None:
                    continue
                delta = abs((timestamp - activity_time).total_seconds())
                if delta <= 300:
                    correlations.append(
                        _correlation(
                            left=item,
                            left_table="telemetry_artifacts",
                            right=activity,
                            right_table="windows_activities",
                            correlation_type="notification_windows_activity_time_app",
                            key=key,
                            confidence="high" if delta <= 60 else "medium",
                            summary=f"Notification and Windows activity share app identity within {int(delta)} seconds",
                            details={"delta_seconds": delta, "notification_title": item.get("title")},
                        )
                    )
    return correlations


def _notification_to_messaging(db: Database, case_id: str, image_id: str) -> list[dict[str, Any]]:
    telemetry = _rows(
        db,
        """
        SELECT id, case_id, computer_id, image_id, tool_name, application,
               event_time_utc, title, artifact_text
        FROM telemetry_artifacts
        WHERE case_id = ? AND image_id = ? AND artifact_group = 'notifications'
          AND record_type = 'notifications_notification'
          AND event_time_utc <> '' AND artifact_text <> ''
        """,
        (case_id, image_id),
    )
    messages = _rows(
        db,
        """
        SELECT id, case_id, computer_id, image_id, tool_name, application,
               timestamp_utc, sender_name, channel_id, message_text
        FROM messaging_messages
        WHERE case_id = ? AND image_id = ? AND message_text <> ''
        """,
        (case_id, image_id),
    )
    correlations = []
    for notification in telemetry:
        notification_time = _parse_time(notification.get("event_time_utc"))
        notification_terms = _terms(notification.get("artifact_text"))
        if notification_time is None or not notification_terms:
            continue
        for message in messages:
            message_time = _parse_time(message.get("timestamp_utc"))
            if message_time is None:
                continue
            delta = abs((notification_time - message_time).total_seconds())
            if delta > 600:
                continue
            overlap = notification_terms.intersection(_terms(message.get("message_text")))
            if len(overlap) < 4:
                continue
            correlations.append(
                _correlation(
                    left=notification,
                    left_table="telemetry_artifacts",
                    right=message,
                    right_table="messaging_messages",
                    correlation_type="notification_message_text_time",
                    key=" ".join(sorted(overlap)[:8]),
                    confidence="high" if delta <= 120 and len(overlap) >= 6 else "medium",
                    summary="Notification text overlaps a messaging row near the same time",
                    details={"delta_seconds": delta, "overlap_terms": sorted(overlap)[:20]},
                )
            )
    return correlations


def _cloud_to_onedrive_items(db: Database, case_id: str, image_id: str) -> list[dict[str, Any]]:
    cloud_rows = _rows(
        db,
        """
        SELECT id, case_id, computer_id, image_id, tool_name, provider,
               artifact_type, user_profile, file_name, event_time_utc
        FROM cloud_sync_artifacts
        WHERE case_id = ? AND image_id = ? AND provider = 'OneDrive' AND file_name <> ''
        """,
        (case_id, image_id),
    )
    onedrive_items = _rows(
        db,
        """
        SELECT id, case_id, computer_id, image_id, tool_name, user_profile,
               account, name, last_change_utc, resource_id
        FROM onedrive_items
        WHERE case_id = ? AND image_id = ? AND name <> ''
        """,
        (case_id, image_id),
    )
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in onedrive_items:
        by_key.setdefault((_norm(item.get("user_profile")), _norm(item.get("name"))), []).append(item)
    rows = []
    for cloud in cloud_rows:
        for item in by_key.get((_norm(cloud.get("user_profile")), _norm(cloud.get("file_name"))), []):
            rows.append(
                _correlation(
                    left=cloud,
                    left_table="cloud_sync_artifacts",
                    right=item,
                    right_table="onedrive_items",
                    correlation_type="onedrive_name_user",
                    key=f"{cloud.get('user_profile')}:{cloud.get('file_name')}",
                    confidence="medium",
                    summary="OneDrive cloud row and OneDrive item share user and item name",
                    details={"cloud_artifact_type": cloud.get("artifact_type"), "account": item.get("account")},
                )
            )
    return rows


def _google_cache_to_cloud_rows(db: Database, case_id: str, image_id: str) -> list[dict[str, Any]]:
    cache_rows = _rows(
        db,
        """
        SELECT id, case_id, computer_id, image_id, tool_name, virtual_path,
               file_name, cache_id, windows_cache_path, mapping_method
        FROM google_drive_cache_map
        WHERE case_id = ? AND image_id = ? AND virtual_path <> ''
        """,
        (case_id, image_id),
    )
    cloud_rows = _rows(
        db,
        """
        SELECT id, case_id, computer_id, image_id, tool_name, provider,
               cloud_path, local_path, file_name, stable_id
        FROM cloud_sync_artifacts
        WHERE case_id = ? AND image_id = ? AND provider = 'Google Drive'
          AND (cloud_path <> '' OR file_name <> '')
        """,
        (case_id, image_id),
    )
    by_path: dict[str, list[dict[str, Any]]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for row in cloud_rows:
        if row.get("cloud_path"):
            by_path.setdefault(_norm_path(row["cloud_path"]), []).append(row)
        if row.get("file_name"):
            by_name.setdefault(_norm(row["file_name"]), []).append(row)
    correlations = []
    for cache in cache_rows:
        matches = by_path.get(_norm_path(cache.get("virtual_path")), [])
        correlation_type = "google_drive_virtual_path"
        confidence = "high"
        if not matches:
            matches = by_name.get(_norm(cache.get("file_name")), [])
            correlation_type = "google_drive_file_name"
            confidence = "low" if len(matches) > 1 else "medium"
        for match in matches:
            correlations.append(
                _correlation(
                    left=cache,
                    left_table="google_drive_cache_map",
                    right=match,
                    right_table="cloud_sync_artifacts",
                    correlation_type=correlation_type,
                    key=cache.get("virtual_path") or cache.get("file_name"),
                    confidence=confidence,
                    summary="Google Drive cache mapping connects to cloud sync metadata",
                    details={"cache_id": cache.get("cache_id"), "mapping_method": cache.get("mapping_method")},
                )
            )
    return correlations


def _correlation(
    *,
    left: dict[str, Any],
    left_table: str,
    right: dict[str, Any],
    right_table: str,
    correlation_type: str,
    key: str | None,
    confidence: str,
    summary: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": left["case_id"],
        "computer_id": left["computer_id"],
        "image_id": left["image_id"],
        "left_source_tool": left.get("tool_name"),
        "left_source_table": left_table,
        "left_source_row_id": left["id"],
        "right_source_tool": right.get("tool_name"),
        "right_source_table": right_table,
        "right_source_row_id": right["id"],
        "correlation_type": correlation_type,
        "correlation_key": key,
        "confidence": confidence,
        "summary": summary,
        "details": details,
    }


def _rows(db: Database, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in db.conn.execute(sql, params).fetchall()]


def _app_keys(*values: object) -> set[str]:
    keys: set[str] = set()
    for value in values:
        text = _norm(value)
        if not text:
            continue
        keys.add(text)
        if "!" in text:
            keys.add(text.split("!", 1)[0])
        if "_" in text:
            keys.add(text.split("_", 1)[0])
    return keys


def _parse_time(value: object) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _terms(value: object) -> set[str]:
    if not value:
        return set()
    return {
        term.lower()
        for term in re.findall(r"[A-Za-z0-9_#-]{4,}", str(value))
        if term.lower() not in {"http", "https", "launch", "title", "message", "team"}
    }


def _norm(value: object) -> str:
    return str(value or "").strip().lower()


def _norm_path(value: object) -> str:
    return re.sub(r"/+", "/", str(value or "").replace("\\", "/").strip().lower()).strip("/")


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for row in rows:
        key = (
            row["left_source_table"],
            row["left_source_row_id"],
            row["right_source_table"],
            row["right_source_row_id"],
            row["correlation_type"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
