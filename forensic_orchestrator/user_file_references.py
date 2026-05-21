from __future__ import annotations

import json
import re
import uuid
from pathlib import PureWindowsPath
from typing import Any, Iterable

from forensic_orchestrator.activity_contract import activity_contract_row
from forensic_orchestrator.db import Database, utc_now


PATH_RE = re.compile(
    r"(?i)(?:[a-z]:\\|\\{1,2}Device\\HarddiskVolume\d+\\|\\\\)[^<>:\"|?\r\n]+"
)
USER_RE = re.compile(r"(?i)(?:\\{1,2}Device\\HarddiskVolume\d+\\|[a-z]:\\)?Users\\([^\\]+)\\(.+)")

USER_CONTENT_DIRS = {
    "desktop",
    "documents",
    "downloads",
    "pictures",
    "videos",
    "music",
    "onedrive",
    "icloudphotos",
}

USER_CONTENT_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt",
    ".rtf", ".csv", ".zip", ".7z", ".rar", ".jpg", ".jpeg", ".png",
    ".gif", ".bmp", ".mp4", ".mov", ".avi", ".lnk",
}


def rebuild_user_controlled_file_references(
    db: Database,
    *,
    case_id: str,
    image_id: str | None = None,
) -> int:
    rows: list[dict[str, Any]] = []
    rows.extend(_defender_rows(db, case_id=case_id, image_id=image_id))
    rows.extend(_wer_rows(db, case_id=case_id, image_id=image_id))
    rows.extend(_etl_rows(db, case_id=case_id, image_id=image_id))
    db.replace_user_controlled_file_references(case_id=case_id, image_id=image_id, rows=rows)
    return len(rows)


def _defender_rows(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where, params = _case_image_where("windows_defender_events", case_id, image_id)
    source_rows = db.conn.execute(
        f"""
        SELECT * FROM windows_defender_events
        WHERE {where}
          AND (
            COALESCE(path, '') LIKE '%Users%'
            OR COALESCE(message, '') LIKE '%Users%'
            OR COALESCE(resource, '') LIKE '%Users%'
          )
        """,
        params,
    ).fetchall()
    rows: list[dict[str, Any]] = []
    for row in source_rows:
        text = "\n".join(str(row[key] or "") for key in ("path", "resource", "message"))
        for path in _paths_from_text(text):
            interpreted = interpret_user_path(path)
            if interpreted is None:
                continue
            interpreted = _resolve_cloud_transfer(db, row["case_id"], row["image_id"], interpreted)
            rows.append(
                _row(
                    case_id=row["case_id"],
                    computer_id=row["computer_id"],
                    image_id=row["image_id"],
                    source_tool=row["tool_name"],
                    source_table="windows_defender_events",
                    source_row_id=row["id"],
                    source_row_number=row["row_number"],
                    event_time_utc=row["event_time_utc"],
                    raw_path=path,
                    context=row["message"],
                    details={
                        "defender_event_type": row["event_type"],
                        "artifact_type": row["artifact_type"],
                        "component": row["component"],
                        "activity_contract": activity_contract_row(
                            source_table="windows_defender_events",
                            source_row_id=row["id"],
                            source_tool=row["tool_name"],
                            event_time_utc=row["event_time_utc"],
                            timestamp_meaning="defender_event_time",
                            path=interpreted["display_path"] or interpreted["normalized_path"],
                            file_name=interpreted["file_name"],
                            user_profile=interpreted["owning_user"],
                            artifact_category="file_reference",
                            interpretation_note=interpreted["artifact_meaning"],
                        ),
                    },
                    interpreted=interpreted,
                )
            )
    return _dedupe(rows)


def _wer_rows(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where, params = _case_image_where("windows_error_reports", case_id, image_id)
    source_rows = db.conn.execute(f"SELECT * FROM windows_error_reports WHERE {where}", params).fetchall()
    rows: list[dict[str, Any]] = []
    for row in source_rows:
        text = "\n".join(
            str(row[key] or "")
            for key in ("ui_path", "loaded_modules_json", "raw_json")
        )
        for path in _paths_from_text(text):
            interpreted = interpret_user_path(path)
            if interpreted is None:
                continue
            interpreted = _resolve_cloud_transfer(db, row["case_id"], row["image_id"], interpreted)
            rows.append(
                _row(
                    case_id=row["case_id"],
                    computer_id=row["computer_id"],
                    image_id=row["image_id"],
                    source_tool=row["tool_name"],
                    source_table="windows_error_reports",
                    source_row_id=row["id"],
                    source_row_number=row["row_number"],
                    event_time_utc=row["event_time_utc"],
                    raw_path=path,
                    context=f"{row['event_type']} {row['app_name'] or ''}".strip(),
                    details={
                        "wer_event_type": row["event_type"],
                        "app_name": row["app_name"],
                        "activity_contract": activity_contract_row(
                            source_table="windows_error_reports",
                            source_row_id=row["id"],
                            source_tool=row["tool_name"],
                            event_time_utc=row["event_time_utc"],
                            timestamp_meaning="wer_event_time",
                            path=interpreted["display_path"] or interpreted["normalized_path"],
                            file_name=interpreted["file_name"],
                            user_profile=interpreted["owning_user"],
                            artifact_category="file_reference",
                            interpretation_note=interpreted["artifact_meaning"],
                        ),
                    },
                    interpreted=interpreted,
                )
            )
    return _dedupe(rows)


def _etl_rows(db: Database, *, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    where, params = _case_image_where("etl_events", case_id, image_id)
    source_rows = db.conn.execute(
        f"""
        SELECT * FROM etl_events
        WHERE {where}
          AND (
            COALESCE(image_name, '') LIKE '%Users%'
            OR COALESCE(command_line, '') LIKE '%Users%'
            OR COALESCE(payload_strings_json, '') LIKE '%Users%'
          )
        """,
        params,
    ).fetchall()
    rows: list[dict[str, Any]] = []
    for row in source_rows:
        text = "\n".join(str(row[key] or "") for key in ("image_name", "command_line", "payload_strings_json"))
        for path in _paths_from_text(text):
            interpreted = interpret_user_path(path)
            if interpreted is None:
                continue
            interpreted = _resolve_cloud_transfer(db, row["case_id"], row["image_id"], interpreted)
            rows.append(
                _row(
                    case_id=row["case_id"],
                    computer_id=row["computer_id"],
                    image_id=row["image_id"],
                    source_tool=row["tool_name"],
                    source_table="etl_events",
                    source_row_id=row["id"],
                    source_row_number=row["row_number"],
                    event_time_utc=row["timestamp_utc"],
                    raw_path=path,
                    context=row["command_line"] or row["image_name"],
                    details={
                        "provider_label": row["provider_label"],
                        "event_category": row["event_category"],
                        "event_name": row["event_name"],
                        "activity_contract": activity_contract_row(
                            source_table="etl_events",
                            source_row_id=row["id"],
                            source_tool=row["tool_name"],
                            event_time_utc=row["timestamp_utc"],
                            timestamp_meaning="etl_event_time",
                            path=interpreted["display_path"] or interpreted["normalized_path"],
                            file_name=interpreted["file_name"],
                            user_profile=interpreted["owning_user"],
                            artifact_category="file_reference",
                            interpretation_note=interpreted["artifact_meaning"],
                        ),
                    },
                    interpreted=interpreted,
                )
            )
    return _dedupe(rows)


def interpret_user_path(raw_path: str) -> dict[str, str] | None:
    normalized = _normalize_path(raw_path)
    match = USER_RE.search(normalized)
    if not match:
        return None
    user = match.group(1)
    remainder = match.group(2).strip("\\")
    parts = [part for part in remainder.split("\\") if part]
    if not parts:
        return None
    lowered_parts = [part.lower() for part in parts]
    lowered = normalized.lower()
    file_name = parts[-1]
    extension = PureWindowsPath(file_name).suffix.lower()
    display_path, volume_device = _display_path(normalized)

    provider = "Local Profile"
    scope = "user_profile"
    meaning = "User profile path observed in artifact"
    basis = "Path contains a Windows user profile segment"
    resolution_status = "not_applicable"
    resolution_basis = ""

    if ".tmp.drivedownload" in lowered or extension in {".driveupload", ".drivedownload"}:
        provider = "Google Drive"
        scope = "user_cloud_transfer_temp"
        meaning = "Google Drive temporary transfer artifact; original filename unresolved"
        basis = "Path contains .tmp.drivedownload or Google Drive transfer extension"
        resolution_status = "unresolved_transfer_temp"
        resolution_basis = "No Google Drive cache mapping has been applied"
    elif "appdata\\local\\microsoft\\onedrive\\" in lowered:
        provider = "OneDrive"
        scope = "cloud_app_artifact"
        meaning = "OneDrive application log or executable path, not direct user content"
        basis = "Path is inside AppData\\Local\\Microsoft\\OneDrive"
    elif "\\onedrive\\" in lowered:
        provider = "OneDrive"
        scope = "user_cloud_content"
        meaning = "Direct user-controlled OneDrive path"
        basis = "Path is under the user's OneDrive folder"
    elif "\\drivefs\\" in lowered or "\\google\\drive" in lowered:
        provider = "Google Drive"
        scope = "user_cloud_content"
        meaning = "Google Drive local filesystem/cache path"
        basis = "Path contains Google Drive or DriveFS markers"
    elif "\\icloudphotos\\" in lowered:
        provider = "iCloud"
        scope = "user_cloud_content"
        meaning = "iCloud Photos user content path"
        basis = "Path contains iCloudPhotos under a user profile"
    elif lowered_parts[0] == "appdata":
        if lowered.startswith(("\\device", "c:")) and "\\appdata\\local\\temp\\" in lowered:
            scope = "user_temp"
            meaning = "User temporary file path"
            basis = "Path is inside AppData\\Local\\Temp"
        else:
            scope = "user_appdata"
            meaning = "Application data under user profile"
            basis = "Path is inside AppData"
    elif lowered_parts[0] in USER_CONTENT_DIRS or extension in USER_CONTENT_EXTS:
        scope = "user_content"
        meaning = "Likely direct user-controlled file or folder path"
        basis = "Path is in a common user content folder or has a user-content extension"

    if scope in {"user_profile", "user_appdata"} and extension not in USER_CONTENT_EXTS:
        return None

    return {
        "normalized_path": normalized,
        "display_path": display_path,
        "volume_device": volume_device,
        "owning_user": user,
        "file_name": file_name,
        "extension": extension,
        "path_scope": scope,
        "storage_provider": provider,
        "artifact_meaning": meaning,
        "confidence_basis": basis,
        "resolved_provider_path": "",
        "resolved_file_name": "",
        "resolved_cache_path": "",
        "resolution_status": resolution_status,
        "resolution_basis": resolution_basis,
    }


def _resolve_cloud_transfer(
    db: Database,
    case_id: str,
    image_id: str,
    interpreted: dict[str, str],
) -> dict[str, str]:
    if interpreted.get("path_scope") != "user_cloud_transfer_temp":
        return interpreted
    transfer_id = PureWindowsPath(interpreted.get("file_name") or "").stem
    if not transfer_id:
        return interpreted
    row = db.conn.execute(
        """
        SELECT virtual_path, file_name, cache_path, windows_cache_path, cache_id, mapping_method, evidence_basis
        FROM google_drive_cache_map
        WHERE case_id = ?
          AND image_id = ?
          AND cache_id = ?
        ORDER BY CASE WHEN COALESCE(virtual_path, '') <> '' THEN 0 ELSE 1 END,
                 row_number
        LIMIT 1
        """,
        (case_id, image_id, transfer_id),
    ).fetchone()
    if row is None:
        return interpreted
    interpreted = dict(interpreted)
    interpreted["resolved_provider_path"] = row["virtual_path"] or ""
    interpreted["resolved_file_name"] = row["file_name"] or ""
    interpreted["resolved_cache_path"] = row["windows_cache_path"] or row["cache_path"] or ""
    interpreted["resolution_status"] = "resolved_by_google_drive_cache_id"
    interpreted["resolution_basis"] = (
        f"Transfer temp name stem matched google_drive_cache_map.cache_id={row['cache_id']}"
    )
    if row["virtual_path"] or row["file_name"]:
        interpreted["artifact_meaning"] = "Google Drive temporary transfer artifact resolved to cached Drive item"
    return interpreted


def _paths_from_text(text: str) -> Iterable[str]:
    seen: set[str] = set()
    for match in PATH_RE.finditer(text):
        path = _trim_path(match.group(0))
        if "\\Users\\" not in path and "\\users\\" not in path:
            continue
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        yield path


def _trim_path(path: str) -> str:
    path = path.strip().strip('"').rstrip(" .")
    for marker in (". Process", ") sent successfully", ". status=", ", Status:", "\\u0000"):
        index = path.lower().find(marker.lower())
        if index > 0:
            path = path[:index]
    return path.rstrip(" .")


def _normalize_path(path: str) -> str:
    path = _trim_path(path).replace("/", "\\")
    path = re.sub(r"(?i)^\\\\\?\\", "", path)
    path = re.sub(r"\\+", r"\\", path)
    return path


def _display_path(path: str) -> tuple[str, str]:
    device_match = re.match(r"(?i)^\\Device\\(HarddiskVolume\d+)\\(.*)$", path)
    if device_match:
        volume = device_match.group(1)
        rest = device_match.group(2)
        return f"{volume}:\\{rest}", volume
    drive_match = re.match(r"(?i)^([a-z]:)\\", path)
    if drive_match:
        return path, drive_match.group(1).upper()
    return path, ""


def _row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    source_tool: str,
    source_table: str,
    source_row_id: str,
    source_row_number: int,
    event_time_utc: str | None,
    raw_path: str,
    context: str | None,
    details: dict[str, Any],
    interpreted: dict[str, str],
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "source_tool": source_tool,
        "source_table": source_table,
        "source_row_id": source_row_id,
        "source_row_number": source_row_number,
        "event_time_utc": event_time_utc,
        "raw_path": raw_path,
        "context": context,
        "details_json": json.dumps(details, sort_keys=True),
        "created_at": utc_now(),
        **interpreted,
    }


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for row in rows:
        key = (row["source_table"], row["source_row_id"], row["normalized_path"].lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _case_image_where(table: str, case_id: str, image_id: str | None) -> tuple[str, list[Any]]:
    where = [f"{table}.case_id = ?"]
    params: list[Any] = [case_id]
    if image_id is not None:
        where.append(f"{table}.image_id = ?")
        params.append(image_id)
    return " AND ".join(where), params
