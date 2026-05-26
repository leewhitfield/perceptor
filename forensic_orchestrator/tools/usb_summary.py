from __future__ import annotations

import uuid
import re
from collections import defaultdict
from typing import Any

from forensic_orchestrator.db import Database
from forensic_orchestrator.analytics_query import query_rows


STORAGE_TYPES = {
    "usb_storage",
    "scsi_storage",
    "usb_volume",
    "portable_device_volume",
    "mounted_device",
    "readyboost_device",
    "usb_partition_diagnostic",
    "usb_cdrom",
}
SUPPORTING_TYPES = {"usb_device"}


def rebuild_usb_storage_devices(db: Database, *, case_id: str, image_id: str | None = None) -> int:
    params: list[Any] = [case_id]
    image_filter = ""
    if image_id is not None:
        image_filter = "AND usb_devices.image_id = ?"
        params.append(image_id)
    rows = query_rows(
        db,
        "usb_devices",
        f"""
        SELECT *
        FROM usb_devices
        WHERE case_id = ? {image_filter}
          AND device_type IN ({", ".join("?" for _ in STORAGE_TYPES | SUPPORTING_TYPES)})
          AND COALESCE(serial, instance_id, parent_id_prefix) IS NOT NULL
        """,
        params + sorted(STORAGE_TYPES | SUPPORTING_TYPES),
    )
    serial_aliases = _serial_aliases([dict(row) for row in rows])
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        item = dict(row)
        serial = _summary_serial(item, serial_aliases)
        if not serial:
            continue
        groups[(item["case_id"], item["image_id"], serial)].append(item)

    summaries = []
    for (_, _, serial), items in sorted(groups.items()):
        summary = _summary_for_group(items, serial)
        if _is_storage_summary(summary):
            summaries.append(summary)
    with db.bulk_transaction():
        db.delete_usb_storage_devices(case_id=case_id, image_id=image_id)
        db.insert_usb_storage_devices(summaries)
    return len(summaries)


def rebuild_usb_connection_events(db: Database, *, case_id: str, image_id: str | None = None) -> int:
    params: list[Any] = [case_id]
    image_filter = ""
    if image_id is not None:
        image_filter = "AND usb_devices.image_id = ?"
        params.append(image_id)
    rows = query_rows(
        db,
        "usb_devices",
        f"""
        SELECT *
        FROM usb_devices
        WHERE case_id = ? {image_filter}
          AND COALESCE(serial, instance_id, parent_id_prefix) IS NOT NULL
        """,
        params,
    )

    row_items = [dict(row) for row in rows]
    serial_aliases = _serial_aliases(row_items)
    storage_id_params: list[Any] = [case_id]
    storage_id_filter = ""
    if image_id is not None:
        storage_id_filter = "AND image_id = ?"
        storage_id_params.append(image_id)
    storage_ids = {
        (row["image_id"], row["serial"]): row["id"]
        for row in query_rows(
            db,
            "usb_storage_devices",
            f"SELECT id, image_id, serial FROM usb_storage_devices WHERE case_id = ? {storage_id_filter}",
            storage_id_params,
        )
        if row["serial"]
    }
    events: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in row_items:
        serial = _summary_serial(item, serial_aliases)
        if not serial:
            continue
        item["usb_device_id"] = storage_ids.get((item["image_id"], serial)) or item.get("usb_device_id")
        if not item.get("usb_device_id") and item.get("device_type") not in STORAGE_TYPES:
            continue
        for event in _connection_events_for_row(item, serial):
            key = (
                event["case_id"],
                event["image_id"],
                event["serial"],
                event.get("volume_serial_number"),
                event.get("event_time_utc"),
                event.get("event_type"),
                event.get("event_source"),
                event.get("record_number"),
                event.get("property_name"),
            )
            if key in seen:
                continue
            seen.add(key)
            events.append(event)

    events.sort(key=lambda event: (event["serial"], event["event_time_utc"], event["event_type"]))
    with db.bulk_transaction():
        db.delete_usb_connection_events(case_id=case_id, image_id=image_id)
        db.insert_usb_connection_events(events)
    return len(events)


def _summary_for_group(items: list[dict[str, Any]], serial: str) -> dict[str, Any]:
    first = items[0]
    return {
        "id": str(uuid.uuid4()),
        "case_id": first["case_id"],
        "computer_id": first["computer_id"],
        "image_id": first["image_id"],
        "serial": serial,
        "vendor_id": _join_unique(items, "vendor_id"),
        "product_id": _join_unique(items, "product_id"),
        "vendor": _join_unique(items, "vendor"),
        "product": _join_unique(items, "product"),
        "revision": _join_unique(items, "revision"),
        "friendly_name": _join_unique(items, "friendly_name"),
        "parent_id_prefix": _join_unique(items, "parent_id_prefix"),
        "device_service": _join_unique(items, "device_service"),
        "drive_letter": _join_drive_letters(items),
        "volume_guid": _join_unique(items, "volume_guid"),
        "volume_serial_number": _join_unique(items, "volume_serial_number"),
        "volume_name": _join_volume_names(items),
        "capacity_bytes": _join_unique(items, "capacity_bytes", exclude={"0"}),
        "file_system": _join_unique(items, "file_system"),
        "alternate_scsi_serial": _join_unique(items, "alternate_scsi_serial"),
        "user_profiles": _join_unique(items, "user_profile"),
        "first_install_date_utc": _property_time(items, "0064", prefer_value=True) or _earliest_value(items, "key_last_write_utc"),
        "last_arrival_utc": _property_time(items, "0066", prefer_value=True, latest=True),
        "last_removal_utc": _property_time(items, "0067", prefer_value=True, latest=True),
        "first_volume_serial_event_utc": _event_time(items, require_volume_serial=True),
        "last_partition_event_utc": _event_time(items, latest=True),
        "last_migration_present_utc": _latest_value(items, "last_present_date_utc"),
        "evidence_row_count": len(items),
        "source_artifacts": _join_unique(items, "artifact"),
        "source_device_types": _join_unique(items, "device_type"),
    }


def _connection_events_for_row(item: dict[str, Any], serial: str) -> list[dict[str, Any]]:
    if item.get("artifact") == "partition_diagnostic":
        return _partition_diagnostic_events_for_row(item, serial)
    if item.get("artifact") == "tzworks_usp":
        return _tzworks_usp_events_for_row(item, serial)
    return _registry_property_events_for_row(item, serial)


def _tzworks_usp_events_for_row(item: dict[str, Any], serial: str) -> list[dict[str, Any]]:
    events = []
    first_seen = _clean(item.get("key_last_write_utc"))
    if first_seen:
        events.append(
            _connection_event(
                item,
                serial,
                event_time_utc=first_seen,
                event_type="arrival",
                event_source="tzworks_usp",
                event_id="device_seen",
            )
        )
    last_present = _clean(item.get("last_present_date_utc"))
    if last_present and last_present != first_seen:
        events.append(
            _connection_event(
                item,
                serial,
                event_time_utc=last_present,
                event_type="last_present",
                event_source="tzworks_usp",
                event_id="volume_or_disk_seen",
            )
        )
    return events


def _partition_diagnostic_events_for_row(item: dict[str, Any], serial: str) -> list[dict[str, Any]]:
    timestamp = _clean(item.get("key_last_write_utc"))
    if not timestamp:
        return []
    capacity = _clean(item.get("capacity_bytes"))
    event_type = "removal" if capacity == "0" else "arrival"
    return [
        _connection_event(
            item,
            serial,
            event_time_utc=timestamp,
            event_type=event_type,
            event_source="partition_diagnostic",
            event_id=_partition_event_id(item.get("property_name")),
        )
    ]


def _registry_property_events_for_row(item: dict[str, Any], serial: str) -> list[dict[str, Any]]:
    if item.get("artifact") == "usb_device_migration" and _clean(item.get("last_present_date_utc")):
        return [
            _connection_event(
                item,
                serial,
                event_time_utc=_clean(item.get("last_present_date_utc")) or "",
                event_type="last_present",
                event_source="usb_device_migration",
                event_id="LastPresentDate",
            )
        ]
    key_path = (_clean(item.get("key_path")) or "").replace("\\", "/")
    event_types = {
        "0064": "first_connected",
        "0066": "arrival",
        "0067": "removal",
    }
    for suffix, event_type in event_types.items():
        if not key_path.endswith(f"/{suffix}"):
            continue
        timestamp = _clean(item.get("property_value")) or _clean(item.get("key_last_write_utc"))
        if not timestamp:
            return []
        return [
            _connection_event(
                item,
                serial,
                event_time_utc=timestamp,
                event_type=event_type,
                event_source=_clean(item.get("artifact")),
                event_id=suffix,
            )
        ]
    return []


def _connection_event(
    item: dict[str, Any],
    serial: str,
    *,
    event_time_utc: str,
    event_type: str,
    event_source: str | None,
    event_id: str | None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": item["case_id"],
        "computer_id": item["computer_id"],
        "image_id": item["image_id"],
        "usb_device_id": item.get("usb_device_id"),
        "serial": serial,
        "volume_serial_number": _clean(item.get("volume_serial_number")),
        "volume_guid": _clean(item.get("volume_guid")),
        "drive_letter": _clean(item.get("drive_letter")),
        "event_time_utc": _normalize_utc_timestamp(event_time_utc),
        "event_type": event_type,
        "event_source": event_source,
        "event_id": event_id,
        "record_number": _clean(item.get("row_number")),
        "source_path": _clean(item.get("source_path")),
        "key_path": _clean(item.get("key_path")),
        "property_name": _clean(item.get("property_name")),
        "property_value": _clean(item.get("property_value")),
        "capacity_bytes": _clean(item.get("capacity_bytes")),
    }


def _partition_event_id(value: Any) -> str | None:
    text = _clean(value)
    if not text:
        return None
    parts = text.split(":")
    return parts[1] if len(parts) > 2 and parts[1].isdigit() else None


def _normalize_utc_timestamp(value: Any) -> str | None:
    text = _clean(value)
    if not text:
        return None
    if len(text) > 10 and text[10] == " ":
        text = f"{text[:10]}T{text[11:]}"
    if text.endswith("+00:00"):
        text = f"{text[:-6]}Z"
    tail = text[10:]
    if not text.endswith("Z") and "+" not in tail and "-" not in tail:
        text = f"{text}Z"
    return text


def _is_storage_summary(summary: dict[str, Any]) -> bool:
    artifacts = set((summary.get("source_artifacts") or "").split(", "))
    device_types = set((summary.get("source_device_types") or "").split(", "))
    if artifacts & {"mounted_devices", "partition_diagnostic", "usb_volume_history"}:
        return True
    if artifacts & {"tzworks_usp"} and device_types & STORAGE_TYPES:
        return True
    service = (summary.get("device_service") or "").lower()
    if ("disk" in service or "usbstor" in service) and (
        summary.get("vendor_id") or summary.get("product_id") or artifacts != {"usb_device_history"}
    ):
        return True
    if summary.get("volume_serial_number") or summary.get("capacity_bytes") or summary.get("drive_letter"):
        return True
    return False


def _join_unique(items: list[dict[str, Any]], key: str, *, exclude: set[str] | None = None) -> str | None:
    excluded = exclude or set()
    seen = []
    seen_normalized = set()
    for item in items:
        value = _clean(item.get(key))
        if not value or value in excluded:
            continue
        normalized = value.casefold()
        if normalized not in seen_normalized:
            seen.append(value)
            seen_normalized.add(normalized)
    return ", ".join(seen) if seen else None


def _join_drive_letters(items: list[dict[str, Any]]) -> str | None:
    seen = []
    seen_normalized = set()
    for item in items:
        for value in (item.get("drive_letter"), item.get("volume_name"), item.get("property_value")):
            drive = _drive_letter_from_text(value)
            if not drive or drive in seen_normalized:
                continue
            seen.append(drive)
            seen_normalized.add(drive)
    return ", ".join(seen) if seen else None


def _join_volume_names(items: list[dict[str, Any]]) -> str | None:
    seen = []
    seen_normalized = set()
    for item in items:
        value = _clean(item.get("volume_name"))
        if not value or _looks_like_drive_metadata(value):
            continue
        normalized = value.casefold()
        if normalized not in seen_normalized:
            seen.append(value)
            seen_normalized.add(normalized)
    return ", ".join(seen) if seen else None


def _looks_like_drive_metadata(value: str) -> bool:
    return bool(re.match(r"^[A-Z]=", value.strip(), re.IGNORECASE))


def _drive_letter_from_text(value: Any) -> str | None:
    text = _clean(value)
    if not text:
        return None
    match = re.search(r"(?:^|\b)([A-Z])(?::|=)", text, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).upper() + ":"


def _latest_value(items: list[dict[str, Any]], key: str) -> str | None:
    values = [_clean(item.get(key)) for item in items]
    values = [value for value in values if value]
    return max(values) if values else None


def _earliest_value(items: list[dict[str, Any]], key: str) -> str | None:
    values = [_clean(item.get(key)) for item in items]
    values = [value for value in values if value]
    return min(values) if values else None


def _property_time(
    items: list[dict[str, Any]],
    property_suffix: str,
    *,
    prefer_value: bool = False,
    latest: bool = False,
) -> str | None:
    matches = []
    for item in items:
        key_path = (_clean(item.get("key_path")) or "").replace("\\", "/")
        if not key_path.endswith(f"/{property_suffix}"):
            continue
        value = _clean(item.get("property_value")) if prefer_value else None
        matches.append(value or _clean(item.get("key_last_write_utc")))
    matches = [item for item in matches if item]
    if not matches:
        return None
    return max(matches) if latest else min(matches)


def _event_time(
    items: list[dict[str, Any]],
    *,
    require_volume_serial: bool = False,
    latest: bool = False,
) -> str | None:
    matches = []
    for item in items:
        if item.get("artifact") != "partition_diagnostic":
            continue
        if require_volume_serial and not item.get("volume_serial_number"):
            continue
        value = _clean(item.get("key_last_write_utc"))
        if value:
            matches.append(value)
    if not matches:
        return None
    return max(matches) if latest else min(matches)


def _logical_serial(value: Any) -> str | None:
    serial = _clean(value)
    if not serial:
        return None
    return serial[:-2] if serial.endswith("&0") else serial


def _serial_aliases(items: list[dict[str, Any]]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for item in items:
        serial = _logical_serial(item.get("serial"))
        parent_id_prefix = _clean(item.get("parent_id_prefix"))
        if serial and parent_id_prefix and serial != parent_id_prefix:
            aliases.setdefault(parent_id_prefix, serial)
    return aliases


def _summary_serial(item: dict[str, Any], aliases: dict[str, str]) -> str | None:
    serial = _logical_serial(item.get("serial"))
    if not serial:
        serial = _clean(item.get("instance_id") or item.get("parent_id_prefix"))
    if not serial:
        return None
    return aliases.get(serial, serial)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
