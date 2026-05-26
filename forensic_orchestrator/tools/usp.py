from __future__ import annotations

import uuid
import re
from pathlib import Path
from typing import Any


def normalized_usp_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> dict[str, Any]:
    device_type_raw = _text(row.get("device_type_raw"))
    volume_name, drive_letter = _volume_fields(row.get("volume_name"))
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "source_path": None,
        "artifact": "tzworks_usp",
        "device_type": _device_type(device_type_raw),
        "vendor_id": _text(row.get("vendor_id")),
        "product_id": _text(row.get("product_id")),
        "vendor": _text(row.get("vendor")),
        "product": _text(row.get("product")),
        "revision": _text(row.get("revision")),
        "friendly_name": _text(row.get("device_name")),
        "serial": _text(row.get("serial")),
        "instance_id": _text(row.get("serial")),
        "parent_id_prefix": None,
        "device_service": None,
        "user_profile": _text(row.get("users")),
        "drive_letter": drive_letter,
        "volume_guid": _text(row.get("volume_guid")),
        "volume_serial_number": None,
        "volume_name": volume_name,
        "capacity_bytes": None,
        "alternate_scsi_serial": None,
        "key_path": None,
        "key_last_write_utc": _text(row.get("device_seen_utc")),
        "last_present_date_utc": _text(row.get("volume_device_utc")) or _text(row.get("disk_device_utc")),
        "property_name": device_type_raw,
        "property_value": _text(row.get("raw_record")),
        "value_data_hex": None,
    }


def _device_type(value: str | None) -> str:
    lowered = (value or "").lower()
    if "disk" in lowered or "usbstor" in lowered:
        return "usb_storage"
    if "cdrom" in lowered:
        return "usb_cdrom"
    if "hid" in lowered:
        return "hid_device"
    return "usb"


def _volume_fields(value: Any) -> tuple[str | None, str | None]:
    text = _text(value)
    if not text:
        return None, None
    drive = _drive_letter(text)
    if drive:
        drive_prefix = drive.rstrip(":")
        return None if text.startswith((f"{drive}=", f"{drive_prefix}=")) else text, drive
    return text, None


def _drive_letter(value: str) -> str | None:
    match = re.search(r"(?:^|\b)([A-Z])(?::|=)", value, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).upper() + ":"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None
