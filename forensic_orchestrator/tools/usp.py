from __future__ import annotations

import uuid
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
        "drive_letter": None,
        "volume_guid": _text(row.get("volume_guid")),
        "volume_serial_number": None,
        "volume_name": _text(row.get("volume_name")),
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


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None
