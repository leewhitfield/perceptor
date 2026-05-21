from __future__ import annotations

import html
import json
import re
import uuid
from typing import Any


def usb_rows_from_partition_diagnostic_event(row: dict[str, Any]) -> list[dict[str, Any]]:
    provider = _text(row.get("provider")) or ""
    channel = _text(row.get("channel")) or ""
    event_id = _text(row.get("event_id")) or ""
    if "microsoft-windows-partition" not in provider.lower():
        return []
    if "partition/diagnostic" not in channel.lower():
        return []
    if event_id and event_id != "1006":
        return []

    data = _event_data(row.get("payload"))
    parent_id = _text(data.get("ParentId"))
    if not parent_id or "USB" not in parent_id.upper():
        return []

    parent_id = html.unescape(parent_id)
    parent = _parse_parent_id(parent_id)
    disk_serial = _clean_text(data.get("SerialNumber"))
    model = _clean_text(data.get("Model"))
    manufacturer = _clean_text(data.get("Manufacturer"))
    revision = _clean_text(data.get("Revision"))
    event_time = _text(row.get("time_created"))

    rows = []
    volume_metadata = _volume_metadata_from_event_data(data)
    if not volume_metadata:
        volume_metadata = [{"volume_serial_number": None, "volume_name": None}]

    for index, volume in enumerate(volume_metadata, start=1):
        rows.append(
            {
                "id": str(uuid.uuid4()),
                "case_id": row["case_id"],
                "computer_id": row["computer_id"],
                "image_id": row["image_id"],
                "tool_output_id": row["tool_output_id"],
                "tool_name": row["tool_name"],
                "source_csv": row["source_csv"],
                "row_number": row["row_number"],
                "source_path": row.get("source_file"),
                "artifact": "partition_diagnostic",
                "device_type": "usb_partition_diagnostic",
                "vendor_id": parent.get("vendor_id"),
                "product_id": parent.get("product_id"),
                "vendor": manufacturer,
                "product": model,
                "revision": revision,
                "friendly_name": None,
                "serial": parent.get("serial") or disk_serial,
                "instance_id": parent.get("serial"),
                "parent_id_prefix": None,
                "device_service": None,
                "user_profile": None,
                "drive_letter": None,
                "volume_guid": data.get("DiskId"),
                "volume_serial_number": volume.get("volume_serial_number"),
                "volume_name": volume.get("volume_name"),
                "capacity_bytes": data.get("Capacity"),
                "alternate_scsi_serial": disk_serial,
                "key_path": parent_id,
                "key_last_write_utc": event_time,
                "property_name": f"PartitionDiagnostic:{event_id}:VBR{index}",
                "property_value": disk_serial,
                "value_data_hex": None,
            }
        )
    return rows


def _event_data(payload: Any) -> dict[str, str | None]:
    if not payload:
        return {}
    try:
        parsed = json.loads(str(payload))
    except json.JSONDecodeError:
        return {}
    data = parsed.get("EventData", {}).get("Data", [])
    if isinstance(data, dict):
        data = [data]
    result: dict[str, str | None] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get("@Name")
        if name:
            result[str(name)] = _clean_text(item.get("#text"))
    return result


def _parse_parent_id(parent_id: str) -> dict[str, str | None]:
    vendor_id = _regex_group(parent_id, r"VID_([0-9A-Fa-f]{4})")
    product_id = _regex_group(parent_id, r"PID_([0-9A-Fa-f]{4})")
    serial = None
    parts = [part for part in re.split(r"[\\/]+", parent_id) if part]
    if len(parts) >= 3 and parts[-1].upper() not in {"USB", "USBSTOR"}:
        serial = parts[-1]
    return {"vendor_id": vendor_id, "product_id": product_id, "serial": serial}


def _volume_metadata_from_event_data(data: dict[str, str | None]) -> list[dict[str, str | None]]:
    rows = []
    direct_serial = _first_text(data, "VolumeSerialNumber", "VolumeSerial", "VolumeSerialNo")
    direct_name = _first_text(data, "VolumeName", "VolumeLabel", "FileSystemLabel")
    for index in range(16):
        if _integer(data.get(f"Vbr{index}Bytes")) == 0:
            continue
        metadata = _parse_vbr(data.get(f"Vbr{index}"))
        if metadata:
            metadata["volume_serial_number"] = metadata.get("volume_serial_number") or direct_serial
            metadata["volume_name"] = metadata.get("volume_name") or direct_name
            rows.append(metadata)
    if not rows and (direct_serial or direct_name):
        rows.append({"volume_serial_number": direct_serial, "volume_name": direct_name})
    return rows


def _parse_vbr(value: str | None) -> dict[str, str | None] | None:
    if not value:
        return None
    try:
        data = bytes.fromhex(value.replace("-", ""))
    except ValueError:
        return None
    if len(data) < 128:
        return None

    oem = _ascii(data[3:11]).upper()
    if oem.startswith("NTFS"):
        return {"volume_serial_number": _serial(data[0x48:0x4C]), "volume_name": None}
    if oem.startswith("EXFAT"):
        return {"volume_serial_number": _serial(data[0x64:0x68]), "volume_name": None}
    if _ascii(data[0x52:0x5A]).upper().startswith("FAT32"):
        return {
            "volume_serial_number": _serial(data[0x43:0x47]),
            "volume_name": _label(data[0x47:0x52]),
        }
    if _ascii(data[0x36:0x3E]).upper().startswith(("FAT12", "FAT16")):
        return {
            "volume_serial_number": _serial(data[0x27:0x2B]),
            "volume_name": _label(data[0x2B:0x36]),
        }
    return None


def _serial(value: bytes) -> str | None:
    if not value or set(value) == {0}:
        return None
    text = value[::-1].hex().upper()
    midpoint = len(text) // 2
    return f"{text[:midpoint]}-{text[midpoint:]}"


def _label(value: bytes) -> str | None:
    label = _ascii(value).strip()
    if not label or label.upper() == "NO NAME":
        return None
    return label


def _ascii(value: bytes) -> str:
    return value.decode("ascii", errors="ignore").rstrip("\x00 ")


def _integer(value: str | None) -> int:
    try:
        return int(value or "0")
    except ValueError:
        return 0


def _regex_group(value: str, pattern: str) -> str | None:
    match = re.search(pattern, value)
    return match.group(1).upper() if match else None


def _clean_text(value: Any) -> str | None:
    text = _text(value)
    if text is None or text.upper() == "NULL":
        return None
    return text


def _first_text(data: dict[str, str | None], *keys: str) -> str | None:
    for key in keys:
        value = _clean_text(data.get(key))
        if value:
            return value
    return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None
