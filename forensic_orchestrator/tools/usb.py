from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any


def usb_rows_from_registry_artifact(row: dict[str, Any]) -> list[dict[str, Any]]:
    artifact = _text(row.get("artifact"))
    if artifact not in {
        "usb_device_history",
        "usb_volume_history",
        "usb_volume_name",
        "usb_volume_info_cache",
        "usb_mountpoints2",
        "usb_device_migration",
        "mounted_devices",
    }:
        return []
    key_path = _text(row.get("key_path"))
    value_name = _text(row.get("value_name"))
    value_data = _text(row.get("value_data"))
    if artifact == "usb_device_migration" and not _is_device_migration_root(key_path):
        return []
    parsed = _parse_usb_key(key_path, artifact, value_name=value_name, value_data=value_data)
    return [
        {
            "id": str(uuid.uuid4()),
            "case_id": row["case_id"],
            "computer_id": row["computer_id"],
            "image_id": row["image_id"],
            "tool_output_id": row["tool_output_id"],
            "tool_name": row["tool_name"],
            "source_csv": row["source_csv"],
            "row_number": row["row_number"],
            "source_path": row.get("source_path"),
            "artifact": artifact,
            "device_type": parsed.get("device_type"),
            "vendor_id": parsed.get("vendor_id"),
            "product_id": parsed.get("product_id"),
            "vendor": parsed.get("vendor"),
            "product": parsed.get("product"),
            "revision": parsed.get("revision"),
            "friendly_name": parsed.get("friendly_name"),
            "serial": parsed.get("serial"),
            "instance_id": parsed.get("instance_id"),
            "parent_id_prefix": parsed.get("parent_id_prefix"),
            "device_service": parsed.get("device_service"),
            "user_profile": row.get("user_profile"),
            "drive_letter": parsed.get("drive_letter"),
            "volume_guid": parsed.get("volume_guid"),
            "volume_serial_number": parsed.get("volume_serial_number"),
            "volume_name": parsed.get("volume_name"),
            "capacity_bytes": parsed.get("capacity_bytes"),
            "alternate_scsi_serial": parsed.get("alternate_scsi_serial"),
            "key_path": key_path,
            "key_last_write_utc": row.get("key_last_write_utc"),
            "last_present_date_utc": parsed.get("last_present_date_utc"),
            "property_name": value_name,
            "property_value": value_data,
            "value_data_hex": row.get("value_data_hex"),
        }
    ]


def _parse_usb_key(
    key_path: str | None,
    artifact: str,
    *,
    value_name: str | None,
    value_data: str | None,
) -> dict[str, str | None]:
    result: dict[str, str | None] = {
        "device_type": "mounted_device" if artifact == "mounted_devices" else "usb",
        "vendor_id": None,
        "product_id": None,
        "vendor": None,
        "product": None,
        "revision": None,
        "friendly_name": None,
        "serial": None,
        "instance_id": None,
        "parent_id_prefix": None,
        "device_service": None,
        "drive_letter": None,
        "volume_guid": None,
        "volume_serial_number": None,
        "volume_name": None,
        "capacity_bytes": None,
        "alternate_scsi_serial": None,
        "last_present_date_utc": None,
    }
    if artifact == "mounted_devices":
        result.update(_parse_mounted_device_value(value_name, value_data))
        return result
    if not key_path:
        return result
    parts = [part for part in re.split(r"[\\/]+", key_path) if part]
    lowered = [part.lower() for part in parts]
    if "usbstor" in lowered:
        index = lowered.index("usbstor")
        descriptor = parts[index + 1] if index + 1 < len(parts) else None
        serial = parts[index + 2] if index + 2 < len(parts) else None
        result.update(_parse_usbstor_descriptor(descriptor))
        result["device_type"] = "usb_storage"
        result["serial"] = serial
        result["instance_id"] = serial
        if value_name and value_name.lower() == "friendlyname":
            result["friendly_name"] = _display_tail(value_data)
        elif value_name and value_name.lower() == "service":
            result["device_service"] = value_data
    elif "scsi" in lowered:
        index = lowered.index("scsi")
        descriptor = parts[index + 1] if index + 1 < len(parts) else None
        identifier = parts[index + 2] if index + 2 < len(parts) else None
        result.update(_parse_usbstor_descriptor(descriptor))
        result["device_type"] = "scsi_storage"
        result["parent_id_prefix"] = identifier
        result["instance_id"] = identifier
        if value_name and value_name.lower() == "friendlyname":
            result["friendly_name"] = _display_tail(value_data)
        elif value_name and value_name.lower() == "service":
            result["device_service"] = value_data
    elif "hid" in lowered:
        index = lowered.index("hid")
        descriptor = parts[index + 1] if index + 1 < len(parts) else None
        identifier = parts[index + 2] if index + 2 < len(parts) else None
        result.update(_parse_usb_descriptor(descriptor))
        result["device_type"] = "hid_device"
        result["parent_id_prefix"] = identifier
        result["instance_id"] = identifier
        if value_name and value_name.lower() == "friendlyname":
            result["friendly_name"] = _display_tail(value_data)
        elif value_name and value_name.lower() == "service":
            result["device_service"] = value_data
    elif "usb" in lowered:
        index = lowered.index("usb")
        descriptor = parts[index + 1] if index + 1 < len(parts) else None
        serial = parts[index + 2] if index + 2 < len(parts) else None
        result.update(_parse_usb_descriptor(descriptor))
        result["device_type"] = "usb_device"
        result["serial"] = serial
        result["instance_id"] = serial
        if value_name and value_name.lower() == "parentidprefix":
            result["parent_id_prefix"] = value_data
        elif value_name and value_name.lower() == "service":
            result["device_service"] = value_data
    elif "wpdbusenum" in lowered:
        index = lowered.index("wpdbusenum")
        descriptor = parts[index + 1] if index + 1 < len(parts) else None
        result.update(_parse_wpd_descriptor(descriptor))
        result["device_type"] = "usb_volume"
        if value_name and value_name.lower() == "friendlyname":
            result.update(_volume_name_or_drive(value_data))
    elif artifact == "usb_volume_name":
        result.update(_parse_embedded_usb_identifier(key_path, value_data))
        result["device_type"] = "portable_device_volume"
        if value_name and value_name.lower() == "friendlyname":
            result.update(_volume_name_or_drive(value_data))
    elif artifact == "usb_volume_info_cache":
        result["device_type"] = "volume_info_cache"
        result.update(_parse_volume_guid_from_text(key_path))
        if value_name and value_name.lower() == "driveletter":
            result["drive_letter"] = value_data
        elif value_name and value_name.lower() in {"volumelabel", "volumename", "friendlyname"}:
            result["volume_name"] = _display_tail(value_data)
    elif artifact == "usb_mountpoints2":
        result["device_type"] = "user_mountpoint"
        result.update(_parse_volume_guid_from_text(key_path))
    elif artifact == "usb_device_migration":
        result.update(_parse_embedded_usb_identifier(key_path, value_data))
        result["device_type"] = "device_migration"
    if value_name:
        lowered_value = value_name.lower()
        if lowered_value == "parentidprefix" and value_data:
            result["parent_id_prefix"] = value_data
        elif lowered_value == "service" and value_data:
            result["device_service"] = value_data
        elif lowered_value == "lastpresentdate" and value_data:
            result["last_present_date_utc"] = value_data
        elif (
            lowered_value == "friendlyname"
            and value_data
            and not result.get("friendly_name")
            and artifact in {"usb_device_history", "usb_device_migration"}
        ):
            result["friendly_name"] = _display_tail(value_data)
    return result


def _is_device_migration_root(key_path: str | None) -> bool:
    normalized = (key_path or "").replace("\\", "/").strip("/").lower()
    return normalized.startswith(
        "root/setup/upgrade/pnp/currentcontrolset/control/devicemigration/devices/"
    ) or normalized.startswith("setup/upgrade/pnp/currentcontrolset/control/devicemigration/devices/")


def _parse_usb_descriptor(descriptor: str | None) -> dict[str, str | None]:
    if not descriptor:
        return {}
    vendor_id = _regex_group(descriptor, r"VID_([0-9A-Fa-f]{4})")
    product_id = _regex_group(descriptor, r"PID_([0-9A-Fa-f]{4})")
    return {"vendor_id": vendor_id, "product_id": product_id}


def _parse_usbstor_descriptor(descriptor: str | None) -> dict[str, str | None]:
    if not descriptor:
        return {}
    fields = {}
    for key in ("Ven", "Prod", "Rev"):
        match = re.search(rf"{key}_([^&\\]+)", descriptor, re.IGNORECASE)
        fields[key.lower()] = match.group(1).replace("_", " ").strip() if match else None
    return {
        "vendor": fields.get("ven"),
        "product": fields.get("prod"),
        "revision": fields.get("rev"),
    }


def _parse_wpd_descriptor(descriptor: str | None) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    if not descriptor:
        return result
    decoded = descriptor.replace("#", "\\")
    serial_match = re.search(r"USBSTOR\\[^\\]+\\([^\\{]+)", decoded, re.IGNORECASE)
    if serial_match:
        result["serial"] = serial_match.group(1).replace("&0", "")
        result["instance_id"] = result["serial"]
    volume_match = re.search(r"Volume\{([^}]+)\}", decoded, re.IGNORECASE)
    if volume_match:
        result["volume_guid"] = "{" + volume_match.group(1) + "}"
    result.update(_parse_usbstor_descriptor(decoded))
    return result


def _parse_mounted_device_value(value_name: str | None, value_data: str | None) -> dict[str, str | None]:
    result = {
        "drive_letter": None,
        "volume_guid": None,
        "volume_serial_number": None,
        "volume_name": None,
        "serial": None,
        "instance_id": None,
        "friendly_name": None,
        "vendor": None,
        "product": None,
        "revision": None,
    }
    if value_name:
        drive = re.search(r"\\DosDevices\\([A-Z]:)", value_name)
        if drive:
            result["drive_letter"] = drive.group(1)
        volume = re.search(r"Volume\{([^}]+)\}", value_name)
        if volume:
            result["volume_guid"] = "{" + volume.group(1) + "}"
    if value_data:
        storage = re.search(r"USBSTOR#([^#]+)#([^#]+)#", value_data, re.IGNORECASE)
        if storage:
            result.update(_parse_usbstor_descriptor(storage.group(1)))
            serial = storage.group(2).replace("&0", "")
            result["serial"] = serial
            result["instance_id"] = serial
        scsi = re.search(r"SCSI#([^#]+)#([^#]+)#", value_data, re.IGNORECASE)
        if scsi:
            result.update(_parse_usbstor_descriptor(scsi.group(1)))
            identifier = scsi.group(2)
            result["parent_id_prefix"] = identifier
            result["instance_id"] = identifier
    return result


def _parse_embedded_usb_identifier(*values: str | None) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    text = " ".join(value for value in values if value)
    if not text:
        return result
    storage = re.search(r"USBSTOR[#\\]([^#\\]+)[#\\]([^#\\]+)", text, re.IGNORECASE)
    if storage:
        result.update(_parse_usbstor_descriptor(storage.group(1)))
        serial = storage.group(2).replace("&0", "")
        result["serial"] = serial
        result["instance_id"] = serial
    scsi = re.search(r"SCSI[#\\]([^#\\]+)[#\\]([^#\\]+)", text, re.IGNORECASE)
    if scsi:
        result.update(_parse_usbstor_descriptor(scsi.group(1)))
        identifier = scsi.group(2)
        result["parent_id_prefix"] = identifier
        result["instance_id"] = identifier
    usb = re.search(r"USB[#\\](VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4})[#\\]([^#\\}]+)", text, re.IGNORECASE)
    if usb:
        result.update(_parse_usb_descriptor(usb.group(1)))
        result["serial"] = usb.group(2)
        result["instance_id"] = usb.group(2)
    volume = _parse_volume_guid_from_text(text)
    result.update({key: value for key, value in volume.items() if value})
    return result


def _parse_volume_guid_from_text(value: str | None) -> dict[str, str | None]:
    if not value:
        return {"volume_guid": None}
    match = re.search(r"Volume\{([^}]+)\}", value, re.IGNORECASE)
    return {"volume_guid": "{" + match.group(1) + "}"} if match else {"volume_guid": None}


def _regex_group(value: str, pattern: str) -> str | None:
    match = re.search(pattern, value)
    return match.group(1).upper() if match else None


def _display_tail(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(";")[-1].strip() if ";" in value else value.strip()


def _volume_name_or_drive(value: str | None) -> dict[str, str | None]:
    display = _display_tail(value)
    if not display:
        return {"volume_name": None}
    drive = re.fullmatch(r"([A-Z]:)\\?", display, re.IGNORECASE)
    if drive:
        return {"drive_letter": drive.group(1).upper()}
    return {"volume_name": display}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None
