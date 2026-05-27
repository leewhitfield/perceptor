from __future__ import annotations

import html
import hashlib
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
    if not data:
        data = _event_data_from_payload_fields(row)
    parent_id = _first_text(data, "ParentId", "ParentDeviceInstanceId")
    if not parent_id or "USB" not in parent_id.upper():
        return []

    parent_id = html.unescape(parent_id)
    parent = _parse_parent_id(parent_id)
    disk_serial = _first_text(data, "SerialNumber", "SCSI SerialNumber", "DriveSerial")
    model = _first_text(data, "Model", "DriveModel", "ProductId")
    manufacturer = _first_text(data, "Manufacturer", "DriveManufacturer", "VendorId")
    revision = _first_text(data, "Revision", "FirmwareVersion")
    event_time = _text(row.get("time_created"))
    log_metadata = _partition_log_metadata(data)

    rows = []
    volume_metadata = _volume_metadata_from_event_data(data)
    if not volume_metadata:
        volume_metadata = [{"volume_serial_number": None, "volume_name": None, "file_system": None}]

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
                "capacity_bytes": _first_text(data, "Capacity", "Size"),
                "file_system": volume.get("file_system"),
                "alternate_scsi_serial": disk_serial,
                **log_metadata,
                "vbr_index": volume.get("vbr_index"),
                "vbr_bytes": volume.get("vbr_bytes"),
                "vbr_oem_name": volume.get("vbr_oem_name"),
                "vbr_file_system": volume.get("vbr_file_system"),
                "vbr_volume_serial_number": volume.get("vbr_volume_serial_number"),
                "vbr_volume_serial_number_full": volume.get("vbr_volume_serial_number_full"),
                "vbr_volume_name": volume.get("vbr_volume_name"),
                "vbr_parse_status": volume.get("vbr_parse_status"),
                "vbr_serial_match": volume.get("vbr_serial_match"),
                "mbr_partition_type": volume.get("partition_type"),
                "partition_start_lba": volume.get("partition_start_lba"),
                "partition_sector_count": volume.get("partition_sector_count"),
                "key_path": parent_id,
                "key_last_write_utc": event_time,
                "property_name": f"PartitionDiagnostic:{event_id}:VBR{volume.get('vbr_index') or index}",
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


def _event_data_from_payload_fields(row: dict[str, Any]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for field in ("payload_data1", "payload_data2", "payload_data3", "payload_data4", "payload_data5", "payload_data6"):
        value = _clean_text(row.get(field))
        if not value or ":" not in value:
            continue
        name, text = value.split(":", 1)
        name = name.strip()
        if not name:
            continue
        result[name] = _clean_text(text)
    return result


def _parse_parent_id(parent_id: str) -> dict[str, str | None]:
    vendor_id = _regex_group(parent_id, r"VID_([0-9A-Fa-f]{4})")
    product_id = _regex_group(parent_id, r"PID_([0-9A-Fa-f]{4})")
    serial = None
    parts = [part for part in re.split(r"[\\/]+", parent_id) if part]
    if len(parts) >= 3 and parts[-1].upper() not in {"USB", "USBSTOR"}:
        serial = parts[-1]
    return {"vendor_id": vendor_id, "product_id": product_id, "serial": serial}


def _partition_log_metadata(data: dict[str, str | None]) -> dict[str, str | None]:
    partition_table = _parse_partition_table(data.get("PartitionTable"), data.get("PartitionTableBytes"))
    storage_id = _parse_storage_id(data.get("StorageId"), data.get("StorageIdBytes"))
    return {
        "partition_disk_number": _first_text(data, "DiskNumber"),
        "partition_bus_type": _bus_type_label(_first_text(data, "BusType")),
        "partition_bus_type_code": _first_text(data, "BusType"),
        "partition_user_removal_policy": _first_text(data, "UserRemovalPolicy"),
        "partition_bytes_per_sector": _first_text(data, "BytesPerSector"),
        "partition_bytes_per_logical_sector": _first_text(data, "BytesPerLogicalSector"),
        "partition_bytes_per_physical_sector": _first_text(data, "BytesPerPhysicalSector"),
        "partition_style": partition_table.get("partition_style") or _partition_style_label(_first_text(data, "PartitionStyle")),
        "partition_style_code": _first_text(data, "PartitionStyle"),
        "partition_count": _first_text(data, "PartitionCount"),
        "partition_table_bytes": _first_text(data, "PartitionTableBytes"),
        "partition_table_sha256": partition_table.get("partition_table_sha256"),
        "partition_table_summary": partition_table.get("partition_table_summary"),
        "partition_table_disk_guid": partition_table.get("partition_table_disk_guid"),
        "storage_id_code_set": _first_text(data, "StorageIdCodeSet"),
        "storage_id_type": _first_text(data, "StorageIdType"),
        "storage_id_association": _first_text(data, "StorageIdAssociation"),
        "storage_id_bytes": _first_text(data, "StorageIdBytes"),
        "storage_id_hex": storage_id.get("storage_id_hex"),
        "storage_id_ascii": storage_id.get("storage_id_ascii"),
        "storage_id_sha256": storage_id.get("storage_id_sha256"),
        "partition_registry_id": _first_text(data, "RegistryId"),
        "partition_adapter_id": _first_text(data, "AdapterId"),
        "partition_pool_id": _first_text(data, "PoolId"),
        "partition_location": _first_text(data, "Location"),
        "partition_flags": _first_text(data, "Flags"),
        "partition_characteristics": _first_text(data, "Characteristics"),
    }


def _volume_metadata_from_event_data(data: dict[str, str | None]) -> list[dict[str, str | None]]:
    rows = []
    direct_serial = _first_text(data, "VolumeSerialNumber", "VolumeSerial", "VolumeSerialNo")
    direct_name = _first_text(data, "VolumeName", "VolumeLabel", "FileSystemLabel")
    for index in range(16):
        vbr_bytes = _integer(data.get(f"Vbr{index}Bytes"))
        if vbr_bytes == 0:
            continue
        metadata = _parse_vbr(data.get(f"Vbr{index}"))
        if metadata:
            metadata["vbr_index"] = str(index)
            metadata["vbr_bytes"] = str(vbr_bytes)
            metadata["volume_serial_number"] = metadata.get("volume_serial_number") or direct_serial
            metadata["volume_name"] = metadata.get("volume_name") or direct_name
            metadata["vbr_serial_match"] = _serial_match(direct_serial, metadata.get("vbr_volume_serial_number"))
            rows.append(metadata)
    if not rows:
        rows.extend(_volume_metadata_from_mbr(data))
    if not rows and (direct_serial or direct_name):
        rows.append(
            {
                "volume_serial_number": direct_serial,
                "volume_name": direct_name,
                "vbr_parse_status": "direct_event_fields",
                "vbr_serial_match": "not_applicable",
            }
        )
    if not rows:
        rows.append({"vbr_parse_status": "absent", "vbr_serial_match": "not_applicable"})
    return rows


def _volume_metadata_from_mbr(data: dict[str, str | None]) -> list[dict[str, str | None]]:
    mbr = data.get("Mbr")
    if not mbr or _integer(data.get("MbrBytes")) == 0:
        return []
    try:
        raw = bytes.fromhex(mbr.replace("-", ""))
    except ValueError:
        return []
    if len(raw) < 512 or raw[510:512] != b"\x55\xaa":
        return []
    rows = []
    for index in range(4):
        offset = 0x1BE + (index * 16)
        entry = raw[offset : offset + 16]
        if len(entry) != 16:
            continue
        partition_type = entry[4]
        start_lba = int.from_bytes(entry[8:12], "little")
        sector_count = int.from_bytes(entry[12:16], "little")
        if partition_type == 0 or sector_count == 0:
            continue
        file_system = _filesystem_from_mbr_partition_type(partition_type)
        if not file_system:
            continue
        rows.append(
            {
                "volume_serial_number": None,
                "volume_name": None,
                "file_system": file_system,
                "vbr_file_system": file_system,
                "vbr_parse_status": "mbr_fallback",
                "vbr_serial_match": "not_applicable",
                "partition_type": f"0x{partition_type:02X}",
                "partition_start_lba": str(start_lba),
                "partition_sector_count": str(sector_count),
            }
        )
    return rows


def _filesystem_from_mbr_partition_type(partition_type: int) -> str | None:
    if partition_type in {0x0B, 0x0C}:
        return "FAT32"
    if partition_type in {0x04, 0x06, 0x0E}:
        return "FAT16"
    if partition_type == 0x01:
        return "FAT12"
    if partition_type == 0x07:
        return "NTFS/exFAT/HPFS"
    return None


def _parse_storage_id(value: str | None, byte_count: str | None) -> dict[str, str | None]:
    raw = _hex_bytes(value)
    if not raw:
        return {}
    if _integer(byte_count) and len(raw) > _integer(byte_count):
        raw = raw[: _integer(byte_count)]
    return {
        "storage_id_hex": raw.hex("-").upper(),
        "storage_id_ascii": _printable_ascii(raw),
        "storage_id_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _parse_partition_table(value: str | None, byte_count: str | None) -> dict[str, str | None]:
    raw = _hex_bytes(value)
    if not raw:
        return {}
    if _integer(byte_count) and len(raw) > _integer(byte_count):
        raw = raw[: _integer(byte_count)]
    result: dict[str, str | None] = {"partition_table_sha256": hashlib.sha256(raw).hexdigest()}
    if len(raw) < 8:
        result["partition_table_summary"] = f"bytes={len(raw)} too_short"
        return result
    style_code = int.from_bytes(raw[0:4], "little")
    count = int.from_bytes(raw[4:8], "little")
    style = _partition_style_label(str(style_code)) or f"unknown({style_code})"
    result["partition_style"] = style
    parts = [f"style={style}", f"count={count}", f"bytes={len(raw)}"]
    if style_code == 1 and len(raw) >= 24:
        disk_guid = _windows_guid(raw[8:24])
        result["partition_table_disk_guid"] = disk_guid
        if disk_guid:
            parts.append(f"disk_guid={disk_guid}")
    result["partition_table_summary"] = " ".join(parts)
    return result


def _hex_bytes(value: str | None) -> bytes | None:
    if not value:
        return None
    try:
        return bytes.fromhex(value.replace("-", "").replace(" ", ""))
    except ValueError:
        return None


def _printable_ascii(value: bytes) -> str | None:
    text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in value).strip(". ")
    return text or None


def _windows_guid(value: bytes) -> str | None:
    if len(value) != 16 or set(value) == {0}:
        return None
    try:
        return str(uuid.UUID(bytes_le=value))
    except ValueError:
        return None


def _partition_style_label(value: str | None) -> str | None:
    labels = {"0": "MBR", "1": "GPT", "2": "RAW"}
    return labels.get(str(value or "").strip())


def _bus_type_label(value: str | None) -> str | None:
    labels = {
        "0": "Unknown",
        "1": "SCSI",
        "2": "ATAPI",
        "3": "ATA",
        "4": "IEEE1394",
        "5": "SSA",
        "6": "Fibre",
        "7": "USB",
        "8": "RAID",
        "9": "iSCSI",
        "10": "SAS",
        "11": "SATA",
        "12": "SD",
        "13": "MMC",
        "14": "Virtual",
        "15": "FileBackedVirtual",
        "16": "Spaces",
        "17": "NVMe",
        "18": "SCM",
        "19": "UFS",
    }
    return labels.get(str(value or "").strip())


def _parse_vbr(value: str | None) -> dict[str, str | None] | None:
    if not value:
        return {"vbr_parse_status": "absent", "vbr_serial_match": "not_applicable"}
    try:
        data = bytes.fromhex(value.replace("-", ""))
    except ValueError:
        return {"vbr_parse_status": "invalid_hex", "vbr_serial_match": "not_applicable"}
    if len(data) < 128:
        return {"vbr_parse_status": "too_short", "vbr_serial_match": "not_applicable"}

    oem = _ascii(data[3:11]).upper()
    base = {"vbr_oem_name": oem, "vbr_parse_status": "parsed"}
    if oem.startswith("NTFS"):
        serial = _serial(data[0x48:0x4C])
        full_serial = _serial(data[0x48:0x50])
        return {
            **base,
            "volume_serial_number": serial,
            "volume_name": None,
            "file_system": "NTFS",
            "vbr_file_system": "NTFS",
            "vbr_volume_serial_number": serial,
            "vbr_volume_serial_number_full": full_serial,
            "vbr_volume_name": None,
        }
    if oem.startswith("EXFAT"):
        serial = _serial(data[0x64:0x68])
        return {
            **base,
            "volume_serial_number": serial,
            "volume_name": None,
            "file_system": "exFAT",
            "vbr_file_system": "exFAT",
            "vbr_volume_serial_number": serial,
            "vbr_volume_serial_number_full": serial,
            "vbr_volume_name": None,
        }
    if _ascii(data[0x52:0x5A]).upper().startswith("FAT32"):
        serial = _serial(data[0x43:0x47])
        label = _label(data[0x47:0x52])
        return {
            **base,
            "volume_serial_number": serial,
            "volume_name": label,
            "file_system": "FAT32",
            "vbr_file_system": "FAT32",
            "vbr_volume_serial_number": serial,
            "vbr_volume_serial_number_full": serial,
            "vbr_volume_name": label,
        }
    if _ascii(data[0x36:0x3E]).upper().startswith(("FAT12", "FAT16")):
        file_system = _ascii(data[0x36:0x3E]).upper()
        serial = _serial(data[0x27:0x2B])
        label = _label(data[0x2B:0x36])
        return {
            **base,
            "volume_serial_number": serial,
            "volume_name": label,
            "file_system": file_system,
            "vbr_file_system": file_system,
            "vbr_volume_serial_number": serial,
            "vbr_volume_serial_number_full": serial,
            "vbr_volume_name": label,
        }
    return {**base, "vbr_parse_status": "unrecognized", "vbr_serial_match": "not_applicable"}


def _serial_match(direct_serial: str | None, vbr_serial: str | None) -> str:
    direct = _normalize_serial(direct_serial)
    vbr = _normalize_serial(vbr_serial)
    if not direct and not vbr:
        return "not_applicable"
    if not direct:
        return "no_direct_serial"
    if not vbr:
        return "no_vbr_serial"
    return "matches_direct" if direct == vbr else "mismatch"


def _normalize_serial(value: str | None) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()


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
