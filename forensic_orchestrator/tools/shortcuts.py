from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any


def normalized_shortcut_rows(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
    artifact_manifest: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    manifest = artifact_manifest or {}
    if tool_name == "LECmd":
        source_file = _first(row, "SourceFile", "Source File")
        mft_metadata = manifest.get(source_file or "", {})
        identity_values = _shortcut_identity_values(row)
        return [
            {
                **_base_values(case_id, computer_id, image_id, tool_output_id, tool_name, source_csv, row_number),
                "artifact_type": "lnk",
                "artifact_name": _name_from_path(source_file),
                "artifact_path": source_file,
                "file_name": _name_from_path(_best_target_path(row)),
                "file_location": _best_target_path(row),
                "target_created": _first(row, "TargetCreated", "Target Created"),
                "target_modified": _first(row, "TargetModified", "Target Modified"),
                "target_accessed": _first(row, "TargetAccessed", "Target Accessed"),
                "device_type": _first(row, "DriveType", "Drive Type"),
                "volume_serial_number": _first(row, "VolumeSerialNumber", "Volume Serial Number"),
                "volume_name": _first(row, "VolumeLabel", "Volume Label", "VolumeName", "Volume Name"),
                **identity_values,
                "command_line_arguments": _first(
                    row,
                    "Arguments",
                    "CommandLineArguments",
                    "Command Line Arguments",
                    "CommandLine",
                    "Command Line",
                ),
                "working_directory": _first(row, "WorkingDirectory", "Working Directory"),
                "network_path": identity_values.get("network_path"),
                "machine_name": identity_values.get("machine_name"),
                "app_id": None,
                "app_id_description": None,
                "entry_id": None,
                "destlist_version": None,
                "lnk_created": mft_metadata.get("mft_created") or _first(row, "SourceCreated", "Source Created"),
                "lnk_modified": mft_metadata.get("mft_modified") or _first(row, "SourceModified", "Source Modified"),
                "lnk_accessed": mft_metadata.get("mft_accessed") or _first(row, "SourceAccessed", "Source Accessed"),
                "jumplist_item_number": None,
            }
        ]
    if tool_name == "JLECmd":
        identity_values = _shortcut_identity_values(row)
        return [
            {
                **_base_values(case_id, computer_id, image_id, tool_output_id, tool_name, source_csv, row_number),
                "artifact_type": "jumplist",
                "artifact_name": _name_from_path(_first(row, "SourceFile", "Source File", "Source")),
                "artifact_path": _first(row, "SourceFile", "Source File", "Source"),
                "file_name": _name_from_path(_best_target_path(row)),
                "file_location": _best_target_path(row),
                "target_created": _first(row, "TargetCreated", "Target Created", "Created"),
                "target_modified": _first(row, "TargetModified", "Target Modified", "Modified", "LastModified", "Last Modified"),
                "target_accessed": _first(row, "TargetAccessed", "Target Accessed", "Accessed"),
                "device_type": _first(row, "DriveType", "Drive Type"),
                "volume_serial_number": _first(row, "VolumeSerialNumber", "Volume Serial Number"),
                "volume_name": _first(row, "VolumeLabel", "Volume Label", "VolumeName", "Volume Name"),
                **identity_values,
                "command_line_arguments": _first(
                    row,
                    "Arguments",
                    "CommandLineArguments",
                    "Command Line Arguments",
                    "CommandLine",
                    "Command Line",
                ),
                "working_directory": _first(row, "WorkingDirectory", "Working Directory"),
                "network_path": identity_values.get("network_path"),
                "machine_name": identity_values.get("machine_name"),
                "app_id": _first(row, "AppId", "AppID", "App Id", "SourceAppId", "Source AppId"),
                "app_id_description": _first(
                    row,
                    "AppIdDescription",
                    "AppIDDescription",
                    "App Id Description",
                    "AppId Desc",
                    "AppID Desc",
                ),
                "entry_id": _first(row, "EntryId", "Entry ID", "EntryGuid", "Entry GUID"),
                "destlist_version": _first(row, "DestListVersion", "DestList Version"),
                "lnk_created": None,
                "lnk_modified": None,
                "lnk_accessed": None,
                "jumplist_item_number": _first(
                    row,
                    "EntryNumber",
                    "Entry Number",
                    "ItemNumber",
                    "Item Number",
                    "DestListEntryNumber",
                    "DestList Entry Number",
                ),
            }
        ]
    return []


def _shortcut_identity_values(row: dict[str, Any]) -> dict[str, str | None]:
    return {
        "local_path": _first(row, "LocalPath", "Local Path"),
        "common_path": _first(row, "CommonPath", "Common Path"),
        "target_path": _first(row, "TargetPath", "Target Path", "Path"),
        "relative_path": _first(row, "RelativePath", "Relative Path"),
        "network_path": _first(row, "NetworkPath", "Network Path"),
        "icon_location": _first(row, "IconLocation", "Icon Location", "IconPath", "Icon Path"),
        "hot_key": _first(row, "HotKey", "Hot Key"),
        "window_style": _first(row, "WindowStyle", "Window Style", "ShowCommand", "Show Command"),
        "header_flags": _first(row, "HeaderFlags", "Header Flags"),
        "link_flags": _first(row, "LinkFlags", "Link Flags"),
        "target_id_absolute_path": _first(row, "TargetIDAbsolutePath", "Target ID Absolute Path"),
        "target_mft_entry_number": _first(row, "TargetMFTEntryNumber", "Target MFT Entry Number"),
        "target_mft_sequence_number": _first(row, "TargetMFTSequenceNumber", "Target MFT Sequence Number"),
        "machine_name": _first(row, "MachineID", "Machine ID", "MachineName", "Machine Name"),
        "machine_mac_address": _first(row, "MachineMACAddress", "Machine MAC Address"),
        "tracker_created_on": _first(row, "TrackerCreatedOn", "Tracker Created On"),
        "tracker_id": _first(row, "TrackerID", "Tracker ID", "TrackerId"),
        "droid_volume_id": _first(row, "DroidVolumeId", "Droid Volume Id", "DroidVolumeID", "Droid Volume ID"),
        "droid_file_id": _first(row, "DroidFileId", "Droid File Id", "DroidFileID", "Droid File ID"),
        "birth_droid_volume_id": _first(
            row,
            "BirthDroidVolumeId",
            "Birth Droid Volume Id",
            "BirthDroidVolumeID",
            "Birth Droid Volume ID",
        ),
        "birth_droid_file_id": _first(row, "BirthDroidFileId", "Birth Droid File Id", "BirthDroidFileID", "Birth Droid File ID"),
    }


def _base_values(
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
    }


def _best_target_path(row: dict[str, Any]) -> str | None:
    return _first(
        row,
        "LocalPath",
        "Local Path",
        "NetworkPath",
        "Network Path",
        "CommonPath",
        "Common Path",
        "TargetPath",
        "Target Path",
        "Path",
    )


def _first(row: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value not in {None, ""}:
            return str(value)
    return None


def _name_from_path(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1] if normalized else None
