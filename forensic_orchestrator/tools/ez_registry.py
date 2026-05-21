from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any


def normalized_amcache_row(
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
    return {
        **_base(case_id, computer_id, image_id, tool_output_id, tool_name, source_csv, row_number),
        "entry_type": _amcache_entry_type(source_csv),
        "source_file": _first(row, "SourceFile", "Source File", "HivePath"),
        "path": _first(row, "Path", "FullPath", "FilePath", "LowerCaseLongPath", "Name"),
        "name": _first(row, "Name", "FileName", "ProgramName", "ApplicationName"),
        "publisher": _first(row, "Publisher", "CompanyName"),
        "product_name": _first(row, "ProductName", "Product Name"),
        "product_version": _first(row, "ProductVersion", "Product Version"),
        "file_version": _first(row, "FileVersion", "File Version", "BinFileVersion"),
        "sha1": _first(row, "SHA1", "Sha1", "FileId", "ProgramId"),
        "sha256": _first(row, "SHA256", "Sha256"),
        "binary_type": _first(row, "BinaryType", "Binary Type", "FileType"),
        "size": _first(row, "Size", "FileSize", "LinkerSize"),
        "created_utc": _first(row, "Created", "CreatedUtc", "CreatedUTC", "FileCreated"),
        "modified_utc": _first(row, "Modified", "ModifiedUtc", "ModifiedUTC", "FileModified", "LastModifiedTimeUTC"),
        "link_date": _first(row, "LinkDate", "Link Date"),
        "compile_time": _first(row, "CompileTime", "Compile Time"),
        "program_id": _first(row, "ProgramId", "Program ID"),
        "install_date": _first(row, "InstallDate", "Install Date"),
        "unassociated": _first(row, "Unassociated", "IsUnassociated"),
    }


def normalized_shimcache_row(
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
    return {
        **_base(case_id, computer_id, image_id, tool_output_id, tool_name, source_csv, row_number),
        "source_file": _first(row, "SourceFile", "Source File", "HivePath"),
        "control_set": _first(row, "ControlSet", "Control Set"),
        "entry_number": _first(row, "EntryNumber", "Entry", "Position"),
        "path": _first(row, "Path", "FilePath", "Name"),
        "last_modified_utc": _first(row, "LastModifiedTimeUTC", "LastModified", "Last Modified", "ModifiedTimeUTC"),
        "executed": _first(row, "Executed", "ExecFlag", "ExecutionFlag"),
        "source_key": _first(row, "SourceKey", "KeyPath", "RegistryPath"),
    }


def normalized_shellbag_row(
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
    hive_path = _first(row, "SourceFile", "Source File", "HivePath", "Hive")
    absolute_path = _first(row, "AbsolutePath", "Absolute Path", "Path", "ShellBagPath", "BagPath")
    user_profile = _user_profile_from_path(hive_path) or _user_profile_from_sbecmd_source(source_csv)
    return {
        **_base(case_id, computer_id, image_id, tool_output_id, tool_name, source_csv, row_number),
        "source_file": _first(row, "SourceFile", "Source File"),
        "hive_path": hive_path,
        "user_profile": user_profile,
        "absolute_path": absolute_path,
        "shell_type": _first(row, "ShellType", "Shell Type", "ItemType", "Type"),
        "value_name": _first(row, "ValueName", "Value Name"),
        "mru_position": _first(row, "MruPosition", "MRUPosition", "MRU Position"),
        "slot": _first(row, "Slot", "BagId"),
        "node_slot": _first(row, "NodeSlot", "Node Slot"),
        "created_on": _first(row, "CreatedOn", "Created On", "CreationTime", "Created"),
        "modified_on": _first(row, "ModifiedOn", "Modified On", "ModifiedTime", "Modified"),
        "accessed_on": _first(row, "AccessedOn", "Accessed On", "AccessedTime", "Accessed"),
        "last_write_time": _first(row, "LastWriteTime", "Last Write Time", "LastWriteTimeUTC"),
        "first_interacted": _first(row, "FirstInteracted", "First Interacted"),
        "last_interacted": _first(row, "LastInteracted", "Last Interacted"),
        "has_explored": _first(row, "HasExplored", "Has Explored"),
        "drive_letter": _first(row, "DriveLetter", "Drive Letter") or _drive_letter_from_path(absolute_path),
        "volume_guid": _first(row, "VolumeGuid", "Volume GUID", "VolumeId", "Volume ID")
        or _volume_guid_from_text(absolute_path),
        "volume_serial_number": _first(
            row,
            "VolumeSerialNumber",
            "Volume Serial Number",
            "VolumeSerial",
            "Volume Serial",
            "VSN",
        ),
        "volume_name": _first(row, "VolumeName", "Volume Name", "VolumeLabel", "Volume Label"),
    }


def _base(
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


def _amcache_entry_type(source_csv: Path) -> str | None:
    stem = source_csv.stem
    if "_Amcache_" in stem:
        return stem.split("_Amcache_", 1)[1]
    if "Amcache_" in stem:
        return stem.split("Amcache_", 1)[1]
    return stem


def _first(row: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    lowered = {key.lower().replace(" ", ""): value for key, value in row.items()}
    for name in names:
        value = lowered.get(name.lower().replace(" ", ""))
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _user_profile_from_path(path: str | None) -> str | None:
    if not path:
        return None
    parts = Path(path).parts
    lowered = [part.lower() for part in parts]
    if "users" in lowered:
        index = lowered.index("users")
        if index + 1 < len(parts):
            return parts[index + 1]
    return None


def _drive_letter_from_path(value: str | None) -> str | None:
    if not value or len(value) < 2:
        return None
    match = re.search(r"(?<![A-Za-z])([A-Za-z]:)(?:\\|/|$)", value)
    if match:
        return match.group(1).upper()
    return None


def _user_profile_from_sbecmd_source(source_csv: Path) -> str | None:
    parent = source_csv.parent.name
    if parent.lower() in {"ntuser", "usrclass"}:
        grandparent = source_csv.parent.parent.name
        if grandparent.lower() not in {"sbecmd", "by_user", "users"}:
            return grandparent
    if parent.lower() not in {"sbecmd", "by_user", "users"}:
        return parent
    return None


def _volume_guid_from_text(value: str | None) -> str | None:
    if not value:
        return None
    lowered = value.lower()
    marker = "volume{"
    index = lowered.find(marker)
    if index == -1:
        return None
    start = index + len("volume")
    end = value.find("}", start)
    if end == -1:
        return None
    return value[start : end + 1]
