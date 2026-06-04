from __future__ import annotations

import csv
import hashlib
import os
import stat as stat_module
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.mounting.tsk import FlsEntry, list_files, read_file_metadata
from forensic_orchestrator.safety import ToolError
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths


TOOL_NAME = "MountedFilesystemInventory"
TSK_TOOL_NAME = "TskFilesystemInventory"


def _iso_from_timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _relative_path(root: Path, path: Path) -> str:
    if path == root:
        return ""
    return path.relative_to(root).as_posix()


def _extension(name: str, is_directory: bool) -> str:
    if is_directory:
        return ""
    return Path(name).suffix.lower().lstrip(".")


def _row_from_path(
    *,
    case_id: str,
    image: EvidenceImage,
    tool_output_id: str,
    source_csv: Path,
    row_number: int,
    mount_path: Path,
    path: Path,
    partition_id: str | None,
    filesystem_type: str | None,
    created_at: str,
) -> dict[str, Any]:
    rel = _relative_path(mount_path, path)
    parent = Path(rel).parent.as_posix() if rel and Path(rel).parent.as_posix() != "." else ""
    name = path.name
    try:
        stat = path.stat(follow_symlinks=False)
        is_directory = stat_module.S_ISDIR(stat.st_mode)
        error = ""
        status = "ok"
    except OSError as exc:
        stat = None
        is_directory = False
        error = str(exc)
        status = "stat_error"
    birth_time = getattr(stat, "st_birthtime", None) if stat is not None else None
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": image.computer_id,
        "image_id": image.id,
        "tool_output_id": tool_output_id,
        "tool_name": TOOL_NAME,
        "source_csv": str(source_csv),
        "row_number": row_number,
        "partition_id": partition_id,
        "filesystem_type": filesystem_type,
        "source_root": str(mount_path),
        "file_path": rel,
        "parent_path": parent,
        "file_name": name,
        "extension": _extension(name, is_directory),
        "file_size": str(stat.st_size) if stat is not None and not is_directory else "",
        "is_directory": "true" if is_directory else "false",
        "created_utc": _iso_from_timestamp(birth_time),
        "modified_utc": _iso_from_timestamp(stat.st_mtime if stat is not None else None),
        "accessed_utc": _iso_from_timestamp(stat.st_atime if stat is not None else None),
        "metadata_changed_utc": _iso_from_timestamp(stat.st_ctime if stat is not None else None),
        "mode": oct(stat.st_mode) if stat is not None else "",
        "uid": str(stat.st_uid) if stat is not None else "",
        "gid": str(stat.st_gid) if stat is not None else "",
        "scan_status": status,
        "error": error,
        "created_at": created_at,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "id", "case_id", "computer_id", "image_id", "tool_output_id",
        "tool_name", "source_csv", "row_number", "partition_id",
        "filesystem_type", "source_root", "file_path", "parent_path",
        "file_name", "extension", "file_size", "is_directory",
        "created_utc", "modified_utc", "accessed_utc",
        "metadata_changed_utc", "mode", "uid", "gid", "scan_status",
        "error", "created_at",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            output = {column: row.get(column, "") for column in columns}
            writer.writerow(output)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scan_mounted_filesystem(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    mount_path: Path,
    partition_id: str | None = None,
    filesystem_type: str | None = None,
    replace_existing: bool = True,
) -> dict[str, Any]:
    if image.computer_id is None:
        raise ValueError("Mounted filesystem inventory requires an image with a computer_id")
    output_dir = paths.outputs_dir(case_id) / image.id / TOOL_NAME
    csv_path = output_dir / "filesystem_entries.csv"
    tool_output_id = str(uuid.uuid4())
    created_at = utc_now()
    rows: list[dict[str, Any]] = []
    row_number = 0
    for dirpath, dirnames, filenames in os.walk(mount_path, topdown=True, followlinks=False, onerror=lambda _exc: None):
        current = Path(dirpath)
        entries = [current / name for name in sorted(dirnames)] + [current / name for name in sorted(filenames)]
        for entry in entries:
            row_number += 1
            rows.append(
                _row_from_path(
                    case_id=case_id,
                    image=image,
                    tool_output_id=tool_output_id,
                    source_csv=csv_path,
                    row_number=row_number,
                    mount_path=mount_path,
                    path=entry,
                    partition_id=partition_id,
                    filesystem_type=filesystem_type,
                    created_at=created_at,
                )
            )
    content_sha256 = _write_csv(csv_path, rows)
    if replace_existing:
        db.purge_tool_data(case_id=case_id, image_id=image.id, tool_names=[TOOL_NAME])
    db.insert_tool_output(
        {
            "id": tool_output_id,
            "case_id": case_id,
            "computer_id": image.computer_id,
            "image_id": image.id,
            "tool_name": TOOL_NAME,
            "output_type": "csv",
            "path": csv_path,
            "content_sha256": content_sha256,
            "row_count": len(rows),
        }
    )
    db.insert_filesystem_entries(rows)
    db.log_activity(
        case_id=case_id,
        computer_id=image.computer_id,
        image_id=image.id,
        event="filesystem.inventory_completed",
        message="Mounted filesystem inventory completed",
        details={
            "mount_path": str(mount_path),
            "partition_id": partition_id,
            "filesystem_type": filesystem_type,
            "row_count": len(rows),
            "output": str(csv_path),
        },
    )
    return {
        "case_id": case_id,
        "image_id": image.id,
        "tool_name": TOOL_NAME,
        "filesystem_type": filesystem_type,
        "row_count": len(rows),
        "output": str(csv_path),
    }


def _row_from_fls_entry(
    *,
    case_id: str,
    image: EvidenceImage,
    tool_output_id: str,
    source_csv: Path,
    row_number: int,
    source_root: str,
    entry: FlsEntry,
    partition_id: str | None,
    filesystem_type: str | None,
    created_at: str,
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    rel = entry.path.replace("\\", "/").lstrip("/")
    parent = Path(rel).parent.as_posix() if rel and Path(rel).parent.as_posix() != "." else ""
    name = Path(rel).name
    if entry.system:
        status = "system"
    elif entry.active_name:
        status = "live"
    else:
        status = "deleted"
    metadata = metadata or {}
    accessed_utc = metadata.get("accessed_utc")
    if _is_fat_filesystem(filesystem_type) and isinstance(accessed_utc, str) and accessed_utc.endswith("T00:00:00Z"):
        accessed_utc = accessed_utc[:10]
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": image.computer_id,
        "image_id": image.id,
        "tool_output_id": tool_output_id,
        "tool_name": TSK_TOOL_NAME,
        "source_csv": str(source_csv),
        "row_number": row_number,
        "partition_id": partition_id,
        "filesystem_type": filesystem_type,
        "source_root": source_root,
        "file_path": rel,
        "parent_path": parent,
        "file_name": name,
        "extension": _extension(name, entry.is_directory),
        "file_size": metadata.get("file_size", ""),
        "is_directory": "true" if entry.is_directory else "false",
        "created_utc": metadata.get("created_utc"),
        "modified_utc": metadata.get("modified_utc"),
        "accessed_utc": accessed_utc,
        "metadata_changed_utc": metadata.get("metadata_changed_utc"),
        "mode": "",
        "uid": "",
        "gid": "",
        "scan_status": status,
        "error": "",
        "created_at": created_at,
    }


def _is_fat_filesystem(filesystem_type: str | None) -> bool:
    normalized = (filesystem_type or "").strip().casefold().replace("_", "").replace("-", "")
    return normalized in {"fat", "fat12", "fat16", "fat32", "vfat", "msdos"}


def _fls_entry_metadata(
    *,
    raw_image: Path,
    offset_sectors: int,
    filesystem_type: str | None,
    entry: FlsEntry,
) -> dict[str, str]:
    if entry.is_directory or entry.system or not entry.inode:
        return {}
    try:
        return read_file_metadata(
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            inode=entry.inode,
            filesystem_type=filesystem_type,
            dry_run=False,
        )
    except ToolError:
        return {}


def scan_tsk_filesystem(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    raw_image: Path,
    offset_sectors: int,
    partition_id: str | None = None,
    filesystem_type: str | None = None,
    replace_existing: bool = True,
) -> dict[str, Any]:
    if image.computer_id is None:
        raise ValueError("TSK filesystem inventory requires an image with a computer_id")
    output_dir = paths.outputs_dir(case_id) / image.id / TSK_TOOL_NAME
    csv_path = output_dir / "filesystem_entries.csv"
    tool_output_id = str(uuid.uuid4())
    created_at = utc_now()
    fls_entries = list_files(
        db=db,
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        raw_image=raw_image,
        offset_sectors=offset_sectors,
        filesystem_type=filesystem_type,
        output_folder=paths.jobs_dir(case_id) / "tsk" / image.id / "filesystem-inventory",
        dry_run=False,
    )
    source_root = f"{raw_image}@{offset_sectors}"
    rows = []
    for index, entry in enumerate(fls_entries, start=1):
        metadata = _fls_entry_metadata(
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            filesystem_type=filesystem_type,
            entry=entry,
        )
        rows.append(
            _row_from_fls_entry(
                case_id=case_id,
                image=image,
                tool_output_id=tool_output_id,
                source_csv=csv_path,
                row_number=index,
                source_root=source_root,
                entry=entry,
                metadata=metadata,
                partition_id=partition_id,
                filesystem_type=filesystem_type,
                created_at=created_at,
            )
        )
    content_sha256 = _write_csv(csv_path, rows)
    if replace_existing:
        db.purge_tool_data(case_id=case_id, image_id=image.id, tool_names=[TSK_TOOL_NAME])
    db.insert_tool_output(
        {
            "id": tool_output_id,
            "case_id": case_id,
            "computer_id": image.computer_id,
            "image_id": image.id,
            "tool_name": TSK_TOOL_NAME,
            "output_type": "csv",
            "path": csv_path,
            "content_sha256": content_sha256,
            "row_count": len(rows),
        }
    )
    db.insert_filesystem_entries(rows)
    db.log_activity(
        case_id=case_id,
        computer_id=image.computer_id,
        image_id=image.id,
        event="filesystem.tsk_inventory_completed",
        message="TSK filesystem inventory completed",
        details={
            "source": str(raw_image),
            "offset_sectors": offset_sectors,
            "partition_id": partition_id,
            "filesystem_type": filesystem_type,
            "row_count": len(rows),
            "output": str(csv_path),
        },
    )
    return {
        "case_id": case_id,
        "image_id": image.id,
        "tool_name": TSK_TOOL_NAME,
        "filesystem_type": filesystem_type,
        "row_count": len(rows),
        "output": str(csv_path),
    }
