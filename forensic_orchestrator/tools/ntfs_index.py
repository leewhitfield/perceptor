from __future__ import annotations

import csv
import json
import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from forensic_orchestrator.db import Database
from forensic_orchestrator.safety import ToolError, require_dependency


INDEX_RECORD_SIZE = 4096
SECTOR_SIZE = 512


@dataclass(frozen=True)
class IndexAttributeIds:
    index_root: str | None
    index_allocation: str | None
    bitmap: str | None


def parse_ntfs_index_to_csv(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    raw_image: Path,
    offset_sectors: int,
    output: Path,
) -> list[Path]:
    require_dependency("istat")
    require_dependency("icat")
    output.mkdir(parents=True, exist_ok=True)
    directories = _target_directories(db, case_id=case_id, image_id=image_id)
    entries_csv = output / "NtfsIndexEntries.csv"
    bitmaps_csv = output / "NtfsIndexBitmaps.csv"
    entry_rows: list[dict[str, Any]] = []
    bitmap_rows: list[dict[str, Any]] = []
    for directory in directories:
        try:
            attributes = _index_attribute_ids(raw_image, offset_sectors, directory["entry_number"])
            bitmap = _read_attribute(raw_image, offset_sectors, directory["entry_number"], attributes.bitmap)
            active_blocks = _bitmap_active_blocks(bitmap)
            bitmap_rows.append(
                {
                    "directory_entry_number": directory["entry_number"],
                    "directory_path": directory["directory_path"],
                    "index_root_attr": attributes.index_root or "",
                    "index_allocation_attr": attributes.index_allocation or "",
                    "bitmap_attr": attributes.bitmap or "",
                    "bitmap_hex": bitmap.hex(),
                    "active_block_count": len(active_blocks),
                    "active_blocks": json.dumps(active_blocks),
                }
            )
            root = _read_attribute(raw_image, offset_sectors, directory["entry_number"], attributes.index_root)
            entry_rows.extend(
                _rows_for_entries(
                    directory=directory,
                    entries=parse_index_root(root),
                    source="index_root",
                    block_vcn=None,
                    block_active=True,
                )
            )
            allocation = _read_attribute(
                raw_image, offset_sectors, directory["entry_number"], attributes.index_allocation
            )
            for block_number, block in enumerate(_blocks(allocation, INDEX_RECORD_SIZE)):
                if not block.startswith(b"INDX"):
                    continue
                entry_rows.extend(
                    _rows_for_entries(
                        directory=directory,
                        entries=parse_indx_block(block),
                        source="index_allocation",
                        block_vcn=block_number,
                        block_active=block_number in active_blocks,
                    )
                )
        except Exception as exc:
            existing = next(
                (
                    item
                    for item in reversed(bitmap_rows)
                    if item["directory_entry_number"] == directory["entry_number"] and not item.get("error")
                ),
                None,
            )
            if existing is not None:
                existing["error"] = str(exc)
            else:
                bitmap_rows.append(
                    {
                        "directory_entry_number": directory["entry_number"],
                        "directory_path": directory["directory_path"],
                        "index_root_attr": "",
                        "index_allocation_attr": "",
                        "bitmap_attr": "",
                        "bitmap_hex": "",
                        "active_block_count": 0,
                        "active_blocks": "[]",
                        "error": str(exc),
                    }
                )
    _write_csv(entries_csv, entry_rows, NTFS_INDEX_ENTRY_FIELDS)
    _write_csv(bitmaps_csv, bitmap_rows, NTFS_INDEX_BITMAP_FIELDS)
    return [entries_csv, bitmaps_csv]


def parse_ntfs_index_with_mftecmd_to_csv(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    raw_image: Path,
    offset_sectors: int,
    output: Path,
    mftecmd_executable: Path,
    dotnet_path: Path | str,
) -> list[Path]:
    require_dependency("istat")
    require_dependency("icat")
    output.mkdir(parents=True, exist_ok=True)
    raw_dir = output / "i30_streams"
    raw_dir.mkdir(parents=True, exist_ok=True)
    mftecmd_dir = output / "mftecmd"
    mftecmd_dir.mkdir(parents=True, exist_ok=True)
    directories = _target_directories(db, case_id=case_id, image_id=image_id)
    entries_csv = output / "NtfsIndexEntries.csv"
    bitmaps_csv = output / "NtfsIndexBitmaps.csv"
    entry_rows: list[dict[str, Any]] = []
    bitmap_rows: list[dict[str, Any]] = []
    for directory in directories:
        try:
            attributes = _index_attribute_ids(raw_image, offset_sectors, directory["entry_number"])
            bitmap = _read_attribute(raw_image, offset_sectors, directory["entry_number"], attributes.bitmap)
            active_blocks = _bitmap_active_blocks(bitmap)
            bitmap_rows.append(
                {
                    "directory_entry_number": directory["entry_number"],
                    "directory_path": directory["directory_path"],
                    "index_root_attr": attributes.index_root or "",
                    "index_allocation_attr": attributes.index_allocation or "",
                    "bitmap_attr": attributes.bitmap or "",
                    "bitmap_hex": bitmap.hex(),
                    "active_block_count": len(active_blocks),
                    "active_blocks": json.dumps(active_blocks),
                    "error": "",
                }
            )
            allocation = _read_attribute(
                raw_image, offset_sectors, directory["entry_number"], attributes.index_allocation
            )
            if not allocation:
                continue
            if b"INDX" not in allocation:
                raise ToolError(
                    "$INDEX_ALLOCATION:$I30 contains no INDX records; stream is zero-filled or not materialized"
                )
            stream_path = raw_dir / f"{_safe_name(directory['entry_number'] + '_' + directory['directory_path'])}_I30.bin"
            stream_path.write_bytes(allocation)
            per_dir_csv = mftecmd_dir / f"{stream_path.stem}.csv"
            command = [
                str(dotnet_path),
                str(mftecmd_executable),
                "-f",
                str(stream_path),
                "--csv",
                str(mftecmd_dir),
                "--csvf",
                per_dir_csv.name,
            ]
            completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
            if completed.returncode != 0:
                raise ToolError(f"MFTECmd $I30 parse failed for {directory['directory_path']}: {completed.stderr.strip()}")
            entry_rows.extend(
                _mftecmd_i30_rows(
                    per_dir_csv,
                    directory=directory,
                    active_blocks=active_blocks,
                    index_record_size=INDEX_RECORD_SIZE,
                )
            )
        except Exception as exc:
            existing = next(
                (
                    item
                    for item in reversed(bitmap_rows)
                    if item["directory_entry_number"] == directory["entry_number"] and not item.get("error")
                ),
                None,
            )
            if existing is not None:
                existing["error"] = str(exc)
            else:
                bitmap_rows.append(
                    {
                        "directory_entry_number": directory["entry_number"],
                        "directory_path": directory["directory_path"],
                        "index_root_attr": "",
                        "index_allocation_attr": "",
                        "bitmap_attr": "",
                        "bitmap_hex": "",
                        "active_block_count": 0,
                        "active_blocks": "[]",
                        "error": str(exc),
                    }
                )
    _write_csv(entries_csv, entry_rows, NTFS_INDEX_ENTRY_FIELDS)
    _write_csv(bitmaps_csv, bitmap_rows, NTFS_INDEX_BITMAP_FIELDS)
    return [entries_csv, bitmaps_csv]


def _mftecmd_i30_rows(
    csv_path: Path,
    *,
    directory: dict[str, str],
    active_blocks: list[int],
    index_record_size: int,
) -> list[dict[str, Any]]:
    if not csv_path.exists():
        return []
    rows = []
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            offset = _int_text(row.get("Offset"))
            block_vcn = offset // index_record_size if offset is not None else None
            rows.append(
                {
                    "directory_entry_number": directory["entry_number"],
                    "directory_path": directory["directory_path"],
                    "source": "mftecmd_i30",
                    "block_vcn": "" if block_vcn is None else str(block_vcn),
                    "block_active": "" if block_vcn is None else str(block_vcn in active_blocks).lower(),
                    "entry_offset": row.get("Offset", ""),
                    "index_entry_length": "",
                    "index_entry_flags": "",
                    "referenced_entry_number": row.get("SelfMftEntry", ""),
                    "referenced_sequence_number": row.get("SelfMftSequence", ""),
                    "parent_entry_number": row.get("ParentMftEntry", ""),
                    "parent_sequence_number": row.get("ParentMftSequence", ""),
                    "file_name": row.get("FileName", ""),
                    "name_type": row.get("NameType", ""),
                    "name_type_label": row.get("NameType", ""),
                    "created_fn": row.get("CreatedOn", ""),
                    "modified_fn": row.get("ContentModifiedOn", ""),
                    "record_changed_fn": row.get("RecordModifiedOn", ""),
                    "accessed_fn": row.get("LastAccessedOn", ""),
                    "allocated_size": row.get("PhysicalSize", ""),
                    "real_size": row.get("LogicalSize", ""),
                    "file_flags": row.get("Flags", ""),
                    "from_slack": str(row.get("FromSlack", "")).lower(),
                    "source_file": row.get("SourceFile", ""),
                }
            )
    return rows


def parse_index_root(data: bytes) -> list[dict[str, Any]]:
    if len(data) < 32:
        return []
    index_header_offset = 16
    return _parse_entries_from_index_header(data, index_header_offset, source_offset=0)


def parse_indx_block(data: bytes) -> list[dict[str, Any]]:
    fixed = _apply_update_sequence_array(data)
    if not fixed.startswith(b"INDX") or len(fixed) < 40:
        return []
    index_header_offset = 24
    return _parse_entries_from_index_header(fixed, index_header_offset, source_offset=0)


def _parse_entries_from_index_header(data: bytes, index_header_offset: int, *, source_offset: int) -> list[dict[str, Any]]:
    entries_offset = _u32(data, index_header_offset)
    entries_size = _u32(data, index_header_offset + 4)
    if entries_offset <= 0 or entries_size <= 0:
        return []
    cursor = index_header_offset + entries_offset
    end = min(index_header_offset + entries_size, len(data))
    rows = []
    while cursor + 16 <= end:
        entry_length = _u16(data, cursor + 8)
        filename_length = _u16(data, cursor + 10)
        flags = _u32(data, cursor + 12)
        if entry_length < 16 or cursor + entry_length > len(data):
            break
        if flags & 0x02:
            break
        if filename_length >= 66:
            parsed = _parse_file_name_entry(data[cursor : cursor + entry_length], filename_length)
            if parsed is not None:
                parsed["entry_offset"] = source_offset + cursor
                parsed["index_entry_length"] = entry_length
                parsed["index_entry_flags"] = _hex(flags, 8)
                rows.append(parsed)
        cursor += entry_length
    return rows


def _parse_file_name_entry(entry: bytes, filename_length: int) -> dict[str, Any] | None:
    content = entry[16 : 16 + filename_length]
    if len(content) < 66:
        return None
    file_ref_raw = _u64(entry, 0)
    parent_ref_raw = _u64(content, 0)
    name_length = content[64]
    namespace = content[65]
    name_bytes = content[66 : 66 + name_length * 2]
    if len(name_bytes) != name_length * 2:
        return None
    try:
        file_name = name_bytes.decode("utf-16le", errors="replace")
    except UnicodeDecodeError:
        file_name = ""
    return {
        "referenced_entry_number": _mft_entry_number(file_ref_raw),
        "referenced_sequence_number": _mft_sequence_number(file_ref_raw),
        "parent_entry_number": _mft_entry_number(parent_ref_raw),
        "parent_sequence_number": _mft_sequence_number(parent_ref_raw),
        "created_fn": _filetime(_u64(content, 8)),
        "modified_fn": _filetime(_u64(content, 16)),
        "record_changed_fn": _filetime(_u64(content, 24)),
        "accessed_fn": _filetime(_u64(content, 32)),
        "allocated_size": str(_u64(content, 40)),
        "real_size": str(_u64(content, 48)),
        "file_flags": _hex(_u32(content, 56), 8),
        "name_type": str(namespace),
        "name_type_label": _name_type_label(namespace),
        "file_name": file_name,
    }


def _target_directories(db: Database, *, case_id: str, image_id: str) -> list[dict[str, str]]:
    parent_paths: set[str] = set()
    rows = db.conn.execute(
        """
        SELECT details_json FROM activity_log
        WHERE case_id = ? AND image_id = ? AND event = 'artifact.skipped_live_orphan'
        ORDER BY created_at DESC
        """,
        (case_id, image_id),
    ).fetchall()
    for row in rows:
        try:
            details = json.loads(row["details_json"] or "{}")
        except json.JSONDecodeError:
            continue
        for sample_path in details.get("sample", []):
            parent = str(Path(str(sample_path).replace("\\", "/")).parent).strip(".")
            if parent:
                parent_paths.add(parent)
    if not parent_paths:
        parent_paths.update(_deleted_mft_parent_paths(db, case_id=case_id, image_id=image_id))
    if not parent_paths:
        return []
    names = sorted({Path(path).name for path in parent_paths})
    placeholders = ", ".join("?" for _ in names)
    sql = f"""
        SELECT entry_number, parent_path, file_name
        FROM mft_entries
        WHERE case_id = ?
          AND image_id = ?
          AND COALESCE(is_directory, '') IN ('True', 'true', '1')
          AND COALESCE(in_use, '') IN ('True', 'true', '1')
          AND file_name IN ({placeholders})
        ORDER BY parent_path, file_name
    """
    directory_rows = _duckdb_rows(db, case_id=case_id, table="mft_entries", sql=sql, params=[case_id, image_id, *names])
    if directory_rows is None:
        directory_rows = [dict(row) for row in db.conn.execute(sql, [case_id, image_id, *names]).fetchall()]
    return [
        {
            "entry_number": str(row["entry_number"]),
            "directory_path": _join_path(row["parent_path"], row["file_name"]),
        }
        for row in directory_rows
        if row["entry_number"] and _join_path(row["parent_path"], row["file_name"]) in parent_paths
    ]


def _deleted_mft_parent_paths(db: Database, *, case_id: str, image_id: str) -> set[str]:
    sql = """
        SELECT DISTINCT parent_path
        FROM mft_entries
        WHERE case_id = ?
          AND image_id = ?
          AND COALESCE(is_directory, '') NOT IN ('True', 'true', '1')
          AND COALESCE(is_ads, '') NOT IN ('True', 'true', '1')
          AND COALESCE(in_use, '') NOT IN ('True', 'true', '1', 'Yes', 'yes')
          AND COALESCE(parent_path, '') != ''
        ORDER BY parent_path
    """
    rows = _duckdb_rows(db, case_id=case_id, table="mft_entries", sql=sql, params=[case_id, image_id])
    if rows is None:
        rows = [dict(row) for row in db.conn.execute(sql, [case_id, image_id]).fetchall()]
    paths: set[str] = set()
    for row in rows:
        parent = _normalize_directory_path(row.get("parent_path"))
        if parent and not parent.lower().startswith("pathunknown/"):
            paths.add(parent)
    return paths


def _normalize_directory_path(value: object) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if text.startswith("./"):
        text = text[2:]
    return text.strip("/")


def _duckdb_rows(
    db: Database,
    *,
    case_id: str,
    table: str,
    sql: str,
    params: list[object],
) -> list[dict[str, object]] | None:
    if db.analytics is None:
        return None
    try:
        conn = db.analytics._connect(case_id)
        if not conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1",
            [table],
        ).fetchone():
            return None
        result = conn.execute(sql, params)
        columns = [item[0] for item in result.description]
        return [dict(zip(columns, row)) for row in result.fetchall()]
    except Exception:
        return None


def _index_attribute_ids(raw_image: Path, offset_sectors: int, inode: str) -> IndexAttributeIds:
    completed = subprocess.run(
        ["istat", "-f", "ntfs", "-o", str(offset_sectors), str(raw_image), inode],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ToolError(f"istat failed for directory inode {inode}: {completed.stderr.strip()}")
    index_root = None
    index_allocation = None
    bitmap = None
    for line in completed.stdout.splitlines():
        if "Name: $I30" not in line:
            continue
        if "Type: $INDEX_ROOT" in line:
            index_root = _attribute_address(line)
        elif "Type: $INDEX_ALLOCATION" in line:
            index_allocation = _attribute_address(line)
        elif "Type: $BITMAP" in line:
            bitmap = _attribute_address(line)
    return IndexAttributeIds(index_root=index_root, index_allocation=index_allocation, bitmap=bitmap)


def _attribute_address(line: str) -> str | None:
    match = __import__("re").search(r"\((\d+-\d+)\)", line)
    return match.group(1) if match else None


def _read_attribute(raw_image: Path, offset_sectors: int, inode: str, attribute: str | None) -> bytes:
    if not attribute:
        return b""
    completed = subprocess.run(
        ["icat", "-f", "ntfs", "-o", str(offset_sectors), str(raw_image), f"{inode}-{attribute}"],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ToolError(f"icat failed for directory inode {inode}-{attribute}: {completed.stderr.decode(errors='replace')}")
    return completed.stdout


def _rows_for_entries(
    *,
    directory: dict[str, str],
    entries: list[dict[str, Any]],
    source: str,
    block_vcn: int | None,
    block_active: bool,
) -> list[dict[str, Any]]:
    rows = []
    for entry in entries:
        rows.append(
            {
                "directory_entry_number": directory["entry_number"],
                "directory_path": directory["directory_path"],
                "source": source,
                "block_vcn": "" if block_vcn is None else str(block_vcn),
                "block_active": str(block_active).lower(),
                **entry,
            }
        )
    return rows


def _apply_update_sequence_array(data: bytes) -> bytes:
    if len(data) < 8:
        return data
    usa_offset = _u16(data, 4)
    usa_count = _u16(data, 6)
    if usa_offset <= 0 or usa_count <= 1 or usa_offset + usa_count * 2 > len(data):
        return data
    mutable = bytearray(data)
    for index in range(1, usa_count):
        replacement_offset = usa_offset + index * 2
        sector_end = index * SECTOR_SIZE - 2
        if sector_end + 2 <= len(mutable):
            mutable[sector_end : sector_end + 2] = mutable[replacement_offset : replacement_offset + 2]
    return bytes(mutable)


def _bitmap_active_blocks(bitmap: bytes) -> list[int]:
    active = []
    for byte_index, value in enumerate(bitmap):
        for bit in range(8):
            if value & (1 << bit):
                active.append(byte_index * 8 + bit)
    return active


def _blocks(data: bytes, size: int):
    for offset in range(0, len(data), size):
        yield data[offset : offset + size]


def _int_text(value: str | None) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return int(str(value).strip(), 10)
    except ValueError:
        return None


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value)[:180]


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0] if offset + 2 <= len(data) else 0


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0] if offset + 4 <= len(data) else 0


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0] if offset + 8 <= len(data) else 0


def _mft_entry_number(reference: int) -> str:
    return str(reference & 0x0000FFFFFFFFFFFF)


def _mft_sequence_number(reference: int) -> str:
    return str((reference >> 48) & 0xFFFF)


def _filetime(value: int) -> str:
    if value <= 0:
        return ""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    try:
        return (epoch + timedelta(microseconds=value / 10)).isoformat()
    except OverflowError:
        return ""


def _hex(value: int, width: int) -> str:
    return f"0x{value:0{width}x}"


def _name_type_label(value: int) -> str:
    return {
        0: "posix",
        1: "win32",
        2: "dos",
        3: "win32_dos",
    }.get(value, str(value))


def _join_path(parent: str | None, name: str | None) -> str:
    parent_text = str(parent or "").replace("\\", "/")
    if parent_text.startswith("./"):
        parent_text = parent_text[2:]
    parent_text = parent_text.strip("/")
    name_text = str(name or "").replace("\\", "/").strip("/")
    return f"{parent_text}/{name_text}" if parent_text else name_text


NTFS_INDEX_ENTRY_FIELDS = [
    "directory_entry_number",
    "directory_path",
    "source",
    "block_vcn",
    "block_active",
    "entry_offset",
    "index_entry_length",
    "index_entry_flags",
    "referenced_entry_number",
    "referenced_sequence_number",
    "parent_entry_number",
    "parent_sequence_number",
    "file_name",
    "name_type",
    "name_type_label",
    "created_fn",
    "modified_fn",
    "record_changed_fn",
    "accessed_fn",
    "allocated_size",
    "real_size",
    "file_flags",
    "from_slack",
    "source_file",
]

NTFS_INDEX_BITMAP_FIELDS = [
    "directory_entry_number",
    "directory_path",
    "index_root_attr",
    "index_allocation_attr",
    "bitmap_attr",
    "bitmap_hex",
    "active_block_count",
    "active_blocks",
    "error",
]
