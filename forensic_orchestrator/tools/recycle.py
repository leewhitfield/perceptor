from __future__ import annotations

import csv
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from forensic_orchestrator.tools.ingest import load_artifact_manifest


RECYCLE_CSV_FIELDS = [
    "record_type",
    "recycle_format",
    "source_path",
    "top_level_name",
    "recycled_path",
    "child_relative_path",
    "display_name",
    "original_path",
    "deletion_time_utc",
    "file_size",
    "is_directory",
    "mft_created",
    "mft_modified",
    "mft_accessed",
    "mft_record_modified",
]
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_recycle_artifacts_to_csv(sources: Iterable[Path], output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for source in sources:
        if source.exists():
            rows.extend(_parse_recycle_root(source))
    csv_path = output / "RecycleParser.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RECYCLE_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _parse_recycle_root(root: Path) -> list[dict[str, object]]:
    manifest = load_artifact_manifest(root / "placeholder")
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.name != "_artifact_manifest.csv" and "_extract_jobs" not in path.parts
    )
    xp_metadata = _xp_info2_metadata(files)
    modern_i = {path.name[2:]: path for path in files if path.name.upper().startswith("$I")}
    rows: list[dict[str, object]] = []
    emitted_top: set[str] = set()
    for path in files:
        relative = path.relative_to(root)
        parts = relative.parts
        if not parts:
            continue
        name_upper = path.name.upper()
        if name_upper == "INFO2":
            continue
        if name_upper.startswith("$I"):
            rows.append(_modern_item_row(path, root, manifest))
            emitted_top.add(path.name[2:])
            continue
        r_index = _part_index(parts, "$R")
        if r_index is not None:
            top = parts[r_index]
            suffix = top[2:]
            metadata = _modern_i_metadata(modern_i.get(suffix))
            rows.extend(_recycled_path_rows(path, root, top, "modern", metadata, manifest))
            emitted_top.add(suffix)
            continue
        dc_index = _part_index(parts, "DC")
        if name_upper.startswith("DC") or dc_index is not None:
            top = parts[dc_index] if dc_index is not None else parts[0]
            rows.extend(_recycled_path_rows(path, root, top, "xp", xp_metadata.get(_xp_key(top), {}), manifest))
            emitted_top.add(top)
    for suffix, i_file in modern_i.items():
        if suffix not in emitted_top:
            rows.append(_modern_item_row(i_file, root, manifest))
    return rows


def _modern_item_row(path: Path, root: Path, manifest: dict[str, dict[str, str]]) -> dict[str, object]:
    metadata = _modern_i_metadata(path)
    return {
        **_manifest_values(path, manifest),
        "record_type": "item",
        "recycle_format": "modern",
        "source_path": str(path),
        "top_level_name": "$R" + path.name[2:] if path.name.upper().startswith("$I") else path.name,
        "recycled_path": str(path.relative_to(root)),
        "display_name": Path(str(metadata.get("original_path") or path.name)).name,
        "original_path": metadata.get("original_path"),
        "deletion_time_utc": metadata.get("deletion_time_utc"),
        "file_size": metadata.get("file_size"),
        "is_directory": None,
    }


def _recycled_path_rows(
    path: Path,
    root: Path,
    top_name: str,
    recycle_format: str,
    metadata: dict[str, object],
    manifest: dict[str, dict[str, str]],
) -> list[dict[str, object]]:
    relative = path.relative_to(root)
    try:
        top_index = relative.parts.index(top_name)
    except ValueError:
        top_index = 0
    child_relative = Path(*relative.parts[top_index + 1 :]) if len(relative.parts) > top_index + 1 else None
    record_type = "child" if child_relative else "item"
    display_name = child_relative.name if child_relative else Path(str(metadata.get("original_path") or top_name)).name
    return [
        {
            **_manifest_values(path, manifest),
            "record_type": record_type,
            "recycle_format": recycle_format,
            "source_path": str(path),
            "top_level_name": top_name,
            "recycled_path": str(relative),
            "child_relative_path": str(child_relative) if child_relative else None,
            "display_name": display_name,
            "original_path": metadata.get("original_path"),
            "deletion_time_utc": metadata.get("deletion_time_utc"),
            "file_size": metadata.get("file_size") if record_type == "item" else path.stat().st_size,
            "is_directory": "0",
        }
    ]


def _modern_i_metadata(path: Path | None) -> dict[str, object]:
    if path is None or not path.exists():
        return {}
    data = path.read_bytes()
    if len(data) < 24:
        return {}
    version = _u64(data, 0)
    size = _u64(data, 8)
    deleted = _filetime_to_iso(_u64(data, 16))
    raw_name = data[24:]
    original = raw_name.decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()
    return {
        "version": version,
        "file_size": size,
        "deletion_time_utc": deleted,
        "original_path": original or None,
    }


def _xp_info2_metadata(files: list[Path]) -> dict[str, dict[str, object]]:
    metadata: dict[str, dict[str, object]] = {}
    for path in files:
        if path.name.upper() != "INFO2":
            continue
        data = path.read_bytes()
        if len(data) < 20:
            continue
        record_size = int.from_bytes(data[12:16], "little", signed=False) or 800
        offset = 20
        while offset + min(record_size, 280) <= len(data):
            record = data[offset : offset + record_size]
            original = record[:260].split(b"\x00", 1)[0].decode("mbcs", errors="replace") if False else record[:260].split(b"\x00", 1)[0].decode("latin1", errors="replace")
            index = int.from_bytes(record[260:264], "little", signed=False)
            deleted = _filetime_to_iso(_u64(record, 268))
            size = int.from_bytes(record[276:280], "little", signed=False) if len(record) >= 280 else None
            if index:
                metadata[f"dc{index}"] = {
                    "original_path": original or None,
                    "deletion_time_utc": deleted,
                    "file_size": size,
                }
            offset += record_size
    return metadata


def _xp_key(value: str) -> str:
    stem = Path(value).stem.lower()
    return stem


def _part_index(parts: tuple[str, ...], prefix: str) -> int | None:
    for index, part in enumerate(parts):
        if part.upper().startswith(prefix):
            return index
    return None


def _manifest_values(path: Path, manifest: dict[str, dict[str, str]]) -> dict[str, str | None]:
    metadata = manifest.get(str(path), {})
    return {
        "mft_created": metadata.get("mft_created"),
        "mft_modified": metadata.get("mft_modified"),
        "mft_accessed": metadata.get("mft_accessed"),
        "mft_record_modified": metadata.get("mft_record_modified"),
    }


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        return 0
    return struct.unpack_from("<Q", data, offset)[0]


def _filetime_to_iso(value: int) -> str | None:
    if not value:
        return None
    try:
        seconds, remainder = divmod(value, 10_000_000)
        dt = FILETIME_EPOCH + timedelta(seconds=seconds, microseconds=remainder // 10)
        if dt.year < 1990 or dt.year > 2200:
            return None
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None
