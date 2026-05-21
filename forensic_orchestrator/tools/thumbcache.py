from __future__ import annotations

import csv
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

try:
    from dissect.thumbcache import Thumbcache, ThumbcacheFile
except Exception:  # pragma: no cover - optional dependency fallback
    Thumbcache = None  # type: ignore[assignment]
    ThumbcacheFile = None  # type: ignore[assignment]


THUMBCACHE_FIELDS = [
    "source_path",
    "source_name",
    "user_profile",
    "cache_file_type",
    "cache_id",
    "entry_index",
    "entry_offset",
    "entry_size",
    "thumbnail_offset",
    "thumbnail_size",
    "thumbnail_type",
    "thumbnail_sha256",
    "source_mtime_utc",
    "parser_status",
    "parser_note",
    "details_json",
]

IMAGE_SIGNATURES = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"BM": "bmp",
    b"RIFF": "riff",
}


def parse_thumbcache_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "ThumbcacheParser.csv"
    rows: list[dict[str, object]] = []
    if source.exists():
        if source.is_file():
            rows.extend(_rows_for_thumbcache(source))
        else:
            parsed_files: set[Path] = set()
            for explorer_dir in _explorer_cache_dirs(source):
                structured_rows, files_seen = _structured_rows_for_directory(explorer_dir)
                rows.extend(structured_rows)
                parsed_files.update(files_seen)
            for path in _thumbcache_candidates(source):
                if path not in parsed_files:
                    rows.extend(_rows_for_thumbcache(path))
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=THUMBCACHE_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _thumbcache_candidates(source: Path) -> list[Path]:
    candidates: list[Path] = []
    for root, dirs, files in os.walk(source, topdown=True, onerror=lambda _exc: None, followlinks=False):
        root_path = Path(root)
        if not _could_contain_explorer_cache(root_path):
            dirs[:] = []
            continue
        for filename in files:
            path = root_path / filename
            if _is_thumbcache_file(path):
                candidates.append(path)
    return sorted(candidates)


def _could_contain_explorer_cache(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    target = ["appdata", "local", "microsoft", "windows", "explorer"]
    if "appdata" not in parts:
        if not parts:
            return True
        name = parts[-1]
        parent = parts[-2] if len(parts) > 1 else ""
        return name in {"users", "windows.old"} or parent in {"users", "windows.old"}
    start = parts.index("appdata")
    suffix = parts[start : start + len(target)]
    return suffix == target[: len(suffix)]


def _rows_for_thumbcache(path: Path) -> list[dict[str, object]]:
    structured_rows = _structured_rows_for_thumbcache(path)
    if structured_rows:
        return structured_rows
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [_status_row(path, "error", str(exc))]
    offsets = _image_offsets(data)
    if not offsets:
        return [_status_row(path, "no_embedded_images", "No embedded thumbnail image signatures were found.")]
    cmmm_offsets = [match.start() for match in re.finditer(b"CMMM", data)]
    rows = []
    for index, (thumb_offset, thumb_type) in enumerate(offsets, start=1):
        next_entry = _next_offset(cmmm_offsets, thumb_offset) or _next_thumb_offset(offsets, thumb_offset) or len(data)
        previous_entry = _previous_offset(cmmm_offsets, thumb_offset)
        entry_offset = previous_entry if previous_entry is not None else thumb_offset
        thumb_size = max(next_entry - thumb_offset, 0)
        thumbnail = data[thumb_offset : thumb_offset + thumb_size]
        cache_id = _cache_id(data, entry_offset, thumb_offset, thumbnail)
        rows.append(
            {
                "source_path": str(path),
                "source_name": path.name,
                "user_profile": _user_from_path(path),
                "cache_file_type": "iconcache" if path.name.lower().startswith("iconcache") else "thumbcache",
                "cache_id": cache_id,
                "entry_index": index,
                "entry_offset": entry_offset,
                "entry_size": max(next_entry - entry_offset, 0),
                "thumbnail_offset": thumb_offset,
                "thumbnail_size": thumb_size,
                "thumbnail_type": thumb_type,
                "thumbnail_sha256": hashlib.sha256(thumbnail).hexdigest(),
                "source_mtime_utc": _mtime(path),
                "parser_status": "parsed",
                "parser_note": "Embedded thumbnail recovered; original filename requires external correlation.",
                "details_json": json.dumps(
                    {
                        "format": "signature_scan",
                        "source_size": len(data),
                        "has_cmmm_header": data[:4] == b"CMMM",
                    },
                    sort_keys=True,
                ),
            }
        )
    return rows


def _explorer_cache_dirs(source: Path) -> list[Path]:
    dirs: set[Path] = set()
    for candidate in _thumbcache_candidates(source):
        dirs.add(candidate.parent)
    return sorted(dirs)


def _structured_rows_for_directory(path: Path) -> tuple[list[dict[str, object]], set[Path]]:
    if Thumbcache is None:
        return [], set()
    rows: list[dict[str, object]] = []
    files_seen: set[Path] = set()
    for prefix in ("thumbcache", "iconcache"):
        try:
            cache = Thumbcache(path=path, prefix=prefix)
            entries = list(cache.entries())
        except Exception:
            continue
        for index, (cache_path, entry) in enumerate(entries, start=1):
            files_seen.add(cache_path)
            rows.append(_structured_row(cache_path, entry, index))
    return rows, files_seen


def _structured_rows_for_thumbcache(path: Path) -> list[dict[str, object]]:
    if ThumbcacheFile is None:
        return []
    try:
        with path.open("rb") as handle:
            cache_file = ThumbcacheFile(handle)
            entries = list(cache_file.entries())
    except Exception:
        return []
    if not entries:
        return [_status_row(path, "no_entries", "No structured thumbcache entries were found.")]
    return [_structured_row(path, entry, index) for index, entry in enumerate(entries, start=1)]


def _structured_row(path: Path, entry: Any, index: int) -> dict[str, object]:
    data = _entry_data(entry)
    cache_hash = _entry_hash(entry)
    return {
        "source_path": str(path),
        "source_name": path.name,
        "user_profile": _user_from_path(path),
        "cache_file_type": "iconcache" if path.name.lower().startswith("iconcache") else "thumbcache",
        "cache_id": cache_hash,
        "entry_index": index,
        "entry_offset": _entry_attr(entry, "offset"),
        "entry_size": _entry_attr(entry, "size"),
        "thumbnail_offset": _entry_attr(entry, "data_offset"),
        "thumbnail_size": len(data),
        "thumbnail_type": _entry_extension(entry, data),
        "thumbnail_sha256": hashlib.sha256(data).hexdigest() if data else "",
        "source_mtime_utc": _mtime(path),
        "parser_status": "parsed" if data else "metadata_only",
        "parser_note": "Structured thumbcache entry parsed; cache_id is the Cache Entry Hash.",
        "details_json": json.dumps(
            {
                "format": "dissect.thumbcache",
                "identifier": _entry_attr(entry, "identifier"),
                "hash": cache_hash,
                "data_checksum": _bytes_hex(_entry_attr(entry, "data_checksum")),
                "header_checksum": _bytes_hex(_entry_attr(entry, "header_checksum")),
            },
            sort_keys=True,
            default=str,
        ),
    }


def _entry_data(entry: Any) -> bytes:
    try:
        data = entry.data
    except Exception:
        return b""
    return data if isinstance(data, bytes) else bytes(data or b"")


def _entry_hash(entry: Any) -> str:
    value = _entry_attr(entry, "hash")
    if value:
        return _bytes_hex(value)
    value = _entry_attr(entry, "identifier")
    return _bytes_hex(value)


def _entry_extension(entry: Any, data: bytes) -> str:
    extension = str(_entry_attr(entry, "extension") or "").lstrip(".").lower()
    if extension:
        return extension
    detected = _image_offsets(data[:32])
    return detected[0][1] if detected else ""


def _entry_attr(entry: Any, name: str) -> object:
    try:
        value = getattr(entry, name)
    except Exception:
        return ""
    if callable(value):
        try:
            value = value()
        except Exception:
            return ""
    return value


def _bytes_hex(value: object) -> str:
    if isinstance(value, bytes):
        return value.hex()
    return str(value or "")


def _image_offsets(data: bytes) -> list[tuple[int, str]]:
    offsets: list[tuple[int, str]] = []
    seen: set[int] = set()
    for signature, image_type in IMAGE_SIGNATURES.items():
        start = 0
        while True:
            offset = data.find(signature, start)
            if offset < 0:
                break
            start = offset + 1
            if offset in seen:
                continue
            if image_type == "riff" and data[offset + 8 : offset + 12] != b"WEBP":
                continue
            seen.add(offset)
            offsets.append((offset, "webp" if image_type == "riff" else image_type))
    return sorted(offsets)


def _cache_id(data: bytes, entry_offset: int, thumb_offset: int, thumbnail: bytes) -> str:
    prefix = data[entry_offset:thumb_offset]
    for size in (16, 8):
        if len(prefix) >= size:
            candidate = prefix[-size:].hex()
            if candidate.strip("0"):
                return candidate
    return hashlib.sha256(thumbnail[:4096]).hexdigest()[:32]


def _previous_offset(offsets: list[int], position: int) -> int | None:
    previous = [offset for offset in offsets if offset < position]
    return previous[-1] if previous else None


def _next_offset(offsets: list[int], position: int) -> int | None:
    for offset in offsets:
        if offset > position:
            return offset
    return None


def _next_thumb_offset(offsets: list[tuple[int, str]], position: int) -> int | None:
    for offset, _ in offsets:
        if offset > position:
            return offset
    return None


def _status_row(path: Path, status: str, note: str) -> dict[str, object]:
    return {
        "source_path": str(path),
        "source_name": path.name,
        "user_profile": _user_from_path(path),
        "cache_file_type": "iconcache" if path.name.lower().startswith("iconcache") else "thumbcache",
        "source_mtime_utc": _mtime(path),
        "parser_status": status,
        "parser_note": note,
        "details_json": "{}",
    }


def _is_thumbcache_file(path: Path) -> bool:
    name = path.name.lower()
    return (name.startswith("thumbcache") or name.startswith("iconcache")) and name.endswith(".db")


def _user_from_path(path: Path) -> str:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    for marker in ("thumbcache", "iconcache", "explorer", "cache"):
        for index, part in enumerate(parts[:-1]):
            if part.lower() == marker and index > 0:
                return parts[index - 1]
    return ""


def _mtime(path: Path) -> str:
    try:
        return datetime.datetime.fromtimestamp(path.stat().st_mtime, tz=datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except OSError:
        return ""
