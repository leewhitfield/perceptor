from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from shutil import which
from typing import Any

from .evidence_sources import evidence_metadata_rows


def collect_image_metadata(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(evidence_metadata_rows(path))
    rows.extend(_filesystem_metadata(path))
    rows.extend(_segment_metadata(path))
    rows.extend(_ewfinfo_metadata(path))
    return rows


def _filesystem_metadata(path: Path) -> list[dict[str, Any]]:
    stat = path.stat()
    return [
        {"source": "filesystem", "key": "path", "value": str(path)},
        {"source": "filesystem", "key": "file_name", "value": path.name},
        {"source": "filesystem", "key": "extension", "value": path.suffix.lower()},
        {"source": "filesystem", "key": "size_bytes", "value": stat.st_size},
        {"source": "filesystem", "key": "modified_time_utc", "value": _iso_from_epoch(stat.st_mtime)},
        {"source": "filesystem", "key": "accessed_time_utc", "value": _iso_from_epoch(stat.st_atime)},
        {"source": "filesystem", "key": "metadata_changed_time_utc", "value": _iso_from_epoch(stat.st_ctime)},
    ]


def _segment_metadata(path: Path) -> list[dict[str, Any]]:
    segments = _ewf_segments(path)
    if not segments:
        return []
    total_size = sum(segment.stat().st_size for segment in segments if segment.exists())
    return [
        {"source": "filesystem", "key": "segment_count", "value": len(segments)},
        {"source": "filesystem", "key": "segment_first", "value": segments[0].name},
        {"source": "filesystem", "key": "segment_last", "value": segments[-1].name},
        {"source": "filesystem", "key": "segment_total_size_bytes", "value": total_size},
    ]


def _ewf_segments(path: Path) -> list[Path]:
    match = re.match(r"^(?P<stem>.+)\.[Ee](?P<number>\d{2,3})$", path.name)
    if not match:
        return []
    pattern = f"{match.group('stem')}.[Ee][0-9][0-9]*"
    return sorted(path.parent.glob(pattern), key=lambda item: item.name.lower())


def _ewfinfo_metadata(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower()[:2] != ".e" or which("ewfinfo") is None:
        return []
    try:
        completed = subprocess.run(
            ["ewfinfo", "-d", "iso8601", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [{"source": "ewfinfo", "key": "status", "value": "failed"}]
    if completed.returncode != 0:
        return [
            {"source": "ewfinfo", "key": "status", "value": "failed"},
            {"source": "ewfinfo", "key": "error", "value": (completed.stderr or "").strip()[:500]},
        ]
    rows = [{"source": "ewfinfo", "key": "status", "value": "parsed"}]
    for key, value in _parse_ewfinfo(completed.stdout).items():
        rows.append({"source": "ewfinfo", "key": key, "value": value})
    return rows


def _parse_ewfinfo(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    section = ""
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ":" not in line:
            section = _normalize_key(line)
            continue
        key, value = line.split(":", 1)
        normalized = _normalize_key(key)
        if section and normalized:
            normalized = f"{section}.{normalized}"
        if normalized:
            values[normalized] = value.strip()
    return values


def _normalize_key(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "_", value.strip().lower()).strip("_")
    return text


def _iso_from_epoch(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
