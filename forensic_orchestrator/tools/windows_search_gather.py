from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote


GATHER_FIELDS = [
    "source_file",
    "source_name",
    "log_type",
    "line_number",
    "timestamp_utc",
    "filetime_hex",
    "time_low_hex",
    "time_high_hex",
    "item_url",
    "item_path",
    "item_scheme",
    "is_deleted_path",
    "status_hex",
    "crawl_code_hex",
    "scope_id",
    "document_id",
    "raw_fields_json",
]


def parse_windows_search_gather_logs_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for path in _iter_gather_logs(source):
        rows.extend(_parse_gather_log(path))

    csv_path = output / "WindowsSearchGatherLogs.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GATHER_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _iter_gather_logs(source: Path) -> list[Path]:
    if not source.exists():
        return []
    if source.is_file():
        return [source] if source.suffix.lower() in {".gthr", ".crwl"} else []
    return sorted(
        path
        for path in source.rglob("*")
        if path.is_file() and path.suffix.lower() in {".gthr", ".crwl"}
    )


def _parse_gather_log(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    text = path.read_text(encoding="utf-16-le", errors="replace")
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.lstrip("\ufeff").strip("\r\n")
        if not line:
            continue
        fields = line.split("\t")
        rows.append(_row_from_fields(path, line_number, fields))
    return rows


def _row_from_fields(path: Path, line_number: int, fields: list[str]) -> dict[str, object]:
    time_low = _field(fields, 0)
    time_high = _field(fields, 1)
    item_url = _field(fields, 2)
    item_path = _path_from_url(item_url)
    scheme = item_url.split(":", 1)[0].lower() if ":" in item_url else ""
    return {
        "source_file": str(path),
        "source_name": path.name,
        "log_type": path.suffix.lower().lstrip("."),
        "line_number": line_number,
        "timestamp_utc": _filetime_from_hex_parts(time_high, time_low),
        "filetime_hex": _filetime_hex(time_high, time_low),
        "time_low_hex": time_low,
        "time_high_hex": time_high,
        "item_url": item_url,
        "item_path": item_path,
        "item_scheme": scheme,
        "is_deleted_path": "true" if "/$extend/$deleted/" in item_url.lower() else "false",
        "status_hex": _field(fields, 3),
        "crawl_code_hex": _field(fields, 5),
        "scope_id": _field(fields, 7),
        "document_id": _field(fields, 9),
        "raw_fields_json": json.dumps(fields, ensure_ascii=False),
    }


def _field(fields: list[str], index: int) -> str:
    return fields[index].strip() if index < len(fields) else ""


def _filetime_from_hex_parts(high_hex: str, low_hex: str) -> str:
    hex_value = _filetime_hex(high_hex, low_hex)
    if not hex_value:
        return ""
    try:
        value = int(hex_value, 16)
    except ValueError:
        return ""
    if value <= 0:
        return ""
    timestamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value / 10)
    return timestamp.isoformat()


def _filetime_hex(high_hex: str, low_hex: str) -> str:
    if not high_hex or not low_hex:
        return ""
    return f"{high_hex}{low_hex.zfill(8)}"


def _path_from_url(item_url: str) -> str:
    if not item_url.lower().startswith("file:"):
        return ""
    path = unquote(item_url[5:])
    if path.startswith("///"):
        path = path[2:]
    path = path.lstrip("/")
    return path.replace("/", "\\")
