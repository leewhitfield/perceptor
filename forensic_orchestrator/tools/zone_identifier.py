from __future__ import annotations

import csv
import datetime
import json
import os
from pathlib import Path
from urllib.parse import urlparse


ZONE_IDENTIFIER_FIELDS = [
    "source_path",
    "file_path",
    "user_profile",
    "stream_name",
    "zone_id",
    "classification",
    "referrer_url",
    "referrer_host",
    "host_url",
    "host",
    "timestamp_utc",
    "details_json",
]


def parse_zone_identifier_ads_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    if source.exists():
        manifest_rows = _load_manifest_rows(source)
        if manifest_rows:
            for manifest_row in manifest_rows:
                artifact_path = Path(manifest_row.get("artifact_path") or "")
                original_path = manifest_row.get("original_path") or str(artifact_path)
                if artifact_path.is_file() and _is_zone_identifier_stream(original_path):
                    row = _row_for_zone_identifier(artifact_path, original_path=original_path)
                    if row:
                        rows.append(row)
        else:
            candidates = [source] if source.is_file() else _zone_identifier_candidates(source)
            for path in candidates:
                if path.is_file() and _is_zone_identifier_stream(path):
                    row = _row_for_zone_identifier(path)
                    if row:
                        rows.append(row)
    csv_path = output / "ZoneIdentifierADS.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ZONE_IDENTIFIER_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _load_manifest_rows(source: Path) -> list[dict[str, str]]:
    manifest_path = source / "_artifact_manifest.csv"
    if not manifest_path.exists():
        return []
    rows: list[dict[str, str]] = []
    with manifest_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            original_path = row.get("original_path") or row.get("artifact_path") or ""
            if _is_zone_identifier_stream(original_path):
                rows.append(dict(row))
    return rows


def _zone_identifier_candidates(source: Path) -> list[Path]:
    candidates: list[Path] = []
    for root, dirs, files in os.walk(source, onerror=lambda exc: None):
        dirs.sort()
        files.sort()
        for name in files:
            if name.lower().endswith(":zone.identifier"):
                candidates.append(Path(root) / name)
    return candidates


def _row_for_zone_identifier(path: Path, *, original_path: str | None = None) -> dict[str, object] | None:
    values = _parse_key_values(path)
    if not values:
        return None
    zone_id = values.get("zoneid") or values.get("zone_id")
    if not zone_id:
        return None
    referrer_url = values.get("referrerurl") or values.get("referrer_url") or ""
    host_url = values.get("hosturl") or values.get("host_url") or ""
    return {
        "source_path": str(path),
        "file_path": _stream_host_path(original_path or str(path)),
        "user_profile": _user_from_path(original_path or str(path)),
        "stream_name": "Zone.Identifier",
        "zone_id": zone_id,
        "classification": "downloaded_file" if zone_id == "3" else "zone_identifier",
        "referrer_url": referrer_url,
        "referrer_host": _host_from_url(referrer_url),
        "host_url": host_url,
        "host": _host_from_url(host_url),
        "timestamp_utc": _mtime(path),
        "details_json": json.dumps({"zone_transfer": values}, sort_keys=True),
    }


def _parse_key_values(path: Path) -> dict[str, str]:
    text = _read_text(path)
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("[") or line.startswith(";") or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            continue
        normalized_key = key.strip().lower()
        if normalized_key:
            values[normalized_key] = value.strip()
    return values


def _read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    for encoding in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _is_zone_identifier_stream(path: Path | str) -> bool:
    return str(path).lower().endswith(":zone.identifier")


def _stream_host_path(path: Path | str) -> str:
    text = str(path)
    suffix = ":Zone.Identifier"
    if text.lower().endswith(suffix.lower()):
        return text[: -len(suffix)]
    return text


def _user_from_path(path: Path | str) -> str:
    parts = Path(str(path).replace("\\", "/")).parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    return parsed.netloc.lower()


def _mtime(path: Path) -> str:
    try:
        return datetime.datetime.fromtimestamp(path.stat().st_mtime, tz=datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except OSError:
        return ""
