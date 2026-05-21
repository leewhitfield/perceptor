from __future__ import annotations

import csv
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse


OFFICE_BACKSTAGE_FIELDS = [
    "artifact_type", "source_path", "user_profile", "application", "name",
    "value", "path", "url", "host", "timestamp_utc", "details_json",
]
PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\[^\\]+\\|/Users/|/home/)[^\x00\r\n<>\"|?*]{3,500}")
URL_RE = re.compile(r"(?i)https?://[^\s\"'<>\\\x00]{4,500}")


def parse_office_backstage_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    if source.exists():
        candidates = [source] if source.is_file() else _walk_files(source)
        for item in candidates:
            if item.is_file() and _looks_office_related(item):
                rows.extend(_rows_for_file(item))
    csv_path = output / "OfficeBackstageArtifacts.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=OFFICE_BACKSTAGE_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _walk_files(source: Path) -> list[Path]:
    paths: list[Path] = []
    for root, dirnames, filenames in os.walk(source, onerror=lambda _exc: None):
        dirnames.sort()
        for filename in sorted(filenames):
            paths.append(Path(root) / filename)
    return paths


def _rows_for_file(path: Path) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    text = data.decode("utf-8", errors="ignore")
    rows: list[dict[str, object]] = []
    for url in sorted(set(URL_RE.findall(text))):
        rows.append(_row(path, "office_backstage_url", value=url, url=url, details={"parser": "string_extract"}))
    for file_path in sorted(set(match.group(0).strip().rstrip(".,;") for match in PATH_RE.finditer(text))):
        rows.append(_row(path, "office_backstage_path", value=file_path, file_path=file_path, details={"parser": "string_extract"}))
    if not rows and data:
        rows.append(_row(path, "office_backstage_file", value=path.name, details={"size": len(data), "parser": "inventory"}))
    return rows


def _row(
    source_path: Path,
    artifact_type: str,
    *,
    value: str,
    file_path: str = "",
    url: str = "",
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "artifact_type": artifact_type,
        "source_path": str(source_path),
        "user_profile": _user_from_path(source_path),
        "application": _office_application(source_path),
        "name": source_path.name,
        "value": value,
        "path": file_path,
        "url": url,
        "host": _safe_url_host(url),
        "timestamp_utc": _mtime(source_path),
        "details_json": json.dumps(details or {}, sort_keys=True),
    }


def _looks_office_related(path: Path) -> bool:
    lowered = str(path).lower()
    return (
        "microsoft/office" in lowered
        or "microsoft\\office" in lowered
        or "backstage" in lowered
        or "filemru" in lowered
        or path.suffix.lower() in {".officeui", ".dat", ".xml", ".lnk"}
    )


def _office_application(path: Path) -> str:
    lowered = str(path).lower()
    for app in ("word", "excel", "powerpoint", "outlook", "onenote", "access"):
        if app in lowered:
            return app
    return "office"


def _safe_url_host(url: str) -> str:
    if not url:
        return ""
    try:
        return urlparse(url).netloc
    except ValueError:
        return ""


def _user_from_path(path: Path) -> str:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "users":
            return parts[index + 1]
    return ""


def _mtime(path: Path) -> str:
    try:
        return path.stat().st_mtime_ns and __import__("datetime").datetime.fromtimestamp(
            path.stat().st_mtime, tz=__import__("datetime").timezone.utc
        ).isoformat().replace("+00:00", "Z")
    except OSError:
        return ""
