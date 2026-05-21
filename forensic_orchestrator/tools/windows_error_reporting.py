from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


WER_FIELDS = [
    "source_file",
    "source_name",
    "report_folder",
    "event_type",
    "event_time_utc",
    "upload_time_utc",
    "report_type",
    "consent",
    "report_status",
    "report_identifier",
    "integrator_report_identifier",
    "app_name",
    "original_filename",
    "target_app_id",
    "target_app_version",
    "fault_module_name",
    "fault_module_version",
    "exception_code",
    "exception_offset",
    "is_fatal",
    "bucket_id",
    "legacy_bucket_id",
    "ui_path",
    "loaded_modules_json",
    "signatures_json",
    "dynamic_signatures_json",
    "ui_json",
    "raw_json",
]

INDEXED_KEY_RE = re.compile(r"^(?P<prefix>[A-Za-z]+)\[(?P<index>\d+)\]\.(?P<suffix>.+)$")
INDEXED_VALUE_RE = re.compile(r"^(?P<prefix>[A-Za-z]+)\[(?P<index>\d+)\]$")


def parse_windows_error_reporting_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows = [_parse_report(path) for path in _iter_report_files(source)]
    csv_path = output / "WindowsErrorReporting.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=WER_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _iter_report_files(source: Path) -> list[Path]:
    if not source.exists():
        return []
    if source.is_file():
        return [source] if source.name.lower() == "report.wer" or source.suffix.lower() == ".wer" else []
    reports: list[Path] = []
    for root, _dirnames, filenames in os.walk(source, onerror=lambda exc: None):
        root_path = Path(root)
        for filename in filenames:
            if filename.lower() == "report.wer" or filename.lower().endswith(".wer"):
                reports.append(root_path / filename)
    return sorted(reports)


def _parse_report(path: Path) -> dict[str, object]:
    values = _parse_key_values(_read_text(path))
    signatures = _indexed_values(values, "Sig")
    dynamic_signatures = _indexed_values(values, "DynamicSig")
    ui_values = _indexed_values(values, "UI")
    loaded_modules = _prefixed_values(values, "LoadedModule")
    sig_lookup = {
        str(item.get("Name") or "").strip().lower(): str(item.get("Value") or "").strip()
        for item in signatures
    }
    row = {
        "source_file": str(path),
        "source_name": path.name,
        "report_folder": path.parent.name,
        "event_type": values.get("EventType", ""),
        "event_time_utc": _filetime_to_iso(values.get("EventTime")),
        "upload_time_utc": _filetime_to_iso(values.get("UploadTime")),
        "report_type": values.get("ReportType", ""),
        "consent": values.get("Consent", ""),
        "report_status": values.get("ReportStatus", ""),
        "report_identifier": values.get("ReportIdentifier", ""),
        "integrator_report_identifier": values.get("IntegratorReportIdentifier", ""),
        "app_name": values.get("NsAppName") or sig_lookup.get("application name", ""),
        "original_filename": values.get("OriginalFilename", ""),
        "target_app_id": values.get("TargetAppId", ""),
        "target_app_version": values.get("TargetAppVer", ""),
        "fault_module_name": sig_lookup.get("fault module name", ""),
        "fault_module_version": sig_lookup.get("fault module version", ""),
        "exception_code": sig_lookup.get("exception code", ""),
        "exception_offset": sig_lookup.get("exception offset", ""),
        "is_fatal": values.get("IsFatal", ""),
        "bucket_id": values.get("Response.BucketId", ""),
        "legacy_bucket_id": values.get("Response.LegacyBucketId", ""),
        "ui_path": _first_ui_path(ui_values),
        "loaded_modules_json": _json(loaded_modules),
        "signatures_json": _json(signatures),
        "dynamic_signatures_json": _json(dynamic_signatures),
        "ui_json": _json(ui_values),
        "raw_json": _json(values),
    }
    return row


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-16", "utf-16-le", "utf-8-sig"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.lstrip("\ufeff").strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _indexed_values(values: dict[str, str], prefix: str) -> list[dict[str, str]]:
    grouped: dict[int, dict[str, str]] = {}
    for key, value in values.items():
        match = INDEXED_KEY_RE.match(key)
        if match and match.group("prefix") == prefix:
            grouped.setdefault(int(match.group("index")), {})[match.group("suffix")] = value
            continue
        direct_match = INDEXED_VALUE_RE.match(key)
        if direct_match and direct_match.group("prefix") == prefix:
            grouped.setdefault(int(direct_match.group("index")), {})["Value"] = value
    return [grouped[index] for index in sorted(grouped)]


def _prefixed_values(values: dict[str, str], prefix: str) -> list[str]:
    found: list[tuple[int, str]] = []
    for key, value in values.items():
        direct_match = INDEXED_VALUE_RE.match(key)
        if direct_match and direct_match.group("prefix") == prefix:
            found.append((int(direct_match.group("index")), value))
            continue
        if not key.startswith(prefix):
            continue
        suffix = key[len(prefix):]
        try:
            index = int(suffix)
        except ValueError:
            continue
        found.append((index, value))
    return [value for _index, value in sorted(found)]


def _first_ui_path(ui_values: list[dict[str, str]]) -> str:
    for item in ui_values:
        for value in item.values():
            if ":\\" in value or value.startswith("\\\\"):
                return value
    return ""


def _filetime_to_iso(value: Any) -> str:
    try:
        filetime = int(str(value or "").strip())
    except ValueError:
        return ""
    if filetime <= 0:
        return ""
    timestamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)
    return timestamp.isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
