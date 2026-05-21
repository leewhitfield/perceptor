from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFENDER_FIELDS = [
    "source_file",
    "source_name",
    "artifact_type",
    "line_number",
    "event_time_utc",
    "event_type",
    "component",
    "severity",
    "threat_name",
    "action",
    "path",
    "resource",
    "message",
    "file_size",
    "modified_time_utc",
    "sha256_first_mb",
    "raw_json",
]

TIMESTAMP_RE = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(?P<message>.*)$")
COMPONENT_RE = re.compile(r"^\[(?P<component>[^\]]+)\]\s*(?P<message>.*)$")
PATH_RE = re.compile(r"(?i)([a-z]:\\[^<>:\"|?*\r\n]+|\\device\\[^<>:\"|?*\r\n]+|\\\\[^<>:\"|?*\r\n]+)")
THREAT_RE = re.compile(r"(?i)\b(?:threat|malware)\s*(?:name)?\s*[:=]\s*(?P<threat>[^,;\r\n]+)")
ACTION_RE = re.compile(r"(?i)\b(action|remediation|quarantine|clean|remove|blocked|allowed)\b[^,;\r\n]*")
ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

INTERESTING_TERMS = (
    "threat",
    "detect",
    "quarantine",
    "remediat",
    "clean",
    "remove",
    "blocked",
    "allowed",
    "scan",
    "signature",
    "engine",
    "version:",
    "service started",
    "service stopped",
    "exclusion",
    "error",
    "warning",
    "failed",
    "first scan",
    "openwithoutread",
)

BINARY_SUFFIXES = {".bin", ".db", ".wal", ".shm", ".vdm", ".dll"}


def parse_windows_defender_artifacts_to_csv(source: Path | list[Path], output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for path in _iter_defender_files(source):
        if path.suffix.lower() == ".log":
            rows.extend(_parse_log(path))
        elif _is_inventory_artifact(path):
            rows.append(_inventory_row(path))
    csv_path = output / "WindowsDefenderEvents.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DEFENDER_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _iter_defender_files(source: Path | list[Path]) -> list[Path]:
    if isinstance(source, list):
        paths: list[Path] = []
        for item in source:
            paths.extend(_iter_defender_files(item))
        return sorted(set(paths))
    if not source.exists():
        return []
    if source.is_file():
        return [source]
    paths: list[Path] = []
    for root, _dirnames, filenames in os.walk(source, onerror=lambda exc: None):
        root_path = Path(root)
        for filename in filenames:
            path = root_path / filename
            name = filename.lower()
            if name.endswith(".log") or name.startswith("mpcache-") or name in {"mpdiag.bin", "mpenginedb.db"} or path.suffix.lower() in {".bin"}:
                paths.append(path)
    return sorted(paths)


def _parse_log(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    text = _read_text(path)
    artifact_type = _artifact_type(path)
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.lstrip("\ufeff").strip()
        if not line or set(line) <= {"-", "*"}:
            continue
        timestamp = ""
        message = line
        match = TIMESTAMP_RE.match(line)
        if match:
            timestamp = _normalize_iso(match.group("timestamp"))
            message = match.group("message").strip()
        if not _is_interesting(message, timestamp):
            continue
        component = ""
        component_match = COMPONENT_RE.match(message)
        if component_match:
            component = component_match.group("component")
            message = component_match.group("message").strip()
        row = _base_row(path, artifact_type)
        row.update(
            {
                "line_number": line_number,
                "event_time_utc": timestamp,
                "event_type": _classify_event(message),
                "component": component,
                "severity": _severity(message),
                "threat_name": _threat_name(message),
                "action": _action(message),
                "path": _first_path(message),
                "resource": _resource(message),
                "message": message,
                "raw_json": _json({"raw_line": line}),
            }
        )
        rows.append(row)
    if not rows:
        rows.append(_inventory_row(path, artifact_type=artifact_type, event_type="log_inventory"))
    return rows


def _inventory_row(path: Path, *, artifact_type: str | None = None, event_type: str = "artifact_inventory") -> dict[str, object]:
    row = _base_row(path, artifact_type or _artifact_type(path))
    try:
        stat = path.stat()
        row.update(
            {
                "event_type": event_type,
                "file_size": str(stat.st_size),
                "modified_time_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "sha256_first_mb": _sha256_first_mb(path),
                "message": _inventory_message(path),
                "raw_json": _json({"strings": _strings_sample(path)}),
            }
        )
    except OSError as exc:
        row.update({"event_type": "artifact_error", "severity": "error", "message": str(exc)})
    return row


def _base_row(path: Path, artifact_type: str) -> dict[str, object]:
    return {
        "source_file": str(path),
        "source_name": path.name,
        "artifact_type": artifact_type,
        "line_number": "",
        "event_time_utc": "",
        "event_type": "",
        "component": "",
        "severity": "",
        "threat_name": "",
        "action": "",
        "path": "",
        "resource": "",
        "message": "",
        "file_size": "",
        "modified_time_utc": "",
        "sha256_first_mb": "",
        "raw_json": "{}",
    }


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-16", "utf-16-le", "utf-8-sig"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text.count("\x00") < max(1, len(text) // 20):
            return text
    return data.decode("utf-8", errors="replace").replace("\x00", "")


def _is_inventory_artifact(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith("mpcache-") or name in {"mpdiag.bin", "mpenginedb.db"} or path.suffix.lower() in BINARY_SUFFIXES


def _artifact_type(path: Path) -> str:
    name = path.name.lower()
    parts = [part.lower() for part in path.parts]
    if name == "history.log":
        return "history_log"
    if name == "unknown.log":
        return "unknown_log"
    if name.startswith("mpdetection"):
        return "detection_log"
    if name.startswith("mplog"):
        return "support_log"
    if name.startswith("mpcache-"):
        return "mpcache"
    if "cachemanager" in parts:
        return "cache_manager"
    if name == "mpenginedb.db":
        return "engine_database"
    if name.startswith("mpwpptracing"):
        return "wpp_trace"
    return "defender_artifact"


def _is_interesting(message: str, timestamp: str) -> bool:
    lowered = message.lower()
    return bool(timestamp) and any(term in lowered for term in INTERESTING_TERMS)


def _classify_event(message: str) -> str:
    lowered = message.lower()
    if "onmountdetection" in lowered or "first scan" in lowered:
        return "defender_scan"
    if "engine upgrade detected" in lowered:
        return "defender_update"
    if "config change detected" in lowered or "dirtyshutdowndetected" in lowered:
        return "defender_log"
    if "threat" in lowered or "malware detected" in lowered or "detected threat" in lowered:
        return "defender_detection"
    if "quarantine" in lowered:
        return "defender_quarantine"
    if "remediat" in lowered or "clean" in lowered or "remove" in lowered:
        return "defender_remediation"
    if "exclusion" in lowered:
        return "defender_exclusion"
    if "service started" in lowered:
        return "defender_service_started"
    if "service stopped" in lowered or "service stop requested" in lowered:
        return "defender_service_stopped"
    if "version:" in lowered or "signature" in lowered or "engine" in lowered:
        return "defender_update"
    if "scan" in lowered:
        return "defender_scan"
    if "error" in lowered or "failed" in lowered or "warning" in lowered:
        return "defender_error"
    return "defender_log"


def _severity(message: str) -> str:
    lowered = message.lower()
    if any(term in lowered for term in ("severe", "critical", "threat")):
        return "high"
    if any(term in lowered for term in ("error", "failed", "warning")):
        return "warning"
    return "info"


def _threat_name(message: str) -> str:
    match = THREAT_RE.search(message)
    return match.group("threat").strip() if match else ""


def _action(message: str) -> str:
    match = ACTION_RE.search(message)
    return match.group(0).strip() if match else ""


def _first_path(message: str) -> str:
    match = PATH_RE.search(message)
    return match.group(1).strip() if match else ""


def _resource(message: str) -> str:
    for marker in ("Resource:", "resource:", "Path:", "path:"):
        if marker in message:
            return message.split(marker, 1)[1].strip()
    return ""


def _normalize_iso(value: str) -> str:
    if value.endswith("Z"):
        return value[:-1] + "+00:00"
    return value


def _inventory_message(path: Path) -> str:
    return f"Defender artifact inventory: {path.name}"


def _sha256_first_mb(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        digest.update(handle.read(1024 * 1024))
    return digest.hexdigest()


def _strings_sample(path: Path, limit: int = 40) -> list[str]:
    try:
        data = path.read_bytes()[:1024 * 1024]
    except OSError:
        return []
    strings: list[str] = []
    for match in ASCII_RE.finditer(data):
        strings.append(match.group(0).decode("ascii", errors="replace"))
        if len(strings) >= limit:
            return strings
    for match in UTF16_RE.finditer(data):
        strings.append(match.group(0).decode("utf-16-le", errors="replace"))
        if len(strings) >= limit:
            break
    return strings


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
