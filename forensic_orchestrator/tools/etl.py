from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - exercised when optional dependency is unavailable
    from dissect.etl import ETL
except Exception:  # pragma: no cover
    ETL = None  # type: ignore[assignment]


ETL_FIELDS = [
    "source_file",
    "source_name",
    "parser_status",
    "parser_error",
    "timestamp_utc",
    "provider_name",
    "provider_id",
    "provider_label",
    "event_category",
    "event_name",
    "event_id",
    "opcode",
    "version",
    "process_id",
    "parent_process_id",
    "session_id",
    "image_name",
    "command_line",
    "user_sid",
    "package_full_name",
    "flags",
    "payload_strings_json",
    "event_values_json",
    "file_size",
    "sha256_first_mb",
]

PATH_RE = re.compile(r"(?i)([a-z]:\\[^<>:\"|?*\r\n]+|\\device\\[^<>:\"|?*\r\n]+|\\\\[^<>:\"|?*\r\n]+)")
EXE_RE = re.compile(r"(?i)(?:^|[\\/])[^\\/]+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|msi|scr)\b")
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def parse_etl_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for path, error in _walk_etl_files(source):
        if error:
            rows.append(_error_row(path or source, error))
            continue
        if path is None:
            continue
        rows.append(_inventory_row(path))
        rows.extend(_parse_etl_file(path))
    csv_path = output / "EtlEvents.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ETL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _walk_etl_files(source: Path) -> Iterable[tuple[Path | None, str]]:
    if not source.exists():
        yield source, "source path does not exist"
        return
    if source.is_file():
        if source.suffix.lower() == ".etl":
            yield source, ""
        return
    for root, dirnames, filenames in os.walk(source, onerror=lambda exc: None):
        root_path = Path(root)
        kept = []
        for dirname in dirnames:
            candidate = root_path / dirname
            try:
                candidate.stat()
            except OSError as exc:
                yield candidate, str(exc)
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            if not filename.lower().endswith(".etl"):
                continue
            path = root_path / filename
            try:
                path.stat()
            except OSError as exc:
                yield path, str(exc)
                continue
            yield path, ""


def _inventory_row(path: Path) -> dict[str, object]:
    row = _base_row(path, "inventory")
    try:
        stat = path.stat()
        row["file_size"] = str(stat.st_size)
        row["sha256_first_mb"] = _sha256_first_mb(path)
    except OSError as exc:
        row["parser_status"] = "error"
        row["parser_error"] = str(exc)
    return row


def _parse_etl_file(path: Path) -> list[dict[str, object]]:
    if ETL is None:
        return [_error_row(path, "dissect.etl is not installed")]
    rows: list[dict[str, object]] = []
    try:
        with path.open("rb") as handle:
            etl = ETL(handle)
            for index, event in enumerate(etl, start=1):
                rows.append(_event_row(path, event, index))
    except Exception as exc:
        if not rows:
            return [_error_row(path, f"{type(exc).__name__}: {exc}"), *_string_scan_rows(path)]
        rows.append(_error_row(path, f"partial parse stopped: {type(exc).__name__}: {exc}"))
    return rows


def _event_row(path: Path, event: Any, row_number: int) -> dict[str, object]:
    record = event
    parsed_event = getattr(event, "event", event)
    header = getattr(record, "header", getattr(parsed_event, "_header", None))
    values = _event_values(parsed_event)
    strings = _payload_strings(parsed_event, values, header)
    row = _base_row(path, "parsed")
    timestamp = _safe_call(parsed_event, "ts") or getattr(header, "timestamp", None)
    provider_id = _safe_call(parsed_event, "provider_id") or getattr(header, "provider_id", None)
    provider_name = _safe_call(parsed_event, "provider_name")
    symbol = _safe_call(parsed_event, "symbol")
    row.update(
        {
            "timestamp_utc": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp or ""),
            "provider_name": str(provider_name or ""),
            "provider_id": str(provider_id or ""),
            "event_name": str(symbol or _first_value(values, "EventName", "EventType", "TaskName", "Task Name") or ""),
            "event_id": _first_value(values, "EventId", "EventID", "id"),
            "opcode": _first_value(values, "opcode", "Opcode") or str(getattr(header, "opcode", "") or ""),
            "version": _first_value(values, "version", "Version") or str(getattr(header, "version", "") or ""),
            "process_id": _first_value(values, "ProcessID", "ProcessId", "PID", "Process") or str(getattr(header, "process_id", "") or ""),
            "parent_process_id": _first_value(values, "ParentProcessID", "ParentProcessId", "ParentPID"),
            "session_id": _first_value(values, "SessionID", "SessionId"),
            "image_name": _first_value(values, "ImageName", "ImagePath", "ProcessName") or _first_process_path(strings),
            "command_line": _first_value(values, "CommandLine", "Command Line") or _first_command_line(strings),
            "user_sid": _first_value(values, "UserSID", "UserSid", "SID"),
            "package_full_name": _first_value(values, "PackageFullName", "PackageName"),
            "flags": _first_value(values, "Flags"),
            "payload_strings_json": json.dumps(strings[:100], ensure_ascii=False),
            "event_values_json": json.dumps(_jsonable(values), ensure_ascii=False, default=str, sort_keys=True),
        }
    )
    _apply_event_labels(row)
    return row


def _apply_event_labels(row: dict[str, object]) -> None:
    source_name = str(row.get("source_name") or "")
    provider_name = str(row.get("provider_name") or "")
    provider_id = str(row.get("provider_id") or "")
    event_name = str(row.get("event_name") or "")
    image_name = str(row.get("image_name") or "")
    command_line = str(row.get("command_line") or "")
    provider_label = _provider_label(source_name, provider_id, provider_name, event_name)
    event_category = _event_category(
        source_name,
        provider_label,
        provider_name,
        event_name,
        image_name,
        command_line,
    )
    row["provider_label"] = provider_label
    row["event_category"] = event_category


def _provider_label(source_name: str, provider_id: str, provider_name: str, event_name: str) -> str:
    source_lower = source_name.lower()
    provider_lower = provider_name.lower()
    event_lower = event_name.lower()
    provider_id_lower = provider_id.lower()
    if "kernel-process" in provider_lower or "process" in event_lower and "kernel" in provider_lower:
        return "Microsoft-Windows-Kernel-Process"
    if provider_id_lower == "68fdd900-4a3e-11d1-84f4-0000f80464e3":
        return "Windows Kernel Trace/EventTrace"
    if source_lower.startswith("cldflt"):
        return "Microsoft Cloud Files Filter (CldFlt)"
    if "diagtrack" in source_lower:
        return "DiagTrack AutoLogger"
    if "diaglog" in source_lower:
        return "Windows Diagnostics AutoLogger"
    if "defender" in source_lower:
        return "Microsoft Defender AutoLogger"
    if "eventlog" in source_lower:
        return "Windows EventLog AutoLogger"
    if "wfp" in source_lower or "ipsec" in source_lower:
        return "Windows Filtering Platform/IPsec AutoLogger"
    if "ubpm" in source_lower:
        return "Unified Background Process Manager AutoLogger"
    if "sgrm" in source_lower:
        return "System Guard Runtime Monitor AutoLogger"
    if "wifi" in source_lower or "wlan" in source_lower:
        return "Wi-Fi AutoLogger"
    if "radiomgr" in source_lower:
        return "Radio Manager AutoLogger"
    if "netcore" in source_lower or "lwtnetlog" in source_lower:
        return "Network AutoLogger"
    return provider_name or provider_id or ""


def _event_category(
    source_name: str,
    provider_label: str,
    provider_name: str,
    event_name: str,
    image_name: str,
    command_line: str,
) -> str:
    text = " ".join([source_name, provider_label, provider_name, event_name]).lower()
    if image_name or command_line or "kernel-process" in text or "processstart" in text or "process started" in text:
        return "process_execution"
    if "cldflt" in text or "cloud files" in text:
        return "cloud_files"
    if "eventtraceevent/" in event_name.lower() or "kernel trace" in text:
        return "etl_session_metadata"
    if "diagtrack" in text:
        return "telemetry_autologger"
    if "diaglog" in text:
        return "diagnostics_autologger"
    if "defender" in text:
        return "security_defender"
    if "eventlog" in text:
        return "eventlog_trace"
    if "wfp" in text or "ipsec" in text:
        return "network_filtering"
    if "ubpm" in text:
        return "power_management"
    if "sgrm" in text:
        return "system_guard"
    if "wifi" in text or "wlan" in text:
        return "wifi"
    if "radiomgr" in text:
        return "radio_manager"
    if "netcore" in text or "lwtnetlog" in text:
        return "network"
    return "etl_event"


def _event_values(event: Any) -> dict[str, Any]:
    try:
        values = event.event_values()
    except Exception:
        values = {}
    return dict(values or {})


def _payload_strings(event: Any, values: dict[str, Any], header: Any | None = None) -> list[str]:
    strings: list[str] = []
    for value in values.values():
        if isinstance(value, str):
            strings.append(value)
    header = header or getattr(event, "_header", None)
    payload = getattr(header, "payload", b"") if header is not None else b""
    try:
        data = bytes(payload)
    except Exception:
        data = b""
    strings.extend(_extract_strings(data))
    return _dedupe(strings)


def _extract_strings(data: bytes) -> list[str]:
    strings = [match.group(0).decode("ascii", errors="ignore") for match in ASCII_RE.finditer(data)]
    for match in UTF16_RE.finditer(data):
        try:
            strings.append(match.group(0).decode("utf-16-le", errors="ignore"))
        except UnicodeDecodeError:
            continue
    return [item.strip("\x00 ") for item in strings if item.strip("\x00 ")]


def _safe_call(event: Any, name: str) -> Any:
    try:
        attr = getattr(event, name)
        return attr() if callable(attr) else attr
    except Exception:
        return None


def _first_value(values: dict[str, Any], *names: str) -> str:
    lowered = {str(key).lower(): value for key, value in values.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value)
    return ""


def _first_process_path(strings: list[str]) -> str:
    for item in strings:
        if PATH_RE.search(item) and EXE_RE.search(item):
            return PATH_RE.search(item).group(1)  # type: ignore[union-attr]
    for item in strings:
        if EXE_RE.search(item):
            return item
    return ""


def _first_command_line(strings: list[str]) -> str:
    for item in strings:
        if EXE_RE.search(item) and (" " in item or "\t" in item):
            return item
    return ""


def _base_row(path: Path, status: str) -> dict[str, object]:
    row = {field: "" for field in ETL_FIELDS} | {
        "source_file": str(path),
        "source_name": path.name,
        "parser_status": status,
    }
    _apply_event_labels(row)
    return row


def _error_row(path: Path, error: str) -> dict[str, object]:
    return _base_row(path, "error") | {"parser_error": error}


def _string_scan_rows(path: Path) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    interesting = [
        item
        for item in _dedupe(_extract_strings(data))
        if PATH_RE.search(item) or EXE_RE.search(item) or "Process" in item or "CommandLine" in item
    ]
    rows = []
    for index, chunk in enumerate(_chunk_strings(interesting, size=50), start=1):
        row = _base_row(path, "strings")
        row["image_name"] = _first_process_path(chunk)
        row["command_line"] = _first_command_line(chunk)
        row["payload_strings_json"] = json.dumps(chunk, ensure_ascii=False)
        row["event_values_json"] = json.dumps({"fallback": "raw ETL string scan", "chunk": index}, sort_keys=True)
        _apply_event_labels(row)
        rows.append(row)
        if index >= 20:
            break
    return rows


def _chunk_strings(values: list[str], *, size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _jsonable(values: dict[str, Any]) -> dict[str, object]:
    result = {}
    for key, value in values.items():
        if isinstance(value, bytes):
            result[str(key)] = {"bytes_hex_prefix": value[:64].hex(), "size": len(value)}
        else:
            result[str(key)] = str(value) if not isinstance(value, (str, int, float, bool, type(None))) else value
    return result


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _sha256_first_mb(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        digest.update(handle.read(1024 * 1024))
    return digest.hexdigest()
