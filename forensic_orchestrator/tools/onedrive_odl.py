from __future__ import annotations

import csv
import gzip
import json
import os
import re
import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ONEDRIVE_ODL_FIELDS = [
    "user_profile",
    "account",
    "source_path",
    "source_name",
    "log_type",
    "record_index",
    "odl_version",
    "one_drive_version",
    "windows_version",
    "timestamp_utc",
    "code_file",
    "function",
    "flags",
    "context_data",
    "event_type",
    "local_path",
    "url",
    "resource_id",
    "params_text",
    "params_json",
    "raw_strings_json",
    "parser_status",
    "error",
]

ODL_SIGNATURE = b"EBFGONED"
BLOCK_SIGNATURE = b"\xCC\xDD\xEE\xFF"
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL_RE = re.compile(r"https?://[^\s,;\"')\]}]+", re.I)
WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:\\(?![\\/])[^<>:\"|?*\r\n]+")
RESOURCE_ID_RE = re.compile(r"(?i)\b[0-9a-f]{32}(?:\+\d+)?\b|[A-Z0-9]{8,}![0-9]+(?:\.[0-9]+)?")
OBFUSCATION_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{2,}")


def parse_onedrive_odl_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    obfuscation_maps = _load_obfuscation_maps(source)
    for path in _walk_odl_files(source):
        try:
            parsed = _parse_odl_file(path, obfuscation_maps=obfuscation_maps)
        except Exception as exc:  # pragma: no cover - defensive per-file isolation
            parsed = [_error_row(path, f"{type(exc).__name__}: {exc}")]
        rows.extend(parsed)
    csv_path = output / "OneDriveOdlEvents.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ONEDRIVE_ODL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _walk_odl_files(source: Path) -> Iterable[Path]:
    if not source.exists():
        return []
    paths: list[Path] = []
    for root, _, filenames in os.walk(source, onerror=lambda exc: None):
        root_path = Path(root)
        if "onedrive" not in root_path.as_posix().lower():
            continue
        for filename in filenames:
            if filename.lower().endswith((".odl", ".odlgz", ".odlsent", ".aodl", ".aold")):
                paths.append(root_path / filename)
    return sorted(paths)


def _parse_odl_file(path: Path, *, obfuscation_maps: dict[Path, dict[str, str]] | None = None) -> list[dict[str, object]]:
    data = _read_log_bytes(path)
    if not data.startswith(ODL_SIGNATURE) and path.suffix.lower() == ".odlgz":
        try:
            data = gzip.decompress(data)
        except OSError:
            pass
    if len(data) < 12 or not data.startswith(ODL_SIGNATURE):
        return [_error_row(path, "Missing EBFGONED ODL signature")]
    version = struct.unpack_from("<I", data, 8)[0]
    offset = 12
    one_drive_version = ""
    windows_version = ""
    obfuscation_map = _obfuscation_map_for_file(path, obfuscation_maps or {})
    if version == 1:
        if len(data) < offset + 84:
            return [_error_row(path, "Truncated ODL v1 header")]
        one_drive_version = _nul_string(data[offset + 16 : offset + 16 + 0x44])
        offset += 84
    elif version in {2, 3}:
        if len(data) < offset + 244:
            return [_error_row(path, "Truncated ODL v2/v3 header")]
        one_drive_version = _nul_string(data[offset + 16 : offset + 16 + 0x40])
        windows_version = _nul_string(data[offset + 16 + 0x40 : offset + 16 + 0x80])
        offset += 244
    else:
        return [_error_row(path, f"Unsupported ODL version: {version}")]

    if data[offset : offset + 4] == b"\x1f\x8b\x08\x00":
        try:
            data = zlib.decompress(data[offset:], 31)
        except zlib.error as exc:
            return [_error_row(path, f"ODL payload gzip decompression failed: {exc}")]
        offset = 0

    rows: list[dict[str, object]] = []
    record_index = 1
    while offset + 8 <= len(data):
        if data[offset : offset + 4] != BLOCK_SIGNATURE:
            next_offset = data.find(BLOCK_SIGNATURE, offset + 1)
            if next_offset == -1:
                break
            offset = next_offset
        try:
            row, offset = _parse_block(
                path,
                data,
                offset,
                version=version,
                record_index=record_index,
                one_drive_version=one_drive_version,
                windows_version=windows_version,
                obfuscation_map=obfuscation_map,
            )
        except ValueError as exc:
            rows.append(_error_row(path, str(exc), record_index=record_index))
            break
        rows.append(row)
        record_index += 1
    if not rows:
        rows.append(_error_row(path, "No ODL records parsed"))
    return rows


def _parse_block(
    path: Path,
    data: bytes,
    offset: int,
    *,
    version: int,
    record_index: int,
    one_drive_version: str,
    windows_version: str,
    obfuscation_map: dict[str, str],
) -> tuple[dict[str, object], int]:
    if version == 3:
        if offset + 32 > len(data):
            raise ValueError("Truncated ODL v3 block")
        _, context_len, unknown_flag, timestamp, _, _, data_len, _ = struct.unpack_from("<IHHQIIII", data, offset)
        header_size = 32 + context_len
        context_raw = data[offset + 32 : offset + header_size]
        payload_offset = offset + header_size
    else:
        if offset + 56 > len(data):
            raise ValueError("Truncated ODL v1/v2 block")
        _, context_len, unknown_flag, timestamp = struct.unpack_from("<IHHQ", data, offset)
        data_len = struct.unpack_from("<I", data, offset + 48)[0]
        header_size = 56
        context_raw = b""
        payload_offset = offset + header_size
    if data[offset : offset + 4] != BLOCK_SIGNATURE:
        raise ValueError("Invalid ODL block signature")
    if data_len < 0 or payload_offset + data_len > len(data):
        raise ValueError("Truncated ODL block payload")

    payload = data[payload_offset : payload_offset + data_len]
    code_file, flags, function, params = _parse_payload(payload, version=version, context_len=context_len)
    strings = _extract_strings(params, obfuscation_map=obfuscation_map)
    context_data = _extract_context_data(context_raw, obfuscation_map=obfuscation_map) if context_raw else ""
    params_text = " | ".join(strings[:25])
    local_path = _first_match(WINDOWS_PATH_RE, strings)
    url = _first_match(URL_RE, strings)
    resource_id = _first_match(RESOURCE_ID_RE, strings + [context_data, function, code_file])
    row = _base_row(path)
    row.update(
        {
            "record_index": record_index,
            "odl_version": str(version),
            "one_drive_version": one_drive_version,
            "windows_version": windows_version,
            "timestamp_utc": _unix_ms_to_iso(timestamp),
            "code_file": code_file,
            "function": function,
            "flags": str(flags),
            "context_data": context_data,
            "event_type": _classify_event(" ".join([code_file, function, context_data, params_text])),
            "local_path": local_path,
            "url": url,
            "resource_id": resource_id,
            "params_text": params_text,
            "params_json": json.dumps({"strings": strings[:100]}, ensure_ascii=False),
            "raw_strings_json": json.dumps(strings[:100], ensure_ascii=False),
            "parser_status": "parsed",
            "error": "",
        }
    )
    return row, payload_offset + data_len


def _parse_payload(payload: bytes, *, version: int, context_len: int) -> tuple[str, int, str, bytes]:
    if version == 3 and context_len == 0:
        if len(payload) < 28:
            return "", 0, "", payload
        cursor = 24
    else:
        cursor = 0
    if cursor + 4 > len(payload):
        return "", 0, "", payload
    code_len = struct.unpack_from("<I", payload, cursor)[0]
    cursor += 4
    if code_len < 0 or cursor + code_len + 8 > len(payload):
        return "", 0, "", payload
    code_file = payload[cursor : cursor + code_len].decode("utf-8", errors="ignore").rstrip("\x00")
    cursor += code_len
    flags = struct.unpack_from("<I", payload, cursor)[0]
    cursor += 4
    func_len = struct.unpack_from("<I", payload, cursor)[0]
    cursor += 4
    if func_len < 0 or cursor + func_len > len(payload):
        return code_file, flags, "", payload[cursor:]
    function = payload[cursor : cursor + func_len].decode("utf-8", errors="ignore").rstrip("\x00")
    cursor += func_len
    return code_file, flags, function, payload[cursor:]


def _read_log_bytes(path: Path) -> bytes:
    if path.suffix.lower() == ".odlgz":
        try:
            with gzip.open(path, "rb") as handle:
                return handle.read()
        except OSError:
            return path.read_bytes()
    return path.read_bytes()


def _extract_strings(data: bytes, *, obfuscation_map: dict[str, str] | None = None) -> list[str]:
    strings = [
        match.group(0).decode("utf-8", errors="replace").strip("\x00")
        for match in ASCII_RE.finditer(data)
    ]
    strings.extend(
        match.group(0).decode("utf-16le", errors="replace").strip("\x00")
        for match in UTF16_RE.finditer(data)
    )
    seen: set[str] = set()
    deduped: list[str] = []
    for item in strings:
        clean = _apply_obfuscation(item.strip(), obfuscation_map or {})
        if not clean or clean in seen:
            continue
        seen.add(clean)
        deduped.append(clean)
    return deduped


def _extract_context_data(data: bytes, *, obfuscation_map: dict[str, str] | None = None) -> str:
    strings = _extract_strings(data, obfuscation_map=obfuscation_map)
    if strings:
        return " ".join(strings)
    if len(data) < 3:
        return ""
    try:
        length = int.from_bytes(data[1:3], "little")
        if 3 + length <= len(data):
            return _apply_obfuscation(data[3 : 3 + length].decode("utf-8", errors="ignore"), obfuscation_map or {})
    except ValueError:
        return ""
    return ""


def _classify_event(text: str) -> str:
    lower = text.lower()
    for token, event in (
        ("delete", "delete"),
        ("remove", "delete"),
        ("upload", "upload"),
        ("download", "download"),
        ("hydrate", "hydrate"),
        ("dehydrate", "dehydrate"),
        ("rename", "rename"),
        ("move", "move"),
        ("error", "error"),
        ("fail", "error"),
        ("sync", "sync"),
        ("create", "create"),
        ("update", "update"),
    ):
        if token in lower:
            return event
    if URL_RE.search(text):
        return "url"
    if WINDOWS_PATH_RE.search(text):
        return "path_reference"
    return "log_record"


def _base_row(path: Path) -> dict[str, object]:
    return {
        "user_profile": _user_profile_from_path(path),
        "account": _onedrive_account_from_path(path),
        "source_path": str(path),
        "source_name": path.name,
        "log_type": path.name.split("-", 1)[0],
        "record_index": "",
        "odl_version": "",
        "one_drive_version": "",
        "windows_version": "",
        "timestamp_utc": "",
        "code_file": "",
        "function": "",
        "flags": "",
        "context_data": "",
        "event_type": "",
        "local_path": "",
        "url": "",
        "resource_id": "",
        "params_text": "",
        "params_json": "",
        "raw_strings_json": "",
        "parser_status": "",
        "error": "",
    }


def _error_row(path: Path, error: str, *, record_index: int | None = None) -> dict[str, object]:
    row = _base_row(path)
    row["record_index"] = "" if record_index is None else str(record_index)
    row["timestamp_utc"] = _timestamp_from_filename(path) or _unix_to_iso(path.stat().st_mtime)
    row["parser_status"] = "error"
    row["error"] = error
    return row


def _timestamp_from_filename(path: Path) -> str:
    match = re.search(r"(?P<date>\d{4}-\d{2}-\d{2})\.(?P<hour>\d{2})(?P<minute>\d{2})", path.name)
    if not match:
        return ""
    return f"{match.group('date')}T{match.group('hour')}:{match.group('minute')}:00+00:00"


def _unix_ms_to_iso(value: int) -> str:
    if not value:
        return ""
    try:
        return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _unix_to_iso(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _nul_string(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")


def _first_match(pattern: re.Pattern[str], values: list[str]) -> str:
    for value in values:
        match = pattern.search(value)
        if match:
            return _clean_extracted_match(match.group(0))
    return ""


def _clean_extracted_match(value: str) -> str:
    value = value.strip()
    value = re.split(r"\s+https?(?:://)?", value, maxsplit=1, flags=re.I)[0].rstrip()
    while value and value[-1] in ",;":
        value = value[:-1].rstrip()
    return value


def _load_obfuscation_maps(source: Path) -> dict[Path, dict[str, str]]:
    maps: dict[Path, dict[str, str]] = {}
    if not source.exists():
        return maps
    for root, _, filenames in os.walk(source, onerror=lambda exc: None):
        if "ObfuscationStringMap.txt" not in filenames:
            continue
        path = Path(root) / "ObfuscationStringMap.txt"
        mapping = _read_obfuscation_map(path)
        if mapping:
            maps[path.parent] = mapping
    return maps


def _read_obfuscation_map(path: Path) -> dict[str, str]:
    data = path.read_bytes()
    encoding = _detect_text_encoding(data)
    text = data.decode(encoding, errors="replace").lstrip("\ufeff")
    mapping: dict[str, str] = {}
    previous_key = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        if "\t" in line:
            key, value = line.split("\t", 1)
            key = key.strip()
            if not key:
                previous_key = ""
                continue
            mapping[key] = value
            previous_key = key
        elif previous_key:
            mapping[previous_key] = f"{mapping[previous_key]}\n{line}"
    return mapping


def _detect_text_encoding(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return "utf-16"
    sample = data[:4096]
    if sample.count(b"\x00") > len(sample) // 5:
        return "utf-16le"
    return "utf-8"


def _obfuscation_map_for_file(path: Path, maps: dict[Path, dict[str, str]]) -> dict[str, str]:
    if not maps:
        return {}
    candidates = [directory for directory in maps if directory == path.parent or directory in path.parents]
    if candidates:
        best = max(candidates, key=lambda item: len(item.parts))
        return maps[best]

    logs_dir = _onedrive_logs_dir(path)
    if not logs_dir:
        return {}
    sibling_maps = [mapping for directory, mapping in sorted(maps.items()) if directory.parent == logs_dir]
    merged: dict[str, str] = {}
    for mapping in sibling_maps:
        for key, value in mapping.items():
            merged.setdefault(key, value)
    return merged


def _onedrive_logs_dir(path: Path) -> Path | None:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    for index in range(len(parts) - 1, -1, -1):
        if lowered[index] == "logs" and index >= 1 and lowered[index - 1] == "onedrive":
            return Path(*parts[: index + 1])
    return None


def _apply_obfuscation(text: str, mapping: dict[str, str]) -> str:
    if not text or not mapping:
        return text

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        return mapping.get(token, token)

    return OBFUSCATION_TOKEN_RE.sub(replace, text)


def _user_profile_from_path(path: Path) -> str:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    if "users" in lowered:
        index = lowered.index("users")
        if index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _onedrive_account_from_path(path: Path) -> str:
    parts = path.parts
    for part in reversed(parts):
        if part.lower() == "personal" or re.fullmatch(r"(?i)business\d+", part):
            return part
    return ""
