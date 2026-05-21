from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any


def taskband_pin_rows_from_registry_artifact(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
) -> list[dict[str, Any]]:
    if str(row.get("artifact") or "").lower() != "taskbar_usage":
        return []
    if str(row.get("value_name") or "").lower() != "favorites":
        return []
    raw = _raw_bytes(row)
    if not raw:
        return []
    strings = _candidate_strings(raw)
    pins = _pin_names(strings)
    rows: list[dict[str, Any]] = []
    for index, pin_name in enumerate(pins, start=1):
        rows.append(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "computer_id": computer_id,
                "image_id": image_id,
                "tool_output_id": tool_output_id,
                "tool_name": tool_name,
                "source_csv": source_csv,
                "row_number": row_number,
                "source_path": row.get("source_path"),
                "hive_type": row.get("hive_type"),
                "user_profile": row.get("user_profile"),
                "pin_order": index,
                "pin_name": pin_name,
                "target_hint": _target_hint(pin_name),
                "key_path": row.get("key_path"),
                "key_last_write_utc": row.get("key_last_write_utc"),
                "details_json": json.dumps(
                    {
                        "value_name": row.get("value_name"),
                        "extracted_strings": strings,
                        "parser_note": "Taskband Favorites contains pinned taskbar state, not MRU activity.",
                    },
                    sort_keys=True,
                ),
            }
        )
    return rows


def _raw_bytes(row: dict[str, Any]) -> bytes:
    for key in ("value_data_hex", "value_data"):
        value = str(row.get(key) or "").strip()
        if not value:
            continue
        compact = re.sub(r"[^0-9a-fA-F]", "", value)
        if len(compact) >= 4 and len(compact) % 2 == 0:
            try:
                return bytes.fromhex(compact)
            except ValueError:
                continue
    return b""


def _candidate_strings(raw: bytes) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()
    for value in [*_utf16_strings(raw), *_ascii_strings(raw)]:
        clean = value.strip("\x00 ").strip()
        if len(clean) < 3 or not any(char.isalnum() for char in clean):
            continue
        if clean.lower() in {"taskbar", "quick launch", "user pinned"}:
            continue
        key = clean.casefold()
        if key in seen:
            continue
        seen.add(key)
        strings.append(clean)
    return strings


def _pin_names(strings: list[str]) -> list[str]:
    candidates = []
    for value in strings:
        lower = value.lower()
        if lower.endswith((".lnk", ".exe")) or "!" in value or "_8wekyb3d8bbwe" in lower:
            candidates.append(value)
    return candidates or strings[:10]


def _target_hint(pin_name: str) -> str | None:
    if pin_name.lower().endswith(".lnk"):
        return pin_name[:-4]
    if "!" in pin_name:
        return pin_name.rsplit("!", 1)[-1] or pin_name
    if "\\" in pin_name:
        return pin_name.rsplit("\\", 1)[-1]
    return pin_name


def _utf16_strings(raw: bytes) -> list[str]:
    try:
        text = raw.decode("utf-16-le", errors="ignore")
    except UnicodeError:
        return []
    return re.findall(r"[ -~]{3,255}", text)


def _ascii_strings(raw: bytes) -> list[str]:
    try:
        text = raw.decode("latin1", errors="ignore")
    except UnicodeError:
        return []
    return re.findall(r"[ -~]{3,255}", text)
