from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any


@dataclass(frozen=True)
class PidlItem:
    item_index: int
    name: str | None
    created_time: str | None
    modified_time: str | None
    accessed_time: str | None
    raw_fat_times: list[str]


def parse_pidl_items(raw: bytes) -> list[PidlItem]:
    items: list[PidlItem] = []
    offset = 0
    index = 0
    while offset + 2 <= len(raw):
        size = int.from_bytes(raw[offset : offset + 2], "little")
        if size == 0:
            break
        if size < 2 or offset + size > len(raw):
            break
        item = raw[offset : offset + size]
        parsed = _parse_item(item, index)
        if parsed.name or parsed.raw_fat_times:
            items.append(parsed)
        offset += size
        index += 1
    if not items:
        parsed = _parse_item(raw, 0)
        if parsed.name or parsed.raw_fat_times:
            items.append(parsed)
    return items


def _parse_item(item: bytes, index: int) -> PidlItem:
    times = _fat_times(item)
    extension_times = _extension_block_times(item)
    return PidlItem(
        item_index=index,
        name=_best_name(item),
        created_time=extension_times.get("created"),
        modified_time=extension_times.get("modified"),
        accessed_time=extension_times.get("accessed"),
        raw_fat_times=times,
    )


def _extension_block_times(item: bytes) -> dict[str, str | None]:
    marker = b"\x04\x00\xef\xbe"
    pos = item.find(marker)
    if pos < 0:
        return {}
    # BEEF0004 extension blocks commonly store FAT timestamps immediately after
    # the signature. Implement conservatively and keep raw candidates too.
    first = _decode_fat_datetime(item[pos + 4 : pos + 8])
    second = _decode_fat_datetime(item[pos + 8 : pos + 12])
    third = _decode_fat_datetime(item[pos + 12 : pos + 16])
    values = [value for value in (first, second, third) if value is not None]
    if len(values) < 2 or not _plausible_shell_times(values):
        return {}
    return {
        "created": values[0] if len(values) >= 1 else None,
        "modified": values[1] if len(values) >= 2 else None,
        "accessed": values[2] if len(values) >= 3 else None,
    }


def _fat_times(item: bytes) -> list[str]:
    times: list[str] = []
    seen: set[str] = set()
    for offset in range(0, max(len(item) - 3, 0)):
        decoded = _decode_fat_datetime(item[offset : offset + 4])
        if decoded is None or decoded in seen:
            continue
        seen.add(decoded)
        times.append(decoded)
    return times


def _plausible_shell_times(values: list[str]) -> bool:
    upper_bound = datetime.now(timezone.utc) + timedelta(days=366)
    for value in values:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed > upper_bound:
            return False
    return True


def _decode_fat_datetime(data: bytes) -> str | None:
    if len(data) != 4:
        return None
    time_raw = int.from_bytes(data[:2], "little")
    date_raw = int.from_bytes(data[2:], "little")
    year = ((date_raw >> 9) & 0x7F) + 1980
    month = (date_raw >> 5) & 0x0F
    day = date_raw & 0x1F
    hour = (time_raw >> 11) & 0x1F
    minute = (time_raw >> 5) & 0x3F
    second = (time_raw & 0x1F) * 2
    if not (1990 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31 and hour <= 23 and minute <= 59 and second <= 59):
        return None
    try:
        value = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None
    return value.isoformat().replace("+00:00", "Z")


def _best_name(item: bytes) -> str | None:
    unicode_names = _unicode_strings(item)
    if unicode_names:
        return unicode_names[-1]
    ascii_names = _ascii_strings(item)
    return ascii_names[-1] if ascii_names else None


def _unicode_strings(item: bytes) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for offset in range(0, len(item) - 1, 2):
        pair = item[offset : offset + 2]
        if pair == b"\x00\x00":
            _append_string(strings, current.decode("utf-16le", errors="ignore"))
            current = bytearray()
            continue
        code = int.from_bytes(pair, "little")
        if 32 <= code <= 0xD7FF:
            current.extend(pair)
        else:
            _append_string(strings, current.decode("utf-16le", errors="ignore"))
            current = bytearray()
    _append_string(strings, current.decode("utf-16le", errors="ignore"))
    return strings


def _ascii_strings(item: bytes) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in item:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            _append_string(strings, current.decode("ascii", errors="ignore"))
            current = bytearray()
    _append_string(strings, current.decode("ascii", errors="ignore"))
    return strings


def _append_string(strings: list[str], value: str) -> None:
    matches = re.findall(r"[A-Za-z0-9][A-Za-z0-9._ $(){}\[\]-]{1,255}", value)
    text = matches[-1].strip() if matches else value.strip("\x00 ").strip()
    if len(text) < 2:
        return
    if not any(char.isalnum() for char in text) or sum(ord(char) > 126 for char in text) > 0:
        return
    strings.append(text)
