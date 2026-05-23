from __future__ import annotations

import csv
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


BASE_BLOCK_SIZE = 0x1000
HBIN_HEADER_SIZE = 0x20
SAM_CSV_FIELDS = [
    "source_path",
    "username",
    "rid",
    "rid_hex",
    "account_category",
    "last_login_utc",
    "password_last_set_utc",
    "last_bad_password_utc",
    "account_expires_utc",
    "logon_count",
    "bad_password_count",
    "account_flags_hex",
    "account_flags",
    "account_flags_unknown_hex",
    "registry_path",
    "account_key_last_write_utc",
]
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
SAM_ACCOUNT_FLAGS = {
    0x0001: "account_disabled",
    0x0002: "home_directory_required",
    0x0004: "password_not_required",
    0x0008: "temporary_duplicate_account",
    0x0010: "normal_account",
    0x0020: "mns_logon_account",
    0x0040: "interdomain_trust_account",
    0x0080: "workstation_trust_account",
    0x0100: "server_trust_account",
    0x0200: "password_does_not_expire",
    0x0400: "account_auto_locked",
}


@dataclass(frozen=True)
class RegistryKeyRecord:
    offset: int
    name: str
    parent_offset: int
    values: dict[str, int]
    value_data: dict[str, bytes] = field(default_factory=dict)
    last_write_utc: str | None = None


@dataclass(frozen=True)
class SamAccount:
    username: str
    rid: int
    registry_path: str
    account_key_last_write_utc: str | None = None
    last_login_utc: str | None = None
    password_last_set_utc: str | None = None
    last_bad_password_utc: str | None = None
    account_expires_utc: str | None = None
    logon_count: int | None = None
    bad_password_count: int | None = None
    account_flags: int | None = None

    @property
    def account_category(self) -> str:
        return "builtin" if self.rid < 1000 else "local"

    def as_row(self, source_path: Path) -> dict[str, object]:
        return {
            "source_path": str(source_path),
            "username": self.username,
            "rid": self.rid,
            "rid_hex": f"0x{self.rid:08X}",
            "account_category": self.account_category,
            "last_login_utc": self.last_login_utc,
            "password_last_set_utc": self.password_last_set_utc,
            "last_bad_password_utc": self.last_bad_password_utc,
            "account_expires_utc": self.account_expires_utc,
            "logon_count": self.logon_count,
            "bad_password_count": self.bad_password_count,
            "account_flags_hex": f"0x{self.account_flags:08X}" if self.account_flags is not None else None,
            "account_flags": ";".join(decode_account_flags(self.account_flags)),
            "account_flags_unknown_hex": unknown_account_flags_hex(self.account_flags),
            "registry_path": self.registry_path,
            "account_key_last_write_utc": self.account_key_last_write_utc,
        }


def parse_sam_accounts(path: Path) -> list[SamAccount]:
    records = scan_registry_keys(path.read_bytes())
    return accounts_from_registry_keys(records)


def parse_sam_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "SAMParser.csv"
    accounts = parse_sam_accounts(source)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SAM_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for account in accounts:
            writer.writerow(account.as_row(source))
    return csv_path


def decode_account_flags(flags: int | None) -> list[str]:
    if flags is None:
        return []
    return [name for bit, name in sorted(SAM_ACCOUNT_FLAGS.items()) if flags & bit]


def unknown_account_flags(flags: int | None) -> int | None:
    if flags is None:
        return None
    known_mask = 0
    for bit in SAM_ACCOUNT_FLAGS:
        known_mask |= bit
    return flags & ~known_mask


def unknown_account_flags_hex(flags: int | None) -> str | None:
    unknown = unknown_account_flags(flags)
    if unknown is None:
        return None
    return f"0x{unknown:08X}" if unknown else ""


def scan_registry_keys(data: bytes) -> dict[int, RegistryKeyRecord]:
    if len(data) < BASE_BLOCK_SIZE or data[:4] != b"regf":
        raise ValueError("Input does not look like a registry hive")
    records: dict[int, RegistryKeyRecord] = {}
    root_cell_offset = _u32(data, 0x24)
    position = BASE_BLOCK_SIZE
    while position + HBIN_HEADER_SIZE <= len(data):
        if data[position : position + 4] != b"hbin":
            position += BASE_BLOCK_SIZE
            continue
        hbin_size = _u32(data, position + 8)
        cell_position = position + HBIN_HEADER_SIZE
        hbin_end = min(position + hbin_size, len(data))
        while cell_position + 4 <= hbin_end:
            cell_size = _i32(data, cell_position)
            if cell_size == 0:
                break
            content_position = cell_position + 4
            if data[content_position : content_position + 2] == b"nk":
                cell_offset = content_position - BASE_BLOCK_SIZE - 4
                record = _parse_nk_record(data, cell_offset)
                if record is not None:
                    records[cell_offset] = record
            cell_position += abs(cell_size)
        position += hbin_size
    root_record = records.get(root_cell_offset)
    if root_record is not None and root_record.parent_offset != 0xFFFFFFFF:
        records[root_cell_offset] = RegistryKeyRecord(
            root_record.offset,
            root_record.name,
            0xFFFFFFFF,
            root_record.values,
            root_record.value_data,
            root_record.last_write_utc,
        )
    return records


def accounts_from_registry_keys(records: dict[int, RegistryKeyRecord]) -> list[SamAccount]:
    detail_records = _account_detail_records(records)
    accounts: list[SamAccount] = []
    for offset, record in records.items():
        path = _registry_path(records, offset)
        parts = path.split("/")
        if len(parts) < 2 or parts[-2].lower() != "names":
            continue
        normalized = "/".join(part.lower() for part in parts)
        if "/domains/account/users/names/" not in normalized:
            continue
        rid = record.values.get("")
        if rid is None:
            continue
        details = _account_details_from_f(detail_records.get(rid, b""))
        accounts.append(
            SamAccount(
                username=record.name,
                rid=rid,
                registry_path=path,
                account_key_last_write_utc=record.last_write_utc,
                last_login_utc=details["last_login_utc"],
                password_last_set_utc=details["password_last_set_utc"],
                last_bad_password_utc=details["last_bad_password_utc"],
                account_expires_utc=details["account_expires_utc"],
                logon_count=details["logon_count"],
                bad_password_count=details["bad_password_count"],
                account_flags=details["account_flags"],
            )
        )
    return sorted(accounts, key=lambda account: account.rid)


def _parse_nk_record(data: bytes, cell_offset: int) -> RegistryKeyRecord | None:
    position = _cell_content_position(cell_offset)
    if position + 0x4C > len(data):
        return None
    parent_offset = _u32(data, position + 0x10)
    value_count = _u32(data, position + 0x24)
    value_list_offset = _u32(data, position + 0x28)
    name_length = _u16(data, position + 0x48)
    name_position = position + 0x4C
    if name_position + name_length > len(data):
        return None
    name = data[name_position : name_position + name_length].decode("latin1", errors="replace")
    value_types, value_data = _parse_values(data, value_count, value_list_offset)
    return RegistryKeyRecord(
        offset=cell_offset,
        name=name,
        parent_offset=parent_offset,
        values=value_types,
        value_data=value_data,
        last_write_utc=_filetime_to_iso(_u64(data, position + 4)),
    )


def _parse_values(
    data: bytes, value_count: int, value_list_offset: int
) -> tuple[dict[str, int], dict[str, bytes]]:
    value_types: dict[str, int] = {}
    value_data: dict[str, bytes] = {}
    if value_count == 0 or value_list_offset == 0xFFFFFFFF:
        return value_types, value_data
    list_position = _cell_content_position(value_list_offset)
    for index in range(value_count):
        if list_position + index * 4 + 4 > len(data):
            break
        value_offset = _u32(data, list_position + index * 4)
        value_position = _cell_content_position(value_offset)
        if value_position + 0x14 > len(data) or data[value_position : value_position + 2] != b"vk":
            continue
        name_length = _u16(data, value_position + 2)
        data_length_raw = _u32(data, value_position + 4)
        data_offset = _u32(data, value_position + 8)
        value_type = _u32(data, value_position + 0x0C)
        name = data[value_position + 0x14 : value_position + 0x14 + name_length].decode(
            "latin1", errors="replace"
        )
        value_types[name] = value_type
        value_data[name] = _read_value_data(data, data_length_raw, data_offset)
    return value_types, value_data


def _read_value_data(data: bytes, data_length_raw: int, data_offset: int) -> bytes:
    length = data_length_raw & 0x7FFFFFFF
    if length == 0:
        return b""
    if data_length_raw & 0x80000000:
        return struct.pack("<I", data_offset)[:length]
    if data_offset == 0xFFFFFFFF:
        return b""
    position = _cell_content_position(data_offset)
    return data[position : position + length]


def _account_detail_records(records: dict[int, RegistryKeyRecord]) -> dict[int, bytes]:
    details: dict[int, bytes] = {}
    for offset, record in records.items():
        path = _registry_path(records, offset)
        normalized = "/".join(part.lower() for part in path.split("/"))
        if "/domains/account/users/" not in normalized or "/names/" in normalized:
            continue
        try:
            rid = int(record.name, 16)
        except ValueError:
            continue
        f_value = record.value_data.get("F")
        if f_value:
            details[rid] = f_value
    return details


def _account_details_from_f(value: bytes) -> dict[str, object]:
    if len(value) < 0x44:
        return {
            "last_login_utc": None,
            "password_last_set_utc": None,
            "last_bad_password_utc": None,
            "account_expires_utc": None,
            "logon_count": None,
            "bad_password_count": None,
            "account_flags": None,
        }
    return {
        "last_login_utc": _filetime_to_iso(_u64_from_bytes(value, 0x08)),
        "password_last_set_utc": _filetime_to_iso(_u64_from_bytes(value, 0x18)),
        "last_bad_password_utc": _filetime_to_iso(_u64_from_bytes(value, 0x20)),
        "account_expires_utc": _filetime_to_iso(_u64_from_bytes(value, 0x28)),
        "account_flags": _u32_from_bytes(value, 0x38),
        "bad_password_count": _u16_from_bytes(value, 0x40),
        "logon_count": _u16_from_bytes(value, 0x42),
    }


def _filetime_to_iso(value: int | None) -> str | None:
    if not value or value in {0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}:
        return None
    try:
        timestamp = FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None
    if timestamp.year < 1990 or timestamp.year > 2100:
        return None
    return timestamp.isoformat().replace("+00:00", "Z")


def _registry_path(records: dict[int, RegistryKeyRecord], offset: int) -> str:
    parts: list[str] = []
    seen: set[int] = set()
    current = offset
    for _ in range(64):
        if current in seen or current not in records:
            break
        seen.add(current)
        record = records[current]
        parts.append(record.name)
        if record.parent_offset == 0xFFFFFFFF or record.parent_offset == current:
            break
        current = record.parent_offset
    return "/".join(reversed(parts))


def registry_path(records: dict[int, RegistryKeyRecord], offset: int) -> str:
    return _registry_path(records, offset)


def _cell_content_position(cell_offset: int) -> int:
    return BASE_BLOCK_SIZE + cell_offset + 4


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _u16_from_bytes(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def _u32_from_bytes(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _u64_from_bytes(data: bytes, offset: int) -> int | None:
    if offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, offset)[0]
