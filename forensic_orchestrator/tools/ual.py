from __future__ import annotations

import csv
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


UAL_FIELDS = [
    "database_file",
    "source_table",
    "record_id",
    "role_guid",
    "role_name",
    "product_name",
    "tenant_id",
    "user_sid",
    "user_name",
    "client_name",
    "client_ip",
    "client_id",
    "first_seen",
    "last_seen",
    "insert_date",
    "last_access",
    "access_count",
    "activity_count",
    "day_count",
    "raw_time_bucket",
]

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_ual_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "UalRecords.csv"
    databases = _ual_databases(source)
    if not databases:
        _write_csv(csv_path, [])
        return csv_path

    rows: list[dict[str, object]] = []
    export_root = output / "_esedbexport"
    if export_root.exists():
        shutil.rmtree(export_root)
    export_root.mkdir(parents=True)
    for database in databases:
        rows.extend(_records_from_database(database, export_root))
    _write_csv(csv_path, rows)
    return csv_path


def _ual_databases(source: Path) -> list[Path]:
    if not source.exists():
        return []
    if source.is_file() and source.suffix.lower() == ".mdb":
        return [source]
    if not source.is_dir():
        return []
    return sorted(path for path in source.rglob("*.mdb") if path.is_file())


def _records_from_database(database: Path, export_root: Path) -> list[dict[str, object]]:
    target = export_root / _safe_name(database.name)
    actual_export_dir = target.with_name(target.name + ".export")
    for export_dir in (target, actual_export_dir):
        if export_dir.exists():
            shutil.rmtree(export_dir)
    result = subprocess.run(
        ["esedbexport", "-t", str(target), str(database)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"esedbexport failed for {database} with exit code {result.returncode}: {result.stderr.strip()}"
        )
    rows: list[dict[str, object]] = []
    for table_path in sorted(actual_export_dir.iterdir() if actual_export_dir.exists() else []):
        if not table_path.is_file():
            continue
        for row in _read_tsv(table_path):
            normalized = _normalize_ual_row(database, table_path.name, row)
            if _has_ual_value(normalized):
                rows.append(normalized)
    return rows


def _normalize_ual_row(database: Path, source_table: str, row: dict[str, str]) -> dict[str, object]:
    first_seen = _time_value(_first(row, "FirstAccess", "FirstSeen", "FirstAccessTime", "FirstSeenTime", "Created"))
    last_seen = _time_value(_first(row, "LastAccess", "LastSeen", "LastAccessTime", "LastSeenTime", "Updated"))
    insert_date = _time_value(_first(row, "InsertDate", "DateInserted", "CreatedDate", "CreationTime"))
    last_access = _time_value(_first(row, "LastAccessDate", "LastAccess", "AccessDate"))
    return {
        "database_file": database.name,
        "source_table": source_table,
        "record_id": _first(row, "AutoIncId", "Id", "ID", "RecordId", "RecordID"),
        "role_guid": _guid(_first(row, "RoleGuid", "RoleId", "RoleID", "Guid", "GUID")),
        "role_name": _first(row, "RoleName", "Role", "RoleDescription", "ProviderName", "ServiceName"),
        "product_name": _first(row, "ProductName", "Product", "ProductVersion", "Service"),
        "tenant_id": _first(row, "TenantId", "TenantID", "Tenant"),
        "user_sid": _sid_or_text(_first(row, "UserSid", "Sid", "SID", "UserId", "UserID")),
        "user_name": _first(row, "UserName", "User", "AccountName", "DomainUserName"),
        "client_name": _first(row, "ClientName", "Client", "ClientDnsName", "DnsName", "HostName", "ComputerName"),
        "client_ip": _first(row, "ClientIp", "ClientIP", "IpAddress", "IPAddress", "Address", "ClientAddress"),
        "client_id": _first(row, "ClientId", "ClientID", "ClientGuid", "ClientGUID", "DeviceId", "DeviceID"),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "insert_date": insert_date,
        "last_access": last_access,
        "access_count": _first(row, "AccessCount", "TotalAccesses", "TotalAccessCount", "Count"),
        "activity_count": _first(row, "ActivityCount", "TotalCount", "Total"),
        "day_count": _first(row, "DayCount", "Days", "NumberOfDays"),
        "raw_time_bucket": _first(row, "Day", "Date", "TimeStamp", "Timestamp"),
    }


def _has_ual_value(row: dict[str, object]) -> bool:
    value_fields = {
        "role_guid",
        "role_name",
        "product_name",
        "user_sid",
        "user_name",
        "client_name",
        "client_ip",
        "client_id",
        "first_seen",
        "last_seen",
        "insert_date",
        "last_access",
        "access_count",
        "activity_count",
    }
    return any(str(row.get(field) or "").strip() for field in value_fields)


def _read_tsv(path: Path) -> Iterable[dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        yield from csv.DictReader(handle, delimiter="\t")


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=UAL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _first(row: dict[str, str], *names: str) -> str:
    lowered = {key.lower(): value for key, value in row.items() if key is not None}
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return str(value)
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value)
    return ""


def _time_value(value: str | None) -> str:
    if not value:
        return ""
    value = value.strip()
    if not value or value.startswith("("):
        return value
    try:
        number = int(value)
    except ValueError:
        return _text_timestamp(value)
    if number <= 0:
        return ""
    if number > 10_000_000_000_000_000:
        try:
            return (FILETIME_EPOCH + timedelta(microseconds=number / 10)).isoformat().replace("+00:00", "Z")
        except (OverflowError, ValueError):
            return value
    if number > 946684800:
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, ValueError, OSError):
            return value
    return value


def _text_timestamp(value: str) -> str:
    text = value.strip()
    if text.endswith("Z") or re.match(r"\d{4}-\d{2}-\d{2}T", text):
        return text
    for fmt in ("%b %d, %Y %H:%M:%S.%f", "%b %d, %Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            continue
    return text


def _guid(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if re.fullmatch(r"[0-9A-Fa-f]{32}", text):
        return f"{text[0:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:32]}".lower()
    return text.strip("{}").lower()


def _sid_or_text(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    compact = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(compact) >= 16 and len(compact) % 2 == 0:
        try:
            decoded = _decode_sid(bytes.fromhex(compact))
        except ValueError:
            decoded = ""
        if decoded:
            return decoded
    return text


def _decode_sid(data: bytes) -> str:
    if len(data) < 8:
        return ""
    revision = data[0]
    subauth_count = data[1]
    authority = int.from_bytes(data[2:8], "big")
    parts = [f"S-{revision}-{authority}"]
    offset = 8
    for _ in range(subauth_count):
        if offset + 4 > len(data):
            return ""
        parts.append(str(int.from_bytes(data[offset:offset + 4], "little")))
        offset += 4
    return "-".join(parts)


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "ual"
