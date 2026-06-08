from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


BITS_FIELDS = [
    "source_path",
    "database_file",
    "source_table",
    "record_id",
    "record_type",
    "job_id",
    "job_name",
    "job_owner",
    "job_state",
    "job_type",
    "priority",
    "created_utc",
    "modified_utc",
    "completed_utc",
    "expiration_utc",
    "url",
    "local_path",
    "remote_name",
    "file_size",
    "bytes_transferred",
    "raw_row_json",
    "parser_status",
    "parser_error",
]

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
MAX_CARVED_ROWS_PER_STORE = 500


def parse_bits_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "BitsJobs.csv"
    rows: list[dict[str, object]] = []
    stores = _bits_stores(source)
    if not stores:
        _write_csv(csv_path, [])
        return csv_path
    export_root = output / "_esedbexport"
    if export_root.exists():
        shutil.rmtree(export_root)
    export_root.mkdir(parents=True)
    for store in stores:
        rows.extend(_records_from_store(store, export_root))
    _write_csv(csv_path, rows)
    return csv_path


def _bits_stores(source: Path) -> list[Path]:
    if not source.exists():
        return []
    if source.is_file() and _is_bits_store(source):
        return [source]
    if not source.is_dir():
        return []
    return sorted(path for path in source.rglob("*") if path.is_file() and _is_bits_store(path))


def _is_bits_store(path: Path) -> bool:
    name = path.name.lower()
    if name in {"qmgr.db", "qmgr.jfm", "qmgr0.dat", "qmgr1.dat", "qmgr0.bak", "qmgr1.bak"}:
        return True
    return bool(re.fullmatch(r"edb(?:tmp|res[0-9]+|[0-9]+)?\\.(?:log|jrs|chk)", name))


def _records_from_store(store: Path, export_root: Path) -> list[dict[str, object]]:
    base = {
        "source_path": str(store),
        "database_file": store.name,
        "source_table": "",
        "record_id": "",
        "record_type": "inventory",
        "job_id": "",
        "job_name": "",
        "job_owner": "",
        "job_state": "",
        "job_type": "",
        "priority": "",
        "created_utc": "",
        "modified_utc": "",
        "completed_utc": "",
        "expiration_utc": "",
        "url": "",
        "local_path": "",
        "remote_name": "",
        "file_size": _file_size(store),
        "bytes_transferred": "",
        "raw_row_json": "",
        "parser_status": "found",
        "parser_error": "",
    }
    if store.name.lower() != "qmgr.db":
        carved = _carved_rows_from_store(store)
        return [
            base
            | {
                "parser_status": "support_file_carved" if carved else "support_file_no_strings",
                "raw_row_json": json.dumps({"carved_rows": len(carved)}, sort_keys=True),
            },
            *carved,
        ]
    if shutil.which("esedbexport") is None:
        carved = _carved_rows_from_store(store)
        return [
            base
            | {
                "parser_status": "dependency_missing",
                "parser_error": "Missing dependency: esedbexport",
                "raw_row_json": json.dumps({"carved_rows": len(carved)}, sort_keys=True),
            },
            *carved,
        ]

    target = export_root / _safe_name(store)
    actual_export_dir = target.with_name(target.name + ".export")
    for export_dir in (target, actual_export_dir):
        if export_dir.exists():
            shutil.rmtree(export_dir)
    result = subprocess.run(
        ["esedbexport", "-t", str(target), str(store)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=_command_timeout(),
    )
    if result.returncode != 0 or not actual_export_dir.exists():
        error = (result.stderr or result.stdout or "").strip()
        carved = _carved_rows_from_store(store)
        return [
            base
            | {
                "parser_status": "export_failed_carved" if carved else "export_failed",
                "parser_error": error[:2000],
                "raw_row_json": json.dumps({"carved_rows": len(carved)}, sort_keys=True),
            },
            *carved,
        ]

    parsed: list[dict[str, object]] = []
    exported_tables: list[str] = []
    for table_path in sorted(actual_export_dir.iterdir()):
        if not table_path.is_file():
            continue
        exported_tables.append(table_path.name)
        if table_path.name.lower().startswith("msys"):
            continue
        if not table_path.name.lower().startswith(("jobs", "files")):
            continue
        for row_number, row in enumerate(_read_tsv(table_path), start=1):
            normalized = _normalize_bits_row(store, table_path.name, row_number, row)
            if _is_interesting_bits_row(normalized):
                parsed.append(normalized)
    if not parsed:
        return [
            base
            | {
                "parser_status": "schema_only",
                "raw_row_json": json.dumps({"exported_tables": exported_tables}, sort_keys=True),
            }
        ]
    return [base | {"parser_status": "parsed", "raw_row_json": json.dumps({"parsed_rows": len(parsed)}, sort_keys=True)}, *parsed]


def _carved_rows_from_store(store: Path) -> list[dict[str, object]]:
    try:
        data = store.read_bytes()
    except OSError:
        return []
    strings = _extract_readable_strings(data)
    urls = _ordered_unique(_url_candidates(strings))
    paths = _ordered_unique(_path_candidates(strings))
    guids = _ordered_unique(_guid_candidates(strings))
    words = _ordered_unique(_bits_word_candidates(strings))
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    def add(record_type: str, value: str, *, field: str) -> None:
        if len(rows) >= MAX_CARVED_ROWS_PER_STORE:
            return
        clean = _clean_carved_value(value)
        if not clean:
            return
        key = (record_type, clean.casefold())
        if key in seen:
            return
        seen.add(key)
        rows.append(_carved_row(store, record_type=record_type, value=clean, field=field))

    for value in urls:
        add("carved_url", value, field="url")
    for value in paths:
        add("carved_path", value, field="local_path")
    for value in guids:
        add("carved_guid", value, field="job_id")
    for value in words:
        add("carved_string", value, field="job_name")
    return rows


def _carved_row(store: Path, *, record_type: str, value: str, field: str) -> dict[str, object]:
    row = {
        "source_path": str(store),
        "database_file": store.name,
        "source_table": "carved_strings",
        "record_id": _stable_carve_id(record_type, value),
        "record_type": record_type,
        "job_id": "",
        "job_name": "",
        "job_owner": "",
        "job_state": "",
        "job_type": "",
        "priority": "",
        "created_utc": "",
        "modified_utc": "",
        "completed_utc": "",
        "expiration_utc": "",
        "url": "",
        "local_path": "",
        "remote_name": "",
        "file_size": _file_size(store),
        "bytes_transferred": "",
        "raw_row_json": json.dumps({"carved_value": value, "carved_field": field}, sort_keys=True),
        "parser_status": "strings_carved",
        "parser_error": "",
    }
    row[field] = value
    return row


def _extract_readable_strings(data: bytes) -> list[str]:
    values: list[str] = []
    values.extend(match.group(0).decode("ascii", errors="replace") for match in re.finditer(rb"[\x20-\x7e]{4,}", data))
    try:
        utf16 = data.decode("utf-16le", errors="ignore")
    except UnicodeError:
        utf16 = ""
    values.extend(re.findall(r"[\x20-\x7e]{4,}", utf16))
    return values


def _url_candidates(strings: list[str]) -> list[str]:
    hits: list[str] = []
    for value in strings:
        hits.extend(re.findall(r"(?i)\b(?:https?|ftp)://[^\s\x00\"'<>]+", value))
    return hits


def _path_candidates(strings: list[str]) -> list[str]:
    hits: list[str] = []
    for value in strings:
        hits.extend(re.findall(r"(?i)(?:[a-z]:\\[^\x00\"'<>|]{3,}|\\\\[^\x00\"'<>|]{3,})", value))
    return hits


def _guid_candidates(strings: list[str]) -> list[str]:
    hits: list[str] = []
    for value in strings:
        hits.extend(
            re.findall(
                r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                value,
            )
        )
    return hits


def _bits_word_candidates(strings: list[str]) -> list[str]:
    hits: list[str] = []
    tokens = ("bits", "download", "update", "job", "transfer", "onedrive", "skydrive", "font", "windows")
    for value in strings:
        clean = _clean_carved_value(value)
        if len(clean) < 6 or len(clean) > 240:
            continue
        lower = clean.casefold()
        if any(token in lower for token in tokens):
            hits.append(clean)
    return hits


def _ordered_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for value in values:
        clean = _clean_carved_value(value)
        key = clean.casefold()
        if not clean or key in seen:
            continue
        seen.add(key)
        results.append(clean)
    return results


def _clean_carved_value(value: str) -> str:
    clean = str(value or "").strip().strip("\x00")
    clean = re.sub(r"[\x00-\x1f]+", "", clean)
    clean = clean.strip(" ,;")
    if len(clean) > 1000:
        clean = clean[:1000]
    return clean


def _stable_carve_id(record_type: str, value: str) -> str:
    import hashlib

    return hashlib.sha256(f"{record_type}\0{value}".encode("utf-8", errors="replace")).hexdigest()


def _normalize_bits_row(store: Path, source_table: str, row_number: int, row: dict[str, str]) -> dict[str, object]:
    raw_json = json.dumps({key: value for key, value in row.items() if value not in (None, "")}, sort_keys=True)
    url = _first_url(row)
    local_path = _first_path(row)
    job_id = _first_guid(row)
    return {
        "source_path": str(store),
        "database_file": store.name,
        "source_table": source_table,
        "record_id": _first(row, "Id", "ID", "AutoIncId", "RecordId", "RecordID") or str(row_number),
        "record_type": _record_type(source_table, row, url=url, local_path=local_path),
        "job_id": _first(row, "JobId", "JobID", "JobGuid", "JobGUID", "Job", "Id") or job_id,
        "job_name": _first(row, "DisplayName", "JobName", "Name", "Title", "Description", "JobTitle"),
        "job_owner": _first(row, "Owner", "User", "UserName", "UserSid", "SID", "Sid"),
        "job_state": _first(row, "State", "JobState", "Status"),
        "job_type": _first(row, "Type", "JobType", "TransferType"),
        "priority": _first(row, "Priority", "JobPriority"),
        "created_utc": _first_time(row, "Created", "CreationTime", "CreateTime", "CreatedTime", "InsertDate"),
        "modified_utc": _first_time(row, "Modified", "ModifiedTime", "UpdateTime", "LastModified", "LastUpdateTime"),
        "completed_utc": _first_time(row, "Completed", "CompleteTime", "CompletionTime", "TransferCompletionTime"),
        "expiration_utc": _first_time(row, "ExpirationTime", "ExpireTime", "NoProgressTimeoutTime"),
        "url": url,
        "local_path": local_path,
        "remote_name": _first(row, "RemoteName", "RemoteFileName", "HttpMethod", "HostName"),
        "file_size": _first(row, "FileSize", "Size", "BytesTotal", "BytesTotalHigh", "Length"),
        "bytes_transferred": _first(row, "BytesTransferred", "BytesTransferredHigh", "BytesDone", "BytesDownloaded"),
        "raw_row_json": raw_json,
        "parser_status": "parsed",
        "parser_error": "",
    }


def _is_interesting_bits_row(row: dict[str, object]) -> bool:
    fields = (
        "job_id",
        "job_name",
        "job_owner",
        "job_state",
        "created_utc",
        "modified_utc",
        "completed_utc",
        "url",
        "local_path",
        "remote_name",
        "file_size",
        "bytes_transferred",
    )
    return any(str(row.get(field) or "").strip() for field in fields)


def _record_type(source_table: str, row: dict[str, str], *, url: str, local_path: str) -> str:
    lower = source_table.lower()
    if url or local_path or "file" in lower:
        return "file"
    if any("url" in str(key).lower() for key in row):
        return "file"
    return "job"


def _read_tsv(path: Path) -> Iterable[dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        yield from csv.DictReader(handle, delimiter="\t")


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=BITS_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _first(row: dict[str, str], *names: str) -> str:
    lowered = {str(key).lower(): value for key, value in row.items() if key is not None}
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return str(value)
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value)
    return ""


def _first_url(row: dict[str, str]) -> str:
    for key, value in row.items():
        text = str(value or "").strip()
        if text.lower().startswith(("http://", "https://", "ftp://")):
            return text
        if "url" in str(key).lower() and text:
            return text
    for value in row.values():
        match = re.search(r"(?i)\\b(?:https?|ftp)://[^\\s\\x00\"']+", str(value or ""))
        if match:
            return match.group(0)
    return ""


def _first_path(row: dict[str, str]) -> str:
    for key, value in row.items():
        lower_key = str(key).lower()
        text = str(value or "").strip()
        if not text:
            continue
        if any(token in lower_key for token in ("local", "path", "filename", "file_name", "destination")):
            if "\\" in text or "/" in text:
                return text
    for value in row.values():
        text = str(value or "").strip()
        if re.search(r"(?i)(?:[a-z]:\\\\|\\\\\\\\|/)", text):
            return text
    return ""


def _first_guid(row: dict[str, str]) -> str:
    for value in row.values():
        match = re.search(r"(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b", str(value or ""))
        if match:
            return match.group(0)
    return ""


def _first_time(row: dict[str, str], *names: str) -> str:
    for name in names:
        value = _first(row, name)
        converted = _time_value(value)
        if converted:
            return converted
    for key, value in row.items():
        if "time" not in str(key).lower() and "date" not in str(key).lower():
            continue
        converted = _time_value(str(value or ""))
        if converted:
            return converted
    return ""


def _time_value(value: str) -> str:
    text = str(value or "").strip()
    if not text or text in {"0", "0x0"}:
        return ""
    if re.fullmatch(r"0x[0-9a-fA-F]{12,16}", text):
        return _filetime_to_iso(int(text, 16))
    if re.fullmatch(r"[0-9]{16,19}", text):
        number = int(text)
        if number > 10_000_000_000_000_000:
            return _filetime_to_iso(number)
    if re.fullmatch(r"[0-9]{9,12}", text):
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (OSError, OverflowError, ValueError):
            return ""
    if re.match(r"\\d{4}-\\d{2}-\\d{2}", text):
        return text.replace(" ", "T").replace("+00:00", "Z")
    return ""


def _filetime_to_iso(value: int) -> str:
    try:
        dt = FILETIME_EPOCH + timedelta(microseconds=value / 10)
    except (OverflowError, ValueError):
        return ""
    if dt.year < 1980 or dt.year > 2100:
        return ""
    return dt.isoformat().replace("+00:00", "Z")


def _safe_name(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name)


def _file_size(path: Path) -> str:
    try:
        return str(path.stat().st_size)
    except OSError:
        return ""


def _command_timeout() -> int:
    raw = os.environ.get("PERCEPTOR_COMMAND_TIMEOUT_SECONDS") or os.environ.get("RELIC_COMMAND_TIMEOUT_SECONDS", "3600")
    try:
        return max(1, int(raw))
    except ValueError:
        return 3600
