from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .mailbox import BODY_LIMIT, MAILBOX_FIELDS


WINDOWS_MAIL_STORE_FIELDS = [
    "source_database",
    "source_table",
    "table_file",
    "table_row_number",
    "user_profile",
    "source_record_id",
    "parent_record_id",
    "display_name",
    "primary_time_utc",
    "secondary_time_utc",
    "row_json",
]

STORE_TABLES = {
    "Store",
    "Folders",
    "Contact",
    "Message",
    "Attachment",
    "Recipient",
    "EmailMetadata",
    "EmailRecipientInfo",
}


def parse_windows_mail_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    store_rows: list[dict[str, object]] = []
    message_rows: list[dict[str, object]] = []
    for store in _store_vol_candidates(source):
        store_rows.extend(_export_store_vol_rows(store, output / "_store_exports"))
    for body_file in _body_file_candidates(source):
        row = _body_file_row(body_file)
        if row:
            message_rows.append(row)
    messages_csv = output / "MailboxMessages.csv"
    _write_csv(messages_csv, MAILBOX_FIELDS, message_rows)
    _write_csv(output / "WindowsMailStoreRows.csv", WINDOWS_MAIL_STORE_FIELDS, store_rows)
    return messages_csv


def _store_vol_candidates(source: Path) -> list[Path]:
    if source.is_file() and source.name.lower() == "store.vol":
        return [source]
    if not source.exists() or not source.is_dir():
        return []
    candidates: list[Path] = []
    for profile in _user_profiles(source):
        candidate = profile / "AppData" / "Local" / "Comms" / "UnistoreDB" / "store.vol"
        if candidate.exists():
            candidates.append(candidate)
    return sorted(candidates)


def _is_windows_mail_store(path: Path) -> bool:
    lowered = [part.lower() for part in path.parts]
    return "unistoredb" in lowered and "comms" in lowered


def _body_file_candidates(source: Path) -> list[Path]:
    if source.is_file() and source.suffix.lower() == ".dat":
        return [source]
    if not source.exists() or not source.is_dir():
        return []
    candidates: list[Path] = []
    for profile in _user_profiles(source):
        for root in (
            profile / "AppData" / "Local" / "Comms" / "Unistore" / "data",
            profile
            / "AppData"
            / "Local"
            / "Packages"
            / "microsoft.windowscommunicationsapps_8wekyb3d8bbwe"
            / "LocalState"
            / "Files",
        ):
            candidates.extend(_safe_dat_walk(root))
    return sorted(candidates)


def _user_profiles(source: Path) -> list[Path]:
    if source.name.lower() not in {"users", "documents and settings"}:
        return [source]
    try:
        return sorted(path for path in source.iterdir() if path.is_dir())
    except OSError:
        return []


def _safe_dat_walk(root: Path) -> list[Path]:
    if not root.exists():
        return []
    matches: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for child in children:
            try:
                is_dir = child.is_dir()
                is_file = child.is_file()
            except OSError:
                continue
            if is_dir:
                stack.append(child)
            elif is_file and child.suffix.lower() == ".dat":
                lowered = [part.lower() for part in child.parts]
                if _is_unistore_body_path(lowered) or _is_efmdata_body_path(lowered):
                    matches.append(child)
    return matches


def _is_unistore_body_path(lowered_parts: list[str]) -> bool:
    return "comms" in lowered_parts and "unistore" in lowered_parts and "data" in lowered_parts


def _is_efmdata_body_path(lowered_parts: list[str]) -> bool:
    return (
        "packages" in lowered_parts
        and "microsoft.windowscommunicationsapps_8wekyb3d8bbwe" in lowered_parts
        and "efmdata" in lowered_parts
    )


def _export_store_vol_rows(store: Path, export_root: Path) -> list[dict[str, object]]:
    user_profile = _user_profile_from_path(store)
    rows: list[dict[str, object]] = []
    destination = export_root / _safe_name(store)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if not shutil.which("esedbexport"):
        return [
            _store_status_row(
                store,
                "store_vol_export_failed",
                user_profile,
                {"error": "esedbexport was not found on PATH"},
            )
        ]
    try:
        completed = subprocess.run(
            ["esedbexport", "-t", str(destination / "store"), str(store)],
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return [_store_status_row(store, "store_vol_export_timeout", user_profile, {"error": "esedbexport timed out"})]
    if completed.returncode != 0:
        return [
            _store_status_row(
                store,
                "store_vol_export_failed",
                user_profile,
                {
                    "exit_code": completed.returncode,
                    "stdout": (completed.stdout or "")[-4000:],
                    "stderr": (completed.stderr or "")[-4000:],
                },
            )
        ]
    export_dir = destination / "store.export"
    if not export_dir.exists():
        export_dirs = sorted(destination.glob("*.export"))
        export_dir = export_dirs[0] if export_dirs else export_dir
    table_counts: dict[str, int] = {}
    if export_dir.exists():
        for table_file in sorted(export_dir.iterdir()):
            table_name = table_file.name.split(".", 1)[0]
            if table_name not in STORE_TABLES:
                continue
            parsed = _parse_exported_table(store, table_file, user_profile)
            table_counts[table_name] = len(parsed)
            rows.extend(parsed)
    rows.append(_store_status_row(store, "store_vol_exported", user_profile, {"table_counts": table_counts}))
    if not table_counts.get("Message") and not table_counts.get("EmailMetadata"):
        rows.append(
            _store_status_row(
                store,
                "store_vol_no_message_rows",
                user_profile,
                {"message": "store.vol exported, but Message/EmailMetadata tables had no rows"},
            )
        )
    return rows


def _parse_exported_table(store: Path, table_file: Path, user_profile: str) -> list[dict[str, object]]:
    table_name = table_file.name.split(".", 1)[0]
    rows: list[dict[str, object]] = []
    try:
        with table_file.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle, dialect="excel-tab")
            for row_number, row in enumerate(reader, start=1):
                rows.append(_store_row(store, table_file, table_name, row_number, user_profile, dict(row)))
    except OSError as exc:
        rows.append(_store_status_row(store, "store_vol_table_read_failed", user_profile, {"table": table_name, "error": str(exc)}))
    return rows


def _store_row(
    store: Path,
    table_file: Path,
    table_name: str,
    row_number: int,
    user_profile: str,
    row: dict[str, str],
) -> dict[str, object]:
    times = [_filetime_to_iso(value) for key, value in row.items() if key.lower().endswith("0040")]
    times = [value for value in times if value]
    return {
        "source_database": str(store),
        "source_table": table_name,
        "table_file": str(table_file),
        "table_row_number": row_number,
        "user_profile": user_profile,
        "source_record_id": row.get("00010003") or "",
        "parent_record_id": row.get("0e090013") or "",
        "display_name": _decode_possible_hex_utf16(row.get("3001001f") or ""),
        "primary_time_utc": times[0] if times else "",
        "secondary_time_utc": times[1] if len(times) > 1 else "",
        "row_json": json.dumps(row, sort_keys=True, ensure_ascii=False),
    }


def _store_status_row(store: Path, status: str, user_profile: str, details: dict[str, object]) -> dict[str, object]:
    return {
        "source_database": str(store),
        "source_table": "_status",
        "table_file": "",
        "table_row_number": "",
        "user_profile": user_profile,
        "source_record_id": "",
        "parent_record_id": "",
        "display_name": status,
        "primary_time_utc": "",
        "secondary_time_utc": "",
        "row_json": json.dumps(details, sort_keys=True),
    }


def _body_file_row(path: Path) -> dict[str, object] | None:
    try:
        raw = path.read_bytes()
        stat = path.stat()
    except OSError:
        return None
    decoded = _decode_body(raw)
    if not decoded or not _looks_like_body(decoded):
        return None
    user_profile = _user_profile_from_path(path)
    body_html = decoded if _looks_like_html(decoded) else ""
    body_text = _html_to_text(decoded) if body_html else _plain_text(decoded)
    source_format = "windows_mail_efmdata_html" if _is_efmdata_body_path([part.lower() for part in path.parts]) else "windows_mail_unistore_body"
    subject = _title_from_html(decoded) if body_html else ""
    message_date = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "source_path": str(path),
        "container_path": str(path),
        "message_path": str(path),
        "source_format": source_format,
        "parser_status": "body_file_extracted",
        "parser_error": (
            "Standalone Windows Mail body file; user profile is path-attributed and "
            "message_date_utc is the body file mtime. Message headers/recipients may be held outside this file."
        ),
        "user_profile": user_profile,
        "user_sid": "",
        "message_id": "",
        "in_reply_to": "",
        "subject": subject,
        "sender": "",
        "recipients": "",
        "cc": "",
        "bcc": "",
        "message_date_utc": message_date,
        "body_text": body_text[:BODY_LIMIT],
        "body_html": body_html[:BODY_LIMIT],
        "attachment_names": "",
        "attachment_count": 0,
        "has_attachments": "0",
        "dedupe_key": hashlib.sha256(f"{source_format}|{path}|{digest}".encode("utf-8", errors="replace")).hexdigest(),
    }


def _decode_body(raw: bytes) -> str:
    if not raw:
        return ""
    if len(raw) >= 4:
        even_nulls = raw[0: min(len(raw), 4096):2].count(0)
        odd_nulls = raw[1: min(len(raw), 4096):2].count(0)
        if even_nulls > odd_nulls * 2:
            try:
                return raw.decode("utf-16-be", errors="replace").replace("\x00", "")
            except UnicodeDecodeError:
                pass
        if odd_nulls > even_nulls * 2:
            try:
                return raw.decode("utf-16-le", errors="replace").replace("\x00", "")
            except UnicodeDecodeError:
                pass
    for encoding in ("utf-8-sig", "utf-16", "utf-16-be", "utf-16-le", "latin-1"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _text_score(text) > 0.5:
            return text.replace("\x00", "")
    return raw.decode("utf-8", errors="replace").replace("\x00", "")


def _text_score(text: str) -> float:
    if not text:
        return 0.0
    sample = text[:4096]
    printable = sum(1 for char in sample if char.isprintable() or char in "\r\n\t")
    return printable / max(len(sample), 1)


def _looks_like_body(text: str) -> bool:
    lowered = text[:8192].lower()
    return _looks_like_html(text) or len(_plain_text(text)) >= 40 or any(marker in lowered for marker in ("subject:", "from:", "to:"))


def _looks_like_html(text: str) -> bool:
    lowered = text[:4096].lower()
    return "<html" in lowered or "<body" in lowered or "<!doctype html" in lowered


def _title_from_html(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = _plain_text(html.unescape(match.group(1)))[:500]
    if not title or title.isdigit() or len(title) < 4:
        return ""
    return title


def _html_to_text(text: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</p\s*>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    return _plain_text(html.unescape(text))


def _plain_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _filetime_to_iso(value: str) -> str:
    if not value or not value.isdigit():
        return ""
    raw = int(value)
    if raw <= 0:
        return ""
    try:
        seconds = (raw - 116444736000000000) / 10_000_000
        if seconds < 0:
            return ""
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _decode_possible_hex_utf16(value: str) -> str:
    if not value:
        return ""
    stripped = value.strip()
    if len(stripped) >= 4 and len(stripped) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", stripped):
        try:
            decoded = bytes.fromhex(stripped).decode("utf-16-le", errors="replace").rstrip("\x00")
            if decoded and _text_score(decoded) > 0.5:
                return decoded
        except ValueError:
            pass
    return stripped


def _user_profile_from_path(path: Path) -> str:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    for marker in ("users", "documents and settings"):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1]
    return ""


def _safe_name(path: Path) -> str:
    digest = hashlib.sha1(str(path).encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{path.stem}-{digest}"


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
