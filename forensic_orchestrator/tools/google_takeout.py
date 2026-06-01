from __future__ import annotations

import csv
import json
import mimetypes
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .file_content import SUPPORTED_EXTENSIONS, parse_file_content_to_csv
from .mailbox import parse_mailbox_artifacts_to_csv


DRIVE_TAKEOUT_FIELDS = [
    "provider",
    "artifact_type",
    "user_profile",
    "source_path",
    "source_name",
    "database_name",
    "table_name",
    "event_time_utc",
    "local_path",
    "cloud_path",
    "file_name",
    "file_id",
    "parent_id",
    "stable_id",
    "server_path",
    "url",
    "mime_type",
    "file_size",
    "is_folder",
    "is_deleted",
    "sync_status",
    "event_type",
    "direction",
    "owner",
    "shared",
    "protobuf_fields_json",
    "details_json",
    "error",
]


def google_takeout_diagnostics(source: Path) -> dict[str, object]:
    try:
        with zipfile.ZipFile(source) as archive:
            names = [name.replace("\\", "/") for name in archive.namelist()]
    except (OSError, zipfile.BadZipFile) as exc:
        return {"status": "unsupported", "reason": f"ZIP could not be inspected: {exc}", "services": []}

    services: list[str] = []
    if any(_is_mail_mbox(name) for name in names):
        services.append("mail")
    if any(_is_drive_member(name) for name in names):
        services.append("drive")
    return {
        "status": "ok" if services else "unsupported",
        "reason": "" if services else "No Takeout/Mail MBOX or Takeout/Drive entries were found",
        "services": services,
        "member_count": len(names),
    }


def import_google_takeout_to_csv(source: Path, output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    diagnostics = google_takeout_diagnostics(source)
    if diagnostics.get("status") != "ok":
        return {
            "diagnostics": diagnostics,
            "mail_messages_csv": None,
            "mail_attachments_csv": None,
            "drive_csv": None,
            "mail_message_rows": 0,
            "mail_attachment_rows": 0,
            "drive_rows": 0,
        }

    result: dict[str, object] = {"diagnostics": diagnostics}
    if "mail" in diagnostics.get("services", []):
        mail_dir = output_dir / "mail"
        extracted = extract_takeout_mail_mboxes(source, mail_dir / "extracted")
        messages_csv = parse_mailbox_artifacts_to_csv(mail_dir / "extracted", mail_dir / "parsed")
        attachments_csv = messages_csv.parent / "MailboxAttachments.csv"
        result.update(
            {
                "mail_extracted": [str(path) for path in extracted],
                "mail_messages_csv": messages_csv,
                "mail_attachments_csv": attachments_csv if attachments_csv.exists() else None,
                "mail_message_rows": _count_csv_rows(messages_csv),
                "mail_attachment_rows": _count_csv_rows(attachments_csv) if attachments_csv.exists() else 0,
            }
        )
    else:
        result.update({"mail_messages_csv": None, "mail_attachments_csv": None, "mail_message_rows": 0, "mail_attachment_rows": 0})

    if "drive" in diagnostics.get("services", []):
        drive_dir = output_dir / "drive"
        drive_csv = parse_takeout_drive_to_csv(source, drive_dir)
        content_files = extract_takeout_drive_content_files(source, drive_dir / "extracted")
        content_csv = parse_file_content_to_csv(drive_dir / "extracted" / "Takeout" / "Drive", drive_dir / "content")
        result.update(
            {
                "drive_csv": drive_csv,
                "drive_rows": _count_csv_rows(drive_csv),
                "drive_content_csv": content_csv,
                "drive_content_rows": _count_csv_rows(content_csv),
                "drive_content_extracted": [str(path) for path in content_files],
            }
        )
    else:
        result.update({"drive_csv": None, "drive_rows": 0, "drive_content_csv": None, "drive_content_rows": 0, "drive_content_extracted": []})
    return result


def extract_takeout_mail_mboxes(source: Path, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            if not _is_mail_mbox(name):
                continue
            destination = _safe_member_destination(output_dir, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, destination.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(destination)
    return extracted


def parse_takeout_drive_to_csv(source: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "GoogleTakeoutDrive.csv"
    rows: list[dict[str, object]] = []
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            if not _is_drive_member(name):
                continue
            rows.append(_drive_row(source, info, name))
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=DRIVE_TAKEOUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def extract_takeout_drive_content_files(source: Path, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            if not _is_drive_member(name) or info.is_dir():
                continue
            if Path(name).suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            destination = _safe_member_destination(output_dir, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, destination.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(destination)
    return extracted


def _drive_row(source: Path, info: zipfile.ZipInfo, member_path: str) -> dict[str, object]:
    drive_path = member_path[len("Takeout/Drive/") :]
    is_dir = info.is_dir()
    in_trash = drive_path == "Trash/" or drive_path.startswith("Trash/")
    file_name = Path(drive_path.rstrip("/")).name
    mime_type = "inode/directory" if is_dir else mimetypes.guess_type(file_name)[0] or ""
    details = {
        "takeout_member_path": member_path,
        "zip_crc": f"{info.CRC:08x}",
        "compressed_size": info.compress_size,
        "date_time_source": "zip_member_timestamp",
    }
    return {
        "provider": "Google Drive",
        "artifact_type": "google_takeout_drive_folder" if is_dir else "google_takeout_drive_file",
        "user_profile": "",
        "source_path": str(source),
        "source_name": source.name,
        "database_name": "Google Takeout",
        "table_name": "Takeout/Drive",
        "event_time_utc": _zip_datetime(info),
        "local_path": "",
        "cloud_path": "/" + drive_path.rstrip("/"),
        "file_name": file_name,
        "file_id": "",
        "parent_id": "",
        "stable_id": "",
        "server_path": "/" + drive_path.rstrip("/"),
        "url": "",
        "mime_type": mime_type,
        "file_size": info.file_size,
        "is_folder": "true" if is_dir else "false",
        "is_deleted": "true" if in_trash else "false",
        "sync_status": "takeout_trash" if in_trash else "takeout_exported",
        "event_type": "takeout_drive_export",
        "direction": "cloud_export",
        "owner": "",
        "shared": "",
        "protobuf_fields_json": "",
        "details_json": json.dumps(details, sort_keys=True),
        "error": "",
    }


def _is_mail_mbox(name: str) -> bool:
    lower = name.lower()
    return lower.startswith("takeout/mail/") and lower.endswith((".mbox", ".mbx"))


def _is_drive_member(name: str) -> bool:
    lower = name.lower()
    return lower.startswith("takeout/drive/") and lower != "takeout/drive/"


def _safe_member_destination(root: Path, member_name: str) -> Path:
    parts = [part for part in member_name.replace("\\", "/").split("/") if part not in {"", ".", ".."}]
    destination = root.joinpath(*parts)
    resolved_root = root.resolve()
    resolved_destination = destination.resolve()
    if resolved_root not in (resolved_destination, *resolved_destination.parents):
        raise ValueError(f"Unsafe ZIP member path: {member_name}")
    return destination


def _zip_datetime(info: zipfile.ZipInfo) -> str:
    try:
        return datetime(*info.date_time, tzinfo=timezone.utc).isoformat()
    except ValueError:
        return ""


def _count_csv_rows(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        return max(0, sum(1 for _ in csv.DictReader(handle)))
