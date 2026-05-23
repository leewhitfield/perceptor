from __future__ import annotations

import csv
import hashlib
import html
import json
import mailbox
import mimetypes
import re
import shutil
import subprocess
import zipfile
from datetime import timezone
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree


MAILBOX_FIELDS = [
    "source_path",
    "container_path",
    "message_path",
    "source_format",
    "parser_status",
    "parser_error",
    "user_profile",
    "user_sid",
    "message_id",
    "in_reply_to",
    "references_header",
    "reply_to",
    "conversation_index",
    "conversation_topic",
    "importance",
    "priority",
    "sensitivity",
    "x_originating_ip",
    "message_flags",
    "message_status",
    "message_status_flags",
    "disposition_notification_to",
    "subject",
    "sender",
    "recipients",
    "cc",
    "bcc",
    "message_date_utc",
    "body_text",
    "body_html",
    "attachment_names",
    "attachment_count",
    "has_attachments",
    "dedupe_key",
]

ATTACHMENT_FIELDS = [
    "source_path",
    "container_path",
    "message_path",
    "user_profile",
    "user_sid",
    "message_id",
    "conversation_index",
    "conversation_topic",
    "subject",
    "sender",
    "recipients",
    "message_date_utc",
    "attachment_name",
    "attachment_path",
    "content_type",
    "size",
    "sha256",
    "metadata_json",
    "extracted_text",
    "extraction_status",
    "parser_error",
    "dedupe_key",
]

BODY_LIMIT = 200_000


def parse_mailbox_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    export_root = output / "exported"
    export_root.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    attachment_rows: list[dict[str, object]] = []
    if source.exists():
        manifest_rows = _load_manifest_rows(source)
        if manifest_rows:
            for manifest_row in manifest_rows:
                item_text = manifest_row.get("artifact_path") or ""
                original_path = manifest_row.get("original_path") or item_text
                item = Path(item_text) if item_text else Path(original_path)
                if not item_text or not item.exists():
                    status = manifest_row.get("extraction_method") or "artifact_not_extracted"
                    rows.append(_status_row(item, status, original_path, container=item))
                    continue
                parsed_rows, parsed_attachments = _mailbox_rows_for_item(item, export_root)
                rows.extend(parsed_rows)
                attachment_rows.extend(parsed_attachments)
        else:
            for item in _mailbox_candidates(source):
                parsed_rows, parsed_attachments = _mailbox_rows_for_item(item, export_root)
                rows.extend(parsed_rows)
                attachment_rows.extend(parsed_attachments)
    csv_path = output / "MailboxMessages.csv"
    _write_csv(csv_path, MAILBOX_FIELDS, rows)
    _write_csv(output / "MailboxAttachments.csv", ATTACHMENT_FIELDS, attachment_rows)
    return csv_path


def _mailbox_rows_for_item(item: Path, export_root: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    suffix = item.suffix.lower()
    if suffix in {".pst", ".ost", ".nst"}:
        return _readpst_rows(item, export_root)
    if suffix in {".mbox", ".mbx"}:
        return _mbox_rows(item, container=item)
    if suffix in {".eml", ".msg"}:
        parsed, attachments = _message_file_row(item, container=item)
        if parsed:
            return [parsed], attachments
    return [], []


def _mailbox_candidates(source: Path) -> Iterable[Path]:
    if source.is_file():
        yield source
        return
    for pattern in ("*.pst", "*.ost", "*.nst", "*.msg", "*.eml", "*.mbox", "*.mbx"):
        yield from sorted(source.rglob(pattern))


def _load_manifest_rows(source: Path) -> list[dict[str, str]]:
    manifest_path = source / "_artifact_manifest.csv"
    if not manifest_path.exists():
        return []
    with manifest_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        rows = []
        seen = set()
        for row in csv.DictReader(handle):
            path_text = row.get("artifact_path") or row.get("original_path") or ""
            suffix = Path(path_text).suffix.lower()
            if suffix not in {".pst", ".ost", ".nst", ".msg", ".eml", ".mbox", ".mbx"}:
                continue
            dedupe_key = (row.get("artifact_path") or "", row.get("original_path") or "")
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            rows.append(dict(row))
    return rows


def _readpst_rows(path: Path, export_root: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    destination = export_root / _safe_name(path)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    validation_error = _pst_ost_validation_error(path)
    if validation_error:
        return [_status_row(path, validation_error[0], validation_error[1])], []
    if not _command_exists("readpst"):
        return [_status_row(path, "readpst_missing", "readpst was not found on PATH")], []
    try:
        completed = subprocess.run(
            ["readpst", "-r", "-e", "-o", str(destination), str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=1800,
        )
    except subprocess.TimeoutExpired as exc:
        completed = subprocess.CompletedProcess(
            args=exc.cmd or [],
            returncode=124,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\nreadpst timed out",
        )
    rows: list[dict[str, object]] = []
    attachment_rows: list[dict[str, object]] = []
    for exported in sorted(destination.rglob("*")):
        if not exported.is_file():
            continue
        suffix = exported.suffix.lower()
        if suffix in {".eml", ".msg"}:
            parsed, attachments = _message_file_row(exported, container=path)
            if parsed:
                rows.append(parsed)
            attachment_rows.extend(attachments)
        elif suffix in {"", ".mbox", ".mbx"}:
            parsed_rows, parsed_attachments = _mbox_rows(exported, container=path)
            rows.extend(parsed_rows)
            attachment_rows.extend(parsed_attachments)
    if completed.returncode != 0:
        status = "readpst_timeout" if completed.returncode == 124 else "readpst_failed"
        rows.append(_status_row(path, status, str(completed.stderr or "")[-BODY_LIMIT:]))
    return rows, attachment_rows


def _pst_ost_validation_error(path: Path) -> tuple[str, str] | None:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            sample = handle.read(4096)
    except OSError as exc:
        return ("mailbox_unreadable", str(exc))
    if size == 0:
        return ("mailbox_empty", "Mailbox container is zero bytes")
    if sample and all(byte == 0 for byte in sample):
        return ("mailbox_zero_filled", "Mailbox container begins with zero-filled data")
    if path.suffix.lower() in {".pst", ".ost", ".nst"} and not sample.startswith(b"!BDN"):
        return ("invalid_mailbox_header", "Mailbox container does not start with the expected PST/OST header")
    return None


def _message_file_row(path: Path, *, container: Path) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None, []
    if path.suffix.lower() == ".msg" and raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _status_row(path, "unsupported_msg_binary", "Binary Outlook MSG parsing is not available in the internal parser", container=container), []
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        return _status_row(path, "parse_failed", "Python email parser could not parse message", container=container), []
    return _message_row(message, source_path=path, container=container, message_path=path)


def _mbox_rows(path: Path, *, container: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows: list[dict[str, object]] = []
    attachment_rows: list[dict[str, object]] = []
    try:
        box = mailbox.mbox(path, create=False)
    except (OSError, mailbox.Error):
        return rows, attachment_rows
    try:
        for key, message in box.items():
            parsed, attachments = _message_row(message, source_path=path, container=container, message_path=Path(f"{path}#{key}"))
            rows.append(parsed)
            attachment_rows.extend(attachments)
    finally:
        try:
            box.close()
        except Exception:
            pass
    return rows, attachment_rows


def _message_row(
    message: Message | EmailMessage,
    *,
    source_path: Path,
    container: Path,
    message_path: Path,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    user_profile, user_sid = _user_scope_from_path(container)
    if not user_profile:
        user_profile, user_sid = _user_scope_from_path(source_path)
    subject = _header(message, "subject")
    sender = _header(message, "from")
    recipients = _header(message, "to")
    cc = _header(message, "cc")
    bcc = _header(message, "bcc")
    message_id = _header(message, "message-id")
    in_reply_to = _header(message, "in-reply-to")
    references_header = _header_limited(message, "references")
    reply_to = _header_limited(message, "reply-to")
    conversation_index = (
        _header_limited(message, "thread-index")
        or _header_limited(message, "x-ms-exchange-organization-conversationindex")
    )
    conversation_topic = _header_limited(message, "thread-topic")
    importance = _header_limited(message, "importance")
    priority = _header_limited(message, "priority") or _header_limited(message, "x-priority")
    sensitivity = _header_limited(message, "sensitivity")
    x_originating_ip = _header_limited(message, "x-originating-ip")
    message_flags = (
        _header_limited(message, "x-ms-exchange-organization-messageflags")
        or _header_limited(message, "x-microsoft-message-flags")
        or _header_limited(message, "x-message-flags")
    )
    message_status = ";".join(
        part
        for part in (
            _header_limited(message, "status"),
            _header_limited(message, "x-status"),
            _header_limited(message, "x-mozilla-status"),
            _header_limited(message, "x-mozilla-status2"),
        )
        if part
    )
    message_status_flags = _decode_message_status_flags(message_status)
    disposition_notification_to = _header_limited(message, "disposition-notification-to")
    message_date = _message_date(_header(message, "date"))
    body_text, body_html, attachments = _message_parts(message, source_path=source_path, container=container, message_path=message_path)
    if not body_text.strip() and body_html.strip():
        body_text = _html_to_text(body_html)
    attachment_names = [str(attachment.get("attachment_name") or "") for attachment in attachments]
    row = {
        "source_path": str(source_path),
        "container_path": str(container),
        "message_path": str(message_path),
        "source_format": _source_format(container),
        "parser_status": "parsed",
        "parser_error": "",
        "user_profile": user_profile,
        "user_sid": user_sid,
        "message_id": message_id,
        "in_reply_to": in_reply_to,
        "references_header": references_header,
        "reply_to": reply_to,
        "conversation_index": conversation_index,
        "conversation_topic": conversation_topic,
        "importance": importance,
        "priority": priority,
        "sensitivity": sensitivity,
        "x_originating_ip": x_originating_ip,
        "message_flags": message_flags,
        "message_status": message_status,
        "message_status_flags": message_status_flags,
        "disposition_notification_to": disposition_notification_to,
        "subject": subject,
        "sender": sender,
        "recipients": recipients,
        "cc": cc,
        "bcc": bcc,
        "message_date_utc": message_date,
        "body_text": body_text[:BODY_LIMIT],
        "body_html": body_html[:BODY_LIMIT],
        "attachment_names": ";".join(attachment_names),
        "attachment_count": len(attachment_names),
        "has_attachments": "1" if attachments else "0",
        "dedupe_key": _dedupe_key(subject, sender, recipients, message_date),
    }
    for attachment in attachments:
        attachment.update(
            {
                "user_profile": user_profile,
                "user_sid": user_sid,
                "message_id": message_id,
                "conversation_index": conversation_index,
                "conversation_topic": conversation_topic,
                "subject": subject,
                "sender": sender,
                "recipients": recipients,
                "message_date_utc": message_date,
                "dedupe_key": row["dedupe_key"],
            }
        )
    return row, attachments


def _status_row(path: Path, status: str, error: str, *, container: Path | None = None) -> dict[str, object]:
    container = container or path
    user_profile, user_sid = _user_scope_from_path(path)
    subject = f"Mailbox parser status: {status}"
    return {
        "source_path": str(path),
        "container_path": str(container),
        "message_path": str(path),
        "source_format": _source_format(container),
        "parser_status": status,
        "parser_error": error,
        "user_profile": user_profile,
        "user_sid": user_sid,
        "message_id": "",
        "in_reply_to": "",
        "references_header": "",
        "reply_to": "",
        "conversation_index": "",
        "conversation_topic": "",
        "importance": "",
        "priority": "",
        "sensitivity": "",
        "x_originating_ip": "",
        "message_flags": "",
        "message_status": "",
        "message_status_flags": "",
        "disposition_notification_to": "",
        "subject": subject,
        "sender": "",
        "recipients": "",
        "cc": "",
        "bcc": "",
        "message_date_utc": "",
        "body_text": error[:BODY_LIMIT],
        "body_html": "",
        "attachment_names": "",
        "attachment_count": 0,
        "has_attachments": "0",
        "dedupe_key": _dedupe_key(subject, "", "", str(path)),
    }


def _message_parts(
    message: Message | EmailMessage,
    *,
    source_path: Path,
    container: Path,
    message_path: Path,
) -> tuple[str, str, list[dict[str, object]]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, object]] = []
    if message.is_multipart():
        iterable = message.walk()
    else:
        iterable = [message]
    for part in iterable:
        filename = part.get_filename()
        if filename:
            attachments.append(_attachment_row(part, filename, source_path=source_path, container=container, message_path=message_path))
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            payload = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if not isinstance(payload, str):
            continue
        if content_type == "text/html":
            html_parts.append(payload)
        else:
            text_parts.append(payload)
    return "\n".join(text_parts), "\n".join(html_parts), attachments


def _html_to_text(value: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", value)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</(?:p|div|tr|li|h[1-6])\s*>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"[ \t\r\f\v]+", " ", text).replace(" \n", "\n").strip()


def _attachment_row(
    part: Message | EmailMessage,
    filename: str,
    *,
    source_path: Path,
    container: Path,
    message_path: Path,
) -> dict[str, object]:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        payload = raw_payload.encode("utf-8", errors="replace") if isinstance(raw_payload, str) else b""
    content_type = part.get_content_type() or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    attachment_dir = message_path.parent / f"{message_path.stem}_attachments"
    attachment_path = attachment_dir / _safe_attachment_name(filename)
    try:
        attachment_dir.mkdir(parents=True, exist_ok=True)
        attachment_path.write_bytes(payload)
        status = "stored_binary"
        parser_error = ""
    except OSError as exc:
        status = "write_failed"
        parser_error = str(exc)
    metadata_json = _attachment_metadata(attachment_path) if status != "write_failed" else ""
    extracted_text, text_error = (
        _attachment_text(payload, filename, content_type, attachment_path)
        if status != "write_failed"
        else ("", "")
    )
    if extracted_text:
        status = "text_extracted"
    elif text_error:
        parser_error = text_error if not parser_error else f"{parser_error}; {text_error}"
    return {
        "source_path": str(source_path),
        "container_path": str(container),
        "message_path": str(message_path),
        "conversation_index": "",
        "conversation_topic": "",
        "attachment_name": filename,
        "attachment_path": str(attachment_path),
        "content_type": content_type,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "metadata_json": metadata_json,
        "extracted_text": extracted_text[:BODY_LIMIT],
        "extraction_status": status,
        "parser_error": parser_error,
    }


def _attachment_text(payload: bytes, filename: str, content_type: str, attachment_path: Path) -> tuple[str, str]:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        if _is_text_attachment(filename, content_type):
            try:
                return payload.decode(encoding, errors="replace"), ""
            except Exception:
                continue
    suffix = Path(filename).suffix.lower()
    if suffix == ".pdf":
        return _pdf_text(attachment_path)
    if suffix in {".docx", ".pptx", ".xlsx"}:
        return _office_openxml_text(attachment_path), ""
    return "", ""


def _is_text_attachment(filename: str, content_type: str) -> bool:
    suffix = Path(filename).suffix.lower()
    if content_type.startswith("text/"):
        return True
    return suffix in {".txt", ".csv", ".log", ".ics", ".html", ".htm", ".xml", ".json", ".rtf"}


def _pdf_text(path: Path) -> tuple[str, str]:
    if not _command_exists("pdftotext"):
        return "", ""
    try:
        completed = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return "", "pdftotext timed out"
    if completed.returncode != 0:
        return "", (completed.stderr or "pdftotext failed")[:1000]
    return completed.stdout, ""


def _office_openxml_text(path: Path) -> str:
    suffix = path.suffix.lower()
    members: list[str]
    if suffix == ".docx":
        members = ["word/document.xml"]
    elif suffix == ".pptx":
        members = []
    elif suffix == ".xlsx":
        members = ["xl/sharedStrings.xml"]
    else:
        return ""
    try:
        with zipfile.ZipFile(path) as archive:
            if suffix == ".pptx":
                members = sorted(name for name in archive.namelist() if name.startswith("ppt/slides/slide") and name.endswith(".xml"))
            chunks = []
            for member in members:
                try:
                    chunks.append(_xml_text(archive.read(member)))
                except KeyError:
                    continue
            return "\n".join(part for part in chunks if part)[:BODY_LIMIT]
    except (OSError, zipfile.BadZipFile):
        return ""


def _xml_text(payload: bytes) -> str:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return ""
    return " ".join((text or "").strip() for text in root.itertext() if (text or "").strip())


def _attachment_metadata(path: Path) -> str:
    if not _command_exists("exiftool"):
        return ""
    try:
        completed = subprocess.run(
            ["exiftool", "-j", "-G1", "-a", "-s", str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"ExifToolError": "exiftool timed out"})
    if completed.returncode != 0:
        return json.dumps({"ExifToolError": (completed.stderr or "exiftool failed")[:1000]})
    try:
        parsed = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError:
        return json.dumps({"ExifToolError": "exiftool returned non-JSON output"})
    if not parsed:
        return ""
    return json.dumps(parsed[0], sort_keys=True)[:BODY_LIMIT]


def _safe_attachment_name(filename: str) -> str:
    clean = Path(filename.replace("\\", "/")).name or "attachment"
    return "".join(char if char.isalnum() or char in "._- " else "_" for char in clean)[:180]


def _header(message: Message | EmailMessage, name: str) -> str:
    value = message.get(name, "")
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()


def _header_limited(message: Message | EmailMessage, name: str, *, limit: int = 2000) -> str:
    return _header(message, name)[:limit]


def _message_date(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat()
    except Exception:
        return value


def _decode_message_status_flags(value: str) -> str:
    if not value:
        return ""
    flags: list[str] = []
    upper = value.upper()
    text_flags = {
        "R": "read",
        "O": "old",
        "A": "answered",
        "D": "deleted",
        "F": "flagged",
        "T": "draft",
    }
    tokens = re.split(r"[^A-Z]+", upper)
    for char, label in text_flags.items():
        if char in tokens or any(char in token and len(token) <= 4 and token.isalpha() for token in tokens):
            flags.append(label)
    for hex_value in re.findall(r"0x[0-9A-F]+|\b[0-9A-F]{4,8}\b", upper):
        try:
            number = int(hex_value, 16)
        except ValueError:
            continue
        bit_flags = [
            (0x0001, "read"),
            (0x0002, "unmodified"),
            (0x0004, "submit"),
            (0x0008, "unsent"),
            (0x0010, "has_attachments"),
            (0x0020, "from_me"),
            (0x0040, "associated"),
            (0x0080, "resend"),
        ]
        for bit, label in bit_flags:
            if number & bit:
                flags.append(label)
    return ";".join(sorted(set(flags)))


def _dedupe_key(subject: str, sender: str, recipients: str, date: str) -> str:
    basis = "|".join(
        [
            (subject or "").strip().lower(),
            (sender or "").strip().lower(),
            (recipients or "").strip().lower(),
            (date or "")[:19],
        ]
    )
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()


def _source_format(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    if suffix:
        return suffix
    return "mbox"


def _user_scope_from_path(path: Path) -> tuple[str, str]:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    if "$recycle.bin" in lowered:
        index = lowered.index("$recycle.bin")
        if index + 1 < len(parts):
            sid = parts[index + 1]
            if sid.upper().startswith("S-1-"):
                return sid, sid
    for marker in ("users", "documents and settings"):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1], ""
    for marker in ("mail", "messaging"):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(parts):
                candidate = parts[index + 1]
                if candidate == "$Recycle.Bin" and index + 2 < len(parts):
                    sid = parts[index + 2]
                    if sid.upper().startswith("S-1-"):
                        return sid, sid
                return candidate, ""
    return "", ""


def _command_exists(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True, text=True, check=False).returncode == 0


def _safe_name(path: Path) -> str:
    digest = hashlib.sha1(str(path).encode()).hexdigest()[:10]
    return f"{path.stem}-{digest}"


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
