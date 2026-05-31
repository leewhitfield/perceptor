from __future__ import annotations

import csv
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any
import zipfile


CONTENT_FIELDS = (
    "body",
    "body_text",
    "content",
    "content_text",
    "message",
    "message_body",
    "text",
)


FIELD_ALIASES = {
    "provider": ("provider", "workload", "Workload", "service_provider"),
    "service": ("service", "Workload", "RecordType", "application", "app"),
    "event_type": ("event_type", "activity", "Activity", "Operation", "eventName", "name"),
    "event_time_utc": ("event_time_utc", "CreationTime", "creationTime", "time", "timestamp", "eventTime", "TimeGenerated"),
    "actor": ("actor", "UserId", "user", "userPrincipalName", "actor.email", "UserKey"),
    "actor_id": ("actor_id", "ActorId", "actor.id", "userId", "UserKey"),
    "actor_ip": ("actor_ip", "ClientIP", "clientIP", "ipAddress", "IPAddress", "sourceIPAddress"),
    "target": ("target", "ObjectId", "targetUserOrGroupName", "resourceName", "itemName"),
    "target_id": ("target_id", "objectId", "id", "resourceId", "itemId"),
    "target_type": ("target_type", "ObjectType", "resourceType", "itemType"),
    "operation": ("operation", "Operation", "activity", "eventName"),
    "result": ("result", "ResultStatus", "status", "outcome", "Result"),
    "user_agent": ("user_agent", "UserAgent", "userAgent"),
    "client_app": ("client_app", "ClientAppId", "clientApp", "AppId", "ApplicationId"),
    "file_name": ("file_name", "SourceFileName", "FileName", "name", "itemName"),
    "file_path": ("file_path", "SourceRelativeUrl", "SiteUrl", "path", "filePath", "sourceFilePath"),
    "url": ("url", "Url", "URL", "webUrl", "link"),
    "message_id": ("message_id", "InternetMessageId", "MessageId", "messageId"),
    "conversation_id": ("conversation_id", "ConversationId", "conversationId", "threadId"),
    "source_log_type": ("source_log_type", "log_type", "RecordType", "eventSource"),
    "source_record_id": ("source_record_id", "Id", "id", "recordId"),
}


def import_cloud_server_logs_to_csv(
    source: Path,
    output_dir: Path,
    *,
    provider: str | None = None,
    service: str | None = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = _load_rows(source)
    output = output_dir / "CloudServerLogImporter.csv"
    fieldnames = [
        "provider",
        "service",
        "event_type",
        "event_time_utc",
        "actor",
        "actor_id",
        "actor_ip",
        "target",
        "target_id",
        "target_type",
        "operation",
        "result",
        "user_agent",
        "client_app",
        "file_name",
        "file_path",
        "url",
        "message_id",
        "conversation_id",
        "content_sha256",
        "content_length",
        "opensearch_document_id",
        "_opensearch_content_text",
        "source_log_type",
        "source_record_id",
        "raw_fields_json",
    ]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            normalized = _normalize_row(row, provider=provider, service=service)
            writer.writerow({key: normalized.get(key, "") for key in fieldnames})
    return output


def cloud_server_import_diagnostics(source: Path) -> dict[str, str]:
    suffix = source.suffix.lower()
    if suffix != ".zip":
        return {"status": "ok", "reason": ""}
    try:
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile) as exc:
        return {"status": "unsupported_layout", "reason": f"ZIP could not be inspected: {exc}"}
    lowered = [name.replace("\\", "/").lower() for name in names]
    if any(name.startswith("takeout/") for name in lowered):
        has_logs = any(name.endswith((".csv", ".json", ".jsonl", ".ndjson")) for name in lowered)
        if not has_logs:
            return {
                "status": "unsupported_layout",
                "reason": (
                    "Google Takeout ZIP contains exported content, not cloud audit logs. "
                    "Use mailbox import for Gmail mbox exports and filesystem/archive workflows for Drive file exports."
                ),
            }
    return {"status": "ok", "reason": ""}


def _load_rows(source: Path) -> list[dict[str, Any]]:
    if source.is_dir():
        rows: list[dict[str, Any]] = []
        for path in sorted(source.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".csv", ".json", ".jsonl", ".ndjson"}:
                rows.extend(_load_rows(path))
        return rows
    suffix = source.suffix.lower()
    if suffix == ".zip":
        rows: list[dict[str, Any]] = []
        try:
            with zipfile.ZipFile(source) as archive:
                for name in sorted(archive.namelist()):
                    lower = name.lower()
                    if not lower.endswith((".csv", ".json", ".jsonl", ".ndjson")):
                        continue
                    with archive.open(name) as member:
                        text = member.read().decode("utf-8-sig", errors="replace")
                    rows.extend(_load_text_rows(text, suffix=Path(name).suffix.lower()))
        except (OSError, zipfile.BadZipFile):
            return []
        return rows
    if suffix == ".csv":
        with source.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    if suffix in {".jsonl", ".ndjson"}:
        rows = []
        with source.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
        return rows
    if suffix == ".json":
        data = json.loads(source.read_text(encoding="utf-8-sig", errors="replace"))
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            for key in ("value", "records", "items", "events", "data"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            return [data]
    return []


def _load_text_rows(text: str, *, suffix: str) -> list[dict[str, Any]]:
    if suffix == ".csv":
        return [dict(row) for row in csv.DictReader(text.splitlines())]
    if suffix in {".jsonl", ".ndjson"}:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
        return rows
    if suffix == ".json":
        data = json.loads(text)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            for key in ("value", "records", "items", "events", "data"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            return [data]
    return []


def _normalize_row(row: dict[str, Any], *, provider: str | None, service: str | None) -> dict[str, Any]:
    flat = _flatten(row)
    content = _first(flat, CONTENT_FIELDS)
    content_sha256 = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest() if content else ""
    normalized = {
        key: _first(flat, aliases)
        for key, aliases in FIELD_ALIASES.items()
    }
    if provider:
        normalized["provider"] = provider
    if service:
        normalized["service"] = service
    if not normalized.get("provider"):
        normalized["provider"] = _infer_provider(flat)
    normalized["content_sha256"] = content_sha256
    normalized["content_length"] = len(content)
    normalized["opensearch_document_id"] = _content_document_id(content) if content else ""
    normalized["_opensearch_content_text"] = content
    normalized["raw_fields_json"] = json.dumps(row, sort_keys=True, default=str)
    return normalized


def _flatten(row: dict[str, Any], prefix: str = "") -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in row.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            output.update(_flatten(value, name))
        elif isinstance(value, (list, tuple)):
            output[name] = json.dumps(value, default=str)
        elif value is None:
            output[name] = ""
        else:
            output[name] = str(value)
    return output


def _first(row: dict[str, str], aliases: tuple[str, ...]) -> str:
    lower = {key.lower(): value for key, value in row.items()}
    for alias in aliases:
        if alias in row and row[alias] != "":
            return row[alias]
        value = lower.get(alias.lower())
        if value:
            return value
    return ""


def _infer_provider(row: dict[str, str]) -> str:
    text = " ".join(f"{key} {value}" for key, value in row.items()).lower()
    if any(token in text for token in ("google", "gmail", "drive.google", "workspace")):
        return "Google Workspace"
    if any(token in text for token in ("exchange", "sharepoint", "onedrive", "azure", "office 365", "o365", "microsoft")):
        return "Microsoft 365"
    return "Cloud"


def _content_document_id(content: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()))
