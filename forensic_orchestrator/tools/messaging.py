from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


MESSAGING_FIELDS = [
    "application",
    "user_profile",
    "artifact_type",
    "source_path",
    "store_path",
    "record_key",
    "record_type",
    "url",
    "host",
    "email",
    "timestamp_utc",
    "message_text",
    "raw_text",
    "dedupe_key",
]

MESSAGE_FIELDS = [
    "application",
    "user_profile",
    "source_path",
    "store_path",
    "record_key",
    "platform_message_id",
    "conversation_id",
    "channel_id",
    "thread_id",
    "sender_id",
    "sender_name",
    "sender_email",
    "recipient",
    "timestamp_utc",
    "message_type",
    "message_text",
    "message_html",
    "url",
    "parser_confidence",
    "raw_json",
    "dedupe_key",
]

TEXT_LIMIT = 100_000
STRING_RE = re.compile(rb"[\x20-\x7e]{8,}")
URL_RE = re.compile(r"https?://[^\s\"'<>\x00-\x1f]+")
SLACK_URI_RE = re.compile(r"slack://[^\s\"'<>\x00-\x1f]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
ISO_TIME_RE = re.compile(r"\b20\d\d-\d\d-\d\d[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?Z?\b")
EPOCH_MS_RE = re.compile(r"\b1[5-9]\d{11,12}\b")
SLACK_ID_RE = re.compile(r"\b([UTC][A-Z0-9]{8,}|[DW][A-Z0-9]{8,})\b")
SLACK_TS_RE = re.compile(r"\b(?:msg_ts|ts|event_ts)[:=]([0-9]{10}\.[0-9]{3,6})\b", re.IGNORECASE)
SLACK_LOG_TIME_RE = re.compile(r"\[(\d\d)/(\d\d)/(\d\d),\s+(\d\d):(\d\d):(\d\d):(\d{3})\]")
SLACK_NOISE_TOKENS = (
    "/beacon/",
    "metricssender",
    "cache_get",
    "cache_set",
    "cache_hit",
    "cache_miss",
    "memory_v5_",
    "localstorage",
    "feature_enabled",
    "perfmark",
    "traceparent",
    "sentry_key",
    "client_logs",
    "browser_session_id",
    "x-slack-",
)
CHAT_APPS = {
    "ChatGPT",
    "Claude",
    "Codex",
    "Microsoft Teams",
    "Slack",
    "Discord",
    "Signal",
    "WhatsApp",
    "Telegram",
    "Skype",
    "Zoom",
    "Mattermost",
    "Viber",
}
NOTE_APPS = {"Obsidian", "Notion", "OneNote", "Evernote"}
FILE_KNOWLEDGE_APPS = {"Adobe Reader", "VLC Media Player", "FileZilla", "WinSCP", "Notepad++"}
REMOTE_ACCESS_APPS = {
    "AnyDesk",
    "TeamViewer",
    "LogMeIn",
    "GoTo",
    "ConnectWise Control",
    "BeyondTrust",
    "Splashtop",
    "RustDesk",
    "Chrome Remote Desktop",
    "RemotePC",
    "Dameware",
    "Atera",
    "NinjaOne",
    "MeshCentral",
    "DWAgent",
    "Parsec",
    "RealVNC",
    "TightVNC",
    "UltraVNC",
}


def parse_messaging_artifacts_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    message_rows: list[dict[str, object]] = []
    if source.exists():
        for path in sorted(source.rglob("*")) if source.is_dir() else [source]:
            if not path.is_file():
                continue
            app = _application_from_path(path)
            if app == "Messaging":
                continue
            artifact_type = _artifact_type(path)
            if artifact_type == "sqlite_database":
                rows.extend(_sqlite_rows(path, app))
                message_rows.extend(_sqlite_message_rows(path, app))
            elif artifact_type in {"leveldb_candidate", "cache_file", "log_file"}:
                if app == "Slack":
                    rows.extend(_slack_rows(path, artifact_type))
                elif app in REMOTE_ACCESS_APPS and artifact_type == "log_file":
                    rows.extend(_text_file_rows(path, app, artifact_type))
                else:
                    rows.extend(_string_rows(path, app, artifact_type))
                message_rows.extend(_structured_message_rows(path, app))
            elif artifact_type in {"markdown_note", "json_file", "text_file", "config_file"}:
                rows.extend(_text_file_rows(path, app, artifact_type))
                message_rows.extend(_structured_message_rows(path, app))
            elif path.name.lower() in {"cookies", "history", "local state", "preferences"}:
                if app == "Slack":
                    rows.extend(_slack_rows(path, artifact_type))
                else:
                    rows.extend(_string_rows(path, app, artifact_type))
                message_rows.extend(_structured_message_rows(path, app))
    csv_path = output / "MessagingRecords.csv"
    _write_csv(csv_path, MESSAGING_FIELDS, rows)
    _write_csv(output / "MessagingMessages.csv", MESSAGE_FIELDS, _dedupe_messages(message_rows))
    return csv_path


def _application_from_path(path: Path) -> str:
    text = str(path).lower()
    if "chatgpt" in text or "openai" in text:
        return "ChatGPT"
    if "claude" in text or "anthropic" in text:
        return "Claude"
    if ".codex" in text or re.search(r"[/\\]codex[/\\]", text):
        return "Codex"
    if "obsidian" in text or ".obsidian" in text:
        return "Obsidian"
    if path.suffix.lower() in {".md", ".markdown"} and _inside_obsidian_vault(path):
        return "Obsidian"
    if "notion" in text:
        return "Notion"
    if "onenote" in text or "microsoftoffice.onenote" in text:
        return "OneNote"
    if "evernote" in text:
        return "Evernote"
    if "adobe" in text or "acrobat" in text:
        return "Adobe Reader"
    if re.search(r"[/\\]vlc[/\\]", text) or "vlc-qt-interface" in text:
        return "VLC Media Player"
    if "filezilla" in text:
        return "FileZilla"
    if "winscp" in text:
        return "WinSCP"
    if "notepad++" in text:
        return "Notepad++"
    if "anydesk" in text:
        return "AnyDesk"
    if "teamviewer" in text:
        return "TeamViewer"
    if "logmein" in text or "lmi" in text and "rescue" in text:
        return "LogMeIn"
    if "gotoassist" in text or "goto resolve" in text or "g2ax_" in text:
        return "GoTo"
    if "screenconnect" in text or "connectwise control" in text:
        return "ConnectWise Control"
    if "bomgar" in text or "beyondtrust" in text:
        return "BeyondTrust"
    if "splashtop" in text:
        return "Splashtop"
    if "rustdesk" in text:
        return "RustDesk"
    if "chrome remote desktop" in text or "chromoting" in text:
        return "Chrome Remote Desktop"
    if "remotepc" in text:
        return "RemotePC"
    if "dameware" in text:
        return "Dameware"
    if "atera" in text:
        return "Atera"
    if "ninjarmm" in text or "ninjaone" in text:
        return "NinjaOne"
    if "meshcentral" in text:
        return "MeshCentral"
    if "dwagent" in text:
        return "DWAgent"
    if "parsec" in text:
        return "Parsec"
    if "realvnc" in text or "vnc viewer" in text or "vnc server" in text:
        return "RealVNC"
    if "tightvnc" in text:
        return "TightVNC"
    if "ultravnc" in text:
        return "UltraVNC"
    if "teams" in text or "msteams" in text:
        return "Microsoft Teams"
    if "slack" in text:
        return "Slack"
    if "discord" in text:
        return "Discord"
    if "signal" in text:
        return "Signal"
    if "whatsapp" in text:
        return "WhatsApp"
    if "telegram" in text:
        return "Telegram"
    if "skype" in text:
        return "Skype"
    if "zoom" in text:
        return "Zoom"
    if "mattermost" in text:
        return "Mattermost"
    if "viber" in text:
        return "Viber"
    if "webview2" in text:
        return "WebView2"
    return "Messaging"


def _inside_obsidian_vault(path: Path) -> bool:
    for parent in path.parents:
        try:
            if (parent / ".obsidian").exists():
                return True
        except OSError:
            return False
    return False


def _artifact_type(path: Path) -> str:
    text = str(path).lower()
    suffix = path.suffix.lower()
    if suffix == ".ldb":
        return "leveldb_candidate"
    if suffix == ".log" and any(marker in text for marker in ("leveldb", "session storage", "indexeddb", "service worker")):
        return "leveldb_candidate"
    if suffix in {".sqlite", ".sqlite3", ".db"}:
        return "sqlite_database"
    if suffix in {".md", ".markdown"}:
        return "markdown_note"
    if suffix == ".json":
        return "json_file"
    if suffix in {".ini", ".conf", ".config", ".cfg", ".xml", ".plist", ".yaml", ".yml"}:
        return "config_file"
    if "cache" in text:
        return "cache_file"
    if suffix in {".log", ".txt", ".trace"}:
        return "log_file"
    return "application_file"


def _sqlite_rows(path: Path, app: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        tables = [
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
        ]
        for table in tables:
            columns = [row["name"] for row in conn.execute(f"PRAGMA table_info({_quote_identifier(table)})")]
            text_columns = [column for column in columns if any(token in column.lower() for token in ("message", "body", "text", "content", "url", "name"))]
            time_columns = [column for column in columns if any(token in column.lower() for token in ("time", "date", "created", "updated"))]
            if not text_columns:
                continue
            selected = ", ".join(_quote_identifier(column) for column in text_columns[:5] + time_columns[:2])
            for index, row in enumerate(conn.execute(f"SELECT {selected} FROM {_quote_identifier(table)} LIMIT 1000"), start=1):
                raw_text = " ".join(str(value) for value in row if value not in (None, ""))
                if not raw_text.strip():
                    continue
                rows.append(
                    {
                        "application": app,
                        "user_profile": _user_profile_from_path(path),
                        "artifact_type": "sqlite_database",
                        "source_path": str(path),
                        "store_path": str(path.parent),
                        "record_key": f"{table}:{index}",
                        "record_type": _record_type(raw_text),
                        "url": _first_url(raw_text),
                        "host": _host_from_url(_first_url(raw_text)),
                        "email": _first_email(raw_text),
                        "timestamp_utc": _first_timestamp(raw_text),
                        "message_text": _message_text(raw_text),
                        "raw_text": raw_text[:TEXT_LIMIT],
                        "dedupe_key": _dedupe_key(app, path, f"{table}:{index}", raw_text),
                    }
                )
    except sqlite3.Error:
        return rows
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return rows


def _sqlite_message_rows(path: Path, app: str) -> list[dict[str, object]]:
    if app not in CHAT_APPS | NOTE_APPS:
        return []
    rows: list[dict[str, object]] = []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        tables = [
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
        ]
        for table in tables:
            columns = [row["name"] for row in conn.execute(f"PRAGMA table_info({_quote_identifier(table)})")]
            text_column = _first_column(columns, ("body", "message", "content", "text", "markdown", "note", "snippet"))
            if not text_column:
                continue
            selected_columns = _sqlite_message_columns(columns, text_column)
            selected = ", ".join(_quote_identifier(column) for column in selected_columns)
            for index, row in enumerate(conn.execute(f"SELECT {selected} FROM {_quote_identifier(table)} LIMIT 5000"), start=1):
                values = {column: row[column] for column in selected_columns}
                message_text = _clean_message_text(str(values.get(text_column) or ""))
                if not _looks_like_message_body(message_text):
                    continue
                raw_json = json.dumps({"table": table, "columns": values}, default=str, sort_keys=True)[:TEXT_LIMIT]
                timestamp = _sqlite_first_value(values, ("timestamp", "time", "date", "created", "updated", "sent", "received"))
                sender = _sqlite_first_value(values, ("sender", "author", "from", "user", "username", "displayname", "name"))
                conversation = _sqlite_first_value(values, ("conversation", "channel", "chat", "thread", "dialog", "room"))
                platform_id = _sqlite_first_value(values, ("id", "messageid", "message_id", "guid", "uuid"))
                rows.append(
                    {
                        "application": app,
                        "user_profile": _user_profile_from_path(path),
                        "source_path": str(path),
                        "store_path": str(path.parent),
                        "record_key": f"{table}:{index}",
                        "platform_message_id": platform_id,
                        "conversation_id": conversation,
                        "channel_id": conversation,
                        "thread_id": _sqlite_first_value(values, ("thread", "threadid", "thread_id", "parent")),
                        "sender_id": sender,
                        "sender_name": sender,
                        "sender_email": _first_email(raw_json),
                        "recipient": _sqlite_first_value(values, ("recipient", "to")),
                        "timestamp_utc": _normalize_timestamp(str(timestamp or "")),
                        "message_type": _sqlite_first_value(values, ("type", "kind")) or ("note" if app in NOTE_APPS else "message"),
                        "message_text": message_text[:TEXT_LIMIT],
                        "message_html": str(values.get("html") or "")[:TEXT_LIMIT],
                        "url": _first_url(raw_json),
                        "parser_confidence": "generic_sqlite_message",
                        "raw_json": raw_json,
                        "dedupe_key": _dedupe_key(app, path, f"{table}:{index}", "|".join([platform_id, conversation, message_text])),
                    }
                )
    except sqlite3.Error:
        return rows
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return rows


def _sqlite_message_columns(columns: list[str], text_column: str) -> list[str]:
    wanted_tokens = (
        "id", "guid", "uuid", "body", "message", "content", "text", "markdown", "note", "html",
        "time", "date", "created", "updated", "sent", "received", "sender", "author", "from",
        "user", "username", "display", "recipient", "to", "conversation", "channel", "chat",
        "thread", "dialog", "room", "type", "kind",
    )
    selected = [text_column]
    for column in columns:
        lower = column.lower()
        if column != text_column and any(token in lower for token in wanted_tokens):
            selected.append(column)
        if len(selected) >= 18:
            break
    return selected


def _first_column(columns: list[str], tokens: tuple[str, ...]) -> str:
    for token in tokens:
        for column in columns:
            if token in column.lower():
                return column
    return ""


def _sqlite_first_value(values: dict[str, object], tokens: tuple[str, ...]) -> str:
    for token in tokens:
        for column, value in values.items():
            if token in column.lower() and value not in (None, ""):
                return str(value)
    return ""


def _string_rows(path: Path, app: str, artifact_type: str) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    strings = []
    for match in STRING_RE.finditer(data):
        text = match.group(0).decode("utf-8", errors="replace")
        if _looks_relevant(text):
            strings.append(text)
        if len(strings) >= 250:
            break
    rows = []
    for index, text in enumerate(strings, start=1):
        rows.append(
            {
                "application": app,
                "user_profile": _user_profile_from_path(path),
                "artifact_type": artifact_type,
                "source_path": str(path),
                "store_path": str(path.parent),
                "record_key": str(index),
                "record_type": _record_type(text),
                "url": _first_url(text),
                "host": _host_from_url(_first_url(text)),
                "email": _first_email(text),
                "timestamp_utc": _first_timestamp(text),
                "message_text": _message_text(text),
                "raw_text": text[:TEXT_LIMIT],
                "dedupe_key": _dedupe_key(app, path, str(index), text),
            }
        )
    return rows


def _slack_rows(path: Path, artifact_type: str) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    candidates: list[str] = []
    if path.suffix.lower() in {".log", ".txt"} or path.name.lower() in {"preferences", "local state"}:
        text = data.decode("utf-8", errors="replace")
        candidates.extend(line.strip() for line in text.splitlines() if line.strip())
    for match in STRING_RE.finditer(data):
        text = match.group(0).decode("utf-8", errors="replace").strip()
        if text:
            candidates.append(text)
    rows: list[dict[str, object]] = []
    seen_candidates: set[str] = set()
    for index, text in enumerate(candidates, start=1):
        key = re.sub(r"\s+", " ", text).strip()[:500]
        if not key or key in seen_candidates:
            continue
        seen_candidates.add(key)
        row = _slack_row_from_text(path, artifact_type, index, text)
        if row:
            rows.append(row)
        if len(rows) >= 500:
            break
    return _dedupe_record_rows(rows)


def _slack_row_from_text(path: Path, artifact_type: str, index: int, text: str) -> dict[str, object] | None:
    cleaned = re.sub(r"\s+", " ", text).strip()
    lower = cleaned.lower()
    url = _first_meaningful_slack_url(cleaned)
    record_type = ""
    record_key = ""
    timestamp = _slack_log_timestamp(cleaned) or _slack_timestamp(cleaned) or _first_timestamp(cleaned)
    slack_uri_summary = _slack_uri_summary(cleaned)
    if slack_uri_summary:
        record_type = "slack_message_reference"
        record_key = slack_uri_summary
        timestamp = timestamp or _slack_timestamp_from_summary(slack_uri_summary)
    elif re.search(r"\bslack\s+\d+\.\d+\.\d+\b", cleaned, flags=re.IGNORECASE):
        record_type = "slack_client_start"
        record_key = _slack_compact(cleaned)
    elif (
        "issignedintoslackorg" in lower
        or "autologinepic" in lower
        or "logged in" in lower and "workspace" in lower
        or "not signed in to any workspaces" in lower
        or "selected workspace:" in lower
    ):
        record_type = "slack_signin_state"
        record_key = _slack_compact(cleaned)
    elif "msg_ts" in lower and re.search(r"\bchannel[:=][CDG][A-Z0-9]+\b", cleaned, flags=re.IGNORECASE):
        record_type = "slack_notification_metadata"
        record_key = _slack_identity_summary(cleaned)
    elif ("team_id" in lower or "teamid" in lower) and ("user_id" in lower or "userid" in lower):
        record_type = "slack_workspace_metadata"
        record_key = _slack_identity_summary(cleaned)
    elif re.search(r'"?messageid"?\s*:\s*"?[0-9]{10}\.[0-9]{3,6}"?', cleaned, flags=re.IGNORECASE):
        record_type = "slack_message_reference"
        record_key = "msg_ts=" + _regex_first(cleaned, r'"?messageid"?\s*:\s*"?([0-9]{10}\.[0-9]{3,6})')
        timestamp = timestamp or _slack_timestamp_from_summary(record_key)
    elif _slack_activity_summary(cleaned):
        record_type = "slack_activity_metadata"
        record_key = _slack_activity_summary(cleaned)
    elif url:
        record_type = "message_candidate" if _slack_message_candidate(cleaned) else "url_reference"
        record_key = str(index)
    elif _slack_message_candidate(cleaned):
        record_type = "message_candidate"
        record_key = str(index)
    if not record_type:
        return None
    message_text = _message_text(cleaned) if record_type == "message_candidate" else ""
    return {
        "application": "Slack",
        "user_profile": _user_profile_from_path(path),
        "artifact_type": artifact_type,
        "source_path": str(path),
        "store_path": str(path.parent),
        "record_key": record_key or str(index),
        "record_type": record_type,
        "url": url,
        "host": _host_from_url(url),
        "email": _first_email(cleaned),
        "timestamp_utc": timestamp,
        "message_text": message_text,
        "raw_text": cleaned[:TEXT_LIMIT],
        "dedupe_key": _dedupe_key("Slack", path, record_key or str(index), cleaned),
    }


def _slack_message_candidate(text: str) -> bool:
    lower = text.lower()
    if _is_slack_noise(text):
        return False
    if SLACK_LOG_TIME_RE.search(text):
        return False
    if re.fullmatch(r'"?msg"?\s*:\s*"?[0-9]{10}\.[0-9]{3,6}"?,?', text.strip(), flags=re.IGNORECASE):
        return False
    if "startuptasks is not iterable" in lower or "err_aborted" in lower:
        return False
    if not any(token in lower for token in ("message", "msg", "chat")):
        return False
    if any(token in lower for token in ("reducer", "versiondatats", "sidebackground", "client_should")):
        return False
    return _looks_like_message_body(text)


def _first_meaningful_slack_url(text: str) -> str:
    for match in URL_RE.finditer(text):
        url = match.group(0)
        if any(ord(char) < 33 or ord(char) > 126 for char in url):
            continue
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        if not parsed.scheme or not parsed.netloc:
            continue
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        if "." not in host:
            continue
        if _is_slack_noise(url):
            continue
        if host == "app.slack.com" and path in {"", "/"}:
            continue
        if host == "app.slack.com" and len(path.strip("/")) <= 2:
            continue
        if host == "app.slack.com" and path.startswith(("/api/", "/g")):
            continue
        if host == "app.slack.com" and path == "/service-worker.js":
            continue
        if host.endswith("slack.com") and path.startswith(("/beacon/", "/api/api.", "/api/telemetry.")):
            continue
        return url
    return ""


def _slack_uri_summary(text: str) -> str:
    match = SLACK_URI_RE.search(text)
    if not match:
        return ""
    parsed = urlparse(match.group(0))
    query = dict(part.split("=", 1) for part in parsed.query.split("&") if "=" in part)
    channel = query.get("id") or query.get("channel")
    message = query.get("message") or query.get("msg")
    team = query.get("team")
    if not (channel or message or team):
        return ""
    parts = []
    if team:
        parts.append(f"team={team}")
    if channel:
        parts.append(f"channel={channel}")
    if message:
        parts.append(f"msg_ts={message}")
    return " ".join(parts)


def _slack_timestamp_from_summary(summary: str) -> str:
    match = re.search(r"msg_ts=([0-9]{10}\.[0-9]{3,6})", summary)
    if not match:
        return ""
    try:
        return datetime.fromtimestamp(float(match.group(1)), tz=timezone.utc).isoformat()
    except ValueError:
        return ""


def _is_slack_noise(text: str) -> bool:
    lower = text.lower()
    return any(token in lower for token in SLACK_NOISE_TOKENS)


def _slack_identity_summary(text: str) -> str:
    parts: list[str] = []
    for name in ("team_id", "team", "user_id", "user", "channel", "msg_ts", "event_ts"):
        match = re.search(rf"\b{name}[:=]([A-Za-z0-9._-]+)", text, flags=re.IGNORECASE)
        if match:
            parts.append(f"{name}={match.group(1)}")
    desc = re.search(r"\bdesc:([^&\s][^&]{0,120})", text, flags=re.IGNORECASE)
    if desc:
        parts.append(f"desc={desc.group(1).strip()}")
    if not parts:
        parts.extend(sorted(set(SLACK_ID_RE.findall(text)))[:6])
    return " ".join(parts)[:500]


def _slack_activity_summary(text: str) -> str:
    if not SLACK_LOG_TIME_RE.search(text):
        return ""
    lower = text.lower()
    interesting = (
        "conversations.history",
        "message-pane",
        "message-history",
        "message-list",
        "action:message",
        "chat.postmessage",
        "webapp_message_send",
        "unread-counts",
        "history-fetch",
        "check-unreads",
        "workspace mounted",
    )
    if not any(token in lower for token in interesting):
        return ""
    summary = _slack_compact(text)
    summary = re.sub(r"\b[0-9a-f]{8}-[0-9]{10}\.[0-9]{3}\s+", "", summary, flags=re.IGNORECASE)
    return summary[:500]


def _slack_compact(text: str) -> str:
    text = re.sub(r"^\[\d\d/\d\d/\d\d,\s+\d\d:\d\d:\d\d:\d{3}\]\s*", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:500]


def _slack_log_timestamp(text: str) -> str:
    match = SLACK_LOG_TIME_RE.search(text)
    if not match:
        return ""
    month, day, year, hour, minute, second, millis = match.groups()
    try:
        value = datetime(
            2000 + int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            int(millis) * 1000,
            tzinfo=timezone.utc,
        )
    except ValueError:
        return ""
    return value.isoformat()


def _slack_timestamp(text: str) -> str:
    match = SLACK_TS_RE.search(text)
    if not match:
        return ""
    try:
        return datetime.fromtimestamp(float(match.group(1)), tz=timezone.utc).isoformat()
    except ValueError:
        return ""


def _dedupe_record_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for row in rows:
        key = "|".join(
            str(row.get(name) or "").strip().lower()
            for name in ("application", "record_type", "record_key", "url", "timestamp_utc", "message_text")
        )
        if not key.strip("|"):
            key = str(row.get("dedupe_key") or "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _text_file_rows(path: Path, app: str, artifact_type: str) -> list[dict[str, object]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not text.strip():
        return []
    if artifact_type == "json_file":
        rows = _json_file_rows(path, app, text)
        if rows:
            return rows
    record_type = "note_content" if app in NOTE_APPS else "text_content"
    if app in FILE_KNOWLEDGE_APPS | REMOTE_ACCESS_APPS:
        record_type = "application_config_or_history"
    content = text[:TEXT_LIMIT]
    return [
        {
            "application": app,
            "user_profile": _user_profile_from_path(path),
            "artifact_type": artifact_type,
            "source_path": str(path),
            "store_path": str(path.parent),
            "record_key": path.name,
            "record_type": record_type,
            "url": _first_url(content),
            "host": _host_from_url(_first_url(content)),
            "email": _first_email(content),
            "timestamp_utc": _first_timestamp(content),
            "message_text": content,
            "raw_text": content,
            "dedupe_key": _dedupe_key(app, path, path.name, content),
        }
    ]


def _json_file_rows(path: Path, app: str, text: str) -> list[dict[str, object]]:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows: list[dict[str, object]] = []
    for index, item in enumerate(_walk_text_objects(obj), start=1):
        content = _clean_message_text(str(item.get("text") or ""))
        if not _looks_like_message_body(content):
            continue
        raw_text = json.dumps(item.get("object"), default=str, sort_keys=True)[:TEXT_LIMIT]
        rows.append(
            {
                "application": app,
                "user_profile": _user_profile_from_path(path),
                "artifact_type": "json_file",
                "source_path": str(path),
                "store_path": str(path.parent),
                "record_key": f"{path.name}:{index}",
                "record_type": "note_content" if app in NOTE_APPS else "message_candidate",
                "url": _first_url(raw_text),
                "host": _host_from_url(_first_url(raw_text)),
                "email": _first_email(raw_text),
                "timestamp_utc": _first_timestamp(raw_text),
                "message_text": content[:TEXT_LIMIT],
                "raw_text": raw_text,
                "dedupe_key": _dedupe_key(app, path, f"{path.name}:{index}", content),
            }
        )
        if len(rows) >= 1000:
            break
    return rows


def _structured_message_rows(path: Path, app: str) -> list[dict[str, object]]:
    if app not in CHAT_APPS:
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    rows: list[dict[str, object]] = []
    if app == "Microsoft Teams":
        rows.extend(_teams_fragment_message_rows(data, path))
    for record_index, obj in enumerate(_json_objects_from_bytes(data), start=1):
        for message_index, message in enumerate(_walk_message_objects(obj, app), start=1):
            row = _message_row_from_object(
                message,
                app=app,
                path=path,
                record_key=f"{record_index}:{message_index}",
            )
            if row:
                rows.append(row)
        if len(rows) >= 2000:
            break
    return rows


def _teams_fragment_message_rows(data: bytes, path: Path) -> list[dict[str, object]]:
    strings = [match.group(0).decode("utf-8", errors="replace") for match in STRING_RE.finditer(data)]
    rows: list[dict[str, object]] = []
    candidate_indexes = [
        index
        for index, text in enumerate(strings)
        if "content" in text.lower() and ("<div" in text.lower() or index + 1 < len(strings) and "<div" in strings[index + 1].lower())
    ]
    seen_windows: set[str] = set()
    for ordinal, index in enumerate(candidate_indexes, start=1):
        start = max(0, index - 35)
        end = min(len(strings), index + 70)
        window = strings[start:end]
        blob = "\n".join(window)
        content = _teams_fragment_content(window)
        if not content:
            continue
        message_text = _clean_message_text(content)
        if not _looks_like_message_body(message_text):
            continue
        conversation_id = _regex_first(blob, r'conversationId"?\s*"?([A-Za-z0-9:._@-]+)')
        parent_message_id = _regex_first(blob, r'parentMessageId"?\s*"?([0-9]{10,})')
        creator = _regex_first(blob, r'creator"?[,]?([^\n"]+)')
        id_union = _regex_first(blob, r'idUnion"?\s*"?([0-9]{8,})')
        timestamp = (
            _regex_first(blob, r'originalarrivaltime"?\s*"?([^"\n]+)')
            or _regex_first(blob, r'composetime"?\s*"?([^"\n]+)')
            or _normalize_timestamp(parent_message_id)
        )
        message_type = _regex_first(blob, r'messagetype"?\s*"?([^"\n]+)') or ("RichText/Html" if "<div" in content else "Text")
        identity = "|".join([conversation_id, parent_message_id, id_union, creator, message_text])
        if identity in seen_windows:
            continue
        seen_windows.add(identity)
        raw_json = json.dumps({"fragment_window": window}, default=str)[:TEXT_LIMIT]
        rows.append(
            {
                "application": "Microsoft Teams",
                "user_profile": _user_profile_from_path(path),
                "source_path": str(path),
                "store_path": str(path.parent),
                "record_key": f"teams-fragment:{ordinal}",
                "platform_message_id": id_union or parent_message_id,
                "conversation_id": conversation_id,
                "channel_id": conversation_id,
                "thread_id": parent_message_id,
                "sender_id": creator,
                "sender_name": _teams_sender_name(blob),
                "sender_email": _first_email(blob),
                "recipient": "",
                "timestamp_utc": timestamp,
                "message_type": message_type,
                "message_text": message_text[:TEXT_LIMIT],
                "message_html": content[:TEXT_LIMIT] if "<" in content and ">" in content else "",
                "url": _first_url(blob),
                "parser_confidence": "teams_leveldb_fragment",
                "raw_json": raw_json,
                "dedupe_key": _dedupe_key("Microsoft Teams", path, f"teams-fragment:{ordinal}", identity),
            }
        )
    return rows


def _teams_fragment_content(window: list[str]) -> str:
    for index, text in enumerate(window):
        lower = text.lower()
        if "content" not in lower:
            continue
        candidates = [text]
        if index + 1 < len(window):
            candidates.append(window[index + 1])
        if index + 2 < len(window):
            candidates.append(window[index + 2])
        joined = "\n".join(candidates)
        match = re.search(r'(<div\b.*?</div>)', joined, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
        after = re.sub(r"^.*?content[^A-Za-z0-9<]*", "", text, flags=re.IGNORECASE).strip()
        if after and not after.lower().startswith(("type", "text", "client", "render")):
            return after
    return ""


def _looks_like_message_body(text: str) -> bool:
    lowered = text.lower().strip()
    if len(lowered) < 8:
        return False
    if not re.search(r"[a-z]{3,}", lowered):
        return False
    technical_tokens = ("processedf", "isrichmessagepropertiesprocessed", "isrichcontentprocessed")
    if any(token in lowered for token in technical_tokens):
        return False
    return True


def _teams_sender_name(blob: str) -> str:
    for match in re.finditer(r'imdisplayname"?\s*"?([^"\n]+)', blob, flags=re.IGNORECASE):
        value = match.group(1).strip()
        if value and value.lower() not in {"null", "undefined"}:
            return value
    return ""


def _regex_first(text: str, pattern: str) -> str:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _json_objects_from_bytes(data: bytes) -> Iterable[object]:
    decoder = json.JSONDecoder()
    seen: set[tuple[int, int]] = set()
    for match in STRING_RE.finditer(data):
        text = match.group(0).decode("utf-8", errors="replace")
        if "{" not in text and "[" not in text:
            continue
        for index, char in enumerate(text):
            if char not in "{[":
                continue
            try:
                obj, end = decoder.raw_decode(text[index:])
            except json.JSONDecodeError:
                continue
            identity = (match.start() + index, end)
            if identity in seen:
                continue
            seen.add(identity)
            yield obj


def _walk_message_objects(obj: object, app: str) -> Iterable[dict[str, object]]:
    if isinstance(obj, dict):
        if _is_structured_message(obj, app):
            yield obj
        for value in obj.values():
            yield from _walk_message_objects(value, app)
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk_message_objects(value, app)


def _is_structured_message(obj: dict[str, object], app: str) -> bool:
    lowered = {str(key).lower() for key in obj}
    if app == "Slack":
        return "text" in lowered and bool(lowered & {"ts", "client_msg_id", "user", "channel", "team"})
    if app == "Microsoft Teams":
        has_text = bool(lowered & {"content", "text", "message", "body"})
        has_message_marker = bool(lowered & {"messagetype", "originalarrivaltime", "clientmessageid", "conversationid", "from"})
        return has_text and has_message_marker
    has_text = bool(lowered & {"content", "text", "message", "body", "markdown"})
    has_message_marker = bool(
        lowered
        & {
            "role", "author", "sender", "from", "user", "username", "created_at", "createdat",
            "create_time", "timestamp", "conversation_id", "conversationid", "channel_id",
            "chat_id", "message_id", "messageid", "thread_id", "threadid",
        }
    )
    return has_text and has_message_marker


def _message_row_from_object(obj: dict[str, object], *, app: str, path: Path, record_key: str) -> dict[str, object] | None:
    raw_json = json.dumps(obj, default=str, sort_keys=True)[:TEXT_LIMIT]
    message_html = _message_html(obj, app)
    message_text = _clean_message_text(_first_nested_text(obj, ("text", "content", "message")) or message_html)
    if not message_text:
        return None
    timestamp = _structured_timestamp(obj, app)
    platform_id = _first_nested_text(obj, ("client_msg_id", "clientmessageid", "client_message_id", "id", "messageid", "message_id", "uuid", "ts"))
    conversation_id = _first_nested_text(obj, ("conversationid", "conversation_id", "conversationId", "threadId", "thread_id", "replyChainId", "chat_id"))
    channel_id = _first_nested_text(obj, ("channel", "channel_id", "channelId", "teamId", "room_id", "server_id"))
    sender_id = _sender_value(obj, ("id", "user", "userId", "mri"))
    sender_name = _sender_value(obj, ("displayName", "name", "imdisplayname", "real_name", "username"))
    sender_email = _first_email(raw_json)
    url = _first_url(raw_json)
    return {
        "application": app,
        "user_profile": _user_profile_from_path(path),
        "source_path": str(path),
        "store_path": str(path.parent),
        "record_key": record_key,
        "platform_message_id": platform_id,
        "conversation_id": conversation_id,
        "channel_id": channel_id,
        "thread_id": _first_nested_text(obj, ("thread_ts", "threadId", "thread_id", "replyChainId", "parent_id")),
        "sender_id": sender_id,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "recipient": _first_nested_text(obj, ("recipient", "to", "members")),
        "timestamp_utc": timestamp,
        "message_type": _first_nested_text(obj, ("type", "messagetype", "messageType", "subtype")) or "message",
        "message_text": message_text[:TEXT_LIMIT],
        "message_html": message_html[:TEXT_LIMIT],
        "url": url,
        "parser_confidence": "structured_json",
        "raw_json": raw_json,
        "dedupe_key": _dedupe_key(app, path, record_key, "|".join([platform_id, conversation_id, timestamp, message_text])),
    }


def _message_html(obj: dict[str, object], app: str) -> str:
    if app == "Microsoft Teams":
        body = obj.get("body")
        if isinstance(body, dict):
            content = body.get("content")
            if isinstance(content, str):
                return content
    value = obj.get("content")
    return value if isinstance(value, str) and "<" in value and ">" in value else ""


def _clean_message_text(text: str) -> str:
    text = html.unescape(text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace("\\n", "\n").replace("\\r", "\n")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _first_nested_text(obj: object, names: tuple[str, ...]) -> str:
    wanted = {name.lower() for name in names}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in wanted and value not in (None, ""):
                if isinstance(value, (str, int, float)):
                    return str(value)
                if isinstance(value, list):
                    return ",".join(str(item) for item in value if item not in (None, ""))
            found = _first_nested_text(value, names)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _first_nested_text(value, names)
            if found:
                return found
    return ""


def _walk_text_objects(obj: object) -> Iterable[dict[str, object]]:
    if isinstance(obj, dict):
        text = _first_nested_text(obj, ("text", "content", "body", "markdown", "message"))
        if text:
            yield {"text": text, "object": obj}
        for value in obj.values():
            yield from _walk_text_objects(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk_text_objects(value)


def _sender_value(obj: dict[str, object], names: tuple[str, ...]) -> str:
    sender = obj.get("from") or obj.get("sender") or obj.get("user")
    if isinstance(sender, dict):
        found = _first_nested_text(sender, names)
        if found:
            return found
    if isinstance(sender, str) and "id" in names:
        return sender
    return _first_nested_text(obj, names)


def _structured_timestamp(obj: dict[str, object], app: str) -> str:
    if app == "Slack":
        value = _first_nested_text(obj, ("ts", "event_ts", "thread_ts"))
        if value:
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
            except ValueError:
                pass
    value = _first_nested_text(
        obj,
        ("originalarrivaltime", "createdDateTime", "created_at", "createdAt", "create_time", "update_time", "timestamp", "time", "date", "ts"),
    )
    return _normalize_timestamp(value)


def _normalize_timestamp(value: str) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if EPOCH_MS_RE.fullmatch(text):
        try:
            return datetime.fromtimestamp(int(text[:13]) / 1000, tz=timezone.utc).isoformat()
        except ValueError:
            return ""
    return text.replace(" ", "T")


def _dedupe_messages(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped = []
    for row in rows:
        key = "|".join(
            str(row.get(name) or "").strip().lower()
            for name in ("application", "timestamp_utc", "sender_name", "conversation_id", "message_text")
        )
        if key.strip("|") == "":
            key = str(row.get("dedupe_key") or "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _looks_relevant(text: str) -> bool:
    lower = text.lower()
    if URL_RE.search(text):
        return True
    return any(token in lower for token in ("message", "channel", "conversation", "thread", "chat", "user", "email", "@"))


def _first_url(text: str) -> str:
    match = URL_RE.search(text)
    if not match:
        return ""
    url = match.group(0)
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    return url if parsed.scheme and parsed.netloc else ""


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    try:
        return urlparse(url).netloc.lower()
    except ValueError:
        return ""


def _first_email(text: str) -> str:
    match = EMAIL_RE.search(text)
    return match.group(0).lower() if match else ""


def _first_timestamp(text: str) -> str:
    match = ISO_TIME_RE.search(text)
    if match:
        return match.group(0).replace(" ", "T")
    match = EPOCH_MS_RE.search(text)
    if match:
        value = match.group(0)
        try:
            seconds = int(value[:13]) / 1000
        except ValueError:
            return ""
        from datetime import datetime, timezone

        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    return ""


def _record_type(text: str) -> str:
    lower = text.lower()
    if "message" in lower or "msg" in lower or "chat" in lower:
        return "message_candidate"
    if "channel" in lower or "thread" in lower or "conversation" in lower:
        return "conversation_candidate"
    if _first_url(text):
        return "url_reference"
    if _first_email(text):
        return "identity_reference"
    return "text_candidate"


def _message_text(text: str) -> str:
    cleaned = text.replace("\\n", "\n").replace("\\r", "\n")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:TEXT_LIMIT]


def _dedupe_key(app: str, path: Path, record_key: str, text: str) -> str:
    basis = "|".join([app, str(path), record_key, text[:500]]).lower()
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()


def _user_profile_from_path(path: Path) -> str:
    parts = path.parts
    lowered = [part.lower() for part in parts]
    for marker in ("users", "documents and settings"):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1]
    for marker in ("mail", "messaging"):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1]
    return ""


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
