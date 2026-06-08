from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse


PATH_KEY_TOKENS = (
    "path",
    "file",
    "csv",
    "directory",
    "folder",
    "image",
    "artifact",
    "source",
    "destination",
    "contact_sheet",
)


def display_evidence_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = unquote(text).split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
    if text.lower().startswith("file:"):
        parsed = urlparse(text)
        if parsed.netloc and parsed.netloc.lower() not in {"", "localhost"}:
            return f"//{parsed.netloc}{parsed.path}".rstrip("/")
        text = parsed.path or text
    text = re.sub(r"^/([A-Za-z]:/)", r"\1", text)
    drive_match = re.match(r"^([A-Za-z]):/(.*)", text)
    if drive_match:
        drive = drive_match.group(1).upper()
        rest = drive_match.group(2)
        if drive != "C":
            return f"{drive}:/{rest}".rstrip("/")
        text = f"/{rest}"
    text = re.sub(r"/+", "/", text)
    for pattern in (
        r"^cases/[0-9a-fA-F-]{36}/(?:artifacts|mounts/volumes)/[^/]+/",
        r"/cases/[0-9a-fA-F-]{36}/(?:artifacts|mounts/volumes)/[^/]+/",
        r"^/tmp/(?:perceptor|forensic-orchestrator)-mounts/cases/[0-9a-fA-F-]{36}/volumes/[^/]+/",
        r"/artifacts/[^/]+/",
        r"/mounts/volumes/[^/]+/",
    ):
        match = re.search(pattern, text)
        if match:
            text = "/" + text[match.end():].lstrip("/")
            break
    match = re.search(r"(?:^|/)cases/[0-9a-fA-F-]{36}/(outputs|reports|logs|jobs|analytics|images|mounts|artifacts)/", text)
    if match:
        text = "/" + text[match.start(1):].lstrip("/")
    for anchor in (
        "/Windows.old/",
        "/Users/",
        "/ProgramData/",
        "/Program Files/",
        "/Program Files (x86)/",
        "/Windows/",
        "/$Recycle.Bin/",
        "/Recovery/",
    ):
        index = text.lower().find(anchor.lower())
        if index >= 0:
            return text[index:].rstrip("/")
    if not text.startswith("/") and re.match(
        r"^(Users|Windows|ProgramData|Program Files|Program Files \(x86\)|\$Recycle\.Bin|Recovery)(/|$)",
        text,
        re.I,
    ):
        text = "/" + text
    return text.rstrip("/")


def sanitize_report_paths(value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        return {item_key: sanitize_report_paths(item_value, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [sanitize_report_paths(item, key=key) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_report_paths(item, key=key) for item in value)
    if isinstance(value, set):
        return {sanitize_report_paths(item, key=key) for item in value}
    if isinstance(value, str) and _looks_like_report_path_key(key) and _looks_like_path_value(value):
        return display_evidence_path(value)
    return value


def sanitize_report_text(text: str) -> str:
    text = text.replace("\x00", "")
    text = re.sub(
        r"(?P<prefix>^|[\s`'\"(<])cases/[0-9a-fA-F-]{36}/(?:artifacts|mounts/volumes)/[^/\s`'\"<>)]*/",
        lambda match: match.group("prefix") + "/",
        text,
    )
    text = re.sub(
        r"/[^\s`'\"<>)]*/cases/[0-9a-fA-F-]{36}/(?:artifacts|mounts/volumes)/[^/\s`'\"<>)]*/",
        "/",
        text,
    )
    text = re.sub(
        r"/tmp/(?:perceptor|forensic-orchestrator)-mounts/cases/[0-9a-fA-F-]{36}/volumes/[^/\s`'\"<>)]*/",
        "/",
        text,
    )
    text = re.sub(
        r"(?P<prefix>^|[\s`'\"(<])cases/[0-9a-fA-F-]{36}/(?P<kind>outputs|reports|logs|jobs|analytics|images|mounts|artifacts)/",
        lambda match: f"{match.group('prefix')}/{match.group('kind')}/",
        text,
    )
    text = re.sub(
        r"/[^\s`'\"<>)]*/cases/[0-9a-fA-F-]{36}/(outputs|reports|logs|jobs|analytics|images|mounts|artifacts)/",
        r"/\1/",
        text,
    )
    text = re.sub(
        r"\b([A-Za-z]):[\\/]+(Users|Windows|ProgramData|Program Files \(x86\)|Program Files|\$Recycle\.Bin|Recovery)([^\s`'\"<>)]*)",
        lambda match: (
            "/" + match.group(2) + match.group(3).replace("\\", "/")
            if match.group(1).upper() == "C"
            else f"{match.group(1).upper()}:/" + match.group(2) + match.group(3).replace("\\", "/")
        ),
        text,
    )
    text = re.sub(
        r"\b([A-BD-Za-bd-z]):[\\/]+([^\s`'\"<>)]*)",
        lambda match: f"{match.group(1).upper()}:/" + match.group(2).replace("\\", "/"),
        text,
    )
    return text


def _looks_like_report_path_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in PATH_KEY_TOKENS)


def _looks_like_path_value(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if text.lower().startswith("file:"):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return True
    if "\\Users\\" in text or "\\Windows\\" in text or "\\Program Files" in text:
        return True
    if text.startswith(("/", "\\\\")):
        return True
    if "/cases/" in text or "/Users/" in text or "/Windows/" in text:
        return True
    return False
