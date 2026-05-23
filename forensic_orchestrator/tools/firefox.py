from __future__ import annotations

import csv
import fnmatch
import json
import os
import re
import sqlite3
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import lz4.block


FIREFOX_HISTORY_FIELDS = [
    "source_path",
    "profile_path",
    "url",
    "title",
    "visit_time_utc",
    "visit_type",
    "visit_count",
    "typed",
    "hidden",
    "frecency",
    "visit_source",
    "visit_source_label",
    "local_vs_synced",
]
FIREFOX_COOKIES_FIELDS = [
    "source_path",
    "profile_path",
    "host",
    "name",
    "value",
    "path",
    "created_utc",
    "last_accessed_utc",
    "expires_utc",
    "is_secure",
    "is_http_only",
]
FIREFOX_DOWNLOAD_FIELDS = [
    "browser",
    "source_path",
    "profile_path",
    "target_path",
    "tab_url",
    "site_url",
    "referrer",
    "start_time_utc",
    "end_time_utc",
    "received_bytes",
    "total_bytes",
    "state",
    "danger_type",
    "interrupt_reason",
]
FIREFOX_ARTIFACT_FIELDS = [
    "browser", "artifact_type", "source_path", "profile_path", "name", "value",
    "url", "title", "host", "local_path", "timestamp_utc", "details_json",
]
FIREFOX_SESSION_FIELDS = [
    "browser", "source_path", "profile_path", "session_type", "window_id",
    "tab_id", "tab_index", "navigation_index", "url", "title",
    "referrer_url", "timestamp_utc", "last_active_time_utc", "is_current",
    "is_pinned", "parser", "details_json",
]
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
URL_RE = re.compile(rb"https?://[^\s\"'<>\\\x00]{4,500}", re.IGNORECASE)


def parse_firefox_artifacts_to_csv(source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    history_rows = []
    cookie_rows = []
    download_rows = []
    artifact_rows = []
    session_rows = []
    if source.exists():
        for places in _rglob(source, "places.sqlite"):
            history_rows.extend(_history_rows(places, source))
            download_rows.extend(_download_rows(places, source))
            artifact_rows.extend(_bookmark_rows(places, source))
        for cookies in _rglob(source, "cookies.sqlite"):
            cookie_rows.extend(_cookie_rows(cookies, source))
        for formhistory in _rglob(source, "formhistory.sqlite"):
            artifact_rows.extend(_formhistory_rows(formhistory, source))
        for extensions in _rglob(source, "extensions.json"):
            artifact_rows.extend(_extensions_rows(extensions, source))
        for prefs in _rglob(source, "prefs.js"):
            artifact_rows.extend(_prefs_rows(prefs, source))
        for signed_in_user in _rglob(source, "signedInUser.json"):
            artifact_rows.extend(_signed_in_user_rows(signed_in_user, source))
        for permissions in _rglob(source, "permissions.sqlite"):
            artifact_rows.extend(_notification_rows(permissions, source))
        for session in _rglob(source, "*.jsonlz4"):
            session_rows.extend(_session_rows(session, source))
    history_csv = output / "FirefoxHistory.csv"
    cookies_csv = output / "FirefoxCookies.csv"
    downloads_csv = output / "BrowserDownloads.csv"
    artifacts_csv = output / "FirefoxArtifacts.csv"
    sessions_csv = output / "FirefoxSessionEntries.csv"
    _write_csv(history_csv, FIREFOX_HISTORY_FIELDS, history_rows)
    _write_csv(cookies_csv, FIREFOX_COOKIES_FIELDS, cookie_rows)
    _write_csv(downloads_csv, FIREFOX_DOWNLOAD_FIELDS, download_rows)
    _write_csv(artifacts_csv, FIREFOX_ARTIFACT_FIELDS, artifact_rows)
    _write_csv(sessions_csv, FIREFOX_SESSION_FIELDS, session_rows)
    return [history_csv, cookies_csv, downloads_csv, artifacts_csv, sessions_csv]


def _rglob(root: Path, pattern: str) -> list[Path]:
    matches: list[Path] = []
    for current_root, _, filenames in os.walk(root, onerror=lambda _error: None):
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                matches.append(Path(current_root) / filename)
    return sorted(matches)


def _history_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    columns = _columns(path, "moz_places")
    sync_expr = "moz_places.syncStatus" if "syncStatus" in columns else "NULL"
    query = f"""
        SELECT moz_places.url, moz_places.title, moz_places.visit_count, moz_places.typed,
               moz_places.hidden, moz_places.frecency, moz_historyvisits.visit_date,
               moz_historyvisits.visit_type, {sync_expr} AS sync_status
        FROM moz_historyvisits
        JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
        ORDER BY moz_historyvisits.visit_date
    """
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query).fetchall()
    except sqlite3.Error:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass
    profile = _profile_path(path, source_root)
    return [
        {
            "source_path": str(path),
            "profile_path": profile,
            "url": row["url"],
            "title": row["title"],
            "visit_time_utc": _firefox_time(row["visit_date"]),
            "visit_type": row["visit_type"],
            "visit_count": row["visit_count"],
            "typed": row["typed"],
            "hidden": row["hidden"],
            "frecency": row["frecency"],
            "visit_source": row["sync_status"],
            "visit_source_label": _firefox_visit_source_label(row["sync_status"]),
            "local_vs_synced": _firefox_local_vs_synced(row["sync_status"]),
        }
        for row in rows
    ]


def _cookie_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    query = """
        SELECT host, name, value, path, creationTime, lastAccessed, expiry,
               isSecure, isHttpOnly
        FROM moz_cookies
        ORDER BY lastAccessed
    """
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query).fetchall()
    except sqlite3.Error:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass
    profile = _profile_path(path, source_root)
    return [
        {
            "source_path": str(path),
            "profile_path": profile,
            "host": row["host"],
            "name": row["name"],
            "value": row["value"],
            "path": row["path"],
            "created_utc": _firefox_time(row["creationTime"]),
            "last_accessed_utc": _firefox_time(row["lastAccessed"]),
            "expires_utc": _unix_time(row["expiry"]),
            "is_secure": row["isSecure"],
            "is_http_only": row["isHttpOnly"],
        }
        for row in rows
    ]


def _download_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    query = """
        SELECT moz_places.id AS place_id, moz_places.url, moz_anno_attributes.name AS annotation_name,
               moz_annos.content, moz_annos.dateAdded, moz_annos.lastModified
        FROM moz_annos
        JOIN moz_anno_attributes ON moz_anno_attributes.id = moz_annos.anno_attribute_id
        JOIN moz_places ON moz_places.id = moz_annos.place_id
        WHERE moz_anno_attributes.name LIKE 'downloads/%'
        ORDER BY moz_annos.dateAdded
    """
    grouped: dict[int, dict[str, object]] = {}
    for row in _query(path, query):
        place_id = row["place_id"]
        item = grouped.setdefault(
            place_id,
            {
                "browser": "firefox",
                "source_path": str(path),
                "profile_path": _profile_path(path, source_root),
                "tab_url": row["url"] or "",
                "site_url": _site_url(row["url"]),
                "start_time_utc": _firefox_time(row["dateAdded"]),
                "end_time_utc": _firefox_time(row["lastModified"]),
            },
        )
        name = str(row["annotation_name"] or "")
        content = str(row["content"] or "")
        if name.endswith("destinationFileURI"):
            item["target_path"] = _file_uri_to_path(content)
        elif name.endswith("metaData"):
            metadata = _parse_download_metadata(content)
            if metadata:
                item["state"] = _download_state(metadata.get("state"))
                item["end_time_utc"] = _unix_millis_time(metadata.get("endTime")) or item.get("end_time_utc")
                size = metadata.get("fileSize")
                if size is not None:
                    item["received_bytes"] = str(size)
                    item["total_bytes"] = str(size)
                item["danger_type"] = "deleted" if metadata.get("deleted") is True else ""
    return [row for row in grouped.values() if row.get("target_path") or row.get("tab_url")]


def _bookmark_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    query = """
        SELECT moz_bookmarks.title, moz_places.url, moz_bookmarks.dateAdded,
               moz_bookmarks.lastModified, moz_bookmarks.type
        FROM moz_bookmarks
        LEFT JOIN moz_places ON moz_places.id = moz_bookmarks.fk
        WHERE moz_bookmarks.type IN (1, 2)
        ORDER BY moz_bookmarks.dateAdded
    """
    return [
        _artifact_row(
            path, source_root, "bookmark" if row["url"] else "bookmark_folder",
            name=row["title"] or "", title=row["title"] or "", url=row["url"] or "",
            timestamp=_firefox_time(row["dateAdded"]),
            details={"last_modified_utc": _firefox_time(row["lastModified"]), "type": row["type"]},
        )
        for row in _query(path, query)
    ]


def _formhistory_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    query = "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory ORDER BY lastUsed"
    return [
        _artifact_row(
            path, source_root, "autocomplete_formhistory",
            name=row["fieldname"] or "", value=row["value"] or "",
            timestamp=_firefox_time(row["lastUsed"]),
            details={"times_used": row["timesUsed"], "first_used_utc": _firefox_time(row["firstUsed"])},
        )
        for row in _query(path, query)
    ]


def _extensions_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    data = _read_json(path)
    addons = data.get("addons") if isinstance(data, dict) else None
    rows = []
    for addon in addons or []:
        rows.append(_artifact_row(
            path, source_root, "extension",
            name=str(addon.get("defaultLocale", {}).get("name") or addon.get("id") or ""),
            value=str(addon.get("version") or ""),
            details=addon,
        ))
    return rows


def _prefs_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows = []
    prefs: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        match = re.match(r'user_pref\("([^"]+)",\s*(.*)\);', line.strip())
        if not match:
            continue
        name, value = match.groups()
        prefs[name] = value.strip()
        if any(token in name for token in ("privacy", "sync", "browser.zoom", "permissions", "safebrowsing")):
            rows.append(_artifact_row(path, source_root, "preference", name=name, value=value[:2000], details={"raw": line.strip()}))
    rows.extend(_firefox_sync_pref_rows(path, source_root, prefs))
    return rows


def _firefox_sync_pref_rows(path: Path, source_root: Path, prefs: dict[str, str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    username = _pref_value(prefs.get("services.sync.username"))
    client_guid = _pref_value(prefs.get("services.sync.client.GUID"))
    device_name = _pref_value(prefs.get("identity.fxaccounts.account.device.name"))
    desktop_count = _pref_value(prefs.get("services.sync.clients.devices.desktop"))
    mobile_count = _pref_value(prefs.get("services.sync.clients.devices.mobile"))
    last_sync = _firefox_sync_time(_pref_value(prefs.get("services.sync.clients.lastSync") or prefs.get("services.sync.lastSync")))
    last_tab_fetch = _firefox_sync_time(_pref_value(prefs.get("services.sync.lastTabFetch")))
    tabs_last_sync = _firefox_sync_time(_pref_value(prefs.get("services.sync.tabs.lastSync")))
    if username or client_guid or device_name or desktop_count or mobile_count:
        rows.append(_artifact_row(
            path,
            source_root,
            "firefox_sync_device_summary",
            name=device_name,
            value=username,
            timestamp=last_sync,
            details={
                "username": username,
                "client_guid": client_guid,
                "device_name": device_name,
                "desktop_devices": desktop_count,
                "mobile_devices": mobile_count,
                "clients_last_sync_utc": last_sync,
                "last_tab_fetch_utc": last_tab_fetch,
                "tabs_last_sync_utc": tabs_last_sync,
            },
        ))
    return rows


def _signed_in_user_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    data = _read_json(path)
    if not isinstance(data, dict):
        return []
    account = data.get("accountData") if isinstance(data.get("accountData"), dict) else {}
    profile_cache = data.get("profileCache") if isinstance(data.get("profileCache"), dict) else {}
    profile = profile_cache.get("profile") if isinstance(profile_cache.get("profile"), dict) else {}
    rows: list[dict[str, object]] = []
    device = account.get("device") if isinstance(account.get("device"), dict) else {}
    if account or profile:
        rows.append(_artifact_row(
            path,
            source_root,
            "firefox_sync_account",
            name=str(profile.get("displayName") or account.get("email") or ""),
            value=str(account.get("email") or profile.get("email") or ""),
            details={
                "email": account.get("email") or profile.get("email"),
                "uid": account.get("uid") or profile.get("uid"),
                "verified": account.get("verified"),
                "display_name": profile.get("displayName"),
            },
        ))
    if device:
        rows.append(_artifact_row(
            path,
            source_root,
            "firefox_sync_device",
            name=str(device.get("name") or device.get("id") or ""),
            value=str(device.get("id") or ""),
            details={
                "device_id": device.get("id"),
                "registration_version": device.get("registrationVersion"),
                "registered_commands": device.get("registeredCommandsKeys"),
                "send_tab_configured": bool(device.get("sendTabKeys")),
            },
        ))
    return rows


def _notification_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    query = "SELECT origin, type, permission, expireType, expireTime, modificationTime FROM moz_perms"
    rows = []
    for row in _query(path, query):
        if str(row["type"]).lower() == "desktop-notification":
            rows.append(_artifact_row(
                path, source_root, "notification_permission",
                name=row["type"] or "", value=str(row["permission"] or ""),
                url=row["origin"] or "", host=_host(row["origin"] or ""),
                timestamp=_firefox_time(row["modificationTime"]),
                details={"expire_type": row["expireType"], "expire_time": row["expireTime"]},
            ))
    return rows


def _session_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    data = _read_jsonlz4(path)
    if isinstance(data, dict):
        rows: list[dict[str, object]] = []
        for window_index, window in enumerate(data.get("windows") or []):
            selected_tab_index = _int(window.get("selected"))
            for tab_index, tab in enumerate(window.get("tabs") or []):
                selected_entry_index = _int(tab.get("index"))
                for entry_index, entry in enumerate(tab.get("entries") or []):
                    if entry.get("url"):
                        rows.append(_session_row(
                            path,
                            source_root,
                            session_type=_session_type(path),
                            window_id=str(window_index),
                            tab_id=str(tab.get("id") or ""),
                            tab_index=str(tab_index),
                            navigation_index=str(entry_index),
                            url=str(entry.get("url") or ""),
                            title=str(entry.get("title") or ""),
                            referrer_url=str(entry.get("referrer") or ""),
                            timestamp=_firefox_session_time(entry.get("lastAccessed") or entry.get("last_accessed")),
                            is_current=str((selected_entry_index or 1) - 1 == entry_index),
                            is_pinned=str(bool(tab.get("pinned"))) if "pinned" in tab else "",
                            parser="jsonlz4",
                            details={
                                "window_index": window_index,
                                "selected_tab_index": selected_tab_index,
                                "tab_index": tab_index,
                                "selected_entry_index": selected_entry_index,
                                "entry": entry,
                            },
                        ))
        return rows
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    seen = set()
    rows = []
    for match in URL_RE.findall(raw):
        url = match.decode("utf-8", errors="replace")
        if url in seen:
            continue
        seen.add(url)
        rows.append(_session_row(path, source_root, url=url, parser="binary_url_carve", details={"parser": "binary_url_carve"}))
    return rows


def _query(path: Path, query: str) -> list[sqlite3.Row]:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn.execute(query).fetchall()
    except sqlite3.Error:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _columns(path: Path, table: str) -> set[str]:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    except sqlite3.Error:
        return set()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _firefox_visit_source_label(value: object) -> str:
    source = _int(value)
    if source is None:
        return ""
    return {
        0: "unknown_or_normal",
        1: "new_or_changed",
        2: "synced",
    }.get(source, str(source))


def _firefox_local_vs_synced(value: object) -> str:
    source = _int(value)
    if source == 2:
        return "synced"
    if source in {0, 1}:
        return "local_or_changed"
    return "unknown"


def _artifact_row(
    path: Path,
    source_root: Path,
    artifact_type: str,
    *,
    name: str = "",
    value: str = "",
    url: str = "",
    title: str = "",
    host: str = "",
    local_path: str = "",
    timestamp: str | None = None,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "browser": "firefox",
        "artifact_type": artifact_type,
        "source_path": str(path),
        "profile_path": _profile_path(path, source_root),
        "name": name,
        "value": value,
        "url": url,
        "title": title,
        "host": host or _host(url),
        "local_path": local_path,
        "timestamp_utc": timestamp,
        "details_json": json.dumps(details or {}, sort_keys=True, default=str),
    }


def _session_row(
    path: Path,
    source_root: Path,
    *,
    session_type: str = "",
    window_id: str = "",
    tab_id: str = "",
    tab_index: str = "",
    navigation_index: str = "",
    url: str = "",
    title: str = "",
    referrer_url: str = "",
    timestamp: str | None = None,
    last_active_time: str | None = None,
    is_current: str = "",
    is_pinned: str = "",
    parser: str = "",
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "browser": "firefox",
        "source_path": str(path),
        "profile_path": _profile_path(path, source_root),
        "session_type": session_type or _session_type(path),
        "window_id": window_id,
        "tab_id": tab_id,
        "tab_index": tab_index,
        "navigation_index": navigation_index,
        "url": url,
        "title": title,
        "referrer_url": referrer_url,
        "timestamp_utc": timestamp,
        "last_active_time_utc": last_active_time,
        "is_current": is_current,
        "is_pinned": is_pinned,
        "parser": parser,
        "details_json": json.dumps(details or {}, sort_keys=True, default=str),
    }


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _profile_path(path: Path, source_root: Path) -> str:
    try:
        return str(path.parent.relative_to(source_root))
    except ValueError:
        return str(path.parent)


def _firefox_time(value: int | None) -> str | None:
    if value is None:
        return None
    try:
        dt = UNIX_EPOCH + timedelta(microseconds=int(value))
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _unix_time(value: int | None) -> str | None:
    if value is None:
        return None
    try:
        dt = UNIX_EPOCH + timedelta(seconds=int(value))
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _unix_millis_time(value: object) -> str | None:
    number = _int(value)
    if number is None:
        return None
    try:
        dt = UNIX_EPOCH + timedelta(milliseconds=number)
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _parse_download_metadata(value: str) -> dict[str, object]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _download_state(value: object) -> str:
    if value is None:
        return ""
    states = {0: "in_progress", 1: "complete", 2: "failed", 3: "canceled"}
    number = _int(value)
    if number is not None:
        return states.get(number, str(number))
    return str(value)


def _file_uri_to_path(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme.lower() != "file":
        return value
    path = parsed.path
    if parsed.netloc:
        return f"//{parsed.netloc}{path}"
    if re.match(r"^/[A-Za-z]:/", path):
        path = path[1:]
    return path.replace("/", "\\")


def _site_url(value: str | None) -> str:
    if not value:
        return ""
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}/"


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _pref_value(value: str | None) -> str:
    if value is None:
        return ""
    text = value.strip().rstrip(";")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text.strip('"')
    return "" if parsed is None else str(parsed)


def _firefox_sync_time(value: str) -> str | None:
    if not value:
        return None
    try:
        number = float(value)
    except ValueError:
        for fmt in ("%a %b %d %Y %H:%M:%S GMT%z (%Z)", "%a %b %d %Y %H:%M:%S GMT%z"):
            try:
                return datetime.strptime(value, fmt).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            except ValueError:
                continue
        return value
    try:
        return (UNIX_EPOCH + timedelta(seconds=number)).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return value


def _read_jsonlz4(path: Path) -> object:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if raw.startswith(b"mozLz40\0"):
        if len(raw) < 12:
            return None
        size = int.from_bytes(raw[8:12], "little", signed=False)
        payload = raw[12:]
        try:
            return json.loads(lz4.block.decompress(payload, uncompressed_size=size))
        except (lz4.block.LZ4BlockError, json.JSONDecodeError, UnicodeDecodeError):
            try:
                return json.loads(zlib.decompress(raw[8:]))
            except (zlib.error, json.JSONDecodeError, UnicodeDecodeError):
                return None
    return None


def _firefox_session_time(value: object) -> str | None:
    number = _int(value)
    if number is None:
        return None
    if number > 10_000_000_000_000:
        return _firefox_time(number)
    if number > 10_000_000_000:
        try:
            dt = UNIX_EPOCH + timedelta(milliseconds=number)
            return dt.isoformat().replace("+00:00", "Z")
        except (OverflowError, ValueError):
            return None
    return None


def _session_type(path: Path) -> str:
    name = path.name.lower()
    if "recovery" in name:
        return "recovery"
    if "previous" in name:
        return "previous"
    if "upgrade" in name:
        return "upgrade"
    if "sessionstore" in name:
        return "sessionstore"
    return ""


def _int(value: object) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _host(value: str) -> str:
    if not value:
        return ""
    try:
        return urlparse(value).netloc
    except ValueError:
        return ""
