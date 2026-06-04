from __future__ import annotations

import csv
import fnmatch
import json
import os
import re
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import plyvel


BROWSER_HISTORY_FIELDS = [
    "browser",
    "source_path",
    "profile_path",
    "url",
    "title",
    "visit_time_utc",
    "visit_count",
    "typed_count",
    "visit_source",
    "visit_source_label",
    "local_vs_synced",
]
BROWSER_DOWNLOAD_FIELDS = [
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
BROWSER_COOKIE_FIELDS = [
    "browser",
    "source_path",
    "profile_path",
    "host",
    "name",
    "path",
    "created_utc",
    "last_accessed_utc",
    "expires_utc",
    "is_secure",
    "is_http_only",
]
BROWSER_ARTIFACT_FIELDS = [
    "browser", "artifact_type", "source_path", "profile_path", "name", "value",
    "url", "title", "host", "local_path", "timestamp_utc", "details_json",
]
BROWSER_SESSION_FIELDS = [
    "browser", "source_path", "profile_path", "session_type", "window_id",
    "tab_id", "tab_index", "navigation_index", "url", "title",
    "referrer_url", "timestamp_utc", "last_active_time_utc", "is_current",
    "is_pinned", "parser", "details_json",
]
BROWSER_SITE_SETTING_FIELDS = [
    "browser", "source_path", "profile_path", "setting_type", "origin",
    "host", "setting_name", "setting_value", "last_modified_utc",
    "expiration_utc", "details_json",
]
BROWSER_NOTIFICATION_FIELDS = [
    "browser", "source_path", "profile_path", "origin", "host",
    "notification_id", "title", "body", "tag", "icon", "badge",
    "created_utc", "notification_timestamp_utc", "first_click_utc",
    "last_click_utc", "closed_utc", "num_clicks", "closed_reason",
    "details_json",
]

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
URL_RE = re.compile(rb"https?://[^\s\"'<>\\\x00]{4,500}", re.IGNORECASE)
SNSS_COMMAND_UPDATE_TAB_NAVIGATION = 6
SNSS_COMMAND_SET_SELECTED_NAVIGATION_INDEX = 7
SNSS_COMMAND_SET_TAB_INDEX_IN_WINDOW = 2
SNSS_COMMAND_SET_PINNED_STATE = 12
SNSS_COMMAND_LAST_ACTIVE_TIME = 21


def parse_chromium_artifacts_to_csv(source: Path, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    history_rows = []
    download_rows = []
    cookie_rows = []
    artifact_rows = []
    session_rows = []
    site_setting_rows = []
    notification_rows = []
    if source.exists():
        for history in _rglob(source, "History"):
            history_rows.extend(_history_rows(history, source))
            download_rows.extend(_download_rows(history, source))
        for cookies in _rglob(source, "Cookies"):
            cookie_rows.extend(_cookie_rows(cookies, source))
        for bookmarks in _rglob(source, "Bookmarks"):
            artifact_rows.extend(_bookmark_rows(bookmarks, source))
        for bookmarks in _rglob(source, "Bookmarks.bak"):
            artifact_rows.extend(_bookmark_rows(bookmarks, source))
        for bookmarks in _rglob(source, "Bookmarks.msbak"):
            artifact_rows.extend(_bookmark_rows(bookmarks, source))
        for web_data in _rglob(source, "Web Data"):
            artifact_rows.extend(_autocomplete_rows(web_data, source))
        for shortcuts in _rglob(source, "Shortcuts"):
            artifact_rows.extend(_shortcut_rows(shortcuts, source))
        for predictor in _rglob(source, "Network Action Predictor"):
            artifact_rows.extend(_network_action_predictor_rows(predictor, source))
        for top_sites in _rglob(source, "Top Sites"):
            artifact_rows.extend(_top_sites_rows(top_sites, source))
        for login_data in _rglob(source, "Login Data"):
            artifact_rows.extend(_login_data_rows(login_data, source))
        for preferences in _rglob(source, "Preferences"):
            artifact_rows.extend(_preference_rows(preferences, source))
            site_setting_rows.extend(_site_setting_rows(preferences, source))
        for secure_preferences in _rglob(source, "Secure Preferences"):
            artifact_rows.extend(_preference_rows(secure_preferences, source))
            site_setting_rows.extend(_site_setting_rows(secure_preferences, source))
        for manifest in _rglob(source, "manifest.json"):
            if "extensions" in str(manifest).lower():
                artifact_rows.extend(_extension_rows(manifest, source))
        for session_file in _rglob(source, "*"):
            if _is_session_file(session_file):
                session_rows.extend(_session_rows(session_file, source))
        for sync_db in _rglob(source, "SyncData.sqlite3"):
            artifact_rows.extend(_sync_sqlite_rows(sync_db, source))
        for sync_leveldb in _rglob(source, "LevelDB"):
            if sync_leveldb.is_dir() and sync_leveldb.parent.name.lower() == "sync data":
                artifact_rows.extend(_sync_leveldb_rows(sync_leveldb, source))
        for notification_db in _rglob(source, "Platform Notifications"):
            notification_rows.extend(_notification_rows(notification_db, source))
        for collections_db in _rglob(source, "collectionsSQLite"):
            artifact_rows.extend(_edge_collection_rows(collections_db, source))
    history_csv = output / "BrowserHistory.csv"
    downloads_csv = output / "BrowserDownloads.csv"
    cookies_csv = output / "BrowserCookies.csv"
    artifacts_csv = output / "BrowserArtifacts.csv"
    sessions_csv = output / "BrowserSessionEntries.csv"
    site_settings_csv = output / "BrowserSiteSettings.csv"
    notifications_csv = output / "BrowserNotifications.csv"
    _write_csv(history_csv, BROWSER_HISTORY_FIELDS, history_rows)
    _write_csv(downloads_csv, BROWSER_DOWNLOAD_FIELDS, download_rows)
    _write_csv(cookies_csv, BROWSER_COOKIE_FIELDS, cookie_rows)
    _write_csv(artifacts_csv, BROWSER_ARTIFACT_FIELDS, artifact_rows)
    _write_csv(sessions_csv, BROWSER_SESSION_FIELDS, session_rows)
    _write_csv(site_settings_csv, BROWSER_SITE_SETTING_FIELDS, site_setting_rows)
    _write_csv(notifications_csv, BROWSER_NOTIFICATION_FIELDS, notification_rows)
    return [
        history_csv, downloads_csv, cookies_csv, artifacts_csv,
        sessions_csv, site_settings_csv, notifications_csv,
    ]


def _rglob(root: Path, pattern: str) -> list[Path]:
    matches: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root, onerror=lambda _error: None):
        for dirname in list(dirnames):
            if fnmatch.fnmatch(dirname, pattern):
                matches.append(Path(current_root) / dirname)
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                matches.append(Path(current_root) / filename)
    return sorted(matches)


def _history_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    has_visit_source = _table_exists(path, "visit_source")
    visit_source_select = "visit_source.source AS visit_source" if has_visit_source else "NULL AS visit_source"
    visit_source_join = "LEFT JOIN visit_source ON visit_source.id = visits.id" if has_visit_source else ""
    query = f"""
        SELECT urls.url, urls.title, urls.visit_count, urls.typed_count,
               visits.visit_time, {visit_source_select}
        FROM visits
        JOIN urls ON urls.id = visits.url
        {visit_source_join}
        ORDER BY visits.visit_time
    """
    rows = _query(path, query)
    profile = _profile_path(path, source_root)
    browser = _browser_from_path(path)
    return [
        {
            "browser": browser,
            "source_path": str(path),
            "profile_path": profile,
            "url": row["url"],
            "title": row["title"],
            "visit_time_utc": _webkit_time(row["visit_time"]),
            "visit_count": row["visit_count"],
            "typed_count": row["typed_count"],
            "visit_source": row["visit_source"],
            "visit_source_label": _chromium_visit_source_label(row["visit_source"]),
            "local_vs_synced": _chromium_local_vs_synced(row["visit_source"]),
        }
        for row in rows
    ]


def _download_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    query = """
        SELECT downloads.target_path, downloads.tab_url, downloads.site_url,
               downloads.referrer, downloads.start_time, downloads.end_time,
               downloads.received_bytes, downloads.total_bytes, downloads.state,
               downloads.danger_type, downloads.interrupt_reason
        FROM downloads
        ORDER BY downloads.start_time
    """
    rows = _query(path, query)
    profile = _profile_path(path, source_root)
    browser = _browser_from_path(path)
    return [
        {
            "browser": browser,
            "source_path": str(path),
            "profile_path": profile,
            "target_path": row["target_path"],
            "tab_url": row["tab_url"],
            "site_url": row["site_url"],
            "referrer": row["referrer"],
            "start_time_utc": _webkit_time(row["start_time"]),
            "end_time_utc": _webkit_time(row["end_time"]),
            "received_bytes": row["received_bytes"],
            "total_bytes": row["total_bytes"],
            "state": row["state"],
            "danger_type": row["danger_type"],
            "interrupt_reason": row["interrupt_reason"],
        }
        for row in rows
    ]


def _cookie_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    query = """
        SELECT host_key, name, path, creation_utc, last_access_utc,
               expires_utc, is_secure, is_httponly
        FROM cookies
        ORDER BY last_access_utc
    """
    rows = _query(path, query)
    profile = _profile_path(path, source_root)
    browser = _browser_from_path(path)
    return [
        {
            "browser": browser,
            "source_path": str(path),
            "profile_path": profile,
            "host": row["host_key"],
            "name": row["name"],
            "path": row["path"],
            "created_utc": _webkit_time(row["creation_utc"]),
            "last_accessed_utc": _webkit_time(row["last_access_utc"]),
            "expires_utc": _webkit_time(row["expires_utc"]),
            "is_secure": row["is_secure"],
            "is_http_only": row["is_httponly"],
        }
        for row in rows
    ]


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


def _table_exists(path: Path, table_name: str) -> bool:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?",
            (table_name,),
        ).fetchone()
        return row is not None
    except sqlite3.Error:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _matching_tables(path: Path, prefix: str) -> list[str]:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND lower(name) LIKE ?",
            (f"{prefix.lower()}%",),
        ).fetchall()
        return [str(row[0]) for row in rows]
    except sqlite3.Error:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _chromium_visit_source_label(value: object) -> str:
    source = _int(value)
    return {
        0: "synced",
        1: "browsed",
        2: "extension",
        3: "firefox_imported",
        4: "ie_imported",
        5: "safari_imported",
        8: "chromium_edge_internal_or_generated_source_8",
    }.get(source, "" if source is None else f"unknown_source_{source}")


def _chromium_local_vs_synced(value: object) -> str:
    source = _int(value)
    if source == 0:
        return "synced"
    if source == 1:
        return "local"
    if source in {2, 3, 4, 5}:
        return "imported_or_external"
    if source == 8:
        return "internal_or_generated_unknown"
    return "unknown"


def _bookmark_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    data = _read_json(path)
    if not isinstance(data, dict):
        return []
    rows: list[dict[str, object]] = []
    for root in (data.get("roots") or {}).values():
        _walk_bookmark_node(root, path, source_root, rows, folder="")
    return rows


def _walk_bookmark_node(node: object, path: Path, source_root: Path, rows: list[dict[str, object]], *, folder: str) -> None:
    if not isinstance(node, dict):
        return
    node_type = str(node.get("type") or "")
    name = str(node.get("name") or "")
    current_folder = f"{folder}/{name}".strip("/") if name else folder
    if node_type == "url":
        url = str(node.get("url") or "")
        rows.append(_artifact_row(
            path, source_root, "bookmark", name=name, url=url, title=name,
            timestamp=_webkit_time(_int(node.get("date_added"))),
            value=current_folder,
            details={"id": node.get("id"), "date_last_used": _webkit_time(_int(node.get("date_last_used")))},
        ))
    for child in node.get("children") or []:
        _walk_bookmark_node(child, path, source_root, rows, folder=current_folder)


def _autocomplete_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table, name_col, value_col, date_col, time_mode in (
        ("autofill", "name", "value", "date_last_used", "unix"),
        ("autofill_profiles", "guid", "full_name", "date_modified", "unix"),
        ("keywords", "short_name", "keyword", None, ""),
    ):
        for row in _query(path, f"SELECT * FROM {table}"):
            details = {key: row[key] for key in row.keys() if key not in {name_col, value_col}}
            if table == "autofill":
                details["date_created_utc"] = _unix_seconds_time(_int(row["date_created"])) if "date_created" in row.keys() else None
                details["date_last_used_utc"] = _unix_seconds_time(_int(row["date_last_used"])) if "date_last_used" in row.keys() else None
            rows.append(_artifact_row(
                path, source_root, f"autocomplete_{table}",
                name=str(row[name_col]) if name_col in row.keys() else table,
                value=_sql_display_value(row[value_col]) if value_col in row.keys() else "",
                timestamp=_chromium_db_time(row[date_col], time_mode) if date_col and date_col in row.keys() else None,
                details=details,
            ))
    for table in _matching_tables(path, "autofill"):
        if table in {"autofill", "autofill_profiles"}:
            continue
        for row in _query(path, f"SELECT * FROM {_quote_identifier(table)}"):
            row_dict = {key: _clean_sql_value(row[key]) for key in row.keys()}
            name = str(row_dict.get("name") or row_dict.get("type") or row_dict.get("guid") or table)
            value = _sql_display_value(row_dict.get("value") or row_dict.get("label") or row_dict.get("email") or row_dict.get("full_name") or "")
            rows.append(_artifact_row(
                path, source_root, f"autocomplete_{table}",
                name=name,
                value=value,
                timestamp=_best_timestamp(row_dict, preferred=("date_modified", "date_last_used", "date_created")),
                details={"table": table, **row_dict},
            ))
    return rows


def _shortcut_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in ("omni_box_shortcuts", "shortcuts"):
        for row in _query(path, f"SELECT * FROM {table}"):
            row_dict = {key: _clean_sql_value(row[key]) for key in row.keys()}
            url = str(row_dict.get("url") or "")
            typed_text = str(row_dict.get("text") or "")
            suggested = str(row_dict.get("fill_into_edit") or "")
            hits = row_dict.get("number_of_hits")
            misses = row_dict.get("number_of_misses")
            rows.append(_artifact_row(
                path,
                source_root,
                "omnibox_shortcut",
                name=typed_text,
                value=suggested,
                url=url,
                title=str(row_dict.get("description") or row_dict.get("title") or ""),
                timestamp=_webkit_time(_int(row_dict.get("last_access_time"))),
                details={
                    "table": table,
                    "typed_text": typed_text,
                    "suggested_text": suggested,
                    "number_of_hits": hits,
                    "number_of_misses": misses,
                    **row_dict,
                },
            ))
    return rows


def _network_action_predictor_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in ("network_action_predictor", "network_action_predictor_private"):
        for row in _query(path, f"SELECT * FROM {table}"):
            row_dict = {key: _clean_sql_value(row[key]) for key in row.keys()}
            user_text = str(row_dict.get("user_text") or row_dict.get("text") or "")
            url = str(row_dict.get("url") or "")
            rows.append(_artifact_row(
                path,
                source_root,
                "network_action_predictor",
                name=user_text,
                value=url,
                url=url,
                timestamp=_best_timestamp(row_dict),
                details={
                    "table": table,
                    "user_text": user_text,
                    "number_of_hits": row_dict.get("number_of_hits"),
                    "number_of_misses": row_dict.get("number_of_misses"),
                    "interpretation": "prefetch prediction row; hits suggest accepted prediction, misses suggest ignored prediction",
                    **row_dict,
                },
            ))
    return rows


def _top_sites_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in ("top_sites", "thumbnails"):
        for row in _query(path, f"SELECT * FROM {table}"):
            row_dict = {key: _clean_sql_value(row[key]) for key in row.keys()}
            url = str(row_dict.get("url") or "")
            rows.append(_artifact_row(
                path,
                source_root,
                "top_site",
                name=str(row_dict.get("title") or ""),
                value=str(row_dict.get("url_rank") or row_dict.get("rank") or ""),
                url=url,
                title=str(row_dict.get("title") or ""),
                timestamp=_best_timestamp(row_dict),
                details={"table": table, **row_dict},
            ))
    return rows


def _login_data_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for row in _query(path, "SELECT * FROM logins"):
        row_dict = {key: _clean_sql_value(row[key]) for key in row.keys() if key != "password_value"}
        url = str(row_dict.get("origin_url") or row_dict.get("action_url") or "")
        username = str(row_dict.get("username_value") or "")
        rows.append(_artifact_row(
            path,
            source_root,
            "login_metadata",
            name=str(row_dict.get("signon_realm") or _host(url)),
            value=username,
            url=url,
            host=_host(url),
            timestamp=_webkit_time(_int(row_dict.get("date_last_used") or row_dict.get("date_created"))),
            details={
                "origin_url": row_dict.get("origin_url"),
                "action_url": row_dict.get("action_url"),
                "username_element": row_dict.get("username_element"),
                "username_value_present": bool(username),
                "password_value_present": "password_value" in row.keys() and bool(row["password_value"]),
                "date_created_utc": _webkit_time(_int(row_dict.get("date_created"))),
                "date_last_used_utc": _webkit_time(_int(row_dict.get("date_last_used"))),
                "times_used": row_dict.get("times_used"),
                "blacklisted_by_user": row_dict.get("blacklisted_by_user"),
                **row_dict,
            },
        ))
    return rows


def _preference_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    data = _read_json(path)
    if not isinstance(data, dict):
        return []
    rows: list[dict[str, object]] = []
    for host, value in ((data.get("partition") or {}).get("per_host_zoom_levels") or {}).items():
        rows.append(_artifact_row(path, source_root, "preference_host_zoom", name=str(host), host=str(host), value=json.dumps(value, sort_keys=True), details={"value": value}))
    if data.get("account_info"):
        rows.append(_artifact_row(path, source_root, "preference_sync_account", name="account_info", value=json.dumps(data["account_info"], sort_keys=True), details={"account_info": data["account_info"]}))
    if data.get("sync"):
        rows.append(_artifact_row(path, source_root, "preference_sync", name="sync", value=json.dumps(data["sync"], sort_keys=True), details={"sync": data["sync"]}))
    for key in ("clear_data", "download", "savefile", "selectfile", "search_prefetch", "zerosuggest"):
        if key in data:
            rows.append(_artifact_row(path, source_root, f"preference_{key}", name=key, value=json.dumps(data[key], sort_keys=True, default=str)[:2000], details={key: data[key]}))
    for key in ("profile", "privacy_sandbox", "safebrowsing", "signin", "alternate_error_pages"):
        if key in data:
            rows.append(_artifact_row(path, source_root, f"preference_{key}", name=key, value=json.dumps(data[key], sort_keys=True)[:2000], details={key: data[key]}))
    return rows


def _site_setting_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    data = _read_json(path)
    if not isinstance(data, dict):
        return []
    rows: list[dict[str, object]] = []
    for host, value in ((data.get("partition") or {}).get("per_host_zoom_levels") or {}).items():
        rows.append(_site_setting_row(
            path, source_root, "host_zoom", str(host), "zoom_level",
            json.dumps(value, sort_keys=True), details={"value": value},
        ))
    exceptions = ((data.get("profile") or {}).get("content_settings") or {}).get("exceptions") or {}
    if isinstance(exceptions, dict):
        for setting_type, origins in exceptions.items():
            if not isinstance(origins, dict):
                continue
            for origin, setting in origins.items():
                if not isinstance(setting, dict):
                    continue
                rows.append(_site_setting_row(
                    path,
                    source_root,
                    str(setting_type),
                    str(origin),
                    "content_setting",
                    json.dumps(setting.get("setting", setting), sort_keys=True, default=str),
                    last_modified=_content_settings_time(setting.get("last_modified")),
                    expiration=_content_settings_time(setting.get("expiration")),
                    details=setting,
                ))
    for section_name in ("media_engagement", "site_engagement"):
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue
        for origin, setting in _walk_preference_origins(section):
            rows.append(_site_setting_row(
                path, source_root, section_name, origin, section_name,
                json.dumps(setting, sort_keys=True, default=str)[:4000],
                details=setting if isinstance(setting, dict) else {"value": setting},
            ))
    return rows


def _extension_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    data = _read_json(path)
    if not isinstance(data, dict):
        return []
    extension_id = path.parent.parent.name if len(path.parts) >= 2 else ""
    return [_artifact_row(
        path, source_root, "extension",
        name=str(data.get("name") or extension_id),
        value=str(data.get("version") or ""),
        details={
            "extension_id": extension_id,
            "description": data.get("description"),
            "permissions": data.get("permissions"),
            "host_permissions": data.get("host_permissions"),
            "manifest_version": data.get("manifest_version"),
        },
    )]


def _session_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    command_rows = _snss_command_rows(path, source_root, data)
    if command_rows:
        return command_rows
    rows: list[dict[str, object]] = []
    seen = set()
    for match in URL_RE.findall(data):
        url = match.decode("utf-8", errors="replace")
        if url in seen:
            continue
        seen.add(url)
        rows.append(_session_row(
            path, source_root, url=url, parser="binary_url_carve",
            details={"parser": "binary_url_carve"},
        ))
    return rows


def _notification_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    if path.is_dir():
        return _notification_leveldb_rows(path, source_root)
    for table in ("notification_data", "notifications"):
        for row in _query(path, f"SELECT * FROM {table}"):
            row_dict = {key: _clean_sql_value(row[key]) for key in row.keys()}
            origin = str(row_dict.get("origin") or row_dict.get("origin_url") or row_dict.get("url") or "")
            rows.append(_notification_row(
                path, source_root, origin=origin,
                notification_id=str(row_dict.get("notification_id") or ""),
                title=str(row_dict.get("title") or ""),
                body=str(row_dict.get("body") or ""),
                details={"table": table, **row_dict},
            ))
    return rows


def _snss_command_rows(path: Path, source_root: Path, data: bytes) -> list[dict[str, object]]:
    if len(data) < 4:
        return []
    rows: list[dict[str, object]] = []
    tab_meta: dict[int, dict[str, object]] = {}
    offset = 0
    command_index = 0
    while offset + 3 <= len(data):
        command_size = int.from_bytes(data[offset:offset + 2], "little", signed=False)
        offset += 2
        if command_size <= 0 or offset + command_size > len(data):
            break
        command = data[offset:offset + command_size]
        offset += command_size
        command_index += 1
        command_id = command[0]
        payload = command[1:]
        if command_id == SNSS_COMMAND_SET_SELECTED_NAVIGATION_INDEX and len(payload) >= 8:
            tab_id, selected_index = struct.unpack_from("<ii", payload)
            tab_meta.setdefault(tab_id, {})["selected_navigation_index"] = selected_index
        elif command_id == SNSS_COMMAND_SET_TAB_INDEX_IN_WINDOW and len(payload) >= 8:
            tab_id, tab_index = struct.unpack_from("<ii", payload)
            tab_meta.setdefault(tab_id, {})["tab_index"] = tab_index
        elif command_id == SNSS_COMMAND_SET_PINNED_STATE and len(payload) >= 5:
            tab_id = struct.unpack_from("<i", payload)[0]
            tab_meta.setdefault(tab_id, {})["is_pinned"] = bool(payload[4])
        elif command_id == SNSS_COMMAND_LAST_ACTIVE_TIME and len(payload) >= 16:
            tab_id, last_active = struct.unpack_from("<iq", payload)
            tab_meta.setdefault(tab_id, {})["last_active_time_utc"] = _webkit_time(last_active)
        elif command_id == SNSS_COMMAND_UPDATE_TAB_NAVIGATION:
            parsed = _parse_navigation_payload(payload)
            if not parsed.get("url"):
                continue
            tab_id = _int(parsed.get("tab_id"))
            meta = tab_meta.get(tab_id or -1, {})
            selected_index = meta.get("selected_navigation_index")
            navigation_index = parsed.get("navigation_index")
            rows.append(_session_row(
                path,
                source_root,
                tab_id=str(tab_id or ""),
                tab_index=str(meta.get("tab_index") or ""),
                navigation_index=str(navigation_index or ""),
                url=str(parsed.get("url") or ""),
                title=str(parsed.get("title") or ""),
                referrer_url=str(parsed.get("referrer_url") or ""),
                timestamp=str(parsed.get("timestamp_utc") or ""),
                last_active_time=str(meta.get("last_active_time_utc") or ""),
                is_current=str(selected_index == navigation_index) if selected_index is not None else "",
                is_pinned=str(meta.get("is_pinned")) if "is_pinned" in meta else "",
                parser="snss_command",
                details={"command_index": command_index, "command_id": command_id, **parsed},
            ))
    return rows


def _parse_navigation_payload(payload: bytes) -> dict[str, object]:
    reader = _PickleReader(payload)
    tab_id = reader.read_int()
    navigation_index = reader.read_int()
    url = reader.read_string()
    title = reader.read_string16()
    page_state = reader.read_string()
    transition_type = reader.read_int()
    type_mask = reader.read_int()
    referrer_url = reader.read_string()
    obsolete_referrer_policy = reader.read_int()
    original_request_url = reader.read_string()
    is_overriding_user_agent = reader.read_bool()
    timestamp = reader.read_int64()
    return {
        "tab_id": tab_id,
        "navigation_index": navigation_index,
        "url": url,
        "title": title,
        "page_state": page_state[:2000] if page_state else "",
        "transition_type": transition_type,
        "type_mask": type_mask,
        "referrer_url": referrer_url,
        "obsolete_referrer_policy": obsolete_referrer_policy,
        "original_request_url": original_request_url,
        "is_overriding_user_agent": is_overriding_user_agent,
        "timestamp_utc": _webkit_time(timestamp),
    }


class _PickleReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = self._header_size(data)

    def _header_size(self, data: bytes) -> int:
        if len(data) >= 4:
            payload_size = int.from_bytes(data[:4], "little", signed=False)
            if payload_size <= len(data) - 4:
                return 4
        return 0

    def _align(self) -> None:
        remainder = self.offset % 4
        if remainder:
            self.offset += 4 - remainder

    def read_int(self) -> int | None:
        self._align()
        if self.offset + 4 > len(self.data):
            return None
        value = struct.unpack_from("<i", self.data, self.offset)[0]
        self.offset += 4
        return value

    def read_int64(self) -> int | None:
        self._align()
        if self.offset + 8 > len(self.data):
            return None
        value = struct.unpack_from("<q", self.data, self.offset)[0]
        self.offset += 8
        return value

    def read_bool(self) -> bool | None:
        value = self.read_int()
        if value is None:
            return None
        return bool(value)

    def read_string(self) -> str:
        self._align()
        if self.offset + 4 > len(self.data):
            return ""
        length = struct.unpack_from("<i", self.data, self.offset)[0]
        self.offset += 4
        if length < 0 or self.offset + length > len(self.data):
            return ""
        value = self.data[self.offset:self.offset + length].decode("utf-8", errors="replace")
        self.offset += length
        self._align()
        return value

    def read_string16(self) -> str:
        self._align()
        if self.offset + 4 > len(self.data):
            return ""
        length = struct.unpack_from("<i", self.data, self.offset)[0]
        self.offset += 4
        byte_length = length * 2
        if length < 0 or self.offset + byte_length > len(self.data):
            return ""
        value = self.data[self.offset:self.offset + byte_length].decode("utf-16-le", errors="replace")
        self.offset += byte_length
        self._align()
        return value


def _notification_leveldb_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        db = plyvel.DB(str(path), create_if_missing=False)
    except Exception:
        return rows
    try:
        for key, value in db:
            if not key.startswith(b"DATA:"):
                continue
            origin_from_key, notification_id_from_key = _notification_key_parts(key)
            parsed = _parse_notification_proto(value)
            data = parsed.get("notification_data") if isinstance(parsed.get("notification_data"), dict) else {}
            origin = str(parsed.get("origin") or origin_from_key)
            created = _unix_millis_time(_int(parsed.get("creation_time_millis")))
            first_click = _millis_after(created, _int(parsed.get("time_until_first_click_millis")))
            last_click = _millis_after(created, _int(parsed.get("time_until_last_click_millis")))
            closed = _millis_after(created, _int(parsed.get("time_until_close_millis")))
            rows.append(_notification_row(
                path,
                source_root,
                origin=origin,
                notification_id=str(parsed.get("notification_id") or parsed.get("persistent_notification_id") or notification_id_from_key),
                title=str(data.get("title") or ""),
                body=str(data.get("body") or ""),
                tag=str(data.get("tag") or ""),
                icon=str(data.get("icon") or data.get("image") or ""),
                badge=str(data.get("badge") or ""),
                created=created,
                notification_timestamp=_unix_millis_time(_int(data.get("timestamp"))),
                first_click=first_click,
                last_click=last_click,
                closed=closed,
                num_clicks=str(parsed.get("num_clicks") or ""),
                closed_reason=_closed_reason(parsed.get("closed_reason")),
                details={"leveldb_key": key.decode("utf-8", errors="replace"), **parsed},
            ))
    finally:
        db.close()
    return rows


def _parse_notification_proto(data: bytes) -> dict[str, object]:
    fields = _read_proto_fields(data)
    result: dict[str, object] = {}
    if 1 in fields:
        result["persistent_notification_id"] = fields[1][0]
    if 2 in fields:
        result["origin"] = _proto_text(fields[2][0])
    if 3 in fields:
        result["service_worker_registration_id"] = fields[3][0]
    if 4 in fields and isinstance(fields[4][0], bytes):
        result["notification_data"] = _parse_notification_data_proto(fields[4][0])
    if 5 in fields:
        result["notification_id"] = _proto_text(fields[5][0])
    for tag, name in (
        (6, "replaced_existing_notification"),
        (7, "num_clicks"),
        (8, "num_action_button_clicks"),
        (9, "creation_time_millis"),
        (10, "time_until_first_click_millis"),
        (11, "time_until_last_click_millis"),
        (12, "time_until_close_millis"),
        (13, "closed_reason"),
        (14, "has_triggered"),
    ):
        if tag in fields:
            result[name] = fields[tag][0]
    return result


def _parse_notification_data_proto(data: bytes) -> dict[str, object]:
    fields = _read_proto_fields(data)
    result: dict[str, object] = {}
    for tag, name in (
        (1, "title"), (3, "lang"), (4, "body"), (5, "tag"), (6, "icon"),
        (8, "data"), (14, "badge"), (15, "image"),
    ):
        if tag in fields:
            result[name] = _proto_text(fields[tag][0])
    for tag, name in (
        (2, "direction"), (7, "silent"), (11, "require_interaction"),
        (12, "timestamp"), (13, "renotify"), (16, "show_trigger_timestamp"),
    ):
        if tag in fields:
            result[name] = fields[tag][0]
    if 10 in fields:
        actions = []
        for action_data in fields[10]:
            if isinstance(action_data, bytes):
                action_fields = _read_proto_fields(action_data)
                actions.append({
                    "action": _proto_text(action_fields.get(1, [""])[0]),
                    "title": _proto_text(action_fields.get(2, [""])[0]),
                    "icon": _proto_text(action_fields.get(3, [""])[0]),
                    "type": action_fields.get(4, [""])[0],
                    "placeholder": _proto_text(action_fields.get(5, [""])[0]),
                })
        result["actions"] = actions
    return result


def _read_proto_fields(data: bytes) -> dict[int, list[object]]:
    fields: dict[int, list[object]] = {}
    offset = 0
    while offset < len(data):
        key, offset = _read_varint(data, offset)
        if key is None:
            break
        field_number = key >> 3
        wire_type = key & 0x07
        value: object
        if wire_type == 0:
            value, offset = _read_varint(data, offset)
        elif wire_type == 1 and offset + 8 <= len(data):
            value = struct.unpack_from("<Q", data, offset)[0]
            offset += 8
        elif wire_type == 2:
            length, offset = _read_varint(data, offset)
            if length is None or length < 0 or offset + length > len(data):
                break
            value = data[offset:offset + length]
            offset += length
        elif wire_type == 5 and offset + 4 <= len(data):
            value = struct.unpack_from("<I", data, offset)[0]
            offset += 4
        else:
            break
        fields.setdefault(field_number, []).append(value)
    return fields


def _read_varint(data: bytes, offset: int) -> tuple[int | None, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    return None, offset


def _proto_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00")
    return "" if value is None else str(value)


def _notification_key_parts(key: bytes) -> tuple[str, str]:
    suffix = key[5:]
    origin, _, notification_id = suffix.partition(b"\x00")
    return (
        origin.decode("utf-8", errors="replace"),
        notification_id.decode("utf-8", errors="replace"),
    )


def _walk_preference_origins(value: object) -> Iterable[tuple[str, object]]:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if "://" in key_text or key_text.startswith("[*.]"):
                yield key_text, child
            else:
                yield from _walk_preference_origins(child)


def _edge_collection_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in ("collections", "collection_items", "items"):
        for row in _query(path, f"SELECT * FROM {table}"):
            row_dict = {key: _clean_sql_value(row[key]) for key in row.keys()}
            url = str(row_dict.get("url") or row_dict.get("source") or "")
            rows.append(_artifact_row(path, source_root, "edge_collection", name=str(row_dict.get("title") or row_dict.get("name") or ""), value=str(row_dict.get("text") or ""), url=url, host=_host(url), details={"table": table, **row_dict}))
    return rows


def _sync_sqlite_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in ("metas", "deleted_metas"):
        for row in _query(path, f"SELECT * FROM {table}"):
            row_dict = {key: _clean_sql_value(row[key]) for key in row.keys()}
            blob_parts = [
                row_dict.get("specifics"),
                row_dict.get("server_specifics"),
                row_dict.get("base_server_specifics"),
                row_dict.get("non_unique_name"),
                row_dict.get("server_non_unique_name"),
                row_dict.get("unique_client_tag"),
            ]
            text = "\n".join(_blob_text(part) for part in blob_parts if part not in (None, ""))
            strings = _interesting_strings(text)
            device_name = _first_matching_string(strings, ("device", "windows", "iphone", "android", "mac", "linux"))
            for url in _unique_urls(text.encode("utf-8", errors="ignore")):
                rows.append(_artifact_row(
                    path,
                    source_root,
                    "sync_open_tab",
                    name=str(row_dict.get("non_unique_name") or row_dict.get("server_non_unique_name") or ""),
                    value=str(row_dict.get("unique_client_tag") or ""),
                    url=url,
                    title=str(row_dict.get("non_unique_name") or row_dict.get("server_non_unique_name") or ""),
                    timestamp=_webkit_time(_int(row_dict.get("mtime") or row_dict.get("server_mtime"))),
                    details={
                        "table": table,
                        "metahandle": row_dict.get("metahandle"),
                        "device_name_candidate": device_name,
                        "strings": strings[:50],
                    },
                ))
            if device_name and not _unique_urls(text.encode("utf-8", errors="ignore")):
                rows.append(_artifact_row(
                    path,
                    source_root,
                    "sync_device",
                    name=device_name,
                    value=str(row_dict.get("unique_client_tag") or ""),
                    timestamp=_webkit_time(_int(row_dict.get("mtime") or row_dict.get("server_mtime"))),
                    details={"table": table, "metahandle": row_dict.get("metahandle"), "strings": strings[:50]},
                ))
    return rows


def _sync_leveldb_rows(path: Path, source_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        db = plyvel.DB(str(path), create_if_missing=False)
    except Exception:
        return rows
    seen: set[tuple[str, str]] = set()
    try:
        for key, value in db:
            payload = key + b"\n" + value
            strings = _interesting_strings(_blob_text(payload))
            for url in _unique_urls(payload):
                marker = (str(path), url)
                if marker in seen:
                    continue
                seen.add(marker)
                rows.append(_artifact_row(
                    path,
                    source_root,
                    "sync_open_tab",
                    url=url,
                    title=_first_non_url_string(strings),
                    details={
                        "leveldb_key": key.decode("utf-8", errors="replace")[:500],
                        "strings": strings[:50],
                    },
                ))
    finally:
        db.close()
    return rows


def _blob_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _unique_urls(data: bytes) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.findall(data):
        url = match.decode("utf-8", errors="replace").rstrip(").,;]")
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _interesting_strings(text: str) -> list[str]:
    strings = []
    for value in re.findall(r"[\x20-\x7e]{4,200}", text):
        cleaned = value.strip()
        if cleaned and cleaned not in strings:
            strings.append(cleaned)
    return strings


def _first_matching_string(strings: list[str], tokens: tuple[str, ...]) -> str:
    for value in strings:
        lowered = value.lower()
        if any(token in lowered for token in tokens):
            return value
    return ""


def _first_non_url_string(strings: list[str]) -> str:
    for value in strings:
        if "://" not in value:
            return value
    return ""


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
        "browser": _browser_from_path(path),
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
        "browser": _browser_from_path(path),
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


def _site_setting_row(
    path: Path,
    source_root: Path,
    setting_type: str,
    origin: str,
    setting_name: str,
    setting_value: str,
    *,
    last_modified: str | None = None,
    expiration: str | None = None,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "browser": _browser_from_path(path),
        "source_path": str(path),
        "profile_path": _profile_path(path, source_root),
        "setting_type": setting_type,
        "origin": origin,
        "host": _host(origin),
        "setting_name": setting_name,
        "setting_value": setting_value,
        "last_modified_utc": last_modified,
        "expiration_utc": expiration,
        "details_json": json.dumps(details or {}, sort_keys=True, default=str),
    }


def _notification_row(
    path: Path,
    source_root: Path,
    *,
    origin: str = "",
    notification_id: str = "",
    title: str = "",
    body: str = "",
    tag: str = "",
    icon: str = "",
    badge: str = "",
    created: str | None = None,
    notification_timestamp: str | None = None,
    first_click: str | None = None,
    last_click: str | None = None,
    closed: str | None = None,
    num_clicks: str = "",
    closed_reason: str = "",
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "browser": _browser_from_path(path),
        "source_path": str(path),
        "profile_path": _profile_path(path, source_root),
        "origin": origin,
        "host": _host(origin),
        "notification_id": notification_id,
        "title": title,
        "body": body,
        "tag": tag,
        "icon": icon,
        "badge": badge,
        "created_utc": created,
        "notification_timestamp_utc": notification_timestamp,
        "first_click_utc": first_click,
        "last_click_utc": last_click,
        "closed_utc": closed,
        "num_clicks": num_clicks,
        "closed_reason": closed_reason,
        "details_json": json.dumps(details or {}, sort_keys=True, default=str),
    }


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _is_session_file(path: Path) -> bool:
    if not path.is_file():
        return False
    lowered = str(path).lower()
    return ("sessions" in lowered or "session storage" in lowered) and path.name.lower() not in {"log", "lock"}


def _session_type(path: Path) -> str:
    name = path.name.lower()
    if "tabs" in name:
        return "tabs"
    if "session" in name:
        return "session"
    return ""


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


def _browser_from_path(path: Path) -> str:
    text = str(path).lower()
    if "microsoft/edge" in text or "microsoft\\edge" in text:
        return "edge"
    if "google/chrome" in text or "google\\chrome" in text:
        return "chrome"
    return "chromium"


def _webkit_time(value: int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        dt = WEBKIT_EPOCH + timedelta(microseconds=int(value))
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _unix_seconds_time(value: int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        dt = UNIX_EPOCH + timedelta(seconds=int(value))
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _unix_millis_time(value: int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        dt = UNIX_EPOCH + timedelta(milliseconds=int(value))
        return dt.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _chromium_db_time(value: object, mode: str = "") -> str | None:
    number = _int(value)
    if number is None:
        return None
    if mode == "unix":
        return _unix_seconds_time(number)
    if mode == "webkit":
        return _webkit_time(number)
    if number > 10_000_000_000_000:
        return _webkit_time(number)
    if number > 10_000_000_000:
        return _unix_millis_time(number)
    return _unix_seconds_time(number)


def _best_timestamp(row: dict[str, object], preferred: tuple[str, ...] = ()) -> str | None:
    keys = preferred or (
        "last_access_time", "date_last_used", "date_modified", "date_created",
        "last_visited", "last_visit_time", "last_used", "time", "timestamp",
    )
    for key in keys:
        if key in row:
            parsed = _chromium_db_time(row.get(key))
            if parsed:
                return parsed
    return None


def _millis_after(start_iso: str | None, delta_millis: int | None) -> str | None:
    if not start_iso or delta_millis in (None, 0):
        return None
    try:
        start = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        return (start + timedelta(milliseconds=int(delta_millis))).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _content_settings_time(value: object) -> str | None:
    number = _int(value)
    if number is None:
        return None
    if number > 10_000_000_000_000:
        return _webkit_time(number)
    if number > 10_000_000_000:
        return _unix_millis_time(number)
    return None


def _closed_reason(value: object) -> str:
    reasons = {0: "user", 1: "developer", 2: "unknown"}
    number = _int(value)
    if number is None:
        return ""
    return reasons.get(number, str(number))


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


def _clean_sql_value(value: object) -> object:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace").strip("\x00")
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            return text
        if isinstance(decoded, dict) and decoded.get("url"):
            return decoded.get("url")
        return decoded
    return value


def _sql_display_value(value: object) -> str:
    if isinstance(value, bytes):
        if value.startswith(b"v10") or value.startswith(b"v11"):
            return "<encrypted_chromium_blob>"
        return value.decode("utf-8", errors="replace").strip("\x00")
    return "" if value is None else str(value)
