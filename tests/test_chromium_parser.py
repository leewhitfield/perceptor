import csv
import json
import sqlite3
import struct

import plyvel

from forensic_orchestrator.tools.chromium import (
    _chromium_local_vs_synced,
    _chromium_visit_source_label,
    parse_chromium_artifacts_to_csv,
)


def test_chromium_visit_source_8_is_labeled_as_ambiguous_edge_generated_source():
    assert _chromium_visit_source_label(8) == "chromium_edge_internal_or_generated_source_8"
    assert _chromium_local_vs_synced(8) == "internal_or_generated_unknown"
    assert _chromium_visit_source_label(42) == "unknown_source_42"
    assert _chromium_local_vs_synced(42) == "unknown"


def test_chromium_parser_writes_history_download_and_cookie_csvs(tmp_path):
    profile = tmp_path / "Users" / "Devon" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    profile.mkdir(parents=True)
    history = profile / "History"
    cookies = profile / "Cookies"

    conn = sqlite3.connect(history)
    conn.executescript(
        """
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
        CREATE TABLE visit_source (id INTEGER PRIMARY KEY, source INTEGER);
        CREATE TABLE downloads (
          id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, site_url TEXT, referrer TEXT,
          start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER,
          state INTEGER, danger_type INTEGER, interrupt_reason INTEGER
        );
        INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 2, 1);
        INSERT INTO visits VALUES (1, 1, 13253760000000000);
        INSERT INTO visit_source VALUES (1, 0);
        INSERT INTO downloads VALUES (
          1, 'C:\\Users\\Devon\\Downloads\\report.docx', 'https://example.com/report',
          'https://example.com', 'https://referrer.example', 13253760000000000,
          13253760001000000, 100, 100, 1, 0, 0
        );
        """
    )
    conn.close()

    conn = sqlite3.connect(cookies)
    conn.executescript(
        """
        CREATE TABLE cookies (
          host_key TEXT, name TEXT, path TEXT, creation_utc INTEGER, last_access_utc INTEGER,
          expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER
        );
        INSERT INTO cookies VALUES ('.example.com', 'sid', '/', 13253760000000000, 13253760001000000, 0, 1, 1);
        """
    )
    conn.close()

    (profile / "Bookmarks").write_text(
        json.dumps(
            {
                "roots": {
                    "bookmark_bar": {
                        "type": "folder",
                        "name": "Bookmarks Bar",
                        "children": [
                            {"type": "url", "name": "Saved", "url": "https://saved.example/", "date_added": "13253760000000000"}
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (profile / "Preferences").write_text(
        json.dumps({"partition": {"per_host_zoom_levels": {"https://zoom.example": {"zoom_level": 1}}}, "sync": {"requested": True}}),
        encoding="utf-8",
    )

    outputs = parse_chromium_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    assert {path.name for path in outputs} == {
        "BrowserHistory.csv",
        "BrowserDownloads.csv",
        "BrowserCookies.csv",
        "BrowserArtifacts.csv",
        "BrowserNotifications.csv",
        "BrowserSessionEntries.csv",
        "BrowserSiteSettings.csv",
    }
    with (tmp_path / "out" / "BrowserHistory.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["browser"] == "chrome"
    assert rows[0]["url"] == "https://example.com"
    assert rows[0]["visit_time_utc"].endswith("Z")
    assert rows[0]["visit_source_label"] == "synced"
    assert rows[0]["local_vs_synced"] == "synced"

    with (tmp_path / "out" / "BrowserDownloads.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["target_path"] == "C:\\Users\\Devon\\Downloads\\report.docx"

    with (tmp_path / "out" / "BrowserCookies.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["host"] == ".example.com"

    with (tmp_path / "out" / "BrowserArtifacts.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert {row["artifact_type"] for row in rows} >= {"bookmark", "preference_host_zoom", "preference_sync"}
    assert any(row["url"] == "https://saved.example/" for row in rows)

    with (tmp_path / "out" / "BrowserSiteSettings.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["setting_type"] == "host_zoom"


def test_chromium_parser_extracts_sync_open_tabs_from_sync_sqlite(tmp_path):
    sync_dir = tmp_path / "Users" / "Devon" / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "Sync Data"
    sync_dir.mkdir(parents=True)
    sync_db = sync_dir / "SyncData.sqlite3"
    conn = sqlite3.connect(sync_db)
    conn.executescript(
        """
        CREATE TABLE metas (
          metahandle INTEGER PRIMARY KEY, mtime INTEGER, server_mtime INTEGER,
          non_unique_name TEXT, server_non_unique_name TEXT, unique_client_tag TEXT,
          specifics BLOB, server_specifics BLOB, base_server_specifics BLOB
        );
        CREATE TABLE deleted_metas (
          metahandle INTEGER PRIMARY KEY, mtime INTEGER, server_mtime INTEGER,
          non_unique_name TEXT, server_non_unique_name TEXT, unique_client_tag TEXT,
          specifics BLOB, server_specifics BLOB, base_server_specifics BLOB
        );
        """
    )
    conn.execute(
        "INSERT INTO metas VALUES (1, 13253760000000000, 0, 'Remote Tab', '', 'session-tag', ?, NULL, NULL)",
        (b"Windows Desktop\x00https://synced.example/tab\x00Synced Title",),
    )
    conn.commit()
    conn.close()

    parse_chromium_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    with (tmp_path / "out" / "BrowserArtifacts.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    sync_rows = [row for row in rows if row["artifact_type"] == "sync_open_tab"]
    assert sync_rows[0]["browser"] == "edge"
    assert sync_rows[0]["url"] == "https://synced.example/tab"


def test_chromium_parser_extracts_chrome_autocomplete_predictor_and_login_metadata(tmp_path):
    profile = tmp_path / "Users" / "Devon" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    profile.mkdir(parents=True)

    web_data = profile / "Web Data"
    conn = sqlite3.connect(web_data)
    conn.executescript(
        """
        CREATE TABLE autofill (
          name TEXT, value TEXT, value_lower TEXT, date_created INTEGER,
          date_last_used INTEGER, count INTEGER
        );
        INSERT INTO autofill VALUES ('email', 'devon@example.com', 'devon@example.com', 1596402818, 1596538462, 15);
        """
    )
    conn.close()

    shortcuts = profile / "Shortcuts"
    conn = sqlite3.connect(shortcuts)
    conn.executescript(
        """
        CREATE TABLE omni_box_shortcuts (
          text TEXT, fill_into_edit TEXT, url TEXT, description TEXT,
          last_access_time INTEGER, number_of_hits INTEGER, number_of_misses INTEGER
        );
        INSERT INTO omni_box_shortcuts VALUES (
          'drop', 'dropbox.com', 'https://dropbox.com', 'Dropbox',
          13253760000000000, 4, 1
        );
        """
    )
    conn.close()

    predictor = profile / "Network Action Predictor"
    conn = sqlite3.connect(predictor)
    conn.executescript(
        """
        CREATE TABLE network_action_predictor (
          id INTEGER PRIMARY KEY, user_text TEXT, url TEXT, number_of_hits INTEGER, number_of_misses INTEGER
        );
        INSERT INTO network_action_predictor VALUES (1, 'hocke', 'https://www.google.com/search?q=hockey', 1, 1);
        """
    )
    conn.close()

    top_sites = profile / "Top Sites"
    conn = sqlite3.connect(top_sites)
    conn.executescript(
        """
        CREATE TABLE top_sites (url TEXT, title TEXT, url_rank INTEGER);
        INSERT INTO top_sites VALUES ('https://example.com', 'Example', 1);
        """
    )
    conn.close()

    login_data = profile / "Login Data"
    conn = sqlite3.connect(login_data)
    conn.executescript(
        """
        CREATE TABLE logins (
          origin_url TEXT, action_url TEXT, username_element TEXT, username_value TEXT,
          password_value BLOB, date_created INTEGER, date_last_used INTEGER,
          times_used INTEGER, blacklisted_by_user INTEGER, signon_realm TEXT
        );
        INSERT INTO logins VALUES (
          'https://mail.example/login', 'https://mail.example/auth', 'email',
          'devon@example.com', X'010203', 13253760000000000, 13253760001000000,
          3, 0, 'https://mail.example'
        );
        """
    )
    conn.close()

    parse_chromium_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    with (tmp_path / "out" / "BrowserArtifacts.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    by_type = {row["artifact_type"]: row for row in rows}
    assert by_type["autocomplete_autofill"]["name"] == "email"
    assert by_type["autocomplete_autofill"]["timestamp_utc"] == "2020-08-04T10:54:22Z"
    assert by_type["omnibox_shortcut"]["name"] == "drop"
    assert by_type["omnibox_shortcut"]["url"] == "https://dropbox.com"
    assert by_type["network_action_predictor"]["name"] == "hocke"
    assert by_type["network_action_predictor"]["url"] == "https://www.google.com/search?q=hockey"
    assert by_type["top_site"]["url"] == "https://example.com"
    assert by_type["login_metadata"]["value"] == "devon@example.com"
    login_details = json.loads(by_type["login_metadata"]["details_json"])
    assert login_details["password_value_present"] is True
    assert "password_value" not in login_details


def test_chromium_parser_extracts_snss_session_entries(tmp_path):
    profile = tmp_path / "Users" / "Devon" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Sessions"
    profile.mkdir(parents=True)
    session_file = profile / "Session_123"
    session_file.write_bytes(_snss_update_navigation_command())

    parse_chromium_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    with (tmp_path / "out" / "BrowserSessionEntries.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["parser"] == "snss_command"
    assert rows[0]["url"] == "https://session.example/page"
    assert rows[0]["title"] == "Session Page"
    assert rows[0]["tab_id"] == "7"


def test_chromium_parser_extracts_site_settings_and_notifications(tmp_path):
    profile = tmp_path / "Users" / "Devon" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    profile.mkdir(parents=True)
    (profile / "Preferences").write_text(
        json.dumps({
            "profile": {
                "content_settings": {
                    "exceptions": {
                        "media_stream_camera": {
                            "https://meet.example,*": {"setting": 1, "last_modified": "13253760000000000"}
                        }
                    }
                }
            }
        }),
        encoding="utf-8",
    )
    notification_db = profile / "Platform Notifications"
    db = plyvel.DB(str(notification_db), create_if_missing=True)
    try:
        db.put(b"DATA:https://notify.example\x00notif-1", _notification_proto())
    finally:
        db.close()

    parse_chromium_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    with (tmp_path / "out" / "BrowserSiteSettings.csv").open(newline="", encoding="utf-8") as handle:
        settings = list(csv.DictReader(handle))
    assert settings[0]["setting_type"] == "media_stream_camera"
    assert settings[0]["origin"] == "https://meet.example,*"

    with (tmp_path / "out" / "BrowserNotifications.csv").open(newline="", encoding="utf-8") as handle:
        notifications = list(csv.DictReader(handle))
    assert notifications[0]["origin"] == "https://notify.example"
    assert notifications[0]["notification_id"] == "notif-1"
    assert notifications[0]["title"] == "Notice"
    assert notifications[0]["body"] == "Body text"


def _snss_update_navigation_command() -> bytes:
    payload = b"".join([
        _pickle_header_payload([
            _i32(7),
            _i32(2),
            _pickle_string("https://session.example/page"),
            _pickle_string16("Session Page"),
            _pickle_string(""),
            _i32(0),
            _i32(0),
            _pickle_string("https://referrer.example/"),
            _i32(0),
            _pickle_string(""),
            _i32(0),
            struct.pack("<q", 13253760000000000),
        ])
    ])
    command = b"\x06" + payload
    return len(command).to_bytes(2, "little") + command


def _pickle_header_payload(chunks: list[bytes]) -> bytes:
    payload = b"".join(chunks)
    return struct.pack("<I", len(payload)) + payload


def _align(data: bytes) -> bytes:
    return data + (b"\x00" * ((4 - (len(data) % 4)) % 4))


def _i32(value: int) -> bytes:
    return struct.pack("<i", value)


def _pickle_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _align(struct.pack("<i", len(encoded)) + encoded)


def _pickle_string16(value: str) -> bytes:
    encoded = value.encode("utf-16-le")
    return _align(struct.pack("<i", len(value)) + encoded)


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _proto_field(field: int, value: int | str | bytes) -> bytes:
    if isinstance(value, int):
        return _varint((field << 3) | 0) + _varint(value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        encoded = value
    return _varint((field << 3) | 2) + _varint(len(encoded)) + encoded


def _notification_proto() -> bytes:
    notification_data = b"".join([
        _proto_field(1, "Notice"),
        _proto_field(4, "Body text"),
        _proto_field(5, "tag-1"),
        _proto_field(12, 1710000000000),
    ])
    return b"".join([
        _proto_field(2, "https://notify.example"),
        _proto_field(4, notification_data),
        _proto_field(5, "notif-1"),
        _proto_field(7, 2),
        _proto_field(9, 1710000000000),
    ])
