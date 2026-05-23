import csv
import json
import sqlite3

import lz4.block

from forensic_orchestrator.tools.firefox import parse_firefox_artifacts_to_csv


def test_firefox_parser_writes_history_and_cookie_csvs(tmp_path):
    profile = tmp_path / "Documents and Settings" / "Jean" / "Application Data" / "Mozilla" / "Firefox" / "Profiles" / "abc.default"
    profile.mkdir(parents=True)
    places = profile / "places.sqlite"
    cookies = profile / "cookies.sqlite"
    create_places(places)
    create_cookies(cookies)
    (profile / "prefs.js").write_text(
        'user_pref("services.sync.username", "jean@example.com");\n'
        'user_pref("identity.fxaccounts.account.device.name", "Jean Firefox");\n'
        'user_pref("services.sync.clients.devices.desktop", 1);\n'
        'user_pref("services.sync.clients.devices.mobile", 1);\n'
        'user_pref("services.sync.clients.lastSync", "1605329244.35");\n',
        encoding="utf-8",
    )

    outputs = parse_firefox_artifacts_to_csv(tmp_path, tmp_path / "out")

    history = (tmp_path / "out" / "FirefoxHistory.csv").read_text()
    cookie_text = (tmp_path / "out" / "FirefoxCookies.csv").read_text()
    download_text = (tmp_path / "out" / "BrowserDownloads.csv").read_text()
    assert len(outputs) == 5
    assert "https://example.com/" in history
    assert "Example" in history
    assert ".example.com" in cookie_text
    assert "session" in cookie_text
    assert "C:\\Users\\Jean\\Downloads\\example.pdf" in download_text
    assert "https://example.com/download.pdf" in download_text
    with (tmp_path / "out" / "FirefoxArtifacts.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert any(row["artifact_type"] == "bookmark" and row["url"] == "https://example.com/" for row in rows)
    bookmark_row = next(row for row in rows if row["artifact_type"] == "bookmark" and row["url"] == "https://example.com/")
    bookmark_details = json.loads(bookmark_row["details_json"])
    assert bookmark_details["bookmark_guid"] == "bookmark-guid-1"
    assert bookmark_details["place_guid"] == "place-guid-1"
    assert any(row["artifact_type"] == "firefox_sync_device_summary" for row in rows)
    with (tmp_path / "out" / "FirefoxHistory.csv").open(newline="", encoding="utf-8") as handle:
        history_rows = list(csv.DictReader(handle))
    assert history_rows[0]["visit_source_label"] == "synced"
    assert history_rows[0]["local_vs_synced"] == "synced"


def test_firefox_parser_extracts_jsonlz4_session_entries(tmp_path):
    profile = tmp_path / "Users" / "Jean" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abc.default"
    profile.mkdir(parents=True)
    payload = {
        "windows": [
            {
                "selected": 1,
                "tabs": [
                    {
                        "id": 22,
                        "index": 1,
                        "entries": [
                            {
                                "url": "https://mozilla.example/page",
                                "title": "Mozilla Page",
                                "referrer": "https://referrer.example/",
                                "lastAccessed": 1710000000000,
                            }
                        ],
                    }
                ],
            }
        ]
    }
    raw = json.dumps(payload).encode("utf-8")
    (profile / "recovery.jsonlz4").write_bytes(
        b"mozLz40\0" + len(raw).to_bytes(4, "little") + lz4.block.compress(raw, store_size=False)
    )

    parse_firefox_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    with (tmp_path / "out" / "FirefoxSessionEntries.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["parser"] == "jsonlz4"
    assert rows[0]["url"] == "https://mozilla.example/page"
    assert rows[0]["title"] == "Mozilla Page"
    assert rows[0]["tab_id"] == "22"


def create_places(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE moz_places (
          id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
          typed INTEGER, hidden INTEGER, frecency INTEGER, syncStatus INTEGER,
          guid TEXT
        );
        CREATE TABLE moz_historyvisits (
          id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER
        );
        CREATE TABLE moz_bookmarks (
          id INTEGER PRIMARY KEY, fk INTEGER, title TEXT, type INTEGER,
          dateAdded INTEGER, lastModified INTEGER, guid TEXT
        );
        CREATE TABLE moz_anno_attributes (
          id INTEGER PRIMARY KEY, name TEXT
        );
        CREATE TABLE moz_annos (
          id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER,
          content TEXT, dateAdded INTEGER, lastModified INTEGER
        );
        INSERT INTO moz_places VALUES (1, 'https://example.com/', 'Example', 3, 1, 0, 100, 2, 'place-guid-1');
        INSERT INTO moz_places VALUES (2, 'https://example.com/download.pdf', 'example.pdf', 1, 0, 0, 10, 1, 'place-guid-2');
        INSERT INTO moz_historyvisits VALUES (1, 1, 1778587200000000, 1);
        INSERT INTO moz_bookmarks VALUES (1, 1, 'Example Bookmark', 1, 1778587200000000, 1778587200000000, 'bookmark-guid-1');
        INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');
        INSERT INTO moz_anno_attributes VALUES (2, 'downloads/metaData');
        INSERT INTO moz_annos VALUES (
          1, 2, 1, 'file:///C:/Users/Jean/Downloads/example.pdf', 1778587200000000, 1778587200000000
        );
        INSERT INTO moz_annos VALUES (
          2, 2, 2, '{"state":1,"deleted":false,"endTime":1778587200500,"fileSize":1234}',
          1778587200000000, 1778587200000000
        );
        """
    )
    conn.close()


def test_firefox_parser_extracts_signed_in_sync_device(tmp_path):
    profile = tmp_path / "Users" / "Jean" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abc.default"
    profile.mkdir(parents=True)
    (profile / "signedInUser.json").write_text(
        json.dumps({
            "accountData": {
                "email": "jean@example.com",
                "uid": "uid-1",
                "device": {"id": "device-1", "name": "Jean Laptop", "registrationVersion": 2},
            },
            "profileCache": {"profile": {"displayName": "Jean", "email": "jean@example.com"}},
        }),
        encoding="utf-8",
    )

    parse_firefox_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    with (tmp_path / "out" / "FirefoxArtifacts.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert any(row["artifact_type"] == "firefox_sync_account" and row["value"] == "jean@example.com" for row in rows)
    assert any(row["artifact_type"] == "firefox_sync_device" and row["name"] == "Jean Laptop" for row in rows)


def create_cookies(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE moz_cookies (
          id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT,
          creationTime INTEGER, lastAccessed INTEGER, expiry INTEGER,
          isSecure INTEGER, isHttpOnly INTEGER
        );
        INSERT INTO moz_cookies VALUES (
          1, '.example.com', 'session', 'abc', '/', 1778587200000000,
          1778587200000000, 1810123200, 0, 1
        );
        """
    )
    conn.close()
