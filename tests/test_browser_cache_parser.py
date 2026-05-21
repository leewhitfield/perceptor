import csv
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.browser_cache import parse_browser_cache_artifacts_to_csv
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.normalized import normalized_browser_cache_entry_row


def test_browser_cache_parser_extracts_chromium_and_firefox_url_references(tmp_path):
    chrome_cache = (
        tmp_path
        / "Users"
        / "Devon"
        / "AppData"
        / "Local"
        / "Google"
        / "Chrome"
        / "User Data"
        / "Default"
        / "Cache"
        / "Cache_Data"
    )
    firefox_cache = (
        tmp_path
        / "Users"
        / "Devon"
        / "AppData"
        / "Local"
        / "Mozilla"
        / "Firefox"
        / "Profiles"
        / "abc.default"
        / "cache2"
        / "entries"
    )
    chrome_cache.mkdir(parents=True)
    firefox_cache.mkdir(parents=True)
    (chrome_cache / "f_000001").write_bytes(b"noise https://example.com/cache-item.png\x00more")
    (firefox_cache / "ABCDEF").write_bytes(b"metadata\nhttps://mozilla.example/file.js\n")

    [csv_path] = parse_browser_cache_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert {row["browser"] for row in rows} == {"chrome", "firefox"}
    assert {row["host"] for row in rows} == {"example.com", "mozilla.example"}
    assert any(row["profile_path"] == "Default" for row in rows)
    assert any(row["profile_path"] == "abc.default" for row in rows)


def test_browser_cache_rows_feed_timeline_events(tmp_path):
    row = normalized_browser_cache_entry_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="BrowserCacheParser",
        source_csv=tmp_path / "BrowserCacheEntries.csv",
        row_number=1,
        row={
            "browser": "chrome",
            "url": "https://example.com/app.js",
            "host": "example.com",
            "cache_file_modified_utc": "2024-01-02T03:04:05Z",
        },
    )

    events = timeline_events_from_rows([row])

    assert events[0]["event_type"] == "browser_cache_file_modified"
    assert events[0]["source_table"] == "browser_cache_entries"


def test_browser_cache_ingest_populates_db(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id=computer.id)
    csv_path = tmp_path / "BrowserCacheEntries.csv"
    csv_path.write_text(
        "browser,source_path,profile_path,cache_type,url,host,cache_file,cache_file_size,cache_file_modified_utc\n"
        "chrome,/cache/f_000001,Default,cache,https://example.com/app.js,example.com,f_000001,42,2024-01-02T03:04:05Z\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-cache",
        tool_name="BrowserCacheParser",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM browser_cache_entries").fetchone()
    assert row["browser"] == "chrome"
    assert row["url"] == "https://example.com/app.js"
    event = db.conn.execute("SELECT * FROM timeline_events").fetchone()
    assert event["event_type"] == "browser_cache_file_modified"
