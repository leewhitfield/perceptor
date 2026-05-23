import csv

from forensic_orchestrator.analytics_query import query_one, query_rows
from forensic_orchestrator.db import Database
from forensic_orchestrator.filesystem_review import rebuild_filesystem_review
from forensic_orchestrator.reports import file_history_report, thumbcache_report
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.thumbcache import parse_thumbcache_artifacts_to_csv


def test_thumbcache_parser_recovers_embedded_thumbnail(tmp_path):
    source = tmp_path / "Users" / "Jane" / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer"
    source.mkdir(parents=True)
    thumbcache = source / "thumbcache_96.db"
    thumbcache.write_bytes(
        b"CMMM"
        + (b"\x00" * 8)
        + bytes.fromhex("11223344556677889900aabbccddeeff")
        + b"\xff\xd8\xff\xe0JPEGDATA"
    )

    csv_path = parse_thumbcache_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["user_profile"] == "Jane"
    assert rows[0]["source_name"] == "thumbcache_96.db"
    assert rows[0]["thumbnail_type"] == "jpg"
    assert rows[0]["cache_id"] == "11223344556677889900aabbccddeeff"
    assert rows[0]["parser_status"] == "parsed"


def test_thumbcache_ingest_correlates_with_windows_search_and_timeline(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id=computer.id)
    db.insert_windows_search_files(
        [
            {
                "id": "search-file-1",
                "case_id": case.id,
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "search-output-1",
                "tool_name": "SIDR",
                "source_csv": tmp_path / "file_report.csv",
                "row_number": 1,
                "work_id": "1",
                "gather_time": "2020-01-02T03:04:05Z",
                "item_path": r"C:\Users\Jane\Pictures\photo.jpg",
                "item_url": "file:///C:/Users/Jane/Pictures/photo.jpg",
                "folder_path": r"C:\Users\Jane\Pictures",
                "file_name": "photo.jpg",
                "file_extension": ".jpg",
                "item_type": "file",
                "date_created": "2020-01-02T03:00:00Z",
                "date_modified": "2020-01-02T03:01:00Z",
                "date_accessed": "2020-01-02T03:02:00Z",
                "date_imported": "",
                "size": "1234",
                "owner": "Jane",
                "computer_name": "DESKTOP",
                "row_json": '{"System_IsDeleted": "true", "System_IsFolder": "false"}',
            }
        ]
    )
    db.insert_windows_search_properties(
        [
            {
                "id": "search-prop-1",
                "case_id": case.id,
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "search-output-1",
                "tool_name": "SIDR",
                "source_csv": tmp_path / "file_report.csv",
                "source_table": "windows_search_files",
                "source_record_id": "search-file-1",
                "row_number": 1,
                "work_id": "1",
                "item_path": r"C:\Users\Jane\Pictures\photo.jpg",
                "property_name": "System.ThumbnailCacheId",
                "property_value": "abc123",
                "normalized_name": "thumbnail_cache_id",
                "timestamp": "2020-01-02T03:04:05Z",
            }
        ]
    )
    csv_path = tmp_path / "ThumbcacheParser.csv"
    csv_path.write_text(
        "source_path,source_name,user_profile,cache_file_type,cache_id,entry_index,entry_offset,entry_size,"
        "thumbnail_offset,thumbnail_size,thumbnail_type,thumbnail_sha256,source_mtime_utc,parser_status,"
        "parser_note,details_json\n"
        f"{tmp_path}/thumbcache_96.db,thumbcache_96.db,Jane,thumbcache,abc123,1,0,100,32,68,jpg,"
        "abcd,2020-01-02T04:00:00Z,parsed,,{}\n",
        encoding="utf-8",
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="thumb-output-1",
        tool_name="ThumbcacheParser",
        path=csv_path,
    )

    entry = query_one(db, "thumbcache_entries", "SELECT * FROM thumbcache_entries")
    correlation = query_one(
        db,
        "thumbcache_search_correlations",
        "SELECT * FROM thumbcache_search_correlations",
    )
    events = query_rows(db, "timeline_events", "SELECT * FROM timeline_events ORDER BY event_type")
    report = thumbcache_report(db, case.id, confidence="high")
    filesystem_count = rebuild_filesystem_review(db, case_id=case.id, image_id=image.id)
    filesystem_row = db.conn.execute(
        "SELECT * FROM filesystem_review WHERE source_table = 'thumbcache_search_correlations'"
    ).fetchone()
    history = file_history_report(db, case.id, name="photo.jpg", limit=10)
    assert row_count == 1
    assert entry["cache_id"] == "abc123"
    assert correlation["confidence"] == "high"
    assert correlation["search_item_path"] == r"C:\Users\Jane\Pictures\photo.jpg"
    assert {event["event_type"] for event in events} == {
        "thumbcache_search_file_accessed",
        "thumbcache_search_file_created",
        "thumbcache_search_file_modified",
    }
    assert report["total_returned"] == 1
    assert report["thumbcache"][0]["search_file_name"] == "photo.jpg"
    assert filesystem_count == 1
    assert filesystem_row["event_type"] == "windows_search_thumbcache_deleted_path"
    assert filesystem_row["status"] == "windows_search_deleted_path"
    assert filesystem_row["file_path"] == r"C:\Users\Jane\Pictures\photo.jpg"
    assert any(
        event["source_table"] == "thumbcache_search_correlations"
        for event in history["events"]
    )
