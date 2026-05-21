import csv
import json
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.normalized import normalized_webcache_entry_row, webcache_file_access_row_from_entry
from forensic_orchestrator.tools.webcache import parse_webcache_artifacts_to_csv


def test_webcache_parser_normalizes_exported_tables(tmp_path):
    source = tmp_path / "exported"
    source.mkdir()
    (source / "Containers.csv").write_text(
        "ContainerId,Name,Directory\n"
        "1,History,C:\\\\Users\\\\Devon\\\\AppData\\\\Local\\\\Packages\\\\microsoft.microsoftedge_8wekyb3d8bbwe\\\\AC\\\\MicrosoftEdge\\\\History\\\\\n",
        encoding="utf-8",
    )
    (source / "Container_1.csv").write_text(
        "EntryId,ContainerId,Url,AccessedTime,ModifiedTime,ResponseHeaders,Filename\n"
        "42,1,https://example.com/page,2024-01-02 03:04:05,133485590450000000,"
        "\"HTTP/1.1 200 OK\nContent-Type: text/html\",ABC123.tmp\n",
        encoding="utf-8",
    )

    [csv_path] = parse_webcache_artifacts_to_csv(source, tmp_path / "out")

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["source_table"] == "Container_1"
    assert rows[0]["user_name"] == "Devon"
    assert rows[0]["application"] == "Microsoft Edge"
    assert rows[0]["application_package"] == "microsoft.microsoftedge_8wekyb3d8bbwe"
    assert rows[0]["container_directory"].replace("\\\\", "\\").endswith("\\MicrosoftEdge\\History\\")
    assert rows[0]["attribution_method"] == "container_directory_package"
    assert rows[0]["container_name"] == "History"
    assert rows[0]["url"] == "https://example.com/page"
    assert rows[0]["host"] == "example.com"
    assert rows[0]["accessed_utc"] == "2024-01-02T03:04:05Z"
    assert rows[0]["modified_utc"] == "2024-01-01T05:04:05Z"
    assert rows[0]["content_type"] == "text/html"
    assert rows[0]["http_status"] == "200"
    assert json.loads(rows[0]["raw_metadata_json"])["EntryId"] == "42"


def test_webcache_rows_feed_timeline_events(tmp_path):
    row = normalized_webcache_entry_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="WebCacheParser",
        source_csv=tmp_path / "WebCacheEntries.csv",
        row_number=1,
        row={
            "url": "https://example.com/page",
            "host": "example.com",
            "accessed_utc": "2024-01-02T03:04:05Z",
            "modified_utc": "2024-01-02T03:05:05Z",
            "container_name": "History",
        },
    )

    events = timeline_events_from_rows([row])

    assert {event["event_type"] for event in events} == {"webcache_accessed", "webcache_modified"}
    assert {event["source_table"] for event in events} == {"webcache_entries"}


def test_webcache_file_url_rows_are_split_into_file_accesses(tmp_path):
    entry = normalized_webcache_entry_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="WebCacheParser",
        source_csv=tmp_path / "WebCacheEntries.csv",
        row_number=1,
        row={
            "url": "file:///C:/Users/Devon/Documents/report%20final.docx",
            "user_name": "Devon",
            "application": "Microsoft Edge",
            "application_package": "microsoft.microsoftedge_8wekyb3d8bbwe",
            "container_directory": r"C:\Users\Devon\AppData\Local\Packages\microsoft.microsoftedge_8wekyb3d8bbwe\AC\MicrosoftEdge\History",
            "attribution_method": "container_directory_package",
            "accessed_utc": "2024-01-02T03:04:05Z",
            "source_table": "Container_1",
            "container_name": "History",
        },
    )

    file_access = webcache_file_access_row_from_entry(entry)

    assert file_access is not None
    assert file_access["source_webcache_entry_id"] == entry["id"]
    assert file_access["user_name"] == "Devon"
    assert file_access["application"] == "Microsoft Edge"
    assert file_access["application_package"] == "microsoft.microsoftedge_8wekyb3d8bbwe"
    assert file_access["local_path"] == "C:\\Users\\Devon\\Documents\\report final.docx"
    assert file_access["normalized_path"] == "c:/users/devon/documents/report final.docx"
    events = timeline_events_from_rows([file_access])
    assert events[0]["event_type"] == "webcache_file_accessed"
    assert events[0]["source_table"] == "webcache_file_accesses"


def test_webcache_visited_file_url_rows_are_split_into_file_accesses(tmp_path):
    entry = normalized_webcache_entry_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="WebCacheParser",
        source_csv=tmp_path / "WebCacheEntries.csv",
        row_number=1,
        row={
            "url": ":2020111320201114: fredr@file:///F:/Files%20of%20interest/report.docx",
            "accessed_utc": "2020-11-14T04:24:10.901000Z",
        },
    )

    file_access = webcache_file_access_row_from_entry(entry)

    assert file_access is not None
    assert file_access["local_path"] == "F:\\Files of interest\\report.docx"
    assert file_access["normalized_path"] == "f:/files of interest/report.docx"


def test_webcache_unc_file_url_rows_are_split_into_file_accesses(tmp_path):
    entry = normalized_webcache_entry_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="WebCacheParser",
        source_csv=tmp_path / "WebCacheEntries.csv",
        row_number=1,
        row={"url": "file://server/share/folder/file.txt"},
    )

    file_access = webcache_file_access_row_from_entry(entry)

    assert file_access is not None
    assert file_access["local_path"] == "\\\\server\\share\\folder\\file.txt"


def test_webcache_ingest_populates_db(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id=computer.id)
    csv_path = tmp_path / "WebCacheEntries.csv"
    csv_path.write_text(
        "source_database,source_table,table_row_number,user_name,application,application_package,container_directory,attribution_method,container_name,url,host,accessed_utc\n"
        "WebCacheV01.dat,Container_1,1,Devon,Microsoft Edge,microsoft.microsoftedge_8wekyb3d8bbwe,C:\\\\Users\\\\Devon\\\\AppData\\\\Local\\\\Packages\\\\microsoft.microsoftedge_8wekyb3d8bbwe\\\\AC\\\\MicrosoftEdge\\\\History,container_directory_package,History,https://example.com,example.com,2024-01-02T03:04:05Z\n"
        "WebCacheV01.dat,Container_1,2,Devon,Microsoft Edge,microsoft.microsoftedge_8wekyb3d8bbwe,C:\\\\Users\\\\Devon\\\\AppData\\\\Local\\\\Packages\\\\microsoft.microsoftedge_8wekyb3d8bbwe\\\\AC\\\\MicrosoftEdge\\\\History,container_directory_package,History,file:///C:/Users/Devon/Documents/report.docx,,2024-01-03T03:04:05Z\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-webcache",
        tool_name="WebCacheParser",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM webcache_entries").fetchone()
    assert row["url"] == "https://example.com"
    assert row["host"] == "example.com"
    assert row["user_name"] == "Devon"
    assert row["application"] == "Microsoft Edge"
    file_access = db.conn.execute("SELECT * FROM webcache_file_accesses").fetchone()
    assert file_access["local_path"] == "C:\\Users\\Devon\\Documents\\report.docx"
    assert file_access["application"] == "Microsoft Edge"
    event_types = {
        row["event_type"]
        for row in db.conn.execute("SELECT event_type FROM timeline_events").fetchall()
    }
    assert "webcache_accessed" in event_types
    assert "webcache_file_accessed" in event_types
