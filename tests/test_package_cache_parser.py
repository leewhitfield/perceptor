import csv
import json
import subprocess
from pathlib import Path

from forensic_orchestrator.analytics_query import query_one
from forensic_orchestrator.db import Database
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.normalized import normalized_package_cache_entry_row
from forensic_orchestrator.tools.package_cache import _cache_rows_from_export
from forensic_orchestrator.tools.package_cache import parse_package_cache_artifacts_to_csv
from forensic_orchestrator.tools.package_artifacts import parse_package_artifacts_to_csv


def test_package_cache_export_rows_store_encrypted_body_metadata(tmp_path):
    users = tmp_path / "Users"
    body = (
        users
        / "fredr"
        / "AppData"
        / "Local"
        / "Packages"
        / "Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
        / "AppData"
        / "User"
        / "Default"
        / "CacheStorage"
        / "Files4"
        / "CHGVYEO8_1"
        / "QOF1BPY7_3"
        / "XG852SP27X_2"
    )
    body.parent.mkdir(parents=True)
    body.write_bytes(bytes([3]) + b"0123456789abcde")
    database = body.parents[3] / "CacheStorage.edb"
    database.write_bytes(b"edb")
    export = tmp_path / "export"
    export.mkdir()
    (export / "CacheStorages4.7").write_text(
        "Id\tCacheStorageId\tSize\tAppContainerId\tSiteOrigin\tCacheName\tFilePath\tPendingDeletion\n"
        "3\t1\t2884\t\t\tohp-app-runtime-cache<|cacheName=folders-api:cacheVersion=1|>-https://www.office.com/\t"
        r"C:\Users\fredr\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AppData\User\Default\CacheStorage\Files4\CHGVYEO8_1\QOF1BPY7_3\\"
        "\t\n",
        encoding="utf-8",
    )
    (export / "Cache4_1_3.10").write_text(
        "Id\tResponseStatus\tResponseType\tSize\tRequestUrl\tResponseHeader\tResponseBodyFilename\n"
        "2\t200\t2\t2242\thttps://api.onedrive.com/v1.0/drive/root\t"
        r"content-length: 16\r\ncontent-type: application/octet-stream\r\ndate: Tue, 27 Oct 2020 02:59:03 GMT"
        "\t"
        r"C:\Users\fredr\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AppData\User\Default\CacheStorage\Files4\CHGVYEO8_1\QOF1BPY7_3\XG852SP27X_2"
        "\n",
        encoding="utf-8",
    )

    rows = _cache_rows_from_export(export, database, users, tmp_path / "out" / "opaque_bodies")

    assert len(rows) == 1
    row = rows[0]
    assert row["user_profile"] == "fredr"
    assert row["host"] == "api.onedrive.com"
    assert row["body_encrypted"] == "true"
    assert row["encryption_version"] == "3"
    assert row["response_date_utc"] == "2020-10-27T02:59:03Z"
    assert Path(str(row["stored_body_path"])).exists()


def test_package_cache_parser_records_export_failure_without_failing(monkeypatch, tmp_path):
    database = (
        tmp_path
        / "Users"
        / "Devon"
        / "AppData"
        / "Local"
        / "Packages"
        / "Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy"
        / "AppData"
        / "CacheStorage"
        / "CacheStorage.edb"
    )
    database.parent.mkdir(parents=True)
    database.write_bytes(b"bad ese")

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess("esedbexport", 1, stdout="", stderr="unable to read catalog")

    monkeypatch.setattr("forensic_orchestrator.tools.package_cache.subprocess.run", fake_run)

    csv_path = parse_package_cache_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")[0]

    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert rows == []
    inventory = json.loads((tmp_path / "out" / "PackageCacheParserInventory.json").read_text(encoding="utf-8"))
    assert inventory[0]["parser_status"] == "export_failed"
    assert "catalog" in inventory[0]["parser_error"]


def test_package_artifacts_parser_extracts_phone_link_sqlite_rows(tmp_path):
    db_path = (
        tmp_path
        / "Users"
        / "Jane"
        / "AppData"
        / "Local"
        / "Packages"
        / "Microsoft.YourPhone_8wekyb3d8bbwe"
        / "LocalState"
        / "phone.db"
    )
    db_path.parent.mkdir(parents=True)
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE messages (timestamp INTEGER, phone_number TEXT, body TEXT)")
    conn.execute("INSERT INTO messages VALUES (1577934245000, '+15551234567', 'Meet at 10')")
    conn.commit()
    conn.close()

    outputs = parse_package_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")

    rows = list(csv.DictReader(outputs[0].open()))
    phone_rows = [row for row in rows if row["record_type"] == "phone_link_message"]
    assert len(phone_rows) == 1
    assert phone_rows[0]["source_name"] == "Microsoft Phone Link"
    assert phone_rows[0]["user_profile"] == "Jane"
    assert phone_rows[0]["artifact_value"] == "+15551234567"
    assert phone_rows[0]["artifact_text"] == "Meet at 10"


def test_package_artifacts_parser_extracts_wsl_outlook_and_recent_file_cache(tmp_path):
    wsl_history = (
        tmp_path
        / "Users"
        / "Jane"
        / "AppData"
        / "Local"
        / "Packages"
        / "CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc"
        / "LocalState"
        / "rootfs"
        / "home"
        / "jane"
        / ".bash_history"
    )
    wsl_history.parent.mkdir(parents=True)
    wsl_history.write_text("ls -la\ncat /mnt/c/Users/Jane/Documents/report.txt\n", encoding="utf-8")
    outlook_file = (
        tmp_path
        / "Users"
        / "Jane"
        / "AppData"
        / "Local"
        / "Microsoft"
        / "Windows"
        / "INetCache"
        / "Content.Outlook"
        / "ABC123"
        / "invoice.docx"
    )
    outlook_file.parent.mkdir(parents=True)
    outlook_file.write_bytes(b"docx")
    recent = tmp_path / "Windows" / "AppCompat" / "Programs" / "RecentFileCache.bcf"
    recent.parent.mkdir(parents=True)
    recent.write_bytes("C:\\Users\\Jane\\Downloads\\tool.exe\x00".encode("utf-16-le"))

    outputs = parse_package_artifacts_to_csv(tmp_path, tmp_path / "out")

    rows = list(csv.DictReader(outputs[0].open()))
    by_type = {}
    for row in rows:
        by_type.setdefault(row["record_type"], []).append(row)
    assert len(by_type["wsl_shell_history"]) == 2
    assert by_type["wsl_shell_history"][1]["artifact_text"] == "cat /mnt/c/Users/Jane/Documents/report.txt"
    assert by_type["outlook_attachment_cache_file"][0]["file_name"] == "invoice.docx"
    assert by_type["recent_file_cache_entry"][0]["artifact_value"] == "C:\\Users\\Jane\\Downloads\\tool.exe"


def test_package_artifacts_parser_extracts_teams_filesystem_diagnostic_rows(tmp_path):
    log_path = (
        tmp_path
        / "Users"
        / "Jane"
        / "AppData"
        / "Local"
        / "Packages"
        / "MSTeams_8wekyb3d8bbwe"
        / "LocalCache"
        / "Microsoft"
        / "MSTeams"
        / "EBWebView"
        / "WV2Profile_tfl"
        / "File System"
        / "000"
        / "t"
        / "Paths"
        / "000003.log"
    )
    log_path.parent.mkdir(parents=True)
    log_path.write_text(
        "CHILD_OF:6:1762967535995 "
        "Teams_diagnostics-event-logs-main_react-web-client_9188040d-6c67-4c5b-b112-36a304b66dad_00000000-0000-0000-dd1b-2dba18cab35a@",
        encoding="utf-8",
    )

    outputs = parse_package_artifacts_to_csv(tmp_path, tmp_path / "out")

    rows = list(csv.DictReader(outputs[0].open()))
    teams_rows = [row for row in rows if row["record_type"] == "teams_filesystem_diagnostic_log"]
    assert len(teams_rows) == 1
    assert teams_rows[0]["event_time_utc"] == "2025-11-12T17:12:15.995000Z"
    assert teams_rows[0]["application_package"] == "MSTeams"
    assert teams_rows[0]["artifact_value"].startswith("Teams_diagnostics-event-logs-main_react-web-client")


def test_package_cache_rows_feed_timeline_events(tmp_path):
    row = normalized_package_cache_entry_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="PackageCacheParser",
        source_csv=tmp_path / "PackageCacheEntries.csv",
        row_number=1,
        row={
            "request_url": "https://api.onedrive.com/v1.0/drive/root",
            "host": "api.onedrive.com",
            "response_date_utc": "2020-10-27T02:59:03Z",
            "body_encrypted": "true",
            "encryption_version": "3",
        },
    )

    events = timeline_events_from_rows([row])

    assert events[0]["event_type"] == "package_cache_response"
    assert events[0]["source_table"] == "package_cache_entries"


def test_package_cache_ingest_populates_db(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id=computer.id)
    csv_path = tmp_path / "PackageCacheEntries.csv"
    csv_path.write_text(
        ",".join(
            [
                "user_profile",
                "application_package",
                "source_database",
                "source_table",
                "table_row_number",
                "cache_name",
                "site_origin",
                "request_url",
                "host",
                "response_status",
                "response_type",
                "response_headers",
                "response_date_utc",
                "content_type",
                "content_length",
                "source_body_path",
                "stored_body_path",
                "body_file_name",
                "body_size",
                "body_sha256",
                "body_encrypted",
                "encryption_version",
                "decoded_state",
            ]
        )
        + "\n"
        + "fredr,Microsoft.MicrosoftEdge_8wekyb3d8bbwe,/edb,Cache4_1_3.10,1,folders,https://www.office.com/,"
        + "https://api.onedrive.com/v1.0/drive/root,api.onedrive.com,200,2,,2020-10-27T02:59:03Z,"
        + "application/octet-stream,16,/body,/stored,XG852SP27X_2,16,abc,true,3,encrypted_opaque\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-cache",
        tool_name="PackageCacheParser",
        path=csv_path,
    )

    row = query_one(db, "package_cache_entries", "SELECT * FROM package_cache_entries")
    assert row["host"] == "api.onedrive.com"
    assert row["body_encrypted"] == "true"
    event = query_one(db, "timeline_events", "SELECT * FROM timeline_events")
    assert event["event_type"] == "package_cache_response"
