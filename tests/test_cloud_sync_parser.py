import csv
import json
import sqlite3
from pathlib import Path

from forensic_orchestrator.analytics_query import query_one
from forensic_orchestrator.db import Database
from forensic_orchestrator.tools import onedrive_explorer
from forensic_orchestrator.tools.cloud_sync import parse_cloud_sync_artifacts_to_csv
from forensic_orchestrator.tools.ingest import ingest_csv_output


def test_cloud_sync_parser_reconstructs_google_drive_snapshot_paths(tmp_path):
    users = tmp_path / "Users"
    database = (
        users
        / "fredr"
        / "AppData"
        / "Local"
        / "Google"
        / "Drive"
        / "user_default"
        / "snapshot.db"
    )
    database.parent.mkdir(parents=True)
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE cloud_entry (
          doc_id TEXT PRIMARY KEY,
          filename TEXT,
          modified INTEGER,
          created INTEGER,
          removed INTEGER,
          size INTEGER,
          shared INTEGER
        );
        CREATE TABLE cloud_relations (child_doc_id TEXT, parent_doc_id TEXT);
        INSERT INTO cloud_entry VALUES ('root', 'root', NULL, NULL, 0, NULL, 0);
        INSERT INTO cloud_entry VALUES ('folder-1', 'Evidence', 1600000000, NULL, 0, NULL, 1);
        INSERT INTO cloud_entry VALUES ('file-1', 'Report.docx', 1600000500, NULL, 0, 1234, 1);
        INSERT INTO cloud_relations VALUES ('folder-1', 'root');
        INSERT INTO cloud_relations VALUES ('file-1', 'folder-1');
        """
    )
    connection.close()

    csv_path = parse_cloud_sync_artifacts_to_csv(users, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
    report = [row for row in rows if row["artifact_type"] == "google_drive_snapshot_entry" and row["file_id"] == "file-1"]

    assert report
    assert report[0]["provider"] == "Google Drive"
    assert report[0]["user_profile"] == "fredr"
    assert report[0]["cloud_path"] == "/Evidence/Report.docx"
    assert report[0]["file_name"] == "Report.docx"
    assert report[0]["parent_id"] == "folder-1"


def test_cloud_sync_parser_extracts_dropbox_sync_history(tmp_path):
    database = (
        tmp_path
        / "Users"
        / "jane"
        / "AppData"
        / "Local"
        / "Dropbox"
        / "sync_history.db"
    )
    database.parent.mkdir(parents=True)
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE sync_history (
          timestamp INTEGER,
          event_type TEXT,
          direction TEXT,
          local_path TEXT,
          file_id TEXT
        );
        INSERT INTO sync_history VALUES
          (1700000000, 'file_added', 'download', 'C:\\Users\\jane\\Dropbox\\Plan.xlsx', 'id:abc');
        """
    )
    connection.close()

    csv_path = parse_cloud_sync_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
    dropbox = [row for row in rows if row["artifact_type"] == "dropbox_sync_history"]

    assert len(dropbox) == 1
    assert dropbox[0]["direction"] == "download"
    assert dropbox[0]["file_name"] == "Plan.xlsx"


def test_cloud_sync_parser_extracts_onedrive_opaque_strings(tmp_path):
    dat_file = (
        tmp_path
        / "Users"
        / "devon"
        / "AppData"
        / "Local"
        / "Microsoft"
        / "OneDrive"
        / "settings"
        / "Personal"
        / "12345.dat"
    )
    dat_file.parent.mkdir(parents=True)
    dat_file.write_bytes("Budget.xlsx\x00Documents\x00".encode("utf-16le"))

    csv_path = parse_cloud_sync_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
    onedrive = [row for row in rows if row["artifact_type"] == "onedrive_dat_item_name"]

    assert any(row["file_name"] == "Budget.xlsx" for row in onedrive)


def test_cloud_sync_parser_extracts_onedrive_log_times_and_events(tmp_path):
    log_file = (
        tmp_path
        / "Users"
        / "devon"
        / "AppData"
        / "Local"
        / "Microsoft"
        / "OneDrive"
        / "logs"
        / "Business1"
        / "SyncEngine-2020-11-16.0232.9648.178.odlgz"
    )
    log_file.parent.mkdir(parents=True)
    import gzip

    with gzip.open(log_file, "wb") as handle:
        handle.write(b"download C:\\Users\\devon\\OneDrive\\Report.docx from SharePoint")

    csv_path = parse_cloud_sync_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
    logs = [row for row in rows if row["artifact_type"] == "onedrive_log_entry"]

    assert logs[0]["event_time_utc"] == "2020-11-16T02:32:00+00:00"
    assert logs[0]["event_type"] == "download"
    assert logs[0]["file_name"] == "Report.docx"


def test_cloud_sync_parser_extracts_onedrive_listsync_ocr(tmp_path):
    database = (
        tmp_path
        / "Users"
        / "jane"
        / "AppData"
        / "Local"
        / "Microsoft"
        / "OneDrive"
        / "ListSync"
        / "Business1"
        / "settings"
        / "Microsoft.ListSync.db"
    )
    database.parent.mkdir(parents=True)
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE list_abc123_site456_rows (
          UniqueId TEXT,
          FileLeafRef TEXT,
          FileRef TEXT,
          Modified INTEGER,
          File_x0020_Size INTEGER,
          FSObjType INTEGER,
          MediaServiceOCR TEXT,
          Author TEXT
        );
        INSERT INTO list_abc123_site456_rows VALUES (
          'item-1',
          'receipt.jpg',
          '/sites/Finance/Shared Documents/receipt.jpg',
          1714564800,
          34567,
          0,
          'Lunch receipt total 42.17',
          'Jane Analyst'
        );
        """
    )
    connection.close()

    csv_path = parse_cloud_sync_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
    listsync = [row for row in rows if row["artifact_type"] == "onedrive_listsync_row"]

    assert len(listsync) == 1
    assert listsync[0]["provider"] == "OneDrive"
    assert listsync[0]["user_profile"] == "jane"
    assert listsync[0]["file_name"] == "receipt.jpg"
    assert listsync[0]["cloud_path"] == "/sites/Finance/Shared Documents/receipt.jpg"
    assert listsync[0]["file_id"] == "item-1"
    assert listsync[0]["sync_status"] == "offline_metadata"
    assert listsync[0]["is_folder"] == "false"
    details = json.loads(listsync[0]["details_json"])
    assert details["list_id"] == "abc123"
    assert details["site_id"] == "site456"
    assert details["media_service_ocr"] == "Lunch receipt total 42.17"


def test_cloud_sync_ingest_populates_normalized_table(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/disk.E01"), computer_id=computer.id)
    csv_path = tmp_path / "CloudSyncArtifacts.csv"
    csv_path.write_text(
        ",".join(
            [
                "provider",
                "artifact_type",
                "user_profile",
                "source_path",
                "source_name",
                "database_name",
                "table_name",
                "event_time_utc",
                "local_path",
                "cloud_path",
                "file_name",
                "file_id",
                "parent_id",
                "stable_id",
                "server_path",
                "url",
                "mime_type",
                "file_size",
                "is_folder",
                "is_deleted",
                "sync_status",
                "event_type",
                "direction",
                "owner",
                "shared",
                "protobuf_fields_json",
                "details_json",
                "error",
            ]
        )
        + "\n"
        + "Google Drive,google_drive_snapshot_entry,fredr,/snapshot.db,snapshot.db,snapshot.db,cloud_entry,"
        + "2020-09-13T12:35:00+00:00,,/Evidence/Report.docx,Report.docx,file-1,folder-1,,,,,"
        + "application/vnd.openxmlformats-officedocument.wordprocessingml.document,1234,false,false,synced,modify,,fred@example.com,true,,{},\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-cloud",
        tool_name="CloudSyncParser",
        path=csv_path,
    )

    row = query_one(db, "cloud_sync_artifacts", "SELECT * FROM cloud_sync_artifacts")
    assert row["provider"] == "Google Drive"
    assert row["cloud_path"] == "/Evidence/Report.docx"


def test_cloud_sync_parser_maps_google_drive_content_cache(tmp_path):
    users = tmp_path / "Users"
    account = users / "fredr" / "AppData" / "Local" / "Google" / "DriveFS" / "123456"
    metadata = account / "metadata_sqlite_db"
    metadata.parent.mkdir(parents=True)
    connection = sqlite3.connect(metadata)
    connection.executescript(
        """
        CREATE TABLE items (
          stable_id INTEGER PRIMARY KEY,
          id TEXT,
          proto BLOB,
          trashed BOOLEAN,
          is_owner BOOLEAN,
          mime_type TEXT,
          is_folder BOOLEAN,
          modified_date INTEGER,
          shared_with_me_date INTEGER,
          viewed_by_me_date INTEGER,
          file_size INTEGER,
          is_tombstone BOOLEAN,
          local_title TEXT,
          subscribed BOOLEAN,
          team_drive_stable_id INTEGER
        );
        CREATE TABLE stable_parents (item_stable_id INTEGER, parent_stable_id INTEGER);
        CREATE TABLE stable_ids (stable_id INTEGER PRIMARY KEY, cloud_id TEXT);
        INSERT INTO items VALUES (1, 'root', x'0801', 0, 1, 'folder', 1, NULL, NULL, NULL, NULL, 0, 'My Drive', 1, NULL);
        INSERT INTO items VALUES (934, 'cloud-file', x'08A607', 0, 1, 'text/plain', 0, 1700000000, NULL, NULL, 5, 0, 'Report.txt', 1, NULL);
        INSERT INTO stable_parents VALUES (934, 1);
        INSERT INTO stable_ids VALUES (934, 'cloud-file');
        """
    )
    connection.close()
    chunks = account / "content_cache" / "chunks.db"
    cache_file = account / "content_cache" / "d1" / "d2" / "934"
    cache_file.parent.mkdir(parents=True)
    cache_file.write_text("hello", encoding="utf-8")
    connection = sqlite3.connect(chunks)
    connection.executescript("CREATE TABLE ranges (id INTEGER PRIMARY KEY NOT NULL, ranges_proto BLOB);")
    connection.execute("INSERT INTO ranges VALUES (?, ?)", (934, b"\x08\xa6\x07"))
    connection.commit()
    connection.close()

    csv_path = parse_cloud_sync_artifacts_to_csv(users, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
    mapping = [row for row in rows if row["artifact_type"] == "google_drive_cache_mapping"]

    assert mapping
    assert mapping[0]["file_name"] == "Report.txt"
    assert mapping[0]["cloud_path"] == "/My Drive/Report.txt"
    assert mapping[0]["local_path"].endswith("/content_cache/d1/d2/934")
    details = json.loads(mapping[0]["details_json"])
    assert details["windows_cache_path"] == "C:\\Users\\fredr\\AppData\\Local\\Google\\DriveFS\\123456\\content_cache\\d1\\d2\\934"


def test_onedrive_explorer_ingest_populates_normalized_table(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/disk.E01"), computer_id=computer.id)
    csv_path = tmp_path / "OneDriveExplorerArtifacts.csv"
    csv_path.write_text(
        ",".join(
            [
                "provider",
                "artifact_type",
                "user_profile",
                "account",
                "source_path",
                "source_csv",
                "source_row_number",
                "record_type",
                "name",
                "path",
                "parent_resource_id",
                "resource_id",
                "etag",
                "status",
                "spo_permissions",
                "volume_id",
                "item_index",
                "last_change_utc",
                "disk_last_access_utc",
                "disk_creation_utc",
                "size",
                "local_hash_digest",
                "local_hash_algorithm",
                "shared_item",
                "media_json",
                "hydration_json",
                "metadata_json",
                "is_deleted",
                "delete_time_utc",
                "deleting_process",
                "error",
            ]
        )
        + "\n"
        + "OneDrive,onedrive_explorer_item,fredr,Personal,/OneDrive,/out.csv,1,File,Plan.docx,"
        + "\\\\Documents,root,res-1,etag,Synced,Read,vol,9,2020-11-13T10:00:00,,,"
        + "12 KB,SHA1(abc),SHA1,false,{},{}," + '"""{}"""' + ",false,,,\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-onedrive",
        tool_name="OneDriveExplorer",
        path=csv_path,
    )

    row = query_one(db, "onedrive_items", "SELECT * FROM onedrive_items")
    assert row["name"] == "Plan.docx"
    assert row["local_hash_algorithm"] == "SHA1"


def test_onedrive_explorer_parses_sync_engine_database_without_external_tool(tmp_path, monkeypatch):
    users = tmp_path / "Users"
    database = users / "fredr" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "settings" / "Personal" / "SyncEngineDatabase.db"
    database.parent.mkdir(parents=True)
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE od_ClientFolder_Records (
          resourceID TEXT PRIMARY KEY,
          parentResourceID TEXT,
          parentScopeID TEXT,
          eTag TEXT,
          folderName TEXT,
          folderStatus INTEGER,
          spoPermissions INTEGER,
          volumeID INTEGER,
          itemIndex INTEGER,
          sharedItem INTEGER
        );
        CREATE TABLE od_ClientFile_Records (
          resourceID TEXT PRIMARY KEY,
          parentResourceID TEXT,
          eTag TEXT,
          fileName TEXT,
          fileStatus INTEGER,
          spoPermissions INTEGER,
          volumeID INTEGER,
          itemIndex INTEGER,
          lastChange INTEGER,
          size INTEGER,
          localHashDigest BLOB,
          localHashAlgorithm INTEGER,
          sharedItem INTEGER,
          diskLastAccessTime INTEGER,
          diskCreationTime INTEGER,
          lastKnownPinState INTEGER
        );
        CREATE TABLE od_HydrationData (
          resourceID TEXT PRIMARY KEY,
          firstHydrationTime INTEGER,
          lastHydrationTime INTEGER,
          hydrationCount INTEGER,
          lastHydrationType TEXT
        );
        INSERT INTO od_ClientFolder_Records VALUES ('folder-1', 'root-scope', 'scope-1', 'etag-folder', 'Documents', 7, 31, 12, 34, 0);
        INSERT INTO od_ClientFile_Records VALUES ('file-1', 'folder-1', 'etag-file', 'Plan.docx', 2, 27, 12, 35, 1600000000, 4096, X'010203', 4, 1, 1600000010, 1600000020, 2);
        INSERT INTO od_HydrationData VALUES ('file-1', 1600000030, 1600000040, 3, 'Active');
        """
    )
    connection.close()
    monkeypatch.setattr(onedrive_explorer, "_find_onedrive_explorer", lambda: None)

    csv_path = onedrive_explorer.parse_onedrive_explorer_to_csv(users, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))

    file_row = next(row for row in rows if row["name"] == "Plan.docx")
    assert file_row["user_profile"] == "fredr"
    assert file_row["account"] == "Personal"
    assert file_row["record_type"] == "File"
    assert file_row["path"] == "Documents"
    assert file_row["last_change_utc"] == "2020-09-13T12:26:40+00:00"
    assert file_row["local_hash_digest"] == "SHA1(010203)"
    assert file_row["local_hash_algorithm"] == "SHA1"
