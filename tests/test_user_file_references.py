from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.reports import user_file_reference_source_report, user_file_references_report
from forensic_orchestrator.user_file_references import (
    interpret_user_path,
    rebuild_user_controlled_file_references,
)


def test_interpret_user_path_separates_cloud_content_and_transfer_artifacts():
    onedrive = interpret_user_path(
        r"\Device\HarddiskVolume3\Users\fredr\OneDrive\Pictures\Camera Roll\IMG_001.jpg"
    )
    assert onedrive is not None
    assert onedrive["storage_provider"] == "OneDrive"
    assert onedrive["path_scope"] == "user_cloud_content"
    assert onedrive["owning_user"] == "fredr"

    google_transfer = interpret_user_path(
        r"\Device\HarddiskVolume3\Users\fredr\OneDrive\Pictures\.tmp.drivedownload\4544319.driveupload"
    )
    assert google_transfer is not None
    assert google_transfer["storage_provider"] == "Google Drive"
    assert google_transfer["path_scope"] == "user_cloud_transfer_temp"
    assert "original filename unresolved" in google_transfer["artifact_meaning"]

    onedrive_app = interpret_user_path(
        r"C:\Users\fredr\AppData\Local\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log"
    )
    assert onedrive_app is not None
    assert onedrive_app["storage_provider"] == "OneDrive"
    assert onedrive_app["path_scope"] == "cloud_app_artifact"


def test_rebuild_user_file_references_from_defender_events(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Laptop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id=computer.id)
    created_at = utc_now()

    base = {
        "case_id": case.id,
        "computer_id": computer.id,
        "image_id": image.id,
        "tool_output_id": "output-defender",
        "tool_name": "WindowsDefenderParser",
        "source_csv": "/tmp/WindowsDefenderEvents.csv",
        "source_file": "MPDetection.log",
        "source_name": "MPDetection.log",
        "artifact_type": "detection_log",
        "line_number": 1,
        "event_time_utc": "2020-10-20T16:40:00+00:00",
        "event_type": "defender_scan",
        "component": "Mini-filter",
        "severity": None,
        "threat_name": None,
        "action": None,
        "resource": None,
        "file_size": None,
        "modified_time_utc": None,
        "sha256_first_mb": None,
        "raw_json": "{}",
        "created_at": created_at,
    }
    db.insert_windows_defender_events(
        [
            {
                **base,
                "id": "defender-1",
                "row_number": 1,
                "path": r"\Device\HarddiskVolume3\Users\fredr\OneDrive\Pictures\Camera Roll\IMG_001.jpg",
                "message": "Scanned OneDrive image",
            },
            {
                **base,
                "id": "defender-2",
                "row_number": 2,
                "path": r"\Device\HarddiskVolume3\Users\fredr\OneDrive\Pictures\.tmp.drivedownload\4544319.driveupload",
                "message": "Scanned Google Drive transfer temp",
            },
        ]
    )

    count = rebuild_user_controlled_file_references(db, case_id=case.id, image_id=image.id)

    rows = db.conn.execute(
        """
        SELECT storage_provider, path_scope, owning_user, normalized_path
        FROM user_controlled_file_references
        ORDER BY storage_provider, path_scope
        """
    ).fetchall()
    report = user_file_references_report(db, case.id, provider="Google Drive", limit=10)
    assert count == 2
    assert [dict(row) for row in rows] == [
        {
            "storage_provider": "Google Drive",
            "path_scope": "user_cloud_transfer_temp",
            "owning_user": "fredr",
            "normalized_path": r"\Device\HarddiskVolume3\Users\fredr\OneDrive\Pictures\.tmp.drivedownload\4544319.driveupload",
        },
        {
            "storage_provider": "OneDrive",
            "path_scope": "user_cloud_content",
            "owning_user": "fredr",
            "normalized_path": r"\Device\HarddiskVolume3\Users\fredr\OneDrive\Pictures\Camera Roll\IMG_001.jpg",
        },
    ]
    assert report["total_matching_rows"] == 1
    assert report["user_file_references"][0]["storage_provider"] == "Google Drive"


def test_rebuild_user_file_references_resolves_google_transfer_cache_id(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Laptop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id=computer.id)
    db.insert_google_drive_cache_map(
        [
            {
                "id": "gdrive-1",
                "case_id": case.id,
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "output-gdrive",
                "tool_name": "GoogleDriveParser",
                "source_csv": tmp_path / "GoogleDriveCacheMap.csv",
                "row_number": 1,
                "account_id": "acct",
                "stable_id": "stable",
                "file_id": "file-id",
                "virtual_path": "My Drive/Reports/Quarterly.xlsx",
                "file_name": "Quarterly.xlsx",
                "cache_id": "4544319",
                "cache_path": "/case/mount/Users/fredr/AppData/Local/Google/DriveFS/acct/content_cache/x/4544319",
                "windows_cache_path": r"C:\Users\fredr\AppData\Local\Google\DriveFS\acct\content_cache\x\4544319",
                "cache_file_size": "1024",
                "mapping_method": "protobuf_cache_id",
                "evidence_basis": "test",
                "details_json": "{}",
            }
        ]
    )
    db.insert_windows_defender_events(
        [
            {
                "id": "defender-1",
                "case_id": case.id,
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "output-defender",
                "tool_name": "WindowsDefenderParser",
                "source_csv": "/tmp/WindowsDefenderEvents.csv",
                "row_number": 1,
                "source_file": "MPDetection.log",
                "source_name": "MPDetection.log",
                "artifact_type": "detection_log",
                "line_number": 1,
                "event_time_utc": "2020-10-20T16:40:00+00:00",
                "event_type": "defender_scan",
                "component": "Mini-filter",
                "severity": None,
                "threat_name": None,
                "action": None,
                "path": r"\Device\HarddiskVolume3\Users\fredr\OneDrive\Pictures\.tmp.drivedownload\4544319.driveupload",
                "resource": None,
                "message": "Scanned Google Drive transfer temp",
                "file_size": None,
                "modified_time_utc": None,
                "sha256_first_mb": None,
                "raw_json": "{}",
                "created_at": utc_now(),
            }
        ]
    )

    count = rebuild_user_controlled_file_references(db, case_id=case.id, image_id=image.id)

    row = db.conn.execute("SELECT * FROM user_controlled_file_references").fetchone()
    source_report = user_file_references_report(db, case.id, contains="Quarterly", limit=10)
    assert count == 1
    assert row["display_path"] == r"HarddiskVolume3:\Users\fredr\OneDrive\Pictures\.tmp.drivedownload\4544319.driveupload"
    assert row["volume_device"] == "HarddiskVolume3"
    assert row["resolved_provider_path"] == "My Drive/Reports/Quarterly.xlsx"
    assert row["resolved_file_name"] == "Quarterly.xlsx"
    assert row["resolution_status"] == "resolved_by_google_drive_cache_id"
    assert source_report["total_matching_rows"] == 1

    drilldown = user_file_reference_source_report(db, case.id, reference_id=row["id"])
    assert drilldown["source_found"] is True
    assert drilldown["source"]["id"] == "defender-1"
    assert drilldown["reference"]["source_table"] == "windows_defender_events"
    assert drilldown["reference"]["details"]["activity_contract"] == {
        "source_table": "windows_defender_events",
        "source_row_id": "defender-1",
        "source_tool": "WindowsDefenderParser",
        "event_time_utc": "2020-10-20T16:40:00+00:00",
        "timestamp_meaning": "defender_event_time",
        "path": r"HarddiskVolume3:\Users\fredr\OneDrive\Pictures\.tmp.drivedownload\4544319.driveupload",
        "file_name": "4544319.driveupload",
        "user_profile": "fredr",
        "artifact_category": "file_reference",
        "interpretation_note": "Google Drive temporary transfer artifact resolved to cached Drive item",
    }
