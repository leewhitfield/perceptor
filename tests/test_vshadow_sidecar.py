import json
import struct
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from forensic_orchestrator.mounting.vshadow import (
    build_vshadowinfo_command,
    build_vshadowmount_command,
    extract_vsc_artifact,
    parse_vshadowinfo_output,
)
from forensic_orchestrator.mounting.vsc_prefetch import (
    compare_prefetch_snapshots,
    parse_vsc_prefetch_snapshot,
)
from forensic_orchestrator.mounting.vsc_registry import (
    VSC_REGISTRY_ARTIFACTS,
    compare_registry_snapshots,
    normalize_vsc_user_profile,
    registry_record_signature,
)
from forensic_orchestrator.mounting.vsc_browser import (
    browser_history_signature,
    compare_browser_snapshots,
    firefox_history_signature,
)
from forensic_orchestrator.mounting.vsc_appcompat import (
    amcache_signature,
    compare_appcompat_snapshots,
    shimcache_signature,
)
from forensic_orchestrator.mounting.vsc_srum import (
    compare_srum_snapshots,
    srum_signature,
)
from forensic_orchestrator.mounting.vsc_evtx import _evtx_signature_sql
from forensic_orchestrator.mounting.vsc_ntfs import compare_ntfs_snapshots_from_db
from forensic_orchestrator.mounting.vsc_search import _inventory_search_sources
from forensic_orchestrator.tools.prefetch import FILETIME_EPOCH
from forensic_orchestrator.paths import WorkspacePaths


def test_vshadow_commands_include_byte_offset(tmp_path):
    raw = tmp_path / "ewf1"
    mount = tmp_path / "vshadow"

    assert build_vshadowinfo_command(raw, offset_bytes=32256) == [
        "vshadowinfo",
        "-o",
        "32256",
        str(raw),
    ]
    assert build_vshadowmount_command(raw, mount, offset_bytes=32256) == [
        "vshadowmount",
        "-o",
        "32256",
        "-X",
        "allow_other",
        str(raw),
        str(mount),
    ]


def test_parse_vshadowinfo_output_extracts_snapshots():
    output = """
Volume Shadow Snapshot information:
Number of stores: 2

Store: 1
Identifier: {11111111-1111-1111-1111-111111111111}
Shadow copy set ID: {aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}
Creation time: 2020-10-27 14:58:04 UTC

Store: 2
Shadow copy identifier: {22222222-2222-2222-2222-222222222222}
Creation time: 2020-10-28 10:00:00 UTC
"""

    snapshots = parse_vshadowinfo_output(output)

    assert len(snapshots) == 2
    assert snapshots[0].index == 1
    assert snapshots[0].snapshot_id == "11111111-1111-1111-1111-111111111111"
    assert snapshots[0].shadow_copy_set_id == "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"
    assert snapshots[1].index == 2
    assert snapshots[1].created_utc == "2020-10-28 10:00:00 UTC"


def test_extract_vsc_artifact_writes_sidecar_manifest(tmp_path):
    paths = WorkspacePaths(tmp_path)
    case_id = "case-1"
    snapshot_id = "vss1"
    source = paths.vsc_snapshot_mount_dir(case_id, snapshot_id) / "Windows" / "Prefetch"
    source.mkdir(parents=True)
    (source / "APP.EXE-12345678.pf").write_bytes(b"prefetch")

    manifest = extract_vsc_artifact(
        paths=paths,
        case_id=case_id,
        snapshot_id=snapshot_id,
        relative_path="Windows/Prefetch",
    )

    destination = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / "Windows" / "Prefetch"
    manifest_path = destination.parent / "Prefetch.manifest.json"
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["file_count"] == 1
    assert saved["byte_count"] == len(b"prefetch")
    assert saved["files"][0]["md5"] == "4c203b76e2847e3b6e1bdf7bf2ad63a2"
    assert (destination / "APP.EXE-12345678.pf").read_bytes() == b"prefetch"


def test_windows_search_vsc_inventory_distinguishes_absent_edb_from_sqlite_candidate(tmp_path):
    snapshot = parse_vshadowinfo_output(
        """
Store: 3
Identifier: {33333333-3333-3333-3333-333333333333}
Creation time: 2020-10-28 10:00:00 UTC
"""
    )[0]
    search_root = tmp_path / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows"
    gather_root = search_root / "GatherLogs" / "SystemIndex"
    gather_root.mkdir(parents=True)
    (gather_root / "system.gthr").write_text("gather", encoding="utf-8")
    sqlite_root = tmp_path / "Users" / "fredr" / "AppData" / "Local" / "Packages" / "Microsoft.Windows.Search_cw5n1h2txyewy"
    sqlite_root.mkdir(parents=True)
    (sqlite_root / "windows-search.db").write_bytes(b"SQLite format 3")

    row = _inventory_search_sources(
        case_id="case-1",
        image_id="image-1",
        snapshot=snapshot,
        snapshot_id="vss3",
        mount_path=tmp_path,
    )

    assert row["source_root_exists"] == "true"
    assert row["windows_edb_exists"] == "false"
    assert row["gather_log_count"] == "1"
    assert row["windows11_sqlite_count"] == "1"
    assert "ESE database absent" in row["notes"]
    assert "SQLite candidate" in row["notes"]


def test_compare_ntfs_snapshots_reports_vsc_only_and_changed_rows(tmp_path):
    paths = WorkspacePaths(tmp_path)
    case_id = "case-1"
    image_id = "image-1"
    case_root = paths.case_dir(case_id)
    (case_root / "analytics").mkdir(parents=True)
    live = duckdb.connect(str(case_root / "analytics" / "events.duckdb"))
    live.execute(
        """
        CREATE TABLE mft_entries (
          case_id VARCHAR, parent_path VARCHAR, file_name VARCHAR, file_size VARCHAR,
          in_use VARCHAR, is_directory VARCHAR, created_si VARCHAR, modified_si VARCHAR,
          record_changed_si VARCHAR, accessed_si VARCHAR, entry_number VARCHAR, sequence_number VARCHAR
        )
        """
    )
    live.execute(
        """
        INSERT INTO mft_entries VALUES
        ('case-1', './Users/fredr', 'same.txt', '10', 'True', 'False', '2020-01-01', '2020-01-02', '2020-01-03', '2020-01-04', '1', '1'),
        ('case-1', './Users/fredr', 'changed.txt', '10', 'True', 'False', '2020-01-01', '2020-01-02', '2020-01-03', '2020-01-04', '2', '1')
        """
    )
    live.execute(
        """
        CREATE TABLE usn_journal_entries (
          case_id VARCHAR, update_sequence_number VARCHAR, update_timestamp VARCHAR,
          file_reference_number VARCHAR, file_reference_sequence_number VARCHAR,
          parent_file_reference_number VARCHAR, parent_file_reference_sequence_number VARCHAR,
          full_path VARCHAR, file_name VARCHAR, reason VARCHAR
        )
        """
    )
    live.execute("INSERT INTO usn_journal_entries VALUES ('case-1', '100', '2020-01-02', '2', '1', '5', '5', './Users/fredr/changed.txt', 'changed.txt', 'DataOverwrite')")
    live.close()

    class FakeCase:
        root = case_root

    class FakeDb:
        def get_case(self, value):
            assert value == case_id
            return FakeCase()

    paths.vsc_parsed_dir(case_id).mkdir(parents=True)
    sidecar = duckdb.connect(str(paths.vsc_parsed_db_path(case_id)))
    sidecar.execute(
        """
        CREATE TABLE vsc_mft_entries (
          case_id VARCHAR, image_id VARCHAR, snapshot_id VARCHAR, snapshot_index VARCHAR,
          snapshot_created_utc VARCHAR, normalized_path VARCHAR, path_key VARCHAR,
          file_name VARCHAR, file_size VARCHAR, in_use VARCHAR, is_directory VARCHAR,
          created_si VARCHAR, modified_si VARCHAR, record_changed_si VARCHAR, accessed_si VARCHAR,
          entry_number VARCHAR, sequence_number VARCHAR, record_signature VARCHAR
        )
        """
    )
    sidecar.execute(
        """
        INSERT INTO vsc_mft_entries VALUES
        ('case-1', 'image-1', 'vss1', '1', '2020', '/Users/fredr/same.txt', '/users/fredr/same.txt', 'same.txt', '10', 'True', 'False', '2020-01-01', '2020-01-02', '2020-01-03', '2020-01-04', '1', '1', lower('/users/fredr/same.txt|10|True|False|2020-01-01|2020-01-02|2020-01-03|2020-01-04|1|1')),
        ('case-1', 'image-1', 'vss1', '1', '2020', '/Users/fredr/changed.txt', '/users/fredr/changed.txt', 'changed.txt', '11', 'True', 'False', '2020-01-01', '2020-01-02', '2020-01-03', '2020-01-04', '2', '1', lower('/users/fredr/changed.txt|11|True|False|2020-01-01|2020-01-02|2020-01-03|2020-01-04|2|1')),
        ('case-1', 'image-1', 'vss1', '1', '2020', '/Users/fredr/gone.txt', '/users/fredr/gone.txt', 'gone.txt', '5', 'False', 'False', '2020-01-01', '2020-01-02', '2020-01-03', '2020-01-04', '3', '1', lower('/users/fredr/gone.txt|5|False|False|2020-01-01|2020-01-02|2020-01-03|2020-01-04|3|1'))
        """
    )
    sidecar.execute(
        """
        CREATE TABLE vsc_usn_journal_entries (
          case_id VARCHAR, image_id VARCHAR, snapshot_id VARCHAR, snapshot_index VARCHAR,
          snapshot_created_utc VARCHAR, update_timestamp VARCHAR, normalized_path VARCHAR,
          file_name VARCHAR, reason VARCHAR, update_sequence_number VARCHAR,
          file_reference_number VARCHAR, file_reference_sequence_number VARCHAR,
          parent_file_reference_number VARCHAR, parent_file_reference_sequence_number VARCHAR,
          record_signature VARCHAR
        )
        """
    )
    sidecar.execute(
        """
        INSERT INTO vsc_usn_journal_entries VALUES
        ('case-1', 'image-1', 'vss1', '1', '2020', '2020-01-02', '/Users/fredr/changed.txt', 'changed.txt', 'DataOverwrite', '100', '2', '1', '5', '5', lower('100|2020-01-02|2|1|5|5|/users/fredr/changed.txt|DataOverwrite')),
        ('case-1', 'image-1', 'vss1', '1', '2020', '2020-01-03', '/Users/fredr/gone.txt', 'gone.txt', 'FileDelete', '101', '3', '1', '5', '5', lower('101|2020-01-03|3|1|5|5|/users/fredr/gone.txt|FileDelete'))
        """
    )

    report = compare_ntfs_snapshots_from_db(conn=sidecar, db=FakeDb(), case_id=case_id, image_id=image_id)

    assert report["summary"]["mft_unique_paths_not_live"] == 1
    assert report["summary"]["mft_changed_unique_paths_from_live"] == 1
    assert report["summary"]["usn_unique_records_not_live"] == 1
    assert report["mft_only"][0]["normalized_path"] == "/Users/fredr/gone.txt"


def test_compare_ntfs_snapshots_treats_windows_old_as_live_alias(tmp_path):
    paths = WorkspacePaths(tmp_path)
    case_id = "case-1"
    image_id = "image-1"
    case_root = paths.case_dir(case_id)
    (case_root / "analytics").mkdir(parents=True)
    live = duckdb.connect(str(case_root / "analytics" / "events.duckdb"))
    live.execute(
        """
        CREATE TABLE mft_entries (
          case_id VARCHAR, parent_path VARCHAR, file_name VARCHAR, file_size VARCHAR,
          in_use VARCHAR, is_directory VARCHAR, created_si VARCHAR, modified_si VARCHAR,
          record_changed_si VARCHAR, accessed_si VARCHAR, entry_number VARCHAR, sequence_number VARCHAR
        )
        """
    )
    live.execute(
        """
        INSERT INTO mft_entries VALUES
        ('case-1', './Windows.old/Users/fredr', 'legacy.txt', '10', 'True', 'False',
         '2020-01-01', '2020-01-02', '2020-01-03', '2020-01-04', '2', '1')
        """
    )
    live.execute(
        """
        CREATE TABLE usn_journal_entries (
          case_id VARCHAR, update_sequence_number VARCHAR, update_timestamp VARCHAR,
          file_reference_number VARCHAR, file_reference_sequence_number VARCHAR,
          parent_file_reference_number VARCHAR, parent_file_reference_sequence_number VARCHAR,
          full_path VARCHAR, file_name VARCHAR, reason VARCHAR
        )
        """
    )
    live.close()

    class FakeCase:
        root = case_root

    class FakeDb:
        def get_case(self, value):
            assert value == case_id
            return FakeCase()

    paths.vsc_parsed_dir(case_id).mkdir(parents=True)
    sidecar = duckdb.connect(str(paths.vsc_parsed_db_path(case_id)))
    sidecar.execute(
        """
        CREATE TABLE vsc_mft_entries (
          case_id VARCHAR, image_id VARCHAR, snapshot_id VARCHAR, snapshot_index VARCHAR,
          snapshot_created_utc VARCHAR, normalized_path VARCHAR, path_key VARCHAR,
          file_name VARCHAR, file_size VARCHAR, in_use VARCHAR, is_directory VARCHAR,
          created_si VARCHAR, modified_si VARCHAR, record_changed_si VARCHAR, accessed_si VARCHAR,
          entry_number VARCHAR, sequence_number VARCHAR, record_signature VARCHAR
        )
        """
    )
    sidecar.execute(
        """
        INSERT INTO vsc_mft_entries VALUES
        ('case-1', 'image-1', 'vss1', '1', '2020', '/Users/fredr/legacy.txt',
         '/users/fredr/legacy.txt', 'legacy.txt', '10', 'True', 'False',
         '2020-01-01', '2020-01-02', '2020-01-03', '2020-01-04', '2', '1',
         lower('/users/fredr/legacy.txt|10|True|False|2020-01-01|2020-01-02|2020-01-03|2020-01-04|2|1'))
        """
    )
    sidecar.execute(
        """
        CREATE TABLE vsc_usn_journal_entries (
          case_id VARCHAR, image_id VARCHAR, snapshot_id VARCHAR, snapshot_index VARCHAR,
          snapshot_created_utc VARCHAR, update_timestamp VARCHAR, normalized_path VARCHAR,
          file_name VARCHAR, reason VARCHAR, update_sequence_number VARCHAR,
          file_reference_number VARCHAR, file_reference_sequence_number VARCHAR,
          parent_file_reference_number VARCHAR, parent_file_reference_sequence_number VARCHAR,
          record_signature VARCHAR
        )
        """
    )

    report = compare_ntfs_snapshots_from_db(conn=sidecar, db=FakeDb(), case_id=case_id, image_id=image_id)

    assert report["summary"]["mft_unique_paths_not_live"] == 0
    assert report["summary"]["mft_changed_unique_paths_from_live"] == 0


def test_parse_vsc_prefetch_snapshot_uses_md5_and_lean_fields(tmp_path):
    paths = WorkspacePaths(tmp_path)
    case_id = "case-1"
    snapshot = parse_vshadowinfo_output(
        """
Store: 1
Identifier: {11111111-1111-1111-1111-111111111111}
Creation time: 2020-10-28 10:00:00 UTC
"""
    )[0]
    prefetch_dir = paths.vsc_snapshot_extract_dir(case_id, "vss1") / "Windows" / "Prefetch"
    prefetch_dir.mkdir(parents=True)
    (prefetch_dir / "APP.EXE-12345678.pf").write_bytes(_scca_prefetch_bytes("APP.EXE", 0x12345678, 3))

    rows = parse_vsc_prefetch_snapshot(
        paths=paths,
        case_id=case_id,
        image_id="image-1",
        snapshot=snapshot,
        snapshot_id="vss1",
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["md5"]
    assert "sha256" not in row
    assert row["prefetch_name"] == "APP.EXE-12345678.pf"
    assert row["executable_name"] == "APP.EXE"
    assert row["run_count"] == "3"
    assert row["original_path"] == "/Windows/Prefetch/APP.EXE-12345678.pf"


def test_compare_prefetch_snapshots_finds_missing_and_changed_live_rows():
    comparison = compare_prefetch_snapshots(
        live_rows=[
            {
                "prefetch_name": "APP.EXE-12345678.pf",
                "executable_name": "APP.EXE",
                "prefetch_hash": "12345678",
                "run_count": 5,
                "last_run_time_utc": "2026-05-12T13:14:15Z",
                "last_run_times_utc": '["2026-05-12T13:14:15Z"]',
            }
        ],
        snapshot_rows=[
            {
                "snapshot_id": "vss1",
                "snapshot_index": 1,
                "snapshot_created_utc": "2020-10-28 10:00:00 UTC",
                "prefetch_name": "APP.EXE-12345678.pf",
                "executable_name": "APP.EXE",
                "prefetch_hash": "12345678",
                "run_count": 4,
                "last_run_time_utc": "2026-05-12T12:14:15Z",
                "last_run_times_utc": '["2026-05-12T12:14:15Z"]',
            },
            {
                "snapshot_id": "vss1",
                "snapshot_index": 1,
                "snapshot_created_utc": "2020-10-28 10:00:00 UTC",
                "prefetch_name": "OLD.EXE-87654321.pf",
                "executable_name": "OLD.EXE",
                "prefetch_hash": "87654321",
                "run_count": 1,
                "last_run_time_utc": "2026-05-11T10:00:00Z",
                "last_run_times_utc": '["2026-05-11T10:00:00Z"]',
            },
        ],
    )

    assert comparison["summary"]["only_in_vsc_count"] == 1
    assert comparison["summary"]["changed_from_live_count"] == 1


def test_compare_registry_snapshots_counts_unique_records_not_live():
    live = {
        registry_record_signature(
            {
                "artifact": "runmru",
                "user_profile": "alice",
                "key_path": "Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU",
                "value_name": "a",
                "value_data": "cmd.exe",
                "key_last_write_utc": "2020-01-01T00:00:00Z",
            }
        )
    }
    new_row = {
        "snapshot_id": "vss1",
        "snapshot_index": 1,
        "snapshot_created_utc": "2020-01-02T00:00:00Z",
        "artifact": "runmru",
        "category": "user_activity",
        "user_profile": "alice",
        "key_path": "Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU",
        "value_name": "b",
        "value_data": "powershell.exe",
        "key_last_write_utc": "2020-01-02T00:00:00Z",
    }
    duplicate_row = dict(new_row)
    duplicate_row["snapshot_id"] = "vss2"
    duplicate_row["snapshot_index"] = 2
    for row in (new_row, duplicate_row):
        row["record_signature"] = registry_record_signature(row)

    comparison = compare_registry_snapshots(live_signatures=live, snapshot_rows=[new_row, duplicate_row])

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["artifact_counts"] == {"runmru": 1}


def test_vsc_registry_artifact_scope_excludes_taskbar_feature_usage():
    assert "taskbar_feature_usage" not in VSC_REGISTRY_ARTIFACTS
    assert "taskbar_usage" in VSC_REGISTRY_ARTIFACTS


def test_vsc_registry_normalizes_default_user_alias():
    assert normalize_vsc_user_profile("Default User") == "Default"
    assert normalize_vsc_user_profile("default user") == "Default"
    assert normalize_vsc_user_profile("fredr") == "fredr"


def test_browser_vsc_signatures_match_live_profile_shapes():
    live = browser_history_signature(
        {
            "browser": "chrome",
            "profile_path": "fredr/AppData/Local/Google/Chrome/User Data/Default",
            "url": "https://example.test/",
            "visit_time_utc": "2020-11-14T13:00:00Z",
        }
    )
    vsc = browser_history_signature(
        {
            "browser": "chrome",
            "profile_path": "Users/fredr/AppData/Local/Google/Chrome/User Data/Default",
            "url": "https://example.test/",
            "visit_time_utc": "2020-11-14T13:00:00Z",
        }
    )
    firefox = firefox_history_signature(
        {
            "profile_path": "Users/fredr/AppData/Roaming/Mozilla/Firefox/Profiles/default",
            "url": "https://example.test/",
            "visit_time_utc": "2020-11-14T13:00:00Z",
            "visit_type": "1",
        }
    )

    assert vsc == live
    assert firefox


def test_compare_browser_snapshots_dedupes_vsc_browser_records_against_live():
    live_signature = browser_history_signature(
        {
            "browser": "chrome",
            "profile_path": "fredr/AppData/Local/Google/Chrome/User Data/Default",
            "url": "https://example.test/live",
            "visit_time_utc": "2020-11-14T13:00:00Z",
        }
    )
    new_row = {
        "snapshot_id": "vss1",
        "snapshot_index": "1",
        "snapshot_created_utc": "2020-11-14 13:00:00 UTC",
        "browser": "chrome",
        "profile_path": "Users/fredr/AppData/Local/Google/Chrome/User Data/Default",
        "url": "https://example.test/new",
        "visit_time_utc": "2020-11-14T13:01:00Z",
    }
    live_row = dict(new_row)
    live_row["url"] = "https://example.test/live"
    live_row["visit_time_utc"] = "2020-11-14T13:00:00Z"
    for row in (new_row, live_row):
        row["record_signature"] = browser_history_signature(row)

    comparison = compare_browser_snapshots(
        live_signatures={live_signature},
        snapshot_rows={"browser_history": [new_row, live_row], "browser_download": [], "firefox_history": []},
    )

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["summary"]["artifact_counts"] == {"browser_history": 1}


def test_appcompat_signatures_normalize_paths_and_compare_against_live():
    live_amcache = amcache_signature(
        {
            "entry_type": "File",
            "path": r"C:\Users\alice\Downloads\tool.exe",
            "sha1": "ABC",
            "modified_utc": "2020-11-14T13:00:00Z",
            "name": "tool.exe",
        }
    )
    live_shimcache = shimcache_signature(
        {
            "path": r"C:\Windows\System32\cmd.exe",
            "last_modified_utc": "2020-11-14T13:00:00Z",
            "executed": "True",
        }
    )
    vsc_amcache = {
        "snapshot_id": "vss1",
        "snapshot_index": "1",
        "snapshot_created_utc": "2020-11-14 13:00:00 UTC",
        "entry_type": "File",
        "path": "/Users/alice/Downloads/tool.exe",
        "sha1": "abc",
        "modified_utc": "2020-11-14T13:00:00Z",
        "name": "tool.exe",
    }
    vsc_amcache["record_signature"] = amcache_signature(vsc_amcache)
    vsc_new = {
        "snapshot_id": "vss1",
        "snapshot_index": "1",
        "snapshot_created_utc": "2020-11-14 13:00:00 UTC",
        "path": "/Windows/Temp/old.exe",
        "last_modified_utc": "2020-11-13T13:00:00Z",
        "executed": "False",
    }
    vsc_new["record_signature"] = shimcache_signature(vsc_new)

    comparison = compare_appcompat_snapshots(
        live_signatures={live_amcache, live_shimcache},
        snapshot_rows={"amcache": [vsc_amcache], "shimcache": [vsc_new]},
    )

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["summary"]["artifact_counts"] == {"shimcache": 1}


def test_srum_signature_and_comparison_dedupes_live_rows():
    live = srum_signature(
        {
            "record_type": "application_resource_usage",
            "source_table": "{guid}",
            "srum_id": "10",
            "timestamp": "2020-11-14T13:00:00Z",
            "app_name": "mstsc.exe",
            "app_path": r"C:\Windows\System32\mstsc.exe",
            "bytes_received": "100",
            "bytes_sent": "20",
        }
    )
    duplicate = {
        "snapshot_id": "vss1",
        "snapshot_index": "1",
        "snapshot_created_utc": "2020-11-14 13:00:00 UTC",
        "record_type": "application_resource_usage",
        "source_table": "{guid}",
        "srum_id": "10",
        "timestamp": "2020-11-14T13:00:00Z",
        "app_name": "mstsc.exe",
        "app_path": "/Windows/System32/mstsc.exe",
        "bytes_received": "100",
        "bytes_sent": "20",
    }
    new = dict(duplicate)
    new["srum_id"] = "11"
    new["timestamp"] = "2020-11-14T14:00:00Z"
    for row in (duplicate, new):
        row["record_signature"] = srum_signature(row)

    comparison = compare_srum_snapshots(live_signatures={live}, snapshot_rows=[duplicate, new])

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["summary"]["record_type_counts"] == {"application_resource_usage": 1}


def test_evtx_signature_uses_stable_event_identity_not_parser_payload():
    conn = duckdb.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE events (
          source_file VARCHAR,
          provider VARCHAR,
          channel VARCHAR,
          event_id VARCHAR,
          event_record_id VARCHAR,
          time_created VARCHAR,
          record_number VARCHAR,
          computer VARCHAR,
          user_id VARCHAR,
          user_name VARCHAR,
          remote_host VARCHAR,
          payload_data1 VARCHAR,
          payload_data2 VARCHAR,
          payload_data3 VARCHAR,
          executable_info VARCHAR
        )
        """
    )
    conn.execute(
        """
        INSERT INTO events VALUES
        ('/case/Windows/System32/winevt/Logs/DifferentPhysicalFile.evtx', 'Microsoft Office 16 Alerts', 'OAlerts', '300', '10',
         '2020-11-14 04:05:01.2428352', '999', 'ROCBATEST', '', '', '',
         'Program: Microsoft Word', 'Alert: Want to save your changes?\r\n  |', '', ''),
        ('OAlerts.evtx', 'truncated provider', 'oalerts', '300', '10',
         '2020-11-14 04:05:01.2428352', '1000', 'rocbatest', '', '', '',
         'Different parser payload', 'Different parser payload', 'Different parser payload', 'different.exe')
        """
    )
    signature_sql = _evtx_signature_sql(table_alias="events")
    signatures = [row[0] for row in conn.execute(f"SELECT {signature_sql} FROM events").fetchall()]

    assert signatures[0] == signatures[1]


def test_evtx_signature_normalizes_source_filename_when_channel_is_missing():
    conn = duckdb.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE events (
          source_file VARCHAR,
          provider VARCHAR,
          channel VARCHAR,
          event_id VARCHAR,
          event_record_id VARCHAR,
          time_created VARCHAR,
          record_number VARCHAR,
          computer VARCHAR,
          user_id VARCHAR,
          user_name VARCHAR,
          remote_host VARCHAR,
          payload_data1 VARCHAR,
          payload_data2 VARCHAR,
          payload_data3 VARCHAR,
          executable_info VARCHAR
        )
        """
    )
    conn.execute(
        """
        INSERT INTO events VALUES
        ('/case/Microsoft-Windows-WMI-Activity%4Operational.evtx', 'Micro', '', '5857', '1336',
         '2020-11-14 08:15:55.0734280', '1336', 'SRL-FORGE', '', '', '', '', '', '', ''),
        ('/case/Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity%4Operational.evtx',
         'Microsoft-Windows-WMI-Activity', 'Microsoft-Windows-WMI-Activity/Operational', '5857', '1336',
         '2020-11-14 08:15:55.0734280', '1336', 'srl-forge', '', '', '', 'PID: 13408', '', '', '')
        """
    )
    signature_sql = _evtx_signature_sql(table_alias="events")
    signatures = [row[0] for row in conn.execute(f"SELECT {signature_sql} FROM events").fetchall()]

    assert signatures[0] == signatures[1]


def test_registry_signature_normalizes_profile_alias_and_registry_path_case():
    live = registry_record_signature(
        {
            "artifact": "startup_approved",
            "user_profile": "Default",
            "key_path": "ROOT/Microsoft/Windows/CurrentVersion/Explorer/StartupApproved/Run",
            "value_name": "OneDriveSetup",
            "value_data": "040000000000000000000000",
        }
    )
    vsc_alias = registry_record_signature(
        {
            "artifact": "Startup_Approved",
            "user_profile": "Default User",
            "key_path": "root\\microsoft\\windows\\currentversion\\explorer\\startupapproved\\run",
            "value_name": "onedrivesetup",
            "value_data": "040000000000000000000000",
        }
    )

    assert vsc_alias == live


def test_registry_signature_normalizes_startupapproved_alias_prefix():
    live = registry_record_signature(
        {
            "artifact": "startup_approved",
            "user_profile": "srl-h",
            "key_path": "ROOT/Microsoft/Windows/CurrentVersion/Explorer/StartupApproved/Run",
            "value_name": "OneDriveSetup",
            "value_data": "040000000000000000000000",
        }
    )
    alias = registry_record_signature(
        {
            "artifact": "startup_approved",
            "user_profile": "srl-h",
            "key_path": "SOFTWARE/Policies/ROOT/Microsoft/Windows/CurrentVersion/Explorer/StartupApproved/Run",
            "value_name": "OneDriveSetup",
            "value_data": "040000000000000000000000",
        }
    )

    assert alias == live


def test_registry_signature_normalizes_policy_root_alias_prefix():
    live = registry_record_signature(
        {
            "artifact": "userassist",
            "user_profile": "alice",
            "key_path": "ROOT/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/{GUID}/Count",
            "value_name": r"P:\Jvaqbjf\Flfgrz32\pzq.rkr",
            "display_name": r"C:\Windows\System32\cmd.exe",
            "value_data": r"C:\Windows\System32\cmd.exe",
        }
    )
    alias = registry_record_signature(
        {
            "artifact": "userassist",
            "user_profile": "alice",
            "key_path": "Policies/ROOT/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/{GUID}/Count",
            "value_name": r"P:\Jvaqbjf\Flfgrz32\pzq.rkr",
            "display_name": r"C:\Windows\System32\cmd.exe",
            "value_data": "different-counter-blob",
        }
    )

    assert alias == live


def test_userassist_signature_uses_decoded_identity_not_counter_blob():
    first = registry_record_signature(
        {
            "artifact": "userassist",
            "user_profile": "alice",
            "key_path": "ROOT/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/{GUID}/Count",
            "value_name": r"P:\Jvaqbjf\Flfgrz32\pzq.rkr",
            "display_name": r"C:\Windows\System32\cmd.exe",
            "value_data": "0100000000000000",
            "last_executed": "2020-01-02T00:00:00Z",
        }
    )
    later_counter = registry_record_signature(
        {
            "artifact": "userassist",
            "user_profile": "alice",
            "key_path": "ROOT/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/{GUID}/Count",
            "value_name": r"P:\Jvaqbjf\Flfgrz32\pzq.rkr",
            "display_name": r"C:\Windows\System32\cmd.exe",
            "value_data": "0200000000000000",
            "last_executed": "2020-01-02T00:00:00Z",
        }
    )

    assert later_counter == first


def test_userassist_signature_keeps_last_executed_in_identity():
    first = registry_record_signature(
        {
            "artifact": "userassist",
            "user_profile": "alice",
            "key_path": "ROOT/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/{GUID}/Count",
            "display_name": r"C:\Windows\System32\cmd.exe",
            "last_executed": "2020-01-02T00:00:00Z",
        }
    )
    later = registry_record_signature(
        {
            "artifact": "userassist",
            "user_profile": "alice",
            "key_path": "ROOT/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/{GUID}/Count",
            "display_name": r"C:\Windows\System32\cmd.exe",
            "last_executed": "2020-01-03T00:00:00Z",
        }
    )

    assert later != first


def test_compare_registry_snapshots_dedupes_state_values_across_key_times():
    row = {
        "snapshot_id": "vss1",
        "snapshot_index": 1,
        "snapshot_created_utc": "2020-01-02T00:00:00Z",
        "artifact": "mui_cache",
        "category": "user_activity",
        "user_profile": "alice",
        "key_path": "Classes/Local Settings/MuiCache/b/52C64B7E",
        "value_name": "C:\\Program Files\\Example\\app.exe",
        "value_data": "Example App",
        "key_last_write_utc": "2020-01-02T00:00:00Z",
    }
    same_value_later_snapshot = dict(row)
    same_value_later_snapshot["snapshot_id"] = "vss2"
    same_value_later_snapshot["snapshot_index"] = 2
    same_value_later_snapshot["key_last_write_utc"] = "2020-01-03T00:00:00Z"

    comparison = compare_registry_snapshots(
        live_signatures=set(),
        snapshot_rows=[row, same_value_later_snapshot],
    )

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["snapshots"][0]["unique_not_live_count"] == 1
    assert comparison["snapshots"][1]["unique_not_live_count"] == 1


def test_mui_cache_vsc_comparison_ignores_resource_strings_and_normalizes_bucket():
    live = {
        registry_record_signature(
            {
                "artifact": "mui_cache",
                "category": "user_activity",
                "user_profile": "alice",
                "key_path": "Classes/Local Settings/MuiCache/10/52C64B7E",
                "value_name": r"C:\Program Files\Example\app.exe.FriendlyAppName",
                "value_data": "Example App",
            }
        )
    }
    snapshot_rows = [
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-02T00:00:00Z",
            "artifact": "mui_cache",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "Classes/Local Settings/MuiCache/b/52C64B7E",
            "value_name": r"C:\Program Files\Example\app.exe.FriendlyAppName",
            "value_data": "Example App",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-02T00:00:00Z",
            "artifact": "mui_cache",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "Classes/Local Settings/MuiCache/b/52C64B7E",
            "value_name": r"@C:\Windows\System32\notepad.exe,-469",
            "value_data": "Text Document",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-02T00:00:00Z",
            "artifact": "mui_cache",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "Classes/Local Settings/ImmutableMuiCache/Strings/52C64B7E",
            "value_name": r"@C:\Windows\System32\systemcpl.dll,-1#immutable1",
            "value_data": "System",
        },
    ]

    comparison = compare_registry_snapshots(live_signatures=live, snapshot_rows=snapshot_rows)

    assert comparison["summary"]["unique_vsc_records_not_live"] == 0
    assert comparison["artifact_counts"] == {}


def test_compare_registry_snapshots_keeps_event_time_in_identity():
    row = {
        "snapshot_id": "vss1",
        "snapshot_index": 1,
        "snapshot_created_utc": "2020-01-02T00:00:00Z",
        "artifact": "bam",
        "category": "execution",
        "user_profile": "alice",
        "user_sid": "S-1-5-21-100-200-300-1000",
        "key_path": "CurrentControlSet/Services/bam/State/UserSettings/S-1-5-21-100-200-300-1000",
        "value_name": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
        "normalized_path": "HarddiskVolume3:\\Windows\\System32\\cmd.exe",
        "event_time_utc": "2020-01-02T00:00:00Z",
        "key_last_write_utc": "2020-01-02T00:00:00Z",
    }
    later_event = dict(row)
    later_event["snapshot_id"] = "vss2"
    later_event["snapshot_index"] = 2
    later_event["event_time_utc"] = "2020-01-03T00:00:00Z"
    later_event["key_last_write_utc"] = "2020-01-03T00:00:00Z"

    comparison = compare_registry_snapshots(live_signatures=set(), snapshot_rows=[row, later_event])

    assert comparison["summary"]["unique_vsc_records_not_live"] == 2
    assert comparison["artifact_counts"] == {"bam": 2}


def test_bam_vsc_comparison_ignores_non_account_sids():
    snapshot_rows = [
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-02T00:00:00Z",
            "artifact": "bam",
            "category": "execution",
            "user_sid": "S-1-5-18",
            "key_path": "CurrentControlSet/Services/bam/State/UserSettings/S-1-5-18",
            "value_name": "\\Device\\HarddiskVolume3\\Windows\\System32\\csrss.exe",
            "normalized_path": "HarddiskVolume3:\\Windows\\System32\\csrss.exe",
            "event_time_utc": "2020-01-02T00:00:00Z",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-02T00:00:00Z",
            "artifact": "bam",
            "category": "execution",
            "user_sid": "S-1-5-21-100-200-300-1000",
            "key_path": "CurrentControlSet/Services/bam/State/UserSettings/S-1-5-21-100-200-300-1000",
            "value_name": "\\Device\\HarddiskVolume3\\Users\\alice\\Downloads\\tool.exe",
            "normalized_path": "HarddiskVolume3:\\Users\\alice\\Downloads\\tool.exe",
            "event_time_utc": "2020-01-02T00:00:00Z",
        },
    ]

    comparison = compare_registry_snapshots(live_signatures=set(), snapshot_rows=snapshot_rows)

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["artifact_counts"] == {"bam": 1}
    assert comparison["examples"][0]["user_sid"] == "S-1-5-21-100-200-300-1000"


def test_wordwheel_comparison_only_counts_most_recent_key_time():
    live = {
        registry_record_signature(
            {
                "artifact": "wordwheel_query",
                "user_profile": "alice",
                "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/WordWheelQuery",
                "key_last_write_utc": "2020-01-02T00:00:00Z",
                "mru_position": "1",
                "value_name": "0",
                "value_data": "current",
            }
        )
    }
    snapshot_rows = [
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "wordwheel_query",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/WordWheelQuery",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "mru_position": "1",
            "value_name": "5",
            "value_data": "cobra",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "wordwheel_query",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/WordWheelQuery",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "mru_position": "2",
            "value_name": "4",
            "value_data": "crimson",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "wordwheel_query",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/WordWheelQuery",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "value_name": "MRUListEx",
            "value_data": "0500000004000000ffffffff",
        },
    ]

    comparison = compare_registry_snapshots(live_signatures=live, snapshot_rows=snapshot_rows)

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["artifact_counts"] == {"wordwheel_query": 1}
    assert comparison["examples"][0]["value_data"] == "cobra"


def test_common_dialog_comparison_only_counts_most_recent_key_time():
    snapshot_rows = [
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "common_dialog",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/OpenSavePidlMRU/*",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "mru_position": "1",
            "value_name": "5",
            "value_data": "shell-item-a",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "common_dialog",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/OpenSavePidlMRU/*",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "mru_position": "2",
            "value_name": "4",
            "value_data": "shell-item-b",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "common_dialog",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/OpenSavePidlMRU/*",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "value_name": "MRUListEx",
            "value_data": "0500000004000000ffffffff",
        },
    ]

    comparison = compare_registry_snapshots(live_signatures=set(), snapshot_rows=snapshot_rows)

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["artifact_counts"] == {"common_dialog": 1}
    assert comparison["examples"][0]["value_data"] == "shell-item-a"


def test_recentdocs_comparison_only_counts_most_recent_key_time():
    snapshot_rows = [
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "recentdocs",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "mru_position": "1",
            "value_name": "5",
            "value_data": "report.docx",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "recentdocs",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "mru_position": "2",
            "value_name": "4",
            "value_data": "older.docx",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "recentdocs",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "value_name": "MRUListEx",
            "value_data": "0500000004000000ffffffff",
        },
    ]

    comparison = compare_registry_snapshots(live_signatures=set(), snapshot_rows=snapshot_rows)

    assert comparison["summary"]["unique_vsc_records_not_live"] == 1
    assert comparison["artifact_counts"] == {"recentdocs": 1}
    assert comparison["examples"][0]["value_data"] == "report.docx"


def test_office_recent_docs_comparison_ignores_cache_and_diagnostics():
    snapshot_rows = [
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "office_recent_docs",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Office/16.0/Common/Internet/WebServiceCache/AllUsers",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "value_name": "OfficeCache",
            "value_data": "https://officestore.microsoft.com/config.json",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "office_recent_docs",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Office/16.0/Outlook/Diagnostics",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "value_name": "BootDiagnosticsLogFile",
            "value_data": "C:\\Users\\alice\\AppData\\Local\\Temp\\Outlook Logging\\boot.etl",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "office_recent_docs",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Office/16.0/Word/User MRU/ADAL_/File MRU",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "value_name": "Item 1",
            "value_data": "[F00000000][T01D6]C:\\Users\\alice\\Documents\\report.docx",
        },
        {
            "snapshot_id": "vss1",
            "snapshot_index": 1,
            "snapshot_created_utc": "2020-01-01T00:00:00Z",
            "artifact": "office_recent_docs",
            "category": "user_activity",
            "user_profile": "alice",
            "key_path": "ROOT/SOFTWARE/Microsoft/Office/16.0/Common/DocToIdMapping",
            "key_last_write_utc": "2020-01-01T00:00:00Z",
            "value_name": "https://contoso.sharepoint.com/sites/finance/Shared Documents/budget.xlsx",
            "value_data": "GUID",
        },
    ]

    comparison = compare_registry_snapshots(live_signatures=set(), snapshot_rows=snapshot_rows)

    assert comparison["summary"]["unique_vsc_records_not_live"] == 2
    assert comparison["artifact_counts"] == {"office_recent_docs": 2}
    assert {row["value_name"] for row in comparison["examples"]} == {
        "Item 1",
        "https://contoso.sharepoint.com/sites/finance/Shared Documents/budget.xlsx",
    }


def _scca_prefetch_bytes(exe_name: str, prefetch_hash: int, run_count: int) -> bytes:
    data = bytearray(0x300)
    struct.pack_into("<I", data, 0, 30)
    data[4:8] = b"SCCA"
    struct.pack_into("<I", data, 12, len(data))
    data[16:76] = exe_name.encode("utf-16le").ljust(60, b"\x00")[:60]
    struct.pack_into("<I", data, 76, prefetch_hash)
    struct.pack_into("<Q", data, 0x80, _filetime(datetime(2026, 5, 12, 13, 14, 15, tzinfo=timezone.utc)))
    struct.pack_into("<I", data, 0xD0, run_count)
    return bytes(data)


def _filetime(dt: datetime) -> int:
    return int((dt - FILETIME_EPOCH).total_seconds() * 10_000_000)
