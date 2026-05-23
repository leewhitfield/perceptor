import struct
from datetime import datetime, timezone

from forensic_orchestrator.tools.registry_artifacts import parse_registry_artifacts
from forensic_orchestrator.tools.sam import RegistryKeyRecord, registry_path


def test_runmru_uses_mrulist_to_assign_event_time(monkeypatch, tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "SOFTWARE", 1, {}),
        3: RegistryKeyRecord(3, "Microsoft", 2, {}),
        4: RegistryKeyRecord(4, "Windows", 3, {}),
        5: RegistryKeyRecord(5, "CurrentVersion", 4, {}),
        6: RegistryKeyRecord(6, "Explorer", 5, {}),
        7: RegistryKeyRecord(
            7,
            "RunMRU",
            6,
            {"MRUList": 1, "a": 1, "b": 1, "c": 1, "d": 1},
            {
                "MRUList": "dbca\x00".encode("utf-16-le"),
                "a": "regedit\\1\x00".encode("utf-16-le"),
                "b": "secpol.msc\\1\x00".encode("utf-16-le"),
                "c": "eventvwr.msc\\1\x00".encode("utf-16-le"),
                "d": "winver\\1\x00".encode("utf-16-le"),
            },
            "2020-11-01T22:17:08.082260Z",
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = parse_registry_artifacts(hive)
    by_value = {row["value_name"]: row for row in rows if row["artifact"] == "runmru"}

    assert by_value["d"]["value_data"] == "winver\\1"
    assert by_value["d"]["mru_position"] == "1"
    assert by_value["d"]["is_most_recent"] == "true"
    assert by_value["d"]["event_time_utc"] == "2020-11-01T22:17:08.082260Z"
    assert by_value["a"]["mru_position"] == "4"
    assert by_value["a"]["event_time_utc"] is None


def test_typedpaths_url1_gets_key_last_write_time(monkeypatch, tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "SOFTWARE", 1, {}),
        3: RegistryKeyRecord(3, "Microsoft", 2, {}),
        4: RegistryKeyRecord(4, "Windows", 3, {}),
        5: RegistryKeyRecord(5, "CurrentVersion", 4, {}),
        6: RegistryKeyRecord(6, "Explorer", 5, {}),
        7: RegistryKeyRecord(
            7,
            "TypedPaths",
            6,
            {"url1": 1, "url2": 1, "url3": 1},
            {
                "url1": "G:\\My Drive\\Project\x00".encode("utf-16-le"),
                "url2": "G:\\My Drive\x00".encode("utf-16-le"),
                "url3": "G:\\\x00".encode("utf-16-le"),
            },
            "2020-11-14T04:43:37.661416Z",
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = parse_registry_artifacts(hive)
    by_value = {row["value_name"]: row for row in rows if row["artifact"] == "typed_paths"}

    assert by_value["url1"]["mru_position"] == "1"
    assert by_value["url1"]["is_most_recent"] == "true"
    assert by_value["url1"]["event_time_utc"] == "2020-11-14T04:43:37.661416Z"
    assert by_value["url2"]["mru_position"] == "2"
    assert by_value["url2"]["event_time_utc"] is None


def test_outlook_secure_temp_folder_is_captured(monkeypatch, tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Software", 1, {}),
        3: RegistryKeyRecord(3, "Microsoft", 2, {}),
        4: RegistryKeyRecord(4, "Office", 3, {}),
        5: RegistryKeyRecord(5, "16.0", 4, {}),
        6: RegistryKeyRecord(6, "Outlook", 5, {}),
        7: RegistryKeyRecord(
            7,
            "Security",
            6,
            {"OutlookSecureTempFolder": 1, "Unrelated": 1},
            {
                "OutlookSecureTempFolder": (
                    r"C:\Users\fredr\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABC123"
                    "\x00"
                ).encode("utf-16-le"),
                "Unrelated": "ignore me\x00".encode("utf-16-le"),
            },
            "2020-11-14T04:43:37.661416Z",
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "outlook_secure_temp"]

    assert len(rows) == 1
    assert rows[0]["category"] == "email"
    assert rows[0]["value_name"] == "OutlookSecureTempFolder"
    assert "Content.Outlook" in rows[0]["value_data"]


def test_mui_cache_entries_are_captured_from_usrclass(monkeypatch, tmp_path):
    hive = tmp_path / "UsrClass.dat"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Local Settings", 1, {}),
        3: RegistryKeyRecord(3, "Software", 2, {}),
        4: RegistryKeyRecord(4, "Microsoft", 3, {}),
        5: RegistryKeyRecord(5, "Windows", 4, {}),
        6: RegistryKeyRecord(6, "Shell", 5, {}),
        7: RegistryKeyRecord(7, "MuiCache", 6, {}),
        8: RegistryKeyRecord(
            8,
            "C:\\Program Files\\Example",
            7,
            {"C:\\Program Files\\Example\\tool.exe.FriendlyAppName": 1},
            {"C:\\Program Files\\Example\\tool.exe.FriendlyAppName": "Example Tool\x00".encode("utf-16-le")},
            "2020-11-14T04:43:37.661416Z",
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "mui_cache"]

    assert len(rows) == 1
    assert rows[0]["category"] == "user_activity"
    assert rows[0]["value_name"] == "C:\\Program Files\\Example\\tool.exe.FriendlyAppName"
    assert rows[0]["display_name"] == "Example Tool"
    assert rows[0]["value_data"] == "Example Tool"


def test_device_migration_only_emits_usb_device_rows(monkeypatch, tmp_path):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Setup", 1, {}),
        3: RegistryKeyRecord(3, "Upgrade", 2, {}),
        4: RegistryKeyRecord(4, "PnP", 3, {}),
        5: RegistryKeyRecord(5, "CurrentControlSet", 4, {}),
        6: RegistryKeyRecord(6, "Control", 5, {}),
        7: RegistryKeyRecord(7, "DeviceMigration", 6, {"MigrationTime": 1}),
        8: RegistryKeyRecord(8, "Classes", 7, {}),
        9: RegistryKeyRecord(9, "{printer-class}", 8, {"SWD\\PRINTENUM\\Queue": 1}),
        10: RegistryKeyRecord(10, "Devices", 7, {}),
        11: RegistryKeyRecord(11, "USB", 10, {}),
        12: RegistryKeyRecord(
            12,
            "VID_0781&PID_5581",
            11,
            {},
        ),
        13: RegistryKeyRecord(
            13,
            "4C530001230101101234",
            12,
            {"HardwareIds": 7, "LastPresentDate": 1, "ParentIdPrefix": 1, "Service": 1},
            {
                "HardwareIds": "USB\\VID_0781&PID_5581;USB\\Class_08\x00".encode("utf-16-le"),
                "LastPresentDate": "2020-11-10T01:02:03Z\x00".encode("utf-16-le"),
                "ParentIdPrefix": "7&abc123&0\x00".encode("utf-16-le"),
                "Service": "USBSTOR\x00".encode("utf-16-le"),
            },
            "2020-11-10T01:02:03Z",
        ),
        14: RegistryKeyRecord(14, "ROOT", 10, {}),
        15: RegistryKeyRecord(
            15,
            "SOME_NON_USB_DEVICE",
            14,
            {"HardwareIds": 7},
            {"HardwareIds": "ROOT\\SOME_NON_USB_DEVICE\x00".encode("utf-16-le")},
        ),
        16: RegistryKeyRecord(16, "ActivationBroker", 1, {}),
        17: RegistryKeyRecord(17, "Plugins", 16, {}),
        18: RegistryKeyRecord(18, "{plugin}", 17, {}),
        19: RegistryKeyRecord(19, "ROOT", 18, {}),
        20: RegistryKeyRecord(20, "Setup", 19, {}),
        21: RegistryKeyRecord(21, "Upgrade", 20, {}),
        22: RegistryKeyRecord(22, "PnP", 21, {}),
        23: RegistryKeyRecord(23, "CurrentControlSet", 22, {}),
        24: RegistryKeyRecord(24, "Control", 23, {}),
        25: RegistryKeyRecord(25, "DeviceMigration", 24, {}),
        26: RegistryKeyRecord(26, "Devices", 25, {}),
        27: RegistryKeyRecord(27, "USB", 26, {}),
        28: RegistryKeyRecord(28, "VID_0781&PID_5581", 27, {}),
        29: RegistryKeyRecord(
            29,
            "DUPLICATE_PLUGIN_PATH",
            28,
            {"LastPresentDate": 1},
            {"LastPresentDate": "2020-11-11T01:02:03Z\x00".encode("utf-16-le")},
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "usb_device_migration"]

    assert {row["value_name"] for row in rows} == {"HardwareIds", "LastPresentDate", "ParentIdPrefix", "Service"}
    assert all("VID_0781&PID_5581" in row["key_path"] for row in rows)


def test_bam_records_executable_path_and_filetime(monkeypatch, tmp_path):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf-test")
    timestamp = datetime(2020, 11, 14, 13, 45, 45, tzinfo=timezone.utc)
    filetime = int((timestamp - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    bam_path = r"\Device\HarddiskVolume3\Users\fredr\Downloads\SDelete\sdelete.exe"
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Select", 1, {"Current": 4}, {"Current": struct.pack("<I", 1)}),
        3: RegistryKeyRecord(3, "Services", 2, {}),
        4: RegistryKeyRecord(4, "ControlSet001", 1, {}),
        5: RegistryKeyRecord(5, "Services", 4, {}),
        6: RegistryKeyRecord(6, "bam", 5, {}),
        7: RegistryKeyRecord(7, "State", 6, {}),
        8: RegistryKeyRecord(8, "UserSettings", 7, {}),
        9: RegistryKeyRecord(
            9,
            "S-1-5-21-100-200-300-1000",
            8,
            {"Version": 4, "SequenceNumber": 4, bam_path: 3},
            {
                "Version": struct.pack("<I", 1),
                "SequenceNumber": struct.pack("<I", 42),
                bam_path: struct.pack("<Q", filetime) + b"\x00" * 16,
            },
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "bam"]

    assert len(rows) == 1
    assert rows[0]["category"] == "execution"
    assert rows[0]["user_sid"] == "S-1-5-21-100-200-300-1000"
    assert rows[0]["value_name"] == bam_path
    assert rows[0]["normalized_path"] == r"HarddiskVolume3:\Users\fredr\Downloads\SDelete\sdelete.exe"
    assert rows[0]["event_time_utc"] == "2020-11-14T13:45:45Z"
    assert "executed_path=" in rows[0]["notes"]
    assert "filetime=2020-11-14T13:45:45Z" in rows[0]["notes"]


def test_userassist_skips_control_values_and_decodes_name(monkeypatch, tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf-test")
    encoded_cmd = r"P:\Jvaqbjf\Flfgrz32\pzq.rkr"
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Software", 1, {}),
        3: RegistryKeyRecord(3, "Microsoft", 2, {}),
        4: RegistryKeyRecord(4, "Windows", 3, {}),
        5: RegistryKeyRecord(5, "CurrentVersion", 4, {}),
        6: RegistryKeyRecord(6, "Explorer", 5, {}),
        7: RegistryKeyRecord(7, "UserAssist", 6, {}),
        8: RegistryKeyRecord(8, "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", 7, {}),
        9: RegistryKeyRecord(
            9,
            "Count",
            8,
            {"Version": 4, "HRZR_PGYFRFFVBA": 3, "HRZR_PGYPHNPbhag:pgbe": 3, encoded_cmd: 3},
            {
                "Version": struct.pack("<I", 5),
                "HRZR_PGYFRFFVBA": b"\x00" * 16,
                "HRZR_PGYPHNPbhag:pgbe": b"\xff" * 72,
                encoded_cmd: _userassist_v5_bytes(run_counter=3, focus_count=4, focus_time_ms=90000),
            },
            "2020-11-14T04:43:37.661416Z",
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "userassist"]

    assert len(rows) == 1
    assert rows[0]["value_name"] == encoded_cmd
    assert rows[0]["display_name"] == r"C:\Windows\System32\cmd.exe"
    assert rows[0]["normalized_path"] == r"C:\Windows\System32\cmd.exe"
    assert rows[0]["value_data"] == r"C:\Windows\System32\cmd.exe"
    assert rows[0]["run_counter"] == "3"
    assert rows[0]["focus_count"] == "4"
    assert rows[0]["focus_time"] == "0d, 0h, 01m, 30s"
    assert rows[0]["last_executed"] == "2020-11-14T13:45:45Z"
    assert rows[0]["notes"] == r"rot13_name=C:\Windows\System32\cmd.exe"


def test_bam_ignores_nested_activationbroker_shadow_path(monkeypatch, tmp_path):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf-test")
    timestamp = datetime(2020, 11, 14, 13, 45, 45, tzinfo=timezone.utc)
    filetime = int((timestamp - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    bam_path = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "ActivationBroker", 1, {}),
        3: RegistryKeyRecord(3, "Plugins", 2, {}),
        4: RegistryKeyRecord(4, "{AC59432D-8659-48C4-A584-AFEBC920256F}", 3, {}),
        5: RegistryKeyRecord(5, "ROOT", 4, {}),
        6: RegistryKeyRecord(6, "Select", 5, {"Current": 4}, {"Current": struct.pack("<I", 1)}),
        7: RegistryKeyRecord(7, "Services", 5, {}),
        8: RegistryKeyRecord(8, "ControlSet001", 5, {}),
        9: RegistryKeyRecord(9, "Services", 8, {}),
        10: RegistryKeyRecord(10, "bam", 9, {}),
        11: RegistryKeyRecord(11, "State", 10, {}),
        12: RegistryKeyRecord(12, "UserSettings", 11, {}),
        13: RegistryKeyRecord(
            13,
            "S-1-5-21-1000",
            12,
            {bam_path: 3},
            {bam_path: struct.pack("<Q", filetime) + b"\x00" * 16},
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "bam"]

    assert rows == []


def test_bam_keeps_short_service_sid_for_system_context_analysis(monkeypatch, tmp_path):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf-test")
    timestamp = datetime(2020, 11, 14, 13, 45, 45, tzinfo=timezone.utc)
    filetime = int((timestamp - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    bam_path = r"\Device\HarddiskVolume3\Windows\System32\csrss.exe"
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Select", 1, {"Current": 4}, {"Current": struct.pack("<I", 1)}),
        3: RegistryKeyRecord(3, "ControlSet001", 1, {}),
        4: RegistryKeyRecord(4, "Services", 3, {}),
        5: RegistryKeyRecord(5, "bam", 4, {}),
        6: RegistryKeyRecord(6, "State", 5, {}),
        7: RegistryKeyRecord(7, "UserSettings", 6, {}),
        8: RegistryKeyRecord(
            8,
            "S-1-5-18",
            7,
            {bam_path: 3},
            {bam_path: struct.pack("<Q", filetime) + b"\x00" * 16},
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "bam"]

    assert len(rows) == 1
    assert rows[0]["user_sid"] == "S-1-5-18"
    assert rows[0]["value_name"] == bam_path


def test_registry_path_stops_when_hive_root_parent_is_normalized():
    records = {
        32: RegistryKeyRecord(32, "ROOT", 0xFFFFFFFF, {}),
        368: RegistryKeyRecord(368, "ActivationBroker", 32, {}),
        856: RegistryKeyRecord(856, "Plugins", 368, {}),
        3720: RegistryKeyRecord(3720, "{AC59432D-8659-48C4-A584-AFEBC920256F}", 856, {}),
        5704: RegistryKeyRecord(5704, "ControlSet001", 32, {}),
        9000: RegistryKeyRecord(9000, "Services", 5704, {}),
    }

    assert registry_path(records, 9000) == "ROOT/ControlSet001/Services"


def test_recentdocs_keeps_root_and_extension_times_separate(monkeypatch, tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "SOFTWARE", 1, {}),
        3: RegistryKeyRecord(3, "Microsoft", 2, {}),
        4: RegistryKeyRecord(4, "Windows", 3, {}),
        5: RegistryKeyRecord(5, "CurrentVersion", 4, {}),
        6: RegistryKeyRecord(6, "Explorer", 5, {}),
        7: RegistryKeyRecord(
            7,
            "RecentDocs",
            6,
            {"MRUListEx": 3, "83": 3, "127": 3},
            {
                "MRUListEx": b"\x53\x00\x00\x00\x7f\x00\x00\x00\xff\xff\xff\xff",
                "83": "ROCBA-SYSTEM\x00".encode("utf-16-le") + b"extra",
                "127": "Outlook Files\x00".encode("utf-16-le") + b"extra",
            },
            "2020-11-16T02:32:19.634820Z",
        ),
        8: RegistryKeyRecord(
            8,
            ".pst",
            7,
            {"MRUListEx": 3, "1": 3, "0": 3},
            {
                "MRUListEx": b"\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff",
                "1": "backup.pst\x00".encode("utf-16-le") + b"extra",
                "0": "SRL-EMAIL-EXPORT.pst\x00".encode("utf-16-le") + b"extra",
            },
            "2020-11-14T14:03:52.763836Z",
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = parse_registry_artifacts(hive)
    by_key_value = {(row["key_path"].split("/")[-1], row["value_name"]): row for row in rows}

    root_first = by_key_value["RecentDocs", "83"]
    assert root_first["display_name"] == "ROCBA-SYSTEM"
    assert root_first["recentdocs_mru_position"] == "1"
    assert root_first["recentdocs_time_utc"] == "2020-11-16T02:32:19.634820Z"
    assert root_first["recentdocs_extension_time_utc"] is None

    root_second = by_key_value["RecentDocs", "127"]
    assert root_second["display_name"] == "Outlook Files"
    assert root_second["recentdocs_mru_position"] == "2"
    assert root_second["recentdocs_time_utc"] is None

    extension_first = by_key_value[".pst", "1"]
    assert extension_first["display_name"] == "backup.pst"
    assert extension_first["recentdocs_extension_mru_position"] == "1"
    assert extension_first["recentdocs_extension_time_utc"] == "2020-11-14T14:03:52.763836Z"
    assert extension_first["recentdocs_time_utc"] is None


def test_registry_artifacts_warn_when_transaction_logs_exist(monkeypatch, tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf-test")
    (tmp_path / "ntuser.dat.LOG1").write_bytes(b"log1")
    (tmp_path / "ntuser.dat.LOG2").write_bytes(b"log2")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "SOFTWARE", 1, {}),
        3: RegistryKeyRecord(3, "Microsoft", 2, {}),
        4: RegistryKeyRecord(4, "Windows", 3, {}),
        5: RegistryKeyRecord(5, "CurrentVersion", 4, {}),
        6: RegistryKeyRecord(6, "Explorer", 5, {}),
        7: RegistryKeyRecord(
            7,
            "RecentDocs",
            6,
            {"MRUListEx": 3, "83": 3},
            {
                "MRUListEx": b"\x53\x00\x00\x00\xff\xff\xff\xff",
                "83": "ROCBA-SYSTEM\x00".encode("utf-16-le"),
            },
            "2020-11-16T02:32:19.634820Z",
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = parse_registry_artifacts(hive)
    row = next(row for row in rows if row["value_name"] == "83")

    assert row["transaction_logs_detected"] == "true"
    assert row["transaction_logs_applied"] == "false"
    assert "ntuser.dat.LOG1" in row["transaction_log_paths"]
    assert "transaction logs detected but not applied" in row["notes"]


def test_registry_artifacts_extract_com_applocker_and_wdac_policy(monkeypatch, tmp_path):
    hive = tmp_path / "SOFTWARE"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Classes", 1, {}),
        3: RegistryKeyRecord(3, "CLSID", 2, {}),
        4: RegistryKeyRecord(4, "{11111111-1111-1111-1111-111111111111}", 3, {"": 1, "AppID": 1}),
        5: RegistryKeyRecord(
            5,
            "InprocServer32",
            4,
            {"": 1, "ThreadingModel": 1},
            {
                "": r"C:\Users\Jane\AppData\Roaming\contoso.dll\x00".encode("utf-16-le"),
                "ThreadingModel": "Apartment\x00".encode("utf-16-le"),
            },
        ),
        6: RegistryKeyRecord(6, "Policies", 1, {}),
        7: RegistryKeyRecord(7, "Microsoft", 6, {}),
        8: RegistryKeyRecord(8, "Windows", 7, {}),
        9: RegistryKeyRecord(9, "SrpV2", 8, {"EnforcementMode": 4}, {"EnforcementMode": struct.pack("<I", 1)}),
        10: RegistryKeyRecord(10, "DeviceGuard", 8, {"EnableVirtualizationBasedSecurity": 4}, {"EnableVirtualizationBasedSecurity": struct.pack("<I", 1)}),
        11: RegistryKeyRecord(11, "Microsoft", 1, {}),
        12: RegistryKeyRecord(12, "Windows", 11, {}),
        13: RegistryKeyRecord(13, "CurrentVersion", 12, {}),
        14: RegistryKeyRecord(14, "Explorer", 13, {}),
        15: RegistryKeyRecord(15, "ShellExecuteHooks", 14, {"{11111111-1111-1111-1111-111111111111}": 1}),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = parse_registry_artifacts(hive)
    artifacts = {row["artifact"] for row in rows}

    assert {"com_registration", "com_autostart", "applocker_policy", "wdac_policy"} <= artifacts
    com_server = next(row for row in rows if row["artifact"] == "com_registration" and row["key_path"].endswith("InprocServer32") and row["value_name"] == "(default)")
    assert "contoso.dll" in com_server["value_data"]
    assert com_server["category"] == "software"
    applocker = next(row for row in rows if row["artifact"] == "applocker_policy")
    assert applocker["category"] == "security_policy"
    wdac = next(row for row in rows if row["artifact"] == "wdac_policy")
    assert wdac["value_name"] == "EnableVirtualizationBasedSecurity"


def test_registry_artifacts_extract_network_interfaces_and_cards(monkeypatch, tmp_path):
    system_hive = tmp_path / "SYSTEM"
    system_hive.write_bytes(b"regf-test")
    system_records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Select", 1, {"Current": 4}, {"Current": struct.pack("<I", 1)}),
        3: RegistryKeyRecord(3, "ControlSet001", 1, {}),
        4: RegistryKeyRecord(4, "Services", 3, {}),
        5: RegistryKeyRecord(5, "Tcpip", 4, {}),
        6: RegistryKeyRecord(6, "Parameters", 5, {}),
        7: RegistryKeyRecord(7, "Interfaces", 6, {}),
        8: RegistryKeyRecord(
            8,
            "{11111111-1111-1111-1111-111111111111}",
            7,
            {"DhcpIPAddress": 1, "NameServer": 1},
            {
                "DhcpIPAddress": "192.168.1.50\x00".encode("utf-16-le"),
                "NameServer": "8.8.8.8\x00".encode("utf-16-le"),
            },
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: system_records,
    )

    system_rows = parse_registry_artifacts(system_hive)
    interface = next(row for row in system_rows if row["artifact"] == "network_interfaces")

    assert interface["category"] == "network"
    assert interface["key_path"].endswith("Tcpip/Parameters/Interfaces/{11111111-1111-1111-1111-111111111111}")
    assert interface["value_name"] == "DhcpIPAddress"
    assert interface["value_data"] == "192.168.1.50"

    software_hive = tmp_path / "SOFTWARE"
    software_hive.write_bytes(b"regf-test")
    software_records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Microsoft", 1, {}),
        3: RegistryKeyRecord(3, "Windows NT", 2, {}),
        4: RegistryKeyRecord(4, "CurrentVersion", 3, {}),
        5: RegistryKeyRecord(5, "NetworkCards", 4, {}),
        6: RegistryKeyRecord(
            6,
            "1",
            5,
            {"Description": 1, "ServiceName": 1},
            {
                "Description": "Intel(R) Ethernet Connection\x00".encode("utf-16-le"),
                "ServiceName": "{11111111-1111-1111-1111-111111111111}\x00".encode("utf-16-le"),
            },
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: software_records,
    )

    software_rows = parse_registry_artifacts(software_hive)
    card = next(row for row in software_rows if row["artifact"] == "network_cards")

    assert card["category"] == "network"
    assert card["key_path"].endswith("Windows NT/CurrentVersion/NetworkCards/1")
    assert card["value_name"] == "Description"
    assert card["value_data"] == "Intel(R) Ethernet Connection"


def test_ras_connection_manager_rules_do_not_match_character_sequences(monkeypatch, tmp_path):
    hive = tmp_path / "SOFTWARE"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Microsoft", 1, {}),
        3: RegistryKeyRecord(3, "Office", 2, {}),
        4: RegistryKeyRecord(4, "ClickToRun", 3, {}),
        5: RegistryKeyRecord(5, "REGISTRY", 4, {}),
        6: RegistryKeyRecord(6, "MACHINE", 5, {}),
        7: RegistryKeyRecord(7, "Software", 6, {}),
        8: RegistryKeyRecord(8, "Microsoft", 7, {}),
        9: RegistryKeyRecord(9, "Exchange", 8, {}),
        10: RegistryKeyRecord(10, "Client", 9, {}),
        11: RegistryKeyRecord(11, "Mac File Types", 10, {"EPSF": 1}, {"EPSF": ".eps\x00".encode("utf-16-le")}),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = parse_registry_artifacts(hive)

    assert [row for row in rows if row["artifact"] == "ras_connection_manager"] == []


def test_office_recent_docs_does_not_treat_profile_as_file_value(monkeypatch, tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "SOFTWARE", 1, {}),
        3: RegistryKeyRecord(3, "Microsoft", 2, {}),
        4: RegistryKeyRecord(4, "Office", 3, {}),
        5: RegistryKeyRecord(5, "16.0", 4, {}),
        6: RegistryKeyRecord(6, "Common", 5, {}),
        7: RegistryKeyRecord(
            7,
            "Recent",
            6,
            {"Profile": 1, "FilePath": 1},
            {
                "Profile": "{00000000-0000-0000-0000-000000000000}\x00".encode("utf-16-le"),
                "FilePath": "C:\\Users\\fredr\\Documents\\report.docx\x00".encode("utf-16-le"),
            },
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "office_recent_docs"]

    assert [row["value_name"] for row in rows] == ["FilePath"]
    assert rows[0]["value_data"] == "C:\\Users\\fredr\\Documents\\report.docx"


def test_registry_artifacts_extract_sam_cloud_account_details_without_full_user_blob(monkeypatch, tmp_path):
    hive = tmp_path / "SAM"
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Domains", 1, {}),
        3: RegistryKeyRecord(3, "Account", 2, {}),
        4: RegistryKeyRecord(4, "Users", 3, {}),
        5: RegistryKeyRecord(
            5,
            "000003E8",
            4,
            {"F": 3, "V": 3, "InternetUserName": 1, "InternetProviderName": 1},
            {
                "F": b"\x00" * 128,
                "V": b"\x01" * 128,
                "InternetUserName": "devon@example.com\x00".encode("utf-16-le"),
                "InternetProviderName": "MicrosoftAccount\x00".encode("utf-16-le"),
            },
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["artifact"] == "cloud_account_details"]

    assert {row["value_name"] for row in rows} == {"InternetUserName", "InternetProviderName"}
    assert all(row["category"] == "account" for row in rows)
    assert next(row for row in rows if row["value_name"] == "InternetUserName")["value_data"] == "devon@example.com"


def test_registry_artifacts_extract_cloud_storage_configuration(monkeypatch, tmp_path):
    hive = tmp_path / "Users" / "Jane" / "NTUSER.DAT"
    hive.parent.mkdir(parents=True)
    hive.write_bytes(b"regf-test")
    records = {
        1: RegistryKeyRecord(1, "ROOT", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Software", 1, {}),
        3: RegistryKeyRecord(3, "Microsoft", 2, {}),
        4: RegistryKeyRecord(4, "OneDrive", 3, {}),
        5: RegistryKeyRecord(5, "Accounts", 4, {}),
        6: RegistryKeyRecord(
            6,
            "Business1",
            5,
            {"UserEmail": 1, "UserFolder": 1, "SPOResourceID": 1, "Noise": 1},
            {
                "UserEmail": "jane@example.com\x00".encode("utf-16-le"),
                "UserFolder": "C:\\Users\\Jane\\OneDrive - Example\x00".encode("utf-16-le"),
                "SPOResourceID": "example.sharepoint.com,site-guid,web-guid\x00".encode("utf-16-le"),
                "Noise": "ignore me\x00".encode("utf-16-le"),
            },
        ),
        7: RegistryKeyRecord(7, "SyncEngines", 3, {}),
        8: RegistryKeyRecord(8, "Providers", 7, {}),
        9: RegistryKeyRecord(9, "OneDrive", 8, {}),
        10: RegistryKeyRecord(
            10,
            "tenant-item",
            9,
            {"MountPoint": 1, "UrlNamespace": 1, "CID": 1},
            {
                "MountPoint": "C:\\Users\\Jane\\Example Shared\x00".encode("utf-16-le"),
                "UrlNamespace": "https://example.sharepoint.com/sites/Finance\x00".encode("utf-16-le"),
                "CID": "abc123\x00".encode("utf-16-le"),
            },
        ),
    }
    monkeypatch.setattr(
        "forensic_orchestrator.tools.registry_artifacts.scan_registry_keys",
        lambda _data: records,
    )

    rows = [row for row in parse_registry_artifacts(hive) if row["category"] == "cloud"]

    assert {row["artifact"] for row in rows} == {"cloud_onedrive_account", "cloud_onedrive_sync_engine"}
    assert {row["value_name"] for row in rows} == {
        "UserEmail",
        "UserFolder",
        "SPOResourceID",
        "MountPoint",
        "UrlNamespace",
        "CID",
    }
    assert next(row for row in rows if row["value_name"] == "UrlNamespace")["value_data"] == "https://example.sharepoint.com/sites/Finance"
    assert all(row["user_profile"] == "Jane" for row in rows)


def _userassist_v5_bytes(*, run_counter: int, focus_count: int, focus_time_ms: int) -> bytes:
    data = bytearray(72)
    struct.pack_into("<I", data, 4, run_counter)
    struct.pack_into("<I", data, 8, focus_count)
    struct.pack_into("<I", data, 12, focus_time_ms)
    timestamp = datetime(2020, 11, 14, 13, 45, 45, tzinfo=timezone.utc)
    filetime = int((timestamp - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    struct.pack_into("<Q", data, 60, filetime)
    return bytes(data)
