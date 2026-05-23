import csv
import struct
from pathlib import Path

from forensic_orchestrator.analytics_query import query_one
from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.onedrive_odl import parse_onedrive_odl_to_csv


def _sample_odl(path: Path) -> None:
    header = b"EBFGONED" + struct.pack("<I", 2)
    one_drive = b"20.169.0823.0008".ljust(0x40, b"\x00")
    windows = b"10.0.19041".ljust(0x40, b"\x00")
    header += struct.pack("<IQI", 1, 0, 1) + one_drive + windows + (b"\x00" * 0x64)
    params = b"download C:\\Users\\fredr\\OneDrive\\Report.docx https://contoso.example/report resource E431499DADA298BA!2594"
    code_file = b"SyncEngine.cpp"
    function = b"Sync::DownloadFile"
    payload = (
        struct.pack("<I", len(code_file))
        + code_file
        + struct.pack("<I", 7)
        + struct.pack("<I", len(function))
        + function
        + params
    )
    block = struct.pack(
        "<IHHQII16sIIII",
        0xFFEEDDCC,
        0,
        0,
        1600000000000,
        0,
        0,
        b"\x00" * 16,
        0,
        0,
        len(payload),
        0,
    )
    path.parent.mkdir(parents=True)
    path.write_bytes(header + block + payload)


def test_onedrive_odl_parser_extracts_core_event_fields(tmp_path):
    source = tmp_path / "Users" / "fredr" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "logs" / "Personal"
    _sample_odl(source / "SyncEngine-2020-11-01.1200.1234.1.odlsent")

    csv_path = parse_onedrive_odl_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))

    assert len(rows) == 1
    assert rows[0]["user_profile"] == "fredr"
    assert rows[0]["account"] == "Personal"
    assert rows[0]["timestamp_utc"] == "2020-09-13T12:26:40+00:00"
    assert rows[0]["code_file"] == "SyncEngine.cpp"
    assert rows[0]["function"] == "Sync::DownloadFile"
    assert rows[0]["event_type"] == "download"
    assert rows[0]["local_path"] == "C:\\Users\\fredr\\OneDrive\\Report.docx"
    assert rows[0]["url"] == "https://contoso.example/report"
    assert rows[0]["resource_id"] == "E431499DADA298BA!2594"


def test_onedrive_odl_parser_preserves_spaces_in_windows_paths(tmp_path):
    source = tmp_path / "Users" / "fredr" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "logs" / "Personal"
    header = b"EBFGONED" + struct.pack("<I", 2)
    one_drive = b"20.169.0823.0008".ljust(0x40, b"\x00")
    windows = b"10.0.19041".ljust(0x40, b"\x00")
    header += struct.pack("<IQI", 1, 0, 1) + one_drive + windows + (b"\x00" * 0x64)
    params = b"C:\\Users\\fredr\\OneDrive\\Documents\\SRL\\SRL VPN Setup.pdf | https://example.test/file"
    code_file = b"StorageProviderUriSource.cpp"
    function = b"GetContentInfoForPathInternal"
    payload = (
        struct.pack("<I", len(code_file))
        + code_file
        + struct.pack("<I", 7)
        + struct.pack("<I", len(function))
        + function
        + params
    )
    block = struct.pack(
        "<IHHQII16sIIII",
        0xFFEEDDCC,
        0,
        0,
        1600000000000,
        0,
        0,
        b"\x00" * 16,
        0,
        0,
        len(payload),
        0,
    )
    source.mkdir(parents=True)
    (source / "FileCoAuth-2020-11-01.1200.1234.1.odl").write_bytes(header + block + payload)

    csv_path = parse_onedrive_odl_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))

    assert rows[0]["local_path"] == "C:\\Users\\fredr\\OneDrive\\Documents\\SRL\\SRL VPN Setup.pdf"


def test_onedrive_odl_parser_applies_obfuscation_map(tmp_path):
    source = tmp_path / "Users" / "srl-h" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "logs" / "Personal"
    source.mkdir(parents=True)
    (source / "ObfuscationStringMap.txt").write_bytes(
        "JokeYakLog\tC\nRodOafGad\tUsers\nPewLeftYew\tsrl-h\nFooDownPal\tOneDrive\n".encode("utf-16le")
    )

    header = b"EBFGONED" + struct.pack("<I", 2)
    one_drive = b"20.169.0823.0008".ljust(0x40, b"\x00")
    windows = b"10.0.19041".ljust(0x40, b"\x00")
    header += struct.pack("<IQI", 1, 0, 1) + one_drive + windows + (b"\x00" * 0x64)
    params = b"hydrate JokeYakLog:\\RodOafGad\\PewLeftYew\\FooDownPal\\Report.docx"
    code_file = b"Hydration.cpp"
    function = b"Hydrate"
    payload = (
        struct.pack("<I", len(code_file))
        + code_file
        + struct.pack("<I", 1)
        + struct.pack("<I", len(function))
        + function
        + params
    )
    block = struct.pack(
        "<IHHQII16sIIII",
        0xFFEEDDCC,
        0,
        0,
        1600000000000,
        0,
        0,
        b"\x00" * 16,
        0,
        0,
        len(payload),
        0,
    )
    (source / "SyncEngine-2020-11-01.1200.1234.1.odl").write_bytes(header + block + payload)

    csv_path = parse_onedrive_odl_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))

    assert rows[0]["local_path"] == "C:\\Users\\srl-h\\OneDrive\\Report.docx"
    assert "JokeYakLog" not in rows[0]["params_text"]


def test_onedrive_odl_ingest_populates_normalized_table(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, Path("/evidence/disk.E01"), computer_id=computer.id)
    source = tmp_path / "Users" / "fredr" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "logs" / "Personal"
    _sample_odl(source / "SyncEngine-2020-11-01.1200.1234.1.odlsent")
    csv_path = parse_onedrive_odl_to_csv(tmp_path / "Users", tmp_path / "out")

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-odl",
        tool_name="OneDriveOdlParser",
        path=csv_path,
    )

    row = query_one(db, "onedrive_log_entries", "SELECT * FROM onedrive_log_entries")
    assert row["event_type"] == "download"
    assert row["local_path"] == "C:\\Users\\fredr\\OneDrive\\Report.docx"
