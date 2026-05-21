import csv

from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.windows_defender import parse_windows_defender_artifacts_to_csv


def test_windows_defender_parser_extracts_log_events_and_inventory(tmp_path):
    defender = tmp_path / "Windows Defender"
    support = defender / "Support"
    scans = defender / "Scans"
    support.mkdir(parents=True)
    scans.mkdir()
    (support / "MPDetection-20201020-091428.log").write_text(
        "2020-10-20T16:38:07.899Z Service started - Microsoft Defender Antivirus\r\n"
        "2020-10-20T16:38:11.767Z Version: Product 4.18 Engine 1.1 AV 1.325\r\n"
        r"2020-10-20T16:40:00.000Z [Mini-filter] First scan on a volume: \Device\HarddiskVolume3\Users\Jean\file.docx"
        "\r\n",
        encoding="utf-16-le",
    )
    (scans / "mpcache-abc.bin").write_bytes(b"C:\\Users\\Jean\\Downloads\\sample.exe\x00")

    csv_path = parse_windows_defender_artifacts_to_csv(defender, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))

    assert any(row["event_type"] == "defender_service_started" for row in rows)
    assert any(row["event_type"] == "defender_update" for row in rows)
    scan = next(row for row in rows if row["event_type"] == "defender_scan")
    assert scan["component"] == "Mini-filter"
    assert scan["path"] == r"\Device\HarddiskVolume3\Users\Jean\file.docx"
    inventory = next(row for row in rows if row["artifact_type"] == "mpcache")
    assert inventory["event_type"] == "artifact_inventory"
    assert inventory["sha256_first_mb"]


def test_windows_defender_ingest_populates_table_and_timeline(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id=computer.id)
    csv_path = tmp_path / "WindowsDefenderEvents.csv"
    fields = [
        "source_file", "source_name", "artifact_type", "line_number",
        "event_time_utc", "event_type", "component", "severity",
        "threat_name", "action", "path", "resource", "message",
        "file_size", "modified_time_utc", "sha256_first_mb", "raw_json",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "source_file": "/Defender/MPDetection.log",
                "source_name": "MPDetection.log",
                "artifact_type": "detection_log",
                "line_number": "1",
                "event_time_utc": "2020-10-20T16:38:07.899+00:00",
                "event_type": "defender_service_started",
                "severity": "info",
                "message": "Service started - Microsoft Defender Antivirus",
                "raw_json": "{}",
            }
        )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-defender",
        tool_name="WindowsDefenderParser",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM windows_defender_events").fetchone()
    event = db.conn.execute("SELECT * FROM timeline_events").fetchone()
    assert row_count == 1
    assert row["event_type"] == "defender_service_started"
    assert event["source_table"] == "windows_defender_events"
    assert event["event_type"] == "defender_service_started"
