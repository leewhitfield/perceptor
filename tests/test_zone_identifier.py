import csv
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.reports import downloaded_files_report
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.zone_identifier import parse_zone_identifier_ads_to_csv


def test_zone_identifier_parser_and_ingest(tmp_path):
    downloads = tmp_path / "Users" / "Jane" / "Downloads"
    downloads.mkdir(parents=True)
    ads = downloads / "report.docx:Zone.Identifier"
    ads.write_text(
        "[ZoneTransfer]\n"
        "ZoneId=3\n"
        "ReferrerUrl=https://example.com/start\n"
        "HostUrl=https://cdn.example.com/files/report.docx\n",
        encoding="utf-8",
    )

    csv_path = parse_zone_identifier_ads_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))

    assert len(rows) == 1
    assert rows[0]["user_profile"] == "Jane"
    assert rows[0]["zone_id"] == "3"
    assert rows[0]["classification"] == "downloaded_file"
    assert rows[0]["file_path"].endswith("Users/Jane/Downloads/report.docx")
    assert rows[0]["referrer_host"] == "example.com"
    assert rows[0]["host"] == "cdn.example.com"

    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/disk.E01"), computer_id="computer-1")
    output_id = db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": "job-1",
            "tool_name": "ZoneIdentifierParser",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 1,
        }
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id=output_id,
        tool_name="ZoneIdentifierParser",
        path=csv_path,
    )

    report = downloaded_files_report(db, case.id, user="Jane")
    assert report["downloaded_files"][0]["file_path"].endswith("Users/Jane/Downloads/report.docx")
    assert report["downloaded_files"][0]["host_url"] == "https://cdn.example.com/files/report.docx"
    assert report["summary"]["top_hosts"][0]["host"] == "cdn.example.com"


def test_zone_identifier_parser_skips_walk_errors(tmp_path, monkeypatch):
    downloads = tmp_path / "Users" / "Jane" / "Downloads"
    downloads.mkdir(parents=True)
    ads = downloads / "report.docx:Zone.Identifier"
    ads.write_text("[ZoneTransfer]\nZoneId=3\n", encoding="utf-8")

    def fake_walk(root, onerror=None):
        if onerror is not None:
            onerror(OSError("mounted path unreadable"))
        yield str(downloads), [], [ads.name]

    monkeypatch.setattr("forensic_orchestrator.tools.zone_identifier.os.walk", fake_walk)

    csv_path = parse_zone_identifier_ads_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))

    assert len(rows) == 1
    assert rows[0]["zone_id"] == "3"
