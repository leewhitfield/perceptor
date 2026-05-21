import csv

from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.windows_error_reporting import parse_windows_error_reporting_to_csv


def test_windows_error_reporting_parser_extracts_report_fields(tmp_path):
    report_dir = tmp_path / "ReportArchive" / "AppCrash_App_123"
    report_dir.mkdir(parents=True)
    report = report_dir / "Report.wer"
    report.write_text(
        "\n".join(
            [
                "Version=1",
                "EventType=APPCRASH",
                "EventTime=132487425816053483",
                "UploadTime=132487428864325529",
                "ReportIdentifier=2bf5e85c-7581-4102-ba48-7f8b240d479d",
                "NsAppName=Example.exe",
                "OriginalFilename=Example.exe",
                "Sig[0].Name=Application Name",
                "Sig[0].Value=Example.exe",
                "Sig[3].Name=Fault Module Name",
                "Sig[3].Value=bad.dll",
                "Sig[6].Name=Exception Code",
                "Sig[6].Value=c0000005",
                r"UI[2]=C:\Program Files\Example\Example.exe",
                r"LoadedModule[0]=C:\Windows\System32\kernel32.dll",
            ]
        ),
        encoding="utf-16-le",
    )

    csv_path = parse_windows_error_reporting_to_csv(tmp_path, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))

    assert len(rows) == 1
    assert rows[0]["event_type"] == "APPCRASH"
    assert rows[0]["event_time_utc"] == "2020-11-01T22:16:21.605348+00:00"
    assert rows[0]["app_name"] == "Example.exe"
    assert rows[0]["fault_module_name"] == "bad.dll"
    assert rows[0]["exception_code"] == "c0000005"
    assert rows[0]["ui_path"] == r"C:\Program Files\Example\Example.exe"


def test_windows_error_reporting_ingest_populates_table_and_timeline(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id=computer.id)
    csv_path = tmp_path / "WindowsErrorReporting.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "source_file", "source_name", "report_folder", "event_type",
                "event_time_utc", "upload_time_utc", "report_type", "consent",
                "report_status", "report_identifier", "integrator_report_identifier",
                "app_name", "original_filename", "target_app_id", "target_app_version",
                "fault_module_name", "fault_module_version", "exception_code",
                "exception_offset", "is_fatal", "bucket_id", "legacy_bucket_id",
                "ui_path", "loaded_modules_json", "signatures_json",
                "dynamic_signatures_json", "ui_json", "raw_json",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "source_file": "/WER/Report.wer",
                "source_name": "Report.wer",
                "report_folder": "AppCrash_App_123",
                "event_type": "APPCRASH",
                "event_time_utc": "2020-10-31T15:36:21.605348+00:00",
                "app_name": "Example.exe",
                "fault_module_name": "bad.dll",
                "exception_code": "c0000005",
                "raw_json": "{}",
            }
        )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-wer",
        tool_name="WindowsErrorReportingParser",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM windows_error_reports").fetchone()
    event = db.conn.execute("SELECT * FROM timeline_events").fetchone()
    assert row_count == 1
    assert row["app_name"] == "Example.exe"
    assert event["source_table"] == "windows_error_reports"
    assert event["event_type"] == "windows_error_report"
