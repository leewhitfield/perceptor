import csv

from forensic_orchestrator.cli import write_csv_rows
from forensic_orchestrator.report_paths import display_evidence_path, sanitize_report_paths, sanitize_report_text


def test_display_evidence_path_starts_at_drive_root_for_windows_paths():
    assert display_evidence_path(r"C:\Users\Jane\file.docx") == "/Users/Jane/file.docx"
    assert display_evidence_path("D:/Windows/System32/cmd.exe") == "D:/Windows/System32/cmd.exe"


def test_display_evidence_path_handles_file_urls_and_unc_paths():
    assert display_evidence_path("file:///C:/Users/Jane/file%20name.docx") == "/Users/Jane/file name.docx"
    assert display_evidence_path("file://server/share/folder/file.txt") == "//server/share/folder/file.txt"


def test_display_evidence_path_strips_case_artifact_prefixes():
    assert (
        display_evidence_path(
            "/mnt/forensic-ssd/cases/case-1/artifacts/image-1/Windows/System32/config/SOFTWARE"
        )
        == "/Windows/System32/config/SOFTWARE"
    )
    assert (
        display_evidence_path(
            "/mnt/forensic-ssd/cases/case-1/mounts/volumes/p2/Users/Jane/Documents/report.docx"
        )
        == "/Users/Jane/Documents/report.docx"
    )
    assert (
        display_evidence_path(
            "/tmp/forensic-orchestrator-mounts/cases/292bcc9d-e60b-4260-9cae-3078df55889b/volumes/p2/Users/Jane/Documents/report.docx"
        )
        == "/Users/Jane/Documents/report.docx"
    )
    assert (
        display_evidence_path(
            "/mnt/forensic-ssd/cases/case-1/artifacts/image-1/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db"
        )
        == "/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db"
    )


def test_display_evidence_path_strips_uuid_case_prefixes():
    case_path = (
        "/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/"
        "292bcc9d-e60b-4260-9cae-3078df55889b/mounts/volumes/p2/Windows/System32/mstsc.exe"
    )
    assert display_evidence_path(case_path) == "/Windows/System32/mstsc.exe"
    output_path = (
        "/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/"
        "292bcc9d-e60b-4260-9cae-3078df55889b/outputs/run/JLECmd.csv"
    )
    assert display_evidence_path(output_path) == "/outputs/run/JLECmd.csv"
    short_case_path = (
        "cases/292bcc9d-e60b-4260-9cae-3078df55889b/artifacts/"
        "2b1fdb43-1ae6-45c2-9b21-9c920ea784f9/Windows.old/Windows/System32/config/SOFTWARE"
    )
    assert display_evidence_path(short_case_path) == "/Windows.old/Windows/System32/config/SOFTWARE"


def test_sanitize_report_paths_only_touches_path_like_fields():
    report = {
        "source_csv": (
            "/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/"
            "292bcc9d-e60b-4260-9cae-3078df55889b/outputs/run/JLECmd.csv"
        ),
        "file_location": r"C:\Windows\System32\mstsc.exe",
        "description": "C:\\Windows\\System32\\mstsc.exe should stay as prose unless the key is path-like",
    }
    sanitized = sanitize_report_paths(report)
    assert sanitized["source_csv"] == "/outputs/run/JLECmd.csv"
    assert sanitized["file_location"] == "/Windows/System32/mstsc.exe"
    assert sanitized["description"].startswith("C:\\Windows")
    assert sanitize_report_paths({"file_location": r"E:\CaseShare\tool.exe"})["file_location"] == "E:/CaseShare/tool.exe"


def test_sanitize_report_text_strips_case_prefixes_and_drive_letters():
    text = (
        "source `/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/"
        "292bcc9d-e60b-4260-9cae-3078df55889b/outputs/run/JLECmd.csv` "
        "target `C:\\Windows\\System32\\mstsc.exe` alt `D:\\Evidence\\file.txt`"
    )
    assert sanitize_report_text(text) == "source `/outputs/run/JLECmd.csv` target `/Windows/System32/mstsc.exe` alt `D:/Evidence/file.txt`"
    short_text = (
        "file `cases/292bcc9d-e60b-4260-9cae-3078df55889b/artifacts/"
        "2b1fdb43-1ae6-45c2-9b21-9c920ea784f9/Windows.old/Windows/System32/winevt/Logs/App.evtx`"
    )
    assert sanitize_report_text(short_text) == "file `/Windows.old/Windows/System32/winevt/Logs/App.evtx`"


def test_write_csv_rows_uses_union_schema_for_mixed_report_sections(tmp_path):
    output = tmp_path / "mixed.csv"

    write_csv_rows(
        [
            {"section": "device", "serial": "USB1"},
            {"section": "timeline", "timestamp": "2020-01-01T00:00:00Z", "event_type": "usb_arrival"},
        ],
        str(output),
    )

    with output.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert rows[0]["serial"] == "USB1"
    assert rows[0]["timestamp"] == ""
    assert rows[1]["serial"] == ""
    assert rows[1]["timestamp"] == "2020-01-01T00:00:00Z"
    assert rows[1]["event_type"] == "usb_arrival"
