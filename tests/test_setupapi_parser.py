from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.reports import device_inventory_report, external_storage_report
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.setupapi import parse_setupapi_logs_to_csv


def test_setupapi_parser_extracts_usb_storage_section(tmp_path):
    source = tmp_path / "Windows" / "INF"
    source.mkdir(parents=True)
    log = source / "setupapi.dev.log"
    log.write_text(
        ">>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5581\\4C530001230101115192]\n"
        ">>>  Section start 2020/11/14 04:34:56.426\n"
        "     dvi:      Service = USBSTOR\n"
        "     inf:      Opened PNF: 'C:\\Windows\\INF\\usbstor.inf'\n"
        "<<<  Section end 2020/11/14 04:34:58.000\n"
        "<<<  [Exit status: SUCCESS]\n",
        encoding="utf-8",
    )

    csv_path = parse_setupapi_logs_to_csv(source, tmp_path / "out")
    text = csv_path.read_text(encoding="utf-8")

    assert "device_install" in text
    assert "VID_0781&PID_5581" in text
    assert "4C530001230101115192" in text
    assert "USBSTOR" in text


def test_setupapi_ingest_surfaces_in_device_reports(tmp_path):
    source = tmp_path / "Windows" / "INF"
    source.mkdir(parents=True)
    (source / "setupapi.dev.log").write_text(
        ">>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5581\\4C530001230101115192]\n"
        ">>>  Section start 2020/11/14 04:34:56.426\n"
        "     dvi:      Service = USBSTOR\n"
        "<<<  Section end 2020/11/14 04:34:58.000\n"
        "<<<  [Exit status: SUCCESS]\n",
        encoding="utf-8",
    )
    csv_path = parse_setupapi_logs_to_csv(source, tmp_path / "out")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-setupapi",
        tool_name="SetupApiParser",
        path=csv_path,
    )

    inventory = device_inventory_report(db, case.id)
    storage = external_storage_report(db, case.id)
    assert count == 1
    assert inventory["devices"][0]["serial"] == "4C530001230101115192"
    assert storage["summary"]["setupapi_observation_count"] == 1
    assert storage["timeline"][0]["source_artifact_type"] == "setupapi.dev.log"
