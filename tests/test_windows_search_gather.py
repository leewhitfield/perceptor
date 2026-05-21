import csv

from forensic_orchestrator.db import Database
from forensic_orchestrator.timeline import timeline_events_from_rows
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.windows_search_gather import parse_windows_search_gather_logs_to_csv


def test_windows_search_gather_parser_decodes_filetime_and_path(tmp_path):
    source = tmp_path / "SystemIndex.26.gthr"
    source.write_text(
        "859fa4a4\t1d6bb2b\tfile:C:/Users/fredr/Downloads/test.tmp\t8000000c\t0\t80041201\t\t8\t4294967295\t8640\r\n",
        encoding="utf-16-le",
    )

    csv_path = parse_windows_search_gather_logs_to_csv(tmp_path, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))

    assert rows[0]["timestamp_utc"] == "2020-11-15T08:44:25.382826+00:00"
    assert rows[0]["item_path"] == r"C:\Users\fredr\Downloads\test.tmp"
    assert rows[0]["item_scheme"] == "file"
    assert rows[0]["is_deleted_path"] == "false"


def test_windows_search_gather_ingest_populates_table_and_timeline(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id=computer.id)
    source = tmp_path / "SystemIndex.26.gthr"
    source.write_text(
        "c195296\t1d6bb2a\tfile:C:/$Extend/$Deleted/000600000005EDFA7E247764/\t8000000c\t0\t80041201\t\t8\t4294967295\t8640\r\n",
        encoding="utf-16-le",
    )
    csv_path = parse_windows_search_gather_logs_to_csv(tmp_path, tmp_path / "out")

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-gather",
        tool_name="WindowsSearchGatherParser",
        path=csv_path,
    )

    row = db.conn.execute("SELECT * FROM windows_search_gather_logs").fetchone()
    event = db.conn.execute("SELECT * FROM timeline_events").fetchone()
    assert row_count == 1
    assert row["is_deleted_path"] == "true"
    assert row["item_path"] == "C:\\$Extend\\$Deleted\\000600000005EDFA7E247764\\"
    assert event["source_table"] == "windows_search_gather_logs"
    assert event["event_type"] == "windows_search_gather"
