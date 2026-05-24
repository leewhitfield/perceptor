import sqlite3
import uuid

from forensic_orchestrator.analytics_query import query_one
from forensic_orchestrator.db import Database
from forensic_orchestrator.reports import windows_search_combined_markdown, windows_search_combined_report
from forensic_orchestrator.tools.windows_search_memory import parse_windows_search_memory_carves


def test_windows_search_memory_carve_parser_imports_schema_and_rows(tmp_path):
    db_path = tmp_path / "carves" / "vmem_carve_01_000000001234abcd.sqlite"
    db_path.parent.mkdir()
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE SecurityDescriptor(Id INTEGER PRIMARY KEY, Value TEXT NOT NULL)")
    conn.execute("INSERT INTO SecurityDescriptor(Value) VALUES (?)", ("S-1-5-18",))
    conn.commit()
    conn.close()

    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "memory.dmp", computer_id=computer.id)
    output_id = str(uuid.uuid4())
    output_path = tmp_path / "WindowsSearchMemoryCarveParser.json"
    output_path.write_text("{}", encoding="utf-8")
    db.insert_tool_output(
        {
            "id": output_id,
            "case_id": case.id,
            "computer_id": computer.id,
            "image_id": image.id,
            "job_id": None,
            "tool_name": "WindowsSearchMemoryCarveParser",
            "output_type": "json",
            "path": output_path,
            "row_count": 0,
        }
    )

    parsed = parse_windows_search_memory_carves(
        db_path.parent,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id=output_id,
        source_csv=output_path,
    )
    db.insert_windows_search_memory_carves(parsed["carves"])
    db.insert_windows_search_memory_objects(parsed["objects"])
    db.insert_windows_search_memory_rows(parsed["rows"])

    carve = query_one(db, "windows_search_memory_carves", "SELECT * FROM windows_search_memory_carves")
    obj = query_one(db, "windows_search_memory_objects", "SELECT * FROM windows_search_memory_objects")
    row = query_one(db, "windows_search_memory_rows", "SELECT * FROM windows_search_memory_rows")
    assert carve["parser_status"] == "parsed"
    assert carve["virtual_address"] == "0x000000001234abcd"
    assert obj["object_name"] == "SecurityDescriptor"
    assert row["table_name"] == "SecurityDescriptor"
    assert "S-1-5-18" in row["row_text"]


def test_windows_search_combined_report_includes_disk_and_memory_rows(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "disk.E01", computer_id=computer.id)
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": computer.id,
            "image_id": image.id,
            "job_id": None,
            "tool_name": "WindowsSearchGatherParser",
            "output_type": "csv",
            "path": tmp_path / "gather.csv",
            "row_count": 1,
        }
    )
    db.insert_windows_search_gather_logs(
        [
            {
                "id": "gather-1",
                "case_id": case.id,
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "output-1",
                "tool_name": "WindowsSearchGatherParser",
                "source_csv": tmp_path / "gather.csv",
                "row_number": 1,
                "source_file": "SystemIndex.1.Crwl",
                "source_name": "SystemIndex.1.Crwl",
                "log_type": "crwl",
                "line_number": 1,
                "timestamp_utc": "2025-01-01T00:00:00+00:00",
                "item_url": "file:C:/Users/Maya/Documents/report.docx",
                "item_path": r"C:\Users\Maya\Documents\report.docx",
                "item_scheme": "file",
                "is_deleted_path": "false",
                "raw_fields_json": "[]",
            }
        ]
    )
    db.insert_windows_search_memory_carves(
        [
            {
                "id": "carve-1",
                "case_id": case.id,
                "computer_id": computer.id,
                "image_id": image.id,
                "tool_output_id": "output-1",
                "tool_name": "WindowsSearchMemoryCarveParser",
                "source_csv": tmp_path / "memory.json",
                "row_number": 1,
                "carve_path": "/scratch/vmem_carve.sqlite",
                "carve_name": "vmem_carve.sqlite",
                "detected_format": "sqlite",
                "parser_status": "schema_only",
                "table_count": "1",
                "object_count": "2",
                "extractable_row_count": "0",
            }
        ]
    )

    report = windows_search_combined_report(db, case.id, limit=10)
    markdown = windows_search_combined_markdown(report)

    assert report["summary"]["windows_search_gather_logs"] == 1
    assert report["summary"]["windows_search_memory_carves"] == 1
    assert any(row["source"] == "disk_gather_log" for row in report["combined_artifacts"])
    assert any(row["source"] == "memory_carve" for row in report["combined_artifacts"])
    assert "Combined Windows Search Artifacts" in markdown
