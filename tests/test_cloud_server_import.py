from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.cloud_server_import import import_cloud_server_logs_to_csv
from forensic_orchestrator.tools.ingest import ingest_csv_output


def test_cloud_server_log_import_normalizes_csv_to_duckdb(tmp_path):
    source = tmp_path / "ual.csv"
    source.write_text(
        "CreationTime,Workload,Operation,UserId,ClientIP,ObjectId,ResultStatus\n"
        "2020-11-14T01:02:03Z,SharePoint,FileDownloaded,fred@example.com,1.2.3.4,/Shared/report.docx,Succeeded\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="cloud-1", case_id=case.id, label="Cloud")
    db.add_image("image-1", case.id, source, computer_id="cloud-1")
    csv_path = import_cloud_server_logs_to_csv(source, tmp_path / "out", provider="Microsoft 365")
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "cloud-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "CloudServerLogImporter",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 1,
        }
    )

    assert ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="cloud-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="CloudServerLogImporter",
        path=csv_path,
    ) == 1

    conn = db.analytics._connect(case.id)
    row = conn.execute("SELECT provider, service, operation, actor, actor_ip, target, result FROM cloud_server_events").fetchone()
    assert tuple(row) == ("Microsoft 365", "SharePoint", "FileDownloaded", "fred@example.com", "1.2.3.4", "/Shared/report.docx", "Succeeded")
