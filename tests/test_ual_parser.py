import csv
from pathlib import Path

from forensic_orchestrator.analytics_query import query_one
from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.ual import parse_ual_artifacts_to_csv


def test_internal_ual_parser_exports_structured_rows(monkeypatch, tmp_path):
    sum_dir = tmp_path / "Windows" / "System32" / "LogFiles" / "SUM"
    sum_dir.mkdir(parents=True)
    (sum_dir / "Current.mdb").write_bytes(b"dummy")

    def fake_run(command, stdout, stderr, text, check):
        export_dir = tmp_path / "out" / "_esedbexport" / "Current.mdb.export"
        export_dir.mkdir(parents=True)
        (export_dir / "CLIENTS.4").write_text(
            "AutoIncId\tRoleName\tUserName\tClientName\tClientIp\tFirstAccess\tLastAccess\tTotalAccesses\n"
            "1\tFile Server\tfredr\tWORKSTATION01\t10.0.0.5\tOct 20, 2020 17:06:59.231231\tOct 21, 2020 18:00:00\t42\n",
            encoding="utf-8",
        )
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr("forensic_orchestrator.tools.ual.shutil.which", lambda name: None)
    monkeypatch.setattr("forensic_orchestrator.tools.ual.subprocess.run", fake_run)

    csv_path = parse_ual_artifacts_to_csv(sum_dir, tmp_path / "out")

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["database_file"] == "Current.mdb"
    assert rows[0]["role_name"] == "File Server"
    assert rows[0]["user_name"] == "fredr"
    assert rows[0]["client_name"] == "WORKSTATION01"
    assert rows[0]["client_ip"] == "10.0.0.5"
    assert rows[0]["first_seen"] == "2020-10-20T17:06:59.231231Z"
    assert rows[0]["access_count"] == "42"


def test_ual_parser_prefers_external_ual_timeliner(monkeypatch, tmp_path):
    sum_dir = tmp_path / "Windows" / "System32" / "LogFiles" / "SUM"
    sum_dir.mkdir(parents=True)
    (sum_dir / "Current.mdb").write_bytes(b"dummy")

    def fake_which(name):
        return "ual-timeliner" if name == "ual-timeliner" else None

    def fake_run(command, stdout, stderr, text, check):
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            "timestamp,timestamp_desc,source_table,authenticated_user,ip_address,host_name,user,"
            "access_count,total_accesses,role_name,role_guid,tenant_id,client_name,source_file\n"
            "2020-10-20T17:06:59Z,InsertDate,CLIENTS,LAB\\\\fredr,10.0.0.5,WORKSTATION01,fredr,"
            "1,42,File Server,{10A9226F-50EE-49D8-A393-9A501D47CE04},,WORKSTATION01,"
            f"{sum_dir / 'Current.mdb'}\n"
            "2020-10-21T00:00:00Z,Day295,CLIENTS,LAB\\\\fredr,10.0.0.5,WORKSTATION01,fredr,"
            "3,42,File Server,{10A9226F-50EE-49D8-A393-9A501D47CE04},,WORKSTATION01,"
            f"{sum_dir / 'Current.mdb'}\n",
            encoding="utf-8",
        )
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr("forensic_orchestrator.tools.ual.shutil.which", fake_which)
    monkeypatch.setattr("forensic_orchestrator.tools.ual.subprocess.run", fake_run)

    csv_path = parse_ual_artifacts_to_csv(sum_dir, tmp_path / "out")

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["database_file"] == "Current.mdb"
    assert rows[0]["insert_date"] == "2020-10-20T17:06:59Z"
    assert rows[0]["role_name"] == "File Server"
    assert rows[0]["client_ip"] == "10.0.0.5"
    assert rows[1]["raw_time_bucket"] == "Day295"
    assert rows[1]["insert_date"] == "2020-10-21T00:00:00Z"
    assert rows[1]["day_count"] == "3"


def test_ual_parser_falls_back_when_external_ual_timeliner_fails(monkeypatch, tmp_path):
    sum_dir = tmp_path / "Windows" / "System32" / "LogFiles" / "SUM"
    sum_dir.mkdir(parents=True)
    (sum_dir / "Current.mdb").write_bytes(b"dummy")
    calls = []

    def fake_which(name):
        return "ual-timeliner" if name == "ual-timeliner" else None

    def fake_run(command, stdout, stderr, text, check):
        calls.append(command)
        if "ual-timeliner" in command[0]:
            return type("Result", (), {"returncode": 2, "stderr": "bad db"})()
        export_dir = tmp_path / "out" / "_esedbexport" / "Current.mdb.export"
        export_dir.mkdir(parents=True)
        (export_dir / "CLIENTS.4").write_text(
            "AutoIncId\tRoleName\tUserName\tClientIp\tInsertDate\n"
            "1\tFile Server\tfredr\t10.0.0.5\t2020-10-20T17:06:59Z\n",
            encoding="utf-8",
        )
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr("forensic_orchestrator.tools.ual.shutil.which", fake_which)
    monkeypatch.setattr("forensic_orchestrator.tools.ual.subprocess.run", fake_run)

    csv_path = parse_ual_artifacts_to_csv(sum_dir, tmp_path / "out")

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["role_name"] == "File Server"
    assert any("ual-timeliner" in call[0] for call in calls)
    assert any("esedbexport" in call[0] for call in calls)


def test_ual_parser_rows_are_ingested(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Server")
    db.add_image("image-1", case.id, Path("/evidence/server.E01"), computer_id="computer-1")
    csv_path = tmp_path / "UalRecords.csv"
    csv_path.write_text(
        "database_file,source_table,record_id,role_guid,role_name,product_name,tenant_id,"
        "user_sid,user_name,client_name,client_ip,client_id,first_seen,last_seen,insert_date,"
        "last_access,access_count,activity_count,day_count,raw_time_bucket\n"
        "Current.mdb,CLIENTS.4,1,,File Server,,,"
        "S-1-5-21-1,fredr,WORKSTATION01,10.0.0.5,,2020-10-20T17:06:59Z,"
        "2020-10-21T18:00:00Z,,,42,,,\n",
        encoding="utf-8",
    )

    row_count = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-ual",
        tool_name="UalParser",
        path=csv_path,
    )

    assert row_count == 1
    row = query_one(db, "ual_records", "SELECT * FROM ual_records")
    assert row["role_name"] == "File Server"
    assert row["client_ip"] == "10.0.0.5"
    assert row["access_count"] == "42"
