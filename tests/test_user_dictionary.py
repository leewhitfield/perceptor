import csv
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.reports import user_dictionaries_report
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.user_dictionary import parse_user_dictionaries_to_csv


def test_user_dictionary_parser_and_ingest(tmp_path):
    source = (
        tmp_path
        / "Users"
        / "Jane"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Office"
        / "16.0"
        / "123456"
        / "Proofing"
    )
    source.mkdir(parents=True)
    dictionary = source / "RoamingCustom.dic"
    dictionary.write_text("AcmeTerm\n# comment\nForensicWord\nAcmeTerm\n", encoding="utf-8")

    csv_path = parse_user_dictionaries_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))

    assert [row["word"] for row in rows] == ["AcmeTerm", "ForensicWord"]
    assert rows[0]["user_profile"] == "Jane"
    assert rows[0]["office_version"] == "16.0"
    assert rows[0]["proofing_id"] == "123456"

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
            "tool_name": "UserDictionaryParser",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 2,
        }
    )
    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id=output_id,
        tool_name="UserDictionaryParser",
        path=csv_path,
    )

    report = user_dictionaries_report(db, case.id, user="Jane")
    assert [row["word"] for row in report["user_dictionary_words"]] == ["AcmeTerm", "ForensicWord"]


def test_user_dictionary_parser_skips_walk_errors(tmp_path, monkeypatch):
    source = tmp_path / "Users"
    dictionary_dir = source / "Jane" / "AppData" / "Roaming" / "Microsoft" / "Office" / "16.0" / "123456" / "Proofing"
    dictionary_dir.mkdir(parents=True)
    dictionary = dictionary_dir / "RoamingCustom.dic"
    dictionary.write_text("AcmeTerm\n", encoding="utf-8")

    def fake_walk(root, onerror=None):
        if onerror is not None:
            onerror(OSError("mounted path unreadable"))
        yield str(dictionary_dir), [], [dictionary.name]

    monkeypatch.setattr("forensic_orchestrator.tools.user_dictionary.os.walk", fake_walk)

    csv_path = parse_user_dictionaries_to_csv(source, tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))

    assert [row["word"] for row in rows] == ["AcmeTerm"]
