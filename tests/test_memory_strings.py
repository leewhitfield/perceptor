from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.memory_strings import assess_hiberfil_source, scan_memory_strings_to_csv


def test_memory_string_scanner_records_targeted_hits(tmp_path):
    source = tmp_path / "pagefile.sys"
    source.write_bytes(b"\x00random C:\\Users\\fred\\Desktop\\secret.txt token=abc123 sharepoint\x00")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, source, computer_id="computer-1")
    csv_path, metadata = scan_memory_strings_to_csv(source, tmp_path / "out", min_length=6)
    db.insert_tool_output(
        {
            "id": "output-1",
            "case_id": case.id,
            "computer_id": "computer-1",
            "image_id": "image-1",
            "job_id": None,
            "tool_name": "MemoryStringScanner",
            "output_type": "csv",
            "path": csv_path,
            "row_count": 1,
        }
    )

    imported = ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="output-1",
        tool_name="MemoryStringScanner",
        path=csv_path,
    )

    assert imported >= 1
    assert metadata["scanner"] in {"strings", "bstrings"}
    conn = db.analytics._connect(case.id)
    rows = conn.execute("SELECT hit_category, matched_term, source_artifact_type FROM memory_string_hits").fetchall()
    assert ("credentials", "token", "pagefile") in [tuple(row) for row in rows]


def test_hiberfil_zeroed_source_is_recorded_without_scanning_payload(tmp_path):
    source = tmp_path / "hiberfil.sys"
    source.write_bytes(b"\x00" * 8192)

    csv_path, metadata = scan_memory_strings_to_csv(source, tmp_path / "out", min_length=6)

    assert metadata["hiberfil_status"] == "zeroed_or_inactive"
    assert metadata["decompress_status"] in {"decompressor_unavailable_or_failed", "not_applicable"}
    assert csv_path.read_text(encoding="utf-8").count("\n") == 1


def test_hiberfil_assessment_detects_active_signature(tmp_path):
    source = tmp_path / "hiberfil.sys"
    source.write_bytes(b"HIBR" + b"\x00" * 8188)

    status, note = assess_hiberfil_source(source)

    assert status == "active_hibernation_header"
    assert "recognized" in note
