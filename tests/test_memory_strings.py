from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.memory_strings import assess_hiberfil_source, memory_artifact_type, scan_memory_strings_to_csv
from forensic_orchestrator.timeline import timeline_events_from_rows


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


def test_memory_artifact_type_classifies_crash_and_process_dumps(tmp_path):
    assert memory_artifact_type(tmp_path / "Windows" / "MEMORY.DMP") == "crash_dump"
    assert memory_artifact_type(tmp_path / "Users" / "Maya" / "AppData" / "Local" / "CrashDumps" / "app.dmp") == "crash_dump"
    assert memory_artifact_type(tmp_path / "lsass.dmp") == "process_dump"
    assert memory_artifact_type(tmp_path / "sample.vmem") == "full_memory_dump"


def test_memory_string_hits_emit_lead_timeline_events():
    row = {
        "id": "mem-1",
        "case_id": "case-1",
        "computer_id": "computer-1",
        "image_id": "image-1",
        "tool_output_id": "output-1",
        "tool_name": "MemoryStringScanner",
        "source_artifact_type": "pagefile",
        "source_path": "/pagefile.sys",
        "scanned_path": "/pagefile.sys",
        "hit_category": "credentials",
        "matched_term": "token",
        "string_sha256": "sha1",
        "string_length": 12,
        "offset": "123",
        "context_hint": "",
        "created_at": "2026-05-24T00:00:00Z",
    }

    events = timeline_events_from_rows([row])

    assert len(events) == 1
    assert events[0]["source_table"] == "memory_string_hits"
    assert events[0]["event_type"] == "memory_string_hit"
    assert events[0]["details"]["evidence_strength"] == "lead"
    assert events[0]["details"]["caveat"] == "Memory string timeline timestamp is import time, not occurrence time."
