import json

from forensic_orchestrator.cli import main as cli_main, run_memory_processing_profile
from forensic_orchestrator.db import Database
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.processing_scheduler import ProcessingTask, run_processing_tasks
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
    assert events[0]["details"]["source_scope"] == "pagefile"
    assert events[0]["details"]["source_origin"] == "memory"
    assert events[0]["details"]["evidence_strength"] == "lead"
    assert events[0]["details"]["caveat"] == "Memory string timeline timestamp is import time, not occurrence time."


def test_processing_scheduler_preserves_order_and_captures_failures():
    tasks = [
        ProcessingTask(name="first", worker=lambda: "one"),
        ProcessingTask(name="failed", worker=lambda: (_ for _ in ()).throw(RuntimeError("boom"))),
        ProcessingTask(name="third", worker=lambda: "three"),
    ]

    results = run_processing_tasks(tasks, workers=2)

    assert [result.name for result in results] == ["first", "failed", "third"]
    assert [result.status for result in results] == ["completed", "failed", "completed"]
    assert results[1].error == "boom"
    assert all(result.duration_seconds >= 0 for result in results)


def test_memory_profile_parallel_scans_then_serializes_ingest(tmp_path):
    paths = WorkspacePaths(tmp_path / "workspace", live_mount_root=tmp_path / "live-mounts")
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", paths.case_dir("case-1"))
    paths.ensure_case_tree(case.id)
    volume = paths.mounts_dir(case.id) / "volumes" / "p1"
    volume.mkdir(parents=True)
    pagefile = volume / "pagefile.sys"
    swapfile = volume / "swapfile.sys"
    pagefile.write_bytes(b"noise token=alpha C:\\Users\\maya\\Desktop\\report.docx\x00")
    swapfile.write_bytes(b"noise sharepoint https://contoso.sharepoint.com/sites/demo\x00")

    report = run_memory_processing_profile(db, paths, case_id=case.id, min_length=6, workers=2)

    assert report["worker_count"] == 2
    assert report["scan_task_count"] == 2
    assert report["scanned_count"] == 2
    assert report["failed_count"] == 0
    rows = db.analytics._connect(case.id).execute("SELECT source_artifact_type, matched_term FROM memory_string_hits").fetchall()
    assert ("pagefile", "token") in [tuple(row) for row in rows]
    assert ("swapfile", "sharepoint") in [tuple(row) for row in rows]


def test_memory_crash_dump_command_scans_with_workers(tmp_path, capsys):
    paths = WorkspacePaths(tmp_path / "workspace", live_mount_root=tmp_path / "live-mounts")
    db = Database(paths.db_path())
    case = db.create_case("case-1", paths.case_dir("case-1"))
    paths.ensure_case_tree(case.id)
    dump_dir = paths.mounts_dir(case.id) / "volumes" / "p1"
    dump_dir.mkdir(parents=True)
    dump = dump_dir / "MEMORY.DMP"
    dump.write_bytes(b"rdp bearer abc1234567890")

    status = cli_main(["--root", str(paths.root), "memory", "crash-dumps", "--case", case.id, "--workers", "2"])

    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["worker_count"] == 2
    assert payload["scan_task_count"] == 1
    assert payload["scanned_count"] == 1
    assert payload["failed_count"] == 0
