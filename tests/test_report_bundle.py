from __future__ import annotations

import csv
import zipfile

import duckdb

import forensic_orchestrator.report_bundle as report_bundle
from forensic_orchestrator.db import Database
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.report_bundle import infer_report_candidate
from forensic_orchestrator.report_bundle import import_report_bundle_many
from forensic_orchestrator.tools.usp import normalized_usp_row


def test_report_bundle_detects_vsc_named_mft_by_header(tmp_path):
    csv_path = tmp_path / "Replaced1-A00521_E_ShadowCopy52_$MFT.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,ParentPath,FileName,Created0x10\n"
        "42,3,C:/Users/test,thing.txt,2023-01-01 00:00:00\n",
        encoding="utf-8",
    )

    candidate = infer_report_candidate(csv_path)

    assert candidate is not None
    assert candidate.tool_name == "MFTECmd"
    assert candidate.transform is None


def test_report_bundle_detects_and_transforms_tzworks_lnk(tmp_path):
    csv_path = tmp_path / "Replaced1_output.csv"
    csv_path.write_text(
        "lp (lnk parser)\n"
        "\n"
        "source path/filename,source type,file mdate, time-UTC,file adate, time-UTC,file cdate, time-UTC,"
        "tgt mdate, time-UTC,tgt adate, time-UTC,tgt cdate, time-UTC,ObjID date, time-UTC,tgt attrib,"
        "target inode,target seq#,file size,target name,IDList extra info,vol type,vol serial,vol label,"
        "local path,common path,network/device info,extra info,netbios name\n"
        "C:/Recent/a.lnk,file,2023-01-02,01:02:03,2023-01-03,02:03:04,2023-01-04,03:04:05,"
        "2023-01-05,04:05:06,2023-01-06,05:06:07,2023-01-07,06:07:08,,,,123,1,4096,"
        "target.exe,,fixed,ABCD-1234,DATA,C:/target.exe,,,/safe,HOST01\n",
        encoding="utf-8",
    )

    candidate = infer_report_candidate(csv_path)
    assert candidate is not None
    assert candidate.tool_name == "LECmd"
    transformed = candidate.transform(csv_path, tmp_path / "lnk.normalized.csv")

    with transformed.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["SourceFile"] == "C:/Recent/a.lnk"
    assert rows[0]["TargetModified"] == "2023-01-05 04:05:06"
    assert rows[0]["VolumeSerialNumber"] == "ABCD-1234"
    assert rows[0]["LocalPath"] == "C:/target.exe"
    assert rows[0]["MachineID"] == "HOST01"


def test_report_bundle_detects_and_transforms_tzworks_usp(tmp_path):
    csv_path = tmp_path / "usp_output.csv"
    csv_path.write_text(
        "usp (usb storage parser)\n"
        "\n"
        "device name,vid/pid, time-UTC,install, time-local,disk dev, time-UTC,vol dev, time-UTC,type,"
        "vid,pid,hub,port,vendor,product,rev,volume guid,vol name/details,users [ date/time-UTC],"
        "instance/serial#,Other dates defined by explicit property keys,Readyboost\n"
        "SanDisk Ultra,2020-12-12,03:37:00,2020-12-12,03:38:00,2020-12-12,03:39:00,"
        "2020-12-12,03:40:00,disk [usbstor],#0781,#5581,hub1,1,SanDisk,Ultra,1.00,"
        "{11111111-2222-3333-4444-555555555555},E={\"\"utc\"\":\"\"2020-12-12 03:40:00\"\"},user1,SERIAL123,,\n",
        encoding="utf-8",
    )

    candidate = infer_report_candidate(csv_path)
    assert candidate is not None
    assert candidate.tool_name == "USPParser"
    transformed = candidate.transform(csv_path, tmp_path / "usp.normalized.csv")

    with transformed.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["device_name"] == "SanDisk Ultra"
    assert rows[0]["vendor_id"] == "0781"
    assert rows[0]["product_id"] == "5581"
    assert rows[0]["serial"] == "SERIAL123"
    assert rows[0]["volume_device_utc"] == "2020-12-12 03:40:00"
    normalized = normalized_usp_row(
        case_id="case-1",
        computer_id="computer-1",
        image_id="image-1",
        tool_output_id="tool-output-1",
        tool_name="USPParser",
        source_csv=transformed,
        row_number=1,
        row=rows[0],
    )
    assert normalized["drive_letter"] == "E:"
    assert normalized["volume_name"] is None


def test_report_bundle_import_many_zip_creates_one_computer_per_top_level_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    input_root = tmp_path / "input"
    for computer in ("ComputerA", "ComputerB"):
        mft_dir = input_root / computer / "MFT"
        mft_dir.mkdir(parents=True)
        (mft_dir / f"{computer}_$MFT.csv").write_text(
            "EntryNumber,SequenceNumber,ParentPath,FileName,Created0x10\n"
            f"42,3,C:/Users/{computer},note.txt,2023-01-01 00:00:00\n",
            encoding="utf-8",
        )
    zip_path = tmp_path / "case.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        for path in input_root.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(input_root))

    paths = WorkspacePaths(tmp_path / "analysis")
    db = Database(paths.db_path())
    result = import_report_bundle_many(
        db=db,
        paths=paths,
        report_root=zip_path,
        accept_duplicate=True,
    )
    db.close()

    assert result.imported_computers == 2
    assert result.imported_files == 2
    assert result.imported_rows == 2
    assert result.failed_files == 0
    conn = duckdb.connect(str(paths.analytics_db_path(result.case_id)), read_only=True)
    try:
        assert conn.execute("SELECT count(*) FROM mft_entries").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM distinct_mft_entries").fetchone()[0] == 2
    finally:
        conn.close()


def test_report_bundle_import_many_emits_progress(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    input_root = tmp_path / "input" / "ComputerA" / "MFT"
    input_root.mkdir(parents=True)
    (input_root / "ComputerA_$MFT.csv").write_text(
        "EntryNumber,SequenceNumber,ParentPath,FileName,Created0x10\n"
        "42,3,C:/Users/ComputerA,note.txt,2023-01-01 00:00:00\n",
        encoding="utf-8",
    )

    paths = WorkspacePaths(tmp_path / "analysis")
    db = Database(paths.db_path())
    messages: list[str] = []
    result = import_report_bundle_many(
        db=db,
        paths=paths,
        report_root=tmp_path / "input",
        accept_duplicate=True,
        progress=messages.append,
    )
    db.close()

    assert result.imported_computers == 1
    assert any(message.startswith("report-bundle-many start") for message in messages)
    assert any("computer 1/1 start" in message for message in messages)
    assert any("csv 1/1 import" in message for message in messages)
    assert any("csv 1/1 imported" in message for message in messages)
    assert any(message.startswith("report-bundle postprocess start") for message in messages)
    assert any(message.startswith("report-bundle-many completed") for message in messages)


def test_report_bundle_import_many_warns_when_distinct_rebuild_hits_disk_full(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "duckdb")
    input_root = tmp_path / "input" / "ComputerA" / "MFT"
    input_root.mkdir(parents=True)
    (input_root / "ComputerA_$MFT.csv").write_text(
        "EntryNumber,SequenceNumber,ParentPath,FileName,Created0x10\n"
        "42,3,C:/Users/ComputerA,note.txt,2023-01-01 00:00:00\n",
        encoding="utf-8",
    )

    original = report_bundle.rebuild_distinct_artifact_tables
    calls = {"count": 0}

    def flaky_distinct(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise duckdb.IOException(
                'IO Error: Could not write file "events.duckdb.tmp/duckdb_temp_storage_DEFAULT-1.tmp": No space left'
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(report_bundle, "rebuild_distinct_artifact_tables", flaky_distinct)
    paths = WorkspacePaths(tmp_path / "analysis")
    db = Database(paths.db_path())
    result = import_report_bundle_many(
        db=db,
        paths=paths,
        report_root=tmp_path / "input",
        accept_duplicate=True,
    )
    db.close()

    assert result.imported_computers == 1
    assert result.imported_files == 1
    assert result.failed_files == 0
    assert result.warnings
    assert "DuckDB ran out of temporary disk space" in result.warnings[0]
