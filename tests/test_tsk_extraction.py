from pathlib import Path

from forensic_orchestrator.mounting.tsk import (
    build_fls_command,
    build_icat_command,
    build_istat_command,
    extract_artifact,
    FlsEntry,
    parse_istat_metadata,
    parse_fls_output,
)
from forensic_orchestrator.db import Database
from forensic_orchestrator.models import ArtifactDefinition


def test_tsk_commands_are_arrays():
    raw = Path("/case/mounts/ewf/ewf1")

    assert build_fls_command(raw, 63) == ["fls", "-f", "ntfs", "-r", "-p", "-o", "63", str(raw)]
    assert build_icat_command(raw, 63, "0") == ["icat", "-f", "ntfs", "-o", "63", str(raw), "0"]
    assert build_istat_command(raw, 63, "200") == ["istat", "-f", "ntfs", "-o", "63", str(raw), "200"]


def test_parse_istat_metadata_uses_standard_information_timestamps():
    output = """
MFT Entry Header Values:
Entry: 200

$STANDARD_INFORMATION Attribute Values:
Created:\t2008-07-06 07:54:26.000000000 (UTC)
File Modified:\t2008-07-06 07:54:18.000000000 (UTC)
MFT Modified:\t2008-07-06 07:54:20.000000000 (UTC)
Accessed:\t2008-07-06 07:54:27.000000000 (UTC)

$FILE_NAME Attribute Values:
Created:\t1999-01-01 00:00:00.000000000 (UTC)
"""

    assert parse_istat_metadata(output) == {
        "mft_created": "2008-07-06 07:54:26.000000000 (UTC)",
        "mft_modified": "2008-07-06 07:54:18.000000000 (UTC)",
        "mft_record_modified": "2008-07-06 07:54:20.000000000 (UTC)",
        "mft_accessed": "2008-07-06 07:54:27.000000000 (UTC)",
    }


def test_parse_fls_output_preserves_paths_and_inodes():
    output = """
r/r 0-128-1:	$MFT
d/d 28-144-6:	WINDOWS
r/r 120-128-1:	WINDOWS/System32/winevt/Logs/System.evtx
r/r 121-128-1:	WINDOWS/System32/winevt/Logs/Security.evtx
"""
    entries = parse_fls_output(output)

    assert entries[0].inode == "0"
    assert entries[0].path == "$MFT"
    assert entries[1].is_directory is True
    assert entries[2].inode == "120"
    assert entries[2].path == "WINDOWS/System32/winevt/Logs/System.evtx"


def test_parse_fls_output_preserves_ads_inode_for_usn_journal():
    output = """
r/r 35-128-4:	$Extend/$UsnJrnl:$J
"""
    entries = parse_fls_output(output)

    assert entries[0].inode == "35-128-4"
    assert entries[0].path == "$Extend/$UsnJrnl:$J"


def test_lnk_paths_are_parsed_from_fls_output():
    output = """
r/r 200-128-1:	Documents and Settings/Jean/Desktop/Report.lnk
r/r 201-128-1:	Documents and Settings/Jean/Recent/Budget.XLS.LNK
r/r 202-128-1:	WINDOWS/not-a-link.txt
"""
    entries = parse_fls_output(output)
    lnk_entries = [
        entry
        for entry in entries
        if not entry.is_directory and entry.path.lower().endswith(".lnk")
    ]

    assert [entry.inode for entry in lnk_entries] == ["200", "201"]


def test_jump_list_paths_are_parsed_from_fls_output():
    output = """
r/r 300-128-1:	Documents and Settings/Jean/Recent/AutomaticDestinations/1b4dd67f29cb1962.automaticDestinations-ms
r/r 301-128-1:	Documents and Settings/Jean/Recent/CustomDestinations/2b4dd67f29cb1962.customDestinations-ms
r/r 302-128-1:	Documents and Settings/Jean/Recent/not-a-jumplist.txt
"""
    entries = parse_fls_output(output)
    jump_list_entries = [
        entry
        for entry in entries
        if not entry.is_directory
        and (
            entry.path.lower().endswith(".automaticdestinations-ms")
            or entry.path.lower().endswith(".customdestinations-ms")
        )
    ]

    assert [entry.inode for entry in jump_list_entries] == ["300", "301"]


def test_prefetch_paths_are_parsed_from_fls_output():
    output = """
r/r 400-128-1:	WINDOWS/Prefetch/NOTEPAD.EXE-12345678.pf
r/r 401-128-1:	WINDOWS/Prefetch/CMD.EXE-87654321.PF
r/r 402-128-1:	WINDOWS/System32/cmd.exe
"""
    entries = parse_fls_output(output)
    prefetch_entries = [
        entry
        for entry in entries
        if entry.path.lower().startswith("windows/prefetch/")
        and entry.path.lower().endswith(".pf")
    ]

    assert [entry.inode for entry in prefetch_entries] == ["400", "401"]


def test_extract_artifact_excludes_start_menu_lnk_by_default(monkeypatch, tmp_path):
    extracted_destinations: list[Path] = []

    def fake_run_icat_to_file(**kwargs):
        destination = kwargs["destination"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("lnk")
        extracted_destinations.append(destination)

    monkeypatch.setattr("forensic_orchestrator.mounting.tsk._run_icat_to_file", fake_run_icat_to_file)
    monkeypatch.setattr("forensic_orchestrator.mounting.tsk.read_file_metadata", lambda **kwargs: {})
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    extract_artifact(
        db=db,
        case_id=case.id,
        image_id="image-1",
        computer_id="computer-1",
        raw_image=Path("/evidence/desktop.E01"),
        offset_sectors=63,
        artifact=ArtifactDefinition(
            name="lnk_files",
            source="",
            destination="lnk_files",
            recursive=True,
            pattern="*.lnk",
            exclude_patterns=("*/Start Menu/*",),
        ),
        artifacts_root=tmp_path / "artifacts",
        dry_run=False,
        fls_entries=[
            FlsEntry("200", "Documents and Settings/Jean/Recent/Report.lnk", False),
            FlsEntry("201", "Documents and Settings/Jean/Start Menu/Programs/App.lnk", False),
        ],
    )

    assert [path.name for path in extracted_destinations] == ["Report.lnk"]


def test_extract_artifact_can_include_start_menu_lnk(monkeypatch, tmp_path):
    extracted_destinations: list[Path] = []

    def fake_run_icat_to_file(**kwargs):
        destination = kwargs["destination"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("lnk")
        extracted_destinations.append(destination)

    monkeypatch.setattr("forensic_orchestrator.mounting.tsk._run_icat_to_file", fake_run_icat_to_file)
    monkeypatch.setattr("forensic_orchestrator.mounting.tsk.read_file_metadata", lambda **kwargs: {})
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")

    extract_artifact(
        db=db,
        case_id=case.id,
        image_id="image-1",
        computer_id="computer-1",
        raw_image=Path("/evidence/desktop.E01"),
        offset_sectors=63,
        artifact=ArtifactDefinition(
            name="lnk_files",
            source="",
            destination="lnk_files",
            recursive=True,
            pattern="*.lnk",
            exclude_patterns=("*/Start Menu/*",),
        ),
        artifacts_root=tmp_path / "artifacts",
        dry_run=False,
        fls_entries=[
            FlsEntry("200", "Documents and Settings/Jean/Recent/Report.lnk", False),
            FlsEntry("201", "Documents and Settings/Jean/Start Menu/Programs/App.lnk", False),
        ],
        ignore_exclude_patterns=True,
    )

    assert sorted(path.name for path in extracted_destinations) == ["App.lnk", "Report.lnk"]
