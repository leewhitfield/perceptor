import zipfile
from pathlib import Path

import pytest

from forensic_orchestrator.db import Database
from forensic_orchestrator.evidence import add_image
from forensic_orchestrator.evidence_sources import classify_evidence_path, prepare_mount_source
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError


@pytest.fixture(autouse=True)
def sqlite_analytics_mode(monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYTICS_MODE", "sqlite")


def _case_with_image(tmp_path: Path, image_path: Path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    paths = WorkspacePaths(tmp_path / "workspace")
    case = db.create_case("case-1", paths.case_dir("case-1"))
    image = add_image(db, paths, case.id, image_path)
    return db, paths, case, image


def test_classify_evidence_path_formats(tmp_path):
    assert classify_evidence_path(tmp_path / "desktop.E01") == "ewf"
    assert classify_evidence_path(tmp_path / "desktop.E02") == "ewf"
    assert classify_evidence_path(tmp_path / "disk.dd") == "raw"
    assert classify_evidence_path(tmp_path / "disk.raw") == "raw"
    assert classify_evidence_path(tmp_path / "triage.vhd") == "vhd"
    assert classify_evidence_path(tmp_path / "triage.vhdx") == "vhdx"
    assert classify_evidence_path(tmp_path / "vm.vmdk") == "vmdk"
    assert classify_evidence_path(tmp_path / "evidence.zip") == "zip"
    assert classify_evidence_path(tmp_path / "EZCmd_Output.csv") == "report"


def test_add_image_records_evidence_kind_and_raw_mountability(tmp_path):
    raw_path = tmp_path / "disk.raw"
    raw_path.write_bytes(b"raw image placeholder")
    db, _paths, case, image = _case_with_image(tmp_path, raw_path)

    values = {(row["source"], row["key"]): row["value"] for row in db.image_metadata(case_id=case.id, image_id=image.id)}
    assert values[("evidence", "kind")] == "raw"
    assert values[("evidence", "mountable")] == "True"


def test_add_image_records_virtual_disk_preparation_metadata(tmp_path):
    vhdx_path = tmp_path / "kape-triage.vhdx"
    vhdx_path.write_bytes(b"vhdx image placeholder")
    db, _paths, case, image = _case_with_image(tmp_path, vhdx_path)

    values = {(row["source"], row["key"]): row["value"] for row in db.image_metadata(case_id=case.id, image_id=image.id)}
    assert values[("evidence", "kind")] == "vhdx"
    assert values[("evidence", "preparation")] == "qemu-img-convert-to-raw"


def test_zip_extract_selects_mountable_raw_candidate(tmp_path):
    zip_path = tmp_path / "triage.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("notes/readme.txt", "not the mount target")
        archive.writestr("exports/disk.raw", b"raw image placeholder")
    db, paths, case, image = _case_with_image(tmp_path, zip_path)

    prepared = prepare_mount_source(db=db, paths=paths, case_id=case.id, image=image, dry_run=False)

    assert prepared.original_kind == "raw"
    assert prepared.source_type == "zip-direct-raw"
    assert prepared.path == paths.images_dir(case.id) / image.id / "extracted" / "exports" / "disk.raw"
    assert prepared.path.read_bytes() == b"raw image placeholder"


def test_zip_report_only_is_identified_but_not_mountable(tmp_path):
    zip_path = tmp_path / "ez-reports.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("EvtxECmd_Output.csv", "EventId,Payload\n4624,test\n")
    db, paths, case, image = _case_with_image(tmp_path, zip_path)

    with pytest.raises(MountError, match="pre-generated report content"):
        prepare_mount_source(db=db, paths=paths, case_id=case.id, image=image, dry_run=False)


def test_zip_extract_rejects_unsafe_member_path(tmp_path):
    zip_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../disk.raw", b"raw image placeholder")
    db, paths, case, image = _case_with_image(tmp_path, zip_path)

    with pytest.raises(MountError, match="Unsafe ZIP member path"):
        prepare_mount_source(db=db, paths=paths, case_id=case.id, image=image, dry_run=False)


def test_zip_extract_requires_workspace_free_space(tmp_path, monkeypatch):
    zip_path = tmp_path / "huge.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("exports/disk.raw", b"raw image placeholder")
    db, paths, case, image = _case_with_image(tmp_path, zip_path)

    class FakeUsage:
        free = 1

    monkeypatch.setattr("forensic_orchestrator.evidence_sources.shutil.disk_usage", lambda _path: FakeUsage())

    with pytest.raises(MountError, match="does not have enough free space"):
        prepare_mount_source(db=db, paths=paths, case_id=case.id, image=image, dry_run=False)


def test_virtual_disk_dry_run_prepares_qemu_raw_target_without_dependency(tmp_path):
    vmdk_path = tmp_path / "vm.vmdk"
    vmdk_path.write_bytes(b"vmdk image placeholder")
    db, paths, case, image = _case_with_image(tmp_path, vmdk_path)

    prepared = prepare_mount_source(db=db, paths=paths, case_id=case.id, image=image, dry_run=True)

    assert prepared.original_kind == "vmdk"
    assert prepared.source_type == "direct-vmdk-qemu-raw"
    assert prepared.path == paths.images_dir(case.id) / image.id / "prepared" / "vm.raw"
