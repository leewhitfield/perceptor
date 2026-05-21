from __future__ import annotations

import subprocess
import time
import uuid
from shutil import which
from pathlib import Path

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.encryption_preflight import (
    assert_not_encrypted,
    build_fsstat_command,
    log_encryption_preflight_inconclusive,
)
from forensic_orchestrator.jobs import JobRunner
from forensic_orchestrator.models import EvidenceImage, Partition
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError, PartitionError, ToolError, require_dependency

from .ewf import build_ewfmount_command, validate_ewfmount_available
from .partitions import (
    build_mmls_command,
    parse_mmls_output,
    select_windows_partition,
    validate_mmls_available,
)
from .volume_mount import build_ntfs_mount_command, validate_mount_available
from .volume_mount import build_umount_command


def _record_mmls_job(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    command: list[str],
    output_folder: Path,
    result: subprocess.CompletedProcess[str],
) -> None:
    output_folder.mkdir(parents=True, exist_ok=True)
    (output_folder / "stdout.txt").write_text(result.stdout)
    (output_folder / "stderr.txt").write_text(result.stderr)
    db.create_job(
        {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "tool_name": "mmls",
            "tool_version": None,
            "command": command,
            "start_time": utc_now(),
            "end_time": utc_now(),
            "exit_code": result.returncode,
            "stdout_path": output_folder / "stdout.txt",
            "stderr_path": output_folder / "stderr.txt",
            "output_folder": output_folder,
            "dry_run": False,
        }
    )
    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        event="job.finished",
        level="error" if result.returncode != 0 else "info",
        message=f"Finished mmls with exit code {result.returncode}",
        details={
            "command": command,
            "stdout_path": str(output_folder / "stdout.txt"),
            "stderr_path": str(output_folder / "stderr.txt"),
        },
    )


def _record_command_job(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool_name: str,
    command: list[str],
    output_folder: Path,
    result: subprocess.CompletedProcess[str],
) -> None:
    output_folder.mkdir(parents=True, exist_ok=True)
    (output_folder / "stdout.txt").write_text(result.stdout)
    (output_folder / "stderr.txt").write_text(result.stderr)
    db.create_job(
        {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "tool_name": tool_name,
            "tool_version": None,
            "command": command,
            "start_time": utc_now(),
            "end_time": utc_now(),
            "exit_code": result.returncode,
            "stdout_path": output_folder / "stdout.txt",
            "stderr_path": output_folder / "stderr.txt",
            "output_folder": output_folder,
            "dry_run": False,
        }
    )
    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        event="job.finished",
        level="error" if result.returncode != 0 else "info",
        message=f"Finished {tool_name} with exit code {result.returncode}",
        details={
            "command": command,
            "stdout_path": str(output_folder / "stdout.txt"),
            "stderr_path": str(output_folder / "stderr.txt"),
        },
    )


def _run_mmls(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    source: Path,
    output_folder: Path,
) -> subprocess.CompletedProcess[str]:
    command = build_mmls_command(source)
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    _record_mmls_job(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        command=command,
        output_folder=output_folder,
        result=result,
    )
    return result


def _run_fsstat(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    source: Path,
    output_folder: Path,
    offset_sectors: int | None = None,
) -> subprocess.CompletedProcess[str]:
    command = build_fsstat_command(source, offset_sectors=offset_sectors)
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    _record_command_job(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool_name="fsstat",
        command=command,
        output_folder=output_folder,
        result=result,
    )
    return result


def _run_encryption_preflight(
    *,
    db: Database,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition,
    output_folder: Path,
) -> None:
    fsstat_result = _run_fsstat(
        db=db,
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        source=source_path,
        output_folder=output_folder,
        offset_sectors=partition.start_sector,
    )
    assert_not_encrypted(
        db=db,
        case_id=case_id,
        image=image,
        source_path=source_path,
        source_type=source_type,
        partition=partition,
        fsstat_result=fsstat_result,
        context="partition-preflight",
    )
    if fsstat_result.returncode != 0:
        log_encryption_preflight_inconclusive(
            db=db,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=source_type,
            partition=partition,
            fsstat_result=fsstat_result,
        )


def _ensure_ewf_raw_source(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    use_sudo_mount: bool,
) -> tuple[Path, str, bool]:
    if source_path != image.path:
        return source_path, source_type, False

    ewf_dir = paths.ewf_mount_dir(case_id)
    raw_path = paths.ewf_raw_path(case_id)
    try:
        if raw_path.exists():
            return raw_path, "ewfmount", False
    except PermissionError:
        if use_sudo_mount:
            return raw_path, "ewfmount", False
        raise

    validate_ewfmount_available()
    runner = JobRunner(db)
    runner.run(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        tool_name="ewfmount",
        command=build_ewfmount_command(image.path, ewf_dir, use_sudo=False, allow_other=True),
        output_folder=paths.jobs_dir(case_id) / "mount" / "ewfmount",
        dry_run=False,
    )
    try:
        raw_exists = raw_path.exists()
    except PermissionError:
        raw_exists = use_sudo_mount
    if not raw_exists:
        raise MountError(f"ewfmount completed but raw image was not found at {raw_path}")
    return raw_path, "ewfmount", True


def _cleanup_ewfmount_after_failed_mount(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_type: str,
    cleanup_enabled: bool,
) -> None:
    if not cleanup_enabled:
        return
    if source_type not in {"ewfmount", "ewfmount-volume"}:
        return
    ewf_dir = paths.ewf_mount_dir(case_id)
    if not ewf_dir.exists():
        return
    fusermount = which("fusermount3") or which("fusermount")
    if fusermount is None:
        db.log_activity(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            level="warning",
            event="ewfmount.cleanup_skipped",
            message="Could not clean up ewfmount after failed NTFS mount; fusermount not found",
            details={"ewf_mount_path": str(ewf_dir)},
        )
        return
    JobRunner(db).run(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        tool_name="fusermount",
        command=[fusermount, "-u", str(ewf_dir)],
        output_folder=paths.jobs_dir(case_id) / "mount" / "ewf-unmount-after-failure",
        dry_run=False,
        check=False,
    )


def _record_prepared_source(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition,
    mount_filesystem: bool,
    use_sudo_mount: bool,
) -> Path | None:
    db.log_activity(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        event="partition.selected",
        message=f"Selected partition {partition.id}",
        details={
            "partition_id": partition.id,
            "offset_bytes": partition.offset_bytes,
            "description": partition.description,
            "source_type": source_type,
        },
    )
    volume_dir = paths.volume_mount_dir(case_id, partition.id)
    volume_dir.mkdir(parents=True, exist_ok=True)
    volume_mount_path: Path | None = None

    if mount_filesystem:
        validate_mount_available()
        require_dependency("sudo") if use_sudo_mount else None
        mount_source_path, source_type, cleanup_ewfmount = _ensure_ewf_raw_source(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=source_type,
            use_sudo_mount=use_sudo_mount,
        )
        source_path = mount_source_path
        command = build_ntfs_mount_command(
            source_path,
            volume_dir,
            partition,
            use_sudo=use_sudo_mount,
            norecover=True,
        )
        try:
            JobRunner(db).run(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                tool_name="mount",
                command=command,
                output_folder=paths.jobs_dir(case_id) / "mount" / "ntfs",
                dry_run=False,
            )
        except Exception:
            _cleanup_ewfmount_after_failed_mount(
                db=db,
                paths=paths,
                case_id=case_id,
                image=image,
                source_type=source_type,
                cleanup_enabled=cleanup_ewfmount,
            )
            raise
        volume_mount_path = volume_dir
        db.log_activity(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            event="volume.mounted",
            message="Mounted NTFS volume read-only",
            details={
                "mount_path": str(volume_dir),
                "source": str(source_path),
                "use_sudo": use_sudo_mount,
                "options": "ro,show_sys_files,streams_interface=windows,norecover",
            },
        )

    db.insert_mount(
        {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "image_id": image.id,
            "partition_id": partition.id,
            "ewf_mount_path": paths.ewf_mount_dir(case_id),
            "raw_path": source_path,
            "source_type": source_type,
            "volume_mount_path": volume_mount_path,
            "offset_bytes": partition.offset_bytes,
        }
    )
    return volume_mount_path


def _is_ntfs_fsstat_output(result: subprocess.CompletedProcess[str]) -> bool:
    return result.returncode == 0 and "File System Type: NTFS" in result.stdout


def mount_image(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    dry_run: bool,
    mount_filesystem: bool = False,
    use_sudo_mount: bool = False,
) -> Path | None:
    paths.ensure_case_tree(case_id)
    ewf_dir = paths.ewf_mount_dir(case_id)
    raw_path = paths.ewf_raw_path(case_id)
    mount_jobs = paths.jobs_dir(case_id) / "mount"
    runner = JobRunner(db)

    if not dry_run:
        validate_mmls_available()
        require_dependency("fsstat")

    if dry_run:
        dry_run_partition_id = "dry-run-selected-partition"
        dry_run_volume_dir = paths.volume_mount_dir(case_id, dry_run_partition_id)
        fsstat_command = ["fsstat", str(image.path)]
        runner.run(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            tool_name="fsstat",
            command=fsstat_command,
            output_folder=mount_jobs / "fsstat-direct",
            dry_run=True,
        )
        mmls_command = build_mmls_command(image.path)
        runner.run(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            tool_name="mmls",
            command=mmls_command,
            output_folder=mount_jobs / "mmls-direct",
            dry_run=True,
        )
        if mount_filesystem:
            ewf_command = build_ewfmount_command(image.path, ewf_dir, use_sudo=False, allow_other=True)
            runner.run(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                tool_name="ewfmount",
                command=ewf_command,
                output_folder=mount_jobs / "ewfmount",
                dry_run=True,
            )
            mount_command = build_ntfs_mount_command(
                raw_path,
                dry_run_volume_dir,
                Partition(
                    id=dry_run_partition_id,
                    slot="dry-run",
                    start_sector=0,
                    end_sector=0,
                    length=0,
                    description="Dry-run NTFS selection",
                ),
                use_sudo=use_sudo_mount,
                norecover=True,
            )
            runner.run(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                tool_name="mount",
                command=mount_command,
                output_folder=mount_jobs / "ntfs",
                dry_run=True,
            )
        db.insert_mount(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "image_id": image.id,
                "partition_id": dry_run_partition_id if mount_filesystem else None,
                "ewf_mount_path": ewf_dir,
                "raw_path": image.path,
                "source_type": "direct-e01",
                "volume_mount_path": dry_run_volume_dir if mount_filesystem else None,
                "offset_bytes": 0 if mount_filesystem else None,
            }
        )
        return None

    source_type = "direct-e01"
    source_path = image.path

    fsstat_result = _run_fsstat(
        db=db,
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        source=source_path,
        output_folder=mount_jobs / "fsstat-direct",
    )
    assert_not_encrypted(
        db=db,
        case_id=case_id,
        image=image,
        source_path=source_path,
        source_type=source_type,
        fsstat_result=fsstat_result,
        context="direct-volume-preflight",
    )
    if _is_ntfs_fsstat_output(fsstat_result):
        db.log_activity(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            event="image.source_selected",
            message="Using direct Sleuth Kit access to NTFS volume E01",
            details={"source": str(source_path), "source_type": "direct-e01-volume"},
        )
        return _record_prepared_source(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type="direct-e01-volume",
            partition=Partition(
                id="volume-ntfs",
                slot="volume",
                start_sector=0,
                end_sector=0,
                length=0,
                description="NTFS volume image without partition table",
            ),
            mount_filesystem=mount_filesystem,
            use_sudo_mount=use_sudo_mount,
        )

    mmls_result = _run_mmls(
        db=db,
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        source=source_path,
        output_folder=mount_jobs / "mmls-direct",
    )
    if mmls_result.returncode == 0:
        db.log_activity(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            event="image.source_selected",
            message="Using direct Sleuth Kit access to E01",
            details={"source": str(source_path)},
        )

    if mmls_result.returncode != 0:
        validate_ewfmount_available()
        ewf_command = build_ewfmount_command(image.path, ewf_dir, use_sudo=False, allow_other=True)
        runner.run(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            tool_name="ewfmount",
            command=ewf_command,
            output_folder=mount_jobs / "ewfmount",
            dry_run=False,
        )
        if not raw_path.exists():
            raise MountError(f"ewfmount completed but raw image was not found at {raw_path}")
        source_type = "ewfmount"
        source_path = raw_path
        mmls_result = _run_mmls(
            db=db,
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            source=source_path,
            output_folder=mount_jobs / "mmls-ewfmount",
        )
        if mmls_result.returncode == 0:
            db.log_activity(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                event="image.source_selected",
                message="Direct E01 access failed; using ewfmount fallback",
                details={"source": str(source_path)},
            )
        if mmls_result.returncode != 0:
            fsstat_result = _run_fsstat(
                db=db,
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                source=source_path,
                output_folder=mount_jobs / "fsstat-ewfmount",
            )
            assert_not_encrypted(
                db=db,
                case_id=case_id,
                image=image,
                source_path=source_path,
                source_type="ewfmount-volume",
                fsstat_result=fsstat_result,
                context="ewfmount-volume-preflight",
            )
            if _is_ntfs_fsstat_output(fsstat_result):
                db.log_activity(
                    case_id=case_id,
                    image_id=image.id,
                    computer_id=image.computer_id,
                    event="image.source_selected",
                    message="Using ewfmount fallback to NTFS volume image",
                    details={"source": str(source_path), "source_type": "ewfmount-volume"},
                )
                return _record_prepared_source(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    source_path=source_path,
                    source_type="ewfmount-volume",
                    partition=Partition(
                        id="volume-ntfs",
                        slot="volume",
                        start_sector=0,
                        end_sector=0,
                        length=0,
                        description="NTFS volume image without partition table",
                    ),
                    mount_filesystem=mount_filesystem,
                    use_sudo_mount=use_sudo_mount,
                )
            raise PartitionError(f"mmls failed with exit code {mmls_result.returncode}")

    partitions = parse_mmls_output(mmls_result.stdout)
    partition = select_windows_partition(partitions)
    assert_not_encrypted(
        db=db,
        case_id=case_id,
        image=image,
        source_path=source_path,
        source_type=source_type,
        partition=partition,
        context="partition-description-preflight",
    )
    _run_encryption_preflight(
        db=db,
        case_id=case_id,
        image=image,
        source_path=source_path,
        source_type=source_type,
        partition=partition,
        output_folder=mount_jobs / "fsstat-selected-partition",
    )
    return _record_prepared_source(
        db=db,
        paths=paths,
        case_id=case_id,
        image=image,
        source_path=source_path,
        source_type=source_type,
        partition=partition,
        mount_filesystem=mount_filesystem,
        use_sudo_mount=use_sudo_mount,
    )


def unmount_image(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    dry_run: bool,
    use_sudo_mount: bool = False,
) -> Path:
    mount_row = db.latest_mount(case_id, image.id)
    if mount_row is None or not mount_row["volume_mount_path"]:
        raise MountError(f"No mounted filesystem recorded for case={case_id} image={image.id}")

    mount_path = Path(mount_row["volume_mount_path"])
    command = build_umount_command(mount_path, use_sudo=use_sudo_mount)
    JobRunner(db).run(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        tool_name="umount",
        command=command,
        output_folder=paths.jobs_dir(case_id) / "mount" / "umount",
        dry_run=dry_run,
    )
    db.log_activity(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        event="volume.unmounted" if not dry_run else "volume.unmount_dry_run",
        message="Unmounted NTFS volume" if not dry_run else "Dry-run recorded NTFS volume unmount",
        details={"mount_path": str(mount_path), "use_sudo": use_sudo_mount},
    )
    if mount_row["source_type"] in {"ewfmount", "ewfmount-volume"}:
        ewf_mount_path = Path(mount_row["ewf_mount_path"])
        ewf_command = build_umount_command(ewf_mount_path, use_sudo=False)
        for attempt in range(1, 4):
            try:
                JobRunner(db).run(
                    case_id=case_id,
                    image_id=image.id,
                    computer_id=image.computer_id,
                    tool_name="umount",
                    command=ewf_command,
                    output_folder=paths.jobs_dir(case_id) / "mount" / f"ewf-umount-attempt-{attempt}",
                    dry_run=dry_run,
                )
                break
            except ToolError:
                if attempt == 3 or dry_run:
                    raise
                time.sleep(0.5)
        db.log_activity(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            event="ewf.unmounted" if not dry_run else "ewf.unmount_dry_run",
            message="Unmounted EWF raw image layer" if not dry_run else "Dry-run recorded EWF unmount",
            details={"mount_path": str(ewf_mount_path), "use_sudo": False},
        )
    return mount_path
