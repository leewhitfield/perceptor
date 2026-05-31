from __future__ import annotations

import json
import subprocess
import time
import uuid
from shutil import which
from pathlib import Path

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.encryption_preflight import (
    assert_not_encrypted,
    build_fsstat_command,
    encrypted_filesystem_evidence,
    is_bitlocker_evidence,
    log_encryption_preflight_inconclusive,
)
from forensic_orchestrator.evidence_sources import prepare_mount_source
from forensic_orchestrator.jobs import JobRunner
from forensic_orchestrator.models import EvidenceImage, Partition
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError, PartitionError, ToolError, require_dependency

from .ewf import build_ewfmount_command, validate_ewfmount_available
from .bitlocker import BitLockerUnlockOptions, cleanup_bitlocker_layers, unlock_bitlocker_volume
from .partitions import (
    build_mmls_command,
    parse_mmls_output,
    select_windows_partition,
    validate_mmls_available,
)
from .volume_mount import (
    build_filesystem_mount_command,
    build_losetup_detach_command,
    build_losetup_offset_command,
    build_ntfs_loop_mount_command,
    build_ntfs_mount_command,
    validate_mount_available,
)
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
    nonzero_level: str = "error",
    nonzero_event: str = "job.finished",
    nonzero_message: str | None = None,
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
        event=nonzero_event if result.returncode != 0 else "job.finished",
        level=nonzero_level if result.returncode != 0 else "info",
        message=(
            nonzero_message.format(tool_name=tool_name, exit_code=result.returncode)
            if result.returncode != 0 and nonzero_message
            else f"Finished {tool_name} with exit code {result.returncode}"
        ),
        details={
            "command": command,
            "stdout_path": str(output_folder / "stdout.txt"),
            "stderr_path": str(output_folder / "stderr.txt"),
            "anticipated_nonzero": result.returncode != 0 and nonzero_level != "error",
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
    expected_probe_failure: bool = False,
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
        nonzero_level="warning" if expected_probe_failure else "error",
        nonzero_event="job.probe_finished" if expected_probe_failure else "job.finished",
        nonzero_message="{tool_name} probe returned exit code {exit_code}; trying partition-table fallback" if expected_probe_failure else None,
    )
    return result


def _run_encryption_preflight(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition,
    output_folder: Path,
    mount_filesystem: bool,
    bitlocker_options: BitLockerUnlockOptions | None,
) -> tuple[Path, str, Partition] | None:
    fsstat_result = _run_fsstat(
        db=db,
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        source=source_path,
        output_folder=output_folder,
        offset_sectors=partition.start_sector,
    )
    evidence = encrypted_filesystem_evidence(
        stdout=fsstat_result.stdout,
        stderr=fsstat_result.stderr,
        partition_description=partition.description,
    )
    if is_bitlocker_evidence(evidence) and bitlocker_options and bitlocker_options.enabled and mount_filesystem:
        _log_encryption_detected(
            db=db,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=source_type,
            partition=partition,
            context="partition-preflight",
            evidence=evidence or {},
        )
        unlock = unlock_bitlocker_volume(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=source_type,
            partition=partition,
            options=bitlocker_options,
        )
        return unlock.source_path, unlock.source_type, _unlocked_partition(partition)
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
    return None


def _log_encryption_detected(
    *,
    db: Database,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition | None,
    context: str,
    evidence: dict[str, str],
) -> None:
    details: dict[str, object] = {
        **evidence,
        "source": str(source_path),
        "source_type": source_type,
        "context": context,
        "unlock_attempted": True,
    }
    if partition is not None:
        details.update(
            {
                "partition_id": partition.id,
                "partition_description": partition.description,
                "offset_sectors": partition.start_sector,
                "offset_bytes": partition.offset_bytes,
            }
        )
    db.log_activity(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        event="image.encryption_detected",
        level="warning",
        message=f"Encrypted filesystem detected ({evidence.get('encryption_type', 'unknown')}); attempting configured unlock",
        details=details,
    )


def _unlocked_partition(partition: Partition) -> Partition:
    return Partition(
        id=partition.id,
        slot=partition.slot,
        start_sector=0,
        end_sector=partition.length,
        length=partition.length,
        description=f"Unlocked BitLocker volume from {partition.description}",
        sector_size=partition.sector_size,
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
    if source_type not in {"direct-e01", "direct-e01-volume"}:
        return source_path, source_type, False

    ewf_dir = paths.ewf_mount_dir(case_id)
    raw_path = paths.ewf_raw_path(case_id)
    try:
        if raw_path.exists():
            return raw_path, "ewfmount-volume" if source_type == "direct-e01-volume" else "ewfmount", False
    except PermissionError:
        if use_sudo_mount:
            return raw_path, "ewfmount-volume" if source_type == "direct-e01-volume" else "ewfmount", False
        raise

    validate_ewfmount_available()
    runner = JobRunner(db)
    runner.run(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        tool_name="ewfmount",
        command=build_ewfmount_command(source_path, ewf_dir, use_sudo=False, allow_other=True),
        output_folder=paths.jobs_dir(case_id) / "mount" / "ewfmount",
        dry_run=False,
    )
    try:
        raw_exists = raw_path.exists()
    except PermissionError:
        raw_exists = use_sudo_mount
    if not raw_exists:
        raise MountError(f"ewfmount completed but raw image was not found at {raw_path}")
    return raw_path, "ewfmount-volume" if source_type == "direct-e01-volume" else "ewfmount", True


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
    if source_type not in {"ewfmount", "ewfmount-volume"} and not source_type.startswith(("ewfmount-", "zip-ewfmount-")):
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


def _partition_as_loopback(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    partition: Partition,
    use_sudo_mount: bool,
) -> Path:
    result = JobRunner(db).run(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        tool_name="losetup",
        command=build_losetup_offset_command(source_path, partition, use_sudo=use_sudo_mount),
        output_folder=paths.jobs_dir(case_id) / "mount" / "losetup-partition",
        dry_run=False,
    )
    loop_device = result.stdout_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    if not loop_device:
        raise MountError(f"losetup completed but did not return a loop device; see {result.stdout_path}")
    return Path(loop_device[-1].strip())


def _mount_ntfs_loopback(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    loop_device: Path,
    volume_dir: Path,
    use_sudo_mount: bool,
) -> None:
    JobRunner(db).run(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        tool_name="mount",
        command=build_ntfs_loop_mount_command(
            str(loop_device),
            volume_dir,
            use_sudo=use_sudo_mount,
            norecover=True,
        ),
        output_folder=paths.jobs_dir(case_id) / "mount" / "ntfs-loop",
        dry_run=False,
    )


def _detach_loopback(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    loop_device: Path,
    use_sudo_mount: bool,
    reason: str,
) -> None:
    JobRunner(db).run(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        tool_name="losetup",
        command=build_losetup_detach_command(str(loop_device), use_sudo=use_sudo_mount),
        output_folder=paths.jobs_dir(case_id) / "mount" / f"losetup-detach-{reason}",
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
    filesystem_type: str | None = None,
) -> Path | None:
    selected_partition_offset_bytes = partition.offset_bytes
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
        if filesystem_type is None:
            fsstat_result = _run_fsstat(
                db=db,
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                source=source_path,
                output_folder=paths.jobs_dir(case_id) / "mount" / "fsstat-mount-selected",
                offset_sectors=partition.start_sector,
            )
            filesystem_type = _filesystem_type_from_fsstat(fsstat_result.stdout) or _filesystem_type_from_partition(partition)
        validate_mount_available(filesystem_type)
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
        command = build_filesystem_mount_command(
            source_path,
            volume_dir,
            partition,
            filesystem_type=filesystem_type,
            use_sudo=use_sudo_mount,
            norecover=True,
        )
        loop_device: Path | None = None
        mounted_with_loopback = False
        try:
            direct_mount_result = JobRunner(db).run(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                tool_name="mount",
                command=command,
                output_folder=paths.jobs_dir(case_id) / "mount" / (filesystem_type or "filesystem"),
                dry_run=False,
                check=False,
                nonzero_level="warning",
                nonzero_event="job.fallback_probe_finished",
                nonzero_message="{tool_name} direct partition mount returned exit code {exit_code}; trying loopback partition fallback",
            )
            if direct_mount_result.exit_code not in (0, None):
                raise ToolError(
                    f"direct filesystem mount returned exit code {direct_mount_result.exit_code}; "
                    f"stdout={direct_mount_result.stdout_path} stderr={direct_mount_result.stderr_path}"
                )
        except Exception as direct_mount_error:
            if (
                use_sudo_mount
                and (filesystem_type or "").casefold() == "ntfs"
                and source_type in {"ewfmount", "zip-ewfmount"}
            ):
                db.log_activity(
                    case_id=case_id,
                    image_id=image.id,
                    computer_id=image.computer_id,
                    level="warning",
                    event="volume.mount_offset_failed",
                    message="Direct NTFS offset mount failed; retrying with read-only loopback partition view",
                    details={
                        "source": str(source_path),
                        "offset_bytes": partition.offset_bytes,
                        "error": str(direct_mount_error),
                    },
                )
                try:
                    loop_device = _partition_as_loopback(
                        db=db,
                        paths=paths,
                        case_id=case_id,
                        image=image,
                        source_path=source_path,
                        partition=partition,
                        use_sudo_mount=use_sudo_mount,
                    )
                    _mount_ntfs_loopback(
                        db=db,
                        paths=paths,
                        case_id=case_id,
                        image=image,
                        loop_device=loop_device,
                        volume_dir=volume_dir,
                        use_sudo_mount=use_sudo_mount,
                    )
                    source_path = loop_device
                    source_type = f"{source_type}-loop"
                    partition = Partition(
                        id=partition.id,
                        slot=partition.slot,
                        start_sector=0,
                        end_sector=partition.length,
                        length=partition.length,
                        description=f"Loopback partition view of {partition.description}",
                        sector_size=partition.sector_size,
                    )
                    mounted_with_loopback = True
                except Exception:
                    if loop_device is not None:
                        _detach_loopback(
                            db=db,
                            paths=paths,
                            case_id=case_id,
                            image=image,
                            loop_device=loop_device,
                            use_sudo_mount=use_sudo_mount,
                            reason="failed-mount",
                        )
                    if "bitlocker" in source_type:
                        cleanup_bitlocker_layers(
                            db=db,
                            paths=paths,
                            case_id=case_id,
                            image=image,
                            cleanup=_latest_bitlocker_cleanup(db, case_id=case_id, image_id=image.id),
                            use_sudo=use_sudo_mount,
                            dry_run=False,
                        )
                    _cleanup_ewfmount_after_failed_mount(
                        db=db,
                        paths=paths,
                        case_id=case_id,
                        image=image,
                        source_type=source_type,
                        cleanup_enabled=cleanup_ewfmount,
                    )
                    raise
            else:
                if "bitlocker" in source_type:
                    cleanup_bitlocker_layers(
                        db=db,
                        paths=paths,
                        case_id=case_id,
                        image=image,
                        cleanup=_latest_bitlocker_cleanup(db, case_id=case_id, image_id=image.id),
                        use_sudo=use_sudo_mount,
                        dry_run=False,
                    )
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
            message=f"Mounted {filesystem_type or 'filesystem'} volume read-only",
            details={
                "mount_path": str(volume_dir),
                "source": str(source_path),
                "filesystem_type": filesystem_type,
                "use_sudo": use_sudo_mount,
                "loop_device": str(loop_device) if mounted_with_loopback and loop_device is not None else None,
                "options": "ro,show_sys_files,streams_interface=windows,norecover" if filesystem_type == "ntfs" else f"ro,loop,offset={partition.offset_bytes}",
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
            "offset_bytes": selected_partition_offset_bytes,
            "filesystem_type": filesystem_type,
        }
    )
    return volume_mount_path


def _is_ntfs_fsstat_output(result: subprocess.CompletedProcess[str]) -> bool:
    return result.returncode == 0 and "File System Type: NTFS" in result.stdout


def _filesystem_type_from_fsstat(stdout: str) -> str | None:
    for line in stdout.splitlines():
        if "File System Type:" not in line:
            continue
        value = line.split("File System Type:", 1)[1].strip().casefold()
        if "exfat" in value:
            return "exfat"
        if "fat32" in value:
            return "fat32"
        if value == "fat" or " fat" in value or "fat" in value:
            return "fat"
        if "ntfs" in value:
            return "ntfs"
        return value or None
    return None


def _filesystem_type_from_partition(partition: Partition) -> str | None:
    text = partition.description.casefold()
    if "ntfs" in text and "exfat" in text:
        return None
    if "exfat" in text:
        return "exfat"
    if "fat32" in text:
        return "fat32"
    if "fat" in text:
        return "fat"
    if "ntfs" in text or "basic data" in text or "windows" in text:
        return "ntfs"
    return None


def _latest_fsstat_stdout(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    output_folder: Path,
) -> str:
    stdout_path = output_folder / "stdout.txt"
    if stdout_path.exists():
        return stdout_path.read_text(errors="ignore")
    row = db.conn.execute(
        """
        SELECT stdout_path
        FROM jobs
        WHERE case_id = ? AND image_id = ? AND tool_name = 'fsstat' AND output_folder = ?
        ORDER BY start_time DESC
        LIMIT 1
        """,
        (case_id, image_id, str(output_folder)),
    ).fetchone()
    if row is None:
        return ""
    try:
        return Path(row["stdout_path"]).read_text(errors="ignore")
    except OSError:
        return ""


def mount_image(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    dry_run: bool,
    mount_filesystem: bool = False,
    use_sudo_mount: bool = False,
    bitlocker_options: BitLockerUnlockOptions | None = None,
) -> Path | None:
    paths.ensure_case_tree(case_id)
    ewf_dir = paths.ewf_mount_dir(case_id)
    raw_path = paths.ewf_raw_path(case_id)
    mount_jobs = paths.jobs_dir(case_id) / "mount"
    runner = JobRunner(db)
    prepared = prepare_mount_source(db=db, paths=paths, case_id=case_id, image=image, dry_run=dry_run)
    source_type = prepared.source_type
    source_path = prepared.path

    if not dry_run:
        validate_mmls_available()
        require_dependency("fsstat")

    if dry_run:
        dry_run_partition_id = "dry-run-selected-partition"
        dry_run_volume_dir = paths.volume_mount_dir(case_id, dry_run_partition_id)
        fsstat_command = ["fsstat", str(source_path)]
        runner.run(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            tool_name="fsstat",
            command=fsstat_command,
            output_folder=mount_jobs / "fsstat-direct",
            dry_run=True,
        )
        mmls_command = build_mmls_command(source_path)
        runner.run(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            tool_name="mmls",
            command=mmls_command,
            output_folder=mount_jobs / "mmls-direct",
            dry_run=True,
        )
        if mount_filesystem and "direct-e01" in source_type:
            ewf_command = build_ewfmount_command(source_path, ewf_dir, use_sudo=False, allow_other=True)
            runner.run(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                tool_name="ewfmount",
                command=ewf_command,
                output_folder=mount_jobs / "ewfmount",
                dry_run=True,
            )
            mount_source_path = raw_path
            mount_source_type = "ewfmount"
        else:
            mount_source_path = source_path
            mount_source_type = source_type
        if mount_filesystem:
            mount_command = build_ntfs_mount_command(
                mount_source_path,
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
                "raw_path": mount_source_path,
                "source_type": mount_source_type,
                "volume_mount_path": dry_run_volume_dir if mount_filesystem else None,
                "offset_bytes": 0 if mount_filesystem else None,
            }
        )
        return None

    fsstat_result = _run_fsstat(
        db=db,
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        source=source_path,
        output_folder=mount_jobs / "fsstat-direct",
        expected_probe_failure=True,
    )
    direct_evidence = encrypted_filesystem_evidence(stdout=fsstat_result.stdout, stderr=fsstat_result.stderr)
    if is_bitlocker_evidence(direct_evidence) and bitlocker_options and bitlocker_options.enabled and mount_filesystem:
        volume_partition = Partition(
            id="volume-ntfs",
            slot="volume",
            start_sector=0,
            end_sector=0,
            length=0,
            description="BitLocker volume image without partition table",
        )
        _log_encryption_detected(
            db=db,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=source_type,
            partition=volume_partition,
            context="direct-volume-preflight",
            evidence=direct_evidence or {},
        )
        unlock = unlock_bitlocker_volume(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=f"{source_type}-volume",
            partition=volume_partition,
            options=bitlocker_options,
        )
        return _record_prepared_source(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source_path=unlock.source_path,
            source_type=unlock.source_type,
            partition=_unlocked_partition(volume_partition),
            mount_filesystem=mount_filesystem,
            use_sudo_mount=use_sudo_mount,
            filesystem_type="ntfs",
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
            message="Using direct Sleuth Kit access to NTFS volume image",
            details={"source": str(source_path), "source_type": f"{source_type}-volume"},
        )
        return _record_prepared_source(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=f"{source_type}-volume",
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
            filesystem_type=_filesystem_type_from_fsstat(fsstat_result.stdout),
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
            message="Using direct Sleuth Kit access to disk image",
            details={"source": str(source_path), "source_type": source_type},
        )

    if mmls_result.returncode != 0:
        if prepared.original_kind != "ewf":
            raise PartitionError(
                f"mmls failed with exit code {mmls_result.returncode} for {prepared.original_kind} source: {source_path}"
            )
        validate_ewfmount_available()
        ewf_command = build_ewfmount_command(source_path, ewf_dir, use_sudo=False, allow_other=True)
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
        source_type = "ewfmount" if prepared.source_type == "direct-e01" else "zip-ewfmount"
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
            ewf_volume_evidence = encrypted_filesystem_evidence(stdout=fsstat_result.stdout, stderr=fsstat_result.stderr)
            if is_bitlocker_evidence(ewf_volume_evidence) and bitlocker_options and bitlocker_options.enabled and mount_filesystem:
                volume_partition = Partition(
                    id="volume-ntfs",
                    slot="volume",
                    start_sector=0,
                    end_sector=0,
                    length=0,
                    description="BitLocker volume image without partition table",
                )
                _log_encryption_detected(
                    db=db,
                    case_id=case_id,
                    image=image,
                    source_path=source_path,
                    source_type="ewfmount-volume",
                    partition=volume_partition,
                    context="ewfmount-volume-preflight",
                    evidence=ewf_volume_evidence or {},
                )
                unlock = unlock_bitlocker_volume(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    source_path=source_path,
                    source_type="ewfmount-volume",
                    partition=volume_partition,
                    options=bitlocker_options,
                )
                return _record_prepared_source(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    source_path=unlock.source_path,
                    source_type=unlock.source_type,
                    partition=_unlocked_partition(volume_partition),
                    mount_filesystem=mount_filesystem,
                    use_sudo_mount=use_sudo_mount,
                    filesystem_type="ntfs",
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
                    filesystem_type=_filesystem_type_from_fsstat(fsstat_result.stdout),
                )
            raise PartitionError(f"mmls failed with exit code {mmls_result.returncode}")

    partitions = parse_mmls_output(mmls_result.stdout)
    partition = select_windows_partition(partitions)
    partition_evidence = encrypted_filesystem_evidence(partition_description=partition.description)
    if is_bitlocker_evidence(partition_evidence) and bitlocker_options and bitlocker_options.enabled and mount_filesystem:
        _log_encryption_detected(
            db=db,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=source_type,
            partition=partition,
            context="partition-description-preflight",
            evidence=partition_evidence or {},
        )
        unlock = unlock_bitlocker_volume(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source_path=source_path,
            source_type=source_type,
            partition=partition,
            options=bitlocker_options,
        )
        return _record_prepared_source(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            source_path=unlock.source_path,
            source_type=unlock.source_type,
            partition=_unlocked_partition(partition),
            mount_filesystem=mount_filesystem,
            use_sudo_mount=use_sudo_mount,
        )
    assert_not_encrypted(
        db=db,
        case_id=case_id,
        image=image,
        source_path=source_path,
        source_type=source_type,
        partition=partition,
        context="partition-description-preflight",
    )
    unlocked = _run_encryption_preflight(
        db=db,
        paths=paths,
        case_id=case_id,
        image=image,
        source_path=source_path,
        source_type=source_type,
        partition=partition,
        output_folder=mount_jobs / "fsstat-selected-partition",
        mount_filesystem=mount_filesystem,
        bitlocker_options=bitlocker_options,
    )
    if unlocked is not None:
        source_path, source_type, partition = unlocked
        selected_filesystem_type = "ntfs"
    else:
        selected_filesystem_type = _filesystem_type_from_fsstat(
            _latest_fsstat_stdout(db, case_id=case_id, image_id=image.id, output_folder=mount_jobs / "fsstat-selected-partition")
        ) or _filesystem_type_from_partition(partition)
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
        filesystem_type=selected_filesystem_type,
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
    ntfs_mounted = mount_path.exists() and mount_path.is_mount()
    if not dry_run and not ntfs_mounted:
        db.log_activity(
            case_id=case_id,
            image_id=image.id,
            computer_id=image.computer_id,
            level="warning",
            event="volume.unmount_skipped_stale",
            message="Recorded NTFS mount path is not currently mounted; skipping NTFS unmount",
            details={"mount_path": str(mount_path), "use_sudo": use_sudo_mount},
        )
    if ntfs_mounted or dry_run:
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
    source_type = mount_row["source_type"]
    if "bitlocker" in source_type:
        cleanup = _latest_bitlocker_cleanup(db, case_id=case_id, image_id=image.id)
        cleanup_bitlocker_layers(
            db=db,
            paths=paths,
            case_id=case_id,
            image=image,
            cleanup=cleanup,
            use_sudo=use_sudo_mount,
            dry_run=dry_run,
        )
    if source_type in {"ewfmount", "ewfmount-volume"} or source_type.startswith(("ewfmount-", "zip-ewfmount-")):
        if source_type.endswith("-loop"):
            loop_device = Path(mount_row["raw_path"])
            if not dry_run:
                _detach_loopback(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    loop_device=loop_device,
                    use_sudo_mount=use_sudo_mount,
                    reason="unmount",
                )
            db.log_activity(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                event="loopback.detached" if not dry_run else "loopback.detach_dry_run",
                message="Detached read-only loopback partition view" if not dry_run else "Dry-run recorded loopback detach",
                details={"loop_device": str(loop_device), "use_sudo": use_sudo_mount},
            )
        ewf_mount_path = Path(mount_row["ewf_mount_path"])
        if not dry_run and not (ewf_mount_path.exists() and ewf_mount_path.is_mount()):
            db.log_activity(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                level="warning",
                event="ewfmount.unmount_skipped_stale",
                message="Recorded EWF mount path is not currently mounted; skipping EWF unmount",
                details={"mount_path": str(ewf_mount_path), "use_sudo": False},
            )
            return mount_path
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


def _latest_bitlocker_cleanup(db: Database, *, case_id: str, image_id: str) -> list[dict[str, object]]:
    row = db.conn.execute(
        """
        SELECT details_json
        FROM activity_log
        WHERE case_id = ? AND image_id = ? AND event = 'image.encryption_unlocked'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (case_id, image_id),
    ).fetchone()
    if row is None:
        return []
    try:
        details = json.loads(row["details_json"] or "{}")
    except (TypeError, ValueError):
        return []
    cleanup = details.get("cleanup") if isinstance(details, dict) else None
    return cleanup if isinstance(cleanup, list) else []
