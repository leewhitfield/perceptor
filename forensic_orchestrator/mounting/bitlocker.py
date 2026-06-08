from __future__ import annotations

import getpass
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Any

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage, Partition
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError, ToolError


@dataclass(frozen=True)
class BitLockerUnlockOptions:
    enabled: bool = False
    tool: str = "auto"
    method: str = "recovery-key"
    key_file: Path | None = None
    secret: str | None = None
    use_sudo: bool = False


@dataclass(frozen=True)
class BitLockerUnlockResult:
    source_path: Path
    source_type: str
    cleanup: list[dict[str, Any]]
    tool: str
    method: str
    offset_bytes: int


def unlock_bitlocker_volume(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition,
    options: BitLockerUnlockOptions,
) -> BitLockerUnlockResult:
    if not options.enabled:
        raise MountError("BitLocker unlock requested without --unlock-bitlocker")
    secret = _secret_for_options(options)
    attempts = _tool_order(options.tool)
    errors: list[dict[str, Any]] = []
    for tool in attempts:
        try:
            if tool == "cryptsetup":
                result = _unlock_with_cryptsetup(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    source_path=source_path,
                    source_type=source_type,
                    partition=partition,
                    options=options,
                    secret=secret,
                )
            elif tool == "dislocker":
                result = _unlock_with_dislocker(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    source_path=source_path,
                    source_type=source_type,
                    partition=partition,
                    options=options,
                    secret=secret,
                )
            elif tool == "bdemount":
                result = _unlock_with_bdemount(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    source_path=source_path,
                    source_type=source_type,
                    partition=partition,
                    options=options,
                    secret=secret,
                )
            else:
                raise MountError(f"Unsupported BitLocker unlock tool: {tool}")
            db.log_activity(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                event="image.encryption_unlocked",
                message=f"Unlocked BitLocker volume with {result.tool}",
                details={
                    "encryption_type": "BitLocker",
                    "tool": result.tool,
                    "method": result.method,
                    "source": str(source_path),
                    "source_type": source_type,
                    "unlocked_source": str(result.source_path),
                    "unlocked_source_type": result.source_type,
                    "partition_id": partition.id,
                    "offset_sectors": partition.start_sector,
                    "offset_bytes": result.offset_bytes,
                    "read_only": True,
                    "secret_stored": False,
                    "secret_source": "key_file" if options.key_file else "prompt",
                    "cleanup": result.cleanup,
                },
            )
            return result
        except Exception as exc:
            errors.append({"tool": tool, "error": str(exc)})
            db.log_activity(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                level="warning",
                event="image.encryption_unlock_failed",
                message=f"BitLocker unlock failed with {tool}",
                details={
                    "encryption_type": "BitLocker",
                    "tool": tool,
                    "method": options.method,
                    "partition_id": partition.id,
                    "offset_bytes": partition.offset_bytes,
                    "secret_stored": False,
                    "error": str(exc),
                },
            )
            cleanup_bitlocker_layers(
                db=db,
                paths=paths,
                case_id=case_id,
                image=image,
                cleanup=getattr(exc, "cleanup", []),
                use_sudo=options.use_sudo,
                dry_run=False,
            )
    raise MountError(f"BitLocker unlock failed with all configured tools: {errors}")


def cleanup_bitlocker_layers(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    cleanup: list[dict[str, Any]],
    use_sudo: bool,
    dry_run: bool,
) -> None:
    for item in reversed(cleanup):
        kind = item.get("kind")
        try:
            if kind == "cryptsetup":
                _run_logged_command(
                    db=db,
                    case_id=case_id,
                    image=image,
                    tool_name="cryptsetup",
                    command=_sudo(["cryptsetup", "close", str(item["name"])], use_sudo=use_sudo),
                    output_folder=paths.jobs_dir(case_id) / "mount" / "bitlocker-cryptsetup-close",
                    dry_run=dry_run,
                    check=False,
                )
            elif kind == "loop":
                _run_logged_command(
                    db=db,
                    case_id=case_id,
                    image=image,
                    tool_name="losetup",
                    command=_sudo(["losetup", "-d", str(item["device"])], use_sudo=use_sudo),
                    output_folder=paths.jobs_dir(case_id) / "mount" / "bitlocker-loop-detach",
                    dry_run=dry_run,
                    check=False,
                )
            elif kind in {"dislocker", "bdemount"}:
                mount_dir = Path(str(item["mount_dir"]))
                if dry_run or mount_dir.exists():
                    _run_logged_command(
                        db=db,
                        case_id=case_id,
                        image=image,
                        tool_name="umount",
                        command=_sudo(["umount", str(mount_dir)], use_sudo=use_sudo),
                        output_folder=paths.jobs_dir(case_id) / "mount" / f"bitlocker-{kind}-umount",
                        dry_run=dry_run,
                        check=False,
                    )
        except Exception as exc:
            db.log_activity(
                case_id=case_id,
                image_id=image.id,
                computer_id=image.computer_id,
                level="warning",
                event="image.encryption_cleanup_failed",
                message=f"BitLocker cleanup failed for {kind}",
                details={"cleanup": item, "error": str(exc)},
            )


def _unlock_with_cryptsetup(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition,
    options: BitLockerUnlockOptions,
    secret: str | None,
) -> BitLockerUnlockResult:
    _require("cryptsetup")
    _require("losetup")
    cleanup: list[dict[str, Any]] = []
    loop = _attach_loop(
        db=db,
        paths=paths,
        case_id=case_id,
        image=image,
        source_path=source_path,
        partition=partition,
        use_sudo=options.use_sudo,
    )
    cleanup.append({"kind": "loop", "device": loop})
    mapper = _mapper_name(case_id, image.id, partition.id)
    command = ["cryptsetup", "open", "--type", "bitlk", "--readonly"]
    stdin_text = None
    if _normalized_method(options.method) == "bek" and options.key_file is not None:
        command.extend(["--key-file", str(options.key_file.expanduser())])
    elif secret is not None:
        command.extend(["--key-file", "-"])
        stdin_text = secret.rstrip("\r\n") + "\n"
    command.extend([loop, mapper])
    try:
        _run_logged_command(
            db=db,
            case_id=case_id,
            image=image,
            tool_name="cryptsetup",
            command=_sudo(command, use_sudo=options.use_sudo),
            output_folder=paths.jobs_dir(case_id) / "mount" / "bitlocker-cryptsetup-open",
            dry_run=False,
            stdin_text=stdin_text,
        )
    except Exception as exc:
        setattr(exc, "cleanup", cleanup)
        raise
    cleanup.append({"kind": "cryptsetup", "name": mapper})
    return BitLockerUnlockResult(
        source_path=Path("/dev/mapper") / mapper,
        source_type=f"{source_type}-bitlocker-cryptsetup",
        cleanup=cleanup,
        tool="cryptsetup",
        method=options.method,
        offset_bytes=partition.offset_bytes,
    )


def _unlock_with_dislocker(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition,
    options: BitLockerUnlockOptions,
    secret: str | None,
) -> BitLockerUnlockResult:
    dislocker = which("dislocker") or which("dislocker-fuse")
    if not dislocker:
        raise MountError("Missing dependency: dislocker")
    mount_dir = paths.live_mounts_dir(case_id) / "bitlocker" / partition.id / "dislocker"
    mount_dir.mkdir(parents=True, exist_ok=True)
    cleanup = [{"kind": "dislocker", "mount_dir": str(mount_dir)}]
    command = [
        dislocker,
        "-r",
        "-V",
        str(source_path),
        "-O",
        str(partition.offset_bytes),
        *_dislocker_method_args(options.method, options.key_file),
        "--",
        str(mount_dir),
    ]
    try:
        _run_logged_command(
            db=db,
            case_id=case_id,
            image=image,
            tool_name="dislocker",
            command=_sudo(command, use_sudo=options.use_sudo),
            output_folder=paths.jobs_dir(case_id) / "mount" / "bitlocker-dislocker",
            dry_run=False,
            stdin_text=secret.rstrip("\r\n") + "\n" if secret is not None else None,
        )
        source = mount_dir / "dislocker-file"
        if not source.exists():
            raise MountError(f"dislocker completed but unlocked file was not found at {source}")
    except Exception as exc:
        setattr(exc, "cleanup", cleanup)
        raise
    return BitLockerUnlockResult(
        source_path=source,
        source_type=f"{source_type}-bitlocker-dislocker",
        cleanup=cleanup,
        tool="dislocker",
        method=options.method,
        offset_bytes=partition.offset_bytes,
    )


def _unlock_with_bdemount(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    source_type: str,
    partition: Partition,
    options: BitLockerUnlockOptions,
    secret: str | None,
) -> BitLockerUnlockResult:
    _require("bdemount")
    mount_dir = paths.live_mounts_dir(case_id) / "bitlocker" / partition.id / "bdemount"
    mount_dir.mkdir(parents=True, exist_ok=True)
    cleanup = [{"kind": "bdemount", "mount_dir": str(mount_dir)}]
    command = ["bdemount", "-o", str(partition.offset_bytes), str(source_path), str(mount_dir)]
    try:
        _run_logged_command(
            db=db,
            case_id=case_id,
            image=image,
            tool_name="bdemount",
            command=_sudo(command, use_sudo=options.use_sudo),
            output_folder=paths.jobs_dir(case_id) / "mount" / "bitlocker-bdemount",
            dry_run=False,
            stdin_text=secret.rstrip("\r\n") + "\n" if secret is not None else None,
        )
        candidates = [mount_dir / "bde1", mount_dir / "bde"]
        source = next((candidate for candidate in candidates if candidate.exists()), None)
        if source is None:
            raise MountError(f"bdemount completed but no bde volume file was found under {mount_dir}")
    except Exception as exc:
        setattr(exc, "cleanup", cleanup)
        raise
    return BitLockerUnlockResult(
        source_path=source,
        source_type=f"{source_type}-bitlocker-bdemount",
        cleanup=cleanup,
        tool="bdemount",
        method=options.method,
        offset_bytes=partition.offset_bytes,
    )


def _attach_loop(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    source_path: Path,
    partition: Partition,
    use_sudo: bool,
) -> str:
    command = [
        "losetup",
        "--find",
        "--show",
        "--read-only",
        "--offset",
        str(partition.offset_bytes),
    ]
    if partition.length:
        command.extend(["--sizelimit", str(partition.length * 512)])
    command.append(str(source_path))
    result = _run_logged_command(
        db=db,
        case_id=case_id,
        image=image,
        tool_name="losetup",
        command=_sudo(command, use_sudo=use_sudo),
        output_folder=paths.jobs_dir(case_id) / "mount" / "bitlocker-loop",
        dry_run=False,
    )
    loop = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if not loop.startswith("/dev/"):
        raise MountError(f"losetup did not return a loop device: {loop!r}")
    return loop


@dataclass(frozen=True)
class _LoggedResult:
    returncode: int
    stdout: str
    stderr: str


def _run_logged_command(
    *,
    db: Database,
    case_id: str,
    image: EvidenceImage,
    tool_name: str,
    command: list[str],
    output_folder: Path,
    dry_run: bool,
    stdin_text: str | None = None,
    check: bool = True,
) -> _LoggedResult:
    job_id = str(uuid.uuid4())
    job_dir = output_folder / "_job"
    job_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = job_dir / "stdout.txt"
    stderr_path = job_dir / "stderr.txt"
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image.id,
            "computer_id": image.computer_id,
            "tool_name": tool_name,
            "tool_version": None,
            "command": command,
            "start_time": utc_now(),
            "end_time": utc_now() if dry_run else None,
            "exit_code": 0 if dry_run else None,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "output_folder": output_folder,
            "dry_run": dry_run,
        }
    )
    db.log_activity(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        job_id=job_id,
        event="job.started",
        message=f"Started {tool_name}",
        details={"command": command, "output_folder": str(output_folder), "dry_run": dry_run, "stdin_supplied": stdin_text is not None},
    )
    if dry_run:
        stdout_path.write_text("DRY RUN: command not executed\n" + repr(command) + "\n")
        stderr_path.write_text("")
        return _LoggedResult(0, "", "")
    completed = subprocess.run(command, input=stdin_text, capture_output=True, text=True, check=False)
    stdout_path.write_text(completed.stdout)
    stderr_path.write_text(completed.stderr)
    db.finish_job(job_id, utc_now(), completed.returncode)
    db.log_activity(
        case_id=case_id,
        image_id=image.id,
        computer_id=image.computer_id,
        job_id=job_id,
        level="error" if completed.returncode != 0 else "info",
        event="job.finished",
        message=f"Finished {tool_name} with exit code {completed.returncode}",
        details={"exit_code": completed.returncode, "stdout_path": str(stdout_path), "stderr_path": str(stderr_path)},
    )
    if check and completed.returncode != 0:
        raise ToolError(
            f"{tool_name} failed with exit code {completed.returncode}; stdout={stdout_path} stderr={stderr_path}"
        )
    return _LoggedResult(completed.returncode, completed.stdout, completed.stderr)


def _read_secret(path: Path | None) -> str | None:
    if path is None:
        return None
    return path.expanduser().read_text(encoding="utf-8").strip()


def _secret_for_options(options: BitLockerUnlockOptions) -> str | None:
    if _normalized_method(options.method) == "bek":
        if options.key_file is None:
            raise MountError("BitLocker BEK/startup-key unlock requires --bitlocker-key-file")
        return None
    if options.secret:
        return options.secret
    if options.key_file is not None:
        return _read_secret(options.key_file)
    return getpass.getpass(f"BitLocker {options.method} (input hidden): ")


def _tool_order(tool: str) -> list[str]:
    normalized = tool.strip().casefold()
    if normalized == "auto":
        return ["cryptsetup", "dislocker", "bdemount"]
    if normalized in {"cryptsetup", "dislocker", "bdemount"}:
        return [normalized]
    raise MountError(f"Unsupported BitLocker tool: {tool}")


def _dislocker_method_args(method: str, key_file: Path | None) -> list[str]:
    normalized = _normalized_method(method)
    if normalized in {"recovery-key", "recovery", "recovery-password"}:
        return ["-p"]
    if normalized in {"password", "user-password"}:
        return ["-u"]
    if normalized in {"bek", "startup-key"}:
        return ["-f", str(key_file.expanduser())] if key_file is not None else ["-f"]
    if normalized == "fvek":
        return ["-k"]
    raise MountError(f"Unsupported BitLocker method for dislocker: {method}")


def _normalized_method(method: str) -> str:
    return method.strip().casefold().replace("_", "-")


def _mapper_name(case_id: str, image_id: str, partition_id: str) -> str:
    raw = f"perceptor-{case_id[:8]}-{image_id[:8]}-{partition_id}"
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in raw)[:120]


def _sudo(command: list[str], *, use_sudo: bool) -> list[str]:
    if not use_sudo:
        return command
    resolved = [which(command[0]) or command[0], *command[1:]]
    return ["sudo", "-n", *resolved]


def _require(name: str) -> None:
    if which(name) is None:
        raise MountError(f"Missing dependency: {name}")
