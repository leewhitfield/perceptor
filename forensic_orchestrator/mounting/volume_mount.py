from __future__ import annotations

from pathlib import Path
from shutil import which

from forensic_orchestrator.models import Partition
from forensic_orchestrator.safety import require_dependency


def _command_path(name: str, *, use_sudo: bool) -> str:
    if not use_sudo:
        return name
    return which(name) or name


def build_ntfs_mount_command(
    raw_image: Path,
    mount_dir: Path,
    partition: Partition,
    *,
    use_sudo: bool = False,
    norecover: bool = False,
) -> list[str]:
    option_parts = [
        "ro",
        "show_sys_files",
        "streams_interface=windows",
    ]
    if norecover:
        option_parts.append("norecover")
    option_parts.append(f"offset={partition.offset_bytes}")
    options = (
        ",".join(option_parts)
    )
    command = [
        _command_path("ntfs-3g", use_sudo=use_sudo),
        "-o",
        options,
        str(raw_image),
        str(mount_dir),
    ]
    if use_sudo:
        return ["sudo", "-n", *command]
    return command


def build_umount_command(mount_dir: Path, *, use_sudo: bool = False) -> list[str]:
    command = [_command_path("umount", use_sudo=use_sudo), str(mount_dir)]
    if use_sudo:
        return ["sudo", "-n", *command]
    return command


def validate_mount_available() -> None:
    require_dependency("ntfs-3g")
