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


def build_losetup_offset_command(raw_image: Path, partition: Partition, *, use_sudo: bool = False) -> list[str]:
    command = [
        _command_path("losetup", use_sudo=use_sudo),
        "-f",
        "--show",
        "-r",
        "-o",
        str(partition.offset_bytes),
        str(raw_image),
    ]
    if use_sudo:
        return ["sudo", "-n", *command]
    return command


def build_losetup_detach_command(loop_device: str, *, use_sudo: bool = False) -> list[str]:
    command = [_command_path("losetup", use_sudo=use_sudo), "-d", loop_device]
    if use_sudo:
        return ["sudo", "-n", *command]
    return command


def build_ntfs_loop_mount_command(
    loop_device: str,
    mount_dir: Path,
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
    command = [
        _command_path("ntfs-3g", use_sudo=use_sudo),
        "-o",
        ",".join(option_parts),
        loop_device,
        str(mount_dir),
    ]
    if use_sudo:
        return ["sudo", "-n", *command]
    return command


def build_generic_mount_command(
    raw_image: Path,
    mount_dir: Path,
    partition: Partition,
    *,
    use_sudo: bool = False,
) -> list[str]:
    options = f"ro,loop,offset={partition.offset_bytes}"
    command = [
        _command_path("mount", use_sudo=use_sudo),
        "-o",
        options,
        str(raw_image),
        str(mount_dir),
    ]
    if use_sudo:
        return ["sudo", "-n", *command]
    return command


def build_filesystem_mount_command(
    raw_image: Path,
    mount_dir: Path,
    partition: Partition,
    *,
    filesystem_type: str | None = None,
    use_sudo: bool = False,
    norecover: bool = False,
) -> list[str]:
    if (filesystem_type or "").casefold() == "ntfs":
        return build_ntfs_mount_command(
            raw_image,
            mount_dir,
            partition,
            use_sudo=use_sudo,
            norecover=norecover,
        )
    return build_generic_mount_command(raw_image, mount_dir, partition, use_sudo=use_sudo)


def build_umount_command(mount_dir: Path, *, use_sudo: bool = False) -> list[str]:
    command = [_command_path("umount", use_sudo=use_sudo), str(mount_dir)]
    if use_sudo:
        return ["sudo", "-n", *command]
    return command


def validate_mount_available(filesystem_type: str | None = None) -> None:
    if (filesystem_type or "").casefold() == "ntfs":
        require_dependency("ntfs-3g")
    else:
        require_dependency("mount")
