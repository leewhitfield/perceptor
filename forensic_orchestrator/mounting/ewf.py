from __future__ import annotations

from pathlib import Path
from shutil import which

from forensic_orchestrator.safety import require_dependency


def build_ewfmount_command(
    image_path: Path,
    mount_dir: Path,
    *,
    use_sudo: bool = False,
    allow_other: bool = False,
) -> list[str]:
    binary = (which("ewfmount") or "ewfmount") if use_sudo else "ewfmount"
    command = [binary]
    if allow_other:
        command.extend(["-X", "allow_other"])
    command.extend([str(image_path), str(mount_dir)])
    if use_sudo:
        return ["sudo", "-n", *command]
    return command


def validate_ewfmount_available() -> None:
    require_dependency("ewfmount")
