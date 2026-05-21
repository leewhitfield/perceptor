from __future__ import annotations

import shutil
from pathlib import Path


class OrchestratorError(RuntimeError):
    pass


class MissingDependencyError(OrchestratorError):
    pass


class EvidenceNotFoundError(OrchestratorError):
    pass


class MountError(OrchestratorError):
    pass


class PartitionError(OrchestratorError):
    pass


class EncryptedImageError(OrchestratorError):
    pass


class ToolError(OrchestratorError):
    pass


def require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise EvidenceNotFoundError(f"{label} does not exist: {path}")
    if not path.is_file():
        raise EvidenceNotFoundError(f"{label} is not a file: {path}")


def require_dependency(executable: str) -> None:
    if shutil.which(executable) is None:
        raise MissingDependencyError(f"Missing dependency: {executable}")
