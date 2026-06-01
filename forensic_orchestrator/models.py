from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class Case:
    id: str
    root: Path
    created_at: str


@dataclass(frozen=True)
class EvidenceImage:
    id: str
    case_id: str
    path: Path
    created_at: str
    computer_id: Optional[str] = None


@dataclass(frozen=True)
class Computer:
    id: str
    case_id: str
    label: str
    hostname: Optional[str]
    notes: Optional[str]
    created_at: str


@dataclass(frozen=True)
class Partition:
    id: str
    slot: str
    start_sector: int
    end_sector: int
    length: int
    description: str
    sector_size: int = 512

    @property
    def offset_bytes(self) -> int:
        return self.start_sector * self.sector_size

    @property
    def likely_ntfs(self) -> bool:
        text = self.description.lower()
        return "ntfs" in text or "basic data" in text or "windows" in text


@dataclass(frozen=True)
class ArtifactDefinition:
    name: str
    source: str
    destination: str
    inode: Optional[str] = None
    recursive: bool = False
    pattern: Optional[str] = None
    patterns: tuple[str, ...] = ()
    include_path_patterns: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    process_in_place: bool = False
    allow_partial: bool = False
    use_tsk: bool = False
    optional: bool = False
    recovery: dict[str, Any] | None = None
    extraction_limits: dict[str, Any] | None = None


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    enabled: bool
    type: str
    executable: Optional[str]
    command: list[str]
    required_paths: list[str]
    outputs: list[str]
    artifacts: list[ArtifactDefinition]


@dataclass(frozen=True)
class ExtractedArtifact:
    name: str
    path: Path
    source: str
    kind: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class JobRecord:
    id: str
    case_id: str
    image_id: str
    tool_name: str
    tool_version: Optional[str]
    command: list[str]
    start_time: str
    end_time: Optional[str]
    exit_code: Optional[int]
    stdout_path: Path
    stderr_path: Path
    output_folder: Path
    dry_run: bool
