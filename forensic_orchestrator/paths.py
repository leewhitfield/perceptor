from __future__ import annotations

import os
import re
from pathlib import Path


DEFAULT_ROOT = Path("/var/lib/perceptor")
DEFAULT_LIVE_MOUNT_ROOT = Path("/tmp/perceptor-mounts")
_SAFE_PATH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def validate_workspace_id(value: str, *, field: str = "identifier") -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if text in {".", ".."} or "/" in text or "\\" in text:
        raise ValueError(f"{field} must be a single path-safe identifier")
    if any(char in text for char in "[]{}*?"):
        raise ValueError(f"{field} contains unsupported wildcard characters")
    if not _SAFE_PATH_ID.fullmatch(text):
        raise ValueError(f"{field} contains unsupported characters")
    return text


class WorkspacePaths:
    def __init__(self, root: Path | str = DEFAULT_ROOT, live_mount_root: Path | str | None = None) -> None:
        self.root = Path(root)
        configured_mount_root = live_mount_root or os.environ.get("PERCEPTOR_MOUNT_ROOT") or os.environ.get("FORENSIC_MOUNT_ROOT")
        self.live_mount_root = Path(configured_mount_root) if configured_mount_root else DEFAULT_LIVE_MOUNT_ROOT

    def case_dir(self, case_id: str) -> Path:
        return self.root / "cases" / validate_workspace_id(case_id, field="case_id")

    def db_path(self) -> Path:
        return self.root / "orchestrator.sqlite3"

    def logs_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "logs"

    def images_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "images"

    def jobs_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "jobs"

    def outputs_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "outputs"

    def artifacts_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "artifacts"

    def analytics_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "analytics"

    def analytics_db_path(self, case_id: str) -> Path:
        return self.analytics_dir(case_id) / "events.duckdb"

    def parquet_dir(self, case_id: str) -> Path:
        return self.analytics_dir(case_id) / "parquet"

    def mounts_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "mounts"

    def live_mounts_dir(self, case_id: str) -> Path:
        return self.live_mount_root / "cases" / validate_workspace_id(case_id, field="case_id")

    def vsc_work_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "vsc-work"

    def vshadow_mount_dir(self, case_id: str) -> Path:
        return self.vsc_work_dir(case_id) / "vshadow"

    def vsc_snapshot_mount_dir(self, case_id: str, snapshot_id: str) -> Path:
        return self.vsc_work_dir(case_id) / "snapshots" / validate_workspace_id(snapshot_id, field="snapshot_id") / "volume"

    def vsc_snapshot_extract_dir(self, case_id: str, snapshot_id: str) -> Path:
        return self.vsc_work_dir(case_id) / "extracts" / validate_workspace_id(snapshot_id, field="snapshot_id")

    def vsc_parsed_dir(self, case_id: str) -> Path:
        return self.vsc_work_dir(case_id) / "parsed"

    def vsc_parsed_db_path(self, case_id: str) -> Path:
        return self.vsc_parsed_dir(case_id) / "vsc.duckdb"

    def vsc_reports_dir(self, case_id: str) -> Path:
        return self.vsc_work_dir(case_id) / "reports"

    def ewf_mount_dir(self, case_id: str) -> Path:
        return self.live_mounts_dir(case_id) / "ewf"

    def ewf_raw_path(self, case_id: str) -> Path:
        return self.ewf_mount_dir(case_id) / "ewf1"

    def volume_mount_dir(self, case_id: str, partition_id: str) -> Path:
        return self.live_mounts_dir(case_id) / "volumes" / validate_workspace_id(partition_id, field="partition_id")

    def ensure_case_tree(self, case_id: str) -> None:
        for path in (
            self.case_dir(case_id),
            self.logs_dir(case_id),
            self.images_dir(case_id),
            self.jobs_dir(case_id),
            self.outputs_dir(case_id),
            self.artifacts_dir(case_id),
            self.analytics_dir(case_id),
            self.parquet_dir(case_id),
            self.mounts_dir(case_id),
            self.ewf_mount_dir(case_id),
            self.live_mounts_dir(case_id) / "volumes",
            self.vsc_work_dir(case_id),
            self.vsc_parsed_dir(case_id),
            self.vsc_reports_dir(case_id),
        ):
            path.mkdir(parents=True, exist_ok=True)

    def ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
