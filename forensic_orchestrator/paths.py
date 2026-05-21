from __future__ import annotations

from pathlib import Path


DEFAULT_ROOT = Path("/var/lib/forensic-orchestrator")


class WorkspacePaths:
    def __init__(self, root: Path | str = DEFAULT_ROOT) -> None:
        self.root = Path(root)

    def case_dir(self, case_id: str) -> Path:
        return self.root / "cases" / case_id

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

    def ewf_mount_dir(self, case_id: str) -> Path:
        return self.mounts_dir(case_id) / "ewf"

    def ewf_raw_path(self, case_id: str) -> Path:
        return self.ewf_mount_dir(case_id) / "ewf1"

    def volume_mount_dir(self, case_id: str, partition_id: str) -> Path:
        return self.mounts_dir(case_id) / "volumes" / partition_id

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
            self.ewf_mount_dir(case_id),
            self.mounts_dir(case_id) / "volumes",
        ):
            path.mkdir(parents=True, exist_ok=True)

    def ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
