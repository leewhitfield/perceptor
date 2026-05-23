from __future__ import annotations

import fnmatch
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
import subprocess

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.jobs import JobRunner
from forensic_orchestrator.models import ArtifactDefinition, ExtractedArtifact
from forensic_orchestrator.safety import ToolError, require_dependency


@dataclass(frozen=True)
class FlsEntry:
    inode: str
    path: str
    is_directory: bool
    kind: str = ""

    @property
    def active_name(self) -> bool:
        return not self.kind.startswith("-/")


def build_fls_command(raw_image: Path, offset_sectors: int) -> list[str]:
    return ["fls", "-f", "ntfs", "-r", "-p", "-o", str(offset_sectors), str(raw_image)]


def build_icat_command(raw_image: Path, offset_sectors: int, inode: str) -> list[str]:
    return ["icat", "-f", "ntfs", "-o", str(offset_sectors), str(raw_image), inode]


def build_istat_command(raw_image: Path, offset_sectors: int, inode: str) -> list[str]:
    return ["istat", "-f", "ntfs", "-o", str(offset_sectors), str(raw_image), inode]


def validate_tsk_available() -> None:
    require_dependency("fls")
    require_dependency("icat")
    require_dependency("istat")


def parse_fls_output(output: str) -> list[FlsEntry]:
    entries: list[FlsEntry] = []
    pattern = re.compile(r"^(?P<kind>[-rdv]/[-rdv])\s+(?P<inode>[^:]+):\s*(?P<path>.+)$")
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        path = match.group("path")
        if " (deleted)" in path:
            path = path.replace(" (deleted)", "")
        raw_inode = match.group("inode")
        inode = raw_inode if ":" in path else raw_inode.split("-")[0]
        entries.append(
            FlsEntry(
                inode=inode,
                path=path,
                is_directory=match.group("kind").startswith("d/"),
                kind=match.group("kind"),
            )
        )
    return entries


def list_files(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    raw_image: Path,
    offset_sectors: int,
    output_folder: Path,
    dry_run: bool,
) -> list[FlsEntry]:
    command = build_fls_command(raw_image, offset_sectors)
    output_folder.mkdir(parents=True, exist_ok=True)
    stdout_path = output_folder / "stdout.txt"
    stderr_path = output_folder / "stderr.txt"
    if dry_run:
        JobRunner(db).run(
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool_name="fls",
            command=command,
            output_folder=output_folder,
            dry_run=True,
        )
        return []

    if stdout_path.exists() and stdout_path.stat().st_size > 0:
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            event="fls.cache_used",
            message="Using cached Sleuth Kit file listing",
            details={
                "command": command,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            },
        )
        return parse_fls_output(stdout_path.read_text(errors="replace"))

    job_id = str(uuid.uuid4())
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "tool_name": "fls",
            "tool_version": None,
            "command": command,
            "start_time": utc_now(),
            "end_time": None,
            "exit_code": None,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "output_folder": output_folder,
            "dry_run": False,
        }
    )
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    stdout_path.write_text(completed.stdout)
    stderr_path.write_text(completed.stderr)
    db.finish_job(job_id, utc_now(), completed.returncode)
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        level="error" if completed.returncode != 0 else "info",
        event="job.finished",
        message=f"Finished fls with exit code {completed.returncode}",
        details={
            "command": command,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        },
    )
    if completed.returncode != 0:
        raise ToolError(f"fls failed with exit code {completed.returncode}; stderr={stderr_path}")
    return parse_fls_output(completed.stdout)


def _safe_relative_path(value: str) -> Path:
    clean = value.replace("\\", "/").lstrip("/")
    parts = [part for part in clean.split("/") if part not in {"", ".", ".."}]
    return Path(*parts) if parts else Path("artifact")


def _run_icat_to_file(
    *,
    db: Database,
    runner: JobRunner,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    raw_image: Path,
    offset_sectors: int,
    inode: str,
    destination: Path,
    dry_run: bool,
) -> None:
    command = build_icat_command(raw_image, offset_sectors, inode)
    output_folder = destination.parent / "_extract_jobs" / destination.name
    if dry_run:
        runner.run(
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool_name="icat",
            command=command,
            output_folder=output_folder,
            dry_run=True,
        )
        return

    output_folder.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    job_id = str(uuid.uuid4())
    stdout_path = output_folder / "stdout.txt"
    stderr_path = output_folder / "stderr.txt"
    start_time = utc_now()
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "tool_name": "icat",
            "tool_version": None,
            "command": command,
            "start_time": start_time,
            "end_time": None,
            "exit_code": None,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "output_folder": output_folder,
            "dry_run": False,
        }
    )
    with destination.open("wb") as extracted, stderr_path.open("wb") as stderr:
        completed = subprocess.run(command, stdout=extracted, stderr=stderr, check=False)
    stdout_path.write_text(str(destination) + "\n")
    end_time = utc_now()
    db.finish_job(job_id, end_time, completed.returncode)
    stderr_text = stderr_path.read_text(errors="replace") if stderr_path.exists() else ""
    extraction_caveat = completed.returncode != 0 and _is_ntfs_decompression_error(stderr_text)
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        level="warning" if extraction_caveat else ("error" if completed.returncode != 0 else "info"),
        event="extraction.caveat" if extraction_caveat else "job.finished",
        message=(
            f"Extraction caveat for {destination.name}: NTFS decompression failed"
            if extraction_caveat
            else f"Finished icat with exit code {completed.returncode}"
        ),
        details={
            "command": command,
            "target": destination.name,
            "destination": str(destination),
            "stderr_path": str(stderr_path),
            "stderr": stderr_text.strip(),
            "caveat_type": "ntfs_decompression" if extraction_caveat else None,
        },
    )
    if completed.returncode != 0:
        raise ToolError(f"icat failed for inode {inode}; stderr={stderr_path}")


def _is_ntfs_decompression_error(stderr_text: str) -> bool:
    lowered = stderr_text.lower()
    return "ntfs_uncompress" in lowered or "error extracting file from image" in lowered


def read_file_metadata(
    *,
    raw_image: Path,
    offset_sectors: int,
    inode: str,
    dry_run: bool,
) -> dict[str, str]:
    if dry_run:
        return {}
    command = build_istat_command(raw_image, offset_sectors, inode)
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise ToolError(f"istat failed for inode {inode}: {completed.stderr.strip()}")
    return parse_istat_metadata(completed.stdout)


def parse_istat_metadata(output: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    in_standard_information = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "$STANDARD_INFORMATION Attribute Values:":
            in_standard_information = True
            continue
        if stripped == "$FILE_NAME Attribute Values:":
            in_standard_information = False
            continue
        if not in_standard_information or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "created":
            metadata["mft_created"] = value
        elif key == "file modified":
            metadata["mft_modified"] = value
        elif key == "accessed":
            metadata["mft_accessed"] = value
        elif key == "mft modified":
            metadata["mft_record_modified"] = value
    return metadata


def write_extraction_manifest(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    import csv

    manifest_path = path / "_artifact_manifest.csv"
    fieldnames = [
        "artifact_path",
        "original_path",
        "inode",
        "extraction_method",
        "partial",
        "header_valid",
        "original_size",
        "recovered_size",
        "readable_bytes",
        "failed_block_count",
        "failed_offsets",
        "mft_created",
        "mft_modified",
        "mft_accessed",
        "mft_record_modified",
        "mft_in_use",
        "path_unresolved",
        "deleted_mft_entry",
        "live_orphan",
    ]
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def extract_artifact(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    raw_image: Path,
    offset_sectors: int,
    artifact: ArtifactDefinition,
    artifacts_root: Path,
    dry_run: bool,
    fls_entries: list[FlsEntry] | None = None,
    ignore_exclude_patterns: bool = False,
) -> ExtractedArtifact:
    runner = JobRunner(db)
    destination = artifacts_root / artifact.destination

    if artifact.inode:
        _run_icat_to_file(
            db=db,
            runner=runner,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            inode=artifact.inode,
            destination=destination,
            dry_run=dry_run,
        )
        db.insert_artifact(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "image_id": image_id,
                "name": artifact.name,
                "source": artifact.source,
                "path": destination,
                "kind": "file",
                "metadata": {"inode": artifact.inode},
            }
        )
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            event="artifact.extracted",
            message=f"Extracted artifact {artifact.name}",
            details={"artifact": artifact.name, "path": str(destination), "count": 1},
        )
        return ExtractedArtifact(artifact.name, destination, artifact.source, "file", {"inode": artifact.inode})

    entries = fls_entries or []
    source_prefix = artifact.source.rstrip("/")
    source_prefix_lower = source_prefix.lower()
    if artifact.recursive:
        destination.mkdir(parents=True, exist_ok=True)
        if dry_run:
            db.insert_artifact(
                {
                    "id": str(uuid.uuid4()),
                    "case_id": case_id,
                    "image_id": image_id,
                    "name": artifact.name,
                    "source": artifact.source,
                    "path": destination,
                    "kind": "directory",
                    "metadata": {"dry_run": True, "count": 0},
                }
            )
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                event="artifact.dry_run",
                message=f"Dry-run recorded recursive artifact extraction for {artifact.name}",
                details={"artifact": artifact.name, "source_path": artifact.source, "path": str(destination)},
            )
            return ExtractedArtifact(
                artifact.name,
                destination,
                artifact.source,
                "directory",
                {"dry_run": True, "count": 0},
            )
        patterns = artifact.patterns or ((artifact.pattern,) if artifact.pattern else ())
        include_path_patterns = artifact.include_path_patterns
        exclude_patterns = () if ignore_exclude_patterns else artifact.exclude_patterns
        matched = [
            entry
            for entry in entries
            if not entry.is_directory
            and (
                not source_prefix_lower
                or entry.path.lower().startswith(source_prefix_lower + "/")
            )
            and (
                not patterns
                or any(
                    fnmatch.fnmatch(Path(entry.path).name.lower(), pattern.lower())
                    for pattern in patterns
                )
            )
            and (
                not include_path_patterns
                or any(
                    fnmatch.fnmatch(entry.path.lower(), pattern.lower())
                    for pattern in include_path_patterns
                )
            )
            and not any(
                fnmatch.fnmatch(entry.path.lower(), exclude_pattern.lower())
                for exclude_pattern in exclude_patterns
            )
        ]
        manifest_rows: list[dict[str, str]] = []
        failed_count = 0
        for entry in matched:
            relative = Path(entry.path[len(source_prefix) :].lstrip("/")) if source_prefix else Path(entry.path)
            extracted_path = destination / _safe_relative_path(str(relative))
            try:
                _run_icat_to_file(
                    db=db,
                    runner=runner,
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=computer_id,
                    raw_image=raw_image,
                    offset_sectors=offset_sectors,
                    inode=entry.inode,
                    destination=extracted_path,
                    dry_run=dry_run,
                )
            except ToolError as exc:
                failed_count += 1
                if extracted_path.exists():
                    extracted_path.unlink()
                db.log_activity(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    level="warning",
                    event="artifact.extract_failed",
                    message=f"Skipped unreadable artifact file for {artifact.name}",
                    details={
                        "artifact": artifact.name,
                        "source_path": entry.path,
                        "inode": entry.inode,
                        "destination": str(extracted_path),
                        "error": str(exc),
                    },
                )
                continue
            try:
                metadata = read_file_metadata(
                    raw_image=raw_image,
                    offset_sectors=offset_sectors,
                    inode=entry.inode,
                    dry_run=dry_run,
                )
            except ToolError as exc:
                metadata = {}
                db.log_activity(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    level="warning",
                    event="artifact.metadata_failed",
                    message=f"Could not read metadata for extracted artifact file {artifact.name}",
                    details={
                        "artifact": artifact.name,
                        "source_path": entry.path,
                        "inode": entry.inode,
                        "destination": str(extracted_path),
                        "error": str(exc),
                    },
                )
            manifest_rows.append(
                {
                    "artifact_path": str(extracted_path),
                    "original_path": entry.path,
                    "inode": entry.inode,
                    **metadata,
                }
            )
        write_extraction_manifest(destination, manifest_rows)
        db.insert_artifact(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "image_id": image_id,
                "name": artifact.name,
                "source": artifact.source,
                "path": destination,
                "kind": "directory",
                "metadata": {
                    "count": len(matched),
                    "extracted_count": len(manifest_rows),
                    "failed_count": failed_count,
                    "pattern": artifact.pattern,
                    "patterns": list(artifact.patterns),
                    "include_path_patterns": list(artifact.include_path_patterns),
                    "exclude_patterns": list(exclude_patterns),
                },
            }
        )
        level = "warning" if len(matched) == 0 or failed_count else "info"
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level=level,
            event="artifact.extracted",
            message=(
                f"No files found for artifact {artifact.name}"
                if len(matched) == 0
                else f"Extracted {len(manifest_rows)} of {len(matched)} files for artifact {artifact.name}"
            ),
            details={
                "artifact": artifact.name,
                "path": str(destination),
                "count": len(matched),
                "extracted_count": len(manifest_rows),
                "failed_count": failed_count,
                "pattern": artifact.pattern,
                "patterns": list(artifact.patterns),
                "include_path_patterns": list(artifact.include_path_patterns),
                "exclude_patterns": list(exclude_patterns),
            },
        )
        return ExtractedArtifact(
            artifact.name,
            destination,
            artifact.source,
            "directory",
            {"count": len(matched), "extracted_count": len(manifest_rows), "failed_count": failed_count},
        )

    matches = [
        entry for entry in entries if entry.path.lower() == artifact.source.lower() and not entry.is_directory
    ]
    if dry_run and not matches:
        db.insert_artifact(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "image_id": image_id,
                "name": artifact.name,
                "source": artifact.source,
                "path": destination,
                "kind": "file",
                "metadata": {"dry_run": True, "count": 0},
            }
        )
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            event="artifact.dry_run",
            message=f"Dry-run recorded artifact extraction for {artifact.name}",
            details={"artifact": artifact.name, "source_path": artifact.source, "path": str(destination)},
        )
        return ExtractedArtifact(
            artifact.name,
            destination,
            artifact.source,
            "file",
            {"dry_run": True, "count": 0},
        )
    if not matches:
        if artifact.optional:
            db.insert_artifact(
                {
                    "id": str(uuid.uuid4()),
                    "case_id": case_id,
                    "image_id": image_id,
                    "name": artifact.name,
                    "source": artifact.source,
                    "path": destination,
                    "kind": "file",
                    "metadata": {"optional": True, "missing": True, "count": 0},
                }
            )
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                level="warning",
                event="artifact.optional_missing",
                message=f"Optional artifact source not found via fls: {artifact.name}",
                details={"artifact": artifact.name, "source_path": artifact.source},
            )
            return ExtractedArtifact(
                artifact.name,
                destination,
                artifact.source,
                "file",
                {"optional": True, "missing": True, "count": 0},
            )
        raise ToolError(f"Artifact source not found via fls: {artifact.source}")
    _run_icat_to_file(
        db=db,
        runner=runner,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        raw_image=raw_image,
        offset_sectors=offset_sectors,
        inode=matches[0].inode,
        destination=destination,
        dry_run=dry_run,
    )
    db.insert_artifact(
        {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "image_id": image_id,
            "name": artifact.name,
            "source": artifact.source,
            "path": destination,
            "kind": "file",
            "metadata": {"inode": matches[0].inode},
        }
    )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        event="artifact.extracted",
        message=f"Extracted artifact {artifact.name}",
        details={"artifact": artifact.name, "path": str(destination), "count": 1},
    )
    return ExtractedArtifact(artifact.name, destination, artifact.source, "file", {"inode": matches[0].inode})
