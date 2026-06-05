from __future__ import annotations

import fnmatch
import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import time

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.jobs import JobRunner, command_timeout_seconds
from forensic_orchestrator.models import ArtifactDefinition, ExtractedArtifact
from forensic_orchestrator.safety import ToolError, require_dependency


@dataclass(frozen=True)
class FlsEntry:
    inode: str
    path: str
    is_directory: bool
    kind: str = ""
    deleted: bool = False
    system: bool = False

    @property
    def active_name(self) -> bool:
        return not self.deleted and not self.kind.startswith("-/")


def _tsk_filesystem_type(filesystem_type: str | None) -> str:
    normalized = (filesystem_type or "ntfs").strip().casefold().replace("_", "").replace("-", "")
    if normalized in {"fat", "fat12", "fat16", "fat32", "vfat", "msdos"}:
        return "fat"
    if normalized in {"exfat"}:
        return "exfat"
    if normalized in {"ntfs"}:
        return "ntfs"
    return filesystem_type or "ntfs"


def build_fls_command(raw_image: Path, offset_sectors: int, *, filesystem_type: str | None = None) -> list[str]:
    return ["fls", "-f", _tsk_filesystem_type(filesystem_type), "-r", "-p", "-o", str(offset_sectors), str(raw_image)]


def build_icat_command(raw_image: Path, offset_sectors: int, inode: str, *, filesystem_type: str | None = None) -> list[str]:
    inode = _validate_inode(inode)
    return ["icat", "-f", _tsk_filesystem_type(filesystem_type), "-o", str(offset_sectors), str(raw_image), inode]


def build_istat_command(raw_image: Path, offset_sectors: int, inode: str, *, filesystem_type: str | None = None) -> list[str]:
    inode = _validate_inode(inode)
    return ["istat", "-f", _tsk_filesystem_type(filesystem_type), "-o", str(offset_sectors), str(raw_image), inode]


def _validate_inode(inode: str) -> str:
    text = str(inode or "").strip()
    if not text or text.startswith("-") or not re.fullmatch(r"[A-Za-z0-9:._-]+", text):
        raise ToolError(f"Unsafe Sleuth Kit inode value: {inode!r}")
    return text


def validate_tsk_available() -> None:
    require_dependency("fls")
    require_dependency("icat")
    require_dependency("istat")


def parse_fls_output(output: str) -> list[FlsEntry]:
    entries: list[FlsEntry] = []
    pattern = re.compile(
        r"^(?P<kind>[-rRdDvV]/[-rRdDvV])\s+(?P<deleted>\*)?\s*(?P<inode>[^:]+):\s*(?P<path>.+)$"
    )
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        path = match.group("path")
        deleted = bool(match.group("deleted")) or " (deleted)" in path
        if " (deleted)" in path:
            path = path.replace(" (deleted)", "")
        raw_inode = match.group("inode")
        inode = raw_inode if ":" in path else raw_inode.split("-")[0]
        kind = match.group("kind")
        normalized_kind = kind.lower()
        system = "v" in normalized_kind or path.endswith("(Volume Label Entry)")
        entries.append(
            FlsEntry(
                inode=inode,
                path=path,
                is_directory=normalized_kind.startswith("d/") or normalized_kind.endswith("/d"),
                kind=kind,
                deleted=deleted or normalized_kind.startswith("-/"),
                system=system,
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
    filesystem_type: str | None = None,
    output_folder: Path,
    dry_run: bool,
) -> list[FlsEntry]:
    command = build_fls_command(raw_image, offset_sectors, filesystem_type=filesystem_type)
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
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=command_timeout_seconds())
    except subprocess.TimeoutExpired as exc:
        stdout_path.write_text(exc.stdout or "", encoding="utf-8", errors="replace")
        stderr_path.write_text(exc.stderr or "", encoding="utf-8", errors="replace")
        db.finish_job(job_id, utc_now(), -9)
        raise ToolError(f"fls timed out after {command_timeout_seconds()} seconds; stderr={stderr_path}") from exc
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extraction_audit_row(
    *,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    artifact_name: str,
    source_path: str,
    extracted_path: Path,
    inode: str,
    metadata: dict[str, str] | None = None,
    status: str = "extracted",
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    metadata = metadata or {}
    try:
        stat = extracted_path.stat()
        size_bytes = stat.st_size
        sha256 = _sha256_file(extracted_path)
    except OSError:
        size_bytes = None
        sha256 = ""
    return {
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "artifact_name": artifact_name,
        "source_path": source_path,
        "extracted_path": str(extracted_path),
        "inode": inode,
        "extraction_method": "icat",
        "sha256": sha256,
        "size_bytes": size_bytes,
        "created_utc": metadata.get("created_utc"),
        "modified_utc": metadata.get("modified_utc"),
        "accessed_utc": metadata.get("accessed_utc"),
        "metadata_changed_utc": metadata.get("metadata_changed_utc"),
        "status": status,
        "details": details or {},
    }


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
    filesystem_type: str | None = None,
) -> None:
    command = build_icat_command(raw_image, offset_sectors, inode, filesystem_type=filesystem_type)
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
    if destination.exists() and destination.is_dir():
        raise ToolError(f"refusing to extract inode {inode} over existing directory: {destination}")
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
    try:
        with destination.open("wb") as extracted, stderr_path.open("wb") as stderr:
            completed = subprocess.run(command, stdout=extracted, stderr=stderr, check=False, timeout=command_timeout_seconds())
    except subprocess.TimeoutExpired as exc:
        stderr_path.write_bytes((exc.stderr or b"") if isinstance(exc.stderr, bytes) else str(exc.stderr or "").encode("utf-8", errors="replace"))
        db.finish_job(job_id, utc_now(), -9)
        raise ToolError(f"icat timed out for inode {inode}; stderr={stderr_path}") from exc
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
    filesystem_type: str | None = None,
    dry_run: bool,
) -> dict[str, str]:
    if dry_run:
        return {}
    command = build_istat_command(raw_image, offset_sectors, inode, filesystem_type=filesystem_type)
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=command_timeout_seconds())
    if completed.returncode != 0:
        raise ToolError(f"istat failed for inode {inode}: {completed.stderr.strip()}")
    return parse_istat_metadata(completed.stdout)


def parse_istat_metadata(output: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    in_standard_information = False
    for line in output.splitlines():
        stripped = line.strip()
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            normalized_key = key.strip().lower()
            normalized_value = value.strip()
            if normalized_key in {"size", "file size"} and normalized_value:
                metadata["file_size"] = normalized_value.split()[0]
            if normalized_value:
                timestamp = _normalize_istat_timestamp(normalized_value)
                if timestamp:
                    if normalized_key == "created":
                        metadata.setdefault("created_utc", timestamp)
                    elif normalized_key == "file modified":
                        metadata.setdefault("modified_utc", timestamp)
                    elif normalized_key == "accessed":
                        metadata.setdefault("accessed_utc", timestamp)
                    elif normalized_key in {"metadata modified", "metadata changed", "mft modified"}:
                        metadata.setdefault("metadata_changed_utc", timestamp)
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
            metadata["created_utc"] = _normalize_istat_timestamp(value) or value
        elif key == "file modified":
            metadata["mft_modified"] = value
            metadata["modified_utc"] = _normalize_istat_timestamp(value) or value
        elif key == "accessed":
            metadata["mft_accessed"] = value
            metadata["accessed_utc"] = _normalize_istat_timestamp(value) or value
        elif key == "mft modified":
            metadata["mft_record_modified"] = value
            metadata["metadata_changed_utc"] = _normalize_istat_timestamp(value) or value
    return metadata


def _normalize_istat_timestamp(value: str) -> str | None:
    text = value.strip()
    if not text:
        return None
    text = re.sub(r"\s*\((UTC|GMT)\)\s*$", "", text, flags=re.IGNORECASE).strip()
    match = re.match(
        r"^(?P<date>\d{4}-\d{2}-\d{2})[ T](?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d+))?$",
        text,
    )
    if not match:
        return None
    fraction = match.group("fraction") or ""
    microsecond = int((fraction + "000000")[:6]) if fraction else 0
    parsed = datetime.strptime(f"{match.group('date')} {match.group('time')}", "%Y-%m-%d %H:%M:%S")
    parsed = parsed.replace(microsecond=microsecond, tzinfo=timezone.utc)
    iso = parsed.isoformat().replace("+00:00", "Z")
    if ".000000Z" in iso:
        iso = iso.replace(".000000Z", "Z")
    return iso


def _positive_int(value: object) -> int | None:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _recovery_limits(recovery: dict[str, object] | None) -> dict[str, int]:
    recovery = recovery or {}
    limits: dict[str, int] = {}
    for key in ("max_files", "max_bytes", "max_seconds"):
        number = _positive_int(recovery.get(key))
        if number is not None:
            limits[key] = number
    return limits


def _extraction_limits(artifact: ArtifactDefinition) -> dict[str, int]:
    limits = _recovery_limits(artifact.recovery)
    for key, value in (artifact.extraction_limits or {}).items():
        number = _positive_int(value)
        if number is not None and key in {"max_files", "max_bytes", "max_seconds"}:
            limits.setdefault(key, number)
    return limits


def _recovery_limit_reason(
    limits: dict[str, int],
    *,
    extracted_files: int,
    extracted_bytes: int,
    started: float,
) -> str:
    max_files = limits.get("max_files")
    if max_files is not None and extracted_files >= max_files:
        return "max_files"
    max_bytes = limits.get("max_bytes")
    if max_bytes is not None and extracted_bytes >= max_bytes:
        return "max_bytes"
    max_seconds = limits.get("max_seconds")
    if max_seconds is not None and time.monotonic() - started >= max_seconds:
        return "max_seconds"
    return ""


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
        "recovery_limited",
        "limit_reason",
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
    filesystem_type: str | None = None,
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
            filesystem_type=filesystem_type,
        )
        if not dry_run:
            try:
                metadata = read_file_metadata(
                    raw_image=raw_image,
                    offset_sectors=offset_sectors,
                    inode=artifact.inode,
                    filesystem_type=filesystem_type,
                    dry_run=dry_run,
                )
            except ToolError:
                metadata = {}
            db.insert_evidence_file_extractions(
                [
                    _extraction_audit_row(
                        case_id=case_id,
                        image_id=image_id,
                        computer_id=computer_id,
                        artifact_name=artifact.name,
                        source_path=artifact.source,
                        extracted_path=destination,
                        inode=artifact.inode,
                        metadata=metadata,
                        details={"source": artifact.source, "mode": "direct_inode"},
                    )
                ]
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
        extracted_bytes = 0
        started = time.monotonic()
        limit_reason = ""
        limits = _extraction_limits(artifact)
        for entry in matched:
            limit_reason = _recovery_limit_reason(
                limits,
                extracted_files=len(manifest_rows),
                extracted_bytes=extracted_bytes,
                started=started,
            )
            if limit_reason:
                break
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
                    filesystem_type=filesystem_type,
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
                extracted_bytes += extracted_path.stat().st_size
            except OSError:
                pass
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
                    "recovery_limited": "true" if limit_reason else "false",
                    "limit_reason": limit_reason,
                    **metadata,
                }
            )
        db.insert_evidence_file_extractions(
            [
                _extraction_audit_row(
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=computer_id,
                    artifact_name=artifact.name,
                    source_path=str(row.get("original_path") or ""),
                    extracted_path=Path(str(row.get("artifact_path") or "")),
                    inode=str(row.get("inode") or ""),
                    metadata={
                        "created_utc": str(row.get("created_utc") or ""),
                        "modified_utc": str(row.get("modified_utc") or ""),
                        "accessed_utc": str(row.get("accessed_utc") or ""),
                        "metadata_changed_utc": str(row.get("metadata_changed_utc") or ""),
                    },
                    details={
                        "source": artifact.source,
                        "partial": row.get("partial"),
                        "recovery_limited": row.get("recovery_limited"),
                        "limit_reason": row.get("limit_reason"),
                    },
                )
                for row in manifest_rows
            ]
        )
        limited = bool(limit_reason)
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
                    "recovery_limited": limited,
                    "limit_reason": limit_reason,
                    "limit_max_files": limits.get("max_files"),
                    "limit_max_bytes": limits.get("max_bytes"),
                    "limit_max_seconds": limits.get("max_seconds"),
                    "pattern": artifact.pattern,
                    "patterns": list(artifact.patterns),
                    "include_path_patterns": list(artifact.include_path_patterns),
                    "exclude_patterns": list(exclude_patterns),
                },
            }
        )
        level = "warning" if len(matched) == 0 or failed_count or limited else "info"
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level=level,
            event="artifact.extracted",
            message=(
                f"No files found for artifact {artifact.name}"
                if len(matched) == 0
                else f"Stopped recovery for artifact {artifact.name} after {len(manifest_rows)} of {len(matched)} files: {limit_reason}"
                if limited
                else f"Extracted {len(manifest_rows)} of {len(matched)} files for artifact {artifact.name}"
            ),
            details={
                "artifact": artifact.name,
                "path": str(destination),
                "count": len(matched),
                "extracted_count": len(manifest_rows),
                "failed_count": failed_count,
                "recovery_limited": limited,
                "limit_reason": limit_reason,
                "limit_max_files": limits.get("max_files"),
                "limit_max_bytes": limits.get("max_bytes"),
                "limit_max_seconds": limits.get("max_seconds"),
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
            {
                "count": len(matched),
                "extracted_count": len(manifest_rows),
                "failed_count": failed_count,
                "recovery_limited": limited,
                "limit_reason": limit_reason,
                "limit_max_files": limits.get("max_files"),
                "limit_max_bytes": limits.get("max_bytes"),
                "limit_max_seconds": limits.get("max_seconds"),
            },
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
        filesystem_type=filesystem_type,
    )
    if not dry_run:
        try:
            metadata = read_file_metadata(
                raw_image=raw_image,
                offset_sectors=offset_sectors,
                inode=matches[0].inode,
                filesystem_type=filesystem_type,
                dry_run=dry_run,
            )
        except ToolError:
            metadata = {}
        db.insert_evidence_file_extractions(
            [
                _extraction_audit_row(
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=computer_id,
                    artifact_name=artifact.name,
                    source_path=matches[0].path,
                    extracted_path=destination,
                    inode=matches[0].inode,
                    metadata=metadata,
                    details={"source": artifact.source, "mode": "path_match"},
                )
            ]
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
