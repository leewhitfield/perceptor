from __future__ import annotations

import fnmatch
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.jobs import JobRunner
from forensic_orchestrator.models import ArtifactDefinition, ExtractedArtifact
from forensic_orchestrator.safety import ToolError

from .libfsntfs import evtx_header_valid, pyfsntfs_available, salvage_ntfs_file
from .tsk import FlsEntry, _run_icat_to_file, read_file_metadata, write_extraction_manifest


def _safe_relative_path(value: str) -> Path:
    clean = value.replace("\\", "/").lstrip("/")
    parts = [part for part in clean.split("/") if part not in {"", ".", ".."}]
    return Path(*parts) if parts else Path("artifact")


def _iso_from_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _file_metadata(path: Path) -> dict[str, str]:
    stat = path.stat()
    return {
        "mft_created": _iso_from_timestamp(stat.st_ctime),
        "mft_modified": _iso_from_timestamp(stat.st_mtime),
        "mft_accessed": _iso_from_timestamp(stat.st_atime),
        "mft_record_modified": _iso_from_timestamp(stat.st_ctime),
    }


def _resolve_case_insensitive(root: Path, source: str) -> Path | None:
    current = root
    parts = [part for part in source.replace("\\", "/").split("/") if part]
    for part in parts:
        candidate = current / part
        if candidate.exists():
            current = candidate
            continue
        try:
            matches = [child for child in current.iterdir() if child.name.lower() == part.lower()]
        except OSError:
            return None
        if not matches:
            return None
        current = matches[0]
    return current


def _mounted_relative(root: Path, path: Path) -> str:
    root_text = os.fspath(root).rstrip(os.sep)
    path_text = os.fspath(path)
    if path_text == root_text:
        return ""
    prefix = root_text + os.sep
    if path_text.startswith(prefix):
        return path_text[len(prefix) :].replace(os.sep, "/")
    return path.relative_to(root).as_posix()


def _matches_artifact(
    *,
    original_path: str,
    filename: str,
    source_prefix: str,
    patterns: tuple[str, ...],
    include_path_patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
) -> bool:
    original_lower = original_path.lower()
    if source_prefix and not original_lower.startswith(source_prefix.lower().rstrip("/") + "/"):
        return False
    if patterns and not any(fnmatch.fnmatch(filename.lower(), pattern.lower()) for pattern in patterns):
        return False
    if include_path_patterns and not any(
        fnmatch.fnmatch(original_lower, pattern.lower()) for pattern in include_path_patterns
    ):
        return False
    return not any(fnmatch.fnmatch(original_lower, pattern.lower()) for pattern in exclude_patterns)


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("wb") as dst:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            dst.write(chunk)


def _copy_sqlite_sidecars(source: Path, destination: Path) -> list[str]:
    copied: list[str] = []
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = source.with_name(f"{source.name}{suffix}")
        if not sidecar.is_file():
            continue
        sidecar_destination = destination.with_name(f"{destination.name}{suffix}")
        _copy_file(sidecar, sidecar_destination)
        copied.append(sidecar_destination.name)
    return copied


def _record_evtx_recovery(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    artifact_path: Path,
    original_path: str,
    extraction_method: str,
    status: str,
    original_size: int | None,
    recovered_size: int | None,
    readable_bytes: int | None = None,
    failed_offsets: list[int] | tuple[int, ...] = (),
    header_valid: bool | None = None,
    details: dict[str, object] | None = None,
) -> None:
    if not original_path.lower().endswith(".evtx"):
        return
    db.upsert_evtx_recovery(
        {
            "case_id": case_id,
            "computer_id": computer_id,
            "image_id": image_id,
            "artifact_path": str(artifact_path),
            "original_path": original_path,
            "file_name": Path(original_path.replace("\\", "/")).name,
            "extraction_method": extraction_method,
            "status": status,
            "original_size": original_size,
            "recovered_size": recovered_size,
            "readable_bytes": readable_bytes,
            "failed_block_count": len(failed_offsets),
            "failed_offsets": list(failed_offsets),
            "header_valid": header_valid,
            "details": details or {},
        }
    )


def _salvage_with_libfsntfs(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    raw_image: Path,
    offset_sectors: int,
    original_path: str,
    destination: Path,
    dry_run: bool,
) -> dict[str, object] | None:
    salvage_destination = destination.with_name(f"{destination.name}.libfsntfs-salvage")
    command = [
        "pyfsntfs-salvage",
        "--raw-image",
        str(raw_image),
        "--offset-bytes",
        str(offset_sectors * 512),
        "--path",
        original_path,
        "--output",
        str(salvage_destination),
    ]
    output_folder = destination.parent / "_extract_jobs" / destination.name / "libfsntfs-salvage"
    stdout_path = output_folder / "stdout.txt"
    stderr_path = output_folder / "stderr.txt"
    if not pyfsntfs_available() and not dry_run:
        output_folder.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text("")
        stderr_path.write_text("python3-libfsntfs/pyfsntfs is not available\n")
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level="warning",
            event="artifact.libfsntfs_salvage_unavailable",
            message="libfsntfs salvage unavailable; install python3-libfsntfs for compressed NTFS recovery",
            details={"source_path": original_path, "destination": str(destination)},
        )
        return None
    job_id = str(uuid.uuid4())
    output_folder.mkdir(parents=True, exist_ok=True)
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "tool_name": "libfsntfs-salvage",
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
    if dry_run:
        stdout_path.write_text("DRY RUN: libfsntfs salvage not executed\n")
        stderr_path.write_text("")
        return None
    try:
        result = salvage_ntfs_file(
            raw_image=raw_image,
            offset_bytes=offset_sectors * 512,
            ntfs_path=original_path,
            destination=salvage_destination,
        )
    except ToolError as exc:
        stdout_path.write_text("")
        stderr_path.write_text(str(exc) + "\n")
        db.finish_job(job_id, utc_now(), 1)
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            level="warning",
            event="artifact.libfsntfs_salvage_failed",
            message="libfsntfs salvage failed; keeping existing partial extraction",
            details={"source_path": original_path, "destination": str(destination), "error": str(exc)},
        )
        return None

    payload = {
        "source_path": result.source_path,
        "destination": str(result.destination),
        "logical_size": result.logical_size,
        "recovered_size": result.recovered_size,
        "readable_bytes": result.readable_bytes,
        "failed_block_count": result.failed_block_count,
        "failed_offsets": list(result.failed_offsets),
        "block_size": result.block_size,
        "header_valid": result.header_valid,
    }
    stdout_path.write_text(json.dumps(payload, indent=2) + "\n")
    stderr_path.write_text("")
    db.finish_job(job_id, utc_now(), 0)
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        level="warning" if result.failed_block_count else "info",
        event="artifact.libfsntfs_salvaged",
        message="Recovered artifact bytes with libfsntfs salvage",
        details=payload,
    )
    return payload


def _iter_mounted_files(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    artifact_name: str,
    root: Path,
) -> tuple[list[Path], int]:
    files: list[Path] = []
    failed_count = 0
    stack = [root]

    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            files.append(Path(entry.path))
                    except OSError as exc:
                        failed_count += 1
                        db.log_activity(
                            case_id=case_id,
                            computer_id=computer_id,
                            image_id=image_id,
                            level="warning",
                            event="artifact.walk_failed",
                            message=f"Skipped unreadable mounted filesystem entry for {artifact_name}",
                            details={
                                "artifact": artifact_name,
                                "path": entry.path,
                                "error": str(exc),
                            },
                        )
        except OSError as exc:
            failed_count += 1
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                level="warning",
                event="artifact.walk_failed",
                message=f"Skipped unreadable mounted filesystem directory for {artifact_name}",
                details={
                    "artifact": artifact_name,
                    "path": str(directory),
                    "error": str(exc),
                },
            )

    return files, failed_count


def inventory_mounted_files(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    mount_path: Path,
) -> tuple[list[Path], int]:
    files, failed_count = _iter_mounted_files(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        artifact_name="mounted_inventory",
        root=mount_path,
    )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        level="warning" if failed_count else "info",
        event="mounted_inventory.completed",
        message=f"Inventoried {len(files)} mounted files",
        details={"file_count": len(files), "failed_count": failed_count, "mount_path": str(mount_path)},
    )
    return files, failed_count


def _fallback_extract_with_tsk(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    raw_image: Path | None,
    salvage_raw_image: Path | None,
    offset_sectors: int | None,
    fls_entries: list[FlsEntry] | None,
    fls_entries_provider: Callable[[], list[FlsEntry] | None] | None,
    source_inode: str | None,
    allow_partial: bool,
    original_path: str,
    destination: Path,
    dry_run: bool,
) -> dict[str, str] | None:
    if raw_image is None or offset_sectors is None:
        return None
    if source_inode:
        match = FlsEntry(inode=source_inode, path=original_path, is_directory=False)
    else:
        match = None
    if match is None and fls_entries is None and fls_entries_provider is not None:
        fls_entries = fls_entries_provider()
    if match is None and fls_entries is None:
        return None
    if match is None:
        match = next(
            (
                entry
                for entry in fls_entries or []
                if not entry.is_directory and entry.path.lower() == original_path.lower()
            ),
            None,
        )
    if match is None:
        return None
    if destination.exists():
        destination.unlink()
    partial_error: str | None = None
    salvage_details: dict[str, object] | None = None
    extraction_method = "icat"
    try:
        _run_icat_to_file(
            db=db,
            runner=JobRunner(db),
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            inode=match.inode,
            destination=destination,
            dry_run=dry_run,
        )
    except ToolError as exc:
        if not allow_partial or not destination.exists() or destination.stat().st_size == 0:
            raise
        partial_error = str(exc)
        original_size = destination.stat().st_size
        if salvage_raw_image is not None:
            salvage_details = _salvage_with_libfsntfs(
                db=db,
                case_id=case_id,
                image_id=image_id,
                computer_id=computer_id,
                raw_image=salvage_raw_image,
                offset_sectors=offset_sectors,
                original_path=original_path,
                destination=destination,
                dry_run=dry_run,
            )
        if (
            salvage_details
            and salvage_details.get("header_valid")
            and int(salvage_details.get("recovered_size") or 0) > original_size
        ):
            salvage_path = destination.with_name(f"{destination.name}.libfsntfs-salvage")
            salvage_path.replace(destination)
            extraction_method = "libfsntfs_salvage"
        else:
            salvage_path = destination.with_name(f"{destination.name}.libfsntfs-salvage")
            if salvage_path.exists():
                salvage_path.unlink()
    try:
        metadata = read_file_metadata(
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            inode=match.inode,
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
            message="Could not read metadata for TSK fallback extraction",
            details={
                "source_path": original_path,
                "inode": match.inode,
                "destination": str(destination),
                "error": str(exc),
            },
        )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        level="warning" if partial_error else "info",
        event="artifact.fallback_extracted",
        message=(
            "Partially extracted mounted artifact file with Sleuth Kit fallback"
            if partial_error
            else "Extracted mounted artifact file with Sleuth Kit fallback"
        ),
        details={
            "source_path": original_path,
            "inode": match.inode,
            "destination": str(destination),
            "partial": bool(partial_error),
            "error": partial_error,
        },
    )
    result = {"inode": match.inode, **metadata}
    if partial_error:
        header_valid = evtx_header_valid(destination)
        recovered_size = destination.stat().st_size if destination.exists() else 0
        failed_offsets = salvage_details.get("failed_offsets", []) if salvage_details else []
        status = "salvaged_partial" if extraction_method == "libfsntfs_salvage" else "partial"
        if original_path.lower().endswith(".evtx"):
            _record_evtx_recovery(
                db=db,
                case_id=case_id,
                image_id=image_id,
                computer_id=computer_id,
                artifact_path=destination,
                original_path=original_path,
                extraction_method=extraction_method,
                status=status,
                original_size=int(salvage_details["logical_size"]) if salvage_details else None,
                recovered_size=recovered_size,
                readable_bytes=int(salvage_details["readable_bytes"]) if salvage_details else recovered_size,
                failed_offsets=failed_offsets,
                header_valid=header_valid,
                details={
                    "icat_error": partial_error,
                    "salvage": salvage_details,
                    "inode": match.inode,
                },
            )
        result.update(
            {
                "partial": "true",
                "fallback_error": partial_error,
                "extraction_method": extraction_method,
                "header_valid": str(header_valid).lower(),
                "original_size": str(salvage_details["logical_size"]) if salvage_details else "",
                "recovered_size": str(recovered_size),
                "readable_bytes": str(salvage_details["readable_bytes"]) if salvage_details else str(recovered_size),
                "failed_block_count": str(len(failed_offsets)),
                "failed_offsets": json.dumps(failed_offsets),
            }
        )
    else:
        if original_path.lower().endswith(".evtx"):
            recovered_size = destination.stat().st_size if destination.exists() else None
            _record_evtx_recovery(
                db=db,
                case_id=case_id,
                image_id=image_id,
                computer_id=computer_id,
                artifact_path=destination,
                original_path=original_path,
                extraction_method="icat",
                status="extracted",
                original_size=recovered_size,
                recovered_size=recovered_size,
                readable_bytes=recovered_size,
                header_valid=evtx_header_valid(destination),
                details={"inode": match.inode},
            )
        result.update({"extraction_method": "icat", "partial": "false"})
    return result


def extract_artifact_from_mount(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    mount_path: Path,
    artifact: ArtifactDefinition,
    artifacts_root: Path,
    dry_run: bool,
    ignore_exclude_patterns: bool = False,
    mounted_files: list[Path] | None = None,
    raw_image: Path | None = None,
    salvage_raw_image: Path | None = None,
    offset_sectors: int | None = None,
    fls_entries: list[FlsEntry] | None = None,
    fls_entries_provider: Callable[[], list[FlsEntry] | None] | None = None,
) -> ExtractedArtifact:
    destination = artifacts_root / artifact.destination
    source_prefix = artifact.source.rstrip("/")
    exclude_patterns = () if ignore_exclude_patterns else artifact.exclude_patterns
    include_path_patterns = artifact.include_path_patterns
    patterns = artifact.patterns or ((artifact.pattern,) if artifact.pattern else ())

    if dry_run:
        db.insert_artifact(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "image_id": image_id,
                "name": artifact.name,
                "source": artifact.source,
                "path": destination,
                "kind": "directory" if artifact.recursive else "file",
                "metadata": {"dry_run": True, "source": "mounted-filesystem"},
            }
        )
        return ExtractedArtifact(
            artifact.name,
            destination,
            artifact.source,
            "directory" if artifact.recursive else "file",
            {"dry_run": True},
        )

    if not mount_path.exists():
        raise ToolError(f"Mounted filesystem path does not exist: {mount_path}")

    if artifact.process_in_place:
        source = _resolve_case_insensitive(mount_path, artifact.source) if artifact.source else mount_path
        if source is None or not source.exists():
            raise ToolError(f"Artifact source not found on mounted filesystem: {artifact.source}")
        kind = "directory" if source.is_dir() else "file"
        count = 1
        if artifact.recursive and mounted_files is not None:
            source_prefix = artifact.source.rstrip("/")
            exclude_patterns = () if ignore_exclude_patterns else artifact.exclude_patterns
            include_path_patterns = artifact.include_path_patterns
            patterns = artifact.patterns or ((artifact.pattern,) if artifact.pattern else ())
            count = sum(
                1
                for item in mounted_files
                if _matches_artifact(
                    original_path=_mounted_relative(mount_path, item),
                    filename=item.name,
                    source_prefix=source_prefix,
                    patterns=patterns,
                    include_path_patterns=include_path_patterns,
                    exclude_patterns=exclude_patterns,
                )
            )
        db.insert_artifact(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "image_id": image_id,
                "name": artifact.name,
                "source": artifact.source,
                "path": source,
                "kind": kind,
                "metadata": {
                    "source": "mounted-filesystem-direct",
                    "original_path": _mounted_relative(mount_path, source),
                    "count": count,
                    "preserved_copy": False,
                },
            }
        )
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            event="artifact.referenced",
            message=f"Using mounted filesystem path directly for artifact {artifact.name}",
            details={"artifact": artifact.name, "path": str(source), "kind": kind, "count": count},
        )
        return ExtractedArtifact(
            artifact.name,
            source,
            artifact.source,
            kind,
            {"source": "mounted-filesystem-direct", "count": count, "preserved_copy": False},
        )

    if not artifact.recursive:
        source = _resolve_case_insensitive(mount_path, artifact.source)
        if source is None or not source.is_file():
            tsk_entries = fls_entries
            if tsk_entries is None and fls_entries_provider is not None:
                tsk_entries = fls_entries_provider()
            tsk_match = next(
                (
                    entry
                    for entry in (tsk_entries or [])
                    if not entry.is_directory and entry.path.lower() == artifact.source.lower()
                ),
                None,
            )
            if tsk_match is not None and raw_image is not None and offset_sectors is not None:
                _run_icat_to_file(
                    db=db,
                    runner=JobRunner(db),
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=computer_id,
                    raw_image=raw_image,
                    offset_sectors=offset_sectors,
                    inode=tsk_match.inode,
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
                        "metadata": {
                            "source": "sleuthkit-fallback",
                            "original_path": tsk_match.path,
                            "inode": tsk_match.inode,
                        },
                    }
                )
                db.log_activity(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    event="artifact.fallback_extracted",
                    message=f"Extracted artifact {artifact.name} with Sleuth Kit fallback",
                    details={
                        "artifact": artifact.name,
                        "source_path": tsk_match.path,
                        "inode": tsk_match.inode,
                        "path": str(destination),
                    },
                )
                return ExtractedArtifact(
                    artifact.name,
                    destination,
                    artifact.source,
                    "file",
                    {"source": "sleuthkit-fallback", "inode": tsk_match.inode},
                )
            if artifact.optional:
                destination.parent.mkdir(parents=True, exist_ok=True)
                db.insert_artifact(
                    {
                        "id": str(uuid.uuid4()),
                        "case_id": case_id,
                        "image_id": image_id,
                        "name": artifact.name,
                        "source": artifact.source,
                        "path": destination,
                        "kind": "file",
                        "metadata": {
                            "source": "mounted-filesystem",
                            "optional": True,
                            "missing": True,
                            "count": 0,
                        },
                    }
                )
                db.log_activity(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    level="warning",
                    event="artifact.optional_missing",
                    message=f"Optional artifact source not found on mounted filesystem: {artifact.name}",
                    details={"artifact": artifact.name, "source_path": artifact.source},
                )
                return ExtractedArtifact(
                    artifact.name,
                    destination,
                    artifact.source,
                    "file",
                    {"optional": True, "missing": True, "count": 0},
                )
            raise ToolError(f"Artifact source not found on mounted filesystem: {artifact.source}")
        _copy_file(source, destination)
        sqlite_sidecars = _copy_sqlite_sidecars(source, destination)
        try:
            metadata = _file_metadata(source)
        except OSError as exc:
            metadata = {}
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                level="warning",
                event="artifact.metadata_failed",
                message=f"Could not read mounted metadata for artifact {artifact.name}",
                details={"artifact": artifact.name, "source_path": str(source), "error": str(exc)},
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
                "metadata": {
                    "source": "mounted-filesystem",
                    "original_path": _mounted_relative(mount_path, source),
                    "sqlite_sidecars": sqlite_sidecars,
                    **metadata,
                },
            }
        )
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            event="artifact.extracted",
            message=f"Copied artifact {artifact.name} from mounted filesystem",
            details={"artifact": artifact.name, "path": str(destination), "count": 1},
        )
        if artifact.source.lower().endswith(".evtx"):
            size = destination.stat().st_size if destination.exists() else None
            _record_evtx_recovery(
                db=db,
                case_id=case_id,
                image_id=image_id,
                computer_id=computer_id,
                artifact_path=destination,
                original_path=_mounted_relative(mount_path, source),
                extraction_method="mounted_copy",
                status="copied",
                original_size=source.stat().st_size,
                recovered_size=size,
                readable_bytes=size,
                header_valid=evtx_header_valid(destination),
            )
        return ExtractedArtifact(
            artifact.name,
            destination,
            artifact.source,
            "file",
            {"count": 1, "sqlite_sidecars": sqlite_sidecars},
        )

    walk_root = _resolve_case_insensitive(mount_path, artifact.source) if artifact.source else mount_path
    matched_count = 0
    failed_count = 0
    manifest_rows: list[dict[str, str]] = []
    destination.mkdir(parents=True, exist_ok=True)

    if walk_root is not None and walk_root.exists():
        if mounted_files is None:
            sources, walk_failed_count = _iter_mounted_files(
                db=db,
                case_id=case_id,
                image_id=image_id,
                computer_id=computer_id,
                artifact_name=artifact.name,
                root=walk_root,
            )
            failed_count += walk_failed_count
        else:
            sources = mounted_files
        for source in sources:
            original_path = _mounted_relative(mount_path, source)
            if not _matches_artifact(
                original_path=original_path,
                filename=source.name,
                source_prefix=source_prefix,
                patterns=patterns,
                include_path_patterns=include_path_patterns,
                exclude_patterns=exclude_patterns,
            ):
                continue
            matched_count += 1
            if source_prefix:
                relative_source = source.relative_to(walk_root)
            else:
                relative_source = source.relative_to(mount_path)
            extracted_path = destination / _safe_relative_path(relative_source.as_posix())
            try:
                _copy_file(source, extracted_path)
                sqlite_sidecars = _copy_sqlite_sidecars(source, extracted_path)
            except OSError as exc:
                try:
                    source_inode = str(source.stat().st_ino)
                except OSError:
                    source_inode = None
                try:
                    metadata = _fallback_extract_with_tsk(
                        db=db,
                        case_id=case_id,
                        image_id=image_id,
                        computer_id=computer_id,
                        raw_image=raw_image,
                        salvage_raw_image=salvage_raw_image,
                        offset_sectors=offset_sectors,
                        fls_entries=fls_entries,
                        fls_entries_provider=fls_entries_provider,
                        source_inode=source_inode,
                        allow_partial=artifact.allow_partial,
                        original_path=original_path,
                        destination=extracted_path,
                        dry_run=dry_run,
                    )
                except ToolError as fallback_exc:
                    metadata = None
                    exc = fallback_exc
                if metadata is None:
                    failed_count += 1
                    db.log_activity(
                        case_id=case_id,
                        computer_id=computer_id,
                        image_id=image_id,
                        level="warning",
                        event="artifact.extract_failed",
                        message=f"Skipped unreadable mounted artifact file for {artifact.name}",
                        details={
                            "artifact": artifact.name,
                            "source_path": original_path,
                            "destination": str(extracted_path),
                            "error": str(exc),
                        },
                    )
                    continue
                manifest_rows.append(
                    {
                        "artifact_path": str(extracted_path),
                        "original_path": original_path,
                        **metadata,
                    }
                )
                continue
            try:
                metadata = _file_metadata(source)
            except OSError as exc:
                metadata = {}
                db.log_activity(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    level="warning",
                    event="artifact.metadata_failed",
                    message=f"Could not read mounted metadata for artifact file {artifact.name}",
                    details={
                        "artifact": artifact.name,
                        "source_path": original_path,
                        "destination": str(extracted_path),
                        "error": str(exc),
                    },
                )
            manifest_rows.append(
                {
                    "artifact_path": str(extracted_path),
                    "original_path": original_path,
                    "inode": "",
                    "extraction_method": "mounted_copy",
                    "partial": "false",
                    "sqlite_sidecars": json.dumps(sqlite_sidecars),
                    "header_valid": str(evtx_header_valid(extracted_path)).lower()
                    if original_path.lower().endswith(".evtx")
                    else "",
                    "original_size": str(source.stat().st_size) if original_path.lower().endswith(".evtx") else "",
                    "recovered_size": str(extracted_path.stat().st_size)
                    if original_path.lower().endswith(".evtx")
                    else "",
                    **metadata,
                }
            )
            if original_path.lower().endswith(".evtx"):
                recovered_size = extracted_path.stat().st_size
                _record_evtx_recovery(
                    db=db,
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=computer_id,
                    artifact_path=extracted_path,
                    original_path=original_path,
                    extraction_method="mounted_copy",
                    status="copied",
                    original_size=source.stat().st_size,
                    recovered_size=recovered_size,
                    readable_bytes=recovered_size,
                    header_valid=evtx_header_valid(extracted_path),
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
                "source": "mounted-filesystem",
                "count": matched_count,
                "extracted_count": len(manifest_rows),
                "failed_count": failed_count,
                "pattern": artifact.pattern,
                "patterns": list(artifact.patterns),
                "include_path_patterns": list(artifact.include_path_patterns),
                "exclude_patterns": list(exclude_patterns),
            },
        }
    )
    level = "warning" if matched_count == 0 or failed_count else "info"
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        level=level,
        event="artifact.extracted",
        message=(
            f"No files found for artifact {artifact.name}"
            if matched_count == 0
            else f"Copied {len(manifest_rows)} of {matched_count} files for artifact {artifact.name}"
        ),
        details={
            "artifact": artifact.name,
            "path": str(destination),
            "count": matched_count,
            "extracted_count": len(manifest_rows),
            "failed_count": failed_count,
            "source": "mounted-filesystem",
        },
    )
    return ExtractedArtifact(
        artifact.name,
        destination,
        artifact.source,
        "directory",
        {"count": matched_count, "extracted_count": len(manifest_rows), "failed_count": failed_count},
    )
