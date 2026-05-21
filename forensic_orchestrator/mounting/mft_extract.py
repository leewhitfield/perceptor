from __future__ import annotations

import fnmatch
import re
import uuid
from collections import Counter
from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.jobs import JobRunner
from forensic_orchestrator.models import ArtifactDefinition, ExtractedArtifact
from forensic_orchestrator.safety import ToolError

from .filesystem import _copy_file, _resolve_case_insensitive
from .tsk import FlsEntry, _run_icat_to_file, write_extraction_manifest


def extract_artifact_from_mft(
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
    tool_name: str | None = None,
    include_deleted_mft: bool = False,
    include_live_orphans: bool = False,
    fls_entries: list[FlsEntry] | None = None,
    mount_path: Path | None = None,
) -> ExtractedArtifact:
    destination = artifacts_root / artifact.destination
    destination.mkdir(parents=True, exist_ok=True)
    active_indx_inodes = _active_indx_inode_set(fls_entries)
    candidates, skipped_reparse, skipped_deleted, skipped_live_orphans = _mft_candidates(
        db,
        case_id=case_id,
        image_id=image_id,
        artifact=artifact,
        include_deleted_mft=include_deleted_mft,
        include_live_orphans=include_live_orphans,
        active_indx_inodes=active_indx_inodes,
    )
    if dry_run:
        db.insert_artifact(
            {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "image_id": image_id,
                "name": artifact.name,
                "source": "mft_entries",
                "path": destination,
                "kind": "directory",
                "metadata": {
                    "dry_run": True,
                    "source": "mft_entries",
                    "count": len(candidates),
                    "skipped_reparse_count": len(skipped_reparse),
                    "skipped_deleted_count": len(skipped_deleted),
                    "skipped_live_orphan_count": len(skipped_live_orphans),
                    "include_deleted_mft": include_deleted_mft,
                    "include_live_orphans": include_live_orphans,
                },
            }
        )
        return ExtractedArtifact(
            artifact.name,
            destination,
            "mft_entries",
            "directory",
            {
                "dry_run": True,
                "count": len(candidates),
                "skipped_reparse_count": len(skipped_reparse),
                "skipped_deleted_count": len(skipped_deleted),
                "skipped_live_orphan_count": len(skipped_live_orphans),
                "include_deleted_mft": include_deleted_mft,
                "include_live_orphans": include_live_orphans,
            },
        )

    runner = JobRunner(db)
    manifest_rows: list[dict[str, str]] = []
    failed_count = 0
    path_unresolved_rows = [row for row in candidates if _is_path_unresolved(row)]
    deleted_path_unresolved_rows = [row for row in path_unresolved_rows if _is_deleted_mft_row(row)]
    live_orphan_inodes: set[str] = {
        str(row["entry_number"]) for row in candidates if _is_live_orphan(row, active_indx_inodes)
    }
    runtime_skipped_live_orphans = []
    extraction_methods: Counter[str] = Counter()
    for row in candidates:
        original_path = _mft_original_path(row)
        extracted_path = destination / _safe_relative_path(original_path)
        extraction_method = "mft_icat"
        try:
            if mount_path is not None and mount_path.exists():
                mounted_source = _resolve_case_insensitive(mount_path, original_path)
                if mounted_source is not None and mounted_source.exists():
                    if artifact.process_in_place:
                        extracted_path = mounted_source
                        extraction_method = "mounted_in_place"
                    else:
                        _copy_file(mounted_source, extracted_path)
                        extraction_method = "mounted_copy"
                else:
                    live_orphan_inodes.add(str(row["entry_number"]))
                    extraction_method = "mft_live_orphan"
                    if not include_live_orphans and active_indx_inodes is None:
                        runtime_skipped_live_orphans.append(row)
                        continue
                    _extract_mft_row(
                        db=db,
                        runner=runner,
                        case_id=case_id,
                        image_id=image_id,
                        computer_id=computer_id,
                        raw_image=raw_image,
                        offset_sectors=offset_sectors,
                        row=row,
                        extracted_path=extracted_path,
                    )
            else:
                _extract_mft_row(
                    db=db,
                    runner=runner,
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=computer_id,
                    raw_image=raw_image,
                    offset_sectors=offset_sectors,
                    row=row,
                    extracted_path=extracted_path,
                )
        except (OSError, ToolError) as exc:
            failed_count += 1
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                level="warning",
                event="artifact.extract_failed",
                message=f"Skipped unreadable MFT-selected artifact file for {artifact.name}",
                details={
                    "artifact": artifact.name,
                    "source_path": original_path,
                    "inode": row["entry_number"],
                    "destination": str(extracted_path),
                    "error": str(exc),
                },
            )
            continue
        manifest_rows.append(
            {
                "artifact_path": str(extracted_path),
                "original_path": original_path,
                "inode": str(row["entry_number"] or ""),
                "original_size": str(row["file_size"] or ""),
                "mft_created": str(row["created_si"] or ""),
                "mft_modified": str(row["modified_si"] or ""),
                "mft_accessed": str(row["accessed_si"] or ""),
                "mft_record_modified": str(row["record_changed_si"] or ""),
                "mft_in_use": str(row["in_use"] or ""),
                "path_unresolved": str(_is_path_unresolved(row)).lower(),
                "deleted_mft_entry": str(_is_deleted_mft_row(row)).lower(),
                "live_orphan": str(str(row["entry_number"]) in live_orphan_inodes).lower(),
                "extraction_method": extraction_method,
                "partial": "false",
            }
        )
        extraction_methods[manifest_rows[-1]["extraction_method"]] += 1
    total_skipped_live_orphans = [*skipped_live_orphans, *runtime_skipped_live_orphans]
    selected_count = len(candidates) - len(runtime_skipped_live_orphans)
    live_orphan_count = sum(1 for row in candidates if str(row["entry_number"]) in live_orphan_inodes)
    skipped_manifest_rows = [
        _skipped_manifest_row(row, extraction_method="skipped_reparse")
        for row in skipped_reparse
    ]
    skipped_manifest_rows.extend(
        _skipped_manifest_row(row, extraction_method="skipped_deleted_mft")
        for row in skipped_deleted
    )
    skipped_manifest_rows.extend(
        _skipped_manifest_row(row, extraction_method="skipped_live_orphan")
        for row in total_skipped_live_orphans
    )
    write_extraction_manifest(destination, [*manifest_rows, *skipped_manifest_rows])
    if skipped_reparse:
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level="info",
            event="artifact.skipped_reparse",
            message=f"Skipped {len(skipped_reparse)} reparse-point candidate files for {artifact.name}",
            details={
                "tool_name": tool_name,
                "artifact": artifact.name,
                "count": len(skipped_reparse),
                "sample": [_mft_original_path(row) for row in skipped_reparse[:25]],
            },
        )
    if skipped_deleted:
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level="info",
            event="artifact.skipped_deleted_mft",
            message=f"Skipped {len(skipped_deleted)} deleted MFT candidate files for {artifact.name}",
            details={
                "tool_name": tool_name,
                "artifact": artifact.name,
                "count": len(skipped_deleted),
                "sample": [_mft_original_path(row) for row in skipped_deleted[:25]],
            },
        )
    if total_skipped_live_orphans:
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level="info",
            event="artifact.skipped_live_orphan",
            message=f"Skipped {len(total_skipped_live_orphans)} allocated MFT records missing from active namespace for {artifact.name}",
            details={
                "tool_name": tool_name,
                "artifact": artifact.name,
                "count": len(total_skipped_live_orphans),
                "sample": [_mft_original_path(row) for row in total_skipped_live_orphans[:25]],
            },
        )
    db.insert_artifact(
        {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "image_id": image_id,
            "name": artifact.name,
            "source": "mft_entries",
            "path": destination,
            "kind": "directory",
            "metadata": {
                "source": "mft_entries",
                "count": selected_count,
                "extracted_count": len(manifest_rows),
                "failed_count": failed_count,
                "include_deleted_mft": include_deleted_mft,
                "include_live_orphans": include_live_orphans,
                "skipped_reparse_count": len(skipped_reparse),
                "skipped_deleted_count": len(skipped_deleted),
                "skipped_live_orphan_count": len(total_skipped_live_orphans),
                "live_orphan_count": live_orphan_count,
                "path_unresolved_count": len(path_unresolved_rows),
                "deleted_path_unresolved_count": len(deleted_path_unresolved_rows),
                "extraction_methods": dict(extraction_methods),
                "patterns": list(artifact.patterns),
                "include_path_patterns": list(artifact.include_path_patterns),
            },
        }
    )
    db.insert_file_metadata_extraction_summary(
        {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "computer_id": computer_id,
            "image_id": image_id,
            "tool_name": tool_name,
            "artifact_name": artifact.name,
            "artifact_path": str(destination),
            "selected_count": selected_count,
            "extracted_count": len(manifest_rows),
            "failed_count": failed_count,
            "include_deleted_mft": include_deleted_mft,
            "include_live_orphans": include_live_orphans,
            "skipped_reparse_count": len(skipped_reparse),
            "skipped_deleted_count": len(skipped_deleted),
            "skipped_live_orphan_count": len(total_skipped_live_orphans),
            "live_orphan_count": live_orphan_count,
            "path_unresolved_count": len(path_unresolved_rows),
            "deleted_path_unresolved_count": len(deleted_path_unresolved_rows),
            "mounted_in_place_count": extraction_methods.get("mounted_in_place", 0),
            "mft_icat_count": extraction_methods.get("mft_icat", 0),
            "source": "mft_entries",
        }
    )
    if path_unresolved_rows:
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level="info",
            event="artifact.path_unresolved",
            message=f"Found {len(path_unresolved_rows)} MFT-selected files with unresolved paths for {artifact.name}",
            details={
                "tool_name": tool_name,
                "artifact": artifact.name,
                "count": len(path_unresolved_rows),
                "deleted_count": len(deleted_path_unresolved_rows),
                "sample": [
                    {
                        "path": _mft_original_path(row),
                        "entry_number": row["entry_number"],
                        "in_use": row["in_use"],
                    }
                    for row in path_unresolved_rows[:25]
                ],
            },
        )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        level="warning" if not selected_count or failed_count else "info",
        event="artifact.extracted",
        message=(
            f"No MFT rows matched artifact {artifact.name}"
            if not selected_count
            else f"Extracted {len(manifest_rows)} of {selected_count} MFT-selected files for {artifact.name}"
        ),
        details={
            "artifact": artifact.name,
            "path": str(destination),
            "count": selected_count,
            "extracted_count": len(manifest_rows),
            "failed_count": failed_count,
            "skipped_reparse_count": len(skipped_reparse),
            "skipped_deleted_count": len(skipped_deleted),
            "skipped_live_orphan_count": len(total_skipped_live_orphans),
            "live_orphan_count": live_orphan_count,
            "path_unresolved_count": len(path_unresolved_rows),
            "deleted_path_unresolved_count": len(deleted_path_unresolved_rows),
            "extraction_methods": dict(extraction_methods),
            "source": "mft_entries",
        },
    )
    return ExtractedArtifact(
        artifact.name,
        destination,
        "mft_entries",
        "directory",
        {
            "count": selected_count,
            "extracted_count": len(manifest_rows),
            "failed_count": failed_count,
            "skipped_reparse_count": len(skipped_reparse),
            "skipped_deleted_count": len(skipped_deleted),
            "skipped_live_orphan_count": len(total_skipped_live_orphans),
            "live_orphan_count": live_orphan_count,
            "path_unresolved_count": len(path_unresolved_rows),
            "deleted_path_unresolved_count": len(deleted_path_unresolved_rows),
            "extraction_methods": dict(extraction_methods),
        },
    )


def _extract_mft_row(
    *,
    db: Database,
    runner: JobRunner,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    raw_image: Path,
    offset_sectors: int,
    row,
    extracted_path: Path,
) -> None:
    inode = str(row["entry_number"])
    if _is_ads_row(row):
        stream_name = _ads_stream_name(str(row["file_name"] or ""))
        attribute = _named_data_attribute(raw_image, offset_sectors, inode, stream_name)
        if attribute is None:
            raise ToolError(f"Could not resolve ADS attribute {stream_name!r} for inode {inode}")
        inode = f"{inode}-{attribute}"
    _run_icat_to_file(
        db=db,
        runner=runner,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        raw_image=raw_image,
        offset_sectors=offset_sectors,
        inode=inode,
        destination=extracted_path,
        dry_run=False,
    )


def _ads_stream_name(file_name: str) -> str:
    if ":" not in file_name:
        return file_name
    return file_name.rsplit(":", 1)[1]


def _named_data_attribute(raw_image: Path, offset_sectors: int, inode: str, stream_name: str) -> str | None:
    import subprocess

    completed = subprocess.run(
        ["istat", "-f", "ntfs", "-o", str(offset_sectors), str(raw_image), inode],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ToolError(f"istat failed for inode {inode}: {completed.stderr.strip()}")
    pattern = re.compile(r"Type:\s+\$DATA\s+\((?P<attr>\d+-\d+)\)\s+Name:\s+(?P<name>.+?)\s+")
    for line in completed.stdout.splitlines():
        match = pattern.search(line)
        if match and match.group("name").strip().lower() == stream_name.lower():
            return match.group("attr")
    return None


def _skipped_manifest_row(row, *, extraction_method: str) -> dict[str, str]:
    return {
        "artifact_path": "",
        "original_path": _mft_original_path(row),
        "inode": str(row["entry_number"] or ""),
        "original_size": str(row["file_size"] or ""),
        "mft_created": str(row["created_si"] or ""),
        "mft_modified": str(row["modified_si"] or ""),
        "mft_accessed": str(row["accessed_si"] or ""),
        "mft_record_modified": str(row["record_changed_si"] or ""),
        "mft_in_use": str(row["in_use"] or ""),
        "path_unresolved": str(_is_path_unresolved(row)).lower(),
        "deleted_mft_entry": str(_is_deleted_mft_row(row)).lower(),
        "live_orphan": "false",
        "extraction_method": extraction_method,
        "partial": "true",
    }


def _mft_candidates(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    artifact: ArtifactDefinition,
    include_deleted_mft: bool = False,
    include_live_orphans: bool = False,
    active_indx_inodes: set[str] | None = None,
) -> tuple[list, list, list, list]:
    rows = _mft_candidate_source_rows(db, case_id=case_id, image_id=image_id)
    patterns = artifact.patterns or ((artifact.pattern,) if artifact.pattern else ())
    source_prefix = artifact.source.strip("\\/")
    include_ads = artifact.name == "zone_identifier_ads"
    seen_keys: set[str] = set()
    selected = []
    skipped_reparse = []
    skipped_deleted = []
    skipped_live_orphans = []
    for row in rows:
        inode = str(row["entry_number"])
        original_path = _mft_original_path(row)
        seen_key = f"{inode}:{original_path.lower()}" if include_ads else inode
        if seen_key in seen_keys:
            continue
        if source_prefix and not original_path.lower().startswith(source_prefix.lower().replace("\\", "/") + "/"):
            continue
        file_name = str(row["file_name"] or "")
        if patterns and not any(fnmatch.fnmatch(file_name.lower(), pattern.lower()) for pattern in patterns):
            continue
        if artifact.include_path_patterns and not any(
            fnmatch.fnmatch(original_path.lower(), pattern.lower())
            for pattern in artifact.include_path_patterns
        ):
            continue
        if any(fnmatch.fnmatch(original_path.lower(), pattern.lower()) for pattern in artifact.exclude_patterns):
            continue
        if _is_ads_row(row) and not include_ads:
            seen_keys.add(seen_key)
            continue
        if _is_reparse_candidate(row):
            seen_keys.add(seen_key)
            skipped_reparse.append(row)
            continue
        if not include_deleted_mft and _is_deleted_mft_row(row):
            seen_keys.add(seen_key)
            skipped_deleted.append(row)
            continue
        if not include_live_orphans and _is_live_orphan(row, active_indx_inodes):
            seen_keys.add(seen_key)
            skipped_live_orphans.append(row)
            continue
        seen_keys.add(seen_key)
        selected.append(row)
    return selected, skipped_reparse, skipped_deleted, skipped_live_orphans


def _mft_candidate_source_rows(db: Database, *, case_id: str, image_id: str) -> list[dict[str, object]]:
    sql = """
        SELECT entry_number, parent_path, file_name, extension, file_size,
               created_si, modified_si, accessed_si, record_changed_si, si_flags,
               reparse_target, in_use, is_directory, is_ads
        FROM mft_entries
        WHERE case_id = ?
          AND image_id = ?
          AND entry_number IS NOT NULL
          AND COALESCE(is_directory, '') NOT IN ('True', 'true', '1')
        ORDER BY entry_number, parent_path, file_name
    """
    duckdb_rows = _duckdb_rows(db, case_id=case_id, table="mft_entries", sql=sql, params=[case_id, image_id])
    if duckdb_rows is not None:
        return duckdb_rows
    return [dict(row) for row in db.conn.execute(sql, (case_id, image_id)).fetchall()]


def _duckdb_rows(
    db: Database,
    *,
    case_id: str,
    table: str,
    sql: str,
    params: list[object],
) -> list[dict[str, object]] | None:
    if db.analytics is None:
        return None
    try:
        conn = db.analytics._connect(case_id)
        if not conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1",
            [table],
        ).fetchone():
            return None
        result = conn.execute(sql, params)
        columns = [item[0] for item in result.description]
        return [dict(zip(columns, row)) for row in result.fetchall()]
    except Exception:
        return None


def _active_indx_inode_set(fls_entries: list[FlsEntry] | None) -> set[str] | None:
    if fls_entries is None:
        return None
    return {str(entry.inode).split("-")[0] for entry in fls_entries if entry.active_name and not entry.is_directory}


def _is_live_orphan(row, active_indx_inodes: set[str] | None) -> bool:
    if active_indx_inodes is None or _is_deleted_mft_row(row):
        return False
    return str(row["entry_number"]) not in active_indx_inodes


def _extraction_method(row, extracted_path: Path, mount_path: Path | None, live_orphan_inodes: set[str]) -> str:
    if str(row["entry_number"]) in live_orphan_inodes:
        return "mft_live_orphan"
    if mount_path is not None and extracted_path.is_relative_to(mount_path):
        return "mounted_in_place"
    return "mft_icat"


def _is_reparse_candidate(row) -> bool:
    si_flags = str(row["si_flags"] or "")
    reparse_target = str(row["reparse_target"] or "")
    return "ReparsePoint" in si_flags or bool(reparse_target)


def _is_ads_row(row) -> bool:
    return str(row["is_ads"] or "").strip().lower() in {"true", "1", "yes"}


def _is_path_unresolved(row) -> bool:
    return _mft_original_path(row).lower().startswith("pathunknown/")


def _is_deleted_mft_row(row) -> bool:
    return str(row["in_use"] or "").strip().lower() not in {"true", "1", "yes"}


def _mft_original_path(row) -> str:
    parent = str(row["parent_path"] or "").replace("\\", "/")
    if parent.startswith("./"):
        parent = parent[2:]
    parent = parent.strip("/")
    file_name = str(row["file_name"] or "")
    return f"{parent}/{file_name}" if parent else file_name


def _safe_relative_path(path: str) -> Path:
    parts = []
    for part in Path(path.replace("\\", "/")).parts:
        if part in {"", ".", ".."}:
            continue
        parts.append(part.replace(":", "_"))
    return Path(*parts) if parts else Path("unnamed")
