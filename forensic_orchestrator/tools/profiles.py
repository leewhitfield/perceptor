from __future__ import annotations

from dataclasses import replace
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from forensic_orchestrator.artifact_dedupe import rebuild_artifact_windows_old_dedupe
from forensic_orchestrator.correlation import rebuild_file_correlations
from forensic_orchestrator.correlation_framework import rebuild_correlation_framework
from forensic_orchestrator.db import Database
from forensic_orchestrator.encryption_preflight import assert_image_not_previously_marked_encrypted
from forensic_orchestrator.filesystem_review import rebuild_filesystem_review
from forensic_orchestrator.sessions import rebuild_sessions
from forensic_orchestrator.user_file_references import rebuild_user_controlled_file_references
from forensic_orchestrator.mounting.filesystem import extract_artifact_from_mount, inventory_mounted_files
from forensic_orchestrator.mounting.mft_extract import extract_artifact_from_mft
from forensic_orchestrator.nested_evidence import rebuild_nested_evidence_inventory
from forensic_orchestrator.mounting.tsk import extract_artifact, list_files, validate_tsk_available
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.processing_scheduler import ProcessingTask, run_processing_tasks
from forensic_orchestrator.safety import MountError, ToolError
from forensic_orchestrator.timeline_dedupe import rebuild_timeline_windows_old_dedupe

from .prefetch import inventory_prefetch_directory
from .registry import ToolRegistry
from .runner import generate_external_tool_outputs, ingest_generated_tool_outputs, run_tool, supports_parallel_generate


WINDOWS_OLD_ROOT = "Windows.old"
WINDOWS_OLD_OUTPUT_NAMESPACE = "Windows.old"
WINDOWS_OLD_EXCLUDED_TOOLS = {
    # These are volume-wide NTFS metadata parsers. They already cover the
    # Windows.old namespace through normal filesystem-wide processing.
    "MFTECmd",
    "MFTECmdUSN",
    "MFTECmdLogFile",
    "NTFSParseLogFile",
    "MFTECmdI30",
}
TIMELINE_TOOLS = {
    "BrowserCacheParser",
    "ChromiumParser",
    "EtlParser",
    "EvtxECmd",
    "FirefoxParser",
    "JLECmd",
    "LECmd",
    "PackageArtifactsParser",
    "PackageCacheParser",
    "PrefetchParser",
    "RecycleParser",
    "RegistryArtifactParser",
    "SAMParser",
    "TelemetryParser",
    "WebCacheParser",
    "WindowsActivitiesParser",
    "WindowsDefenderParser",
    "WindowsErrorReportingParser",
    "WindowsSearchGatherParser",
}
ARTIFACT_DEDUPE_TOOLS = {
    "BrowserCacheParser",
    "ChromiumParser",
    "FirefoxParser",
    "LECmd",
    "JLECmd",
    "PrefetchParser",
    "RegistryArtifactParser",
    "SBECmd",
    "SQLECmd",
    "WebCacheParser",
    "WindowsActivitiesParser",
    "WindowsSearchESEParser",
}
MFT_DEPENDENT_TOOL_BARRIERS = {
    # This internal wrapper builds targeted $I30 inputs from the imported MFT
    # rows, so any queued MFTECmd generation must be ingested before it runs.
    "MFTECmdI30",
}


def _progress(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"[{timestamp}] {message}", file=sys.stderr, flush=True)


def _format_elapsed(start: float) -> str:
    elapsed = time.monotonic() - start
    if elapsed < 60:
        return f"{elapsed:.1f}s"
    minutes, seconds = divmod(elapsed, 60)
    return f"{int(minutes)}m {seconds:.1f}s"


def _progress_detail(details: dict | None) -> str:
    if not details:
        return ""
    parts = []
    if "file_count" in details:
        parts.append(f"files={details['file_count']}")
    if "byte_count" in details:
        parts.append(f"bytes={details['byte_count']}")
    if "count" in details:
        parts.append(f"count={details['count']}")
    if details.get("recovery_limited"):
        parts.append(f"limited={details.get('limit_reason') or 'yes'}")
    if "path_stat_error" in details:
        parts.append("stat_error=yes")
    return f" ({', '.join(parts)})" if parts else ""


def _extract_artifact_with_worker_db(*, db_path: Path, artifact_callback: Callable[[Database], object]) -> object:
    worker_db = Database(db_path, migrate=False)
    try:
        return artifact_callback(worker_db)
    finally:
        worker_db.close()


def _windows_old_tools(tools: list) -> list:
    scoped = []
    for tool in tools:
        if tool.name in WINDOWS_OLD_EXCLUDED_TOOLS or not tool.artifacts:
            continue
        scoped_artifacts = [_windows_old_artifact(artifact) for artifact in tool.artifacts]
        scoped.append(replace(tool, artifacts=scoped_artifacts))
    return scoped


def _apply_profile_artifact_overrides(tools: list, profile_config: dict | None) -> list:
    if not profile_config:
        return tools
    force_tsk_artifacts = set(str(item) for item in profile_config.get("force_tsk_artifacts", []))
    recovery_limits = dict(profile_config.get("recovery_limits") or {})
    extraction_policy = str(
        profile_config.get("extraction_policy") or profile_config.get("recovery_policy") or "fast"
    ).lower()
    policy_uses_deleted_recovery = extraction_policy in {"balanced", "deep", "exhaustive", "deleted", "recovery"}
    if not force_tsk_artifacts and not policy_uses_deleted_recovery:
        return tools
    scoped = []
    for tool in tools:
        artifacts = []
        changed = False
        for artifact in tool.artifacts:
            artifact_keys = {artifact.name, f"{tool.name}:{artifact.name}"}
            recovery = artifact.recovery or {}
            policy_force_tsk = _recovery_policy_forces_tsk(extraction_policy, recovery)
            if force_tsk_artifacts.intersection(artifact_keys) or policy_force_tsk:
                scoped_recovery = _recovery_with_profile_limits(recovery, recovery_limits)
                artifacts.append(replace(artifact, use_tsk=True, recovery=scoped_recovery))
                changed = True
            else:
                artifacts.append(artifact)
        scoped.append(replace(tool, artifacts=artifacts) if changed else tool)
    return scoped


def _recovery_with_profile_limits(recovery: dict | None, recovery_limits: dict | None) -> dict:
    scoped = dict(recovery or {})
    limits = dict(recovery_limits or {})
    for profile_key, recovery_key in (
        ("max_files", "max_files"),
        ("max_files_per_artifact", "max_files"),
        ("max_bytes", "max_bytes"),
        ("max_bytes_per_artifact", "max_bytes"),
        ("max_seconds", "max_seconds"),
        ("max_seconds_per_artifact", "max_seconds"),
    ):
        if profile_key in limits and recovery_key not in scoped:
            scoped[recovery_key] = limits[profile_key]
    return scoped


def _recovery_policy_forces_tsk(policy: str, recovery: dict | None) -> bool:
    recovery = recovery or {}
    if not (bool(recovery.get("deleted_files")) or bool(recovery.get("orphaned_files"))):
        return False
    policy = (policy or "fast").lower()
    if policy in {"deep", "exhaustive", "deleted", "recovery"}:
        return True
    if policy != "balanced":
        return False
    cost = str(recovery.get("cost") or "").lower()
    noise = str(recovery.get("noise") or "").lower()
    return cost in {"low", "medium"} and noise == "low"


def profile_extraction_preview(registry: ToolRegistry, profile: str) -> dict:
    profile_config = registry.profiles.get(profile)
    if profile_config is None:
        raise ToolError(f"Profile not configured: {profile}")
    extraction_policy = str(
        profile_config.get("extraction_policy") or profile_config.get("recovery_policy") or "fast"
    ).lower()
    base_tools = registry.profile_tools(profile)
    effective_tools = _apply_profile_artifact_overrides(base_tools, profile_config)
    base_artifacts = {
        f"{tool.name}:{artifact.name}": artifact
        for tool in base_tools
        for artifact in tool.artifacts
    }
    artifacts = []
    forced_count = 0
    for tool in effective_tools:
        for artifact in tool.artifacts:
            key = f"{tool.name}:{artifact.name}"
            base_artifact = base_artifacts.get(key, artifact)
            recovery = artifact.recovery or {}
            forced_by_policy = artifact.use_tsk and not base_artifact.use_tsk
            forced_count += 1 if forced_by_policy else 0
            artifacts.append(
                {
                    "tool_name": tool.name,
                    "artifact_name": artifact.name,
                    "source": artifact.source,
                    "destination": artifact.destination,
                    "default_method": "tsk" if base_artifact.use_tsk else "mount",
                    "effective_method": "tsk" if artifact.use_tsk else "mount",
                    "forced_by_policy": forced_by_policy,
                    "recovery": recovery,
                }
            )
    return {
        "profile": profile,
        "description": profile_config.get("description", ""),
        "extraction_policy": extraction_policy,
        "recommendation": profile_config.get("recommendation", ""),
        "recovery_tier": profile_config.get("recovery_tier", ""),
        "recovery_limits": profile_config.get("recovery_limits") or {},
        "tool_count": len(effective_tools),
        "artifact_count": len(artifacts),
        "policy_tsk_artifact_count": forced_count,
        "tools": [tool.name for tool in effective_tools],
        "artifacts": artifacts,
    }


def _windows_old_artifact(artifact):
    source = _windows_old_source(artifact.source)
    destination = f"{WINDOWS_OLD_ROOT}/{artifact.destination}".strip("/")
    return replace(
        artifact,
        source=source,
        destination=destination,
        include_path_patterns=tuple(_windows_old_pattern(pattern) for pattern in artifact.include_path_patterns),
        exclude_patterns=tuple(
            pattern
            for pattern in artifact.exclude_patterns
            if pattern.replace("\\", "/").lower() not in {f"{WINDOWS_OLD_ROOT.lower()}/*", "windows.old/**"}
        ),
    )


def _windows_old_source(source: str) -> str:
    clean = source.replace("\\", "/").strip("/")
    if not clean:
        return WINDOWS_OLD_ROOT
    if clean.lower().startswith(f"{WINDOWS_OLD_ROOT.lower()}/"):
        return clean
    return f"{WINDOWS_OLD_ROOT}/{clean}"


def _windows_old_pattern(pattern: str) -> str:
    clean = pattern.replace("\\", "/")
    if clean.lower().startswith(f"{WINDOWS_OLD_ROOT.lower()}/"):
        return clean
    if clean.startswith("*/"):
        return f"*/{WINDOWS_OLD_ROOT}/{clean[2:]}"
    return f"{WINDOWS_OLD_ROOT}/{clean}"


def _is_missing_source_error(exc: Exception) -> bool:
    message = str(exc).lower()
    stderr_match = re.search(r"stderr=(?P<path>\\S+)", str(exc))
    if stderr_match:
        try:
            message += "\n" + Path(stderr_match.group("path")).read_text(errors="replace").lower()
        except OSError:
            pass
    return (
        "required input path missing" in message
        or "input path missing" in message
        or "artifact source not found" in message
        or "not found under" in message
        or "source artifact was not present" in message
    )


def _artifact_timing_details(path: Path, metadata: dict | None = None, *, include_path_stats: bool = True) -> dict:
    details = {"path": str(path)}
    if metadata:
        details.update(metadata)
    if not include_path_stats:
        return details
    try:
        if path.is_dir():
            total_files = 0
            total_bytes = 0
            for root, _, files in os.walk(path):
                for filename in files:
                    total_files += 1
                    try:
                        total_bytes += (Path(root) / filename).stat().st_size
                    except OSError:
                        pass
            details.update({"file_count": total_files, "byte_count": total_bytes})
        elif path.exists():
            details.update({"file_count": 1, "byte_count": path.stat().st_size})
    except OSError as exc:
        details["path_stat_error"] = str(exc)
    return details


def run_profile(
    *,
    db: Database,
    paths: WorkspacePaths,
    registry: ToolRegistry,
    case_id: str,
    image_id: str,
    profile: str,
    dry_run: bool,
    include_start_menu_lnk: bool = False,
    include_deleted_mft: bool = False,
    include_live_orphans: bool = False,
    replace_existing: bool = False,
    accept_duplicate: bool = False,
    include_windows_old: bool = False,
    parent_timing_id: str | None = None,
    workers: int = 1,
) -> None:
    image = db.get_image(image_id, case_id)
    profile_label = profile if not include_windows_old else f"{profile}:windows-old"
    profile_started = time.monotonic()
    _progress(f"profile start {profile_label}")
    timing_id = db.start_process_timing(
        case_id=case_id,
        computer_id=image.computer_id,
        image_id=image_id,
        parent_id=parent_timing_id,
        scope="profile",
        phase="profile",
        name=profile_label,
        source_scope=WINDOWS_OLD_OUTPUT_NAMESPACE if include_windows_old else "live",
        details={
            "profile": profile,
            "dry_run": dry_run,
            "include_windows_old": include_windows_old,
            "replace_existing": replace_existing,
            "accept_duplicate": accept_duplicate,
            "requested_workers": workers,
            "effective_workers": workers if workers > 1 else 1,
            "parallel_scope": "artifact_extraction_and_external_tools" if workers > 1 else "serial",
            "parallel_note": (
                "Mounted artifact extraction and external dotnet/binary tool generation can run in parallel; "
                "TSK extraction, DB ingest, dependency barriers, and internal parsers remain serialized."
                if workers > 1
                else ""
            ),
        },
    )
    if workers > 1:
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            level="info",
            event="profile.parallel_external_tools",
            message="Profile workers enabled for mounted artifact extraction and external tool output generation; dependency-sensitive work remains serialized",
            details={
                "profile": profile,
                "requested_workers": workers,
                "parallel_scope": "artifact_extraction_and_external_tools",
            },
        )
    try:
        _run_profile_impl(
            db=db,
            paths=paths,
            registry=registry,
            case_id=case_id,
            image_id=image_id,
            profile=profile,
            dry_run=dry_run,
            include_start_menu_lnk=include_start_menu_lnk,
            include_deleted_mft=include_deleted_mft,
            include_live_orphans=include_live_orphans,
            replace_existing=replace_existing,
            accept_duplicate=accept_duplicate,
            include_windows_old=include_windows_old,
            profile_timing_id=timing_id,
            workers=workers,
        )
    except Exception as exc:
        db.finish_process_timing(timing_id, status="failed", details={"error": str(exc)})
        _progress(f"profile failed {profile_label} elapsed={_format_elapsed(profile_started)} error={exc}")
        raise
    else:
        db.finish_process_timing(timing_id)
        _progress(f"profile completed {profile_label} elapsed={_format_elapsed(profile_started)}")


def _run_profile_impl(
    *,
    db: Database,
    paths: WorkspacePaths,
    registry: ToolRegistry,
    case_id: str,
    image_id: str,
    profile: str,
    dry_run: bool,
    include_start_menu_lnk: bool = False,
    include_deleted_mft: bool = False,
    include_live_orphans: bool = False,
    replace_existing: bool = False,
    accept_duplicate: bool = False,
    include_windows_old: bool = False,
    profile_timing_id: str | None = None,
    workers: int = 1,
) -> None:
    image = db.get_image(image_id, case_id)
    if not dry_run:
        assert_image_not_previously_marked_encrypted(db, case_id=case_id, image_id=image_id)
    mount_row = db.latest_mount(case_id, image_id)
    source_image: Path | None = None
    fallback_source_image: Path | None = None
    offset_sectors: int | None = None
    mounted_volume_path = Path(mount_row["volume_mount_path"]) if mount_row and mount_row["volume_mount_path"] else None
    mounted_volume_active = bool(mounted_volume_path and mounted_volume_path.exists() and mounted_volume_path.is_mount())
    if mount_row and mounted_volume_path and not mounted_volume_active and not dry_run:
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            level="warning",
            event="mount.stale",
            message="Recorded NTFS mount path is not currently mounted; remount before running profiles that require filesystem access",
            details={"mount_path": str(mounted_volume_path), "profile": profile},
        )
    if mount_row and mounted_volume_active:
        mount = Path(mount_row["volume_mount_path"])
        source_image = Path(mount_row["raw_path"])
        fallback_source_image = image.path
        if mount_row["offset_bytes"] is not None:
            offset_sectors = int(mount_row["offset_bytes"]) // 512
    elif mount_row and mount_row["offset_bytes"] is not None:
        mount = paths.volume_mount_dir(case_id, mount_row["partition_id"] or "selected-partition")
        source_image = Path(mount_row["raw_path"])
        fallback_source_image = source_image if source_image.exists() else image.path
        offset_sectors = int(mount_row["offset_bytes"]) // 512
    elif dry_run:
        mount = paths.volume_mount_dir(case_id, "dry-run-selected-partition")
    else:
        raise MountError(
            f"No prepared image recorded for case={case_id} image={image_id}; run image mount first"
        )

    if not dry_run and source_image is None:
        raise MountError(f"No prepared source image recorded for case={case_id} image={image_id}")
    if not dry_run and offset_sectors is None:
        raise MountError(f"No partition offset recorded for case={case_id} image={image_id}")

    profile_config = registry.profiles.get(profile) or {}
    auto_include_windows_old = bool(profile_config.get("include_windows_old")) and not include_windows_old
    windows_old_mode = include_windows_old or bool(profile_config.get("windows_old"))
    tools = _apply_profile_artifact_overrides(registry.profile_tools(profile), profile_config)
    if windows_old_mode:
        if mounted_volume_path and not (mounted_volume_path / WINDOWS_OLD_ROOT).exists():
            db.log_activity(
                case_id=case_id,
                computer_id=image.computer_id,
                image_id=image_id,
                level="info",
                event="windows_old.root_not_present",
                message=f"Windows.old root not present; skipping profile {profile} Windows.old pass",
                details={"profile": profile, "artifact_root": WINDOWS_OLD_ROOT},
            )
            _progress(f"profile skipped {profile}:windows-old reason=Windows.old root not present")
            return
        tools = _windows_old_tools(tools)
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            level="info",
            event="windows_old.profile_started",
            message=f"Running profile {profile} against Windows.old artifacts",
            details={
                "profile": profile,
                "artifact_root": WINDOWS_OLD_ROOT,
                "tools": [tool.name for tool in tools],
            },
        )
    if replace_existing and not dry_run:
        purge_started = time.monotonic()
        _progress(f"profile purge start {profile}{':windows-old' if windows_old_mode else ''}")
        purged = db.purge_tool_data(
            case_id=case_id,
            image_id=image_id,
            tool_names=[tool.name for tool in tools],
        )
        removed_output_folders: list[str] = []
        for tool in tools:
            output_folder = paths.outputs_dir(case_id) / image_id / tool.name
            if output_folder.exists():
                shutil.rmtree(output_folder)
                removed_output_folders.append(str(output_folder))
        if auto_include_windows_old:
            windows_old_output = paths.outputs_dir(case_id) / image_id / WINDOWS_OLD_OUTPUT_NAMESPACE
            if windows_old_output.exists():
                shutil.rmtree(windows_old_output)
                removed_output_folders.append(str(windows_old_output))
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="tool.output_purged",
            message=f"Purged existing tool output records for profile {profile}",
            details={
                "profile": profile,
                "tool_names": [tool.name for tool in tools],
                "outputs": purged,
                "removed_output_folders": removed_output_folders,
            },
        )
        _progress(
            f"profile purge completed {profile}{':windows-old' if windows_old_mode else ''} "
            f"elapsed={_format_elapsed(purge_started)} outputs={purged} folders={len(removed_output_folders)}"
        )
    artifact_definitions = {
        artifact.name: artifact
        for tool in tools
        for artifact in tool.artifacts
    }
    mft_selected_artifacts = {
        artifact.name
        for tool in tools
            if tool.type in {"internal_file_metadata", "internal_mailbox", "internal_zone_identifier"}
            for artifact in tool.artifacts
    }
    artifact_tool_names = {
        artifact.name: tool.name
        for tool in tools
        for artifact in tool.artifacts
    }
    if replace_existing and not dry_run and artifact_definitions:
        artifacts_root = paths.artifacts_dir(case_id) / image_id
        removed_artifacts: list[str] = []
        for artifact in artifact_definitions.values():
            artifact_path = artifacts_root / artifact.destination
            if artifact_path.is_dir():
                shutil.rmtree(artifact_path)
                removed_artifacts.append(str(artifact_path))
            elif artifact_path.exists():
                artifact_path.unlink()
                removed_artifacts.append(str(artifact_path))
        if auto_include_windows_old:
            windows_old_artifacts = artifacts_root / WINDOWS_OLD_ROOT
            if windows_old_artifacts.exists():
                shutil.rmtree(windows_old_artifacts)
                removed_artifacts.append(str(windows_old_artifacts))
        if removed_artifacts:
            db.log_activity(
                case_id=case_id,
                computer_id=image.computer_id,
                image_id=image_id,
                event="artifact.cache_purged",
                message=f"Purged extracted artifact files for profile {profile}",
                details={"profile": profile, "artifacts": removed_artifacts},
            )
    artifact_paths: dict[str, Path] = {}
    if artifact_definitions:
        artifacts_root = paths.artifacts_dir(case_id) / image_id
        artifacts_root.mkdir(parents=True, exist_ok=True)
        use_mounted_extraction = bool(mounted_volume_active and not dry_run)
        needs_recursive_inventory = any(
            artifact.name not in mft_selected_artifacts for artifact in artifact_definitions.values()
        )
        if (
            not dry_run
            and not use_mounted_extraction
            and needs_recursive_inventory
            and os.environ.get("FORENSIC_ALLOW_RECURSIVE_TSK_INVENTORY") != "1"
        ):
            raise MountError(
                "Profile requires a mounted NTFS filesystem; refusing broad recursive TSK inventory. "
                "Mount the volume first, or set FORENSIC_ALLOW_RECURSIVE_TSK_INVENTORY=1 to permit fallback."
            )
        if not dry_run and not use_mounted_extraction:
            validate_tsk_available()
        fls_entries = None
        mounted_files = None
        fls_fallback_attempted = False
        fls_fallback_entries: list | None = None

        def fls_entries_provider():
            nonlocal fls_fallback_attempted
            nonlocal fls_fallback_entries
            if fls_fallback_attempted:
                return fls_fallback_entries
            fls_fallback_attempted = True
            try:
                validate_tsk_available()
                fls_fallback_entries = list_files(
                    db=db,
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=image.computer_id,
                    raw_image=fallback_source_image or source_image or paths.ewf_raw_path(case_id),
                    offset_sectors=offset_sectors or 0,
                    output_folder=paths.jobs_dir(case_id) / "tsk" / image_id / "fls-fallback",
                    dry_run=dry_run,
                )
            except Exception as exc:
                db.log_activity(
                    case_id=case_id,
                    computer_id=image.computer_id,
                    image_id=image_id,
                    level="warning",
                    event="tsk.fallback_inventory_failed",
                    message="Sleuth Kit fallback inventory failed; continuing with mounted extraction only",
                    details={"error": str(exc), "source_image": str(fallback_source_image or source_image)},
                )
                fls_fallback_entries = None
            return fls_fallback_entries

        if not use_mounted_extraction and needs_recursive_inventory:
            fls_entries = list_files(
                db=db,
                case_id=case_id,
                image_id=image_id,
                computer_id=image.computer_id,
                raw_image=fallback_source_image or source_image or paths.ewf_raw_path(case_id),
                offset_sectors=offset_sectors or 0,
                output_folder=paths.jobs_dir(case_id) / "tsk" / image_id / "fls",
                dry_run=dry_run,
            )
        if use_mounted_extraction and any(
            artifact.recursive and not artifact.source and not artifact.process_in_place
            for artifact in artifact_definitions.values()
        ):
            mounted_files, _ = inventory_mounted_files(
                db=db,
                case_id=case_id,
                image_id=image_id,
                computer_id=image.computer_id,
                mount_path=Path(mount_row["volume_mount_path"]),
            )
        def extract_profile_artifact(artifact, *, artifact_db: Database | None = None, record_path: bool = True):
            nonlocal fls_entries
            active_db = artifact_db or db
            extraction_method = "mft" if artifact.name in mft_selected_artifacts else (
                "mount" if use_mounted_extraction and not artifact.use_tsk else "tsk"
            )
            artifact_started = time.monotonic()
            _progress(f"artifact start {artifact.name} method={extraction_method}")
            artifact_timing_id = active_db.start_process_timing(
                case_id=case_id,
                computer_id=image.computer_id,
                image_id=image_id,
                parent_id=profile_timing_id,
                scope="artifact",
                phase="extract",
                name=artifact.name,
                tool_name=artifact_tool_names.get(artifact.name),
                artifact_name=artifact.name,
                source_scope=WINDOWS_OLD_OUTPUT_NAMESPACE if windows_old_mode else "live",
                details={
                    "profile": profile,
                    "source": artifact.source,
                    "destination": artifact.destination,
                    "method": extraction_method,
                    "use_tsk": artifact.use_tsk,
                    "recovery": artifact.recovery or {},
                    "windows_old": windows_old_mode,
                },
            )
            try:
                if artifact.name in mft_selected_artifacts:
                    extracted = extract_artifact_from_mft(
                        db=active_db,
                        case_id=case_id,
                        image_id=image_id,
                        computer_id=image.computer_id,
                        raw_image=fallback_source_image or source_image or paths.ewf_raw_path(case_id),
                        offset_sectors=offset_sectors or 0,
                        artifact=artifact,
                        artifacts_root=artifacts_root,
                        dry_run=dry_run,
                        tool_name=artifact_tool_names.get(artifact.name),
                        include_deleted_mft=include_deleted_mft,
                        include_live_orphans=include_live_orphans,
                        fls_entries=None if dry_run or mounted_volume_active else fls_entries_provider(),
                        mount_path=Path(mount_row["volume_mount_path"]) if mounted_volume_active and mount_row else None,
                    )
                elif use_mounted_extraction and not artifact.use_tsk:
                    extracted = extract_artifact_from_mount(
                        db=active_db,
                        case_id=case_id,
                        image_id=image_id,
                        computer_id=image.computer_id,
                        mount_path=Path(mount_row["volume_mount_path"]),
                        artifact=artifact,
                        artifacts_root=artifacts_root,
                        dry_run=dry_run,
                        ignore_exclude_patterns=artifact.name == "lnk_files" and include_start_menu_lnk,
                        mounted_files=mounted_files,
                        raw_image=fallback_source_image or source_image,
                        salvage_raw_image=source_image,
                        offset_sectors=offset_sectors,
                        fls_entries=fls_entries,
                        fls_entries_provider=fls_entries_provider,
                    )
                else:
                    current_fls_entries = fls_entries
                    if use_mounted_extraction and artifact.use_tsk and current_fls_entries is None:
                        current_fls_entries = fls_entries_provider()
                        if artifact_db is None:
                            fls_entries = current_fls_entries
                    extracted = extract_artifact(
                        db=active_db,
                        case_id=case_id,
                        image_id=image_id,
                        computer_id=image.computer_id,
                        raw_image=fallback_source_image or source_image or paths.ewf_raw_path(case_id),
                        offset_sectors=offset_sectors or 0,
                        artifact=artifact,
                        artifacts_root=artifacts_root,
                        dry_run=dry_run,
                        fls_entries=current_fls_entries,
                        ignore_exclude_patterns=artifact.name == "lnk_files" and include_start_menu_lnk,
                    )
            except Exception as exc:
                if windows_old_mode and _is_missing_source_error(exc):
                    active_db.finish_process_timing(
                        artifact_timing_id,
                        status="source_not_present",
                        details={"error": str(exc)},
                    )
                    _progress(
                        f"artifact source_not_present {artifact.name} method={extraction_method} "
                        f"elapsed={_format_elapsed(artifact_started)} error={exc}"
                    )
                    active_db.log_activity(
                        case_id=case_id,
                        computer_id=image.computer_id,
                        image_id=image_id,
                        level="warning",
                        event="windows_old.artifact_source_not_present",
                        message=f"Windows.old source artifact was not present for {artifact.name}; continuing",
                        details={"artifact": artifact.name, "error": str(exc)},
                    )
                    return None
                active_db.finish_process_timing(artifact_timing_id, status="failed", details={"error": str(exc)})
                _progress(
                    f"artifact failed {artifact.name} method={extraction_method} "
                    f"elapsed={_format_elapsed(artifact_started)} error={exc}"
                )
                raise
            artifact_details = _artifact_timing_details(
                extracted.path,
                getattr(extracted, "metadata", None),
                include_path_stats=not artifact.process_in_place,
            )
            active_db.finish_process_timing(
                artifact_timing_id,
                status="partial_limited" if artifact_details.get("recovery_limited") else "completed",
                details=artifact_details,
            )
            _progress(
                f"artifact {'partial_limited' if artifact_details.get('recovery_limited') else 'completed'} {artifact.name} method={extraction_method} "
                f"elapsed={_format_elapsed(artifact_started)}{_progress_detail(artifact_details)}"
            )
            if record_path:
                artifact_paths[artifact.name] = extracted.path
            if artifact.name == "prefetch_files" and not dry_run:
                inventory = inventory_prefetch_directory(extracted.path)
                active_db.log_activity(
                    case_id=case_id,
                    computer_id=image.computer_id,
                    image_id=image_id,
                    level="warning" if inventory.modern_compressed else "info",
                    event="artifact.prefetch_inventory",
                    message=(
                        "Prefetch inventory includes Windows 10/11 MAM-compressed files"
                        if inventory.modern_compressed
                        else "Prefetch inventory completed"
                    ),
                    details=inventory.as_dict(),
                )
            return extracted

        initial_artifacts = [
            artifact for artifact in artifact_definitions.values() if artifact.name not in mft_selected_artifacts
        ]
        if workers > 1 and not dry_run and len(initial_artifacts) > 1:
            parallel_artifacts = [artifact for artifact in initial_artifacts if not artifact.use_tsk]
            serial_artifacts = [artifact for artifact in initial_artifacts if artifact.use_tsk]
            artifact_tasks: list[ProcessingTask] = []
            for artifact in parallel_artifacts:
                artifact_tasks.append(
                    ProcessingTask(
                        name=f"profile-artifact:{artifact.name}",
                        payload={"artifact_name": artifact.name},
                        worker=lambda artifact=artifact: _extract_artifact_with_worker_db(
                            db_path=paths.db_path(),
                            artifact_callback=lambda worker_db, artifact=artifact: extract_profile_artifact(
                                artifact,
                                artifact_db=worker_db,
                                record_path=False,
                            ),
                        ),
                    )
                )
            for result in run_processing_tasks(artifact_tasks, workers=workers):
                if result.status == "failed":
                    raise ToolError(f"{result.name} failed during parallel artifact extraction: {result.error}")
                if result.value is not None:
                    artifact_paths[result.value.name] = result.value.path
            for artifact in serial_artifacts:
                extract_profile_artifact(artifact)
        else:
            for artifact in initial_artifacts:
                extract_profile_artifact(artifact)

    parallel_tool_tasks: list[ProcessingTask] = []
    parallel_tool_contexts: dict[str, dict[str, object]] = {}
    parallel_enabled = workers > 1

    def flush_parallel_tool_tasks() -> None:
        nonlocal parallel_tool_tasks
        if not parallel_tool_tasks:
            return
        for result in run_processing_tasks(parallel_tool_tasks, workers=workers):
            context = parallel_tool_contexts.pop(result.name)
            tool = context["tool"]
            tool_timing_id = str(context["tool_timing_id"])
            tool_started = float(context["tool_started"])
            if result.status == "failed":
                db.finish_process_timing(
                    tool_timing_id,
                    status="failed",
                    details={"error": result.error, "parallelized": True},
                )
                _progress(f"tool failed {tool.name} elapsed={_format_elapsed(tool_started)} error={result.error}")
                raise ToolError(f"{tool.name} failed during parallel generation: {result.error}")
            try:
                ingest_generated_tool_outputs(
                    db=db,
                    case_id=case_id,
                    image_id=image_id,
                    computer_id=image.computer_id,
                    tool=tool,
                    generated=result.value,
                    accept_duplicate=accept_duplicate or windows_old_mode,
                    rebuild_correlations=False,
                    raw_image=source_image or fallback_source_image or paths.ewf_raw_path(case_id),
                    offset_sectors=offset_sectors or 0,
                    mount=mount,
                )
            except Exception as exc:
                db.finish_process_timing(
                    tool_timing_id,
                    status="failed",
                    details={"error": str(exc), "parallelized": True},
                )
                _progress(f"tool failed {tool.name} elapsed={_format_elapsed(tool_started)} error={exc}")
                raise
            db.finish_process_timing(
                tool_timing_id,
                details={
                    "parallelized": True,
                    "generate_seconds": round(result.duration_seconds, 3),
                    "requested_workers": workers,
                },
            )
            _progress(f"tool completed {tool.name} elapsed={_format_elapsed(tool_started)} parallelized=yes")
        parallel_tool_tasks = []

    for tool in tools:
        if tool.name in MFT_DEPENDENT_TOOL_BARRIERS:
            flush_parallel_tool_tasks()
        for artifact in tool.artifacts:
            if artifact.name in mft_selected_artifacts and artifact.name not in artifact_paths:
                flush_parallel_tool_tasks()
                extract_profile_artifact(artifact)
        missing_tool_artifacts = [artifact.name for artifact in tool.artifacts if artifact.name not in artifact_paths]
        tool_artifacts = {
            artifact.name: artifact_paths[artifact.name]
            for artifact in tool.artifacts
            if artifact.name in artifact_paths
        }
        tool_timing_id = db.start_process_timing(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            parent_id=profile_timing_id,
            scope="tool",
            phase="parse",
            name=tool.name,
            tool_name=tool.name,
            source_scope=WINDOWS_OLD_OUTPUT_NAMESPACE if windows_old_mode else "live",
            details={
                "profile": profile,
                "tool_type": tool.type,
                "artifact_names": sorted(tool_artifacts),
                "windows_old": windows_old_mode,
                "output_namespace": WINDOWS_OLD_OUTPUT_NAMESPACE if windows_old_mode else None,
            },
        )
        tool_started = time.monotonic()
        if windows_old_mode and missing_tool_artifacts:
            db.finish_process_timing(
                tool_timing_id,
                status="source_not_present",
                details={"missing_artifacts": missing_tool_artifacts},
            )
            _progress(
                f"tool source_not_present {tool.name} elapsed={_format_elapsed(tool_started)} "
                f"missing_artifacts={','.join(missing_tool_artifacts)}"
            )
            db.log_activity(
                case_id=case_id,
                computer_id=image.computer_id,
                image_id=image_id,
                level="warning",
                event="windows_old.tool_source_not_present",
                message=f"Windows.old source artifacts were not present for {tool.name}; continuing",
                details={"tool": tool.name, "missing_artifacts": missing_tool_artifacts},
            )
            continue
        _progress(f"tool start {tool.name} artifacts={','.join(sorted(tool_artifacts)) or '-'}")
        if parallel_enabled and supports_parallel_generate(tool):
            task_name = f"profile-tool:{tool.name}"
            parallel_tool_contexts[task_name] = {
                "tool": tool,
                "tool_timing_id": tool_timing_id,
                "tool_started": tool_started,
            }
            parallel_tool_tasks.append(
                ProcessingTask(
                    name=task_name,
                    payload={"tool_name": tool.name},
                    worker=lambda tool=tool, tool_artifacts=tool_artifacts: generate_external_tool_outputs(
                        paths=paths,
                        case_id=case_id,
                        image_id=image_id,
                        tool=tool,
                        mount=mount,
                        artifacts=tool_artifacts,
                        dry_run=dry_run,
                        output_namespace=WINDOWS_OLD_OUTPUT_NAMESPACE if windows_old_mode else None,
                    ),
                )
            )
            _progress(f"tool queued_parallel {tool.name} workers={workers}")
            continue
        try:
            run_tool(
                db=db,
                paths=paths,
                case_id=case_id,
                image_id=image_id,
                tool=tool,
                mount=mount,
                artifacts=tool_artifacts,
                computer_id=image.computer_id,
                dry_run=dry_run,
                accept_duplicate=accept_duplicate or windows_old_mode,
                output_namespace=WINDOWS_OLD_OUTPUT_NAMESPACE if windows_old_mode else None,
                rebuild_correlations=False,
                raw_image=source_image or fallback_source_image or paths.ewf_raw_path(case_id),
                offset_sectors=offset_sectors or 0,
            )
        except Exception as exc:
            missing_windows_old_source = windows_old_mode and _is_missing_source_error(exc)
            db.finish_process_timing(
                tool_timing_id,
                status="source_not_present" if missing_windows_old_source else "failed",
                details={"error": str(exc)},
            )
            _progress(
                f"tool {'source_not_present' if missing_windows_old_source else 'failed'} {tool.name} "
                f"elapsed={_format_elapsed(tool_started)} error={exc}"
            )
            if not windows_old_mode:
                raise
            db.log_activity(
                case_id=case_id,
                computer_id=image.computer_id,
                image_id=image_id,
                level="warning",
                event="windows_old.source_not_present" if missing_windows_old_source else "windows_old.tool_failed",
                message=(
                    f"Windows.old source artifact was not present for {tool.name}; continuing with remaining tools"
                    if missing_windows_old_source
                    else f"Windows.old parser failed for {tool.name}; continuing with remaining tools"
                ),
                details={"tool": tool.name, "error": str(exc)},
            )
        else:
            db.finish_process_timing(tool_timing_id)
            _progress(f"tool completed {tool.name} elapsed={_format_elapsed(tool_started)}")

    flush_parallel_tool_tasks()

    def timed_postprocess(name: str, callback):
        postprocess_started = time.monotonic()
        _progress(f"postprocess start {name}")
        timing_id = db.start_process_timing(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            parent_id=profile_timing_id,
            scope="postprocess",
            phase="rebuild",
            name=name,
            details={"profile": profile, "windows_old": windows_old_mode},
        )
        try:
            result = callback()
        except Exception as exc:
            db.finish_process_timing(timing_id, status="failed", details={"error": str(exc)})
            _progress(f"postprocess failed {name} elapsed={_format_elapsed(postprocess_started)} error={exc}")
            raise
        details = result if isinstance(result, dict) else {"count": result}
        db.finish_process_timing(timing_id, details=details)
        _progress(f"postprocess completed {name} elapsed={_format_elapsed(postprocess_started)}{_progress_detail(details)}")
        return result

    if not dry_run and any(
        tool.name in {"MFTECmd", "LECmd", "JLECmd", "PrefetchParser"} for tool in tools
    ):
        count = timed_postprocess(
            "file_correlations",
            lambda: rebuild_file_correlations(db, case_id=case_id, image_id=image_id),
        )
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="file_correlations.rebuilt",
            message=f"Rebuilt {count} file correlations after profile {profile}",
            details={"profile": profile, "count": count},
        )
    if not dry_run and any(
        tool.name in {
            "MFTECmd",
            "MFTECmdUSN",
            "MFTECmdLogFile",
            "NTFSParseLogFile",
            "MFTECmdI30",
            "WindowsSearchGatherParser",
            "WindowsSearchESEParser",
        }
        for tool in tools
    ):
        count = timed_postprocess(
            "filesystem_review",
            lambda: rebuild_filesystem_review(db, case_id=case_id, image_id=image_id),
        )
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="filesystem_review.rebuilt",
            message=f"Rebuilt {count} filesystem review rows after profile {profile}",
            details={"profile": profile, "count": count},
        )
    if not dry_run and any(tool.name == "MFTECmd" for tool in tools):
        count = timed_postprocess(
            "nested_evidence_inventory",
            lambda: rebuild_nested_evidence_inventory(db, case_id=case_id, image_id=image_id),
        )
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="nested_evidence.inventory_rebuilt",
            message=f"Inventoried {count} nested disk image candidates after profile {profile}",
            details={"profile": profile, "count": count},
        )
    if not dry_run and any(tool.name in TIMELINE_TOOLS for tool in tools):
        stats = timed_postprocess(
            "timeline_windows_old_dedupe",
            lambda: rebuild_timeline_windows_old_dedupe(db, case_id=case_id, image_id=image_id),
        )
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="timeline.windows_old_dedupe_profile_rebuilt",
            message=f"Rebuilt Windows.old timeline dedupe after profile {profile}",
            details={"profile": profile, **stats},
        )
    if not dry_run and any(tool.name in ARTIFACT_DEDUPE_TOOLS for tool in tools):
        stats = timed_postprocess(
            "artifact_windows_old_dedupe",
            lambda: rebuild_artifact_windows_old_dedupe(db, case_id=case_id, image_id=image_id),
        )
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="artifact.windows_old_dedupe_profile_rebuilt",
            message=f"Rebuilt Windows.old artifact dedupe after profile {profile}",
            details={"profile": profile, **stats},
        )
        session_stats = timed_postprocess(
            "derived_sessions",
            lambda: rebuild_sessions(db, case_id=case_id, image_id=image_id),
        )
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="derived_sessions.profile_rebuilt",
            message=f"Rebuilt derived sessions after profile {profile}",
            details={"profile": profile, **session_stats},
        )
        correlation_stats = timed_postprocess(
            "correlation_framework",
            lambda: rebuild_correlation_framework(db, case_id=case_id, image_id=image_id),
        )
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="correlation_framework.profile_rebuilt",
            message=f"Rebuilt correlation framework after profile {profile}",
            details={"profile": profile, **correlation_stats},
        )
    if not dry_run and any(
        tool.name in {"WindowsDefenderParser", "WindowsErrorReportingParser", "EtlParser"} for tool in tools
    ):
        count = timed_postprocess(
            "user_file_references",
            lambda: rebuild_user_controlled_file_references(db, case_id=case_id, image_id=image_id),
        )
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            event="user_file_references.rebuilt",
            message=f"Rebuilt {count} user-controlled file reference rows after profile {profile}",
            details={"profile": profile, "count": count},
        )
    if auto_include_windows_old:
        db.log_activity(
            case_id=case_id,
            computer_id=image.computer_id,
            image_id=image_id,
            level="info",
            event="windows_old.profile_queued",
            message=f"Profile {profile} includes Windows.old; starting scoped Windows.old pass",
            details={"profile": profile, "artifact_root": WINDOWS_OLD_ROOT},
        )
        run_profile(
            db=db,
            paths=paths,
            registry=registry,
            case_id=case_id,
            image_id=image_id,
            profile=profile,
            dry_run=dry_run,
            include_start_menu_lnk=include_start_menu_lnk,
            include_deleted_mft=include_deleted_mft,
            include_live_orphans=include_live_orphans,
            replace_existing=False,
            accept_duplicate=True,
            include_windows_old=True,
            parent_timing_id=profile_timing_id,
            workers=workers,
        )
