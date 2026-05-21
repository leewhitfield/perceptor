from __future__ import annotations

from dataclasses import replace
import os
import shutil
from pathlib import Path

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
from forensic_orchestrator.mounting.tsk import extract_artifact, list_files, validate_tsk_available
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError
from forensic_orchestrator.timeline_dedupe import rebuild_timeline_windows_old_dedupe

from .prefetch import inventory_prefetch_directory
from .registry import ToolRegistry
from .runner import run_tool


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


def _windows_old_tools(tools: list) -> list:
    scoped = []
    for tool in tools:
        if tool.name in WINDOWS_OLD_EXCLUDED_TOOLS or not tool.artifacts:
            continue
        scoped_artifacts = [_windows_old_artifact(artifact) for artifact in tool.artifacts]
        scoped.append(replace(tool, artifacts=scoped_artifacts))
    return scoped


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


def _artifact_timing_details(path: Path, metadata: dict | None = None) -> dict:
    details = {"path": str(path)}
    if metadata:
        details.update(metadata)
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
) -> None:
    image = db.get_image(image_id, case_id)
    timing_id = db.start_process_timing(
        case_id=case_id,
        computer_id=image.computer_id,
        image_id=image_id,
        parent_id=parent_timing_id,
        scope="profile",
        phase="profile",
        name=profile if not include_windows_old else f"{profile}:windows-old",
        details={
            "profile": profile,
            "dry_run": dry_run,
            "include_windows_old": include_windows_old,
            "replace_existing": replace_existing,
            "accept_duplicate": accept_duplicate,
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
        )
    except Exception as exc:
        db.finish_process_timing(timing_id, status="failed", details={"error": str(exc)})
        raise
    else:
        db.finish_process_timing(timing_id)


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
    tools = registry.profile_tools(profile)
    if windows_old_mode:
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
            artifact.recursive and not artifact.source for artifact in artifact_definitions.values()
        ):
            mounted_files, _ = inventory_mounted_files(
                db=db,
                case_id=case_id,
                image_id=image_id,
                computer_id=image.computer_id,
                mount_path=Path(mount_row["volume_mount_path"]),
            )
        def extract_profile_artifact(artifact):
            nonlocal fls_entries
            extraction_method = "mft" if artifact.name in mft_selected_artifacts else (
                "mount" if use_mounted_extraction and not artifact.use_tsk else "tsk"
            )
            artifact_timing_id = db.start_process_timing(
                case_id=case_id,
                computer_id=image.computer_id,
                image_id=image_id,
                parent_id=profile_timing_id,
                scope="artifact",
                phase="extract",
                name=artifact.name,
                tool_name=artifact_tool_names.get(artifact.name),
                artifact_name=artifact.name,
                details={
                    "profile": profile,
                    "source": artifact.source,
                    "destination": artifact.destination,
                    "method": extraction_method,
                    "windows_old": windows_old_mode,
                },
            )
            try:
                if artifact.name in mft_selected_artifacts:
                    extracted = extract_artifact_from_mft(
                        db=db,
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
                        db=db,
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
                    if use_mounted_extraction and artifact.use_tsk and fls_entries is None:
                        fls_entries = fls_entries_provider()
                    extracted = extract_artifact(
                        db=db,
                        case_id=case_id,
                        image_id=image_id,
                        computer_id=image.computer_id,
                        raw_image=fallback_source_image or source_image or paths.ewf_raw_path(case_id),
                        offset_sectors=offset_sectors or 0,
                        artifact=artifact,
                        artifacts_root=artifacts_root,
                        dry_run=dry_run,
                        fls_entries=fls_entries,
                        ignore_exclude_patterns=artifact.name == "lnk_files" and include_start_menu_lnk,
                    )
            except Exception as exc:
                db.finish_process_timing(artifact_timing_id, status="failed", details={"error": str(exc)})
                raise
            db.finish_process_timing(
                artifact_timing_id,
                details=_artifact_timing_details(extracted.path, getattr(extracted, "metadata", None)),
            )
            artifact_paths[artifact.name] = extracted.path
            if artifact.name == "prefetch_files" and not dry_run:
                inventory = inventory_prefetch_directory(extracted.path)
                db.log_activity(
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

        for artifact in artifact_definitions.values():
            if artifact.name in mft_selected_artifacts:
                continue
            extract_profile_artifact(artifact)

    for tool in tools:
        for artifact in tool.artifacts:
            if artifact.name in mft_selected_artifacts and artifact.name not in artifact_paths:
                extract_profile_artifact(artifact)
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
            details={
                "profile": profile,
                "tool_type": tool.type,
                "artifact_names": sorted(tool_artifacts),
                "windows_old": windows_old_mode,
                "output_namespace": WINDOWS_OLD_OUTPUT_NAMESPACE if windows_old_mode else None,
            },
        )
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
                raw_image=fallback_source_image or source_image or paths.ewf_raw_path(case_id),
                offset_sectors=offset_sectors or 0,
            )
        except Exception as exc:
            db.finish_process_timing(tool_timing_id, status="failed", details={"error": str(exc)})
            if not windows_old_mode:
                raise
            db.log_activity(
                case_id=case_id,
                computer_id=image.computer_id,
                image_id=image_id,
                level="warning",
                event="windows_old.tool_failed",
                message=f"Windows.old parser failed for {tool.name}; continuing with remaining tools",
                details={"tool": tool.name, "error": str(exc)},
            )
        else:
            db.finish_process_timing(tool_timing_id)

    def timed_postprocess(name: str, callback):
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
            raise
        details = result if isinstance(result, dict) else {"count": result}
        db.finish_process_timing(timing_id, details=details)
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
        )
