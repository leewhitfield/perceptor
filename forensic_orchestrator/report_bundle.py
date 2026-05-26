from __future__ import annotations

import csv
import json
import re
import shutil
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from forensic_orchestrator.artifact_correlations import rebuild_artifact_correlations
from forensic_orchestrator.artifact_distinct import rebuild_distinct_artifact_tables
from forensic_orchestrator.common_dialog import rebuild_common_dialog_items
from forensic_orchestrator.copied_indicators import rebuild_copied_file_indicators
from forensic_orchestrator.correlation import rebuild_file_correlations
from forensic_orchestrator.db import Database
from forensic_orchestrator.evidence import create_case, create_computer
from forensic_orchestrator.image_metadata import collect_image_metadata
from forensic_orchestrator.nested_evidence import rebuild_nested_evidence_inventory
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.sessions import rebuild_sessions
from forensic_orchestrator.timeline_dedupe import rebuild_timeline_windows_old_dedupe
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.runner import file_sha256
from forensic_orchestrator.tools.usb_summary import rebuild_usb_connection_events, rebuild_usb_storage_devices


TransformFn = Callable[[Path, Path], Path]
ProgressFn = Callable[[str], None]


@dataclass(frozen=True)
class ReportCandidate:
    source_path: Path
    tool_name: str
    transform: TransformFn | None = None
    note: str = ""


@dataclass
class ReportImportItem:
    path: str
    tool_name: str | None
    status: str
    row_count: int = 0
    output_path: str | None = None
    error: str | None = None
    note: str | None = None


@dataclass
class ReportBundleImportResult:
    case_id: str
    computer_id: str
    image_id: str
    report_root: str
    markdown_path: str
    imported_files: int = 0
    imported_rows: int = 0
    skipped_files: int = 0
    failed_files: int = 0
    warnings: list[str] = field(default_factory=list)
    items: list[ReportImportItem] = field(default_factory=list)


@dataclass
class ReportBundleBulkImportResult:
    case_id: str
    report_root: str
    imported_computers: int = 0
    imported_files: int = 0
    imported_rows: int = 0
    skipped_files: int = 0
    failed_files: int = 0
    warnings: list[str] = field(default_factory=list)
    items: list[ReportBundleImportResult] = field(default_factory=list)
    markdown_path: str = ""


def import_report_bundle(
    *,
    db: Database,
    paths: WorkspacePaths,
    report_root: Path,
    case_id: str | None = None,
    computer_id: str | None = None,
    computer_label: str | None = None,
    accept_duplicate: bool = False,
    progress: ProgressFn | None = None,
) -> ReportBundleImportResult:
    report_root = report_root.resolve()
    if not report_root.is_dir():
        raise ValueError(f"Report bundle path is not a directory: {report_root}")
    started = datetime.now(timezone.utc)
    _progress(progress, f"report-bundle start root={report_root}")

    if case_id is None:
        case_id = create_case(db, paths)
    else:
        db.get_case(case_id)
        paths.ensure_case_tree(case_id)

    if computer_id is None:
        computer = create_computer(
            db,
            paths,
            case_id,
            label=computer_label or report_root.name or "report-bundle",
        )
        computer_id = computer.id
    else:
        db.get_computer(computer_id, case_id)

    image_id = str(uuid.uuid4())
    image = db.add_image(image_id, case_id, report_root, computer_id=computer_id)
    metadata_rows = collect_image_metadata(report_root)
    metadata_rows.extend(
        [
            {"source": "report_bundle", "key": "source_type", "value": "pre_generated_reports"},
            {"source": "report_bundle", "key": "importer", "value": "kape_ez_report_bundle"},
        ]
    )
    db.replace_image_metadata(case_id=case_id, image_id=image.id, rows=metadata_rows)

    root_timing_id = db.start_process_timing(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        scope="report_bundle",
        phase="import",
        name="Import pre-generated report bundle",
        artifact_name=report_root.name,
        source_scope="report_bundle",
        details={"path": str(report_root)},
    )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        level="info",
        event="report_bundle.import_started",
        message="Started report bundle import",
        details={"path": str(report_root)},
    )

    result = ReportBundleImportResult(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        report_root=str(report_root),
        markdown_path="",
    )
    transformed_dir = paths.outputs_dir(case_id) / "report-bundle-import" / image_id / "transformed"
    transformed_dir.mkdir(parents=True, exist_ok=True)

    try:
        csv_paths = sorted(report_root.rglob("*.csv"))
        _progress(progress, f"report-bundle discovered csv_files={len(csv_paths)} computer={computer_label or report_root.name}")
        for index, csv_path in enumerate(csv_paths, 1):
            candidate = infer_report_candidate(csv_path)
            if candidate is None:
                result.skipped_files += 1
                result.items.append(
                    ReportImportItem(
                        path=str(csv_path),
                        tool_name=None,
                        status="unsupported",
                        note="No safe importer mapping for this CSV",
                    )
                )
                _progress(
                    progress,
                    f"report-bundle csv {index}/{len(csv_paths)} unsupported path={_display_path(csv_path, report_root)}",
                )
                continue
            _progress(
                progress,
                f"report-bundle csv {index}/{len(csv_paths)} import tool={candidate.tool_name} path={_display_path(csv_path, report_root)}",
            )
            item_timing_id = db.start_process_timing(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                parent_id=root_timing_id,
                scope="report_bundle",
                phase="csv_import",
                name=csv_path.name,
                tool_name=candidate.tool_name,
                artifact_name=csv_path.parent.name,
                source_scope="report_bundle",
                details={"path": str(csv_path), "note": candidate.note},
            )
            try:
                import_path = csv_path
                if candidate.transform is not None:
                    import_path = candidate.transform(
                        csv_path,
                        transformed_dir / _transformed_name(csv_path, candidate.tool_name),
                    )
                content_sha256 = file_sha256(import_path)
                duplicate = db.duplicate_tool_output(
                    case_id=case_id,
                    image_id=image_id,
                    tool_name=candidate.tool_name,
                    content_sha256=content_sha256,
                )
                if duplicate is not None and not accept_duplicate:
                    result.skipped_files += 1
                    result.items.append(
                        ReportImportItem(
                            path=str(csv_path),
                            tool_name=candidate.tool_name,
                            status="duplicate",
                            output_path=str(import_path),
                            note=f"Duplicate of tool output {duplicate['id']}",
                        )
                    )
                    db.finish_process_timing(item_timing_id, status="skipped", details={"duplicate_output_id": duplicate["id"]})
                    _progress(
                        progress,
                        f"report-bundle csv {index}/{len(csv_paths)} duplicate tool={candidate.tool_name} imported_files={result.imported_files} skipped={result.skipped_files}",
                    )
                    continue
                tool_output_id = str(uuid.uuid4())
                row_count = ingest_csv_output(
                    db=db,
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    tool_output_id=tool_output_id,
                    tool_name=candidate.tool_name,
                    path=import_path,
                    rebuild_correlations=False,
                )
                db.insert_tool_output(
                    {
                        "id": tool_output_id,
                        "case_id": case_id,
                        "computer_id": computer_id,
                        "image_id": image_id,
                        "tool_name": candidate.tool_name,
                        "output_type": "csv",
                        "path": import_path,
                        "content_sha256": content_sha256,
                        "row_count": row_count,
                    }
                )
                result.imported_files += 1
                result.imported_rows += row_count
                result.items.append(
                    ReportImportItem(
                        path=str(csv_path),
                        tool_name=candidate.tool_name,
                        status="imported",
                        row_count=row_count,
                        output_path=str(import_path),
                        note=candidate.note,
                    )
                )
                db.finish_process_timing(item_timing_id, details={"row_count": row_count, "output_path": str(import_path)})
                _progress(
                    progress,
                    f"report-bundle csv {index}/{len(csv_paths)} imported tool={candidate.tool_name} rows={row_count} total_rows={result.imported_rows}",
                )
            except Exception as exc:  # keep importing remaining report outputs
                result.failed_files += 1
                result.items.append(
                    ReportImportItem(
                        path=str(csv_path),
                        tool_name=candidate.tool_name,
                        status="failed",
                        error=str(exc),
                        note=candidate.note,
                    )
                )
                db.log_activity(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    level="error",
                    event="report_bundle.csv_import_failed",
                    message="Failed to import report CSV",
                    details={"path": str(csv_path), "tool_name": candidate.tool_name, "error": str(exc)},
                )
                db.finish_process_timing(item_timing_id, status="failed", details={"error": str(exc)})
                _progress(
                    progress,
                    f"report-bundle csv {index}/{len(csv_paths)} failed tool={candidate.tool_name} failed={result.failed_files} error={exc}",
                )

        _progress(progress, "report-bundle postprocess start")
        result.warnings.extend(_run_post_import_rebuilds(db, case_id=case_id, image_id=image_id))
        _progress(progress, "report-bundle postprocess completed")
        markdown_path = _write_markdown_report(paths, result)
        result.markdown_path = str(markdown_path)
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            level="info" if result.failed_files == 0 else "warning",
            event="report_bundle.import_completed",
            message="Completed report bundle import",
            details={
                "path": str(report_root),
                "imported_files": result.imported_files,
                "imported_rows": result.imported_rows,
                "skipped_files": result.skipped_files,
                "failed_files": result.failed_files,
                "warnings": result.warnings,
                "markdown_path": str(markdown_path),
            },
        )
        db.finish_process_timing(
            root_timing_id,
            status="completed" if result.failed_files == 0 else "completed_with_errors",
            details={
                "imported_files": result.imported_files,
                "imported_rows": result.imported_rows,
                "skipped_files": result.skipped_files,
                "failed_files": result.failed_files,
                "warnings": result.warnings,
                "markdown_path": str(markdown_path),
            },
        )
        _progress(
            progress,
            "report-bundle completed "
            f"elapsed={_format_elapsed(started)} imported_files={result.imported_files} imported_rows={result.imported_rows} "
            f"skipped={result.skipped_files} failed={result.failed_files} report={markdown_path}",
        )
        return result
    except Exception as exc:
        db.finish_process_timing(root_timing_id, status="failed", details={"error": str(exc)})
        raise


def import_report_bundle_many(
    *,
    db: Database,
    paths: WorkspacePaths,
    report_root: Path,
    case_id: str | None = None,
    accept_duplicate: bool = False,
    progress: ProgressFn | None = None,
) -> ReportBundleBulkImportResult:
    started = datetime.now(timezone.utc)
    _progress(progress, f"report-bundle-many start root={report_root.resolve()}")
    source_root, cleanup_root = _prepare_bulk_report_root(paths, report_root, progress=progress)
    try:
        computer_roots = _top_level_report_roots(source_root)
        if not computer_roots:
            raise ValueError(f"No top-level computer folders found under: {source_root}")
        _progress(progress, f"report-bundle-many discovered computers={len(computer_roots)}")
        active_case_id = case_id
        bulk = ReportBundleBulkImportResult(case_id=case_id or "", report_root=str(report_root.resolve()))
        for index, computer_root in enumerate(computer_roots, 1):
            label = _computer_label_for_folder(computer_root)
            _progress(progress, f"report-bundle-many computer {index}/{len(computer_roots)} start label={label} path={computer_root}")
            result = import_report_bundle(
                db=db,
                paths=paths,
                report_root=computer_root,
                case_id=active_case_id,
                computer_label=label,
                accept_duplicate=accept_duplicate,
                progress=progress,
            )
            if active_case_id is None:
                active_case_id = result.case_id
                bulk.case_id = result.case_id
            bulk.imported_computers += 1
            bulk.imported_files += result.imported_files
            bulk.imported_rows += result.imported_rows
            bulk.skipped_files += result.skipped_files
            bulk.failed_files += result.failed_files
            bulk.warnings.extend(result.warnings)
            bulk.items.append(result)
            _progress(
                progress,
                f"report-bundle-many computer {index}/{len(computer_roots)} completed label={label} "
                f"files={result.imported_files} rows={result.imported_rows} skipped={result.skipped_files} failed={result.failed_files}",
            )
        if active_case_id is None:
            raise ValueError("Bulk import did not create or use a case")
        bulk.case_id = active_case_id
        _progress(progress, "report-bundle-many distinct rebuild start")
        distinct_stats, distinct_warning = _try_rebuild_distinct_artifact_tables(db, case_id=active_case_id, image_id=None)
        if distinct_warning:
            bulk.warnings.append(distinct_warning)
            _progress(progress, f"report-bundle-many distinct rebuild warning warning={distinct_warning}")
        _progress(
            progress,
            "report-bundle-many distinct rebuild completed "
            f"distinct_rows={distinct_stats.get('distinct_rows', 0)} duplicate_rows={distinct_stats.get('duplicate_rows', 0)}",
        )
        bulk.markdown_path = str(_write_bulk_markdown_report(paths, bulk, distinct_stats))
        _progress(
            progress,
            "report-bundle-many completed "
            f"elapsed={_format_elapsed(started)} computers={bulk.imported_computers} files={bulk.imported_files} "
            f"rows={bulk.imported_rows} skipped={bulk.skipped_files} failed={bulk.failed_files} report={bulk.markdown_path}",
        )
        return bulk
    finally:
        if cleanup_root is not None:
            _progress(progress, f"report-bundle-many cleanup staging={cleanup_root}")
            shutil.rmtree(cleanup_root, ignore_errors=True)


def infer_report_candidate(path: Path) -> ReportCandidate | None:
    name = _strip_timestamp(path.name)
    lower = name.lower()
    if lower == "evtxecmd_output.csv":
        return ReportCandidate(path, "EvtxECmd")
    if lower == "rbcmd_output.csv":
        return ReportCandidate(path, "RecycleParser", _transform_rbcmd, "RBCmd recycle-bin output normalized")
    if lower == "pecmd_output.csv":
        return ReportCandidate(path, "PrefetchParser")
    if lower == "lecmd_output.csv":
        return ReportCandidate(path, "LECmd")
    if lower in {"automaticdestinations.csv", "customdestinations.csv"}:
        return ReportCandidate(path, "JLECmd")
    if re.match(r".+_activity\.csv$", lower) or re.match(r".+_activityoperations\.csv$", lower):
        return ReportCandidate(path, "WindowsActivitiesParser", _transform_windows_activity, "Windows Activity CSV normalized")
    if re.match(r".+_activity_packageids\.csv$", lower):
        return ReportCandidate(path, "WindowsActivitiesParser", _transform_windows_activity_package, "Windows Activity package mapping normalized")
    if lower.endswith("_ntuser.csv") or lower.endswith("_usrclass.csv"):
        return ReportCandidate(path, "SBECmd")
    if lower == "mftecmd_$mft_output.csv":
        return ReportCandidate(path, "MFTECmd")
    if lower == "mftecmd_$j_output.csv":
        return ReportCandidate(path, "MFTECmdUSN")
    if lower.startswith("amcache_"):
        return ReportCandidate(path, "AmcacheParser")
    if "recmd_batch" in lower:
        return ReportCandidate(path, "RegistryArtifactParser", _transform_recmd_generic, "RECmd batch output normalized to registry artifacts")
    recmd_detail_artifact = _recmd_detail_artifact(path)
    if recmd_detail_artifact is not None:
        return ReportCandidate(path, "RECmd", _transform_recmd_detail, f"RECmd detail output normalized as {recmd_detail_artifact}")
    if _looks_like_recmd_plugin_csv(path):
        return ReportCandidate(path, "RegistryArtifactParser", _transform_recmd_generic, "RECmd plugin output normalized to registry artifacts")
    if lower.startswith("chromiumbrowser_historyvisits"):
        return ReportCandidate(path, "ChromiumParser", _transform_chromium_history, "SQLECmd Chromium history normalized")
    if lower.startswith("chromiumbrowser_downloads"):
        return ReportCandidate(path, "ChromiumParser", _transform_chromium_downloads, "SQLECmd Chromium downloads normalized")
    if lower.startswith("chromiumbrowser_keywordsearches"):
        return ReportCandidate(path, "ChromiumParser", _transform_chromium_searches, "SQLECmd Chromium searches normalized")
    if lower.startswith("chromiumbrowser_favicons"):
        return ReportCandidate(path, "ChromiumParser", _transform_chromium_favicons, "SQLECmd Chromium favicons normalized")
    if lower.startswith("chromiumbrowser_networkactionpredictor"):
        return ReportCandidate(path, "ChromiumParser", _transform_chromium_predictor, "SQLECmd Chromium network predictor normalized")
    if lower.startswith("chromiumbrowser_omniboxshortcuts"):
        return ReportCandidate(path, "ChromiumParser", _transform_chromium_omnibox, "SQLECmd Chromium omnibox shortcuts normalized")
    if lower.startswith("chromiumbrowser_topsites"):
        return ReportCandidate(path, "ChromiumParser", _transform_chromium_top_sites, "SQLECmd Chromium top sites normalized")
    if lower.startswith("firefox_history"):
        return ReportCandidate(path, "FirefoxParser", _transform_firefox_history, "SQLECmd Firefox history normalized")
    if lower.startswith("firefox_cookies"):
        return ReportCandidate(path, "FirefoxParser", _transform_firefox_cookies, "SQLECmd Firefox cookies normalized")
    if lower.startswith("firefox_bookmarks"):
        return ReportCandidate(path, "FirefoxParser", _transform_firefox_bookmarks, "SQLECmd Firefox bookmarks normalized")
    if lower.startswith("firefox_formhistory"):
        return ReportCandidate(path, "FirefoxParser", _transform_firefox_form_history, "SQLECmd Firefox form history normalized")
    if lower.startswith("firefox_favicons"):
        return ReportCandidate(path, "FirefoxParser", _transform_firefox_favicons, "SQLECmd Firefox favicons normalized")
    if lower.startswith("windows_activitiescachedb") or lower.startswith("windows_activityoperation"):
        return ReportCandidate(path, "WindowsActivitiesParser", _transform_windows_activity, "SQLECmd Windows Activity normalized")
    if lower.startswith("windows_activitypackageid"):
        return ReportCandidate(path, "WindowsActivitiesParser", _transform_windows_activity_package, "SQLECmd Windows Activity package mapping normalized")
    if lower.startswith("googledrive_"):
        return ReportCandidate(path, "CloudSyncParser", _transform_google_drive, "SQLECmd Google Drive output normalized")
    header = _detect_csv_header(path)
    if not header:
        return None
    if _header_has(header, "recordnumber", "eventrecordid", "timecreated", "eventid", "provider", "channel"):
        return ReportCandidate(path, "EvtxECmd", note="Event log CSV detected by header")
    if _header_has(header, "entrynumber", "sequencenumber", "parentpath", "filename", "created0x10"):
        return ReportCandidate(path, "MFTECmd", note="MFT CSV detected by header")
    if _header_has(header, "sourcefilename", "executablename", "hash", "runcount", "lastrun"):
        return ReportCandidate(path, "PrefetchParser", _transform_pecmd_prefetch, "PECmd prefetch output normalized")
    if _header_has(header, "sourcefile", "appid", "appiddescription"):
        return ReportCandidate(path, "JLECmd", note="JLECmd jump list output detected by header")
    if _header_has(header, "controlset", "cacheentryposition", "path", "lastmodifiedtimeutc", "executed"):
        return ReportCandidate(path, "AppCompatCacheParser", note="Shimcache output detected by header")
    if _header_has(header, "bagpath", "absolutepath", "lastwritetime"):
        return ReportCandidate(path, "SBECmd", note="Shellbags output detected by header")
    if _header_has(header, "sourcename", "filetype", "filename", "deletedon"):
        return ReportCandidate(path, "RecycleParser", _transform_rbcmd, "RBCmd recycle-bin output normalized")
    if _header_has(header, "source path/filename", "target name", "local path", "vol serial"):
        return ReportCandidate(path, "LECmd", _transform_tzworks_lnk, "TZWorks lp output normalized to LECmd columns")
    if _header_has(header, "device name", "instance/serial#", "volume guid", "vol name/details"):
        return ReportCandidate(path, "USPParser", _transform_tzworks_usp, "TZWorks USP output normalized")
    return None


def _run_post_import_rebuilds(db: Database, *, case_id: str, image_id: str) -> list[str]:
    warnings: list[str] = []
    rebuild_common_dialog_items(db, case_id=case_id, image_id=image_id)
    rebuild_copied_file_indicators(db, case_id=case_id, image_id=image_id)
    rebuild_file_correlations(db, case_id=case_id, image_id=image_id)
    rebuild_artifact_correlations(db, case_id=case_id, image_id=image_id)
    rebuild_nested_evidence_inventory(db, case_id=case_id, image_id=image_id)
    rebuild_timeline_windows_old_dedupe(db, case_id=case_id, image_id=image_id)
    rebuild_sessions(db, case_id=case_id, image_id=image_id)
    rebuild_usb_storage_devices(db, case_id=case_id, image_id=image_id)
    rebuild_usb_connection_events(db, case_id=case_id, image_id=image_id)
    _, distinct_warning = _try_rebuild_distinct_artifact_tables(db, case_id=case_id, image_id=image_id)
    if distinct_warning:
        warnings.append(distinct_warning)
    return warnings


def _try_rebuild_distinct_artifact_tables(
    db: Database, *, case_id: str, image_id: str | None
) -> tuple[dict[str, Any], str | None]:
    try:
        return rebuild_distinct_artifact_tables(db, case_id=case_id, image_id=image_id), None
    except Exception as exc:
        if not _is_disk_full_error(exc):
            raise
        warning = f"Skipped distinct artifact table rebuild because DuckDB ran out of temporary disk space: {exc}"
        db.log_activity(
            case_id=case_id,
            image_id=image_id,
            level="warning",
            event="report_bundle.distinct_rebuild_skipped",
            message="Skipped distinct artifact rebuild after disk-full error",
            details={"error": str(exc)},
        )
        return _empty_distinct_stats(case_id, image_id), warning


def _is_disk_full_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "no space left" in text or ("could not write file" in text and "duckdb_temp_storage" in text)


def _empty_distinct_stats(case_id: str, image_id: str | None) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "image_id": image_id,
        "tables": {},
        "distinct_rows": 0,
        "source_rows": 0,
        "duplicate_rows": 0,
        "skipped": True,
    }


def _write_markdown_report(paths: WorkspacePaths, result: ReportBundleImportResult) -> Path:
    report_dir = paths.outputs_dir(result.case_id) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"report-bundle-import-{result.image_id}.md"
    lines = [
        "# Report Bundle Import",
        "",
        f"- Case ID: `{result.case_id}`",
        f"- Computer ID: `{result.computer_id}`",
        f"- Evidence ID: `{result.image_id}`",
        f"- Report root: `{result.report_root}`",
        f"- Imported files: {result.imported_files}",
        f"- Imported rows: {result.imported_rows}",
        f"- Skipped files: {result.skipped_files}",
        f"- Failed files: {result.failed_files}",
        "",
    ]
    if result.warnings:
        lines.extend(["## Warnings", ""])
        for warning in result.warnings:
            lines.append(f"- {warning}")
        lines.append("")
    lines.extend(["## Imported", ""])
    imported = [item for item in result.items if item.status == "imported"]
    if imported:
        for item in imported:
            lines.append(f"- `{item.tool_name}` {item.row_count} rows from `{item.path}`")
    else:
        lines.append("- None")
    lines.extend(["", "## Skipped / Unsupported", ""])
    skipped = [item for item in result.items if item.status in {"unsupported", "duplicate"}]
    if skipped:
        for item in skipped:
            tool = item.tool_name or "unmapped"
            lines.append(f"- `{item.status}` `{tool}` `{item.path}` - {item.note or ''}".rstrip())
    else:
        lines.append("- None")
    lines.extend(["", "## Failed", ""])
    failed = [item for item in result.items if item.status == "failed"]
    if failed:
        for item in failed:
            lines.append(f"- `{item.tool_name}` `{item.path}` - {item.error}")
    else:
        lines.append("- None")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def _write_bulk_markdown_report(paths: WorkspacePaths, result: ReportBundleBulkImportResult, distinct_stats: dict[str, Any]) -> Path:
    report_dir = paths.outputs_dir(result.case_id) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"report-bundle-bulk-import-{result.case_id}.md"
    lines = [
        "# Report Bundle Bulk Import",
        "",
        f"- Case ID: `{result.case_id}`",
        f"- Report root: `{result.report_root}`",
        f"- Imported computers: {result.imported_computers}",
        f"- Imported files: {result.imported_files}",
        f"- Imported rows: {result.imported_rows}",
        f"- Skipped files: {result.skipped_files}",
        f"- Failed files: {result.failed_files}",
        f"- Distinct rows: {distinct_stats.get('distinct_rows', 0)}",
        f"- Duplicate rows collapsed in distinct tables: {distinct_stats.get('duplicate_rows', 0)}",
        "",
    ]
    if result.warnings:
        lines.extend(["## Warnings", ""])
        for warning in result.warnings:
            lines.append(f"- {warning}")
        lines.append("")
    lines.extend(["## Computers", ""])
    for item in result.items:
        lines.append(
            f"- Computer `{item.computer_id}` evidence `{item.image_id}`: "
            f"{item.imported_files} files, {item.imported_rows} rows from `{item.report_root}`"
        )
    lines.extend(["", "## Distinct Tables", ""])
    tables = distinct_stats.get("tables") if isinstance(distinct_stats.get("tables"), dict) else {}
    if tables:
        for table, stats in sorted(tables.items()):
            lines.append(
                f"- `{table}`: {stats.get('distinct_rows', 0)} distinct from "
                f"{stats.get('source_rows', 0)} source rows"
            )
    else:
        lines.append("- None")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def _prepare_bulk_report_root(paths: WorkspacePaths, report_root: Path, *, progress: ProgressFn | None = None) -> tuple[Path, Path | None]:
    report_root = report_root.resolve()
    if report_root.is_dir():
        return report_root, None
    if not report_root.is_file() or report_root.suffix.lower() != ".zip":
        raise ValueError(f"Bulk report input must be a directory or .zip file: {report_root}")
    staging_root = paths.root / "staging" / "report-bundle-import" / f"{report_root.stem}-{uuid.uuid4()}"
    staging_root.mkdir(parents=True, exist_ok=True)
    _progress(progress, f"report-bundle-many extract start zip={report_root} staging={staging_root}")
    _safe_extract_zip(report_root, staging_root, progress=progress)
    _progress(progress, f"report-bundle-many extract completed staging={staging_root}")
    return staging_root, staging_root


def _safe_extract_zip(zip_path: Path, destination: Path, *, progress: ProgressFn | None = None) -> None:
    destination_resolved = destination.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        members = archive.infolist()
        for member in members:
            member_path = destination / member.filename
            resolved = member_path.resolve()
            if destination_resolved not in resolved.parents and resolved != destination_resolved:
                raise ValueError(f"Unsafe zip member path: {member.filename}")
        _progress(progress, f"report-bundle-many extract members={len(members)}")
        archive.extractall(destination)


def _top_level_report_roots(root: Path) -> list[Path]:
    if _has_artifact_named_children(root):
        return [root]
    children = [path for path in sorted(root.iterdir()) if path.is_dir() and not path.name.startswith(".")]
    if len(children) == 1 and not _has_artifact_named_children(children[0]):
        nested = [path for path in sorted(children[0].iterdir()) if path.is_dir() and not path.name.startswith(".")]
        if nested:
            return [path for path in nested if any(path.rglob("*.csv"))]
    return [path for path in children if any(path.rglob("*.csv"))]


def _progress(progress: ProgressFn | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _format_elapsed(started: datetime) -> str:
    seconds = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{seconds:02d}s"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


def _has_artifact_named_children(path: Path) -> bool:
    artifact_tokens = {
        "mft",
        "usb_info",
        "systeminfo",
        "system_info",
        "eventlogs_evtxexplorer",
        "prefetch",
        "jumplists_jlecmd",
        "shimcache",
        "recyclebin_rbcmd",
        "shellbags",
        "lnk_files_lp",
    }
    child_names = {child.name.lower() for child in path.iterdir() if child.is_dir()}
    return bool(child_names & artifact_tokens)


def _computer_label_for_folder(path: Path) -> str:
    metadata = _read_device_metadata(path)
    for key in ("computer_name", "hostname", "device_name", "name", "label"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return path.name


def _read_device_metadata(path: Path) -> dict[str, Any]:
    for candidate in sorted(path.glob("*.json")):
        try:
            parsed = json.loads(candidate.read_text(encoding="utf-8-sig", errors="replace"))
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _strip_timestamp(name: str) -> str:
    return re.sub(r"^\d{14,20}_", "", name)


def _looks_like_recmd_plugin_csv(path: Path) -> bool:
    if not path.parent.name.isdigit():
        return False
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.reader(line for line in handle if not line.startswith("#"))
            header = next(reader, [])
    except OSError:
        return False
    lowered = {item.lower() for item in header}
    return bool(
        {
            "value",
            "valuename",
            "value name",
            "keypath",
            "key path",
            "batchkeypath",
            "batchvaluename",
            "lastwritetimestamp",
            "last write timestamp",
            "sourcefile",
            "source file",
        }
        & lowered
    )


def _detect_csv_header(path: Path) -> set[str]:
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            for index, row in enumerate(reader):
                if index > 40:
                    break
                lowered = {cell.strip().lower() for cell in row if cell.strip()}
                if _looks_like_supported_header(lowered):
                    return lowered
    except OSError:
        return set()
    return set()


def _looks_like_supported_header(header: set[str]) -> bool:
    signatures = (
        {"recordnumber", "eventrecordid", "timecreated", "eventid", "provider", "channel"},
        {"entrynumber", "sequencenumber", "parentpath", "filename", "created0x10"},
        {"sourcefilename", "executablename", "hash", "runcount", "lastrun"},
        {"sourcefile", "appid", "appiddescription"},
        {"controlset", "cacheentryposition", "path", "lastmodifiedtimeutc", "executed"},
        {"bagpath", "absolutepath", "lastwritetime"},
        {"sourcename", "filetype", "filename", "deletedon"},
        {"source path/filename", "target name", "local path", "vol serial"},
        {"device name", "instance/serial#", "volume guid", "vol name/details"},
    )
    return any(signature <= header for signature in signatures)


def _header_has(header: set[str], *columns: str) -> bool:
    return set(columns) <= header


def _recmd_detail_artifact(path: Path) -> str | None:
    if not path.parent.name.isdigit():
        return None
    stem = _strip_timestamp(path.stem)
    token = stem.split("_C_", 1)[0].lower()
    return {
        "recentdocs": "recentdocs",
        "runmru": "runmru",
        "wordwheelquery": "wordwheelquery",
        "userassist": "userassist",
        "officemru": "officemru",
        "opensavepidlmru": "opensavepidlmru",
        "lastvisitedpidlmru": "lastvisitedpidlmru",
        "trusteddocuments": "trusteddocuments",
    }.get(token)


def _transformed_name(source_path: Path, tool_name: str) -> str:
    return f"{source_path.stem}.{tool_name}.normalized.csv"


def _transform_csv(source: Path, destination: Path, mapper: Callable[[dict[str, str]], dict[str, Any]]) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("r", encoding="utf-8-sig", errors="replace", newline="") as input_handle:
        reader = csv.DictReader(line for line in input_handle if not line.startswith("#"))
        rows = [mapper(dict(row)) for row in reader]
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with destination.open("w", encoding="utf-8", newline="") as output_handle:
        writer = csv.DictWriter(output_handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return destination


def _transform_rbcmd(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "record_type": "item",
            "recycle_format": "RBCmd",
            "source_path": row.get("SourceName", ""),
            "top_level_name": Path(row.get("SourceName", "")).name,
            "display_name": Path(row.get("FileName", "")).name,
            "original_path": row.get("FileName", ""),
            "deletion_time_utc": row.get("DeletedOn", ""),
            "file_size": row.get("FileSize", ""),
            "is_directory": "true" if row.get("FileType", "").lower() == "directory" else "",
        },
    )


def _transform_pecmd_prefetch(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "source_path": row.get("SourceFilename", ""),
            "prefetch_name": Path(row.get("SourceFilename", "")).name,
            "executable_name": row.get("ExecutableName", ""),
            "prefetch_hash": row.get("Hash", ""),
            "prefetch_version": row.get("Version", ""),
            "run_count": row.get("RunCount", ""),
            "last_run_time_utc": row.get("LastRun", ""),
            "last_run_times_utc": json.dumps(
                [
                    value
                    for value in [
                        row.get("LastRun", ""),
                        row.get("PreviousRun0", ""),
                        row.get("PreviousRun1", ""),
                        row.get("PreviousRun2", ""),
                        row.get("PreviousRun3", ""),
                        row.get("PreviousRun4", ""),
                        row.get("PreviousRun5", ""),
                        row.get("PreviousRun6", ""),
                    ]
                    if value
                ]
            ),
            "referenced_strings": json.dumps(_split_prefetch_references(row.get("FilesLoaded", ""))),
            "referenced_string_count": str(len(_split_prefetch_references(row.get("FilesLoaded", "")))),
            "parser_note": row.get("Note", "") or row.get("ParsingError", ""),
        },
    )


def _split_prefetch_references(value: str | None) -> list[str]:
    if not value:
        return []
    parts = re.split(r"\s*[|;]\s*|,\s+", value)
    return [part for part in parts if part]


def _transform_tzworks_lnk(source: Path, destination: Path) -> Path:
    rows = []
    for row in _iter_rows_after_header(source, {"source path/filename", "target name", "local path"}):
        rows.append(
            {
                "SourceFile": _cell(row, 0),
                "SourceCreated": _date_time(_cell(row, 6), _cell(row, 7)),
                "SourceModified": _date_time(_cell(row, 2), _cell(row, 3)),
                "SourceAccessed": _date_time(_cell(row, 4), _cell(row, 5)),
                "TargetCreated": _date_time(_cell(row, 12), _cell(row, 13)),
                "TargetModified": _date_time(_cell(row, 8), _cell(row, 9)),
                "TargetAccessed": _date_time(_cell(row, 10), _cell(row, 11)),
                "FileSize": _cell(row, 19),
                "FileName": _cell(row, 20),
                "LocalPath": _cell(row, 25),
                "CommonPath": _cell(row, 26),
                "NetworkPath": _cell(row, 27),
                "DriveType": _cell(row, 22),
                "VolumeSerialNumber": _cell(row, 23),
                "VolumeLabel": _cell(row, 24),
                "Arguments": _cell(row, 28),
                "MachineID": _cell(row, 29),
            }
        )
    return _write_rows(destination, rows)


def _transform_tzworks_usp(source: Path, destination: Path) -> Path:
    rows = []
    for row in _iter_rows_after_header(source, {"device name", "instance/serial#", "volume guid"}):
        rows.append(
            {
                "device_name": _cell(row, 0),
                "device_seen_utc": _date_time(_cell(row, 1), _cell(row, 2)),
                "install_time_local": _date_time(_cell(row, 3), _cell(row, 4)),
                "disk_device_utc": _date_time(_cell(row, 5), _cell(row, 6)),
                "volume_device_utc": _date_time(_cell(row, 7), _cell(row, 8)),
                "device_type_raw": _cell(row, 9),
                "vendor_id": _strip_hash(_cell(row, 10)),
                "product_id": _strip_hash(_cell(row, 11)),
                "hub": _cell(row, 12),
                "port": _cell(row, 13),
                "vendor": _cell(row, 14),
                "product": _cell(row, 15),
                "revision": _cell(row, 16),
                "volume_guid": _cell(row, 17),
                "volume_name": _cell(row, 18),
                "users": _cell(row, 19),
                "serial": _cell(row, 20),
                "other_dates": _cell(row, 21),
                "readyboost": _cell(row, 22),
                "raw_record": json.dumps(row, ensure_ascii=False),
            }
        )
    return _write_rows(destination, rows)


def _iter_rows_after_header(source: Path, required_columns: set[str]) -> list[list[str]]:
    with source.open("r", encoding="utf-8-sig", errors="replace", newline="") as input_handle:
        reader = csv.reader(input_handle)
        found = False
        rows: list[list[str]] = []
        for row in reader:
            lowered = {cell.strip().lower() for cell in row if cell.strip()}
            if not found:
                if required_columns <= lowered:
                    found = True
                continue
            if any(cell.strip() for cell in row):
                rows.append(row)
        return rows


def _write_rows(destination: Path, rows: list[dict[str, Any]]) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with destination.open("w", encoding="utf-8", newline="") as output_handle:
        writer = csv.DictWriter(output_handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return destination


def _cell(row: list[str], index: int) -> str:
    if index >= len(row):
        return ""
    return row[index].strip()


def _date_time(date_value: str, time_value: str) -> str:
    date_value = (date_value or "").strip()
    time_value = (time_value or "").strip()
    if not date_value:
        return ""
    if not time_value:
        return date_value
    return f"{date_value} {time_value}"


def _strip_hash(value: str) -> str:
    return value.lstrip("#").strip()


def _transform_recmd_detail(source: Path, destination: Path) -> Path:
    artifact = _recmd_detail_artifact(source)
    if artifact is None:
        return source
    detail_path = destination.with_name(f"RECmd_WindowsActivity_{artifact}.csv")
    with source.open("r", encoding="utf-8-sig", errors="replace", newline="") as input_handle:
        reader = csv.reader(line for line in input_handle if not line.startswith("#"))
        rows = list(reader)
    detail_path.parent.mkdir(parents=True, exist_ok=True)
    with detail_path.open("w", encoding="utf-8", newline="") as output_handle:
        writer = csv.writer(output_handle)
        writer.writerows(rows)
    return detail_path


def _transform_recmd_generic(source: Path, destination: Path) -> Path:
    return _transform_csv(source, destination, lambda row: _generic_registry_row(source, row))


def _generic_registry_row(source: Path, row: dict[str, str]) -> dict[str, Any]:
    artifact = _registry_artifact_name(source, row)
    value_data = _registry_value_data(row)
    normalized_path = (
        row.get("Program")
        or row.get("ProgramName")
        or row.get("AbsolutePath")
        or row.get("Path")
        or row.get("FileName")
        or row.get("TargetName")
        or row.get("DeviceName")
        or row.get("SerialNumber")
        or row.get("ValueData")
        or value_data
        or ""
    )
    return {
        "source_path": row.get("HivePath", "") or row.get("SourceFile", ""),
        "hive_type": row.get("HiveType", ""),
        "artifact": artifact,
        "category": row.get("Category", "") or row.get("Description", "") or artifact,
        "key_path": row.get("KeyPath", "") or row.get("BatchKeyPath", ""),
        "key_last_write_utc": row.get("LastWriteTimestamp", "")
        or row.get("LastWriteTime", "")
        or row.get("Timestamp", ""),
        "event_time_utc": _registry_event_time(row),
        "recentdocs_time_utc": row.get("OpenedOn", ""),
        "recentdocs_extension_time_utc": row.get("ExtensionLastOpened", ""),
        "mru_position": row.get("MruPosition", "") or row.get("MRUPosition", ""),
        "value_name": row.get("ValueName", "") or row.get("BatchValueName", ""),
        "value_type": row.get("ValueType", ""),
        "value_data": value_data,
        "display_name": row.get("Description", "") or row.get("Title", "") or row.get("ProgramName", ""),
        "normalized_path": normalized_path,
        "run_counter": row.get("RunCounter", ""),
        "focus_count": row.get("FocusCount", ""),
        "focus_time": row.get("FocusTime", ""),
        "last_executed": row.get("LastExecuted", ""),
        "notes": row.get("Comment", "") or row.get("Miscellaneous", ""),
    }


def _registry_artifact_name(source: Path, row: dict[str, str]) -> str:
    description = (row.get("Description") or "").strip()
    if description:
        lowered = description.lower()
        if "usbstor" in lowered or "usb" in lowered:
            return "usb_device_history"
        if "mounted" in lowered and "device" in lowered:
            return "mounted_devices"
        return re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")[:80] or "registry_value"
    token = _strip_timestamp(source.stem).split("_C_", 1)[0].lower()
    mapping = {
        "bamdam": "bam_dam",
        "featureusage": "taskbar_feature_usage",
        "lastvisitedpidlmru": "lastvisitedpidlmru",
        "opensavepidlmru": "opensavepidlmru",
        "runmru": "runmru",
        "userassist": "userassist",
        "recentdocs": "recentdocs",
        "officemru": "office_mru",
        "typedurls": "typed_urls",
        "wordwheelquery": "wordwheelquery",
        "usbstor": "usb_device_history",
        "usb": "usb_device_history",
        "mounteddevices": "mounted_devices",
        "volumeinfocache": "usb_volume_info_cache",
        "emdmgmt": "usb_emdmgmt",
    }
    return mapping.get(token, re.sub(r"[^a-z0-9]+", "_", token).strip("_")[:80] or "registry_value")


def _registry_value_data(row: dict[str, str]) -> str:
    explicit = row.get("ValueData") or row.get("ValueData2") or row.get("ValueData3")
    if explicit:
        return explicit
    skip = {
        "HivePath",
        "HiveType",
        "Description",
        "Category",
        "KeyPath",
        "BatchKeyPath",
        "ValueName",
        "BatchValueName",
        "ValueType",
        "LastWriteTimestamp",
        "Timestamp",
        "Comment",
        "Recursive",
        "Deleted",
        "PluginDetailFile",
    }
    values = [f"{key}={value}" for key, value in row.items() if key not in skip and value]
    return "; ".join(values[:12])


def _registry_event_time(row: dict[str, str]) -> str:
    for key in (
        "ExecutionTime",
        "LastExecuted",
        "OpenedOn",
        "LastOpened",
        "LastConnected",
        "FirstInstalled",
        "Installed",
        "LastRemoved",
        "Timestamp",
        "LastWriteTimestamp",
    ):
        value = row.get(key)
        if value:
            return value
    return ""


def _transform_chromium_history(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "browser": "Chromium",
            "source_path": row.get("SourceFile", ""),
            "url": row.get("URL", ""),
            "title": row.get("URLTitle", "") or row.get("Title", ""),
            "visit_time_utc": row.get("VisitTime (UTC)", "") or row.get("LastVisitedTime (UTC)", ""),
            "visit_count": row.get("VisitCount", ""),
            "typed_count": row.get("TypedCount", ""),
        },
    )


def _transform_chromium_downloads(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "browser": "Chromium",
            "source_path": row.get("SourceFile", ""),
            "target_path": row.get("TargetPath", "") or row.get("CurrentPath", ""),
            "tab_url": row.get("TabUrl", "") or row.get("URL", ""),
            "site_url": row.get("SiteUrl", ""),
            "referrer": row.get("Referrer", ""),
            "start_time_utc": row.get("StartTime", ""),
            "end_time_utc": row.get("EndTime", ""),
            "received_bytes": row.get("ReceivedBytes", ""),
            "total_bytes": row.get("TotalBytes", ""),
            "state": row.get("State", ""),
            "danger_type": row.get("DangerType", ""),
            "interrupt_reason": row.get("InterruptReason", ""),
        },
    )


def _transform_chromium_searches(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "browser": "Chromium",
            "artifact_type": "keyword_search",
            "source_path": row.get("SourceFile", ""),
            "name": row.get("KeywordSearchTerm", ""),
            "value": row.get("KeywordSearchTerm", ""),
            "url": row.get("URL", ""),
            "title": row.get("Title", ""),
            "timestamp_utc": row.get("LastVisitTime", ""),
            "details_json": json.dumps({"keyword_id": row.get("KeywordID"), "url_id": row.get("URLID")}, sort_keys=True),
        },
    )


def _transform_chromium_favicons(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "browser": "Chromium",
            "artifact_type": "favicon",
            "source_path": row.get("SourceFile", ""),
            "name": row.get("PageURL", ""),
            "value": row.get("FaviconURL", ""),
            "url": row.get("PageURL", ""),
            "timestamp_utc": row.get("LastUpdated", ""),
            "details_json": json.dumps({"id": row.get("ID"), "icon_id": row.get("IconID")}, sort_keys=True),
        },
    )


def _transform_chromium_predictor(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "browser": "Chromium",
            "artifact_type": "network_action_predictor",
            "source_path": row.get("SourceFile", ""),
            "name": row.get("UserText", ""),
            "value": row.get("UserText", ""),
            "url": row.get("URL", ""),
            "details_json": json.dumps(
                {
                    "id": row.get("ID"),
                    "hits": row.get("NumberOfHits"),
                    "misses": row.get("NumberOfMisses"),
                },
                sort_keys=True,
            ),
        },
    )


def _transform_chromium_omnibox(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "browser": "Chromium",
            "artifact_type": "omnibox_shortcut",
            "source_path": row.get("SourceFile", ""),
            "name": row.get("TextTyped", "") or row.get("Keyword", ""),
            "value": row.get("FillIntoEdit", "") or row.get("Contents", ""),
            "url": row.get("URL", ""),
            "title": row.get("Description", ""),
            "timestamp_utc": row.get("LastAccessTime", ""),
            "details_json": json.dumps(
                {
                    "id": row.get("ID"),
                    "type": row.get("Type"),
                    "keyword": row.get("Keyword"),
                    "times_selected": row.get("TimesSelectedByUser"),
                },
                sort_keys=True,
            ),
        },
    )


def _transform_chromium_top_sites(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "browser": "Chromium",
            "artifact_type": "top_site",
            "source_path": row.get("SourceFile", ""),
            "name": row.get("Title", ""),
            "value": row.get("URL", ""),
            "url": row.get("URL", ""),
            "title": row.get("Title", ""),
            "details_json": json.dumps({"rank": row.get("URLRank")}, sort_keys=True),
        },
    )


def _transform_firefox_history(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "source_path": row.get("SourceFile", ""),
            "url": row.get("URL", ""),
            "title": row.get("Title", ""),
            "visit_time_utc": row.get("LastVisitDate", ""),
            "visit_type": row.get("VisitType", ""),
            "visit_count": row.get("VisitCount", ""),
            "typed": row.get("Typed", ""),
            "hidden": row.get("Hidden", ""),
            "frecency": row.get("Frecency", ""),
        },
    )


def _transform_firefox_cookies(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "source_path": row.get("SourceFile", ""),
            "host": row.get("Host", ""),
            "name": row.get("Name", ""),
            "value": row.get("Value", ""),
            "created_utc": row.get("Creation Time", ""),
            "last_accessed_utc": row.get("Last Accessed Time", ""),
            "expires_utc": row.get("Expiration", ""),
            "is_secure": row.get("IsSecure", ""),
            "is_http_only": row.get("IsHTTPOnly", ""),
        },
    )


def _transform_firefox_bookmarks(source: Path, destination: Path) -> Path:
    return _transform_csv(source, destination, lambda row: _firefox_artifact(row, "bookmark", row.get("DateAdded", "")))


def _transform_firefox_form_history(source: Path, destination: Path) -> Path:
    return _transform_csv(source, destination, lambda row: _firefox_artifact(row, "form_history", row.get("Last Used", "")))


def _transform_firefox_favicons(source: Path, destination: Path) -> Path:
    return _transform_csv(source, destination, lambda row: _firefox_artifact(row, "favicon", row.get("Expiration", "")))


def _firefox_artifact(row: dict[str, str], artifact_type: str, timestamp: str) -> dict[str, Any]:
    return {
        "browser": "Firefox",
        "artifact_type": artifact_type,
        "source_path": row.get("SourceFile", ""),
        "name": row.get("Title", "") or row.get("FieldName", "") or row.get("Name", ""),
        "value": row.get("Value", "") or row.get("URL", "") or row.get("FaviconURL", ""),
        "url": row.get("URL", "") or row.get("PageURL", ""),
        "title": row.get("Title", ""),
        "timestamp_utc": timestamp,
        "details_json": json.dumps(row, sort_keys=True),
    }


def _transform_windows_activity(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "source_path": row.get("SourceFile", ""),
            "source_table": "ActivitiesCacheDB" if "Id" in row else "ActivityOperation",
            "activity_id": row.get("Id", "") or row.get("OperationOrder", ""),
            "app_id": row.get("AppId", "") or row.get("PackageIdHash", "") or row.get("Executable", ""),
            "activity_type": row.get("ActivityType", ""),
            "display_text": row.get("Payload", ""),
            "content_uri": row.get("ContentInfo", ""),
            "activation_uri": row.get("ClipboardPayload", ""),
            "start_time_utc": row.get("StartTime", "") or row.get("CreatedTime", ""),
            "end_time_utc": row.get("EndTime", ""),
            "last_modified_utc": row.get("LastModifiedTime", ""),
            "expiration_time_utc": row.get("ExpirationTime", ""),
            "platform_device_id": row.get("PlatformDeviceId", ""),
            "payload_json": row.get("Payload", ""),
            "raw_json": json.dumps(row, sort_keys=True),
        },
    )


def _transform_windows_activity_package(source: Path, destination: Path) -> Path:
    return _transform_csv(
        source,
        destination,
        lambda row: {
            "source_path": row.get("SourceFile", ""),
            "source_table": "ActivityPackageId",
            "activity_id": row.get("ActivityId", "") or row.get("Id", ""),
            "app_id": row.get("PackageName", "") or row.get("Name", ""),
            "app_display_name": row.get("PackageName", "") or row.get("Name", ""),
            "activity_type": "package",
            "expiration_time_utc": row.get("ExpirationTime", "") or row.get("Expires", ""),
            "platform_device_id": row.get("Platform", ""),
            "raw_json": json.dumps(row, sort_keys=True),
        },
    )


def _transform_google_drive(source: Path, destination: Path) -> Path:
    def mapper(row: dict[str, str]) -> dict[str, Any]:
        return {
            "provider": "Google Drive",
            "artifact_type": _strip_timestamp(source.stem).rsplit("_", 1)[0],
            "source_path": row.get("SourceFile", ""),
            "database_name": source.name,
            "event_time_utc": row.get("ModifiedTime", "") or row.get("LastInteractionTime", ""),
            "local_path": row.get("FullPath", "") or row.get("Path", ""),
            "cloud_path": row.get("ParentFolder", ""),
            "file_name": row.get("Filename", "") or row.get("Name", ""),
            "file_id": row.get("FileID", "") or row.get("ID", "") or row.get("stable_id", ""),
            "parent_id": row.get("ParentFolder", ""),
            "stable_id": row.get("stable_id", ""),
            "mime_type": row.get("mime_type", "") or row.get("Type", ""),
            "file_size": row.get("SizeInBytes", "") or row.get("Size in bytes", ""),
            "is_folder": row.get("IsFolder", ""),
            "is_deleted": row.get("DeletionStatus", "") or row.get("RemovedStatus", ""),
            "sync_status": row.get("Cloud Status", "") or row.get("Shared Status", ""),
            "owner": row.get("Ownership", ""),
            "shared": row.get("SharedStatus", "") or row.get("SharedWithUser", ""),
            "details_json": json.dumps(row, sort_keys=True),
        }

    return _transform_csv(source, destination, mapper)
