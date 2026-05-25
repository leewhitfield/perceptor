from __future__ import annotations

import subprocess
import uuid
import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from os.path import basename
from types import SimpleNamespace

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.common_dialog import rebuild_common_dialog_items
from forensic_orchestrator.copied_indicators import rebuild_copied_file_indicators
from forensic_orchestrator.jobs import JobRunner
from forensic_orchestrator.models import ToolDefinition
from forensic_orchestrator.namespace_reconcile import rebuild_ntfs_namespace_reconciliation
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MissingDependencyError, ToolError, require_dependency

from .ingest import ingest_csv_output
from .archive_inventory import parse_archive_inventory_to_csv
from .chromium import parse_chromium_artifacts_to_csv
from .browser_cache import parse_browser_cache_artifacts_to_csv
from .cloud_sync import parse_cloud_sync_artifacts_to_csv
from .etl import parse_etl_artifacts_to_csv
from .activities import parse_windows_activities_to_csv
from .firefox import parse_firefox_artifacts_to_csv
from .file_metadata import parse_file_metadata_to_csv
from .file_content import parse_file_content_to_csv
from .mailbox import parse_mailbox_artifacts_to_csv
from .messaging import parse_messaging_artifacts_to_csv
from .ntfs_index import parse_ntfs_index_to_csv
from .onedrive_explorer import parse_onedrive_explorer_to_csv
from .onedrive_odl import parse_onedrive_odl_to_csv
from .office_backstage import parse_office_backstage_artifacts_to_csv
from .thumbcache import parse_thumbcache_artifacts_to_csv
from .user_dictionary import parse_user_dictionaries_to_csv
from .zone_identifier import parse_zone_identifier_ads_to_csv
from .package_artifacts import parse_package_artifacts_to_csv
from .package_cache import parse_package_cache_artifacts_to_csv
from .telemetry import parse_telemetry_artifacts_to_csv
from .prefetch import parse_prefetch_directory_to_csv
from .recycle import parse_recycle_artifacts_to_csv
from .registry_artifacts import parse_registry_artifacts_to_csv
from .registry_hives import parse_registry_hives_to_csv
from .registry import build_tool_command, required_paths
from .rdp_cache import parse_rdp_cache_to_csv
from .rdp_vision_review import parse_rdp_vision_review_to_csv
from .sam import parse_sam_to_csv
from .setupapi import parse_setupapi_logs_to_csv
from .spotify import parse_spotify_artifacts_to_csv
from .srum import parse_srum_artifacts_to_csv
from .ual import parse_ual_artifacts_to_csv
from .webcache import parse_webcache_artifacts_to_csv
from .windows_search_ese import parse_windows_search_ese_to_csv
from .windows_search_gather import parse_windows_search_gather_logs_to_csv
from .windows_mail import parse_windows_mail_artifacts_to_csv
from .windows_defender import parse_windows_defender_artifacts_to_csv
from .windows_error_reporting import parse_windows_error_reporting_to_csv


@dataclass(frozen=True)
class GeneratedToolOutput:
    tool_name: str
    tool_version: str | None
    command: list[str]
    output_folder: Path
    stdout_path: Path
    stderr_path: Path
    exit_code: int | None
    source_scope: str
    dry_run: bool
    prepared_registry_logs: tuple[str, ...] = ()


def supports_parallel_generate(tool: ToolDefinition) -> bool:
    return tool.type in {"dotnet", "binary", "internal_etl"}


def read_command_output_snippets(result_path: Path, *, limit: int = 2000) -> str:
    if not result_path.exists():
        return ""
    try:
        text = result_path.read_text(errors="replace").strip()
    except OSError:
        return ""
    if len(text) <= limit:
        return text
    return text[-limit:]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_scope_from_output(output: Path) -> str:
    lowered = str(output).lower().replace("\\", "/")
    if "windows.old" in lowered or "windows_old" in lowered:
        return "Windows.old"
    if re.search(r"(^|[/_. -])vsc([0-9]+|[/_. -]|$)", lowered) or re.search(
        r"(^|[/_. -])snapshot([0-9]+|[/_. -]|$)", lowered
    ):
        return "VSC"
    return "live"


def parse_evtx_parser_errors(stdout_text: str, stderr_text: str = "") -> dict[str, dict[str, object]]:
    text = "\n".join(part for part in [stdout_text, stderr_text] if part)
    errors: dict[str, dict[str, object]] = {}
    current_file: str | None = None
    for line in text.splitlines():
        processing = re.search(r"^Processing (?P<path>.+\.evtx)\.\.\.", line)
        if processing:
            current_file = Path(processing.group("path")).name
            continue
        invalid = re.search(r"(?P<path>.+\.evtx) is not an evtx file! Message: (?P<message>.+)", line)
        if invalid:
            name = Path(invalid.group("path")).name
            errors[name] = {"type": "invalid_evtx", "message": invalid.group("message").strip()}
            continue
        file_error = re.search(r"Error processing (?P<path>.+\.evtx)! Message: (?P<message>.+)", line)
        if file_error:
            name = Path(file_error.group("path")).name
            errors[name] = {"type": "file_error", "message": file_error.group("message").strip()}
            continue
        count_error = re.search(r"(?P<path>.+\.evtx) error count: (?P<count>\d+)", line)
        if count_error:
            name = Path(count_error.group("path")).name
            existing = errors.get(name, {})
            existing["type"] = existing.get("type", "record_errors")
            existing["error_count"] = int(count_error.group("count"))
            errors[name] = existing
            continue
        record_error = re.search(r"Error processing record #(?P<record>\d+): (?P<message>.+)", line)
        if record_error and current_file:
            existing = errors.setdefault(current_file, {"type": "record_errors", "records": []})
            records = existing.setdefault("records", [])
            if isinstance(records, list) and len(records) < 25:
                records.append(
                    {
                        "record": record_error.group("record"),
                        "message": record_error.group("message").strip(),
                    }
                )
    return errors


def detect_tool_version(tool: ToolDefinition, command: list[str], dry_run: bool) -> str | None:
    if dry_run:
        return None
    is_dotnet = tool.type == "dotnet" or (command and basename(command[0]).lower() == "dotnet")
    probe = command[:2] + ["--version"] if is_dotnet else [command[0], "--version"]
    try:
        completed = subprocess.run(probe, capture_output=True, text=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or completed.stderr).strip()
    return output.splitlines()[0] if output else None


def validate_tool(
    tool: ToolDefinition,
    command: list[str],
    *,
    mount: Path,
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> None:
    if not tool.enabled:
        raise ToolError(f"Tool is disabled: {tool.name}")
    if tool.type in {
        "internal_prefetch",
        "internal_sam",
        "internal_recycle",
        "internal_srum",
        "internal_ual",
        "internal_chromium",
        "internal_browser_cache",
        "internal_cloud_sync",
        "internal_onedrive_explorer",
        "internal_onedrive_odl",
        "internal_package_cache",
        "internal_package_artifacts",
        "internal_spotify",
        "internal_rdp_cache",
        "internal_rdp_vision_review",
        "internal_telemetry",
        "internal_windows_activities",
        "internal_windows_search_ese",
        "internal_windows_search_gather",
        "internal_windows_defender",
        "internal_windows_error_reporting",
        "internal_etl",
        "internal_firefox",
        "internal_registry",
        "internal_registry_artifacts",
        "internal_setupapi",
        "internal_file_metadata",
        "internal_file_content",
        "internal_archive_inventory",
        "internal_mailbox",
        "internal_windows_mail",
        "internal_messaging",
        "internal_office_backstage",
        "internal_user_dictionary",
        "internal_zone_identifier",
        "internal_thumbcache",
        "internal_ntfs_index_mftecmd",
        "internal_ntfs_logfile_ntfsparse",
        "internal_webcache",
    }:
        return
    if tool.type == "dotnet" or Path(command[0]).name.lower() == "dotnet":
        if not dry_run:
            require_dependency(command[0])
        if tool.executable and not dry_run and not Path(tool.executable).exists():
            raise MissingDependencyError(f"Tool executable not found: {tool.executable}")
    elif not dry_run:
        require_dependency(command[0])
    if not dry_run:
        missing = [
            path
            for path in required_paths(tool, mount=mount, output=output, artifacts=artifacts)
            if not path.exists()
        ]
        if missing:
            raise ToolError(f"Required input path missing for {tool.name}: {missing[0]}")


def generate_external_tool_outputs(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    tool: ToolDefinition,
    mount: Path,
    artifacts: dict[str, Path] | None = None,
    dry_run: bool,
    output_namespace: str | None = None,
) -> GeneratedToolOutput:
    if not supports_parallel_generate(tool):
        raise ToolError(f"{tool.name} does not support split generate/ingest execution")
    artifact_paths = artifacts or {}
    output = paths.outputs_dir(case_id) / image_id
    if output_namespace:
        output = output / output_namespace
    output = output / tool.name
    source_scope = _source_scope_from_output(output)
    output.mkdir(parents=True, exist_ok=True)
    prepared_registry_logs: list[Path] = []
    if not dry_run and tool.name in {"RECmd", "AmcacheParser", "AppCompatCacheParser", "SBECmd"}:
        prepared_registry_logs = prepare_registry_transaction_logs(artifact_paths)
    command = build_tool_command(tool, mount=mount, output=output, artifacts=artifact_paths)
    validate_tool(tool, command, mount=mount, output=output, artifacts=artifact_paths, dry_run=dry_run)
    if tool.type == "internal_etl":
        tool_version = "internal_etl-v1"
    else:
        tool_version = detect_tool_version(tool, command, dry_run)
    job_dir = output / "_job"
    job_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = job_dir / "stdout.txt"
    stderr_path = job_dir / "stderr.txt"
    if dry_run:
        description = "internal ETL parser" if tool.type == "internal_etl" else "command"
        stdout_path.write_text(f"DRY RUN: {description} not executed\n" + repr(command) + "\n")
        stderr_path.write_text("")
        exit_code = 0
    elif tool.type == "internal_etl":
        source = artifact_paths.get("etl_files", output / "_missing_artifact")
        try:
            csv_path = parse_etl_artifacts_to_csv(source, output)
            stdout_path.write_text(f"Wrote {csv_path}\n")
            stderr_path.write_text("")
            exit_code = 0
        except Exception as exc:
            stdout_path.write_text("")
            stderr_path.write_text(str(exc) + "\n")
            exit_code = 1
    else:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            completed = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
        exit_code = completed.returncode
    return GeneratedToolOutput(
        tool_name=tool.name,
        tool_version=tool_version,
        command=command,
        output_folder=output,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        exit_code=exit_code,
        source_scope=source_scope,
        dry_run=dry_run,
        prepared_registry_logs=tuple(str(path) for path in prepared_registry_logs),
    )


def prepare_recmd_transaction_logs(artifacts: dict[str, Path]) -> list[Path]:
    return prepare_registry_transaction_logs(artifacts)


def prepare_registry_transaction_logs(artifacts: dict[str, Path]) -> list[Path]:
    prepared: list[Path] = []
    for path in artifacts.values():
        candidates: list[Path]
        if path.is_dir():
            candidates = [
                item
                for item in path.rglob("*")
                if item.is_file()
                and item.name.lower() in {
                    "ntuser.dat", "usrclass.dat", "system", "software", "sam", "security", "amcache.hve",
                }
            ]
        elif path.is_file():
            candidates = [path]
        else:
            candidates = []
        for hive in candidates:
            prepared.extend(_ensure_recmd_log_case(hive))
    return prepared


def _ensure_recmd_log_case(hive: Path) -> list[Path]:
    created: list[Path] = []
    existing = {item.name.lower(): item for item in hive.parent.iterdir() if item.is_file()}
    for suffix in (".LOG1", ".LOG2"):
        expected = hive.with_name(hive.name + suffix)
        if expected.exists():
            continue
        source = existing.get((hive.name + suffix).lower())
        if source is None:
            continue
        shutil.copy2(source, expected)
        created.append(expected)
    return created


def run_internal_prefetch_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    job_id = str(uuid.uuid4())
    source_scope = _source_scope_from_output(output)
    job_dir = output / "_job"
    job_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = job_dir / "stdout.txt"
    stderr_path = job_dir / "stderr.txt"
    start_time = utc_now()
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "source_scope": source_scope,
            "tool_name": tool.name,
            "tool_version": "internal-prefetch-v1",
            "command": command,
            "start_time": start_time,
            "end_time": utc_now() if dry_run else None,
            "exit_code": 0 if dry_run else None,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "output_folder": output,
            "dry_run": dry_run,
        }
    )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        event="job.started",
        message=f"Started {tool.name}",
        details={"command": command, "output_folder": str(output), "dry_run": dry_run},
    )
    if dry_run:
        stdout_path.write_text("DRY RUN: internal Prefetch parser not executed\n" + repr(command) + "\n")
        stderr_path.write_text("")
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            event="job.dry_run",
            message=f"Dry-run recorded {tool.name}; command was not executed",
            details={"stdout_path": str(stdout_path), "stderr_path": str(stderr_path)},
        )
        return SimpleNamespace(
            job_id=job_id,
            exit_code=0,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            output_folder=output,
        )

    source = artifacts.get("prefetch_files")
    if source is None:
        raise ToolError("Internal Prefetch parser requires artifact: prefetch_files")
    if not source.exists():
        raise ToolError(f"Internal Prefetch parser input path missing: {source}")
    try:
        csv_path = parse_prefetch_directory_to_csv(source, output)
        stdout_path.write_text(f"Wrote {csv_path}\n")
        stderr_path.write_text("")
        exit_code = 0
    except Exception as exc:
        stdout_path.write_text("")
        stderr_path.write_text(str(exc) + "\n")
        source_missing = isinstance(exc, FileNotFoundError) and source_scope == "Windows.old"
        exit_code = 0 if source_missing else 1
    db.finish_job(job_id, utc_now(), exit_code)
    source_missing = bool(exit_code == 0 and stderr_path.exists() and stderr_path.read_text(errors="replace").strip())
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        level="warning" if source_missing else ("error" if exit_code else "info"),
        event="tool.source_not_present" if source_missing else "job.finished",
        message=(
            f"{tool.name} source artifact was not present in {source_scope}; recorded as no source artifact"
            if source_missing
            else f"Finished {tool.name} with exit code {exit_code}"
        ),
        details={
            "exit_code": exit_code,
            "source_scope": source_scope,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        },
    )
    if exit_code:
        raise ToolError(f"{tool.name} failed; stderr={stderr_path}")
    return SimpleNamespace(
        job_id=job_id,
        exit_code=exit_code,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        output_folder=output,
    )


def run_internal_sam_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="sam_hive",
        parser_description="internal SAM parser",
        parse_to_csv=parse_sam_to_csv,
    )


def run_internal_recycle_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_multi_artifact_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_names=["recycle_modern", "recycle_xp", "recycled_xp"],
        parser_description="internal Recycle Bin parser",
        parse_to_csv=parse_recycle_artifacts_to_csv,
    )


def run_internal_firefox_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="firefox_profiles",
        parser_description="internal Firefox parser",
        parse_to_csv=parse_firefox_artifacts_to_csv,
    )


def run_internal_chromium_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="chromium_profiles",
        parser_description="internal Chromium browser parser",
        parse_to_csv=parse_chromium_artifacts_to_csv,
    )


def run_internal_srum_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="srum_dir",
        parser_description="internal SRUM ESE parser",
        parse_to_csv=lambda source, output: parse_srum_artifacts_to_csv(
            source,
            output,
            software_hive=artifacts.get("registry_software"),
            phonebooks=artifacts.get("ras_phonebooks"),
        ),
    )


def run_internal_ual_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="ual_sum_dir",
        parser_description="internal UAL/SUM ESE parser",
        parse_to_csv=parse_ual_artifacts_to_csv,
    )


def run_internal_office_backstage_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="office_backstage",
        parser_description="internal Office Backstage parser",
        parse_to_csv=parse_office_backstage_artifacts_to_csv,
    )


def run_internal_user_dictionary_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="user_dictionaries",
        parser_description="Internal Office user dictionary parser",
        parse_to_csv=parse_user_dictionaries_to_csv,
    )


def run_internal_zone_identifier_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="zone_identifier_ads",
        parser_description="Internal Zone.Identifier ADS parser",
        parse_to_csv=parse_zone_identifier_ads_to_csv,
    )


def run_internal_thumbcache_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="thumbcache",
        parser_description="Internal Thumbcache parser",
        parse_to_csv=parse_thumbcache_artifacts_to_csv,
        allow_missing_source=True,
    )


def run_internal_webcache_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="webcache",
        parser_description="internal WebCache parser",
        parse_to_csv=parse_webcache_artifacts_to_csv,
        allow_missing_source=True,
    )


def run_internal_browser_cache_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="browser_cache_profiles",
        parser_description="internal browser cache parser",
        parse_to_csv=parse_browser_cache_artifacts_to_csv,
        allow_missing_source=True,
    )


def run_internal_cloud_sync_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="cloud_sync_artifacts",
        parser_description="internal cloud sync artifact parser",
        parse_to_csv=parse_cloud_sync_artifacts_to_csv,
        allow_missing_source=True,
    )


def run_internal_onedrive_explorer_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="onedrive_profiles",
        parser_description="OneDriveExplorer wrapper",
        parse_to_csv=parse_onedrive_explorer_to_csv,
        allow_missing_source=True,
    )


def run_internal_onedrive_odl_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="onedrive_logs",
        parser_description="internal OneDrive ODL parser",
        parse_to_csv=parse_onedrive_odl_to_csv,
        allow_missing_source=True,
    )


def run_internal_package_cache_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="package_cache_profiles",
        parser_description="internal package CacheStorage parser",
        parse_to_csv=parse_package_cache_artifacts_to_csv,
    )


def run_internal_package_artifacts_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="package_artifact_profiles",
        parser_description="internal package artifact parser",
        parse_to_csv=parse_package_artifacts_to_csv,
    )


def run_internal_setupapi_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="setupapi_logs",
        parser_description="internal SetupAPI device install parser",
        parse_to_csv=parse_setupapi_logs_to_csv,
    )


def run_internal_spotify_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="spotify_profiles",
        parser_description="internal Spotify artifact parser",
        parse_to_csv=parse_spotify_artifacts_to_csv,
    )


def run_internal_rdp_cache_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="rdp_cache_profiles",
        parser_description="internal RDP bitmap cache parser",
        parse_to_csv=parse_rdp_cache_to_csv,
        allow_missing_source=True,
    )


def run_internal_rdp_vision_review_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="rdp_cache_profiles",
        parser_description="internal RDP contact-sheet vision review",
        parse_to_csv=parse_rdp_vision_review_to_csv,
        allow_missing_source=True,
    )


def run_internal_telemetry_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="telemetry_artifacts",
        parser_description="internal telemetry artifact parser",
        parse_to_csv=parse_telemetry_artifacts_to_csv,
    )


def run_internal_windows_activities_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="windows_activities",
        parser_description="internal Windows Activities parser",
        parse_to_csv=parse_windows_activities_to_csv,
        allow_missing_source=True,
    )


def run_internal_windows_search_gather_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="windows_search_gather_logs",
        parser_description="internal Windows Search gather log parser",
        parse_to_csv=parse_windows_search_gather_logs_to_csv,
        allow_missing_source=True,
    )


def run_internal_windows_search_ese_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="windows_search_index",
        parser_description="internal Windows Search ESE parser",
        parse_to_csv=parse_windows_search_ese_to_csv,
        allow_missing_source=True,
    )


def run_internal_windows_error_reporting_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="windows_error_reporting",
        parser_description="internal Windows Error Reporting parser",
        parse_to_csv=parse_windows_error_reporting_to_csv,
        allow_missing_source=True,
    )


def run_internal_windows_defender_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_multi_artifact_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_names=[
            "windows_defender_service_history",
            "windows_defender_support_logs",
            "windows_defender_cache_manager",
            "windows_defender_scan_cache",
            "windows_defender_engine_db",
        ],
        parser_description="internal Windows Defender parser",
        parse_to_csv=parse_windows_defender_artifacts_to_csv,
    )


def run_internal_etl_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="etl_files",
        parser_description="internal ETL parser",
        parse_to_csv=parse_etl_artifacts_to_csv,
        allow_missing_source=True,
    )


def run_internal_registry_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_multi_artifact_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_names=[
            "registry_system",
            "registry_software",
            "registry_security",
            "registry_sam",
            "registry_ntuser",
            "registry_amcache",
        ],
        parser_description="internal Registry hive inventory parser",
        parse_to_csv=parse_registry_hives_to_csv,
    )


def run_internal_registry_artifact_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_multi_artifact_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_names=[
            "registry_system",
            "registry_software",
            "registry_sam",
            "registry_ntuser",
            "registry_usrclass",
            "registry_amcache",
        ],
        parser_description="internal Registry artifact parser",
        parse_to_csv=parse_registry_artifacts_to_csv,
    )


def run_internal_file_metadata_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="metadata_files",
        parser_description="internal file metadata parser",
        parse_to_csv=parse_file_metadata_to_csv,
    )


def run_internal_file_content_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="content_files",
        parser_description="internal user file content parser",
        parse_to_csv=parse_file_content_to_csv,
    )


def run_internal_archive_inventory_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="archive_inventory_root",
        parser_description="internal archive inventory parser",
        parse_to_csv=parse_archive_inventory_to_csv,
    )


def run_internal_mailbox_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="mail_artifacts",
        parser_description="internal mailbox parser",
        parse_to_csv=parse_mailbox_artifacts_to_csv,
        allow_missing_source=True,
    )


def run_internal_windows_mail_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="windows_mail_data",
        parser_description="internal Windows Mail store.vol parser",
        parse_to_csv=parse_windows_mail_artifacts_to_csv,
        allow_missing_source=True,
    )


def run_internal_messaging_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts=artifacts,
        dry_run=dry_run,
        artifact_name="messaging_app_data",
        parser_description="internal messaging artifact parser",
        parse_to_csv=parse_messaging_artifacts_to_csv,
        allow_missing_source=True,
    )


def run_internal_ntfs_index_mftecmd_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    raw_image: Path,
    offset_sectors: int,
    dry_run: bool,
) -> object:
    job_id = str(uuid.uuid4())
    job_dir = output / "_job"
    job_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = job_dir / "stdout.txt"
    stderr_path = job_dir / "stderr.txt"
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "tool_name": tool.name,
            "tool_version": f"{tool.type}-v1",
            "command": command,
            "start_time": utc_now(),
            "end_time": utc_now() if dry_run else None,
            "exit_code": 0 if dry_run else None,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "output_folder": output,
            "dry_run": dry_run,
        }
    )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        event="job.started",
        message=f"Started {tool.name}",
        details={"command": command, "output_folder": str(output), "dry_run": dry_run},
    )
    if dry_run:
        stdout_path.write_text("DRY RUN: internal MFTECmd $I30 parser not executed\n" + repr(command) + "\n")
        stderr_path.write_text("")
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            event="job.dry_run",
            message=f"Dry-run recorded {tool.name}; command was not executed",
            details={"stdout_path": str(stdout_path), "stderr_path": str(stderr_path)},
        )
        return SimpleNamespace(
            job_id=job_id,
            exit_code=0,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            output_folder=output,
        )
    try:
        csv_paths = parse_ntfs_index_to_csv(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            output=output,
        )
        stdout_path.write_text("\n".join(str(path) for path in csv_paths) + "\n")
        stderr_path.write_text("")
        exit_code = 0
    except Exception as exc:
        stdout_path.write_text("")
        stderr_path.write_text(str(exc) + "\n")
        exit_code = 1
    db.finish_job(job_id, utc_now(), exit_code)
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        level="error" if exit_code else "info",
        event="job.finished",
        message=f"Finished {tool.name} with exit code {exit_code}",
        details={
            "exit_code": exit_code,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        },
    )
    if exit_code:
        raise ToolError(f"{tool.name} failed; stderr={stderr_path}")
    return SimpleNamespace(
        job_id=job_id,
        exit_code=exit_code,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        output_folder=output,
    )


def run_internal_ntfs_logfile_ntfsparse_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
) -> object:
    job_id = str(uuid.uuid4())
    job_dir = output / "_job"
    job_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = job_dir / "stdout.txt"
    stderr_path = job_dir / "stderr.txt"
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "tool_name": tool.name,
            "tool_version": f"{tool.type}-v1",
            "command": command,
            "start_time": utc_now(),
            "end_time": utc_now() if dry_run else None,
            "exit_code": 0 if dry_run else None,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "output_folder": output,
            "dry_run": dry_run,
        }
    )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        event="job.started",
        message=f"Started {tool.name}",
        details={"command": command, "output_folder": str(output), "dry_run": dry_run},
    )
    if dry_run:
        stdout_path.write_text("DRY RUN: ntfs_parse logfile parser not executed\n" + repr(command) + "\n")
        stderr_path.write_text("")
        return SimpleNamespace(job_id=job_id, exit_code=0, stdout_path=stdout_path, stderr_path=stderr_path, output_folder=output)
    try:
        source = artifacts.get("LogFile")
        if source is None or not source.exists():
            raise ToolError("NTFSParseLogFile requires extracted $LogFile artifact")
        script = _resolve_ntfsparse_logfile_script()
        require_dependency("python3")
        output.mkdir(parents=True, exist_ok=True)
        error_dir = output / "errorpages"
        error_dir.mkdir(parents=True, exist_ok=True)
        csv_path = output / "LogFile.csv"
        run_command = [
            "python3",
            str(script),
            "-f",
            str(source),
            "-t",
            "csv",
            "-e",
            str(csv_path),
            "-d",
            str(error_dir),
        ]
        completed = subprocess.run(run_command, capture_output=True, text=True, check=False)
        stdout_path.write_text((completed.stdout or "") + "\n" + repr(run_command) + "\n")
        stderr_path.write_text(completed.stderr or "")
        exit_code = completed.returncode
    except Exception as exc:
        stdout_path.write_text("")
        stderr_path.write_text(str(exc) + "\n")
        exit_code = 1
    db.finish_job(job_id, utc_now(), exit_code)
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        level="error" if exit_code else "info",
        event="job.finished",
        message=f"Finished {tool.name} with exit code {exit_code}",
        details={"exit_code": exit_code, "stdout_path": str(stdout_path), "stderr_path": str(stderr_path)},
    )
    if exit_code:
        raise ToolError(f"{tool.name} failed; stderr={stderr_path}")
    return SimpleNamespace(job_id=job_id, exit_code=exit_code, stdout_path=stdout_path, stderr_path=stderr_path, output_folder=output)


def _resolve_ntfsparse_logfile_script() -> Path:
    project_root = Path(__file__).resolve().parents[2]
    for candidate in (
        project_root / "third_party" / "ntfs_parse" / "logfileparse.py",
        Path("/opt/ntfs_parse/logfileparse.py"),
        Path("logfileparse.py"),
    ):
        if candidate.exists():
            return candidate
    raise MissingDependencyError(
        "ntfs_parse logfileparse.py not found. Expected vendored parser at "
        "third_party/ntfs_parse/logfileparse.py or system parser at /opt/ntfs_parse/logfileparse.py."
    )


def run_internal_multi_artifact_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
    artifact_names: list[str],
    parser_description: str,
    parse_to_csv,
) -> object:
    def parse_existing(_source: Path, out: Path) -> Path:
        sources = [artifacts[name] for name in artifact_names if name in artifacts and artifacts[name].exists()]
        return parse_to_csv(sources, out)

    return run_internal_csv_tool(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        command=command,
        output=output,
        artifacts={"_multi": output},
        dry_run=dry_run,
        artifact_name="_multi",
        parser_description=parser_description,
        parse_to_csv=parse_existing,
    )


def run_internal_csv_tool(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    command: list[str],
    output: Path,
    artifacts: dict[str, Path],
    dry_run: bool,
    artifact_name: str,
    parser_description: str,
    parse_to_csv,
    allow_missing_source: bool = False,
) -> object:
    job_id = str(uuid.uuid4())
    job_dir = output / "_job"
    job_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = job_dir / "stdout.txt"
    stderr_path = job_dir / "stderr.txt"
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "tool_name": tool.name,
            "tool_version": f"{tool.type}-v1",
            "command": command,
            "start_time": utc_now(),
            "end_time": utc_now() if dry_run else None,
            "exit_code": 0 if dry_run else None,
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "output_folder": output,
            "dry_run": dry_run,
        }
    )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        event="job.started",
        message=f"Started {tool.name}",
        details={"command": command, "output_folder": str(output), "dry_run": dry_run},
    )
    if dry_run:
        stdout_path.write_text(f"DRY RUN: {parser_description} not executed\n" + repr(command) + "\n")
        stderr_path.write_text("")
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            event="job.dry_run",
            message=f"Dry-run recorded {tool.name}; command was not executed",
            details={"stdout_path": str(stdout_path), "stderr_path": str(stderr_path)},
        )
        return SimpleNamespace(
            job_id=job_id,
            exit_code=0,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            output_folder=output,
        )

    source = artifacts.get(artifact_name)
    if source is None:
        if allow_missing_source:
            source = output / "_missing_artifact"
        else:
            raise ToolError(f"{tool.name} requires artifact: {artifact_name}")
    if not source.exists() and not allow_missing_source:
        raise ToolError(f"{tool.name} input path missing: {source}")
    try:
        csv_path = parse_to_csv(source, output)
        stdout_path.write_text(f"Wrote {csv_path}\n")
        stderr_path.write_text("")
        exit_code = 0
    except Exception as exc:
        stdout_path.write_text("")
        stderr_path.write_text(str(exc) + "\n")
        exit_code = 1
    db.finish_job(job_id, utc_now(), exit_code)
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        level="error" if exit_code else "info",
        event="job.finished",
        message=f"Finished {tool.name} with exit code {exit_code}",
        details={
            "exit_code": exit_code,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        },
    )
    if exit_code:
        raise ToolError(f"{tool.name} failed; stderr={stderr_path}")
    return SimpleNamespace(
        job_id=job_id,
        exit_code=exit_code,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        output_folder=output,
    )


def run_tool(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    tool: ToolDefinition,
    mount: Path,
    artifacts: dict[str, Path] | None = None,
    computer_id: str | None = None,
    dry_run: bool,
    accept_duplicate: bool = False,
    rebuild_correlations: bool = True,
    raw_image: Path | None = None,
    offset_sectors: int | None = None,
    output_namespace: str | None = None,
) -> None:
    artifact_paths = artifacts or {}
    output = paths.outputs_dir(case_id) / image_id
    if output_namespace:
        output = output / output_namespace
    output = output / tool.name
    source_scope = _source_scope_from_output(output)
    output.mkdir(parents=True, exist_ok=True)
    prepared_registry_logs: list[Path] = []
    if not dry_run and tool.name in {"RECmd", "AmcacheParser", "AppCompatCacheParser", "SBECmd"}:
        prepared_registry_logs = prepare_registry_transaction_logs(artifact_paths)
    command = build_tool_command(tool, mount=mount, output=output, artifacts=artifact_paths)
    validate_tool(tool, command, mount=mount, output=output, artifacts=artifact_paths, dry_run=dry_run)
    if prepared_registry_logs:
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            event="registry.transaction_logs_prepared",
            message=f"Prepared registry transaction log filenames for {tool.name}",
            details={"tool": tool.name, "paths": [str(path) for path in prepared_registry_logs]},
        )
    if tool.type == "internal_prefetch":
        result = run_internal_prefetch_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_sam":
        result = run_internal_sam_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_recycle":
        result = run_internal_recycle_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_firefox":
        result = run_internal_firefox_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_chromium":
        result = run_internal_chromium_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_srum":
        result = run_internal_srum_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_ual":
        result = run_internal_ual_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_office_backstage":
        result = run_internal_office_backstage_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_user_dictionary":
        result = run_internal_user_dictionary_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_zone_identifier":
        result = run_internal_zone_identifier_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_thumbcache":
        result = run_internal_thumbcache_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_webcache":
        result = run_internal_webcache_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_browser_cache":
        result = run_internal_browser_cache_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_cloud_sync":
        result = run_internal_cloud_sync_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_onedrive_explorer":
        result = run_internal_onedrive_explorer_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_onedrive_odl":
        result = run_internal_onedrive_odl_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_package_cache":
        result = run_internal_package_cache_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_package_artifacts":
        result = run_internal_package_artifacts_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_setupapi":
        result = run_internal_setupapi_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_spotify":
        result = run_internal_spotify_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_rdp_cache":
        result = run_internal_rdp_cache_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_rdp_vision_review":
        result = run_internal_rdp_vision_review_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_windows_activities":
        result = run_internal_windows_activities_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_windows_search_gather":
        result = run_internal_windows_search_gather_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_telemetry":
        result = run_internal_telemetry_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_windows_search_ese":
        result = run_internal_windows_search_ese_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_windows_error_reporting":
        result = run_internal_windows_error_reporting_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_windows_defender":
        result = run_internal_windows_defender_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_etl":
        result = run_internal_etl_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_registry":
        result = run_internal_registry_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_registry_artifacts":
        result = run_internal_registry_artifact_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_file_metadata":
        result = run_internal_file_metadata_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_file_content":
        result = run_internal_file_content_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_archive_inventory":
        result = run_internal_archive_inventory_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_mailbox":
        result = run_internal_mailbox_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_windows_mail":
        result = run_internal_windows_mail_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_messaging":
        result = run_internal_messaging_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    elif tool.type == "internal_ntfs_index_mftecmd":
        if raw_image is None or offset_sectors is None:
            raise ToolError(f"{tool.name} requires raw image and partition offset")
        result = run_internal_ntfs_index_mftecmd_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            dry_run=dry_run,
        )
    elif tool.type == "internal_ntfs_logfile_ntfsparse":
        result = run_internal_ntfs_logfile_ntfsparse_tool(
            db=db,
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool=tool,
            command=command,
            output=output,
            artifacts=artifact_paths,
            dry_run=dry_run,
        )
    else:
        version = detect_tool_version(tool, command, dry_run)
        result = JobRunner(db).run(
            case_id=case_id,
            image_id=image_id,
            computer_id=computer_id,
            tool_name=tool.name,
            tool_version=version,
            command=command,
            output_folder=output,
            dry_run=dry_run,
            source_scope=source_scope,
        )
    if not dry_run and computer_id:
        csv_files = sorted(output.glob("*.csv"))
        if not csv_files:
            stdout_snippet = read_command_output_snippets(result.stdout_path)
            stderr_snippet = read_command_output_snippets(result.stderr_path)
            unsupported_text = f"{stdout_snippet}\n{stderr_snippet}".lower()
            platform_unsupported = "non-windows platforms not supported" in unsupported_text
            unsupported_message = (
                f"{tool.name} did not produce CSV files; parser reported platform unsupported"
            )
            if tool.name == "PrefetchParser":
                unsupported_message += (
                    ". Windows 10/11 compressed Prefetch parsing requires a Windows-capable parser runtime."
                )
            elif tool.name == "SrumECmd":
                unsupported_message += (
                    ". SrumECmd currently depends on Windows ESE libraries; parse SRUM on a Windows-capable runtime "
                    "or add a Linux ESE parser."
                )
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                job_id=result.job_id,
                level="warning",
                event="tool.platform_unsupported" if platform_unsupported else "tool.no_output",
                message=unsupported_message if platform_unsupported else f"{tool.name} ran but produced no CSV files",
                details={
                    "output_folder": str(output),
                    "stdout_path": str(result.stdout_path),
                    "stderr_path": str(result.stderr_path),
                    "stdout_snippet": stdout_snippet,
                    "stderr_snippet": stderr_snippet,
                },
            )
        csv_files = sorted(output.rglob("*.csv")) if tool.name == "RECmd" else sorted(output.glob("*.csv"))
        for output_file in csv_files:
            output_id = str(uuid.uuid4())
            content_sha256 = file_sha256(output_file)
            duplicate = db.duplicate_tool_output(
                case_id=case_id,
                image_id=image_id,
                tool_name=tool.name,
                content_sha256=content_sha256,
            )
            if duplicate is not None and not accept_duplicate:
                db.log_activity(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    job_id=result.job_id,
                    level="warning",
                    event="tool.duplicate_output_detected",
                    message=f"Duplicate {tool.name} output detected; import rejected",
                    details={
                        "path": str(output_file),
                        "content_sha256": content_sha256,
                        "duplicate_output_id": duplicate["id"],
                    },
                )
                raise ToolError(
                    f"Duplicate output detected for {tool.name}: {output_file}. "
                    "Use --accept-duplicate to import it anyway or --replace-existing to replace prior rows."
                )
            if duplicate is not None and accept_duplicate:
                db.log_activity(
                    case_id=case_id,
                    computer_id=computer_id,
                    image_id=image_id,
                    job_id=result.job_id,
                    level="warning",
                    event="tool.duplicate_output_accepted",
                    message=f"Duplicate {tool.name} output detected; import accepted",
                    details={
                        "path": str(output_file),
                        "content_sha256": content_sha256,
                        "duplicate_output_id": duplicate["id"],
                    },
                )
            row_count = ingest_csv_output(
                db=db,
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=output_id,
                tool_name=tool.name,
                path=output_file,
                rebuild_correlations=rebuild_correlations,
            )
            db.insert_tool_output(
                {
                    "id": output_id,
                    "case_id": case_id,
                    "computer_id": computer_id,
                    "image_id": image_id,
                    "job_id": result.job_id,
                    "tool_name": tool.name,
                    "output_type": "csv",
                    "path": output_file,
                    "content_sha256": content_sha256,
                    "row_count": row_count,
                }
            )
            if tool.name == "EvtxECmd":
                db.update_evtx_recovery_parser_counts(
                    case_id=case_id,
                    image_id=image_id,
                    tool_output_id=output_id,
                )
                parser_errors = parse_evtx_parser_errors(
                    read_command_output_snippets(result.stdout_path, limit=100000),
                    read_command_output_snippets(result.stderr_path, limit=100000),
                )
                db.update_evtx_recovery_parser_errors(
                    case_id=case_id,
                    image_id=image_id,
                    tool_output_id=output_id,
                    parser_errors=parser_errors,
                )
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                job_id=result.job_id,
                level="warning" if row_count == 0 else "info",
                event="tool.output_ingested",
                message=(
                    f"{tool.name} output contained no rows"
                    if row_count == 0
                    else f"Imported {row_count} rows from {tool.name}"
                ),
                details={
                    "tool_output_id": output_id,
                    "path": str(output_file),
                    "row_count": row_count,
                },
            )
        if tool.name == "MFTECmdI30" and raw_image is not None and offset_sectors is not None:
            rebuild_ntfs_namespace_reconciliation(
                db,
                case_id=case_id,
                image_id=image_id,
                raw_image=raw_image,
                offset_sectors=offset_sectors,
                mount_path=mount,
            )
        if tool.name == "RegistryArtifactParser":
            rebuild_common_dialog_items(db, case_id=case_id, image_id=image_id)
        if tool.name in {"MFTECmd", "LECmd", "JLECmd", "SBECmd", "RECmd", "RegistryArtifactParser"}:
            rebuild_copied_file_indicators(db, case_id=case_id, image_id=image_id)


def ingest_generated_tool_outputs(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str | None,
    tool: ToolDefinition,
    generated: GeneratedToolOutput,
    accept_duplicate: bool = False,
    rebuild_correlations: bool = True,
    raw_image: Path | None = None,
    offset_sectors: int | None = None,
    mount: Path | None = None,
) -> None:
    job_id = str(uuid.uuid4())
    start_time = utc_now()
    db.create_job(
        {
            "id": job_id,
            "case_id": case_id,
            "image_id": image_id,
            "computer_id": computer_id,
            "source_scope": generated.source_scope,
            "tool_name": tool.name,
            "tool_version": generated.tool_version,
            "command": generated.command,
            "start_time": start_time,
            "end_time": utc_now(),
            "exit_code": generated.exit_code,
            "stdout_path": generated.stdout_path,
            "stderr_path": generated.stderr_path,
            "output_folder": generated.output_folder,
            "dry_run": generated.dry_run,
        }
    )
    if generated.prepared_registry_logs:
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            event="registry.transaction_logs_prepared",
            message=f"Prepared registry transaction log filenames for {tool.name}",
            details={"tool": tool.name, "paths": list(generated.prepared_registry_logs)},
        )
    db.log_activity(
        case_id=case_id,
        computer_id=computer_id,
        image_id=image_id,
        job_id=job_id,
        level="error" if generated.exit_code not in {0, None} else "info",
        event="job.finished",
        message=f"Finished {tool.name} with exit code {generated.exit_code}",
        details={
            "exit_code": generated.exit_code,
            "stdout_path": str(generated.stdout_path),
            "stderr_path": str(generated.stderr_path),
            "parallel_generate": True,
        },
    )
    if generated.exit_code not in {0, None}:
        raise ToolError(
            f"{tool.name} failed with exit code {generated.exit_code}; "
            f"stdout={generated.stdout_path} stderr={generated.stderr_path}"
        )
    if generated.dry_run or not computer_id:
        return
    _ingest_tool_csv_outputs(
        db=db,
        case_id=case_id,
        image_id=image_id,
        computer_id=computer_id,
        tool=tool,
        output=generated.output_folder,
        job_id=job_id,
        accept_duplicate=accept_duplicate,
        rebuild_correlations=rebuild_correlations,
        raw_image=raw_image,
        offset_sectors=offset_sectors,
        mount=mount,
    )


def _ingest_tool_csv_outputs(
    *,
    db: Database,
    case_id: str,
    image_id: str,
    computer_id: str,
    tool: ToolDefinition,
    output: Path,
    job_id: str,
    accept_duplicate: bool,
    rebuild_correlations: bool,
    raw_image: Path | None,
    offset_sectors: int | None,
    mount: Path | None,
) -> None:
    csv_files = sorted(output.glob("*.csv"))
    stdout_path = output / "_job" / "stdout.txt"
    stderr_path = output / "_job" / "stderr.txt"
    if not csv_files:
        stdout_snippet = read_command_output_snippets(stdout_path)
        stderr_snippet = read_command_output_snippets(stderr_path)
        unsupported_text = f"{stdout_snippet}\n{stderr_snippet}".lower()
        platform_unsupported = "non-windows platforms not supported" in unsupported_text
        unsupported_message = (
            f"{tool.name} did not produce CSV files; parser reported platform unsupported"
        )
        if tool.name == "PrefetchParser":
            unsupported_message += (
                ". Windows 10/11 compressed Prefetch parsing requires a Windows-capable parser runtime."
            )
        elif tool.name == "SrumECmd":
            unsupported_message += (
                ". SrumECmd currently depends on Windows ESE libraries; parse SRUM on a Windows-capable runtime "
                "or add a Linux ESE parser."
            )
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            level="warning",
            event="tool.platform_unsupported" if platform_unsupported else "tool.no_output",
            message=unsupported_message if platform_unsupported else f"{tool.name} ran but produced no CSV files",
            details={
                "output_folder": str(output),
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "stdout_snippet": stdout_snippet,
                "stderr_snippet": stderr_snippet,
            },
        )
    csv_files = sorted(output.rglob("*.csv")) if tool.name == "RECmd" else sorted(output.glob("*.csv"))
    for output_file in csv_files:
        output_id = str(uuid.uuid4())
        content_sha256 = file_sha256(output_file)
        duplicate = db.duplicate_tool_output(
            case_id=case_id,
            image_id=image_id,
            tool_name=tool.name,
            content_sha256=content_sha256,
        )
        if duplicate is not None and not accept_duplicate:
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                job_id=job_id,
                level="warning",
                event="tool.duplicate_output_detected",
                message=f"Duplicate {tool.name} output detected; import rejected",
                details={
                    "path": str(output_file),
                    "content_sha256": content_sha256,
                    "duplicate_output_id": duplicate["id"],
                },
            )
            raise ToolError(
                f"Duplicate output detected for {tool.name}: {output_file}. "
                "Use --accept-duplicate to import it anyway or --replace-existing to replace prior rows."
            )
        if duplicate is not None and accept_duplicate:
            db.log_activity(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                job_id=job_id,
                level="warning",
                event="tool.duplicate_output_accepted",
                message=f"Duplicate {tool.name} output detected; import accepted",
                details={
                    "path": str(output_file),
                    "content_sha256": content_sha256,
                    "duplicate_output_id": duplicate["id"],
                },
            )
        row_count = ingest_csv_output(
            db=db,
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            tool_output_id=output_id,
            tool_name=tool.name,
            path=output_file,
            rebuild_correlations=rebuild_correlations,
        )
        db.insert_tool_output(
            {
                "id": output_id,
                "case_id": case_id,
                "computer_id": computer_id,
                "image_id": image_id,
                "job_id": job_id,
                "tool_name": tool.name,
                "output_type": "csv",
                "path": output_file,
                "content_sha256": content_sha256,
                "row_count": row_count,
            }
        )
        if tool.name == "EvtxECmd":
            db.update_evtx_recovery_parser_counts(
                case_id=case_id,
                image_id=image_id,
                tool_output_id=output_id,
            )
            parser_errors = parse_evtx_parser_errors(
                read_command_output_snippets(stdout_path, limit=100000),
                read_command_output_snippets(stderr_path, limit=100000),
            )
            db.update_evtx_recovery_parser_errors(
                case_id=case_id,
                image_id=image_id,
                tool_output_id=output_id,
                parser_errors=parser_errors,
            )
        db.log_activity(
            case_id=case_id,
            computer_id=computer_id,
            image_id=image_id,
            job_id=job_id,
            level="warning" if row_count == 0 else "info",
            event="tool.output_ingested",
            message=(
                f"{tool.name} output contained no rows"
                if row_count == 0
                else f"Imported {row_count} rows from {tool.name}"
            ),
            details={
                "tool_output_id": output_id,
                "path": str(output_file),
                "row_count": row_count,
            },
        )
    if tool.name == "MFTECmdI30" and raw_image is not None and offset_sectors is not None and mount is not None:
        rebuild_ntfs_namespace_reconciliation(
            db,
            case_id=case_id,
            image_id=image_id,
            raw_image=raw_image,
            offset_sectors=offset_sectors,
            mount_path=mount,
        )
    if tool.name == "RegistryArtifactParser":
        rebuild_common_dialog_items(db, case_id=case_id, image_id=image_id)
    if tool.name in {"MFTECmd", "LECmd", "JLECmd", "SBECmd", "RECmd", "RegistryArtifactParser"}:
        rebuild_copied_file_indicators(db, case_id=case_id, image_id=image_id)
