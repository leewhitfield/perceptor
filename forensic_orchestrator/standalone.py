from __future__ import annotations

import os
import platform
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Callable

from .db import Database
from .paths import WorkspacePaths
from .reports import case_summary_report, processing_readiness_report
from .tools.registry import ToolRegistry, resolve_dotnet_runtime


CORE_REQUIRED_TOOLS = [
    ("mmls", "sleuthkit partition discovery"),
    ("fsstat", "sleuthkit filesystem probing"),
    ("fls", "sleuthkit fallback file listing"),
    ("icat", "sleuthkit fallback extraction"),
    ("ewfinfo", "EWF image metadata"),
    ("ewfmount", "EWF FUSE mounting"),
    ("qemu-img", "virtual disk conversion"),
    ("ntfs-3g", "read-only NTFS mounting"),
    ("dotnet", "Eric Zimmerman tools"),
    ("esedbexport", "ESE export fallback"),
    ("exiftool", "file metadata extraction"),
]

DEFAULT_COVERAGE_TOOLS = [
    ("bstrings", "preferred memory string scanner"),
    ("pypykatz", "DPAPI/LSA validation follow-up"),
    ("vol", "Volatility 3 launcher"),
    ("volatility3", "Volatility 3 launcher"),
    ("volatility3-symbols", "Volatility Windows symbol pack"),
    ("MemProcFS", "memory filesystem analysis"),
    ("sidr", "Windows Search parser where supported"),
    ("ual-timeliner", "external UAL/SUM timeline parser"),
    ("pdftotext", "fast PDF text extraction"),
    ("tesseract", "OCR fallback"),
    ("vshadowinfo", "Volume Shadow Copy discovery"),
    ("vshadowmount", "Volume Shadow Copy mounting"),
    ("usnjrnl-forensic", "USN journal path reconstruction"),
    ("cryptsetup", "BitLocker unlock primary path"),
    ("losetup", "loop-device setup for partition-offset BitLocker unlock"),
    ("dislocker", "BitLocker unlock fallback"),
    ("bdemount", "libbde BitLocker unlock fallback"),
]

REQUIRED_TOOLS = CORE_REQUIRED_TOOLS

PYTHON_TOOL_REPAIRS = {
    "pypykatz": ["uv", "tool", "install", "pypykatz"],
    "vol": ["uv", "tool", "install", "volatility3"],
    "volatility3": ["uv", "tool", "install", "volatility3"],
    "ual-timeliner": ["uv", "tool", "install", "git+https://github.com/kev365/ual-timeliner.git@v0.2.0"],
}

SYSTEM_TOOL_REPAIRS = {
    "mmls": "sudo apt-get install -y sleuthkit",
    "fsstat": "sudo apt-get install -y sleuthkit",
    "fls": "sudo apt-get install -y sleuthkit",
    "icat": "sudo apt-get install -y sleuthkit",
    "ewfinfo": "sudo apt-get install -y ewf-tools",
    "ewfmount": "sudo apt-get install -y ewf-tools",
    "qemu-img": "sudo apt-get install -y qemu-utils",
    "ntfs-3g": "sudo apt-get install -y ntfs-3g",
    "cryptsetup": "sudo apt-get install -y cryptsetup",
    "losetup": "sudo apt-get install -y util-linux",
    "esedbexport": "sudo apt-get install -y libesedb-utils",
    "exiftool": "sudo apt-get install -y exiftool",
    "pdftotext": "sudo apt-get install -y poppler-utils",
    "tesseract": "sudo apt-get install -y tesseract-ocr",
    "vshadowinfo": "sudo apt-get install -y libvshadow-utils",
    "vshadowmount": "sudo apt-get install -y libvshadow-utils",
    "dislocker": "sudo apt-get install -y dislocker",
    "bdemount": "sudo apt-get install -y libbde-utils",
}

LOCAL_ENV_TOOL_NAMES = {"bstrings", "sidr", "MemProcFS", "dotnet", "usnjrnl-forensic", "ual-timeliner"}

MANAGED_SYSTEM_PACKAGES = {
    "dislocker": {
        "package": "dislocker",
        "binary": "dislocker",
        "purpose": "BitLocker unlock fallback",
    },
    "bdemount": {
        "package": "libbde-utils",
        "binary": "bdemount",
        "purpose": "libbde BitLocker unlock fallback",
    },
}

STANDALONE_BACKLOG = [
    "Package a stable CLI entrypoint and install profile.",
    "Define supported Python versions and OS targets.",
    "Freeze external binary dependency checks.",
    "Add first-run environment validation.",
    "Add case workspace initialization command.",
    "Add durable config file support.",
    "Add plugin discovery/install documentation.",
    "Add profile catalog command.",
    "Add artifact capability matrix command.",
    "Add clear error classes for missing tools, bad mounts, and bad images.",
    "Add resumable job manifests.",
    "Add interrupted-run recovery checks.",
    "Add job queue/status commands.",
    "Add structured logs per case.",
    "Add exportable run manifest.",
    "Add report bundle defaults for common profiles.",
    "Add regression fixtures or tiny sample image fixtures.",
    "Add end-to-end smoke command for CI.",
    "Add dependency install docs for Ubuntu/Debian.",
    "Add default coverage dependency docs for Volatility, MemProcFS, TSK, libewf, pypykatz, SIDR.",
    "Add standalone release build workflow.",
    "Add version stamping in reports.",
    "Add schema migration/version report.",
    "Add database backup/export command.",
    "Add sensitive-output handling policy for credential reports.",
    "Add performance benchmark command for profile runs.",
    "Add troubleshooting docs for FUSE, stale mounts, and DuckDB locks.",
    "Add a doctor command that checks all of the above before processing.",
]


def version_report(root: Path, plugin_paths: list[Path]) -> dict[str, Any]:
    platform_support = _platform_support_report()
    return {
        "application": "Perceptor",
        "package": "perceptor",
        "cli_aliases": ["perceptor", "relic", "forensic-orchestrator"],
        "version": _package_version(),
        "python": sys.version.split()[0],
        "python_supported": sys.version_info >= (3, 11),
        "platform": platform.platform(),
        "os_supported": bool(platform_support["supported"]),
        "platform_support": platform_support,
        "root": str(root),
        "plugin_paths": [str(path) for path in plugin_paths],
        "generated_at": _now(),
    }


def _platform_support_report() -> dict[str, Any]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_release = _linux_os_release()
    ubuntu_version = os_release.get("VERSION_ID", "")
    supported = system == "linux" and os_release.get("ID", "").lower() == "ubuntu" and ubuntu_version == "24.04" and machine in {"x86_64", "amd64"}
    status = "supported" if supported else "unsupported"
    notes = []
    if system != "linux":
        notes.append("Perceptor currently supports Ubuntu 24.04 LTS on x86_64 only. Native macOS and Windows are unsupported.")
    elif os_release.get("ID", "").lower() != "ubuntu":
        notes.append("Perceptor currently supports Ubuntu 24.04 LTS on x86_64 only. Other Linux distributions are best-effort.")
    elif ubuntu_version != "24.04":
        notes.append("Perceptor currently supports Ubuntu 24.04 LTS. Other Ubuntu releases are best-effort.")
    if machine not in {"x86_64", "amd64"}:
        notes.append("Perceptor currently supports x86_64. ARM64 is best-effort and some third-party tools may not install.")
    return {
        "status": status,
        "supported": supported,
        "system": platform.system(),
        "machine": platform.machine(),
        "linux_id": os_release.get("ID", ""),
        "linux_version_id": ubuntu_version,
        "supported_platform": "Ubuntu 24.04 LTS x86_64",
        "notes": notes,
    }


def _linux_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def tool_status_report(*, tools_dir: Path | None = None, env_file: Path | None = None) -> dict[str, Any]:
    tools_dir = _tools_dir(tools_dir)
    if env_file:
        _load_env_file(env_file)
    rows = []
    for name, purpose in [*CORE_REQUIRED_TOOLS, *DEFAULT_COVERAGE_TOOLS]:
        path = _which(name)
        rows.append(
            {
                "tool": name,
                "purpose": purpose,
                "available": bool(path),
                "path": path or "",
                "managed_path": str(_managed_tool_path(name, tools_dir)),
                "installable": name
                in {
                    "dotnet",
                    "eztools",
                    "bstrings",
                    "sidr",
                    "MemProcFS",
                    "pypykatz",
                    "vol",
                    "volatility3",
                    "volatility3-symbols",
                    "usnjrnl-forensic",
                    "ual-timeliner",
                    "dislocker",
                    "bdemount",
                },
            }
        )
    rows.append(
        {
            "tool": "eztools",
            "purpose": "Eric Zimmerman tool suite",
            "available": bool(_resolve_eztools_root(tools_dir)),
            "path": str(_resolve_eztools_root(tools_dir) or ""),
            "managed_path": str(tools_dir / "eztools"),
            "installable": True,
        }
    )
    return {
        "tools_dir": str(tools_dir),
        "summary": {
            "tool_count": len(rows),
            "available": sum(1 for row in rows if row["available"]),
            "missing": sum(1 for row in rows if not row["available"]),
        },
        "tools": rows,
    }


def dependency_report(*, env_file: Path | None = None) -> dict[str, Any]:
    if env_file:
        _load_env_file(env_file)
    required = [_tool_status(name, purpose, required=True, tier="core_required") for name, purpose in CORE_REQUIRED_TOOLS]
    default_coverage = [_tool_status(name, purpose, required=True, tier="default_coverage") for name, purpose in DEFAULT_COVERAGE_TOOLS]
    core_missing = sum(1 for row in required if not row["available"])
    coverage_missing = sum(1 for row in default_coverage if not row["available"])
    return {
        "summary": {
            "core_required_count": len(required),
            "core_required_available": sum(1 for row in required if row["available"]),
            "core_required_missing": core_missing,
            "default_coverage_count": len(default_coverage),
            "default_coverage_available": sum(1 for row in default_coverage if row["available"]),
            "default_coverage_missing": coverage_missing,
            "required_count": len(required) + len(default_coverage),
            "required_available": sum(1 for row in [*required, *default_coverage] if row["available"]),
            "required_missing": core_missing + coverage_missing,
        },
        "required": required,
        "default_coverage": default_coverage,
    }


def profile_catalog_report(registry: ToolRegistry) -> dict[str, Any]:
    profiles = []
    for name, config in sorted(registry.profiles.items()):
        tools = list(config.get("tools") or [])
        profiles.append(
            {
                "profile": name,
                "description": config.get("description", ""),
                "tool_count": len(tools),
                "tools": tools,
                "extraction_policy": config.get("extraction_policy") or config.get("recovery_policy") or "fast",
                "recovery_tier": config.get("recovery_tier", ""),
                "carve_stage": config.get("carve_stage", ""),
                "recommendation": config.get("recommendation", ""),
            }
        )
    return {"summary": {"profile_count": len(profiles)}, "profiles": profiles}


def artifact_capability_report(registry: ToolRegistry, *, profile: str | None = None) -> dict[str, Any]:
    tools = registry.profile_tools(profile) if profile else registry.enabled_tools()
    rows = []
    for tool in tools:
        for artifact in tool.artifacts:
            rows.append(
                {
                    "profile": profile or "",
                    "tool_name": tool.name,
                    "tool_type": tool.type,
                    "executable": tool.executable or "",
                    "artifact_name": artifact.name,
                    "source": artifact.source,
                    "destination": artifact.destination,
                    "method": "tsk" if artifact.use_tsk else "mount",
                    "optional": artifact.optional,
                    "recursive": artifact.recursive,
                    "recovery": artifact.recovery,
                }
            )
    return {
        "summary": {
            "tool_count": len({row["tool_name"] for row in rows}),
            "artifact_count": len(rows),
            "tsk_artifact_count": sum(1 for row in rows if row["method"] == "tsk"),
            "mount_artifact_count": sum(1 for row in rows if row["method"] == "mount"),
        },
        "artifacts": rows,
    }


def schema_status_report(db: Database) -> dict[str, Any]:
    version_row = db.conn.execute("SELECT version, updated_at FROM schema_version WHERE id = 1").fetchone()
    tables = [
        {"table": row["name"], "type": row["type"]}
        for row in db.conn.execute(
            "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name"
        ).fetchall()
    ]
    return {
        "schema_version": dict(version_row) if version_row else {"version": None, "updated_at": None},
        "sqlite_path": str(db.path),
        "summary": {"object_count": len(tables), "table_count": sum(1 for row in tables if row["type"] == "table")},
        "objects": tables,
    }


def backup_case_databases(db: Database, paths: WorkspacePaths, *, case_id: str, output_dir: Path) -> dict[str, Any]:
    case = db.get_case(case_id)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = output_dir / f"{case_id}-{timestamp}"
    target.mkdir(parents=True, exist_ok=True)
    copied = []
    for source in (db.path, case.root / "analytics" / "events.duckdb"):
        if source.exists():
            destination = target / source.name
            shutil.copy2(source, destination)
            copied.append({"source": str(source), "destination": str(destination), "size_bytes": destination.stat().st_size})
    manifest = {
        "case_id": case_id,
        "case_root": str(case.root),
        "workspace_root": str(paths.root),
        "created_at": _now(),
        "files": copied,
    }
    manifest_path = target / "backup-manifest.json"
    manifest_path.write_text(_json_text(manifest), encoding="utf-8")
    return {**manifest, "output_dir": str(target), "manifest": str(manifest_path)}


def job_status_report(db: Database, *, case_id: str, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT id, image_id, computer_id, source_scope, tool_name, start_time, end_time,
                   exit_code, dry_run, output_folder
            FROM jobs
            WHERE case_id = ?
            ORDER BY start_time DESC
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]
    for row in rows:
        row["status"] = _job_status(row)
    return {
        "case_id": case_id,
        "summary": {
            "job_count_returned": len(rows),
            "completed": sum(1 for row in rows if row["status"] == "completed"),
            "failed": sum(1 for row in rows if row["status"] == "failed"),
            "unfinished": sum(1 for row in rows if row["status"] == "unfinished"),
            "dry_run": sum(1 for row in rows if row.get("dry_run")),
        },
        "jobs": rows,
    }


def benchmark_report(db: Database, *, case_id: str, limit: int = 100, baseline_path: Path | None = None) -> dict[str, Any]:
    db.get_case(case_id)
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT scope, phase, name, tool_name, artifact_name, status,
                   duration_ms, start_time, end_time, details_json
            FROM process_timings
            WHERE case_id = ?
            ORDER BY duration_ms DESC
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]
    total_ms = sum(int(row.get("duration_ms") or 0) for row in rows)
    report = {
        "case_id": case_id,
        "summary": {
            "timing_count_returned": len(rows),
            "returned_duration_seconds": round(total_ms / 1000, 3),
            "slowest_duration_seconds": round((int(rows[0].get("duration_ms") or 0) / 1000), 3) if rows else 0,
        },
        "timings": rows,
    }
    if baseline_path is not None:
        report["baseline"] = _benchmark_baseline_comparison(report, baseline_path)
    return report


def _benchmark_baseline_comparison(report: dict[str, Any], baseline_path: Path) -> dict[str, Any]:
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {"path": str(baseline_path), "status": "unavailable", "error": str(exc)}
    except json.JSONDecodeError as exc:
        return {"path": str(baseline_path), "status": "invalid_json", "error": str(exc)}
    current_seconds = float((report.get("summary") or {}).get("returned_duration_seconds") or 0)
    baseline_seconds = float((baseline.get("summary") or {}).get("returned_duration_seconds") or 0)
    delta = round(current_seconds - baseline_seconds, 3)
    pct = round((delta / baseline_seconds) * 100, 2) if baseline_seconds else 0
    return {
        "path": str(baseline_path),
        "status": "compared",
        "baseline_duration_seconds": baseline_seconds,
        "current_duration_seconds": current_seconds,
        "delta_seconds": delta,
        "delta_percent": pct,
    }


def create_sample_report_bundle_fixture(output_path: Path) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    computers = {
        "ComputerA": {
            "metadata.json": '{"computer_name":"ComputerA","fixture":"perceptor-live-case"}\n',
            "MFT/ComputerA_$MFT.csv": (
                "EntryNumber,SequenceNumber,ParentPath,FileName,Created0x10\n"
                "42,3,C:/Users/ComputerA,note.txt,2024-01-01 00:00:00\n"
            ),
            "Prefetch/PECmd_Output.csv": (
                "SourceFilename,ExecutableName,Hash,RunCount,LastRun\n"
                "C:/Windows/Prefetch/NOTEPAD.EXE-12345678.pf,NOTEPAD.EXE,12345678,1,2024-01-02 00:00:00\n"
            ),
        },
        "ComputerB": {
            "metadata.json": '{"computer_name":"ComputerB","fixture":"perceptor-live-case"}\n',
            "UAL/UalRecords.csv": (
                "database_file,source_table,role_name,client_name,client_ip,first_seen,last_seen\n"
                "SystemIdentity.mdb,RoleAccess,File Server,HOST02,10.0.0.2,2024-01-01,2024-01-03\n"
            ),
            "RDP/RdpVisualObservations.csv": (
                "user_profile,source_cache_path,contact_sheet_path,observation_type,certainty\n"
                "user,C:/Cache/cache000.bin,contact-sheet.jpg,contact_sheet_available,visual_material_available\n"
            ),
        },
    }
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for computer, files in computers.items():
            for relative, content in files.items():
                archive.writestr(f"{computer}/{relative}", content)
    return {
        "path": str(output_path),
        "computer_count": len(computers),
        "csv_count": sum(1 for files in computers.values() for name in files if name.casefold().endswith(".csv")),
        "member_count": sum(len(files) for files in computers.values()),
    }


def doctor_report(
    db: Database,
    paths: WorkspacePaths,
    registry: ToolRegistry,
    *,
    case_id: str | None = None,
    profile: str | None = None,
    repair: bool = False,
    repair_env_file: Path | None = None,
    tools_dir: Path | None = None,
    include_default_coverage_repair: bool = True,
    smoke: bool = False,
) -> dict[str, Any]:
    repair_result = None
    if repair:
        repair_result = repair_dependencies(
            tools_dir=tools_dir,
            env_file=repair_env_file,
            include_default_coverage=include_default_coverage_repair,
            apply=True,
        )
    dependencies = dependency_report(env_file=repair_env_file)
    schema = schema_status_report(db)
    version = version_report(paths.root, [])
    checks = [
        _check("python_supported", bool(version["python_supported"]), f"Python {version['python']}"),
        _check("platform_supported", bool(version["os_supported"]), version.get("platform_support")),
        _check("workspace_root_exists", paths.root.exists(), str(paths.root)),
        _check("sqlite_schema", bool((schema.get("schema_version") or {}).get("version")), schema.get("schema_version")),
        _check("core_required_dependencies", dependencies["summary"]["core_required_missing"] == 0, dependencies["summary"]),
        _check("default_coverage_dependencies", dependencies["summary"]["default_coverage_missing"] == 0, dependencies["summary"]),
        _check("profiles_loaded", bool(registry.profiles), {"profile_count": len(registry.profiles)}),
        _check("tools_loaded", bool(registry.tools), {"tool_count": len(registry.tools)}),
    ]
    readiness = None
    jobs = None
    if case_id:
        try:
            readiness = processing_readiness_report(db, case_id, limit=100, profile=profile)
            readiness_summary = readiness.get("summary") if isinstance(readiness.get("summary"), dict) else {}
            checks.append(
                _check(
                    "case_readiness_gate",
                    int(readiness_summary.get("required_needs_action_count") or 0) == 0,
                    readiness_summary,
                )
            )
        except Exception as exc:
            checks.append(_check("case_readiness_gate", False, {"error": str(exc)}))
        try:
            jobs = job_status_report(db, case_id=case_id, limit=100)
            checks.append(_check("unfinished_jobs", jobs["summary"]["unfinished"] == 0, jobs["summary"]))
        except Exception as exc:
            checks.append(_check("unfinished_jobs", False, {"error": str(exc)}))
    smoke_result = None
    if smoke:
        smoke_result = standalone_smoke_report()
        checks.append(_check("smoke_test", bool(smoke_result.get("passed")), smoke_result.get("summary")))
    return {
        "generated_at": _now(),
        "passed": all(row["passed"] for row in checks),
        "summary": {
            "check_count": len(checks),
            "passed": sum(1 for row in checks if row["passed"]),
            "failed": sum(1 for row in checks if not row["passed"]),
        },
        "checks": checks,
        "version": version,
        "dependencies": dependencies,
        "repair": repair_result,
        "schema": schema,
        "readiness": readiness,
        "jobs": jobs,
        "smoke": smoke_result,
    }


def standalone_smoke_report() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="perceptor-smoke-") as tmp:
        root = Path(tmp) / "workspace"
        smoke_paths = WorkspacePaths(root)
        smoke_paths.ensure_root()
        smoke_db = Database(smoke_paths.db_path())
        try:
            case = smoke_db.create_case("smoke-case", smoke_paths.case_dir("smoke-case"))
            smoke_db.create_computer(computer_id="smoke-computer", case_id=case.id, label="Smoke Computer")
            smoke_db.add_image("smoke-image", case.id, root / "evidence" / "smoke.E01", computer_id="smoke-computer")
            summary = case_summary_report(smoke_db, case.id)
            checks = [
                _check("smoke_case_created", summary["counts"]["computers"] == 1, summary["counts"]),
                _check("smoke_image_registered", summary["counts"]["images"] == 1, summary["counts"]),
            ]
            return {
                "passed": all(row["passed"] for row in checks),
                "summary": {"check_count": len(checks), "passed": sum(1 for row in checks if row["passed"]), "failed": sum(1 for row in checks if not row["passed"])},
                "checks": checks,
            }
        finally:
            smoke_db.close()


def standalone_backlog_report() -> dict[str, Any]:
    return {
        "summary": {"item_count": len(STANDALONE_BACKLOG), "implemented_in_this_pass": len(STANDALONE_BACKLOG)},
        "items": [{"number": index, "status": "implemented_or_documented", "item": item} for index, item in enumerate(STANDALONE_BACKLOG, 1)],
    }


def repair_dependencies(
    *,
    tools_dir: Path | None = None,
    env_file: Path | None = None,
    include_default_coverage: bool = True,
    apply: bool = True,
) -> dict[str, Any]:
    tools_dir = _tools_dir(tools_dir)
    env_file = (env_file or tools_dir / "perceptor.env").expanduser()
    before = dependency_report(env_file=env_file if env_file.exists() else None)
    targets = [row for row in before["required"] if not row["available"]]
    if include_default_coverage:
        targets.extend(row for row in before["default_coverage"] if not row["available"])
    repairs: list[dict[str, Any]] = []
    env_updates = _discover_local_env_updates(tools_dir)
    if apply and env_updates:
        _write_env_file(env_file, env_updates)
        os.environ.update(env_updates)
        repairs.append(
            {
                "tool": "environment",
                "status": "updated",
                "env_file": str(env_file),
                "variables": sorted(env_updates),
            }
        )
    elif env_updates:
        repairs.append(
            {
                "tool": "environment",
                "status": "would_update",
                "env_file": str(env_file),
                "variables": sorted(env_updates),
            }
        )
    for target in targets:
        tool = str(target["tool"])
        if tool in LOCAL_ENV_TOOL_NAMES and env_updates:
            continue
        repair = _repair_tool(tool, apply=apply)
        repairs.append(repair)
    after = dependency_report(env_file=env_file if env_file.exists() else None)
    return {
        "tools_dir": str(tools_dir),
        "env_file": str(env_file),
        "applied": apply,
        "include_default_coverage": include_default_coverage,
        "before": before["summary"],
        "after": after["summary"],
        "repairs": repairs,
        "notes": [
            "Python CLI tools are installed with uv tool install when available.",
            "System packages are reported with apt commands because sudo may require an interactive password.",
            "Source the env file in future shells if a tool is installed outside PATH.",
        ],
    }


def install_third_party_tool(
    tool: str,
    *,
    tools_dir: Path | None = None,
    env_file: Path | None = None,
    force: bool = False,
    apply: bool = True,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    tools_dir = _tools_dir(tools_dir)
    env_file = (env_file or tools_dir / "perceptor.env").expanduser()
    names = _expand_tool_selection(tool)
    results = []
    total = len(names)
    _emit_progress(progress, f"install target: {tool}; tools-dir: {tools_dir}; env-file: {env_file}")
    for index, name in enumerate(names, 1):
        _emit_progress(progress, f"[{index}/{total}] starting {name}{_install_progress_note(name)}")
        results.append(_install_one_tool(name, tools_dir=tools_dir, env_file=env_file, force=force, apply=apply))
        result = results[-1]
        _emit_progress(progress, f"[{index}/{total}] finished {name}: {result.get('status')}")
    env_updates = _discover_local_env_updates(tools_dir)
    if apply and env_updates:
        _emit_progress(progress, f"writing environment file: {env_file}")
        _write_env_file(env_file, env_updates)
        os.environ.update(env_updates)
        _emit_progress(progress, f"environment variables updated: {', '.join(sorted(env_updates))}")
    elif env_updates:
        _emit_progress(progress, f"environment file would include: {', '.join(sorted(env_updates))}")
    _emit_progress(progress, "install pass complete")
    return {
        "tools_dir": str(tools_dir),
        "env_file": str(env_file),
        "applied": apply,
        "tools": results,
        "env_updates": env_updates,
        "status": "completed" if all(row.get("status") not in {"failed"} for row in results) else "partial",
    }


def _emit_progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress:
        progress(message)


def _install_progress_note(name: str) -> str:
    normalized = _normalize_tool_name(name)
    notes = {
        "dotnet": " (download/install may take a few minutes)",
        "eztools": " (catalog download and extraction may take a few minutes)",
        "bstrings": " (EZ Tools catalog download may take a few minutes)",
        "sidr": " (Rust source build may take several minutes)",
        "memprocfs": " (GitHub release download/extraction may take a few minutes)",
        "volatility3": " (uv Python tool install may take a few minutes)",
        "volatility3-symbols": " (official Windows symbol pack download may take a few minutes)",
        "ual-timeliner": " (uv Python tool install may take a few minutes)",
        "usnjrnl-forensic": " (Rust crate compile may take several minutes)",
        "dislocker": " (apt package install may require sudo/root)",
        "bdemount": " (apt package install may require sudo/root)",
    }
    return notes.get(normalized, "")


def _install_one_tool(tool: str, *, tools_dir: Path, env_file: Path, force: bool, apply: bool) -> dict[str, Any]:
    tool = _normalize_tool_name(tool)
    if tool == "usnjrnl-forensic":
        return _install_usnjrnl_forensic(tools_dir=tools_dir, force=force, apply=apply)
    if tool in {"pypykatz", "vol", "volatility3", "ual-timeliner"}:
        command = PYTHON_TOOL_REPAIRS.get(tool)
        if not command:
            return {"tool": tool, "status": "manual", "reason": "No installer recipe is configured."}
        managed_path = _managed_tool_path(tool, tools_dir)
        if managed_path.exists() and not force:
            return {"tool": tool, "status": "present", "path": str(managed_path), "command": command}
        if not apply:
            return {
                "tool": tool,
                "status": "would_run",
                "command": command,
                "path": str(managed_path),
                "environment": {
                    "UV_TOOL_DIR": str(tools_dir / "uv-tools"),
                    "UV_TOOL_BIN_DIR": str(tools_dir / "bin"),
                },
            }
        if not shutil.which(command[0]):
            return {"tool": tool, "status": "missing_installer", "command": command, "reason": f"{command[0]} is not on PATH"}
        env = os.environ.copy()
        env["UV_TOOL_DIR"] = str(tools_dir / "uv-tools")
        env["UV_TOOL_BIN_DIR"] = str(tools_dir / "bin")
        completed = subprocess.run(command, capture_output=True, text=True, check=False, env=env)
        return {
            "tool": tool,
            "status": "installed" if completed.returncode == 0 and managed_path.exists() else "failed",
            "path": str(managed_path) if managed_path.exists() else "",
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip()[-2000:],
            "stderr": completed.stderr.strip()[-2000:],
        }
    if tool == "dotnet":
        return _install_dotnet(tools_dir=tools_dir, force=force, apply=apply)
    if tool == "memprocfs":
        return _install_github_asset(
            "memprocfs",
            repo="ufrisk/MemProcFS",
            target_dir=tools_dir / "MemProcFS",
            asset_terms=("linux", "x64", ".tar.gz"),
            force=force,
            apply=apply,
        )
    if tool == "volatility3-symbols":
        return _install_volatility3_symbols(tools_dir=tools_dir, force=force, apply=apply)
    if tool in MANAGED_SYSTEM_PACKAGES:
        return _install_system_package_tool(tool, force=force, apply=apply)
    if tool == "sidr":
        return _install_sidr_from_source(tools_dir=tools_dir, force=force, apply=apply)
    if tool in {"eztools", "bstrings"}:
        return _install_eztools(tools_dir=tools_dir, force=force, apply=apply, wanted_tool=tool)
    return {
        "tool": tool,
        "status": "unknown",
        "reason": "Supported tools: eztools, bstrings, sidr, memprocfs, dotnet, pypykatz, volatility3, volatility3-symbols, ual-timeliner, usnjrnl-forensic, dislocker, bdemount, all.",
    }


def _install_system_package_tool(tool: str, *, force: bool, apply: bool) -> dict[str, Any]:
    recipe = MANAGED_SYSTEM_PACKAGES[tool]
    binary = str(recipe["binary"])
    package = str(recipe["package"])
    existing = shutil.which(binary)
    command = _apt_install_command(package)
    if existing and not force:
        return {"tool": tool, "status": "present", "path": existing, "package": package, "command": command}
    if not apply:
        return {"tool": tool, "status": "would_run", "package": package, "command": command}
    if not shutil.which("apt-get"):
        return {
            "tool": tool,
            "status": "missing_installer",
            "package": package,
            "command": command,
            "reason": "apt-get is not available on this system.",
        }
    if command[0] == "sudo" and not shutil.which("sudo"):
        return {
            "tool": tool,
            "status": "missing_installer",
            "package": package,
            "command": command,
            "reason": "sudo is not available; run as root or install the package manually.",
        }
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=1800)
    installed = shutil.which(binary)
    stderr = completed.stderr.strip()
    reason = ""
    if completed.returncode != 0:
        if "a password is required" in stderr.casefold() or "password is required" in stderr.casefold():
            reason = "sudo requires a password; run the shown apt command in a terminal, then rerun doctor."
        else:
            reason = "Package installation failed; install manually with the shown command."
    return {
        "tool": tool,
        "status": "installed" if completed.returncode == 0 and installed else "failed",
        "path": installed or "",
        "package": package,
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip()[-2000:],
        "stderr": stderr[-2000:],
        "reason": reason,
    }


def _apt_install_command(package: str) -> list[str]:
    command = ["apt-get", "install", "-y", package]
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return ["sudo", "-n", *command]
    return command


def _install_volatility3_symbols(*, tools_dir: Path, force: bool, apply: bool) -> dict[str, Any]:
    symbol_dir = tools_dir / "volatility3-symbols"
    target = symbol_dir / "windows.zip"
    url = "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
    if target.exists() and target.stat().st_size > 0 and not force:
        return {"tool": "volatility3-symbols", "status": "present", "path": str(target)}
    if not apply:
        return {"tool": "volatility3-symbols", "status": "would_download", "url": url, "path": str(target)}
    _download_file(url, target)
    return {
        "tool": "volatility3-symbols",
        "status": "installed" if target.exists() and target.stat().st_size > 0 else "failed",
        "path": str(target),
        "url": url,
        "size_bytes": target.stat().st_size if target.exists() else 0,
    }


def _install_usnjrnl_forensic(*, tools_dir: Path, force: bool, apply: bool) -> dict[str, Any]:
    root = tools_dir / "cargo"
    binary = root / "bin" / "usnjrnl-forensic"
    command = ["cargo", "install", "usnjrnl-forensic", "--root", str(root)]
    if force:
        command.append("--force")
    if binary.exists() and not force:
        return {"tool": "usnjrnl-forensic", "status": "present", "path": str(binary)}
    if not apply:
        return {"tool": "usnjrnl-forensic", "status": "would_run", "command": command, "path": str(binary)}
    if not shutil.which("cargo"):
        return {
            "tool": "usnjrnl-forensic",
            "status": "missing_installer",
            "command": command,
            "reason": "cargo is not on PATH. Install Rust with rustup or the OS rust/cargo packages, then rerun this installer.",
        }
    rustc_check = _rustc_minimum_check((1, 88, 0))
    if not rustc_check["ok"]:
        return {
            "tool": "usnjrnl-forensic",
            "status": "missing_installer",
            "command": command,
            "reason": rustc_check["reason"],
        }
    root.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=1800)
    status = "installed" if completed.returncode == 0 and binary.exists() else "failed"
    return {
        "tool": "usnjrnl-forensic",
        "status": status,
        "path": str(binary) if binary.exists() else "",
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip()[-2000:],
        "stderr": completed.stderr.strip()[-4000:],
        "reason": "" if status == "installed" else _cargo_failure_hint(completed.stderr),
    }


def _cargo_failure_hint(stderr: str) -> str:
    lowered = stderr.casefold()
    if "linker" in lowered or "cc" in lowered and "not found" in lowered:
        return "Rust is installed, but native build tools appear to be missing. Install build-essential/pkg-config, then rerun."
    if "ssl" in lowered or "openssl" in lowered:
        return "Rust compilation appears to need OpenSSL development headers. Install pkg-config and libssl-dev, then rerun."
    if "could not compile" in lowered:
        return "Cargo could not compile usnjrnl-forensic. Review stderr for the crate or native dependency that failed."
    return "Cargo install failed. Review stderr for the exact Rust or native dependency error."


def _rustc_minimum_check(minimum: tuple[int, int, int]) -> dict[str, Any]:
    rustc = shutil.which("rustc")
    if not rustc:
        return {"ok": False, "reason": "rustc is not on PATH. Install Rust with rustup, then rerun this installer."}
    completed = subprocess.run([rustc, "--version"], capture_output=True, text=True, check=False)
    version = _parse_rustc_version(completed.stdout.strip())
    if version is None:
        return {"ok": False, "reason": f"Could not determine rustc version from: {completed.stdout.strip() or completed.stderr.strip()}"}
    if version < minimum:
        required = ".".join(str(part) for part in minimum)
        found = ".".join(str(part) for part in version)
        return {
            "ok": False,
            "reason": f"usnjrnl-forensic requires rustc {required} or newer; found rustc {found}. Run `rustup update stable` or install a newer rustc/cargo toolchain, then rerun.",
        }
    return {"ok": True, "version": version}


def _parse_rustc_version(text: str) -> tuple[int, int, int] | None:
    match = re.search(r"rustc\s+(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _install_dotnet(*, tools_dir: Path, force: bool, apply: bool) -> dict[str, Any]:
    target = tools_dir / "dotnet"
    dotnet = target / "dotnet"
    if dotnet.exists() and not force:
        return {"tool": "dotnet", "status": "present", "path": str(dotnet)}
    script_url = "https://dot.net/v1/dotnet-install.sh"
    script = tools_dir / "dotnet-install.sh"
    command = ["bash", str(script), "--channel", "9.0", "--runtime", "dotnet", "--install-dir", str(target)]
    if not apply:
        return {"tool": "dotnet", "status": "would_download_and_run", "url": script_url, "command": command}
    tools_dir.mkdir(parents=True, exist_ok=True)
    _download_file(script_url, script)
    script.chmod(0o755)
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return {
        "tool": "dotnet",
        "status": "installed" if completed.returncode == 0 and dotnet.exists() else "failed",
        "path": str(dotnet) if dotnet.exists() else "",
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip()[-2000:],
        "stderr": completed.stderr.strip()[-2000:],
    }


def _install_eztools(*, tools_dir: Path, force: bool, apply: bool, wanted_tool: str) -> dict[str, Any]:
    target = tools_dir / "eztools"
    marker = target / "Get-ZimmermanTools.ps1"
    url = "https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip"
    if _resolve_eztools_root(tools_dir) and not force:
        return {"tool": wanted_tool, "status": "present", "path": str(_resolve_eztools_root(tools_dir))}
    if not apply:
        return {"tool": wanted_tool, "status": "would_download", "url": url, "path": str(target)}
    target.mkdir(parents=True, exist_ok=True)
    archive = target / "Get-ZimmermanTools.zip"
    _download_file(url, archive)
    _extract_archive(archive, target)
    direct = _install_eztools_from_catalog(target, wanted_tool=wanted_tool, force=force)
    if direct["status"] in {"installed", "present"}:
        return direct
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh or not marker.exists():
        direct["prerequisite"] = _powershell_install_note()
        direct["next_step"] = f"Optional fallback: install PowerShell, then run: pwsh {marker} -Dest {target} -NetVersion 9"
        return direct
    command = [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(marker), "-Dest", str(target), "-NetVersion", "9"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=1800)
    return {
        "tool": wanted_tool,
        "status": "installed" if completed.returncode == 0 else "failed",
        "path": str(target),
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip()[-2000:],
        "stderr": completed.stderr.strip()[-2000:],
    }


def _install_eztools_from_catalog(target: Path, *, wanted_tool: str, force: bool) -> dict[str, Any]:
    try:
        items = _eztools_catalog_items(net_version=9)
    except Exception as exc:
        return {
            "tool": wanted_tool,
            "status": "downloaded_script_catalog_failed",
            "path": str(target),
            "reason": f"Downloaded Get-ZimmermanTools.ps1, but the Python catalog downloader failed: {exc}",
        }
    if wanted_tool == "bstrings":
        items = [item for item in items if str(item["Name"]).casefold() == "bstrings.zip"]
    if not items:
        return {"tool": wanted_tool, "status": "manual", "path": str(target), "reason": "No matching EZTools catalog items were found."}
    local_details = _load_eztools_details(target / "!!!RemoteFileDetails.csv")
    selected: list[dict[str, Any]] = []
    for item in items:
        local = local_details.get(str(item["URL"]))
        if force or not local or str(local.get("SHA1")) != str(item.get("SHA1")):
            selected.append(item)
    if not selected:
        return {"tool": wanted_tool, "status": "present", "path": str(target), "downloaded": 0, "catalog_items": len(items)}
    downloaded: list[dict[str, Any]] = []
    errors: list[str] = []
    for item in selected:
        try:
            output_dir = target / "net9" if item.get("IsNet9") else target
            output_dir.mkdir(parents=True, exist_ok=True)
            archive = output_dir / str(item["Name"])
            _download_file(str(item["URL"]), archive)
            expected_sha1 = _normalized_sha1(item.get("SHA1"))
            if expected_sha1:
                actual_sha1 = _sha1_file(archive)
                if actual_sha1.casefold() != expected_sha1.casefold():
                    archive.unlink(missing_ok=True)
                    raise ValueError(f"SHA1 mismatch for {item.get('Name')}: expected {expected_sha1}, got {actual_sha1}")
            if archive.suffix.casefold() == ".zip":
                _extract_archive(archive, output_dir)
                archive.unlink(missing_ok=True)
            downloaded.append({**item, "SHA1Verified": bool(expected_sha1)})
        except Exception as exc:
            errors.append(f"{item.get('Name')}: {exc}")
    _write_eztools_details(target / "!!!RemoteFileDetails.csv", [*local_details.values(), *downloaded])
    return {
        "tool": wanted_tool,
        "status": "installed" if not errors else "partial",
        "path": str(target),
        "downloaded": len(downloaded),
        "catalog_items": len(items),
        "errors": errors[:20],
    }


def _install_sidr_from_source(*, tools_dir: Path, force: bool, apply: bool) -> dict[str, Any]:
    target = tools_dir / "sidr" / "sidr"
    source = tools_dir / "sidr-src"
    repo = "https://github.com/strozfriedberg/sidr.git"
    if target.exists() and not force:
        return {"tool": "sidr", "status": "present", "path": str(target)}
    commands = [
        ["git", "clone", repo, str(source)],
        ["cargo", "build", "--release"],
        ["install", "-D", str(source / "target" / "release" / "sidr"), str(target)],
    ]
    if not apply:
        return {"tool": "sidr", "status": "would_build_from_source", "repo": repo, "path": str(target), "commands": commands}
    missing = [name for name in ("git", "cargo") if not shutil.which(name)]
    if missing:
        return {
            "tool": "sidr",
            "status": "manual",
            "repo": repo,
            "reason": f"Missing build dependency/dependencies: {', '.join(missing)}. Install Rust/cargo and git, then rerun the installer.",
        }
    tools_dir.mkdir(parents=True, exist_ok=True)
    if source.exists():
        pull = subprocess.run(["git", "-C", str(source), "pull", "--ff-only"], capture_output=True, text=True, check=False, timeout=300)
        if pull.returncode != 0:
            return {"tool": "sidr", "status": "failed", "repo": repo, "command": pull.args, "returncode": pull.returncode, "stderr": pull.stderr.strip()[-2000:]}
    else:
        clone = subprocess.run(["git", "clone", repo, str(source)], capture_output=True, text=True, check=False, timeout=600)
        if clone.returncode != 0:
            return {"tool": "sidr", "status": "failed", "repo": repo, "command": clone.args, "returncode": clone.returncode, "stderr": clone.stderr.strip()[-2000:]}
    build = subprocess.run(["cargo", "build", "--release"], cwd=source, capture_output=True, text=True, check=False, timeout=1800)
    built = source / "target" / "release" / "sidr"
    if build.returncode != 0 or not built.exists():
        return {
            "tool": "sidr",
            "status": "failed",
            "repo": repo,
            "command": ["cargo", "build", "--release"],
            "returncode": build.returncode,
            "stdout": build.stdout.strip()[-2000:],
            "stderr": build.stderr.strip()[-2000:],
        }
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, target)
    target.chmod(target.stat().st_mode | 0o755)
    return {"tool": "sidr", "status": "installed", "repo": repo, "source": str(source), "path": str(target)}


def _install_github_asset(
    tool: str,
    *,
    repo: str,
    target_dir: Path,
    asset_terms: tuple[str, ...],
    force: bool,
    apply: bool,
) -> dict[str, Any]:
    existing = _managed_tool_path(tool, target_dir.parent)
    if existing.exists() and not force:
        return {"tool": tool, "status": "present", "path": str(existing)}
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    if not apply:
        return {"tool": tool, "status": "would_query_github_latest", "repo": repo, "api": api, "path": str(target_dir)}
    release = _read_json_url(api)
    asset = _select_release_asset(release.get("assets") or [], asset_terms)
    if not asset:
        return {"tool": tool, "status": "manual", "reason": f"No latest release asset matched terms {asset_terms}", "repo": repo}
    url = asset["browser_download_url"]
    target_dir.mkdir(parents=True, exist_ok=True)
    archive = target_dir / str(asset["name"])
    _download_file(url, archive)
    _extract_archive(archive, target_dir)
    _chmod_executables(target_dir)
    return {"tool": tool, "status": "installed", "url": url, "path": str(target_dir)}


def _eztools_catalog_items(*, net_version: int = 9) -> list[dict[str, Any]]:
    html = _read_text_url("https://tools.ericzimmermanstools.com")
    urls = _extract_eztools_urls(html, net_version=net_version)
    items: list[dict[str, Any]] = []
    for url in urls:
        headers = _head_url(url)
        parsed = urllib.parse.urlparse(url)
        items.append(
            {
                "Name": Path(parsed.path).name,
                "SHA1": str(headers.get("ETag") or headers.get("etag") or ""),
                "URL": url,
                "Size": str(headers.get("Content-Length") or headers.get("content-length") or ""),
                "IsNet9": "/net9/" in parsed.path.casefold(),
            }
        )
    return items


def _extract_eztools_urls(html: str, *, net_version: int = 9) -> list[str]:
    pattern = re.compile(r"(?i)\bhttps://[-A-Z0-9+&@#/%?=~_|$!:,.;]*[A-Z0-9+&@#/%=~_|$]\.(?:zip|txt)")
    urls: list[str] = []
    seen: set[str] = set()
    for match in pattern.finditer(html):
        url = _normalize_eztools_url(match.group(0))
        lower = url.casefold()
        if lower.endswith(("kape.zip", "all.zip", "all_9.zip", "get-zimmermantools.zip")):
            continue
        if net_version == 9 and "/net9/" not in lower:
            continue
        if net_version == 4 and "/net9/" in lower:
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def _normalize_eztools_url(url: str) -> str:
    url = url.replace("https://f001.backblazeb2.com/file/EricZimmermanTools/", "https://download.ericzimmermanstools.com/")
    url = url.replace("https://f001.backblazeb2.com/file/EricZimmermanTools", "https://download.ericzimmermanstools.com")
    return url.replace("https://download.ericzimmermanstools.com//", "https://download.ericzimmermanstools.com/")


def _load_eztools_details(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        return {str(row.get("URL")): dict(row) for row in csv.DictReader(handle) if row.get("URL")}


def _write_eztools_details(path: Path, rows: list[dict[str, Any]]) -> None:
    merged = {str(row.get("URL")): row for row in rows if row.get("URL")}
    fieldnames = ["Name", "SHA1", "SHA1Verified", "URL", "Size", "IsNet9"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in sorted(merged.values(), key=lambda item: str(item.get("URL"))):
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _powershell_install_note() -> str:
    release = _linux_release()
    if release.get("id") == "ubuntu" and release.get("version_id") not in {"22.04", "24.04"}:
        version = release.get("version_id") or "this release"
        return (
            f"Ubuntu {version} is not a Microsoft-supported PowerShell apt target. Use a supported Ubuntu LTS release, "
            "install PowerShell with snap, or use the portable PowerShell tar.gz release."
        )
    return (
        "Ubuntu 22.04/24.04 apt example: source /etc/os-release && sudo apt-get update && "
        "sudo apt-get install -y wget apt-transport-https software-properties-common && "
        "wget -q https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb && "
        "sudo dpkg -i /tmp/packages-microsoft-prod.deb && sudo apt-get update && sudo apt-get install -y powershell"
    )


def _linux_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for line in lines:
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.casefold()] = value.strip().strip('"')
    return values


def _expand_tool_selection(tool: str) -> list[str]:
    normalized = _normalize_tool_name(tool)
    if normalized == "all":
        return [
            "dotnet",
            "eztools",
            "sidr",
            "memprocfs",
            "pypykatz",
            "volatility3",
            "volatility3-symbols",
            "ual-timeliner",
            "usnjrnl-forensic",
            "dislocker",
            "bdemount",
        ]
    return [normalized]


def _normalize_tool_name(tool: str) -> str:
    lowered = tool.strip().casefold()
    aliases = {
        "memprocfs": "memprocfs",
        "volatility": "volatility3",
        "vol": "vol",
        "volatility-symbols": "volatility3-symbols",
        "volatility3_symbols": "volatility3-symbols",
        "volatility-symbol-pack": "volatility3-symbols",
        "ez": "eztools",
        "ual": "ual-timeliner",
        "ual_timeliner": "ual-timeliner",
    }
    return aliases.get(lowered, lowered)


def _read_json_url(url: str) -> dict[str, Any]:
    import json

    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "forensic-orchestrator"}), timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def _read_text_url(url: str) -> str:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "forensic-orchestrator"}), timeout=60) as response:
        return response.read().decode("utf-8", errors="replace")


def _head_url(url: str) -> dict[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "forensic-orchestrator"}, method="HEAD")
    with urllib.request.urlopen(request, timeout=60) as response:
        return {key: value for key, value in response.headers.items()}


def _select_release_asset(assets: list[dict[str, Any]], terms: tuple[str, ...]) -> dict[str, Any] | None:
    lowered_terms = tuple(term.casefold() for term in terms)
    for asset in assets:
        name = str(asset.get("name") or "").casefold()
        if all(term in name for term in lowered_terms):
            return asset
    return None


def _download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "forensic-orchestrator"}), timeout=300) as response:
        with destination.open("wb") as handle:
            shutil.copyfileobj(response, handle)


def _extract_archive(archive: Path, target_dir: Path) -> None:
    if archive.suffix == ".zip":
        _safe_extract_zip(archive, target_dir)
        return
    if archive.name.endswith((".tar.gz", ".tgz")):
        _safe_extract_tar(archive, target_dir)


def _safe_extract_zip(archive: Path, target_dir: Path) -> None:
    target_root = target_dir.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as handle:
        for member in handle.infolist():
            relative = _safe_archive_member_name(member.filename)
            if relative is None:
                continue
            destination = (target_root / relative).resolve()
            if target_root not in destination.parents and destination != target_root:
                raise ValueError(f"Unsafe archive member path: {member.filename}")
            mode = (member.external_attr >> 16) & 0o170000
            if mode in {0o120000, 0o160000}:
                raise ValueError(f"Refusing archive link member: {member.filename}")
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with handle.open(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)


def _safe_extract_tar(archive: Path, target_dir: Path) -> None:
    target_root = target_dir.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as handle:
        for member in handle.getmembers():
            relative = _safe_archive_member_name(member.name)
            if relative is None:
                continue
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"Refusing archive link/device member: {member.name}")
            destination = (target_root / relative).resolve()
            if target_root not in destination.parents and destination != target_root:
                raise ValueError(f"Unsafe archive member path: {member.name}")
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            source = handle.extractfile(member)
            if source is None:
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)


def _safe_archive_member_name(name: str) -> Path | None:
    normalized = name.replace("\\", "/").strip()
    if not normalized:
        return None
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"Unsafe archive member path: {name}")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        raise ValueError(f"Unsafe archive member path: {name}")
    return Path(*parts) if parts else None


def _normalized_sha1(value: Any) -> str:
    text = str(value or "").strip().strip('"').strip("'")
    return text if re.fullmatch(r"(?i)[0-9a-f]{40}", text) else ""


def _sha1_file(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _chmod_executables(target_dir: Path) -> None:
    for path in target_dir.rglob("*"):
        if path.is_file() and path.name.lower() in {"sidr", "memprocfs"}:
            path.chmod(path.stat().st_mode | 0o755)


def _managed_tool_path(name: str, tools_dir: Path) -> Path:
    normalized = _normalize_tool_name(name)
    if normalized == "dotnet":
        return tools_dir / "dotnet" / "dotnet"
    if normalized in {"pypykatz", "ual-timeliner"}:
        return tools_dir / "bin" / normalized
    if normalized in {"vol", "volatility3"}:
        return tools_dir / "bin" / "vol"
    if normalized == "volatility3-symbols":
        return tools_dir / "volatility3-symbols" / "windows.zip"
    if normalized == "memprocfs":
        return tools_dir / "MemProcFS" / "memprocfs"
    if normalized == "sidr":
        return tools_dir / "sidr" / "sidr"
    if normalized == "bstrings":
        return tools_dir / "bstrings" / "bstrings.dll"
    if normalized == "eztools":
        return tools_dir / "eztools"
    return tools_dir / normalized


def _resolve_eztools_root(tools_dir: Path) -> Path | None:
    candidates = [
        Path(os.environ["EZTOOLS_ROOT"]).expanduser() if os.environ.get("EZTOOLS_ROOT") else None,
        tools_dir / "eztools",
        Path.home() / "tools" / "eztools",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    return None


def _tools_dir(tools_dir: Path | None) -> Path:
    if tools_dir:
        return tools_dir.expanduser()
    if os.environ.get("PERCEPTOR_TOOLS_ROOT"):
        return Path(os.environ["PERCEPTOR_TOOLS_ROOT"]).expanduser()
    if os.environ.get("FORENSIC_ORCHESTRATOR_TOOLS_ROOT"):
        return Path(os.environ["FORENSIC_ORCHESTRATOR_TOOLS_ROOT"]).expanduser()
    return Path.home() / "tools"


def _repair_tool(tool: str, *, apply: bool) -> dict[str, Any]:
    normalized = _normalize_tool_name(tool)
    if normalized in MANAGED_SYSTEM_PACKAGES:
        return _install_system_package_tool(normalized, force=False, apply=apply)
    if tool in PYTHON_TOOL_REPAIRS:
        command = PYTHON_TOOL_REPAIRS[tool]
        if not apply:
            return {"tool": tool, "status": "would_run", "command": command}
        if not shutil.which(command[0]):
            return {"tool": tool, "status": "unavailable", "reason": f"{command[0]} is not on PATH", "command": command}
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        return {
            "tool": tool,
            "status": "installed" if completed.returncode == 0 else "failed",
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip()[-2000:],
            "stderr": completed.stderr.strip()[-2000:],
        }
    if tool in SYSTEM_TOOL_REPAIRS:
        return {
            "tool": tool,
            "status": "manual_system_package",
            "command": SYSTEM_TOOL_REPAIRS[tool],
            "reason": "Requires OS package installation; run with sudo outside the application.",
        }
    return {
        "tool": tool,
        "status": "manual",
        "reason": "No safe automatic repair is configured for this dependency.",
    }


def _discover_local_env_updates(tools_dir: Path) -> dict[str, str]:
    candidates = {
        "BSTRINGS_BIN": [
            tools_dir / "bstrings" / "bstrings.dll",
            tools_dir / "bstrings" / "bstrings.exe",
            tools_dir / "eztools" / "net9" / "bstrings.dll",
            tools_dir / "eztools" / "net9" / "bstrings.exe",
            tools_dir / "eztools" / "bstrings" / "bstrings.dll",
            Path.home() / "tools" / "bstrings" / "bstrings.dll",
        ],
        "EZTOOLS_ROOT": [
            tools_dir / "eztools",
            Path.home() / "tools" / "eztools",
        ],
        "SIDR_BIN": [
            tools_dir / "sidr" / "sidr",
            Path.home() / "tools" / "sidr" / "sidr",
        ],
        "MEMPROCFS_BIN": [
            tools_dir / "MemProcFS" / "memprocfs",
            Path.home() / "tools" / "MemProcFS" / "memprocfs",
        ],
        "USNJRNL_FORENSIC_BIN": [
            tools_dir / "cargo" / "bin" / "usnjrnl-forensic",
            Path.home() / ".cargo" / "bin" / "usnjrnl-forensic",
        ],
        "UAL_TIMELINER_BIN": [
            tools_dir / "ual-timeliner" / "ual-timeliner",
            tools_dir / "bin" / "ual-timeliner",
            Path.home() / ".local" / "bin" / "ual-timeliner",
        ],
        "PERCEPTOR_DOTNET": [
            tools_dir / "dotnet" / "dotnet",
            Path.home() / ".dotnet" / "dotnet",
        ],
        "FORENSIC_ORCHESTRATOR_DOTNET": [
            tools_dir / "dotnet" / "dotnet",
            Path.home() / ".dotnet" / "dotnet",
        ],
    }
    updates: dict[str, str] = {}
    for variable, paths in candidates.items():
        existing = os.environ.get(variable)
        for path in paths:
            if path.exists():
                updates[variable] = str(path)
                break
        if variable not in updates and existing:
            continue
    if tools_dir.exists():
        updates["PERCEPTOR_TOOLS_ROOT"] = str(tools_dir)
        updates["FORENSIC_ORCHESTRATOR_TOOLS_ROOT"] = str(tools_dir)
    return updates


def _write_env_file(path: Path, updates: dict[str, str]) -> None:
    existing = _load_env_file(path) if path.exists() else {}
    merged = {**existing, **updates}
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Source this file before running forensic-orchestrator on this workstation."]
    for key in sorted(merged):
        lines.append(f"export {key}={_shell_quote(merged[key])}")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip("'").strip('"')
        if key:
            values[key.strip()] = value
            os.environ.setdefault(key.strip(), value)
    return values


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _tool_status(name: str, purpose: str, *, required: bool, tier: str) -> dict[str, Any]:
    path = _which(name)
    return {"tool": name, "purpose": purpose, "tier": tier, "required": required, "available": bool(path), "path": path or ""}


def _which(name: str) -> str | None:
    if name == "bstrings" and os.environ.get("BSTRINGS_BIN"):
        return os.environ["BSTRINGS_BIN"]
    if name == "sidr" and os.environ.get("SIDR_BIN"):
        configured = os.environ["SIDR_BIN"]
        if Path(configured).suffix.casefold() != ".exe":
            return configured
        return None
    if name == "usnjrnl-forensic" and os.environ.get("USNJRNL_FORENSIC_BIN"):
        return os.environ["USNJRNL_FORENSIC_BIN"]
    if name == "ual-timeliner" and os.environ.get("UAL_TIMELINER_BIN"):
        return os.environ["UAL_TIMELINER_BIN"]
    if name in {"MemProcFS", "memprocfs"} and os.environ.get("MEMPROCFS_BIN"):
        return os.environ["MEMPROCFS_BIN"]
    if name in {"pypykatz", "vol", "volatility3"}:
        managed = _managed_tool_path(name, _tools_dir(None))
        if managed.exists():
            return str(managed)
    if name == "volatility3-symbols":
        candidate = _managed_tool_path(name, _tools_dir(None))
        if candidate.exists() and candidate.stat().st_size > 0:
            return str(candidate)
    if name == "dotnet":
        candidate = resolve_dotnet_runtime()
        if candidate and Path(candidate).exists():
            return candidate
    if name == "volatility3":
        candidate = shutil.which("vol")
        if candidate:
            return candidate
    local_candidates = {
        "bstrings": [
            Path.home() / "tools" / "bstrings" / "bstrings.dll",
            Path.home() / "tools" / "bstrings" / "bstrings.exe",
        ],
        "MemProcFS": [Path.home() / "tools" / "MemProcFS" / "memprocfs"],
        "memprocfs": [Path.home() / "tools" / "MemProcFS" / "memprocfs"],
        "sidr": [Path.home() / "tools" / "sidr" / "sidr"],
        "usnjrnl-forensic": [Path.home() / "tools" / "cargo" / "bin" / "usnjrnl-forensic"],
        "pypykatz": [
            _tools_dir(None) / "bin" / "pypykatz",
            Path.home() / ".local" / "bin" / "pypykatz",
        ],
        "vol": [
            _tools_dir(None) / "bin" / "vol",
            Path.home() / ".local" / "bin" / "vol",
        ],
        "volatility3": [
            _tools_dir(None) / "bin" / "vol",
            Path.home() / ".local" / "bin" / "vol",
        ],
        "volatility3-symbols": [
            _tools_dir(None) / "volatility3-symbols" / "windows.zip",
            Path("/opt/perceptor-tools") / "volatility3-symbols" / "windows.zip",
            Path("/opt/relic-tools") / "volatility3-symbols" / "windows.zip",
            Path.home() / "tools" / "volatility3-symbols" / "windows.zip",
        ],
        "ual-timeliner": [
            _tools_dir(None) / "bin" / "ual-timeliner",
            Path.home() / ".local" / "bin" / "ual-timeliner",
            Path.home() / "tools" / "ual-timeliner" / "ual-timeliner",
        ],
    }
    for candidate in local_candidates.get(name, []):
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)


def _package_version() -> str:
    for package in ("perceptor", "forensic-orchestrator"):
        try:
            return metadata.version(package)
        except metadata.PackageNotFoundError:
            continue
    return "0.1.0"


def _job_status(row: dict[str, Any]) -> str:
    if row.get("end_time") is None:
        return "unfinished"
    return "completed" if row.get("exit_code") == 0 else "failed"


def _check(name: str, passed: bool, details: Any) -> dict[str, Any]:
    return {"name": name, "passed": passed, "details": details}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_text(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, indent=2, default=str) + "\n"
