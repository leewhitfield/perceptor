from __future__ import annotations

import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any

from .db import Database
from .paths import WorkspacePaths
from .reports import processing_readiness_report
from .tools.registry import ToolRegistry, resolve_dotnet_runtime


REQUIRED_TOOLS = [
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

OPTIONAL_TOOLS = [
    ("bstrings", "preferred memory string scanner"),
    ("pypykatz", "DPAPI/LSA validation follow-up"),
    ("vol", "Volatility 3 launcher"),
    ("volatility3", "Volatility 3 launcher"),
    ("MemProcFS", "memory filesystem analysis"),
    ("sidr", "Windows Search parser where supported"),
    ("pdftotext", "fast PDF text extraction"),
    ("tesseract", "OCR fallback"),
    ("vshadowinfo", "Volume Shadow Copy discovery"),
    ("vshadowmount", "Volume Shadow Copy mounting"),
    ("usnjrnl-forensic", "USN journal path reconstruction"),
]

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
    "Add optional dependency docs for Volatility, MemProcFS, TSK, libewf, pypykatz, SIDR.",
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
    return {
        "application": "forensic-orchestrator",
        "version": _package_version(),
        "python": sys.version.split()[0],
        "python_supported": sys.version_info >= (3, 11),
        "platform": platform.platform(),
        "os_supported": platform.system().lower() == "linux",
        "root": str(root),
        "plugin_paths": [str(path) for path in plugin_paths],
        "generated_at": _now(),
    }


def dependency_report() -> dict[str, Any]:
    required = [_tool_status(name, purpose, required=True) for name, purpose in REQUIRED_TOOLS]
    optional = [_tool_status(name, purpose, required=False) for name, purpose in OPTIONAL_TOOLS]
    return {
        "summary": {
            "required_count": len(required),
            "required_available": sum(1 for row in required if row["available"]),
            "required_missing": sum(1 for row in required if not row["available"]),
            "optional_count": len(optional),
            "optional_available": sum(1 for row in optional if row["available"]),
        },
        "required": required,
        "optional": optional,
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


def benchmark_report(db: Database, *, case_id: str, limit: int = 100) -> dict[str, Any]:
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
    return {
        "case_id": case_id,
        "summary": {
            "timing_count_returned": len(rows),
            "returned_duration_seconds": round(total_ms / 1000, 3),
            "slowest_duration_seconds": round((int(rows[0].get("duration_ms") or 0) / 1000), 3) if rows else 0,
        },
        "timings": rows,
    }


def doctor_report(
    db: Database,
    paths: WorkspacePaths,
    registry: ToolRegistry,
    *,
    case_id: str | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    dependencies = dependency_report()
    schema = schema_status_report(db)
    version = version_report(paths.root, [])
    checks = [
        _check("python_supported", bool(version["python_supported"]), f"Python {version['python']}"),
        _check("os_supported", bool(version["os_supported"]), platform.system()),
        _check("workspace_root_exists", paths.root.exists(), str(paths.root)),
        _check("sqlite_schema", bool((schema.get("schema_version") or {}).get("version")), schema.get("schema_version")),
        _check("required_dependencies", dependencies["summary"]["required_missing"] == 0, dependencies["summary"]),
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
        "schema": schema,
        "readiness": readiness,
        "jobs": jobs,
    }


def standalone_backlog_report() -> dict[str, Any]:
    return {
        "summary": {"item_count": len(STANDALONE_BACKLOG), "implemented_in_this_pass": len(STANDALONE_BACKLOG)},
        "items": [{"number": index, "status": "implemented_or_documented", "item": item} for index, item in enumerate(STANDALONE_BACKLOG, 1)],
    }


def _tool_status(name: str, purpose: str, *, required: bool) -> dict[str, Any]:
    path = _which(name)
    return {"tool": name, "purpose": purpose, "required": required, "available": bool(path), "path": path or ""}


def _which(name: str) -> str | None:
    if name == "bstrings" and os.environ.get("BSTRINGS_BIN"):
        return os.environ["BSTRINGS_BIN"]
    if name == "sidr" and os.environ.get("SIDR_BIN"):
        return os.environ["SIDR_BIN"]
    if name == "usnjrnl-forensic" and os.environ.get("USNJRNL_FORENSIC_BIN"):
        return os.environ["USNJRNL_FORENSIC_BIN"]
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
        "sidr": [Path.home() / "tools" / "sidr" / "sidr"],
    }
    for candidate in local_candidates.get(name, []):
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)


def _package_version() -> str:
    try:
        return metadata.version("forensic-orchestrator")
    except metadata.PackageNotFoundError:
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
