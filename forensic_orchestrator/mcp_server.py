from __future__ import annotations

import json
import mimetypes
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable, TextIO
from urllib.parse import quote, unquote
import uuid

from .config import default_plugin_path
from .db import Database
from .paths import WorkspacePaths
from .report_bundle import parser_coverage_report, report_bundle_preflight_report
from .reports import (
    browser_activity_report,
    case_review_report,
    case_dashboard_report,
    case_summary_report,
    cloud_artifacts_report,
    communications_report,
    external_storage_report,
    file_movement_identity_report,
    memory_analysis_report,
    memory_artifacts_report,
    opened_from_cloud_storage_report,
    opened_from_removable_media_report,
    processing_progress_report,
    registry_activity_report,
    resume_plan_report,
    shortcuts_report,
    suspicious_executions_report,
    timeline_report,
    usb_file_correlation_report,
    workspace_health_report,
)
from .standalone import doctor_report, job_status_report
from .tools.profiles import profile_extraction_preview
from .tools.registry import ToolRegistry


SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SUPPORTED_MCP_REPORTS = {
    "dashboard",
    "progress",
    "resume-plan",
    "external-storage",
    "suspicious-executions",
    "interesting-executables",
    "file-movement-identity",
    "opened-from-removable-media",
    "opened-from-cloud-storage",
    "memory-analysis",
    "memory-artifacts",
    "cloud-artifacts",
    "usb-files",
    "usb-timeline",
}
MCP_JOB_INDEX = "index.json"
MCP_AUDIT_LOG = "audit.jsonl"
MCP_RESOURCE_MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class McpTool:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    annotations: dict[str, Any]
    permission: str = "read"

    def definition(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations,
        }


class RelicMcpServer:
    def __init__(
        self,
        *,
        root: Path,
        allow_processing: bool = False,
        allow_sensitive: bool = False,
        allow_external_ai: bool = False,
        plugin_paths: list[Path] | None = None,
    ) -> None:
        self.paths = WorkspacePaths(root)
        self.allow_processing = allow_processing
        self.allow_sensitive = allow_sensitive
        self.allow_external_ai = allow_external_ai
        self.plugin_paths = plugin_paths or [default_plugin_path()]
        self._mcp_jobs: dict[str, dict[str, Any]] = self._load_mcp_job_index()
        self.tools = {tool.name: tool for tool in self._build_tools()}

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            return self._error(None, -32600, "Invalid JSON-RPC message")
        request_id = message.get("id")
        method = str(message.get("method") or "")
        if request_id is None:
            self._handle_notification(method)
            return None
        try:
            if method == "initialize":
                return self._response(request_id, self._initialize_result(message.get("params") or {}))
            if method == "ping":
                return self._response(request_id, {})
            if method == "resources/list":
                return self._response(request_id, self._list_resources(message.get("params") or {}))
            if method == "resources/read":
                return self._response(request_id, self._read_resource(message.get("params") or {}))
            if method == "tools/list":
                return self._response(request_id, {"tools": [tool.definition() for tool in self.tools.values()]})
            if method == "tools/call":
                return self._response(request_id, self._call_tool(message.get("params") or {}))
            return self._error(request_id, -32601, f"Method not found: {method}")
        except ValueError as exc:
            return self._error(request_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover - defensive protocol boundary
            return self._error(request_id, -32603, str(exc))

    def _handle_notification(self, method: str) -> None:
        if method in {"notifications/initialized", "notifications/cancelled"}:
            return

    def _initialize_result(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = str(params.get("protocolVersion") or "")
        protocol_version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return {
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {"listChanged": False}, "resources": {"subscribe": False, "listChanged": False}},
            "serverInfo": {"name": "relic", "version": _package_version()},
            "instructions": (
                "Relic MCP exposes forensic workspace tools. Inspection and report-generation tools are available by default. "
                "Import and processing calls require --allow-processing. Sensitive credential reveal, external AI upload, "
                "and destructive actions are not implemented in the default MCP surface."
            ),
        }

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise ValueError("tools/call arguments must be an object")
        tool = self.tools.get(name)
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")
        self._require_permission(tool.permission)
        try:
            result = tool.handler(arguments)
            self._audit_tool_call(tool, arguments, status="ok", error=None)
            return _tool_result(result)
        except Exception as exc:
            self._audit_tool_call(tool, arguments, status="error", error=str(exc))
            return _tool_result({"error": str(exc), "tool": name}, is_error=True)

    def _build_tools(self) -> list[McpTool]:
        read_only = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
        safe_write = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False}
        processing = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False}
        return [
            McpTool(
                name="relic_workspace_summary",
                title="Relic Workspace Summary",
                description="Summarize the configured Relic workspace and top-level case/job counts.",
                input_schema=_object_schema({}),
                handler=self.workspace_summary,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_cases",
                title="List Relic Cases",
                description="List cases in the configured Relic workspace.",
                input_schema=_object_schema({"limit": _integer_schema("Maximum cases to return.", default=100, minimum=1, maximum=1000)}),
                handler=self.list_cases,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_summary",
                title="Relic Case Summary",
                description="Return computers, images, parsed row counts, artifacts, jobs, warnings, and errors for a case.",
                input_schema=_object_schema({"case_id": _string_schema("Relic case ID.")}, required=["case_id"]),
                handler=self.case_summary,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_dashboard",
                title="Relic Case Dashboard",
                description="Return the high-level investigation dashboard for a case.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_dashboard,
                annotations=read_only,
            ),
            McpTool(
                name="relic_processing_progress",
                title="Relic Processing Progress",
                description="Return active/failed timings and recent jobs for a case.",
                input_schema=_case_limit_schema(default=50),
                handler=self.processing_progress,
                annotations=read_only,
            ),
            McpTool(
                name="relic_resume_plan",
                title="Relic Resume Plan",
                description="Return recommended next commands after interrupted or partial processing.",
                input_schema=_case_limit_schema(default=50),
                handler=self.resume_plan,
                annotations=read_only,
            ),
            McpTool(
                name="relic_workspace_health",
                title="Relic Workspace Health",
                description="Check workspace disk, temp, and case health indicators.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Optional Relic case ID."),
                        "min_free_gb": {"type": "number", "description": "Minimum free GB warning threshold.", "default": 10.0},
                    }
                ),
                handler=self.workspace_health,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_computers",
                title="List Relic Computers",
                description="List computers attached to a case.",
                input_schema=_object_schema({"case_id": _string_schema("Relic case ID.")}, required=["case_id"]),
                handler=self.list_computers,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_images",
                title="List Relic Images",
                description="List images attached to a case.",
                input_schema=_object_schema({"case_id": _string_schema("Relic case ID.")}, required=["case_id"]),
                handler=self.list_images,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_jobs",
                title="List Relic Jobs",
                description="List recent jobs for a case.",
                input_schema=_case_limit_schema(default=100),
                handler=self.list_jobs,
                annotations=read_only,
            ),
            McpTool(
                name="relic_get_job",
                title="Get Relic Job",
                description="Return one job record by case ID and job ID.",
                input_schema=_object_schema(
                    {"case_id": _string_schema("Relic case ID."), "job_id": _string_schema("Relic job ID.")},
                    required=["case_id", "job_id"],
                ),
                handler=self.get_job,
                annotations=read_only,
            ),
            McpTool(
                name="relic_timeline",
                title="Relic Timeline",
                description="Query the normalized timeline for a case.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum events to return.", default=50, minimum=1, maximum=1000),
                        "event_type": _string_schema("Optional event type filter."),
                        "source_tool": _string_schema("Optional source tool filter."),
                        "contains": _string_schema("Optional case-insensitive text filter."),
                    },
                    required=["case_id"],
                ),
                handler=self.timeline,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_suspicious_executions",
                title="Query Suspicious Executions",
                description="Return suspicious execution findings for a case.",
                input_schema=_case_limit_schema(default=100),
                handler=self.query_suspicious_executions,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_external_storage",
                title="Query External Storage",
                description="Return external/removable storage summary and timeline context.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=250, minimum=1, maximum=1000),
                        "include_file_activity": {"type": "boolean", "default": True},
                    },
                    required=["case_id"],
                ),
                handler=self.query_external_storage,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_usb_files",
                title="Query USB Files",
                description="Return USB/removable-media file correlations.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=500, minimum=1, maximum=1000),
                        "grouped": {"type": "boolean", "default": False},
                    },
                    required=["case_id"],
                ),
                handler=self.query_usb_files,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_file_movement_identity",
                title="Query File Movement Identity",
                description="Return identity and movement correlations from shortcuts, DROID, and related artifacts.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                        "contains": _string_schema("Optional text filter."),
                        "min_confidence": {"type": "string", "enum": ["review", "low", "context", "medium", "high"]},
                        "high_confidence_only": {"type": "boolean", "default": False},
                    },
                    required=["case_id"],
                ),
                handler=self.query_file_movement_identity,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_opened_from_removable_media",
                title="Query Opened From Removable Media",
                description="Return files or artifacts indicating user-opened content from removable media.",
                input_schema=_user_contains_schema(default=100),
                handler=self.query_opened_from_removable_media,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_opened_from_cloud_storage",
                title="Query Opened From Cloud Storage",
                description="Return files or artifacts indicating user-opened content from cloud-synced storage.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                        "user": _string_schema("Optional user/profile filter."),
                        "provider": _string_schema("Optional cloud provider filter."),
                        "contains": _string_schema("Optional text filter."),
                    },
                    required=["case_id"],
                ),
                handler=self.query_opened_from_cloud_storage,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_cloud_artifacts",
                title="Query Cloud Artifacts",
                description="Return cloud storage and cloud application artifacts.",
                input_schema=_case_limit_schema(default=100),
                handler=self.query_cloud_artifacts,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_memory_artifacts",
                title="Query Memory Artifacts",
                description="Return memory artifact inventory rows.",
                input_schema=_case_limit_schema(default=100),
                handler=self.query_memory_artifacts,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_browser_activity",
                title="Query Browser Activity",
                description="Return browser host, download, WebCache, and cache correlation summary.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                        "browser": _string_schema("Optional browser filter."),
                        "user": _string_schema("Optional user/profile filter."),
                        "include_noise": {"type": "boolean", "default": False},
                    },
                    required=["case_id"],
                ),
                handler=self.query_browser_activity,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_registry_activity",
                title="Query Registry Activity",
                description="Return targeted registry activity such as RunMRU, RecentDocs, UserAssist, or Office MRU.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "artifact": _string_schema("Registry artifact name, for example runmru, recentdocs, userassist, office-mru."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                        "user": _string_schema("Optional user/profile filter."),
                    },
                    required=["case_id", "artifact"],
                ),
                handler=self.query_registry_activity,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_shortcuts",
                title="Query Shortcuts",
                description="Return LNK or JumpList shortcut artifacts.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                        "artifact_type": {"type": "string", "enum": ["lnk", "jumplist"]},
                    },
                    required=["case_id"],
                ),
                handler=self.query_shortcuts,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_communications",
                title="Query Communications",
                description="Return communication artifacts from mailbox, Windows Search, messaging, and related sources.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                        "user": _string_schema("Optional user/profile filter."),
                        "contains": _string_schema("Optional text filter."),
                        "source_type": _string_schema("Optional source type filter."),
                        "include_low_value": {"type": "boolean", "default": False},
                    },
                    required=["case_id"],
                ),
                handler=self.query_communications,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_review",
                title="Relic Case Review",
                description="Return a combined investigative review across dashboard, suspicious execution, storage, cloud, movement, memory, browser, and communications.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_review,
                annotations=read_only,
            ),
            McpTool(
                name="relic_ingest_triage_zip_preflight",
                title="Relic Triage ZIP Preflight",
                description="Validate a live-case/report ZIP without importing it.",
                input_schema=_object_schema(
                    {
                        "path": _string_schema("Path to the live-case/report ZIP or folder."),
                        "max_uncompressed_gb": {"type": "number", "description": "Optional maximum uncompressed ZIP size in GB. 0 disables.", "default": 0.0},
                    },
                    required=["path"],
                ),
                handler=self.ingest_triage_zip_preflight,
                annotations=read_only,
            ),
            McpTool(
                name="relic_report_bundle_coverage",
                title="Relic Report Bundle Coverage",
                description="Inspect report-bundle parser coverage for a folder or ZIP.",
                input_schema=_object_schema({"path": _string_schema("Optional report bundle folder or ZIP path.")}),
                handler=self.report_bundle_coverage,
                annotations=read_only,
            ),
            McpTool(
                name="relic_profile_preview",
                title="Relic Profile Preview",
                description="Preview extraction and tool coverage for a Relic processing profile.",
                input_schema=_object_schema({"profile": _string_schema("Relic profile name.")}, required=["profile"]),
                handler=self.profile_preview,
                annotations=read_only,
            ),
            McpTool(
                name="relic_doctor",
                title="Relic Doctor",
                description="Run Relic doctor checks. This MCP tool does not repair dependencies.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Optional Relic case ID."),
                        "profile": _string_schema("Optional profile name."),
                        "smoke": {"type": "boolean", "description": "Run a small isolated smoke test.", "default": False},
                    }
                ),
                handler=self.doctor,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_report_types",
                title="Relic Report Types",
                description="List report types supported by the generic MCP report runner.",
                input_schema=_object_schema({}),
                handler=self.list_report_types,
                annotations=read_only,
            ),
            McpTool(
                name="relic_mcp_tool_reference",
                title="Relic MCP Tool Reference",
                description="Return MCP tool names, permission tiers, annotations, and schemas.",
                input_schema=_object_schema({}),
                handler=self.mcp_tool_reference,
                annotations=read_only,
            ),
            McpTool(
                name="relic_generate_report",
                title="Relic Generate Report",
                description="Generate a supported report through the Relic CLI and return stdout/stderr metadata.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "report_name": _string_schema("Supported report name."),
                        "format": {"type": "string", "enum": ["json", "table", "csv", "md"], "default": "json"},
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                        "output": _string_schema("Optional output path. Must be under the workspace root."),
                    },
                    required=["case_id", "report_name"],
                ),
                handler=self.generate_report,
                annotations=safe_write,
                permission="safe_write",
            ),
            McpTool(
                name="relic_write_report_bundle",
                title="Relic Write Report Bundle",
                description="Write a purpose-built report bundle under the workspace root.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "output_dir": _string_schema("Output directory under the workspace root."),
                        "purpose": {"type": "string", "enum": ["full", "usb", "cloud", "execution", "memory", "triage"], "default": "full"},
                        "limit": _integer_schema("Maximum rows per report.", default=100, minimum=1, maximum=1000),
                    },
                    required=["case_id", "output_dir"],
                ),
                handler=self.write_report_bundle,
                annotations=safe_write,
                permission="safe_write",
            ),
            McpTool(
                name="relic_get_mcp_job",
                title="Get Relic MCP Job",
                description="Return persisted status for a long-running process launched by MCP.",
                input_schema=_object_schema({"mcp_job_id": _string_schema("MCP job ID returned by a processing tool.")}, required=["mcp_job_id"]),
                handler=self.get_mcp_job,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_mcp_jobs",
                title="List Relic MCP Jobs",
                description="List persisted MCP-launched subprocess jobs.",
                input_schema=_object_schema(
                    {
                        "limit": _integer_schema("Maximum jobs to return.", default=100, minimum=1, maximum=1000),
                        "status": _string_schema("Optional status filter."),
                    }
                ),
                handler=self.list_mcp_jobs,
                annotations=read_only,
            ),
            McpTool(
                name="relic_get_mcp_job_output",
                title="Get Relic MCP Job Output",
                description="Return stdout/stderr tails and parsed JSON stdout when available for an MCP job.",
                input_schema=_object_schema(
                    {
                        "mcp_job_id": _string_schema("MCP job ID returned by a processing tool."),
                        "max_bytes": _integer_schema("Maximum bytes to return from each stream.", default=20000, minimum=1000, maximum=200000),
                    },
                    required=["mcp_job_id"],
                ),
                handler=self.get_mcp_job_output,
                annotations=read_only,
            ),
            McpTool(
                name="relic_cancel_mcp_job",
                title="Cancel Relic MCP Job",
                description="Cancel a running MCP-launched subprocess. Requires --allow-processing.",
                input_schema=_object_schema({"mcp_job_id": _string_schema("MCP job ID returned by a processing tool.")}, required=["mcp_job_id"]),
                handler=self.cancel_mcp_job,
                annotations=processing,
                permission="processing",
            ),
            McpTool(
                name="relic_import_triage_zip",
                title="Relic Import Triage ZIP",
                description="Start a gated bulk live-case/report ZIP import as a background MCP job.",
                input_schema=_object_schema(
                    {
                        "path": _string_schema("Path to the live-case/report ZIP or folder."),
                        "case_id": _string_schema("Optional existing case ID."),
                        "accept_duplicate": {"type": "boolean", "default": False},
                        "no_progress": {"type": "boolean", "default": False},
                        "write_reports": {"type": "boolean", "default": True},
                        "report_purpose": {"type": "string", "enum": ["full", "usb", "cloud", "execution", "memory", "triage"], "default": "triage"},
                        "report_output_dir": _string_schema("Optional report output directory under the workspace root."),
                    },
                    required=["path"],
                ),
                handler=self.import_triage_zip,
                annotations=processing,
                permission="processing",
            ),
            McpTool(
                name="relic_import_report_bundle",
                title="Relic Import Report Bundle",
                description="Start a gated single-computer report bundle import as a background MCP job.",
                input_schema=_object_schema(
                    {
                        "path": _string_schema("Path to report bundle folder."),
                        "case_id": _string_schema("Optional existing case ID."),
                        "computer_id": _string_schema("Optional existing computer ID."),
                        "computer_label": _string_schema("Optional computer label."),
                        "accept_duplicate": {"type": "boolean", "default": False},
                        "no_progress": {"type": "boolean", "default": False},
                    },
                    required=["path"],
                ),
                handler=self.import_report_bundle,
                annotations=processing,
                permission="processing",
            ),
            McpTool(
                name="relic_process_image",
                title="Relic Process Image",
                description="Start a gated image processing run as a background MCP job.",
                input_schema=_object_schema(
                    {
                        "path": _string_schema("Path to source image."),
                        "case_id": _string_schema("Optional existing case ID."),
                        "computer_id": _string_schema("Optional existing computer ID."),
                        "computer_label": _string_schema("Optional computer label."),
                        "hostname": _string_schema("Optional hostname."),
                        "profile": _string_schema("Processing profile name."),
                        "filesystem": {"type": "boolean", "default": False},
                        "use_sudo_mount": {"type": "boolean", "default": False},
                        "keep_mounted": {"type": "boolean", "default": False},
                        "accept_duplicate": {"type": "boolean", "default": False},
                        "replace_existing": {"type": "boolean", "default": False},
                        "workers": _integer_schema("Worker slots.", default=1, minimum=1, maximum=64),
                        "dry_run": {"type": "boolean", "default": False},
                    },
                    required=["path"],
                ),
                handler=self.process_image,
                annotations=processing,
                permission="processing",
            ),
            McpTool(
                name="relic_run_profile",
                title="Relic Run Profile",
                description="Start a gated profile run against an existing case image as a background MCP job.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "image_id": _string_schema("Relic image ID."),
                        "profile": _string_schema("Processing profile name."),
                        "accept_duplicate": {"type": "boolean", "default": False},
                        "replace_existing": {"type": "boolean", "default": False},
                    },
                    required=["case_id", "image_id", "profile"],
                ),
                handler=self.run_profile,
                annotations=processing,
                permission="processing",
            ),
        ]

    def _db(self) -> Database:
        return Database(self.paths.db_path())

    def _list_resources(self, params: dict[str, Any]) -> dict[str, Any]:
        limit = _bounded_int(params, "limit", default=200, minimum=1, maximum=1000)
        case_id = _optional_text(params, "case_id")
        kind = _optional_text(params, "kind")
        resources = []
        root_resolved = self.paths.root.resolve()
        for path in _resource_candidates(self.paths.root, case_id=case_id, kind=kind):
            if len(resources) >= limit:
                break
            resolved = path.resolve()
            if resolved != root_resolved and root_resolved not in resolved.parents:
                continue
            stat = resolved.stat()
            relative = resolved.relative_to(root_resolved)
            mime_type = mimetypes.guess_type(resolved.name)[0] or "text/plain"
            resources.append(
                {
                    "uri": _resource_uri(relative),
                    "name": str(relative),
                    "title": resolved.name,
                    "mimeType": mime_type,
                    "description": f"Relic workspace file ({stat.st_size} bytes)",
                }
            )
        return {"resources": resources}

    def _read_resource(self, params: dict[str, Any]) -> dict[str, Any]:
        uri = _required(params, "uri")
        path = _path_from_resource_uri(self.paths.root, uri)
        if not path.exists() or not path.is_file():
            raise ValueError(f"Resource not found: {uri}")
        size = path.stat().st_size
        if size > MCP_RESOURCE_MAX_BYTES:
            raise ValueError(f"Resource exceeds MCP read limit ({size} > {MCP_RESOURCE_MAX_BYTES} bytes): {uri}")
        mime_type = mimetypes.guess_type(path.name)[0] or "text/plain"
        text = path.read_text(encoding="utf-8", errors="replace")
        return {"contents": [{"uri": uri, "mimeType": mime_type, "text": text}]}

    def workspace_summary(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.paths.db_path().exists():
            return {
                "workspace_root": str(self.paths.root),
                "db_path": str(self.paths.db_path()),
                "db_exists": False,
                "counts": {"cases": 0, "computers": 0, "images": 0, "jobs": 0},
                "permissions": self._permissions(),
            }
        db = self._db()
        try:
            counts = {
                "cases": _count_table(db, "cases"),
                "computers": _count_table(db, "computers"),
                "images": _count_table(db, "images"),
                "jobs": _count_table(db, "jobs"),
            }
            latest_cases = _case_rows(db, _limit(arguments, default=10))
            return {
                "workspace_root": str(self.paths.root),
                "db_path": str(self.paths.db_path()),
                "db_exists": True,
                "counts": counts,
                "cases": latest_cases,
                "permissions": self._permissions(),
            }
        finally:
            db.close()

    def list_cases(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = _limit(arguments, default=100)
        db = self._db()
        try:
            rows = _case_rows(db, limit)
            return {"workspace_root": str(self.paths.root), "cases": rows, "total_returned": len(rows)}
        finally:
            db.close()

    def case_summary(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return case_summary_report(db, _required(arguments, "case_id"))
        finally:
            db.close()

    def case_dashboard(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return case_dashboard_report(db, _required(arguments, "case_id"), limit=_limit(arguments, default=25))
        finally:
            db.close()

    def processing_progress(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return processing_progress_report(db, _required(arguments, "case_id"), limit=_limit(arguments, default=50))
        finally:
            db.close()

    def resume_plan(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return resume_plan_report(db, _required(arguments, "case_id"), limit=_limit(arguments, default=50))
        finally:
            db.close()

    def workspace_health(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            case_id = str(arguments.get("case_id") or "").strip() or None
            return workspace_health_report(db, case_id, min_free_gb=float(arguments.get("min_free_gb") or 10.0))
        finally:
            db.close()

    def list_computers(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        db = self._db()
        try:
            db.get_case(case_id)
            rows = db.conn.execute(
                "SELECT id, case_id, label, hostname, notes, created_at FROM computers WHERE case_id = ? ORDER BY label, created_at",
                (case_id,),
            ).fetchall()
            return {"case_id": case_id, "computers": [dict(row) for row in rows], "total_returned": len(rows)}
        finally:
            db.close()

    def list_images(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        db = self._db()
        try:
            db.get_case(case_id)
            rows = db.conn.execute(
                """
                SELECT images.id, images.case_id, images.computer_id, computers.label AS computer_label,
                       images.path, images.created_at
                FROM images
                LEFT JOIN computers ON computers.id = images.computer_id
                WHERE images.case_id = ?
                ORDER BY images.created_at
                """,
                (case_id,),
            ).fetchall()
            return {"case_id": case_id, "images": [dict(row) for row in rows], "total_returned": len(rows)}
        finally:
            db.close()

    def list_jobs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return job_status_report(db, case_id=_required(arguments, "case_id"), limit=_limit(arguments, default=100))
        finally:
            db.close()

    def get_job(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        job_id = _required(arguments, "job_id")
        db = self._db()
        try:
            row = db.conn.execute(
                """
                SELECT id, case_id, image_id, computer_id, source_scope, tool_name, tool_version,
                       command_json, start_time, end_time, exit_code, stdout_path, stderr_path,
                       output_folder, dry_run
                FROM jobs
                WHERE case_id = ? AND id = ?
                """,
                (case_id, job_id),
            ).fetchone()
            if row is None:
                raise ValueError(f"Job not found: {job_id}")
            job = dict(row)
            job["command"] = _json_value(job.pop("command_json"), [])
            job["status"] = "unfinished" if job.get("end_time") is None else ("completed" if job.get("exit_code") == 0 else "failed")
            return {"case_id": case_id, "job": job}
        finally:
            db.close()

    def timeline(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return timeline_report(
                db,
                _required(arguments, "case_id"),
                limit=_limit(arguments, default=50),
                event_type=str(arguments.get("event_type") or "").strip() or None,
                source_tool=str(arguments.get("source_tool") or "").strip() or None,
                contains=str(arguments.get("contains") or "").strip() or None,
            )
        finally:
            db.close()

    def query_suspicious_executions(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return suspicious_executions_report(db, _required(arguments, "case_id"), limit=_limit(arguments, default=100))
        finally:
            db.close()

    def query_external_storage(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return external_storage_report(
                db,
                _required(arguments, "case_id"),
                limit=_limit(arguments, default=250),
                rebuild_correlations=False,
                include_file_activity=bool(arguments.get("include_file_activity", True)),
            )
        finally:
            db.close()

    def query_usb_files(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return usb_file_correlation_report(
                db,
                _required(arguments, "case_id"),
                limit=_limit(arguments, default=500),
                grouped=bool(arguments.get("grouped") or False),
            )
        finally:
            db.close()

    def query_file_movement_identity(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return file_movement_identity_report(
                db,
                _required(arguments, "case_id"),
                contains=_optional_text(arguments, "contains"),
                min_confidence=_optional_text(arguments, "min_confidence"),
                high_confidence_only=bool(arguments.get("high_confidence_only") or False),
                limit=_limit(arguments, default=100),
            )
        finally:
            db.close()

    def query_opened_from_removable_media(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return opened_from_removable_media_report(
                db,
                _required(arguments, "case_id"),
                user=_optional_text(arguments, "user"),
                contains=_optional_text(arguments, "contains"),
                limit=_limit(arguments, default=100),
            )
        finally:
            db.close()

    def query_opened_from_cloud_storage(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return opened_from_cloud_storage_report(
                db,
                _required(arguments, "case_id"),
                user=_optional_text(arguments, "user"),
                provider=_optional_text(arguments, "provider"),
                contains=_optional_text(arguments, "contains"),
                limit=_limit(arguments, default=100),
            )
        finally:
            db.close()

    def query_cloud_artifacts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return cloud_artifacts_report(db, _required(arguments, "case_id"), limit=_limit(arguments, default=100))
        finally:
            db.close()

    def query_memory_artifacts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return memory_artifacts_report(db, _required(arguments, "case_id"), limit=_limit(arguments, default=100))
        finally:
            db.close()

    def query_browser_activity(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return browser_activity_report(
                db,
                _required(arguments, "case_id"),
                limit=_limit(arguments, default=100),
                browser=_optional_text(arguments, "browser"),
                user=_optional_text(arguments, "user"),
                exclude_noise=not bool(arguments.get("include_noise") or False),
            )
        finally:
            db.close()

    def query_registry_activity(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return registry_activity_report(
                db,
                _required(arguments, "case_id"),
                artifact=_required(arguments, "artifact"),
                user=_optional_text(arguments, "user"),
                limit=_limit(arguments, default=100),
            )
        finally:
            db.close()

    def query_shortcuts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return shortcuts_report(
                db,
                _required(arguments, "case_id"),
                artifact_type=_optional_text(arguments, "artifact_type"),
                limit=_limit(arguments, default=100),
            )
        finally:
            db.close()

    def query_communications(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return communications_report(
                db,
                _required(arguments, "case_id"),
                limit=_limit(arguments, default=100),
                user=_optional_text(arguments, "user"),
                contains=_optional_text(arguments, "contains"),
                source_type=_optional_text(arguments, "source_type"),
                include_low_value=bool(arguments.get("include_low_value") or False),
            )
        finally:
            db.close()

    def case_review(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        limit = _limit(arguments, default=25)
        db = self._db()
        try:
            review = case_review_report(db, case_id, limit=limit)
            return {
                "case_id": case_id,
                "review": review,
                "dashboard": case_dashboard_report(db, case_id, limit=limit),
                "suspicious_executions": suspicious_executions_report(db, case_id, limit=limit),
                "external_storage": external_storage_report(db, case_id, limit=limit, rebuild_correlations=False, include_file_activity=False),
                "cloud_artifacts": cloud_artifacts_report(db, case_id, limit=limit),
                "file_movement_identity": file_movement_identity_report(db, case_id, limit=limit),
                "opened_from_removable_media": opened_from_removable_media_report(db, case_id, limit=limit),
                "opened_from_cloud_storage": opened_from_cloud_storage_report(db, case_id, limit=limit),
                "memory_analysis": memory_analysis_report(db, case_id, limit=limit),
                "memory_artifacts": memory_artifacts_report(db, case_id, limit=limit),
                "browser_activity": browser_activity_report(db, case_id, limit=limit),
                "communications": communications_report(db, case_id, limit=limit),
            }
        finally:
            db.close()

    def ingest_triage_zip_preflight(self, arguments: dict[str, Any]) -> dict[str, Any]:
        report = report_bundle_preflight_report(Path(_required(arguments, "path")).expanduser())
        _enforce_uncompressed_limit(report, float(arguments.get("max_uncompressed_gb") or 0.0))
        return report

    def report_bundle_coverage(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = str(arguments.get("path") or "").strip()
        return parser_coverage_report(Path(path).expanduser() if path else None)

    def profile_preview(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return profile_extraction_preview(self._registry(), _required(arguments, "profile"))

    def doctor(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return doctor_report(
                db,
                self.paths,
                self._registry(),
                case_id=str(arguments.get("case_id") or "").strip() or None,
                profile=str(arguments.get("profile") or "").strip() or None,
                smoke=bool(arguments.get("smoke") or False),
                repair=False,
            )
        finally:
            db.close()

    def list_report_types(self, arguments: dict[str, Any]) -> dict[str, Any]:
        reports = [
            {"name": name, "safe_write": True}
            for name in sorted(SUPPORTED_MCP_REPORTS)
        ]
        return {"reports": reports, "total_returned": len(reports)}

    def mcp_tool_reference(self, arguments: dict[str, Any]) -> dict[str, Any]:
        tools = []
        for tool in self.tools.values():
            tools.append(
                {
                    "name": tool.name,
                    "title": tool.title,
                    "description": tool.description,
                    "permission": tool.permission,
                    "annotations": tool.annotations,
                    "input_schema": tool.input_schema,
                }
            )
        return {"tools": tools, "total_returned": len(tools), "permissions": self._permissions()}

    def generate_report(self, arguments: dict[str, Any]) -> dict[str, Any]:
        report_name = _required(arguments, "report_name")
        if report_name not in SUPPORTED_MCP_REPORTS:
            raise ValueError(f"Unsupported MCP report_name: {report_name}")
        fmt = str(arguments.get("format") or "json")
        if fmt not in {"json", "table", "csv", "md"}:
            raise ValueError("format must be one of: json, table, csv, md")
        command = self._base_cli_command() + [
            "report",
            report_name,
            "--case",
            _required(arguments, "case_id"),
            "--format",
            fmt,
            "--limit",
            str(_limit(arguments, default=100)),
        ]
        output = str(arguments.get("output") or "").strip()
        if output:
            command.extend(["--output", str(_workspace_path(self.paths.root, output))])
        return self._run_cli_capture(command)

    def write_report_bundle(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            from .cli import write_case_report_bundle

            output_dir = _workspace_path(self.paths.root, _required(arguments, "output_dir"))
            purpose = str(arguments.get("purpose") or "full")
            if purpose not in {"full", "usb", "cloud", "execution", "memory", "triage"}:
                raise ValueError("purpose must be one of: full, usb, cloud, execution, memory, triage")
            result = write_case_report_bundle(
                db,
                _required(arguments, "case_id"),
                output_dir,
                limit=_limit(arguments, default=100),
                purpose=purpose,
            )
            result["resource_uris"] = _resource_uris_for_path(self.paths.root, output_dir)
            return result
        finally:
            db.close()

    def list_mcp_jobs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        rows = []
        status_filter = _optional_text(arguments, "status")
        for job in self._mcp_jobs.values():
            self._refresh_mcp_job(job)
            public = _public_job(job)
            if status_filter and public.get("status") != status_filter:
                continue
            rows.append(public)
        rows.sort(key=lambda row: str(row.get("started_at") or ""), reverse=True)
        self._save_mcp_job_index()
        limit = _limit(arguments, default=100)
        return {"jobs": rows[:limit], "total_returned": min(len(rows), limit), "total_matching": len(rows)}

    def get_mcp_job(self, arguments: dict[str, Any]) -> dict[str, Any]:
        mcp_job_id = _required(arguments, "mcp_job_id")
        job = self._mcp_jobs.get(mcp_job_id)
        if job is None:
            raise ValueError(f"MCP job not found: {mcp_job_id}")
        self._refresh_mcp_job(job)
        self._save_mcp_job_index()
        return _public_job(job)

    def get_mcp_job_output(self, arguments: dict[str, Any]) -> dict[str, Any]:
        job = self._mcp_jobs.get(_required(arguments, "mcp_job_id"))
        if job is None:
            raise ValueError("MCP job not found")
        max_bytes = _bounded_int(arguments, "max_bytes", default=20_000, minimum=1_000, maximum=200_000)
        self._refresh_mcp_job(job)
        stdout_tail = _read_tail(Path(str(job["stdout_path"])), max_bytes)
        stderr_tail = _read_tail(Path(str(job["stderr_path"])), max_bytes)
        parsed_stdout = _json_value(stdout_tail, None) if stdout_tail.strip().startswith(("{", "[")) else None
        return {**_public_job(job), "stdout_tail": stdout_tail, "stderr_tail": stderr_tail, "json": parsed_stdout}

    def cancel_mcp_job(self, arguments: dict[str, Any]) -> dict[str, Any]:
        job = self._mcp_jobs.get(_required(arguments, "mcp_job_id"))
        if job is None:
            raise ValueError("MCP job not found")
        self._refresh_mcp_job(job)
        if job.get("status") != "running":
            return {**_public_job(job), "cancelled": False, "reason": "Job is not running."}
        pid = int(job["pid"])
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            job["status"] = "unknown_finished"
            job["ended_at"] = job.get("ended_at") or _now()
            self._save_mcp_job_index()
            return {**_public_job(job), "cancelled": False, "reason": "Process was no longer running."}
        process = job.get("process")
        if isinstance(process, subprocess.Popen):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        job["status"] = "cancelled"
        job["ended_at"] = _now()
        job["returncode"] = -signal.SIGTERM
        self._save_mcp_job_index()
        return {**_public_job(job), "cancelled": True}

    def import_triage_zip(self, arguments: dict[str, Any]) -> dict[str, Any]:
        command = self._base_cli_command() + ["ingest", "triage-zip", "--path", str(Path(_required(arguments, "path")).expanduser())]
        _extend_optional(command, "--case", arguments.get("case_id"))
        if bool(arguments.get("accept_duplicate") or False):
            command.append("--accept-duplicate")
        if bool(arguments.get("no_progress") or False):
            command.append("--no-progress")
        if bool(arguments.get("write_reports", True)):
            command.append("--write-reports")
        else:
            command.append("--no-write-reports")
        _extend_optional(command, "--report-purpose", arguments.get("report_purpose") or "triage")
        if arguments.get("report_output_dir"):
            command.extend(["--report-output-dir", str(_workspace_path(self.paths.root, str(arguments["report_output_dir"])))])
        return self._start_mcp_process("import_triage_zip", command)

    def import_report_bundle(self, arguments: dict[str, Any]) -> dict[str, Any]:
        command = self._base_cli_command() + ["report-bundle", "import", "--path", str(Path(_required(arguments, "path")).expanduser())]
        _extend_optional(command, "--case", arguments.get("case_id"))
        _extend_optional(command, "--computer", arguments.get("computer_id"))
        _extend_optional(command, "--computer-label", arguments.get("computer_label"))
        if bool(arguments.get("accept_duplicate") or False):
            command.append("--accept-duplicate")
        if bool(arguments.get("no_progress") or False):
            command.append("--no-progress")
        return self._start_mcp_process("import_report_bundle", command)

    def process_image(self, arguments: dict[str, Any]) -> dict[str, Any]:
        command = self._base_cli_command(dry_run=bool(arguments.get("dry_run") or False)) + [
            "process",
            "--path",
            str(Path(_required(arguments, "path")).expanduser()),
            "--profile",
            str(arguments.get("profile") or "windows-basic"),
            "--workers",
            str(_bounded_int(arguments, "workers", default=1, minimum=1, maximum=64)),
        ]
        _extend_optional(command, "--case", arguments.get("case_id"))
        _extend_optional(command, "--computer", arguments.get("computer_id"))
        _extend_optional(command, "--computer-label", arguments.get("computer_label"))
        _extend_optional(command, "--hostname", arguments.get("hostname"))
        for flag, key in (
            ("--filesystem", "filesystem"),
            ("--sudo", "use_sudo_mount"),
            ("--keep-mounted", "keep_mounted"),
            ("--accept-duplicate", "accept_duplicate"),
            ("--replace-existing", "replace_existing"),
        ):
            if bool(arguments.get(key) or False):
                command.append(flag)
        return self._start_mcp_process("process_image", command)

    def run_profile(self, arguments: dict[str, Any]) -> dict[str, Any]:
        command = self._base_cli_command() + [
            "run",
            "--case",
            _required(arguments, "case_id"),
            "--image",
            _required(arguments, "image_id"),
            "--profile",
            _required(arguments, "profile"),
        ]
        for flag, key in (("--accept-duplicate", "accept_duplicate"), ("--replace-existing", "replace_existing")):
            if bool(arguments.get(key) or False):
                command.append(flag)
        return self._start_mcp_process("run_profile", command)

    def _registry(self) -> ToolRegistry:
        return ToolRegistry.from_files(self.plugin_paths)

    def _base_cli_command(self, *, dry_run: bool = False) -> list[str]:
        command = [sys.executable, "-m", "forensic_orchestrator.cli", "--root", str(self.paths.root)]
        for plugin_path in self.plugin_paths:
            command.extend(["--plugin", str(plugin_path)])
        if dry_run:
            command.append("--dry-run")
        return command

    def _run_cli_capture(self, command: list[str]) -> dict[str, Any]:
        completed = subprocess.run(command, cwd=Path.cwd(), capture_output=True, text=True, check=False)
        parsed_stdout = _json_value(completed.stdout, None) if completed.stdout.strip().startswith(("{", "[")) else None
        return {
            "command": command,
            "returncode": completed.returncode,
            "status": "completed" if completed.returncode == 0 else "failed",
            "stdout": completed.stdout[-100_000:],
            "stderr": completed.stderr[-20_000:],
            "json": parsed_stdout,
        }

    def _start_mcp_process(self, name: str, command: list[str]) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        job_dir = self._mcp_jobs_dir() / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = job_dir / "stdout.txt"
        stderr_path = job_dir / "stderr.txt"
        stdout_handle = stdout_path.open("w", encoding="utf-8")
        stderr_handle = stderr_path.open("w", encoding="utf-8")
        try:
            process = subprocess.Popen(
                command,
                cwd=Path.cwd(),
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                start_new_session=True,
            )
        finally:
            stdout_handle.close()
            stderr_handle.close()
        job = {
            "mcp_job_id": job_id,
            "name": name,
            "status": "running",
            "pid": process.pid,
            "command": command,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "started_at": _now(),
            "ended_at": None,
            "returncode": None,
            "process": process,
        }
        self._mcp_jobs[job_id] = job
        self._save_mcp_job_index()
        return _public_job(job)

    def _audit_tool_call(self, tool: McpTool, arguments: dict[str, Any], *, status: str, error: str | None) -> None:
        row = {
            "timestamp": _now(),
            "tool": tool.name,
            "permission": tool.permission,
            "status": status,
            "error": error,
            "argument_keys": sorted(arguments.keys()),
            "case_id": arguments.get("case_id"),
            "image_id": arguments.get("image_id"),
            "path": _summarize_path(arguments.get("path")),
        }
        audit_path = self._mcp_jobs_dir() / MCP_AUDIT_LOG
        try:
            with audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, default=str, separators=(",", ":")) + "\n")
        except OSError:
            return

    def _refresh_mcp_job(self, job: dict[str, Any]) -> None:
        process = job.get("process")
        returncode = process.poll() if isinstance(process, subprocess.Popen) else None
        if returncode is not None:
            job["returncode"] = returncode
            job["status"] = "completed" if returncode == 0 else "failed"
            job["ended_at"] = job.get("ended_at") or _now()
            return
        if job.get("status") in {"completed", "failed", "cancelled"}:
            return
        pid = int(job.get("pid") or 0)
        if pid and _pid_is_running(pid):
            job["status"] = "running"
        else:
            job["status"] = "unknown_finished"
            job["ended_at"] = job.get("ended_at") or _now()

    def _mcp_jobs_dir(self) -> Path:
        path = self.paths.root / "mcp-jobs"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _mcp_job_index_path(self) -> Path:
        return self._mcp_jobs_dir() / MCP_JOB_INDEX

    def _load_mcp_job_index(self) -> dict[str, dict[str, Any]]:
        path = self.paths.root / "mcp-jobs" / MCP_JOB_INDEX
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        jobs = data.get("jobs") if isinstance(data, dict) else data
        if not isinstance(jobs, list):
            return {}
        return {str(job["mcp_job_id"]): dict(job) for job in jobs if isinstance(job, dict) and job.get("mcp_job_id")}

    def _save_mcp_job_index(self) -> None:
        path = self._mcp_job_index_path()
        rows = [_public_job(job) for job in self._mcp_jobs.values()]
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"jobs": rows}, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)

    def _require_permission(self, permission: str) -> None:
        if permission == "processing" and not self.allow_processing:
            raise ValueError("Tool requires MCP server startup flag: --allow-processing")
        if permission == "sensitive" and not self.allow_sensitive:
            raise ValueError("Tool requires MCP server startup flag: --allow-sensitive")
        if permission == "external_ai" and not self.allow_external_ai:
            raise ValueError("Tool requires MCP server startup flag: --allow-external-ai")

    def _permissions(self) -> dict[str, bool]:
        return {
            "read_only": True,
            "processing": self.allow_processing,
            "sensitive": self.allow_sensitive,
            "external_ai": self.allow_external_ai,
        }

    @staticmethod
    def _response(request_id: object, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: object, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


def run_mcp_server(
    *,
    root: Path,
    allow_processing: bool = False,
    allow_sensitive: bool = False,
    allow_external_ai: bool = False,
    plugin_paths: list[Path] | None = None,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
) -> int:
    server = RelicMcpServer(
        root=root,
        allow_processing=allow_processing,
        allow_sensitive=allow_sensitive,
        allow_external_ai=allow_external_ai,
        plugin_paths=plugin_paths,
    )
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
            responses = []
            if isinstance(message, list):
                responses = [response for item in message if (response := server.handle_message(item)) is not None]
            else:
                response = server.handle_message(message)
                responses = [] if response is None else [response]
            if not responses:
                continue
            payload: dict[str, Any] | list[dict[str, Any]] = responses if isinstance(message, list) else responses[0]
            stdout.write(json.dumps(payload, default=str, separators=(",", ":")) + "\n")
            stdout.flush()
        except json.JSONDecodeError as exc:
            stdout.write(json.dumps(RelicMcpServer._error(None, -32700, "Parse error", str(exc)), separators=(",", ":")) + "\n")
            stdout.flush()
    return 0


def _tool_result(result: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}],
        "structuredContent": result,
        "isError": is_error,
    }


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in job.items() if key != "process"}


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_tail(path: Path, max_bytes: int) -> str:
    if not path.exists() or not path.is_file():
        return ""
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > max_bytes:
            handle.seek(-max_bytes, os.SEEK_END)
        return handle.read(max_bytes).decode("utf-8", errors="replace")


def _object_schema(properties: dict[str, Any], *, required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


def _case_limit_schema(*, default: int) -> dict[str, Any]:
    return _object_schema(
        {
            "case_id": _string_schema("Relic case ID."),
            "limit": _integer_schema("Maximum rows to return.", default=default, minimum=1, maximum=1000),
        },
        required=["case_id"],
    )


def _user_contains_schema(*, default: int) -> dict[str, Any]:
    return _object_schema(
        {
            "case_id": _string_schema("Relic case ID."),
            "limit": _integer_schema("Maximum rows to return.", default=default, minimum=1, maximum=1000),
            "user": _string_schema("Optional user/profile filter."),
            "contains": _string_schema("Optional text filter."),
        },
        required=["case_id"],
    )


def _string_schema(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def _integer_schema(description: str, *, default: int, minimum: int, maximum: int) -> dict[str, Any]:
    return {"type": "integer", "description": description, "default": default, "minimum": minimum, "maximum": maximum}


def _required(arguments: dict[str, Any], key: str) -> str:
    value = str(arguments.get(key) or "").strip()
    if not value:
        raise ValueError(f"Missing required argument: {key}")
    return value


def _optional_text(arguments: dict[str, Any], key: str) -> str | None:
    value = str(arguments.get(key) or "").strip()
    return value or None


def _limit(arguments: dict[str, Any], *, default: int) -> int:
    try:
        limit = int(arguments.get("limit") or default)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer")
    return max(1, min(limit, 1000))


def _bounded_int(arguments: dict[str, Any], key: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(arguments.get(key) or default)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be an integer")
    return max(minimum, min(value, maximum))


def _count_table(db: Database, table: str) -> int:
    row = db.conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
    return int(row["count"] if row else 0)


def _enforce_uncompressed_limit(report: dict[str, Any], max_uncompressed_gb: float) -> None:
    if max_uncompressed_gb <= 0:
        return
    summary = report.get("summary") or {}
    uncompressed = int(summary.get("uncompressed_size") or summary.get("uncompressed_bytes") or 0)
    if uncompressed <= 0:
        return
    limit = int(max_uncompressed_gb * 1024 * 1024 * 1024)
    if uncompressed > limit:
        raise ValueError(f"ZIP uncompressed size {uncompressed} exceeds MCP limit {limit}")


def _workspace_path(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError(f"MCP output paths must stay under workspace root: {root_resolved}")
    return resolved


def _resource_candidates(root: Path, *, case_id: str | None = None, kind: str | None = None) -> list[Path]:
    candidates: list[Path] = []
    if not root.exists():
        return candidates
    case_glob = _safe_resource_case_glob(case_id)
    kind_patterns = {
        "report": (f"cases/{case_glob}/reports/**/*", f"cases/{case_glob}/outputs/reports/**/*"),
        "manifest": (f"cases/{case_glob}/outputs/**/*manifest*.json", f"cases/{case_glob}/outputs/**/*manifest*.csv"),
        "log": (f"cases/{case_glob}/logs/**/*",),
        "mcp-job": ("mcp-jobs/**/*",),
    }
    if kind:
        if kind not in kind_patterns:
            raise ValueError(f"Unsupported resource kind: {kind}")
        patterns = kind_patterns[kind]
    else:
        patterns = tuple(pattern for values in kind_patterns.values() for pattern in values)
    for pattern in patterns:
        for path in root.glob(pattern):
            if path.is_file() and _is_text_resource(path):
                candidates.append(path)
    candidates.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    return candidates


def _safe_resource_case_glob(case_id: str | None) -> str:
    if not case_id:
        return "*"
    if case_id in {".", ".."} or any(char in case_id for char in "\\/[]{}*?"):
        raise ValueError("case_id is not a valid resource filter")
    return case_id


def _resource_uris_for_path(root: Path, path: Path) -> list[str]:
    if not path.exists():
        return []
    if path.is_file():
        files = [path]
    else:
        files = [item for item in path.rglob("*") if item.is_file()]
    uris = []
    root_resolved = root.resolve()
    for file_path in files:
        if not _is_text_resource(file_path):
            continue
        resolved = file_path.resolve()
        if resolved != root_resolved and root_resolved not in resolved.parents:
            continue
        uris.append(_resource_uri(resolved.relative_to(root_resolved)))
    return sorted(uris)


def _is_text_resource(path: Path) -> bool:
    if path.name == MCP_JOB_INDEX:
        return True
    return path.suffix.casefold() in {".txt", ".md", ".json", ".jsonl", ".csv", ".tsv", ".log", ".html", ".htm", ".xml"}


def _resource_uri(relative: Path) -> str:
    return "relic://workspace/" + quote(str(relative).replace("\\", "/"), safe="/")


def _path_from_resource_uri(root: Path, uri: str) -> Path:
    prefix = "relic://workspace/"
    if not uri.startswith(prefix):
        raise ValueError(f"Unsupported resource URI: {uri}")
    relative = unquote(uri[len(prefix):])
    return _workspace_path(root, relative)


def _extend_optional(command: list[str], option: str, value: object) -> None:
    text = str(value or "").strip()
    if text:
        command.extend([option, text])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summarize_path(value: object) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text if len(text) <= 500 else "..." + text[-497:]


def _case_rows(db: Database, limit: int) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT c.id, c.root, c.created_at,
               COUNT(DISTINCT computers.id) AS computer_count,
               COUNT(DISTINCT images.id) AS image_count,
               COUNT(DISTINCT jobs.id) AS job_count
        FROM cases c
        LEFT JOIN computers ON computers.case_id = c.id
        LEFT JOIN images ON images.case_id = c.id
        LEFT JOIN jobs ON jobs.case_id = c.id
        GROUP BY c.id, c.root, c.created_at
        ORDER BY c.created_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def _json_value(value: Any, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except Exception:
        return default


def _package_version() -> str:
    try:
        return version("forensic-orchestrator")
    except PackageNotFoundError:
        return "0.1.0"
