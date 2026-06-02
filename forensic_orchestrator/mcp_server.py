from __future__ import annotations

import json
import mimetypes
import os
import re
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
from .report_bundle import parser_coverage_report, progress_manifest_report, report_bundle_preflight_report
from .reports import (
    artifact_lead_search_report,
    artifact_search_report,
    artifact_search_source_inventory_report,
    browser_activity_report,
    case_activity_digest_report,
    case_next_actions_report,
    case_review_report,
    case_dashboard_report,
    case_summary_report,
    cloud_artifacts_report,
    communications_report,
    external_storage_report,
    evidence_gaps_report,
    file_movement_identity_report,
    file_dossier_report,
    filesystem_listing_report,
    memory_analysis_report,
    memory_artifacts_report,
    opened_from_cloud_storage_report,
    opened_from_removable_media_report,
    processing_progress_report,
    registry_activity_report,
    rerun_search_packet_report,
    search_packet_metadata,
    resume_plan_report,
    processing_readiness_report,
    shortcuts_report,
    suspicious_executions_report,
    timeline_report,
    timeline_review_report,
    unmapped_imports_report,
    usb_file_correlation_report,
    usb_dossier_report,
    user_activity_report,
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
MCP_POLICY_FILE = "mcp-policy.json"
MCP_RESOURCE_MAX_BYTES = 1_000_000
SENSITIVE_ARGUMENT_KEYS = {
    "password",
    "passphrase",
    "recovery_key",
    "token",
    "api_key",
    "secret",
    "credential",
    "credentials",
}


@dataclass(frozen=True)
class McpTool:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    annotations: dict[str, Any]
    permission: str = "read"
    category: str = ""
    tags: tuple[str, ...] = ()
    output_type: str = "object"
    version: str = "1.0"
    examples: tuple[dict[str, Any], ...] = ()
    dependencies: tuple[str, ...] = ()
    source_priority: tuple[str, ...] = ()

    def definition(self) -> dict[str, Any]:
        metadata = self.metadata()
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations,
            "metadata": metadata,
        }

    def metadata(self) -> dict[str, Any]:
        return _tool_metadata(self)


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
        self.policy = self._load_mcp_policy()
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
                return self._response(request_id, self._call_tool(message.get("params") or {}, request_id=request_id))
            return self._error(request_id, -32601, f"Method not found: {method}")
        except ValueError as exc:
            return self._error(request_id, -32602, str(exc), _error_details(exc))
        except Exception as exc:  # pragma: no cover - defensive protocol boundary
            return self._error(request_id, -32603, str(exc), _error_details(exc))

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
                "For broad questions, call relic_route_question first to classify the request and receive the source-of-truth order. "
                "For report-backed questions, call relic_read_existing_report or relic_discover_reports first and treat generated reports "
                "as the source of truth before querying raw artifacts or starting processing. "
                "For questions phrased as evidence contents, drive contents, files on a volume, or list files, call "
                "relic_query_evidence_contents; do not start filesystem processing, mounts, or SleuthKit/FLS unless stored "
                "listings are absent, stale, or the user explicitly requests new processing. "
                "For filesystem/file-listing questions, call relic_query_filesystem_listings first because it reads generated "
                "case file listings and avoids slow image tooling. "
                "Import and processing calls require --allow-processing. Sensitive credential reveal, external AI upload, "
                "and destructive actions are not implemented in the default MCP surface."
            ),
        }

    def _call_tool(self, params: dict[str, Any], *, request_id: object | None = None) -> dict[str, Any]:
        name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise ValueError("tools/call arguments must be an object")
        tool = self.tools.get(name)
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")
        correlation_id = str(uuid.uuid4())
        started = datetime.now(timezone.utc)
        self._require_permission(tool.permission)
        self._require_policy(tool, arguments)
        try:
            result = tool.handler(arguments)
            duration_ms = _duration_ms(started)
            self._audit_tool_call(tool, arguments, status="ok", error=None, correlation_id=correlation_id, request_id=request_id, duration_ms=duration_ms)
            return _tool_result(result, tool=tool, correlation_id=correlation_id, duration_ms=duration_ms)
        except Exception as exc:
            duration_ms = _duration_ms(started)
            self._audit_tool_call(tool, arguments, status="error", error=str(exc), correlation_id=correlation_id, request_id=request_id, duration_ms=duration_ms)
            return _tool_result(_tool_error_payload(tool, exc, correlation_id=correlation_id), is_error=True, tool=tool, correlation_id=correlation_id, duration_ms=duration_ms)

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
                name="relic_case_evidence_map",
                title="Relic Case Evidence Map",
                description="Return case computers, images, report resources, memory sources, jobs, and processing state in one response.",
                input_schema=_case_limit_schema(default=100),
                handler=self.case_evidence_map,
                annotations=read_only,
            ),
            McpTool(
                name="relic_workspace_map",
                title="Relic Workspace Map",
                description="Return cases, computers, images, reports, progress manifests, MCP packets, and active jobs in one structure.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Optional case ID to scope the map."),
                        "limit": _integer_schema("Maximum rows per section.", default=100, minimum=1, maximum=1000),
                    }
                ),
                handler=self.workspace_map,
                annotations=read_only,
            ),
            McpTool(
                name="relic_mcp_workflow_guide",
                title="Relic MCP Workflow Guide",
                description="Return the recommended MCP workflow for case review, lead searches, drilldowns, packets, and exports.",
                input_schema=_object_schema({}),
                handler=self.mcp_workflow_guide,
                annotations=read_only,
            ),
            McpTool(
                name="relic_route_question",
                title="Relic Route Question",
                description=(
                    "Classify an examiner question and return the correct Relic source-of-truth order. "
                    "Use this before answering broad MCP questions, especially filesystem, USB, report, memory, "
                    "timeline, processing, recovery, credential, or external-AI requests."
                ),
                input_schema=_object_schema(
                    {
                        "question": _string_schema("Natural-language examiner question to route."),
                        "case_id": _string_schema("Optional Relic case ID for report candidate discovery."),
                        "evidence_hint": _string_schema("Optional evidence, image, device, drive, volume, or computer hint."),
                        "allow_processing": {"type": "boolean", "default": False},
                    },
                    required=["question"],
                ),
                handler=self.route_question,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_readiness",
                title="Relic Case Readiness",
                description="Return MCP-friendly doctor, workspace health, processing readiness, progress, and resume signals.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Optional Relic case ID."),
                        "profile": _string_schema("Optional profile name."),
                        "limit": _integer_schema("Maximum rows to return.", default=50, minimum=1, maximum=1000),
                        "smoke": {"type": "boolean", "default": False},
                    }
                ),
                handler=self.case_readiness,
                annotations=read_only,
            ),
            McpTool(
                name="relic_discover_reports",
                title="Relic Discover Reports",
                description="Discover existing report bundle files and resource URIs for a case. Use this before raw artifact queries or report generation.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "purpose": {"type": "string", "enum": ["full", "usb", "cloud", "execution", "memory", "triage", "review"], "default": "full"},
                        "limit": _integer_schema("Maximum resources to return.", default=250, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.discover_reports,
                annotations=read_only,
            ),
            McpTool(
                name="relic_discover_report_exports",
                title="Relic Discover Report Exports",
                description="Discover existing report bundle exports by purpose and report-index tags. Use this before raw artifact queries or report generation.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "purpose": {"type": "string", "enum": ["full", "usb", "cloud", "execution", "memory", "triage", "review"], "default": "full"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "limit": _integer_schema("Maximum resources to return.", default=250, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.discover_report_exports,
                annotations=read_only,
            ),
            McpTool(
                name="relic_read_existing_report",
                title="Read Existing Relic Report",
                description=(
                    "Find and read an existing generated report for a case by report name, purpose, tag, or text. "
                    "This is the first source of truth for report-backed MCP questions."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "report_name": _string_schema("Optional report name or filename stem, for example usb-files or opened-from-removable-media."),
                        "purpose": {"type": "string", "enum": ["full", "usb", "cloud", "execution", "memory", "triage", "review"], "default": "full"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "contains": _string_schema("Optional text that must appear in the report contents."),
                        "max_bytes": _integer_schema("Maximum report bytes to read.", default=200000, minimum=1000, maximum=MCP_RESOURCE_MAX_BYTES),
                    },
                    required=["case_id"],
                ),
                handler=self.read_existing_report,
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
                name="relic_timeline_window",
                title="Relic Timeline Window",
                description="Return a focused timeline review window for a case.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "limit": _integer_schema("Maximum events to return.", default=100, minimum=1, maximum=1000),
                        "user": _string_schema("Optional user/profile filter."),
                        "contains": _string_schema("Optional text filter."),
                        "source": _string_schema("Optional source filter."),
                        "preset": _string_schema("Optional timeline preset."),
                    },
                    required=["case_id"],
                ),
                handler=self.timeline_window,
                annotations=read_only,
            ),
            McpTool(
                name="relic_file_dossier",
                title="Relic File Dossier",
                description="Return a file-centric dossier by path or name. For broad filesystem listings, use relic_query_filesystem_listings first.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "path": _string_schema("Optional full or partial path."),
                        "name": _string_schema("Optional file name."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.file_dossier,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_filesystem_listings",
                title="Query Filesystem Listings",
                description=(
                    "Return generated file listings from filesystem_entries. This is the first source of truth for "
                    "filesystem questions and should be used before any live image, mount, or SleuthKit processing."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "contains": _string_schema("Optional text filter for path, file name, parent path, or extension."),
                        "computer_id": _string_schema("Optional computer ID filter."),
                        "image_id": _string_schema("Optional image ID filter."),
                        "scan_status": _string_schema("Optional scan status filter, for example live, deleted, system, ok, virtual, or error."),
                        "include_deleted": {"type": "boolean", "default": True},
                        "include_virtual": {"type": "boolean", "default": False},
                        "limit": _integer_schema("Maximum rows to return.", default=250, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.query_filesystem_listings,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_evidence_contents",
                title="Query Evidence Contents",
                description=(
                    "Return file contents/listings for any evidence image, drive, volume, or filesystem from stored filesystem_entries only. "
                    "Use this for questions like 'pull a list of contents' before any FLS, SleuthKit, mount, or image processing."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "contains": _string_schema("Optional text filter for path, file name, parent path, or extension."),
                        "computer_id": _string_schema("Optional computer ID filter."),
                        "image_id": _string_schema("Optional image ID filter. Use this when the target evidence image is known."),
                        "scan_status": _string_schema("Optional scan status filter, for example live, deleted, system, ok, virtual, or error."),
                        "include_deleted": {"type": "boolean", "default": True},
                        "include_virtual": {"type": "boolean", "default": False},
                        "limit": _integer_schema("Maximum rows to return.", default=500, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.query_evidence_contents,
                annotations=read_only,
            ),
            McpTool(
                name="relic_usb_dossier",
                title="Relic USB Dossier",
                description="Return a USB/storage-device dossier by serial, volume serial, or volume GUID.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "serial": _string_schema("Optional USB serial."),
                        "volume_serial_number": _string_schema("Optional volume serial number."),
                        "volume_guid": _string_schema("Optional volume GUID."),
                        "limit": _integer_schema("Maximum rows to return.", default=250, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.usb_dossier,
                annotations=read_only,
            ),
            McpTool(
                name="relic_user_activity",
                title="Relic User Activity",
                description="Return user-focused execution, file, browser, logon, communication, and USB activity.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "user": _string_schema("User/profile text to review."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                    },
                    required=["case_id", "user"],
                ),
                handler=self.user_activity,
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
                name="relic_search_artifacts",
                title="Relic Artifact Search",
                description=(
                    "Search parsed artifact tables by text, user, computer, source type, and time bounds without requiring OpenSearch. "
                    "Use relic_route_question and existing reports first for broad review questions; for filesystem questions, use "
                    "relic_query_filesystem_listings first."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "query": _string_schema("Optional text to find in searchable artifact fields."),
                        "user": _string_schema("Optional user/profile filter."),
                        "computer": _string_schema("Optional computer label or ID filter."),
                        "source_type": _string_schema("Optional artifact category or table name."),
                        "start": _string_schema("Optional inclusive timestamp lower bound."),
                        "end": _string_schema("Optional inclusive timestamp upper bound."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.search_artifacts,
                annotations=read_only,
            ),
            McpTool(
                name="relic_artifact_search_sources",
                title="Relic Artifact Search Sources",
                description="Return the artifact tables, categories, fields, and row counts covered by artifact and lead search.",
                input_schema=_object_schema({"case_id": _string_schema("Relic case ID.")}, required=["case_id"]),
                handler=self.artifact_search_sources,
                annotations=read_only,
            ),
            McpTool(
                name="relic_lead_search",
                title="Relic Lead Search",
                description=(
                    "Run preset artifact searches for execution, USB, cloud, documents, browser, or communications leads. "
                    "Use relic_route_question and existing reports first for broad review questions."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "preset": {"type": "string", "enum": ["execution", "usb", "cloud", "documents", "browser", "communications"]},
                        "query": _string_schema("Optional text to find in preset artifact fields."),
                        "user": _string_schema("Optional user/profile filter."),
                        "computer": _string_schema("Optional computer label or ID filter."),
                        "start": _string_schema("Optional inclusive timestamp lower bound."),
                        "end": _string_schema("Optional inclusive timestamp upper bound."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                    },
                    required=["case_id", "preset"],
                ),
                handler=self.lead_search,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_activity_digest",
                title="Relic Case Activity Digest",
                description="Return a compact digest of recent activity, suspicious execution, storage, cloud/removable opens, gaps, and next actions.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_activity_digest,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_next_actions",
                title="Relic Case Next Actions",
                description="Return ranked next investigative actions from readiness, gaps, unmapped imports, suspicious execution, USB, and cloud findings.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_next_actions,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_runbook",
                title="Relic Case Runbook",
                description="Return safe next commands and reasons based on review status, readiness, packets, reports, and gaps.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_runbook,
                annotations=read_only,
            ),
            McpTool(
                name="relic_write_review_packet",
                title="Write Relic Review Packet",
                description="Write a small MCP review packet with selected findings, report URIs, timeline slices, and examiner notes.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "title": _string_schema("Optional packet title."),
                        "notes": _string_schema("Optional examiner notes."),
                        "findings": {"type": "array", "items": {"type": "object"}},
                        "report_uris": {"type": "array", "items": {"type": "string"}},
                        "timeline": {"type": "array", "items": {"type": "object"}},
                    },
                    required=["case_id"],
                ),
                handler=self.write_review_packet,
                annotations=safe_write,
                permission="safe_write",
            ),
            McpTool(
                name="relic_list_review_packets",
                title="List Relic Review Packets",
                description="List MCP review packets previously written for a case.",
                input_schema=_case_limit_schema(default=50),
                handler=self.list_review_packets,
                annotations=read_only,
            ),
            McpTool(
                name="relic_read_review_packet",
                title="Read Relic Review Packet",
                description="Read a saved MCP review packet JSON or Markdown resource.",
                input_schema=_object_schema({"uri": _string_schema("Review packet resource URI.")}, required=["uri"]),
                handler=self.read_review_packet,
                annotations=read_only,
            ),
            McpTool(
                name="relic_write_search_packet",
                title="Write Relic Search Packet",
                description="Run and save an artifact or preset lead search packet with filters and result counts.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "title": _string_schema("Optional packet title."),
                        "preset": {"type": "string", "enum": ["execution", "usb", "cloud", "documents", "browser", "communications"]},
                        "query": _string_schema("Optional search text."),
                        "user": _string_schema("Optional user/profile filter."),
                        "computer": _string_schema("Optional computer label or ID filter."),
                        "source_type": _string_schema("Optional artifact category or table name for general artifact search."),
                        "start": _string_schema("Optional inclusive timestamp lower bound."),
                        "end": _string_schema("Optional inclusive timestamp upper bound."),
                        "limit": _integer_schema("Maximum rows to save.", default=100, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.write_search_packet,
                annotations=safe_write,
                permission="safe_write",
            ),
            McpTool(
                name="relic_list_search_packets",
                title="List Relic Search Packets",
                description="List MCP search packets previously written for a case.",
                input_schema=_case_limit_schema(default=50),
                handler=self.list_search_packets,
                annotations=read_only,
            ),
            McpTool(
                name="relic_read_search_packet",
                title="Read Relic Search Packet",
                description="Read a saved MCP search packet JSON or Markdown resource.",
                input_schema=_object_schema({"uri": _string_schema("Search packet resource URI.")}, required=["uri"]),
                handler=self.read_search_packet,
                annotations=read_only,
            ),
            McpTool(
                name="relic_rerun_search_packet",
                title="Rerun Relic Search Packet",
                description="Rerun a saved MCP search packet and compare added, removed, changed, and unchanged result IDs.",
                input_schema=_object_schema(
                    {
                        "uri": _string_schema("Search packet JSON resource URI."),
                        "limit": _integer_schema("Optional rerun limit override.", default=100, minimum=1, maximum=1000),
                    },
                    required=["uri"],
                ),
                handler=self.rerun_search_packet,
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
                description="Return an existing generated report when available; regenerate through the Relic CLI only when regenerate=true or no matching report exists.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "report_name": _string_schema("Supported report name."),
                        "format": {"type": "string", "enum": ["json", "table", "csv", "md"], "default": "json"},
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                        "output": _string_schema("Optional output path. Must be under the workspace root."),
                        "regenerate": {"type": "boolean", "default": False},
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
                        "purpose": {"type": "string", "enum": ["full", "usb", "cloud", "execution", "memory", "triage", "review"], "default": "full"},
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
                name="relic_get_mcp_job_progress",
                title="Get Relic MCP Job Progress",
                description="Return structured progress signals parsed from MCP-launched job output.",
                input_schema=_object_schema(
                    {
                        "mcp_job_id": _string_schema("MCP job ID returned by a processing tool."),
                        "max_bytes": _integer_schema("Maximum bytes to scan from stderr/stdout.", default=50000, minimum=1000, maximum=200000),
                    },
                    required=["mcp_job_id"],
                ),
                handler=self.get_mcp_job_progress,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_progress_manifests",
                title="List Relic Progress Manifests",
                description="List live report-bundle/import progress manifests under the workspace progress directory.",
                input_schema=_object_schema(
                    {
                        "limit": _integer_schema("Maximum manifests to return.", default=50, minimum=1, maximum=1000),
                        "path": _string_schema("Optional specific progress manifest path."),
                    }
                ),
                handler=self.list_progress_manifests,
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
                description=(
                    "Start a gated bulk live-case/report ZIP import as a background MCP job. Do not use this to answer review "
                    "questions when existing reports or parsed artifacts can answer them."
                ),
                input_schema=_object_schema(
                    {
                        "path": _string_schema("Path to the live-case/report ZIP or folder."),
                        "case_id": _string_schema("Optional existing case ID."),
                        "accept_duplicate": {"type": "boolean", "default": False},
                        "no_progress": {"type": "boolean", "default": False},
                        "write_reports": {"type": "boolean", "default": True},
                        "report_purpose": {"type": "string", "enum": ["full", "usb", "cloud", "execution", "memory", "triage"], "default": "triage"},
                        "report_output_dir": _string_schema("Optional report output directory under the workspace root."),
                        "progress_manifest": _string_schema("Optional live progress JSON path under the workspace root."),
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
                description=(
                    "Start a gated single-computer report bundle import as a background MCP job. Do not use this to answer review "
                    "questions when existing reports or parsed artifacts can answer them."
                ),
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
                description=(
                    "Start a gated image processing run as a background MCP job only when the user explicitly asks to process or "
                    "reprocess evidence. Do not use this for read-only questions; use existing reports and parsed artifact tables first."
                ),
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
                description=(
                    "Start a gated profile run against an existing case image as a background MCP job only when the user explicitly "
                    "asks to run processing. Do not use this for read-only questions; use existing reports and parsed artifact tables first."
                ),
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
            McpTool(
                name="relic_recover_deleted_files",
                title="Recover Deleted Files",
                description=(
                    "Start a gated deleted-file recovery job from parsed filesystem_entries and mft_entries. Use only when the user "
                    "explicitly asks to recover deleted files; normal contents questions should use existing reports and listings first."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Relic case ID."),
                        "image_id": _string_schema("Optional image ID filter."),
                        "contains": _string_schema("Optional text filter for path or file name."),
                        "name": _string_schema("Optional exact file name filter."),
                        "source": {"type": "string", "enum": ["all", "filesystem_entries", "mft_entries"], "default": "all"},
                        "limit": _integer_schema("Maximum deleted files to recover.", default=100, minimum=1, maximum=1000),
                        "max_bytes": _integer_schema("Optional maximum source file size to recover.", default=0, minimum=0, maximum=10_000_000_000),
                        "output_dir": _string_schema("Optional output directory under the workspace root."),
                    },
                    required=["case_id"],
                ),
                handler=self.recover_deleted_files,
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
            metadata = _resource_metadata(root_resolved, resolved, case_id=case_id, kind=kind)
            resources.append(
                {
                    "uri": _resource_uri(relative),
                    "name": str(relative),
                    "title": resolved.name,
                    "mimeType": mime_type,
                    "description": metadata["description"],
                    **metadata,
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

    def case_evidence_map(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        limit = _limit(arguments, default=100)
        db = self._db()
        try:
            case = db.get_case(case_id)
            computers = [
                dict(row)
                for row in db.conn.execute(
                    "SELECT id, label, hostname, notes, created_at FROM computers WHERE case_id = ? ORDER BY label, created_at",
                    (case_id,),
                ).fetchall()
            ]
            images = [
                dict(row)
                for row in db.conn.execute(
                    """
                    SELECT images.id, images.computer_id, computers.label AS computer_label,
                           images.path, images.created_at
                    FROM images
                    LEFT JOIN computers ON computers.id = images.computer_id
                    WHERE images.case_id = ?
                    ORDER BY computers.label, images.created_at
                    """,
                    (case_id,),
                ).fetchall()
            ]
            for image in images:
                image["metadata"] = [
                    dict(row)
                    for row in db.conn.execute(
                        """
                        SELECT source, key, value
                        FROM image_metadata
                        WHERE case_id = ? AND image_id = ?
                        ORDER BY source, key
                        LIMIT ?
                        """,
                        (case_id, image["id"], limit),
                    ).fetchall()
                ]
            jobs = job_status_report(db, case_id=case_id, limit=limit)
            progress = processing_progress_report(db, case_id, limit=min(limit, 100))
            memory_sources = _memory_source_rows(db, case_id, limit=limit)
            report_resources = _case_report_resources(self.paths.root, case_id, purpose=None, limit=limit)
            return {
                "case_id": case_id,
                "case": {"id": case.id, "root": str(case.root), "created_at": case.created_at},
                "summary": {
                    "computer_count": len(computers),
                    "image_count": len(images),
                    "job_count_returned": len(jobs.get("jobs") or []),
                    "report_resource_count": len(report_resources),
                    "memory_source_count": len(memory_sources),
                    "active_timing_count": (progress.get("summary") or {}).get("active_timing_count", 0),
                    "failed_timing_count": (progress.get("summary") or {}).get("failed_timing_count", 0),
                },
                "computers": computers,
                "images": images,
                "jobs": jobs,
                "processing": progress,
                "memory_sources": memory_sources,
                "report_resources": report_resources,
            }
        finally:
            db.close()

    def workspace_map(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = _limit(arguments, default=100)
        case_filter = _optional_text(arguments, "case_id")
        db = self._db()
        try:
            cases = [dict(row) for row in db.conn.execute("SELECT id, root, created_at FROM cases ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]
            if case_filter:
                cases = [row for row in cases if row.get("id") == case_filter]
            case_maps = []
            for case in cases[:limit]:
                case_id = str(case["id"])
                computers = [dict(row) for row in db.conn.execute("SELECT id, label, notes, created_at FROM computers WHERE case_id = ? ORDER BY label LIMIT ?", (case_id, limit)).fetchall()]
                images = [dict(row) for row in db.conn.execute("SELECT id, computer_id, path, created_at FROM images WHERE case_id = ? ORDER BY created_at DESC LIMIT ?", (case_id, limit)).fetchall()]
                reports = _case_report_resources(self.paths.root, case_id, purpose=None, limit=limit)
                packets = _case_packet_resources(self.paths.root, case_id, limit=limit)
                jobs = job_status_report(db, case_id=case_id, limit=limit)
                case_maps.append(
                    {
                        "case": case,
                        "computers": computers,
                        "images": images,
                        "reports": reports,
                        "packets": packets,
                        "jobs": jobs.get("jobs") or [],
                    }
                )
            progress = progress_manifest_report(self.paths.root, limit=limit)
            mcp_jobs = self.list_mcp_jobs({"limit": limit})
            return {
                "workspace_root": str(self.paths.root),
                "summary": {
                    "case_count": len(case_maps),
                    "progress_manifest_count": (progress.get("summary") or {}).get("manifest_count", 0),
                    "mcp_job_count": len(mcp_jobs.get("jobs") or []),
                },
                "cases": case_maps,
                "progress_manifests": progress.get("manifests") or [],
                "mcp_jobs": mcp_jobs.get("jobs") or [],
            }
        finally:
            db.close()

    def mcp_workflow_guide(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return _mcp_workflow_guide()

    def route_question(self, arguments: dict[str, Any]) -> dict[str, Any]:
        question = _required(arguments, "question")
        case_id = _optional_text(arguments, "case_id")
        evidence_hint = _optional_text(arguments, "evidence_hint")
        allow_processing = bool(arguments.get("allow_processing") or False)
        route = _route_mcp_question(
            question,
            case_id=case_id,
            evidence_hint=evidence_hint,
            allow_processing=allow_processing,
            server_allows_processing=self.allow_processing,
            server_allows_sensitive=self.allow_sensitive,
            server_allows_external_ai=self.allow_external_ai,
        )
        if case_id and route.get("report_names"):
            resources: list[dict[str, Any]] = []
            for report_name in route["report_names"][:8]:
                resources.extend(
                    _matching_report_resources(
                        self.paths.root,
                        case_id,
                        purpose=str(route.get("report_purpose") or "full"),
                        report_name=str(report_name),
                        tags=[],
                        contains=None,
                        max_bytes=200_000,
                        limit=50,
                    )[:3]
                )
            route["report_candidates"] = _dedupe_resource_rows(resources)[:10]
        else:
            route["report_candidates"] = []
        return route

    def case_readiness(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = str(arguments.get("case_id") or "").strip() or None
        profile = str(arguments.get("profile") or "").strip() or None
        limit = _limit(arguments, default=50)
        db = self._db()
        try:
            doctor = doctor_report(
                db,
                self.paths,
                self._registry(),
                case_id=case_id,
                profile=profile,
                smoke=bool(arguments.get("smoke") or False),
                repair=False,
            )
            health = workspace_health_report(db, case_id, min_free_gb=10.0)
            readiness = processing_readiness_report(db, case_id, limit=limit, profile=profile) if case_id else None
            progress = processing_progress_report(db, case_id, limit=limit) if case_id else None
            resume = resume_plan_report(db, case_id, limit=limit) if case_id else None
            failed_checks = [row for row in doctor.get("checks", []) if not row.get("passed")]
            decisions = (resume or {}).get("decisions") or []
            return {
                "case_id": case_id,
                "profile": profile,
                "ready": bool(doctor.get("passed")) and not _has_required_action(readiness) and not failed_checks,
                "summary": {
                    "doctor_passed": bool(doctor.get("passed")),
                    "failed_check_count": len(failed_checks),
                    "required_needs_action_count": ((readiness or {}).get("summary") or {}).get("required_needs_action_count", 0),
                    "active_timing_count": ((progress or {}).get("summary") or {}).get("active_timing_count", 0),
                    "failed_timing_count": ((progress or {}).get("summary") or {}).get("failed_timing_count", 0),
                    "resume_decision_count": len(decisions),
                },
                "doctor": doctor,
                "workspace_health": health,
                "processing_readiness": readiness,
                "processing_progress": progress,
                "resume_plan": resume,
            }
        finally:
            db.close()

    def discover_reports(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        purpose = str(arguments.get("purpose") or "full")
        if purpose not in {"full", "usb", "cloud", "execution", "memory", "triage", "review"}:
            raise ValueError("purpose must be one of: full, usb, cloud, execution, memory, triage, review")
        limit = _limit(arguments, default=250)
        resources = _case_report_resources(self.paths.root, case_id, purpose=purpose, limit=limit)
        indexes = [item for item in resources if Path(str(item.get("relative_path") or "")).name in {"index.md", "report-index.json"}]
        return {
            "case_id": case_id,
            "purpose": purpose,
            "summary": {
                "resource_count": len(resources),
                "index_count": len(indexes),
                "expected_report_names": sorted(_expected_report_names(purpose)),
            },
            "resources": resources,
            "indexes": indexes,
        }

    def discover_report_exports(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        purpose = str(arguments.get("purpose") or "full")
        if purpose not in {"full", "usb", "cloud", "execution", "memory", "triage", "review"}:
            raise ValueError("purpose must be one of: full, usb, cloud, execution, memory, triage, review")
        requested_tags = _string_list(arguments.get("tags"))
        resources = _case_report_resources(self.paths.root, case_id, purpose=purpose, limit=_limit(arguments, default=250))
        if requested_tags:
            wanted = {tag.casefold() for tag in requested_tags}
            resources = [
                row
                for row in resources
                if wanted <= {str(tag).casefold() for tag in (row.get("tags") or [])}
            ]
        return {
            "case_id": case_id,
            "purpose": purpose,
            "tags": requested_tags,
            "summary": {"resource_count": len(resources), "tag_count": len(requested_tags)},
            "resources": resources,
        }

    def read_existing_report(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        purpose = str(arguments.get("purpose") or "full")
        if purpose not in {"full", "usb", "cloud", "execution", "memory", "triage", "review"}:
            raise ValueError("purpose must be one of: full, usb, cloud, execution, memory, triage, review")
        max_bytes = _bounded_int(arguments, "max_bytes", default=200_000, minimum=1_000, maximum=MCP_RESOURCE_MAX_BYTES)
        resources = _matching_report_resources(
            self.paths.root,
            case_id,
            purpose=purpose,
            report_name=_optional_text(arguments, "report_name"),
            tags=_string_list(arguments.get("tags")),
            contains=_optional_text(arguments, "contains"),
            max_bytes=max_bytes,
            limit=250,
        )
        if not resources:
            return {
                "case_id": case_id,
                "source_of_truth": "existing_reports",
                "matched": False,
                "summary": {"matching_report_count": 0},
                "guidance": "No existing generated report matched. Use raw artifact tools or regenerate only if the existing reports are absent or stale.",
                "available_reports": _case_report_resources(self.paths.root, case_id, purpose=purpose, limit=50),
            }
        selected = resources[0]
        path = _path_from_resource_uri(self.paths.root, str(selected["uri"]))
        size = path.stat().st_size
        if size > max_bytes:
            raise ValueError(f"Report exceeds MCP read limit ({size} > {max_bytes} bytes): {selected['uri']}")
        text = path.read_text(encoding="utf-8", errors="replace")
        return {
            "case_id": case_id,
            "source_of_truth": "existing_reports",
            "matched": True,
            "selected_report": selected,
            "candidate_reports": resources[:25],
            "summary": {"matching_report_count": len(resources), "selected_size_bytes": size},
            "content": {"uri": selected["uri"], "mimeType": mimetypes.guess_type(path.name)[0] or "text/plain", "text": text},
        }

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

    def timeline_window(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return timeline_review_report(
                db,
                _required(arguments, "case_id"),
                limit=_limit(arguments, default=100),
                user=_optional_text(arguments, "user"),
                contains=_optional_text(arguments, "contains"),
                source=_optional_text(arguments, "source"),
                preset=_optional_text(arguments, "preset"),
            )
        finally:
            db.close()

    def file_dossier(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return file_dossier_report(
                db,
                _required(arguments, "case_id"),
                path=_optional_text(arguments, "path"),
                name=_optional_text(arguments, "name"),
                limit=_limit(arguments, default=100),
            )
        finally:
            db.close()

    def query_filesystem_listings(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return filesystem_listing_report(
                db,
                _required(arguments, "case_id"),
                contains=_optional_text(arguments, "contains"),
                computer_id=_optional_text(arguments, "computer_id"),
                image_id=_optional_text(arguments, "image_id"),
                scan_status=_optional_text(arguments, "scan_status"),
                include_deleted=bool(arguments.get("include_deleted", True)),
                include_virtual=bool(arguments.get("include_virtual") or False),
                limit=_limit(arguments, default=250),
            )
        finally:
            db.close()

    def query_evidence_contents(self, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.query_filesystem_listings(arguments)
        result["source_of_truth"] = "filesystem_entries"
        result["intent"] = "evidence_contents"
        result["guidance"] = (
            "These rows come from generated evidence file listings. Treat them as the first source for contents questions; "
            "only run image processing, mounts, or SleuthKit/FLS when the stored listing is absent, stale, or insufficient."
        )
        return result

    def usb_dossier(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return usb_dossier_report(
                db,
                _required(arguments, "case_id"),
                serial=_optional_text(arguments, "serial"),
                volume_serial_number=_optional_text(arguments, "volume_serial_number"),
                volume_guid=_optional_text(arguments, "volume_guid"),
                limit=_limit(arguments, default=250),
            )
        finally:
            db.close()

    def user_activity(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return user_activity_report(
                db,
                _required(arguments, "case_id"),
                user=_required(arguments, "user"),
                limit=_limit(arguments, default=100),
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

    def search_artifacts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return artifact_search_report(
                db,
                _required(arguments, "case_id"),
                query=_optional_text(arguments, "query"),
                user=_optional_text(arguments, "user"),
                computer=_optional_text(arguments, "computer"),
                source_type=_optional_text(arguments, "source_type"),
                start=_optional_text(arguments, "start"),
                end=_optional_text(arguments, "end"),
                limit=_limit(arguments, default=100),
            )
        finally:
            db.close()

    def artifact_search_sources(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return artifact_search_source_inventory_report(db, _required(arguments, "case_id"))
        finally:
            db.close()

    def lead_search(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return artifact_lead_search_report(
                db,
                _required(arguments, "case_id"),
                preset=_required(arguments, "preset"),
                query=_optional_text(arguments, "query"),
                user=_optional_text(arguments, "user"),
                computer=_optional_text(arguments, "computer"),
                start=_optional_text(arguments, "start"),
                end=_optional_text(arguments, "end"),
                limit=_limit(arguments, default=100),
            )
        finally:
            db.close()

    def case_activity_digest(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return case_activity_digest_report(db, _required(arguments, "case_id"), limit=_limit(arguments, default=25))
        finally:
            db.close()

    def case_next_actions(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        limit = _limit(arguments, default=25)
        db = self._db()
        try:
            return case_next_actions_report(db, case_id, limit=limit)
        finally:
            db.close()

    def case_runbook(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            from .cli import case_runbook_report

            return case_runbook_report(db, self.paths, _required(arguments, "case_id"), limit=_limit(arguments, default=25))
        finally:
            db.close()

    def write_review_packet(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        title = _optional_text(arguments, "title") or "MCP Review Packet"
        packet_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_dir = self.paths.case_dir(case_id) / "reports" / "mcp-review-packets"
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "case_id": case_id,
            "title": title,
            "created_at": _now(),
            "notes": _optional_text(arguments, "notes") or "",
            "findings": arguments.get("findings") if isinstance(arguments.get("findings"), list) else [],
            "report_uris": arguments.get("report_uris") if isinstance(arguments.get("report_uris"), list) else [],
            "timeline": arguments.get("timeline") if isinstance(arguments.get("timeline"), list) else [],
        }
        json_path = output_dir / f"{packet_id}-review-packet.json"
        md_path = output_dir / f"{packet_id}-review-packet.md"
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        md_path.write_text(_review_packet_markdown(payload), encoding="utf-8")
        return {
            "case_id": case_id,
            "json_path": str(json_path),
            "markdown_path": str(md_path),
            "resource_uris": _resource_uris_for_path(self.paths.root, output_dir),
        }

    def list_review_packets(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        limit = _limit(arguments, default=50)
        packet_dir = self.paths.case_dir(case_id) / "reports" / "mcp-review-packets"
        packets = []
        if packet_dir.exists():
            for path in sorted(packet_dir.glob("*-review-packet.json"), key=lambda item: item.stat().st_mtime, reverse=True)[:limit]:
                payload = _load_json_file(path)
                stat = path.stat()
                markdown_path = path.with_suffix(".md")
                packets.append(
                    {
                        "case_id": case_id,
                        "title": payload.get("title") or path.stem,
                        "created_at": payload.get("created_at") or "",
                        "json_uri": _resource_uri(path.resolve().relative_to(self.paths.root.resolve())),
                        "markdown_uri": _resource_uri(markdown_path.resolve().relative_to(self.paths.root.resolve())) if markdown_path.exists() else "",
                        "relative_path": str(path.resolve().relative_to(self.paths.root.resolve())),
                        "size_bytes": stat.st_size,
                        "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    }
                )
        return {"case_id": case_id, "packets": packets, "summary": {"packet_count": len(packets), "limit": limit}}

    def read_review_packet(self, arguments: dict[str, Any]) -> dict[str, Any]:
        uri = _required(arguments, "uri")
        path = _path_from_resource_uri(self.paths.root, uri)
        packet_dir_token = f"{os.sep}mcp-review-packets{os.sep}"
        if packet_dir_token not in str(path) or path.suffix.casefold() not in {".json", ".md"}:
            raise ValueError("URI is not a review packet resource")
        if path.stat().st_size > MCP_RESOURCE_MAX_BYTES:
            raise ValueError(f"Review packet is too large to read through MCP: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        payload = json.loads(text) if path.suffix.casefold() == ".json" else None
        return {
            "uri": uri,
            "path": str(path),
            "format": path.suffix.casefold().lstrip("."),
            "text": text,
            "packet": payload,
        }

    def write_search_packet(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        preset = _optional_text(arguments, "preset")
        limit = _limit(arguments, default=100)
        db = self._db()
        try:
            if preset:
                search = artifact_lead_search_report(
                    db,
                    case_id,
                    preset=preset,
                    query=_optional_text(arguments, "query"),
                    user=_optional_text(arguments, "user"),
                    computer=_optional_text(arguments, "computer"),
                    start=_optional_text(arguments, "start"),
                    end=_optional_text(arguments, "end"),
                    limit=limit,
                )
            else:
                search = artifact_search_report(
                    db,
                    case_id,
                    query=_optional_text(arguments, "query"),
                    user=_optional_text(arguments, "user"),
                    computer=_optional_text(arguments, "computer"),
                    source_type=_optional_text(arguments, "source_type"),
                    start=_optional_text(arguments, "start"),
                    end=_optional_text(arguments, "end"),
                    limit=limit,
                )
        finally:
            db.close()
        title = _optional_text(arguments, "title") or ("Lead Search Packet" if preset else "Artifact Search Packet")
        packet_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{uuid.uuid4().hex[:8]}"
        output_dir = self.paths.case_dir(case_id) / "reports" / "mcp-search-packets"
        output_dir.mkdir(parents=True, exist_ok=True)
        metadata_db = self._db()
        try:
            metadata = search_packet_metadata(metadata_db, case_id, search, arguments, tool_version=_package_version())
        finally:
            metadata_db.close()
        payload = {
            "case_id": case_id,
            "title": title,
            "created_at": _now(),
            "search_type": "lead" if preset else "artifact",
            "arguments": {key: value for key, value in arguments.items() if key not in {"findings", "timeline"}},
            "metadata": metadata,
            "search": search,
        }
        json_path = output_dir / f"{packet_id}-search-packet.json"
        md_path = output_dir / f"{packet_id}-search-packet.md"
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        md_path.write_text(_search_packet_markdown(payload), encoding="utf-8")
        return {
            "case_id": case_id,
            "json_path": str(json_path),
            "markdown_path": str(md_path),
            "resource_uris": _resource_uris_for_path(self.paths.root, output_dir),
            "summary": (search.get("summary") if isinstance(search, dict) else {}),
        }

    def list_search_packets(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return _list_packet_files(self.paths.root, self.paths.case_dir(_required(arguments, "case_id")) / "reports" / "mcp-search-packets", limit=_limit(arguments, default=50), suffix="-search-packet.json")

    def read_search_packet(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return _read_packet_resource(self.paths.root, _required(arguments, "uri"), directory_name="mcp-search-packets", label="search")

    def rerun_search_packet(self, arguments: dict[str, Any]) -> dict[str, Any]:
        packet = self.read_search_packet({"uri": _required(arguments, "uri")}).get("packet")
        if not isinstance(packet, dict):
            raise ValueError("Search packet URI must reference a JSON packet")
        db = self._db()
        try:
            return rerun_search_packet_report(db, packet, limit_override=_limit(arguments, default=int((packet.get("arguments") or {}).get("limit") or 100)))
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
            metadata = tool.metadata()
            tools.append(
                {
                    "name": tool.name,
                    "title": tool.title,
                    "description": tool.description,
                    "permission": tool.permission,
                    "category": metadata["category"],
                    "tags": metadata["tags"],
                    "version": metadata["version"],
                    "output_type": metadata["output_type"],
                    "dependencies": metadata["dependencies"],
                    "source_priority": metadata["source_priority"],
                    "examples": metadata["examples"],
                    "error_handling": metadata["error_handling"],
                    "annotations": tool.annotations,
                    "input_schema": tool.input_schema,
                }
            )
        categories: dict[str, int] = {}
        permissions: dict[str, int] = {}
        for tool in tools:
            categories[str(tool["category"])] = categories.get(str(tool["category"]), 0) + 1
            permissions[str(tool["permission"])] = permissions.get(str(tool["permission"]), 0) + 1
        return {
            "tools": tools,
            "total_returned": len(tools),
            "summary": {
                "categories": [{"category": key, "count": value} for key, value in sorted(categories.items())],
                "permissions": [{"permission": key, "count": value} for key, value in sorted(permissions.items())],
            },
            "permissions": self._permissions(),
            "policy": self._public_policy(),
        }

    def generate_report(self, arguments: dict[str, Any]) -> dict[str, Any]:
        report_name = _required(arguments, "report_name")
        if report_name not in SUPPORTED_MCP_REPORTS:
            raise ValueError(f"Unsupported MCP report_name: {report_name}")
        fmt = str(arguments.get("format") or "json")
        if fmt not in {"json", "table", "csv", "md"}:
            raise ValueError("format must be one of: json, table, csv, md")
        case_id = _required(arguments, "case_id")
        if not bool(arguments.get("regenerate") or False):
            existing = self.read_existing_report(
                {
                    "case_id": case_id,
                    "report_name": report_name,
                    "purpose": "full",
                    "max_bytes": MCP_RESOURCE_MAX_BYTES,
                }
            )
            if existing.get("matched"):
                return {
                    **existing,
                    "status": "existing_report_returned",
                    "regenerated": False,
                    "guidance": "Existing generated report was returned. Pass regenerate=true to force CLI report regeneration.",
                }
        command = self._base_cli_command() + [
            "report",
            report_name,
            "--case",
            case_id,
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
            if purpose not in {"full", "usb", "cloud", "execution", "memory", "triage", "review"}:
                raise ValueError("purpose must be one of: full, usb, cloud, execution, memory, triage, review")
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

    def get_mcp_job_progress(self, arguments: dict[str, Any]) -> dict[str, Any]:
        job = self._mcp_jobs.get(_required(arguments, "mcp_job_id"))
        if job is None:
            raise ValueError("MCP job not found")
        max_bytes = _bounded_int(arguments, "max_bytes", default=50_000, minimum=1_000, maximum=200_000)
        self._refresh_mcp_job(job)
        text = "\n".join(
            [
                _read_tail(Path(str(job["stderr_path"])), max_bytes),
                _read_tail(Path(str(job["stdout_path"])), max_bytes),
            ]
        )
        progress = _parse_mcp_progress(text)
        return {**_public_job(job), **progress}

    def list_progress_manifests(self, arguments: dict[str, Any]) -> dict[str, Any]:
        manifest_path = _workspace_path(self.paths.root, str(arguments["path"])) if arguments.get("path") else None
        return progress_manifest_report(self.paths.root, limit=_limit(arguments, default=50), path=manifest_path)

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
        progress_manifest = (
            _workspace_path(self.paths.root, str(arguments["progress_manifest"]))
            if arguments.get("progress_manifest")
            else self.paths.root / "progress" / f"mcp-import-{uuid.uuid4()}.json"
        )
        command.extend(["--progress-manifest", str(progress_manifest)])
        result = self._start_mcp_process("import_triage_zip", command)
        result["progress_manifest_path"] = str(progress_manifest)
        result["progress_manifest_uri"] = _resource_uri(progress_manifest.resolve().relative_to(self.paths.root.resolve()))
        return result

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

    def recover_deleted_files(self, arguments: dict[str, Any]) -> dict[str, Any]:
        command = self._base_cli_command() + [
            "recover",
            "deleted-files",
            "--case",
            _required(arguments, "case_id"),
            "--source",
            _optional_text(arguments, "source") or "all",
            "--limit",
            str(_limit(arguments, default=100)),
            "--format",
            "json",
        ]
        _extend_optional(command, "--image", arguments.get("image_id"))
        _extend_optional(command, "--contains", arguments.get("contains"))
        _extend_optional(command, "--name", arguments.get("name"))
        max_bytes = _bounded_int(arguments, "max_bytes", default=0, minimum=0, maximum=10_000_000_000)
        if max_bytes:
            command.extend(["--max-bytes", str(max_bytes)])
        if arguments.get("output_dir"):
            command.extend(["--output-dir", str(_workspace_path(self.paths.root, str(arguments["output_dir"])))])
        return self._start_mcp_process("recover_deleted_files", command)

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
            "command_display": _redacted_command(command),
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

    def _audit_tool_call(
        self,
        tool: McpTool,
        arguments: dict[str, Any],
        *,
        status: str,
        error: str | None,
        correlation_id: str,
        request_id: object | None,
        duration_ms: int,
    ) -> None:
        details = _error_details(ValueError(error)) if error else {}
        row = {
            "timestamp": _now(),
            "correlation_id": correlation_id,
            "request_id": request_id,
            "tool": tool.name,
            "title": tool.title,
            "category": tool.metadata()["category"],
            "tags": tool.metadata()["tags"],
            "permission": tool.permission,
            "status": status,
            "error": error,
            "error_details": details,
            "duration_ms": duration_ms,
            "argument_keys": sorted(arguments.keys()),
            "arguments_redacted": _redact_arguments(arguments),
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

    def _load_mcp_policy(self) -> dict[str, Any]:
        candidates = [self.paths.root / MCP_POLICY_FILE, self.paths.root / "config" / MCP_POLICY_FILE]
        for path in candidates:
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return {"status": "invalid", "path": str(path)}
            if isinstance(data, dict):
                return {"status": "loaded", "path": str(path), **data}
        return {"status": "not_configured"}

    def _public_policy(self) -> dict[str, Any]:
        policy = dict(self.policy)
        for key in ("allowed_tools", "blocked_tools", "allowed_categories", "blocked_categories", "allowed_permissions", "blocked_permissions", "allowed_case_ids", "blocked_case_ids"):
            if key in policy and not isinstance(policy[key], list):
                policy[key] = list(policy[key]) if isinstance(policy[key], (set, tuple)) else policy[key]
        return policy

    def _require_permission(self, permission: str) -> None:
        if permission == "processing" and not self.allow_processing:
            raise ValueError("Tool requires MCP server startup flag: --allow-processing")
        if permission == "sensitive" and not self.allow_sensitive:
            raise ValueError("Tool requires MCP server startup flag: --allow-sensitive")
        if permission == "external_ai" and not self.allow_external_ai:
            raise ValueError("Tool requires MCP server startup flag: --allow-external-ai")

    def _require_policy(self, tool: McpTool, arguments: dict[str, Any]) -> None:
        if self.policy.get("status") == "invalid":
            raise ValueError(f"MCP policy file is invalid: {self.policy.get('path')}")
        metadata = tool.metadata()
        category = str(metadata.get("category") or "")
        case_id = str(arguments.get("case_id") or "").strip()
        checks = (
            ("allowed_tools", tool.name, True),
            ("blocked_tools", tool.name, False),
            ("allowed_categories", category, True),
            ("blocked_categories", category, False),
            ("allowed_permissions", tool.permission, True),
            ("blocked_permissions", tool.permission, False),
        )
        for key, value, allowlist in checks:
            configured = _policy_values(self.policy.get(key))
            if not configured:
                continue
            if allowlist and value not in configured:
                raise ValueError(f"MCP policy does not allow {_policy_label(key)}: {value}")
            if not allowlist and value in configured:
                raise ValueError(f"MCP policy blocks {_policy_label(key)}: {value}")
        allowed_cases = _policy_values(self.policy.get("allowed_case_ids"))
        blocked_cases = _policy_values(self.policy.get("blocked_case_ids"))
        if case_id and allowed_cases and case_id not in allowed_cases:
            raise ValueError(f"MCP policy does not allow case_id: {case_id}")
        if case_id and blocked_cases and case_id in blocked_cases:
            raise ValueError(f"MCP policy blocks case_id: {case_id}")

    def _permissions(self) -> dict[str, bool]:
        return {
            "read_only": True,
            "processing": self.allow_processing,
            "sensitive": self.allow_sensitive,
            "external_ai": self.allow_external_ai,
            "policy_configured": self.policy.get("status") == "loaded",
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


def _tool_result(
    result: dict[str, Any],
    *,
    is_error: bool = False,
    tool: McpTool | None = None,
    correlation_id: str | None = None,
    duration_ms: int | None = None,
) -> dict[str, Any]:
    if isinstance(result, dict):
        result = dict(result)
        result.setdefault(
            "_mcp",
            {
                "status": "error" if is_error else "ok",
                "correlation_id": correlation_id,
                "tool": tool.name if tool else None,
                "category": tool.metadata()["category"] if tool else None,
                "permission": tool.permission if tool else None,
                "generated_at": _now(),
                "duration_ms": duration_ms,
                "response_version": "1.0",
            },
        )
    return {
        "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}],
        "structuredContent": result,
        "isError": is_error,
    }


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    public = {key: value for key, value in job.items() if key != "process"}
    if "command" in public:
        public["command_display"] = public.get("command_display") or _redacted_command(public["command"])
    public["duration_seconds"] = _job_duration_seconds(public)
    public["output_sizes"] = {
        "stdout_bytes": _path_size(public.get("stdout_path")),
        "stderr_bytes": _path_size(public.get("stderr_path")),
    }
    progress = _job_progress_summary(public)
    if progress:
        public["progress"] = progress
    return public


def _tool_metadata(tool: McpTool) -> dict[str, Any]:
    category = tool.category or _infer_tool_category(tool.name)
    tags = sorted(set(tool.tags or _infer_tool_tags(tool.name, category, tool.permission)))
    dependencies = sorted(set(tool.dependencies or _infer_tool_dependencies(tool.name, tool.permission)))
    source_priority = list(tool.source_priority or _infer_source_priority(tool.name, category))
    examples = list(tool.examples or [_default_tool_example(tool)])
    return {
        "category": category,
        "tags": tags,
        "version": tool.version,
        "output_type": tool.output_type,
        "dependencies": dependencies,
        "source_priority": source_priority,
        "examples": examples,
        "error_handling": {
            "error_shape": {"error": "string", "error_code": "string", "retryable": "boolean", "suggested_fix": "string"},
            "permission_errors": "Processing, sensitive, and external-AI tools require matching server startup flags and policy allowances.",
            "retry_guidance": "Retry only when retryable=true or when the suggested_fix identifies a corrected parameter or missing generated artifact.",
        },
    }


def _infer_tool_category(name: str) -> str:
    if "mcp_job" in name or name.startswith("relic_mcp_") or "progress" in name or "readiness" in name or "doctor" in name:
        return "operations"
    if "report" in name or "packet" in name or "review" in name or "dashboard" in name or "digest" in name or "runbook" in name:
        return "reports"
    if "filesystem" in name or "evidence_contents" in name or "file_" in name or "recover_deleted" in name:
        return "filesystem"
    if "usb" in name or "removable" in name:
        return "external_storage"
    if "cloud" in name:
        return "cloud"
    if "memory" in name:
        return "memory"
    if "browser" in name:
        return "browser"
    if "registry" in name or "shortcut" in name or "execution" in name:
        return "windows_artifacts"
    if "communication" in name:
        return "communications"
    if "import" in name or "process" in name or "profile" in name:
        return "processing"
    return "workspace"


def _infer_tool_tags(name: str, category: str, permission: str) -> tuple[str, ...]:
    tags = {category, permission}
    for token in ("source_of_truth", "filesystem", "cloud", "usb", "memory", "timeline", "report", "processing", "recovery"):
        if token.replace("_", "-") in name or token in name:
            tags.add(token)
    if name in {"relic_read_existing_report", "relic_discover_reports", "relic_query_filesystem_listings", "relic_query_evidence_contents"}:
        tags.add("source_of_truth")
    return tuple(tags)


def _infer_tool_dependencies(name: str, permission: str) -> tuple[str, ...]:
    deps = ["orchestrator.sqlite3"]
    if permission == "processing":
        deps.append("relic CLI")
    if "report" in name:
        deps.append("generated reports")
    if "filesystem" in name or "evidence_contents" in name:
        deps.append("filesystem_entries")
    if "mcp_job" in name:
        deps.append("mcp-jobs/index.json")
    if "doctor" in name:
        deps.append("third-party dependency registry")
    return tuple(deps)


def _infer_source_priority(name: str, category: str) -> tuple[str, ...]:
    if name in {"relic_read_existing_report", "relic_discover_reports", "relic_generate_report"} or category == "reports":
        return ("existing_reports", "parsed_artifacts", "processing")
    if category == "filesystem":
        return ("filesystem_entries", "mft_entries", "mounted_image_or_tsk")
    if category == "cloud":
        return ("existing_cloud_reports", "cloud_sync_artifacts", "opened_from_cloud_storage", "raw_processing")
    if category == "external_storage":
        return ("existing_usb_reports", "usb_storage_devices", "usb_connection_events", "filesystem_entries")
    return ("parsed_artifacts", "existing_reports", "processing")


def _default_tool_example(tool: McpTool) -> dict[str, Any]:
    properties = tool.input_schema.get("properties") if isinstance(tool.input_schema, dict) else {}
    required = tool.input_schema.get("required") if isinstance(tool.input_schema, dict) else []
    arguments: dict[str, Any] = {}
    for key in required or []:
        if key == "case_id":
            arguments[key] = "case-id"
        elif key == "image_id":
            arguments[key] = "image-id"
        elif key == "mcp_job_id":
            arguments[key] = "mcp-job-id"
        elif key == "uri":
            arguments[key] = "relic://reports/case-id/full/report.json"
        elif key == "path":
            arguments[key] = "/path/to/evidence"
        else:
            arguments[key] = f"<{key}>"
    if "limit" in (properties or {}) and "limit" not in arguments:
        arguments["limit"] = properties["limit"].get("default", 100)
    return {"description": f"Call {tool.name}.", "arguments": arguments}


def _duration_ms(started: datetime) -> int:
    return max(0, int((datetime.now(timezone.utc) - started).total_seconds() * 1000))


def _tool_error_payload(tool: McpTool, exc: Exception, *, correlation_id: str) -> dict[str, Any]:
    details = _error_details(exc)
    return {
        "error": str(exc),
        "tool": tool.name,
        "error_code": details["error_code"],
        "cause": details["cause"],
        "retryable": details["retryable"],
        "suggested_fix": details["suggested_fix"],
        "correlation_id": correlation_id,
        "related_jobs": [],
    }


def _error_details(exc: Exception) -> dict[str, Any]:
    text = str(exc)
    lower = text.lower()
    if "requires mcp server startup flag" in lower or "policy" in lower:
        return {"error_code": "permission_denied", "cause": "permission", "retryable": False, "suggested_fix": text}
    if "not found" in lower or "missing" in lower:
        return {"error_code": "not_found", "cause": "missing_resource", "retryable": False, "suggested_fix": "Verify the case ID, resource URI, path, or generated report exists."}
    if "timeout" in lower or "tempor" in lower or "locked" in lower:
        return {"error_code": "transient_failure", "cause": "transient", "retryable": True, "suggested_fix": "Retry after checking active jobs and available disk space."}
    if "unsupported" in lower:
        return {"error_code": "unsupported", "cause": "unsupported_input", "retryable": False, "suggested_fix": "Use a supported report, profile, artifact type, or input layout."}
    return {"error_code": "tool_error", "cause": type(exc).__name__, "retryable": False, "suggested_fix": "Inspect the MCP audit log and job output for context."}


def _redact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in arguments.items():
        key_lower = str(key).lower()
        if any(token in key_lower for token in SENSITIVE_ARGUMENT_KEYS):
            redacted[key] = "<redacted>"
        elif isinstance(value, dict):
            redacted[key] = _redact_arguments(value)
        elif isinstance(value, list):
            redacted[key] = ["<list>", len(value)]
        else:
            redacted[key] = value
    return redacted


def _redacted_command(command: Any) -> list[str]:
    if not isinstance(command, list):
        return []
    redacted: list[str] = []
    redact_next = False
    for part in command:
        text = str(part)
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        redacted.append(text)
        if any(token in text.lower().lstrip("-").replace("-", "_") for token in SENSITIVE_ARGUMENT_KEYS):
            redact_next = True
    return redacted


def _policy_values(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple, set)):
        return {str(item) for item in value}
    return set()


def _policy_label(key: str) -> str:
    labels = {
        "allowed_tools": "tool",
        "blocked_tools": "tool",
        "allowed_categories": "category",
        "blocked_categories": "category",
        "allowed_permissions": "permission",
        "blocked_permissions": "permission",
    }
    return labels.get(key, key)


def _path_size(path: Any) -> int:
    try:
        candidate = Path(str(path))
        return candidate.stat().st_size if candidate.exists() else 0
    except OSError:
        return 0


def _job_duration_seconds(job: dict[str, Any]) -> float | None:
    started = _parse_iso(str(job.get("started_at") or ""))
    ended = _parse_iso(str(job.get("ended_at") or "")) or datetime.now(timezone.utc)
    if not started:
        return None
    return round(max(0.0, (ended - started).total_seconds()), 3)


def _job_progress_summary(job: dict[str, Any]) -> dict[str, Any]:
    text = "\n".join(
        [
            _read_tail(Path(str(job.get("stderr_path") or "")), 50_000),
            _read_tail(Path(str(job.get("stdout_path") or "")), 50_000),
        ]
    )
    return _parse_mcp_progress(text)


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


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


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


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


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


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
        "progress": ("progress/**/*.json",),
        "packet": (f"cases/{case_glob}/reports/mcp-review-packets/**/*", f"cases/{case_glob}/reports/mcp-search-packets/**/*"),
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


def _case_report_resources(root: Path, case_id: str, *, purpose: str | None, limit: int) -> list[dict[str, Any]]:
    expected = _expected_report_names(purpose or "full")
    rows: list[dict[str, Any]] = []
    root_resolved = root.resolve()
    for path in _resource_candidates(root, case_id=case_id, kind="report"):
        resolved = path.resolve()
        if resolved != root_resolved and root_resolved not in resolved.parents:
            continue
        if expected and not _is_packet_resource(resolved) and _report_resource_name(resolved) not in expected and resolved.name not in {"index.md", "report-index.json", "bundle-quality.json"}:
            continue
        stat = resolved.stat()
        relative = resolved.relative_to(root_resolved)
        metadata = _resource_metadata(root_resolved, resolved, case_id=case_id, kind="report")
        rows.append(
            {
                "uri": _resource_uri(relative),
                "relative_path": str(relative),
                "name": _report_resource_name(resolved),
                "filename": resolved.name,
                "format": resolved.suffix.casefold().lstrip("."),
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "kind": metadata["kind"],
                "purpose": metadata["purpose"],
                "tags": metadata["tags"],
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _matching_report_resources(
    root: Path,
    case_id: str,
    *,
    purpose: str,
    report_name: str | None,
    tags: list[str],
    contains: str | None,
    max_bytes: int,
    limit: int,
) -> list[dict[str, Any]]:
    resources = _case_report_resources(root, case_id, purpose=purpose, limit=limit)
    if report_name:
        wanted = _normalize_report_token(report_name)
        resources = [
            row
            for row in resources
            if wanted in {
                _normalize_report_token(str(row.get("name") or "")),
                _normalize_report_token(str(row.get("filename") or "")),
                _normalize_report_token(Path(str(row.get("filename") or "")).stem),
            }
        ]
    if tags:
        wanted_tags = {tag.casefold() for tag in tags}
        resources = [
            row
            for row in resources
            if wanted_tags <= {str(tag).casefold() for tag in (row.get("tags") or [])}
        ]
    if contains:
        needle = contains.casefold()
        filtered = []
        for row in resources:
            try:
                path = _path_from_resource_uri(root, str(row["uri"]))
            except ValueError:
                continue
            if path.stat().st_size > max_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if needle in text.casefold():
                filtered.append(row)
        resources = filtered
    resources.sort(key=lambda row: (_report_format_rank(str(row.get("format") or "")), str(row.get("modified_at") or "")), reverse=True)
    return resources


def _normalize_report_token(value: str) -> str:
    text = value.casefold().strip()
    for suffix in (".json", ".md", ".csv", ".txt"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")


def _report_format_rank(fmt: str) -> int:
    return {"md": 4, "json": 3, "csv": 2, "txt": 1}.get(fmt.casefold(), 0)


def _case_packet_resources(root: Path, case_id: str, *, limit: int) -> list[dict[str, Any]]:
    rows = []
    for directory in ("mcp-review-packets", "mcp-search-packets"):
        packet_dir = root / "cases" / case_id / "reports" / directory
        if not packet_dir.exists():
            continue
        for path in sorted(packet_dir.glob("*"), key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
            if not path.is_file() or not _is_text_resource(path):
                continue
            metadata = _resource_metadata(root.resolve(), path.resolve(), case_id=case_id, kind="packet")
            rows.append({"uri": _resource_uri(path.resolve().relative_to(root.resolve())), "relative_path": str(path.resolve().relative_to(root.resolve())), **metadata})
            if len(rows) >= limit:
                return rows
    return rows


def _resource_metadata(root: Path, path: Path, *, case_id: str | None = None, kind: str | None = None) -> dict[str, Any]:
    stat = path.stat()
    relative = path.relative_to(root)
    inferred_kind = "packet" if _is_packet_resource(path) else (kind or _infer_resource_kind(relative))
    inferred_case = case_id or _case_id_from_relative(relative)
    report_name = _report_resource_name(path) if inferred_kind == "report" else ""
    purpose, tags = _resource_report_index_metadata(path, report_name)
    if _is_packet_resource(path):
        purpose = purpose or "examiner-work-product"
        tags = sorted(set(tags) | {"packet", "review" if "review-packet" in path.name else "search"})
    if not tags and report_name:
        tags = sorted(_expected_report_names("usb") & {report_name}) or []
    description = f"Relic {inferred_kind} resource"
    if inferred_case:
        description += f" for case {inferred_case}"
    description += f" ({stat.st_size} bytes)"
    return {
        "kind": inferred_kind,
        "case_id": inferred_case or "",
        "report_name": report_name,
        "purpose": purpose,
        "tags": tags,
        "size_bytes": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "description": description,
    }


def _infer_resource_kind(relative: Path) -> str:
    parts = relative.parts
    if parts and parts[0] == "progress":
        return "progress"
    if parts and parts[0] == "mcp-jobs":
        return "mcp-job"
    if "mcp-review-packets" in parts or "mcp-search-packets" in parts:
        return "packet"
    if "logs" in parts:
        return "log"
    if "manifest" in relative.name.casefold():
        return "manifest"
    return "report"


def _is_packet_resource(path: Path) -> bool:
    parts = path.parts
    return "mcp-review-packets" in parts or "mcp-search-packets" in parts


def _case_id_from_relative(relative: Path) -> str:
    parts = relative.parts
    if len(parts) >= 2 and parts[0] == "cases":
        return parts[1]
    return ""


def _resource_report_index_metadata(path: Path, report_name: str) -> tuple[str, list[str]]:
    index_path = path.parent / "report-index.json"
    if not index_path.exists():
        return "", []
    index = _load_json_file(index_path)
    reports = index.get("reports") if isinstance(index.get("reports"), list) else []
    for row in reports:
        if not isinstance(row, dict):
            continue
        if row.get("name") == report_name or row.get("filename") == path.name:
            tags = row.get("tags") if isinstance(row.get("tags"), list) else []
            return str(row.get("purpose") or index.get("purpose") or ""), [str(tag) for tag in tags]
    return str(index.get("purpose") or ""), []


def _report_resource_name(path: Path) -> str:
    if path.name == "index.md":
        return "index"
    if path.name == "report-index.json":
        return "report-index"
    if path.suffix.casefold() in {".md", ".json", ".csv"}:
        return path.stem
    return path.name


def _expected_report_names(purpose: str) -> set[str]:
    common = {
        "executive-summary",
        "case-overview",
        "evidence-gaps",
        "processing-decisions",
        "processing-readiness",
        "regression-smoke",
        "bundle-quality",
        "index",
        "report-index",
    }
    groups = {
        "triage": common | {"suspicious-executions", "user-intent", "file-movement-identity", "opened-from-removable-media", "opened-from-cloud-storage", "cloud-mounts", "cloud-removable-overlap", "artifact-processing-status"},
        "usb": common | {"shellbag-external-storage", "file-movement-identity", "opened-from-removable-media", "cloud-removable-overlap", "shortcut-droid-changes", "shortcut-object-tracking", "usn-lifecycle"},
        "cloud": common | {"cloud-artifacts", "opened-from-cloud-storage", "cloud-mounts", "cloud-removable-overlap", "user-intent"},
        "execution": common | {"execution", "execution-correlation", "suspicious-executions", "program-provenance", "remote-access", "user-intent"},
        "memory": common | {"memory-analysis", "memory-credentials", "memory-disk-correlations", "memory-support-files", "combined-artifacts", "crash-dump-analysis", "memory-artifacts"},
    }
    if purpose == "full":
        return set()
    return groups.get(purpose, groups["triage"])


def _memory_source_rows(db: Database, case_id: str, *, limit: int) -> list[dict[str, Any]]:
    rows = []
    for row in db.conn.execute(
        """
        SELECT activity_log.created_at, activity_log.computer_id, computers.label AS computer_label,
               activity_log.image_id, activity_log.event, activity_log.message, activity_log.details_json
        FROM activity_log
        LEFT JOIN computers ON computers.id = activity_log.computer_id
        WHERE activity_log.case_id = ?
          AND (
            activity_log.event LIKE 'memory.%'
            OR activity_log.event LIKE 'crash%'
            OR activity_log.message LIKE '%memory%'
            OR activity_log.message LIKE '%pagefile%'
            OR activity_log.message LIKE '%hiberfil%'
            OR activity_log.message LIKE '%swapfile%'
            OR activity_log.message LIKE '%dump%'
          )
        ORDER BY activity_log.created_at DESC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall():
        item = dict(row)
        item["details"] = _json_value(item.pop("details_json"), {})
        rows.append(item)
    return rows


def _has_required_action(readiness: dict[str, Any] | None) -> bool:
    if not readiness:
        return False
    summary = readiness.get("summary") if isinstance(readiness.get("summary"), dict) else {}
    return int(summary.get("required_needs_action_count") or summary.get("needs_action_count") or 0) > 0


def _parse_mcp_progress(text: str) -> dict[str, Any]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    parsed: list[dict[str, Any]] = []
    latest: dict[str, Any] = {}
    for line in lines:
        row = _parse_progress_line(line)
        if row:
            parsed.append(row)
            latest.update({key: value for key, value in row.items() if key != "raw"})
    return {
        "summary": {
            "progress_line_count": len(parsed),
            "last_progress": parsed[-1] if parsed else None,
            **latest,
        },
        "progress": parsed[-100:],
    }


def _parse_progress_line(line: str) -> dict[str, Any] | None:
    if "report-bundle-many" not in line and "report-bundle csv" not in line and "profile " not in line:
        return None
    row: dict[str, Any] = {"raw": line}
    if "report-bundle-many" in line:
        row["workflow"] = "report_bundle_many"
        match = re.search(r"computer (?P<current>\d+)/(?P<total>\d+)", line)
        if match:
            row["current_computer_index"] = int(match.group("current"))
            row["computer_count"] = int(match.group("total"))
        progress = re.search(r"computers_done=(?P<done>\d+) computers_total=(?P<total>\d+)", line)
        if progress:
            row["computers_done"] = int(progress.group("done"))
            row["computer_count"] = int(progress.group("total"))
        label = re.search(r"label=(?P<label>[^\s]+)", line)
        if label:
            row["computer_label"] = label.group("label")
        for key in ("imported_computers", "rows", "skipped", "failed", "files"):
            match = re.search(rf"{key}=(?P<value>\d+)", line)
            if match:
                row[key] = int(match.group("value"))
    elif "report-bundle csv" in line:
        row["workflow"] = "report_bundle"
        match = re.search(r"csv (?P<current>\d+)/(?P<total>\d+)", line)
        if match:
            row["current_csv_index"] = int(match.group("current"))
            row["csv_count"] = int(match.group("total"))
        tool = re.search(r"tool=(?P<tool>[^\s]+)", line)
        if tool:
            row["tool_name"] = tool.group("tool")
    elif "profile " in line:
        row["workflow"] = "profile"
    return row


def _review_packet_markdown(payload: dict[str, Any]) -> str:
    lines = [
        f"# {payload.get('title') or 'MCP Review Packet'}",
        "",
        f"Case: `{payload.get('case_id')}`",
        f"Created: `{payload.get('created_at')}`",
        "",
    ]
    if payload.get("notes"):
        lines.extend(["## Notes", "", str(payload["notes"]), ""])
    for section, key in (("Findings", "findings"), ("Report URIs", "report_uris"), ("Timeline", "timeline")):
        values = payload.get(key) or []
        lines.extend([f"## {section}", ""])
        if not values:
            lines.append("- None")
        for value in values[:100]:
            lines.append(f"- `{json.dumps(value, default=str) if isinstance(value, dict) else value}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _search_packet_markdown(payload: dict[str, Any]) -> str:
    search = payload.get("search") if isinstance(payload.get("search"), dict) else {}
    summary = search.get("summary") if isinstance(search.get("summary"), dict) else {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    lines = [
        f"# {payload.get('title') or 'Search Packet'}",
        "",
        f"Case: `{payload.get('case_id')}`",
        f"Created: `{payload.get('created_at')}`",
        f"Type: `{payload.get('search_type')}`",
        "",
        "## Summary",
        "",
    ]
    if not summary:
        lines.append("- None")
    for key, value in summary.items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Filters", ""])
    for key, value in (payload.get("arguments") or {}).items():
        if value not in (None, "", [], {}):
            lines.append(f"- {key}: `{value}`")
    if metadata:
        lines.extend(["", "## Packet Metadata", ""])
        for key in ("tool", "tool_version", "generated_at", "result_count", "result_hash_algorithm", "result_hash_set"):
            if metadata.get(key) not in (None, "", [], {}):
                lines.append(f"- {key}: `{metadata.get(key)}`")
        case_counts = metadata.get("case_counts") if isinstance(metadata.get("case_counts"), dict) else {}
        for key, value in case_counts.items():
            lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Results", ""])
    results = search.get("results") if isinstance(search.get("results"), list) else []
    if not results:
        lines.append("- None")
    for row in results[:100]:
        if isinstance(row, dict):
            lines.append(
                f"- `{row.get('timestamp') or ''}` `{row.get('category') or row.get('table') or ''}` "
                f"{row.get('summary') or row.get('description') or row.get('title') or row.get('id') or ''}"
            )
    return "\n".join(lines).rstrip() + "\n"


def _route_mcp_question(
    question: str,
    *,
    case_id: str | None,
    evidence_hint: str | None,
    allow_processing: bool,
    server_allows_processing: bool,
    server_allows_sensitive: bool,
    server_allows_external_ai: bool,
) -> dict[str, Any]:
    text = f"{question} {evidence_hint or ''}".casefold()
    tokens = set(re.findall(r"[a-z0-9$._:-]+", text))
    requires_sensitive = _contains_any(text, {"credential", "credentials", "password", "secret", "token", "hash", "dpapi", "lsa", "mimikatz"})
    requires_external_ai = _contains_any(text, {"chatgpt", "claude", "openai", "external ai", "upload to ai", "send to ai"})
    explicit_processing = _contains_any(
        text,
        {
            "process ",
            "processing",
            "parse ",
            "parsing",
            "import ",
            "ingest ",
            "reprocess",
            "run profile",
            "extract from image",
            "mount ",
            "fls",
            "sleuthkit",
        },
    )
    wants_recovery = _contains_any(text, {"recover", "restore", "undelete", "extract deleted", "deleted file", "deleted files"})

    intent = "general_review"
    report_purpose = "full"
    report_names: list[str] = []
    recommended_tool = "relic_read_existing_report"
    fallback_tools = ["relic_discover_report_exports", "relic_lead_search", "relic_search_artifacts"]
    first_source = "existing_reports"
    reason = "Generated reports are the highest-level source of truth for broad case questions."
    source_order = [
        {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_discover_report_exports"]},
        {"order": 2, "source": "parsed_artifact_tables", "tools": ["relic_lead_search", "relic_search_artifacts", "domain query tools"]},
        {"order": 3, "source": "case_resources_and_packets", "tools": ["resources/list", "resources/read", "relic_list_review_packets", "relic_list_search_packets"]},
        {"order": 4, "source": "processing_or_image_access", "tools": ["processing tools"], "requires_explicit_user_request": True},
    ]

    if wants_recovery:
        intent = "deleted_file_recovery"
        first_source = "generated_filesystem_listings"
        recommended_tool = "relic_query_evidence_contents"
        fallback_tools = ["relic_query_filesystem_listings", "relic_file_dossier"]
        if allow_processing and server_allows_processing:
            fallback_tools.append("relic_recover_deleted_files")
        report_names = ["opened-from-removable-media", "file-movement-identity"]
        report_purpose = "usb" if _contains_any(text, {"usb", "removable", "external", "drive"}) else "full"
        reason = "Deleted-file recovery should first identify the target in parsed listings, then run recovery only on explicit request."
        source_order = [
            {"order": 1, "source": "generated_filesystem_listings", "tools": ["relic_query_evidence_contents", "relic_query_filesystem_listings"]},
            {"order": 2, "source": "file_context_reports", "tools": ["relic_read_existing_report"], "report_names": report_names},
            {"order": 3, "source": "file_dossier", "tools": ["relic_file_dossier"]},
            {"order": 4, "source": "deleted_file_recovery", "tools": ["relic_recover_deleted_files"], "requires_explicit_user_request": True},
        ]
    elif _contains_any(text, {"contents", "content", "list files", "files on", "folder", "directory", "filesystem", "file listing", "drive contents", "volume contents"}) or "files" in tokens and _contains_any(text, {"usb", "drive", "volume", "image"}):
        intent = "evidence_contents"
        first_source = "generated_filesystem_listings"
        recommended_tool = "relic_query_evidence_contents"
        fallback_tools = ["relic_query_filesystem_listings", "relic_file_dossier", "relic_search_artifacts"]
        report_names = ["opened-from-removable-media", "file-movement-identity", "usb-files"]
        report_purpose = "usb" if _contains_any(text, {"usb", "removable", "external"}) else "full"
        reason = "Filesystem answers should come from stored filesystem_entries before live image access or SleuthKit."
        source_order = [
            {"order": 1, "source": "generated_filesystem_listings", "tools": ["relic_query_evidence_contents", "relic_query_filesystem_listings"]},
            {"order": 2, "source": "generated_reports", "tools": ["relic_read_existing_report"], "report_names": report_names},
            {"order": 3, "source": "parsed_artifact_tables", "tools": ["relic_file_dossier", "relic_search_artifacts"]},
            {"order": 4, "source": "image_processing_or_fls", "tools": ["relic_process_image", "relic_run_profile"], "requires_explicit_user_request": True},
        ]
    elif _contains_any(text, {"usb", "removable", "external storage", "thumb drive", "flash drive", "uasp", "usbstor", "volume serial"}):
        intent = "usb_storage"
        report_purpose = "usb"
        report_names = ["external-storage", "usb-files", "usb-timeline", "opened-from-removable-media", "file-movement-identity"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_query_external_storage", "relic_query_usb_files", "relic_usb_dossier", "relic_query_evidence_contents"]
        reason = "USB/storage questions should begin with deduped storage reports, then storage-specific parsed tables."
    elif _contains_any(text, {"suspicious", "execution", "executed", "executable", "program", "process", "runmru", "userassist", "prefetch"}):
        intent = "execution"
        report_purpose = "execution"
        report_names = ["suspicious-executions", "execution", "execution-correlation", "program-provenance"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_query_suspicious_executions", "relic_lead_search", "relic_query_registry_activity"]
        reason = "Execution questions should start with generated execution and suspicious-execution reports."
    elif _contains_any(text, {"timeline", "when", "between", "around", "date", "time window"}):
        intent = "timeline"
        report_names = ["case-overview", "external-storage", "suspicious-executions", "memory-analysis"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_timeline_window", "relic_timeline", "relic_search_artifacts"]
        reason = "Timeline questions should use generated summaries first, then normalized timeline windows."
    elif _contains_any(text, {"memory", "ram", "pagefile", "hiberfil", "swapfile", "crash dump", "dump"}):
        intent = "memory"
        report_purpose = "memory"
        report_names = ["memory-analysis", "memory-artifacts", "memory-disk-correlations", "crash-dump-analysis"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_query_memory_artifacts", "relic_search_artifacts"]
        reason = "Memory questions should start with generated memory reports and combined memory/disk artifacts."
    elif _contains_any(text, {"cloud", "onedrive", "google drive", "dropbox", "sync", "virtual drive"}):
        intent = "cloud_storage"
        report_purpose = "cloud"
        report_names = ["cloud-artifacts", "opened-from-cloud-storage", "cloud-mounts", "cloud-removable-overlap"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_query_cloud_artifacts", "relic_query_opened_from_cloud_storage", "relic_lead_search"]
        reason = "Cloud questions should start with cloud-specific reports because virtual drives can mimic removable media."
    elif _contains_any(text, {"browser", "download", "history", "cache", "webcache", "firefox", "chrome", "edge"}):
        intent = "browser"
        report_names = ["user-intent", "case-overview"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_query_browser_activity", "relic_lead_search"]
        reason = "Browser questions should start with generated review reports, then browser activity tables."
    elif _contains_any(text, {"email", "mail", "message", "communications", "chat", "teams", "outlook"}):
        intent = "communications"
        report_names = ["user-intent", "case-overview"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_query_communications", "relic_lead_search"]
        reason = "Communication questions should start with existing review reports and then communications tables."
    elif explicit_processing:
        intent = "processing"
        first_source = "case_state"
        recommended_tool = "relic_case_readiness"
        fallback_tools = ["relic_profile_preview", "relic_process_image", "relic_run_profile", "relic_import_triage_zip"]
        reason = "Processing requests should verify readiness and workspace health before starting a gated job."
        source_order = [
            {"order": 1, "source": "readiness_and_workspace_health", "tools": ["relic_case_readiness", "relic_workspace_health"]},
            {"order": 2, "source": "case_state", "tools": ["relic_case_evidence_map", "relic_workspace_map"]},
            {"order": 3, "source": "processing_preview", "tools": ["relic_profile_preview", "relic_doctor"]},
            {"order": 4, "source": "processing_job", "tools": ["relic_process_image", "relic_run_profile", "relic_import_triage_zip"], "requires_explicit_user_request": True},
        ]

    processing_requested = explicit_processing or wants_recovery
    processing_permitted = bool(processing_requested and allow_processing and server_allows_processing)
    blocked_actions = []
    if processing_requested and not processing_permitted:
        blocked_actions.append(
            {
                "action": "processing_or_recovery",
                "reason": "Requires an explicit processing request, route allow_processing=true, and MCP server startup flag --allow-processing.",
                "server_allows_processing": server_allows_processing,
                "route_allows_processing": allow_processing,
            }
        )
    if requires_sensitive and not server_allows_sensitive:
        blocked_actions.append({"action": "sensitive_credential_reveal", "reason": "Requires MCP server startup flag --allow-sensitive."})
    if requires_external_ai and not server_allows_external_ai:
        blocked_actions.append({"action": "external_ai_upload", "reason": "Requires MCP server startup flag --allow-external-ai."})

    return {
        "case_id": case_id,
        "question": question,
        "evidence_hint": evidence_hint,
        "intent": intent,
        "first_source": first_source,
        "recommended_tool": recommended_tool,
        "fallback_tools": fallback_tools,
        "source_order": source_order,
        "report_purpose": report_purpose,
        "report_names": report_names,
        "processing_requested": processing_requested,
        "processing_allowed": processing_permitted,
        "requires_sensitive": requires_sensitive,
        "sensitive_allowed": server_allows_sensitive,
        "requires_external_ai": requires_external_ai,
        "external_ai_allowed": server_allows_external_ai,
        "blocked_actions": blocked_actions,
        "reason": reason,
        "guardrails": [
            "Use existing generated reports before raw artifact queries when a report can answer the question.",
            "Use filesystem_entries through relic_query_evidence_contents for any file-listing or drive-contents question.",
            "Use parsed artifact tables before resources, packet files, or direct image tooling.",
            "Use processing, mounts, FLS, or recovery tools only after the user explicitly asks for that work and MCP processing is enabled.",
            "Do not reveal credentials or send data to external AI unless the corresponding MCP startup gate is enabled.",
        ],
    }


def _contains_any(text: str, needles: set[str]) -> bool:
    return any(needle in text for needle in needles)


def _dedupe_resource_rows(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    rows = []
    for row in resources:
        key = str(row.get("uri") or row.get("relative_path") or row.get("filename") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows


def _mcp_workflow_guide() -> dict[str, Any]:
    steps = [
        {"order": 1, "tool": "relic_route_question", "purpose": "Classify the examiner question and follow the returned source-of-truth order."},
        {"order": 2, "tool": "relic_case_readiness", "purpose": "Check doctor, workspace health, readiness, progress, and resume signals."},
        {"order": 3, "tool": "relic_workspace_map", "purpose": "Get cases, evidence, reports, packets, progress manifests, and active jobs."},
        {"order": 4, "tool": "relic_case_evidence_map", "purpose": "Review computers, images, report resources, memory sources, jobs, and processing state for one case."},
        {"order": 5, "tool": "relic_read_existing_report", "purpose": "For report-backed questions, read an existing generated report first and treat it as the source of truth."},
        {"order": 6, "tool": "relic_discover_report_exports", "purpose": "Find generated reports and packets by purpose and tags before querying lower-level artifacts."},
        {"order": 7, "tool": "relic_case_runbook", "purpose": "Get safe next commands and reasons based on current case state."},
        {"order": 8, "tool": "relic_artifact_search_sources", "purpose": "Check which source tables, fields, and row counts are available for search."},
        {"order": 9, "tool": "relic_query_evidence_contents", "purpose": "For evidence contents, drive contents, volume contents, or file-listing questions, query generated filesystem_entries first before considering live image, mount, or SleuthKit processing."},
        {"order": 10, "tool": "relic_lead_search", "purpose": "Run preset execution, USB, cloud, document, browser, or communications searches after existing reports have been checked."},
        {"order": 11, "tool": "relic_search_artifacts", "purpose": "Run ad hoc artifact searches with user, computer, source, and time filters after existing reports have been checked."},
        {"order": 12, "tool": "drilldown tools", "purpose": "Follow search result drilldown hints into file, USB, user, timeline, registry, cloud, communication, shortcut, or remote-access context."},
        {"order": 13, "tool": "relic_write_search_packet", "purpose": "Save repeatable searches, result hash sets, case counts, and result sets as examiner work product."},
        {"order": 14, "tool": "relic_rerun_search_packet", "purpose": "Rerun saved searches and compare added, removed, changed, and unchanged results."},
        {"order": 15, "tool": "relic_write_review_packet", "purpose": "Save selected findings, notes, timeline slices, and report URIs."},
        {"order": 16, "tool": "relic_write_report_bundle", "purpose": "Export a review bundle for handoff or UI consumption. Use purpose=review for MCP/operator review packs."},
    ]
    return {
        "title": "Relic MCP Workflow Guide",
        "summary": {"step_count": len(steps)},
        "steps": steps,
        "recommended_presets": ["execution", "usb", "cloud", "documents", "browser", "communications"],
        "route_first_tool": "relic_route_question",
        "reports_first_tool": "relic_read_existing_report",
        "evidence_contents_first_tool": "relic_query_evidence_contents",
        "filesystem_first_tool": "relic_query_filesystem_listings",
        "packet_tools": ["relic_write_search_packet", "relic_list_search_packets", "relic_rerun_search_packet", "relic_write_review_packet", "relic_list_review_packets"],
    }


def _list_packet_files(root: Path, packet_dir: Path, *, limit: int, suffix: str) -> dict[str, Any]:
    packets = []
    root_resolved = root.resolve()
    packet_dir_resolved = packet_dir.resolve()
    case_id = _case_id_from_relative(packet_dir_resolved.relative_to(root_resolved)) if _is_relative_to(packet_dir_resolved, root_resolved) else ""
    if packet_dir.exists():
        for path in sorted(packet_dir.glob(f"*{suffix}"), key=lambda item: item.stat().st_mtime, reverse=True)[:limit]:
            payload = _load_json_file(path)
            stat = path.stat()
            markdown_path = path.with_suffix(".md")
            packets.append(
                {
                    "case_id": payload.get("case_id") or case_id,
                    "title": payload.get("title") or path.stem,
                    "created_at": payload.get("created_at") or "",
                    "json_uri": _resource_uri(path.resolve().relative_to(root_resolved)),
                    "markdown_uri": _resource_uri(markdown_path.resolve().relative_to(root_resolved)) if markdown_path.exists() else "",
                    "relative_path": str(path.resolve().relative_to(root_resolved)),
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                }
            )
    return {"case_id": case_id, "packets": packets, "summary": {"packet_count": len(packets), "limit": limit}}


def _read_packet_resource(root: Path, uri: str, *, directory_name: str, label: str) -> dict[str, Any]:
    path = _path_from_resource_uri(root, uri)
    packet_dir_token = f"{os.sep}{directory_name}{os.sep}"
    if packet_dir_token not in str(path) or path.suffix.casefold() not in {".json", ".md"}:
        raise ValueError(f"URI is not a {label} packet resource")
    if path.stat().st_size > MCP_RESOURCE_MAX_BYTES:
        raise ValueError(f"{label.title()} packet is too large to read through MCP: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    payload = json.loads(text) if path.suffix.casefold() == ".json" else None
    return {
        "uri": uri,
        "path": str(path),
        "format": path.suffix.casefold().lstrip("."),
        "text": text,
        "packet": payload,
    }


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


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


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
