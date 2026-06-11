from __future__ import annotations

import json
import mimetypes
import os
import re
import secrets
import signal
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable, TextIO
from urllib.parse import quote, unquote
import uuid

from .config import default_plugin_path
from .db import Database
from .jobs import command_timeout_seconds
from .paths import WorkspacePaths, validate_workspace_id
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
    clipboard_report,
    cloud_artifacts_report,
    communications_report,
    external_storage_report,
    evidence_gaps_report,
    file_movement_identity_report,
    investigation_findings_report,
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
    system_users_report,
    user_activity_report,
    wifi_activity_report,
    workspace_health_report,
    _query_report_rows,
)
from .search.opensearch import OpenSearchConfig, OpenSearchRestClient, search_case_content
from .standalone import doctor_report, job_status_report
from .tools.profiles import profile_extraction_preview
from .tools.registry import ToolRegistry


SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SUPPORTED_MCP_REPORTS = {
    "dashboard",
    "progress",
    "resume-plan",
    "external-storage",
    "investigation-findings",
    "suspicious-executions",
    "interesting-executables",
    "software-footprint-review",
    "event-interpretation",
    "file-movement-identity",
    "opened-from-removable-media",
    "opened-from-cloud-storage",
    "memory-analysis",
    "memory-artifacts",
    "structured-memory",
    "cloud-artifacts",
    "bits-activity",
    "clipboard",
    "examiner-edge-artifacts",
    "mapped-network-paths",
    "non-standard-ads",
    "ntfs-security-descriptors",
    "remote-access-tool-logs",
    "windows-activities",
    "usb-files",
    "usb-timeline",
}
MCP_JOB_INDEX = "index.json"
MCP_AUDIT_LOG = "audit.jsonl"
MCP_POLICY_FILE = "mcp-policy.json"
MCP_RESOURCE_MAX_BYTES = 1_000_000
DEFAULT_MCP_REPORT_EXPORT_LIMIT = 10_000
DEFAULT_MCP_REPORT_BUNDLE_LIMIT = 50_000
DEFAULT_MCP_MAX_RUNNING_JOBS = 4
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


def _mcp_tool_aliases(tools: list[McpTool]) -> dict[str, McpTool]:
    aliases: dict[str, McpTool] = {}
    for tool in tools:
        if tool.name.startswith("relic_"):
            perceptor_name = "perceptor_" + tool.name.removeprefix("relic_")
            aliases[perceptor_name] = replace(
                tool,
                name=perceptor_name,
                title=tool.title.replace("relic", "perceptor"),
                description=tool.description.replace("relic_", "perceptor_").replace("perceptor CLI", "perceptor CLI"),
            )
        aliases[tool.name] = tool
    return aliases


def _legacy_mcp_tool_name(name: str) -> str:
    if name.startswith("perceptor_"):
        return "relic_" + name.removeprefix("perceptor_")
    return name


class PerceptorMcpServer:
    def __init__(
        self,
        *,
        root: Path,
        allow_processing: bool = False,
        allow_sensitive: bool = False,
        allow_external_ai: bool = False,
        plugin_paths: list[Path] | None = None,
        auth_token: str | None = None,
        max_running_jobs: int | None = None,
    ) -> None:
        self.paths = WorkspacePaths(root)
        self.allow_processing = allow_processing
        self.allow_sensitive = allow_sensitive
        self.allow_external_ai = allow_external_ai
        self.plugin_paths = plugin_paths or [default_plugin_path()]
        self.auth_token = auth_token if auth_token is not None else (
            os.environ.get("PERCEPTOR_MCP_TOKEN") or os.environ.get("RELIC_MCP_TOKEN")
        )
        self.max_running_jobs = max_running_jobs or _env_int(
            "PERCEPTOR_MCP_MAX_RUNNING_JOBS",
            _env_int("RELIC_MCP_MAX_RUNNING_JOBS", DEFAULT_MCP_MAX_RUNNING_JOBS),
        )
        self.policy = self._load_mcp_policy()
        self._mcp_jobs: dict[str, dict[str, Any]] = self._load_mcp_job_index()
        self.tools = _mcp_tool_aliases(self._build_tools())

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            return self._error(None, -32600, "Invalid JSON-RPC message")
        request_id = message.get("id")
        method = str(message.get("method") or "")
        if request_id is None:
            self._handle_notification(method)
            return None
        try:
            self._require_auth(message)
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
            return self._error(request_id, -32602, _safe_error_message(exc), _error_details(exc))
        except Exception as exc:  # pragma: no cover - defensive protocol boundary
            return self._error(request_id, -32603, "Internal MCP server error; inspect the MCP audit log for details.", _error_details(exc))

    def _require_auth(self, message: dict[str, Any]) -> None:
        if not self.auth_token:
            return
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        token = (
            str(params.get("auth_token") or "")
            or str(params.get("authorization") or "")
            or str(message.get("auth_token") or "")
        )
        token = token.removeprefix("Bearer ").strip()
        if not secrets.compare_digest(token, self.auth_token):
            raise ValueError("MCP authentication failed")

    def _handle_notification(self, method: str) -> None:
        if method in {"notifications/initialized", "notifications/cancelled"}:
            return

    def _initialize_result(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = str(params.get("protocolVersion") or "")
        protocol_version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return {
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {"listChanged": False}, "resources": {"subscribe": False, "listChanged": False}},
            "serverInfo": {"name": "perceptor", "version": _package_version()},
            "instructions": (
                "Perceptor MCP exposes forensic workspace tools. Inspection and report-generation tools are available by default. "
                "For broad questions, call perceptor_route_question first to classify the request and receive the source-of-truth order. "
                "For matter background or scope context, call perceptor_case_summary or perceptor_report_case_overview first; case descriptions "
                "stored with `case describe` are returned there. "
                "For report-backed questions, call perceptor_read_existing_report or perceptor_discover_reports first and treat generated reports "
                "as the source of truth before querying raw artifacts or starting processing. "
                "For questions phrased as evidence contents, drive contents, files on a volume, or list files, call "
                "perceptor_query_evidence_contents; do not start filesystem processing, mounts, or SleuthKit/FLS unless stored "
                "listings are absent, stale, or the user explicitly requests new processing. "
                "For filesystem/file-listing questions, call perceptor_query_filesystem_listings first because it reads generated "
                "case file listings and avoids slow image tooling. "
                "For Wi-Fi, WLAN, SSID, or network-connection questions, call perceptor_query_wifi_activity because it reconciles "
                "WLAN/NetworkProfile EVTX, SRUM, and NetworkList registry evidence. "
                "For questions about what happened during a Wi-Fi connection, first call perceptor_query_wifi_activity to resolve "
                "the session window, then call perceptor_timeline_window with that start/end. "
                "For file-content, document-text, body-text, or indexed-content search questions, call perceptor_search_content after "
                "checking relevant generated reports; it queries OpenSearch indexed content and does not start image processing. "
                "Import and processing calls require --allow-processing. Sensitive credential reveal, external AI upload, "
                "and destructive actions are not implemented in the default MCP surface."
            ),
        }

    def _call_tool(self, params: dict[str, Any], *, request_id: object | None = None) -> dict[str, Any]:
        name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise ValueError("tools/call arguments must be an object")
        tool = self.tools.get(name) or self.tools.get(_legacy_mcp_tool_name(name))
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")
        correlation_id = str(uuid.uuid4())
        started = datetime.now(timezone.utc)
        self._require_permission(tool.permission)
        self._require_policy(tool, arguments)
        try:
            result = tool.handler(arguments)
            result = _add_result_limit_guidance(result, arguments, tool)
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
                title="Perceptor Workspace Summary",
                description="Summarize the configured Perceptor workspace and top-level case/job counts.",
                input_schema=_object_schema({}),
                handler=self.workspace_summary,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_cases",
                title="List Perceptor Cases",
                description="List cases in the configured Perceptor workspace.",
                input_schema=_object_schema({"limit": _integer_schema("Maximum cases to return.", default=100, minimum=1, maximum=1000)}),
                handler=self.list_cases,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_summary",
                title="Perceptor Case Summary",
                description="Return computers, images, parsed row counts, artifacts, jobs, warnings, and errors for a case.",
                input_schema=_object_schema({"case_id": _string_schema("Perceptor case ID.")}, required=["case_id"]),
                handler=self.case_summary,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_evidence_map",
                title="Perceptor Case Evidence Map",
                description="Return case computers, images, report resources, memory sources, jobs, and processing state in one response.",
                input_schema=_case_limit_schema(default=100),
                handler=self.case_evidence_map,
                annotations=read_only,
            ),
            McpTool(
                name="relic_workspace_map",
                title="Perceptor Workspace Map",
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
                title="Perceptor MCP Workflow Guide",
                description="Return the recommended MCP workflow for case review, lead searches, drilldowns, packets, and exports.",
                input_schema=_object_schema({}),
                handler=self.mcp_workflow_guide,
                annotations=read_only,
            ),
            McpTool(
                name="relic_route_question",
                title="Perceptor Route Question",
                description=(
                    "Classify an examiner question and return the correct Perceptor source-of-truth order. "
                    "Use this before answering broad MCP questions, especially filesystem, USB, report, memory, "
                    "timeline, processing, recovery, credential, or external-AI requests."
                ),
                input_schema=_object_schema(
                    {
                        "question": _string_schema("Natural-language examiner question to route."),
                        "case_id": _string_schema("Optional Perceptor case ID for report candidate discovery."),
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
                title="Perceptor Case Readiness",
                description="Return MCP-friendly doctor, workspace health, processing readiness, progress, and resume signals.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Optional Perceptor case ID."),
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
                title="Perceptor Discover Reports",
                description="Discover existing report bundle files and resource URIs for a case. Use this before raw artifact queries or report generation.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="Perceptor Discover Report Exports",
                description="Discover existing report bundle exports by purpose and report-index tags. Use this before raw artifact queries or report generation.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="Read Existing Perceptor Report",
                description=(
                    "Find and read an existing generated report for a case by report name, purpose, tag, or text. "
                    "This is the first source of truth for report-backed MCP questions."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="Perceptor Case Dashboard",
                description="Return the high-level investigation dashboard for a case.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_dashboard,
                annotations=read_only,
            ),
            McpTool(
                name="relic_processing_progress",
                title="Perceptor Processing Progress",
                description="Return active/failed timings and recent jobs for a case.",
                input_schema=_case_limit_schema(default=50),
                handler=self.processing_progress,
                annotations=read_only,
            ),
            McpTool(
                name="relic_resume_plan",
                title="Perceptor Resume Plan",
                description="Return recommended next commands after interrupted or partial processing.",
                input_schema=_case_limit_schema(default=50),
                handler=self.resume_plan,
                annotations=read_only,
            ),
            McpTool(
                name="relic_workspace_health",
                title="Perceptor Workspace Health",
                description="Check workspace disk, temp, and case health indicators.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Optional Perceptor case ID."),
                        "min_free_gb": {"type": "number", "description": "Minimum free GB warning threshold.", "default": 10.0},
                    }
                ),
                handler=self.workspace_health,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_computers",
                title="List Perceptor Computers",
                description="List computers attached to a case.",
                input_schema=_object_schema({"case_id": _string_schema("Perceptor case ID.")}, required=["case_id"]),
                handler=self.list_computers,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_images",
                title="List Perceptor Images",
                description="List images attached to a case.",
                input_schema=_object_schema({"case_id": _string_schema("Perceptor case ID.")}, required=["case_id"]),
                handler=self.list_images,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_jobs",
                title="List Perceptor Jobs",
                description="List recent jobs for a case.",
                input_schema=_case_limit_schema(default=100),
                handler=self.list_jobs,
                annotations=read_only,
            ),
            McpTool(
                name="relic_get_job",
                title="Get Perceptor Job",
                description="Return one job record by case ID and job ID.",
                input_schema=_object_schema(
                    {"case_id": _string_schema("Perceptor case ID."), "job_id": _string_schema("Perceptor job ID.")},
                    required=["case_id", "job_id"],
                ),
                handler=self.get_job,
                annotations=read_only,
            ),
            McpTool(
                name="relic_timeline",
                title="Perceptor Timeline",
                description="Query the normalized timeline for a case.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="Perceptor Timeline Window",
                description=(
                    "Return normalized master-timeline events for a case, optionally bounded by start/end. "
                    "Use this as the first source for questions about what happened during, around, or overlapping "
                    "a resolved activity window. For broad activity-window questions, do not pass the Wi-Fi SSID, "
                    "USB name, user term, or trigger phrase as contains; contains is only applied when "
                    "filter_within_window is true."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "limit": _integer_schema("Maximum events to return.", default=100, minimum=1, maximum=1000),
                        "start": _string_schema("Optional inclusive timestamp lower bound."),
                        "end": _string_schema("Optional inclusive timestamp upper bound."),
                        "user": _string_schema("Optional user/profile filter."),
                        "contains": _string_schema("Optional text filter. Ignored for start/end windows unless filter_within_window is true."),
                        "filter_within_window": {
                            "type": "boolean",
                            "default": False,
                            "description": "When true, apply contains inside the bounded window. Leave false for broad 'what happened during this session' questions.",
                        },
                        "source": _string_schema("Optional source filter."),
                        "preset": _string_schema("Optional timeline preset."),
                    },
                    required=["case_id"],
                ),
                handler=self.timeline_window,
                annotations=read_only,
            ),
            McpTool(
                name="relic_activity_windows",
                title="Perceptor Activity Windows",
                description=(
                    "Aggregate activity across multiple resolved time windows. Use this after tools such as "
                    "relic_query_wifi_activity return session_activity_plan.calls. This is the preferred tool for "
                    "questions like what happened while connected to a network when there are multiple sessions."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "windows": {
                            "type": "array",
                            "description": "Resolved windows to aggregate. Each item needs start and end.",
                            "items": _object_schema(
                                {
                                    "label": _string_schema("Optional window label."),
                                    "start": _string_schema("Inclusive start timestamp."),
                                    "end": _string_schema("Inclusive end timestamp."),
                                },
                                required=["start", "end"],
                            ),
                        },
                        "limit": _integer_schema("Maximum rows per window/source.", default=250, minimum=1, maximum=1000),
                    },
                    required=["case_id", "windows"],
                ),
                handler=self.activity_windows,
                annotations=read_only,
            ),
            McpTool(
                name="relic_file_dossier",
                title="Perceptor File Dossier",
                description=(
                    "Return a file-centric dossier by path or name. Use this for questions such as what can you tell me "
                    "about this file, file metadata, filesystem metadata for a file, internal metadata, and file provenance. "
                    "For broad filesystem listings, use relic_query_filesystem_listings first."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                        "case_id": _string_schema("Perceptor case ID."),
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
                    "Return file listings / drive contents for any evidence image, drive, volume, or filesystem from stored filesystem_entries only. "
                    "This does not return file text. For the text/content inside a specific file, use relic_file_dossier for metadata and then relic_search_content."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                name="relic_query_usb_contents",
                title="Query USB Contents",
                description=(
                    "Resolve a USB volume/device such as BYEBYE to stored filesystem_entries and USB file correlations. "
                    "Use this for questions like what else was on the USB drive, especially after relic_activity_windows "
                    "or relic_query_wifi_activity identifies a USB volume name or drive letter."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "volume_name": _string_schema("Optional USB volume label/name, for example BYEBYE."),
                        "image_id": _string_schema("Optional USB evidence image ID."),
                        "serial": _string_schema("Optional USB serial."),
                        "include_system": {"type": "boolean", "default": False},
                        "limit": _integer_schema("Maximum rows to return.", default=500, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.query_usb_contents,
                annotations=read_only,
            ),
            McpTool(
                name="relic_usb_dossier",
                title="Perceptor USB Dossier",
                description="Return a USB/storage-device dossier by serial, volume serial, or volume GUID.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="Perceptor User Activity",
                description=(
                    "Return user-focused execution, file, browser, logon, communication, and USB activity. "
                    "This is not the source of truth for bounded activity-window questions such as what happened "
                    "during a Wi-Fi connection, USB attachment, logon session, or other resolved time span; use "
                    "relic_timeline_window with start/end for those questions."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "user": _string_schema("User/profile text to review."),
                        "limit": _integer_schema("Maximum rows to return.", default=100, minimum=1, maximum=1000),
                    },
                    required=["case_id", "user"],
                ),
                handler=self.user_activity,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_system_users",
                title="Query System Users",
                description=(
                    "Return consolidated Windows local and Microsoft-account users for a case/computer. "
                    "Use this as the source of truth for questions about users, accounts, usernames, SIDs, "
                    "last logon, and Microsoft account InternetUserName before searching raw artifacts."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "computer_id": _string_schema("Optional computer ID filter."),
                        "include_builtin": {"type": "boolean", "default": True},
                        "limit": _integer_schema("Maximum users to return.", default=500, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.query_system_users,
                annotations=read_only,
                category="identity",
                tags=("users", "accounts", "sam", "sid", "microsoft-account", "read"),
                dependencies=("sam_accounts", "registry_artifacts"),
                source_priority=("parsed_artifact_tables", "generated_reports"),
                examples=(
                    {
                        "description": "List users and account types for a case.",
                        "arguments": {"case_id": "case-id", "include_builtin": False},
                    },
                ),
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
                name="relic_investigation_findings",
                title="Query Investigation Findings",
                description=(
                    "Return Perceptor's deterministic evidence-backed findings, entities, and relationship counts. "
                    "Use this before broad artifact searches when the user asks what happened, why something matters, "
                    "or how a conclusion is supported. Results are limited by count; increase limit or ask for source "
                    "evidence rows for the full picture."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "limit": _integer_schema("Maximum findings to return.", default=100, minimum=1, maximum=1000),
                        "rebuild": {"type": "boolean", "default": False, "description": "Rebuild derived entities, relationships, and findings before querying."},
                    },
                    required=["case_id"],
                ),
                handler=self.query_investigation_findings,
                annotations=read_only,
                category="analysis",
                tags=("findings", "entities", "relationships", "evidence", "narrative", "read"),
                dependencies=("parsed_artifact_tables", "timeline_events"),
                source_priority=("investigation_findings", "investigation_relationships", "investigation_entities", "parsed_artifact_tables"),
                examples=(
                    {
                        "description": "Ask for evidence-backed conclusions for a case.",
                        "arguments": {"case_id": "case-id", "limit": 25},
                    },
                ),
            ),
            McpTool(
                name="relic_query_external_storage",
                title="Query External Storage",
                description="Return external/removable storage summary and timeline context.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=250, minimum=1, maximum=1000),
                        "include_file_activity": {"type": "boolean", "default": True},
                    },
                    required=["case_id"],
                ),
                handler=self.query_external_storage,
                annotations=read_only,
            ),
            McpTool(
                name="relic_query_wifi_activity",
                title="Query Wi-Fi Activity",
                description=(
                    "Return reconciled Wi-Fi/network activity from WLAN and NetworkProfile EVTX events, SRUM "
                    "network_connectivity rows, and NetworkList registry artifacts. Use this for SSID, Wi-Fi, "
                    "wireless, WLAN, or network-connection questions before broad timeline searches. If the "
                    "user names a network such as Hyatt, Lemonade, or xfinitywifi, pass that name in the ssid argument. "
                    "For questions asking what happened while connected to a network, use session_activity_plan and "
                    "call session_activity_plan.aggregate_tool first; use per-session connection_sessions rows only for drilldown."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "start": _string_schema("Optional inclusive timestamp lower bound, for example 2025-11-17 00:00:00."),
                        "end": _string_schema("Optional exclusive timestamp upper bound, for example 2025-11-18 00:00:00."),
                        "ssid": _string_schema("Optional SSID/network name filter."),
                        "limit": _integer_schema("Maximum rows per source to return.", default=100, minimum=1, maximum=1000),
                    },
                    required=["case_id"],
                ),
                handler=self.query_wifi_activity,
                annotations=read_only,
                category="network",
                tags=("network", "wifi", "wlan", "ssid", "evtx", "srum", "registry", "read"),
                dependencies=("evtx_events", "srum_records", "registry_artifacts"),
                source_priority=("parsed_artifact_tables", "generated_reports"),
                examples=(
                    {
                        "description": "Review Wi-Fi activity for one day.",
                        "arguments": {"case_id": "case-id", "start": "2025-11-17 00:00:00", "end": "2025-11-18 00:00:00"},
                    },
                    {
                        "description": "Review evidence for one SSID.",
                        "arguments": {"case_id": "case-id", "ssid": "Lemonade", "start": "2025-11-17 00:00:00", "end": "2025-11-18 00:00:00"},
                    },
                ),
            ),
            McpTool(
                name="relic_query_usb_files",
                title="Query USB Files",
                description=(
                    "Return USB/removable-media file correlations from LNK, Jump List, and Shellbag artifacts. "
                    "Use this for questions about files opened from a USB device or volume; filter by any device name, "
                    "volume name, serial, volume serial, file name, or path before falling back to broader searches."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "limit": _integer_schema("Maximum rows to return.", default=500, minimum=1, maximum=1000),
                        "grouped": {"type": "boolean", "default": False},
                        "contains": _string_schema("Optional text filter across file name, file path, source artifact, device serial, volume name, and volume serial."),
                        "serial": _string_schema("Optional physical USB/device serial filter."),
                        "volume_serial_number": _string_schema("Optional volume serial filter. Matches both device-side and file-artifact-derived volume serials."),
                        "volume_name": _string_schema("Optional volume label/name filter, for example BYEBYE."),
                        "source_artifact_type": _string_schema("Optional source type filter, for example lnk, jumplist, or shellbag."),
                        "include_drive_roots": {"type": "boolean", "default": False},
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
                        "case_id": _string_schema("Perceptor case ID."),
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
                        "case_id": _string_schema("Perceptor case ID."),
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
                description=(
                    "Return browser host, download, WebCache, and cache correlation summary. Includes "
                    "attribution_warnings for mirrored cross-browser Chromium records, such as Edge visit_source=8, "
                    "which should not be treated alone as proof of active Edge browsing."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                        "case_id": _string_schema("Perceptor case ID."),
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
                        "case_id": _string_schema("Perceptor case ID."),
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
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="Perceptor Case Review",
                description="Return a combined investigative review across dashboard, suspicious execution, storage, cloud, movement, memory, browser, and communications.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_review,
                annotations=read_only,
            ),
            McpTool(
                name="relic_search_artifacts",
                title="Perceptor Artifact Search",
                description=(
                    "Search parsed artifact tables by text, user, computer, source type, and time bounds without requiring OpenSearch. "
                    "Use relic_route_question and existing reports first for broad review questions; for filesystem questions, use "
                    "relic_query_filesystem_listings first."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="Perceptor Artifact Search Sources",
                description="Return the artifact tables, categories, fields, and row counts covered by artifact and lead search.",
                input_schema=_object_schema({"case_id": _string_schema("Perceptor case ID.")}, required=["case_id"]),
                handler=self.artifact_search_sources,
                annotations=read_only,
            ),
            McpTool(
                name="relic_lead_search",
                title="Perceptor Lead Search",
                description=(
                    "Run preset artifact searches for execution, USB, cloud, documents, browser, or communications leads. "
                    "Use relic_route_question and existing reports first for broad review questions."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                name="relic_search_content",
                title="Perceptor OpenSearch Content Search",
                description=(
                    "Search full-text content indexed in OpenSearch, including extracted document text, mailbox bodies, "
                    "attachments, Windows Search indexed content, and other large text stores. Use existing generated reports "
                    "and filesystem listings first for report-backed or file-listing questions; use this tool when the examiner "
                    "asks to search file contents, body text, document text, or indexed content. Credentials are read from "
                    "FORENSIC_OPENSEARCH_* environment variables and are not accepted as MCP arguments."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "query": _string_schema("Required full-text content query."),
                        "limit": _integer_schema("Maximum content hits to return.", default=25, minimum=1, maximum=1000),
                        "url": _string_schema("Optional OpenSearch URL. Defaults to FORENSIC_OPENSEARCH_URL or http://localhost:9200."),
                        "index": _string_schema("Optional OpenSearch index. Defaults to FORENSIC_OPENSEARCH_INDEX or forensic-content."),
                        "insecure": {"type": "boolean", "default": False, "description": "Disable TLS certificate verification for this request."},
                        "no_synonyms": {"type": "boolean", "default": False, "description": "Disable built-in synonym expansion."},
                    },
                    required=["case_id", "query"],
                ),
                handler=self.search_content,
                annotations=read_only,
                category="search",
                tags=("search", "content", "opensearch", "read"),
                dependencies=("orchestrator.sqlite3", "OpenSearch", "FORENSIC_OPENSEARCH_* environment variables when authentication is required"),
                source_priority=("existing_reports", "opensearch_content_index", "parsed_artifact_tables"),
                examples=(
                    {
                        "description": "Search indexed file and message content for a phrase.",
                        "arguments": {"case_id": "case-id", "query": "confidential project notes", "limit": 25},
                    },
                ),
            ),
            McpTool(
                name="relic_get_indexed_content",
                title="Perceptor Get Indexed Content",
                description=(
                    "Return the stored full-text content for one OpenSearch content hit. Use the opensearch_document_id "
                    "returned by relic_search_content when the user wants to read more than the search snippet. "
                    "Credentials are read from FORENSIC_OPENSEARCH_* environment variables and are not accepted as MCP arguments."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID. The OpenSearch document must belong to this case."),
                        "opensearch_document_id": _string_schema("OpenSearch document ID returned by relic_search_content."),
                        "max_chars": _integer_schema("Maximum indexed-content characters to return.", default=20000, minimum=1, maximum=1000000),
                        "url": _string_schema("Optional OpenSearch URL. Defaults to FORENSIC_OPENSEARCH_URL or http://localhost:9200."),
                        "index": _string_schema("Optional OpenSearch index. Defaults to FORENSIC_OPENSEARCH_INDEX or forensic-content."),
                        "insecure": {"type": "boolean", "default": False, "description": "Disable TLS certificate verification for this request."},
                    },
                    required=["case_id", "opensearch_document_id"],
                ),
                handler=self.get_indexed_content,
                annotations=read_only,
                category="search",
                tags=("search", "content", "opensearch", "read", "drilldown"),
                dependencies=("OpenSearch", "FORENSIC_OPENSEARCH_* environment variables when authentication is required"),
                source_priority=("opensearch_content_index", "parsed_artifact_tables", "existing_reports"),
                examples=(
                    {
                        "description": "Read full indexed text for a content-search hit.",
                        "arguments": {"case_id": "case-id", "opensearch_document_id": "opensearch-doc-id", "max_chars": 20000},
                    },
                ),
            ),
            McpTool(
                name="relic_case_activity_digest",
                title="Perceptor Case Activity Digest",
                description="Return a compact digest of recent activity, suspicious execution, storage, cloud/removable opens, gaps, and next actions.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_activity_digest,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_next_actions",
                title="Perceptor Case Next Actions",
                description="Return ranked next investigative actions from readiness, gaps, unmapped imports, suspicious execution, USB, and cloud findings.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_next_actions,
                annotations=read_only,
            ),
            McpTool(
                name="relic_case_runbook",
                title="Perceptor Case Runbook",
                description="Return safe next commands and reasons based on review status, readiness, packets, reports, and gaps.",
                input_schema=_case_limit_schema(default=25),
                handler=self.case_runbook,
                annotations=read_only,
            ),
            McpTool(
                name="relic_write_review_packet",
                title="Write Perceptor Review Packet",
                description="Write a small MCP review packet with selected findings, report URIs, timeline slices, and examiner notes.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="List Perceptor Review Packets",
                description="List MCP review packets previously written for a case.",
                input_schema=_case_limit_schema(default=50),
                handler=self.list_review_packets,
                annotations=read_only,
            ),
            McpTool(
                name="relic_read_review_packet",
                title="Read Perceptor Review Packet",
                description="Read a saved MCP review packet JSON or Markdown resource.",
                input_schema=_object_schema({"uri": _string_schema("Review packet resource URI.")}, required=["uri"]),
                handler=self.read_review_packet,
                annotations=read_only,
            ),
            McpTool(
                name="relic_write_search_packet",
                title="Write Perceptor Search Packet",
                description="Run and save an artifact or preset lead search packet with filters and result counts.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
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
                title="List Perceptor Search Packets",
                description="List MCP search packets previously written for a case.",
                input_schema=_case_limit_schema(default=50),
                handler=self.list_search_packets,
                annotations=read_only,
            ),
            McpTool(
                name="relic_read_search_packet",
                title="Read Perceptor Search Packet",
                description="Read a saved MCP search packet JSON or Markdown resource.",
                input_schema=_object_schema({"uri": _string_schema("Search packet resource URI.")}, required=["uri"]),
                handler=self.read_search_packet,
                annotations=read_only,
            ),
            McpTool(
                name="relic_rerun_search_packet",
                title="Rerun Perceptor Search Packet",
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
                title="Perceptor Triage ZIP Preflight",
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
                title="Perceptor Report Bundle Coverage",
                description="Inspect report-bundle parser coverage for a folder or ZIP.",
                input_schema=_object_schema({"path": _string_schema("Optional report bundle folder or ZIP path.")}),
                handler=self.report_bundle_coverage,
                annotations=read_only,
            ),
            McpTool(
                name="relic_profile_preview",
                title="Perceptor Profile Preview",
                description="Preview extraction and tool coverage for a Perceptor processing profile.",
                input_schema=_object_schema({"profile": _string_schema("Perceptor profile name.")}, required=["profile"]),
                handler=self.profile_preview,
                annotations=read_only,
            ),
            McpTool(
                name="relic_doctor",
                title="Perceptor Doctor",
                description="Run Perceptor doctor checks. This MCP tool does not repair dependencies.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Optional Perceptor case ID."),
                        "profile": _string_schema("Optional profile name."),
                        "smoke": {"type": "boolean", "description": "Run a small isolated smoke test.", "default": False},
                    }
                ),
                handler=self.doctor,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_report_types",
                title="Perceptor Report Types",
                description="List report types supported by the generic MCP report runner.",
                input_schema=_object_schema({}),
                handler=self.list_report_types,
                annotations=read_only,
            ),
            McpTool(
                name="relic_mcp_tool_reference",
                title="Perceptor MCP Tool Reference",
                description="Return MCP tool names, permission tiers, annotations, and schemas.",
                input_schema=_object_schema({}),
                handler=self.mcp_tool_reference,
                annotations=read_only,
            ),
            McpTool(
                name="relic_generate_report",
                title="Perceptor Generate Report",
                description="Return an existing generated report when available; regenerate through the Perceptor CLI only when regenerate=true or no matching report exists.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "report_name": _string_schema("Supported report name."),
                        "format": {"type": "string", "enum": ["json", "table", "csv", "md"], "default": "json"},
                        "category": _string_schema("Optional report-specific category filter. Supported by event-interpretation."),
                        "contains": _string_schema("Optional report-specific text filter. Supported by clipboard."),
                        "limit": _integer_schema(
                            "Maximum rows to return. Defaults high for saved/generated reports; increase if result_limit_warning indicates truncation.",
                            default=DEFAULT_MCP_REPORT_EXPORT_LIMIT,
                            minimum=1,
                            maximum=DEFAULT_MCP_REPORT_EXPORT_LIMIT,
                        ),
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
                title="Perceptor Write Report Bundle",
                description="Write a purpose-built report bundle under the workspace root.",
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "output_dir": _string_schema("Output directory under the workspace root."),
                        "purpose": {"type": "string", "enum": ["full", "usb", "cloud", "execution", "memory", "triage", "review"], "default": "full"},
                        "limit": _integer_schema(
                            "Maximum rows per report. Defaults high for saved bundles; increase if any report indicates truncation.",
                            default=DEFAULT_MCP_REPORT_BUNDLE_LIMIT,
                            minimum=1,
                            maximum=DEFAULT_MCP_REPORT_BUNDLE_LIMIT,
                        ),
                    },
                    required=["case_id", "output_dir"],
                ),
                handler=self.write_report_bundle,
                annotations=safe_write,
                permission="safe_write",
            ),
            McpTool(
                name="relic_get_mcp_job",
                title="Get Perceptor MCP Job",
                description="Return persisted status for a long-running process launched by MCP.",
                input_schema=_object_schema({"mcp_job_id": _string_schema("MCP job ID returned by a processing tool.")}, required=["mcp_job_id"]),
                handler=self.get_mcp_job,
                annotations=read_only,
            ),
            McpTool(
                name="relic_list_mcp_jobs",
                title="List Perceptor MCP Jobs",
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
                title="Get Perceptor MCP Job Output",
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
                title="Get Perceptor MCP Job Progress",
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
                title="List Perceptor Progress Manifests",
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
                title="Cancel Perceptor MCP Job",
                description="Cancel a running MCP-launched subprocess. Requires --allow-processing.",
                input_schema=_object_schema({"mcp_job_id": _string_schema("MCP job ID returned by a processing tool.")}, required=["mcp_job_id"]),
                handler=self.cancel_mcp_job,
                annotations=processing,
                permission="processing",
            ),
            McpTool(
                name="relic_import_triage_zip",
                title="Perceptor Import Triage ZIP",
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
                title="Perceptor Import Report Bundle",
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
                title="Perceptor Process Image",
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
                title="Perceptor Run Profile",
                description=(
                    "Start a gated profile run against an existing case image as a background MCP job only when the user explicitly "
                    "asks to run processing. Do not use this for read-only questions; use existing reports and parsed artifact tables first."
                ),
                input_schema=_object_schema(
                    {
                        "case_id": _string_schema("Perceptor case ID."),
                        "image_id": _string_schema("Perceptor image ID."),
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
                        "case_id": _string_schema("Perceptor case ID."),
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
            start = _optional_text(arguments, "start")
            end = _optional_text(arguments, "end")
            if start or end:
                requested_contains = _optional_text(arguments, "contains")
                filter_within_window = bool(arguments.get("filter_within_window", False))
                result = timeline_report(
                    db,
                    _required(arguments, "case_id"),
                    limit=_limit(arguments, default=100),
                    contains=requested_contains if filter_within_window else None,
                    start=start,
                    end=end,
                )
                result["source_of_truth"] = "normalized_master_timeline"
                result["requested_contains"] = requested_contains
                result["filter_within_window"] = filter_within_window
                if requested_contains and not filter_within_window:
                    result["ignored_contains"] = requested_contains
                window_summary = result.get("window_summary") if isinstance(result.get("window_summary"), dict) else {}
                highlights = window_summary.get("activity_highlights") if isinstance(window_summary.get("activity_highlights"), dict) else {}
                activity_counts: dict[str, int] = {}
                activity_events: dict[str, list[dict[str, Any]]] = {}
                for key in (
                    "browser_activity",
                    "usb_activity",
                    "file_activity",
                    "execution_activity",
                    "communication_activity",
                    "network_activity",
                ):
                    value = highlights.get(key) if isinstance(highlights.get(key), dict) else {}
                    activity_events[key] = value.get("events", [])
                    activity_counts[key] = int(value.get("count") or 0)
                guidance = (
                    "This is the master timeline with interval-overlap matching. For broad activity-window questions, "
                    "review the unfiltered window first; only use contains with filter_within_window=true when the user "
                    "explicitly asks to search for a term inside the window. Use browser_activity, usb_activity, "
                    "file_activity, execution_activity, communication_activity, and network_activity for the first "
                    "summary pass; use source_table/source_row_id for drilldown."
                )
                return _timeline_window_activity_response(
                    result,
                    activity_counts=activity_counts,
                    activity_events=activity_events,
                    highlights=highlights,
                    guidance=guidance,
                    requested_contains=requested_contains,
                    filter_within_window=filter_within_window,
                    ignored_contains=requested_contains if requested_contains and not filter_within_window else None,
                )
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

    def activity_windows(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        windows_arg = arguments.get("windows")
        if not isinstance(windows_arg, list) or not windows_arg:
            raise ValueError("windows must be a non-empty list")
        limit = _limit(arguments, default=250)
        windows: list[dict[str, Any]] = []
        for index, item in enumerate(windows_arg, start=1):
            if not isinstance(item, dict):
                raise ValueError("each window must be an object with start and end")
            start = str(item.get("start") or "").strip()
            end = str(item.get("end") or "").strip()
            if not start or not end:
                raise ValueError("each window must include start and end")
            windows.append({"index": index, "label": str(item.get("label") or f"window-{index}"), "start": start, "end": end})
        window_results = []
        totals: dict[str, int] = {}
        combined: dict[str, list[dict[str, Any]]] = {
            "browser_activity": [],
            "usb_activity": [],
            "usb_file_interaction": [],
            "file_activity": [],
            "onedrive_file_activity": [],
            "desktop_file_activity": [],
            "onedrive_desktop_file_activity": [],
            "execution_activity": [],
            "communication_activity": [],
            "network_activity": [],
        }
        direct_source_rows: dict[str, list[dict[str, Any]]] = {}
        direct_counts: dict[str, int] = {}
        for window in windows:
            result = self.timeline_window({"case_id": case_id, "start": window["start"], "end": window["end"], "limit": limit})
            result["window_index"] = window["index"]
            result["window_label"] = window["label"]
            window_results.append(
                {
                    "index": window["index"],
                    "label": window["label"],
                    "start": window["start"],
                    "end": window["end"],
                    "activity_counts": result.get("activity_answer", {}).get("activity_counts", {}),
                    "direct_activity_counts": result.get("direct_activity_counts", {}),
                    "folder_activity_counts": result.get("activity_answer", {}).get("folder_activity_counts", {}),
                    "browser_activity_count": result.get("browser_activity_count", 0),
                    "usb_activity_count": result.get("usb_activity_count", 0),
                    "usb_file_interaction_count": result.get("usb_file_interaction_count", 0),
                }
            )
            for key, value in (result.get("activity_answer", {}).get("activity_counts") or {}).items():
                totals[key] = totals.get(key, 0) + int(value or 0)
            for key, value in (result.get("direct_activity_counts") or {}).items():
                direct_counts[key] = direct_counts.get(key, 0) + int(value or 0)
            for key in combined:
                combined[key].extend(_tag_window_rows(result.get(key) or [], window))
            sources = ((result.get("direct_activity") or {}).get("sources") or {})
            for source_key, source in sources.items():
                if not isinstance(source, dict):
                    continue
                direct_source_rows.setdefault(source_key, []).extend(_tag_window_rows(source.get("rows") or [], window))
        for key in list(combined):
            combined[key] = _dedupe_activity_rows(combined[key])[:limit]
        for key in list(direct_source_rows):
            direct_source_rows[key] = _dedupe_activity_rows(direct_source_rows[key])[:limit]
        usb_identity_summary = _usb_identity_summary_for_activity_windows(self, case_id, combined, limit=limit)
        summary = _activity_windows_summary(totals, direct_counts, combined)
        summary["usb_identity_summary"] = usb_identity_summary
        return {
            "case_id": case_id,
            "source_of_truth": "aggregated_activity_windows",
            "window_count": len(windows),
            "activity_answer": summary,
            "activity_counts": totals,
            "direct_activity_counts": direct_counts,
            "windows": window_results,
            "browser_activity": combined["browser_activity"],
            "usb_activity": combined["usb_activity"],
            "usb_file_interaction": combined["usb_file_interaction"],
            "file_activity": combined["file_activity"],
            "onedrive_file_activity": combined["onedrive_file_activity"],
            "desktop_file_activity": combined["desktop_file_activity"],
            "onedrive_desktop_file_activity": combined["onedrive_desktop_file_activity"],
            "execution_activity": combined["execution_activity"],
            "communication_activity": combined["communication_activity"],
            "network_activity": combined["network_activity"],
            "usb_identity_summary": usb_identity_summary,
            "direct_activity_sources": direct_source_rows,
            "guidance": "This aggregates every supplied window. Use this for multi-session network questions before drawing conclusions.",
        }

    def file_dossier(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            result = file_dossier_report(
                db,
                _required(arguments, "case_id"),
                path=_optional_text(arguments, "path"),
                name=_optional_text(arguments, "name"),
                limit=_limit(arguments, default=100),
            )
            query_text = _optional_text(arguments, "path") or _optional_text(arguments, "name") or ""
            result["content_followup"] = {
                "required_for_content_questions": True,
                "tool": "relic_search_content",
                "arguments": {
                    "case_id": result.get("case_id"),
                    "query": query_text,
                    "limit": 10,
                },
                "next_step": "If relic_search_content returns full_content_available=true, call relic_get_indexed_content with that hit's opensearch_document_id.",
                "reason": "A file dossier focuses on metadata/provenance. File text/content lives in the OpenSearch content index when extracted or indexed.",
            }
            return result
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

    def query_usb_contents(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        volume_name = _optional_text(arguments, "volume_name")
        image_id = _optional_text(arguments, "image_id")
        limit = _limit(arguments, default=500)
        include_system = bool(arguments.get("include_system", False))
        db = self._db()
        try:
            resolved_image_ids = [image_id] if image_id else _resolve_usb_content_image_ids(db, case_id, volume_name=volume_name)
            entries: list[dict[str, Any]] = []
            for resolved_image_id in resolved_image_ids:
                listing = filesystem_listing_report(
                    db,
                    case_id,
                    image_id=resolved_image_id,
                    include_deleted=True,
                    include_virtual=True,
                    limit=limit,
                )
                for row in listing.get("filesystem_entries") or []:
                    if not include_system and str(row.get("scan_status") or "").casefold() == "system":
                        continue
                    entries.append(row)
            if volume_name and not entries:
                listing = filesystem_listing_report(
                    db,
                    case_id,
                    contains=volume_name,
                    include_deleted=True,
                    include_virtual=True,
                    limit=limit,
                )
                entries.extend(listing.get("filesystem_entries") or [])
            status_counts: dict[str, int] = {}
            for row in entries:
                status = str(row.get("scan_status") or "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1
            usb_files = usb_file_correlation_report(
                db,
                case_id,
                limit=limit,
                persist=False,
                grouped=False,
                serial=_optional_text(arguments, "serial"),
                volume_name=volume_name,
                include_drive_roots=True,
            )
            return {
                "case_id": case_id,
                "source_of_truth": "filesystem_entries_and_usb_file_correlations",
                "filters": {
                    "volume_name": volume_name,
                    "image_id": image_id,
                    "resolved_image_ids": resolved_image_ids,
                    "include_system": include_system,
                },
                "summary": {
                    "filesystem_entry_count": len(entries),
                    "filesystem_status_counts": status_counts,
                    "usb_file_correlation_count": len(usb_files.get("items") or []),
                    "listing_available": bool(entries),
                },
                "filesystem_entries": entries[:limit],
                "usb_file_correlations": (usb_files.get("items") or [])[:limit],
                "guidance": (
                    "Use filesystem_entries for what was on the USB evidence image. Use usb_file_correlations for host artifacts "
                    "showing files/folders referenced from that USB. If listing_available is false, the USB image listing has not been generated."
                ),
            }
        finally:
            db.close()

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

    def query_system_users(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return system_users_report(
                db,
                _required(arguments, "case_id"),
                computer_id=_optional_text(arguments, "computer_id"),
                include_builtin=bool(arguments.get("include_builtin", True)),
                limit=_limit(arguments, default=500),
            )
        finally:
            db.close()

    def query_suspicious_executions(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            return suspicious_executions_report(db, _required(arguments, "case_id"), limit=_limit(arguments, default=100))
        finally:
            db.close()

    def query_investigation_findings(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            result = investigation_findings_report(
                db,
                _required(arguments, "case_id"),
                limit=_limit(arguments, default=100),
                rebuild=bool(arguments.get("rebuild", False)),
            )
            result["source_of_truth"] = "investigation_findings"
            result["usage_guidance"] = (
                "Use findings first for evidence-backed conclusions. Each finding includes rule metadata and "
                "supporting source_table/source_row_id evidence. The returned findings are count-limited; increase "
                "limit or query the referenced source artifacts for the complete evidence set."
            )
            return result
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

    def query_wifi_activity(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            result = wifi_activity_report(
                db,
                _required(arguments, "case_id"),
                start=_optional_text(arguments, "start"),
                end=_optional_text(arguments, "end"),
                ssid=_optional_text(arguments, "ssid"),
                limit=_limit(arguments, default=100),
            )
            result["source_of_truth"] = "parsed_network_artifact_tables"
            result["guidance"] = (
                "Use reconciled_networks first. Treat EVTX WLAN 8001 and NetworkProfile 10000 as stronger "
                "successful-connection evidence than SRUM alone; treat WLAN 8002 as failed-attempt evidence. "
                "For what happened while connected to a network, call session_activity_plan.aggregate_tool first. "
                "Use per-session relic_timeline_window calls only for drilldown. Do not answer from only the first "
                "session when multiple sessions are present. Do not use relic_user_activity for bounded activity-window questions."
            )
            result["next_step"] = {
                "for_activity_during_connection": "Call session_activity_plan.aggregate_tool to aggregate every matching session.",
                "tool": "relic_activity_windows",
                "argument_source": "session_activity_plan.aggregate_tool.arguments",
                "avoid": "relic_user_activity is narrower and can miss browser, cache, USB, filesystem, and other timeline events in the window.",
            }
            return result
        finally:
            db.close()

    def query_usb_files(self, arguments: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        try:
            result = usb_file_correlation_report(
                db,
                _required(arguments, "case_id"),
                limit=_limit(arguments, default=500),
                persist=False,
                grouped=bool(arguments.get("grouped") or False),
                contains=_optional_text(arguments, "contains"),
                serial=_optional_text(arguments, "serial"),
                volume_serial_number=_optional_text(arguments, "volume_serial_number"),
                volume_name=_optional_text(arguments, "volume_name"),
                source_artifact_type=_optional_text(arguments, "source_artifact_type"),
                include_drive_roots=bool(arguments.get("include_drive_roots") or False),
            )
            result["source_of_truth"] = "usb_file_correlations"
            result["guidance"] = (
                "For USB file questions, use items/files from this report before broad text search or filesystem listing. "
                "When usb_volume_serial_number is blank, use matched_volume_serial_number or artifact_volume_serial_number for the file-artifact-derived volume serial."
            )
            return result
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

    def search_content(self, arguments: dict[str, Any]) -> dict[str, Any]:
        query = _required(arguments, "query").strip()
        if not query:
            raise ValueError("query is required")
        config = OpenSearchConfig.from_values(
            url=_optional_text(arguments, "url"),
            index=_optional_text(arguments, "index"),
            insecure=bool(arguments.get("insecure") or False),
        )
        synonym_groups = [] if bool(arguments.get("no_synonyms") or False) else None
        result = search_case_content(
            case_id=_required(arguments, "case_id"),
            query=query,
            config=config,
            limit=_limit(arguments, default=25),
            synonym_groups=synonym_groups,
        )
        for hit in result.get("hits", []):
            if not isinstance(hit, dict):
                continue
            source_table = str(hit.get("source_table") or "")
            source_record_id = str(hit.get("source_record_id") or "")
            opensearch_document_id = str(hit.get("opensearch_document_id") or "")
            content_length = _safe_int(hit.get("content_length"))
            hit["snippet_note"] = "OpenSearch highlight fields are matching snippets, not the full indexed content."
            forensic_source_table = str(hit.get("forensic_source_table") or source_table)
            evidence_nature = str(hit.get("evidence_nature") or "")
            hit["provenance_summary"] = _indexed_content_provenance_summary(
                retrieval_backend="OpenSearch",
                storage_table=str(hit.get("storage_table") or source_table),
                forensic_source_table=forensic_source_table,
                evidence_nature=evidence_nature,
            )
            hit["full_content_available"] = bool(opensearch_document_id and content_length > 0)
            hit["full_content_tool"] = {
                "tool": "relic_get_indexed_content",
                "arguments": {
                    "case_id": result.get("case_id"),
                    "opensearch_document_id": opensearch_document_id,
                },
                "note": "Call this tool when the user wants to read the full indexed content for this hit.",
            }
            hit["drilldown"] = {
                "tool": "relic_file_dossier" if source_table in {"windows_search_indexed_content", "mailbox_attachments"} else "relic_search_artifacts",
                "source_table": source_table,
                "source_record_id": source_record_id,
                "note": "Use source_table and source_record_id to pivot into parsed metadata or related reports.",
            }
        result["source_of_truth"] = "opensearch_content_index"
        result["guidance"] = (
            "These hits come from OpenSearch indexed content. Highlight values are snippets only and are not the full "
            "indexed content. If the user wants to read the full indexed text for a hit, call relic_get_indexed_content "
            "with that hit's opensearch_document_id. Use generated reports/listings for high-level conclusions, then "
            "pivot from source_table/source_record_id into parsed metadata for provenance."
        )
        return result

    def get_indexed_content(self, arguments: dict[str, Any]) -> dict[str, Any]:
        case_id = _required(arguments, "case_id")
        document_id = _required(arguments, "opensearch_document_id")
        max_chars = _bounded_int(arguments, "max_chars", default=20000, minimum=1, maximum=1_000_000)
        config = OpenSearchConfig.from_values(
            url=_optional_text(arguments, "url"),
            index=_optional_text(arguments, "index"),
            insecure=bool(arguments.get("insecure") or False),
        )
        response = OpenSearchRestClient(config).request("GET", f"/{quote(config.index)}/_doc/{quote(document_id, safe='')}")
        source = response.get("_source") or {}
        actual_case_id = str(source.get("case_id") or "")
        if actual_case_id != case_id:
            raise ValueError("OpenSearch document does not belong to the requested case")
        content = str(source.get("content") or "")
        returned_content = content[:max_chars]
        metadata = source.get("metadata") if isinstance(source.get("metadata"), dict) else {}
        storage_table = str(metadata.get("storage_table") or source.get("source_table") or "")
        forensic_source_table = str(
            metadata.get("forensic_source_table")
            or metadata.get("windows_search_source_table")
            or storage_table
        )
        evidence_nature = str(
            metadata.get("evidence_nature")
            or _indexed_content_evidence_nature(forensic_source_table)
        )
        return {
            "case_id": case_id,
            "opensearch_document_id": document_id,
            "found": bool(response.get("found", True)),
            "source_of_truth": "opensearch_content_index",
            "retrieval_backend": "OpenSearch",
            "title": source.get("title"),
            "source_path": source.get("source_path"),
            "container_path": source.get("container_path"),
            "source_type": source.get("source_type"),
            "source_table": source.get("source_table"),
            "storage_table": storage_table,
            "forensic_source_table": forensic_source_table,
            "evidence_nature": evidence_nature,
            "direct_file_content_extraction": evidence_nature == "direct_file_content_extraction",
            "windows_search_artifact_content": evidence_nature == "windows_search_artifact_indexed_content",
            "source_record_id": source.get("source_record_id"),
            "computer_id": source.get("computer_id"),
            "image_id": source.get("image_id"),
            "timestamp": source.get("timestamp"),
            "user_profile": source.get("user_profile"),
            "content_hash": source.get("content_hash"),
            "content_length": _safe_int(source.get("content_length"), default=len(content)),
            "returned_content_length": len(returned_content),
            "truncated": len(content) > len(returned_content),
            "content": returned_content,
            "provenance_summary": _indexed_content_provenance_summary(
                retrieval_backend="OpenSearch",
                storage_table=storage_table,
                forensic_source_table=forensic_source_table,
                evidence_nature=evidence_nature,
            ),
            "guidance": (
                "This content was retrieved from OpenSearch. Use forensic_source_table/evidence_nature to identify "
                "whether the underlying forensic source was direct file-content extraction, Windows Search artifact "
                "content, email content, or another indexed source."
            ),
        }

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
        report = report_bundle_preflight_report(_input_path(self.paths.root, _required(arguments, "path")))
        _enforce_uncompressed_limit(report, float(arguments.get("max_uncompressed_gb") or 0.0))
        return report

    def report_bundle_coverage(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = str(arguments.get("path") or "").strip()
        return parser_coverage_report(_input_path(self.paths.root, path) if path else None)

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
            str(_limit(arguments, default=DEFAULT_MCP_REPORT_EXPORT_LIMIT, maximum=DEFAULT_MCP_REPORT_EXPORT_LIMIT)),
        ]
        if report_name == "event-interpretation":
            _extend_optional(command, "--category", arguments.get("category"))
        if report_name == "clipboard":
            _extend_optional(command, "--contains", arguments.get("contains"))
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
                limit=_limit(arguments, default=DEFAULT_MCP_REPORT_BUNDLE_LIMIT, maximum=DEFAULT_MCP_REPORT_BUNDLE_LIMIT),
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
        command = self._base_cli_command() + ["ingest", "triage-zip", "--path", str(_input_path(self.paths.root, _required(arguments, "path")))]
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
        command = self._base_cli_command() + ["report-bundle", "import", "--path", str(_input_path(self.paths.root, _required(arguments, "path")))]
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
            str(_input_path(self.paths.root, _required(arguments, "path"))),
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
        try:
            completed = subprocess.run(command, cwd=Path.cwd(), capture_output=True, text=True, check=False, timeout=command_timeout_seconds())
        except subprocess.TimeoutExpired as exc:
            return {
                "command": command,
                "returncode": -9,
                "status": "timeout",
                "stdout": str(exc.stdout or "")[-100_000:],
                "stderr": str(exc.stderr or "")[-20_000:],
                "json": None,
            }
        parsed_stdout = _json_value(completed.stdout, None) if completed.stdout.strip().startswith(("{", "[")) else None
        result = {
            "command": command,
            "returncode": completed.returncode,
            "status": "completed" if completed.returncode == 0 else "failed",
            "stdout": completed.stdout[-100_000:],
            "stderr": completed.stderr[-20_000:],
            "json": parsed_stdout,
        }
        if isinstance(parsed_stdout, dict):
            for key in ("total_returned", "total_available", "total_matching", "limit", "limited"):
                if key in parsed_stdout:
                    result[key] = parsed_stdout.get(key)
        return result

    def _start_mcp_process(self, name: str, command: list[str]) -> dict[str, Any]:
        running = self._running_mcp_jobs()
        if len(running) >= self.max_running_jobs:
            raise ValueError(f"MCP processing job limit reached ({len(running)}/{self.max_running_jobs}); wait for a job to finish or cancel one.")
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

    def _running_mcp_jobs(self) -> list[dict[str, Any]]:
        running: list[dict[str, Any]] = []
        for job in self._mcp_jobs.values():
            self._refresh_mcp_job(job)
            if job.get("status") == "running":
                running.append(job)
        if running:
            self._save_mcp_job_index()
        return running

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
        if case_id:
            validate_workspace_id(case_id, field="case_id")
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
            "auth_required": bool(self.auth_token),
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


RelicMcpServer = PerceptorMcpServer


def run_mcp_server(
    *,
    root: Path,
    allow_processing: bool = False,
    allow_sensitive: bool = False,
    allow_external_ai: bool = False,
    plugin_paths: list[Path] | None = None,
    auth_token: str | None = None,
    max_running_jobs: int | None = None,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
) -> int:
    server = PerceptorMcpServer(
        root=root,
        allow_processing=allow_processing,
        allow_sensitive=allow_sensitive,
        allow_external_ai=allow_external_ai,
        plugin_paths=plugin_paths,
        auth_token=auth_token,
        max_running_jobs=max_running_jobs,
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
            stdout.write(json.dumps(_decode_escaped_unicode(payload), default=str, ensure_ascii=False, separators=(",", ":")) + "\n")
            stdout.flush()
        except json.JSONDecodeError as exc:
            stdout.write(json.dumps(PerceptorMcpServer._error(None, -32700, "Parse error", str(exc)), separators=(",", ":")) + "\n")
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
    result = _decode_escaped_unicode(result)
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
        "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str, ensure_ascii=False)}],
        "structuredContent": result,
        "isError": is_error,
    }


def _decode_escaped_unicode(value: Any) -> Any:
    if isinstance(value, str):
        return _decode_escaped_unicode_text(value)
    if isinstance(value, list):
        return [_decode_escaped_unicode(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_decode_escaped_unicode(item) for item in value)
    if isinstance(value, dict):
        return {key: _decode_escaped_unicode(item) for key, item in value.items()}
    return value


def _decode_escaped_unicode_text(value: str) -> str:
    if "\\u" not in value and "\\U" not in value:
        return value
    pattern = re.compile(r"(?:\\u[0-9a-fA-F]{4}){2,}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}")

    def replace(match: re.Match[str]) -> str:
        try:
            decoded = json.loads(f'"{match.group(0)}"')
        except Exception:
            return match.group(0)
        return decoded if isinstance(decoded, str) else match.group(0)

    return pattern.sub(replace, value)


def _timeline_window_activity_response(
    result: dict[str, Any],
    *,
    activity_counts: dict[str, int],
    activity_events: dict[str, list[dict[str, Any]]],
    highlights: dict[str, Any],
    guidance: str,
    requested_contains: str | None,
    filter_within_window: bool,
    ignored_contains: str | None,
) -> dict[str, Any]:
    window_summary = result.get("window_summary") if isinstance(result.get("window_summary"), dict) else {}
    direct_activity = window_summary.get("direct_activity") if isinstance(window_summary.get("direct_activity"), dict) else {}
    direct_counts = direct_activity.get("summary_counts") if isinstance(direct_activity.get("summary_counts"), dict) else {}
    combined_counts = dict(activity_counts)
    for key, value in direct_counts.items():
        try:
            direct_value = int(value or 0)
        except (TypeError, ValueError):
            direct_value = 0
        combined_counts[key] = max(int(combined_counts.get(key) or 0), direct_value)
    browser_examples = _activity_examples(activity_events.get("browser_activity", []))
    folder_activity = highlights.get("folder_activity") if isinstance(highlights.get("folder_activity"), dict) else {}
    folder_counts = {
        key: int((value if isinstance(value, dict) else {}).get("count") or 0)
        for key, value in folder_activity.items()
    }
    folder_examples = {
        key: _activity_examples((value if isinstance(value, dict) else {}).get("events", []), limit=12)
        for key, value in folder_activity.items()
    }
    response: dict[str, Any] = {
        "case_id": result.get("case_id"),
        "source_of_truth": "normalized_master_timeline",
        "activity_answer": {
            "summary": _timeline_activity_summary_text(combined_counts, browser_examples),
            "time_window": {
                "start": (result.get("filters") or {}).get("start"),
                "end": (result.get("filters") or {}).get("end"),
                "time_match": (result.get("filters") or {}).get("time_match"),
            },
            "total_window_events": window_summary.get("total_events"),
            "activity_counts": combined_counts,
            "timeline_activity_counts": activity_counts,
            "direct_activity_counts": direct_counts,
            "folder_activity_counts": folder_counts,
            "browser_examples": browser_examples,
            "folder_examples": folder_examples,
        },
        "combined_activity_counts": combined_counts,
        "timeline_activity_counts": activity_counts,
        "direct_activity_counts": direct_counts,
        "direct_activity": direct_activity,
        "folder_activity": folder_activity,
        "onedrive_file_activity_count": folder_counts.get("onedrive_file_activity", 0),
        "onedrive_file_activity": (folder_activity.get("onedrive_file_activity") or {}).get("events", []),
        "desktop_file_activity_count": folder_counts.get("desktop_file_activity", 0),
        "desktop_file_activity": (folder_activity.get("desktop_file_activity") or {}).get("events", []),
        "onedrive_desktop_file_activity_count": folder_counts.get("onedrive_desktop_file_activity", 0),
        "onedrive_desktop_file_activity": (folder_activity.get("onedrive_desktop_file_activity") or {}).get("events", []),
        "usb_file_interaction_count": folder_counts.get("usb_file_interaction", 0),
        "usb_file_interaction": (folder_activity.get("usb_file_interaction") or {}).get("events", []),
        "browser_activity_count": combined_counts.get("browser_activity", 0),
        "browser_activity": activity_events.get("browser_activity", []),
        "usb_activity_count": combined_counts.get("usb_activity", 0),
        "usb_activity": activity_events.get("usb_activity", []),
        "file_activity_count": combined_counts.get("file_activity", 0),
        "file_activity": activity_events.get("file_activity", []),
        "execution_activity_count": combined_counts.get("execution_activity", 0),
        "execution_activity": activity_events.get("execution_activity", []),
        "communication_activity_count": combined_counts.get("communication_activity", 0),
        "communication_activity": activity_events.get("communication_activity", []),
        "network_activity_count": combined_counts.get("network_activity", 0),
        "network_activity": activity_events.get("network_activity", []),
        "guidance": guidance,
        "filters": result.get("filters"),
        "requested_contains": requested_contains,
        "filter_within_window": filter_within_window,
        "activity_highlights": highlights,
        "window_summary": window_summary,
        "events": result.get("events", []),
        "total_returned": result.get("total_returned"),
    }
    if ignored_contains:
        response["ignored_contains"] = ignored_contains
    return response


def _activity_examples(events: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    for event in events[:limit]:
        examples.append(
            {
                "timestamp_utc": event.get("timestamp_utc"),
                "event_type": event.get("event_type"),
                "source_table": event.get("source_table"),
                "description": event.get("description"),
                "computer": event.get("computer_label") or event.get("computer"),
            }
        )
    return examples


def _timeline_activity_summary_text(activity_counts: dict[str, int], browser_examples: list[dict[str, Any]]) -> str:
    browser_count = activity_counts.get("browser_activity", 0)
    if browser_count:
        first = browser_examples[0].get("description") if browser_examples else None
        return (
            f"Browser/web activity is present in this window ({browser_count} matching timeline events). "
            f"Start with browser_activity before summarizing the chronological events. First example: {first or 'available in browser_activity'}."
        )
    return "No browser/web activity was found in the categorized timeline highlights for this window; review other activity categories and raw events."


def _tag_window_rows(rows: list[dict[str, Any]], window: dict[str, Any]) -> list[dict[str, Any]]:
    tagged = []
    for row in rows:
        item = dict(row)
        item["window_index"] = window.get("index")
        item["window_label"] = window.get("label")
        item["window_start"] = window.get("start")
        item["window_end"] = window.get("end")
        tagged.append(item)
    return tagged


def _dedupe_activity_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    output = []
    for row in rows:
        key = (
            str(row.get("source_table") or ""),
            str(row.get("id") or row.get("source_row_id") or ""),
            str(row.get("timestamp_utc") or row.get("activity_time_utc") or ""),
            str(row.get("description") or row.get("activity_description") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def _activity_windows_summary(
    activity_counts: dict[str, int],
    direct_counts: dict[str, int],
    combined: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    usb_count = int(activity_counts.get("usb_activity") or 0) + int(direct_counts.get("device_activity") or 0)
    usb_file_count = len(combined.get("usb_file_interaction") or [])
    browser_count = int(activity_counts.get("browser_activity") or 0) or int(direct_counts.get("browser_activity") or 0)
    email_count = int(direct_counts.get("email_activity") or 0)
    execution_count = int(activity_counts.get("execution_activity") or 0) or int(direct_counts.get("application_execution") or 0)
    file_count = int(activity_counts.get("file_activity") or 0) + int(direct_counts.get("file_index_activity") or 0)
    findings = []
    if usb_count or usb_file_count:
        findings.append(f"USB/removable activity is present across the supplied windows ({usb_count} USB activity events, {usb_file_count} USB file-interaction rows returned).")
    else:
        findings.append("No USB/removable activity was found across the supplied windows.")
    if browser_count:
        findings.append(f"Browser/web activity is present ({browser_count} matching events).")
    if email_count:
        findings.append(f"Email activity is present ({email_count} messages).")
    if file_count:
        findings.append(f"File/index activity is present ({file_count} matching events/rows).")
    if execution_count:
        findings.append(f"Application execution/resource activity is present ({execution_count} matching events/rows).")
    return {
        "summary": " ".join(findings),
        "activity_counts": activity_counts,
        "direct_activity_counts": direct_counts,
        "usb_activity_present": bool(usb_count or usb_file_count),
        "browser_activity_present": bool(browser_count),
        "email_activity_present": bool(email_count),
        "file_activity_present": bool(file_count),
        "execution_activity_present": bool(execution_count),
        "usb_examples": _activity_examples((combined.get("usb_file_interaction") or combined.get("usb_activity") or []), limit=10),
        "browser_examples": _activity_examples(combined.get("browser_activity") or [], limit=10),
        "file_examples": _activity_examples(combined.get("file_activity") or [], limit=10),
    }


def _resolve_usb_content_image_ids(db: Database, case_id: str, *, volume_name: str | None) -> list[str]:
    if not volume_name:
        rows = _query_report_rows(
            db,
            case_id,
            "filesystem_entries",
            """
            SELECT image_id, COUNT(*) AS count
            FROM filesystem_entries
            WHERE case_id = ?
            GROUP BY image_id
            ORDER BY count DESC
            LIMIT 20
            """,
            [case_id],
        )
        return [str(row.get("image_id")) for row in rows if row.get("image_id")]
    like = f"%{volume_name}%"
    rows = _query_report_rows(
        db,
        case_id,
        "filesystem_entries",
        """
        SELECT DISTINCT image_id
        FROM filesystem_entries
        WHERE case_id = ?
          AND (
            file_name LIKE ?
            OR file_path LIKE ?
            OR parent_path LIKE ?
          )
        ORDER BY image_id
        LIMIT 20
        """,
        [case_id, like, like, like],
    )
    return [str(row.get("image_id")) for row in rows if row.get("image_id")]


def _usb_identity_summary_for_activity_windows(
    server: PerceptorMcpServer,
    case_id: str,
    combined: dict[str, list[dict[str, Any]]],
    *,
    limit: int,
) -> dict[str, Any]:
    usb_rows = list(combined.get("usb_file_interaction") or []) + list(combined.get("usb_activity") or [])
    observed_names = _observed_usb_names_from_rows(usb_rows)
    observed_drive_letters = _observed_drive_letters_from_rows(usb_rows)
    db = server._db()
    try:
        storage = external_storage_report(db, case_id, limit=max(limit, 250), rebuild_correlations=False, include_file_activity=True)
    finally:
        db.close()
    devices = []
    possible_drive_letter_devices = []
    for device in storage.get("devices") or []:
        public_device = _public_usb_identity_device(device)
        if _usb_device_matches_observed_name(device, observed_names):
            public_device["identity_basis"] = "observed_volume_or_device_name"
            public_device["identity_confidence"] = "medium"
            devices.append(public_device)
        elif _usb_device_matches_observed_drive_letter(device, observed_drive_letters):
            public_device["identity_basis"] = "drive_letter_only"
            public_device["identity_confidence"] = "low"
            public_device["caveat"] = "Drive letters are reusable; this is a possible device context, not a firm identity for the activity window."
            possible_drive_letter_devices.append(public_device)
    file_rows = []
    possible_drive_letter_file_rows = []
    for row in storage.get("file_activity") or []:
        if _usb_file_row_matches_observed_name(row, observed_names):
            file_rows.append(row)
        elif _usb_file_row_matches_observed_drive_letter(row, observed_drive_letters):
            possible_drive_letter_file_rows.append(row)
    names = sorted(
        {
            str(value).strip()
            for row in devices
            for value in (row.get("volume_name"), row.get("vbr_volume_name"), row.get("friendly_name"), row.get("product"))
            if str(value or "").strip()
        }
        | observed_names
    )
    return {
        "observed_names_in_windows": sorted(observed_names),
        "observed_drive_letters_in_windows": sorted(observed_drive_letters),
        "device_count": len(devices),
        "device_names": names,
        "devices": devices[:limit],
        "possible_drive_letter_devices": possible_drive_letter_devices[:limit],
        "file_activity_rows": file_rows[:limit],
        "possible_drive_letter_file_activity_rows": possible_drive_letter_file_rows[:limit],
        "evidence_note": "Observed names come from the supplied windows; device metadata is enriched from the external-storage report. Drive-letter-only matches are reported separately because drive letters are reusable.",
    }


def _public_usb_identity_device(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "serial": device.get("serial"),
        "friendly_name": device.get("friendly_name"),
        "vendor": device.get("vendor"),
        "product": device.get("product"),
        "drive_letter": device.get("drive_letter"),
        "volume_serial_number": device.get("volume_serial_number"),
        "volume_name": device.get("volume_name"),
        "vbr_volume_name": device.get("vbr_volume_name"),
        "file_system": device.get("file_system") or device.get("vbr_file_system"),
        "last_arrival_utc": device.get("last_arrival_utc"),
        "last_removal_utc": device.get("last_removal_utc"),
        "file_activity_detected": device.get("file_activity_detected"),
        "file_activity_count": device.get("file_activity_count"),
    }


def _observed_usb_names_from_rows(rows: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    generic = {"usb drive", "removable disk", "local disk", "this pc"}
    for row in rows:
        text = " ".join(str(row.get(key) or "") for key in ("description", "activity_description", "file_location", "file_name", "volume_name", "usb_volume_name", "artifact_volume_name"))
        for match in re.finditer(r"\b([A-Za-z0-9 _.-]{2,40})\s*\(([A-Z]:)\)", text):
            label = match.group(1).strip()
            if label and label.casefold() not in generic:
                names.add(label)
        for key in ("volume_name", "usb_volume_name", "artifact_volume_name", "matched_volume_name"):
            value = str(row.get(key) or "").strip()
            if value and value.casefold() not in generic:
                names.add(value)
    return names


def _observed_drive_letters_from_rows(rows: list[dict[str, Any]]) -> set[str]:
    letters: set[str] = set()
    for row in rows:
        text = " ".join(str(value or "") for value in row.values())
        for match in re.finditer(r"\b([A-Z]:)\\?", text):
            letters.add(match.group(1))
    return letters


def _usb_device_matches_observed_name(device: dict[str, Any], observed_names: set[str]) -> bool:
    device_values = {
        str(device.get(key) or "").strip().casefold()
        for key in ("volume_name", "vbr_volume_name", "friendly_name", "product", "serial")
        if str(device.get(key) or "").strip()
    }
    if any(name.casefold() in device_values for name in observed_names):
        return True
    return bool(device.get("file_activity_detected") and any(name.casefold() in json.dumps(device, default=str).casefold() for name in observed_names))


def _usb_device_matches_observed_drive_letter(device: dict[str, Any], observed_drive_letters: set[str]) -> bool:
    drive = str(device.get("drive_letter") or "").strip().upper()
    return bool(drive and drive in observed_drive_letters)


def _usb_file_row_matches_observed_name(row: dict[str, Any], observed_names: set[str]) -> bool:
    text = json.dumps(row, default=str).casefold()
    return any(name.casefold() in text for name in observed_names)


def _usb_file_row_matches_observed_drive_letter(row: dict[str, Any], observed_drive_letters: set[str]) -> bool:
    text = json.dumps(row, default=str).casefold()
    return any(letter.casefold() in text for letter in observed_drive_letters)


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
    name = _legacy_mcp_tool_name(name)
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
    name = _legacy_mcp_tool_name(name)
    tags = {category, permission}
    for token in ("source_of_truth", "filesystem", "cloud", "usb", "memory", "timeline", "report", "processing", "recovery"):
        if token.replace("_", "-") in name or token in name:
            tags.add(token)
    if name in {"relic_read_existing_report", "relic_discover_reports", "relic_query_filesystem_listings", "relic_query_evidence_contents", "relic_query_usb_contents"}:
        tags.add("source_of_truth")
    return tuple(tags)


def _infer_tool_dependencies(name: str, permission: str) -> tuple[str, ...]:
    name = _legacy_mcp_tool_name(name)
    deps = ["orchestrator.sqlite3"]
    if permission == "processing":
        deps.append("perceptor CLI")
    if "report" in name:
        deps.append("generated reports")
    if "filesystem" in name or "evidence_contents" in name or "usb_contents" in name:
        deps.append("filesystem_entries")
    if "usb_contents" in name:
        deps.append("usb_file_correlations")
    if "mcp_job" in name:
        deps.append("mcp-jobs/index.json")
    if "doctor" in name:
        deps.append("third-party dependency registry")
    return tuple(deps)


def _indexed_content_evidence_nature(source_table: str) -> str:
    if source_table == "user_file_content":
        return "direct_file_content_extraction"
    if source_table.startswith("windows_search_"):
        return "windows_search_artifact_indexed_content"
    if source_table in {"mailbox_messages", "mailbox_attachments"}:
        return "email_or_attachment_extracted_content"
    return "indexed_content"


def _indexed_content_provenance_summary(
    *,
    retrieval_backend: str,
    storage_table: str,
    forensic_source_table: str,
    evidence_nature: str,
) -> str:
    if evidence_nature == "direct_file_content_extraction":
        return (
            f"Retrieved from {retrieval_backend}; underlying forensic source is direct file-content extraction "
            f"({forensic_source_table}), stored in compatibility table {storage_table}."
        )
    if evidence_nature == "windows_search_artifact_indexed_content":
        return (
            f"Retrieved from {retrieval_backend}; underlying forensic source is Windows Search artifact content "
            f"({forensic_source_table}), stored in {storage_table}."
        )
    return (
        f"Retrieved from {retrieval_backend}; underlying forensic source is {forensic_source_table}, "
        f"stored in {storage_table}."
    )


def _infer_source_priority(name: str, category: str) -> tuple[str, ...]:
    if name in {"relic_read_existing_report", "relic_discover_reports", "relic_generate_report"} or category == "reports":
        return ("existing_reports", "parsed_artifacts", "processing")
    if category == "filesystem":
        return ("filesystem_entries", "mft_entries", "mounted_image_or_tsk")
    if category == "cloud":
        return ("existing_cloud_reports", "cloud_sync_artifacts", "opened_from_cloud_storage", "raw_processing")
    if category == "external_storage":
        return ("existing_usb_reports", "usb_storage_devices", "usb_connection_events", "filesystem_entries", "usb_file_correlations")
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
            arguments[key] = "perceptor://reports/case-id/full/report.json"
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


def _add_result_limit_guidance(result: dict[str, Any], arguments: dict[str, Any], tool: McpTool) -> dict[str, Any]:
    if not isinstance(result, dict):
        return result
    output = dict(result)
    limit = _result_limit(arguments, output)
    returned = _result_returned_count(output)
    total_matching = _safe_optional_int(output.get("total_matching"))
    total_available = _safe_optional_int(output.get("total_available"))
    possibly_limited = False
    reason = ""
    if bool(output.get("limited")):
        possibly_limited = True
        reason = "The report explicitly indicates that returned rows are limited."
    elif total_available is not None and returned is not None and total_available > returned:
        possibly_limited = True
        reason = "The report returned fewer rows than the total available rows."
    elif total_matching is not None and returned is not None and total_matching > returned:
        possibly_limited = True
        reason = "The tool returned fewer rows than the total matching rows."
    elif limit is not None and returned is not None and returned >= limit:
        possibly_limited = True
        reason = "The returned row count reached the active limit."
    elif limit is not None and _contains_capped_collection(output, limit):
        possibly_limited = True
        reason = "At least one returned collection reached the active limit."
    if possibly_limited:
        output["result_limit_warning"] = {
            "limited": True,
            "reason": reason,
            "active_limit": limit,
            "returned": returned,
            "total_matching": total_matching,
            "total_available": total_available,
            "guidance": (
                "This MCP response is a bounded preview, not proof that no additional evidence exists. "
                "Do not treat omitted rows as evidence of absence. Re-run with a higher limit when appropriate, "
                "read the generated full report/export if one exists, or ask for the full artifact dossier/context."
            ),
            "full_picture_options": _full_picture_options(tool.name),
        }
    elif limit is not None:
        output.setdefault(
            "result_limit",
            {
                "limited": False,
                "active_limit": limit,
                "returned": returned,
                "guidance": (
                    "MCP responses are intentionally bounded for usability. UTC/source data remains in the case database; "
                    "increase the limit, read an existing report/export, or request full artifact context when this item is material."
                ),
            },
        )
    return output


def _result_limit(arguments: dict[str, Any], result: dict[str, Any]) -> int | None:
    for source in (arguments, result.get("filters") if isinstance(result.get("filters"), dict) else {}, result.get("summary") if isinstance(result.get("summary"), dict) else {}):
        if not isinstance(source, dict):
            continue
        value = source.get("limit")
        if value is None:
            continue
        parsed = _safe_optional_int(value)
        if parsed is not None:
            return parsed
    return None


def _result_returned_count(result: dict[str, Any]) -> int | None:
    for key in ("total_returned", "returned", "count"):
        parsed = _safe_optional_int(result.get(key))
        if parsed is not None:
            return parsed
    return None


def _contains_capped_collection(result: dict[str, Any], limit: int) -> bool:
    for value in result.values():
        if isinstance(value, list) and len(value) >= limit:
            return True
    return False


def _full_picture_options(tool_name: str) -> list[str]:
    options = ["Increase the limit and rerun the same MCP tool.", "Use relic_discover_reports and relic_read_existing_report to inspect generated reports before raw artifact queries."]
    if any(token in tool_name for token in ("file", "content", "filesystem", "usb")):
        options.append("Use relic_file_dossier or relic_query_evidence_contents for full file/device context.")
    if "timeline" in tool_name or "activity" in tool_name:
        options.append("Use a wider relic_timeline_window and then follow report_hints/artifact_reference entries for supporting artifacts.")
    if "search" in tool_name or "content" in tool_name:
        options.append("Use relic_get_indexed_content for the full indexed body when search_content reports full_content_available.")
    return options


def _safe_optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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
            "case_id": _string_schema("Perceptor case ID."),
            "limit": _integer_schema("Maximum rows to return.", default=default, minimum=1, maximum=1000),
        },
        required=["case_id"],
    )


def _user_contains_schema(*, default: int) -> dict[str, Any]:
    return _object_schema(
        {
            "case_id": _string_schema("Perceptor case ID."),
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


def _limit(arguments: dict[str, Any], *, default: int, maximum: int = 1000) -> int:
    try:
        limit = int(arguments.get("limit") or default)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer")
    return max(1, min(limit, maximum))


def _bounded_int(arguments: dict[str, Any], key: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(arguments.get(key) or default)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be an integer")
    return max(minimum, min(value, maximum))


def _safe_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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


def _input_path(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    allowed_roots = _allowed_input_roots(root)
    if not any(resolved == allowed or _is_relative_to(resolved, allowed) for allowed in allowed_roots):
        roots = ", ".join(_display_path(path) for path in allowed_roots)
        raise ValueError(f"MCP input path is outside allowed evidence roots. Configure PERCEPTOR_MCP_ALLOWED_INPUT_ROOTS if needed. Allowed roots: {roots}")
    return resolved


def _allowed_input_roots(root: Path) -> list[Path]:
    configured = os.environ.get("PERCEPTOR_MCP_ALLOWED_INPUT_ROOTS") or os.environ.get("RELIC_MCP_ALLOWED_INPUT_ROOTS", "")
    values = [value for value in configured.split(os.pathsep) if value.strip()]
    if not values:
        values = [str(root), str(Path.cwd()), str(Path.home()), "/mnt", "/media", "/tmp"]
    roots: list[Path] = []
    for value in values:
        try:
            resolved = Path(value).expanduser().resolve()
        except OSError:
            continue
        if resolved not in roots:
            roots.append(resolved)
    return roots


def _display_path(path: Path) -> str:
    text = str(path)
    home = str(Path.home())
    if home and text.startswith(home):
        return text.replace(home, "~", 1)
    return text


def _safe_error_message(exc: Exception) -> str:
    text = str(exc)
    for path in (Path.home(), Path.cwd()):
        value = str(path)
        if value:
            text = text.replace(value, _display_path(path))
    return text


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, "") or default)
    except ValueError:
        return default
    return max(1, value)


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
    description = f"Perceptor {inferred_kind} resource"
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
        "triage": common | {"suspicious-executions", "software-footprint-review", "user-intent", "file-movement-identity", "opened-from-removable-media", "opened-from-cloud-storage", "cloud-mounts", "cloud-removable-overlap", "artifact-processing-status"},
        "usb": common | {"shellbag-external-storage", "file-movement-identity", "opened-from-removable-media", "cloud-removable-overlap", "shortcut-droid-changes", "shortcut-object-tracking", "usn-lifecycle"},
        "cloud": common | {"cloud-artifacts", "opened-from-cloud-storage", "cloud-mounts", "cloud-removable-overlap", "user-intent"},
        "execution": common | {"execution", "execution-correlation", "suspicious-executions", "program-provenance", "software-footprint-review", "remote-access", "user-intent"},
        "memory": common | {"memory-analysis", "memory-credentials", "memory-disk-correlations", "memory-support-files", "structured-memory", "combined-artifacts", "crash-dump-analysis", "memory-artifacts"},
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
    wants_file_content = _is_file_content_lookup_question(text)
    wants_recovery = _contains_any(text, {"recover", "restore", "undelete", "extract deleted", "deleted file", "deleted files"})
    has_wifi_terms = _contains_any(
        text,
        {
            "wifi",
            "wi-fi",
            "wireless",
            "wlan",
            "ssid",
            "networkprofile",
            "network profile",
            "connected to network",
            "connect to network",
            "network connection",
            "network connections",
        },
    )
    wants_activity_during_connection = _contains_any(
        text,
        {"activity", "occurred", "happened", "during", "while connected", "while the computer was connected", "usage", "used", "what did"},
    )
    wants_user_inventory = _contains_any(
        text,
        {
            "users on",
            "users of",
            "system users",
            "local users",
            "local accounts",
            "microsoft account",
            "microsoft accounts",
            "internetusername",
            "internet user name",
            "user accounts",
            "accounts on",
            "who are the users",
            "which users",
            "list users",
            "list accounts",
            "sid",
            "sids",
            "last login",
            "last logon",
        },
    )

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

    if wants_user_inventory:
        intent = "system_users"
        first_source = "parsed_identity_artifact_tables"
        report_purpose = "identity"
        report_names = ["case-overview"]
        recommended_tool = "relic_query_system_users"
        fallback_tools = ["relic_user_activity", "relic_search_artifacts"]
        reason = (
            "User/account inventory questions should use the consolidated system-users view, which joins SAM accounts "
            "with registry cloud-account details and SID evidence before falling back to raw artifact searches."
        )
        source_order = [
            {"order": 1, "source": "consolidated_user_inventory", "tools": ["relic_query_system_users"]},
            {"order": 2, "source": "user_activity_if_named_user", "tools": ["relic_user_activity"]},
            {"order": 3, "source": "parsed_artifact_tables", "tools": ["relic_search_artifacts"], "tables": ["sam_accounts", "registry_artifacts"]},
            {"order": 4, "source": "processing_or_reparse", "tools": ["relic_process_image", "relic_run_profile"], "requires_explicit_user_request": True},
        ]
    elif wants_recovery:
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
    elif _is_content_search_question(text) and not _is_file_information_question(text, tokens):
        intent = "content_search"
        first_source = "generated_reports"
        recommended_tool = "relic_search_content"
        fallback_tools = ["relic_search_artifacts", "relic_file_dossier", "relic_artifact_search_sources"]
        report_names = ["user-intent", "communications", "cloud-files", "windows-search", "case-overview"]
        report_purpose = "documents"
        reason = "File-content and body-text search should query the OpenSearch content index after checking generated report context."
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_discover_report_exports"], "report_names": report_names},
            {"order": 2, "source": "opensearch_content_index", "tools": ["relic_search_content"]},
            {"order": 3, "source": "parsed_artifact_tables", "tools": ["relic_search_artifacts", "relic_file_dossier"]},
            {"order": 4, "source": "processing_or_reindexing", "tools": ["relic_process_image", "relic_run_profile"], "requires_explicit_user_request": True},
        ]
    elif _is_file_information_question(text, tokens):
        intent = "file_content_and_information" if wants_file_content else "file_information"
        first_source = "file_dossier"
        recommended_tool = "relic_file_dossier"
        fallback_tools = ["relic_query_filesystem_listings", "relic_search_content", "relic_search_artifacts", "relic_read_existing_report"]
        report_names = ["file-movement-identity", "opened-from-removable-media", "opened-from-cloud-storage", "windows-search"]
        report_purpose = "documents"
        reason = (
            "Single-file questions should use the file dossier first because it combines generated filesystem listings, "
            "MFT/USN/Search/shortcut/cloud evidence, and internal file metadata when available."
        )
        source_order = [
            {"order": 1, "source": "file_dossier", "tools": ["relic_file_dossier"]},
            {"order": 2, "source": "generated_filesystem_listings", "tools": ["relic_query_filesystem_listings"]},
            {
                "order": 3,
                "source": "opensearch_content_index",
                "tools": ["relic_search_content"],
                "required_when": "The user asks for file contents, text inside the file, full content, or what the file says.",
                "followup": "If a hit is returned and full_content_available is true, call relic_get_indexed_content with that hit's opensearch_document_id.",
            },
            {"order": 4, "source": "parsed_artifact_tables", "tools": ["relic_search_artifacts"]},
            {"order": 5, "source": "generated_reports", "tools": ["relic_read_existing_report"], "report_names": report_names},
            {"order": 6, "source": "processing_or_image_access", "tools": ["relic_process_image", "relic_run_profile"], "requires_explicit_user_request": True},
        ]
        if wants_file_content:
            reason += " Because the question asks for content, do not stop at metadata; query relic_search_content with the file name/path and use relic_get_indexed_content when available."
    elif _contains_any(text, {"contents", "content", "list files", "files on", "folder", "directory", "filesystem", "file listing", "drive contents", "volume contents"}) or "files" in tokens and _contains_any(text, {"usb", "drive", "volume", "image"}) or _contains_any(text, {"what else", "what was on", "what is on", "anything else"}) and _contains_any(text, {"usb", "removable", "external", "drive", "volume"}):
        intent = "evidence_contents"
        usb_scoped = _contains_any(text, {"usb", "removable", "external"})
        first_source = "generated_usb_filesystem_listings" if usb_scoped else "generated_filesystem_listings"
        recommended_tool = "relic_query_usb_contents" if usb_scoped else "relic_query_evidence_contents"
        fallback_tools = (
            ["relic_query_evidence_contents", "relic_query_filesystem_listings", "relic_query_usb_files", "relic_file_dossier", "relic_search_artifacts"]
            if usb_scoped
            else ["relic_query_filesystem_listings", "relic_file_dossier", "relic_search_artifacts"]
        )
        report_names = ["opened-from-removable-media", "file-movement-identity", "usb-files"]
        report_purpose = "usb" if usb_scoped else "full"
        reason = (
            "USB contents answers should resolve the USB volume/device to stored filesystem_entries, then use USB file correlations for host-side references."
            if usb_scoped
            else "Filesystem answers should come from stored filesystem_entries before live image access or SleuthKit."
        )
        source_order = [
            {
                "order": 1,
                "source": "generated_usb_filesystem_listings" if usb_scoped else "generated_filesystem_listings",
                "tools": ["relic_query_usb_contents"] if usb_scoped else ["relic_query_evidence_contents", "relic_query_filesystem_listings"],
            },
            {
                "order": 2,
                "source": "usb_file_correlations" if usb_scoped else "generated_reports",
                "tools": ["relic_query_usb_files", "relic_query_evidence_contents", "relic_query_filesystem_listings"] if usb_scoped else ["relic_read_existing_report"],
                "report_names": report_names,
            },
            {"order": 3, "source": "generated_reports", "tools": ["relic_read_existing_report"], "report_names": report_names},
            {"order": 4, "source": "parsed_artifact_tables", "tools": ["relic_file_dossier", "relic_search_artifacts"]},
            {"order": 5, "source": "image_processing_or_fls", "tools": ["relic_process_image", "relic_run_profile"], "requires_explicit_user_request": True},
        ]
    elif not (has_wifi_terms and wants_activity_during_connection) and _contains_any(text, {"usb", "removable", "external storage", "thumb drive", "flash drive", "uasp", "usbstor", "volume serial"}):
        intent = "usb_storage"
        report_purpose = "usb"
        report_names = ["external-storage", "usb-files", "usb-timeline", "opened-from-removable-media", "file-movement-identity"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_query_external_storage", "relic_query_usb_files", "relic_usb_dossier", "relic_query_evidence_contents"]
        reason = "USB/storage questions should begin with deduped storage reports, then storage-specific parsed tables."
    elif _contains_any(
        text,
        {
            "software footprint",
            "application residue",
            "app residue",
            "uninstalled",
            "uninstall residue",
            "left behind",
            "leftover",
            "remnant",
            "remnants",
            "portable app",
            "portable application",
        },
    ):
        intent = "software_footprint"
        report_purpose = "execution"
        report_names = ["software-footprint-review", "program-provenance", "execution", "suspicious-executions"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_generate_report", "relic_search_artifacts", "relic_timeline_window"]
        reason = (
            "Software residue and post-uninstall questions should start with the software-footprint-review report, "
            "which compares current installed-program inventory against execution, persistence, user-activity, "
            "presence, download, and filesystem remnants."
        )
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_generate_report"], "report_names": report_names},
            {"order": 2, "source": "software_footprint_review", "tools": ["relic_generate_report"], "report_names": ["software-footprint-review"]},
            {"order": 3, "source": "parsed_artifact_tables", "tools": ["relic_search_artifacts"], "tables": ["registry_artifacts", "prefetch_items", "amcache_entries", "shimcache_entries", "srum_records", "shortcut_items"]},
        ]
    elif _contains_any(
        text,
        {
            "suspicious",
            "execution",
            "executed",
            "executable",
            "program",
            "process",
            "command line",
            "4688",
            "powershell",
            "script block",
            "4104",
            "scheduled task",
            "4698",
            "4699",
            "wmi",
            "wmi-activity",
            "event consumer",
            "consumer binding",
            "5861",
            "5859",
            "5860",
            "print",
            "printed",
            "printer",
            "printservice",
            "spool",
            "account created",
            "account changed",
            "account disabled",
            "password reset",
            "audit log",
            "log cleared",
            "1102",
            "104",
            "runmru",
            "userassist",
            "prefetch",
        },
    ):
        intent = "execution"
        report_purpose = "execution"
        report_names = ["event-interpretation", "suspicious-executions", "execution", "execution-correlation", "program-provenance", "software-footprint-review"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_generate_report", "relic_query_suspicious_executions", "relic_lead_search", "relic_query_registry_activity"]
        reason = "Execution and high-value event-log questions should start with generated event-interpretation, execution, and suspicious-execution reports."
    elif _contains_any(text, {"bits", "background intelligent transfer", "qmgr", "download transfer", "transfer job", "onedrive setup", "component updater"}):
        intent = "bits_activity"
        report_purpose = "full"
        report_names = ["bits-activity"]
        recommended_tool = "relic_generate_report"
        fallback_tools = ["relic_timeline_window", "relic_search_artifacts", "relic_read_existing_report"]
        reason = (
            "BITS questions should use the BITS activity report because it correlates timestamped BITS Client EVTX rows "
            "with qmgr database/carved rows by exact job ID or URL where available."
        )
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_generate_report"], "report_names": report_names},
            {"order": 2, "source": "bits_activity_table", "tools": ["relic_generate_report"], "report_names": report_names},
            {"order": 3, "source": "normalized_master_timeline", "tools": ["relic_timeline_window"], "tables": ["bits_activity"]},
            {"order": 4, "source": "parsed_artifact_tables", "tools": ["relic_search_artifacts"], "tables": ["bits_activity", "bits_jobs", "evtx_events"]},
        ]
    elif _contains_any(text, {"clipboard", "copied", "paste", "pasted", "clip history", "cloud clipboard", "sync across devices"}):
        intent = "clipboard_activity"
        report_purpose = "full"
        report_names = ["clipboard", "windows-activities"]
        recommended_tool = "relic_read_existing_report"
        fallback_tools = ["relic_generate_report", "relic_timeline_window", "relic_search_artifacts"]
        reason = (
            "Clipboard questions should start with the dedicated clipboard report, then use the normalized master timeline "
            "for time-window context and Windows Activities only as secondary clipboard-adjacent evidence."
        )
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_generate_report"], "report_names": ["clipboard"]},
            {"order": 2, "source": "clipboard_items_table", "tools": ["relic_generate_report", "relic_search_artifacts"], "tables": ["clipboard_items"]},
            {"order": 3, "source": "normalized_master_timeline", "tools": ["relic_timeline_window"], "tables": ["clipboard_items"]},
            {"order": 4, "source": "secondary_activity_artifacts", "tools": ["relic_generate_report", "relic_search_artifacts"], "tables": ["windows_activities", "browser_site_settings", "evtx_events"]},
        ]
    elif _contains_any(
        text,
        {
            "mapped network path",
            "mapped network paths",
            "mapped network drive",
            "mapped network drives",
            "network mapped",
            "network share",
            "network shares",
            "mountpoints2 ##",
            "##server",
            "unc path",
            "unc paths",
        },
    ):
        intent = "mapped_network_paths"
        report_purpose = "network"
        report_names = ["mapped-network-paths", "examiner-edge-artifacts"]
        recommended_tool = "relic_generate_report"
        fallback_tools = ["relic_read_existing_report", "relic_search_artifacts", "relic_timeline_window"]
        reason = (
            "Mapped network path questions should start with the mapped-network-paths report, "
            "which decodes MountPoints2 ##host#share#path registry keys into UNC-style network paths."
        )
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_generate_report"], "report_names": report_names},
            {"order": 2, "source": "registry_artifacts_mountpoints2_rows", "tools": ["relic_search_artifacts"], "tables": ["registry_artifacts"]},
            {"order": 3, "source": "normalized_master_timeline", "tools": ["relic_timeline_window"], "tables": ["registry_artifacts"]},
        ]
    elif _contains_any(text, {"$secure", "$sds", "$sii", "$sdh", "security descriptor", "security descriptors", "ntfs permissions", "file permissions", "acl", "access control list"}):
        intent = "ntfs_security_descriptors"
        report_purpose = "filesystem"
        report_names = ["ntfs-security-descriptors", "non-standard-ads"]
        recommended_tool = "relic_generate_report"
        fallback_tools = ["relic_read_existing_report", "relic_search_artifacts", "relic_timeline_window"]
        reason = "NTFS permission/security descriptor questions should start with the ntfs-security-descriptors report, which inventories $Secure stream presence and states the current structured parsing caveat."
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_generate_report"], "report_names": report_names},
            {"order": 2, "source": "mft_security_descriptor_stream_rows", "tools": ["relic_search_artifacts"], "tables": ["mft_entries"]},
            {"order": 3, "source": "normalized_master_timeline", "tools": ["relic_timeline_window"], "tables": ["mft_entries"]},
        ]
    elif _contains_any(text, {"alternate data stream", "alternate data streams", "non-standard ads", "non standard ads", "hidden stream", "ads stream"}):
        intent = "non_standard_ads"
        report_purpose = "filesystem"
        report_names = ["non-standard-ads"]
        recommended_tool = "relic_generate_report"
        fallback_tools = ["relic_read_existing_report", "relic_search_artifacts", "relic_timeline_window"]
        reason = "Alternate data stream questions should start with the non-standard-ads report, which filters MFT ADS rows beyond common Zone.Identifier/system streams."
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_generate_report"], "report_names": report_names},
            {"order": 2, "source": "mft_ads_rows", "tools": ["relic_search_artifacts"], "tables": ["mft_entries"]},
            {"order": 3, "source": "normalized_master_timeline", "tools": ["relic_timeline_window"], "tables": ["mft_entries"]},
        ]
    elif _contains_any(text, {"anydesk", "teamviewer", "logmein", "screenconnect", "connectwise control", "splashtop", "rustdesk", "remote access tool", "remote support tool"}):
        intent = "remote_access_tool_logs"
        report_purpose = "remote_access"
        report_names = ["remote-access-tool-logs", "remote-access", "suspicious-executions"]
        recommended_tool = "relic_generate_report"
        fallback_tools = ["relic_read_existing_report", "relic_search_artifacts", "relic_timeline_window"]
        reason = "Remote access tool questions should start with the remote-access-tool-logs report, then correlate with remote-access sessions and execution artifacts."
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_generate_report"], "report_names": report_names},
            {"order": 2, "source": "messaging_records_remote_access_logs", "tools": ["relic_search_artifacts"], "tables": ["messaging_records", "messaging_messages"]},
            {"order": 3, "source": "execution_and_filesystem_candidates", "tools": ["relic_search_artifacts"], "tables": ["mft_entries", "prefetch_items", "amcache_entries", "shimcache_entries"]},
            {"order": 4, "source": "normalized_master_timeline", "tools": ["relic_timeline_window"]},
        ]
    elif _contains_any(
        text,
        {
            "sticky note",
            "sticky notes",
            "plum.sqlite",
            "notification database",
            "wpndatabase",
            "networklist",
            "outbound rdp",
            "terminal server client",
            "mountpoints2",
            "scheduled task xml",
            "task scheduler xml",
            "cryptnet",
            "cryptneturlcache",
            "hosts file",
            "wsl",
            "ext4.vhdx",
            "windows update",
            "datastore.edb",
            "credential manager",
            "windows vault",
            "bluetooth",
            "swiftkey",
            "inputpersonalization",
            "installed programs",
            "installed applications",
        },
    ):
        intent = "examiner_edge_artifacts"
        report_purpose = "full"
        report_names = ["examiner-edge-artifacts", "mapped-network-paths"]
        recommended_tool = "relic_generate_report"
        fallback_tools = ["relic_read_existing_report", "relic_search_artifacts", "relic_timeline_window"]
        reason = (
            "These high-value edge artifact questions should start with the examiner-edge-artifacts report, "
            "which consolidates Sticky Notes, notifications, NetworkList, outbound RDP, MountPoints2, task XML, "
            "CryptnetUrlCache, hosts, WSL, Windows Update, Credential/Vault metadata, Bluetooth, installed "
            "applications, and SwiftKey/InputPersonalization leads."
        )
        source_order = [
            {"order": 1, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_generate_report"], "report_names": report_names},
            {"order": 2, "source": "parsed_artifact_tables", "tools": ["relic_search_artifacts"], "tables": ["package_artifacts", "telemetry_artifacts", "registry_artifacts"]},
            {"order": 3, "source": "normalized_master_timeline", "tools": ["relic_timeline_window"], "tables": ["package_artifacts", "telemetry_artifacts", "registry_artifacts"]},
        ]
    elif has_wifi_terms:
        intent = "wifi_network_activity"
        first_source = "parsed_network_artifact_tables"
        report_purpose = "network"
        report_names = ["case-overview", "user-intent"]
        recommended_tool = "relic_query_wifi_activity" if wants_activity_during_connection else "relic_query_wifi_activity"
        fallback_tools = ["relic_timeline_window", "relic_timeline", "relic_search_artifacts", "relic_read_existing_report"]
        reason = (
            "Wi-Fi questions need reconciliation across WLAN/NetworkProfile EVTX, SRUM, and NetworkList registry rows. "
            "For questions about activity while connected to a network, resolve all matching connect/disconnect sessions first, then "
            "call relic_activity_windows with session_activity_plan.aggregate_tool so normalized timeline and direct artifact activity are aggregated across sessions. "
            "Do not pass the SSID as contains unless the user specifically asks to filter timeline results to that SSID."
        )
        source_order = [
            {"order": 1, "source": "parsed_network_artifact_tables", "tools": ["relic_query_wifi_activity"]},
            {
                "order": 2,
                "source": "normalized_master_timeline",
                "tools": ["relic_activity_windows", "relic_timeline_window"],
                "requires": "Use session_activity_plan.aggregate_tool unless the user specified one session or exact start/end; interval events are matched by overlap. Leave contains unset and filter_within_window false for broad activity questions.",
            },
            {"order": 3, "source": "generated_reports", "tools": ["relic_read_existing_report", "relic_discover_report_exports"], "report_names": report_names},
            {"order": 4, "source": "artifact_drilldown", "tools": ["relic_search_artifacts", "domain query tools"]},
            {"order": 5, "source": "broad_artifact_search", "tools": ["relic_search_artifacts"]},
        ]
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
            "Use relic_query_wifi_activity for Wi-Fi, WLAN, SSID, or network-connection questions so EVTX, SRUM, and registry evidence are reconciled.",
            "Use relic_search_content for file-content, document-text, body-text, attachment-text, or indexed-content search questions.",
            "Use parsed artifact tables before resources, packet files, or direct image tooling.",
            "Use processing, mounts, FLS, or recovery tools only after the user explicitly asks for that work and MCP processing is enabled.",
            "Do not reveal credentials or send data to external AI unless the corresponding MCP startup gate is enabled.",
        ],
    }


def _is_content_search_question(text: str) -> bool:
    wants_search = _contains_any(text, {"search", "find", "look for", "contains", "contained", "mention", "mentions", "keyword"})
    content_target = _contains_any(
        text,
        {
            "file content",
            "file contents",
            "document text",
            "doc text",
            "body text",
            "message body",
            "email body",
            "attachment text",
            "indexed content",
            "full text",
            "full-text",
            "ocr text",
            "text inside",
            "within files",
            "inside files",
            "inside documents",
            "contents of files",
        },
    )
    return wants_search and content_target


def _is_file_content_lookup_question(text: str) -> bool:
    return _contains_any(
        text,
        {
            "content of",
            "contents of",
            "file content",
            "file contents",
            "what does",
            "what did it say",
            "what it says",
            "read the file",
            "full content",
            "full text",
            "text from",
            "text in",
            "inside the file",
            "inside this file",
            "extract text",
            "show me the content",
            "show the content",
        },
    )


def _is_file_information_question(text: str, tokens: set[str]) -> bool:
    asks_about_file = _contains_any(
        text,
        {
            "what can you tell me about",
            "tell me about this file",
            "tell me about the file",
            "file metadata",
            "filesystem metadata",
            "internal metadata",
            "metadata for",
            "file provenance",
            "file dossier",
            "this file",
            "that file",
        },
    )
    file_like_token = any(
        re.search(r"\.[a-z0-9]{1,8}$", token)
        for token in tokens
        if not token.startswith("http")
    )
    path_like = bool(re.search(r"(?:[a-z]:[\\/]|[\\/][^\\/\s]+[\\/]|users[\\/][^\\/\s]+[\\/])", text, flags=re.IGNORECASE))
    return (
        asks_about_file
        and (file_like_token or path_like or "file metadata" in text or "filesystem metadata" in text)
    ) or (file_like_token and _is_file_content_lookup_question(text))


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
        {"order": 10, "tool": "relic_query_wifi_activity", "purpose": "For Wi-Fi, WLAN, SSID, or network-connection questions, reconcile WLAN/NetworkProfile EVTX, SRUM, and NetworkList registry evidence before broad timeline search."},
        {"order": 11, "tool": "relic_lead_search", "purpose": "Run preset execution, USB, cloud, document, browser, or communications searches after existing reports have been checked."},
        {"order": 12, "tool": "relic_search_content", "purpose": "Search OpenSearch indexed file contents, document text, message bodies, attachments, and Windows Search indexed content after report context has been checked."},
        {"order": 13, "tool": "relic_search_artifacts", "purpose": "Run ad hoc artifact searches with user, computer, source, and time filters after existing reports have been checked."},
        {"order": 14, "tool": "drilldown tools", "purpose": "Follow search result drilldown hints into file, USB, user, timeline, registry, cloud, communication, shortcut, or remote-access context."},
        {"order": 15, "tool": "relic_write_search_packet", "purpose": "Save repeatable searches, result hash sets, case counts, and result sets as examiner work product."},
        {"order": 16, "tool": "relic_rerun_search_packet", "purpose": "Rerun saved searches and compare added, removed, changed, and unchanged results."},
        {"order": 17, "tool": "relic_write_review_packet", "purpose": "Save selected findings, notes, timeline slices, and report URIs."},
        {"order": 18, "tool": "relic_write_report_bundle", "purpose": "Export a review bundle for handoff or UI consumption. Use purpose=review for MCP/operator review packs."},
    ]
    return {
        "title": "Perceptor MCP Workflow Guide",
        "summary": {"step_count": len(steps)},
        "steps": steps,
        "recommended_presets": ["execution", "usb", "cloud", "documents", "browser", "communications"],
        "route_first_tool": "relic_route_question",
        "reports_first_tool": "relic_read_existing_report",
        "evidence_contents_first_tool": "relic_query_evidence_contents",
        "filesystem_first_tool": "relic_query_filesystem_listings",
        "wifi_activity_tool": "relic_query_wifi_activity",
        "content_search_tool": "relic_search_content",
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
    return "perceptor://workspace/" + quote(str(relative).replace("\\", "/"), safe="/")


def _path_from_resource_uri(root: Path, uri: str) -> Path:
    prefixes = ("perceptor://workspace/", "relic://workspace/")
    prefix = next((candidate for candidate in prefixes if uri.startswith(candidate)), "")
    if not prefix:
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
    for package in ("perceptor", "forensic-orchestrator"):
        try:
            return version(package)
        except PackageNotFoundError:
            continue
    return "0.1.0"
