from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable, TextIO

from .db import Database
from .paths import WorkspacePaths
from .reports import (
    case_dashboard_report,
    case_summary_report,
    processing_progress_report,
    resume_plan_report,
    timeline_report,
    workspace_health_report,
)
from .standalone import job_status_report


SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


@dataclass(frozen=True)
class McpTool:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    annotations: dict[str, Any]

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
    ) -> None:
        self.paths = WorkspacePaths(root)
        self.allow_processing = allow_processing
        self.allow_sensitive = allow_sensitive
        self.allow_external_ai = allow_external_ai
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
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "relic", "version": _package_version()},
            "instructions": (
                "Relic MCP exposes forensic workspace tools. This initial surface is read-only; "
                "processing, sensitive credential reveal, external AI upload, and destructive actions "
                "require explicit server startup flags before those tools are exposed."
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
        try:
            result = tool.handler(arguments)
            return _tool_result(result)
        except Exception as exc:
            return _tool_result({"error": str(exc), "tool": name}, is_error=True)

    def _build_tools(self) -> list[McpTool]:
        read_only = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
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
        ]

    def _db(self) -> Database:
        return Database(self.paths.db_path())

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
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
) -> int:
    server = RelicMcpServer(
        root=root,
        allow_processing=allow_processing,
        allow_sensitive=allow_sensitive,
        allow_external_ai=allow_external_ai,
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


def _string_schema(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def _integer_schema(description: str, *, default: int, minimum: int, maximum: int) -> dict[str, Any]:
    return {"type": "integer", "description": description, "default": default, "minimum": minimum, "maximum": maximum}


def _required(arguments: dict[str, Any], key: str) -> str:
    value = str(arguments.get(key) or "").strip()
    if not value:
        raise ValueError(f"Missing required argument: {key}")
    return value


def _limit(arguments: dict[str, Any], *, default: int) -> int:
    try:
        limit = int(arguments.get("limit") or default)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer")
    return max(1, min(limit, 1000))


def _count_table(db: Database, table: str) -> int:
    row = db.conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
    return int(row["count"] if row else 0)


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
