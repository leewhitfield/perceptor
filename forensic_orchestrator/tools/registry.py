from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import yaml

from forensic_orchestrator.models import ArtifactDefinition, ToolDefinition
from forensic_orchestrator.safety import ToolError


class ToolRegistry:
    def __init__(self, tools: dict[str, ToolDefinition], profiles: dict[str, Any]) -> None:
        self.tools = tools
        self.profiles = profiles

    @classmethod
    def from_files(cls, paths: list[Path]) -> "ToolRegistry":
        tools: dict[str, ToolDefinition] = {}
        profiles: dict[str, Any] = {}
        for path in paths:
            if not path.exists():
                raise ToolError(f"Plugin YAML not found: {path}")
            data = yaml.safe_load(path.read_text()) or {}
            for name, raw in (data.get("tools") or {}).items():
                artifacts = [
                    ArtifactDefinition(
                        name=str(artifact["name"]),
                        source=str(artifact["source"]),
                        destination=str(artifact.get("destination", artifact["name"])),
                        inode=str(artifact["inode"]) if artifact.get("inode") is not None else None,
                        recursive=bool(artifact.get("recursive", False)),
                        pattern=str(artifact["pattern"]) if artifact.get("pattern") else None,
                        patterns=tuple(str(item) for item in artifact.get("patterns", [])),
                        include_path_patterns=tuple(str(item) for item in artifact.get("include_path_patterns", [])),
                        exclude_patterns=tuple(str(item) for item in artifact.get("exclude_patterns", [])),
                        process_in_place=bool(artifact.get("process_in_place", False)),
                        allow_partial=bool(artifact.get("allow_partial", False)),
                        use_tsk=bool(artifact.get("use_tsk", False)),
                        optional=bool(artifact.get("optional", False)),
                        recovery=dict(artifact.get("recovery") or {}),
                    )
                    for artifact in raw.get("artifacts", [])
                ]
                tools[name] = ToolDefinition(
                    name=name,
                    enabled=bool(raw.get("enabled", True)),
                    type=str(raw.get("type", "binary")),
                    executable=_resolve_executable(raw.get("executable")),
                    command=[str(item) for item in raw.get("command", [])],
                    required_paths=[str(item) for item in raw.get("required_paths", [])],
                    outputs=[str(item) for item in raw.get("outputs", [])],
                    artifacts=artifacts,
                )
            profiles.update(data.get("profiles") or {})
        return cls(tools=tools, profiles=profiles)

    def enabled_tools(self) -> list[ToolDefinition]:
        return [tool for tool in self.tools.values() if tool.enabled]

    def get_tool(self, name: str) -> ToolDefinition:
        try:
            return self.tools[name]
        except KeyError as exc:
            raise ToolError(f"Tool not configured: {name}") from exc

    def profile_tools(self, profile: str) -> list[ToolDefinition]:
        raw = self.profiles.get(profile)
        if raw is None:
            raise ToolError(f"Profile not configured: {profile}")
        names = raw.get("tools", [])
        return [self.get_tool(name) for name in names]


def _resolve_executable(executable: str | None) -> str | None:
    if not executable:
        return executable
    if executable == "sidr":
        configured = os.environ.get("SIDR_BIN")
        if configured:
            return configured
        for candidate in (Path.home() / "tools" / "sidr" / "sidr",):
            if candidate.exists():
                return str(candidate)
    if executable == "usnjrnl-forensic":
        configured = os.environ.get("USNJRNL_FORENSIC_BIN")
        if configured:
            return configured
        candidate = Path.home() / ".cargo" / "bin" / "usnjrnl-forensic"
        if candidate.exists():
            return str(candidate)
    eztools_root = os.environ.get("EZTOOLS_ROOT")
    default_prefix = "/opt/eztools/"
    if eztools_root and executable.startswith(default_prefix):
        return str(Path(eztools_root) / executable.removeprefix(default_prefix))
    local_eztools_root = Path.home() / "tools" / "eztools"
    if executable.startswith(default_prefix) and local_eztools_root.exists() and not Path(executable).exists():
        local_candidate = local_eztools_root / executable.removeprefix(default_prefix)
        if local_candidate.exists():
            return str(local_candidate)
        nested = sorted(local_candidate.parent.rglob(local_candidate.name)) if local_candidate.parent.exists() else []
        if nested:
            return str(nested[0])
    return executable


def render_template(
    value: str,
    *,
    tool: ToolDefinition,
    mount: Path,
    output: Path,
    artifacts: dict[str, Path] | None = None,
) -> str:
    executable = tool.executable or ""
    plugin_dir = Path(__file__).resolve().parents[1] / "plugins"
    rendered = value
    for name, path in (artifacts or {}).items():
        rendered = rendered.replace(f"{{artifact:{name}}}", str(path))
        rendered = rendered.replace(f"{{artifact_parent:{name}}}", str(path.parent))
    rendered = rendered.format(
        executable=executable,
        mount=str(mount),
        output=str(output),
        plugins=str(plugin_dir),
    )
    return rendered


def build_tool_command(
    tool: ToolDefinition,
    *,
    mount: Path,
    output: Path,
    artifacts: dict[str, Path] | None = None,
) -> list[str]:
    if not tool.command:
        raise ToolError(f"Tool has no command configured: {tool.name}")
    command = [
        render_template(item, tool=tool, mount=mount, output=output, artifacts=artifacts)
        for item in tool.command
    ]
    if command and Path(command[0]).name.lower() == "dotnet":
        command[0] = resolve_dotnet_runtime()
    if command and Path(command[0]).suffix.casefold() == ".exe":
        raise ToolError(f"Windows SIDR executable is not supported on Linux; build or configure a native sidr binary: {command[0]}")
    return command


def resolve_dotnet_runtime() -> str:
    configured = os.environ.get("FORENSIC_ORCHESTRATOR_DOTNET") or os.environ.get("DOTNET_BIN")
    if configured:
        return configured
    on_path = shutil.which("dotnet")
    if on_path:
        return on_path
    dotnet_root = os.environ.get("DOTNET_ROOT")
    if dotnet_root:
        candidate = Path(dotnet_root) / "dotnet"
        if candidate.exists():
            return str(candidate)
    home_candidate = Path.home() / ".dotnet" / "dotnet"
    if home_candidate.exists():
        return str(home_candidate)
    return "dotnet"


def required_paths(
    tool: ToolDefinition,
    *,
    mount: Path,
    output: Path,
    artifacts: dict[str, Path] | None = None,
) -> list[Path]:
    return [
        Path(render_template(item, tool=tool, mount=mount, output=output, artifacts=artifacts))
        for item in tool.required_paths
    ]
