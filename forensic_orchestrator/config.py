from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from .paths import DEFAULT_ROOT


@dataclass(frozen=True)
class AppConfig:
    root: Path
    plugin_paths: list[Path]
    tools_root: Path | None = None
    eztools_root: Path | None = None


def default_plugin_path() -> Path:
    return Path(__file__).parent / "plugins" / "eztools.yaml"


def load_config(root: str | None = None, plugins: list[str] | None = None, config_path: str | None = None) -> AppConfig:
    config = _load_config_file(config_path)
    configured_root = Path(
        root
        or config.get("root")
        or os.environ.get("PERCEPTOR_ROOT")
        or os.environ.get("FORENSIC_ORCHESTRATOR_ROOT", DEFAULT_ROOT)
    )
    configured_plugins = plugins or config.get("plugins")
    plugin_paths = [Path(p) for p in configured_plugins] if configured_plugins else [default_plugin_path()]
    tools_root = Path(config["tools_root"]).expanduser() if config.get("tools_root") else None
    eztools_root = Path(config["eztools_root"]).expanduser() if config.get("eztools_root") else None
    _apply_tool_environment(config, tools_root=tools_root, eztools_root=eztools_root)
    return AppConfig(root=configured_root, plugin_paths=plugin_paths, tools_root=tools_root, eztools_root=eztools_root)


def _load_config_file(config_path: str | None) -> dict:
    path_value = config_path or os.environ.get("PERCEPTOR_CONFIG") or os.environ.get("FORENSIC_ORCHESTRATOR_CONFIG")
    if not path_value:
        return {}
    path = Path(path_value).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file must contain a mapping: {path}")
    return data


def _apply_tool_environment(config: dict, *, tools_root: Path | None, eztools_root: Path | None) -> None:
    if tools_root:
        os.environ.setdefault("PERCEPTOR_TOOLS_ROOT", str(tools_root))
        os.environ.setdefault("FORENSIC_ORCHESTRATOR_TOOLS_ROOT", str(tools_root))
    if eztools_root:
        os.environ.setdefault("EZTOOLS_ROOT", str(eztools_root))
    env_map = {
        "bstrings_bin": "BSTRINGS_BIN",
        "sidr_bin": "SIDR_BIN",
        "memprocfs_bin": "MEMPROCFS_BIN",
        "dotnet_bin": "PERCEPTOR_DOTNET",
        "usnjrnl_forensic_bin": "USNJRNL_FORENSIC_BIN",
    }
    for key, variable in env_map.items():
        if config.get(key):
            os.environ.setdefault(variable, str(Path(config[key]).expanduser()))
            if variable == "PERCEPTOR_DOTNET":
                os.environ.setdefault("FORENSIC_ORCHESTRATOR_DOTNET", str(Path(config[key]).expanduser()))
