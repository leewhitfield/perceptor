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


def default_plugin_path() -> Path:
    return Path(__file__).parent / "plugins" / "eztools.yaml"


def load_config(root: str | None = None, plugins: list[str] | None = None, config_path: str | None = None) -> AppConfig:
    config = _load_config_file(config_path)
    configured_root = Path(
        root
        or config.get("root")
        or os.environ.get("FORENSIC_ORCHESTRATOR_ROOT", DEFAULT_ROOT)
    )
    configured_plugins = plugins or config.get("plugins")
    plugin_paths = [Path(p) for p in configured_plugins] if configured_plugins else [default_plugin_path()]
    return AppConfig(root=configured_root, plugin_paths=plugin_paths)


def _load_config_file(config_path: str | None) -> dict:
    path_value = config_path or os.environ.get("FORENSIC_ORCHESTRATOR_CONFIG")
    if not path_value:
        return {}
    path = Path(path_value).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file must contain a mapping: {path}")
    return data
