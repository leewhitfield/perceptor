from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .paths import DEFAULT_ROOT


@dataclass(frozen=True)
class AppConfig:
    root: Path
    plugin_paths: list[Path]


def default_plugin_path() -> Path:
    return Path(__file__).parent / "plugins" / "eztools.yaml"


def load_config(root: str | None = None, plugins: list[str] | None = None) -> AppConfig:
    configured_root = Path(root or os.environ.get("FORENSIC_ORCHESTRATOR_ROOT", DEFAULT_ROOT))
    plugin_paths = [Path(p) for p in plugins] if plugins else [default_plugin_path()]
    return AppConfig(root=configured_root, plugin_paths=plugin_paths)
