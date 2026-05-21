from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


DEFAULT_INTERESTING_EXECUTABLES_PATH = Path(__file__).parent / "plugins" / "interesting_executables.yaml"


def load_interesting_executable_rules(path: str | Path | None = None) -> dict[str, Any]:
    rules_path = Path(path) if path else DEFAULT_INTERESTING_EXECUTABLES_PATH
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8")) if rules_path.exists() else {}
    rules = data or {"interesting_executables": []}
    rules["interesting_executables"] = [_normalize_rule(rule) for rule in rules.get("interesting_executables") or []]
    return rules


def _normalize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(rule or {})
    normalized["id"] = str(normalized.get("id") or normalized.get("label") or "unnamed_rule")
    normalized["label"] = str(normalized.get("label") or normalized["id"])
    normalized["category"] = str(normalized.get("category") or "interesting_application")
    normalized["severity"] = str(normalized.get("severity") or "medium")
    for key in ("filenames", "name_contains", "path_contains", "text_contains", "regex"):
        values = normalized.get(key)
        if values is None:
            normalized[key] = []
        elif isinstance(values, str):
            normalized[key] = [values]
        else:
            normalized[key] = [str(value) for value in values if str(value or "").strip()]
    evidence_types = normalized.get("evidence_types")
    if evidence_types is None:
        normalized["evidence_types"] = []
    elif isinstance(evidence_types, str):
        normalized["evidence_types"] = [evidence_types]
    else:
        normalized["evidence_types"] = [str(value) for value in evidence_types if str(value or "").strip()]
    normalized["filenames"] = [_normalize_filename(value) for value in normalized["filenames"]]
    return normalized


def _normalize_filename(value: Any) -> str:
    text = str(value or "").strip().strip("\"'").replace("\\", "/")
    return text.rsplit("/", 1)[-1].casefold()
