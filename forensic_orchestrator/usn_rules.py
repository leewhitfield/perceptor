from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


DEFAULT_USN_RULES_PATH = Path(__file__).parent / "plugins" / "usn_rules.yaml"


def load_usn_rules(path: str | Path | None = None) -> dict[str, Any]:
    rules_path = Path(path) if path else DEFAULT_USN_RULES_PATH
    data = yaml.safe_load(rules_path.read_text()) if rules_path.exists() else {}
    return data or {"usn_filters": {"include": [], "suppress": []}}


def match_usn_rules(row: dict[str, Any], rules: dict[str, Any]) -> tuple[list[str], list[str]]:
    filters = rules.get("usn_filters") or {}
    return (
        _matching_rule_names(row, filters.get("include") or []),
        _matching_rule_names(row, filters.get("suppress") or []),
    )


def _matching_rule_names(row: dict[str, Any], rules: list[dict[str, Any]]) -> list[str]:
    return [str(rule.get("name") or "unnamed_rule") for rule in rules if _rule_matches(row, rule)]


def _rule_matches(row: dict[str, Any], rule: dict[str, Any]) -> bool:
    path = _lower(row.get("full_path"))
    file_name = _lower(row.get("file_name"))
    extension = _normalize_extension(row.get("extension"))
    reason = _lower(row.get("reason"))
    path_contains = rule.get("path_contains")
    if path_contains and _lower(path_contains) not in path and _lower(path_contains) not in file_name:
        return False
    reason_contains = rule.get("reason_contains")
    if reason_contains and _lower(reason_contains) not in reason:
        return False
    extensions = rule.get("extensions")
    if extensions and extension not in {_normalize_extension(item) for item in extensions}:
        return False
    return True


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _normalize_extension(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text[1:] if text.startswith(".") else text
