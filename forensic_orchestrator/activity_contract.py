from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import PureWindowsPath
from typing import Any


CONTRACT_FIELDS = (
    "source_table",
    "source_row_id",
    "source_tool",
    "event_time_utc",
    "timestamp_meaning",
    "path",
    "file_name",
    "user_profile",
    "artifact_category",
    "interpretation_note",
)


@dataclass(frozen=True)
class ActivityContract:
    source_table: str
    source_row_id: str
    source_tool: str
    event_time_utc: str | None
    timestamp_meaning: str
    path: str | None
    file_name: str | None
    user_profile: str | None
    artifact_category: str
    interpretation_note: str

    def as_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}


def activity_contract_row(
    *,
    source_table: str,
    source_row_id: str,
    source_tool: str,
    event_time_utc: str | None,
    timestamp_meaning: str,
    path: str | None,
    file_name: str | None = None,
    user_profile: str | None = None,
    artifact_category: str,
    interpretation_note: str,
) -> dict[str, Any]:
    contract = ActivityContract(
        source_table=_required("source_table", source_table),
        source_row_id=_required("source_row_id", source_row_id),
        source_tool=_required("source_tool", source_tool),
        event_time_utc=event_time_utc or None,
        timestamp_meaning=_required("timestamp_meaning", timestamp_meaning),
        path=path or None,
        file_name=file_name or _file_name(path),
        user_profile=user_profile or _user_from_path(path),
        artifact_category=_required("artifact_category", artifact_category),
        interpretation_note=_required("interpretation_note", interpretation_note),
    )
    return contract.as_dict()


def validate_activity_contract(row: dict[str, Any]) -> None:
    missing = [field for field in CONTRACT_FIELDS if field not in row]
    if missing:
        raise ValueError(f"Activity contract row is missing required fields: {', '.join(missing)}")
    empty_required = [
        field
        for field in (
            "source_table",
            "source_row_id",
            "source_tool",
            "timestamp_meaning",
            "artifact_category",
            "interpretation_note",
        )
        if not row.get(field)
    ]
    if empty_required:
        raise ValueError(f"Activity contract row has empty required fields: {', '.join(empty_required)}")


def _required(name: str, value: str | None) -> str:
    if not value:
        raise ValueError(f"Activity contract field is required: {name}")
    return str(value)


def _file_name(path: str | None) -> str | None:
    if not path:
        return None
    return PureWindowsPath(path.replace("/", "\\")).name or None


def _user_from_path(path: str | None) -> str | None:
    if not path:
        return None
    parts = [part for part in path.replace("/", "\\").split("\\") if part]
    for index, part in enumerate(parts[:-1]):
        if part.lower() == "users":
            return parts[index + 1]
    return None
