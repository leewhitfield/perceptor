from __future__ import annotations

import uuid
import csv
from pathlib import Path
from typing import Any


def normalized_recmd_detail_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
    ownership: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]] | None:
    artifact = _artifact_from_csv(source_csv)
    if artifact is None:
        return None
    owner = ownership or {}
    base = {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": str(source_csv),
        "row_number": row_number,
        "hive_path": _text(owner.get("HivePath")),
        "hive_type": _text(owner.get("HiveType")),
        "user_profile": _user_profile_from_hive_path(_text(owner.get("HivePath"))),
        "category": _text(owner.get("Category")),
        "key_path": _text(owner.get("KeyPath")) or _text(row.get("BatchKeyPath")),
        "key_last_write_timestamp": _text(owner.get("LastWriteTimestamp")),
        "recmd_description": _text(owner.get("Description")) or artifact,
    }
    if artifact == "recentdocs":
        return "registry_recentdocs", {
            **base,
            "extension": _text(row.get("Extension")),
            "batch_key_path": _text(row.get("BatchKeyPath")),
            "value_name": _text(row.get("ValueName")),
            "batch_value_name": _text(row.get("BatchValueName")),
            "target_name": _text(row.get("TargetName")),
            "lnk_name": _text(row.get("LnkName")),
            "mru_position": _text(row.get("MruPosition")),
            "opened_on": _text(row.get("OpenedOn")),
            "extension_last_opened": _text(row.get("ExtensionLastOpened")),
        }
    if artifact == "runmru":
        return "registry_runmru", {
            **base,
            "value_name": _text(row.get("ValueName")),
            "batch_key_path": _text(row.get("BatchKeyPath")),
            "mru_position": _text(row.get("MruPosition")),
            "batch_value_name": _text(row.get("BatchValueName")),
            "executable": _text(row.get("Executable")),
            "opened_on": _text(row.get("OpenedOn")),
        }
    if artifact == "typedpaths":
        return "registry_typedpaths", {
            **base,
            "value_name": _text(row.get("ValueName")),
            "batch_key_path": _text(row.get("BatchKeyPath")),
            "mru_position": _text(row.get("MruPosition")),
            "batch_value_name": _text(row.get("BatchValueName")),
            "path": _text(row.get("Path") or row.get("AbsolutePath") or row.get("ValueData")),
            "opened_on": _text(row.get("OpenedOn") or row.get("LastWriteTimestamp")),
        }
    if artifact == "wordwheelquery":
        return "registry_wordwheel_query", {
            **base,
            "search_term": _text(row.get("SearchTerm")),
            "batch_key_path": _text(row.get("BatchKeyPath")),
            "mru_position": _text(row.get("MruPosition")),
            "batch_value_name": _text(row.get("BatchValueName")),
            "key_name": _text(row.get("KeyName")),
            "last_write_timestamp": _text(row.get("LastWriteTimestamp")),
        }
    if artifact == "userassist":
        return "registry_userassist", {
            **base,
            "batch_key_path": _text(row.get("BatchKeyPath")),
            "batch_value_name": _text(row.get("BatchValueName")),
            "program_name": _text(row.get("ProgramName")),
            "run_counter": _text(row.get("RunCounter")),
            "focus_count": _text(row.get("FocusCount")),
            "focus_time": _text(row.get("FocusTime")),
            "last_executed": _text(row.get("LastExecuted")),
        }
    if artifact == "officemru":
        return "registry_office_mru", {
            **base,
            "value_name": _text(row.get("ValueName")),
            "batch_key_path": _text(row.get("BatchKeyPath")),
            "last_opened": _text(row.get("LastOpened")),
            "batch_value_name": _text(row.get("BatchValueName")),
            "last_closed": _text(row.get("LastClosed")),
            "file_name": _text(row.get("FileName")),
        }
    if artifact in {"opensavepidlmru", "lastvisitedpidlmru"}:
        return "registry_common_dialog_mru", {
            **base,
            "artifact": artifact,
            "extension": _text(row.get("Extension")),
            "value_name": _text(row.get("ValueName")),
            "batch_key_path": _text(row.get("BatchKeyPath")),
            "mru_position": _text(row.get("MruPosition")),
            "batch_value_name": _text(row.get("BatchValueName")),
            "executable": _text(row.get("Executable")),
            "absolute_path": _text(row.get("AbsolutePath")),
            "opened_on": _text(row.get("OpenedOn")),
            "details": _text(row.get("Details")),
        }
    if artifact == "trusteddocuments":
        return "registry_trusted_documents", {
            **base,
            "event_type": _text(row.get("EventType")),
            "batch_key_path": _text(row.get("BatchKeyPath")),
            "timestamp": _text(row.get("Timestamp")),
            "batch_value_name": _text(row.get("BatchValueName")),
            "file_name": _text(row.get("FileName")),
            "username": _text(row.get("Username")),
        }
    return None


def _artifact_from_csv(source_csv: Path) -> str | None:
    stem = source_csv.stem
    prefix = "RECmd_WindowsActivity_"
    if not stem.startswith(prefix):
        return None
    return stem[len(prefix) :].lower()


def recmd_ownership_rows(detail_csv: Path) -> list[dict[str, Any]]:
    main_csv = _find_recmd_main_csv(detail_csv)
    if main_csv is None:
        return []
    rows: list[dict[str, Any]] = []
    with main_csv.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            plugin_detail = _text(row.get("PluginDetailFile"))
            if not plugin_detail:
                continue
            plugin_path = Path(plugin_detail)
            if plugin_path.name == detail_csv.name:
                rows.append(dict(row))
    return rows


def _find_recmd_main_csv(detail_csv: Path) -> Path | None:
    candidates = [
        detail_csv.parent / "RECmd_WindowsActivity.csv",
        detail_csv.parent.parent / "RECmd_WindowsActivity.csv",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _user_profile_from_hive_path(path: str | None) -> str | None:
    if not path:
        return None
    parts = Path(path).parts
    lowered = [part.lower() for part in parts]
    if "users" in lowered:
        index = lowered.index("users")
        if index + 1 < len(parts):
            return parts[index + 1]
    if path.lower().endswith("ntuser.dat") or path.lower().endswith("usrclass.dat"):
        return Path(path).parent.name
    return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None
