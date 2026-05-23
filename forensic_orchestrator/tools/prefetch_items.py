from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from forensic_orchestrator.tools.prefetch_hash_lookup import resolve_prefetch_hash


def normalized_prefetch_row(
    *,
    case_id: str,
    computer_id: str,
    image_id: str,
    tool_output_id: str,
    tool_name: str,
    source_csv: Path,
    row_number: int,
    row: dict[str, Any],
    artifact_manifest: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    manifest = artifact_manifest or {}
    source_path = _text(row.get("source_path"))
    source_metadata = manifest.get(source_path or "", {})
    reference = resolve_prefetch_hash(
        prefetch_name=_text(row.get("prefetch_name")),
        executable_name=_text(row.get("executable_name")),
        prefetch_hash=_text(row.get("prefetch_hash")),
    )
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "tool_output_id": tool_output_id,
        "tool_name": tool_name,
        "source_csv": source_csv,
        "row_number": row_number,
        "prefetch_name": _text(row.get("prefetch_name")),
        "artifact_path": source_path,
        "original_path": source_metadata.get("original_path"),
        "executable_name": _text(row.get("executable_name")),
        "prefetch_hash": _text(row.get("prefetch_hash")),
        "prefetch_version": _text(row.get("prefetch_version")),
        "prefetch_version_label": _text(row.get("prefetch_version_label")),
        "compression": _text(row.get("compression")),
        "run_count": _text(row.get("run_count")),
        "last_run_time_utc": _text(row.get("last_run_time_utc")),
        "last_run_times_utc": _json_text(row.get("last_run_times_utc")),
        "_run_times_utc": _json_text(row.get("last_run_times_utc")),
        "referenced_string_count": _text(row.get("referenced_string_count")),
        "referenced_strings": _json_text(row.get("referenced_strings")),
        "parser_note": _text(row.get("parser_note")),
        "resolved_reference_path": reference["reference_path"],
        "resolved_reference_device_path": reference["reference_device_path"],
        "resolved_reference_command_line": reference["reference_command_line"],
        "resolved_reference_os": reference["reference_os"],
        "resolved_reference_description": reference["reference_description"],
        "resolved_reference_source": reference["reference_source"],
        "resolved_reference_match_count": reference["reference_match_count"],
        "pf_created": source_metadata.get("mft_created"),
        "pf_modified": source_metadata.get("mft_modified"),
        "pf_accessed": source_metadata.get("mft_accessed"),
        "pf_mft_record_modified": source_metadata.get("mft_record_modified"),
        "source_scope": "live",
        "snapshot_id": None,
        "snapshot_ids": None,
        "snapshot_count": None,
        "snapshot_index": None,
        "snapshot_created_utc": None,
    }


def normalized_prefetch_run_time_rows(prefetch_row: dict[str, Any]) -> list[dict[str, Any]]:
    run_times = _run_times(prefetch_row)
    if not run_times:
        return []
    last_run_time = _text(prefetch_row.get("last_run_time_utc"))
    rows: list[dict[str, Any]] = []
    for index, run_time in enumerate(run_times, start=1):
        rows.append(
            {
                "id": str(uuid.uuid4()),
                "case_id": prefetch_row["case_id"],
                "computer_id": prefetch_row["computer_id"],
                "image_id": prefetch_row["image_id"],
                "tool_output_id": prefetch_row["tool_output_id"],
                "tool_name": prefetch_row["tool_name"],
                "source_csv": prefetch_row["source_csv"],
                "prefetch_item_id": prefetch_row["id"],
                "prefetch_name": prefetch_row.get("prefetch_name"),
                "executable_name": prefetch_row.get("executable_name"),
                "prefetch_hash": prefetch_row.get("prefetch_hash"),
                "artifact_path": prefetch_row.get("artifact_path"),
                "original_path": prefetch_row.get("original_path"),
                "run_index": str(index),
                "run_time_utc": run_time,
                "is_last_run": "true" if last_run_time and run_time == last_run_time else "false",
                "source_scope": prefetch_row.get("source_scope") or "live",
                "snapshot_id": prefetch_row.get("snapshot_id"),
                "snapshot_ids": prefetch_row.get("snapshot_ids"),
                "snapshot_count": prefetch_row.get("snapshot_count"),
                "snapshot_index": prefetch_row.get("snapshot_index"),
                "snapshot_created_utc": prefetch_row.get("snapshot_created_utc"),
            }
        )
    return rows


def _run_times(row: dict[str, Any]) -> list[str]:
    values: list[str] = []
    raw_many = row.get("_run_times_utc") or row.get("last_run_times_utc")
    if raw_many:
        if isinstance(raw_many, list):
            values.extend(str(value).strip() for value in raw_many if str(value).strip())
        else:
            try:
                parsed = json.loads(str(raw_many))
                if isinstance(parsed, list):
                    values.extend(str(value).strip() for value in parsed if str(value).strip())
            except json.JSONDecodeError:
                pass
    single = _text(row.get("last_run_time_utc"))
    if single:
        values.append(single)
    return sorted(set(values))


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _json_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return json.dumps(value)
    normalized = str(value).strip()
    return normalized or None
