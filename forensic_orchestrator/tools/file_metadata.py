from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path
from typing import Any

from forensic_orchestrator.safety import MissingDependencyError


CSV_FIELDS = [
    "source_file",
    "original_path",
    "file_name",
    "extension",
    "parser",
    "metadata_group",
    "property_name",
    "property_value",
    "raw_property_name",
    "file_size",
    "mft_created",
    "mft_modified",
    "mft_accessed",
    "mft_record_modified",
    "mft_in_use",
    "path_unresolved",
    "deleted_mft_entry",
    "live_orphan",
    "extraction_method",
]


def parse_file_metadata_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "FileMetadata.csv"
    manifest = _load_manifest(source)
    files = _manifest_files(manifest)
    if not files:
        files = sorted(
            path
            for path in source.rglob("*")
            if path.is_file() and path.name != "_artifact_manifest.csv" and "_extract_jobs" not in path.parts
        )
    rows: list[dict[str, str]] = []
    for batch in _batches(files, size=50):
        rows.extend(_exiftool_rows(batch, manifest))
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def _exiftool_rows(files: list[Path], manifest: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    if not files:
        return []
    command = ["exiftool", "-j", "-G1", "-a", "-s", *[str(path) for path in files]]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise MissingDependencyError("Missing dependency: exiftool") from exc
    if completed.returncode != 0 and not completed.stdout.strip():
        raise RuntimeError((completed.stderr or "exiftool failed").strip())
    try:
        records = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse exiftool JSON output: {exc}") from exc

    rows: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        source_file = _text(record.get("SourceFile"))
        source_path = Path(source_file) if source_file else None
        manifest_row = manifest.get(source_file or "", {})
        for raw_name, value in sorted(record.items()):
            if raw_name == "SourceFile":
                continue
            property_value = _metadata_value(value)
            if property_value is None:
                continue
            group, property_name = _split_property_name(str(raw_name))
            rows.append(
                {
                    "source_file": source_file or "",
                    "original_path": manifest_row.get("original_path", ""),
                    "file_name": source_path.name if source_path else "",
                    "extension": source_path.suffix.lower() if source_path else "",
                    "parser": "exiftool",
                    "metadata_group": group,
                    "property_name": property_name,
                    "property_value": property_value,
                    "raw_property_name": str(raw_name),
                    "file_size": manifest_row.get("original_size") or manifest_row.get("size", ""),
                    "mft_created": manifest_row.get("mft_created", ""),
                    "mft_modified": manifest_row.get("mft_modified", ""),
                    "mft_accessed": manifest_row.get("mft_accessed", ""),
                    "mft_record_modified": manifest_row.get("mft_record_modified", ""),
                    "mft_in_use": manifest_row.get("mft_in_use", ""),
                    "path_unresolved": manifest_row.get("path_unresolved", ""),
                    "deleted_mft_entry": manifest_row.get("deleted_mft_entry", ""),
                    "live_orphan": manifest_row.get("live_orphan", ""),
                    "extraction_method": manifest_row.get("extraction_method", ""),
                }
            )
    return rows


def _load_manifest(source: Path) -> dict[str, dict[str, str]]:
    manifest_path = source / "_artifact_manifest.csv"
    if not manifest_path.exists():
        return {}
    with manifest_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        return {
            row["artifact_path"]: dict(row)
            for row in csv.DictReader(handle)
            if row.get("artifact_path")
        }


def _manifest_files(manifest: dict[str, dict[str, str]]) -> list[Path]:
    files = []
    for path_text in manifest:
        path = Path(path_text)
        if path.exists() and path.is_file():
            files.append(path)
    return sorted(files)


def _split_property_name(name: str) -> tuple[str, str]:
    if ":" not in name:
        return "", name
    group, property_name = name.split(":", 1)
    return group, property_name


def _metadata_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
    elif isinstance(value, (int, float, bool)):
        normalized = str(value)
    else:
        normalized = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return normalized or None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _batches(values: list[Path], *, size: int) -> list[list[Path]]:
    return [values[index : index + size] for index in range(0, len(values), size)]
