from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .cloud_sync import _timestamp_value, _unix_to_iso, _user_profile_from_path


ONEDRIVE_EXPLORER_FIELDS = [
    "provider",
    "artifact_type",
    "user_profile",
    "account",
    "source_path",
    "source_csv",
    "source_row_number",
    "record_type",
    "name",
    "path",
    "parent_resource_id",
    "resource_id",
    "etag",
    "status",
    "spo_permissions",
    "volume_id",
    "item_index",
    "last_change_utc",
    "disk_last_access_utc",
    "disk_creation_utc",
    "size",
    "local_hash_digest",
    "local_hash_algorithm",
    "shared_item",
    "media_json",
    "hydration_json",
    "metadata_json",
    "is_deleted",
    "delete_time_utc",
    "deleting_process",
    "error",
]


def parse_onedrive_explorer_to_csv(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    explorer = _find_onedrive_explorer()
    if explorer is None:
        rows.append(_error_row(source, "OneDriveExplorer.py not found. Set ONEDRIVE_EXPLORER to the script path."))
        return _write_output(output, rows)
    for profile in _onedrive_profiles(source):
        profile_output = output / "_onedrive_explorer" / _safe_name(str(profile.relative_to(source)))
        profile_output.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, str(explorer), "--PROFILE", str(profile), "--csv", "--output-dir", str(profile_output)]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(explorer.parent) + os.pathsep + env.get("PYTHONPATH", "")
        completed = subprocess.run(command, capture_output=True, text=True, check=False, env=env, timeout=1800)
        if completed.returncode:
            fallback_rows = _parse_onedrive_dat_with_explorer_library(profile, explorer, profile_output)
            if fallback_rows:
                rows.extend(fallback_rows)
                rows.append(
                    _error_row(
                        profile,
                        "OneDriveExplorer CLI failed; imported .dat records with OneDriveExplorer parser library fallback",
                        {
                            "command": command,
                            "returncode": completed.returncode,
                            "stderr": completed.stderr[-4000:],
                        },
                    )
                )
                continue
            rows.append(
                _error_row(
                    profile,
                    "OneDriveExplorer failed",
                    {
                        "command": command,
                        "returncode": completed.returncode,
                        "stdout": completed.stdout[-4000:],
                        "stderr": completed.stderr[-4000:],
                    },
                )
            )
            continue
        produced = list(profile_output.glob("*.csv"))
        if not produced:
            rows.append(_error_row(profile, "OneDriveExplorer produced no CSV output", {"command": command}))
            continue
        for csv_path in produced:
            rows.extend(_rows_from_onedrive_explorer_csv(profile, csv_path))
    return _write_output(output, rows)


def _parse_onedrive_dat_with_explorer_library(profile: Path, explorer: Path, output: Path) -> list[dict[str, object]]:
    sys.path.insert(0, str(explorer.parent))
    try:
        import ode.parsers.dat as dat_parser  # type: ignore
        import ode.parsers.dat_legacy as dat_legacy_parser  # type: ignore
    except Exception:
        return []
    rows: list[dict[str, object]] = []
    dat_files = sorted((profile / "settings").glob("*/*.dat")) + sorted((profile / "settings").glob("*/*.dat.previous"))
    if not dat_files:
        return []
    original_cwd = Path.cwd()
    with tempfile.TemporaryDirectory(dir=output) as temp_name:
        temp_dir = Path(temp_name)
        try:
            os.chdir(temp_dir)
            for dat_file in dat_files:
                account = dat_file.parent.name
                synthetic = f"{account}/{dat_file.name}"
                link_name = synthetic.replace("/", "\\")
                link_path = temp_dir / link_name
                try:
                    if not link_path.exists():
                        link_path.symlink_to(dat_file)
                    dat_parser.os.sep = "\\"
                    result, exit_code = dat_parser.DATParser().parse_dat(synthetic, account=account)
                    if exit_code or getattr(result.df, "empty", True):
                        dat_legacy_parser.os.sep = "\\"
                        result = dat_legacy_parser.DATParser().parse_dat(synthetic, account=account)
                        exit_code = 0
                except Exception as exc:
                    rows.append(_error_row(dat_file, "OneDriveExplorer DAT parser fallback failed", {"error": str(exc)}))
                    continue
                if exit_code:
                    rows.append(_error_row(dat_file, "OneDriveExplorer DAT parser returned non-zero", {"exit_code": exit_code}))
                    continue
                rows.extend(_rows_from_dataframe(profile, dat_file, result.df, "OneDriveExplorerDatFallback.csv"))
                rows.extend(_rows_from_dataframe(profile, dat_file, result.rbin_df, "OneDriveExplorerDatDeletedFallback.csv"))
        finally:
            os.chdir(original_cwd)
    return rows


def _rows_from_dataframe(profile: Path, source_path: Path, dataframe: Any, csv_name: str) -> list[dict[str, object]]:
    if dataframe is None or getattr(dataframe, "empty", True):
        return []
    rows: list[dict[str, object]] = []
    fake_csv = source_path.with_name(csv_name)
    for row_number, row in enumerate(dataframe.to_dict(orient="records"), start=1):
        normalized = _normalize_ode_row(profile, fake_csv, row_number, {str(k): "" if v is None else v for k, v in row.items()})
        normalized["source_path"] = str(source_path)
        normalized["source_csv"] = str(fake_csv)
        rows.append(normalized)
    return rows


def _find_onedrive_explorer() -> Path | None:
    configured = os.environ.get("ONEDRIVE_EXPLORER")
    candidates = [
        Path(configured) if configured else None,
        Path("third_party/OneDriveExplorer/OneDriveExplorer/OneDriveExplorer.py"),
        Path("/opt/OneDriveExplorer/OneDriveExplorer/OneDriveExplorer.py"),
        Path.home() / "tools" / "OneDriveExplorer" / "OneDriveExplorer" / "OneDriveExplorer.py",
        Path("/tmp/OneDriveExplorer/OneDriveExplorer/OneDriveExplorer.py"),
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate.resolve()
    return None


def _onedrive_profiles(source: Path) -> Iterable[Path]:
    if not source.exists():
        return []
    profiles: list[Path] = []
    for root, dirnames, _ in os.walk(source, onerror=lambda exc: None):
        root_path = Path(root)
        if root_path.name == "OneDrive" and root_path.parent.as_posix().lower().endswith("appdata/local/microsoft"):
            profiles.append(root_path)
            dirnames[:] = []
            continue
        if root_path.name.lower() not in {"users", "appdata", "local", "microsoft"} and "onedrive" not in root_path.as_posix().lower():
            lowered = root_path.as_posix().lower()
            if "appdata" in lowered or root_path == source:
                pass
    if source.name.lower() == "onedrive" and source.is_dir():
        profiles.append(source)
    return sorted(set(profiles))


def _rows_from_onedrive_explorer_csv(profile: Path, csv_path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(line for line in handle if not line.startswith("#"))
        for row_number, row in enumerate(reader, start=1):
            rows.append(_normalize_ode_row(profile, csv_path, row_number, dict(row)))
    return rows


def _normalize_ode_row(profile: Path, csv_path: Path, row_number: int, row: dict[str, Any]) -> dict[str, object]:
    record_type = _first_text(row, "Type", "type")
    name = _first_text(row, "Name", "name", "fileName", "folderName", "itemName")
    metadata = _json_payload(row)
    return {
        "provider": "OneDrive",
        "artifact_type": _artifact_type(csv_path, record_type),
        "user_profile": _user_profile_from_path(profile),
        "account": _account_from_path(profile, csv_path, row),
        "source_path": str(profile),
        "source_csv": str(csv_path),
        "source_row_number": row_number,
        "record_type": record_type,
        "name": name,
        "path": _first_text(row, "Path", "path", "remotePath"),
        "parent_resource_id": _first_text(row, "parentResourceID", "parentResourceId", "ParentFileSystemId"),
        "resource_id": _first_text(row, "resourceID", "resourceId", "scopeID"),
        "etag": _first_text(row, "eTag", "etag"),
        "status": _first_text(row, "fileStatus", "folderStatus", "Status", "inRecycleBin"),
        "spo_permissions": _first_text(row, "spoPermissions"),
        "volume_id": _first_text(row, "volumeID", "volumeId"),
        "item_index": _first_text(row, "itemIndex", "fileId"),
        "last_change_utc": _timestamp_value(_first_text(row, "lastChange")),
        "disk_last_access_utc": _timestamp_value(_first_text(row, "diskLastAccessTime")),
        "disk_creation_utc": _timestamp_value(_first_text(row, "diskCreationTime")),
        "size": _first_text(row, "size", "Size"),
        "local_hash_digest": _first_text(row, "localHashDigest", "hash"),
        "local_hash_algorithm": _hash_algorithm(_first_text(row, "localHashDigest", "hash")),
        "shared_item": _first_text(row, "sharedItem"),
        "media_json": _first_text(row, "Media"),
        "hydration_json": _hydration_json(row),
        "metadata_json": metadata,
        "is_deleted": "true" if record_type.lower() == "deleted" or _first_text(row, "DeleteTimeStamp") else "",
        "delete_time_utc": _timestamp_value(_first_text(row, "DeleteTimeStamp", "notificationTime")),
        "deleting_process": _first_text(row, "deletingProcess"),
        "error": "",
    }


def _artifact_type(csv_path: Path, record_type: str) -> str:
    name = csv_path.name.lower()
    if name.endswith("_logs.csv"):
        return "onedrive_explorer_log"
    if "fileusagesync" in name:
        return "onedrive_file_usage_sync"
    if "list_sync" in name:
        return "onedrive_list_sync"
    if "fod" in name:
        return "onedrive_files_on_demand"
    if record_type.lower() == "deleted":
        return "onedrive_deleted_item"
    return "onedrive_explorer_item"


def _account_from_path(profile: Path, csv_path: Path, row: dict[str, Any]) -> str:
    account = _first_text(row, "Account", "account")
    if account:
        return account
    match = re.search(r"(Personal|Business\d)", str(csv_path), flags=re.I)
    if match:
        return match.group(1)
    for part in reversed(profile.parts):
        if part.lower().startswith("business") or part.lower() == "personal":
            return part
    return ""


def _hydration_json(row: dict[str, Any]) -> str:
    hydration = {
        key: value
        for key, value in row.items()
        if "hydration" in str(key).lower() or str(key).lower() in {"lastknownpinstate", "pinstate"}
    }
    return json.dumps(hydration, ensure_ascii=False, default=str) if hydration else ""


def _json_payload(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, default=str)


def _hash_algorithm(value: str) -> str:
    lower = value.lower()
    if lower.startswith("sha1("):
        return "SHA1"
    if lower.startswith("quickxor("):
        return "quickXor"
    return ""


def _error_row(path: Path, error: str, details: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "provider": "OneDrive",
        "artifact_type": "onedrive_explorer_error",
        "user_profile": _user_profile_from_path(path),
        "source_path": str(path),
        "source_csv": "",
        "error": error,
        "metadata_json": json.dumps(details or {}, ensure_ascii=False, default=str),
    }


def _write_output(output: Path, rows: list[dict[str, object]]) -> Path:
    csv_path = output / "OneDriveExplorerArtifacts.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ONEDRIVE_EXPLORER_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return csv_path


def _first_text(row: dict[str, Any], *names: str) -> str:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value)
    return ""


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "onedrive"
