from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
import re
import shutil
from typing import Any

import duckdb

from forensic_orchestrator.common_dialog_resolution import (
    common_dialog_guid_resolution_map,
    is_common_dialog_guid,
)
from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.models import EvidenceImage
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError
from forensic_orchestrator.tools.normalized import normalized_registry_artifact_row
from forensic_orchestrator.tools.registry_artifacts import parse_registry_artifacts

from .vshadow import VscSnapshot, discover_vsc_snapshots, mount_vsc_snapshot, unmount_vsc
from .vsc_promote import add_vsc_provenance, clear_vsc_rows, promote_deduped_rows


REGISTRY_ARTIFACT_COLUMNS = [
    "case_id",
    "image_id",
    "snapshot_id",
    "snapshot_index",
    "snapshot_created_utc",
    "source_path",
    "hive_type",
    "user_profile",
    "user_sid",
    "artifact",
    "category",
    "key_path",
    "key_last_write_utc",
    "event_time_utc",
    "recentdocs_time_utc",
    "recentdocs_extension_time_utc",
    "mru_position",
    "recentdocs_mru_position",
    "recentdocs_extension_mru_position",
    "is_most_recent",
    "value_name",
    "value_type",
    "value_data",
    "display_name",
    "normalized_path",
    "run_counter",
    "focus_count",
    "focus_time",
    "last_executed",
    "value_data_hex",
    "transaction_logs_detected",
    "transaction_logs_applied",
    "transaction_log_paths",
    "application_identity",
    "resolved_application",
    "application_resolution_source",
    "application_resolution_confidence",
    "notes",
    "record_signature",
    "parsed_at",
]

VSC_REGISTRY_ARTIFACTS = {
    "autostart",
    "bam",
    "dam",
    "cloud_google_drivefs",
    "cloud_icloud",
    "cloud_onedrive_account",
    "cloud_onedrive_sync_engine",
    "cloud_dropbox_syncroot",
    "common_dialog",
    "connected_networks",
    "mui_cache",
    "office_recent_docs",
    "outlook_secure_temp",
    "ras_connection_manager",
    "ras_phonebook_registry",
    "recentdocs",
    "runmru",
    "startup_approved",
    "taskbar_usage",
    "typed_paths",
    "userassist",
    "wordwheel_query",
}

VSC_USER_PROFILE_ALIASES = {
    "default user": "Default",
}

OFFICE_RECENT_DOC_EXTENSIONS = {
    ".doc",
    ".docm",
    ".docx",
    ".dot",
    ".dotm",
    ".dotx",
    ".csv",
    ".xls",
    ".xlsb",
    ".xlsm",
    ".xlsx",
    ".xlt",
    ".xltm",
    ".xltx",
    ".odp",
    ".ods",
    ".odt",
    ".one",
    ".pdf",
    ".pot",
    ".potm",
    ".potx",
    ".pps",
    ".ppsm",
    ".ppsx",
    ".ppt",
    ".pptm",
    ".pptx",
    ".rtf",
}

OFFICE_RECENT_DOC_KEY_ALLOWLIST = (
    "/user mru/",
    "/file mru/",
    "/place mru/",
    "/reading locations/",
)

OFFICE_RECENT_DOC_KEY_BLOCKLIST = (
    "/common/internet/webservicecache/",
    "/outlook/diagnostics/",
    "/common/targetedmessagingservice/",
    "/common/servicesmanagercache/",
    "/common/identity/",
    "/common/roaming/identities/",
    "/common/general/",
    "/common/fileio/",
    "/security/trusted locations/",
)


def run_vsc_registry_scan(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image: EvidenceImage,
    snapshot_indexes: list[int] | None = None,
    use_sudo_mount: bool = False,
) -> dict[str, Any]:
    paths.ensure_case_tree(case_id)
    started_at = utc_now()
    inventory = discover_vsc_snapshots(db=db, paths=paths, case_id=case_id, image=image)
    snapshots = [_snapshot_from_payload(item) for item in inventory.get("snapshots", [])]
    if snapshot_indexes:
        wanted = set(snapshot_indexes)
        snapshots = [snapshot for snapshot in snapshots if snapshot.index in wanted]
    if not snapshots:
        raise MountError("No VSC snapshots selected for registry scan")

    db_path = paths.vsc_parsed_db_path(case_id)
    conn = duckdb.connect(str(db_path))
    try:
        _ensure_registry_table(conn)
        _clear_snapshot_rows(conn, case_id=case_id, image_id=image.id, snapshot_ids=[f"vss{s.index}" for s in snapshots])
        clear_vsc_rows(
            db,
            table="registry_artifacts",
            case_id=case_id,
            image_id=image.id,
            snapshot_ids=[f"vss{s.index}" for s in snapshots],
        )
        live_signatures = _live_registry_signatures(db, case_id=case_id)
        common_dialog_resolutions = common_dialog_guid_resolution_map(db, case_id=case_id, image_id=image.id)
        snapshot_results: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        all_rows: list[dict[str, Any]] = []
        for snapshot in snapshots:
            snapshot_id = f"vss{snapshot.index}"
            step_started_at = utc_now()
            try:
                mount = mount_vsc_snapshot(
                    db=db,
                    paths=paths,
                    case_id=case_id,
                    image=image,
                    snapshot_index=snapshot.index,
                    use_sudo_mount=use_sudo_mount,
                )
                extracted = extract_vsc_registry_hives(
                    paths=paths,
                    case_id=case_id,
                    snapshot_id=snapshot_id,
                )
                rows = parse_vsc_registry_snapshot(
                    paths=paths,
                    case_id=case_id,
                    computer_id=image.computer_id or "vsc",
                    image_id=image.id,
                    snapshot=snapshot,
                    snapshot_id=snapshot_id,
                    hive_paths=extracted["hives"],
                    common_dialog_resolutions=common_dialog_resolutions,
                )
                _insert_registry_rows(conn, rows)
                all_rows.extend(rows)
                snapshot_results.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "hive_count": len(extracted["hives"]),
                        "parsed_rows": len(rows),
                        "mount_path": mount["volume_mount_path"],
                        "started_at": step_started_at,
                        "ended_at": utc_now(),
                    }
                )
            except Exception as exc:
                failures.append(
                    {
                        "snapshot_id": snapshot_id,
                        "snapshot_index": snapshot.index,
                        "snapshot_created_utc": snapshot.created_utc,
                        "error": str(exc),
                        "started_at": step_started_at,
                        "ended_at": utc_now(),
                    }
                )
            finally:
                unmount_vsc(paths=paths, case_id=case_id, snapshot_id=snapshot_id, use_sudo_mount=use_sudo_mount)

        promote_deduped_rows(
            db,
            table="registry_artifacts",
            rows=[add_vsc_provenance(row, source_csv=f"vsc://{row.get('snapshot_id')}/RegistryHives") for row in all_rows],
            key_func=registry_record_signature,
        )
        snapshot_rows = _snapshot_rows(conn, case_id=case_id, image_id=image.id)
        comparison = compare_registry_snapshots(live_signatures=live_signatures, snapshot_rows=snapshot_rows)
        ended_at = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "registry-vsc-comparison.md"
        report_path.write_text(
            _registry_comparison_markdown(
                comparison,
                snapshot_results,
                failures,
                started_at=started_at,
                ended_at=ended_at,
            ),
            encoding="utf-8",
        )
        payload = {
            "case_id": case_id,
            "image_id": image.id,
            "started_at": started_at,
            "ended_at": ended_at,
            "vsc_db_path": str(db_path),
            "report_path": str(report_path),
            "snapshot_count": len(snapshots),
            "successful_snapshots": len(snapshot_results),
            "failed_snapshots": len(failures),
            "snapshot_results": snapshot_results,
            "failures": failures,
            "comparison_summary": comparison["summary"],
        }
        _write_json(paths.vsc_work_dir(case_id) / "registry-scan.json", payload)
        return payload
    finally:
        conn.close()


def extract_vsc_registry_hives(*, paths: WorkspacePaths, case_id: str, snapshot_id: str) -> dict[str, Any]:
    mount_dir = paths.vsc_snapshot_mount_dir(case_id, snapshot_id)
    if not mount_dir.exists():
        raise MountError(f"VSC snapshot is not mounted: {mount_dir}")
    destination = paths.vsc_snapshot_extract_dir(case_id, snapshot_id) / "RegistryHives"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    hives: list[Path] = []
    errors: list[dict[str, str]] = []

    config = mount_dir / "Windows" / "System32" / "config"
    for name in ("SYSTEM", "SOFTWARE"):
        source = config / name
        if source.is_file():
            copied = _try_copy_hive_with_logs(source, destination / "Windows" / "System32" / "config" / name, errors)
            if copied:
                hives.append(copied)

    users_dir = mount_dir / "Users"
    if users_dir.is_dir():
        for ntuser in sorted(users_dir.glob("*/NTUSER.DAT")):
            user = ntuser.parent.name
            copied = _try_copy_hive_with_logs(ntuser, destination / "Users" / user / "NTUSER.DAT", errors)
            if copied:
                hives.append(copied)
        for usrclass in sorted(users_dir.glob("*/AppData/Local/Microsoft/Windows/UsrClass.dat")):
            user = usrclass.parents[4].name
            copied = _try_copy_hive_with_logs(
                usrclass,
                destination / "Users" / user / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat",
                errors,
            )
            if copied:
                hives.append(copied)
    manifest = {
        "snapshot_id": snapshot_id,
        "hive_count": len(hives),
        "hives": [str(path) for path in hives],
        "copy_errors": errors,
        "created_at": utc_now(),
    }
    _write_json(destination / "manifest.json", manifest)
    return {"hives": hives, "manifest": manifest}


def parse_vsc_registry_snapshot(
    *,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
    computer_id: str = "vsc",
    snapshot: VscSnapshot,
    snapshot_id: str,
    hive_paths: list[Path],
    common_dialog_resolutions: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    common_dialog_resolutions = common_dialog_resolutions or {}
    rows: list[dict[str, Any]] = []
    for hive_path in hive_paths:
        try:
            parsed_rows = parse_registry_artifacts(hive_path, allowed_artifacts=VSC_REGISTRY_ARTIFACTS)
        except Exception as exc:
            parsed_rows = [
                {
                    "source_path": str(hive_path),
                    "artifact": "parser_error",
                    "category": "error",
                    "notes": str(exc),
                }
            ]
        for row_number, row in enumerate(parsed_rows, start=1):
            live_normalized = normalized_registry_artifact_row(
                case_id=case_id,
                computer_id=computer_id,
                image_id=image_id,
                tool_output_id=f"{snapshot_id}-RegistryArtifactParser",
                tool_name="RegistryArtifactParser",
                source_csv=hive_path,
                row_number=row_number,
                row=dict(row),
            )
            normalized = {
                "case_id": case_id,
                "computer_id": computer_id,
                "image_id": image_id,
                "tool_output_id": f"{snapshot_id}-RegistryArtifactParser",
                "tool_name": "RegistryArtifactParser",
                "source_csv": hive_path,
                "row_number": row_number,
                "snapshot_id": snapshot_id,
                "snapshot_index": snapshot.index,
                "snapshot_created_utc": snapshot.created_utc,
                "source_path": _relative_to_work(paths.vsc_work_dir(case_id), hive_path),
                "parsed_at": utc_now(),
            }
            for column in REGISTRY_ARTIFACT_COLUMNS:
                if column in normalized or column in {"snapshot_id", "snapshot_index", "snapshot_created_utc", "application_identity", "resolved_application", "application_resolution_source", "application_resolution_confidence", "record_signature", "parsed_at"}:
                    continue
                normalized[column] = _text(live_normalized.get(column))
            normalized["user_profile"] = normalize_vsc_user_profile(normalized.get("user_profile"))
            if normalized["artifact"] == "common_dialog":
                application_identity = _common_dialog_application_identity(normalized["value_data"])
                normalized["application_identity"] = application_identity
                resolution = common_dialog_resolutions.get(application_identity.casefold()) if application_identity else None
                if resolution is not None:
                    normalized["resolved_application"] = resolution.resolved_executable
                    normalized["application_resolution_source"] = f"live_common_dialog:{resolution.resolution_source}"
                    normalized["application_resolution_confidence"] = resolution.resolution_confidence
            normalized["record_signature"] = registry_record_signature(normalized)
            rows.append(normalized)
    return rows


def compare_registry_snapshots(*, live_signatures: set[str], snapshot_rows: list[dict[str, Any]]) -> dict[str, Any]:
    unique: dict[str, dict[str, Any]] = {}
    by_snapshot: dict[str, dict[str, Any]] = {}
    for row in snapshot_rows:
        summary = by_snapshot.setdefault(
            row["snapshot_id"],
            {
                "snapshot_id": row["snapshot_id"],
                "snapshot_index": row["snapshot_index"],
                "snapshot_created_utc": row.get("snapshot_created_utc") or "",
                "row_count": 0,
                "unique_not_live_count": 0,
            },
        )
        summary["row_count"] += 1
        signature = registry_value_signature(row)
        if signature and not _vsc_comparison_candidate(row):
            signature = ""
        if signature and signature not in live_signatures:
            summary["unique_not_live_count"] += 1
            unique.setdefault(signature, row)

    artifact_counts = Counter(row.get("artifact") or "unknown" for row in unique.values())
    category_counts = Counter(row.get("category") or "unknown" for row in unique.values())
    examples = _balanced_examples(unique.values(), per_artifact=10, total=100)
    return {
        "summary": {
            "vsc_registry_rows": len(snapshot_rows),
            "unique_vsc_records_not_live": len(unique),
            "artifact_count": len(artifact_counts),
        },
        "snapshots": sorted(by_snapshot.values(), key=lambda item: int(item["snapshot_index"])),
        "artifact_counts": dict(sorted(artifact_counts.items(), key=lambda item: (-item[1], item[0]))),
        "category_counts": dict(sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))),
        "examples": examples,
    }


def registry_record_signature(row: dict[str, Any]) -> str:
    return registry_value_signature(row)


def normalize_vsc_user_profile(value: str | None) -> str:
    text = _text(value)
    if not text:
        return ""
    return VSC_USER_PROFILE_ALIASES.get(text.casefold(), text)


def registry_value_signature(row: dict[str, Any]) -> str:
    artifact = _comparison_text(row.get("artifact"), case_insensitive=True)
    if artifact == "userassist":
        identity = _userassist_identity(row)
        parts = [
            artifact,
            _comparison_text(normalize_vsc_user_profile(_text(row.get("user_profile"))), case_insensitive=True),
            _normalize_registry_key_path(row.get("key_path")),
            identity,
            _text(row.get("last_executed")),
        ]
        return "\x1f".join(value or "" for value in parts)
    event_time = _text(row.get("event_time_utc"))
    if artifact in {"common_dialog", "recentdocs", "wordwheel_query"}:
        event_time = _text(row.get("key_last_write_utc"))
    parts = [
        artifact,
        _comparison_text(normalize_vsc_user_profile(_text(row.get("user_profile"))), case_insensitive=True),
        _comparison_text(row.get("user_sid"), case_insensitive=True),
        _normalize_registry_key_path(row.get("key_path")),
        _comparison_text(row.get("value_name"), path_aware=True, case_insensitive=True),
        event_time,
        _comparison_text(row.get("normalized_path"), path_aware=True, case_insensitive=True),
        _comparison_text(row.get("display_name"), path_aware=True, case_insensitive=False),
        _comparison_text(row.get("value_data"), path_aware=True, case_insensitive=False),
    ]
    return "\x1f".join(value or "" for value in parts)


def _vsc_comparison_candidate(row: dict[str, Any]) -> bool:
    artifact = _comparison_text(row.get("artifact"), case_insensitive=True)
    if artifact == "office_recent_docs":
        return _office_recent_docs_vsc_comparison_candidate(row)
    if artifact == "mui_cache":
        return _mui_cache_vsc_comparison_candidate(row)
    if artifact in {"bam", "dam"}:
        return _is_full_account_sid(_comparison_text(row.get("user_sid"), case_insensitive=True))
    if artifact not in {"common_dialog", "recentdocs", "wordwheel_query"}:
        return True
    if _comparison_text(row.get("value_name"), case_insensitive=True) == "mrulistex":
        return False
    return _text(row.get("mru_position")) == "1" and bool(_text(row.get("key_last_write_utc")))


def _is_full_account_sid(value: str) -> bool:
    parts = value.split("-")
    return (
        len(parts) == 8
        and parts[:4] == ["s", "1", "5", "21"]
        and all(part.isdigit() for part in parts[4:])
    )


def _office_recent_docs_vsc_comparison_candidate(row: dict[str, Any]) -> bool:
    key_path = _normalize_registry_key_path(row.get("key_path"))
    if not key_path:
        return False
    key_path = f"/{key_path}/"
    if any(fragment in key_path for fragment in OFFICE_RECENT_DOC_KEY_BLOCKLIST):
        return False
    value_text = " ".join(
        _text(row.get(field))
        for field in ("value_name", "value_data", "display_name", "normalized_path")
        if _text(row.get(field))
    )
    if any(fragment in key_path for fragment in OFFICE_RECENT_DOC_KEY_ALLOWLIST):
        return True
    if "/doctoidmapping/" in key_path:
        return _contains_office_document_indicator(value_text)
    return _contains_office_document_indicator(value_text) and _looks_path_like(value_text)


def _contains_office_document_indicator(value: str) -> bool:
    lowered = value.casefold()
    if any(ext in lowered for ext in OFFICE_RECENT_DOC_EXTENSIONS):
        return True
    return any(marker in lowered for marker in ("/documents/", "\\documents\\", "sharepoint.com/", "onedrive."))


def _comparison_text(
    value: object,
    *,
    path_aware: bool = False,
    case_insensitive: bool = False,
) -> str:
    text = (_text(value) or "").replace("\x00", "").strip()
    if not text:
        return ""
    if path_aware and _looks_path_like(text):
        return _normalize_path_text(text)
    if _looks_hex_blob(text):
        return text.casefold()
    return text.casefold() if case_insensitive else text


def _normalize_registry_key_path(value: object) -> str:
    text = _comparison_text(value, case_insensitive=True)
    if not text:
        return ""
    text = text.replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    text = text.strip("/")
    # Some hives surface through compatibility/alias paths; compare the real
    # StartupApproved branch rather than the alias prefix used to reach it.
    if text.startswith("software/policies/root/"):
        text = text.removeprefix("software/policies/")
    if text.startswith("policies/root/"):
        text = text.removeprefix("policies/")
    text = re.sub(r"/local settings/muicache/[0-9a-f]+/[0-9a-f]+$", "/local settings/muicache/<bucket>/<hash>", text)
    return text


def _mui_cache_vsc_comparison_candidate(row: dict[str, Any]) -> bool:
    key_path = _normalize_registry_key_path(row.get("key_path"))
    value_name = _comparison_text(row.get("value_name"), path_aware=True, case_insensitive=True)
    if not key_path or not value_name:
        return False
    if "immutablemuicache" in key_path:
        return False
    if value_name.startswith("@"):
        return False
    return ".exe." in value_name or value_name.endswith(".exe")


def _userassist_identity(row: dict[str, Any]) -> str:
    for field in ("normalized_path", "display_name"):
        text = _comparison_text(row.get(field), path_aware=True, case_insensitive=True)
        if text:
            return text
    value_name = _text(row.get("value_name"))
    if value_name:
        return _comparison_text(_rot13_text(value_name), path_aware=True, case_insensitive=True)
    notes = _text(row.get("notes")) or ""
    match = re.search(r"(?:^|;\s*)rot13_name=([^;]+)", notes)
    if match:
        return _comparison_text(match.group(1), path_aware=True, case_insensitive=True)
    return ""


def _rot13_text(value: str) -> str:
    output: list[str] = []
    for char in value:
        if "a" <= char <= "z":
            output.append(chr((ord(char) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            output.append(chr((ord(char) - ord("A") + 13) % 26 + ord("A")))
        else:
            output.append(char)
    return "".join(output)


def _normalize_path_text(value: str) -> str:
    text = value.replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    text = text.rstrip("/")
    return text.casefold()


def _looks_path_like(value: str) -> bool:
    lowered = value.casefold()
    return (
        "\\" in value
        or "/" in value
        or bool(re.match(r"^[a-z]:", lowered))
        or lowered.startswith("\\device\\")
        or lowered.startswith("harddiskvolume")
        or lowered.startswith("%")
    )


def _looks_hex_blob(value: str) -> bool:
    compact = value.replace(" ", "")
    return bool(compact) and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact) is not None


def _ensure_registry_table(conn: duckdb.DuckDBPyConnection) -> None:
    column_defs = ", ".join(f"{column} VARCHAR" for column in REGISTRY_ARTIFACT_COLUMNS)
    conn.execute(f"CREATE TABLE IF NOT EXISTS vsc_registry_artifacts ({column_defs})")
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info('vsc_registry_artifacts')").fetchall()}
    for column in REGISTRY_ARTIFACT_COLUMNS:
        if column not in columns:
            conn.execute(f"ALTER TABLE vsc_registry_artifacts ADD COLUMN {column} VARCHAR")


def _clear_snapshot_rows(
    conn: duckdb.DuckDBPyConnection,
    *,
    case_id: str,
    image_id: str,
    snapshot_ids: list[str],
) -> None:
    if not snapshot_ids:
        return
    placeholders = ", ".join("?" for _ in snapshot_ids)
    conn.execute(
        f"DELETE FROM vsc_registry_artifacts WHERE case_id = ? AND image_id = ? AND snapshot_id IN ({placeholders})",
        [case_id, image_id, *snapshot_ids],
    )


def _insert_registry_rows(conn: duckdb.DuckDBPyConnection, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    placeholders = ", ".join("?" for _ in REGISTRY_ARTIFACT_COLUMNS)
    conn.executemany(
        f"INSERT INTO vsc_registry_artifacts ({', '.join(REGISTRY_ARTIFACT_COLUMNS)}) VALUES ({placeholders})",
        [[row.get(column) for column in REGISTRY_ARTIFACT_COLUMNS] for row in rows],
    )


def _snapshot_rows(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT * FROM vsc_registry_artifacts
        WHERE case_id = ? AND image_id = ?
        ORDER BY snapshot_index, artifact, key_path, value_name
        """,
        [case_id, image_id],
    ).fetchall()
    columns = [item[0] for item in conn.description]
    return [dict(zip(columns, row)) for row in rows]


def _live_registry_signatures(db: Database, *, case_id: str) -> set[str]:
    case = db.get_case(case_id)
    duckdb_path = case.root / "analytics" / "events.duckdb"
    rows: list[dict[str, Any]] = []
    if duckdb_path.exists():
        conn = duckdb.connect(str(duckdb_path), read_only=True)
        try:
            tables = {row[0] for row in conn.execute("SHOW TABLES").fetchall()}
            if "registry_artifacts" in tables:
                result = conn.execute(
                    """
                    SELECT artifact, user_profile, user_sid, key_path, value_name,
                           event_time_utc, key_last_write_utc, normalized_path,
                           display_name, value_data, last_executed
                    FROM registry_artifacts
                    WHERE case_id = ?
                    """,
                    [case_id],
                ).fetchall()
                columns = [item[0] for item in conn.description]
                rows = [dict(zip(columns, row)) for row in result]
        finally:
            conn.close()
    if not rows:
        result = db.conn.execute(
            """
            SELECT artifact, user_profile, user_sid, key_path, value_name,
                   event_time_utc, key_last_write_utc, normalized_path,
                   display_name, value_data
            FROM registry_artifacts
            WHERE case_id = ?
            """,
            [case_id],
        ).fetchall()
        rows = [dict(row) for row in result]
    return {registry_record_signature(row) for row in rows}


def _registry_comparison_markdown(
    comparison: dict[str, Any],
    snapshot_results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    *,
    started_at: str,
    ended_at: str,
) -> str:
    summary = comparison["summary"]
    lines = [
        "# VSC Registry Comparison",
        "",
        "## Summary",
        "",
        f"- Started: {started_at}",
        f"- Ended: {ended_at}",
        f"- VSC registry rows parsed: {summary['vsc_registry_rows']}",
        f"- Unique VSC registry records not present live: {summary['unique_vsc_records_not_live']}",
        f"- Artifact types with VSC-only records: {summary['artifact_count']}",
        "",
        "## Snapshot Counts",
        "",
        "| Snapshot | Created | Rows | Unique not live |",
        "| --- | --- | ---: | ---: |",
    ]
    for item in comparison["snapshots"]:
        lines.append(
            f"| {item['snapshot_id']} | {item.get('snapshot_created_utc') or ''} | "
            f"{item['row_count']} | {item['unique_not_live_count']} |"
        )
    if failures:
        lines.extend(["", "## Failures", ""])
        for failure in failures:
            lines.append(f"- `{failure['snapshot_id']}`: {failure['error']}")
    lines.extend(["", "## Artifact Counts", "", "| Artifact | Unique not live |", "| --- | ---: |"])
    for artifact, count in comparison["artifact_counts"].items():
        lines.append(f"| `{artifact}` | {count} |")
    lines.extend(["", "## Category Counts", "", "| Category | Unique not live |", "| --- | ---: |"])
    for category, count in comparison["category_counts"].items():
        lines.append(f"| `{category}` | {count} |")
    lines.extend(
        [
            "",
            "## Examples",
            "",
            "| Artifact | User | Time | Key | Value | Application | Data | Snapshot |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in comparison["examples"]:
        data = row.get("normalized_path") or row.get("display_name") or row.get("value_data") or ""
        application = row.get("resolved_application") or row.get("application_identity") or ""
        lines.append(
            f"| `{row.get('artifact') or ''}` | {row.get('user_profile') or ''} | "
            f"{row.get('event_time_utc') or row.get('key_last_write_utc') or ''} | "
            f"`{_md_escape(_truncate(row.get('key_path') or '', 120))}` | "
            f"`{_md_escape(_truncate(row.get('value_name') or '', 80))}` | "
            f"`{_md_escape(_truncate(application, 80))}` | "
            f"`{_md_escape(_truncate(data, 120))}` | {row.get('snapshot_id') or ''} |"
        )
    lines.extend(["", "## Processing", ""])
    for result in snapshot_results:
        lines.append(
            f"- `{result['snapshot_id']}` copied {result['hive_count']} hives and parsed {result['parsed_rows']} rows "
            f"from {result.get('started_at') or ''} to {result.get('ended_at') or ''}"
        )
    return "\n".join(lines) + "\n"


def _balanced_examples(
    rows: Any,
    *,
    per_artifact: int,
    total: int,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row.get("artifact") or "unknown", []).append(row)
    examples: list[dict[str, Any]] = []
    for artifact in sorted(grouped):
        artifact_rows = sorted(
            grouped[artifact],
            key=lambda row: (
                row.get("user_profile") or "",
                row.get("event_time_utc") or row.get("key_last_write_utc") or "",
                row.get("key_path") or "",
                row.get("value_name") or "",
            ),
        )
        examples.extend(artifact_rows[:per_artifact])
    return examples[:total]


def _try_copy_hive_with_logs(source: Path, destination: Path, errors: list[dict[str, str]]) -> Path | None:
    try:
        return _copy_hive_with_logs(source, destination)
    except OSError as exc:
        errors.append({"source": str(source), "destination": str(destination), "error": str(exc)})
        return None


def _copy_hive_with_logs(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    for suffix in (".LOG", ".LOG1", ".LOG2", ".log", ".log1", ".log2"):
        log_source = source.with_name(source.name + suffix)
        if log_source.is_file():
            shutil.copy2(log_source, destination.with_name(destination.name + suffix))
    return destination


def _snapshot_from_payload(payload: dict[str, Any]) -> VscSnapshot:
    return VscSnapshot(
        index=int(payload["index"]),
        snapshot_id=str(payload.get("snapshot_id") or ""),
        identifier=str(payload.get("identifier") or ""),
        shadow_copy_set_id=str(payload.get("shadow_copy_set_id") or ""),
        created_utc=str(payload.get("created_utc") or ""),
    )


def _relative_to_work(work_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(work_dir)).replace("\\", "/")
    except ValueError:
        return str(path)


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _common_dialog_application_identity(value: object) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if re.fullmatch(r"[0-9a-fA-F]+", text or "") and len(text) % 2 == 0:
        try:
            raw = bytes.fromhex(text)
            for encoding in ("utf-16le", "utf-8", "latin1"):
                decoded = raw.decode(encoding, errors="ignore").replace("\x00", "").strip()
                if decoded.startswith("{"):
                    text = decoded
                    break
        except ValueError:
            pass
    match = re.match(r"^\{[0-9a-fA-F-]{36}\}", text)
    if not match:
        return ""
    guid = match.group(0)
    return guid if is_common_dialog_guid(guid) else ""


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
