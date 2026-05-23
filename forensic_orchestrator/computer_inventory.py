from __future__ import annotations

import re
import uuid
from typing import Any

from .analytics_query import query_rows
from .db import Database


def rebuild_computer_inventory(db: Database, *, case_id: str, image_id: str) -> int:
    rows: list[dict[str, Any]] = []
    rows.extend(_registry_inventory(db, case_id, image_id))
    rows.extend(_software_inventory(db, case_id, image_id))
    rows.extend(_artifact_expectations(db, case_id, image_id, rows))
    rows = _dedupe(rows)
    db.replace_computer_inventory(case_id=case_id, image_id=image_id, rows=rows)
    return len(rows)


def _registry_inventory(db: Database, case_id: str, image_id: str) -> list[dict[str, Any]]:
    registry_rows = query_rows(
        db,
        "registry_artifacts",
            """
            SELECT id, case_id, computer_id, image_id, artifact, value_name, value_data,
                   display_name, key_path, event_time_utc
            FROM registry_artifacts
            WHERE case_id = ? AND image_id = ?
              AND artifact IN ('install_time_software', 'install_time_source_os',
                               'computer_name', 'time_zone', 'current_control_set')
            """,
            (case_id, image_id),
    )
    rows: list[dict[str, Any]] = []
    current_version = _current_version_values(registry_rows)
    for name in (
        "ProductName",
        "EditionID",
        "DisplayVersion",
        "ReleaseId",
        "CurrentBuild",
        "CurrentBuildNumber",
        "UBR",
        "BuildBranch",
        "BuildLabEx",
        "InstallDate",
        "InstallTime",
        "RegisteredOwner",
        "SystemRoot",
    ):
        source = current_version.get(name.lower())
        if source:
            rows.append(_row(source, "os", _snake(name), source["value_data"], "registry_artifacts"))
    for row in registry_rows:
        if row["artifact"] == "computer_name" and row["value_name"].lower() == "computername":
            rows.append(_row(row, "identity", "computer_name", row["value_data"], "registry_artifacts"))
        elif row["artifact"] == "time_zone" and row["value_name"].lower() == "timezonekeyname":
            rows.append(_row(row, "os", "time_zone", row["value_data"], "registry_artifacts"))
        elif row["artifact"] == "current_control_set" and row["value_name"].lower() == "current":
            rows.append(_row(row, "os", "current_control_set", row["value_data"], "registry_artifacts"))
    build = _value(rows, "current_build") or _value(rows, "current_build_number")
    if build:
        rows.append(_derived_row(rows[0], "os", "windows_generation", _windows_generation(build), {"build": build}))
    return rows


def _software_inventory(db: Database, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in query_rows(
        db,
        "onedrive_log_entries",
        """
        SELECT id, case_id, computer_id, image_id, one_drive_version, windows_version
        FROM onedrive_log_entries
        WHERE case_id = ? AND image_id = ?
          AND (one_drive_version <> '' OR windows_version <> '')
        GROUP BY one_drive_version, windows_version
        """,
        (case_id, image_id),
    ):
        data = dict(row)
        if data.get("one_drive_version"):
            rows.append(_row(data, "software_version", "onedrive_version", data["one_drive_version"], "onedrive_log_entries"))
        if data.get("windows_version"):
            rows.append(_row(data, "software_version", "onedrive_reported_windows_version", data["windows_version"], "onedrive_log_entries"))
    for row in query_rows(
        db,
        "telemetry_artifacts",
        """
        SELECT id, case_id, computer_id, image_id, application, title
        FROM telemetry_artifacts
        WHERE case_id = ? AND image_id = ? AND artifact_group = 'apprepository'
          AND record_type IN ('apprepository_application', 'apprepository_applicationidentity')
          AND application <> ''
        LIMIT 500
        """,
        (case_id, image_id),
    ):
        data = dict(row)
        rows.append(_row(data, "installed_app", data["application"], data.get("title") or data["application"], "telemetry_artifacts"))
    return rows


def _artifact_expectations(
    db: Database,
    case_id: str,
    image_id: str,
    inventory_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not inventory_rows:
        return []
    build = _numeric(_value(inventory_rows, "current_build") or _value(inventory_rows, "current_build_number"))
    expected = [
        ("windows_notifications", build >= 10240, "Windows 10+ notification database", "telemetry_artifacts", "artifact_group='notifications'"),
        ("cloudstore", build >= 10240, "Windows 10+ CloudStore state", "telemetry_artifacts", "artifact_group='cloudstore'"),
        ("apprepository", build >= 9200, "Windows Store AppRepository", "telemetry_artifacts", "artifact_group='apprepository'"),
        ("srum", build >= 9200, "SRUM ESE database", "srum_records", ""),
        ("windows_activities", build >= 17134, "Timeline/Activities introduced in Windows 10 1803", "windows_activities", ""),
        ("webcache", build >= 9200, "IE/Edge WebCache", "webcache_entries", ""),
        ("wdac", build >= 10240, "WDAC/Code Integrity policies", "telemetry_artifacts", "artifact_group='wdac'"),
        ("prefetch_mam", build >= 10240, "Windows 10+ compressed Prefetch support required", "prefetch_items", ""),
    ]
    basis = inventory_rows[0]
    rows = []
    for name, should_exist, reason, table, where in expected:
        count = _table_count(db, case_id, image_id, table, where)
        if not should_exist:
            status = "not_expected_for_os"
        elif count:
            status = "observed"
        else:
            status = "expected_not_observed"
        rows.append(
            _derived_row(
                basis,
                "artifact_expectation",
                name,
                status,
                {"reason": reason, "build": build, "observed_rows": count, "table": table, "filter": where},
            )
        )
    return rows


def _current_version_values(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    values = {}
    for row in rows:
        if row["artifact"] != "install_time_software":
            continue
        key_path = str(row.get("key_path") or "").lower()
        if "wow6432node" in key_path:
            continue
        values[str(row["value_name"]).lower()] = row
    return values


def _table_count(db: Database, case_id: str, image_id: str, table: str, extra_where: str) -> int:
    where = "case_id = ? AND image_id = ?"
    if extra_where:
        where += f" AND {extra_where}"
    rows = query_rows(db, table, f"SELECT COUNT(*) AS count FROM {table} WHERE {where}", (case_id, image_id))
    return int(rows[0]["count"]) if rows else 0


def _row(source: dict[str, Any], category: str, name: str, value: str | None, source_table: str) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": source["case_id"],
        "computer_id": source["computer_id"],
        "image_id": source["image_id"],
        "category": category,
        "name": name,
        "value": value,
        "source_table": source_table,
        "source_row_id": source["id"],
        "confidence": "source",
        "details": {},
    }


def _derived_row(source: dict[str, Any], category: str, name: str, value: str | None, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "case_id": source["case_id"],
        "computer_id": source["computer_id"],
        "image_id": source["image_id"],
        "category": category,
        "name": name,
        "value": value,
        "source_table": source.get("source_table"),
        "source_row_id": source.get("source_row_id"),
        "confidence": "derived",
        "details": details,
    }


def _value(rows: list[dict[str, Any]], name: str) -> str:
    for row in rows:
        if row["name"] == name:
            return str(row.get("value") or "")
    return ""


def _numeric(value: str) -> int:
    match = re.search(r"\d+", value or "")
    return int(match.group(0)) if match else 0


def _windows_generation(build: str) -> str:
    number = _numeric(build)
    if number >= 22000:
        return "Windows 11"
    if number >= 10240:
        return "Windows 10"
    if number >= 9200:
        return "Windows 8/8.1"
    if number >= 7600:
        return "Windows 7"
    return "Windows legacy/unknown"


def _snake(value: str) -> str:
    special = {"EditionID": "edition_id", "UBR": "ubr"}
    if value in special:
        return special[value]
    return re.sub(r"(?<!^)([A-Z])", r"_\1", value).lower()


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for row in rows:
        key = (row["computer_id"], row["image_id"], row["category"], row["name"], row.get("value"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped
