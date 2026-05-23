from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import duckdb

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.paths import WorkspacePaths
from forensic_orchestrator.safety import MountError

from .vsc_recycle import compare_recycle_snapshots_from_db
from .vsc_registry import _live_registry_signatures, _snapshot_rows as _registry_snapshot_rows
from .vsc_registry import compare_registry_snapshots
from .vsc_shortcuts import _live_shortcut_signatures, _snapshot_rows as _shortcut_snapshot_rows
from .vsc_shortcuts import compare_shortcut_snapshots


FILE_HISTORY_REGISTRY_ARTIFACTS = {
    "common_dialog",
    "office_recent_docs",
    "recentdocs",
    "wordwheel_query",
}


def build_vsc_file_history_report(
    *,
    db: Database,
    paths: WorkspacePaths,
    case_id: str,
    image_id: str,
) -> dict[str, Any]:
    case = db.get_case(case_id)
    sidecar_path = paths.vsc_parsed_db_path(case_id)
    if not sidecar_path.exists():
        raise MountError(f"VSC sidecar DB not found: {sidecar_path}")
    started_at = utc_now()
    conn = duckdb.connect(str(sidecar_path))
    try:
        tables = _tables(conn)
        live_db = case.root / "analytics" / "events.duckdb"
        main_ntfs_conn = duckdb.connect(str(live_db), read_only=True) if live_db.exists() else None
        try:
            main_tables = _tables(main_ntfs_conn) if main_ntfs_conn is not None else set()
            ntfs = _main_ntfs_delta_summary(main_ntfs_conn, case_id=case_id, image_id=image_id) if main_ntfs_conn is not None and _has_all(main_tables, {"vsc_mft_deltas", "vsc_usn_deltas"}) else _missing("ntfs")
            ntfs_signal = _ntfs_signal_report(main_ntfs_conn, case_id=case_id, image_id=image_id) if main_ntfs_conn is not None and "vsc_mft_deltas" in main_tables else {}
        finally:
            if main_ntfs_conn is not None:
                main_ntfs_conn.close()
        recycle = compare_recycle_snapshots_from_db(conn=conn, db=db, case_id=case_id, image_id=image_id) if "vsc_recycle_items" in tables else _missing("recycle")
        shortcuts = (
            compare_shortcut_snapshots(
                live_signatures=_live_shortcut_signatures(paths=paths, case_id=case_id),
                snapshot_rows=_shortcut_snapshot_rows(conn, case_id=case_id, image_id=image_id),
            )
            if "vsc_shortcut_items" in tables
            else _missing("shortcuts")
        )
        registry = (
            compare_registry_snapshots(
                live_signatures=_live_registry_signatures(db, case_id=case_id),
                snapshot_rows=_registry_snapshot_rows(conn, case_id=case_id, image_id=image_id),
            )
            if "vsc_registry_artifacts" in tables
            else _missing("registry")
        )
        live_coverage = _live_windows_old_coverage(live_db, case_id=case_id)
        report = {
            "case_id": case_id,
            "image_id": image_id,
            "started_at": started_at,
            "ended_at": utc_now(),
            "vsc_db_path": str(sidecar_path),
            "live_db_path": str(live_db),
            "tables": sorted(tables),
            "summary": _summary(ntfs, recycle, shortcuts, registry, live_coverage),
            "live_windows_old_coverage": live_coverage,
            "ntfs": ntfs,
            "ntfs_signal": ntfs_signal,
            "recycle": recycle,
            "shortcuts": shortcuts,
            "registry_file_history": _registry_file_history_subset(registry),
            "notes": [
                "Live comparison includes Windows.old MFT aliases as live root-relative paths.",
                "VSC MFT and USN findings are read from the main DuckDB delta tables.",
            ],
        }
        report["ended_at"] = utc_now()
        report_path = paths.vsc_reports_dir(case_id) / "file-history-vsc-validation.md"
        report_path.write_text(vsc_file_history_markdown(report), encoding="utf-8")
        json_path = paths.vsc_work_dir(case_id) / "file-history-vsc-validation.json"
        json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        report["report_path"] = str(report_path)
        report["json_path"] = str(json_path)
        return report
    finally:
        conn.close()


def _summary(
    ntfs: dict[str, Any],
    recycle: dict[str, Any],
    shortcuts: dict[str, Any],
    registry: dict[str, Any],
    live_coverage: dict[str, Any],
) -> dict[str, Any]:
    registry_file_history_counts = {
        key: value
        for key, value in (registry.get("artifact_counts") or {}).items()
        if key in FILE_HISTORY_REGISTRY_ARTIFACTS
    }
    return {
        "mft_unique_paths_not_live": _summary_value(ntfs, "mft_unique_paths_not_live"),
        "mft_changed_unique_paths_from_live": _summary_value(ntfs, "mft_changed_unique_paths_from_live"),
        "usn_unique_records_not_live": _summary_value(ntfs, "usn_unique_records_not_live"),
        "recycle_unique_records_not_live": _summary_value(recycle, "unique_vsc_records_not_live"),
        "shortcut_unique_records_not_live": _summary_value(shortcuts, "unique_vsc_shortcut_records_not_live"),
        "registry_file_history_unique_records_not_live": sum(registry_file_history_counts.values()),
        "registry_file_history_artifact_counts": registry_file_history_counts,
        "live_windows_old_rows": sum(int(item.get("windows_old_rows") or 0) for item in live_coverage.values()),
    }


def _main_ntfs_delta_summary(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> dict[str, Any]:
    return {
        "summary": {
            "mft_unique_paths_not_live": _count_sql(
                conn,
                "SELECT COUNT(DISTINCT path_key) FROM vsc_mft_deltas WHERE case_id = ? AND image_id = ? AND delta_type = 'not_live'",
                [case_id, image_id],
            ),
            "mft_changed_unique_paths_from_live": _count_sql(
                conn,
                "SELECT COUNT(DISTINCT path_key) FROM vsc_mft_deltas WHERE case_id = ? AND image_id = ? AND delta_type = 'changed_from_live'",
                [case_id, image_id],
            ),
            "usn_unique_records_not_live": _count_sql(
                conn,
                "SELECT COUNT(DISTINCT record_signature) FROM vsc_usn_deltas WHERE case_id = ? AND image_id = ? AND delta_type = 'not_live'",
                [case_id, image_id],
            ),
        }
    }


def _ntfs_signal_report(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> dict[str, Any]:
    tables = _tables(conn)
    if not _has_all(tables, {"vsc_mft_deltas", "vsc_usn_deltas"}):
        return {}
    return {
        "mft_vsc_only_class_counts": _mft_class_counts(conn, case_id=case_id, image_id=image_id, changed=False),
        "mft_changed_class_counts": _mft_class_counts(conn, case_id=case_id, image_id=image_id, changed=True),
        "usn_vsc_only_class_counts": _usn_class_counts(conn, case_id=case_id, image_id=image_id),
        "mft_vsc_only_interesting_examples": _mft_interesting_examples(conn, case_id=case_id, image_id=image_id, changed=False),
        "mft_changed_interesting_examples": _mft_interesting_examples(conn, case_id=case_id, image_id=image_id, changed=True),
        "usn_interesting_groups": _usn_interesting_groups(conn, case_id=case_id, image_id=image_id),
    }


def _mft_class_counts(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str, changed: bool) -> list[dict[str, Any]]:
    delta_type = "changed_from_live" if changed else "not_live"
    rows = conn.execute(
        f"""
        SELECT {_path_class_sql('v.normalized_path')} AS class,
               COUNT(DISTINCT v.path_key) AS unique_paths
        FROM vsc_mft_deltas v
        WHERE v.case_id = ? AND v.image_id = ? AND COALESCE(v.path_key, '') != ''
          AND v.delta_type = ?
        GROUP BY 1
        ORDER BY unique_paths DESC, class
        """,
        [case_id, image_id, delta_type],
    ).fetchall()
    return [_row(["class", "unique_paths"], row) for row in rows]


def _usn_class_counts(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"""
        SELECT {_path_class_sql('v.normalized_path')} AS class,
               COUNT(DISTINCT v.record_signature) AS unique_records,
               COUNT(DISTINCT v.path_key) AS unique_paths
        FROM vsc_usn_deltas v
        WHERE v.case_id = ? AND v.image_id = ? AND COALESCE(v.record_signature, '') != ''
          AND v.delta_type = 'not_live'
        GROUP BY 1
        ORDER BY unique_records DESC, class
        """,
        [case_id, image_id],
    ).fetchall()
    return [_row(["class", "unique_records", "unique_paths"], row) for row in rows]


def _mft_interesting_examples(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str, changed: bool) -> list[dict[str, Any]]:
    delta_type = "changed_from_live" if changed else "not_live"
    rows = conn.execute(
        f"""
        SELECT v.snapshot_id, v.snapshot_created_utc, v.normalized_path, v.file_name,
               v.file_size, v.in_use, v.is_directory, v.created_si, v.modified_si,
               v.record_changed_si, v.accessed_si, {_path_class_sql('v.normalized_path')} AS class
        FROM vsc_mft_deltas v
        WHERE v.case_id = ? AND v.image_id = ? AND COALESCE(v.path_key, '') != ''
          AND v.delta_type = ?
          AND {_high_signal_path_sql('v.normalized_path')}
        QUALIFY ROW_NUMBER() OVER (
          PARTITION BY v.path_key
          ORDER BY CAST(v.snapshot_index AS INTEGER), v.modified_si, v.accessed_si
        ) = 1
        ORDER BY
          {_path_priority_sql('v.normalized_path')},
          COALESCE(v.modified_si, v.created_si, ''),
          v.normalized_path
        LIMIT 100
        """,
        [case_id, image_id, delta_type],
    ).fetchall()
    return [
        _row(
            [
                "snapshot_id", "snapshot_created_utc", "normalized_path", "file_name",
                "file_size", "in_use", "is_directory", "created_si", "modified_si",
                "record_changed_si", "accessed_si", "class",
            ],
            row,
        )
        for row in rows
    ]


def _usn_interesting_groups(conn: duckdb.DuckDBPyConnection, *, case_id: str, image_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"""
        SELECT v.normalized_path,
               {_path_class_sql('v.normalized_path')} AS class,
               MIN(v.update_timestamp) AS first_seen,
               MAX(v.update_timestamp) AS last_seen,
               COUNT(DISTINCT v.record_signature) AS unique_records,
               COUNT(DISTINCT v.reason) AS reason_count,
               string_agg(DISTINCT v.reason, '; ' ORDER BY v.reason) AS reasons,
               string_agg(DISTINCT v.snapshot_id, ', ' ORDER BY v.snapshot_id) AS snapshots
        FROM vsc_usn_deltas v
        WHERE v.case_id = ? AND v.image_id = ? AND COALESCE(v.record_signature, '') != ''
          AND v.delta_type = 'not_live'
          AND {_high_signal_path_sql('v.normalized_path')}
        GROUP BY 1, 2
        ORDER BY
          {_path_priority_sql('v.normalized_path')},
          unique_records DESC,
          first_seen,
          normalized_path
        LIMIT 100
        """,
        [case_id, image_id],
    ).fetchall()
    return [_row(["normalized_path", "class", "first_seen", "last_seen", "unique_records", "reason_count", "reasons", "snapshots"], row) for row in rows]


def _registry_file_history_subset(registry: dict[str, Any]) -> dict[str, Any]:
    examples = [
        row for row in registry.get("examples", [])
        if str(row.get("artifact") or "") in FILE_HISTORY_REGISTRY_ARTIFACTS
    ]
    artifact_counts = {
        key: value
        for key, value in (registry.get("artifact_counts") or {}).items()
        if key in FILE_HISTORY_REGISTRY_ARTIFACTS
    }
    return {
        "artifact_counts": artifact_counts,
        "examples": examples[:100],
    }


def _live_windows_old_coverage(live_db: Path, *, case_id: str) -> dict[str, Any]:
    if not live_db.exists():
        return {}
    conn = duckdb.connect(str(live_db), read_only=True)
    try:
        tables = _tables(conn)
        coverage: dict[str, Any] = {}
        checks = {
            "mft_entries": ["parent_path", "source_csv", "source_file"],
            "usn_journal_entries": ["full_path", "source_csv", "source_file"],
            "shortcut_items": ["artifact_path", "source_csv", "file_location"],
            "registry_artifacts": ["source_csv", "source_path", "key_path"],
            "recycle_items": ["source_path", "original_path"],
            "recycle_children": ["source_path", "child_relative_path"],
        }
        for table, columns in checks.items():
            if table not in tables:
                continue
            existing = _columns(conn, table)
            predicates = [f"lower(coalesce({column}, '')) LIKE '%windows.old%'" for column in columns if column in existing]
            if not predicates:
                continue
            total = _count_sql(conn, f"SELECT COUNT(*) FROM {table} WHERE case_id = ?", [case_id])
            windows_old = _count_sql(conn, f"SELECT COUNT(*) FROM {table} WHERE case_id = ? AND ({' OR '.join(predicates)})", [case_id])
            coverage[table] = {"total_rows": total, "windows_old_rows": windows_old}
        return coverage
    finally:
        conn.close()


def vsc_file_history_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# VSC File History Validation",
        "",
        f"Case: `{report['case_id']}`",
        f"Image: `{report['image_id']}`",
        "",
        "## Summary",
        "",
        f"- Started: `{report['started_at']}`",
        f"- Ended: `{report['ended_at']}`",
        f"- MFT paths present in VSC but not live/Windows.old: `{summary['mft_unique_paths_not_live']}`",
        f"- MFT paths present live but with changed metadata in VSC: `{summary['mft_changed_unique_paths_from_live']}`",
        f"- USN records present in VSC but not live: `{summary['usn_unique_records_not_live']}`",
        f"- Recycle records present in VSC but not live: `{summary['recycle_unique_records_not_live']}`",
        f"- Shortcut/Jump List records present in VSC but not live: `{summary['shortcut_unique_records_not_live']}`",
        f"- Registry file-history records present in VSC but not live: `{summary['registry_file_history_unique_records_not_live']}`",
        f"- Live Windows.old rows considered during validation: `{summary['live_windows_old_rows']}`",
        "",
        "## Live Windows.old Coverage",
        "",
        "| Table | Total rows | Windows.old rows |",
        "| --- | ---: | ---: |",
    ]
    for table, item in sorted(report["live_windows_old_coverage"].items()):
        lines.append(f"| `{table}` | {item.get('total_rows') or 0} | {item.get('windows_old_rows') or 0} |")
    _append_ntfs_signal(lines, report.get("ntfs_signal") or {})
    lines.extend(["", "## Registry File-History Artifact Counts", "", "| Artifact | Unique not live |", "| --- | ---: |"])
    for artifact, count in sorted(summary["registry_file_history_artifact_counts"].items()):
        lines.append(f"| `{artifact}` | {count} |")
    _append_ntfs_examples(lines, report.get("ntfs") or {})
    _append_recycle_examples(lines, report.get("recycle") or {})
    _append_shortcut_examples(lines, report.get("shortcuts") or {})
    _append_registry_examples(lines, report.get("registry_file_history") or {})
    lines.extend(["", "## Notes", ""])
    for note in report.get("notes") or []:
        lines.append(f"- {note}")
    return "\n".join(lines).rstrip() + "\n"


def _append_ntfs_signal(lines: list[str], signal: dict[str, Any]) -> None:
    if not signal:
        return
    lines.extend(["", "## High-Signal NTFS Deltas", ""])
    lines.extend(["### Classified Counts", "", "| Source | Class | Unique paths | Unique records |", "| --- | --- | ---: | ---: |"])
    for source, rows in (
        ("MFT VSC-only", signal.get("mft_vsc_only_class_counts") or []),
        ("MFT changed", signal.get("mft_changed_class_counts") or []),
        ("USN VSC-only", signal.get("usn_vsc_only_class_counts") or []),
    ):
        for row in rows:
            lines.append(
                f"| {source} | `{row.get('class') or ''}` | "
                f"{row.get('unique_paths') or 0} | {row.get('unique_records') or ''} |"
            )
    lines.extend(
        [
            "",
            "### Interesting VSC-Only MFT Paths",
            "",
            "| Snapshot | Class | Path | Size | In use | Modified | Accessed |",
            "| --- | --- | --- | ---: | --- | --- | --- |",
        ]
    )
    for row in signal.get("mft_vsc_only_interesting_examples") or []:
        lines.append(
            f"| {row.get('snapshot_id') or ''} | `{row.get('class') or ''}` | `{_md(row.get('normalized_path'))}` | "
            f"{row.get('file_size') or ''} | {row.get('in_use') or ''} | {row.get('modified_si') or ''} | {row.get('accessed_si') or ''} |"
        )
    lines.extend(
        [
            "",
            "### Interesting Changed MFT Paths",
            "",
            "| Snapshot | Class | Path | Size | In use | Modified | Accessed |",
            "| --- | --- | --- | ---: | --- | --- | --- |",
        ]
    )
    for row in signal.get("mft_changed_interesting_examples") or []:
        lines.append(
            f"| {row.get('snapshot_id') or ''} | `{row.get('class') or ''}` | `{_md(row.get('normalized_path'))}` | "
            f"{row.get('file_size') or ''} | {row.get('in_use') or ''} | {row.get('modified_si') or ''} | {row.get('accessed_si') or ''} |"
        )
    lines.extend(
        [
            "",
            "### Grouped Interesting USN Records",
            "",
            "| Class | Path | First seen | Last seen | Unique records | Snapshots | Reasons |",
            "| --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for row in signal.get("usn_interesting_groups") or []:
        lines.append(
            f"| `{row.get('class') or ''}` | `{_md(row.get('normalized_path'))}` | {row.get('first_seen') or ''} | "
            f"{row.get('last_seen') or ''} | {row.get('unique_records') or 0} | `{row.get('snapshots') or ''}` | `{_md(row.get('reasons'), 120)}` |"
        )


def _append_ntfs_examples(lines: list[str], ntfs: dict[str, Any]) -> None:
    lines.extend(["", "## NTFS Examples", "", "### VSC-Only MFT Paths", "", "| Snapshot | Path | Size | In use | Modified | Accessed |", "| --- | --- | ---: | --- | --- | --- |"])
    for row in _prefer_user_visible_paths(ntfs.get("mft_only") or [], path_field="normalized_path")[:25]:
        lines.append(f"| {row.get('snapshot_id') or ''} | `{_md(row.get('normalized_path'))}` | {row.get('file_size') or ''} | {row.get('in_use') or ''} | {row.get('modified_si') or ''} | {row.get('accessed_si') or ''} |")
    lines.extend(["", "### Changed MFT Metadata", "", "| Snapshot | Path | Size | In use | Modified | Accessed |", "| --- | --- | ---: | --- | --- | --- |"])
    for row in _prefer_user_visible_paths(ntfs.get("mft_changed") or [], path_field="normalized_path")[:25]:
        lines.append(f"| {row.get('snapshot_id') or ''} | `{_md(row.get('normalized_path'))}` | {row.get('file_size') or ''} | {row.get('in_use') or ''} | {row.get('modified_si') or ''} | {row.get('accessed_si') or ''} |")
    lines.extend(["", "### VSC-Only USN Records", "", "| Snapshot | Time | Path | Reason | USN |", "| --- | --- | --- | --- | ---: |"])
    for row in _prefer_user_visible_paths(ntfs.get("usn_only") or [], path_field="normalized_path")[:25]:
        lines.append(f"| {row.get('snapshot_id') or ''} | {row.get('update_timestamp') or ''} | `{_md(row.get('normalized_path'))}` | `{_md(row.get('reason'))}` | {row.get('update_sequence_number') or ''} |")


def _append_recycle_examples(lines: list[str], recycle: dict[str, Any]) -> None:
    lines.extend(["", "## Recycle Bin Examples", "", "| Snapshot | Type | Deleted | Original path | Source | Size |", "| --- | --- | --- | --- | --- | ---: |"])
    for row in (recycle.get("examples") or [])[:25]:
        lines.append(f"| {row.get('snapshot_id') or ''} | `{row.get('record_type') or ''}` | {row.get('deletion_time_utc') or ''} | `{_md(row.get('original_path'))}` | `{_md(row.get('source_vsc_path'))}` | {row.get('file_size') or ''} |")


def _append_shortcut_examples(lines: list[str], shortcuts: dict[str, Any]) -> None:
    lines.extend(["", "## Shortcut And Jump List Examples", "", "| Artifact | Snapshot | Target | Created | Modified | Accessed | Source |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for row in _dedupe_rows(shortcuts.get("examples") or [], fields=("artifact_type", "snapshot_id", "file_location", "target_created", "target_modified", "target_accessed", "source_vsc_path"))[:50]:
        lines.append(f"| `{row.get('artifact_type') or ''}` | {row.get('snapshot_id') or ''} | `{_md(row.get('file_location') or row.get('file_name'))}` | {row.get('target_created') or ''} | {row.get('target_modified') or ''} | {row.get('target_accessed') or ''} | `{_md(row.get('source_vsc_path'))}` |")


def _append_registry_examples(lines: list[str], registry: dict[str, Any]) -> None:
    lines.extend(["", "## Registry File-History Examples", "", "| Artifact | Snapshot | User | Time | Data | Key |", "| --- | --- | --- | --- | --- | --- |"])
    for row in _dedupe_rows(registry.get("examples") or [], fields=("artifact", "snapshot_id", "user_profile", "key_path", "value_name", "event_time_utc", "key_last_write_utc", "display_name", "normalized_path", "resolved_application"))[:50]:
        data = _registry_display_data(row)
        lines.append(f"| `{row.get('artifact') or ''}` | {row.get('snapshot_id') or ''} | {row.get('user_profile') or ''} | {row.get('event_time_utc') or row.get('key_last_write_utc') or ''} | `{_md(data)}` | `{_md(row.get('key_path'), 100)}` |")


def _tables(conn: duckdb.DuckDBPyConnection) -> set[str]:
    return {str(row[0]) for row in conn.execute("SHOW TABLES").fetchall()}


def _columns(conn: duckdb.DuckDBPyConnection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}


def _path_class_sql(path_expr: str) -> str:
    path = f"lower(coalesce({path_expr}, ''))"
    return f"""
    CASE
      WHEN {path} LIKE '/users/%/appdata/local/dropbox/%'
        OR {path} LIKE '/users/%/appdata/local/google/drive%'
        OR {path} LIKE '/users/%/appdata/local/google/drivefs/%'
        OR {path} LIKE '/users/%/appdata/local/microsoft/onedrive/%'
        OR regexp_matches({path}, '^/users/[^/]+/[^/]*dropbox[^/]*/\\.dropbox\\.cache/')
        THEN 'cloud_app_state'
      WHEN {path} LIKE '/users/%/appdata/local/google/chrome/user data/%'
        OR {path} LIKE '/users/%/appdata/roaming/mozilla/firefox/profiles/%'
        OR {path} LIKE '/users/%/appdata/local/microsoft/windows/inetcache/%'
        OR regexp_matches({path}, '^/users/[^/]+/appdata/local/packages/[^/]+/ac/inetcache/')
        THEN 'browser_or_web_cache'
      WHEN regexp_matches({path}, '^/users/[^/]+/(desktop|documents|downloads|pictures|videos|onedrive|onedrive - [^/]+|google drive|stark research labs)(/|$)')
        THEN 'user_file_space'
      WHEN {path} LIKE '/windows/%'
        OR {path} LIKE '/program files/%'
        OR {path} LIKE '/program files (x86)/%'
        OR {path} LIKE '/programdata/%'
        OR {path} LIKE '/$%'
        OR {path} = '/config.msi'
        OR {path} LIKE '/pathunknown/%'
        THEN 'system_or_application_churn'
      WHEN {path} LIKE '%.pst'
        OR {path} LIKE '%.ost'
        OR {path} LIKE '%.mbox'
        OR {path} LIKE '%.eml'
        THEN 'mail_or_message_store'
      WHEN {path} LIKE '%.zip'
        OR {path} LIKE '%.7z'
        OR {path} LIKE '%.rar'
        OR {path} LIKE '%.tar'
        OR {path} LIKE '%.gz'
        THEN 'archive'
      WHEN {path} LIKE '%.exe'
        OR {path} LIKE '%.dll'
        OR {path} LIKE '%.msi'
        OR {path} LIKE '%.ps1'
        OR {path} LIKE '%.bat'
        OR {path} LIKE '%.cmd'
        OR {path} LIKE '%.vbs'
        OR {path} LIKE '%.js'
        OR {path} LIKE '%.jar'
        OR {path} LIKE '%.scr'
        OR {path} LIKE '%.lnk'
        THEN 'executable_or_script'
      ELSE 'other'
    END
    """


def _interesting_path_sql(path_expr: str) -> str:
    return f"{_path_class_sql(path_expr)} NOT IN ('system_or_application_churn', 'browser_or_web_cache')"


def _high_signal_path_sql(path_expr: str) -> str:
    return f"{_path_class_sql(path_expr)} IN ('user_file_space', 'mail_or_message_store', 'archive', 'executable_or_script')"


def _path_priority_sql(path_expr: str) -> str:
    return f"""
    CASE {_path_class_sql(path_expr)}
      WHEN 'user_file_space' THEN 0
      WHEN 'mail_or_message_store' THEN 1
      WHEN 'archive' THEN 2
      WHEN 'executable_or_script' THEN 3
      WHEN 'cloud_app_state' THEN 4
      WHEN 'other' THEN 5
      WHEN 'browser_or_web_cache' THEN 8
      ELSE 9
    END
    """


def _has_all(tables: set[str], required: set[str]) -> bool:
    return required.issubset(tables)


def _count_sql(conn: duckdb.DuckDBPyConnection, sql: str, params: list[Any]) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def _row(columns: list[str], values: tuple[Any, ...]) -> dict[str, Any]:
    return dict(zip(columns, values, strict=False))


def _summary_value(section: dict[str, Any], key: str) -> int:
    return int((section.get("summary") or {}).get(key) or 0)


def _missing(name: str) -> dict[str, Any]:
    return {"summary": {}, "examples": [], "missing": name}


def _prefer_user_visible_paths(rows: list[dict[str, Any]], *, path_field: str) -> list[dict[str, Any]]:
    def score(row: dict[str, Any]) -> tuple[int, str, str]:
        path = str(row.get(path_field) or "").casefold()
        if path.startswith("/users/"):
            rank = 0
        elif path.startswith("/programdata/") or path.startswith("/windows/temp/"):
            rank = 1
        elif path.startswith("/windows/"):
            rank = 2
        elif path.startswith("/pathunknown/") or path.startswith("/$"):
            rank = 9
        else:
            rank = 4
        return (rank, path, str(row.get("snapshot_id") or ""))

    return sorted(rows, key=score)


def _dedupe_rows(rows: list[dict[str, Any]], *, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    output: list[dict[str, Any]] = []
    for row in rows:
        key = tuple(str(row.get(field) or "") for field in fields)
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def _registry_display_data(row: dict[str, Any]) -> str:
    artifact = str(row.get("artifact") or "")
    if artifact == "common_dialog":
        for field in ("resolved_application", "application_identity", "normalized_path", "display_name"):
            if row.get(field):
                text = _common_dialog_text(str(row[field]))
                if text:
                    return text
        return _common_dialog_text(str(row.get("value_data") or "")) or "<binary PIDL/MRU value>"
    return str(row.get("normalized_path") or row.get("display_name") or row.get("value_data") or "")


def _common_dialog_text(value: str) -> str:
    match = re.search(r"([A-Za-z0-9_. -]+\.exe)", value, flags=re.IGNORECASE)
    if match:
        return match.group(1).strip()
    compact = value.replace(" ", "")
    if len(compact) > 40 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return "<binary PIDL/MRU value>"
    printable = sum(1 for char in value if " " <= char <= "~")
    if value and printable / max(len(value), 1) < 0.7:
        return "<binary PIDL/MRU value>"
    return value.strip()


def _md(value: object, limit: int = 140) -> str:
    text = "" if value is None else str(value)
    text = "".join(char if char >= " " else " " for char in text)
    text = text.replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."
