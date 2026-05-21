from __future__ import annotations

import base64
import binascii
import hashlib
import html
import csv
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import duckdb

from .db import Database, utc_now
from .interesting_executables import load_interesting_executable_rules
from .report_paths import display_evidence_path
from .storage_policy import CONTENT_HEAVY_TABLES, storage_policy_items
from .timestamps import parse_timestamp
from .usn_rules import load_usn_rules, match_usn_rules


USERASSIST_CAVEAT = (
    "UserAssist is inconsistent and should not be treated as definitive execution evidence. "
    "Use it as an investigative lead and corroborate with Prefetch, BAM/DAM, SRUM, event logs, "
    "shortcuts, or other stronger execution/file-use sources. Amcache and ShimCache/AppCompatCache "
    "are presence/inventory/cache metadata and should not be treated as execution proof by themselves."
)


WEB_CLOUD_PROVIDERS = [
    {
        "provider": "Google Drive",
        "category": "cloud_storage",
        "tokens": ("drive.google.com", "docs.google.com", "google drive", "googledrive", "drivefs", "my drive"),
    },
    {
        "provider": "OneDrive",
        "category": "cloud_storage",
        "tokens": ("onedrive", "1drv.ms", "sharepoint.com", "d.docs.live.net", "skydrive"),
    },
    {
        "provider": "Dropbox",
        "category": "cloud_storage",
        "tokens": ("dropbox.com", "dropbox", "dropboxusercontent.com"),
    },
    {
        "provider": "iCloud",
        "category": "cloud_storage",
        "tokens": ("icloud.com", "icloud drive", "appleinc.icloud", "clouddocs"),
    },
    {
        "provider": "Box",
        "category": "cloud_storage",
        "tokens": ("box.com", "boxcloud.com", "box drive"),
    },
    {
        "provider": "Google Mail",
        "category": "webmail",
        "tokens": ("mail.google.com", "gmail.com", "googlemail"),
    },
    {
        "provider": "Outlook Web",
        "category": "webmail",
        "tokens": ("outlook.live.com", "outlook.office.com", "outlook.office365.com", "owa/", "mail.live.com"),
    },
    {
        "provider": "Yahoo Mail",
        "category": "webmail",
        "tokens": ("mail.yahoo.com", "ymail"),
    },
    {
        "provider": "Proton Mail",
        "category": "webmail",
        "tokens": ("mail.proton.me", "protonmail.com"),
    },
]


APPLICATION_INDICATORS = [
    {"application": "Tor Browser", "tokens": ("tor browser", "start tor browser", "torbrowser", "\\tor.exe", "/tor.exe")},
    {"application": "VMware", "tokens": ("vmware", "vmware.exe", ".vmx", ".vmdk", ".vmem", ".nvram")},
    {"application": "VirtualBox", "tokens": ("virtualbox", "vbox", ".vdi", ".vbox")},
    {"application": "Hyper-V", "tokens": ("hyper-v", "hyperv", "vmcompute", "vmms.exe", ".vhd", ".vhdx")},
    {"application": "QEMU", "tokens": ("qemu", "qcow", ".qcow2")},
    {"application": "Parallels", "tokens": ("parallels", ".pvm")},
    {"application": "VeraCrypt", "tokens": ("veracrypt", ".hc")},
    {"application": "TrueCrypt", "tokens": ("truecrypt", ".tc")},
    {"application": "Cryptomator", "tokens": ("cryptomator", "masterkey.cryptomator")},
    {"application": "BitLocker", "tokens": ("bitlocker", "manage-bde", ".bek", "recovery key")},
    {"application": "Dropbox", "tokens": ("dropbox",)},
    {"application": "Google Drive", "tokens": ("google drive", "googledrive", "drivefs")},
    {"application": "OneDrive", "tokens": ("onedrive", "skydrive")},
    {"application": "Slack", "tokens": ("slack",)},
    {"application": "Teams", "tokens": ("teams", "msteams")},
    {"application": "Zoom", "tokens": ("zoom",)},
    {"application": "AnyDesk", "tokens": ("anydesk",)},
    {"application": "TeamViewer", "tokens": ("teamviewer", "tv_w32.exe", "tv_x64.exe")},
    {"application": "LogMeIn", "tokens": ("logmein", "lmi_rescue", "lmi rescue")},
    {"application": "GoTo", "tokens": ("gotoassist", "goto resolve", "g2ax_")},
    {"application": "ConnectWise Control", "tokens": ("screenconnect", "connectwise control")},
    {"application": "BeyondTrust", "tokens": ("bomgar", "beyondtrust")},
    {"application": "Splashtop", "tokens": ("splashtop",)},
    {"application": "RustDesk", "tokens": ("rustdesk",)},
    {"application": "Chrome Remote Desktop", "tokens": ("chrome remote desktop", "chromoting")},
    {"application": "RemotePC", "tokens": ("remotepc",)},
    {"application": "Dameware", "tokens": ("dameware",)},
    {"application": "Atera", "tokens": ("atera",)},
    {"application": "NinjaOne", "tokens": ("ninjarmm", "ninjaone")},
    {"application": "MeshCentral", "tokens": ("meshcentral",)},
    {"application": "DWAgent", "tokens": ("dwagent",)},
    {"application": "Parsec", "tokens": ("parsec",)},
    {"application": "RealVNC", "tokens": ("realvnc", "vnc viewer", "vnc server")},
    {"application": "TightVNC", "tokens": ("tightvnc",)},
    {"application": "UltraVNC", "tokens": ("ultravnc",)},
]

TOR_TOKENS = ("tor browser", "start tor browser", "torbrowser", "\\tor.exe", "/tor.exe", "\\tor\\browser\\", "/tor/browser/")
ENCRYPTED_VOLUME_INDICATORS = [
    {"type": "BitLocker", "tokens": ("bitlocker", "manage-bde", "bitlocker recovery key", ".bek", "fvevol")},
    {"type": "VeraCrypt", "tokens": ("veracrypt", ".hc")},
    {"type": "TrueCrypt", "tokens": ("truecrypt", ".tc")},
    {"type": "Cryptomator", "tokens": ("cryptomator", "masterkey.cryptomator", ".c9r")},
    {"type": "LUKS", "tokens": ("luks", "cryptsetup")},
    {"type": "VHD/VHDX container", "tokens": (".vhd", ".vhdx")},
]
VIRTUALIZATION_INDICATORS = [
    {"platform": "VMware", "tokens": ("vmware", ".vmx", ".vmdk", ".vmem", ".nvram", "vmtoolsd", "vmwaretray")},
    {"platform": "VirtualBox", "tokens": ("virtualbox", "vbox", ".vdi", ".vbox", "vboxservice", "vboxtray")},
    {"platform": "Hyper-V", "tokens": ("hyper-v", "hyperv", "vmcompute", "vmms.exe", ".vhd", ".vhdx")},
    {"platform": "QEMU", "tokens": ("qemu", "qcow", ".qcow2")},
    {"platform": "Parallels", "tokens": ("parallels", ".pvm")},
]


PREFETCH_TIME_FIELDS = ("last_run_time_utc",)
LNK_TIME_FIELDS = (
    "TargetCreated",
    "TargetModified",
    "TargetAccessed",
    "Target Created",
    "Target Modified",
    "Target Accessed",
)
JUMPLIST_TIME_FIELDS = (
    "LastModified",
    "Last Modified",
    "Created",
    "Modified",
    "Accessed",
)
TARGET_CREATED_FIELDS = (
    "TargetCreated",
    "Target Created",
    "TargetCreationTime",
    "Target Creation Time",
    "Target Created Date",
)
TARGET_MODIFIED_FIELDS = (
    "TargetModified",
    "Target Modified",
    "TargetModificationTime",
    "Target Modification Time",
    "Target Modified Date",
)


def case_summary_report(db: Database, case_id: str) -> dict[str, Any]:
    status = db.case_status(case_id)
    warnings = db.activity_for_case(case_id, level="warning", limit=1000)
    errors = db.activity_for_case(case_id, level="error", limit=1000)
    return {
        "case": status["case"],
        "computers": status["computers"],
        "images": status["images"],
        "counts": {
            "computers": len(status["computers"]),
            "images": len(status["images"]),
            "jobs": len(status["jobs"]),
            "artifacts": len(status["artifacts"]),
            "outputs": len(status["outputs"]),
            "warnings": len(warnings),
            "errors": len(errors),
        },
        "tool_outputs": status["outputs"],
        "parsed_row_counts": status["parsed_row_counts"],
        "artifact_counts": _artifact_counts(status["artifacts"]),
        "evtx_recovery": _evtx_recovery_counts(db, case_id),
    }


def issues_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT * FROM activity_log
        WHERE case_id = ? AND level IN ('warning', 'error')
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {"case_id": case_id, "issues": [dict(row) for row in reversed(rows)]}


def operation_manifest_report(db: Database, case_id: str, *, limit: int = 500) -> dict[str, Any]:
    db.get_case(case_id)
    outputs = [dict(row) for row in db.conn.execute(
        """
        SELECT tool_outputs.*, jobs.exit_code, jobs.dry_run, jobs.start_time, jobs.end_time,
               jobs.stdout_path, jobs.stderr_path, jobs.output_folder
        FROM tool_outputs
        LEFT JOIN jobs ON jobs.id = tool_outputs.job_id
        WHERE tool_outputs.case_id = ?
        ORDER BY COALESCE(jobs.start_time, tool_outputs.created_at), tool_outputs.tool_name, tool_outputs.path
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()]
    jobs = [dict(row) for row in db.conn.execute(
        """
        SELECT id, computer_id, image_id, tool_name, tool_version, command_json, dry_run,
               start_time, end_time, exit_code, stdout_path, stderr_path, output_folder
        FROM jobs
        WHERE case_id = ?
        ORDER BY start_time, tool_name
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()]
    skipped = [dict(row) for row in db.conn.execute(
        """
        SELECT event, level, message, COUNT(*) AS count,
               MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
        FROM activity_log
        WHERE case_id = ?
          AND (
            event LIKE '%skipped%' OR message LIKE '%skipped%'
            OR event LIKE '%missing%' OR message LIKE '%missing%'
            OR level IN ('warning', 'error')
          )
        GROUP BY event, level, message
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()]
    attempts = _artifact_attempts(db, case_id)
    return {
        "case_id": case_id,
        "summary": {
            "jobs": len(jobs),
            "tool_outputs_returned": len(outputs),
            "completed_jobs": sum(1 for row in jobs if row.get("exit_code") == 0),
            "failed_or_unfinished_jobs": sum(1 for row in jobs if row.get("exit_code") not in (0,)),
            "skip_warning_error_groups": len(skipped),
        },
        "artifact_attempts": attempts,
        "jobs": jobs,
        "tool_outputs": outputs,
        "skips_warnings_errors": skipped,
    }


def database_storage_report(
    db: Database,
    case_id: str | None = None,
    *,
    limit: int = 100,
    include_object_sizes: bool = False,
) -> dict[str, Any]:
    page_count = db.conn.execute("PRAGMA page_count").fetchone()[0]
    page_size = db.conn.execute("PRAGMA page_size").fetchone()[0]
    freelist_count = db.conn.execute("PRAGMA freelist_count").fetchone()[0]
    table_rows = _database_table_rows(db, case_id=case_id)
    sizes = _database_object_sizes(db) if include_object_sizes else {}
    tables = []
    for row in table_rows:
        table_size = sizes.get(row["table"], {})
        tables.append(
            {
                **row,
                "table_bytes": table_size.get("bytes"),
                "table_pages": table_size.get("pages"),
                "index_bytes": sum(
                    item["bytes"]
                    for name, item in sizes.items()
                    if name.startswith(f"idx_{row['table']}") or name.startswith(f"sqlite_autoindex_{row['table']}")
                ),
            }
        )
    tables.sort(key=lambda row: (row.get("table_bytes") or 0, row.get("row_count") or 0), reverse=True)
    return {
        "case_id": case_id,
        "database": {
            "path": str(db.path),
            "page_count": page_count,
            "page_size": page_size,
            "file_bytes_estimate": page_count * page_size,
            "freelist_pages": freelist_count,
            "freelist_bytes": freelist_count * page_size,
            "object_sizes_included": include_object_sizes,
        },
        "largest_tables": tables[:limit],
        "content_heavy_tables": _content_heavy_storage(db, case_id),
        "duplicate_tool_outputs": _duplicate_tool_outputs(db, case_id),
    }


def cleanup_candidates_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    storage = database_storage_report(db, case_id, limit=limit)
    candidates = []
    for item in storage["content_heavy_tables"]:
        if item["row_count"]:
            candidates.append(
                {
                    "category": "content_heavy_sqlite",
                    "table": item["table"],
                    "row_count": item["row_count"],
                    "large_columns": item["large_columns"],
                    "recommendation": "Keep metadata in SQLite, move/rebuild large text bodies in OpenSearch or external content store.",
                }
            )
    for duplicate in storage["duplicate_tool_outputs"]:
        candidates.append(
            {
                "category": "duplicate_tool_output",
                "tool_name": duplicate["tool_name"],
                "content_sha256": duplicate["content_sha256"],
                "copies": duplicate["copies"],
                "recommendation": "Preserve provenance, but avoid reimporting duplicate normalized rows unless operator accepts replacement.",
            }
        )
    parsed_rows = _table_count(db, "parsed_rows", case_id)
    if parsed_rows:
        candidates.append(
            {
                "category": "generic_raw_rows",
                "table": "parsed_rows",
                "row_count": parsed_rows,
                "recommendation": "Legacy generic row imports should be purged after confirming normalized tables and raw output files cover the evidence.",
            }
        )
    return {
        "case_id": case_id,
        "database": storage["database"],
        "candidates": candidates[:limit],
    }


def accounts_report(db: Database, case_id: str) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT sam_accounts.*, computers.label AS computer_label, images.path AS image_path
        FROM sam_accounts
        LEFT JOIN computers ON sam_accounts.computer_id = computers.id
        LEFT JOIN images ON sam_accounts.image_id = images.id
        WHERE sam_accounts.case_id = ?
        ORDER BY sam_accounts.image_id, CAST(sam_accounts.rid AS INTEGER)
        """,
        (case_id,),
    ).fetchall()
    accounts = []
    for row in rows:
        accounts.append(
            {
                "computer_id": row["computer_id"],
                "computer_label": row["computer_label"],
                "image_id": row["image_id"],
                "image_path": row["image_path"],
                "username": row["username"],
                "rid": row["rid"],
                "rid_hex": row["rid_hex"],
                "account_category": row["account_category"],
                "last_login_utc": row["last_login_utc"],
                "password_last_set_utc": row["password_last_set_utc"],
                "last_bad_password_utc": row["last_bad_password_utc"],
                "account_expires_utc": row["account_expires_utc"],
                "logon_count": row["logon_count"],
                "bad_password_count": row["bad_password_count"],
                "account_flags_hex": row["account_flags_hex"],
                "account_flags": row["account_flags"],
                "account_flags_unknown_hex": row["account_flags_unknown_hex"],
                "registry_path": row["registry_path"],
            }
        )
    return {"case_id": case_id, "accounts": accounts, "total_accounts": len(accounts)}


def prefetch_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    report = _table_report(db, case_id, "prefetch_items", "prefetch", limit)
    rows = report.get("prefetch") if isinstance(report.get("prefetch"), list) else []
    matched = [
        row for row in rows
        if isinstance(row, dict) and row.get("resolved_reference_path")
    ]
    report["summary"] = {
        "rows_returned": len(rows),
        "reference_matches_returned": len(matched),
        "reference_sources": sorted(
            {
                str(row.get("resolved_reference_source"))
                for row in matched
                if row.get("resolved_reference_source")
            }
        ),
        "reference_caveat": (
            "Prefetch hash reference matches are resolver enrichment only. "
            "They are not proof that the resolved path existed on this system unless corroborated by case artifacts."
        ),
    }
    return report


def cd_burning_activity_report(db: Database, case_id: str, *, limit: int = 250) -> dict[str, Any]:
    db.get_case(case_id)
    items: list[dict[str, Any]] = []
    items.extend(_cd_burning_mft_items(db, case_id, limit=limit))
    items.extend(_cd_burning_usn_items(db, case_id, limit=limit))
    items.extend(_cd_burning_logfile_items(db, case_id, limit=limit))
    items.sort(
        key=lambda item: (
            _timestamp_sort_key(item.get("timestamp_utc")),
            item.get("source_table") or "",
            item.get("path") or "",
        )
    )
    if len(items) > limit:
        items = items[:limit]
    source_counts: dict[str, int] = {}
    indicator_counts: dict[str, int] = {}
    for item in items:
        source = str(item.get("source_table") or "unknown")
        indicator = str(item.get("indicator") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
        indicator_counts[indicator] = indicator_counts.get(indicator, 0) + 1
    return {
        "case_id": case_id,
        "summary": {
            "items_returned": len(items),
            "source_counts": source_counts,
            "indicator_counts": indicator_counts,
            "limit": limit,
        },
        "caveats": [
            "Windows burn staging artifacts indicate CD/DVD burning preparation or staging activity; corroborate with filesystem transactions and user context before concluding media was successfully burned.",
            "DAT/FIL/POST temporary burn files are pattern-based indicators and should be reviewed with surrounding $LogFile, USN, and MFT activity.",
        ],
        "items": items,
        "total_returned": len(items),
    }


def cd_burning_activity_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    rows = report.get("items") if isinstance(report.get("items"), list) else []
    lines = [
        "# CD/DVD Burning Activity Report",
        "",
        f"Case: `{report.get('case_id') or ''}`",
        "",
        "## Summary",
        "",
        f"- Items returned: `{summary.get('items_returned', 0)}`",
        f"- Limit: `{summary.get('limit', '')}`",
        "",
    ]
    caveats = report.get("caveats") if isinstance(report.get("caveats"), list) else []
    if caveats:
        lines.extend(["## Caveats", ""])
        for caveat in caveats:
            lines.append(f"- {caveat}")
        lines.append("")
    for heading, key in (("Sources", "source_counts"), ("Indicators", "indicator_counts")):
        counts = summary.get(key) if isinstance(summary.get(key), dict) else {}
        if counts:
            lines.extend([f"## {heading}", ""])
            for value, count in sorted(counts.items()):
                lines.append(f"- `{value}`: `{count}`")
            lines.append("")
    lines.extend(["## Timeline", ""])
    if not rows:
        lines.append("- No CD/DVD burning indicators were found.")
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(
            f"- `{row.get('timestamp_utc') or ''}` `{row.get('indicator') or ''}` "
            f"`{row.get('source_table') or ''}` `{row.get('display_path') or row.get('path') or ''}`"
        )
        detail_values = {
            "operation": row.get("operation"),
            "reason": row.get("reason"),
            "file_name": row.get("file_name"),
            "source_file": row.get("source_file"),
            "row_number": row.get("row_number"),
        }
        details = [f"{key}={value}" for key, value in detail_values.items() if value not in (None, "")]
        if details:
            lines.append(f"  - {', '.join(details)}")
    lines.append("")
    return "\n".join(lines)


def _cd_burning_mft_items(db: Database, case_id: str, *, limit: int) -> list[dict[str, Any]]:
    rows = _query_report_rows(
        db,
        case_id,
        "mft_entries",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               parent_path, file_name, extension, in_use, is_directory,
               created_si, modified_si, record_changed_si, accessed_si, source_file
        FROM mft_entries
        WHERE case_id = ?
          AND (
            LOWER(COALESCE(parent_path, '')) LIKE '%/appdata/local/microsoft/windows/burn/burn%'
            OR LOWER(COALESCE(parent_path, '')) LIKE '%\\appdata\\local\\microsoft\\windows\\burn\\burn%'
            OR (
              LOWER(COALESCE(parent_path, '')) LIKE '%/appdata/local/temp%'
              AND _cd_tmp_name_predicate_sql()
            )
            OR (
              LOWER(COALESCE(parent_path, '')) LIKE '%\\appdata\\local\\temp%'
              AND _cd_tmp_name_predicate_sql()
            )
          )
        ORDER BY COALESCE(record_changed_si, modified_si, created_si, accessed_si, '') DESC, row_number
        LIMIT ?
        """.replace("_cd_tmp_name_predicate_sql()", _cd_tmp_name_predicate_sql()),
        (case_id, limit),
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        path = _join_path(row.get("parent_path"), row.get("file_name"))
        items.append(
            {
                "source_table": "mft_entries",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("record_changed_si") or row.get("modified_si") or row.get("created_si") or row.get("accessed_si"),
                "indicator": _cd_indicator_for_path(path, row.get("file_name")),
                "path": path,
                "display_path": _display_evidence_path(path),
                "file_name": row.get("file_name"),
                "operation": "mft_metadata",
                "reason": None,
                "tool": row.get("tool_name"),
                "source_file": row.get("source_file") or row.get("source_csv"),
                "row_number": row.get("row_number"),
                "details": {
                    "in_use": row.get("in_use"),
                    "is_directory": row.get("is_directory"),
                    "created_si": row.get("created_si"),
                    "modified_si": row.get("modified_si"),
                    "record_changed_si": row.get("record_changed_si"),
                    "accessed_si": row.get("accessed_si"),
                },
            }
        )
    return items


def _cd_burning_usn_items(db: Database, case_id: str, *, limit: int) -> list[dict[str, Any]]:
    rows = _query_report_rows(
        db,
        case_id,
        "usn_journal_entries",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               update_timestamp, file_name, full_path, reason, source_file
        FROM usn_journal_entries
        WHERE case_id = ?
          AND (
            LOWER(COALESCE(full_path, '')) LIKE '%/appdata/local/microsoft/windows/burn/burn%'
            OR LOWER(COALESCE(full_path, '')) LIKE '%\\appdata\\local\\microsoft\\windows\\burn\\burn%'
            OR (
              LOWER(COALESCE(full_path, '')) LIKE '%/appdata/local/temp%'
              AND _cd_tmp_name_predicate_sql()
            )
            OR (
              LOWER(COALESCE(full_path, '')) LIKE '%\\appdata\\local\\temp%'
              AND _cd_tmp_name_predicate_sql()
            )
          )
        ORDER BY COALESCE(update_timestamp, '') DESC, row_number
        LIMIT ?
        """.replace("_cd_tmp_name_predicate_sql()", _cd_tmp_name_predicate_sql()),
        (case_id, limit),
    )
    return [
        {
            "source_table": "usn_journal_entries",
            "source_row_id": row.get("id"),
            "timestamp_utc": row.get("update_timestamp"),
            "indicator": _cd_indicator_for_path(row.get("full_path"), row.get("file_name")),
            "path": row.get("full_path"),
            "display_path": _display_evidence_path(row.get("full_path")),
            "file_name": row.get("file_name"),
            "operation": "usn_journal",
            "reason": row.get("reason"),
            "tool": row.get("tool_name"),
            "source_file": row.get("source_file") or row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {"reason": row.get("reason")},
        }
        for row in rows
    ]


def _cd_burning_logfile_items(db: Database, case_id: str, *, limit: int) -> list[dict[str, Any]]:
    rows = _query_report_rows(
        db,
        case_id,
        "ntfs_logfile_entries",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               event_time, operation, redo_operation, undo_operation, file_name, file_path, source_file
        FROM ntfs_logfile_entries
        WHERE case_id = ?
          AND (
            LOWER(COALESCE(file_path, '')) LIKE '%/appdata/local/microsoft/windows/burn/burn%'
            OR LOWER(COALESCE(file_path, '')) LIKE '%\\appdata\\local\\microsoft\\windows\\burn\\burn%'
            OR (
              LOWER(COALESCE(file_path, '')) LIKE '%/appdata/local/temp%'
              AND _cd_tmp_name_predicate_sql()
            )
            OR (
              LOWER(COALESCE(file_path, '')) LIKE '%\\appdata\\local\\temp%'
              AND _cd_tmp_name_predicate_sql()
            )
          )
        ORDER BY COALESCE(event_time, '') DESC, row_number
        LIMIT ?
        """.replace("_cd_tmp_name_predicate_sql()", _cd_tmp_name_predicate_sql()),
        (case_id, limit),
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        path = row.get("file_path") or row.get("file_name")
        items.append(
            {
                "source_table": "ntfs_logfile_entries",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("event_time"),
                "indicator": _cd_indicator_for_path(path, row.get("file_name")),
                "path": path,
                "display_path": _display_evidence_path(path),
                "file_name": row.get("file_name"),
                "operation": row.get("operation") or row.get("redo_operation"),
                "reason": row.get("undo_operation"),
                "tool": row.get("tool_name"),
                "source_file": row.get("source_file") or row.get("source_csv"),
                "row_number": row.get("row_number"),
                "details": {
                    "operation": row.get("operation"),
                    "redo_operation": row.get("redo_operation"),
                    "undo_operation": row.get("undo_operation"),
                },
            }
        )
    return items


def _cd_tmp_name_predicate_sql() -> str:
    return (
        "(LOWER(COALESCE(file_name, '')) LIKE 'dat%.tmp' "
        "OR LOWER(COALESCE(file_name, '')) LIKE 'fil%.tmp' "
        "OR LOWER(COALESCE(file_name, '')) LIKE 'post%.tmp')"
    )


def _cd_indicator_for_path(path: Any, file_name: Any = None) -> str:
    text = str(path or file_name or "").replace("\\", "/").lower()
    name = str(file_name or _basename_from_path(text) or "").lower()
    if "/appdata/local/microsoft/windows/burn/burn" in text:
        return "burn_staging_folder"
    if re.match(r"^(dat|fil|post).+\.tmp$", name):
        return "burn_temp_file"
    return "burn_related_path"


def _join_path(parent: Any, name: Any) -> str | None:
    if not parent and not name:
        return None
    if not parent:
        return str(name)
    if not name:
        return str(parent)
    return f"{str(parent).rstrip('/\\\\')}/{name}"


def mft_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "mft_entries", "mft_entries", limit)


def usn_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "usn_journal_entries", "usn_journal_entries", limit)


def usn_summary_report(db: Database, case_id: str, *, limit: int = 25) -> dict[str, Any]:
    db.get_case(case_id)
    total = db.conn.execute(
        "SELECT COUNT(*) AS count FROM usn_journal_entries WHERE case_id = ?",
        (case_id,),
    ).fetchone()["count"]
    time_range = db.conn.execute(
        """
        SELECT MIN(update_timestamp) AS first_update_timestamp,
               MAX(update_timestamp) AS last_update_timestamp
        FROM usn_journal_entries
        WHERE case_id = ?
        """,
        (case_id,),
    ).fetchone()
    reason_counts = db.conn.execute(
        """
        SELECT reason, COUNT(*) AS count
        FROM usn_journal_entries
        WHERE case_id = ?
        GROUP BY reason
        ORDER BY count DESC, reason
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    extension_counts = db.conn.execute(
        """
        SELECT COALESCE(NULLIF(extension, ''), '<none>') AS extension, COUNT(*) AS count
        FROM usn_journal_entries
        WHERE case_id = ?
        GROUP BY COALESCE(NULLIF(extension, ''), '<none>')
        ORDER BY count DESC, extension
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    directory_counts = db.conn.execute(
        """
        SELECT full_path AS path, COUNT(*) AS count
        FROM usn_journal_entries
        WHERE case_id = ? AND COALESCE(full_path, '') != ''
        GROUP BY full_path
        ORDER BY count DESC, full_path
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    user_counts = db.conn.execute(
        """
        WITH normalized AS (
          SELECT
            CASE
              WHEN full_path LIKE '.\\%' THEN substr(full_path, 3)
              ELSE full_path
            END AS path
          FROM usn_journal_entries
          WHERE case_id = ?
        )
        SELECT
          CASE
            WHEN path = 'Users' OR path = 'Users\\' THEN '<user-root>'
            WHEN path LIKE 'Users\\%' AND instr(substr(path, 7), '\\') > 0
              THEN substr(substr(path, 7), 1, instr(substr(path, 7), '\\') - 1)
            WHEN path LIKE 'Users\\%' THEN substr(path, 7)
            ELSE '<non-user-path>'
          END AS user_profile,
          COUNT(*) AS count
        FROM normalized
        GROUP BY user_profile
        ORDER BY count DESC, user_profile
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {
        "case_id": case_id,
        "total_rows": total,
        "time_range": dict(time_range),
        "top_reasons": [dict(row) for row in reason_counts],
        "top_extensions": [dict(row) for row in extension_counts],
        "top_directories": [dict(row) for row in directory_counts],
        "top_user_profiles": [dict(row) for row in user_counts],
    }


def usn_path_report(db: Database, case_id: str, *, contains: str, limit: int = 100) -> dict[str, Any]:
    return _usn_filtered_report(db, case_id, limit=limit, path_contains=contains)


def usn_user_report(db: Database, case_id: str, *, user: str, limit: int = 100) -> dict[str, Any]:
    normalized = user.strip("\\/")
    return _usn_filtered_report(
        db,
        case_id,
        limit=limit,
        path_contains=f"Users\\{normalized}\\",
        filters={"user": user},
    )


def usn_reasons_report(db: Database, case_id: str, *, reason: str, limit: int = 100) -> dict[str, Any]:
    return _usn_filtered_report(db, case_id, limit=limit, reason_contains=reason, filters={"reason": reason})


def usn_timeline_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
    path_contains: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    filters = {}
    if user:
        path_contains = f"Users\\{user.strip('\\/')}\\"
        filters["user"] = user
    if path_contains:
        filters["path_contains"] = path_contains
    if reason:
        filters["reason"] = reason
    return _usn_filtered_report(
        db,
        case_id,
        limit=limit,
        path_contains=path_contains,
        reason_contains=reason,
        order="ASC",
        filters=filters,
        key="timeline",
    )


def usn_suspicious_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT usn_journal_entries.*, computers.label AS computer_label, images.path AS image_path
        FROM usn_journal_entries
        LEFT JOIN computers ON usn_journal_entries.computer_id = computers.id
        LEFT JOIN images ON usn_journal_entries.image_id = images.id
        WHERE usn_journal_entries.case_id = ?
          AND (
            reason LIKE '%Delete%'
            OR reason LIKE '%Rename%'
            OR LOWER(COALESCE(extension, '')) IN (
              '.exe', 'exe', '.dll', 'dll', '.ps1', 'ps1', '.bat', 'bat',
              '.cmd', 'cmd', '.vbs', 'vbs', '.js', 'js', '.lnk', 'lnk',
              '.zip', 'zip', '.rar', 'rar', '.7z', '7z'
            )
            OR LOWER(COALESCE(full_path, '')) LIKE '%\\downloads%'
            OR LOWER(COALESCE(full_path, '')) LIKE '%\\desktop%'
            OR LOWER(COALESCE(full_path, '')) LIKE '%\\temp%'
          )
          AND LOWER(COALESCE(full_path, '')) NOT LIKE '%\\appdata\\local\\google\\chrome\\user data%'
          AND LOWER(COALESCE(full_path, '')) NOT LIKE '%\\appdata\\local\\microsoft\\edge\\user data%'
          AND LOWER(COALESCE(full_path, '')) NOT LIKE '%\\appdata\\roaming\\microsoft\\teams\\service worker%'
          AND LOWER(COALESCE(full_path, '')) NOT LIKE '%\\appdata\\local\\google\\drivefs\\logs%'
        ORDER BY update_timestamp DESC, update_sequence_number DESC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {
        "case_id": case_id,
        "criteria": {
            "included": ["Delete", "Rename", "script/executable/archive extensions", "Downloads/Desktop/Temp paths"],
            "noise_suppressed": ["browser cache", "Teams service worker cache", "Google DriveFS logs"],
        },
        "items": [_compact_usn_row(row) for row in rows],
        "total_returned": len(rows),
    }


def usn_user_files_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    rules_path: str | None = None,
    include_suppressed: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    rules = load_usn_rules(rules_path)
    rows = db.conn.execute(
        """
        SELECT usn_journal_entries.*, computers.label AS computer_label, images.path AS image_path,
               mft_entries.id AS mft_entry_id,
               mft_entries.in_use AS mft_in_use,
               mft_entries.parent_path AS mft_parent_path,
               mft_entries.file_size AS mft_file_size,
               mft_entries.is_directory AS mft_is_directory,
               mft_entries.is_ads AS mft_is_ads,
               mft_entries.created_si AS mft_created_si,
               mft_entries.modified_si AS mft_modified_si,
               mft_entries.record_changed_si AS mft_record_changed_si,
               mft_entries.accessed_si AS mft_accessed_si
        FROM usn_journal_entries
        LEFT JOIN computers ON usn_journal_entries.computer_id = computers.id
        LEFT JOIN images ON usn_journal_entries.image_id = images.id
        LEFT JOIN mft_entries
          ON mft_entries.case_id = usn_journal_entries.case_id
         AND mft_entries.image_id = usn_journal_entries.image_id
         AND mft_entries.entry_number = usn_journal_entries.file_reference_number
         AND (
              usn_journal_entries.file_reference_sequence_number IS NULL
              OR usn_journal_entries.file_reference_sequence_number = ''
              OR mft_entries.sequence_number = usn_journal_entries.file_reference_sequence_number
         )
        WHERE usn_journal_entries.case_id = ?
          AND (
            usn_journal_entries.full_path LIKE '.\\Users\\%'
            OR usn_journal_entries.full_path LIKE 'Users\\%'
            OR usn_journal_entries.reason LIKE '%Rename%'
            OR usn_journal_entries.reason LIKE '%Delete%'
          )
        ORDER BY usn_journal_entries.update_timestamp DESC, usn_journal_entries.update_sequence_number DESC
        LIMIT ?
        """,
        (case_id, max(limit * 100, 10000)),
    ).fetchall()
    items = []
    for row in rows:
        item = _compact_usn_row(row)
        matched, suppressed = match_usn_rules(item, rules)
        substantive_matches = [name for name in matched if name != "user_profile_path"]
        if not substantive_matches:
            continue
        if "user_profile_path" not in matched and set(substantive_matches).issubset({"rename_event", "delete_event"}):
            continue
        if suppressed and not include_suppressed:
            continue
        item["matched_rules"] = matched
        item["substantive_matched_rules"] = substantive_matches
        item["suppressed_rules"] = suppressed
        item["classification"] = "candidate_user_file_activity"
        item["confidence"] = "filter_match"
        item["mft"] = _mft_enrichment(row)
        items.append(item)
        if len(items) >= limit:
            break
    return {
        "case_id": case_id,
        "rules_path": str(rules_path) if rules_path else "default",
        "include_suppressed": include_suppressed,
        "language": "Rows matched transparent filter rules; this report does not conclude user intent.",
        "items": items,
        "total_returned": len(items),
    }


def usn_rename_pairs_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        WITH renames AS (
          SELECT *
          FROM usn_journal_entries
          WHERE case_id = ?
            AND (reason LIKE '%RenameOldName%' OR reason LIKE '%RenameNewName%')
        )
        SELECT old.computer_id, computers.label AS computer_label, old.image_id, images.path AS image_path,
               old.update_timestamp, old.file_reference_number,
               old.full_path AS old_parent_path, old.file_name AS old_name,
               new.full_path AS new_parent_path, new.file_name AS new_name,
               old.reason AS old_reason, new.reason AS new_reason,
               old.update_sequence_number AS old_usn, new.update_sequence_number AS new_usn
        FROM renames old
        JOIN renames new
          ON new.case_id = old.case_id
         AND new.image_id = old.image_id
         AND new.file_reference_number = old.file_reference_number
         AND new.update_timestamp = old.update_timestamp
         AND new.reason LIKE '%RenameNewName%'
        LEFT JOIN computers ON old.computer_id = computers.id
        LEFT JOIN images ON old.image_id = images.id
        WHERE old.reason LIKE '%RenameOldName%'
        ORDER BY old.update_timestamp DESC, old.update_sequence_number DESC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {"case_id": case_id, "rename_pairs": [dict(row) for row in rows], "total_returned": len(rows)}


SDELETE_WIPE_NAME_RE = re.compile(r"(?i)^O?([A-Z])\1{2,80}\.\1{2,16}$")


def sdelete_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT usn_journal_entries.*, computers.label AS computer_label, images.path AS image_path
        FROM usn_journal_entries
        LEFT JOIN computers ON usn_journal_entries.computer_id = computers.id
        LEFT JOIN images ON usn_journal_entries.image_id = images.id
        WHERE usn_journal_entries.case_id = ?
          AND (
            usn_journal_entries.reason LIKE '%Rename%'
            OR usn_journal_entries.reason LIKE '%Delete%'
            OR usn_journal_entries.reason LIKE '%DataOverwrite%'
            OR usn_journal_entries.reason LIKE '%ReparsePointChange%'
          )
        ORDER BY usn_journal_entries.image_id,
                 usn_journal_entries.file_reference_number,
                 usn_journal_entries.file_reference_sequence_number,
                 usn_journal_entries.update_timestamp,
                 CAST(NULLIF(usn_journal_entries.update_sequence_number, '') AS INTEGER),
                 usn_journal_entries.row_number
        """,
        (case_id,),
    ).fetchall()

    groups: dict[tuple[str, str, str, str], list[Any]] = {}
    for row in rows:
        key = (
            row["computer_id"] or "",
            row["image_id"] or "",
            row["file_reference_number"] or "",
            row["file_reference_sequence_number"] or "",
        )
        groups.setdefault(key, []).append(row)

    items: list[dict[str, Any]] = []
    for group_rows in groups.values():
        item = _sdelete_item_from_usn_group(db, case_id, group_rows)
        if item:
            items.append(item)
    items.extend(_sdelete_items_from_windows_search_gather(db, case_id=case_id))

    items.sort(key=lambda item: (item.get("first_wipe_timestamp") or "", item.get("file_reference_number") or ""))
    items = items[:limit]
    return {
        "case_id": case_id,
        "criteria": {
            "source": "USN Journal",
            "secondary_source": "Windows Search GatherLogs/SystemIndex is used as supporting deletion/wipe evidence and can produce possible wipe observations when USN evidence is unavailable.",
            "wipe_name_pattern": "optional O prefix + repeated A-Z basename + matching repeated extension",
            "minimum_distinct_letters": 6,
            "delete_required": True,
            "odl_correlation": "Best-effort match on original filename near the wipe timestamps.",
            "prefetch_correlation": "SDELETE prefetch rows are included when execution times overlap the wipe window; Prefetch usually proves execution, not target filenames.",
        },
        "items": items,
        "total_returned": len(items),
    }


def _sdelete_item_from_usn_group(db: Database, case_id: str, rows: list[Any]) -> dict[str, Any] | None:
    wipe_rows = [row for row in rows if _is_sdelete_wipe_name(row["file_name"])]
    if not wipe_rows:
        return None
    letters = _sdelete_letters(wipe_rows)
    has_delete = any("Delete" in (row["reason"] or "") for row in wipe_rows)
    if len(letters) < 6 or not has_delete:
        return None

    first_wipe = wipe_rows[0]
    last_wipe = wipe_rows[-1]
    original_rows = [
        row
        for row in rows
        if not _is_sdelete_wipe_name(row["file_name"])
        and (row["update_timestamp"] or "") <= (first_wipe["update_timestamp"] or "")
    ]
    original = original_rows[-1] if original_rows else None
    original_name = original["file_name"] if original else ""
    original_parent = original["full_path"] if original else ""
    metadata = _sdelete_filesystem_metadata(
        db,
        case_id=case_id,
        image_id=first_wipe["image_id"],
        entry_number=first_wipe["file_reference_number"],
        sequence_number=first_wipe["file_reference_sequence_number"],
        parent_entry_number=original["parent_file_reference_number"] if original else first_wipe["parent_file_reference_number"],
        parent_sequence_number=original["parent_file_reference_sequence_number"] if original else first_wipe["parent_file_reference_sequence_number"],
        original_file_name=original_name,
        original_parent_path=original_parent,
        first_timestamp=first_wipe["update_timestamp"],
        last_timestamp=last_wipe["update_timestamp"],
    )
    odl = _sdelete_odl_correlations(
        db,
        case_id=case_id,
        image_id=first_wipe["image_id"],
        file_name=original_name,
        first_timestamp=first_wipe["update_timestamp"],
        last_timestamp=last_wipe["update_timestamp"],
    )
    return {
        "computer_id": first_wipe["computer_id"],
        "computer_label": first_wipe["computer_label"],
        "image_id": first_wipe["image_id"],
        "image_path": first_wipe["image_path"],
        "file_reference_number": first_wipe["file_reference_number"],
        "file_reference_sequence_number": first_wipe["file_reference_sequence_number"],
        "original_file_name": original_name,
        "original_parent_path": original_parent,
        "original_path": _join_windows_path(original_parent, original_name),
        "original_file_attributes": original["file_attributes"] if original else "",
        "first_wipe_timestamp": first_wipe["update_timestamp"],
        "last_wipe_timestamp": last_wipe["update_timestamp"],
        "first_wipe_name": first_wipe["file_name"],
        "last_wipe_name": last_wipe["file_name"],
        "letters_seen": "".join(letters),
        "letter_count": len(letters),
        "wipe_rename_event_count": len(wipe_rows),
        "final_reason": last_wipe["reason"],
        "final_parent_path": last_wipe["full_path"],
        "classification": "sdelete_style_wipe_delete",
        "basis": "USN rename chain through repeated-letter names followed by delete",
        "usn_event_count": len(wipe_rows) + (1 if original else 0),
        "usn_events": [_compact_usn_row(row) for row in rows],
        "usn_events_sample": _sdelete_usn_event_sample(original, wipe_rows),
        "filesystem_metadata": metadata,
        "deletion_timestamps": _sdelete_deletion_timestamps(rows, odl),
        "recovered_timestamps": _sdelete_recovered_timestamps(rows, metadata, odl),
        "odl_correlations": odl,
        "odl_correlation_count": len(odl),
    }


def _is_sdelete_wipe_name(file_name: str | None) -> bool:
    return bool(file_name and SDELETE_WIPE_NAME_RE.match(file_name))


def _sdelete_letters(rows: list[Any]) -> list[str]:
    letters = set()
    for row in rows:
        match = SDELETE_WIPE_NAME_RE.match(row["file_name"] or "")
        if match:
            letters.add(match.group(1).upper())
    return sorted(letters)


def _sdelete_items_from_windows_search_gather(db: Database, *, case_id: str) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT windows_search_gather_logs.*, computers.label AS computer_label, images.path AS image_path
        FROM windows_search_gather_logs
        LEFT JOIN computers ON windows_search_gather_logs.computer_id = computers.id
        LEFT JOIN images ON windows_search_gather_logs.image_id = images.id
        WHERE windows_search_gather_logs.case_id = ?
          AND windows_search_gather_logs.item_path IS NOT NULL
          AND windows_search_gather_logs.item_path != ''
        ORDER BY windows_search_gather_logs.image_id,
                 windows_search_gather_logs.timestamp_utc,
                 windows_search_gather_logs.row_number
        """,
        (case_id,),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        file_name = _windows_basename(row["item_path"])
        if not _is_sdelete_wipe_name(file_name):
            continue
        items.append(
            {
                "computer_id": row["computer_id"],
                "computer_label": row["computer_label"],
                "image_id": row["image_id"],
                "image_path": row["image_path"],
                "file_reference_number": "",
                "file_reference_sequence_number": "",
                "original_file_name": "",
                "original_parent_path": _windows_parent(row["item_path"]),
                "original_path": "",
                "original_file_attributes": "",
                "first_wipe_timestamp": row["timestamp_utc"],
                "last_wipe_timestamp": row["timestamp_utc"],
                "first_wipe_name": file_name,
                "last_wipe_name": file_name,
                "letters_seen": "".join(_sdelete_letters([{"file_name": file_name}])),
                "letter_count": 1,
                "wipe_rename_event_count": 1,
                "final_reason": row["crawl_code_hex"],
                "final_parent_path": _windows_parent(row["item_path"]),
                "classification": "possible_sdelete_style_wipe_observed_in_windows_search_gather_log",
                "basis": "Windows Search gather log observed SDelete-style repeated-letter filename; corroborate with USN, Prefetch, registry, or filesystem metadata before treating as confirmed wiping.",
                "usn_event_count": 0,
                "usn_events": [],
                "usn_events_sample": [],
                "filesystem_metadata": {
                    "windows_search_gather_logs": [
                        {
                            "source_name": row["source_name"],
                            "log_type": row["log_type"],
                            "line_number": row["line_number"],
                            "timestamp_utc": row["timestamp_utc"],
                            "item_url": row["item_url"],
                            "item_path": row["item_path"],
                            "item_scheme": row["item_scheme"],
                            "is_deleted_path": row["is_deleted_path"],
                            "status_hex": row["status_hex"],
                            "crawl_code_hex": row["crawl_code_hex"],
                            "scope_id": row["scope_id"],
                            "document_id": row["document_id"],
                        }
                    ]
                },
                "deletion_timestamps": [
                    {
                        "source": "windows_search_gather_logs",
                        "timestamp": row["timestamp_utc"],
                        "time_type": "search_gather_observation",
                        "description": row["crawl_code_hex"],
                        "file_name": file_name,
                        "path": row["item_path"],
                    }
                ],
                "recovered_timestamps": [
                    {
                        "source": "windows_search_gather_logs",
                        "timestamp": row["timestamp_utc"],
                        "time_type": "timestamp_utc",
                        "description": row["crawl_code_hex"],
                        "file_name": file_name,
                        "path": row["item_path"],
                    }
                ],
                "odl_correlations": [],
                "odl_correlation_count": 0,
            }
        )
    return items


def _sdelete_usn_event_sample(original: Any | None, wipe_rows: list[Any]) -> list[dict[str, Any]]:
    sample: list[Any] = []
    if original is not None:
        sample.append(original)
    sample.extend(wipe_rows[:6])
    if len(wipe_rows) > 9:
        sample.extend(wipe_rows[-3:])
    else:
        sample.extend(wipe_rows[6:])
    seen: set[tuple[str, str, str]] = set()
    compacted = []
    for row in sample:
        key = (row["update_timestamp"] or "", row["update_sequence_number"] or "", row["file_name"] or "")
        if key in seen:
            continue
        seen.add(key)
        compacted.append(_compact_usn_row(row))
    return compacted


def _sdelete_filesystem_metadata(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    entry_number: str | None,
    sequence_number: str | None,
    parent_entry_number: str | None,
    parent_sequence_number: str | None,
    original_file_name: str | None,
    original_parent_path: str | None,
    first_timestamp: str | None,
    last_timestamp: str | None,
) -> dict[str, Any]:
    original_path = _join_windows_path(original_parent_path, original_file_name)
    mft_entry = _sdelete_mft_entry(
        db,
        case_id=case_id,
        image_id=image_id,
        entry_number=entry_number,
        sequence_number=sequence_number,
    )
    current_mft = _sdelete_mft_entry(
        db,
        case_id=case_id,
        image_id=image_id,
        entry_number=entry_number,
        sequence_number=None,
    )
    return {
        "mft_entry": mft_entry,
        "mft_entry_status": "exact_sequence_available" if mft_entry else "exact_sequence_not_present_in_current_mft",
        "mft_reuse": _sdelete_mft_reuse(entry_number, sequence_number, current_mft),
        "parent_mft_entry": _sdelete_mft_entry(
            db,
            case_id=case_id,
            image_id=image_id,
            entry_number=parent_entry_number,
            sequence_number=parent_sequence_number,
        ),
        "filesystem_review": _sdelete_filesystem_review_rows(
            db,
            case_id=case_id,
            image_id=image_id,
            entry_number=entry_number,
            sequence_number=sequence_number,
            file_name=original_file_name,
        ),
        "ntfs_logfile": _sdelete_logfile_rows(
            db,
            case_id=case_id,
            image_id=image_id,
            entry_number=entry_number,
            sequence_number=sequence_number,
            file_name=original_file_name,
        ),
        "ntfs_index": _sdelete_index_rows(
            db,
            case_id=case_id,
            image_id=image_id,
            entry_number=entry_number,
            sequence_number=sequence_number,
            file_name=original_file_name,
        ),
        "namespace_reconciliation": _sdelete_namespace_rows(
            db,
            case_id=case_id,
            image_id=image_id,
            entry_number=entry_number,
            sequence_number=sequence_number,
            file_name=original_file_name,
        ),
        "windows_search_files": _sdelete_windows_search_rows(
            db,
            case_id=case_id,
            image_id=image_id,
            file_name=original_file_name,
        ),
        "windows_search_gather_logs": _sdelete_windows_search_gather_rows(
            db,
            case_id=case_id,
            image_id=image_id,
            file_name=original_file_name,
            original_path=original_path,
            first_timestamp=first_timestamp,
            last_timestamp=last_timestamp,
        ),
        "file_internal_metadata": _sdelete_internal_metadata_rows(
            db,
            case_id=case_id,
            image_id=image_id,
            file_name=original_file_name,
            original_path=original_path,
        ),
        "associated_artifacts": _sdelete_associated_artifacts(
            db,
            case_id=case_id,
            image_id=image_id,
            file_name=original_file_name,
            original_path=original_path,
            original_parent_path=original_parent_path,
            first_timestamp=first_timestamp,
            last_timestamp=last_timestamp,
        ),
    }


def _sdelete_mft_reuse(
    entry_number: str | None,
    wiped_sequence_number: str | None,
    current_mft: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not current_mft:
        return None
    if wiped_sequence_number and current_mft.get("sequence_number") == wiped_sequence_number:
        return None
    return {
        "entry_number": entry_number,
        "wiped_sequence_number": wiped_sequence_number,
        "current_sequence_number": current_mft.get("sequence_number"),
        "current_file_name": current_mft.get("file_name"),
        "current_parent_path": current_mft.get("parent_path"),
        "current_in_use": current_mft.get("in_use"),
        "current_file_size": current_mft.get("file_size"),
        "current_created_si": current_mft.get("created_si"),
        "current_modified_si": current_mft.get("modified_si"),
        "current_record_changed_si": current_mft.get("record_changed_si"),
        "note": "Same MFT entry number currently points to a different sequence; this is record reuse, not wiped-file metadata.",
    }


def _sdelete_mft_entry(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    entry_number: str | None,
    sequence_number: str | None,
) -> dict[str, Any] | None:
    if not entry_number:
        return None
    row = db.conn.execute(
        """
        SELECT id, tool_name, source_csv, row_number, entry_number, sequence_number,
               in_use, parent_entry_number, parent_sequence_number, parent_path,
               file_name, extension, file_size, is_directory, has_ads, is_ads,
               si_flags, reparse_target, si_fn_copied,
               created_si, created_fn, modified_si, modified_fn,
               record_changed_si, record_changed_fn, accessed_si, accessed_fn,
               source_file
        FROM mft_entries
        WHERE case_id = ? AND image_id = ? AND entry_number = ?
          AND (? IS NULL OR ? = '' OR sequence_number = ?)
        ORDER BY row_number DESC
        LIMIT 1
        """,
        (case_id, image_id, entry_number, sequence_number, sequence_number, sequence_number),
    ).fetchone()
    return dict(row) if row else None


def _sdelete_filesystem_review_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    entry_number: str | None,
    sequence_number: str | None,
    file_name: str | None,
) -> list[dict[str, Any]]:
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT source_table, source_tool, source_row_number, event_type, event_time,
                   file_name, file_path, parent_path, mft_entry_number, mft_sequence_number,
                   parent_entry_number, parent_sequence_number, in_use, is_directory,
                   operation, reason, status, details_json
            FROM filesystem_review
            WHERE case_id = ? AND image_id = ?
              AND (
                (mft_entry_number = ? AND (? IS NULL OR ? = '' OR mft_sequence_number = ?))
                OR (? IS NOT NULL AND file_name = ?)
              )
            ORDER BY event_time, source_table, source_row_number
            LIMIT 50
            """,
            (case_id, image_id, entry_number, sequence_number, sequence_number, sequence_number, file_name, file_name),
        ).fetchall()
    )


def _sdelete_logfile_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    entry_number: str | None,
    sequence_number: str | None,
    file_name: str | None,
) -> list[dict[str, Any]]:
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT event_time, operation, redo_operation, undo_operation, target_attribute,
                   file_name, file_path, file_reference_number, file_reference_sequence_number,
                   parent_file_reference_number, parent_file_reference_sequence_number,
                   log_sequence_number, previous_log_sequence_number, transaction_id,
                   client_id, record_offset, row_json
            FROM ntfs_logfile_entries
            WHERE case_id = ? AND image_id = ?
              AND (
                (file_reference_number = ? AND (? IS NULL OR ? = '' OR file_reference_sequence_number = ?))
                OR (? IS NOT NULL AND file_name = ?)
              )
            ORDER BY event_time, log_sequence_number
            LIMIT 50
            """,
            (case_id, image_id, entry_number, sequence_number, sequence_number, sequence_number, file_name, file_name),
        ).fetchall()
    )


def _sdelete_index_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    entry_number: str | None,
    sequence_number: str | None,
    file_name: str | None,
) -> list[dict[str, Any]]:
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT directory_entry_number, directory_path, source, block_vcn, block_active,
                   entry_offset, index_entry_flags, referenced_entry_number,
                   referenced_sequence_number, parent_entry_number, parent_sequence_number,
                   file_name, name_type, name_type_label, created_fn, modified_fn,
                   record_changed_fn, accessed_fn, allocated_size, real_size,
                   file_flags, from_slack, source_file
            FROM ntfs_index_entries
            WHERE case_id = ? AND image_id = ?
              AND (
                (referenced_entry_number = ? AND (? IS NULL OR ? = '' OR referenced_sequence_number = ?))
                OR (? IS NOT NULL AND file_name = ?)
              )
            ORDER BY directory_path, source, row_number
            LIMIT 50
            """,
            (case_id, image_id, entry_number, sequence_number, sequence_number, sequence_number, file_name, file_name),
        ).fetchall()
    )


def _sdelete_namespace_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    entry_number: str | None,
    sequence_number: str | None,
    file_name: str | None,
) -> list[dict[str, Any]]:
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT mft_entry_number, mft_sequence_number, parent_entry_number,
                   parent_path, file_name, original_path, mft_in_use,
                   mounted_present, parent_mounted_exists, parent_access_status,
                   index_status, legit_active_file, index_entry_id, index_from_slack,
                   index_block_active, index_bitmap_error, icat_recovered,
                   recovered_size, recovered_sha256, header_type, zero_prefix, reason
            FROM ntfs_namespace_reconciliation
            WHERE case_id = ? AND image_id = ?
              AND (
                (mft_entry_number = ? AND (? IS NULL OR ? = '' OR mft_sequence_number = ?))
                OR (? IS NOT NULL AND file_name = ?)
              )
            ORDER BY original_path, created_at
            LIMIT 50
            """,
            (case_id, image_id, entry_number, sequence_number, sequence_number, sequence_number, file_name, file_name),
        ).fetchall()
    )


def _sdelete_windows_search_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
) -> list[dict[str, Any]]:
    if not file_name:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT work_id, gather_time, item_path, item_url, folder_path,
                   file_name, file_extension, item_type, date_created,
                   date_modified, date_accessed, date_imported, size,
                   owner, computer_name
            FROM windows_search_files
            WHERE case_id = ? AND image_id = ? AND file_name = ?
            ORDER BY gather_time
            LIMIT 50
            """,
            (case_id, image_id, file_name),
        ).fetchall()
    )


def _sdelete_windows_search_gather_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
    original_path: str | None,
    first_timestamp: str | None,
    last_timestamp: str | None,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?", "image_id = ?"]
    params: list[Any] = [case_id, image_id]
    path_terms = [term for term in (file_name, original_path) if term]
    if path_terms:
        filters.append("(" + " OR ".join("item_path LIKE ?" for _ in path_terms) + ")")
        params.extend(f"%{term}%" for term in path_terms)
    elif first_timestamp and last_timestamp:
        filters.append("timestamp_utc BETWEEN ? AND ?")
        params.extend([first_timestamp, last_timestamp])
    else:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            f"""
            SELECT source_name, log_type, line_number, timestamp_utc, item_url,
                   item_path, item_scheme, is_deleted_path, status_hex,
                   crawl_code_hex, scope_id, document_id
            FROM windows_search_gather_logs
            WHERE {' AND '.join(filters)}
            ORDER BY timestamp_utc, source_name, line_number
            LIMIT 100
            """,
            params,
        ).fetchall()
    )


def _sdelete_internal_metadata_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
    original_path: str | None,
) -> list[dict[str, Any]]:
    if not file_name and not original_path:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT source_file, original_path, file_name, extension, parser,
                   metadata_group, property_name, property_value, raw_property_name,
                   file_size, mft_created, mft_modified, mft_accessed,
                   mft_record_modified, mft_in_use, path_unresolved,
                   deleted_mft_entry, live_orphan, extraction_method
            FROM file_internal_metadata
            WHERE case_id = ? AND image_id = ?
              AND ((? IS NOT NULL AND file_name = ?) OR (? IS NOT NULL AND original_path = ?))
            ORDER BY parser, metadata_group, property_name
            LIMIT 100
            """,
            (case_id, image_id, file_name, file_name, original_path, original_path),
        ).fetchall()
    )


def _sdelete_associated_artifacts(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
    original_path: str | None,
    original_parent_path: str | None,
    first_timestamp: str | None,
    last_timestamp: str | None,
) -> dict[str, list[dict[str, Any]]]:
    return {
        "shortcuts_and_jumplists": _sdelete_shortcut_rows(db, case_id=case_id, image_id=image_id, file_name=file_name, original_path=original_path),
        "shellbags": _sdelete_shellbag_rows(db, case_id=case_id, image_id=image_id, file_name=file_name, original_parent_path=original_parent_path),
        "registry_recentdocs": _sdelete_registry_recentdocs_rows(db, case_id=case_id, image_id=image_id, file_name=file_name),
        "registry_office_mru": _sdelete_registry_office_rows(db, case_id=case_id, image_id=image_id, file_name=file_name),
        "registry_common_dialog_mru": _sdelete_registry_common_dialog_rows(db, case_id=case_id, image_id=image_id, file_name=file_name, original_path=original_path),
        "registry_common_dialog_shell_items": _sdelete_registry_common_dialog_item_rows(db, case_id=case_id, image_id=image_id, file_name=file_name),
        "registry_artifacts": _sdelete_registry_artifact_rows(db, case_id=case_id, image_id=image_id, file_name=file_name),
        "sdelete_prefetch": _sdelete_prefetch_rows(
            db,
            case_id=case_id,
            image_id=image_id,
            first_timestamp=first_timestamp,
            last_timestamp=last_timestamp,
        ),
    }


def _sdelete_prefetch_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    first_timestamp: str | None,
    last_timestamp: str | None,
) -> list[dict[str, Any]]:
    rows = _rows_as_dicts(
        db.conn.execute(
            """
            SELECT prefetch_name, artifact_path, original_path, executable_name,
                   prefetch_hash, prefetch_version, prefetch_version_label,
                   compression, run_count, last_run_time_utc, last_run_times_utc,
                   referenced_string_count, referenced_strings, parser_note,
                   pf_created, pf_modified, pf_accessed, pf_mft_record_modified,
                   tool_name, source_csv, row_number
            FROM prefetch_items
            WHERE case_id = ? AND image_id = ?
              AND LOWER(COALESCE(executable_name, prefetch_name, '')) LIKE '%sdelete%'
            ORDER BY last_run_time_utc
            LIMIT 25
            """,
            (case_id, image_id),
        ).fetchall()
    )
    if not rows:
        return []
    start = _parse_report_timestamp(first_timestamp)
    end = _parse_report_timestamp(last_timestamp)
    if not start or not end:
        return rows
    correlated = []
    for row in rows:
        run_times = _prefetch_run_times(row)
        if any(-300 <= (timestamp - start).total_seconds() <= 300 or -300 <= (timestamp - end).total_seconds() <= 300 for timestamp in run_times):
            row["basis"] = "SDELETE prefetch execution within five minutes of USN wipe window"
            correlated.append(row)
    return correlated or rows


def _prefetch_run_times(row: dict[str, Any]) -> list[datetime]:
    values = []
    if row.get("last_run_time_utc"):
        values.append(row["last_run_time_utc"])
    raw = row.get("last_run_times_utc")
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                values.extend(str(value) for value in parsed)
        except (TypeError, ValueError):
            pass
    times = []
    for value in values:
        timestamp = _parse_report_timestamp(str(value))
        if timestamp:
            times.append(timestamp)
    return times


def _sdelete_shortcut_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
    original_path: str | None,
) -> list[dict[str, Any]]:
    if not file_name:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT artifact_type, artifact_name, artifact_path, file_name, file_location,
                   target_created, target_modified, target_accessed, device_type,
                   volume_serial_number, volume_name, lnk_created, lnk_modified,
                   lnk_accessed, jumplist_item_number, tool_name, source_csv, row_number
            FROM shortcut_items
            WHERE case_id = ? AND image_id = ?
              AND (
                file_name = ?
                OR file_location LIKE ?
                OR (? IS NOT NULL AND file_location = ?)
              )
            ORDER BY COALESCE(target_accessed, target_modified, target_created, lnk_modified, lnk_created), artifact_type
            LIMIT 50
            """,
            (case_id, image_id, file_name, f"%{file_name}%", original_path, original_path),
        ).fetchall()
    )


def _sdelete_shellbag_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
    original_parent_path: str | None,
) -> list[dict[str, Any]]:
    parent_like = f"%{_normalize_path_for_like(original_parent_path)}%" if original_parent_path else None
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT source_file, hive_path, user_profile, absolute_path, shell_type,
                   value_name, mru_position, created_on, modified_on, accessed_on,
                   last_write_time, first_interacted, last_interacted, has_explored,
                   drive_letter, volume_guid, volume_serial_number, volume_name,
                   tool_name, source_csv, row_number
            FROM shellbag_entries
            WHERE case_id = ? AND image_id = ?
              AND (
                (? IS NOT NULL AND absolute_path LIKE ?)
                OR (? IS NOT NULL AND absolute_path LIKE ?)
              )
            ORDER BY COALESCE(last_interacted, first_interacted, last_write_time, modified_on, accessed_on, created_on)
            LIMIT 50
            """,
            (
                case_id,
                image_id,
                file_name,
                f"%{file_name}%" if file_name else None,
                parent_like,
                parent_like,
            ),
        ).fetchall()
    )


def _sdelete_registry_recentdocs_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
) -> list[dict[str, Any]]:
    if not file_name:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT hive_path, hive_type, user_profile, category, key_path,
                   key_last_write_timestamp, extension, value_name, target_name,
                   lnk_name, mru_position, opened_on, extension_last_opened,
                   tool_name, source_csv, row_number
            FROM registry_recentdocs
            WHERE case_id = ? AND image_id = ?
              AND (target_name = ? OR lnk_name = ? OR target_name LIKE ? OR lnk_name LIKE ?)
            ORDER BY COALESCE(opened_on, extension_last_opened, key_last_write_timestamp)
            LIMIT 50
            """,
            (case_id, image_id, file_name, file_name, f"%{file_name}%", f"%{file_name}%"),
        ).fetchall()
    )


def _sdelete_registry_office_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
) -> list[dict[str, Any]]:
    if not file_name:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT hive_path, hive_type, user_profile, category, key_path,
                   key_last_write_timestamp, value_name, last_opened,
                   last_closed, file_name, tool_name, source_csv, row_number
            FROM registry_office_mru
            WHERE case_id = ? AND image_id = ? AND file_name LIKE ?
            ORDER BY COALESCE(last_opened, last_closed, key_last_write_timestamp)
            LIMIT 50
            """,
            (case_id, image_id, f"%{file_name}%"),
        ).fetchall()
    )


def _sdelete_registry_common_dialog_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
    original_path: str | None,
) -> list[dict[str, Any]]:
    if not file_name:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT hive_path, hive_type, user_profile, category, key_path,
                   key_last_write_timestamp, artifact, extension, value_name,
                   mru_position, executable, absolute_path, opened_on, details,
                   tool_name, source_csv, row_number
            FROM registry_common_dialog_mru
            WHERE case_id = ? AND image_id = ?
              AND (
                absolute_path LIKE ?
                OR details LIKE ?
                OR (? IS NOT NULL AND absolute_path = ?)
              )
            ORDER BY COALESCE(opened_on, key_last_write_timestamp)
            LIMIT 50
            """,
            (case_id, image_id, f"%{file_name}%", f"%{file_name}%", original_path, original_path),
        ).fetchall()
    )


def _sdelete_registry_common_dialog_item_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
) -> list[dict[str, Any]]:
    if not file_name:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT source_path, hive_type, user_profile, artifact, key_path,
                   key_last_write_utc, mru_position, value_name, item_index,
                   shell_item_name, shell_created, shell_modified, shell_accessed,
                   raw_fat_times_json, source_csv
            FROM registry_common_dialog_items
            WHERE case_id = ? AND image_id = ? AND shell_item_name = ?
            ORDER BY COALESCE(shell_accessed, shell_modified, shell_created, key_last_write_utc)
            LIMIT 50
            """,
            (case_id, image_id, file_name),
        ).fetchall()
    )


def _sdelete_registry_artifact_rows(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
) -> list[dict[str, Any]]:
    if not file_name:
        return []
    return _rows_as_dicts(
        db.conn.execute(
            """
            SELECT source_path, hive_type, user_profile, artifact, category,
                   key_path, key_last_write_utc, value_name, value_type,
                   value_data, notes, event_time_utc, mru_position,
                   recentdocs_time_utc, recentdocs_extension_time_utc,
                   recentdocs_mru_position, recentdocs_extension_mru_position,
                   display_name, transaction_logs_detected,
                   transaction_logs_applied, transaction_log_paths,
                   tool_name, source_csv, row_number
            FROM registry_artifacts
            WHERE case_id = ? AND image_id = ?
              AND (
                display_name LIKE ?
                OR value_data LIKE ?
                OR notes LIKE ?
              )
            ORDER BY COALESCE(event_time_utc, recentdocs_time_utc, recentdocs_extension_time_utc, key_last_write_utc)
            LIMIT 50
            """,
            (case_id, image_id, f"%{file_name}%", f"%{file_name}%", f"%{file_name}%"),
        ).fetchall()
    )


def _normalize_path_for_like(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").lstrip(".\\")


def _sdelete_recovered_timestamps(
    usn_rows: list[Any],
    metadata: dict[str, Any],
    odl_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in usn_rows:
        timestamp = row["update_timestamp"]
        if timestamp:
            events.append(
                {
                    "source": "usn_journal",
                    "timestamp": timestamp,
                    "time_type": "usn_update",
                    "description": row["reason"],
                    "file_name": row["file_name"],
                    "path": _join_windows_path(row["full_path"], row["file_name"]),
                }
            )
    for row in odl_rows:
        if row.get("timestamp_utc"):
            events.append(
                {
                    "source": "onedrive_odl",
                    "timestamp": row.get("timestamp_utc"),
                    "time_type": row.get("event_type") or "odl_event",
                    "description": f"{row.get('code_file') or ''} / {row.get('function') or ''}".strip(" /"),
                    "path": row.get("local_path") or row.get("params_text"),
                }
            )
    for source, rows in (metadata.get("associated_artifacts") or {}).items():
        for row in rows:
            _add_sdelete_timestamp_events(events, source, row)
    for source in ("windows_search_files", "windows_search_gather_logs", "file_internal_metadata", "ntfs_index", "filesystem_review", "ntfs_logfile"):
        for row in metadata.get(source) or []:
            _add_sdelete_timestamp_events(events, source, row)
    events.sort(key=lambda item: str(item.get("timestamp") or ""))
    return events[:300]


def _sdelete_deletion_timestamps(usn_rows: list[Any], odl_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in usn_rows:
        reason = row["reason"] or ""
        if "Delete" not in reason and "Rename" not in reason:
            continue
        events.append(
            {
                "source": "usn_journal",
                "timestamp": row["update_timestamp"],
                "time_type": "delete_or_rename_sequence",
                "description": reason,
                "file_name": row["file_name"],
                "path": _join_windows_path(row["full_path"], row["file_name"]),
            }
        )
    for row in odl_rows:
        if row.get("event_type") != "delete" and "delete" not in str(row.get("params_text") or "").lower() and "removed" not in str(row.get("params_text") or "").lower():
            continue
        events.append(
            {
                "source": "onedrive_odl",
                "timestamp": row.get("timestamp_utc"),
                "time_type": row.get("event_type") or "odl_delete_observation",
                "description": f"{row.get('code_file') or ''} / {row.get('function') or ''}".strip(" /"),
                "path": row.get("local_path") or row.get("params_text"),
            }
        )
    events.sort(key=lambda item: str(item.get("timestamp") or ""))
    return events


SDELETE_TIME_FIELDS = (
    "target_created", "target_modified", "target_accessed",
    "lnk_created", "lnk_modified", "lnk_accessed",
    "created_on", "modified_on", "accessed_on", "last_write_time",
    "first_interacted", "last_interacted",
    "key_last_write_timestamp", "opened_on", "extension_last_opened",
    "last_opened", "last_closed", "key_last_write_utc",
    "shell_created", "shell_modified", "shell_accessed",
    "event_time_utc", "recentdocs_time_utc", "recentdocs_extension_time_utc",
    "gather_time", "date_created", "date_modified", "date_accessed", "date_imported",
    "mft_created", "mft_modified", "mft_accessed", "mft_record_modified",
    "created_fn", "modified_fn", "accessed_fn", "record_changed_fn",
    "last_run_time_utc", "pf_created", "pf_modified", "pf_accessed", "pf_mft_record_modified",
    "event_time",
    "timestamp_utc",
)


def _add_sdelete_timestamp_events(events: list[dict[str, Any]], source: str, row: dict[str, Any]) -> None:
    for field in SDELETE_TIME_FIELDS:
        value = row.get(field)
        if not value:
            continue
        events.append(
            {
                "source": source,
                "timestamp": value,
                "time_type": field,
                "description": row.get("artifact") or row.get("operation") or row.get("reason") or row.get("status") or row.get("parser"),
                "file_name": row.get("file_name") or row.get("target_name") or row.get("shell_item_name"),
                "path": row.get("file_location") or row.get("absolute_path") or row.get("item_path") or row.get("file_path") or row.get("original_path"),
            }
        )
    if source == "sdelete_prefetch":
        raw_run_times = row.get("last_run_times_utc")
        if raw_run_times:
            try:
                parsed = json.loads(raw_run_times)
            except (TypeError, ValueError):
                parsed = []
            if isinstance(parsed, list):
                for run_time in parsed:
                    if not run_time:
                        continue
                    events.append(
                        {
                            "source": source,
                            "timestamp": str(run_time),
                            "time_type": "prefetch_run_time",
                            "description": row.get("executable_name") or row.get("prefetch_name"),
                            "file_name": row.get("prefetch_name"),
                            "path": row.get("original_path") or row.get("artifact_path"),
                        }
                    )


def _rows_as_dicts(rows: list[Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _join_windows_path(parent: str | None, name: str | None) -> str:
    if not parent:
        return name or ""
    if not name:
        return parent
    return parent.rstrip("\\/") + "\\" + name


def _windows_basename(path: str | None) -> str:
    if not path:
        return ""
    return path.rstrip("\\/").replace("/", "\\").rsplit("\\", 1)[-1]


def _windows_parent(path: str | None) -> str:
    if not path:
        return ""
    normalized = path.rstrip("\\/").replace("/", "\\")
    if "\\" not in normalized:
        return ""
    return normalized.rsplit("\\", 1)[0]


def _sdelete_odl_correlations(
    db: Database,
    *,
    case_id: str,
    image_id: str,
    file_name: str | None,
    first_timestamp: str | None,
    last_timestamp: str | None,
) -> list[dict[str, Any]]:
    if not file_name:
        return []
    rows = db.conn.execute(
        """
        SELECT timestamp_utc, user_profile, account, event_type, resource_id,
               code_file, function, source_name, params_text, local_path, url
        FROM onedrive_log_entries
        WHERE case_id = ? AND image_id = ?
          AND (
            params_text LIKE ?
            OR local_path LIKE ?
          )
        ORDER BY timestamp_utc
        LIMIT 10000
        """,
        (case_id, image_id, f"%{file_name}%", f"%{file_name}%"),
    ).fetchall()
    start = _parse_report_timestamp(first_timestamp)
    end = _parse_report_timestamp(last_timestamp)
    items = []
    for row in rows:
        timestamp = _parse_report_timestamp(row["timestamp_utc"])
        if start and timestamp and (timestamp - start).total_seconds() < -5:
            continue
        if end and timestamp and (timestamp - end).total_seconds() > 10:
            continue
        item = dict(row)
        item["basis"] = "original filename observed by OneDrive near USN wipe time"
        items.append(item)
        if len(items) >= 25:
            break
    return items


def _parse_report_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    candidates = [
        text.replace("Z", "+00:00"),
        text.replace(" ", "T", 1).replace("Z", "+00:00"),
    ]
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            continue
    return None


def usn_bursts_report(db: Database, case_id: str, *, minutes: int = 5, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    seconds = max(minutes, 1) * 60
    rows = db.conn.execute(
        """
        SELECT datetime(strftime('%s', update_timestamp) / ? * ?, 'unixepoch') AS bucket_start,
               reason,
               full_path,
               COUNT(*) AS count,
               COUNT(DISTINCT file_name) AS distinct_files
        FROM usn_journal_entries
        WHERE case_id = ? AND update_timestamp IS NOT NULL
        GROUP BY bucket_start, reason, full_path
        HAVING count >= 10
        ORDER BY count DESC, bucket_start DESC
        LIMIT ?
        """,
        (seconds, seconds, case_id, limit),
    ).fetchall()
    return {
        "case_id": case_id,
        "bucket_minutes": minutes,
        "bursts": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def usn_usb_candidates_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    correlations = db.conn.execute(
        """
        SELECT *
        FROM usb_file_correlations
        WHERE case_id = ?
          AND COALESCE(file_name, '') != ''
        ORDER BY confidence DESC, created_at DESC
        LIMIT ?
        """,
        (case_id, max(limit * 20, 1000)),
    ).fetchall()
    items = []
    seen: set[tuple[str, str, str, str]] = set()
    for correlation in correlations:
        rows = db.conn.execute(
            """
            SELECT usn_journal_entries.*, computers.label AS computer_label, images.path AS image_path
            FROM usn_journal_entries
            LEFT JOIN computers ON usn_journal_entries.computer_id = computers.id
            LEFT JOIN images ON usn_journal_entries.image_id = images.id
            WHERE usn_journal_entries.case_id = ?
              AND usn_journal_entries.image_id = ?
              AND LOWER(usn_journal_entries.file_name) = LOWER(?)
            ORDER BY usn_journal_entries.update_timestamp DESC, usn_journal_entries.update_sequence_number DESC
            LIMIT 5
            """,
            (case_id, correlation["image_id"], correlation["file_name"]),
        ).fetchall()
        for row in rows:
            key = (
                str(row["image_id"]),
                str(row["update_sequence_number"]),
                str(row["file_reference_number"]),
                str(correlation["usb_serial"]),
                str(correlation["usb_volume_serial_number"]),
                str(correlation["source_artifact_type"]),
            )
            if key in seen:
                continue
            seen.add(key)
            item = _compact_usn_row(row)
            item["usb"] = {
                "serial": correlation["usb_serial"],
                "volume_serial_number": correlation["usb_volume_serial_number"],
                "volume_name": correlation["usb_volume_name"],
                "drive_letter": correlation["usb_drive_letter"],
                "confidence": correlation["confidence"],
                "source_artifact_type": correlation["source_artifact_type"],
            }
            item["classification"] = "usb_adjacent_candidate"
            item["language"] = "Matched existing USB file correlation data; review source artifacts before concluding transfer."
            items.append(item)
            if len(items) >= limit:
                return {"case_id": case_id, "items": items, "total_returned": len(items)}
    return {"case_id": case_id, "items": items, "total_returned": len(items)}


def ntfs_index_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "ntfs_index_entries", "ntfs_index_entries", limit)


def ntfs_logfile_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "ntfs_logfile_entries", "ntfs_logfile_entries", limit)


def ntfs_namespace_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    status_rows = db.conn.execute(
        """
        SELECT index_status, legit_active_file, header_type, zero_prefix, COUNT(*) AS count
        FROM ntfs_namespace_reconciliation
        WHERE case_id = ?
        GROUP BY index_status, legit_active_file, header_type, zero_prefix
        ORDER BY count DESC, index_status
        """,
        (case_id,),
    ).fetchall()
    access_rows = db.conn.execute(
        """
        SELECT parent_access_status, mounted_present, COUNT(*) AS count
        FROM ntfs_namespace_reconciliation
        WHERE case_id = ?
        GROUP BY parent_access_status, mounted_present
        ORDER BY count DESC, parent_access_status
        """,
        (case_id,),
    ).fetchall()
    rows = db.conn.execute(
        """
        SELECT ntfs_namespace_reconciliation.*, computers.label AS computer_label, images.path AS image_path
        FROM ntfs_namespace_reconciliation
        LEFT JOIN computers ON ntfs_namespace_reconciliation.computer_id = computers.id
        LEFT JOIN images ON ntfs_namespace_reconciliation.image_id = images.id
        WHERE ntfs_namespace_reconciliation.case_id = ?
        ORDER BY ntfs_namespace_reconciliation.original_path
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {
        "case_id": case_id,
        "summary": {
            "status_counts": [dict(row) for row in status_rows],
            "mount_access_counts": [dict(row) for row in access_rows],
        },
        "ntfs_namespace_reconciliation": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def filesystem_review_report(
    db: Database,
    case_id: str,
    *,
    contains: str | None = None,
    event_type: str | None = None,
    status: str | None = None,
    source_table: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["filesystem_review.case_id = ?", _artifact_duplicate_condition("filesystem_review")]
    params: list[Any] = [case_id]
    if contains:
        where.append(
            "(filesystem_review.file_path LIKE ? OR filesystem_review.file_name LIKE ? OR filesystem_review.reason LIKE ?)"
        )
        params.extend([f"%{contains}%", f"%{contains}%", f"%{contains}%"])
    if event_type:
        where.append("filesystem_review.event_type = ?")
        params.append(event_type)
    if status:
        where.append("filesystem_review.status = ?")
        params.append(status)
    if source_table:
        where.append("filesystem_review.source_table = ?")
        params.append(source_table)
    clause = " AND ".join(where)
    total = db.conn.execute(
        f"SELECT COUNT(*) AS count FROM filesystem_review WHERE {clause}",
        params,
    ).fetchone()["count"]
    source_counts = db.conn.execute(
        f"""
        SELECT source_table, event_type, status, COUNT(*) AS count
        FROM filesystem_review
        WHERE {clause}
        GROUP BY source_table, event_type, status
        ORDER BY count DESC, source_table, event_type
        LIMIT 50
        """,
        params,
    ).fetchall()
    rows = db.conn.execute(
        f"""
        SELECT filesystem_review.*, computers.label AS computer_label, images.path AS image_path,
               {_artifact_source_count_sql("filesystem_review")} AS source_count
        FROM filesystem_review
        LEFT JOIN computers ON filesystem_review.computer_id = computers.id
        LEFT JOIN images ON filesystem_review.image_id = images.id
        WHERE {clause}
        ORDER BY COALESCE(filesystem_review.event_time, '') DESC,
                 filesystem_review.file_path,
                 filesystem_review.source_table
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["details"] = _json_details(item.pop("details_json", None))
        items.append(item)
    return {
        "case_id": case_id,
        "total_matching_rows": total,
        "summary": {"source_event_status_counts": [dict(row) for row in source_counts]},
        "filesystem_review": items,
        "total_returned": len(items),
    }


def user_file_references_report(
    db: Database,
    case_id: str,
    *,
    provider: str | None = None,
    scope: str | None = None,
    user: str | None = None,
    contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["user_controlled_file_references.case_id = ?"]
    params: list[Any] = [case_id]
    if provider:
        where.append("LOWER(user_controlled_file_references.storage_provider) = LOWER(?)")
        params.append(provider)
    if scope:
        where.append("LOWER(user_controlled_file_references.path_scope) = LOWER(?)")
        params.append(scope)
    if user:
        where.append("LOWER(user_controlled_file_references.owning_user) = LOWER(?)")
        params.append(user)
    if contains:
        where.append(
            "(user_controlled_file_references.normalized_path LIKE ? OR "
            "user_controlled_file_references.display_path LIKE ? OR "
            "user_controlled_file_references.resolved_provider_path LIKE ? OR "
            "user_controlled_file_references.resolved_file_name LIKE ? OR "
            "user_controlled_file_references.artifact_meaning LIKE ? OR "
            "user_controlled_file_references.context LIKE ?)"
        )
        params.extend([f"%{contains}%"] * 6)
    clause = " AND ".join(where)
    total = db.conn.execute(
        f"SELECT COUNT(*) AS count FROM user_controlled_file_references WHERE {clause}",
        params,
    ).fetchone()["count"]
    scope_rows = db.conn.execute(
        f"""
        SELECT path_scope, storage_provider, artifact_meaning, COUNT(*) AS count
        FROM user_controlled_file_references
        WHERE {clause}
        GROUP BY path_scope, storage_provider, artifact_meaning
        ORDER BY count DESC, storage_provider, path_scope
        """,
        params,
    ).fetchall()
    user_rows = db.conn.execute(
        f"""
        SELECT owning_user, storage_provider, COUNT(*) AS count
        FROM user_controlled_file_references
        WHERE {clause}
        GROUP BY owning_user, storage_provider
        ORDER BY count DESC, owning_user
        LIMIT 50
        """,
        params,
    ).fetchall()
    rows = db.conn.execute(
        f"""
        SELECT user_controlled_file_references.*, computers.label AS computer_label, images.path AS image_path
        FROM user_controlled_file_references
        LEFT JOIN computers ON user_controlled_file_references.computer_id = computers.id
        LEFT JOIN images ON user_controlled_file_references.image_id = images.id
        WHERE {clause}
        ORDER BY COALESCE(user_controlled_file_references.event_time_utc, '') DESC,
                 user_controlled_file_references.normalized_path
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["details"] = _json_details(item.pop("details_json", None))
        items.append(item)
    return {
        "case_id": case_id,
        "total_matching_rows": total,
        "summary": {
            "scope_provider_counts": [dict(row) for row in scope_rows],
            "user_provider_counts": [dict(row) for row in user_rows],
        },
        "user_file_references": items,
        "total_returned": len(items),
    }


def user_file_reference_source_report(
    db: Database,
    case_id: str,
    *,
    reference_id: str,
) -> dict[str, Any]:
    db.get_case(case_id)
    ref_row = db.conn.execute(
        """
        SELECT *
        FROM user_controlled_file_references
        WHERE case_id = ? AND id = ?
        """,
        (case_id, reference_id),
    ).fetchone()
    if ref_row is None:
        raise KeyError(f"User-controlled file reference not found: {reference_id}")
    reference = dict(ref_row)
    reference["details"] = _json_details(reference.pop("details_json", None))
    source_table = reference["source_table"]
    if source_table not in {"windows_defender_events", "windows_error_reports", "etl_events"}:
        raise KeyError(f"Unsupported source table for user file reference: {source_table}")
    source_row = db.conn.execute(
        f"""
        SELECT *
        FROM {source_table}
        WHERE case_id = ? AND id = ?
        """,
        (case_id, reference["source_row_id"]),
    ).fetchone()
    source = dict(source_row) if source_row is not None else None
    if source:
        for key in ("raw_json", "details_json", "loaded_modules_json", "payload_strings_json"):
            if key in source:
                source[f"{key}_decoded"] = _json_details(source.get(key))
    return {
        "case_id": case_id,
        "reference": reference,
        "source": source,
        "source_found": source is not None,
    }


def srum_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    report = _table_report(db, case_id, "srum_records", "srum_records", limit)
    counts = db.conn.execute(
        """
        SELECT record_type, provider_guid, provider_name, COUNT(*) AS count
        FROM srum_records
        WHERE case_id = ?
        GROUP BY record_type, provider_guid, provider_name
        ORDER BY count DESC, record_type
        """,
        (case_id,),
    ).fetchall()
    report["summary"] = {"provider_counts": [dict(row) for row in counts]}
    return report


def ual_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    timeline_sql = """
        SELECT *
        FROM (
          SELECT id AS source_record_id, case_id, computer_id, image_id, tool_name,
                 source_csv, row_number, database_file, source_table, role_name,
                 product_name, user_sid, user_name, client_name, client_ip,
                 access_count, activity_count, first_seen AS event_time_utc,
                 'ual_first_seen' AS event_type
          FROM ual_records
          WHERE case_id = ? AND COALESCE(first_seen, '') != ''
          UNION ALL
          SELECT id AS source_record_id, case_id, computer_id, image_id, tool_name,
                 source_csv, row_number, database_file, source_table, role_name,
                 product_name, user_sid, user_name, client_name, client_ip,
                 access_count, activity_count, last_seen AS event_time_utc,
                 'ual_last_seen' AS event_type
          FROM ual_records
          WHERE case_id = ? AND COALESCE(last_seen, '') != ''
          UNION ALL
          SELECT id AS source_record_id, case_id, computer_id, image_id, tool_name,
                 source_csv, row_number, database_file, source_table, role_name,
                 product_name, user_sid, user_name, client_name, client_ip,
                 access_count, activity_count, last_access AS event_time_utc,
                 'ual_last_access' AS event_type
          FROM ual_records
          WHERE case_id = ? AND COALESCE(last_access, '') != ''
          UNION ALL
          SELECT id AS source_record_id, case_id, computer_id, image_id, tool_name,
                 source_csv, row_number, database_file, source_table, role_name,
                 product_name, user_sid, user_name, client_name, client_ip,
                 access_count, activity_count, insert_date AS event_time_utc,
                 'ual_insert_date' AS event_type
          FROM ual_records
          WHERE case_id = ? AND COALESCE(insert_date, '') != ''
        )
        ORDER BY event_time_utc, event_type, role_name, client_name, user_name
        LIMIT ?
    """
    timeline = _query_report_rows(db, case_id, "ual_records", timeline_sql, [case_id, case_id, case_id, case_id, limit])
    records_sql = """
        SELECT *
        FROM ual_records
        WHERE case_id = ?
        ORDER BY COALESCE(first_seen, insert_date, last_seen, last_access, ''),
                 role_name, client_name, user_name, row_number
        LIMIT ?
    """
    records = _query_report_rows(db, case_id, "ual_records", records_sql, [case_id, limit])
    summary_sql = """
        SELECT COALESCE(NULLIF(role_name, ''), '(unknown)') AS role_name,
               COALESCE(NULLIF(client_name, ''), NULLIF(client_ip, ''), NULLIF(client_id, ''), '(unknown)') AS client,
               COALESCE(NULLIF(user_name, ''), NULLIF(user_sid, ''), '(unknown)') AS user,
               MIN(COALESCE(NULLIF(first_seen, ''), NULLIF(insert_date, ''), NULLIF(last_seen, ''), NULLIF(last_access, ''))) AS first_logged_utc,
               MAX(COALESCE(NULLIF(last_seen, ''), NULLIF(last_access, ''), NULLIF(first_seen, ''), NULLIF(insert_date, ''))) AS last_logged_utc,
               COUNT(*) AS record_count,
               SUM(CAST(COALESCE(NULLIF(access_count, ''), '0') AS BIGINT)) AS total_access_count
        FROM ual_records
        WHERE case_id = ?
        GROUP BY role_name, client, user
        ORDER BY first_logged_utc, role_name, client, user
        LIMIT ?
    """
    grouped = _query_report_rows(db, case_id, "ual_records", summary_sql, [case_id, limit])
    return {
        "case_id": case_id,
        "summary": {
            "timeline_events": len(timeline),
            "access_records_returned": len(records),
            "grouped_access_returned": len(grouped),
            "caveats": [
                "UAL/SUM records are usually aggregated by role/client/user and are not precise per-access event logs.",
                "Use first/last timestamps and counts as server-role access context; corroborate with EVTX, SMB, RDP, firewall, and authentication logs.",
            ],
        },
        "timeline": timeline,
        "access_records": records,
        "grouped_access": grouped,
        "total_returned": len(timeline),
    }


def srum_networks_report(db: Database, case_id: str, *, include_zero: bool = False, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["case_id = ?", "record_type = 'network_connectivity'"]
    params: list[Any] = [case_id]
    if not include_zero:
        filters.append("CAST(COALESCE(NULLIF(connected_time, ''), '0') AS INTEGER) > 0")
    rows = db.conn.execute(
        f"""
        SELECT
          CASE
            WHEN interface_type = '23'
              THEN COALESCE(NULLIF(vpn_profile_name, ''), NULLIF(l2_profile_name, ''), '(unknown)')
            ELSE COALESCE(NULLIF(l2_profile_name, ''), '(unknown)')
          END AS network_name,
          CASE interface_type
            WHEN '23' THEN 'PPP/VPN'
            WHEN '71' THEN 'Wi-Fi'
            WHEN '6' THEN 'Ethernet'
            ELSE COALESCE(NULLIF(interface_type, ''), '(unknown)')
          END AS connection_type,
          vpn_server,
          vpn_device,
          vpn_protocol,
          vpn_phonebook_path,
          vpn_match_method,
          interface_type,
          l2_profile_id,
          interface_luid,
          MIN(connect_start_time) AS first_connected_utc,
          MAX(timestamp) AS last_observed_utc,
          MAX(CAST(COALESCE(NULLIF(connected_time, ''), '0') AS INTEGER)) AS max_connected_seconds,
          COUNT(*) AS observation_count,
          GROUP_CONCAT(DISTINCT user_name) AS users,
          GROUP_CONCAT(DISTINCT app_name) AS applications,
          MIN(source_csv) AS source_csv
        FROM srum_records
        WHERE {' AND '.join(filters)}
        GROUP BY network_name, connection_type, vpn_server, vpn_device, vpn_protocol,
          vpn_phonebook_path, vpn_match_method, interface_type, l2_profile_id, interface_luid
        ORDER BY first_connected_utc, network_name, connection_type
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    summary = db.conn.execute(
        f"""
        SELECT
          CASE interface_type
            WHEN '23' THEN 'PPP/VPN'
            WHEN '71' THEN 'Wi-Fi'
            WHEN '6' THEN 'Ethernet'
            ELSE COALESCE(NULLIF(interface_type, ''), '(unknown)')
          END AS connection_type,
          COUNT(*) AS observation_count,
          COUNT(DISTINCT CASE
            WHEN interface_type = '23'
              THEN COALESCE(NULLIF(vpn_profile_name, ''), NULLIF(l2_profile_name, ''), '(unknown)')
            ELSE COALESCE(NULLIF(l2_profile_name, ''), '(unknown)')
          END) AS network_count
        FROM srum_records
        WHERE {' AND '.join(filters)}
        GROUP BY connection_type
        ORDER BY observation_count DESC
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "summary": {"connection_type_counts": [dict(row) for row in summary]},
        "networks": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def srum_app_network_usage_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT
          COALESCE(NULLIF(app_name, ''), NULLIF(app_path, ''), '(unknown)') AS application,
          app_path,
          app_description,
          user_name,
          user_sid,
          COALESCE(NULLIF(l2_profile_name, ''), '(unknown)') AS network_name,
          SUM(CAST(COALESCE(NULLIF(bytes_received, ''), '0') AS INTEGER)) AS total_bytes_received,
          SUM(CAST(COALESCE(NULLIF(bytes_sent, ''), '0') AS INTEGER)) AS total_bytes_sent,
          SUM(CAST(COALESCE(NULLIF(bytes_received, ''), '0') AS INTEGER))
            + SUM(CAST(COALESCE(NULLIF(bytes_sent, ''), '0') AS INTEGER)) AS total_bytes,
          MIN(timestamp) AS first_observed_utc,
          MAX(timestamp) AS last_observed_utc,
          COUNT(*) AS observation_count
        FROM srum_records
        WHERE case_id = ?
          AND record_type = 'network_usage'
        GROUP BY application, app_path, app_description, user_name, user_sid, network_name
        HAVING total_bytes > 0
        ORDER BY total_bytes DESC, application
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    totals = db.conn.execute(
        """
        SELECT
          SUM(CAST(COALESCE(NULLIF(bytes_received, ''), '0') AS INTEGER)) AS total_bytes_received,
          SUM(CAST(COALESCE(NULLIF(bytes_sent, ''), '0') AS INTEGER)) AS total_bytes_sent,
          COUNT(*) AS observation_count,
          COUNT(DISTINCT COALESCE(NULLIF(app_name, ''), NULLIF(app_path, ''), '(unknown)')) AS application_count
        FROM srum_records
        WHERE case_id = ?
          AND record_type = 'network_usage'
        """,
        (case_id,),
    ).fetchone()
    return {
        "case_id": case_id,
        "summary": dict(totals) if totals else {},
        "applications": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def srum_context_report(db: Database, case_id: str, *, limit: int = 250) -> dict[str, Any]:
    db.get_case(case_id)
    rows = _query_report_rows(
        db,
        case_id,
        "srum_records",
        """
        SELECT
          id,
          computer_id,
          image_id,
          record_type,
          source_table,
          COALESCE(NULLIF(timestamp, ''), NULLIF(connect_start_time, ''), NULLIF(start_time, '')) AS event_time_utc,
          app_name,
          app_path,
          app_description,
          user_name,
          user_sid,
          l2_profile_name,
          interface_type,
          vpn_profile_name,
          vpn_server,
          vpn_protocol,
          bytes_received,
          bytes_sent,
          connected_time,
          source_csv,
          row_number
        FROM srum_records
        WHERE case_id = ?
          AND (
            lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%onedrive%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%dropbox%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%drivefs%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%google drive%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%icloud%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%mstsc%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%remote desktop%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%chrome%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%firefox%'
            OR lower(coalesce(app_name, '') || ' ' || coalesce(app_path, '') || ' ' || coalesce(app_description, '')) LIKE '%msedge%'
            OR interface_type = '23'
            OR lower(coalesce(vpn_profile_name, '') || ' ' || coalesce(vpn_server, '') || ' ' || coalesce(vpn_protocol, '')) LIKE '%vpn%'
          )
        ORDER BY event_time_utc DESC, record_type
        LIMIT ?
        """,
        (case_id, limit),
    )
    for row in rows:
        row["context"] = _srum_context_label(row)
        row["total_bytes"] = _int_or_zero(row.get("bytes_received")) + _int_or_zero(row.get("bytes_sent"))
        row["source_table"] = row.get("source_table") or "srum_records"
    by_context: dict[str, int] = {}
    for row in rows:
        by_context[row["context"]] = by_context.get(row["context"], 0) + 1
    return {
        "case_id": case_id,
        "summary": {
            "context_counts": [
                {"context": key, "count": value}
                for key, value in sorted(by_context.items(), key=lambda item: (-item[1], item[0]))
            ],
            "interpretation_note": "SRUM timestamps and counters are contextual telemetry, not precise process execution times.",
        },
        "items": rows,
        "total_returned": len(rows),
    }


def _srum_context_label(row: dict[str, Any]) -> str:
    text = " ".join(
        str(row.get(key) or "")
        for key in ("app_name", "app_path", "app_description", "vpn_profile_name", "vpn_server", "vpn_protocol")
    ).lower()
    if row.get("interface_type") == "23" or "vpn" in text:
        return "vpn_context"
    if any(token in text for token in ("onedrive", "dropbox", "drivefs", "google drive", "icloud")):
        return "cloud_sync_context"
    if any(token in text for token in ("mstsc", "remote desktop", "terminal services")):
        return "rdp_context"
    if any(token in text for token in ("chrome", "firefox", "msedge", "edge")):
        return "browser_network_context"
    return "srum_context"


def _int_or_zero(value: Any) -> int:
    try:
        return int(str(value or "0"))
    except ValueError:
        return 0


VPN_TEXT_MATCH = """
(
  lower(coalesce({0}, '')) LIKE '%vpn%'
  OR lower(coalesce({0}, '')) LIKE '%rasclient%'
  OR lower(coalesce({0}, '')) LIKE '%rasman%'
  OR lower(coalesce({0}, '')) LIKE '%rasphone%'
  OR lower(coalesce({0}, '')) LIKE '%rasdial%'
  OR lower(coalesce({0}, '')) LIKE '%remoteaccess%'
  OR lower(coalesce({0}, '')) LIKE '%anyconnect%'
  OR lower(coalesce({0}, '')) LIKE '%globalprotect%'
  OR lower(coalesce({0}, '')) LIKE '%forticlient%'
  OR lower(coalesce({0}, '')) LIKE '%openvpn%'
  OR lower(coalesce({0}, '')) LIKE '%wireguard%'
  OR lower(coalesce({0}, '')) LIKE '%tailscale%'
  OR lower(coalesce({0}, '')) LIKE '%zerotier%'
)
"""

RASCLIENT_EVENT_MEANINGS = {
    "20220": ("connect_attempt", "VPN connect attempt"),
    "20221": ("connect_attempt", "VPN connection initiated"),
    "20222": ("connect_attempt", "VPN server contacted"),
    "20223": ("connected", "VPN connection established"),
    "20224": ("connected", "VPN link negotiated"),
    "20225": ("connected", "VPN connection authenticated"),
    "20226": ("disconnected", "VPN connection disconnected"),
    "20227": ("failed", "VPN connection failed"),
    "20228": ("failed", "VPN connection terminated with error"),
    "20268": ("disconnected", "VPN interface disconnected"),
    "20269": ("failed", "VPN reconnect failed"),
    "20270": ("connect_attempt", "VPN reconnect started"),
    "20271": ("connected", "VPN reconnect completed"),
    "20272": ("failed", "VPN authentication failed"),
    "20275": ("failed", "VPN connection blocked or failed"),
}


def _vpn_row(
    *,
    source_type: str,
    activity_type: str,
    event_time_utc: Any = "",
    profile_name: Any = "",
    server: Any = "",
    protocol: Any = "",
    event: Any = "",
    user: Any = "",
    path_or_process: Any = "",
    source_file: Any = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "source_type": source_type,
        "activity_type": activity_type,
        "event_time_utc": event_time_utc or "",
        "profile_name": profile_name or "",
        "server": server or "",
        "protocol": protocol or "",
        "event": event or "",
        "user": user or "",
        "path_or_process": path_or_process or "",
        "source_file": source_file or "",
        "evidence_group": _vpn_evidence_group(profile_name=profile_name, server=server, protocol=protocol),
        "details": details or {},
    }


def vpn_activity_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = _vpn_all_rows(db, case_id, limit)
    return _vpn_report_from_rows(case_id, rows, "vpn_activity", limit)


def vpn_connections_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = [
        row for row in _vpn_all_rows(db, case_id, limit)
        if row["activity_type"] in {"connect_attempt", "connected", "disconnected", "failed", "connection_observation"}
    ]
    return _vpn_report_from_rows(case_id, rows, "vpn_connections", limit)


def vpn_config_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = [row for row in _vpn_all_rows(db, case_id, limit) if row["activity_type"] == "configured"]
    return _vpn_report_from_rows(case_id, rows, "vpn_config", limit)


def vpn_execution_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = [row for row in _vpn_all_rows(db, case_id, limit) if row["activity_type"] == "supporting_execution"]
    return _vpn_report_from_rows(case_id, rows, "vpn_execution", limit)


def vpn_session_evidence_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = _vpn_all_rows(db, case_id, limit)
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        group = row["evidence_group"] or "unknown"
        item = groups.setdefault(
            group,
            {
                "evidence_group": group,
                "profile_name": row["profile_name"],
                "server": row["server"],
                "protocol": row["protocol"],
                "first_observed_utc": row["event_time_utc"],
                "last_observed_utc": row["event_time_utc"],
                "activity_types": set(),
                "source_types": set(),
                "evidence_count": 0,
                "evidence": [],
            },
        )
        if row["event_time_utc"]:
            observed_times = [value for value in (item["first_observed_utc"], row["event_time_utc"]) if value]
            if observed_times:
                item["first_observed_utc"] = min(observed_times)
                item["last_observed_utc"] = max(observed_times)
        item["profile_name"] = item["profile_name"] or row["profile_name"]
        item["server"] = item["server"] or row["server"]
        item["protocol"] = item["protocol"] or row["protocol"]
        item["activity_types"].add(row["activity_type"])
        item["source_types"].add(row["source_type"])
        item["evidence_count"] += 1
        if len(item["evidence"]) < 10:
            item["evidence"].append(row)
    session_rows = []
    for item in groups.values():
        item["activity_types"] = ",".join(sorted(item["activity_types"]))
        item["source_types"] = ",".join(sorted(item["source_types"]))
        session_rows.append(item)
    session_rows.sort(key=lambda row: (row.get("first_observed_utc") or "", row.get("evidence_group") or ""))
    return {
        "case_id": case_id,
        "summary": {"group_count": len(session_rows), "total_evidence_rows": len(rows)},
        "vpn_sessions": session_rows[:limit],
        "total_returned": min(len(session_rows), limit),
    }


def vpn_local_activity_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 500,
    padding_minutes: int = 0,
) -> dict[str, Any]:
    db.get_case(case_id)
    vpn_rows = _vpn_all_rows(db, case_id, max(limit * 10, 1000))
    windows = _vpn_activity_windows(vpn_rows, padding_minutes=padding_minutes)
    activity_rows = _local_activity_rows(db, case_id, limit=max(limit * 20, 2000))
    window_items: list[dict[str, Any]] = []
    all_related: list[dict[str, Any]] = []
    for index, window in enumerate(windows, 1):
        related = [
            row for row in activity_rows
            if _timestamp_in_window(row.get("event_time_utc"), window["window_start_utc"], window["window_end_utc"])
        ]
        related = _dedupe_report_rows(related)
        related.sort(key=lambda row: (row.get("event_time_utc") or "", row.get("source_table") or "", row.get("description") or ""))
        usb_devices = _vpn_window_usb_devices(db, case_id, window, limit=25)
        all_related.extend({**row, "vpn_window_index": index} for row in related)
        window_items.append(
            {
                **window,
                "index": index,
                "activity_count": len(related),
                "external_storage_count": len(usb_devices),
                "external_storage_devices": usb_devices,
                "activity_counts": _activity_category_counts(related),
                "source_counts": _activity_source_counts(related),
                "notable_activity": _rank_vpn_window_activity(related)[:15],
                "activity": related[:limit],
            }
        )
    all_related = all_related[:limit]
    return {
        "case_id": case_id,
        "summary": {
            "vpn_window_count": len(windows),
            "windows_with_activity": sum(1 for item in window_items if item["activity_count"]),
            "total_activity_rows": sum(item["activity_count"] for item in window_items),
            "padding_minutes": padding_minutes,
            "scope": "Local endpoint activity on the analysed system during VPN-connected windows. Remote RDP screen/cache observations are intentionally excluded.",
            "high_volume_note": "This report uses parsed app/file-use artefacts. Raw MFT/USN sweeps are intentionally not dumped into the Markdown report.",
        },
        "vpn_windows": window_items,
        "activity_rows": all_related,
        "total_returned": len(all_related),
    }


def vpn_local_activity_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    windows = report.get("vpn_windows") if isinstance(report.get("vpn_windows"), list) else []
    lines = [
        "# VPN Local Activity Report",
        "",
        f"Case: `{report.get('case_id') or ''}`",
        "",
        "## Summary",
        "",
        f"- VPN windows: `{summary.get('vpn_window_count', 0)}`",
        f"- Windows with local activity: `{summary.get('windows_with_activity', 0)}`",
        f"- Local activity rows: `{summary.get('total_activity_rows', 0)}`",
        f"- Padding minutes: `{summary.get('padding_minutes', 0)}`",
        f"- Scope: {summary.get('scope') or ''}",
        f"- Note: {summary.get('high_volume_note') or ''}",
        "",
    ]
    for window in windows:
        if not isinstance(window, dict):
            continue
        lines.extend(
            [
                f"## VPN Window {window.get('index')}",
                "",
                f"- Window: `{_format_report_window_time(window.get('window_start_utc'))}` to `{_format_report_window_time(window.get('window_end_utc'))}`",
                f"- Profile: `{window.get('profile_name') or ''}`",
                f"- Server: `{window.get('server') or ''}`",
                f"- Protocol: `{window.get('protocol') or ''}`",
                f"- VPN source rows: `{window.get('vpn_evidence_count') or 0}`",
                f"- Local activity rows: `{window.get('activity_count') or 0}`",
                f"- External storage devices active/observed: `{window.get('external_storage_count') or 0}`",
                "",
                "### Activity Counts",
                "",
            ]
        )
        counts = window.get("activity_counts") if isinstance(window.get("activity_counts"), list) else []
        if counts:
            for item in counts:
                if isinstance(item, dict):
                    lines.append(f"- `{item.get('activity_category')}`: `{item.get('count')}`")
        else:
            lines.append("- No local parsed activity rows in this window.")
        lines.extend(["", "### External Storage During VPN Window", ""])
        usb_devices = window.get("external_storage_devices") if isinstance(window.get("external_storage_devices"), list) else []
        if not usb_devices:
            lines.append("- No parsed external storage device rows overlapped this VPN window.")
        for item in usb_devices:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `{item.get('session_start') or ''}` to `{item.get('session_end') or ''}` "
                f"serial `{item.get('serial') or ''}` volume `{item.get('volume_serial_number') or ''}` "
                f"drive `{item.get('drive_letter') or ''}` product `{item.get('product') or ''}` "
                f"source `{item.get('event_source') or ''}`"
            )
        lines.extend(["", "### Notable Local Activity", ""])
        notable = window.get("notable_activity") if isinstance(window.get("notable_activity"), list) else []
        if not notable:
            lines.append("- No notable local activity rows selected for this window.")
        for row in notable:
            if not isinstance(row, dict):
                continue
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            detail_bits = [
                f"{key}={details.get(key)}"
                for key in ("artifact", "key_path", "value_name", "record_type", "user_profile", "run_count", "prefetch_name")
                if details.get(key) not in (None, "")
            ]
            suffix = f" ({', '.join(detail_bits)})" if detail_bits else ""
            lines.append(
                f"- `{row.get('event_time_utc') or ''}` `{row.get('activity_category') or ''}` "
                f"`{row.get('source_table') or ''}` {row.get('description') or ''} "
                f"path `{_display_evidence_path(row.get('path'))}` source `{_display_evidence_path(row.get('source_file'))}`{suffix}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _format_report_window_time(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    return str(value or "")


def remote_access_sessions_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rdp_sessions = _rdp_client_sessions(db, case_id)
    vpn_rows = _vpn_all_rows(db, case_id, max(limit * 20, 500))
    cache_rows = _rdp_cache_file_rows(db, case_id)
    empty_cache_paths = {
        str(row.get("source_cache_path") or "")
        for row in cache_rows
        if row.get("is_empty_cache_file") and row.get("source_cache_path")
    }
    visual_rows = _rdp_visual_observation_rows(db, case_id)
    visual_rows = [
        row for row in visual_rows
        if str(row.get("source_cache_path") or "") not in empty_cache_paths
    ]
    shortcut_rows = _rdp_shortcut_rows(db, case_id)
    session_rows: list[dict[str, Any]] = []
    session_vpn_context_rows: list[dict[str, Any]] = []
    for session in rdp_sessions:
        start = _parse_report_timestamp(session.get("start_time_utc"))
        end = _parse_report_timestamp(session.get("end_time_utc")) or start
        vpn_window_start = start - timedelta(minutes=10) if start else None
        vpn_window_end = end + timedelta(minutes=10) if end else None
        cache_window_start = start - timedelta(minutes=2) if start else None
        cache_window_end = end + timedelta(minutes=2) if end else None
        related_vpn = [
            row for row in vpn_rows
            if _timestamp_in_window(row.get("event_time_utc"), vpn_window_start, vpn_window_end)
        ]
        related_vpn = _dedupe_report_rows(related_vpn)
        related_vpn.sort(key=lambda row: (row.get("event_time_utc") or "", row.get("source_type") or ""))
        session_vpn_context_rows.extend(related_vpn)
        related_cache = [
            row for row in cache_rows
            if not row.get("is_empty_cache_file")
            and _timestamp_in_window(row.get("modified_utc"), cache_window_start, cache_window_end)
        ]
        related_shortcuts = [
            row for row in shortcut_rows
            if _timestamp_in_window(row.get("event_time_utc"), vpn_window_start, vpn_window_end)
        ]
        related_shortcuts = _dedupe_report_rows(related_shortcuts)
        related_shortcuts.sort(key=lambda row: (row.get("event_time_utc") or "", row.get("artifact_type") or ""))
        related_cache_paths = {str(row.get("source_cache_path") or "") for row in related_cache if row.get("source_cache_path")}
        related_visual = [
            row for row in visual_rows
            if (
                row.get("source_cache_path") in related_cache_paths
                or _timestamp_in_window(row.get("observation_time_utc"), cache_window_start, cache_window_end)
            )
        ]
        basis = ["rdp_client_event_sequence"]
        if related_vpn:
            basis.append("vpn_activity_time_overlap")
        if related_cache:
            basis.append("rdp_bitmap_cache_time_overlap")
        if related_shortcuts:
            basis.append("rdp_shortcut_or_jumplist_time_overlap")
        if related_visual:
            basis.append("rdp_visual_observation")
        if session.get("remote_host") and session.get("remote_ip"):
            basis.append("rdp_destination_host_and_ip")
        session_rows.append(
            {
                **session,
                "correlation_basis": ",".join(basis),
                "vpn_event_count": len(related_vpn),
                "vpn_sources": ",".join(sorted({str(row.get("source_type") or "") for row in related_vpn if row.get("source_type")})),
                "vpn_profiles": ",".join(sorted({str(row.get("profile_name") or "") for row in related_vpn if row.get("profile_name")})),
                "vpn_servers": ",".join(sorted({str(row.get("server") or "") for row in related_vpn if row.get("server")})),
                "rdp_cache_file_count": len(related_cache),
                "rdp_cache_files": related_cache[:10],
                "rdp_shortcut_file_count": len(related_shortcuts),
                "rdp_shortcut_files": related_shortcuts[:20],
                "rdp_visual_observation_count": len(related_visual),
                "rdp_visual_observations": related_visual[:20],
                "vpn_evidence": related_vpn[:50],
            }
        )
    vpn_context_rows = _dedupe_report_rows(session_vpn_context_rows)
    vpn_context_rows.sort(key=lambda row: (row.get("event_time_utc") or "", row.get("source_type") or ""))
    return {
        "case_id": case_id,
        "summary": {
            "rdp_session_count": len(rdp_sessions),
            "sessions_with_vpn_overlap": sum(1 for row in session_rows if row["vpn_event_count"]),
            "sessions_with_cache_overlap": sum(1 for row in session_rows if row["rdp_cache_file_count"]),
            "sessions_with_shortcut_overlap": sum(1 for row in session_rows if row["rdp_shortcut_file_count"]),
            "sessions_with_visual_observations": sum(1 for row in session_rows if row["rdp_visual_observation_count"]),
            "vpn_context_source_counts": _vpn_source_counts(vpn_context_rows),
            "vpn_context_profile_count": len(_vpn_context_groups(vpn_context_rows)),
        },
        "vpn_context": _vpn_context_groups(vpn_context_rows),
        "vpn_context_rows": vpn_context_rows[:50],
        "remote_access_sessions": session_rows[:limit],
        "total_returned": min(len(session_rows), limit),
    }


def rdp_remote_access_markdown(report: dict[str, Any]) -> str:
    case_id = report.get("case_id", "")
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    sessions = report.get("remote_access_sessions") if isinstance(report.get("remote_access_sessions"), list) else []
    lines = [
        "# RDP Remote Access Report",
        "",
        f"Case: `{case_id}`",
        "",
        "## Summary",
        "",
        f"- RDP sessions: {summary.get('rdp_session_count', 0)}",
        f"- Sessions with VPN overlap: {summary.get('sessions_with_vpn_overlap', 0)}",
        f"- Sessions with RDP bitmap-cache overlap: {summary.get('sessions_with_cache_overlap', 0)}",
        f"- Sessions with RDP shortcut/Jump List overlap: {summary.get('sessions_with_shortcut_overlap', 0)}",
        f"- Sessions with visual observations: {summary.get('sessions_with_visual_observations', 0)}",
        "",
        "## Evidence Model",
        "",
        "- RDP connection/session data comes from `evtx_events` entries for provider `Microsoft-Windows-TerminalServices-ClientActiveXCore` in channel `Microsoft-Windows-TerminalServices-RDPClient/Operational`.",
        "- VPN/network overlap comes from normalized rows whose timestamps fall inside each RDP session window, including RAS/VPN EVTX, SRUM VPN connectivity, and relevant Software hive NetworkList observations when present.",
        "- RDP shortcut and Jump List context comes from `shortcut_items` rows for `mstsc.exe`, `.rdp` files, Remote Desktop AppIDs/descriptions, or RDP-related source artefacts whose timestamps fall inside the session window.",
        "- RDP bitmap-cache interpretation comes from `rdp_cache_items`, produced by `RdpCacheParser` from files under `Users/*/AppData/Local/Microsoft/Terminal Server Client/Cache`.",
        "- Visual observations come from `rdp_visual_observations`; rows are labeled as contact-sheet references, OCR text extraction, or semantic visual interpretation.",
        "- Contact sheets and extracted bitmap fragments remain on disk; DuckDB stores parsed metadata, bounded observations, hashes, caveats, and source references.",
        "",
    ]
    lines.extend(_vpn_context_markdown(report))
    for index, session in enumerate(sessions, 1):
        lines.extend(_rdp_session_markdown(index, session if isinstance(session, dict) else {}))
    return "\n".join(lines).rstrip() + "\n"


def _vpn_context_markdown(report: dict[str, Any]) -> list[str]:
    context = report.get("vpn_context") if isinstance(report.get("vpn_context"), list) else []
    rows = report.get("vpn_context_rows") if isinstance(report.get("vpn_context_rows"), list) else []
    lines = ["## VPN Context and Enrichment", ""]
    if not context:
        lines.extend(
            [
                "- No additional VPN context rows were available beyond the per-session overlap evidence.",
                "- This usually means no parsed SRUM VPN connectivity rows or RAS phonebook/profile rows are currently present in DuckDB for this case.",
                "",
            ]
        )
        return lines
    lines.append("- The following VPN/network context is limited to rows inside the reported RDP session windows.")
    for group in context:
        if not isinstance(group, dict):
            continue
        lines.append(
            f"- Profile `{group.get('profile_name') or ''}` server `{group.get('server') or ''}` protocol `{group.get('protocol') or ''}`: "
            f"sources `{group.get('source_types') or ''}`, activity `{group.get('activity_types') or ''}`, "
            f"first `{group.get('first_observed_utc') or ''}`, last `{group.get('last_observed_utc') or ''}`, rows `{group.get('evidence_count') or 0}`"
        )
        for evidence in (group.get("evidence") or [])[:5]:
            if not isinstance(evidence, dict):
                continue
            details = evidence.get("details") if isinstance(evidence.get("details"), dict) else {}
            detail_bits = [
                f"{key}={details.get(key)}"
                for key in ("phonebook", "match_method", "interface_type", "connected_seconds", "key_path", "value_name", "run_count", "artifact_type", "app_id_description")
                if details.get(key) not in (None, "")
            ]
            suffix = f" ({', '.join(detail_bits)})" if detail_bits else ""
            lines.append(
                f"  - `{evidence.get('event_time_utc')}` `{evidence.get('source_type')}` `{evidence.get('activity_type')}` "
                f"source `{_short_case_path(evidence.get('source_file'))}`{suffix}"
            )
    row_source_types = {str(row.get("source_type") or "") for row in rows if isinstance(row, dict)}
    if "srum_network_connectivity" not in row_source_types:
        lines.append("- SRUM VPN connectivity rows are not currently present in this report output.")
    if not any(source.startswith("registry_ras_phonebook") for source in row_source_types):
        lines.append(
            "- RAS phonebook registry rows are not currently present in this report output; "
            "PBK file enrichment may still be present through SRUM phonebook parsing."
        )
    lines.append("")
    return lines


def _rdp_session_markdown(index: int, session: dict[str, Any]) -> list[str]:
    lines = [
        f"## Session {index}",
        "",
        f"- Start: `{session.get('start_time_utc') or ''}`",
        f"- Connected: `{session.get('connected_time_utc') or ''}`",
        f"- End: `{session.get('end_time_utc') or ''}`",
        f"- Client computer: `{session.get('client_computer') or ''}`",
        f"- User: `{session.get('user') or ''}`",
        f"- Remote host: `{session.get('remote_host') or ''}`",
        f"- Remote IP: `{session.get('remote_ip') or ''}`",
        f"- Domain: `{session.get('domain') or ''}`",
        f"- Disconnect reason: `{session.get('disconnect_reason') or ''}`",
        f"- Correlation basis: `{session.get('correlation_basis') or ''}`",
        "",
        "### RDP Event Log Evidence",
        "",
        "- Source table: `evtx_events`",
        f"- Source EVTX: `{_short_case_path(session.get('source_file'))}`",
        f"- Event sequence: `{_rdp_event_sequence(session.get('events') if isinstance(session.get('events'), list) else [])}`",
    ]
    for event in session.get("events") or []:
        if not isinstance(event, dict):
            continue
        lines.append(
            f"- Event `{event.get('event_id')}` at `{event.get('time_created')}`: "
            f"{event.get('description') or ''}; payload `{event.get('payload_data1') or ''}`"
        )
    lines.extend(["", "### VPN Overlap Evidence", ""])
    vpn_rows = [row for row in (session.get("vpn_evidence") or []) if isinstance(row, dict)]
    if not vpn_rows:
        lines.append("- No VPN overlap rows in the report window.")
    else:
        lines.append(f"- Rows in overlap window: `{len(vpn_rows)}`")
        source_counts: dict[str, int] = {}
        for row in vpn_rows:
            source = str(row.get("source_type") or "<none>")
            source_counts[source] = source_counts.get(source, 0) + 1
        for source, count in sorted(source_counts.items()):
            lines.append(f"- Source `{source}` rows: `{count}`")
        for row in vpn_rows[:10]:
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            detail_bits = [
                f"{key}={details.get(key)}"
                for key in ("provider", "channel", "event_id", "interface_type", "connected_seconds", "match_method")
                if details.get(key) not in (None, "")
            ]
            suffix = f" ({', '.join(detail_bits)})" if detail_bits else ""
            lines.append(
                f"- `{row.get('event_time_utc')}` `{row.get('activity_type')}` profile `{row.get('profile_name')}` "
                f"server `{row.get('server')}` source `{row.get('source_type')}` "
                f"path/process `{row.get('path_or_process') or ''}` file `{_short_case_path(row.get('source_file'))}`{suffix}"
            )
    lines.extend(["", "### RDP Bitmap Cache Evidence", ""])
    cache_rows = [row for row in (session.get("rdp_cache_files") or []) if isinstance(row, dict)]
    if not cache_rows:
        lines.append("- No RDP bitmap-cache files correlated to this session window.")
    else:
        lines.append(f"- Cache files in overlap window: `{len(cache_rows)}`")
        for row in cache_rows:
            lines.append(
                f"- `{row.get('modified_utc')}` `{row.get('file_name')}` size `{row.get('file_size')}` "
                f"status `{row.get('parser_status')}` source `{_short_case_path(row.get('source_cache_path'))}`"
            )
            if row.get("is_empty_cache_file"):
                lines.append("  - Empty cache file; no visual context should be attributed to this file.")
    lines.extend(["", "### RDP Shortcut and Jump List Evidence", ""])
    shortcut_rows = [row for row in (session.get("rdp_shortcut_files") or []) if isinstance(row, dict)]
    if not shortcut_rows:
        lines.append("- No RDP shortcut or Jump List rows correlated to this session window.")
    else:
        lines.append(f"- Rows in overlap window: `{len(shortcut_rows)}`")
        for row in shortcut_rows:
            detail_bits = [
                f"{key}={row.get(key)}"
                for key in ("app_id", "app_id_description", "jumplist_item_number", "command_line_arguments", "working_directory")
                if row.get(key) not in (None, "")
            ]
            suffix = f" ({', '.join(detail_bits)})" if detail_bits else ""
            lines.append(
                f"- `{row.get('event_time_utc')}` `{row.get('artifact_type')}` file `{row.get('file_location') or row.get('file_name')}` "
                f"source `{_short_case_path(row.get('source_csv'))}` row `{row.get('row_number')}`{suffix}"
            )
    lines.extend(["", "### Visual Observations", ""])
    visual_rows = [row for row in (session.get("rdp_visual_observations") or []) if isinstance(row, dict)]
    if not visual_rows:
        lines.append("- No visual observations correlated to this session window.")
    else:
        semantic_rows = [row for row in visual_rows if row.get("interpretation_level") == "semantic"]
        if semantic_rows:
            lines.append("- Semantic visual interpretations:")
            for row in semantic_rows:
                lines.append(
                    f"  - `{row.get('contact_sheet_path')}`: applications `{row.get('observed_application')}`; "
                    f"text `{row.get('observed_text')}`; certainty `{row.get('certainty')}`; caveat `{row.get('caveat')}`"
                )
        ocr_rows = [row for row in visual_rows if row.get("interpretation_level") == "ocr"]
        if ocr_rows:
            lines.append("- OCR-only observations:")
            for row in ocr_rows[:10]:
                lines.append(
                    f"  - `{row.get('contact_sheet_path')}`: text `{row.get('observed_text')}`; "
                    f"certainty `{row.get('certainty')}`; caveat `{row.get('caveat')}`"
                )
        type_counts: dict[str, int] = {}
        for row in visual_rows:
            if row.get("interpretation_level") in {"semantic", "ocr"}:
                continue
            key = str(row.get("interpretation_label") or row.get("observation_type") or "<none>")
            type_counts[key] = type_counts.get(key, 0) + 1
        if type_counts:
            lines.append("- Supporting visual/OCR rows: " + ", ".join(f"`{key}`={value}" for key, value in sorted(type_counts.items())))
        for path in sorted({str(row.get("contact_sheet_path") or "") for row in visual_rows if row.get("contact_sheet_path")}):
            lines.append(f"- Contact sheet: `{path}`")
    lines.append("")
    return lines


def _vpn_activity_windows(rows: list[dict[str, Any]], *, padding_minutes: int = 0) -> list[dict[str, Any]]:
    windows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    padding = timedelta(minutes=max(padding_minutes, 0))
    for row in sorted(rows, key=lambda item: str(item.get("event_time_utc") or "")):
        timestamp = _parse_report_timestamp(str(row.get("event_time_utc") or ""))
        if timestamp is None:
            continue
        activity_type = str(row.get("activity_type") or "")
        if row.get("source_type") == "srum_network_connectivity":
            connected_seconds = _int_or_zero((row.get("details") or {}).get("connected_seconds") if isinstance(row.get("details"), dict) else None)
            start = timestamp - timedelta(seconds=connected_seconds) if connected_seconds > 0 else timestamp
            windows.append(_vpn_window_from_rows(start, timestamp, [row], padding=padding))
            continue
        if activity_type in {"connect_attempt", "connected"}:
            if current is None:
                current = _vpn_window_from_rows(timestamp, timestamp, [row], padding=timedelta())
            else:
                current["end_raw_utc"] = max(current["end_raw_utc"], timestamp)
                current["vpn_evidence"].append(row)
            current["profile_name"] = current.get("profile_name") or row.get("profile_name") or ""
            current["server"] = current.get("server") or row.get("server") or ""
            current["protocol"] = current.get("protocol") or row.get("protocol") or ""
            continue
        if activity_type == "disconnected":
            if current is None:
                current = _vpn_window_from_rows(timestamp, timestamp, [row], padding=timedelta())
            else:
                current["end_raw_utc"] = max(current["end_raw_utc"], timestamp)
                current["vpn_evidence"].append(row)
            current["window_start_utc"] = current["start_raw_utc"] - padding
            current["window_end_utc"] = current["end_raw_utc"] + padding
            current["vpn_evidence_count"] = len(current["vpn_evidence"])
            windows.append(current)
            current = None
    if current is not None:
        current["window_start_utc"] = current["start_raw_utc"] - padding
        current["window_end_utc"] = current["end_raw_utc"] + padding
        current["vpn_evidence_count"] = len(current["vpn_evidence"])
        windows.append(current)
    return _merge_vpn_windows(windows)


def _vpn_window_from_rows(start: datetime, end: datetime, rows: list[dict[str, Any]], *, padding: timedelta) -> dict[str, Any]:
    first = rows[0] if rows else {}
    return {
        "start_raw_utc": start,
        "end_raw_utc": end,
        "window_start_utc": start - padding,
        "window_end_utc": end + padding,
        "profile_name": first.get("profile_name") or "",
        "server": first.get("server") or "",
        "protocol": first.get("protocol") or "",
        "source_types": ",".join(sorted({str(row.get("source_type") or "") for row in rows if row.get("source_type")})),
        "vpn_evidence_count": len(rows),
        "vpn_evidence": rows,
    }


def _merge_vpn_windows(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for window in sorted(windows, key=lambda item: item["window_start_utc"]):
        if not merged or window["window_start_utc"] > merged[-1]["window_end_utc"] + timedelta(minutes=1):
            merged.append(window)
            continue
        current = merged[-1]
        current["end_raw_utc"] = max(current["end_raw_utc"], window["end_raw_utc"])
        current["window_end_utc"] = max(current["window_end_utc"], window["window_end_utc"])
        current["profile_name"] = current.get("profile_name") or window.get("profile_name") or ""
        current["server"] = current.get("server") or window.get("server") or ""
        current["protocol"] = current.get("protocol") or window.get("protocol") or ""
        current["vpn_evidence"].extend(window.get("vpn_evidence") or [])
        current["vpn_evidence_count"] = len(current["vpn_evidence"])
        current["source_types"] = ",".join(
            sorted({str(row.get("source_type") or "") for row in current["vpn_evidence"] if row.get("source_type")})
        )
    return merged


def _vpn_window_usb_devices(db: Database, case_id: str, window: dict[str, Any], *, limit: int) -> list[dict[str, Any]]:
    start = _format_report_window_time(window.get("window_start_utc"))
    end = _format_report_window_time(window.get("window_end_utc"))
    if not start or not end:
        return []
    rows = _query_report_rows(
        db,
        case_id,
        "usb_connection_events",
        """
        SELECT start_event.serial, start_event.volume_serial_number, start_event.volume_guid,
               start_event.drive_letter, start_event.event_time_utc AS session_start,
               COALESCE(
                 (
                   SELECT MIN(end_event.event_time_utc)
                   FROM usb_connection_events end_event
                   WHERE end_event.case_id = start_event.case_id
                     AND end_event.image_id = start_event.image_id
                     AND COALESCE(end_event.serial, '') = COALESCE(start_event.serial, '')
                     AND end_event.event_type = 'removal'
                     AND end_event.event_time_utc >= start_event.event_time_utc
                 ),
                 ?
               ) AS session_end,
               start_event.event_source,
               usb_storage_devices.volume_name,
               usb_storage_devices.product,
               usb_storage_devices.vendor
        FROM usb_connection_events start_event
        LEFT JOIN usb_storage_devices
          ON usb_storage_devices.id = start_event.usb_device_id
        WHERE start_event.case_id = ?
          AND start_event.event_type IN ('arrival', 'first_connected', 'partition_seen')
          AND start_event.event_time_utc <= ?
          AND COALESCE(
                (
                  SELECT MIN(end_event.event_time_utc)
                  FROM usb_connection_events end_event
                  WHERE end_event.case_id = start_event.case_id
                    AND end_event.image_id = start_event.image_id
                    AND COALESCE(end_event.serial, '') = COALESCE(start_event.serial, '')
                    AND end_event.event_type = 'removal'
                    AND end_event.event_time_utc >= start_event.event_time_utc
                ),
                ?
              ) >= ?
        ORDER BY start_event.event_time_utc DESC
        LIMIT ?
        """,
        (end, case_id, end, end, start, limit * 5),
    )
    devices: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("serial") or ""),
            str(row.get("volume_serial_number") or ""),
            str(row.get("drive_letter") or ""),
        )
        if key in devices:
            continue
        devices[key] = row
        if len(devices) >= limit:
            break
    return list(devices.values())


def _local_activity_rows(db: Database, case_id: str, *, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(_local_prefetch_activity_rows(db, case_id, limit))
    rows.extend(_local_registry_activity_rows(db, case_id, limit))
    rows.extend(_local_srum_activity_rows(db, case_id, limit))
    rows.extend(_local_shortcut_activity_rows(db, case_id, limit))
    rows.extend(_local_package_activity_rows(db, case_id, limit))
    rows.extend(_local_browser_download_activity_rows(db, case_id, limit))
    rows.extend(_local_webcache_file_activity_rows(db, case_id, limit))
    rows.extend(_local_windows_activity_rows(db, case_id, limit))
    return [row for row in rows if row.get("event_time_utc")]


def _local_prefetch_activity_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    columns = _report_table_columns(db, case_id, "prefetch_items")
    return [
        {
            "event_time_utc": row.get("last_run_time_utc"),
            "activity_category": "application_execution",
            "source_table": "prefetch_items",
            "source_row_id": row.get("id"),
            "description": row.get("executable_name") or row.get("prefetch_name"),
            "application": row.get("executable_name"),
            "path": row.get("resolved_reference_path") or row.get("original_path") or row.get("artifact_path"),
            "source_file": row.get("artifact_path") or row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {"run_count": row.get("run_count"), "prefetch_name": row.get("prefetch_name")},
        }
        for row in _query_report_rows(
            db,
            case_id,
            "prefetch_items",
            f"""
            SELECT {_generic_select_sql(
                [
                    "id",
                    "source_csv",
                    "row_number",
                    "prefetch_name",
                    "artifact_path",
                    "original_path",
                    "executable_name",
                    "run_count",
                    "last_run_time_utc",
                    "resolved_reference_path",
                ],
                columns,
            )}
            FROM prefetch_items
            WHERE case_id = ? AND COALESCE(last_run_time_utc, '') != ''
            ORDER BY last_run_time_utc
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _local_registry_activity_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    artifacts = (
        "'bam','dam','userassist','runmru','recentdocs','office_recent_docs',"
        "'common_dialog','typed_paths','wordwheel_query','taskbar_feature_usage','mui_cache'"
    )
    return [
        {
            "event_time_utc": row.get("event_time_utc") or row.get("key_last_write_utc"),
            "activity_category": "registry_app_or_file_use",
            "source_table": "registry_artifacts",
            "source_row_id": row.get("id"),
            "description": _registry_activity_description(row),
            "application": _basename_from_path(row.get("normalized_path")) or row.get("display_name"),
            "path": row.get("normalized_path") or row.get("value_data"),
            "source_file": row.get("source_path") or row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {"artifact": row.get("artifact"), "key_path": row.get("key_path"), "value_name": row.get("value_name")},
        }
        for row in _query_report_rows(
            db,
            case_id,
            "registry_artifacts",
            f"""
            SELECT id, source_csv, row_number, source_path, artifact, category, key_path,
                   key_last_write_utc, event_time_utc, value_name, value_data,
                   display_name, normalized_path, notes
            FROM registry_artifacts
            WHERE case_id = ?
              AND artifact IN ({artifacts})
              AND COALESCE(event_time_utc, key_last_write_utc, '') != ''
              AND NOT (artifact IN ('bam', 'dam') AND COALESCE(normalized_path, value_name, '') = '')
            ORDER BY COALESCE(event_time_utc, key_last_write_utc)
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _registry_activity_description(row: dict[str, Any]) -> str:
    artifact = str(row.get("artifact") or "")
    if artifact in {"bam", "dam"}:
        path = row.get("normalized_path") or row.get("value_name") or ""
        return f"{artifact.upper()} application activity: {_display_evidence_path(path)}"
    if artifact == "userassist":
        return f"UserAssist entry: {row.get('display_name') or row.get('value_name') or ''}"
    if artifact == "mui_cache":
        return f"MUI Cache entry: {row.get('display_name') or row.get('value_name') or ''}"
    return str(row.get("display_name") or row.get("value_data") or row.get("value_name") or "")


def _local_package_activity_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    return [
        {
            "event_time_utc": row.get("event_time_utc") or row.get("modified_utc"),
            "activity_category": _package_activity_category(row.get("record_type")),
            "source_table": "package_artifacts",
            "source_row_id": row.get("id"),
            "description": row.get("artifact_text") or row.get("artifact_value") or row.get("file_name") or row.get("record_type"),
            "application": row.get("source_name") or row.get("application_package"),
            "path": row.get("artifact_value") if row.get("record_type") == "recent_file_cache_entry" else row.get("source_path"),
            "source_file": row.get("source_path") or row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {
                "record_type": row.get("record_type"),
                "user_profile": row.get("user_profile"),
                "package": row.get("application_package"),
            },
        }
        for row in _query_report_rows(
            db,
            case_id,
            "package_artifacts",
            """
            SELECT id, source_csv, row_number, record_type, user_profile,
                   application_package, source_path, source_name, file_name,
                   modified_utc, event_time_utc, artifact_value, artifact_text
            FROM package_artifacts
            WHERE case_id = ?
              AND record_type IN ('outlook_attachment_cache_file', 'wsl_shell_history', 'recent_file_cache_entry')
              AND COALESCE(event_time_utc, modified_utc, '') != ''
            ORDER BY COALESCE(event_time_utc, modified_utc)
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _package_activity_category(record_type: Any) -> str:
    if record_type == "wsl_shell_history":
        return "wsl_typed_command"
    if record_type == "outlook_attachment_cache_file":
        return "outlook_attachment_cache"
    if record_type == "recent_file_cache_entry":
        return "recent_file_cache"
    return "package_artifact_activity"


def _local_srum_activity_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    return [
        {
            "event_time_utc": row.get("timestamp"),
            "activity_category": "srum_local_app_activity",
            "source_table": "srum_records",
            "source_row_id": row.get("id"),
            "description": row.get("app_name") or row.get("app_path") or row.get("app_id"),
            "application": row.get("app_name") or _basename_from_path(row.get("app_path")),
            "path": row.get("app_path"),
            "source_file": row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {
                "record_type": row.get("record_type"),
                "bytes_received": row.get("bytes_received"),
                "bytes_sent": row.get("bytes_sent"),
                "user_name": row.get("user_name"),
            },
        }
        for row in _query_report_rows(
            db,
            case_id,
            "srum_records",
            """
            SELECT id, source_csv, row_number, record_type, timestamp, app_id,
                   app_name, app_path, user_name, bytes_received, bytes_sent
            FROM srum_records
            WHERE case_id = ?
              AND record_type IN ('network_usage', 'app_resource_usage', 'app_timeline_provider')
              AND COALESCE(timestamp, '') != ''
              AND COALESCE(app_name, app_path, app_id, '') != ''
            ORDER BY timestamp
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _local_shortcut_activity_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    columns = _report_table_columns(db, case_id, "shortcut_items")
    return [
        {
            "event_time_utc": row.get("event_time_utc"),
            "activity_category": "shortcut_or_jumplist_file_use",
            "source_table": "shortcut_items",
            "source_row_id": row.get("id"),
            "description": row.get("file_name") or row.get("file_location") or row.get("artifact_name"),
            "application": row.get("app_id_description") or _jumplist_application_name(row),
            "path": row.get("file_location") or row.get("artifact_path"),
            "source_file": row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {
                "artifact_type": row.get("artifact_type"),
                "artifact_name": row.get("artifact_name"),
                "jumplist_item_number": row.get("jumplist_item_number"),
            },
        }
        for row in _query_report_rows(
            db,
            case_id,
            "shortcut_items",
            f"""
            SELECT {_shortcut_select_sql(columns)},
                   COALESCE(NULLIF(target_accessed, ''), NULLIF(target_modified, ''), NULLIF(target_created, ''), NULLIF(lnk_accessed, ''), NULLIF(lnk_modified, ''), NULLIF(lnk_created, '')) AS event_time_utc
            FROM shortcut_items
            WHERE case_id = ?
              AND COALESCE(target_accessed, target_modified, target_created, lnk_accessed, lnk_modified, lnk_created, '') != ''
            ORDER BY event_time_utc
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _local_browser_download_activity_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    return [
        {
            "event_time_utc": row.get("start_time_utc") or row.get("end_time_utc"),
            "activity_category": "browser_download",
            "source_table": "browser_downloads",
            "source_row_id": row.get("id"),
            "description": row.get("target_path") or row.get("tab_url") or row.get("site_url"),
            "application": row.get("browser"),
            "path": row.get("target_path"),
            "url": row.get("tab_url") or row.get("site_url") or row.get("referrer"),
            "source_file": row.get("source_path") or row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {"state": row.get("state"), "received_bytes": row.get("received_bytes"), "total_bytes": row.get("total_bytes")},
        }
        for row in _query_report_rows(
            db,
            case_id,
            "browser_downloads",
            """
            SELECT id, source_csv, row_number, browser, source_path, target_path,
                   tab_url, site_url, referrer, start_time_utc, end_time_utc,
                   received_bytes, total_bytes, state
            FROM browser_downloads
            WHERE case_id = ? AND COALESCE(start_time_utc, end_time_utc, '') != ''
            ORDER BY COALESCE(start_time_utc, end_time_utc)
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _local_webcache_file_activity_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    return [
        {
            "event_time_utc": row.get("accessed_utc") or row.get("modified_utc") or row.get("created_utc"),
            "activity_category": "webcache_local_file_access",
            "source_table": "webcache_file_accesses",
            "source_row_id": row.get("id"),
            "description": row.get("file_name") or row.get("local_path") or row.get("url"),
            "application": row.get("application") or row.get("application_package"),
            "path": row.get("normalized_path") or row.get("local_path"),
            "url": row.get("url"),
            "source_file": row.get("source_database") or row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {"container_name": row.get("container_name"), "attribution_method": row.get("attribution_method")},
        }
        for row in _query_report_rows(
            db,
            case_id,
            "webcache_file_accesses",
            """
            SELECT id, source_csv, row_number, source_database, user_name,
                   application, application_package, container_name,
                   attribution_method, url, local_path, normalized_path,
                   file_name, created_utc, accessed_utc, modified_utc
            FROM webcache_file_accesses
            WHERE case_id = ? AND COALESCE(accessed_utc, modified_utc, created_utc, '') != ''
            ORDER BY COALESCE(accessed_utc, modified_utc, created_utc)
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _local_windows_activity_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    return [
        {
            "event_time_utc": row.get("start_time_utc") or row.get("last_modified_utc"),
            "activity_category": "connected_devices_activity",
            "source_table": "windows_activities",
            "source_row_id": row.get("id"),
            "description": row.get("display_text") or row.get("file_name") or row.get("app_display_name"),
            "application": row.get("app_display_name") or row.get("app_id"),
            "path": row.get("content_uri") or row.get("activation_uri") or row.get("fallback_uri"),
            "source_file": row.get("source_csv"),
            "row_number": row.get("row_number"),
            "details": {"activity_type": row.get("activity_type"), "user_profile": row.get("user_profile")},
        }
        for row in _query_report_rows(
            db,
            case_id,
            "windows_activities",
            """
            SELECT id, source_csv, row_number, user_profile, app_id, app_display_name,
                   activity_type, display_text, file_name, content_uri, activation_uri,
                   fallback_uri, start_time_utc, last_modified_utc
            FROM windows_activities
            WHERE case_id = ? AND COALESCE(start_time_utc, last_modified_utc, '') != ''
            ORDER BY COALESCE(start_time_utc, last_modified_utc)
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _activity_category_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        category = str(row.get("activity_category") or "unknown")
        counts[category] = counts.get(category, 0) + 1
    return [{"activity_category": key, "count": value} for key, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def _activity_source_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        source = str(row.get("source_table") or "unknown")
        counts[source] = counts.get(source, 0) + 1
    return [{"source_table": key, "count": value} for key, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def _rank_vpn_window_activity(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority = {
        "application_execution": 0,
        "shortcut_or_jumplist_file_use": 1,
        "browser_download": 2,
        "webcache_local_file_access": 3,
        "outlook_attachment_cache": 4,
        "recent_file_cache": 5,
        "wsl_typed_command": 6,
        "registry_app_or_file_use": 7,
        "srum_local_app_activity": 8,
        "connected_devices_activity": 9,
    }
    return sorted(rows, key=lambda row: (priority.get(str(row.get("activity_category")), 99), row.get("event_time_utc") or ""))


def _vpn_source_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get("source_type") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"source_type": key, "count": count} for key, count in sorted(counts.items())]


def _vpn_context_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        group_key = row.get("evidence_group") or _vpn_evidence_group(
            profile_name=row.get("profile_name"),
            server=row.get("server"),
            protocol=row.get("protocol"),
        )
        item = groups.setdefault(
            str(group_key),
            {
                "evidence_group": group_key,
                "profile_name": row.get("profile_name") or "",
                "server": row.get("server") or "",
                "protocol": row.get("protocol") or "",
                "first_observed_utc": row.get("event_time_utc") or "",
                "last_observed_utc": row.get("event_time_utc") or "",
                "activity_types": set(),
                "source_types": set(),
                "evidence_count": 0,
                "evidence": [],
            },
        )
        item["profile_name"] = item["profile_name"] or row.get("profile_name") or ""
        item["server"] = item["server"] or row.get("server") or ""
        item["protocol"] = item["protocol"] or row.get("protocol") or ""
        if row.get("event_time_utc"):
            times = [value for value in (item["first_observed_utc"], item["last_observed_utc"], row.get("event_time_utc")) if value]
            item["first_observed_utc"] = min(times)
            item["last_observed_utc"] = max(times)
        item["activity_types"].add(row.get("activity_type") or "unknown")
        item["source_types"].add(row.get("source_type") or "unknown")
        item["evidence_count"] += 1
        if len(item["evidence"]) < 10:
            item["evidence"].append(row)
    grouped: list[dict[str, Any]] = []
    for item in groups.values():
        item["activity_types"] = ",".join(sorted(str(value) for value in item["activity_types"]))
        item["source_types"] = ",".join(sorted(str(value) for value in item["source_types"]))
        grouped.append(item)
    grouped.sort(key=lambda row: (row.get("first_observed_utc") or "", row.get("evidence_group") or ""))
    return grouped


def _dedupe_report_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for row in rows:
        key = (
            str(row.get("source_type") or ""),
            str(row.get("event_time_utc") or ""),
            str(row.get("profile_name") or ""),
            str(row.get("server") or ""),
            str(row.get("source_file") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _rdp_event_sequence(events: list[Any]) -> str:
    return ", ".join(
        f"{event.get('event_id')}@{event.get('time_created')}"
        for event in events
        if isinstance(event, dict)
    )


def _short_case_path(value: Any) -> str:
    text = str(value or "")
    marker = "/cases/"
    if marker in text:
        return text[text.index(marker) + 1:]
    return text


def _display_evidence_path(value: Any) -> str:
    return display_evidence_path(value)


def _rdp_client_sessions(db: Database, case_id: str) -> list[dict[str, Any]]:
    events = _query_report_rows(
        db,
        case_id,
        "evtx_events",
        """
        SELECT time_created, event_id, provider, channel, computer, user_name,
               payload_data1, payload_data2, payload_data3, map_description, source_file
        FROM evtx_events
        WHERE case_id = ?
          AND provider = 'Microsoft-Windows-TerminalServices-ClientActiveXCore'
          AND channel = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'
          AND event_id IN ('1024', '1025', '1026', '1027', '1102', '1103')
        ORDER BY time_created
        """,
        (case_id,),
    )
    sessions: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    last_remote_host = ""
    for event in events:
        event_id = str(event.get("event_id") or "")
        timestamp = event.get("time_created") or ""
        text = " ".join(str(event.get(key) or "") for key in ("payload_data1", "payload_data2", "payload_data3", "map_description"))
        payload1 = str(event.get("payload_data1") or "")
        if event_id == "1024":
            last_remote_host = _rdp_dest_from_text(text) or last_remote_host
            if current and current.get("connected_time_utc"):
                sessions.append(current)
            current = {
                "start_time_utc": timestamp,
                "connected_time_utc": "",
                "end_time_utc": "",
                "client_computer": event.get("computer") or "",
                "user": event.get("user_name") or "",
                "remote_host": last_remote_host,
                "remote_ip": "",
                "domain": "",
                "disconnect_reason": "",
                "event_count": 1,
                "source_file": event.get("source_file") or "",
                "events": [_remote_access_event_row(event)],
            }
            continue
        if current is None:
            if event_id not in {"1029", "1102"}:
                continue
            current = {
                "start_time_utc": timestamp,
                "connected_time_utc": "",
                "end_time_utc": "",
                "client_computer": event.get("computer") or "",
                "user": event.get("user_name") or "",
                "remote_host": last_remote_host,
                "remote_ip": _rdp_address_from_text(text) if event_id == "1102" else "",
                "domain": "",
                "disconnect_reason": "",
                "event_count": 1,
                "source_file": event.get("source_file") or "",
                "events": [_remote_access_event_row(event)],
            }
            continue
        current["event_count"] += 1
        current["events"].append(_remote_access_event_row(event))
        if event_id == "1102":
            current["remote_ip"] = current.get("remote_ip") or _rdp_address_from_text(text)
        elif event_id == "1025":
            current["connected_time_utc"] = current.get("connected_time_utc") or timestamp
        elif event_id == "1027":
            current["domain"] = current.get("domain") or _rdp_domain_from_text(text)
        elif event_id == "1026":
            current["end_time_utc"] = timestamp
            current["disconnect_reason"] = _rdp_disconnect_from_text(payload1)
            sessions.append(current)
            current = None
    if current and current.get("connected_time_utc"):
        sessions.append(current)
    return sessions


def _remote_access_vpn_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(_vpn_evtx_rows(db, case_id, limit))
    rows.extend(_vpn_srum_rows(db, case_id, limit))
    return [
        row for row in rows
        if row.get("activity_type") in {
            "connect_attempt",
            "connected",
            "disconnected",
            "failed",
            "connection_observation",
        }
    ]


def _rdp_cache_file_rows(db: Database, case_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _query_report_rows(
        db,
        case_id,
        "rdp_cache_items",
        """
        SELECT user_profile, source_cache_path, file_name, file_size, parser_status
        FROM rdp_cache_items
        WHERE case_id = ? AND record_type = 'cache_file'
        ORDER BY source_cache_path
        """,
        (case_id,),
    ):
        item = dict(row)
        path = Path(str(item.get("source_cache_path") or ""))
        item["modified_utc"] = ""
        item["is_empty_cache_file"] = False
        if path.exists():
            stat = path.stat()
            item["modified_utc"] = datetime.fromtimestamp(stat.st_mtime, timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
            item["file_size"] = str(stat.st_size)
            item["is_empty_cache_file"] = stat.st_size == 0
            if stat.st_size == 0:
                item["parser_status"] = "empty_cache_file"
        rows.append(item)
    return rows


def _rdp_visual_observation_rows(db: Database, case_id: str) -> list[dict[str, Any]]:
    rows = _query_report_rows(
        db,
        case_id,
        "rdp_visual_observations",
        """
        SELECT user_profile, source_cache_path, contact_sheet_path,
               observation_time_utc, time_basis, observation_type,
               observed_application, observed_text, observed_path,
               certainty, caveat
        FROM rdp_visual_observations
        WHERE case_id = ?
        ORDER BY observation_time_utc, observed_application, observed_text
        """,
        (case_id,),
    )
    return [_annotate_rdp_visual_observation(dict(row)) for row in rows]


def _rdp_shortcut_rows(db: Database, case_id: str, *, limit: int = 1000) -> list[dict[str, Any]]:
    columns = _report_table_columns(db, case_id, "shortcut_items")
    text_sql = _coalesced_text_sql(
        [
            "artifact_name",
            "artifact_path",
            "file_name",
            "file_location",
            "command_line_arguments",
            "working_directory",
            "network_path",
            "app_id",
            "app_id_description",
            "source_csv",
        ],
        columns,
    )
    rows = _query_report_rows(
        db,
        case_id,
        "shortcut_items",
        f"""
        SELECT
          {_shortcut_select_sql(columns)},
          COALESCE(NULLIF(target_accessed, ''), NULLIF(target_modified, ''), NULLIF(target_created, ''), NULLIF(lnk_accessed, ''), NULLIF(lnk_modified, ''), NULLIF(lnk_created, '')) AS event_time_utc
        FROM shortcut_items
        WHERE case_id = ?
          AND {_rdp_shortcut_match_sql(text_sql)}
        ORDER BY event_time_utc, artifact_type, row_number
        LIMIT ?
        """,
        (case_id, limit),
    )
    return [dict(row) for row in rows]


def _rdp_shortcut_match_sql(text: str) -> str:
    return (
        f"({text} LIKE '%mstsc%' OR {text} LIKE '%.rdp%' OR "
        f"{text} LIKE '%remote desktop%' OR {text} LIKE '%terminal server client%' OR "
        f"{text} LIKE '%terminal services%' OR {text} LIKE '%rdpclient%')"
    )


def _shortcut_select_sql(columns: set[str]) -> str:
    names = [
        "id",
        "computer_id",
        "image_id",
        "tool_name",
        "source_csv",
        "row_number",
        "artifact_type",
        "artifact_name",
        "artifact_path",
        "file_name",
        "file_location",
        "target_created",
        "target_modified",
        "target_accessed",
        "lnk_created",
        "lnk_modified",
        "lnk_accessed",
        "jumplist_item_number",
        "command_line_arguments",
        "working_directory",
        "network_path",
        "machine_name",
        "app_id",
        "app_id_description",
        "entry_id",
        "destlist_version",
    ]
    return ",\n          ".join(name if name in columns else f"NULL AS {name}" for name in names)


def _generic_select_sql(names: list[str], columns: set[str]) -> str:
    return ",\n                   ".join(name if name in columns else f"NULL AS {name}" for name in names)


def _coalesced_text_sql(names: list[str], columns: set[str]) -> str:
    available = [name for name in names if name in columns]
    if not available:
        return "''"
    return "lower(" + " || ' ' || ".join(f"coalesce({name}, '')" for name in available) + ")"


def _annotate_rdp_visual_observation(row: dict[str, Any]) -> dict[str, Any]:
    observation_type = str(row.get("observation_type") or "").lower()
    observed_application = str(row.get("observed_application") or "").strip()
    observed_text = str(row.get("observed_text") or "").strip()
    if observation_type in {"openai_vision_contact_sheet_review", "application_visible"}:
        level = "semantic"
        label = "Semantic visual interpretation"
    elif "ocr" in observation_type or (observed_text and not observed_application):
        level = "ocr"
        label = "OCR text extraction"
    elif row.get("contact_sheet_path"):
        level = "contact_sheet"
        label = "Contact sheet reference"
    else:
        level = "metadata"
        label = "Visual metadata"
    row["interpretation_level"] = level
    row["interpretation_label"] = label
    return row


def _timestamp_in_window(value: Any, start: datetime | None, end: datetime | None) -> bool:
    timestamp = _parse_report_timestamp(str(value)) if value else None
    if timestamp is None:
        return False
    if start and timestamp < start:
        return False
    if end and timestamp > end:
        return False
    return True


def _remote_access_event_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "time_created": row.get("time_created") or "",
        "event_id": row.get("event_id") or "",
        "description": row.get("map_description") or "",
        "payload_data1": row.get("payload_data1") or "",
    }


def _rdp_dest_from_text(text: str) -> str:
    match = re.search(r"Dest:\s*([^,\s]+)", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _rdp_address_from_text(text: str) -> str:
    match = re.search(r"Address:\s*([0-9A-Fa-f:.]+)", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _rdp_domain_from_text(text: str) -> str:
    match = re.search(r"Domain:\s*([^,\s]+)", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _rdp_disconnect_from_text(text: str) -> str:
    match = re.search(r"Disconnect Reason:\s*(.+)", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _vpn_all_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    source_limit = max(limit, 100)
    rows.extend(_vpn_srum_rows(db, case_id, source_limit))
    rows.extend(_vpn_evtx_rows(db, case_id, source_limit))
    rows.extend(_vpn_registry_rows(db, case_id, source_limit))
    rows.extend(_vpn_prefetch_rows(db, case_id, source_limit))
    rows.extend(_vpn_shortcut_rows(db, case_id, source_limit))
    rows.extend(_vpn_execution_cache_rows(db, case_id, source_limit))
    rows.extend(_vpn_etl_rows(db, case_id, source_limit))
    rows.extend(_vpn_wer_defender_rows(db, case_id, source_limit))
    return rows


def _vpn_report_from_rows(case_id: str, rows: list[dict[str, Any]], key: str, limit: int) -> dict[str, Any]:
    rows.sort(key=lambda row: (row.get("event_time_utc") or "", row.get("source_type") or ""))
    limited = rows[:limit]
    counts: dict[str, int] = {}
    activity_counts: dict[str, int] = {}
    for row in rows:
        counts[str(row.get("source_type") or "unknown")] = counts.get(str(row.get("source_type") or "unknown"), 0) + 1
        activity_counts[str(row.get("activity_type") or "unknown")] = activity_counts.get(str(row.get("activity_type") or "unknown"), 0) + 1
    return {
        "case_id": case_id,
        "summary": {
            "source_counts": [
                {"source_type": source_type, "count": count}
                for source_type, count in sorted(counts.items())
            ],
            "activity_type_counts": [
                {"activity_type": activity_type, "count": count}
                for activity_type, count in sorted(activity_counts.items())
            ],
            "total_matching_rows": len(rows),
        },
        key: limited,
        "total_returned": len(limited),
    }


def _vpn_srum_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    return [
        _vpn_row(
            source_type="srum_network_connectivity",
            activity_type="connection_observation",
            event_time_utc=row["timestamp"],
            profile_name=row["vpn_profile_name"] or row["l2_profile_name"] or "(unknown)",
            server=row["vpn_server"],
            protocol=row["vpn_protocol"],
            event="SRUM PPP/VPN connectivity observation",
            user=row["user_name"],
            path_or_process=row["app_path"] or row["app_name"],
            source_file=row["source_csv"],
            details={
                "interface_type": row["interface_type"],
                "connected_seconds": row["connected_time"],
                "match_method": row["vpn_match_method"],
                "phonebook": row["vpn_phonebook_path"],
            },
        )
        for row in _query_report_rows(
            db,
            case_id,
            "srum_records",
            """
            SELECT *
            FROM srum_records
            WHERE case_id = ? AND interface_type = '23'
            ORDER BY timestamp
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _vpn_evtx_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    return [
        _vpn_event_log_row(row)
        for row in _query_report_rows(
            db,
            case_id,
            "evtx_events",
            f"""
            SELECT *
            FROM evtx_events
            WHERE case_id = ?
              AND (
                event_id IN (
                  '20220', '20221', '20222', '20223', '20224', '20225',
                  '20226', '20227', '20228', '20268', '20269', '20270',
                  '20271', '20272', '20275'
                )
              )
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _vpn_event_log_row(row: Any) -> dict[str, Any]:
    activity_type, event_name = RASCLIENT_EVENT_MEANINGS.get(
        str(_row_value(row, "event_id") or ""),
        ("connection_observation", _row_value(row, "map_description") or f"Event ID {_row_value(row, 'event_id')}"),
    )
    text = " ".join(str(_row_value(row, key) or "") for key in ("payload", "payload_data1", "payload_data2", "payload_data3", "map_description"))
    return _vpn_row(
        source_type="event_log",
        activity_type=activity_type,
        event_time_utc=_row_value(row, "time_created"),
        profile_name=_vpn_profile_from_text(text),
        server=_vpn_server_from_text(text),
        protocol=_vpn_protocol_from_text(f"{text} {_row_value(row, 'provider')} {_row_value(row, 'channel')}"),
        event=event_name,
        user=_row_value(row, "user_name") or _row_value(row, "user_id"),
        path_or_process=_row_value(row, "executable_info"),
        source_file=_row_value(row, "source_file"),
        details={
            "provider": _row_value(row, "provider"),
            "channel": _row_value(row, "channel"),
            "event_id": _row_value(row, "event_id"),
        },
    )


def _vpn_registry_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    text = (
        "coalesce(key_path, '') || ' ' || coalesce(value_name, '') || ' ' || "
        "coalesce(value_data, '') || ' ' || coalesce(normalized_path, '') || ' ' || coalesce(notes, '')"
    )
    return [
        _vpn_row(
            source_type=f"registry_{row['artifact']}",
            activity_type=_vpn_registry_activity_type(row["artifact"]),
            event_time_utc=row["event_time_utc"] or row["key_last_write_utc"],
            profile_name=_vpn_registry_profile_name(row),
            server=_vpn_server_from_text(f"{row['value_name']} {row['value_data']} {row['key_path']}"),
            protocol=_vpn_protocol_from_text(f"{row['value_name']} {row['value_data']} {row['key_path']}"),
            event=row["artifact"],
            user=row["user_profile"] or row["user_sid"],
            path_or_process=row["normalized_path"] or row["value_name"],
            source_file=row["source_path"],
            details={"key_path": row["key_path"], "value_name": row["value_name"], "notes": row["notes"]},
        )
        for row in _query_report_rows(
            db,
            case_id,
            "registry_artifacts",
            f"""
            SELECT *
            FROM registry_artifacts
            WHERE case_id = ?
              AND (
                (
                  artifact = 'connected_networks'
                  AND (
                    lower(coalesce(key_path, '')) LIKE '%networklist/profiles/%'
                    OR lower(coalesce(key_path, '')) LIKE '%networklist/signatures/%'
                  )
                  AND (
                    value_name IN ('Description', 'ProfileName', 'FirstNetwork')
                    OR (value_name = 'DnsSuffix' AND value_data NOT IN ('', '<none>'))
                    OR (value_name = 'NameType' AND value_data LIKE '23%')
                  )
                )
                OR (
                  (
                    artifact IN (
                      'ras_connection_manager', 'ras_phonebook_registry',
                      'bam', 'dam', 'autostart', 'installed_applications',
                      'amcache', 'userassist'
                    )
                  )
                  AND {VPN_TEXT_MATCH.format(text)}
                )
              )
            ORDER BY COALESCE(event_time_utc, key_last_write_utc)
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _vpn_registry_activity_type(artifact: str) -> str:
    if artifact in {"bam", "dam", "autostart"}:
        return "supporting_execution"
    if artifact == "connected_networks":
        return "network_profile_observation"
    return "configured"


def _vpn_registry_profile_name(row: Any) -> str:
    artifact = _row_value(row, "artifact") or ""
    value_name = _row_value(row, "value_name") or ""
    value_data = _row_value(row, "value_data") or ""
    if artifact == "connected_networks" and value_name == "NameType" and str(value_data).startswith("23"):
        profile_guid = _network_profile_guid(_row_value(row, "key_path") or "")
        return f"NetworkList VPN profile {profile_guid}".strip()
    return _row_value(row, "display_name") or value_data or value_name


def _network_profile_guid(key_path: str) -> str:
    match = re.search(r"\{[0-9a-fA-F-]{36}\}", key_path)
    return match.group(0) if match else ""


def _vpn_prefetch_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    text = "coalesce(prefetch_name, '') || ' ' || coalesce(executable_name, '') || ' ' || coalesce(referenced_strings, '')"
    return [
        _vpn_row(
            source_type="prefetch",
            activity_type="supporting_execution",
            event_time_utc=row["last_run_time_utc"],
            server=_vpn_server_from_text(row["referenced_strings"] or ""),
            protocol=_vpn_protocol_from_text(row["referenced_strings"] or row["executable_name"] or ""),
            event="VPN-related executable prefetch",
            path_or_process=row["executable_name"] or row["prefetch_name"],
            source_file=row["artifact_path"] or row["source_csv"],
            details={"run_count": row["run_count"], "last_run_times_utc": row["last_run_times_utc"]},
        )
        for row in db.conn.execute(
            f"""
            SELECT *
            FROM prefetch_items
            WHERE case_id = ? AND {VPN_TEXT_MATCH.format(text)}
            ORDER BY last_run_time_utc
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]


def _vpn_shortcut_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    columns = _report_table_columns(db, case_id, "shortcut_items")
    text = " || ' ' || ".join(
        f"coalesce({name}, '')"
        for name in [
            "artifact_name",
            "artifact_path",
            "file_name",
            "file_location",
            "command_line_arguments",
            "working_directory",
            "network_path",
            "app_id",
            "app_id_description",
            "source_csv",
        ]
        if name in columns
    )
    text = text or "''"
    return [
        _vpn_row(
            source_type=f"shortcut_items_{row['artifact_type']}",
            activity_type="supporting_file_or_app_use",
            event_time_utc=row["event_time_utc"],
            profile_name=_vpn_profile_from_text(
                f"{row['file_name']} {row['file_location']} {row['artifact_name']} {row['app_id_description']}"
            ),
            server=_vpn_server_from_text(f"{row['file_name']} {row['file_location']} {row['command_line_arguments']}"),
            protocol=_vpn_protocol_from_text(
                f"{row['file_name']} {row['file_location']} {row['command_line_arguments']} {row['app_id_description']}"
            ),
            event=f"VPN-related {row['artifact_type']} shortcut/Jump List evidence",
            path_or_process=row["file_location"] or row["file_name"] or row["artifact_path"],
            source_file=row["source_csv"],
            details={
                "artifact_type": row["artifact_type"],
                "artifact_name": row["artifact_name"],
                "artifact_path": row["artifact_path"],
                "app_id": row["app_id"],
                "app_id_description": row["app_id_description"],
                "jumplist_item_number": row["jumplist_item_number"],
                "command_line_arguments": row["command_line_arguments"],
                "working_directory": row["working_directory"],
                "row_number": row["row_number"],
            },
        )
        for row in _query_report_rows(
            db,
            case_id,
            "shortcut_items",
            f"""
            SELECT {_shortcut_select_sql(columns)},
                   COALESCE(NULLIF(target_accessed, ''), NULLIF(target_modified, ''), NULLIF(target_created, ''), NULLIF(lnk_accessed, ''), NULLIF(lnk_modified, ''), NULLIF(lnk_created, '')) AS event_time_utc
            FROM shortcut_items
            WHERE case_id = ?
              AND {VPN_TEXT_MATCH.format(text)}
            ORDER BY event_time_utc
            LIMIT ?
            """,
            (case_id, limit),
        )
    ]


def _vpn_execution_cache_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for table, time_col in (("amcache_entries", "modified_utc"), ("shimcache_entries", "last_modified_utc")):
        path_col = "path"
        for row in db.conn.execute(
            f"""
            SELECT *
            FROM {table}
            WHERE case_id = ? AND {VPN_TEXT_MATCH.format(path_col)}
            ORDER BY {time_col}
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall():
            rows.append(_vpn_row(
                source_type=table.replace("_entries", ""),
                activity_type="supporting_execution",
                event_time_utc=row[time_col],
                protocol=_vpn_protocol_from_text(row["path"] or ""),
                event="VPN-related executable artifact",
                path_or_process=row["path"],
                source_file=row["source_file"] or row["source_csv"],
            ))
    return rows


def _vpn_etl_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    text = "coalesce(source_name, '') || ' ' || coalesce(provider_name, '') || ' ' || coalesce(event_name, '') || ' ' || coalesce(command_line, '')"
    return [
        _vpn_row(
            source_type="etl",
            activity_type="connection_observation",
            event_time_utc=row["timestamp_utc"],
            profile_name=_vpn_profile_from_text(row["command_line"] or ""),
            server=_vpn_server_from_text(row["command_line"] or ""),
            protocol=_vpn_protocol_from_text(f"{row['provider_name']} {row['event_name']} {row['command_line']}"),
            event=row["event_name"] or row["event_category"],
            user=row["user_sid"],
            path_or_process=row["image_name"] or row["command_line"],
            source_file=row["source_file"],
            details={"provider": row["provider_name"], "source_name": row["source_name"]},
        )
        for row in db.conn.execute(
            f"""
            SELECT *
            FROM etl_events
            WHERE case_id = ? AND {VPN_TEXT_MATCH.format(text)}
            ORDER BY timestamp_utc
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]


def _vpn_wer_defender_rows(db: Database, case_id: str, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in db.conn.execute(
        """
        SELECT *
        FROM windows_error_reports
        WHERE case_id = ?
          AND lower(coalesce(app_name, '') || ' ' || coalesce(original_filename, '') || ' ' || coalesce(ui_path, '')) LIKE '%vpn%'
        ORDER BY event_time_utc
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall():
        rows.append(_vpn_row(
            source_type="windows_error_reporting",
            activity_type="supporting_execution",
            event_time_utc=row["event_time_utc"],
            protocol=_vpn_protocol_from_text(f"{row['app_name']} {row['original_filename']} {row['ui_path']}"),
            event=row["event_type"] or "WER report",
            path_or_process=row["app_name"] or row["ui_path"],
            source_file=row["source_file"],
            details={"report_identifier": row["report_identifier"]},
        ))
    for row in db.conn.execute(
        """
        SELECT *
        FROM windows_defender_events
        WHERE case_id = ?
          AND lower(coalesce(event_type, '') || ' ' || coalesce(path, '') || ' ' || coalesce(resource, '') || ' ' || coalesce(message, '')) LIKE '%vpn%'
        ORDER BY event_time_utc
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall():
        rows.append(_vpn_row(
            source_type="windows_defender",
            activity_type="supporting_execution",
            event_time_utc=row["event_time_utc"],
            protocol=_vpn_protocol_from_text(f"{row['event_type']} {row['path']} {row['message']}"),
            event=row["event_type"] or row["component"],
            path_or_process=row["path"] or row["resource"],
            source_file=row["source_file"],
            details={"threat_name": row["threat_name"]},
        ))
    return rows


def _vpn_server_from_text(text: str) -> str:
    for match in re.finditer(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{2,5})?\b", text, re.IGNORECASE):
        host = match.group(0)
        tld = host.split(":")[0].rsplit(".", 1)[-1].lower()
        if tld in {"exe", "dll", "sys", "pf", "nls", "mui", "dat", "ini", "log", "tmp", "cat", "inf", "sdb"}:
            continue
        return host
    return ""


def _vpn_protocol_from_text(text: str) -> str:
    lowered = text.lower()
    for protocol in ("sstp", "ikev2", "l2tp", "pptp", "wireguard", "openvpn"):
        if protocol in lowered:
            return protocol.upper()
    return ""


def _vpn_profile_from_text(text: str) -> str:
    match = re.search(r"(?:profile name|connection name|entry name|vpn name)[=:\s]+([A-Za-z0-9 _.-]{3,80})", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _vpn_evidence_group(*, profile_name: Any = "", server: Any = "", protocol: Any = "") -> str:
    profile = str(profile_name or "").strip().lower()
    host = str(server or "").strip().lower()
    vpn_protocol = str(protocol or "").strip().lower()
    if host:
        return "|".join(part for part in (f"server:{host}", f"protocol:{vpn_protocol}" if vpn_protocol else "") if part)
    if profile and profile not in {"(unknown)", "unknown"}:
        return "|".join(part for part in (f"profile:{profile}", f"protocol:{vpn_protocol}" if vpn_protocol else "") if part)
    if vpn_protocol:
        return f"protocol:{vpn_protocol}"
    return "unknown"


def windows_search_report(db: Database, case_id: str, *, report_type: str = "files", limit: int = 100) -> dict[str, Any]:
    tables = {
        "files": ("windows_search_files", "files"),
        "internet": ("windows_search_internet_history", "internet_history"),
        "activity": ("windows_search_activity_history", "activity_history"),
        "emails": ("windows_search_email_indicators", "email_indicators"),
        "content": ("windows_search_indexed_content", "indexed_content"),
        "properties": ("windows_search_properties", "properties"),
    }
    table, key = tables[report_type]
    return _table_report(db, case_id, table, key, limit)


def file_metadata_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    extension: str | None = None,
    property_name: str | None = None,
    path_contains: str | None = None,
    tool_name: str | None = None,
    source_folder: str | None = None,
    user_only: bool = False,
    exclude_system: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["file_internal_metadata.case_id = ?"]
    params: list[Any] = [case_id]
    if extension:
        normalized_extension = extension if extension.startswith(".") else f".{extension}"
        filters.append("LOWER(file_internal_metadata.extension) = LOWER(?)")
        params.append(normalized_extension)
    if property_name:
        filters.append("LOWER(file_internal_metadata.property_name) = LOWER(?)")
        params.append(property_name)
    if path_contains:
        filters.append("file_internal_metadata.original_path LIKE ?")
        params.append(f"%{path_contains}%")
    if source_folder:
        normalized_folder = source_folder.strip("/").replace("\\", "/")
        filters.append("file_internal_metadata.original_path LIKE ?")
        params.append(f"{normalized_folder}/%")
    if tool_name:
        filters.append("file_internal_metadata.tool_name = ?")
        params.append(tool_name)
    if user_only:
        filters.append("file_internal_metadata.original_path LIKE 'Users/%'")
    if exclude_system:
        filters.append(
            """
            file_internal_metadata.original_path NOT LIKE 'Windows/%'
            AND file_internal_metadata.original_path NOT LIKE 'Windows.old/Windows/%'
            AND file_internal_metadata.original_path NOT LIKE 'Windows.old/Program Files/%'
            AND file_internal_metadata.original_path NOT LIKE 'Windows.old/Program Files (x86)/%'
            AND file_internal_metadata.original_path NOT LIKE 'Windows.old/ProgramData/%'
            AND file_internal_metadata.original_path NOT LIKE 'Program Files/%'
            AND file_internal_metadata.original_path NOT LIKE 'Program Files (x86)/%'
            AND file_internal_metadata.original_path NOT LIKE 'ProgramData/%'
            """
        )
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT file_internal_metadata.*, computers.label AS computer_label, images.path AS image_path
        FROM file_internal_metadata
        LEFT JOIN computers ON file_internal_metadata.computer_id = computers.id
        LEFT JOIN images ON file_internal_metadata.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY file_internal_metadata.created_at, file_internal_metadata.row_number
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {
            "extension": extension,
            "property": property_name,
            "path": path_contains,
            "source_folder": source_folder,
            "tool_name": tool_name,
            "user_only": user_only,
            "exclude_system": exclude_system,
        },
        "file_internal_metadata": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def file_metadata_folders_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    depth: int = 3,
    tool_name: str | None = None,
    extension: str | None = None,
    user_only: bool = False,
    exclude_system: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    rows = file_metadata_report(
        db,
        case_id,
        limit=1_000_000,
        extension=extension,
        tool_name=tool_name,
        user_only=user_only,
        exclude_system=exclude_system,
    )["file_internal_metadata"]
    folders: dict[str, dict[str, Any]] = {}
    for row in rows:
        original_path = str(row.get("original_path") or "")
        parts = [part for part in original_path.replace("\\", "/").split("/") if part]
        folder = "/".join(parts[:depth]) if len(parts) >= depth else "/".join(parts[:-1])
        if not folder:
            folder = "."
        item = folders.setdefault(
            folder,
            {"folder": folder, "metadata_rows": 0, "files": set(), "properties": set()},
        )
        item["metadata_rows"] += 1
        item["files"].add(original_path)
        if row.get("property_name"):
            item["properties"].add(row["property_name"])
    folder_rows = []
    for item in folders.values():
        folder_rows.append(
            {
                "folder": item["folder"],
                "metadata_rows": item["metadata_rows"],
                "file_count": len(item["files"]),
                "property_count": len(item["properties"]),
            }
        )
    folder_rows.sort(key=lambda row: (-row["file_count"], row["folder"]))
    return {
        "case_id": case_id,
        "filters": {
            "depth": depth,
            "tool_name": tool_name,
            "extension": extension,
            "user_only": user_only,
            "exclude_system": exclude_system,
        },
        "folders": folder_rows[:limit],
        "total_returned": min(len(folder_rows), limit),
        "total_folders": len(folder_rows),
    }


def file_metadata_skipped_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    tool_name: str | None = None,
    since: str | None = None,
    latest: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["activity_log.case_id = ?", "activity_log.event = 'artifact.skipped_reparse'"]
    params: list[Any] = [case_id]
    if since:
        filters.append("activity_log.created_at >= ?")
        params.append(since)
    params.append(limit * 10 if latest else limit)
    rows = db.conn.execute(
        f"""
        SELECT activity_log.*, computers.label AS computer_label, images.path AS image_path
        FROM activity_log
        LEFT JOIN computers ON activity_log.computer_id = computers.id
        LEFT JOIN images ON activity_log.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY activity_log.created_at DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    skipped = []
    seen_latest: set[str] = set()
    for row in rows:
        details = json.loads(row["details_json"] or "{}")
        row_tool_name = details.get("tool_name")
        if tool_name and row_tool_name != tool_name:
            continue
        latest_key = str(row_tool_name or details.get("artifact") or row["message"])
        if latest and latest_key in seen_latest:
            continue
        seen_latest.add(latest_key)
        skipped.append(
            {
                "created_at": row["created_at"],
                "tool_name": row_tool_name,
                "computer_id": row["computer_id"],
                "computer_label": row["computer_label"],
                "image_id": row["image_id"],
                "image_path": row["image_path"],
                "message": row["message"],
                "count": details.get("count"),
                "sample": details.get("sample", []),
            }
        )
        if len(skipped) >= limit:
            break
    return {"case_id": case_id, "skipped_reparse": skipped, "total_returned": len(skipped)}


def file_metadata_unresolved_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    tool_name: str | None = None,
    since: str | None = None,
    latest: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["activity_log.case_id = ?", "activity_log.event = 'artifact.path_unresolved'"]
    params: list[Any] = [case_id]
    if since:
        filters.append("activity_log.created_at >= ?")
        params.append(since)
    params.append(limit * 10 if latest else limit)
    rows = db.conn.execute(
        f"""
        SELECT activity_log.*, computers.label AS computer_label, images.path AS image_path
        FROM activity_log
        LEFT JOIN computers ON activity_log.computer_id = computers.id
        LEFT JOIN images ON activity_log.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY activity_log.created_at DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    unresolved = []
    seen_latest: set[str] = set()
    for row in rows:
        details = json.loads(row["details_json"] or "{}")
        row_tool_name = details.get("tool_name")
        if tool_name and row_tool_name != tool_name:
            continue
        latest_key = str(row_tool_name or details.get("artifact") or row["message"])
        if latest and latest_key in seen_latest:
            continue
        seen_latest.add(latest_key)
        unresolved.append(
            {
                "created_at": row["created_at"],
                "tool_name": row_tool_name,
                "computer_id": row["computer_id"],
                "computer_label": row["computer_label"],
                "image_id": row["image_id"],
                "image_path": row["image_path"],
                "message": row["message"],
                "count": details.get("count"),
                "deleted_count": details.get("deleted_count"),
                "sample": details.get("sample", []),
            }
        )
        if len(unresolved) >= limit:
            break
    return {"case_id": case_id, "path_unresolved": unresolved, "total_returned": len(unresolved)}


def file_metadata_deleted_skipped_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    tool_name: str | None = None,
    since: str | None = None,
    latest: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["activity_log.case_id = ?", "activity_log.event = 'artifact.skipped_deleted_mft'"]
    params: list[Any] = [case_id]
    if since:
        filters.append("activity_log.created_at >= ?")
        params.append(since)
    params.append(limit * 10 if latest else limit)
    rows = db.conn.execute(
        f"""
        SELECT activity_log.*, computers.label AS computer_label, images.path AS image_path
        FROM activity_log
        LEFT JOIN computers ON activity_log.computer_id = computers.id
        LEFT JOIN images ON activity_log.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY activity_log.created_at DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    skipped = []
    seen_latest: set[str] = set()
    for row in rows:
        details = json.loads(row["details_json"] or "{}")
        row_tool_name = details.get("tool_name")
        if tool_name and row_tool_name != tool_name:
            continue
        latest_key = str(row_tool_name or details.get("artifact") or row["message"])
        if latest and latest_key in seen_latest:
            continue
        seen_latest.add(latest_key)
        skipped.append(
            {
                "created_at": row["created_at"],
                "tool_name": row_tool_name,
                "computer_id": row["computer_id"],
                "computer_label": row["computer_label"],
                "image_id": row["image_id"],
                "image_path": row["image_path"],
                "message": row["message"],
                "count": details.get("count"),
                "sample": details.get("sample", []),
            }
        )
        if len(skipped) >= limit:
            break
    return {"case_id": case_id, "skipped_deleted_mft": skipped, "total_returned": len(skipped)}


def file_metadata_live_orphan_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    tool_name: str | None = None,
    since: str | None = None,
    latest: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["activity_log.case_id = ?", "activity_log.event = 'artifact.skipped_live_orphan'"]
    params: list[Any] = [case_id]
    if since:
        filters.append("activity_log.created_at >= ?")
        params.append(since)
    params.append(limit * 10 if latest else limit)
    rows = db.conn.execute(
        f"""
        SELECT activity_log.*, computers.label AS computer_label, images.path AS image_path
        FROM activity_log
        LEFT JOIN computers ON activity_log.computer_id = computers.id
        LEFT JOIN images ON activity_log.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY activity_log.created_at DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    skipped = []
    seen_latest: set[str] = set()
    for row in rows:
        details = json.loads(row["details_json"] or "{}")
        row_tool_name = details.get("tool_name")
        if tool_name and row_tool_name != tool_name:
            continue
        latest_key = str(row_tool_name or details.get("artifact") or row["message"])
        if latest and latest_key in seen_latest:
            continue
        seen_latest.add(latest_key)
        skipped.append(
            {
                "created_at": row["created_at"],
                "tool_name": row_tool_name,
                "computer_id": row["computer_id"],
                "computer_label": row["computer_label"],
                "image_id": row["image_id"],
                "image_path": row["image_path"],
                "message": row["message"],
                "count": details.get("count"),
                "sample": details.get("sample", []),
            }
        )
        if len(skipped) >= limit:
            break
    return {"case_id": case_id, "skipped_live_orphans": skipped, "total_returned": len(skipped)}


def file_metadata_summary_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT file_metadata_extraction_summaries.*, computers.label AS computer_label, images.path AS image_path
        FROM file_metadata_extraction_summaries
        LEFT JOIN computers ON file_metadata_extraction_summaries.computer_id = computers.id
        LEFT JOIN images ON file_metadata_extraction_summaries.image_id = images.id
        WHERE file_metadata_extraction_summaries.case_id = ?
        ORDER BY file_metadata_extraction_summaries.created_at DESC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {
        "case_id": case_id,
        "file_metadata_extraction_summaries": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def evtx_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "evtx_events", "events", limit)


def evtx_recovery_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT evtx_recovery.*, computers.label AS computer_label, images.path AS image_path
        FROM evtx_recovery
        LEFT JOIN computers ON evtx_recovery.computer_id = computers.id
        LEFT JOIN images ON evtx_recovery.image_id = images.id
        WHERE evtx_recovery.case_id = ?
        ORDER BY
          CASE evtx_recovery.status
            WHEN 'partial' THEN 0
            WHEN 'salvaged_partial' THEN 1
            WHEN 'extracted' THEN 2
            WHEN 'copied' THEN 3
            ELSE 4
          END,
          evtx_recovery.failed_block_count DESC,
          evtx_recovery.file_name
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    recovery = []
    for row in rows:
        item = dict(row)
        item["failed_offsets"] = json.loads(row["failed_offsets_json"])
        item["details"] = json.loads(row["details_json"])
        del item["failed_offsets_json"]
        del item["details_json"]
        recovery.append(item)
    counts = db.conn.execute(
        """
        SELECT status, COUNT(*) AS count
        FROM evtx_recovery
        WHERE case_id = ?
        GROUP BY status
        ORDER BY status
        """,
        (case_id,),
    ).fetchall()
    return {
        "case_id": case_id,
        "status_counts": [dict(row) for row in counts],
        "evtx_recovery": recovery,
        "total_returned": len(recovery),
    }


def recycle_report(db: Database, case_id: str, *, user: str | None = None, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    params: list[Any] = [case_id]
    user_filter = ""
    if user:
        user_filter = "AND (recycle_items.original_path LIKE ? OR recycle_items.source_path LIKE ?)"
        params.extend([f"%{user}%", f"%{user}%"])
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT recycle_items.*, computers.label AS computer_label, images.path AS image_path,
               (SELECT COUNT(*) FROM recycle_children
                WHERE recycle_children.case_id = recycle_items.case_id
                  AND recycle_children.image_id = recycle_items.image_id
                  AND recycle_children.top_level_name = recycle_items.top_level_name) AS child_count
        FROM recycle_items
        LEFT JOIN computers ON recycle_items.computer_id = computers.id
        LEFT JOIN images ON recycle_items.image_id = images.id
        WHERE recycle_items.case_id = ? {user_filter}
        ORDER BY recycle_items.deletion_time_utc, recycle_items.recycled_path
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {"case_id": case_id, "recycle_items": [dict(row) for row in rows], "total_returned": len(rows)}


def deleted_folders_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT recycle_children.case_id, recycle_children.computer_id, recycle_children.image_id,
               recycle_children.top_level_name, recycle_children.recycle_format,
               COUNT(*) AS child_count,
               MIN(recycle_children.mft_created) AS first_child_created,
               MAX(recycle_children.mft_modified) AS last_child_modified,
               computers.label AS computer_label, images.path AS image_path
        FROM recycle_children
        LEFT JOIN computers ON recycle_children.computer_id = computers.id
        LEFT JOIN images ON recycle_children.image_id = images.id
        WHERE recycle_children.case_id = ?
        GROUP BY recycle_children.case_id, recycle_children.computer_id, recycle_children.image_id,
                 recycle_children.top_level_name, recycle_children.recycle_format
        ORDER BY child_count DESC, top_level_name
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {"case_id": case_id, "deleted_folders": [dict(row) for row in rows], "total_returned": len(rows)}


def firefox_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "firefox_history", "history", limit)


def browser_report(db: Database, case_id: str, *, report_type: str = "history", limit: int = 100) -> dict[str, Any]:
    tables = {
        "history": ("browser_history", "history"),
        "downloads": ("browser_downloads", "downloads"),
        "cookies": ("browser_cookies", "cookies"),
        "artifacts": ("browser_artifacts", "artifacts"),
        "sessions": ("browser_session_entries", "sessions"),
        "site-settings": ("browser_site_settings", "site_settings"),
        "notifications": ("browser_notifications", "notifications"),
    }
    table, key = tables[report_type]
    return _table_report(db, case_id, table, key, limit)


def browser_artifacts_report(
    db: Database,
    case_id: str,
    *,
    artifact_type: str | None = None,
    browser: str | None = None,
    contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["browser_artifacts.case_id = ?", _artifact_duplicate_condition("browser_artifacts")]
    params: list[Any] = [case_id]
    if artifact_type:
        filters.append("browser_artifacts.artifact_type = ?")
        params.append(artifact_type)
    if browser:
        filters.append("LOWER(browser_artifacts.browser) = LOWER(?)")
        params.append(browser)
    if contains:
        filters.append(
            "(browser_artifacts.name LIKE ? OR browser_artifacts.value LIKE ? "
            "OR browser_artifacts.url LIKE ? OR browser_artifacts.title LIKE ? "
            "OR browser_artifacts.host LIKE ? OR browser_artifacts.details_json LIKE ?)"
        )
        params.extend([f"%{contains}%"] * 6)
    rows = db.conn.execute(
        f"""
        SELECT browser_artifacts.*, computers.label AS computer_label, images.path AS image_path,
               {_artifact_source_count_sql("browser_artifacts")} AS source_count
        FROM browser_artifacts
        LEFT JOIN computers ON browser_artifacts.computer_id = computers.id
        LEFT JOIN images ON browser_artifacts.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY COALESCE(browser_artifacts.timestamp_utc, browser_artifacts.created_at) DESC,
                 browser_artifacts.row_number DESC
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    counts = db.conn.execute(
        f"""
        SELECT browser, artifact_type, COUNT(*) AS count
        FROM browser_artifacts
        WHERE {' AND '.join(filters)}
        GROUP BY browser, artifact_type
        ORDER BY count DESC, browser, artifact_type
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "summary": {"artifact_counts": [dict(row) for row in counts]},
        "browser_artifacts": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def office_backstage_report(
    db: Database,
    case_id: str,
    *,
    contains: str | None = None,
    artifact_type: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["office_backstage_items.case_id = ?"]
    params: list[Any] = [case_id]
    if artifact_type:
        filters.append("office_backstage_items.artifact_type = ?")
        params.append(artifact_type)
    if contains:
        filters.append(
            "(office_backstage_items.name LIKE ? OR office_backstage_items.value LIKE ? "
            "OR office_backstage_items.path LIKE ? OR office_backstage_items.url LIKE ?)"
        )
        params.extend([f"%{contains}%"] * 4)
    rows = db.conn.execute(
        f"""
        SELECT office_backstage_items.*, computers.label AS computer_label, images.path AS image_path
        FROM office_backstage_items
        LEFT JOIN computers ON office_backstage_items.computer_id = computers.id
        LEFT JOIN images ON office_backstage_items.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY COALESCE(office_backstage_items.timestamp_utc, office_backstage_items.created_at) DESC,
                 office_backstage_items.row_number DESC
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    return {
        "case_id": case_id,
        "office_backstage_items": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def user_dictionaries_report(
    db: Database,
    case_id: str,
    *,
    user: str | None = None,
    contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["user_dictionary_words.case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("LOWER(COALESCE(user_dictionary_words.user_profile, '')) = LOWER(?)")
        params.append(user)
    if contains:
        filters.append("LOWER(COALESCE(user_dictionary_words.word, '')) LIKE LOWER(?)")
        params.append(f"%{contains}%")
    rows = db.conn.execute(
        f"""
        SELECT user_dictionary_words.*, computers.label AS computer_label, images.path AS image_path
        FROM user_dictionary_words
        LEFT JOIN computers ON user_dictionary_words.computer_id = computers.id
        LEFT JOIN images ON user_dictionary_words.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY user_dictionary_words.user_profile,
                 user_dictionary_words.source_path,
                 user_dictionary_words.word_index
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    counts = db.conn.execute(
        f"""
        SELECT user_profile, dictionary_name, COUNT(*) AS word_count
        FROM user_dictionary_words
        WHERE {' AND '.join(filters)}
        GROUP BY user_profile, dictionary_name
        ORDER BY user_profile, dictionary_name
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"user": user, "contains": contains},
        "summary": {"dictionary_counts": [dict(row) for row in counts]},
        "user_dictionary_words": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def uninstalled_application_artifacts_report(
    db: Database,
    case_id: str,
    *,
    application: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    installed_text = _installed_application_text(db, case_id)
    rows = []
    for candidate in _application_indicator_rows(db, case_id, APPLICATION_INDICATORS, limit=max(limit * 20, 500)):
        app = candidate["indicator"]
        if application and application.lower() not in app.lower():
            continue
        installed = _application_is_installed(app, installed_text)
        if installed:
            continue
        candidate.update(
            {
                "application": app,
                "status": "not_present_in_installed_application_inventory",
                "interpretation": (
                    "Artifact exists for this application, but no matching installed-application "
                    "registry/inventory row was found. Treat as an uninstalled-application or "
                    "portable-application lead and corroborate with filesystem timestamps."
                ),
            }
        )
        rows.append(candidate)
        if len(rows) >= limit:
            break
    return {
        "case_id": case_id,
        "filters": {"application": application},
        "uninstalled_application_artifacts": rows,
        "total_returned": len(rows),
    }


def tor_usage_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = _token_indicator_rows(
        db,
        case_id,
        [{"indicator": "Tor Browser", "tokens": TOR_TOKENS}],
        limit=limit,
        include_mft=False,
    )
    for row in rows:
        row["interpretation"] = (
            "Tor Browser indicator. Execution sources such as Prefetch, BAM/DAM, SRUM, "
            "and UserAssist should be correlated before treating this as confirmed use."
        )
        if row.get("source_table") == "registry_userassist":
            row["evidence_caveat"] = USERASSIST_CAVEAT
    return {"case_id": case_id, "tor_usage": rows, "total_returned": len(rows)}


def encrypted_volume_indicators_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = _token_indicator_rows(
        db,
        case_id,
        [{"indicator": item["type"], "tokens": item["tokens"]} for item in ENCRYPTED_VOLUME_INDICATORS],
        limit=limit,
        include_mft=True,
    )
    for row in rows:
        row["indicator_type"] = row.pop("indicator")
        row["interpretation"] = (
            "Encrypted volume/container indicator. File extensions alone are leads; "
            "prefer corroboration from execution, registry, event logs, mounted volumes, "
            "and filenames such as recovery keys."
        )
    return {"case_id": case_id, "encrypted_volume_indicators": rows, "total_returned": len(rows)}


def phone_link_report(
    db: Database,
    case_id: str,
    *,
    record_type: str | None = None,
    user: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["package_artifacts.case_id = ?"]
    params: list[Any] = [case_id]
    filters.append(
        "(LOWER(COALESCE(package_artifacts.application_package, '')) LIKE '%microsoft.yourphone%' "
        "OR package_artifacts.source_name = 'Microsoft Phone Link' "
        "OR package_artifacts.record_type LIKE 'phone_link_%')"
    )
    if record_type:
        filters.append("package_artifacts.record_type = ?")
        params.append(record_type)
    if user:
        filters.append("LOWER(COALESCE(package_artifacts.user_profile, '')) = LOWER(?)")
        params.append(user)
    rows = db.conn.execute(
        f"""
        SELECT package_artifacts.*, computers.label AS computer_label, images.path AS image_path
        FROM package_artifacts
        LEFT JOIN computers ON package_artifacts.computer_id = computers.id
        LEFT JOIN images ON package_artifacts.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY COALESCE(package_artifacts.event_time_utc, package_artifacts.modified_utc, package_artifacts.created_at) DESC,
                 package_artifacts.record_type,
                 package_artifacts.source_path
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    counts = db.conn.execute(
        f"""
        SELECT record_type, COUNT(*) AS count
        FROM package_artifacts
        WHERE {' AND '.join(filters)}
        GROUP BY record_type
        ORDER BY count DESC, record_type
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"record_type": record_type, "user": user},
        "summary": {"record_counts": [dict(row) for row in counts]},
        "phone_link_artifacts": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def virtualization_indicators_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = _token_indicator_rows(
        db,
        case_id,
        [{"indicator": item["platform"], "tokens": item["tokens"]} for item in VIRTUALIZATION_INDICATORS],
        limit=limit,
        include_mft=True,
    )
    for row in rows:
        row["platform"] = row.pop("indicator")
        row["interpretation"] = (
            "Virtualization indicator. This may represent installed virtualization software, "
            "guest additions/tools, or VM/container files such as VMDK/VDI/VHD."
        )
    return {"case_id": case_id, "virtualization_indicators": rows, "total_returned": len(rows)}


def _installed_application_text(db: Database, case_id: str) -> str:
    rows = db.conn.execute(
        """
        SELECT COALESCE(display_name, '') || ' ' || COALESCE(value_data, '') || ' ' ||
               COALESCE(normalized_path, '') || ' ' || COALESCE(notes, '') AS text
        FROM registry_artifacts
        WHERE case_id = ?
          AND artifact IN ('installed_applications', 'installed_app', 'uninstall')
        UNION ALL
        SELECT COALESCE(application, '') || ' ' || COALESCE(title, '') || ' ' ||
               COALESCE(path, '') || ' ' || COALESCE(artifact_text, '') AS text
        FROM telemetry_artifacts
        WHERE case_id = ?
          AND record_type IN ('installed_app', 'application_inventory')
        """,
        (case_id, case_id),
    ).fetchall()
    return "\n".join(str(row["text"] or "").lower() for row in rows)


def _application_is_installed(application: str, installed_text: str) -> bool:
    app_lower = application.lower()
    if app_lower in installed_text:
        return True
    for indicator in APPLICATION_INDICATORS:
        if indicator["application"].lower() != app_lower:
            continue
        return any(token.lower().strip(".") in installed_text for token in indicator["tokens"] if len(token.strip(".")) > 3)
    return False


def _application_indicator_rows(
    db: Database,
    case_id: str,
    indicators: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    normalized = [
        {"indicator": item.get("indicator") or item.get("application"), "tokens": item["tokens"]}
        for item in indicators
    ]
    return _token_indicator_rows(db, case_id, normalized, limit=limit, include_mft=True)


def _token_indicator_rows(
    db: Database,
    case_id: str,
    indicators: list[dict[str, Any]],
    *,
    limit: int,
    include_mft: bool,
) -> list[dict[str, Any]]:
    sources = _indicator_source_rows(db, case_id, include_mft=include_mft)
    matches: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in sources:
        text = _indicator_text(row).lower()
        if not text:
            continue
        for indicator in indicators:
            token = next((token for token in indicator["tokens"] if token.lower() in text), "")
            if not token:
                continue
            item = {
                **row,
                "indicator": indicator["indicator"],
                "matched_token": token,
            }
            key = (
                item.get("indicator"),
                item.get("source_table"),
                item.get("source_id"),
                item.get("matched_token"),
            )
            if key in seen:
                continue
            seen.add(key)
            matches.append(item)
            break
    matches.sort(
        key=lambda row: (
            _indicator_priority(row.get("source_table")),
            str(row.get("event_time_utc") or row.get("timestamp_utc") or row.get("modified_utc") or ""),
            str(row.get("path") or row.get("name") or ""),
        ),
        reverse=False,
    )
    return matches[:limit]


def _indicator_source_rows(db: Database, case_id: str, *, include_mft: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(_indicator_query(
        db,
        """
        SELECT id AS source_id, 'prefetch_items' AS source_table,
               executable_name AS name,
               COALESCE(original_path, artifact_path, referenced_strings) AS path,
               last_run_time_utc AS event_time_utc,
               NULL AS user_profile,
               COALESCE(prefetch_name, '') || ' ' || COALESCE(executable_name, '') || ' ' ||
               COALESCE(original_path, '') || ' ' || COALESCE(artifact_path, '') || ' ' ||
               COALESCE(referenced_strings, '') AS text
        FROM prefetch_items WHERE case_id = ?
        """,
        case_id,
    ))
    rows.extend(_indicator_query(
        db,
        """
        SELECT id AS source_id, 'registry_artifacts' AS source_table,
               COALESCE(display_name, value_name, artifact) AS name,
               COALESCE(normalized_path, value_data, key_path) AS path,
               COALESCE(event_time_utc, key_last_write_utc) AS event_time_utc,
               user_profile,
               COALESCE(artifact, '') || ' ' || COALESCE(display_name, '') || ' ' ||
               COALESCE(normalized_path, '') || ' ' || COALESCE(value_name, '') || ' ' ||
               COALESCE(value_data, '') || ' ' || COALESCE(key_path, '') || ' ' ||
               COALESCE(notes, '') AS text
        FROM registry_artifacts WHERE case_id = ?
        """,
        case_id,
    ))
    rows.extend(_indicator_query(
        db,
        """
        SELECT id AS source_id, 'registry_userassist' AS source_table,
               program_name AS name,
               COALESCE(program_name, key_path) AS path,
               last_executed AS event_time_utc,
               user_profile,
               COALESCE(program_name, '') || ' ' || COALESCE(key_path, '') AS text
        FROM registry_userassist WHERE case_id = ?
        """,
        case_id,
    ))
    rows.extend(_indicator_query(
        db,
        """
        SELECT id AS source_id, 'srum_records' AS source_table,
               COALESCE(app_name, app_id) AS name,
               app_path AS path,
               timestamp AS event_time_utc,
               user_name AS user_profile,
               COALESCE(app_name, '') || ' ' || COALESCE(app_id, '') || ' ' ||
               COALESCE(app_path, '') || ' ' || COALESCE(app_description, '') AS text
        FROM srum_records WHERE case_id = ?
        """,
        case_id,
    ))
    rows.extend(_indicator_query(
        db,
        """
        SELECT id AS source_id, 'package_artifacts' AS source_table,
               COALESCE(source_name, application_package, file_name) AS name,
               source_path AS path,
               COALESCE(event_time_utc, modified_utc) AS event_time_utc,
               user_profile,
               COALESCE(source_name, '') || ' ' || COALESCE(application_package, '') || ' ' ||
               COALESCE(file_name, '') || ' ' || COALESCE(source_path, '') || ' ' ||
               COALESCE(title, '') || ' ' || COALESCE(artifact_value, '') || ' ' ||
               COALESCE(artifact_text, '') AS text
        FROM package_artifacts WHERE case_id = ?
        """,
        case_id,
    ))
    rows.extend(_indicator_query(
        db,
        """
        SELECT id AS source_id, 'browser_artifacts' AS source_table,
               COALESCE(browser, artifact_type) AS name,
               COALESCE(url, value, profile_path) AS path,
               timestamp_utc AS event_time_utc,
               NULL AS user_profile,
               COALESCE(browser, '') || ' ' || COALESCE(artifact_type, '') || ' ' ||
               COALESCE(profile_path, '') || ' ' || COALESCE(url, '') || ' ' ||
               COALESCE(title, '') || ' ' || COALESCE(value, '') AS text
        FROM browser_artifacts WHERE case_id = ?
        """,
        case_id,
    ))
    if include_mft:
        rows.extend(_indicator_query(
            db,
            """
            SELECT id AS source_id, 'mft_entries' AS source_table,
                   file_name AS name,
                   COALESCE(parent_path, '') || CASE
                     WHEN COALESCE(parent_path, '') = '' THEN ''
                     WHEN substr(parent_path, -1) IN ('\\', '/') THEN ''
                     ELSE '\\'
                   END || COALESCE(file_name, '') AS path,
                   COALESCE(modified_si, created_si, record_changed_si) AS event_time_utc,
                   NULL AS user_profile,
                   COALESCE(parent_path, '') || ' ' || COALESCE(file_name, '') || ' ' ||
                   COALESCE(extension, '') || ' ' || COALESCE(reparse_target, '') AS text
            FROM mft_entries WHERE case_id = ?
            """,
            case_id,
        ))
    return rows


def _indicator_query(db: Database, sql: str, case_id: str) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in db.conn.execute(sql, (case_id,)).fetchall()]
    except Exception:
        return []


def _indicator_text(row: dict[str, Any]) -> str:
    return " ".join(str(row.get(key) or "") for key in ("text", "name", "path", "user_profile"))


def _indicator_priority(source_table: Any) -> int:
    priorities = {
        "prefetch_items": 0,
        "registry_artifacts": 1,
        "registry_userassist": 2,
        "srum_records": 3,
        "package_artifacts": 4,
        "browser_artifacts": 5,
        "mft_entries": 6,
    }
    return priorities.get(str(source_table), 99)


def downloaded_files_report(
    db: Database,
    case_id: str,
    *,
    user: str | None = None,
    contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["zone_identifier_ads.case_id = ?", "zone_identifier_ads.zone_id = '3'"]
    params: list[Any] = [case_id]
    if user:
        filters.append("LOWER(COALESCE(zone_identifier_ads.user_profile, '')) = LOWER(?)")
        params.append(user)
    if contains:
        filters.append(
            "("
            "LOWER(COALESCE(zone_identifier_ads.file_path, '')) LIKE LOWER(?) OR "
            "LOWER(COALESCE(zone_identifier_ads.host_url, '')) LIKE LOWER(?) OR "
            "LOWER(COALESCE(zone_identifier_ads.referrer_url, '')) LIKE LOWER(?)"
            ")"
        )
        needle = f"%{contains}%"
        params.extend([needle, needle, needle])
    rows = db.conn.execute(
        f"""
        SELECT zone_identifier_ads.*, computers.label AS computer_label, images.path AS image_path
        FROM zone_identifier_ads
        LEFT JOIN computers ON zone_identifier_ads.computer_id = computers.id
        LEFT JOIN images ON zone_identifier_ads.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY zone_identifier_ads.timestamp_utc DESC,
                 zone_identifier_ads.user_profile,
                 zone_identifier_ads.file_path
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    hosts = db.conn.execute(
        f"""
        SELECT COALESCE(NULLIF(host, ''), NULLIF(referrer_host, ''), '(unknown)') AS host,
               COUNT(*) AS downloaded_file_count
        FROM zone_identifier_ads
        WHERE {' AND '.join(filters)}
        GROUP BY COALESCE(NULLIF(host, ''), NULLIF(referrer_host, ''), '(unknown)')
        ORDER BY downloaded_file_count DESC, host
        LIMIT 25
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"user": user, "contains": contains, "zone_id": "3"},
        "summary": {"top_hosts": [dict(row) for row in hosts]},
        "downloaded_files": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def thumbcache_report(
    db: Database,
    case_id: str,
    *,
    user: str | None = None,
    confidence: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["te.case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        where.append("LOWER(COALESCE(te.user_profile, '')) = LOWER(?)")
        params.append(user)
    if confidence:
        where.append("LOWER(COALESCE(tsc.confidence, '')) = LOWER(?)")
        params.append(confidence)
    rows = db.conn.execute(
        f"""
        SELECT te.user_profile, te.source_name, te.cache_file_type, te.cache_id,
               te.entry_index, te.thumbnail_type, te.thumbnail_size,
               te.thumbnail_sha256, te.source_mtime_utc, te.parser_status,
               te.parser_note, tsc.correlation_basis, tsc.confidence,
               tsc.search_item_path, tsc.search_file_name,
               tsc.search_date_created, tsc.search_date_modified,
               tsc.search_date_accessed, tsc.search_date_imported,
               te.source_path, te.id AS thumbcache_entry_id,
               tsc.id AS correlation_id
        FROM thumbcache_entries AS te
        LEFT JOIN thumbcache_search_correlations AS tsc
          ON tsc.thumbcache_entry_id = te.id
        WHERE {' AND '.join(where)}
        ORDER BY te.user_profile, te.source_name,
                 CAST(COALESCE(te.entry_index, '0') AS INTEGER),
                 tsc.confidence DESC, tsc.search_item_path
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    counts = db.conn.execute(
        """
        SELECT
          COUNT(*) AS entries,
          SUM(CASE WHEN parser_status = 'parsed' THEN 1 ELSE 0 END) AS parsed_entries
        FROM thumbcache_entries
        WHERE case_id = ?
        """,
        (case_id,),
    ).fetchone()
    correlation_counts = db.conn.execute(
        """
        SELECT COALESCE(confidence, '<none>') AS confidence, COUNT(*) AS count
        FROM thumbcache_search_correlations
        WHERE case_id = ?
        GROUP BY COALESCE(confidence, '<none>')
        ORDER BY count DESC, confidence
        """,
        (case_id,),
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"user": user, "confidence": confidence},
        "summary": dict(counts) if counts else {"entries": 0, "parsed_entries": 0},
        "correlation_counts": [dict(row) for row in correlation_counts],
        "thumbcache": [dict(row) for row in rows],
        "total_returned": len(rows),
        "caveats": [
            "Thumbcache entries usually do not carry original filenames by themselves.",
            "High-confidence rows require a matching Windows Search thumbnail/cache property; low-confidence rows are same-user image candidates.",
        ],
    }


def rdp_cache_report(
    db: Database,
    case_id: str,
    *,
    user: str | None = None,
    record_type: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        where.append("LOWER(COALESCE(user_profile, '')) = LOWER(?)")
        params.append(user)
    if record_type:
        where.append("LOWER(COALESCE(record_type, '')) = LOWER(?)")
        params.append(record_type)
    rows = _query_report_rows(
        db,
        case_id,
        "rdp_cache_items",
        f"""
        SELECT *
        FROM rdp_cache_items
        WHERE {' AND '.join(where)}
        ORDER BY user_profile, source_cache_path, CAST(COALESCE(fragment_index, '0') AS INTEGER), record_type
        LIMIT ?
        """,
        [*params, limit],
    )
    counts = _query_report_rows(
        db,
        case_id,
        "rdp_cache_items",
        """
        SELECT COALESCE(record_type, '<none>') AS record_type, COUNT(*) AS count
        FROM rdp_cache_items
        WHERE case_id = ?
        GROUP BY COALESCE(record_type, '<none>')
        ORDER BY count DESC, record_type
        """,
        (case_id,),
    )
    return {
        "case_id": case_id,
        "filters": {"user": user, "record_type": record_type},
        "record_type_counts": [dict(row) for row in counts],
        "rdp_cache": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def image_analysis_report(
    db: Database,
    case_id: str,
    *,
    source_artifact_type: str | None = None,
    contains: str | None = None,
    ocr_only: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if source_artifact_type:
        where.append("LOWER(COALESCE(source_artifact_type, '')) = LOWER(?)")
        params.append(source_artifact_type)
    if contains:
        like = f"%{contains.lower()}%"
        where.append("(LOWER(COALESCE(source_path, '')) LIKE ? OR LOWER(COALESCE(output_path, '')) LIKE ? OR LOWER(COALESCE(file_name, '')) LIKE ?)")
        params.extend([like, like, like])
    if ocr_only:
        where.append("COALESCE(ocr_text, '') != ''")
    rows = _query_report_rows(
        db,
        case_id,
        "image_analysis_items",
        f"""
        SELECT *
        FROM image_analysis_items
        WHERE {' AND '.join(where)}
        ORDER BY source_artifact_type, file_name, row_number
        LIMIT ?
        """,
        [*params, limit],
    )
    counts = _query_report_rows(
        db,
        case_id,
        "image_analysis_items",
        """
        SELECT COALESCE(source_artifact_type, '<none>') AS source_artifact_type, COUNT(*) AS count
        FROM image_analysis_items
        WHERE case_id = ?
        GROUP BY COALESCE(source_artifact_type, '<none>')
        ORDER BY count DESC, source_artifact_type
        """,
        (case_id,),
    )
    return {
        "case_id": case_id,
        "filters": {
            "source_artifact_type": source_artifact_type,
            "contains": contains,
            "ocr_only": ocr_only,
        },
        "source_type_counts": [dict(row) for row in counts],
        "image_analysis": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def rdp_visual_observations_report(
    db: Database,
    case_id: str,
    *,
    user: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        where.append("LOWER(COALESCE(user_profile, '')) = LOWER(?)")
        params.append(user)
    rows = _query_report_rows(
        db,
        case_id,
        "rdp_visual_observations",
        f"""
        SELECT *
        FROM rdp_visual_observations
        WHERE {' AND '.join(where)}
        ORDER BY observation_time_utc, user_profile, observed_application, observed_text
        LIMIT ?
        """,
        [*params, limit],
    )
    observations = [_annotate_rdp_visual_observation(dict(row)) for row in rows]
    counts = _query_report_rows(
        db,
        case_id,
        "rdp_visual_observations",
        """
        SELECT COALESCE(observed_application, '<none>') AS observed_application,
               COUNT(*) AS count
        FROM rdp_visual_observations
        WHERE case_id = ?
        GROUP BY COALESCE(observed_application, '<none>')
        ORDER BY count DESC, observed_application
        """,
        (case_id,),
    )
    return {
        "case_id": case_id,
        "filters": {"user": user},
        "application_counts": [dict(row) for row in counts],
        "rdp_visual_observations": observations,
        "total_returned": len(observations),
        "caveat": "RDP cache visual observations show what appeared in cached remote screen tiles/contact sheets. They are corroborating visual evidence, not proof of application execution by themselves.",
    }


def browser_downloads_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT browser_downloads.*, computers.label AS computer_label, images.path AS image_path
        FROM browser_downloads
        LEFT JOIN computers ON browser_downloads.computer_id = computers.id
        LEFT JOIN images ON browser_downloads.image_id = images.id
        WHERE browser_downloads.case_id = ?
        ORDER BY COALESCE(browser_downloads.start_time_utc, browser_downloads.end_time_utc) DESC,
                 browser_downloads.row_number DESC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    downloads = []
    for row in rows:
        item = dict(row)
        item["downloaded_file_name"] = _basename(item.get("target_path"))
        item["mft_matches"] = _mft_matches_for_path(db, case_id, item.get("image_id"), item.get("target_path"))
        item["usb_file_matches"] = _usb_matches_for_path(db, case_id, item.get("target_path"))
        downloads.append(item)
    return {"case_id": case_id, "downloads": downloads, "total_returned": len(downloads)}


def browser_cache_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    browser: str | None = None,
    host: str | None = None,
    exclude_noise: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["browser_cache_entries.case_id = ?"]
    params: list[Any] = [case_id]
    if browser:
        where.append("LOWER(browser_cache_entries.browser) = LOWER(?)")
        params.append(browser)
    if host:
        where.append("LOWER(COALESCE(browser_cache_entries.host, '')) LIKE LOWER(?)")
        params.append(f"%{host}%")
    if exclude_noise:
        where.append(_browser_noise_filter_sql("browser_cache_entries.host", "browser_cache_entries.url"))
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT browser_cache_entries.*, computers.label AS computer_label, images.path AS image_path
        FROM browser_cache_entries
        LEFT JOIN computers ON browser_cache_entries.computer_id = computers.id
        LEFT JOIN images ON browser_cache_entries.image_id = images.id
        WHERE {' AND '.join(where)}
        ORDER BY COALESCE(browser_cache_entries.cache_file_modified_utc, browser_cache_entries.created_at) DESC,
                 browser_cache_entries.row_number DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"browser": browser, "host": host, "exclude_noise": exclude_noise},
        "cache_entries": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def browser_hosts_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    browser: str | None = None,
    exclude_noise: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    union_filters = []
    params: list[Any] = []
    sources = (
        ("browser_history", "host_from_url(browser_history.url)", "browser_history.url"),
        (
            "browser_downloads",
            "host_from_url(COALESCE(browser_downloads.tab_url, browser_downloads.site_url, browser_downloads.referrer))",
            "COALESCE(browser_downloads.tab_url, browser_downloads.site_url, browser_downloads.referrer)",
        ),
        ("browser_cache_entries", "browser_cache_entries.host", "browser_cache_entries.url"),
        ("webcache_entries", "webcache_entries.host", "webcache_entries.url"),
    )
    for alias, host_expr, url_expr in sources:
        filters = [f"{alias}.case_id = ?"]
        params.append(case_id)
        if browser and alias.startswith("browser_"):
            filters.append(f"LOWER({alias}.browser) = LOWER(?)")
            params.append(browser)
        if exclude_noise:
            filters.append(_browser_noise_filter_sql(host_expr, url_expr))
        union_filters.append(" AND ".join(filters))
    params.append(limit)
    rows = db.conn.execute(
        f"""
        WITH browser_events AS (
          SELECT browser AS browser, profile_path AS profile_path,
                 LOWER(COALESCE(NULLIF(host_from_url(url), ''), '')) AS host,
                 visit_time_utc AS timestamp_utc,
                 'browser_history' AS source
          FROM browser_history
          WHERE {union_filters[0]}
          UNION ALL
          SELECT browser, profile_path,
                 LOWER(COALESCE(NULLIF(host_from_url(COALESCE(tab_url, site_url, referrer)), ''), '')) AS host,
                 COALESCE(start_time_utc, end_time_utc) AS timestamp_utc,
                 'browser_downloads' AS source
          FROM browser_downloads
          WHERE {union_filters[1]}
          UNION ALL
          SELECT browser, profile_path, LOWER(COALESCE(host, '')) AS host,
                 cache_file_modified_utc AS timestamp_utc,
                 'browser_cache_entries' AS source
          FROM browser_cache_entries
          WHERE {union_filters[2]}
          UNION ALL
          SELECT application AS browser, user_name AS profile_path, LOWER(COALESCE(host, host_from_url(url), '')) AS host,
                 COALESCE(accessed_utc, modified_utc, created_utc) AS timestamp_utc,
                 'webcache_entries' AS source
          FROM webcache_entries
          WHERE {union_filters[3]}
        )
        SELECT browser, profile_path, host,
               COUNT(*) AS reference_count,
               MIN(timestamp_utc) AS first_seen_utc,
               MAX(timestamp_utc) AS last_seen_utc,
               GROUP_CONCAT(DISTINCT source) AS sources
        FROM browser_events
        WHERE host != ''
        GROUP BY browser, profile_path, host
        ORDER BY reference_count DESC, last_seen_utc DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"browser": browser, "exclude_noise": exclude_noise},
        "hosts": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def browser_activity_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    browser: str | None = None,
    user: str | None = None,
    exclude_noise: bool = True,
) -> dict[str, Any]:
    hosts = browser_hosts_report(db, case_id, limit=limit, browser=browser, exclude_noise=exclude_noise)["hosts"]
    downloads = browser_downloads_report(db, case_id, limit=limit)["downloads"]
    if browser:
        downloads = [row for row in downloads if (row.get("browser") or "").lower() == browser.lower()]
    if user:
        downloads = [row for row in downloads if user.lower() in (row.get("profile_path") or "").lower()]
    webcache_files = webcache_files_report(db, case_id, limit=limit, user=user)["file_accesses"]
    cache_correlations = browser_cache_correlations_report(
        db, case_id, limit=limit, browser=browser, exclude_noise=exclude_noise
    )["correlations"]
    return {
        "case_id": case_id,
        "filters": {"browser": browser, "user": user, "exclude_noise": exclude_noise},
        "top_hosts": hosts,
        "downloads": downloads[:limit],
        "webcache_file_accesses": webcache_files[:limit],
        "cache_correlations": cache_correlations[:limit],
    }


def browser_profile_activity_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        WITH browser_events AS (
          SELECT browser, profile_path, 'history' AS artifact_type, visit_time_utc AS event_time
          FROM browser_history
          WHERE case_id = ?
          UNION ALL
          SELECT browser, profile_path, 'download' AS artifact_type, COALESCE(start_time_utc, end_time_utc) AS event_time
          FROM browser_downloads
          WHERE case_id = ?
          UNION ALL
          SELECT browser, profile_path, artifact_type, timestamp_utc AS event_time
          FROM browser_artifacts
          WHERE case_id = ?
          UNION ALL
          SELECT browser, profile_path, 'session' AS artifact_type, COALESCE(timestamp_utc, last_active_time_utc) AS event_time
          FROM browser_session_entries
          WHERE case_id = ?
          UNION ALL
          SELECT browser, profile_path, 'site_setting' AS artifact_type, last_modified_utc AS event_time
          FROM browser_site_settings
          WHERE case_id = ?
          UNION ALL
          SELECT browser, profile_path, 'notification' AS artifact_type,
                 COALESCE(notification_timestamp_utc, created_utc, first_click_utc, last_click_utc, closed_utc, created_at) AS event_time
          FROM browser_notifications
          WHERE case_id = ?
          UNION ALL
          SELECT browser, profile_path, 'cache' AS artifact_type, cache_file_modified_utc AS event_time
          FROM browser_cache_entries
          WHERE case_id = ?
        )
        SELECT COALESCE(browser, 'unknown') AS browser,
               COALESCE(profile_path, '') AS profile_path,
               COUNT(*) AS artifact_count,
               SUM(CASE WHEN artifact_type = 'history' THEN 1 ELSE 0 END) AS history_count,
               SUM(CASE WHEN artifact_type = 'download' THEN 1 ELSE 0 END) AS download_count,
               SUM(CASE WHEN artifact_type = 'session' THEN 1 ELSE 0 END) AS session_count,
               SUM(CASE WHEN artifact_type = 'site_setting' THEN 1 ELSE 0 END) AS site_setting_count,
               SUM(CASE WHEN artifact_type = 'notification' THEN 1 ELSE 0 END) AS notification_count,
               SUM(CASE WHEN artifact_type = 'cache' THEN 1 ELSE 0 END) AS cache_count,
               MIN(event_time) AS first_seen_utc,
               MAX(event_time) AS last_seen_utc,
               GROUP_CONCAT(DISTINCT artifact_type) AS artifact_types
        FROM browser_events
        GROUP BY COALESCE(browser, 'unknown'), COALESCE(profile_path, '')
        ORDER BY artifact_count DESC, last_seen_utc DESC
        LIMIT ?
        """,
        (case_id, case_id, case_id, case_id, case_id, case_id, case_id, limit),
    ).fetchall()
    return {
        "case_id": case_id,
        "profiles": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def browser_deep_storage_report(db: Database, case_id: str, *, limit: int = 250) -> dict[str, Any]:
    db.get_case(case_id)
    items: list[dict[str, Any]] = []
    artifact_rows = _query_report_rows(
        db,
        case_id,
        "browser_artifacts",
        """
        SELECT
          'browser_artifacts' AS source_table,
          artifact_type AS storage_type,
          browser,
          profile_path,
          source_path,
          name,
          value,
          url,
          host,
          timestamp_utc AS event_time_utc,
          source_csv,
          row_number
        FROM browser_artifacts
        WHERE case_id = ?
          AND (
            lower(coalesce(artifact_type, '')) LIKE '%leveldb%'
            OR lower(coalesce(artifact_type, '')) LIKE '%sync%'
            OR lower(coalesce(source_path, '')) LIKE '%leveldb%'
            OR lower(coalesce(source_path, '')) LIKE '%indexeddb%'
            OR lower(coalesce(source_path, '')) LIKE '%service worker%'
          )
        ORDER BY event_time_utc DESC
        LIMIT ?
        """,
        (case_id, limit),
    )
    for row in artifact_rows:
        row["classification"] = _browser_storage_classification(row)
        items.append(row)
    for table, sql in (
        (
            "browser_session_entries",
            """
            SELECT 'browser_session_entries' AS source_table, 'session' AS storage_type,
                   browser, profile_path, source_path, title AS name, NULL AS value, url, host,
                   COALESCE(timestamp_utc, last_active_time_utc) AS event_time_utc, source_csv, row_number
            FROM browser_session_entries
            WHERE case_id = ?
            ORDER BY event_time_utc DESC
            LIMIT ?
            """,
        ),
        (
            "browser_site_settings",
            """
            SELECT 'browser_site_settings' AS source_table, 'site_setting' AS storage_type,
                   browser, profile_path, source_path, setting_name AS name, setting_value AS value,
                   origin AS url, host, last_modified_utc AS event_time_utc, source_csv, row_number
            FROM browser_site_settings
            WHERE case_id = ?
            ORDER BY event_time_utc DESC
            LIMIT ?
            """,
        ),
        (
            "browser_notifications",
            """
            SELECT 'browser_notifications' AS source_table, 'notification' AS storage_type,
                   browser, profile_path, source_path, title AS name, body AS value,
                   origin AS url, host,
                   COALESCE(notification_timestamp_utc, created_utc, first_click_utc, last_click_utc, closed_utc) AS event_time_utc,
                   source_csv, row_number
            FROM browser_notifications
            WHERE case_id = ?
            ORDER BY event_time_utc DESC
            LIMIT ?
            """,
        ),
    ):
        rows = _query_report_rows(db, case_id, table, sql, (case_id, limit))
        for row in rows:
            row["classification"] = _browser_storage_classification(row)
            items.append(row)
    messaging_rows = _query_report_rows(
        db,
        case_id,
        "messaging_records",
        """
        SELECT 'messaging_records' AS source_table, artifact_type AS storage_type,
               application AS browser, store_path AS profile_path, source_path,
               record_key AS name, NULL AS value, url, host, timestamp_utc AS event_time_utc,
               source_csv, row_number
        FROM messaging_records
        WHERE case_id = ?
          AND lower(coalesce(artifact_type, '') || ' ' || coalesce(source_path, '') || ' ' || coalesce(store_path, '')) LIKE '%leveldb%'
        ORDER BY event_time_utc DESC
        LIMIT ?
        """,
        (case_id, limit),
    )
    for row in messaging_rows:
        row["classification"] = "electron_leveldb_candidate"
        items.append(row)
    items = sorted(items, key=lambda row: str(row.get("event_time_utc") or ""), reverse=True)[:limit]
    counts: dict[str, int] = {}
    for item in items:
        key = str(item.get("classification") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return {
        "case_id": case_id,
        "summary": {
            "classification_counts": [
                {"classification": key, "count": value}
                for key, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            ],
            "interpretation_note": "This inventories parsed browser deep-storage artefacts and LevelDB/IndexedDB candidates; it does not copy raw browser database contents into DuckDB.",
        },
        "items": items,
        "total_returned": len(items),
    }


def _browser_storage_classification(row: dict[str, Any]) -> str:
    text = " ".join(str(row.get(key) or "") for key in ("storage_type", "source_path", "profile_path")).lower()
    if "leveldb" in text:
        return "leveldb_candidate"
    if "indexeddb" in text:
        return "indexeddb_candidate"
    if "service worker" in text:
        return "service_worker_storage"
    if "sync" in text:
        return "browser_sync"
    if "notification" in text:
        return "notification"
    if "site_setting" in text:
        return "site_setting"
    if "session" in text:
        return "session_restore"
    return "browser_storage"


def browser_cache_correlations_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    browser: str | None = None,
    exclude_noise: bool = True,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["cache.case_id = ?"]
    params: list[Any] = [case_id]
    if browser:
        filters.append("LOWER(cache.browser) = LOWER(?)")
        params.append(browser)
    if exclude_noise:
        filters.append(_browser_noise_filter_sql("cache.host", "cache.url"))
    params.append(case_id)
    params.append(case_id)
    params.append(limit)
    rows = db.conn.execute(
        f"""
        WITH cache AS (
          SELECT *, LOWER(COALESCE(host, host_from_url(url), '')) AS cache_host
          FROM browser_cache_entries cache
          WHERE {' AND '.join(filters)}
        ),
        history_hosts AS (
          SELECT browser, profile_path, LOWER(COALESCE(host_from_url(url), '')) AS host,
                 MIN(visit_time_utc) AS first_history_utc,
                 MAX(visit_time_utc) AS last_history_utc,
                 COUNT(*) AS history_count
          FROM browser_history
          WHERE case_id = ?
          GROUP BY browser, profile_path, host
        ),
        download_hosts AS (
          SELECT browser, profile_path,
                 LOWER(COALESCE(host_from_url(COALESCE(tab_url, site_url, referrer)), '')) AS host,
                 MIN(COALESCE(start_time_utc, end_time_utc)) AS first_download_utc,
                 MAX(COALESCE(start_time_utc, end_time_utc)) AS last_download_utc,
                 COUNT(*) AS download_count
          FROM browser_downloads
          WHERE case_id = ?
          GROUP BY browser, profile_path, host
        )
        SELECT cache.browser, cache.profile_path, cache.cache_host AS host,
               COUNT(*) AS cache_reference_count,
               MIN(cache.cache_file_modified_utc) AS first_cache_utc,
               MAX(cache.cache_file_modified_utc) AS last_cache_utc,
               COALESCE(MAX(history_hosts.history_count), 0) AS history_count,
               MAX(history_hosts.first_history_utc) AS first_history_utc,
               MAX(history_hosts.last_history_utc) AS last_history_utc,
               COALESCE(MAX(download_hosts.download_count), 0) AS download_count,
               MAX(download_hosts.first_download_utc) AS first_download_utc,
               MAX(download_hosts.last_download_utc) AS last_download_utc,
               CASE
                 WHEN COALESCE(MAX(history_hosts.history_count), 0) > 0
                   OR COALESCE(MAX(download_hosts.download_count), 0) > 0
                 THEN 'corroborates_known_activity'
                 ELSE 'cache_only_reference'
               END AS interpretation
        FROM cache
        LEFT JOIN history_hosts
          ON history_hosts.browser = cache.browser
         AND history_hosts.profile_path = cache.profile_path
         AND history_hosts.host = cache.cache_host
        LEFT JOIN download_hosts
          ON download_hosts.browser = cache.browser
         AND download_hosts.profile_path = cache.profile_path
         AND download_hosts.host = cache.cache_host
        WHERE cache.cache_host != ''
        GROUP BY cache.browser, cache.profile_path, cache.cache_host
        ORDER BY interpretation, cache_reference_count DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"browser": browser, "exclude_noise": exclude_noise},
        "correlations": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def windows_activities_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
    app: str | None = None,
    include_auxiliary: bool = False,
    files_only: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["windows_activities.case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("LOWER(COALESCE(windows_activities.user_profile, '')) LIKE LOWER(?)")
        params.append(f"%{user}%")
    if app:
        filters.append(
            "(LOWER(COALESCE(windows_activities.app_display_name, '')) LIKE LOWER(?) "
            "OR LOWER(COALESCE(windows_activities.app_id, '')) LIKE LOWER(?))"
        )
        params.extend([f"%{app}%", f"%{app}%"])
    if not include_auxiliary:
        filters.append("windows_activities.source_table = 'Activity'")
    if files_only:
        filters.append(
            """
            (
              COALESCE(windows_activities.file_name, '') != ''
              OR COALESCE(windows_activities.content_uri, '') != ''
              OR COALESCE(windows_activities.activation_uri, '') LIKE '%/%'
              OR COALESCE(windows_activities.fallback_uri, '') LIKE '%/%'
            )
            """
        )
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT windows_activities.*, computers.label AS computer_label, images.path AS image_path
        FROM windows_activities
        LEFT JOIN computers ON windows_activities.computer_id = computers.id
        LEFT JOIN images ON windows_activities.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY COALESCE(windows_activities.start_time_utc, windows_activities.last_modified_utc, windows_activities.created_at) DESC,
                 windows_activities.row_number DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"user": user, "app": app, "include_auxiliary": include_auxiliary, "files_only": files_only},
        "activities": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def webcache_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    application: str | None = None,
    user: str | None = None,
    local_files_only: bool = False,
    exclude_metadata: bool = False,
) -> dict[str, Any]:
    table = "webcache_file_accesses" if local_files_only else "webcache_entries"
    key = "file_accesses" if local_files_only else "webcache_entries"
    return _webcache_filtered_report(
        db,
        case_id,
        table=table,
        key=key,
        limit=limit,
        application=application,
        user=user,
        exclude_metadata=exclude_metadata,
    )


def webcache_files_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    application: str | None = None,
    user: str | None = None,
    usb_overlap: bool = False,
) -> dict[str, Any]:
    report = _webcache_filtered_report(
        db,
        case_id,
        table="webcache_file_accesses",
        key="file_accesses",
        limit=limit,
        application=application,
        user=user,
        exclude_metadata=False,
    )
    if usb_overlap:
        for row in report["file_accesses"]:
            row["usb_overlaps"] = _usb_overlaps_for_time(
                db,
                case_id,
                row.get("image_id"),
                row.get("accessed_utc") or row.get("modified_utc") or row.get("created_utc"),
                row.get("local_path"),
            )
    return report


def user_timeline_report(
    db: Database,
    case_id: str,
    *,
    user: str,
    limit: int = 250,
    include_expiry: bool = False,
    include_metadata: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    user_like = f"%{user}%"
    expiry_filter = "" if include_expiry else "AND timeline_events.event_type NOT LIKE '%expires'"
    metadata_filter = "" if include_metadata else """
          AND NOT (
            timeline_events.source_tool = 'WebCacheParser'
            AND timeline_events.source_table = 'webcache_entries'
            AND (
              timeline_events.details_json LIKE '%shared_webcache_table%'
              OR timeline_events.details_json LIKE '%MicrosoftEdge_iecompat:%'
              OR timeline_events.details_json LIKE '%MicrosoftEdge_iecompatua:%'
              OR timeline_events.details_json LIKE '%MicrosoftEdge_ieflipahead:%'
            )
          )
    """
    rows = db.conn.execute(
        f"""
        SELECT timeline_events.*, computers.label AS computer_label, images.path AS image_path
        FROM timeline_events
        LEFT JOIN computers ON timeline_events.computer_id = computers.id
        LEFT JOIN images ON timeline_events.image_id = images.id
        WHERE timeline_events.case_id = ?
          AND timeline_events.dedupe_status != 'duplicate'
          AND timeline_events.dedupe_status != 'duplicate'
          {expiry_filter}
          {metadata_filter}
          AND (
            timeline_events.description LIKE ?
            OR timeline_events.details_json LIKE ?
          )
        ORDER BY timeline_events.timestamp_utc DESC
        LIMIT ?
        """,
        (case_id, user_like, user_like, limit),
    ).fetchall()
    events = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        events.append(item)
    return {
        "case_id": case_id,
        "user": user,
        "include_expiry": include_expiry,
        "include_metadata": include_metadata,
        "events": events,
        "total_returned": len(events),
    }


def cloud_artifacts_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows: list[dict[str, Any]] = []
    for row in db.conn.execute(
        """
        SELECT
          provider,
          'cloud_sync_artifacts' AS source,
          computer_id,
          image_id,
          local_path,
          cloud_path,
          COALESCE(NULLIF(cloud_path, ''), NULLIF(local_path, ''), source_path) AS artifact_path,
          file_name,
          mime_type AS extension,
          file_size,
          event_time_utc AS modified_utc,
          event_time_utc AS accessed_utc,
          artifact_type,
          database_name,
          table_name,
          file_id,
          parent_id,
          stable_id,
          event_type,
          direction,
          sync_status,
          is_deleted,
          shared,
          url
        FROM cloud_sync_artifacts
        WHERE case_id = ?
        ORDER BY
          CASE WHEN artifact_type IN ('cloud_artifact_file', 'sqlite_inventory') THEN 1 ELSE 0 END,
          COALESCE(event_time_utc, '') DESC,
          provider,
          artifact_path
        LIMIT ?
        """,
        (case_id, limit),
    ):
        item = dict(row)
        item["evidence_tags"] = ["cloud_sync_artifact", item.get("artifact_type") or "cloud_sync"]
        rows.append(item)
    remaining = max(0, limit - len(rows))
    if not remaining:
        return {"case_id": case_id, "cloud_artifacts": rows, "total_returned": len(rows)}
    for row in db.conn.execute(
        """
        SELECT
          CASE
            WHEN lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%onedrive%' THEN 'OneDrive'
            WHEN lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%google drive%'
              OR lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%drivefs%' THEN 'Google Drive'
            WHEN lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%dropbox%' THEN 'Dropbox'
            WHEN lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%icloud%' THEN 'iCloud'
            ELSE 'cloud'
          END AS provider,
          'mft' AS source,
          mft_entries.computer_id,
          computers.label AS computer_label,
          mft_entries.image_id,
          images.path AS image_path,
          mft_entries.entry_number,
          mft_entries.in_use,
          mft_entries.is_directory,
          mft_entries.parent_path,
          mft_entries.file_name,
          mft_entries.extension,
          mft_entries.file_size,
          mft_entries.created_si AS created_utc,
          mft_entries.modified_si AS modified_utc,
          mft_entries.accessed_si AS accessed_utc,
          NULL AS application,
          NULL AS url
        FROM mft_entries
        LEFT JOIN computers ON mft_entries.computer_id = computers.id
        LEFT JOIN images ON mft_entries.image_id = images.id
        WHERE mft_entries.case_id = ?
          AND (
            lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%onedrive%'
            OR lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%google drive%'
            OR lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%drivefs%'
            OR lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%dropbox%'
            OR lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE '%icloud%'
          )
        ORDER BY provider, parent_path, file_name
        LIMIT ?
        """,
        (case_id, remaining),
    ):
        item = dict(row)
        item["artifact_path"] = _join_path(item.get("parent_path"), item.get("file_name"))
        item["evidence_tags"] = ["cloud_path_indicator", "mft_entry_present"]
        rows.append(item)
    remaining = max(0, limit - len(rows))
    if remaining:
        for row in db.conn.execute(
            """
            SELECT
              CASE
                WHEN lower(COALESCE(normalized_path, url, '')) LIKE '%onedrive%' THEN 'OneDrive'
                WHEN lower(COALESCE(normalized_path, url, '')) LIKE '%google drive%'
                  OR lower(COALESCE(normalized_path, url, '')) LIKE '%drivefs%' THEN 'Google Drive'
                WHEN lower(COALESCE(normalized_path, url, '')) LIKE '%dropbox%' THEN 'Dropbox'
                WHEN lower(COALESCE(normalized_path, url, '')) LIKE '%icloud%' THEN 'iCloud'
                ELSE 'cloud'
              END AS provider,
              'webcache_file_access' AS source, computer_id, image_id, normalized_path AS artifact_path,
              file_name, NULL AS extension, NULL AS file_size, created_utc, modified_utc,
              accessed_utc, application, url
            FROM webcache_file_accesses
            WHERE case_id = ?
              AND (
                lower(COALESCE(normalized_path, url, '')) LIKE '%onedrive%'
                OR lower(COALESCE(normalized_path, url, '')) LIKE '%google drive%'
                OR lower(COALESCE(normalized_path, url, '')) LIKE '%drivefs%'
                OR lower(COALESCE(normalized_path, url, '')) LIKE '%dropbox%'
                OR lower(COALESCE(normalized_path, url, '')) LIKE '%icloud%'
              )
            ORDER BY accessed_utc DESC
            LIMIT ?
            """,
            (case_id, remaining),
        ):
            item = dict(row)
            item["evidence_tags"] = ["cloud_path_indicator", "webcache_file_access_present"]
            rows.append(item)
    return {"case_id": case_id, "cloud_artifacts": rows, "total_returned": len(rows)}


def cloud_files_report(
    db: Database,
    case_id: str,
    *,
    provider: str | None = None,
    include_deleted: bool = True,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    provider_filter = ""
    params: list[Any] = [case_id, case_id, case_id]
    source_limit = max(limit * 10, limit)
    if provider:
        provider_filter = "AND LOWER(provider) = LOWER(?)"
        params.append(provider)
    deleted_filter = "" if include_deleted else "AND COALESCE(is_deleted, '') NOT IN ('1', 'true', 'True', 'yes', 'Yes')"
    rows = db.conn.execute(
        f"""
        WITH cloud_rows AS (
          SELECT provider,
                 'cloud_sync_artifacts' AS source_table,
                 id AS source_id,
                 user_profile,
                 COALESCE(NULLIF(cloud_path, ''), NULLIF(server_path, ''), NULLIF(local_path, ''), source_path) AS cloud_path,
                 local_path,
                 file_name,
                 file_id,
                 parent_id,
                 stable_id,
                 file_size,
                 mime_type,
                 event_time_utc,
                 is_folder,
                 is_deleted,
                 sync_status,
                 event_type,
                 direction,
                 shared,
                 url,
                 source_path
          FROM cloud_sync_artifacts
          WHERE case_id = ? {deleted_filter}
          UNION ALL
          SELECT 'Google Drive' AS provider,
                 'google_drive_cache_map' AS source_table,
                 id AS source_id,
                 account_id AS user_profile,
                 virtual_path AS cloud_path,
                 COALESCE(windows_cache_path, cache_path) AS local_path,
                 file_name,
                 file_id,
                 NULL AS parent_id,
                 stable_id,
                 cache_file_size AS file_size,
                 NULL AS mime_type,
                 NULL AS event_time_utc,
                 NULL AS is_folder,
                 NULL AS is_deleted,
                 mapping_method AS sync_status,
                 'cache_mapping' AS event_type,
                 NULL AS direction,
                 NULL AS shared,
                 NULL AS url,
                 cache_path AS source_path
          FROM google_drive_cache_map
          WHERE case_id = ?
          UNION ALL
          SELECT 'OneDrive' AS provider,
                 'onedrive_items' AS source_table,
                 id AS source_id,
                 COALESCE(user_profile, account) AS user_profile,
                 path AS cloud_path,
                 NULL AS local_path,
                 name AS file_name,
                 resource_id AS file_id,
                 parent_resource_id AS parent_id,
                 etag AS stable_id,
                 size AS file_size,
                 NULL AS mime_type,
                 COALESCE(last_change_utc, disk_last_access_utc, disk_creation_utc, delete_time_utc) AS event_time_utc,
                 NULL AS is_folder,
                 is_deleted,
                 status AS sync_status,
                 record_type AS event_type,
                 NULL AS direction,
                 shared_item AS shared,
                 NULL AS url,
                 source_path
          FROM onedrive_items
          WHERE case_id = ? {deleted_filter}
        )
        SELECT *
        FROM cloud_rows
        WHERE 1=1 {provider_filter}
        ORDER BY COALESCE(event_time_utc, '') DESC, provider, cloud_path, file_name
        LIMIT ?
        """,
        [*params, source_limit],
    ).fetchall()
    output = []
    seen: set[tuple[Any, ...]] = set()
    for row in rows:
        item = dict(row)
        key = (
            item.get("provider"),
            item.get("source_table"),
            item.get("user_profile"),
            item.get("cloud_path"),
            item.get("local_path"),
            item.get("file_name"),
            item.get("file_id"),
            item.get("stable_id"),
            item.get("event_time_utc"),
            item.get("is_deleted"),
            item.get("sync_status"),
            item.get("event_type"),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
        if len(output) >= limit:
            break
    provider_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    deleted_count = 0
    for row in output:
        provider_counts[row["provider"] or "unknown"] = provider_counts.get(row["provider"] or "unknown", 0) + 1
        source_counts[row["source_table"]] = source_counts.get(row["source_table"], 0) + 1
        if str(row.get("is_deleted") or "").lower() in {"1", "true", "yes"}:
            deleted_count += 1
    return {
        "case_id": case_id,
        "filters": {"provider": provider, "include_deleted": include_deleted},
        "summary": {
            "provider_counts": [{"provider": key, "count": value} for key, value in sorted(provider_counts.items())],
            "source_counts": [{"source_table": key, "count": value} for key, value in sorted(source_counts.items())],
            "deleted_rows_returned": deleted_count,
        },
        "cloud_files": output,
        "total_returned": len(output),
    }


def cloud_configuration_report(
    db: Database,
    case_id: str,
    *,
    provider: str | None = None,
    user: str | None = None,
    limit: int = 250,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["case_id = ?", "category = 'cloud'"]
    params: list[Any] = [case_id]
    if provider:
        filters.append(_cloud_config_provider_filter_sql())
        params.extend([f"%{provider}%"] * 5)
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR key_path LIKE ? OR value_data LIKE ?)")
        params.extend([f"%{user}%"] * 4)
    rows = _query_report_rows(
        db,
        case_id,
        "registry_artifacts",
        f"""
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               source_path, hive_type, user_profile, user_sid, artifact, key_path,
               key_last_write_utc, value_name, value_type, value_data, display_name,
               normalized_path, notes
        FROM registry_artifacts
        WHERE {" AND ".join(filters)}
        ORDER BY artifact, user_profile, key_path, value_name
        LIMIT ?
        """,
        [*params, limit],
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["provider"] = _cloud_config_provider(item)
        item["config_type"] = _cloud_config_type(item)
        item["value_preview"] = _sanitize_report_inline(_truncate_middle(str(item.get("value_data") or ""), 220))
        items.append(item)
    provider_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for item in items:
        provider_name = str(item.get("provider") or "unknown")
        config_type = str(item.get("config_type") or "unknown")
        provider_counts[provider_name] = provider_counts.get(provider_name, 0) + 1
        type_counts[config_type] = type_counts.get(config_type, 0) + 1
    return {
        "case_id": case_id,
        "filters": {"provider": provider, "user": user},
        "summary": {
            "items_returned": len(items),
            "provider_counts": [{"provider": key, "count": value} for key, value in sorted(provider_counts.items())],
            "config_type_counts": [{"config_type": key, "count": value} for key, value in sorted(type_counts.items())],
            "limit": limit,
        },
        "cloud_configuration": items,
        "total_returned": len(items),
    }


def _cloud_config_provider_filter_sql() -> str:
    return (
        "(artifact LIKE ? OR key_path LIKE ? OR value_name LIKE ? OR value_data LIKE ? OR source_path LIKE ?)"
    )


def _cloud_config_provider(row: dict[str, Any]) -> str:
    artifact = str(row.get("artifact") or "").lower()
    key_path = str(row.get("key_path") or "").lower()
    value = str(row.get("value_data") or "").lower()
    if "onedrive" in artifact or "onedrive" in key_path or "sharepoint" in value or "sharepoint.com" in value:
        return "OneDrive"
    if "google" in artifact or "drivefs" in key_path or "google" in key_path:
        return "Google Drive"
    if "dropbox" in artifact or "dropbox" in key_path:
        return "Dropbox"
    if "icloud" in artifact or "icloud" in key_path:
        return "iCloud"
    return "cloud"


def _cloud_config_type(row: dict[str, Any]) -> str:
    artifact = str(row.get("artifact") or "")
    value_name = str(row.get("value_name") or "").lower()
    if "account" in artifact:
        return "account"
    if "sync_engine" in artifact or value_name in {"mountpoint", "urlnamespace", "sporesourceid", "resourceid"}:
        return "sync_engine"
    if "syncroot" in artifact or value_name == "usersyncroots":
        return "sync_root"
    if "drivefs" in artifact:
        return "drivefs"
    return artifact or "cloud_config"


def email_artifacts_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    file_rows = [
        dict(row)
        for row in db.conn.execute(
        """
        SELECT 'mft' AS source, computer_id, image_id, parent_path AS path, file_name AS name,
               extension, created_si AS timestamp, file_size, NULL AS email, NULL AS evidence_value
        FROM mft_entries
        WHERE case_id = ?
          AND lower(COALESCE(extension, '')) IN ('pst', 'ost', 'msg', 'eml', 'mbox', 'mbx', 'olm')
        UNION ALL
        SELECT 'windows_search_email' AS source, computer_id, image_id, context_path AS path,
               context_title AS name, NULL AS extension, timestamp, NULL AS file_size,
               email, evidence_value
        FROM windows_search_email_indicators
        WHERE case_id = ?
        ORDER BY source, timestamp
        LIMIT ?
        """,
        (case_id, case_id, limit),
        ).fetchall()
    ]
    remaining = max(0, limit - len(file_rows))
    if remaining:
        file_rows.extend(
            dict(row)
            for row in db.conn.execute(
                """
                SELECT 'mailbox_message' AS source, computer_id, image_id, container_path AS path,
                       subject AS name, NULL AS extension, message_date_utc AS timestamp,
                       NULL AS file_size, sender AS email, recipients AS evidence_value,
                       dedupe_key
                FROM mailbox_messages
                WHERE case_id = ?
                ORDER BY message_date_utc DESC
                LIMIT ?
                """,
                (case_id, remaining),
            ).fetchall()
        )
    remaining = max(0, limit - len(file_rows))
    if remaining:
        file_rows.extend(
            dict(row)
            for row in db.conn.execute(
                """
                SELECT 'outlook_secure_temp_registry' AS source, computer_id, image_id,
                       key_path AS path, value_name AS name, NULL AS extension,
                       COALESCE(event_time_utc, key_last_write_utc) AS timestamp,
                       NULL AS file_size, NULL AS email, value_data AS evidence_value,
                       id AS dedupe_key
                FROM registry_artifacts
                WHERE case_id = ?
                  AND artifact = 'outlook_secure_temp'
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (case_id, remaining),
            ).fetchall()
        )
    for row in file_rows:
        row["dedupe_key"] = row.get("dedupe_key") or _email_dedupe_key(row)
    return {
        "case_id": case_id,
        "email_artifacts": file_rows,
        "deduplicated": _dedupe_email_rows(file_rows),
        "total_returned": len(file_rows),
    }


def mailbox_messages_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
    status: str | None = None,
    contains: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["mailbox_messages.case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(mailbox_messages.user_profile LIKE ? OR mailbox_messages.container_path LIKE ?)")
        params.extend([f"%{user}%", f"%{user}%"])
    if status:
        filters.append("mailbox_messages.parser_status = ?")
        params.append(status)
    if contains:
        filters.append(
            "(mailbox_messages.subject LIKE ? OR mailbox_messages.sender LIKE ? "
            "OR mailbox_messages.recipients LIKE ?)"
        )
        params.extend([f"%{contains}%"] * 3)
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT mailbox_messages.*, computers.label AS computer_label, images.path AS image_path
            FROM mailbox_messages
            LEFT JOIN computers ON mailbox_messages.computer_id = computers.id
            LEFT JOIN images ON mailbox_messages.image_id = images.id
            WHERE {where}
            ORDER BY mailbox_messages.message_date_utc DESC, mailbox_messages.subject
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"user": user, "status": status, "contains": contains},
        "mailbox_messages": rows,
        "total_returned": len(rows),
    }


def mailbox_attachments_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
    status: str | None = None,
    content_type: str | None = None,
    sha256: str | None = None,
    contains: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["mailbox_attachments.case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(mailbox_attachments.user_profile LIKE ? OR mailbox_attachments.container_path LIKE ?)")
        params.extend([f"%{user}%", f"%{user}%"])
    if status:
        filters.append("mailbox_attachments.extraction_status = ?")
        params.append(status)
    if content_type:
        filters.append("mailbox_attachments.content_type LIKE ?")
        params.append(f"%{content_type}%")
    if sha256:
        filters.append("mailbox_attachments.sha256 = ?")
        params.append(sha256)
    if contains:
        filters.append(
            "(mailbox_attachments.subject LIKE ? OR mailbox_attachments.sender LIKE ? "
            "OR mailbox_attachments.recipients LIKE ? OR mailbox_attachments.attachment_name LIKE ? "
            "OR mailbox_attachments.content_type LIKE ?)"
        )
        params.extend([f"%{contains}%"] * 5)
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT mailbox_attachments.*, computers.label AS computer_label, images.path AS image_path
            FROM mailbox_attachments
            LEFT JOIN computers ON mailbox_attachments.computer_id = computers.id
            LEFT JOIN images ON mailbox_attachments.image_id = images.id
            WHERE {where}
            ORDER BY mailbox_attachments.message_date_utc DESC, mailbox_attachments.attachment_name
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {
            "user": user,
            "status": status,
            "content_type": content_type,
            "sha256": sha256,
            "contains": contains,
        },
        "mailbox_attachments": rows,
        "total_returned": len(rows),
    }


def mailbox_attachment_coverage_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR container_path LIKE ? OR attachment_path LIKE ?)")
        params.extend([f"%{user}%"] * 4)
    where = " AND ".join(filters)
    status_rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT COALESCE(NULLIF(extraction_status, ''), 'unknown') AS extraction_status,
                   COUNT(*) AS attachment_count,
                   SUM(CASE WHEN COALESCE(extracted_text_length, 0) > 0 THEN 1 ELSE 0 END) AS with_extracted_text,
                   SUM(CASE WHEN COALESCE(metadata_json_length, 0) > 0 THEN 1 ELSE 0 END) AS with_metadata,
                   SUM(CASE WHEN COALESCE(parser_error, '') != '' THEN 1 ELSE 0 END) AS with_errors
            FROM mailbox_attachments
            WHERE {where}
            GROUP BY COALESCE(NULLIF(extraction_status, ''), 'unknown')
            ORDER BY attachment_count DESC, extraction_status
            """,
            params,
        ).fetchall()
    ]
    type_rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT COALESCE(NULLIF(content_type, ''), 'unknown') AS content_type,
                   COUNT(*) AS attachment_count,
                   SUM(CASE WHEN COALESCE(extracted_text_length, 0) > 0 THEN 1 ELSE 0 END) AS with_extracted_text,
                   SUM(CASE WHEN COALESCE(metadata_json_length, 0) > 0 THEN 1 ELSE 0 END) AS with_metadata
            FROM mailbox_attachments
            WHERE {where}
            GROUP BY COALESCE(NULLIF(content_type, ''), 'unknown')
            ORDER BY attachment_count DESC, content_type
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    issue_rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT id, message_date_utc, user_profile, subject, sender, attachment_name,
                   content_type, size, sha256, extraction_status, parser_error,
                   attachment_path, container_path
            FROM mailbox_attachments
            WHERE {where}
              AND (
                COALESCE(extraction_status, '') NOT IN ('text_extracted', 'metadata_extracted', 'text_and_metadata_extracted')
                OR COALESCE(parser_error, '') != ''
                OR (COALESCE(extracted_text_length, 0) = 0 AND COALESCE(metadata_json_length, 0) = 0)
              )
            ORDER BY message_date_utc DESC, attachment_name
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    totals = dict(
        db.conn.execute(
            f"""
            SELECT COUNT(*) AS attachment_count,
                   SUM(CASE WHEN COALESCE(extracted_text_length, 0) > 0 THEN 1 ELSE 0 END) AS with_extracted_text,
                   SUM(CASE WHEN COALESCE(metadata_json_length, 0) > 0 THEN 1 ELSE 0 END) AS with_metadata,
                   SUM(CASE WHEN COALESCE(parser_error, '') != '' THEN 1 ELSE 0 END) AS with_errors
            FROM mailbox_attachments
            WHERE {where}
            """,
            params,
        ).fetchone()
    )
    return {
        "case_id": case_id,
        "filters": {"user": user},
        "totals": totals,
        "by_status": status_rows,
        "by_content_type": type_rows,
        "issues": issue_rows,
        "total_returned": len(issue_rows),
    }


def mailbox_attachment_copies_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
    contains: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR container_path LIKE ? OR attachment_path LIKE ?)")
        params.extend([f"%{user}%"] * 4)
    if contains:
        filters.append("(subject LIKE ? OR sender LIKE ? OR recipients LIKE ? OR attachment_name LIKE ? OR content_type LIKE ?)")
        params.extend([f"%{contains}%"] * 5)
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            WITH keyed AS (
              SELECT *,
                     CASE
                       WHEN COALESCE(sha256, '') != '' THEN 'sha256:' || sha256
                       WHEN COALESCE(dedupe_key, '') != '' THEN 'dedupe:' || dedupe_key
                       ELSE 'name-size:' || lower(COALESCE(attachment_name, '')) || ':' || COALESCE(size, -1)
                     END AS attachment_copy_key
              FROM mailbox_attachments
              WHERE {where}
            )
            SELECT attachment_copy_key,
                   MAX(attachment_name) AS attachment_name,
                   MAX(content_type) AS content_type,
                   MAX(size) AS size,
                   MAX(sha256) AS sha256,
                   MIN(message_date_utc) AS first_seen,
                   MAX(message_date_utc) AS last_seen,
                   COUNT(*) AS attachment_count,
                   COUNT(DISTINCT message_path) AS message_count,
                   COUNT(DISTINCT container_path) AS container_count,
                   GROUP_CONCAT(DISTINCT NULLIF(user_profile, '')) AS users,
                   GROUP_CONCAT(DISTINCT NULLIF(subject, '')) AS subjects,
                   GROUP_CONCAT(DISTINCT attachment_path) AS attachment_paths,
                   GROUP_CONCAT(DISTINCT container_path) AS container_paths
            FROM keyed
            GROUP BY attachment_copy_key
            HAVING COUNT(*) > 1 OR COUNT(DISTINCT container_path) > 1 OR COUNT(DISTINCT message_path) > 1
            ORDER BY attachment_count DESC, last_seen DESC
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"user": user, "contains": contains},
        "mailbox_attachment_copies": rows,
        "total_returned": len(rows),
    }


def mailbox_message_copies_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
    contains: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = [
        "case_id = ?",
        "parser_status = 'parsed'",
        "COALESCE(dedupe_key, '') != ''",
    ]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR container_path LIKE ?)")
        params.extend([f"%{user}%", f"%{user}%", f"%{user}%"])
    if contains:
        filters.append("(subject LIKE ? OR sender LIKE ? OR recipients LIKE ?)")
        params.extend([f"%{contains}%"] * 3)
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT dedupe_key,
                   MIN(message_date_utc) AS message_date_utc,
                   MAX(subject) AS subject,
                   MAX(sender) AS sender,
                   MAX(recipients) AS recipients,
                   COUNT(*) AS message_count,
                   COUNT(DISTINCT container_path) AS container_count,
                   GROUP_CONCAT(DISTINCT NULLIF(user_profile, '')) AS users,
                   GROUP_CONCAT(DISTINCT NULLIF(user_sid, '')) AS user_sids,
                   GROUP_CONCAT(DISTINCT container_path) AS container_paths
            FROM mailbox_messages
            WHERE {where}
            GROUP BY dedupe_key
            HAVING COUNT(DISTINCT container_path) > 1 OR COUNT(*) > 1
            ORDER BY message_date_utc DESC, subject
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"user": user, "contains": contains},
        "mailbox_message_copies": rows,
        "total_returned": len(rows),
    }


def search_index_runs_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT *
            FROM search_index_runs
            WHERE case_id = ?
            ORDER BY started_at DESC, created_at DESC
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]
    for row in rows:
        for key in ("source_counts_json", "query_synonyms_json"):
            try:
                row[key.removesuffix("_json")] = json.loads(row.get(key) or "{}")
            except json.JSONDecodeError:
                row[key.removesuffix("_json")] = row.get(key)
    return {"case_id": case_id, "search_index_runs": rows, "total_returned": len(rows)}


def storage_policy_report(db: Database, case_id: str) -> dict[str, Any]:
    db.get_case(case_id)
    content_tables = []
    for item in CONTENT_HEAVY_TABLES:
        table = item["table"]
        if not _table_exists(db, table):
            content_tables.append(
                {
                    **item,
                    "exists": False,
                    "row_count": 0,
                    "non_empty_large_rows": 0,
                    "referenced_large_rows": 0,
                    "estimated_large_text_bytes": 0,
                }
            )
            continue
        large_columns = [
            column
            for column in item["large_columns"]
            if _table_has_column(db, table, column)
        ]
        row_count = _count(db, table, case_id)
        non_empty_rows = 0
        referenced_rows = 0
        estimated_bytes = 0
        if large_columns:
            non_empty_expression = " OR ".join(f"COALESCE({column}, '') != ''" for column in large_columns)
            byte_expression = " + ".join(f"LENGTH(COALESCE({column}, ''))" for column in large_columns)
            aggregate = db.conn.execute(
                f"""
                SELECT COUNT(*) AS non_empty_rows,
                       COALESCE(SUM({byte_expression}), 0) AS estimated_bytes
                FROM {table}
                WHERE case_id = ? AND ({non_empty_expression})
                """,
                (case_id,),
            ).fetchone()
            non_empty_rows = int(aggregate["non_empty_rows"])
            estimated_bytes = int(aggregate["estimated_bytes"])
            reference_columns = [
                f"{column}_sha256"
                for column in large_columns
                if _table_has_column(db, table, f"{column}_sha256")
            ]
            if table == "windows_search_indexed_content" and _table_has_column(db, table, "content_sha256"):
                reference_columns = ["content_sha256"]
            if reference_columns:
                reference_expression = " OR ".join(f"COALESCE({column}, '') != ''" for column in reference_columns)
                reference_row = db.conn.execute(
                    f"""
                    SELECT COUNT(*) AS referenced_rows
                    FROM {table}
                    WHERE case_id = ? AND ({reference_expression})
                    """,
                    (case_id,),
                ).fetchone()
                referenced_rows = int(reference_row["referenced_rows"])
        content_tables.append(
            {
                **item,
                "exists": True,
                "large_columns": large_columns,
                "row_count": row_count,
                "non_empty_large_rows": non_empty_rows,
                "referenced_large_rows": referenced_rows,
                "estimated_large_text_bytes": estimated_bytes,
            }
        )

    index_runs = search_index_runs_report(db, case_id, limit=5)["search_index_runs"]
    return {
        "case_id": case_id,
        "policy": storage_policy_items(),
        "content_heavy_tables": content_tables,
        "artifact_files": _tool_output_bytes(db, case_id),
        "opensearch": {
            "latest_runs": index_runs,
            "latest_status": index_runs[0]["status"] if index_runs else "not_indexed",
            "latest_document_count": index_runs[0]["document_count"] if index_runs else 0,
        },
        "guidance": [
            "Keep normalized facts and provenance in SQLite.",
            "Keep raw parser output and extracted files under the case artifact/output folders.",
            "Use OpenSearch for large body text, attachment text, Windows Search indexed content, and future OCR.",
            "Promote JSON fields into columns when reports or joins depend on them repeatedly.",
        ],
    }


def telemetry_artifacts_report(
    db: Database,
    case_id: str,
    *,
    artifact_group: str | None = None,
    contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["telemetry_artifacts.case_id = ?"]
    params: list[Any] = [case_id]
    if artifact_group:
        filters.append("telemetry_artifacts.artifact_group = ?")
        params.append(artifact_group)
    if contains:
        like = f"%{contains}%"
        filters.append(
            """
            (telemetry_artifacts.source_path LIKE ?
             OR telemetry_artifacts.title LIKE ?
             OR telemetry_artifacts.value_data LIKE ?
             OR telemetry_artifacts.artifact_text LIKE ?)
            """
        )
        params.extend([like, like, like, like])
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT telemetry_artifacts.*, computers.label AS computer_label, images.path AS image_path
            FROM telemetry_artifacts
            LEFT JOIN computers ON telemetry_artifacts.computer_id = computers.id
            LEFT JOIN images ON telemetry_artifacts.image_id = images.id
            WHERE {where}
            ORDER BY COALESCE(telemetry_artifacts.event_time_utc, telemetry_artifacts.modified_utc, telemetry_artifacts.created_at) DESC,
                     telemetry_artifacts.artifact_group,
                     telemetry_artifacts.record_type
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT artifact_group, record_type, COUNT(*) AS count
            FROM telemetry_artifacts
            WHERE case_id = ?
            GROUP BY artifact_group, record_type
            ORDER BY artifact_group, record_type
            """,
            (case_id,),
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"artifact_group": artifact_group, "contains": contains},
        "counts": counts,
        "telemetry_artifacts": rows,
        "total_returned": len(rows),
    }


def artifact_correlations_report(
    db: Database,
    case_id: str,
    *,
    correlation_type: str | None = None,
    confidence: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["artifact_correlations.case_id = ?"]
    params: list[Any] = [case_id]
    if correlation_type:
        filters.append("artifact_correlations.correlation_type = ?")
        params.append(correlation_type)
    if confidence:
        filters.append("artifact_correlations.confidence = ?")
        params.append(confidence)
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT artifact_correlations.*, computers.label AS computer_label, images.path AS image_path
            FROM artifact_correlations
            LEFT JOIN computers ON artifact_correlations.computer_id = computers.id
            LEFT JOIN images ON artifact_correlations.image_id = images.id
            WHERE {where}
            ORDER BY
              CASE artifact_correlations.confidence
                WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
              artifact_correlations.correlation_type,
              artifact_correlations.correlation_key
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT correlation_type, confidence, COUNT(*) AS count
            FROM artifact_correlations
            WHERE case_id = ?
            GROUP BY correlation_type, confidence
            ORDER BY correlation_type, confidence
            """,
            (case_id,),
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"correlation_type": correlation_type, "confidence": confidence},
        "counts": counts,
        "artifact_correlations": rows,
        "total_returned": len(rows),
    }


def correlation_groups_report(
    db: Database,
    case_id: str,
    *,
    category: str | None = None,
    rule_id: str | None = None,
    contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["correlation_groups.case_id = ?"]
    params: list[Any] = [case_id]
    if category:
        filters.append("correlation_groups.category = ?")
        params.append(category)
    if rule_id:
        filters.append("correlation_groups.rule_id = ?")
        params.append(rule_id)
    if contains:
        filters.append(
            "(correlation_groups.title LIKE ? OR correlation_groups.summary LIKE ? OR correlation_groups.primary_path LIKE ? OR correlation_groups.details_json LIKE ?)"
        )
        params.extend([f"%{contains}%"] * 4)
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT correlation_groups.*, correlation_rules.name AS rule_name,
                   correlation_rules.description AS rule_description,
                   correlation_interpretations.interpretation,
                   correlation_interpretations.caveats
            FROM correlation_groups
            LEFT JOIN correlation_rules ON correlation_rules.id = correlation_groups.rule_id
            LEFT JOIN correlation_interpretations ON correlation_interpretations.group_id = correlation_groups.id
            WHERE {where}
            ORDER BY
              CASE correlation_groups.review_value WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
              correlation_groups.category,
              COALESCE(correlation_groups.primary_time_utc, '') DESC
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    for row in rows:
        row["details"] = _json_details(row.pop("details_json", None))
    counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT category, rule_id, review_value, COUNT(*) AS count
            FROM correlation_groups
            WHERE case_id = ?
            GROUP BY category, rule_id, review_value
            ORDER BY category, rule_id, review_value
            """,
            (case_id,),
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"category": category, "rule_id": rule_id, "contains": contains},
        "counts": counts,
        "correlation_groups": rows,
        "total_returned": len(rows),
    }


def correlation_group_detail_report(db: Database, case_id: str, group_id: str) -> dict[str, Any]:
    db.get_case(case_id)
    group = db.conn.execute(
        """
        SELECT correlation_groups.*, correlation_rules.name AS rule_name,
               correlation_rules.description AS rule_description,
               correlation_interpretations.interpretation,
               correlation_interpretations.caveats
        FROM correlation_groups
        LEFT JOIN correlation_rules ON correlation_rules.id = correlation_groups.rule_id
        LEFT JOIN correlation_interpretations ON correlation_interpretations.group_id = correlation_groups.id
        WHERE correlation_groups.case_id = ? AND correlation_groups.id = ?
        """,
        (case_id, group_id),
    ).fetchone()
    if group is None:
        return {"case_id": case_id, "group_id": group_id, "group": None, "members": []}
    group_item = dict(group)
    group_item["details"] = _json_details(group_item.pop("details_json", None))
    members = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT *
            FROM correlation_members
            WHERE case_id = ? AND group_id = ?
            ORDER BY role, source_table, event_time_utc
            """,
            (case_id, group_id),
        ).fetchall()
    ]
    for member in members:
        member["details"] = _json_details(member.pop("details_json", None))
    return {"case_id": case_id, "group_id": group_id, "group": group_item, "members": members}


def sessions_report(
    db: Database,
    case_id: str,
    *,
    session_type: str | None = None,
    user: str | None = None,
    contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if session_type:
        filters.append("session_type = ?")
        params.append(session_type)
    if user:
        filters.append("user_profile LIKE ?")
        params.append(f"%{user}%")
    if contains:
        filters.append("(session_key LIKE ? OR remote_host LIKE ? OR remote_ip LIKE ? OR profile_name LIKE ? OR details_json LIKE ?)")
        params.extend([f"%{contains}%"] * 5)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT *
            FROM derived_sessions
            WHERE {' AND '.join(filters)}
            ORDER BY COALESCE(start_time_utc, end_time_utc, '') DESC, session_type
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    for row in rows:
        row["details"] = _json_details(row.pop("details_json", None))
    counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT session_type, status, COUNT(*) AS count
            FROM derived_sessions
            WHERE case_id = ?
            GROUP BY session_type, status
            ORDER BY session_type, status
            """,
            (case_id,),
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"session_type": session_type, "user": user, "contains": contains},
        "counts": counts,
        "sessions": rows,
        "total_returned": len(rows),
    }


def session_detail_report(db: Database, case_id: str, session_id: str) -> dict[str, Any]:
    db.get_case(case_id)
    row = db.conn.execute(
        "SELECT * FROM derived_sessions WHERE case_id = ? AND id = ?",
        (case_id, session_id),
    ).fetchone()
    if row is None:
        return {"case_id": case_id, "session_id": session_id, "session": None, "members": []}
    session = dict(row)
    session["details"] = _json_details(session.pop("details_json", None))
    members = [
        dict(member)
        for member in db.conn.execute(
            """
            SELECT *
            FROM derived_session_members
            WHERE case_id = ? AND session_id = ?
            ORDER BY event_time_utc, source_table
            """,
            (case_id, session_id),
        ).fetchall()
    ]
    for member in members:
        member["details"] = _json_details(member.pop("details_json", None))
    return {"case_id": case_id, "session_id": session_id, "session": session, "members": members}


def computer_inventory_report(
    db: Database,
    case_id: str,
    *,
    category: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["computer_inventory.case_id = ?"]
    params: list[Any] = [case_id]
    if category:
        filters.append("computer_inventory.category = ?")
        params.append(category)
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT computer_inventory.*, computers.label AS computer_label, images.path AS image_path
            FROM computer_inventory
            LEFT JOIN computers ON computer_inventory.computer_id = computers.id
            LEFT JOIN images ON computer_inventory.image_id = images.id
            WHERE {where}
            ORDER BY computer_inventory.computer_id, computer_inventory.category, computer_inventory.name
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT category, COUNT(*) AS count
            FROM computer_inventory
            WHERE case_id = ?
            GROUP BY category
            ORDER BY category
            """,
            (case_id,),
        ).fetchall()
    ]
    os_summary = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT computer_id,
                   MAX(CASE WHEN name = 'computer_name' THEN value END) AS computer_name,
                   MAX(CASE WHEN name = 'product_name' THEN value END) AS product_name,
                   MAX(CASE WHEN name = 'display_version' THEN value END) AS display_version,
                   MAX(CASE WHEN name = 'current_build' THEN value END) AS current_build,
                   MAX(CASE WHEN name = 'ubr' THEN value END) AS ubr,
                   MAX(CASE WHEN name = 'windows_generation' THEN value END) AS windows_generation,
                   MAX(CASE WHEN name = 'time_zone' THEN value END) AS time_zone
            FROM computer_inventory
            WHERE case_id = ?
            GROUP BY computer_id
            """,
            (case_id,),
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"category": category},
        "os_summary": os_summary,
        "counts": counts,
        "computer_inventory": rows,
        "total_returned": len(rows),
    }


def web_cloud_correlations_report(
    db: Database,
    case_id: str,
    *,
    provider: str | None = None,
    category: str | None = None,
    user: str | None = None,
    contains: str | None = None,
    limit: int = 250,
) -> dict[str, Any]:
    db.get_case(case_id)
    candidates = _web_cloud_candidates(db, case_id)
    rows = []
    for item in candidates:
        item["user_profile"] = _web_cloud_user(item)
        classification = _classify_web_cloud(item)
        if classification is None:
            continue
        item.update(classification)
        if provider and item["provider"].lower() != provider.lower():
            continue
        if category and item["category"].lower() != category.lower():
            continue
        if user and user.lower() not in str(item.get("user_profile") or item.get("user_name") or "").lower():
            continue
        if contains and contains.lower() not in _web_cloud_search_text(item):
            continue
        rows.append(item)
    rows.sort(
        key=lambda row: (
            _web_cloud_evidence_priority(row["evidence_type"]),
            row.get("timestamp") or "",
            row["provider"],
            row["source_table"],
        ),
        reverse=True,
    )
    grouped = _web_cloud_grouped(rows)
    return {
        "case_id": case_id,
        "filters": {"provider": provider, "category": category, "user": user, "contains": contains},
        "counts": _web_cloud_counts(rows),
        "grouped": grouped,
        "web_cloud_correlations": rows[:limit],
        "total_matches": len(rows),
        "total_returned": min(len(rows), limit),
    }


def _web_cloud_candidates(db: Database, case_id: str) -> list[dict[str, Any]]:
    queries = [
        (
            "browser_history",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'browser_history' AS source_table,
                   browser AS source_name, profile_path AS user_profile, visit_time_utc AS timestamp,
                   url, host_from_url(url) AS host, title, NULL AS path, NULL AS file_name, local_vs_synced AS context
            FROM browser_history WHERE case_id = ?
            """,
        ),
        (
            "browser_downloads",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'browser_downloads' AS source_table,
                   browser AS source_name, profile_path AS user_profile, COALESCE(end_time_utc, start_time_utc) AS timestamp,
                   COALESCE(tab_url, site_url, referrer) AS url, host_from_url(COALESCE(tab_url, site_url, referrer)) AS host,
                   NULL AS title, target_path AS path, target_path AS file_name, state AS context
            FROM browser_downloads WHERE case_id = ?
            """,
        ),
        (
            "webcache_entries",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'webcache_entries' AS source_table,
                   COALESCE(application, application_package, container_name) AS source_name, user_name AS user_profile,
                   COALESCE(accessed_utc, modified_utc, created_utc, synced_utc) AS timestamp,
                   url, host, container_name AS title, cache_file AS path, file_name, entry_type AS context
            FROM webcache_entries WHERE case_id = ?
            """,
        ),
        (
            "webcache_file_accesses",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'webcache_file_accesses' AS source_table,
                   COALESCE(application, application_package, container_name) AS source_name, user_name AS user_profile,
                   COALESCE(accessed_utc, modified_utc, created_utc, synced_utc) AS timestamp,
                   url, host_from_url(url) AS host, container_name AS title, local_path AS path, file_name, entry_id AS context
            FROM webcache_file_accesses WHERE case_id = ?
            """,
        ),
        (
            "shortcut_items",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'shortcut_items' AS source_table,
                   artifact_type AS source_name, artifact_path AS user_profile,
                   COALESCE(target_accessed, target_modified, target_created, lnk_accessed, lnk_modified, lnk_created) AS timestamp,
                   NULL AS url, NULL AS host, artifact_name AS title, file_location AS path, file_name,
                   COALESCE(volume_name, device_type, jumplist_item_number) AS context
            FROM shortcut_items WHERE case_id = ?
            """,
        ),
        (
            "shellbag_entries",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'shellbag_entries' AS source_table,
                   shell_type AS source_name, user_profile,
                   COALESCE(last_interacted, first_interacted, accessed_on, modified_on, created_on, last_write_time) AS timestamp,
                   NULL AS url, NULL AS host, value_name AS title, absolute_path AS path,
                   absolute_path AS file_name, COALESCE(volume_name, volume_serial_number, drive_letter) AS context
            FROM shellbag_entries WHERE case_id = ?
            """,
        ),
        (
            "registry_artifacts",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'registry_artifacts' AS source_table,
                   artifact AS source_name, user_profile,
                   COALESCE(event_time_utc, recentdocs_time_utc, recentdocs_extension_time_utc, key_last_write_utc) AS timestamp,
                   CASE WHEN value_data LIKE 'http%' THEN value_data ELSE NULL END AS url,
                   host_from_url(CASE WHEN value_data LIKE 'http%' THEN value_data ELSE NULL END) AS host,
                   value_name AS title, COALESCE(normalized_path, value_data) AS path, display_name AS file_name,
                   artifact AS context
            FROM registry_artifacts WHERE case_id = ?
            """,
        ),
        (
            "cloud_sync_artifacts",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'cloud_sync_artifacts' AS source_table,
                   provider AS source_name, user_profile, event_time_utc AS timestamp,
                   url, host_from_url(url) AS host, cloud_path AS title, COALESCE(local_path, cloud_path, server_path) AS path,
                   file_name, COALESCE(sync_status, event_type, artifact_type) AS context
            FROM cloud_sync_artifacts WHERE case_id = ?
            """,
        ),
        (
            "onedrive_items",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'onedrive_items' AS source_table,
                   account AS source_name, user_profile,
                   COALESCE(last_change_utc, disk_last_access_utc, disk_creation_utc, delete_time_utc) AS timestamp,
                   NULL AS url, NULL AS host, name AS title, path, name AS file_name,
                   COALESCE(status, record_type, artifact_type) AS context
            FROM onedrive_items WHERE case_id = ?
            """,
        ),
        (
            "google_drive_cache_map",
            """
            SELECT id, case_id, computer_id, image_id, tool_name, 'google_drive_cache_map' AS source_table,
                   account_id AS source_name, account_id AS user_profile, NULL AS timestamp,
                   NULL AS url, NULL AS host, virtual_path AS title, COALESCE(windows_cache_path, cache_path, virtual_path) AS path,
                   file_name, mapping_method AS context
            FROM google_drive_cache_map WHERE case_id = ?
            """,
        ),
    ]
    rows: list[dict[str, Any]] = []
    for _name, sql in queries:
        rows.extend(dict(row) for row in db.conn.execute(sql, (case_id,)).fetchall())
    return rows


def _classify_web_cloud(row: dict[str, Any]) -> dict[str, str] | None:
    haystack = _web_cloud_search_text(row)
    for provider in WEB_CLOUD_PROVIDERS:
        for token in provider["tokens"]:
            if token.lower() in haystack:
                return {
                    "provider": provider["provider"],
                    "category": provider["category"],
                    "match_token": token,
                    "evidence_type": _web_cloud_evidence_type(row),
                    "summary": _web_cloud_summary(row, provider["provider"], token),
                }
    return None


def _web_cloud_search_text(row: dict[str, Any]) -> str:
    return " ".join(
        str(row.get(key) or "")
        for key in ("url", "host", "title", "path", "file_name", "source_name", "context", "user_profile")
    ).lower()


def _web_cloud_evidence_type(row: dict[str, Any]) -> str:
    source = row.get("source_table")
    if source in {"browser_history", "webcache_entries"}:
        return "web_visit_or_cache"
    if source in {"browser_downloads", "webcache_file_accesses"}:
        return "web_file_transfer_or_access"
    if source == "shortcut_items":
        return "shortcut_or_jumplist_reference"
    if source == "shellbag_entries":
        return "explorer_folder_interaction"
    if source == "registry_artifacts":
        return "registry_user_activity"
    if source in {"cloud_sync_artifacts", "onedrive_items", "google_drive_cache_map"}:
        return "local_cloud_client_state"
    return "web_cloud_reference"


def _web_cloud_evidence_priority(evidence_type: str) -> int:
    return {
        "web_file_transfer_or_access": 6,
        "web_visit_or_cache": 5,
        "shortcut_or_jumplist_reference": 4,
        "explorer_folder_interaction": 3,
        "registry_user_activity": 2,
        "local_cloud_client_state": 1,
    }.get(evidence_type, 0)


def _web_cloud_user(row: dict[str, Any]) -> str:
    for key in ("user_profile", "path"):
        user = _user_profile_from_artifact_path(row.get(key)) or _user_from_path(row.get(key))
        if user:
            return user
    raw = str(row.get("user_profile") or "")
    if "/" not in raw and "\\" not in raw:
        return raw
    return ""


def _web_cloud_summary(row: dict[str, Any], provider: str, token: str) -> str:
    source = row.get("source_table")
    value = row.get("url") or row.get("path") or row.get("title") or row.get("file_name") or row.get("host")
    return f"{provider} reference in {source} matched {token}: {value or ''}".strip()


def _web_cloud_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str], int] = {}
    for row in rows:
        key = (row["provider"], row["category"], row["source_table"])
        counts[key] = counts.get(key, 0) + 1
    return [
        {"provider": provider, "category": category, "source_table": source_table, "count": count}
        for (provider, category, source_table), count in sorted(counts.items())
    ]


def _web_cloud_grouped(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["provider"], row["category"])
        item = grouped.setdefault(
            key,
            {
                "provider": row["provider"],
                "category": row["category"],
                "count": 0,
                "source_tables": {},
                "users": set(),
                "first_seen": None,
                "last_seen": None,
            },
        )
        item["count"] += 1
        item["source_tables"][row["source_table"]] = item["source_tables"].get(row["source_table"], 0) + 1
        if row.get("user_profile"):
            item["users"].add(row["user_profile"])
        timestamp = row.get("timestamp")
        if timestamp:
            item["first_seen"] = timestamp if item["first_seen"] is None else min(item["first_seen"], timestamp)
            item["last_seen"] = timestamp if item["last_seen"] is None else max(item["last_seen"], timestamp)
    result = []
    for item in grouped.values():
        item["users"] = sorted(item["users"])
        item["source_tables"] = [
            {"source_table": source, "count": count}
            for source, count in sorted(item["source_tables"].items())
        ]
        result.append(item)
    result.sort(key=lambda item: (item["category"], item["provider"]))
    return result


def messaging_artifacts_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    application: str | None = None,
    artifact_type: str | None = None,
    user: str | None = None,
    contains: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    rows: list[dict[str, Any]] = []
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if application:
        filters.append("application LIKE ?")
        params.append(f"%{application}%")
    if artifact_type:
        filters.append("artifact_type = ?")
        params.append(artifact_type)
    if user:
        filters.append("(user_profile LIKE ? OR source_path LIKE ?)")
        params.extend([f"%{user}%", f"%{user}%"])
    if contains:
        filters.append("(url LIKE ? OR email LIKE ? OR record_key LIKE ?)")
        params.extend([f"%{contains}%"] * 3)
    where = " AND ".join(filters)
    for row in db.conn.execute(
        f"""
        SELECT application, artifact_type, 'messaging_record' AS source,
               source_path AS artifact_path, store_path, record_key, url,
               host, email, user_profile, record_type, timestamp_utc,
               message_text, raw_text, dedupe_key
        FROM messaging_records
        WHERE {where}
        ORDER BY timestamp_utc DESC, application
        LIMIT ?
        """,
        [*params, limit],
    ):
        item = dict(row)
        item["evidence_tags"] = ["messaging_record_extracted", item["artifact_type"]]
        rows.append(item)
    if len(rows) >= limit:
        return {
            "case_id": case_id,
            "filters": {"application": application, "artifact_type": artifact_type, "user": user, "contains": contains},
            "messaging_artifacts": rows,
            "total_returned": len(rows),
        }
    if any((application, artifact_type, user, contains)):
        return {
            "case_id": case_id,
            "filters": {"application": application, "artifact_type": artifact_type, "user": user, "contains": contains},
            "messaging_artifacts": rows,
            "total_returned": len(rows),
        }
    app_patterns = _messaging_app_patterns()
    pattern_sql = " OR ".join("lower(COALESCE(parent_path, '') || '/' || COALESCE(file_name, '')) LIKE ?" for _ in app_patterns)
    params = [case_id, *[pattern for _, pattern in app_patterns], limit - len(rows)]
    for row in db.conn.execute(
        f"""
        SELECT 'mft' AS source, computer_id, image_id,
               parent_path, file_name, extension, file_size,
               created_si, modified_si, accessed_si
        FROM mft_entries
        WHERE case_id = ? AND ({pattern_sql})
        ORDER BY modified_si DESC
        LIMIT ?
        """,
        params,
    ):
        path = _join_path(row["parent_path"], row["file_name"])
        app = _messaging_app_for_path(path)
        item = dict(row)
        item["application"] = app
        item["artifact_path"] = path
        item["artifact_type"] = _messaging_artifact_type(path, row["extension"])
        item["evidence_tags"] = _messaging_tags(path, row["extension"])
        rows.append(item)
    remaining = max(0, limit - len(rows))
    if remaining:
        cache_patterns = [pattern for _, pattern in app_patterns]
        cache_sql = " OR ".join("lower(COALESCE(profile_path, '') || ' ' || COALESCE(url, '') || ' ' || COALESCE(cache_file, '')) LIKE ?" for _ in cache_patterns)
        for row in db.conn.execute(
            f"""
            SELECT 'browser_cache' AS source, computer_id, image_id, browser,
                   profile_path AS artifact_path, cache_type, url, host,
                   cache_file, cache_file_modified_utc
            FROM browser_cache_entries
            WHERE case_id = ? AND ({cache_sql})
            ORDER BY cache_file_modified_utc DESC
            LIMIT ?
            """,
            [case_id, *cache_patterns, remaining],
        ):
            item = dict(row)
            item["application"] = _messaging_app_for_path(f"{row['profile_path']} {row['url']} {row['cache_file']}")
            item["artifact_type"] = "cache_reference"
            item["evidence_tags"] = ["app_cache_reference"]
            rows.append(item)
    return {
        "case_id": case_id,
        "filters": {"application": application, "artifact_type": artifact_type, "user": user, "contains": contains},
        "messaging_artifacts": rows,
        "total_returned": len(rows),
    }


def messaging_messages_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    application: str | None = None,
    user: str | None = None,
    contains: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if application:
        filters.append("application LIKE ?")
        params.append(f"%{application}%")
    if user:
        filters.append("(user_profile LIKE ? OR sender_email LIKE ? OR sender_name LIKE ?)")
        params.extend([f"%{user}%", f"%{user}%", f"%{user}%"])
    if contains:
        filters.append(
            "(sender_email LIKE ? OR sender_name LIKE ? OR url LIKE ?)"
        )
        params.extend([f"%{contains}%"] * 3)
    where = " AND ".join(filters)
    rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT *
            FROM messaging_messages
            WHERE {where}
            ORDER BY timestamp_utc DESC, application, row_number
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "filters": {"application": application, "user": user, "contains": contains},
        "messaging_messages": rows,
        "total_returned": len(rows),
    }


def communications_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
    contains: str | None = None,
    source_type: str | None = None,
    include_low_value: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    rows: list[dict[str, Any]] = []
    per_source_limit = max(limit * 2, 100)
    rows.extend(_communication_mailbox_rows(db, case_id, per_source_limit, user=user, contains=contains))
    rows.extend(_communication_attachment_rows(db, case_id, per_source_limit, user=user, contains=contains))
    rows.extend(_communication_windows_search_rows(db, case_id, per_source_limit, user=user, contains=contains))
    rows.extend(_communication_messaging_rows(db, case_id, per_source_limit, user=user, contains=contains))
    if source_type:
        rows = [row for row in rows if row.get("source_type") == source_type]
    elif not include_low_value:
        rows = [row for row in rows if row.get("review_value") != "low"]
    rows.sort(key=lambda row: (row.get("timestamp") or "", row.get("source_type") or ""), reverse=True)
    rows = rows[:limit]
    groups = _communication_groups(rows)
    return {
        "case_id": case_id,
        "filters": {
            "user": user,
            "contains": contains,
            "source_type": source_type,
            "include_low_value": include_low_value,
        },
        "communications": rows,
        "groups": groups,
        "total_returned": len(rows),
        "group_count": len(groups),
    }


def communication_groups_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    user: str | None = None,
    contains: str | None = None,
    source_type: str | None = None,
    include_low_value: bool = False,
) -> dict[str, Any]:
    report = communications_report(
        db,
        case_id,
        limit=max(limit * 10, 500),
        user=user,
        contains=contains,
        source_type=source_type,
        include_low_value=include_low_value,
    )
    groups = report["groups"][:limit]
    return {
        "case_id": case_id,
        "filters": report["filters"],
        "communication_groups": groups,
        "total_returned": len(groups),
    }


def communication_review_report(
    db: Database,
    case_id: str,
    *,
    view: str,
    limit: int = 100,
    user: str | None = None,
    contains: str | None = None,
    include_low_value: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    if view == "conversations":
        rows = _communication_conversation_rows(db, case_id, limit, user=user, contains=contains)
    elif view == "pairs":
        rows = _communication_pair_rows(db, case_id, limit, user=user, contains=contains)
    elif view == "attachments":
        rows = _communication_attachment_review_rows(db, case_id, limit, user=user, contains=contains)
    elif view == "indexed-only":
        rows = _communication_indexed_only_rows(db, case_id, limit, user=user, contains=contains)
    elif view == "recovered-fragments":
        rows = _communication_recovered_fragment_rows(
            db,
            case_id,
            limit,
            user=user,
            contains=contains,
            include_low_value=include_low_value,
        )
    else:
        raise ValueError(f"Unsupported communication review view: {view}")
    return {
        "case_id": case_id,
        "filters": {
            "view": view,
            "user": user,
            "contains": contains,
            "include_low_value": include_low_value,
        },
        "communication_review": rows,
        "total_returned": len(rows),
    }


def _communication_conversation_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?", "parser_status = 'parsed'"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR sender LIKE ? OR recipients LIKE ? OR container_path LIKE ?)")
        params.extend([f"%{user}%"] * 5)
    if contains:
        filters.append("(subject LIKE ? OR sender LIKE ? OR recipients LIKE ?)")
        params.extend([f"%{contains}%"] * 3)
    grouped: dict[str, dict[str, Any]] = {}
    for row in db.conn.execute(
        f"""
        SELECT id, user_profile, source_format, container_path, message_path, subject,
               sender, recipients, message_date_utc, attachment_count, dedupe_key
        FROM mailbox_messages
        WHERE {' AND '.join(filters)}
        ORDER BY message_date_utc DESC, row_number
        """,
        params,
    ):
        item = dict(row)
        key = _conversation_key(item.get("subject"))
        group = grouped.setdefault(
            key,
            {
                "conversation_key": key,
                "subject": _clean_subject(item.get("subject")),
                "message_count": 0,
                "attachment_count": 0,
                "first_seen": None,
                "last_seen": None,
                "users": set(),
                "senders": set(),
                "recipients": set(),
                "source_formats": set(),
                "container_paths": set(),
                "source_ids": [],
            },
        )
        group["message_count"] += 1
        group["attachment_count"] += int(item.get("attachment_count") or 0)
        _set_min_max_time(group, item.get("message_date_utc"))
        _set_add(group["users"], item.get("user_profile"))
        _set_add(group["senders"], item.get("sender"))
        _set_add(group["recipients"], item.get("recipients"))
        _set_add(group["source_formats"], item.get("source_format"))
        _set_add(group["container_paths"], item.get("container_path"))
        if item.get("id"):
            group["source_ids"].append(item["id"])
    rows = []
    for group in grouped.values():
        rows.append(_finalize_set_group(group, ["users", "senders", "recipients", "source_formats", "container_paths"]))
    rows.sort(key=lambda item: (item.get("last_seen") or "", int(item.get("message_count") or 0)), reverse=True)
    return rows[:limit]


def _communication_pair_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?", "parser_status = 'parsed'"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR sender LIKE ? OR recipients LIKE ? OR container_path LIKE ?)")
        params.extend([f"%{user}%"] * 5)
    if contains:
        filters.append("(subject LIKE ? OR sender LIKE ? OR recipients LIKE ?)")
        params.extend([f"%{contains}%"] * 3)
    grouped: dict[str, dict[str, Any]] = {}
    for row in db.conn.execute(
        f"""
        SELECT id, user_profile, subject, sender, recipients, message_date_utc, container_path
        FROM mailbox_messages
        WHERE {' AND '.join(filters)}
        ORDER BY message_date_utc DESC, row_number
        """,
        params,
    ):
        item = dict(row)
        sender = _normalize_party(item.get("sender"))
        recipients = [_normalize_party(value) for value in _split_parties(item.get("recipients"))]
        if not recipients:
            recipients = [""]
        for recipient in recipients:
            key = f"{sender}|{recipient}"
            group = grouped.setdefault(
                key,
                {
                    "sender": sender,
                    "recipient": recipient,
                    "message_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "users": set(),
                    "subjects": set(),
                    "container_paths": set(),
                    "source_ids": [],
                },
            )
            group["message_count"] += 1
            _set_min_max_time(group, item.get("message_date_utc"))
            _set_add(group["users"], item.get("user_profile"))
            _set_add(group["subjects"], _clean_subject(item.get("subject")))
            _set_add(group["container_paths"], item.get("container_path"))
            if item.get("id"):
                group["source_ids"].append(item["id"])
    rows = [_finalize_set_group(group, ["users", "subjects", "container_paths"]) for group in grouped.values()]
    rows.sort(key=lambda item: (int(item.get("message_count") or 0), item.get("last_seen") or ""), reverse=True)
    return rows[:limit]


def _communication_attachment_review_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR sender LIKE ? OR recipients LIKE ? OR container_path LIKE ?)")
        params.extend([f"%{user}%"] * 5)
    if contains:
        filters.append("(subject LIKE ? OR sender LIKE ? OR recipients LIKE ? OR attachment_name LIKE ? OR content_type LIKE ?)")
        params.extend([f"%{contains}%"] * 5)
    return [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT id, message_date_utc, user_profile, subject, sender, recipients,
                   attachment_name, content_type, size, sha256, extraction_status,
                   CASE WHEN COALESCE(extracted_text_length, 0) > 0 THEN 1 ELSE 0 END AS has_extracted_text,
                   CASE WHEN COALESCE(metadata_json_length, 0) > 0 THEN 1 ELSE 0 END AS has_metadata,
                   attachment_path, message_path, container_path
            FROM mailbox_attachments
            WHERE {' AND '.join(filters)}
            ORDER BY message_date_utc DESC, attachment_name
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    ]


def _communication_indexed_only_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
) -> list[dict[str, Any]]:
    filters = ["wic.case_id = ?", "COALESCE(wic.content_length, 0) > 0"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(wic.item_path LIKE ? OR wic.item_name LIKE ?)")
        params.extend([f"%{user}%"] * 2)
    if contains:
        filters.append("(wic.item_path LIKE ? OR wic.item_name LIKE ?)")
        params.extend([f"%{contains}%"] * 2)
    rows = []
    for row in db.conn.execute(
        f"""
        SELECT wic.id, wic.source_table, wic.source_record_id, wic.work_id,
               COALESCE(wic.timestamp, wic.gather_time) AS timestamp,
               wic.item_path, wic.item_name, wic.item_type, wic.content_field,
               wic.opensearch_document_id, wic.content_sha256, wic.content_length
        FROM windows_search_indexed_content AS wic
        WHERE {' AND '.join(filters)}
          AND (
            lower(COALESCE(wic.item_path, '')) LIKE '%inbox%'
            OR lower(COALESCE(wic.item_path, '')) LIKE '%outlook%'
            OR lower(COALESCE(wic.item_path, '')) LIKE '%windowscommunicationsapps%'
            OR lower(COALESCE(wic.item_type, '')) LIKE '%email%'
          )
          AND NOT EXISTS (
            SELECT 1
            FROM mailbox_messages AS mm
            WHERE mm.case_id = wic.case_id
              AND mm.parser_status = 'parsed'
              AND (
                lower(COALESCE(wic.item_path, '')) LIKE '%' || lower(COALESCE(mm.subject, '')) || '%'
                OR wic.opensearch_document_id = mm.opensearch_document_id
              )
              AND (COALESCE(mm.subject, '') != '' OR COALESCE(mm.body_text_length, 0) >= 80)
          )
        ORDER BY COALESCE(wic.timestamp, wic.gather_time) DESC, wic.row_number
        LIMIT ?
        """,
        [*params, limit],
    ):
        item = dict(row)
        item["user_profile"] = _user_from_communication_path(db, case_id, item.get("item_path"))
        rows.append(item)
    return rows


def _communication_recovered_fragment_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
    include_low_value: bool,
) -> list[dict[str, Any]]:
    rows = _communication_mailbox_rows(db, case_id, max(limit * 4, 100), user=user, contains=contains)
    rows = [row for row in rows if row.get("source_type") in {"windows_mail_body", "windows_mail_encoded_fragment", "email_body_fragment"}]
    if not include_low_value:
        rows = [row for row in rows if row.get("review_value") != "low"]
    rows.sort(key=lambda row: row.get("timestamp") or "", reverse=True)
    return rows[:limit]


def _communication_mailbox_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?", "parser_status IN ('parsed', 'body_file_extracted')"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR container_path LIKE ? OR message_path LIKE ?)")
        params.extend([f"%{user}%"] * 4)
    if contains:
        filters.append("(subject LIKE ? OR sender LIKE ? OR recipients LIKE ? OR message_path LIKE ?)")
        params.extend([f"%{contains}%"] * 4)
    rows = []
    for row in db.conn.execute(
        f"""
        SELECT *
        FROM mailbox_messages
        WHERE {' AND '.join(filters)}
        ORDER BY message_date_utc DESC, row_number
        LIMIT ?
        """,
        [*params, limit],
    ):
        item = dict(row)
        source = "windows_mail_body" if item.get("parser_status") == "body_file_extracted" else "email"
        review_value = "normal"
        related = _related_windows_search_for_windows_mail(db, case_id, item) if source == "windows_mail_body" else []
        related_messages = _related_mailbox_messages_for_body(db, case_id, item) if source == "windows_mail_body" else []
        exact_match = next((match for match in related_messages if match.get("match_type") == "normalized_body_hash"), None)
        communication_key = (
            exact_match.get("dedupe_key")
            if exact_match and exact_match.get("dedupe_key")
            else item.get("dedupe_key") or item.get("opensearch_document_id") or _content_key("", item.get("message_path"))
        )
        rows.append(
            {
                "source_type": source,
                "source_table": "mailbox_messages",
                "source_id": item.get("id"),
                "computer_id": item.get("computer_id"),
                "image_id": item.get("image_id"),
                "user_profile": item.get("user_profile"),
                "timestamp": item.get("message_date_utc"),
                "sender": item.get("sender"),
                "recipients": item.get("recipients"),
                "title": item.get("subject"),
                "preview": "",
                "source_path": item.get("message_path"),
                "container_path": item.get("container_path"),
                "communication_key": communication_key,
                "attribution": item.get("parser_error") if source == "windows_mail_body" else "Parsed message headers/body.",
                "review_value": review_value,
                "related_windows_search_count": len(related),
                "related_windows_search": related[:3],
                "related_mailbox_message_count": len(related_messages),
                "related_mailbox_messages": related_messages[:3],
            }
        )
    return rows


def _communication_attachment_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?", "COALESCE(extracted_text_length, 0) > 0"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR user_sid LIKE ? OR container_path LIKE ? OR attachment_path LIKE ?)")
        params.extend([f"%{user}%"] * 4)
    if contains:
        filters.append("(subject LIKE ? OR sender LIKE ? OR recipients LIKE ? OR attachment_name LIKE ? OR content_type LIKE ?)")
        params.extend([f"%{contains}%"] * 5)
    rows = []
    for row in db.conn.execute(
        f"""
        SELECT *
        FROM mailbox_attachments
        WHERE {' AND '.join(filters)}
        ORDER BY message_date_utc DESC, row_number
        LIMIT ?
        """,
        [*params, limit],
    ):
        item = dict(row)
        rows.append(
            {
                "source_type": "email_attachment",
                "source_table": "mailbox_attachments",
                "source_id": item.get("id"),
                "computer_id": item.get("computer_id"),
                "image_id": item.get("image_id"),
                "user_profile": item.get("user_profile"),
                "timestamp": item.get("message_date_utc"),
                "sender": item.get("sender"),
                "recipients": item.get("recipients"),
                "title": item.get("attachment_name") or item.get("subject"),
                "preview": "",
                "source_path": item.get("attachment_path"),
                "container_path": item.get("container_path"),
                "communication_key": item.get("dedupe_key") or item.get("sha256") or item.get("opensearch_document_id") or _content_key("", item.get("attachment_path")),
                "attribution": "Attachment extracted from parsed message.",
                "review_value": "normal",
                "related_windows_search_count": 0,
                "related_windows_search": [],
                "related_mailbox_message_count": 0,
                "related_mailbox_messages": [],
            }
        )
    return rows


def _communication_windows_search_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?", "COALESCE(content_length, 0) > 0"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(item_path LIKE ? OR item_name LIKE ?)")
        params.extend([f"%{user}%"] * 2)
    if contains:
        filters.append("(item_path LIKE ? OR item_name LIKE ?)")
        params.extend([f"%{contains}%"] * 2)
    rows = []
    for row in db.conn.execute(
        f"""
        SELECT *
        FROM windows_search_indexed_content
        WHERE {' AND '.join(filters)}
          AND (
            lower(COALESCE(item_path, '')) LIKE '%inbox%'
            OR lower(COALESCE(item_path, '')) LIKE '%outlook%'
            OR lower(COALESCE(item_path, '')) LIKE '%windowscommunicationsapps%'
            OR lower(COALESCE(item_type, '')) LIKE '%email%'
          )
        ORDER BY COALESCE(timestamp, gather_time) DESC, row_number
        LIMIT ?
        """,
        [*params, limit],
    ):
        item = dict(row)
        rows.append(
            {
                "source_type": "windows_search_content",
                "source_table": "windows_search_indexed_content",
                "source_id": item.get("id"),
                "computer_id": item.get("computer_id"),
                "image_id": item.get("image_id"),
                "user_profile": _user_from_communication_path(db, case_id, item.get("item_path")),
                "timestamp": item.get("timestamp") or item.get("gather_time"),
                "sender": "",
                "recipients": "",
                "title": item.get("item_name"),
                "preview": "",
                "source_path": item.get("item_path"),
                "container_path": "",
                "communication_key": item.get("opensearch_document_id") or _content_key("", item.get("item_path")),
                "attribution": "Indexed content from Windows Search.",
                "review_value": "normal",
                "related_windows_search_count": 0,
                "related_windows_search": [],
                "related_mailbox_message_count": 0,
                "related_mailbox_messages": [],
            }
        )
    return rows


def _communication_messaging_rows(
    db: Database,
    case_id: str,
    limit: int,
    *,
    user: str | None,
    contains: str | None,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("(user_profile LIKE ? OR sender_email LIKE ? OR sender_name LIKE ?)")
        params.extend([f"%{user}%"] * 3)
    if contains:
        filters.append("(sender_email LIKE ? OR sender_name LIKE ? OR url LIKE ?)")
        params.extend([f"%{contains}%"] * 3)
    rows = []
    for row in db.conn.execute(
        f"""
        SELECT *
        FROM messaging_messages
        WHERE {' AND '.join(filters)}
        ORDER BY timestamp_utc DESC, row_number
        LIMIT ?
        """,
        [*params, limit],
    ):
        item = dict(row)
        rows.append(
            {
                "source_type": "app_message",
                "source_table": "messaging_messages",
                "source_id": item.get("id"),
                "computer_id": item.get("computer_id"),
                "image_id": item.get("image_id"),
                "user_profile": item.get("user_profile"),
                "timestamp": item.get("timestamp_utc"),
                "sender": item.get("sender_email") or item.get("sender_name"),
                "recipients": item.get("conversation_id"),
                "title": item.get("application"),
                "preview": "",
                "source_path": item.get("source_path"),
                "container_path": item.get("store_path"),
                "communication_key": item.get("dedupe_key") or item.get("opensearch_document_id") or _content_key("", item.get("source_path")),
                "attribution": "Message extracted from application store/cache.",
                "review_value": "normal",
                "related_windows_search_count": 0,
                "related_windows_search": [],
                "related_mailbox_message_count": 0,
                "related_mailbox_messages": [],
            }
        )
    return rows


def event_interpretation_report(
    db: Database,
    case_id: str,
    *,
    category: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    rows = []
    for row in db.conn.execute(
        """
        SELECT evtx_events.*, computers.label AS computer_label
        FROM evtx_events
        LEFT JOIN computers ON evtx_events.computer_id = computers.id
        WHERE evtx_events.case_id = ?
        ORDER BY evtx_events.time_created DESC
        LIMIT ?
        """,
        (case_id, limit * 20),
    ):
        interpreted = _interpret_evtx_row(row)
        if interpreted is None:
            continue
        if category and interpreted["category"] != category:
            continue
        rows.append(interpreted)
        if len(rows) >= limit:
            break
    category_counts: dict[str, int] = {}
    for row in rows:
        category_counts[row["category"]] = category_counts.get(row["category"], 0) + 1
    return {
        "case_id": case_id,
        "filters": {"category": category},
        "category_counts": category_counts,
        "events": rows,
        "total_returned": len(rows),
    }


def timeline_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    event_type: str | None = None,
    source_tool: str | None = None,
    contains: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["timeline_events.case_id = ?", "timeline_events.dedupe_status != 'duplicate'"]
    params: list[Any] = [case_id]
    if event_type:
        where.append("timeline_events.event_type = ?")
        params.append(event_type)
    if source_tool:
        where.append("timeline_events.source_tool = ?")
        params.append(source_tool)
    if contains:
        where.append("(timeline_events.description LIKE ? OR timeline_events.details_json LIKE ?)")
        params.extend([f"%{contains}%", f"%{contains}%"])
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT timeline_events.*, computers.label AS computer_label, images.path AS image_path,
               (
                 SELECT COUNT(*)
                 FROM timeline_event_sources
                 WHERE timeline_event_sources.primary_event_id = timeline_events.id
               ) AS source_count
        FROM timeline_events
        LEFT JOIN computers ON timeline_events.computer_id = computers.id
        LEFT JOIN images ON timeline_events.image_id = images.id
        WHERE {' AND '.join(where)}
        ORDER BY timeline_events.timestamp_utc
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {"case_id": case_id, "events": _rows_with_details(rows), "total_returned": len(rows)}


def timeline_sources_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    source_scope: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["timeline_event_sources.case_id = ?"]
    params: list[Any] = [case_id]
    if source_scope:
        where.append("timeline_event_sources.source_scope = ?")
        params.append(source_scope)
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT timeline_event_sources.*,
               primary_event.timestamp_utc AS primary_timestamp_utc,
               primary_event.event_type AS primary_event_type,
               primary_event.description AS primary_description,
               duplicate_event.timestamp_utc AS source_timestamp_utc,
               duplicate_event.event_type AS source_event_type,
               duplicate_event.description AS source_description
        FROM timeline_event_sources
        JOIN timeline_events AS primary_event
          ON primary_event.id = timeline_event_sources.primary_event_id
        JOIN timeline_events AS duplicate_event
          ON duplicate_event.id = timeline_event_sources.duplicate_event_id
        WHERE {' AND '.join(where)}
        ORDER BY primary_event.timestamp_utc, timeline_event_sources.source_scope
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {"case_id": case_id, "sources": _rows_with_details(rows), "total_returned": len(rows)}


def artifact_sources_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    artifact_family: str | None = None,
    source_scope: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["artifact_record_sources.case_id = ?"]
    params: list[Any] = [case_id]
    if artifact_family:
        where.append("artifact_record_sources.artifact_family = ?")
        params.append(artifact_family)
    if source_scope:
        where.append("artifact_record_sources.source_scope = ?")
        params.append(source_scope)
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT artifact_record_sources.*
        FROM artifact_record_sources
        WHERE {' AND '.join(where)}
        ORDER BY artifact_family, primary_table, primary_row_id, source_scope
        LIMIT ?
        """,
        params,
    ).fetchall()
    counts = db.conn.execute(
        f"""
        SELECT artifact_family, source_scope, COUNT(*) AS count
        FROM artifact_record_sources
        WHERE {' AND '.join(where)}
        GROUP BY artifact_family, source_scope
        ORDER BY artifact_family, source_scope
        """,
        params[:-1],
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"artifact_family": artifact_family, "source_scope": source_scope},
        "summary": {"counts": [dict(row) for row in counts]},
        "sources": _rows_with_details(rows),
        "total_returned": len(rows),
    }


def timeline_review_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 500,
    user: str | None = None,
    contains: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    events: list[dict[str, Any]] = []
    source_limit = max(limit * 25, 250)

    def add_event(
        *,
        timestamp: Any,
        source_name: str,
        source_table: str,
        source_id: Any,
        event_type: str,
        summary: str | None,
        user_profile: str | None = None,
        file_path: str | None = None,
        artifact: str | None = None,
        basis: str | None = None,
    ) -> None:
        if not timestamp or _is_placeholder_timestamp(str(timestamp)):
            return
        row = {
            "timestamp": str(timestamp),
            "user": user_profile or _user_from_path(file_path),
            "source": source_name,
            "event_type": event_type,
            "file_path": file_path,
            "artifact": artifact or source_name,
            "summary": summary or file_path or "",
            "confidence_basis": basis or source_table,
            "source_table": source_table,
            "source_record_id": str(source_id or ""),
        }
        if user and user.lower() not in " ".join(str(value or "").lower() for value in row.values()):
            return
        if contains and contains.lower() not in " ".join(str(value or "").lower() for value in row.values()):
            return
        if source and source.lower() != source_name.lower():
            return
        events.append(row)

    timeline_filters = ["case_id = ?", "dedupe_status != 'duplicate'"]
    timeline_params: list[Any] = [case_id]
    if contains:
        timeline_filters.append("(description LIKE ? OR details_json LIKE ?)")
        timeline_params.extend([f"%{contains}%", f"%{contains}%"])
    timeline_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, source_tool, source_table, source_row_id, timestamp_utc,
               event_type, description, details_json
        FROM timeline_events
        WHERE {' AND '.join(timeline_filters)}
        ORDER BY timestamp_utc DESC
        LIMIT ?
        """,
        timeline_params,
    ):
        add_event(
            timestamp=row["timestamp_utc"],
            source_name=row["source_tool"] or "timeline",
            source_table=row["source_table"],
            source_id=row["source_row_id"],
            event_type=row["event_type"],
            summary=row["description"],
            basis="normalized timeline event",
        )

    mft_filters = ["case_id = ?"]
    mft_params: list[Any] = [case_id]
    if user:
        mft_filters.append("(parent_path LIKE ? OR file_name LIKE ?)")
        mft_params.extend([f"%/Users/{user}/%", f"%{user}%"])
    if contains:
        mft_filters.append("(parent_path LIKE ? OR file_name LIKE ?)")
        mft_params.extend([f"%{contains}%", f"%{contains}%"])
    mft_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, parent_path, file_name, created_si, modified_si, accessed_si,
               record_changed_si, in_use
        FROM mft_entries
        WHERE {' AND '.join(mft_filters)}
        ORDER BY COALESCE(modified_si, created_si, accessed_si) DESC
        LIMIT ?
        """,
        mft_params,
    ):
        path = _join_path(row["parent_path"], row["file_name"])
        for event_type, field in (
            ("file_created", "created_si"),
            ("file_modified", "modified_si"),
            ("file_accessed", "accessed_si"),
            ("file_record_changed", "record_changed_si"),
        ):
            add_event(
                timestamp=row[field],
                source_name="mft",
                source_table="mft_entries",
                source_id=row["id"],
                event_type=event_type,
                file_path=path,
                summary=f"{event_type}: {path}",
                basis=f"MFT $STANDARD_INFORMATION {field}; in_use={row['in_use']}",
            )

    usn_filters = ["case_id = ?"]
    usn_params: list[Any] = [case_id]
    if user:
        usn_filters.append("(full_path LIKE ? OR file_name LIKE ?)")
        usn_params.extend([f"%/Users/{user}/%", f"%{user}%"])
    if contains:
        usn_filters.append("(full_path LIKE ? OR file_name LIKE ? OR reason LIKE ?)")
        usn_params.extend([f"%{contains}%", f"%{contains}%", f"%{contains}%"])
    usn_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, update_timestamp, reason, file_name, full_path
        FROM usn_journal_entries
        WHERE {' AND '.join(usn_filters)}
        ORDER BY update_timestamp DESC
        LIMIT ?
        """,
        usn_params,
    ):
        add_event(
            timestamp=row["update_timestamp"],
            source_name="usn",
            source_table="usn_journal_entries",
            source_id=row["id"],
            event_type="usn_change",
            file_path=row["full_path"],
            summary=f"{row['reason']}: {row['full_path'] or row['file_name']}",
            basis="USN journal reason flags",
        )

    shortcut_filters = ["case_id = ?"]
    shortcut_params: list[Any] = [case_id]
    if user:
        shortcut_filters.append("(artifact_path LIKE ? OR file_location LIKE ?)")
        shortcut_params.extend([f"%{user}%", f"%{user}%"])
    if contains:
        shortcut_filters.append("(artifact_path LIKE ? OR file_location LIKE ? OR file_name LIKE ? OR artifact_name LIKE ?)")
        shortcut_params.extend([f"%{contains}%"] * 4)
    shortcut_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, artifact_type, artifact_name, artifact_path, file_name, file_location,
               target_created, target_modified, target_accessed
        FROM shortcut_items
        WHERE {' AND '.join(shortcut_filters)}
        ORDER BY COALESCE(target_accessed, target_modified, target_created) DESC
        LIMIT ?
        """,
        shortcut_params,
    ):
        file_path = row["file_location"] or row["file_name"]
        for event_type, field in (
            ("target_created", "target_created"),
            ("target_modified", "target_modified"),
            ("target_accessed", "target_accessed"),
        ):
            add_event(
                timestamp=row[field],
                source_name=row["artifact_type"] or "shortcut",
                source_table="shortcut_items",
                source_id=row["id"],
                event_type=event_type,
                file_path=file_path,
                artifact=row["artifact_name"],
                summary=f"{event_type}: {file_path}",
                basis=f"{row['artifact_type']} embedded target timestamp",
            )

    shellbag_filters = ["case_id = ?"]
    shellbag_params: list[Any] = [case_id]
    if user:
        shellbag_filters.append("(user_profile LIKE ? OR absolute_path LIKE ?)")
        shellbag_params.extend([f"%{user}%", f"%{user}%"])
    if contains:
        shellbag_filters.append("absolute_path LIKE ?")
        shellbag_params.append(f"%{contains}%")
    shellbag_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, user_profile, absolute_path, created_on, modified_on, accessed_on,
               first_interacted, last_interacted
        FROM shellbag_entries
        WHERE {' AND '.join(shellbag_filters)}
        ORDER BY COALESCE(last_interacted, first_interacted, modified_on, accessed_on, created_on) DESC
        LIMIT ?
        """,
        shellbag_params,
    ):
        for event_type, field in (
            ("shellbag_created", "created_on"),
            ("shellbag_modified", "modified_on"),
            ("shellbag_accessed", "accessed_on"),
            ("shellbag_first_interacted", "first_interacted"),
            ("shellbag_last_interacted", "last_interacted"),
        ):
            add_event(
                timestamp=row[field],
                source_name="shellbags",
                source_table="shellbag_entries",
                source_id=row["id"],
                event_type=event_type,
                user_profile=row["user_profile"],
                file_path=row["absolute_path"],
                summary=f"{event_type}: {row['absolute_path']}",
                basis="ShellBag shell item timestamp",
            )

    registry_filters = ["case_id = ?", "COALESCE(event_time_utc, '') != ''"]
    registry_params: list[Any] = [case_id]
    if user:
        registry_filters.append("(user_profile LIKE ? OR key_path LIKE ? OR value_data LIKE ?)")
        registry_params.extend([f"%{user}%"] * 3)
    if contains:
        registry_filters.append("(artifact LIKE ? OR key_path LIKE ? OR value_name LIKE ? OR value_data LIKE ?)")
        registry_params.extend([f"%{contains}%"] * 4)
    registry_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, artifact, user_profile, event_time_utc, key_path, value_name, value_data
        FROM registry_artifacts
        WHERE {' AND '.join(registry_filters)}
        ORDER BY event_time_utc DESC
        LIMIT ?
        """,
        registry_params,
    ):
        add_event(
            timestamp=row["event_time_utc"],
            source_name="registry",
            source_table="registry_artifacts",
            source_id=row["id"],
            event_type=row["artifact"] or "registry_artifact",
            user_profile=row["user_profile"],
            file_path=row["value_data"],
            artifact=row["artifact"],
            summary=f"{row['artifact']}: {row['value_name'] or row['key_path']}",
            basis="registry key/value timestamp",
        )

    browser_filters = ["case_id = ?"]
    browser_params: list[Any] = [case_id]
    if user:
        browser_filters.append("profile_path LIKE ?")
        browser_params.append(f"%{user}%")
    if contains:
        browser_filters.append("(url LIKE ? OR title LIKE ?)")
        browser_params.extend([f"%{contains}%"] * 2)
    browser_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, browser, profile_path, url, title, visit_time_utc
        FROM browser_history
        WHERE {' AND '.join(browser_filters)}
        ORDER BY visit_time_utc DESC
        LIMIT ?
        """,
        browser_params,
    ):
        add_event(
            timestamp=row["visit_time_utc"],
            source_name="browser",
            source_table="browser_history",
            source_id=row["id"],
            event_type="browser_visit",
            user_profile=_user_from_path(row["profile_path"]),
            file_path=row["url"],
            artifact=row["browser"],
            summary=row["title"] or row["url"],
            basis="browser history visit time",
        )

    download_filters = ["case_id = ?"]
    download_params: list[Any] = [case_id]
    if user:
        download_filters.append("(profile_path LIKE ? OR target_path LIKE ?)")
        download_params.extend([f"%{user}%"] * 2)
    if contains:
        download_filters.append("(target_path LIKE ? OR tab_url LIKE ? OR site_url LIKE ?)")
        download_params.extend([f"%{contains}%"] * 3)
    download_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, browser, profile_path, target_path, tab_url, start_time_utc, end_time_utc
        FROM browser_downloads
        WHERE {' AND '.join(download_filters)}
        ORDER BY COALESCE(end_time_utc, start_time_utc) DESC
        LIMIT ?
        """,
        download_params,
    ):
        add_event(
            timestamp=row["start_time_utc"],
            source_name="browser_download",
            source_table="browser_downloads",
            source_id=row["id"],
            event_type="download_started",
            user_profile=_user_from_path(row["profile_path"]),
            file_path=row["target_path"],
            artifact=row["browser"],
            summary=row["tab_url"] or row["target_path"],
            basis="browser download start time",
        )
        add_event(
            timestamp=row["end_time_utc"],
            source_name="browser_download",
            source_table="browser_downloads",
            source_id=row["id"],
            event_type="download_ended",
            user_profile=_user_from_path(row["profile_path"]),
            file_path=row["target_path"],
            artifact=row["browser"],
            summary=row["target_path"],
            basis="browser download end time",
        )

    mailbox_filters = ["case_id = ?", "parser_status IN ('parsed', 'body_file_extracted')"]
    mailbox_params: list[Any] = [case_id]
    if user:
        mailbox_filters.append("(user_profile LIKE ? OR sender LIKE ? OR recipients LIKE ? OR container_path LIKE ?)")
        mailbox_params.extend([f"%{user}%"] * 4)
    if contains:
        mailbox_filters.append("(subject LIKE ? OR sender LIKE ? OR recipients LIKE ? OR message_path LIKE ?)")
        mailbox_params.extend([f"%{contains}%"] * 4)
    mailbox_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, user_profile, subject, sender, recipients, message_date_utc, message_path
        FROM mailbox_messages
        WHERE {' AND '.join(mailbox_filters)}
        ORDER BY message_date_utc DESC
        LIMIT ?
        """,
        mailbox_params,
    ):
        add_event(
            timestamp=row["message_date_utc"],
            source_name="email",
            source_table="mailbox_messages",
            source_id=row["id"],
            event_type="email_message",
            user_profile=row["user_profile"],
            file_path=row["message_path"],
            summary=row["subject"] or f"{row['sender']} -> {row['recipients']}",
            basis="message date",
        )

    usb_filters = ["case_id = ?"]
    usb_params: list[Any] = [case_id]
    if contains:
        usb_filters.append("(serial LIKE ? OR volume_serial_number LIKE ? OR drive_letter LIKE ?)")
        usb_params.extend([f"%{contains}%"] * 3)
    usb_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, serial, volume_serial_number, drive_letter,
               event_type, event_time_utc
        FROM usb_connection_events
        WHERE {' AND '.join(usb_filters)}
        ORDER BY event_time_utc DESC
        LIMIT ?
        """,
        usb_params,
    ):
        add_event(
            timestamp=row["event_time_utc"],
            source_name="usb",
            source_table="usb_connection_events",
            source_id=row["id"],
            event_type=f"usb_{row['event_type']}",
            file_path=row["drive_letter"],
            summary=f"{row['event_type']}: {row['serial']} {row['volume_serial_number'] or ''}".strip(),
            basis="USB connection event",
        )

    recycle_filters = ["case_id = ?"]
    recycle_params: list[Any] = [case_id]
    if user:
        recycle_filters.append("original_path LIKE ?")
        recycle_params.append(f"%{user}%")
    if contains:
        recycle_filters.append("(original_path LIKE ? OR display_name LIKE ? OR top_level_name LIKE ?)")
        recycle_params.extend([f"%{contains}%"] * 3)
    recycle_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, original_path, deletion_time_utc, display_name, top_level_name
        FROM recycle_items
        WHERE {' AND '.join(recycle_filters)}
        ORDER BY deletion_time_utc DESC
        LIMIT ?
        """,
        recycle_params,
    ):
        add_event(
            timestamp=row["deletion_time_utc"],
            source_name="recycle_bin",
            source_table="recycle_items",
            source_id=row["id"],
            event_type="file_deleted_to_recycle_bin",
            file_path=row["original_path"],
            summary=row["display_name"] or row["top_level_name"] or row["original_path"],
            basis="$I recycle metadata",
        )

    search_filters = ["case_id = ?"]
    search_params: list[Any] = [case_id]
    if user:
        search_filters.append("item_path LIKE ?")
        search_params.append(f"%{user}%")
    if contains:
        search_filters.append("(item_path LIKE ? OR item_name LIKE ?)")
        search_params.extend([f"%{contains}%"] * 2)
    search_params.append(source_limit)
    for row in db.conn.execute(
        f"""
        SELECT id, item_path, item_name, item_type, timestamp, gather_time
        FROM windows_search_indexed_content
        WHERE {' AND '.join(search_filters)}
        ORDER BY COALESCE(timestamp, gather_time) DESC
        LIMIT ?
        """,
        search_params,
    ):
        add_event(
            timestamp=row["timestamp"] or row["gather_time"],
            source_name="windows_search",
            source_table="windows_search_indexed_content",
            source_id=row["id"],
            event_type="indexed_content",
            user_profile=_user_from_path(row["item_path"]),
            file_path=row["item_path"],
            artifact=row["item_type"],
            summary=row["item_name"] or row["item_path"],
            basis="Windows Search timestamp/gather time",
        )

    events = _dedupe_review_events(events)
    events.sort(key=lambda item: (item["timestamp"], item["source"], item["event_type"]))
    return {
        "case_id": case_id,
        "filters": {"user": user, "contains": contains, "source": source},
        "events": events[:limit],
        "total_events": len(events),
        "total_returned": min(len(events), limit),
        "source_counts": _review_event_counts(events, "source"),
        "event_type_counts": _review_event_counts(events, "event_type"),
    }


def validation_report(db: Database, case_id: str) -> dict[str, Any]:
    db.get_case(case_id)
    expected_tools = [
        "MFTECmd", "MFTECmdUSN", "MFTECmdI30", "SAMParser", "RegistryParser", "RECmd",
        "RegistryArtifactParser", "SrumECmd", "AmcacheParser", "AppCompatCacheParser",
        "SBECmd", "PrefetchParser", "RecycleParser", "FirefoxParser", "ChromiumParser",
        "WebCacheParser", "JLECmd", "LECmd", "SIDR",
    ]
    outputs = db.conn.execute(
        """
        SELECT tool_name, COUNT(*) AS output_count, COALESCE(SUM(row_count), 0) AS row_count
        FROM tool_outputs
        WHERE case_id = ?
        GROUP BY tool_name
        """,
        (case_id,),
    ).fetchall()
    output_by_tool = {row["tool_name"]: dict(row) for row in outputs}
    failed_jobs = db.conn.execute(
        """
        SELECT id, tool_name, start_time, end_time, exit_code, stderr_path
        FROM jobs
        WHERE case_id = ? AND (exit_code IS NULL OR exit_code != 0)
        ORDER BY start_time
        """,
        (case_id,),
    ).fetchall()
    issue_counts = db.conn.execute(
        """
        SELECT level, COUNT(*) AS count
        FROM activity_log
        WHERE case_id = ? AND level IN ('warning', 'error')
        GROUP BY level
        """,
        (case_id,),
    ).fetchall()
    skipped = db.conn.execute(
        """
        SELECT event, message, COUNT(*) AS count
        FROM activity_log
        WHERE case_id = ? AND (event LIKE '%skipped%' OR message LIKE '%skipped%')
        GROUP BY event, message
        ORDER BY count DESC
        """,
        (case_id,),
    ).fetchall()
    missing = [tool for tool in expected_tools if tool not in output_by_tool]
    return {
        "case_id": case_id,
        "tools_with_outputs": list(output_by_tool.values()),
        "expected_tools_without_outputs": missing,
        "failed_or_unfinished_jobs": [dict(row) for row in failed_jobs],
        "issue_counts": {row["level"]: row["count"] for row in issue_counts},
        "skipped_activity": [dict(row) for row in skipped],
        "evtx_recovery": _evtx_recovery_counts(db, case_id),
    }


def registry_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "registry_hives", "registry_hives", limit)


def amcache_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "amcache_entries", "amcache_entries", limit)


def shimcache_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "shimcache_entries", "shimcache_entries", limit)


def shellbags_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    return _table_report(db, case_id, "shellbag_entries", "shellbag_entries", limit)


def usb_report(db: Database, case_id: str, *, limit: int = 100, raw: bool = False) -> dict[str, Any]:
    if raw:
        return _table_report(db, case_id, "usb_devices", "usb_devices", limit)
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT usb_storage_devices.*, computers.label AS computer_label, images.path AS image_path
        FROM usb_storage_devices
        LEFT JOIN computers ON usb_storage_devices.computer_id = computers.id
        LEFT JOIN images ON usb_storage_devices.image_id = images.id
        WHERE usb_storage_devices.case_id = ?
        ORDER BY COALESCE(last_removal_utc, last_arrival_utc, first_install_date_utc, serial), serial
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    devices = []
    for row in rows:
        item = dict(row)
        item["first_connection_utc"] = item.get("first_install_date_utc")
        devices.append(item)
    return {"case_id": case_id, "usb_storage_devices": devices, "total_returned": len(devices)}


def usb_breakdown_report(db: Database, case_id: str) -> dict[str, Any]:
    db.get_case(case_id)
    total_raw = db.conn.execute(
        "SELECT COUNT(*) AS count FROM usb_devices WHERE case_id = ?",
        (case_id,),
    ).fetchone()["count"]
    total_storage = db.conn.execute(
        "SELECT COUNT(*) AS count FROM usb_storage_devices WHERE case_id = ?",
        (case_id,),
    ).fetchone()["count"]
    artifact_counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT artifact, COUNT(*) AS row_count
            FROM usb_devices
            WHERE case_id = ?
            GROUP BY artifact
            ORDER BY row_count DESC, artifact
            """,
            (case_id,),
        ).fetchall()
    ]
    device_type_counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT device_type, COUNT(*) AS row_count
            FROM usb_devices
            WHERE case_id = ?
            GROUP BY device_type
            ORDER BY row_count DESC, device_type
            """,
            (case_id,),
        ).fetchall()
    ]
    storage_evidence_counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT artifact, device_type, COUNT(*) AS row_count
            FROM usb_devices
            WHERE case_id = ?
              AND device_type IN (
                'usb_storage',
                'scsi_storage',
                'usb_volume',
                'portable_device_volume',
                'mounted_device',
                'usb_partition_diagnostic'
              )
            GROUP BY artifact, device_type
            ORDER BY row_count DESC, artifact, device_type
            """,
            (case_id,),
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "raw_usb_evidence_rows": total_raw,
        "summarized_usb_storage_devices": total_storage,
        "artifact_counts": artifact_counts,
        "device_type_counts": device_type_counts,
        "storage_evidence_counts": storage_evidence_counts,
    }


def usb_verbose_report(
    db: Database,
    case_id: str,
    *,
    serial: str | None = None,
    volume_serial_number: str | None = None,
    volume_guid: str | None = None,
    limit: int = 250,
) -> dict[str, Any]:
    db.get_case(case_id)
    rebuild_usb_file_correlations(db, case_id)
    device = _find_usb_storage_device(
        db,
        case_id,
        serial=serial,
        volume_serial_number=volume_serial_number,
        volume_guid=volume_guid,
    )
    device_id = {
        "serial": device["serial"],
        "volume_serial_number": device["volume_serial_number"],
        "volume_guid": device["volume_guid"],
    }
    raw_rows = _usb_verbose_raw_rows(db, case_id, device_id)
    file_rows = _usb_verbose_file_rows(db, case_id, device, limit=limit)
    return {
        "case_id": case_id,
        "query": {
            "serial": serial,
            "volume_serial_number": volume_serial_number,
            "volume_guid": volume_guid,
        },
        "device": device,
        "description_attributes": _usb_verbose_description_attributes(device, raw_rows),
        "connection_times": _usb_verbose_connection_times(device, raw_rows),
        "volume_attributes": _usb_verbose_volume_attributes(device, raw_rows),
        "mbr_vbr_details": _usb_verbose_mbr_vbr_details(raw_rows),
        "other_details": _usb_verbose_other_details(raw_rows),
        "files_opened_accessed": file_rows,
        "raw_evidence_counts": _usb_verbose_counts(raw_rows),
        "raw_evidence_rows": [_usb_verbose_raw_summary(row) for row in raw_rows],
        "total_files_returned": len(file_rows),
        "total_raw_evidence_rows": len(raw_rows),
    }


def rebuild_usb_file_correlations(db: Database, case_id: str) -> int:
    db.get_case(case_id)
    rows = _usb_file_correlation_rows(db, case_id, limit=None)
    created_at = utc_now()
    correlation_rows = []
    for row in rows:
        item = dict(row)
        item["id"] = str(uuid.uuid4())
        item["created_at"] = created_at
        if not item.get("user_profile"):
            item["user_profile"] = _user_profile_from_artifact_path(item.get("source_artifact_path"))
        correlation_rows.append(item)
    with db.bulk_transaction():
        db.delete_usb_file_correlations(case_id=case_id)
        db.insert_usb_file_correlations(correlation_rows)
    return len(correlation_rows)


def usb_file_correlation_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 500,
    persist: bool = True,
    grouped: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    if persist:
        rebuild_usb_file_correlations(db, case_id)
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT *
            FROM usb_file_correlations
            WHERE case_id = ?
            ORDER BY
              usb_volume_serial_number,
              source_artifact_type,
              file_location,
              file_name,
              source_artifact_path
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]
    files = _dedupe_usb_file_items(rows)
    counts_by_device: dict[tuple[str, str | None, str | None, str | None], dict[str, Any]] = {}
    for row in rows:
        key = (
            row["usb_serial"],
            row["usb_volume_serial_number"],
            row["usb_volume_name"],
            row["usb_drive_letter"],
        )
        item = counts_by_device.setdefault(
            key,
            {
                "usb_serial": row["usb_serial"],
                "usb_volume_serial_number": row["usb_volume_serial_number"],
                "usb_volume_name": row["usb_volume_name"],
                "usb_drive_letter": row["usb_drive_letter"],
                "usb_product": row["usb_product"],
                "file_artifact_matches": 0,
                "lnk_matches": 0,
                "jumplist_matches": 0,
                "shellbag_matches": 0,
                "exact_vsn_matches": 0,
                "suffix_vsn_matches": 0,
            },
        )
        item["file_artifact_matches"] += 1
        if row["source_artifact_type"] == "lnk":
            item["lnk_matches"] += 1
        elif row["source_artifact_type"] == "jumplist":
            item["jumplist_matches"] += 1
        elif row["source_artifact_type"] == "shellbag":
            item["shellbag_matches"] += 1
        if row["volume_serial_match"] == "exact":
            item["exact_vsn_matches"] += 1
        elif row["volume_serial_match"] == "suffix":
            item["suffix_vsn_matches"] += 1
    shellbag_rows = db.conn.execute(
        "SELECT COUNT(*) AS count FROM shellbag_entries WHERE case_id = ?",
        (case_id,),
    ).fetchone()["count"]
    return {
        "case_id": case_id,
        "correlation_key": "normalized volume serial number",
        "notes": [
            "LNK and Jump List rows are matched to USB storage devices by volume serial number.",
            "Shellbag rows participate when volume serial data is available in shellbag_entries.",
            "Suffix matching is used when USB evidence has a wider NTFS-style serial and shortcut evidence has the lower 32-bit serial.",
        ],
        "shellbag_rows_available": shellbag_rows,
        "devices": list(counts_by_device.values()),
        "files": files,
        "items": rows,
        "total_files": len(files),
        "total_returned": len(files) if grouped else len(rows),
    }


def _usb_file_correlation_rows(db: Database, case_id: str, *, limit: int | None) -> list[dict[str, Any]]:
    limit_clause = "" if limit is None else "LIMIT ?"
    params: list[Any] = [case_id, case_id, case_id, case_id, case_id]
    if limit is not None:
        params.append(limit)
    return [
        dict(row)
        for row in db.conn.execute(
            f"""
            WITH usb AS (
              SELECT *,
                     UPPER(REPLACE(volume_serial_number, '-', '')) AS usb_vsn_norm,
                     UPPER(REPLACE(REPLACE(volume_guid, CHAR(123), ''), CHAR(125), '')) AS usb_guid_norm,
                     UPPER(drive_letter) AS usb_drive_norm
              FROM usb_storage_devices
              WHERE case_id = ?
            ),
            usb_sessions AS (
              SELECT
                start_event.case_id,
                start_event.image_id,
                start_event.serial,
                UPPER(REPLACE(start_event.volume_serial_number, '-', '')) AS session_vsn_norm,
                start_event.event_time_utc AS session_start,
                COALESCE(
                  (
                    SELECT MIN(end_event.event_time_utc)
                    FROM usb_connection_events end_event
                    WHERE end_event.case_id = start_event.case_id
                      AND end_event.image_id = start_event.image_id
                      AND end_event.serial = start_event.serial
                      AND end_event.event_type = 'removal'
                      AND datetime(REPLACE(SUBSTR(end_event.event_time_utc, 1, 19), 'T', ' ')) >=
                          datetime(REPLACE(SUBSTR(start_event.event_time_utc, 1, 19), 'T', ' '))
                  ),
                  start_event.event_time_utc
                ) AS session_end
              FROM usb_connection_events start_event
              WHERE start_event.case_id = ?
                AND start_event.event_type IN ('arrival', 'first_connected', 'partition_seen')
            ),
            artifacts AS (
              SELECT
                id AS source_artifact_id,
                case_id,
                computer_id,
                image_id,
                artifact_type AS source_artifact_type,
                artifact_name AS source_artifact_name,
                artifact_path AS source_artifact_path,
                NULL AS user_profile,
                jumplist_item_number,
                file_name,
                file_location,
                target_created,
                target_modified,
                target_accessed,
                device_type,
                volume_serial_number AS artifact_volume_serial_number,
                volume_name AS artifact_volume_name,
                NULL AS artifact_volume_guid,
                NULL AS artifact_drive_letter,
                UPPER(REPLACE(volume_serial_number, '-', '')) AS artifact_vsn_norm,
                NULL AS artifact_guid_norm,
                NULL AS artifact_drive_norm,
                UPPER(REPLACE(COALESCE(file_location, file_name, ''), '\\\\', '\\')) AS artifact_path_norm,
                NULL AS interaction_start_norm,
                NULL AS interaction_end_norm
              FROM shortcut_items
              WHERE case_id = ?
                AND volume_serial_number IS NOT NULL
                AND TRIM(volume_serial_number) != ''
              UNION ALL
              SELECT
                id AS source_artifact_id,
                case_id,
                computer_id,
                image_id,
                'shellbag' AS source_artifact_type,
                value_name AS source_artifact_name,
                source_file AS source_artifact_path,
                user_profile,
                NULL AS jumplist_item_number,
                NULL AS file_name,
                absolute_path AS file_location,
                created_on AS target_created,
                modified_on AS target_modified,
                COALESCE(NULLIF(last_interacted, ''), NULLIF(first_interacted, ''), accessed_on) AS target_accessed,
                shell_type AS device_type,
                volume_serial_number AS artifact_volume_serial_number,
                volume_name AS artifact_volume_name,
                volume_guid AS artifact_volume_guid,
                drive_letter AS artifact_drive_letter,
                UPPER(REPLACE(volume_serial_number, '-', '')) AS artifact_vsn_norm,
                UPPER(REPLACE(REPLACE(volume_guid, CHAR(123), ''), CHAR(125), '')) AS artifact_guid_norm,
                UPPER(drive_letter) AS artifact_drive_norm,
                UPPER(
                  REPLACE(
                    REPLACE(
                      REPLACE(COALESCE(absolute_path, ''), 'Desktop\\This PC\\', ''),
                      'Desktop\\',
                      ''
                    ),
                    '\\\\',
                    '\\'
                  )
                ) AS artifact_path_norm,
                datetime(
                  REPLACE(
                    SUBSTR(
                      COALESCE(NULLIF(first_interacted, ''), NULLIF(last_interacted, '')),
                      1,
                      19
                    ),
                    'T',
                    ' '
                  )
                ) AS interaction_start_norm,
                datetime(
                  REPLACE(
                    SUBSTR(
                      COALESCE(NULLIF(last_interacted, ''), NULLIF(first_interacted, '')),
                      1,
                      19
                    ),
                    'T',
                    ' '
                  )
                ) AS interaction_end_norm
              FROM shellbag_entries
              WHERE case_id = ?
                AND (
                  (volume_serial_number IS NOT NULL AND TRIM(volume_serial_number) != '')
                  OR (volume_guid IS NOT NULL AND TRIM(volume_guid) != '')
                  OR (drive_letter IS NOT NULL AND TRIM(drive_letter) != '')
                )
            ),
            anchor_paths AS (
              SELECT
                case_id,
                UPPER(REPLACE(volume_serial_number, '-', '')) AS anchor_vsn_norm,
                UPPER(REPLACE(COALESCE(file_location, file_name, ''), '\\\\', '\\')) AS anchor_path_norm
              FROM shortcut_items
              WHERE case_id = ?
                AND volume_serial_number IS NOT NULL
                AND TRIM(volume_serial_number) != ''
                AND COALESCE(file_location, file_name, '') IS NOT NULL
                AND LENGTH(TRIM(COALESCE(file_location, file_name, ''))) > 3
            ),
            anchor_scores AS (
              SELECT
                artifacts.source_artifact_id,
                usb.usb_vsn_norm,
                COUNT(DISTINCT anchor_paths.anchor_path_norm) AS anchor_count
              FROM artifacts
              JOIN usb
                ON artifacts.source_artifact_type = 'shellbag'
                AND artifacts.artifact_drive_norm IS NOT NULL
                AND artifacts.artifact_drive_norm != ''
                AND artifacts.artifact_drive_norm = usb.usb_drive_norm
              JOIN anchor_paths
                ON anchor_paths.case_id = artifacts.case_id
                AND anchor_paths.anchor_vsn_norm = usb.usb_vsn_norm
                AND anchor_paths.anchor_path_norm != ''
                AND artifacts.artifact_path_norm != ''
                AND LENGTH(RTRIM(anchor_paths.anchor_path_norm, '\\')) > 2
                AND (
                  anchor_paths.anchor_path_norm = artifacts.artifact_path_norm
                  OR anchor_paths.anchor_path_norm LIKE artifacts.artifact_path_norm || '\\%'
                  OR artifacts.artifact_path_norm LIKE anchor_paths.anchor_path_norm || '\\%'
                )
              GROUP BY artifacts.source_artifact_id, usb.usb_vsn_norm
            ),
            anchor_summary AS (
              SELECT
                source_artifact_id,
                COUNT(*) AS anchored_device_count,
                MAX(anchor_count) AS max_anchor_count
              FROM anchor_scores
              GROUP BY source_artifact_id
            ),
            scored AS (
              SELECT
                usb.*,
                artifacts.*,
                COALESCE(anchor_scores.anchor_count, 0) AS anchor_count,
                COALESCE(anchor_summary.anchored_device_count, 0) AS anchored_device_count,
                CASE
                  WHEN artifacts.source_artifact_type = 'shellbag'
                    AND artifacts.interaction_start_norm IS NOT NULL
                    AND EXISTS (
                      SELECT 1
                      FROM usb_sessions
                      WHERE usb_sessions.case_id = usb.case_id
                        AND usb_sessions.image_id = usb.image_id
                        AND usb_sessions.serial = usb.serial
                        AND (
                          usb.usb_vsn_norm IS NULL
                          OR usb.usb_vsn_norm = ''
                          OR usb_sessions.session_vsn_norm IS NULL
                          OR usb_sessions.session_vsn_norm = ''
                          OR usb_sessions.session_vsn_norm = usb.usb_vsn_norm
                        )
                        AND artifacts.interaction_start_norm <=
                            datetime(REPLACE(SUBSTR(usb_sessions.session_end, 1, 19), 'T', ' '))
                        AND artifacts.interaction_end_norm >=
                            datetime(REPLACE(SUBSTR(usb_sessions.session_start, 1, 19), 'T', ' '))
                    )
                  THEN 1
                  WHEN artifacts.source_artifact_type = 'shellbag'
                    AND artifacts.interaction_start_norm IS NOT NULL
                    AND NOT EXISTS (
                      SELECT 1
                      FROM usb_sessions
                      WHERE usb_sessions.case_id = usb.case_id
                        AND usb_sessions.image_id = usb.image_id
                        AND usb_sessions.serial = usb.serial
                        AND (
                          usb.usb_vsn_norm IS NULL
                          OR usb.usb_vsn_norm = ''
                          OR usb_sessions.session_vsn_norm IS NULL
                          OR usb_sessions.session_vsn_norm = ''
                          OR usb_sessions.session_vsn_norm = usb.usb_vsn_norm
                        )
                    )
                    AND datetime(REPLACE(SUBSTR(usb.first_install_date_utc, 1, 19), 'T', ' ')) IS NOT NULL
                    AND datetime(REPLACE(SUBSTR(COALESCE(usb.last_removal_utc, usb.last_arrival_utc, usb.first_install_date_utc), 1, 19), 'T', ' ')) IS NOT NULL
                    AND artifacts.interaction_start_norm <= datetime(REPLACE(SUBSTR(COALESCE(usb.last_removal_utc, usb.last_arrival_utc, usb.first_install_date_utc), 1, 19), 'T', ' '))
                    AND artifacts.interaction_end_norm >= datetime(REPLACE(SUBSTR(usb.first_install_date_utc, 1, 19), 'T', ' '))
                  THEN 1
                  ELSE 0
                END AS interaction_overlaps_usb
              FROM usb
              JOIN artifacts
                ON (artifacts.artifact_vsn_norm IS NOT NULL AND artifacts.artifact_vsn_norm = usb.usb_vsn_norm)
                OR (
                  artifacts.artifact_vsn_norm IS NOT NULL
                  AND LENGTH(usb.usb_vsn_norm) > 8
                  AND artifacts.artifact_vsn_norm = SUBSTR(usb.usb_vsn_norm, -8)
                )
                OR (
                  artifacts.artifact_guid_norm IS NOT NULL
                  AND artifacts.artifact_guid_norm != ''
                  AND usb.usb_guid_norm LIKE '%' || artifacts.artifact_guid_norm || '%'
                )
                OR (
                  artifacts.source_artifact_type = 'shellbag'
                  AND artifacts.artifact_drive_norm IS NOT NULL
                  AND artifacts.artifact_drive_norm != ''
                  AND artifacts.artifact_drive_norm = usb.usb_drive_norm
                )
              LEFT JOIN anchor_scores
                ON anchor_scores.source_artifact_id = artifacts.source_artifact_id
                AND anchor_scores.usb_vsn_norm = usb.usb_vsn_norm
              LEFT JOIN anchor_summary
                ON anchor_summary.source_artifact_id = artifacts.source_artifact_id
            )
            SELECT
              scored.case_id,
              scored.computer_id,
              scored.image_id,
              scored.serial AS usb_serial,
              scored.volume_serial_number AS usb_volume_serial_number,
              scored.volume_name AS usb_volume_name,
              scored.drive_letter AS usb_drive_letter,
              scored.vendor_id AS usb_vendor_id,
              scored.product_id AS usb_product_id,
              scored.vendor AS usb_vendor,
              scored.product AS usb_product,
              scored.friendly_name AS usb_friendly_name,
              scored.first_install_date_utc AS usb_first_install_date_utc,
              scored.last_arrival_utc AS usb_last_arrival_utc,
              scored.last_removal_utc AS usb_last_removal_utc,
              scored.source_artifact_type,
              scored.source_artifact_id,
              scored.source_artifact_name,
              scored.source_artifact_path,
              COALESCE(scored.user_profile, '') AS user_profile,
              scored.jumplist_item_number,
              scored.file_name,
              scored.file_location,
              scored.target_created,
              scored.target_modified,
              scored.target_accessed,
              scored.device_type,
              scored.artifact_volume_serial_number,
              scored.artifact_volume_name,
              scored.artifact_volume_guid,
              scored.artifact_drive_letter,
              CASE
                WHEN scored.artifact_vsn_norm = scored.usb_vsn_norm THEN 'exact'
                WHEN scored.artifact_vsn_norm IS NOT NULL
                  AND LENGTH(scored.usb_vsn_norm) > 8
                  AND scored.artifact_vsn_norm = SUBSTR(scored.usb_vsn_norm, -8) THEN 'suffix'
                WHEN scored.artifact_guid_norm IS NOT NULL
                  AND scored.usb_guid_norm LIKE '%' || scored.artifact_guid_norm || '%' THEN 'volume_guid'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.anchor_count >= 2
                  AND scored.anchored_device_count = 1
                  AND scored.interaction_overlaps_usb = 1 THEN 'folder_tree_time'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.anchor_count >= 2
                  AND scored.anchored_device_count = 1 THEN 'folder_tree'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.anchor_count > 0
                  AND scored.interaction_overlaps_usb = 1 THEN 'path_time_anchor'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.anchor_count > 0 THEN 'path_anchor'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.interaction_overlaps_usb = 1 THEN 'time_overlap'
                ELSE 'drive_letter'
              END AS volume_serial_match,
              CASE
                WHEN scored.artifact_vsn_norm = scored.usb_vsn_norm THEN 'high'
                WHEN scored.artifact_vsn_norm IS NOT NULL
                  AND LENGTH(scored.usb_vsn_norm) > 8
                  AND scored.artifact_vsn_norm = SUBSTR(scored.usb_vsn_norm, -8) THEN 'medium'
                WHEN scored.artifact_guid_norm IS NOT NULL
                  AND scored.usb_guid_norm LIKE '%' || scored.artifact_guid_norm || '%' THEN 'high'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.anchor_count >= 2
                  AND scored.anchored_device_count = 1 THEN 'high'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.anchor_count > 0
                  AND scored.interaction_overlaps_usb = 1 THEN 'high'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.anchor_count > 0 THEN 'medium'
                WHEN scored.source_artifact_type = 'shellbag'
                  AND scored.interaction_overlaps_usb = 1 THEN 'medium'
                ELSE 'low'
              END AS confidence
            FROM scored
            ORDER BY
              scored.volume_serial_number,
              scored.source_artifact_type,
              scored.file_location,
              scored.file_name,
              scored.source_artifact_path
            {limit_clause}
            """,
            params,
        ).fetchall()
    ]


def _dedupe_usb_file_items(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.get("usb_serial") or "",
            row.get("usb_volume_serial_number") or "",
            row.get("file_location") or row.get("file_name") or "",
        )
        item = grouped.setdefault(
            key,
            {
                "usb_serial": row.get("usb_serial"),
                "usb_volume_serial_number": row.get("usb_volume_serial_number"),
                "usb_volume_name": row.get("usb_volume_name"),
                "usb_drive_letter": row.get("usb_drive_letter"),
                "usb_product": row.get("usb_product"),
                "file_name": row.get("file_name"),
                "file_location": row.get("file_location"),
                "artifact_count": 0,
                "source_artifact_types": set(),
                "user_profiles": set(),
                "first_target_time": None,
                "last_target_time": None,
                "best_confidence": "low",
                "match_types": set(),
            },
        )
        item["artifact_count"] += 1
        if row.get("source_artifact_type"):
            item["source_artifact_types"].add(row["source_artifact_type"])
        if row.get("user_profile"):
            item["user_profiles"].add(row["user_profile"])
        if row.get("confidence") == "high":
            item["best_confidence"] = "high"
        elif row.get("confidence") == "medium" and item["best_confidence"] == "low":
            item["best_confidence"] = "medium"
        if row.get("volume_serial_match"):
            item["match_types"].add(row["volume_serial_match"])
        for field in ("target_created", "target_modified", "target_accessed"):
            value = row.get(field)
            if not value:
                continue
            if item["first_target_time"] is None or value < item["first_target_time"]:
                item["first_target_time"] = value
            if item["last_target_time"] is None or value > item["last_target_time"]:
                item["last_target_time"] = value
    result = []
    for item in grouped.values():
        converted = dict(item)
        converted["source_artifact_types"] = ", ".join(sorted(item["source_artifact_types"]))
        converted["user_profiles"] = ", ".join(sorted(item["user_profiles"]))
        converted["match_types"] = ", ".join(sorted(item["match_types"]))
        result.append(converted)
    return sorted(
        result,
        key=lambda item: (
            item.get("usb_volume_serial_number") or "",
            item.get("file_location") or item.get("file_name") or "",
        ),
    )


def _find_usb_storage_device(
    db: Database,
    case_id: str,
    *,
    serial: str | None,
    volume_serial_number: str | None,
    volume_guid: str | None,
) -> dict[str, Any]:
    criteria = []
    params: list[Any] = [case_id]
    if serial:
        criteria.append("UPPER(serial) = UPPER(?)")
        params.append(serial)
    if volume_serial_number:
        criteria.append("UPPER(REPLACE(volume_serial_number, '-', '')) = UPPER(REPLACE(?, '-', ''))")
        params.append(volume_serial_number)
    if volume_guid:
        criteria.append(
            "UPPER(REPLACE(REPLACE(COALESCE(volume_guid, ''), CHAR(123), ''), CHAR(125), '')) "
            "LIKE '%' || UPPER(REPLACE(REPLACE(?, CHAR(123), ''), CHAR(125), '')) || '%'"
        )
        params.append(volume_guid)
    if not criteria:
        raise ValueError("Provide one of serial, volume_serial_number, or volume_guid")
    row = db.conn.execute(
        f"""
        SELECT usb_storage_devices.*, computers.label AS computer_label, images.path AS image_path
        FROM usb_storage_devices
        LEFT JOIN computers ON usb_storage_devices.computer_id = computers.id
        LEFT JOIN images ON usb_storage_devices.image_id = images.id
        WHERE usb_storage_devices.case_id = ?
          AND ({' OR '.join(criteria)})
        ORDER BY evidence_row_count DESC, COALESCE(last_removal_utc, last_arrival_utc, first_install_date_utc) DESC
        LIMIT 1
        """,
        params,
    ).fetchone()
    if row is None:
        raise ValueError("No USB storage device matched the provided identifier")
    item = dict(row)
    item["first_connection_utc"] = item.get("first_install_date_utc")
    return item


def _usb_verbose_raw_rows(db: Database, case_id: str, device: dict[str, Any]) -> list[dict[str, Any]]:
    serial = device.get("serial")
    vsn = _norm_vsn(device.get("volume_serial_number"))
    guids = _split_multi_value(device.get("volume_guid"))
    clauses = []
    params: list[Any] = [case_id]
    if serial:
        clauses.append("UPPER(COALESCE(serial, alternate_scsi_serial, instance_id, '')) LIKE '%' || UPPER(?) || '%'")
        params.append(serial)
    if vsn:
        clauses.append("UPPER(REPLACE(COALESCE(volume_serial_number, ''), '-', '')) = ?")
        params.append(vsn)
    for guid in guids:
        clauses.append("UPPER(COALESCE(volume_guid, key_path, property_value, '')) LIKE '%' || UPPER(?) || '%'")
        params.append(guid.strip("{}"))
    if not clauses:
        return []
    return [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT *
            FROM usb_devices
            WHERE case_id = ?
              AND ({' OR '.join(clauses)})
            ORDER BY COALESCE(key_last_write_utc, property_name, artifact), artifact, row_number
            """,
            params,
        ).fetchall()
    ]


def _usb_verbose_file_rows(
    db: Database,
    case_id: str,
    device: dict[str, Any],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT *
            FROM usb_file_correlations
            WHERE case_id = ?
              AND usb_serial = ?
              AND usb_volume_serial_number = ?
            ORDER BY
              CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
              COALESCE(target_modified, target_created, target_accessed, ''),
              COALESCE(file_location, file_name, '')
            LIMIT ?
            """,
            (case_id, device["serial"], device["volume_serial_number"], limit),
        ).fetchall()
    ]


def _usb_verbose_description_attributes(device: dict[str, Any], raw_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "serial": device.get("serial"),
        "vid": device.get("vendor_id"),
        "pid": device.get("product_id"),
        "vendor": device.get("vendor"),
        "product": device.get("product"),
        "revision": device.get("revision"),
        "friendly_name": device.get("friendly_name"),
        "parent_id_prefix": device.get("parent_id_prefix"),
        "device_service": device.get("device_service"),
        "alternate_scsi_serial": device.get("alternate_scsi_serial"),
        "sources": _usb_verbose_sources(raw_rows),
    }


def _usb_verbose_connection_times(device: dict[str, Any], raw_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "first_connected_utc": device.get("first_install_date_utc"),
        "last_arrival_utc": device.get("last_arrival_utc"),
        "last_removal_utc": device.get("last_removal_utc"),
        "first_volume_serial_event_utc": device.get("first_volume_serial_event_utc"),
        "last_partition_event_utc": device.get("last_partition_event_utc"),
        "raw_events": [
            _usb_verbose_raw_summary(row)
            for row in raw_rows
            if row.get("key_last_write_utc") or row.get("property_name") in {"0064", "0065", "0066", "0067"}
        ],
    }


def _usb_verbose_volume_attributes(device: dict[str, Any], raw_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "drive_letter": device.get("drive_letter"),
        "volume_guid": device.get("volume_guid"),
        "volume_serial_number": device.get("volume_serial_number"),
        "volume_name": device.get("volume_name"),
        "capacity_bytes": device.get("capacity_bytes"),
        "user_profiles": device.get("user_profiles"),
        "raw_volume_rows": [
            _usb_verbose_raw_summary(row)
            for row in raw_rows
            if row.get("drive_letter") or row.get("volume_guid") or row.get("volume_serial_number") or row.get("volume_name")
        ],
    }


def _usb_verbose_mbr_vbr_details(raw_rows: list[dict[str, Any]]) -> dict[str, Any]:
    partition_rows = [row for row in raw_rows if row.get("artifact") == "partition_diagnostic"]
    return {
        "available": bool(partition_rows),
        "partition_diagnostic_rows": [_usb_verbose_raw_summary(row) for row in partition_rows],
    }


def _usb_verbose_other_details(raw_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "device_classes": [
            _usb_verbose_raw_summary(row)
            for row in raw_rows
            if row.get("artifact") in {"usb_device_history", "usb_volume_history"}
            and "DeviceClasses" in (row.get("key_path") or "")
        ],
        "mounted_devices": [
            _usb_verbose_raw_summary(row)
            for row in raw_rows
            if row.get("artifact") == "mounted_devices"
        ],
    }


def _usb_verbose_counts(raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], int] = {}
    for row in raw_rows:
        key = (row.get("artifact") or "", row.get("device_type") or "")
        counts[key] = counts.get(key, 0) + 1
    return [
        {"artifact": artifact, "device_type": device_type, "row_count": count}
        for (artifact, device_type), count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _usb_verbose_sources(raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sources: dict[tuple[str, str], int] = {}
    for row in raw_rows:
        key = (row.get("artifact") or "", row.get("source_path") or "")
        sources[key] = sources.get(key, 0) + 1
    return [
        {"artifact": artifact, "source_path": source_path, "row_count": count}
        for (artifact, source_path), count in sorted(sources.items(), key=lambda item: (-item[1], item[0]))
    ]


def _usb_verbose_raw_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact": row.get("artifact"),
        "device_type": row.get("device_type"),
        "source_path": row.get("source_path"),
        "row_number": row.get("row_number"),
        "key_path": row.get("key_path"),
        "key_last_write_utc": row.get("key_last_write_utc"),
        "property_name": row.get("property_name"),
        "property_value": row.get("property_value"),
        "drive_letter": row.get("drive_letter"),
        "volume_guid": row.get("volume_guid"),
        "volume_serial_number": row.get("volume_serial_number"),
        "volume_name": row.get("volume_name"),
        "capacity_bytes": row.get("capacity_bytes"),
    }


def _norm_vsn(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.replace("-", "").upper()
    return normalized or None


def _split_multi_value(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def usb_timeline_report(db: Database, case_id: str, *, limit: int = 500) -> dict[str, Any]:
    db.get_case(case_id)
    rebuild_usb_file_correlations(db, case_id)
    events = []
    connection_event_count = db.conn.execute(
        "SELECT COUNT(*) AS count FROM usb_connection_events WHERE case_id = ?",
        (case_id,),
    ).fetchone()["count"]
    if connection_event_count:
        for row in db.conn.execute(
            """
            SELECT usb_connection_events.*, usb_storage_devices.product, usb_storage_devices.volume_name
            FROM usb_connection_events
            LEFT JOIN usb_storage_devices
              ON usb_storage_devices.id = usb_connection_events.usb_device_id
            WHERE usb_connection_events.case_id = ?
            """,
            (case_id,),
        ).fetchall():
            base = dict(row)
            events.append(
                {
                    "timestamp": base["event_time_utc"],
                    "event_type": f"usb_{base['event_type']}",
                    "usb_serial": base["serial"],
                    "usb_volume_serial_number": base["volume_serial_number"],
                    "usb_volume_name": base["volume_name"],
                    "usb_drive_letter": base["drive_letter"],
                    "usb_product": base["product"],
                    "user_profile": None,
                    "source_artifact_type": base["event_source"] or "usb",
                    "file_location": None,
                    "description": f"usb_{base['event_type']}: {base['serial']}",
                    "confidence": "high",
                }
            )
    else:
        for row in db.conn.execute(
            """
            SELECT serial, volume_serial_number, volume_name, drive_letter, product,
                   first_install_date_utc, last_arrival_utc, last_removal_utc,
                   first_volume_serial_event_utc, last_partition_event_utc
            FROM usb_storage_devices
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchall():
            base = dict(row)
            for event_type, field in (
                ("usb_first_connected", "first_install_date_utc"),
                ("usb_last_arrival", "last_arrival_utc"),
                ("usb_last_removal", "last_removal_utc"),
                ("usb_first_partition_event", "first_volume_serial_event_utc"),
                ("usb_last_partition_event", "last_partition_event_utc"),
            ):
                timestamp = base.get(field)
                if timestamp:
                    events.append(
                        {
                            "timestamp": timestamp,
                            "event_type": event_type,
                            "usb_serial": base["serial"],
                            "usb_volume_serial_number": base["volume_serial_number"],
                            "usb_volume_name": base["volume_name"],
                            "usb_drive_letter": base["drive_letter"],
                            "usb_product": base["product"],
                            "user_profile": None,
                            "source_artifact_type": "usb",
                            "file_location": None,
                            "description": f"{event_type}: {base['serial']}",
                            "confidence": "high",
                        }
                    )
    for row in db.conn.execute(
        """
        SELECT *
        FROM usb_file_correlations
        WHERE case_id = ?
        """,
        (case_id,),
    ).fetchall():
        item = dict(row)
        for event_type, field in (
            ("usb_file_target_created", "target_created"),
            ("usb_file_target_modified", "target_modified"),
            ("usb_file_target_accessed", "target_accessed"),
        ):
            timestamp = item.get(field)
            if timestamp and not _is_placeholder_timestamp(timestamp):
                events.append(
                    {
                        "timestamp": timestamp,
                        "event_type": event_type,
                        "usb_serial": item["usb_serial"],
                        "usb_volume_serial_number": item["usb_volume_serial_number"],
                        "usb_volume_name": item["usb_volume_name"],
                        "usb_drive_letter": item["usb_drive_letter"],
                        "usb_product": item["usb_product"],
                        "user_profile": item.get("user_profile"),
                        "source_artifact_type": item["source_artifact_type"],
                        "file_location": item["file_location"],
                        "description": item["file_location"] or item["file_name"],
                        "confidence": item["confidence"],
                    }
                )
    events = _dedupe_timeline_events(events)
    events.sort(key=lambda item: (item["timestamp"], item["event_type"], item.get("description") or ""))
    return {"case_id": case_id, "events": events[:limit], "total_returned": min(len(events), limit), "total_events": len(events)}


def _dedupe_timeline_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for event in events:
        key = (
            event.get("timestamp"),
            event.get("event_type"),
            event.get("usb_serial"),
            event.get("usb_volume_serial_number"),
            event.get("source_artifact_type"),
            event.get("user_profile"),
            event.get("file_location"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(event)
    return unique


def _dedupe_review_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for event in events:
        key = (
            event.get("timestamp"),
            event.get("source"),
            event.get("event_type"),
            event.get("file_path"),
            event.get("source_table"),
            event.get("source_record_id"),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(event)
    return output


def _review_event_counts(events: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for event in events:
        value = str(event.get(key) or "")
        if not value:
            value = "unknown"
        counts[value] = counts.get(value, 0) + 1
    return [
        {key: value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _is_placeholder_timestamp(value: str) -> bool:
    return value.startswith("1980-01-01")


def _user_profile_from_artifact_path(path: Any) -> str | None:
    if not path:
        return None
    parts = str(path).replace("\\", "/").split("/")
    for marker in ("lnk_files", "jumplists"):
        if marker in parts:
            index = parts.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1] or None
    if "Users" in parts:
        index = parts.index("Users")
        if index + 1 < len(parts):
            return parts[index + 1] or None
    return None


def registry_artifacts_report(
    db: Database,
    case_id: str,
    *,
    artifact: str | None = None,
    user: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["registry_artifacts.case_id = ?", _artifact_duplicate_condition("registry_artifacts")]
    params: list[Any] = [case_id]
    if artifact:
        filters.append("registry_artifacts.artifact = ?")
        params.append(artifact)
    if user:
        filters.append("(registry_artifacts.user_profile LIKE ? OR registry_artifacts.key_path LIKE ?)")
        params.extend([f"%{user}%", f"%{user}%"])
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT registry_artifacts.*, computers.label AS computer_label, images.path AS image_path,
               {_artifact_source_count_sql("registry_artifacts")} AS source_count
        FROM registry_artifacts
        LEFT JOIN computers ON registry_artifacts.computer_id = computers.id
        LEFT JOIN images ON registry_artifacts.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY registry_artifacts.artifact, registry_artifacts.user_profile,
                 registry_artifacts.key_path, registry_artifacts.value_name
        LIMIT ?
        """,
        params,
    ).fetchall()
    items = [_with_userassist_caveat(dict(row)) for row in rows]
    caveats = _report_caveats_for_userassist(items, artifact=artifact)
    return {
        "case_id": case_id,
        "artifact": artifact,
        "user": user,
        "caveats": caveats,
        "registry_artifacts": items,
        "total_returned": len(rows),
    }


REGISTRY_ACTIVITY_TABLES = {
    "recentdocs": ("registry_recentdocs", "recentdocs"),
    "runmru": ("registry_runmru", "runmru"),
    "typedpaths": ("registry_typedpaths", "typedpaths"),
    "wordwheel": ("registry_wordwheel_query", "wordwheel_query"),
    "wordwheelquery": ("registry_wordwheel_query", "wordwheel_query"),
    "userassist": ("registry_userassist", "userassist"),
    "office-mru": ("registry_office_mru", "office_mru"),
    "officemru": ("registry_office_mru", "office_mru"),
    "common-dialog": ("registry_common_dialog_mru", "common_dialog_mru"),
    "trusted-documents": ("registry_trusted_documents", "trusted_documents"),
}


def _with_userassist_caveat(item: dict[str, Any]) -> dict[str, Any]:
    artifact = str(item.get("artifact") or "").lower()
    source_table = str(item.get("source_table") or "").lower()
    if artifact == "userassist" or source_table == "registry_userassist" or "program_name" in item:
        item["evidence_caveat"] = USERASSIST_CAVEAT
        tags = set(item.get("evidence_tags") or [])
        tags.add("requires_corroboration")
        tags.add("userassist_inconsistent")
        item["evidence_tags"] = sorted(tags)
    return item


def _report_caveats_for_userassist(items: list[dict[str, Any]], *, artifact: str | None = None) -> list[str]:
    if str(artifact or "").lower() == "userassist" or any(row.get("evidence_caveat") == USERASSIST_CAVEAT for row in items):
        return [USERASSIST_CAVEAT]
    return []


def registry_activity_report(
    db: Database,
    case_id: str,
    *,
    artifact: str,
    user: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    try:
        table, key = REGISTRY_ACTIVITY_TABLES[artifact.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported registry activity artifact: {artifact}") from exc
    where = [f"{table}.case_id = ?", _artifact_duplicate_condition(table)]
    params: list[Any] = [case_id]
    if user:
        where.append(f"({table}.user_profile LIKE ? OR {table}.hive_path LIKE ? OR {table}.key_path LIKE ?)")
        params.extend([f"%{user}%", f"%{user}%", f"%{user}%"])
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT {table}.*, computers.label AS computer_label, images.path AS image_path,
               {_artifact_source_count_sql(table)} AS source_count
        FROM {table}
        LEFT JOIN computers ON {table}.computer_id = computers.id
        LEFT JOIN images ON {table}.image_id = images.id
        WHERE {' AND '.join(where)}
        ORDER BY {table}.user_profile, {table}.key_path, CAST({table}.row_number AS INTEGER)
        LIMIT ?
        """,
        params,
    ).fetchall()
    items = [_with_userassist_caveat(dict(row)) for row in rows]
    caveats = _report_caveats_for_userassist(items, artifact=artifact)
    return {
        "case_id": case_id,
        "artifact": artifact,
        "user": user,
        "caveats": caveats,
        key: items,
        "total_returned": len(rows),
    }


def office_trust_report(
    db: Database,
    case_id: str,
    *,
    user: str | None = None,
    trust_type: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["registry_office_trust_records.case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("LOWER(COALESCE(registry_office_trust_records.user_profile, '')) = LOWER(?)")
        params.append(user)
    if trust_type:
        filters.append("registry_office_trust_records.trust_type = ?")
        params.append(trust_type)
    rows = db.conn.execute(
        f"""
        SELECT registry_office_trust_records.*, computers.label AS computer_label, images.path AS image_path
        FROM registry_office_trust_records
        LEFT JOIN computers ON registry_office_trust_records.computer_id = computers.id
        LEFT JOIN images ON registry_office_trust_records.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY COALESCE(registry_office_trust_records.event_time_utc, registry_office_trust_records.key_last_write_utc) DESC,
                 registry_office_trust_records.user_profile,
                 registry_office_trust_records.key_path,
                 registry_office_trust_records.value_name
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    counts = db.conn.execute(
        f"""
        SELECT trust_type, user_profile, COUNT(*) AS row_count
        FROM registry_office_trust_records
        WHERE {' AND '.join(filters)}
        GROUP BY trust_type, user_profile
        ORDER BY trust_type, user_profile
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"user": user, "trust_type": trust_type},
        "summary": {"counts": [dict(row) for row in counts]},
        "office_trust_records": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def taskbar_feature_usage_report(
    db: Database,
    case_id: str,
    *,
    user: str | None = None,
    feature: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["registry_taskbar_feature_usage.case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("LOWER(COALESCE(registry_taskbar_feature_usage.user_profile, '')) = LOWER(?)")
        params.append(user)
    if feature:
        filters.append("LOWER(COALESCE(registry_taskbar_feature_usage.feature, '')) = LOWER(?)")
        params.append(feature)
    rows = db.conn.execute(
        f"""
        SELECT registry_taskbar_feature_usage.*, computers.label AS computer_label, images.path AS image_path
        FROM registry_taskbar_feature_usage
        LEFT JOIN computers ON registry_taskbar_feature_usage.computer_id = computers.id
        LEFT JOIN images ON registry_taskbar_feature_usage.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY registry_taskbar_feature_usage.user_profile,
                 registry_taskbar_feature_usage.feature,
                 CAST(COALESCE(registry_taskbar_feature_usage.usage_count, 0) AS INTEGER) DESC,
                 registry_taskbar_feature_usage.value_name
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    counts = db.conn.execute(
        f"""
        SELECT user_profile, feature, COUNT(*) AS row_count,
               SUM(CASE WHEN value_name = 'KeyCreationTime' THEN 0 ELSE COALESCE(usage_count, 0) END) AS total_usage_count
        FROM registry_taskbar_feature_usage
        WHERE {' AND '.join(filters)}
        GROUP BY user_profile, feature
        ORDER BY user_profile, feature
        """,
        params,
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        _enrich_taskbar_feature_usage_row(item)
        items.append(item)
    return {
        "case_id": case_id,
        "filters": {"user": user, "feature": feature},
        "caveats": [
            "FeatureUsage subkeys have different meanings; interpret each row by feature_semantics.",
            "FeatureUsage timestamps are registry key last-write times for feature buckets, not per-app activity times.",
            "KeyCreationTime values are metadata and are not usage counts.",
        ],
        "summary": {"feature_counts": [dict(row) for row in counts]},
        "taskbar_feature_usage": items,
        "total_returned": len(rows),
    }


TASKBAR_FEATURE_SEMANTICS = {
    "AppLaunch": "Cumulative application launch count recorded by Explorer FeatureUsage.",
    "AppSwitched": "Cumulative foreground/window switch count, not launch count.",
    "AppBadgeUpdated": "Cumulative taskbar badge update count, not launch count.",
    "ShowJumpView": "Cumulative Jump List view/open count, not launch count.",
    "TrayButtonClicked": "Cumulative notification-area/tray interaction count, not launch count.",
    "AuxilliaryPins": "Auxiliary pin state/counter data, not launch count.",
    "Taskband": "Taskbar pin/order state, not launch count.",
    "FeatureUsage": "FeatureUsage key metadata, not per-application usage.",
}


def _enrich_taskbar_feature_usage_row(item: dict[str, Any]) -> None:
    feature = str(item.get("feature") or "")
    value_name = str(item.get("value_name") or "")
    item["feature_semantics"] = TASKBAR_FEATURE_SEMANTICS.get(feature, "Unknown FeatureUsage subkey; inspect manually.")
    item["timestamp_semantics"] = "registry_key_last_write_time"
    if value_name == "KeyCreationTime":
        item["value_semantics"] = "metadata_key_creation_time"
        item["usage_count"] = None
    elif feature == "AppLaunch":
        item["value_semantics"] = "application_launch_counter"
    else:
        item["value_semantics"] = "feature_specific_counter_not_launch_count"


def taskbar_pins_report(
    db: Database,
    case_id: str,
    *,
    user: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["registry_taskbar_pins.case_id = ?"]
    params: list[Any] = [case_id]
    if user:
        filters.append("LOWER(COALESCE(registry_taskbar_pins.user_profile, '')) = LOWER(?)")
        params.append(user)
    rows = db.conn.execute(
        f"""
        SELECT registry_taskbar_pins.*, computers.label AS computer_label, images.path AS image_path
        FROM registry_taskbar_pins
        LEFT JOIN computers ON registry_taskbar_pins.computer_id = computers.id
        LEFT JOIN images ON registry_taskbar_pins.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY registry_taskbar_pins.user_profile, registry_taskbar_pins.pin_order
        LIMIT ?
        """,
        [*params, limit],
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {"user": user},
        "caveats": [
            "Taskband Favorites represents pinned taskbar state/order, not MRU use.",
            "The timestamp is the Taskband key last-write time, not a per-pin launch time.",
        ],
        "taskbar_pins": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def common_dialog_items_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT registry_common_dialog_items.*, computers.label AS computer_label, images.path AS image_path
        FROM registry_common_dialog_items
        LEFT JOIN computers ON registry_common_dialog_items.computer_id = computers.id
        LEFT JOIN images ON registry_common_dialog_items.image_id = images.id
        WHERE registry_common_dialog_items.case_id = ?
        ORDER BY registry_common_dialog_items.created_at, registry_common_dialog_items.key_path,
                 registry_common_dialog_items.value_name, registry_common_dialog_items.item_index
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["raw_fat_times"] = json.loads(item.pop("raw_fat_times_json") or "[]")
        items.append(item)
    return {"case_id": case_id, "common_dialog_items": items, "total_returned": len(items)}


def activity_summary_report(db: Database, case_id: str, *, user: str | None = None, limit: int = 25) -> dict[str, Any]:
    db.get_case(case_id)
    user_like = f"%{user}%" if user else None
    user_path_like = f"%/Users/{user}/%" if user else None
    return {
        "case_id": case_id,
        "user": user,
        "counts": {
            "accounts": _count(db, "sam_accounts", case_id, user_filter=("username", user_like)),
            "prefetch": _count(db, "prefetch_items", case_id),
            "shortcuts": _count(
                db,
                "shortcut_items",
                case_id,
                user_filter=("artifact_path", user_like),
            ),
            "copied_file_indicators": _count_timeline(db, case_id, "copied_file_indicator"),
            "recycle_items": _count(
                db,
                "recycle_items",
                case_id,
                user_filter=("original_path", user_like),
            ),
            "browser_history": _count(
                db,
                "firefox_history",
                case_id,
                user_filter=("profile_path", user_like),
            ),
            "evtx_logons": _count_evtx_logons(db, case_id, user_like),
            "registry_artifacts": _count(
                db,
                "registry_artifacts",
                case_id,
                user_filter=("user_profile", user_like),
            ),
            "registry_activity": _count_registry_activity(db, case_id, user_like),
            "amcache": _count(db, "amcache_entries", case_id),
            "shimcache": _count(db, "shimcache_entries", case_id),
            "shellbags": _count(
                db,
                "shellbag_entries",
                case_id,
                user_filter=("user_profile", user_like),
            ),
            "usb_devices": _count(db, "usb_devices", case_id),
        },
        "recent_execution": _recent_prefetch(db, case_id, limit=limit),
        "recent_file_activity": _recent_shortcuts(db, case_id, user_path_like or user_like, limit=limit),
        "recent_browser_history": _recent_browser(db, case_id, user_like, limit=limit),
        "recent_logons": _recent_logons(db, case_id, user_like, limit=limit),
        "recycle_items": _recent_recycle(db, case_id, user_like, limit=limit),
    }


def users_report(db: Database, case_id: str) -> dict[str, Any]:
    accounts = accounts_report(db, case_id)["accounts"]
    users = [
        account for account in accounts
        if account.get("account_category") == "local" or _safe_int(account.get("rid"), 0) >= 1000
    ]
    return {"case_id": case_id, "users": users, "total_users": len(users)}


def files_report(db: Database, case_id: str, *, user: str | None = None, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    params: list[Any] = [case_id]
    user_filter = ""
    if user:
        user_filter = "AND (mft_entries.parent_path LIKE ? OR mft_entries.file_name LIKE ?)"
        params.extend([f"%Users/{user}/%", f"%{user}%"])
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT mft_entries.*, computers.label AS computer_label, images.path AS image_path
        FROM mft_entries
        LEFT JOIN computers ON mft_entries.computer_id = computers.id
        LEFT JOIN images ON mft_entries.image_id = images.id
        WHERE mft_entries.case_id = ? {user_filter}
        ORDER BY mft_entries.parent_path, mft_entries.file_name
        LIMIT ?
        """,
        params,
    ).fetchall()
    files = []
    for row in rows:
        item = dict(row)
        item["correlations"] = _correlations_for_mft_entry(db, row["id"])
        files.append(item)
    return {"case_id": case_id, "files": files, "total_returned": len(files)}


def file_names_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    contains: str | None = None,
    include_mft: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    groups: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []

    def include_name(name: str | None) -> bool:
        if not name:
            return False
        if contains and contains.lower() not in name.lower():
            return False
        return True

    def add_signal(
        *,
        source: str,
        source_table: str,
        source_id: str,
        file_name: str | None,
        path: str | None = None,
        timestamp: str | None = None,
        user_profile: str | None = None,
        application: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        name = _coalesce_file_name(file_name, path)
        if not include_name(name):
            return
        key = name.lower()
        group = groups.setdefault(
            key,
            {
                "file_name": name,
                "evidence_count": 0,
                "sources": set(),
                "source_tables": set(),
                "paths": set(),
                "users": set(),
                "applications": set(),
                "first_seen_utc": None,
                "last_seen_utc": None,
            },
        )
        group["evidence_count"] += 1
        group["sources"].add(source)
        group["source_tables"].add(source_table)
        if path:
            group["paths"].add(path)
            normalized_path = _normalize_artifact_path(path)
            if normalized_path:
                group.setdefault("normalized_paths", set()).add(normalized_path)
        if user_profile:
            group["users"].add(user_profile)
        if application:
            group["applications"].add(application)
        _merge_time_bounds(group, timestamp)
        evidence_tags = _file_evidence_tags(source=source, source_table=source_table, path=path, detail=detail)
        rows.append(
            {
                "file_name": name,
                "source": source,
                "source_table": source_table,
                "source_id": source_id,
                "path": path,
                "normalized_path": _normalize_artifact_path(path),
                "timestamp": timestamp,
                "user_profile": user_profile,
                "application": application,
                "evidence_tags": evidence_tags,
                "details": detail or {},
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "shortcut_items",
        """
        SELECT id, artifact_type, artifact_name, artifact_path, file_name,
               file_location, target_created, target_modified, target_accessed
        FROM shortcut_items
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        add_signal(
            source=row["artifact_type"] or "shortcut",
            source_table="shortcut_items",
            source_id=row["id"],
            file_name=row["file_name"],
            path=row["file_location"] or row["artifact_path"],
            timestamp=row["target_accessed"] or row["target_modified"] or row["target_created"],
            user_profile=_user_from_path(row["artifact_path"] or row["file_location"]),
            detail={"artifact_name": row["artifact_name"], "artifact_path": row["artifact_path"]},
        )

    for row in _query_report_rows(
        db,
        case_id,
        "copied_file_indicators",
        """
        SELECT id, source_artifact_type, source_artifact_name, file_name,
               file_location, created_timestamp_utc, modified_timestamp_utc
        FROM copied_file_indicators
        WHERE case_id = ?
          AND source_artifact_type NOT IN ('mft_si', 'mft_fn')
        """,
        (case_id,),
    ):
        add_signal(
            source=f"copied:{row['source_artifact_type']}",
            source_table="copied_file_indicators",
            source_id=row["id"],
            file_name=row["file_name"],
            path=row["file_location"],
            timestamp=row["created_timestamp_utc"],
            user_profile=_user_from_path(row["file_location"]),
            detail={
                "source_artifact_name": row["source_artifact_name"],
                "modified_timestamp_utc": row["modified_timestamp_utc"],
            },
        )

    for row in _query_report_rows(
        db,
        case_id,
        "windows_activities",
        """
        SELECT id, user_profile, app_display_name, activity_type, file_name,
               display_text, content_uri, activation_uri, fallback_uri,
               start_time_utc, end_time_utc
        FROM windows_activities
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        path = row["content_uri"] or row["activation_uri"] or row["fallback_uri"]
        add_signal(
            source="windows_activities",
            source_table="windows_activities",
            source_id=row["id"],
            file_name=row["file_name"] or row["display_text"],
            path=path,
            timestamp=row["start_time_utc"] or row["end_time_utc"],
            user_profile=row["user_profile"],
            application=row["app_display_name"],
            detail={"activity_type": row["activity_type"], "display_text": row["display_text"]},
        )

    for row in _query_report_rows(
        db,
        case_id,
        "browser_downloads",
        """
        SELECT id, browser, profile_path, target_path, tab_url, site_url,
               start_time_utc, end_time_utc
        FROM browser_downloads
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        add_signal(
            source=f"browser_download:{row['browser'] or 'browser'}",
            source_table="browser_downloads",
            source_id=row["id"],
            file_name=None,
            path=row["target_path"],
            timestamp=row["end_time_utc"] or row["start_time_utc"],
            user_profile=_user_from_path(row["profile_path"] or row["target_path"]),
            application=row["browser"],
            detail={"tab_url": row["tab_url"], "site_url": row["site_url"]},
        )

    for row in _query_report_rows(
        db,
        case_id,
        "webcache_file_accesses",
        """
        SELECT id, user_name, application, file_name, normalized_path, url,
               accessed_utc, modified_utc, created_utc
        FROM webcache_file_accesses
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        add_signal(
            source="webcache_file",
            source_table="webcache_file_accesses",
            source_id=row["id"],
            file_name=row["file_name"],
            path=row["normalized_path"] or row["url"],
            timestamp=row["accessed_utc"] or row["modified_utc"] or row["created_utc"],
            user_profile=row["user_name"] or _user_from_path(row["normalized_path"]),
            application=row["application"],
            detail={"url": row["url"]},
        )

    for row in _query_report_rows(
        db,
        case_id,
        "windows_search_files",
        """
        SELECT id, item_path, item_url, file_name, gather_time, date_created,
               date_modified, date_accessed, owner
        FROM windows_search_files
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        add_signal(
            source="windows_search_file",
            source_table="windows_search_files",
            source_id=row["id"],
            file_name=row["file_name"],
            path=row["item_path"] or row["item_url"],
            timestamp=row["date_accessed"] or row["date_modified"] or row["gather_time"] or row["date_created"],
            user_profile=row["owner"] or _user_from_path(row["item_path"]),
        )

    for row in _query_report_rows(
        db,
        case_id,
        "thumbcache_search_correlations",
        """
        SELECT id, cache_id, thumbcache_user, thumbcache_name, search_file_name,
               search_item_path, search_date_created, search_date_modified,
               search_date_accessed, search_date_imported, correlation_basis,
               confidence
        FROM thumbcache_search_correlations
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        add_signal(
            source="thumbcache_search",
            source_table="thumbcache_search_correlations",
            source_id=row["id"],
            file_name=row["search_file_name"],
            path=row["search_item_path"],
            timestamp=(
                row["search_date_accessed"]
                or row["search_date_modified"]
                or row["search_date_created"]
                or row["search_date_imported"]
            ),
            user_profile=row["thumbcache_user"] or _user_from_path(row["search_item_path"]),
            detail={
                "cache_id": row["cache_id"],
                "thumbcache_name": row["thumbcache_name"],
                "correlation_basis": row["correlation_basis"],
                "confidence": row["confidence"],
            },
        )

    for row in _query_report_rows(
        db,
        case_id,
        "windows_search_indexed_content",
        """
        SELECT id, item_path, item_name, item_type, content_field,
               content_length, timestamp, gather_time
        FROM windows_search_indexed_content
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        add_signal(
            source="windows_search_content",
            source_table="windows_search_indexed_content",
            source_id=row["id"],
            file_name=row["item_name"],
            path=row["item_path"],
            timestamp=row["timestamp"] or row["gather_time"],
            user_profile=_user_from_path(row["item_path"]),
            detail={"item_type": row["item_type"], "content_field": row["content_field"], "content_length": row["content_length"]},
        )

    for row in _query_report_rows(
        db,
        case_id,
        "file_internal_metadata",
        """
        SELECT id, original_path, file_name, extension, property_name,
               property_value, mft_created, mft_modified, mft_accessed
        FROM file_internal_metadata
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        add_signal(
            source="file_metadata",
            source_table="file_internal_metadata",
            source_id=row["id"],
            file_name=row["file_name"],
            path=row["original_path"],
            timestamp=row["mft_accessed"] or row["mft_modified"] or row["mft_created"],
            user_profile=_user_from_path(row["original_path"]),
            detail={"property_name": row["property_name"], "extension": row["extension"]},
        )

    for row in _query_report_rows(
        db,
        case_id,
        "usn_journal_entries",
        """
        SELECT id, file_name, full_path, reason, update_timestamp
        FROM usn_journal_entries
        WHERE case_id = ?
        """,
        (case_id,),
    ):
        add_signal(
            source="usn_journal",
            source_table="usn_journal_entries",
            source_id=row["id"],
            file_name=row["file_name"],
            path=row["full_path"],
            timestamp=row["update_timestamp"],
            user_profile=_user_from_path(row["full_path"]),
            detail={"reason": row["reason"]},
        )

    if include_mft:
        for row in _query_report_rows(
            db,
            case_id,
            "mft_entries",
            """
            SELECT id, file_name, parent_path, created_si, modified_si,
                   accessed_si, in_use, is_directory
            FROM mft_entries
            WHERE case_id = ?
            """,
            (case_id,),
        ):
            path = _join_path(row["parent_path"], row["file_name"])
            add_signal(
                source="mft",
                source_table="mft_entries",
                source_id=row["id"],
                file_name=row["file_name"],
                path=path,
                timestamp=row["accessed_si"] or row["modified_si"] or row["created_si"],
                user_profile=_user_from_path(path),
                detail={"in_use": row["in_use"], "is_directory": row["is_directory"]},
            )

    file_names = []
    for group in groups.values():
        item = dict(group)
        item["sources"] = sorted(item["sources"])
        item["source_tables"] = sorted(item["source_tables"])
        item["paths"] = sorted(item["paths"])[:10]
        item["normalized_paths"] = sorted(item.get("normalized_paths", set()))[:10]
        item["users"] = sorted(item["users"])
        item["applications"] = sorted(item["applications"])
        item["source_count"] = len(item["sources"])
        item["path_count"] = len(group["paths"])
        item["evidence_tags"] = _group_evidence_tags(item)
        file_names.append(item)
    file_names.sort(key=lambda item: (-item["source_count"], -item["evidence_count"], item["file_name"].lower()))
    visible_names = {item["file_name"].lower() for item in file_names[:limit]}
    evidence_rows = [
        row for row in rows
        if row["file_name"].lower() in visible_names
    ]
    evidence_rows.sort(key=lambda row: (row["file_name"].lower(), row.get("timestamp") or "", row["source"]))
    return {
        "case_id": case_id,
        "filters": {"contains": contains, "include_mft": include_mft},
        "file_names": file_names[:limit],
        "evidence": evidence_rows[: limit * 10],
        "total_file_names": len(file_names),
        "total_evidence_rows": len(rows),
        "total_returned": min(len(file_names), limit),
    }


def file_name_drilldown_report(
    db: Database,
    case_id: str,
    *,
    name: str,
    include_mft: bool = True,
    limit: int = 500,
) -> dict[str, Any]:
    report = file_names_report(db, case_id, contains=name, include_mft=include_mft, limit=max(limit, 1000))
    exact = name.lower()
    evidence = [
        row for row in report["evidence"]
        if row["file_name"].lower() == exact or exact in row["file_name"].lower()
    ][:limit]
    evidence_by_source: dict[str, list[dict[str, Any]]] = {}
    for row in evidence:
        evidence_by_source.setdefault(row["source_table"], []).append(row)
    matching_names = [
        row for row in report["file_names"]
        if row["file_name"].lower() == exact or exact in row["file_name"].lower()
    ]
    return {
        "case_id": case_id,
        "name": name,
        "include_mft": include_mft,
        "matching_file_names": matching_names,
        "evidence_by_source": evidence_by_source,
        "evidence": evidence,
        "total_matching_file_names": len(matching_names),
        "total_evidence_rows": len(evidence),
    }


def file_history_report(
    db: Database,
    case_id: str,
    *,
    name: str | None = None,
    path: str | None = None,
    mft_entry: str | None = None,
    include_artifacts: bool = True,
    limit: int = 500,
) -> dict[str, Any]:
    db.get_case(case_id)
    if not any((name, path, mft_entry)):
        raise ValueError("file_history_report requires name, path, or mft_entry")

    derived_name = name or _basename_from_path(path)
    filters = ["filesystem_review.case_id = ?", _artifact_duplicate_condition("filesystem_review")]
    params: list[Any] = [case_id]
    if mft_entry:
        filters.append("filesystem_review.mft_entry_number = ?")
        params.append(mft_entry)
    if path:
        filters.append("filesystem_review.file_path LIKE ?")
        params.append(f"%{path}%")
    elif name:
        filters.append("(filesystem_review.file_name LIKE ? OR filesystem_review.file_path LIKE ?)")
        params.extend([f"%{name}%", f"%{name}%"])
    where = " AND ".join(filters)
    fs_rows = _query_report_rows(
        db,
        case_id,
        "filesystem_review",
        f"""
        SELECT filesystem_review.*, computers.label AS computer_label, images.path AS image_path,
               {_artifact_source_count_sql("filesystem_review")} AS source_count
        FROM filesystem_review
        LEFT JOIN computers ON filesystem_review.computer_id = computers.id
        LEFT JOIN images ON filesystem_review.image_id = images.id
        WHERE {where}
        ORDER BY COALESCE(filesystem_review.event_time, '') ASC,
                 filesystem_review.source_table,
                 filesystem_review.source_row_number
        LIMIT ?
        """,
        [*params, limit],
    )
    if not fs_rows:
        fs_rows = _duckdb_file_history_rows(
            db,
            case_id,
            name=name,
            path=path,
            mft_entry=mft_entry,
            limit=limit,
        )

    events: list[dict[str, Any]] = []
    for row in fs_rows:
        item = dict(row)
        details = _json_details(item.pop("details_json", None))
        events.append(
            {
                "timestamp": item["event_time"],
                "source": _history_source_label(item["source_table"]),
                "source_table": item["source_table"],
                "source_id": item["source_id"],
                "event_type": item["event_type"],
                "status": item["status"],
                "operation": item["operation"],
                "reason": item["reason"],
                "file_name": item["file_name"],
                "path": item["file_path"],
                "display_path": _display_evidence_path(item["file_path"]),
                "normalized_path": _normalize_artifact_path(item["file_path"]),
                "parent_path": item["parent_path"],
                "mft_entry_number": item["mft_entry_number"],
                "mft_sequence_number": item["mft_sequence_number"],
                "computer_label": item["computer_label"],
                "details": details,
            }
        )

    artifact_events: list[dict[str, Any]] = _direct_file_history_artifact_events(
        db,
        case_id,
        name=derived_name,
        path=path,
        limit=limit,
    )
    events.extend(artifact_events)
    if include_artifacts and derived_name:
        seen_artifact_events: set[tuple[str, str, str, str, str]] = set()
        drilldown = file_name_drilldown_report(
            db,
            case_id,
            name=derived_name,
            include_mft=False,
            limit=limit,
        )
        for row in drilldown["evidence"]:
            if row.get("source_table") in {
                "mft_entries",
                "usn_journal_entries",
                "filesystem_review",
                "shortcut_items",
            }:
                continue
            row_path = row.get("path") or ""
            if path and path.lower() not in row_path.lower():
                continue
            reason = ",".join(row.get("evidence_tags") or [])
            artifact_key = (
                str(row.get("timestamp") or ""),
                str(row.get("source_table") or ""),
                str(row.get("file_name") or "").casefold(),
                _normalize_path_for_like(row_path).casefold(),
                reason,
            )
            if artifact_key in seen_artifact_events:
                continue
            seen_artifact_events.add(artifact_key)
            generic_event = {
                "timestamp": row.get("timestamp"),
                "source": row.get("source"),
                "source_table": row.get("source_table"),
                "source_id": row.get("source_id"),
                "event_type": "artifact_reference",
                "status": None,
                "operation": None,
                "reason": reason,
                "file_name": row.get("file_name"),
                "path": row_path,
                "display_path": _display_evidence_path(row_path),
                "normalized_path": _normalize_artifact_path(row_path),
                "parent_path": None,
                "mft_entry_number": None,
                "mft_sequence_number": None,
                "computer_label": None,
                "details": row.get("details") or {},
            }
            artifact_events.append(generic_event)
            events.append(generic_event)

    events.sort(
        key=lambda item: (
            _timestamp_sort_key(item.get("timestamp")),
            item.get("source") or "",
            item.get("path") or "",
        )
    )
    if len(events) > limit:
        events = events[:limit]

    source_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}
    for event in events:
        source_counts[event["source"]] = source_counts.get(event["source"], 0) + 1
        event_type_counts[event["event_type"]] = event_type_counts.get(event["event_type"], 0) + 1

    return {
        "case_id": case_id,
        "filters": {
            "name": name,
            "path": path,
            "mft_entry": mft_entry,
            "include_artifacts": include_artifacts,
        },
        "summary": {
            "source_counts": source_counts,
            "event_type_counts": event_type_counts,
            "filesystem_event_count": len(fs_rows),
            "artifact_event_count": len(artifact_events),
        },
        "events": events,
        "total_returned": len(events),
    }


def _direct_file_history_artifact_events(
    db: Database,
    case_id: str,
    *,
    name: str | None,
    path: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    events.extend(_shortcut_file_history_events(db, case_id, name=name, path=path, limit=limit))
    events.extend(_prefetch_file_history_events(db, case_id, name=name, path=path, limit=limit))
    events.extend(_office_backstage_file_history_events(db, case_id, name=name, path=path, limit=limit))
    events.extend(_cloud_file_history_events(db, case_id, name=name, path=path, limit=limit))
    events.extend(_email_attachment_file_history_events(db, case_id, name=name, path=path, limit=limit))
    events.extend(_webcache_file_history_events(db, case_id, name=name, path=path, limit=limit))
    return events


def _shortcut_file_history_events(
    db: Database,
    case_id: str,
    *,
    name: str | None,
    path: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    target = path or name
    if target:
        filters.append(
            "(file_name LIKE ? OR file_location LIKE ? OR artifact_name LIKE ? OR artifact_path LIKE ?)"
        )
        params.extend([f"%{target}%", f"%{target}%", f"%{target}%", f"%{target}%"])
    rows = _query_report_rows(
        db,
        case_id,
        "shortcut_items",
        f"""
        SELECT id, artifact_type, artifact_name, artifact_path, file_name, file_location,
               target_created, target_modified, target_accessed,
               lnk_created, lnk_modified, lnk_accessed
        FROM shortcut_items
        WHERE {" AND ".join(filters)}
        ORDER BY artifact_type, artifact_path, row_number
        LIMIT ?
        """,
        [*params, limit],
    )
    events: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for row in rows:
        for field, event_type, reason in (
            ("target_created", "target_created", "shortcut target created timestamp"),
            ("target_modified", "target_modified", "shortcut target modified timestamp"),
            ("target_accessed", "target_accessed", "shortcut target accessed timestamp"),
            ("lnk_created", "shortcut_created", "shortcut file created timestamp"),
            ("lnk_modified", "shortcut_modified", "shortcut file modified timestamp"),
            ("lnk_accessed", "shortcut_accessed", "shortcut file accessed timestamp"),
        ):
            timestamp = row.get(field)
            if not timestamp:
                continue
            key = (
                str(row.get("artifact_type") or "shortcut"),
                str(row.get("artifact_name") or ""),
                str(row.get("file_name") or ""),
                str(row.get("file_location") or ""),
                event_type,
            )
            if key in seen:
                continue
            seen.add(key)
            events.append(
                {
                    "timestamp": timestamp,
                    "source": row.get("artifact_type") or "shortcut",
                    "source_table": "shortcut_items",
                    "source_id": row.get("id"),
                    "event_type": event_type,
                    "status": None,
                    "operation": field,
                    "reason": reason,
                    "file_name": row.get("file_name"),
                    "path": row.get("file_location") or row.get("artifact_path"),
                    "display_path": _display_evidence_path(row.get("file_location") or row.get("artifact_path")),
                    "normalized_path": _normalize_artifact_path(row.get("file_location") or row.get("artifact_path")),
                    "parent_path": None,
                    "mft_entry_number": None,
                    "mft_sequence_number": None,
                    "computer_label": None,
                    "details": {
                        "artifact_name": row.get("artifact_name"),
                        "artifact_path": row.get("artifact_path"),
                        "source_table": "shortcut_items",
                    },
                }
            )
    return events


def _prefetch_file_history_events(
    db: Database,
    case_id: str,
    *,
    name: str | None,
    path: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    target = path or name
    if not target:
        return []
    target_name = _basename_from_path(target) or target
    target_terms = {
        str(target).replace("/", "\\").casefold(),
        str(target).replace("\\", "/").casefold(),
        str(target_name).casefold(),
    }
    like_terms = [term for term in target_terms if term]
    if not like_terms:
        return []
    filters = ["case_id = ?", "referenced_strings IS NOT NULL", "(" + " OR ".join("lower(referenced_strings) LIKE ?" for _ in like_terms) + ")"]
    params: list[Any] = [case_id, *(f"%{term}%" for term in like_terms)]
    rows = _query_report_rows(
        db,
        case_id,
        "prefetch_items",
        f"""
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               prefetch_name, executable_name, artifact_path, original_path,
               prefetch_hash, run_count, last_run_time_utc, last_run_times_utc,
               referenced_strings
        FROM prefetch_items
        WHERE {" AND ".join(filters)}
        ORDER BY COALESCE(last_run_time_utc, '') ASC, executable_name, prefetch_name
        LIMIT ?
        """,
        [*params, limit],
    )
    events: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        references = [
            str(value)
            for value in _coerce_list(row.get("referenced_strings"))
            if any(term in str(value).casefold() for term in target_terms)
        ]
        if not references:
            references = [str(row.get("referenced_strings") or "")]
        timestamps = _coerce_list(row.get("last_run_times_utc"))
        if not timestamps and row.get("last_run_time_utc"):
            timestamps = [row.get("last_run_time_utc")]
        if not timestamps:
            timestamps = [None]
        for reference in references:
            for timestamp in timestamps:
                key = (str(row.get("id") or ""), str(timestamp or ""), reference)
                if key in seen:
                    continue
                seen.add(key)
                events.append(
                    {
                        "timestamp": timestamp,
                        "source": "Prefetch",
                        "source_table": "prefetch_items",
                        "source_id": row.get("id"),
                        "event_type": "prefetch_file_reference",
                        "status": None,
                        "operation": "prefetch_referenced_string",
                        "reason": "file path/name appears in Prefetch referenced strings; indicates file use context during executable runs, not direct file execution",
                        "file_name": target_name,
                        "path": reference,
                        "display_path": _display_evidence_path(reference),
                        "normalized_path": _normalize_artifact_path(reference),
                        "parent_path": None,
                        "mft_entry_number": None,
                        "mft_sequence_number": None,
                        "computer_label": None,
                        "details": {
                            "executable_name": row.get("executable_name"),
                            "prefetch_name": row.get("prefetch_name"),
                            "prefetch_hash": row.get("prefetch_hash"),
                            "run_count": row.get("run_count"),
                            "prefetch_artifact_path": row.get("artifact_path") or row.get("original_path"),
                            "source_file": row.get("source_csv"),
                            "row_number": row.get("row_number"),
                        },
                    }
                )
    return events


def _office_backstage_file_history_events(
    db: Database,
    case_id: str,
    *,
    name: str | None,
    path: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    if not _duckdb_table_available(db, case_id, "office_backstage_items"):
        return []
    target = path or name
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if target:
        filters.append("(name LIKE ? OR value LIKE ? OR path LIKE ? OR source_path LIKE ? OR url LIKE ?)")
        params.extend([f"%{target}%", f"%{target}%", f"%{target}%", f"%{target}%", f"%{target}%"])
    rows = _query_report_rows(
        db,
        case_id,
        "office_backstage_items",
        f"""
        SELECT id, artifact_type, source_path, user_profile, application, name, value, path, url,
               timestamp_utc, details_json
        FROM office_backstage_items
        WHERE {" AND ".join(filters)}
        ORDER BY COALESCE(timestamp_utc, '') ASC, row_number
        LIMIT ?
        """,
        [*params, limit],
    )
    events: list[dict[str, Any]] = []
    for row in rows:
        details = _json_details(row.get("details_json"))
        details.update(
            {
                "artifact_name": row.get("name"),
                "source_artifact_name": row.get("artifact_type"),
                "source_path": row.get("source_path"),
                "application": row.get("application"),
                "user_profile": row.get("user_profile"),
            }
        )
        events.append(
            {
                "timestamp": row.get("timestamp_utc"),
                "source": "office_backstage",
                "source_table": "office_backstage_items",
                "source_id": row.get("id"),
                "event_type": row.get("artifact_type") or "office_backstage_reference",
                "status": None,
                "operation": row.get("artifact_type"),
                "reason": "office backstage recent-file reference",
                        "file_name": _coalesce_file_name(row.get("name"), row.get("path") or row.get("value")),
                        "path": row.get("path") or row.get("value") or row.get("url"),
                        "display_path": _display_evidence_path(row.get("path") or row.get("value") or row.get("url")),
                        "normalized_path": _normalize_artifact_path(row.get("path") or row.get("value") or row.get("url")),
                        "parent_path": None,
                "mft_entry_number": None,
                "mft_sequence_number": None,
                "computer_label": None,
                "details": details,
            }
        )
    return events


def _cloud_file_history_events(
    db: Database,
    case_id: str,
    *,
    name: str | None,
    path: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    target = path or name
    if not target:
        return []
    events: list[dict[str, Any]] = []
    for table, sql, source_name in (
        (
            "cloud_sync_artifacts",
            """
            SELECT id, provider AS source, file_name, COALESCE(local_path, cloud_path, server_path) AS path,
                   event_time_utc AS timestamp, COALESCE(sync_status, event_type, artifact_type) AS reason
            FROM cloud_sync_artifacts
            WHERE case_id = ? AND (file_name LIKE ? OR local_path LIKE ? OR cloud_path LIKE ? OR server_path LIKE ?)
            ORDER BY COALESCE(event_time_utc, '') ASC
            LIMIT ?
            """,
            "cloud_sync",
        ),
        (
            "onedrive_items",
            """
            SELECT id, account AS source, name AS file_name, path,
                   COALESCE(last_change_utc, disk_last_access_utc, disk_creation_utc, delete_time_utc) AS timestamp,
                   COALESCE(status, record_type, artifact_type) AS reason
            FROM onedrive_items
            WHERE case_id = ? AND (name LIKE ? OR path LIKE ? OR resource_id LIKE ? OR parent_resource_id LIKE ?)
            ORDER BY COALESCE(last_change_utc, disk_last_access_utc, disk_creation_utc, delete_time_utc, '') ASC
            LIMIT ?
            """,
            "onedrive",
        ),
        (
            "google_drive_cache_map",
            """
            SELECT id, account_id AS source, file_name,
                   COALESCE(virtual_path, windows_cache_path, cache_path) AS path,
                   NULL AS timestamp, mapping_method AS reason
            FROM google_drive_cache_map
            WHERE case_id = ? AND (file_name LIKE ? OR virtual_path LIKE ? OR windows_cache_path LIKE ? OR cache_path LIKE ?)
            LIMIT ?
            """,
            "google_drive",
        ),
    ):
        if not _duckdb_table_available(db, case_id, table):
            continue
        rows = _query_report_rows(
            db,
            case_id,
            table,
            sql,
            (case_id, f"%{target}%", f"%{target}%", f"%{target}%", f"%{target}%", limit),
        )
        for row in rows:
            events.append(
                {
                    "timestamp": row.get("timestamp"),
                    "source": row.get("source") or source_name,
                    "source_table": table,
                    "source_id": row.get("id"),
                    "event_type": "cloud_sync_reference",
                    "status": None,
                    "operation": None,
                    "reason": row.get("reason"),
                    "file_name": row.get("file_name"),
                    "path": row.get("path"),
                    "display_path": _display_evidence_path(row.get("path")),
                    "normalized_path": _normalize_artifact_path(row.get("path")),
                    "parent_path": None,
                    "mft_entry_number": None,
                    "mft_sequence_number": None,
                    "computer_label": None,
                    "details": {},
                }
            )
    return events


def _email_attachment_file_history_events(
    db: Database,
    case_id: str,
    *,
    name: str | None,
    path: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    target = path or name
    if not target:
        return []
    target_name = _basename_from_path(target) or target
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    filters.append(
        "(attachment_name LIKE ? OR attachment_path LIKE ? OR subject LIKE ? OR message_path LIKE ?)"
    )
    params.extend([f"%{target_name}%", f"%{target}%", f"%{target_name}%", f"%{target}%"])
    rows = _query_report_rows(
        db,
        case_id,
        "mailbox_attachments",
        f"""
        SELECT id, user_profile, message_date_utc, subject, sender, recipients,
               conversation_index, conversation_topic,
               attachment_name, attachment_path, message_path, container_path,
               content_type, size, sha256, extraction_status, opensearch_document_id
        FROM mailbox_attachments
        WHERE {" AND ".join(filters)}
        ORDER BY COALESCE(message_date_utc, '') ASC, attachment_name
        LIMIT ?
        """,
        [*params, limit],
    )
    events: list[dict[str, Any]] = []
    for row in rows:
        attachment_path = row.get("attachment_path") or row.get("attachment_name")
        events.append(
            {
                "timestamp": row.get("message_date_utc"),
                "source": "email_attachment",
                "source_table": "mailbox_attachments",
                "source_id": row.get("id"),
                "event_type": "email_attachment_origin",
                "status": row.get("extraction_status"),
                "operation": "email_attachment_observed",
                "reason": "file name/path appears as an email attachment in parsed mailbox data",
                "file_name": row.get("attachment_name"),
                "path": attachment_path,
                "display_path": _display_evidence_path(attachment_path),
                "normalized_path": _normalize_artifact_path(attachment_path),
                "parent_path": None,
                "mft_entry_number": None,
                "mft_sequence_number": None,
                "computer_label": None,
                "details": {
                    "subject": row.get("subject"),
                    "sender": row.get("sender"),
                    "recipients": row.get("recipients"),
                    "conversation_index": row.get("conversation_index"),
                    "conversation_topic": row.get("conversation_topic"),
                    "message_path": row.get("message_path"),
                    "container_path": row.get("container_path"),
                    "content_type": row.get("content_type"),
                    "size": row.get("size"),
                    "sha256": row.get("sha256"),
                    "opensearch_document_id": row.get("opensearch_document_id"),
                    "source_table": "mailbox_attachments",
                },
            }
        )
    return events


def _webcache_file_history_events(
    db: Database,
    case_id: str,
    *,
    name: str | None,
    path: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    target = path or name
    if not target:
        return []
    target_name = _basename_from_path(target) or target
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    filters.append("(local_path LIKE ? OR normalized_path LIKE ? OR url LIKE ? OR file_name LIKE ?)")
    params.extend([f"%{target}%", f"%{target}%", f"%{target}%", f"%{target_name}%"])
    rows = _query_report_rows(
        db,
        case_id,
        "webcache_file_accesses",
        f"""
        SELECT id, user_name, application, source_table, url, local_path,
               normalized_path, file_name, created_utc, accessed_utc, modified_utc,
               source_database, container_name
        FROM webcache_file_accesses
        WHERE {" AND ".join(filters)}
        ORDER BY COALESCE(accessed_utc, modified_utc, created_utc, '') ASC, file_name
        LIMIT ?
        """,
        [*params, limit],
    )
    events: list[dict[str, Any]] = []
    for row in rows:
        timestamp = row.get("accessed_utc") or row.get("modified_utc") or row.get("created_utc")
        events.append(
            {
                "timestamp": timestamp,
                "source": "webcache_file_access",
                "source_table": "webcache_file_accesses",
                "source_id": row.get("id"),
                "event_type": "webcache_file_access",
                "status": None,
                "operation": "file_url_access",
                "reason": "file:/// URL extracted from WebCache and normalized to a local path",
                "file_name": row.get("file_name") or _basename_from_path(row.get("local_path")),
                "path": row.get("local_path"),
                "display_path": _display_evidence_path(row.get("local_path")),
                "normalized_path": row.get("normalized_path") or _normalize_artifact_path(row.get("local_path")),
                "parent_path": None,
                "mft_entry_number": None,
                "mft_sequence_number": None,
                "computer_label": None,
                "details": {
                    "user_name": row.get("user_name"),
                    "application": row.get("application"),
                    "url": row.get("url"),
                    "source_webcache_table": row.get("source_table"),
                    "source_database": row.get("source_database"),
                    "container_name": row.get("container_name"),
                },
            }
        )
    return events


def file_history_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    filters = report.get("filters") if isinstance(report.get("filters"), dict) else {}
    events = report.get("events") if isinstance(report.get("events"), list) else []
    lines = [
        "# File History Report",
        "",
        f"Case: `{report.get('case_id') or ''}`",
        "",
        "## Scope",
        "",
        f"- Name: `{filters.get('name') or ''}`",
        f"- Path: `{filters.get('path') or ''}`",
        f"- MFT entry: `{filters.get('mft_entry') or ''}`",
        f"- Artifact references included: `{filters.get('include_artifacts')}`",
        "",
        "## Summary",
        "",
        f"- Filesystem events: `{summary.get('filesystem_event_count', 0)}`",
        f"- Artifact references: `{summary.get('artifact_event_count', 0)}`",
        f"- Total returned: `{report.get('total_returned', 0)}`",
        "",
    ]
    source_counts = summary.get("source_counts") if isinstance(summary.get("source_counts"), dict) else {}
    if source_counts:
        lines.extend(["### Sources", ""])
        for source, count in sorted(source_counts.items()):
            lines.append(f"- `{source}`: `{count}`")
        lines.append("")
    event_type_counts = summary.get("event_type_counts") if isinstance(summary.get("event_type_counts"), dict) else {}
    if event_type_counts:
        lines.extend(["### Event Types", ""])
        for event_type, count in sorted(event_type_counts.items()):
            lines.append(f"- `{event_type}`: `{count}`")
        lines.append("")
    lines.extend(["## Timeline", ""])
    if not events:
        lines.append("- No matching file history events were found.")
    for event in events:
        if not isinstance(event, dict):
            continue
        lines.append(
            f"- `{event.get('timestamp') or ''}` `{event.get('source') or ''}` `{event.get('event_type') or ''}` "
            f"`{event.get('file_name') or ''}` path `{event.get('display_path') or _display_evidence_path(event.get('path'))}`"
        )
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        detail_bits = [
            f"{key}={value}"
            for key, value in {
                "status": event.get("status"),
                "operation": event.get("operation"),
                "reason": event.get("reason"),
                "mft_entry": event.get("mft_entry_number"),
                "computer": event.get("computer_label"),
                "artifact": details.get("artifact_name") or details.get("source_artifact_name"),
                "source_table": event.get("source_table"),
                "registry_key": details.get("key_path"),
                "email_subject": details.get("subject"),
                "webcache_table": details.get("source_webcache_table"),
            }.items()
            if value not in (None, "")
        ]
        if detail_bits:
            lines.append(f"  - " + "; ".join(detail_bits))
    return "\n".join(lines).rstrip() + "\n"


def file_history_overview_markdown(report: dict[str, Any]) -> str:
    file_names = report.get("file_names") if isinstance(report.get("file_names"), list) else []
    evidence = report.get("evidence") if isinstance(report.get("evidence"), list) else []
    lines = [
        "# File History Overview",
        "",
        f"Case: `{report.get('case_id') or ''}`",
        "",
        "## Summary",
        "",
        f"- Matching file names: `{report.get('total_file_names', 0)}`",
        f"- Evidence rows scanned: `{report.get('total_evidence_rows', 0)}`",
        f"- File names returned: `{report.get('total_returned', 0)}`",
        "",
        "## Top File Names",
        "",
    ]
    if not file_names:
        lines.append("- No file-history evidence was found.")
    for item in file_names:
        if not isinstance(item, dict):
            continue
        sources = ", ".join(f"`{source}`" for source in item.get("sources") or [])
        users = ", ".join(f"`{user}`" for user in item.get("users") or [])
        lines.append(
            f"- `{item.get('file_name') or ''}`: evidence `{item.get('evidence_count') or 0}`, "
            f"sources {sources or '`<none>`'}, users {users or '`<none>`'}"
        )
        for path in (item.get("paths") or [])[:3]:
            lines.append(f"  - path `{path}`")
    lines.extend(["", "## Evidence Sample", ""])
    if not evidence:
        lines.append("- No evidence rows available.")
    for row in evidence[:50]:
        if not isinstance(row, dict):
            continue
        tags = ",".join(row.get("evidence_tags") or [])
        lines.append(
            f"- `{row.get('timestamp') or ''}` `{row.get('source') or ''}` "
            f"`{row.get('file_name') or ''}` path `{row.get('path') or ''}` tags `{tags}`"
        )
    return "\n".join(lines).rstrip() + "\n"


def _duckdb_file_history_rows(
    db: Database,
    case_id: str,
    *,
    name: str | None,
    path: str | None,
    mft_entry: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    computer_labels = _computer_labels(db, case_id)
    image_paths = _image_paths(db, case_id)

    mft_where = ["case_id = ?"]
    mft_params: list[Any] = [case_id]
    if mft_entry:
        mft_where.append("entry_number = ?")
        mft_params.append(mft_entry)
    if name:
        mft_where.append("(file_name LIKE ? OR parent_path LIKE ?)")
        mft_params.extend([f"%{name}%", f"%{name}%"])
    if path:
        mft_where.append("(file_name LIKE ? OR parent_path LIKE ?)")
        mft_params.extend([f"%{path}%", f"%{path}%"])
    mft_params.append(limit)
    if _duckdb_table_available(db, case_id, "mft_entries"):
        for row in _query_report_rows(
            db,
            case_id,
            "mft_entries",
            f"""
            SELECT id, computer_id, image_id, entry_number, sequence_number,
                   parent_path, file_name, in_use, is_directory,
                   created_si, modified_si, accessed_si
            FROM mft_entries
            WHERE {' AND '.join(mft_where)}
            ORDER BY COALESCE(accessed_si, modified_si, created_si, created_at)
            LIMIT ?
            """,
            mft_params,
        ):
            file_path = _join_path(row.get("parent_path"), row.get("file_name"))
            rows.append(
                {
                    "event_time": row.get("accessed_si") or row.get("modified_si") or row.get("created_si"),
                    "source_table": "mft_entries",
                    "source_id": row.get("id"),
                    "event_type": "mft_record",
                    "status": "in_use" if str(row.get("in_use")).lower() in {"true", "1", "yes"} else "not_in_use",
                    "operation": None,
                    "reason": None,
                    "file_name": row.get("file_name"),
                    "file_path": file_path,
                    "parent_path": row.get("parent_path"),
                    "mft_entry_number": row.get("entry_number"),
                    "mft_sequence_number": row.get("sequence_number"),
                    "computer_label": computer_labels.get(str(row.get("computer_id"))),
                    "image_path": image_paths.get(str(row.get("image_id"))),
                    "details_json": json.dumps({"is_directory": row.get("is_directory")}),
                }
            )

    usn_where = ["case_id = ?"]
    usn_params: list[Any] = [case_id]
    if mft_entry:
        usn_where.append("file_reference_number = ?")
        usn_params.append(mft_entry)
    if name:
        usn_where.append("(file_name LIKE ? OR full_path LIKE ?)")
        usn_params.extend([f"%{name}%", f"%{name}%"])
    if path:
        usn_where.append("(file_name LIKE ? OR full_path LIKE ?)")
        usn_params.extend([f"%{path}%", f"%{path}%"])
    usn_params.append(limit)
    if _duckdb_table_available(db, case_id, "usn_journal_entries"):
        for row in _query_report_rows(
            db,
            case_id,
            "usn_journal_entries",
            f"""
            SELECT id, computer_id, image_id, file_name, full_path, reason,
                   update_timestamp, file_reference_number, file_reference_sequence_number
            FROM usn_journal_entries
            WHERE {' AND '.join(usn_where)}
            ORDER BY update_timestamp
            LIMIT ?
            """,
            usn_params,
        ):
            rows.append(
                {
                    "event_time": row.get("update_timestamp"),
                    "source_table": "usn_journal_entries",
                    "source_id": row.get("id"),
                    "event_type": "usn_record",
                    "status": None,
                    "operation": None,
                    "reason": row.get("reason"),
                    "file_name": row.get("file_name"),
                    "file_path": row.get("full_path"),
                    "parent_path": None,
                    "mft_entry_number": row.get("file_reference_number"),
                    "mft_sequence_number": row.get("file_reference_sequence_number"),
                    "computer_label": computer_labels.get(str(row.get("computer_id"))),
                    "image_path": image_paths.get(str(row.get("image_id"))),
                    "details_json": "{}",
                }
            )
    rows.sort(key=lambda item: (_timestamp_sort_key(item.get("event_time")), item.get("source_table") or ""))
    return rows[:limit]


def correlations_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT file_correlations.*, computers.label AS computer_label, images.path AS image_path
        FROM file_correlations
        LEFT JOIN computers ON file_correlations.computer_id = computers.id
        LEFT JOIN images ON file_correlations.image_id = images.id
        WHERE file_correlations.case_id = ?
        ORDER BY file_correlations.confidence DESC, file_correlations.match_type, file_correlations.mft_path
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {
        "case_id": case_id,
        "correlations": [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def copied_files_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT timeline_events.*, computers.label AS computer_label, images.path AS image_path
        FROM timeline_events
        LEFT JOIN computers ON timeline_events.computer_id = computers.id
        LEFT JOIN images ON timeline_events.image_id = images.id
        WHERE timeline_events.case_id = ? AND timeline_events.event_type = 'copied_file_indicator'
        ORDER BY timeline_events.timestamp_utc
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    copied = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        copied.append(item)
    return {"case_id": case_id, "copied_files": copied, "total_returned": len(copied)}


def copied_file_indicators_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    source_artifact_type: str | None = None,
    user_only: bool = False,
    exclude_system: bool = True,
    include_mft_only: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters = ["copied_file_indicators.case_id = ?"]
    params: list[Any] = [case_id]
    if source_artifact_type:
        filters.append("copied_file_indicators.source_artifact_type = ?")
        params.append(source_artifact_type)
    elif not include_mft_only:
        filters.append("copied_file_indicators.source_artifact_type NOT IN ('mft_si', 'mft_fn')")
    if user_only:
        filters.append(
            """
            (
              copied_file_indicators.file_location LIKE '.\\Users\\%'
              OR copied_file_indicators.file_location LIKE 'Users/%'
              OR copied_file_indicators.file_location LIKE 'C:\\Users\\%'
            )
            """
        )
    if exclude_system:
        filters.append(
            """
            copied_file_indicators.file_location NOT LIKE '.\\Windows\\%'
            AND copied_file_indicators.file_location NOT LIKE '.\\Windows/%'
            AND copied_file_indicators.file_location NOT LIKE '.\\Program Files%'
            AND copied_file_indicators.file_location NOT LIKE '.\\ProgramData%'
            AND copied_file_indicators.file_location NOT LIKE 'C:\\Windows\\%'
            AND copied_file_indicators.file_location NOT LIKE 'C:\\Windows/%'
            AND copied_file_indicators.file_location NOT LIKE 'C:\\Program Files%'
            AND copied_file_indicators.file_location NOT LIKE '%/Windows/%'
            AND copied_file_indicators.file_location NOT LIKE '%/Program Files%'
            AND copied_file_indicators.file_location NOT LIKE '%/ProgramData/%'
            """
        )
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT copied_file_indicators.*, computers.label AS computer_label, images.path AS image_path
        FROM copied_file_indicators
        LEFT JOIN computers ON copied_file_indicators.computer_id = computers.id
        LEFT JOIN images ON copied_file_indicators.image_id = images.id
        WHERE {' AND '.join(filters)}
        ORDER BY copied_file_indicators.created_timestamp_utc, copied_file_indicators.source_table
        LIMIT ?
        """,
        params,
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json") or "{}")
        items.append(item)
    return {
        "case_id": case_id,
        "filters": {
            "source_artifact_type": source_artifact_type,
            "user_only": user_only,
            "exclude_system": exclude_system,
            "include_mft_only": include_mft_only,
        },
        "copied_file_indicators": items,
        "total_returned": len(items),
    }


def copied_file_groups_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    include_system: bool = False,
    include_mft_only: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    filters, params = _copied_indicator_filter_sql(
        case_id=case_id,
        exclude_system=not include_system,
        include_mft_only=include_mft_only,
    )
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT
          COALESCE(file_location, file_name, '') AS file_location,
          file_name,
          created_timestamp_utc,
          modified_timestamp_utc,
          COUNT(*) AS indicator_count,
          COUNT(DISTINCT source_artifact_type) AS source_type_count,
          GROUP_CONCAT(DISTINCT source_artifact_type) AS source_artifact_types,
          GROUP_CONCAT(DISTINCT source_tool) AS source_tools,
          MIN(created_at) AS first_recorded_at,
          MAX(created_at) AS last_recorded_at
        FROM copied_file_indicators
        WHERE {' AND '.join(filters)}
        GROUP BY COALESCE(file_location, file_name, ''), created_timestamp_utc, modified_timestamp_utc
        ORDER BY indicator_count DESC, source_type_count DESC, created_timestamp_utc
        LIMIT ?
        """,
        params,
    ).fetchall()
    groups = [dict(row) for row in rows]
    for group in groups:
        group["source_artifact_types"] = _split_csv(group.get("source_artifact_types"))
        group["source_tools"] = _split_csv(group.get("source_tools"))
    total_groups = db.conn.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM (
          SELECT 1
          FROM copied_file_indicators
          WHERE {' AND '.join(filters)}
          GROUP BY COALESCE(file_location, file_name, ''), created_timestamp_utc, modified_timestamp_utc
        )
        """,
        params[:-1],
    ).fetchone()["count"]
    return {
        "case_id": case_id,
        "filters": {
            "include_system": include_system,
            "include_mft_only": include_mft_only,
        },
        "groups": groups,
        "total_groups": total_groups,
        "total_returned": len(groups),
    }


def copied_usb_files_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 250,
    grouped: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    rebuild_usb_file_correlations(db, case_id)
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT
              copied_file_indicators.id AS copied_indicator_id,
              copied_file_indicators.source_tool,
              copied_file_indicators.source_table,
              copied_file_indicators.source_artifact_type,
              copied_file_indicators.source_artifact_name,
              copied_file_indicators.file_name,
              copied_file_indicators.file_location,
              copied_file_indicators.created_timestamp_utc,
              copied_file_indicators.modified_timestamp_utc,
              copied_file_indicators.details_json,
              usb_file_correlations.usb_serial,
              usb_file_correlations.usb_volume_serial_number,
              usb_file_correlations.usb_volume_name,
              usb_file_correlations.usb_drive_letter,
              usb_file_correlations.usb_vendor_id,
              usb_file_correlations.usb_product_id,
              usb_file_correlations.usb_vendor,
              usb_file_correlations.usb_product,
              usb_file_correlations.usb_friendly_name,
              usb_file_correlations.usb_first_install_date_utc,
              usb_file_correlations.usb_last_arrival_utc,
              usb_file_correlations.usb_last_removal_utc,
              usb_file_correlations.user_profile,
              usb_file_correlations.jumplist_item_number,
              usb_file_correlations.artifact_volume_serial_number,
              usb_file_correlations.artifact_volume_name,
              usb_file_correlations.artifact_volume_guid,
              usb_file_correlations.artifact_drive_letter,
              usb_file_correlations.volume_serial_match AS association_basis,
              computers.label AS computer_label,
              images.path AS image_path
            FROM copied_file_indicators
            JOIN usb_file_correlations
              ON usb_file_correlations.case_id = copied_file_indicators.case_id
             AND usb_file_correlations.image_id = copied_file_indicators.image_id
             AND usb_file_correlations.source_artifact_id = copied_file_indicators.source_row_id
            LEFT JOIN computers ON copied_file_indicators.computer_id = computers.id
            LEFT JOIN images ON copied_file_indicators.image_id = images.id
            WHERE copied_file_indicators.case_id = ?
              AND copied_file_indicators.source_artifact_type NOT IN ('mft_si', 'mft_fn')
            ORDER BY
              usb_file_correlations.usb_volume_serial_number,
              copied_file_indicators.created_timestamp_utc,
              copied_file_indicators.file_location
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]
    for row in rows:
        row["details"] = json.loads(row.pop("details_json") or "{}")
        row["association_wording"] = _usb_association_wording(row["source_artifact_type"], row["association_basis"])
    groups = _group_copied_usb_rows(rows) if grouped else []
    device_counts: dict[tuple[str | None, str | None, str | None], dict[str, Any]] = {}
    for row in rows:
        key = (row["usb_serial"], row["usb_volume_serial_number"], row["usb_volume_name"])
        item = device_counts.setdefault(
            key,
            {
                "usb_serial": row["usb_serial"],
                "usb_volume_serial_number": row["usb_volume_serial_number"],
                "usb_volume_name": row["usb_volume_name"],
                "usb_drive_letter": row["usb_drive_letter"],
                "usb_product": row["usb_product"],
                "copied_file_indicators": 0,
            },
        )
        item["copied_file_indicators"] += 1
    return {
        "case_id": case_id,
        "notes": [
            "Rows are copied-file timestamp indicators that also correlate to USB storage evidence.",
            "LNK and Jump List rows are associated by volume serial where available.",
            "Shellbag folder rows are worded as consistent with a USB device when based on folder tree and/or connection-time overlap.",
        ],
        "devices": list(device_counts.values()),
        "items": rows,
        "groups": groups,
        "total_returned": len(groups) if grouped else len(rows),
    }


def tool_run_summary_report(db: Database, case_id: str, *, limit: int = 250) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        SELECT jobs.*, computers.label AS computer_label, images.path AS image_path,
               COUNT(DISTINCT tool_outputs.id) AS output_count,
               COALESCE(SUM(tool_outputs.row_count), 0) AS imported_row_count,
               COUNT(DISTINCT CASE WHEN activity_log.level = 'warning' THEN activity_log.id END) AS warning_count,
               COUNT(DISTINCT CASE WHEN activity_log.level = 'error' THEN activity_log.id END) AS error_count
        FROM jobs
        LEFT JOIN computers ON jobs.computer_id = computers.id
        LEFT JOIN images ON jobs.image_id = images.id
        LEFT JOIN tool_outputs ON tool_outputs.job_id = jobs.id
        LEFT JOIN activity_log ON activity_log.job_id = jobs.id
        WHERE jobs.case_id = ?
        GROUP BY jobs.id
        ORDER BY jobs.start_time DESC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    runs = []
    for row in rows:
        item = dict(row)
        item["command"] = json.loads(item.pop("command_json") or "[]")
        item["status"] = _job_status(item)
        item["warnings"] = _job_activity(db, item["id"], level="warning")
        item["errors"] = _job_activity(db, item["id"], level="error")
        runs.append(item)
    status_counts = _job_status_counts(db, case_id)
    tool_counts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT tool_name,
                   COUNT(*) AS run_count,
                   SUM(CASE WHEN exit_code = 0 THEN 1 ELSE 0 END) AS succeeded,
                   SUM(CASE WHEN exit_code IS NOT NULL AND exit_code != 0 THEN 1 ELSE 0 END) AS failed,
                   SUM(CASE WHEN dry_run = 1 THEN 1 ELSE 0 END) AS dry_runs
            FROM jobs
            WHERE case_id = ?
            GROUP BY tool_name
            ORDER BY tool_name
            """,
            (case_id,),
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "status_counts": status_counts,
        "tools": tool_counts,
        "runs": runs,
        "total_returned": len(runs),
    }


def process_timing_report(db: Database, case_id: str, *, limit: int = 500) -> dict[str, Any]:
    db.get_case(case_id)
    rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT process_timings.*, computers.label AS computer_label, images.path AS image_path
            FROM process_timings
            LEFT JOIN computers ON computers.id = process_timings.computer_id
            LEFT JOIN images ON images.id = process_timings.image_id
            WHERE process_timings.case_id = ?
            ORDER BY process_timings.start_time DESC
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]
    for row in rows:
        row["details"] = json.loads(row.pop("details_json") or "{}")
        row["duration_seconds"] = round((row.get("duration_ms") or 0) / 1000, 3)
    summary = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT scope, phase, status, COUNT(*) AS count,
                   SUM(COALESCE(duration_ms, 0)) AS total_duration_ms,
                   AVG(COALESCE(duration_ms, 0)) AS avg_duration_ms,
                   MIN(start_time) AS first_start,
                   MAX(end_time) AS last_end
            FROM process_timings
            WHERE case_id = ?
            GROUP BY scope, phase, status
            ORDER BY scope, phase, status
            """,
            (case_id,),
        ).fetchall()
    ]
    for row in summary:
        row["total_duration_seconds"] = round((row.get("total_duration_ms") or 0) / 1000, 3)
        row["avg_duration_seconds"] = round((row.get("avg_duration_ms") or 0) / 1000, 3)
    return {
        "case_id": case_id,
        "summary": summary,
        "timings": rows,
        "total_returned": len(rows),
    }


def process_timing_markdown(report: dict[str, Any]) -> str:
    lines = [f"# Process Timing Report", "", f"Case: `{report['case_id']}`", ""]
    lines.append("## Summary")
    lines.append("")
    lines.append("| Scope | Phase | Status | Count | Total seconds | Average seconds | First start | Last end |")
    lines.append("|---|---|---|---:|---:|---:|---|---|")
    for row in report.get("summary", []):
        lines.append(
            "| {scope} | {phase} | {status} | {count} | {total:.3f} | {avg:.3f} | {first} | {last} |".format(
                scope=row.get("scope") or "",
                phase=row.get("phase") or "",
                status=row.get("status") or "",
                count=row.get("count") or 0,
                total=row.get("total_duration_seconds") or 0,
                avg=row.get("avg_duration_seconds") or 0,
                first=row.get("first_start") or "",
                last=row.get("last_end") or "",
            )
        )
    lines.extend(["", "## Timings", ""])
    lines.append("| Start | End | Seconds | Scope | Phase | Name | Status | Tool | Artifact |")
    lines.append("|---|---|---:|---|---|---|---|---|---|")
    for row in reversed(report.get("timings", [])):
        lines.append(
            "| {start} | {end} | {seconds:.3f} | {scope} | {phase} | {name} | {status} | {tool} | {artifact} |".format(
                start=row.get("start_time") or "",
                end=row.get("end_time") or "",
                seconds=row.get("duration_seconds") or 0,
                scope=row.get("scope") or "",
                phase=row.get("phase") or "",
                name=str(row.get("name") or "").replace("|", "\\|"),
                status=row.get("status") or "",
                tool=str(row.get("tool_name") or "").replace("|", "\\|"),
                artifact=str(row.get("artifact_name") or "").replace("|", "\\|"),
            )
        )
    return "\n".join(lines).rstrip() + "\n"


def case_review_report(db: Database, case_id: str, *, limit: int = 25) -> dict[str, Any]:
    db.get_case(case_id)
    completeness = artifact_completeness_report(db, case_id, limit=limit)
    copied = copied_file_indicators_report(db, case_id, limit=limit)
    copied_groups = copied_file_groups_report(db, case_id, limit=limit)
    copied_usb = copied_usb_files_report(db, case_id, limit=limit, grouped=True)
    usb = usb_report(db, case_id, limit=limit)
    issues = issues_report(db, case_id, limit=limit)
    evtx = evtx_recovery_report(db, case_id, limit=limit)
    tool_runs = tool_run_summary_report(db, case_id, limit=limit)
    activity = activity_summary_report(db, case_id, limit=limit)
    return {
        "case_id": case_id,
        "summary": {
            "copied_file_indicators": _count_default_copied_indicators(db, case_id),
            "copied_file_groups": copied_groups["total_groups"],
            "copied_usb_file_groups": len(copied_usb["groups"]),
            "usb_storage_devices": _count(db, "usb_storage_devices", case_id),
            "warnings": len([item for item in issues["issues"] if item["level"] == "warning"]),
            "errors": len([item for item in issues["issues"] if item["level"] == "error"]),
            "evtx_recovery_status_counts": evtx["status_counts"],
            "job_status_counts": tool_runs["status_counts"],
            "tools_with_errors": completeness["summary"]["tools_with_errors"],
            "tools_with_warnings": completeness["summary"]["tools_with_warnings"],
            "tools_without_output": completeness["summary"]["tools_without_output"],
        },
        "artifact_completeness_summary": completeness["summary"],
        "artifact_completeness_by_tool": completeness["tools"][:limit],
        "copied_files": copied["copied_file_indicators"],
        "copied_file_groups": copied_groups["groups"],
        "copied_usb_files": copied_usb["groups"] or copied_usb["items"],
        "usb_devices": usb.get("usb_storage_devices", usb.get("devices", [])),
        "tool_runs": tool_runs["tools"],
        "issues": issues["issues"],
        "evtx_recovery": evtx["evtx_recovery"],
        "activity_counts": activity["counts"],
    }


def file_dossier_report(
    db: Database,
    case_id: str,
    *,
    path: str | None = None,
    name: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    if not path and not name:
        raise ValueError("Provide path or name for file dossier")
    basename = name or _coalesce_file_name(None, path)
    if not basename:
        raise ValueError("Could not derive a file name from dossier query")

    rows: list[dict[str, Any]] = []
    windows_search_record_ids: set[str] = set()
    windows_search_work_ids: set[str] = set()

    def add_row(
        *,
        category: str,
        source_table: str,
        source_id: str,
        file_name: str | None,
        row_path: str | None,
        timestamp: str | None,
        summary: str,
        details: dict[str, Any] | None = None,
        row_confidence: str | None = None,
    ) -> None:
        if not _dossier_include_row(row_path, path):
            return
        path_matched = _dossier_path_matches(row_path, path)
        rows.append(
            {
                "category": category,
                "source_table": source_table,
                "source_id": source_id,
                "source_type": _dossier_source_type(source_table, category),
                "confidence": _dossier_confidence(source_table, path_matched=path_matched, row_confidence=row_confidence),
                "timestamp": timestamp,
                "file_name": file_name or basename,
                "path": row_path,
                "normalized_path": _normalize_artifact_path(row_path),
                "summary": summary,
                "details": details or {},
            }
        )

    mft_rows = db.conn.execute(
        """
        SELECT id, file_name, parent_path, created_si, modified_si, accessed_si,
               record_changed_si, in_use, is_directory, entry_number, sequence_number
        FROM mft_entries
        WHERE case_id = ? AND file_name = ?
        ORDER BY row_number
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in mft_rows:
        row_path = _join_path(row["parent_path"], row["file_name"])
        for event_type, timestamp in (
            ("MFT created", row["created_si"]),
            ("MFT modified", row["modified_si"]),
            ("MFT accessed", row["accessed_si"]),
            ("MFT record changed", row["record_changed_si"]),
        ):
            if timestamp:
                add_row(
                    category="filesystem",
                    source_table="mft_entries",
                    source_id=row["id"],
                    file_name=row["file_name"],
                    row_path=row_path,
                    timestamp=timestamp,
                    summary=event_type,
                    details={
                        "entry_number": row["entry_number"],
                        "sequence_number": row["sequence_number"],
                        "in_use": row["in_use"],
                        "is_directory": row["is_directory"],
                    },
                )

    fs_rows = db.conn.execute(
        """
        SELECT *
        FROM filesystem_review
        WHERE case_id = ? AND file_name = ?
        ORDER BY COALESCE(event_time, ''), source_table, source_row_number
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in fs_rows:
        add_row(
            category=_dossier_category(row["source_table"]),
            source_table=row["source_table"],
            source_id=row["source_id"],
            file_name=row["file_name"],
            row_path=row["file_path"],
            timestamp=row["event_time"],
            summary=row["event_type"],
            details={
                "status": row["status"],
                "reason": row["reason"],
                "operation": row["operation"],
                "mft_entry_number": row["mft_entry_number"],
                "mft_sequence_number": row["mft_sequence_number"],
                **_json_details(row["details_json"]),
            },
        )

    shortcut_rows = db.conn.execute(
        """
        SELECT id, artifact_type, artifact_name, artifact_path, file_name, file_location,
               target_created, target_modified, target_accessed, device_type,
               volume_serial_number, volume_name, jumplist_item_number
        FROM shortcut_items
        WHERE case_id = ? AND file_name = ?
        ORDER BY COALESCE(target_accessed, target_modified, target_created, '')
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in shortcut_rows:
        add_row(
            category="shortcuts",
            source_table="shortcut_items",
            source_id=row["id"],
            file_name=row["file_name"],
            row_path=row["file_location"],
            timestamp=row["target_accessed"] or row["target_modified"] or row["target_created"],
            summary=f"{row['artifact_type'] or 'shortcut'} reference",
            details={
                "artifact_name": row["artifact_name"],
                "artifact_path": row["artifact_path"],
                "item_number": row["jumplist_item_number"],
                "target_created": row["target_created"],
                "target_modified": row["target_modified"],
                "target_accessed": row["target_accessed"],
                "target_device_type": row["device_type"],
                "volume_serial_number": row["volume_serial_number"],
                "volume_name": row["volume_name"],
            },
        )

    copied_rows = db.conn.execute(
        """
        SELECT *
        FROM copied_file_indicators
        WHERE case_id = ? AND file_name = ?
        ORDER BY created_timestamp_utc, source_artifact_type
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in copied_rows:
        add_row(
            category="copied_indicators",
            source_table="copied_file_indicators",
            source_id=row["id"],
            file_name=row["file_name"],
            row_path=row["file_location"],
            timestamp=row["created_timestamp_utc"],
            summary=row["indicator"],
            row_confidence=row["confidence"],
            details={
                "source_artifact_type": row["source_artifact_type"],
                "source_artifact_name": row["source_artifact_name"],
                "created_timestamp_utc": row["created_timestamp_utc"],
                "modified_timestamp_utc": row["modified_timestamp_utc"],
                "reason": row["reason"],
            },
        )

    search_file_rows = db.conn.execute(
        """
        SELECT *
        FROM windows_search_files
        WHERE case_id = ? AND file_name = ?
        ORDER BY COALESCE(date_accessed, date_modified, gather_time, date_created, '')
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in search_file_rows:
        if row["id"]:
            windows_search_record_ids.add(row["id"])
        if row["work_id"]:
            windows_search_work_ids.add(row["work_id"])
        add_row(
            category="windows_search",
            source_table="windows_search_files",
            source_id=row["id"],
            file_name=row["file_name"],
            row_path=row["item_path"] or row["item_url"],
            timestamp=row["date_accessed"] or row["date_modified"] or row["gather_time"] or row["date_created"],
            summary="Windows Search file record",
            details={
                "work_id": row["work_id"],
                "item_type": row["item_type"],
                "file_extension": row["file_extension"],
                "date_created": row["date_created"],
                "date_modified": row["date_modified"],
                "date_accessed": row["date_accessed"],
                "date_imported": row["date_imported"],
                "size": row["size"],
                "owner": row["owner"],
            },
        )

    if windows_search_record_ids or windows_search_work_ids:
        property_filters: list[str] = []
        params: list[Any] = [case_id]
        if windows_search_record_ids:
            placeholders = ",".join("?" for _ in windows_search_record_ids)
            property_filters.append(f"source_record_id IN ({placeholders})")
            params.extend(sorted(windows_search_record_ids))
        if windows_search_work_ids:
            placeholders = ",".join("?" for _ in windows_search_work_ids)
            property_filters.append(f"work_id IN ({placeholders})")
            params.extend(sorted(windows_search_work_ids))
        params.append(limit * 5)
        property_rows = db.conn.execute(
            f"""
            SELECT *
            FROM windows_search_properties
            WHERE case_id = ? AND ({' OR '.join(property_filters)})
            ORDER BY property_name, timestamp
            LIMIT ?
            """,
            params,
        ).fetchall()
        for row in property_rows:
            translated = _translate_windows_search_property(row["property_name"], row["property_value"])
            add_row(
                category="windows_search",
                source_table="windows_search_properties",
                source_id=row["id"],
                file_name=basename,
                row_path=row["item_path"],
                timestamp=row["timestamp"],
                summary=f"Windows Search property: {row['normalized_name'] or row['property_name']}",
                details={
                    "property_name": row["property_name"],
                    "normalized_name": row["normalized_name"],
                    "property_value": row["property_value"],
                    "translated": translated,
                    "work_id": row["work_id"],
                },
            )

    thumb_rows = db.conn.execute(
        """
        SELECT *
        FROM thumbcache_search_correlations
        WHERE case_id = ? AND search_file_name = ?
        ORDER BY COALESCE(search_date_accessed, search_date_modified, search_date_created, search_date_imported, '')
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in thumb_rows:
        add_row(
            category="thumbcache",
            source_table="thumbcache_search_correlations",
            source_id=row["id"],
            file_name=row["search_file_name"],
            row_path=row["search_item_path"],
            timestamp=row["search_date_accessed"] or row["search_date_modified"] or row["search_date_created"] or row["search_date_imported"],
            summary="Thumbcache to Windows Search path correlation",
            row_confidence=row["confidence"],
            details={
                "cache_id": row["cache_id"],
                "thumbcache_name": row["thumbcache_name"],
                "correlation_basis": row["correlation_basis"],
                "confidence": row["confidence"],
            },
        )

    metadata_rows = db.conn.execute(
        """
        SELECT *
        FROM file_internal_metadata
        WHERE case_id = ? AND file_name = ?
        ORDER BY metadata_group, property_name
        LIMIT ?
        """,
        (case_id, basename, max(limit, 250)),
    ).fetchall()
    for row in metadata_rows:
        add_row(
            category="internal_metadata",
            source_table="file_internal_metadata",
            source_id=row["id"],
            file_name=row["file_name"],
            row_path=row["original_path"] or row["source_file"],
            timestamp=row["mft_modified"] or row["mft_created"] or row["mft_accessed"],
            summary=f"{row['metadata_group'] or row['parser'] or 'metadata'}: {row['property_name']}",
            details={
                "property_name": row["property_name"],
                "property_value": row["property_value"],
                "raw_property_name": row["raw_property_name"],
                "parser": row["parser"],
                "metadata_group": row["metadata_group"],
                "file_size": row["file_size"],
                "extraction_method": row["extraction_method"],
            },
        )

    cloud_rows = db.conn.execute(
        """
        SELECT *
        FROM cloud_sync_artifacts
        WHERE case_id = ? AND file_name = ?
        ORDER BY COALESCE(event_time_utc, '')
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in cloud_rows:
        add_row(
            category="cloud_sync",
            source_table="cloud_sync_artifacts",
            source_id=row["id"],
            file_name=row["file_name"],
            row_path=row["local_path"] or row["cloud_path"] or row["server_path"],
            timestamp=row["event_time_utc"],
            summary=f"{row['provider'] or 'cloud'} {row['artifact_type'] or 'artifact'}",
            details={
                "provider": row["provider"],
                "artifact_type": row["artifact_type"],
                "sync_status": row["sync_status"],
                "event_type": row["event_type"],
                "direction": row["direction"],
                "file_id": row["file_id"],
                "parent_id": row["parent_id"],
                "stable_id": row["stable_id"],
                "is_deleted": row["is_deleted"],
                "mime_type": row["mime_type"],
                "file_size": row["file_size"],
            },
        )

    google_cache_rows = db.conn.execute(
        """
        SELECT *
        FROM google_drive_cache_map
        WHERE case_id = ? AND file_name = ?
        ORDER BY virtual_path, cache_path
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in google_cache_rows:
        add_row(
            category="cloud_sync",
            source_table="google_drive_cache_map",
            source_id=row["id"],
            file_name=row["file_name"],
            row_path=row["virtual_path"],
            timestamp=None,
            summary="Google Drive virtual path to cache mapping",
            details={
                "account_id": row["account_id"],
                "stable_id": row["stable_id"],
                "file_id": row["file_id"],
                "cache_id": row["cache_id"],
                "cache_path": row["cache_path"],
                "windows_cache_path": row["windows_cache_path"],
                "cache_file_size": row["cache_file_size"],
                "mapping_method": row["mapping_method"],
                "evidence_basis": row["evidence_basis"],
            },
        )

    onedrive_rows = db.conn.execute(
        """
        SELECT *
        FROM onedrive_items
        WHERE case_id = ? AND name = ?
        ORDER BY COALESCE(last_change_utc, disk_last_access_utc, disk_creation_utc, delete_time_utc, '')
        LIMIT ?
        """,
        (case_id, basename, limit),
    ).fetchall()
    for row in onedrive_rows:
        add_row(
            category="cloud_sync",
            source_table="onedrive_items",
            source_id=row["id"],
            file_name=row["name"],
            row_path=row["path"],
            timestamp=row["last_change_utc"] or row["disk_last_access_utc"] or row["disk_creation_utc"] or row["delete_time_utc"],
            summary=f"OneDrive {row['record_type'] or row['artifact_type'] or 'item'}",
            details={
                "account": row["account"],
                "artifact_type": row["artifact_type"],
                "record_type": row["record_type"],
                "resource_id": row["resource_id"],
                "parent_resource_id": row["parent_resource_id"],
                "status": row["status"],
                "volume_id": row["volume_id"],
                "size": row["size"],
                "local_hash_digest": row["local_hash_digest"],
                "local_hash_algorithm": row["local_hash_algorithm"],
                "shared_item": row["shared_item"],
                "is_deleted": row["is_deleted"],
                "delete_time_utc": row["delete_time_utc"],
            },
        )

    deduped_rows = _dedupe_dossier_rows(rows)
    sections = _dossier_sections(deduped_rows)
    source_counts: dict[str, int] = {}
    source_type_counts: dict[str, int] = {}
    for row in deduped_rows:
        source_counts[row["source_table"]] = source_counts.get(row["source_table"], 0) + row.get("source_count", 1)
        source_type_counts[row["source_type"]] = source_type_counts.get(row["source_type"], 0) + row.get("source_count", 1)

    evidence = deduped_rows[:limit]
    copied = {
        "case_id": case_id,
        "path_query": path or basename,
        "copied_file_indicators": sections["copied_indicators"],
        "shortcuts": sections["shortcuts"],
        "shellbags": [],
        "mft_entries": [row for row in sections["filesystem"] if row["source_table"] == "mft_entries"],
        "usb_matches": [],
        "counts": {
            "copied_file_indicators": len(sections["copied_indicators"]),
            "shortcuts": len(sections["shortcuts"]),
            "shellbags": 0,
            "mft_entries": len([row for row in sections["filesystem"] if row["source_table"] == "mft_entries"]),
            "usb_matches": 0,
        },
    }
    return {
        "case_id": case_id,
        "filters": {"path": path, "name": name},
        "summary": {
            "queried_file_name": basename,
            "evidence_rows": len(deduped_rows),
            "raw_evidence_rows": len(rows),
            "deduplicated_rows_removed": max(0, len(rows) - len(deduped_rows)),
            "timeline_events": len(sections["filesystem"]),
            "copied_indicators": len(sections["copied_indicators"]),
            "windows_search_hits": len(sections["windows_search"]),
            "mailbox_attachment_hits": 0,
            "web_references": 0,
            "source_counts": [{"source": key, "count": value} for key, value in sorted(source_counts.items())],
            "source_type_counts": [{"source_type": key, "count": value} for key, value in sorted(source_type_counts.items())],
        },
        "identity": {
            "file_name": basename,
            "requested_path": path,
            "normalized_requested_path": _normalize_artifact_path(path),
        },
        "sections": sections,
        "interpretation": _dossier_interpretation(sections),
        "history": sections["filesystem"],
        "evidence": evidence,
        "copied": copied,
        "windows_search_hits": sections["windows_search"],
        "mailbox_attachments": [],
        "web_references": [],
    }


def file_intelligence_report(
    db: Database,
    case_id: str,
    *,
    path: str | None = None,
    name: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    dossier = file_dossier_report(db, case_id, path=path, name=name, limit=limit)
    evidence_rows = list(dossier["evidence"])
    source_counts: dict[str, int] = {}
    timestamped_rows = 0
    for row in evidence_rows:
        source = str(row.get("source_table") or row.get("source") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
        if row.get("timestamp"):
            timestamped_rows += 1
    sections = {
        "filesystem_history": len(dossier["history"]),
        "artifact_evidence": len(evidence_rows),
        "copied_indicators": dossier["summary"].get("copied_indicators", 0),
        "windows_search_hits": len(dossier["windows_search_hits"]),
        "mailbox_attachment_hits": len(dossier["mailbox_attachments"]),
        "web_references": len(dossier["web_references"]),
    }
    return {
        "case_id": case_id,
        "filters": dossier["filters"],
        "summary": {
            **dossier["summary"],
            "sections": sections,
            "source_counts": [{"source": key, "count": value} for key, value in sorted(source_counts.items())],
            "timestamped_evidence_rows": timestamped_rows,
        },
        "timeline": dossier["history"],
        "evidence": evidence_rows,
        "copied": dossier["copied"],
        "windows_search_hits": dossier["windows_search_hits"],
        "mailbox_attachments": dossier["mailbox_attachments"],
        "web_references": dossier["web_references"],
    }


def user_activity_report(
    db: Database,
    case_id: str,
    *,
    user: str,
    limit: int = 100,
) -> dict[str, Any]:
    db.get_case(case_id)
    summary = activity_summary_report(db, case_id, user=user, limit=min(limit, 50))
    communications = communications_report(db, case_id, user=user, limit=min(limit, 50))
    usb_rows = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT *
            FROM usb_file_correlations
            WHERE case_id = ?
              AND (user_profile LIKE ? OR file_location LIKE ? OR source_artifact_path LIKE ?)
            ORDER BY
              CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
              COALESCE(target_modified, target_created, target_accessed, ''),
              COALESCE(file_location, file_name, '')
            LIMIT ?
            """,
            (case_id, f"%{user}%", f"%{user}%", f"%{user}%", min(limit, 50)),
        ).fetchall()
    ]
    return {
        "case_id": case_id,
        "user": user,
        "counts": {
            **summary["counts"],
            "communications": communications["total_returned"],
            "copied_usb_file_hits": len(usb_rows),
        },
        "recent_execution": summary["recent_execution"],
        "recent_file_activity": summary["recent_file_activity"],
        "recent_browser_history": summary["recent_browser_history"],
        "recent_logons": summary["recent_logons"],
        "communications": communications["communications"],
        "browser_activity": {
            "recent_browser_history": summary["recent_browser_history"],
        },
        "copied_usb_files": usb_rows,
    }


EXPECTED_ARTIFACT_TABLES = [
    ("MFT", ["mft_entries"]),
    ("USN Journal", ["usn_journal_entries"]),
    ("NTFS LogFile", ["ntfs_logfile_entries"]),
    ("I30 Directory Indexes", ["ntfs_index_entries", "ntfs_index_bitmaps"]),
    ("Registry", ["registry_hives", "registry_artifacts", "registry_office_trust_records", "registry_taskbar_feature_usage", "registry_taskbar_pins"]),
    ("SAM Accounts", ["sam_accounts"]),
    ("Event Logs", ["evtx_events"]),
    ("SRUM", ["srum_records"]),
    ("SUM / User Access Logging", ["ual_records"]),
    ("Browser History", ["browser_history", "firefox_history", "webcache_entries"]),
    ("Browser Cache And Sessions", ["browser_cache_entries", "browser_session_entries", "browser_site_settings"]),
    ("User Dictionaries", ["user_dictionary_words"]),
    ("Zone.Identifier ADS", ["zone_identifier_ads"]),
    ("Thumbcache", ["thumbcache_entries", "thumbcache_search_correlations"]),
    ("Cloud Sync", ["cloud_sync_artifacts", "google_drive_cache_map", "onedrive_items", "onedrive_log_entries"]),
    ("Email And Messaging", ["mailbox_messages", "mailbox_attachments", "windows_mail_store_rows", "messaging_messages"]),
    ("Prefetch", ["prefetch_items"]),
    ("Recycle Bin", ["recycle_items", "recycle_children"]),
    ("USB Storage", ["usb_devices"]),
    ("Windows Search", ["windows_search_files", "windows_search_indexed_content", "windows_search_gather_logs"]),
    ("WER And Defender", ["windows_error_reports", "windows_defender_events"]),
    ("ETL", ["etl_events"]),
    ("Telemetry Artifacts", ["telemetry_artifacts"]),
]


def _safe_table_count(db: Database, table: str, case_id: str) -> int | None:
    duckdb_count = _safe_duckdb_table_count(db, table, case_id)
    if duckdb_count is not None:
        return duckdb_count
    exists = db.conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if not exists:
        return None
    row = db.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE case_id = ?", (case_id,)).fetchone()
    return int(row["count"] or 0) if row else 0


def _safe_duckdb_table_count(db: Database, table: str, case_id: str) -> int | None:
    db_path = _duckdb_path_for_case(db, case_id)
    if not db_path.exists():
        return None
    conn, should_close = _duckdb_report_connection(db, case_id, db_path)
    try:
        if not _duckdb_table_exists(conn, table):
            return None
        row = conn.execute(f"SELECT COUNT(*) FROM {_quote_identifier(table)} WHERE case_id = ?", [case_id]).fetchone()
        return int(row[0] or 0) if row else 0
    finally:
        if should_close:
            conn.close()


def _expected_artifact_status(db: Database, case_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for artifact_name, tables in EXPECTED_ARTIFACT_TABLES:
        table_counts = []
        total = 0
        for table in tables:
            count = _safe_table_count(db, table, case_id)
            if count is None:
                continue
            total += count
            table_counts.append({"table": table, "row_count": count})
        if not table_counts:
            status = "not_supported"
        elif total > 0:
            status = "parsed"
        else:
            status = "not_populated"
        rows.append(
            {
                "artifact": artifact_name,
                "status": status,
                "row_count": total,
                "tables": table_counts,
            }
        )
    return rows


def _latest_completed_profile_timing(db: Database, case_id: str) -> dict[str, Any] | None:
    row = db.conn.execute(
        """
        SELECT id, name, start_time, end_time, status
        FROM process_timings
        WHERE case_id = ?
          AND scope = 'profile'
          AND phase = 'profile'
          AND status = 'completed'
          AND parent_id IS NULL
        ORDER BY
          CASE WHEN name IN ('windows-full', 'windows-full-evtx') THEN 0 ELSE 1 END,
          COALESCE(end_time, start_time) DESC,
          start_time DESC
        LIMIT 1
        """,
        (case_id,),
    ).fetchone()
    return dict(row) if row else None


def artifact_completeness_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    latest_profile_only: bool = False,
) -> dict[str, Any]:
    db.get_case(case_id)
    latest_profile = _latest_completed_profile_timing(db, case_id) if latest_profile_only else None
    run_start = latest_profile.get("start_time") if latest_profile else None
    output_filter = "WHERE tool_outputs.case_id = ?"
    output_params: list[Any] = [case_id]
    job_filter = "WHERE case_id = ?"
    job_params: list[Any] = [case_id]
    issue_filter = "WHERE case_id = ?"
    issue_params: list[Any] = [case_id]
    artifact_filter = "WHERE case_id = ?"
    artifact_params: list[Any] = [case_id]
    if run_start:
        output_filter += " AND COALESCE(jobs.start_time, tool_outputs.created_at) >= ?"
        output_params.append(run_start)
        job_filter += " AND start_time >= ?"
        job_params.append(run_start)
        issue_filter += " AND created_at >= ?"
        issue_params.append(run_start)
        artifact_filter += " AND created_at >= ?"
        artifact_params.append(run_start)
    tool_rows = [
        dict(row)
        for row in db.conn.execute(
            f"""
            WITH output_counts AS (
              SELECT tool_outputs.tool_name,
                     COUNT(*) AS output_count,
                     COALESCE(SUM(row_count), 0) AS imported_row_count
              FROM tool_outputs
              LEFT JOIN jobs ON jobs.id = tool_outputs.job_id
              {output_filter}
              GROUP BY tool_outputs.tool_name
            ),
            job_counts AS (
              SELECT tool_name,
                     COUNT(*) AS job_count,
                     SUM(CASE WHEN exit_code = 0 THEN 1 ELSE 0 END) AS successful_jobs,
                     SUM(CASE WHEN exit_code IS NULL OR exit_code != 0 THEN 1 ELSE 0 END) AS failed_jobs,
                     MIN(start_time) AS first_started,
                     MAX(end_time) AS last_ended
              FROM jobs
              {job_filter}
              GROUP BY tool_name
            ),
            issue_counts AS (
              SELECT COALESCE(json_extract(details_json, '$.tool_name'), '') AS tool_name,
                     SUM(CASE WHEN level = 'warning' THEN 1 ELSE 0 END) AS warnings,
                     SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END) AS errors,
                     SUM(CASE WHEN event LIKE '%skipped%' OR message LIKE '%skipped%' THEN 1 ELSE 0 END) AS skipped
              FROM activity_log
              {issue_filter}
              GROUP BY COALESCE(json_extract(details_json, '$.tool_name'), '')
            ),
            tools AS (
              SELECT tool_name FROM output_counts
              UNION
              SELECT tool_name FROM job_counts
              UNION
              SELECT tool_name FROM issue_counts WHERE tool_name != ''
            )
            SELECT tools.tool_name,
                   COALESCE(job_counts.job_count, 0) AS job_count,
                   COALESCE(job_counts.successful_jobs, 0) AS successful_jobs,
                   COALESCE(job_counts.failed_jobs, 0) AS failed_jobs,
                   COALESCE(output_counts.output_count, 0) AS output_count,
                   COALESCE(output_counts.imported_row_count, 0) AS imported_row_count,
                   COALESCE(issue_counts.warnings, 0) AS warning_count,
                   COALESCE(issue_counts.errors, 0) AS error_count,
                   COALESCE(issue_counts.skipped, 0) AS skipped_count,
                   job_counts.first_started,
                   job_counts.last_ended
            FROM tools
            LEFT JOIN output_counts ON output_counts.tool_name = tools.tool_name
            LEFT JOIN job_counts ON job_counts.tool_name = tools.tool_name
            LEFT JOIN issue_counts ON issue_counts.tool_name = tools.tool_name
            ORDER BY tools.tool_name
            LIMIT ?
            """,
            (*output_params, *job_params, *issue_params, limit),
        ).fetchall()
    ]
    source_artifacts = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT name, kind, COUNT(*) AS artifact_count
            FROM artifacts
            {artifact_filter}
            GROUP BY name, kind
            ORDER BY name, kind
            LIMIT ?
            """,
            (*artifact_params, limit),
        ).fetchall()
    ]
    skipped = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT event, message, COUNT(*) AS count
            FROM activity_log
            {issue_filter}
              AND (event LIKE '%skipped%' OR message LIKE '%skipped%')
            GROUP BY event, message
            ORDER BY count DESC, event
            LIMIT ?
            """,
            (*issue_params, limit),
        ).fetchall()
    ]
    failed_jobs = [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT id, tool_name, start_time, end_time, exit_code, stderr_path, output_folder
            FROM jobs
            {job_filter} AND (exit_code IS NULL OR exit_code != 0)
            ORDER BY start_time DESC
            LIMIT ?
            """,
            (*job_params, limit),
        ).fetchall()
    ]
    expected_artifacts = _expected_artifact_status(db, case_id)
    summary = {
        "tool_count": len(tool_rows),
        "tools_with_output": sum(1 for row in tool_rows if int(row.get("output_count") or 0) > 0),
        "tools_without_output": sum(1 for row in tool_rows if int(row.get("output_count") or 0) == 0),
        "tools_with_warnings": sum(1 for row in tool_rows if int(row.get("warning_count") or 0) > 0),
        "tools_with_errors": sum(1 for row in tool_rows if int(row.get("error_count") or 0) > 0 or int(row.get("failed_jobs") or 0) > 0),
        "failed_jobs": len(failed_jobs),
        "skipped_issue_groups": len(skipped),
        "source_artifact_groups": len(source_artifacts),
        "expected_artifacts_parsed": sum(1 for row in expected_artifacts if row["status"] == "parsed"),
        "expected_artifacts_not_populated": sum(1 for row in expected_artifacts if row["status"] == "not_populated"),
    }
    return {
        "case_id": case_id,
        "run_scope": {
            "mode": "latest_profile" if latest_profile else "all_history",
            "profile": latest_profile,
        },
        "summary": summary,
        "expected_artifacts": expected_artifacts,
        "tools": tool_rows,
        "source_artifacts": source_artifacts,
        "skipped": skipped,
        "failed_jobs": failed_jobs,
        "evtx_recovery": _evtx_recovery_counts(db, case_id),
    }


def evidence_quality_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    latest_profile_only: bool = False,
) -> dict[str, Any]:
    completeness = artifact_completeness_report(db, case_id, limit=limit, latest_profile_only=latest_profile_only)
    findings: list[dict[str, Any]] = []
    for job in completeness["failed_jobs"]:
        severity = "error" if job.get("exit_code") is not None else "warning"
        findings.append(
            {
                "severity": severity,
                "category": "tool_job",
                "title": f"{job['tool_name']} did not complete cleanly",
                "details": job,
            }
        )
    for skipped in completeness["skipped"]:
        findings.append(
            {
                "severity": "warning",
                "category": "skipped_artifact",
                "title": skipped["message"] or skipped["event"],
                "details": skipped,
            }
        )
    for artifact in completeness["expected_artifacts"]:
        if artifact["status"] == "not_populated":
            findings.append(
                {
                    "severity": "warning",
                    "category": "empty_artifact_family",
                    "title": f"{artifact['artifact']} has no normalized rows",
                    "details": artifact,
                }
            )
    for row in completeness["evtx_recovery"]:
        if row.get("status") in {"partial", "salvaged_partial"}:
            findings.append(
                {
                    "severity": "warning",
                    "category": "event_log_recovery",
                    "title": f"EVTX recovery status: {row['status']}",
                    "details": row,
                }
            )
    findings.extend(registry_timestamp_cluster_findings(db, case_id))
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
    return {
        "case_id": case_id,
        "summary": {
            "finding_count": len(findings),
            "severity_counts": [{"severity": key, "count": value} for key, value in sorted(severity_counts.items())],
            "completeness": completeness["summary"],
        },
        "findings": findings[:limit],
        "completeness": completeness,
        "total_returned": min(len(findings), limit),
    }


def registry_timestamp_cluster_findings(
    db: Database,
    case_id: str,
    *,
    cluster_seconds: int = 60,
    install_alignment_seconds: int = 600,
    min_items: int = 3,
) -> list[dict[str, Any]]:
    db.get_case(case_id)
    findings: list[dict[str, Any]] = []
    install_times = _registry_install_times(db, case_id)
    sam_rows = db.conn.execute(
        """
        SELECT sam_accounts.*, computers.label AS computer_label
        FROM sam_accounts
        LEFT JOIN computers ON sam_accounts.computer_id = computers.id
        WHERE sam_accounts.case_id = ?
          AND COALESCE(sam_accounts.account_key_last_write_utc, '') != ''
        ORDER BY sam_accounts.image_id, sam_accounts.account_key_last_write_utc, sam_accounts.rid
        """,
        (case_id,),
    ).fetchall()
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in sam_rows:
        groups.setdefault((row["computer_id"], row["image_id"]), []).append(dict(row))
    for (computer_id, image_id), rows in groups.items():
        clusters = _close_timestamp_clusters(
            rows,
            timestamp_field="account_key_last_write_utc",
            label_field="username",
            cluster_seconds=cluster_seconds,
            min_items=min_items,
        )
        for cluster in clusters:
            nearest = _nearest_install_time(
                install_times,
                image_id=image_id,
                timestamp=cluster["start_time_utc"],
                max_seconds=install_alignment_seconds,
            )
            if nearest is None:
                title = "SAM account key timestamps are clustered"
                explanation = (
                    "Multiple SAM account name keys have the same or very close last-write timestamps. "
                    "Treat these account creation-style timestamps cautiously and corroborate with other artifacts."
                )
                severity = "warning"
            else:
                title = "SAM account key timestamp cluster aligns with Windows install or upgrade metadata"
                explanation = (
                    "Multiple SAM account name keys have very close last-write timestamps and the cluster is near "
                    "Windows install/SourceOS metadata. This pattern can occur after Windows update/upgrade activity, "
                    "so these registry timestamps should not be treated as precise account creation times."
                )
                severity = "warning"
            findings.append(
                {
                    "severity": severity,
                    "category": "registry_timestamp_cluster",
                    "title": title,
                    "details": {
                        "source_table": "sam_accounts",
                        "computer_id": computer_id,
                        "computer_label": rows[0].get("computer_label"),
                        "image_id": image_id,
                        "timestamp_field": "account_key_last_write_utc",
                        "cluster_window_seconds": cluster_seconds,
                        "install_alignment_window_seconds": install_alignment_seconds,
                        "start_time_utc": cluster["start_time_utc"],
                        "end_time_utc": cluster["end_time_utc"],
                        "item_count": cluster["item_count"],
                        "items": cluster["items"],
                        "nearest_install_time": nearest,
                        "explanation": explanation,
                    },
                }
            )
    findings.extend(
        _registry_artifact_timestamp_cluster_findings(
            db,
            case_id,
            install_times=install_times,
            cluster_seconds=cluster_seconds,
            install_alignment_seconds=install_alignment_seconds,
            min_items=min_items,
        )
    )
    return findings


REGISTRY_CLUSTER_ARTIFACTS = {
    "autostart",
    "bam",
    "dam",
    "common_dialog",
    "connected_networks",
    "office_recent_docs",
    "office_trusted_documents",
    "office_trusted_locations",
    "recentdocs",
    "runmru",
    "shellbags",
    "taskbar_feature_usage",
    "taskbar_usage",
    "typed_paths",
    "userassist",
    "wordwheel_query",
}


def _registry_artifact_timestamp_cluster_findings(
    db: Database,
    case_id: str,
    *,
    install_times: list[dict[str, Any]],
    cluster_seconds: int,
    install_alignment_seconds: int,
    min_items: int,
) -> list[dict[str, Any]]:
    placeholders = ", ".join("?" for _ in REGISTRY_CLUSTER_ARTIFACTS)
    rows = db.conn.execute(
        f"""
        SELECT registry_artifacts.*, computers.label AS computer_label
        FROM registry_artifacts
        LEFT JOIN computers ON registry_artifacts.computer_id = computers.id
        WHERE registry_artifacts.case_id = ?
          AND registry_artifacts.artifact IN ({placeholders})
          AND COALESCE(registry_artifacts.key_last_write_utc, registry_artifacts.event_time_utc, '') != ''
        ORDER BY registry_artifacts.image_id, registry_artifacts.artifact,
                 COALESCE(registry_artifacts.key_last_write_utc, registry_artifacts.event_time_utc),
                 registry_artifacts.key_path, registry_artifacts.value_name
        """,
        [case_id, *sorted(REGISTRY_CLUSTER_ARTIFACTS)],
    ).fetchall()
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in rows:
        item = dict(row)
        item["cluster_timestamp_utc"] = item.get("key_last_write_utc") or item.get("event_time_utc")
        grouped.setdefault((item["computer_id"], item["image_id"], item["artifact"]), []).append(item)
    findings: list[dict[str, Any]] = []
    for (computer_id, image_id, artifact), artifact_rows in grouped.items():
        clusters = _close_timestamp_clusters(
            artifact_rows,
            timestamp_field="cluster_timestamp_utc",
            label_field="value_name",
            cluster_seconds=cluster_seconds,
            min_items=min_items,
        )
        for cluster in clusters:
            nearest = _nearest_install_time(
                install_times,
                image_id=image_id,
                timestamp=cluster["start_time_utc"],
                max_seconds=install_alignment_seconds,
            )
            if nearest is None:
                title = f"{artifact} registry timestamps are clustered"
                explanation = (
                    "Multiple commonly analyzed registry values or keys have the same or very close timestamps. "
                    "Treat the clustered timestamps cautiously and corroborate with independent artifacts."
                )
            else:
                title = f"{artifact} registry timestamp cluster aligns with Windows install or upgrade metadata"
                explanation = (
                    "Multiple commonly analyzed registry values or keys have very close timestamps and the cluster is near "
                    "Windows install/SourceOS metadata. This may indicate update/upgrade-related timestamp churn rather than "
                    "individual user activity at that exact time."
                )
            findings.append(
                {
                    "severity": "warning",
                    "category": "registry_timestamp_cluster",
                    "title": title,
                    "details": {
                        "source_table": "registry_artifacts",
                        "artifact": artifact,
                        "computer_id": computer_id,
                        "computer_label": artifact_rows[0].get("computer_label"),
                        "image_id": image_id,
                        "timestamp_field": "key_last_write_utc_or_event_time_utc",
                        "cluster_window_seconds": cluster_seconds,
                        "install_alignment_window_seconds": install_alignment_seconds,
                        "start_time_utc": cluster["start_time_utc"],
                        "end_time_utc": cluster["end_time_utc"],
                        "item_count": cluster["item_count"],
                        "items": cluster["items"],
                        "nearest_install_time": nearest,
                        "explanation": explanation,
                    },
                }
            )
    return findings


def _close_timestamp_clusters(
    rows: list[dict[str, Any]],
    *,
    timestamp_field: str,
    label_field: str,
    cluster_seconds: int,
    min_items: int,
) -> list[dict[str, Any]]:
    parsed_rows = []
    for row in rows:
        parsed = parse_timestamp(row.get(timestamp_field))
        if parsed is not None:
            parsed_rows.append((parsed, row))
    parsed_rows.sort(key=lambda item: item[0])
    clusters: list[dict[str, Any]] = []
    consumed: set[int] = set()
    for index, (start, _) in enumerate(parsed_rows):
        if index in consumed:
            continue
        window = [
            (candidate_index, timestamp, row)
            for candidate_index, (timestamp, row) in enumerate(parsed_rows[index:], start=index)
            if timestamp - start <= timedelta(seconds=cluster_seconds)
        ]
        if len(window) < min_items:
            continue
        for candidate_index, _, _ in window:
            consumed.add(candidate_index)
        end = max(timestamp for _, timestamp, _ in window)
        clusters.append(
            {
                "start_time_utc": start.isoformat().replace("+00:00", "Z"),
                "end_time_utc": end.isoformat().replace("+00:00", "Z"),
                "item_count": len(window),
                "items": [
                    {
                        "label": row.get(label_field),
                        "timestamp_utc": row.get(timestamp_field),
                        "rid": row.get("rid"),
                        "registry_path": row.get("registry_path"),
                        "artifact": row.get("artifact"),
                        "key_path": row.get("key_path"),
                        "value_name": row.get("value_name"),
                        "value_data": row.get("value_data"),
                    }
                    for _, _, row in window
                ],
            }
        )
    return clusters


def _registry_install_times(db: Database, case_id: str) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT image_id, computer_id, artifact, key_path, key_last_write_utc,
               event_time_utc, value_name, value_data, notes
        FROM registry_artifacts
        WHERE case_id = ?
          AND artifact IN ('install_time_software', 'install_time_source_os')
        """,
        (case_id,),
    ).fetchall()
    install_times: list[dict[str, Any]] = []
    for row in rows:
        values = [
            ("event_time_utc", row["event_time_utc"]),
            ("key_last_write_utc", row["key_last_write_utc"]),
            ("value_data", row["value_data"]),
        ]
        for match in _ISO_TIMESTAMP_RE.findall(row["notes"] or ""):
            values.append(("notes", match))
        for source_field, value in values:
            parsed = parse_timestamp(value)
            if parsed is None:
                continue
            install_times.append(
                {
                    "image_id": row["image_id"],
                    "computer_id": row["computer_id"],
                    "artifact": row["artifact"],
                    "key_path": row["key_path"],
                    "value_name": row["value_name"],
                    "source_field": source_field,
                    "timestamp_utc": parsed.isoformat().replace("+00:00", "Z"),
                }
            )
    return install_times


_ISO_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")


def _nearest_install_time(
    install_times: list[dict[str, Any]],
    *,
    image_id: str,
    timestamp: str,
    max_seconds: int,
) -> dict[str, Any] | None:
    parsed = parse_timestamp(timestamp)
    if parsed is None:
        return None
    best: tuple[float, dict[str, Any]] | None = None
    for row in install_times:
        if row["image_id"] != image_id:
            continue
        install_dt = parse_timestamp(row.get("timestamp_utc"))
        if install_dt is None:
            continue
        delta = abs((parsed - install_dt).total_seconds())
        if delta <= max_seconds and (best is None or delta < best[0]):
            best = (delta, row)
    if best is None:
        return None
    return {**best[1], "delta_seconds": int(best[0])}


def copied_file_drilldown_report(db: Database, case_id: str, *, path: str, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    like = f"%{path}%"
    copied_rows = _rows_with_details(
        db.conn.execute(
            """
            SELECT copied_file_indicators.*, computers.label AS computer_label, images.path AS image_path
            FROM copied_file_indicators
            LEFT JOIN computers ON copied_file_indicators.computer_id = computers.id
            LEFT JOIN images ON copied_file_indicators.image_id = images.id
            WHERE copied_file_indicators.case_id = ?
              AND (copied_file_indicators.file_location LIKE ? OR copied_file_indicators.file_name LIKE ?)
            ORDER BY copied_file_indicators.created_timestamp_utc, copied_file_indicators.source_artifact_type
            LIMIT ?
            """,
            (case_id, like, like, limit),
        ).fetchall()
    )
    shortcuts = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT shortcut_items.*, computers.label AS computer_label, images.path AS image_path
            FROM shortcut_items
            LEFT JOIN computers ON shortcut_items.computer_id = computers.id
            LEFT JOIN images ON shortcut_items.image_id = images.id
            WHERE shortcut_items.case_id = ?
              AND (shortcut_items.file_location LIKE ? OR shortcut_items.file_name LIKE ? OR shortcut_items.artifact_path LIKE ?)
            ORDER BY shortcut_items.artifact_type, shortcut_items.artifact_path
            LIMIT ?
            """,
            (case_id, like, like, like, limit),
        ).fetchall()
    ]
    shellbags = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT shellbag_entries.*, computers.label AS computer_label, images.path AS image_path
            FROM shellbag_entries
            LEFT JOIN computers ON shellbag_entries.computer_id = computers.id
            LEFT JOIN images ON shellbag_entries.image_id = images.id
            WHERE shellbag_entries.case_id = ?
              AND shellbag_entries.absolute_path LIKE ?
            ORDER BY shellbag_entries.user_profile, shellbag_entries.absolute_path
            LIMIT ?
            """,
            (case_id, like, limit),
        ).fetchall()
    ]
    mft = [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT mft_entries.*, computers.label AS computer_label, images.path AS image_path
            FROM mft_entries
            LEFT JOIN computers ON mft_entries.computer_id = computers.id
            LEFT JOIN images ON mft_entries.image_id = images.id
            WHERE mft_entries.case_id = ?
              AND ((mft_entries.parent_path || '/' || mft_entries.file_name) LIKE ? OR mft_entries.file_name LIKE ?)
            ORDER BY mft_entries.row_number
            LIMIT ?
            """,
            (case_id, like, like, limit),
        ).fetchall()
    ]
    usb_rows = _copied_usb_for_path(db, case_id, path=path, limit=limit)
    return {
        "case_id": case_id,
        "path_query": path,
        "copied_file_indicators": copied_rows,
        "shortcuts": shortcuts,
        "shellbags": shellbags,
        "mft_entries": mft,
        "usb_matches": usb_rows,
        "counts": {
            "copied_file_indicators": len(copied_rows),
            "shortcuts": len(shortcuts),
            "shellbags": len(shellbags),
            "mft_entries": len(mft),
            "usb_matches": len(usb_rows),
        },
    }


def usb_dossier_report(
    db: Database,
    case_id: str,
    *,
    serial: str | None = None,
    volume_serial_number: str | None = None,
    volume_guid: str | None = None,
    limit: int = 250,
) -> dict[str, Any]:
    verbose = usb_verbose_report(
        db,
        case_id,
        serial=serial,
        volume_serial_number=volume_serial_number,
        volume_guid=volume_guid,
        limit=limit,
    )
    device = verbose["device"]
    copied = copied_usb_files_report(db, case_id, limit=limit, grouped=True)
    copied_items = [
        item for item in copied["items"]
        if item.get("usb_serial") == device.get("serial")
        or _norm_vsn(item.get("usb_volume_serial_number")) == _norm_vsn(device.get("volume_serial_number"))
    ]
    copied_groups = _group_copied_usb_rows(copied_items)
    timeline = usb_timeline_report(db, case_id, limit=limit)
    device_timeline = [
        event for event in timeline["events"]
        if event.get("usb_serial") == device.get("serial")
        or _norm_vsn(event.get("usb_volume_serial_number")) == _norm_vsn(device.get("volume_serial_number"))
    ]
    return {
        "case_id": case_id,
        "device": device,
        "description_attributes": verbose["description_attributes"],
        "connection_times": verbose["connection_times"],
        "volume_attributes": verbose["volume_attributes"],
        "mbr_vbr_details": verbose["mbr_vbr_details"],
        "copied_files": copied_groups,
        "file_activity": verbose["files_opened_accessed"],
        "timeline": device_timeline,
        "raw_evidence_counts": verbose["raw_evidence_counts"],
        "raw_evidence_rows": verbose["raw_evidence_rows"],
        "totals": {
            "copied_file_groups": len(copied_groups),
            "file_activity_rows": len(verbose["files_opened_accessed"]),
            "timeline_events": len(device_timeline),
            "raw_evidence_rows": len(verbose["raw_evidence_rows"]),
        },
    }


def device_inventory_report(db: Database, case_id: str, *, limit: int = 250) -> dict[str, Any]:
    db.get_case(case_id)
    rows = _query_report_rows(
        db,
        case_id,
        "usb_devices",
        """
        SELECT
          computer_id,
          image_id,
          COALESCE(NULLIF(device_type, ''), NULLIF(artifact, ''), '(unknown)') AS device_type,
          COALESCE(NULLIF(serial, ''), NULLIF(instance_id, ''), NULLIF(parent_id_prefix, ''), '(unknown)') AS device_identifier,
          vendor_id,
          product_id,
          vendor,
          product,
          revision,
          friendly_name,
          serial,
          instance_id,
          parent_id_prefix,
          device_service,
          user_profile,
          drive_letter,
          volume_guid,
          volume_serial_number,
          volume_name,
          MIN(COALESCE(NULLIF(last_present_date_utc, ''), NULLIF(key_last_write_utc, ''))) AS first_observed_utc,
          MAX(COALESCE(NULLIF(last_present_date_utc, ''), NULLIF(key_last_write_utc, ''))) AS last_observed_utc,
          COUNT(*) AS evidence_row_count,
          GROUP_CONCAT(DISTINCT artifact) AS source_artifacts,
          GROUP_CONCAT(DISTINCT source_path) AS source_paths
        FROM usb_devices
        WHERE case_id = ?
        GROUP BY
          computer_id,
          image_id,
          device_type,
          device_identifier,
          vendor_id,
          product_id,
          vendor,
          product,
          revision,
          friendly_name,
          serial,
          instance_id,
          parent_id_prefix,
          device_service,
          user_profile,
          drive_letter,
          volume_guid,
          volume_serial_number,
          volume_name
        ORDER BY evidence_row_count DESC, last_observed_utc DESC, device_type, device_identifier
        LIMIT ?
        """,
        (case_id, limit),
    )
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get("device_type") or "(unknown)")
        counts[key] = counts.get(key, 0) + 1
    return {
        "case_id": case_id,
        "summary": {
            "device_type_counts": [
                {"device_type": key, "count": value}
                for key, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            ],
            "interpretation_note": "This is a broad device inventory from parsed USB/device registry artefacts; storage-specific copy/open activity remains in the USB dossier reports.",
        },
        "devices": rows,
        "total_returned": len(rows),
    }


def _copied_indicator_filter_sql(
    *,
    case_id: str,
    exclude_system: bool,
    include_mft_only: bool,
) -> tuple[list[str], list[Any]]:
    filters = ["case_id = ?"]
    params: list[Any] = [case_id]
    if not include_mft_only:
        filters.append("source_artifact_type NOT IN ('mft_si', 'mft_fn')")
    if exclude_system:
        filters.append(
            """
            file_location NOT LIKE '.\\Windows\\%'
            AND file_location NOT LIKE '.\\Windows/%'
            AND file_location NOT LIKE '.\\Program Files%'
            AND file_location NOT LIKE '.\\ProgramData%'
            AND file_location NOT LIKE 'C:\\Windows\\%'
            AND file_location NOT LIKE 'C:\\Windows/%'
            AND file_location NOT LIKE 'C:\\Program Files%'
            AND file_location NOT LIKE '%/Windows/%'
            AND file_location NOT LIKE '%/Program Files%'
            AND file_location NOT LIKE '%/ProgramData/%'
            """
        )
    return filters, params


def _count_default_copied_indicators(db: Database, case_id: str) -> int:
    filters, params = _copied_indicator_filter_sql(
        case_id=case_id,
        exclude_system=True,
        include_mft_only=False,
    )
    return int(
        db.conn.execute(
            f"SELECT COUNT(*) AS count FROM copied_file_indicators WHERE {' AND '.join(filters)}",
            params,
        ).fetchone()["count"]
    )


def _dossier_source_type(source_table: str | None, category: str | None = None) -> str:
    table = source_table or ""
    if table in {
        "mft_entries",
        "usn_journal_entries",
        "ntfs_logfile_entries",
        "ntfs_index_entries",
        "ntfs_namespace_reconciliation",
        "filesystem_review",
        "recycle_items",
        "recycle_children",
        "zone_identifier_ads",
    }:
        return "filesystem"
    if table in {"shortcut_items", "windows_activities", "browser_downloads", "webcache_file_accesses"}:
        return "user activity"
    if table in {"file_internal_metadata", "copied_file_indicators"}:
        return "app metadata" if table == "file_internal_metadata" else "derived indicator"
    if table in {"cloud_sync_artifacts", "google_drive_cache_map", "onedrive_items"}:
        return "cloud sync"
    if table in {"windows_search_files", "windows_search_indexed_content", "windows_search_properties"}:
        return "Search index"
    if table in {"thumbcache_search_correlations", "thumbcache_entries"}:
        return "thumbnail cache"
    if category:
        return category
    return "unknown"


def _dossier_category(source_table: str | None) -> str:
    table = source_table or ""
    if table in {"mft_entries", "usn_journal_entries", "ntfs_logfile_entries", "ntfs_index_entries", "ntfs_namespace_reconciliation", "filesystem_review", "recycle_items", "recycle_children", "zone_identifier_ads"}:
        return "filesystem"
    if table in {"shortcut_items"}:
        return "shortcuts"
    if table in {"windows_activities", "browser_downloads", "webcache_file_accesses"}:
        return "user_activity"
    if table in {"windows_search_files", "windows_search_indexed_content", "windows_search_properties"}:
        return "windows_search"
    if table in {"thumbcache_search_correlations", "thumbcache_entries"}:
        return "thumbcache"
    if table in {"file_internal_metadata"}:
        return "internal_metadata"
    if table in {"cloud_sync_artifacts", "google_drive_cache_map", "onedrive_items"}:
        return "cloud_sync"
    if table in {"copied_file_indicators"}:
        return "copied_indicators"
    return "filesystem"


def _dossier_confidence(source_table: str | None, *, path_matched: bool = False, row_confidence: str | None = None) -> str:
    if row_confidence:
        text = str(row_confidence).lower()
        if text in {"high", "medium", "low"}:
            return text
    if path_matched:
        return "high"
    if source_table in {"mft_entries", "filesystem_review", "windows_search_files", "file_internal_metadata"}:
        return "high"
    if source_table in {"shortcut_items", "windows_activities", "thumbcache_search_correlations", "copied_file_indicators"}:
        return "medium"
    return "medium"


def _decode_hex_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or len(text) % 2:
        return None
    if not re.fullmatch(r"[0-9A-Fa-f]+", text):
        return None
    try:
        decoded = bytes.fromhex(text).decode("utf-8", errors="ignore").strip("\x00\r\n\t ")
    except ValueError:
        return None
    return decoded or None


def _translate_windows_search_property(property_name: str | None, value: Any) -> dict[str, Any]:
    name = str(property_name or "")
    raw = "" if value is None else str(value)
    if name.endswith("System_FilePlaceholderStatus") or name == "System_FilePlaceholderStatus":
        labels = {
            "0": "not reported or normal file state",
            "1": "placeholder-related state",
            "2": "placeholder-related state",
            "4": "placeholder-related state",
            "6": "cloud placeholder or hydrated-placeholder state",
        }
        return {
            "raw": raw,
            "translated": labels.get(raw, f"placeholder status {raw}"),
            "note": "Windows Search provider-specific placeholder status; use with cloud sync artifacts for final interpretation.",
        }
    if name.endswith("System_Kind") or name == "System_Kind":
        decoded = _decode_hex_text(raw)
        return {"raw": raw, "translated": decoded or raw}
    lowered = raw.lower()
    if lowered in {"true", "false"}:
        return {"raw": raw, "translated": lowered == "true"}
    return {"raw": raw, "translated": raw}


def _dossier_path_matches(row_path: str | None, requested_path: str | None) -> bool:
    if not requested_path:
        return False
    normalized_row = _normalize_artifact_path(row_path)
    normalized_requested = _normalize_artifact_path(requested_path)
    if not normalized_row or not normalized_requested:
        return False
    return normalized_row == normalized_requested or normalized_requested in normalized_row


def _dossier_include_row(row_path: str | None, requested_path: str | None) -> bool:
    if not requested_path:
        return True
    return _dossier_path_matches(row_path, requested_path)


def _dedupe_dossier_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.get("category"),
            row.get("source_table"),
            row.get("timestamp"),
            _normalize_artifact_path(row.get("path")),
            row.get("summary"),
            json.dumps(row.get("details") or {}, sort_keys=True, default=str),
        )
        item = grouped.get(key)
        if item is None:
            item = dict(row)
            item["source_count"] = 1
            item["source_ids"] = [row.get("source_id")]
            item["sources"] = [row.get("source_table")]
            grouped[key] = item
            continue
        item["source_count"] += 1
        if row.get("source_id") not in item["source_ids"]:
            item["source_ids"].append(row.get("source_id"))
        if row.get("source_table") not in item["sources"]:
            item["sources"].append(row.get("source_table"))
    return sorted(
        grouped.values(),
        key=lambda item: (item.get("category") or "", _timestamp_sort_key(item.get("timestamp")), item.get("summary") or ""),
    )


def _dossier_sections(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    sections = {
        "filesystem": [],
        "user_activity": [],
        "shortcuts": [],
        "windows_search": [],
        "thumbcache": [],
        "internal_metadata": [],
        "cloud_sync": [],
        "copied_indicators": [],
    }
    for row in rows:
        category = row.get("category")
        if category in sections:
            sections[category].append(row)
    return sections


def _dossier_interpretation(sections: dict[str, list[dict[str, Any]]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if sections.get("copied_indicators"):
        findings.append(
            {
                "rule": "copied_timestamp_pattern",
                "interpretation": "One or more artifacts show file creation after file modification, which is consistent with a copied or imported file.",
            }
        )
    if sections.get("shortcuts") or sections.get("user_activity"):
        findings.append(
            {
                "rule": "user_interaction_artifacts",
                "interpretation": "Shortcut, Jump List, activity, browser, or WebCache evidence indicates user-level interaction with this file name or path.",
            }
        )
    if sections.get("thumbcache"):
        findings.append(
            {
                "rule": "thumbnail_cache_correlation",
                "interpretation": "Thumbcache evidence correlated with Windows Search indicates Explorer or shell thumbnail activity for this item.",
            }
        )
    if any(
        row.get("details", {}).get("property_name", "").endswith("System_FilePlaceholderStatus")
        for row in sections.get("windows_search", [])
    ):
        findings.append(
            {
                "rule": "cloud_placeholder_status",
                "interpretation": "Windows Search recorded placeholder-state metadata. Correlate with cloud sync rows before deciding whether file content was fully local.",
            }
        )
    if sections.get("internal_metadata"):
        findings.append(
            {
                "rule": "internal_metadata_available",
                "interpretation": "Internal file metadata is available and may describe document authorship, application, revision, or embedded timestamps.",
            }
        )
    if not findings:
        findings.append(
            {
                "rule": "limited_correlated_evidence",
                "interpretation": "The indexed dossier sources contain limited correlated evidence for this file query.",
            }
        )
    return findings


def _coalesce_file_name(file_name: str | None, path: str | None) -> str | None:
    if file_name and str(file_name).strip():
        return str(file_name).strip()
    if not path:
        return None
    text = str(path).strip()
    if not text:
        return None
    parsed = urlparse(text)
    if parsed.scheme:
        text = unquote(parsed.path or parsed.netloc or text)
    text = text.split("?", 1)[0].split("#", 1)[0].rstrip("\\/")
    if not text:
        return None
    return re.split(r"[\\/]", text)[-1] or None


def _normalize_artifact_path(path: str | None) -> str | None:
    if not path:
        return None
    text = unquote(str(path).strip())
    if not text:
        return None
    if text.lower().startswith("file:"):
        parsed = urlparse(text)
        text = parsed.path or text
        if re.match(r"^/[a-zA-Z]:/", text):
            text = text[1:]
    else:
        parsed = urlparse(text)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{unquote(parsed.path)}".rstrip("/").lower()
    text = text.replace("/", "\\")
    text = re.sub(r"^\\\\\?\\", "", text)
    text = re.sub(r"^\.[\\]+", "", text)
    text = re.sub(r"^[a-zA-Z]:\\", "", text)
    text = re.sub(r"\\+", r"\\", text).strip("\\")
    return text.lower() or None


def _file_evidence_tags(
    *,
    source: str,
    source_table: str,
    path: str | None,
    detail: dict[str, Any] | None,
) -> list[str]:
    tags = {"same_filename"}
    if _normalize_artifact_path(path):
        tags.add("same_normalized_path_available")
    if source.startswith("copied:"):
        tags.add("copied_timestamp_pattern")
    if source_table == "windows_search_indexed_content":
        tags.add("indexed_content_present")
    if source_table == "windows_search_files":
        tags.add("windows_search_file_present")
    if source_table == "browser_downloads":
        tags.add("browser_download_present")
    if source_table == "windows_activities":
        tags.add("activity_cache_present")
    if source_table == "webcache_file_accesses":
        tags.add("webcache_file_access_present")
    if source_table == "usn_journal_entries":
        tags.add("usn_change_present")
    if source_table == "file_internal_metadata":
        tags.add("internal_metadata_present")
    if source_table == "mft_entries":
        tags.add("mft_entry_present")
    if source_table == "shortcut_items":
        tags.add("shortcut_artifact_present")
    if detail and detail.get("content_length"):
        tags.add("indexed_text_present")
    return sorted(tags)


def _group_evidence_tags(item: dict[str, Any]) -> list[str]:
    tags = {"same_filename"}
    sources = set(item.get("sources") or [])
    tables = set(item.get("source_tables") or [])
    if item.get("normalized_paths"):
        tags.add("same_normalized_path_available")
    if any(str(source).startswith("copied:") for source in sources):
        tags.add("copied_timestamp_pattern")
    if "windows_search_indexed_content" in tables:
        tags.add("indexed_content_present")
    if "browser_downloads" in tables:
        tags.add("browser_download_present")
    if "windows_activities" in tables:
        tags.add("activity_cache_present")
    if "webcache_file_accesses" in tables:
        tags.add("webcache_file_access_present")
    if "usn_journal_entries" in tables:
        tags.add("usn_change_present")
    if "file_internal_metadata" in tables:
        tags.add("internal_metadata_present")
    if "mft_entries" in tables:
        tags.add("mft_entry_present")
    if "shortcut_items" in tables:
        tags.add("shortcut_artifact_present")
    return sorted(tags)


def _merge_time_bounds(group: dict[str, Any], timestamp: str | None) -> None:
    if not timestamp:
        return
    if group.get("first_seen_utc") is None or timestamp < group["first_seen_utc"]:
        group["first_seen_utc"] = timestamp
    if group.get("last_seen_utc") is None or timestamp > group["last_seen_utc"]:
        group["last_seen_utc"] = timestamp


def _user_from_path(path: str | None) -> str | None:
    if not path:
        return None
    text = unquote(str(path)).replace("/", "\\")
    match = re.search(r"(?:^|\\)Users\\([^\\]+)", text, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _join_path(parent: str | None, name: str | None) -> str | None:
    if not parent and not name:
        return None
    if not parent:
        return name
    if not name:
        return parent
    normalized_parent = str(parent).rstrip("/\\")
    return f"{normalized_parent}/{name}"


def _email_dedupe_key(row: dict[str, Any]) -> str:
    subject = str(row.get("name") or "").strip().lower()
    email = str(row.get("email") or "").strip().lower()
    timestamp = str(row.get("timestamp") or "")[:19]
    path = _normalize_artifact_path(str(row.get("path") or ""))
    return "|".join([subject, email, timestamp, path or ""])


def _content_key(content: str | None, fallback: str | None = None) -> str:
    basis = (content or "").strip()
    if not basis:
        basis = fallback or ""
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()


def _looks_like_encoded_fragment(value: str | None) -> bool:
    raw = str(value or "").strip()
    text = re.sub(r"\s+", "", raw)
    if len(text) < 80:
        return False
    tokens = raw.split()
    if tokens:
        longest = max(len(token) for token in tokens)
        natural_words = [
            token
            for token in tokens
            if re.search(r"[aeiou]", token, flags=re.IGNORECASE)
            and re.fullmatch(r"[A-Za-z][A-Za-z'-]{2,}", token)
        ]
        if longest >= 120 and len(natural_words) <= 3:
            return True
    encoded_chars = sum(1 for char in text if char.isalnum() or char in "+/=%_-")
    encoded_ratio = encoded_chars / max(len(text), 1)
    has_markup = "<" in text and ">" in text
    has_sentence_spacing = " " in str(value or "").strip()[:500]
    return encoded_ratio > 0.90 and not has_markup and not has_sentence_spacing


def _text_preview(value: str | None, *, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _communication_preview(value: str | None, *, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    tokens = text.split()
    while tokens and (len(tokens[0]) > 80 or _looks_like_html_attribute_noise(tokens[0])):
        tokens.pop(0)
    text = " ".join(tokens)
    text = re.sub(r"\b(?:originalsrc|target|rel|shash|data-[A-Za-z0-9_-]+)=\"[^\"]*\"", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(unquote(text))
    text = re.sub(r"^[>\s]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return _text_preview(text, limit=limit)


def _looks_like_html_attribute_noise(token: str) -> bool:
    lowered = token.lower()
    return (
        "=" in lowered
        and any(prefix in lowered for prefix in ("http", "data=", "target=", "rel=", "shash=", "originalsrc="))
    )


def _communication_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("communication_key") or "")
        if not key:
            continue
        group = grouped.setdefault(
            key,
            {
                "communication_key": key,
                "count": 0,
                "source_types": set(),
                "users": set(),
                "first_seen": None,
                "last_seen": None,
                "titles": set(),
                "source_ids": [],
            },
        )
        group["count"] += 1
        if row.get("source_type"):
            group["source_types"].add(row["source_type"])
        if row.get("user_profile"):
            group["users"].add(row["user_profile"])
        if row.get("title"):
            group["titles"].add(row["title"])
        if row.get("source_id"):
            group["source_ids"].append(row["source_id"])
        timestamp = row.get("timestamp")
        if timestamp:
            if group["first_seen"] is None or str(timestamp) < str(group["first_seen"]):
                group["first_seen"] = timestamp
            if group["last_seen"] is None or str(timestamp) > str(group["last_seen"]):
                group["last_seen"] = timestamp
    output = []
    for group in grouped.values():
        item = dict(group)
        item["source_types"] = sorted(item["source_types"])
        item["users"] = sorted(item["users"])
        item["titles"] = sorted(item["titles"])[:5]
        output.append(item)
    output.sort(key=lambda item: (-int(item["count"]), str(item.get("last_seen") or "")), reverse=False)
    return output


def _conversation_key(subject: str | None) -> str:
    cleaned = _clean_subject(subject).lower()
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return hashlib.sha256(cleaned.encode("utf-8", errors="replace")).hexdigest() if cleaned else "no-subject"


def _clean_subject(subject: str | None) -> str:
    text = str(subject or "").strip()
    while True:
        updated = re.sub(r"^\s*(?:re|fw|fwd)\s*:\s*", "", text, flags=re.IGNORECASE)
        if updated == text:
            return text
        text = updated


def _set_min_max_time(group: dict[str, Any], timestamp: Any) -> None:
    if not timestamp:
        return
    value = str(timestamp)
    if group.get("first_seen") is None or value < str(group.get("first_seen")):
        group["first_seen"] = value
    if group.get("last_seen") is None or value > str(group.get("last_seen")):
        group["last_seen"] = value


def _set_add(values: set[Any], value: Any) -> None:
    text = str(value or "").strip()
    if text:
        values.add(text)


def _finalize_set_group(group: dict[str, Any], set_keys: list[str]) -> dict[str, Any]:
    output = dict(group)
    for key in set_keys:
        output[key] = sorted(output.get(key) or [])
    if "source_ids" in output:
        output["source_ids"] = list(output["source_ids"])[:25]
    return output


def _split_parties(value: str | None) -> list[str]:
    text = str(value or "")
    if not text.strip():
        return []
    parts = re.split(r";|,\s+(?=[^<>]*(?:<|$))", text)
    return [part.strip() for part in parts if part.strip()]


def _normalize_party(value: str | None) -> str:
    text = str(value or "").strip()
    match = re.search(r"<([^<>@\s]+@[^<>\s]+)>", text)
    if match:
        return match.group(1).lower()
    match = re.search(r"([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", text, flags=re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return re.sub(r"\s+", " ", text).strip().lower()


def _related_windows_search_for_windows_mail(db: Database, case_id: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    document_id = row.get("opensearch_document_id")
    if not document_id:
        return []
    return [
        dict(match)
        for match in db.conn.execute(
            """
            SELECT id, item_path, item_name, timestamp, gather_time, content_field,
                   opensearch_document_id, content_sha256, content_length
            FROM windows_search_indexed_content
            WHERE case_id = ?
              AND opensearch_document_id = ?
              AND lower(COALESCE(item_path, '')) LIKE '%windowscommunicationsapps%'
            ORDER BY COALESCE(timestamp, gather_time) DESC
            LIMIT 5
            """,
            (case_id, document_id),
        ).fetchall()
    ]


def _related_mailbox_messages_for_body(db: Database, case_id: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    document_id = row.get("opensearch_document_id")
    if not document_id:
        return []
    candidates = db.conn.execute(
        """
        SELECT id, user_profile, message_date_utc, subject, sender, recipients,
               message_path, container_path, dedupe_key
        FROM mailbox_messages
        WHERE case_id = ?
          AND parser_status = 'parsed'
          AND id != ?
          AND tool_name != 'WindowsMailParser'
          AND opensearch_document_id = ?
        ORDER BY message_date_utc DESC
        LIMIT 25
        """,
        (case_id, row.get("id") or "", document_id),
    ).fetchall()
    related = []
    for candidate in candidates:
        candidate_dict = dict(candidate)
        related.append(
            {
                "id": candidate_dict.get("id"),
                "match_type": "opensearch_document_id",
                "overlap": 1.0,
                "user_profile": candidate_dict.get("user_profile"),
                "timestamp": candidate_dict.get("message_date_utc"),
                "subject": candidate_dict.get("subject"),
                "sender": candidate_dict.get("sender"),
                "recipients": candidate_dict.get("recipients"),
                "message_path": candidate_dict.get("message_path"),
                "container_path": candidate_dict.get("container_path"),
                "dedupe_key": candidate_dict.get("dedupe_key"),
            }
        )
    return related[:5]


def _user_from_communication_path(db: Database, case_id: str, path: str | None) -> str | None:
    user = _user_from_path(path)
    if user:
        return user
    match = re.search(r"S-1-5-21-[0-9-]+", str(path or ""), flags=re.IGNORECASE)
    if not match:
        return None
    sid = match.group(0)
    rid = sid.rsplit("-", 1)[-1]
    account = db.conn.execute(
        """
        SELECT username
        FROM sam_accounts
        WHERE case_id = ? AND rid = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (case_id, rid),
    ).fetchone()
    return account["username"] if account and account["username"] else sid


def _dedupe_email_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = row.get("dedupe_key") or _email_dedupe_key(row)
        item = grouped.setdefault(
            str(key),
            {
                "dedupe_key": key,
                "name": row.get("name"),
                "email": row.get("email"),
                "timestamp": row.get("timestamp"),
                "sources": set(),
                "paths": set(),
                "count": 0,
            },
        )
        item["count"] += 1
        if row.get("source"):
            item["sources"].add(row["source"])
        if row.get("path"):
            item["paths"].add(row["path"])
    output = []
    for item in grouped.values():
        item = dict(item)
        item["sources"] = sorted(item["sources"])
        item["paths"] = sorted(item["paths"])
        output.append(item)
    output.sort(key=lambda item: (item.get("timestamp") or "", item.get("name") or ""), reverse=True)
    return output


def _messaging_app_patterns() -> list[tuple[str, str]]:
    return [
        ("ChatGPT", "%chatgpt%"),
        ("ChatGPT", "%openai%"),
        ("Claude", "%claude%"),
        ("Claude", "%anthropic%"),
        ("Codex", "%.codex%"),
        ("Codex", "%/codex/%"),
        ("Obsidian", "%obsidian%"),
        ("Notion", "%notion%"),
        ("OneNote", "%onenote%"),
        ("OneNote", "%microsoftoffice.onenote%"),
        ("Evernote", "%evernote%"),
        ("Adobe Reader", "%adobe%acrobat%"),
        ("Adobe Reader", "%acrobat%reader%"),
        ("VLC Media Player", "%/vlc/%"),
        ("VLC Media Player", "%vlc-qt-interface%"),
        ("FileZilla", "%filezilla%"),
        ("WinSCP", "%winscp%"),
        ("Notepad++", "%notepad++%"),
        ("AnyDesk", "%anydesk%"),
        ("TeamViewer", "%teamviewer%"),
        ("LogMeIn", "%logmein%"),
        ("LogMeIn", "%lmi%rescue%"),
        ("GoTo", "%gotoassist%"),
        ("GoTo", "%goto resolve%"),
        ("GoTo", "%g2ax_%"),
        ("ConnectWise Control", "%screenconnect%"),
        ("ConnectWise Control", "%connectwise control%"),
        ("BeyondTrust", "%bomgar%"),
        ("BeyondTrust", "%beyondtrust%"),
        ("Splashtop", "%splashtop%"),
        ("RustDesk", "%rustdesk%"),
        ("Chrome Remote Desktop", "%chrome remote desktop%"),
        ("Chrome Remote Desktop", "%chromoting%"),
        ("RemotePC", "%remotepc%"),
        ("Dameware", "%dameware%"),
        ("Atera", "%atera%"),
        ("NinjaOne", "%ninjarmm%"),
        ("NinjaOne", "%ninjaone%"),
        ("MeshCentral", "%meshcentral%"),
        ("DWAgent", "%dwagent%"),
        ("Parsec", "%parsec%"),
        ("RealVNC", "%realvnc%"),
        ("RealVNC", "%vnc viewer%"),
        ("RealVNC", "%vnc server%"),
        ("TightVNC", "%tightvnc%"),
        ("UltraVNC", "%ultravnc%"),
        ("Microsoft Teams", "%teams%"),
        ("Microsoft Teams", "%msteams%"),
        ("Slack", "%slack%"),
        ("Discord", "%discord%"),
        ("Signal", "%signal%"),
        ("WhatsApp", "%whatsapp%"),
        ("Telegram", "%telegram%"),
        ("Skype", "%skype%"),
        ("Zoom", "%zoom%"),
        ("Mattermost", "%mattermost%"),
        ("Viber", "%viber%"),
    ]


def _messaging_app_for_path(path: str | None) -> str:
    text = str(path or "").lower()
    for name, pattern in _messaging_app_patterns():
        needle = pattern.replace("%", "").replace("\\\\", "\\").strip("\\/")
        if needle and needle in text:
            return name
    return "Messaging"


def _messaging_artifact_type(path: str | None, extension: str | None) -> str:
    text = str(path or "").lower()
    ext = str(extension or "").lower().lstrip(".")
    if ext in {"ldb", "log"} and "leveldb" in text:
        return "leveldb_candidate"
    if ext in {"sqlite", "db"}:
        return "sqlite_database"
    if ext in {"md", "markdown"}:
        return "markdown_note"
    if ext in {"json"}:
        return "json_file"
    if ext in {"ini", "conf", "config", "xml"}:
        return "config_or_history"
    if "cache" in text:
        return "cache"
    if "cookies" in text:
        return "cookie_store"
    if "history" in text:
        return "history_store"
    return "application_file"


def _messaging_tags(path: str | None, extension: str | None) -> list[str]:
    tags = {"messaging_app_path"}
    artifact_type = _messaging_artifact_type(path, extension)
    if artifact_type == "leveldb_candidate":
        tags.add("leveldb_candidate")
    elif artifact_type == "sqlite_database":
        tags.add("sqlite_database_candidate")
    elif artifact_type == "markdown_note":
        tags.add("note_content_candidate")
    elif artifact_type == "json_file":
        tags.add("json_content_candidate")
    elif artifact_type == "config_or_history":
        tags.add("application_config_or_history")
    elif artifact_type == "cache":
        tags.add("app_cache_present")
    elif artifact_type == "cookie_store":
        tags.add("cookie_store_present")
    return sorted(tags)


def _interpret_evtx_row(row: Any) -> dict[str, Any] | None:
    event_id = str(row["event_id"] or "")
    channel = str(row["channel"] or "")
    source_file = str(row["source_file"] or "")
    payload = " ".join(
        str(row[key] or "")
        for key in ("map_description", "payload_data1", "payload_data2", "payload_data3", "payload", "executable_info")
    )
    text = f"{channel} {source_file} {payload}".lower()
    category = None
    tags: list[str] = []
    if "partition%4diagnostic" in text or "usbstor" in text or event_id in {"1006", "20001", "20003", "2100", "2102"}:
        category = "usb"
        tags.append("usb_event")
    elif (
        "wlan" in text
        or "wifi" in text
        or "wireless" in text
        or "networkprofile" in text
        or (
            event_id in {"8001", "8002", "8003", "10000", "10001"}
            and any(token in text for token in ("wlan", "wifi", "wireless", "network"))
        )
    ):
        category = "wifi"
        tags.append("wifi_network_event")
    elif any(token in text for token in ("onedrive", "dropbox", "google drive", "drivefs", "icloud")):
        category = "cloud"
        tags.append("cloud_related_event")
    elif (
        event_id in RASCLIENT_EVENT_MEANINGS
        or any(
            token in text
            for token in (
                "rasclient",
                "rasman",
                "remoteaccess",
                " vpn",
                "sstp",
                "ikev2",
                "l2tp",
                "pptp",
                "wireguard",
                "openvpn",
                "anyconnect",
                "globalprotect",
                "forticlient",
                "tailscale",
                "zerotier",
            )
        )
    ):
        category = "vpn"
        tags.append("vpn_event")
        if event_id in RASCLIENT_EVENT_MEANINGS:
            tags.append(RASCLIENT_EVENT_MEANINGS[event_id][0])
    elif event_id in {"4663", "4656", "4660", "4658", "4664"}:
        category = "file_activity"
        tags.append("object_access_event")
    elif event_id in {"4624", "4634", "4647", "4672", "4776"}:
        category = "logon"
        tags.append("logon_event")
    if category is None:
        return None
    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "computer_id": row["computer_id"],
        "computer_label": row["computer_label"] if "computer_label" in row.keys() else None,
        "image_id": row["image_id"],
        "category": category,
        "event_id": event_id,
        "time_created": row["time_created"],
        "channel": channel,
        "provider": row["provider"],
        "user_name": row["user_name"],
        "source_file": source_file,
        "summary": row["map_description"],
        "payload_data1": row["payload_data1"],
        "payload_data2": row["payload_data2"],
        "payload_data3": row["payload_data3"],
        "evidence_tags": sorted(set(tags)),
    }


def _rows_with_details(rows: list[Any]) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        item = dict(row)
        if "details_json" in item:
            item["details"] = json.loads(item.pop("details_json") or "{}")
        output.append(item)
    return output


def _copied_usb_for_path(db: Database, case_id: str, *, path: str, limit: int) -> list[dict[str, Any]]:
    copied = copied_usb_files_report(db, case_id, limit=10000, grouped=False)
    needle = path.lower()
    matches = []
    for item in copied["items"]:
        haystack = f"{item.get('file_location') or ''} {item.get('file_name') or ''}".lower()
        if needle in haystack:
            matches.append(item)
        if len(matches) >= limit:
            break
    return matches


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item for item in value.split(",") if item]


def _usb_association_wording(source_artifact_type: str, basis: str | None) -> str:
    if source_artifact_type == "shellbag" and basis in {"folder_tree_time", "path_time_anchor", "time_overlap"}:
        return "Shellbag folder interaction is consistent with this USB device by folder path and/or connection-time overlap."
    if source_artifact_type == "shellbag":
        return "Shellbag folder path is consistent with this USB device."
    return "Shortcut artifact volume metadata links this file activity to this USB device."


def _group_copied_usb_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.get("usb_serial"),
            row.get("usb_volume_serial_number"),
            row.get("file_location"),
            row.get("created_timestamp_utc"),
            row.get("modified_timestamp_utc"),
        )
        group = groups.setdefault(
            key,
            {
                "usb_serial": row.get("usb_serial"),
                "usb_volume_serial_number": row.get("usb_volume_serial_number"),
                "usb_volume_name": row.get("usb_volume_name"),
                "file_name": row.get("file_name"),
                "file_location": row.get("file_location"),
                "created_timestamp_utc": row.get("created_timestamp_utc"),
                "modified_timestamp_utc": row.get("modified_timestamp_utc"),
                "indicator_count": 0,
                "source_artifact_types": set(),
                "user_profiles": set(),
                "association_bases": set(),
            },
        )
        group["indicator_count"] += 1
        if row.get("source_artifact_type"):
            group["source_artifact_types"].add(row["source_artifact_type"])
        if row.get("user_profile"):
            group["user_profiles"].add(row["user_profile"])
        if row.get("association_basis"):
            group["association_bases"].add(row["association_basis"])
    result = []
    for group in groups.values():
        item = dict(group)
        item["source_artifact_types"] = sorted(item["source_artifact_types"])
        item["user_profiles"] = sorted(item["user_profiles"])
        item["association_bases"] = sorted(item["association_bases"])
        result.append(item)
    result.sort(key=lambda item: (-item["indicator_count"], item.get("file_location") or ""))
    return result


def _job_status(row: dict[str, Any]) -> str:
    if row.get("dry_run"):
        return "dry_run"
    if row.get("exit_code") is None:
        return "started"
    if row.get("exit_code") != 0:
        return "error"
    if row.get("output_count", 0) == 0:
        return "completed_no_output"
    return "completed"


def _job_status_counts(db: Database, case_id: str) -> dict[str, int]:
    rows = db.conn.execute(
        """
        WITH job_output_counts AS (
          SELECT jobs.id,
                 jobs.dry_run,
                 jobs.exit_code,
                 COUNT(tool_outputs.id) AS output_count
          FROM jobs
          LEFT JOIN tool_outputs ON tool_outputs.job_id = jobs.id
          WHERE jobs.case_id = ?
          GROUP BY jobs.id
        )
        SELECT
          CASE
            WHEN dry_run = 1 THEN 'dry_run'
            WHEN exit_code IS NULL THEN 'started'
            WHEN exit_code != 0 THEN 'error'
            WHEN output_count = 0 THEN 'completed_no_output'
            ELSE 'completed'
          END AS status,
          COUNT(*) AS count
        FROM job_output_counts
        GROUP BY status
        ORDER BY status
        """,
        (case_id,),
    ).fetchall()
    return {row["status"]: row["count"] for row in rows}


def _job_activity(db: Database, job_id: str, *, level: str) -> list[dict[str, Any]]:
    return [
        {
            "created_at": row["created_at"],
            "event": row["event"],
            "message": row["message"],
            "details": json.loads(row["details_json"] or "{}"),
        }
        for row in db.conn.execute(
            """
            SELECT created_at, event, message, details_json
            FROM activity_log
            WHERE job_id = ? AND level = ?
            ORDER BY created_at
            """,
            (job_id, level),
        ).fetchall()
    ]


def artifact_summary_report(db: Database, case_id: str) -> dict[str, Any]:
    status = db.case_status(case_id)
    return {
        "case_id": case_id,
        "artifacts": _artifact_counts(status["artifacts"]),
        "outputs": status["parsed_row_counts"],
        "tool_outputs": status["outputs"],
    }


def execution_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    events: list[dict[str, Any]] = []
    process_activity: list[dict[str, Any]] = []
    presence_indicators: list[dict[str, Any]] = []

    for row in _query_report_rows(
        db,
        case_id,
        "prefetch_items",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number, prefetch_name,
               artifact_path, executable_name, prefetch_hash, run_count, last_run_time_utc,
               last_run_times_utc, resolved_reference_path, resolved_reference_device_path,
               resolved_reference_command_line, resolved_reference_os, resolved_reference_description,
               resolved_reference_source, resolved_reference_match_count, pf_created, pf_modified, pf_accessed
        FROM prefetch_items
        WHERE case_id = ?
        ORDER BY COALESCE(last_run_time_utc, '') DESC, executable_name
        LIMIT ?
        """,
        (case_id, limit),
    ):
        timestamps = _coerce_list(row.get("last_run_times_utc"))
        if not timestamps and row.get("last_run_time_utc"):
            timestamps = [row["last_run_time_utc"]]
        for index, timestamp in enumerate(timestamps, start=1):
            if not timestamp:
                continue
            events.append(
                {
                    "case_id": case_id,
                    "computer_id": row.get("computer_id"),
                    "computer_label": None,
                    "image_id": row.get("image_id"),
                    "image_path": None,
                    "tool": row.get("tool_name"),
                    "source_table": "prefetch_items",
                    "source_row_id": row.get("id"),
                    "timestamp_utc": timestamp,
                    "raw_timestamp": timestamp,
                    "event_type": "prefetch_last_run",
                    "description": row.get("executable_name") or row.get("prefetch_name"),
                    "path": row.get("artifact_path"),
                    "display_path": _display_evidence_path(row.get("artifact_path")),
                    "normalized_path": _normalize_artifact_path(row.get("artifact_path")),
                    "application": row.get("executable_name") or row.get("prefetch_name"),
                    "execution_count": 1,
                    "details": {
                        "run_count": row.get("run_count"),
                        "prefetch_name": row.get("prefetch_name"),
                        "prefetch_hash": row.get("prefetch_hash"),
                        "resolved_reference_path": row.get("resolved_reference_path"),
                        "resolved_reference_device_path": row.get("resolved_reference_device_path"),
                        "resolved_reference_command_line": row.get("resolved_reference_command_line"),
                        "resolved_reference_os": row.get("resolved_reference_os"),
                        "resolved_reference_description": row.get("resolved_reference_description"),
                        "resolved_reference_source": row.get("resolved_reference_source"),
                        "resolved_reference_match_count": row.get("resolved_reference_match_count"),
                        "reference_caveat": (
                            "Prefetch hash reference matches are resolver enrichment only; corroborate with case artifacts."
                            if row.get("resolved_reference_path") else None
                        ),
                        "timestamp_index": index,
                        "timestamp_count": len(timestamps),
                        "pf_created": row.get("pf_created"),
                        "pf_modified": row.get("pf_modified"),
                        "pf_accessed": row.get("pf_accessed"),
                        "source_file": row.get("source_csv"),
                        "row_number": row.get("row_number"),
                    },
                }
            )

    for row in _query_report_rows(
        db,
        case_id,
        "registry_artifacts",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number, source_path,
               user_profile, user_sid, artifact, category, key_path, key_last_write_utc,
               event_time_utc, value_name, value_data, display_name, normalized_path, notes
        FROM registry_artifacts
        WHERE case_id = ?
          AND (
            artifact IN ('bam', 'dam', 'userassist', 'autostart', 'capability_access_manager')
          )
        ORDER BY COALESCE(event_time_utc, key_last_write_utc, '') DESC, artifact, row_number
        LIMIT ?
        """,
        (case_id, limit),
    ):
        artifact = str(row.get("artifact") or "registry_execution")
        timestamp = row.get("event_time_utc") or row.get("key_last_write_utc")
        details = {
            "artifact": artifact,
            "category": row.get("category"),
            "user_profile": row.get("user_profile"),
            "user_sid": row.get("user_sid"),
            "key_path": row.get("key_path"),
            "value_name": row.get("value_name"),
            "value_data": row.get("value_data"),
            "notes": row.get("notes"),
            "source_file": row.get("source_csv") or row.get("source_path"),
            "row_number": row.get("row_number"),
        }
        description = _registry_execution_description(row)
        if not description and artifact.lower() == "userassist":
            continue
        if artifact.lower() == "userassist" and _is_userassist_control_value(description):
            continue
        event_type = f"registry_{artifact}"
        if artifact.lower() == "capability_access_manager":
            event_type = "capability_access"
        event = {
            "case_id": case_id,
            "computer_id": row.get("computer_id"),
            "computer_label": None,
            "image_id": row.get("image_id"),
            "image_path": None,
            "tool": row.get("tool_name"),
            "source_table": "registry_artifacts",
            "source_row_id": row.get("id"),
            "timestamp_utc": timestamp,
            "raw_timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "path": _registry_execution_path(row, description),
            "display_path": _display_evidence_path(_registry_execution_path(row, description)),
            "normalized_path": _normalize_artifact_path(_registry_execution_path(row, description)),
            "application": description,
            "execution_count": 1,
            "details": details,
        }
        if artifact.lower() == "userassist":
            event["evidence_caveat"] = USERASSIST_CAVEAT
            details["evidence_caveat"] = USERASSIST_CAVEAT
            details["requires_corroboration"] = True
        events.append(event)

    for row in _query_report_rows(
        db,
        case_id,
        "amcache_entries",
        """
        SELECT id, computer_id, image_id, tool_name, source_file, row_number,
               entry_type, path, name, publisher, product_name, sha1, sha256,
               created_utc, modified_utc, install_date
        FROM amcache_entries
        WHERE case_id = ?
        ORDER BY COALESCE(modified_utc, created_utc, install_date, '') DESC, path, name
        LIMIT ?
        """,
        (case_id, limit),
    ):
        path_value = row.get("path") or row.get("name")
        presence_indicators.append(
            {
                "source_table": "amcache_entries",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("modified_utc") or row.get("created_utc") or row.get("install_date"),
                "indicator_type": "program_presence",
                "description": row.get("name") or path_value,
                "path": path_value,
                "display_path": _display_evidence_path(path_value),
                "normalized_path": _normalize_artifact_path(path_value),
                "application": row.get("name") or _basename_from_path(path_value) or path_value,
                "tool": row.get("tool_name"),
                "details": {
                    "entry_type": row.get("entry_type"),
                    "publisher": row.get("publisher"),
                    "product_name": row.get("product_name"),
                    "sha1": row.get("sha1"),
                    "sha256": row.get("sha256"),
                    "source_file": row.get("source_file"),
                    "row_number": row.get("row_number"),
                    "evidence_caveat": "Amcache records program/file presence and inventory metadata. It is not standalone execution proof.",
                },
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "shimcache_entries",
        """
        SELECT id, computer_id, image_id, tool_name, source_file, row_number,
               path, executed, last_modified_utc AS timestamp_utc, source_key
        FROM shimcache_entries
        WHERE case_id = ?
        ORDER BY COALESCE(last_modified_utc, '') DESC, path
        LIMIT ?
        """,
        (case_id, limit),
    ):
        display_path = _clean_shimcache_display_path(row.get("path"))
        presence_indicators.append(
            {
                "source_table": "shimcache_entries",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("timestamp_utc"),
                "indicator_type": "program_presence",
                "description": display_path,
                "path": display_path,
                "display_path": _display_evidence_path(display_path),
                "normalized_path": _normalize_artifact_path(display_path),
                "application": _basename_from_path(display_path) or display_path,
                "tool": row.get("tool_name"),
                "details": {
                    "executed": row.get("executed"),
                    "source_key": row.get("source_key"),
                    "source_file": row.get("source_file"),
                    "row_number": row.get("row_number"),
                    "evidence_caveat": "ShimCache/AppCompatCache records program presence/cache metadata. Even an Executed flag should be corroborated before treating it as execution proof.",
                },
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "shortcut_items",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               artifact_type, artifact_name, artifact_path, file_name, file_location,
               target_created, target_modified
        FROM shortcut_items
        WHERE case_id = ?
          AND COALESCE(target_created, '') != ''
          AND COALESCE(target_modified, '') != ''
        ORDER BY COALESCE(target_created, '') DESC, row_number
        LIMIT ?
        """,
        (case_id, limit),
    ):
        created = _parse_timestamp(row.get("target_created"))
        modified = _parse_timestamp(row.get("target_modified"))
        if created is None or modified is None or created <= modified:
            continue
        events.append(
            {
                "case_id": case_id,
                "computer_id": row.get("computer_id"),
                "computer_label": None,
                "image_id": row.get("image_id"),
                "image_path": None,
                "tool": row.get("tool_name"),
                "source_table": "shortcut_items",
                "source_row_id": row.get("id"),
                "timestamp_utc": _format_timestamp(created),
                "raw_timestamp": row.get("target_created"),
                "event_type": "copied_file_indicator",
                "description": row.get("file_location") or row.get("file_name") or row.get("artifact_name"),
                "path": row.get("file_location"),
                "display_path": _display_evidence_path(row.get("file_location")),
                "normalized_path": _normalize_artifact_path(row.get("file_location")),
                "application": None,
                "execution_count": 0,
                "details": {
                    "classification": "copied_file",
                    "reason": "target creation time is after target modification time",
                    "artifact_type": row.get("artifact_type"),
                    "artifact_name": row.get("artifact_name"),
                    "artifact_path": row.get("artifact_path"),
                    "target_created": row.get("target_created"),
                    "target_modified": row.get("target_modified"),
                    "source_file": row.get("source_csv"),
                    "row_number": row.get("row_number"),
                },
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "registry_runmru",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               user_profile, executable, opened_on, key_last_write_timestamp,
               mru_position, value_name
        FROM registry_runmru
        WHERE case_id = ?
        ORDER BY COALESCE(opened_on, key_last_write_timestamp, '') DESC, row_number
        LIMIT ?
        """,
        (case_id, limit),
    ):
        executable = row.get("executable")
        events.append(
            {
                "case_id": case_id,
                "computer_id": row.get("computer_id"),
                "computer_label": None,
                "image_id": row.get("image_id"),
                "image_path": None,
                "tool": row.get("tool_name"),
                "source_table": "registry_runmru",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("opened_on") or row.get("key_last_write_timestamp"),
                "raw_timestamp": row.get("opened_on") or row.get("key_last_write_timestamp"),
                "event_type": "runmru_command",
                "description": executable,
                "path": executable,
                "display_path": _display_evidence_path(executable),
                "normalized_path": _normalize_artifact_path(executable),
                "application": _basename_from_path(executable) or executable,
                "execution_count": 1,
                "details": {
                    "user_profile": row.get("user_profile"),
                    "mru_position": row.get("mru_position"),
                    "value_name": row.get("value_name"),
                    "source_file": row.get("source_csv"),
                    "row_number": row.get("row_number"),
                    "evidence_caveat": "RunMRU records commands entered through the Run dialog; corroborate with execution artifacts.",
                },
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "registry_common_dialog_mru",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               user_profile, executable, absolute_path, opened_on, key_last_write_timestamp,
               artifact, mru_position
        FROM registry_common_dialog_mru
        WHERE case_id = ?
        ORDER BY COALESCE(opened_on, key_last_write_timestamp, '') DESC, row_number
        LIMIT ?
        """,
        (case_id, limit),
    ):
        events.append(
            {
                "case_id": case_id,
                "computer_id": row.get("computer_id"),
                "computer_label": None,
                "image_id": row.get("image_id"),
                "image_path": None,
                "tool": row.get("tool_name"),
                "source_table": "registry_common_dialog_mru",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("opened_on") or row.get("key_last_write_timestamp"),
                "raw_timestamp": row.get("opened_on") or row.get("key_last_write_timestamp"),
                "event_type": "lastvisitedpidl_file_dialog",
                "description": row.get("executable") or row.get("absolute_path"),
                "path": row.get("absolute_path"),
                "display_path": _display_evidence_path(row.get("absolute_path")),
                "normalized_path": _normalize_artifact_path(row.get("absolute_path")),
                "application": _basename_from_path(row.get("executable")) or row.get("executable"),
                "execution_count": 0,
                "details": {
                    "user_profile": row.get("user_profile"),
                    "artifact": row.get("artifact"),
                    "mru_position": row.get("mru_position"),
                    "source_file": row.get("source_csv"),
                    "row_number": row.get("row_number"),
                    "evidence_caveat": "Common Dialog LastVisitedPIDL is file-dialog/file-use context, not process execution proof.",
                },
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "srum_records",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               record_type, timestamp, app_name, app_path, app_id, user_name,
               foreground_bytes_read, foreground_bytes_written, background_bytes_read, background_bytes_written,
               foreground_cycle_time, background_cycle_time
        FROM srum_records
        WHERE case_id = ?
          AND record_type IN ('app_resource_usage', 'network_usage', 'app_timeline_provider')
          AND COALESCE(app_name, app_path, app_id, '') != ''
        ORDER BY COALESCE(timestamp, '') DESC, record_type, row_number
        LIMIT ?
        """,
        (case_id, limit),
    ):
        app_name = row.get("app_name")
        app = (
            _basename_from_path(row.get("app_path"))
            if _looks_like_numeric_id(app_name)
            else app_name
        ) or _basename_from_path(row.get("app_path")) or row.get("app_id")
        if _looks_like_numeric_id(app) and not row.get("app_path"):
            continue
        events.append(
            {
                "case_id": case_id,
                "computer_id": row.get("computer_id"),
                "computer_label": None,
                "image_id": row.get("image_id"),
                "image_path": None,
                "tool": row.get("tool_name"),
                "source_table": "srum_records",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("timestamp"),
                "raw_timestamp": row.get("timestamp"),
                "event_type": f"srum_{row.get('record_type') or 'app_activity'}",
                "description": app,
                "path": row.get("app_path"),
                "display_path": _display_evidence_path(row.get("app_path")),
                "normalized_path": _normalize_artifact_path(row.get("app_path")),
                "application": app,
                "execution_count": 1,
                "details": {
                    "record_type": row.get("record_type"),
                    "user_name": row.get("user_name"),
                    "app_id": row.get("app_id"),
                    "foreground_bytes_read": row.get("foreground_bytes_read"),
                    "foreground_bytes_written": row.get("foreground_bytes_written"),
                    "background_bytes_read": row.get("background_bytes_read"),
                    "background_bytes_written": row.get("background_bytes_written"),
                    "foreground_cycle_time": row.get("foreground_cycle_time"),
                    "background_cycle_time": row.get("background_cycle_time"),
                    "source_file": row.get("source_csv"),
                    "row_number": row.get("row_number"),
                    "evidence_caveat": "SRUM records application resource/network activity, not process creation by itself.",
                },
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "windows_activities",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               user_profile, app_id, app_display_name, activity_type, display_text,
               file_name, content_uri, activation_uri, fallback_uri,
               start_time_utc, last_modified_utc
        FROM windows_activities
        WHERE case_id = ?
        ORDER BY COALESCE(start_time_utc, last_modified_utc, '') DESC, row_number
        LIMIT ?
        """,
        (case_id, limit),
    ):
        app = row.get("app_display_name") or row.get("app_id")
        events.append(
            {
                "case_id": case_id,
                "computer_id": row.get("computer_id"),
                "computer_label": None,
                "image_id": row.get("image_id"),
                "image_path": None,
                "tool": row.get("tool_name"),
                "source_table": "windows_activities",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("start_time_utc") or row.get("last_modified_utc"),
                "raw_timestamp": row.get("start_time_utc") or row.get("last_modified_utc"),
                "event_type": "connected_devices_activity",
                "description": app,
                "path": row.get("content_uri") or row.get("activation_uri") or row.get("fallback_uri"),
                "display_path": _display_evidence_path(row.get("content_uri") or row.get("activation_uri") or row.get("fallback_uri")),
                "normalized_path": _normalize_artifact_path(row.get("content_uri") or row.get("activation_uri") or row.get("fallback_uri")),
                "application": app,
                "execution_count": 1,
                "details": {
                    "user_profile": row.get("user_profile"),
                    "activity_type": row.get("activity_type"),
                    "display_text": row.get("display_text"),
                    "file_name": row.get("file_name"),
                    "source_file": row.get("source_csv"),
                    "row_number": row.get("row_number"),
                    "evidence_caveat": "ConnectedDevicesPlatform records user/activity history; it is app-use context, not standalone execution proof.",
                },
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "shortcut_items",
        """
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               artifact_type, artifact_name, artifact_path, file_name, file_location,
               target_accessed, target_modified, target_created, jumplist_item_number
        FROM shortcut_items
        WHERE case_id = ? AND artifact_type = 'jumplist'
        ORDER BY COALESCE(target_accessed, target_modified, target_created, '') DESC, row_number
        LIMIT ?
        """,
        (case_id, limit),
    ):
        timestamp = row.get("target_accessed") or row.get("target_modified") or row.get("target_created")
        application = _jumplist_application_name(row)
        events.append(
            {
                "case_id": case_id,
                "computer_id": row.get("computer_id"),
                "computer_label": None,
                "image_id": row.get("image_id"),
                "image_path": None,
                "tool": row.get("tool_name"),
                "source_table": "shortcut_items",
                "source_row_id": row.get("id"),
                "timestamp_utc": timestamp,
                "raw_timestamp": timestamp,
                "event_type": "jumplist_file_use",
                "description": row.get("file_name") or row.get("file_location"),
                "path": row.get("file_location"),
                "display_path": _display_evidence_path(row.get("file_location")),
                "normalized_path": _normalize_artifact_path(row.get("file_location")),
                "application": application,
                "execution_count": 1,
                "details": {
                    "application": application,
                    "artifact_name": row.get("artifact_name"),
                    "artifact_path": row.get("artifact_path"),
                    "jumplist_item_number": row.get("jumplist_item_number"),
                    "target_accessed": row.get("target_accessed"),
                    "target_modified": row.get("target_modified"),
                    "target_created": row.get("target_created"),
                    "source_file": row.get("source_csv"),
                    "row_number": row.get("row_number"),
                    "evidence_caveat": "Jump Lists show application file-use context and target timestamps; they are not direct process creation events.",
                },
            }
        )

    for row in _query_report_rows(
        db,
        case_id,
        "evtx_events",
        """
        SELECT id, computer_id, image_id, tool_name, source_file, row_number, time_created,
               event_id, provider, channel, computer, user_name, remote_host, map_description,
               executable_info, payload_data1, payload_data2, payload_data3
        FROM evtx_events
        WHERE case_id = ?
          AND event_id IN ('4688', '4689', '4697', '7045')
        ORDER BY COALESCE(time_created, '') DESC, event_id, row_number
        LIMIT ?
        """,
        (case_id, limit),
    ):
        timestamp = row.get("time_created")
        description = row.get("executable_info") or row.get("map_description") or row.get("provider") or row.get("event_id")
        process_activity.append(
            {
                "case_id": case_id,
                "computer_id": row.get("computer_id"),
                "computer_label": None,
                "image_id": row.get("image_id"),
                "image_path": None,
                "tool": row.get("tool_name"),
                "source_table": "evtx_events",
                "source_row_id": row.get("id"),
                "timestamp_utc": timestamp,
                "raw_timestamp": timestamp,
                "event_type": "windows_process_event" if row.get("event_id") in {"4688", "4689"} else "windows_service_event",
                "description": description,
                "path": row.get("executable_info"),
                "display_path": _display_evidence_path(row.get("executable_info")),
                "normalized_path": _normalize_artifact_path(row.get("executable_info")),
                "application": _basename_from_path(row.get("executable_info")) or row.get("executable_info"),
                "details": {
                    "event_id": row.get("event_id"),
                    "provider": row.get("provider"),
                    "channel": row.get("channel"),
                    "computer": row.get("computer"),
                    "user_name": row.get("user_name"),
                    "remote_host": row.get("remote_host"),
                    "map_description": row.get("map_description"),
                    "payload_data1": row.get("payload_data1"),
                    "payload_data2": row.get("payload_data2"),
                    "payload_data3": row.get("payload_data3"),
                    "source_file": row.get("source_file"),
                    "row_number": row.get("row_number"),
                },
            }
        )

    events.sort(
        key=lambda item: (
            _timestamp_sort_key(item.get("timestamp_utc")),
            item.get("source_table") or "",
            item.get("event_type") or "",
            item.get("description") or "",
        )
    )
    process_activity.sort(
        key=lambda item: (
            _timestamp_sort_key(item.get("timestamp_utc")),
            item.get("event_type") or "",
            item.get("description") or "",
        )
    )
    source_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}
    for event in events:
        source = str(event.get("source_table") or "unknown")
        event_type = str(event.get("event_type") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
    process_source_counts: dict[str, int] = {}
    for event in process_activity:
        source = str(event.get("source_table") or "unknown")
        process_source_counts[source] = process_source_counts.get(source, 0) + 1
    presence_source_counts: dict[str, int] = {}
    for item in presence_indicators:
        source = str(item.get("source_table") or "unknown")
        presence_source_counts[source] = presence_source_counts.get(source, 0) + 1
    return {
        "case_id": case_id,
        "caveats": _report_caveats_for_userassist(events),
        "summary": {
            "source_counts": source_counts,
            "event_type_counts": event_type_counts,
            "events_returned": len(events),
            "process_activity_returned": len(process_activity),
            "presence_indicator_returned": len(presence_indicators),
            "process_activity_source_counts": process_source_counts,
            "presence_source_counts": presence_source_counts,
            "limit_per_source": limit,
        },
        "applications": _execution_application_summary(events),
        "events": events,
        "process_activity": process_activity,
        "presence_indicators": presence_indicators,
        "total_events": len(events),
    }


def execution_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    events = report.get("events") if isinstance(report.get("events"), list) else []
    applications = report.get("applications") if isinstance(report.get("applications"), list) else []
    process_activity = report.get("process_activity") if isinstance(report.get("process_activity"), list) else []
    presence_indicators = report.get("presence_indicators") if isinstance(report.get("presence_indicators"), list) else []
    lines = [
        "# Execution Report",
        "",
        f"Case: `{report.get('case_id') or ''}`",
        "",
        "## Summary",
        "",
        f"- Events returned: `{report.get('total_events', 0)}`",
        f"- Process/service activity records: `{summary.get('process_activity_returned', 0)}`",
        f"- Presence indicators: `{summary.get('presence_indicator_returned', 0)}`",
        f"- Limit per source: `{summary.get('limit_per_source', '')}`",
        "",
    ]
    caveats = report.get("caveats") if isinstance(report.get("caveats"), list) else []
    if caveats:
        lines.extend(["## Caveats", ""])
        for caveat in caveats:
            lines.append(f"- {caveat}")
        lines.append("")
    for heading, key in (("Sources", "source_counts"), ("Event Types", "event_type_counts")):
        counts = summary.get(key) if isinstance(summary.get(key), dict) else {}
        if counts:
            lines.extend([f"## {heading}", ""])
            for value, count in sorted(counts.items()):
                lines.append(f"- `{value}`: `{count}`")
            lines.append("")
    process_counts = summary.get("process_activity_source_counts") if isinstance(summary.get("process_activity_source_counts"), dict) else {}
    if process_counts:
        lines.extend(["## Process And Service Activity Sources", ""])
        for value, count in sorted(process_counts.items()):
            lines.append(f"- `{value}`: `{count}`")
        lines.append("")
    presence_counts = summary.get("presence_source_counts") if isinstance(summary.get("presence_source_counts"), dict) else {}
    if presence_counts:
        lines.extend(["## Presence Indicator Sources", ""])
        for value, count in sorted(presence_counts.items()):
            lines.append(f"- `{value}`: `{count}`")
        lines.append("")
    lines.extend(["## Applications", ""])
    if not applications:
        lines.append("- No application summary rows were found.")
    for app in applications:
        if not isinstance(app, dict):
            continue
        lines.append(
            f"- `{app.get('application') or ''}`: events `{app.get('event_count') or 0}`, "
            f"execution/use count `{app.get('execution_count') or 0}`, sources `{', '.join(app.get('sources') or [])}`"
        )
    lines.append("")
    lines.extend(["## Timeline", ""])
    if not events:
        lines.append("- No execution evidence was found.")
    for event in events:
        if not isinstance(event, dict):
            continue
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        lines.append(
            f"- `{event.get('timestamp_utc') or ''}` `{event.get('source_table') or ''}` "
            f"`{event.get('event_type') or ''}` `{event.get('description') or ''}`"
        )
        detail_bits = [
            f"{key}={value}"
            for key, value in {
                "path": event.get("path"),
                "display_path": event.get("display_path") or _display_evidence_path(event.get("path")),
                "artifact": details.get("artifact"),
                "event_id": details.get("event_id"),
                "user": details.get("user_profile") or details.get("user_name"),
                "run_count": details.get("run_count"),
                "registry_key": details.get("key_path"),
                "source_table": event.get("source_table"),
                "source_file": details.get("source_file"),
            }.items()
            if value not in (None, "")
        ]
        if detail_bits:
            lines.append("  - " + "; ".join(str(bit) for bit in detail_bits))
    lines.extend(["", "## Presence Indicators", ""])
    lines.append("- Amcache and ShimCache/AppCompatCache rows are listed here as program/file presence, inventory, or cache metadata. They are not execution proof by themselves.")
    if not presence_indicators:
        lines.append("- No Amcache or ShimCache presence rows were found.")
    for item in presence_indicators[:100]:
        if not isinstance(item, dict):
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        lines.append(
            f"- `{item.get('timestamp_utc') or ''}` `{item.get('source_table') or ''}` "
            f"`{item.get('application') or item.get('description') or ''}` path `{item.get('display_path') or _display_evidence_path(item.get('path'))}`"
        )
        detail_bits = [
            f"{key}={value}"
            for key, value in {
                "executed": details.get("executed"),
                "entry_type": details.get("entry_type"),
                "publisher": details.get("publisher"),
                "source_key": details.get("source_key"),
                "source_file": details.get("source_file"),
            }.items()
            if value not in (None, "")
        ]
        if detail_bits:
            lines.append("  - " + "; ".join(str(bit) for bit in detail_bits))
    lines.extend(["", "## Process And Service Activity", ""])
    if not process_activity:
        lines.append("- No process/service activity records were found.")
    for event in process_activity:
        if not isinstance(event, dict):
            continue
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        lines.append(
            f"- `{event.get('timestamp_utc') or ''}` `{event.get('event_type') or ''}` "
            f"`{event.get('description') or ''}`"
        )
        detail_bits = [
            f"{key}={value}"
            for key, value in {
                "event_id": details.get("event_id"),
                "provider": details.get("provider"),
                "user": details.get("user_name"),
                "path": event.get("display_path") or _display_evidence_path(event.get("path")),
                "source_file": details.get("source_file"),
            }.items()
            if value not in (None, "")
        ]
        if detail_bits:
            lines.append("  - " + "; ".join(str(bit) for bit in detail_bits))
    return "\n".join(lines).rstrip() + "\n"


def _registry_execution_description(row: dict[str, Any]) -> Any:
    artifact = str(row.get("artifact") or "").lower()
    notes = str(row.get("notes") or "")
    if artifact == "userassist":
        return _expand_known_folder_path(_extract_note_value(notes, "rot13_name") or "")
    if artifact in {"bam", "dam"}:
        return _extract_note_value(notes, "executed_path") or row.get("display_name") or row.get("normalized_path") or row.get("value_data") or row.get("value_name")
    return row.get("display_name") or row.get("normalized_path") or row.get("value_data") or row.get("value_name")


def _registry_execution_path(row: dict[str, Any], description: Any) -> Any:
    if str(row.get("artifact") or "").lower() == "userassist":
        return description
    return row.get("normalized_path") or row.get("value_data")


def _extract_note_value(notes: str, key: str) -> str | None:
    match = re.search(rf"(?:^|; ){re.escape(key)}=([^;]+)", notes)
    return match.group(1) if match else None


KNOWN_FOLDER_GUID_PATHS = {
    "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": r"%SystemRoot%\System32",
    "F38BF404-1D43-42F2-9305-67DE0B28FC23": r"%SystemRoot%",
    "905E63B6-C1BF-494E-B29C-65B732D3D21A": r"%ProgramFiles%",
    "6D809377-6AF0-444B-8957-A3773F02200E": r"%ProgramFiles%",
    "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": r"%ProgramFiles(x86)%",
    "F7F1ED05-9F6D-47A2-AAAE-29D317C6F066": r"%CommonProgramFiles%",
    "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": r"%UserProfile%\Desktop",
    "FDD39AD0-238F-46AF-ADB4-6C85480369C7": r"%UserProfile%\Documents",
    "374DE290-123F-4565-9164-39C4925E467B": r"%UserProfile%\Downloads",
    "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": r"%AppData%",
    "F1B32785-6FBA-4FCF-9D55-7B8E7F157091": r"%LocalAppData%",
    "A77F5D77-2E2B-44C3-A6A2-ABA601054A51": r"%StartMenu%\Programs",
    "B97D20BB-F46A-4C97-BA10-5E3608430854": r"%StartMenu%\Programs\Startup",
}


def _expand_known_folder_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    def repl(match: re.Match[str]) -> str:
        guid = match.group(1).upper()
        return KNOWN_FOLDER_GUID_PATHS.get(guid, match.group(0))

    return re.sub(r"\{([0-9A-Fa-f-]{36})\}", repl, text)


def _is_userassist_control_value(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return (
        not text
        or text in {"version", "irefvba"}
        or text.startswith("ueme_ctl")
    )


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return None


def _looks_like_numeric_id(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text) and bool(re.fullmatch(r"\d+", text))


def _clean_shimcache_display_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parts = [part.strip() for part in text.split("\t") if part.strip()]
    if len(parts) >= 5:
        return parts[4]
    return text


_JUMPLIST_APP_CACHE: dict[tuple[str, int], str | None] = {}


def _jumplist_application_name(row: dict[str, Any]) -> str | None:
    source_csv = str(row.get("source_csv") or "")
    row_number = _int_or_none(row.get("row_number")) or 0
    cached = _JUMPLIST_APP_CACHE.get((source_csv, row_number))
    if cached is not None:
        return cached
    value = _jumplist_application_name_from_csv(source_csv, row_number)
    if not value:
        value = _basename_from_path(row.get("artifact_path"))
    _JUMPLIST_APP_CACHE[(source_csv, row_number)] = value
    return value


def _jumplist_application_name_from_csv(source_csv: str, row_number: int) -> str | None:
    if not source_csv or row_number <= 0:
        return None
    path = Path(source_csv)
    if not path.exists() or not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader, start=1):
                if index != row_number:
                    continue
                return (
                    row.get("AppIdDescription")
                    or row.get("AppId Description")
                    or row.get("AppId")
                    or row.get("App ID")
                    or None
                )
    except OSError:
        return None
    return None


def _execution_application_summary(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        app = event.get("application") or event.get("description") or event.get("path")
        app_text = str(app or "").strip()
        if not app_text:
            continue
        key = app_text.casefold()
        item = grouped.setdefault(
            key,
            {
                "application": app_text,
                "event_count": 0,
                "execution_count": 0,
                "_execution_keys": set(),
                "sources": set(),
                "event_types": set(),
                "first_seen": None,
                "last_seen": None,
            },
        )
        item["event_count"] += 1
        if (_int_or_none(event.get("execution_count")) or 0) > 0:
            timestamp_key = str(event.get("timestamp_utc") or event.get("raw_timestamp") or "")
            if timestamp_key:
                item["_execution_keys"].add(timestamp_key)
            else:
                item["_execution_keys"].add(
                    f"{event.get('source_table') or ''}:{event.get('source_row_id') or ''}:{event.get('event_type') or ''}"
                )
        if event.get("source_table"):
            item["sources"].add(event["source_table"])
        if event.get("event_type"):
            item["event_types"].add(event["event_type"])
        timestamp = event.get("timestamp_utc")
        if timestamp:
            text = str(timestamp)
            if item["first_seen"] is None or text < item["first_seen"]:
                item["first_seen"] = text
            if item["last_seen"] is None or text > item["last_seen"]:
                item["last_seen"] = text
    rows = []
    for item in grouped.values():
        row = dict(item)
        row["execution_count"] = len(row.pop("_execution_keys"))
        if row["execution_count"] == 0:
            continue
        row["sources"] = sorted(row["sources"])
        row["event_types"] = sorted(row["event_types"])
        rows.append(row)
    rows.sort(key=lambda row: row["application"].casefold())
    return rows


INTERESTING_EVIDENCE_RANK = {
    "execution": 0,
    "process_activity": 1,
    "presence": 2,
    "installed_application": 3,
    "file_system": 4,
}

INTERESTING_SEVERITY_RANK = {
    "high": 0,
    "medium": 1,
    "low": 2,
    "info": 3,
}


def interesting_executables_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    rules_path: str | None = None,
) -> dict[str, Any]:
    db.get_case(case_id)
    rules_config = load_interesting_executable_rules(rules_path)
    rules = rules_config.get("interesting_executables") or []
    execution = execution_report(db, case_id, limit=max(limit * 10, 1000))
    candidates = [
        *_interesting_execution_candidates(execution.get("events"), evidence_type="execution"),
        *_interesting_execution_candidates(execution.get("process_activity"), evidence_type="process_activity"),
        *_interesting_execution_candidates(execution.get("presence_indicators"), evidence_type="presence"),
        *_interesting_installed_application_candidates(db, case_id, limit=max(limit * 20, 1000)),
        *_interesting_mft_candidates(db, case_id, rules, limit=max(limit * 20, 1000)),
    ]
    evidence_rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for candidate in candidates:
        for rule in rules:
            matched_terms = _interesting_rule_match_terms(rule, candidate)
            if not matched_terms:
                continue
            key = (
                str(rule.get("id") or ""),
                str(candidate.get("evidence_type") or ""),
                str(candidate.get("source_table") or ""),
                str(candidate.get("source_row_id") or candidate.get("path") or candidate.get("application") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            evidence_rows.append(
                {
                    "rule_id": rule.get("id"),
                    "label": rule.get("label"),
                    "category": rule.get("category"),
                    "severity": rule.get("severity"),
                    "evidence_type": candidate.get("evidence_type"),
                    "timestamp_utc": candidate.get("timestamp_utc"),
                    "application": candidate.get("application"),
                    "executable_name": candidate.get("executable_name"),
                    "display_path": candidate.get("display_path"),
                    "source_table": candidate.get("source_table"),
                    "source_row_id": candidate.get("source_row_id"),
                    "event_type": candidate.get("event_type"),
                    "matched_terms": matched_terms,
                    "description": rule.get("description"),
                    "details": candidate.get("details") or {},
                }
            )
    evidence_rows.sort(
        key=lambda row: (
            INTERESTING_SEVERITY_RANK.get(str(row.get("severity") or "medium"), 9),
            INTERESTING_EVIDENCE_RANK.get(str(row.get("evidence_type") or ""), 9),
            str(row.get("label") or "").casefold(),
            _timestamp_sort_key(row.get("timestamp_utc")),
        )
    )
    grouped = _interesting_executable_groups(evidence_rows)
    return {
        "case_id": case_id,
        "filters": {
            "limit": limit,
            "rules_path": rules_path or "default",
            "rules_loaded": len(rules),
        },
        "summary": {
            "matched_rule_count": len(grouped),
            "evidence_count": len(evidence_rows),
            "execution_evidence_count": sum(1 for row in evidence_rows if row["evidence_type"] == "execution"),
            "process_activity_count": sum(1 for row in evidence_rows if row["evidence_type"] == "process_activity"),
            "presence_count": sum(1 for row in evidence_rows if row["evidence_type"] == "presence"),
            "installed_application_count": sum(1 for row in evidence_rows if row["evidence_type"] == "installed_application"),
            "file_system_count": sum(1 for row in evidence_rows if row["evidence_type"] == "file_system"),
        },
        "applications": grouped[:limit],
        "evidence": evidence_rows[: max(limit * 5, limit)],
        "total_returned": len(grouped[:limit]),
    }


def interesting_executables_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    applications = report.get("applications") if isinstance(report.get("applications"), list) else []
    lines = [
        "# Interesting Executables And Applications",
        "",
        f"Case: `{report.get('case_id') or ''}`",
        f"Rules: `{(report.get('filters') or {}).get('rules_path') or 'default'}`",
        "",
        "## Summary",
        "",
        f"- Matched rules: `{summary.get('matched_rule_count', 0)}`",
        f"- Evidence rows: `{summary.get('evidence_count', 0)}`",
        f"- Execution/use evidence: `{summary.get('execution_evidence_count', 0)}`",
        f"- Process/service activity records: `{summary.get('process_activity_count', 0)}`",
        f"- Presence indicators: `{summary.get('presence_count', 0)}`",
        f"- Installed application indicators: `{summary.get('installed_application_count', 0)}`",
        f"- File system hits: `{summary.get('file_system_count', 0)}`",
        "",
        "## Matches",
        "",
    ]
    if not applications:
        lines.append("- No configured interesting executables or applications were found.")
    for app in applications:
        if not isinstance(app, dict):
            continue
        run_text = "yes" if app.get("has_run_evidence") else "no"
        lines.append(
            f"- `{app.get('severity') or ''}` `{app.get('label') or ''}` "
            f"category `{app.get('category') or ''}` run/process evidence `{run_text}`"
        )
        lines.append(
            f"  - evidence: execution `{app.get('execution_evidence_count') or 0}`, "
            f"process `{app.get('process_activity_count') or 0}`, presence `{app.get('presence_count') or 0}`, "
            f"installed `{app.get('installed_application_count') or 0}`, file system `{app.get('file_system_count') or 0}`"
        )
        if app.get("first_seen_utc") or app.get("last_seen_utc"):
            lines.append(f"  - first/last: `{app.get('first_seen_utc') or ''}` / `{app.get('last_seen_utc') or ''}`")
        if app.get("description"):
            lines.append(f"  - note: {app.get('description')}")
        samples = app.get("evidence_samples") if isinstance(app.get("evidence_samples"), list) else []
        for sample in samples[:5]:
            lines.append(
                f"  - `{sample.get('evidence_type') or ''}` `{sample.get('timestamp_utc') or ''}` "
                f"`{sample.get('source_table') or ''}` `{sample.get('application') or sample.get('executable_name') or ''}` "
                f"path `{sample.get('display_path') or ''}`"
            )
    return "\n".join(lines).rstrip() + "\n"


def _interesting_execution_candidates(rows: Any, *, evidence_type: str) -> list[dict[str, Any]]:
    output = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        path = row.get("display_path") or display_evidence_path(row.get("path")) or row.get("path")
        application = row.get("application") or row.get("description") or _basename_from_path(path)
        output.append(
            {
                "evidence_type": evidence_type,
                "timestamp_utc": row.get("timestamp_utc"),
                "application": application,
                "executable_name": _basename_from_path(path) or _basename_from_path(application) or application,
                "display_path": display_evidence_path(path),
                "source_table": row.get("source_table"),
                "source_row_id": row.get("source_row_id"),
                "event_type": row.get("event_type") or row.get("indicator_type"),
                "details": row.get("details") if isinstance(row.get("details"), dict) else {},
            }
        )
    return output


def _interesting_installed_application_candidates(db: Database, case_id: str, *, limit: int) -> list[dict[str, Any]]:
    rows = _query_report_rows(
        db,
        case_id,
        "registry_artifacts",
        """
        SELECT id, key_path, key_last_write_utc, source_path, value_name, value_data
        FROM registry_artifacts
        WHERE case_id = ?
          AND artifact = 'installed_applications'
          AND LOWER(COALESCE(value_name, '')) IN ('displayname', 'displayversion', 'publisher', 'installlocation', 'displayicon', 'uninstallstring')
        ORDER BY key_path, row_number
        LIMIT ?
        """,
        (case_id, limit),
    )
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("key_path") or row.get("id") or "")
        item = grouped.setdefault(
            key,
            {
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("key_last_write_utc"),
                "source_path": row.get("source_path"),
                "key_path": key,
                "values": {},
            },
        )
        value_name = str(row.get("value_name") or "").casefold()
        if value_name:
            item["values"][value_name] = row.get("value_data")
    output = []
    for item in grouped.values():
        values = item["values"]
        app = values.get("displayname") or _basename_from_path(values.get("displayicon")) or _basename_from_path(values.get("uninstallstring"))
        path = values.get("installlocation") or values.get("displayicon") or values.get("uninstallstring")
        if not app and not path:
            continue
        output.append(
            {
                "evidence_type": "installed_application",
                "timestamp_utc": item.get("timestamp_utc"),
                "application": app,
                "executable_name": _basename_from_path(path) or _basename_from_path(app) or app,
                "display_path": display_evidence_path(path),
                "source_table": "registry_artifacts",
                "source_row_id": item.get("source_row_id"),
                "event_type": "installed_application",
                "details": {
                    "key_path": item.get("key_path"),
                    "source_file": display_evidence_path(item.get("source_path")),
                    "publisher": values.get("publisher"),
                    "display_version": values.get("displayversion"),
                },
            }
        )
    return output


def _interesting_mft_candidates(db: Database, case_id: str, rules: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    filenames = sorted({name for rule in rules for name in (rule.get("filenames") or []) if name})
    if not filenames:
        return []
    placeholders = ",".join("?" for _ in filenames)
    rows = _query_report_rows(
        db,
        case_id,
        "mft_entries",
        f"""
        SELECT id, computer_id, image_id, tool_name, source_csv, row_number,
               parent_path, file_name, extension, in_use, is_directory,
               created_si, modified_si, accessed_si, record_changed_si
        FROM mft_entries
        WHERE case_id = ?
          AND LOWER(COALESCE(file_name, '')) IN ({placeholders})
        ORDER BY COALESCE(modified_si, created_si, accessed_si, '') DESC, file_name
        LIMIT ?
        """,
        [case_id, *filenames, limit],
    )
    output = []
    for row in rows:
        path = _join_windows_path(row.get("parent_path"), row.get("file_name"))
        output.append(
            {
                "evidence_type": "file_system",
                "timestamp_utc": row.get("modified_si") or row.get("created_si") or row.get("accessed_si"),
                "application": row.get("file_name"),
                "executable_name": row.get("file_name"),
                "display_path": display_evidence_path(path),
                "source_table": "mft_entries",
                "source_row_id": row.get("id"),
                "event_type": "file_exists",
                "details": {
                    "in_use": row.get("in_use"),
                    "is_directory": row.get("is_directory"),
                    "created_si": row.get("created_si"),
                    "modified_si": row.get("modified_si"),
                    "accessed_si": row.get("accessed_si"),
                    "record_changed_si": row.get("record_changed_si"),
                    "source_file": row.get("source_csv"),
                    "row_number": row.get("row_number"),
                },
            }
        )
    return output


def _interesting_rule_match_terms(rule: dict[str, Any], candidate: dict[str, Any]) -> list[str]:
    allowed_evidence = {str(value).casefold() for value in (rule.get("evidence_types") or [])}
    evidence_type = str(candidate.get("evidence_type") or "").casefold()
    if allowed_evidence and evidence_type not in allowed_evidence:
        return []
    filename = _interesting_filename(candidate)
    name_values = [
        candidate.get("application"),
        candidate.get("executable_name"),
    ]
    path_values = [
        candidate.get("display_path"),
    ]
    text_values = [
        *name_values,
        *path_values,
        candidate.get("event_type"),
    ]
    details = candidate.get("details") if isinstance(candidate.get("details"), dict) else {}
    text_values.extend(str(value) for value in details.values() if value not in (None, ""))
    name_haystack = " ".join(str(value or "") for value in name_values).casefold()
    path_haystack = " ".join(str(value or "") for value in path_values).casefold()
    text_haystack = " ".join(str(value or "") for value in text_values).casefold()
    matched: list[str] = []
    if filename and filename in set(rule.get("filenames") or []):
        matched.append(f"filename:{filename}")
    for term in rule.get("name_contains") or []:
        lowered = str(term).casefold()
        if lowered and lowered in name_haystack:
            matched.append(f"name_contains:{term}")
    for term in rule.get("path_contains") or []:
        lowered = str(term).casefold()
        if lowered and lowered in path_haystack:
            matched.append(f"path_contains:{term}")
    for term in rule.get("text_contains") or []:
        lowered = str(term).casefold()
        if lowered and lowered in text_haystack:
            matched.append(f"text_contains:{term}")
    for pattern in rule.get("regex") or []:
        try:
            if re.search(str(pattern), text_haystack, re.IGNORECASE):
                matched.append(f"regex:{pattern}")
        except re.error:
            continue
    return sorted(set(matched))


def _interesting_filename(candidate: dict[str, Any]) -> str:
    for key in ("executable_name", "display_path", "application"):
        value = candidate.get(key)
        basename = _basename_from_path(value)
        text = str(basename or value or "").strip().strip("\"'").casefold()
        if "." in text:
            return text
    return ""


def _interesting_executable_groups(evidence_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in evidence_rows:
        rule_id = str(row.get("rule_id") or "")
        item = grouped.setdefault(
            rule_id,
            {
                "rule_id": rule_id,
                "label": row.get("label"),
                "category": row.get("category"),
                "severity": row.get("severity"),
                "description": row.get("description"),
                "has_run_evidence": False,
                "execution_evidence_count": 0,
                "process_activity_count": 0,
                "presence_count": 0,
                "installed_application_count": 0,
                "file_system_count": 0,
                "sources": set(),
                "applications": set(),
                "paths": set(),
                "first_seen_utc": None,
                "last_seen_utc": None,
                "evidence_samples": [],
            },
        )
        evidence_type = str(row.get("evidence_type") or "")
        if evidence_type == "execution":
            item["execution_evidence_count"] += 1
            item["has_run_evidence"] = True
        elif evidence_type == "process_activity":
            item["process_activity_count"] += 1
            item["has_run_evidence"] = True
        elif evidence_type == "presence":
            item["presence_count"] += 1
        elif evidence_type == "installed_application":
            item["installed_application_count"] += 1
        elif evidence_type == "file_system":
            item["file_system_count"] += 1
        if row.get("source_table"):
            item["sources"].add(row["source_table"])
        if row.get("application"):
            item["applications"].add(row["application"])
        if row.get("display_path"):
            item["paths"].add(row["display_path"])
        timestamp = row.get("timestamp_utc")
        if timestamp:
            text = str(timestamp)
            if item["first_seen_utc"] is None or text < item["first_seen_utc"]:
                item["first_seen_utc"] = text
            if item["last_seen_utc"] is None or text > item["last_seen_utc"]:
                item["last_seen_utc"] = text
        if len(item["evidence_samples"]) < 10:
            item["evidence_samples"].append(row)
    output = []
    for item in grouped.values():
        row = dict(item)
        row["sources"] = sorted(row["sources"])
        row["applications"] = sorted(row["applications"], key=str.casefold)
        row["paths"] = sorted(row["paths"], key=str.casefold)
        output.append(row)
    output.sort(
        key=lambda row: (
            INTERESTING_SEVERITY_RANK.get(str(row.get("severity") or "medium"), 9),
            0 if row.get("has_run_evidence") else 1,
            str(row.get("label") or "").casefold(),
        )
    )
    return output


def execution_correlation_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    rows = db.conn.execute(
        """
        WITH execution_sources AS (
          SELECT 'prefetch' AS source_table,
                 id AS source_id,
                 executable_name AS executable,
                 prefetch_name AS display_name,
                 last_run_time_utc AS event_time_utc,
                 NULL AS user_name,
                 artifact_path AS path,
                 run_count AS run_count,
                 source_csv AS source_file
          FROM prefetch_items
          WHERE case_id = ?
          UNION ALL
          SELECT 'registry_artifacts' AS source_table,
                 id AS source_id,
                 COALESCE(NULLIF(normalized_path, ''), NULLIF(display_name, ''), NULLIF(value_data, ''), value_name) AS executable,
                 artifact AS display_name,
                 COALESCE(event_time_utc, key_last_write_utc) AS event_time_utc,
                 COALESCE(user_profile, user_sid) AS user_name,
                 COALESCE(NULLIF(normalized_path, ''), NULLIF(value_data, ''), NULLIF(value_name, ''), key_path) AS path,
                 NULL AS run_count,
                 source_path AS source_file
          FROM registry_artifacts
          WHERE case_id = ?
            AND artifact IN ('bam', 'dam', 'autostart')
            AND (
              COALESCE(normalized_path, '') != ''
              OR lower(COALESCE(value_data, '') || ' ' || COALESCE(value_name, '')) LIKE '%.exe%'
              OR lower(COALESCE(value_data, '') || ' ' || COALESCE(value_name, '')) LIKE '%.dll%'
              OR lower(COALESCE(value_data, '') || ' ' || COALESCE(value_name, '')) LIKE '%.bat%'
              OR lower(COALESCE(value_data, '') || ' ' || COALESCE(value_name, '')) LIKE '%.cmd%'
              OR lower(COALESCE(value_data, '') || ' ' || COALESCE(value_name, '')) LIKE '%.ps1%'
            )
        )
        SELECT LOWER(COALESCE(NULLIF(path, ''), NULLIF(executable, ''), display_name)) AS correlation_key,
               COALESCE(NULLIF(path, ''), NULLIF(executable, ''), display_name) AS path,
               executable,
               COUNT(*) AS evidence_count,
               COUNT(DISTINCT source_table) AS source_count,
               GROUP_CONCAT(DISTINCT source_table) AS sources,
               GROUP_CONCAT(DISTINCT user_name) AS users,
               MIN(event_time_utc) AS first_seen_utc,
               MAX(event_time_utc) AS last_seen_utc,
               MAX(CAST(COALESCE(run_count, '0') AS INTEGER)) AS max_run_count
        FROM execution_sources
        WHERE COALESCE(NULLIF(path, ''), NULLIF(executable, ''), display_name) IS NOT NULL
        GROUP BY LOWER(COALESCE(NULLIF(path, ''), NULLIF(executable, ''), display_name))
        ORDER BY source_count DESC, evidence_count DESC, last_seen_utc DESC
        LIMIT ?
        """,
        (case_id, case_id, limit),
    ).fetchall()
    correlations = [dict(row) for row in rows]
    return {
        "case_id": case_id,
        "execution_correlations": correlations,
        "total_returned": len(correlations),
    }


def persistence_report(db: Database, case_id: str, *, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    artifacts = {
        "autostart",
        "startup_approved",
        "services",
        "scheduled_task_cache",
        "wmi_persistence",
        "winlogon_persistence",
        "image_file_execution_options",
        "appinit_dlls",
    }
    placeholders = ",".join("?" for _ in artifacts)
    rows = db.conn.execute(
        f"""
        SELECT registry_artifacts.*, computers.label AS computer_label, images.path AS image_path
        FROM registry_artifacts
        LEFT JOIN computers ON registry_artifacts.computer_id = computers.id
        LEFT JOIN images ON registry_artifacts.image_id = images.id
        WHERE registry_artifacts.case_id = ?
          AND registry_artifacts.artifact IN ({placeholders})
        ORDER BY registry_artifacts.artifact,
                 COALESCE(registry_artifacts.event_time_utc, registry_artifacts.key_last_write_utc) DESC,
                 registry_artifacts.key_path,
                 registry_artifacts.value_name
        LIMIT ?
        """,
        [case_id, *sorted(artifacts), limit],
    ).fetchall()
    items = [dict(row) for row in rows]
    counts: dict[str, int] = {}
    for row in items:
        counts[row["artifact"]] = counts.get(row["artifact"], 0) + 1
    return {
        "case_id": case_id,
        "summary": {"artifact_counts": [{"artifact": key, "count": value} for key, value in sorted(counts.items())]},
        "persistence_items": items,
        "total_returned": len(items),
    }


def autostarts_report(db: Database, case_id: str, *, limit: int = 1000) -> dict[str, Any]:
    db.get_case(case_id)
    artifacts = sorted(MALWARE_REPORT_KNOWN_AUTOSTART_ARTIFACT_LABELS)
    placeholders = ",".join("?" for _ in artifacts)
    rows = _query_report_rows(
        db,
        case_id,
        "registry_artifacts",
        f"""
        SELECT *
        FROM registry_artifacts
        WHERE case_id = ?
          AND artifact IN ({placeholders})
        ORDER BY artifact,
                 COALESCE(event_time_utc, key_last_write_utc) DESC,
                 key_path,
                 value_name
        LIMIT ?
        """,
        [case_id, *artifacts, max(limit * 20, 5000)],
    )
    items: list[dict[str, Any]] = []
    scheduled_task_groups: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for row in rows:
        item = dict(row)
        if not _autostart_report_include_row(item):
            continue
        if str(item.get("artifact") or "").casefold() == "scheduled_task_cache":
            _merge_scheduled_task_autostart_group(scheduled_task_groups, item)
            continue
        item["autostart_location"] = _malware_known_autostart_location(item)
        item["timestamp_utc"] = item.get("event_time_utc") or item.get("key_last_write_utc")
        item["source_path"] = display_evidence_path(item.get("source_path"))
        item["image_path"] = display_evidence_path(item.get("image_path"))
        item["value_preview"] = _sanitize_report_inline(_truncate_middle(str(item.get("value_data") or ""), 180))
        location = str(item.get("autostart_location") or item.get("artifact") or "unknown")
        counts[location] = counts.get(location, 0) + 1
        items.append(item)
    scheduled_items = sorted(
        (_scheduled_task_autostart_item(group) for group in scheduled_task_groups.values()),
        key=lambda item: item.get("timestamp_utc") or "",
        reverse=True,
    )
    for item in scheduled_items:
        items.append(item)
    items.sort(key=_autostart_report_sort_key)
    items = items[:limit]
    counts = {}
    for item in items:
        location = str(item.get("autostart_location") or item.get("artifact") or "unknown")
        counts[location] = counts.get(location, 0) + 1
    scheduled_task_count = sum(1 for item in items if item.get("artifact") == "scheduled_task_cache")
    return {
        "case_id": case_id,
        "summary": {
            "total_items": len(items),
            "scheduled_task_items": scheduled_task_count,
            "autostart_location_counts": [
                {"autostart_location": key, "count": value}
                for key, value in sorted(counts.items())
            ],
        },
        "autostarts": items,
        "total_returned": len(items),
    }


def autostarts_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    rows = report.get("autostarts") if isinstance(report.get("autostarts"), list) else []
    lines = [
        "# Autostarts And Scheduled Tasks",
        "",
        f"Case: `{report.get('case_id') or ''}`",
        "",
        "## Summary",
        "",
        f"- Total items returned: `{summary.get('total_items', 0)}`",
        f"- Scheduled task items: `{summary.get('scheduled_task_items', 0)}`",
        "",
    ]
    counts = summary.get("autostart_location_counts") if isinstance(summary.get("autostart_location_counts"), list) else []
    if counts:
        lines.extend(["## Location Counts", ""])
        for row in counts:
            if isinstance(row, dict):
                lines.append(f"- `{row.get('autostart_location') or ''}`: `{row.get('count') or 0}`")
        lines.append("")
    lines.extend(["## Items", ""])
    if not rows:
        lines.append("- No autostart or scheduled task registry items were found.")
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(
            f"- `{row.get('timestamp_utc') or ''}` `{row.get('autostart_location') or row.get('artifact') or ''}` "
            f"`{row.get('value_name') or ''}`"
        )
        lines.append(
            f"  - key `{row.get('key_path') or ''}`; value `{row.get('value_preview') or ''}`"
        )
        if row.get("task_path") or row.get("task_action"):
            lines.append(
                f"  - task_path `{row.get('task_path') or ''}`; action `{row.get('task_action') or ''}`"
            )
    return "\n".join(lines).rstrip() + "\n"


def _merge_scheduled_task_autostart_group(groups: dict[str, dict[str, Any]], row: dict[str, Any]) -> None:
    key = str(row.get("key_path") or row.get("id") or "")
    group = groups.setdefault(
        key,
        {
            "artifact": "scheduled_task_cache",
            "category": row.get("category"),
            "key_path": row.get("key_path"),
            "values": {},
            "source_path": row.get("source_path"),
            "image_path": row.get("image_path"),
            "timestamp_utc": row.get("event_time_utc") or row.get("key_last_write_utc"),
            "ids": [],
        },
    )
    timestamp = row.get("event_time_utc") or row.get("key_last_write_utc")
    if timestamp and (not group.get("timestamp_utc") or str(timestamp) > str(group.get("timestamp_utc"))):
        group["timestamp_utc"] = timestamp
    value_name = str(row.get("value_name") or "")
    group["values"][value_name.casefold()] = row.get("value_data")
    group["ids"].append(row.get("id"))


def _scheduled_task_autostart_item(group: dict[str, Any]) -> dict[str, Any]:
    values = group.get("values") if isinstance(group.get("values"), dict) else {}
    task_path = _sanitize_report_inline(values.get("path") or values.get("uri") or "")
    action = _sanitize_report_inline(_truncate_middle(str(values.get("actions") or ""), 220))
    triggers = _sanitize_report_inline(_truncate_middle(str(values.get("triggers") or ""), 120))
    preview_parts = []
    if task_path:
        preview_parts.append(f"path={task_path}")
    if action:
        preview_parts.append(f"action={action}")
    if triggers:
        preview_parts.append(f"triggers={triggers}")
    return {
        "source_table": "registry_artifacts",
        "source_row_ids": [item for item in group.get("ids", []) if item],
        "artifact": "scheduled_task_cache",
        "category": group.get("category"),
        "autostart_location": "Scheduled Task Cache",
        "timestamp_utc": group.get("timestamp_utc"),
        "key_path": group.get("key_path"),
        "value_name": "Task",
        "value_preview": "; ".join(preview_parts),
        "task_path": task_path,
        "task_action": action,
        "task_triggers_preview": triggers,
        "source_path": display_evidence_path(group.get("source_path")),
        "image_path": display_evidence_path(group.get("image_path")),
    }


def _autostart_report_sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
    priority = {
        "Run/RunOnce": 0,
        "Scheduled Task Cache": 1,
        "Windows service": 2,
        "StartupApproved": 3,
        "Winlogon": 4,
        "AppInit DLLs": 5,
        "Image File Execution Options": 6,
        "COM autostart": 7,
        "WMI persistence": 8,
    }
    location = str(item.get("autostart_location") or "")
    timestamp = str(item.get("timestamp_utc") or "")
    key_path = str(item.get("key_path") or "")
    return (priority.get(location, 99), _reverse_sort_text(timestamp), key_path)


def _reverse_sort_text(value: str) -> str:
    return "".join(chr(0x10FFFF - ord(char)) for char in value)


def _autostart_report_include_row(row: dict[str, Any]) -> bool:
    artifact = str(row.get("artifact") or "").casefold()
    value_name = str(row.get("value_name") or "").casefold()
    allowed_names = AUTOSTART_REPORT_VALUE_NAMES_BY_ARTIFACT.get(artifact)
    if allowed_names is None:
        return artifact in AUTOSTART_REPORT_VALUE_NAMES_BY_ARTIFACT
    return value_name in {name.casefold() for name in allowed_names}


UNUSUAL_EXECUTION_PATH_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"/users/[^/]+/appdata/local/temp/", "user_temp"),
    (r"/users/[^/]+/appdata/local/microsoft/windows/inetcache/", "browser_cache"),
    (r"/users/[^/]+/appdata/local/microsoft/windows/temporary internet files/", "browser_cache"),
    (r"/users/[^/]+/appdata/roaming/", "user_roaming_profile"),
    (r"/users/[^/]+/downloads/", "downloads"),
    (r"/users/[^/]+/desktop/", "desktop"),
    (r"/users/public/", "public_profile"),
    (r"/programdata/", "programdata"),
    (r"/windows/temp/", "windows_temp"),
    (r"/windows/tasks/", "windows_tasks"),
    (r"/perflogs/", "perflogs"),
    (r"/\$recycle\.bin/", "recycle_bin"),
)


EXECUTABLE_OR_SCRIPT_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".msi",
    ".msp",
    ".cpl",
    ".lnk",
}


MALWARE_REPORT_BENIGN_PATH_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"/programdata/microsoft/windows defender/", "windows_defender_platform"),
    (r"/programdata/microsoft/windows defender advanced threat protection/", "windows_defender_atp"),
)

MALWARE_REPORT_BENIGN_FILE_NAMES = {
    "msmpeng.exe",
    "nissrv.exe",
    "mpcmdrun.exe",
    "msascuil.exe",
    "smartscreen.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
}

MALWARE_REPORT_IGNORED_REGISTRY_ARTIFACTS = {
    "amcache",
    "bam",
    "capability_access_manager",
    "common_dialog",
    "connected_networks",
    "dam",
    "installed_applications",
    "office_recent_docs",
    "office_trusted_documents",
    "office_trusted_locations",
    "ras_connection_manager",
    "ras_phonebook_registry",
    "recentdocs",
    "shellbags",
    "taskbar_feature_usage",
    "taskbar_usage",
    "typed_paths",
    "userassist",
    "wordwheel_query",
}

MALWARE_REPORT_REGISTRY_ARTIFACTS_OF_INTEREST = {
    "appinit_dlls",
    "autostart",
    "com_autostart",
    "image_file_execution_options",
    "runmru",
    "scheduled_task_cache",
    "services",
    "startup_approved",
    "winlogon_persistence",
    "wmi_persistence",
}

MALWARE_REPORT_KNOWN_AUTOSTART_ARTIFACT_LABELS = {
    "appinit_dlls": "AppInit DLLs",
    "autostart": "Run/RunOnce",
    "com_autostart": "COM autostart",
    "image_file_execution_options": "Image File Execution Options",
    "scheduled_task_cache": "Scheduled Task Cache",
    "services": "Windows service",
    "startup_approved": "StartupApproved",
    "winlogon_persistence": "Winlogon",
    "wmi_persistence": "WMI persistence",
}

AUTOSTART_REPORT_VALUE_NAMES_BY_ARTIFACT = {
    "appinit_dlls": {"appinit_dlls", "loadappinit_dlls", "requiresignedappinit_dlls"},
    "autostart": None,
    "com_autostart": {"(default)", ""},
    "image_file_execution_options": {"debugger", "verifierdlls", "globalflag", "usefilter"},
    "scheduled_task_cache": {"actions", "path", "uri", "triggers"},
    "services": {"imagepath", "servicedll", "dependservice", "start", "type"},
    "startup_approved": None,
    "winlogon_persistence": {"shell", "userinit", "vmApplet", "taskman", "system"},
    "wmi_persistence": None,
}

MALWARE_REPORT_REGISTRY_KEY_TOKENS_OF_INTEREST = (
    "appinit_dlls",
    "browser helper objects",
    "currentversion\\run",
    "currentversion/run",
    "currentversion\\runonce",
    "currentversion/runonce",
    "image file execution options",
    "schedule\\taskcache",
    "schedule/taskcache",
    "shellexecutehooks",
    "shellserviceobjectdelayload",
    "startupapproved",
    "winlogon",
    "\\services\\",
    "/services/",
    "\\wbem\\",
    "/wbem/",
)

MALWARE_REPORT_EXECUTION_IGNORED_EVENT_TYPES = {
    "registry_userassist",
}

MALWARE_REPORT_COMMAND_VALUE_NAMES = {
    "actions",
    "appinit_dlls",
    "command",
    "debugger",
    "dependservice",
    "dllname",
    "imagepath",
    "objectname",
    "script",
    "serviceDll",
    "servicedll",
    "shell",
    "task",
    "userinit",
}

MALWARE_REPORT_COMMAND_TEXT_TOKENS = (
    " -enc",
    " -encodedcommand",
    " -nop",
    " -w hidden",
    "bitsadmin",
    "certutil",
    "cmd.exe",
    "downloadfile",
    "downloadstring",
    "frombase64string",
    "http://",
    "https://",
    "iex",
    "mshta",
    "powershell",
    "regsvr32",
    "rundll32",
    "scriptblock",
    "wscript",
)

MALWARE_REPORT_BENIGN_REGISTRY_VALUE_PATTERNS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (
        "scheduled_task_cache",
        (
            r"%windir%\\system32\\rundll32\.exe.*\\pcasvc\.dll,pcapatchsdbtask",
            r"%windir%\\system32\\rundll32\.exe.*dfdts\.dll,dfdgetdefaultpolicyandsmart",
        ),
        "known_windows_scheduled_task_action",
    ),
)


def malware_hiding_places_report(
    db: Database,
    case_id: str,
    *,
    limit: int = 100,
    long_value_threshold: int = 300,
) -> dict[str, Any]:
    db.get_case(case_id)
    execution = execution_report(db, case_id, limit=max(limit, 250))
    autostart_references = _malware_autostart_references(db, case_id)
    unusual_rows = _malware_unusual_execution_rows(execution, autostart_references=autostart_references)
    registry_rows, registry_suppressed_counts = _malware_registry_value_rows(
        db,
        case_id,
        limit=limit,
        long_value_threshold=long_value_threshold,
    )
    unusual_rows = unusual_rows[:limit]
    registry_rows = registry_rows[:limit]
    severity_counts: dict[str, int] = {}
    for item in [*unusual_rows, *registry_rows]:
        severity = str(item.get("severity") or "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    source_counts: dict[str, int] = {}
    for item in unusual_rows:
        source = str(item.get("source_table") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
    return {
        "case_id": case_id,
        "filters": {
            "limit": limit,
            "long_value_threshold": long_value_threshold,
        },
        "summary": {
            "unusual_execution_location_count": len(unusual_rows),
            "long_or_encoded_registry_value_count": len(registry_rows),
            "severity_counts": [{"severity": key, "count": value} for key, value in sorted(severity_counts.items())],
            "unusual_execution_source_counts": [
                {"source_table": key, "count": value}
                for key, value in sorted(source_counts.items())
            ],
            "suppressed_registry_value_counts": [
                {"reason": key, "count": value}
                for key, value in sorted(registry_suppressed_counts.items())
            ],
        },
        "unusual_execution_locations": unusual_rows,
        "registry_value_indicators": registry_rows,
        "total_returned": len(unusual_rows) + len(registry_rows),
    }


def malware_hiding_places_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    unusual = report.get("unusual_execution_locations") if isinstance(report.get("unusual_execution_locations"), list) else []
    registry = report.get("registry_value_indicators") if isinstance(report.get("registry_value_indicators"), list) else []
    lines = [
        "# Potential Malware Hiding Places",
        "",
        f"Case: `{report.get('case_id') or ''}`",
        "",
        "## Summary",
        "",
        f"- Unusual execution/persistence locations: `{summary.get('unusual_execution_location_count', 0)}`",
        f"- Long or encoded registry values: `{summary.get('long_or_encoded_registry_value_count', 0)}`",
        "",
    ]
    suppressed_counts = summary.get("suppressed_registry_value_counts")
    if isinstance(suppressed_counts, list) and suppressed_counts:
        lines.extend(["## Suppressed Registry Value Noise", ""])
        for row in suppressed_counts:
            if isinstance(row, dict):
                lines.append(f"- `{row.get('reason') or ''}`: `{row.get('count') or 0}`")
        lines.append("")
    lines.extend(["## Unusual Execution Or Persistence Locations", ""])
    if not unusual:
        lines.append("- No unusual execution or persistence locations were found by the current rules.")
    for row in unusual:
        if not isinstance(row, dict):
            continue
        lines.append(
            f"- `{row.get('timestamp_utc') or ''}` `{row.get('severity') or ''}` "
            f"`{row.get('source_table') or ''}` `{row.get('event_type') or row.get('indicator_type') or ''}` "
            f"`{row.get('application') or row.get('description') or ''}` path `{row.get('display_path') or ''}`"
        )
        detail_values = {
            "reason": row.get("reason"),
            "category": row.get("location_category"),
            "source": row.get("source_file"),
            "registry_key": row.get("registry_key"),
        }
        autostart_ref_count = len(row.get("autostart_references") or [])
        if autostart_ref_count:
            detail_values["autostart_refs"] = autostart_ref_count
        detail_bits = [f"{key}={value}" for key, value in detail_values.items() if value not in (None, "")]
        if detail_bits:
            lines.append("  - " + "; ".join(detail_bits))
    lines.extend(["", "## Long Or Encoded Registry Values", ""])
    if not registry:
        lines.append("- No long or base64-looking registry values were found by the current rules.")
    for row in registry:
        if not isinstance(row, dict):
            continue
        flags = ",".join(row.get("flags") or [])
        lines.append(
            f"- `{row.get('timestamp_utc') or ''}` `{row.get('severity') or ''}` "
            f"`{row.get('artifact') or ''}` `{row.get('value_name') or ''}` flags `{flags}`"
        )
        lines.append(
            f"  - key `{row.get('key_path') or ''}`; chars `{row.get('value_length') or 0}`; "
            f"autostart `{row.get('autostart_location') or 'not_known_autostart'}`; "
            f"preview `{row.get('value_preview') or ''}`"
        )
    return "\n".join(lines).rstrip() + "\n"


def _malware_unusual_execution_rows(
    execution: dict[str, Any],
    *,
    autostart_references: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    autostart_references = autostart_references or {}
    for source_name in ("events", "process_activity"):
        rows = execution.get(source_name) if isinstance(execution.get(source_name), list) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("event_type") or "").casefold() in MALWARE_REPORT_EXECUTION_IGNORED_EVENT_TYPES:
                continue
            path = str(row.get("display_path") or display_evidence_path(row.get("path")) or "")
            category = _unusual_execution_location(path)
            if not category:
                continue
            if not _path_looks_executable_or_script(path, row.get("application") or row.get("description")):
                continue
            benign_reason = _malware_report_benign_suppression_reason(path, row.get("application") or row.get("description"))
            if benign_reason:
                continue
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            source_table = str(row.get("source_table") or "")
            reason = f"Executable/script observed from unusual location category `{category}`."
            severity = "high" if source_table in {"prefetch_items", "registry_runmru", "evtx_events"} else "medium"
            if source_table in {"amcache_entries", "shimcache_entries"}:
                reason += " Source is presence/cache metadata, not execution proof."
            normalized_path = _normalize_artifact_path(path)
            autostart_matches = autostart_references.get(normalized_path.casefold(), [])
            candidates.append(
                {
                    "severity": severity,
                    "location_category": category,
                    "timestamp_utc": row.get("timestamp_utc"),
                    "source_table": source_table,
                    "source_row_id": row.get("source_row_id"),
                    "event_type": row.get("event_type"),
                    "indicator_type": row.get("indicator_type"),
                    "application": row.get("application"),
                    "description": row.get("description"),
                    "display_path": path,
                    "normalized_path": normalized_path,
                    "source_file": _short_case_path(display_evidence_path(details.get("source_file")) or details.get("source_file")),
                    "registry_key": details.get("key_path") or details.get("source_key"),
                    "autostart_references": autostart_matches,
                    "reason": reason,
                }
            )
    candidates.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("severity")), 9),
            item.get("location_category") or "",
            item.get("display_path") or "",
            item.get("timestamp_utc") or "",
        )
    )
    return _dedupe_malware_indicator_rows(candidates)


def _malware_registry_value_rows(
    db: Database,
    case_id: str,
    *,
    limit: int,
    long_value_threshold: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows = _query_report_rows(
        db,
        case_id,
        "registry_artifacts",
        """
        SELECT id, source_path, hive_type, artifact, category, key_path,
               key_last_write_utc, event_time_utc, value_name, value_type,
               value_data, display_name, normalized_path
        FROM registry_artifacts
        WHERE case_id = ?
          AND COALESCE(value_data, '') != ''
        ORDER BY COALESCE(event_time_utc, key_last_write_utc, '') DESC, artifact, key_path
        LIMIT ?
        """,
        (case_id, max(limit * 20, 1000)),
    )
    indicators: list[dict[str, Any]] = []
    suppressed_counts: dict[str, int] = {}
    for row in rows:
        suppression_reason = _malware_registry_suppression_reason(row)
        if suppression_reason:
            suppressed_counts[suppression_reason] = suppressed_counts.get(suppression_reason, 0) + 1
            continue
        value_data = str(row.get("value_data") or "")
        flags = _registry_value_indicator_flags(value_data, long_value_threshold=long_value_threshold)
        if not flags:
            continue
        if (
            "base64_decodable" not in flags
            and not _malware_registry_command_text_is_useful(row, flags)
            and not _malware_registry_long_value_name_is_command(row, flags)
        ):
            continue
        autostart_location = _malware_known_autostart_location(row)
        benign_reason = _malware_report_benign_registry_value_reason(row)
        if benign_reason:
            suppressed_counts[benign_reason] = suppressed_counts.get(benign_reason, 0) + 1
            continue
        severity = "high" if "base64_decodable" in flags and "long_value" in flags else "medium"
        indicators.append(
            {
                "severity": severity,
                "source_table": "registry_artifacts",
                "source_row_id": row.get("id"),
                "timestamp_utc": row.get("event_time_utc") or row.get("key_last_write_utc"),
                "source_path": display_evidence_path(row.get("source_path")),
                "hive_type": row.get("hive_type"),
                "artifact": row.get("artifact"),
                "category": row.get("category"),
                "key_path": row.get("key_path"),
                "value_name": row.get("value_name"),
                "value_type": row.get("value_type"),
                "value_length": len(value_data),
                "value_preview": _sanitize_report_inline(_truncate_middle(value_data, 160)),
                "flags": flags,
                "autostart_location": autostart_location,
                "known_autostart_location": autostart_location is not None,
            }
        )
    indicators.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("severity")), 9),
            -(item.get("value_length") or 0),
            item.get("artifact") or "",
        )
    )
    return indicators[:limit], suppressed_counts


def _malware_registry_suppression_reason(row: dict[str, Any]) -> str | None:
    artifact = str(row.get("artifact") or "").casefold()
    category = str(row.get("category") or "").casefold()
    key_path = str(row.get("key_path") or "").replace("/", "\\").casefold()
    if artifact in MALWARE_REPORT_IGNORED_REGISTRY_ARTIFACTS:
        return f"parsed_legitimate_registry_artifact:{artifact}"
    if category == "user_activity":
        return "parsed_user_activity_registry_artifact"
    if artifact in MALWARE_REPORT_REGISTRY_ARTIFACTS_OF_INTEREST:
        return None
    if any(token in key_path for token in MALWARE_REPORT_REGISTRY_KEY_TOKENS_OF_INTEREST):
        return None
    return "registry_artifact_not_persistence_or_command_source"


def _malware_known_autostart_location(row: dict[str, Any]) -> str | None:
    artifact = str(row.get("artifact") or "").casefold()
    label = MALWARE_REPORT_KNOWN_AUTOSTART_ARTIFACT_LABELS.get(artifact)
    if label:
        return label
    key_path = str(row.get("key_path") or "").replace("/", "\\").casefold()
    if "\\currentversion\\runonce" in key_path:
        return "RunOnce"
    if "\\currentversion\\run" in key_path:
        return "Run"
    if "\\schedule\\taskcache" in key_path:
        return "Scheduled Task Cache"
    if "\\services\\" in key_path:
        return "Windows service"
    if "\\image file execution options\\" in key_path:
        return "Image File Execution Options"
    if "\\windows nt\\currentversion\\winlogon" in key_path:
        return "Winlogon"
    return None


def _malware_report_benign_registry_value_reason(row: dict[str, Any]) -> str | None:
    artifact = str(row.get("artifact") or "").casefold()
    value = str(row.get("value_data") or "").casefold()
    normalized_value = value.replace("/", "\\")
    for pattern_artifact, patterns, reason in MALWARE_REPORT_BENIGN_REGISTRY_VALUE_PATTERNS:
        if artifact != pattern_artifact:
            continue
        if any(re.search(pattern, normalized_value, re.IGNORECASE) for pattern in patterns):
            return reason
    return None


def _malware_autostart_references(db: Database, case_id: str) -> dict[str, list[dict[str, Any]]]:
    artifacts = sorted(MALWARE_REPORT_KNOWN_AUTOSTART_ARTIFACT_LABELS)
    placeholders = ",".join("?" for _ in artifacts)
    rows = _query_report_rows(
        db,
        case_id,
        "registry_artifacts",
        f"""
        SELECT id, artifact, key_path, value_name, value_data, normalized_path,
               key_last_write_utc, event_time_utc
        FROM registry_artifacts
        WHERE case_id = ?
          AND artifact IN ({placeholders})
          AND (
            COALESCE(normalized_path, '') != ''
            OR COALESCE(value_data, '') != ''
          )
        """,
        [case_id, *artifacts],
    )
    refs: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        item = dict(row)
        location = _malware_known_autostart_location(item)
        paths = _candidate_paths_from_registry_value(item)
        for path in paths:
            normalized = _normalize_artifact_path(path)
            if not normalized:
                continue
            refs.setdefault(normalized.casefold(), []).append(
                {
                    "source_table": "registry_artifacts",
                    "source_row_id": item.get("id"),
                    "artifact": item.get("artifact"),
                    "autostart_location": location,
                    "key_path": item.get("key_path"),
                    "value_name": item.get("value_name"),
                    "timestamp_utc": item.get("event_time_utc") or item.get("key_last_write_utc"),
                }
            )
    return refs


def _candidate_paths_from_registry_value(row: dict[str, Any]) -> list[str]:
    candidates = [
        str(row.get("normalized_path") or ""),
        str(row.get("value_data") or ""),
    ]
    paths: list[str] = []
    for value in candidates:
        if not value:
            continue
        paths.extend(re.findall(r"[A-Za-z]:[\\/][^\"'\s|<>]+", value))
        paths.extend(re.findall(r"\\Device\\HarddiskVolume\d+\\[^\"'\s|<>]+", value, flags=re.IGNORECASE))
        if not paths and _path_looks_executable_or_script(value):
            paths.append(value)
    return paths


def _unusual_execution_location(path: str) -> str | None:
    normalized = display_evidence_path(path).replace("\\", "/").casefold()
    if not normalized:
        return None
    for pattern, category in UNUSUAL_EXECUTION_PATH_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return category
    return None


def _path_looks_executable_or_script(path: str, fallback: Any = None) -> bool:
    text = f"{path} {fallback or ''}".casefold()
    return any(ext in text for ext in EXECUTABLE_OR_SCRIPT_EXTENSIONS)


def _malware_report_benign_suppression_reason(path: str, fallback: Any = None) -> str | None:
    text = display_evidence_path(path).replace("\\", "/").casefold()
    file_name = (_basename_from_path(text) or str(fallback or "")).casefold()
    for pattern, reason in MALWARE_REPORT_BENIGN_PATH_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return reason
    if file_name in MALWARE_REPORT_BENIGN_FILE_NAMES and "microsoft" in text:
        return "known_microsoft_security_binary"
    return None


def _registry_value_indicator_flags(value: str, *, long_value_threshold: int) -> list[str]:
    flags: list[str] = []
    compact = re.sub(r"\s+", "", value)
    if len(value) >= long_value_threshold:
        flags.append("long_value")
    lowered = value.casefold()
    if any(token in lowered for token in MALWARE_REPORT_COMMAND_TEXT_TOKENS):
        flags.append("command_or_script_text")
    compact_is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", compact or "")) and len(compact) % 2 == 0
    if len(compact) >= 80 and _looks_like_base64(compact):
        flags.append("base64_decodable")
    elif len(compact) >= 80 and not compact_is_hex and re.fullmatch(r"[A-Za-z0-9+/=]+", compact or ""):
        flags.append("base64_like")
    return flags


def _looks_like_base64(value: str) -> bool:
    if re.fullmatch(r"[0-9a-fA-F]+", value or "") and len(value) % 2 == 0:
        return False
    if len(value) % 4 != 0:
        value = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(decoded) < 32:
        return False
    return _decoded_base64_has_text_signal(decoded)


def _decoded_base64_has_text_signal(decoded: bytes) -> bool:
    decoded_variants: list[str] = []
    for encoding in ("utf-8", "utf-16-le", "latin-1"):
        try:
            decoded_variants.append(decoded.decode(encoding, errors="ignore"))
        except LookupError:
            continue
    for text in decoded_variants:
        lowered = text.casefold()
        if any(token.strip().casefold() in lowered for token in MALWARE_REPORT_COMMAND_TEXT_TOKENS):
            return True
        printable = sum(1 for char in text if char.isprintable() or char.isspace())
        alphabetic = sum(1 for char in text if char.isalpha())
        if text and printable / max(len(text), 1) >= 0.75 and alphabetic >= 8 and (" " in text or "\\" in text or "/" in text):
            return True
    return False


def _malware_registry_command_text_is_useful(row: dict[str, Any], flags: list[str]) -> bool:
    if "command_or_script_text" not in flags:
        return False
    artifact = str(row.get("artifact") or "").casefold()
    if artifact in {"autostart", "runmru", "scheduled_task_cache"}:
        return True
    return _malware_registry_value_name_is_command_context(row)


def _malware_registry_long_value_name_is_command(row: dict[str, Any], flags: list[str]) -> bool:
    if "long_value" not in flags:
        return False
    return _malware_registry_value_name_is_command_context(row)


def _malware_registry_value_name_is_command_context(row: dict[str, Any]) -> bool:
    value_name = str(row.get("value_name") or "").casefold()
    return value_name in {name.casefold() for name in MALWARE_REPORT_COMMAND_VALUE_NAMES}


def _truncate_middle(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    half = max(1, (max_length - 5) // 2)
    return f"{value[:half]} ... {value[-half:]}"


def _sanitize_report_inline(value: Any) -> str:
    text = str(value or "")
    return "".join(char if char.isprintable() or char in "\t " else "." for char in text)


def _dedupe_malware_indicator_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in rows:
        key = (
            str(row.get("source_table") or ""),
            str(row.get("source_row_id") or ""),
            str(row.get("display_path") or "").casefold(),
            str(row.get("location_category") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def shortcuts_report(db: Database, case_id: str, *, artifact_type: str | None = None, limit: int = 100) -> dict[str, Any]:
    db.get_case(case_id)
    params: list[Any] = [case_id]
    where = "WHERE shortcut_items.case_id = ?"
    if artifact_type:
        where += " AND shortcut_items.artifact_type = ?"
        params.append(artifact_type)
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT shortcut_items.*, computers.label AS computer_label, images.path AS image_path
        FROM shortcut_items
        LEFT JOIN computers ON shortcut_items.computer_id = computers.id
        LEFT JOIN images ON shortcut_items.image_id = images.id
        {where}
        ORDER BY shortcut_items.artifact_type, shortcut_items.artifact_path, shortcut_items.row_number
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {"case_id": case_id, "shortcuts": [dict(row) for row in rows], "total_returned": len(rows)}


def _artifact_counts(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], int] = {}
    for artifact in artifacts:
        metadata = json.loads(artifact["metadata_json"])
        count = int(metadata.get("count", 1))
        key = (artifact["image_id"], artifact["name"])
        counts[key] = counts.get(key, 0) + count
    return [
        {"image_id": image_id, "artifact": artifact, "count": count}
        for (image_id, artifact), count in sorted(counts.items())
    ]


def _evtx_recovery_counts(db: Database, case_id: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT status, COUNT(*) AS count,
                   SUM(COALESCE(parser_rows_recovered, 0)) AS parser_rows_recovered
            FROM evtx_recovery
            WHERE case_id = ?
            GROUP BY status
            ORDER BY status
            """,
            (case_id,),
        ).fetchall()
    ]


def _artifact_attempts(db: Database, case_id: str) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT jobs.tool_name,
               COUNT(*) AS attempts,
               SUM(CASE WHEN jobs.exit_code = 0 THEN 1 ELSE 0 END) AS completed,
               SUM(CASE WHEN jobs.exit_code IS NULL OR jobs.exit_code != 0 THEN 1 ELSE 0 END) AS failed_or_unfinished,
               COUNT(DISTINCT tool_outputs.id) AS outputs,
               COALESCE(SUM(tool_outputs.row_count), 0) AS output_rows,
               MIN(jobs.start_time) AS first_started,
               MAX(jobs.end_time) AS last_finished
        FROM jobs
        LEFT JOIN tool_outputs ON tool_outputs.job_id = jobs.id
        WHERE jobs.case_id = ?
        GROUP BY jobs.tool_name
        ORDER BY jobs.tool_name
        """,
        (case_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _database_table_rows(db: Database, *, case_id: str | None) -> list[dict[str, Any]]:
    tables = [
        row["name"]
        for row in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    ]
    output = []
    for table in tables:
        if case_id and _table_has_column(db, table, "case_id"):
            count = db.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE case_id = ?", (case_id,)).fetchone()["count"]
        elif case_id:
            continue
        else:
            count = db.conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
        output.append({"table": table, "row_count": int(count)})
    return output


def _database_object_sizes(db: Database) -> dict[str, dict[str, int]]:
    try:
        rows = db.conn.execute(
            """
            SELECT name, SUM(pgsize) AS bytes, COUNT(*) AS pages
            FROM dbstat
            GROUP BY name
            """
        ).fetchall()
    except Exception:
        return {}
    return {row["name"]: {"bytes": int(row["bytes"] or 0), "pages": int(row["pages"] or 0)} for row in rows}


def _content_heavy_storage(db: Database, case_id: str | None) -> list[dict[str, Any]]:
    rows = []
    for item in CONTENT_HEAVY_TABLES:
        table = item["table"]
        if not _table_exists(db, table):
            continue
        if case_id and _table_has_column(db, table, "case_id"):
            row_count = db.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE case_id = ?", (case_id,)).fetchone()["count"]
        elif case_id:
            continue
        else:
            row_count = db.conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
        rows.append(
            {
                "table": table,
                "row_count": int(row_count),
                "large_columns": list(item["large_columns"]),
                "policy": item["policy"],
                "sqlite_role": item["sqlite_role"],
            }
        )
    return rows


def _duplicate_tool_outputs(db: Database, case_id: str | None) -> list[dict[str, Any]]:
    where = "WHERE content_sha256 IS NOT NULL AND content_sha256 != ''"
    params: list[Any] = []
    if case_id:
        where += " AND case_id = ?"
        params.append(case_id)
    rows = db.conn.execute(
        f"""
        SELECT tool_name, content_sha256, COUNT(*) AS copies,
               GROUP_CONCAT(id) AS tool_output_ids,
               GROUP_CONCAT(path) AS paths
        FROM tool_outputs
        {where}
        GROUP BY tool_name, content_sha256
        HAVING COUNT(*) > 1
        ORDER BY copies DESC, tool_name
        LIMIT 100
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def _table_count(db: Database, table: str, case_id: str) -> int:
    if not _table_exists(db, table) or not _table_has_column(db, table, "case_id"):
        return 0
    return int(db.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE case_id = ?", (case_id,)).fetchone()["count"])


def _count(
    db: Database,
    table: str,
    case_id: str,
    *,
    user_filter: tuple[str, str | None] | None = None,
) -> int:
    where = "case_id = ?"
    params: list[Any] = [case_id]
    if user_filter and user_filter[1]:
        where += f" AND {user_filter[0]} LIKE ?"
        params.append(user_filter[1])
    return int(db.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {where}", params).fetchone()["count"])


def _table_exists(db: Database, table: str) -> bool:
    row = db.conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _table_has_column(db: Database, table: str, column: str) -> bool:
    if not _table_exists(db, table):
        return False
    return any(row["name"] == column for row in db.conn.execute(f"PRAGMA table_info({table})").fetchall())


def _tool_output_bytes(db: Database, case_id: str) -> dict[str, Any]:
    rows = db.conn.execute(
        """
        SELECT id, tool_name, output_type, path, row_count
        FROM tool_outputs
        WHERE case_id = ?
        ORDER BY created_at DESC
        """,
        (case_id,),
    ).fetchall()
    total_size = 0
    existing_files = 0
    missing_files = 0
    by_tool: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = Path(row["path"]) if row["path"] else None
        size = path.stat().st_size if path and path.exists() and path.is_file() else 0
        if size:
            existing_files += 1
            total_size += size
        else:
            missing_files += 1
        tool = row["tool_name"] or "unknown"
        item = by_tool.setdefault(tool, {"tool_name": tool, "output_count": 0, "existing_file_count": 0, "estimated_bytes": 0, "row_count": 0})
        item["output_count"] += 1
        item["existing_file_count"] += 1 if size else 0
        item["estimated_bytes"] += size
        item["row_count"] += int(row["row_count"] or 0)
    return {
        "tool_output_count": len(rows),
        "existing_file_count": existing_files,
        "missing_or_non_file_count": missing_files,
        "estimated_bytes": total_size,
        "by_tool": sorted(by_tool.values(), key=lambda item: (-item["estimated_bytes"], item["tool_name"])),
    }


def _count_timeline(db: Database, case_id: str, event_type: str) -> int:
    return int(
        db.conn.execute(
            "SELECT COUNT(*) AS count FROM timeline_events WHERE case_id = ? AND event_type = ?",
            (case_id, event_type),
        ).fetchone()["count"]
    )


def _count_evtx_logons(db: Database, case_id: str, user_like: str | None) -> int:
    where = "case_id = ? AND event_id IN ('4624', '4625', '4634', '4647', '4778', '4779')"
    params: list[Any] = [case_id]
    if user_like:
        where += " AND (user_name LIKE ? OR payload LIKE ?)"
        params.extend([user_like, user_like])
    return int(db.conn.execute(f"SELECT COUNT(*) AS count FROM evtx_events WHERE {where}", params).fetchone()["count"])


def _count_registry_activity(db: Database, case_id: str, user_like: str | None) -> int:
    total = 0
    for table, _key in sorted(set(REGISTRY_ACTIVITY_TABLES.values())):
        where = "case_id = ?"
        params: list[Any] = [case_id]
        if user_like:
            where += " AND (user_profile LIKE ? OR hive_path LIKE ? OR key_path LIKE ?)"
            params.extend([user_like, user_like, user_like])
        total += int(db.conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {where}", params).fetchone()["count"])
    return total


def _recent_prefetch(db: Database, case_id: str, *, limit: int) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in db.conn.execute(
            """
            SELECT executable_name, prefetch_name, run_count, last_run_time_utc, artifact_path
            FROM prefetch_items
            WHERE case_id = ?
            ORDER BY last_run_time_utc DESC
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
    ]


def _recent_shortcuts(db: Database, case_id: str, user_like: str | None, *, limit: int) -> list[dict[str, Any]]:
    where = "case_id = ?"
    params: list[Any] = [case_id]
    if user_like:
        where += " AND (artifact_path LIKE ? OR file_location LIKE ? OR file_name LIKE ?)"
        params.extend([user_like, user_like, user_like])
    params.append(limit)
    return [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT artifact_type, artifact_name, file_name, file_location,
                   target_created, target_modified, target_accessed, artifact_path
            FROM shortcut_items
            WHERE {where}
            ORDER BY COALESCE(target_accessed, target_modified, target_created) DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    ]


def _recent_browser(db: Database, case_id: str, user_like: str | None, *, limit: int) -> list[dict[str, Any]]:
    where = "case_id = ?"
    params: list[Any] = [case_id]
    if user_like:
        where += " AND profile_path LIKE ?"
        params.append(user_like)
    params.append(limit)
    return [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT visit_time_utc, url, title, profile_path
            FROM firefox_history
            WHERE {where}
            ORDER BY visit_time_utc DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    ]


def _recent_logons(db: Database, case_id: str, user_like: str | None, *, limit: int) -> list[dict[str, Any]]:
    where = "case_id = ? AND event_id IN ('4624', '4625', '4634', '4647', '4778', '4779')"
    params: list[Any] = [case_id]
    if user_like:
        where += " AND (user_name LIKE ? OR payload LIKE ?)"
        params.extend([user_like, user_like])
    params.append(limit)
    return [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT time_created, event_id, provider, channel, user_name, computer,
                   map_description, payload_data1, payload_data2, payload_data3, source_file
            FROM evtx_events
            WHERE {where}
            ORDER BY time_created DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    ]


def _recent_recycle(db: Database, case_id: str, user_like: str | None, *, limit: int) -> list[dict[str, Any]]:
    where = "case_id = ?"
    params: list[Any] = [case_id]
    if user_like:
        where += " AND (original_path LIKE ? OR source_path LIKE ?)"
        params.extend([user_like, user_like])
    params.append(limit)
    return [
        dict(row)
        for row in db.conn.execute(
            f"""
            SELECT deletion_time_utc, display_name, original_path, recycled_path,
                   file_size, is_directory
            FROM recycle_items
            WHERE {where}
            ORDER BY deletion_time_utc DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    ]


def _correlations_for_mft_entry(db: Database, mft_entry_id: str) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT * FROM file_correlations
        WHERE mft_entry_id = ?
        ORDER BY confidence DESC, match_type, source_path
        """,
        (mft_entry_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _browser_noise_filter_sql(host_expr: str, url_expr: str) -> str:
    noisy = [
        "doubleclick.",
        "googlesyndication.",
        "google-analytics.",
        "analytics.",
        "adnxs.",
        "adsystem.",
        "ads.",
        "adsrvr.",
        "pubmatic.",
        "mxptint.",
        "bidswitch.",
        "bidr.",
        "mathtag.",
        "rubiconproject.",
        "rlcdn.",
        "zeotap.",
        "dotomi.",
        "adform.",
        "casalemedia.",
        "openx.",
        "criteo.",
        "taboola.",
        "outbrain.",
        "scorecardresearch.",
        "facebook.net",
        "connect.facebook.",
        "yahoo.com/sync",
        "cookie",
        "usersync",
        "pixel",
    ]
    clauses = [
        f"LOWER(COALESCE({host_expr}, '')) NOT LIKE '%{needle}%'"
        for needle in noisy
        if "/" not in needle
    ]
    clauses.extend(
        f"LOWER(COALESCE({url_expr}, '')) NOT LIKE '%{needle}%'"
        for needle in noisy
    )
    return "(" + " AND ".join(clauses) + ")"


def _webcache_filtered_report(
    db: Database,
    case_id: str,
    *,
    table: str,
    key: str,
    limit: int,
    application: str | None,
    user: str | None,
    exclude_metadata: bool,
) -> dict[str, Any]:
    db.get_case(case_id)
    where = [f"{table}.case_id = ?"]
    params: list[Any] = [case_id]
    if application:
        where.append(f"LOWER(COALESCE({table}.application, '')) LIKE LOWER(?)")
        params.append(f"%{application}%")
    if user:
        where.append(f"LOWER(COALESCE({table}.user_name, '')) = LOWER(?)")
        params.append(user)
    if exclude_metadata:
        where.append(
            f"""
            COALESCE({table}.url, '') NOT LIKE 'MicrosoftEdge_iecompat:%'
            AND COALESCE({table}.url, '') NOT LIKE 'MicrosoftEdge_iecompatua:%'
            AND COALESCE({table}.url, '') NOT LIKE 'MicrosoftEdge_ieflipahead:%'
            AND COALESCE({table}.source_table, '') NOT LIKE 'MSysObjects%'
            AND COALESCE({table}.source_table, '') NOT LIKE 'CookieEntry%'
            AND COALESCE({table}.source_table, '') NOT LIKE 'BlobEntry%'
            AND COALESCE({table}.source_table, '') NOT LIKE 'DependencyEntry%'
            """
        )
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT {table}.*, computers.label AS computer_label, images.path AS image_path
        FROM {table}
        LEFT JOIN computers ON {table}.computer_id = computers.id
        LEFT JOIN images ON {table}.image_id = images.id
        WHERE {' AND '.join(where)}
        ORDER BY COALESCE({table}.accessed_utc, {table}.modified_utc, {table}.created_utc, {table}.created_at) DESC,
                 {table}.row_number DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": {
            "application": application,
            "user": user,
            "exclude_metadata": exclude_metadata,
            "table": table,
        },
        key: [dict(row) for row in rows],
        "total_returned": len(rows),
    }


def _usb_overlaps_for_time(
    db: Database,
    case_id: str,
    image_id: str | None,
    timestamp_utc: str | None,
    local_path: str | None,
) -> list[dict[str, Any]]:
    if not timestamp_utc:
        return []
    params: list[Any] = [case_id]
    image_filter = ""
    if image_id:
        image_filter = "AND start_event.image_id = ?"
        params.append(image_id)
    params.append(timestamp_utc)
    params.append(timestamp_utc)
    rows = db.conn.execute(
        f"""
        SELECT start_event.serial, start_event.volume_serial_number, start_event.volume_guid,
               start_event.drive_letter, start_event.event_time_utc AS session_start,
               COALESCE(
                 (
                   SELECT MIN(end_event.event_time_utc)
                   FROM usb_connection_events end_event
                   WHERE end_event.case_id = start_event.case_id
                     AND end_event.image_id = start_event.image_id
                     AND end_event.serial = start_event.serial
                     AND end_event.event_type = 'removal'
                     AND end_event.event_time_utc >= start_event.event_time_utc
                 ),
                 start_event.event_time_utc
               ) AS session_end,
               usb_storage_devices.volume_name,
               usb_storage_devices.product,
               usb_storage_devices.vendor
        FROM usb_connection_events start_event
        LEFT JOIN usb_storage_devices
          ON usb_storage_devices.id = start_event.usb_device_id
        WHERE start_event.case_id = ?
          {image_filter}
          AND start_event.event_type IN ('arrival', 'first_connected', 'partition_seen')
          AND start_event.event_time_utc <= ?
          AND COALESCE(
                (
                  SELECT MIN(end_event.event_time_utc)
                  FROM usb_connection_events end_event
                  WHERE end_event.case_id = start_event.case_id
                    AND end_event.image_id = start_event.image_id
                    AND end_event.serial = start_event.serial
                    AND end_event.event_type = 'removal'
                    AND end_event.event_time_utc >= start_event.event_time_utc
                ),
                start_event.event_time_utc
              ) >= ?
        ORDER BY start_event.event_time_utc DESC
        LIMIT 10
        """,
        params,
    ).fetchall()
    drive = (local_path or "")[:2].upper() if re.match(r"^[A-Za-z]:", local_path or "") else None
    overlaps = []
    for row in rows:
        item = dict(row)
        item["drive_letter_match"] = bool(drive and (item.get("drive_letter") or "").upper().startswith(drive))
        overlaps.append(item)
    return overlaps


def _mft_matches_for_path(db: Database, case_id: str, image_id: str | None, target_path: str | None) -> list[dict[str, Any]]:
    normalized = _normalize_windows_path(target_path)
    filename = _basename(target_path)
    if not normalized or not filename:
        return []
    params: list[Any] = [case_id, filename]
    image_clause = ""
    if image_id:
        image_clause = "AND image_id = ?"
        params.append(image_id)
    rows = db.conn.execute(
        f"""
        SELECT id, entry_number, in_use, parent_path, file_name, file_size,
               created_si, modified_si, accessed_si
        FROM mft_entries
        WHERE case_id = ? AND LOWER(file_name) = LOWER(?) {image_clause}
        LIMIT 100
        """,
        params,
    ).fetchall()
    matches = []
    for row in rows:
        item = dict(row)
        candidate = _normalize_windows_path((item.get("parent_path") or "") + "/" + (item.get("file_name") or ""))
        if candidate and (candidate.endswith(normalized) or normalized.endswith(candidate)):
            matches.append(item)
    return matches[:10]


def _usb_matches_for_path(db: Database, case_id: str, target_path: str | None) -> list[dict[str, Any]]:
    normalized = _normalize_windows_path(target_path)
    filename = _basename(target_path)
    if not normalized or not filename:
        return []
    rows = db.conn.execute(
        """
        SELECT usb_serial, usb_volume_serial_number, usb_volume_name, usb_drive_letter,
               file_name, file_location, source_artifact_type, target_created, target_modified
        FROM usb_file_correlations
        WHERE case_id = ? AND LOWER(file_name) = LOWER(?)
        LIMIT 100
        """,
        (case_id, filename),
    ).fetchall()
    matches = []
    for row in rows:
        item = dict(row)
        candidate = _normalize_windows_path(item.get("file_location"))
        if candidate and (candidate.endswith(normalized) or normalized.endswith(candidate)):
            matches.append(item)
    return matches[:10]


def _normalize_windows_path(path: str | None) -> str | None:
    if not path:
        return None
    text = path.replace("\\", "/").strip().lower()
    text = re.sub(r"^[a-z]:/", "", text)
    text = re.sub(r"^\./", "", text)
    return text.strip("/") or None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    normalized = path.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1] if normalized else None


def _table_report(db: Database, case_id: str, table: str, key: str, limit: int) -> dict[str, Any]:
    db.get_case(case_id)
    duck_rows = _duckdb_table_rows(db, case_id, table, limit)
    if duck_rows is not None:
        return {"case_id": case_id, key: duck_rows, "total_returned": len(duck_rows)}

    duplicate_filter = _artifact_duplicate_filter(table)
    rows = db.conn.execute(
        f"""
        SELECT {table}.*, computers.label AS computer_label, images.path AS image_path,
               {_artifact_source_count_sql(table)} AS source_count
        FROM {table}
        LEFT JOIN computers ON {table}.computer_id = computers.id
        LEFT JOIN images ON {table}.image_id = images.id
        WHERE {table}.case_id = ?
          {duplicate_filter}
        ORDER BY {table}.created_at, {table}.row_number
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    return {"case_id": case_id, key: [dict(row) for row in rows], "total_returned": len(rows)}


def _duckdb_table_rows(db: Database, case_id: str, table: str, limit: int) -> list[dict[str, Any]] | None:
    if not _safe_identifier(table):
        raise ValueError(f"Unsafe report table name: {table}")
    db_path = _duckdb_path_for_case(db, case_id)
    if not db_path.exists():
        return None
    conn, should_close = _duckdb_report_connection(db, case_id, db_path)
    try:
        if not _duckdb_table_exists(conn, table):
            return None
        duplicate_ids = _duplicate_row_ids(db, table)
        rows: list[dict[str, Any]] = []
        fetch_limit = max(limit, min(limit * 5, 5000))
        result = conn.execute(
            f"""
            SELECT *
            FROM {_quote_identifier(table)}
            WHERE case_id = ?
            ORDER BY created_at, row_number
            LIMIT ?
            """,
            [case_id, fetch_limit],
        ).fetchdf()
        computer_labels = _computer_labels(db, case_id)
        image_paths = _image_paths(db, case_id)
        source_counts = _source_counts(db, table)
        for item in result.to_dict("records"):
            row_id = str(item.get("id") or "")
            if row_id and row_id in duplicate_ids:
                continue
            computer_id = item.get("computer_id")
            image_id = item.get("image_id")
            item["computer_label"] = computer_labels.get(str(computer_id)) if computer_id else None
            item["image_path"] = image_paths.get(str(image_id)) if image_id else None
            item["source_count"] = source_counts.get(row_id, 0) if row_id else 0
            rows.append(item)
            if len(rows) >= limit:
                break
        return rows
    finally:
        if should_close:
            conn.close()


def _query_report_rows(
    db: Database,
    case_id: str,
    table: str,
    sql: str,
    params: tuple[Any, ...] | list[Any],
) -> list[dict[str, Any]]:
    if _duckdb_table_available(db, case_id, table):
        db_path = _duckdb_path_for_case(db, case_id)
        conn, should_close = _duckdb_report_connection(db, case_id, db_path)
        try:
            result = conn.execute(sql, list(params))
            names = [column[0] for column in result.description or []]
            return [dict(zip(names, row, strict=False)) for row in result.fetchall()]
        finally:
            if should_close:
                conn.close()
    rows = db.conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def _report_table_columns(db: Database, case_id: str, table: str) -> set[str]:
    if _duckdb_table_available(db, case_id, table):
        db_path = _duckdb_path_for_case(db, case_id)
        conn, should_close = _duckdb_report_connection(db, case_id, db_path)
        try:
            return {str(row[1]) for row in conn.execute(f"PRAGMA table_info('{table}')").fetchall()}
        finally:
            if should_close:
                conn.close()
    return {str(row["name"]) for row in db.conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _row_value(row: Any, key: str) -> Any:
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


def _duckdb_table_available(db: Database, case_id: str, table: str) -> bool:
    if not _safe_identifier(table):
        raise ValueError(f"Unsafe report table name: {table}")
    db_path = _duckdb_path_for_case(db, case_id)
    if not db_path.exists():
        return False
    conn, should_close = _duckdb_report_connection(db, case_id, db_path)
    try:
        return _duckdb_table_exists(conn, table)
    finally:
        if should_close:
            conn.close()


def _duckdb_path_for_case(db: Database, case_id: str) -> Path:
    case = db.get_case(case_id)
    return case.root / "analytics" / "events.duckdb"


def _duckdb_report_connection(
    db: Database,
    case_id: str,
    db_path: Path,
) -> tuple[duckdb.DuckDBPyConnection, bool]:
    analytics = getattr(db, "analytics", None)
    if analytics is not None and hasattr(analytics, "_connect"):
        key = str(db_path)
        existing_connections = getattr(analytics, "_connections", {})
        if key in existing_connections:
            return existing_connections[key], False
    return duckdb.connect(str(db_path), read_only=True), True


def _duckdb_table_exists(conn: duckdb.DuckDBPyConnection, table: str) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1",
            [table],
        ).fetchone()
    )


def _safe_identifier(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value))


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _duplicate_row_ids(db: Database, table: str) -> set[str]:
    rows = db.conn.execute(
        """
        SELECT duplicate_row_id
        FROM artifact_record_sources
        WHERE duplicate_table = ? AND source_scope = 'windows_old'
        """,
        (table,),
    ).fetchall()
    return {str(row["duplicate_row_id"]) for row in rows if row["duplicate_row_id"] is not None}


def _source_counts(db: Database, table: str) -> dict[str, int]:
    rows = db.conn.execute(
        """
        SELECT primary_row_id, COUNT(*) AS count
        FROM artifact_record_sources
        WHERE primary_table = ?
        GROUP BY primary_row_id
        """,
        (table,),
    ).fetchall()
    return {str(row["primary_row_id"]): int(row["count"]) for row in rows}


def _computer_labels(db: Database, case_id: str) -> dict[str, str]:
    rows = db.conn.execute("SELECT id, label FROM computers WHERE case_id = ?", (case_id,)).fetchall()
    return {str(row["id"]): row["label"] for row in rows}


def _image_paths(db: Database, case_id: str) -> dict[str, str]:
    rows = db.conn.execute("SELECT id, path FROM images WHERE case_id = ?", (case_id,)).fetchall()
    return {str(row["id"]): row["path"] for row in rows}


def _artifact_duplicate_filter(table: str) -> str:
    return f"AND {_artifact_duplicate_condition(table)}"


def _artifact_duplicate_condition(table: str) -> str:
    return (
        "NOT EXISTS ("
        "SELECT 1 FROM artifact_record_sources ars "
        f"WHERE ars.duplicate_table = '{table}' AND ars.duplicate_row_id = {table}.id "
        "AND ars.source_scope = 'windows_old'"
        ")"
    )


def _artifact_source_count_sql(table: str) -> str:
    return (
        "(SELECT COUNT(*) FROM artifact_record_sources ars "
        f"WHERE ars.primary_table = '{table}' AND ars.primary_row_id = {table}.id)"
    )


def _usn_filtered_report(
    db: Database,
    case_id: str,
    *,
    limit: int,
    path_contains: str | None = None,
    reason_contains: str | None = None,
    order: str = "DESC",
    filters: dict[str, Any] | None = None,
    key: str = "items",
) -> dict[str, Any]:
    db.get_case(case_id)
    where = ["usn_journal_entries.case_id = ?"]
    params: list[Any] = [case_id]
    if path_contains:
        where.append("(usn_journal_entries.full_path LIKE ? OR usn_journal_entries.file_name LIKE ?)")
        params.extend([f"%{path_contains}%", f"%{path_contains}%"])
    if reason_contains:
        where.append("usn_journal_entries.reason LIKE ?")
        params.append(f"%{reason_contains}%")
    direction = "ASC" if order.upper() == "ASC" else "DESC"
    params.append(limit)
    rows = db.conn.execute(
        f"""
        SELECT usn_journal_entries.*, computers.label AS computer_label, images.path AS image_path
        FROM usn_journal_entries
        LEFT JOIN computers ON usn_journal_entries.computer_id = computers.id
        LEFT JOIN images ON usn_journal_entries.image_id = images.id
        WHERE {' AND '.join(where)}
        ORDER BY usn_journal_entries.update_timestamp {direction},
                 usn_journal_entries.update_sequence_number {direction}
        LIMIT ?
        """,
        params,
    ).fetchall()
    return {
        "case_id": case_id,
        "filters": filters or {
            "path_contains": path_contains,
            "reason": reason_contains,
        },
        key: [_compact_usn_row(row) for row in rows],
        "total_returned": len(rows),
    }


def _compact_usn_row(row: Any) -> dict[str, Any]:
    return {
        "computer_id": row["computer_id"],
        "computer_label": row["computer_label"],
        "image_id": row["image_id"],
        "image_path": row["image_path"],
        "update_timestamp": row["update_timestamp"],
        "update_sequence_number": row["update_sequence_number"],
        "file_name": row["file_name"],
        "extension": row["extension"],
        "full_path": row["full_path"],
        "reason": row["reason"],
        "file_attributes": row["file_attributes"],
        "file_reference_number": row["file_reference_number"],
        "parent_file_reference_number": row["parent_file_reference_number"],
    }


def _mft_enrichment(row: Any) -> dict[str, Any] | None:
    if "mft_entry_id" not in row.keys() or row["mft_entry_id"] is None:
        return None
    return {
        "id": row["mft_entry_id"],
        "in_use": row["mft_in_use"],
        "parent_path": row["mft_parent_path"],
        "file_size": row["mft_file_size"],
        "is_directory": row["mft_is_directory"],
        "is_ads": row["mft_is_ads"],
        "created_si": row["mft_created_si"],
        "modified_si": row["mft_modified_si"],
        "record_changed_si": row["mft_record_changed_si"],
        "accessed_si": row["mft_accessed_si"],
    }


def _base_event(row: Any, parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": row["case_id"],
        "computer_id": row["computer_id"],
        "computer_label": row["computer_label"],
        "image_id": row["image_id"],
        "image_path": row["image_path"],
        "tool": row["tool_name"],
        "source_path": parsed.get("source_path") or row["source_path"],
        "row_number": row["row_number"],
    }


def _prefetch_events(row: Any, parsed: dict[str, Any]) -> list[dict[str, Any]]:
    timestamps = _coerce_list(parsed.get("last_run_times_utc"))
    if not timestamps and parsed.get("last_run_time_utc"):
        timestamps = [parsed["last_run_time_utc"]]
    events: list[dict[str, Any]] = []
    for index, timestamp in enumerate(timestamps, start=1):
        if not timestamp:
            continue
        events.append(
            {
                **_base_event(row, parsed),
                "timestamp_utc": timestamp,
                "event_type": "prefetch_last_run",
                "description": parsed.get("executable_name") or parsed.get("prefetch_name"),
                "details": {
                    "run_count": parsed.get("run_count"),
                    "prefetch_name": parsed.get("prefetch_name"),
                    "prefetch_hash": parsed.get("prefetch_hash"),
                    "timestamp_index": index,
                    "timestamp_count": len(timestamps),
                },
            }
        )
    return events


def _prefetch_item_base_event(row: Any) -> dict[str, Any]:
    return {
        "case_id": row["case_id"],
        "computer_id": row["computer_id"],
        "computer_label": row["computer_label"],
        "image_id": row["image_id"],
        "image_path": row["image_path"],
        "tool": row["tool_name"],
        "source_path": row["artifact_path"],
        "row_number": row["row_number"],
    }


def _prefetch_item_events(row: Any) -> list[dict[str, Any]]:
    timestamps = _coerce_list(row["last_run_times_utc"])
    if not timestamps and row["last_run_time_utc"]:
        timestamps = [row["last_run_time_utc"]]
    events: list[dict[str, Any]] = []
    for index, timestamp in enumerate(timestamps, start=1):
        if not timestamp:
            continue
        events.append(
            {
                **_prefetch_item_base_event(row),
                "timestamp_utc": timestamp,
                "event_type": "prefetch_last_run",
                "description": row["executable_name"] or row["prefetch_name"],
                "details": {
                    "run_count": row["run_count"],
                    "prefetch_name": row["prefetch_name"],
                    "prefetch_hash": row["prefetch_hash"],
                    "timestamp_index": index,
                    "timestamp_count": len(timestamps),
                    "pf_created": row["pf_created"],
                    "pf_modified": row["pf_modified"],
                    "pf_accessed": row["pf_accessed"],
                },
            }
        )
    return events


def _evtx_item_events(row: Any) -> list[dict[str, Any]]:
    if not row["time_created"]:
        return []
    description = row["map_description"] or row["provider"] or row["event_id"]
    return [
        {
            "case_id": row["case_id"],
            "computer_id": row["computer_id"],
            "computer_label": row["computer_label"],
            "image_id": row["image_id"],
            "image_path": row["image_path"],
            "tool": row["tool_name"],
            "source_path": row["source_file"],
            "row_number": row["row_number"],
            "timestamp_utc": row["time_created"],
            "event_type": "windows_event_log",
            "description": description,
            "details": {
                "event_id": row["event_id"],
                "level": row["level"],
                "provider": row["provider"],
                "channel": row["channel"],
                "computer": row["computer"],
                "user_name": row["user_name"],
                "remote_host": row["remote_host"],
                "payload_data1": row["payload_data1"],
                "payload_data2": row["payload_data2"],
                "payload_data3": row["payload_data3"],
            },
        }
    ]


def _shortcut_base_event(row: Any) -> dict[str, Any]:
    return {
        "case_id": row["case_id"],
        "computer_id": row["computer_id"],
        "computer_label": row["computer_label"],
        "image_id": row["image_id"],
        "image_path": row["image_path"],
        "tool": row["tool_name"],
        "source_path": row["artifact_path"],
        "row_number": row["row_number"],
    }


def _shortcut_timestamp_events(row: Any) -> list[dict[str, Any]]:
    fields = (
        ("target_created", row["target_created"]),
        ("target_modified", row["target_modified"]),
        ("target_accessed", row["target_accessed"]),
    )
    event_type = "lnk_timestamp" if row["artifact_type"] == "lnk" else "jumplist_timestamp"
    events = []
    for field, timestamp in fields:
        if not timestamp:
            continue
        events.append(
            {
                **_shortcut_base_event(row),
                "timestamp_utc": timestamp,
                "event_type": event_type,
                "description": row["file_location"] or row["file_name"] or row["artifact_name"],
                "details": {"timestamp_field": field},
            }
        )
    return events


def _shortcut_copied_file_indicator_events(row: Any) -> list[dict[str, Any]]:
    created_raw = row["target_created"]
    modified_raw = row["target_modified"]
    created = _parse_timestamp(created_raw)
    modified = _parse_timestamp(modified_raw)
    if created is None or modified is None or created <= modified:
        return []
    return [
        {
            **_shortcut_base_event(row),
            "timestamp_utc": _format_timestamp(created),
            "event_type": "copied_file_indicator",
            "description": row["file_location"] or row["file_name"] or row["artifact_name"],
            "details": {
                "classification": "copied_file",
                "reason": "target creation time is after target modification time",
                "target_created": created_raw,
                "target_modified": modified_raw,
            },
        }
    ]


def _timestamp_field_events(
    row: Any,
    parsed: dict[str, Any],
    fields: tuple[str, ...],
    event_type: str,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for field in fields:
        timestamp = parsed.get(field)
        if not timestamp:
            continue
        events.append(
            {
                **_base_event(row, parsed),
                "timestamp_utc": timestamp,
                "event_type": event_type,
                "description": _best_description(parsed),
                "details": {"timestamp_field": field},
            }
        )
    return events


def _copied_file_indicator_events(row: Any, parsed: dict[str, Any]) -> list[dict[str, Any]]:
    created_raw = _first_value(parsed, TARGET_CREATED_FIELDS)
    modified_raw = _first_value(parsed, TARGET_MODIFIED_FIELDS)
    created = _parse_timestamp(created_raw)
    modified = _parse_timestamp(modified_raw)
    if created is None or modified is None or created <= modified:
        return []
    return [
        {
            **_base_event(row, parsed),
            "timestamp_utc": _format_timestamp(created),
            "event_type": "copied_file_indicator",
            "description": _best_description(parsed),
            "details": {
                "classification": "copied_file",
                "reason": "target creation time is after target modification time",
                "target_created": created_raw,
                "target_modified": modified_raw,
            },
        }
    ]


def _best_description(parsed: dict[str, Any]) -> str | None:
    for key in ("Target", "TargetPath", "Target Path", "Local Path", "Path", "Name", "SourceFile"):
        if parsed.get(key):
            return str(parsed[key])
    return None


def _first_value(parsed: dict[str, Any], fields: tuple[str, ...]) -> Any:
    for field in fields:
        value = parsed.get(field)
        if value:
            return value
    return None


def _parse_timestamp(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(value.strip(), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return [value]
        return parsed if isinstance(parsed, list) else [parsed]
    return [value]


def _json_details(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {"raw": value}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _basename_from_path(path: str | None) -> str | None:
    if not path:
        return None
    parts = re.split(r"[\\/]+", path.rstrip("\\/"))
    return parts[-1] if parts else None


def _history_source_label(source_table: str | None) -> str:
    labels = {
        "mft_entries": "MFT",
        "usn_journal_entries": "USN Journal",
        "ntfs_logfile_entries": "$LogFile",
        "ntfs_index_entries": "$I30",
        "ntfs_namespace_reconciliation": "Namespace Reconciliation",
    }
    return labels.get(source_table or "", source_table or "unknown")


def _timestamp_sort_key(value: Any) -> str:
    return str(value) if value not in (None, "") else "9999-99-99"
