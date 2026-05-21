from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.reports import _parse_report_timestamp


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    name: str
    description: str
    review_value: str = "normal"


RULES: tuple[Rule, ...] = (
    Rule("file.path_convergence", "file", "File Path Convergence", "Multiple artifacts reference the same filesystem object or MFT record.", "high"),
    Rule("file.copied_timestamp_pattern", "file", "Copied File Timestamp Pattern", "A user-facing artifact shows target creation after target modification.", "high"),
    Rule("usb.file_attribution", "usb", "USB File Attribution", "A file artifact is associated with a USB device by volume serial, drive letter, or device metadata.", "high"),
    Rule("execution.convergence", "execution", "Execution Convergence", "Multiple execution artifacts reference the same executable or path.", "high"),
    Rule("app.existing_pairwise", "application", "Existing Pairwise Correlation", "Existing parser-specific pairwise correlation promoted into the grouped framework.", "normal"),
    Rule("web.cloud_webmail_convergence", "web", "Web Cloud/Webmail Convergence", "Cloud storage or webmail activity appears in multiple web, cache, search, or cloud-sync sources.", "high"),
    Rule("session.vpn_rdp_overlap", "session", "VPN/RDP Session Overlap", "A VPN session and RDP session overlap or occur close together.", "high"),
    Rule("file.deleted_still_referenced", "file", "Deleted File Still Referenced", "A file marked deleted or missing from the live namespace is still referenced by user-facing artifacts.", "high"),
    Rule("windows_old.unique_context", "windows_old", "Windows.old Unique Context", "Windows.old contains artifact context that is not duplicated by the current Windows installation.", "medium"),
    Rule("execution.special_tool_usage", "execution", "Special Tool Usage", "Execution evidence references wiping, Tor, or virtualization tools.", "high"),
)


def rebuild_correlation_framework(db: Database, *, case_id: str, image_id: str | None = None) -> dict[str, Any]:
    db.get_case(case_id)
    _seed_rules(db)
    _delete_existing(db, case_id=case_id, image_id=image_id)

    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []

    builders = (
        _file_path_convergence,
        _copied_file_indicators,
        _usb_file_attribution,
        _execution_convergence,
        _web_cloud_webmail_convergence,
        _vpn_rdp_overlap,
        _deleted_file_still_referenced,
        _windows_old_unique_context,
        _special_tool_usage,
        _existing_pairwise_correlations,
    )
    stats: dict[str, int] = {}
    for builder in builders:
        built_groups, built_members, built_interpretations = builder(db, case_id=case_id, image_id=image_id)
        groups.extend(built_groups)
        members.extend(built_members)
        interpretations.extend(built_interpretations)
        if built_groups:
            stats[built_groups[0]["rule_id"]] = len(built_groups)

    _insert_groups(db, groups)
    _insert_members(db, members)
    _insert_interpretations(db, interpretations)
    db.log_activity(
        case_id=case_id,
        image_id=image_id,
        event="correlation_framework.rebuilt",
        message=f"Rebuilt {len(groups)} correlation groups with {len(members)} members",
        details={"image_id": image_id, "groups": len(groups), "members": len(members), "rules": stats},
    )
    db.conn.commit()
    return {
        "case_id": case_id,
        "image_id": image_id,
        "groups": len(groups),
        "members": len(members),
        "interpretations": len(interpretations),
        "rules": stats,
    }


def _file_path_convergence(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    image_filter = "AND file_correlations.image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    rows = _rows(
        db,
        f"""
        SELECT file_correlations.*, mft_entries.file_name, mft_entries.parent_path,
               mft_entries.modified_si, mft_entries.created_si
        FROM file_correlations
        JOIN mft_entries ON mft_entries.id = file_correlations.mft_entry_id
        WHERE file_correlations.case_id = ? {image_filter}
        ORDER BY file_correlations.mft_entry_id, file_correlations.confidence DESC
        """,
        tuple(params),
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["mft_entry_id"]), []).append(row)
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    for mft_id, items in grouped.items():
        source_tables = sorted({str(item["source_table"]) for item in items} | {"mft_entries"})
        if len(source_tables) < 2:
            continue
        first = items[0]
        path = first.get("mft_path") or _join_path(first.get("parent_path"), first.get("file_name"))
        group = _group(
            rule_id="file.path_convergence",
            case_id=first["case_id"],
            computer_id=first["computer_id"],
            image_id=first["image_id"],
            category="file",
            key=f"mft:{mft_id}",
            title=f"File path convergence: {path or first.get('file_name') or mft_id}",
            summary=f"{len(items)} artifact reference(s) converge on one MFT record.",
            review_value="high",
            primary_time=first.get("modified_si") or first.get("created_si"),
            primary_path=path,
            member_count=len(items) + 1,
            source_tables=source_tables,
            details={"mft_entry_id": mft_id, "match_types": sorted({str(item.get("match_type")) for item in items})},
        )
        groups.append(group)
        members.append(_member(group, "mft_entries", mft_id, role="filesystem_record", path=path, event_time=first.get("modified_si"), description="MFT record"))
        for item in items:
            members.append(
                _member(
                    group,
                    item["source_table"],
                    item["source_row_id"],
                    source_tool=item.get("source_tool"),
                    role="referencing_artifact",
                    path=item.get("source_path"),
                    description=item.get("match_type"),
                    details={"confidence": item.get("confidence"), "mft_path": item.get("mft_path")},
                )
            )
        interpretations.append(_interpretation(group, "These rows reference the same file-system record or path. Review source rows before inferring user intent."))
    return groups, members, interpretations


def _copied_file_indicators(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    image_filter = "AND image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    rows = _rows(
        db,
        f"""
        SELECT * FROM copied_file_indicators
        WHERE case_id = ? {image_filter}
          AND source_artifact_type NOT IN ('mft_si', 'mft_fn')
        ORDER BY created_timestamp_utc DESC
        LIMIT 5000
        """,
        tuple(params),
    )
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    for row in rows:
        path = row.get("file_location") or row.get("file_name")
        group = _group(
            rule_id="file.copied_timestamp_pattern",
            case_id=row["case_id"],
            computer_id=row["computer_id"],
            image_id=row["image_id"],
            category="file",
            key=f"copied:{row['id']}",
            title=f"Copied file indicator: {path}",
            summary="Creation timestamp is after modification timestamp in a user-facing artifact.",
            review_value="high",
            primary_time=row.get("created_timestamp_utc"),
            primary_path=path,
            member_count=1,
            source_tables=[row["source_table"], "copied_file_indicators"],
            details={"indicator": row.get("indicator"), "reason": row.get("reason"), "source_artifact_type": row.get("source_artifact_type")},
        )
        groups.append(group)
        members.append(_member(group, "copied_file_indicators", row["id"], source_tool=row.get("source_tool"), role="copied_file_indicator", event_time=row.get("created_timestamp_utc"), path=path, description=row.get("reason")))
        interpretations.append(_interpretation(group, "This is a timestamp-pattern indicator of copying. Treat it as strong file movement evidence when corroborated by the source artifact and filesystem context."))
    return groups, members, interpretations


def _usb_file_attribution(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    image_filter = "AND image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    rows = _rows(db, f"SELECT * FROM usb_file_correlations WHERE case_id = ? {image_filter} ORDER BY file_name LIMIT 10000", tuple(params))
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    for row in rows:
        path = row.get("file_location") or row.get("file_name")
        key = "|".join(str(row.get(part) or "") for part in ("usb_serial", "usb_volume_serial_number", "file_location", "source_artifact_id"))
        group = _group(
            rule_id="usb.file_attribution",
            case_id=row["case_id"],
            computer_id=row["computer_id"],
            image_id=row["image_id"],
            category="usb",
            key=f"usb:{key}",
            title=f"USB file attribution: {path}",
            summary=f"File artifact associated with USB serial {row.get('usb_serial')} / VSN {row.get('usb_volume_serial_number')}.",
            review_value="high",
            primary_time=row.get("target_modified") or row.get("target_created"),
            primary_path=path,
            primary_user=row.get("user_profile"),
            member_count=1,
            source_tables=["usb_file_correlations", str(row.get("source_artifact_type") or "")],
            details={"volume_serial_match": row.get("volume_serial_match"), "confidence": row.get("confidence")},
        )
        groups.append(group)
        members.append(_member(group, "usb_file_correlations", row["id"], role="usb_file_correlation", event_time=row.get("target_modified") or row.get("target_created"), user=row.get("user_profile"), path=path, description=row.get("volume_serial_match")))
        interpretations.append(_interpretation(group, "The artifact contains device or volume metadata that ties the referenced file to removable media. Prefer volume serial matches over drive-letter-only matches."))
    return groups, members, interpretations


def _execution_convergence(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    image_filter = "AND image_id = ?" if image_id else ""
    params = [case_id]
    if image_id:
        params.append(image_id)
    execution_rows = _rows(
        db,
        f"""
        SELECT 'prefetch_items' AS source_table, id, case_id, computer_id, image_id, tool_name,
               executable_name AS executable, artifact_path AS path, last_run_time_utc AS event_time,
               NULL AS user_profile, prefetch_name AS description
        FROM prefetch_items WHERE case_id = ? {image_filter}
        UNION ALL
        SELECT 'registry_artifacts', id, case_id, computer_id, image_id, tool_name,
               COALESCE(NULLIF(normalized_path, ''), NULLIF(display_name, ''), NULLIF(value_data, ''), value_name),
               COALESCE(NULLIF(normalized_path, ''), NULLIF(value_data, ''), key_path),
               COALESCE(event_time_utc, key_last_write_utc), COALESCE(user_profile, user_sid), artifact
        FROM registry_artifacts WHERE case_id = ? {image_filter} AND artifact IN ('bam', 'dam', 'autostart')
        UNION ALL
        SELECT 'amcache_entries', id, case_id, computer_id, image_id, tool_name,
               COALESCE(NULLIF(name, ''), path), path, COALESCE(modified_utc, created_utc, install_date), NULL, entry_type
        FROM amcache_entries WHERE case_id = ? {image_filter}
        UNION ALL
        SELECT 'shimcache_entries', id, case_id, computer_id, image_id, tool_name,
               path, path, last_modified_utc, NULL, executed
        FROM shimcache_entries WHERE case_id = ? {image_filter}
        """,
        tuple(params * 4),
    )
    by_key: dict[str, list[dict[str, Any]]] = {}
    for row in execution_rows:
        key = _norm_path(row.get("path") or row.get("executable"))
        if key and any(ext in key for ext in (".exe", ".dll", ".bat", ".cmd", ".ps1")):
            by_key.setdefault(key, []).append(row)
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    for key, items in by_key.items():
        source_tables = sorted({str(item["source_table"]) for item in items})
        if len(source_tables) < 2:
            continue
        first = items[0]
        times = sorted(str(item.get("event_time") or "") for item in items if item.get("event_time"))
        group = _group(
            rule_id="execution.convergence",
            case_id=first["case_id"],
            computer_id=first["computer_id"],
            image_id=first["image_id"],
            category="execution",
            key=f"exec:{key}",
            title=f"Execution convergence: {first.get('path') or first.get('executable')}",
            summary=f"{len(items)} execution artifact(s) across {len(source_tables)} source type(s).",
            review_value="high",
            primary_time=times[-1] if times else None,
            primary_path=first.get("path") or first.get("executable"),
            primary_user=first.get("user_profile"),
            primary_application=first.get("executable"),
            member_count=len(items),
            source_tables=source_tables,
            details={"first_seen_utc": times[0] if times else None, "last_seen_utc": times[-1] if times else None},
        )
        groups.append(group)
        for item in items:
            members.append(_member(group, item["source_table"], item["id"], source_tool=item.get("tool_name"), role="execution_evidence", event_time=item.get("event_time"), user=item.get("user_profile"), path=item.get("path"), application=item.get("executable"), description=item.get("description")))
        interpretations.append(_interpretation(group, "Multiple execution-oriented artifacts reference the same executable/path. This strengthens evidence of presence or execution depending on the source types."))
    return groups, members, interpretations


def _web_cloud_webmail_convergence(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    rows.extend(_web_rows_from_table(db, case_id, image_id, "browser_history", "url", "visit_time_utc", "browser", "title"))
    rows.extend(_web_rows_from_table(db, case_id, image_id, "browser_downloads", "tab_url", "start_time_utc", "browser", "target_path"))
    rows.extend(_web_rows_from_table(db, case_id, image_id, "webcache_entries", "url", "accessed_utc", "application", "entry_type"))
    rows.extend(_web_rows_from_table(db, case_id, image_id, "windows_search_internet_history", "target_url", "gather_time", None, "title", host_column="target_host"))
    rows.extend(_web_rows_from_table(db, case_id, image_id, "cloud_sync_artifacts", "url", "event_time_utc", "provider", "cloud_path"))
    rows.extend(_web_rows_from_table(db, case_id, image_id, "mailbox_messages", "sender", "message_date_utc", "source_format", "subject", host_from_email=True))
    by_provider_host: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        provider = _web_provider(row.get("host") or row.get("url") or "")
        if not provider:
            continue
        row["provider"] = provider
        host = row.get("host") or provider.lower().replace(" ", "-")
        by_provider_host.setdefault(f"{provider}:{host}", []).append(row)
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    for key, items in sorted(by_provider_host.items(), key=lambda item: len(item[1]), reverse=True)[:500]:
        source_tables = sorted({str(item["source_table"]) for item in items})
        if len(source_tables) < 2:
            continue
        first = items[0]
        times = sorted(str(item.get("event_time") or "") for item in items if item.get("event_time"))
        group = _group(
            rule_id="web.cloud_webmail_convergence",
            case_id=case_id,
            computer_id=first.get("computer_id"),
            image_id=image_id or first.get("image_id"),
            category="web",
            key=f"web:{key}",
            title=f"{first['provider']} web/cloud convergence: {first.get('host') or key}",
            summary=f"{len(items)} row(s) across {len(source_tables)} source type(s) reference this cloud/webmail provider.",
            review_value="high",
            primary_time=times[-1] if times else None,
            primary_path=first.get("url"),
            primary_application=first.get("application"),
            member_count=len(items),
            source_tables=source_tables,
            details={"provider": first["provider"], "host": first.get("host"), "first_seen_utc": times[0] if times else None, "last_seen_utc": times[-1] if times else None},
        )
        groups.append(group)
        for item in items[:100]:
            members.append(_member(group, item["source_table"], item["id"], role="web_cloud_reference", event_time=item.get("event_time"), path=item.get("url"), application=item.get("application"), description=item.get("description"), details={"host": item.get("host"), "provider": item.get("provider")}))
        interpretations.append(_interpretation(group, "The same cloud storage or webmail provider appears in multiple artifacts. Use timestamps and source applications to distinguish browsing, syncing, cached content, and mail activity."))
    return groups, members, interpretations


def _vpn_rdp_overlap(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if not _table_exists(db, "derived_sessions"):
        return [], [], []
    image_filter = "AND image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    rows = _rows(db, f"SELECT * FROM derived_sessions WHERE case_id = ? {image_filter} AND session_type IN ('vpn', 'rdp')", tuple(params))
    vpns = [row for row in rows if row["session_type"] == "vpn"]
    rdps = [row for row in rows if row["session_type"] == "rdp"]
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    for vpn in vpns:
        vpn_start, vpn_end = _session_window(vpn)
        for rdp in rdps:
            rdp_start, rdp_end = _session_window(rdp)
            if not _windows_overlap(vpn_start, vpn_end, rdp_start, rdp_end, tolerance_minutes=10):
                continue
            group = _group(
                rule_id="session.vpn_rdp_overlap",
                case_id=case_id,
                computer_id=rdp.get("computer_id") or vpn.get("computer_id"),
                image_id=image_id or rdp.get("image_id") or vpn.get("image_id"),
                category="session",
                key=f"vpn-rdp:{vpn['id']}:{rdp['id']}",
                title=f"VPN/RDP overlap: {vpn.get('profile_name') or vpn.get('remote_host') or 'VPN'} -> {rdp.get('remote_host') or rdp.get('remote_ip') or 'RDP'}",
                summary="VPN and RDP derived sessions overlap or occur within ten minutes of each other.",
                review_value="high",
                primary_time=rdp.get("start_time_utc") or vpn.get("start_time_utc"),
                primary_user=rdp.get("user_profile") or vpn.get("user_profile"),
                primary_application="Remote access",
                member_count=2,
                source_tables=["derived_sessions"],
                details={"vpn_duration_seconds": vpn.get("duration_seconds"), "rdp_duration_seconds": rdp.get("duration_seconds")},
            )
            groups.append(group)
            members.append(_member(group, "derived_sessions", vpn["id"], role="vpn_session", event_time=vpn.get("start_time_utc"), user=vpn.get("user_profile"), application=vpn.get("profile_name"), description=vpn.get("session_key")))
            members.append(_member(group, "derived_sessions", rdp["id"], role="rdp_session", event_time=rdp.get("start_time_utc"), user=rdp.get("user_profile"), application="RDP", description=rdp.get("session_key")))
            interpretations.append(_interpretation(group, "This is a temporal link between VPN and RDP evidence. It does not prove the RDP connection traversed the VPN, but it is strong remote-access context for review."))
    return groups, members, interpretations


def _deleted_file_still_referenced(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    deleted = _deleted_file_rows(db, case_id, image_id)
    refs = _user_file_reference_rows(db, case_id, image_id)
    refs_by_path: dict[str, list[dict[str, Any]]] = {}
    refs_by_name: dict[str, list[dict[str, Any]]] = {}
    for ref in refs:
        norm = _norm_path(ref.get("path"))
        name = _basename(norm)
        if norm:
            refs_by_path.setdefault(norm, []).append(ref)
        if name:
            refs_by_name.setdefault(name, []).append(ref)
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in deleted[:5000]:
        path = _norm_path(row.get("path"))
        name = _basename(path or row.get("name"))
        matches = list(refs_by_path.get(path, []))
        if not matches and name and len(name) > 8:
            matches = refs_by_name.get(name, [])[:25]
        if not matches:
            continue
        key = (row["source_table"], str(row["id"]))
        if key in seen:
            continue
        seen.add(key)
        source_tables = sorted({row["source_table"]} | {str(item["source_table"]) for item in matches})
        group = _group(
            rule_id="file.deleted_still_referenced",
            case_id=case_id,
            computer_id=row.get("computer_id"),
            image_id=image_id or row.get("image_id"),
            category="file",
            key=f"deleted-ref:{row['source_table']}:{row['id']}",
            title=f"Deleted/missing file still referenced: {row.get('path') or row.get('name')}",
            summary=f"Deleted or non-live filesystem evidence has {len(matches)} user-facing reference(s).",
            review_value="high",
            primary_time=row.get("event_time"),
            primary_path=row.get("path"),
            member_count=len(matches) + 1,
            source_tables=source_tables,
            details={"match_basis": "path_or_filename", "status": row.get("status")},
        )
        groups.append(group)
        members.append(_member(group, row["source_table"], row["id"], role="deleted_or_missing_filesystem_record", event_time=row.get("event_time"), path=row.get("path"), description=row.get("status")))
        for ref in matches[:25]:
            members.append(_member(group, ref["source_table"], ref["id"], role="referencing_artifact", event_time=ref.get("event_time"), user=ref.get("user"), path=ref.get("path"), description=ref.get("description")))
        interpretations.append(_interpretation(group, "A file no longer present in the live namespace still appears in activity artifacts. This is useful for deleted-file review and user-knowledge context."))
    return groups, members, interpretations


def _windows_old_unique_context(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    for table, time_col, path_col, label_col in (
        ("registry_artifacts", "event_time_utc", "normalized_path", "artifact"),
        ("browser_history", "visit_time_utc", "url", "title"),
        ("shortcut_items", "target_modified", "file_location", "file_name"),
        ("shellbag_entries", "last_interacted", "absolute_path", "shell_type"),
        ("prefetch_items", "last_run_time_utc", "executable_name", "prefetch_name"),
        ("amcache_entries", "modified_utc", "path", "name"),
    ):
        if not _table_exists(db, table):
            continue
        image_filter = f"AND {table}.image_id = ?" if image_id else ""
        params: list[Any] = [case_id]
        if image_id:
            params.append(image_id)
        rows.extend(
            _rows(
                db,
                f"""
                SELECT {table}.id, {table}.case_id, {table}.computer_id, {table}.image_id,
                       '{table}' AS source_table, {table}.{time_col} AS event_time,
                       {table}.{path_col} AS path, {table}.{label_col} AS description, tool_outputs.path AS output_path
                FROM {table}
                JOIN tool_outputs ON tool_outputs.id = {table}.tool_output_id
                LEFT JOIN artifact_record_sources ars
                  ON ars.case_id = {table}.case_id
                 AND ars.duplicate_table = '{table}'
                 AND ars.duplicate_row_id = {table}.id
                WHERE {table}.case_id = ? {image_filter}
                  AND tool_outputs.path LIKE '%Windows.old%'
                  AND ars.id IS NULL
                LIMIT 1000
                """,
                tuple(params),
            )
        )
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    by_table: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_table.setdefault(str(row["source_table"]), []).append(row)
    for table, items in by_table.items():
        first = items[0]
        times = sorted(str(item.get("event_time") or "") for item in items if item.get("event_time"))
        group = _group(
            rule_id="windows_old.unique_context",
            case_id=case_id,
            computer_id=first.get("computer_id"),
            image_id=image_id or first.get("image_id"),
            category="windows_old",
            key=f"windows-old-unique:{table}",
            title=f"Windows.old unique context: {table}",
            summary=f"{len(items)} Windows.old row(s) in {table} have no current-install duplicate.",
            review_value="medium",
            primary_time=times[-1] if times else None,
            member_count=min(len(items), 100),
            source_tables=[table, "tool_outputs", "artifact_record_sources"],
            details={"unique_rows_scanned": len(items), "first_seen_utc": times[0] if times else None, "last_seen_utc": times[-1] if times else None},
        )
        groups.append(group)
        for item in items[:100]:
            members.append(_member(group, table, item["id"], role="windows_old_unique_artifact", event_time=item.get("event_time"), path=item.get("path"), description=item.get("description"), details={"output_path": item.get("output_path")}))
        interpretations.append(_interpretation(group, "These artifacts come from Windows.old and were not matched to current-install rows by the dedupe pass. Treat them as prior-install context unless corroborated elsewhere."))
    return groups, members, interpretations


def _special_tool_usage(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows = _execution_search_rows(db, case_id, image_id)
    families = {
        "sdelete": ("sdelete",),
        "tor": ("tor browser", "tor.exe", "/tor/", "\\tor\\"),
        "virtualization": ("vmware", "virtualbox", "vbox", "qemu", "hyper-v", ".vmdk", ".vhd", ".vhdx", "vboxmanage"),
    }
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        haystack = " ".join(str(row.get(key) or "") for key in ("path", "application", "description")).lower()
        for family, tokens in families.items():
            if any(token in haystack for token in tokens):
                key = (family, _norm_path(row.get("path") or row.get("application") or row.get("description"))[:200])
                grouped.setdefault(key, []).append(row)
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    for (family, key), items in sorted(grouped.items())[:1000]:
        first = items[0]
        times = sorted(str(item.get("event_time") or "") for item in items if item.get("event_time"))
        source_tables = sorted({str(item["source_table"]) for item in items})
        group = _group(
            rule_id="execution.special_tool_usage",
            case_id=case_id,
            computer_id=first.get("computer_id"),
            image_id=image_id or first.get("image_id"),
            category="execution",
            key=f"special-exec:{family}:{key}",
            title=f"{family.title()} related execution evidence: {first.get('path') or first.get('application')}",
            summary=f"{len(items)} execution/context row(s) reference {family} related tooling.",
            review_value="high",
            primary_time=times[-1] if times else None,
            primary_path=first.get("path"),
            primary_application=first.get("application"),
            member_count=len(items),
            source_tables=source_tables,
            details={"family": family, "first_seen_utc": times[0] if times else None, "last_seen_utc": times[-1] if times else None},
        )
        groups.append(group)
        for item in items[:100]:
            members.append(_member(group, item["source_table"], item["id"], role=f"{family}_evidence", event_time=item.get("event_time"), user=item.get("user"), path=item.get("path"), application=item.get("application"), description=item.get("description")))
        interpretations.append(_interpretation(group, "This is rule-based execution/context evidence for tools of investigative interest. Corroborate with Prefetch, BAM/DAM, SRUM, Amcache, Shimcache, and filesystem records."))
    return groups, members, interpretations


def _existing_pairwise_correlations(db: Database, *, case_id: str, image_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    image_filter = "AND image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    rows = _rows(db, f"SELECT * FROM artifact_correlations WHERE case_id = ? {image_filter} LIMIT 10000", tuple(params))
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("correlation_type") or "pairwise"), str(row.get("correlation_key") or row.get("id")))
        grouped.setdefault(key, []).append(row)
    groups: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    interpretations: list[dict[str, Any]] = []
    for (correlation_type, correlation_key), items in grouped.items():
        first = items[0]
        source_tables = sorted(
            {str(item["left_source_table"]) for item in items}
            | {str(item["right_source_table"]) for item in items}
        )
        member_keys = {
            (str(item["left_source_table"]), str(item["left_source_row_id"]), str(item.get("left_source_tool") or ""), "left_artifact")
            for item in items
        } | {
            (str(item["right_source_table"]), str(item["right_source_row_id"]), str(item.get("right_source_tool") or ""), "right_artifact")
            for item in items
        }
        group = _group(
            rule_id="app.existing_pairwise",
            case_id=first["case_id"],
            computer_id=first["computer_id"],
            image_id=first["image_id"],
            category="application",
            key=f"pairwise:{correlation_type}:{correlation_key}",
            title=f"{correlation_type}: {correlation_key}",
            summary=first.get("summary") or correlation_type or "Pairwise artifact correlation",
            review_value=first.get("confidence") or "normal",
            member_count=len(member_keys),
            source_tables=source_tables,
            details={"correlation_type": correlation_type, "correlation_key": correlation_key, "pairwise_rows": len(items)},
        )
        groups.append(group)
        for source_table, source_row_id, source_tool, role in sorted(member_keys):
            members.append(_member(group, source_table, source_row_id, source_tool=source_tool or None, role=role))
        interpretations.append(_interpretation(group, "This group was promoted from an existing pairwise parser correlation. Review both source rows for context."))
    return groups, members, interpretations


def _seed_rules(db: Database) -> None:
    created_at = utc_now()
    db.conn.executemany(
        """
        INSERT INTO correlation_rules (id, category, name, description, enabled, review_value, created_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          category = excluded.category,
          name = excluded.name,
          description = excluded.description,
          review_value = excluded.review_value
        """,
        [(rule.id, rule.category, rule.name, rule.description, rule.review_value, created_at) for rule in RULES],
    )


def _delete_existing(db: Database, *, case_id: str, image_id: str | None) -> None:
    where = ["case_id = ?"]
    params: list[Any] = [case_id]
    if image_id:
        where.append("image_id = ?")
        params.append(image_id)
    group_ids = [row["id"] for row in db.conn.execute(f"SELECT id FROM correlation_groups WHERE {' AND '.join(where)}", params)]
    if not group_ids:
        return
    placeholders = ",".join("?" for _ in group_ids)
    db.conn.execute(f"DELETE FROM correlation_interpretations WHERE group_id IN ({placeholders})", group_ids)
    db.conn.execute(f"DELETE FROM correlation_members WHERE group_id IN ({placeholders})", group_ids)
    db.conn.execute(f"DELETE FROM correlation_groups WHERE id IN ({placeholders})", group_ids)


def _insert_groups(db: Database, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    db.conn.executemany(
        """
        INSERT INTO correlation_groups (
          id, case_id, computer_id, image_id, rule_id, category, correlation_key,
          title, summary, review_value, primary_time_utc, primary_path, primary_user,
          primary_application, member_count, source_tables, details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row["id"], row["case_id"], row.get("computer_id"), row.get("image_id"),
                row["rule_id"], row["category"], row["correlation_key"], row["title"],
                row["summary"], row["review_value"], row.get("primary_time_utc"),
                row.get("primary_path"), row.get("primary_user"), row.get("primary_application"),
                row["member_count"], ",".join(row.get("source_tables") or []),
                json.dumps(row.get("details", {}), default=str), row["created_at"],
            )
            for row in rows
        ],
    )


def _insert_members(db: Database, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    db.conn.executemany(
        """
        INSERT INTO correlation_members (
          id, group_id, case_id, computer_id, image_id, source_table, source_row_id,
          source_tool, role, event_time_utc, user_profile, path, application,
          description, details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row["id"], row["group_id"], row["case_id"], row.get("computer_id"),
                row.get("image_id"), row["source_table"], row["source_row_id"],
                row.get("source_tool"), row["role"], row.get("event_time_utc"),
                row.get("user_profile"), row.get("path"), row.get("application"),
                row.get("description"), json.dumps(row.get("details", {}), default=str),
                row["created_at"],
            )
            for row in rows
        ],
    )


def _insert_interpretations(db: Database, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    db.conn.executemany(
        """
        INSERT INTO correlation_interpretations (id, group_id, rule_id, interpretation, caveats, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [(row["id"], row["group_id"], row["rule_id"], row["interpretation"], row.get("caveats"), row["created_at"]) for row in rows],
    )


def _group(**kwargs: Any) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "created_at": utc_now(),
        **kwargs,
        "correlation_key": kwargs["key"],
        "source_tables": kwargs.get("source_tables") or [],
        "details": kwargs.get("details") or {},
    }


def _member(group: dict[str, Any], source_table: str, source_row_id: str, *, role: str, source_tool: str | None = None, event_time: Any = None, user: Any = None, path: Any = None, application: Any = None, description: Any = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "group_id": group["id"],
        "case_id": group["case_id"],
        "computer_id": group.get("computer_id"),
        "image_id": group.get("image_id"),
        "source_table": source_table,
        "source_row_id": str(source_row_id),
        "source_tool": source_tool,
        "role": role,
        "event_time_utc": str(event_time) if event_time else None,
        "user_profile": str(user) if user else None,
        "path": str(path) if path else None,
        "application": str(application) if application else None,
        "description": str(description) if description else None,
        "details": details or {},
        "created_at": utc_now(),
    }


def _interpretation(group: dict[str, Any], text: str, caveats: str | None = None) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "group_id": group["id"],
        "rule_id": group["rule_id"],
        "interpretation": text,
        "caveats": caveats,
        "created_at": utc_now(),
    }


def _rows(db: Database, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in db.conn.execute(sql, params).fetchall()]


def _join_path(parent: Any, name: Any) -> str | None:
    if not parent and not name:
        return None
    return "/".join(part.strip("\\/") for part in (str(parent or ""), str(name or "")) if part)


def _norm_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip().lower()
    text = re.sub(r"^[a-z]:/", "", text)
    return re.sub(r"/+", "/", text).strip("/")


def _basename(value: Any) -> str:
    text = _norm_path(value)
    return text.rsplit("/", 1)[-1] if text else ""


def _table_exists(db: Database, table: str) -> bool:
    row = db.conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    return row is not None


def _web_rows_from_table(
    db: Database,
    case_id: str,
    image_id: str | None,
    table: str,
    url_column: str,
    time_column: str,
    app_column: str | None,
    description_column: str | None,
    *,
    host_column: str | None = None,
    host_from_email: bool = False,
) -> list[dict[str, Any]]:
    if not _table_exists(db, table):
        return []
    image_filter = "AND image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    app_expr = app_column if app_column else "NULL"
    description_expr = description_column if description_column else "NULL"
    host_expr = host_column if host_column else "NULL"
    rows = _rows(
        db,
        f"""
        SELECT id, case_id, computer_id, image_id, '{table}' AS source_table,
               {url_column} AS url, {time_column} AS event_time,
               {app_expr} AS application, {description_expr} AS description,
               {host_expr} AS host
        FROM {table}
        WHERE case_id = ? {image_filter}
        LIMIT 5000
        """,
        tuple(params),
    )
    for row in rows:
        if host_from_email:
            row["host"] = _host_from_email(row.get("url"))
        else:
            row["host"] = row.get("host") or _host_from_url(row.get("url"))
    return rows


def _host_from_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text) else f"https://{text}")
    return (parsed.hostname or "").lower()


def _host_from_email(value: Any) -> str:
    text = str(value or "")
    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)
    return match.group(1).lower() if match else ""


def _web_provider(value: Any) -> str:
    text = str(value or "").lower()
    providers = {
        "Google Drive": ("drive.google.com", "docs.google.com", "google drive", "drivefs"),
        "OneDrive": ("onedrive", "sharepoint.com", "1drv.ms", "d.docs.live.net", "skydrive"),
        "Dropbox": ("dropbox", "dropbox.com", "dropboxusercontent.com"),
        "Gmail": ("mail.google.com", "gmail.com"),
        "Outlook Webmail": ("outlook.office.com", "outlook.live.com", "owa", "mail.office365.com"),
        "Yahoo Mail": ("mail.yahoo.com", "ymail.com"),
        "iCloud": ("icloud.com", "icloud drive"),
    }
    for provider, tokens in providers.items():
        if any(token in text for token in tokens):
            return provider
    return ""


def _session_window(row: dict[str, Any]) -> tuple[Any, Any]:
    start = _parse_report_timestamp(row.get("start_time_utc") or row.get("end_time_utc"))
    end = _parse_report_timestamp(row.get("end_time_utc") or row.get("start_time_utc"))
    return start, end


def _windows_overlap(start_a: Any, end_a: Any, start_b: Any, end_b: Any, *, tolerance_minutes: int) -> bool:
    if not start_a or not start_b:
        return False
    tolerance = timedelta(minutes=tolerance_minutes)
    end_a = end_a or start_a
    end_b = end_b or start_b
    return start_a - tolerance <= end_b and start_b - tolerance <= end_a


def _deleted_file_rows(db: Database, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    image_filter = "AND image_id = ?" if image_id else ""
    params: list[Any] = [case_id]
    if image_id:
        params.append(image_id)
    if _table_exists(db, "filesystem_review"):
        rows.extend(
            _rows(
                db,
                f"""
                SELECT id, case_id, computer_id, image_id, source_table, event_time,
                       file_path AS path, file_name AS name, status
                FROM filesystem_review
                WHERE case_id = ? {image_filter}
                  AND (
                    LOWER(COALESCE(in_use, '')) IN ('false', '0', 'no')
                    OR LOWER(COALESCE(status, '')) LIKE '%deleted%'
                    OR LOWER(COALESCE(status, '')) LIKE '%not_live%'
                    OR LOWER(COALESCE(status, '')) LIKE '%not in use%'
                    OR LOWER(COALESCE(operation, '')) LIKE '%delete%'
                  )
                LIMIT 5000
                """,
                tuple(params),
            )
        )
    if _table_exists(db, "mft_entries"):
        rows.extend(
            _rows(
                db,
                f"""
                SELECT id, case_id, computer_id, image_id, 'mft_entries' AS source_table,
                       COALESCE(modified_si, record_changed_si, created_si) AS event_time,
                       COALESCE(parent_path || '/' || file_name, file_name) AS path,
                       file_name AS name, 'mft_not_in_use' AS status
                FROM mft_entries
                WHERE case_id = ? {image_filter}
                  AND LOWER(COALESCE(in_use, '')) IN ('false', '0', 'no')
                LIMIT 5000
                """,
                tuple(params),
            )
        )
    return rows


def _user_file_reference_rows(db: Database, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    specs = [
        ("shortcut_items", "COALESCE(file_location, artifact_path)", "COALESCE(target_modified, target_created)", "artifact_type", "file_name", None),
        ("shellbag_entries", "absolute_path", "COALESCE(last_interacted, first_interacted, last_write_time)", "shell_type", "absolute_path", "user_profile"),
        ("webcache_file_accesses", "normalized_path", "accessed_utc", "application", "url", "user_name"),
        ("windows_search_files", "item_path", "gather_time", "item_type", "file_name", "owner"),
        ("windows_search_gather_logs", "item_path", "timestamp_utc", "log_type", "item_url", None),
        ("registry_artifacts", "COALESCE(normalized_path, value_data)", "COALESCE(event_time_utc, key_last_write_utc)", "artifact", "value_name", "user_profile"),
    ]
    rows: list[dict[str, Any]] = []
    for table, path_expr, time_expr, app_expr, desc_expr, user_expr in specs:
        if not _table_exists(db, table):
            continue
        image_filter = f"AND {table}.image_id = ?" if image_id else ""
        params: list[Any] = [case_id]
        if image_id:
            params.append(image_id)
        user_sql = user_expr if user_expr else "NULL"
        rows.extend(
            _rows(
                db,
                f"""
                SELECT id, case_id, computer_id, image_id, '{table}' AS source_table,
                       {path_expr} AS path, {time_expr} AS event_time,
                       {app_expr} AS application, {desc_expr} AS description,
                       {user_sql} AS user
                FROM {table}
                WHERE {table}.case_id = ? {image_filter}
                  AND {path_expr} IS NOT NULL
                LIMIT 10000
                """,
                tuple(params),
            )
        )
    return rows


def _execution_search_rows(db: Database, case_id: str, image_id: str | None) -> list[dict[str, Any]]:
    specs = [
        ("prefetch_items", "executable_name", "artifact_path", "last_run_time_utc", "prefetch_name", "NULL"),
        ("registry_artifacts", "COALESCE(display_name, value_name, artifact)", "COALESCE(normalized_path, value_data, key_path)", "COALESCE(event_time_utc, key_last_write_utc)", "artifact", "COALESCE(user_profile, user_sid)"),
        ("amcache_entries", "COALESCE(name, path)", "path", "COALESCE(modified_utc, created_utc, install_date)", "entry_type", "NULL"),
        ("shimcache_entries", "path", "path", "last_modified_utc", "executed", "NULL"),
        ("srum_records", "COALESCE(app_name, app_path)", "app_path", "timestamp", "provider_name", "user_name"),
        ("evtx_events", "COALESCE(executable_info, provider)", "COALESCE(executable_info, payload_data1, payload_data2, payload_data3)", "time_created", "map_description", "user_name"),
    ]
    rows: list[dict[str, Any]] = []
    for table, app_expr, path_expr, time_expr, desc_expr, user_expr in specs:
        if not _table_exists(db, table):
            continue
        image_filter = f"AND {table}.image_id = ?" if image_id else ""
        params: list[Any] = [case_id]
        if image_id:
            params.append(image_id)
        rows.extend(
            _rows(
                db,
                f"""
                SELECT id, case_id, computer_id, image_id, '{table}' AS source_table,
                       {app_expr} AS application, {path_expr} AS path,
                       {time_expr} AS event_time, {desc_expr} AS description,
                       {user_expr} AS user
                FROM {table}
                WHERE {table}.case_id = ? {image_filter}
                LIMIT 20000
                """,
                tuple(params),
            )
        )
    return rows
