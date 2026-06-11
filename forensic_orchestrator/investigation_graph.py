from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .analytics_query import query_rows
from .db import Database, utc_now
from .timestamps import parse_timestamp


def rebuild_investigation_graph(db: Database, *, case_id: str, image_id: str | None = None, limit: int = 10_000) -> dict[str, Any]:
    """Build a deterministic entity, relationship, and finding layer from parsed artifacts."""
    db.get_case(case_id)
    with db.bulk_transaction():
        if image_id:
            db.conn.execute(
                """
                DELETE FROM investigation_finding_evidence
                WHERE finding_id IN (
                  SELECT id FROM investigation_findings WHERE case_id = ? AND image_id = ?
                )
                """,
                (case_id, image_id),
            )
            for table in ("investigation_findings", "investigation_relationships", "investigation_entities"):
                db.conn.execute(f"DELETE FROM {table} WHERE case_id = ? AND image_id = ?", (case_id, image_id))
        else:
            for table in (
                "investigation_finding_evidence",
                "investigation_findings",
                "investigation_relationships",
                "investigation_entities",
            ):
                db.conn.execute(f"DELETE FROM {table} WHERE case_id = ?", (case_id,))
        builder = _InvestigationGraphBuilder(db, case_id=case_id, image_id=image_id, limit=limit)
        builder.build()
    return builder.summary()


class _InvestigationGraphBuilder:
    def __init__(self, db: Database, *, case_id: str, image_id: str | None, limit: int) -> None:
        self.db = db
        self.case_id = case_id
        self.image_id = image_id
        self.limit = max(1, limit)
        self.created_at = utc_now()
        self.entities: dict[tuple[str, str], dict[str, Any]] = {}
        self.relationship_count = 0
        self.finding_count = 0
        self.evidence_count = 0

    def build(self) -> None:
        self._build_users()
        self._build_usb_devices()
        self._build_browser_downloads()
        self._build_usb_file_activity()
        self._build_shortcut_activity()
        self._build_execution_activity()
        self._build_email_attachments()
        self._build_cloud_activity()
        self._build_archive_activity()
        self._build_findings()

    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "image_id": self.image_id,
            "entity_count": len(self.entities),
            "relationship_count": self.relationship_count,
            "finding_count": self.finding_count,
            "finding_evidence_count": self.evidence_count,
        }

    def _where(self, prefix: str = "WHERE") -> tuple[str, list[Any]]:
        clause = f"{prefix} case_id = ?"
        params: list[Any] = [self.case_id]
        if self.image_id:
            clause += " AND image_id = ?"
            params.append(self.image_id)
        return clause, params

    def _build_users(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "sam_accounts",
            f"""
            SELECT id, computer_id, image_id, username, rid, account_category, last_login_utc
            FROM sam_accounts
            {clause}
            ORDER BY COALESCE(last_login_utc, '') DESC
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            display = row["username"] or row["rid"]
            if not display:
                continue
            self.entity(
                "person",
                f"{row['computer_id']}:{row['rid'] or display}",
                display,
                computer_id=row["computer_id"],
                image_id=row["image_id"],
                source_table="sam_accounts",
                source_row_id=row["id"],
                first_seen=row["last_login_utc"],
                last_seen=row["last_login_utc"],
                details={"rid": row["rid"], "account_category": row["account_category"]},
            )

    def _build_usb_devices(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "usb_storage_devices",
            f"""
            SELECT id, computer_id, image_id, serial, friendly_name, product, volume_name, volume_serial_number,
                   first_install_date_utc, last_arrival_utc, last_removal_utc
            FROM usb_storage_devices
            {clause}
            ORDER BY COALESCE(last_removal_utc, last_arrival_utc, first_install_date_utc, '') DESC
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            key = row["serial"] or row["volume_serial_number"] or row["id"]
            display = row["friendly_name"] or row["product"] or row["volume_name"] or key
            entity = self.entity(
                "usb_device",
                key,
                display,
                computer_id=row["computer_id"],
                image_id=row["image_id"],
                source_table="usb_storage_devices",
                source_row_id=row["id"],
                first_seen=row["first_install_date_utc"],
                last_seen=row["last_removal_utc"] or row["last_arrival_utc"],
                details=dict(row),
            )
            computer = self.entity("device", row["computer_id"] or "unknown", row["computer_id"] or "Unknown computer")
            self.relationship(
                "connected_to",
                entity,
                computer,
                source_table="usb_storage_devices",
                source_row_id=row["id"],
                event_time=row["last_removal_utc"] or row["last_arrival_utc"] or row["first_install_date_utc"],
                summary=f"{display} connected to computer",
                details=dict(row),
            )

    def _build_browser_downloads(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "browser_downloads",
            f"""
            SELECT id, computer_id, image_id, browser, target_path, tab_url, site_url, referrer,
                   start_time_utc, end_time_utc, total_bytes, danger_type
            FROM browser_downloads
            {clause}
            ORDER BY COALESCE(start_time_utc, end_time_utc, '') DESC
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            path = row["target_path"]
            if not path:
                continue
            file_entity = self.entity(
                "file",
                _path_key(path),
                _basename(path),
                computer_id=row["computer_id"],
                image_id=row["image_id"],
                source_table="browser_downloads",
                source_row_id=row["id"],
                first_seen=row["start_time_utc"],
                last_seen=row["end_time_utc"] or row["start_time_utc"],
                details={"path": path, "total_bytes": row["total_bytes"], "danger_type": row["danger_type"]},
            )
            app = self.entity("application", row["browser"] or "browser", row["browser"] or "Browser")
            self.relationship(
                "downloaded_by",
                file_entity,
                app,
                source_table="browser_downloads",
                source_row_id=row["id"],
                event_time=row["start_time_utc"] or row["end_time_utc"],
                summary=f"{_basename(path)} downloaded by {row['browser'] or 'browser'}",
                details=dict(row),
            )
            url = row["tab_url"] or row["site_url"] or row["referrer"]
            if url:
                host = urlparse(str(url)).netloc or str(url)
                url_entity = self.entity("network_connection", host, host, details={"url": url})
                self.relationship(
                    "downloaded_from",
                    file_entity,
                    url_entity,
                    source_table="browser_downloads",
                    source_row_id=row["id"],
                    event_time=row["start_time_utc"] or row["end_time_utc"],
                    summary=f"{_basename(path)} downloaded from {host}",
                    details=dict(row),
                )

    def _build_usb_file_activity(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "usb_file_correlations",
            f"""
            SELECT id, computer_id, image_id, file_name, file_location, source_artifact_type, source_artifact_id,
                   usb_serial, usb_volume_serial_number, usb_volume_name, target_modified, target_created,
                   target_accessed, confidence
            FROM usb_file_correlations
            {clause}
            ORDER BY COALESCE(target_modified, target_created, target_accessed, '') DESC
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            path = row["file_location"] or row["file_name"]
            if not path:
                continue
            file_entity = self.entity(
                "file",
                _path_key(path),
                row["file_name"] or _basename(path),
                computer_id=row["computer_id"],
                image_id=row["image_id"],
                source_table="usb_file_correlations",
                source_row_id=row["id"],
                first_seen=row["target_modified"] or row["target_created"] or row["target_accessed"],
                last_seen=row["target_modified"] or row["target_created"] or row["target_accessed"],
                details=dict(row),
            )
            usb_key = row["usb_serial"] or row["usb_volume_serial_number"] or row["usb_volume_name"] or "unknown_usb"
            usb = self.entity("usb_device", usb_key, row["usb_volume_name"] or usb_key, details={"volume_serial_number": row["usb_volume_serial_number"]})
            self.relationship(
                "file_seen_on_usb",
                file_entity,
                usb,
                source_table="usb_file_correlations",
                source_row_id=row["id"],
                event_time=row["target_modified"] or row["target_created"] or row["target_accessed"],
                confidence=row["confidence"] or "derived",
                summary=f"{row['file_name'] or _basename(path)} associated with removable media",
                details=dict(row),
            )

    def _build_shortcut_activity(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "shortcut_items",
            f"""
            SELECT id, computer_id, image_id, file_name, target_path, local_path, app_id_description,
                   target_created, target_modified, target_accessed
            FROM shortcut_items
            {clause}
            ORDER BY COALESCE(target_modified, target_created, target_accessed, '') DESC
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            path = row["target_path"] or row["local_path"] or row["file_name"]
            if not path:
                continue
            file_entity = self.entity("file", _path_key(path), row["file_name"] or _basename(path), computer_id=row["computer_id"], image_id=row["image_id"], source_table="shortcut_items", source_row_id=row["id"], first_seen=row["target_created"], last_seen=row["target_modified"] or row["target_accessed"], details=dict(row))
            if row["app_id_description"]:
                app = self.entity("application", row["app_id_description"], row["app_id_description"])
                self.relationship("opened_by", file_entity, app, source_table="shortcut_items", source_row_id=row["id"], event_time=row["target_modified"] or row["target_accessed"] or row["target_created"], summary=f"{row['file_name'] or _basename(path)} referenced by {row['app_id_description']}", details=dict(row))

    def _build_execution_activity(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "prefetch_items",
            f"""
            SELECT id, computer_id, image_id, executable_name, original_path, last_run_time_utc, run_count
            FROM prefetch_items
            {clause}
            ORDER BY COALESCE(last_run_time_utc, '') DESC
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            name = row["executable_name"] or _basename(row["original_path"])
            if not name:
                continue
            app = self.entity("application", _path_key(row["original_path"] or name), name, computer_id=row["computer_id"], image_id=row["image_id"], source_table="prefetch_items", source_row_id=row["id"], first_seen=row["last_run_time_utc"], last_seen=row["last_run_time_utc"], details=dict(row))
            computer = self.entity("device", row["computer_id"] or "unknown", row["computer_id"] or "Unknown computer")
            self.relationship("executed_on", app, computer, source_table="prefetch_items", source_row_id=row["id"], event_time=row["last_run_time_utc"], summary=f"{name} executed", details=dict(row))

    def _build_email_attachments(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "mailbox_attachments",
            f"""
            SELECT id, computer_id, image_id, message_id, attachment_name, attachment_path, size
            FROM mailbox_attachments
            {clause}
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            name = row["attachment_name"] or _basename(row["attachment_path"])
            if not name:
                continue
            file_entity = self.entity("file", _path_key(row["attachment_path"] or name), name, computer_id=row["computer_id"], image_id=row["image_id"], source_table="mailbox_attachments", source_row_id=row["id"], details=dict(row))
            email = self.entity("email", row["message_id"] or row["id"], row["message_id"] or "Email message")
            self.relationship("attached_to", file_entity, email, source_table="mailbox_attachments", source_row_id=row["id"], summary=f"{name} attached to email", details=dict(row))

    def _build_cloud_activity(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "cloud_sync_artifacts",
            f"""
            SELECT id, computer_id, image_id, provider, user_profile, local_path, cloud_path, file_name,
                   event_time_utc, event_type, is_deleted
            FROM cloud_sync_artifacts
            {clause}
            ORDER BY COALESCE(event_time_utc, '') DESC
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            path = row["local_path"] or row["cloud_path"] or row["file_name"]
            if not path:
                continue
            file_entity = self.entity("file", _path_key(path), row["file_name"] or _basename(path), computer_id=row["computer_id"], image_id=row["image_id"], source_table="cloud_sync_artifacts", source_row_id=row["id"], first_seen=row["event_time_utc"], last_seen=row["event_time_utc"], details=dict(row))
            account = self.entity("cloud_account", f"{row['provider']}:{row['user_profile'] or ''}", row["user_profile"] or row["provider"] or "Cloud account")
            self.relationship("synced_with_cloud", file_entity, account, source_table="cloud_sync_artifacts", source_row_id=row["id"], event_time=row["event_time_utc"], summary=f"{row['file_name'] or _basename(path)} cloud sync activity", details=dict(row))

    def _build_archive_activity(self) -> None:
        clause, params = self._where()
        rows = query_rows(
            self.db,
            "archive_entries",
            f"""
            SELECT id, computer_id, image_id, archive_path, member_path, member_size, archive_modified_time_utc, member_modified_time_utc
            FROM archive_entries
            {clause}
            ORDER BY COALESCE(member_modified_time_utc, archive_modified_time_utc, '') DESC
            LIMIT ?
            """,
            (*params, self.limit),
        )
        for row in rows:
            archive_path = row["archive_path"]
            if not archive_path:
                continue
            event_time = row["member_modified_time_utc"] or row["archive_modified_time_utc"]
            archive = self.entity("file", _path_key(archive_path), _basename(archive_path), computer_id=row["computer_id"], image_id=row["image_id"], source_table="archive_entries", source_row_id=row["id"], first_seen=event_time, last_seen=event_time, details={"archive_path": archive_path})
            if row["member_path"]:
                member = self.entity("file", _path_key(f"{archive_path}!{row['member_path']}"), row["member_path"], computer_id=row["computer_id"], image_id=row["image_id"], source_table="archive_entries", source_row_id=row["id"], details=dict(row))
                self.relationship("contained_in_archive", member, archive, source_table="archive_entries", source_row_id=row["id"], event_time=event_time, summary=f"{row['member_path']} contained in archive {_basename(archive_path)}", details=dict(row))

    def _build_findings(self) -> None:
        self._finding_usb_file_activity()
        self._finding_download_to_usb_sequence()

    def _finding_usb_file_activity(self) -> None:
        rows = self.db.conn.execute(
            """
            SELECT relationship_type, object_entity_id, COUNT(*) AS count, MIN(event_time_utc) AS first_seen, MAX(event_time_utc) AS last_seen
            FROM investigation_relationships
            WHERE case_id = ? AND relationship_type = 'file_seen_on_usb'
            GROUP BY object_entity_id
            HAVING COUNT(*) > 0
            ORDER BY count DESC
            LIMIT ?
            """,
            (self.case_id, self.limit),
        ).fetchall()
        for row in rows:
            usb = self._entity_by_id(row["object_entity_id"])
            finding_id = self.finding(
                finding_type="removable_media_file_activity",
                title="Files associated with removable media",
                summary=f"{row['count']} file activity relationship(s) were associated with {usb.get('display_name') or 'removable media'}.",
                severity="medium",
                confidence="medium",
                confidence_score=min(90, 45 + int(row["count"] or 0) * 5),
                rule_id="PERCEPTOR-USB-001",
                rule_name="USB file activity",
                start=row["first_seen"],
                end=row["last_seen"],
                primary_entity_id=row["object_entity_id"],
                details={"relationship_count": row["count"]},
            )
            self._attach_relationship_evidence(
                finding_id,
                role="usb_file_activity",
                relationship_type="file_seen_on_usb",
                object_entity_id=row["object_entity_id"],
            )

    def _finding_download_to_usb_sequence(self) -> None:
        downloads = self._relationships("downloaded_by", limit=self.limit)
        usb_files = self._relationships("file_seen_on_usb", limit=self.limit)
        for download in downloads:
            download_time = _parse_time(download.get("event_time_utc"))
            if not download_time:
                continue
            download_file = self._entity_by_id(download["subject_entity_id"])
            download_name = _name_key(download_file.get("display_name"))
            if not download_name:
                continue
            for usb_rel in usb_files:
                usb_time = _parse_time(usb_rel.get("event_time_utc"))
                if usb_time and abs((usb_time - download_time).total_seconds()) > 3600:
                    continue
                usb_file = self._entity_by_id(usb_rel["subject_entity_id"])
                if download_name not in _name_key(usb_file.get("display_name")) and _name_key(usb_file.get("display_name")) not in download_name:
                    continue
                finding_id = self.finding(
                    finding_type="download_removable_media_sequence",
                    title="Downloaded file later associated with removable media",
                    summary=f"{download_file.get('display_name')} was downloaded and also appeared in removable-media file activity.",
                    severity="high",
                    confidence="high" if usb_time else "medium",
                    confidence_score=90 if usb_time else 75,
                    rule_id="PERCEPTOR-USB-002",
                    rule_name="Download to removable media sequence",
                    start=download.get("event_time_utc"),
                    end=usb_rel.get("event_time_utc") or download.get("event_time_utc"),
                    primary_entity_id=download["subject_entity_id"],
                    details={"download_relationship_id": download["id"], "usb_relationship_id": usb_rel["id"]},
                )
                self.finding_evidence(finding_id, download, role="download")
                self.finding_evidence(finding_id, usb_rel, role="removable_media_file_activity")

    def entity(
        self,
        entity_type: str,
        entity_key: Any,
        display_name: Any,
        *,
        computer_id: Any = None,
        image_id: Any = None,
        source_table: str | None = None,
        source_row_id: Any = None,
        first_seen: Any = None,
        last_seen: Any = None,
        confidence: str = "derived",
        details: dict[str, Any] | None = None,
    ) -> str:
        key = _stable_key(entity_type, entity_key)
        cache_key = (entity_type, key)
        if cache_key in self.entities:
            entity = self.entities[cache_key]
            self._update_entity_times(entity["id"], first_seen, last_seen)
            return str(entity["id"])
        entity_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self.case_id}:{entity_type}:{key}"))
        self.db.conn.execute(
            """
            INSERT OR REPLACE INTO investigation_entities (
              id, case_id, computer_id, image_id, entity_type, entity_key, display_name, normalized_value,
              source_table, source_row_id, confidence, first_seen_utc, last_seen_utc, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity_id,
                self.case_id,
                computer_id,
                image_id or self.image_id,
                entity_type,
                key,
                str(display_name or entity_key or entity_type)[:500],
                key,
                source_table,
                source_row_id,
                confidence,
                first_seen,
                last_seen,
                json.dumps(details or {}, default=str, sort_keys=True),
                self.created_at,
            ),
        )
        self.entities[cache_key] = {"id": entity_id, "display_name": str(display_name or entity_key or entity_type)}
        return entity_id

    def relationship(self, relationship_type: str, subject_entity_id: str, object_entity_id: str, *, source_table: str, source_row_id: Any = None, event_time: Any = None, confidence: str = "derived", summary: str | None = None, details: dict[str, Any] | None = None) -> str:
        rel_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self.case_id}:{relationship_type}:{subject_entity_id}:{object_entity_id}:{source_table}:{source_row_id}:{event_time}"))
        self.db.conn.execute(
            """
            INSERT OR IGNORE INTO investigation_relationships (
              id, case_id, computer_id, image_id, relationship_type, subject_entity_id, object_entity_id,
              source_table, source_row_id, event_time_utc, confidence, summary, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rel_id,
                self.case_id,
                (details or {}).get("computer_id"),
                (details or {}).get("image_id") or self.image_id,
                relationship_type,
                subject_entity_id,
                object_entity_id,
                source_table,
                source_row_id,
                event_time,
                confidence,
                summary,
                json.dumps(details or {}, default=str, sort_keys=True),
                self.created_at,
            ),
        )
        self.relationship_count += int(self.db.conn.total_changes > 0)
        return rel_id

    def finding(self, *, finding_type: str, title: str, summary: str, severity: str, confidence: str, confidence_score: int, rule_id: str, rule_name: str, start: Any = None, end: Any = None, primary_entity_id: str | None = None, details: dict[str, Any] | None = None) -> str:
        finding_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self.case_id}:{rule_id}:{primary_entity_id}:{start}:{end}:{summary}"))
        self.db.conn.execute(
            """
            INSERT OR IGNORE INTO investigation_findings (
              id, case_id, computer_id, image_id, finding_type, title, summary, severity, confidence,
              confidence_score, rule_id, rule_name, start_time_utc, end_time_utc, primary_entity_id,
              details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (finding_id, self.case_id, None, self.image_id, finding_type, title, summary, severity, confidence, confidence_score, rule_id, rule_name, start, end, primary_entity_id, json.dumps(details or {}, default=str, sort_keys=True), self.created_at),
        )
        self.finding_count += 1
        return finding_id

    def finding_evidence(self, finding_id: str, relationship: dict[str, Any], *, role: str) -> None:
        evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{finding_id}:{relationship.get('id')}:{role}"))
        self.db.conn.execute(
            """
            INSERT OR IGNORE INTO investigation_finding_evidence (
              id, finding_id, case_id, source_table, source_row_id, relationship_id, role, event_time_utc,
              summary, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                finding_id,
                self.case_id,
                relationship.get("source_table"),
                relationship.get("source_row_id"),
                relationship.get("id"),
                role,
                relationship.get("event_time_utc"),
                relationship.get("summary"),
                relationship.get("details_json") or "{}",
                self.created_at,
            ),
        )
        self.evidence_count += 1

    def _attach_relationship_evidence(self, finding_id: str, *, role: str, **filters: Any) -> None:
        where = ["case_id = ?"]
        params: list[Any] = [self.case_id]
        for key, value in filters.items():
            where.append(f"{key} = ?")
            params.append(value)
        rows = self.db.conn.execute(f"SELECT * FROM investigation_relationships WHERE {' AND '.join(where)} LIMIT ?", (*params, self.limit)).fetchall()
        for row in rows:
            self.finding_evidence(finding_id, dict(row), role=role)

    def _relationships(self, relationship_type: str, *, limit: int) -> list[dict[str, Any]]:
        rows = self.db.conn.execute(
            "SELECT * FROM investigation_relationships WHERE case_id = ? AND relationship_type = ? ORDER BY COALESCE(event_time_utc, '') DESC LIMIT ?",
            (self.case_id, relationship_type, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def _entity_by_id(self, entity_id: str) -> dict[str, Any]:
        row = self.db.conn.execute("SELECT * FROM investigation_entities WHERE id = ?", (entity_id,)).fetchone()
        return dict(row) if row else {}

    def _update_entity_times(self, entity_id: str, first_seen: Any, last_seen: Any) -> None:
        if not first_seen and not last_seen:
            return
        self.db.conn.execute(
            """
            UPDATE investigation_entities
            SET first_seen_utc = CASE WHEN ? IS NOT NULL AND (first_seen_utc IS NULL OR ? < first_seen_utc) THEN ? ELSE first_seen_utc END,
                last_seen_utc = CASE WHEN ? IS NOT NULL AND (last_seen_utc IS NULL OR ? > last_seen_utc) THEN ? ELSE last_seen_utc END
            WHERE id = ?
            """,
            (first_seen, first_seen, first_seen, last_seen, last_seen, last_seen, entity_id),
        )


def _stable_key(entity_type: str, value: Any) -> str:
    text = str(value or "").strip().casefold().replace("\\", "/")
    text = re.sub(r"\s+", " ", text)
    if not text:
        text = "unknown"
    if len(text) > 300:
        return hashlib.sha256(f"{entity_type}:{text}".encode("utf-8", errors="replace")).hexdigest()
    return text


def _path_key(value: Any) -> str:
    return _stable_key("file", value)


def _basename(value: Any) -> str:
    text = str(value or "").replace("\\", "/").rstrip("/")
    return Path(text).name or text


def _name_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _parse_time(value: Any):
    if not value:
        return None
    try:
        return parse_timestamp(str(value))
    except Exception:
        return None
