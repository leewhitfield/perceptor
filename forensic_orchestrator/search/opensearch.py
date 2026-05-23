from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json
import os
import ssl
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from forensic_orchestrator.db import Database, utc_now
from forensic_orchestrator.safety import OrchestratorError


DEFAULT_INDEX = "forensic-content"
DEFAULT_SYNONYM_GROUPS: tuple[tuple[str, ...], ...] = (
    ("communications", "communication", "comms"),
    ("exfiltration", "exfil"),
    ("jumplist", "jump list", "jump lists"),
    ("prefetch", "pf"),
)


@dataclass(frozen=True)
class OpenSearchConfig:
    url: str
    index: str = DEFAULT_INDEX
    username: str | None = None
    password: str | None = None
    verify_tls: bool = True

    @classmethod
    def from_values(
        cls,
        *,
        url: str | None = None,
        index: str | None = None,
        username: str | None = None,
        password: str | None = None,
        insecure: bool = False,
    ) -> "OpenSearchConfig":
        return cls(
            url=(url or os.environ.get("FORENSIC_OPENSEARCH_URL") or "http://localhost:9200").rstrip("/"),
            index=index or os.environ.get("FORENSIC_OPENSEARCH_INDEX") or DEFAULT_INDEX,
            username=username or os.environ.get("FORENSIC_OPENSEARCH_USERNAME"),
            password=password or os.environ.get("FORENSIC_OPENSEARCH_PASSWORD"),
            verify_tls=not (insecure or _truthy(os.environ.get("FORENSIC_OPENSEARCH_INSECURE"))),
        )


class IngestContentIndexer:
    def __init__(self, config: OpenSearchConfig, *, batch_size: int = 500) -> None:
        self.config = config
        self.batch_size = batch_size
        self.client: OpenSearchRestClient | None = None
        self.batch: list[dict[str, Any]] = []
        self.source_counts: Counter[str] = Counter()
        self.seen_document_ids: set[str] = set()
        self.total = 0
        self.batches = 0
        self.backend_version = ""
        self.started_at = utc_now()

    def add(self, document: dict[str, Any] | None) -> None:
        if not document or not str(document.get("content") or "").strip():
            return
        document_id = str(document.get("id") or "")
        if document_id and document_id in self.seen_document_ids:
            return
        if document_id:
            self.seen_document_ids.add(document_id)
        if self.client is None:
            self.client = OpenSearchRestClient(self.config)
            info = self.client.info()
            self.backend_version = str((info.get("version") or {}).get("number") or "")
            self.client.ensure_index()
        self.batch.append(document)
        self.source_counts[str(document.get("source_type") or "unknown")] += 1
        if len(self.batch) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if self.client is None or not self.batch:
            return
        self.client.bulk_index(self.batch)
        self.total += len(self.batch)
        self.batches += 1
        self.batch = []

    def close(self, db: Database, *, case_id: str) -> dict[str, Any] | None:
        if self.client is None:
            return None
        self.flush()
        run_id = str(uuid.uuid4())
        ended_at = utc_now()
        db.insert_search_index_run(
            {
                "id": run_id,
                "case_id": case_id,
                "backend": "opensearch",
                "backend_url": self.config.url,
                "index_name": self.config.index,
                "backend_version": self.backend_version,
                "status": "completed",
                "document_count": self.total,
                "batch_count": self.batches,
                "source_counts": dict(self.source_counts),
                "query_synonyms": [list(group) for group in DEFAULT_SYNONYM_GROUPS],
                "started_at": self.started_at,
                "ended_at": ended_at,
                "error": "",
                "created_at": ended_at,
            }
        )
        db.log_activity(
            case_id=case_id,
            level="info",
            event="search.opensearch_ingest_indexed",
            message=f"Indexed {self.total} content documents into OpenSearch during ingest",
            details={
                "index_run_id": run_id,
                "index": self.config.index,
                "url": self.config.url,
                "document_count": self.total,
                "batch_count": self.batches,
                "source_counts": dict(self.source_counts),
            },
        )
        return {
            "search_index_run_id": run_id,
            "document_count": self.total,
            "batch_count": self.batches,
            "source_counts": dict(self.source_counts),
        }


def mailbox_message_document(row: dict[str, Any], *, body_text: str, body_html: str) -> dict[str, Any] | None:
    content = "\n".join(part for part in (body_text, body_html) if part)
    if not content.strip():
        return None
    return _base_document(
        case_id=row["case_id"],
        computer_id=row.get("computer_id"),
        image_id=row.get("image_id"),
        source_type=_mailbox_source_type(row.get("source_format"), row.get("parser_status")),
        source_table="mailbox_messages",
        source_record_id=row["id"],
        document_id=row.get("opensearch_document_id"),
        source_path=row.get("message_path"),
        container_path=row.get("container_path"),
        title=row.get("subject"),
        content=content,
        timestamp=row.get("message_date_utc"),
        user_profile=row.get("user_profile"),
        extra={
            "user_sid": row.get("user_sid"),
            "source_format": row.get("source_format"),
            "subject": row.get("subject"),
            "sender": row.get("sender"),
            "recipients": row.get("recipients"),
            "cc": row.get("cc"),
            "bcc": row.get("bcc"),
            "attachment_names": row.get("attachment_names"),
            "dedupe_key": row.get("dedupe_key"),
            "parser_status": row.get("parser_status"),
            "parser_error": row.get("parser_error"),
            "created_at": row.get("created_at"),
        },
    )


def mailbox_attachment_document(row: dict[str, Any], *, extracted_text: str) -> dict[str, Any] | None:
    content = extracted_text
    if not content.strip():
        return None
    return _base_document(
        case_id=row["case_id"],
        computer_id=row.get("computer_id"),
        image_id=row.get("image_id"),
        source_type="email_attachment",
        source_table="mailbox_attachments",
        source_record_id=row["id"],
        document_id=row.get("opensearch_document_id"),
        source_path=row.get("attachment_path"),
        container_path=row.get("container_path"),
        title=row.get("attachment_name"),
        content=content,
        timestamp=row.get("message_date_utc"),
        user_profile=row.get("user_profile"),
        extra={
            "user_sid": row.get("user_sid"),
            "subject": row.get("subject"),
            "sender": row.get("sender"),
            "recipients": row.get("recipients"),
            "message_path": row.get("message_path"),
            "attachment_name": row.get("attachment_name"),
            "content_type": row.get("content_type"),
            "size": row.get("size"),
            "attachment_sha256": row.get("sha256"),
            "extraction_status": row.get("extraction_status"),
            "dedupe_key": row.get("dedupe_key"),
            "created_at": row.get("created_at"),
        },
    )


def windows_search_content_document(row: dict[str, Any], *, content_text: str) -> dict[str, Any] | None:
    if not content_text.strip():
        return None
    return _base_document(
        case_id=row["case_id"],
        computer_id=row.get("computer_id"),
        image_id=row.get("image_id"),
        source_type="indexed_file_content",
        source_table="windows_search_indexed_content",
        source_record_id=row["id"],
        document_id=row.get("opensearch_document_id"),
        source_path=row.get("item_path"),
        container_path="",
        title=row.get("item_name"),
        content=content_text,
        timestamp=row.get("timestamp") or row.get("gather_time"),
        user_profile=_user_from_path(row.get("item_path") or ""),
        extra={
            "source_record_parent_id": row.get("source_record_id"),
            "windows_search_source_table": row.get("source_table"),
            "work_id": row.get("work_id"),
            "item_type": row.get("item_type"),
            "content_field": row.get("content_field"),
            "created_at": row.get("created_at"),
        },
    )


def messaging_record_document(row: dict[str, Any], *, message_text: str) -> dict[str, Any] | None:
    content = message_text
    if not content.strip():
        return None
    return _base_document(
        case_id=row["case_id"],
        computer_id=row.get("computer_id"),
        image_id=row.get("image_id"),
        source_type="messaging_record",
        source_table="messaging_records",
        source_record_id=row["id"],
        document_id=row.get("opensearch_document_id"),
        source_path=row.get("source_path"),
        container_path=row.get("store_path"),
        title=row.get("application"),
        content=content,
        timestamp=row.get("timestamp_utc"),
        user_profile=row.get("user_profile"),
        extra={key: row.get(key) for key in ("application", "artifact_type", "record_type", "url", "host", "email", "dedupe_key")},
    )


def messaging_message_document(row: dict[str, Any], *, message_text: str, message_html: str) -> dict[str, Any] | None:
    content = "\n".join(part for part in (message_text, message_html) if part)
    if not content.strip():
        return None
    return _base_document(
        case_id=row["case_id"],
        computer_id=row.get("computer_id"),
        image_id=row.get("image_id"),
        source_type="chat_message",
        source_table="messaging_messages",
        source_record_id=row["id"],
        document_id=row.get("opensearch_document_id"),
        source_path=row.get("source_path"),
        container_path=row.get("store_path"),
        title=row.get("application"),
        content=content,
        timestamp=row.get("timestamp_utc"),
        user_profile=row.get("user_profile"),
        extra={
            key: row.get(key)
            for key in (
                "application", "conversation_id", "channel_id", "thread_id",
                "sender_id", "sender_name", "sender_email", "recipient",
                "message_type", "url", "parser_confidence", "dedupe_key",
            )
        },
    )


def search_case_content(
    *,
    case_id: str,
    query: str,
    config: OpenSearchConfig,
    limit: int = 25,
    synonym_groups: Iterable[Iterable[str]] | None = None,
) -> dict[str, Any]:
    client = OpenSearchRestClient(config)
    if synonym_groups is None:
        synonym_groups = DEFAULT_SYNONYM_GROUPS
    expanded_terms = _expanded_synonym_terms(query, synonym_groups)
    should_clauses = [
        {
            "multi_match": {
                "query": term,
                "fields": ["content"],
                "boost": 0.35,
            }
        }
        for term in expanded_terms
    ]
    bool_query: dict[str, Any] = {
        "filter": [{"term": {"case_id": case_id}}],
        "must": [
            {
                "multi_match": {
                    "query": query,
                    "fields": ["content"],
                }
            }
        ],
    }
    if should_clauses:
        bool_query["should"] = should_clauses
    body = {
        "size": limit,
        "query": {"bool": bool_query},
        "highlight": {
            "fields": {
                "content": {"fragment_size": 180, "number_of_fragments": 3},
            }
        },
    }
    response = client.request("POST", f"/{config.index}/_search", body)
    hits = []
    for hit in response.get("hits", {}).get("hits", []):
        source = hit.get("_source") or {}
        hits.append(
            {
                "score": hit.get("_score"),
                "source_type": source.get("source_type"),
                "source_table": source.get("source_table"),
                "source_record_id": source.get("source_record_id"),
                "computer_id": source.get("computer_id"),
                "image_id": source.get("image_id"),
                "content_hash": source.get("content_hash"),
                "content_length": source.get("content_length"),
                "highlight": hit.get("highlight", {}),
            }
        )
    return {
        "case_id": case_id,
        "index": config.index,
        "query": query,
        "synonym_expansions": expanded_terms,
        "total": response.get("hits", {}).get("total", {}),
        "hits": hits,
        "total_returned": len(hits),
    }


def load_synonym_groups(path: str | os.PathLike[str]) -> list[list[str]]:
    groups: list[list[str]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            terms = [term.strip() for term in text.split(",") if term.strip()]
            if len(terms) > 1:
                groups.append(terms)
    return groups


def search_result_drilldown(db: Database, *, case_id: str, source_table: str, source_record_id: str) -> dict[str, Any]:
    db.get_case(case_id)
    if source_table == "mailbox_messages":
        row = _row_by_id(db, "mailbox_messages", case_id, source_record_id)
        copies = []
        attachments = []
        related_windows_search = []
        related_mailbox_messages = []
        content_references = []
        if row:
            if row.get("dedupe_key"):
                copies = _rows_by_value(db, "mailbox_messages", case_id, "dedupe_key", row["dedupe_key"])
            if row.get("message_path"):
                attachments = _rows_by_value(db, "mailbox_attachments", case_id, "message_path", row["message_path"])
            content_references = _content_references_for_source(db, case_id, "mailbox_messages", source_record_id)
            related_windows_search = _related_sources_for_document(db, case_id, content_references, exclude_table="mailbox_messages", exclude_id=source_record_id)
            related_mailbox_messages = _related_sources_for_document(db, case_id, content_references, include_table="mailbox_messages", exclude_id=source_record_id)
        return {
            "case_id": case_id,
            "source_table": source_table,
            "source_record_id": source_record_id,
            "summary": _drilldown_summary(row, "mailbox_message"),
            "message": row,
            "copies": copies,
            "attachments": attachments,
            "content_references": content_references,
            "related_windows_search": related_windows_search,
            "related_mailbox_messages": related_mailbox_messages,
        }
    if source_table == "mailbox_attachments":
        row = _row_by_id(db, "mailbox_attachments", case_id, source_record_id)
        message = None
        sibling_attachments = []
        if row and row.get("message_path"):
            message = _first_row_by_value(db, "mailbox_messages", case_id, "message_path", row["message_path"])
            sibling_attachments = _rows_by_value(db, "mailbox_attachments", case_id, "message_path", row["message_path"])
        duplicate_attachments = []
        content_references = []
        if row:
            if row.get("sha256"):
                duplicate_attachments = _rows_by_value(db, "mailbox_attachments", case_id, "sha256", row["sha256"])
            elif row.get("dedupe_key"):
                duplicate_attachments = _rows_by_value(db, "mailbox_attachments", case_id, "dedupe_key", row["dedupe_key"])
            content_references = _content_references_for_source(db, case_id, "mailbox_attachments", source_record_id)
        return {
            "case_id": case_id,
            "source_table": source_table,
            "source_record_id": source_record_id,
            "summary": _drilldown_summary(row, "mailbox_attachment"),
            "attachment": row,
            "message": message,
            "sibling_attachments": sibling_attachments,
            "duplicate_attachments": duplicate_attachments,
            "content_references": content_references,
        }
    if source_table == "windows_search_indexed_content":
        row = _row_by_id(db, "windows_search_indexed_content", case_id, source_record_id)
        parent = None
        if row and row.get("source_table") in {"windows_search_files", "windows_search_internet_history", "windows_activities"}:
            parent = _row_by_id(db, row["source_table"], case_id, row["source_record_id"])
        content_references = _content_references_for_source(db, case_id, "windows_search_indexed_content", source_record_id) if row else []
        related_mailbox_messages = _related_sources_for_document(db, case_id, content_references, include_table="mailbox_messages") if row else []
        return {
            "case_id": case_id,
            "source_table": source_table,
            "source_record_id": source_record_id,
            "summary": _drilldown_summary(row, "windows_search_indexed_content"),
            "indexed_content": row,
            "source_record": parent,
            "content_references": content_references,
            "related_mailbox_messages": related_mailbox_messages,
        }
    allowed = {"windows_search_files", "windows_search_internet_history", "windows_activities"}
    if source_table in allowed:
        record = _row_by_id(db, source_table, case_id, source_record_id)
        return {
            "case_id": case_id,
            "source_table": source_table,
            "source_record_id": source_record_id,
            "summary": _drilldown_summary(record, source_table),
            "record": record,
        }
    raise OrchestratorError(f"Unsupported drilldown source table: {source_table}")


def _mailbox_source_type(source_format: str | None, parser_status: str | None) -> str:
    if parser_status == "body_file_extracted":
        if str(source_format or "").startswith("windows_mail_"):
            return "windows_mail_body"
        return "email_body_fragment"
    return "email"


def _base_document(
    *,
    case_id: str,
    computer_id: str | None,
    image_id: str | None,
    source_type: str,
    source_table: str,
    source_record_id: str,
    source_path: str | None,
    container_path: str | None,
    title: str | None,
    content: str,
    timestamp: str | None,
    user_profile: str | None,
    extra: dict[str, Any],
    document_id: str | None = None,
) -> dict[str, Any]:
    content_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    if not document_id:
        document_id = hashlib.sha256(f"{case_id}|content|{content_hash}".encode()).hexdigest()
    return {
        "id": document_id,
        "case_id": case_id,
        "computer_id": computer_id,
        "image_id": image_id,
        "source_type": source_type,
        "source_table": source_table,
        "source_record_id": source_record_id,
        "source_path": source_path,
        "container_path": container_path,
        "title": title,
        "content": content,
        "content_hash": content_hash,
        "content_length": len(content),
        "timestamp": timestamp,
        "user_profile": user_profile,
        "metadata": extra,
        "indexed_at": utc_now(),
    }


class OpenSearchRestClient:
    def __init__(self, config: OpenSearchConfig) -> None:
        self.config = config
        self.context = None
        if config.url.startswith("https://") and not config.verify_tls:
            self.context = ssl._create_unverified_context()

    def ensure_index(self) -> None:
        try:
            self.request("HEAD", f"/{self.config.index}")
            return
        except OrchestratorError as exc:
            if "HTTP 404" not in str(exc):
                raise
        self.request("PUT", f"/{self.config.index}", _index_mapping())

    def info(self) -> dict[str, Any]:
        return self.request("GET", "/")

    def delete_index(self, *, ignore_missing: bool = False) -> None:
        try:
            self.request("DELETE", f"/{self.config.index}")
        except OrchestratorError as exc:
            if ignore_missing and "HTTP 404" in str(exc):
                return
            raise

    def bulk_index(self, documents: list[dict[str, Any]]) -> None:
        if not documents:
            return
        lines = []
        for document in documents:
            doc_id = document["id"]
            payload = dict(document)
            payload.pop("id", None)
            lines.append(json.dumps({"index": {"_index": self.config.index, "_id": doc_id}}, default=str))
            lines.append(json.dumps(payload, default=str))
        response = self.request(
            "POST",
            "/_bulk",
            "\n".join(lines) + "\n",
            content_type="application/x-ndjson",
        )
        if response.get("errors"):
            failures = [
                item
                for item in response.get("items", [])
                if item.get("index", {}).get("error")
            ]
            raise OrchestratorError(f"OpenSearch bulk index reported {len(failures)} failures")

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | str | None = None,
        *,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        data = None
        if body is not None:
            data = (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
        request = urllib.request.Request(
            f"{self.config.url}{path}",
            data=data,
            method=method,
            headers={"Content-Type": content_type},
        )
        if self.config.username is not None and self.config.password is not None:
            token = base64.b64encode(f"{self.config.username}:{self.config.password}".encode()).decode()
            request.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=120) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise OrchestratorError(f"OpenSearch request failed: HTTP {exc.code} {detail}") from exc
        except urllib.error.URLError as exc:
            raise OrchestratorError(f"OpenSearch request failed: {exc}") from exc
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OrchestratorError(f"OpenSearch returned non-JSON response: {raw[:200]}") from exc


def _index_mapping() -> dict[str, Any]:
    keyword_fields = [
        "case_id",
        "computer_id",
        "image_id",
        "source_type",
        "source_table",
        "source_record_id",
        "content_hash",
    ]
    properties: dict[str, Any] = {
        field: {"type": "keyword", "ignore_above": 1024}
        for field in keyword_fields
    }
    properties.update(
        {
            "content": {"type": "text"},
            "content_length": {"type": "integer"},
            "indexed_at": {"type": "date", "ignore_malformed": True},
        }
    )
    return {"mappings": {"dynamic": True, "properties": properties}}


def _expanded_synonym_terms(query: str, groups: Iterable[Iterable[str]] | None) -> list[str]:
    if not groups:
        return []
    lowered = f" {query.lower()} "
    expanded: list[str] = []
    seen: set[str] = set()
    for group in groups:
        terms = [str(term).strip() for term in group if str(term).strip()]
        if not terms:
            continue
        if any(term.lower() in lowered for term in terms):
            for term in terms:
                if term.lower() == query.lower() or term.lower() in seen:
                    continue
                seen.add(term.lower())
                expanded.append(term)
    return expanded


def _row_by_id(db: Database, table: str, case_id: str, row_id: str | None) -> dict[str, Any] | None:
    if not row_id:
        return None
    row = db.conn.execute(
        f"SELECT * FROM {table} WHERE case_id = ? AND id = ?",
        (case_id, row_id),
    ).fetchone()
    return dict(row) if row else None


def _table_exists(db: Database, table: str) -> bool:
    row = db.conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _content_references_for_source(db: Database, case_id: str, source_table: str, source_row_id: str) -> list[dict[str, Any]]:
    if not _table_exists(db, "content_references"):
        return []
    rows = db.conn.execute(
        """
        SELECT *
        FROM content_references
        WHERE case_id = ? AND source_table = ? AND source_row_id = ?
        ORDER BY content_role, id
        """,
        (case_id, source_table, source_row_id),
    ).fetchall()
    return [dict(row) for row in rows]


def _related_sources_for_document(
    db: Database,
    case_id: str,
    references: list[dict[str, Any]],
    *,
    include_table: str | None = None,
    exclude_table: str | None = None,
    exclude_id: str | None = None,
) -> list[dict[str, Any]]:
    if not references or not _table_exists(db, "content_references"):
        return []
    document_ids = sorted({str(row.get("opensearch_document_id") or "") for row in references if row.get("opensearch_document_id")})
    if not document_ids:
        return []
    placeholders = ", ".join("?" for _ in document_ids)
    filters = [f"case_id = ?", f"opensearch_document_id IN ({placeholders})"]
    params: list[Any] = [case_id, *document_ids]
    if include_table:
        filters.append("source_table = ?")
        params.append(include_table)
    if exclude_table:
        filters.append("source_table != ?")
        params.append(exclude_table)
    if exclude_id:
        filters.append("source_row_id != ?")
        params.append(exclude_id)
    rows = db.conn.execute(
        f"""
        SELECT source_table, source_row_id, source_tool, content_role,
               opensearch_document_id, content_sha256, content_length, source_path
        FROM content_references
        WHERE {' AND '.join(filters)}
        ORDER BY source_table, source_row_id
        LIMIT 25
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def _drilldown_summary(row: dict[str, Any] | None, source_kind: str) -> dict[str, Any]:
    if not row:
        return {"source_kind": source_kind, "found": False}
    path = row.get("source_path") or row.get("message_path") or row.get("attachment_path") or row.get("item_path")
    title = row.get("subject") or row.get("attachment_name") or row.get("item_name") or row.get("title")
    timestamp = row.get("message_date_utc") or row.get("timestamp") or row.get("gather_time") or row.get("created_at")
    return {
        "source_kind": source_kind,
        "found": True,
        "case_id": row.get("case_id"),
        "computer_id": row.get("computer_id"),
        "image_id": row.get("image_id"),
        "user_profile": row.get("user_profile") or _user_from_path(str(path or "")),
        "timestamp": timestamp,
        "title": title,
        "source_path": path,
        "container_path": row.get("container_path"),
        "tool_name": row.get("tool_name"),
        "tool_output_id": row.get("tool_output_id"),
        "dedupe_key": row.get("dedupe_key"),
    }


def _rows_by_value(db: Database, table: str, case_id: str, column: str, value: str | None) -> list[dict[str, Any]]:
    if not value:
        return []
    return [
        dict(row)
        for row in db.conn.execute(
            f"SELECT * FROM {table} WHERE case_id = ? AND {column} = ? ORDER BY created_at, id",
            (case_id, value),
        ).fetchall()
    ]


def _first_row_by_value(db: Database, table: str, case_id: str, column: str, value: str | None) -> dict[str, Any] | None:
    rows = _rows_by_value(db, table, case_id, column, value)
    return rows[0] if rows else None


def _user_from_path(path: str) -> str:
    parts = [part for part in path.replace("\\", "/").split("/") if part]
    lowered = [part.lower() for part in parts]
    for marker in ("users", "documents and settings"):
        if marker in lowered:
            index = lowered.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1]
    return ""


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}
