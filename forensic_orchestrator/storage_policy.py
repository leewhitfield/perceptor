from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class StoragePolicyItem:
    name: str
    storage: str
    purpose: str
    examples: tuple[str, ...]
    rule: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["examples"] = list(self.examples)
        return value


DUCKDB_POLICY = StoragePolicyItem(
    name="normalized_facts",
    storage="duckdb",
    purpose="Auditable analytics store for structured artifact facts, provenance, dedupe keys, and report-ready relationships.",
    examples=(
        "mft_entries",
        "usn_journal_entries",
        "shortcut_items",
        "registry_artifacts",
        "cloud_sync_artifacts",
        "file_correlations",
    ),
    rule="Use explicit columns for fields that are queried, joined, filtered, sorted, or shown in reports. Do not stage parsed rows through SQLite.",
)

SQLITE_POLICY = StoragePolicyItem(
    name="orchestration_metadata",
    storage="sqlite",
    purpose="Small case-control database for cases, images, mounts, jobs, tool outputs, timings, activity logs, and run state.",
    examples=(
        "cases",
        "images",
        "mounts",
        "jobs",
        "tool_outputs",
        "process_timings",
        "activity_log",
    ),
    rule="Keep SQLite limited to orchestration and bounded provenance. Parsed artifact facts belong in DuckDB.",
)

ARTIFACT_FILE_POLICY = StoragePolicyItem(
    name="raw_outputs",
    storage="case_artifact_files",
    purpose="Immutable raw parser output, extracted evidence-derived files, and large exported artifacts.",
    examples=(
        "tool CSV exports",
        "raw JSON/XML parser exports",
        "extracted attachments",
        "copied registry hives",
        "stdout/stderr logs",
    ),
    rule="Store large or tool-native output on disk and keep path, hash, row count, and provenance in SQLite.",
)

OPENSEARCH_POLICY = StoragePolicyItem(
    name="searchable_content",
    storage="opensearch",
    purpose="Rebuildable full-text index for large text search and investigator keyword workflows.",
    examples=(
        "email body text",
        "attachment extracted text",
        "Windows Search indexed content",
        "message fragments",
        "note bodies",
        "AI assistant conversation text",
        "future OCR text",
    ),
    rule="Index large searchable text in OpenSearch during ingest; keep DuckDB/SQLite references to source table/row, hashes, lengths, and metadata.",
)

SQLITE_DETAILS_POLICY = StoragePolicyItem(
    name="small_details_json",
    storage="sqlite_details_json",
    purpose="Small bounded provenance or parser context that is useful but not stable enough to become first-class columns yet.",
    examples=(
        "parser notes",
        "source-specific option flags",
        "small decoded metadata fragments",
    ),
    rule="Keep JSON small and bounded; never use it for raw exports, large text, or unparsed artifact payloads. Promote fields to columns when reports, joins, filters, or repeated interpretation depend on them.",
)


STORAGE_POLICY = (
    DUCKDB_POLICY,
    SQLITE_POLICY,
    ARTIFACT_FILE_POLICY,
    OPENSEARCH_POLICY,
    SQLITE_DETAILS_POLICY,
)


CONTENT_HEAVY_TABLES = (
    {
        "table": "mailbox_messages",
        "large_columns": ("body_text", "body_html"),
        "policy": "opensearch",
        "sqlite_role": "message metadata, dedupe, provenance, body reference",
    },
    {
        "table": "mailbox_attachments",
        "large_columns": ("extracted_text",),
        "policy": "opensearch",
        "sqlite_role": "attachment metadata, hashes, extraction status, path",
    },
    {
        "table": "windows_search_indexed_content",
        "large_columns": ("content_text",),
        "policy": "opensearch",
        "sqlite_role": "source record mapping and indexed-content provenance",
    },
    {
        "table": "messaging_messages",
        "large_columns": ("message_text", "message_html"),
        "policy": "opensearch",
        "sqlite_role": "messaging/note/AI-app metadata, participants, timestamps, source mapping",
    },
)


def storage_policy_items() -> list[dict[str, Any]]:
    return [item.to_dict() for item in STORAGE_POLICY]
