# Reference-Derived Open Work

Date: 2026-05-23

This file tracks only reference-derived work that remains open, so it can be
used as a backlog rather than a historical status report.

The active coverage control document is `docs/artifact-coverage-matrix.md`.

## Open Items

### SetupAPI Device Install Chronology

Add normalized parsing for `setupapi.dev.log`.

Purpose:

- strengthen USB, UASP/SCSI, MTP/PTP, Bluetooth, printer, HID, and other device
  installation timelines
- provide install/start/removal context beyond registry keys and event logs
- add source-labeled rows to external-storage and device dossier reports

Expected storage:

- parsed metadata in DuckDB
- no raw log bodies in DuckDB
- source path, line/range reference, device instance ID, class, service,
  inf/driver package, timestamp, and confidence/caveat fields

### Selective Browser And App Deep-Storage Content Parsers

The current deep-storage work inventories browser/app storage and parses known
metadata. Remaining work is selective content extraction for known schemas.

Targets:

- IndexedDB
- OPFS
- LevelDB
- Electron/WebView2 app stores
- known app schemas for Slack, Teams, Discord, Signal, WhatsApp, Telegram,
  ChatGPT, Claude, Codex, Notion, Obsidian, OneNote, Zoom, and similar apps

Storage boundary:

- structured metadata in DuckDB
- message, note, assistant conversation, document, and other readable body
  content in OpenSearch
- no raw databases, large JSON blobs, binary values, or unparsed chunks in
  DuckDB

### Server-Side Cloud Log Imports

These are not local disk-image artifacts. Treat them as separate evidence
imports/connectors when provided.

Potential sources:

- Microsoft Purview
- Microsoft Unified Audit Log
- Exchange audit logs
- Exchange Recoverable Items exports
- Google Vault
- Google Workspace audit logs

Expected behavior:

- source-labeled import separate from disk image parsing
- compact event metadata in DuckDB
- message/file/content bodies in OpenSearch where applicable
- correlation to local artifacts after import, not by duplicating local data

### Additional Prefetch Hash Reference Sets

Add more trusted public or analyst-provided hash/path reference lists.

Rules:

- keep reference data outside case evidence
- label matches as reference-based enrichment
- never treat a lookup match as proof the resolved path existed on the analysed
  system without corroborating image evidence

### Low-Level Outlook PR_* Extraction

Mailbox metadata currently includes bounded headers, conversation fields,
attachment metadata, and OpenSearch body/content routing. Remaining work is
deeper MAPI property extraction if a parser/library exposes it cleanly.

Candidate fields:

- `PR_Conversation_Index`
- `PR_Message_Flags`
- other read/replied/forwarded state fields

Constraints:

- do not store message bodies or raw MAPI blobs in DuckDB
- retain source message/container references
- preserve attachment provenance for file-history correlation
