# Reference-Derived Open Work

Date: 2026-05-23

This file tracks only reference-derived work that remains open, so it can be
used as a backlog rather than a historical status report.

The active coverage control document is `docs/artifact-coverage-matrix.md`.

## Open Items

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
