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

Initial support is available through:

```bash
perceptor --root /case/root cloud import-logs --case CASE_ID --path /evidence/cloud-export
perceptor --root /case/root report cloud-server-events --case CASE_ID --format table
```

The importer accepts CSV, JSON, JSONL, and directories containing those files.
It normalizes common Microsoft 365, Google Workspace, Vault, Purview, and audit
field names into `cloud_server_events`. Large content/body fields are routed
through the OpenSearch content path and referenced by document ID.

### Memory-Adjacent String Leads

Full memory parsing depends on a memory image and specialist tooling. For
on-disk memory-adjacent artifacts, the first-pass workflow is targeted string
triage:

```bash
perceptor --root /case/root memory strings --case CASE_ID --path /mounted/hiberfil.sys
perceptor --root /case/root report memory-string-hits --case CASE_ID --format table
```

If a supported hiberfil decompressor is available (`hibr2bin` or
`HibernationRecon`), the scanner attempts to decompress `hiberfil.sys` under the
case root before string scanning. If not, it records the fallback status and
scans the original file. String hits are investigative leads only.
