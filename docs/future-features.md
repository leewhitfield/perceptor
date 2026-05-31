# Future Features

This page tracks features and platform areas that have been discussed or
partially explored but are not yet supported as complete Relic workflows.

Items here are intentionally separate from the operator workflows. Do not treat
them as supported case-processing paths until they move into the normal
documentation and pass release verification.

## Windows Recall

Add Windows Recall artifact support when evidence availability, schema behavior,
privacy constraints, and parsing expectations are better defined.

Potential work:

- Detect Recall databases, screenshots, and related metadata.
- Parse bounded metadata into DuckDB.
- Route screenshot OCR or extracted text through the content indexing policy.
- Add Recall-specific reports and timeline integration.
- Define privacy and sensitive-content handling rules before exposing results
  through MCP.

## Windows Search SQL Processing

Relic parses supported Windows Search outputs and records unsupported encrypted
Search states, but Windows 11 `AesGcm1` encrypted SQLite Search databases are not
fully decrypted offline.

Potential work:

- Add a dedicated Windows Search SQLite processing workflow for unencrypted or
  decrypted SQL databases.
- Store SQL table inventory, schema, parser status, and extracted rows in
  normalized tables.
- Add controlled DPAPI/LSA-assisted decryption only when collected artifacts
  actually unlock the target database.
- Keep failure states reportable without crashing the processing run.
- Add report guidance that distinguishes supported parsing, encrypted databases,
  memory-carved fragments, and live-collection requirements.

## macOS Processing

Relic is currently Ubuntu-only for supported operation and Windows-focused for
most artifact coverage. Native macOS evidence processing is future work.

Potential work:

- Add macOS artifact profiles.
- Parse APFS metadata where supported by Linux tooling.
- Add macOS user activity, browser, cloud, application, and timeline reports.
- Define image mounting expectations for APFS, FileVault, DMG, sparsebundle, and
  Time Machine sources.
- Add platform-specific dependency checks.

## Linux Desktop Processing

Linux endpoint processing is not a supported profile today.

Potential work:

- Add Linux user activity profiles.
- Parse shell history, desktop files, browser profiles, systemd journals, audit
  logs, package logs, mounts, removable media history, and cloud-sync artifacts.
- Add Linux-specific reports and timeline categories.

## Web UI

Relic is CLI-first today. Reports, MCP, and structured outputs are intended to
support a future UI.

Potential work:

- Case dashboard.
- Processing progress view.
- Evidence and report browser.
- Timeline review.
- USB/storage review.
- File recovery review with manifest display.
- MCP packet and report bundle viewer.

## OpenSearch Hardening

OpenSearch is assumed local in the current deployment model.

Potential work:

- TLS and authentication guidance.
- Index lifecycle management.
- Backup and restore workflow.
- Reindex or migration workflow for content-heavy artifacts.
- Clear deployment model for single-user local use versus shared infrastructure.

## External AI Review

External AI usage is gated and should remain policy-driven.

Potential work:

- Add explicit per-case approval state.
- Redaction and minimization before outbound requests.
- Audit prompts, model, request metadata, and result provenance.
- Keep local OCR and non-AI parsing as fallback paths.

## Server-Side Cloud Logs

Relic currently focuses on endpoint evidence and imported report bundles.

Potential work:

- Import server-side logs from Microsoft 365, Google Workspace, Dropbox, Slack,
  and similar providers.
- Label these as non-image evidence sources.
- Correlate server-side cloud events with endpoint cloud-sync artifacts.
- Add source-specific trust and timestamp caveats.

## Report and Documentation Automation

The report catalog is currently generated manually from `report --help`.

Potential work:

- Generate the report catalog during release checks.
- Add command metadata descriptions for every report.
- Link report catalog entries to examples and output schemas.
- Add stale-doc detection to CI.
