# Source-of-Truth Routing

MCP clients should not jump straight to image tools. Perceptor now exposes a routing
tool that returns the correct source order for a question.

## First Tool

Use:

```text
relic_route_question
```

Inputs:

- `question`: examiner question.
- `case_id`: optional case ID.
- `evidence_hint`: optional device, image, volume, or computer hint.
- `allow_processing`: whether this specific route may recommend processing.

## Default Source Order

1. Existing generated reports.
2. Parsed artifact tables.
3. Generated resources, packets, and job output.
4. Direct image access, mounts, FLS, recovery, or processing.

## Result Limits

MCP answers are bounded for usability. Treat `result_limit` and
`result_limit_warning` as analyst-facing caveats. A bounded response is not
evidence that no additional records exist; increase the limit, read the saved
report/export, or request a dossier/full context for material findings.

## Filesystem Questions

For questions like "pull a list of contents for the USB drive", use:

```text
relic_query_evidence_contents
relic_query_filesystem_listings
```

These read `filesystem_entries` and avoid slow FLS/mount behavior.

## Report Questions

For report-backed questions, use:

```text
relic_read_existing_report
relic_discover_report_exports
```

Generate or regenerate reports only when existing reports are absent, stale, or
the user explicitly asks.

## Indexed File Content

For questions about file content, search the OpenSearch-backed content index
before attempting direct file extraction:

```text
relic_search_content
relic_get_indexed_content
```

`relic_search_content` returns snippets and reports when full indexed content is
available. Snippets are not the whole body. Use `relic_get_indexed_content` with
the returned document ID when the user asks to read the full indexed content.

## BITS and qmgr Questions

For Background Intelligent Transfer Service, qmgr, OneDrive updater, component
updater, or transfer-job questions, use:

```text
relic_generate_report
```

with `report_name: "bits-activity"`.

`bits-activity` is the source of truth because it correlates timestamped BITS
Client EVTX rows with qmgr database/carved rows by exact job ID or URL where
available. qmgr carved rows without native timestamps are leads only; the
timestamp source is the EVTX event.

## High-Value Event Log Questions

For account changes, audit-log clearing, PowerShell script blocks, scheduled
task creation/deletion, WMI event subscription indicators, print-service
history, service installs, or process creation with command-line context, use
existing/generated reports first:

```text
relic_read_existing_report
relic_generate_report
```

with `report_name: "event-interpretation"`.

Use category-specific filtering when the user asks a narrow question, such as
`powershell`, `account_manipulation`, `audit_log_clearing`, `scheduled_task`,
`wmi_persistence`, `print`, `service_install`, or `process_creation`.

## Clipboard Questions

For clipboard, copied, pasted, cloud clipboard, or sync-across-devices
questions, use existing/generated reports first:

```text
relic_read_existing_report
relic_generate_report
```

with `report_name: "clipboard"`.

Use `relic_timeline_window` for time-window context after the clipboard report.
Treat Windows Activities clipboard payloads as secondary clipboard-adjacent
evidence, not the primary dedicated clipboard store.

## Processing and Recovery

Processing tools require both:

- MCP server started with `--allow-processing`.
- an explicit user request for processing, import, profile execution, or
  recovery.

Deleted-file recovery should first identify the target in parsed listings, then
run `relic_recover_deleted_files` only when requested.

The MCP job log records the Perceptor recovery command. The recovery manifest records
the exact `icat` command for each file candidate.

## Sensitive and External AI Gates

Credential reveal requires `--allow-sensitive`.

External AI upload or analysis requires `--allow-external-ai`.
