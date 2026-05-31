# Source-of-Truth Routing

MCP clients should not jump straight to image tools. Relic now exposes a routing
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

## Processing and Recovery

Processing tools require both:

- MCP server started with `--allow-processing`.
- an explicit user request for processing, import, profile execution, or
  recovery.

Deleted-file recovery should first identify the target in parsed listings, then
run `relic_recover_deleted_files` only when requested.

The MCP job log records the Relic recovery command. The recovery manifest records
the exact `icat` command for each file candidate.

## Sensitive and External AI Gates

Credential reveal requires `--allow-sensitive`.

External AI upload or analysis requires `--allow-external-ai`.
