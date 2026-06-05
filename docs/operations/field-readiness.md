# Field Readiness

This page covers operational behavior examiners should understand before
starting a long run.

## Evidence Integrity

Relic hashes disk images on import with MD5, SHA1, and SHA256. Re-verify before
final reporting:

```bash
uv run relic --root ROOT image integrity --case CASE_ID --image IMAGE_ID --format table
uv run relic --root ROOT image verify --case CASE_ID --image IMAGE_ID --format table
```

Files materialized from evidence through TSK `icat` are recorded in
`report evidence-extractions` with source path, inode, extracted path, size, and
SHA256.

## Disk Preflight

Run workspace and processing estimates before large processing jobs:

```bash
uv run relic --root ROOT report workspace-health --case CASE_ID --format table
uv run relic --root ROOT report processing-estimate --case CASE_ID --profile windows-full --format table
```

`processing-estimate` is a conservative warning tool, not an exact prediction.
Deep recovery, carving, and artifact-heavy images can exceed the estimate.

## Resumability

Relic tracks jobs, process timings, tool outputs, progress manifests, and
resume-plan signals. After an interrupted run:

```bash
uv run relic --root ROOT report progress --case CASE_ID --format table
uv run relic --root ROOT report resume-plan --case CASE_ID --format table
uv run relic --root ROOT report processing-readiness --case CASE_ID --profile windows-full --format table
```

For live-case/report ZIP imports, use the generated manifest with
`--resume-from-manifest` to skip completed computer folders.

## Reporting and MCP Limits

Interactive reports and MCP tools use limits so output remains usable. A limit
is not evidence of absence.

- MCP responses include `result_limit` or `result_limit_warning` when a limit is
  active or reached.
- Report bundles default to broader saved exports.
- Increase `--limit`, read an existing generated report/export, or request a
  dossier/full context when a result is material.

## Multi-Partition Images

Relic can inventory multiple partitions and filesystem types. The preferred
workflow mounts selected supported filesystems read-only under `/tmp` for fast
artifact access. TSK is used as fallback for recovery and artifacts not
available through a mounted namespace.

If an image contains BitLocker plus unencrypted partitions, unlock failures
should be treated as scoped limitations. Continue processing accessible
unencrypted partitions where the workflow supports it, and document the locked
partition as unavailable until a valid protector is supplied.

## Corrupt or Partial Artifacts

Real images often contain corrupt hives, incomplete EVTX files, malformed
SQLite/ESE databases, and partially recoverable filesystem records. Relic should
skip the bad artifact, record the failure or caveat, and continue the profile
where possible.

Use:

```bash
uv run relic --root ROOT report issues --case CASE_ID --format table
uv run relic --root ROOT report artifact-processing-status --case CASE_ID --format table
uv run relic --root ROOT report processing-decisions --case CASE_ID --format table
```

Expected limitations should be described as warnings, caveats, or unavailable
coverage rather than fatal application errors.

## Keyword Search

For “search the whole case” questions, use both:

```bash
uv run relic --root ROOT report artifact-search --case CASE_ID --query "needle" --limit 1000 --format table
uv run relic --root ROOT search query --case CASE_ID --query "needle" --limit 100
```

`artifact-search` covers parsed fields such as paths, registry values, browser
URLs, shortcut targets, usernames, device IDs, and event text. `search query`
covers OpenSearch indexed content such as document, email, attachment, message,
and selected extracted text.

## Known Limitations

- UTC is authoritative. Local time display is optional and display-only.
- Exact processing size cannot be predicted before parsing.
- Some proprietary databases and encrypted stores may be unreadable without live
  collection, user context, or valid keys.
- Unsupported corrupt artifacts should be logged and skipped; they should not be
  interpreted as clean absence.
- MCP output is bounded. Use reports/exports or higher limits for full review.
