# Live-Case and Report ZIPs

Use this workflow for a ZIP with one top-level folder per computer or device.

## Preflight

```bash
uv run perceptor --root ~/analysis/case-root ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --preflight \
  --format table \
  --max-uncompressed-gb 75
```

Preflight reports detected computer folders, CSV counts, parser mapping, ZIP
member counts, compressed size, and uncompressed size.

## Import

```bash
uv run perceptor --root ~/analysis/case-root ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --accept-duplicate \
  --report-purpose triage
```

By default, Perceptor creates or reuses a case, creates one computer per top-level
folder, imports mapped CSVs, logs unsupported CSVs, rebuilds distinct artifact
tables, writes a triage bundle, and writes progress JSON under `ROOT/progress/`.

## Progress

```bash
uv run perceptor --root ~/analysis/case-root report dashboard --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report progress --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report unmapped-imports --case CASE_ID --format table
```

## ZIP Safety

Perceptor rejects unsafe ZIP members:

- absolute paths.
- drive-letter paths.
- parent-directory traversal.
- empty paths.
- link or device entries.
- more than 1,000,000 file members.
- expansion that would exceed available workspace space while leaving reserve.

There is no fixed evidence-size cap. The practical limit is available workspace
space.
