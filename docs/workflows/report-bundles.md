# Report Bundles

Report bundles are generated outputs for review, handoff, MCP clients, and UI
consumption.

## Write a Bundle

```bash
uv run perceptor --root ~/analysis/case-root report bundle \
  --case CASE_ID \
  --purpose triage \
  --output ~/analysis/case-root/cases/CASE_ID/outputs/reports/triage-bundle
```

Common purposes:

- `triage`
- `usb`
- `cloud`
- `execution`
- `memory`
- `review`
- `full`

## Validate Outputs

```bash
uv run perceptor --root ~/analysis/case-root report validate-outputs \
  --path ~/analysis/case-root/cases/CASE_ID/outputs/reports/triage-bundle \
  --format table
```

## Import a Bundle

```bash
uv run perceptor --root ~/analysis/case-root report-bundle import \
  --path ~/reports/HOST01 \
  --case CASE_ID \
  --computer-label HOST01
```

## Import Many

Use this when a folder or ZIP contains multiple computer folders:

```bash
uv run perceptor --root ~/analysis/case-root report-bundle import-many \
  --path ~/evidence/live-case.zip \
  --accept-duplicate
```

## Coverage

```bash
uv run perceptor --root ~/analysis/case-root report-bundle coverage \
  --path ~/evidence/live-case.zip \
  --format table
```
