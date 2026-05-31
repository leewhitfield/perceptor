# Reports

Reports are investigator-facing views over parsed data. Use reports before raw
table searches when a report exists for the question.

For the complete list of report subcommands, see
[Report Catalog](report-catalog.md).

## Common Reports

```bash
uv run relic --root ~/analysis/case-root report dashboard --case CASE_ID --format table
uv run relic --root ~/analysis/case-root report progress --case CASE_ID --format table
uv run relic --root ~/analysis/case-root report suspicious-executions --case CASE_ID --format md
uv run relic --root ~/analysis/case-root report external-storage --case CASE_ID --format md
uv run relic --root ~/analysis/case-root report usb-files --case CASE_ID --format md
uv run relic --root ~/analysis/case-root report opened-from-removable-media --case CASE_ID --format md
uv run relic --root ~/analysis/case-root report opened-from-cloud-storage --case CASE_ID --format md
uv run relic --root ~/analysis/case-root report file-movement-identity --case CASE_ID --format md
uv run relic --root ~/analysis/case-root report memory-analysis --case CASE_ID --format md
```

## Formats

Most reports support:

- `json`
- `table`
- `csv`
- `md`

Use Markdown for examiner review, CSV for spreadsheet review, and JSON for
automation.

## Output Path

```bash
uv run relic --root ~/analysis/case-root report usb-files \
  --case CASE_ID \
  --format md \
  --output ~/analysis/case-root/cases/CASE_ID/outputs/reports/usb-files.md
```

## Distinct Tables

Relic rebuilds distinct/deduped artifact tables after imports and processing.
Reports should prefer these deduped views when available.
