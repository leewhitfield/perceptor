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
uv run relic --root ~/analysis/case-root report bits-activity --case CASE_ID --format table
```

## BITS Activity

`bits-activity` correlates timestamped BITS Client EVTX events with qmgr
database or carved BITS rows when an exact job ID or URL match exists. Use it
for Background Intelligent Transfer Service, qmgr, OneDrive updater, component
updater, and transfer-job questions.

The JSON payload includes `total_returned`, `total_available`, `limit`, and
`limited`. If `limited` is true, regenerate with a higher `--limit` before
relying on absence of a specific BITS row.

For an existing case processed before BITS activity support was added, rebuild
the derived table from stored EVTX rows:

```bash
uv run relic --root ~/analysis/case-root report bits-activity \
  --case CASE_ID \
  --rebuild \
  --format table
```

Carved qmgr rows without native timestamps remain investigative leads. The
report treats BITS Client EVTX as the timestamp source and records qmgr
correlation separately.

## Event Interpretation

`event-interpretation` is the high-value EVTX analytics report. It targets:

- Account manipulation: `4720`, `4722`, `4724`, `4725`, `4726`,
  `4728`, `4729`, `4732`, `4733`, `4738`, `4756`, `4757`.
- Audit log clearing: Security `1102` and System `104`.
- PowerShell: `4103`, `4104`, and related engine/module/script-block events.
- Scheduled tasks: Security `4698`, `4699`, plus TaskScheduler definition and
  action events.
- WMI persistence indicators: WMI-Activity `5857` through `5861`, with
  `5859`, `5860`, and `5861` highlighted as filter, consumer, and binding
  evidence.
- Print history: PrintService `307`, `805`, and `842` events where present.
- Process creation: Security `4688`, including command/process context where
  present.
- Service installs: `4697` and `7045`.

Example:

```bash
uv run relic --root ~/analysis/case-root report event-interpretation \
  --case CASE_ID \
  --category powershell \
  --format table
```

## Clipboard

`clipboard` reports Windows clipboard-history artifacts from
`%LocalAppData%\Microsoft\Clipboard` when present. It includes copied text,
file URI, HTML/image indicators, item timestamps, cloud sync state, cloud sync
ID, source device ID, and parser status.

Example:

```bash
uv run relic --root ~/analysis/case-root report clipboard \
  --case CASE_ID \
  --contains "copied text" \
  --format table
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
