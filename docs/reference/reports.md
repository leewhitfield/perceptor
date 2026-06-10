# Reports

Reports are investigator-facing views over parsed data. Use reports before raw
table searches when a report exists for the question.

For the complete list of report subcommands, see
[Report Catalog](report-catalog.md).

## Common Reports

```bash
uv run perceptor --root ~/analysis/case-root report dashboard --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report progress --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report suspicious-executions --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report software-footprint-review --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report external-storage --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report usb-files --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report opened-from-removable-media --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report opened-from-cloud-storage --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report file-movement-identity --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report memory-analysis --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report structured-memory --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report bits-activity --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report examiner-edge-artifacts --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report mapped-network-paths --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report non-standard-ads --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report ntfs-security-descriptors --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report remote-access-tool-logs --case CASE_ID --format table
```

## Software Footprint Review

`software-footprint-review` compares current installed-program inventory with
execution, persistence, user-activity, presence, download, and filesystem
remnants. Use it to identify applications that are currently installed, likely
uninstalled, portable, or represented only by historical residue.

```bash
uv run perceptor --root ~/analysis/case-root report software-footprint-review --case CASE_ID --format md
uv run perceptor --root ~/analysis/case-root report software-footprint-review --case CASE_ID --target anydesk --format json
```

The report is inventory-first. Absence from installed inventory means no
matching installed-program artifact was parsed; corroborate with source rows
before treating a footprint as a confirmed uninstall.

## Examiner Edge Artifacts

`examiner-edge-artifacts` surfaces small, high-value artifacts that commonly
produce leads:

- Sticky Notes.
- Windows notifications.
- NetworkList, outbound RDP history, and MountPoints2 registry rows.
- EventTranscript.db diagnostic telemetry rows where present, with app launch,
  file, network, and device-census rows classified where possible.
- Scheduled Task XML files.
- TokenBroker cache metadata and account leads. Token-like values are not
  emitted as report text.
- CryptnetUrlCache and hosts file mappings.
- Legacy `Thumbs.db` presence metadata and OLE stream inventory when the
  `olefile` parser is available.
- WSL presence/history, Windows Update registry/DataStore presence, Credential
  Manager/Vault metadata, Bluetooth paired-device registry rows, installed
  application registry rows, and SwiftKey/InputPersonalization leads.

Credential and Vault entries are metadata-only unless separate DPAPI context is
available. SwiftKey/InputPersonalization strings are investigative fragments,
not standalone proof of typed content.

## Mapped Network Paths

`mapped-network-paths` decodes MountPoints2 network-share keys from user
registry hives. Keys in the form `##host#share#path` are reported as UNC-style
paths such as `\\host\share\path`, with the associated user profile, first/last
observed key times, and sampled registry values. Use this report for mapped
network drives, UNC share access, and MountPoints2 network questions.

## Non-Standard ADS

`non-standard-ads` reports MFT alternate data stream rows beyond common
`Zone.Identifier` streams. It classifies common Cloud Files/OneDrive metadata,
WOF compression, SmartScreen, and NTFS metadata streams as expected/low-priority
so unclassified streams stand out. Treat high-priority rows as leads for hidden
content or unusual file metadata and corroborate with file extraction where
possible.

## NTFS Security Descriptors

`ntfs-security-descriptors` inventories `$Secure` security descriptor streams
such as `$SDS`, `$SII`, and `$SDH` when they appear in MFT ADS rows. The current
report is presence/metadata-only; structured ACL interpretation requires
dedicated `$Secure:$SDS` parsing or MFTECmd security descriptor output.

## Remote Access Tool Logs

`remote-access-tool-logs` surfaces collected AnyDesk, TeamViewer, LogMeIn,
ConnectWise Control, Splashtop, RustDesk, VNC-family, and similar remote-support
application logs or candidate files. Log lines are normalized into connection,
authentication, transfer, and identity/routing leads where possible. Correlate
these rows with execution, remote-access sessions, and network artifacts.

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
uv run perceptor --root ~/analysis/case-root report bits-activity \
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
uv run perceptor --root ~/analysis/case-root report event-interpretation \
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
uv run perceptor --root ~/analysis/case-root report clipboard \
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

## Limits

Interactive reports and MCP tools may use bounded defaults so output stays
readable. A bounded response is a preview, not evidence that no additional
records exist.

When JSON includes `limited: true`, `limit`, `total_available`,
`result_limit`, or `result_limit_warning`, regenerate the saved report/export
with a higher `--limit` or request the full report context before relying on
absence. Report bundles default to broader exports, but very large cases can
still require an explicit higher limit.

## Output Path

```bash
uv run perceptor --root ~/analysis/case-root report usb-files \
  --case CASE_ID \
  --format md \
  --output ~/analysis/case-root/cases/CASE_ID/outputs/reports/usb-files.md
```

## Distinct Tables

Perceptor rebuilds distinct/deduped artifact tables after imports and processing.
Reports should prefer these deduped views when available.
