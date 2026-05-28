# Relic User Manual

Relic is a CLI-first forensic processing and reporting tool. It can process
Windows disk images, import pre-generated triage/report bundles, normalize many
artifact outputs into a case database, dedupe derived artifacts, and generate
investigator-facing reports.

The executable names are:

- `relic`
- `forensic-orchestrator`

Examples below use `uv run relic`. If Relic is installed as a console script,
drop `uv run`.

## Core Concepts

- **Workspace root**: the directory that stores cases, outputs, logs, staging
  data, and SQLite/DuckDB databases.
- **Case/project**: a single investigation container. Most commands use
  `--case CASE_ID`.
- **Computer**: a device inside a case. Bulk live-case zips create one computer
  per top-level folder.
- **Image/evidence**: a disk image, mounted volume, triage folder, or imported
  report bundle.
- **Profile**: a configured group of artifact parsers. Examples include
  `windows-full`, `windows-basic`, `windows-deep`, `windows-search`, and
  `windows-rdp-cache`.
- **Report bundle**: generated markdown/JSON/CSV reports under a case output
  directory.

## Global Command Shape

```bash
uv run relic [--root ROOT] [--config CONFIG] [--plugin PLUGIN] [--dry-run] COMMAND ...
```

Global switches:

- `--root ROOT`: workspace root. Use a large disk for real evidence.
- `--config CONFIG`: YAML config containing root, tool paths, and plugin paths.
- `--plugin PLUGIN`: additional tool plugin YAML path.
- `--dry-run`: record and print commands without executing where supported.

If a command creates or writes case data, always pass the same `--root` each
time. A common layout is:

```bash
uv run relic --root ~/analysis/my-case-root ...
```

## Configuration

Relic can be run entirely with command-line switches, but a config file is
cleaner for repeated use.

Example `config.yaml`:

```yaml
root: /analysis/relic
tools_root: /home/lee/tools
eztools_root: /home/lee/tools/eztools
plugins:
  - /home/lee/projects/investigator/forensic_orchestrator/plugins/eztools.yaml
```

Run with:

```bash
uv run relic --config config.yaml standalone doctor
```

Command-line `--root` and `--plugin` override config values.

## First-Run Setup

Check the install:

```bash
uv sync
uv run relic standalone version
uv run relic standalone dependencies --format table
uv run relic standalone doctor --smoke --format table
```

Repair or install managed third-party tools:

```bash
uv run relic standalone repair-dependencies --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone install-tool eztools --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone install-tool sidr --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone install-tool all --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
source ~/tools/forensic-orchestrator.env
```

Important dependency nuance:

- System packages such as Sleuth Kit, libewf, `ntfs-3g`, `qemu-img`, poppler,
  and tesseract are reported with install commands because they normally require
  privileged package management.
- Python tools such as `pypykatz` and Volatility can be installed by the app.
- EZ tools are downloaded into the managed tools folder.
- Managed tool archives are extracted with explicit path checks. Relic rejects
  absolute paths, drive-letter paths, parent-directory traversal, and archive
  link/device entries during extraction.
- EZ tools are SHA1 checked when the download catalog provides a valid SHA1
  value. The managed `!!!RemoteFileDetails.csv` records whether a SHA1 was
  verified for each downloaded item.
- SIDR is built as the native Linux Rust binary from source. Relic does not use
  the upstream Windows `sidr.exe` for Linux parsing.
- Optional tools reduce coverage but should not stop workflows unless the
  selected artifact requires them.

## Quick Start: Live-Case Zip

Use this for a zip containing one top-level folder per computer/device.

1. Generate a tiny sample zip if you want to test the workflow:

```bash
uv run relic standalone sample-fixture --output sample-live-case.zip --format table
```

2. Preflight the real zip:

```bash
uv run relic --root ~/analysis/case-root ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --preflight \
  --format table \
  --max-uncompressed-gb 75
```

Preflight does not import data. It reports:

- detected computer folders,
- CSV counts,
- mapped/unmapped parser counts,
- zip member counts,
- compressed and uncompressed size metadata.

Mounting a ZIP evidence file also performs a safety preflight before extraction.
This applies when the ZIP is being treated as evidence that contains a disk
image or virtual disk. Relic rejects:

- unsafe member paths, including absolute paths, drive-letter paths, empty paths,
  and parent-directory traversal,
- ZIP link entries,
- archives with more than 1,000,000 file members,
- archives whose uncompressed file size would not fit in the workspace
  filesystem while leaving a 10 GB reserve.

There is no fixed evidence-size cap for disk-image ZIPs. The effective limit is
available workspace disk space minus the reserve.

3. Import:

```bash
uv run relic --root ~/analysis/case-root ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --accept-duplicate \
  --report-purpose triage
```

By default, this creates/reuses a case, creates one computer per top-level
folder, imports mapped CSVs, logs unsupported CSVs, rebuilds post-processing
tables, and writes a triage report bundle.

4. Check progress/status:

```bash
uv run relic --root ~/analysis/case-root report dashboard --case CASE_ID --format table
uv run relic --root ~/analysis/case-root report progress --case CASE_ID --format table
uv run relic --root ~/analysis/case-root report unmapped-imports --case CASE_ID --format table
```

5. Validate generated reports:

```bash
uv run relic --root ~/analysis/case-root report validate-outputs \
  --path ~/analysis/case-root/cases/CASE_ID/outputs/reports/triage-bundle \
  --format table
```

## Quick Start: Disk Image

For E01/raw/virtual disk evidence:

```bash
uv run relic --root ~/analysis/case-root process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --workers 4
```

Common processing switches:

- `--case CASE_ID`: add the evidence to an existing case; omitted creates one.
- `--path PATH`: source E01/raw/zip/virtual disk path.
- `--computer COMPUTER_ID`: existing computer.
- `--computer-label LABEL`: label for a newly created computer.
- `--hostname HOSTNAME`: hostname metadata.
- `--profile PROFILE`: parser profile to run.
- `--filesystem`: mount the selected NTFS volume read-only before parsing.
- `--sudo`: use non-interactive sudo for mount/unmount commands.
- `--keep-mounted`: leave read-only mount active for manual review.
- `--unlock-bitlocker`: when BitLocker is detected, try a read-only unlock
  before mounting NTFS. The default tool chain is `cryptsetup`, `dislocker`,
  then `bdemount`.
- `--bitlocker-tool auto|cryptsetup|dislocker|bdemount`: choose the unlock tool
  or fallback chain.
- `--bitlocker-method recovery-key|password|bek|fvek`: choose the protector
  type for tools that support it.
- `--bitlocker-key-file PATH`: read unlock material from a file. Relic supplies
  the value through stdin where supported and does not log the secret. If no
  file is supplied, Relic prompts after BitLocker detection.
- `--workers N`: parallel external tool/output generation slots. Database ingest
  and internal parser writes remain serialized.
- `--include-memory-profile`: run memory support-file processing after the
  selected profile.
- `--no-memory-profile`: skip automatic memory support processing.
- `--replace-existing`: delete existing output rows for this image/profile
  before importing fresh output.
- `--accept-duplicate`: import even if content hash already exists.
- `--include-start-menu-lnk`: include Start Menu shortcuts.
- `--include-deleted-mft`: include deleted/orphaned MFT entries in MFT-driven
  extraction.
- `--include-live-orphans`: include allocated MFT records missing from active
  INDX entries.
- `--include-windows-old`: process Windows.old artifacts into a Windows.old
  namespace.

Use `--dry-run` before a first profile run:

```bash
uv run relic --root ~/analysis/case-root --dry-run process \
  --path ~/evidence/host.E01 \
  --profile windows-full \
  --filesystem
```

## Workspace and Case Commands

`case` and `project` are aliases for the same case workspace operations. Use
whichever reads more clearly for your workflow.

```bash
uv run relic --root ROOT case create
uv run relic --root ROOT case status CASE_ID
uv run relic --root ROOT case activity CASE_ID
uv run relic --root ROOT case activity CASE_ID --level warning
uv run relic --root ROOT case activity CASE_ID --level error
```

Post-processing rebuilds:

```bash
uv run relic --root ROOT case rebuild-postprocess CASE_ID
uv run relic --root ROOT case rebuild-timeline-dedupe CASE_ID
uv run relic --root ROOT case rebuild-artifact-dedupe CASE_ID
uv run relic --root ROOT case rebuild-correlations CASE_ID
uv run relic --root ROOT case rebuild-sessions CASE_ID
uv run relic --root ROOT case rebuild-derived-timeline CASE_ID
uv run relic --root ROOT project rebuild-distinct-artifacts CASE_ID
```

Destructive cleanup:

```bash
uv run relic --root ROOT case purge-output CASE_ID --yes
```

Nuance: do not purge output unless you intend to remove parsed output rows for
that case. Prefer `--replace-existing` on a rerun of one image/profile when
possible.

## Computer and Image Commands

```bash
uv run relic --root ROOT computer add --case CASE_ID --label HOST01
uv run relic --root ROOT computer list --case CASE_ID
uv run relic --root ROOT image add --case CASE_ID --path /evidence/host.E01 --computer COMPUTER_ID
uv run relic --root ROOT image mount --case CASE_ID --image IMAGE_ID --filesystem
uv run relic --root ROOT image mount --case CASE_ID --image IMAGE_ID --filesystem --sudo
uv run relic --root ROOT image mount --case CASE_ID --image IMAGE_ID --filesystem --unlock-bitlocker --bitlocker-key-file /secure/recovery-key.txt
uv run relic --root ROOT image unmount --case CASE_ID --image IMAGE_ID
uv run relic --root ROOT image cleanup-stale-mounts --case CASE_ID
uv run relic --root ROOT image cleanup-stale-mounts --case CASE_ID --apply --sudo
```

Mounting nuances:

- Mounts are read-only.
- Use `--sudo` only when non-interactive sudo is configured.
- BitLocker unlock is opt-in and only applies to `--filesystem` mounts. `auto`
  tries `cryptsetup`, then `dislocker`, then `bdemount`. Use a recovery key,
  BEK/startup key, password protector, or FVEK material as appropriate for the
  evidence; a normal Windows login password only works when the volume has a
  BitLocker password protector.
- `--keep-mounted` on `process` is useful for manual review.
- If a session crashes while mounted, use `image cleanup-stale-mounts` first as
  a dry-run, then add `--apply`.

## Report Bundle Import Commands

Single folder import:

```bash
uv run relic --root ROOT report-bundle import \
  --path /evidence/HOST01-reports \
  --computer-label HOST01 \
  --accept-duplicate
```

Bulk folder/zip import:

```bash
uv run relic --root ROOT report-bundle import-many \
  --path /evidence/live-case.zip \
  --accept-duplicate \
  --write-reports \
  --report-purpose triage
```

Coverage scan:

```bash
uv run relic report-bundle coverage --path /evidence/live-case.zip --format table
```

Important switches:

- `--case CASE_ID`: use an existing case.
- `--path PATH`: folder or zip to import.
- `--computer COMPUTER_ID`: attach a single import to an existing computer.
- `--computer-label LABEL`: label for a new single-import computer.
- `--resume-from-manifest PATH`: skip completed computers from a previous bulk
  manifest.
- `--accept-duplicate`: import duplicate content.
- `--no-progress`: suppress progress lines on stderr.
- `--write-reports`: write purpose bundle after import.
- `--report-purpose full|usb|cloud|execution|memory|triage`: report bundle
  focus.
- `--report-output-dir DIR`: custom report bundle output directory.

Nuance: `report-bundle coverage` can run without a workspace root when only
checking parser routes or input coverage.

## Ingest Commands

Currently the main high-level ingest command is:

```bash
uv run relic --root ROOT ingest triage-zip --path evidence.zip
```

Switches:

- `--case CASE_ID`: use existing case.
- `--path PATH`: zip with one top-level folder per computer.
- `--preflight`: validate without import.
- `--format json|table|csv`: output format for preflight.
- `--output PATH`: write preflight output.
- `--max-uncompressed-gb N`: abort if zip uncompressed size exceeds N GB; `0`
  disables the check.
- `--resume-from-manifest PATH`: resume interrupted import.
- `--accept-duplicate`: import duplicate content.
- `--no-progress`: hide progress lines.
- `--write-reports` / `--no-write-reports`: enable/disable report bundle.
- `--report-purpose full|usb|cloud|execution|memory|triage`.
- `--report-output-dir DIR`.

Nuance: use `--preflight --max-uncompressed-gb` before importing large live-case
zips. This option belongs to bulk report/triage ZIP import, where the operator
can choose a case-specific expansion ceiling. Disk-image ZIP mounting uses a
different guard: it rejects unsafe paths and requires the uncompressed contents
to fit in the workspace filesystem with a 10 GB free-space reserve.

## Memory Commands

Run the combined memory workflow:

```bash
uv run relic --root ROOT memory workflow --case CASE_ID --workers 4
```

Switches:

- `--case CASE_ID`
- `--computer COMPUTER_ID`
- `--image IMAGE_ID`
- `--min-length N`: minimum string length, default 6.
- `--workers N`
- `--no-crash-dumps`
- `--no-extract-fallback`: do not extract MFT-discovered support files with
  `icat` when mounts are unavailable.
- `--write-reports` / `--no-write-reports`
- `--report-output-dir DIR`

Scan a specific memory-like file:

```bash
uv run relic --root ROOT memory strings \
  --case CASE_ID \
  --path /evidence/pagefile.sys \
  --min-length 6
```

Crash dumps:

```bash
uv run relic --root ROOT memory crash-dumps --case CASE_ID --workers 4 --copy
```

Windows Search SQLite memory carves:

```bash
uv run relic --root ROOT memory windows-search-carves \
  --case CASE_ID \
  --path /evidence/search-carves \
  --max-rows-per-table 100
```

Nuances:

- Credential-looking strings are reported as candidates unless separately
  validated.
- Credential reports redact values by default. Use `report memory-credentials
  --reveal` only for controlled examiner output.
- Hiberfil/pagefile/swapfile parsing is best-effort. If a hiberfil is compressed
  and cannot be decompressed, the workflow should record the limitation and keep
  processing other artifacts.

## VSC Commands

Volume Shadow Copy support is separate from normal processing.

Common commands:

```bash
uv run relic --root ROOT vsc list --case CASE_ID --image IMAGE_ID
uv run relic --root ROOT vsc mount --case CASE_ID --image IMAGE_ID --snapshot 1 --sudo
uv run relic --root ROOT vsc unmount --case CASE_ID --image IMAGE_ID --snapshot 1 --sudo
```

VSC profile scans are used for targeted follow-up rather than default
`windows-full` processing. Use VSC recovery when you need historical copies of
registry hives, browser databases, prefetch, SRUM, event logs, recycle bin,
Windows Search, or NTFS namespace deltas.

## Tool Commands

List configured tools:

```bash
uv run relic --root ROOT tools list
```

Preview a profile:

```bash
uv run relic --root ROOT tools profile-preview --profile windows-full
```

Use `standalone profile-catalog` and `standalone artifact-capability` for a more
operator-friendly view.

## Run Command

`run` executes a profile against an already registered image. It is lower-level
than `process`, which can create/register evidence and optionally mount the
filesystem in one command.

```bash
uv run relic --root ROOT run \
  --case CASE_ID \
  --image IMAGE_ID \
  --profile windows-full \
  --workers 4
```

Switches:

- `--case CASE_ID`
- `--image IMAGE_ID`
- `--profile PROFILE`
- `--include-start-menu-lnk`
- `--replace-existing`
- `--accept-duplicate`
- `--include-deleted-mft`
- `--include-live-orphans`
- `--include-windows-old`
- `--include-memory-profile`
- `--no-memory-profile`
- `--workers N`

Nuance: prefer `process` for normal operator use. Use `run` when evidence has
already been added/mounted and you want to rerun one profile by image ID.

## Carve Commands

SQLite carving:

```bash
uv run relic --root ROOT carve sqlite \
  --case CASE_ID \
  --path /evidence/pagefile.sys \
  --profile windows-database-carve \
  --max-carves 100 \
  --max-bytes 1073741824 \
  --import-artifacts
```

ESE carving:

```bash
uv run relic --root ROOT carve ese \
  --case CASE_ID \
  --path /evidence/pagefile.sys \
  --profile windows-database-carve \
  --max-carves 100
```

Shared carving switches:

- `--case CASE_ID`
- `--path PATH`: raw source file, staged carve directory, or candidate database.
- `--computer COMPUTER_ID`
- `--image IMAGE_ID`
- `--profile PROFILE`
- `--max-carves N`
- `--max-bytes N`
- `--max-carve-size N`
- `--start-offset N`
- `--chunk-size N`

SQLite-specific switches:

- `--max-rows-per-table N`
- `--import-artifacts`: route recognized SQLite files through Firefox,
  Chromium, or Activities parsers.
- `--import-windows-search-memory`: also parse staged SQLite carves into
  Windows Search memory carve tables.

Nuance: carving is intentionally separate from default full processing. Use it
for unallocated/pagefile/hiberfil/swapfile/deep recovery work where runtime and
false positives are acceptable.

## Cloud Import Commands

Import server-side cloud logs:

```bash
uv run relic --root ROOT cloud import-logs \
  --case CASE_ID \
  --path /evidence/cloud-logs \
  --provider Google \
  --service Drive
```

Switches:

- `--case CASE_ID`
- `--path PATH`
- `--computer COMPUTER_ID`
- `--provider PROVIDER`
- `--service SERVICE`

Nuance: cloud imports are supplemental evidence. They create or use the case
context but are not disk image mounts.

## Standalone Commands

```bash
uv run relic standalone version --format table
uv run relic standalone dependencies --format table
uv run relic standalone repair-dependencies --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone tool-status --tools-dir ~/tools --format table
uv run relic standalone install-tool all --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone profile-catalog --format table
uv run relic standalone artifact-capability --profile windows-full --format table
uv run relic standalone schema-status --format table
uv run relic standalone doctor --smoke --format table
uv run relic standalone backup --case CASE_ID --output-dir /safe/backups
uv run relic standalone jobs --case CASE_ID --format table
uv run relic standalone benchmark --case CASE_ID --write-baseline benchmark.json
uv run relic standalone benchmark --case CASE_ID --baseline benchmark.json --format table
uv run relic standalone sample-fixture --output sample-live-case.zip --format table
uv run relic standalone backlog --format table
```

Key standalone switches:

- `doctor --case CASE_ID --profile PROFILE`: include case/profile readiness.
- `doctor --repair`: attempt safe dependency repairs before checking.
- `doctor --smoke`: run a tiny isolated DB/report smoke test.
- `dependencies --env-file PATH`: load tool env vars before checking.
- `repair-dependencies --required-only`: skip optional dependencies.
- `install-tool TOOL --force`: force reinstall/rebuild.
- `install-tool TOOL --dry-run`: preview tool install actions.
- `benchmark --write-baseline PATH`: save current timing report.
- `benchmark --baseline PATH`: compare current timing report to a saved
  baseline.

## Report Commands

Reports usually share these switches:

- `--case CASE_ID`
- `--limit N`
- `--format json|table|csv|md`
- `--output PATH`

Not every report supports every format or filter. Use:

```bash
uv run relic report REPORT_NAME --help
```

Operational reports:

```bash
uv run relic --root ROOT report dashboard --case CASE_ID --format table
uv run relic --root ROOT report progress --case CASE_ID --format table
uv run relic --root ROOT report resume-plan --case CASE_ID --format table
uv run relic --root ROOT report workspace-health --case CASE_ID --format md
uv run relic --root ROOT report unmapped-imports --case CASE_ID --format table
uv run relic --root ROOT report validate-outputs --path REPORT_DIR --format table
uv run relic --root ROOT report regression-smoke --case CASE_ID --format table
uv run relic --root ROOT report write-bundle --case CASE_ID --purpose triage --output-dir REPORT_DIR
```

Purpose bundles:

- `triage`: broad high-signal starting point.
- `usb`: removable media, shellbags, shortcuts, object IDs, USN lifecycle.
- `cloud`: cloud artifacts, opened-from-cloud, virtual mounts.
- `execution`: execution, suspicious execution, provenance, remote access.
- `memory`: memory artifacts, credentials, memory/disk correlations, crash
  dumps.
- `full`: all bundle reports.

High-value report families:

- Case health: `summary`, `dashboard`, `case-overview`, `executive-summary`,
  `case-review`, `issues`, `evidence-gaps`, `evidence-quality`,
  `artifact-completeness`.
- Execution: `execution`, `execution-correlation`, `suspicious-executions`,
  `suspicious-timeline-windows`, `program-provenance`, `prefetch`, `amcache`,
  `shimcache`, `autostarts`, `persistence`, `malware-hiding-places`.
- Filesystem and file movement: `mft`, `ntfs-index`, `ntfs-logfile`,
  `ntfs-namespace`, `filesystem-review`, `files`, `file-names`,
  `file-name-drilldown`, `file-history`, `file-dossier`, `file-intelligence`,
  `copied-files`, `copied-file-indicators`, `copied-file-groups`,
  `copied-usb-files`, `file-movement-identity`.
- USB/storage: `usb`, `external-storage`, `device-inventory`, `usb-files`,
  `usb-timeline`, `usb-verbose`, `usb-dossier`, `shellbag-external-storage`,
  `opened-from-removable-media`, `shortcut-droid-changes`,
  `shortcut-object-tracking`.
- Browser/web/cloud: `firefox`, `browser`, `browser-artifacts`,
  `browser-downloads`, `browser-cache`, `browser-hosts`, `browser-activity`,
  `browser-profile-activity`, `browser-deep-storage`,
  `browser-cache-correlations`, `webcache`, `webcache-files`,
  `cloud-artifacts`, `cloud-files`, `cloud-configuration`, `cloud-mounts`,
  `cloud-removable-overlap`, `opened-from-cloud-storage`,
  `web-cloud-correlations`.
- Communications/email: `email-artifacts`, `mailbox-messages`,
  `mailbox-attachments`, `mailbox-attachment-coverage`,
  `mailbox-attachment-copies`, `mailbox-copies`, `communications`,
  `communication-groups`, `communication-review`, `messaging-artifacts`,
  `messaging-messages`.
- Remote access: `remote-access`, `remote-access-attribution`, `rdp`,
  `rdp-cache`, `rdp-visual-observations`, `vpn-activity`,
  `vpn-local-activity`, `vpn-connections`, `vpn-config`, `vpn-execution`,
  `vpn-sessions`, `sessions`, `session`.
- Registry/user activity: `registry`, `registry-artifacts`,
  `registry-activity`, `office-trust`, `office-backstage`,
  `taskbar-feature-usage`, `taskbar-pins`, `common-dialog-items`,
  `activity-summary`, `user-activity`, `users`, `accounts`, `shellbags`,
  `windows-activities`, `ual`, `srum`, `srum-context`, `srum-networks`,
  `srum-app-usage`.
- Windows Search and memory: `windows-search`, `windows-search-combined`,
  `search-index-runs`, `memory-artifacts`, `memory-support-files`,
  `memory-analysis`, `memory-credentials`, `memory-credential-review`,
  `memory-disk-correlations`, `memory-string-hits`, `crash-dump-analysis`.
- Recovery/deep parsing: `recovery-coverage`, `carve-coverage`,
  `sqlite-inventory`, `evtx-recovery`, `deep-recovery-status`,
  `artifact-processing-status`, `processing-decisions`,
  `processing-readiness`, `readiness-gate`, `db-storage`, `cleanup-candidates`.
- Timeline/correlation: `timeline`, `timeline-sources`, `timeline-review`,
  `user-timeline`, `derived-timeline-events`, `artifact-sources`,
  `artifact-correlations`, `correlation-groups`, `correlation-group`,
  `correlations`, `artifact-summary`.
- Special topics: `downloaded-files`, `uninstalled-app-artifacts`, `tor-usage`,
  `encrypted-volumes`, `phone-link`, `virtualization`, `thumbcache`,
  `cd-burning`, `brute-force`, `data-exfiltration`, `account-compromise`,
  `sdelete`, `usn-*`.

## Search Commands

Relic has an OpenSearch-backed search surface for indexed content where
configured:

```bash
uv run relic --root ROOT search query --case CASE_ID --query "report.docx" --limit 25
uv run relic --root ROOT search show --case CASE_ID --source-table TABLE --source-id ID
```

Search options include:

- `--host`
- `--index`
- `--username`
- `--password`
- `--insecure`
- `--limit`
- `--no-synonyms`
- `--synonyms PATH`
- `--format json|table`
- `--output PATH`

## Output Locations

Within the workspace root, expect:

- `cases/CASE_ID/`: case tree.
- `cases/CASE_ID/outputs/`: tool outputs and generated reports.
- `cases/CASE_ID/outputs/reports/`: markdown/JSON/CSV reports and manifests.
- `cases/CASE_ID/artifacts/`: extracted artifacts.
- `staging/`: temporary staged imports or zip members.
- SQLite database at the workspace root.
- DuckDB analytics database under the case analytics path.

Exact paths are returned in command JSON output and report manifests.

## Resuming Failed or Interrupted Runs

Check state:

```bash
uv run relic --root ROOT report dashboard --case CASE_ID --format table
uv run relic --root ROOT report progress --case CASE_ID --format table
uv run relic --root ROOT report resume-plan --case CASE_ID --format table
uv run relic --root ROOT report workspace-health --case CASE_ID --format md
```

Resume a bulk live-case zip:

```bash
uv run relic --root ROOT ingest triage-zip \
  --path /evidence/live-case.zip \
  --resume-from-manifest /analysis/root/cases/CASE_ID/outputs/reports/report-bundle-bulk-import-CASE_ID.manifest.json
```

Run post-processing rebuilds:

```bash
uv run relic --root ROOT case rebuild-postprocess CASE_ID
```

Nuance: if DuckDB temp storage failed during distinct-table rebuilds, the import
can still complete with a warning. Free disk space or move temp storage, then
rerun post-processing.

## Performance and Parallel Processing

Use `--workers N` on `process`, `memory workflow`, and crash dump scanning where
available.

Parallelism currently applies to extraction/external tool work. Database ingest,
post-processing rebuilds, and many internal writes are intentionally serialized
to avoid corruption and lock contention.

Record a baseline:

```bash
uv run relic --root ROOT standalone benchmark --case CASE_ID --write-baseline benchmark.json
```

Compare later:

```bash
uv run relic --root ROOT standalone benchmark --case CASE_ID --baseline benchmark.json --format table
```

## Safety and Evidence Handling

- Keep original evidence read-only.
- Prefer `--filesystem` read-only mounts for speed when processing disk images.
- Use `--keep-mounted` only when you need manual review.
- Run `image cleanup-stale-mounts` after crashes or interrupted sessions.
- Use `--preflight` for large zips before import.
- Use `--max-uncompressed-gb` on bulk live-case/report zip imports to avoid
  exhausting workspace disk. Disk-image ZIP mounting has no fixed GB cap, but it
  requires enough free space for the uncompressed files plus a 10 GB reserve.
- External AI review is off by default. Set `FORENSIC_ALLOW_EXTERNAL_AI=1` only
  when uploading RDP contact sheets to the configured model provider is approved.
- Use credential reveal options only under controlled conditions.
- Treat memory credential strings as leads unless validated.
- Treat UserAssist, Amcache, and ShimCache as activity/presence indicators, not
  standalone proof of execution.

## Common End-to-End Live-Case Workflow

```bash
uv run relic standalone doctor --smoke --format table

uv run relic --root ~/analysis/live-case ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --preflight \
  --format table \
  --max-uncompressed-gb 75

uv run relic --root ~/analysis/live-case ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --accept-duplicate \
  --report-purpose triage

uv run relic --root ~/analysis/live-case report dashboard --case CASE_ID --format table
uv run relic --root ~/analysis/live-case report unmapped-imports --case CASE_ID --format table
uv run relic --root ~/analysis/live-case report write-bundle \
  --case CASE_ID \
  --purpose usb \
  --output-dir ~/analysis/live-case/cases/CASE_ID/outputs/reports/usb-bundle
```

## Common End-to-End Disk Image Workflow

```bash
uv run relic standalone doctor --smoke --format table

uv run relic --root ~/analysis/disk-case --dry-run process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --workers 4

uv run relic --root ~/analysis/disk-case process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --workers 4

uv run relic --root ~/analysis/disk-case report dashboard --case CASE_ID --format table
uv run relic --root ~/analysis/disk-case report write-bundle \
  --case CASE_ID \
  --purpose full \
  --output-dir ~/analysis/disk-case/cases/CASE_ID/outputs/reports/full-bundle
```
