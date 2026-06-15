# Perceptor User Manual

Perceptor is a CLI-first forensic processing and reporting tool. It can process
Windows disk images, import pre-generated triage/report bundles, normalize many
artifact outputs into a case database, dedupe derived artifacts, and generate
investigator-facing reports.

This page is the legacy single-page operator manual. The MkDocs-ready topic
manual starts at [Documentation Home](index.md).

Useful topic pages:

- [Supported Artifacts](reference/supported-artifacts.md): artifact families,
  tables, reports, and search coverage.
- [Field Readiness](operations/field-readiness.md): evidence integrity,
  preflight estimates, resume behavior, reporting limits, and known operational
  caveats.

The executable names are:

- `perceptor`
- `forensic-orchestrator`

Examples below use `uv run perceptor`. If Perceptor is installed as a console script,
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
uv run perceptor [--root ROOT] [--config CONFIG] [--plugin PLUGIN] [--dry-run] COMMAND ...
```

Global switches:

- `--root ROOT`: workspace root. Use a large disk for real evidence.
- `--config CONFIG`: YAML config containing root, tool paths, and plugin paths.
- `--plugin PLUGIN`: additional tool plugin YAML path.
- `--dry-run`: record and print commands without executing where supported.
- `--timezone AREA/LOCATION`: optional display-only timezone. UTC remains
  unchanged and authoritative; Perceptor adds companion fields such as
  `timestamp_utc_local` only when this switch is supplied.

If a command creates or writes case data, always pass the same `--root` each
time. A common layout is:

```bash
uv run perceptor --root ~/analysis/my-case-root ...
```

## Configuration

Perceptor can be run entirely with command-line switches, but a config file is
cleaner for repeated use.

Example `config.yaml`:

```yaml
root: /analysis/perceptor
tools_root: /opt/perceptor-tools
eztools_root: /opt/perceptor-tools/eztools
plugins:
  - /opt/perceptor/forensic_orchestrator/plugins/eztools.yaml
```

Run with:

```bash
uv run perceptor --config config.yaml standalone doctor
```

Command-line `--root` and `--plugin` override config values.

## First-Run Setup

Check the install:

```bash
uv sync
uv run perceptor standalone version
uv run perceptor standalone dependencies --format table
uv run perceptor standalone doctor --smoke --format table
uv run perceptor standalone smoke-regression --format table
```

Repair or install managed third-party tools:

```bash
uv run perceptor standalone repair-dependencies --tools-dir ~/tools --env-file ~/tools/perceptor.env
uv run perceptor standalone install-tool eztools --tools-dir ~/tools --env-file ~/tools/perceptor.env
uv run perceptor standalone install-tool sidr --tools-dir ~/tools --env-file ~/tools/perceptor.env
uv run perceptor standalone install-tool all --tools-dir ~/tools --env-file ~/tools/perceptor.env
source ~/tools/perceptor.env
```

Important dependency nuance:

- System packages such as Sleuth Kit, libewf, `ntfs-3g`, `qemu-img`, poppler,
  and tesseract are reported with install commands because they normally require
  privileged package management.
- `install-tool all` attempts the BitLocker fallback apt packages
  `dislocker` and `libbde-utils` with non-interactive sudo. If sudo requires a
  password, run `sudo apt-get install -y dislocker libbde-utils` yourself and
  rerun doctor.
- Python tools such as `pypykatz` and Volatility can be installed by the app.
- EZ tools are downloaded into the managed tools folder.
- Managed tool archives are extracted with explicit path checks. Perceptor rejects
  absolute paths, drive-letter paths, parent-directory traversal, and archive
  link/device entries during extraction.
- EZ tools are SHA1 checked when the download catalog provides a valid SHA1
  value. The managed `!!!RemoteFileDetails.csv` records whether a SHA1 was
  verified for each downloaded item.
- SIDR is built as the native Linux Rust binary from source. Perceptor does not use
  the upstream Windows `sidr.exe` for Linux parsing.
- Optional tools reduce coverage but should not stop workflows unless the
  selected artifact requires them.

## Quick Start: Live-Case Zip

Use this for a zip containing one top-level folder per computer/device.

1. Generate a tiny sample zip if you want to test the workflow:

```bash
uv run perceptor standalone sample-fixture --output sample-live-case.zip --format table
```

2. Preflight the real zip:

```bash
uv run perceptor --root ~/analysis/case-root ingest triage-zip \
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
image or virtual disk. Perceptor rejects:

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
uv run perceptor --root ~/analysis/case-root ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --accept-duplicate \
  --report-purpose triage
```

By default, this creates/reuses a case, creates one computer per top-level
folder, imports mapped CSVs, logs unsupported CSVs, rebuilds post-processing
tables, writes a triage report bundle, and writes a live progress JSON file
under `ROOT/progress/`. Use `--progress-manifest PATH` to choose the progress
file path explicitly.

4. Check progress/status:

```bash
uv run perceptor --root ~/analysis/case-root report dashboard --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report progress --case CASE_ID --format table
uv run perceptor --root ~/analysis/case-root report unmapped-imports --case CASE_ID --format table
```

5. Validate generated reports:

```bash
uv run perceptor --root ~/analysis/case-root report validate-outputs \
  --path ~/analysis/case-root/cases/CASE_ID/outputs/reports/triage-bundle \
  --format table
```

## Quick Start: Disk Image

For E01/raw/virtual disk evidence:

```bash
uv run perceptor --root ~/analysis/case-root process \
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
- `--bitlocker-key-file PATH`: read unlock material from a file. Perceptor supplies
  the value through stdin where supported and does not log the secret. If no
  file is supplied, Perceptor prompts after BitLocker detection.
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

When `--filesystem` mounts a non-NTFS volume such as FAT32 or exFAT, Perceptor
automatically writes a mounted filesystem inventory to
`filesystem_entries`. This gives removable volumes a file listing even when
there is no `$MFT`.

Disk images added through `process --path` are hashed on import with MD5, SHA1,
and SHA256. Use `image verify` later to prove the current image bytes still
match the stored hashes.

Use `--dry-run` before a first profile run:

```bash
uv run perceptor --root ~/analysis/case-root --dry-run process \
  --path ~/evidence/host.E01 \
  --profile windows-full \
  --filesystem
```

## Workspace and Case Commands

`case` and `project` are aliases for the same case workspace operations. Use
whichever reads more clearly for your workflow.

```bash
uv run perceptor --root ROOT case create
uv run perceptor --root ROOT case status CASE_ID
uv run perceptor --root ROOT case describe CASE_ID
uv run perceptor --root ROOT case describe CASE_ID --description "Brief matter context"
uv run perceptor --root ROOT case describe CASE_ID --description-file ./case-description.md --write-notes
uv run perceptor --root ROOT case activity CASE_ID
uv run perceptor --root ROOT case activity CASE_ID --level warning
uv run perceptor --root ROOT case activity CASE_ID --level error
```

`case describe` stores short matter context in SQLite so reports and MCP case
summary tools can surface it. `--write-notes` also writes the supplied text to
`case-description.md` in the case directory and records that file as the longer
notes reference.

Post-processing rebuilds:

```bash
uv run perceptor --root ROOT case rebuild-postprocess CASE_ID
uv run perceptor --root ROOT case rebuild-timeline-dedupe CASE_ID
uv run perceptor --root ROOT case rebuild-artifact-dedupe CASE_ID
uv run perceptor --root ROOT case rebuild-correlations CASE_ID
uv run perceptor --root ROOT case rebuild-sessions CASE_ID
uv run perceptor --root ROOT case rebuild-derived-timeline CASE_ID
uv run perceptor --root ROOT project rebuild-distinct-artifacts CASE_ID
```

`rebuild-derived-timeline` adds normalized correlation/session events such as
Wi-Fi sessions, SRUM observations, USB connection events, removable/cloud file
references, and file-identity correlations to the master timeline.

Destructive cleanup:

```bash
uv run perceptor --root ROOT case purge-output CASE_ID --yes
```

Nuance: do not purge output unless you intend to remove parsed output rows for
that case. Prefer `--replace-existing` on a rerun of one image/profile when
possible.

## Computer and Image Commands

```bash
uv run perceptor --root ROOT computer add --case CASE_ID --label HOST01
uv run perceptor --root ROOT computer list --case CASE_ID
uv run perceptor --root ROOT image add --case CASE_ID --path /evidence/host.E01 --computer COMPUTER_ID
uv run perceptor --root ROOT image integrity --case CASE_ID --image IMAGE_ID --format table
uv run perceptor --root ROOT image verify --case CASE_ID --image IMAGE_ID --format table
uv run perceptor --root ROOT image mount --case CASE_ID --image IMAGE_ID --filesystem
uv run perceptor --root ROOT image mount --case CASE_ID --image IMAGE_ID --filesystem --sudo
uv run perceptor --root ROOT image mount --case CASE_ID --image IMAGE_ID --filesystem --unlock-bitlocker --bitlocker-key-file /secure/recovery-key.txt
uv run perceptor --root ROOT image unmount --case CASE_ID --image IMAGE_ID
uv run perceptor --root ROOT image cleanup-stale-mounts --case CASE_ID
uv run perceptor --root ROOT image cleanup-stale-mounts --case CASE_ID --apply --sudo
```

Mounting nuances:

- Mounts are read-only.
- `image add` stores MD5, SHA1, and SHA256 evidence hashes. `image verify`
  records a verification attempt and returns non-zero if the current image bytes
  do not match.
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
uv run perceptor --root ROOT report-bundle import \
  --path /evidence/HOST01-reports \
  --computer-label HOST01 \
  --accept-duplicate
```

Bulk folder/zip import:

```bash
uv run perceptor --root ROOT report-bundle import-many \
  --path /evidence/live-case.zip \
  --accept-duplicate \
  --write-reports \
  --report-purpose triage
```

Coverage scan:

```bash
uv run perceptor report-bundle coverage --path /evidence/live-case.zip --format table
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
uv run perceptor --root ROOT ingest triage-zip --path evidence.zip
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
uv run perceptor --root ROOT memory workflow --case CASE_ID --workers 4
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
uv run perceptor --root ROOT memory strings \
  --case CASE_ID \
  --path /evidence/pagefile.sys \
  --min-length 6
```

Crash dumps:

```bash
uv run perceptor --root ROOT memory crash-dumps --case CASE_ID --workers 4 --copy
```

Windows Search SQLite memory carves:

```bash
uv run perceptor --root ROOT memory windows-search-carves \
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
uv run perceptor --root ROOT vsc list --case CASE_ID --image IMAGE_ID
uv run perceptor --root ROOT vsc mount --case CASE_ID --image IMAGE_ID --snapshot 1 --sudo
uv run perceptor --root ROOT vsc unmount --case CASE_ID --image IMAGE_ID --snapshot 1 --sudo
```

VSC profile scans are used for targeted follow-up rather than default
`windows-full` processing. Use VSC recovery when you need historical copies of
registry hives, browser databases, prefetch, SRUM, event logs, recycle bin,
Windows Search, or NTFS namespace deltas.

## Tool Commands

List configured tools:

```bash
uv run perceptor --root ROOT tools list
```

Preview a profile:

```bash
uv run perceptor --root ROOT tools profile-preview --profile windows-full
```

Use `standalone profile-catalog` and `standalone artifact-capability` for a more
operator-friendly view.

## Run Command

`run` executes a profile against an already registered image. It is lower-level
than `process`, which can create/register evidence and optionally mount the
filesystem in one command.

```bash
uv run perceptor --root ROOT run \
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
uv run perceptor --root ROOT carve sqlite \
  --case CASE_ID \
  --path /evidence/pagefile.sys \
  --profile windows-database-carve \
  --max-carves 100 \
  --max-bytes 1073741824 \
  --import-artifacts
```

ESE carving:

```bash
uv run perceptor --root ROOT carve ese \
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
uv run perceptor --root ROOT cloud import-logs \
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

Perceptor's supported install target is Ubuntu 24.04 LTS on x86_64, either bare
metal or VM. Native macOS, native Windows, Docker full-image mounting, WSL full
mounting, ARM64, and non-Ubuntu Linux are not primary support targets. See
`docs/getting-started/ubuntu-install.md` for the current install contract and
`docs/release-checklist.md` for release verification.

```bash
uv run perceptor standalone version --format table
uv run perceptor standalone dependencies --format table
uv run perceptor standalone repair-dependencies --tools-dir ~/tools --env-file ~/tools/perceptor.env
uv run perceptor standalone tool-status --tools-dir ~/tools --format table
uv run perceptor standalone install-tool all --tools-dir ~/tools --env-file ~/tools/perceptor.env
uv run perceptor standalone profile-catalog --format table
uv run perceptor standalone artifact-capability --profile windows-full --format table
uv run perceptor standalone schema-status --format table
uv run perceptor standalone doctor --smoke --format table
uv run perceptor standalone backup --case CASE_ID --output-dir /safe/backups
uv run perceptor standalone jobs --case CASE_ID --format table
uv run perceptor standalone benchmark --case CASE_ID --write-baseline benchmark.json
uv run perceptor standalone benchmark --case CASE_ID --baseline benchmark.json --format table
uv run perceptor standalone sample-fixture --output sample-live-case.zip --format table
uv run perceptor standalone verify-install --format table
uv run perceptor standalone backlog --format table
```

Key standalone switches:

- `doctor --case CASE_ID --profile PROFILE`: include case/profile readiness.
- `doctor --repair`: attempt safe dependency repairs before checking.
- `doctor --smoke`: run a tiny isolated DB/report smoke test.
- `smoke-regression`: run the standalone proof path: doctor smoke, sample
  live-case fixture import, report bundle generation, output validation, and
  MCP tool listing.
- `verify-install`: friendly alias for `smoke-regression`.
- `dependencies --env-file PATH`: load tool env vars before checking.
- `repair-dependencies --required-only`: repair only core required tools and skip
  default coverage tools.
- `install-tool TOOL --force`: force reinstall/rebuild.
- `install-tool TOOL --dry-run`: preview tool install actions.
- `benchmark --write-baseline PATH`: save current timing report.
- `benchmark --baseline PATH`: compare current timing report to a saved
  baseline.

## MCP Server

Perceptor can run as a local MCP stdio server so an MCP-capable client can inspect a
workspace and call approved Perceptor tools.

Start the server against one workspace root:

```bash
uv run perceptor --root ROOT mcp serve
```

For clients that use a JSON command configuration, use the same command and args:

```json
{
  "command": "uv",
  "args": ["run", "perceptor", "--root", "ROOT", "mcp", "serve"]
}
```

The base MCP surface includes read-only inspection and safe report-generation
tools. Processing tools are visible to clients but reject calls unless the
server was started with `--allow-processing`. Sensitive credential reveal,
external AI, and destructive actions are intentionally not implemented in the
default MCP surface.

Opt-in switches:

- `--allow-processing`: permits import and image/profile processing tools.
- `--allow-sensitive`: reserved for future sensitive tools.
- `--allow-external-ai`: reserved for future external-AI tools.

Read-only MCP tools:

- `perceptor_workspace_summary`
- `perceptor_route_question`
- `perceptor_mcp_workflow_guide`
- `perceptor_list_cases`
- `perceptor_case_summary`
- `perceptor_case_evidence_map`
- `perceptor_case_readiness`
- `perceptor_discover_reports`
- `perceptor_discover_report_exports`
- `perceptor_read_existing_report`
- `perceptor_case_dashboard`
- `perceptor_processing_progress`
- `perceptor_resume_plan`
- `perceptor_workspace_health`
- `perceptor_list_computers`
- `perceptor_list_images`
- `perceptor_list_jobs`
- `perceptor_get_job`
- `perceptor_timeline`
- `perceptor_timeline_window`
- `perceptor_activity_windows`
- `perceptor_file_dossier`
- `perceptor_usb_dossier`
- `perceptor_user_activity`
- `perceptor_ingest_triage_zip_preflight`
- `perceptor_report_bundle_coverage`
- `perceptor_profile_preview`
- `perceptor_doctor`
- `perceptor_list_report_types`
- `perceptor_query_evidence_contents`
- `perceptor_query_filesystem_listings`
- `perceptor_query_suspicious_executions`
- `perceptor_query_external_storage`
- `perceptor_query_usb_files`
- `perceptor_query_usb_contents`
- `perceptor_query_file_movement_identity`
- `perceptor_query_opened_from_removable_media`
- `perceptor_query_opened_from_cloud_storage`
- `perceptor_query_cloud_artifacts`
- `perceptor_query_memory_artifacts`
- `perceptor_query_browser_activity`
- `perceptor_query_registry_activity`
- `perceptor_query_shortcuts`
- `perceptor_query_communications`
- `perceptor_query_system_users`
- `perceptor_case_review`
- `perceptor_workspace_map`
- `perceptor_artifact_search_sources`
- `perceptor_search_artifacts`
- `perceptor_search_content`
- `perceptor_get_indexed_content`
- `perceptor_lead_search`
- `perceptor_case_activity_digest`
- `perceptor_case_next_actions`
- `perceptor_case_runbook`
- `perceptor_list_search_packets`
- `perceptor_read_search_packet`
- `perceptor_rerun_search_packet`
- `perceptor_list_review_packets`
- `perceptor_read_review_packet`
- `perceptor_get_mcp_job`
- `perceptor_list_mcp_jobs`
- `perceptor_get_mcp_job_output`
- `perceptor_get_mcp_job_progress`
- `perceptor_list_progress_manifests`
- `perceptor_mcp_tool_reference`

Safe-write MCP tools:

- `perceptor_generate_report`
- `perceptor_write_report_bundle`
- `perceptor_write_search_packet`
- `perceptor_write_review_packet`

Processing-gated MCP tools:

- `perceptor_import_triage_zip`
- `perceptor_import_report_bundle`
- `perceptor_process_image`
- `perceptor_run_profile`
- `perceptor_cancel_mcp_job`

Processing tools start background subprocesses and return an `mcp_job_id`, PID,
command, and stdout/stderr paths under `ROOT/mcp-jobs/`. MCP job metadata is
persisted in `ROOT/mcp-jobs/index.json`, so a new MCP server process can still
inspect jobs launched earlier.
Add `dry_run: true` to `perceptor_process_image` arguments to launch the normal
Perceptor process command in CLI dry-run mode before real processing.

Operational MCP tools:

- `perceptor_get_mcp_job`: poll persisted MCP subprocess state.
- `perceptor_list_mcp_jobs`: list persisted MCP subprocess jobs, optionally filtered
  by status.
- `perceptor_get_mcp_job_output`: read stdout/stderr tails and parsed JSON stdout
  when available.
- `perceptor_get_mcp_job_progress`: parse structured progress from MCP-launched
  job output, including bulk report ZIP computer counts where available.
- `perceptor_cancel_mcp_job`: terminate a running MCP-launched subprocess; requires
  `--allow-processing`.
- `perceptor_mcp_tool_reference`: export MCP tool names, permissions, schemas, and
  annotations.

Case-navigation MCP tools:

- `perceptor_case_evidence_map`: returns computers, images, image metadata, report
  resources, memory-source activity, job status, and processing progress in one
  response.
- `perceptor_case_readiness`: combines doctor, workspace health, processing
  readiness, processing progress, and resume-plan signals.
- `perceptor_discover_reports`: returns report bundle files as
  `perceptor://workspace/...` resource URIs, optionally filtered by bundle purpose.
- `perceptor_workspace_map`: returns cases, computers, images, generated reports,
  saved packets, progress manifests, and MCP jobs in one structure.
- `perceptor_artifact_search_sources`: returns the artifact tables, categories,
  searchable fields, and row counts available to artifact and lead search.
- `perceptor_search_artifacts` and `perceptor_lead_search`: run general or preset lead
  searches. Results include score, score reasons, matched fields, and drilldown
  hints.
- `perceptor_file_dossier`, `perceptor_usb_dossier`, `perceptor_user_activity`, and
  `perceptor_timeline_window`: focused drilldowns for following leads without
  knowing the matching CLI report names.
- `perceptor_timeline_window` is the first source for “what happened during this
  time/window/session?” questions. It accepts `start` and `end` and matches
  interval events by overlap where the source has an end time. Use domain tools
  such as `perceptor_query_wifi_activity` or USB reports to resolve session/window
  bounds, then query the master timeline with those bounds.
- `perceptor_case_next_actions`: ranks likely next investigative steps from
  readiness, evidence gaps, unmapped imports, suspicious execution, and storage
  findings.
- `perceptor_write_review_packet`: writes selected findings, report URIs, timeline
  rows, and notes to JSON/Markdown under the case reports folder.
- `perceptor_write_search_packet`: saves repeatable search arguments, result sets,
  result hash sets, case/image/tool-output counts, and JSON/Markdown work
  product under `reports/mcp-search-packets`.
- `perceptor_rerun_search_packet`: reruns a saved search packet and reports added,
  removed, changed, and unchanged results. Use `report changed-search-packets`
  to rerun all saved search packets for a case from the CLI.

Recommended MCP review sequence:

1. `perceptor_workspace_map`
2. `perceptor_case_runbook`
3. `perceptor_artifact_search_sources`
4. `perceptor_lead_search` or `perceptor_search_artifacts`
5. Follow each result's drilldown hint.
6. `perceptor_write_search_packet`
7. `perceptor_rerun_search_packet`
8. `perceptor_write_report_bundle` with `purpose: "review"`

MCP audit entries are written to `ROOT/mcp-jobs/audit.jsonl`. Each entry records
the tool name, permission tier, status, timestamp, argument keys, and bounded
case/path context.

Use `perceptor_list_jobs` or `perceptor_processing_progress` for Perceptor's internal
parser/tool job records created by the subprocess itself.

MCP resources:

- `resources/list` exposes text report, manifest, log, and MCP job files under
  the workspace root.
- `resources/list` accepts optional `case_id`, `kind`, and `limit` parameters.
  Supported kinds are `report`, `manifest`, `log`, `mcp-job`, and `progress`.
- `resources/read` reads those files through `perceptor://workspace/...` URIs.
- Individual resource reads are limited to 1 MB to avoid accidentally returning
  large evidence or bulk artifact files.

## Report Commands

Reports usually share these switches:

- `--case CASE_ID`
- `--limit N`
- `--format json|table|csv|md`
- `--output PATH`

Not every report supports every format or filter. Use:

```bash
uv run perceptor report REPORT_NAME --help
```

Interactive report commands may use preview-sized default limits so terminal
output remains usable. Saved report bundles default to broader exports
(`--limit 50000`) so MCP and later review have the full available picture for
most artifacts. If a JSON report includes `limited: true`, do not treat missing
rows as evidence of absence; regenerate that report or bundle with a higher
`--limit`.

MCP tools are also bounded for usability. If a response includes `result_limit`
or `result_limit_warning`, treat the answer as a preview. Increase the tool
limit, read an existing generated report/export, or request a dossier/full
context before relying on absence.

`report-bundle coverage --path PATH` reports parser coverage for live-response
CSV folders/zips with computer attribution, mapped parser, row count, and a
recommendation for unmapped files. It also groups unmapped files by header
signature so repeated parser gaps across many computers are visible as one
implementation target.

Operational reports:

```bash
uv run perceptor --root ROOT report dashboard --case CASE_ID --format table
uv run perceptor --root ROOT report progress --case CASE_ID --format table
uv run perceptor --root ROOT report resume-plan --case CASE_ID --format table
uv run perceptor --root ROOT report workspace-health --case CASE_ID --format md
uv run perceptor --root ROOT report processing-estimate --case CASE_ID --profile windows-full --format table
uv run perceptor --root ROOT report workspace-map --case CASE_ID --format json
uv run perceptor --root ROOT report unmapped-imports --case CASE_ID --format table
uv run perceptor --root ROOT report validate-outputs --path REPORT_DIR --format table
uv run perceptor --root ROOT report regression-smoke --case CASE_ID --format table
uv run perceptor --root ROOT report artifact-search-sources --case CASE_ID --format table
uv run perceptor --root ROOT report changed-search-packets --case CASE_ID --format md
uv run perceptor --root ROOT report review-status --case CASE_ID --format table
uv run perceptor --root ROOT report runbook --case CASE_ID --format md
uv run perceptor --root ROOT report write-bundle --case CASE_ID --purpose review
uv run perceptor --root ROOT report handoff-package --case CASE_ID --bundle-dir REPORT_DIR --output CASE_ID-handoff.zip
```

Purpose bundles:

- `review`: MCP/operator review pack with activity digest, next actions,
  workspace map, search-source inventory, lead summaries, saved packet index,
  changed search-packet summary, and USB/storage context.
- `triage`: broad high-signal starting point.
- `write-bundle` writes to `cases/CASE_ID/outputs/reports/PURPOSE-bundle`
  by default. Use `--output-dir` only when you intentionally need a different
  location.
- `write-bundle` defaults to `--limit 50000` per bounded report export. Raise
  this if a report indicates `limited: true`.
- `usb`: removable media, shellbags, shortcuts, object IDs, USN lifecycle.
- `cloud`: cloud artifacts, opened-from-cloud, virtual mounts.
- `execution`: execution, suspicious execution, provenance, remote access.
- `memory`: memory artifacts, credentials, memory/disk correlations, crash
  dumps.
- `full`: all bundle reports.

Each bundle writes `index.md` for human navigation, `report-index.json` for
programmatic/UI/MCP navigation, `bundle-quality.json` with report, CSV export,
lead-search, and saved-packet checks, and `bundle-manifest.json` with file
sizes and SHA256 hashes. Bundle generation prints timestamped progress to
stderr by default; add `--no-progress` to suppress it. `report handoff-package`
zips the selected bundle plus MCP packets and a handoff manifest without
including evidence files or case databases.

High-value report families:

- Case health: `summary`, `dashboard`, `case-overview`, `executive-summary`,
  `case-review`, `issues`, `evidence-gaps`, `evidence-quality`,
  `artifact-completeness`.
- Execution and event logs: `execution`, `execution-correlation`,
  `suspicious-executions`, `event-interpretation`,
  `suspicious-timeline-windows`, `program-provenance`,
  `software-footprint-review`, `prefetch`, `amcache`, `shimcache`,
  `autostarts`, `persistence`, `malware-hiding-places`,
  `bits-activity`, `examiner-edge-artifacts`, `mapped-network-paths`,
  `remote-access-tool-logs`.
- Filesystem and file movement: `mft`, `ntfs-index`, `ntfs-logfile`,
  `ntfs-namespace`, `filesystem-review`, `files`, `file-names`,
  `file-name-drilldown`, `file-history`, `file-dossier`, `file-intelligence`,
  `copied-files`, `copied-file-indicators`, `copied-file-groups`,
  `copied-usb-files`, `file-movement-identity`, `non-standard-ads`,
  `ntfs-security-descriptors`.
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
- Remote access: `remote-access`, `remote-access-attribution`,
  `mapped-network-paths`, `rdp`,
  `rdp-cache`, `rdp-visual-observations`, `vpn-activity`,
  `vpn-local-activity`, `vpn-connections`, `vpn-config`, `vpn-execution`,
  `vpn-sessions`, `sessions`, `session`.
- Registry/user activity: `registry`, `registry-artifacts`,
  `registry-activity`, `office-trust`, `office-backstage`,
  `taskbar-feature-usage`, `taskbar-pins`, `common-dialog-items`,
  `activity-summary`, `user-activity`, `users`, `accounts`, `shellbags`,
  `windows-activities`, `clipboard`, `ual`, `bits-activity`, `srum`, `srum-context`, `srum-networks`,
  `srum-app-usage`, `examiner-edge-artifacts`, `mapped-network-paths`.
- Windows Search and memory: `windows-search`, `windows-search-combined`,
  `search-index-runs`, `memory-artifacts`, `memory-support-files`,
  `memory-analysis`, `memory-credentials`, `memory-credential-review`,
  `memory-disk-correlations`, `memory-string-hits`, `structured-memory`,
  `crash-dump-analysis`.
- Recovery/deep parsing: `recovery-coverage`, `carve-coverage`,
  `sqlite-inventory`, `evtx-recovery`, `deep-recovery-status`,
  `artifact-processing-status`, `processing-decisions`,
  `processing-readiness`, `readiness-gate`, `db-storage`, `cleanup-candidates`.
- Timeline/correlation: `timeline`, `timeline-sources`, `timeline-review`,
  `user-timeline`, `derived-timeline-events`, `artifact-sources`,
  `artifact-correlations`, `correlation-groups`, `correlation-group`,
  `correlations`, `artifact-summary`.
  `timeline` accepts `--start` and `--end`; interval events are matched by
  overlap when an end timestamp is available.
- Special topics: `downloaded-files`, `uninstalled-app-artifacts`, `tor-usage`,
  `encrypted-volumes`, `phone-link`, `virtualization`, `thumbcache`,
  `cd-burning`, `brute-force`, `data-exfiltration`, `account-compromise`,
  `sdelete`, `usn-*`.

High-value event-log analytics:

```bash
uv run perceptor --root ROOT report event-interpretation --case CASE_ID --format json
uv run perceptor --root ROOT report event-interpretation --case CASE_ID --category powershell --format table
uv run perceptor --root ROOT report event-interpretation --case CASE_ID --category account_manipulation --format table
uv run perceptor --root ROOT report event-interpretation --case CASE_ID --category audit_log_clearing --format table
uv run perceptor --root ROOT report event-interpretation --case CASE_ID --category process_creation --format table
uv run perceptor --root ROOT report event-interpretation --case CASE_ID --category wmi_persistence --format table
uv run perceptor --root ROOT report event-interpretation --case CASE_ID --category print --format table
```

The event interpretation report targets account manipulation, audit log
clearing, PowerShell script-block/module logging, scheduled task creation or
deletion, WMI event subscription indicators, print-service history, service
installs, and process creation with command-line context when present.

Windows clipboard history:

```bash
uv run perceptor --root ROOT report clipboard --case CASE_ID --format table
uv run perceptor --root ROOT report clipboard --case CASE_ID --contains "copied text" --format json
```

`clipboard` parses `%LocalAppData%\Microsoft\Clipboard` stores when present.
It records text, file URI, HTML payload indicators, item timestamps, image
presence, and cloud sync identifiers/state. Windows Activities clipboard rows
remain secondary clipboard-adjacent evidence.

Examiner-edge and filesystem edge reports:

```bash
uv run perceptor --root ROOT report examiner-edge-artifacts --case CASE_ID --format table
uv run perceptor --root ROOT report mapped-network-paths --case CASE_ID --format table
uv run perceptor --root ROOT report non-standard-ads --case CASE_ID --format table
uv run perceptor --root ROOT report ntfs-security-descriptors --case CASE_ID --format table
uv run perceptor --root ROOT report remote-access-tool-logs --case CASE_ID --format table
```

`examiner-edge-artifacts` includes Sticky Notes, notification database rows,
NetworkList, outbound RDP, MountPoints2, Task Scheduler XML, EventTranscript.db,
TokenBroker metadata, CryptnetUrlCache, hosts, WSL, Windows Update,
Credential/Vault metadata, Bluetooth, installed applications, SwiftKey fragments,
and legacy `Thumbs.db` leads where present. `ntfs-security-descriptors` is
presence/metadata-only for `$Secure` streams; use dedicated SDS output when ACL
decoding is required.

## Search Commands

Perceptor has an OpenSearch-backed search surface for indexed content where
configured:

```bash
uv run perceptor --root ROOT search query --case CASE_ID --query "report.docx" --limit 25
uv run perceptor --root ROOT search show --case CASE_ID --source-table TABLE --source-id ID
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
- `cases/CASE_ID/outputs/IMAGE_ID/MountedFilesystemInventory/`: mounted
  FAT/exFAT filesystem listings.
- `cases/CASE_ID/artifacts/`: extracted artifacts.
- `staging/`: temporary staged imports or zip members.
- SQLite database at the workspace root.
- DuckDB analytics database under the case analytics path.

Exact paths are returned in command JSON output and report manifests.

## Resuming Failed or Interrupted Runs

Check state:

```bash
uv run perceptor --root ROOT report dashboard --case CASE_ID --format table
uv run perceptor --root ROOT report progress --case CASE_ID --format table
uv run perceptor --root ROOT report resume-plan --case CASE_ID --format table
uv run perceptor --root ROOT report workspace-health --case CASE_ID --format md
uv run perceptor --root ROOT report processing-estimate --case CASE_ID --profile windows-full --format table
```

Resume a bulk live-case zip:

```bash
uv run perceptor --root ROOT ingest triage-zip \
  --path /evidence/live-case.zip \
  --resume-from-manifest /analysis/root/cases/CASE_ID/outputs/reports/report-bundle-bulk-import-CASE_ID.manifest.json
```

Run post-processing rebuilds:

```bash
uv run perceptor --root ROOT case rebuild-postprocess CASE_ID
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
uv run perceptor --root ROOT standalone benchmark --case CASE_ID --write-baseline benchmark.json
```

Compare later:

```bash
uv run perceptor --root ROOT standalone benchmark --case CASE_ID --baseline benchmark.json --format table
```

## Safety and Evidence Handling

- Keep original evidence read-only.
- UTC is the default and primary timestamp basis for storage, correlation,
  reports, exports, and MCP context. Use `--timezone America/New_York` only when
  you need local display companion fields; do not replace UTC fields.
- Perceptor hashes disk images on import and stores verification history. Run
  `image integrity` to review stored hashes and `image verify` before producing
  final reports or testimony material.
- Perceptor records TSK `icat` materializations in `report evidence-extractions`
  with source path, inode, extracted path, size, and SHA256.
- Prefer `--filesystem` read-only mounts for speed when processing disk images.
- Use `--keep-mounted` only when you need manual review.
- Run `image cleanup-stale-mounts` after crashes or interrupted sessions.
- Use `--preflight` for large zips before import.
- Use `--max-uncompressed-gb` on bulk live-case/report zip imports to avoid
  exhausting workspace disk. Disk-image ZIP mounting has no fixed GB cap, but it
  requires enough free space for the uncompressed files plus a 10 GB reserve.
- External AI review is off by default. Set `FORENSIC_ALLOW_EXTERNAL_AI=1` only
  when uploading RDP contact sheets to the configured model provider is approved.
  OpenAI-backed review records token usage and estimated cost in RDP visual
  observation report output.
- Use credential reveal options only under controlled conditions.
- Treat memory credential strings as leads unless validated.
- Treat UserAssist, Amcache, and ShimCache as activity/presence indicators, not
  standalone proof of execution.

## Common End-to-End Live-Case Workflow

```bash
uv run perceptor standalone doctor --smoke --format table

uv run perceptor --root ~/analysis/live-case ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --preflight \
  --format table \
  --max-uncompressed-gb 75

uv run perceptor --root ~/analysis/live-case ingest triage-zip \
  --path ~/evidence/live-case.zip \
  --accept-duplicate \
  --report-purpose triage

uv run perceptor --root ~/analysis/live-case report dashboard --case CASE_ID --format table
uv run perceptor --root ~/analysis/live-case report unmapped-imports --case CASE_ID --format table
uv run perceptor --root ~/analysis/live-case report write-bundle \
  --case CASE_ID \
  --purpose usb
```

## Common End-to-End Disk Image Workflow

```bash
uv run perceptor standalone doctor --smoke --format table

uv run perceptor --root ~/analysis/disk-case --dry-run process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --workers 4

uv run perceptor --root ~/analysis/disk-case process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --workers 4

uv run perceptor --root ~/analysis/disk-case report dashboard --case CASE_ID --format table
uv run perceptor --root ~/analysis/disk-case report write-bundle \
  --case CASE_ID \
  --purpose full
```
