# Standalone Pre-UI Checklist

This is the pre-UI operator surface for running the project as a standalone CLI
tool.

For the full operator manual, including common workflows, command switches, and
report families, see [Relic User Manual](user-manual.md).

Supported install target: Ubuntu 24.04 LTS on x86_64, bare metal or VM. Other
platforms are best-effort or unsupported for full mounted-image workflows. See
[Ubuntu Install](ubuntu-install.md).

## Install

```bash
uv sync
uv run forensic-orchestrator standalone version
uv run forensic-orchestrator standalone dependencies
```

Supported target: Linux with Python 3.11 or newer. Windows evidence processing
expects Linux forensic tooling such as Sleuth Kit, libewf, ntfs-3g, qemu-img,
and default memory coverage tooling.

## Config File

Use `--config` or `FORENSIC_ORCHESTRATOR_CONFIG` with YAML:

```yaml
root: /mnt/forensic-ssd/forensic-orchestrator
tools_root: /opt/relic-tools
eztools_root: /opt/relic-tools/eztools
plugins:
  - /opt/relic/forensic_orchestrator/plugins/eztools.yaml
```

Command-line `--root` and `--plugin` values override the file.

## First-Run Doctor

```bash
uv run forensic-orchestrator --config config.yaml standalone doctor
uv run forensic-orchestrator --config config.yaml standalone doctor --case CASE_ID --profile windows-full
uv run forensic-orchestrator --config config.yaml standalone doctor --smoke
uv run forensic-orchestrator --config config.yaml standalone smoke-regression
```

The doctor checks Python/OS support, workspace availability, schema migration,
external dependencies, loaded tools/profiles, optional case readiness, and
unfinished jobs. `--smoke` also creates a tiny isolated temporary workspace,
case, computer, image record, and summary report to verify basic database and
report operations without touching case data.

Use repair mode when the dependency check is missing tools that can be safely
installed or configured without interactive system package management:

```bash
uv run forensic-orchestrator --config config.yaml standalone repair-dependencies
uv run forensic-orchestrator --config config.yaml standalone install-tool eztools
uv run forensic-orchestrator --config config.yaml standalone install-tool sidr
uv run forensic-orchestrator --config config.yaml standalone install-tool memprocfs
source ~/tools/forensic-orchestrator.env
uv run forensic-orchestrator --config config.yaml standalone doctor
```

`repair-dependencies` installs Python CLI tools such as `pypykatz` and
Volatility with `uv tool install`, discovers local tool installs under
`~/tools`, and writes a sourceable env file for values such as `BSTRINGS_BIN`,
`SIDR_BIN`, `MEMPROCFS_BIN`, and `FORENSIC_ORCHESTRATOR_DOTNET`.
System packages such as Sleuth Kit, libewf, ntfs-3g, cryptsetup, dislocker,
libbde-utils, poppler, or tesseract are reported with apt commands because they
require an interactive privileged install on most workstations.

`install-tool` gives the app a managed way to place third-party tools where the
resolver expects them. It supports `eztools`, `bstrings`, `sidr`, `memprocfs`,
`dotnet`, `pypykatz`, `volatility3`, `usnjrnl-forensic`, and `all`. Use
`--dry-run` to preview downloads and commands first:

For SIDR on Linux, `install-tool sidr` builds the native Rust binary from
`https://github.com/strozfriedberg/sidr.git` with `cargo build --release` and
places it at `~/tools/sidr/sidr`. The orchestrator does not use the upstream
Windows `sidr.exe` asset for Linux parsing.

```bash
uv run forensic-orchestrator --config config.yaml --dry-run standalone install-tool all --format table
uv run forensic-orchestrator --config config.yaml standalone tool-status
```

## Standalone Commands

- `ingest triage-zip --path evidence.zip`: import a zip containing one
  top-level folder per computer, create/reuse a case, create one computer record
  per folder, run post-import rebuilds, write durable import manifests, and
  generate a triage report bundle by default.
- `ingest triage-zip --preflight --path evidence.zip`: validate computer-folder
  detection and CSV parser coverage without creating case records or importing
  data.
- `memory workflow --case CASE_ID`: run memory support-file processing and write
  the memory purpose bundle in one command.
- `standalone version`: application, Python, OS, root, and plugin paths.
- `standalone dependencies`: core required and default coverage external tools.
- `standalone repair-dependencies`: safe install/config repair for Python tools
  and local external-tool env variables.
- `standalone install-tool`: download or install supported third-party tools
  into the managed tools directory.
- `standalone tool-status`: show resolved paths, managed paths, and installable
  state for third-party tools.
- `standalone profile-catalog`: configured workflow profiles.
- `standalone artifact-capability`: tool/artifact extraction matrix.
- `standalone schema-status`: SQLite schema version and objects.
- `standalone backup --case CASE_ID --output-dir DIR`: copy SQLite and DuckDB
  databases with a manifest.
- `standalone jobs --case CASE_ID`: recent job status.
- `standalone benchmark --case CASE_ID`: slowest recorded process timings.
- `standalone benchmark --case CASE_ID --write-baseline benchmark.json`: record
  a timing baseline; use `--baseline benchmark.json` on a later run to compare.
- `standalone sample-fixture --output sample-live-case.zip`: create a tiny
  multi-computer report bundle for smoke tests and demonstrations.
- `standalone smoke-regression`: run doctor smoke, generate/import the sample
  live-case fixture, write a triage report bundle, validate report output, and
  verify MCP tool listing in an isolated temporary workspace.
- `standalone verify-install`: friendly alias for `standalone smoke-regression`.
- `standalone backlog`: the pre-UI standalone hardening checklist.

## Operational Defaults

Use `report write-bundle` for report bundle defaults, `report regression-smoke`
for end-to-end report health checks, and `image cleanup-stale-mounts` when FUSE
mount paths become inaccessible.

Common pre-UI run:

```bash
uv run relic --root /analysis/case-root ingest triage-zip \
  --path /evidence/live-case.zip \
  --report-purpose triage
```

The import writes a markdown summary plus JSON manifest under the case reports
folder. The manifest records the source zip/folder, computer folders,
imported/skipped/failed CSVs, generated evidence IDs, row counts, warnings, and
per-computer import reports. If the run is interrupted, use:

```bash
uv run relic --root /analysis/case-root report progress --case CASE_ID
uv run relic --root /analysis/case-root report resume-plan --case CASE_ID
uv run relic --root /analysis/case-root report workspace-health --case CASE_ID
```

Then resume from the bulk import manifest. Completed computer folders from the
manifest are skipped:

```bash
uv run relic --root /analysis/case-root ingest triage-zip \
  --path /evidence/live-case.zip \
  --resume-from-manifest /analysis/case-root/cases/CASE_ID/outputs/reports/report-bundle-bulk-import-CASE_ID.manifest.json
```

Before importing unfamiliar export sets, check parser coverage:

```bash
uv run relic --root /analysis/case-root ingest triage-zip \
  --path /evidence/live-case.zip \
  --preflight \
  --format table \
  --max-uncompressed-gb 75

uv run relic --root /analysis/case-root report-bundle coverage \
  --path /evidence/live-case.zip \
  --format table
```

After import, unsupported CSVs are also stored as case activity and can be
reported later:

```bash
uv run relic --root /analysis/case-root report unmapped-imports --case CASE_ID --format table
uv run relic --root /analysis/case-root report dashboard --case CASE_ID --format table
uv run relic --root /analysis/case-root report validate-outputs \
  --path /analysis/case-root/cases/CASE_ID/outputs/reports/triage-bundle \
  --format table
```

Purpose bundles keep review output focused:

```bash
uv run relic --root /analysis/case-root report write-bundle \
  --case CASE_ID \
  --purpose review
```

Supported purposes are `review`, `triage`, `usb`, `cloud`, `execution`,
`memory`, and `full`. Purpose bundles are computed lazily, so a narrow purpose
avoids building reports outside that review lane. Each bundle also writes
`bundle-quality.json` with report, CSV export, lead-search, and saved-packet
checks. Bundle generation prints timestamped progress to stderr unless
`--no-progress` is supplied.

Memory workflow shortcut:

```bash
uv run relic --root /analysis/case-root memory workflow \
  --case CASE_ID \
  --workers 4
```

Credential reports redact values by default. Use `report memory-credentials
--reveal` only for controlled examiner output, and record analyst decisions with
`report memory-credential-review`.

## Troubleshooting

- FUSE: ensure `/etc/fuse.conf` contains `user_allow_other` when needed, and use
  `image cleanup-stale-mounts --apply` only after reviewing the dry-run output.
- DuckDB: same-case writes are serialized with the case write lock; stale locks
  should only be removed after confirming no processing process is active.
- Missing tools: run `standalone dependencies`; default coverage tools should be
  installed during setup, and specialized workflows should still fail gracefully
  if a tool is unavailable.
  but should not fail normal profiles unless the selected artifact requires them.
