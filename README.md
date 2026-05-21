# Forensic Orchestrator MVP

CLI-first starter repo for lawful forensic processing orchestration.

This MVP proves the initial workflow:

1. Register a Windows E01 forensic image.
2. Detect whether the image is an NTFS volume or full disk image.
3. Discover partitions with `mmls` when needed.
4. Extract configured artifacts with Sleuth Kit `fls`/`icat`.
5. Run configured forensic tools against extracted artifacts.
6. Store auditable orchestration state and tool-output metadata in SQLite.
7. Store normalized parsed artifact rows in per-case DuckDB analytics files.
8. Store only searchable body/content text in OpenSearch, with SQLite/DuckDB references back to origin rows.

This is not a validated forensic product yet. Validate behavior, logging, mounts, and tool output handling before using it on real evidence.

## Requirements

Linux worker packages:

- `sleuthkit` for `mmls`, `fls`, and `icat`
- `dotnet-runtime-9.0` or equivalent
- `ewf-tools` for `ewfmount` fallback when Sleuth Kit cannot read E01 directly
- `ntfs-3g` if using optional read-only filesystem mounts
- `libfsntfs-utils` and `python3-libfsntfs` for optional recovery of compressed NTFS files
- Eric Zimmerman's `SrumECmd` for SRUM parsing. The configured .NET tool runs
  on Windows-capable runtimes; on this Linux MVP worker it may report that
  Windows ESE libraries are unavailable.
- `sidr` for Windows Search index parsing. Set `SIDR_BIN=/path/to/sidr` if it
  is not on `PATH`. SIDR parses both older `Windows.edb` ESE indexes and newer
  Windows 11 SQLite indexes.
- `libesedb-utils` for `esedbexport`, used by the internal WebCache parser to
  export `WebCacheV01.dat` ESE tables on Linux.
- `exiftool` for embedded/internal file metadata extraction from Office files,
  PDFs, pictures, videos, executables, scripts, and archives.
- `$LogFile` parsing uses the vendored `ntfs_parse` parser under
  `third_party/ntfs_parse`. No `/tmp` code dependency is required.
- OneDrive `.dat` parsing can use OneDriveExplorer when available. Set
  `ONEDRIVE_EXPLORER=/path/to/OneDriveExplorer.py`. On Linux the app uses
  OneDriveExplorer's `.dat` parser library as a fallback because the upstream
  CLI imports Windows-only ODL code; ODL/ODLSENT files are still inventoried by
  the internal cloud parser.
- RDP Bitmap Cache extraction can use BMC Tools when available. Set
  `BMC_TOOLS=/path/to/bmc-tools.py`. Without it, the app still inventories RDP
  cache files and records that fragment extraction was skipped.
- Future image-wide analysis hooks are centralized in `image_analysis_items`.
  OCR currently uses `tesseract` only when explicitly requested by a parser and
  when `tesseract-ocr` is installed; RDP cache parsing records image metadata
  without OCR by default.

See `docs/dependencies.md` for the maintained dependency checklist, optional
tool environment variables, and verification commands.

The default MVP flow does not require a kernel NTFS mount. Image preparation
first runs `fsstat` to detect volume-captured NTFS E01s at offset `0`, then
uses `mmls` for full-disk images. If the local Sleuth Kit build cannot read EWF
images, it falls back to `ewfmount` for the EWF container layer and then uses
Sleuth Kit against `ewf1`.

Before mounting or running a profile, image preparation performs an encryption
preflight. It checks `fsstat` output for volume images, then checks the selected
partition description and runs `fsstat -o <offset>` against the selected
partition for full-disk images. If BitLocker, VeraCrypt, TrueCrypt, LUKS,
FileVault/APFS encryption, or a similar encrypted filesystem signal is detected,
processing stops and logs `image.encryption_detected`. Encrypted filesystem
support is intentionally fail-closed for now.

When `ewfmount` fallback is used, the app invokes `ewfmount -X allow_other` so
the mounted `ewf1` raw image remains readable by the worker process. On systems
that enforce FUSE's default restrictions, `/etc/fuse.conf` must include:

```text
user_allow_other
```

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

By default, case data is stored under:

```text
/var/lib/forensic-orchestrator
```

Override it with either:

```bash
export FORENSIC_ORCHESTRATOR_ROOT=/tmp/forensic-orchestrator
```

or:

```bash
forensic-orchestrator --root /tmp/forensic-orchestrator ...
```

If Eric Zimmerman tools are installed somewhere other than `/opt/eztools`, set:

```bash
export EZTOOLS_ROOT=/path/to/eztools
```

The built-in YAML keeps `/opt/eztools/...` paths for deployment clarity, and the
CLI rewrites that prefix at runtime when `EZTOOLS_ROOT` is present.

If OneDriveExplorer is installed outside the repo, set:

```bash
export ONEDRIVE_EXPLORER=/path/to/OneDriveExplorer/OneDriveExplorer.py
```

## Operator Run

Use a durable workspace root for real case data. `/tmp` is scratch-only and
should not hold evidence, case databases, extracted artifacts, parser output, or
checkpoints that need to survive a reboot.

For a normal operator run, use one command. This creates a project when `--case`
is omitted, creates a computer record, registers the E01, prepares the image,
optionally mounts the selected NTFS volume read-only, runs the profile, records
tool output metadata in SQLite, writes normalized parsed artifacts to DuckDB, and
returns a JSON status payload.

SQLite is for orchestration metadata: cases, images, mounts, artifacts, jobs,
tool outputs, activity logs, content references, search index runs, and
process timing rows. It is not the default store for high-volume normalized
artifact rows. DuckDB is the default analytics store for parsed artifacts such
as MFT, USN, EVTX, SRUM, registry artifacts, browser artifacts, mail/message
metadata, Windows Search, and timeline events. Set `FORENSIC_ANALYTICS_MODE=sqlite`
only for legacy compatibility tests or one-off debugging; `mirror` writes both
stores for transition checks.

Profile runs write UI-ready timing records to SQLite table `process_timings`.
The table records start/end time, duration, status, parent timing, and bounded
metadata for profile, artifact extraction, parser/tool, and post-processing
steps. It is intended for progress displays and run audits, not for parsed
artifact payloads or raw content. Generate a markdown timing audit with:

```bash
forensic-orchestrator --root /path/to/workspace report process-timings \
  --case CASE_ID \
  --format md \
  --output /path/to/timing-report.md
```

Report plugins can add read-only SQL reports without changing the built-in
Python report functions. Specs can be embedded in the YAML passed to `--plugin`,
placed in a `report_specs/` directory beside that plugin file, or installed
under `forensic_orchestrator/plugins/report_specs/`. Extra plugin directories
can also be supplied with `FORENSIC_REPORT_SPEC_DIRS`. Artifact reports should
query DuckDB parsed fields and references; body/content text remains in
OpenSearch. See `docs/report-specs.md` for the spec format.

Dry-run first:

```bash
forensic-orchestrator --root /tmp/fo --dry-run process \
  --path /evidence/disk.E01 \
  --computer-label "Laptop 1" \
  --profile windows-basic-evtx \
  --filesystem \
  --sudo
```

Run for real:

```bash
forensic-orchestrator --root /tmp/fo process \
  --path /evidence/disk.E01 \
  --computer-label "Laptop 1" \
  --profile windows-basic-evtx \
  --filesystem \
  --sudo \
  --replace-existing
```

Use `--keep-mounted` when you intentionally want to leave the read-only volume
mounted for manual inspection. Without it, `process --filesystem` unmounts the
volume after the profile finishes.

## ROCBA Mounting Caveat

The ROCBA VM currently has a legacy sudoers NOPASSWD allowance hardcoded to
`/tmp/forensic-orchestrator-rocba-case` and `/tmp/rocba-cdrive.e01`. Keep durable
data on `/mnt/forensic-ssd`; use `/tmp` only as a symlink compatibility path for
that exact sudoers rule.

Create the compatibility symlink when needed:

```bash
ln -s /mnt/forensic-ssd/forensic-orchestrator-rocba-case /tmp/forensic-orchestrator-rocba-case
```

The EWF layer can be mounted as the normal user:

```bash
ewfmount -X allow_other \
  /mnt/forensic-ssd/evidence/rocba/rocba-cdrive.e01 \
  /mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/CASE_ID/mounts/ewf
```

The NTFS layer must use the legacy sudoers command path through the symlink:

```bash
sudo -n /usr/bin/ntfs-3g -o ro,show_sys_files,streams_interface=windows,norecover,offset=0 \
  /tmp/forensic-orchestrator-rocba-case/cases/CASE_ID/mounts/ewf/ewf1 \
  /tmp/forensic-orchestrator-rocba-case/cases/CASE_ID/mounts/volumes/volume-ntfs
```

Verify the real SSD-backed mount target:

```bash
findmnt /mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/CASE_ID/mounts/volumes/volume-ntfs
```

Full profiles should run against a mounted NTFS volume. Broad recursive TSK
inventory is disabled by default; set `FORENSIC_ALLOW_RECURSIVE_TSK_INVENTORY=1`
only when intentionally using the fallback path.

## Example Usage

Create a project:

```bash
forensic-orchestrator --root /tmp/fo project create
```

Add a computer to the project:

```bash
forensic-orchestrator --root /tmp/fo computer add \
  --case CASE_ID \
  --label "Laptop 1" \
  --hostname LAPTOP-1
```

Add an E01 image:

```bash
forensic-orchestrator --root /tmp/fo image add \
  --case CASE_ID \
  --computer COMPUTER_ID \
  --path /evidence/disk.E01
```

Dry-run image preparation:

```bash
forensic-orchestrator --root /tmp/fo --dry-run image mount --case CASE_ID --image IMAGE_ID
```

Prepare the image for processing:

```bash
forensic-orchestrator --root /tmp/fo image mount --case CASE_ID --image IMAGE_ID
```

Optionally mount the selected NTFS volume read-only with non-interactive sudo:

```bash
forensic-orchestrator --root /tmp/fo image mount \
  --case CASE_ID \
  --image IMAGE_ID \
  --filesystem \
  --sudo
```

This records the mount command as a normal job and uses options equivalent to:

```text
ro,show_sys_files,streams_interface=windows,norecover,offset=<bytes>
```

Unmount the recorded filesystem mount:

```bash
forensic-orchestrator --root /tmp/fo image unmount \
  --case CASE_ID \
  --image IMAGE_ID \
  --sudo
```

List configured tools and profiles:

```bash
forensic-orchestrator --root /tmp/fo tools list
```

Dry-run the Windows basic EVTX triage profile:

```bash
forensic-orchestrator --root /tmp/fo --dry-run run --case CASE_ID --image IMAGE_ID --profile windows-basic
```

Run one of the Windows profiles:

```bash
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-no-evtx
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-basic-evtx
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-full-evtx
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-srum
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-search
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-webcache
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-search-srum
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-office
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-pictures
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-pictures-deep
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-pictures-user-content
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-videos
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-executables
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-documents
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-all
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-rdp-cache
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-deep
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-old
```

`windows-basic` is kept as an alias for `windows-basic-evtx`.
`windows-srum`, `windows-search`, and `windows-webcache` are useful for testing those larger
artifacts independently. `windows-deep` includes the full EVTX profile plus SRUM,
Windows Search, and WebCache.
`windows-full` also carries `coverage_categories` metadata in the tool profile.
Those categories mirror the SANS FOR500 poster groupings for coverage review
only; they do not remove tools or change the profile execution order.

The `file-metadata-*` profiles extract matching files read-only and run
`exiftool` to collect embedded/internal metadata into `file_internal_metadata`.
Use the category profiles to control runtime and extraction volume; `file-metadata-all`
covers common document, media, executable, script, and archive extensions.
The built-in metadata profiles exclude high-noise OS/application roots by
default (`Windows`, `Windows.old`, `Program Files`, and `ProgramData`) so broad
media/document scans do not spend most of their time on system assets.
`file-metadata-pictures` is the default fast image scan focused on likely user
content folders. It excludes `AppData` and `Google Drive` paths; Google Drive
for Desktop should be handled as a separate cloud-storage artifact because its
files may be virtualized or cached. Use `file-metadata-pictures-deep` for a
broader sweep outside common OS/application roots.

`windows-rdp-cache` inventories Remote Desktop bitmap cache files under user
profiles and, when `BMC_TOOLS` is configured, extracts tile fragments, records
their dimensions and hashes in `rdp_cache_items`, and stores reusable image
metadata in `image_analysis_items`. The follow-on `RdpVisionReview` stage uses
the OpenAI Responses API when `OPENAI_API_KEY` is configured to produce bounded
semantic observations from contact sheets. If no key is configured, or the API
call fails, it records a Tesseract OCR fallback row instead. `windows-deep` also
includes this parser.

`windows-old` scopes the existing Windows artifact parsers to `Windows.old`.
It stores extracted artifacts and parser output under a `Windows.old` namespace,
keeps the original parser names so rows land in the same normalized tables, logs
parser failures as warnings, and logs accepted duplicate output hashes.

If the same tool output content has already been imported for the same
case/image/tool, the run stops and logs `tool.duplicate_output_detected`.
Choose the rerun behavior explicitly:

```bash
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-basic --accept-duplicate
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-basic --replace-existing
```

MFT-driven metadata extraction processes live MFT entries by default. Include
deleted/orphaned MFT entries explicitly when you want that broader sweep:

```bash
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile file-metadata-pictures-deep --include-deleted-mft
```

Start Menu shortcuts are excluded from LNK parsing by default to reduce noisy
program shortcut findings. Include them explicitly when needed:

```bash
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-basic --include-start-menu-lnk
```

Check case status:

```bash
forensic-orchestrator --root /tmp/fo case status CASE_ID
```

View the activity log:

```bash
forensic-orchestrator --root /tmp/fo case activity CASE_ID
forensic-orchestrator --root /tmp/fo case activity CASE_ID --level warning
forensic-orchestrator --root /tmp/fo case activity CASE_ID --level error
```

Generate investigator-facing JSON reports:

```bash
forensic-orchestrator --root /tmp/fo report summary --case CASE_ID
forensic-orchestrator --root /tmp/fo report specs
forensic-orchestrator --root /tmp/fo report spec --case CASE_ID --name mft-recent --format table
forensic-orchestrator --root /tmp/fo report issues --case CASE_ID
forensic-orchestrator --root /tmp/fo report execution --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report interesting-executables --case CASE_ID --format md
forensic-orchestrator --root /tmp/fo report interesting-executables --case CASE_ID --rules ./my-interesting-tools.yaml --format table
forensic-orchestrator --root /tmp/fo report accounts --case CASE_ID
forensic-orchestrator --root /tmp/fo report users --case CASE_ID
forensic-orchestrator --root /tmp/fo report files --case CASE_ID --user Devon
forensic-orchestrator --root /tmp/fo report file-names --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report file-names --case CASE_ID --contains "GunStar" --format table
forensic-orchestrator --root /tmp/fo report file-name-drilldown --case CASE_ID --name "GunStar Death Blossom Data.docx" --format table
forensic-orchestrator --root /tmp/fo report file-history --case CASE_ID --name "GunStar Death Blossom Data.docx" --format table
forensic-orchestrator --root /tmp/fo report file-history --case CASE_ID --mft-entry 130698 --filesystem-only --format table
forensic-orchestrator --root /tmp/fo report copied-files --case CASE_ID
forensic-orchestrator --root /tmp/fo report copied-file-indicators --case CASE_ID
forensic-orchestrator --root /tmp/fo report copied-file-groups --case CASE_ID
forensic-orchestrator --root /tmp/fo report copied-usb-files --case CASE_ID --grouped
forensic-orchestrator --root /tmp/fo report copied-file-indicators --case CASE_ID --include-mft-only --include-system
forensic-orchestrator --root /tmp/fo report copied-file-drilldown --case CASE_ID --path "E:\\copied.docx"
forensic-orchestrator --root /tmp/fo report usb-dossier --case CASE_ID --volume-serial-number 2CB9-F845
forensic-orchestrator --root /tmp/fo report device-inventory --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report case-review --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report correlations --case CASE_ID
forensic-orchestrator --root /tmp/fo report artifact-summary --case CASE_ID
forensic-orchestrator --root /tmp/fo report tool-runs --case CASE_ID --limit 250
forensic-orchestrator --root /tmp/fo report mft --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report usn --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report prefetch --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report evtx --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report evtx-recovery --case CASE_ID
forensic-orchestrator --root /tmp/fo report recycle --case CASE_ID --user Jean
forensic-orchestrator --root /tmp/fo report deleted-folders --case CASE_ID
forensic-orchestrator --root /tmp/fo report firefox --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report browser --case CASE_ID --type history --limit 100
forensic-orchestrator --root /tmp/fo report browser --case CASE_ID --type downloads --limit 100
forensic-orchestrator --root /tmp/fo report browser-downloads --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report browser-cache --case CASE_ID --browser edge --host microsoft.com --format table --limit 100
forensic-orchestrator --root /tmp/fo report browser-cache --case CASE_ID --exclude-noise --format table --limit 100
forensic-orchestrator --root /tmp/fo report browser-hosts --case CASE_ID --exclude-noise --format table --limit 100
forensic-orchestrator --root /tmp/fo report browser-cache-correlations --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report browser-activity --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report browser-deep-storage --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report webcache --case CASE_ID --application "Microsoft Edge" --exclude-metadata --format table --limit 100
forensic-orchestrator --root /tmp/fo report webcache-files --case CASE_ID --usb-overlap --format table --limit 100
forensic-orchestrator --root /tmp/fo report windows-activities --case CASE_ID --files-only --format table --limit 100
forensic-orchestrator --root /tmp/fo report uninstalled-app-artifacts --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report tor-usage --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report encrypted-volumes --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report phone-link --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report virtualization --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report cloud-artifacts --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report srum-context --case CASE_ID --format table --limit 250
forensic-orchestrator --root /tmp/fo report vpn-local-activity --case CASE_ID --format md --limit 500
forensic-orchestrator --root /tmp/fo report web-cloud-correlations --case CASE_ID --category webmail --format table --limit 100
forensic-orchestrator --root /tmp/fo report web-cloud-correlations --case CASE_ID --provider "Google Drive" --format table --limit 100
forensic-orchestrator --root /tmp/fo report messaging-artifacts --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report messaging-artifacts --case CASE_ID --application Slack --user fredr --contains frocba --format table
forensic-orchestrator --root /tmp/fo report event-interpretation --case CASE_ID --category usb --format table --limit 100
forensic-orchestrator --root /tmp/fo report email-artifacts --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report mailbox-messages --case CASE_ID --format table --limit 100
forensic-orchestrator --root /tmp/fo report mailbox-messages --case CASE_ID --user fredr --status parsed --contains SharePoint --format table
forensic-orchestrator --root /tmp/fo report timeline --case CASE_ID --contains "report.docx"
forensic-orchestrator --root /tmp/fo report user-timeline --case CASE_ID --user Jean --format table --limit 250
forensic-orchestrator --root /tmp/fo report validate --case CASE_ID
forensic-orchestrator --root /tmp/fo report registry --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report registry-artifacts --case CASE_ID --artifact usb_device_history
forensic-orchestrator --root /tmp/fo report registry-activity --case CASE_ID --artifact runmru --user Jean
forensic-orchestrator --root /tmp/fo report registry-activity --case CASE_ID --artifact recentdocs --user Devon
forensic-orchestrator --root /tmp/fo report common-dialog-items --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report amcache --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report shimcache --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report shellbags --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report usb --case CASE_ID --limit 100
forensic-orchestrator --root /tmp/fo report usb --case CASE_ID --breakdown
forensic-orchestrator --root /tmp/fo report usb-files --case CASE_ID --format table --limit 500
forensic-orchestrator --root /tmp/fo report usb-files --case CASE_ID --grouped --format csv --output usb-files-deduped.csv
forensic-orchestrator --root /tmp/fo report usb-files --case CASE_ID --format csv --output usb-files.csv
forensic-orchestrator --root /tmp/fo report usb-timeline --case CASE_ID --format table --limit 500
forensic-orchestrator --root /tmp/fo report export --case CASE_ID --preset usb-summary --output usb-summary.csv
forensic-orchestrator --root /tmp/fo report export --case CASE_ID --preset usb-file-correlations --output usb-file-correlations.csv
forensic-orchestrator --root /tmp/fo report export --case CASE_ID --preset usb-timeline --output usb-timeline.csv
forensic-orchestrator --root /tmp/fo report file-metadata --case CASE_ID --user-only --exclude-system --limit 100
forensic-orchestrator --root /tmp/fo report file-metadata --case CASE_ID --extension .docx --property Creator
forensic-orchestrator --root /tmp/fo report file-metadata --case CASE_ID --source-folder Users/fredr/Downloads
forensic-orchestrator --root /tmp/fo report file-metadata-folders --case CASE_ID --tool FileMetadataPicturesUserContent
forensic-orchestrator --root /tmp/fo report file-metadata-skipped --case CASE_ID --latest
forensic-orchestrator --root /tmp/fo report file-metadata-skipped-deleted --case CASE_ID --latest
forensic-orchestrator --root /tmp/fo report file-metadata-unresolved --case CASE_ID --latest
forensic-orchestrator --root /tmp/fo report file-metadata-summary --case CASE_ID
forensic-orchestrator --root /tmp/fo report activity-summary --case CASE_ID --user Jean
forensic-orchestrator --root /tmp/fo report shortcuts --case CASE_ID --type lnk
forensic-orchestrator --root /tmp/fo report shortcuts --case CASE_ID --type jumplist
```

`case` remains as a CLI alias while the MVP evolves toward project terminology.

## Tool Plugins

Tools are configured with YAML. The built-in plugin is:

```text
forensic_orchestrator/plugins/eztools.yaml
```

The enabled MVP tools are:

- `MFTECmd`
- `SAMParser`
- `EvtxECmd`
- `EvtxECmdTriage`
- `PrefetchParser`
- `RecycleParser`
- `FirefoxParser`
- `ChromiumParser`
- `WebCacheParser`
- `RegistryParser`
- `RECmd`
- `RegistryArtifactParser`
- `AmcacheParser`
- `AppCompatCacheParser`
- `SBECmd`
- `JLECmd`
- `LECmd`

The built-in profiles provide explicit EVTX cost/coverage choices:

- `windows-no-evtx`: skips event log parsing.
- `windows-basic-evtx`: processes selected high-value logs such as Security,
  System, Application, PowerShell, Task Scheduler, Terminal Services, Defender,
  WinRM, Group Policy, and Sysmon if present.
- `windows-full-evtx`: processes all `.evtx` files under
  `Windows/System32/winevt/Logs`.
- `windows-full`: complete mounted Windows profile with full EVTX, filesystem
  metadata, browser, registry, cloud, email, messaging, package, telemetry, RDP
  bitmap cache, and shell/Jumplist artifacts. RDP cache output is stored as
  parsed metadata in DuckDB plus fragment/contact-sheet files on disk. Visual
  observation rows are generated for contact-sheet availability and timing. The
  vision-review stage uses OpenAI API keys as the primary semantic contact-sheet
  reviewer and falls back to Tesseract OCR. Only bounded observations and
  metadata are stored in DuckDB; contact-sheet files remain on disk. Broad
  embedded per-file metadata extraction is intentionally excluded from
  `windows-full`; analysts can run the targeted `file-metadata-*` profiles when
  they want that heavier collection.
- `windows-basic`: alias for `windows-basic-evtx`.

Disabled stubs are present for:

- `RBCmd`

Eric Zimmerman's CLI tools can be installed as .NET 9 builds via `Get-ZimmermanTools`. Update executable paths in YAML if your deployment path is not `/opt/eztools`.

Tool definitions can declare artifacts to extract before command execution:

```yaml
artifacts:
  - name: MFT
    source: "$MFT"
    inode: "0"
    destination: "$MFT"
    process_in_place: true
command:
  - dotnet
  - "{executable}"
  - "-f"
  - "{artifact:MFT}"
  - "--csv"
  - "{output}"
```

Recursive directory extraction is also supported, for example:

- Extracting `*.evtx` files from `Windows/System32/winevt/Logs` before running `EvtxECmd`.
- Referencing `Windows/Prefetch` directly from a read-only mounted volume before running `PECmd`.
- Referencing user Jump List folders directly from a read-only mounted volume before running `JLECmd`.
- Extracting user `*.lnk` files before running `LECmd`, with Start Menu links excluded unless `--include-start-menu-lnk` is set.
- Extracting registry hives including `SYSTEM`, `SOFTWARE`, `SECURITY`, `SAM`,
  optional `Amcache.hve`, and user `NTUSER.DAT`/`UsrClass.dat` files before
  running the built-in `RegistryParser` inventory.
- Parsing targeted registry artifacts from `SYSTEM`, `SOFTWARE`, optional
  `Amcache.hve`, and user `NTUSER.DAT`/`UsrClass.dat` files with
  `RegistryArtifactParser`. Registry transaction sidecars such as `.LOG1` and
  `.LOG2` are extracted when present, and registry artifact rows record whether
  logs were detected and whether they were applied. The current internal parser
  does not replay transaction logs, so rows from hives with detected logs should
  be treated as unrecovered base-hive output until a log-aware backend is used.
- Running RECmd batch mode with `recmd_windows_activity.reb` against extracted
  registry hives. The RECmd command intentionally does not use `--nl`, so RECmd
  can apply transaction logs when matching sidecars are present beside the hive.

RECmd coverage in the bundled batch:

- Collected by RECmd: current control set, computer name, time zone, shutdown
  time, SOFTWARE install time/date, SourceOS install keys, connected network
  profiles/signatures, Capability Access Manager, Run/RunOnce autostarts,
  installed applications, USB/USBSTOR/MountedDevices, raw AppCompatCache value,
  RunMRU, TypedPaths, WordWheelQuery, RecentDocs, Office MRU, common dialog MRUs,
  UserAssist, Taskband, Trusted Documents, and raw ShellBag BagMRU values.
- Also collected by dedicated parsers: ShellBags via SBECmd, Amcache via
  AmcacheParser, and ShimCache via AppCompatCacheParser. RECmd can collect raw
  registry values for some of these, while the dedicated tools now populate
  normalized DuckDB analytics tables for investigation-ready review.

`RegistryArtifactParser` currently records targeted registry key/value evidence
for:

- Current control set, computer name, time zone, shutdown time, and install time.
- Source OS install records under the SYSTEM hive.
- Autostart locations, installed applications, connected networks, and Capability Access Manager.
- Amcache and ShimCache key/value evidence.
- WordWheelQuery, TypedPaths, RecentDocs, Office recent docs, common dialog, RunMRU, UserAssist, taskbar, and ShellBags key/value evidence.
- USBSTOR, USB enum, and MountedDevices history.

ShellBags, Amcache, and ShimCache are still represented as registry key/value
evidence in this internal parser, but `SBECmd`, `AmcacheParser`, and
`AppCompatCacheParser` are now enabled in the default Windows profiles for
richer artifact-specific decoding.

When `process_in_place: true` is set and a read-only filesystem mount exists, the
tool receives the mounted artifact path directly instead of a copied artifact.
For copied artifacts, mounted extraction copies file bytes only and logs metadata
separately so unusual NTFS metadata does not cause otherwise-readable files to be
skipped. If mounted extraction fails and Sleuth Kit inventory is available, the
app attempts a targeted `icat` fallback for that file.

`PECmd` is still configured for Windows-capable parser runners, but the default
Linux `windows-basic` profile uses the built-in `PrefetchParser`. It handles
modern Windows 10/11 MAM-compressed Prefetch files by decompressing the embedded
XPRESS-Huffman stream, parsing the SCCA data, writing `PrefetchParser.csv`, and
ingesting the rows into the case artifact store.

For Prefetch, the artifact inventory also records whether extracted files are
older uncompressed SCCA Prefetch files or Windows 10/11 MAM-compressed files.
MAM-compressed originals are preserved under `artifacts/<image_id>/Windows/Prefetch`
and logged as `artifact.prefetch_inventory`.

Prefetch hash/path reference enrichment is supported without importing the
reference dataset into case evidence. Set `FORENSIC_PREFETCH_HASH_LOOKUP_PATHS`
to one or more tab-delimited lookup files separated by the platform path
separator, or place the FOR500 lookup at
`/home/lee/reference/upload/FOR500_K01/Library/Analysis/prefetch_hashes_lookup.txt`.
Matches populate `resolved_reference_*` fields on `prefetch_items` and should be
treated as resolver enrichment, not proof of a path on the examined system unless
other case artifacts corroborate it.

## Audit Records

Every command is stored in SQLite as a job record with:

- UUID
- case ID
- image ID
- tool name
- tool version when detectable
- full command array
- start time
- end time
- exit code
- stdout/stderr paths
- output folder
- dry-run flag

Artifact extraction jobs from `fls` and `icat` are recorded the same way as
parser jobs.

The project database also records computers and generated parser outputs:

- `projects`: project metadata, currently one project per workspace case.
- `computers`: multiple computers per project.
- `images`: E01 images, optionally linked to a computer.
- `tool_outputs`: generated CSV files, linked to project, computer, image, job, tool, and content SHA-256 for duplicate detection.
- `parsed_rows`: legacy table retained for older case databases only. New ingests
  do not import generic full-row JSON; tools without a normalized parser keep
  their raw output on disk under the case `outputs/` tree.
- `mft_entries`: normalized MFTECmd `$MFT` rows.
- `usn_journal_entries`: normalized MFTECmd `$Extend/$UsnJrnl:$J` rows, parsed
  with `$MFT` context by the `MFTECmdUSN` tool.
- `ntfs_logfile_entries`: normalized `$LogFile` parser rows. The
  `NTFSParseLogFile` tool uses the vendored open-source `ntfs_parse`
  `logfileparse.py` parser. MFTECmd 2026.5.0 identifies `$LogFile` but reports
  it as unsupported.
- `ntfs_namespace_reconciliation`: targeted checks for allocated MFT records
  that were not visible through the mounted filesystem, including `$I30`
  status, parent mount accessibility, `icat` recovery status, recovered SHA-256,
  and simple header validation.
- `filesystem_review`: unified review rows rebuilt from MFT, USN, `$LogFile`,
  `$I30`, and namespace reconciliation evidence.
- `sam_accounts`: normalized SAM account rows.
- `registry_hives`: registry hive inventory rows with hive type, size, SHA-256, key/value counts, and parser errors.
- `registry_artifacts`: targeted registry artifact rows with hive type, user profile, artifact name, key path, key last-write time, derived event time where supported, MRU ordering, value name/type/data, transaction-log detection status, and notes.
- `usb_devices`: normalized USB profile rows from Enum\\USB, USBSTOR/SCSI/HID,
  SWD/WPDBUSENUM, Windows Portable Devices, VolumeInfoCache,
  MountPoints2, MountedDevices, DeviceMigration, and
  Microsoft-Windows-Partition/Diagnostic. Rows retain VID/PID where present,
  iSerialNumber/ParentIdPrefix, device service/type, vendor/product/revision,
  device friendly name, drive letter, volume GUID, volume serial number/name, capacity, alternate
  SCSI serial, related user profile, key/event time, and source property/value
  evidence.
- `usb_storage_devices`: one-row-per-storage-device summary rebuilt from USB
  evidence rows. This is the default `report usb` view.
- `usb_file_correlations`: persisted LNK, Jump List, and Shellbag file artifact
  correlations to USB storage devices. Rows include inferred user profile where
  available. Exact VSN and volume GUID matches are marked high confidence;
  lower-32-bit VSN suffix matches are marked medium confidence; drive-letter-only
  Shellbag fallback matches are marked low confidence.
- `registry_recentdocs`, `registry_runmru`, `registry_typedpaths`,
  `registry_wordwheel_query`, `registry_userassist`, `registry_office_mru`,
  `registry_common_dialog_mru`, and `registry_trusted_documents`:
  normalized RECmd batch/plugin outputs split into artifact-specific tables.
- `registry_common_dialog_items`: decoded shell items from OpenSavePidlMRU and
  LastVisitedPidlMRU binary PIDL values, including item names, MRU position,
  source hive/user, key last-write time, parsed shell timestamps when
  available, and raw FAT timestamp candidates for review.
- `amcache_entries`: normalized AmcacheParser rows with entry type, file path,
  hashes, publisher/product fields, version fields, and high-value timestamps.
- `shimcache_entries`: normalized AppCompatCacheParser rows with control set,
  entry number, path, last modified time, and execution flag when present.
- `shellbag_entries`: normalized SBECmd rows with hive/user, absolute path,
  shell type, MRU/slot fields, interaction timestamps, and explored flag.
- `evtx_events`: normalized EvtxECmd rows.
- `evtx_recovery`: EVTX extraction status, partial recovery counts, libfsntfs salvage details, and EvtxECmd parser errors per source log.
- `telemetry_artifacts`: normalized telemetry-adjacent inventory and decoded
  rows for WMI repository files, Windows CloudStore, Windows Notifications,
  AppRepository, AppLocker policy artifacts, and WDAC/Code Integrity policy
  artifacts.
- `prefetch_items`: normalized Prefetch rows, including Prefetch source-file NTFS timestamps from Sleuth Kit metadata and optional Prefetch hash reference enrichment.
- `recycle_items`: normalized top-level Recycle Bin entries.
- `recycle_children`: files found inside deleted Recycle Bin folders, so deleted folder contents are not hidden by top-level `$R`/`Dc` parsing.
- `firefox_history`: normalized Firefox visit history from `places.sqlite`.
- `firefox_cookies`: normalized Firefox cookies from `cookies.sqlite`.
- `shortcut_items`: normalized LNK and Jump List fields for shortcut name, target path, target times, device type, volume serial/name, LNK source times, and Jump List item number.
- `timeline_events`: persisted timeline events with both raw timestamps and normalized UTC ISO timestamps.
- `file_correlations`: links LNK, Jump List, and Prefetch findings back to matching `mft_entries` where possible.
- `copied_file_indicators`: normalized `created_time > modified_time`
  indicators from MFTECmd, LNK files, Jump Lists, Shellbags, and registry
  MRU-style artifacts when they can be tied back to MFT metadata. Decoded
  Common Dialog PIDL shell item timestamps are considered only after filtering
  out app MRU entries, drive roots, GUID shell objects, and implausible
  timestamp candidates.
- `activity_log`: human-readable activity, warnings, and errors with structured details.

Core parser outputs are now stored in parser-specific normalized tables.
Generic full-row JSON fallback imports are disabled by design.

Future file-activity reporting uses a lightweight activity contract rather than
collapsing all artifacts into one table too early. New artifact parsers should
preserve their dedicated normalized table and expose, directly or in derived
details, these fields when the artifact can describe a file, path, or user file
activity:

- `source_table`: normalized table that stores the source row.
- `source_row_id`: source row UUID.
- `source_tool`: parser or derived tool name.
- `event_time_utc`: UTC event timestamp, if the artifact has one.
- `timestamp_meaning`: what that timestamp means, such as `mft_created`,
  `usn_close`, `defender_event_time`, or `lnk_target_modified`.
- `path`: best available path for investigator review.
- `file_name`: filename or final path component.
- `user_profile`: owning user when attributable.
- `artifact_category`: broad source category, such as `file_reference`,
  `filesystem`, `shortcut`, `cloud`, or `registry_mru`.
- `interpretation_note`: short explanation of what the row proves, and what it
  does not prove.

The shared helper is `forensic_orchestrator.activity_contract`. It validates
required provenance and timestamp semantics so the eventual unified
`file-activity` report can be built from consistent source-backed rows.

## Storage Policy

SQLite is the case system of record, not the universal content store.

- Store normalized, reportable artifact facts in SQLite columns. This includes
  file system metadata, registry artifacts, shortcuts, browser rows, cloud sync
  metadata, USB records, correlations, dedupe keys, parser provenance, and job
  audit data.
- Store raw parser output and extracted files under the case `outputs/` and
  `artifacts/` folders. SQLite stores paths, hashes, row counts, tool names, and
  source row IDs so raw output can be traced and reprocessed.
- Store large searchable text in OpenSearch during ingest. This includes email
  bodies, attachment text, Windows Search indexed content, message fragments,
  and future OCR output. SQLite/DuckDB keep metadata references, hashes,
  lengths, provenance, and OpenSearch document IDs, not the content itself.
- Do not use `details_json`/`raw_json` as a place to park unparsed artifacts.
  Small bounded provenance details are acceptable where unavoidable, but fields
  needed for reports, joins, filtering, sorting, or repeated interpretation
  should be promoted into explicit columns.

Review the current case against this boundary with:

```bash
forensic-orchestrator --root /tmp/fo report storage-policy \
  --case CASE_ID \
  --format table
```

Activity records include command starts and finishes, exit codes, selected
partition/source, artifact extraction counts, empty artifact warnings, missing
CSV warnings, and imported row counts. The `jobs` table remains the source for
full command arrays and stdout/stderr paths.

The report commands are intentionally thin JSON views over SQLite:

- `report summary`: project/computer/image counts, artifact counts, tool outputs, parser row counts, and EVTX recovery counts.
- `report storage-policy`: storage-boundary review showing content-heavy SQLite
  tables, estimated large text currently held there, raw output file footprint,
  and latest OpenSearch indexing status.
- `report issues`: warning and error activity records in chronological order.
- `report telemetry-artifacts`: WMI, CloudStore, Notifications,
  AppRepository, AppLocker, and WDAC artifacts, optionally filtered by
  `--artifact-group` or `--contains`.
- `report computer-inventory`: OS/build/timezone/software inventory and
  artifact expectations. This is intended to be one of the first reports
  reviewed for a computer, because Windows and application versions determine
  which artifacts should exist and where parsers should look.
- `report artifact-correlations`: cross-artifact links such as notification to
  Windows Activity, cloud metadata to OneDrive rows, and Google Drive cache
  mappings to cloud sync metadata. Rows preserve source table/row IDs, match
  type, key, and confidence.
- `report execution`: persisted timeline events from normalized parser rows. LNK and Jump List target metadata is checked for copied-file behavior: if the target creation time is later than the target modification time, the timeline contains a `copied_file_indicator`.
- `report interesting-executables`: configurable matches for tools such as
  SDelete, CCleaner, credential recovery utilities, remote access tools, and
  network utilities. The default editable rule list is
  `forensic_orchestrator/plugins/interesting_executables.yaml`; pass `--rules`
  to use a case/team-specific YAML list.
- `report activity-summary`: higher-level recent activity slices for accounts, execution, file activity, browser history, logons, Recycle Bin, and copied-file indicators.
- `report accounts`: local account records parsed from the SAM hive.
- `report users`: local user-focused account records.
- `report files`: normalized MFT file rows, optionally filtered by user path.
- `report copied-files`: copied-file indicators from the timeline.
- `report common-dialog-items`: decoded OpenSavePidlMRU and
  LastVisitedPidlMRU shell items with source hive/user and shell timestamps.
- `report copied-file-indicators`: normalized copied-file timestamp indicators
  from MFT, shortcuts, Shellbags, registry/MFT correlation, and validated
  Common Dialog shell item timestamps. By default it suppresses system paths
  and MFT-only timestamp indicators so the view is investigator-facing. Use
  `--include-mft-only` for raw MFT timestamp rows, `--include-system` for
  system paths, and `--source-artifact-type` or `--user-only` to narrow results.
- `report copied-file-groups`: deduplicated copied-file indicators grouped by
  file path and created/modified timestamps, with source artifact counts.
  Supports `--format json|table|csv` and `--output`.
- `report copied-usb-files`: copied-file timestamp indicators that also
  correlate to USB storage evidence. ShellBag folder associations are worded as
  consistent with a USB device when based on folder tree and/or time overlap.
  Supports `--grouped`, `--format json|table|csv`, and `--output`.
- `report copied-file-drilldown`: source drilldown for a file path, including
  copied indicators, LNK/Jump List rows, ShellBag rows, MFT rows, and USB
  matches.
- `report usb-dossier`: consolidated USB device report by serial, volume serial
  number, or volume GUID. Includes device identity, connection data, volume
  attributes, copied files, file activity, timeline events, and raw evidence.
- `report device-inventory`: broad device inventory from parsed USB/device
  registry evidence, including non-storage categories such as HID and portable
  devices. Storage-specific movement analysis remains in the USB dossier and
  USB file-correlation reports.
- `report case-review`: case-level review summary for copied files, copied USB
  files, USB devices, parser warnings/errors, EVTX recovery, and tool status.
- `report validate`: operator validation view for missing expected tool outputs,
  failed or unfinished jobs, warning/error counts, skipped activity, and EVTX
  recovery status.
- `report tool-runs`: job/run summary with command, start/end time, exit code,
  output count, imported row count, warnings, and errors. Supports
  `--format json|table|csv` and `--output`.
- `report browser`: Chromium-family browser history, downloads, and cookies
  imported from Chrome, Edge, and compatible profiles.
- `report browser-downloads`: enriched Chromium-family downloads with local
  target path, source URL fields, MFT matches for the downloaded target, and
  any USB file-correlation matches.
- `report browser-cache`: URL references recovered by scanning Chromium-family
  and Firefox cache files. Supports `--browser`, `--host`, `--format`, and
  `--output`. This is a cache-reference view, not proof that a page was
  intentionally visited. Use `--exclude-noise` to suppress common adtech,
  tracker, cookie-sync, and redirect hosts.
- `report browser-hosts`: host/domain aggregation across browser history,
  downloads, cache references, and WebCache.
- `report browser-cache-correlations`: groups cache-only references and marks
  whether the same browser/profile/host is corroborated by history or download
  records.
- `report browser-activity`: compact browser summary combining host
  aggregation, downloads, WebCache local file accesses, and cache correlation
  output.
- `report browser-deep-storage`: parsed browser deep-storage inventory for
  sessions, site settings, notifications, sync artefacts, and LevelDB/IndexedDB
  candidates without copying raw browser storage into DuckDB.
- `report srum-context`: contextual SRUM rows for VPN, RDP, cloud sync, and
  browser/network usage. SRUM is approximate telemetry and should be treated as
  supporting context rather than exact process execution timing.
- `report vpn-local-activity`: local endpoint activity on the analysed system
  during VPN-connected windows. Includes parsed application and file-use
  artefacts such as Prefetch, registry activity, SRUM app activity, LNK/Jump
  Lists, browser downloads, WebCache file accesses, and Windows activity
  records. Remote RDP visual/cache observations are intentionally excluded.
- `report webcache`: Windows WebCache/WinINet records from `WebCacheV01.dat`,
  kept separate from browser history because records can come from browsers,
  Windows components, Office, Store/UWP apps, or any application using WinINet.
  Supports `--application`, `--user`, `--local-files-only`,
  `--exclude-metadata`, `--format`, and `--output`.
- `report webcache-files`: derived local `file:///` references from WebCache,
  with associated created/accessed/modified/synced/expiry timestamps when
  present. `--usb-overlap` annotates rows whose file-access timestamp falls
  inside known USB connection windows.
- `report cloud-artifacts`: cloud storage indicators from MFT and WebCache
  local-file activity for OneDrive, Google Drive/DriveFS, Dropbox, and iCloud.
- `report cloud-configuration`: registry-backed cloud account and sync
  configuration, including OneDrive account/sync-engine values, SharePoint/Teams
  URL namespaces and SPO resource IDs, Google DriveFS mount points, Dropbox
  SyncRootManager roots, and iCloud registry context where present.
- `report web-cloud-correlations`: correlates webmail and cloud-storage
  indicators across browser history/downloads, WebCache, LNK/Jump Lists,
  ShellBags, registry artifacts, and cloud sync metadata. Supports provider,
  category, user, and text filters.
- `report messaging-artifacts`: common Electron/WebView2 messaging, note, AI
  assistant, and application-knowledge artifact locations, including Teams,
  Slack, Discord, Signal, WhatsApp, Telegram, Skype, Zoom, Mattermost, ChatGPT,
  Claude, Codex, Obsidian, Notion, OneNote, Adobe Reader, VLC, FileZilla,
  WinSCP, Notepad++, Evernote, Viber, and common remote-access/RMM tools such
  as AnyDesk, TeamViewer, LogMeIn/Rescue, GoTo, ConnectWise Control,
  BeyondTrust/Bomgar, Splashtop, RustDesk, Chrome Remote Desktop, RemotePC,
  Dameware, Atera, NinjaOne, MeshCentral, DWAgent, Parsec, and VNC variants.
  LevelDB files are surfaced as `leveldb_candidate` rows; Markdown notes,
  JSON/config files, SQLite stores, recent-file/config files, URLs, hosts,
  email addresses, timestamps, record types, and dedupe fields are surfaced
  where recoverable. Filter with
  `--application`, `--type`, `--user`, and `--contains`.
- `report event-interpretation`: first-pass event log interpretation for USB,
  Wi-Fi, cloud-related, file-object, and logon events from normalized EVTX rows.
- `report email-artifacts`: email containers from MFT, including PST, OST, MSG,
  EML, MBOX/MBX, and OLM, plus email indicators recovered from Windows Search.
  Rows include a stable dedupe key for subject/context, email, timestamp, and
  path.
- `report mailbox-messages`: parsed message rows from `MailboxParser`, including
  subject, sender, recipients, date, bounded thread/header metadata such as
  `Thread-Index`, references, reply-to, importance/priority, body text/HTML
  hashes and lengths, attachment counts/names, parser status, source format,
  user profile, and dedupe key. If `readpst`
  partially exports messages before failing on PST/OST content, the parser keeps
  recovered messages and adds a `readpst_failed` status row for the container.
  `MailboxParser` also writes `MailboxAttachments.csv` and imports attachment
  metadata into `mailbox_attachments`, including attachment path, size, SHA-256,
  content type, source message conversation metadata, extraction status,
  `exiftool` metadata where available, and
  extracted text for text-like attachments, Office Open XML attachments, and
  PDFs when `pdftotext` is installed. Filter with `--user`, `--status`, and
  `--contains`.
- `report mailbox-attachments`: focused attachment view with filters for user,
  extraction status, content type, SHA-256, and text/metadata content.
- `report timeline`: unified timeline event view with filters for event type,
  source tool, and text contained in descriptions/details.
- `report user-timeline`: combined user-focused timeline across normalized
  artifacts. WebCache expiry events are excluded by default; pass
  `--include-expiry` when those cache expiry timestamps are needed. WebCache
  compatibility/cookie/blob metadata is also suppressed by default; pass
  `--include-metadata` for a rawer timeline.
- `report windows-activities`: Windows 10/11 `ActivitiesCache.db` rows from
  Connected Devices Platform, focused on timestamped `Activity` records by
  default. The parser promotes `displayText`, `file_name`, `contentUri`,
  `activationUri`, and `fallbackUri` into dedicated columns. Use
  `--files-only` to focus on rows with file/document references. Pass
  `--include-auxiliary` to include package mapping and operation tables.
- `report uninstalled-app-artifacts`: generalized leads for artifacts tied to
  applications that are not present in the installed-application inventory.
  Absence from the installed-app registry is a lead, not proof of uninstall.
- `report tor-usage`: Tor Browser indicators across execution and application
  artifact sources, including Prefetch, registry execution artifacts,
  UserAssist, SRUM, and package/browser artifacts.
- `report encrypted-volumes`: first-pass BitLocker, VeraCrypt, TrueCrypt,
  Cryptomator, LUKS, and virtual-disk/container indicators.
- `report phone-link`: Microsoft Phone Link package artifacts, including
  parsed SQLite rows that look like messages, contacts, photos, or calls.
- `report virtualization`: VMware, VirtualBox, Hyper-V, QEMU, Parallels, and
  related VM/container filename indicators.
- `report file-names`: filename-first grouping across shortcuts, copied-file
  indicators, Windows Activities, browser downloads, WebCache local file
  accesses, Windows Search files/content, file metadata, and USN Journal rows.
  Pass `--include-mft` when you also want all MFT filenames in the grouping.
- `report file-name-drilldown`: source-by-source evidence rows for a single
  filename, including normalized path keys and explicit evidence tags such as
  `activity_cache_present`, `browser_download_present`, `indexed_content_present`,
  `usn_change_present`, and `copied_timestamp_pattern`.
- `report file-history`: chronological history for a filename, path, or MFT
  entry. It combines `filesystem_review` rows from MFT, USN, `$LogFile`, `$I30`,
  and namespace reconciliation with user artifact references unless
  `--filesystem-only` is used.
- `report correlations`: file correlation links between user activity artifacts and MFT entries.
- `report artifact-correlations`: broader non-MFT cross-source correlations.
- `report artifact-summary`: artifact and output counts.
- `report mft`, `report usn`, `report ntfs-namespace`, `report srum`, `report prefetch`, `report evtx`: focused normalized table views.
- `report cd-burning`: CD/DVD burning activity indicators from existing MFT, USN Journal, and NTFS `$LogFile` rows, including Windows burn staging paths and DAT/FIL/POST temp-file patterns.
- `report usn-summary`, `report usn-path`, `report usn-user`,
  `report usn-reasons`, `report usn-timeline`, and `report usn-suspicious`:
  investigator-focused USNJRNL views for counts, path/user/reason filters,
  chronological change activity, and a first-pass suspicious-change triage with
  common cache noise suppressed.
- `report usn-user-files`: conservative, rule-based candidate view. It reports
  matched and suppressed rule names from `forensic_orchestrator/plugins/usn_rules.yaml`
  and uses `candidate_user_file_activity` wording rather than asserting user
  intent.
- `report usn-renames`, `report usn-bursts`, and `report usn-usb-candidates`:
  reconstruct RenameOldName/RenameNewName pairs, group high-volume change
  bursts, and cross-reference USN rows with existing USB file correlations.
- `report filesystem-review`: combined filesystem metadata review across MFT,
  USN, `$LogFile`, `$I30`, and namespace reconciliation rows. Supports
  `--contains`, `--event-type`, `--status`, and `--source-table`.
- `report windows-search --type files|internet|activity|emails|content|properties`: SIDR Windows Search rows split into focused tables. `content` contains indexed text recovered for any indexed item, not just email. `properties` records every raw SIDR property/value pair, including normalized names for SIDR extra fields such as size, owner, computer name, and indexed content.
- `report file-metadata`: embedded/internal file metadata extracted with `exiftool`.
- `report evtx-recovery`: per-log EVTX copy, partial extraction, salvage, recovered event count, and parser error details.
- `report recycle`: top-level Recycle Bin entries with child counts.
- `report deleted-folders`: deleted Recycle Bin folders with child item counts.
- `report firefox`: Firefox browser history rows.
- `report registry`: registry hive inventory rows.
- `report registry-artifacts`: targeted registry artifact rows, optionally filtered by `--artifact` and `--user`.
- `report registry-activity`: normalized RECmd activity rows from split tables such as `recentdocs`, `runmru`, `typedpaths`, `wordwheel`, `userassist`, `office-mru`, `common-dialog`, and `trusted-documents`.
- `report amcache`, `report shimcache`, `report shellbags`: focused views over dedicated EZ parser output imported into normalized SQLite tables.
- `report usb`: summarized USB storage devices. Use `report usb --raw` for the
  underlying evidence rows, or `report usb --breakdown` to explain raw row counts.
- `report usb-files`: USB device to file artifact correlation by volume serial.
  Supports `--grouped`, `--format json`, `--format table`, and
  `--format csv --output <path>`.
- `report usb-timeline`: USB connection/removal and correlated file timestamp
  timeline. When Partition Diagnostic or USB registry connection events are
  available, ShellBag time-overlap association uses those discrete session
  windows instead of the broader first-seen/last-seen device summary.
- `report export`: CSV export presets for `usb-summary`,
  `usb-file-correlations`, and `usb-timeline`.
- `report shortcuts`: normalized LNK and Jump List rows from `shortcut_items`.

All subprocess execution uses argument arrays, not shell-interpolated strings.

## File Correlation

After normalized rows are imported, the orchestrator rebuilds file correlations
for that image:

- LNK and Jump List target paths are matched to `mft_entries` by normalized path.
- Prefetch referenced strings are matched to `mft_entries` by normalized path.
- If Prefetch only has an executable name, it can fall back to a lower-confidence filename match.

Correlation rows include match type, confidence, source artifact row, and target
MFT row. This keeps path matching explicit and auditable instead of hiding it in
report logic.

## Recycle Bin

The built-in `RecycleParser` extracts and parses:

- XP-style `RECYCLER` and `Recycled` roots.
- XP `INFO2` original path/deletion metadata where available.
- Vista+ `$Recycle.Bin` roots.
- Modern `$I` metadata where available.
- `$R`/`Dc` deleted item content recursively.

This intentionally improves on top-level-only Recycle Bin views by recording
files inside deleted folders in `recycle_children`.

## Firefox

The built-in `FirefoxParser` extracts `places.sqlite` and `cookies.sqlite`
from profiles anywhere in the image, then writes normalized history and cookie
CSV outputs before importing high-value fields into SQLite.

## Chromium Browsers

The built-in `ChromiumParser` extracts Chrome, Edge, and compatible Chromium
`History` and `Cookies` SQLite databases under user profiles. It writes
`BrowserHistory.csv`, `BrowserDownloads.csv`, and `BrowserCookies.csv`, then
imports those rows into dedicated SQLite tables and the unified timeline.
`BrowserCacheParser` scans Chromium cache, code cache, GPU/media cache, service
worker cache, and Firefox `cache2`/startup cache files for embedded HTTP/HTTPS
URL references, writing them to `browser_cache_entries`.
Use the `windows-browsers` profile to run Firefox, Chromium, and WebCache
parsing together. It also includes browser cache URL reference extraction and
Windows Activities parsing:

```bash
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-browsers
```

Use `windows-activities` when you only want Windows Activities:

```bash
forensic-orchestrator --root /tmp/fo run --case CASE_ID --image IMAGE_ID --profile windows-activities
```

## WebCache

The built-in `WebCacheParser` extracts `WebCache*.dat` files under user
profiles. It uses `esedbexport` when a raw ESE database is present, writes
`WebCacheEntries.csv`, imports rows into `webcache_entries`, and adds created,
accessed, modified, synced, and expiry timestamps to the unified timeline when
present. WebCache is intentionally reported separately from browser history
because it can include browser activity and non-browser application web activity.
Local `file:///` references are additionally copied into `webcache_file_accesses`
and reported with `report webcache-files`. Rows include conservative
application attribution fields: `user_name`, `application`,
`application_package`, `container_directory`, and `attribution_method`.

## OpenSearch Content Index

SQLite remains the forensic system of record for normalized metadata.
OpenSearch is the required destination for large derived text: email bodies,
email attachment text, Windows Search indexed content, chat/message bodies,
note bodies, AI assistant conversation text, and future OCR text. These
documents are indexed during ingest; SQLite stores only source references,
hashes, lengths, provenance, and OpenSearch document IDs.

Start a local OpenSearch instance before running parsers that produce large
text. Content is indexed during ingest; there is no DB-to-OpenSearch reindex
path for new cases.

Query the index:

```bash
forensic-orchestrator --root /tmp/fo search query \
  --case CASE_ID \
  --url http://localhost:9200 \
  --index forensic-content \
  --query "megaforce" \
  --format table
```

Every indexing run is recorded in SQLite in `search_index_runs`, including the
backend URL, index name, backend version, document counts by source type, start
and end times, status, and any error. Review those records with:

```bash
forensic-orchestrator --root /tmp/fo report search-index-runs \
  --case CASE_ID \
  --format table
```

Search results include `source_table` and `source_record_id`. Use those for a
SQLite drilldown back to the record, related message copies, and attachments:

```bash
forensic-orchestrator --root /tmp/fo search show \
  --case CASE_ID \
  --source-table mailbox_attachments \
  --source-id ROW_ID
```

Query-time synonym expansion is explicit and auditable. Defaults include small
groups such as `communications, communication, comms`; returned JSON includes
the expansions applied. Disable it with `--no-synonyms`, or provide a custom
comma-separated synonym file with `--synonyms`.

RDP bitmap cache and generic image-analysis reports:

```bash
forensic-orchestrator --root /tmp/fo report rdp-cache --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report rdp-visual-observations --case CASE_ID --format table
forensic-orchestrator --root /tmp/fo report image-analysis --case CASE_ID --source-artifact-type rdp_bitmap_cache --format table
```

Remote access correlation ties RDP client events to nearby VPN activity and RDP
bitmap cache file writes. When visual observations have been recorded from RDP
contact sheets, they are included as corroborating screen evidence rather than
execution proof:

```bash
forensic-orchestrator --root /tmp/fo report remote-access --case CASE_ID --format table
```

For authenticated clusters, use `--username` and `--password`, or set
`FORENSIC_OPENSEARCH_URL`, `FORENSIC_OPENSEARCH_INDEX`,
`FORENSIC_OPENSEARCH_USERNAME`, and `FORENSIC_OPENSEARCH_PASSWORD`. For local
test clusters with self-signed TLS, pass `--insecure`.

## Safety Notes

- Source evidence is never modified.
- Direct E01 processing is preferred when the local Sleuth Kit build supports EWF.
- E01 fallback uses `ewfmount -X allow_other`; the exposed raw image is expected at `mounts/ewf/ewf1`.
- NTFS volume images are detected with `fsstat`; partition offsets are discovered with `mmls`.
- Encrypted filesystem indicators stop processing before filesystem mounting or tool execution.
- Files are extracted read-only with Sleuth Kit `fls` and `icat`.
- Optional filesystem mounts invoke `ntfs-3g` directly with read-only options.
- Dry-run records jobs and writes command previews, but does not execute mounts or tools.

## Passwordless Sudo for Mounts

The CLI uses `sudo -n` only when `image mount --filesystem --sudo` or
`image unmount --sudo` is passed. `ewfmount` itself is run without sudo and
requires the FUSE `user_allow_other` setting above. Configure a narrow sudoers
rule for the worker user and workspace root. Replace `lee` and `/tmp/fo` with
your worker user and root path.

Check command paths first:

```bash
command -v mount
command -v umount
```

Create the rule with `visudo`:

```bash
sudo visudo -f /etc/sudoers.d/forensic-orchestrator
```

Example rule:

```text
lee ALL=(root) NOPASSWD: /usr/bin/ntfs-3g -o ro\,show_sys_files\,streams_interface=windows\,norecover\,offset=* /tmp/fo/cases/*/mounts/ewf/ewf1 /tmp/fo/cases/*/mounts/volumes/*, /usr/bin/umount /tmp/fo/cases/*/mounts/volumes/*
```

The application still validates and records the exact subprocess array it runs.
Do not grant broad passwordless access to arbitrary `mount` commands.

## Tests

```bash
pytest
```
