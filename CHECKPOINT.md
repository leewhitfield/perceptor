# Investigator Checkpoint - 2026-05-19

## Current State

This workspace is not currently a git repository, so this checkpoint records the current progress in the project tree.

The application has evolved from the original CLI-first E01 processing MVP into a broader forensic orchestration prototype with:

- E01 handling through `ewfmount`
- read-only NTFS mounting
- Sleuth Kit fallback extraction
- EZ tool orchestration
- normalized DuckDB ingestion for parsed artifact families
- SQLite orchestration metadata for cases, images, jobs, tool outputs, activity logs, content references, and search index runs
- OpenSearch indexing for searchable content
- case/job/activity logging
- USB, cloud, browser, registry, email, filesystem, and session correlation reports

The previous active ROCBA case database was under `/tmp` and was not present after the VM/disk upgrade. The new SSD-backed workspace root is:

```text
/mnt/forensic-ssd/forensic-orchestrator-rocba-case
```

The current SSD-backed orchestration database is:

```text
/mnt/forensic-ssd/forensic-orchestrator-rocba-case/orchestrator.sqlite3
```

The previous ROCBA case database was:

```text
/tmp/forensic-orchestrator-rocba-case/orchestrator.sqlite3
```

The current SSD-backed case ID is:

```text
292bcc9d-e60b-4260-9cae-3078df55889b
```

The previous ROCBA case ID was:

```text
91c575ca-739a-4d59-a52a-66480b1f9ca7
```

The previous ROCBA image ID was:

```text
d204842b-166c-4822-94be-a5ae479c6916
```

The current ROCBA image path is:

```text
/mnt/forensic-ssd/evidence/rocba/rocba-cdrive.e01
```

The current ROCBA image ID is:

```text
2b1fdb43-1ae6-45c2-9b21-9c920ea784f9
```

The image was validated with `ewfinfo`:

- Description: `rocba-cdrivev6`
- EnCase 1 E01
- Media size: 81 GiB / 87,431,311,360 bytes
- MD5: `5efc207c85587683e5ca5fa2d5ef1aa4`
- SHA1: `645dcd29ab039359fbdb6643961478b3d914f21d`

It was mounted/prepared in direct Sleuth Kit mode as an NTFS volume image without a partition table:

```text
partition_id: volume-ntfs
source_type: direct-e01-volume
offset_bytes: 0
```

### ROCBA Mounting Note

The old sudoers/NOPASSWD mount allowance is hardcoded to `/tmp` paths:

```text
/usr/bin/ewfmount /tmp/rocba-cdrive.e01 /tmp/forensic-orchestrator-rocba-case/cases/*/mounts/ewf
/usr/bin/ntfs-3g -o ro,show_sys_files,streams_interface=windows,norecover,offset=* /tmp/forensic-orchestrator-rocba-case/cases/*/mounts/ewf/ewf1 /tmp/forensic-orchestrator-rocba-case/cases/*/mounts/volumes/*
/usr/bin/umount /tmp/forensic-orchestrator-rocba-case/cases/*/mounts/volumes/*
/usr/bin/umount /tmp/forensic-orchestrator-rocba-case/cases/*/mounts/ewf
```

Because durable case data now lives on `/mnt/forensic-ssd`, use `/tmp` only as symlinked command-path compatibility for this sudoers rule:

```bash
ln -s /mnt/forensic-ssd/forensic-orchestrator-rocba-case /tmp/forensic-orchestrator-rocba-case
```

Do not store evidence, databases, artifacts, or parser output under `/tmp`.

The EWF layer can be mounted as the normal user:

```bash
ewfmount -X allow_other \
  /mnt/forensic-ssd/evidence/rocba/rocba-cdrive.e01 \
  /mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/ewf
```

The NTFS layer currently uses the old sudoers command path through the `/tmp` symlink:

```bash
sudo -n /usr/bin/ntfs-3g -o ro,show_sys_files,streams_interface=windows,norecover,offset=0 \
  /tmp/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/ewf/ewf1 \
  /tmp/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/volumes/volume-ntfs
```

This resolves to the real SSD-backed mount target:

```text
/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/volumes/volume-ntfs
```

The earlier interrupted `windows-full` run did **not** have an active NTFS mount and fell back to direct recursive TSK inventory. That produced duplicate 89 MB `fls` listings and was stopped. The code now refuses broad recursive TSK inventory by default; set `FORENSIC_ALLOW_RECURSIVE_TSK_INVENTORY=1` only when intentionally using that fallback.

The new case has an active analytics area for DuckDB-backed parsed artifact rows:

```text
/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/analytics/
/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/analytics/events.duckdb
/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/analytics/parquet/
```

## Most Recent Changes

### Durable Process Timing

Profile execution now records durable timing rows in SQLite table `process_timings`.
This is intended for UI progress/timing views and post-run audit reports.

Timed scopes currently include:

- `profile` rows for the overall profile pass and scoped Windows.old child pass.
- `artifact/extract` rows for each artifact extraction step, with bounded metadata such as extraction method, output path, file count, and byte count.
- `tool/parse` rows for each parser/tool invocation.
- `postprocess/rebuild` rows for correlation, dedupe, session, and reference rebuild steps.

Each row records `start_time`, `end_time`, `duration_ms`, `status`, optional parent timing, tool/artifact names, and bounded `details_json`. This is orchestration metadata only; it does not store parsed artifact bodies, raw content, binary data, or unbounded parser output.

The current report command is:

```bash
forensic-orchestrator --root /mnt/forensic-ssd/forensic-orchestrator-rocba-case \
  report process-timings \
  --case 292bcc9d-e60b-4260-9cae-3078df55889b \
  --format md \
  --output /mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/reports/windows-full-process-timings-2026-05-20.md
```

Latest ROCBA timed `windows-full` run on 2026-05-20:

- Command: `windows-full --replace-existing --include-deleted-mft --include-live-orphans`
- Main profile start/end: `2026-05-20T16:09:42.991526+00:00` to `2026-05-20T16:41:18.084666+00:00`
- Main profile duration: `1895.093` seconds
- Windows.old child pass duration: `697.731` seconds
- Completed timing rows: `133` artifact extractions, `88` parser/tool steps, `14` postprocess rebuilds, `2` profile rows
- Failed scoped Windows.old parser rows: `WindowsSearchESEParser` and `AmcacheParser`; Windows.old mode continued by design and logged warnings/errors in `activity_log`.
- Timing report: `/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/reports/windows-full-process-timings-2026-05-20.md`

Longest recorded steps in that run:

- Windows.old `EvtxECmd`: `448.084` seconds
- Main `EvtxECmd`: `370.392` seconds
- Main `OneDriveOdlParser`: `208.386` seconds
- Windows.old `EtlParser`: `102.370` seconds
- Main `MFTECmd`: `62.671` seconds
- Main `cloud_sqlite_candidates` extraction: `61.729` seconds

### DuckDB Parsed Artifact Storage Boundary

The default storage boundary has been corrected:

- SQLite is for orchestration metadata only: cases, images, mounts, artifacts, jobs, tool outputs, activity logs, content references, and search index runs.
- DuckDB is the default store for normalized parsed artifact rows, including MFT, USN, EVTX, SRUM, registry artifacts, browser artifacts, mail/message metadata, Windows Search, and timeline events.
- OpenSearch remains limited to actual searchable body/content text, such as email bodies, message bodies, attachments/file text, and Windows Search indexed content.
- `FORENSIC_ANALYTICS_MODE` now defaults to `duckdb`.
- `FORENSIC_ANALYTICS_MODE=sqlite` is retained for legacy/debug compatibility.
- `FORENSIC_ANALYTICS_MODE=mirror` writes both stores for transition checks.

The timed ROCBA `windows-full` attempts on 2026-05-19 exposed the previous issue:
DuckDB was essentially empty while SQLite held high-volume parsed rows. The
report is:

```text
/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/reports/20260519T200137Z-windows-full-timing-report.md
```

Both timed attempts failed at `OfficeBackstageParser`. Fixes now applied:

- mounted-path walk errors are skipped with `os.walk(..., onerror=...)`
- malformed URL text no longer raises `Invalid IPv6 URL`; host is left blank

Validation after the storage-boundary fix:

```text
uv run pytest -q
235 passed
```

Follow-up verification on 2026-05-19:

- `windows-fast-triage` completed successfully for ROCBA with run ID `20260519T212300Z-windows-fast-triage-duckdb-bulk`.
- Elapsed time: `5:18.94`.
- All 23 profile tools exited `0`.
- SQLite stayed orchestration-only for this case after cleanup: parsed/materialized artifact rows in SQLite are `0`.
- SQLite was vacuumed from `7.2G` down to `18M` after deleting stale pre-DuckDB analytics rows and stale `filesystem_review` materialization.
- DuckDB now holds the parsed fast-triage rows, including the small Firefox and Recycle outputs that previously bypassed analytics routing.
- Key DuckDB row counts: `mft_entries=602,367`, `registry_artifacts=97,621`, `srum_records=146,646`, `office_backstage_items=28,506`, `webcache_entries=22,171`, `timeline_events=42,651`.

Additional fixes applied during the verification:

- DuckDB analytics inserts now bulk-load each flush through a registered DataFrame instead of slow `executemany()` row insertion.
- Mounted relative-path calculations now use a string-prefix fast path instead of repeated `Path.relative_to()` work for every mounted item.
- `UserDictionaryParser`, `ZoneIdentifierParser`, `ThumbcacheParser`, and `WebCacheParser` now tolerate mounted filesystem walk/read errors and skip unreadable paths.
- `purge_tool_data()` now also purges DuckDB `timeline_events`.
- Tool-scoped `--replace-existing` now deletes DuckDB rows by tool instead of
  deleting every normalized DuckDB table when a tool is not listed in a narrow
  purge map.
- `filesystem_review` is no longer rebuilt as a durable SQLite materialization in DuckDB mode; the source facts already live in DuckDB tables such as `mft_entries`.
- Legacy Firefox and Recycle insert helpers now route through the generic DuckDB analytics path.
- MFT-selected artifact extraction now runs just-in-time before its parser, after
  preceding tools such as `MFTECmd` have populated DuckDB. This fixes mailbox
  and ADS extraction during `windows-full --replace-existing`.
- `MailboxParser` selected `7` PST/OST containers from MFT and imported `1,072`
  mailbox message/status rows plus `234` attachment rows. DuckDB currently has
  `1,372` `mailbox_messages` rows after combining mailbox and Windows Mail
  imports.
- `ZoneIdentifierParser` selected `29` Zone.Identifier ADS rows from MFT and
  imported them into DuckDB.
- `MFTECmdI30` now falls back to parent directories of deleted MFT file records
  when no skipped-live-orphan log entries exist. ROCBA currently has `7,451`
  `ntfs_index_entries` rows and `85` `ntfs_index_bitmaps` rows.
- `RdpCacheParser` auto-discovers the repo-local
  `.external/bmc-tools/bmc-tools.py` when `BMC_TOOLS` is not set. ROCBA RDP
  cache rows are restored: `38,607` RDP cache rows, `38,601` image-analysis
  rows, and `9` visual-observation rows in DuckDB.
- `report artifact-completeness` now counts DuckDB tables instead of only
  SQLite tables. On ROCBA it reports all expected artifact families parsed except
  `SUM / User Access Logging`, which is expected for this image.
- Broad `FileMetadataExtractor` is no longer part of `windows-full` or
  `windows-old`; embedded per-file metadata remains available through the
  targeted `file-metadata-*` profiles.

RDP cache follow-up on 2026-05-19:

- `windows-full` now includes `RdpCacheParser`, `RdpVisionReview`, and `TelemetryParser`; a registry test asserts the current full artifact set is present.
- `RdpCacheParser --replace-existing` is scoped to RDP cache/image-analysis/visual-observation outputs, preventing a repeat of the earlier broad purge that removed unrelated DuckDB analytics rows.
- RDP cache, image-analysis, and visual-observation reports now read DuckDB first and only fall back to SQLite for old/debug cases.
- Report-mode DuckDB reads now use read-only connections unless the process already has an analytics connection open, avoiding unnecessary writer locks during report generation.
- `RdpCacheParser` now emits `RdpVisualObservations.csv` as part of normal parsing, so `windows-full` produces visual-observation rows automatically through its `RdpCacheParser` step. These rows record contact-sheet availability and timing, and they attempt contact-sheet OCR with Tesseract when available. OCR text is stored as a bounded excerpt with status/length/hash metadata, not as unbounded text.
- `RdpVisionReview` is a separate follow-on stage. It uses `OPENAI_API_KEY` with the OpenAI Responses API as the primary semantic reviewer for RDP contact sheets and falls back to existing Tesseract OCR observations when OpenAI is unavailable or fails. DuckDB stores bounded observations, hashes, caveats, and provider metadata only; raw contact sheets remain on disk and full model JSON is not stored.
- ROCBA RDP cache was re-run with bundled BMC Tools under `/mnt/forensic-ssd`: `38,607` RDP cache rows, `38,601` RDP image-analysis rows, and `3` RDP visual-observation rows are in DuckDB; SQLite has `0` rows for those parsed tables.
- Tesseract was installed after the first OCR attempt. The maintained dependency list is now `docs/dependencies.md`; rerun `windows-rdp-cache --replace-existing` or `windows-full --replace-existing` after dependency changes to refresh OCR text observations.
- The earlier broad purge removed the ROCBA EVTX rows from analytics. The existing EvtxECmd CSV on SSD was re-ingested into DuckDB: `1,269,229` rows in `2:26.18`; SQLite has `0` EVTX parsed rows.
- The ROCBA remote-access report is restored: `4` RDP sessions, all with VPN overlap, RDP bitmap-cache overlap, and contact-sheet visual-observation overlap.

Full-profile audit on 2026-05-19:

- `windows-full` completed successfully for ROCBA with run ID `20260519T221400Z-windows-full-duckdb-audit`.
- Elapsed time: `18:48.58`.
- Exit status: `0`.
- Timing/storage report:
  `/mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/reports/20260519T221400Z-windows-full-duckdb-audit-timing-storage-report.md`
- SQLite after the run and stale-reference cleanup: `13M`; DuckDB after the run: `918M`.
- SQLite analytics/materialized artifact rows checked: `0`, including `filesystem_review`.
- Stale `content_references` from interrupted/replaced runs were pruned; current references are `5,250`, all tied to existing `tool_outputs`.
- DuckDB largest row counts included `onedrive_log_entries=1,497,224`, `timeline_events=1,387,537`, `evtx_events=1,269,229`, `mft_entries=602,367`, `windows_search_properties=576,857`, and `usn_journal_entries=383,915`.
- The first full audit attempt stopped at `RBCmd` because `RBCmd` is a disabled Recycle Bin tool with no command configured but was still listed in `windows-full`. It was removed from the profile; Recycle Bin data is covered by `RecycleParser`.

### Chromium / Browser Parsing

Enhanced Chromium parsing based on `/tmp/chrome_screens` and `/tmp/references`:

- Bookmarks, `Bookmarks.bak`, `Bookmarks.msbak`
- Web Data autofill variants
- Shortcuts / omnibox shortcuts
- Network Action Predictor
- Top Sites
- Login Data metadata only, without decrypted passwords
- Preferences/site settings-related activity
- Session recovery URLs
- Extension metadata

The broad `LevelDB` artifact pattern was removed from Chromium profile collection because it was too expensive on mounted evidence. Targeted Sync Data collection remains.

Validated `browser-chromium --replace-existing` against ROCBA after optimizing purge behavior.

### DeviceMigration USB Registry Keys

DeviceMigration parsing now captures:

- VID
- PID
- serial / instance ID
- `ParentIdPrefix`
- `Service`
- `LastPresentDate`

New normalized columns:

- `usb_devices.last_present_date_utc`
- `usb_storage_devices.last_migration_present_utc`

DeviceMigration parsing was tightened to the actual root:

```text
SYSTEM\Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration\Devices
```

Embedded duplicate paths under plugin-style keys, such as `ActivationBroker/.../ROOT/Setup/...`, are filtered out.

Current ROCBA backfill after filtering:

- 736 registry rows observed
- 367 accepted DeviceMigration rows
- 9 USB storage summaries rebuilt
- 150 USB connection events rebuilt

### Operational Reports

Added these CLI reports:

```bash
uv run forensic-orchestrator --root /tmp/forensic-orchestrator-rocba-case report operation-manifest \
  --case 91c575ca-739a-4d59-a52a-66480b1f9ca7

uv run forensic-orchestrator --root /tmp/forensic-orchestrator-rocba-case report db-storage \
  --case 91c575ca-739a-4d59-a52a-66480b1f9ca7

uv run forensic-orchestrator --root /tmp/forensic-orchestrator-rocba-case report cleanup-candidates \
  --case 91c575ca-739a-4d59-a52a-66480b1f9ca7
```

`db-storage --include-object-sizes` is available, but it should be used carefully. It invokes SQLite `dbstat`, which was too slow as a default on the 19 GB ROCBA database.

## Current ROCBA DB Findings

Database size:

```text
~19 GB
page_count: 4,825,929
page_size: 4096
freelist_pages: 2,099
freelist_bytes: ~8.6 MB
```

This means there is little ordinary SQLite free-page waste. The database size is mostly real rows and indexes.

Largest row-count tables observed:

- `timeline_events`: 3,173,547
- `evtx_events`: 2,755,787
- `onedrive_log_entries`: 1,497,224
- `filesystem_review`: 1,131,933
- `file_internal_metadata`: 647,462
- `mft_entries`: 602,367
- `windows_search_properties`: 579,099
- `usn_journal_entries`: 383,915
- `etl_events`: 298,561
- `copied_file_indicators`: 205,203

Cleanup candidates identified:

- Duplicate tool outputs for `CloudSyncParser`, `OneDriveExplorer`, `SBECmd`, `SrumParser`
- `parsed_rows`: 10,080 rows, mostly `EvtxECmdTriage` and `PackageCacheParser`
- Content-heavy text in SQLite exists, but is not the main cause of DB size in this dataset:
  - mailbox bodies: about 25 MB
  - Windows Search indexed content: about 1.7 MB
  - attachment extracted text: small in this case

## Validation

Recent focused test runs passed:

```text
35 passed
32 passed
```

Key covered areas:

- Chromium parser
- Tool registry
- DeviceMigration registry filtering
- USB normalization
- purge/replace behavior

## Architecture Notes

For the MVP, Python and SQLite have been useful and appropriate. The current workload is now pushing beyond where a single SQLite database is comfortable:

- millions of EVTX/timeline/OneDrive/filesystem rows
- repeated rebuilds
- derived correlation tables
- large joins
- single-writer SQLite behavior
- VM with 8 GB RAM and limited CPU

Recommended next storage split:

- Keep SQLite for case metadata, jobs, provenance, summaries, dedupe keys, and report-ready facts.
- Move high-volume append-only analytical tables to DuckDB or Parquet:
  - `evtx_events`
  - `timeline_events`
  - `onedrive_log_entries`
  - `filesystem_review`
  - `windows_search_properties`
  - `file_internal_metadata`
- Keep OpenSearch for large searchable content:
  - email body text
  - attachments
  - indexed content
  - messaging text
  - future OCR text
- Keep Python for orchestration.
- Consider Rust for hot parsers/importers later:
  - EVTX
  - ETL
  - registry hive walking
  - CSV normalization
  - timeline/correlation rebuilds

Recommended VM upgrade:

- Move case root and SQLite DB to NVMe.
- Increase RAM to at least 32 GB; 64 GB is preferable for larger images.
- More cores will help concurrent parsing, compression/decompression, external tools, and indexing.

## Next Suggested Work

1. Add a storage migration layer for DuckDB/Parquet-backed high-volume tables.
2. Add a cleanup command that can prune redundant `parsed_rows` and duplicate normalized rows safely.
3. Add incremental rebuilds for timeline/correlation tables instead of full rebuilds.
4. Add DB/table index review after moving to NVMe.
5. Continue artifact work after the VM upgrade stabilizes performance.

Future additions bucket:

- Event-log detection enrichment: keep `EvtxECmd` as the canonical parser for
  normalized `evtx_events`. Consider adding Hayabusa later as a derived
  detection/timeline pass only, storing compact rule hits and references back to
  `evtx_events` rather than duplicating raw event-log content. Chainsaw remains
  a possible optional hunt/search tool, not a primary event-log ingestion path.

## Report Plugins

Added a read-only report spec mechanism so custom reports can be contributed by
plugins without editing `reports.py`.

- Built-in specs: `forensic_orchestrator/plugins/report_specs/*.yaml`
- Plugin YAML: embed a top-level `reports` list in any file passed with `--plugin`
- Plugin sidecar dirs: place YAML specs under `report_specs/` beside a plugin file
- Extra spec directories: `FORENSIC_REPORT_SPEC_DIRS`
- CLI list: `forensic-orchestrator --root <case-root> report specs`
- CLI run: `forensic-orchestrator --root <case-root> report spec --case <case-id> --name <spec-name>`
- Spec documentation: `docs/report-specs.md`

Storage boundary still applies to report specs: DuckDB stores parsed artifact
fields and references; OpenSearch stores body/content text; SQLite stores
orchestration and provenance metadata.
