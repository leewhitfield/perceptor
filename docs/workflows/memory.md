# Memory and Support Files

Relic treats memory artifacts as part of the same case model as disk artifacts.
Memory-derived findings should be reported alongside disk-derived counterparts
when possible.

## Inputs

Supported memory-adjacent inputs include:

- full memory images.
- pagefile.
- swapfile.
- hiberfil.
- crash dumps.
- extracted process dumps.
- memory-derived registry hives or secrets, when available.

## Processing Goals

Memory workflows aim to:

- inventory memory sources.
- extract strings and indicators.
- correlate memory artifacts to disk artifacts.
- identify suspicious execution or user activity.
- document unsupported or failed decompression gracefully.
- avoid treating failed hiberfil decompression as an application crash.

## Processing Workflow

Run the memory workflow after image mounting and artifact extraction:

```bash
uv run relic --root /path/to/workspace memory workflow \
  --case CASE_ID \
  --workers 4 \
  --write-reports
```

Relic inventories memory-adjacent artifacts from mounted volumes and MFT output,
including `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`, `MEMORY.DMP`,
Minidumps, WER dumps, LiveKernelReports, user CrashDumps, process dumps, and
full memory images such as `.raw`, `.vmem`, and `.mem`.

For each source, Relic:

- scans targeted strings with `bstrings` when available, otherwise `strings`.
- attempts hiberfil decompression with configured hiberfil tooling before raw
  scanning.
- records hiberfil assessment status, decompression status, decompression
  command, source size, scanned size, and any decompression caveat.
- extracts inaccessible MFT-listed support files with `icat` when possible.
- records the exact fallback extraction command in activity logs and support
  file reports.
- ingests memory string hits into `memory_string_hits` and the timeline as lead
  evidence.

Hiberfil decompression is best-effort. Unsupported, inactive, zeroed, or failed
hiberfil files are reported as caveats and do not stop the processing run.

## Tool Paths

Preferred tools can be placed on `PATH` or configured explicitly:

```bash
export BSTRINGS_BIN=/opt/relic-tools/bstrings/bstrings.dll
export HIBR2BIN_BIN=/opt/relic-tools/Hibr2Bin-linux/hibr2bin-linux
export FORENSIC_ORCHESTRATOR_TOOLS_ROOT=/opt/relic-tools
```

Relic also checks common tool-root layouts under
`FORENSIC_ORCHESTRATOR_TOOLS_ROOT`, `/opt/relic-tools`, and `~/tools`.

## Fallback Extraction

When a memory support file is present in MFT data but not accessible through the
mounted filesystem, Relic attempts a targeted NTFS `icat` extraction using the
stored image partition offset:

```bash
icat -f ntfs -o OFFSET_SECTORS /path/to/image ENTRY_NUMBER
```

`OFFSET_SECTORS` is derived from the mounted partition byte offset divided by
512. The full command is retained in the activity log and
`report memory-support-files`.

## Reports

```bash
uv run relic --root /path/to/workspace report memory-analysis --case CASE_ID --format md
uv run relic --root /path/to/workspace report memory-artifacts --case CASE_ID --format md
uv run relic --root /path/to/workspace report memory-support-files --case CASE_ID --format md
uv run relic --root /path/to/workspace report structured-memory --case CASE_ID --format md
uv run relic --root /path/to/workspace report memory-string-hits --case CASE_ID --format csv
```

Run structured tooling against a full memory image or decompressed hiberfil
candidate with:

```bash
uv run relic --root /path/to/workspace memory structured \
  --case CASE_ID \
  --path /path/to/memory.dmp
```

Relic records Volatility and MemProcFS run attempts even when a tool cannot
derive structured rows from a dump. `report structured-memory` shows both
imported rows and tool-level failures or no-row results.

The managed installer downloads the official Volatility Windows symbol pack to
`/opt/relic-tools/volatility3-symbols/windows.zip`. Symbols help future Intel
Windows memory cases, but they do not guarantee support for Windows ARM64 dumps;
those may still fail because the memory layer/architecture is unsupported by
the current Volatility release.

Memory report bundles use purpose `memory`:

```bash
uv run relic --root /path/to/workspace report bundle \
  --case CASE_ID \
  --purpose memory
```

## Windows Search Note

Testing did not identify a reliable offline SIDR option for decrypting Windows
11 `AesGcm1` encrypted Search databases. If full Search content is required,
collect live memory while the user is logged in and SearchIndexer.exe is running,
and preserve registry hives and DPAPI/LSA material.
