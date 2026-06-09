# Third-Party Tools

Perceptor combines internal parsers with established forensic and data-processing
tools. This page lists the third-party tools and services Perceptor expects or
can use during normal Windows processing.

Use the dependency and doctor commands to check local coverage:

```bash
uv run perceptor standalone dependencies --format table
uv run perceptor standalone doctor --smoke --format table
uv run perceptor standalone tool-status --tools-dir ~/tools --format table
```

## System Packages

These are installed through Ubuntu package management during setup.

### Sleuth Kit

Commands: `mmls`, `fsstat`, `fls`, `icat`

Used for partition discovery, filesystem inspection, and fallback file
extraction when a mounted read-only volume is not available or a targeted
filesystem operation is required.

### libewf / ewf-tools

Commands: `ewfinfo`, `ewfmount`

Used for EWF/E01 metadata inspection and read-only EWF mounting.

### qemu-utils

Command: `qemu-img`

Used for virtual disk inspection and conversion support.

### ntfs-3g

Command: `ntfs-3g`

Used for read-only NTFS mounts.

### util-linux

Commands include `losetup`, `mount`, `umount`, and related system utilities.

Used for loop-device and mount workflow support.

### cryptsetup

Command: `cryptsetup`

Primary BitLocker unlock path where supported by the local system.

### dislocker

Command: `dislocker`

BitLocker fallback unlock tool.

### libbde-utils

Command: `bdemount`

BitLocker fallback unlock tool.

### libesedb-utils

Command: `esedbexport`

Used as an ESE database export fallback for artifacts such as SRUM, BITS, and
other Windows ESE stores.

### ExifTool

Command: `exiftool`

Used for embedded file metadata extraction.

### poppler-utils

Command: `pdftotext`

Used for fast PDF text extraction. Perceptor can fall back to Python PDF
parsing when this is unavailable.

### Tesseract OCR

Command: `tesseract`

Used for OCR extraction where text is embedded in images or visual artifacts.

### libvshadow-utils

Commands: `vshadowinfo`, `vshadowmount`

Used for Volume Shadow Copy inventory and read-only VSC mounting.

### libfsntfs-utils

Used for compressed NTFS recovery support.

### python3-libfsntfs

Python bindings used with compressed NTFS recovery support.

## Managed Tools

These are installed or built by Perceptor's managed installer:

```bash
uv run perceptor standalone install-tool all \
  --tools-dir ~/tools \
  --env-file ~/tools/perceptor.env
```

### Eric Zimmerman Tools

Perceptor downloads EZ Tools directly. PowerShell is not required for the
managed installer. SHA1 hashes are checked when the tool catalog supplies a
valid SHA1 value.

### AmcacheParser

Parses Windows Amcache artifacts for application and file presence context.

### AppCompatCacheParser

Parses ShimCache/AppCompatCache data for application presence context.

### EvtxECmd

Parses Windows EVTX logs into structured event rows.

### JLECmd

Parses Jump List artifacts.

### LECmd

Parses Windows shortcut (`.lnk`) artifacts.

### MFTECmd

Parses NTFS `$MFT` records and related NTFS metadata.

### MFTECmdUSN

Uses MFTECmd support for USN Journal parsing.

### MFTECmdLogFile

Uses MFTECmd support for NTFS `$LogFile` parsing.

### MFTECmdI30

Uses MFTECmd support for `$I30` directory index parsing.

### PECmd

Parses Prefetch artifacts.

### RBCmd

Parses Recycle Bin artifacts.

### RECmd

Parses Windows registry hives with configured batch files and targeted keys.

### SBECmd

Parses Shellbags artifacts.

### SQLECmd

Parses supported SQLite artifacts through EZ Tools maps where configured.

### SrumECmd

Parses SRUM ESE data.

### bstrings

Preferred memory and binary string scanner. Perceptor falls back to `strings`
where appropriate, but `bstrings` should be present after the default managed
install.

### SIDR

Perceptor expects a native Linux SIDR Rust build, not the upstream Windows
`sidr.exe`. SIDR is used for supported Windows Search parsing.

### usnjrnl-forensic

Used for USN reconstruction support. Building this tool requires Rust 1.88.0 or
newer.

### Volatility 3

Used for structured memory analysis where the captured memory architecture and
available symbols are supported.

### Volatility Windows Symbols

The managed installer stores the Windows symbol pack at:

```text
/opt/perceptor-tools/volatility3-symbols/windows.zip
```

Structured memory analysis passes the symbol directory to Volatility when it is
present.

### MemProcFS

Used for bounded structured memory inventory attempts, including process,
module, handle, registry, and file views where supported.

### pypykatz

Used for controlled DPAPI/LSA validation from memory plus registry-hive cases.

### ual-timeliner

External User Access Logging/SUM timeline parser. Perceptor also has an
internal fallback parser when the external tool is unavailable or fails.

### bmc-tools.py

Used for RDP bitmap cache fragment extraction.

### hibr2bin

Optional hibernation decompressor used before hiberfil scanning when available.

### HibernationRecon

Optional hibernation decompressor used before hiberfil scanning when available.

## Python Packages

These are installed through `uv sync`.

### beautifulsoup4

Used for HTML parsing and cleanup.

### cerberus

Used for schema validation.

### dissect-cstruct

Used by parser components that need structured binary parsing support.

### dissect.esedb

Used for ESE database parsing support.

### dissect-etl

Used for ETL/ETW parsing support.

### dissect.thumbcache

Used for Windows thumbcache parsing support.

### DuckDB

Embedded analytics database used for high-volume parsed artifact tables and
report queries.

### lxml

Used for XML/HTML parsing, including artifacts with XML structures.

### lz4

Used for compressed data handling where required by parsed artifacts.

### numpy

Used by data-processing paths and supporting libraries.

### pandas

Used for tabular data processing where appropriate.

### plyvel

Used for LevelDB-backed artifact parsing.

### pycryptodome

Used for cryptographic parsing and validation support.

### python-magic

Used for file type identification.

### python-registry

Used for direct Windows registry hive parsing.

### PyYAML

Used for YAML configuration and plugin data.

### quickxorhash

Used for OneDrive/SharePoint-style hash support.

### ruamel-yaml

Used for YAML parsing and writing where round-trip behavior matters.

### pypdf

Python fallback for PDF text extraction when `pdftotext` is unavailable.

## Services

### OpenSearch

OpenSearch stores readable content from files, emails, messages, and other
text-bearing artifacts. DuckDB and SQLite keep references, hashes, and
metadata; large content bodies belong in OpenSearch.

### OpenAI API

`OPENAI_API_KEY` is optional. When configured and enabled by policy, Perceptor
can use it for semantic RDP contact-sheet review. Without it, OCR fallback is
used where available. Perceptor records token usage and estimated cost when the
OpenAI path is used.

## Notes

- The default Ubuntu setup plus `install-tool all` should install the tools
  needed for normal Windows processing.
- Missing specialized tools should be reported by doctor and fixed during
  setup. Individual workflows should still fail gracefully when a tool is
  unavailable.
- SIDR on Linux means the native Linux binary; Perceptor does not use Wine to
  run `sidr.exe` for Windows Search parsing.
- MCP and report workflows should prefer parsed reports, DuckDB tables, and
  OpenSearch content before falling back to direct evidence access.
