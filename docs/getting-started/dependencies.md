# Dependency Management

Relic separates dependencies into three groups:

- Python packages managed by `uv`.
- System packages installed with apt.
- Relic-managed third-party tools downloaded or built under a tools directory.

## Python

```bash
uv sync
```

## Default System Packages

These packages are part of the default Ubuntu setup. They cover baseline image
processing plus recovery, VSC, BitLocker fallback, OCR, PDF text extraction, and
compressed NTFS support.

```bash
sudo apt install -y \
  sleuthkit ewf-tools qemu-utils ntfs-3g cryptsetup util-linux \
  libesedb-utils exiftool poppler-utils tesseract-ocr \
  libfsntfs-utils python3-libfsntfs libvshadow-utils dislocker libbde-utils
```

Important binaries include `mmls`, `fsstat`, `fls`, `icat`, `ewfinfo`,
`ewfmount`, `qemu-img`, `ntfs-3g`, `cryptsetup`, `esedbexport`, `exiftool`,
`pdftotext`, `tesseract`, `vshadowinfo`, `vshadowmount`, `dislocker`, and
`bdemount`.

## Default Managed Tools

Install all supported managed tools as part of setup:

```bash
uv run relic standalone install-tool all \
  --tools-dir ~/tools \
  --env-file ~/tools/forensic-orchestrator.env
```

Install one tool:

```bash
uv run relic standalone install-tool eztools --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone install-tool sidr --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone install-tool usnjrnl-forensic --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
```

## Tool Notes

- EZ Tools are downloaded directly; PowerShell is not required for Relic's
  managed installer.
- EZ Tools are SHA1 checked when the catalog supplies a valid SHA1.
- `bstrings` is obtained from the EZ Tools catalog and should be present after
  the default managed install.
- SIDR is expected to be a native Linux Rust build, not upstream `sidr.exe`.
- `usnjrnl-forensic` requires Rust 1.88.0 or newer.
- `pypykatz`, Volatility 3, the Volatility Windows symbol pack, MemProcFS,
  SIDR, `ual-timeliner`, and `usnjrnl-forensic` are treated as default coverage
  tools by `install-tool all`.
- The Volatility Windows symbol pack is stored as
  `/opt/relic-tools/volatility3-symbols/windows.zip` by the managed installer.
  Structured memory analysis passes that directory to Volatility when present.
- Missing coverage tools should be reported by doctor and fixed during setup.
  Individual workflows should still fail gracefully when a specialized tool is
  unavailable.

## Default Coverage Tools

These should be present after the default Ubuntu setup and managed tool install:

- `libfsntfs-utils` and `python3-libfsntfs`: compressed NTFS recovery support.
- `libvshadow-utils`: Volume Shadow Copy inventory and mount support.
- `dislocker` and `libbde-utils`: BitLocker fallback unlock tools.
- `pypykatz`: controlled DPAPI/LSA validation for memory plus registry-hive
  cases.
- `bstrings`: preferred memory/string scanner; Relic falls back to `strings`.
- `hibr2bin` or `HibernationRecon`: hiberfil decompression before scanning.
- `ual-timeliner`: external UAL/SUM timeline parser. Relic still has an
  internal fallback parser when this tool is unavailable or fails.
- `poppler-utils`: fast PDF text extraction through `pdftotext`; Relic falls
  back to `pypdf`.
- `bmc-tools.py`: RDP bitmap cache fragment extraction.

Example default coverage paths:

```bash
export BMC_TOOLS=/opt/relic/.external/bmc-tools/bmc-tools.py
export BSTRINGS_BIN=/opt/relic-tools/bstrings/bstrings
export UAL_TIMELINER_BIN=$HOME/.local/bin/ual-timeliner
```

## Truly Optional Services

- `OPENAI_API_KEY`: enables semantic RDP contact-sheet review. Without it, OCR
  fallback is used where available. This remains optional because it depends on
  case policy and external service approval. When OpenAI is used, Relic records
  response token usage and estimated cost in the RDP visual observation details
  and report output.

## Windows Search Note

SIDR supports Windows Search parsing where the database format is supported. On
Linux, use a native SIDR binary. Current testing did not identify an offline SIDR
option that decrypts Windows 11 `AesGcm1` encrypted SQLite Search databases. If
that format is required, collect live memory while the user is logged in and
SearchIndexer.exe is running, and preserve registry hives plus DPAPI/LSA
material for controlled follow-up.

## Check Dependency State

```bash
uv run relic standalone dependencies --format table
uv run relic standalone doctor --smoke --format table
```

## Quick Binary Check

```bash
command -v mmls fsstat fls icat
command -v ewfinfo ewfmount
command -v qemu-img
command -v ntfs-3g
command -v dotnet
command -v esedbexport
command -v exiftool
command -v pdftotext || echo "pdftotext not installed; PDF parser will use pypdf fallback"
command -v tesseract
command -v usnjrnl-forensic || test -x "$HOME/.cargo/bin/usnjrnl-forensic"
command -v vshadowinfo vshadowmount
command -v dislocker bdemount
python3 - <<'PY'
import pyfsntfs
PY
```
