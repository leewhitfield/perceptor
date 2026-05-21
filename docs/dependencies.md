# Dependencies

This project depends on Python packages from `pyproject.toml` plus external
forensic and system tools. Keep durable dependencies installed under normal
system, repo, or configured tool paths. Do not put required tools under `/tmp`.

## Python Environment

Install the project dependencies with:

```bash
uv sync
```

or, for editable development:

```bash
uv pip install -e ".[dev]"
```

## Required System Tools

These should be installed on Linux workers that process Windows E01 evidence:

- `sleuthkit`: `mmls`, `fsstat`, `fls`, `icat`
- `ewf-tools`: `ewfinfo`, `ewfmount`
- `ntfs-3g`: optional read-only NTFS filesystem mounting
- `.NET runtime 9`: required for Eric Zimmerman .NET tools
- `libesedb-utils`: `esedbexport` for internal WebCache parsing
- `exiftool`: embedded/internal document, media, and executable metadata
- `tesseract-ocr`: OCR for RDP contact sheets and other image OCR hooks

Ubuntu/Debian example:

```bash
sudo apt-get update
sudo apt-get install -y sleuthkit ewf-tools ntfs-3g libesedb-utils exiftool tesseract-ocr
```

## Optional System Tools

These improve coverage but are not required for every case:

- `libfsntfs-utils`, `python3-libfsntfs`: recovery of compressed NTFS files
- `sidr`: Windows Search index parsing. Set `SIDR_BIN=/path/to/sidr` when not on `PATH`.
- `OneDriveExplorer.py`: OneDrive `.dat` parsing. Set `ONEDRIVE_EXPLORER=/path/to/OneDriveExplorer.py`.
- `bmc-tools.py`: RDP bitmap cache fragment extraction. The parser uses
  `BMC_TOOLS=/path/to/bmc-tools.py` when set, otherwise it auto-discovers the
  repo-local `.external/bmc-tools/bmc-tools.py` if present.
- OpenAI API key: primary semantic review of RDP contact sheets. Set
  `OPENAI_API_KEY`; optionally set `FORENSIC_OPENAI_VISION_MODEL`,
  `FORENSIC_OPENAI_RESPONSES_URL`, and `FORENSIC_OPENAI_TIMEOUT`.

The repo currently has a bundled BMC Tools path used in the ROCBA run:

```bash
export BMC_TOOLS=/home/lee/projects/investigator/.external/bmc-tools/bmc-tools.py
```

## Eric Zimmerman Tools

The built-in plugin expects Zimmerman tools under `/opt/eztools` by default.
Set this if your installation lives elsewhere:

```bash
export EZTOOLS_ROOT=/path/to/eztools
```

Key configured tools include `MFTECmd`, `EvtxECmd`, `RECmd`, `PECmd`, `SBECmd`,
`JLECmd`, `LECmd`, `SrumECmd`, and related parsers. The internal Linux parsers
cover some artifacts when the external Windows-oriented tools are not suitable.

## Quick Verification

Run these before a full processing job:

```bash
command -v mmls fsstat fls icat
command -v ewfinfo ewfmount
command -v ntfs-3g
command -v dotnet
command -v esedbexport
command -v exiftool
command -v tesseract
test -n "${BMC_TOOLS:-}" && test -f "$BMC_TOOLS"
test -n "${OPENAI_API_KEY:-}" || echo "OPENAI_API_KEY not set; RDP vision review will use Tesseract fallback"
```

For ROCBA RDP review, set `OPENAI_API_KEY` for semantic contact-sheet review.
Without it, `tesseract` must be on `PATH` for OCR fallback before running:

```bash
BMC_TOOLS=/home/lee/projects/investigator/.external/bmc-tools/bmc-tools.py \
uv run python -m forensic_orchestrator.cli \
  --root /mnt/forensic-ssd/forensic-orchestrator-rocba-case \
  run --case 292bcc9d-e60b-4260-9cae-3078df55889b \
  --image 2b1fdb43-1ae6-45c2-9b21-9c920ea784f9 \
  --profile windows-rdp-cache \
  --replace-existing
```
