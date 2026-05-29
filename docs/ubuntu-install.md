# Ubuntu Install

Relic currently supports **Ubuntu 24.04 LTS on x86_64**. Bare metal and virtual machines are both acceptable. Other Linux distributions, older Ubuntu releases, ARM64, WSL, Docker, native macOS, and native Windows are best-effort or unsupported for now, especially for filesystem mounting, BitLocker, VSC, and FUSE workflows.

## Base System

Start with a clean Ubuntu 24.04 LTS x86_64 install and a workspace volume with enough free space for evidence expansion, extracted artifacts, DuckDB analytics files, and report bundles.

## Automated Bootstrap

From a source checkout, the supported bootstrap path is:

```bash
scripts/bootstrap-ubuntu.sh
```

Useful options:

```bash
scripts/bootstrap-ubuntu.sh --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
scripts/bootstrap-ubuntu.sh --skip-tools
scripts/bootstrap-ubuntu.sh --skip-smoke
```

The bootstrap script verifies Ubuntu 24.04 x86_64, installs baseline apt
packages, installs `uv` if needed, runs `uv sync`, installs Relic-managed
third-party tools unless skipped, loads the generated tool environment file, and
runs `standalone doctor --smoke` unless skipped.

## Manual Install

Install baseline packages:

```bash
sudo apt update
sudo apt install -y \
  git curl python3 python3-venv python3-dev build-essential pkg-config libleveldb-dev \
  sleuthkit ewf-tools qemu-utils ntfs-3g cryptsetup util-linux \
  libesedb-utils exiftool poppler-utils tesseract-ocr \
  libvshadow-utils dislocker libbde-utils
```

Install `uv`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
exec "$SHELL" -l
```

## Relic Source Install

Clone the repository and install Python dependencies:

```bash
git clone https://github.com/leewhitfield/relic.git
cd relic
uv sync
```

Install Relic-managed third-party tools into a user-controlled tools directory:

```bash
uv run relic standalone install-tool all \
  --tools-dir ~/tools \
  --env-file ~/tools/forensic-orchestrator.env
```

Load the generated environment file for the current shell:

```bash
source ~/tools/forensic-orchestrator.env
```

## Verify Install

Run doctor and the smoke test:

```bash
uv run relic standalone doctor --smoke --format table
```

For a specific workspace root:

```bash
uv run relic --root ~/analysis/case01 standalone doctor --smoke --format table
```

If `platform_supported` fails, Relic is running outside the primary support target. It may still work for parsing/reporting, but full image mounting and third-party tool installation are not supported on that platform.

## Common Failure Paths

- `uv: command not found`: open a new login shell or add `~/.local/bin` to
  `PATH`, then rerun `uv sync`.
- `quickxorhash` or `plyvel` build failures: install baseline build packages
  with `sudo apt install -y build-essential python3-dev pkg-config libleveldb-dev`.
- Rust or `usnjrnl-forensic` failures: install a current Rust toolchain with
  `rustup`, ensure `rustc --version` is 1.88.0 or newer, then rerun
  `standalone install-tool usnjrnl-forensic`.
- FUSE or mount failures: run `standalone doctor --smoke`, confirm `ewfmount`,
  `ntfs-3g`, and `/dev/fuse` exist, and clean stale mounts with
  `image cleanup-stale-mounts` before retrying.
- EZ Tools setup failures: rerun `standalone install-tool eztools`; Relic
  downloads the required release assets directly and does not require
  PowerShell for the managed install path.
- SIDR setup failures: rerun `standalone install-tool sidr`; Relic expects a
  native Linux Rust build, not the upstream Windows `sidr.exe`.
- Missing env file: rerun `standalone install-tool all --tools-dir ~/tools
  --env-file ~/tools/forensic-orchestrator.env`, then `source` that file.

## First Case Checks

For live-response/report ZIPs:

```bash
uv run relic --root ~/analysis/case01 report-bundle coverage \
  --path ~/evidence/livecase.zip \
  --format table
```

For disk-image workflows, run doctor first, then use a dry run before processing:

```bash
uv run relic --root ~/analysis/case01 standalone doctor --smoke --format table

uv run relic --root ~/analysis/case01 --dry-run process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --workers 4
```

## Support Boundaries

Supported:

- Ubuntu 24.04 LTS x86_64
- Bare metal or VM
- Source checkout with `uv sync`
- Relic-managed tools under `~/tools` or a configured tools directory
- Full parsing, reporting, MCP, and read-only mounted-image workflows when required tools are installed

Best-effort:

- Other Ubuntu/Debian versions
- Ubuntu ARM64
- WSL for parsing/reporting only
- Docker for parsing/reporting only

Unsupported for now:

- Native macOS
- Native Windows
- Docker as the primary full disk-image mounting workflow
