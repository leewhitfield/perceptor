# Ubuntu Install

Relic currently supports Ubuntu 24.04 LTS x86_64. A VM is acceptable. Native
macOS, native Windows, WSL, Docker, ARM64, and older Ubuntu releases are
best-effort or unsupported for full image processing.

## Automated Bootstrap

From a source checkout:

```bash
scripts/bootstrap-ubuntu.sh
```

Useful options:

```bash
scripts/bootstrap-ubuntu.sh --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
scripts/bootstrap-ubuntu.sh --skip-tools
scripts/bootstrap-ubuntu.sh --skip-smoke
```

The bootstrap script installs apt packages, installs `uv` if needed, runs
`uv sync`, installs Relic-managed tools unless skipped, writes a tool environment
file, and runs `standalone doctor --smoke`.

## Manual Install

Install baseline packages:

```bash
sudo apt update
sudo apt install -y \
  git curl python3 python3-venv python3-dev build-essential pkg-config libleveldb-dev \
  sleuthkit ewf-tools qemu-utils ntfs-3g cryptsetup util-linux \
  libesedb-utils exiftool poppler-utils tesseract-ocr \
  libfsntfs-utils python3-libfsntfs libvshadow-utils dislocker libbde-utils
```

Install `uv`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
exec "$SHELL" -l
```

Clone and sync:

```bash
git clone https://github.com/example/relic.git
cd relic
uv sync
```

Install managed third-party tools. This is part of the default setup, not an
extra step for advanced users:

```bash
uv run relic standalone install-tool all \
  --tools-dir ~/tools \
  --env-file ~/tools/forensic-orchestrator.env

source ~/tools/forensic-orchestrator.env
```

## Verify

```bash
uv run relic standalone doctor --smoke --format table
uv run relic standalone smoke-regression --format table
```

For a specific workspace:

```bash
uv run relic --root ~/analysis/case01 standalone doctor --smoke --format table
```
