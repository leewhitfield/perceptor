# Ubuntu Install

Relic currently supports **Ubuntu 24.04 LTS on x86_64**. Bare metal and virtual machines are both acceptable. Other Linux distributions, older Ubuntu releases, ARM64, WSL, Docker, native macOS, and native Windows are best-effort or unsupported for now, especially for filesystem mounting, BitLocker, VSC, and FUSE workflows.

## Base System

Start with a clean Ubuntu 24.04 LTS x86_64 install and a workspace volume with enough free space for evidence expansion, extracted artifacts, DuckDB analytics files, and report bundles.

Install baseline packages:

```bash
sudo apt update
sudo apt install -y git curl python3 python3-venv build-essential
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
