#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/bootstrap-ubuntu.sh [--tools-dir DIR] [--env-file FILE] [--skip-tools] [--skip-smoke]

Bootstraps Relic on the supported platform: Ubuntu 24.04 LTS x86_64.

Options:
  --tools-dir DIR   Managed third-party tools directory. Default: ~/tools
  --env-file FILE   Tool environment file. Default: ~/tools/forensic-orchestrator.env
  --skip-tools      Skip Relic-managed third-party tool installation.
  --skip-smoke      Skip standalone doctor smoke verification.
  -h, --help        Show this help.
USAGE
}

TOOLS_DIR="${HOME}/tools"
ENV_FILE=""
SKIP_TOOLS=0
SKIP_SMOKE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools-dir)
      TOOLS_DIR="$2"
      shift 2
      ;;
    --env-file)
      ENV_FILE="$2"
      shift 2
      ;;
    --skip-tools)
      SKIP_TOOLS=1
      shift
      ;;
    --skip-smoke)
      SKIP_SMOKE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$ENV_FILE" ]]; then
  ENV_FILE="${TOOLS_DIR}/forensic-orchestrator.env"
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
else
  echo "Cannot read /etc/os-release; Ubuntu 24.04 x86_64 is required." >&2
  exit 1
fi

ARCH="$(uname -m)"
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" || "$ARCH" != "x86_64" ]]; then
  echo "Unsupported platform: ${PRETTY_NAME:-unknown} ${ARCH}" >&2
  echo "Relic currently supports Ubuntu 24.04 LTS x86_64." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

sudo apt-get update
sudo apt-get install -y \
  git curl python3 python3-venv python3-dev build-essential pkg-config libleveldb-dev \
  sleuthkit ewf-tools qemu-utils ntfs-3g cryptsetup util-linux \
  libesedb-utils exiftool poppler-utils tesseract-ocr \
  libfsntfs-utils python3-libfsntfs libvshadow-utils dislocker libbde-utils

if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="${HOME}/.local/bin:${PATH}"
fi

uv sync

mkdir -p "$TOOLS_DIR"

if [[ "$SKIP_TOOLS" -eq 0 ]]; then
  uv run relic standalone install-tool all \
    --tools-dir "$TOOLS_DIR" \
    --env-file "$ENV_FILE"
fi

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

if [[ "$SKIP_SMOKE" -eq 0 ]]; then
  uv run relic standalone doctor --smoke --format table
fi

echo
echo "Bootstrap complete."
echo "For future shells, run: source ${ENV_FILE}"
