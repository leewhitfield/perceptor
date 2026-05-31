# Configuration

Relic can be run with command-line switches only, but a config file is better for
repeat work.

## Example Config

```yaml
root: /analysis/relic
tools_root: /opt/relic-tools
eztools_root: /opt/relic-tools/eztools
plugins:
  - /opt/relic/forensic_orchestrator/plugins/eztools.yaml
```

Run with:

```bash
uv run relic --config config.yaml standalone doctor
```

Command-line `--root` and `--plugin` override config values.

## Common Environment Variables

```bash
export EZTOOLS_ROOT=/opt/relic-tools/eztools
export SIDR_BIN=/opt/relic-tools/sidr/sidr
export USNJRNL_FORENSIC_BIN=$HOME/.cargo/bin/usnjrnl-forensic
export BMC_TOOLS=/path/to/bmc-tools.py
export BSTRINGS_BIN=/path/to/bstrings
```

Managed installs can write these to an env file:

```bash
uv run relic standalone install-tool all \
  --tools-dir ~/tools \
  --env-file ~/tools/forensic-orchestrator.env
source ~/tools/forensic-orchestrator.env
```

## Analytics Mode

DuckDB is the default analytics store. Use SQLite mode only for tests or
debugging:

```bash
export FORENSIC_ANALYTICS_MODE=sqlite
```

The normal case layout expects parsed artifact tables in per-case DuckDB files.
