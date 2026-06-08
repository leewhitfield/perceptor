# Configuration

Perceptor can be run with command-line switches only, but a config file is better for
repeat work.

## Example Config

```yaml
root: /analysis/perceptor
tools_root: /opt/perceptor-tools
eztools_root: /opt/perceptor-tools/eztools
plugins:
  - /opt/perceptor/forensic_orchestrator/plugins/eztools.yaml
```

Run with:

```bash
uv run perceptor --config config.yaml standalone doctor
```

Command-line `--root` and `--plugin` override config values.

## Common Environment Variables

```bash
export EZTOOLS_ROOT=/opt/perceptor-tools/eztools
export SIDR_BIN=/opt/perceptor-tools/sidr/sidr
export USNJRNL_FORENSIC_BIN=$HOME/.cargo/bin/usnjrnl-forensic
export BMC_TOOLS=/path/to/bmc-tools.py
export BSTRINGS_BIN=/path/to/bstrings
```

Managed installs can write these to an env file:

```bash
uv run perceptor standalone install-tool all \
  --tools-dir ~/tools \
  --env-file ~/tools/perceptor.env
source ~/tools/perceptor.env
```

## Analytics Mode

DuckDB is the default analytics store. Use SQLite mode only for tests or
debugging:

```bash
export FORENSIC_ANALYTICS_MODE=sqlite
```

The normal case layout expects parsed artifact tables in per-case DuckDB files.
