# Relic Checkpoint

This checkpoint intentionally avoids case names, evidence labels, examiner user
names, absolute home-directory paths, and live case identifiers.

## Current State

Relic is a CLI-first forensic orchestration tool for Ubuntu 24.04 LTS x86_64.
It supports read-only image preparation, optional mounted-filesystem processing,
Sleuth Kit fallback extraction, managed third-party tooling, normalized SQLite
and DuckDB storage, report bundles, MCP access, and MkDocs-ready operator
documentation.

## Supported Workspace Pattern

Use a durable workspace root outside `/tmp`:

```text
/path/to/workspace
```

Use a separate evidence location:

```text
/path/to/evidence
```

Use a managed tool root:

```text
/opt/relic-tools
```

## Setup

Bootstrap a supported Ubuntu system from a source checkout:

```bash
scripts/bootstrap-ubuntu.sh --tools-dir /opt/relic-tools --env-file /opt/relic-tools/relic.env
source /opt/relic-tools/relic.env
```

The managed installer should install default coverage tools, including EZ
Tools, bstrings, SIDR, MemProcFS, Volatility, pypykatz, `ual-timeliner`, and
USN journal tooling where build requirements are met.

## Verification

Run:

```bash
uv run relic --root /path/to/workspace standalone doctor --smoke --format table
uv run relic --root /path/to/workspace standalone tool-status --tools-dir /opt/relic-tools --format table
uv run pytest
```

## Operational Notes

- Keep original evidence read-only.
- Prefer `/opt/relic-tools` for managed tools so installs are not tied to a
  specific user profile.
- Use `FORENSIC_ORCHESTRATOR_TOOLS_ROOT=/opt/relic-tools` when a shell needs an
  explicit tool root.
- Use `OPENAI_API_KEY` and `FORENSIC_ALLOW_EXTERNAL_AI=1` only when external AI
  review is approved for the case.
- OpenAI-backed review records token usage and estimated cost in report details.
