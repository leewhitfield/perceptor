# MCP Overview

Perceptor exposes a local MCP stdio server for MCP-capable clients such as Codex or
Claude Desktop style clients.

## Start the Server

```bash
uv run perceptor --root ~/analysis/case-root mcp serve
```

Enable processing tools only when needed:

```bash
uv run perceptor --root ~/analysis/case-root mcp serve --allow-processing
```

Additional gates:

```bash
--allow-sensitive
--allow-external-ai
```

## What MCP Can Do

Read-only by default:

- list cases, computers, images, jobs, and reports.
- read existing reports.
- query timelines and parsed artifact tables.
- query filesystem listings from `filesystem_entries`.
- review USB, cloud, memory, browser, registry, communication, and shortcut
  artifacts.
- write review/search packets when safe-write tools are used.

Gated with `--allow-processing`:

- import triage/report ZIPs.
- process images.
- run profiles.
- recover deleted files.
- cancel MCP-launched jobs.

## State and Audit

MCP job state is stored under:

```text
ROOT/mcp-jobs/
```

Tool calls are audited in:

```text
ROOT/mcp-jobs/audit.jsonl
```

For MCP-launched processing jobs, Perceptor stores the launched CLI command, stdout,
stderr, status, PID, timestamps, and return code under `ROOT/mcp-jobs/`. For
deleted-file recovery, the exact per-candidate `icat` command is also recorded
in the recovery manifest:

```text
cases/<case-id>/outputs/recovered-files/<run>/deleted-file-recovery-manifest.json
cases/<case-id>/outputs/recovered-files/<run>/deleted-file-recovery-manifest.csv
```
