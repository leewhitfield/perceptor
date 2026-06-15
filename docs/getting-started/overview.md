# Overview

Perceptor stores each investigation in a workspace root. A workspace contains cases,
computers, images, logs, extracted artifacts, parsed analytics data, progress
manifests, generated reports, and MCP job state.

## Core Concepts

- **Workspace root**: durable storage for all case data.
- **Case**: one investigation container. Most commands use `--case CASE_ID`.
- **Computer**: a device within a case.
- **Image/evidence**: a disk image, mounted volume, report bundle, or triage
  folder.
- **Profile**: a group of extraction and parser steps, such as `windows-full`,
  `windows-basic`, `windows-deep`, `windows-search`, or `windows-rdp-cache`.
- **DuckDB analytics store**: high-volume parsed artifact tables.
- **SQLite orchestration store**: cases, jobs, images, tool outputs, timings,
  progress, and metadata.
- **Report bundle**: generated Markdown, JSON, and CSV reports under a case
  output directory.
- **MCP server**: a local stdio server that lets MCP-capable clients query Perceptor.

## Executable Names

Perceptor installs the preferred command name and the existing long-form CLI alias:

```bash
perceptor
forensic-orchestrator
```

Examples use `uv run perceptor`. If Perceptor is installed as a console script, omit
`uv run`.

## Global Command Shape

```bash
uv run perceptor [--root ROOT] [--config CONFIG] [--plugin PLUGIN] [--dry-run] COMMAND ...
```

Use the same `--root` for all commands that read or write a case.

```bash
uv run perceptor --root ~/analysis/my-case-root ...
```

## Storage Guidance

Use a large durable disk. Real cases can expand significantly during:

- ZIP extraction and preflight.
- E01/VHD/VHDX/VMDK preparation.
- mounted filesystem inventory.
- DuckDB rebuilds and temporary files.
- report bundle generation.
- deleted-file recovery output.

Do not store evidence or case work under `/tmp`.
