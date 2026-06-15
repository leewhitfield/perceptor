# Perceptor Architecture

Perceptor is a CLI-first forensic processing and reporting platform. Its core
boundary is simple: evidence stays read-only, processing writes to a separate
workspace, and generated outputs remain traceable to their source artifacts.

## Core Boundaries

- Evidence paths are read-only inputs. Perceptor must not write into source
  evidence directories, mounted evidence volumes, or original image files.
- Workspaces are separate from evidence. SQLite orchestration data, DuckDB
  analytics, OpenSearch indexes, staged extracts, logs, reports, and recovery
  output belong under the configured workspace root.
- Tool output is derived evidence. Commands, generated reports, extracted rows,
  hashes, and caveats should be recorded so findings can be traced back to the
  source image, report bundle, or artifact.
- MCP is local/private by default. MCP exists to help an analyst query a case
  workspace with guardrails; it is not a public processing API.
- Cloud or VPS instances must be isolated case workspaces. A hosted deployment
  should be treated as a private examiner workstation with controlled access,
  not as a shared public upload service.

## Storage Model

- SQLite stores case state, evidence metadata, jobs, audit records, processing
  status, and orchestration metadata.
- DuckDB stores high-volume parsed artifact tables and analytical views.
- OpenSearch stores searchable text extracted from documents, emails, messages,
  indexed content, and other readable sources.
- Filesystem outputs under the workspace store extracted reports, command logs,
  staged files, recovered deleted files, and generated bundles.

## Processing Model

Perceptor prefers mounted read-only filesystems when available because they are
faster and closer to normal filesystem semantics. It falls back to structured
tool access or Sleuth Kit-style extraction only when mounting is unavailable or
the profile explicitly needs deeper recovery behavior.

Processing profiles should remain explicit. Deep recovery, carving, and deleted
file recovery are intentionally separate from ordinary Windows processing
because they can be slow, noisy, and storage-intensive.

## MCP Model

MCP tools should route questions through the safest available source first:

1. Generated reports and report exports.
2. Parsed artifact tables and normalized indexes.
3. Indexed content in OpenSearch.
4. Existing file listings and recovery inventories.
5. Direct image access only when existing Perceptor outputs cannot answer the
   question and the user explicitly requests processing or recovery.

Processing through MCP requires explicit opt-in flags and is intended for
localhost or private-network use only.

## Docker Stance

Docker support is allowed only for local or isolated case workspaces with
explicit read-only evidence mounts. Docker is not currently a supported public
multi-user evidence upload or processing service.
