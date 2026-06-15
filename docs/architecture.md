# Architecture

Perceptor is a CLI-first forensic processing and reporting platform. Its core
boundary is simple: evidence stays read-only, processing writes to a separate
workspace, and generated outputs remain traceable to their source artifacts.

## Core Boundaries

- Evidence paths are read-only inputs. Perceptor must not write into source
  evidence directories, mounted evidence volumes, or original image files.
- Workspaces are separate from evidence. SQLite orchestration data, DuckDB
  analytics, OpenSearch indexes, staged extracts, logs, reports, and recovery
  output belong under the configured workspace root.
- MCP is local/private by default. MCP exists to help an analyst query a case
  workspace with guardrails; it is not a public processing API.
- Cloud or VPS instances must be isolated case workspaces. A hosted deployment
  should be treated as a private examiner workstation with controlled access,
  not as a shared public upload service.

## Source Priority

MCP and analyst workflows should prefer:

1. Generated reports and report exports.
2. Parsed artifact tables and normalized indexes.
3. Indexed content in OpenSearch.
4. Existing file listings and recovery inventories.
5. Direct image access only when existing Perceptor outputs cannot answer the
   question and the user explicitly requests processing or recovery.

## Docker Stance

Docker support is allowed only for local or isolated case workspaces with
explicit read-only evidence mounts. Docker is not currently a supported public
multi-user evidence upload or processing service.
