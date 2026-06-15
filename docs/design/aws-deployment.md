# Design AWS Deployment Model For Isolated Perceptor Case Workspaces

Status: design needed.

Perceptor does not currently support public hosted evidence upload or public MCP
processing. Any AWS or VPS deployment must be designed before implementation.

## Problem

Examiners may eventually want hosted Perceptor workspaces for large cases,
collaboration, or remote processing. A hosted deployment is higher risk than a
local analyst workstation because it introduces network services, credentials,
evidence transfer, tenant isolation, cloud storage, and operational monitoring.

## Required Boundaries

- One isolated workspace per case or tenant.
- Evidence storage mounted read-only for processing.
- No public unauthenticated upload endpoint.
- No public unauthenticated MCP endpoint.
- MCP processing must not be treated as a public API.
- Secrets must live in AWS secret stores or local ignored files, never in repo
  examples or committed config.
- OpenSearch must not be publicly exposed.
- All processing and recovery jobs must write to workspace/output paths, not
  source evidence paths.

## Design Questions

- Should evidence ingress be pull-based from examiner-controlled storage instead
  of push-based public upload?
- What authentication model gates upload, MCP, report access, and job control?
- How are workspaces isolated at the filesystem, process, and OpenSearch index
  levels?
- How are case workspaces created, locked, archived, and destroyed?
- How are audit logs exported for review?
- How are evidence hashes verified before and after transfer?
- What resource limits prevent one case from exhausting disk, CPU, memory, or
  OpenSearch capacity?
- What backup and retention rules apply to evidence-derived data?

## Docker Stance

Docker is acceptable only for local or isolated case workspaces with explicit
read-only evidence mounts. A Docker stack that exposes upload or processing
services publicly is out of scope until this design is completed.

## Initial Issue Text

Title:

```text
Design AWS deployment model for isolated Perceptor case workspaces
```

Body:

```text
Define a hosted Perceptor model that preserves evidence integrity and examiner
control. The design must cover isolated case workspaces, read-only evidence
access, authenticated ingress, private MCP access, OpenSearch isolation, secret
management, audit logging, resource limits, and teardown/archive behavior.

Do not implement public evidence upload or public MCP processing until this
design is reviewed.
```
