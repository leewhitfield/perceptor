# Security Policy

Perceptor processes sensitive forensic evidence and untrusted artifact output.
Security decisions should preserve evidence integrity, examiner control, and
private case workspaces.

## Non-Negotiable Boundaries

- Do not write to original evidence paths, mounted evidence volumes, or source
  image files.
- Do not expose a public evidence upload endpoint.
- Do not expose unauthenticated MCP processing.
- Do not treat MCP processing as a public API.
- Do not commit secrets, tokens, passwords, API keys, private keys, certificates,
  or case-specific credentials.
- Do not include real examiner names, client names, evidence names, or live case
  identifiers in examples, tests, documentation, or fixtures.

## Evidence Access

Evidence must be mounted or opened read-only. Work products, extracted files,
indexes, databases, logs, and generated reports must be written under the
configured workspace root or another explicit output path, not into evidence
locations.

Any contribution that changes image mounting, extraction, deleted-file recovery,
carving, archive extraction, or direct filesystem access must describe how it
preserves read-only evidence handling.

## MCP Safety

The MCP server is intended for localhost or private-network use by an analyst.
Processing-capable MCP tools require explicit startup flags such as
`--allow-processing`. Sensitive or external-AI workflows require their own
explicit opt-in flags.

Do not expose MCP processing over the public internet unless a future reviewed
authentication, authorization, logging, and deployment model exists.

## Network Services

Perceptor does not currently support a public evidence-upload service. Any
network-facing deployment proposal must document:

- authentication and authorization.
- transport security.
- per-case workspace isolation.
- evidence storage isolation.
- logging and audit behavior.
- secret handling.
- operational limits and abuse controls.

## Secrets

Use local ignored files or secret stores for sensitive values. The repository
includes `.env.example` with empty placeholders only. Copy it to `.env` locally
when needed.

Ignored local secret patterns include:

- `.env`
- `.env.*`
- `*.key`
- `*.pem`
- `*.p12`
- `secrets/`
- `credentials/`

Never commit real values for variables such as:

- `OPENSEARCH_PASSWORD`
- `PERCEPTOR_MCP_TOKEN`
- `OPENAI_API_KEY`
- cloud provider keys
- SSH private keys
- BitLocker recovery keys or passwords

## Docker Stance

Docker support is allowed only for local or isolated case workspaces with
explicit read-only evidence mounts. Docker is not currently a supported public
multi-user evidence upload or processing service.

## Reporting Security Issues

Until a formal security contact is published, open a private report or contact
the project maintainer directly. Do not include real evidence, secrets, or case
identifiers in public issues.
