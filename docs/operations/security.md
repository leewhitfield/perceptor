# Security Model

Relic processes untrusted evidence and third-party tool outputs. Treat the
workspace as sensitive.

## Paths

Use explicit workspace and tool paths. Avoid placing required evidence, tools,
or outputs under `/tmp`.

Managed archive extraction rejects:

- absolute paths.
- drive-letter paths.
- parent traversal.
- empty paths.
- link and device entries.

## Third-Party Tools

Managed installers download tools into a user-controlled tools directory. EZ
Tools are SHA1 checked when a valid SHA1 is supplied by the catalog. Supply chain
risk is not eliminated; preserve installer logs and tool manifests.

## ZIP Preflight

ZIP preflight checks unsafe names, member count, compressed size, uncompressed
size, and available workspace space. There is no fixed evidence-size cap; the
workspace must have enough free space to expand safely with reserve.

## Secrets

BitLocker unlock material should be provided with key files where possible.
Relic avoids logging unlock material.

MCP credential reveal is gated by `--allow-sensitive`.

## External AI

External AI use is gated by `--allow-external-ai`. Do not upload evidence-derived
data to external services unless case policy allows it.

## OpenSearch

OpenSearch is assumed local for the current deployment model. Revisit transport
security and authentication before exposing it over a network.
