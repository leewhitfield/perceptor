# Security Model

Perceptor processes untrusted evidence and third-party tool outputs. Treat the
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

## Evidence Integrity

Disk images added with `image add` or `process --path` are hashed on import with
MD5, SHA1, and SHA256. Perceptor stores those hashes separately from generic image
metadata so an examiner can re-verify the evidence later:

```bash
uv run perceptor --root ROOT image integrity --case CASE_ID --image IMAGE_ID --format table
uv run perceptor --root ROOT image verify --case CASE_ID --image IMAGE_ID --format table
```

Perceptor records each verification attempt. A mismatch means the current bytes at
the image path no longer match the hashes captured when the image was added.

Perceptor mounts evidence read-only when mounting is requested. The preferred
processing path is a read-only filesystem mount under `/tmp`, with direct TSK
fallback only for recovery or artifacts that cannot be read through the mount.

## Extraction Audit

Files materialized from evidence through TSK `icat` are recorded in
`evidence_file_extractions` with the source path, inode, extracted path, size,
SHA256, and available filesystem timestamps. Use:

```bash
uv run perceptor --root ROOT report evidence-extractions --case CASE_ID --format table
```

The extraction hash is the hash of the extracted copy Perceptor analyzed. It is the
database-backed link between the evidence source entry and the local parser
input.

## Secrets

BitLocker unlock material should be provided with key files where possible.
Perceptor avoids logging unlock material.

MCP credential reveal is gated by `--allow-sensitive`.

## External AI

External AI use is gated by `--allow-external-ai`. Do not upload evidence-derived
data to external services unless case policy allows it.

## OpenSearch

OpenSearch is assumed local for the current deployment model. Revisit transport
security and authentication before exposing it over a network.
