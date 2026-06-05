# Command Reference

This is a compact operator reference for common Relic commands.

## Global

```bash
uv run relic [--root ROOT] [--config CONFIG] [--plugin PLUGIN] [--dry-run] COMMAND ...
```

## Standalone

```bash
uv run relic standalone version
uv run relic standalone dependencies --format table
uv run relic standalone doctor --smoke --format table
uv run relic standalone smoke-regression --format table
uv run relic standalone install-tool all --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone repair-dependencies --tools-dir ~/tools --env-file ~/tools/forensic-orchestrator.env
uv run relic standalone sample-fixture --output sample-live-case.zip --format table
```

## Processing

```bash
uv run relic --root ROOT process --path IMAGE --computer-label HOST --profile windows-full --filesystem --sudo --workers 4
uv run relic --root ROOT --dry-run process --path IMAGE --computer-label HOST --profile windows-full --filesystem --sudo
uv run relic --root ROOT run --case CASE_ID --image IMAGE_ID --profile windows-rdp-cache --replace-existing
```

Use `--filesystem` for mounted-volume processing. If it is omitted, Relic will
not mount the image and will use Sleuth Kit extraction where possible.

## Ingest

```bash
uv run relic --root ROOT ingest triage-zip --path live-case.zip --preflight --format table
uv run relic --root ROOT ingest triage-zip --path live-case.zip --accept-duplicate --report-purpose triage
uv run relic --root ROOT report-bundle coverage --path live-case.zip --format table
uv run relic --root ROOT report-bundle import --path HOST01 --case CASE_ID --computer-label HOST01
uv run relic --root ROOT report-bundle import-many --path live-case.zip --accept-duplicate
```

## Reports

```bash
uv run relic --root ROOT report dashboard --case CASE_ID --format table
uv run relic --root ROOT report progress --case CASE_ID --format table
uv run relic --root ROOT report runbook --case CASE_ID --format md
uv run relic --root ROOT report review-status --case CASE_ID --format table
uv run relic --root ROOT report bundle --case CASE_ID --purpose review
uv run relic --root ROOT report validate-outputs --path reports/triage-bundle --format table
```

## Recovery

```bash
uv run relic --root ROOT recover deleted-files --case CASE_ID --image IMAGE_ID --name file.docx --limit 1 --format table
```

## Image Maintenance

```bash
uv run relic --root ROOT image add --case CASE_ID --path /evidence/host.E01 --computer COMPUTER_ID
uv run relic --root ROOT image integrity --case CASE_ID --image IMAGE_ID --format table
uv run relic --root ROOT image verify --case CASE_ID --image IMAGE_ID --format table
uv run relic --root ROOT image cleanup-stale-mounts --format table
uv run relic --root ROOT image mount --case CASE_ID --image IMAGE_ID --filesystem --sudo
uv run relic --root ROOT image unmount --case CASE_ID --image IMAGE_ID --sudo
```

`image add` hashes the evidence with MD5, SHA1, and SHA256. `image verify`
recomputes the stored algorithms and records the verification result.

## Extraction Audit

```bash
uv run relic --root ROOT report evidence-extractions --case CASE_ID --format table
uv run relic --root ROOT report evidence-extractions --case CASE_ID --image IMAGE_ID --artifact lnk_files --format csv --output extracted-lnk.csv
```

## MCP

```bash
uv run relic --root ROOT mcp serve
uv run relic --root ROOT mcp serve --allow-processing
uv run relic --root ROOT mcp serve --allow-processing --allow-sensitive --allow-external-ai
```
