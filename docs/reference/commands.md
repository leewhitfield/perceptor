# Command Reference

This is a compact operator reference for common Perceptor commands.

## Global

```bash
uv run perceptor [--root ROOT] [--config CONFIG] [--plugin PLUGIN] [--dry-run] COMMAND ...
```

UTC is the default timestamp display. Add `--timezone AREA/LOCATION` only when
you want display-only local companion fields while keeping UTC fields unchanged:

```bash
uv run perceptor --root ROOT --timezone America/New_York report timeline --case CASE_ID --format csv --output timeline.csv
```

## Standalone

```bash
uv run perceptor standalone version
uv run perceptor standalone dependencies --format table
uv run perceptor standalone doctor --smoke --format table
uv run perceptor standalone smoke-regression --format table
uv run perceptor standalone install-tool all --tools-dir ~/tools --env-file ~/tools/perceptor.env
uv run perceptor standalone repair-dependencies --tools-dir ~/tools --env-file ~/tools/perceptor.env
uv run perceptor standalone sample-fixture --output sample-live-case.zip --format table
```

`install-tool all` includes `dislocker` and `bdemount` for BitLocker fallback
coverage. Those are apt packages (`dislocker` and `libbde-utils`), so Perceptor
uses non-interactive sudo. If sudo prompts for a password, install them manually
with `sudo apt-get install -y dislocker libbde-utils` and rerun doctor.

## Processing

```bash
uv run perceptor --root ROOT process --path IMAGE --computer-label HOST --profile windows-full --filesystem --sudo --workers 4
uv run perceptor --root ROOT --dry-run process --path IMAGE --computer-label HOST --profile windows-full --filesystem --sudo
uv run perceptor --root ROOT run --case CASE_ID --image IMAGE_ID --profile windows-rdp-cache --replace-existing
```

Use `--filesystem` for mounted-volume processing. If it is omitted, Perceptor will
not mount the image and will use Sleuth Kit extraction where possible.

## Ingest

```bash
uv run perceptor --root ROOT ingest triage-zip --path live-case.zip --preflight --format table
uv run perceptor --root ROOT ingest triage-zip --path live-case.zip --accept-duplicate --report-purpose triage
uv run perceptor --root ROOT report-bundle coverage --path live-case.zip --format table
uv run perceptor --root ROOT report-bundle import --path HOST01 --case CASE_ID --computer-label HOST01
uv run perceptor --root ROOT report-bundle import-many --path live-case.zip --accept-duplicate
```

## Reports

```bash
uv run perceptor --root ROOT report dashboard --case CASE_ID --format table
uv run perceptor --root ROOT report progress --case CASE_ID --format table
uv run perceptor --root ROOT report processing-estimate --case CASE_ID --profile windows-full --format table
uv run perceptor --root ROOT report examiner-edge-artifacts --case CASE_ID --format table
uv run perceptor --root ROOT report mapped-network-paths --case CASE_ID --format table
uv run perceptor --root ROOT report non-standard-ads --case CASE_ID --format table
uv run perceptor --root ROOT report ntfs-security-descriptors --case CASE_ID --format table
uv run perceptor --root ROOT report remote-access-tool-logs --case CASE_ID --format table
uv run perceptor --root ROOT report runbook --case CASE_ID --format md
uv run perceptor --root ROOT report review-status --case CASE_ID --format table
uv run perceptor --root ROOT report bundle --case CASE_ID --purpose review
uv run perceptor --root ROOT report validate-outputs --path reports/triage-bundle --format table
```

## Recovery

```bash
uv run perceptor --root ROOT recover deleted-files --case CASE_ID --image IMAGE_ID --name file.docx --limit 1 --format table
```

## Image Maintenance

```bash
uv run perceptor --root ROOT image add --case CASE_ID --path /evidence/host.E01 --computer COMPUTER_ID
uv run perceptor --root ROOT image integrity --case CASE_ID --image IMAGE_ID --format table
uv run perceptor --root ROOT image verify --case CASE_ID --image IMAGE_ID --format table
uv run perceptor --root ROOT image cleanup-stale-mounts --format table
uv run perceptor --root ROOT image mount --case CASE_ID --image IMAGE_ID --filesystem --sudo
uv run perceptor --root ROOT image unmount --case CASE_ID --image IMAGE_ID --sudo
```

`image add` hashes the evidence with MD5, SHA1, and SHA256. `image verify`
recomputes the stored algorithms and records the verification result.

## Extraction Audit

```bash
uv run perceptor --root ROOT report evidence-extractions --case CASE_ID --format table
uv run perceptor --root ROOT report evidence-extractions --case CASE_ID --image IMAGE_ID --artifact lnk_files --format csv --output extracted-lnk.csv
```

## MCP

```bash
uv run perceptor --root ROOT mcp serve
uv run perceptor --root ROOT mcp serve --allow-processing
uv run perceptor --root ROOT mcp serve --allow-processing --allow-sensitive --allow-external-ai
```
