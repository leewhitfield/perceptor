# First Run Checks

Run these checks before processing real evidence.

## Version

```bash
uv run relic standalone version
```

## Dependencies

```bash
uv run relic standalone dependencies --format table
```

## Doctor

```bash
uv run relic standalone doctor --smoke --format table
```

For a real workspace:

```bash
uv run relic --root ~/analysis/case01 standalone doctor --smoke --format table
```

## Smoke Regression

```bash
uv run relic standalone smoke-regression --format table
```

## Dry Run an Image

```bash
uv run relic --root ~/analysis/case01 --dry-run process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --workers 4
```

## Common Checks

```bash
command -v mmls fsstat fls icat
command -v ewfinfo ewfmount
command -v qemu-img
command -v ntfs-3g
command -v dotnet
command -v esedbexport
command -v exiftool
command -v pdftotext || echo "PDF parser will use pypdf fallback"
command -v tesseract
command -v vshadowinfo vshadowmount || echo "VSC sidecar unavailable"
```
