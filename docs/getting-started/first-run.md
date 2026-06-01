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
  --sudo \
  --workers 4
```

`--filesystem` is the switch that enables mounted-volume processing. If it is
left out, Relic will not mount the image and will use Sleuth Kit extraction
where possible. Use `--sudo` only after configuring the passwordless mount rule
in [Mounted Image Notes](../mounted-image-notes.md).

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
