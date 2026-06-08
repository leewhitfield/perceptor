# Deleted File Recovery

Perceptor can recover selected deleted files from parsed filesystem listings and MFT
rows. Recovery is intentionally explicit and separate from normal listing or
report questions.

## Supported Sources

- FAT, FAT32, and exFAT candidates from `filesystem_entries`.
- NTFS candidates from `mft_entries`.

For FAT-style filesystems, Perceptor resolves the deleted address with `fls` and
extracts with `icat`. For NTFS, Perceptor uses the MFT entry number with `icat`.

## Recover a File

```bash
uv run perceptor --root ~/analysis/case-root recover deleted-files \
  --case CASE_ID \
  --image IMAGE_ID \
  --name timeline.docx \
  --limit 1 \
  --output-dir ~/analysis/case-root/cases/CASE_ID/outputs/recovered-files/timeline \
  --format table
```

## Useful Filters

- `--image IMAGE_ID`: limit recovery to one evidence image.
- `--contains TEXT`: match text in path or file name.
- `--name NAME`: exact file name.
- `--source all|filesystem_entries|mft_entries`: choose source tables.
- `--limit N`: maximum candidates.
- `--max-bytes N`: skip files larger than this size.
- `--output-dir PATH`: recovery output directory.
- `--format json|table|csv`: result format.

## Output

Perceptor writes recovered files plus:

- `deleted-file-recovery-manifest.csv`
- `deleted-file-recovery-manifest.json`

The manifest records original path, source table, image, filesystem type,
offset, inode/MFT entry, command, output path, recovered size, SHA256, status,
and failure reason.

The `command` field is the exact extraction command used for that candidate. For
successful and failed recovery attempts, this includes the full `icat` command,
for example:

```json
["icat", "-f", "fat", "-o", "240", "/evidence/usb.img", "9"]
```

For FAT-style rows where the inode is not stored in `filesystem_entries`, Perceptor
first resolves the deleted metadata address with `fls`. The extraction manifest
records the final `icat` command used to recover the file.

## MCP Behavior

MCP clients should first use `relic_query_evidence_contents` to identify the
target. `relic_recover_deleted_files` requires the MCP server to be started with
`--allow-processing`.

MCP also records the launched Perceptor command under `ROOT/mcp-jobs/<job-id>/` and
in `ROOT/mcp-jobs/index.json`. The per-file `icat` command is stored in the
deleted-file recovery manifests written to the recovery output directory.
