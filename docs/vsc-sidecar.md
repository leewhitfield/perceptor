# Volume Shadow Copy Work Area and Promotion

This is the experimental workflow for Volume Shadow Copy review. It is
intentionally separate from normal profile execution, but supported parsed rows
are promoted into the main case DuckDB after source-aware dedupe. The
`vsc-work` area remains the temporary workspace for mounts, extracted files,
intermediate databases, and comparison reports.

## Workspace

VSC inventory, mount metadata, command logs, and test extractions are written
under:

```text
cases/<case_id>/vsc-work/
```

The current work-area layout is:

```text
vsc-work/
  inventory.json
  jobs/
  vshadow/
  snapshots/<vssN>/mount.json
  snapshots/<vssN>/volume/
  extracts/<vssN>/
  parsed/vsc.duckdb
  reports/
```

## Commands

List snapshots from the prepared raw image and partition offset:

```bash
uv run forensic-orchestrator --root /path/to/case-root \
  vsc list --case CASE_ID --image IMAGE_ID
```

Mount one snapshot read-only:

```bash
uv run forensic-orchestrator --root /path/to/case-root \
  vsc mount --case CASE_ID --image IMAGE_ID --snapshot 1 --sudo
```

Extract one mounted artifact path for testing:

```bash
uv run forensic-orchestrator --root /path/to/case-root \
  vsc extract --case CASE_ID --snapshot vss1 --path Windows/Prefetch
```

Unmount VSC mounts:

```bash
uv run forensic-orchestrator --root /path/to/case-root \
  vsc unmount --case CASE_ID --snapshot vss1 --sudo
```

Run the current Prefetch pass across all discovered snapshots:

```bash
uv run forensic-orchestrator --root /path/to/case-root \
  vsc prefetch-scan --case CASE_ID --image IMAGE_ID --sudo
```

The Prefetch scan mounts one snapshot at a time, extracts only
`Windows/Prefetch`, stages lean parsed metadata in `vsc-work/parsed/vsc.duckdb`,
promotes distinct run-time rows into the main case DuckDB, and writes
`vsc-work/reports/prefetch-vsc-comparison.md`. The scan uses MD5, file size,
Prefetch modified time, run counts, and embedded run timestamps for change
detection. Raw Prefetch blobs and large referenced-string dumps are not stored.

Run the current Registry pass across all discovered snapshots:

```bash
uv run forensic-orchestrator --root /path/to/case-root \
  vsc registry-scan --case CASE_ID --image IMAGE_ID --sudo
```

The Registry scan mounts one snapshot at a time, copies targeted hives
(`SYSTEM`, `SOFTWARE`, per-user `NTUSER.DAT`, and per-user `UsrClass.dat`),
parses them with the internal registry artifact rules, stores lean rows in
`vsc-work/parsed/vsc.duckdb`, promotes distinct rows into the main case DuckDB,
and writes `vsc-work/reports/registry-vsc-comparison.md`.

This first Registry pass is scoped to activity, persistence, cloud, network,
and application-use keys. ShellBags are intentionally excluded from this pass
because they are high-volume and should be handled as a separate VSC comparison
when needed.

## Notes

- `vshadowinfo` and `vshadowmount` are required.
- The normal image preparation step must already have recorded a raw image path
  and partition offset.
- Keep VSC parsing scoped to artifact families where the live parser and VSC
  parser share the same normalized schema and dedupe rules.
