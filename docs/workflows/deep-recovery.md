# Deep Recovery

Deep recovery is separate from `windows-full`. It is intended for slower,
heavier workflows such as unallocated carving, deleted entry recovery, and
sidecar analysis.

## When to Use It

Use deep recovery when:

- normal artifact parsing leaves an investigative gap.
- deleted filesystem entries are important.
- unallocated space may contain relevant browser, document, or artifact data.
- VSC or sidecar workflows need to be evaluated.

## Profile

Use the deep profile explicitly:

```bash
uv run perceptor --root ~/analysis/case-root process \
  --path ~/evidence/host.E01 \
  --case CASE_ID \
  --profile windows-deep \
  --filesystem \
  --workers 4
```

## Boundary

Keep deep recovery out of baseline `windows-full` runs unless there is a clear
reason. This keeps normal processing predictable and faster.

See also [Deleted File Recovery](deleted-file-recovery.md).
