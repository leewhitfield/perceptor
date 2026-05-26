# Deep Recovery Profiles

Deep recovery profiles are opt-in workflows. They are separate from `windows-full`
because they can be slower, noisier, and more dependent on image condition than
mounted-volume artifact extraction.

The `windows-full-deep-recovery` family is intended for cases where deleted
folder entries, orphaned file metadata, or explicit unallocated-space carving are
in scope. Normal `windows-full` processing should continue to prefer mounted
filesystem access first, with TSK used only where it adds specific recovery value.

Use:

```bash
forensic-orchestrator --root <case-root> report deep-recovery-status --case <case-id>
forensic-orchestrator --root <case-root> report readiness-gate --case <case-id> --profile windows-full-deep-recovery --summary-only
```

The status report combines readiness, TSK recovery timings, staged carve
coverage, and SQLite carve inventory. A failed deep-recovery gate does not mean a
standard Windows profile failed; it means the explicitly slower recovery layer
has not been completed or fully documented.

