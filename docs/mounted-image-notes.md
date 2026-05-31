# Mounting

Durable case data lives under the configured workspace root, for example:

```text
/analysis/relic/example-case
```

Do not store evidence, databases, artifacts, reports, logs, or parser output
under `/tmp`.

Live EWF and NTFS mount points are intentionally temporary. By default they live
under:

```text
/tmp/forensic-orchestrator-mounts/cases/<case_id>/ewf/ewf1
/tmp/forensic-orchestrator-mounts/cases/<case_id>/volumes/<partition_id>
```

This keeps the sudoers rule stable across cases. If `/tmp` is cleared or the
system reboots, no case data is lost; remount the image before running profiles
that require filesystem access.

Default sudoers shape:

```text
analyst ALL=(root) NOPASSWD: /usr/bin/ntfs-3g -o ro\,show_sys_files\,streams_interface\=windows\,norecover\,offset\=* /tmp/forensic-orchestrator-mounts/cases/*/ewf/ewf1 /tmp/forensic-orchestrator-mounts/cases/*/volumes/*, /usr/bin/umount /tmp/forensic-orchestrator-mounts/cases/*/volumes/*
```

Mount with the normal workflow:

```bash
uv run forensic-orchestrator --root /analysis/relic/example-case \
  image mount --case CASE_ID --image IMAGE_ID --filesystem --sudo
```

Verify:

```bash
findmnt /tmp/forensic-orchestrator-mounts/cases/CASE_ID/volumes/PARTITION_ID
ls /tmp/forensic-orchestrator-mounts/cases/CASE_ID/volumes/PARTITION_ID/Windows
```

Full profiles should run against a mounted NTFS path. The broad recursive TSK
fallback is intentionally disabled unless
`FORENSIC_ALLOW_RECURSIVE_TSK_INVENTORY=1` is set.
