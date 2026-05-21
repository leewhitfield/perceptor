# ROCBA Mounting

Durable case data lives under:

```text
/mnt/forensic-ssd/forensic-orchestrator-rocba-case
```

Do not store evidence, databases, artifacts, or parser output under `/tmp`.

The current sudoers NOPASSWD mount rule is hardcoded to old `/tmp` command paths. Use `/tmp` only as a symlink compatibility path:

```bash
ln -s /mnt/forensic-ssd/forensic-orchestrator-rocba-case /tmp/forensic-orchestrator-rocba-case
```

Mount the EWF layer as the normal user:

```bash
ewfmount -X allow_other \
  /mnt/forensic-ssd/evidence/rocba/rocba-cdrive.e01 \
  /mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/ewf
```

Mount the NTFS layer through the old sudoers path:

```bash
sudo -n /usr/bin/ntfs-3g -o ro,show_sys_files,streams_interface=windows,norecover,offset=0 \
  /tmp/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/ewf/ewf1 \
  /tmp/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/volumes/volume-ntfs
```

Verify:

```bash
findmnt /mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/volumes/volume-ntfs
ls /mnt/forensic-ssd/forensic-orchestrator-rocba-case/cases/292bcc9d-e60b-4260-9cae-3078df55889b/mounts/volumes/volume-ntfs/Windows
```

The parser should run against the mounted NTFS path. The broad recursive TSK fallback is intentionally disabled unless `FORENSIC_ALLOW_RECURSIVE_TSK_INVENTORY=1` is set.
