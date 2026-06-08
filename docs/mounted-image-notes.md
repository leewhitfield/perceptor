# Mounting

Durable case data lives under the configured workspace root, for example:

```text
/analysis/perceptor/example-case
```

Do not store evidence, databases, artifacts, reports, logs, or parser output
under `/tmp`.

Live EWF and NTFS mount points are intentionally temporary. By default they live
under:

```text
/tmp/perceptor-mounts/cases/<case_id>/ewf/ewf1
/tmp/perceptor-mounts/cases/<case_id>/volumes/<partition_id>
```

This keeps the sudoers rule stable across cases. If `/tmp` is cleared or the
system reboots, no case data is lost; remount the image before running profiles
that require filesystem access.

## Passwordless Mount Sudoers

Perceptor uses non-interactive sudo. If `--sudo` is supplied but the sudoers rule is
missing, the mount will fail instead of prompting for a password.

Create a dedicated sudoers entry with `visudo`. Replace `analyst` with the Linux
user that runs Perceptor:

```text
analyst ALL=(root) NOPASSWD: /usr/bin/ntfs-3g -o ro\,show_sys_files\,streams_interface\=windows\,norecover\,offset\=* /tmp/perceptor-mounts/cases/*/ewf/ewf1 /tmp/perceptor-mounts/cases/*/volumes/*, /usr/bin/umount /tmp/perceptor-mounts/cases/*/volumes/*
```

Recommended editor flow:

```bash
sudo visudo -f /etc/sudoers.d/perceptor-mounts
```

Set safe permissions after saving:

```bash
sudo chmod 0440 /etc/sudoers.d/perceptor-mounts
```

## Mount with Perceptor

Mounted processing requires `--filesystem`. Without it, Perceptor will not attempt a
mount and will use Sleuth Kit extraction where possible.

Mount with the normal workflow:

```bash
uv run perceptor --root /analysis/perceptor/example-case \
  image mount --case CASE_ID --image IMAGE_ID --filesystem --sudo
```

Process with mounted-volume access:

```bash
uv run perceptor --root /analysis/perceptor/example-case process \
  --path /evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --sudo \
  --workers 4
```

Verify:

```bash
findmnt /tmp/perceptor-mounts/cases/CASE_ID/volumes/PARTITION_ID
ls /tmp/perceptor-mounts/cases/CASE_ID/volumes/PARTITION_ID/Windows
```

Full profiles should run against a mounted NTFS path. The broad recursive TSK
fallback is intentionally disabled unless
`FORENSIC_ALLOW_RECURSIVE_TSK_INVENTORY=1` is set.
