# Disk Images

Use this workflow for E01, raw, VHD, VHDX, VMDK, IMG, or ZIP-wrapped disk
evidence.

## Basic Processing

```bash
uv run relic --root ~/analysis/case-root process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --sudo \
  --workers 4
```

## Common Switches

- `--case CASE_ID`: add evidence to an existing case.
- `--path PATH`: source evidence path.
- `--computer COMPUTER_ID`: existing computer ID.
- `--computer-label LABEL`: label for a new computer.
- `--hostname HOSTNAME`: hostname metadata.
- `--profile PROFILE`: parser profile.
- `--filesystem`: mount the selected filesystem read-only before parsing.
- `--sudo`: use non-interactive sudo for mount and unmount.
- `--keep-mounted`: leave the read-only mount active after processing.
- `--workers N`: parallel worker slots.
- `--accept-duplicate`: allow duplicate evidence registration.
- `--replace-existing`: replace existing outputs for the selected run.

## Profiles

- `windows-basic`: lighter Windows parsing.
- `windows-full`: normal full Windows workflow.
- `windows-deep`: heavier recovery-oriented parsing.
- `windows-search`: Windows Search focused parsing.
- `windows-rdp-cache`: RDP bitmap cache focused parsing.

Deep recovery work should stay out of `windows-full` unless explicitly needed.

## Image Preparation

Relic detects volume images and full disk images. It uses `fsstat` for direct
volume detection and `mmls` for partition discovery when needed. EWF images use
Sleuth Kit directly when possible, with `ewfmount` fallback. VHD, VHDX, and VMDK
sources are converted with `qemu-img` into case-local raw images.

## Mounting

The normal parser flow does not require a kernel mount for every artifact. When
`--filesystem` is supplied, Relic mounts read-only and prefers mounted-volume
access for file inventory and parsers that benefit from filesystem paths.

For normal full-image processing, include `--filesystem`. If `--filesystem` is
omitted, Relic does not attempt a mounted-volume workflow and will rely on
Sleuth Kit extraction where possible. That fallback is useful for recovery and
for systems without mount privileges, but it is slower for broad recursive
artifact extraction.

Use `--sudo` only after configuring non-interactive sudo for Relic mount and
unmount commands. The sudoers rule is documented in
[Mounted Image Notes](../mounted-image-notes.md).

If `ewfmount` uses `allow_other`, `/etc/fuse.conf` must contain:

```text
user_allow_other
```

Clean stale mounts:

```bash
uv run relic --root ~/analysis/case-root image cleanup-stale-mounts --format table
```
