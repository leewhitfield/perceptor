# Troubleshooting

## `uv: command not found`

Open a new login shell or add `~/.local/bin` to `PATH`.

```bash
exec "$SHELL" -l
```

## Python Build Failures

For `quickxorhash`, `plyvel`, or wheel build errors:

```bash
sudo apt install -y build-essential python3-dev pkg-config libleveldb-dev
uv sync
```

## `usnjrnl-forensic` Requires Newer Rust

Install or update Rust with `rustup`, then rerun the managed install.

```bash
rustc --version
uv run perceptor standalone install-tool usnjrnl-forensic --tools-dir ~/tools --env-file ~/tools/perceptor.env
```

`rustc` must be 1.88.0 or newer.

## EZ Tools Install Fails

Perceptor's managed EZ Tools installer does not require PowerShell.

```bash
uv run perceptor standalone install-tool eztools --tools-dir ~/tools --env-file ~/tools/perceptor.env
```

## SIDR Install Fails

Perceptor expects native Linux SIDR, not `sidr.exe`.

```bash
uv run perceptor standalone install-tool sidr --tools-dir ~/tools --env-file ~/tools/perceptor.env
```

## Missing Env File

Regenerate it:

```bash
uv run perceptor standalone install-tool all --tools-dir ~/tools --env-file ~/tools/perceptor.env
source ~/tools/perceptor.env
```

## FUSE or Mount Failures

Check dependencies:

```bash
uv run perceptor standalone doctor --smoke --format table
command -v ewfmount ntfs-3g
test -e /dev/fuse
```

Clean stale mounts:

```bash
uv run perceptor --root ~/analysis/case-root image cleanup-stale-mounts --format table
```

If `allow_other` is needed, set:

```text
user_allow_other
```

in `/etc/fuse.conf`.

## DuckDB Temporary Space

Use a workspace on a large disk. If a run fails because DuckDB temporary storage
cannot be written, verify filesystem free space and rerun after cleanup or disk
expansion.

```bash
df -h ~/analysis/case-root
du -h --max-depth=1 ~/analysis/case-root | sort -h
```
