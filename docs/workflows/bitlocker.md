# BitLocker Images

Perceptor performs an encryption preflight before mounting or running a profile.
When BitLocker is detected, unlocking must be explicit.

## Process with Unlock

```bash
uv run perceptor --root ~/analysis/case-root process \
  --path ~/evidence/host.E01 \
  --computer-label HOST01 \
  --profile windows-full \
  --filesystem \
  --unlock-bitlocker \
  --bitlocker-method recovery-key \
  --bitlocker-key-file ~/keys/host01.recovery-key
```

## Tool Chain

The default fallback order is:

1. `cryptsetup`
2. `dislocker`
3. `bdemount`

Choose a specific backend:

```bash
--bitlocker-tool auto|cryptsetup|dislocker|bdemount
```

Choose a protector type:

```bash
--bitlocker-method recovery-key|password|bek|fvek
```

## Secret Handling

Use `--bitlocker-key-file PATH` where possible. Perceptor supplies unlock material
through stdin for supported tools and does not log the secret.

If BitLocker is detected without `--unlock-bitlocker`, processing stops and
records `image.encryption_detected`.
