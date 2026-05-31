# Volume Shadow Copies

Volume Shadow Copy support is a sidecar workflow. It is not required for every
case.

## Requirements

The default Ubuntu setup installs `libvshadow-utils`.

Verify:

```bash
command -v vshadowinfo vshadowmount
```

## Output Location

VSC inventory, mounts, manifests, intermediate databases, and comparisons stay
under:

```text
cases/<case-id>/vsc-work/
```

Supported parsed rows can be promoted into the main case analytics store after
dedupe.

## Operational Note

Use VSC when the question requires historical copies of artifacts. Do not use it
as a default replacement for normal disk parsing.
