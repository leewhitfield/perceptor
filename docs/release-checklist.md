# Release Checklist

Use this checklist before tagging a Relic release.

## Platform Contract

- Supported target remains Ubuntu 24.04 LTS x86_64.
- `standalone version --format json` reports `platform_support.status` as
  `supported` on the release workstation.
- `docs/ubuntu-install.md` matches the tested install path.

## Verification

Run from a clean checkout:

```bash
uv sync --extra dev
uv run python -m compileall forensic_orchestrator
uv run pytest -q
uv run relic standalone doctor --smoke --format table
uv run relic standalone smoke-regression --format table
```

Run the documented operator loop against at least one representative dataset:

```bash
uv run relic --root ~/analysis/release-check standalone doctor --smoke --format table
uv run relic --root ~/analysis/release-check --dry-run process --path /evidence/example.E01 --computer-label RELEASE-CHECK --profile windows-full --filesystem --workers 4 > ~/analysis/release-check/dry-process.json
CASE_ID="$(uv run python -c 'import json,sys; print(json.load(open(sys.argv[1]))["case_id"])' ~/analysis/release-check/dry-process.json)"
uv run relic --root ~/analysis/release-check report review-status --case "${CASE_ID}" --format table
uv run relic --root ~/analysis/release-check report runbook --case "${CASE_ID}" --format md
uv run relic --root ~/analysis/release-check report write-bundle --case "${CASE_ID}" --purpose review --output-dir ~/analysis/release-check/cases/"${CASE_ID}"/outputs/reports/review-bundle
uv run relic --root ~/analysis/release-check report handoff-package --case "${CASE_ID}" --bundle-dir ~/analysis/release-check/cases/"${CASE_ID}"/outputs/reports/review-bundle --output ~/analysis/release-check/cases/"${CASE_ID}"/outputs/reports/"${CASE_ID}"-handoff.zip
```

## Dependency Checks

- `standalone dependencies --format table` has no missing required tools on the
  release workstation.
- `standalone install-tool all --tools-dir ~/tools --env-file
  ~/tools/forensic-orchestrator.env` succeeds or known exceptions are documented.
- `source ~/tools/forensic-orchestrator.env` works in a fresh shell.

## Documentation

- README support statement is current.
- `docs/user-manual.md` command examples match the CLI.
- `docs/dependencies.md` and `docs/ubuntu-install.md` reflect current
  third-party tool behavior.
- Any known unsupported formats or case-specific limitations are documented.

## Tagging

```bash
git status --short
git tag -a vX.Y.Z -m "Relic vX.Y.Z"
git push origin vX.Y.Z
```

The release workflow builds distributions and uploads them as GitHub Actions
artifacts.
