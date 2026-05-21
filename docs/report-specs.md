# Report Specs

Report specs let plugins add read-only reports without adding Python code to
`forensic_orchestrator/reports.py`.

Specs are YAML entries with a top-level `reports` list. They can be embedded in
the same YAML passed to `--plugin`, placed in a `report_specs/` directory beside
that plugin file, or installed under the built-in
`forensic_orchestrator/plugins/report_specs/` directory. Additional directories
can be provided with `FORENSIC_REPORT_SPEC_DIRS`, separated by the platform path
separator.

```yaml
reports:
  - name: mft-recent
    title: Recent MFT entries
    description: Recent MFT rows from the DuckDB analytics store.
    store: duckdb
    parameters:
      - case_id
      - limit
    columns:
      - source_csv
      - file_name
      - parent_path
      - entry_number
      - sequence_number
      - row_number
    query: |
      SELECT source_csv, file_name, parent_path, entry_number, sequence_number, row_number
      FROM mft_entries
      WHERE case_id = ?
      ORDER BY row_number
      LIMIT ?
```

Constraints:

- `name` must be lowercase letters, numbers, hyphens, or underscores.
- `store` is `duckdb` or `sqlite`; artifact reports should normally use `duckdb`.
- `query` must be a single read-only `SELECT` or `WITH` query.
- Supported parameters are `case_id` and `limit`; list them in the same order as
  the query placeholders.
- Specs should return parsed fields and references only. File bodies, email
  bodies, chat content, binary data, and raw JSON belong in OpenSearch or source
  files, not report-spec query output.

Run specs with:

```bash
uv run python -m forensic_orchestrator.cli report specs
uv run python -m forensic_orchestrator.cli report spec --case <case-id> --name mft-recent --format table
uv run python -m forensic_orchestrator.cli --plugin ./my-plugin.yaml report spec --case <case-id> --name <plugin-report>
```
