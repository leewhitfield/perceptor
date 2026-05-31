# File Listings

Relic generates file listings for filesystems, including NTFS, FAT, and exFAT
where supported by the mounted or parser workflow. These listings are stored in
`filesystem_entries`.

## Why They Matter

File listings are the first source of truth for questions such as:

- "What files are on this USB drive?"
- "List the contents of this image."
- "Does this volume contain `timeline.docx`?"
- "Show deleted files on this evidence item."

MCP clients should query stored listings before using FLS, mounting, or direct
image tooling.

## Query Through MCP

Use:

```text
relic_query_evidence_contents
relic_query_filesystem_listings
```

The MCP router will recommend these tools for contents and filesystem questions.

## Query Through Reports

Use file movement, removable media, and USB reports for interpreted context:

```bash
uv run relic --root ~/analysis/case-root report usb-files --case CASE_ID --format md
uv run relic --root ~/analysis/case-root report opened-from-removable-media --case CASE_ID --format md
uv run relic --root ~/analysis/case-root report file-movement-identity --case CASE_ID --format md
```

## Deleted Rows

Deleted filesystem rows are retained when the source inventory can identify
them. They can be used as candidates for deleted-file recovery.
