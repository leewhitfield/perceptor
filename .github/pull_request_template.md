## Summary

Describe the change and why it is needed.

## Safety Checklist

- [ ] Does this touch evidence access, mounting, extraction, recovery, carving, or archive expansion?
- [ ] Does this expose or modify network services?
- [ ] Does this modify processing behavior, parser behavior, report generation, or MCP routing?
- [ ] Does this require authentication, authorization, tokens, credentials, or other secrets?
- [ ] Has this been tested with read-only evidence or read-only evidence mounts where applicable?

## Evidence Handling

If this changes evidence access, explain how original evidence remains read-only
and where derived outputs are written.

## Network and MCP Impact

If this exposes network services or MCP tools, explain the bind address,
authentication model, permission gates, and audit logging.

## Secrets

Do not include real secrets in the PR. Use `.env.example` placeholders for
documentation or configuration examples.

## Tests

List the commands run and summarize any skipped or failing checks.
