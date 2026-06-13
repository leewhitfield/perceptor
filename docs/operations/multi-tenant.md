# Multi-Tenant Operations

Perceptor supports multi-tenant isolation, allowing a single server to host multiple independent examiners or investigations.

## Tenant Isolation Limits
Each tenant gets:
- A dedicated workspace directory (`/var/lib/perceptor/tenants/<tenant-id>`).
- A dedicated OpenSearch index (`forensic-content-<tenant-id>`).
- An isolated evidence directory (`/evidence/<tenant-id>`).
- A unique MCP Authorization Token.

## Creating a Tenant
```bash
perceptor tenant create --name "Examiner A"
```
*Output will provide the newly generated `tenant-id` and `token`.*

## Listing Tenants
```bash
perceptor tenant list --format table
```

## Deleting a Tenant
> [!WARNING]  
> This currently does not physically delete the tenant's data off disk. It only removes them from the registry. You must manually delete `/var/lib/perceptor/tenants/<tenant-id>`.

```bash
perceptor tenant delete --tenant-id <tenant-id>
```

## Retrieving a Token
```bash
perceptor tenant token --tenant-id <tenant-id>
```
Provide this token to the examiner. They will configure their local MCP client to send it as a Bearer token in the `Authorization` header.
