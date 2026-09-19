---
title: Azure Key Vault
description: "Setup, authentication, and configuration for the Azure Key Vault provider."
---

## Setup

### Prerequisites

- An Azure subscription with a Key Vault (Standard or Premium SKU)
- A vault with your identity granted secret permissions (see below)
- Azure credentials available through one of the DefaultAzureCredential sources

### Access policy

Grant your identity the least-privileged built-in role (**Key Vault Secrets
User** for reads, **Key Vault Secrets Officer** for reads + writes) under the
vault's Access control (IAM), or the equivalent access-policy secret
permissions (`Get`, `List`, `Set`, `Delete`) on legacy access-policy vaults.

### Authentication

skret uses the Azure SDK's **DefaultAzureCredential** chain and never prompts:

1. `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` environment
   variables (service principal)
2. Managed identity (when running inside Azure compute)
3. Azure CLI login (`az login`)

Whichever source resolves first wins. For CI, the service-principal env vars
are the usual choice; locally, `az login` is enough.

### Configuration

One of `vault_url` or `vault_name` is required. Setting both requires them to
agree (the name derives `https://<name>.vault.azure.net`):

```yaml
environments:
  prod:
    provider: azure
    vault_name: my-vault          # derives https://my-vault.vault.azure.net
    # vault_url: https://my-vault.vault.azure.net/   # alternative (sovereign clouds need this)
    path: myapp-prod-             # optional name-prefix filter (see below)
```

For sovereign clouds (Azure Government, China), set `vault_url` explicitly —
`vault_name` derivation assumes the public cloud.

## Secret naming

Key Vault secret names accept only **alphanumeric characters and dashes**
(1–127 chars). skret keys are sanitized deterministically on *both* read and
write paths, so `skret set DB_URL` stores `DB-URL` and `skret get DB_URL`
reads it back:

| Rule | Example |
|------|---------|
| Disallowed characters become `-` | `app.config.v2` → `app-config-v2` |
| Consecutive dashes collapse | `a///b` → `a-b` |
| Leading/trailing dashes trim | `/myapp/KEY` → `myapp-KEY` |
| Names cap at 127 chars | — |

The mapping is deterministic but **not injective**: `db_url` and `db-url`
both store as `db-url`. Pick one spelling per key in `required:`/`exclude:`
lists (those lists are matched against the sanitized names skret reports).

The optional `path` field is a literal **name-prefix filter** applied by
`list`, `env`, and `run` — e.g. `path: myapp-prod-` scopes those commands to
names beginning with `myapp-prod-`. It is not a hierarchy and is never
prepended to keys.

## Versioning

Key Vault versions are 32-character hex IDs, while skret numbers versions
with 64-bit integers. skret folds the leading hex characters of each version
ID into that integer space deterministically; `skret history`, `rollback`,
and version-pinned launches all operate on the folded numbers and resolve
them back through the vault's version list. Two versions of one secret
colliding on the folded number is negligible, but the numbers are *skret*
identifiers, not Key Vault IDs — use the Azure portal/CLI with the full IDs
when you need the raw values.

Every `set` creates a new immutable version. `rollback` re-PUTs an old
version's value as a new version (versions themselves are never mutated).
`delete` performs a **soft delete** (recoverable for the vault's retention
window, 7–90 days); skret never purges.

## Metadata tags

skret mirrors secret metadata into Key Vault tags:

| skret metadata | Key Vault tag |
|----------------|---------------|
| `set --ttl` expiry | `skret-expires-at` (RFC3339) |
| description | `skret-description` |
| other tags | passed through, excluding reserved `skret-*` names |

The expires-at timestamp is authoritative: it wins over a user-supplied tag
of the same name. All tags ride in the same request as the value, so a write
commits value + tags atomically — there is no put-then-tag partial-commit
window. If a response is lost after the vault committed, skret reads the
latest version back and reconciles before reporting.

## Usage

```bash
# Set a secret (stored as a new version with skret tags)
skret set DB_URL "postgres://prod-host/db"

# Get a secret
skret get DB_URL

# List secrets (scope with the optional path prefix)
skret list

# Run with injected env vars
skret run -- node server.js

# History and rollback (folded version numbers)
SKRET_EXPERIMENTAL=1 skret history DB_URL
SKRET_EXPERIMENTAL=1 skret rollback DB_URL 3
```

## Quotas

| Resource | Limit |
|----------|-------|
| Secret value size | 25 KB |
| Transactions per 10 s per vault (Standard) | 2,000 (reads), 400 (writes) |
| Secret versions per secret | unlimited |

A value over 25 KB is rejected by the vault and surfaced as a provider error
(skret exit code **3**) — see [error codes](/reference/error-codes/).

## Security

- Values are encrypted at rest with the vault's key (Microsoft-managed or
  customer-managed; Premium SKUs support HSM-backed keys)
- Decryption happens at read time, never cached to disk
- Vault-level audit logging is available through Azure Monitor diagnostics
  (enable the `AuditEvent` category to capture every skret read/write)
