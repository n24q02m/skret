---
title: OCI Vault
description: "Setup, minimum IAM policy, and provider-specific notes for OCI Vault."
---

## Setup

### Prerequisites

- An OCI tenancy with a vault in your compartment (Vaults → Create Vault in the OCI console; the **default vault** with software-protected master keys is free)
- A **software-protected** master encryption key in the same vault (free tier; `key_id` below)
- OCI credentials for the SDK: an API key in `~/.oci/config`, `OCI_CLI_*` environment variables, or an instance principal

### IAM Policy

Minimum policy for a group running skret:

```text
Allow group skret-users to manage secret-family in compartment myapp
Allow group skret-users to read vaults in compartment myapp
Allow group skret-users to use key-delegate in compartment myapp
  where target.key.id = 'ocid1.key.oc1..example'
```

`use key-delegate` lets the Vault service use your master key to encrypt and
decrypt secret content; without it every read and write fails with an auth
error. For read-only use (CI/CD), downgrade `manage secret-family` to
`read secret-family` plus `read secret-bundles`.

### Authentication

skret resolves OCI auth in the OCI CLI's precedence:

1. `OCI_CLI_AUTH=instance_principal` — use the compute instance's identity
2. `OCI_CLI_USER`, `OCI_CLI_TENANCY`, `OCI_CLI_FINGERPRINT`, `OCI_CLI_KEY_FILE`
   (plus optional `OCI_CLI_PASS_PHRASE`) — API key from the environment,
   composed over the config file (the environment wins per field)
3. `~/.oci/config` (or `OCI_CLI_CONFIG_FILE`) with profile
   `OCI_CLI_PROFILE` > the environment's `profile` > `DEFAULT`

`region` in the environment config overrides the region from any auth
source.

### Configuration

```yaml
environments:
  prod:
    provider: oci
    path: /myapp/prod
    region: ap-singapore-1
    compartment_id: ocid1.compartment.oc1..xxx  # Required
    vault_id: ocid1.vault.oc1..yyy              # Required
    key_id: ocid1.key.oc1..zzz                  # Required for `skret set` of new secrets
    profile: DEFAULT                            # Optional. Profile in ~/.oci/config
```

`key_id` is only consulted when skret creates a secret that does not exist
yet; updates keep the secret's existing master key. Use a
software-protected key to stay on the free tier.

## Key mapping

OCI secret names are flat, unique per vault, and may only contain letters,
digits, `.`, `-`, `_` (1–255 chars). skret encodes its path-prefixed keys:

```text
path "/myapp/prod" + key "/myapp/prod/DATABASE_URL"
  -> secret name "myapp-prod_DATABASE_URL"
```

The path becomes a name prefix (its `/` become `-`), a single `_` separates
prefix and leaf, and any `/` inside a leaf is stored as `-`. Keys listed by
skret are decoded back under the configured prefix, so commands like
`skret get /myapp/prod/DATABASE_URL` behave exactly as on AWS. Choose vault
paths whose `/`-vs-`-` spellings cannot collide (or use one vault per
environment); a genuine collision is rejected by OCI on create.

## Usage

```bash
# Set a secret (base64-encoded into a new secret version)
skret set /myapp/prod/DATABASE_URL "postgres://prod-host/db"

# Get a secret (decoded automatically)
skret get /myapp/prod/DATABASE_URL

# List all secrets under path
skret list

# Run with injected env vars (path prefix stripped)
skret run -- node server.js
```

## Versioning, deletion and rotation

- Every `skret set` on an existing secret uploads a **new secret version**
  (OCI `UpdateSecret`); `skret history` and `skret rollback` see every
  version with its value.
- `skret delete` schedules the secret for **immediate deletion** (OCI
  default when no deletion time is given). Until OCI purges the deleted
  secret, the vault reserves its name — recreating the same secret name
  before the purge fails at the provider level (exit code 3).
- `--ttl` expiry metadata is mirrored to the `skret-expires-at` freeform
  tag, exactly like the AWS provider.

## Quotas

| Resource | Limit |
|----------|-------|
| Secret content size (via skret) | 25 KB |
| Secret name length | 255 characters |
| Default vault | Free (150 secrets, software-protected keys) |

A value over 25 KB fails with OCI's `LimitExceeded`-class error, surfaced as
a provider error (skret exit code **3**) — see [error
codes](/reference/error-codes/).

## Security

- Secret content is base64-encoded into OCI secret bundles and encrypted at
  rest with your vault's master key; decryption happens at read time and is
  never cached to disk
- IAM policies scope access per compartment and vault; `use key-delegate`
  is the only key permission skret needs
- API calls are covered by OCI Audit; key completion and `skret list`
  listings never decrypt values
