---
title: GCP Secret Manager
description: "Setup, minimum IAM roles, provider-specific notes."
---

## Setup

### Prerequisites

- A GCP project with the Secret Manager API enabled
  (`gcloud services enable secretmanager.googleapis.com`)
- Application Default Credentials configured (one of the three standard ways
  below -- skret stores no GCP credential of its own)

### Authentication

skret's `gcp` provider authenticates exclusively through **Application
Default Credentials (ADC)**:

1. `GOOGLE_APPLICATION_CREDENTIALS` pointing at a service-account key file,
2. `gcloud auth application-default login` (developer workstations), or
3. Workload identity when skret runs on GCP infrastructure (GCE, GKE,
   Cloud Run, Cloud Build -- no configuration needed).

When none of these resolve, every command fails fast with exit code **4**
(auth) and the three remedies printed inline.

### IAM Roles

Minimum required permissions for a dedicated service account:

```bash
# Read/write on secrets in one project (covers get, set, list, history, delete)
gcloud projects add-iam-policy-binding MY_PROJECT \
  --member="serviceAccount:skret@MY_PROJECT.iam.gserviceaccount.com" \
  --role="roles/secretmanager.admin"
```

For read-only workflows (`run`, `env`, `get`, `list`) use
`roles/secretmanager.secretAccessor` + `roles/secretmanager.viewer` instead.

### Configuration

```yaml
environments:
  prod:
    provider: gcp
    project: my-gcp-project   # Required. GCP project id (GOOGLE_CLOUD_PROJECT overrides).
    region: us-east1          # Optional. GCP location for regional secrets; omit for global.
    kms_key_id: projects/my-gcp-project/locations/global/keyRings/skret/cryptoKeys/main  # Optional CMEK.
```

GCP secret ids are **flat** -- no path hierarchy exists. Keep `path` empty
(config validation rejects a non-empty `path` for gcp environments) and
isolate environments by **project**, or by naming convention
(`prod-DATABASE_URL`). Keys must match `^[a-zA-Z0-9_-]{1,255}$`; anything
else is rejected before an API call with an actionable error.

## Usage

```bash
# Set a secret (creates the secret on first write, then a version)
skret set DATABASE_URL "postgres://prod-host/db"

# Get a secret (auto-decrypts)
skret get DATABASE_URL

# List all secrets in the project
skret list

# Run with injected env vars
skret run -- node server.js
# DATABASE_URL=postgres://prod-host/db is injected
```

## Quotas

| Resource | Limit |
|----------|-------|
| Secret value size | 64 KiB (skret rejects larger values locally before any API call) |
| Secret id length | 1-255 chars, `[a-zA-Z0-9_-]` |
| Labels/annotations per secret | 64 entries, lowercase `[a-z0-9_-]`, <=63 bytes each |

A value over 64 KiB fails with a provider error (skret exit code **3**) --
see [error codes](/reference/error-codes/). For larger payloads see the
[provider comparison](/providers/comparison/).

## Metadata mapping

skret mirrors `SecretMeta` into GCP-native metadata:

| skret metadata | GCP target | Notes |
|----------------|------------|-------|
| user tags | secret **labels** | Must satisfy GCP label rules (lowercase). |
| description | annotation `skret-description` | Secret Manager has no description field. |
| `--ttl` expiry | annotation `skret-expires-at` | RFC3339 timestamp, wins over a user annotation of the same name. |

## Security

- Values are encrypted at rest with Google-managed keys by default, or with
  your own key via `kms_key_id` (CMEK; rides automatic replication globally
  and user-managed replication when `region` is set).
- Decryption happens at read time, never cached to disk.
- IAM controls access per secret and per project.
- `skret delete` soft-deletes (GCP keeps the secret restorable for 30 days);
  listing excludes it once all versions are gone.

## Doctor

`skret doctor` probes gcp environments with one bounded 1-result listing
(never reads a value) and classifies credential failures as auth errors with
the ADC remedies.
