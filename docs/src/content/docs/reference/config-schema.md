---
title: Config Schema Reference
description: "Complete reference for the `.skret.yaml` configuration file."
---

Complete reference for the `.skret.yaml` configuration file.

## Full Schema

```yaml
# .skret.yaml
version: "1"                # Required. Schema version. Only "1" is supported.
project: myapp              # Optional. Project name for display/logging.
default_env: prod           # Optional. Default environment when --env is not specified.

environments:               # Required. At least one environment must be defined.
  prod:
    provider: aws           # Required. Provider type: "aws", "local", "gcp", or "oci".
p/prod       # Required for aws. SSM parameter path prefix.
    region: us-east-1       # Optional for aws/oci. Provider region.
    profile: production     # Optional for aws/oci. Credential profile name.
    kms_key_id: alias/aws/ssm  # Optional for aws. KMS key for SecureString encryption.
    compartment_id: ocid1.compartment.oc1..xxx  # Required for oci. Compartment OCID.
    vault_id: ocid1.vault.oc1..yyy              # Required for oci. Vault OCID.
    key_id: ocid1.key.oc1..zzz                  # Optional for oci. Master key for new secrets.

  gcp-prod:
    provider: gcp
    project: my-gcp-project  # Required for gcp. Project id (GOOGLE_CLOUD_PROJECT overrides).
    region: us-east1         # Optional for gcp. GCP location for regional secrets; omit for global.
    kms_key_id: projects/my-gcp-project/locations/global/keyRings/skret/cryptoKeys/main  # Optional CMEK for gcp.

  dev:
    provider: local         # Required. "local" for YAML-file-based secrets.
    file: ./.secrets.dev.yaml  # Required for local. Path to the secrets file.
    encrypted: true         # Optional. Store the file as an encrypted envelope (see `skret keys`).
    audit_log: ./trails/audit-dev.log  # Optional. Audit trail path (default: .skret-audit.log next to the secrets file).

required:                   # Optional. List of secret keys that must exist.
  - DATABASE_URL            # skret fails fast if any required key is missing.
  - REDIS_URL

exclude:                    # Optional. Keys excluded from injection by run/env.
  - GITHUB_TOKEN
  - DEBUG_TOKEN

sync:                       # Optional. Declared targets for `skret sync` / `skret hub push`.
  targets:
    - type: github          # "github" | "cloudflare" | "dotenv" | "gitlab" | "terraform" | "k8s" (alias "k8s-manifest")
      repo: myorg/myapp     # Required for github. owner/repo.
      no_overwrite: true    # Optional. Only write keys absent at this target; never overwrites.
    - type: cloudflare
      worker: my-worker     # One of worker/pages required for cloudflare.
      account: ${CLOUDFLARE_ACCOUNT_ID}  # Required for cloudflare. Supports ${VAR} expansion.
    - type: gitlab
      project: mygroup/myapp  # Required for gitlab. Project id or group/project path.
      masked: true            # Optional for gitlab. Marks variables masked.
      protected: true         # Optional for gitlab. Marks variables protected.
    - type: terraform
      file: skret.auto.tfvars # Optional for terraform. Defaults to "terraform.tfvars".
    - type: k8s
      file: deploy/secret.yaml # Optional for k8s. Defaults to stdout ("-").
      name: myapp-secrets      # Optional for k8s. metadata.name; default "skret-secrets".
      namespace: prod          # Optional for k8s. metadata.namespace.
    - type: dotenv
      file: .env.sync       # Optional for dotenv. Defaults to ".env".
  hub:
    url: https://vault.example.com  # Optional. Base URL for `skret hub push`.

notify:                     # Optional. Webhook notifications fired after successful secret mutations.
  webhook_url: https://hooks.example.com/skret  # Required when notify is present. One URL or a YAML list of URLs.
  events:                   # Optional. Filter which events fire; omit for all.
    - set
    - delete
    - rotate
    - sync
  secret: ${NOTIFY_SECRET}  # Optional. HMAC-SHA256 signing key; receivers verify the X-Skret-Signature header.
```

## Field Reference

### Top-Level Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `version` | string | Yes | -- | Config schema version. Must be `"1"`. |
| `project` | string | No | -- | Project name. Used in logging and display. |
| `default_env` | string | No | -- | Environment used when `--env` is not specified. Must match a key in `environments`. If omitted and only one environment exists, that environment is used automatically. |
| `environments` | map | Yes | -- | Map of environment name to environment config. At least one entry required. |
| `required` | list | No | `[]` | Secret keys that must be present. Commands fail with exit code 2 if any are missing. |
| `exclude` | list | No | `[]` | Secret keys excluded from `run` and `env` output. |
| `sync` | map | No | -- | Declared sync targets and hub endpoint for `skret sync` / `skret hub push`. See [Sync Fields](#sync-fields). |
| `notify` | map | No | -- | Webhook notifications fired after successful secret mutations (`set`/`delete`/`rotate`/`sync`). See [Notify Fields](#notify-fields). |

### Environment Fields

| Field | Type | Required | Provider | Description |
|-------|------|----------|----------|-------------|
| `provider` | string | Yes | All | Provider type. Supported: `"aws"`, `"local"`, `"gcp"`, `"oci"`. |
| `path` | string | Yes | `aws` | SSM parameter path prefix. Must start with `/`. |
| `region` | string | No | `aws`, `gcp`, `oci` | AWS region (`aws`, falls back to `AWS_REGION`), GCP location for regional secrets (`gcp`, omit for global), or OCI region (`oci`, falls back to the auth source's region / `OCI_CLI_REGION`). |
| `profile` | string | No | `aws`, `oci` | AWS credential profile name (`aws`, falls back to `AWS_PROFILE`) or profile in `~/.oci/config` (`oci`, falls back to `OCI_CLI_PROFILE` then `DEFAULT`). |
| `kms_key_id` | string | No | `aws`, `gcp` | `aws`: KMS key ID or alias for SecureString encryption (defaults to the AWS-managed SSM key `alias/aws/ssm`). `gcp`: CMEK key resource name for new secrets; rides automatic replication globally and user-managed replication when `region` is set. |
| `project` | string | Yes | `gcp` | GCP project id. `GOOGLE_CLOUD_PROJECT` overrides the config value. |
| `compartment_id` | string | Yes | `oci` | OCID of the compartment holding the vault. |
| `vault_id` | string | Yes | `oci` | OCID of the OCI vault where secrets live. |
| `key_id` | string | No | `oci` | OCID of the software-protected master encryption key used when creating new secrets (updates keep the secret's existing key). |
ng | Yes | `local` | Path to the local secrets YAML file. Relative paths are resolved from the `.skret.yaml` location. |
| `encrypted` | bool | No | `false` | `local` only. Write-side encryption intent: when `true`, saves store the file as a keystore envelope (`skret-encrypted-v1`, argon2id + XChaCha20-Poly1305). Reads auto-detect an encrypted file on disk regardless of this flag. Set up with `skret keys init --encrypt-existing`. |
| `audit_log` | string | No | `local` | Where the append-only audit trail lives (default: `.skret-audit.log` next to the secrets file). `skret set`/`rotate`/`delete` append one JSONL line per mutation — timestamp, op, key names, env, actor, never values — and `skret audit` renders it. |

### Sync Fields

`sync` declares reusable routes for [`skret sync`](/guide/sync/) and the vault dashboard endpoint for [`skret hub push`](/guide/hub/). Both fields are optional — omitting `sync` entirely preserves the pre-sync-fabric, flags-only behavior of `sync`.

| Field | Type | Required | Description |
|-------|------|----------|--------------|
| `sync.targets` | list | No | Declared sync destinations. A bare `skret sync` pushes to every entry; `--to` filters by `type`. |
| `sync.hub` | map | No | Vault dashboard config for `skret hub push`. |
| `sync.hub.url` | string | No | Hub base URL. Overridden by `--hub-url`. |

### Sync Target Fields (`sync.targets[]`)

| Field | Type | Required | Target | Description |
|-------|------|----------|--------|-------------|
| `type` | string | Yes | All | `"github"`, `"cloudflare"`, `"dotenv"`, `"gitlab"`, `"terraform"`, or `"k8s"` (alias `"k8s-manifest"`). |
| `repo` | string | Yes | `github` | `owner/repo`. Pushed as a GitHub Actions repository secret (sealed-box encrypted). Auth via `GITHUB_TOKEN`. |
| `worker` | string | One of `worker`/`pages` | `cloudflare` | Cloudflare Worker script name. Secrets pushed via the Workers secrets API. |
| `pages` | string | One of `worker`/`pages` | `cloudflare` | Cloudflare Pages project name. Secrets pushed as production environment variables via a partial-merge PATCH — only the synced keys are sent; existing variables outside that set are untouched. |
| `account` | string | Yes | `cloudflare` | Cloudflare account ID. Supports `${VAR}` expansion (e.g. `${CLOUDFLARE_ACCOUNT_ID}`) so the ID need not be committed literally. Auth via `CLOUDFLARE_API_TOKEN`. |
| `project` | string | Yes | `gitlab` | Project ID or `group/project` path. Secrets pushed as CI/CD variables via the project variables API. Auth via `GITLAB_TOKEN`. |
| `masked` | bool | No | `gitlab` | Marks CI/CD variables masked. The value must satisfy GitLab masking requirements or the API rejects the write. |
| `protected` | bool | No | `gitlab` | Marks CI/CD variables protected (exposed only to protected branches/tags). |
| `file` | string | No | `dotenv`, `terraform`, `k8s` | Output file path. `dotenv` defaults to `.env`; `terraform` defaults to `terraform.tfvars`; `k8s` defaults to stdout (`-` also means stdout). |
| `name` | string | No | `k8s` | `metadata.name` of the generated Secret. Defaults to `skret-secrets`. |
| `namespace` | string | No | `k8s` | `metadata.namespace` of the generated Secret. Omitted when unset. |
| `no_overwrite` | bool | No | All | Only write keys absent at this target; existing keys are never overwritten. Rotation = delete the key at the target, the next sync repopulates it from the provider. |
| `base_url` | string | No | `github`, `gitlab` | Override the target API endpoint (GitHub Enterprise, self-managed GitLab). Optional. |

Exactly one of `worker`/`pages` must be set per `cloudflare` target — setting both, or neither, fails validation. `GITHUB_TOKEN`, `CLOUDFLARE_API_TOKEN`, and `GITLAB_TOKEN` are read from the environment at sync time and are never stored in `.skret.yaml`.

### Notify Fields

`notify` fires webhook notifications after successful secret mutations. The feature is off unless the block is present; payloads carry key names and event metadata only — secret values are never included.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `notify.webhook_url` | string or list | Yes (when `notify` is present) | Absolute `http(s)` URL to POST the JSON payload to. Accepts a single URL or a YAML list for fan-out. |
| `notify.events` | list | No | Which mutation events fire: `set`, `delete`, `rotate`, `sync`. Omit for all of them. |
| `notify.secret` | string | No | HMAC-SHA256 signing key. Each request carries `X-Skret-Signature: sha256=<hex>` computed over the raw request body; receivers recompute it to verify authenticity. |

Payload shape (one POST per event; `sync`/`rotate` fire once per completed target):

```json
{
  "event": "set",
  "key_names": ["/myapp/prod/API_KEY"],
  "env": "prod",
  "timestamp": "2026-09-19T12:00:00Z",
  "actor": "ci"
}
```

`timestamp` is RFC3339 UTC; `actor` is only present when `SKRET_ACTOR` is set (e.g. `SKRET_ACTOR=ci` in a pipeline). Delivery is timeout-bounded (5s per attempt) and retries once on a 5xx response. A delivery failure never fails the mutation: it warns on stderr, or fails the command after the fact when `--strict-notify` is passed.

## Validation Rules

skret validates the config at load time and fails fast on errors:

1. `version` must be `"1"` (the only supported version)
2. `environments` must contain at least one entry
3. `default_env`, if set, must reference an existing environment name
4. Each environment must have a `provider` field
5. AWS environments must have a `path` field
6. GCP environments must have a `project` field, and `path` must be empty (GCP secret ids are flat; isolate environments by project)
7. OCI environments must have `compartment_id` and `vault_id` fields
8. Local environments must have a `file` field
9. Unknown provider names are rejected
10. Each `sync.targets` entry must have a known `type` (`github`, `cloudflare`, `dotenv`, `gitlab`, `terraform`, or `k8s`)
11. `github` sync targets must have a `repo` field
12. `cloudflare` sync targets must set exactly one of `worker`/`pages`
13. `gitlab` sync targets must have a `project` field
14. `notify.webhook_url` must be present when the `notify` block is, and every URL must be absolute `http(s)`
15. `notify.events` entries must be known events (`set`, `delete`, `rotate`, `sync`)
ider names are rejected
9. Each `sync.targets` entry must have a known `type` (`github`, `cloudflare`, `dotenv`, `gitlab`, `terraform`, or `k8s`)
10. `github` sync targets must have a `repo` field
11. `cloudflare` sync targets must set exactly one of `worker`/`pages`
12. `gitlab` sync targets must have a `project` field
13. `notify.webhook_url` must be present when the `notify` block is, and every URL must be absolute `http(s)`
14. `notify.events` entries must be known events (`set`, `delete`, `rotate`, `sync`)

## Config Discovery

skret walks from the current directory upward to find `.skret.yaml`, stopping at:

- The git root (directory containing `.git`)
- The filesystem root

This allows you to place `.skret.yaml` at the repository root and run skret from any subdirectory.

## Local Secrets File Format

The local provider reads secrets from a YAML file:

```yaml
version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost:5432/mydb"
  API_KEY: "dev-key-123"
  REDIS_URL: "redis://localhost:6379/0"
```

This file should always be gitignored. `skret init` adds `.secrets.*.yaml` to `.gitignore` automatically.

## Environment Variable Overrides

Every config field can be overridden via environment variables or CLI flags:

| Config Field | CLI Flag | Env Var | Precedence |
|---|---|---|---|
| `default_env` | `--env` | `SKRET_ENV` | Flag > Env > Config |
| `provider` | `--provider` | `SKRET_PROVIDER` | Flag > Env > Config |
| `path` | `--path` | `SKRET_PATH` | Flag > Env > Config |
| `region` | `--region` | `SKRET_REGION`, `AWS_REGION` | Flag > Env > Config |
| `profile` | `--profile` | `SKRET_PROFILE`, `AWS_PROFILE` | Flag > Env > Config |
| `project` (gcp) | -- | `GOOGLE_CLOUD_PROJECT` | Env > Config |
| `file` | `--file` | -- | Flag > Config |

## Examples

### Single environment (minimal)

```yaml
version: "1"
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
```

### Multi-environment with local dev

```yaml
version: "1"
project: knowledgeprism
default_env: prod

environments:
  prod:
    provider: aws
    path: /knowledgeprism/prod
    region: ap-southeast-1

  dev:
    provider: local
    file: ./.secrets.dev.yaml

required:
  - DATABASE_URL
  - REDIS_URL
  - OPENAI_API_KEY

exclude:
  - GITHUB_TOKEN
```

Environment names are free-form — use whatever your team is comfortable with (`prod`, `dev`, `staging`, `qa`, `preview`, `test`, etc.). skret does not prescribe a fixed set. The examples above pick `prod` + `dev` as the minimal pair; add more entries if you need them.

### CI-only (no local provider)

```yaml
version: "1"
default_env: prod

environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
```
