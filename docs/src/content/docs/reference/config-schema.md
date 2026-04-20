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
    provider: aws           # Required. Provider type: "aws" or "local".
    path: /myapp/prod       # Required for aws. SSM parameter path prefix.
    region: us-east-1       # Optional for aws. AWS region (falls back to AWS_REGION).
    profile: production     # Optional for aws. AWS profile name (falls back to AWS_PROFILE).
    kms_key_id: alias/aws/ssm  # Optional for aws. KMS key for SecureString encryption.

  dev:
    provider: local         # Required. "local" for YAML-file-based secrets.
    file: ./.secrets.dev.yaml  # Required for local. Path to the secrets file.

required:                   # Optional. List of secret keys that must exist.
  - DATABASE_URL            # skret fails fast if any required key is missing.
  - REDIS_URL

exclude:                    # Optional. Keys excluded from injection by run/env.
  - GITHUB_TOKEN
  - DEBUG_TOKEN
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

### Environment Fields

| Field | Type | Required | Provider | Description |
|-------|------|----------|----------|-------------|
| `provider` | string | Yes | All | Provider type. Supported: `"aws"`, `"local"`. |
| `path` | string | Yes | `aws` | SSM parameter path prefix. Must start with `/`. |
| `region` | string | No | `aws` | AWS region. Falls back to `AWS_REGION` env var. |
| `profile` | string | No | `aws` | AWS credential profile name. Falls back to `AWS_PROFILE` env var. |
| `kms_key_id` | string | No | `aws` | KMS key ID or alias for SecureString encryption. Defaults to the AWS-managed SSM key (`alias/aws/ssm`). |
| `file` | string | Yes | `local` | Path to the local secrets YAML file. Relative paths are resolved from the `.skret.yaml` location. |

## Validation Rules

skret validates the config at load time and fails fast on errors:

1. `version` must be `"1"` (the only supported version)
2. `environments` must contain at least one entry
3. `default_env`, if set, must reference an existing environment name
4. Each environment must have a `provider` field
5. AWS environments must have a `path` field
6. Local environments must have a `file` field
7. Unknown provider names are rejected

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

  staging:
    provider: aws
    path: /knowledgeprism/staging
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

### CI-only (no local provider)

```yaml
version: "1"
default_env: prod

environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1

  staging:
    provider: aws
    path: /myapp/staging
    region: us-east-1
```
