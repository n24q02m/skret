---
title: Configuration
description: "skret uses a `.skret.yaml` file in your project root to define environments, providers, and settings."
---

skret uses a `.skret.yaml` file in your project root to define environments, providers, and settings.

## Schema

```yaml
version: "1"              # Required. Config schema version.
project: myapp             # Optional. Project name.
default_env: prod          # Optional. Default environment.

environments:              # Required. At least one environment.
  prod:
    provider: aws          # Required. "aws" or "local".
    path: /myapp/prod      # Required for aws. SSM path prefix.
    region: us-east-1      # Optional for aws. AWS region.
    profile: production    # Optional for aws. AWS profile name.
    kms_key_id: arn:...    # Optional for aws. Custom KMS key.

  dev:
    provider: local        # Required."local" for YAML file.
    file: ./.secrets.dev.yaml  # Required for local. Path to secrets file.

required:                  # Optional. Secrets that must exist.
  - DATABASE_URL
  - API_KEY

exclude:                   # Optional. Secrets to exclude from injection.
  - DEBUG_TOKEN
```

## Discovery

skret walks from the current directory upward to find `.skret.yaml`, stopping at the git root (`.git` directory) or filesystem root.

## Precedence

Configuration values are resolved in this order (highest wins):

1. **CLI flags** — `--env`, `--provider`, `--path`, `--region`, `--profile`, `--file`
2. **Environment variables** — `SKRET_ENV`, `SKRET_PROVIDER`, `SKRET_PATH`, `SKRET_REGION`, `SKRET_PROFILE`
3. **Config file** — `.skret.yaml` values
4. **Defaults** — Built-in defaults

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SKRET_ENV` | Override target environment |
| `SKRET_PROVIDER` | Override provider |
| `SKRET_PATH` | Override secret path prefix |
| `SKRET_REGION` | Override AWS region |
| `SKRET_PROFILE` | Override AWS profile |
| `SKRET_LOG` | Log level (debug, info, warn, error) |
| `SKRET_LOG_FORMAT` | Log format (text, json) |

## Local Secrets File

For the `local` provider, secrets are stored in a YAML file:

```yaml
version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost/mydb"
  API_KEY: "dev-key-123"
  REDIS_URL: "redis://localhost:6379"
```

> **IMPORTANT:** Add `.secrets.*.yaml` to your `.gitignore`. The `skret init` command does this automatically.
