# skret

[![CI](https://github.com/n24q02m/skret/actions/workflows/ci.yml/badge.svg)](https://github.com/n24q02m/skret/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/n24q02m/skret)](https://goreportcard.com/report/github.com/n24q02m/skret)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Cloud-provider secret manager CLI wrapper with Doppler/Infisical-grade developer experience.

> **skret** wraps cloud-provider secret managers (AWS SSM, GCP, Azure, OCI, Cloudflare) with a unified, ergonomic CLI. Think of it as `doppler` or `infisical` but for any cloud provider, with zero lock-in.

## Quick Start

```bash
# Initialize project
skret init --provider=aws --path=/myapp/prod --region=us-east-1

# Read secrets
skret get DATABASE_URL
skret list
skret env

# Write secrets
skret set API_KEY sk-new-secret-key
skret delete OLD_KEY --confirm

# Run with injected env vars
skret run -- node server.js

# Import from existing tools
skret import --from=dotenv --file=.env
skret import --from=doppler --doppler-project=myapp --doppler-config=prd

# Sync to external targets
skret sync --to=github --github-repo=owner/repo
skret sync --to=dotenv --file=.env.local
```

## Features

| Feature | Description |
|---------|-------------|
| **Multi-provider** | AWS SSM Parameter Store, local YAML (more coming) |
| **Multi-environment** | Dev, staging, prod via `.skret.yaml` config |
| **Import** | Migrate from Doppler, Infisical, dotenv files |
| **Sync** | Push secrets to GitHub Actions, dotenv files |
| **Run** | Inject secrets as env vars into any command |
| **Precedence** | CLI flags > env vars > config file > defaults |
| **Secret Redaction** | Automatic redaction of secrets in logs |
| **Cross-platform** | Linux, macOS, Windows (amd64, arm64) |

## Installation

### macOS (Homebrew)

```bash
brew install n24q02m/tap/skret
```

### Windows (Scoop)

```powershell
scoop bucket add n24q02m https://github.com/n24q02m/scoop-bucket
scoop install skret
```

### Go Install

```bash
go install github.com/n24q02m/skret/cmd/skret@latest
```

### Docker

```bash
docker pull ghcr.io/n24q02m/skret:latest
docker run --rm -v $(pwd):/app -w /app ghcr.io/n24q02m/skret list
```

### Binary Download

Download from [GitHub Releases](https://github.com/n24q02m/skret/releases).

## Configuration

Create `.skret.yaml` in your project root:

```yaml
version: "1"
default_env: prod
project: myapp

environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
    profile: production

  dev:
    provider: local
    file: ./.secrets.dev.yaml

required:
  - DATABASE_URL
  - API_KEY

exclude:
  - DEBUG_TOKEN
```

### Precedence Order

1. **CLI flags** (`--env`, `--provider`, `--path`, `--region`, `--profile`, `--file`)
2. **Environment variables** (`SKRET_ENV`, `SKRET_PROVIDER`, `SKRET_PATH`, `SKRET_REGION`)
3. **Config file** (`.skret.yaml`)
4. **Defaults**

## Commands

| Command | Description |
|---------|-------------|
| `skret init` | Initialize `.skret.yaml` in current directory |
| `skret get <KEY>` | Get a single secret value |
| `skret list` | List secrets (table/JSON output) |
| `skret env` | Dump secrets as dotenv/JSON/YAML/export |
| `skret set <KEY> <VALUE>` | Create or update a secret |
| `skret delete <KEY>` | Delete a secret |
| `skret run -- <cmd>` | Run command with injected env vars |
| `skret import` | Import from dotenv/Doppler/Infisical |
| `skret sync` | Sync to GitHub Actions/dotenv |

## Providers

### AWS SSM Parameter Store

Requires AWS credentials configured via standard methods (env vars, `~/.aws/credentials`, IAM roles).

```yaml
environments:
  prod:
    provider: aws
    path: /myapp/prod
    region: us-east-1
    profile: production  # optional
    kms_key_id: arn:aws:kms:...  # optional, for custom KMS
```

### Local YAML

For development and testing. Secrets stored in a local YAML file:

```yaml
# .secrets.dev.yaml
version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost/mydb"
  API_KEY: "dev-key-123"
```

## Development

```bash
# Build
go build -o skret ./cmd/skret

# Test
go test ./internal/...

# Test with coverage
go test -cover ./internal/...

# E2E tests
go test -v ./tests/e2e/...

# Build with version injection
go build -ldflags="-X github.com/n24q02m/skret/internal/version.Version=0.1.0" -o skret ./cmd/skret
```

## Architecture

```
cmd/skret/          → Entry point
internal/
  cli/              → Cobra commands (init, get, list, env, set, delete, run, import, sync)
  config/           → Config schema, loader, resolver (.skret.yaml)
  exec/             → Env builder for subprocess injection
  importer/         → Import from dotenv, Doppler, Infisical
  logging/          → Structured logging with secret redaction
  provider/         → SecretProvider interface + registry
    aws/            → AWS SSM Parameter Store provider
    local/          → Local YAML file provider
  syncer/           → Sync to dotenv, GitHub Actions
  version/          → Version info (ldflags injection)
tests/e2e/          → End-to-end CLI tests
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE) © n24q02m
