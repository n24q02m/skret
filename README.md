# skret

**Cloud-provider secret manager CLI wrapper with Doppler/Infisical-grade developer experience. Zero Lock-in. Zero Server.**

[![CI](https://github.com/n24q02m/skret/actions/workflows/ci.yml/badge.svg)](https://github.com/n24q02m/skret/actions/workflows/ci.yml)
[![CD](https://github.com/n24q02m/skret/actions/workflows/cd.yml/badge.svg)](https://github.com/n24q02m/skret/actions/workflows/cd.yml)
[![codecov](https://codecov.io/gh/n24q02m/skret/graph/badge.svg)](https://codecov.io/gh/n24q02m/skret)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Go Report Card](https://goreportcard.com/badge/github.com/n24q02m/skret)](https://goreportcard.com/report/github.com/n24q02m/skret)
[![semantic-release](https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white)](https://github.com/python-semantic-release/python-semantic-release)
[![License: MIT](https://img.shields.io/github/license/n24q02m/skret)](LICENSE)

```bash
skret run -- make up-prod        # Inject secrets from AWS SSM into a command
skret import --from=doppler      # Migrate from Doppler
skret sync --to=github           # Push secrets to GitHub Actions
```

## Why skret?

Managing secrets across many repositories, VMs, and developer machines is painful:

- **Doppler** charges per user seat, gets expensive at team scale.
- **Infisical self-host** has real ops overhead (DB, web UI, container).
- **Raw AWS SSM / GCP SM CLIs** lack the developer-friendly `run -- cmd` pattern that makes Doppler/Infisical pleasant.

skret gives you Doppler-grade DX on top of free cloud secret stores. A single Go binary, no server, no subscription.

## Features

- **Multi-provider backend**: AWS SSM Parameter Store today; OCI Vault, Azure Key Vault, GCP Secret Manager on the roadmap. Switch with one config line.
- **Zero-server architecture**: Direct cloud IAM. No self-hosted control plane, no license fees.
- **Doppler-grade CLI**: `skret run -- your-cmd` injects secrets as env vars. Identical UX to `doppler run --`.
- **Migration-first**: Built-in importers for Doppler, Infisical, and `.env` files.
- **CI/CD syncers**: Push secrets to GitHub Actions repository secrets in one command.
- **Production-grade**: 93%+ test coverage, CodeQL security scanning, SBOM + cosign-signed release artifacts.
- **Cross-platform**: Linux, macOS, Windows — amd64 and arm64 binaries for each.

## Install

```bash
# Homebrew (macOS, Linux) — coming soon
brew install n24q02m/tap/skret

# Scoop (Windows) — coming soon
scoop bucket add n24q02m https://github.com/n24q02m/scoop-bucket
scoop install skret

# Docker
docker pull ghcr.io/n24q02m/skret:latest

# go install
go install github.com/n24q02m/skret/cmd/skret@latest

# Direct binary download — see Releases
# https://github.com/n24q02m/skret/releases/latest
```

## Quick Start

```bash
# 1. Initialize .skret.yaml in your repo
skret init --provider=aws --path=/myapp/prod --region=ap-southeast-1

# 2. (Optional) Import existing secrets from Doppler
export DOPPLER_TOKEN=dp.pt.xxx
skret import --from=doppler \
  --doppler-project=myapp --doppler-config=prd \
  --to-path=/myapp/prod

# 3. Run your app with secrets injected
skret run -- make up-prod

# 4. Sync to GitHub Actions for CI/CD
export GITHUB_TOKEN=ghp_xxx
skret sync --to=github \
  --github-repo=myorg/myapp --from-env=prod
```

## Provider ranking (cost at scale: 17 repos × 340 secrets × 30k reads/month)

| Rank | Backend | Monthly cost | Recommended for |
|------|---------|-------------|-----------------|
| 1 | AWS SSM Parameter Store (Standard) | **$0** | Default — AWS-native or mixed-cloud |
| 2 | OCI Vault (software-protected) | **$0** | Best rotation; users with OCI tenancy |
| 3 | Azure Key Vault (Standard) | **~$0.09** | Azure-native or multi-cloud DR |
| 4 | GCP Secret Manager | **~$20** | GCP-native workloads |
| 5 | AWS Secrets Manager | **~$136** | Only for managed rotation (RDS/Redshift) |

See [provider comparison](https://skret.n24q02m.com/providers/comparison) for the full matrix.

## Documentation

Full docs at **[skret.n24q02m.com](https://skret.n24q02m.com)**:

- [Getting Started](https://skret.n24q02m.com/guide/getting-started) — 5-minute tutorial
- [Configuration](https://skret.n24q02m.com/guide/configuration) — `.skret.yaml` reference
- [Authentication](https://skret.n24q02m.com/guide/authentication) — AWS SSO, OIDC, IAM
- [Migration from Doppler](https://skret.n24q02m.com/migration/from-doppler)
- [Migration from Infisical](https://skret.n24q02m.com/migration/from-infisical)
- [Makefile patterns](https://skret.n24q02m.com/integrations/makefile-patterns)
- [Command reference](https://skret.n24q02m.com/reference/cli)
- [FAQ](https://skret.n24q02m.com/faq)

## Command overview

| Command | Purpose |
|---------|---------|
| `skret init` | Create `.skret.yaml` in the current repo |
| `skret run -- <cmd>` | Inject secrets as env vars and exec a command |
| `skret get <KEY>` | Print a single secret value |
| `skret env` | Dump all secrets in dotenv/JSON/YAML/export format |
| `skret set <KEY> <VALUE>` | Create or update a secret |
| `skret delete <KEY>` | Delete a secret |
| `skret list` | List secrets under the current environment path |
| `skret import --from=<source>` | Import from Doppler, Infisical, dotenv |
| `skret sync --to=<target>` | Sync to GitHub Actions, dotenv |

## Comparison vs Doppler and Infisical

| Feature | skret | Doppler | Infisical (self-host) |
|---------|-------|---------|----------------------|
| Server required | No | No (SaaS) | Yes (container + DB) |
| Cost (10 devs, 17 repos) | $0 | $84/mo | ~$30/mo infra |
| `run -- cmd` DX | Yes | Yes | Yes |
| Multi-cloud storage backends | Yes | No | No |
| Migration from other tools | Yes | Limited | No |
| Open source | Yes (MIT) | No | Yes (but complex) |
| Sync to GitHub Actions | Built-in | Via integration | Via integration |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [contributing/setup](https://skret.n24q02m.com/contributing/setup).

```bash
git clone https://github.com/n24q02m/skret
cd skret
mise install
pre-commit install
go test -race ./...
```

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
