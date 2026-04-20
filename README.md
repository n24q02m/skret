<p align="center">
  <img src="https://skret.n24q02m.com/logo.svg" alt="skret" width="120">
</p>

<h1 align="center">skret</h1>

<p align="center">
  <strong>Secrets without the server.</strong><br>
  Cloud-provider secret manager CLI with Doppler/Infisical-grade developer experience.
</p>

<p align="center">
  <a href="https://github.com/n24q02m/skret/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/n24q02m/skret/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/n24q02m/skret/actions/workflows/cd.yml"><img alt="CD" src="https://github.com/n24q02m/skret/actions/workflows/cd.yml/badge.svg"></a>
  <a href="https://codecov.io/gh/n24q02m/skret"><img alt="codecov" src="https://codecov.io/gh/n24q02m/skret/graph/badge.svg"></a>
  <a href="https://goreportcard.com/report/github.com/n24q02m/skret"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/n24q02m/skret"></a>
  <a href="https://github.com/n24q02m/skret/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/n24q02m/skret?display_name=tag&sort=semver"></a>
  <a href="https://go.dev"><img alt="Go 1.26+" src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white"></a>
  <a href="https://github.com/python-semantic-release/python-semantic-release"><img alt="semantic-release" src="https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/n24q02m/skret"></a>
</p>

<p align="center">
  <a href="https://skret.n24q02m.com">Docs</a> ·
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="https://github.com/n24q02m/skret/discussions">Community</a> ·
  <a href="https://skret.n24q02m.com/guide/getting-started/">Getting started</a>
</p>

```sh
skret run -- make up-prod        # Inject secrets from AWS SSM into a command
skret import --from=doppler      # Migrate from Doppler
skret sync --to=github           # Push secrets to GitHub Actions
```

<p align="center">
  <img src="https://skret.n24q02m.com/demo.gif" alt="skret demo" width="820">
</p>

## Table of contents

- [Why skret?](#why-skret)
- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [Provider ranking](#provider-ranking)
- [Comparison vs Doppler and Infisical](#comparison-vs-doppler-and-infisical)
- [Documentation](#documentation)
- [Command overview](#command-overview)
- [Contributing](#contributing)
- [Sponsors](#sponsors)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Why skret?

Managing secrets across many repositories, VMs, and developer machines is painful:

- **Doppler** charges per user seat; the free tier maxes out at five projects.
- **Infisical self-host** has real ops overhead — database, web UI, container, upgrades.
- **Raw AWS SSM / GCP SM CLIs** lack the developer-friendly `run -- cmd` pattern that makes Doppler and Infisical pleasant.

skret gives you Doppler-grade DX on top of free cloud secret stores. A single Go binary, no server, no subscription, secrets stay inside the cloud account you already pay for.

## Features

- **Multi-provider backend**: AWS SSM Parameter Store today; OCI Vault, Azure Key Vault, GCP Secret Manager on the roadmap. Switch backends with one config line.
- **Zero-server architecture**: Direct cloud IAM. No self-hosted control plane, no license fees, no new billing surface.
- **Doppler-grade CLI**: `skret run -- your-cmd` injects secrets as env vars. Identical UX to `doppler run --`.
- **Migration-first**: Built-in importers for Doppler, Infisical, and `.env` files.
- **CI/CD syncers**: Push secrets to GitHub Actions repository secrets in one command.
- **Production-grade**: 93%+ test coverage, CodeQL security scanning, SBOM + cosign-signed release artifacts.
- **Cross-platform**: Linux, macOS, Windows — amd64 and arm64 binaries for each.

## Install

| Platform | One-shot script | Package manager |
|----------|-----------------|-----------------|
| **macOS / Linux** | `curl -fsSL https://skret.n24q02m.com/install.sh \| sh` | `brew install n24q02m/tap/skret` |
| **Windows** | `iwr -useb https://skret.n24q02m.com/install.ps1 \| iex` | `scoop bucket add n24q02m https://github.com/n24q02m/scoop-bucket && scoop install skret` |
| **Cross-OS managers** | `mise use -g aqua:n24q02m/skret@latest` | `nix shell github:n24q02m/skret-nix#skret` |
| **Go developers** | `go install github.com/n24q02m/skret/cmd/skret@latest` | — |
| **Direct binary** | Download from [Releases](https://github.com/n24q02m/skret/releases/latest) | — |

Verify the install and check the version:

```sh
skret --version
```

The `install.sh` and `install.ps1` scripts verify SHA256 checksums and (if `cosign` is available) the Sigstore signature before placing the binary. Source both scripts at [skret.n24q02m.com/install.sh](https://skret.n24q02m.com/install.sh) and [skret.n24q02m.com/install.ps1](https://skret.n24q02m.com/install.ps1) before piping to a shell if you prefer — both are short, POSIX-pure or PowerShell 5+.

## Quick start

```sh
# 1. Initialise .skret.yaml in your repo
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

See [Getting started](https://skret.n24q02m.com/guide/getting-started/) for the 5-minute guided tour.

## Provider ranking

Cost figures below use a representative scale: 17 repos × 340 secrets × 30,000 reads/month, `ap-southeast-1` (Singapore).

| Rank | Backend | Monthly cost | Recommended for |
|------|---------|--------------|-----------------|
| 1 | **AWS SSM Parameter Store (Standard)** | **$0** | Default — AWS-native or mixed-cloud |
| 2 | **OCI Vault (software-protected)** | **$0** | Users with OCI tenancy; best rotation lifecycle |
| 3 | **Azure Key Vault (Standard)** | **~$0.09** | Azure-native or multi-cloud DR |
| 4 | **GCP Secret Manager** | **~$20** | GCP-native workloads |
| 5 | **AWS Secrets Manager** | **~$136** | Only when managed rotation (RDS/Redshift) is required |

See [provider comparison](https://skret.n24q02m.com/reference/provider-comparison/) for the full feature matrix.

## Comparison vs Doppler and Infisical

| Feature | skret | Doppler | Infisical (self-host) |
|---------|-------|---------|------------------------|
| Server required | No | No (SaaS) | Yes (container + DB) |
| Cost (10 devs, 17 repos) | **$0** | $84/mo | ~$30/mo infra |
| `run -- cmd` DX | Yes | Yes | Yes |
| Multi-cloud storage backends | Yes | No | No |
| Migration from other tools | Yes | Limited | No |
| Sync to GitHub Actions | Built-in | Via integration | Via integration |
| Open source license | MIT | Proprietary | MIT (but complex) |
| Release artifact signing | Cosign + SBOM | n/a | n/a |

## Documentation

Full docs at **[skret.n24q02m.com](https://skret.n24q02m.com)**:

- [Getting started](https://skret.n24q02m.com/guide/getting-started/) — 5-minute tutorial
- [Installation](https://skret.n24q02m.com/guide/installation/) — every platform, every method
- [Configuration](https://skret.n24q02m.com/guide/configuration/) — `.skret.yaml` reference
- [Authentication](https://skret.n24q02m.com/guide/authentication/) — AWS SSO, OIDC, IAM
- [Provider comparison](https://skret.n24q02m.com/reference/provider-comparison/) — cost + features across AWS, OCI, Azure, GCP
- [Migrate from Doppler](https://skret.n24q02m.com/migration/from-doppler/)
- [Migrate from Infisical](https://skret.n24q02m.com/migration/from-infisical/)
- [Makefile patterns](https://skret.n24q02m.com/integrations/makefile-patterns/)
- [Troubleshooting](https://skret.n24q02m.com/guide/troubleshooting/)
- [FAQ](https://skret.n24q02m.com/faq/)

## Command overview

| Command | Purpose |
|---------|---------|
| `skret init` | Create `.skret.yaml` in the current repo |
| `skret run -- <cmd>` | Inject secrets as env vars and exec a command |
| `skret get <KEY>` | Print a single secret value |
| `skret env` | Dump all secrets in dotenv / JSON / YAML / export format |
| `skret set <KEY> <VALUE>` | Create or update a secret |
| `skret delete <KEY>` | Delete a secret |
| `skret list` | List secrets under the current environment path |
| `skret import --from=<source>` | Import from Doppler, Infisical, dotenv |
| `skret sync --to=<target>` | Sync to GitHub Actions, dotenv |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [contributing guide](https://skret.n24q02m.com/contributing/setup/).

```sh
git clone https://github.com/n24q02m/skret
cd skret
mise install          # Installs Go 1.26+, pnpm, golangci-lint
pre-commit install
go test -race ./...
```

## Sponsors

<p>
  <a href="https://github.com/sponsors/n24q02m"><img alt="GitHub Sponsors" src="https://img.shields.io/badge/Sponsor-n24q02m-EA4AAA?logo=githubsponsors"></a>
</p>

If skret saves your team the Doppler seat cost or the Infisical ops overhead, please consider sponsoring continued development.

## Acknowledgments

skret was inspired by [Doppler](https://www.doppler.com) and [Infisical](https://infisical.com) — teams who made CLI-first secrets management pleasant. It is built on [AWS SDK for Go v2](https://github.com/aws/aws-sdk-go-v2), [Cobra](https://github.com/spf13/cobra), and documented with [Astro Starlight](https://starlight.astro.build) on Cloudflare Pages.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © n24q02m
