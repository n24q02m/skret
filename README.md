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
- [Comparison vs alternatives](#comparison-vs-alternatives)
- [Documentation](#documentation)
- [Command overview](#command-overview)
- [Contributing](#contributing)
- [Sponsors](#sponsors)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Why skret?

CLI wrappers that inject cloud secrets into a `run -- cmd` invocation already exist — `teller`, `novops`, `summon`, and a long tail of single-backend tools like `chamber`. What was missing for our use case was a single binary that combines:

1. **Migration importers** for Doppler, Infisical, and `.env` — so a team can leave a paid SaaS without rewriting deploy pipelines.
2. **CI/CD sync** that pushes the same secret set to GitHub Actions in one command, with hash-based drift detection.
3. **Production-grade release artifacts** — cosign signatures, SBOMs, reproducible builds — so the binary itself can sit on a build agent without separate hardening.
4. **Doppler-grade DX** (`skret run -- your-cmd`) on top of cloud-native IAM, no self-hosted control plane, no per-seat licence.

If you only need a single-cloud injector and you don't care about migration or CI sync, `teller` or `summon` may already be enough — see the [comparison table](#comparison-vs-alternatives) for the honest trade-offs.

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
skret setup            # pick provider + path, then authenticate (once)
skret run -- <command> # run anything with secrets injected
```

That's the whole loop — same shape as `doppler setup && doppler run`.
`skret setup` authenticates once (SSO refreshes silently for the whole
session, or a stored access key) so you never re-run `aws login`.

Or step by step:

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

# 5. Re-sync, skip secrets that haven't changed since the last successful run
skret sync --to=github --github-repo=myorg/myapp --skip-unchanged

# 6. See what differs between staging and prod (values are never printed)
skret diff staging prod
skret diff staging prod --show-hash        # confirm which values changed via sha256[:8]
skret diff prod --to=github --github-repo=myorg/myapp   # presence-only (github is write-only)
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

## Comparison vs alternatives

Audited 2026-05-01 against the latest release of each tool. The comparison covers three SaaS / self-host secret managers (Doppler, Infisical, Bitwarden Secrets Manager) and three OSS CLI wrappers in skret's design space (teller, novops, summon).

| Feature | skret | Doppler | Infisical | Bitwarden SM | teller | novops | summon |
|---|---|---|---|---|---|---|---|
| Type | OSS CLI | SaaS | SaaS / self-host | SaaS / self-host | OSS CLI | OSS CLI | OSS CLI |
| Language | Go 1.26 | proprietary | TypeScript | Rust | Rust | Rust | Go |
| Licence | MIT | proprietary | MIT (complex) | GPL-3.0 (CLI) | Apache-2.0 | LGPL-3.0 | MIT |
| Server / control plane | none | none (SaaS) | container + Postgres | none (SaaS) | none | none | none |
| Free tier ceiling (10 devs, 17 repos) | unlimited (cloud cost only) | 5 projects, then $7/seat | self-host or $7/seat | 3 projects, then $6/seat (Teams) | unlimited | unlimited | unlimited |
| Cloud secret-store backends | AWS SSM today; OCI Vault, Azure KV, GCP SM on roadmap | own store | own store | own store | AWS SM, AWS SSM, GCP SM, Vault, Consul, dotenv | AWS SM/SSM, GCP SM, Azure KV, Vault, SOPS, Bitwarden | Conjur, AWS, keyring (provider plugin) |
| `run -- cmd` injection | yes | yes | yes | yes | yes | yes (`run` and `load`) | yes |
| Importer for Doppler / Infisical / .env | **all three built-in** | n/a | partial (one-way) | none | dotenv only | none (Infisical on roadmap) | none |
| Sync to GitHub Actions secrets | **built-in (`skret sync --to=github`; `--skip-unchanged` for hash-based drift detection)** | via paid integration | via paid integration | none | none | none | none |
| Release-artifact provenance | **cosign + SBOM + reproducible** | n/a (SaaS) | n/a (SaaS) | n/a (SaaS) | none | none | none |
| Cost at our scale (17 repos × 340 secrets × 30k reads/mo, AWS SSM Standard) | **$0** | $84 / mo (10 seats) | ~$30 / mo infra (self-host) | $60 / mo (10 seats, Teams) | $0 | $0 | $0 |
| Latest release (audit 2026-05-01) | rolling, semantic-release | rolling SaaS | rolling SaaS | rolling SaaS | v2.0.7, May 2024 (12 mo gap) | v0.20.1, Jun 2025 (10 mo gap) | v0.11.0, Mar 2026 |

**How to read this:**

- If you want a managed UX and you're happy paying per seat, **Doppler** still has the best DX in this space.
- If you want self-host SaaS with K8s-native operators and a web UI, **Infisical** is the right pick — accept the Postgres + container ops cost.
- If you only need a single-cloud `run -- cmd` injector and don't care about migration / CI sync, **summon** (most actively maintained) or **novops** (broadest backend list) is enough — and shorter than skret.
- skret's wedge is the combination: cloud-native backend ranking + migration importers + GitHub Actions sync + signed release artifacts in one binary. If two or more of those matter to you, skret is meant to replace the patchwork.

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
| `skret setup` | Create `.skret.yaml` + authenticate in one step |
| `skret init` | Create `.skret.yaml` in the current repo |
| `skret run -- <cmd>` | Inject secrets as env vars and exec a command |
| `skret get <KEY>` | Print a single secret value |
| `skret env` | Dump all secrets in dotenv / JSON / YAML / export format |
| `skret set <KEY> <VALUE>` | Create or update a secret |
| `skret delete <KEY>` | Delete a secret |
| `skret list` | List secrets under the current environment path |
| `skret import --from=<source>` | Import from Doppler, Infisical, dotenv |
| `skret sync --to=<target>` | Sync to GitHub Actions, dotenv |
| `skret diff <A> <B>` | Compare two environments (or env vs dotenv / env vs github) and report drift without printing values |

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

<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->
<details>
  <summary><strong>Sister projects from n24q02m</strong> (click to expand)</summary>

| Project | Tagline | Tag |
|---|---|---|
| [better-code-review-graph](https://github.com/n24q02m/better-code-review-graph) | Knowledge graph for token-efficient code reviews -- fixed search, configurabl... | MCP |
| [better-email-mcp](https://github.com/n24q02m/better-email-mcp) | IMAP/SMTP email server for AI agents -- 6 composite tools with multi-account ... | MCP |
| [better-godot-mcp](https://github.com/n24q02m/better-godot-mcp) | Composite MCP server for Godot Engine -- 17 mega-tools for AI-assisted game d... | MCP |
| [better-notion-mcp](https://github.com/n24q02m/better-notion-mcp) | Markdown-first Notion API server for AI agents -- 10 composite tools replacin... | MCP |
| [better-telegram-mcp](https://github.com/n24q02m/better-telegram-mcp) | MCP server for Telegram with dual-mode support: Bot API (httpx) for quick bot... | MCP |
| [claude-plugins](https://github.com/n24q02m/claude-plugins) | Full documentation: mcp.n24q02m.com — unified docs for all 8 servers + the mc... | Marketplace |
| [imagine-mcp](https://github.com/n24q02m/imagine-mcp) | Production-grade MCP server for image and video understanding + generation ac... | MCP |
| [jules-task-archiver](https://github.com/n24q02m/jules-task-archiver) | Chrome Extension for bulk operations on Jules tasks via batchexecute API -- a... | Tooling |
| [mcp-core](https://github.com/n24q02m/mcp-core) | Unified MCP Streamable HTTP 2025-11-25 transport, OAuth 2.1 Authorization Ser... | MCP |
| [mnemo-mcp](https://github.com/n24q02m/mnemo-mcp) | Persistent AI memory with hybrid search and embedded sync. Open, free, unlimi... | MCP |
| [qwen3-embed](https://github.com/n24q02m/qwen3-embed) | Lightweight Qwen3 text embedding and reranking via ONNX Runtime and GGUF | Library |
| [skret](https://github.com/n24q02m/skret) | Secrets without the server. | CLI |
| [web-core](https://github.com/n24q02m/web-core) | Shared web infrastructure package for search, scraping, HTTP security, and st... | Library |
| [wet-mcp](https://github.com/n24q02m/wet-mcp) | Open-source MCP Server for web search, content extraction, library docs & mul... | MCP |

</details>
<!-- END: AUTO-GENERATED-CROSS-PROMO -->


If skret saves your team the Doppler seat cost or the Infisical ops overhead, please consider sponsoring continued development.

## Acknowledgments

skret was inspired by [Doppler](https://www.doppler.com) and [Infisical](https://infisical.com) — teams who made CLI-first secrets management pleasant — and by the OSS injection-wrapper lineage of [teller](https://github.com/tellerops/teller), [novops](https://github.com/PierreBeucher/novops), [summon](https://github.com/cyberark/summon), and [chamber](https://github.com/segmentio/chamber). It is built on [AWS SDK for Go v2](https://github.com/aws/aws-sdk-go-v2), [Cobra](https://github.com/spf13/cobra), and documented with [Astro Starlight](https://starlight.astro.build) on Cloudflare Pages.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © n24q02m