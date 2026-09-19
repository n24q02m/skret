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
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/github/license/n24q02m/skret"></a>
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
skret sync --to=k8s              # Render a Kubernetes Secret manifest
```

<p align="center">
  <img src="https://skret.n24q02m.com/demo.gif" alt="skret demo" width="820">
</p>

## Table of contents

- [Usage](#usage)
- [Why skret?](#why-skret)
- [Features](#features)
- [Install](#install)
- [GitHub Action](#github-action)
- [Quick start](#quick-start)
- [Provider ranking](#provider-ranking)
- [Comparison vs alternatives](#comparison-vs-alternatives)
- [Vault dashboard](#vault-dashboard)
- [Documentation](#documentation)
- [Command overview](#command-overview)
- [Contributing](#contributing)
- [Sponsors](#sponsors)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Usage

```sh
skret setup                       # pick provider + path, authenticate once
skret run -- make deploy          # run a command with secrets injected
skret get DATABASE_URL --plain    # print one value (exact bytes)
skret sync --to=github,cloudflare # push secrets to CI/edge targets
skret scan --staged               # leak-guard: exits 10 if a value leaked
skret scan --history              # scan committed blobs across git history
```

Using skret from a script or AI agent? See the [agent guide](https://skret.n24q02m.com/guide/agents/).

## Why skret?

CLI wrappers that inject cloud secrets into a `run -- cmd` invocation already exist — `teller`, `novops`, `summon`, and narrower single-cloud tools like `chamber` (AWS-only: SSM, Secrets Manager, S3). What was missing for our use case was a single binary that combines:

1. **Migration importers** for Doppler, Infisical, and `.env` — so a team can leave a paid SaaS without rewriting deploy pipelines.
2. **CI/CD sync** that pushes the same secret set to GitHub Actions in one command, with hash-based drift detection.
3. **Production-grade release artifacts** — cosign signatures, SBOMs, reproducible builds — so the binary itself can sit on a build agent without separate hardening.
4. **Doppler-grade DX** (`skret run -- your-cmd`) on top of cloud-native IAM, no self-hosted control plane, no per-seat licence.

If you only need a single-cloud injector and you don't care about migration or CI sync, `teller` or `summon` may already be enough — see the [comparison table](#comparison-vs-alternatives) for the honest trade-offs.

## Features

- **One-command bootstrap**: `skret bootstrap` provisions a dedicated least-privilege IAM user + permanent access key scoped to your SSM path, from an admin/root identity used once and never stored.
- **Multi-provider backend**: AWS SSM Parameter Store, Azure Key Vault, GCP Secret Manager, and OCI Vault today. Switch backends with one config line.
- **Zero-server architecture**: Direct cloud IAM. No self-hosted control plane, no license fees, no new billing surface.
- **Doppler-grade CLI**: `skret run -- your-cmd` injects secrets as env vars. Identical UX to `doppler run --`.
- **Migration-first**: Built-in importers for Doppler, Infisical, and `.env` files.
- **CI/CD syncers**: Push secrets to GitHub Actions repository secrets in one command.
- **Agent-ready**: documented exit-code contract, byte-exact secret reads, and an `llms.txt` map built for LLM/agent discovery — see the [agent guide](https://skret.n24q02m.com/guide/agents/).
- **MCP server**: `skret-mcp` plugs skret straight into Claude Code, OMP, and any MCP client — read-only by default, writes gated behind config, reads audited. See the [MCP guide](https://skret.n24q02m.com/guide/mcp/).
- **Production-grade**: Coverage gates enforced in CI (`internal/` >=90%, `pkg/skret/` >=95% -- see the codecov badge above for the live number), CodeQL security scanning, SBOM + cosign-signed release artifacts.
- **Cross-platform**: Linux, macOS, Windows — amd64 and arm64 binaries for each.
- **Tab-completion of secret keys**: `skret get <TAB>` completes real key names via a names-only listing — zero decryption, zero KMS cost.
- **Watch mode**: `skret run --watch -- your-cmd` auto-restarts the command when secrets change. Change detection polls a no-decrypt fingerprint, so it issues zero KMS Decrypt requests.
- **Leak guard**: `skret scan` checks tracked files for your real managed secret values — precise, no pattern-matching false positives — and exits `10` when one is found, so CI and pre-commit hooks fail on a leak. `--history` walks committed blobs across git history and reports the commit that introduced each leak.
- **Webhook notifications**: fire a names-only, optionally HMAC-signed webhook on every successful `set`/`delete`/`rotate`/`sync` — audit trail for pipelines without a control plane.
- **Secret access audit trail**: `skret audit` renders who changed or read what, when — from the local provider's append-only JSONL log (names only, never values, `0600`) or an AWS CloudTrail export of SSM parameter operations.
- **Interactive browser**: `skret browse` opens a TUI of your secret keys and reveals each value on demand. The list never decrypts, so browsing is free of KMS cost; only the secret you reveal is decrypted.

## Install

| Platform | One-shot script | Package manager |
|----------|-----------------|-----------------|
| **macOS / Linux** | `curl -fsSL https://skret.n24q02m.com/install.sh \| sh` | `brew install n24q02m/tap/skret` |
| **Windows** | `iwr -useb https://skret.n24q02m.com/install.ps1 \| iex` | `scoop bucket add n24q02m https://github.com/n24q02m/scoop-bucket && scoop install skret` |
| **Go developers** | `go install github.com/n24q02m/skret/cmd/skret@latest` | — |
| **Direct binary** | Download from [Releases](https://github.com/n24q02m/skret/releases/latest) | — |

Homebrew users who installed before 1.15.1: the tap now ships a cask rather than a formula, because goreleaser retired its formula generator. The install command is unchanged, but an existing install has to be swapped once — `brew uninstall skret && brew install n24q02m/tap/skret`.

Verify the install and check the version:

```sh
skret --version
```

The one-shot installers require SHA256 verification and a non-empty Sigstore bundle verified by `cosign` before extraction. They then enforce the `SAFE-ARCHIVE-V1` allowlist and resource bounds, extract into an owner-only staging directory, atomically replace the target, and roll back to the byte-identical prior binary if activation or `skret --version` fails. Set `SKRET_INSECURE_SKIP_VERIFY=1` only for an explicit signature-verification bypass; checksum, archive, path, and rollback checks remain enforced. Source both scripts at [skret.n24q02m.com/install.sh](https://skret.n24q02m.com/install.sh) and [skret.n24q02m.com/install.ps1](https://skret.n24q02m.com/install.ps1) before piping to a shell if you prefer.

## GitHub Action

The official composite action installs skret from checksum-verified release assets and runs `run`, `scan`, or `diff` directly in your workflow — no container, no control plane. Works on `ubuntu`, `macos`, and `windows` runners.

```yaml
- uses: n24q02m/skret@v1
  with:
    command: scan        # leak gate: fails the job with exit 10 when a value leaked

- uses: n24q02m/skret@v1
  with:
    command: run         # inject secrets, then run your command
    args: -- npm test
```

| Input | Default | Description |
|-------|---------|-------------|
| `version` | `latest` | Release tag to install: `v1.19.3`, `1.19.3`, or `latest` |
| `command` | `run` | `run`, `scan`, or `diff` — leave empty for install-only, then call the binary via `SKRET_BIN` or `PATH` in later steps |
| `args` | — | Arguments passed to skret, split on whitespace (no shell quoting or evaluation). For `run`, start with `--` followed by the child command |
| `config` | — | Path to a `.skret.yaml` config file, passed to skret as `--config` |
| `workdir` | `.` | Working directory where skret is invoked; relative config and secret paths resolve from here |
| `env` | — | Newline-separated `KEY=VALUE` pairs exported into the skret process (e.g. `AWS_REGION`); blank lines and `#` comments ignored |

The action exports the installed binary as `SKRET_BIN` and adds it to `PATH` for subsequent steps, and exposes a `version` output with the resolved version. Assets are downloaded from GitHub releases and verified against the release's `checksums.txt` (SHA-256) before extraction. skret's exit codes pass through untouched, so `command: scan` fails the job with `10` on a leak and `diff --exit-code` with `9` on drift — see the [agent guide](https://skret.n24q02m.com/guide/agents/) for the full exit-code contract. The action itself is exercised on every change by this repo's own CI in [`.github/workflows/action-e2e.yml`](.github/workflows/action-e2e.yml).

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
# 0. (One-time) Provision a scoped least-privilege key from an admin identity
skret bootstrap --path=/myapp/prod --region=ap-southeast-1   # creates IAM user skret-<project> + stores the key

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
skret --env=prod sync --to=github \
  --github-repo=myorg/myapp

# 5. Re-sync, skip secrets that haven't changed since the last successful run
skret sync --to=github --github-repo=myorg/myapp --skip-unchanged

# 6. See what differs between staging and prod (values are never printed)
skret diff staging prod
skret diff staging prod --show-hash        # confirm which values changed via sha256[:8]
skret diff prod --to=github --github-repo=myorg/myapp   # presence-only (github is write-only)

# 7. Render a config template (only ${KEY} is substituted; $vars are left intact)
skret template nginx.conf.tpl --output nginx.conf

# 8. Enable tab-completion of secret keys (bash/zsh/fish/powershell)
source <(skret completion zsh)   # then: skret get <TAB> completes real key names — no decryption / no KMS cost

# 9. Auto-restart a command when secrets change (no polling cost)
skret run --watch -- make up-prod          # restart on change; --watch-interval 30s to tune the poll

# 10. Guard against leaks: scan tracked files for your managed secret values
skret scan                                 # exits 10 if any managed value is found in a tracked file
skret scan --staged                        # staged-only, for a .git/hooks/pre-commit hook

# 11. Browse secrets in an interactive TUI; reveal values on demand (no KMS cost to browse)
skret browse                               # arrow keys to move, / to filter, enter to reveal/hide, q to quit
```

See [Getting started](https://skret.n24q02m.com/guide/getting-started/) for the 5-minute guided tour.

## Provider ranking

Cost figures below use a representative scale: 17 repos × 20 secrets/repo × 1,000 reads/day (30k/month), `ap-southeast-1` (Singapore).

| Rank | Backend | Monthly cost | Recommended for |
|------|---------|--------------|-----------------|
| 1 | **AWS SSM Parameter Store (Standard)** | **$0** | Default — AWS-native or mixed-cloud |
| 2 | **OCI Vault (software-protected)** | **$0** | Users with OCI tenancy; best rotation lifecycle |
| 3 | **Azure Key Vault (Standard)** | **~$0.09** | Azure-native or multi-cloud DR |
| 4 | **GCP Secret Manager** | **~$20** | GCP-native workloads (**supported today**) |
| 5 | **AWS Secrets Manager** | **~$136** | Only when managed rotation (RDS/Redshift) is required |

See [provider comparison](https://skret.n24q02m.com/reference/provider-comparison/) for the full feature matrix.

## Comparison vs alternatives

Audited 2026-07-13 against the latest release of each tool. The comparison covers three SaaS / self-host secret managers (Doppler, Infisical, Bitwarden Secrets Manager) and four OSS CLI wrappers in skret's design space (teller, novops, summon, chamber).

| Feature | skret | Doppler | Infisical | Bitwarden SM | teller | novops | summon | chamber |
|---|---|---|---|---|---|---|---|---|
| Type | OSS CLI | SaaS | SaaS / self-host | SaaS / self-host | OSS CLI | OSS CLI | OSS CLI | OSS CLI |
| Language | Go 1.26 | proprietary | TypeScript | Rust | Rust | Rust | Go | Go |
| Licence | Apache-2.0 | proprietary | MIT (complex) | GPL-3.0 (CLI) | Apache-2.0 | LGPL-3.0 | MIT | MIT |
| Server / control plane | none | none (SaaS) | container + Postgres | none (SaaS) | none | none | none | none |
| Free tier ceiling (10 devs, 17 repos) | unlimited (cloud cost only) | 3 users, then $8/seat* | self-host or $7/seat | 3 projects, then $6/seat (Teams) | unlimited | unlimited | unlimited | unlimited (cloud cost only) |
| Cloud secret-store backends | AWS SSM, Azure KV, GCP SM, OCI Vault today | own store | own store | own store | AWS SM, AWS SSM, GCP SM, Vault, Consul, dotenv | AWS SM/SSM, GCP SM, Azure KV, Vault, SOPS, Bitwarden | Conjur, AWS, keyring (provider plugin) | AWS SSM, AWS Secrets Manager, S3 / S3-KMS (AWS-only) |
| `run -- cmd` injection | yes | yes | yes | yes | yes | yes (`run` and `load`) | yes | yes (`chamber exec`) |
| Importer for Doppler / Infisical / .env | **all three built-in** | n/a | partial (one-way) | none | dotenv only | none (Infisical on roadmap) | none | none (own export/import format only) |
| Sync to GitHub Actions secrets | **built-in (`skret sync --to=github`; `--skip-unchanged` for hash-based drift detection)** | via paid integration | via paid integration | none | none | none | none | none |
| Sync to GitLab CI/CD variables, Terraform tfvars, or a K8s Secret manifest | **built-in (`skret sync --to=gitlab` with masked/protected flags, `--to=terraform`, `--to=k8s`; manifest rendering only, no live cluster apply)** | not audited | not audited | not audited | not audited | not audited | not audited | not audited |
| Release-artifact provenance | **cosign + SBOM + reproducible** | n/a (SaaS) | n/a (SaaS) | n/a (SaaS) | none | none | none | none (sha256 checksums only) |
| Cost at our scale (17 repos × 20 secrets/repo × 1,000 reads/day, AWS SSM Standard) | **$0** | $56 / mo (10 seats: 3 free + 7 × $8, Developer plan)* | ~$30 / mo infra (self-host) | $60 / mo (10 seats, Teams) | $0 | $0 | $0 | $0 |
| Latest release (audited 2026-07-13) | rolling, semantic-release | rolling SaaS | rolling SaaS | rolling SaaS | v2.0.7, May 2024 (26 mo gap) | v0.20.1, Jun 2025 (13 mo gap) | v0.11.0, Mar 2026 | v3.1.5, Feb 2026 (5 mo gap) |

\* Doppler pricing from <https://www.doppler.com/pricing> (as of 2026-07): Developer plan is free for 3 users, then $8/user/month; the larger Team plan is $21/user/month.

**How to read this:**

- If you want a managed UX and you're happy paying per seat, **Doppler** still has the best DX in this space.
- If you want self-host SaaS with K8s-native operators and a web UI, **Infisical** is the right pick — accept the Postgres + container ops cost.
- If you only need a single-cloud `run -- cmd` injector and don't care about migration / CI sync, **summon** (most actively maintained) or **novops** (broadest backend list) is enough — and shorter than skret.
- If you're AWS-only and want a lean multi-backend CLI (SSM, Secrets Manager, S3) without migration importers or CI sync, **chamber** is a solid, actively-maintained pick.
- skret's wedge is the combination: cloud-native backend ranking + migration importers + GitHub Actions sync + signed release artifacts in one binary. If two or more of those matter to you, skret is meant to replace the patchwork.

## Vault dashboard

`skret hub push` publishes a names-only manifest — key names, salted `sha256[:8]` fingerprints, and a per-target status — to a self-hosted, read-only dashboard. No secret value ever leaves your machine. Deploy your own on Cloudflare Workers + KV; see the [hub guide](https://skret.n24q02m.com/guide/hub/).

<p align="center">
  <img src="https://skret.n24q02m.com/hub-screenshot.png" alt="skret vault dashboard showing per-key sync status badges" width="760">
</p>

## Documentation

Full docs at **[skret.n24q02m.com](https://skret.n24q02m.com)**:

- [Getting started](https://skret.n24q02m.com/guide/getting-started/) — 5-minute tutorial
- [Installation](https://skret.n24q02m.com/guide/installation/) — every platform, every method
- [Configuration](https://skret.n24q02m.com/guide/configuration/) — `.skret.yaml` reference
- [Authentication](https://skret.n24q02m.com/guide/authentication/) — AWS SSO, OIDC, IAM
- [Provider comparison](https://skret.n24q02m.com/reference/provider-comparison/) — cost + features across AWS, OCI, Azure, GCP
- [Providers](https://skret.n24q02m.com/providers/) — per-backend setup guides (AWS SSM, Azure Key Vault, local)
- [Migrate from Doppler](https://skret.n24q02m.com/migration/from-doppler/)
- [Migrate from Infisical](https://skret.n24q02m.com/migration/from-infisical/)
- [Makefile patterns](https://skret.n24q02m.com/integrations/makefile-patterns/)
- [Troubleshooting](https://skret.n24q02m.com/guide/troubleshooting/)
- [FAQ](https://skret.n24q02m.com/faq/)

## Command overview

| Command | Purpose |
|---------|---------|
| `skret bootstrap` | Provision a dedicated least-privilege IAM user + permanent access key scoped to your SSM path, from an admin identity |
| `skret setup` | Create `.skret.yaml` + authenticate in one step |
| `skret init` | Create `.skret.yaml` in the current repo |
| `skret run -- <cmd>` | Inject secrets as env vars and exec a command |
| `skret get <KEY>` | Print a single secret value |
| `skret env` | Dump all secrets in dotenv / JSON / YAML / export format |
| `skret set <KEY> <VALUE>` | Create or update a secret |
| `skret rotate <KEY> [KEY...]` | Replace a secret's value with a fresh generated value (crypto/rand); `--ttl` records expiry metadata, `--show` prints the new value, CI-safe (prompt only on a TTY) |
| `skret generate` | Generate a random password, UUID, hex, or base64 value (crypto/rand, rejection sampling); `--set KEY` stores it directly |
| `skret delete <KEY>` | Delete a secret |
| `skret list` | List secret keys under the current environment path (no decryption; use --values for KEY+VERSION+VALUE) |
| `skret import --from=<source>` | Import from Doppler, Infisical, dotenv |
| `skret sync --to=<target>` | Sync to GitHub Actions, GitLab CI/CD variables, Cloudflare, dotenv, Terraform tfvars, or a Kubernetes Secret manifest |
| `skret hub push` | Publish a names-only secret inventory (no values) to the vault dashboard |
| `skret diff <A> <B>` | Compare two environments (or env vs dotenv / env vs github) and report drift without printing values |
| `skret template <file>` | Render a template file, substituting `${KEY}` with secret values |
| `skret scan` | Scan tracked files for any managed secret value and exit 10 on a leak (`--staged` for pre-commit hooks, `--history` to scan git history) |
| `skret browse` | Browse secret keys in an interactive TUI, revealing values on demand (no decryption to browse) |
| `skret keys init --encrypt-existing` | Set up key material and encrypt the local secrets file at rest (`skret keys show` reports state) |
| `skret audit` | Show the secret access audit trail — local append-only JSONL log (names only, never values) or AWS CloudTrail export of SSM parameter operations |
| `skret doctor` | Read-only health check: config validity, provider reachability, auth state, local file permissions and at-rest encryption state; exits with the failing check's class (`--format json` for machines) |

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
| [agent-chat-plugin](https://github.com/n24q02m/agent-chat-plugin) | Peer AI agents chat in a shared folder — no human relay, no orchestrator, wor... | Tooling |
| [better-code-review-graph](https://github.com/n24q02m/better-code-review-graph) | Knowledge graph for token-efficient code reviews -- semantic search and call-... | MCP |
| [better-drive](https://github.com/n24q02m/better-drive) | 2-way Google Drive sync with .driveignore filter — rclone engine, Windows tray | Tooling |
| [better-email-mcp](https://github.com/n24q02m/better-email-mcp) | IMAP/SMTP email for AI agents -- read, send, organize folders, and manage att... | MCP |
| [better-godot-mcp](https://github.com/n24q02m/better-godot-mcp) | Composite MCP server for Godot Engine -- 17 composite tools for AI-assisted g... | MCP |
| [better-notion-mcp](https://github.com/n24q02m/better-notion-mcp) | Markdown-first Notion for AI agents -- pages, databases, blocks, and comments... | MCP |
| [better-semantic-release](https://github.com/n24q02m/better-semantic-release) | Drop-in python-semantic-release fork with built-in release-safety guards (orp... | Tooling |
| [better-telegram-mcp](https://github.com/n24q02m/better-telegram-mcp) | Telegram for AI agents -- messages, chats, media, and contacts across both bo... | MCP |
| [better-workspace-mcp](https://github.com/n24q02m/better-workspace-mcp) | Google Workspace MCP server (Docs/Drive/Calendar/Gmail/Sheets/Slides/Tasks/Ch... | MCP |
| [claude-plugins](https://github.com/n24q02m/claude-plugins) | Claude Code plugin marketplace for the n24q02m MCP servers -- install web sea... | Marketplace |
| [imagine-mcp](https://github.com/n24q02m/imagine-mcp) | Image and video understanding + generation for AI agents -- across Gemini, Op... | MCP |
| [jules-task-archiver](https://github.com/n24q02m/jules-task-archiver) | Chrome Extension for bulk operations on Jules tasks via batchexecute API -- a... | Tooling |
| [mcp-core](https://github.com/n24q02m/mcp-core) | Shared foundation for building MCP servers -- Streamable HTTP transport, OAut... | MCP |
| [mnemo-mcp](https://github.com/n24q02m/mnemo-mcp) | Persistent AI memory with hybrid search and embedded sync. Open, free, unlimi... | MCP |
| [qwen3-embed](https://github.com/n24q02m/qwen3-embed) | Lightweight Qwen3 text embedding and reranking via ONNX Runtime and GGUF | Library |
| [skret](https://github.com/n24q02m/skret) | Secrets without the server. | CLI |
| [tacet](https://github.com/n24q02m/tacet) | A self-distilling neuro-symbolic cascade that amortises LLM cost across knowl... | Tooling |
| [web-core](https://github.com/n24q02m/web-core) | Shared web infrastructure package for search, scraping, HTTP security, and st... | Library |
| [wet-mcp](https://github.com/n24q02m/wet-mcp) | Open-source MCP server for AI agents: web search, content extraction, and lib... | MCP |

</details>
<!-- END: AUTO-GENERATED-CROSS-PROMO -->


If skret saves your team the Doppler seat cost or the Infisical ops overhead, please consider sponsoring continued development.

## Acknowledgments

skret was inspired by [Doppler](https://www.doppler.com) and [Infisical](https://infisical.com) — teams who made CLI-first secrets management pleasant — and by the OSS injection-wrapper lineage of [teller](https://github.com/tellerops/teller), [novops](https://github.com/PierreBeucher/novops), [summon](https://github.com/cyberark/summon), and [chamber](https://github.com/segmentio/chamber). It is built on [AWS SDK for Go v2](https://github.com/aws/aws-sdk-go-v2), [Cobra](https://github.com/spf13/cobra), and documented with [Astro Starlight](https://starlight.astro.build) on Cloudflare Pages.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE) © n24q02m
