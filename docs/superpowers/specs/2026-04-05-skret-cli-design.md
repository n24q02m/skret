# skret CLI — Design Document

**Status:** Draft for review
**Date:** 2026-04-05
**Author:** n24q02m
**Target version:** v0.1.0

---

## 1. Overview

### 1.1 Problem statement

Managing secrets across 17 production repositories, 2 OCI VMs, and multiple physical machines currently requires Doppler (paid, 10-project free tier) + Infisical (self-hosted, complex ops). Both have DX overhead and neither is truly free + unlimited at this scale.

AWS SSM Parameter Store Standard offers unlimited projects/environments via path hierarchy, 10,000 parameters free, and unlimited API operations — but its CLI is verbose and lacks the developer ergonomics of Doppler/Infisical.

### 1.2 Goals

1. **DX parity with Doppler/Infisical**: `skret run -- make up` replaces `doppler run -- make up` with zero friction.
2. **Multi-cloud abstraction**: Wrap cloud-provider secret managers (AWS SSM, GCP SM, Cloudflare Workers Secrets, Azure Key Vault, OCI Vault) behind a uniform interface.
3. **Single binary distribution**: Go binary via brew/scoop/apt/direct download, no runtime dependencies.
4. **Migration-first**: First-class import from Doppler + Infisical + dotenv. Sync to GitHub Actions secrets for CI/CD.
5. **Production-grade**: ≥95% test coverage, semantic versioning, reproducible builds, full docs suite.

### 1.3 Non-goals (v0.1)

- Pure secret managers (Doppler, Infisical, Bitwarden SM, 1Password) as providers — only cloud-provider secret services.
- Dynamic/time-limited secrets generation (v0.5+).
- Secret rotation automation (v0.3+).
- Web UI / dashboard.
- Team collaboration features beyond IAM-based access.

### 1.4 Success metrics

- 100% workflow parity with `doppler run --` in 17 repos' Makefiles.
- Cold-start latency < 50ms for `skret get` / `skret run` commands.
- Binary size < 20 MB.
- Migration of all secrets from Doppler + Infisical in < 1 day.
- Zero runtime cost (AWS SSM Standard free tier + AWS-managed KMS key).
- Full cross-platform support: Windows (amd64/arm64), Linux (amd64/arm64), macOS (amd64/arm64).

### 1.5 Cross-platform requirements

skret MUST work identically on all three major OSes. Platform-specific concerns:

| Concern | Unix (Linux/macOS) | Windows |
|---|---|---|
| Process exec (`run`) | `syscall.Exec` (process replacement) | `os/exec.Command` (child process, wait + exit code forwarding) |
| File locking (local provider) | `flock` via `syscall.Flock` | `LockFileEx` via `golang.org/x/sys/windows` |
| Path handling | Forward slashes | `filepath.Join` / `filepath.Abs` normalize to backslashes |
| File permissions | `0600` for secrets files | ACLs (best-effort, Go `os.Chmod` limited on Windows) |
| Shell completions | bash, zsh, fish | PowerShell |
| Atomic file write | temp + `os.Rename` (same filesystem) | temp + `os.Rename` (same drive letter) |
| Signal handling | SIGTERM, SIGINT | Ctrl+C via `os.Interrupt` |
| CI testing | `ubuntu-latest`, `macos-latest` runners | `windows-latest` runner |

**Build tags:** Use `//go:build !windows` and `//go:build windows` for platform-specific code. All other code MUST be OS-agnostic.

**goreleaser targets:** `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64` (6 binaries per release).

---

## 2. Architecture

### 2.1 High-level design

```
┌────────────────────────────────────────────────────┐
│                  skret CLI binary                  │
│                                                    │
│  ┌────────────┐   ┌──────────┐   ┌──────────────┐  │
│  │ cmd/skret  │──▶│ internal │──▶│  pkg/skret   │  │
│  │  (Cobra)   │   │   /cli   │   │  (library)   │  │
│  └────────────┘   └──────────┘   └──────┬───────┘  │
│                                         │          │
│  ┌──────────────────────────────────────▼───────┐  │
│  │  internal/provider (SecretProvider iface)    │  │
│  ├──────────────────────────────────────────────┤  │
│  │  aws/     local/     gcp/     (future)       │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  ┌──────────────┐  ┌───────────┐  ┌────────────┐   │
│  │ importer/    │  │ syncer/   │  │  config/   │   │
│  │ - doppler    │  │ - github  │  │  - loader  │   │
│  │ - infisical  │  │ - dotenv  │  │  - schema  │   │
│  │ - dotenv     │  │           │  │            │   │
│  └──────────────┘  └───────────┘  └────────────┘   │
└────────────────────────────────────────────────────┘
```

### 2.2 Package layout

```
skret/
├── cmd/skret/              # main entry point
│   └── main.go
├── internal/
│   ├── cli/                # Cobra commands
│   │   ├── root.go
│   │   ├── init.go
│   │   ├── run.go
│   │   ├── get.go
│   │   ├── env.go
│   │   ├── set.go
│   │   ├── delete.go
│   │   ├── list.go
│   │   ├── import.go
│   │   └── sync.go
│   ├── config/             # .skret.yaml schema + loader
│   │   ├── schema.go
│   │   ├── loader.go
│   │   └── resolver.go     # precedence resolution
│   ├── provider/           # SecretProvider interface + impls
│   │   ├── provider.go     # interface + types
│   │   ├── registry.go     # factory: name -> constructor
│   │   ├── aws/
│   │   │   ├── aws.go
│   │   │   ├── auth.go     # credential chain helpers
│   │   │   └── errors.go   # AWS error translation
│   │   └── local/
│   │       └── local.go    # YAML file provider
│   ├── importer/
│   │   ├── importer.go     # interface
│   │   ├── doppler.go
│   │   ├── infisical.go
│   │   └── dotenv.go
│   ├── syncer/
│   │   ├── syncer.go       # interface
│   │   ├── github.go
│   │   └── dotenv.go
│   ├── exec/
│   │   └── exec.go         # env injection + syscall.Exec
│   ├── logging/
│   │   └── logger.go       # structured logging (slog)
│   └── version/
│       └── version.go      # injected at build time
├── pkg/skret/              # public library API
│   ├── client.go
│   └── doc.go
├── tests/
│   ├── integration/        # real AWS SSM tests (env-gated)
│   └── e2e/                # full command-line tests
├── docs/                   # documentation site
├── scripts/
├── .github/workflows/
│   ├── ci.yml
│   └── cd.yml
├── .goreleaser.yaml
├── .golangci.yaml
├── .mise.toml
├── .pre-commit-config.yaml
├── .editorconfig
├── .gitignore
## .infisical.json intentionally omitted — skret bootstraps from environment variables only (see S14 Q4)
├── .pr_agent.toml
├── renovate.json
├── AGENTS.md
├── CHANGELOG.md
├── CLAUDE.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE                 # MIT
├── README.md
├── SECURITY.md
├── go.mod
└── go.sum
```

### 2.3 Core abstractions

```go
// internal/provider/provider.go

type Secret struct {
    Key       string            // "/knowledgeprism/prod/DB_URL"
    Value     string
    Version   int64             // provider-native version
    Meta      SecretMeta
}

type SecretMeta struct {
    Description string
    Tags        map[string]string
    CreatedAt   time.Time
    UpdatedAt   time.Time
    CreatedBy   string
}

type SecretProvider interface {
    // Identity
    Name() string
    Capabilities() Capabilities

    // Read
    Get(ctx context.Context, key string) (*Secret, error)
    List(ctx context.Context, pathPrefix string) ([]*Secret, error)

    // Write (may return ErrCapabilityNotSupported)
    Set(ctx context.Context, key string, value string, meta SecretMeta) error
    Delete(ctx context.Context, key string) error

    // Lifecycle
    Close() error
}

type Capabilities struct {
    Write       bool
    Versioning  bool
    Tagging     bool
    Rotation    bool
    AuditLog    bool
    MaxValueKB  int
}

var ErrNotFound = errors.New("secret not found")
var ErrCapabilityNotSupported = errors.New("provider does not support this operation")
```

### 2.4 Design principles

1. **Thin CLI, rich library**: `cmd/skret` is a minimal Cobra entrypoint. All core logic is importable via `pkg/skret`.
2. **Provider-agnostic CLI**: Commands depend on the `SecretProvider` interface, not concrete implementations.
3. **Errors wrap with context**: `fmt.Errorf("get secret %q: %w", key, err)` at every layer boundary.
4. **No global state**: Client instantiated per-command. Config flows top-down through explicit parameters.
5. **Fail-fast validation**: Config parsed and validated at startup. Required secrets checked at load time.
6. **Testability first**: All I/O goes through interfaces. `local` provider doubles as a test fixture.
7. **Secrets never logged**: Secret values never appear in logs, even at DEBUG level. Always redacted.
8. **Context propagation**: Every provider call accepts `context.Context` for cancellation/deadlines.

### 2.5 Command flow example

```
skret run -- make up-klprism
  1. config.Load(".skret.yaml")
     → ResolvedConfig{ Provider: "aws", Path: "/kp/prod", Region: "ap-southeast-1" }
  2. provider.Registry.New("aws", cfg)
     → *aws.Provider
  3. provider.List(ctx, "/kp/prod")
     → []*Secret{ {Key:"/kp/prod/DB_URL", Value:"postgres://..."}, ... }
  4. exec.Inject(secrets, os.Environ(), config.Exclude)
     → []string{ "DB_URL=postgres://...", "REDIS_URL=...", ... }
  5. syscall.Exec("/usr/bin/make", ["make", "up-klprism"], env)
```

---

## 3. Configuration

### 3.1 `.skret.yaml` schema

```yaml
# .skret.yaml (committed to repo)
version: "1"

default_env: prod
project: knowledgeprism

environments:
  prod:
    provider: aws
    path: /knowledgeprism/prod
    region: ap-southeast-1
    # profile: default              # optional, defaults to AWS SDK credential chain
    # kms_key_id: alias/aws/ssm     # optional, defaults to AWS-managed SSM key

  staging:
    provider: aws
    path: /knowledgeprism/staging
    region: ap-southeast-1

  dev:
    provider: local
    file: ./.secrets.dev.yaml       # gitignored

required:                           # fail-fast if missing
  - DATABASE_URL
  - REDIS_URL
  - OPENAI_API_KEY

exclude:                            # never injected by run/env
  - GITHUB_TOKEN

# Future v0.4+: secret references / templates
# refs:
#   DATABASE_URL: "postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:5432/${DB_NAME}"
```

### 3.2 Resolution precedence (high → low)

1. CLI flags: `--provider`, `--path`, `--env`, `--region`, `--profile`, `--file`
2. Environment variables: `SKRET_ENV`, `SKRET_PROVIDER`, `SKRET_PATH`, `SKRET_REGION`, `SKRET_PROFILE`, `AWS_PROFILE`, `AWS_REGION`
3. `.skret.yaml` environment-specific config
4. `.skret.yaml` top-level defaults
5. Provider defaults

### 3.3 Local provider file format

```yaml
# .secrets.dev.yaml (gitignored)
version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost:5432/klprism_dev"
  REDIS_URL: "redis://localhost:6379/0"
  OPENAI_API_KEY: "sk-fake-dev-key"
```

Values are stored in plaintext. This provider is for **development and testing only** — not suitable for production. Files are always added to `.gitignore` by `skret init`.

### 3.4 Multi-repo examples

See `docs/examples/` for full `.skret.yaml` files for:
- Monorepo (multiple projects sharing a config)
- Single-service repo
- OCI infrastructure repos (replaces `doppler.yaml`)
- CI-only repos (no local provider)

---

## 4. Commands (v0.1 MVP)

### 4.1 `skret init`

Initialize a new `.skret.yaml` in the current directory.

```bash
skret init                                       # interactive wizard
skret init --provider=aws --path=/myapp/prod     # non-interactive
skret init --template=aws-multi-env              # pre-built template
```

**Behavior:**
- Detects git repo root, places `.skret.yaml` there.
- Adds `.secrets.dev.yaml` and `.secrets.*.yaml` to `.gitignore`.
- If existing `.skret.yaml` present, prompts to overwrite or merge.
- Templates: `aws-single`, `aws-multi-env`, `local-only`, `migration-from-doppler`.

**Exit codes:** 0 success, 1 file exists (no `--force`), 2 invalid template.

### 4.2 `skret run -- <command>`

Inject secrets as env vars and exec the command. **Primary use case.**

```bash
skret run -- make up-klprism
skret run -- docker compose up -d
skret run -e staging -- pnpm test
skret --env dev run -- go test ./...
```

**Behavior:**
- Resolves config for current env.
- Lists all secrets under `path:`.
- Converts path segments to env var names: `/kp/prod/DB_URL` → `DB_URL`.
- Merges with existing `os.Environ()`. Existing env vars **override** secret values (user control).
- Filters out keys in `exclude:` list.
- Validates `required:` keys are present.
- Uses `syscall.Exec` (Unix) / `os/exec` with process replacement (Windows) for zero-overhead pass-through.

**Env var naming rules:**
- Strip `path:` prefix from key.
- Replace `/` with `_`.
- Uppercase the result.
- Example: `/kp/prod/database/pg_url` with `path=/kp/prod` → env var `DATABASE_PG_URL`.

**Exit codes:** inherits from child process. Internal errors use 125+.

### 4.3 `skret get <KEY>`

Print a single secret value to stdout.

```bash
skret get DATABASE_URL                      # plain value
skret get DATABASE_URL --plain              # explicit (default)
skret get DATABASE_URL --json               # {"key":"...","value":"..."}
skret get DATABASE_URL --with-metadata      # includes tags, version, updated_at
```

### 4.4 `skret env`

Dump all secrets as dotenv format.

```bash
skret env                                   # prints to stdout
skret env > .env.prod.backup               # save to file
skret env --format=json                     # JSON object
skret env --format=yaml                     # YAML dict
skret env --format=export                   # bash `export` statements
```

**Dotenv format** (default):
```
DATABASE_URL="postgres://..."
REDIS_URL="redis://..."
```
Values are always quoted, with proper escaping.

### 4.5 `skret set <KEY> <VALUE>`

Create or update a secret.

```bash
skret set DATABASE_URL "postgres://..."
skret set API_KEY --from-stdin             # pipe value from stdin
skret set API_KEY --from-file ./key.txt
skret set API_KEY "secret" --description "Third-party API key"
skret set API_KEY "secret" --tag owner=team-backend --tag env=prod
```

**Behavior:**
- Creates if not exists, updates if exists (upsert).
- For AWS SSM: always uses `SecureString` type with configured KMS key.
- Value size validated against provider max (4 KB for SSM Standard).

### 4.6 `skret delete <KEY>`

Delete a secret.

```bash
skret delete OLD_API_KEY
skret delete OLD_API_KEY --confirm          # skip interactive prompt
```

**Behavior:**
- Prompts for confirmation by default.
- For versioned providers: deletes all versions by default. `--version=N` deletes specific version.

### 4.7 `skret list [--path=<prefix>]`

List secrets under the current env's path, or custom prefix.

```bash
skret list                                  # lists under current env path
skret list --path=/knowledgeprism           # all envs for this project
skret list --recursive                      # include sub-paths
skret list --format=table                   # pretty table (default)
skret list --format=json                    # JSON array
skret list --values                         # include values (requires --confirm)
```

**Default output** (table):
```
KEY                      UPDATED              VERSION
/kp/prod/DATABASE_URL    2026-04-05 14:23     3
/kp/prod/REDIS_URL       2026-04-01 09:12     1
```

### 4.8 `skret import`

Import secrets from an external source.

```bash
# From Doppler
skret import --from=doppler \
  --doppler-project=oci-vm-infra \
  --doppler-config=prd \
  --to-path=/oci-vm-infra/prod

# From Infisical (self-hosted)
skret import --from=infisical \
  --infisical-url=https://infisical.internal \
  --infisical-project-id=abc123 \
  --infisical-env=prod \
  --to-path=/knowledgeprism/prod

# From dotenv file
skret import --from=dotenv \
  --file=.env.production \
  --to-path=/knowledgeprism/prod

# Dry-run (preview, no writes)
skret import --from=doppler --doppler-project=X --doppler-config=Y --to-path=/foo --dry-run
```

**Authentication:**
- Doppler: `DOPPLER_TOKEN` env var (service token or CLI token).
- Infisical: `INFISICAL_CLIENT_ID` + `INFISICAL_CLIENT_SECRET` (machine identity) or `INFISICAL_TOKEN`.
- Dotenv: file path only.

**Conflict handling:**
- `--on-conflict=skip` (default): skip existing keys.
- `--on-conflict=overwrite`: replace existing.
- `--on-conflict=fail`: abort on first conflict.

### 4.9 `skret sync`

Push secrets to an external target.

```bash
# Sync to GitHub Actions secrets
skret sync --to=github \
  --github-repo=n24q02m/KnowledgePrism \
  --from-env=prod

# Sync to multiple repos
skret sync --to=github \
  --github-repo=n24q02m/KnowledgePrism,n24q02m/Aiora \
  --from-env=prod

# Sync to dotenv
skret sync --to=dotenv \
  --file=.env.prod.backup \
  --from-env=prod
```

**GitHub authentication:**
- `GITHUB_TOKEN` env var (PAT with `repo` scope), or
- Delegates to `gh` CLI if installed.

**GitHub API mechanism:**
- Uses `PUT /repos/{owner}/{repo}/actions/secrets/{name}` with libsodium-sealed box encryption.
- Secrets with values > 64 KB rejected (GitHub limit).

---

## 5. Providers

### 5.1 AWS SSM Parameter Store

**Default authentication chain** (AWS SDK v2 default):
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Shared credentials file (`~/.aws/credentials` with profile)
3. Shared config file (`~/.aws/config` with SSO profile)
4. ECS/EC2 IMDS (when running on AWS)
5. Process credentials (external process in config)
6. IAM Roles Anywhere (when configured)

**Configuration overrides:**
- `--profile` flag or `profile:` in `.skret.yaml`.
- `--region` flag or `region:` in `.skret.yaml`.

**API mappings:**

| skret op | AWS API                                |
|----------|----------------------------------------|
| Get      | `GetParameter(WithDecryption=true)`    |
| List     | `GetParametersByPath(Recursive=true)`  |
| Set      | `PutParameter(Type=SecureString, Overwrite=true)` |
| Delete   | `DeleteParameter`                      |

**KMS integration:**
- `SecureString` type requires KMS key. Default: AWS-managed key `alias/aws/ssm` (20,000 requests/month free).
- `kms_key_id:` in config overrides to customer-managed key.

**Path conventions:**
- Paths must start with `/` (SSM requirement).
- Max depth: 15 hierarchy levels.
- Recommended pattern: `/<project>/<env>/<key_name>` where `<key_name>` can contain `_`.

**Error handling:**
- `ParameterNotFound` → `ErrNotFound`.
- `ThrottlingException` → automatic retry with exponential backoff (max 3 retries).
- `AccessDeniedException` → descriptive error including ARN attempted.
- `ValidationException` on oversized value → clear error citing 4 KB limit.

**Quotas** (AWS docs, 2026):
- 10,000 standard parameters per Region per account.
- 4 KB value size per standard parameter.
- 40 TPS for `GetParameter*` calls (default, shared across GetParameter/GetParameters/GetParametersByPath).
- KMS: 5,500 requests/second, 20,000 requests/month free with AWS-managed key.

### 5.2 Local YAML provider

For development and testing. **Not for production use.**

**File format:** see §3.3.

**Capabilities:**
- Read: YES
- Write: YES (rewrites file atomically via temp file + rename)
- Versioning: NO
- Tagging: NO (ignored on write)
- Audit log: NO

**Concurrency:** file-locked on writes via `flock` (Unix) / `LockFileEx` (Windows).

**Use cases:**
- Local dev when offline or without AWS credentials.
- CI pipelines that don't need real secrets (unit tests).
- Integration tests for the `SecretProvider` interface.

---

## 6. Import / Sync mechanisms

### 6.1 Doppler importer

- Uses Doppler REST API: `GET /v3/configs/config/secrets`.
- Auth: `DOPPLER_TOKEN` environment variable.
- Pagination: handles 100 secrets per page, auto-paginates.
- Preserves Doppler secret names verbatim (no transformation).

### 6.2 Infisical importer

- Uses Infisical REST API: `GET /api/v3/secrets/raw`.
- Auth: machine identity (client ID + secret → access token) OR bearer token.
- Supports self-hosted Infisical URLs via `--infisical-url` flag.
- Handles Infisical's E2EE secrets by requesting raw (pre-decrypted by server with machine identity).

### 6.3 Dotenv importer

- Parses `.env` format per dotenv spec (quoted values, comments, empty lines, multi-line).
- Supports `export` prefix (removed on import).
- Preserves original key casing.

### 6.4 GitHub Actions secrets syncer

- Uses `POST /repos/{owner}/{repo}/actions/secrets/public-key` to fetch public key.
- Seals each secret value with libsodium-sealed box using NaCl curve25519.
- Uses `PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}` to upload.
- Handles GitHub's per-secret limit (64 KB encrypted, ~48 KB plaintext).
- Authentication: `GITHUB_TOKEN` env var or delegates to `gh auth token`.

### 6.5 Dotenv syncer

- Generates `.env` file with proper quoting/escaping.
- Atomic write (temp file + rename) to prevent partial writes.
- File permissions set to `0600` (user read/write only).

---

## 7. Error handling & observability

### 7.1 Error categories

| Category            | Exit code | Example                                    |
|---------------------|-----------|--------------------------------------------|
| Usage error         | 2         | Missing required flag, invalid command     |
| Config error        | 3         | `.skret.yaml` not found, invalid schema    |
| Auth error          | 4         | AWS credentials missing or invalid         |
| Not found           | 5         | Secret key does not exist                  |
| Permission denied   | 6         | IAM policy denies operation                |
| Quota exceeded      | 7         | Throttled, rate limit hit                  |
| Provider error      | 8         | Generic provider failure                   |
| Internal error      | 125       | Panic, unexpected state                    |

### 7.2 Logging

- Uses Go stdlib `log/slog` with structured output.
- Default level: `INFO`. Override via `SKRET_LOG=DEBUG` or `--log-level=DEBUG`.
- Format: JSON when `SKRET_LOG_FORMAT=json`, text otherwise.
- **Secret values never logged.** Redaction enforced at slog handler level.
- Output goes to stderr. Stdout reserved for command output (`get`, `env`, `list`).

### 7.3 Telemetry

- **Opt-in only.** Disabled by default.
- Future v0.2+ consideration: anonymous usage metrics (command counts, provider types) to `https://telemetry.n24q02m.com/skret`.
- Enable via `skret config set telemetry.enabled=true` or `SKRET_TELEMETRY=1`.

---

## 8. Security model

### 8.1 Credential handling

- skret itself stores **no credentials**. All auth is delegated to provider SDKs and their credential chains.
- Doppler/Infisical/GitHub tokens read from env vars, never written to disk by skret.
- AWS credentials read via AWS SDK v2 default chain — user controls lifecycle.

### 8.2 In-memory secret lifecycle

- Secret values held in `Secret.Value` (string) during command execution.
- Go strings are immutable; values remain in memory until GC. skret does not attempt secure memory wiping (acceptable for CLI lifetime).
- After `exec.Exec`, process is replaced — all skret memory freed by kernel.

### 8.3 Audit trail

- skret delegates audit logging to the underlying provider:
  - AWS: CloudTrail logs all SSM `GetParameter`/`PutParameter` calls with caller IAM identity.
  - Local: no audit (dev use only).
- skret does NOT write its own audit log to avoid secret leakage.

### 8.4 IAM policy examples

Policy for a GitHub Actions OIDC role (read-only for one project's prod env):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
    "Resource": "arn:aws:ssm:ap-southeast-1:123456789012:parameter/knowledgeprism/prod/*"
  }, {
    "Effect": "Allow",
    "Action": ["kms:Decrypt"],
    "Resource": "*",
    "Condition": {
      "StringEquals": {"kms:EncryptionContext:PARAMETER_ARN": "arn:aws:ssm:ap-southeast-1:123456789012:parameter/knowledgeprism/prod/*"}
    }
  }]
}
```

### 8.5 Threat model

| Threat                                 | Mitigation                                           |
|----------------------------------------|------------------------------------------------------|
| Malicious `.skret.yaml` in repo        | skret only reads config, never executes arbitrary code from it. Path validation. |
| Secret leaked to logs                  | slog handler redacts values matching stored-secret list. |
| Secret leaked via error message        | Errors wrap structured error types, never embed raw values. |
| Compromised AWS credentials            | Out of scope — user's responsibility. IAM least-privilege recommended. |
| `skret run` injects into untrusted child | User's responsibility. Document that `run` passes secrets unchecked. |

---

## 9. Distribution & release

### 9.1 Release channels

| Channel          | Mechanism                                              |
|------------------|--------------------------------------------------------|
| Homebrew         | `n24q02m/tap` formula (`brew install n24q02m/tap/skret`) |
| Scoop            | `n24q02m/bucket` manifest (`scoop install n24q02m/skret`) |
| APT (Debian/Ubuntu) | `deb.n24q02m.com/skret` repo                        |
| Direct binary    | GitHub Releases with per-platform binaries             |
| Docker           | `ghcr.io/n24q02m/skret:<version>`                      |
| Go install       | `go install github.com/n24q02m/skret/cmd/skret@latest` |

### 9.2 goreleaser config

Platforms: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`.

Artifacts:
- Binary archives (`.tar.gz` for Unix, `.zip` for Windows).
- Checksums file (`SHA256SUMS`).
- SBOM (Software Bill of Materials) via syft.
- Signed with cosign (keyless, GitHub OIDC).

### 9.3 Version policy

- Semantic versioning (semver 2.0).
- `v0.x.y`: pre-stable, breaking changes possible between minor versions (documented in CHANGELOG).
- `v1.0.0`: stable API, breaking changes only in major versions.
- Release cadence: monthly minor releases, patch releases as needed.
- Managed by `python-semantic-release` (matches user's existing 17 repos).

### 9.4 Commit convention

Per user's global rule: only `fix:` and `feat:` prefixes. Never `chore:`, `docs:`, `refactor:`, etc.

---

## 10. Testing strategy

### 10.1 Test levels

| Level           | Scope                             | Tool                     | Target coverage |
|-----------------|-----------------------------------|--------------------------|-----------------|
| Unit            | Single function/method            | `testing` + `testify`    | ≥95%            |
| Integration     | Provider against real/mocked API  | `testing` + `localstack` | All providers   |
| E2E             | Full CLI invocation               | `testing` + subprocess   | All commands    |
| Property-based  | Path parsing, env var naming      | `testing/quick` or `gopter` | Core parsers |
| Benchmarks      | Hot paths (get, list, run)        | `testing.B`              | Latency budget  |

### 10.2 Integration test strategy

- **AWS SSM**: LocalStack (Docker) for offline CI. Also env-gated real-AWS tests (`SKRET_E2E_AWS=1`).
- **Doppler/Infisical importers**: record-replay via `go-vcr` for CI, env-gated live tests for manual verification.
- **GitHub syncer**: GitHub API mocked via `httptest`, env-gated live test against `n24q02m/skret-e2e-test` fixture repo.

### 10.3 Coverage gates

- Pre-commit: `go test -race ./...` must pass.
- CI: coverage ≥95% on `internal/` packages. `pkg/` requires ≥90%.
- Coverage reported to Codecov.

### 10.4 Performance targets

- `skret get` cold start: < 50ms (p95).
- `skret run` cold start to exec: < 100ms (p95).
- `skret list --recursive` on 1000 secrets: < 2s (p95).
- `skret import --from=doppler` on 100 secrets: < 10s.

Benchmarks run in CI, regressions >20% fail the build.

---

## 11. Documentation plan

### 11.1 Docs site

Static site generated via **VitePress** (matches user's `knowledge-core` pattern) hosted on GitHub Pages at `skret.n24q02m.com`.

### 11.2 Content structure

```
docs/
├── index.md                  # Marketing page + quick install
├── guide/
│   ├── getting-started.md    # 5-min tutorial
│   ├── installation.md       # All install methods
│   ├── configuration.md      # .skret.yaml reference
│   ├── authentication.md     # AWS credential setup
│   └── troubleshooting.md
├── commands/
│   ├── init.md
│   ├── run.md
│   ├── get.md
│   ├── env.md
│   ├── set.md
│   ├── delete.md
│   ├── list.md
│   ├── import.md
│   └── sync.md
├── providers/
│   ├── aws.md                # Setup, IAM policies, quotas
│   └── local.md              # File format, use cases
├── migration/
│   ├── from-doppler.md       # Step-by-step with examples
│   ├── from-infisical.md
│   └── from-dotenv.md
├── integrations/
│   ├── github-actions.md     # OIDC setup + sync workflow
│   ├── oci-vms.md            # IAM Roles Anywhere + step-ca
│   ├── makefile-patterns.md
│   └── docker-compose.md
├── cookbook/
│   ├── rotating-keys.md
│   ├── multi-region-sync.md
│   ├── team-access.md
│   └── backup-restore.md
├── reference/
│   ├── cli.md                # Full CLI flag reference (auto-generated)
│   ├── config-schema.md      # JSON schema + YAML schema
│   ├── error-codes.md        # All exit codes + causes
│   └── library-api.md        # Go library docs (pkg.go.dev link)
├── contributing/
│   ├── setup.md
│   ├── adding-provider.md    # How to add new providers
│   ├── adding-importer.md
│   └── release-process.md
└── faq.md
```

### 11.3 Auto-generated docs

- `skret docs generate` subcommand produces markdown for all commands from Cobra.
- JSON schema of `.skret.yaml` generated from Go structs via `invopop/jsonschema`.
- Go library reference auto-published to pkg.go.dev.

### 11.4 Man pages

Generated via `cobra/doc` for all commands. Packaged with `.deb`/`.rpm`/brew formulas.

---

## 12. Repository standards

Repo MUST match patterns of the 17 production repos (reference: `n24q02m/QuikShipping`, `n24q02m/wet-mcp`).

### 12.1 Required files

- `CLAUDE.md` — project-specific Claude Code instructions
- `AGENTS.md` — agent collaboration notes
- `CHANGELOG.md` — auto-generated by semantic-release
- `CODE_OF_CONDUCT.md` — Contributor Covenant
- `CONTRIBUTING.md` — contribution guide
- `LICENSE` — MIT
- `README.md` — marketing + quickstart
- `SECURITY.md` — vuln disclosure + supported versions
- `.editorconfig`
- `.gitignore`
- `.golangci.yaml` — linter config
- `.goreleaser.yaml` — release automation
- ~~`.infisical.json`~~ — `.infisical.json` intentionally omitted — skret bootstraps from environment variables only (see S14 Q4).
- `.mise.toml` — tool versions
- `.pr_agent.toml` — Qodo Merge AI review
- `.pre-commit-config.yaml`
- `renovate.json`

### 12.2 CI/CD workflows

- `.github/workflows/ci.yml`:
  - Runs on every PR + push to `main`/`staging`.
  - Jobs: lint (golangci-lint, gofumpt), test (unit, integration, race), build (all platforms), AI review (Qodo Merge), security scan (Semgrep for private, CodeQL for public).
- `.github/workflows/cd.yml`:
  - Runs on tag push matching `v*`.
  - Jobs: goreleaser build+publish, homebrew tap update, scoop bucket update, docker push to ghcr.io, docs deploy.

### 12.3 Pre-commit hooks

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks: [trailing-whitespace, end-of-file-fixer, check-yaml, check-added-large-files]
  - repo: https://github.com/golangci/golangci-lint
    hooks: [golangci-lint]
  - repo: local
    hooks:
      - id: gofumpt
        entry: gofumpt -w
      - id: go-mod-tidy
        entry: go mod tidy
      - id: go-test
        entry: go test -race ./...
```

### 12.4 mise tools

```toml
[tools]
go = "1.26"
golangci-lint = "latest"
gofumpt = "latest"
goreleaser = "latest"
python = "3.13"           # for semantic-release
uv = "latest"
pre-commit = "latest"
syft = "latest"
cosign = "latest"
```

---

## 13. Future roadmap

> **Amended 2026-04-12** based on `2026-04-12-secrets-provider-comparison.md` research. Provider priority re-ordered by cost-at-scale + feature fit. Cloudflare Workers Secrets removed as a provider candidate (structural incompatibility with external CLI reads — both Workers Secrets and Secrets Store only expose plaintext inside the Worker runtime, never via API).

### v0.2 (month 2)

- **`skret auth <provider>` command** (see `2026-04-12-skret-auth-design.md`): native auth for AWS SSO, Doppler OAuth, Infisical browser login; zero external CLI dependencies.
- **OCI Vault provider** (promoted from v0.5): $0/month at scale, best rotation story, 25 KB payload, user already has OCI tenancy.
- **`skret gen` command**: generate secret values with patterns (UUIDs, random strings, passwords with complexity rules).
- **`skret diff` command**: compare two paths/envs side-by-side.
- **Shell completions**: bash, zsh, fish, PowerShell.

### v0.3 (month 3)

- **Azure Key Vault provider** (promoted from v0.4): ~$0.09/month at scale, unlimited secrets, 25 KB payload, excellent Go SDK, Azure AD / Managed Identity integration for multi-cloud workloads.
- **`skret rotate` command**: trigger rotation workflow (emit webhook, update value, verify downstream). Leverages OCI Vault's 4-step rotation as the reference implementation.
- **`skret audit` command**: query AWS CloudTrail / OCI Audit / Azure Monitor for recent access logs across configured backends.
- **`skret init --template` expansion**: more templates (Kubernetes, Terraform, Serverless).

### v0.4 (month 4)

- **GCP Secret Manager provider** (demoted from v0.2): $20/month at scale — ship for GCP-native workloads parity, not primary recommendation.
- **Secret references & templates**: `DATABASE_URL: "postgres://${DB_USER}:${DB_PASS}@${DB_HOST}"` resolved at read time.
- **Branch configs**: environments inherit from parent configs (like Doppler's branching).
- **Per-secret backend routing**: `overrides:` block in `.skret.yaml` routes specific large secrets (TLS certs, service-account JSON) to a backend that handles them (e.g. OCI Vault) while the rest stay on the default (e.g. SSM Standard).

### v0.5 (month 5)

- **Managed rotation integration**: AWS Secrets Manager opt-in for RDS/Redshift managed rotation; wire OCI Vault 4-step rotation into the skret rotation framework.
- **Dynamic secrets**: time-limited credentials (Vault-style), starting with database credentials.
- **History/rollback** (if not promoted earlier from v0.1 experimental gate): `skret history <KEY>`, `skret rollback <KEY> --to-version=3`.
- **`skret cost estimate` command**: project monthly cost from current backend config + secret inventory. Warn on Secrets Manager misuse, over-replicated GCP SM, unnecessary SSM Advanced.

### v1.0 (month 6)

- Stable API (`pkg/skret` backward-compatible from here).
- Full 4-provider parity (AWS SSM + Secrets Manager, OCI Vault, Azure Key Vault, GCP Secret Manager).
- Team features: personal vs shared secrets (namespaces), access grants.
- Webhook support on secret changes.
- **HashiCorp Vault provider** (optional): self-hosted alternative for users who require zero cloud lock-in.

### Explicitly rejected

- **Cloudflare Workers Secrets**: scoped to single Worker, no external API for plaintext reads. Skret's use case (CLI + CI/CD consumption) is architecturally impossible.
- **Cloudflare Secrets Store**: 100-secret/account cap, 1024-byte value cap, API returns metadata only. Explicitly documented: *"Once a secret is added to the Secrets Store, it can no longer be decrypted or accessed via API or on the dashboard."* Re-evaluate only if CF adds an account-owner plaintext read API.

---

## 14. Open questions

1. **Provider registry extensibility**: should providers be pluggable via Go plugins (`plugin.Open`) for third-party providers, or only built-in? **Proposal:** built-in only for v0.x, revisit for v1.0.

2. **Secret caching**: should skret cache secrets locally (encrypted) to reduce SSM API calls? **Proposal:** no caching in v0.1. Add opt-in cache in v0.3 once usage patterns observed.

3. **MCP server**: should skret also ship as an MCP server so AI agents can manage secrets? **Proposal:** defer to v1.0+ roadmap, separate repo `skret-mcp`.

4. **Configuration bootstrap**: where does skret store its own secrets (e.g., Doppler token for import)? **Proposal:** always env vars, never config file. Document clearly.

5. **Binary signing keys**: cosign keyless (GitHub OIDC) sufficient, or need long-lived signing key? **Proposal:** cosign keyless for v0.x.

---

## 15. Risks & mitigations

| Risk                                           | Likelihood | Impact | Mitigation                                               |
|------------------------------------------------|------------|--------|----------------------------------------------------------|
| AWS free tier policy changes                   | Low        | High   | Monitor billing alerts; 10k params covers planned scale. |
| KMS 20k requests/month exceeded                | Medium     | Medium | Use `GetParametersByPath` batching; document cache option. |
| 40 TPS throttle blocks CI                      | Low        | Medium | Batch calls; document backoff-retry behavior.            |
| Breaking changes in AWS SDK v2                 | Low        | Medium | Pin minor versions in go.mod; integration tests.         |
| goreleaser config drift between platforms      | Medium     | Low    | CI tests release build on all platforms.                 |
| Doppler/Infisical API changes                  | Medium     | Low    | Version their API in client; document minimum version.   |
| GitHub Actions secrets API rate limit          | Low        | Low    | Respect rate limit headers, backoff.                     |

---

**End of design document.**
