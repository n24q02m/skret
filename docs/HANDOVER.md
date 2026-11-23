# HANDOVER

## Status: GA (Actively Maintained)

`skret` is an active, generally available (GA) multi-cloud secret manager CLI, Go library (`pkg/skret`), and MCP server for developers, CI/CD pipelines, and AI coding agents. It unifies secret storage across cloud providers and local encrypted files behind a single `.skret.yaml` contract.

## Architecture and Surfaces

- **CLI (`cmd/skret`)**: Core commands for reading, writing, running processes with injected secrets, validating schemas, diffing environments, scanning for leaks, and projecting secrets to target platforms (`skret get`, `set`, `list`, `delete`, `rotate`, `run`, `env`, `sync`, `diff`, `doctor`, `scan`, `template`, `watch`, `browse`).
- **Go SDK (`pkg/skret`)**: Public library API with strict typed errors and provider abstraction (`internal/provider/...`).
- **MCP Server**: Exposes read-only secret inspection and policy-gated write/rotate tools to MCP-compatible agent harnesses (`mcp.allow_write` defaults to `false`, `mcp.allowed_envs` restricts environment scope, and local reads are recorded to the audit log).
- **Providers (`internal/provider`)**:
  - AWS Systems Manager Parameter Store (`aws-ssm`)
  - Google Cloud Secret Manager (`gcp-sm`)
  - Azure Key Vault (`azure-kv`)
  - Oracle Cloud Infrastructure Vault (`oci-vault`)
  - Local SOPS / age encrypted files (`local`)
- **Sync Targets (`internal/syncer`)**:
  - GitHub Actions repository and environment secrets (`github`)
  - Dotenv files with atomic writes (`dotenv`)
  - Kubernetes `Secret` manifests (`k8s`)
  - Terraform `.tfvars` files (`terraform`)

## Release and Verification Runbook

1. **Continuous Integration (`.github/workflows/ci.yml`)**:
   - Enforces `verify_readme_sync.py` and repo-bootstrap policy tests.
   - Runs `golangci-lint` across `linux`, `windows`, and `darwin` targets.
   - Executes unit and race-detector test suites on `ubuntu-latest`, `windows-latest`, and `macos-latest` with coverage thresholds (`>= 95%` on both `internal/...` and `pkg/skret/...`).
   - Verifies multi-arch OCI archive builds (`linux/amd64`, `linux/arm64`).
2. **Continuous Delivery (`.github/workflows/cd.yml`)**:
   - Triggered via `workflow_dispatch` (`release_type=beta` or `release_type=stable`).
   - Uses `better-semantic-release` to compute versions from Conventional Commits, cross-compiles release binaries via GoReleaser, signs artifacts and SBOMs with Cosign keyless OIDC, and updates `n24q02m/homebrew-tap` and `n24q02m/scoop-bucket` on stable releases.
3. **Documentation**:
   - Published from `docs/` (Astro Starlight) and aggregated into `docs.n24q02m.com/skret/`.
