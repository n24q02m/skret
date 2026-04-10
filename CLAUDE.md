# skret

Cloud-provider secret manager CLI wrapper. Go 1.25.

## Build & Test

- Build: `go build -o skret ./cmd/skret`
- Test: `go test -race -cover ./...`
- Lint: `golangci-lint run ./...`
- Format: `gofumpt -w cmd internal pkg`

## Architecture

- `cmd/skret/` — Cobra CLI entry point
- `internal/cli/` — command implementations
- `internal/config/` — `.skret.yaml` schema + loader
- `internal/provider/` — `SecretProvider` interface + registry
- `internal/provider/aws/` — AWS SSM Parameter Store
- `internal/provider/local/` — local YAML file (dev/test)
- `internal/importer/` — import from Doppler/Infisical/dotenv
- `internal/syncer/` — sync to GitHub Actions/dotenv
- `internal/exec/` — env injection + process exec
- `pkg/skret/` — public Go library API

## Rules

- Commits: only `fix:` and `feat:` prefixes
- Test coverage: >=95% on `internal/`, >=90% on `pkg/`
- Secret values MUST NEVER appear in logs, errors, or test output
- All provider calls accept `context.Context`
- Errors wrap with `fmt.Errorf("operation %q: %w", key, err)`
