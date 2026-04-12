# Style Guide - skret

## Architecture
Cloud-provider secret manager CLI wrapper. Go, single-binary distribution.

## Go
- Formatter: gofumpt (stricter than gofmt)
- Linter: golangci-lint (config in .golangci.yaml)
- Test: testing + testify, -race -cover ./...
- Module: Go 1.26+
- Core deps: Cobra, AWS SDK v2, slog, yaml.v3

## Code Patterns
- Context propagation: every provider method accepts context.Context
- Error wrapping: fmt.Errorf("op %q: %w", key, err) at each layer boundary
- Secret redaction: slog handler redacts known values; never log raw secret values
- Thin CLI, rich library: cmd/skret minimal, pkg/skret is the public surface
- Build-tagged platform code: exec_unix.go + exec_windows.go
- Atomic file writes: temp file + os.Rename for local provider
- File locking: flock (Unix), LockFileEx (Windows)

## Commits
Only `fix:` and `feat:` (never chore:, docs:, refactor:, ci:, build:, style:, perf:, test:).
Never use `!` breaking-change marker. Never `--no-verify`.

## Security
Never commit credentials. Use env vars only. SecureString + KMS for AWS SSM.
Validate all config paths. Filter `exclude:` keys from env injection.
