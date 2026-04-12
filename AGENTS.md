# Agent Collaboration

## Quick Reference

- Language: Go 1.25.0
- Test: `go test -race -cover ./...`
- Lint: `golangci-lint run ./...`
- Build: `go build -o skret ./cmd/skret`

## Key Interfaces

- `internal/provider.SecretProvider` — all providers implement this
- `internal/importer.Importer` — all import sources implement this
- `internal/syncer.Syncer` — all sync targets implement this

## Adding a New Provider

1. Create `internal/provider/<name>/<name>.go`
2. Implement `SecretProvider` interface
3. Register in `internal/provider/registry.go`
4. Add tests in `internal/provider/<name>/<name>_test.go`
5. Add docs in `docs/providers/<name>.md`
