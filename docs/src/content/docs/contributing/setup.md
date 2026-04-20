---
title: Development Setup
description: "The `mise run setup` command runs:"
---

## Prerequisites

- [mise](https://mise.jdx.dev/) (tool version manager)
- Go 1.22+ (installed via mise)
- Git

## Quick Setup

```bash
git clone https://github.com/n24q02m/skret.git
cd skret
mise install
mise run setup
```

The `mise run setup` command runs:

1. `mise install` -- installs Go and golangci-lint at pinned versions
2. `go mod download` -- fetches Go dependencies
3. `pip install pre-commit` -- installs the pre-commit framework
4. `pre-commit install` -- registers the pre-commit hook
5. `pre-commit install --hook-type commit-msg` -- registers the commit-msg hook (enforces `feat:`/`fix:` prefix)

## Manual Setup

If you prefer not to use mise:

```bash
# Install Go 1.22+ from https://go.dev/dl/
go mod download

# Install pre-commit
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg

# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Build

```bash
go build -o skret ./cmd/skret
```

The binary is output to `./skret` in the project root.

## Test

```bash
# Run all tests
go test -race -cover ./...

# Run tests with verbose output
mise run test

# Run tests for a specific package
go test -race -cover ./internal/config/...
```

## Lint

```bash
# Run all linters
golangci-lint run ./...

# Auto-fix formatting issues
mise run fix

# Or manually
gofmt -w .
golangci-lint run --fix ./...
```

## Pre-Commit Hooks

The repo uses these hooks (run automatically on `git commit`):

| Hook | Description |
|------|-------------|
| `trailing-whitespace` | Removes trailing whitespace |
| `end-of-file-fixer` | Ensures files end with a newline |
| `check-yaml` | Validates YAML syntax |
| `check-added-large-files` | Prevents committing large files |
| `enforce-commit` | Rejects commits without `feat:` or `fix:` prefix |

Run hooks manually:

```bash
pre-commit run --all-files
```

## Project Structure

```
cmd/skret/              -- CLI entry point (Cobra)
internal/cli/           -- Command implementations
internal/config/        -- .skret.yaml schema + loader + resolver
internal/provider/      -- SecretProvider interface + registry
internal/provider/aws/  -- AWS SSM Parameter Store
internal/provider/local/-- Local YAML file (dev/test)
internal/importer/      -- Import from Doppler/Infisical/dotenv
internal/syncer/        -- Sync to GitHub Actions/dotenv
internal/exec/          -- env injection + process exec
internal/logging/       -- Structured logging (slog)
pkg/skret/              -- Public Go library API
tests/                  -- Integration and E2E tests
docs/                   -- VitePress documentation site
```

## Running the Docs Site

```bash
cd docs
npm install
npm run dev
```

The site runs at `http://localhost:5173`.
