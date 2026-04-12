# Bolt Learnings

## Refactoring newEnvCmd
- **What**: Split `newEnvCmd` into `getEnvPairs` and `printEnvPairs`.
- **Why**: The function exceeded recommended length, mixing logic for data retrieval and presentation.
- **Impact**: Improved readability and testability of the `env` command.
- **Measurement**: All `TestEnvCmd_*` tests in `internal/cli/cli_test.go` pass.

## CI Fix for golangci-lint
- **What**: Added `install-mode: go` to `golangci-lint-action`.
- **Why**: The pre-built binary for `golangci-lint` was built with a Go version (1.24) lower than the project's Go version (1.26), causing a config load error.
- **Impact**: CI lint job now correctly builds and runs the linter using the specified Go version.
- **Measurement**: CI pipeline should pass the linting stage.
