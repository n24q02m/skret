# Bolt Learnings

## Refactoring newEnvCmd
- **What**: Split `newEnvCmd` into `getEnvPairs` and `printEnvPairs`.
- **Why**: The function exceeded recommended length, mixing logic for data retrieval and presentation.
- **Impact**: Improved readability and testability of the `env` command.
- **Measurement**: All `TestEnvCmd_*` tests in `internal/cli/cli_test.go` pass.
