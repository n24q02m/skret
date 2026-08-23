# Task 6 sync-state migration CLI report

## Status

PASS for the source-only `sync-state migrate` CLI slice. The command verifies a signed, value-free state manifest and exact source row/hash before a dry-run result; `--execute` delegates the verified local transaction to `syncer.MigrateStateFileV1ToV2`, preserving the `.v1` backup and committed journal. No provider, KMS, Hub, executor, deployment, candidate, production, public, or release mutation was performed.

## Commit

- `8d9bbb5` — `feat: add sync-state migration CLI`

## Implemented

- Registered `sync-state migrate` under the Cobra root.
- Added `--to` (only `v2`), required manifest/journal/public-key inputs, optional exact manifest-row `--state`, role/audience/operation identity, `--execute`, and table/JSON output.
- Accepted Ed25519 public keys as direct hex or regular files containing raw or hex key bytes.
- Loaded and verified the signed manifest, resolved state only through an exact manifest file row under the signed source root, rejected traversal and ambiguous rows, and checked source size/hash without emitting file contents.
- Kept dry-run non-mutating and value-free. Execute output exposes only phase, paths, sizes, and SHA-256 metadata; it does not print state fields or values.
- Covered registration, required/invalid flags, key-file inputs, single-row inference, dry-run non-mutation, successful migration with backup/journal, committed-operation idempotence, manifest mismatch before mutation, traversal, and ambiguous-row rejection.

## TDD and focused verification

- Red: `go test ./internal/cli -run 'Test(RootCmd_RegistersSyncStateMigrate|SyncStateMigrate)' -count=1` failed before implementation with the expected missing `sync-state` command/registration errors.
- Green: `go test ./internal/cli -run 'Test(RootCmd_RegistersSyncStateMigrate|SyncStateMigrate|SyncCmd)' -count=1` — PASS (`ok github.com/n24q02m/skret/internal/cli`, 10.984s).
- Green migration API compatibility: `go test ./internal/syncer -run 'Test(StateMigration|MigrateState|RecoverState)' -count=1` — PASS (`ok github.com/n24q02m/skret/internal/syncer`, 7.034s).
- `gofmt -w internal/cli/sync_state.go internal/cli/sync_state_test.go internal/cli/root.go` — PASS.
- `git diff --check` — PASS.

## Residuals and gates

- The source tree has no executor-backed envelope submission wiring for this command. `--execute` therefore performs only the verified local migration; it does not claim remote executor execution. Authenticated Hub routing, short-lived executor identity, envelope submission, replay handling, provider acknowledgement, deployment, candidate, production, and release gates remain outside this slice.
- No private evidence was added by this task.
