# Task 5 per-key target acknowledgement report

## Status

DONE_WITH_CONCERNS for the bounded durable per-key acknowledgement slice. No provider, KMS, Hub, executor, deployment, production, candidate, public, or release mutation was performed; all target coverage uses local synthetic HTTP fixtures.

## Commits

- `655b5d2` — `feat: journal per-key sync acknowledgements`
- `3a748bd` — `fix: recover durable sync journal state`
- `e3d4584` — `docs: report per-key sync acknowledgements` (this report; prior report commit)

## Focused TDD evidence

- Red: `go test ./internal/syncer -run 'TestPerKeySyncer_' -count=1` failed because the new optional per-key capability was absent.
- Red: `go test ./internal/cli -run 'TestSync_PerKeyTargetJournalsPartialFailureWithoutFalseSuccess' -count=1` failed because the existing batch path attempted the unattempted key and journaled all keys as reconciliation.
- Green: `go test ./internal/syncer -run 'TestPerKeySyncer_' -count=1` — PASS (`ok github.com/n24q02m/skret/internal/syncer`).
- Green: `go test ./internal/cli -run 'TestSync_PerKeyTargetJournalsPartialFailureWithoutFalseSuccess' -count=1` — PASS (`ok github.com/n24q02m/skret/internal/cli`).
- Green compatibility: `go test ./internal/syncer -run 'TestCloudflareSyncer_Pages|TestCloudflareExistingKeys_PagesUnsupported|TestCloudflareSyncer_Worker|TestPerKeySyncer_' -count=1` — PASS.
- Green compatibility: `go test ./internal/syncer -run 'TestGitHubSyncer_|TestNewGitHub|TestPerKeySyncer_' -count=1` — PASS.
- Green CLI regressions: `go test ./internal/cli -run 'TestSyncCmd_Dotenv|TestSyncCmd_SkipUnchanged|TestSyncOptions_Run_JSONFormat|TestSyncOptions_Run_TableFormatUnchanged|TestSyncOptions_Run_Rotate|TestSync_PerKeyTargetJournalsPartialFailureWithoutFalseSuccess' -count=1` — PASS.
- Red: `go test ./internal/cli -run 'TestSync_PerKeyRecoversPendingOperationAfterFinalJournalSaveFailure' -count=1` failed because a pending operation with all keys acknowledged was never finalized after a failed final journal save.
- Green: `go test ./internal/cli -run 'TestSync_PerKey(RecoversPendingOperationAfterFinalJournalSaveFailure|JournalFailureIsGenericAndValueFree|TargetJournalsPartialFailureWithoutFalseSuccess)' -count=1` — PASS.

## Implemented

- Added optional `syncer.PerKeySyncer` with one-key `SyncKey` semantics.
- Added GitHub Actions `SyncKey`, reusing the existing public-key fetch, encryption, authentication, name normalization, and retry path.
- Added a Cloudflare Worker-only adapter from the registry factory; Cloudflare Pages and dotenv remain batch-only so whole-file/whole-patch semantics are preserved. The legacy `NewCloudflare` concrete shape remains compatible.
- Added recovery for a loaded pending operation whose operation-owned keys were all acknowledged before a final journal save failure; recovery finalizes and persists without rewriting provider keys.
- Classified per-key provider failures as network errors and state record/save/finalize failures as generic errors, with value-free regression coverage.
- Updated durable CLI operations to write one key at a time for per-key targets, save each successful key acknowledgement before the next write, mark only a failed key `needs_reconciliation`, leave unattempted keys pending, finalize/save only after all successes, and emit success output only after persistence.
- Added deterministic adapter retry/error-boundary tests, Pages capability exclusion coverage, and a CLI partial-failure regression that checks call order/count, state hashes/outcomes/phase, pending unattempted keys, and no false global success.

## Concerns / residuals

- Remote envelope/provider authorization, executor verification, KMS, Hub, candidate, deployment, and production proof remain outside this offline source slice as required.
- `NewCloudflare` retains its legacy concrete return shape; config/registry-built Worker targets receive the per-key adapter used by the CLI, while direct legacy construction remains batch-compatible.
