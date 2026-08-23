# Task 6 state migration report

## Status

PASS for the bounded local v1-to-v2 state-file migration slice. Only synthetic temporary-root files were mutated; no provider, KMS, Hub, executor, deployment, candidate, production, public, or release operation was performed.

## Commits

- `5805e07` — `feat: add crash-safe state migration`
- `ab6db7f` — `fix: retain migration temp after backup rename`
- `d0e0a68` — `fix: serialize state migration transitions`
- `805e897` — `fix: harden migration race and file security`
- `bdf31a5` — `fix: preserve migration recovery artifacts`

- TDD red: `go test ./internal/syncer -run 'Test(StateMigration|MigrateState|RecoverState)' -count=1` failed before implementation with undefined `StateMigrationJournal`, `MigrateStateFileV1ToV2`, and `RecoverStateMigration` symbols.
- P1 red: `go test ./internal/syncer -run 'TestStateMigration_(PostBackup|Secures|RecoverySecures)' -count=1` failed before the fault-injection persist hook existed.
- P1 green: `go test ./internal/syncer -run 'TestStateMigration_(PostBackup|TempRename|Secures|RecoverySecures)' -count=1` — PASS.
- Race green: `go test ./internal/syncer -run 'TestStateMigration_(Serializes|RecoveryDoesNotOverwrite|PostRenameBackupMismatch)' -count=1` — PASS.
- Windows manifest protection: `go test ./internal/syncer -run 'TestWindows(StableRootHandle|FinalPathContainment|Scanner|OpenedDirectoryHandle)' -count=1` — PASS.
- Unsafe-ancestor regression: `go test ./internal/syncer -run TestStateMigration_RejectsUnsafeAncestorBeforeRecoveryMutation -count=1` — PASS.
- Windows compile: `GOOS=windows GOARCH=amd64 go test -c ./internal/syncer` — PASS.
- Linux compile: `GOOS=linux GOARCH=amd64 go test -c ./internal/syncer` — PASS.
- Green: `go test ./internal/syncer -run 'Test(StateMigration|MigrateState|RecoverState)' -count=1` — PASS.
- Compatibility: `go test ./internal/syncer -run 'Test(StateMigration|MigrateState|RecoverState|SaveSyncState|SyncState)' -count=1` — PASS.

## Implemented
- Added versioned, value-free `StateMigrationJournal` metadata with operation ID, signed manifest digest, exact source/backup/temp/journal paths, source and desired hashes/sizes, phases, and timestamps.
- Added strict operation ID, absolute path/traversal, digest/hash, phase, timestamp, journal schema, regular-file, and exact-path validation.
- `MigrateStateFileV1ToV2` verifies the signed manifest before mutation, requires the exact manifest source row hash/size, accepts only a v1 JSON object, adds `schema_version=2` and `manifest_digest`, fsyncs a same-directory temp, journals `prepared` and `backup_renamed`, atomically preserves the original at `.v1`, commits v2, and journals `committed`.
- Before source rename, migration forces 0600 source/backup modes; temp retention now survives every post-backup failure so recovery can restore or complete deterministically, and recovery re-secures restored/committed files. Windows builds additionally apply a protected owner-only DACL through `x/sys/windows`; non-Windows builds keep the portable mode-only path.
- Migrate and Recover serialize with the existing `syncStateSaveMu`, re-check backup hash/size after the journaled backup transition, and use exclusive same-directory hardlinks rather than replacement renames; an appearing source fails closed and post-rename mismatches restore without overwriting. Committed journal writes re-inspect source/backup/temp first.
- Ancestor/reparse checks run before mutation helpers; the existing Windows stable-root/final-path scanner remains the authority for manifest traversal, while migration fails closed on unsafe ancestor metadata.
- Added synthetic tests for manifest-before-mutation, successful migration/backup/journal, v1 parsing/trailing data rejection, prepared and backup-renamed recovery, backup preservation, idempotence/different-operation refusal, ambiguity, traversal, invalid journal schema, post-backup persistence/temp-rename failures, secure modes, SaveSyncState serialization, appearing-source no-replacement, post-rename mismatch reconciliation, source-removal failure retention, unsafe ancestors, temp cleanup, and value-free output.
## Residuals

- This source-only slice intentionally does not wire migration into CLI/provider/Hub/executor flows and does not claim provider acknowledgements, KMS authorization, rollback policy, candidate readiness, production readiness, or public release proof.
