# Task 6 migration manifest report

## Status

PASS for the bounded offline signed state-manifest slice. The Windows path-reopen P1 is closed: traversal now enumerates opened directory handles and hashes opened file handles, with no provider, KMS, Hub, executor, deployment, candidate, production, public, or release mutation.

- `1c805a0` — `feat: add signed state migration manifest`
- `77bec3f` — `fix: harden migration manifest traversal`
- `3ac3597` — `fix: harden Windows migration manifest traversal`

## Focused test evidence

- Original TDD red: `go test ./internal/syncer -run 'Test(StateManifest|BuildStateManifest|VerifyStateManifest)' -count=1` failed before implementation with undefined manifest symbols.
- Original green: `go test ./internal/syncer -run 'Test(StateManifest|BuildStateManifest|VerifyStateManifest)' -count=1` — PASS.
- Symlink/empty-root proof: `go test ./internal/syncer -run 'TestBuildStateManifest_RejectsEmptyRootsAndSymlinkEntries' -count=1 -v` — PASS.
- TDD red for the hardening regressions: the new unsafe-mode and expected-file-identity tests failed to compile before the hardening helpers/signature existed.
- Green before the Windows P1: `go test ./internal/syncer -run 'Test(StateManifest|BuildStateManifest|VerifyStateManifest|HashStateManifestFile|RevalidateStateManifestDirectories)' -count=1` — PASS.
- Windows P1 TDD red: `go test ./internal/syncer -run 'TestWindows(FinalPathContainment|Scanner)' -count=1 -v` failed before the platform scanner with undefined final-path containment helper.
- Windows focused green: `go test ./internal/syncer -run 'Test(StateManifest|BuildStateManifest|VerifyStateManifest|HashStateManifestFile|RevalidateStateManifestDirectories|Windows)' -count=1` — PASS.
- Windows opened-handle replacement proof: `TestWindowsOpenedDirectoryHandleDoesNotFollowPathReplacement` — PASS; after the original directory path was replaced by a real junction, `ReadDir` on the already-open handle returned only the original entry.
- Windows junction proof: `TestBuildStateManifest_RejectsWindowsJunctionRootsAndEntries` and `TestWindowsScannerRejectsJunctionEntryBeforeEnumeration` — PASS; real NTFS junction roots and entries were rejected without exposing the target path.
- Portable wrapper compile: `GOOS=linux GOARCH=amd64 go test -c ./internal/syncer` — PASS.

## Implemented

- Added versioned `StateManifest` and `StateManifestFile` metadata types with role, audience, canonical absolute `source_root`, nonce, expiry, sorted exhaustive file rows, and detached Ed25519 signature.
- Added deterministic canonical JSON signing bytes that exclude the detached signature and contain only paths, sizes, SHA-256 digests, and authority metadata; file contents/secret values never enter canonical bytes or errors.
- Hardened the portable scanner with central `ModeSymlink|ModeIrregular` rejection for roots, ancestors, and entries; every entry is inspected with `Info` before directory/file decisions, and the existing portable body remains behind `scanStateManifestRootPortable`.
- Added platform dispatch through `migration_manifest_scan_other.go` and a Windows-only `migration_manifest_scan_windows.go`. Windows opens the root and every child with `CreateFileW` using `FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS` and all share flags, binds opened child identities with `os.SameFile`, enumerates only through opened `*os.File` handles, hashes opened file handles, and rejects any opened handle whose `GetFinalPathNameByHandle` path is outside the case-insensitive opened-root final path.
- Retained value-free manifest errors and avoided provider/KMS/Hub dependencies and migration writes/deletes.

## Residuals

- Executor/Hub authorization, nonce replay storage, migration v1/v2 writes, provider acknowledgements, rollback, and candidate/production proof remain outside this source-only slice.
