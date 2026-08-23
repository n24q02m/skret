# Task 6 migration manifest report

## Status

PASS for the bounded offline signed state-manifest slice. The Windows path-reopen P1 is closed: traversal now enumerates opened directory handles and hashes opened file handles, while the root is opened through a stable no-follow ancestor chain. No provider, KMS, Hub, executor, deployment, candidate, production, public, or release mutation was performed.

- `1c805a0` — `feat: add signed state migration manifest`
- `77bec3f` — `fix: harden migration manifest traversal`
- `3ac3597` — `fix: harden Windows migration manifest traversal`
- `3e37fa8` — `fix: bind Windows manifest roots through stable ancestors`
- `47e7a29` — `fix: handle extended UNC manifest roots`

## Focused test evidence

- Original TDD red: `go test ./internal/syncer -run 'Test(StateManifest|BuildStateManifest|VerifyStateManifest)' -count=1` failed before implementation with undefined manifest symbols.
- Original green: `go test ./internal/syncer -run 'Test(StateManifest|BuildStateManifest|VerifyStateManifest)' -count=1` — PASS.
- Symlink/empty-root proof: `go test ./internal/syncer -run 'TestBuildStateManifest_RejectsEmptyRootsAndSymlinkEntries' -count=1 -v` — PASS.
- TDD red for the hardening regressions: the new unsafe-mode and expected-file-identity tests failed to compile before the hardening helpers/signature existed.
- Green before the Windows P1: `go test ./internal/syncer -run 'Test(StateManifest|BuildStateManifest|VerifyStateManifest|HashStateManifestFile|RevalidateStateManifestDirectories)' -count=1` — PASS.
- Windows P1 TDD red: `go test ./internal/syncer -run 'TestWindows(FinalPathContainment|Scanner)' -count=1 -v` failed before the platform scanner with undefined final-path containment helper.
- Stable-ancestor TDD red: `go test ./internal/syncer -run TestWindowsStableRootHandleRejectsAncestorJunctionSwap -count=1 -v` failed before the chain helper with an undefined `openWindowsStateManifestRoot`.
- Extended-UNC TDD red: `go test ./internal/syncer -run TestWindowsStateManifestPathComponentsHandlesExtendedUNC -count=1 -v` failed before the parser special case because `\\?\UNC\server\share\state` was split at `\\?\UNC\`.
- Extended-UNC focused green: the same command — PASS for `\\?\UNC\` and `\\.\UNC\` forms, with server/share retained in the volume root.
- Stable-ancestor focused green: `go test ./internal/syncer -run 'TestWindows(StableRootHandle|FinalPathContainment|Scanner|OpenedDirectoryHandle)' -count=1` — PASS; a parent renamed and replaced with a junction to the moved original was rejected even though the root identity matched the pre-swap identity.
- Windows focused green: `go test ./internal/syncer -run 'Test(StateManifest|BuildStateManifest|VerifyStateManifest|HashStateManifestFile|RevalidateStateManifestDirectories|Windows)' -count=1` — PASS.
- Windows opened-handle replacement proof: `TestWindowsOpenedDirectoryHandleDoesNotFollowPathReplacement` — PASS; after the original directory path was replaced by a real junction, `ReadDir` on the already-open handle returned only the original entry.
- Windows junction proof: `TestBuildStateManifest_RejectsWindowsJunctionRootsAndEntries` and `TestWindowsScannerRejectsJunctionEntryBeforeEnumeration` — PASS; real NTFS junction roots and entries were rejected without exposing the target path.
- Portable wrapper compile: `GOOS=linux GOARCH=amd64 go test -c ./internal/syncer` — PASS.

## Implemented

- Added versioned `StateManifest` and `StateManifestFile` metadata types with role, audience, canonical absolute `source_root`, nonce, expiry, sorted exhaustive file rows, and detached Ed25519 signature.
- Added deterministic canonical JSON signing bytes that exclude the detached signature and contain only paths, sizes, SHA-256 digests, and authority metadata; file contents/secret values never enter canonical bytes or errors.
- Hardened the portable scanner with central `ModeSymlink|ModeIrregular` rejection for roots, ancestors, and entries; every entry is inspected with `Info` before directory/file decisions, and the existing portable body remains behind `scanStateManifestRootPortable`.
- Added platform dispatch through `migration_manifest_scan_other.go` and a Windows-only `migration_manifest_scan_windows.go`. Windows opens the volume root and every lexical root component with `CreateFileW` using `FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS` and all share flags, keeps that no-follow ancestor chain open, requires each opened component final path to remain within its stable parent final path, binds opened child identities with `os.SameFile`, enumerates only through opened `*os.File` handles, hashes opened file handles, and rejects any opened handle whose `GetFinalPathNameByHandle` path is outside the case-insensitive opened-root final path.
- Retained value-free manifest errors and avoided provider/KMS/Hub dependencies and migration writes/deletes.

## Residuals

- Executor/Hub authorization, nonce replay storage, migration v1/v2 writes, provider acknowledgements, rollback, and candidate/production proof remain outside this source-only slice.
