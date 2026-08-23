# Task 6 sync-state migration CLI report

## Status

PASS for the source-only `sync-state migrate` CLI slice and its optional
authenticated executor-envelope submission route. The command verifies a
signed, value-free state manifest and exact source row/hash before either the
existing offline local migration or a metadata-only remote submission. Remote
mode never mutates local state, backup, or journal files. No provider, KMS,
Hub, executor, deployment, candidate, production, public, or release mutation
was performed.

## Commits

- `8d9bbb5` — `feat: add sync-state migration CLI`
- `b796367` — `feat: route state migration through executor envelope`

## Implemented

- Preserved `--execute` as the verified offline/local
  `MigrateStateFileV1ToV2` path and documented that it does not submit a
  remote request.
- Added explicit `--remote-execute` plus `--executor-url`,
  `--operator-session`, and `--signing-key` flags. Remote mode requires
  explicit role, audience, operation identity, manifest/public-key inputs,
  Hub origin, session cookie, and Ed25519 private signing key.
- Added raw/hex private-key file parsing without echoing key, cookie, request
  body, or state values. `SKRET_OPERATOR_SESSION_COOKIE` is used only when
  `--operator-session` is omitted.
- Built a deterministic metadata-only migration body binding operation ID,
  canonical state/journal paths, manifest digest, target, and source hash/size.
  Submission uses a fresh random nonce and short expiry through the existing
  `syncer.EnvelopeClient`, which enforces the fixed
  `/operator/executor-envelope` route and forwards the operator session cookie.
- Remote output reports only submission phase and response hash/size; remote
  errors do not include response bodies. Remote success and error fixtures
  assert no local state, `.v1` backup, or journal mutation.

## TDD and focused verification

- Red: after adding the remote tests, focused CLI compilation failed with the
  expected missing `readCLIStateMigrationPrivateKey` implementation.
- Green: `go test ./internal/cli -run 'Test(RootCmd_RegistersSyncStateMigrate|SyncStateMigrate|ReadCLIStateMigrationPrivateKey)' -count=1` — PASS (`ok github.com/n24q02m/skret/internal/cli`, 10.563s).
- Green envelope compatibility: `go test ./internal/syncer -run 'Test(BuildSignedEnvelope|EnvelopeClient|VerifySignedEnvelope)' -count=1` — PASS (`ok github.com/n24q02m/skret/internal/syncer`, 2.745s).
- `gofmt -w internal/cli/sync_state.go internal/cli/sync_state_test.go` — PASS.
- `git diff --check -- internal/cli/sync_state.go internal/cli/sync_state_test.go` — PASS.

## Residuals and gates

- The source tree now has CLI-side authenticated envelope submission, but no
  production Hub executor-envelope router or executor runtime was wired by this
  slice. The route therefore remains a source-only integration seam backed by
  httptest fixtures; provider acknowledgement, executor-side replay handling,
  deployment, candidate, production, and release gates remain outside scope.
- No private evidence was added by this task.
