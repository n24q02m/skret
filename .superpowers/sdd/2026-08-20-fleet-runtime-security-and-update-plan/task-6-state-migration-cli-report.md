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

## Security executor source-only follow-up

- Added the separate source-only `skret-security-executor` Worker entrypoint,
  `SecurityExecutorReplay` Durable Object, RPC replay-status adapter, strict
  raw-safe key/config validation, and AES-GCM metadata acknowledgement path.
  The Worker accepts only the exact seven-field migration metadata body, never
  performs migration/provider calls, and does not return plaintext paths/body or
  source values.
- Added `hub/wrangler.executor.jsonc` with the `EXECUTOR_REPLAY` binding and
  first migration tag, plus matching ordinary Hub `EXECUTOR` service bindings
  in both committed Hub configs. Vitest uses a local fail-closed service stub;
  no remote service was contacted.
- Focused source/config evidence:
  `pnpm exec vitest run test/security-executor.test.ts` — PASS (11 tests);
  `pnpm typecheck` — PASS; `python -m unittest
  tests/repo_bootstrap/test_executor_config_policy.py -v` — PASS (2 tests);
  `pnpm dryrun` and `pnpm exec wrangler deploy --dry-run --config
  wrangler.executor.jsonc` — PASS. No deployment, provider call, KMS access,
  or real remote migration was performed.

## Residuals and gates

- Production deployment, live Hub-to-executor binding/readback, secret
  injection, candidate/production promotion, provider acknowledgement, and
  real host migration remain explicitly gated. The source/config parity checks
  prove only committed wiring shape and dry-run compilation, not live routing.
- Remote CLI output remains `submitted`, not committed. No private evidence was
  added by this source-only follow-up.
