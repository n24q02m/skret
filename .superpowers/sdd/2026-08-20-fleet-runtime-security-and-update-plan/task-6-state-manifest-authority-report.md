# Signed StateManifest authority report

## Decision

`PASS_WITH_SOURCE_ONLY_RESIDUALS` for the bounded source-only change. Remote state migration now carries the exact signed StateManifest file bytes in a standard-base64 `state_manifest` body field while retaining the canonical manifest digest and existing metadata fields. The security executor independently parses, canonicalizes, hashes, and verifies that manifest with a separate out-of-band Ed25519 key before returning an encrypted metadata acknowledgement. The remote CLI remains `submitted`; it never claims or performs a host migration.

## Implemented

- `internal/cli/sync_state.go`
  - Reads the manifest bytes once, retaining the exact on-disk bytes separately from the parsed manifest.
  - Adds `state_manifest` as a `[]byte` JSON field; Go JSON encoding emits standard base64 with no line breaks.
  - Continues to compute `manifest_digest` from canonical `StateManifest.CanonicalSigningBytes`, so raw formatting/signature bytes cannot replace the canonical digest authority.
  - Leaves local dry-run and explicit local `--execute` behavior unchanged; remote execution still performs no local mutation and emits metadata-only output.
  - Hardens `readCLIStateManifestWithBytes` with exact case-sensitive root/file-row wire-key validation (including missing/unknown aliases), token-based duplicate-key detection for nested JSON, `DisallowUnknownFields`, and strict canonical standard-base64 signature validation (88 characters, standard alphabet, valid padding, canonical re-encode equality) without exposing values, while preserving exact raw file bytes for remote submission.
- `hub/src/security-executor.ts`
  - Requires `EXECUTOR_STATE_MANIFEST_PUBLIC_KEY` in the executor build options and fails closed on missing/malformed/import-failing values. The envelope signer key and AES response key remain separate out-of-band values.
  - Bounds the migration body and embedded manifest at 256 KiB; oversized input is rejected before JSON/manifest authority decoding. The private handler's existing 1 MiB envelope boundary remains in force.
  - Requires the exact eight-field migration body, rejects duplicate JSON keys, and accepts only canonical standard-base64 manifest bytes.
  - Validates the exact StateManifest object and file-row schemas, version, envelope role/audience binding, canonical absolute source root, nonempty sorted safe relative paths, SHA-256 row digests, nonnegative safe sizes, nonce, future expiry, and the 15-minute manifest TTL.
  - Rejects `/` in Windows (`^[A-Za-z]:\\(?:[^\\/]+(?:\\[^\\/]+)*)?$`) and UNC (`^\\\\[^\\/]+\\[^\\/]+(?:\\[^\\/]+)*$`) path patterns, preventing mixed-separator traversal, and strictly honors `allowRoot` for Windows drive roots (`C:\`) and UNC share roots (`\\server\share`) while keeping POSIX semantics separate.
  - Reconstructs Go-compatible canonical signing JSON with field order, RFC3339Nano UTC normalization, and Go JSON HTML escaping (`<`, `>`, `&`, U+2028/U+2029), computes the canonical `sha256:` digest, and verifies the detached Ed25519 signature.
  - Requires the canonical digest to equal both envelope and body `manifest_digest`, and requires `state_path` to equal source-root plus the exact row while `source_hash`/`source_size` equal that row. No local filesystem, provider, KMS, or migration write is reachable from the executor authority.
  - Returns only the existing encrypted metadata acknowledgement; signed manifest bytes and paths are never projected in plaintext.
- `hub/test/security-executor-state-manifest.test.ts`
  - Adds signed valid/tampered fixtures and coverage for missing/malformed state key, signature/byte tampering, role/audience and digest mismatches, path/row/hash/size mismatches, expiry/TTL, nonce, sorted rows, duplicate keys, oversized bodies, mixed Windows/UNC forward-slash traversal (with the source-root case keeping `state_path` canonical), drive/UNC root rejection when `allowRoot=false`, encrypted-only response, and value-free failures.
- `hub/test/security-executor.test.ts`
  - Updates the existing executor fixtures to carry a dynamically signed manifest while preserving the prior replay, envelope, acknowledgement, and boundary contracts.
- `hub/wrangler.executor.jsonc` and `tests/repo_bootstrap/test_executor_config_policy.py`
  - Document and assert that envelope, StateManifest, and response keys are out-of-band and absent from committed vars.

## Focused evidence

- TDD red: the new signed-manifest Vitest file initially failed all 17 cases against the pre-authority executor (valid request returned `400`; missing state-key fail-closed and malformed-authority cases did not have the new contract).
- Green: `pnpm exec vitest run test/security-executor.test.ts test/security-executor-state-manifest.test.ts test/private-executor-handler.test.ts test/executor-envelope-verifier.test.ts test/executor-replay-store.test.ts test/operator-executor-proxy.test.ts --maxWorkers=1` — 91 tests passed (23 state-manifest tests).
- CLI: `go test ./internal/cli -run '^TestSyncStateMigrate_' -count=1` — pass (including exact-case root and nested alias rejection in dry-run, duplicate root/nested keys, unknown root/nested fields, canonical unpadded/url-safe base64 rejection, and remote preflight rejection with raw and hex Ed25519 private signing keys before any request or local mutation).
- Hub typecheck: `pnpm typecheck` — exit 0.
- Config policy: `python -m unittest tests.repo_bootstrap.test_executor_config_policy -v` — 5 tests passed.
- Ordinary Hub dry-run: `pnpm dryrun` — exit 0; the existing `env.EXECUTOR` service binding was read back and Wrangler exited at `--dry-run`.
- Executor dry-run: `pnpm exec wrangler deploy --dry-run --config wrangler.executor.jsonc` — exit 0; only the replay Durable Object and committed non-secret vars were read back, and Wrangler exited at `--dry-run`.
- Additional source check: `git diff --check` — no output.
- No provider, KMS, host, Cloudflare, deployment, public, or production mutation was performed.

## Residuals

- The source executor can independently verify a signed manifest and return encrypted metadata, but it does not perform real host migration or provider/KMS work.
- Deployment, live executor readback, and injection/rotation of `EXECUTOR_STATE_MANIFEST_PUBLIC_KEY` and the other out-of-band keys remain external gated work.
- Hub/executor production wiring and candidate/production/stable promotion are not claimed. The remote CLI contract remains metadata-only and `submitted`, never `committed`.
