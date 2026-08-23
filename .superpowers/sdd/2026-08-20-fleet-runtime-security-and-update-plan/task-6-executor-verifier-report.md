# Task 6 bounded executor envelope verifier report

## Status

PASS for the bounded executor-only Cloudflare envelope verifier source slice. No provider, KMS, Hub route, candidate, production, deployment, public, release, or external mutation was performed.

## Commit

- Source, focused tests, and this report are committed together in the local commit reported at delivery.

## Focused verification

- TDD red: `pnpm exec vitest run test/executor-envelope-verifier.test.ts` failed before implementation because `../src/executor-envelope-verifier` did not exist.
- Green: `pnpm exec vitest run test/executor-envelope-verifier.test.ts` — PASS (20 tests).
- Typecheck: `pnpm typecheck` — PASS with no diagnostics.
- Post-commit whitespace check: `git show --check --oneline HEAD` — PASS.

Only the requested focused Vitest file and Hub typecheck were run; no formatter, linter, project-wide suite, deploy, provider call, or external mutation was run.

## Implemented

- Added a strict parsed `ExecutorEnvelope` boundary with exact Go field set/order, version 1, required authority fields, lowercase `sha256:` digests, RFC3339 expiry parsing, standard base64 canonicality, non-empty body, and fixed-size public key/signature checks.
- Recreated Go-compatible canonical signing bytes in the order `version`, `audience`, `role`, `manifest_digest`, `body_digest`, `nonce`, `expires_at`, `body`, excluding the detached signature and applying Go's HTML-safe JSON escapes.
- Normalized accepted expiry instants to Go's UTC `time.RFC3339Nano` representation for signing (including offset conversion and trailing fractional-zero trimming), while passing conservative millisecond expiry to replay consumption.
- Added WebCrypto Ed25519 raw-key import and signature verification with generic value-free invalid-envelope errors.
- Added `verifyAndConsumeExecutorEnvelope`, which verifies every binding before invoking `DurableExecutorReplayStore.consume({ audience, role, nonce }, bodyDigest, expiresAtMs, now)` and returns a copied body only after successful consume.
- Mapped replay rejection, invalid replay requests, and storage failures to generic verifier errors without exposing scope, digest, body, or underlying exception text.
- Kept the verifier source unreferenced by ordinary Hub source; production executor wiring, replay binding, and authorization remain explicit residuals.

## Test coverage

- Valid canonical verification, replay consume/rejection, exact consume arguments, and returned-body copy.
- Go RFC3339Nano UTC expiry canonicalization (offset and trailing-zero regression) plus HTML-safe JSON escaping.
- Bad/short signatures, changed body, changed body digest, and changed signed field before replay access.
- Expired and overlong TTL envelopes.
- Unknown parsed fields, missing/unsupported fields, malformed expiry/base64, empty body, malformed public key, and value-free errors.
- Replay-store transaction failure and replay rejection mapping without underlying error leakage.

## Residuals

- Wiring this verifier into a private executor request handler, binding the durable replay store in deployment, and adding executor-side authorization remain separate follow-up work by design.
