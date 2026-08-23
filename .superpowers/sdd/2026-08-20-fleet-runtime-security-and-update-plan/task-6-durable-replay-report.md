# Task 6 bounded Durable Object replay-store report

## Status

PASS for the bounded executor-only Durable Object replay-store source slice. No Hub route, provider, candidate, production, public, release, deploy, or external mutation was performed.

## Commit

- Source, focused tests, and this report are committed together in the local commit reported at delivery.

## Focused verification

- TDD red: `pnpm exec vitest run test/executor-replay-store.test.ts` failed before implementation because `../src/executor-replay-store` did not exist.
- Green: `pnpm exec vitest run test/executor-replay-store.test.ts` — PASS (8 tests).
- Typecheck: `pnpm typecheck` — PASS with no diagnostics.

Only the requested focused Vitest file and Hub typecheck were run. No formatter, linter, project-wide suite, deploy, or external call was run.

## Implemented

- Added `ExecutorReplayScope` with stable `audience`, `role`, and `nonce` fields and generic value-free validation for blank, control-character, overlong, malformed, or whitespace-padded input.
- Added `DurableExecutorReplayStore` around a typed `DurableObjectStorage` transaction surface. `consume` hashes the canonical scope under `private:executor-replay:`, stores only digest/expiry metadata, removes expired rows before replacement, and rejects every unexpired duplicate scope regardless of a later digest.
- Masked storage/transaction failures as the generic `replay store unavailable` error; invalid requests and duplicate scopes use generic errors without scope, digest, or body values.
- Added bounded transactional `sweep(now, limit)` with an explicit list limit and no unbounded list/delete operation.
- Kept the module unreferenced by `hub/src/router.ts` and other ordinary Hub source; it is source-only and makes no claim of deployed durability.

## Test coverage

- First consume and replay rejection.
- Same-scope changed-digest rejection.
- Expired-row replacement and metadata-only persistence.
- Invalid scope, digest, and expiry rejection without value leakage.
- Transaction-error masking.
- Deterministic private key derivation without embedded scope values.
- Bounded expiry sweep.
- Concurrent identical consumes with exactly one winner.

## Residuals

- Wiring this store into a private security executor Durable Object, adding a binding, deploying it, and connecting any provider operation remain separate follow-up work by design.
