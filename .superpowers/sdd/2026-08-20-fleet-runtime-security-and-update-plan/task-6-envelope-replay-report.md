# Task 6 bounded envelope replay report

## Status

PASS for the bounded executor-side replay-verifier source slice. No Hub route, executor Durable Object, provider, candidate, production, public, release, or external mutation was performed.

## Commit

- Source, focused tests, and this report are committed together in the local commit reported at delivery.

## Focused verification

- TDD red: `go test ./internal/syncer -run 'Test(EnvelopeReplay|VerifyAndConsume)' -count=1` failed before implementation with undefined replay store/verifier symbols.
- Green: `go test ./internal/syncer -run 'Test(EnvelopeReplay|VerifyAndConsume)' -count=1` — PASS.
- Concurrency proof: `go test -race ./internal/syncer -run 'Test(EnvelopeReplay|VerifyAndConsume)' -count=1` — PASS.
- Existing envelope regression proof: `go test ./internal/syncer -run 'Test(Envelope|Submit)' -count=1` — PASS.

## Implemented

- Added `EnvelopeReplayStore` and stable `EnvelopeReplayScope` (`audience`, `role`, `nonce`) with an atomic consume operation carrying the SHA-256 digest of canonical signing bytes.
- Added a mutex-protected, bounded in-memory replay store with expiry cleanup before admission, duplicate-scope rejection regardless of later digest, zero-value initialization, and deterministic capacity errors. The store is explicitly source/test-only and non-durable.
- Added `VerifyAndConsumeSignedEnvelope`, which calls existing signature/schema/body/expiry verification before canonical digest derivation and atomic scoped nonce consumption.
- Added focused coverage for first consume and exact replay, same-scope body/signature/expiry changes, scope/nonce separation, invalid signature/expiry non-consumption, concurrent single-winner behavior, expiry cleanup and bounded capacity, canonical digest/scope forwarding, and value-free errors.

## Concerns / residuals

- Durable replay authority in the production executor Durable Object/store remains a follow-up residual by design. The Hub proxy and public envelope client do not call or own replay state.
