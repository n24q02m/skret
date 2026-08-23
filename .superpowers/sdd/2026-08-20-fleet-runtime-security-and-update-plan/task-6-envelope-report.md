# Task 6 envelope client report

## Status

PASS for the bounded signed-envelope client slice. No Hub route, executor, provider, candidate, production, public, or release mutation was performed; tests use Ed25519 keys and synthetic local `httptest` servers only.

## Commit

- `820dcc3` — `feat: add signed executor envelope client`

## Focused test output

- `go test ./internal/syncer -run 'Envelope' -count=1` — PASS (`ok github.com/n24q02m/skret/internal/syncer`, 4.111s).
- TDD red proof: the same focused envelope tests failed before implementation with undefined `BuildSignedEnvelope`, `VerifySignedEnvelope`, `EnvelopeVersion`, and response/TTL constants.

## Implemented

- Added a versioned Ed25519 envelope with deterministic canonical JSON over all authority fields and body content binding, excluding the detached signature.
- Added value-free field, SHA-256 digest, body, signer-length, expiry, maximum-TTL, schema, body-digest, public-key, and signature validation.
- Added explicit nonce preservation and documentation that replay acceptance/tracking remains executor/Hub-owned.
- Added a fixed-origin Hub client that posts only `/operator/executor-envelope`, rejects path/query/fragment/userinfo base URLs, does not follow redirects, bounds successful response reads to 1 MiB, and exposes status only for non-2xx responses.

## Concerns / residuals

- The Hub route and executor are intentionally not implemented or exercised; nonce replay, executor authorization, provider acknowledgements, retries, rollback, candidate, production, and public proof remain outside this slice.

## Follow-up: operator-session auth binding

### Commit

- `13f2554` — `fix(syncer): bind envelope client to operator session`

### Implemented

- Added the compatibility-preserving `EnvelopeClient.OperatorSessionCookie` field without changing `NewEnvelopeClient(baseURL, signer)`.
- `Submit` validates the supplied cookie with `strings.TrimSpace` before building the request or resolving the endpoint. Missing and whitespace-only values return the value-free error `envelope: operator session cookie is required`, with no transport call.
- The caller-supplied cookie value is forwarded unchanged in the exact `Cookie` request header. No `Authorization`/bearer header is added, and the cookie is not copied into the signed envelope body.
- Updated all existing focused `EnvelopeClient` fixtures with synthetic `session=...` cookies and added exact-header forwarding plus absent/blank no-request regression coverage.

### Focused verification

- TDD red: `go test ./internal/syncer -run TestEnvelopeClientSubmit_RejectsMissingOperatorSessionCookieBeforeNetwork -count=1` failed before implementation because `OperatorSessionCookie` was undefined.
- Green: the same focused no-network test passed after implementation.
- Green: `go test ./internal/syncer -run 'Test(Envelope|Submit)' -count=1`.
