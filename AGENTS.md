# Agent Collaboration

## Quick Reference

- Language: Go 1.26
- Test: `go test -race -cover ./...`
- Lint: `golangci-lint run ./...`
- Build: `go build -o skret ./cmd/skret`

## Key Interfaces

- `internal/provider.SecretProvider` — all providers implement this
- `internal/importer.Importer` — all import sources implement this
- `internal/syncer.Syncer` — all sync targets implement this

## Adding a New Provider

1. Create `internal/provider/<name>/<name>.go`
2. Implement `SecretProvider` interface
3. Register in `internal/provider/registry.go`
4. Add tests in `internal/provider/<name>/<name>_test.go`
5. Add docs in `docs/providers/<name>.md`

## Provider credential boundary

- The ordinary Hub, public routes, CI, sync planner, and Container are credential-free and value-free. They may create or forward bounded signed planning metadata only.
- Provider reads/writes and KMS access belong exclusively to the separate security executor after it verifies the signed operation, source, target, generation, capability, deadline, and replay state.
- Never add AWS, GitHub, Cloudflare, provider, trust, or deployment credentials to ordinary Hub/Container config to make a scheduled operation work. Manual local CLI use may read the documented target credential from the operator environment.
- Persist an immutable invocation outcome before interpreting a provider response. Native-CAS operations reconcile exact state; enforced-exclusive operations may replay only the same verified operation; an opaque or dropped response otherwise requires a fresh signed owner-risk decision. Never silently retry a write-only provider call.

## Security-sensitive code

- Never log, return, persist, or test with secret values, plaintext hashes, credentials, private keys, session cookies, or decrypted provider responses. Redact embedded values globally and redact fields whose key denotes sensitive data.
- Construct URLs with `net/url`; validate the allowed scheme and origin. Do not interpolate path/query input into URL strings.
- Pass external commands an argument vector, use the platform's end-of-options separator where supported, and never route untrusted input through a shell.
- Every network client and local callback server needs explicit timeouts. OAuth/browser callbacks require an unpredictable `state` value verified byte-for-byte before code exchange.
- State-file paths require final base-directory containment checks in addition to sanitized identifiers. Reject symlink/reparse traversal and ambiguous replacement.
- For variable-length secret comparisons, hash both inputs to fixed length before constant-time comparison.

## CLI output contracts

- Machine-readable data belongs on stdout. Progress, confirmations, warnings, and actionable human guidance belong on stderr.
- JSON mode must preserve its declared type; an empty list is `[]`, not prose, `null`, or omitted output.
- Human-mode empty states should explain the next valid command, but an empty-input fast path must never bypass a provider capability, safety, authorization, or validation guard.

## Performance changes

- Optimize only a measured hot path. A fast path or allocation rewrite requires a representative `Benchmark*` (or a focused Vitest benchmark for Hub code) and must name the per-request, per-byte, or unbounded-loop call path.
- Hoist invariant parsing/decoding out of provider loops and avoid avoidable allocations, copies, and repeated initialization in compiled code.
- Do not add speculative empty-input guards or style-only string rewrites. In particular, `KeyToEnvName`, Hub base64url helpers, and existing sync-state empty-input behavior are settled unless a benchmark and a preserved-contract test prove a material win.
- Validation, capability checks, and fail-closed assertions run before any optimization shortcut.

## Agent policy lifecycle

Durable policy lives in this file and executable tests. Per-bot `.jules/` learning ledgers are historical traces, not current instructions; they are intentionally ignored and must not be recommitted.
