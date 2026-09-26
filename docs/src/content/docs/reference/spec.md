---
title: The skret Spec
description: "The machine-readable contract for skret: exit codes, JSON envelope, stream discipline, byte-exact guarantees, and provider naming rules. Normative, versioned."
sidebar:
  order: 90
---

# The skret Spec

**Version 1.1.0** — normative. The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described in RFC 2119.

This document is the contract every `skret` command and every skret release MUST conform to. It exists so agents, scripts, and wrappers can consume skret blind: parse the exit code, parse the envelope, trust the streams. The human-friendly version of the exit-code table lives in [error codes](/reference/error-codes/); where the two differ, this spec wins.

A conformance test (`pkg/skret/spec_conformance_test.go`) enforces the exit-code table against the code on every CI run.

## 1. Exit codes

skret exits with exactly one code from this table. Codes are a closed set: a release MUST NOT exit with any other value, and new values require a spec minor version.

| Code | Constant (`pkg/skret`) | Meaning |
|------|------------------------|---------|
| 0 | `ExitSuccess` | Operation completed successfully |
| 1 | `ExitGenericError` | Unclassified error |
| 2 | `ExitConfigError` | Configuration problem (missing/invalid `.skret.yaml`, unsupported schema `version`, undeclared env, missing required keys) |
| 3 | `ExitProviderError` | Backend provider failure (SSM/Key Vault/Secret Manager/Vault/local I/O) |
| 4 | `ExitAuthError` | Authentication failed (credentials missing/invalid, no encryption key material) |
| 5 | `ExitNotFoundError` | Secret does not exist |
| 6 | `ExitConflictError` | Resource conflict (e.g. key exists with `--on-conflict=fail`) |
| 7 | `ExitNetworkError` | Network/connectivity failure |
| 8 | `ExitValidationError` | Input validation failed (bad flag value, oversized payload, unresolvable `${KEY}` reference) |
| 9 | `ExitDrift` | Drift detected (`diff --exit-code` only) |
| 10 | `ExitLeakFound` | A managed secret value was found in a scanned file (`scan`, `scan --staged`, `scan --history`) |
| 125 | `ExitExecError` | The child command passed to `run --` could not be executed (matches docker/podman convention) |

Rules:

- There is exactly ONE exit path: `cmd/skret/main.go` resolves `skret.ExitCode(err)` and exits. Command implementations MUST NOT call `os.Exit`.
- `ExitCode` resolves, in order: `*skret.Error.Code`; any error in the chain implementing `interface{ ExitCode() int }` (used by cycle-constrained leaf packages such as `internal/keystore`); otherwise `ExitGenericError`.
- Codes 9 and 10 are successful scans/diffs with findings: the command did its job; the code is the finding.
- A command MAY add flags that change the exit code only when the flag names it (e.g. `--exit-code`).

## 2. JSON error envelope

When a command invoked with `--format json` fails, it MUST print exactly one JSON object to stderr:

```json
{
  "error": "provider[prod]: get DATABASE_URL: <cause>",
  "code": 3,
  "remediation": "fix: check network and region (AWS_REGION, or --region)"
}
```

- `error` (string, required): the human-readable error text, identical to what the table format would print.
- `code` (int, required): the exit code from §1 the process will exit with. A caller can unmarshal the envelope instead of parsing `os.Exit` semantics.
- `remediation` (string, optional): a one-line, copy-pasteable fix hint. Omitted (not empty) when the error carries none.
- Output is `json.MarshalIndent` with two-space indent and a trailing newline.
- In the default `table` format, the same error prints as a single line on stderr (the bare `error` text) — never the JSON shape.
- Errors are status, not data: the envelope goes to stderr even in `--format json` mode.

## 3. Stream discipline

- **stdout carries data only.** Secret values, JSON result payloads, lists, diffs, generated values. Nothing else.
- **stderr carries status.** Warnings, progress, errors, remediation hints.
- `get` prints the value plus one trailing newline; `get --plain` prints the value with NO trailing newline (byte-exact capture into `$(...)` or redirection).
- `--format json` result payloads on stdout are `json.MarshalIndent` with two-space indent and one trailing newline.
- `run` and `watch` pass the child's stdout/stderr through unmodified after skret's own status lines (stderr). skret MUST NOT interleave its own output into the child's stdout.
- Warnings (e.g. recovered shell-mangled keys, skipped sync targets) MUST NOT change the exit code unless a rule in §1 says otherwise.
- Webhook notification delivery failures warn on stderr and never fail the mutation, except under `--strict-notify`.

## 4. Byte-exact guarantees

- A value stored via `set` (file, stdin, or argv) is stored verbatim and returned verbatim. skret MUST NOT trim, re-encode, normalize newlines, or expand anything in stored values.
- `run`/`env` inject secret values byte-exact: `$` is never expanded by skret. bcrypt hashes (`$2a$14$...`), `$`-bearing URLs, and shell-significant bytes survive verbatim. The child process's own shell may expand them; skret does not.
- `${KEY}` reference resolution (§9) applies ONLY at read time in `get`/`env`/`run`/`watch`, and ONLY to tokens that parse as environment-variable names. Values containing no valid reference token are returned byte-exact, always.
- `--no-resolve` on read commands returns the raw stored value, skipping reference resolution entirely.

## 5. Non-interactive guarantees

- skret MUST NOT prompt unless stdin is a terminal. In non-interactive contexts (CI, scripts, agents) any input skret would have prompted for instead fails with a documented exit code and a remediation hint.
- Encryption key material is resolved without prompting when possible (§10 key precedence); a missing key fails with exit 4 and a remediation hint rather than prompting.
- The interactive TUI is explicit opt-in (`skret browse`). No other command launches a UI.
- Every command MUST be safe to run inside a script with no TTY: no pagination, no confirmation dialogs, no "are you sure?".

## 6. Environment variable precedence

Resolution order for one configuration value, first non-empty wins:

| Value | Precedence |
|-------|-----------|
| `default_env`, `provider`, `path` | CLI flag → `SKRET_*` env var → `.skret.yaml` environment field |
| `region`, `profile` | CLI flag → `SKRET_REGION`/`SKRET_PROFILE` → `AWS_REGION`/`AWS_PROFILE` → `.skret.yaml` environment field |
| GCP project | CLI flag → `GOOGLE_CLOUD_PROJECT` → `.skret.yaml` `project` |
| Without a config file (ephemeral mode) | CLI flag → `SKRET_ENV` (default `prod`) → `SKRET_PROVIDER` (default `aws`) |

Other environment variables with defined behavior:

| Variable | Effect |
|----------|--------|
| `SKRET_AGE_KEY` | Primary key material for the local encrypted provider (§10) |
| `SKRET_LOCAL_KEY` | Fallback key material for the local encrypted provider (§10) |
| `SKRET_ACTOR` | Actor recorded in audit log entries and webhook payloads (e.g. `SKRET_ACTOR=ci`) |
| `SKRET_LOG`, `SKRET_LOG_FORMAT` | Log level and format for stderr logging |
| `SKRET_EXPERIMENTAL=1` | Gates experimental commands (`history`, `rollback`) |
| `SKRET_HUB_URL`, `SKRET_HUB_TOKEN` | Vault dashboard endpoint and token |

## 7. Config schema

`.skret.yaml` carries `version: "1"`. This is the only supported schema version; anything else is `ExitConfigError`. Schema changes bump the spec version and ship a migration (`skret migrate`), never a silent reinterpretation.

Required structure:

```yaml
version: "1"                  # required, exactly "1"
default_env: prod             # optional; must name a declared environment
project: my-project           # optional
environments:                 # required, at least one
  prod:
    provider: aws             # aws | azure | gcp | oci | local
    path: /myapp/prod         # aws: required
    region: us-east-1
    profile: production
    file: .secrets.prod.yaml  # local: required
    encrypted: true           # local: write-side encryption intent (§10)
    audit_log: .skret-audit.log  # local: audit trail override
    project: my-gcp-project   # gcp: project id
    vault_url: https://myvault.vault.azure.net/  # azure (or vault_name)
    compartment_id: ocid1...  # oci
    vault_id: ocid1...        # oci
    key_id: ocid1...          # oci: master key for new secrets
    kms_key_id: alias/...     # aws: KMS key for SecureString
required: [DATABASE_URL]      # optional; missing keys fail with exit 2
exclude: [PUBLIC_FLAG]        # optional; never injected by env/run
sync:                         # optional; reusable sync targets + hub
notify:                       # optional; webhook fan-out on mutations
```

Validation is two-phase and MUST stay that way: structural checks (version, at least one environment, `default_env` resolves, sync/notify shape) run for every command; per-environment provider requirements run only for the environment actually selected, so a broken unused environment cannot block a working one.

## 8. Secret-name rules per provider

skret keys are provider-neutral: bare leaf (`DB_PASSWORD`) or slash-delimited (`/myapp/prod/DB_PASSWORD`). The resolved `path` prefixes bare leaves. Per-provider mapping, all deterministic:

| Provider | Name skret stores | Rules |
|----------|-------------------|-------|
| `aws` | SSM parameter name `path/KEY` | Full path-prefixed name; already-qualified keys pass through. Git Bash/MSYS path-mangled arguments are recovered heuristically (with a warning). 4 KB value cap (Standard tier). |
| `local` | YAML mapping key, verbatim | Any YAML string key in the secrets file. |
| `gcp` | Secret ID, verbatim | `^[a-zA-Z0-9_-]{1,255}$`; a single leading `/` is stripped. Environment `path` MUST be empty — isolation is one GCP project per environment. Payload cap 64 KiB. |
| `azure` | Key Vault secret name, sanitized | Only `[A-Za-z0-9-]` survive; every other rune becomes `-`; runs of `-` collapse; leading/trailing `-` trimmed; truncated to 127 chars. Mapping is deterministic but LOSSY: `DB_URL` and `DB-URL` collide. |
| `oci` | Vault secret name, encoded | Path becomes a `-`-joined prefix token; prefix and leaf join with a single `_`; `/` inside the leaf becomes `-`. Result must be 1–255 chars of letters, digits, `.`, `-`, `_`. Paths differing only by `/`-vs-`-` spelling collide within one vault — use distinct vaults. |

## 9. `${KEY}` reference semantics

Secret values MAY reference other secrets in the same environment scope:

```yaml
secrets:
  DB_USER: app_rw
  DB_PASS: hunter2
  DB_URL: postgres://${DB_USER}:${DB_PASS}@db.internal/app
```

- Resolution happens at READ time (`get`, `env`, `run`, `watch`), never at write time. The stored value always keeps the reference text.
- Resolution is transitive (A → B → C) up to a maximum depth of 10 (`ref.MaxDepth`).
- A token is a reference only if its payload is a valid environment-variable name: ASCII letters, digits, underscores, not starting with a digit. `${VAR:-default}`, `${a.b}`, `${}` pass through byte-exact.
- Escapes: a `\` or `$` byte immediately before `${` suppresses resolution for that token — `\${NAME}` and `$${NAME}` stay byte-exact and their payload is never resolved.
- Failures are exit 8 (`ExitValidationError`) with a remediation hint:
  - missing name: `reference ${NAME} not found in the environment scope`;
  - cycle: the full chain is printed, outermost first;
  - depth: chain deeper than 10 hops.
- `template` files use single-pass substitution (not transitive) and collapse `$$` to `$` — deliberately different from secret references; do not conflate the two.

## 10. Local encryption envelope format

When an environment sets `encrypted: true`, the local provider stores the secrets file as a standard **age** file (format `age-encryption.org/v1`). Readers auto-detect an encrypted file on disk regardless of the flag, so plaintext keeps working until `skret keys init --encrypt-existing` migrates it.

An encrypted file is a complete age file: the ASCII header `age-encryption.org/v1` followed by recipient stanzas and the encrypted payload. The payload is the plaintext local-file shape — `version`, `secrets`, and `meta` (per-key expiry, RFC3339) — encrypted as one blob, so external decryption yields a normal skret secrets file:

```
$ age -d -i key.txt .secrets.dev.yaml
version: "1"
secrets:
  DATABASE_URL: postgres://dev:dev@localhost/db
meta:
  DATABASE_URL: "2026-10-01T00:00:00Z"
```

- Recipient: an age X25519 keypair when the key material is an age private key (`AGE-SECRET-KEY-1...`, bech32 — as generated by `age-keygen` or `skret keys init`); an age **scrypt** recipient derived from the material as a passphrase otherwise. Interop is normative: files skret encrypts MUST decrypt with the standalone `age`/`rage` CLIs, and files those CLIs encrypt to a skret-managed key MUST decrypt with skret.
- Writes are atomic (temp file + rename) with `0600` permissions.
- Wrong key material or tampered bytes fail with exit 4 (`ExitAuthError`) and a remediation hint; it is never a silent empty read.

Key-material precedence (first wins; the first value present is used — its shape selects the arm):

1. `SKRET_AGE_KEY` — an age private key (X25519 arm) or any other value (passphrase arm)
2. `SKRET_LOCAL_KEY` — same semantics (legacy alias)
3. OS keyring entry (service `skret`, user `local-enc-key`) — where `skret keys init` stores the generated age identity
4. Interactive passphrase prompt (confirm twice) — ONLY when stdin is a terminal; otherwise exit 4

### Legacy `skret-encrypted-v1` envelopes

Files written by skret ≤ 1.34 use the retired per-value envelope (`format: skret-encrypted-v1`, argon2id 64 MiB/t=3/p=4 + XChaCha20-Poly1305, key name bound as AEAD additional data, `meta` plaintext in the header). skret still reads them transparently and keeps their format on write; `skret keys init --encrypt-existing` migrates them to the age format in one command, preserving every value and per-key metadata. `skret keys show` / `skret doctor` report the legacy format and the migration command.

### Migration note (passphrase arm)

A legacy envelope encrypted under a passphrase now migrates to an age **scrypt** recipient — the same passphrase decrypts it, but the KDF changes from argon2id to scrypt (age spec §5.3.4). Migration with an age private key (recommended) moves custody to the X25519 keypair instead.

## 11. Audit log

Local-provider mutations (`set`, `rotate`, `delete`) append one JSONL line per change to the audit log (default `.skret-audit.log` next to the secrets file). Entries record key NAMES, operation, environment, actor (`SKRET_ACTOR` when set), and RFC3339 timestamp. Values MUST NEVER be written to the audit log. `skret audit` reads this log; for AWS it can export CloudTrail events for the SSM path.

## 12. Changelog

All notable changes to this spec (not to the tool) are listed here. Adding an exit code, changing the envelope, or altering a byte-exact guarantee requires a version bump.

### 1.1.0 — 2026-09-26

- Local encryption switched to the standard age format (`age-encryption.org/v1`): X25519 recipients for age keypairs, scrypt recipients for the passphrase arm; interop with the standalone `age`/`rage` CLIs is normative. `skret keys init` generates a bech32 age X25519 keypair (`AGE-SECRET-KEY-1...`).
- Legacy `skret-encrypted-v1` envelopes: read support and format-preserving writes remain; `skret keys init --encrypt-existing` is the one-command migration (values and per-key metadata preserved).

### 1.0.0 — 2026-09-19

- Initial publication: exit-code table, JSON error envelope, stream discipline, byte-exact guarantees, non-interactive guarantees, env-var precedence, config schema v1, per-provider secret-name rules, `${KEY}` reference semantics, local encryption envelope format, audit-log contract.
