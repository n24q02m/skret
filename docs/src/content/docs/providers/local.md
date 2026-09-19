---
title: Local YAML Provider
description: "The local provider stores secrets in a YAML file — plaintext by default for dev, optional at-rest encryption for sensitive setups."
---

The local provider stores secrets in a YAML file. Plaintext is the default for development; optional at-rest encryption is available via `skret keys`.

## Configuration

```yaml
environments:
  dev:
    provider: local
    file: ./.secrets.dev.yaml
```

## File Format

```yaml
version: "1"
secrets:
  DATABASE_URL: "postgres://dev:dev@localhost/mydb"
  API_KEY: "dev-key-123"
  REDIS_URL: "redis://localhost:6379"
```

## Encryption (optional)

With `encrypted: true` on the environment, the file is stored as a
`skret-encrypted-v1` envelope: every value is XChaCha20-Poly1305 encrypted
(bound to its key name as AEAD additional data) with a key derived from the
key material via argon2id (64 MiB, t=3, p=4). Reads auto-detect an envelope
on disk even when the flag is off, and encryption is sticky — once a file is
an envelope, saves keep it one.

```bash
# One command: create key material, migrate the file, record the flag.
skret keys init --encrypt-existing
```

Key material resolution order: `SKRET_AGE_KEY` → `SKRET_LOCAL_KEY` → OS
keyring (seeded by `skret keys init`) → interactive passphrase prompt
(terminals only; non-interactive contexts fail with exit 4 and a remediation
hint). See [`skret keys`](/reference/commands/#skret-keys-init).

## Audit trail

Every mutation on the local provider (`skret set`, `skret rotate`, `skret delete`, and the mutations sync/import issue) appends one JSONL line to an append-only audit log: `.skret-audit.log` next to the secrets file, or the `audit_log` path configured for the environment.

```json
{"timestamp":"2026-09-19T09:00:00.123Z","op":"set","key_names":["API_KEY"],"env":"prod","actor":"deploy-bot"}
```

- Names only: the trail records key names, operation, environment, and actor (`SKRET_ACTOR` when set, else the OS user). Values are structurally excluded.
- Created `0600`; at 1 MiB it rotates to `.skret-audit.log.1` (single backup).
- `skret audit` renders and filters the trail (`--since`, `--key`, `--limit`, `--format json`) without decrypting the secrets file.

## Security

> **WARNING (plaintext mode):** By default local secrets files are NOT encrypted. Never use the plaintext local provider for production secrets.

- Always add `.secrets.*.yaml` to `.gitignore`
- The `skret init` command does this automatically
- File permissions are set to `0600` (owner read/write only), encrypted and plaintext alike
- With `encrypted: true`, values are never at rest in plaintext; `skret keys show` warns when a plaintext file holds high-entropy values

## Capabilities

| Capability | Supported |
|-----------|-----------|
| Read | ✅ |
| Write | ✅ |
| Versioning | ❌ |
| Tagging | ❌ |
| Encryption | ✅ (optional, `encrypted: true` + `skret keys init`) |
| Max value size | 1 MB |
