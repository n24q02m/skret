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
