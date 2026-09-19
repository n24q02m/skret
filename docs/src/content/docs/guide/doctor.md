---
title: Doctor
description: "Read-only health check for your skret setup."
---

Read-only health check for your skret setup.

```bash
skret doctor
```

Each check reports one `PASS`, `WARN`, or `FAIL` line on stderr, and a summary goes to stdout. Exit code `0` means every check passed (warnings do not fail the run); any failing check exits with the failing check's error class, so scripts can react to *why* doctor failed, not just *that* it failed.

## Checks

- **config** — `.skret.yaml` parses and passes schema validation (per environment: unknown providers, missing provider-specific fields).
- **provider[env]** — the configured backend works: for `local`, the secrets file loads (a missing file warns — it is created on first `skret set`); for `aws`, a real `GetCallerIdentity` probe using the same credential resolution as everyday commands.
- **auth[aws]** — stored credential state: missing (warn — the SDK default chain may still work), expired (fail), expiring within 24 hours (warn), or valid.
- **permissions[env]** — local secrets-file mode is owner-only (`0600`); advisory only, and always a pass on Windows, which does not enforce unix modes.
- **encryption[env]** — local at-rest encryption state via the keystore: an encrypted file with the key available passes; an encrypted file with no key material available (set `SKRET_AGE_KEY`/`SKRET_LOCAL_KEY` or run `skret keys init`) is an auth-class failure; plaintext warns (the supported default for development) and surfaces key names holding high-entropy values; `encrypted: true` with a still-plaintext file warns as pre-migration.

## Options

### `--env`

Check only one environment instead of every declared one.

```bash
skret doctor --env prod
```

### `--format`

Output format: `table` (default) or `json`. JSON prints a `{checks: [{name, status, detail, remediation?}]}` report on stdout — `remediation` is present only on checks that carry a fix hint, and failing commands still render the standard JSON error envelope with the same hint.

```bash
skret doctor --format json
```

### `--timeout`

Per-provider reachability probe timeout (default `10s`).

```bash
skret doctor --timeout=3s
```

## Scripting

```bash
skret doctor || echo "unhealthy, exit code $?"
```

| Exit code | Meaning |
|-----------|---------|
| 0 | All checks passed (warnings allowed) |
| 2 | A config check failed |
| 3 | A local provider check failed (e.g. corrupt secrets file) |
| 4 | An auth check failed (expired credentials, or an encrypted file whose key material is unavailable) |
| 7 | A provider was unreachable |

## Scope

`skret doctor` is read-only: it never mutates config, secrets, or credentials. Reachability probes call read-only provider endpoints (`sts:GetCallerIdentity` for AWS) and never print secret values.
