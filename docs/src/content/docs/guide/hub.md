---
title: Hub
description: "Publish a names-only secret inventory to the vault dashboard — values never leave your machine."
---

Publish a names-only secret inventory to the vault dashboard — values never leave your machine.

```bash
skret hub push
```

`skret hub push` sends a **manifest**: key names, a salted fingerprint per key, and a drift status per sync target. It never sends a secret value.

## Setting the hub URL

```bash
skret hub push --hub-url https://vault.example.com
```

Or declare it once in `.skret.yaml` so a bare `skret hub push` picks it up:

```yaml
sync:
  hub:
    url: https://vault.example.com
```

`--hub-url` overrides `sync.hub.url` when both are set. If neither is set, `skret hub push` fails fast with a config error instead of guessing an endpoint.

## Authentication

Set `SKRET_HUB_TOKEN` to have `skret hub push` send it as a bearer token:

```bash
export SKRET_HUB_TOKEN=hub_xxx
skret hub push
```

Without `SKRET_HUB_TOKEN`, the request is sent with no `Authorization` header.

## What's in the manifest

For each secret in the resolved environment, the manifest carries:

- **`name`** — the secret's key name (the final path segment, e.g. `DATABASE_URL` from SSM path `/myapp/prod/DATABASE_URL`).
- **`fingerprint`** — an eight-character `sha256[:8]` of the value, salted with a 16-byte deployment salt kept at `~/.skret/hub-salt` (created on first use, `0600`, never transmitted). The salt keeps fingerprints opaque to cross-deployment rainbow tables while staying stable across pushes from the same machine.
- **`updated_at`** — the value's last-modified timestamp from the provider.
- **`targets`** — a map of `"<type>:<id>"` (e.g. `"github:myorg/myapp"`, `"cloudflare:worker/my-worker"`) to a drift status, one per target declared in `sync.targets`.

No secret value is ever included, at any point in the request.

## Drift status per target

Each declared `sync.targets` entry is compared against its local sync-state cache (the same cache `skret sync --skip-unchanged` writes) to classify every key as:

| Status | Meaning |
|--------|---------|
| `in-sync` | The key was synced to this target and the value has not changed since. |
| `drift` | The key was synced to this target, but the current value differs from what was last pushed. |
| `missing` | The key has never been synced to this target (no prior sync-state entry), or the target has no sync-state cache at all yet. |

Drift is computed entirely from local state — `skret hub push` does not call out to GitHub or Cloudflare to check what is actually stored there.

## Options

### `--hub-url`

Hub base URL, overriding `sync.hub.url` from `.skret.yaml`.

```bash
skret hub push --hub-url https://vault.example.com
```

## Security

- Secret **values never leave your machine** — the manifest carries only names, salted fingerprints, and drift status.
- `SKRET_HUB_TOKEN` is read from the environment and sent as `Authorization: Bearer <token>`; it is never written to `.skret.yaml` or logged.
- The deployment salt at `~/.skret/hub-salt` is generated once per machine and stored at `0600`. Two machines pushing the same secret produce different fingerprints unless they share a salt.
