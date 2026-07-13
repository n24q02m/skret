---
title: Hub
description: "Publish a names-only secret inventory to the vault dashboard — values never leave your machine."
---

Publish a names-only secret inventory to the vault dashboard — values never leave your machine.

```bash
skret hub push
```

`skret hub push` sends a **manifest**: key names, a salted fingerprint per key, and a presence status per sync target. It never sends a secret value.

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
- **`targets`** — a map of `"<type>:<id>"` (e.g. `"github:myorg/myapp"`, `"cloudflare:worker/my-worker"`) to a presence status (`present`/`absent`/`unknown`), one per target declared in `sync.targets`.

No secret value is ever included, at any point in the request.

## Presence status per target

`skret hub push` looks up presence **live**, by calling each declared `sync.targets` entry's own "list existing secret names" API once per push — the same mechanism `skret sync --no-overwrite` uses. It does not read the local sync-state cache (`~/.skret/sync-state/`) at all, so the manifest reflects what is actually at the target right now, not what the last successful `skret sync` on this machine happened to write.

Each key gets one status per declared target:

| Status | Meaning |
|--------|---------|
| `present` | The target was asked "what secret names do you have?" and this key's name was in the answer. |
| `absent` | The target answered, and this key's name was **not** in the answer. |
| `unknown` | Presence could not be determined for this target: either its type cannot enumerate existing names at all (a `dotenv` target, or a Cloudflare **Pages** target), or the lookup call itself failed (network/API error, or a required credential like `GITHUB_TOKEN` was not set). A failed lookup never fails the whole push — it prints a `warning:` line to stderr and marks every key `unknown` for that one target only. |

A `github` target and a Cloudflare **Worker** target (`sync.targets: - type: cloudflare, worker: ...`) can both enumerate, so they get real `present`/`absent` status; `dotenv` and Cloudflare **Pages** targets always show `unknown` — there is no API to list what a dotenv file or a Pages project's env vars currently hold, in the way `hub push` needs.

### Credentials for a live presence check

Because presence is looked up live, `skret hub push` needs the **same credentials `skret sync` needs** for any target it should check: `GITHUB_TOKEN` for a `github` target, `CLOUDFLARE_API_TOKEN` (plus an account id) for a `cloudflare` target.

- The cron sync container already forwards these from the Worker's own secrets — no extra setup for the scheduled push.
- Running `skret hub push` **by hand** (a laptop, CI, anywhere outside the cron container) needs you to export the same variables yourself, exactly as for `skret sync`:

```bash
export GITHUB_TOKEN=ghp_xxx
export CLOUDFLARE_API_TOKEN=xxx
skret hub push
```

Without them, those targets simply show `unknown` for every key — the push still succeeds, it just can't tell you more than that.

## Options

### `--hub-url`

Hub base URL, overriding `sync.hub.url` from `.skret.yaml`.

```bash
skret hub push --hub-url https://vault.example.com
```

## Security

- Secret **values never leave your machine** — the manifest carries only names, salted fingerprints, and presence status.
- `SKRET_HUB_TOKEN` is read from the environment and sent as `Authorization: Bearer <token>`; it is never written to `.skret.yaml` or logged.
- The deployment salt at `~/.skret/hub-salt` is generated once per machine and stored at `0600`. Two machines pushing the same secret produce different fingerprints unless they share a salt.
