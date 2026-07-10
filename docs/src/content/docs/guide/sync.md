---
title: Sync
description: "Push secrets from a skret environment to GitHub Actions, Cloudflare, or a dotenv file."
---

Push secrets from a skret environment to GitHub Actions, Cloudflare, or a dotenv file.

```bash
skret sync --to=github --github-repo=myorg/myapp
```

`skret sync` lists every secret in the resolved environment and pushes them to one or more external targets. Targets can be passed as one-off flags or declared once in `.skret.yaml` and reused across machines and CI.

## Declaring targets in `.skret.yaml`

Add a `sync.targets` block so `skret sync` (no flags) pushes to every declared target:

```yaml
sync:
  targets:
    - type: github
      repo: myorg/myapp
    - type: cloudflare
      worker: my-worker
      account: ${CLOUDFLARE_ACCOUNT_ID}
    - type: cloudflare
      pages: my-pages-project
      account: ${CLOUDFLARE_ACCOUNT_ID}
    - type: dotenv
      file: .env.sync
```

```bash
skret sync
```

`account` supports `${VAR}` expansion from the environment, so the Cloudflare account ID never has to be committed to `.skret.yaml`. See the [config schema reference](/reference/config-schema/) for the full field list.

## `--to`: comma-separated target filter

`--to` selects which target types run, as a comma-separated list:

```bash
skret sync --to=github,dotenv
```

- Each type named in `--to` is resolved **independently**: if `sync.targets` declares one or more entries of that type, those run; otherwise that type is built from flags instead, preserving the pre-sync-fabric behavior (`skret sync --to=github --github-repo=owner/repo` and `skret sync --to=dotenv --file=.env` both still work with no `.skret.yaml` sync block at all). So with a `sync.targets` block that declares only `github`, `skret sync --to=github,dotenv --file=.env` uses the declared `github` target **and** writes `.env` from the flag — a type named in `--to` is never silently dropped just because a different type happened to match `sync.targets`.
- With no `--to` and no declared targets, `skret sync` defaults to writing `.env` (or `--file`).

## Target types

### `dotenv`

Writes secrets to a local dotenv file (default `.env`).

```bash
skret sync --to=dotenv --file=.env.local
```

### `github`

Pushes to GitHub Actions repository secrets (sealed-box encrypted via the repo's public key). Requires `GITHUB_TOKEN` in the environment.

```bash
export GITHUB_TOKEN=ghp_xxx
skret sync --to=github --github-repo=myorg/myapp
```

`--github-repo` accepts a comma-separated list to push the same secrets to multiple repositories in one run. In `.skret.yaml`, add one `type: github` entry per repository instead.

### `cloudflare` (Worker)

Pushes secrets as [Cloudflare Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/) via the Workers API. Requires `worker` + `account` and `CLOUDFLARE_API_TOKEN` in the environment. Only declarable through `.skret.yaml` — there is no flags-only path for `cloudflare`.

```yaml
sync:
  targets:
    - type: cloudflare
      worker: my-worker
      account: ${CLOUDFLARE_ACCOUNT_ID}
```

### `cloudflare` (Pages)

Pushes secrets as Cloudflare Pages **production** environment variables. Requires `pages` + `account` and `CLOUDFLARE_API_TOKEN`.

```yaml
sync:
  targets:
    - type: cloudflare
      pages: my-pages-project
      account: ${CLOUDFLARE_ACCOUNT_ID}
```

Pages sync is a **partial merge**: only the keys being synced are sent in the PATCH request body. Every other environment variable already configured on the Pages project — set through the dashboard, another tool, or a prior sync with a different key set — is left untouched. skret never reads the existing variables back first, because Cloudflare masks `secret_text` values on GET; a get-then-merge-then-patch would blank every pre-existing secret. Set exactly one of `worker` or `pages` per cloudflare target, never both.

## Drift-aware sync: `--skip-unchanged`

```bash
skret sync --to=github --github-repo=myorg/myapp --skip-unchanged
```

`--skip-unchanged` compares each secret's SHA256 hash against a local cache (`~/.skret/sync-state/`, one file per target) from the last successful sync and only pushes values that changed. This avoids unnecessary API calls on scheduled sync jobs where most secrets are unchanged run to run. The cache updates only after a fully successful sync to that target.

## Safety flags

### `--dry-run`

Prints, per target, the exact secret names a sync would write, then exits
without writing anything: no write request is issued, no sync state is saved,
no dotenv file is touched. Combined with no-overwrite it first performs the
read-only listing of the target so the printed set is accurate.

### no-overwrite

Two layers, same semantics -- only keys absent at the target are written,
existing values are never overwritten:

- Per target in `.skret.yaml`: `no_overwrite: true` on a `sync.targets`
  entry. Use this for targets that must behave as a cache of the provider.
- For a whole run: `skret sync --no-overwrite` forces it on every target.

Rotation under no-overwrite is deliberate: delete the key at the target
(`gh secret delete <KEY> -R owner/repo`), and the next sync repopulates it
from the provider. Deleting is recoverable (the provider still holds the
value); overwriting is not (GitHub and Cloudflare secrets are write-only).

Supported targets: `github` (repository Actions secrets) and `cloudflare`
worker scripts. A `dotenv` target rejects no-overwrite: it rewrites the whole
file atomically, so "only new keys" would drop every existing line. A
`cloudflare` pages target rejects it too.

## Security

- Secret **values** are sent only to the target's own API — never printed to stdout/stderr.
- Tokens (`GITHUB_TOKEN`, `CLOUDFLARE_API_TOKEN`) are read from the environment at sync time and are never written to `.skret.yaml`.
- `sync-state` cache files store SHA256 hashes, not secret values, and are written with `0600` permissions.

## Publishing an inventory instead of values

If you want a dashboard to see which secrets exist and whether each sync target is up to date — without ever transmitting a value — use [`skret hub push`](/guide/hub/) instead.
