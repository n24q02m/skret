---
title: Sync
description: "Push secrets from a skret environment to GitHub Actions, GitLab, Cloudflare, a dotenv file, Terraform tfvars, or a Kubernetes Secret manifest."
---

Push secrets from a skret environment to GitHub Actions, GitLab, Cloudflare, a dotenv file, Terraform tfvars, or a Kubernetes Secret manifest.

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

`--to` selects which target types run, as a comma-separated list (`--target` is an accepted alias):

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

### `gitlab`

Pushes secrets as [GitLab project CI/CD variables](https://docs.gitlab.com/ee/ci/variables/#add-a-cicd-variable-to-a-project) via the project variables API. Requires `project` (numeric project ID or `group/project` path) and `GITLAB_TOKEN` in the environment (a project or group access token with the `api` scope works). Only declarable through `.skret.yaml` — there is no flags-only path for `gitlab`.

```yaml
sync:
  targets:
    - type: gitlab
      project: mygroup/myapp
      masked: true       # optional; the value must satisfy GitLab masking requirements
      protected: true    # optional; variable is exposed only to protected branches/tags
```

```bash
export GITLAB_TOKEN=glpat-xxx
skret sync --to=gitlab
```

Each secret is stored under its target-side name (the last path segment of the provider key, e.g. `/app/prod/db/PASSWORD` → `PASSWORD`). skret updates existing variables in place and creates missing ones. Because GitLab only allows `A-Z`, `a-z`, `0-9` and `_` in variable keys, a provider key whose last segment contains anything else (a dash, for example) is rejected before any request with a rename hint. `masked: true` makes GitLab reject values that don't meet its masking rules (single line, at least 8 characters, limited charset) — the error includes that remediation.

### `terraform`

Writes secrets as a [tfvars file](https://developer.hashicorp.com/terraform/language/values/variables#variable-definitions-tfvars-files) — one `name = "value"` assignment per secret, sorted by name, HCL-escaped so values survive byte-exact. The file is managed wholesale: every sync rewrites it atomically with exactly the synced keys, so point `file` at a dedicated `.auto.tfvars` (for example `skret.auto.tfvars`) instead of mixing hand-written variables into it.

```bash
skret sync --to=terraform --file=skret.auto.tfvars
```

Without `--file` (or a `file:` on the target entry) the output defaults to `terraform.tfvars`. Variable names must be valid HCL identifiers (start with a letter or underscore, then letters, digits, underscores or dashes); anything else fails with a rename hint before any file is written.

### `k8s` (alias `k8s-manifest`)

Renders secrets as a Kubernetes `Secret` manifest (`type: Opaque`, values under `stringData` so the cluster base64-encodes them on apply). This is YAML generation only — skret never talks to a cluster; applying the file stays the operator's job (`kubectl apply`, Flux, Argo, ...).

```bash
skret sync --to=k8s --file=secret.yaml
```

- With no `file` (or `file: -`), the manifest is printed to **stdout** — pipe it wherever you need it. Don't combine stdout output with `--format json`: both write to stdout.
- `name` sets `metadata.name` (default `skret-secrets`); `namespace` adds `metadata.namespace`.

```yaml
sync:
  targets:
    - type: k8s
      file: deploy/secret.yaml
      name: myapp-secrets
      namespace: prod
```

Secret keys must satisfy the Kubernetes Secret data-key charset (alphanumerics, `-`, `_`, `.`); other names fail with a rename hint before anything is written. `k8s-manifest` is accepted as an exact synonym of `k8s`.

## Drift-aware sync: `--skip-unchanged`

```bash
skret sync --to=github --github-repo=myorg/myapp --skip-unchanged
```

`--skip-unchanged` compares each secret's SHA256 hash against a local cache (`~/.skret/sync-state/`, one file per target) from the last successful sync and only pushes values that changed. This avoids unnecessary API calls on scheduled sync jobs where most secrets are unchanged run to run. The cache updates only after a fully successful sync to that target.

## Explicit rotation: `--rotate`

```bash
skret sync --to=github --github-repo=myorg/myapp --rotate
```

`--rotate` is an explicit controlled overwrite intent: it sends every selected source key, bypasses `--skip-unchanged`, and overrides a target's `no_overwrite: true` setting. Rotation loads and saves the per-target sync-state journal so its operation ID, per-key outcomes, intent, and last-success state remain durable. It cannot be combined with `--no-overwrite`; that conflict is rejected before provider or target calls. Rotation does not claim canary, rollback, or production approval.

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

Rotation under no-overwrite is deliberate only on the ordinary sync path:
delete the key at the target (`gh secret delete <KEY> -R owner/repo`), and the
next sync repopulates it from the provider. `--rotate` is the separate
explicit overwrite intent for replacing an existing target value. Deleting is
recoverable (the provider still holds the value); overwriting is not (GitHub
and Cloudflare secrets are write-only).

`--skip-unchanged` is ignored for a no-overwrite target: the target listing
already determines the write set, and a warm value cache could otherwise
mask a deletion you made at the target on purpose.

Supported targets: `github` (repository Actions secrets), `cloudflare`
worker scripts, and `gitlab` (project CI/CD variables — the write is a
per-key API upsert, so names can be enumerated and skipped). `dotenv`,
`terraform`, and `k8s` targets reject no-overwrite: they rewrite the whole
output atomically, so "only new keys" would drop every existing entry. A
`cloudflare` pages target rejects it too.

## `--format json`

```bash
skret sync --to=dotenv --format json
```

```json
[
  {
    "source": "/myapp/prod",
    "target": "dotenv",
    "synced": 4
  }
]
```

With `--rotate`, the object also includes `"intent": "rotate"`; this records
intent only and never includes secret values:

```json
[
  {
    "source": "/myapp/prod",
    "target": "dotenv",
    "synced": 4,
    "intent": "rotate"
  }
]
```

One object per target actually synced, in the order they ran; a multi-target
run (`--to=github,dotenv`, or several `sync.targets` entries) produces one
array entry per target. `synced` is the same count the default table's
`Synced N secrets to TARGET` stderr line already reports — no target
implements a per-key added/updated/deleted breakdown (`dotenv` rewrites its
file wholesale and has no such concept), so `--format json` doesn't invent
one either. `--dry-run` is unaffected: it still only prints its preview to
stderr, since nothing is written for `--format json` to report. See [Using
skret from a script or agent](/guide/agents/#json-output-on-the-write-path)
for the equivalent shapes on `set`/`delete`.

## Security

- Secret **values** are sent only to the target's own API — never printed to stdout/stderr.
- Tokens (`GITHUB_TOKEN`, `CLOUDFLARE_API_TOKEN`) are read from the environment at sync time and are never written to `.skret.yaml`.
- `sync-state` cache files store SHA256 hashes, not secret values, and are written with `0600` permissions.

## Publishing an inventory instead of values

If you want a dashboard to see which secrets exist and whether each sync target is up to date — without ever transmitting a value — use [`skret hub push`](/guide/hub/) instead.
