# skret vault hub (Cloudflare serverless mode)

Read-only vault dashboard for skret. Ingests the names-only manifest that
`skret hub push` sends (no secret values, ever) and renders a password-gated
map of every namespace's keys + per-target drift status.

## What it is / is NOT

- **Is:** a CF Worker + KV. Holds key **names**, salted `sha256[:8]`
  fingerprints, and drift status only.
- **Is NOT:** a secret store. It has **0 AWS credentials** and never sees or
  stores a secret value. Ingest rejects any value-like field.

## Routes

| Route | Auth | Purpose |
|---|---|---|
| `POST /api/manifest` | `Authorization: Bearer $SKRET_HUB_TOKEN` | ingest a manifest |
| `POST /login` | form `password` = `$RELAY_PASSWORD` | mint a signed session cookie |
| `GET /` | session cookie | the dashboard map |
| `GET /healthz` | none | uptime check |

## BYO deploy (bring your own infra)

Committed `wrangler.jsonc` and `wrangler.deploy.template.jsonc` carry only
placeholders. Fill real IDs into the gitignored `wrangler.deploy.jsonc`.

One-time owner setup:

```bash
# 1. Create the KV namespace (note the returned id -> GH secret VAULT_KV_ID)
cd hub && wrangler kv namespace create VAULT_KV

# 2. Set the two Worker secrets (never committed, never GH secrets)
wrangler secret put SKRET_HUB_TOKEN     # the bearer skret hub push uses
wrangler secret put RELAY_PASSWORD      # the dashboard login password

# 3. GH repo secrets for CD (Settings > Secrets):
#    HUB_CF_DEPLOY_TOKEN  - project-scoped CF token (Workers + KV edit + zone DNS)
#    VAULT_KV_ID          - from step 1
#    HUB_PUBLIC_HOST      - vault.n24q02m.com
#    CLOUDFLARE_ACCOUNT_ID - (already present for docs deploy)
```

CD (`.github/workflows/cd.yml` `deploy-hub` job) renders the template from
GH secrets and runs `wrangler deploy` on push to main.

Point `skret hub push` at it via `.skret.yaml`:

```yaml
sync:
  hub:
    url: https://vault.n24q02m.com
```

and export `SKRET_HUB_TOKEN` before pushing.

## Develop

```bash
cd hub
pnpm install
pnpm test        # vitest + @cloudflare/vitest-pool-workers (miniflare)
pnpm typecheck
pnpm dryrun      # wrangler deploy --dry-run (bundle check)
```
