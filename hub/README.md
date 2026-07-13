# skret vault hub (Cloudflare serverless mode)

Read-only vault dashboard for skret. Ingests the names-only manifest that
`skret hub push` sends (no secret values, ever) and renders a password-gated
map of every namespace's keys + per-target presence status.

## What it is / is NOT

- **Is:** a CF Worker + KV. Holds key **names**, salted `sha256[:8]`
  fingerprints, and presence status only.
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

# 2. First deploy (creates the Worker), then set the two Worker secrets
#    (never committed, never GH secrets)
wrangler deploy -c wrangler.deploy.jsonc  # rendered from the template
wrangler secret put SKRET_HUB_TOKEN     # the bearer skret hub push uses
wrangler secret put RELAY_PASSWORD      # the dashboard login password

# 3. Attach the custom domain ONCE (out-of-band, self-creates CF-managed DNS).
#    This is NOT done by CD, so the CD token needs no zone permission:
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/workers/domains" \
  -H "Authorization: Bearer <a token with zone Workers-Routes edit, e.g. the dev token>" \
  -H "Content-Type: application/json" \
  --data '{"zone_id":"<ZONE_ID>","hostname":"vault.n24q02m.com","service":"skret-hub","environment":"production"}'
#    (or Dashboard > Workers > skret-hub > Settings > Domains & Routes > Add custom domain)

# 4. GH repo secrets for CD (Settings > Secrets):
#    HUB_CF_DEPLOY_TOKEN   - project-scoped token: account Workers Scripts + KV
#                            write ONLY (no zone perm — the domain is attached
#                            out-of-band in step 3 and persists across deploys)
#    VAULT_KV_ID           - from step 1
#    CLOUDFLARE_ACCOUNT_ID - (already present for docs deploy)
```

CD (`.github/workflows/cd.yml` `deploy-hub` job) builds `Dockerfile.sync`,
pushes it to the Cloudflare managed registry, renders the template
(`${VAULT_KV_ID}`, `${SKRET_SYNC_IMAGE}`, `${CLOUDFLARE_ACCOUNT_ID}`) from GH
secrets, and runs `wrangler deploy` on push to main — it updates the script;
the custom domain from step 3 stays attached.

## Hardening (owner-side)

`/login` has no in-code rate limit (the Worker is stateless, so there is
nowhere to hold a counter across requests). The owner should add a
Cloudflare WAF rate-limiting rule on `POST /login` (by IP or by path) to
blunt password brute-force attempts.

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
