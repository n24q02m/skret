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
| `GET /healthz` | none | uptime check: probes `VAULT_KV`, `200 {ok:true,kv:"ok"}` or `503 {ok:false,kv:"error"}` |

`POST /login` (5/min per client address) and `POST /api/manifest` (30/min) are
rate limited; over the limit is `429`. The two are enforced differently, on
purpose.

Ingest relies on a Workers Rate Limiting binding alone. Cloudflare documents
that binding as permissive and eventually consistent, each isolate checking its
own cached count, and measured against this Worker a fresh connection per
request walks past it entirely. Acceptable on a route whose credential is a
high-entropy bearer token, where the exposure is cost and noise rather than a
guessable secret.

Login guards one shared password, so it cannot rely on that. The binding still
runs first as a free filter, then a `LoginGate` Durable Object — one instance
per client address, so one counter worldwide for that address — makes the
5/min real. Bindings and Durable Object are declared in `wrangler.jsonc` and
`wrangler.deploy.template.jsonc`, and `Env` requires them: a deploy that drops
them fails at the first login instead of quietly serving an unlimited one.

Neither is a cap across *all* addresses — a distributed attacker gets one
counter per address. Put a zone WAF rate-limiting rule in front if you need
that.

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

`/login` is rate limited in code — see Routes above — at 5 attempts a minute
per client address, counted in a Durable Object so the limit holds whichever
isolate or location serves the request. That bounds guessing from one address;
it is not a cap across all of them. An owner who wants that, or who wants the
guessing turned away before it reaches the Worker at all, should add a
Cloudflare WAF rate-limiting rule on `POST /login` (by IP or by path).

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
