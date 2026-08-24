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
5/min real. Bindings and Durable Object are declared in
`wrangler.jsonc` and `wrangler.deploy.template.jsonc`, and `Env` requires them:
a configuration that drops them fails at the first login instead of quietly
serving an unlimited one.

Neither is a cap across *all* addresses — a distributed attacker gets one
counter per address. Put a zone WAF rate-limiting rule in front if you need
that.

## Build-only Wrangler package

Committed `wrangler.jsonc` and `wrangler.deploy.template.jsonc` carry only
placeholders. The repository exposes source checks and explicit dry-runs; it
does not contain a deployment command or credential setup.

```bash
cd hub
pnpm install
pnpm test
pnpm typecheck
pnpm dryrun
pnpm exec wrangler deploy --dry-run --config wrangler.jsonc --outdir "$TMPDIR/skret-hub"
pnpm exec wrangler deploy --dry-run --config wrangler.executor.jsonc --outdir "$TMPDIR/skret-executor"
```

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
