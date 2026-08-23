# Security executor remediation report

## Decision

`PASS_WITH_SOURCE_ONLY_RESIDUALS` for the bounded remediation. The executor replay authority now has an arithmetic `2 ** 40` metadata source-size bound, a value-free bounded `sweep` RPC, and a scheduled Worker hook with a fifteen-minute cron trigger. The executor config is explicitly non-public (`workers_dev: false`, `preview_urls: false`, and no routes). The Hub `EXECUTOR` service binding remains required and is not removed.

Hub readiness is deliberately **not** claimed: `hub/deployment-order.json` requires `skret-security-executor` deployment and readback before `skret-hub`, records `hub_ready_without_executor_readback: false`, and sets `hub_deploy_allowed: false` with blocker `executor_readback_required`. No Cloudflare deployment or live readback was performed.

## Changed files

- `hub/src/security-executor.ts`
  - Replaced the JavaScript bitwise `1 << 40` bound with `2 ** 40`.
  - Added duplicate-key rejection before metadata JSON parsing so duplicate fields cannot be collapsed by `JSON.parse`.
  - Added value-free `SecurityExecutorReplay.sweep(now, limit, startAfter?)` RPC mapping store outcomes to `swept`, `invalid`, or `unavailable`.
  - Added a scheduled Worker hook that performs one bounded replay sweep and fails closed on a missing binding, thrown RPC, or unexpected result.
- `hub/test/security-executor.test.ts`
  - Added regression coverage for the arithmetic bound, duplicate metadata keys, DO sweep mapping, scheduled sweep invocation, and fail-closed scheduled errors.
- `hub/wrangler.executor.jsonc`
  - Added `workers_dev: false`, `preview_urls: false`, and `triggers.crons: ["*/15 * * * *"]`.
- `hub/deployment-order.json`
  - Added source-only executor-before-Hub order/readback metadata.
- `tests/repo_bootstrap/test_executor_config_policy.py`
  - Added policy assertions for non-public executor exposure, sweep cron, and deployment-order/readback metadata.

## Focused evidence

- TDD red: `pnpm exec vitest run test/security-executor.test.ts` initially reported 6 expected failures for the new bound, duplicate-key, scheduled-hook, and DO-sweep contracts.
- Green: `pnpm exec vitest run test/security-executor.test.ts --maxWorkers=1` — 17 tests passed.
- Typecheck: `pnpm typecheck` — exit 0.
- Config/order policy: `python -m unittest tests.repo_bootstrap.test_executor_config_policy -v` — 5 tests passed.
- Ordinary Hub dry-run: `pnpm dryrun` — exit 0; `env.EXECUTOR` remains the declared service binding and Wrangler exited at `--dry-run`.
- Executor dry-run: `pnpm exec wrangler deploy --dry-run --config wrangler.executor.jsonc` — exit 0; replay Durable Object and non-secret vars were read back, and Wrangler exited at `--dry-run`.
- Whitespace: `git diff --check` — no output.

## Residual status

- **Source/deployment ordering residual:** the executor Worker has not been deployed or read back. The existing Hub-only `deploy-hub` job therefore cannot be treated as executor-ready; the manifest explicitly keeps `hub_deploy_allowed: false` until the executor readback gate is satisfied. No provider, production, public, or Cloudflare mutation was performed.
- **Secret/config residual:** `EXECUTOR_PUBLIC_KEY` and `EXECUTOR_RESPONSE_KEY` remain out-of-band secrets and are intentionally absent from committed Wrangler config.
- **Runtime residual:** scheduled reclamation is source/config only until the executor Worker is deployed with the configured cron and its replay Durable Object is verified.
