// Types the vitest-pool-workers `env` (from "cloudflare:test") with the
// Worker's own bindings so `pnpm typecheck` (tsc --noEmit) resolves
// env.VAULT_KV / env.SKRET_HUB_TOKEN / env.RELAY_PASSWORD. Without this
// declaration merge, ProvidedEnv is empty and every test that touches a
// binding fails typecheck (vitest itself transpiles via esbuild and does not
// type-check, so the gap only surfaces under tsc).
import type { Env } from "../src/types";

declare module "cloudflare:test" {
  interface ProvidedEnv extends Env {}
}
