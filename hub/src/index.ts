import { getContainer } from "@cloudflare/containers";
import type { Env } from "./types";
import { handleRequest } from "./router";

// The Durable Object container class must be re-exported from the Worker entry
// so the runtime can construct the SYNC binding.
export { SyncContainer } from "./container";

// Secrets forwarded from the Worker env into the sync container process. Unset
// values are dropped so an optional-but-absent secret never injects a blank.
const SYNC_ENV_KEYS = [
  "GITHUB_TOKEN",
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_ACCOUNT_ID",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_REGION",
  "SKRET_HUB_TOKEN",
  "SKRET_HUB_URL",
] as const;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch {
      // Durable boundary: never leak a stack/exception to the client.
      return new Response("internal error", { status: 500 });
    }
  },

  // Cron trigger (wrangler triggers.crons): boot the one-shot sync container,
  // forwarding the sync creds as envVars. start() returns once the container
  // has started — the container runs `skret sync` + `skret hub push` then
  // exits on its own, so we deliberately do not await job completion.
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const envVars: Record<string, string> = {};
    for (const k of SYNC_ENV_KEYS) {
      const v = (env as unknown as Record<string, string | undefined>)[k];
      if (v) envVars[k] = v;
    }
    await getContainer(env.SYNC).start({ envVars });
  },
};
