import { getContainer } from "@cloudflare/containers";
import type { Env } from "./types";
import { handleRequest, serverError } from "./router";

// Durable Object classes must be re-exported from the Worker entry so the
// runtime can construct their bindings: SyncContainer for SYNC, LoginGate for
// LOGIN_GATE.
export { SyncContainer } from "./container";
export { LoginGate } from "./gate";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch {
      // Durable boundary: never leak a stack/exception to the client.
      return serverError();
    }
  },

  // Cron trigger (wrangler triggers.crons): start the credential-free
  // metadata planner and wait until its required port is ready. Durable run
  // ownership is created by SyncContainer.onStart(), not by this trigger.
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const container = getContainer(env.SYNC);
    await container.ensurePlannerReady();
  },
};
