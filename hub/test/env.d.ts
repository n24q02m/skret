// Extend Vitest 4's Cloudflare.Env with the Worker's binding types.
import type { Env as WorkerEnv } from "../src/types";

declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {}
  }
}
