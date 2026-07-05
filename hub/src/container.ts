import { Container, type StopParams } from "@cloudflare/containers";
import type { Env } from "./types";

// Batch one-shot container: it exposes NO defaultPort (no HTTP surface). The
// entrypoint runs `skret sync --skip-unchanged` then `skret hub push` and
// exits, which stops the container. sleepAfter is only a safety net so a run
// that hangs without exiting still sleeps and stops billing.
export class SyncContainer extends Container<Env> {
  sleepAfter = "30s";

  // Log the run outcome only (exit code + reason) — never any forwarded secret
  // value. StopParams is the @cloudflare/containers lifecycle payload
  // ({ exitCode, reason }); the plan's single-number signature predates it.
  onStop(params: StopParams): void {
    console.log(`sync-container stopped exit=${params.exitCode} reason=${params.reason}`);
  }
}
