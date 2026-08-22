import { Container, type StopParams } from "@cloudflare/containers";
import type { Env, SyncRunMetadata } from "./types";
import {
  SYNC_ACTIVE_RUN_KEY,
  completeSyncRun,
  putStartedSyncRun,
} from "./store";

// Batch one-shot container: it exposes NO defaultPort (no HTTP surface). The
// entrypoint runs `skret sync --skip-unchanged` then `skret hub push` and exits,
// which stops the container. sleepAfter is only a safety net so a run that
// hangs without exiting still sleeps and stops billing.
export class SyncContainer extends Container<Env> {
  sleepAfter = "30s";

  // The Worker calls this RPC before Container.start(). It writes only the
  // metadata needed to correlate the eventual lifecycle callback; forwarded
  // secrets never cross this boundary.
  async beginRun(metadata: SyncRunMetadata = {}): Promise<string> {
    const runId = crypto.randomUUID();
    await putStartedSyncRun(this.ctx.storage, runId, new Date().toISOString(), metadata);
    return runId;
  }

  // Container.start() only acknowledges that the process was launched. This
  // hook is the sole terminal transition and last-success writer.
  override async onStop(params: StopParams): Promise<void> {
    const runId = await this.ctx.storage.get<string>(SYNC_ACTIVE_RUN_KEY);
    if (!runId) return;

    const finished = await completeSyncRun(
      this.ctx.storage,
      runId,
      new Date().toISOString(),
      params.exitCode,
      params.reason,
    );
    if (!finished) return;

    console.log(
      `sync-container stopped run=${finished.runId} status=${finished.status} ` +
        `classification=${finished.classification} exit=${finished.exitCode} reason=${finished.reason}`,
    );
  }
}
