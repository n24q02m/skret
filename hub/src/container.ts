import { Container, type State, type StopParams } from "@cloudflare/containers";
import type { Env, SyncHealth, SyncRunMetadata } from "./types";
import {
  SYNC_ACTIVE_RUN_KEY,
  SYNC_PLANNER_STOP_STATE_KEY,
  completeSyncRun,
  ensureStartedSyncRun,
  getSyncHealth as readSyncHealth,
  putStartedSyncRun,
} from "./store";

const PLANNER_STOP_RECONCILE_TIMEOUT_MS = 5000;
const PLANNER_RPC_TIMEOUT_MS = 500;

type PlannerStopState = "clear" | "pending" | "uncertain";
async function boundedPlannerOperation<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: number | null = null;
  const timeout = new Promise<T>((_, reject) => {
    timer = setTimeout(() => reject(new Error("planner operation timeout")), timeoutMs);
  });
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// Long-lived private planner container: it exposes the metadata-only HTTP
// planner on port 8080. Its long idle window and activity-expiration override
// keep the planner available instead of treating normal idleness as a failure.
export class SyncContainer extends Container<Env> {
  defaultPort = 8080;
  requiredPorts = [8080];
  sleepAfter = "24h";
  private plannerStartInFlight?: Promise<void>;
  private plannerReadinessCleanup = false;
  private plannerStopPending = false;
  private plannerStopUncertain = false;

  // Serialize the full readiness path, including the SDK's pending-stop
  // reconciliation, so concurrent cron deliveries cannot pair an old onStop
  // callback with a newly-started planner run.
  async ensurePlannerReady(): Promise<void> {
    if (this.plannerStartInFlight) return this.plannerStartInFlight;
    const readyPromise = (async () => {
      if (!this.plannerStopPending) {
        let persistedState: string | undefined;
        try {
          persistedState =
            (await boundedPlannerOperation(
              this.ctx.storage.get<string>(SYNC_PLANNER_STOP_STATE_KEY),
              PLANNER_RPC_TIMEOUT_MS,
            )) ?? undefined;
        } catch {
          throw new Error("planner stop state unavailable");
        }
        if (
          persistedState !== undefined &&
          persistedState !== "clear" &&
          persistedState !== "pending" &&
          persistedState !== "uncertain"
        ) {
          throw new Error("planner stop state unavailable");
        }
        if (persistedState === "pending" || persistedState === "uncertain") {
          this.plannerStopPending = true;
          this.plannerReadinessCleanup = true;
          this.plannerStopUncertain = persistedState === "uncertain";
        }
      }
      if (!this.plannerStopPending) {
        let state: State;
        let activeRunId: string | undefined;
        try {
          state = await boundedPlannerOperation(
            this.getState(),
            PLANNER_RPC_TIMEOUT_MS,
          );
          activeRunId =
            (await boundedPlannerOperation(
              this.ctx.storage.get<string>(SYNC_ACTIVE_RUN_KEY),
              PLANNER_RPC_TIMEOUT_MS,
            )) ?? undefined;
        } catch {
          throw new Error("planner state unavailable");
        }
        if (
          (state.status === "stopping" ||
            state.status === "stopped" ||
            state.status === "stopped_with_code") &&
          activeRunId
        ) {
          this.plannerStopPending = true;
          this.plannerReadinessCleanup = true;
          await this.waitForPlannerStopReconciliation();
          if (this.plannerStopPending) {
            throw new Error("planner stop reconciliation pending");
          }
        }
      }
      if (this.plannerStopPending) {
        await this.waitForPlannerStopReconciliation();
        if (this.plannerStopPending) throw new Error("planner stop reconciliation pending");
      }
      try {
        await this.startAndWaitForPorts();
      } catch (error) {
        this.plannerReadinessCleanup = true;
        this.plannerStopPending = true;
        let markerPersisted = true;
        try {
          await boundedPlannerOperation(
            this.writePlannerStopState("pending"),
            PLANNER_RPC_TIMEOUT_MS,
          );
        } catch {
          markerPersisted = false;
          await this.markPlannerStopUncertain();
        }
        try {
          // Force cleanup so an unready instance cannot remain running, and
          // keep the readiness lock held until the stop RPC has reconciled.
          await boundedPlannerOperation(this.stop("SIGKILL"), PLANNER_RPC_TIMEOUT_MS);
        } catch {
          // Preserve the original readiness error; later reconciliation can
          // observe a stop RPC that was unavailable.
        }
        if (markerPersisted) await this.waitForPlannerStopReconciliation();
        this.plannerStopPending = true;
        if (!markerPersisted) throw new Error("planner stop state unavailable");
        throw error;
      }
    })();
    this.plannerStartInFlight = readyPromise;
    try {
      await readyPromise;
      this.plannerReadinessCleanup = false;
    } finally {
      if (this.plannerStartInFlight === readyPromise) this.plannerStartInFlight = undefined;
    }
  }
  private async writePlannerStopState(
    next: PlannerStopState,
    force = false,
  ): Promise<void> {
    await this.ctx.storage.transaction(async (transaction) => {
      const current = await transaction.get<string>(SYNC_PLANNER_STOP_STATE_KEY);
      if (
        current !== undefined &&
        current !== "clear" &&
        current !== "pending" &&
        current !== "uncertain"
      ) {
        throw new Error("planner stop state unavailable");
      }
      if (!force && next === "clear" && current === "uncertain") return;
      await transaction.put(SYNC_PLANNER_STOP_STATE_KEY, next);
    });
  }

  private async markPlannerStopUncertain(): Promise<void> {
    this.plannerStopUncertain = true;
    try {
      await boundedPlannerOperation(
        this.writePlannerStopState("uncertain"),
        PLANNER_RPC_TIMEOUT_MS,
      );
    } catch {
      // Keep the in-memory fail-closed state when durable repair is unavailable.
    }
  }

  private async waitForPlannerStopReconciliation(): Promise<void> {
    const deadline = Date.now() + PLANNER_STOP_RECONCILE_TIMEOUT_MS;
    let lastStopAttempt = 0;
    let stopAttempted = false;
    for (;;) {
      const remainingBeforeState = deadline - Date.now();
      if (remainingBeforeState <= 0) return;
      let state: State | undefined;
      try {
        state = await boundedPlannerOperation(
          this.getState(),
          Math.min(PLANNER_RPC_TIMEOUT_MS, remainingBeforeState),
        );
      } catch {
        await this.markPlannerStopUncertain();
      }
      const remainingBeforeActive = deadline - Date.now();
      if (remainingBeforeActive <= 0) return;
      let activeRunId: string | null | undefined;
      try {
        activeRunId =
          (await boundedPlannerOperation(
            this.ctx.storage.get<string>(SYNC_ACTIVE_RUN_KEY),
            Math.min(PLANNER_RPC_TIMEOUT_MS, remainingBeforeActive),
          )) ?? null;
      } catch {
        activeRunId = undefined;
        await this.markPlannerStopUncertain();
      }
      const stopped =
        state?.status === "stopped" || state?.status === "stopped_with_code";
      const activeRunPresent = activeRunId !== null;
      const retryStop =
        !stopAttempted || !stopped || activeRunPresent;
      if (retryStop && Date.now() - lastStopAttempt >= 250) {
        const remainingBeforeStop = deadline - Date.now();
        if (remainingBeforeStop <= 0) return;
        try {
          // Reconcile both a still-running process and a stopped state whose
          // onStop callback has not yet repaired the active run record.
          await boundedPlannerOperation(
            this.stop("SIGKILL"),
            Math.min(PLANNER_RPC_TIMEOUT_MS, remainingBeforeStop),
          );
        } catch {
          await this.markPlannerStopUncertain();
        }
        lastStopAttempt = Date.now();
        stopAttempted = true;
        const remainingAfterStop = deadline - Date.now();
        if (remainingAfterStop <= 0) return;
        try {
          activeRunId =
            (await boundedPlannerOperation(
              this.ctx.storage.get<string>(SYNC_ACTIVE_RUN_KEY),
              Math.min(PLANNER_RPC_TIMEOUT_MS, remainingAfterStop),
            )) ?? null;
        } catch {
          activeRunId = undefined;
          await this.markPlannerStopUncertain();
        }
      }
      if (stopped && activeRunId) {
        this.plannerReadinessCleanup = true;
        const remainingBeforeTerminalize = deadline - Date.now();
        if (remainingBeforeTerminalize <= 0) return;
        try {
          // The SDK skips onStop for state=stopped; terminalize the durable
          // active run explicitly before any restart can reuse its identity.
          const exitCode =
            state?.status === "stopped_with_code" ? (state.exitCode ?? 0) : 0;
          await boundedPlannerOperation(
            this.onStop({ exitCode, reason: "runtime_signal" }),
            Math.min(PLANNER_RPC_TIMEOUT_MS, remainingBeforeTerminalize),
          );
        } catch {
          await this.markPlannerStopUncertain();
        }
        const remainingAfterTerminalize = deadline - Date.now();
        if (remainingAfterTerminalize <= 0) return;
        try {
          activeRunId =
            (await boundedPlannerOperation(
              this.ctx.storage.get<string>(SYNC_ACTIVE_RUN_KEY),
              Math.min(PLANNER_RPC_TIMEOUT_MS, remainingAfterTerminalize),
            )) ?? null;
        } catch {
          activeRunId = undefined;
          await this.markPlannerStopUncertain();
        }
      }
      if (stopped && activeRunId === null) {
        if (this.plannerStopUncertain) return;
        const remainingBeforeClear = deadline - Date.now();
        if (remainingBeforeClear <= 0) return;
        try {
          await boundedPlannerOperation(
            this.writePlannerStopState("clear"),
            Math.min(PLANNER_RPC_TIMEOUT_MS, remainingBeforeClear),
          );
          this.plannerStopPending = false;
          return;
        } catch {
          await this.markPlannerStopUncertain();
        }
      }
      const remainingBeforeSleep = deadline - Date.now();
      if (remainingBeforeSleep <= 0) return;
      await new Promise((resolve) => setTimeout(resolve, Math.min(50, remainingBeforeSleep)));
    }
  }
  // Direct callers may create a run with metadata before exercising the
  // lifecycle hooks. The container runtime uses onStart() below instead.
  async beginRun(metadata: SyncRunMetadata = {}): Promise<string> {
    const runId = crypto.randomUUID();
    await putStartedSyncRun(this.ctx.storage, runId, new Date().toISOString(), metadata);
    return runId;
  }

  // The runtime invokes onStart only after a process has started. A startup
  // failure before this hook creates no run; repeated callbacks reuse the
  // active started record so readiness timeouts cannot falsely terminalize it.
  override async onStart(): Promise<void> {
    await ensureStartedSyncRun(this.ctx.storage, new Date().toISOString());
    this.plannerReadinessCleanup = false;
  }

  // Public health reads receive only the coarse freshness projection. Detailed
  // run records remain in Durable Object storage for authenticated operators.
  async getSyncHealth(): Promise<SyncHealth> {
    return readSyncHealth(this.ctx.storage);
  }

  // Once onStart() persists a record, onStop() is the sole terminal transition
  // and last-success writer for that container process.
  // @cloudflare/containers stops idle containers by default. Renew the
  // activity window instead so expected idleness never emits runtime_signal.
  override async onActivityExpired(): Promise<void> {
    this.renewActivityTimeout();
  }

  override async onStop(params: StopParams): Promise<void> {
    const readinessCleanup = this.plannerReadinessCleanup;
    const runId = await this.ctx.storage.get<string>(SYNC_ACTIVE_RUN_KEY);
    if (!runId) {
      await boundedPlannerOperation(
        this.writePlannerStopState("clear", true),
        PLANNER_RPC_TIMEOUT_MS,
      );
      this.plannerReadinessCleanup = false;
      this.plannerStopPending = false;
      this.plannerStopUncertain = false;
      return;
    }
    const finished = await completeSyncRun(
      this.ctx.storage,
      runId,
      new Date().toISOString(),
      params.exitCode,
      readinessCleanup ? "runtime_signal" : params.reason,
    );
    if (!finished) return;
    await boundedPlannerOperation(
      this.writePlannerStopState("clear", true),
      PLANNER_RPC_TIMEOUT_MS,
    );
    this.plannerReadinessCleanup = false;
    this.plannerStopPending = false;
    this.plannerStopUncertain = false;

    console.log(
      `sync-container stopped run=${finished.runId} status=${finished.status} ` +
        `classification=${finished.classification} exit=${finished.exitCode} reason=${finished.reason}`,
    );
  }
}
