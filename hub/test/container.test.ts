import { describe, it, expect, vi } from "vitest";
import { Container, type State } from "@cloudflare/containers";
import { SyncContainer } from "../src/container";
import {
  SYNC_ACTIVE_RUN_KEY,
  SYNC_LAST_SUCCESS_KEY,
  SYNC_PLANNER_STOP_STATE_KEY,
  SYNC_RUN_PREFIX,
  completeSyncRun,
  syncRunKey,
} from "../src/store";
import worker from "../src/index";
import type { Env, SyncRunMetadata, SyncRunRecord } from "../src/types";

type TestStorageOperation = {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
};

type TestStorage = TestStorageOperation & {
  values: Map<string, unknown>;
  failNextPutKey?: string;
  failNextTransactionCount?: number;
  transaction<T>(closure: (transaction: TestStorageOperation) => Promise<T>): Promise<T>;
};

function fakeStorage(): TestStorage {
  const values = new Map<string, unknown>();
  let transactionTail = Promise.resolve();
  const storage = {
    values,
    failNextPutKey: undefined as string | undefined,
    failNextTransactionCount: 0,
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      if (storage.failNextPutKey === key) {
        storage.failNextPutKey = undefined;
        throw new Error(`injected storage failure for ${key}`);
      }
      values.set(key, value);
    },
    async delete(key: string): Promise<boolean> {
      return values.delete(key);
    },
    async transaction<T>(
      closure: (transaction: TestStorageOperation) => Promise<T>,
    ): Promise<T> {
      const previous = transactionTail;
      let release!: () => void;
      transactionTail = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;
      try {
        if (storage.failNextTransactionCount > 0) {
          storage.failNextTransactionCount -= 1;
          throw new Error("injected transaction failure");
        }
        return await closure(storage);
      } finally {
        release();
      }
    },
  };
  return storage;
}

function fakeContainer(storage: TestStorage): SyncContainer {
  const instance = Object.create(SyncContainer.prototype) as SyncContainer;
  Object.defineProperty(instance, "ctx", { value: { storage } });
  return instance;
}
describe("SyncContainer", () => {
  it("is a Container subclass named SyncContainer", () => {
    expect(SyncContainer.name).toBe("SyncContainer");
    // Prototype-chain check: SyncContainer extends the @cloudflare/containers
    // Container base. Port fields are class-instance settings consumed by
    // startAndWaitForPorts() in scheduled(); the fake DO avoids construction.
    expect(SyncContainer.prototype instanceof Container).toBe(true);
  });

  it("overrides onStop for the planner lifecycle", () => {
    expect(Object.getOwnPropertyNames(SyncContainer.prototype)).toContain("onStop");
  });

  it("creates one started run when startup is delivered more than once", async () => {
    const { container, storage } = fakeEnv({});

    await container.onStart();
    const firstRunId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
    expect(firstRunId).toEqual(expect.any(String));

    await container.onStart();
    const secondRunId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
    const runKeys = [...storage.values.keys()].filter((key) => key.startsWith(SYNC_RUN_PREFIX));

    expect(secondRunId).toBe(firstRunId);
    expect(runKeys).toEqual([syncRunKey(firstRunId as string)]);
    expect(await storage.get<SyncRunRecord>(syncRunKey(firstRunId as string))).toMatchObject({
      runId: firstRunId,
      status: "started",
      classification: "started",
      endedAt: null,
    });
  });

  it("does not create a terminal run when startup has not reached onStart", async () => {
    const { container, storage } = fakeEnv({});

    await expect(container.onStop({ exitCode: 17, reason: "runtime_signal" })).resolves.toBeUndefined();

    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBeUndefined();
    expect([...storage.values.keys()].filter((key) => key.startsWith(SYNC_RUN_PREFIX))).toEqual([]);
  });

  it("keeps the planner alive when activity expires", async () => {
    const stop = vi.fn();
    const renewActivityTimeout = vi.fn();
    const onActivityExpired = SyncContainer.prototype.onActivityExpired;

    expect(Object.getOwnPropertyNames(SyncContainer.prototype)).toContain("onActivityExpired");
    await onActivityExpired.call({
      stop,
      renewActivityTimeout,
    } as unknown as SyncContainer);

    expect(renewActivityTimeout).toHaveBeenCalledTimes(1);
    expect(stop).not.toHaveBeenCalled();
  });
  it("coalesces concurrent readiness calls", async () => {
    const { container } = fakeEnv({});
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const startAndWaitForPorts = vi.fn(() => gate);
    container.startAndWaitForPorts = startAndWaitForPorts;

    const first = container.ensurePlannerReady();
    const second = container.ensurePlannerReady();

    await Promise.resolve();
    await Promise.resolve();
    release();
    await Promise.all([first, second]);
  });
  it("holds the readiness lock through failed-start cleanup", async () => {
    const { container } = fakeEnv({});
    const readinessError = new Error("port readiness timed out");
    let releaseStop!: () => void;
    let signalStopStarted!: () => void;
    const stopGate = new Promise<void>((resolve) => {
      releaseStop = resolve;
    });
    const stopStarted = new Promise<void>((resolve) => {
      signalStopStarted = resolve;
    });
    const startAndWaitForPorts = vi.fn(async () => {
      throw readinessError;
    });
    const stop = vi.fn(async () => {
      signalStopStarted();
      await stopGate;
    });
    container.startAndWaitForPorts = startAndWaitForPorts;
    container.stop = stop;

    const first = container.ensurePlannerReady();
    await stopStarted;
    const second = container.ensurePlannerReady();

    expect(startAndWaitForPorts).toHaveBeenCalledTimes(1);
    releaseStop();
    const results = await Promise.allSettled([first, second]);
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    expect(stop).toHaveBeenCalledTimes(2);
  });

});
describe("sync health projection", () => {
  it("returns an unknown freshness state when no clean success exists", async () => {
    const { container } = fakeEnv({});

    await expect(container.getSyncHealth()).resolves.toEqual({
      active: false,
      last_success_at: null,
      age_seconds: null,
    });
  });

  it("reports an active state only for a started run", async () => {
    const { container } = fakeEnv({});
    await container.beginRun();

    await expect(container.getSyncHealth()).resolves.toEqual({
      active: true,
      last_success_at: null,
      age_seconds: null,
    });
  });

  it("reports clean-success age in non-negative seconds", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-22T00:01:40.000Z"));
    try {
      const { container, storage } = fakeEnv({});
      const runId = await container.beginRun();
      await completeSyncRun(
        storage,
        runId,
        "2026-08-22T00:00:10.000Z",
        0,
        "exit",
      );

      await expect(container.getSyncHealth()).resolves.toEqual({
        active: false,
        last_success_at: "2026-08-22T00:00:10.000Z",
        age_seconds: 90,
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not treat a stale terminal active pointer as active", async () => {
    const { container, storage } = fakeEnv({});
    const runId = await container.beginRun();
    await completeSyncRun(storage, runId, "2026-08-22T00:00:10.000Z", 17, "exit");
    await storage.put(SYNC_ACTIVE_RUN_KEY, runId);

    await expect(container.getSyncHealth()).resolves.toMatchObject({
      active: false,
      last_success_at: null,
      age_seconds: null,
    });
  });
});


// Build a fake env whose SYNC namespace resolves (getContainer calls
// idFromName + get) to a stub with lifecycle and readiness-start spies. This
// exercises the real scheduled() wiring without instantiating a container DO.
function fakeEnv(secrets: Record<string, string | undefined> = {}) {
  const storage = fakeStorage();
  const container = fakeContainer(storage);
  const order: string[] = [];
  const beginRun = vi.fn(async (metadata?: SyncRunMetadata) => {
    const runId = await container.beginRun(metadata);
    order.push("begin");
    return runId;
  });
  const start = vi.fn(async (_options?: unknown) => {
    order.push("start");
  });
  const stop = vi.fn(async () => {
    order.push("stop");
  });
  const getState = vi.fn(async () => ({ status: "stopped" as const, lastChange: 0 }));
  container.getState = getState;
  const stub = { beginRun, ensurePlannerReady: start, stop };
  const SYNC = {
    idFromName: () => ({}),
    get: () => stub,
  };
  return {
    env: { SYNC, ...secrets } as unknown as Env,
    start,
    stop,
    beginRun,
    storage,
    container,
    order,
  };
}
describe("scheduled()", () => {
  it("only starts the planner without creating a run or forwarding provider secrets", async () => {
    const secrets = {
      GITHUB_TOKEN: "gh-tok",
      CLOUDFLARE_API_TOKEN: "cf-tok",
      AWS_ACCESS_KEY_ID: "akid",
      AWS_SECRET_ACCESS_KEY: "sk",
      AWS_REGION: "ap-southeast-1",
    };
    const { env, start, beginRun, order } = fakeEnv(secrets);

    await worker.scheduled({} as ScheduledController, env);

    expect(order).toEqual(["start"]);
    expect(beginRun).not.toHaveBeenCalled();
    expect(start).toHaveBeenCalledTimes(1);
    expect(start.mock.calls[0]).toEqual([]);
  });

  it("is safe for repeated daily calls while the planner remains active", async () => {
    const { env, start, beginRun, container, storage } = fakeEnv({});
    start.mockImplementation(async () => {
      await container.onStart();
    });

    await worker.scheduled({} as ScheduledController, env);
    const firstRunId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
    await worker.scheduled({} as ScheduledController, env);

    const secondRunId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
    const runKeys = [...storage.values.keys()].filter((key) => key.startsWith(SYNC_RUN_PREFIX));
    expect(start).toHaveBeenCalledTimes(2);
    expect(beginRun).not.toHaveBeenCalled();
    expect(secondRunId).toBe(firstRunId);
    expect(runKeys).toHaveLength(1);
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBeUndefined();
  });

  it("stops an unready planner before it can create a run", async () => {
    const { container, start, stop, storage } = fakeEnv({});
    const readinessError = new Error("port readiness timed out");
    container.startAndWaitForPorts = start;
    container.stop = stop;
    start.mockRejectedValueOnce(readinessError);

    await expect(container.ensurePlannerReady()).rejects.toBe(readinessError);

    expect(stop).toHaveBeenCalledWith("SIGKILL");
    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBeUndefined();
    expect([...storage.values.keys()].filter((key) => key.startsWith(SYNC_RUN_PREFIX))).toEqual([]);
  });

  it("stops after a startup failure and preserves the original error", async () => {
    const { container, start, stop, storage } = fakeEnv({});
    const startError = new Error("container start failed");
    container.startAndWaitForPorts = start;
    container.stop = stop;
    start.mockRejectedValueOnce(startError);

    await expect(container.ensurePlannerReady()).rejects.toBe(startError);

    expect(stop).toHaveBeenCalledWith("SIGKILL");
    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBeUndefined();
    expect([...storage.values.keys()].filter((key) => key.startsWith(SYNC_RUN_PREFIX))).toEqual([]);
  });

  it("marks readiness cleanup as failure for an active run", async () => {
    const { container, storage } = fakeEnv({});
    container.getState = vi.fn(async () => ({ status: "running" as const, lastChange: 0 }));
    const runId = await container.beginRun();
    const readinessError = new Error("planner port failed");
    const startAndWaitForPorts = vi.fn(async () => {
      throw readinessError;
    });
    const stop = vi.fn(async () => {
      container.getState = vi.fn(async () => ({ status: "stopped" as const, lastChange: 1 }));
      await container.onStop({ exitCode: 0, reason: "exit" });
    });
    container.startAndWaitForPorts = startAndWaitForPorts;
    container.stop = stop;

    await expect(container.ensurePlannerReady()).rejects.toBe(readinessError);

    expect(stop).toHaveBeenCalledWith("SIGKILL");
    await expect(storage.get<SyncRunRecord>(syncRunKey(runId))).resolves.toMatchObject({
      status: "failed",
      classification: "runtime_signal",
      reason: "runtime_signal",
    });
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBeUndefined();
  });
  it("preserves forced-stop classification across a failed completion write", async () => {
    const { container, storage } = fakeEnv({});
    container.getState = vi.fn(async () => ({ status: "running" as const, lastChange: 0 }));
    const runId = await container.beginRun();
    const readinessError = new Error("planner port failed");
    const startAndWaitForPorts = vi.fn(async () => {
      throw readinessError;
    });
    const stop = vi.fn(async () => {
      container.getState = vi.fn(async () => ({ status: "stopped" as const, lastChange: 1 }));
      await container.onStop({ exitCode: 137, reason: "exit" });
    });
    container.startAndWaitForPorts = startAndWaitForPorts;
    container.stop = stop;
    storage.failNextPutKey = syncRunKey(runId);

    await expect(container.ensurePlannerReady()).rejects.toBe(readinessError);

    expect(stop).toHaveBeenCalledTimes(2);
    await expect(storage.get<SyncRunRecord>(syncRunKey(runId))).resolves.toMatchObject({
      status: "failed",
      classification: "runtime_signal",
      reason: "runtime_signal",
    });
    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBeUndefined();
  });
  it("reconciles a durable pending marker after container reconstruction", async () => {
    const { container, storage } = fakeEnv({});
    await storage.put(SYNC_PLANNER_STOP_STATE_KEY, "pending");
    const startAndWaitForPorts = vi.fn(async () => undefined);
    const stop = vi.fn(async () => undefined);
    container.startAndWaitForPorts = startAndWaitForPorts;
    container.stop = stop;

    await container.ensurePlannerReady();

    expect(stop).toHaveBeenCalledWith("SIGKILL");
    expect(startAndWaitForPorts).toHaveBeenCalledTimes(1);
    expect(await storage.get<string>(SYNC_PLANNER_STOP_STATE_KEY)).toBe("clear");
  });
  it("terminalizes a stale active run before restarting a stopped planner", async () => {
    const { container, storage } = fakeEnv({});
    const runId = await container.beginRun();
    const start = vi.fn(async () => undefined);
    const stop = vi.fn(async () => undefined);
    container.startAndWaitForPorts = start;
    container.stop = stop;

    await container.ensurePlannerReady();

    expect(stop).toHaveBeenCalledWith("SIGKILL");
    expect(start).toHaveBeenCalledTimes(1);
    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBeUndefined();
    await expect(storage.get<SyncRunRecord>(syncRunKey(runId))).resolves.toMatchObject({
      status: "failed",
      classification: "runtime_signal",
      reason: "runtime_signal",
    });
  });
  it("preserves the stopped container exit code during forced reconciliation", async () => {
    const { container, storage } = fakeEnv({});
    const runId = await container.beginRun();
    container.getState = vi.fn(async () => ({
      status: "stopped_with_code" as const,
      exitCode: 137,
      lastChange: 0,
    }));
    container.startAndWaitForPorts = vi.fn(async () => undefined);
    container.stop = vi.fn(async () => undefined);

    await container.ensurePlannerReady();

    await expect(storage.get<SyncRunRecord>(syncRunKey(runId))).resolves.toMatchObject({
      status: "failed",
      classification: "runtime_signal",
      exitCode: 137,
    });
  });

  it("waits for a stopping planner to terminalize before starting its successor", async () => {
    vi.useFakeTimers();
    try {
      const { container, storage } = fakeEnv({});
      const runId = await container.beginRun();
      const order: string[] = [];
      let state: State = { status: "stopping", lastChange: 0 };
      container.getState = vi.fn(async () => state);
      container.stop = vi.fn(async () => {
        order.push("stop");
        state = { status: "stopped" as const, lastChange: 1 };
        await container.onStop({ exitCode: 0, reason: "runtime_signal" });
      });
      container.startAndWaitForPorts = vi.fn(async () => {
        order.push("start");
      });

      const readiness = container.ensurePlannerReady();
      await vi.advanceTimersByTimeAsync(100);
      await readiness;

      expect(order).toEqual(["stop", "start"]);
      await expect(storage.get<SyncRunRecord>(syncRunKey(runId))).resolves.toMatchObject({
        status: "failed",
        classification: "runtime_signal",
      });
    } finally {
      vi.useRealTimers();
    }
  });
  it("reconstructs safely after both readiness marker writes fail", async () => {
    const { container, storage } = fakeEnv({});
    const runId = await container.beginRun();
    container.getState = vi.fn(async () => ({ status: "running" as const, lastChange: 0 }));
    const readinessError = new Error("planner readiness failed");
    container.startAndWaitForPorts = vi.fn(async () => {
      throw readinessError;
    });
    container.stop = vi.fn(async () => {
      container.getState = vi.fn(async () => ({ status: "stopped" as const, lastChange: 1 }));
    });
    storage.failNextTransactionCount = 2;

    await expect(container.ensurePlannerReady()).rejects.toThrow("planner stop state unavailable");

    const reconstructed = fakeContainer(storage);
    reconstructed.getState = vi.fn(async () => ({ status: "stopped" as const, lastChange: 1 }));
    reconstructed.startAndWaitForPorts = vi.fn(async () => undefined);
    reconstructed.stop = vi.fn(async () => undefined);
    await reconstructed.ensurePlannerReady();

    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBeUndefined();
    await expect(storage.get<SyncRunRecord>(syncRunKey(runId))).resolves.toMatchObject({
      status: "failed",
      classification: "runtime_signal",
    });
  });


  it("starts the planner with only the SYNC binding", async () => {
    const { env, start, beginRun } = fakeEnv({});

    expect(Object.keys(env)).toEqual(["SYNC"]);
    await worker.scheduled({} as ScheduledController, env);

    expect(beginRun).not.toHaveBeenCalled();
    expect(start).toHaveBeenCalledTimes(1);
    expect(start.mock.calls[0]).toEqual([]);
  });
});
describe("durable sync run records", () => {
  it("finalizes a clean exit and advances last success", async () => {
    const { container, storage } = fakeEnv({});
    const runId = await container.beginRun({
      imageDigest: "sha256:image",
      configFingerprint: "config-fingerprint",
      targetCount: 3,
    });

    const started = await storage.get<SyncRunRecord>(syncRunKey(runId));
    expect(started).toMatchObject({
      runId,
      imageDigest: "sha256:image",
      configFingerprint: "config-fingerprint",
      targetCount: 3,
      status: "started",
      classification: "started",
      endedAt: null,
      exitCode: null,
      reason: null,
    });
    await container.onStop({ exitCode: 0, reason: "exit" });

    const finished = await storage.get<SyncRunRecord>(syncRunKey(runId));
    expect(finished).toMatchObject({
      runId,
      status: "succeeded",
      classification: "clean_exit",
      endedAt: expect.any(String),
      exitCode: 0,
      reason: "exit",
    });
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBe(runId);
    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBeUndefined();
  });

  it("does not let a replayed older clean run regress last success", async () => {
    const { container, storage } = fakeEnv({});
    const firstRunId = await container.beginRun();
    await completeSyncRun(
      storage,
      firstRunId,
      "2026-08-22T00:00:10.000Z",
      0,
      "exit",
    );
    const secondRunId = await container.beginRun();
    await completeSyncRun(
      storage,
      secondRunId,
      "2026-08-22T00:00:20.000Z",
      0,
      "exit",
    );
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBe(secondRunId);

    await completeSyncRun(
      storage,
      firstRunId,
      "2026-08-22T00:00:10.000Z",
      0,
      "exit",
    );

    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBe(secondRunId);
  });

  it("requires parseable completion timestamps for last-success repair", async () => {
    const { container, storage } = fakeEnv({});
    const invalidFirstRunId = await container.beginRun();
    await completeSyncRun(storage, invalidFirstRunId, "not-a-timestamp", 0, "exit");
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBeUndefined();

    const validFirstRunId = await container.beginRun();
    await completeSyncRun(
      storage,
      validFirstRunId,
      "2026-08-22T00:00:10.000Z",
      0,
      "exit",
    );
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBe(validFirstRunId);

    const invalidLaterRunId = await container.beginRun();
    await completeSyncRun(storage, invalidLaterRunId, "also-not-a-timestamp", 0, "exit");
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBe(validFirstRunId);

    await storage.put(SYNC_LAST_SUCCESS_KEY, invalidLaterRunId);
    const validSecondRunId = await container.beginRun();
    await completeSyncRun(
      storage,
      validSecondRunId,
      "2026-08-22T00:00:20.000Z",
      0,
      "exit",
    );
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBe(validSecondRunId);
  });

  it("finalizes a nonzero exit as failure without replacing last success", async () => {
    const { container, storage } = fakeEnv({});
    const successfulRunId = await container.beginRun();
    await container.onStop({ exitCode: 0, reason: "exit" });

    const failedRunId = await container.beginRun();
    await container.onStop({ exitCode: 17, reason: "exit" });

    const failed = await storage.get<SyncRunRecord>(syncRunKey(failedRunId));
    expect(failed).toMatchObject({
      status: "failed",
      classification: "nonzero_exit",
      endedAt: expect.any(String),
      exitCode: 17,
      reason: "exit",
    });
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBe(successfulRunId);
  });

  it("finalizes a runtime signal as failure even when its exit code is zero", async () => {
    const { container, storage } = fakeEnv({});
    const runId = await container.beginRun();

    await container.onStop({ exitCode: 0, reason: "runtime_signal" });

    const finished = await storage.get<SyncRunRecord>(syncRunKey(runId));
    expect(finished).toMatchObject({
      status: "failed",
      classification: "runtime_signal",
      endedAt: expect.any(String),
      exitCode: 0,
      reason: "runtime_signal",
    });
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBeUndefined();
  });

  it("repairs terminal pointers when a completion write fails partway through", async () => {
    const { container, storage } = fakeEnv({});
    const runId = await container.beginRun();
    storage.failNextPutKey = SYNC_LAST_SUCCESS_KEY;

    await expect(container.onStop({ exitCode: 0, reason: "exit" })).rejects.toThrow(
      "injected storage failure",
    );
    expect((await storage.get<SyncRunRecord>(syncRunKey(runId)))?.status).toBe("succeeded");
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBeUndefined();
    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBe(runId);

    await container.onStop({ exitCode: 0, reason: "exit" });

    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBe(runId);
    expect(await storage.get<string>(SYNC_ACTIVE_RUN_KEY)).toBeUndefined();
  });

  it("stores and logs metadata only, never forwarded secret values", async () => {
    const secrets = {
      GITHUB_TOKEN: "github-secret-value",
      CLOUDFLARE_API_TOKEN: "cloudflare-secret-value",
      AWS_SECRET_ACCESS_KEY: "aws-secret-value",
      SKRET_HUB_TOKEN: "hub-secret-value",
    };
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      const { env, container, storage } = fakeEnv(secrets);
      await container.onStart();
      const runId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
      await worker.scheduled({} as ScheduledController, env);
      await container.onStop({ exitCode: 0, reason: "exit" });

      const stored = JSON.stringify([...storage.values.values()]);
      const logged = JSON.stringify(log.mock.calls);
      for (const secret of Object.values(secrets)) {
        expect(stored).not.toContain(secret);
        expect(logged).not.toContain(secret);
      }
      expect(stored).toContain(runId as string);
    } finally {
      log.mockRestore();
    }
  });
});
