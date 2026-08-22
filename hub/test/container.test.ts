import { describe, it, expect, vi } from "vitest";
import { Container } from "@cloudflare/containers";
import { SyncContainer } from "../src/container";
import {
  SYNC_ACTIVE_RUN_KEY,
  SYNC_LAST_SUCCESS_KEY,
  syncRunKey,
} from "../src/store";
import worker from "../src/index";
import type { Env, SyncRunMetadata, SyncRunRecord } from "../src/types";

type TestStorage = {
  values: Map<string, unknown>;
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
};

function fakeStorage(): TestStorage {
  const values = new Map<string, unknown>();
  return {
    values,
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      values.set(key, value);
    },
    async delete(key: string): Promise<boolean> {
      return values.delete(key);
    },
  };
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
    // Container base (bound as the SYNC Durable Object). sleepAfter / no
    // defaultPort are instance fields set on construction, so they are asserted
    // via the batch lifecycle rather than an un-instantiable DO here.
    expect(SyncContainer.prototype instanceof Container).toBe(true);
  });

  it("overrides onStop for the one-shot batch lifecycle", () => {
    expect(Object.getOwnPropertyNames(SyncContainer.prototype)).toContain("onStop");
  });
});

// Build a fake env whose SYNC namespace resolves (getContainer just calls
// idFromName + get) to a stub with lifecycle and `start` spies. This exercises
// the real getContainer + scheduled() wiring without instantiating a container
// DO here.
function fakeEnv(secrets: Partial<Env>) {
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
  const stub = { beginRun, start };
  const SYNC = {
    idFromName: () => ({}),
    get: () => stub,
  };
  return {
    env: { SYNC, ...secrets } as unknown as Env,
    start,
    beginRun,
    storage,
    container,
    order,
  };
}
describe("scheduled()", () => {
  it("persists a started run before booting the container and forwards secrets unchanged", async () => {
    const secrets = {
      GITHUB_TOKEN: "gh-tok",
      CLOUDFLARE_API_TOKEN: "cf-tok",
      AWS_ACCESS_KEY_ID: "akid",
      AWS_SECRET_ACCESS_KEY: "sk",
      AWS_REGION: "ap-southeast-1",
      SKRET_HUB_TOKEN: "hub-tok",
      SKRET_HUB_URL: "https://vault.example.com",
    };
    const { env, start, beginRun, order } = fakeEnv(secrets);

    await worker.scheduled({} as ScheduledController, env);

    expect(order).toEqual(["begin", "start"]);
    expect(beginRun).toHaveBeenCalledTimes(1);
    expect(start).toHaveBeenCalledTimes(1);
    expect(start.mock.calls[0][0]).toEqual({ envVars: secrets });
  });

  it("does not treat start alone as completion or last success", async () => {
    const { env, start, storage } = fakeEnv({ GITHUB_TOKEN: "secret-token" });

    await worker.scheduled({} as ScheduledController, env);

    expect(start).toHaveBeenCalledTimes(1);
    const runId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
    expect(runId).toEqual(expect.any(String));
    const record = await storage.get<SyncRunRecord>(syncRunKey(runId as string));
    expect(record).toMatchObject({
      runId,
      imageDigest: null,
      configFingerprint: null,
      targetCount: null,
      startedAt: expect.any(String),
      status: "started",
      classification: "started",
      endedAt: null,
      exitCode: null,
      reason: null,
    });
    expect(await storage.get<string>(SYNC_LAST_SUCCESS_KEY)).toBeUndefined();
  });

  it("omits unset sync secrets from envVars", async () => {
    const { env, start } = fakeEnv({
      SKRET_HUB_TOKEN: "hub-tok",
      SKRET_HUB_URL: "https://vault.example.com",
    });

    await worker.scheduled({} as ScheduledController, env);

    expect(start).toHaveBeenCalledTimes(1);
    const arg = start.mock.calls[0][0] as { envVars: Record<string, string> };
    expect(arg.envVars).toEqual({
      SKRET_HUB_TOKEN: "hub-tok",
      SKRET_HUB_URL: "https://vault.example.com",
    });
    expect(arg.envVars).not.toHaveProperty("GITHUB_TOKEN");
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
      await worker.scheduled({} as ScheduledController, env);
      const runId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
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
