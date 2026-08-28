import { describe, expect, it, vi } from "vitest";
import {
  DurableExecutorOperationStore,
  SecurityExecutorOperations,
  ExecutorOperationInvalidRequestError,
  executorOperationFingerprint,
  type ExecutorOperationStorage,
  type ExecutorOperationTransaction,
  type ExecutorOperationRecord,
} from "../src/executor-operation-store";

const NOW = 1_700_000_000_000;
const DIGEST = (letter: string) => `sha256:${letter.repeat(64)}`;

async function digestBytes(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

function fakeStorage(): ExecutorOperationStorage & { values: Map<string, unknown>; alarms: number[] } {
  const values = new Map<string, unknown>();
  const alarms: number[] = [];
  let tail = Promise.resolve();
  const storage: ExecutorOperationStorage & { values: Map<string, unknown>; alarms: number[] } = {
    values,
    alarms,
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      values.set(key, value);
    },
    async delete(key: string): Promise<boolean> {
      return values.delete(key);
    },
    async transaction<T>(closure: (transaction: ExecutorOperationTransaction) => Promise<T>): Promise<T> {
      const previous = tail;
      let release!: () => void;
      tail = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;
      try {
        return await closure(storage);
      } finally {
        release();
      }
    },
  };
  return storage;
}

function startRequest(
  operationID: string,
  fingerprint = DIGEST("a"),
  invocationID = "invocation-1",
) {
  return {
    operation_id: operationID,
    schedule_digest: DIGEST("9"),
    exclusive: true,
    invocation_id: invocationID,
    fingerprint,
    generation: "g-001",
    source_digest: DIGEST("b"),
    target_digest: DIGEST("c"),
    config_digest: DIGEST("d"),
    deadline_at: NOW + 60_000,
  } as const;
}

describe("executor operation store", () => {
  it("fingerprints the complete operation input deterministically", async () => {
    const first = await executorOperationFingerprint({
      schedule_digest: DIGEST("9"),
      generation: "g-001",
      exclusive: true,
      source_digest: DIGEST("a"),
      target_digest: DIGEST("b"),
      config_digest: DIGEST("c"),
      image_digest: DIGEST("d"),
    });
    const second = await executorOperationFingerprint({
      schedule_digest: DIGEST("9"),
      generation: "g-001",
      source_digest: DIGEST("a"),
      exclusive: true,
      target_digest: DIGEST("b"),
      config_digest: DIGEST("c"),
      image_digest: DIGEST("d"),
    });
    expect(first).toBe(second);
    await expect(
      executorOperationFingerprint({
        schedule_digest: DIGEST("9"),
        generation: "g-001",
        source_digest: DIGEST("a"),
        exclusive: true,
        target_digest: DIGEST("b"),
        config_digest: DIGEST("c"),
        image_digest: DIGEST("e"),
      }),
    ).resolves.not.toBe(first);
  });

  it("coalesces the same operation and queues a different fingerprint", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage, async (timestamp) => {
      storage.alarms.push(timestamp);
    });
    const first = await store.begin(startRequest("op-1"), NOW);
    const same = await store.begin(startRequest("op-1"), NOW + 1);
    const queued = await store.begin(startRequest("op-2", DIGEST("e")), NOW + 2);

    expect(first.status).toBe("started");
    expect(same.status).toBe("coalesced");
    expect(queued.status).toBe("queued");
    expect((queued as { operation: ExecutorOperationRecord }).operation.status).toBe("queued");
  });
  it("promotes the oldest queued operation after terminal completion", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    await store.begin(startRequest("op-1"), NOW);
    await store.begin(startRequest("op-2", DIGEST("e")), NOW + 1);

    await store.complete("op-1", "invocation-1", "succeeded", DIGEST("f"), NOW + 2);

    await expect(storage.get<ExecutorOperationRecord>("private:executor-operation:op-2")).resolves.toMatchObject({
      status: "active",
      started_at: NOW + 2,
      active_invocation_id: null,
    });
    await expect(storage.get<string[]>("private:executor-operation:active")).resolves.toEqual(["op-2"]);

    const resumed = await store.begin(
      startRequest("op-2", DIGEST("e"), "invocation-2"),
      NOW + 3,
    );
    expect(resumed).toMatchObject({
      status: "started",
      operation: { active_invocation_id: "invocation-2" },
    });
  });

  it("runs unrelated schedule lanes concurrently", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    const first = await store.begin(startRequest("op-1"), NOW);
    const second = await store.begin(
      { ...startRequest("op-2"), schedule_digest: DIGEST("8") },
      NOW + 1,
    );

    expect(first.status).toBe("started");
    expect(second.status).toBe("started");
    await expect(storage.get<string[]>("private:executor-operation:active")).resolves.toEqual([
      "op-1",
      "op-2",
    ]);
  });

  it("runs value-free nonexclusive operations in the same schedule lane", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    const first = await store.begin({ ...startRequest("op-1"), exclusive: false }, NOW);
    const second = await store.begin(
      { ...startRequest("op-2"), exclusive: false },
      NOW + 1,
    );

    expect(first.status).toBe("started");
    expect(second.status).toBe("started");
    await expect(storage.get<string[]>("private:executor-operation:active")).resolves.toEqual([
      "op-1",
      "op-2",
    ]);
  });

  it("rejects an operation id reused with a different fingerprint", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    await store.begin(startRequest("op-1"), NOW);
    await expect(store.begin(startRequest("op-1", DIGEST("e")), NOW + 1)).resolves.toEqual({
      status: "conflict",
    });
  });

  it("rejects a terminal transition from a foreign invocation", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    await store.begin(startRequest("op-1"), NOW);

    await expect(
      store.complete("op-1", "invocation-2", "succeeded", DIGEST("f"), NOW + 1),
    ).rejects.toThrow("executor invocation mismatch");
    await expect(storage.get<ExecutorOperationRecord>("private:executor-operation:op-1")).resolves.toMatchObject({
      status: "active",
      active_invocation_id: "invocation-1",
    });
  });

  it("does not roll back committed state when alarm scheduling fails", async () => {
    const storage = fakeStorage();
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const store = new DurableExecutorOperationStore(storage, async () => {
        throw new Error("alarm unavailable");
      });

      await expect(store.begin(startRequest("op-1"), NOW)).resolves.toMatchObject({
        status: "started",
      });
      await expect(storage.get<ExecutorOperationRecord>("private:executor-operation:op-1")).resolves.toMatchObject({
        status: "active",
      });
    } finally {
      consoleError.mockRestore();
    }
  });

  it("records an invocation timeout without losing the later immutable terminal outcome", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    await store.begin(startRequest("op-1"), NOW);
    const timedOut = await store.recordInvocationTimeout(
      "op-1",
      "invocation-1",
      NOW + 60_000,
    );
    const finished = await store.complete(
      "op-1",
      "invocation-1",
      "succeeded",
      DIGEST("f"),
      NOW + 61_000,
    );

    expect(timedOut.status).toBe("timed_out");
    expect(finished.status).toBe("succeeded");
    expect(finished.timeout_at).toBe(NOW + 60_000);
    expect(finished.alert).toBe("invocation_timeout");
    expect([...storage.values.keys()]).toContain("private:executor-invocation:op-1:invocation-1");
  });

  it("persists a value-free result for a fresh-envelope re-ack", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    const result = new TextEncoder().encode(
      JSON.stringify({ operation_id: "op-1", status: "accepted" }),
    );
    const resultDigest = await digestBytes(result);
    await store.begin(startRequest("op-1"), NOW);
    await store.complete(
      "op-1",
      "invocation-1",
      "succeeded",
      resultDigest,
      NOW + 1,
      result,
    );

    const retry = await store.begin(
      startRequest("op-1", DIGEST("a"), "invocation-2"),
      NOW + 2,
    );
    expect(retry).toMatchObject({
      status: "existing",
      operation: { status: "succeeded" },
    });
    await expect(store.readResult("op-1")).resolves.toEqual(result);
  });

  it("watchdog marks deadline timeout and later terminalizes after the bounded lifetime", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    await store.begin(startRequest("op-1"), NOW);

    const timedOut = await store.watchdog(NOW + 60_000);
    const stillPending = await store.watchdog(NOW + 60_001);
    const activeAfterPending = await storage.get<string[]>("private:executor-operation:active");

    const reconciled = await store.watchdog(NOW + 60_000 + 15 * 60_000);

    expect(timedOut.marked_timeout).toEqual(["op-1"]);
    expect(timedOut.next_alarm_at).toBe(NOW + 60_000 + 15 * 60_000);
    expect(stillPending.terminalized).toEqual([]);
    expect(activeAfterPending).toEqual(["op-1"]);
    expect(reconciled.terminalized).toEqual(["op-1"]);
    await expect(storage.get<ExecutorOperationRecord>("private:executor-operation:op-1")).resolves.toMatchObject({
      status: "needs_reconciliation",
      alert: "watchdog_deadline",
      active_invocation_id: null,
    });
  });
  it("reschedules the Durable Object alarm after a watchdog transaction failure", async () => {
    const setAlarm = vi.fn(async () => undefined);
    const operations = Object.create(
      SecurityExecutorOperations.prototype,
    ) as SecurityExecutorOperations;
    Object.defineProperty(operations, "ctx", {
      value: { storage: { setAlarm } },
    });
    operations.watchdog = vi.fn(async () => {
      throw new Error("transaction unavailable");
    });

    await expect(operations.alarm()).rejects.toThrow("transaction unavailable");

    expect(setAlarm).toHaveBeenCalledTimes(1);
    expect(setAlarm).toHaveBeenCalledWith(expect.any(Number));
  });

  it("rejects malformed deadlines and digests before durable writes", async () => {
    const storage = fakeStorage();
    const store = new DurableExecutorOperationStore(storage);
    await expect(store.begin({ ...startRequest("op-1"), deadline_at: NOW }, NOW)).rejects.toBeInstanceOf(
      ExecutorOperationInvalidRequestError,
    );
    expect(storage.values.size).toBe(0);
  });
});
