import { describe, expect, it } from "vitest";
import {
  DurableExecutorReplayStore,
  EXECUTOR_REPLAY_PREFIX,
  executorReplayKey,
  type ExecutorReplayScope,
} from "../src/executor-replay-store";

const NOW = 1_000;
const FUTURE = 2_000;
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;

const SCOPE: ExecutorReplayScope = {
  audience: "hub-executor",
  role: "operator",
  nonce: "nonce-001",
};

type ReplayValue = { digest: string; expiresAt: number };
type ReplayTransaction = {
  get<T>(key: string): Promise<T | undefined>;
  list<T>(options?: { prefix?: string; limit?: number; startAfter?: string }): Promise<Map<string, T>>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
};

class FakeDurableStorage {
  readonly values = new Map<string, unknown>();
  readonly transactionOptions: Array<{ prefix?: string; limit?: number; startAfter?: string }> = [];
  failNextTransactionWith?: Error;
  private transactionTail = Promise.resolve();

  async transaction<T>(closure: (transaction: ReplayTransaction) => Promise<T>): Promise<T> {
    const previous = this.transactionTail;
    let release!: () => void;
    this.transactionTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      if (this.failNextTransactionWith) {
        const error = this.failNextTransactionWith;
        this.failNextTransactionWith = undefined;
        throw error;
      }
      const transaction: ReplayTransaction = {
        get: async <V>(key: string) => this.values.get(key) as V | undefined,
        list: async <V>(options: { prefix?: string; limit?: number; startAfter?: string } = {}) => {
          this.transactionOptions.push(options);
          const entries = [...this.values.entries()]
            .filter(([key]) => !options.prefix || key.startsWith(options.prefix))
            .filter(([key]) => !options.startAfter || key > options.startAfter)
            .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
            .slice(0, options.limit ?? Number.POSITIVE_INFINITY)
            .map(([key, value]) => [key, value] as [string, V]);
          return new Map(entries);
        },
        put: async <V>(key: string, value: V) => {
          this.values.set(key, value);
        },
        delete: async (key: string) => this.values.delete(key),
      };
      return await closure(transaction);
    } finally {
      release();
    }
  }
}

function storeFor(storage: FakeDurableStorage): DurableExecutorReplayStore {
  return new DurableExecutorReplayStore(storage as unknown as DurableObjectStorage);
}

function seed(storage: FakeDurableStorage, scope: ExecutorReplayScope, value: ReplayValue): Promise<void> {
  return executorReplayKey(scope).then((key) => {
    storage.values.set(key, value);
  });
}

describe("DurableExecutorReplayStore", () => {
  it("accepts the first scope and rejects its replay", async () => {
    const storage = new FakeDurableStorage();
    const store = storeFor(storage);

    const key = await executorReplayKey(SCOPE);

    await expect(store.consume(SCOPE, DIGEST_A, FUTURE, NOW)).resolves.toBeUndefined();
    expect(storage.values.get(key)).toEqual({ digest: DIGEST_A, expiresAt: FUTURE });
    await expect(store.consume(SCOPE, DIGEST_A, FUTURE, NOW)).rejects.toThrow("replay rejected");
  });

  it("rejects a changed digest for an already consumed scope", async () => {
    const storage = new FakeDurableStorage();
    const store = storeFor(storage);

    await store.consume(SCOPE, DIGEST_A, FUTURE, NOW);

    await expect(store.consume(SCOPE, DIGEST_B, FUTURE, NOW)).rejects.toThrow("replay rejected");
  });

  it("replaces an expired row inside the same transaction", async () => {
    const storage = new FakeDurableStorage();
    const store = storeFor(storage);
    const key = await executorReplayKey(SCOPE);

    await store.consume(SCOPE, DIGEST_A, NOW + 10, NOW);
    await store.consume(SCOPE, DIGEST_B, NOW + 100, NOW + 10);

    expect(storage.values.get(key)).toEqual({ digest: DIGEST_B, expiresAt: NOW + 100 });
  });

  it("rejects invalid scope, digest, and expiry without exposing values", async () => {
    const invalidCases: Array<[string, ExecutorReplayScope, string, number, number]> = [
      ["blank audience", { ...SCOPE, audience: " " }, DIGEST_A, FUTURE, NOW],
      ["blank role", { ...SCOPE, role: "" }, DIGEST_A, FUTURE, NOW],
      ["blank nonce", { ...SCOPE, nonce: "\n" }, DIGEST_A, FUTURE, NOW],
      ["invalid digest", SCOPE, "private-body-digest", FUTURE, NOW],
      ["expired", SCOPE, DIGEST_A, NOW, NOW],
      ["non-finite expiry", SCOPE, DIGEST_A, Number.NaN, NOW],
    ];

    for (const [name, scope, digest, expiresAt, now] of invalidCases) {
      const storage = new FakeDurableStorage();
      const store = storeFor(storage);
      let error: Error;
      try {
        await store.consume(scope, digest, expiresAt, now);
        throw new Error("expected replay request rejection");
      } catch (caught) {
        if (!(caught instanceof Error)) throw new Error("expected an Error rejection");
        error = caught;
      }

      expect(error, name).toBeInstanceOf(Error);
      expect(error.message, name).toBe("invalid replay request");
      expect(error.message, name).not.toContain("private-body-digest");
      expect(storage.values.size, name).toBe(0);
    }
  });

  it("masks transaction failures with a value-free unavailable error", async () => {
    const storage = new FakeDurableStorage();
    storage.failNextTransactionWith = new Error("storage exploded with private-body-digest");
    const store = storeFor(storage);

    let error: Error;
    try {
      await store.consume(SCOPE, DIGEST_A, FUTURE, NOW);
      throw new Error("expected transaction failure");
    } catch (caught) {
      if (!(caught instanceof Error)) throw new Error("expected an Error rejection");
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe("replay store unavailable");
    expect(error.message).not.toContain("private-body-digest");
  });

  it("derives a deterministic private key without embedding scope values", async () => {
    const key = await executorReplayKey(SCOPE);
    const sameKey = await executorReplayKey({ ...SCOPE });
    const differentKey = await executorReplayKey({ ...SCOPE, nonce: "nonce-002" });

    expect(key).toBe(sameKey);
    expect(key).not.toBe(differentKey);
    expect(key).toMatch(new RegExp(`^${EXECUTOR_REPLAY_PREFIX}[a-f0-9]{64}$`));
    expect(key).not.toContain(SCOPE.audience);
    expect(key).not.toContain(SCOPE.role);
    expect(key).not.toContain(SCOPE.nonce);
  });

  it("sweeps only a bounded batch of expired rows transactionally", async () => {
    const storage = new FakeDurableStorage();
    const store = storeFor(storage);
    const expiredKeyA = `${EXECUTOR_REPLAY_PREFIX}${"1".repeat(64)}`;
    const expiredKeyB = `${EXECUTOR_REPLAY_PREFIX}${"2".repeat(64)}`;
    const liveKey = `${EXECUTOR_REPLAY_PREFIX}${"3".repeat(64)}`;

    storage.values.set(expiredKeyA, { digest: DIGEST_A, expiresAt: NOW - 2 });
    storage.values.set(expiredKeyB, { digest: DIGEST_A, expiresAt: NOW - 1 });
    storage.values.set(liveKey, { digest: DIGEST_A, expiresAt: FUTURE });

    const result = await store.sweep(NOW, 2);

    expect(result).toEqual({ removed: 2, nextAfter: expiredKeyB });
    expect(storage.transactionOptions).toContainEqual({ prefix: EXECUTOR_REPLAY_PREFIX, limit: 2 });
    expect(storage.values.size).toBe(1);
    expect(storage.values.has(liveKey)).toBe(true);
  });
  it("resumes a bounded sweep after live rows before an expired row", async () => {
    const storage = new FakeDurableStorage();
    const store = storeFor(storage);
    const liveKey = `${EXECUTOR_REPLAY_PREFIX}${"0".repeat(64)}`;
    const expiredKey = `${EXECUTOR_REPLAY_PREFIX}${"f".repeat(64)}`;

    storage.values.set(liveKey, { digest: DIGEST_A, expiresAt: FUTURE });
    storage.values.set(expiredKey, { digest: DIGEST_A, expiresAt: NOW - 1 });

    const first = await store.sweep(NOW, 1);
    expect(first).toEqual({ removed: 0, nextAfter: liveKey });

    const second = await store.sweep(NOW, 1, first.nextAfter);
    expect(second).toEqual({ removed: 1, nextAfter: expiredKey });

    const third = await store.sweep(NOW, 1, second.nextAfter);
    expect(third).toEqual({ removed: 0, nextAfter: null });
    expect(storage.values.has(liveKey)).toBe(true);
    expect(storage.values.has(expiredKey)).toBe(false);
    expect(storage.transactionOptions).toEqual([
      { prefix: EXECUTOR_REPLAY_PREFIX, limit: 1 },
      { prefix: EXECUTOR_REPLAY_PREFIX, limit: 1, startAfter: liveKey },
      { prefix: EXECUTOR_REPLAY_PREFIX, limit: 1, startAfter: expiredKey },
    ]);
  });
  it("rejects malformed sweep cursors before touching storage", async () => {
    const storage = new FakeDurableStorage();
    const store = storeFor(storage);
    const invalidCursors = [
      `${EXECUTOR_REPLAY_PREFIX}not-a-digest`,
      `${EXECUTOR_REPLAY_PREFIX}${"A".repeat(64)}`,
      `${EXECUTOR_REPLAY_PREFIX}${"a".repeat(63)}`,
      `private:other:${"a".repeat(64)}`,
    ];

    for (const cursor of invalidCursors) {
      await expect(store.sweep(NOW, 1, cursor)).rejects.toThrow("invalid replay request");
    }
    expect(storage.transactionOptions.length).toBe(0);
  });

  it("allows exactly one winner when identical consumes race", async () => {
    const storage = new FakeDurableStorage();
    const store = storeFor(storage);

    const results = await Promise.allSettled(
      Array.from({ length: 12 }, () => store.consume(SCOPE, DIGEST_A, FUTURE, NOW)),
    );

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(11);
    expect(
      results
        .filter((result): result is PromiseRejectedResult => result.status === "rejected")
        .every((result) => result.reason instanceof Error && result.reason.message === "replay rejected"),
    ).toBe(true);
  });
});
