const SHA256_HEX_LENGTH = 64;
const SHA256_DIGEST_PATTERN = new RegExp(`^sha256:[a-f0-9]{${SHA256_HEX_LENGTH}}$`, "u");
const MAX_SCOPE_FIELD_LENGTH = 256;
const MAX_SWEEP_LIMIT = 1_000;

/**
 * Private key namespace for replay authority. This module is executor-only
 * source; the ordinary Hub router intentionally has no call path to it.
 */
export const EXECUTOR_REPLAY_PREFIX = "private:executor-replay:";
const EXECUTOR_REPLAY_KEY_PATTERN = new RegExp(
  `^${EXECUTOR_REPLAY_PREFIX}[a-f0-9]{${SHA256_HEX_LENGTH}}$`,
  "u",
);
export const DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT = 100;

const INVALID_REPLAY_REQUEST = "invalid replay request";
const REPLAY_REJECTED = "replay rejected";
const REPLAY_STORE_UNAVAILABLE = "replay store unavailable";

/** The value-free scope in which one nonce can be consumed exactly once. */
export interface ExecutorReplayScope {
  readonly audience: string;
  readonly role: string;
  readonly nonce: string;
}

interface ExecutorReplayRecord {
  readonly digest: string;
  readonly expiresAt: number;
}
export interface ExecutorReplaySweepResult {
  readonly removed: number;
  readonly nextAfter: string | null;
}

type ReplaySweepListOptions = {
  prefix: string;
  limit: number;
  startAfter?: string;
};
type ReplayStorage = Pick<DurableObjectStorage, "transaction">;

export class ExecutorReplayInvalidRequestError extends Error {
  constructor() {
    super(INVALID_REPLAY_REQUEST);
    this.name = "ExecutorReplayInvalidRequestError";
  }
}

export class ExecutorReplayRejectedError extends Error {
  constructor() {
    super(REPLAY_REJECTED);
    this.name = "ExecutorReplayRejectedError";
  }
}

export class ExecutorReplayStoreUnavailableError extends Error {
  constructor() {
    super(REPLAY_STORE_UNAVAILABLE);
    this.name = "ExecutorReplayStoreUnavailableError";
  }
}

/**
 * Derive the private replay key from a length-stable canonical scope. Scope
 * values never appear in the returned key or in persisted storage metadata.
 */
export async function executorReplayKey(scope: ExecutorReplayScope): Promise<string> {
  validateScope(scope);
  const canonicalScope = JSON.stringify([scope.audience, scope.role, scope.nonce]);
  const digest = await sha256Hex(new TextEncoder().encode(canonicalScope));
  return `${EXECUTOR_REPLAY_PREFIX}${digest}`;
}

/**
 * Durable executor-side replay authority. It is deliberately unreferenced by
 * the ordinary Hub router and only persists a digest plus expiry metadata.
 */
export class DurableExecutorReplayStore {
  constructor(private readonly storage: ReplayStorage) {}

  /**
   * Atomically consume a scope. An unexpired existing row rejects regardless
   * of its digest; an expired row is removed before the replacement is put.
   */
  async consume(
    scope: ExecutorReplayScope,
    digest: string,
    expiresAt: number,
    now = Date.now(),
  ): Promise<void> {
    validateScope(scope);
    validateDigest(digest);
    validateExpiry(expiresAt, now);

    let key: string;
    try {
      key = await executorReplayKey(scope);
    } catch {
      throw new ExecutorReplayStoreUnavailableError();
    }

    let accepted: boolean;
    try {
      accepted = await this.storage.transaction(async (transaction) => {
        const current = await transaction.get<ExecutorReplayRecord>(key);
        if (current && current.expiresAt > now) return false;
        if (current) await transaction.delete(key);
        await transaction.put(key, { digest, expiresAt } satisfies ExecutorReplayRecord);
        return true;
      });
    } catch {
      throw new ExecutorReplayStoreUnavailableError();
    }

    if (!accepted) throw new ExecutorReplayRejectedError();
  }

  /**
   * Delete at most `limit` expired rows under the private prefix in one
   * transaction. A returned cursor resumes after the last inspected key, so
   * live rows cannot starve expired rows that sort later in the prefix.
   */
  async sweep(
    now = Date.now(),
    limit = DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT,
    startAfter?: string | null,
  ): Promise<ExecutorReplaySweepResult> {
    validateNow(now);
    validateSweepLimit(limit);
    validateSweepCursor(startAfter);

    try {
      return await this.storage.transaction(async (transaction) => {
        const listOptions: ReplaySweepListOptions = {
          prefix: EXECUTOR_REPLAY_PREFIX,
          limit,
        };
        if (startAfter !== undefined && startAfter !== null) {
          listOptions.startAfter = startAfter;
        }
        const rows = await transaction.list<ExecutorReplayRecord>(listOptions);
        let removed = 0;
        let inspected = 0;
        let lastInspectedKey: string | null = null;
        for (const [key, record] of rows) {
          if (inspected >= limit) break;
          inspected += 1;
          lastInspectedKey = key;
          if (record && Number.isFinite(record.expiresAt) && record.expiresAt <= now) {
            if (await transaction.delete(key)) removed += 1;
          }
        }
        return {
          removed,
          nextAfter: rows.size >= limit ? lastInspectedKey : null,
        };
      });
    } catch {
      throw new ExecutorReplayStoreUnavailableError();
    }
  }
}

function validateScope(scope: ExecutorReplayScope): void {
  if (!scope || typeof scope !== "object") throw new ExecutorReplayInvalidRequestError();
  validateScopeField(scope.audience);
  validateScopeField(scope.role);
  validateScopeField(scope.nonce);
}

function validateScopeField(value: unknown): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_SCOPE_FIELD_LENGTH ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new ExecutorReplayInvalidRequestError();
  }
}

function validateDigest(digest: unknown): void {
  if (typeof digest !== "string" || !SHA256_DIGEST_PATTERN.test(digest)) {
    throw new ExecutorReplayInvalidRequestError();
  }
}

function validateExpiry(expiresAt: number, now: number): void {
  validateNow(now);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    throw new ExecutorReplayInvalidRequestError();
  }
}

function validateNow(now: number): void {
  if (!Number.isFinite(now) || now < 0) throw new ExecutorReplayInvalidRequestError();
}

function validateSweepLimit(limit: number): void {
  if (!Number.isSafeInteger(limit) || limit <= 0 || limit > MAX_SWEEP_LIMIT) {
    throw new ExecutorReplayInvalidRequestError();
  }
}

function validateSweepCursor(startAfter: unknown): void {
  if (
    startAfter !== undefined &&
    startAfter !== null &&
    (typeof startAfter !== "string" || !EXECUTOR_REPLAY_KEY_PATTERN.test(startAfter))
  ) {
    throw new ExecutorReplayInvalidRequestError();
  }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}


