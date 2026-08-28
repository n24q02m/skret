import { DurableObject } from "cloudflare:workers";
import {
  DurableProviderOperationStore,
  type ProviderControlDecision,
  type ProviderDispatchRequest,
  type ProviderDispatchResponse,
  type ProviderLastSuccess,
  type ProviderOperationRecord,
  type ProviderOperationStart,
  type ProviderOperationStartResult,
  type ProviderVerification,
  type ProviderInvocationOutcome,
} from "./provider-operation-store";

const OPERATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const GENERATION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const CONFIG_HEX_PATTERN = /^[0-9a-fA-F]+$/u;
const OPERATION_PREFIX = "private:executor-operation:";
const INVOCATION_PREFIX = "private:executor-invocation:";
const RESULT_PREFIX = "private:executor-operation-result:";
const LANE_PREFIX = "private:executor-operation-lane:";
const ACTIVE_OPERATION_KEY = `${OPERATION_PREFIX}active`;
const MAX_ACTIVE_OPERATIONS = 256;
const WATCHDOG_INTERVAL_MS = 60_000;
const MAX_OPERATION_LIFETIME_MS = 15 * 60_000;
const MAX_OPERATION_RESULT_BYTES = 1 << 20;

export const EXECUTOR_OPERATION_OBJECT_NAME = "security-executor-operations";
export const EXECUTOR_OPERATION_BINDING = "EXECUTOR_OPERATIONS";

export interface SecurityExecutorOperationEnv {
  readonly EXECUTOR_PROVIDER_CONTROL_PUBLIC_KEY?: string;
}

export type ExecutorOperationStatus =
  | "active"
  | "queued"
  | "timed_out"
  | "succeeded"
  | "failed"
  | "needs_reconciliation"
  | "cancel_requested"
  | "cancel_needs_reconciliation";

export interface ExecutorOperationStart {
  readonly operation_id: string;
  readonly schedule_digest: string;
  readonly exclusive: boolean;
  readonly invocation_id: string;
  readonly fingerprint: string;
  readonly generation: string;
  readonly source_digest: string;
  readonly target_digest: string;
  readonly config_digest: string;
  readonly deadline_at: number;
}

export interface ExecutorOperationRecord extends ExecutorOperationStart {
  readonly status: ExecutorOperationStatus;
  readonly created_at: number;
  readonly started_at: number | null;
  readonly completed_at: number | null;
  readonly timeout_at: number | null;
  readonly alert: "invocation_timeout" | "watchdog_deadline" | null;
  readonly attempts: number;
  readonly active_invocation_id: string | null;
}

export interface ExecutorInvocationOutcome {
  readonly invocation_id: string;
  readonly operation_id: string;
  readonly status: "timed_out" | "succeeded" | "failed";
  readonly observed_at: number;
  readonly result_digest: string | null;
}

interface ExecutorRedactedResult {
  readonly digest: string;
  readonly bytes: Uint8Array;
}

export type ExecutorOperationStartResult =
  | { readonly status: "started"; readonly operation: ExecutorOperationRecord }
  | { readonly status: "coalesced"; readonly operation: ExecutorOperationRecord }
  | { readonly status: "queued"; readonly operation: ExecutorOperationRecord }
  | { readonly status: "existing"; readonly operation: ExecutorOperationRecord }
  | { readonly status: "conflict" };

export interface ExecutorOperationWatchdogResult {
  readonly marked_timeout: readonly string[];
  readonly terminalized: readonly string[];
  readonly next_alarm_at: number | null;
}

export interface ExecutorOperationTransaction {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

export interface ExecutorOperationStorage extends ExecutorOperationTransaction {
  transaction<T>(closure: (transaction: ExecutorOperationTransaction) => Promise<T>): Promise<T>;
}
export interface ExecutorOperationStore {
  begin(request: ExecutorOperationStart, now?: number): Promise<ExecutorOperationStartResult>;
  recordInvocationTimeout(operationID: string, invocationID: string, now?: number): Promise<ExecutorOperationRecord>;
  complete(
    operationID: string,
    invocationID: string,
    status: "succeeded" | "failed",
    resultDigest: string | null,
    now?: number,
    redactedResult?: Uint8Array,
  ): Promise<ExecutorOperationRecord>;
  readResult(operationID: string): Promise<Uint8Array | null>;
  requestCancel(operationID: string, now?: number): Promise<ExecutorOperationRecord>;
  watchdog(now?: number): Promise<ExecutorOperationWatchdogResult>;
}

export class ExecutorOperationInvalidRequestError extends Error {
  constructor(message = "invalid executor operation") {
    super(message);
    this.name = "ExecutorOperationInvalidRequestError";
  }
}

export class ExecutorOperationUnavailableError extends Error {
  constructor() {
    super("executor operation store unavailable");
    this.name = "ExecutorOperationUnavailableError";
  }
}

export class DurableExecutorOperationStore implements ExecutorOperationStore {
  constructor(
    private readonly storage: ExecutorOperationStorage,
    private readonly scheduleAlarm?: (timestamp: number) => Promise<void>,
  ) {}

  async begin(request: ExecutorOperationStart, now = Date.now()): Promise<ExecutorOperationStartResult> {
    validateStart(request, now);
    const result = await this.storage.transaction(async (transaction) => {
      const key = operationKey(request.operation_id);
      const existing = await transaction.get<ExecutorOperationRecord>(key);
      if (existing) {
        if (
          existing.fingerprint !== request.fingerprint ||
          existing.schedule_digest !== request.schedule_digest ||
          existing.exclusive !== request.exclusive
        ) {
          return { status: "conflict" } as const;
        }
        if (existing.status === "active" || existing.status === "timed_out") {
          if (existing.active_invocation_id === request.invocation_id) {
            return { status: "coalesced", operation: existing } as const;
          }
          if (existing.active_invocation_id === null) {
            const active = await readActiveOperations(transaction);
            const resumed: ExecutorOperationRecord = {
              ...existing,
              status: "active",
              started_at: existing.started_at ?? now,
              active_invocation_id: request.invocation_id,
              attempts: existing.attempts + 1,
            };
            await transaction.put(key, resumed);
            if (existing.exclusive) {
              await transaction.put(laneActiveKey(existing.schedule_digest), existing.operation_id);
            }
            if (!active.includes(existing.operation_id)) {
              active.push(existing.operation_id);
              await transaction.put(ACTIVE_OPERATION_KEY, active);
            }
            return { status: "started", operation: resumed } as const;
          }
          return { status: "existing", operation: existing } as const;
        }
        return { status: "existing", operation: existing } as const;
      }

      const active = await readActiveOperations(transaction);
      const queued = (await transaction.get<string[]>(`${OPERATION_PREFIX}queue`)) ?? [];
      if (active.length + queued.length >= MAX_ACTIVE_OPERATIONS) {
        throw new ExecutorOperationUnavailableError();
      }
      const laneKey = laneActiveKey(request.schedule_digest);
      let laneOperationID: string | undefined;
      if (request.exclusive) {
        laneOperationID = await transaction.get<string>(laneKey);
        if (laneOperationID) {
          const laneOperation = await transaction.get<ExecutorOperationRecord>(
            operationKey(laneOperationID),
          );
          if (!laneOperation || !holdsExecutionLane(laneOperation.status)) {
            await transaction.delete(laneKey);
            laneOperationID = undefined;
          }
        }
      }
      const startsImmediately = !request.exclusive || laneOperationID === undefined;
      const operation: ExecutorOperationRecord = {
        ...request,
        status: startsImmediately ? "active" : "queued",
        created_at: now,
        started_at: startsImmediately ? now : null,
        completed_at: null,
        timeout_at: null,
        alert: null,
        attempts: 0,
        active_invocation_id: startsImmediately ? request.invocation_id : null,
      };
      await transaction.put(key, operation);
      if (operation.status === "active") {
        active.push(operation.operation_id);
        await transaction.put(ACTIVE_OPERATION_KEY, active);
        if (operation.exclusive) {
          await transaction.put(laneKey, operation.operation_id);
        }
        return { status: "started", operation } as const;
      }
      queued.push(operation.operation_id);
      await transaction.put(`${OPERATION_PREFIX}queue`, queued);
      return { status: "queued", operation } as const;
    });
    await this.scheduleNextAlarm(now);
    return result;
  }

  async recordInvocationTimeout(
    operationID: string,
    invocationID: string,
    now = Date.now(),
  ): Promise<ExecutorOperationRecord> {
    validateOperationID(operationID);
    validateInvocationID(invocationID);
    const operation = await this.storage.transaction(async (transaction) => {
      const key = operationKey(operationID);
      const current = await transaction.get<ExecutorOperationRecord>(key);
      if (!current) throw new ExecutorOperationInvalidRequestError("unknown executor operation");
      await writeInvocationOutcome(transaction, {
        invocation_id: invocationID,
        operation_id: operationID,
        status: "timed_out",
        observed_at: now,
        result_digest: null,
      });
      if (
        current.status !== "active" ||
        current.active_invocation_id !== invocationID
      ) {
        return current;
      }
      const timedOut: ExecutorOperationRecord = {
        ...current,
        status: "timed_out",
        timeout_at: current.timeout_at ?? now,
        alert: current.alert ?? "invocation_timeout",
        attempts: current.attempts + 1,
      };
      await transaction.put(key, timedOut);
      return timedOut;
    });
    await this.scheduleNextAlarm(now);
    return operation;
  }

  async complete(
    operationID: string,
    invocationID: string,
    status: "succeeded" | "failed",
    resultDigest: string | null,
    now = Date.now(),
    redactedResult?: Uint8Array,
  ): Promise<ExecutorOperationRecord> {
    validateOperationID(operationID);
    validateInvocationID(invocationID);
    if (resultDigest !== null) validateDigest(resultDigest);
    let resultCopy: Uint8Array | undefined;
    if (redactedResult !== undefined) {
      if (
        status !== "succeeded" ||
        resultDigest === null ||
        !(redactedResult instanceof Uint8Array) ||
        redactedResult.byteLength === 0 ||
        redactedResult.byteLength > MAX_OPERATION_RESULT_BYTES
      ) {
        throw new ExecutorOperationInvalidRequestError("invalid redacted executor result");
      }
      resultCopy = redactedResult.slice();
      if ((await digestBytes(resultCopy)) !== resultDigest) {
        throw new ExecutorOperationInvalidRequestError("executor result digest mismatch");
      }
    }

    const result = await this.storage.transaction(async (transaction) => {
      const key = operationKey(operationID);
      const current = await transaction.get<ExecutorOperationRecord>(key);
      if (!current) throw new ExecutorOperationInvalidRequestError("unknown executor operation");
      if (
        current.status === "succeeded" ||
        current.status === "failed" ||
        current.status === "needs_reconciliation"
      ) {
        return current;
      }
      if (
        current.active_invocation_id !== invocationID ||
        (current.status !== "active" &&
          current.status !== "timed_out" &&
          current.status !== "cancel_requested")
      ) {
        throw new ExecutorOperationInvalidRequestError("executor invocation mismatch");
      }
      await writeInvocationOutcome(transaction, {
        invocation_id: invocationID,
        operation_id: operationID,
        status,
        observed_at: now,
        result_digest: resultDigest,
      });
      if (resultCopy !== undefined && resultDigest !== null) {
        await transaction.put(resultKey(operationID), {
          digest: resultDigest,
          bytes: resultCopy,
        } satisfies ExecutorRedactedResult);
      }
      const finished: ExecutorOperationRecord = {
        ...current,
        status,
        completed_at: now,
        active_invocation_id: null,
      };
      await transaction.put(key, finished);
      const active = await readActiveOperations(transaction);
      const remaining = active.filter((id) => id !== operationID);
      if (current.exclusive) {
        const laneKey = laneActiveKey(current.schedule_digest);
        if ((await transaction.get<string>(laneKey)) === operationID) {
          await transaction.delete(laneKey);
        }
        const queued = await this.promoteNextQueued(
          transaction,
          remaining,
          now,
          current.schedule_digest,
        );
        if (queued) {
          remaining.push(queued.operation_id);
          await transaction.put(laneKey, queued.operation_id);
        }
      }
      await transaction.put(ACTIVE_OPERATION_KEY, remaining);
      return finished;
    });
    await this.scheduleNextAlarm(now);
    return result;
  }

  async readResult(operationID: string): Promise<Uint8Array | null> {
    validateOperationID(operationID);
    return this.storage.transaction(async (transaction) => {
      const operation = await transaction.get<ExecutorOperationRecord>(operationKey(operationID));
      const result = await transaction.get<ExecutorRedactedResult>(resultKey(operationID));
      if (
        operation?.status !== "succeeded" ||
        !result ||
        !DIGEST_PATTERN.test(result.digest) ||
        !(result.bytes instanceof Uint8Array) ||
        result.bytes.byteLength === 0 ||
        result.bytes.byteLength > MAX_OPERATION_RESULT_BYTES
      ) {
        return null;
      }
      if ((await digestBytes(result.bytes)) !== result.digest) {
        throw new ExecutorOperationUnavailableError();
      }
      return result.bytes.slice();
    });
  }

  async requestCancel(operationID: string, now = Date.now()): Promise<ExecutorOperationRecord> {
    validateOperationID(operationID);
    const result = await this.storage.transaction(async (transaction) => {
      const key = operationKey(operationID);
      const current = await transaction.get<ExecutorOperationRecord>(key);
      if (!current) throw new ExecutorOperationInvalidRequestError("unknown executor operation");
      if (current.status !== "active" && current.status !== "timed_out") return current;
      const requested: ExecutorOperationRecord = {
        ...current,
        status: "cancel_requested",
        alert: current.alert ?? "watchdog_deadline",
        timeout_at: current.timeout_at ?? now,
      };
      await transaction.put(key, requested);
      return requested;
    });
    await this.scheduleNextAlarm(now);
    return result;
  }

  async watchdog(now = Date.now()): Promise<ExecutorOperationWatchdogResult> {
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new ExecutorOperationInvalidRequestError("invalid watchdog time");
    }
    const result = await this.storage.transaction(async (transaction) => {
      const active = await readActiveOperations(transaction);
      const markedTimeout: string[] = [];
      const terminalized: string[] = [];
      const terminalRecords: ExecutorOperationRecord[] = [];
      const remaining: string[] = [];
      let nextAlarm: number | null = null;
      for (const operationID of active) {
        const key = operationKey(operationID);
        const operation = await transaction.get<ExecutorOperationRecord>(key);
        if (
          !operation ||
          (operation.status !== "active" &&
            operation.status !== "timed_out" &&
            operation.status !== "cancel_requested")
        ) {
          continue;
        }

        const terminalDeadline = operation.deadline_at + MAX_OPERATION_LIFETIME_MS;
        if (operation.status === "active" && now >= operation.deadline_at) {
          const timedOut: ExecutorOperationRecord = {
            ...operation,
            status: "timed_out",
            timeout_at: operation.timeout_at ?? now,
            alert: operation.alert ?? "watchdog_deadline",
            attempts: operation.attempts + 1,
          };
          await transaction.put(key, timedOut);
          markedTimeout.push(operationID);
          remaining.push(operationID);
          nextAlarm = earlierAlarm(nextAlarm, terminalDeadline);
          continue;
        }

        if (
          (operation.status === "timed_out" || operation.status === "cancel_requested") &&
          now >= terminalDeadline
        ) {
          const reconciled: ExecutorOperationRecord = {
            ...operation,
            status: "needs_reconciliation",
            alert: operation.alert ?? "watchdog_deadline",
            timeout_at: operation.timeout_at ?? now,
            completed_at: now,
            active_invocation_id: null,
          };
          await transaction.put(key, reconciled);
          terminalized.push(operationID);
          terminalRecords.push(reconciled);
          continue;
        }

        remaining.push(operationID);
        nextAlarm = earlierAlarm(
          nextAlarm,
          operation.status === "active" ? operation.deadline_at : terminalDeadline,
        );
      }

      for (const terminalRecord of terminalRecords) {
        if (!terminalRecord.exclusive) continue;
        const laneKey = laneActiveKey(terminalRecord.schedule_digest);
        if ((await transaction.get<string>(laneKey)) === terminalRecord.operation_id) {
          await transaction.delete(laneKey);
        }
        const promoted = await this.promoteNextQueued(
          transaction,
          remaining,
          now,
          terminalRecord.schedule_digest,
        );
        if (!promoted) continue;
        remaining.push(promoted.operation_id);
        await transaction.put(laneKey, promoted.operation_id);
        nextAlarm = earlierAlarm(nextAlarm, promoted.deadline_at);
      }
      await transaction.put(ACTIVE_OPERATION_KEY, remaining);
      return {
        marked_timeout: markedTimeout,
        terminalized,
        next_alarm_at: nextAlarm === null ? null : Math.max(now + 1, nextAlarm),
      };
    });
    if (result.next_alarm_at !== null) await this.scheduleAlarmAt(result.next_alarm_at);
    return result;
  }

  private async promoteNextQueued(
    transaction: ExecutorOperationTransaction,
    active: readonly string[],
    now: number,
    scheduleDigest: string,
  ): Promise<ExecutorOperationRecord | null> {
    const candidates: ExecutorOperationRecord[] = [];
    const prefix = `${OPERATION_PREFIX}`;
    const queuedIDs = (await transaction.get<string[]>(`${prefix}queue`)) ?? [];
    for (const operationID of queuedIDs) {
      if (active.includes(operationID)) continue;
      const operation = await transaction.get<ExecutorOperationRecord>(operationKey(operationID));
      if (
        operation?.status === "queued" &&
        operation.schedule_digest === scheduleDigest
      ) {
        candidates.push(operation);
      }
    }
    candidates.sort(
      (left, right) =>
        left.created_at - right.created_at ||
        left.operation_id.localeCompare(right.operation_id),
    );
    const next = candidates[0];
    if (!next) return null;
    const promoted: ExecutorOperationRecord = {
      ...next,
      status: "active",
      started_at: now,
      active_invocation_id: null,
    };
    await transaction.put(operationKey(next.operation_id), promoted);
    const remainingQueue = queuedIDs.filter((id) => id !== next.operation_id);
    await transaction.put(`${prefix}queue`, remainingQueue);
    return promoted;
  }

  private async scheduleNextAlarm(now: number): Promise<void> {
    if (!this.scheduleAlarm) return;
    try {
      const active = await this.storage.get<string[]>(ACTIVE_OPERATION_KEY);
      if (!active || active.length === 0) return;
      let next: number | null = null;
      for (const operationID of active) {
        const operation = await this.storage.get<ExecutorOperationRecord>(operationKey(operationID));
        if (!operation) continue;
        next = earlierAlarm(next, operationAlarmAt(operation));
      }
      if (next !== null) await this.scheduleAlarmAt(Math.max(now + 1, next));
    } catch {
      console.error("executor operation alarm scheduling unavailable");
    }
  }

  private async scheduleAlarmAt(timestamp: number): Promise<void> {
    if (!this.scheduleAlarm) return;
    try {
      await this.scheduleAlarm(timestamp);
    } catch {
      // The durable active index/deadline remains authoritative; the Worker
      // cron watchdog retries alarm registration without replaying the call.
      console.error("executor operation alarm scheduling unavailable");
    }
  }
}

export class SecurityExecutorOperations extends DurableObject<SecurityExecutorOperationEnv> {
  private get operationStore(): DurableExecutorOperationStore {
    return new DurableExecutorOperationStore(
      this.ctx.storage,
      (timestamp) => this.ctx.storage.setAlarm(timestamp),
    );
  }

  private providerStore(): DurableProviderOperationStore {
    return new DurableProviderOperationStore(this.ctx.storage);
  }

  private providerControlStore(): DurableProviderOperationStore {
    return new DurableProviderOperationStore(this.ctx.storage, {
      control_public_key: decodeProviderControlPublicKey(
        this.env.EXECUTOR_PROVIDER_CONTROL_PUBLIC_KEY,
      ),
    });
  }

  async providerStart(
    request: ProviderOperationStart,
    now = Date.now(),
  ): Promise<ProviderOperationStartResult> {
    return this.providerStore().start(request, now);
  }

  async providerClaim(
    operationID: string,
    invocationID: string,
    now = Date.now(),
  ): Promise<ProviderDispatchRequest | null> {
    return this.providerStore().claim(operationID, invocationID, now);
  }

  async providerRecordOutcome(
    operationID: string,
    invocationID: string,
    response: ProviderDispatchResponse,
    now = Date.now(),
  ): Promise<ProviderOperationRecord> {
    return this.providerStore().recordOutcome(operationID, invocationID, response, now);
  }


  async providerApplyDecision(
    decision: ProviderControlDecision,
    now = Date.now(),
  ): Promise<ProviderOperationRecord> {
    return this.providerControlStore().applyDecision(decision, now);
  }

  async providerVerify(
    operationID: string,
    verification: ProviderVerification,
    now = Date.now(),
  ): Promise<ProviderOperationRecord> {
    return this.providerStore().verify(operationID, verification, now);
  }

  async providerRead(operationID: string): Promise<ProviderOperationRecord | null> {
    return this.providerStore().read(operationID);
  }

  async providerReadInvocationOutcome(
    operationID: string,
    invocationID: string,
  ): Promise<ProviderInvocationOutcome | null> {
    return this.providerStore().readInvocationOutcome(operationID, invocationID);
  }

  async providerReadLastSuccess(
    targetIdentity: string,
    targetDigest: string,
    sourceFingerprint: string,
  ): Promise<ProviderLastSuccess | null> {
    return this.providerStore().readLastSuccess(targetIdentity, targetDigest, sourceFingerprint);
  }

  async begin(request: ExecutorOperationStart, now = Date.now()): Promise<ExecutorOperationStartResult> {
    return this.operationStore.begin(request, now);
  }

  async recordInvocationTimeout(
    operationID: string,
    invocationID: string,
    now = Date.now(),
  ): Promise<ExecutorOperationRecord> {
    return this.operationStore.recordInvocationTimeout(operationID, invocationID, now);
  }

  async complete(
    operationID: string,
    invocationID: string,
    status: "succeeded" | "failed",
    resultDigest: string | null,
    now = Date.now(),
    redactedResult?: Uint8Array,
  ): Promise<ExecutorOperationRecord> {
    return this.operationStore.complete(
      operationID,
      invocationID,
      status,
      resultDigest,
      now,
      redactedResult,
    );
  }

  async readResult(operationID: string): Promise<Uint8Array | null> {
    return this.operationStore.readResult(operationID);
  }

  async requestCancel(operationID: string, now = Date.now()): Promise<ExecutorOperationRecord> {
    return this.operationStore.requestCancel(operationID, now);
  }

  async watchdog(now = Date.now()): Promise<ExecutorOperationWatchdogResult> {
    return this.operationStore.watchdog(now);
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    let shouldReschedule = true;
    let nextAlarm = now + WATCHDOG_INTERVAL_MS;
    try {
      const result = await this.watchdog(now);
      shouldReschedule = result.next_alarm_at !== null;
      if (result.next_alarm_at !== null) nextAlarm = result.next_alarm_at;
    } finally {
      if (shouldReschedule) {
        try {
          await this.ctx.storage.setAlarm(nextAlarm);
        } catch {
          console.error("executor operation alarm rescheduling unavailable");
        }
      }
    }
  }
}

export function createOperationStoreAdapter(
  namespace: DurableObjectNamespace<SecurityExecutorOperations>,
): ExecutorOperationStore {
  const stub = namespace.getByName(EXECUTOR_OPERATION_OBJECT_NAME);
  const adapter: ExecutorOperationStore = {
    begin: (request, now) => stub.begin(request, now),
    recordInvocationTimeout: (operationID, invocationID, timestamp) =>
      stub.recordInvocationTimeout(operationID, invocationID, timestamp),
    complete: (operationID, invocationID, status, resultDigest, timestamp, redactedResult) =>
      stub.complete(
        operationID,
        invocationID,
        status,
        resultDigest,
        timestamp,
        redactedResult,
      ),
    readResult: (operationID) => stub.readResult(operationID),
    requestCancel: (operationID, timestamp) => stub.requestCancel(operationID, timestamp),
    watchdog: (timestamp) => stub.watchdog(timestamp),
  };
  return adapter;
}

export async function executorOperationFingerprint(input: {
  readonly schedule_digest: string;
  readonly exclusive: boolean;
  readonly generation: string;
  readonly source_digest: string;
  readonly target_digest: string;
  readonly config_digest: string;
  readonly image_digest: string;
}): Promise<string> {
  validateDigest(input.schedule_digest);
  if (typeof input.exclusive !== "boolean") {
    throw new ExecutorOperationInvalidRequestError();
  }
  if (!GENERATION_PATTERN.test(input.generation)) {
    throw new ExecutorOperationInvalidRequestError();
  }
  validateDigest(input.source_digest);
  validateDigest(input.target_digest);
  validateDigest(input.config_digest);
  validateDigest(input.image_digest);
  const canonical = [
    "skret/executor-operation/v1",
    `schedule=${input.schedule_digest}`,
    `exclusive=${input.exclusive ? "1" : "0"}`,
    `generation=${input.generation}`,
    `source=${input.source_digest}`,
    `target=${input.target_digest}`,
    `config=${input.config_digest}`,
    `image=${input.image_digest}`,
  ].join("\n");
  return digestBytes(new TextEncoder().encode(canonical));
}

function earlierAlarm(current: number | null, candidate: number): number {
  return current === null ? candidate : Math.min(current, candidate);
}

function operationAlarmAt(operation: ExecutorOperationRecord): number {
  return operation.status === "active"
    ? operation.deadline_at
    : operation.deadline_at + MAX_OPERATION_LIFETIME_MS;
}

function validateStart(request: ExecutorOperationStart, now: number): void {
  validateOperationID(request.operation_id);
  validateInvocationID(request.invocation_id);
  validateDigest(request.schedule_digest);
  if (typeof request.exclusive !== "boolean") {
    throw new ExecutorOperationInvalidRequestError();
  }
  validateDigest(request.fingerprint);
  validateDigest(request.source_digest);
  validateDigest(request.target_digest);
  validateDigest(request.config_digest);
  if (!GENERATION_PATTERN.test(request.generation)) {
    throw new ExecutorOperationInvalidRequestError();
  }
  if (
    !Number.isSafeInteger(request.deadline_at) ||
    request.deadline_at <= now ||
    request.deadline_at > now + MAX_OPERATION_LIFETIME_MS
  ) {
    throw new ExecutorOperationInvalidRequestError("invalid operation deadline");
  }
}

function holdsExecutionLane(status: ExecutorOperationStatus): boolean {
  return (
    status === "active" ||
    status === "timed_out" ||
    status === "cancel_requested"
  );
}

function validateOperationID(operationID: string): void {
  if (typeof operationID !== "string" || !OPERATION_ID_PATTERN.test(operationID)) throw new ExecutorOperationInvalidRequestError();
}

function validateInvocationID(invocationID: string): void {
  if (typeof invocationID !== "string" || !OPERATION_ID_PATTERN.test(invocationID)) throw new ExecutorOperationInvalidRequestError();
}

function validateDigest(digest: string): void {
  if (typeof digest !== "string" || !DIGEST_PATTERN.test(digest)) throw new ExecutorOperationInvalidRequestError();
}

function validateInvocationOutcome(outcome: ExecutorInvocationOutcome): void {
  validateInvocationID(outcome.invocation_id);
  validateOperationID(outcome.operation_id);
  if (!Number.isSafeInteger(outcome.observed_at) || outcome.observed_at < 0) {
    throw new ExecutorOperationInvalidRequestError();
  }
  if (outcome.result_digest !== null) validateDigest(outcome.result_digest);
}

async function writeInvocationOutcome(
  transaction: ExecutorOperationTransaction,
  outcome: ExecutorInvocationOutcome,
): Promise<void> {
  validateInvocationOutcome(outcome);
  const key = invocationKey(outcome.operation_id, outcome.invocation_id);
  const existing = await transaction.get<ExecutorInvocationOutcome>(key);
  if (existing) return;
  await transaction.put(key, outcome);
}

async function readActiveOperations(transaction: ExecutorOperationTransaction): Promise<string[]> {
  const active = (await transaction.get<string[]>(ACTIVE_OPERATION_KEY)) ?? [];
  if (!Array.isArray(active) || active.some((value) => typeof value !== "string")) {
    throw new ExecutorOperationUnavailableError();
  }
  return [...new Set(active)];
}

function laneActiveKey(scheduleDigest: string): string {
  return `${LANE_PREFIX}${scheduleDigest.slice("sha256:".length)}`;
}

function resultKey(operationID: string): string {
  return `${RESULT_PREFIX}${operationID}`;
}

async function digestBytes(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

function operationKey(operationID: string): string {
  return `${OPERATION_PREFIX}${operationID}`;
}

function invocationKey(operationID: string, invocationID: string): string {
  return `${INVOCATION_PREFIX}${operationID}:${invocationID}`;
}

function decodeProviderControlPublicKey(value: string | undefined): Uint8Array | undefined {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) return undefined;
  if (value.length === 64 && CONFIG_HEX_PATTERN.test(value)) {
    const decoded = new Uint8Array(32);
    for (let index = 0; index < decoded.length; index += 1) {
      decoded[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
    }
    return decoded;
  }

  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const unpadded = normalized.replace(/=+$/u, "");
  if (!/^[A-Za-z0-9+/]*$/u.test(unpadded) || unpadded.length % 4 === 1) return undefined;
  const padded = unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return undefined;
  }
  if (binary.length !== 32) return undefined;
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  let canonical = "";
  for (const byte of decoded) canonical += String.fromCharCode(byte);
  const standard = btoa(canonical);
  const standardRaw = standard.replace(/=+$/u, "");
  const urlSafe = standardRaw.replace(/\+/gu, "-").replace(/\//gu, "_");
  return value === standard || value === standardRaw || value === urlSafe ? decoded : undefined;
}
