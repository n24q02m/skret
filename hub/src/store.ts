import type {
  Manifest,
  SyncRunMetadata,
  SyncRunRecord,
  SyncRunStatus,
  SyncRunClassification,
  SyncRunStopReason,
} from "./types";

const PREFIX = "manifest:";
export const SYNC_RUN_PREFIX = "sync:run:";
export const SYNC_ACTIVE_RUN_KEY = "sync:active-run";
export const SYNC_LAST_SUCCESS_KEY = "sync:last-success";

export interface SyncRunStorageOperation {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

export interface SyncRunStorage extends SyncRunStorageOperation {
  transaction<T>(
    closure: (transaction: SyncRunStorageOperation) => Promise<T>,
  ): Promise<T>;
}

export class SyncRunAlreadyActiveError extends Error {
  constructor() {
    super("sync run already active");
    this.name = "SyncRunAlreadyActiveError";
  }
}

export function manifestKey(ns: string, env: string): string {
  return `${PREFIX}${ns}:${env}`;
}

export function syncRunKey(runId: string): string {
  return `${SYNC_RUN_PREFIX}${runId}`;
}

export async function putManifest(kv: KVNamespace, m: Manifest): Promise<void> {
  await kv.put(manifestKey(m.namespace, m.env), JSON.stringify(m), {
    metadata: { updated: m.generated_at },
  });
}

export async function getAllManifests(kv: KVNamespace): Promise<Manifest[]> {
  const out: Manifest[] = [];
  let cursor: string | undefined;
  do {
    const page = await kv.list({ prefix: PREFIX, cursor });
    for (const k of page.keys) {
      const raw = await kv.get(k.name);
      if (raw) out.push(JSON.parse(raw) as Manifest);
    }
    if (page.list_complete) {
      cursor = undefined;
    } else {
      cursor = page.cursor;
    }
  } while (cursor);
  return out;
}

export async function putStartedSyncRun(
  storage: SyncRunStorage,
  runId: string,
  startedAt: string,
  metadata: SyncRunMetadata = {},
): Promise<SyncRunRecord> {
  const record: SyncRunRecord = {
    runId,
    imageDigest: normalizeString(metadata.imageDigest),
    configFingerprint: normalizeString(metadata.configFingerprint),
    targetCount: normalizeCount(metadata.targetCount),
    startedAt,
    endedAt: null,
    status: "started",
    classification: "started",
    exitCode: null,
    reason: null,
  };

  return storage.transaction(async (transaction) => {
    const activeRunId = await transaction.get<string>(SYNC_ACTIVE_RUN_KEY);
    if (activeRunId) {
      const activeRun = await transaction.get<SyncRunRecord>(syncRunKey(activeRunId));
      if (activeRun?.status === "started") {
        throw new SyncRunAlreadyActiveError();
      }
      await transaction.delete(SYNC_ACTIVE_RUN_KEY);
    }
    await transaction.put(syncRunKey(runId), record);
    await transaction.put(SYNC_ACTIVE_RUN_KEY, runId);
    return record;
  });
}

export async function getSyncRun(
  storage: SyncRunStorageOperation,
  runId: string,
): Promise<SyncRunRecord | undefined> {
  return storage.get<SyncRunRecord>(syncRunKey(runId));
}

export async function getLastSuccessRunId(
  storage: SyncRunStorageOperation,
): Promise<string | undefined> {
  return storage.get<string>(SYNC_LAST_SUCCESS_KEY);
}

export async function getLastSuccessSyncRun(
  storage: SyncRunStorageOperation,
): Promise<SyncRunRecord | undefined> {
  const runId = await getLastSuccessRunId(storage);
  return runId ? getSyncRun(storage, runId) : undefined;
}

export async function completeSyncRun(
  storage: SyncRunStorage,
  runId: string,
  endedAt: string,
  exitCode: number,
  reason: SyncRunStopReason,
): Promise<SyncRunRecord | undefined> {
  const key = syncRunKey(runId);
  const cleanExit = reason === "exit" && exitCode === 0;
  const status: SyncRunStatus = cleanExit ? "succeeded" : "failed";
  const classification: SyncRunClassification =
    reason === "runtime_signal"
      ? "runtime_signal"
      : cleanExit
        ? "clean_exit"
        : "nonzero_exit";

  return storage.transaction(async (transaction) => {
    const started = await transaction.get<SyncRunRecord>(key);
    if (!started) return undefined;

    if (started.status !== "started") {
      await repairTerminalRun(transaction, started, runId);
      return started;
    }

    const finished: SyncRunRecord = {
      runId: started.runId,
      imageDigest: started.imageDigest,
      configFingerprint: started.configFingerprint,
      targetCount: started.targetCount,
      startedAt: started.startedAt,
      endedAt,
      status,
      classification,
      exitCode,
      reason,
    };
    await transaction.put(key, finished);
    if (cleanExit) await advanceLastSuccess(transaction, finished);
    await clearActiveRun(transaction, runId);
    return finished;
  });
}

export async function failStartedSyncRun(
  storage: SyncRunStorage,
  runId: string,
  endedAt: string,
): Promise<SyncRunRecord | undefined> {
  const key = syncRunKey(runId);
  return storage.transaction(async (transaction) => {
    const started = await transaction.get<SyncRunRecord>(key);
    if (!started) return undefined;

    if (started.status !== "started") {
      await repairTerminalRun(transaction, started, runId);
      return started;
    }

    const failed: SyncRunRecord = {
      runId: started.runId,
      imageDigest: started.imageDigest,
      configFingerprint: started.configFingerprint,
      targetCount: started.targetCount,
      startedAt: started.startedAt,
      endedAt,
      status: "failed",
      classification: "start_failure",
      exitCode: null,
      reason: "start_failure",
    };
    await transaction.put(key, failed);
    await clearActiveRun(transaction, runId);
    return failed;
  });
}

async function repairTerminalRun(
  storage: SyncRunStorageOperation,
  record: SyncRunRecord,
  runId: string,
): Promise<void> {
  if (isCleanSuccess(record)) await advanceLastSuccess(storage, record);
  await clearActiveRun(storage, runId);
}

async function clearActiveRun(
  storage: SyncRunStorageOperation,
  runId: string,
): Promise<void> {
  const activeRunId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
  if (activeRunId === runId) await storage.delete(SYNC_ACTIVE_RUN_KEY);
}

async function advanceLastSuccess(
  storage: SyncRunStorageOperation,
  candidate: SyncRunRecord,
): Promise<void> {
  if (!isCleanSuccess(candidate)) return;
  const currentRunId = await storage.get<string>(SYNC_LAST_SUCCESS_KEY);
  if (!currentRunId) {
    await storage.put(SYNC_LAST_SUCCESS_KEY, candidate.runId);
    return;
  }
  if (currentRunId === candidate.runId) return;

  const current = await storage.get<SyncRunRecord>(syncRunKey(currentRunId));
  if (!isCleanSuccess(current) || isCompletionNewer(candidate, current)) {
    await storage.put(SYNC_LAST_SUCCESS_KEY, candidate.runId);
  }
}

function isCleanSuccess(record: SyncRunRecord | undefined): record is SyncRunRecord {
  return (
    record !== undefined &&
    record.status === "succeeded" &&
    record.classification === "clean_exit" &&
    record.exitCode === 0 &&
    record.reason === "exit" &&
    record.endedAt !== null &&
    Number.isFinite(Date.parse(record.endedAt))
  );
}

function isCompletionNewer(candidate: SyncRunRecord, current: SyncRunRecord): boolean {
  return (
    Date.parse(candidate.endedAt ?? "") > Date.parse(current.endedAt ?? "")
  );
}

function normalizeString(value: string | null | undefined): string | null {
  return value && value.trim() ? value : null;
}

function normalizeCount(value: number | null | undefined): number | null {
  return value !== null &&
    value !== undefined &&
    Number.isSafeInteger(value) &&
    value >= 0
    ? value
    : null;
}
