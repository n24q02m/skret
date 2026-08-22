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

export interface SyncRunStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
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
  await storage.put(syncRunKey(runId), record);
  await storage.put(SYNC_ACTIVE_RUN_KEY, runId);
  return record;
}

export async function getSyncRun(
  storage: SyncRunStorage,
  runId: string,
): Promise<SyncRunRecord | undefined> {
  return storage.get<SyncRunRecord>(syncRunKey(runId));
}

export async function getLastSuccessRunId(
  storage: SyncRunStorage,
): Promise<string | undefined> {
  return storage.get<string>(SYNC_LAST_SUCCESS_KEY);
}

export async function getLastSuccessSyncRun(
  storage: SyncRunStorage,
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
  const started = await storage.get<SyncRunRecord>(key);
  if (!started || started.status !== "started") return undefined;

  const cleanExit = reason === "exit" && exitCode === 0;
  const status: SyncRunStatus = cleanExit ? "succeeded" : "failed";
  const classification: SyncRunClassification =
    reason === "runtime_signal"
      ? "runtime_signal"
      : cleanExit
        ? "clean_exit"
        : "nonzero_exit";
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
  await storage.put(key, finished);
  if (cleanExit) await storage.put(SYNC_LAST_SUCCESS_KEY, runId);
  await storage.delete(SYNC_ACTIVE_RUN_KEY);
  return finished;
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
