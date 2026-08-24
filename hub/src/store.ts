import type {
  Manifest,
  OperatorSyncHealth,
  SyncHealth,
  SyncHealthAlerts,
  SyncRunClassification,
  SyncRunMetadata,
  SyncRunRecord,
  SyncRunStatus,
  SyncRunStopReason,
  Env,
} from "./types";

const PREFIX = "manifest:";
export const SYNC_RUN_PREFIX = "sync:run:";
export const SYNC_ACTIVE_RUN_KEY = "sync:active-run";
export const SYNC_LAST_COMPLETION_KEY = "sync:last-completion";
const SYNC_COMPLETION_SEQUENCE_KEY = "sync:completion-sequence";
export const SYNC_LAST_SUCCESS_KEY = "sync:last-success";
export const SYNC_PLANNER_STOP_STATE_KEY = "sync:planner-stop-state";

export const DEFAULT_SYNC_STALE_THRESHOLD_SECONDS = 27 * 60 * 60;
export const MIN_SYNC_STALE_THRESHOLD_SECONDS = 60;
export const MAX_SYNC_STALE_THRESHOLD_SECONDS = 7 * 24 * 60 * 60;
const MAX_FINGERPRINT_LENGTH = 256;

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
export interface SyncHealthConfig {
  expectedFingerprint: string | null;
  staleThresholdSeconds: number;
}

export function resolveSyncHealthConfig(
  env?: Pick<Env, "SYNC_EXPECTED_FINGERPRINT" | "SYNC_STALE_THRESHOLD_SECONDS">,
): SyncHealthConfig {
  const expectedFingerprint = validateFingerprint(env?.SYNC_EXPECTED_FINGERPRINT);
  const staleThresholdSeconds = parseStaleThreshold(env?.SYNC_STALE_THRESHOLD_SECONDS);
  return { expectedFingerprint, staleThresholdSeconds };
}

function validateFingerprint(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new Error("invalid sync health configuration");
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > MAX_FINGERPRINT_LENGTH ||
    [...normalized].some((char) => char.charCodeAt(0) < 0x20 || char === "\u007f")
  ) {
    throw new Error("invalid sync health configuration");
  }
  return normalized;
}

function parseStaleThreshold(value: unknown): number {
  if (value === undefined) return DEFAULT_SYNC_STALE_THRESHOLD_SECONDS;
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    throw new Error("invalid sync health configuration");
  }
  const parsed = Number(value);
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < MIN_SYNC_STALE_THRESHOLD_SECONDS ||
    parsed > MAX_SYNC_STALE_THRESHOLD_SECONDS
  ) {
    throw new Error("invalid sync health configuration");
  }
  return parsed;
}
function validateSyncHealthConfig(config: SyncHealthConfig): SyncHealthConfig {
  if (
    config === null ||
    typeof config !== "object" ||
    (config.expectedFingerprint !== null && typeof config.expectedFingerprint !== "string") ||
    !Number.isSafeInteger(config.staleThresholdSeconds) ||
    config.staleThresholdSeconds < MIN_SYNC_STALE_THRESHOLD_SECONDS ||
    config.staleThresholdSeconds > MAX_SYNC_STALE_THRESHOLD_SECONDS
  ) {
    throw new Error("invalid sync health configuration");
  }
  const expectedFingerprint = validateFingerprint(config.expectedFingerprint);
  if (config.expectedFingerprint !== null && expectedFingerprint === null) {
    throw new Error("invalid sync health configuration");
  }
  return {
    expectedFingerprint,
    staleThresholdSeconds: config.staleThresholdSeconds,
  };
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
  const record = newStartedSyncRunRecord(runId, startedAt, metadata);

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

export async function ensureStartedSyncRun(
  storage: SyncRunStorage,
  startedAt: string,
  metadata: SyncRunMetadata = {},
): Promise<SyncRunRecord> {
  return storage.transaction(async (transaction) => {
    const activeRunId = await transaction.get<string>(SYNC_ACTIVE_RUN_KEY);
    if (activeRunId) {
      const activeRun = await transaction.get<SyncRunRecord>(syncRunKey(activeRunId));
      if (activeRun?.status === "started") return activeRun;
      await transaction.delete(SYNC_ACTIVE_RUN_KEY);
    }

    const record = newStartedSyncRunRecord(crypto.randomUUID(), startedAt, metadata);
    await transaction.put(syncRunKey(record.runId), record);
    await transaction.put(SYNC_ACTIVE_RUN_KEY, record.runId);
    return record;
  });
}

function newStartedSyncRunRecord(
  runId: string,
  startedAt: string,
  metadata: SyncRunMetadata,
): SyncRunRecord {
  return {
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
export async function getLastCompletionRunId(
  storage: SyncRunStorageOperation,
): Promise<string | undefined> {
  return storage.get<string>(SYNC_LAST_COMPLETION_KEY);
}

export async function getLastCompletionSyncRun(
  storage: SyncRunStorageOperation,
): Promise<SyncRunRecord | undefined> {
  const runId = await getLastCompletionRunId(storage);
  const record = runId ? await getSyncRun(storage, runId) : undefined;
  return record && record.status !== "started" ? record : undefined;
}
export async function getOperatorSyncHealth(
  storage: SyncRunStorageOperation,
  now = new Date(),
  config: SyncHealthConfig = resolveSyncHealthConfig(),
): Promise<OperatorSyncHealth> {
  const validatedConfig = validateSyncHealthConfig(config);
  const activeRunId = await storage.get<string>(SYNC_ACTIVE_RUN_KEY);
  const activeRecord = activeRunId
    ? await getSyncRun(storage, activeRunId)
    : undefined;
  const activeRun = activeRecord?.status === "started" ? activeRecord : null;
  const lastCompletion = (await getLastCompletionSyncRun(storage)) ?? null;
  const successRecord = await getLastSuccessSyncRun(storage);
  const lastSuccess = isCleanSuccess(successRecord) ? successRecord : null;
  const lastSuccessAt = lastSuccess?.endedAt ?? null;
  const endedAtMs = lastSuccessAt === null ? NaN : Date.parse(lastSuccessAt);
  const ageSeconds = Number.isFinite(endedAtMs)
    ? Math.max(0, Math.floor((now.getTime() - endedAtMs) / 1000))
    : null;
  const stale =
    lastSuccess === null ||
    ageSeconds === null ||
    ageSeconds >= validatedConfig.staleThresholdSeconds;
  const fingerprintMatch =
    validatedConfig.expectedFingerprint === null || lastSuccess === null
      ? null
      : lastSuccess.configFingerprint === validatedConfig.expectedFingerprint;
  const fingerprintDrift = fingerprintMatch === false;
  const nonzeroCompletion = lastCompletion?.status === "failed";
  const status = healthStatus(
    activeRun !== null,
    lastSuccess !== null,
    stale,
    fingerprintDrift,
    nonzeroCompletion,
  );
  const alerts: SyncHealthAlerts = {
    nonzero_completion: nonzeroCompletion,
    stale,
    fingerprint_drift: fingerprintDrift,
  };

  return {
    status,
    active: activeRun !== null,
    stale,
    fingerprint_match: fingerprintMatch,
    last_success_at: lastSuccessAt,
    age_seconds: ageSeconds,
    last_completion: lastCompletion ? copySyncRunRecord(lastCompletion) : null,
    last_success: lastSuccess ? copySyncRunRecord(lastSuccess) : null,
    active_run: activeRun ? copySyncRunRecord(activeRun) : null,
    expected_fingerprint: validatedConfig.expectedFingerprint,
    stale_threshold_seconds: validatedConfig.staleThresholdSeconds,
    alerts,
  };
}

export async function getSyncHealth(
  storage: SyncRunStorageOperation,
  now = new Date(),
  config: SyncHealthConfig = resolveSyncHealthConfig(),
): Promise<SyncHealth> {
  const detailed = await getOperatorSyncHealth(storage, now, config);
  return {
    status: detailed.status,
    active: detailed.active,
    stale: detailed.stale,
    fingerprint_match: detailed.fingerprint_match,
    last_success_at: detailed.last_success_at,
    age_seconds: detailed.age_seconds,
  };
}

function healthStatus(
  active: boolean,
  hasSuccess: boolean,
  stale: boolean,
  fingerprintDrift: boolean,
  nonzeroCompletion: boolean,
): OperatorSyncHealth["status"] {
  if (active) return "active";
  if (!hasSuccess) return "unknown";
  if (fingerprintDrift) return "fingerprint_drift";
  if (stale) return "stale";
  if (nonzeroCompletion) return "degraded";
  return "healthy";
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

    const completionSequence = await nextCompletionSequence(transaction);
    const finished: SyncRunRecord = {
      runId: started.runId,
      imageDigest: started.imageDigest,
      configFingerprint: started.configFingerprint,
      targetCount: started.targetCount,
      startedAt: started.startedAt,
      completionSequence,
      endedAt,
      status,
      classification,
      exitCode,
      reason,
    };
    await transaction.put(key, finished);
    await advanceLastCompletion(transaction, finished);
    if (cleanExit) await advanceLastSuccess(transaction, finished);
    await clearActiveRun(transaction, runId);
    return finished;
  });
}


async function repairTerminalRun(
  storage: SyncRunStorageOperation,
  record: SyncRunRecord,
  runId: string,
): Promise<void> {
  await advanceLastCompletion(storage, record);
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
async function advanceLastCompletion(
  storage: SyncRunStorageOperation,
  candidate: SyncRunRecord,
): Promise<void> {
  if (candidate.status === "started") return;
  const currentRunId = await storage.get<string>(SYNC_LAST_COMPLETION_KEY);
  if (!currentRunId) {
    await storage.put(SYNC_LAST_COMPLETION_KEY, candidate.runId);
    return;
  }
  if (currentRunId === candidate.runId) return;

  const current = await storage.get<SyncRunRecord>(syncRunKey(currentRunId));
  if (
    current === undefined ||
    current.status === "started" ||
    isCompletionNewer(candidate, current)
  ) {
    await storage.put(SYNC_LAST_COMPLETION_KEY, candidate.runId);
  }
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

function copySyncRunRecord(record: SyncRunRecord): SyncRunRecord {
  return {
    runId: record.runId,
    imageDigest: record.imageDigest,
    configFingerprint: record.configFingerprint,
    targetCount: record.targetCount,
    startedAt: record.startedAt,
    endedAt: record.endedAt,
    status: record.status,
    classification: record.classification,
    exitCode: record.exitCode,
    reason: record.reason,
  };
}

async function nextCompletionSequence(
  storage: SyncRunStorageOperation,
): Promise<number> {
  const current = await storage.get<number>(SYNC_COMPLETION_SEQUENCE_KEY);
  if (
    current !== undefined &&
    (!Number.isSafeInteger(current) || current < 0 || current === Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error("invalid sync completion sequence");
  }
  const next = (current ?? 0) + 1;
  await storage.put(SYNC_COMPLETION_SEQUENCE_KEY, next);
  return next;
}

function isCompletionNewer(candidate: SyncRunRecord, current: SyncRunRecord): boolean {
  const candidateTime = Date.parse(candidate.endedAt ?? "");
  const currentTime = Date.parse(current.endedAt ?? "");
  if (Number.isFinite(candidateTime) && Number.isFinite(currentTime)) {
    if (candidateTime !== currentTime) return candidateTime > currentTime;
    const candidateSequence = validCompletionSequence(candidate.completionSequence);
    const currentSequence = validCompletionSequence(current.completionSequence);
    if (candidateSequence !== null || currentSequence !== null) {
      if (candidateSequence === null) return false;
      if (currentSequence === null) return true;
      return candidateSequence > currentSequence;
    }
    return candidate.runId > current.runId;
  }
  if (Number.isFinite(candidateTime)) return true;
  if (Number.isFinite(currentTime)) return false;
  return candidate.runId > current.runId;
}

function validCompletionSequence(value: number | undefined): number | null {
  return Number.isSafeInteger(value) && (value as number) > 0 ? (value as number) : null;
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
