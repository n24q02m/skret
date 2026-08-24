const SHA256_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const SAFE_TEXT_PATTERN = /^[\u0021-\u007e]{1,1024}$/u;
const MIGRATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const HEAD_KEY = "kv-migration:head";
const MIGRATION_KEY_PREFIX = "kv-migration:lineage:";

const MIGRATION_FIELDS = [
  "version",
  "migration_id",
  "fencing_epoch",
  "rows",
  "status",
  "acknowledgements",
  "scans",
  "consecutive_zero_v1_scans",
  "minimum_safety_window_at",
] as const;
const ROW_FIELDS = ["v1_key", "v1_content_digest", "v2_key"] as const;
const ACK_FIELDS = ["v1_key", "observed_v2_digest"] as const;
const SCAN_FIELDS = ["scan_id", "observed_at", "v1_rows"] as const;
const HEAD_FIELDS = ["migration_id", "fencing_epoch"] as const;

export const KV_MIGRATION_HEAD_KEY = HEAD_KEY;

export interface KVMigrationRow {
  readonly v1_key: string;
  readonly v1_content_digest: string;
  readonly v2_key: string;
}

export interface KVMigrationAppliedAcknowledgement {
  readonly v1_key: string;
  readonly observed_v2_digest: string;
}

export interface KVMigrationScanObservation {
  readonly scan_id: string;
  readonly observed_at: number;
  readonly v1_rows: readonly KVMigrationSourceRow[];
}

export interface KVMigrationSourceRow {
  readonly v1_key: string;
  readonly v1_content_digest: string;
}

export interface KVMigrationStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(closure: (transaction: KVMigrationStorage) => Promise<T>): Promise<T>;
}

export interface KVMigrationPrepareInput {
  readonly migration_id: string;
  readonly fencing_epoch: number;
  readonly rows: readonly KVMigrationRow[];
  readonly now?: number;
}

export interface KVMigrationAppliedInput {
  readonly migration_id: string;
  readonly fencing_epoch: number;
  readonly v1_key: string;
  readonly observed_v2_digest: string;
}

export interface KVMigrationScanInput {
  readonly migration_id: string;
  readonly fencing_epoch: number;
  readonly scan_id: string;
  readonly observed_at: number;
  readonly v1_rows: readonly KVMigrationSourceRow[];
}

export interface KVMigrationEpochInput {
  readonly migration_id: string;
  readonly fencing_epoch: number;
}

export interface KVMigrationTombstoneInput extends KVMigrationEpochInput {
  readonly minimum_safety_window_at: number;
  readonly required_zero_v1_scans: number;
  readonly now: number;
}

export interface KVMigrationReadDecisionInput extends KVMigrationEpochInput {
  readonly key: string;
  readonly source: "v1" | "v2";
  readonly observed_content_digest?: string;
}

export type KVMigrationPrepareResult =
  | { readonly status: "prepared"; readonly migration_id: string; readonly fencing_epoch: number }
  | { readonly status: "existing"; readonly migration_id: string; readonly fencing_epoch: number }
  | { readonly status: "stale_epoch" }
  | { readonly status: "conflict" }
  | { readonly status: "invalid" }
  | { readonly status: "invalid_state" };

export type KVMigrationAppliedResult =
  | { readonly status: "applied"; readonly migration_id: string; readonly v1_key: string }
  | { readonly status: "duplicate"; readonly migration_id: string; readonly v1_key: string }
  | { readonly status: "digest_mismatch" }
  | { readonly status: "not_found" }
  | { readonly status: "stale_epoch" }
  | { readonly status: "closed" }
  | { readonly status: "invalid" }
  | { readonly status: "invalid_state" };

export type KVMigrationScanResult =
  | { readonly status: "observed"; readonly migration_id: string; readonly zero_v1_scans: number }
  | { readonly status: "duplicate"; readonly migration_id: string; readonly zero_v1_scans: number }
  | { readonly status: "scan_mismatch"; readonly zero_v1_scans: 0 }
  | { readonly status: "not_found" }
  | { readonly status: "stale_epoch" }
  | { readonly status: "invalid" }
  | { readonly status: "invalid_state" };

export type KVMigrationCommitResult =
  | { readonly status: "committed"; readonly migration_id: string; readonly fencing_epoch: number }
  | { readonly status: "pending"; readonly remaining: number }
  | { readonly status: "stale_epoch" }
  | { readonly status: "not_found" }
  | { readonly status: "invalid" }
  | { readonly status: "invalid_state" }
  | { readonly status: "closed" };

export type KVMigrationTombstoneResult =
  | { readonly status: "authorized"; readonly migration_id: string; readonly fencing_epoch: number }
  | { readonly status: "safety_window" }
  | { readonly status: "zero_scan_gate" }
  | { readonly status: "safety_window_mismatch" }
  | { readonly status: "stale_epoch" }
  | { readonly status: "not_found" }
  | { readonly status: "not_committed" }
  | { readonly status: "invalid" }
  | { readonly status: "invalid_state" };

export type KVMigrationReadDecisionResult =
  | { readonly status: "v1_allowed"; readonly v2_key: string }
  | { readonly status: "v2_allowed"; readonly v2_key: string }
  | { readonly status: "old_epoch_rejected" }
  | { readonly status: "stale_read_rejected" }
  | { readonly status: "tombstone_required" }
  | { readonly status: "not_bound" }
  | { readonly status: "pending" }
  | { readonly status: "not_found" }
  | { readonly status: "invalid" }
  | { readonly status: "invalid_state" };

interface StoredMigration {
  version: 1;
  migration_id: string;
  fencing_epoch: number;
  rows: readonly KVMigrationRow[];
  status: "prepared" | "committed" | "tombstone_authorized";
  acknowledgements: readonly KVMigrationAppliedAcknowledgement[];
  scans: readonly KVMigrationScanObservation[];
  consecutive_zero_v1_scans: number;
  minimum_safety_window_at: number | null;
}

interface StoredHead {
  readonly migration_id: string;
  readonly fencing_epoch: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length && keys.every((key, index) => key === fields[index]);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function validateSafeText(value: unknown): asserts value is string {
  if (typeof value !== "string" || !SAFE_TEXT_PATTERN.test(value)) throw new Error("invalid text");
}

function validateDigest(value: unknown): asserts value is string {
  if (typeof value !== "string" || !SHA256_DIGEST_PATTERN.test(value)) throw new Error("invalid digest");
}

function validateTimestamp(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error("invalid timestamp");
}

function validateNow(value: number | undefined): number {
  const now = value ?? Date.now();
  validateTimestamp(now);
  return now;
}

function validateEpoch(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new Error("invalid epoch");
}

function validateMigrationID(value: unknown): asserts value is string {
  if (typeof value !== "string" || !MIGRATION_ID_PATTERN.test(value)) throw new Error("invalid migration id");
}

function validateRow(value: unknown): asserts value is KVMigrationRow {
  if (!isRecord(value) || !exactFields(value, ROW_FIELDS)) throw new Error("invalid row");
  validateSafeText(value.v1_key);
  validateDigest(value.v1_content_digest);
  validateSafeText(value.v2_key);
}

function validateRows(value: unknown): asserts value is readonly KVMigrationRow[] {
  if (!Array.isArray(value)) throw new Error("invalid rows");
  let previous: string | undefined;
  const v2Keys = new Set<string>();
  for (const row of value) {
    validateRow(row);
    if (previous !== undefined && compareStrings(previous, row.v1_key) >= 0) throw new Error("unsorted rows");
    if (v2Keys.has(row.v2_key)) throw new Error("duplicate v2 key");
    v2Keys.add(row.v2_key);
    previous = row.v1_key;
  }
}

function validateSourceRows(value: unknown): asserts value is readonly KVMigrationSourceRow[] {
  if (!Array.isArray(value)) throw new Error("invalid source rows");
  let previous: string | undefined;
  const seen = new Set<string>();
  for (const candidate of value) {
    if (!isRecord(candidate) || !exactFields(candidate, ["v1_key", "v1_content_digest"])) throw new Error("invalid source row");
    validateSafeText(candidate.v1_key);
    validateDigest(candidate.v1_content_digest);
    if (previous !== undefined && compareStrings(previous, candidate.v1_key) >= 0) throw new Error("unsorted source rows");
    if (seen.has(candidate.v1_key)) throw new Error("duplicate source key");
    seen.add(candidate.v1_key);
    previous = candidate.v1_key;
  }
}

function copyRows(rows: readonly KVMigrationRow[]): readonly KVMigrationRow[] {
  return rows.map((row) => ({ ...row }));
}

function copySourceRows(rows: readonly KVMigrationSourceRow[]): readonly KVMigrationSourceRow[] {
  return rows.map((row) => ({ ...row }));
}

function migrationKey(migrationID: string): string {
  return `${MIGRATION_KEY_PREFIX}${migrationID}`;
}

function validHead(value: unknown): value is StoredHead {
  return (
    isRecord(value) &&
    exactFields(value, HEAD_FIELDS) &&
    typeof value.migration_id === "string" &&
    MIGRATION_ID_PATTERN.test(value.migration_id) &&
    Number.isSafeInteger(value.fencing_epoch) &&
    (value.fencing_epoch as number) >= 1
  );
}

function validStoredMigration(value: unknown): value is StoredMigration {
  if (
    !isRecord(value) ||
    !exactFields(value, MIGRATION_FIELDS) ||
    value.version !== 1 ||
    typeof value.migration_id !== "string" ||
    !MIGRATION_ID_PATTERN.test(value.migration_id) ||
    !Number.isSafeInteger(value.fencing_epoch) ||
    (value.fencing_epoch as number) < 1 ||
    !Array.isArray(value.rows) ||
    !Array.isArray(value.acknowledgements) ||
    !Array.isArray(value.scans) ||
    !Number.isSafeInteger(value.consecutive_zero_v1_scans) ||
    (value.consecutive_zero_v1_scans as number) < 0 ||
    !(
      value.minimum_safety_window_at === null ||
      (Number.isSafeInteger(value.minimum_safety_window_at) &&
        (value.minimum_safety_window_at as number) >= 0)
    )
  ) {
    return false;
  }
  if (value.status !== "prepared" && value.status !== "committed" && value.status !== "tombstone_authorized") return false;
  try {
    validateRows(value.rows);
    let previousAck: string | undefined;
    for (const ack of value.acknowledgements) {
      if (!isRecord(ack) || !exactFields(ack, ACK_FIELDS)) return false;
      validateSafeText(ack.v1_key);
      validateDigest(ack.observed_v2_digest);
      if (previousAck !== undefined && compareStrings(previousAck, ack.v1_key) >= 0) return false;
      previousAck = ack.v1_key;
      const boundRow = value.rows.find((row) => row.v1_key === ack.v1_key);
      if (boundRow === undefined || boundRow.v1_content_digest !== ack.observed_v2_digest) return false;
    }
    let previousScanAt: number | undefined;
    const scanIDs = new Set<string>();
    for (const scan of value.scans) {
      if (!isRecord(scan) || !exactFields(scan, SCAN_FIELDS)) return false;
      validateSafeText(scan.scan_id);
      validateTimestamp(scan.observed_at);
      validateSourceRows(scan.v1_rows);
      if (scanIDs.has(scan.scan_id)) return false;
      scanIDs.add(scan.scan_id);
      if (previousScanAt !== undefined && scan.observed_at <= previousScanAt) return false;
      previousScanAt = scan.observed_at;
    }
    let trailingZeroScans = 0;
    for (let index = value.scans.length - 1; index >= 0; index -= 1) {
      if (value.scans[index].v1_rows.length !== 0) break;
      trailingZeroScans += 1;
    }
    if (trailingZeroScans !== value.consecutive_zero_v1_scans) return false;
    if (
      value.status !== "prepared" &&
      value.acknowledgements.length !== value.rows.length
    ) {
      return false;
    }
  } catch {
    return false;
  }
  return true;
}

function copyStoredMigration(record: StoredMigration): StoredMigration {
  return {
    version: 1,
    migration_id: record.migration_id,
    fencing_epoch: record.fencing_epoch,
    rows: copyRows(record.rows),
    status: record.status,
    acknowledgements: record.acknowledgements.map((ack) => ({ ...ack })),
    scans: record.scans.map((scan) => ({
      scan_id: scan.scan_id,
      observed_at: scan.observed_at,
      v1_rows: copySourceRows(scan.v1_rows),
    })),
    consecutive_zero_v1_scans: record.consecutive_zero_v1_scans,
    minimum_safety_window_at: record.minimum_safety_window_at,
  };
}

function samePreparedInput(
  record: StoredMigration,
  input: KVMigrationPrepareInput,
): boolean {
  return (
    record.migration_id === input.migration_id &&
    record.fencing_epoch === input.fencing_epoch &&
    JSON.stringify(record.rows) === JSON.stringify(input.rows)
  );
}

function sameSourceRows(left: readonly KVMigrationSourceRow[], right: readonly KVMigrationRow[]): boolean {
  if (left.length !== right.length) return false;
  return left.every(
    (row, index) => row.v1_key === right[index].v1_key && row.v1_content_digest === right[index].v1_content_digest,
  );
}

function sourceRowMatchesBound(row: KVMigrationSourceRow, bound: readonly KVMigrationRow[]): boolean {
  return bound.some(
    (candidate) => candidate.v1_key === row.v1_key && candidate.v1_content_digest === row.v1_content_digest,
  );
}

function activeEpochFor(record: StoredMigration, head: StoredHead | undefined): boolean {
  if (head === undefined) return true;
  return head.migration_id === record.migration_id && head.fencing_epoch === record.fencing_epoch;
}

function trailingZeroScansSince(record: StoredMigration, minimumTime: number): number {
  let count = 0;
  for (let index = record.scans.length - 1; index >= 0; index -= 1) {
    const scan = record.scans[index];
    if (scan.v1_rows.length !== 0 || scan.observed_at < minimumTime) break;
    count += 1;
  }
  return count;
}

export class KVMigrationStore {
  constructor(private readonly storage: KVMigrationStorage) {}

  async prepare(input: KVMigrationPrepareInput): Promise<KVMigrationPrepareResult> {
    try {
      validateMigrationID(input.migration_id);
      validateEpoch(input.fencing_epoch);
      validateRows(input.rows);
      validateNow(input.now);
    } catch {
      return { status: "invalid" };
    }
    return this.storage.transaction(async (transaction) => {
      const rawHead = await transaction.get<unknown>(HEAD_KEY);
      if (rawHead !== undefined && !validHead(rawHead)) return { status: "invalid_state" } as const;
      const existingRaw = await transaction.get<unknown>(migrationKey(input.migration_id));
      if (existingRaw !== undefined && !validStoredMigration(existingRaw)) return { status: "invalid_state" } as const;
      if (existingRaw !== undefined) {
        const head = rawHead as StoredHead | undefined;
        if (head === undefined) return { status: "invalid_state" } as const;
        if (!activeEpochFor(existingRaw, head)) return { status: "stale_epoch" } as const;
        if (samePreparedInput(existingRaw, input)) {
          return { status: "existing", migration_id: input.migration_id, fencing_epoch: input.fencing_epoch } as const;
        }
        return { status: "conflict" } as const;
      }
      const head = rawHead as StoredHead | undefined;
      if (head !== undefined) {
        if (input.fencing_epoch <= head.fencing_epoch) return { status: "stale_epoch" } as const;
        const priorRaw = await transaction.get<unknown>(migrationKey(head.migration_id));
        if (priorRaw === undefined || !validStoredMigration(priorRaw)) {
          return { status: "invalid_state" } as const;
        }
        if (priorRaw.status === "prepared") return { status: "conflict" } as const;
      }
      const record: StoredMigration = {
        version: 1,
        migration_id: input.migration_id,
        fencing_epoch: input.fencing_epoch,
        rows: copyRows(input.rows),
        status: "prepared",
        acknowledgements: [],
        scans: [],
        consecutive_zero_v1_scans: 0,
        minimum_safety_window_at: null,
      };
      await transaction.put(migrationKey(input.migration_id), record);
      await transaction.put(HEAD_KEY, {
        migration_id: input.migration_id,
        fencing_epoch: input.fencing_epoch,
      } satisfies StoredHead);
      return { status: "prepared", migration_id: input.migration_id, fencing_epoch: input.fencing_epoch } as const;
    }).catch(() => ({ status: "invalid_state" as const }));
  }

  async acknowledgeApplied(input: KVMigrationAppliedInput): Promise<KVMigrationAppliedResult> {
    try {
      validateMigrationID(input.migration_id);
      validateEpoch(input.fencing_epoch);
      validateSafeText(input.v1_key);
      validateDigest(input.observed_v2_digest);
    } catch {
      return { status: "invalid" };
    }
    return this.storage.transaction(async (transaction) => {
      const raw = await transaction.get<unknown>(migrationKey(input.migration_id));
      if (raw === undefined) return { status: "not_found" } as const;
      if (!validStoredMigration(raw)) return { status: "invalid_state" } as const;
      const record = copyStoredMigration(raw);
      if (record.fencing_epoch !== input.fencing_epoch) return { status: "stale_epoch" } as const;
      const headRaw = await transaction.get<unknown>(HEAD_KEY);
      if (headRaw === undefined || !validHead(headRaw)) return { status: "invalid_state" } as const;
      if (!activeEpochFor(record, headRaw)) return { status: "stale_epoch" } as const;
      if (record.status === "tombstone_authorized" || record.status === "committed") return { status: "closed" } as const;
      const row = record.rows.find((candidate) => candidate.v1_key === input.v1_key);
      if (row === undefined) return { status: "not_found" } as const;
      const existing = record.acknowledgements.find((ack) => ack.v1_key === input.v1_key);
      if (existing !== undefined) {
        return existing.observed_v2_digest === input.observed_v2_digest
          ? ({ status: "duplicate", migration_id: input.migration_id, v1_key: input.v1_key } as const)
          : ({ status: "digest_mismatch" } as const);
      }
      if (row.v1_content_digest !== input.observed_v2_digest) return { status: "digest_mismatch" } as const;
      record.acknowledgements = [
        ...record.acknowledgements,
        { v1_key: input.v1_key, observed_v2_digest: input.observed_v2_digest },
      ].sort((left, right) => compareStrings(left.v1_key, right.v1_key));
      await transaction.put(migrationKey(input.migration_id), record);
      return { status: "applied", migration_id: input.migration_id, v1_key: input.v1_key } as const;
    }).catch(() => ({ status: "invalid_state" as const }));
  }

  async observeFullScan(input: KVMigrationScanInput): Promise<KVMigrationScanResult> {
    try {
      validateMigrationID(input.migration_id);
      validateEpoch(input.fencing_epoch);
      validateSafeText(input.scan_id);
      validateNow(input.observed_at);
      validateSourceRows(input.v1_rows);
    } catch {
      return { status: "invalid" };
    }
    return this.storage.transaction(async (transaction) => {
      const raw = await transaction.get<unknown>(migrationKey(input.migration_id));
      if (raw === undefined) return { status: "not_found" } as const;
      if (!validStoredMigration(raw)) return { status: "invalid_state" } as const;
      const record = copyStoredMigration(raw);
      if (record.fencing_epoch !== input.fencing_epoch) return { status: "stale_epoch" } as const;
      const headRaw = await transaction.get<unknown>(HEAD_KEY);
      if (headRaw === undefined || !validHead(headRaw)) return { status: "invalid_state" } as const;
      if (!activeEpochFor(record, headRaw)) return { status: "stale_epoch" } as const;
      const duplicate = record.scans.find((scan) => scan.scan_id === input.scan_id);
      if (duplicate !== undefined) {
        const same = duplicate.observed_at === input.observed_at && JSON.stringify(duplicate.v1_rows) === JSON.stringify(input.v1_rows);
        if (!same) return { status: "invalid_state" } as const;
        return { status: "duplicate", migration_id: input.migration_id, zero_v1_scans: record.consecutive_zero_v1_scans } as const;
      }
      const lastScan = record.scans[record.scans.length - 1];
      if (lastScan !== undefined && input.observed_at <= lastScan.observed_at) return { status: "invalid" } as const;
      const exactBound = sameSourceRows(input.v1_rows, record.rows);
      const knownSubset = input.v1_rows.every((row) => sourceRowMatchesBound(row, record.rows));
      const validObservation = input.v1_rows.length === 0 || (exactBound || knownSubset);
      record.scans = [
        ...record.scans,
        { scan_id: input.scan_id, observed_at: input.observed_at, v1_rows: copySourceRows(input.v1_rows) },
      ];
      record.consecutive_zero_v1_scans = input.v1_rows.length === 0 ? record.consecutive_zero_v1_scans + 1 : 0;
      await transaction.put(migrationKey(input.migration_id), record);
      if (!validObservation) return { status: "scan_mismatch", zero_v1_scans: 0 } as const;
      return {
        status: "observed",
        migration_id: input.migration_id,
        zero_v1_scans: record.consecutive_zero_v1_scans,
      } as const;
    }).catch(() => ({ status: "invalid_state" as const }));
  }

  async commit(input: KVMigrationEpochInput): Promise<KVMigrationCommitResult> {
    try {
      validateMigrationID(input.migration_id);
      validateEpoch(input.fencing_epoch);
    } catch {
      return { status: "invalid" };
    }
    return this.storage.transaction(async (transaction) => {
      const raw = await transaction.get<unknown>(migrationKey(input.migration_id));
      if (raw === undefined) return { status: "not_found" } as const;
      if (!validStoredMigration(raw)) return { status: "invalid_state" } as const;
      const record = copyStoredMigration(raw);
      if (record.fencing_epoch !== input.fencing_epoch) return { status: "stale_epoch" } as const;
      if (record.status === "tombstone_authorized") return { status: "closed" } as const;
      if (record.status === "committed") return { status: "committed", migration_id: record.migration_id, fencing_epoch: record.fencing_epoch } as const;
      const acknowledged = new Set(record.acknowledgements.map((ack) => ack.v1_key));
      const remaining = record.rows.filter((row) => !acknowledged.has(row.v1_key)).length;
      if (remaining !== 0) return { status: "pending", remaining } as const;
      const headRaw = await transaction.get<unknown>(HEAD_KEY);
      if (headRaw === undefined || !validHead(headRaw)) return { status: "invalid_state" } as const;
      if (!activeEpochFor(record, headRaw)) return { status: "stale_epoch" } as const;
      record.status = "committed";
      await transaction.put(migrationKey(record.migration_id), record);
      await transaction.put(HEAD_KEY, { migration_id: record.migration_id, fencing_epoch: record.fencing_epoch } satisfies StoredHead);
      return { status: "committed", migration_id: record.migration_id, fencing_epoch: record.fencing_epoch } as const;
    }).catch(() => ({ status: "invalid_state" as const }));
  }

  async authorizeTombstone(input: KVMigrationTombstoneInput): Promise<KVMigrationTombstoneResult> {
    try {
      validateMigrationID(input.migration_id);
      validateEpoch(input.fencing_epoch);
      validateNow(input.minimum_safety_window_at);
      validateNow(input.now);
      if (!Number.isSafeInteger(input.required_zero_v1_scans) || input.required_zero_v1_scans < 1) throw new Error("invalid scan count");
    } catch {
      return { status: "invalid" };
    }
    return this.storage.transaction(async (transaction) => {
      const raw = await transaction.get<unknown>(migrationKey(input.migration_id));
      if (raw === undefined) return { status: "not_found" } as const;
      if (!validStoredMigration(raw)) return { status: "invalid_state" } as const;
      const record = copyStoredMigration(raw);
      if (record.fencing_epoch !== input.fencing_epoch) return { status: "stale_epoch" } as const;
      const headRaw = await transaction.get<unknown>(HEAD_KEY);
      if (headRaw === undefined || !validHead(headRaw)) return { status: "invalid_state" } as const;
      if (!activeEpochFor(record, headRaw)) return { status: "stale_epoch" } as const;
      if (record.status === "prepared") return { status: "not_committed" } as const;
      if (record.minimum_safety_window_at !== null && record.minimum_safety_window_at !== input.minimum_safety_window_at) {
        return { status: "safety_window_mismatch" } as const;
      }
      if (record.minimum_safety_window_at === null) record.minimum_safety_window_at = input.minimum_safety_window_at;
      if (record.status === "tombstone_authorized") {
        return { status: "authorized", migration_id: record.migration_id, fencing_epoch: record.fencing_epoch } as const;
      }
      await transaction.put(migrationKey(record.migration_id), record);
      if (input.now < input.minimum_safety_window_at) return { status: "safety_window" } as const;
      if (trailingZeroScansSince(record, input.minimum_safety_window_at) < input.required_zero_v1_scans) {
        return { status: "zero_scan_gate" } as const;
      }
      record.status = "tombstone_authorized";
      await transaction.put(migrationKey(record.migration_id), record);
      return { status: "authorized", migration_id: record.migration_id, fencing_epoch: record.fencing_epoch } as const;
    }).catch(() => ({ status: "invalid_state" as const }));
  }

  async readDecision(input: KVMigrationReadDecisionInput): Promise<KVMigrationReadDecisionResult> {
    try {
      validateMigrationID(input.migration_id);
      validateEpoch(input.fencing_epoch);
      validateSafeText(input.key);
      if (input.observed_content_digest !== undefined) validateDigest(input.observed_content_digest);
    } catch {
      return { status: "invalid" };
    }
    return this.storage.transaction(async (transaction) => {
      const raw = await transaction.get<unknown>(migrationKey(input.migration_id));
      if (raw === undefined) return { status: "not_found" } as const;
      if (!validStoredMigration(raw)) return { status: "invalid_state" } as const;
      const record = raw;
      const headRaw = await transaction.get<unknown>(HEAD_KEY);
      if (headRaw === undefined || !validHead(headRaw)) return { status: "invalid_state" } as const;
      if (!activeEpochFor(record, headRaw)) {
        return { status: "old_epoch_rejected" } as const;
      }
      const row = record.rows.find((candidate) =>
        input.source === "v1" ? candidate.v1_key === input.key : candidate.v2_key === input.key,
      );
      if (row === undefined) return { status: "not_bound" } as const;
      if (
        input.observed_content_digest !== undefined &&
        input.observed_content_digest !== row.v1_content_digest
      ) {
        return { status: "stale_read_rejected" } as const;
      }
      if (input.source === "v1") {
        if (record.status === "tombstone_authorized") return { status: "tombstone_required" } as const;
        return { status: "v1_allowed", v2_key: row.v2_key } as const;
      }
      if (record.status === "prepared") return { status: "pending" } as const;
      return { status: "v2_allowed", v2_key: row.v2_key } as const;
    }).catch(() => ({ status: "invalid_state" as const }));
  }
}
