import { DurableObject } from "cloudflare:workers";
import {
  CANDIDATE_ACCOUNT_ID,
  CANDIDATE_DEPLOY_ROLE,
  CANDIDATE_EXECUTOR_SCRIPT,
  CANDIDATE_SCHEDULE_ROLE,
  candidateLifecycleTargetDigest,
  executeCandidateLifecycleAuthorization,
} from "./candidate-lifecycle-authorizer";
import {
  DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT,
  DurableExecutorReplayStore,
  ExecutorReplayInvalidRequestError,
  ExecutorReplayRejectedError,
  ExecutorReplayStoreUnavailableError,
  type ExecutorReplayScope,
} from "./executor-replay-store";
import type { ExecutorEnvelope } from "./executor-envelope-verifier";
import {
  handlePrivateExecutorEnvelope,
  MAX_PRIVATE_EXECUTOR_ROLES,
  PRIVATE_EXECUTOR_PATH,
  type PrivateExecutorHandlerOptions,
  type PrivateExecutorReplayStore,
  type PrivateExecutorRoleAuthority,
  type PrivateExecutorRoleAuthorityBinding,
} from "./private-executor-handler";

import {
  createOperationStoreAdapter,
  executorOperationFingerprint,
  EXECUTOR_OPERATION_OBJECT_NAME,
  type ExecutorOperationStore,
  type SecurityExecutorOperations,
} from "./executor-operation-store";
export { SecurityExecutorOperations } from "./executor-operation-store";
export const SECURITY_EXECUTOR_SERVICE = "skret-security-executor";
export const SECURITY_EXECUTOR_REPLAY_BINDING = "EXECUTOR_REPLAY";
export const SECURITY_EXECUTOR_REPLAY_OBJECT_NAME = "security-executor-replay";
export const MAX_METADATA_MIGRATION_BODY_BYTES = 256 * 1024;
export const MAX_METADATA_MIGRATION_SOURCE_SIZE = 2 ** 40;
export const MAX_STATE_MANIFEST_BYTES = 256 * 1024;
export const METADATA_ACK_AAD_PREFIX = "skret/security-executor/metadata-ack/v1";
export const MAX_EXECUTOR_CLIENT_PUBLIC_KEYS_JSON_LENGTH = 32 * 1024;
export const MAX_EXECUTOR_CLIENT_AUTHORITY_HORIZON_MS = 7 * 24 * 60 * 60 * 1000;
export const METADATA_MIGRATION_EXECUTOR_ROLE = "migration-client";

const ED25519_PUBLIC_KEY_BYTES = 32;
const AES_GCM_KEY_BYTES = 32;
const AES_GCM_IV_BYTES = 12;
const MAX_CONFIG_TEXT_LENGTH = 256;
const MAX_METADATA_TEXT_LENGTH = 4_096;
const MAX_STATE_MANIFEST_TTL_MS = 15 * 60 * 1000;
const OPERATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/u;
const STANDARD_BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const CONFIG_HEX_PATTERN = /^[0-9a-fA-F]+$/u;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/u;
const WINDOWS_CANONICAL_ABSOLUTE_PATH_PATTERN = /^[A-Za-z]:\\(?:[^\\/]+(?:\\[^\\/]+)*)?$/u;
const EXECUTOR_CLIENT_AUTHORITY_FIELDS = [
  "public_key",
  "generation",
  "not_after",
  "capability_digest",
] as const;
const UNC_CANONICAL_ABSOLUTE_PATH_PATTERN = /^\\\\[^\\/]+\\[^\\/]+(?:\\[^\\/]+)*$/u;
const POSIX_CANONICAL_ABSOLUTE_PATH_PATTERN = /^\/(?:[^/]+(?:\/[^/]+)*)?$/u;
const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; base-uri 'none'",
};

export type SecurityExecutorReplayStatus = "accepted" | "rejected" | "invalid" | "unavailable";

export interface SecurityExecutorReplayResult {
  readonly status: SecurityExecutorReplayStatus;
}

export type SecurityExecutorReplaySweepStatus = "swept" | "invalid" | "unavailable";

export interface SecurityExecutorReplaySweepResult {
  readonly status: SecurityExecutorReplaySweepStatus;
  readonly removed?: number;
  readonly nextAfter?: string | null;
}

export interface SecurityExecutorEnv {
  readonly EXECUTOR_REPLAY?: DurableObjectNamespace<SecurityExecutorReplay>;
  readonly EXECUTOR_OPERATIONS?: DurableObjectNamespace<SecurityExecutorOperations>;
  readonly EXECUTOR_EXPECTED_AUDIENCE?: string;
  readonly EXECUTOR_CLIENT_PUBLIC_KEYS?: string;
  readonly EXECUTOR_STATE_MANIFEST_PUBLIC_KEY?: string;
  readonly EXECUTOR_RESPONSE_KEY?: string;
  readonly EXECUTOR_PROVIDER_CONTROL_PUBLIC_KEY?: string;
  readonly EXECUTOR_IMAGE_DIGEST?: string;
  readonly EXECUTOR_CONFIG_DIGEST?: string;
  readonly CANDIDATE_LIFECYCLE_ACCOUNT_ID?: string;
  readonly CANDIDATE_LIFECYCLE_SCRIPT_NAME?: string;
  readonly CANDIDATE_LIFECYCLE_TRANSACTION_DIGEST?: string;
}

interface MetadataMigrationRequest {
  readonly operation_id: string;
  readonly state_path: string;
  readonly journal_path: string;
  readonly manifest_digest: string;
  readonly target: "v2";
  readonly source_hash: string;
  readonly source_size: number;
  readonly state_manifest: Uint8Array;
}

/**
 * Source-only Durable Object authority for executor replay. Only value-free
 * status tokens cross the RPC boundary; the durable store persists a digest
 * and expiry, never the signed body or metadata paths.
 */
export class SecurityExecutorReplay extends DurableObject<SecurityExecutorEnv> {
  async consume(
    scope: ExecutorReplayScope,
    digest: string,
    expiresAt: number,
    now = Date.now(),
  ): Promise<SecurityExecutorReplayResult> {
    try {
      await new DurableExecutorReplayStore(this.ctx.storage).consume(scope, digest, expiresAt, now);
      return { status: "accepted" };
    } catch (error) {
      if (error instanceof ExecutorReplayRejectedError) return { status: "rejected" };
      if (error instanceof ExecutorReplayInvalidRequestError) return { status: "invalid" };
      return { status: "unavailable" };
    }
  }

  async sweep(
    now = Date.now(),
    limit = DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT,
    startAfter?: string | null,
  ): Promise<SecurityExecutorReplaySweepResult> {
    try {
      const result = await new DurableExecutorReplayStore(this.ctx.storage).sweep(now, limit, startAfter);
      return { status: "swept", removed: result.removed, nextAfter: result.nextAfter };
    } catch (error) {
      if (error instanceof ExecutorReplayInvalidRequestError) return { status: "invalid" };
      return { status: "unavailable" };
    }
  }
}

/**
 * Adapt the RPC-only Durable Object to the existing verifier's typed replay
 * store. Unknown or thrown RPC results fail closed as unavailable and never
 * cross the response boundary with their original error/value.
 */
export function createReplayStoreAdapter(
  namespace: DurableObjectNamespace<SecurityExecutorReplay>,
): PrivateExecutorReplayStore {
  return {
    async consume(scope, digest, expiresAt, now): Promise<void> {
      let result: SecurityExecutorReplayResult;
      try {
        const stub = namespace.getByName(SECURITY_EXECUTOR_REPLAY_OBJECT_NAME);
        result = await stub.consume(scope, digest, expiresAt, now);
      } catch {
        throw new ExecutorReplayStoreUnavailableError();
      }

      if (!result || typeof result !== "object") throw new ExecutorReplayStoreUnavailableError();
      if (result.status === "accepted") return;
      if (result.status === "rejected") throw new ExecutorReplayRejectedError();
      if (result.status === "invalid") throw new ExecutorReplayInvalidRequestError();
      throw new ExecutorReplayStoreUnavailableError();
    },
  };
}

/**
 * Construct the private handler dependencies only after every required Worker
 * binding/config value has passed strict shape validation. Secrets are parsed
 * in memory and are never included in errors, logs, or response bodies.
 */
export async function buildSecurityExecutorOptions(
  env: SecurityExecutorEnv,
  now?: number,
): Promise<PrivateExecutorHandlerOptions | null> {
  const buildNow = now ?? Date.now();
  if (
    !env ||
    typeof env !== "object" ||
    !Number.isSafeInteger(buildNow) ||
    buildNow < 0
  ) {
    return null;
  }
  const expectedAudience = readConfigText(env.EXECUTOR_EXPECTED_AUDIENCE);
  const configuredRoleAuthorities = parseExecutorClientAuthorities(
    env.EXECUTOR_CLIENT_PUBLIC_KEYS,
    buildNow,
  );
  const migrationAuthority = configuredRoleAuthorities?.find(
    (authority) => authority.role === METADATA_MIGRATION_EXECUTOR_ROLE,
  );
  const candidateDeployAuthority = configuredRoleAuthorities?.find(
    (authority) => authority.role === CANDIDATE_DEPLOY_ROLE,
  );
  const candidateScheduleAuthority = configuredRoleAuthorities?.find(
    (authority) => authority.role === CANDIDATE_SCHEDULE_ROLE,
  );
  const candidateScopePresent =
    env.CANDIDATE_LIFECYCLE_ACCOUNT_ID !== undefined ||
    env.CANDIDATE_LIFECYCLE_SCRIPT_NAME !== undefined ||
    env.CANDIDATE_LIFECYCLE_TRANSACTION_DIGEST !== undefined;
  const candidateRolePresent =
    candidateDeployAuthority !== undefined || candidateScheduleAuthority !== undefined;
  const candidateLifecycleRequested = candidateScopePresent || candidateRolePresent;
  const candidateAccountId = readConfigText(env.CANDIDATE_LIFECYCLE_ACCOUNT_ID);
  const candidateScriptName = readConfigText(env.CANDIDATE_LIFECYCLE_SCRIPT_NAME);
  const candidateTransactionDigest = readConfigDigest(
    env.CANDIDATE_LIFECYCLE_TRANSACTION_DIGEST,
  );
  const stateManifestPublicKey = decodeConfiguredBytes(
    env.EXECUTOR_STATE_MANIFEST_PUBLIC_KEY,
    ED25519_PUBLIC_KEY_BYTES,
  );
  const responseKeyBytes = decodeConfiguredBytes(env.EXECUTOR_RESPONSE_KEY, AES_GCM_KEY_BYTES);
  const imageDigest = readConfigDigest(env.EXECUTOR_IMAGE_DIGEST);
  const configDigest = readConfigDigest(env.EXECUTOR_CONFIG_DIGEST);
  const replayNamespace = env.EXECUTOR_REPLAY;
  const operationNamespace = env.EXECUTOR_OPERATIONS;
  if (
    !expectedAudience ||
    !configuredRoleAuthorities ||
    !migrationAuthority ||
    !stateManifestPublicKey ||
    !responseKeyBytes ||
    !imageDigest ||
    !configDigest ||
    !hasReplayNamespace(replayNamespace) ||
    !hasOperationNamespace(operationNamespace) ||
    (candidateLifecycleRequested &&
      (!candidateDeployAuthority ||
        !candidateScheduleAuthority ||
        candidateAccountId !== CANDIDATE_ACCOUNT_ID ||
        candidateScriptName !== CANDIDATE_EXECUTOR_SCRIPT ||
        !candidateTransactionDigest ||
        candidateDeployAuthority.capabilityDigest !== candidateTransactionDigest ||
        candidateScheduleAuthority.capabilityDigest !== candidateTransactionDigest))
  ) {
    return null;
  }

  let responseKey: CryptoKey;
  let stateManifestKey: CryptoKey;
  try {
    responseKey = await crypto.subtle.importKey("raw", responseKeyBytes, "AES-GCM", false, ["encrypt"]);
    stateManifestKey = await crypto.subtle.importKey("raw", stateManifestPublicKey, "Ed25519", false, ["verify"]);
  } catch {
    return null;
  }

  const operationStore = createOperationStoreAdapter(operationNamespace);
  let candidateTargetDigest: string | null = null;
  if (candidateLifecycleRequested) {
    try {
      candidateTargetDigest = await candidateLifecycleTargetDigest(
        candidateAccountId as typeof CANDIDATE_ACCOUNT_ID,
        candidateScriptName as typeof CANDIDATE_EXECUTOR_SCRIPT,
      );
    } catch {
      return null;
    }
  }
  const roleAuthorities = candidateLifecycleRequested
    ? [migrationAuthority, candidateDeployAuthority!, candidateScheduleAuthority!]
    : [migrationAuthority];
  return {
    expectedAudience,
    roleAuthorities,
    replayStore: createReplayStoreAdapter(replayNamespace),
    execute: (body, envelope, authority) => {
      if (
        envelope.role === METADATA_MIGRATION_EXECUTOR_ROLE &&
        authority.role === METADATA_MIGRATION_EXECUTOR_ROLE
      ) {
        return executeMetadataMigration(
          body,
          envelope,
          authority,
          responseKey,
          stateManifestKey,
          operationStore,
          imageDigest,
          configDigest,
          now ?? Date.now(),
        );
      }
      if (
        candidateLifecycleRequested &&
        candidateTargetDigest &&
        candidateTransactionDigest &&
        candidateAccountId === CANDIDATE_ACCOUNT_ID &&
        candidateScriptName === CANDIDATE_EXECUTOR_SCRIPT &&
        (authority.role === CANDIDATE_DEPLOY_ROLE ||
          authority.role === CANDIDATE_SCHEDULE_ROLE)
      ) {
        return executeCandidateLifecycleAuthorization(body, envelope, authority, {
          accountId: candidateAccountId,
          scriptName: candidateScriptName,
          transactionDigest: candidateTransactionDigest,
          targetDigest: candidateTargetDigest,
          executorImageDigest: imageDigest,
          executorConfigDigest: configDigest,
          operations: operationStore,
          ...(now === undefined ? {} : { now }),
        });
      }
      throw new Error("executor role unavailable");
    },
    ...(now === undefined ? {} : { now }),
  };
}

export async function handleSecurityExecutorRequest(request: Request, env: SecurityExecutorEnv): Promise<Response> {
  const options = await buildSecurityExecutorOptions(env);
  if (!options) return emptyResponse(503);
  try {
    return await handlePrivateExecutorEnvelope(request, options);
  } catch {
    return emptyResponse(503);
  }
}
const worker = {
  fetch: handleSecurityExecutorRequest,
  async scheduled(_controller: ScheduledController, env: SecurityExecutorEnv): Promise<void> {
    const replayNamespace = env?.EXECUTOR_REPLAY;
    const operationNamespace = env?.EXECUTOR_OPERATIONS;
    if (
      !hasReplayNamespace(replayNamespace) ||
      !hasOperationNamespace(operationNamespace)
    ) {
      throw new Error("executor maintenance unavailable");
    }

    try {
      const replayResult = await replayNamespace
        .getByName(SECURITY_EXECUTOR_REPLAY_OBJECT_NAME)
        .sweep(Date.now(), DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT);
      const removed = replayResult?.removed;
      const nextAfter = replayResult?.nextAfter;
      if (
        !replayResult ||
        typeof replayResult !== "object" ||
        replayResult.status !== "swept" ||
        typeof removed !== "number" ||
        !Number.isSafeInteger(removed) ||
        removed < 0 ||
        (nextAfter !== null && typeof nextAfter !== "string")
      ) {
        throw new Error("invalid replay sweep result");
      }

      const operationResult = await operationNamespace
        .getByName(EXECUTOR_OPERATION_OBJECT_NAME)
        .watchdog(Date.now());
      if (
        !operationResult ||
        !Array.isArray(operationResult.marked_timeout) ||
        !Array.isArray(operationResult.terminalized) ||
        (operationResult.next_alarm_at !== null &&
          !Number.isSafeInteger(operationResult.next_alarm_at))
      ) {
        throw new Error("invalid operation watchdog result");
      }
    } catch {
      throw new Error("executor maintenance unavailable");
    }
  },
};
export default worker;


async function executeMetadataMigration(
  body: Uint8Array,
  envelope: ExecutorEnvelope,
  authority: PrivateExecutorRoleAuthority,
  responseKey: CryptoKey,
  stateManifestKey: CryptoKey,
  operationStore: ExecutorOperationStore,
  imageDigest: string,
  configDigest: string,
  now: number,
): Promise<Uint8Array> {
  const metadata = parseMetadataMigrationRequest(body, envelope);
  if (!metadata) throw new Error("invalid migration metadata");
  if (
    envelope.manifest_digest !== authority.capabilityDigest ||
    metadata.manifest_digest !== authority.capabilityDigest
  ) {
    throw new Error("invalid executor capability authority");
  }
  if (!(await verifyStateManifestAuthority(metadata, envelope, stateManifestKey, now))) {
    throw new Error("invalid state manifest authority");
  }

  const encoder = new TextEncoder();
  const startedAt = now;
  const invocationDigest = await sha256Digest(
    encoder.encode(`${envelope.nonce}\u0000${envelope.signature}`),
  );
  const invocationID = `inv-${invocationDigest.slice("sha256:".length)}`;
  const scheduleDigest = await sha256Digest(
    encoder.encode(
      `skret/executor-client-authority/v1\u0000${authority.role}\u0000${authority.generation}\u0000${authority.notAfter}\u0000${authority.capabilityDigest}\u0000${metadata.manifest_digest}`,
    ),
  );
  const generation = `authority-${authority.generation}-manifest-${metadata.manifest_digest.slice("sha256:".length)}`;
  const sourceDigest = `sha256:${metadata.source_hash}`;
  const operationFingerprint = await executorOperationFingerprint({
    schedule_digest: scheduleDigest,
    exclusive: false,
    generation,
    source_digest: sourceDigest,
    target_digest: metadata.manifest_digest,
    config_digest: configDigest,
    image_digest: imageDigest,
  });
  const operation = await operationStore.begin(
    {
      operation_id: metadata.operation_id,
      schedule_digest: scheduleDigest,
      exclusive: false,
      invocation_id: invocationID,
      fingerprint: operationFingerprint,
      generation,
      source_digest: sourceDigest,
      target_digest: metadata.manifest_digest,
      config_digest: configDigest,
      deadline_at: Math.min(authority.notAfter, startedAt + 14 * 60 * 1000),
    },
    startedAt,
  );

  if (operation.status === "existing" && operation.operation.status === "succeeded") {
    const storedResult = await operationStore.readResult(metadata.operation_id);
    if (!storedResult) throw new Error("executor operation result unavailable");
    return encryptMetadataAcknowledgement(storedResult, envelope, responseKey);
  }
  if (operation.status !== "started") throw new Error("executor operation unavailable");

  const redactedResult = encoder.encode(
    JSON.stringify({
      operation_id: metadata.operation_id,
      target: metadata.target,
      manifest_digest: metadata.manifest_digest,
      source_hash: metadata.source_hash,
      source_size: metadata.source_size,
      status: "accepted",
    }),
  );
  try {
    await operationStore.complete(
      metadata.operation_id,
      invocationID,
      "succeeded",
      await sha256Digest(redactedResult),
      now,
      redactedResult,
    );
  } catch (error) {
    try {
      await operationStore.complete(
        metadata.operation_id,
        invocationID,
        "failed",
        null,
        now,
      );
    } catch {
      // The watchdog retains the active operation when terminal persistence
      // is unavailable; never report a false acknowledgement.
    }
    throw error;
  }
  return encryptMetadataAcknowledgement(redactedResult, envelope, responseKey);
}

async function encryptMetadataAcknowledgement(
  redactedResult: Uint8Array,
  envelope: ExecutorEnvelope,
  responseKey: CryptoKey,
): Promise<Uint8Array> {
  const iv = new Uint8Array(AES_GCM_IV_BYTES);
  crypto.getRandomValues(iv);
  const additionalData = new TextEncoder().encode(
    `${METADATA_ACK_AAD_PREFIX}|${envelope.audience}|${envelope.role}|${envelope.manifest_digest}|${envelope.nonce}`,
  );
  let ciphertext: ArrayBuffer;
  try {
    ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData },
      responseKey,
      redactedResult,
    );
  } catch {
    throw new Error("metadata acknowledgement unavailable");
  }

  return new TextEncoder().encode(
    JSON.stringify({
      version: 1,
      algorithm: "AES-GCM",
      iv: encodeBase64Url(iv),
      ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
    }),
  );
}

function parseMetadataMigrationRequest(
  body: Uint8Array,
  envelope: ExecutorEnvelope,
): MetadataMigrationRequest | null {
  if (body.byteLength === 0 || body.byteLength > MAX_METADATA_MIGRATION_BODY_BYTES) return null;

  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
    if (hasDuplicateJsonKeys(text)) return null;
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (text.length > MAX_METADATA_MIGRATION_BODY_BYTES || !isRecord(parsed)) return null;

  const expectedFields = [
    "operation_id",
    "state_path",
    "journal_path",
    "manifest_digest",
    "target",
    "source_hash",
    "source_size",
    "state_manifest",
  ];
  const keys = Object.keys(parsed);
  if (keys.length !== expectedFields.length || expectedFields.some((field) => !Object.prototype.hasOwnProperty.call(parsed, field))) {
    return null;
  }

  const operationID = parsed.operation_id;
  const statePath = parsed.state_path;
  const journalPath = parsed.journal_path;
  const manifestDigest = parsed.manifest_digest;
  const target = parsed.target;
  const sourceHash = parsed.source_hash;
  const sourceSize = parsed.source_size;
  const stateManifest = decodeStateManifestBase64(parsed.state_manifest);
  if (
    typeof operationID !== "string" ||
    !OPERATION_ID_PATTERN.test(operationID) ||
    typeof statePath !== "string" ||
    !validMetadataPath(statePath) ||
    typeof journalPath !== "string" ||
    !validMetadataPath(journalPath) ||
    typeof manifestDigest !== "string" ||
    !SHA256_DIGEST_PATTERN.test(manifestDigest) ||
    manifestDigest !== envelope.manifest_digest ||
    target !== "v2" ||
    typeof sourceHash !== "string" ||
    !SHA256_HEX_PATTERN.test(sourceHash) ||
    typeof sourceSize !== "number" ||
    !Number.isSafeInteger(sourceSize) ||
    sourceSize < 0 ||
    sourceSize > MAX_METADATA_MIGRATION_SOURCE_SIZE ||
    stateManifest === null
  ) {
    return null;
  }

  return {
    operation_id: operationID,
    state_path: statePath,
    journal_path: journalPath,
    manifest_digest: manifestDigest,
    target,
    source_hash: sourceHash,
    source_size: sourceSize,
    state_manifest: stateManifest,
  };
}

interface ParsedStateManifestFile {
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
}

interface ParsedStateManifest {
  readonly role: string;
  readonly audience: string;
  readonly source_root: string;
  readonly files: ParsedStateManifestFile[];
  readonly signature: Uint8Array;
  readonly canonicalBytes: Uint8Array;
  readonly digest: string;
  readonly expiresAtMs: number;
}

async function verifyStateManifestAuthority(
  metadata: MetadataMigrationRequest,
  envelope: ExecutorEnvelope,
  stateManifestKey: CryptoKey,
  now: number,
): Promise<boolean> {
  const manifest = await parseStateManifest(metadata.state_manifest, envelope, now);
  if (!manifest || manifest.digest !== envelope.manifest_digest || manifest.digest !== metadata.manifest_digest) return false;

  const matchingRows = manifest.files.filter((file) => file.path === relativeManifestPath(manifest.source_root, metadata.state_path));
  if (matchingRows.length !== 1) return false;
  const row = matchingRows[0];
  if (
    joinManifestPath(manifest.source_root, row.path) !== metadata.state_path ||
    row.sha256 !== metadata.source_hash ||
    row.size !== metadata.source_size
  ) {
    return false;
  }

  try {
    return await crypto.subtle.verify("Ed25519", stateManifestKey, manifest.signature, manifest.canonicalBytes);
  } catch {
    return false;
  }
}

async function parseStateManifest(
  bytes: Uint8Array,
  envelope: ExecutorEnvelope,
  now: number,
): Promise<ParsedStateManifest | null> {
  if (
    bytes.byteLength === 0 ||
    bytes.byteLength > MAX_STATE_MANIFEST_BYTES ||
    (bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
  ) {
    return null;
  }

  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
    if (hasDuplicateJsonKeys(text)) return null;
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;

  const expectedFields = ["version", "role", "audience", "source_root", "files", "nonce", "expires_at", "signature"];
  const keys = Object.keys(parsed);
  if (keys.length !== expectedFields.length || expectedFields.some((field) => !Object.prototype.hasOwnProperty.call(parsed, field))) {
    return null;
  }

  const role = parsed.role;
  const audience = parsed.audience;
  const sourceRoot = parsed.source_root;
  const nonce = parsed.nonce;
  const expiresAt = parseStateManifestRFC3339(parsed.expires_at);
  const signature = decodeStandardBase64(parsed.signature, 64);
  if (
    parsed.version !== 1 ||
    typeof role !== "string" ||
    !validStateManifestText(role) ||
    role !== envelope.role ||
    typeof audience !== "string" ||
    !validStateManifestText(audience) ||
    audience !== envelope.audience ||
    typeof sourceRoot !== "string" ||
    !validCanonicalAbsolutePath(sourceRoot, true) ||
    typeof nonce !== "string" ||
    !validStateManifestText(nonce) ||
    !expiresAt ||
    expiresAt.expiresAtMs <= now ||
    expiresAt.expiresAtMs - now > MAX_STATE_MANIFEST_TTL_MS ||
    signature === null ||
    !Array.isArray(parsed.files) ||
    parsed.files.length === 0
  ) {
    return null;
  }

  const files: ParsedStateManifestFile[] = [];
  let previousPath = "";
  for (const value of parsed.files) {
    if (!isRecord(value)) return null;
    const rowKeys = Object.keys(value);
    if (
      rowKeys.length !== 3 ||
      !Object.prototype.hasOwnProperty.call(value, "path") ||
      !Object.prototype.hasOwnProperty.call(value, "size") ||
      !Object.prototype.hasOwnProperty.call(value, "sha256")
    ) {
      return null;
    }
    const path = value.path;
    const size = value.size;
    const sha256 = value.sha256;
    if (
      typeof path !== "string" ||
      !validStateManifestRelativePath(path) ||
      (previousPath !== "" && compareUTF8(previousPath, path) >= 0) ||
      typeof size !== "number" ||
      !Number.isSafeInteger(size) ||
      size < 0 ||
      typeof sha256 !== "string" ||
      !SHA256_HEX_PATTERN.test(sha256)
    ) {
      return null;
    }
    files.push({ path, size, sha256 });
    previousPath = path;
  }

  const signingDocument = {
    version: 1,
    role,
    audience,
    source_root: sourceRoot,
    files,
    nonce,
    expires_at: expiresAt.canonical,
  };
  const canonicalBytes = canonicalStateManifestBytes(signingDocument);
  let digest: string;
  try {
    digest = `sha256:${await sha256Hex(canonicalBytes)}`;
  } catch {
    return null;
  }
  return {
    role,
    audience,
    source_root: sourceRoot,
    files,
    signature,
    canonicalBytes,
    digest,
    expiresAtMs: expiresAt.expiresAtMs,
  };
}

function decodeStateManifestBase64(value: unknown): Uint8Array | null {
  return decodeStandardBase64(value, undefined, MAX_STATE_MANIFEST_BYTES);
}

function decodeStandardBase64(value: unknown, expectedLength?: number, maxLength?: number): Uint8Array | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !STANDARD_BASE64_PATTERN.test(value) ||
    (maxLength !== undefined && value.length > Math.ceil(maxLength / 3) * 4)
  ) {
    return null;
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    return null;
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (toBase64(decoded) !== value || (expectedLength !== undefined && decoded.byteLength !== expectedLength)) return null;
  if (maxLength !== undefined && decoded.byteLength > maxLength) return null;
  return decoded;
}

function validStateManifestText(value: string): boolean {
  return value.length > 0 && value.length <= MAX_METADATA_TEXT_LENGTH && value.trim() === value && !CONTROL_CHARACTER_PATTERN.test(value);
}

function validStateManifestRelativePath(value: string): boolean {
  if (
    value.length === 0 ||
    value.length > MAX_METADATA_TEXT_LENGTH ||
    value.trim() !== value ||
    value.startsWith("/") ||
    value.endsWith("/") ||
    value.includes("\\") ||
    value.includes(":") ||
    CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    return false;
  }
  const components = value.split("/");
  return components.every((component) => component.length > 0 && component !== "." && component !== "..");
}

function validCanonicalAbsolutePath(value: string, allowRoot: boolean): boolean {
  if (
    value.length === 0 ||
    value.length > MAX_METADATA_TEXT_LENGTH ||
    value.trim() !== value ||
    CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    return false;
  }
  if (POSIX_CANONICAL_ABSOLUTE_PATH_PATTERN.test(value)) {
    if (value === "/") return allowRoot;
    return value.split("/").slice(1).every((component) => component.length > 0 && component !== "." && component !== "..");
  }
  if (WINDOWS_CANONICAL_ABSOLUTE_PATH_PATTERN.test(value)) {
    if (value.length === 3) return allowRoot;
    const components = value.slice(3).split("\\");
    return components.every((component) => component.length > 0 && component !== "." && component !== "..");
  }
  if (UNC_CANONICAL_ABSOLUTE_PATH_PATTERN.test(value)) {
    const components = value.slice(2).split("\\");
    if (components.length === 2) return allowRoot;
    return components.every((component) => component.length > 0 && component !== "." && component !== "..");
  }
  return false;
}

function joinManifestPath(root: string, relative: string): string {
  if (root.startsWith("/")) return `${root === "/" ? "" : root}/${relative}`;
  const separator = root.endsWith("\\") ? "" : "\\";
  return `${root}${separator}${relative.replaceAll("/", "\\")}`;
}

function relativeManifestPath(root: string, absolute: string): string {
  if (root.startsWith("/")) {
    const prefix = `${root === "/" ? "" : root}/`;
    if (!absolute.startsWith(prefix)) return "";
    return absolute.slice(prefix.length);
  }
  const prefix = `${root}${root.endsWith("\\") ? "" : "\\"}`;
  if (!absolute.startsWith(prefix)) return "";
  return absolute.slice(prefix.length).replaceAll("\\", "/");
}

function compareUTF8(left: string, right: string): number {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return leftBytes[index] - rightBytes[index];
  }
  return leftBytes.length - rightBytes.length;
}

interface ParsedStateManifestExpiry {
  readonly expiresAtMs: number;
  readonly canonical: string;
}

function parseStateManifestRFC3339(value: unknown): ParsedStateManifestExpiry | null {
  if (typeof value !== "string") return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/u.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fraction = match[7] ?? "";
  const nanoseconds = Number((fraction + "000000000").slice(0, 9));
  const milliseconds = Math.floor(nanoseconds / 1_000_000);
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, milliseconds);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second ||
    date.getUTCMilliseconds() !== milliseconds
  ) {
    return null;
  }
  const offsetSign = match[9] === "-" ? -1 : 1;
  const offsetHours = Number(match[10] ?? "0");
  const offsetMinutes = Number(match[11] ?? "0");
  if (offsetHours > 23 || offsetMinutes > 59) return null;
  const expiresAtMs = date.getTime() - offsetSign * (offsetHours * 60 + offsetMinutes) * 60_000;
  if (!Number.isFinite(expiresAtMs)) return null;
  const canonicalFraction = String(nanoseconds).padStart(9, "0").replace(/0+$/u, "");
  const canonicalBase = new Date(expiresAtMs).toISOString().slice(0, 19);
  return {
    expiresAtMs,
    canonical: `${canonicalBase}${canonicalFraction ? `.${canonicalFraction}` : ""}Z`,
  };
}

function canonicalStateManifestBytes(document: Record<string, unknown>): Uint8Array {
  const canonicalEscapes: Record<string, string> = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
  };
  const encoded = JSON.stringify(document).replace(/[<>&\u2028\u2029]/gu, (character) => canonicalEscapes[character]);
  return new TextEncoder().encode(encoded);
}

type JsonScanResult = {
  readonly next: number;
  readonly duplicate: boolean;
};

function hasDuplicateJsonKeys(text: string): boolean {
  return scanJsonValue(text, 0)?.duplicate ?? false;
}

function scanJsonValue(text: string, start: number): JsonScanResult | null {
  const index = skipJsonWhitespace(text, start);
  const character = text[index];
  if (character === "{") return scanJsonObject(text, index);
  if (character === "[") return scanJsonArray(text, index);
  if (character === '"') {
    const next = scanJsonString(text, index);
    return next === null ? null : { next, duplicate: false };
  }

  for (const literal of ["true", "false", "null"]) {
    if (text.startsWith(literal, index)) return { next: index + literal.length, duplicate: false };
  }

  let next = index;
  while (next < text.length && !' \t\r\n,]}'.includes(text[next])) next += 1;
  return next === index ? null : { next, duplicate: false };
}

function scanJsonObject(text: string, start: number): JsonScanResult | null {
  let index = start + 1;
  const keys = new Set<string>();
  index = skipJsonWhitespace(text, index);
  if (text[index] === "}") return { next: index + 1, duplicate: false };

  while (index < text.length) {
    const keyStart = index;
    const keyEnd = scanJsonString(text, keyStart);
    if (keyEnd === null) return null;
    let key: unknown;
    try {
      key = JSON.parse(text.slice(keyStart, keyEnd));
    } catch {
      return null;
    }
    if (typeof key !== "string") return null;
    if (keys.has(key)) return { next: keyEnd, duplicate: true };
    keys.add(key);

    index = skipJsonWhitespace(text, keyEnd);
    if (text[index] !== ":") return null;
    const value = scanJsonValue(text, index + 1);
    if (value === null) return null;
    if (value.duplicate) return value;

    index = skipJsonWhitespace(text, value.next);
    if (text[index] === "}") return { next: index + 1, duplicate: false };
    if (text[index] !== ",") return null;
    index = skipJsonWhitespace(text, index + 1);
  }
  return null;
}

function scanJsonArray(text: string, start: number): JsonScanResult | null {
  let index = skipJsonWhitespace(text, start + 1);
  if (text[index] === "]") return { next: index + 1, duplicate: false };

  while (index < text.length) {
    const value = scanJsonValue(text, index);
    if (value === null) return null;
    if (value.duplicate) return value;
    index = skipJsonWhitespace(text, value.next);
    if (text[index] === "]") return { next: index + 1, duplicate: false };
    if (text[index] !== ",") return null;
    index = skipJsonWhitespace(text, index + 1);
  }
  return null;
}

function scanJsonString(text: string, start: number): number | null {
  if (text[start] !== '"') return null;
  let index = start + 1;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code < 0x20) return null;
    if (text[index] === '"') return index + 1;
    if (text[index] === "\\") {
      index += 2;
      continue;
    }
    index += 1;
  }
  return null;
}

function skipJsonWhitespace(text: string, start: number): number {
  let index = start;
  while (index < text.length && ' \t\r\n'.includes(text[index])) index += 1;
  return index;
}

function validMetadataPath(value: string): boolean {
  return validCanonicalAbsolutePath(value, false);
}

function parseExecutorClientAuthorities(
  value: unknown,
  now: number,
): readonly PrivateExecutorRoleAuthorityBinding[] | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_EXECUTOR_CLIENT_PUBLIC_KEYS_JSON_LENGTH ||
    value.trim() !== value ||
    hasDuplicateJsonKeys(value)
  ) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;

  const entries = Object.entries(parsed);
  if (entries.length === 0 || entries.length > MAX_PRIVATE_EXECUTOR_ROLES) return null;

  const roleAuthorities: PrivateExecutorRoleAuthorityBinding[] = [];
  const expectedFields = EXECUTOR_CLIENT_AUTHORITY_FIELDS;
  for (const [role, candidate] of entries) {
    if (readConfigText(role) === null || !isRecord(candidate)) return null;
    const fields = Object.keys(candidate);
    if (
      fields.length !== expectedFields.length ||
      expectedFields.some((field) => !Object.prototype.hasOwnProperty.call(candidate, field))
    ) {
      return null;
    }

    const publicKey = decodeStandardBase64(candidate.public_key, ED25519_PUBLIC_KEY_BYTES);
    const expiry = typeof candidate.not_after === "string"
      ? parseStateManifestRFC3339(candidate.not_after)
      : null;
    if (
      publicKey === null ||
      typeof candidate.generation !== "number" ||
      !Number.isSafeInteger(candidate.generation) ||
      candidate.generation <= 0 ||
      expiry === null ||
      expiry.expiresAtMs <= now ||
      expiry.expiresAtMs - now > MAX_EXECUTOR_CLIENT_AUTHORITY_HORIZON_MS ||
      typeof candidate.capability_digest !== "string" ||
      !SHA256_DIGEST_PATTERN.test(candidate.capability_digest)
    ) {
      return null;
    }

    for (const existing of roleAuthorities) {
      let duplicate = true;
      for (let index = 0; index < publicKey.byteLength; index += 1) {
        if (publicKey[index] !== existing.publicKey[index]) {
          duplicate = false;
          break;
        }
      }
      if (duplicate) return null;
    }
    roleAuthorities.push({
      role,
      publicKey,
      generation: candidate.generation,
      notAfter: expiry.expiresAtMs,
      capabilityDigest: candidate.capability_digest,
    });
  }
  return roleAuthorities;
}

function readConfigText(value: unknown): string | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_CONFIG_TEXT_LENGTH ||
    value.trim() !== value ||
    CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    return null;
  }
  return value;
}

function readConfigDigest(value: unknown): string | null {
  return typeof value === "string" && SHA256_DIGEST_PATTERN.test(value)
    ? value
    : null;
}

function decodeConfiguredBytes(value: unknown, expectedLength: number): Uint8Array | null {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) return null;

  if (value.length === expectedLength * 2 && CONFIG_HEX_PATTERN.test(value)) {
    const decoded = new Uint8Array(expectedLength);
    for (let index = 0; index < expectedLength; index += 1) {
      decoded[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
    }
    return decoded;
  }
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const unpadded = normalized.replace(/=+$/u, "");
  if (!/^[A-Za-z0-9+/]*$/u.test(unpadded) || unpadded.length % 4 === 1) return null;
  const padded = unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (decoded.byteLength !== expectedLength) return null;
  const canonicalStandard = toBase64(decoded);
  const canonicalStandardRaw = canonicalStandard.replace(/=+$/u, "");
  const canonicalUrl = encodeBase64Url(decoded);
  if (value !== canonicalStandard && value !== canonicalStandardRaw && value !== canonicalUrl) return null;
  return decoded;
}
function hasOperationNamespace(value: unknown): value is DurableObjectNamespace<SecurityExecutorOperations> {
  if (!value || typeof value !== "object" || !("getByName" in value)) return false;
  return typeof value.getByName === "function";
}

function hasReplayNamespace(value: unknown): value is DurableObjectNamespace<SecurityExecutorReplay> {
  if (!value || typeof value !== "object" || !("getByName" in value)) return false;
  return typeof value.getByName === "function";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Digest(bytes: Uint8Array): Promise<string> {
  return `sha256:${await sha256Hex(bytes)}`;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function encodeBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function emptyResponse(status: number): Response {
  return new Response(null, { status, headers: SECURITY_HEADERS });
}
