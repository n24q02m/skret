import {
  ProviderEnvelopeLifecycle,
  canonicalSourceIdentity,
  type PreparedProviderGeneration,
  type SourceIdentity,
} from "./executor-provider-crypto";
import {
  canonicalCloudflareTarget,
  canonicalGitHubTarget,
  canonicalTargetSet,
  createTargetOperation,
  type CanonicalTargetIdentity,
  type TargetOperation,
  type TargetWriteResult,
} from "./executor-provider-clients";
import type {
  ProviderOperationRecord,
  ProviderOperationStart,
  ProviderOperationStore,
} from "./provider-operation-store";
import type { ExecutorEnvelope } from "./executor-envelope-verifier";
import type {
  PrivateExecutorHandlerOptions,
  PrivateExecutorReplayStore,
} from "./private-executor-handler";

export const PROVIDER_DISPATCH_SCHEMA = "skret/executor/provider-dispatch/v1" as const;
export const PROVIDER_VERIFICATION_SCHEMA = "skret/executor/provider-verification/v1" as const;
export const PROVIDER_DISPATCH_ROLE = "provider-sync";
export const PROVIDER_VERIFICATION_ROLE = "provider-sync-verification";
export const PROVIDER_EXECUTOR_ROLES = Object.freeze([
  PROVIDER_DISPATCH_ROLE,
  PROVIDER_VERIFICATION_ROLE,
] as const);

const MAX_PROVIDER_BODY_BYTES = 256 * 1024;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const GENERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SAFE_REFERENCE = /^[\u0021-\u007e]{1,2048}$/u;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const DISPATCH_FIELDS = [
  "schema",
  "operation",
  "invocation_id",
  "source_identity",
  "target",
  "kms_key_reference",
] as const;
const OPERATION_FIELDS = [
  "operation_id",
  "generation",
  "source_fingerprint",
  "source_digest",
  "target_identity",
  "target_digest",
  "old_generation_ref",
  "current_generation_ref",
  "intended_generation_ref",
  "kms_envelope_ref",
  "operator_identity",
  "capability",
  "deadline_at",
] as const;
const SOURCE_FIELDS = [
  "partition",
  "account",
  "region",
  "fullParameterName",
  "version",
  "lifecycleLabel",
] as const;
const VERIFICATION_FIELDS = [
  "schema",
  "operation_id",
  "provider_state_oid",
  "canary",
  "postconditions",
  "acknowledged_target_identity",
] as const;

export class ProviderExecutorInvalidRequestError extends Error {
  constructor() {
    super("provider executor invalid request");
    this.name = "ProviderExecutorInvalidRequestError";
  }
}

export class ProviderExecutorUnavailableError extends Error {
  constructor() {
    super("provider executor unavailable");
    this.name = "ProviderExecutorUnavailableError";
  }
}

export interface ProviderTargetClient {
  upsertSecret(input: {
    readonly operation: TargetOperation;
    readonly value: Uint8Array;
  }): Promise<TargetWriteResult>;
}

export interface ProviderExecutorDependencies {
  readonly operations: ProviderOperationStore;
  readonly lifecycle: ProviderEnvelopeLifecycle;
  readonly targetClient: (identity: CanonicalTargetIdentity) => ProviderTargetClient | null;
  readonly now?: () => number;
}

interface ProviderDispatchDocument {
  readonly schema: typeof PROVIDER_DISPATCH_SCHEMA;
  readonly operation: ProviderOperationStart;
  readonly invocation_id: string;
  readonly source_identity: SourceIdentity;
  readonly target: CanonicalTargetIdentity;
  readonly kms_key_reference: string;
}

export interface ProviderPrivateExecutorOptionsInput {
  readonly expectedAudience: string;
  readonly publicKey: Uint8Array;
  readonly replayStore: PrivateExecutorReplayStore;
  readonly dependencies: ProviderExecutorDependencies;
  readonly now?: number;
}

export function buildProviderPrivateExecutorOptions(
  input: ProviderPrivateExecutorOptionsInput,
): PrivateExecutorHandlerOptions | null {
  try {
    if (
      !input ||
      typeof input !== "object" ||
      typeof input.expectedAudience !== "string" ||
      input.expectedAudience.length === 0 ||
      input.expectedAudience.length > 256 ||
      input.expectedAudience.trim() !== input.expectedAudience ||
      /[\u0000-\u001f\u007f]/u.test(input.expectedAudience) ||
      !(input.publicKey instanceof Uint8Array) ||
      input.publicKey.byteLength !== 32 ||
      !input.replayStore ||
      typeof input.replayStore.consume !== "function" ||
      (input.now !== undefined && (!Number.isSafeInteger(input.now) || input.now < 0))
    ) {
      return null;
    }
    validateDependencies(input.dependencies);
    return {
      expectedAudience: input.expectedAudience,
      expectedRoles: PROVIDER_EXECUTOR_ROLES,
      publicKey: input.publicKey.slice(),
      replayStore: input.replayStore,
      execute: (body, envelope) =>
        executeProviderExecutorRole(body, envelope, input.dependencies),
      ...(input.now === undefined ? {} : { now: input.now }),
    };
  } catch {
    return null;
  }
}

export async function executeProviderExecutorRole(
  body: Uint8Array,
  envelope: Pick<ExecutorEnvelope, "role">,
  dependencies: ProviderExecutorDependencies,
): Promise<Uint8Array> {
  if (envelope.role === PROVIDER_DISPATCH_ROLE) {
    return executeProviderDispatchBody(body, dependencies);
  }
  if (envelope.role === PROVIDER_VERIFICATION_ROLE) {
    return executeProviderVerificationBody(body, dependencies);
  }
  throw new ProviderExecutorInvalidRequestError();
}

interface ProviderVerificationDocument {
  readonly schema: typeof PROVIDER_VERIFICATION_SCHEMA;
  readonly operation_id: string;
  readonly provider_state_oid: string;
  readonly canary: "passed" | "failed";
  readonly postconditions: "passed" | "failed";
  readonly acknowledged_target_identity: string;
}

export async function executeProviderDispatchBody(
  body: Uint8Array,
  dependencies: ProviderExecutorDependencies,
): Promise<Uint8Array> {
  const document = await parseDispatchDocument(body);
  validateDependencies(dependencies);
  const now = readNow(dependencies);
  let targetSet;
  try {
    targetSet = await canonicalTargetSet([document.target]);
  } catch {
    throw new ProviderExecutorInvalidRequestError();
  }
  if (
    targetSet.digest !== document.operation.target_digest ||
    document.operation.target_identity !== document.target.canonical ||
    document.operation.capability !== document.target.capability ||
    document.operation.generation !== document.source_identity.lifecycleLabel ||
    document.operation.intended_generation_ref !== document.operation.generation ||
    document.operation.deadline_at <= now ||
    document.operation.deadline_at > now + 15 * 60_000 ||
    document.operation.kms_envelope_ref !== `provider-envelope:${document.operation.operation_id}`
  ) {
    throw new ProviderExecutorInvalidRequestError();
  }
  const client = dependencies.targetClient(document.target);
  if (client === null || typeof client.upsertSecret !== "function") {
    throw new ProviderExecutorInvalidRequestError();
  }

  let started;
  try {
    started = await dependencies.operations.start(document.operation, now);
  } catch {
    throw new ProviderExecutorUnavailableError();
  }
  if (started.status === "conflict") throw new ProviderExecutorInvalidRequestError();
  if (started.status === "fenced") return operationResponse(started.operation);
  if (started.status === "existing" && started.operation.status !== "prepared") {
    return operationResponse(started.operation);
  }

  let claimed;
  try {
    claimed = await dependencies.operations.claim(
      document.operation.operation_id,
      document.invocation_id,
      now,
    );
  } catch {
    throw new ProviderExecutorUnavailableError();
  }
  if (claimed === null) return readOperationResponse(document.operation.operation_id, dependencies);

  let prepared: PreparedProviderGeneration | undefined;
  try {
    prepared = await dependencies.lifecycle.getRetained(document.operation.operation_id);
    if (prepared === undefined) {
      prepared = await dependencies.lifecycle.prepare({
        operationId: document.operation.operation_id,
        generation: document.operation.generation,
        sourceIdentity: document.source_identity,
        targetSetDigest: targetSet.digest,
        expectedSourceDigest: document.operation.source_digest,
        keyReference: document.kms_key_reference,
        targetIdentities: [document.target.canonical],
        references: [{ kind: "target", id: document.target.canonical }],
      });
    } else if (!preparedMatches(prepared, document, targetSet.digest)) {
      return recordAmbiguousOutcome(
        document.operation.operation_id,
        document.invocation_id,
        "provider_envelope_binding_mismatch",
        dependencies,
        now,
      );
    }
  } catch {
    return recordAmbiguousOutcome(
      document.operation.operation_id,
      document.invocation_id,
      "provider_prepare_unavailable",
      dependencies,
      now,
    );
  }

  const operation = createTargetOperation({
    operationId: document.operation.operation_id,
    generation: document.operation.generation,
    target: document.target,
    contextDigest: prepared.envelope.contextDigest,
  });
  let result: TargetWriteResult;
  try {
    result = await dependencies.lifecycle.withDecryptedValue(prepared, (value) =>
      client.upsertSecret({ operation, value }),
    );
  } catch {
    return recordAmbiguousOutcome(
      document.operation.operation_id,
      document.invocation_id,
      "provider_dispatch_unavailable",
      dependencies,
      now,
    );
  }
  if (
    result.operationId !== document.operation.operation_id ||
    result.targetIdentity !== document.target.canonical ||
    (result.status === "applied" && result.providerStateOID === null) ||
    (result.status === "needs_reconciliation" && result.providerStateOID !== null)
  ) {
    return recordAmbiguousOutcome(
      document.operation.operation_id,
      document.invocation_id,
      "provider_response_binding_mismatch",
      dependencies,
      now,
    );
  }
  try {
    const record = await dependencies.operations.recordOutcome(
      document.operation.operation_id,
      document.invocation_id,
      result.status === "applied"
        ? {
            status: "committed",
            provider_state_oid: result.providerStateOID,
            canary: "unknown",
            postconditions: "unknown",
            error_code: null,
          }
        : {
            status: "unknown",
            provider_state_oid: null,
            canary: "unknown",
            postconditions: "unknown",
            error_code: "provider_response_ambiguous",
          },
      now,
    );
    return operationResponse(record);
  } catch {
    throw new ProviderExecutorUnavailableError();
  }
}

export async function executeProviderVerificationBody(
  body: Uint8Array,
  dependencies: ProviderExecutorDependencies,
): Promise<Uint8Array> {
  const document = parseVerificationDocument(body);
  validateDependencies(dependencies);
  const now = readNow(dependencies);
  let existing: ProviderOperationRecord | null;
  try {
    existing = await dependencies.operations.read(document.operation_id);
  } catch {
    throw new ProviderExecutorUnavailableError();
  }
  if (existing === null) throw new ProviderExecutorInvalidRequestError();
  if (existing.target_identity !== document.acknowledged_target_identity) {
    throw new ProviderExecutorInvalidRequestError();
  }
  let record: ProviderOperationRecord;
  try {
    record = await dependencies.operations.verify(
      document.operation_id,
      {
        provider_state_oid: document.provider_state_oid,
        canary: document.canary,
        postconditions: document.postconditions,
      },
      now,
    );
  } catch {
    throw new ProviderExecutorUnavailableError();
  }
  if (record.status !== "succeeded") return operationResponse(record);
  const cleanup = await dependencies.lifecycle.cleanup({
    operationId: record.operation_id,
    acknowledgements: [{
      targetIdentity: document.acknowledged_target_identity,
      acknowledged: true,
    }],
    canary: document.canary,
    postconditions: document.postconditions,
    explicitVerification: true,
  });
  return responseBytes({
    operation_id: record.operation_id,
    status: cleanup.status === "cleaned" ? "succeeded" : "succeeded_envelope_retained",
  });
}

async function parseDispatchDocument(body: Uint8Array): Promise<ProviderDispatchDocument> {
  const parsed = parseCanonicalBody(body);
  if (!exactFields(parsed, DISPATCH_FIELDS) || parsed.schema !== PROVIDER_DISPATCH_SCHEMA) {
    throw new ProviderExecutorInvalidRequestError();
  }
  const operation = parseExactObject(parsed.operation, OPERATION_FIELDS);
  const sourceInput = parseExactObject(parsed.source_identity, SOURCE_FIELDS);
  const targetInput = parseObject(parsed.target);
  let sourceIdentity: SourceIdentity;
  try {
    sourceIdentity = canonicalSourceIdentity(sourceInput as unknown as SourceIdentity);
  } catch {
    throw new ProviderExecutorInvalidRequestError();
  }
  if (JSON.stringify(sourceIdentity) !== JSON.stringify(sourceInput)) {
    throw new ProviderExecutorInvalidRequestError();
  }
  const target = canonicalTargetIdentity(targetInput);
  if (JSON.stringify(target) !== JSON.stringify(targetInput)) throw new ProviderExecutorInvalidRequestError();
  validateOperationShape(operation);
  if (typeof parsed.invocation_id !== "string" || !OPERATION_ID.test(parsed.invocation_id)) {
    throw new ProviderExecutorInvalidRequestError();
  }
  if (typeof parsed.kms_key_reference !== "string" || !SAFE_REFERENCE.test(parsed.kms_key_reference)) {
    throw new ProviderExecutorInvalidRequestError();
  }
  return {
    schema: PROVIDER_DISPATCH_SCHEMA,
    operation: operation as unknown as ProviderOperationStart,
    invocation_id: parsed.invocation_id,
    source_identity: sourceIdentity,
    target,
    kms_key_reference: parsed.kms_key_reference,
  };
}

function parseVerificationDocument(body: Uint8Array): ProviderVerificationDocument {
  const parsed = parseCanonicalBody(body);
  if (!exactFields(parsed, VERIFICATION_FIELDS) || parsed.schema !== PROVIDER_VERIFICATION_SCHEMA) {
    throw new ProviderExecutorInvalidRequestError();
  }
  if (
    typeof parsed.operation_id !== "string" ||
    !OPERATION_ID.test(parsed.operation_id) ||
    typeof parsed.provider_state_oid !== "string" ||
    !SAFE_REFERENCE.test(parsed.provider_state_oid) ||
    (parsed.canary !== "passed" && parsed.canary !== "failed") ||
    (parsed.postconditions !== "passed" && parsed.postconditions !== "failed") ||
    typeof parsed.acknowledged_target_identity !== "string" ||
    !SAFE_REFERENCE.test(parsed.acknowledged_target_identity)
  ) {
    throw new ProviderExecutorInvalidRequestError();
  }
  return parsed as unknown as ProviderVerificationDocument;
}

function parseCanonicalBody(body: Uint8Array): Record<string, unknown> {
  if (!(body instanceof Uint8Array) || body.byteLength === 0 || body.byteLength > MAX_PROVIDER_BODY_BYTES) {
    throw new ProviderExecutorInvalidRequestError();
  }
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
    parsed = JSON.parse(text);
  } catch {
    throw new ProviderExecutorInvalidRequestError();
  }
  const object = parseObject(parsed);
  if (JSON.stringify(object) !== text) throw new ProviderExecutorInvalidRequestError();
  return object;
}

function canonicalTargetIdentity(input: Record<string, unknown>): CanonicalTargetIdentity {
  try {
    if (input.provider === "github") {
      return canonicalGitHubTarget({
        owner: input.owner as string,
        repository: input.repository as string,
        secretName: input.secretName as string,
        environment: input.environment as string,
        capability: input.capability as never,
      });
    }
    if (input.provider === "cloudflare") {
      return canonicalCloudflareTarget({
        accountId: input.accountId as string,
        resourceKind: input.resourceKind as never,
        resourceName: input.resourceName as string,
        secretName: input.secretName as string,
        environment: input.environment as string,
        capability: input.capability as never,
      });
    }
  } catch {
    throw new ProviderExecutorInvalidRequestError();
  }
  throw new ProviderExecutorInvalidRequestError();
}

function validateOperationShape(operation: Record<string, unknown>): void {
  const stringFields = [
    operation.operation_id,
    operation.generation,
    operation.target_identity,
    operation.intended_generation_ref,
    operation.kms_envelope_ref,
    operation.operator_identity,
  ];
  if (stringFields.some((value) => typeof value !== "string" || !SAFE_REFERENCE.test(value))) {
    throw new ProviderExecutorInvalidRequestError();
  }
  if (!OPERATION_ID.test(operation.operation_id as string) || !GENERATION_ID.test(operation.generation as string)) {
    throw new ProviderExecutorInvalidRequestError();
  }
  for (const digest of [operation.source_fingerprint, operation.source_digest, operation.target_digest]) {
    if (typeof digest !== "string" || !SHA256_DIGEST.test(digest)) throw new ProviderExecutorInvalidRequestError();
  }
  for (const generation of [operation.old_generation_ref, operation.current_generation_ref]) {
    if (generation !== null && (typeof generation !== "string" || !GENERATION_ID.test(generation))) {
      throw new ProviderExecutorInvalidRequestError();
    }
  }
  if (
    operation.capability !== "owner_risk_gate" ||
    !Number.isSafeInteger(operation.deadline_at) ||
    (operation.deadline_at as number) < 0
  ) {
    throw new ProviderExecutorInvalidRequestError();
  }
}

function preparedMatches(
  prepared: PreparedProviderGeneration,
  document: ProviderDispatchDocument,
  targetSetDigest: string,
): boolean {
  return (
    prepared.operationId === document.operation.operation_id &&
    prepared.generation === document.operation.generation &&
    prepared.sourceDigest === document.operation.source_digest &&
    prepared.context.targetSetDigest === targetSetDigest &&
    prepared.keyReference === document.kms_key_reference &&
    prepared.targetIdentities.length === 1 &&
    prepared.targetIdentities[0] === document.target.canonical
  );
}

async function recordAmbiguousOutcome(
  operationID: string,
  invocationID: string,
  errorCode: string,
  dependencies: ProviderExecutorDependencies,
  now: number,
): Promise<Uint8Array> {
  try {
    return operationResponse(await dependencies.operations.recordOutcome(
      operationID,
      invocationID,
      {
        status: "unknown",
        provider_state_oid: null,
        canary: "unknown",
        postconditions: "unknown",
        error_code: errorCode,
      },
      now,
    ));
  } catch {
    throw new ProviderExecutorUnavailableError();
  }
}

async function readOperationResponse(
  operationID: string,
  dependencies: ProviderExecutorDependencies,
): Promise<Uint8Array> {
  try {
    const record = await dependencies.operations.read(operationID);
    if (record === null) throw new ProviderExecutorUnavailableError();
    return operationResponse(record);
  } catch (error) {
    if (error instanceof ProviderExecutorUnavailableError) throw error;
    throw new ProviderExecutorUnavailableError();
  }
}

function operationResponse(record: ProviderOperationRecord): Uint8Array {
  return responseBytes({ operation_id: record.operation_id, status: record.status });
}

function responseBytes(value: { readonly operation_id: string; readonly status: string }): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function validateDependencies(dependencies: ProviderExecutorDependencies): void {
  if (
    !dependencies ||
    typeof dependencies !== "object" ||
    !dependencies.operations ||
    !dependencies.lifecycle ||
    typeof dependencies.targetClient !== "function"
  ) {
    throw new ProviderExecutorUnavailableError();
  }
}

function readNow(dependencies: ProviderExecutorDependencies): number {
  const now = dependencies.now?.() ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0) throw new ProviderExecutorUnavailableError();
  return now;
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length && keys.every((key, index) => key === fields[index]);
}

function parseExactObject(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const object = parseObject(value);
  if (!exactFields(object, fields)) throw new ProviderExecutorInvalidRequestError();
  return object;
}

function parseObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProviderExecutorInvalidRequestError();
  }
  return value as Record<string, unknown>;
}
