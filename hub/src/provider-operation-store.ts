import type {
  ExecutorOperationStorage,
  ExecutorOperationTransaction,
} from "./executor-operation-store";

const OPERATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const GENERATION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const IDENTIFIER_PATTERN = /^[\u0021-\u007e]{1,2048}$/u;
const OID_PATTERN = /^[\u0021-\u007e]{1,2048}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const CONTROL_TEXT_PATTERN = /[\u0000-\u001f\u007f]/u;
const STANDARD_BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const MAX_PROVIDER_OPERATION_LIFETIME_MS = 15 * 60_000;
const MAX_CONTROL_DECISION_TTL_MS = 15 * 60_000;

const OPERATION_PREFIX = "private:provider-operation:";
const FENCE_PREFIX = "private:provider-operation-fence:";
const INVOCATION_PREFIX = "private:provider-invocation:";
const DECISION_PREFIX = "private:provider-decision:";
const LAST_SUCCESS_PREFIX = "private:provider-last-success:";
const ED25519_ALGORITHM = "Ed25519";
const CONTROL_DECISION_VERSION = 1;

const CANONICAL_HTML_ESCAPES: Record<string, string> = {
  "<": "\\u003c",
  ">": "\\u003e",
  "&": "\\u0026",
  "\u2028": "\\u2028",
  "\u2029": "\\u2029",
};

const START_FIELDS = [
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

const DECISION_FIELDS = [
  "version",
  "action",
  "operation_id",
  "generation",
  "source_fingerprint",
  "source_digest",
  "target_digest",
  "current_state_oid",
  "reason",
  "issuer",
  "nonce",
  "issued_at",
  "expires_at",
  "approval_nonce",
  "signature",
] as const;

export type ProviderOperationStatus =
  | "prepared"
  | "dispatching"
  | "awaiting_verification"
  | "cancel_requested"
  | "needs_reconciliation"
  | "cancel_needs_reconciliation"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "superseded";

export type ProviderOperationCapability =
  | "native_cas"
  | "enforced_exclusive"
  | "owner_risk_gate"
  | "blocked";

export type ProviderDispatchStatus = "committed" | "rejected" | "dropped" | "unknown";
export type ProviderVerificationStatus = "unknown" | "passed" | "failed";
export type ProviderControlAction =
  | "cancel"
  | "replay_once"
  | "confirm_applied"
  | "confirm_not_applied"
  | "supersede";

export interface ProviderOperationStart {
  readonly operation_id: string;
  readonly generation: string;
  readonly source_fingerprint: string;
  readonly source_digest: string;
  readonly target_identity: string;
  readonly target_digest: string;
  readonly old_generation_ref: string | null;
  readonly current_generation_ref: string | null;
  readonly intended_generation_ref: string;
  readonly kms_envelope_ref: string;
  readonly operator_identity: string;
  readonly capability: ProviderOperationCapability;
  readonly deadline_at: number;
}

export interface ProviderOperationRecord extends ProviderOperationStart {
  readonly status: ProviderOperationStatus;
  readonly created_at: number;
  readonly updated_at: number;
  readonly completed_at: number | null;
  readonly active_invocation_id: string | null;
  readonly attempt: number;
  readonly observed_state_oid: string | null;
  readonly canary: ProviderVerificationStatus;
  readonly postconditions: ProviderVerificationStatus;
  readonly failure_code: string | null;
}

export interface ProviderDispatchRequest extends ProviderOperationStart {
  readonly invocation_id: string;
  readonly attempt: number;
}

export interface ProviderDispatchResponse {
  readonly status: ProviderDispatchStatus;
  readonly provider_state_oid: string | null;
  readonly canary: ProviderVerificationStatus;
  readonly postconditions: ProviderVerificationStatus;
  readonly error_code: string | null;
}

export interface ProviderInvocationOutcome extends ProviderDispatchResponse {
  readonly operation_id: string;
  readonly invocation_id: string;
  readonly observed_at: number;
}

export interface ProviderVerification {
  readonly provider_state_oid: string;
  readonly canary: "passed" | "failed";
  readonly postconditions: "passed" | "failed";
}

export interface ProviderLastSuccess {
  readonly operation_id: string;
  readonly generation: string;
  readonly source_fingerprint: string;
  readonly source_digest: string;
  readonly target_identity: string;
  readonly target_digest: string;
  readonly provider_state_oid: string;
  readonly completed_at: number;
}

export interface ProviderControlDecision {
  readonly version: 1;
  readonly action: ProviderControlAction;
  readonly operation_id: string;
  readonly generation: string;
  readonly source_fingerprint: string;
  readonly source_digest: string;
  readonly target_digest: string;
  readonly current_state_oid: string | null;
  readonly reason: string;
  readonly issuer: string;
  readonly nonce: string;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly approval_nonce: string | null;
  readonly signature: string;
}

export interface ProviderOperationStoreOptions {
  readonly control_public_key?: Uint8Array;
  readonly expected_issuer?: string;
}

export type ProviderOperationStartResult =
  | { readonly status: "prepared"; readonly operation: ProviderOperationRecord }
  | { readonly status: "existing"; readonly operation: ProviderOperationRecord }
  | { readonly status: "fenced"; readonly operation: ProviderOperationRecord }
  | { readonly status: "conflict" };

export interface ProviderOperationTransaction extends ExecutorOperationTransaction {}
export type ProviderOperationStorage = ExecutorOperationStorage;

export interface ProviderOperationStore {
  start(request: ProviderOperationStart, now?: number): Promise<ProviderOperationStartResult>;
  claim(operationID: string, invocationID: string, now?: number): Promise<ProviderDispatchRequest | null>;
  recordOutcome(
    operationID: string,
    invocationID: string,
    response: ProviderDispatchResponse,
    now?: number,
  ): Promise<ProviderOperationRecord>;
  applyDecision(decision: ProviderControlDecision, now?: number): Promise<ProviderOperationRecord>;
  verify(operationID: string, verification: ProviderVerification, now?: number): Promise<ProviderOperationRecord>;
  read(operationID: string): Promise<ProviderOperationRecord | null>;
  readInvocationOutcome(operationID: string, invocationID: string): Promise<ProviderInvocationOutcome | null>;
  readLastSuccess(
    targetIdentity: string,
    targetDigest: string,
    sourceFingerprint: string,
  ): Promise<ProviderLastSuccess | null>;
}

export interface ProviderDispatcher {
  dispatch(request: ProviderDispatchRequest): Promise<ProviderDispatchResponse>;
}

export class ProviderOperationInvalidRequestError extends Error {
  constructor(message = "invalid provider operation") {
    super(message);
    this.name = "ProviderOperationInvalidRequestError";
  }
}

export class ProviderOperationDecisionRejectedError extends Error {
  constructor(_message?: string) {
    super("provider control decision rejected");
    this.name = "ProviderOperationDecisionRejectedError";
  }
}

export class ProviderOperationOutcomeConflictError extends Error {
  constructor() {
    super("provider invocation outcome conflict");
    this.name = "ProviderOperationOutcomeConflictError";
  }
}

export class ProviderOperationUnavailableError extends Error {
  constructor() {
    super("provider operation store unavailable");
    this.name = "ProviderOperationUnavailableError";
  }
}

export function canonicalProviderControlDecisionBytes(
  decision: Omit<ProviderControlDecision, "signature"> | ProviderControlDecision,
): Uint8Array {
  const document = {
    version: decision.version,
    action: decision.action,
    operation_id: decision.operation_id,
    generation: decision.generation,
    source_fingerprint: decision.source_fingerprint,
    source_digest: decision.source_digest,
    target_digest: decision.target_digest,
    current_state_oid: decision.current_state_oid,
    reason: decision.reason,
    issuer: decision.issuer,
    nonce: decision.nonce,
    issued_at: decision.issued_at,
    expires_at: decision.expires_at,
    approval_nonce: decision.approval_nonce,
  };
  const encoded = JSON.stringify(document).replace(/[<>&\u2028\u2029]/gu, (character) => CANONICAL_HTML_ESCAPES[character]);
  return new TextEncoder().encode(encoded);
}

export class DurableProviderOperationStore implements ProviderOperationStore {
  private readonly controlPublicKey: Uint8Array | undefined;
  private readonly expectedIssuer: string | undefined;

  constructor(
    private readonly storage: ProviderOperationStorage,
    options: ProviderOperationStoreOptions = {},
  ) {
    this.controlPublicKey = options.control_public_key?.slice();
    this.expectedIssuer = options.expected_issuer;
    if (this.expectedIssuer !== undefined) validateIdentifier(this.expectedIssuer);
    if (this.controlPublicKey !== undefined && this.controlPublicKey.byteLength !== 32) {
      throw new ProviderOperationInvalidRequestError("invalid provider control key");
    }
  }

  async start(request: ProviderOperationStart, now = Date.now()): Promise<ProviderOperationStartResult> {
    validateNow(now);
    validateStart(request, now);
    return this.storage.transaction(async (transaction) => {
      const existing = await transaction.get<ProviderOperationRecord>(operationKey(request.operation_id));
      if (existing) {
        if (!sameStart(existing, request)) return { status: "conflict" } as const;
        return { status: "existing", operation: copyRecord(existing) } as const;
      }

      const fence = await transaction.get<ProviderTargetFence>(fenceKey(request.target_identity));
      if (fence) {
        const fencedOperation = await transaction.get<ProviderOperationRecord>(operationKey(fence.operation_id));
        if (fencedOperation && unresolved(fencedOperation.status)) {
          return { status: "fenced", operation: copyRecord(fencedOperation) } as const;
        }
        await transaction.delete(fenceKey(request.target_identity));
      }

      const operation: ProviderOperationRecord = {
        ...request,
        status: "prepared",
        created_at: now,
        updated_at: now,
        completed_at: null,
        active_invocation_id: null,
        attempt: 0,
        observed_state_oid: null,
        canary: "unknown",
        postconditions: "unknown",
        failure_code: null,
      };
      await transaction.put(operationKey(request.operation_id), operation);
      await transaction.put(fenceKey(request.target_identity), {
        operation_id: request.operation_id,
        target_identity: request.target_identity,
        target_digest: request.target_digest,
      } satisfies ProviderTargetFence);
      return { status: "prepared", operation: copyRecord(operation) } as const;
    });
  }

  async claim(operationID: string, invocationID: string, now = Date.now()): Promise<ProviderDispatchRequest | null> {
    validateNow(now);
    validateOperationID(operationID);
    validateOperationID(invocationID);
    return this.storage.transaction(async (transaction) => {
      const key = operationKey(operationID);
      const current = await transaction.get<ProviderOperationRecord>(key);
      if (!current) throw new ProviderOperationInvalidRequestError("unknown provider operation");
      if (current.status !== "prepared") return null;
      if (current.capability === "blocked") {
        const blocked: ProviderOperationRecord = {
          ...current,
          status: "failed",
          updated_at: now,
          completed_at: now,
          failure_code: "capability_blocked",
        };
        await transaction.put(key, blocked);
        await releaseFence(transaction, blocked);
        return null;
      }
      if (now >= current.deadline_at) {
        const expired: ProviderOperationRecord = {
          ...current,
          status: "failed",
          updated_at: now,
          completed_at: now,
          failure_code: "deadline",
        };
        await transaction.put(key, expired);
        await releaseFence(transaction, expired);
        return null;
      }
      const invocation: ProviderDispatchRequest = {
        ...current,
        invocation_id: invocationID,
        attempt: current.attempt + 1,
      };
      const dispatching: ProviderOperationRecord = {
        ...current,
        status: "dispatching",
        updated_at: now,
        active_invocation_id: invocationID,
        attempt: current.attempt + 1,
      };
      await transaction.put(key, dispatching);
      return invocation;
    });
  }

  async recordOutcome(
    operationID: string,
    invocationID: string,
    response: ProviderDispatchResponse,
    now = Date.now(),
  ): Promise<ProviderOperationRecord> {
    validateNow(now);
    validateOperationID(operationID);
    validateOperationID(invocationID);
    validateDispatchResponse(response);
    return this.storage.transaction(async (transaction) => {
      const operationKeyValue = operationKey(operationID);
      const current = await transaction.get<ProviderOperationRecord>(operationKeyValue);
      if (!current) throw new ProviderOperationInvalidRequestError("unknown provider operation");
      const invocationKeyValue = invocationKey(operationID, invocationID);
      const existingOutcome = await transaction.get<ProviderInvocationOutcome>(invocationKeyValue);
      const outcome: ProviderInvocationOutcome = {
        ...response,
        operation_id: operationID,
        invocation_id: invocationID,
        observed_at: now,
      };
      if (existingOutcome) {
        if (!sameOutcome(existingOutcome, outcome)) throw new ProviderOperationOutcomeConflictError();
        return copyRecord(current);
      }
      if (
        current.active_invocation_id !== invocationID ||
        (current.status !== "dispatching" && current.status !== "cancel_requested")
      ) {
        throw new ProviderOperationInvalidRequestError("provider invocation mismatch");
      }
      await transaction.put(invocationKeyValue, outcome);

      const terminalDeadline = now >= current.deadline_at;
      let nextStatus: ProviderOperationStatus;
      if (response.status === "rejected") {
        nextStatus = current.status === "cancel_requested" ? "cancelled" : "failed";
      } else if (current.status === "cancel_requested") {
        nextStatus = "cancel_needs_reconciliation";
      } else if (response.status === "committed" && !terminalDeadline) {
        nextStatus = "awaiting_verification";
      } else {
        nextStatus = "needs_reconciliation";
      }
      const finished: ProviderOperationRecord = {
        ...current,
        status: nextStatus,
        updated_at: now,
        completed_at: isTerminal(nextStatus) ? now : null,
        active_invocation_id: null,
        observed_state_oid: response.provider_state_oid ?? current.observed_state_oid,
        canary: response.canary,
        postconditions: response.postconditions,
        failure_code: terminalDeadline && response.status !== "rejected"
          ? "deadline"
          : response.error_code,
      };
      await transaction.put(operationKeyValue, finished);
      if (isTerminal(nextStatus)) await releaseFence(transaction, finished);
      return copyRecord(finished);
    });
  }


  async applyDecision(
    decision: ProviderControlDecision,
    now = Date.now(),
  ): Promise<ProviderOperationRecord> {
    validateNow(now);
    validateControlDecision(decision, now);
    const keyBytes = this.controlPublicKey?.slice();
    if (!keyBytes || keyBytes.byteLength !== 32) throw new ProviderOperationDecisionRejectedError();

    const current = await this.storage.get<ProviderOperationRecord>(operationKey(decision.operation_id));
    if (!current) throw new ProviderOperationDecisionRejectedError();
    validateDecisionBinding(decision, current, now, this.expectedIssuer);
    try {
      const imported = await crypto.subtle.importKey("raw", keyBytes, ED25519_ALGORITHM, false, ["verify"]);
      const valid = await crypto.subtle.verify(
        ED25519_ALGORITHM,
        imported,
        decodeBase64(decision.signature),
        canonicalProviderControlDecisionBytes(decision),
      );
      if (!valid) throw new ProviderOperationDecisionRejectedError();
    } catch (error) {
      if (error instanceof ProviderOperationDecisionRejectedError) throw error;
      throw new ProviderOperationDecisionRejectedError();
    }

    return this.storage.transaction(async (transaction) => {
      const key = operationKey(decision.operation_id);
      const operation = await transaction.get<ProviderOperationRecord>(key);
      if (!operation) throw new ProviderOperationDecisionRejectedError();
      validateDecisionBinding(decision, operation, now, this.expectedIssuer);
      const consumedKey = decisionKey(decision.nonce);
      if (await transaction.get<ProviderDecisionConsumption>(consumedKey)) {
        throw new ProviderOperationDecisionRejectedError();
      }

      const next = applyDecisionTransition(operation, decision, now);
      await transaction.put(consumedKey, {
        operation_id: decision.operation_id,
        action: decision.action,
        nonce: decision.nonce,
        consumed_at: now,
      } satisfies ProviderDecisionConsumption);
      if (next.status !== operation.status || next.updated_at !== operation.updated_at) {
        await transaction.put(key, next);
        if (isTerminal(next.status)) await releaseFence(transaction, next);
      }
      return copyRecord(next);
    });
  }

  async verify(
    operationID: string,
    verification: ProviderVerification,
    now = Date.now(),
  ): Promise<ProviderOperationRecord> {
    validateNow(now);
    validateOperationID(operationID);
    validateVerification(verification);
    return this.storage.transaction(async (transaction) => {
      const key = operationKey(operationID);
      const current = await transaction.get<ProviderOperationRecord>(key);
      if (!current) throw new ProviderOperationInvalidRequestError("unknown provider operation");
      if (isTerminal(current.status)) return copyRecord(current);
      if (current.status !== "awaiting_verification" && current.status !== "cancel_requested") {
        throw new ProviderOperationInvalidRequestError("provider operation is not awaiting verification");
      }
      if (current.observed_state_oid !== null && current.observed_state_oid !== verification.provider_state_oid) {
        throw new ProviderOperationDecisionRejectedError();
      }

      let status: ProviderOperationStatus;
      let completedAt: number | null = null;
      let failureCode = current.failure_code;
      if (now >= current.deadline_at) {
        status = current.status === "cancel_requested" ? "cancel_needs_reconciliation" : "needs_reconciliation";
        failureCode = "deadline";
      } else if (current.status === "cancel_requested") {
        status = "cancel_needs_reconciliation";
        failureCode = "cancel_requires_reconciliation";
      } else if (verification.canary !== "passed" || verification.postconditions !== "passed") {
        status = "needs_reconciliation";
        failureCode = "verification_failed";
      } else {
        status = "succeeded";
        completedAt = now;
      }
      const finished: ProviderOperationRecord = {
        ...current,
        status,
        updated_at: now,
        completed_at: completedAt,
        observed_state_oid: verification.provider_state_oid,
        canary: verification.canary,
        postconditions: verification.postconditions,
        failure_code: failureCode,
        active_invocation_id: null,
        current_generation_ref: status === "succeeded"
          ? current.intended_generation_ref
          : current.current_generation_ref,
      };
      await transaction.put(key, finished);
      if (status === "succeeded") {
        await transaction.put(lastSuccessKey(current), {
          operation_id: current.operation_id,
          generation: current.generation,
          source_fingerprint: current.source_fingerprint,
          source_digest: current.source_digest,
          target_identity: current.target_identity,
          target_digest: current.target_digest,
          provider_state_oid: verification.provider_state_oid,
          completed_at: now,
        } satisfies ProviderLastSuccess);
      }
      if (isTerminal(status)) await releaseFence(transaction, finished);
      return copyRecord(finished);
    });
  }

  async read(operationID: string): Promise<ProviderOperationRecord | null> {
    validateOperationID(operationID);
    const operation = await this.storage.get<ProviderOperationRecord>(operationKey(operationID));
    return operation ? copyRecord(operation) : null;
  }

  async readInvocationOutcome(operationID: string, invocationID: string): Promise<ProviderInvocationOutcome | null> {
    validateOperationID(operationID);
    validateOperationID(invocationID);
    const outcome = await this.storage.get<ProviderInvocationOutcome>(invocationKey(operationID, invocationID));
    return outcome ? { ...outcome } : null;
  }

  async readLastSuccess(
    targetIdentity: string,
    targetDigest: string,
    sourceFingerprint: string,
  ): Promise<ProviderLastSuccess | null> {
    validateIdentifier(targetIdentity);
    validateDigest(targetDigest);
    validateDigest(sourceFingerprint);
    const result = await this.storage.get<ProviderLastSuccess>(lastSuccessKeyFromParts(targetIdentity, targetDigest, sourceFingerprint));
    return result ? { ...result } : null;
  }
}

export class ProviderOperationCoordinator {
  constructor(
    private readonly store: ProviderOperationStore,
    private readonly dispatcher: ProviderDispatcher,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  async run(request: ProviderOperationStart, now = this.clock()): Promise<ProviderOperationRecord> {
    const started = await this.store.start(request, now);
    if (started.status === "conflict") throw new ProviderOperationInvalidRequestError("provider operation conflict");
    if (started.status === "fenced") throw new ProviderOperationInvalidRequestError("provider target fenced");
    if (isTerminal(started.operation.status) || started.operation.status === "needs_reconciliation" || started.operation.status === "cancel_needs_reconciliation") {
      return started.operation;
    }
    const invocationID = `${request.operation_id}-attempt-${started.operation.attempt + 1}`;
    const claim = await this.store.claim(request.operation_id, invocationID, now);
    if (!claim) {
      const current = await this.store.read(request.operation_id);
      if (!current) throw new ProviderOperationUnavailableError();
      return current;
    }

    let response: ProviderDispatchResponse;
    try {
      response = await this.dispatcher.dispatch({ ...claim });
    } catch {
      response = {
        status: "unknown",
        provider_state_oid: null,
        canary: "unknown",
        postconditions: "unknown",
        error_code: "dispatcher_error",
      };
    }
    const observedAt = this.clock();
    const recorded = await this.store.recordOutcome(request.operation_id, invocationID, response, observedAt);
    if (
      recorded.status === "awaiting_verification" &&
      response.status === "committed" &&
      response.provider_state_oid !== null &&
      response.canary === "passed" &&
      response.postconditions === "passed"
    ) {
      return this.store.verify(request.operation_id, {
        provider_state_oid: response.provider_state_oid,
        canary: response.canary,
        postconditions: response.postconditions,
      }, observedAt);
    }
    return recorded;
  }
}

interface ProviderTargetFence {
  readonly operation_id: string;
  readonly target_identity: string;
  readonly target_digest: string;
}

interface ProviderDecisionConsumption {
  readonly operation_id: string;
  readonly action: ProviderControlAction;
  readonly nonce: string;
  readonly consumed_at: number;
}

function validateStart(request: ProviderOperationStart, now: number): void {
  if (!isObjectWithExactFields(request, START_FIELDS)) throw new ProviderOperationInvalidRequestError();
  validateOperationID(request.operation_id);
  validateGeneration(request.generation);
  validateDigest(request.source_fingerprint);
  validateDigest(request.source_digest);
  validateIdentifier(request.target_identity);
  validateDigest(request.target_digest);
  validateNullableGeneration(request.old_generation_ref);
  validateNullableGeneration(request.current_generation_ref);
  validateGeneration(request.intended_generation_ref);
  validateIdentifier(request.kms_envelope_ref);
  validateIdentifier(request.operator_identity);
  if (!isCapability(request.capability)) throw new ProviderOperationInvalidRequestError();
  validateDeadline(request.deadline_at, now);
}

function validateControlDecision(decision: ProviderControlDecision, now: number): void {
  if (!isObjectWithExactFields(decision, DECISION_FIELDS)) throw new ProviderOperationDecisionRejectedError();
  if (decision.version !== CONTROL_DECISION_VERSION || !isControlAction(decision.action)) throw new ProviderOperationDecisionRejectedError();
  validateOperationID(decision.operation_id, ProviderOperationDecisionRejectedError);
  validateGeneration(decision.generation, ProviderOperationDecisionRejectedError);
  validateDigest(decision.source_fingerprint, ProviderOperationDecisionRejectedError);
  validateDigest(decision.source_digest, ProviderOperationDecisionRejectedError);
  validateDigest(decision.target_digest, ProviderOperationDecisionRejectedError);
  validateNullableOID(decision.current_state_oid, ProviderOperationDecisionRejectedError);
  validateReason(decision.reason, ProviderOperationDecisionRejectedError);
  validateIdentifier(decision.issuer, ProviderOperationDecisionRejectedError);
  validateNonce(decision.nonce, ProviderOperationDecisionRejectedError);
  if (decision.approval_nonce !== null) validateNonce(decision.approval_nonce, ProviderOperationDecisionRejectedError);
  validateDecisionTime(decision.issued_at, decision.expires_at, now);
  const signature = decodeBase64(decision.signature);
  if (signature.byteLength !== 64) throw new ProviderOperationDecisionRejectedError();
}

function validateDecisionBinding(
  decision: ProviderControlDecision,
  operation: ProviderOperationRecord,
  now: number,
  expectedIssuer: string | undefined,
): void {
  if (
    decision.operation_id !== operation.operation_id ||
    decision.generation !== operation.generation ||
    decision.source_fingerprint !== operation.source_fingerprint ||
    decision.source_digest !== operation.source_digest ||
    decision.target_digest !== operation.target_digest ||
    decision.current_state_oid !== operation.observed_state_oid ||
    decision.issuer !== operation.operator_identity ||
    (expectedIssuer !== undefined && decision.issuer !== expectedIssuer)
  ) {
    throw new ProviderOperationDecisionRejectedError();
  }
  if (decision.expires_at <= now || decision.issued_at > now) {
    throw new ProviderOperationDecisionRejectedError();
  }
}

function applyDecisionTransition(
  operation: ProviderOperationRecord,
  decision: ProviderControlDecision,
  now: number,
): ProviderOperationRecord {
  const ownerAction =
    decision.action === "replay_once" ||
    decision.action === "confirm_applied" ||
    decision.action === "confirm_not_applied" ||
    decision.action === "supersede";
  if (operation.capability === "owner_risk_gate" && ownerAction && decision.approval_nonce !== decision.nonce) {
    throw new ProviderOperationDecisionRejectedError();
  }
  if (operation.capability !== "owner_risk_gate" && decision.approval_nonce !== null) {
    throw new ProviderOperationDecisionRejectedError();
  }
  if (decision.action === "cancel") return applyCancelDecision(operation, now);
  if (decision.action === "replay_once") {
    if (operation.status !== "needs_reconciliation") throw new ProviderOperationDecisionRejectedError();
    if (operation.capability !== "enforced_exclusive" && operation.capability !== "owner_risk_gate") {
      throw new ProviderOperationDecisionRejectedError();
    }
    return {
      ...operation,
      status: "prepared",
      updated_at: now,
      active_invocation_id: null,
      completed_at: null,
      failure_code: null,
    };
  }
  if (decision.action === "confirm_applied") {
    if (operation.status !== "needs_reconciliation" || operation.observed_state_oid === null) {
      throw new ProviderOperationDecisionRejectedError();
    }
    if (operation.capability !== "native_cas" && operation.capability !== "owner_risk_gate") {
      throw new ProviderOperationDecisionRejectedError();
    }
    return {
      ...operation,
      status: "awaiting_verification",
      updated_at: now,
      active_invocation_id: null,
      observed_state_oid: decision.current_state_oid,
    };
  }
  if (decision.action === "confirm_not_applied") {
    if (operation.status !== "needs_reconciliation" && operation.status !== "cancel_needs_reconciliation") {
      throw new ProviderOperationDecisionRejectedError();
    }
    if (operation.capability !== "native_cas" && operation.capability !== "owner_risk_gate") {
      throw new ProviderOperationDecisionRejectedError();
    }
    if (decision.current_state_oid !== operation.observed_state_oid) throw new ProviderOperationDecisionRejectedError();
    const status: ProviderOperationStatus = operation.status === "cancel_needs_reconciliation" ? "cancelled" : "failed";
    return {
      ...operation,
      status,
      updated_at: now,
      completed_at: now,
      active_invocation_id: null,
      failure_code: status === "cancelled" ? "cancelled" : "not_applied",
    };
  }
  if (decision.action === "supersede") {
    if (operation.status !== "needs_reconciliation" && operation.status !== "cancel_needs_reconciliation") {
      throw new ProviderOperationDecisionRejectedError();
    }
    return {
      ...operation,
      status: "superseded",
      updated_at: now,
      completed_at: now,
      active_invocation_id: null,
      failure_code: "superseded",
    };
  }
  throw new ProviderOperationDecisionRejectedError();
}

function applyCancelDecision(operation: ProviderOperationRecord, now: number): ProviderOperationRecord {
  if (isTerminal(operation.status)) throw new ProviderOperationDecisionRejectedError();
  let status: ProviderOperationStatus = operation.status;
  let completedAt = operation.completed_at;
  if (operation.status === "prepared") {
    status = "cancelled";
    completedAt = now;
  } else if (operation.status === "dispatching" || operation.status === "awaiting_verification") {
    status = "cancel_requested";
  } else if (operation.status === "needs_reconciliation") {
    status = "cancel_needs_reconciliation";
  }
  return {
    ...operation,
    status,
    updated_at: now,
    completed_at: completedAt,
    failure_code: status === "cancelled" ? "cancelled" : operation.failure_code,
  };
}

function validateDispatchResponse(response: ProviderDispatchResponse): void {
  const fields = ["status", "provider_state_oid", "canary", "postconditions", "error_code"] as const;
  if (!isObjectWithExactFields(response, fields)) throw new ProviderOperationInvalidRequestError();
  if (!isDispatchStatus(response.status)) throw new ProviderOperationInvalidRequestError();
  validateNullableOID(response.provider_state_oid);
  if (!isVerificationStatus(response.canary) || !isVerificationStatus(response.postconditions)) {
    throw new ProviderOperationInvalidRequestError();
  }
  if (response.error_code !== null) validateIdentifier(response.error_code);
  if (response.status === "committed" && response.provider_state_oid === null) {
    throw new ProviderOperationInvalidRequestError();
  }
  if (response.status === "rejected" && response.error_code === null) {
    throw new ProviderOperationInvalidRequestError();
  }
  if (
    response.status !== "committed" &&
    (response.canary !== "unknown" || response.postconditions !== "unknown")
  ) {
    throw new ProviderOperationInvalidRequestError();
  }
}

function validateVerification(verification: ProviderVerification): void {
  const fields = ["provider_state_oid", "canary", "postconditions"] as const;
  if (!isObjectWithExactFields(verification, fields)) throw new ProviderOperationInvalidRequestError();
  validateOID(verification.provider_state_oid);
  if (verification.canary !== "passed" && verification.canary !== "failed") {
    throw new ProviderOperationInvalidRequestError();
  }
  if (verification.postconditions !== "passed" && verification.postconditions !== "failed") {
    throw new ProviderOperationInvalidRequestError();
  }
}

function validateDecisionTime(issuedAt: number, expiresAt: number, now: number): void {
  if (
    !Number.isSafeInteger(issuedAt) ||
    !Number.isSafeInteger(expiresAt) ||
    issuedAt < 0 ||
    expiresAt <= issuedAt ||
    issuedAt > now ||
    now - issuedAt > MAX_CONTROL_DECISION_TTL_MS ||
    expiresAt <= now ||
    expiresAt - now > MAX_CONTROL_DECISION_TTL_MS
  ) {
    throw new ProviderOperationDecisionRejectedError();
  }
}

function validateDeadline(deadlineAt: number, now: number): void {
  if (
    !Number.isSafeInteger(deadlineAt) ||
    deadlineAt <= now ||
    deadlineAt > now + MAX_PROVIDER_OPERATION_LIFETIME_MS
  ) throw new ProviderOperationInvalidRequestError("invalid provider operation deadline");
}

function validateNow(now: number): void {
  if (!Number.isSafeInteger(now) || now < 0) throw new ProviderOperationInvalidRequestError("invalid provider operation time");
}

type ProviderErrorConstructor = new (message?: string) => Error;

function validateOperationID(
  value: unknown,
  ErrorType: ProviderErrorConstructor = ProviderOperationInvalidRequestError,
): asserts value is string {
  if (typeof value !== "string" || !OPERATION_ID_PATTERN.test(value)) throw new ErrorType();
}

function validateNonce(
  value: unknown,
  ErrorType: ProviderErrorConstructor = ProviderOperationInvalidRequestError,
): asserts value is string {
  if (typeof value !== "string" || !NONCE_PATTERN.test(value)) throw new ErrorType();
}

function validateGeneration(
  value: unknown,
  ErrorType: ProviderErrorConstructor = ProviderOperationInvalidRequestError,
): asserts value is string {
  if (typeof value !== "string" || !GENERATION_PATTERN.test(value)) throw new ErrorType();
}

function validateNullableGeneration(value: unknown): void {
  if (value !== null) validateGeneration(value);
}

function validateDigest(
  value: unknown,
  ErrorType: ProviderErrorConstructor = ProviderOperationInvalidRequestError,
): asserts value is string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) throw new ErrorType();
}

function validateIdentifier(
  value: unknown,
  ErrorType: ProviderErrorConstructor = ProviderOperationInvalidRequestError,
): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) throw new ErrorType();
}

function validateOID(
  value: unknown,
  ErrorType: ProviderErrorConstructor = ProviderOperationInvalidRequestError,
): asserts value is string {
  if (typeof value !== "string" || !OID_PATTERN.test(value)) throw new ErrorType();
}

function validateNullableOID(
  value: unknown,
  ErrorType: ProviderErrorConstructor = ProviderOperationInvalidRequestError,
): void {
  if (value !== null) validateOID(value, ErrorType);
}

function validateReason(
  value: unknown,
  ErrorType: ProviderErrorConstructor = ProviderOperationInvalidRequestError,
): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 512 ||
    value.trim() !== value ||
    CONTROL_TEXT_PATTERN.test(value)
  ) throw new ErrorType("invalid provider operation reason");
}

function decodeBase64(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length === 0 || !STANDARD_BASE64_PATTERN.test(value)) {
    throw new ProviderOperationDecisionRejectedError();
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new ProviderOperationDecisionRejectedError();
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64(bytes) !== value) throw new ProviderOperationDecisionRejectedError();
  return bytes;
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function isObjectWithExactFields<T extends readonly string[]>(value: unknown, fields: T): value is Record<T[number], unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === fields.length && fields.every((field) => Object.prototype.hasOwnProperty.call(value, field));
}

function isCapability(value: unknown): value is ProviderOperationCapability {
  return value === "native_cas" || value === "enforced_exclusive" || value === "owner_risk_gate" || value === "blocked";
}

function isDispatchStatus(value: unknown): value is ProviderDispatchStatus {
  return value === "committed" || value === "rejected" || value === "dropped" || value === "unknown";
}

function isVerificationStatus(value: unknown): value is ProviderVerificationStatus {
  return value === "unknown" || value === "passed" || value === "failed";
}

function isControlAction(value: unknown): value is ProviderControlAction {
  return value === "cancel" || value === "replay_once" || value === "confirm_applied" || value === "confirm_not_applied" || value === "supersede";
}

function isTerminal(status: ProviderOperationStatus): boolean {
  return status === "succeeded" || status === "failed" || status === "cancelled" || status === "superseded";
}

function unresolved(status: ProviderOperationStatus): boolean {
  return !isTerminal(status);
}

function sameStart(operation: ProviderOperationRecord, request: ProviderOperationStart): boolean {
  return START_FIELDS.every((field) => operation[field] === request[field]);
}

function sameOutcome(left: ProviderInvocationOutcome, right: ProviderInvocationOutcome): boolean {
  return (
    left.operation_id === right.operation_id &&
    left.invocation_id === right.invocation_id &&
    left.status === right.status &&
    left.provider_state_oid === right.provider_state_oid &&
    left.canary === right.canary &&
    left.postconditions === right.postconditions &&
    left.error_code === right.error_code
  );
}

function copyRecord(record: ProviderOperationRecord): ProviderOperationRecord {
  return { ...record };
}

async function releaseFence(transaction: ProviderOperationTransaction, operation: ProviderOperationRecord): Promise<void> {
  const key = fenceKey(operation.target_identity);
  const fence = await transaction.get<ProviderTargetFence>(key);
  if (fence?.operation_id === operation.operation_id) await transaction.delete(key);
}

function operationKey(operationID: string): string {
  return `${OPERATION_PREFIX}${operationID}`;
}

function invocationKey(operationID: string, invocationID: string): string {
  return `${INVOCATION_PREFIX}${operationID}:${invocationID}`;
}

function decisionKey(nonce: string): string {
  return `${DECISION_PREFIX}${nonce}`;
}

function fenceKey(targetIdentity: string): string {
  return `${FENCE_PREFIX}${targetIdentity}`;
}

function lastSuccessKey(operation: ProviderOperationStart): string {
  return lastSuccessKeyFromParts(operation.target_identity, operation.target_digest, operation.source_fingerprint);
}

function lastSuccessKeyFromParts(targetIdentity: string, targetDigest: string, sourceFingerprint: string): string {
  return `${LAST_SUCCESS_PREFIX}${targetIdentity}:${targetDigest}:${sourceFingerprint}`;
}
