import { describe, expect, it } from "vitest";
import {
  DurableProviderOperationStore,
  ProviderOperationCoordinator,
  ProviderOperationDecisionRejectedError,
  ProviderOperationOutcomeConflictError,
  canonicalProviderControlDecisionBytes,
  type ProviderControlDecision,
  type ProviderDispatchResponse,
  type ProviderOperationStart,
  type ProviderOperationStorage,
  type ProviderOperationTransaction,
} from "../src/provider-operation-store";
import { SecurityExecutorOperations } from "../src/executor-operation-store";

const NOW = 1_700_000_000_000;
const DIGEST = (letter: string) => `sha256:${letter.repeat(64)}`;

function fakeStorage(): ProviderOperationStorage & { values: Map<string, unknown> } {
  const values = new Map<string, unknown>();
  let tail = Promise.resolve();
  const storage: ProviderOperationStorage & { values: Map<string, unknown> } = {
    values,
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      values.set(key, value);
    },
    async delete(key: string): Promise<boolean> {
      return values.delete(key);
    },
    async transaction<T>(closure: (transaction: ProviderOperationTransaction) => Promise<T>): Promise<T> {
      const previous = tail;
      let release!: () => void;
      tail = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;
      try {
        return await closure(storage);
      } finally {
        release();
      }
    },
  };
  return storage;
}

function startRequest(
  operationID: string,
  overrides: Partial<ProviderOperationStart> = {},
): ProviderOperationStart {
  return {
    operation_id: operationID,
    generation: "generation-1",
    source_fingerprint: DIGEST("a"),
    source_digest: DIGEST("b"),
    target_identity: "github:owner/repository:prod",
    target_digest: DIGEST("c"),
    old_generation_ref: "generation-0",
    current_generation_ref: "generation-0",
    intended_generation_ref: "generation-1",
    kms_envelope_ref: "kms:envelope-1",
    operator_identity: "operator-1",
    capability: "native_cas",
    deadline_at: NOW + 60_000,
    ...overrides,
  };
}

function committedResponse(
  providerStateOID = "state-1",
  overrides: Partial<ProviderDispatchResponse> = {},
): ProviderDispatchResponse {
  return {
    status: "committed",
    provider_state_oid: providerStateOID,
    canary: "passed",
    postconditions: "passed",
    error_code: null,
    ...overrides,
  };
}

async function keyPair(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("raw", pair.publicKey);
  if (!(exported instanceof ArrayBuffer)) throw new Error("unexpected Ed25519 public-key format");
  const publicKey = new Uint8Array(exported);
  return { privateKey: pair.privateKey, publicKey };
}

function baseDecision(
  operation: ProviderOperationStart,
  overrides: Partial<Omit<ProviderControlDecision, "signature">> = {},
): Omit<ProviderControlDecision, "signature"> {
  return {
    version: 1,
    action: "confirm_applied",
    operation_id: operation.operation_id,
    generation: operation.generation,
    source_fingerprint: operation.source_fingerprint,
    source_digest: operation.source_digest,
    target_digest: operation.target_digest,
    current_state_oid: "state-1",
    reason: "verified provider state",
    issuer: operation.operator_identity,
    nonce: "decision-1",
    issued_at: NOW,
    expires_at: NOW + 30_000,
    approval_nonce: null,
    ...overrides,
  };
}

async function signedDecision(
  privateKey: CryptoKey,
  operation: ProviderOperationStart,
  overrides: Partial<Omit<ProviderControlDecision, "signature">> = {},
): Promise<ProviderControlDecision> {
  const unsigned = baseDecision(operation, overrides);
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    canonicalProviderControlDecisionBytes(unsigned),
  );
  let binary = "";
  for (const byte of new Uint8Array(signature)) binary += String.fromCharCode(byte);
  return { ...unsigned, signature: btoa(binary) };
}

function encodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function prepareDropped(
  store: DurableProviderOperationStore,
  operation: ProviderOperationStart,
  response: ProviderDispatchResponse = {
    status: "unknown",
    provider_state_oid: "state-1",
    canary: "unknown",
    postconditions: "unknown",
    error_code: "provider-response-unavailable",
  },
) {
  await expect(store.start(operation, NOW)).resolves.toMatchObject({ status: "prepared" });
  const request = await store.claim(operation.operation_id, "invocation-1", NOW + 1);
  expect(request).not.toBeNull();
  await store.recordOutcome(operation.operation_id, "invocation-1", response, NOW + 2);
}

describe("provider operation store", () => {
  it("promotes a generation only after canary and postconditions verification", async () => {
    const storage = fakeStorage();
    const store = new DurableProviderOperationStore(storage);
    const operation = startRequest("operation-success");
    const coordinator = new ProviderOperationCoordinator(store, {
      async dispatch() {
        return committedResponse();
      },
    }, () => NOW);

    const completed = await coordinator.run(operation, NOW);
    expect(completed).toMatchObject({
      status: "succeeded",
      current_generation_ref: operation.intended_generation_ref,
    });
    await expect(store.readLastSuccess(operation.target_identity, operation.target_digest, operation.source_fingerprint)).resolves.toMatchObject({
      operation_id: operation.operation_id,
      generation: operation.generation,
      source_fingerprint: operation.source_fingerprint,
    });
  });

  it("does not dispatch after signed cancellation before claim", async () => {
    const { privateKey, publicKey } = await keyPair();
    const store = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    const operation = startRequest("operation-cancel-before");
    await store.start(operation, NOW);
    const decision = await signedDecision(privateKey, operation, {
      action: "cancel",
      current_state_oid: null,
      nonce: "cancel-before",
      reason: "operator cancellation before dispatch",
    });
    await expect(store.applyDecision(decision, NOW + 1)).resolves.toMatchObject({ status: "cancelled" });
    await expect(store.claim(operation.operation_id, "invocation-1", NOW + 2)).resolves.toBeNull();
  });

  it("moves signed cancellation during dispatch to cancel reconciliation after a dropped response", async () => {
    const { privateKey, publicKey } = await keyPair();
    const store = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    const operation = startRequest("operation-cancel-during");
    await store.start(operation, NOW);
    await store.claim(operation.operation_id, "invocation-1", NOW + 1);
    const decision = await signedDecision(privateKey, operation, {
      action: "cancel",
      current_state_oid: null,
      nonce: "cancel-during",
      reason: "operator cancellation during dispatch",
    });
    await expect(store.applyDecision(decision, NOW + 2)).resolves.toMatchObject({ status: "cancel_requested" });
    await expect(
      store.recordOutcome(operation.operation_id, "invocation-1", {
        status: "unknown",
        provider_state_oid: null,
        canary: "unknown",
        postconditions: "unknown",
        error_code: "lost-response",
      }, NOW + 3),
    ).resolves.toMatchObject({ status: "cancel_needs_reconciliation" });
  });

  it("does not acknowledge signed cancellation after provider commit", async () => {
    const { privateKey, publicKey } = await keyPair();
    const store = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    const operation = startRequest("operation-cancel-after");
    await store.start(operation, NOW);
    await store.claim(operation.operation_id, "invocation-1", NOW + 1);
    await store.recordOutcome(operation.operation_id, "invocation-1", committedResponse(), NOW + 2);
    const decision = await signedDecision(privateKey, operation, {
      action: "cancel",
      current_state_oid: "state-1",
      nonce: "cancel-after",
      reason: "operator cancellation after provider commit",
    });
    await expect(store.applyDecision(decision, NOW + 3)).resolves.toMatchObject({ status: "cancel_requested" });
    await expect(store.verify(operation.operation_id, {
      provider_state_oid: "state-1",
      canary: "passed",
      postconditions: "passed",
    }, NOW + 4)).resolves.toMatchObject({ status: "cancel_needs_reconciliation" });
  });

  it.each([
    ["native_cas", "state-1"],
    ["enforced_exclusive", null],
    ["owner_risk_gate", null],
  ] as const)("retains references for dropped %s operations", async (capability, providerStateOID) => {
    const store = new DurableProviderOperationStore(fakeStorage());
    const operation = startRequest(`operation-dropped-${capability}`, { capability });
    await prepareDropped(store, operation, {
      status: "dropped",
      provider_state_oid: providerStateOID,
      canary: "unknown",
      postconditions: "unknown",
      error_code: "response-dropped",
    });
    await expect(store.read(operation.operation_id)).resolves.toMatchObject({
      status: "needs_reconciliation",
      generation: operation.generation,
      source_fingerprint: operation.source_fingerprint,
      source_digest: operation.source_digest,
      target_identity: operation.target_identity,
      target_digest: operation.target_digest,
      old_generation_ref: operation.old_generation_ref,
      current_generation_ref: operation.current_generation_ref,
      intended_generation_ref: operation.intended_generation_ref,
      kms_envelope_ref: operation.kms_envelope_ref,
    });
  });

  it("makes zero provider calls for a blocked capability", async () => {
    const store = new DurableProviderOperationStore(fakeStorage());
    const operation = startRequest("operation-blocked", { capability: "blocked" });
    await store.start(operation, NOW);
    await expect(store.claim(operation.operation_id, "invocation-1", NOW + 1)).resolves.toBeNull();
    await expect(store.read(operation.operation_id)).resolves.toMatchObject({
      status: "failed",
      attempt: 0,
      failure_code: "capability_blocked",
    });
    await expect(store.readInvocationOutcome(operation.operation_id, "invocation-1")).resolves.toBeNull();
  });

  it("retains the target fence when verification fails", async () => {
    const store = new DurableProviderOperationStore(fakeStorage());
    const operation = startRequest("operation-verification-failed");
    await store.start(operation, NOW);
    await store.claim(operation.operation_id, "invocation-1", NOW + 1);
    await store.recordOutcome(operation.operation_id, "invocation-1", committedResponse(), NOW + 2);
    await expect(store.verify(operation.operation_id, {
      provider_state_oid: "state-1",
      canary: "failed",
      postconditions: "passed",
    }, NOW + 3)).resolves.toMatchObject({
      status: "needs_reconciliation",
      failure_code: "verification_failed",
      old_generation_ref: operation.old_generation_ref,
      kms_envelope_ref: operation.kms_envelope_ref,
    });
    await expect(store.start(startRequest("operation-successor"), NOW + 4)).resolves.toMatchObject({
      status: "fenced",
      operation: { operation_id: operation.operation_id },
    });
  });

  it("watchdog expires prepared provider operations and releases their target fence", async () => {
    const storage = fakeStorage();
    const store = new DurableProviderOperationStore(storage);
    const operation = startRequest("operation-watchdog-prepared");
    await store.start(operation, NOW);

    await expect(store.watchdog(operation.deadline_at)).resolves.toMatchObject({
      expired: [operation.operation_id],
      reconciled: [],
      next_alarm_at: null,
    });
    await expect(store.read(operation.operation_id)).resolves.toMatchObject({
      status: "failed",
      completed_at: operation.deadline_at,
      failure_code: "deadline",
    });
    await expect(storage.get("private:provider-operation-fence:" + operation.target_identity)).resolves.toBeUndefined();
    await expect(storage.get("private:provider-operation:active")).resolves.toEqual([]);
  });

  it("watchdog reconciles in-flight provider operations without releasing their fence", async () => {
    const storage = fakeStorage();
    const store = new DurableProviderOperationStore(storage);
    const operation = startRequest("operation-watchdog-dispatching");
    await store.start(operation, NOW);
    await expect(store.claim(operation.operation_id, "invocation-watchdog", NOW + 1)).resolves.toMatchObject({
      operation_id: operation.operation_id,
    });

    await expect(store.watchdog(operation.deadline_at)).resolves.toMatchObject({
      expired: [],
      reconciled: [operation.operation_id],
      next_alarm_at: null,
    });
    await expect(store.read(operation.operation_id)).resolves.toMatchObject({
      status: "needs_reconciliation",
      completed_at: null,
      failure_code: "watchdog_deadline",
      active_invocation_id: null,
    });
    await expect(storage.get("private:provider-operation-fence:" + operation.target_identity)).resolves.toBeDefined();
    await expect(storage.get("private:provider-operation:active")).resolves.toEqual([]);
    await expect(store.start(startRequest("operation-watchdog-successor"), NOW + 1)).resolves.toMatchObject({
      status: "fenced",
      operation: { operation_id: operation.operation_id },
    });
  });

  it("watchdog reconciles a cancelled in-flight provider operation without releasing its fence", async () => {
    const { privateKey, publicKey } = await keyPair();
    const storage = fakeStorage();
    const store = new DurableProviderOperationStore(storage, { control_public_key: publicKey });
    const operation = startRequest("operation-watchdog-cancel-requested");
    await store.start(operation, NOW);
    await store.claim(operation.operation_id, "invocation-cancel-watchdog", NOW + 1);
    const decision = await signedDecision(privateKey, operation, {
      action: "cancel",
      current_state_oid: null,
      nonce: "cancel-watchdog",
      reason: "cancel before watchdog deadline",
    });
    await expect(store.applyDecision(decision, NOW + 2)).resolves.toMatchObject({
      status: "cancel_requested",
    });

    await expect(store.watchdog(operation.deadline_at)).resolves.toMatchObject({
      expired: [],
      reconciled: [operation.operation_id],
      next_alarm_at: null,
    });
    await expect(store.read(operation.operation_id)).resolves.toMatchObject({
      status: "cancel_needs_reconciliation",
      failure_code: "watchdog_deadline",
      active_invocation_id: null,
    });
    await expect(storage.get("private:provider-operation-fence:" + operation.target_identity)).resolves.toBeDefined();
  });

  it("binds an owner-confirmed provider OID when the ambiguous outcome had no OID", async () => {
    const { privateKey, publicKey } = await keyPair();
    const operation = startRequest("operation-confirm-applied-bind");
    const store = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    await prepareDropped(store, operation, {
      status: "unknown",
      provider_state_oid: null,
      canary: "unknown",
      postconditions: "unknown",
      error_code: "response-dropped",
    });

    const decision = await signedDecision(privateKey, operation, {
      current_state_oid: "owner-readback-state",
      nonce: "confirm-applied-bind",
    });

    await expect(store.applyDecision(decision, NOW + 3)).resolves.toMatchObject({
      status: "awaiting_verification",
      observed_state_oid: "owner-readback-state",
    });
  });

  it("rejects wrong issuer, current state, expiry, signature, and replayed decision nonce", async () => {
    const { privateKey, publicKey } = await keyPair();
    const operation = startRequest("operation-decision-reject");
    const store = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    await prepareDropped(store, operation);

    const wrongIssuer = await signedDecision(privateKey, operation, { issuer: "foreign-operator" });
    await expect(store.applyDecision(wrongIssuer, NOW + 3)).rejects.toBeInstanceOf(ProviderOperationDecisionRejectedError);
    const wrongState = await signedDecision(privateKey, operation, { nonce: "decision-state", current_state_oid: "state-2" });
    await expect(store.applyDecision(wrongState, NOW + 3)).rejects.toBeInstanceOf(ProviderOperationDecisionRejectedError);
    const expired = await signedDecision(privateKey, operation, { nonce: "decision-expired", expires_at: NOW + 2 });
    await expect(store.applyDecision(expired, NOW + 3)).rejects.toBeInstanceOf(ProviderOperationDecisionRejectedError);
    const malformedSignature = { ...(await signedDecision(privateKey, operation, { nonce: "decision-signature" })), signature: "AAAA" };
    await expect(store.applyDecision(malformedSignature, NOW + 3)).rejects.toBeInstanceOf(ProviderOperationDecisionRejectedError);
    const valid = await signedDecision(privateKey, operation, { nonce: "decision-valid" });
    const confirmed = await store.applyDecision(valid, NOW + 3);
    expect(confirmed.status).toBe("awaiting_verification");
    await expect(store.applyDecision(valid, NOW + 4)).rejects.toBeInstanceOf(ProviderOperationDecisionRejectedError);
  });

  it("rejects a valid decision when no trusted control key is configured", async () => {
    const { privateKey } = await keyPair();
    const operation = startRequest("operation-missing-control-key");
    const store = new DurableProviderOperationStore(fakeStorage());
    await prepareDropped(store, operation);
    const decision = await signedDecision(privateKey, operation, { nonce: "missing-control-key" });
    await expect(store.applyDecision(decision, NOW + 3)).rejects.toBeInstanceOf(
      ProviderOperationDecisionRejectedError,
    );
  });

  it("uses only the Durable Object trusted control key for signed decisions", async () => {
    const { privateKey, publicKey } = await keyPair();
    const storage = fakeStorage();
    const operations = Object.create(
      SecurityExecutorOperations.prototype,
    ) as SecurityExecutorOperations;
    Object.defineProperty(operations, "ctx", { value: { storage } });
    Object.defineProperty(operations, "env", {
      value: { EXECUTOR_PROVIDER_CONTROL_PUBLIC_KEY: encodeBytes(publicKey) },
    });
    const operation = startRequest("operation-do-control-key");
    await operations.providerStart(operation, NOW);
    await operations.providerClaim(operation.operation_id, "invocation-1", NOW + 1);
    await operations.providerRecordOutcome(
      operation.operation_id,
      "invocation-1",
      {
        status: "unknown",
        provider_state_oid: "state-1",
        canary: "unknown",
        postconditions: "unknown",
        error_code: "response-dropped",
      },
      NOW + 2,
    );
    const decision = await signedDecision(privateKey, operation, {
      nonce: "durable-object-control-key",
    });
    await expect(operations.providerApplyDecision(decision, NOW + 3)).resolves.toMatchObject({
      status: "awaiting_verification",
    });
  });

  it("replays only the same operation for enforced exclusivity", async () => {
    const operation = startRequest("operation-exclusive-replay", { capability: "enforced_exclusive" });
    const storage = fakeStorage();
    const store = new DurableProviderOperationStore(storage);
    await prepareDropped(store, operation, {
      status: "unknown",
      provider_state_oid: null,
      canary: "unknown",
      postconditions: "unknown",
      error_code: "provider-response-unavailable",
    });
    const { privateKey, publicKey } = await keyPair();
    const configured = new DurableProviderOperationStore(storage, { control_public_key: publicKey });
    const decision = await signedDecision(privateKey, operation, {
      action: "replay_once",
      current_state_oid: null,
    });
    await expect(configured.applyDecision(decision, NOW + 3)).resolves.toMatchObject({ status: "prepared" });
    await expect(configured.claim(operation.operation_id, "invocation-2", NOW + 4)).resolves.toMatchObject({
      operation_id: operation.operation_id,
      invocation_id: "invocation-2",
      generation: operation.generation,
    });
  });

  it("consumes an owner-risk replay_once decision before the dispatcher call", async () => {
    const { privateKey, publicKey } = await keyPair();
    const operation = startRequest("operation-owner-risk", { capability: "owner_risk_gate" });
    const store = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    await prepareDropped(store, operation);
    const replay = await signedDecision(privateKey, operation, {
      action: "replay_once",
      nonce: "replay-once-1",
      current_state_oid: "state-1",
      approval_nonce: "replay-once-1",
    });
    await expect(store.applyDecision(replay, NOW + 3)).resolves.toMatchObject({ status: "prepared" });
    await expect(store.claim(operation.operation_id, "invocation-2", NOW + 4)).resolves.toBeDefined();
    await expect(store.recordOutcome(operation.operation_id, "invocation-2", {
      status: "dropped",
      provider_state_oid: null,
      canary: "unknown",
      postconditions: "unknown",
      error_code: "response-dropped",
    }, NOW + 5)).resolves.toMatchObject({ status: "needs_reconciliation" });
    await expect(store.applyDecision(replay, NOW + 6)).rejects.toBeInstanceOf(ProviderOperationDecisionRejectedError);
  });
  it("consumes owner confirmation decisions for exactly the signed action", async () => {
    const { privateKey, publicKey } = await keyPair();
    const appliedOperation = startRequest("operation-owner-confirm-applied", { capability: "owner_risk_gate" });
    const appliedStore = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    await prepareDropped(appliedStore, appliedOperation);
    const applied = await signedDecision(privateKey, appliedOperation, {
      action: "confirm_applied",
      nonce: "confirm-applied-1",
      current_state_oid: "state-1",
      approval_nonce: "confirm-applied-1",
    });
    await expect(appliedStore.applyDecision(applied, NOW + 3)).resolves.toMatchObject({ status: "awaiting_verification" });
    await expect(appliedStore.verify(appliedOperation.operation_id, {
      provider_state_oid: "state-1",
      canary: "passed",
      postconditions: "passed",
    }, NOW + 4)).resolves.toMatchObject({ status: "succeeded" });

    const notAppliedOperation = startRequest("operation-owner-confirm-not-applied", { capability: "owner_risk_gate" });
    const notAppliedStore = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    await prepareDropped(notAppliedStore, notAppliedOperation);
    const notApplied = await signedDecision(privateKey, notAppliedOperation, {
      action: "confirm_not_applied",
      nonce: "confirm-not-applied-1",
      current_state_oid: "state-1",
      approval_nonce: "confirm-not-applied-1",
    });
    await expect(notAppliedStore.applyDecision(notApplied, NOW + 3)).resolves.toMatchObject({ status: "failed" });
  });


  it("fences a successor until an owner-risk supersede decision is consumed", async () => {
    const { privateKey, publicKey } = await keyPair();
    const oldOperation = startRequest("operation-fence-old", { capability: "owner_risk_gate" });
    const successor = startRequest("operation-fence-successor", {
      generation: "generation-2",
      source_fingerprint: DIGEST("e"),
      source_digest: DIGEST("f"),
      intended_generation_ref: "generation-2",
      capability: "owner_risk_gate",
    });
    const store = new DurableProviderOperationStore(fakeStorage(), { control_public_key: publicKey });
    await prepareDropped(store, oldOperation);
    await expect(store.start(successor, NOW + 3)).resolves.toMatchObject({ status: "fenced" });
    await expect(store.applyDecision(await signedDecision(privateKey, oldOperation, {
      action: "supersede",
      nonce: "supersede-1",
      current_state_oid: "state-1",
      approval_nonce: "supersede-1",
    }), NOW + 4)).resolves.toMatchObject({ status: "superseded" });
    await expect(store.start(successor, NOW + 5)).resolves.toMatchObject({ status: "prepared" });
  });

  it("keeps invocation outcomes immutable", async () => {
    const store = new DurableProviderOperationStore(fakeStorage());
    const operation = startRequest("operation-outcome-immutable");
    await store.start(operation, NOW);
    await store.claim(operation.operation_id, "invocation-1", NOW + 1);
    const outcome = committedResponse();
    await store.recordOutcome(operation.operation_id, "invocation-1", outcome, NOW + 2);
    await expect(store.recordOutcome(operation.operation_id, "invocation-1", outcome, NOW + 3)).resolves.toMatchObject({ status: "awaiting_verification" });
    await expect(store.recordOutcome(operation.operation_id, "invocation-1", {
      ...outcome,
      provider_state_oid: "state-2",
    }, NOW + 4)).rejects.toBeInstanceOf(ProviderOperationOutcomeConflictError);
  });

  it("fails closed at the deadline before claiming a provider call", async () => {
    const store = new DurableProviderOperationStore(fakeStorage());
    const operation = startRequest("operation-deadline", { deadline_at: NOW + 1 });
    await store.start(operation, NOW);
    await expect(store.claim(operation.operation_id, "invocation-1", NOW + 1)).resolves.toBeNull();
    await expect(store.read(operation.operation_id)).resolves.toMatchObject({ status: "failed", failure_code: "deadline" });
  });

  it("returns no last-success state for a drifted fingerprint", async () => {
    const store = new DurableProviderOperationStore(fakeStorage());
    const operation = startRequest("operation-last-success");
    await store.start(operation, NOW);
    await store.claim(operation.operation_id, "invocation-1", NOW + 1);
    await store.recordOutcome(operation.operation_id, "invocation-1", committedResponse(), NOW + 2);
    await store.verify(operation.operation_id, {
      provider_state_oid: "state-1",
      canary: "passed",
      postconditions: "passed",
    }, NOW + 3);
    await expect(store.readLastSuccess(operation.target_identity, operation.target_digest, operation.source_fingerprint)).resolves.not.toBeNull();
    await expect(store.readLastSuccess(operation.target_identity, operation.target_digest, DIGEST("e"))).resolves.toBeNull();
  });
});
