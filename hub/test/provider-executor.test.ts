import { describe, expect, it } from "vitest";
import {
  AwsSourceClient,
  KmsClient,
  ProviderEnvelopeLifecycle,
  type AwsParameterMetadata,
  type AwsSourceTransport,
  type KmsTransport,
  type PreparedProviderGeneration,
  type ProviderEnvelopeGenerationStore,
  type SourceIdentity,
} from "../src/executor-provider-crypto";
import {
  canonicalGitHubTarget,
  canonicalTargetSet,
  type CanonicalTargetIdentity,
  type TargetOperation,
  type TargetWriteResult,
} from "../src/executor-provider-clients";
import type { ExecutorEnvelope } from "../src/executor-envelope-verifier";
import type { PrivateExecutorRoleAuthority } from "../src/private-executor-handler";
import {
  DurableProviderOperationStore,
  type ProviderOperationStorage,
  type ProviderOperationTransaction,
} from "../src/provider-operation-store";
import {
  PROVIDER_DISPATCH_SCHEMA,
  PROVIDER_VERIFICATION_SCHEMA,
  PROVIDER_DISPATCH_ROLE,
  PROVIDER_VERIFICATION_ROLE,
  buildProviderPrivateExecutorOptions,
  executeProviderDispatchBody,
  executeProviderVerificationBody,
  providerAuthorityIdentity,
  type ProviderAuthorityBinding,
  type ProviderExecutorDependencies,
  type ProviderTargetClient,
} from "../src/provider-executor";

const NOW = 1_700_000_000_000;
const VALUE = new TextEncoder().encode("synthetic-provider-value");
const VALUE_DIGEST = "sha256:1604a44f3c506bae9ec71fa3ae12f60affc9922a155a664f182d8309c4f26c75";
const SOURCE_FINGERPRINT = `sha256:${"f".repeat(64)}`;
const KMS_KEY = "arn:aws:kms:ap-southeast-1:123456789012:key/fixture";
const AUTHORITY_GENERATION = 1;
const AUTHORITY_NOT_AFTER = NOW + 24 * 60 * 60 * 1000;

class MemoryStorage implements ProviderOperationStorage {
  private readonly values = new Map<string, unknown>();
  private tail = Promise.resolve();

  async get<T>(key: string): Promise<T | undefined> {
    return this.values.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, structuredClone(value));
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  transaction<T>(closure: (transaction: ProviderOperationTransaction) => Promise<T>): Promise<T> {
    const result = this.tail.then(() => closure(this));
    this.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

class GenerationStore implements ProviderEnvelopeGenerationStore {
  readonly records = new Map<string, PreparedProviderGeneration>();

  async get(operationId: string): Promise<PreparedProviderGeneration | undefined> {
    return this.records.get(operationId);
  }

  async put(generation: PreparedProviderGeneration): Promise<void> {
    this.records.set(generation.operationId, structuredClone(generation));
  }

  async delete(operationId: string): Promise<void> {
    this.records.delete(operationId);
  }
}

class SourceTransport implements AwsSourceTransport {
  readonly calls: string[] = [];
  label: number | null = null;

  async describeParameterVersion(): Promise<AwsParameterMetadata> {
    this.calls.push("describe");
    return {
      exists: true,
      parameterName: "/fixture/value",
      version: 101,
      versionCount: 100,
      labels: [],
    };
  }

  async readParameterVersion(): Promise<Uint8Array> {
    this.calls.push("read");
    return VALUE.slice();
  }

  async labelParameterVersion(request: { version: number }): Promise<void> {
    this.calls.push("label");
    this.label = request.version;
  }

  async readParameterLabel(): Promise<number | null> {
    this.calls.push("read-label");
    return this.label;
  }

  async unlabelParameterVersion(): Promise<void> {
    this.calls.push("unlabel");
    this.label = null;
  }
}

class KmsTransportFixture implements KmsTransport {
  private readonly key = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

  async generateDataKey() {
    return { plaintextDataKey: this.key.slice(), encryptedDataKey: new Uint8Array([1, 2, 3]) };
  }

  async decrypt() {
    return { plaintextDataKey: this.key.slice() };
  }
}

class TargetClientFixture implements ProviderTargetClient {
  readonly values: Uint8Array[] = [];
  status: TargetWriteResult["status"] = "applied";
  resultTarget: string | null = null;

  async upsertSecret(input: { readonly operation: TargetOperation; readonly value: Uint8Array }): Promise<TargetWriteResult> {
    this.values.push(input.value.slice());
    input.value.fill(0);
    return {
      status: this.status,
      operationId: input.operation.operationId,
      targetIdentity: this.resultTarget ?? input.operation.target.canonical,
      providerStateOID: this.status === "applied" ? `state:${input.operation.operationId}` : null,
    };
  }
}

const SOURCE: SourceIdentity = {
  partition: "aws",
  account: "123456789012",
  region: "ap-southeast-1",
  fullParameterName: "/fixture/value",
  version: 101,
  lifecycleLabel: "generation-1",
};

async function fixture() {
  const storage = new MemoryStorage();
  const operations = new DurableProviderOperationStore(storage);
  const generations = new GenerationStore();
  const source = new SourceTransport();
  const lifecycle = new ProviderEnvelopeLifecycle(
    new AwsSourceClient(source),
    new KmsClient(new KmsTransportFixture()),
    generations,
  );
  const targetClient = new TargetClientFixture();
  const target = canonicalGitHubTarget({
    owner: "fixture",
    repository: "repo",
    secretName: "TOKEN",
    capability: "owner_risk_gate",
  });
  const targetSet = await canonicalTargetSet([target]);
  const dispatchAuthority: PrivateExecutorRoleAuthority = {
    role: PROVIDER_DISPATCH_ROLE,
    generation: AUTHORITY_GENERATION,
    notAfter: AUTHORITY_NOT_AFTER,
    capabilityDigest: targetSet.digest,
  };
  const verificationAuthority: PrivateExecutorRoleAuthority = {
    role: PROVIDER_VERIFICATION_ROLE,
    generation: AUTHORITY_GENERATION,
    notAfter: AUTHORITY_NOT_AFTER,
    capabilityDigest: targetSet.digest,
  };
  const authorityBinding: ProviderAuthorityBinding = {
    dispatchGeneration: dispatchAuthority.generation,
    verificationGeneration: verificationAuthority.generation,
    capabilityDigest: targetSet.digest,
  };
  const dependencies: ProviderExecutorDependencies = {
    operations,
    lifecycle,
    targetClient: (identity: CanonicalTargetIdentity) =>
      identity.canonical === target.canonical ? targetClient : null,
    now: () => NOW,
  };
  return {
    operations,
    generations,
    source,
    targetClient,
    target,
    targetSet,
    dependencies,
    dispatchAuthority,
    verificationAuthority,
    authorityBinding,
  };
}

function dispatchBody(
  target: CanonicalTargetIdentity,
  targetDigest: string,
  sourceDigest = VALUE_DIGEST,
  dispatchAuthorityGeneration = AUTHORITY_GENERATION,
  verificationAuthorityGeneration = AUTHORITY_GENERATION,
): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    schema: PROVIDER_DISPATCH_SCHEMA,
    operation: {
      operation_id: "provider-op-1",
      generation: "generation-1",
      source_fingerprint: SOURCE_FINGERPRINT,
      source_digest: sourceDigest,
      target_identity: target.canonical,
      target_digest: targetDigest,
      old_generation_ref: null,
      current_generation_ref: null,
      intended_generation_ref: "generation-1",
      kms_envelope_ref: "provider-envelope:provider-op-1",
      operator_identity: providerAuthorityIdentity(
        dispatchAuthorityGeneration,
        verificationAuthorityGeneration,
      ),
      capability: "owner_risk_gate",
      deadline_at: NOW + 60_000,
    },
    invocation_id: "provider-invocation-1",
    source_identity: SOURCE,
    target,
    kms_key_reference: KMS_KEY,
  }));
}

function verificationBody(
  target: CanonicalTargetIdentity,
  acknowledgedTargetIdentity = target.canonical,
): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    schema: PROVIDER_VERIFICATION_SCHEMA,
    operation_id: "provider-op-1",
    provider_state_oid: "state:provider-op-1",
    canary: "passed",
    postconditions: "passed",
    acknowledged_target_identity: acknowledgedTargetIdentity,
  }));
}

describe("provider executor metadata wiring", () => {
  it("fetches an exact source version, writes once, and waits for verification", async () => {
    const context = await fixture();
    const response = await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );
    expect(JSON.parse(new TextDecoder().decode(response))).toEqual({
      operation_id: "provider-op-1",
      status: "awaiting_verification",
    });
    expect(context.targetClient.values).toEqual([VALUE]);
    expect(context.source.calls.filter((call) => call === "label")).toHaveLength(1);
    expect(context.generations.records.has("provider-op-1")).toBe(true);

    const replay = await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );
    expect(JSON.parse(new TextDecoder().decode(replay)).status).toBe("awaiting_verification");
    expect(context.targetClient.values).toHaveLength(1);
  });

  it("fences a renewed authority generation from satisfying a prior durable operation", async () => {
    const context = await fixture();
    await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );

    await expect(executeProviderDispatchBody(
      dispatchBody(
        context.target,
        context.targetSet.digest,
        VALUE_DIGEST,
        AUTHORITY_GENERATION + 1,
      ),
      context.dependencies,
      { ...context.dispatchAuthority, generation: AUTHORITY_GENERATION + 1 },
      {
        ...context.authorityBinding,
        dispatchGeneration: AUTHORITY_GENERATION + 1,
      },
    )).rejects.toThrow("provider executor invalid request");

    const operation = await context.operations.read("provider-op-1");
    expect(operation?.operator_identity).toBe(
      providerAuthorityIdentity(AUTHORITY_GENERATION, AUTHORITY_GENERATION),
    );
    expect(context.targetClient.values).toHaveLength(1);
  });

  it("records an ambiguous target response without retry", async () => {
    const context = await fixture();
    context.targetClient.status = "needs_reconciliation";
    const response = await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );
    expect(JSON.parse(new TextDecoder().decode(response)).status).toBe("needs_reconciliation");
    expect(context.targetClient.values).toHaveLength(1);
  });

  it("fences a provider response whose operation binding does not match", async () => {
    const context = await fixture();
    context.targetClient.resultTarget = `${context.target.canonical}|wrong`;
    const response = await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );
    expect(JSON.parse(new TextDecoder().decode(response)).status).toBe("needs_reconciliation");
    expect(context.targetClient.values).toHaveLength(1);
  });

  it("rejects metadata drift before target mutation", async () => {
    const context = await fixture();
    const response = await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest, `sha256:${"0".repeat(64)}`),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );
    expect(JSON.parse(new TextDecoder().decode(response)).status).toBe("needs_reconciliation");
    expect(context.targetClient.values).toHaveLength(0);
    expect(context.source.calls).not.toContain("label");
  });

  it("verifies provider readback and cleans the retained source label", async () => {
    const context = await fixture();
    await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );
    const response = await executeProviderVerificationBody(
      verificationBody(context.target),
      context.dependencies,
      context.verificationAuthority,
      context.authorityBinding,
    );
    expect(JSON.parse(new TextDecoder().decode(response))).toEqual({
      operation_id: "provider-op-1",
      status: "succeeded",
    });
    expect(context.generations.records.has("provider-op-1")).toBe(false);
    expect(context.source.label).toBeNull();
  });

  it("rejects an acknowledgement for another target before verification mutation", async () => {
    const context = await fixture();
    await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );
    await expect(
      executeProviderVerificationBody(
        verificationBody(context.target, `${context.target.canonical}|wrong`),
        context.dependencies,
        context.verificationAuthority,
        context.authorityBinding,
      ),
    ).rejects.toThrow("provider executor invalid request");
    const operation = await context.operations.read("provider-op-1");
    expect(operation?.status).toBe("awaiting_verification");
    expect(context.generations.records.has("provider-op-1")).toBe(true);
  });

  it("rejects mismatched verification authority metadata before verification mutation", async () => {
    const context = await fixture();
    await executeProviderDispatchBody(
      dispatchBody(context.target, context.targetSet.digest),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    );

    await expect(executeProviderVerificationBody(
      verificationBody(context.target),
      context.dependencies,
      { ...context.verificationAuthority, capabilityDigest: `sha256:${"8".repeat(64)}` },
      context.authorityBinding,
    )).rejects.toThrow("provider executor invalid request");
    await expect(executeProviderVerificationBody(
      verificationBody(context.target),
      context.dependencies,
      { ...context.verificationAuthority, generation: AUTHORITY_GENERATION + 1 },
      context.authorityBinding,
    )).rejects.toThrow("provider executor invalid request");

    const operation = await context.operations.read("provider-op-1");
    expect(operation?.status).toBe("awaiting_verification");
    expect(context.generations.records.has("provider-op-1")).toBe(true);
  });

  it("builds an explicit two-role authority route with distinct keys and bound metadata", async () => {
    const context = await fixture();
    const dispatchPublicKey = new Uint8Array(32).fill(1);
    const verificationPublicKey = new Uint8Array(32).fill(2);
    const dispatchAuthority = {
      publicKey: dispatchPublicKey,
      generation: AUTHORITY_GENERATION,
      notAfter: AUTHORITY_NOT_AFTER,
      capabilityDigest: context.targetSet.digest,
    };
    const verificationAuthority = {
      publicKey: verificationPublicKey,
      generation: AUTHORITY_GENERATION + 1,
      notAfter: AUTHORITY_NOT_AFTER,
      capabilityDigest: context.targetSet.digest,
    };
    const input = {
      expectedAudience: "skret-security-executor",
      dispatchAuthority,
      verificationAuthority,
      replayStore: { async consume() {} },
      dependencies: context.dependencies,
      now: NOW,
    };
    const options = buildProviderPrivateExecutorOptions(input);

    expect(options?.roleAuthorities).toEqual([
      { role: PROVIDER_DISPATCH_ROLE, ...dispatchAuthority },
      { role: PROVIDER_VERIFICATION_ROLE, ...verificationAuthority },
    ]);
    const dispatch = await options!.execute(
      dispatchBody(
        context.target,
        context.targetSet.digest,
        VALUE_DIGEST,
        AUTHORITY_GENERATION,
        AUTHORITY_GENERATION + 1,
      ),
      { role: PROVIDER_DISPATCH_ROLE, manifest_digest: context.targetSet.digest } as ExecutorEnvelope,
      context.dispatchAuthority,
    );
    expect(JSON.parse(new TextDecoder().decode(dispatch as Uint8Array)).status).toBe("awaiting_verification");
    const verified = await options!.execute(
      verificationBody(context.target),
      { role: PROVIDER_VERIFICATION_ROLE, manifest_digest: context.targetSet.digest } as ExecutorEnvelope,
      { ...context.verificationAuthority, generation: AUTHORITY_GENERATION + 1 },
    );
    expect(JSON.parse(new TextDecoder().decode(verified as Uint8Array)).status).toBe("succeeded");
    await expect(options!.execute(
      dispatchBody(context.target, context.targetSet.digest),
      { role: "wrong-role", manifest_digest: context.targetSet.digest } as ExecutorEnvelope,
      context.dispatchAuthority,
    )).rejects.toThrow("provider executor invalid request");

    const invalidInputs = [
      { ...input, dispatchAuthority: { ...dispatchAuthority, publicKey: new Uint8Array(31) } },
      { ...input, verificationAuthority: { ...verificationAuthority, publicKey: dispatchPublicKey.slice() } },
      { ...input, verificationAuthority: { ...verificationAuthority, generation: 0 } },
      { ...input, verificationAuthority: { ...verificationAuthority, capabilityDigest: `sha256:${"9".repeat(64)}` } },
    ];
    for (const invalid of invalidInputs) {
      expect(buildProviderPrivateExecutorOptions(invalid)).toBeNull();
    }
  });

  it("rejects noncanonical bodies and target or authority digest substitution with zero provider calls", async () => {
    const context = await fixture();
    const canonical = new TextDecoder().decode(dispatchBody(context.target, context.targetSet.digest));
    await expect(executeProviderDispatchBody(
      new TextEncoder().encode(` ${canonical}`),
      context.dependencies,
      context.dispatchAuthority,
      context.authorityBinding,
    )).rejects.toThrow("provider executor invalid request");
    await expect(
      executeProviderDispatchBody(
        dispatchBody(context.target, `sha256:${"9".repeat(64)}`),
        context.dependencies,
        context.dispatchAuthority,
        context.authorityBinding,
      ),
    ).rejects.toThrow("provider executor invalid request");
    await expect(
      executeProviderDispatchBody(
        dispatchBody(context.target, context.targetSet.digest),
        context.dependencies,
        { ...context.dispatchAuthority, capabilityDigest: `sha256:${"8".repeat(64)}` },
        context.authorityBinding,
      ),
    ).rejects.toThrow("provider executor invalid request");
    await expect(
      executeProviderDispatchBody(
        dispatchBody(context.target, context.targetSet.digest),
        context.dependencies,
        { ...context.dispatchAuthority, generation: AUTHORITY_GENERATION + 1 },
        context.authorityBinding,
      ),
    ).rejects.toThrow("provider executor invalid request");
    await expect(
      executeProviderDispatchBody(
        dispatchBody(context.target, context.targetSet.digest),
        context.dependencies,
        { ...context.dispatchAuthority, notAfter: NOW + 30_000 },
        context.authorityBinding,
      ),
    ).rejects.toThrow("provider executor invalid request");
    expect(await context.operations.read("provider-op-1")).toBeNull();
    expect(context.source.calls).toHaveLength(0);
    expect(context.targetClient.values).toHaveLength(0);
  });
});
