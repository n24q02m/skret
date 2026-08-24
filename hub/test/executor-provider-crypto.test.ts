import { describe, expect, it } from "vitest";
import {
  AwsSourceClient,
  KmsClient,
  ProviderEnvelopeLifecycle,
  SourceMissingError,
  canonicalKmsEncryptionContext,
  createEnvelopeContext,
  createProviderEnvelope,
  decryptProviderEnvelope,
  encodeLengthPrefixed,
  type AwsParameterMetadata,
  type AwsSourceTransport,
  type KmsTransport,
  type PersistedProviderEnvelope,
  type PreparedProviderGeneration,
  type ProviderEnvelopeGenerationStore,
  type SourceIdentity,
} from "../src/executor-provider-crypto";
const SOURCE: SourceIdentity = {
  partition: "aws",
  account: "123456789012",
  region: "ap-southeast-1",
  fullParameterName: "/fixture/skret/value",
  version: 1,
  lifecycleLabel: "gen-fixture-1",
};

const CONTEXT = createEnvelopeContext({
  operationId: "op-fixture-1",
  generation: "generation-fixture-1",
  sourceIdentity: SOURCE,
  targetSetDigest: `sha256:${"a".repeat(64)}`,
});

const DATA_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const ENCRYPTED_DATA_KEY = Uint8Array.from({ length: 32 }, (_, index) => 0xa0 + index);
const IV = Uint8Array.from({ length: 12 }, (_, index) => index + 1);
const FIXTURE_VALUE = new TextEncoder().encode("synthetic-fixture-value");

function metadata(overrides: Partial<AwsParameterMetadata> = {}): AwsParameterMetadata {
  return {
    exists: true,
    parameterName: SOURCE.fullParameterName,
    version: SOURCE.version,
    versionCount: 1,
    labels: [],
    ...overrides,
  };
}

class FakeKmsTransport implements KmsTransport {
  readonly calls: Array<{ operation: string; context: Readonly<Record<string, string>> }> = [];
  disabled = false;
  wrongContext = false;

  async generateDataKey(request: Parameters<KmsTransport["generateDataKey"]>[0]) {
    this.calls.push({ operation: "GenerateDataKey", context: request.encryptionContext });
    if (this.disabled) throw new Error("synthetic KMS disabled");
    return {
      plaintextDataKey: DATA_KEY.slice(),
      encryptedDataKey: ENCRYPTED_DATA_KEY.slice(),
    };
  }

  async decrypt(request: Parameters<KmsTransport["decrypt"]>[0]) {
    this.calls.push({ operation: "Decrypt", context: request.encryptionContext });
    if (this.disabled || this.wrongContext || request.encryptedDataKey.some((byte, index) => byte !== ENCRYPTED_DATA_KEY[index])) {
      throw new Error("synthetic KMS rejected context");
    }
    return { plaintextDataKey: DATA_KEY.slice() };
  }
}

class FakeAwsTransport implements AwsSourceTransport {
  readonly calls: string[] = [];
  currentMetadata = metadata();
  currentValue: Uint8Array | null = FIXTURE_VALUE.slice();
  labelReadback: number | null = null;
  throwAfterLabelCommit = false;
  throwAfterUnlabelCommit = false;
  labelReadbackOverride: number | null | undefined;

  async describeParameterVersion(request: Parameters<AwsSourceTransport["describeParameterVersion"]>[0]) {
    this.calls.push(`Describe:${request.parameterName}:${request.version}`);
    if (!this.currentMetadata.exists) return null;
    return structuredClone(this.currentMetadata);
  }

  async readParameterVersion(request: Parameters<AwsSourceTransport["readParameterVersion"]>[0]) {
    this.calls.push(`Get:${request.parameterName}:${request.version}:decrypt`);
    return this.currentValue?.slice() ?? null;
  }

  async labelParameterVersion(request: Parameters<AwsSourceTransport["labelParameterVersion"]>[0]) {
    this.calls.push(`Label:${request.parameterName}:${request.version}:${request.label}`);
    this.labelReadback = request.version;
    if (this.throwAfterLabelCommit) throw new Error("synthetic dropped label response");
  }

  async readParameterLabel(request: Parameters<AwsSourceTransport["readParameterLabel"]>[0]) {
    this.calls.push(`ReadLabel:${request.parameterName}:${request.label}`);
    return this.labelReadbackOverride === undefined ? this.labelReadback : this.labelReadbackOverride;
  }

  async unlabelParameterVersion(request: Parameters<AwsSourceTransport["unlabelParameterVersion"]>[0]) {
    this.calls.push(`Unlabel:${request.parameterName}:${request.version}:${request.label}`);
    this.labelReadback = null;
    if (this.throwAfterUnlabelCommit) throw new Error("synthetic dropped unlabel response");
  }
}
class FakeGenerationStore implements ProviderEnvelopeGenerationStore {
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


async function expectInvalidEnvelope(
  envelope: PersistedProviderEnvelope,
  kms: KmsClient,
  context = CONTEXT,
): Promise<void> {
  await expect(
    decryptProviderEnvelope({
      envelope,
      context,
      keyReference: "fixture-kms-key",
      kms,
    }),
  ).rejects.toThrow("invalid provider envelope");
}

describe("executor provider envelope crypto", () => {
  it("encodes MAC fields in fixed order with unsigned big-endian lengths", () => {
    expect(Array.from(encodeLengthPrefixed([new Uint8Array([0x61]), new Uint8Array([0x62, 0x63])]))).toEqual([
      0,
      0,
      0,
      1,
      0x61,
      0,
      0,
      0,
      2,
      0x62,
      0x63,
    ]);
  });

  it("produces deterministic ciphertext, context digest, and MAC for a fixed vector", async () => {
    const kms = new KmsClient(new FakeKmsTransport());
    const first = await createProviderEnvelope({
      plaintext: FIXTURE_VALUE.slice(),
      context: CONTEXT,
      keyReference: "fixture-kms-key",
      iv: IV,
      kms,
    });
    const second = await createProviderEnvelope({
      plaintext: FIXTURE_VALUE.slice(),
      context: CONTEXT,
      keyReference: "fixture-kms-key",
      iv: IV,
      kms,
    });

    expect(first).toEqual(second);
    expect(first.contextDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(first.ciphertext).not.toContain("synthetic-fixture-value");
    expect(first.mac).not.toContain("synthetic-fixture-value");
    expect(JSON.stringify(first)).not.toContain("plaintext");
  });

  it("fails closed on ciphertext, MAC, references, context, and encrypted-data-key tampering", async () => {
    const kms = new KmsClient(new FakeKmsTransport());
    const envelope = await createProviderEnvelope({
      plaintext: FIXTURE_VALUE.slice(),
      context: CONTEXT,
      keyReference: "fixture-kms-key",
      iv: IV,
      kms,
    });

    await expectInvalidEnvelope({ ...envelope, ciphertext: `${envelope.ciphertext.slice(0, -1)}A` }, kms);
    await expectInvalidEnvelope({ ...envelope, mac: `${envelope.mac.slice(0, -1)}A` }, kms);
    await expectInvalidEnvelope(
      envelope,
      kms,
      createEnvelopeContext({ ...CONTEXT, generation: "generation-fixture-tampered" }),
    );
    await expect(
      decryptProviderEnvelope({
        envelope: { ...envelope, encryptedDataKey: `${envelope.encryptedDataKey.slice(0, -1)}A` },
        context: CONTEXT,
        keyReference: "fixture-kms-key",
        kms,
      }),
    ).rejects.toThrow("KMS operation failed");
    await expectInvalidEnvelope(
      {
        ...envelope,
        references: envelope.references.map((reference, index) =>
          index === 0 ? { ...reference, id: `${reference.id}-tampered` } : reference,
        ),
      },
      kms,
    );
  });

  it("passes exact canonical context to GenerateDataKey and Decrypt and fails disabled or wrong-context KMS", async () => {
    const transport = new FakeKmsTransport();
    const kms = new KmsClient(transport);
    const envelope = await createProviderEnvelope({
      plaintext: FIXTURE_VALUE.slice(),
      context: CONTEXT,
      keyReference: "fixture-kms-key",
      iv: IV,
      kms,
    });
    expect(transport.calls[0]?.operation).toBe("GenerateDataKey");
    expect(transport.calls[0]?.context).toEqual(canonicalKmsEncryptionContext(CONTEXT));

    const recovered = await decryptProviderEnvelope({
      envelope,
      context: CONTEXT,
      keyReference: "fixture-kms-key",
      kms,
    });
    expect(recovered).toEqual(FIXTURE_VALUE);
    expect(transport.calls[1]?.operation).toBe("Decrypt");

    transport.wrongContext = true;
    await expect(decryptProviderEnvelope({ envelope, context: CONTEXT, keyReference: "fixture-kms-key", kms }))
      .rejects.toThrow("KMS operation failed");
    transport.wrongContext = false;
    transport.disabled = true;
    await expect(decryptProviderEnvelope({ envelope, context: CONTEXT, keyReference: "fixture-kms-key", kms }))
      .rejects.toThrow("KMS operation failed");
  });
});

describe("AWS source client and lifecycle", () => {
  it("accepts exact monotonically increasing versions but rejects invalid numbers before transport", async () => {
    const transport = new FakeAwsTransport();
    const client = new AwsSourceClient(transport);
    await expect(client.readExact(SOURCE)).resolves.toMatchObject({ metadata: { version: 1 } });

    transport.currentMetadata = metadata({ version: 101, versionCount: 100 });
    await expect(client.readExact({ ...SOURCE, version: 101 })).resolves.toMatchObject({
      metadata: { version: 101 },
    });

    const before = transport.calls.length;
    await expect(client.readExact({ ...SOURCE, version: 0 })).rejects.toThrow("provider source boundary");
    expect(transport.calls).toHaveLength(before);
  });

  it("blocks full version and label-slot boundaries and detects label drift", async () => {
    const transport = new FakeAwsTransport();
    const client = new AwsSourceClient(transport);
    transport.currentMetadata = metadata({ versionCount: 101 });
    await expect(client.preflight(SOURCE)).rejects.toThrow("provider source boundary");

    transport.currentMetadata = metadata({ labels: Array.from({ length: 10 }, (_, i) => ({ label: `l-${i}`, version: 1 })) });
    await expect(client.preflight(SOURCE)).rejects.toThrow("provider label boundary");

    transport.currentMetadata = metadata({ labels: [{ label: SOURCE.lifecycleLabel, version: 2 }] });
    await expect(client.preflight(SOURCE)).rejects.toThrow("provider label drift");
  });

  it("requires exact label readback and exact absence readback during cleanup", async () => {
    const transport = new FakeAwsTransport();
    const client = new AwsSourceClient(transport);
    transport.labelReadbackOverride = 2;
    await expect(client.labelExact(SOURCE)).rejects.toThrow("provider label readback mismatch");

    transport.labelReadbackOverride = SOURCE.version;
    await expect(client.labelExact(SOURCE)).resolves.toBeUndefined();
    transport.labelReadbackOverride = SOURCE.version;
    await expect(client.unlabelExact(SOURCE)).rejects.toThrow("provider label cleanup mismatch");
    transport.labelReadbackOverride = undefined;
    transport.throwAfterLabelCommit = true;
    await expect(client.labelExact(SOURCE)).resolves.toBeUndefined();
    expect(transport.calls.filter((call) => call.startsWith("Label:"))).toHaveLength(3);

    transport.throwAfterUnlabelCommit = true;
    await expect(client.unlabelExact(SOURCE)).resolves.toBeUndefined();
    expect(transport.calls.filter((call) => call.startsWith("Unlabel:"))).toHaveLength(2);
  });

  it("labels and reads back before envelope creation, and retains state at every cleanup kill point", async () => {
    const aws = new FakeAwsTransport();
    const kmsTransport = new FakeKmsTransport();
    const store = new FakeGenerationStore();
    const lifecycle = new ProviderEnvelopeLifecycle(
      new AwsSourceClient(aws),
      new KmsClient(kmsTransport),
      store,
    );
    const events: string[] = [];
    const prepared = await lifecycle.prepare({
      operationId: CONTEXT.operationId,
      generation: CONTEXT.generation,
      sourceIdentity: SOURCE,
      targetSetDigest: CONTEXT.targetSetDigest,
      keyReference: "fixture-kms-key",
      targetIdentities: ["github|fixture/repo|SECRET"],
      iv: IV,
      onEvent: (event) => events.push(event),
    });
    const restarted = new ProviderEnvelopeLifecycle(
      new AwsSourceClient(aws),
      new KmsClient(kmsTransport),
      store,
    );
    expect(events.indexOf("label-readback")).toBeLessThan(events.indexOf("kms-generate"));
    await expect(restarted.getRetained(prepared.operationId)).resolves.toBeDefined();

    for (const killPoint of ["after-final-acknowledgement", "during-canary", "after-canary", "during-cleanup"] as const) {
      const result = await restarted.cleanup({
        operationId: prepared.operationId,
        acknowledgements: [{ targetIdentity: "github|fixture/repo|SECRET", acknowledged: true }],
        canary: "passed",
        postconditions: "passed",
        explicitVerification: true,
        onKillPoint: (point) => {
          if (point === killPoint) throw new Error("synthetic kill point");
        },
      });
      expect(result.status).toBe("retained");
      await expect(restarted.getRetained(prepared.operationId)).resolves.toBeDefined();
    }

    const result = await restarted.cleanup({
      operationId: prepared.operationId,
      acknowledgements: [{ targetIdentity: "github|fixture/repo|SECRET", acknowledged: true }],
      canary: "passed",
      postconditions: "passed",
      explicitVerification: true,
    });
    expect(result.status).toBe("cleaned");
    await expect(restarted.getRetained(prepared.operationId)).resolves.toBeUndefined();
  });

  it("recovers a deleted source from a valid envelope and classifies invalid envelope as source_unrecoverable", async () => {
    const aws = new FakeAwsTransport();
    const kmsTransport = new FakeKmsTransport();
    const kms = new KmsClient(kmsTransport);
    const lifecycle = new ProviderEnvelopeLifecycle(new AwsSourceClient(aws), kms, new FakeGenerationStore());
    const prepared = await lifecycle.prepare({
      operationId: CONTEXT.operationId,
      generation: CONTEXT.generation,
      sourceIdentity: SOURCE,
      targetSetDigest: CONTEXT.targetSetDigest,
      keyReference: "fixture-kms-key",
      targetIdentities: ["github|fixture/repo|SECRET"],
      iv: IV,
    });
    aws.currentMetadata = metadata({ exists: false });
    aws.currentValue = null;

    const recovered = await lifecycle.recover({ prepared });
    expect(recovered.status).toBe("recovered");
    if (recovered.status === "recovered") expect(recovered.value).toEqual(FIXTURE_VALUE);

    const invalid = await lifecycle.recover({
      prepared: { ...prepared, envelope: { ...prepared.envelope, mac: `${prepared.envelope.mac.slice(0, -1)}A` } },
    });
    expect(invalid.status).toBe("source_unrecoverable");
    kmsTransport.disabled = true;
    expect((await lifecycle.recover({ prepared })).status).toBe("recovery_unavailable");
  });

  it("does not clean up without explicit acknowledgements, canary, and postconditions", async () => {
    const aws = new FakeAwsTransport();
    const lifecycle = new ProviderEnvelopeLifecycle(
      new AwsSourceClient(aws),
      new KmsClient(new FakeKmsTransport()),
      new FakeGenerationStore(),
    );
    const prepared = await lifecycle.prepare({
      operationId: CONTEXT.operationId,
      generation: CONTEXT.generation,
      sourceIdentity: SOURCE,
      targetSetDigest: CONTEXT.targetSetDigest,
      keyReference: "fixture-kms-key",
      targetIdentities: ["github|fixture/repo|SECRET"],
      iv: IV,
    });
    const result = await lifecycle.cleanup({
      operationId: prepared.operationId,
      acknowledgements: [{ targetIdentity: "github|fixture/repo|SECRET", acknowledged: false }],
      canary: "pending",
      postconditions: "pending",
      explicitVerification: false,
    });
    expect(result.status).toBe("retained");
    expect(aws.calls.some((call) => call.startsWith("Unlabel:"))).toBe(false);
  });

  it("uses a value-free missing-source error", async () => {
    const transport = new FakeAwsTransport();
    transport.currentMetadata = metadata({ exists: false });
    const client = new AwsSourceClient(transport);
    await expect(client.readExact(SOURCE)).rejects.toBeInstanceOf(SourceMissingError);
    await expect(client.readExact(SOURCE)).rejects.toThrow("provider source missing");
  });
});
