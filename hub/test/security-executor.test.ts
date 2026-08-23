import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT,
  ExecutorReplayInvalidRequestError,
  ExecutorReplayRejectedError,
  ExecutorReplayStoreUnavailableError,
} from "../src/executor-replay-store";
import { PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER, PRIVATE_EXECUTOR_PATH } from "../src/private-executor-handler";
import securityExecutor, {
  MAX_METADATA_MIGRATION_BODY_BYTES,
  MAX_METADATA_MIGRATION_SOURCE_SIZE,
  METADATA_ACK_AAD_PREFIX,
  SecurityExecutorReplay,
  createReplayStoreAdapter,
  handleSecurityExecutorRequest,
  type SecurityExecutorEnv,
} from "../src/security-executor";

const NOW = Date.now();
const AUDIENCE = "skret-security-executor";
const ROLE = "operator";
const MANIFEST_DIGEST = `sha256:${"a".repeat(64)}`;
const SOURCE_HASH = "b".repeat(64);
const CALLER_CONTEXT = `sha256:${"c".repeat(64)}`;
type ReplayNamespace = NonNullable<SecurityExecutorEnv["EXECUTOR_REPLAY"]>;
const RESPONSE_KEY_BYTES = new Uint8Array(Array.from({ length: 32 }, (_, index) => index + 1));

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function canonicalBytes(envelope: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      version: envelope.version,
      audience: envelope.audience,
      role: envelope.role,
      manifest_digest: envelope.manifest_digest,
      body_digest: envelope.body_digest,
      nonce: envelope.nonce,
      expires_at: envelope.expires_at,
      body: envelope.body,
    }),
  );
}

async function keyPair(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("raw", pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(exported as ArrayBuffer) };
}

function migrationBody(overrides: Record<string, unknown> = {}): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      operation_id: "migration-20260824-001",
      state_path: "C:\\skret\\state\\state.json",
      journal_path: "C:\\skret\\state\\migration-journal.json",
      manifest_digest: MANIFEST_DIGEST,
      target: "v2",
      source_hash: SOURCE_HASH,
      source_size: 128,
      ...overrides,
    }),
  );
}

async function makeEnvelope(privateKey: CryptoKey, body = migrationBody(), overrides: Record<string, unknown> = {}) {
  const envelope: Record<string, unknown> = {
    version: 1,
    audience: AUDIENCE,
    role: ROLE,
    manifest_digest: MANIFEST_DIGEST,
    body_digest: `sha256:${await sha256Hex(body)}`,
    nonce: "nonce-security-executor-001",
    expires_at: new Date(Date.now() + 5 * 60 * 1_000).toISOString().replace(".000Z", "Z"),
    body: toBase64(body),
    signature: "",
    ...overrides,
  };
  const signature = await crypto.subtle.sign("Ed25519", privateKey, canonicalBytes(envelope));
  envelope.signature = toBase64(new Uint8Array(signature));
  return envelope;
}

function request(body: BodyInit | null, init: RequestInit & { url?: string } = {}): Request {
  const { url = `https://executor.internal${PRIVATE_EXECUTOR_PATH}`, ...requestInit } = init;
  const headers = new Headers(requestInit.headers);
  if (!headers.has(PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER)) headers.set(PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER, CALLER_CONTEXT);
  const method = requestInit.method ?? "POST";
  return new Request(url, { ...requestInit, method, headers, body: method === "GET" || method === "HEAD" ? null : body });
}

function namespaceFor(status: string = "accepted") {
  const consume = vi.fn(async () => ({ status }));
  const sweep = vi.fn(async () => ({ status: "swept", removed: 0, nextAfter: null }));
  return {
    consume,
    sweep,
    namespace: {
      getByName: vi.fn(() => ({ consume, sweep })),
    },
  };
}

function envFor(publicKey: Uint8Array, namespace: unknown, overrides: Partial<SecurityExecutorEnv> = {}): SecurityExecutorEnv {
  return {
    EXECUTOR_EXPECTED_AUDIENCE: AUDIENCE,
    EXECUTOR_EXPECTED_ROLE: ROLE,
    EXECUTOR_PUBLIC_KEY: toBase64(publicKey),
    EXECUTOR_RESPONSE_KEY: toBase64(RESPONSE_KEY_BYTES),
    EXECUTOR_REPLAY: namespace as SecurityExecutorEnv["EXECUTOR_REPLAY"],
    ...overrides,
  };
}

describe.sequential("security executor Worker", () => {
  it("fails closed when any required dependency is absent or malformed", async () => {
    const { publicKey, privateKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const { namespace } = namespaceFor();
    const candidates: Array<Partial<SecurityExecutorEnv>> = [
      { EXECUTOR_EXPECTED_AUDIENCE: "" },
      { EXECUTOR_EXPECTED_ROLE: "" },
      { EXECUTOR_PUBLIC_KEY: "not-a-key" },
      { EXECUTOR_RESPONSE_KEY: "00" },
      { EXECUTOR_REPLAY: undefined },
      { EXECUTOR_EXPECTED_AUDIENCE: "a".repeat(257) },
      { EXECUTOR_RESPONSE_KEY: "a".repeat(257) },
    ];

    for (const candidate of candidates) {
      const response = await handleSecurityExecutorRequest(
        request(JSON.stringify(envelope)),
        envFor(publicKey, namespace, candidate),
      );
      expect(response.status).toBe(503);
      expect(await response.text()).toBe("");
    }
  });

  it("enforces method and fixed path before accepting an envelope", async () => {
    const { publicKey, privateKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const { namespace, consume } = namespaceFor();
    const env = envFor(publicKey, namespace);

    const methodResponse = await handleSecurityExecutorRequest(request(JSON.stringify(envelope), { method: "GET" }), env);
    const pathResponse = await handleSecurityExecutorRequest(
      request(JSON.stringify(envelope), { url: "https://executor.internal/operator/other" }),
      env,
    );

    expect(methodResponse.status).toBe(405);
    expect(pathResponse.status).toBe(404);
    expect(consume).not.toHaveBeenCalled();
  });

  it("rejects missing or malformed caller context", async () => {
    const { publicKey, privateKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const { namespace, consume } = namespaceFor();
    const env = envFor(publicKey, namespace);

    const response = await handleSecurityExecutorRequest(
      request(JSON.stringify(envelope), { headers: { [PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER]: "sha256:BAD" } }),
      env,
    );

    expect(response.status).toBe(400);
    expect(consume).not.toHaveBeenCalled();
  });

  it("rejects wrong role and invalid signatures without execution", async () => {
    const { publicKey, privateKey } = await keyPair();
    const wrongRole = await makeEnvelope(privateKey, migrationBody(), { role: "reader" });
    const tampered = await makeEnvelope(privateKey);
    tampered.signature = toBase64(new Uint8Array(64));
    const { namespace, consume } = namespaceFor();
    const env = envFor(publicKey, namespace);
    const worker = { fetch: handleSecurityExecutorRequest };

    expect((await worker.fetch(request(JSON.stringify(wrongRole)), env)).status).toBe(403);
    expect((await worker.fetch(request(JSON.stringify(tampered)), env)).status).toBe(400);
    expect(consume).not.toHaveBeenCalled();
  });
  it("uses an arithmetic 1 TiB source-size bound", () => {
    expect(MAX_METADATA_MIGRATION_SOURCE_SIZE).toBe(2 ** 40);
  });

  it("rejects duplicate migration metadata keys before execution", async () => {
    const { publicKey, privateKey } = await keyPair();
    const body = new TextEncoder().encode(
      new TextDecoder().decode(migrationBody()).replace('"source_size":128', '"source_size":128,"source_size":256'),
    );
    const { namespace } = namespaceFor();
    const envelope = await makeEnvelope(privateKey, body, { nonce: "nonce-duplicate-source-size" });

    const response = await handleSecurityExecutorRequest(request(JSON.stringify(envelope)), envFor(publicKey, namespace));

    expect([400, 502]).toContain(response.status);
    expect(await response.text()).toBe("");
  });

  it("sweeps one bounded replay batch from the scheduled hook", async () => {
    const { publicKey } = await keyPair();
    const { namespace, sweep } = namespaceFor();

    await securityExecutor.scheduled({} as ScheduledController, envFor(publicKey, namespace));

    expect(sweep).toHaveBeenCalledWith(expect.any(Number), DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT);
  });

  it("fails closed when the scheduled replay sweep binding or result is unavailable", async () => {
    const { publicKey } = await keyPair();

    await expect(
      securityExecutor.scheduled({} as ScheduledController, envFor(publicKey, undefined)),
    ).rejects.toThrow("executor replay sweep unavailable");

    const malformedNamespace = {
      getByName: vi.fn(() => ({ sweep: vi.fn(async () => ({ status: "unexpected", secret: "must-not-leak" })) })),
    };
    await expect(
      securityExecutor.scheduled({} as ScheduledController, envFor(publicKey, malformedNamespace)),
    ).rejects.toThrow("executor replay sweep unavailable");
  });

  it("maps a bounded Durable Object sweep to value-free status", async () => {
    const key = `private:executor-replay:${"d".repeat(64)}`;
    const transactionRecord = { digest: `sha256:${"e".repeat(64)}`, expiresAt: NOW - 1 };
    const transaction = {
      list: vi.fn(async () => new Map([[key, transactionRecord]])),
      delete: vi.fn(async () => true),
    };
    const storage = {
      transaction: vi.fn(async (callback: (value: typeof transaction) => Promise<unknown>) => callback(transaction)),
    };
    const replay = Object.create(SecurityExecutorReplay.prototype) as SecurityExecutorReplay;
    Object.defineProperty(replay, "ctx", { value: { storage } });

    const result = await replay.sweep(NOW, 2);

    expect(result).toEqual({ status: "swept", removed: 1, nextAfter: null });
    expect(transaction.list).toHaveBeenCalledWith({
      prefix: "private:executor-replay:",
      limit: 2,
    });
    expect(transaction.delete).toHaveBeenCalledWith(key);
  });

  it("maps invalid or unavailable Durable Object sweeps without leaking details", async () => {
    const invalidReplay = Object.create(SecurityExecutorReplay.prototype) as SecurityExecutorReplay;
    Object.defineProperty(invalidReplay, "ctx", {
      value: { storage: { transaction: vi.fn(async () => { throw new Error("secret storage detail"); }) } },
    });

    const invalid = await invalidReplay.sweep(NOW, 0);
    expect(invalid).toEqual({ status: "invalid" });

    const unavailable = await invalidReplay.sweep(NOW, 1);
    expect(unavailable).toEqual({ status: "unavailable" });
    expect(JSON.stringify(unavailable)).not.toContain("secret storage detail");
  });

  it("accepts the exact metadata request and returns only encrypted metadata acknowledgement", async () => {
    const { publicKey, privateKey } = await keyPair();
    const body = migrationBody();
    const envelope = await makeEnvelope(privateKey, body);
    const { namespace } = namespaceFor();
    const response = await securityExecutor.fetch(request(JSON.stringify(envelope)), envFor(publicKey, namespace));
    const encrypted = new TextDecoder().decode(await response.arrayBuffer());

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(encrypted).not.toContain("C:\\skret\\state\\state.json");
    expect(encrypted).not.toContain(new TextDecoder().decode(body));

    const envelopeResponse = JSON.parse(encrypted) as { version: number; algorithm: string; iv: string; ciphertext: string };
    expect(envelopeResponse.version).toBe(1);
    expect(envelopeResponse.algorithm).toBe("AES-GCM");
    const key = await crypto.subtle.importKey("raw", RESPONSE_KEY_BYTES, "AES-GCM", false, ["decrypt"]);
    const aad = new TextEncoder().encode(
      `${METADATA_ACK_AAD_PREFIX}|${AUDIENCE}|${ROLE}|${MANIFEST_DIGEST}|${String(envelope.nonce)}`,
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(envelopeResponse.iv), additionalData: aad },
      key,
      fromBase64Url(envelopeResponse.ciphertext),
    );
    expect(JSON.parse(new TextDecoder().decode(plaintext))).toEqual({
      operation_id: "migration-20260824-001",
      target: "v2",
      manifest_digest: MANIFEST_DIGEST,
      source_hash: SOURCE_HASH,
      source_size: 128,
      status: "accepted",
    });
  });

  it("rejects extra or malformed migration metadata and oversized metadata bodies", async () => {
    const { publicKey, privateKey } = await keyPair();
    const worker = { fetch: handleSecurityExecutorRequest };
    const { namespace } = namespaceFor();
    const env = envFor(publicKey, namespace);
    const cases = [
      migrationBody({ extra: true }),
      migrationBody({ target: "v1" }),
      migrationBody({ state_path: "C:\\skret\\state\\..\\secret.json" }),
      migrationBody({ manifest_digest: "sha256:bad" }),
      migrationBody({ source_hash: "not-a-digest" }),
      migrationBody({ source_size: -1 }),
      migrationBody({ source_size: Number.MAX_SAFE_INTEGER + 1 }),
    ];

    for (const [index, body] of cases.entries()) {
      const envelope = await makeEnvelope(privateKey, body, { nonce: `nonce-${await sha256Hex(body)}` });
      const response = await worker.fetch(request(JSON.stringify(envelope)), env);
      expect([400, 502], `malformed case ${index}`).toContain(response.status);
    }

    const oversized = new Uint8Array(MAX_METADATA_MIGRATION_BODY_BYTES + 1);
    oversized.fill(120);
    const oversizedEnvelope = await makeEnvelope(privateKey, oversized, { nonce: "nonce-oversized-metadata" });
    expect((await worker.fetch(request(JSON.stringify(oversizedEnvelope)), env)).status).toBe(502);
  });

  it("maps replay rejection without invoking the metadata acknowledgement", async () => {
    const { publicKey, privateKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const { namespace, consume } = namespaceFor("rejected");
    const worker = { fetch: handleSecurityExecutorRequest };
    const response = await worker.fetch(request(JSON.stringify(envelope)), envFor(publicKey, namespace));

    expect(response.status).toBe(409);
    expect(await response.text()).toBe("");
    expect(consume).toHaveBeenCalledTimes(1);
  });
});

describe("security executor replay RPC adapter", () => {
  const scope = { audience: AUDIENCE, role: ROLE, nonce: "nonce-adapter" };
  const digest = `sha256:${"d".repeat(64)}`;

  it.each([
    ["rejected", ExecutorReplayRejectedError],
    ["invalid", ExecutorReplayInvalidRequestError],
    ["unavailable", ExecutorReplayStoreUnavailableError],
  ] as const)("maps DO status %s without leaking values", async (status, errorType) => {
    const { namespace } = namespaceFor(status);
    const adapter = createReplayStoreAdapter(namespace as unknown as ReplayNamespace);
    await expect(adapter.consume(scope, digest, NOW + 60_000, NOW)).rejects.toBeInstanceOf(errorType);
  });

  it("maps an unknown RPC result or thrown RPC error to unavailable", async () => {
    const thrown = {
      getByName: vi.fn(() => ({ consume: vi.fn(async () => { throw new Error("secret replay detail"); }) })),
    };
    const unknown = {
      getByName: vi.fn(() => ({ consume: vi.fn(async () => ({ status: "unexpected" })) })),
    };

    for (const namespace of [thrown, unknown]) {
      const adapter = createReplayStoreAdapter(namespace as unknown as ReplayNamespace);
      await expect(adapter.consume(scope, digest, NOW + 60_000, NOW)).rejects.toBeInstanceOf(
        ExecutorReplayStoreUnavailableError,
      );
    }
  });
});
