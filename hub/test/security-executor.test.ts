import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT,
  ExecutorReplayInvalidRequestError,
  ExecutorReplayRejectedError,
  ExecutorReplayStoreUnavailableError,
} from "../src/executor-replay-store";
import { PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER, PRIVATE_EXECUTOR_PATH } from "../src/private-executor-handler";
import securityExecutor, {
  MAX_EXECUTOR_CLIENT_AUTHORITY_HORIZON_MS,
  MAX_EXECUTOR_CLIENT_PUBLIC_KEYS_JSON_LENGTH,
  MAX_METADATA_MIGRATION_BODY_BYTES,
  MAX_METADATA_MIGRATION_SOURCE_SIZE,
  METADATA_ACK_AAD_PREFIX,
  METADATA_MIGRATION_EXECUTOR_ROLE,
  SecurityExecutorReplay,
  buildSecurityExecutorOptions,
  createReplayStoreAdapter,
  handleSecurityExecutorRequest,
  type SecurityExecutorEnv,
} from "../src/security-executor";

const NOW = Date.now();
const AUDIENCE = "skret-security-executor";
const ROLE = METADATA_MIGRATION_EXECUTOR_ROLE;
let MANIFEST_DIGEST = "";
let STATE_MANIFEST_PUBLIC_KEY = new Uint8Array();
const SOURCE_HASH = "b".repeat(64);
const CALLER_CONTEXT = `sha256:${"c".repeat(64)}`;
const IMAGE_DIGEST = `sha256:${"d".repeat(64)}`;
const CONFIG_DIGEST = `sha256:${"e".repeat(64)}`;
type ReplayNamespace = NonNullable<SecurityExecutorEnv["EXECUTOR_REPLAY"]>;
const RESPONSE_KEY_BYTES = new Uint8Array(Array.from({ length: 32 }, (_, index) => index + 1));
const CLIENT_AUTHORITY_NOT_AFTER = new Date(NOW + 24 * 60 * 60 * 1000).toISOString();

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

function canonicalManifestBytes(document: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify(document).replace(/[<>&\u2028\u2029]/gu, (character) => {
      const escapes: Record<string, string> = {
        "<": "\\u003c",
        ">": "\\u003e",
        "&": "\\u0026",
        "\u2028": "\\u2028",
        "\u2029": "\\u2029",
      };
      return escapes[character];
    }),
  );
}

interface DefaultManifestFixture {
  readonly bytes: Uint8Array;
}

let defaultManifestPromise: Promise<DefaultManifestFixture> | undefined;

function defaultManifestFixture(): Promise<DefaultManifestFixture> {
  defaultManifestPromise ??= (async () => {
    const { privateKey, publicKey } = await keyPair();
    STATE_MANIFEST_PUBLIC_KEY = Uint8Array.from(publicKey);
    const document = {
      version: 1,
      role: ROLE,
      audience: AUDIENCE,
      source_root: "C:\\skret\\state",
      files: [{ path: "state.json", size: 128, sha256: SOURCE_HASH }],
      nonce: "manifest-nonce-001",
      expires_at: new Date(Math.floor(Date.now() / 1_000) * 1_000 + 5 * 60 * 1_000).toISOString().replace(".000Z", "Z"),
    };
    const canonical = canonicalManifestBytes(document);
    const signature = await crypto.subtle.sign("Ed25519", privateKey, canonical);
    MANIFEST_DIGEST = `sha256:${await sha256Hex(canonical)}`;
    return {
      bytes: new TextEncoder().encode(JSON.stringify({ ...document, signature: toBase64(new Uint8Array(signature)) })),
    };
  })();
  return defaultManifestPromise;
}

async function migrationBody(overrides: Record<string, unknown> = {}): Promise<Uint8Array> {
  const fixture = await defaultManifestFixture();
  return new TextEncoder().encode(
    JSON.stringify({
      operation_id: "migration-20260824-001",
      state_path: "C:\\skret\\state\\state.json",
      journal_path: "C:\\skret\\state\\migration-journal.json",
      manifest_digest: MANIFEST_DIGEST,
      target: "v2",
      source_hash: SOURCE_HASH,
      source_size: 128,
      state_manifest: toBase64(fixture.bytes),
      ...overrides,
    }),
  );
}

async function makeEnvelope(privateKey: CryptoKey, body?: Uint8Array, overrides: Record<string, unknown> = {}) {
  body ??= await migrationBody();
  const envelope: Record<string, unknown> = {
    version: 1,
    audience: AUDIENCE,
    role: ROLE,
    manifest_digest: MANIFEST_DIGEST,
    body_digest: `sha256:${await sha256Hex(body)}`,
    nonce: "nonce-security-executor-001",
    expires_at: new Date(Math.floor(Date.now() / 1_000) * 1_000 + 5 * 60 * 1_000).toISOString().replace(".000Z", "Z"),
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
  let operation: Record<string, unknown> | null = null;
  let storedResult: Uint8Array | null = null;
  const begin = vi.fn(async (request: Record<string, unknown>) => {
    if (operation?.status === "succeeded") {
      return { status: "existing", operation };
    }
    operation = { ...request, status: "active" };
    return { status: "started", operation };
  });
  const complete = vi.fn(
    async (
      _operationID: string,
      _invocationID: string,
      _status: string,
      _digest: string | null,
      _now: number,
      redactedResult?: Uint8Array,
    ) => {
      if (redactedResult) storedResult = redactedResult.slice();
      operation = { ...(operation ?? {}), status: "succeeded" };
      return operation;
    },
  );
  const readResult = vi.fn(async () => storedResult?.slice() ?? null);
  const watchdog = vi.fn(async () => ({ marked_timeout: [], terminalized: [], next_alarm_at: null }));
  return {
    consume,
    sweep,
    begin,
    complete,
    readResult,
    watchdog,
    namespace: {
      getByName: vi.fn(() => ({ consume, sweep })),
    },
    operationNamespace: {
      getByName: vi.fn(() => ({ begin, complete, readResult, watchdog })),
    },
  };
}

function clientAuthority(
  publicKey: Uint8Array,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    public_key: toBase64(publicKey),
    generation: 1,
    not_after: CLIENT_AUTHORITY_NOT_AFTER,
    capability_digest: MANIFEST_DIGEST || `sha256:${"a".repeat(64)}`,
    ...overrides,
  };
}

function clientPublicKeys(publicKey: Uint8Array): string {
  const roleKey = (mask: number): Uint8Array => {
    const key = publicKey.slice();
    key[0] ^= mask;
    return key;
  };
  return JSON.stringify({
    operator: clientAuthority(roleKey(1)),
    "bd-client": clientAuthority(roleKey(2)),
    [ROLE]: clientAuthority(publicKey),
    "sync-client": clientAuthority(roleKey(3)),
    "provider-sync": clientAuthority(roleKey(4)),
    "provider-sync-verification": clientAuthority(roleKey(5)),
  });
}

function envFor(
  publicKey: Uint8Array,
  namespace: unknown,
  overrides: Partial<SecurityExecutorEnv> = {},
): SecurityExecutorEnv {
  const operationNamespace = namespaceFor().operationNamespace;
  return {
    EXECUTOR_EXPECTED_AUDIENCE: AUDIENCE,
    EXECUTOR_CLIENT_PUBLIC_KEYS: clientPublicKeys(publicKey),
    EXECUTOR_STATE_MANIFEST_PUBLIC_KEY: toBase64(STATE_MANIFEST_PUBLIC_KEY),
    EXECUTOR_RESPONSE_KEY: toBase64(RESPONSE_KEY_BYTES),
    EXECUTOR_REPLAY: namespace as SecurityExecutorEnv["EXECUTOR_REPLAY"],
    EXECUTOR_OPERATIONS: operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
    EXECUTOR_IMAGE_DIGEST: IMAGE_DIGEST,
    EXECUTOR_CONFIG_DIGEST: CONFIG_DIGEST,
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
      { EXECUTOR_OPERATIONS: undefined },
      { EXECUTOR_CLIENT_PUBLIC_KEYS: "" },
      { EXECUTOR_CLIENT_PUBLIC_KEYS: "not-json" },
      { EXECUTOR_RESPONSE_KEY: "00" },
      { EXECUTOR_REPLAY: undefined },
      { EXECUTOR_EXPECTED_AUDIENCE: "a".repeat(257) },
      { EXECUTOR_RESPONSE_KEY: "a".repeat(257) },
      { EXECUTOR_IMAGE_DIGEST: undefined },
      { EXECUTOR_CONFIG_DIGEST: "not-a-digest" },
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

  it("activates only the exact migration-client authority from the validated role map", async () => {
    await defaultManifestFixture();
    const { publicKey } = await keyPair();
    const { namespace } = namespaceFor();

    const options = await buildSecurityExecutorOptions(envFor(publicKey, namespace), NOW);

    expect(options?.roleAuthorities.map((authority) => ({
      role: authority.role,
      generation: authority.generation,
      notAfter: authority.notAfter,
      capabilityDigest: authority.capabilityDigest,
      publicKey: toBase64(authority.publicKey),
    }))).toEqual([{
      role: ROLE,
      generation: 1,
      notAfter: Date.parse(CLIENT_AUTHORITY_NOT_AFTER),
      capabilityDigest: MANIFEST_DIGEST,
      publicKey: toBase64(publicKey),
    }]);
  });

  it("rejects duplicate, malformed, expired, overlong-horizon, and noncanonical authority config", async () => {
    await defaultManifestFixture();
    const { publicKey } = await keyPair();
    const { publicKey: otherPublicKey } = await keyPair();
    const { namespace } = namespaceFor();
    const valid = clientAuthority(publicKey);
    const other = clientAuthority(otherPublicKey);
    const duplicateRole = `{"operator":${JSON.stringify(valid)},"operator":${JSON.stringify(other)}}`;
    const duplicateField = JSON.stringify({ operator: valid })
      .replace('"generation":1', '"generation":1,"generation":2');
    const tooMany = Object.fromEntries(
      Array.from({ length: 17 }, (_, index) => [
        `role-${index}`,
        clientAuthority(new Uint8Array(32).fill(index + 20)),
      ]),
    );
    const cases = [
      "{}",
      "[]",
      "not-json",
      ` ${JSON.stringify({ operator: valid })}`,
      duplicateRole,
      duplicateField,
      JSON.stringify({ operator: toBase64(publicKey) }),
      JSON.stringify({ operator: { ...valid, unknown: true } }),
      JSON.stringify({ operator: clientAuthority(publicKey, { generation: 0 }) }),
      JSON.stringify({ operator: clientAuthority(publicKey, { generation: 1.5 }) }),
      JSON.stringify({ operator: clientAuthority(publicKey, { not_after: new Date(NOW).toISOString() }) }),
      JSON.stringify({
        operator: clientAuthority(publicKey, {
          not_after: new Date(NOW + MAX_EXECUTOR_CLIENT_AUTHORITY_HORIZON_MS + 1).toISOString(),
        }),
      }),
      JSON.stringify({ operator: clientAuthority(publicKey, { not_after: "not-rfc3339" }) }),
      JSON.stringify({ operator: clientAuthority(publicKey, { not_after: NOW + 60_000 }) }),
      JSON.stringify({ operator: clientAuthority(publicKey, { capability_digest: "sha256:bad" }) }),
      JSON.stringify({ operator: clientAuthority(publicKey, { public_key: "not-base64" }) }),
      JSON.stringify({ operator: clientAuthority(new Uint8Array(31)) }),
      JSON.stringify({
        operator: clientAuthority(new Uint8Array(32).fill(255), {
          public_key: toBase64Url(new Uint8Array(32).fill(255)),
        }),
      }),
      JSON.stringify({ operator: valid, "bd-client": clientAuthority(publicKey) }),
      JSON.stringify({ "bad\u0000role": valid }),
      JSON.stringify(tooMany),
      "x".repeat(MAX_EXECUTOR_CLIENT_PUBLIC_KEYS_JSON_LENGTH + 1),
    ];

    for (const configured of cases) {
      const options = await buildSecurityExecutorOptions(
        envFor(publicKey, namespace, { EXECUTOR_CLIENT_PUBLIC_KEYS: configured }),
        NOW,
      );
      expect(options, configured.slice(0, 80)).toBeNull();
    }
  });

  it("does not fall back to legacy shared role or public-key bindings", async () => {
    await defaultManifestFixture();
    const { publicKey } = await keyPair();
    const { namespace } = namespaceFor();
    const legacy = {
      ...envFor(publicKey, namespace),
      EXECUTOR_CLIENT_PUBLIC_KEYS: undefined,
      EXECUTOR_EXPECTED_ROLE: ROLE,
      EXECUTOR_PUBLIC_KEY: toBase64(publicKey),
    } as SecurityExecutorEnv;

    expect(await buildSecurityExecutorOptions(legacy, NOW)).toBeNull();
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

  it("routes only migration-client and rejects every non-migration role before replay or operation", async () => {
    await defaultManifestFixture();
    const { publicKey, privateKey } = await keyPair();
    const operation = namespaceFor();
    const env = envFor(publicKey, operation.namespace, {
      EXECUTOR_OPERATIONS: operation.operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
    });
    const accepted = await makeEnvelope(privateKey);

    const acceptedResponse = await handleSecurityExecutorRequest(
      request(JSON.stringify(accepted)),
      env,
    );

    expect(acceptedResponse.status).toBe(200);
    expect(operation.consume).toHaveBeenCalledTimes(1);
    expect(operation.begin).toHaveBeenCalledTimes(1);

    for (const [index, role] of [
      "operator",
      "bd-client",
      "sync-client",
      "provider-sync",
      "provider-sync-verification",
      "reader",
    ].entries()) {
      const denied = await makeEnvelope(privateKey, await migrationBody(), {
        role,
        nonce: `nonce-denied-role-${index}`,
      });
      const deniedResponse = await handleSecurityExecutorRequest(
        request(JSON.stringify(denied)),
        env,
      );
      expect(deniedResponse.status, role).toBe(403);
      expect(await deniedResponse.text()).toBe("");
    }
    expect(operation.consume).toHaveBeenCalledTimes(1);
    expect(operation.begin).toHaveBeenCalledTimes(1);
    expect(operation.complete).toHaveBeenCalledTimes(1);

    const tampered = await makeEnvelope(privateKey, await migrationBody(), {
      nonce: "nonce-invalid-signature",
    });
    tampered.signature = toBase64(new Uint8Array(64));
    expect((await handleSecurityExecutorRequest(request(JSON.stringify(tampered)), env)).status).toBe(400);
    expect(operation.consume).toHaveBeenCalledTimes(1);
  });

  it("rejects a configured capability mismatch before replay or durable operation side effects", async () => {
    const { publicKey, privateKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const operation = namespaceFor();
    const configured = JSON.stringify({
      [ROLE]: clientAuthority(publicKey, {
        capability_digest: `sha256:${"f".repeat(64)}`,
      }),
    });
    const env = envFor(publicKey, operation.namespace, {
      EXECUTOR_CLIENT_PUBLIC_KEYS: configured,
      EXECUTOR_OPERATIONS: operation.operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
    });

    const response = await handleSecurityExecutorRequest(request(JSON.stringify(envelope)), env);

    expect(response.status).toBe(403);
    expect(await response.text()).toBe("");
    expect(operation.consume).not.toHaveBeenCalled();
    expect(operation.begin).not.toHaveBeenCalled();
    expect(operation.complete).not.toHaveBeenCalled();
  });
  it("uses an arithmetic 1 TiB source-size bound", () => {
    expect(MAX_METADATA_MIGRATION_SOURCE_SIZE).toBe(2 ** 40);
  });

  it("rejects duplicate migration metadata keys before execution", async () => {
    const { publicKey, privateKey } = await keyPair();
    const body = new TextEncoder().encode(
      new TextDecoder().decode(await migrationBody()).replace('"source_size":128', '"source_size":128,"source_size":256'),
    );
    const { namespace } = namespaceFor();
    const envelope = await makeEnvelope(privateKey, body, { nonce: "nonce-duplicate-source-size" });

    const response = await handleSecurityExecutorRequest(request(JSON.stringify(envelope)), envFor(publicKey, namespace));

    expect([400, 502]).toContain(response.status);
    expect(await response.text()).toBe("");
  });

  it("runs one bounded replay sweep and operation watchdog batch", async () => {
    const { publicKey } = await keyPair();
    const replay = namespaceFor();
    const operations = namespaceFor();

    await securityExecutor.scheduled(
      {} as ScheduledController,
      envFor(publicKey, replay.namespace, {
        EXECUTOR_OPERATIONS: operations.operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
      }),
    );

    expect(replay.sweep).toHaveBeenCalledWith(expect.any(Number), DEFAULT_EXECUTOR_REPLAY_SWEEP_LIMIT);
    expect(operations.watchdog).toHaveBeenCalledWith(expect.any(Number));
  });

  it("fails closed when either scheduled maintenance binding or result is unavailable", async () => {
    const { publicKey } = await keyPair();
    const replay = namespaceFor();

    await expect(
      securityExecutor.scheduled({} as ScheduledController, envFor(publicKey, undefined)),
    ).rejects.toThrow("executor maintenance unavailable");
    await expect(
      securityExecutor.scheduled(
        {} as ScheduledController,
        envFor(publicKey, replay.namespace, { EXECUTOR_OPERATIONS: undefined }),
      ),
    ).rejects.toThrow("executor maintenance unavailable");

    const malformedNamespace = {
      getByName: vi.fn(() => ({ sweep: vi.fn(async () => ({ status: "unexpected", secret: "must-not-leak" })) })),
    };
    await expect(
      securityExecutor.scheduled({} as ScheduledController, envFor(publicKey, malformedNamespace)),
    ).rejects.toThrow("executor maintenance unavailable");
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
    const body = await migrationBody();
    const envelope = await makeEnvelope(privateKey, body);
    const operation = namespaceFor();
    const response = await securityExecutor.fetch(
      request(JSON.stringify(envelope)),
      envFor(publicKey, operation.namespace, {
        EXECUTOR_OPERATIONS: operation.operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
      }),
    );
    const encrypted = new TextDecoder().decode(await response.arrayBuffer());

    expect(response.status).toBe(200);
    expect(operation.begin).toHaveBeenCalledWith(
      expect.objectContaining({
        operation_id: "migration-20260824-001",
        exclusive: false,
        fingerprint: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
        generation: `authority-1-manifest-${MANIFEST_DIGEST.slice("sha256:".length)}`,
        config_digest: CONFIG_DIGEST,
      }),
      expect.any(Number),
    );
    expect(operation.complete).toHaveBeenCalledWith(
      "migration-20260824-001",
      expect.stringMatching(/^inv-[a-f0-9]{64}$/u),
      "succeeded",
      expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
      expect.any(Number),
      expect.any(Uint8Array),
    );
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

  it("changes the durable schedule and fingerprint when the client authority generation renews", async () => {
    const { publicKey, privateKey } = await keyPair();
    const body = await migrationBody();
    const envelope = await makeEnvelope(privateKey, body, { nonce: "nonce-authority-generation" });
    const firstOperation = namespaceFor();
    const renewedOperation = namespaceFor();
    const firstEnv = envFor(publicKey, firstOperation.namespace, {
      EXECUTOR_CLIENT_PUBLIC_KEYS: JSON.stringify({
        [ROLE]: clientAuthority(publicKey, { generation: 1 }),
      }),
      EXECUTOR_OPERATIONS: firstOperation.operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
    });
    const renewedEnv = envFor(publicKey, renewedOperation.namespace, {
      EXECUTOR_CLIENT_PUBLIC_KEYS: JSON.stringify({
        [ROLE]: clientAuthority(publicKey, { generation: 2 }),
      }),
      EXECUTOR_OPERATIONS: renewedOperation.operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
    });

    expect((await securityExecutor.fetch(request(JSON.stringify(envelope)), firstEnv)).status).toBe(200);
    expect((await securityExecutor.fetch(request(JSON.stringify(envelope)), renewedEnv)).status).toBe(200);

    const firstStart = firstOperation.begin.mock.calls[0]?.[0];
    const renewedStart = renewedOperation.begin.mock.calls[0]?.[0];
    expect(firstStart?.generation).toBe(`authority-1-manifest-${MANIFEST_DIGEST.slice("sha256:".length)}`);
    expect(renewedStart?.generation).toBe(`authority-2-manifest-${MANIFEST_DIGEST.slice("sha256:".length)}`);
    expect(renewedStart?.schedule_digest).not.toBe(firstStart?.schedule_digest);
    expect(renewedStart?.fingerprint).not.toBe(firstStart?.fingerprint);
  });

  it("re-encrypts a persisted redacted result for a fresh-envelope retry", async () => {
    const { publicKey, privateKey } = await keyPair();
    const body = await migrationBody();
    const firstEnvelope = await makeEnvelope(privateKey, body, { nonce: "nonce-first-ack" });
    const secondEnvelope = await makeEnvelope(privateKey, body, { nonce: "nonce-second-ack" });
    const operation = namespaceFor();
    const env = envFor(publicKey, operation.namespace, {
      EXECUTOR_OPERATIONS: operation.operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
    });

    const first = await securityExecutor.fetch(request(JSON.stringify(firstEnvelope)), env);
    const second = await securityExecutor.fetch(request(JSON.stringify(secondEnvelope)), env);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(operation.complete).toHaveBeenCalledTimes(1);
    expect(operation.readResult).toHaveBeenCalledTimes(1);
    const secondResult = JSON.parse(
      new TextDecoder().decode(await second.arrayBuffer()),
    ) as {
      iv: string;
      ciphertext: string;
    };
    const key = await crypto.subtle.importKey(
      "raw",
      RESPONSE_KEY_BYTES,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const aad = new TextEncoder().encode(
      `${METADATA_ACK_AAD_PREFIX}|${AUDIENCE}|${ROLE}|${MANIFEST_DIGEST}|${String(secondEnvelope.nonce)}`,
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(secondResult.iv), additionalData: aad },
      key,
      fromBase64Url(secondResult.ciphertext),
    );
    expect(JSON.parse(new TextDecoder().decode(plaintext))).toMatchObject({
      operation_id: "migration-20260824-001",
      status: "accepted",
    });
  });

  it("rejects extra or malformed migration metadata and oversized metadata bodies", async () => {
    const { publicKey, privateKey } = await keyPair();
    const worker = { fetch: handleSecurityExecutorRequest };
    const operation = namespaceFor();
    const env = envFor(publicKey, operation.namespace, {
      EXECUTOR_OPERATIONS: operation.operationNamespace as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
    });
    const cases = [
      await migrationBody({ extra: true }),
      await migrationBody({ target: "v1" }),
      await migrationBody({ state_path: "C:\\skret\\state\\..\\secret.json" }),
      await migrationBody({ manifest_digest: "sha256:bad" }),
      await migrationBody({ manifest_digest: `sha256:${"f".repeat(64)}` }),
      await migrationBody({ source_hash: "not-a-digest" }),
      await migrationBody({ source_size: -1 }),
      await migrationBody({ source_size: Number.MAX_SAFE_INTEGER + 1 }),
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
    expect(operation.begin).not.toHaveBeenCalled();
    expect(operation.complete).not.toHaveBeenCalled();
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
