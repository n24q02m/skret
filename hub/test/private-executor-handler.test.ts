import { describe, expect, it, vi } from "vitest";
import { ExecutorReplayRejectedError } from "../src/executor-replay-store";
import { ExecutorEnvelopeInvalidError, type ExecutorEnvelope } from "../src/executor-envelope-verifier";
import {
  handlePrivateExecutorEnvelope,
  MAX_PRIVATE_EXECUTOR_BYTES,
  PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER,
  PRIVATE_EXECUTOR_PATH,
  type PrivateExecutorHandlerOptions,
  type PrivateExecutorReplayStore,
} from "../src/private-executor-handler";


const NOW = Date.parse("2026-08-23T12:00:00.000Z");
const EXPIRES_AT = "2026-08-23T12:05:00.123Z";
const AUDIENCE = "hub-executor";
const ROLE = "operator";
const NONCE = "nonce-handler-123";
const MANIFEST_DIGEST = `sha256:${"a".repeat(64)}`;
const BODY = new TextEncoder().encode('{"operation":"sync"}');
const CALLER_CONTEXT = `sha256:${"b".repeat(64)}`;

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function goJSONString(value: unknown): string {
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/gu, (character) => {
    const escapes: Record<string, string> = {
      "<": "\\u003c",
      ">": "\\u003e",
      "&": "\\u0026",
      "\u2028": "\\u2028",
      "\u2029": "\\u2029",
    };
    return escapes[character];
  });
}

function canonicalExpiry(value: string): string {
  const match = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:Z|[+-]\d{2}:\d{2})$/u.exec(value);
  if (!match) return value;
  const nanoseconds = Number((match[1] ?? "").padEnd(9, "0"));
  const fraction = String(nanoseconds).padStart(9, "0").replace(/0+$/u, "");
  const instant = new Date(value);
  return `${instant.toISOString().slice(0, 19)}${fraction ? `.${fraction}` : ""}Z`;
}

function canonicalBytes(envelope: ExecutorEnvelope): Uint8Array {
  return new TextEncoder().encode(
    goJSONString({
      version: envelope.version,
      audience: envelope.audience,
      role: envelope.role,
      manifest_digest: envelope.manifest_digest,
      body_digest: envelope.body_digest,
      nonce: envelope.nonce,
      expires_at: canonicalExpiry(envelope.expires_at),
      body: envelope.body,
    }),
  );
}

async function keyPair(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("raw", pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(exported as ArrayBuffer) };
}

async function makeEnvelope(
  privateKey: CryptoKey,
  overrides: Partial<ExecutorEnvelope> = {},
): Promise<ExecutorEnvelope> {
  const bodyDigest = `sha256:${await sha256Hex(BODY)}`;
  const envelope: ExecutorEnvelope = {
    version: 1,
    audience: AUDIENCE,
    role: ROLE,
    manifest_digest: MANIFEST_DIGEST,
    body_digest: bodyDigest,
    nonce: NONCE,
    expires_at: EXPIRES_AT,
    body: toBase64(BODY),
    signature: "",
    ...overrides,
  };
  const signature = await crypto.subtle.sign("Ed25519", privateKey, canonicalBytes(envelope));
  return {
    ...envelope,
    signature: overrides.signature ?? toBase64(new Uint8Array(signature)),
  };
}

function request(
  body: BodyInit | null,
  init: RequestInit & { url?: string } = {},
): Request {
  const { url = `https://executor.internal${PRIVATE_EXECUTOR_PATH}`, ...requestInit } = init;
  const headers = new Headers(requestInit.headers);
  if (!requestInit.headers) {
    headers.set(PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER, CALLER_CONTEXT);
  }
  const method = requestInit.method ?? "POST";
  return new Request(url, { ...requestInit, method, headers, body: method === "GET" || method === "HEAD" ? null : body });
}

function storeThat(records: string[] = []): PrivateExecutorReplayStore {
  return {
    async consume(scope) {
      records.push(`${scope.audience}:${scope.role}:${scope.nonce}`);
    },
  };
}

async function options(
  publicKey: Uint8Array,
  replayStore: PrivateExecutorReplayStore = storeThat(),
  execute: PrivateExecutorHandlerOptions["execute"] = async () => new Uint8Array([1, 2, 3]),
): Promise<PrivateExecutorHandlerOptions> {
  return {
    expectedAudience: AUDIENCE,
    expectedRoles: [ROLE],
    publicKey,
    replayStore,
    execute,
    now: NOW,
  };
}

describe("private executor envelope handler", () => {
  it("checks policy, verifies and consumes replay, then executes once and returns a copied result", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const order: string[] = [];
    const result = new Uint8Array([1, 2, 3]);
    const replayStore = storeThat(order);
    const execute = vi.fn(async (body: Uint8Array, received: ExecutorEnvelope) => {
      order.push("execute");
      expect(body).toEqual(BODY);
      expect(received).toEqual(envelope);
      return result;
    });

    const response = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(envelope)),
      await options(publicKey, replayStore, execute),
    );
    result[0] = 9;

    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    expect(order).toEqual(["hub-executor:operator:nonce-handler-123", "execute"]);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(response.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("Content-Security-Policy")).toBe("default-src 'none'; base-uri 'none'");
  });

  it("rejects non-POST requests before replay consumption or execution", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const consume = vi.fn();
    const execute = vi.fn();

    const response = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(envelope), { method: "GET" }),
      await options(publicKey, { consume }, execute),
    );

    expect(response.status).toBe(405);
    expect(await response.text()).toBe("");
    expect(consume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects the non-fixed path before replay consumption or execution", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const consume = vi.fn();
    const execute = vi.fn();

    const response = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(envelope), { url: "https://executor.internal/operator/other" }),
      await options(publicKey, { consume }, execute),
    );

    expect(response.status).toBe(404);
    expect(await response.text()).toBe("");
    expect(consume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it.each([
    ["missing", undefined],
    ["uppercase", `sha256:${"B".repeat(64)}`],
    ["short", "sha256:abcd"],
  ])("rejects %s caller context before replay consumption or execution", async (_name, value) => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const consume = vi.fn();
    const execute = vi.fn();
    const headers = new Headers();
    if (value !== undefined) headers.set(PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER, value);

    const response = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(envelope), { headers }),
      await options(publicKey, { consume }, execute),
    );

    expect(response.status).toBe(400);
    expect(await response.text()).toBe("");
    expect(consume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("accepts a signed envelope for any explicitly configured role", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey, { role: "provider-sync" });
    const execute = vi.fn(async () => new Uint8Array([7]));
    const base = await options(publicKey, storeThat(), execute);
    const response = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(envelope)),
      { ...base, expectedRoles: [ROLE, "provider-sync"] },
    );
    expect(response.status).toBe(200);
    expect(execute).toHaveBeenCalledOnce();
  });

  it.each([
    ["audience", { audience: "other-audience" }],
    ["role", { role: "other-role" }],
  ])("rejects wrong %s policy before replay consumption", async (_name, override) => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey, override);
    const consume = vi.fn();
    const execute = vi.fn();

    const response = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(envelope)),
      await options(publicKey, { consume }, execute),
    );

    expect(response.status).toBe(403);
    expect(await response.text()).toBe("");
    expect(consume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects an oversized request without consuming replay or executing", async () => {
    const { publicKey } = await keyPair();
    const consume = vi.fn();
    const execute = vi.fn();
    const body = "x".repeat(MAX_PRIVATE_EXECUTOR_BYTES + 1);

    const response = await handlePrivateExecutorEnvelope(
      request(body),
      await options(publicKey, { consume }, execute),
    );

    expect(response.status).toBe(413);
    expect(await response.text()).toBe("");
    expect(consume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects malformed JSON without consuming replay or executing", async () => {
    const { publicKey } = await keyPair();
    const consume = vi.fn();
    const execute = vi.fn();

    const response = await handlePrivateExecutorEnvelope(
      request("not-json"),
      await options(publicKey, { consume }, execute),
    );

    expect(response.status).toBe(400);
    expect(await response.text()).toBe("");
    expect(consume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects missing or invalid dependencies with a generic no-body response", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const incomplete = [
      { expectedAudience: AUDIENCE, expectedRoles: [ROLE], publicKey: new Uint8Array(31), replayStore: storeThat(), execute: vi.fn() },
      { expectedAudience: AUDIENCE, expectedRoles: [ROLE], publicKey, replayStore: undefined, execute: vi.fn() },
      { expectedAudience: AUDIENCE, expectedRoles: [ROLE], publicKey, replayStore: storeThat(), execute: undefined },
      { expectedAudience: AUDIENCE, expectedRoles: [], publicKey, replayStore: storeThat(), execute: vi.fn() },
      { expectedAudience: AUDIENCE, expectedRoles: [ROLE, ROLE], publicKey, replayStore: storeThat(), execute: vi.fn() },
    ];

    for (const candidate of incomplete) {
      const response = await handlePrivateExecutorEnvelope(
        request(JSON.stringify(envelope)),
        candidate as unknown as PrivateExecutorHandlerOptions,
      );
      expect(response.status).toBe(503);
      expect(await response.text()).toBe("");
    }
  });

  it("does not execute when the verifier rejects replay", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const execute = vi.fn();
    const response = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(envelope)),
      await options(
        publicKey,
        {
          async consume() {
            throw new ExecutorReplayRejectedError();
          },
        },
        execute,
      ),
    );

    expect(response.status).toBe(409);
    expect(await response.text()).toBe("");
    expect(execute).not.toHaveBeenCalled();
  });

  it("executes an accepted replay scope only once", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const consumed = new Set<string>();
    const replayStore: PrivateExecutorReplayStore = {
      async consume(scope) {
        const key = `${scope.audience}:${scope.role}:${scope.nonce}`;
        if (consumed.has(key)) throw new ExecutorReplayRejectedError();
        consumed.add(key);
      },
    };
    const execute = vi.fn(async () => new Uint8Array([7]));
    const handlerOptions = await options(publicKey, replayStore, execute);

    const first = await handlePrivateExecutorEnvelope(request(JSON.stringify(envelope)), handlerOptions);
    const second = await handlePrivateExecutorEnvelope(request(JSON.stringify(envelope)), handlerOptions);

    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("maps operation failures and oversized results to generic 502 responses", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const secret = "operation-secret-that-must-not-escape";
    const failing = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(envelope)),
      await options(publicKey, storeThat(), async () => {
        throw new Error(secret);
      }),
    );
    expect(failing.status).toBe(502);
    expect(await failing.text()).toBe("");

    const oversizedEnvelope = await makeEnvelope(privateKey, { nonce: "nonce-oversized-result" });
    const oversized = await handlePrivateExecutorEnvelope(
      request(JSON.stringify(oversizedEnvelope)),
      await options(publicKey, storeThat(), async () => new Uint8Array(MAX_PRIVATE_EXECUTOR_BYTES + 1)),
    );
    expect(oversized.status).toBe(502);
    expect(await oversized.text()).toBe("");
    expect((await oversized.arrayBuffer()).byteLength).toBe(0);
    expect(failing.headers.get("Content-Type")).toBeNull();
  });

  it("maps invalid envelopes to a generic response without exposing verifier errors", async () => {
    const { publicKey } = await keyPair();
    const consume = vi.fn();
    const execute = vi.fn();
    const invalid = await handlePrivateExecutorEnvelope(
      request(JSON.stringify({ version: 1, audience: AUDIENCE, role: ROLE })),
      await options(publicKey, { consume }, execute),
    );

    expect(invalid.status).toBe(400);
    expect(await invalid.text()).toBe("");
    expect(consume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
    expect(invalid.headers.get("Content-Type")).toBeNull();
    expect(ExecutorEnvelopeInvalidError).toBeDefined();
  });
});
