import { describe, expect, it, vi } from "vitest";
import {
  DurableExecutorReplayStore,
  ExecutorReplayRejectedError,
  type ExecutorReplayScope,
} from "../src/executor-replay-store";
import {
  verifyAndConsumeExecutorEnvelope,
  type ExecutorEnvelope,
} from "../src/executor-envelope-verifier";

const NOW = Date.parse("2026-08-23T12:00:00.000Z");
const EXPIRES_AT = "2026-08-23T12:05:00.123Z";
const AUDIENCE = "hub-executor";
const ROLE = "operator";
const NONCE = "nonce-123";
const MANIFEST_DIGEST = `sha256:${"a".repeat(64)}`;
const BODY = new TextEncoder().encode('{"operation":"sync"}');



interface ReplayTransaction {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

class FakeDurableStorage {
  readonly values = new Map<string, unknown>();
  failNextTransactionWith?: Error;
  transactionCalls = 0;
  private transactionTail = Promise.resolve();

  async transaction<T>(closure: (transaction: ReplayTransaction) => Promise<T>): Promise<T> {
    const previous = this.transactionTail;
    let release!: () => void;
    this.transactionTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    this.transactionCalls += 1;
    try {
      if (this.failNextTransactionWith) {
        const error = this.failNextTransactionWith;
        this.failNextTransactionWith = undefined;
        throw error;
      }
      return await closure({
        get: async <V>(key: string) => this.values.get(key) as V | undefined,
        put: async <V>(key: string, value: V) => {
          this.values.set(key, value);
        },
        delete: async (key: string) => this.values.delete(key),
      });
    } finally {
      release();
    }
  }
}

function storeFor(storage: FakeDurableStorage): DurableExecutorReplayStore {
  return new DurableExecutorReplayStore(storage as unknown as DurableObjectStorage);
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
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
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    canonicalBytes(envelope),
  );
  return {
    ...envelope,
    signature: overrides.signature ?? toBase64(new Uint8Array(signature)),
  };

}
async function keyPair(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey(
    "Ed25519",
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("raw", pair.publicKey);
  const publicKey = new Uint8Array(exported as ArrayBuffer);
  return { privateKey: pair.privateKey, publicKey };
}

function scopeOf(envelope: ExecutorEnvelope): ExecutorReplayScope {
  return {
    audience: envelope.audience,
    role: envelope.role,
    nonce: envelope.nonce,
  };
}

describe("verifyAndConsumeExecutorEnvelope", () => {
  it("verifies canonical bytes, consumes replay scope, and returns a copy of the body", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const storage = new FakeDurableStorage();
    const store = storeFor(storage);

    const result = await verifyAndConsumeExecutorEnvelope(envelope, publicKey, store, NOW);

    expect(result).toEqual(BODY);
    expect(result).not.toBe(BODY);
    result[0] ^= 0xff;
    expect(fromBase64(envelope.body)).toEqual(BODY);
    expect(storage.transactionCalls).toBe(1);
    await expect(verifyAndConsumeExecutorEnvelope(envelope, publicKey, store, NOW)).rejects.toThrow(
      "executor envelope replay rejected",
    );
    expect(JSON.stringify([...storage.values.values()])).not.toContain(envelope.body);
  });

  it("matches Go RFC3339Nano canonicalization and HTML-safe JSON escaping", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey, {
      audience: "hub<executor",
      role: "operator&admin",
      nonce: "nonce\u2028line",
    });
    const storage = new FakeDurableStorage();

    await expect(verifyAndConsumeExecutorEnvelope(envelope, publicKey, storeFor(storage), NOW)).resolves.toEqual(BODY);
    expect(storage.transactionCalls).toBe(1);
  });

  it("accepts Go-signed offset and trailing-zero fractional expiries", async () => {
    const { privateKey, publicKey } = await keyPair();
    const expiresAt = "2026-08-23T14:05:00.123000+02:00";
    const envelope = await makeEnvelope(privateKey, { expires_at: expiresAt });
    const storage = new FakeDurableStorage();

    await expect(verifyAndConsumeExecutorEnvelope(envelope, publicKey, storeFor(storage), NOW)).resolves.toEqual(BODY);
    expect([...storage.values.values()]).toContainEqual({
      digest: envelope.body_digest,
      expiresAt: Date.parse(expiresAt),
    });
  });

  it.each([
    ["bad signature", async (envelope: ExecutorEnvelope) => ({ ...envelope, signature: toBase64(new Uint8Array(64)) })],
    ["short signature", async (envelope: ExecutorEnvelope) => ({ ...envelope, signature: toBase64(new Uint8Array(63)) })],
    ["changed body", async (envelope: ExecutorEnvelope) => ({ ...envelope, body: toBase64(new TextEncoder().encode("changed")) })],
    ["changed body digest", async (envelope: ExecutorEnvelope) => ({ ...envelope, body_digest: `sha256:${"b".repeat(64)}` })],
    ["changed canonical field", async (envelope: ExecutorEnvelope) => ({ ...envelope, role: "different-role" })],
  ] as const)("rejects %s before replay consume", async (_name, mutate) => {
    const { privateKey, publicKey } = await keyPair();
    const original = await makeEnvelope(privateKey);
    const envelope = await mutate(original);
    const storage = new FakeDurableStorage();

    await expect(verifyAndConsumeExecutorEnvelope(envelope, publicKey, storeFor(storage), NOW)).rejects.toThrow(
      "executor envelope",
    );
    expect(storage.transactionCalls).toBe(0);
  });

  it.each([
    ["expired", { expires_at: "2026-08-23T11:59:59.999Z" }],
    ["overlong TTL", { expires_at: "2026-08-23T12:15:00.001Z" }],
  ] as const)("rejects %s before replay consume", async (_name, override) => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey, override);
    const storage = new FakeDurableStorage();

    await expect(verifyAndConsumeExecutorEnvelope(envelope, publicKey, storeFor(storage), NOW)).rejects.toThrow(
      "executor envelope",
    );
    expect(storage.transactionCalls).toBe(0);
  });

  it("rejects unknown fields at the parsed-envelope boundary", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const storage = new FakeDurableStorage();

    await expect(
      verifyAndConsumeExecutorEnvelope({ ...envelope, extra: "unexpected" }, publicKey, storeFor(storage), NOW),
    ).rejects.toThrow("invalid executor envelope");
    expect(storage.transactionCalls).toBe(0);
  });

  it.each([
    ["missing audience", { audience: "" }],
    ["unsupported version", { version: 2 }],
    ["invalid manifest digest", { manifest_digest: "not-a-digest" }],
    ["invalid expiry", { expires_at: "not-rfc3339" }],
    ["invalid body base64", { body: "%%%" }],
    ["empty body", { body: "" }],
    ["invalid signature base64", { signature: "%%%" }],
  ] as const)("rejects %s without exposing values", async (_name, override) => {
    const { privateKey, publicKey } = await keyPair();
    const secret = "private-body-digest-and-scope";
    const envelope = await makeEnvelope(privateKey, { ...override, nonce: secret });
    const storage = new FakeDurableStorage();

    try {
      await verifyAndConsumeExecutorEnvelope(envelope, publicKey, storeFor(storage), NOW);
      throw new Error("expected verifier rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe("invalid executor envelope");
      expect((error as Error).message).not.toContain(secret);
      expect((error as Error).message).not.toContain("not-a-digest");
    }
    expect(storage.transactionCalls).toBe(0);
  });

  it("rejects malformed public keys before verification", async () => {
    const { privateKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const storage = new FakeDurableStorage();

    await expect(
      verifyAndConsumeExecutorEnvelope(envelope, new Uint8Array(31), storeFor(storage), NOW),
    ).rejects.toThrow("invalid executor envelope");
    expect(storage.transactionCalls).toBe(0);
  });

  it("maps replay-store failures without leaking the underlying error", async () => {
    const { privateKey, publicKey } = await keyPair();
    const envelope = await makeEnvelope(privateKey);
    const storage = new FakeDurableStorage();
    storage.failNextTransactionWith = new Error("storage exploded with private-body-digest");

    await expect(verifyAndConsumeExecutorEnvelope(envelope, publicKey, storeFor(storage), NOW)).rejects.toThrow(
      "executor envelope replay unavailable",
    );
    expect(storage.transactionCalls).toBe(1);

    const rejectedStore = {
      consume: vi.fn(async () => {
        throw new ExecutorReplayRejectedError();
      }),
    };
    await expect(
      verifyAndConsumeExecutorEnvelope(envelope, publicKey, rejectedStore, NOW),
    ).rejects.toThrow("executor envelope replay rejected");
    expect(rejectedStore.consume).toHaveBeenCalledWith(scopeOf(envelope), envelope.body_digest, Date.parse(EXPIRES_AT), NOW);
  });
});
