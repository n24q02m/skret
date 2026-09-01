import { describe, expect, it } from "vitest";
import { PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER, PRIVATE_EXECUTOR_PATH } from "../src/private-executor-handler";
import {
  MAX_METADATA_MIGRATION_BODY_BYTES,
  handleSecurityExecutorRequest,
  type SecurityExecutorEnv,
} from "../src/security-executor";
const NOW = Math.floor(Date.now() / 1_000) * 1_000;
const ROLE = "operator";
const AUDIENCE = "skret-security-executor";
const ROOT = "C:\\skret\\state";
const STATE_PATH = "C:\\skret\\state\\state.json";
const JOURNAL_PATH = "C:\\skret\\state\\migration-journal.json";
const SOURCE_HASH = "b".repeat(64);
const CALLER_CONTEXT = `sha256:${"c".repeat(64)}`;
const RESPONSE_KEY = new Uint8Array(Array.from({ length: 32 }, (_, index) => index + 1));
const IMAGE_DIGEST = `sha256:${"d".repeat(64)}`;
const CONFIG_DIGEST = `sha256:${"e".repeat(64)}`;

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
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

async function keyPair(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("raw", pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(exported as ArrayBuffer) };
}

interface ManifestFixture {
  readonly bytes: Uint8Array;
  readonly digest: string;
  readonly publicKey: Uint8Array;
  readonly document: Record<string, unknown>;
}

async function manifestFixture(
  overrides: {
    document?: Partial<Record<string, unknown>>;
    files?: Array<Record<string, unknown>>;
    statePath?: string;
    journalPath?: string;
    sourceHash?: string;
    sourceSize?: number;
    bodyManifestDigest?: string;
  } = {},
): Promise<ManifestFixture> {
  const { privateKey, publicKey } = await keyPair();
  const document: Record<string, unknown> = {
    version: 1,
    role: ROLE,
    audience: AUDIENCE,
    source_root: ROOT,
    files: overrides.files ?? [{ path: "state.json", size: overrides.sourceSize ?? 128, sha256: overrides.sourceHash ?? SOURCE_HASH }],
    nonce: "manifest-nonce-001",
    expires_at: new Date(NOW + 5 * 60 * 1_000).toISOString().replace(".000Z", "Z"),
    ...overrides.document,
  };
  const canonical = canonicalManifestBytes(document);
  const signature = await crypto.subtle.sign("Ed25519", privateKey, canonical);
  const parsed = { ...document, signature: toBase64(new Uint8Array(signature)) };
  const bytes = new TextEncoder().encode(JSON.stringify(parsed));
  const digest = `sha256:${await sha256Hex(canonical)}`;
  return { bytes, digest: overrides.bodyManifestDigest ?? digest, publicKey, document: parsed };
}

async function migrationBody(fixture: ManifestFixture, overrides: Record<string, unknown> = {}): Promise<Uint8Array> {
  return new TextEncoder().encode(
    JSON.stringify({
      operation_id: "migration-20260824-001",
      state_path: STATE_PATH,
      journal_path: JOURNAL_PATH,
      manifest_digest: fixture.digest,
      target: "v2",
      source_hash: SOURCE_HASH,
      source_size: 128,
      state_manifest: toBase64(fixture.bytes),
      ...overrides,
    }),
  );
}

function envelopeCanonicalBytes(envelope: Record<string, unknown>): Uint8Array {
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

async function makeEnvelope(
  fixture: ManifestFixture,
  body: Uint8Array,
  envelopeOverrides: Record<string, unknown> = {},
): Promise<{ envelope: Record<string, unknown>; envelopePublicKey: Uint8Array }> {
  const { privateKey, publicKey } = await keyPair();
  const envelope: Record<string, unknown> = {
    version: 1,
    audience: AUDIENCE,
    role: ROLE,
    manifest_digest: fixture.digest,
    body_digest: `sha256:${await sha256Hex(body)}`,
    nonce: "envelope-nonce-001",
    expires_at: new Date(NOW + 5 * 60 * 1_000).toISOString().replace(".000Z", "Z"),
    body: toBase64(body),
    signature: "",
    ...envelopeOverrides,
  };
  envelope.signature = toBase64(new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, envelopeCanonicalBytes(envelope))));
  return { envelope, envelopePublicKey: publicKey };
}

function namespace() {
  return { getByName: () => ({ consume: async () => ({ status: "accepted" }) }) };
}

function operationNamespace() {
  return {
    getByName: () => ({
      begin: async (request: Record<string, unknown>) => ({ status: "started", operation: request }),
      complete: async () => ({ status: "succeeded" }),
      watchdog: async () => ({ marked_timeout: [], terminalized: [], next_alarm_at: null }),
    }),
  };
}

function envFor(fixture: ManifestFixture, envelopePublicKey: Uint8Array, overrides: Partial<SecurityExecutorEnv> = {}): SecurityExecutorEnv {
  return {
    EXECUTOR_EXPECTED_AUDIENCE: AUDIENCE,
    EXECUTOR_EXPECTED_ROLE: ROLE,
    EXECUTOR_PUBLIC_KEY: toBase64(envelopePublicKey),
    EXECUTOR_STATE_MANIFEST_PUBLIC_KEY: toBase64(fixture.publicKey),
    EXECUTOR_RESPONSE_KEY: toBase64(RESPONSE_KEY),
    EXECUTOR_REPLAY: namespace() as unknown as SecurityExecutorEnv["EXECUTOR_REPLAY"],
    EXECUTOR_OPERATIONS: operationNamespace() as unknown as SecurityExecutorEnv["EXECUTOR_OPERATIONS"],
    EXECUTOR_IMAGE_DIGEST: IMAGE_DIGEST,
    EXECUTOR_CONFIG_DIGEST: CONFIG_DIGEST,
    ...overrides,
  };
}

function request(envelope: Record<string, unknown>, bodyOverride?: BodyInit): Request {
  const headers = new Headers({ [PRIVATE_EXECUTOR_CALLER_CONTEXT_HEADER]: CALLER_CONTEXT });
  return new Request(`https://executor.internal${PRIVATE_EXECUTOR_PATH}`, {
    method: "POST",
    headers,
    body: bodyOverride ?? JSON.stringify(envelope),
  });
}

describe("security executor signed StateManifest authority", () => {
  it("accepts a valid manifest and returns only the encrypted metadata acknowledgement", async () => {
    const fixture = await manifestFixture();
    const body = await migrationBody(fixture);
    const { envelope, envelopePublicKey } = await makeEnvelope(fixture, body);

    const response = await handleSecurityExecutorRequest(request(envelope), envFor(fixture, envelopePublicKey));

    expect(response.status).toBe(200);
    const encrypted = new TextDecoder().decode(await response.arrayBuffer());
    expect(encrypted).not.toContain(ROOT);
    expect(encrypted).not.toContain(toBase64(fixture.bytes));
    expect(encrypted).not.toContain(new TextDecoder().decode(body));
  });

  it("fails closed when the independent StateManifest public key is absent or malformed", async () => {
    const fixture = await manifestFixture();
    const body = await migrationBody(fixture);
    const { envelope, envelopePublicKey } = await makeEnvelope(fixture, body);

    for (const value of [undefined, "", "not-a-key", "00"]) {
      const response = await handleSecurityExecutorRequest(
        request(envelope),
        envFor(fixture, envelopePublicKey, { EXECUTOR_STATE_MANIFEST_PUBLIC_KEY: value }),
      );
      expect(response.status).toBe(503);
      expect(await response.text()).toBe("");
    }
  });

  it.each([
    ["tampered manifest bytes", async () => {
      const fixture = await manifestFixture();
      const tampered = fixture.bytes.slice();
      tampered[tampered.length - 1] ^= 1;
      return { fixture, body: await migrationBody(fixture, { state_manifest: toBase64(tampered) }) };
    }],
    ["tampered signature", async () => {
      const fixture = await manifestFixture();
      const parsed = JSON.parse(new TextDecoder().decode(fixture.bytes)) as Record<string, unknown>;
      parsed.signature = toBase64(new Uint8Array(64));
      return { fixture, body: await migrationBody(fixture, { state_manifest: toBase64(new TextEncoder().encode(JSON.stringify(parsed))) }) };
    }],
    ["manifest role mismatch", async () => {
      const fixture = await manifestFixture({ document: { role: "reader" } });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["manifest audience mismatch", async () => {
      const fixture = await manifestFixture({ document: { audience: "other-audience" } });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["manifest digest mismatch", async () => {
      const fixture = await manifestFixture({ bodyManifestDigest: `sha256:${"d".repeat(64)}` });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["state path does not equal manifest row", async () => {
      const fixture = await manifestFixture();
      return { fixture, body: await migrationBody(fixture, { state_path: "C:\\skret\\state\\other.json" }) };
    }],
    ["source hash does not equal manifest row", async () => {
      const fixture = await manifestFixture();
      return { fixture, body: await migrationBody(fixture, { source_hash: "e".repeat(64) }) };
    }],
    ["source size does not equal manifest row", async () => {
      const fixture = await manifestFixture();
      return { fixture, body: await migrationBody(fixture, { source_size: 129 }) };
    }],
    ["expired manifest", async () => {
      const fixture = await manifestFixture({ document: { expires_at: new Date(NOW - 1).toISOString() } });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["manifest expiry exceeds fifteen minutes", async () => {
      const fixture = await manifestFixture({ document: { expires_at: new Date(NOW + 16 * 60 * 1_000).toISOString() } });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["empty nonce", async () => {
      const fixture = await manifestFixture({ document: { nonce: "" } });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["unsorted rows", async () => {
      const fixture = await manifestFixture({ files: [
        { path: "z.json", size: 1, sha256: SOURCE_HASH },
        { path: "a.json", size: 1, sha256: SOURCE_HASH },
      ] });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["negative size", async () => {
      const fixture = await manifestFixture({ files: [{ path: "state.json", size: -1, sha256: SOURCE_HASH }] });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["unsafe size", async () => {
      const fixture = await manifestFixture({ files: [{ path: "state.json", size: Number.MAX_SAFE_INTEGER + 1, sha256: SOURCE_HASH }] });
      return { fixture, body: await migrationBody(fixture) };
    }],
    ["mixed separator forward-slash traversal in Windows source root", async () => {
      const fixture = await manifestFixture({ document: { source_root: "C:\\skret/../state" } });
      return { fixture, body: await migrationBody(fixture, { state_path: "C:\\state\\state.json" }) };
    }],
    ["mixed separator forward-slash in Windows metadata path", async () => {
      const fixture = await manifestFixture();
      return { fixture, body: await migrationBody(fixture, { state_path: "C:\\skret\\state/other.json" }) };
    }],
    ["mixed separator forward-slash in UNC metadata path", async () => {
      const fixture = await manifestFixture({ document: { source_root: "\\\\server\\share\\state" } });
      return { fixture, body: await migrationBody(fixture, { state_path: "\\\\server\\share\\state/nested\\state.json" }) };
    }],
    ["Windows drive root path rejected when allowRoot is false", async () => {
      const fixture = await manifestFixture({ document: { source_root: "C:\\" } });
      return { fixture, body: await migrationBody(fixture, { state_path: "C:\\", journal_path: "C:\\" }) };
    }],
    ["UNC share root path rejected when allowRoot is false", async () => {
      const fixture = await manifestFixture({ document: { source_root: "\\\\server\\share" } });
      return { fixture, body: await migrationBody(fixture, { state_path: "\\\\server\\share", journal_path: "\\\\server\\share" }) };
    }],
  ])("rejects %s without plaintext output", async (_name, buildCase) => {
    const { fixture, body } = await buildCase();
    const { envelope, envelopePublicKey } = await makeEnvelope(fixture, body);
    const response = await handleSecurityExecutorRequest(request(envelope), envFor(fixture, envelopePublicKey));

    expect(response.status).toBe(502);
    expect(await response.text()).toBe("");
  });

  it("rejects duplicate manifest JSON keys before authority parsing", async () => {
    const fixture = await manifestFixture();
    const text = new TextDecoder().decode(fixture.bytes).replace('"nonce":"manifest-nonce-001"', '"nonce":"manifest-nonce-001","nonce":"duplicate"');
    const body = await migrationBody(fixture, { state_manifest: toBase64(new TextEncoder().encode(text)) });
    const { envelope, envelopePublicKey } = await makeEnvelope(fixture, body);

    const response = await handleSecurityExecutorRequest(request(envelope), envFor(fixture, envelopePublicKey));

    expect(response.status).toBe(502);
    expect(await response.text()).toBe("");
  });

  it("rejects an oversized migration body before decoding its manifest", async () => {
    const fixture = await manifestFixture();
    const oversized = new Uint8Array(MAX_METADATA_MIGRATION_BODY_BYTES + 1);
    oversized.fill(0x78);
    const { envelope, envelopePublicKey } = await makeEnvelope(fixture, oversized);

    const response = await handleSecurityExecutorRequest(request(envelope), envFor(fixture, envelopePublicKey));

    expect(response.status).toBe(502);
    expect(await response.text()).toBe("");
  });
});
