import {
  DurableExecutorReplayStore,
  ExecutorReplayInvalidRequestError,
  ExecutorReplayRejectedError,
  type ExecutorReplayScope,
} from "./executor-replay-store";

const SHA256_HEX_LENGTH = 64;
const SHA256_DIGEST_PATTERN = new RegExp(`^sha256:[a-f0-9]{${SHA256_HEX_LENGTH}}$`, "u");
const STANDARD_BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const RFC3339_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/u;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/u;
const MAX_SCOPE_FIELD_LENGTH = 256;

export const EXECUTOR_ENVELOPE_VERSION = 1;
export const MAX_EXECUTOR_ENVELOPE_TTL_MS = 15 * 60 * 1000;

const INVALID_EXECUTOR_ENVELOPE = "invalid executor envelope";
const EXECUTOR_ENVELOPE_REPLAY_REJECTED = "executor envelope replay rejected";
const EXECUTOR_ENVELOPE_REPLAY_UNAVAILABLE = "executor envelope replay unavailable";

const ED25519_ALGORITHM = "Ed25519";
const CANONICAL_HTML_ESCAPES: Record<string, string> = {
  "<": "\\u003c",
  ">": "\\u003e",
  "&": "\\u0026",
  "\u2028": "\\u2028",
  "\u2029": "\\u2029",
};

const CANONICAL_FIELD_NAMES = [
  "version",
  "audience",
  "role",
  "manifest_digest",
  "body_digest",
  "nonce",
  "expires_at",
  "body",
  "signature",
] as const;

/**
 * JSON shape emitted by Go's ExecutorEnvelope. Body and signature retain their
 * standard base64 representation so canonical signing can use the original
 * JSON values without a re-encoding ambiguity.
 */
export interface ExecutorEnvelope {
  readonly version: number;
  readonly audience: string;
  readonly role: string;
  readonly manifest_digest: string;
  readonly body_digest: string;
  readonly nonce: string;
  readonly expires_at: string;
  readonly body: string;
  readonly signature: string;
}

/** Alias for callers that want to make the parsed-input boundary explicit. */
export type ParsedExecutorEnvelope = ExecutorEnvelope;

export class ExecutorEnvelopeInvalidError extends Error {
  constructor() {
    super(INVALID_EXECUTOR_ENVELOPE);
    this.name = "ExecutorEnvelopeInvalidError";
  }
}

export class ExecutorEnvelopeReplayRejectedError extends Error {
  constructor() {
    super(EXECUTOR_ENVELOPE_REPLAY_REJECTED);
    this.name = "ExecutorEnvelopeReplayRejectedError";
  }
}

export class ExecutorEnvelopeReplayUnavailableError extends Error {
  constructor() {
    super(EXECUTOR_ENVELOPE_REPLAY_UNAVAILABLE);
    this.name = "ExecutorEnvelopeReplayUnavailableError";
  }
}

/** Alias retained for code that calls all verifier failures verification errors. */
export { ExecutorEnvelopeInvalidError as ExecutorEnvelopeVerificationError };

type ExecutorReplayConsumer = Pick<DurableExecutorReplayStore, "consume">;

interface ValidatedExecutorEnvelope {
  readonly envelope: ExecutorEnvelope;
  readonly body: Uint8Array;
  readonly signature: Uint8Array;
  readonly expiresAtMs: number;
  readonly canonicalBytes: Uint8Array;
}

/**
 * Verify one executor envelope and consume its durable replay scope only after
 * all signed bindings pass. Ordinary Hub routes deliberately do not import
 * this source-only executor module. Production executor wiring, replay
 * binding, and authorization remain explicit follow-up residuals.
 */
export async function verifyAndConsumeExecutorEnvelope(
  envelope: unknown,
  publicKey: Uint8Array,
  store: ExecutorReplayConsumer,
  now?: number,
): Promise<Uint8Array>;
export async function verifyAndConsumeExecutorEnvelope(
  envelope: unknown,
  publicKey: Uint8Array,
  now: number,
  store: ExecutorReplayConsumer,
): Promise<Uint8Array>;
export async function verifyAndConsumeExecutorEnvelope(
  envelope: unknown,
  publicKey: Uint8Array,
  storeOrNow: ExecutorReplayConsumer | number,
  nowOrStore?: number | ExecutorReplayConsumer,
): Promise<Uint8Array> {
  const { store, now } = resolveVerifierArguments(storeOrNow, nowOrStore);
  const validated = await validateExecutorEnvelope(envelope, publicKey, now);

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", publicKey, ED25519_ALGORITHM, false, ["verify"]);
    const valid = await crypto.subtle.verify(
      ED25519_ALGORITHM,
      key,
      validated.signature,
      validated.canonicalBytes,
    );
    if (!valid) throw new ExecutorEnvelopeInvalidError();
  } catch (error) {
    if (error instanceof ExecutorEnvelopeInvalidError) throw error;
    throw new ExecutorEnvelopeInvalidError();
  }

  if (!store || typeof store.consume !== "function") {
    throw new ExecutorEnvelopeReplayUnavailableError();
  }

  const scope: ExecutorReplayScope = {
    audience: validated.envelope.audience,
    role: validated.envelope.role,
    nonce: validated.envelope.nonce,
  };
  try {
    await store.consume(scope, validated.envelope.body_digest, validated.expiresAtMs, now);
  } catch (error) {
    if (error instanceof ExecutorReplayRejectedError) {
      throw new ExecutorEnvelopeReplayRejectedError();
    }
    if (error instanceof ExecutorReplayInvalidRequestError) {
      throw new ExecutorEnvelopeInvalidError();
    }
    throw new ExecutorEnvelopeReplayUnavailableError();
  }

  return validated.body.slice();
}

function resolveVerifierArguments(
  storeOrNow: ExecutorReplayConsumer | number,
  nowOrStore: number | ExecutorReplayConsumer | undefined,
): { store: ExecutorReplayConsumer; now: number } {
  if (typeof storeOrNow === "number") {
    if (!nowOrStore || typeof nowOrStore === "number") throw new ExecutorEnvelopeInvalidError();
    return { store: nowOrStore, now: storeOrNow };
  }
  if (nowOrStore !== undefined && typeof nowOrStore !== "number") {
    throw new ExecutorEnvelopeInvalidError();
  }
  return { store: storeOrNow, now: nowOrStore ?? Date.now() };
}

async function validateExecutorEnvelope(
  input: unknown,
  publicKey: Uint8Array,
  now: number,
): Promise<ValidatedExecutorEnvelope> {
  if (!Number.isFinite(now) || now < 0) throw new ExecutorEnvelopeInvalidError();
  if (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== 32) {
    throw new ExecutorEnvelopeInvalidError();
  }
  if (
    typeof input !== "object" ||
    input === null ||
    Array.isArray(input) ||
    !hasExactEnvelopeFields(input as Record<string, unknown>)
  ) {
    throw new ExecutorEnvelopeInvalidError();
  }

  const envelope = input as unknown as ExecutorEnvelope;
  if (envelope.version !== EXECUTOR_ENVELOPE_VERSION) throw new ExecutorEnvelopeInvalidError();
  validateScopeField(envelope.audience);
  validateScopeField(envelope.role);
  validateDigest(envelope.manifest_digest);
  validateDigest(envelope.body_digest);
  validateScopeField(envelope.nonce);

  const expiresAtMs = parseRFC3339(envelope.expires_at);
  if (expiresAtMs <= now || expiresAtMs - now > MAX_EXECUTOR_ENVELOPE_TTL_MS) {
    throw new ExecutorEnvelopeInvalidError();
  }

  const body = decodeStandardBase64(envelope.body);
  if (body.byteLength === 0) throw new ExecutorEnvelopeInvalidError();
  const signature = decodeStandardBase64(envelope.signature);
  if (signature.byteLength !== 64) throw new ExecutorEnvelopeInvalidError();

  let bodyDigest: string;
  try {
    bodyDigest = `sha256:${await sha256Hex(body)}`;
  } catch {
    throw new ExecutorEnvelopeInvalidError();
  }
  if (bodyDigest !== envelope.body_digest) throw new ExecutorEnvelopeInvalidError();

  return {
    envelope,
    body,
    signature,
    expiresAtMs,
    canonicalBytes: canonicalSigningBytes(envelope),
  };
}

function hasExactEnvelopeFields(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value);
  if (keys.length !== CANONICAL_FIELD_NAMES.length) return false;
  return CANONICAL_FIELD_NAMES.every((field) => Object.prototype.hasOwnProperty.call(value, field));
}

function validateScopeField(value: unknown): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_SCOPE_FIELD_LENGTH ||
    value.trim() !== value ||
    CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    throw new ExecutorEnvelopeInvalidError();
  }
}

function validateDigest(value: unknown): asserts value is string {
  if (typeof value !== "string" || !SHA256_DIGEST_PATTERN.test(value)) {
    throw new ExecutorEnvelopeInvalidError();
  }
}

function decodeStandardBase64(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length === 0 || !STANDARD_BASE64_PATTERN.test(value)) {
    throw new ExecutorEnvelopeInvalidError();
  }

  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new ExecutorEnvelopeInvalidError();
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeStandardBase64(decoded) !== value) throw new ExecutorEnvelopeInvalidError();
  return decoded;
}

function encodeStandardBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function parseRFC3339(value: unknown): number {
  if (typeof value !== "string") throw new ExecutorEnvelopeInvalidError();
  const match = RFC3339_PATTERN.exec(value);
  if (!match) throw new ExecutorEnvelopeInvalidError();

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fraction = match[7] ?? "";
  const milliseconds = Number((fraction + "000").slice(0, 3));
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, milliseconds);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second ||
    date.getUTCMilliseconds() !== milliseconds
  ) {
    throw new ExecutorEnvelopeInvalidError();
  }

  const offsetSign = match[9] === "-" ? -1 : 1;
  const offsetHours = Number(match[10] ?? "0");
  const offsetMinutes = Number(match[11] ?? "0");
  if (offsetHours > 23 || offsetMinutes > 59) throw new ExecutorEnvelopeInvalidError();
  const timestamp = date.getTime() - offsetSign * (offsetHours * 60 + offsetMinutes) * 60_000;
  if (!Number.isFinite(timestamp)) throw new ExecutorEnvelopeInvalidError();
  return timestamp;
}

function canonicalSigningBytes(envelope: ExecutorEnvelope): Uint8Array {
  const document = {
    version: envelope.version,
    audience: envelope.audience,
    role: envelope.role,
    manifest_digest: envelope.manifest_digest,
    body_digest: envelope.body_digest,
    nonce: envelope.nonce,
    expires_at: envelope.expires_at,
    body: envelope.body,
  };
  const encoded = JSON.stringify(document).replace(/[<>&\u2028\u2029]/gu, (character) => CANONICAL_HTML_ESCAPES[character]);
  return new TextEncoder().encode(encoded);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
