const ED25519_ALGORITHM = "Ed25519";
const SHA256_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]+$/u;
const SAFE_TEXT_PATTERN = /^[\u0021-\u007e]{1,1024}$/u;
const HEAD_KEY = "host-authorization:head";
const GENERATION_KEY_PREFIX = "host-authorization:generation:";

const GENERATION_FIELDS = [
  "version",
  "generation",
  "previous_head_hash",
  "issuer",
  "issued_at",
  "expires_at",
  "mappings",
] as const;
const SIGNED_GENERATION_FIELDS = [...GENERATION_FIELDS, "signature"] as const;
const MAPPING_FIELDS = [
  "verified_jwt_hash",
  "mapped_instance",
  "role",
  "executor_audience",
  "launch_namespace",
  "ssm_allowlist",
  "git_allowlist",
  "ghcr_allowlist",
] as const;

export const HOST_AUTHORIZATION_HEAD_KEY = HEAD_KEY;

export interface HostAuthorizationMapping {
  readonly verified_jwt_hash: string;
  readonly mapped_instance: string;
  readonly role: string;
  readonly executor_audience: string;
  readonly launch_namespace: string;
  readonly ssm_allowlist: readonly string[];
  readonly git_allowlist: readonly string[];
  readonly ghcr_allowlist: readonly string[];
}

export interface HostAuthorizationGenerationInput {
  readonly version: 1;
  readonly generation: number;
  readonly previous_head_hash: string | null;
  readonly issuer: string;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly mappings: readonly HostAuthorizationMapping[];
}

export interface HostAuthorizationGeneration extends HostAuthorizationGenerationInput {
  readonly signature: string;
}

export interface HostAuthorizationHead {
  readonly generation: number;
  readonly head_hash: string;
}

export interface HostAuthorizationStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(closure: (transaction: HostAuthorizationStorage) => Promise<T>): Promise<T>;
}

export type HostAuthorizationPublicKey = CryptoKey | Uint8Array | string;

export interface HostAuthorizationLookupRequest {
  readonly verified_jwt_hash: string;
  readonly mapped_instance: string;
  readonly caller_role?: string;
}

export interface HostAuthorizationHeadOptions {
  readonly expectedHeadHash?: string | null;
  readonly now?: number;
}

export type HostAuthorizationActivationResult =
  | { readonly status: "activated"; readonly generation: number; readonly head_hash: string }
  | { readonly status: "replay"; readonly generation: number; readonly head_hash: string }
  | { readonly status: "head_mismatch" }
  | { readonly status: "stale" }
  | { readonly status: "conflict" }
  | { readonly status: "expired" }
  | { readonly status: "not_yet_valid" }
  | { readonly status: "signature_invalid" }
  | { readonly status: "noncanonical" }
  | { readonly status: "duplicate_key" }
  | { readonly status: "invalid" }
  | { readonly status: "invalid_state" };

export type HostAuthorizationLookupResult =
  | {
      readonly status: "authorized";
      readonly generation: number;
      readonly head_hash: string;
      readonly mapping: HostAuthorizationMapping;
    }
  | { readonly status: "caller_role_denied" }
  | { readonly status: "cross_instance" }
  | { readonly status: "not_found" }
  | { readonly status: "head_mismatch" }
  | { readonly status: "expired" }
  | { readonly status: "not_yet_valid" }
  | { readonly status: "invalid_request" }
  | { readonly status: "invalid_state" };
export type HostAuthorizationHeadResult =
  | { readonly status: "head"; readonly head: HostAuthorizationHead }
  | { readonly status: "not_found" }
  | { readonly status: "invalid_state" };


export class HostAuthorizationInputError extends Error {
  readonly code: "invalid" | "noncanonical" | "duplicate_key";

  constructor(code: "invalid" | "noncanonical" | "duplicate_key") {
    super(`invalid host authorization generation: ${code}`);
    this.name = "HostAuthorizationInputError";
    this.code = code;
  }
}

interface StoredGeneration {
  readonly generation: number;
  readonly head_hash: string;
  readonly signed_generation: string;
}

type ParsedGeneration =
  | { readonly ok: true; readonly document: HostAuthorizationGeneration; readonly payload: Uint8Array }
  | { readonly ok: false; readonly status: "invalid" | "noncanonical" | "duplicate_key" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length && keys.every((key, index) => key === fields[index]);
}
function hasOnlyFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length && keys.every((key) => fields.includes(key));
}


function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareMappingKeys(left: HostAuthorizationMapping, right: HostAuthorizationMapping): number {
  const hashComparison = compareStrings(left.verified_jwt_hash, right.verified_jwt_hash);
  return hashComparison !== 0 ? hashComparison : compareStrings(left.mapped_instance, right.mapped_instance);
}

function validateSafeText(value: unknown): asserts value is string {
  if (typeof value !== "string" || !SAFE_TEXT_PATTERN.test(value)) throw new HostAuthorizationInputError("invalid");
}

function validateDigest(value: unknown): asserts value is string {
  if (typeof value !== "string" || !SHA256_DIGEST_PATTERN.test(value)) throw new HostAuthorizationInputError("invalid");
}

function validateTime(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new HostAuthorizationInputError("invalid");
}

function validateSortedList(value: unknown): asserts value is readonly string[] {
  if (!Array.isArray(value)) throw new HostAuthorizationInputError("invalid");
  let previous: string | undefined;
  for (const item of value) {
    validateSafeText(item);
    if (previous !== undefined) {
      const comparison = compareStrings(previous, item);
      if (comparison === 0) throw new HostAuthorizationInputError("duplicate_key");
      if (comparison > 0) throw new HostAuthorizationInputError("noncanonical");
    }
    previous = item;
  }
}

function validateMapping(value: unknown): asserts value is HostAuthorizationMapping {
  if (!isRecord(value) || !exactFields(value, MAPPING_FIELDS)) throw new HostAuthorizationInputError("noncanonical");
  validateDigest(value.verified_jwt_hash);
  validateSafeText(value.mapped_instance);
  validateSafeText(value.role);
  validateSafeText(value.executor_audience);
  validateSafeText(value.launch_namespace);
  validateSortedList(value.ssm_allowlist);
  validateSortedList(value.git_allowlist);
  validateSortedList(value.ghcr_allowlist);
}

function validateGenerationInput(value: unknown): asserts value is HostAuthorizationGenerationInput {
  if (!isRecord(value) || !exactFields(value, GENERATION_FIELDS)) throw new HostAuthorizationInputError("noncanonical");
  if (value.version !== 1 || !Number.isSafeInteger(value.generation) || (value.generation as number) < 1) {
    throw new HostAuthorizationInputError("invalid");
  }
  if (value.previous_head_hash !== null) validateDigest(value.previous_head_hash);
  validateSafeText(value.issuer);
  validateTime(value.issued_at);
  validateTime(value.expires_at);
  if ((value.expires_at as number) <= (value.issued_at as number)) throw new HostAuthorizationInputError("invalid");
  if ((value.generation as number) === 1 && value.previous_head_hash !== null) {
    throw new HostAuthorizationInputError("invalid");
  }
  if ((value.generation as number) > 1 && value.previous_head_hash === null) {
    throw new HostAuthorizationInputError("invalid");
  }
  if (!Array.isArray(value.mappings)) throw new HostAuthorizationInputError("invalid");
  let previousMapping: HostAuthorizationMapping | undefined;
  const seen = new Set<string>();
  for (const candidate of value.mappings) {
    validateMapping(candidate);
    const key = `${candidate.verified_jwt_hash}\u0000${candidate.mapped_instance}`;
    if (seen.has(key)) throw new HostAuthorizationInputError("duplicate_key");
    seen.add(key);
    if (previousMapping !== undefined) {
      const comparison = compareMappingKeys(previousMapping, candidate);
      if (comparison > 0) throw new HostAuthorizationInputError("noncanonical");
    }
    previousMapping = candidate;
  }
}

function unsignedGenerationDocument(input: HostAuthorizationGenerationInput): HostAuthorizationGenerationInput {
  return {
    version: 1,
    generation: input.generation,
    previous_head_hash: input.previous_head_hash,
    issuer: input.issuer,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    mappings: input.mappings.map((mapping) => ({
      verified_jwt_hash: mapping.verified_jwt_hash,
      mapped_instance: mapping.mapped_instance,
      role: mapping.role,
      executor_audience: mapping.executor_audience,
      launch_namespace: mapping.launch_namespace,
      ssm_allowlist: [...mapping.ssm_allowlist],
      git_allowlist: [...mapping.git_allowlist],
      ghcr_allowlist: [...mapping.ghcr_allowlist],
    })),
  };
}

export function canonicalHostAuthorizationGenerationPayload(input: HostAuthorizationGenerationInput): string {
  validateGenerationInput(input);
  return JSON.stringify(unsignedGenerationDocument(input));
}

function signedGenerationDocument(
  input: HostAuthorizationGenerationInput,
  signature: string,
): HostAuthorizationGeneration {
  return {
    ...unsignedGenerationDocument(input),
    signature,
  };
}

export async function createSignedHostAuthorizationGeneration(
  input: HostAuthorizationGenerationInput,
  signingKey: CryptoKey,
): Promise<string> {
  const payload = canonicalHostAuthorizationGenerationPayload(input);
  let signature: Uint8Array;
  try {
    signature = new Uint8Array(
      await crypto.subtle.sign(ED25519_ALGORITHM, signingKey, new TextEncoder().encode(payload)),
    );
  } catch {
    throw new HostAuthorizationInputError("invalid");
  }
  return JSON.stringify(signedGenerationDocument(input, toBase64Url(signature)));
}

function parseSignedGeneration(serialized: string): ParsedGeneration {
  if (typeof serialized !== "string" || serialized.length === 0) return { ok: false, status: "invalid" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    return { ok: false, status: "invalid" };
  }
  if (!isRecord(parsed) || !exactFields(parsed, SIGNED_GENERATION_FIELDS)) {
    return { ok: false, status: "noncanonical" };
  }
  if (JSON.stringify(parsed) !== serialized) return { ok: false, status: "noncanonical" };
  const signature = parsed.signature;
  if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature)) return { ok: false, status: "invalid" };
  let input: HostAuthorizationGenerationInput;
  try {
    const { signature: _signature, ...unsigned } = parsed;
    validateGenerationInput(unsigned);
    input = unsigned;
  } catch (error) {
    if (error instanceof HostAuthorizationInputError) return { ok: false, status: error.code };
    return { ok: false, status: "invalid" };
  }
  const canonical = JSON.stringify(signedGenerationDocument(input, signature));
  if (canonical !== serialized) return { ok: false, status: "noncanonical" };
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64Url(signature);
  } catch {
    return { ok: false, status: "invalid" };
  }
  if (toBase64Url(signatureBytes) !== signature || signatureBytes.byteLength !== 64) {
    return { ok: false, status: "invalid" };
  }
  return {
    ok: true,
    document: signedGenerationDocument(input, signature),
    payload: new TextEncoder().encode(canonicalHostAuthorizationGenerationPayload(input)),
  };
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function fromBase64Url(value: string): Uint8Array {
  if (!SIGNATURE_PATTERN.test(value)) throw new Error("invalid base64url");
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function digestBytes(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return `sha256:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export async function hostAuthorizationHeadHash(signedGeneration: string): Promise<string> {
  return digestBytes(new TextEncoder().encode(signedGeneration));
}

async function importTrustedPublicKey(value: HostAuthorizationPublicKey): Promise<CryptoKey | null> {
  if (typeof CryptoKey !== "undefined" && value instanceof CryptoKey) return value;
  let bytes: Uint8Array;
  if (value instanceof Uint8Array) {
    bytes = new Uint8Array(value);
  } else if (typeof value === "string") {
    try {
      bytes = fromBase64Url(value);
    } catch {
      return null;
    }
  } else {
    return null;
  }
  if (bytes.byteLength !== 32) return null;
  try {
    return await crypto.subtle.importKey("raw", bytes, ED25519_ALGORITHM, false, ["verify"]);
  } catch {
    return null;
  }
}

async function verifyGeneration(
  parsed: Extract<ParsedGeneration, { readonly ok: true }>,
  trustedPublicKey: HostAuthorizationPublicKey,
): Promise<boolean> {
  const key = await importTrustedPublicKey(trustedPublicKey);
  if (key === null) return false;
  try {
    return await crypto.subtle.verify(
      ED25519_ALGORITHM,
      key,
      fromBase64Url(parsed.document.signature),
      parsed.payload,
    );
  } catch {
    return false;
  }
}

function generationKey(generation: number): string {
  return `${GENERATION_KEY_PREFIX}${generation}`;
}

function validHead(value: unknown): value is HostAuthorizationHead {
  return (
    isRecord(value) &&
    exactFields(value, ["generation", "head_hash"]) &&
    Number.isSafeInteger(value.generation) &&
    (value.generation as number) >= 1 &&
    typeof value.head_hash === "string" &&
    SHA256_DIGEST_PATTERN.test(value.head_hash)
  );
}

function validStoredGeneration(value: unknown): value is StoredGeneration {
  return (
    isRecord(value) &&
    exactFields(value, ["generation", "head_hash", "signed_generation"]) &&
    Number.isSafeInteger(value.generation) &&
    (value.generation as number) >= 1 &&
    typeof value.head_hash === "string" &&
    SHA256_DIGEST_PATTERN.test(value.head_hash) &&
    typeof value.signed_generation === "string" &&
    value.signed_generation.length > 0
  );
}

function validNow(value: number | undefined): number {
  const now = value ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("invalid time");
  return now;
}

export class HostAuthorizationStore {
  private readonly trustedPublicKey: HostAuthorizationPublicKey;

  constructor(storage: HostAuthorizationStorage, trustedPublicKey: HostAuthorizationPublicKey) {
    this.storage = storage;
    this.trustedPublicKey = trustedPublicKey instanceof Uint8Array ? new Uint8Array(trustedPublicKey) : trustedPublicKey;
  }

  private readonly storage: HostAuthorizationStorage;

  async activate(
    serializedGeneration: string,
    options: HostAuthorizationHeadOptions = {},
  ): Promise<HostAuthorizationActivationResult> {
    const parsed = parseSignedGeneration(serializedGeneration);
    if (!parsed.ok) return { status: parsed.status };
    let now: number;
    try {
      now = validNow(options.now);
    } catch {
      return { status: "invalid" };
    }
    if (now < parsed.document.issued_at) return { status: "not_yet_valid" };
    if (now >= parsed.document.expires_at) return { status: "expired" };
    if (!(await verifyGeneration(parsed, this.trustedPublicKey))) return { status: "signature_invalid" };
    let headHash: string;
    try {
      headHash = await hostAuthorizationHeadHash(serializedGeneration);
    } catch {
      return { status: "invalid" };
    }

    try {
      return await this.storage.transaction(async (transaction) => {
        const rawHead = await transaction.get<unknown>(HEAD_KEY);
        if (rawHead !== undefined && !validHead(rawHead)) return { status: "invalid_state" } as const;
        const currentHead = rawHead as HostAuthorizationHead | undefined;
        const currentHash = currentHead?.head_hash ?? null;
        if (options.expectedHeadHash !== undefined && options.expectedHeadHash !== currentHash) {
          return { status: "head_mismatch" } as const;
        }
        const existing = await transaction.get<unknown>(generationKey(parsed.document.generation));
        if (existing !== undefined && !validStoredGeneration(existing)) return { status: "invalid_state" } as const;
        if (currentHead !== undefined && parsed.document.generation <= currentHead.generation) {
          if (currentHead.generation === parsed.document.generation && currentHead.head_hash === headHash) {
            return { status: "replay", generation: parsed.document.generation, head_hash: headHash } as const;
          }
          return { status: "stale" } as const;
        }
        if (existing !== undefined) {
          if (existing.head_hash === headHash && existing.signed_generation === serializedGeneration) {
            return { status: "replay", generation: parsed.document.generation, head_hash: headHash } as const;
          }
          return { status: "conflict" } as const;
        }
        if (currentHead === undefined) {
          if (parsed.document.generation !== 1 || parsed.document.previous_head_hash !== null) return { status: "stale" } as const;
        } else if (parsed.document.previous_head_hash !== currentHead.head_hash) {
          return { status: "stale" } as const;
        }
        await transaction.put(generationKey(parsed.document.generation), {
          generation: parsed.document.generation,
          head_hash: headHash,
          signed_generation: serializedGeneration,
        } satisfies StoredGeneration);
        await transaction.put(HEAD_KEY, { generation: parsed.document.generation, head_hash: headHash } satisfies HostAuthorizationHead);
        return { status: "activated", generation: parsed.document.generation, head_hash: headHash } as const;
      });
    } catch {
      return { status: "invalid_state" };
    }
  }

  async lookup(
    request: HostAuthorizationLookupRequest,
    options: HostAuthorizationHeadOptions = {},
  ): Promise<HostAuthorizationLookupResult> {
    if (!isRecord(request)) return { status: "invalid_request" };
    if (Object.prototype.hasOwnProperty.call(request, "caller_role")) {
      return hasOnlyFields(request, ["verified_jwt_hash", "mapped_instance", "caller_role"])
        ? { status: "caller_role_denied" }
        : { status: "invalid_request" };
    }
    if (
      !hasOnlyFields(request, ["verified_jwt_hash", "mapped_instance"]) ||
      typeof request.verified_jwt_hash !== "string" ||
      !SHA256_DIGEST_PATTERN.test(request.verified_jwt_hash) ||
      typeof request.mapped_instance !== "string" ||
      !SAFE_TEXT_PATTERN.test(request.mapped_instance)
    ) {
      return { status: "invalid_request" };
    }
    let now: number;
    try {
      now = validNow(options.now);
    } catch {
      return { status: "invalid_request" };
    }
    try {
      return await this.storage.transaction(async (transaction) => {
        const rawHead = await transaction.get<unknown>(HEAD_KEY);
        if (rawHead === undefined) return { status: "not_found" } as const;
        if (!validHead(rawHead)) return { status: "invalid_state" } as const;
        if (options.expectedHeadHash !== undefined && options.expectedHeadHash !== rawHead.head_hash) {
          return { status: "head_mismatch" } as const;
        }
        const stored = await transaction.get<unknown>(generationKey(rawHead.generation));
        if (!validStoredGeneration(stored) || stored.generation !== rawHead.generation || stored.head_hash !== rawHead.head_hash) {
          return { status: "invalid_state" } as const;
        }
        const parsed = parseSignedGeneration(stored.signed_generation);
        if (!parsed.ok) return { status: "invalid_state" } as const;
        const actualHash = await hostAuthorizationHeadHash(stored.signed_generation);
        if (actualHash !== rawHead.head_hash || !(await verifyGeneration(parsed, this.trustedPublicKey))) {
          return { status: "invalid_state" } as const;
        }
        if (now < parsed.document.issued_at) return { status: "not_yet_valid" } as const;
        if (now >= parsed.document.expires_at) return { status: "expired" } as const;
        const mapping = parsed.document.mappings.find(
          (candidate) =>
            candidate.verified_jwt_hash === request.verified_jwt_hash &&
            candidate.mapped_instance === request.mapped_instance,
        );
        if (mapping === undefined) {
          const sameHash = parsed.document.mappings.some(
            (candidate) => candidate.verified_jwt_hash === request.verified_jwt_hash,
          );
          return sameHash ? { status: "cross_instance" } as const : { status: "not_found" } as const;
        }
        return {
          status: "authorized",
          generation: parsed.document.generation,
          head_hash: rawHead.head_hash,
          mapping: {
            ...mapping,
            ssm_allowlist: [...mapping.ssm_allowlist],
            git_allowlist: [...mapping.git_allowlist],
            ghcr_allowlist: [...mapping.ghcr_allowlist],
          },
        } as const;
      });
    } catch {
      return { status: "invalid_state" };
    }
  }

  async readHead(): Promise<HostAuthorizationHeadResult> {
    try {
      return await this.storage.transaction(async (transaction) => {
        const value = await transaction.get<unknown>(HEAD_KEY);
        if (value === undefined) return { status: "not_found" } as const;
        if (!validHead(value)) return { status: "invalid_state" } as const;
        return {
          status: "head",
          head: { generation: value.generation, head_hash: value.head_hash },
        } as const;
      });
    } catch {
      return { status: "invalid_state" };
    }
  }
}
