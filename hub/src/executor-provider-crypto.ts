const textEncoder = new TextEncoder();

export const PROVIDER_ENVELOPE_SCHEMA = "skret/executor/provider-envelope/v1" as const;
export const MAX_AWS_PARAMETER_VERSIONS = 100;
export const MAX_AWS_PARAMETER_LABELS = 10;
export const AES_GCM_IV_BYTES = 12;
export const AES_GCM_TAG_BYTES = 16;
export const DATA_KEY_BYTES = 32;

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const SAFE_LABEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/u;
const SAFE_REFERENCE = /^[\u0021-\u007e]{1,1024}$/u;
const MAX_ENVELOPE_COMPONENT_BYTES = 16 * 1024 * 1024;

export type ProviderEnvelopeErrorMessage =
  | "invalid provider envelope"
  | "provider source boundary"
  | "provider source missing"
  | "provider source unavailable"
  | "provider label boundary"
  | "provider label drift"
  | "provider label readback mismatch"
  | "provider label cleanup mismatch"
  | "KMS operation failed";

export class ProviderEnvelopeError extends Error {
  constructor(message: ProviderEnvelopeErrorMessage) {
    super(message);
    this.name = "ProviderEnvelopeError";
  }
}

export class InvalidProviderEnvelopeError extends ProviderEnvelopeError {
  constructor() {
    super("invalid provider envelope");
    this.name = "InvalidProviderEnvelopeError";
  }
}

export class ProviderSourceBoundaryError extends ProviderEnvelopeError {
  constructor() {
    super("provider source boundary");
    this.name = "ProviderSourceBoundaryError";
  }
}

export class SourceMissingError extends ProviderEnvelopeError {
  constructor() {
    super("provider source missing");
    this.name = "SourceMissingError";
  }
}
export class SourceUnavailableError extends ProviderEnvelopeError {
  constructor() {
    super("provider source unavailable");
    this.name = "SourceUnavailableError";
  }
}


export class ProviderLabelBoundaryError extends ProviderEnvelopeError {
  constructor() {
    super("provider label boundary");
    this.name = "ProviderLabelBoundaryError";
  }
}

export class ProviderLabelDriftError extends ProviderEnvelopeError {
  constructor() {
    super("provider label drift");
    this.name = "ProviderLabelDriftError";
  }
}

export class ProviderLabelReadbackError extends ProviderEnvelopeError {
  constructor() {
    super("provider label readback mismatch");
    this.name = "ProviderLabelReadbackError";
  }
}

export class ProviderLabelCleanupError extends ProviderEnvelopeError {
  constructor() {
    super("provider label cleanup mismatch");
    this.name = "ProviderLabelCleanupError";
  }
}

export class KmsOperationError extends ProviderEnvelopeError {
  constructor() {
    super("KMS operation failed");
    this.name = "KmsOperationError";
  }
}

export interface SourceIdentity {
  readonly partition: string;
  readonly account: string;
  readonly region: string;
  readonly fullParameterName: string;
  readonly version: number;
  readonly lifecycleLabel: string;
}

export interface EnvelopeContextInput {
  readonly schema?: typeof PROVIDER_ENVELOPE_SCHEMA;
  readonly operationId: string;
  readonly generation: string;
  readonly sourceIdentity: SourceIdentity;
  readonly targetSetDigest: string;
}

export interface ProviderEnvelopeContext {
  readonly schema: typeof PROVIDER_ENVELOPE_SCHEMA;
  readonly operationId: string;
  readonly generation: string;
  readonly sourceIdentity: SourceIdentity;
  readonly lifecycleLabel: string;
  readonly version: number;
  readonly targetSetDigest: string;
}

export function canonicalSourceIdentity(input: SourceIdentity): SourceIdentity {
  if (!isRecord(input)) throw new ProviderSourceBoundaryError();
  const partition = readCanonicalText(input.partition, 64);
  const account = readCanonicalText(input.account, 128);
  const region = readCanonicalText(input.region, 128);
  const fullParameterName = readCanonicalText(input.fullParameterName, 2_048);
  const lifecycleLabel = readCanonicalText(input.lifecycleLabel, 100);
  if (!SAFE_ID.test(partition) || !SAFE_ID.test(account) || !SAFE_ID.test(region) || !SAFE_LABEL.test(lifecycleLabel)) {
    throw new ProviderSourceBoundaryError();
  }
  if (!fullParameterName.startsWith("/") || fullParameterName.endsWith("/") || fullParameterName.includes("//") || /[\u0000-\u001f\u007f]/u.test(fullParameterName)) {
    throw new ProviderSourceBoundaryError();
  }
  if (!Number.isSafeInteger(input.version) || input.version < 1) {
    throw new ProviderSourceBoundaryError();
  }
  return Object.freeze({ partition, account, region, fullParameterName, version: input.version, lifecycleLabel });
}

export function createEnvelopeContext(input: EnvelopeContextInput): ProviderEnvelopeContext {
  if (!isRecord(input) || (input.schema !== undefined && input.schema !== PROVIDER_ENVELOPE_SCHEMA)) {
    throw new InvalidProviderEnvelopeError();
  }
  const operationId = readCanonicalText(input.operationId, 256);
  const generation = readCanonicalText(input.generation, 256);
  if (!SAFE_ID.test(operationId) || !SAFE_ID.test(generation)) throw new InvalidProviderEnvelopeError();
  const sourceIdentity = canonicalSourceIdentity(input.sourceIdentity);
  if (!SHA256_DIGEST.test(input.targetSetDigest)) throw new InvalidProviderEnvelopeError();
  return Object.freeze({
    schema: PROVIDER_ENVELOPE_SCHEMA,
    operationId,
    generation,
    sourceIdentity,
    lifecycleLabel: sourceIdentity.lifecycleLabel,
    version: sourceIdentity.version,
    targetSetDigest: input.targetSetDigest,
  });
}

function sourceIdentityBytes(source: SourceIdentity): Uint8Array {
  const identity = canonicalSourceIdentity(source);
  return encodeLengthPrefixed([
    textEncoder.encode(identity.partition),
    textEncoder.encode(identity.account),
    textEncoder.encode(identity.region),
    textEncoder.encode(identity.fullParameterName),
    textEncoder.encode(String(identity.version)),
    textEncoder.encode(identity.lifecycleLabel),
  ]);
}

export function encodeLengthPrefixed(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    if (!(part instanceof Uint8Array) || part.byteLength > 0xffff_ffff) throw new InvalidProviderEnvelopeError();
    total += 4 + part.byteLength;
    if (total > 0xffff_ffff || total > MAX_ENVELOPE_COMPONENT_BYTES) throw new InvalidProviderEnvelopeError();
  }
  const output = new Uint8Array(total);
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.byteLength, false);
    offset += 4;
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

export function canonicalProviderContextBytes(context: ProviderEnvelopeContext): Uint8Array {
  const canonical = createEnvelopeContext(context);
  return encodeLengthPrefixed([
    textEncoder.encode(canonical.schema),
    textEncoder.encode(canonical.operationId),
    textEncoder.encode(canonical.generation),
    sourceIdentityBytes(canonical.sourceIdentity),
    textEncoder.encode(canonical.lifecycleLabel),
    textEncoder.encode(String(canonical.version)),
    textEncoder.encode(canonical.targetSetDigest),
  ]);
}

export function canonicalKmsEncryptionContext(context: ProviderEnvelopeContext): Readonly<Record<string, string>> {
  const canonical = createEnvelopeContext(context);
  return Object.freeze({
    schema: canonical.schema,
    operation_id: canonical.operationId,
    generation: canonical.generation,
    source_identity: toBase64Url(sourceIdentityBytes(canonical.sourceIdentity)),
    lifecycle_label: canonical.lifecycleLabel,
    version: String(canonical.version),
    target_set_digest: canonical.targetSetDigest,
  });
}

export async function providerContextDigest(context: ProviderEnvelopeContext): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", canonicalProviderContextBytes(context)));
  return `sha256:${toHex(digest)}`;
}

export interface KmsGenerateDataKeyRequest {
  readonly keyReference: string;
  readonly keySpec: "AES_256";
  readonly encryptionContext: Readonly<Record<string, string>>;
}

export interface KmsDecryptRequest {
  readonly keyReference: string;
  readonly encryptedDataKey: Uint8Array;
  readonly encryptionContext: Readonly<Record<string, string>>;
}

export interface KmsGeneratedDataKey {
  readonly plaintextDataKey: Uint8Array;
  readonly encryptedDataKey: Uint8Array;
}

export interface KmsDecryptedDataKey {
  readonly plaintextDataKey: Uint8Array;
}

export interface KmsTransport {
  generateDataKey(request: KmsGenerateDataKeyRequest): Promise<KmsGeneratedDataKey>;
  decrypt(request: KmsDecryptRequest): Promise<KmsDecryptedDataKey>;
}

export class KmsClient {
  readonly #transport: KmsTransport;

  constructor(transport: KmsTransport) {
    this.#transport = transport;
  }

  async generateDataKey(keyReference: string, context: ProviderEnvelopeContext): Promise<KmsGeneratedDataKey> {
    validateReference(keyReference);
    let result: KmsGeneratedDataKey | undefined;
    try {
      result = await this.#transport.generateDataKey({
        keyReference,
        keySpec: "AES_256",
        encryptionContext: canonicalKmsEncryptionContext(context),
      });
      if (!(result.plaintextDataKey instanceof Uint8Array) || result.plaintextDataKey.byteLength !== DATA_KEY_BYTES || !(result.encryptedDataKey instanceof Uint8Array) || result.encryptedDataKey.byteLength === 0) {
        throw new KmsOperationError();
      }
      return { plaintextDataKey: result.plaintextDataKey.slice(), encryptedDataKey: result.encryptedDataKey.slice() };
    } catch (error) {
      if (error instanceof KmsOperationError) throw error;
      throw new KmsOperationError();
    } finally {
      zeroize(result?.plaintextDataKey);
      zeroize(result?.encryptedDataKey);
    }
  }


  async decryptDataKey(
    keyReference: string,
    encryptedDataKey: Uint8Array,
    context: ProviderEnvelopeContext,
  ): Promise<KmsDecryptedDataKey> {
    validateReference(keyReference);
    if (!(encryptedDataKey instanceof Uint8Array) || encryptedDataKey.byteLength === 0) throw new KmsOperationError();
    let result: KmsDecryptedDataKey | undefined;
    try {
      result = await this.#transport.decrypt({
        keyReference,
        encryptedDataKey: encryptedDataKey.slice(),
        encryptionContext: canonicalKmsEncryptionContext(context),
      });
      if (!(result.plaintextDataKey instanceof Uint8Array) || result.plaintextDataKey.byteLength !== DATA_KEY_BYTES) {
        throw new KmsOperationError();
      }
      return { plaintextDataKey: result.plaintextDataKey.slice() };
    } catch (error) {
      if (error instanceof KmsOperationError) throw error;
      throw new KmsOperationError();
    } finally {
      zeroize(result?.plaintextDataKey);
    }
  }
}

export interface AwsLabelBinding {
  readonly label: string;
  readonly version: number;
}

export interface AwsParameterMetadata {
  readonly exists: boolean;
  readonly parameterName: string;
  readonly version: number;
  readonly versionCount: number;
  readonly labels: readonly AwsLabelBinding[];
}

export interface AwsParameterRead {
  readonly metadata: AwsParameterMetadata;
  readonly value: Uint8Array;
}

export interface AwsDescribeParameterVersionRequest {
  readonly parameterName: string;
  readonly version: number;
}

export interface AwsReadParameterVersionRequest {
  readonly parameterName: string;
  readonly version: number;
}

export interface AwsLabelParameterVersionRequest {
  readonly parameterName: string;
  readonly version: number;
  readonly label: string;
}

export interface AwsReadParameterLabelRequest {
  readonly parameterName: string;
  readonly label: string;
}

export interface AwsUnlabelParameterVersionRequest {
  readonly parameterName: string;
  readonly version: number;
  readonly label: string;
}

export interface AwsSourceTransport {
  describeParameterVersion(request: AwsDescribeParameterVersionRequest): Promise<AwsParameterMetadata | null>;
  readParameterVersion(request: AwsReadParameterVersionRequest): Promise<Uint8Array | null>;
  labelParameterVersion(request: AwsLabelParameterVersionRequest): Promise<void>;
  readParameterLabel(request: AwsReadParameterLabelRequest): Promise<number | null>;
  unlabelParameterVersion(request: AwsUnlabelParameterVersionRequest): Promise<void>;
}

export class AwsSourceClient {
  readonly #transport: AwsSourceTransport;

  constructor(transport: AwsSourceTransport) {
    this.#transport = transport;
  }

  async readExact(sourceIdentity: SourceIdentity): Promise<AwsParameterRead> {
    const identity = canonicalSourceIdentity(sourceIdentity);
    let metadata: AwsParameterMetadata | null;
    try {
      metadata = await this.#transport.describeParameterVersion({
        parameterName: identity.fullParameterName,
        version: identity.version,
      });
    } catch {
      throw new SourceUnavailableError();
    }
    if (metadata === null || metadata.exists === false) throw new SourceMissingError();
    validateMetadata(identity, metadata);
    let value: Uint8Array | null;
    try {
      value = await this.#transport.readParameterVersion({
        parameterName: identity.fullParameterName,
        version: identity.version,
      });
    } catch {
      throw new SourceUnavailableError();
    }
    if (value === null) throw new SourceMissingError();
    if (!(value instanceof Uint8Array)) throw new SourceUnavailableError();
    return { metadata, value: value.slice() };
  }

  async preflight(sourceIdentity: SourceIdentity): Promise<AwsParameterMetadata> {
    const identity = canonicalSourceIdentity(sourceIdentity);
    let metadata: AwsParameterMetadata | null;
    try {
      metadata = await this.#transport.describeParameterVersion({
        parameterName: identity.fullParameterName,
        version: identity.version,
      });
    } catch {
      throw new SourceUnavailableError();
    }
    if (metadata === null || metadata.exists === false) throw new SourceMissingError();
    this.preflightMetadata(identity, metadata);
    return metadata;
  }

  preflightMetadata(sourceIdentity: SourceIdentity, metadata: AwsParameterMetadata): void {
    const identity = canonicalSourceIdentity(sourceIdentity);
    validateMetadata(identity, metadata);
    if (metadata.labels.length >= MAX_AWS_PARAMETER_LABELS) throw new ProviderLabelBoundaryError();
    const existing = metadata.labels.find((binding) => binding.label === identity.lifecycleLabel);
    if (existing !== undefined && existing.version !== identity.version) throw new ProviderLabelDriftError();
  }

  async labelExact(sourceIdentity: SourceIdentity): Promise<void> {
    const identity = canonicalSourceIdentity(sourceIdentity);
    try {
      await this.#transport.labelParameterVersion({
        parameterName: identity.fullParameterName,
        version: identity.version,
        label: identity.lifecycleLabel,
      });
    } catch {
      // The provider may have committed before the response was lost. Never
      // replay the write here; the exact readback below resolves or blocks it.
    }
    let readback: number | null;
    try {
      readback = await this.#transport.readParameterLabel({
        parameterName: identity.fullParameterName,
        label: identity.lifecycleLabel,
      });
    } catch {
      throw new ProviderLabelReadbackError();
    }
    if (readback !== identity.version) throw new ProviderLabelReadbackError();
  }

  async unlabelExact(sourceIdentity: SourceIdentity): Promise<void> {
    const identity = canonicalSourceIdentity(sourceIdentity);
    let before: number | null;
    try {
      before = await this.#transport.readParameterLabel({
        parameterName: identity.fullParameterName,
        label: identity.lifecycleLabel,
      });
    } catch {
      throw new ProviderLabelCleanupError();
    }
    if (before === null) return;
    if (before !== identity.version) throw new ProviderLabelCleanupError();
    try {
      await this.#transport.unlabelParameterVersion({
        parameterName: identity.fullParameterName,
        version: identity.version,
        label: identity.lifecycleLabel,
      });
    } catch {
      // As above, reconcile only by exact readback and never a second write.
    }
    let after: number | null;
    try {
      after = await this.#transport.readParameterLabel({
        parameterName: identity.fullParameterName,
        label: identity.lifecycleLabel,
      });
    } catch {
      throw new ProviderLabelCleanupError();
    }
    if (after !== null) throw new ProviderLabelCleanupError();
  }
}

export interface EnvelopeReference {
  readonly kind: "source" | "kms" | "target";
  readonly id: string;
}

export interface PersistedProviderEnvelope {
  readonly schema: typeof PROVIDER_ENVELOPE_SCHEMA;
  readonly ciphertext: string;
  readonly iv: string;
  readonly mac: string;
  readonly encryptedDataKey: string;
  readonly contextDigest: string;
  readonly references: readonly EnvelopeReference[];
}

export interface CreateProviderEnvelopeInput {
  readonly plaintext: Uint8Array;
  readonly context: ProviderEnvelopeContext;
  readonly keyReference: string;
  readonly references?: readonly EnvelopeReference[];
  readonly iv?: Uint8Array;
  readonly kms: KmsClient;
}

export interface DecryptProviderEnvelopeInput {
  readonly envelope: PersistedProviderEnvelope;
  readonly context: ProviderEnvelopeContext;
  readonly keyReference: string;
  readonly kms: KmsClient;
}

export async function createProviderEnvelope(input: CreateProviderEnvelopeInput): Promise<PersistedProviderEnvelope> {
  const context = createEnvelopeContext(input.context);
  validateReference(input.keyReference);
  if (!(input.plaintext instanceof Uint8Array) || input.plaintext.byteLength > MAX_ENVELOPE_COMPONENT_BYTES) {
    throw new InvalidProviderEnvelopeError();
  }
  const plaintext = input.plaintext;
  const plaintextCopy = plaintext.slice();
  const references = normalizeReferences([
    { kind: "source", id: sourceReference(context.sourceIdentity) },
    { kind: "kms", id: input.keyReference },
    ...(input.references ?? []),
  ]);
  let dataKey: Uint8Array | undefined;
  let macInput: Uint8Array | undefined;
  let contextBytes: Uint8Array | undefined;
  let additionalData: Uint8Array | undefined;
  try {
    const generated = await input.kms.generateDataKey(input.keyReference, context);
    dataKey = generated.plaintextDataKey;
    const iv = input.iv === undefined ? crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES)) : input.iv.slice();
    if (iv.byteLength !== AES_GCM_IV_BYTES) throw new InvalidProviderEnvelopeError();
    contextBytes = canonicalProviderContextBytes(context);
    additionalData = envelopeAdditionalData(context, references);
    const derived = await deriveEnvelopeKeys(dataKey, contextBytes);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData, tagLength: 128 }, derived.aesKey, plaintextCopy),
    );
    macInput = envelopeMacInput(additionalData, plaintextCopy);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", derived.macKey, macInput));
    const contextDigest = await providerContextDigest(context);
    return Object.freeze({
      schema: PROVIDER_ENVELOPE_SCHEMA,
      ciphertext: toBase64Url(ciphertext),
      iv: toBase64Url(iv),
      mac: toBase64Url(mac),
      encryptedDataKey: toBase64Url(generated.encryptedDataKey),
      contextDigest,
      references,
    });
  } catch (error) {
    if (error instanceof ProviderEnvelopeError) throw error;
    throw new InvalidProviderEnvelopeError();
  } finally {
    zeroize(plaintext);
    zeroize(plaintextCopy);
    zeroize(dataKey);
    zeroize(macInput);
    zeroize(contextBytes);
    zeroize(additionalData);
  }
}

export async function decryptProviderEnvelope(input: DecryptProviderEnvelopeInput): Promise<Uint8Array> {
  const context = createEnvelopeContext(input.context);
  validateReference(input.keyReference);
  const encoded = decodePersistedEnvelope(input.envelope);
  const expectedContextDigest = await providerContextDigest(context);
  if (encoded.contextDigest !== expectedContextDigest) throw new InvalidProviderEnvelopeError();
  let dataKey: Uint8Array | undefined;
  let contextBytes: Uint8Array | undefined;
  let additionalData: Uint8Array | undefined;
  let macInput: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  let success = false;
  try {
    const decryptedKey = await input.kms.decryptDataKey(input.keyReference, encoded.encryptedDataKey, context);
    dataKey = decryptedKey.plaintextDataKey;
    contextBytes = canonicalProviderContextBytes(context);
    additionalData = envelopeAdditionalData(context, encoded.references);
    const derived = await deriveEnvelopeKeys(dataKey, contextBytes);
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: encoded.iv, additionalData, tagLength: 128 },
        derived.aesKey,
        encoded.ciphertext,
      ),
    );
    macInput = envelopeMacInput(additionalData, plaintext);
    const validMac = await crypto.subtle.verify("HMAC", derived.macKey, encoded.mac, macInput);
    if (!validMac) throw new InvalidProviderEnvelopeError();
    success = true;
    return plaintext;
  } catch (error) {
    if (error instanceof ProviderEnvelopeError) throw error;
    throw new InvalidProviderEnvelopeError();
  } finally {
    zeroize(dataKey);
    zeroize(contextBytes);
    zeroize(additionalData);
    zeroize(macInput);
    if (!success) zeroize(plaintext);
  }
}

export async function withDecryptedProviderEnvelope<T>(
  input: DecryptProviderEnvelopeInput,
  callback: (plaintext: Uint8Array) => Promise<T> | T,
): Promise<T> {
  const plaintext = await decryptProviderEnvelope(input);
  try {
    return await callback(plaintext);
  } finally {
    zeroize(plaintext);
  }
}

interface DerivedEnvelopeKeys {
  readonly aesKey: CryptoKey;
  readonly macKey: CryptoKey;
}

async function deriveEnvelopeKeys(dataKey: Uint8Array, contextBytes: Uint8Array): Promise<DerivedEnvelopeKeys> {
  let salt: Uint8Array | undefined;
  try {
    salt = new Uint8Array(await crypto.subtle.digest("SHA-256", contextBytes));
    const baseKey = await crypto.subtle.importKey("raw", dataKey, "HKDF", false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: textEncoder.encode(`${PROVIDER_ENVELOPE_SCHEMA}/aes-gcm`) },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const macKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: textEncoder.encode(`${PROVIDER_ENVELOPE_SCHEMA}/hmac-sha256`) },
      baseKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"],
    );
    return { aesKey, macKey };
  } catch {
    throw new InvalidProviderEnvelopeError();
  } finally {
    zeroize(salt);
  }
}

function envelopeAdditionalData(
  context: ProviderEnvelopeContext,
  references: readonly EnvelopeReference[],
): Uint8Array {
  return encodeLengthPrefixed([
    canonicalProviderContextBytes(context),
    ...references.map((reference) =>
      encodeLengthPrefixed([textEncoder.encode(reference.kind), textEncoder.encode(reference.id)]),
    ),
  ]);
}

function envelopeMacInput(additionalData: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return encodeLengthPrefixed([additionalData, plaintext]);
}

function decodePersistedEnvelope(envelope: PersistedProviderEnvelope): {
  readonly ciphertext: Uint8Array;
  readonly iv: Uint8Array;
  readonly mac: Uint8Array;
  readonly encryptedDataKey: Uint8Array;
  readonly contextDigest: string;
  readonly references: readonly EnvelopeReference[];
} {
  if (!isRecord(envelope) || envelope.schema !== PROVIDER_ENVELOPE_SCHEMA || !SHA256_DIGEST.test(envelope.contextDigest)) {
    throw new InvalidProviderEnvelopeError();
  }
  const ciphertext = fromBase64Url(envelope.ciphertext);
  const iv = fromBase64Url(envelope.iv);
  const mac = fromBase64Url(envelope.mac);
  const encryptedDataKey = fromBase64Url(envelope.encryptedDataKey);
  if (ciphertext === null || ciphertext.byteLength < AES_GCM_TAG_BYTES || iv === null || iv.byteLength !== AES_GCM_IV_BYTES || mac === null || mac.byteLength !== 32 || encryptedDataKey === null || encryptedDataKey.byteLength === 0) {
    throw new InvalidProviderEnvelopeError();
  }
  if (!Array.isArray(envelope.references)) throw new InvalidProviderEnvelopeError();
  const references = normalizeReferences(envelope.references as readonly EnvelopeReference[]);
  return { ciphertext, iv, mac, encryptedDataKey, contextDigest: envelope.contextDigest, references };
}

export type LifecycleKillPoint = "after-final-acknowledgement" | "during-canary" | "after-canary" | "during-cleanup";
export type LifecycleEvent = "source-read" | "label-readback" | "kms-generate" | "envelope-created";

export interface PrepareProviderEnvelopeInput {
  readonly operationId: string;
  readonly generation: string;
  readonly sourceIdentity: SourceIdentity;
  readonly targetSetDigest: string;
  readonly keyReference: string;
  readonly targetIdentities: readonly string[];
  readonly references?: readonly EnvelopeReference[];
  readonly iv?: Uint8Array;
  readonly onEvent?: (event: LifecycleEvent) => void;
}

export interface PreparedProviderGeneration {
  readonly operationId: string;
  readonly generation: string;
  readonly sourceIdentity: SourceIdentity;
  readonly context: ProviderEnvelopeContext;
  readonly targetIdentities: readonly string[];
  readonly keyReference: string;
  readonly envelope: PersistedProviderEnvelope;
}

export interface CleanupAcknowledgement {
  readonly targetIdentity: string;
  readonly acknowledged: boolean;
}

export interface CleanupProviderEnvelopeInput {
  readonly operationId: string;
  readonly acknowledgements: readonly CleanupAcknowledgement[];
  readonly canary: "passed" | "pending" | "failed";
  readonly postconditions: "passed" | "pending" | "failed";
  readonly explicitVerification: boolean;
  readonly onKillPoint?: (point: LifecycleKillPoint) => void | Promise<void>;
}

export interface CleanupProviderEnvelopeResult {
  readonly status: "cleaned" | "retained";
}

export type ProviderRecoveryResult =
  | { readonly status: "source_available" }
  | { readonly status: "recovered"; readonly value: Uint8Array }
  | { readonly status: "recovery_unavailable" }
  | { readonly status: "source_unrecoverable" };

export interface ProviderEnvelopeGenerationStore {
  get(operationId: string): Promise<PreparedProviderGeneration | undefined>;
  put(generation: PreparedProviderGeneration): Promise<void>;
  delete(operationId: string): Promise<void>;
}

export class ProviderEnvelopeLifecycle {
  readonly #source: AwsSourceClient;
  readonly #kms: KmsClient;
  readonly #store: ProviderEnvelopeGenerationStore;

  constructor(source: AwsSourceClient, kms: KmsClient, store: ProviderEnvelopeGenerationStore) {
    this.#source = source;
    this.#kms = kms;
    this.#store = store;
  }

  async prepare(input: PrepareProviderEnvelopeInput): Promise<PreparedProviderGeneration> {
    const context = createEnvelopeContext({
      operationId: input.operationId,
      generation: input.generation,
      sourceIdentity: input.sourceIdentity,
      targetSetDigest: input.targetSetDigest,
    });
    validateReference(input.keyReference);
    const targetIdentities = normalizeTargetIdentities(input.targetIdentities);
    const sourceRead = await this.#source.readExact(context.sourceIdentity);
    input.onEvent?.("source-read");
    try {
      this.#source.preflightMetadata(context.sourceIdentity, sourceRead.metadata);
      await this.#source.labelExact(context.sourceIdentity);
      input.onEvent?.("label-readback");
      input.onEvent?.("kms-generate");
      const envelope = await createProviderEnvelope({
        plaintext: sourceRead.value,
        context,
        keyReference: input.keyReference,
        references: input.references,
        iv: input.iv,
        kms: this.#kms,
      });
      input.onEvent?.("envelope-created");
      const prepared = Object.freeze({
        operationId: context.operationId,
        generation: context.generation,
        sourceIdentity: context.sourceIdentity,
        context,
        targetIdentities,
        keyReference: input.keyReference,
        envelope,
      });
      await this.#store.put(prepared);
      return prepared;
    } finally {
      zeroize(sourceRead.value);
    }
  }

  async getRetained(operationId: string): Promise<PreparedProviderGeneration | undefined> {
    return this.#store.get(operationId);
  }

  async cleanup(input: CleanupProviderEnvelopeInput): Promise<CleanupProviderEnvelopeResult> {
    const retained = await this.#store.get(input.operationId);
    if (retained === undefined || !cleanupVerificationMatches(retained, input)) return { status: "retained" };
    try {
      await input.onKillPoint?.("after-final-acknowledgement");
      await input.onKillPoint?.("during-canary");
      await input.onKillPoint?.("after-canary");
      await input.onKillPoint?.("during-cleanup");
      await this.#source.unlabelExact(retained.sourceIdentity);
    } catch {
      return { status: "retained" };
    }
    await this.#store.delete(retained.operationId);
    return { status: "cleaned" };
  }

  async recover(input: { readonly prepared: PreparedProviderGeneration }): Promise<ProviderRecoveryResult> {
    try {
      const sourceRead = await this.#source.readExact(input.prepared.sourceIdentity);
      zeroize(sourceRead.value);
      return { status: "source_available" };
    } catch (error) {
      if (!(error instanceof SourceMissingError)) return { status: "recovery_unavailable" };
    }
    try {
      const value = await decryptProviderEnvelope({
        envelope: input.prepared.envelope,
        context: input.prepared.context,
        keyReference: input.prepared.keyReference,
        kms: this.#kms,
      });
      return { status: "recovered", value };
    } catch (error) {
      return error instanceof InvalidProviderEnvelopeError
        ? { status: "source_unrecoverable" }
        : { status: "recovery_unavailable" };
    }
  }
}

function cleanupVerificationMatches(
  retained: PreparedProviderGeneration,
  input: CleanupProviderEnvelopeInput,
): boolean {
  if (!input.explicitVerification || input.canary !== "passed" || input.postconditions !== "passed") return false;
  if (input.acknowledgements.length !== retained.targetIdentities.length) return false;
  const expected = new Set(retained.targetIdentities);
  const seen = new Set<string>();
  for (const acknowledgement of input.acknowledgements) {
    if (!SAFE_REFERENCE.test(acknowledgement.targetIdentity) || !acknowledgement.acknowledged || !expected.has(acknowledgement.targetIdentity) || seen.has(acknowledgement.targetIdentity)) return false;
    seen.add(acknowledgement.targetIdentity);
  }
  return seen.size === expected.size;
}

function normalizeTargetIdentities(targetIdentities: readonly string[]): readonly string[] {
  if (!Array.isArray(targetIdentities) || targetIdentities.length === 0) throw new InvalidProviderEnvelopeError();
  const normalized = targetIdentities.map((targetIdentity) => {
    const value = readCanonicalText(targetIdentity, 2_048);
    if (!SAFE_REFERENCE.test(value)) throw new InvalidProviderEnvelopeError();
    return value;
  });
  if (new Set(normalized).size !== normalized.length) throw new InvalidProviderEnvelopeError();
  return Object.freeze([...normalized].sort(compareCanonicalText));
}

function normalizeReferences(references: readonly EnvelopeReference[]): readonly EnvelopeReference[] {
  if (!Array.isArray(references) || references.length > 64) throw new InvalidProviderEnvelopeError();
  const normalized = references.map((reference) => {
    if (!isValidReference(reference)) throw new InvalidProviderEnvelopeError();
    return Object.freeze({ kind: reference.kind, id: reference.id });
  });
  normalized.sort((left, right) =>
    compareCanonicalText(`${left.kind}\u0000${left.id}`, `${right.kind}\u0000${right.id}`),
  );
  const keys = normalized.map((reference) => `${reference.kind}:${reference.id}`);
  if (new Set(keys).size !== keys.length) throw new InvalidProviderEnvelopeError();
  return Object.freeze(normalized);
}

function sourceReference(source: SourceIdentity): string {
  const identity = canonicalSourceIdentity(source);
  return `${identity.partition}|${identity.account}|${identity.region}|${identity.fullParameterName}|${identity.version}|${identity.lifecycleLabel}`;
}

function validateMetadata(sourceIdentity: SourceIdentity, metadata: AwsParameterMetadata): void {
  if (!isRecord(metadata) || metadata.exists !== true || metadata.parameterName !== sourceIdentity.fullParameterName || metadata.version !== sourceIdentity.version || !Number.isSafeInteger(metadata.versionCount) || metadata.versionCount < 1 || metadata.versionCount > MAX_AWS_PARAMETER_VERSIONS || !Array.isArray(metadata.labels)) {
    throw new ProviderSourceBoundaryError();
  }
  for (const binding of metadata.labels) {
    if (!isRecord(binding)) throw new ProviderSourceBoundaryError();
    const label = binding.label;
    const version = binding.version;
    if (
      typeof label !== "string" ||
      !SAFE_LABEL.test(label) ||
      typeof version !== "number" ||
      !Number.isSafeInteger(version) ||
      version < 1
    ) {
      throw new ProviderSourceBoundaryError();
    }
  }
}

function compareCanonicalText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function readCanonicalText(value: unknown, maxLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength || value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new InvalidProviderEnvelopeError();
  }
  return value;
}

function validateReference(value: unknown): asserts value is string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) throw new InvalidProviderEnvelopeError();
}

function isValidReference(value: unknown): value is EnvelopeReference {
  return isRecord(value) && (value.kind === "source" || value.kind === "kms" || value.kind === "target") && typeof value.id === "string" && SAFE_REFERENCE.test(value.id);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function zeroize(value: Uint8Array | null | undefined): void {
  if (value !== undefined && value !== null) value.fill(0);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function fromBase64Url(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/u.test(value)) return null;
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return toBase64Url(decoded) === value ? decoded : null;
  } catch {
    return null;
  }
}
