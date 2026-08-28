import { encodeLengthPrefixed } from "./executor-provider-crypto";

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const SAFE_TARGET_REFERENCE = /^[\u0021-\u007e]{1,2048}$/u;
const GITHUB_NAME = /^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$/u;
const GITHUB_SECRET = /^[A-Z0-9_]{1,100}$/u;
const CLOUDFLARE_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CLOUDFLARE_ACCOUNT_ID = /^[a-f0-9]{32}$/u;

export type TargetCapability = "native_cas" | "enforced_exclusive" | "owner_risk_gate" | "blocked";
export type TargetOperationKind = "upsert" | "delete";
export type TargetWriteStatus = "applied" | "needs_reconciliation";

export class TargetClientError extends Error {
  constructor(
    message:
      | "invalid target capability"
      | "invalid target identity"
      | "target identity collision"
      | "invalid target operation"
      | "invalid provider response"
      | "target capability blocked",
  ) {
    super(message);
    this.name = "TargetClientError";
  }
}

export class InvalidTargetCapabilityError extends TargetClientError {
  constructor() {
    super("invalid target capability");
    this.name = "InvalidTargetCapabilityError";
  }
}

export class InvalidTargetIdentityError extends TargetClientError {
  constructor() {
    super("invalid target identity");
    this.name = "InvalidTargetIdentityError";
  }
}
export class TargetIdentityCollisionError extends TargetClientError {
  constructor() {
    super("target identity collision");
    this.name = "TargetIdentityCollisionError";
  }
}

export class InvalidTargetOperationError extends TargetClientError {
  constructor() {
    super("invalid target operation");
    this.name = "InvalidTargetOperationError";
  }
}

export class InvalidProviderResponseError extends TargetClientError {
  constructor() {
    super("invalid provider response");
    this.name = "InvalidProviderResponseError";
  }
}

export class TargetCapabilityBlockedError extends TargetClientError {
  constructor() {
    super("target capability blocked");
    this.name = "TargetCapabilityBlockedError";
  }
}

export interface GitHubTargetInput {
  readonly owner: string;
  readonly repository: string;
  readonly secretName: string;
  readonly environment?: string;
  readonly capability?: TargetCapability;
}

export interface CloudflareTargetInput {
  readonly accountId: string;
  readonly resourceKind: "worker" | "pages";
  readonly resourceName: string;
  readonly secretName: string;
  readonly environment?: string;
  readonly capability?: TargetCapability;
}

export interface GitHubTargetIdentity {
  readonly provider: "github";
  readonly owner: string;
  readonly repository: string;
  readonly secretName: string;
  readonly environment: string;
  readonly scope: string;
  readonly resource: "repository-secret";
  readonly capability: TargetCapability;
  readonly canonical: string;
}

export interface CloudflareTargetIdentity {
  readonly provider: "cloudflare";
  readonly accountId: string;
  readonly resourceKind: "worker" | "pages";
  readonly resourceName: string;
  readonly secretName: string;
  readonly environment: string;
  readonly scope: string;
  readonly resource: "worker-secret" | "pages-secret";
  readonly capability: TargetCapability;
  readonly canonical: string;
}

export type CanonicalTargetIdentity = GitHubTargetIdentity | CloudflareTargetIdentity;

export interface TargetCapabilityRow {
  readonly provider: CanonicalTargetIdentity["provider"];
  readonly resource: CanonicalTargetIdentity["resource"];
  readonly operation: TargetOperationKind;
  readonly capability: TargetCapability;
  readonly nativeCas: boolean;
  readonly exclusiveWriter: boolean;
  readonly ownerApprovalRequired: boolean;
}

export interface TargetOperation {
  readonly operationId: string;
  readonly generation: string;
  readonly target: CanonicalTargetIdentity;
  readonly contextDigest: string;
  readonly capability: TargetCapabilityRow;
  readonly operation: TargetOperationKind;
}



export interface TargetSet {
  readonly targets: readonly CanonicalTargetIdentity[];
  readonly digest: string;
}

export interface ProviderWriteResponse {
  readonly status: "applied" | "ambiguous";
  readonly operationId: string;
  readonly targetIdentity: string;
  readonly providerStateOID: string | null;
}

export interface TargetWriteResult {
  readonly status: TargetWriteStatus;
  readonly operationId: string;
  readonly targetIdentity: string;
  readonly providerStateOID: string | null;
}

export function canonicalGitHubTarget(input: GitHubTargetInput): GitHubTargetIdentity {
  const owner = normalizeGitHubName(input.owner);
  const repository = normalizeGitHubName(input.repository);
  const secretName = normalizeGitHubSecret(input.secretName);
  const environment = normalizeEnvironment(input.environment);
  const capability = normalizeCapability(input.capability);
  const scope = `${owner}/${repository}`;
  return Object.freeze({
    provider: "github",
    owner,
    repository,
    secretName,
    environment,
    scope,
    resource: "repository-secret",
    capability,
    canonical: `github|${scope}|${environment}|${secretName}`,
  });
}

export function canonicalCloudflareTarget(input: CloudflareTargetInput): CloudflareTargetIdentity {
  if (input.resourceKind !== "worker" && input.resourceKind !== "pages") throw new InvalidTargetIdentityError();
  const accountId = normalizeCloudflareAccountId(input.accountId);
  const resourceName = normalizeCloudflareName(input.resourceName);
  const secretName = normalizeGitHubSecret(input.secretName);
  const environment = normalizeEnvironment(input.environment);
  const capability = normalizeCapability(input.capability);
  const scope = `${accountId}/${input.resourceKind}/${resourceName}`;
  return Object.freeze({
    provider: "cloudflare",
    accountId,
    resourceKind: input.resourceKind,
    resourceName,
    secretName,
    environment,
    scope,
    resource: input.resourceKind === "worker" ? "worker-secret" : "pages-secret",
    capability,
    canonical: `cloudflare|${accountId}|${input.resourceKind}|${resourceName}|${environment}|${secretName}`,
  });
}

export async function canonicalTargetSet(targets: readonly CanonicalTargetIdentity[]): Promise<TargetSet> {
  if (!Array.isArray(targets) || targets.length === 0) throw new InvalidTargetIdentityError();
  const canonicalTargets = targets.map((target) => validateTargetIdentity(target));
  const sorted = [...canonicalTargets].sort((left, right) =>
    compareCanonicalText(left.canonical, right.canonical),
  );
  const seen = new Set<string>();
  for (const target of sorted) {
    if (seen.has(target.canonical)) throw new TargetIdentityCollisionError();
    seen.add(target.canonical);
  }
  const digestBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encodeLengthPrefixed(sorted.map((target) => new TextEncoder().encode(target.canonical)))),
  );
  return Object.freeze({ targets: Object.freeze(sorted), digest: `sha256:${toHex(digestBytes)}` });
}

export function targetCapabilityRow(target: CanonicalTargetIdentity, operation: TargetOperationKind): TargetCapabilityRow {
  const canonical = validateTargetIdentity(target);
  const capability = canonical.capability;
  if (capability === "blocked") throw new TargetCapabilityBlockedError();
  return Object.freeze({
    provider: canonical.provider,
    resource: canonical.resource,
    operation,
    capability,
    nativeCas: capability === "native_cas",
    exclusiveWriter: capability === "enforced_exclusive",
    ownerApprovalRequired: capability === "owner_risk_gate",
  });
}

export function createTargetOperation(input: {
  readonly operationId: string;
  readonly generation: string;
  readonly target: CanonicalTargetIdentity;
  readonly contextDigest: string;
  readonly operation?: TargetOperationKind;
}): TargetOperation {
  if (!SAFE_OPERATION_ID.test(input.operationId) || !SAFE_OPERATION_ID.test(input.generation) || !SHA256_DIGEST.test(input.contextDigest)) {
    throw new InvalidTargetOperationError();
  }
  const target = validateTargetIdentity(input.target);
  const operation = input.operation ?? "upsert";
  return Object.freeze({
    operationId: input.operationId,
    generation: input.generation,
    target,
    contextDigest: input.contextDigest,
    capability: targetCapabilityRow(target, operation),
    operation,
  });
}

export interface GitHubPublicKeyRequest {
  readonly owner: string;
  readonly repository: string;
}

export interface GitHubPublicKeyResponse {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

export interface GitHubSecretUpsertRequest {
  readonly owner: string;
  readonly repository: string;
  readonly secretName: string;
  readonly environment: string;
  readonly operationId: string;
  readonly generation: string;
  readonly targetIdentity: string;
  readonly contextDigest: string;
  readonly keyId: string;
  readonly sealedValue: Uint8Array;
}

export interface GitHubSecretDeleteRequest {
  readonly owner: string;
  readonly repository: string;
  readonly secretName: string;
  readonly environment: string;
  readonly operationId: string;
  readonly generation: string;
  readonly targetIdentity: string;
  readonly contextDigest: string;
}

export interface GitHubTargetTransport {
  getRepositoryPublicKey(request: GitHubPublicKeyRequest): Promise<GitHubPublicKeyResponse>;
  upsertRepositorySecret(request: GitHubSecretUpsertRequest): Promise<ProviderWriteResponse | null | undefined>;
  deleteRepositorySecret?(request: GitHubSecretDeleteRequest): Promise<ProviderWriteResponse | null | undefined>;
}

export interface SealedBox {
  seal(publicKey: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
}

export class GitHubTargetClient {
  readonly #transport: GitHubTargetTransport;
  readonly #sealedBox: SealedBox;
  #queue: Promise<void> = Promise.resolve();

  constructor(transport: GitHubTargetTransport, sealedBox: SealedBox) {
    this.#transport = transport;
    this.#sealedBox = sealedBox;
  }
  async upsertSecret(input: { readonly operation: TargetOperation; readonly value: Uint8Array }): Promise<TargetWriteResult> {
    const operation = validateOperationForProvider(input.operation, "github", "repository-secret", "upsert");
    if (operation.target.provider !== "github") throw new InvalidTargetOperationError();
    const target = operation.target;
    return this.enqueue(async () => {
      if (!(input.value instanceof Uint8Array)) throw new InvalidTargetOperationError();
      const plaintext = input.value.slice();
      let publicKey: Uint8Array | undefined;
      let sealedValue: Uint8Array | undefined;
      let wireValue: Uint8Array | undefined;
      try {
        let key: GitHubPublicKeyResponse;
        try {
          key = await this.#transport.getRepositoryPublicKey({ owner: target.owner, repository: target.repository });
        } catch {
          throw new InvalidProviderResponseError();
        }
        if (!(key.publicKey instanceof Uint8Array) || key.publicKey.byteLength !== 32 || typeof key.keyId !== "string" || !SAFE_TARGET_REFERENCE.test(key.keyId)) {
          throw new InvalidProviderResponseError();
        }
        publicKey = key.publicKey.slice();
        try {
          sealedValue = await this.#sealedBox.seal(publicKey, plaintext);
        } catch {
          throw new InvalidProviderResponseError();
        }
        if (!(sealedValue instanceof Uint8Array) || sealedValue.byteLength === 0) throw new InvalidProviderResponseError();
        wireValue = sealedValue.slice();
        let response: ProviderWriteResponse | null | undefined;
        try {
          response = await this.#transport.upsertRepositorySecret({
            owner: target.owner,
            repository: target.repository,
            secretName: target.secretName,
            environment: target.environment,
            operationId: operation.operationId,
            generation: operation.generation,
            targetIdentity: target.canonical,
            contextDigest: operation.contextDigest,
            keyId: key.keyId,
            sealedValue: wireValue,
          });
        } catch {
          return reconciliationResult(operation);
        }
        return normalizeWriteResponse(response, operation);
      } finally {
        plaintext.fill(0);
        publicKey?.fill(0);
        sealedValue?.fill(0);
        wireValue?.fill(0);
        input.value.fill(0);
      }
    });
  }

  async deleteSecret(input: { readonly operation: TargetOperation }): Promise<TargetWriteResult> {
    const operation = validateOperationForProvider(input.operation, "github", "repository-secret", "delete");
    if (operation.target.provider !== "github") throw new InvalidTargetOperationError();
    const target = operation.target;
    return this.enqueue(async () => {
      if (this.#transport.deleteRepositorySecret === undefined) throw new TargetCapabilityBlockedError();
      try {
        const response = await this.#transport.deleteRepositorySecret({
          owner: target.owner,
          repository: target.repository,
          secretName: target.secretName,
          environment: target.environment,
          operationId: operation.operationId,
          generation: operation.generation,
          targetIdentity: target.canonical,
          contextDigest: operation.contextDigest,
        });
        return normalizeWriteResponse(response, operation);
      } catch (error) {
        if (error instanceof InvalidProviderResponseError) throw error;
        return reconciliationResult(operation);
      }
    });
  }


  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.#queue;
    let release!: () => void;
    this.#queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    return previous.then(operation).finally(() => release());
  }
}

export interface CloudflareSecretWriteRequest {
  readonly accountId: string;
  readonly resourceName: string;
  readonly secretName: string;
  readonly environment: string;
  readonly operationId: string;
  readonly generation: string;
  readonly targetIdentity: string;
  readonly contextDigest: string;
  readonly value: Uint8Array;
}

export interface CloudflareSecretDeleteRequest {
  readonly accountId: string;
  readonly resourceName: string;
  readonly secretName: string;
  readonly environment: string;
  readonly operationId: string;
  readonly generation: string;
  readonly targetIdentity: string;
  readonly contextDigest: string;
}

export interface CloudflareTargetTransport {
  writeWorkerSecret(request: CloudflareSecretWriteRequest): Promise<ProviderWriteResponse | null | undefined>;
  writePagesSecret(request: CloudflareSecretWriteRequest): Promise<ProviderWriteResponse | null | undefined>;
  deleteWorkerSecret?(request: CloudflareSecretDeleteRequest): Promise<ProviderWriteResponse | null | undefined>;
  deletePagesSecret?(request: CloudflareSecretDeleteRequest): Promise<ProviderWriteResponse | null | undefined>;
}

export class CloudflareTargetClient {
  readonly #transport: CloudflareTargetTransport;
  #queue: Promise<void> = Promise.resolve();

  constructor(transport: CloudflareTargetTransport) {
    this.#transport = transport;
  }

  async upsertSecret(input: { readonly operation: TargetOperation; readonly value: Uint8Array }): Promise<TargetWriteResult> {
    const operation = validateOperationForProvider(input.operation, "cloudflare", undefined, "upsert");
    if (operation.target.provider !== "cloudflare") throw new InvalidTargetOperationError();
    const target = operation.target;
    return this.enqueue(async () => {
      if (!(input.value instanceof Uint8Array)) throw new InvalidTargetOperationError();
      const value = input.value.slice();
      const wireValue = value.slice();
      try {
        const request: CloudflareSecretWriteRequest = {
          accountId: target.accountId,
          resourceName: target.resourceName,
          secretName: target.secretName,
          environment: target.environment,
          operationId: operation.operationId,
          generation: operation.generation,
          targetIdentity: target.canonical,
          contextDigest: operation.contextDigest,
          value: wireValue,
        };
        let response: ProviderWriteResponse | null | undefined;
        try {
          response = target.resourceKind === "worker"
            ? await this.#transport.writeWorkerSecret(request)
            : await this.#transport.writePagesSecret(request);
        } catch {
          return reconciliationResult(operation);
        }
        return normalizeWriteResponse(response, operation);
      } finally {
        value.fill(0);
        wireValue.fill(0);
        input.value.fill(0);
      }
    });
  }

  async deleteSecret(input: { readonly operation: TargetOperation }): Promise<TargetWriteResult> {
    const operation = validateOperationForProvider(input.operation, "cloudflare", undefined, "delete");
    if (operation.target.provider !== "cloudflare") throw new InvalidTargetOperationError();
    const target = operation.target;
    return this.enqueue(async () => {
      const mutate = target.resourceKind === "worker"
        ? this.#transport.deleteWorkerSecret === undefined
          ? null
          : (request: CloudflareSecretDeleteRequest) => this.#transport.deleteWorkerSecret!(request)
        : this.#transport.deletePagesSecret === undefined
          ? null
          : (request: CloudflareSecretDeleteRequest) => this.#transport.deletePagesSecret!(request);
      if (mutate === null) throw new TargetCapabilityBlockedError();
      const request: CloudflareSecretDeleteRequest = {
        accountId: target.accountId,
        resourceName: target.resourceName,
        secretName: target.secretName,
        environment: target.environment,
        operationId: operation.operationId,
        generation: operation.generation,
        targetIdentity: target.canonical,
        contextDigest: operation.contextDigest,
      };
      try {
        return normalizeWriteResponse(await mutate(request), operation);
      } catch (error) {
        if (error instanceof InvalidProviderResponseError) throw error;
        return reconciliationResult(operation);
      }
    });
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.#queue;
    let release!: () => void;
    this.#queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    return previous.then(operation).finally(() => release());
  }
}


function normalizeGitHubName(value: unknown): string {
  if (typeof value !== "string") throw new InvalidTargetIdentityError();
  const normalized = value.normalize("NFKC").trim().toLowerCase();
  if (!GITHUB_NAME.test(normalized)) throw new InvalidTargetIdentityError();
  return normalized;
}

function normalizeGitHubSecret(value: unknown): string {
  if (typeof value !== "string") throw new InvalidTargetIdentityError();
  const normalized = value.normalize("NFKC").trim().toUpperCase();
  if (!GITHUB_SECRET.test(normalized)) throw new InvalidTargetIdentityError();
  return normalized;
}

function normalizeCloudflareAccountId(value: unknown): string {
  if (typeof value !== "string") throw new InvalidTargetIdentityError();
  const normalized = value.normalize("NFKC").trim().toLowerCase();
  if (!CLOUDFLARE_ACCOUNT_ID.test(normalized)) throw new InvalidTargetIdentityError();
  return normalized;
}

function normalizeCloudflareName(value: unknown): string {
  if (typeof value !== "string") throw new InvalidTargetIdentityError();
  const normalized = value.normalize("NFKC").trim().toLowerCase();
  if (!CLOUDFLARE_NAME.test(normalized)) throw new InvalidTargetIdentityError();
  return normalized;
}

function normalizeEnvironment(value: unknown): string {
  if (value === undefined) return "production";
  if (typeof value !== "string") throw new InvalidTargetIdentityError();
  const normalized = value.normalize("NFKC").trim().toLowerCase();
  if (!CLOUDFLARE_NAME.test(normalized)) throw new InvalidTargetIdentityError();
  return normalized;
}

function normalizeCapability(value: unknown): TargetCapability {
  if (value === undefined) return "owner_risk_gate";
  if (value !== "native_cas" && value !== "enforced_exclusive" && value !== "owner_risk_gate" && value !== "blocked") {
    throw new InvalidTargetCapabilityError();
  }
  return value;
}

function validateTargetIdentity(target: CanonicalTargetIdentity): CanonicalTargetIdentity {
  if (target.provider === "github") {
    const canonical = canonicalGitHubTarget({
      owner: target.owner,
      repository: target.repository,
      secretName: target.secretName,
      environment: target.environment,
      capability: target.capability,
    });
    if (canonical.canonical !== target.canonical || canonical.scope !== target.scope || canonical.resource !== target.resource) throw new InvalidTargetIdentityError();
    return canonical;
  }
  if (target.provider === "cloudflare") {
    const canonical = canonicalCloudflareTarget({
      accountId: target.accountId,
      resourceKind: target.resourceKind,
      resourceName: target.resourceName,
      secretName: target.secretName,
      environment: target.environment,
      capability: target.capability,
    });
    if (canonical.canonical !== target.canonical || canonical.scope !== target.scope || canonical.resource !== target.resource) throw new InvalidTargetIdentityError();
    return canonical;
  }
  throw new InvalidTargetIdentityError();
}

function validateOperationForProvider(
  operation: TargetOperation,
  provider: CanonicalTargetIdentity["provider"],
  resource: CanonicalTargetIdentity["resource"] | undefined,
  expectedOperation: TargetOperationKind,
): TargetOperation {
  if (!operation || !SAFE_OPERATION_ID.test(operation.operationId) || !SAFE_OPERATION_ID.test(operation.generation) || !SHA256_DIGEST.test(operation.contextDigest)) {
    throw new InvalidTargetOperationError();
  }
  const target = validateTargetIdentity(operation.target);
  if (target.provider !== provider || (resource !== undefined && target.resource !== resource) || operation.operation !== expectedOperation || operation.capability.capability !== target.capability || operation.capability.operation !== expectedOperation) {
    throw new InvalidTargetOperationError();
  }
  if (target.capability === "blocked") throw new TargetCapabilityBlockedError();
  if (target.capability !== "owner_risk_gate") throw new InvalidTargetCapabilityError();
  return Object.freeze({ ...operation, target, capability: targetCapabilityRow(target, expectedOperation), operation: expectedOperation });
}


function reconciliationResult(operation: TargetOperation): TargetWriteResult {
  return {
    status: "needs_reconciliation",
    operationId: operation.operationId,
    targetIdentity: operation.target.canonical,
    providerStateOID: null,
  };
}

function normalizeWriteResponse(response: ProviderWriteResponse | null | undefined, operation: TargetOperation): TargetWriteResult {
  if (response === null || response === undefined) return reconciliationResult(operation);
  if (
    typeof response !== "object" ||
    (response.status !== "applied" && response.status !== "ambiguous") ||
    response.operationId !== operation.operationId ||
    response.targetIdentity !== operation.target.canonical
  ) {
    throw new InvalidProviderResponseError();
  }
  if (response.status === "ambiguous") {
    if (response.providerStateOID !== null) throw new InvalidProviderResponseError();
    return reconciliationResult(operation);
  }
  if (typeof response.providerStateOID !== "string" || !SAFE_TARGET_REFERENCE.test(response.providerStateOID)) {
    throw new InvalidProviderResponseError();
  }
  return {
    status: "applied",
    operationId: operation.operationId,
    targetIdentity: operation.target.canonical,
    providerStateOID: response.providerStateOID,
  };
}

function compareCanonicalText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
