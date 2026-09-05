import type { ExecutorEnvelope } from "./executor-envelope-verifier";
import type { ExecutorOperationStore } from "./executor-operation-store";
import type { PrivateExecutorRoleAuthority } from "./private-executor-handler";

export const CANDIDATE_LIFECYCLE_SCHEMA = "skret/executor/candidate-cloudflare-lifecycle/v1" as const;
export const CANDIDATE_LIFECYCLE_AUTHORIZATION_SCHEMA =
  "skret/executor/candidate-cloudflare-lifecycle-authorization/v1" as const;
export const CANDIDATE_LIFECYCLE_TARGET_SCHEMA =
  "skret/executor/candidate-cloudflare-target/v1" as const;
export const CANDIDATE_DEPLOY_ROLE = "SK-CF-NOCAS-RW" as const;
export const CANDIDATE_SCHEDULE_ROLE = "SK-SCHEDULE-RW" as const;
export const CANDIDATE_ACCOUNT_ID = "53feac446e497b886f384c9f8a58132b" as const;
export const CANDIDATE_EXECUTOR_SCRIPT = "skret-candidate-security-executor" as const;
export const EMPTY_SCHEDULES_DIGEST =
  "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945" as const;
export const ENABLED_CANDIDATE_SCHEDULE_DIGEST =
  "sha256:cea08586b02f42ab2e628f8a1d80c7f904679f56c48091e357abdfdceef57eb4" as const;

const MAX_BODY_BYTES = 16 * 1024;
const MAX_AUTHORIZATION_TTL_MS = 15 * 60 * 1000;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const BODY_FIELDS = [
  "schema",
  "action",
  "transaction_digest",
  "operation_id",
  "invocation_id",
  "account_id",
  "script_name",
  "authority_generation",
  "deadline_at",
  "executor_image_digest",
  "executor_config_digest",
  "source_digest",
  "target_digest",
  "config_digest",
  "module_digest",
  "payload_digest",
  "deployment_digest",
  "rollback_digest",
  "schedule_before_digest",
  "schedule_desired_digest",
] as const;

export const CANDIDATE_LIFECYCLE_BODY_FIELDS = BODY_FIELDS;

export type CandidateLifecycleAction =
  | "deploy_forward"
  | "enable_initial"
  | "disable_before_rollback"
  | "rollback"
  | "deploy_redeploy"
  | "enable_redeploy"
  | "terminal_check"
  | "disable_final";

export interface CandidateLifecycleDocument {
  readonly schema: typeof CANDIDATE_LIFECYCLE_SCHEMA;
  readonly action: CandidateLifecycleAction;
  readonly transaction_digest: string;
  readonly operation_id: string;
  readonly invocation_id: string;
  readonly account_id: string;
  readonly script_name: string;
  readonly authority_generation: number;
  readonly deadline_at: number;
  readonly executor_image_digest: string;
  readonly executor_config_digest: string;
  readonly source_digest: string;
  readonly target_digest: string;
  readonly config_digest: string;
  readonly module_digest: string;
  readonly payload_digest: string;
  readonly deployment_digest: string;
  readonly rollback_digest: string;
  readonly schedule_before_digest: string;
  readonly schedule_desired_digest: string;
}

export interface CandidateLifecycleAuthorizerOptions {
  readonly accountId: string;
  readonly scriptName: string;
  readonly transactionDigest: string;
  readonly targetDigest: string;
  readonly executorImageDigest: string;
  readonly executorConfigDigest: string;
  readonly operations: ExecutorOperationStore;
  readonly now?: number;
}

export class CandidateLifecycleInvalidRequestError extends Error {
  constructor() {
    super("candidate lifecycle authorization invalid");
    this.name = "CandidateLifecycleInvalidRequestError";
  }
}

export class CandidateLifecycleUnavailableError extends Error {
  constructor() {
    super("candidate lifecycle authorization unavailable");
    this.name = "CandidateLifecycleUnavailableError";
  }
}

export async function candidateLifecycleTargetDigest(
  accountId: string,
  scriptName: string,
): Promise<string> {
  if (accountId !== CANDIDATE_ACCOUNT_ID || scriptName !== CANDIDATE_EXECUTOR_SCRIPT) {
    throw new CandidateLifecycleInvalidRequestError();
  }
  return sha256Digest(
    new TextEncoder().encode(
      JSON.stringify({
        schema: CANDIDATE_LIFECYCLE_TARGET_SCHEMA,
        account_id: accountId,
        script_name: scriptName,
      }),
    ),
  );
}

export function canonicalCandidateLifecycleBodyBytes(
  document: CandidateLifecycleDocument,
): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      schema: document.schema,
      action: document.action,
      transaction_digest: document.transaction_digest,
      operation_id: document.operation_id,
      invocation_id: document.invocation_id,
      account_id: document.account_id,
      script_name: document.script_name,
      authority_generation: document.authority_generation,
      deadline_at: document.deadline_at,
      executor_image_digest: document.executor_image_digest,
      executor_config_digest: document.executor_config_digest,
      source_digest: document.source_digest,
      target_digest: document.target_digest,
      config_digest: document.config_digest,
      module_digest: document.module_digest,
      payload_digest: document.payload_digest,
      deployment_digest: document.deployment_digest,
      rollback_digest: document.rollback_digest,
      schedule_before_digest: document.schedule_before_digest,
      schedule_desired_digest: document.schedule_desired_digest,
    }),
  );
}

export async function executeCandidateLifecycleAuthorization(
  body: Uint8Array,
  envelope: Pick<ExecutorEnvelope, "role" | "manifest_digest" | "body_digest" | "expires_at">,
  authority: PrivateExecutorRoleAuthority,
  options: CandidateLifecycleAuthorizerOptions,
): Promise<Uint8Array> {
  const document = parseCandidateLifecycleDocument(body);
  const now = options.now ?? Date.now();
  const envelopeExpiry = Date.parse(envelope.expires_at);
  if (
    !Number.isSafeInteger(now) ||
    now < 0 ||
    !Number.isSafeInteger(envelopeExpiry) ||
    envelopeExpiry <= now ||
    !validOptions(options) ||
    envelope.role !== authority.role ||
    expectedRole(document.action) !== authority.role ||
    document.authority_generation !== authority.generation ||
    document.transaction_digest !== options.transactionDigest ||
    document.transaction_digest !== authority.capabilityDigest ||
    document.transaction_digest !== envelope.manifest_digest ||
    document.account_id !== options.accountId ||
    document.script_name !== options.scriptName ||
    document.target_digest !== options.targetDigest ||
    document.executor_image_digest !== options.executorImageDigest ||
    document.executor_config_digest !== options.executorConfigDigest ||
    document.deadline_at <= now ||
    document.deadline_at > now + MAX_AUTHORIZATION_TTL_MS ||
    document.deadline_at > authority.notAfter ||
    document.deadline_at > envelopeExpiry ||
    !validScheduleTransition(document)
  ) {
    throw new CandidateLifecycleInvalidRequestError();
  }

  let started;
  try {
    started = await options.operations.begin(
      {
        operation_id: document.operation_id,
        schedule_digest: document.transaction_digest,
        exclusive: true,
        invocation_id: document.invocation_id,
        fingerprint: envelope.body_digest,
        generation: `candidate-lifecycle:${authority.generation}`,
        source_digest: document.source_digest,
        target_digest: document.target_digest,
        config_digest: document.config_digest,
        deadline_at: document.deadline_at,
      },
      now,
    );
  } catch {
    throw new CandidateLifecycleUnavailableError();
  }
  if (started.status !== "started") throw new CandidateLifecycleInvalidRequestError();

  const authorization = new TextEncoder().encode(
    JSON.stringify({
      schema: CANDIDATE_LIFECYCLE_AUTHORIZATION_SCHEMA,
      status: "authorized",
      action: document.action,
      operation_id: document.operation_id,
      invocation_id: document.invocation_id,
      account_id: document.account_id,
      script_name: document.script_name,
      role: authority.role,
      authority_generation: authority.generation,
      transaction_digest: document.transaction_digest,
      body_digest: envelope.body_digest,
      source_digest: document.source_digest,
      target_digest: document.target_digest,
      config_digest: document.config_digest,
      module_digest: document.module_digest,
      payload_digest: document.payload_digest,
      deployment_digest: document.deployment_digest,
      rollback_digest: document.rollback_digest,
      schedule_before_digest: document.schedule_before_digest,
      schedule_desired_digest: document.schedule_desired_digest,
      authorized_at: now,
      deadline_at: document.deadline_at,
    }),
  );

  try {
    const completed = await options.operations.complete(
      document.operation_id,
      document.invocation_id,
      "succeeded",
      await sha256Digest(authorization),
      now,
      authorization,
    );
    if (completed.status !== "succeeded") throw new CandidateLifecycleUnavailableError();
  } catch (error) {
    if (error instanceof CandidateLifecycleUnavailableError) throw error;
    throw new CandidateLifecycleUnavailableError();
  }
  return authorization;
}

function parseCandidateLifecycleDocument(body: Uint8Array): CandidateLifecycleDocument {
  if (!(body instanceof Uint8Array) || body.byteLength === 0 || body.byteLength > MAX_BODY_BYTES) {
    throw new CandidateLifecycleInvalidRequestError();
  }
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
    parsed = JSON.parse(text);
  } catch {
    throw new CandidateLifecycleInvalidRequestError();
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new CandidateLifecycleInvalidRequestError();
  }
  const fields = Object.keys(parsed);
  if (
    fields.length !== BODY_FIELDS.length ||
    fields.some((field, index) => field !== BODY_FIELDS[index])
  ) {
    throw new CandidateLifecycleInvalidRequestError();
  }

  const candidate = parsed as unknown as CandidateLifecycleDocument;
  if (
    candidate.schema !== CANDIDATE_LIFECYCLE_SCHEMA ||
    !isCandidateLifecycleAction(candidate.action) ||
    !isDigest(candidate.transaction_digest) ||
    !isID(candidate.operation_id) ||
    !isID(candidate.invocation_id) ||
    candidate.account_id !== CANDIDATE_ACCOUNT_ID ||
    candidate.script_name !== CANDIDATE_EXECUTOR_SCRIPT ||
    !Number.isSafeInteger(candidate.authority_generation) ||
    candidate.authority_generation <= 0 ||
    !Number.isSafeInteger(candidate.deadline_at) ||
    candidate.deadline_at <= 0 ||
    !isDigest(candidate.executor_image_digest) ||
    !isDigest(candidate.executor_config_digest) ||
    !isDigest(candidate.source_digest) ||
    !isDigest(candidate.target_digest) ||
    !isDigest(candidate.config_digest) ||
    !isDigest(candidate.module_digest) ||
    !isDigest(candidate.payload_digest) ||
    !isDigest(candidate.deployment_digest) ||
    !isDigest(candidate.rollback_digest) ||
    !isDigest(candidate.schedule_before_digest) ||
    !isDigest(candidate.schedule_desired_digest) ||
    !sameBytes(body, canonicalCandidateLifecycleBodyBytes(candidate))
  ) {
    throw new CandidateLifecycleInvalidRequestError();
  }
  return candidate;
}



function validOptions(options: CandidateLifecycleAuthorizerOptions): boolean {
  return Boolean(
    options &&
      options.accountId === CANDIDATE_ACCOUNT_ID &&
      options.scriptName === CANDIDATE_EXECUTOR_SCRIPT &&
      isDigest(options.transactionDigest) &&
      isDigest(options.targetDigest) &&
      isDigest(options.executorImageDigest) &&
      isDigest(options.executorConfigDigest) &&
      options.operations &&
      typeof options.operations.begin === "function" &&
      typeof options.operations.complete === "function",
  );
}

function expectedRole(action: CandidateLifecycleAction): string {
  return action === "deploy_forward" || action === "rollback" || action === "deploy_redeploy"
    ? CANDIDATE_DEPLOY_ROLE
    : CANDIDATE_SCHEDULE_ROLE;
}

function validScheduleTransition(document: CandidateLifecycleDocument): boolean {
  switch (document.action) {
    case "deploy_forward":
    case "rollback":
    case "deploy_redeploy":
      return (
        document.schedule_before_digest === EMPTY_SCHEDULES_DIGEST &&
        document.schedule_desired_digest === EMPTY_SCHEDULES_DIGEST
      );
    case "enable_initial":
    case "enable_redeploy":
      return (
        document.schedule_before_digest === EMPTY_SCHEDULES_DIGEST &&
        document.schedule_desired_digest === ENABLED_CANDIDATE_SCHEDULE_DIGEST
      );
    case "terminal_check":
      return (
        document.schedule_before_digest === ENABLED_CANDIDATE_SCHEDULE_DIGEST &&
        document.schedule_desired_digest === ENABLED_CANDIDATE_SCHEDULE_DIGEST
      );
    case "disable_before_rollback":
    case "disable_final":
      return (
        document.schedule_before_digest === ENABLED_CANDIDATE_SCHEDULE_DIGEST &&
        document.schedule_desired_digest === EMPTY_SCHEDULES_DIGEST
      );
  }
}

function isCandidateLifecycleAction(value: unknown): value is CandidateLifecycleAction {
  return (
    value === "deploy_forward" ||
    value === "enable_initial" ||
    value === "disable_before_rollback" ||
    value === "rollback" ||
    value === "deploy_redeploy" ||
    value === "enable_redeploy" ||
    value === "terminal_check" ||
    value === "disable_final"
  );
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && SHA256_DIGEST_PATTERN.test(value);
}

function isID(value: unknown): value is string {
  return typeof value === "string" && ID_PATTERN.test(value);
}


function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

async function sha256Digest(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}
