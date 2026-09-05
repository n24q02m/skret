import type { ExecutorEnvelope } from "./executor-envelope-verifier";
import type { ExecutorOperationStore } from "./executor-operation-store";
import type { PrivateExecutorRoleAuthority } from "./private-executor-handler";

export const CANDIDATE_GITHUB_SCHEMA = "skret/executor/candidate-github-lifecycle/v1" as const;
export const CANDIDATE_GITHUB_AUTHORIZATION_SCHEMA =
  "skret/executor/candidate-github-lifecycle-authorization/v1" as const;
export const CANDIDATE_GITHUB_ROLE = "GH-SETTINGS-RW" as const;
export const CANDIDATE_GITHUB_RESOURCE = {
  repository: "n24q02m/skret-wave3-synthetic-20260904-2f60ff93",
  repository_id: 1357350321,
  repository_node_id: "R_kgDOUOeFsQ",
  environment: "synthetic-candidate",
  environment_node_id: "EN_kwDOUOeFsc8AAAAE8xLZTA",
  app_id: 3200052,
  installation_id: 119415436,
} as const;

const MAX_BODY_BYTES = 16 * 1024;
const MAX_AUTHORIZATION_TTL_MS = 15 * 60 * 1000;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
export const CANDIDATE_GITHUB_BODY_FIELDS = [
  "schema", "action", "transaction_digest", "operation_id", "invocation_id",
  "repository", "repository_id", "repository_node_id", "environment", "environment_node_id",
  "app_id", "installation_id", "authority_generation", "deadline_at", "executor_image_digest",
  "executor_config_digest", "source_digest", "target_digest", "config_digest", "fixture_digest",
  "fixture_commit_oid", "payload_digest", "precondition_digest", "rollback_digest",
] as const;
export const CANDIDATE_GITHUB_ACTIONS = [
  "mint_provisioner", "mint_dispatcher", "mint_retiring", "mint_active",
  "put_retiring", "put_active", "delete_retiring", "delete_active",
  "dispatch_retiring_baseline", "dispatch_active_baseline", "dispatch_retiring_denied",
  "dispatch_active_pre_revoke", "dispatch_active_post_revoke", "dispatch_retiring_rollback",
  "revoke_retiring", "revoke_active", "revoke_provisioner", "revoke_dispatcher",
] as const;
export type CandidateGithubAction = typeof CANDIDATE_GITHUB_ACTIONS[number];

export interface CandidateGithubDocument {
  readonly schema: typeof CANDIDATE_GITHUB_SCHEMA;
  readonly action: CandidateGithubAction;
  readonly transaction_digest: string;
  readonly operation_id: string;
  readonly invocation_id: string;
  readonly repository: string;
  readonly repository_id: number;
  readonly repository_node_id: string;
  readonly environment: string;
  readonly environment_node_id: string;
  readonly app_id: number;
  readonly installation_id: number;
  readonly authority_generation: number;
  readonly deadline_at: number;
  readonly executor_image_digest: string;
  readonly executor_config_digest: string;
  readonly source_digest: string;
  readonly target_digest: string;
  readonly config_digest: string;
  readonly fixture_digest: string;
  readonly fixture_commit_oid: string;
  readonly payload_digest: string;
  readonly precondition_digest: string;
  readonly rollback_digest: string;
}

export interface CandidateGithubAuthorizerOptions {
  readonly transactionDigest: string;
  readonly sourceDigest: string;
  readonly fixtureDigest: string;
  readonly fixtureCommitOid: string;
  readonly targetDigest: string;
  readonly executorImageDigest: string;
  readonly executorConfigDigest: string;
  readonly operations: ExecutorOperationStore;
  readonly now?: number;
}

export async function candidateGithubTargetDigest(): Promise<string> {
  return sha256Digest(new TextEncoder().encode(JSON.stringify({
    schema: "skret/executor/candidate-github-target/v1",
    ...CANDIDATE_GITHUB_RESOURCE,
    aliases: ["SKRET_CANDIDATE_ACTIVE_TOKEN", "SKRET_CANDIDATE_RETIRING_TOKEN"],
  })));
}

export function canonicalCandidateGithubBodyBytes(document: CandidateGithubDocument): Uint8Array {
  const ordered: Record<string, unknown> = {};
  for (const field of CANDIDATE_GITHUB_BODY_FIELDS) ordered[field] = document[field];
  return new TextEncoder().encode(JSON.stringify(ordered));
}

export async function executeCandidateGithubAuthorization(
  body: Uint8Array,
  envelope: Pick<ExecutorEnvelope, "role" | "manifest_digest" | "body_digest" | "expires_at">,
  authority: PrivateExecutorRoleAuthority,
  options: CandidateGithubAuthorizerOptions,
): Promise<Uint8Array> {
  const document = parseDocument(body);
  const now = options.now ?? Date.now();
  const envelopeExpiry = Date.parse(envelope.expires_at);
  if (
    !Number.isSafeInteger(now) || now < 0 ||
    !Number.isSafeInteger(envelopeExpiry) || envelopeExpiry <= now ||
    envelope.role !== CANDIDATE_GITHUB_ROLE || authority.role !== CANDIDATE_GITHUB_ROLE ||
    document.authority_generation !== authority.generation ||
    document.transaction_digest !== authority.capabilityDigest ||
    document.transaction_digest !== envelope.manifest_digest ||
    document.transaction_digest !== options.transactionDigest ||
    document.source_digest !== options.sourceDigest ||
    document.fixture_digest !== options.fixtureDigest ||
    document.fixture_commit_oid !== options.fixtureCommitOid ||
    document.target_digest !== options.targetDigest ||
    document.executor_image_digest !== options.executorImageDigest ||
    document.executor_config_digest !== options.executorConfigDigest ||
    document.deadline_at <= now || document.deadline_at > now + MAX_AUTHORIZATION_TTL_MS ||
    document.deadline_at > authority.notAfter || document.deadline_at > envelopeExpiry
  ) throw new Error("candidate GitHub authorization invalid");

  const started = await options.operations.begin({
    operation_id: document.operation_id,
    schedule_digest: document.transaction_digest,
    exclusive: true,
    invocation_id: document.invocation_id,
    fingerprint: envelope.body_digest,
    generation: `candidate-github-lifecycle:${authority.generation}`,
    source_digest: document.source_digest,
    target_digest: document.target_digest,
    config_digest: document.config_digest,
    deadline_at: document.deadline_at,
  }, now);
  if (started.status !== "started") throw new Error("candidate GitHub authorization unavailable");

  const authorization = new TextEncoder().encode(JSON.stringify({
    ...document,
    schema: CANDIDATE_GITHUB_AUTHORIZATION_SCHEMA,
    status: "authorized",
    role: authority.role,
    body_digest: envelope.body_digest,
    authorized_at: now,
  }));
  const completed = await options.operations.complete(
    document.operation_id, document.invocation_id, "succeeded",
    await sha256Digest(authorization), now, authorization,
  );
  if (completed.status !== "succeeded") throw new Error("candidate GitHub authorization unavailable");
  return authorization;
}

function parseDocument(body: Uint8Array): CandidateGithubDocument {
  if (!(body instanceof Uint8Array) || body.byteLength === 0 || body.byteLength > MAX_BODY_BYTES) {
    throw new Error("candidate GitHub request invalid");
  }
  const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("candidate GitHub request invalid");
  }
  const fields = Object.keys(parsed);
  const document = parsed as CandidateGithubDocument;
  if (
    fields.length !== CANDIDATE_GITHUB_BODY_FIELDS.length ||
    fields.some((field, index) => field !== CANDIDATE_GITHUB_BODY_FIELDS[index]) ||
    document.schema !== CANDIDATE_GITHUB_SCHEMA ||
    !CANDIDATE_GITHUB_ACTIONS.includes(document.action) ||
    Object.entries(CANDIDATE_GITHUB_RESOURCE).some(([field, value]) =>
      document[field as keyof typeof CANDIDATE_GITHUB_RESOURCE] !== value) ||
    !isID(document.operation_id) || !isID(document.invocation_id) ||
    !Number.isSafeInteger(document.authority_generation) || document.authority_generation <= 0 ||
    !Number.isSafeInteger(document.deadline_at) || document.deadline_at <= 0 ||
    typeof document.fixture_commit_oid !== "string" || !COMMIT_PATTERN.test(document.fixture_commit_oid) ||
    [document.transaction_digest, document.executor_image_digest, document.executor_config_digest,
      document.source_digest, document.target_digest, document.config_digest, document.fixture_digest,
      document.payload_digest, document.precondition_digest, document.rollback_digest].some(value => !isDigest(value)) ||
    !sameBytes(body, canonicalCandidateGithubBodyBytes(document))
  ) throw new Error("candidate GitHub request invalid");
  return document;
}

function isID(value: unknown): value is string {
  return typeof value === "string" && ID_PATTERN.test(value);
}
function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
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
  return `sha256:${Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("")}`;
}
