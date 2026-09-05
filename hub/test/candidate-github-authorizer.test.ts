import { describe, expect, it } from "vitest";
import {
  CANDIDATE_GITHUB_AUTHORIZATION_SCHEMA,
  CANDIDATE_GITHUB_RESOURCE,
  CANDIDATE_GITHUB_ROLE,
  CANDIDATE_GITHUB_SCHEMA,
  canonicalCandidateGithubBodyBytes,
  candidateGithubTargetDigest,
  executeCandidateGithubAuthorization,
  type CandidateGithubDocument,
} from "../src/candidate-github-authorizer";
import {
  DurableExecutorOperationStore,
  type ExecutorOperationStorage,
  type ExecutorOperationTransaction,
} from "../src/executor-operation-store";

const NOW = 1_780_000_000_000;
const DIGEST = `sha256:${"a".repeat(64)}`;
const OTHER_DIGEST = `sha256:${"b".repeat(64)}`;

async function fixture() {
  const values = new Map<string, unknown>();
  let tail = Promise.resolve();
  const storage: ExecutorOperationStorage = {
    async get<T>(key: string) { return values.get(key) as T | undefined; },
    async put<T>(key: string, value: T) { values.set(key, value); },
    async delete(key: string) { return values.delete(key); },
    async transaction<T>(closure: (transaction: ExecutorOperationTransaction) => Promise<T>): Promise<T> {
      const previous = tail;
      let release!: () => void;
      tail = new Promise<void>((resolve) => { release = resolve; });
      await previous;
      try { return await closure(storage); } finally { release(); }
    },
  };
  const targetDigest = await candidateGithubTargetDigest();
  const document: CandidateGithubDocument = {
    schema: CANDIDATE_GITHUB_SCHEMA,
    action: "put_active",
    transaction_digest: DIGEST,
    operation_id: "github-operation-1",
    invocation_id: "github-invocation-1",
    ...CANDIDATE_GITHUB_RESOURCE,
    authority_generation: 3,
    deadline_at: NOW + 60_000,
    executor_image_digest: DIGEST,
    executor_config_digest: DIGEST,
    source_digest: DIGEST,
    target_digest: targetDigest,
    config_digest: DIGEST,
    fixture_digest: DIGEST,
    fixture_commit_oid: "c".repeat(40),
    payload_digest: DIGEST,
    precondition_digest: DIGEST,
    rollback_digest: DIGEST,
  };
  const authority = {
    role: CANDIDATE_GITHUB_ROLE,
    generation: 3,
    notAfter: NOW + 900_000,
    capabilityDigest: DIGEST,
  };
  const options = {
    transactionDigest: DIGEST,
    sourceDigest: DIGEST,
    fixtureDigest: DIGEST,
    fixtureCommitOid: document.fixture_commit_oid,
    targetDigest,
    executorImageDigest: DIGEST,
    executorConfigDigest: DIGEST,
    operations: new DurableExecutorOperationStore(storage),
    now: NOW,
  };
  async function authorize(changes: Partial<CandidateGithubDocument> = {}, role = CANDIDATE_GITHUB_ROLE as string) {
    const body = canonicalCandidateGithubBodyBytes({ ...document, ...changes });
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
    return executeCandidateGithubAuthorization(body, {
      role,
      manifest_digest: DIGEST,
      body_digest: `sha256:${Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("")}`,
      expires_at: new Date(NOW + 900_000).toISOString(),
    }, { ...authority, role }, options);
  }
  return { document, authorize, options, authority };
}

describe("candidate GitHub purpose", () => {
  it("authorizes the exact synthetic action once even when a fresh invocation retries it", async () => {
    const { authorize } = await fixture();
    const result = JSON.parse(new TextDecoder().decode(await authorize()));
    expect(result.schema).toBe(CANDIDATE_GITHUB_AUTHORIZATION_SCHEMA);
    expect(result.status).toBe("authorized");
    await expect(authorize({ invocation_id: "github-invocation-2" })).rejects.toThrow();
  });

  it("rejects production resource selection without consuming the legitimate operation", async () => {
    const { authorize } = await fixture();
    await expect(authorize({ repository: "n24q02m/skret" })).rejects.toThrow();
    expect(JSON.parse(new TextDecoder().decode(await authorize())).status).toBe("authorized");
  });

  it("rejects a signed fixture substitution and Cloudflare role reuse", async () => {
    const { authorize } = await fixture();
    await expect(authorize({ fixture_digest: OTHER_DIGEST })).rejects.toThrow();
    await expect(authorize({}, "SK-CF-NOCAS-RW")).rejects.toThrow();
    expect(JSON.parse(new TextDecoder().decode(await authorize())).status).toBe("authorized");
  });

  it("rejects authorization beyond the 15-minute envelope boundary", async () => {
    const { authorize } = await fixture();
    await expect(authorize({ deadline_at: NOW + 900_001 })).rejects.toThrow();
    await expect(authorize({ deadline_at: NOW })).rejects.toThrow();
  });
});
