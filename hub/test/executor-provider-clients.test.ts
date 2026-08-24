import { describe, expect, it } from "vitest";
import {
  CloudflareTargetClient,
  GitHubTargetClient,
  canonicalCloudflareTarget,
  canonicalGitHubTarget,
  canonicalTargetSet,
  createTargetOperation,
  type CloudflareTargetTransport,
  type GitHubTargetTransport,
  type ProviderWriteResponse,
  type SealedBox,
} from "../src/executor-provider-clients";

const VALUE = new TextEncoder().encode("synthetic-target-value");
const CONTEXT_DIGEST = `sha256:${"b".repeat(64)}`;
const CF_ACCOUNT = "a".repeat(32);

function applied(operationId: string, targetIdentity: string): ProviderWriteResponse {
  return { status: "applied", operationId, targetIdentity };
}

class FakeSealedBox implements SealedBox {
  readonly calls: Array<{ publicKey: Uint8Array; plaintext: Uint8Array }> = [];

  async seal(publicKey: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    this.calls.push({ publicKey: publicKey.slice(), plaintext: plaintext.slice() });
    return Uint8Array.from(plaintext, (byte) => byte ^ 0xa5);
  }
}

class FakeGitHubTransport implements GitHubTargetTransport {
  readonly calls: Array<{ operation: string; input: Record<string, unknown> }> = [];
  response: ProviderWriteResponse | null | undefined = null;
  readonly responseByOperation = new Map<string, ProviderWriteResponse | null | undefined>();
  publicKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  keyId = "fixture-key-id";
  delayFirst = false;
  throwWrite = false;
  private pending = false;

  async getRepositoryPublicKey(input: Parameters<GitHubTargetTransport["getRepositoryPublicKey"]>[0]) {
    this.calls.push({ operation: "public-key", input: { ...input } });
    return { keyId: this.keyId, publicKey: this.publicKey.slice() };
  }

  async upsertRepositorySecret(input: Parameters<GitHubTargetTransport["upsertRepositorySecret"]>[0]) {
    this.calls.push({ operation: "upsert", input: { ...input, sealedValue: input.sealedValue.slice() } });
    if (this.throwWrite) throw new Error("synthetic dropped response");
    if (this.delayFirst && !this.pending) {
      this.pending = true;
      await Promise.resolve();
      await new Promise<void>((resolve) => queueMicrotask(resolve));
    }
    return this.responseByOperation.has(input.operationId) ? this.responseByOperation.get(input.operationId) : this.response;
  }
}

class FakeCloudflareTransport implements CloudflareTargetTransport {
  readonly calls: Array<{ operation: string; input: Record<string, unknown> }> = [];
  response: ProviderWriteResponse | null | undefined = null;
  throwWrite = false;

  async writeWorkerSecret(input: Parameters<CloudflareTargetTransport["writeWorkerSecret"]>[0]) {
    this.calls.push({ operation: "worker-write", input: { ...input, value: input.value.slice() } });
    if (this.throwWrite) throw new Error("synthetic dropped response");
    return this.response;
  }

  async writePagesSecret(input: Parameters<CloudflareTargetTransport["writePagesSecret"]>[0]) {
    this.calls.push({ operation: "pages-write", input: { ...input, value: input.value.slice() } });
    if (this.throwWrite) throw new Error("synthetic dropped response");
    return this.response;
  }
}

describe("canonical executor target clients", () => {
  it("canonicalizes GitHub and Cloudflare identities with explicit capability rows", async () => {
    const github = canonicalGitHubTarget({
      owner: "Fixture",
      repository: "Repo",
      secretName: "token",
      capability: "owner_risk_gate",
    });
    const worker = canonicalCloudflareTarget({
      accountId: CF_ACCOUNT.toUpperCase(),
      resourceKind: "worker",
      resourceName: "Worker-Name",
      secretName: "token",
      environment: "production",
      capability: "owner_risk_gate",
    });
    const pages = canonicalCloudflareTarget({
      accountId: CF_ACCOUNT,
      resourceKind: "pages",
      resourceName: "Worker-Name",
      secretName: "token",
      environment: "production",
      capability: "owner_risk_gate",
    });

    expect(github.canonical).toBe("github|fixture/repo|production|TOKEN");
    expect(github.capability).toBe("owner_risk_gate");
    expect(worker.canonical).toBe(`cloudflare|${CF_ACCOUNT}|worker|worker-name|production|TOKEN`);
    expect(pages.canonical).toBe(`cloudflare|${CF_ACCOUNT}|pages|worker-name|production|TOKEN`);

    const setA = await canonicalTargetSet([github, worker, pages]);
    const setB = await canonicalTargetSet([pages, github, worker]);
    expect(setA).toEqual(setB);
    expect(setA.digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });

  it("rejects capability, identity, and canonical collision ambiguity", async () => {
    expect(() =>
      canonicalGitHubTarget({
        owner: "fixture",
        repository: "repo",
        secretName: "TOKEN",
        capability: "unknown" as never,
      }),
    ).toThrow("invalid target capability");
    expect(() =>
      canonicalCloudflareTarget({
        accountId: "fixture",
        resourceKind: "worker",
        resourceName: "a/b",
        secretName: "TOKEN",
        capability: "owner_risk_gate",
      }),
    ).toThrow("invalid target identity");

    const first = canonicalGitHubTarget({ owner: "fixture", repository: "repo", secretName: "TOKEN" });
    const second = canonicalGitHubTarget({ owner: "FIXTURE", repository: "REPO", secretName: "token" });
    await expect(canonicalTargetSet([first, second])).rejects.toThrow("target identity collision");
  });

  it("requires immutable operation identity and sends one sealed-box GitHub upsert", async () => {
    const target = canonicalGitHubTarget({ owner: "fixture", repository: "repo", secretName: "TOKEN" });
    const operation = createTargetOperation({
      operationId: "op-github-1",
      generation: "generation-1",
      target,
      contextDigest: CONTEXT_DIGEST,
    });
    const transport = new FakeGitHubTransport();
    transport.response = applied(operation.operationId, target.canonical);
    const sealedBox = new FakeSealedBox();
    const client = new GitHubTargetClient(transport, sealedBox);
    const callerValue = VALUE.slice();
    const result = await client.upsertSecret({ operation, value: callerValue });

    expect(result.status).toBe("applied");
    expect(transport.calls.map(({ operation: name }) => name)).toEqual(["public-key", "upsert"]);
    expect(transport.calls[1]?.input).toMatchObject({
      owner: "fixture",
      repository: "repo",
      secretName: "TOKEN",
      operationId: "op-github-1",
      keyId: "fixture-key-id",
    });
    expect(sealedBox.calls).toHaveLength(1);
    expect(sealedBox.calls[0]?.plaintext).toEqual(VALUE);
    expect(JSON.stringify(transport.calls)).not.toContain("synthetic-target-value");
    expect(callerValue.every((byte) => byte === 0)).toBe(true);
  });

  it("does not retry an opaque dropped GitHub response and moves to reconciliation", async () => {
    const target = canonicalGitHubTarget({ owner: "fixture", repository: "repo", secretName: "TOKEN" });
    const operation = createTargetOperation({
      operationId: "op-github-dropped",
      generation: "generation-1",
      target,
      contextDigest: CONTEXT_DIGEST,
    });
    const transport = new FakeGitHubTransport();
    transport.response = undefined;
    const client = new GitHubTargetClient(transport, new FakeSealedBox());
    const result = await client.upsertSecret({ operation, value: VALUE.slice() });

    expect(result.status).toBe("needs_reconciliation");
    expect(transport.calls.filter(({ operation: name }) => name === "upsert")).toHaveLength(1);
    transport.throwWrite = true;
    const thrownOperation = createTargetOperation({
      operationId: "op-github-thrown",
      generation: "generation-1",
      target,
      contextDigest: CONTEXT_DIGEST,
    });
    await expect(client.upsertSecret({ operation: thrownOperation, value: VALUE.slice() })).resolves.toMatchObject({
      status: "needs_reconciliation",
    });
    expect(transport.calls.filter(({ operation: name }) => name === "upsert")).toHaveLength(2);
  });

  it("rejects unknown GitHub responses and serializes concurrent writes deterministically", async () => {
    const target = canonicalGitHubTarget({ owner: "fixture", repository: "repo", secretName: "TOKEN" });
    const transport = new FakeGitHubTransport();
    const client = new GitHubTargetClient(transport, new FakeSealedBox());
    const first = createTargetOperation({ operationId: "op-1", generation: "g", target, contextDigest: CONTEXT_DIGEST });
    const second = createTargetOperation({ operationId: "op-2", generation: "g", target, contextDigest: CONTEXT_DIGEST });
    transport.response = { status: "mystery" } as never;
    await expect(client.upsertSecret({ operation: first, value: VALUE.slice() })).rejects.toThrow("invalid provider response");
    transport.response = applied(first.operationId, target.canonical);
    transport.responseByOperation.set(second.operationId, applied(second.operationId, target.canonical));
    const results = await Promise.all([
      client.upsertSecret({ operation: first, value: VALUE.slice() }),
      client.upsertSecret({ operation: second, value: VALUE.slice() }),
    ]);
    expect(results[0]?.status).toBe("applied");
    expect(results[1]?.status).toBe("applied");
    expect(transport.calls.filter(({ operation: name }) => name === "upsert")).toHaveLength(3);
  });
  it("rejects unsupported CAS claims before any provider write", async () => {
    const target = canonicalGitHubTarget({
      owner: "fixture",
      repository: "repo",
      secretName: "TOKEN",
      capability: "native_cas",
    });
    const operation = createTargetOperation({
      operationId: "op-invalid-cas",
      generation: "g",
      target,
      contextDigest: CONTEXT_DIGEST,
    });
    const transport = new FakeGitHubTransport();
    const client = new GitHubTargetClient(transport, new FakeSealedBox());
    await expect(client.upsertSecret({ operation, value: VALUE.slice() })).rejects.toThrow(
      "invalid target capability",
    );
    expect(transport.calls).toHaveLength(0);
  });


  it("writes Cloudflare Worker and Pages targets with one immutable operation each", async () => {
    const transport = new FakeCloudflareTransport();
    const client = new CloudflareTargetClient(transport);
    const worker = canonicalCloudflareTarget({
      accountId: CF_ACCOUNT,
      resourceKind: "worker",
      resourceName: "fixture-worker",
      secretName: "TOKEN",
      capability: "owner_risk_gate",
    });
    const pages = canonicalCloudflareTarget({
      accountId: CF_ACCOUNT,
      resourceKind: "pages",
      resourceName: "fixture-pages",
      secretName: "TOKEN",
      capability: "owner_risk_gate",
    });
    const workerOperation = createTargetOperation({ operationId: "op-worker", generation: "g", target: worker, contextDigest: CONTEXT_DIGEST });
    const pagesOperation = createTargetOperation({ operationId: "op-pages", generation: "g", target: pages, contextDigest: CONTEXT_DIGEST });
    transport.response = applied(workerOperation.operationId, worker.canonical);
    await expect(client.upsertSecret({ operation: workerOperation, value: VALUE.slice() })).resolves.toMatchObject({ status: "applied" });
    transport.response = applied(pagesOperation.operationId, pages.canonical);
    await expect(client.upsertSecret({ operation: pagesOperation, value: VALUE.slice() })).resolves.toMatchObject({ status: "applied" });
    expect(transport.calls.map(({ operation: name }) => name)).toEqual(["worker-write", "pages-write"]);
  });

  it("maps a dropped Cloudflare response to reconciliation without a second write", async () => {
    const target = canonicalCloudflareTarget({
      accountId: CF_ACCOUNT,
      resourceKind: "worker",
      resourceName: "fixture-worker",
      secretName: "TOKEN",
      capability: "owner_risk_gate",
    });
    const operation = createTargetOperation({ operationId: "op-cf-dropped", generation: "g", target, contextDigest: CONTEXT_DIGEST });
    const transport = new FakeCloudflareTransport();
    transport.response = null;
    const client = new CloudflareTargetClient(transport);
    const result = await client.upsertSecret({ operation, value: VALUE.slice() });
    expect(result.status).toBe("needs_reconciliation");
    expect(transport.calls).toHaveLength(1);
    transport.throwWrite = true;
    const thrownOperation = createTargetOperation({
      operationId: "op-cf-thrown",
      generation: "g",
      target,
      contextDigest: CONTEXT_DIGEST,
    });
    await expect(client.upsertSecret({ operation: thrownOperation, value: VALUE.slice() })).resolves.toMatchObject({
      status: "needs_reconciliation",
    });
    expect(transport.calls).toHaveLength(2);
  });
});
