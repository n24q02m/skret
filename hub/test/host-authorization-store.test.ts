import { describe, expect, it } from "vitest";
import {
  HostAuthorizationStore,
  type HostAuthorizationMapping,
  type HostAuthorizationStorage,
  createSignedHostAuthorizationGeneration,
} from "../src/host-authorization-store";

const NOW = 1_700_000_000_000;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;

class MemoryStorage implements HostAuthorizationStorage {
  private readonly values = new Map<string, unknown>();
  private tail = Promise.resolve();

  async get<T>(key: string): Promise<T | undefined> {
    return this.values.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  transaction<T>(closure: (transaction: HostAuthorizationStorage) => Promise<T>): Promise<T> {
    const run = this.tail.then(() => closure(this));
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

function mapping(overrides: Partial<HostAuthorizationMapping> = {}): HostAuthorizationMapping {
  return {
    verified_jwt_hash: HASH_A,
    mapped_instance: "ocid1.instance.oc1..host-a",
    role: "sync-reader",
    executor_audience: "skret-executor",
    launch_namespace: "host-a",
    ssm_allowlist: ["/skret/host-a/state"],
    git_allowlist: ["refs/heads/main"],
    ghcr_allowlist: ["ghcr.io/example/skret"],
    ...overrides,
  };
}

function generation(
  generationNumber: number,
  overrides: Partial<Parameters<typeof createSignedHostAuthorizationGeneration>[0]> = {},
) {
  return {
    version: 1 as const,
    generation: generationNumber,
    previous_head_hash: generationNumber === 1 ? null : `sha256:${"c".repeat(64)}`,
    issuer: "security-executor",
    issued_at: NOW - 100,
    expires_at: NOW + 60_000,
    mappings: [mapping()],
    ...overrides,
  };
}

async function keyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
}

async function publicKeyBytes(publicKey: CryptoKey): Promise<Uint8Array> {
  const exported = await crypto.subtle.exportKey("raw", publicKey);
  if (!(exported instanceof ArrayBuffer)) throw new Error("expected raw public key");
  return new Uint8Array(exported);
}

describe("HostAuthorizationStore", () => {
  it("activates a canonical signed generation and returns only metadata", async () => {
    const { publicKey, privateKey } = (await keyPair()) as CryptoKeyPair;
    const store = new HostAuthorizationStore(new MemoryStorage(), await publicKeyBytes(publicKey));
    const signed = await createSignedHostAuthorizationGeneration(generation(1), privateKey);

    const result = await store.activate(signed, { expectedHeadHash: null, now: NOW });

    expect(result.status).toBe("activated");
    if (result.status === "activated") {
      expect(result.generation).toBe(1);
      expect(result.head_hash).toMatch(/^sha256:[0-9a-f]{64}$/u);
    }
    expect(JSON.stringify(result)).not.toContain("secret");
    const lookup = await store.lookup(
      { mapped_instance: "ocid1.instance.oc1..host-a", verified_jwt_hash: HASH_A },
      { expectedHeadHash: result.status === "activated" ? result.head_hash : undefined, now: NOW },
    );
    expect(lookup.status).toBe("authorized");
    if (lookup.status === "authorized") expect(lookup.mapping).toEqual(mapping());
    await expect(store.readHead()).resolves.toMatchObject({
      status: "head",
      head: { generation: 1 },
    });
  });

  it("rejects noncanonical JSON and a tampered signature", async () => {
    const { publicKey, privateKey } = (await keyPair()) as CryptoKeyPair;
    const store = new HostAuthorizationStore(new MemoryStorage(), await publicKeyBytes(publicKey));
    const signed = await createSignedHostAuthorizationGeneration(generation(1), privateKey);

    expect((await store.activate(` ${signed}`, { expectedHeadHash: null, now: NOW })).status).toBe("noncanonical");
    const parsed = JSON.parse(signed) as Record<string, unknown>;
    parsed.issuer = "other-issuer";
    expect((await store.activate(JSON.stringify(parsed), { expectedHeadHash: null, now: NOW })).status).toBe("signature_invalid");
  });

  it("rejects duplicate mapping keys and expired generations", async () => {
    const { publicKey, privateKey } = (await keyPair()) as CryptoKeyPair;
    const store = new HostAuthorizationStore(new MemoryStorage(), await publicKeyBytes(publicKey));
    const duplicate = generation(1, { mappings: [mapping(), mapping()] });
    await expect(createSignedHostAuthorizationGeneration(duplicate, privateKey)).rejects.toThrow();
    const expired = await createSignedHostAuthorizationGeneration(
      generation(1, { expires_at: NOW - 1 }),
      privateKey,
    );
    expect((await store.activate(expired, { expectedHeadHash: null, now: NOW })).status).toBe("expired");
  });

  it("enforces CAS, monotonic generations, and replay rejection", async () => {
    const { publicKey, privateKey } = (await keyPair()) as CryptoKeyPair;
    const store = new HostAuthorizationStore(new MemoryStorage(), await publicKeyBytes(publicKey));
    const first = await createSignedHostAuthorizationGeneration(generation(1), privateKey);
    const activated = await store.activate(first, { expectedHeadHash: null, now: NOW });
    expect(activated.status).toBe("activated");
    if (activated.status !== "activated") return;
    expect((await store.activate(first, { expectedHeadHash: activated.head_hash, now: NOW })).status).toBe("replay");
    expect((await store.activate(first, { expectedHeadHash: null, now: NOW })).status).toBe("head_mismatch");

    const downgrade = await createSignedHostAuthorizationGeneration(
      generation(1, { issuer: "different-signed-generation" }),
      privateKey,
    );
    expect((await store.activate(downgrade, { expectedHeadHash: activated.head_hash, now: NOW })).status).toBe("stale");

    const next = await createSignedHostAuthorizationGeneration(
      generation(2, { previous_head_hash: `sha256:${"d".repeat(64)}` }),
      privateKey,
    );
    expect((await store.activate(next, { expectedHeadHash: activated.head_hash, now: NOW })).status).toBe("stale");
    const validNext = await createSignedHostAuthorizationGeneration(
      generation(2, { previous_head_hash: activated.head_hash }),
      privateKey,
    );
    expect((await store.activate(validNext, { expectedHeadHash: activated.head_hash, now: NOW })).status).toBe(
      "activated",
    );
  });

  it("denies caller roles and cross-instance lookups", async () => {
    const { publicKey, privateKey } = (await keyPair()) as CryptoKeyPair;
    const store = new HostAuthorizationStore(new MemoryStorage(), await publicKeyBytes(publicKey));
    const signed = await createSignedHostAuthorizationGeneration(generation(1), privateKey);
    const activated = await store.activate(signed, { expectedHeadHash: null, now: NOW });
    expect(activated.status).toBe("activated");

    expect(
      (await store.lookup({ verified_jwt_hash: HASH_A, mapped_instance: "ocid1.instance.oc1..host-a", caller_role: "admin" }, { now: NOW })).status,
    ).toBe("caller_role_denied");
    expect(
      (
        await store.lookup(
          { verified_jwt_hash: HASH_A, mapped_instance: "ocid1.instance.oc1..host-a", role: "admin" } as never,
          { now: NOW },
        )
      ).status,
    ).toBe("invalid_request");
    expect(
      (await store.lookup({ verified_jwt_hash: HASH_A, mapped_instance: "ocid1.instance.oc1..host-b" }, { now: NOW })).status,
    ).toBe("cross_instance");
    expect(
      (await store.lookup({ verified_jwt_hash: HASH_B, mapped_instance: "ocid1.instance.oc1..host-b" }, { now: NOW })).status,
    ).toBe("not_found");
  });

  it("rejects expired lookup records and preserves transactional duplicate-call safety", async () => {
    const { publicKey, privateKey } = (await keyPair()) as CryptoKeyPair;
    const storage = new MemoryStorage();
    const store = new HostAuthorizationStore(storage, await publicKeyBytes(publicKey));
    const signed = await createSignedHostAuthorizationGeneration(generation(1), privateKey);
    const results = await Promise.all([
      store.activate(signed, { expectedHeadHash: null, now: NOW }),
      store.activate(signed, { expectedHeadHash: null, now: NOW }),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual(["activated", "head_mismatch"]);

    const lookup = await store.lookup(
      { verified_jwt_hash: HASH_A, mapped_instance: "ocid1.instance.oc1..host-a" },
      { now: NOW + 60_000 },
    );
    expect(lookup.status).toBe("expired");
  });
});
