import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { manifestKey, putManifest, getAllManifests } from "../src/store";
import type { Manifest } from "../src/types";

function sampleManifest(ns: string, environment: string): Manifest {
  return {
    namespace: ns,
    env: environment,
    generated_at: "2026-07-03T10:00:00Z",
    keys: [
      {
        name: "DATABASE_URL",
        fingerprint: "a1b2c3d4",
        updated_at: "2026-07-01T00:00:00Z",
        targets: { "github:n24q02m/skret": { present: true, status: "in-sync" } },
      },
    ],
  };
}

describe("store", () => {
  it("keys manifests by namespace + env", () => {
    expect(manifestKey("/klprism/prod", "prod")).toBe("manifest:/klprism/prod:prod");
  });

  it("put then getAll round-trips the manifest", async () => {
    await putManifest(env.VAULT_KV, sampleManifest("/klprism/prod", "prod"));
    const all = await getAllManifests(env.VAULT_KV);
    const got = all.find((m) => m.namespace === "/klprism/prod");
    expect(got?.keys[0]?.name).toBe("DATABASE_URL");
    expect(got?.keys[0]?.fingerprint).toBe("a1b2c3d4");
  });

  it("overwrites last-writer-wins per ns+env", async () => {
    await putManifest(env.VAULT_KV, sampleManifest("/aiora/prod", "prod"));
    const updated = sampleManifest("/aiora/prod", "prod");
    updated.keys[0].fingerprint = "ffffffff";
    await putManifest(env.VAULT_KV, updated);
    const all = await getAllManifests(env.VAULT_KV);
    const got = all.filter((m) => m.namespace === "/aiora/prod");
    expect(got).toHaveLength(1);
    expect(got[0].keys[0].fingerprint).toBe("ffffffff");
  });
});
