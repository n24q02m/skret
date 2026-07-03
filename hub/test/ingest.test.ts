import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { validateManifest } from "../src/ingest";

const good = {
  namespace: "/klprism/prod",
  env: "prod",
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

function post(body: unknown, auth?: string): Promise<Response> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (auth) headers.Authorization = auth;
  return SELF.fetch("https://hub.test/api/manifest", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

describe("validateManifest", () => {
  it("accepts a well-formed manifest", () => {
    expect(validateManifest(good).ok).toBe(true);
  });
  it("rejects a missing required field", () => {
    const bad = { ...good, namespace: undefined };
    expect(validateManifest(bad).ok).toBe(false);
  });
  it("rejects a bad status enum", () => {
    const bad = structuredClone(good);
    bad.keys[0].targets["github:n24q02m/skret"].status = "weird" as never;
    expect(validateManifest(bad).ok).toBe(false);
  });
  it("rejects a value-like field on a key (defense-in-depth)", () => {
    const bad = structuredClone(good) as Record<string, any>;
    bad.keys[0].value = "super-secret";
    expect(validateManifest(bad).ok).toBe(false);
  });
  it("rejects a value-like field on a target", () => {
    const bad = structuredClone(good) as Record<string, any>;
    bad.keys[0].targets["github:n24q02m/skret"].secret = "leak";
    expect(validateManifest(bad).ok).toBe(false);
  });
});

describe("ingest route", () => {
  it("401 with no bearer", async () => {
    expect((await post(good)).status).toBe(401);
  });
  it("401 with wrong bearer", async () => {
    expect((await post(good, "Bearer wrong")).status).toBe(401);
  });
  it("200 with right bearer and stores the manifest", async () => {
    const res = await post(good, "Bearer test-hub-token");
    expect(res.status).toBe(200);
    const raw = await env.VAULT_KV.get("manifest:/klprism/prod:prod");
    expect(raw).not.toBeNull();
  });
  it("400 with value-like field, does NOT store", async () => {
    const bad = structuredClone(good) as Record<string, any>;
    bad.namespace = "/leaky/prod";
    bad.keys[0].value = "leak";
    const res = await post(bad, "Bearer test-hub-token");
    expect(res.status).toBe(400);
    expect(await env.VAULT_KV.get("manifest:/leaky/prod:prod")).toBeNull();
  });
});
