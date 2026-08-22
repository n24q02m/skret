import { SELF } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import { handleRequest } from "../src/router";
import type { Env } from "../src/types";

describe("healthz", () => {
  it("returns 200 with KV status, coarse sync freshness, and shared security headers", async () => {
    const env = {
      VAULT_KV: { get: vi.fn(async () => null) },
      SYNC: {
        idFromName: () => ({}),
        get: () => ({
          getSyncHealth: vi.fn(async () => ({
            active: false,
            last_success_at: null,
            age_seconds: null,
          })),
        }),
      },
    } as unknown as Env;
    const res = await handleRequest(new Request("https://hub.test/healthz"), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      ok: true,
      kv: "ok",
      sync: { active: false, last_success_at: null, age_seconds: null },
    });
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(res.headers.get("Content-Security-Policy")).toContain("img-src data:");
    // The two headers #597 was opened to add. Router sets them; nothing asserted
    // them, so deleting either one from SECURITY_HEADERS passed CI.
    expect(res.headers.get("Strict-Transport-Security")).toBe("max-age=31536000; includeSubDomains");
    expect(res.headers.get("X-Frame-Options")).toBe("DENY");
  });

  // The point of the route. With a static {ok:true} this test could not exist,
  // and an unreachable VAULT_KV -- a wrong namespace id in wrangler.deploy.jsonc
  it("returns 503 when the KV the dashboard depends on is unreachable", async () => {
    const brokenEnv = {
      VAULT_KV: {
        get: () => Promise.reject(new Error("KV namespace 'deadbeefdeadbeef' not found")),
      },
    } as unknown as Env;

    const res = await handleRequest(new Request("https://hub.test/healthz"), brokenEnv);

    expect(res.status).toBe(503);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ ok: false, kv: "error", sync: null });
    // /healthz has no auth, so the failure must not narrate account internals
    // (namespace ids, stack frames) to anyone who curls it.
    expect(body).not.toContain("deadbeef");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("degrades a sync RPC failure to null without exposing internal details", async () => {
    const rpcError = new Error("private run id and provider failure details");
    const brokenSyncEnv = {
      VAULT_KV: { get: vi.fn(async () => null) },
      SYNC: {
        idFromName: () => ({}),
        get: () => ({
          getSyncHealth: vi.fn(async () => {
            throw rpcError;
          }),
        }),
      },
    } as unknown as Env;

    const res = await handleRequest(new Request("https://hub.test/healthz"), brokenSyncEnv);

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ ok: true, kv: "ok", sync: null });
    expect(body).not.toContain("private run id");
    expect(body).not.toContain("provider failure details");
  });

  it("keeps run ids and detailed metadata out of the public health projection", async () => {
    const detailedHealth = {
      active: true,
      last_success_at: "2026-08-22T00:00:10.000Z",
      age_seconds: 12,
      runId: "private-run-id",
      targetCount: 7,
      configFingerprint: "private-config-fingerprint",
      failureDetails: "private-failure-details",
      secret: "private-secret-value",
    };
    const envWithDetailedHealth = {
      VAULT_KV: { get: vi.fn(async () => null) },
      SYNC: {
        idFromName: () => ({}),
        get: () => ({
          getSyncHealth: vi.fn(async () => detailedHealth),
        }),
      },
    } as unknown as Env;

    const res = await handleRequest(
      new Request("https://hub.test/healthz"),
      envWithDetailedHealth,
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({
      ok: true,
      kv: "ok",
      sync: {
        active: true,
        last_success_at: "2026-08-22T00:00:10.000Z",
        age_seconds: 12,
      },
    });
    expect(body).not.toContain("private-run-id");
    expect(body).not.toContain("private-config-fingerprint");
    expect(body).not.toContain("private-failure-details");
    expect(body).not.toContain("private-secret-value");
  });

  it("returns 404 for unknown path with the shared security headers", async () => {
    const res = await SELF.fetch("https://hub.test/nope");
    expect(res.status).toBe(404);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });
});
