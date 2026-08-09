import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { handleRequest } from "../src/router";
import type { Env } from "../src/types";

describe("healthz", () => {
  it("returns 200 {ok:true} with no auth and the shared security headers", async () => {
    const res = await SELF.fetch("https://hub.test/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, kv: "ok" });
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
  // is the realistic way in -- took GET / down while the monitor stayed green.
  it("returns 503 when the KV the dashboard depends on is unreachable", async () => {
    const brokenEnv = {
      VAULT_KV: {
        get: () => Promise.reject(new Error("KV namespace 'deadbeefdeadbeef' not found")),
      },
    } as unknown as Env;

    const res = await handleRequest(new Request("https://hub.test/healthz"), brokenEnv);

    expect(res.status).toBe(503);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ ok: false, kv: "error" });
    // /healthz has no auth, so the failure must not narrate account internals
    // (namespace ids, stack frames) to anyone who curls it.
    expect(body).not.toContain("deadbeef");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("returns 404 for unknown path with the shared security headers", async () => {
    const res = await SELF.fetch("https://hub.test/nope");
    expect(res.status).toBe(404);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });
});
