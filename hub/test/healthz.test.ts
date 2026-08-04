import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

describe("healthz", () => {
  it("returns 200 {ok:true} with no auth and the shared security headers", async () => {
    const res = await SELF.fetch("https://hub.test/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(res.headers.get("Content-Security-Policy")).toContain("img-src data:");
  });

  it("returns 404 for unknown path with the shared security headers", async () => {
    const res = await SELF.fetch("https://hub.test/nope");
    expect(res.status).toBe(404);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });
});
