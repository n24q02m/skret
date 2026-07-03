import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

describe("healthz", () => {
  it("returns 200 {ok:true} with no auth", async () => {
    const res = await SELF.fetch("https://hub.test/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("returns 404 for unknown path", async () => {
    const res = await SELF.fetch("https://hub.test/nope");
    expect(res.status).toBe(404);
  });
});
