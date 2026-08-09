import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { handleRequest } from "../src/router";
import type { Env } from "../src/types";

// Split deliberately: the wiring ("is the binding actually on this route?")
// needs real requests, and everything else -- status, body, headers, what key
// the limiter is charged -- is asserted against a stub. Driving 40 real
// requests through SELF.fetch just to exhaust a 30/min bucket took the suite
// past its per-test timeout on this machine, and CI runners are slower.
//
// Rate-limit counters are also NOT reset between tests by vitest-pool-workers
// (workers-sdk#14392), so every real request below carries its own
// CF-Connecting-IP. Sharing one would make these order-dependent.

function login(ip: string): Promise<Response> {
  return SELF.fetch("https://hub.test/login", {
    method: "POST",
    headers: { "CF-Connecting-IP": ip, "Content-Type": "application/x-www-form-urlencoded" },
    body: "password=definitely-wrong",
  });
}

// A limiter that always refuses, plus one that always allows, so a test can
// pick the branch it wants without depending on counter state.
function envWith(success: boolean, seen?: string[]): Env {
  const limiter = {
    limit: ({ key }: { key: string }) => {
      seen?.push(key);
      return Promise.resolve({ success });
    },
  };
  return {
    LOGIN_LIMIT: limiter,
    INGEST_LIMIT: limiter,
    RELAY_PASSWORD: "test-relay-password",
    SKRET_HUB_TOKEN: "test-hub-token",
  } as unknown as Env;
}

function post(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`https://hub.test${path}`, { method: "POST", headers });
}

describe("rate limiting", () => {
  it("stops a password-guessing run, and only for that address", async () => {
    const attacker = "203.0.113.10";

    const first = await login(attacker);
    expect(first.status).toBe(401); // a real attempt still gets through

    // LOGIN_LIMIT is 5/min, so six is enough to prove guessing does not stay
    // free. Unlimited guessing against ONE shared password was the exposure.
    const statuses = [first.status];
    for (let i = 0; i < 5; i++) statuses.push((await login(attacker)).status);
    expect(statuses).toContain(429);

    // A bystander must still be able to log in, or one guessing run would lock
    // the dashboard for everyone -- a denial of service handed to the attacker.
    expect((await login("203.0.113.11")).status).toBe(401);
  });

  it("charges the limiter the client address Cloudflare stamped on the request", async () => {
    const seen: string[] = [];
    await handleRequest(post("/login", { "CF-Connecting-IP": "203.0.113.20" }), envWith(true, seen));
    expect(seen).toEqual(["203.0.113.20"]);

    // Off Cloudflare's edge there is no such header. Those requests share one
    // bucket rather than skipping the limit.
    seen.length = 0;
    await handleRequest(post("/login"), envWith(true, seen));
    expect(seen).toEqual(["no-ip"]);
  });

  it("answers a blocked login with the form and a reason, not a dead end", async () => {
    const res = await handleRequest(post("/login"), envWith(false));

    expect(res.status).toBe(429);
    const body = await res.text();
    expect(body).toContain("too many attempts");
    expect(body).toContain('name="password"');
  });

  it("answers a blocked ingest with Retry-After and the shared security headers", async () => {
    const res = await handleRequest(post("/api/manifest"), envWith(false));

    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("60");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("checks the limit before the password, so a flood costs nothing", async () => {
    // The correct password, refused anyway: proof the limiter runs first and
    // the handler never reads the body or does the constant-time compare.
    const req = new Request("https://hub.test/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "password=test-relay-password",
    });

    const res = await handleRequest(req, envWith(false));

    expect(res.status).toBe(429);
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });
});
