import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { handleRequest } from "../src/router";
import { LOGIN_ATTEMPTS, ATTEMPTS_KEY, type LoginGate } from "../src/gate";
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
    // The real Durable Object namespace from miniflare, not a stub. Stubbing
    // the thing that now enforces the limit would only assert that a stub got
    // called -- and a stub is exactly what the binding turned out to behave
    // like in production.
    LOGIN_GATE: env.LOGIN_GATE,
    RELAY_PASSWORD: "test-relay-password",
    SKRET_HUB_TOKEN: "test-hub-token",
  } as unknown as Env;
}

function loginReq(ip: string): Request {
  return new Request("https://hub.test/login", {
    method: "POST",
    headers: { "CF-Connecting-IP": ip, "Content-Type": "application/x-www-form-urlencoded" },
    body: "password=definitely-wrong",
  });
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

  // The regression test for what #660 shipped. envWith(true) is a limiter that
  // never refuses -- which is what the Rate Limiting binding does in
  // production once each guess arrives on its own connection. Measured against
  // the deployed Worker on 2026-08-09: 15 wrong passwords that way, all served
  // by one location, drew zero 429s. The suite missed it because SELF.fetch
  // runs every request through a single miniflare isolate, so the binding's
  // per-isolate counter always accumulated there. Run this against the code
  // before LoginGate and every status is 401.
  it("holds the limit when the cheap limiter never refuses", async () => {
    const permissive = envWith(true);
    const attacker = "203.0.113.30";

    const statuses: number[] = [];
    for (let i = 0; i < LOGIN_ATTEMPTS + 1; i++) {
      statuses.push((await handleRequest(loginReq(attacker), permissive)).status);
    }

    expect(statuses.slice(0, LOGIN_ATTEMPTS)).toEqual(Array(LOGIN_ATTEMPTS).fill(401));
    expect(statuses[LOGIN_ATTEMPTS]).toBe(429);

    // One counter per address, not one counter. Otherwise the fix would hand
    // the attacker a way to lock the owner out.
    expect((await handleRequest(loginReq("203.0.113.31"), permissive)).status).toBe(401);
  });

  // A refused attempt must not itself be recorded. If it were, a client that
  // keeps hammering would keep pushing its own window forward and never
  // recover -- turning a rate limit into a permanent lockout that an attacker
  // can inflict on the owner's address just by never stopping.
  it("does not extend the window with attempts it already refused", async () => {
    const stub = env.LOGIN_GATE.get(env.LOGIN_GATE.idFromName("203.0.113.40"));

    await runInDurableObject(stub, async (gate: LoginGate, state) => {
      const verdicts: boolean[] = [];
      for (let i = 0; i < LOGIN_ATTEMPTS + 3; i++) verdicts.push(await gate.attempt());

      expect(verdicts.filter(Boolean)).toHaveLength(LOGIN_ATTEMPTS);
      expect(await state.storage.get<number[]>(ATTEMPTS_KEY)).toHaveLength(LOGIN_ATTEMPTS);
    });
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
