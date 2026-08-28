import { describe, expect, it } from "vitest";
import { mintSession, SESSION_TTL } from "../src/auth";
import { handleRequest } from "../src/router";
import { handleExecutorEnvelope, MAX_EXECUTOR_ENVELOPE_BYTES } from "../src/operator-executor-proxy";
import type { Env } from "../src/types";

const RELAY_PASSWORD = "test-relay-password";
const HUB_TOKEN = "public-hub-token";
const EXECUTOR_ORIGIN = "https://executor.internal";

interface FakeExecutor {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

function fakeExecutor(response: Response | ((request: Request) => Response | Promise<Response>)) {
  const requests: Request[] = [];
  const executor: FakeExecutor = {
    async fetch(input, init) {
      const request = input instanceof Request ? input : new Request(input, init);
      requests.push(request);
      return typeof response === "function" ? response(request) : response.clone();
    },
  };
  return { executor, requests };
}

async function sessionCookie() {
  return `session=${await mintSession(RELAY_PASSWORD, SESSION_TTL)}`;
}

function env(executor?: FakeExecutor): Env {
  return {
    RELAY_PASSWORD,
    SKRET_HUB_TOKEN: HUB_TOKEN,
    ...(executor ? { EXECUTOR: executor } : {}),
  } as unknown as Env;
}

describe("authenticated executor envelope proxy", () => {
  it("rejects non-POST requests when called directly", async () => {
    const { executor, requests } = fakeExecutor(new Response("should not run", { status: 200 }));
    const response = await handleExecutorEnvelope(new Request(`${EXECUTOR_ORIGIN}/operator/executor-envelope`), env(executor));

    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("POST");
    expect(requests).toHaveLength(0);
    expect(await response.text()).toBe("method not allowed");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("requires a valid session before touching the executor", async () => {
    const { executor, requests } = fakeExecutor(new Response("should not run", { status: 200 }));
    const request = new Request(`${EXECUTOR_ORIGIN}/operator/executor-envelope`, {
      method: "POST",
      headers: { Authorization: `Bearer ${HUB_TOKEN}` },
      body: "body must not be forwarded",
    });

    const response = await handleExecutorEnvelope(request, env(executor));

    expect(response.status).toBe(401);
    expect(await response.text()).toBe("unauthorized");
    expect(requests).toHaveLength(0);
  });

  it("fails closed when the private executor binding is absent", async () => {
    const request = new Request(`${EXECUTOR_ORIGIN}/operator/executor-envelope`, {
      method: "POST",
      headers: { Cookie: await sessionCookie() },
      body: "signed envelope bytes",
    });

    const response = await handleRequest(request, env());

    expect(response.status).toBe(503);
    expect(await response.text()).toBe("executor unavailable");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("forwards exact bytes to the fixed path with only safe derived headers", async () => {
    const body = new Uint8Array([0, 1, 2, 255, 10, 13, 42]);
    const upstream = new Response("accepted", { status: 202, headers: { "Content-Type": "text/plain" } });
    const { executor, requests } = fakeExecutor(upstream);
    const cookie = await sessionCookie();
    const request = new Request(`${EXECUTOR_ORIGIN}/operator/executor-envelope?ignored=yes`, {
      method: "POST",
      headers: {
        Cookie: cookie,
        Authorization: "Bearer public-token-must-not-forward",
        "Content-Type": "application/json",
        "X-Evil": "must-not-forward",
      },
      body,
    });

    const response = await handleRequest(request, env(executor));

    expect(response.status).toBe(202);
    expect(await response.text()).toBe("accepted");
    expect(requests).toHaveLength(1);
    const forwarded = requests[0];
    expect(new URL(forwarded.url).origin).toBe(EXECUTOR_ORIGIN);
    expect(new URL(forwarded.url).pathname).toBe("/operator/executor-envelope");
    expect(new URL(forwarded.url).search).toBe("");
    expect(forwarded.method).toBe("POST");
    expect(new Uint8Array(await forwarded.arrayBuffer())).toEqual(body);
    expect(forwarded.headers.get("Content-Type")).toBe("application/json");
    expect(forwarded.headers.get("X-Skret-Body-Digest")).toBe(
      "sha256:805a18cabc25ee738955ea6b659707a971426c3a8cde3ef2b0ab0ef48da7ebc5",
    );
    expect(forwarded.headers.get("X-Skret-Caller-Context")).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(forwarded.headers.get("X-Skret-Caller-Context")).not.toBe(cookie);
    expect(forwarded.headers.get("Cookie")).toBeNull();
    expect(forwarded.headers.get("Authorization")).toBeNull();
    expect(forwarded.headers.get("X-Evil")).toBeNull();
    expect(response.headers.get("Set-Cookie")).toBeNull();
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("rejects an oversized body before invoking the executor", async () => {
    const { executor, requests } = fakeExecutor(new Response("should not run", { status: 200 }));
    const oversized = new Uint8Array(MAX_EXECUTOR_ENVELOPE_BYTES + 1);
    const request = new Request(`${EXECUTOR_ORIGIN}/operator/executor-envelope`, {
      method: "POST",
      headers: { Cookie: await sessionCookie() },
      body: oversized,
    });

    const response = await handleExecutorEnvelope(request, env(executor));

    expect(response.status).toBe(413);
    expect(await response.text()).toBe("payload too large");
    expect(requests).toHaveLength(0);
  });

  it("passes through executor status and body without leaking upstream headers", async () => {
    const { executor } = fakeExecutor(
      new Response('{"error":"executor rejected"}', {
        status: 422,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": "executor-secret=do-not-forward",
          "X-Internal-Trace": "private-trace",
        },
      }),
    );
    const request = new Request(`${EXECUTOR_ORIGIN}/operator/executor-envelope`, {
      method: "POST",
      headers: { Cookie: await sessionCookie() },
      body: "signed envelope bytes",
    });

    const response = await handleExecutorEnvelope(request, env(executor));

    expect(response.status).toBe(422);
    expect(await response.text()).toBe('{"error":"executor rejected"}');
    expect(response.headers.get("Content-Type")).toBe("application/json");
    expect(response.headers.get("Set-Cookie")).toBeNull();
    expect(response.headers.get("X-Internal-Trace")).toBeNull();
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });
});
