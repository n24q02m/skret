import { describe, it, expect, vi } from "vitest";
import { Container } from "@cloudflare/containers";
import { SyncContainer } from "../src/container";
import worker from "../src/index";
import type { Env } from "../src/types";

describe("SyncContainer", () => {
  it("is a Container subclass named SyncContainer", () => {
    expect(SyncContainer.name).toBe("SyncContainer");
    // Prototype-chain check: SyncContainer extends the @cloudflare/containers
    // Container base (bound as the SYNC Durable Object). sleepAfter / no
    // defaultPort are instance fields set on construction, so they are asserted
    // via the batch lifecycle rather than an un-instantiable DO here.
    expect(SyncContainer.prototype instanceof Container).toBe(true);
  });

  it("overrides onStop for the one-shot batch lifecycle", () => {
    expect(Object.getOwnPropertyNames(SyncContainer.prototype)).toContain("onStop");
  });
});

// Build a fake env whose SYNC namespace resolves (getContainer just calls
// idFromName + get) to a stub with a `start` spy. This exercises the real
// getContainer + scheduled() wiring without instantiating a container DO.
function fakeEnv(secrets: Partial<Env>): { env: Env; start: ReturnType<typeof vi.fn> } {
  const start = vi.fn().mockResolvedValue(undefined);
  const stub = { start };
  const SYNC = {
    idFromName: () => ({}),
    get: () => stub,
  };
  return { env: { SYNC, ...secrets } as unknown as Env, start };
}

describe("scheduled()", () => {
  it("boots the sync container once, forwarding the set sync secrets as envVars", async () => {
    const secrets = {
      GITHUB_TOKEN: "gh-tok",
      CLOUDFLARE_API_TOKEN: "cf-tok",
      AWS_ACCESS_KEY_ID: "akid",
      AWS_SECRET_ACCESS_KEY: "sk",
      AWS_REGION: "ap-southeast-1",
      SKRET_HUB_TOKEN: "hub-tok",
      SKRET_HUB_URL: "https://vault.example.com",
    };
    const { env, start } = fakeEnv(secrets);

    await worker.scheduled({} as ScheduledController, env);

    expect(start).toHaveBeenCalledTimes(1);
    expect(start.mock.calls[0][0]).toEqual({ envVars: secrets });
  });

  it("omits unset sync secrets from envVars", async () => {
    const { env, start } = fakeEnv({
      SKRET_HUB_TOKEN: "hub-tok",
      SKRET_HUB_URL: "https://vault.example.com",
    });

    await worker.scheduled({} as ScheduledController, env);

    expect(start).toHaveBeenCalledTimes(1);
    const arg = start.mock.calls[0][0] as { envVars: Record<string, string> };
    expect(arg.envVars).toEqual({
      SKRET_HUB_TOKEN: "hub-tok",
      SKRET_HUB_URL: "https://vault.example.com",
    });
    expect(arg.envVars).not.toHaveProperty("GITHUB_TOKEN");
  });
});
