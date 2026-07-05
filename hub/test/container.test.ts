import { describe, it, expect } from "vitest";
import { Container } from "@cloudflare/containers";
import { SyncContainer } from "../src/container";

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
