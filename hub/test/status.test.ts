import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

const good = {
  namespace: "/klprism/prod",
  env: "prod",
  generated_at: "2026-09-19T10:00:00Z",
  keys: [
    {
      name: "DB_PASSWORD",
      fingerprint: "a1b2c3d4",
      updated_at: "2026-09-01T00:00:00Z",
      targets: { "github:n24q02m/skret": { present: true, status: "present" } },
    },
    {
      name: "API_TOKEN",
      fingerprint: "e5f6a7b8",
      updated_at: "2026-09-02T00:00:00Z",
      targets: {},
    },
  ],
};

async function pushManifest(body: unknown): Promise<Response> {
  return SELF.fetch("https://hub.test/api/manifest", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer test-hub-token",
    },
    body: JSON.stringify(body),
  });
}

function get(path: string, auth?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (auth) headers.Authorization = auth;
  return SELF.fetch(`https://hub.test${path}`, { headers });
}

describe("status + namespaces auth", () => {
  it("401 on /api/status with no bearer", async () => {
    expect((await get("/api/status")).status).toBe(401);
  });
  it("401 on /api/status with wrong bearer", async () => {
    expect((await get("/api/status", "Bearer wrong")).status).toBe(401);
  });
  it("401 on /api/namespaces with no bearer", async () => {
    expect((await get("/api/namespaces")).status).toBe(401);
  });
  it("401 on /api/namespaces with wrong bearer", async () => {
    expect((await get("/api/namespaces", "Bearer wrong")).status).toBe(401);
  });
});

describe("status + namespaces shape", () => {
  it("returns empty stats before anything is pushed", async () => {
    // Runs first: storage isolation in the test pool is per-file, so this
    // must precede every push in this file to observe an empty KV.
    const st = await (await get("/api/status", "Bearer test-hub-token")).json();
    expect(st).toEqual({
      ok: true,
      namespace_count: 0,
      key_count: 0,
      namespaces: [],
    });
  });

  it("reports pushed manifests with counts", async () => {
    expect((await pushManifest(good)).status).toBe(200);

    type StatusBody = {
      ok: boolean;
      namespace_count: number;
      key_count: number;
      namespaces: Array<{
        namespace: string;
        env: string;
        generated_at: string;
        key_count: number;
      }>;
    };
    const st = (await (
      await get("/api/status", "Bearer test-hub-token")
    ).json()) as StatusBody;
    expect(st).toEqual({
      ok: true,
      namespace_count: 1,
      key_count: 2,
      namespaces: [
        {
          namespace: "/klprism/prod",
          env: "prod",
          generated_at: "2026-09-19T10:00:00Z",
          key_count: 2,
        },
      ],
    });

    const ns = await (await get("/api/namespaces", "Bearer test-hub-token")).json();
    expect(ns).toEqual({ ok: true, namespaces: st.namespaces });
  });
});

// The names-only guarantee for the stats routes: even if a value somehow
// reached KV (a future producer regression that slips past ingest's
// rejection), summarizeManifests projects allowlisted fields only -- so a
// planted value can never cross the status/namespaces boundary.
describe("names-only guarantee", () => {
  it("omits key names and fingerprints from stats", async () => {
    expect((await pushManifest(good)).status).toBe(200);
    for (const path of ["/api/status", "/api/namespaces"]) {
      const raw = await (await get(path, "Bearer test-hub-token")).text();
      expect(raw).not.toContain("DB_PASSWORD");
      expect(raw).not.toContain("API_TOKEN");
      expect(raw).not.toContain("a1b2c3d4");
      expect(raw).not.toContain("e5f6a7b8");
      expect(raw).toContain("/klprism/prod");
    }
  });

  it("never echoes a planted value, even from an adversarial KV entry", async () => {
    // Bypass ingest entirely: simulate a stale/regressed writer that stored
    // a value-bearing manifest. The projection must stay value-blind.
    await env.VAULT_KV.put(
      "manifest:/rogue/prod",
      JSON.stringify({
        namespace: "/rogue/prod",
        env: "prod",
        generated_at: "2026-09-19T00:00:00Z",
        keys: [
          {
            name: "K",
            fingerprint: "deadbeef",
            updated_at: "2026-09-19T00:00:00Z",
            targets: {},
            value: "PlantedSecretValue99",
          },
        ],
      }),
    );
    for (const path of ["/api/status", "/api/namespaces"]) {
      const raw = await (await get(path, "Bearer test-hub-token")).text();
      expect(raw).not.toContain("PlantedSecretValue99");
      expect(raw).not.toContain("deadbeef");
      expect(raw).toContain("/rogue/prod");
      expect(raw).toContain('"key_count":1');
    }
  });
});
