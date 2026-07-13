import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

const manifest = {
  namespace: "/integration/prod",
  env: "prod",
  generated_at: "2026-07-03T10:00:00Z",
  keys: [
    {
      name: "API_KEY",
      fingerprint: "deadbeef",
      updated_at: "2026-07-01T00:00:00Z",
      targets: { "github:n24q02m/skret": { present: true, status: "present" } },
    },
  ],
};

function cookieFrom(res: Response): string {
  const setCookie = res.headers.get("Set-Cookie") ?? "";
  return setCookie.split(";")[0]; // "session=<token>"
}

describe("dashboard flow", () => {
  it("GET / with no cookie shows the login form, not data", async () => {
    const res = await SELF.fetch("https://hub.test/");
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('name="password"');
    expect(body).not.toContain("API_KEY");
  });

  it("POST /login with wrong password returns 401 login form", async () => {
    const res = await SELF.fetch("https://hub.test/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "password=nope",
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('name="password"');
  });

  it("full flow: push manifest, login, dashboard shows it (no values)", async () => {
    // 1. ingest
    const ingestRes = await SELF.fetch("https://hub.test/api/manifest", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-hub-token" },
      body: JSON.stringify(manifest),
    });
    expect(ingestRes.status).toBe(200);

    // 2. login (redirect + Set-Cookie)
    const loginRes = await SELF.fetch("https://hub.test/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "password=test-relay-password",
      redirect: "manual",
    });
    expect(loginRes.status).toBe(303);
    const cookie = cookieFrom(loginRes);
    expect(cookie).toContain("session=");

    // 3. dashboard with cookie
    const dashRes = await SELF.fetch("https://hub.test/", { headers: { Cookie: cookie } });
    expect(dashRes.status).toBe(200);
    const body = await dashRes.text();
    expect(body).toContain("API_KEY");
    expect(body).toContain("deadbeef");
    expect(body).toContain("present");
  });

  it("GET / with a garbage cookie falls back to login", async () => {
    const res = await SELF.fetch("https://hub.test/", { headers: { Cookie: "session=forged.sig" } });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('name="password"');
  });

  it("POST /login with a malformed body returns 400, not 500", async () => {
    const res = await SELF.fetch("https://hub.test/login", {
      method: "POST",
      headers: { "Content-Type": "multipart/form-data; boundary=x" },
      body: "not-a-valid-multipart-body",
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('name="password"');
  });

  it("POST /logout clears the session cookie and redirects to /", async () => {
    const loginRes = await SELF.fetch("https://hub.test/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "password=test-relay-password",
      redirect: "manual",
    });
    const cookie = cookieFrom(loginRes);

    const logoutRes = await SELF.fetch("https://hub.test/logout", {
      method: "POST",
      headers: { Cookie: cookie },
      redirect: "manual",
    });
    expect(logoutRes.status).toBe(303);
    expect(logoutRes.headers.get("Location")).toBe("/");
    const setCookie = logoutRes.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain("session=;");
    expect(setCookie).toContain("Max-Age=0");
  });
});
