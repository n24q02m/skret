import { describe, it, expect } from "vitest";
import { renderDashboard, renderLogin } from "../src/render";
import type { Manifest } from "../src/types";

const m: Manifest = {
  namespace: "/klprism/prod",
  env: "prod",
  generated_at: "2026-07-03T10:00:00Z",
  keys: [
    {
      name: "DATABASE_URL",
      fingerprint: "a1b2c3d4",
      updated_at: "2026-07-01T00:00:00Z",
      targets: {
        "github:n24q02m/skret": { present: true, status: "in-sync" },
        "cloudflare:worker": { present: false, status: "missing" },
      },
    },
  ],
};

describe("renderDashboard", () => {
  it("renders key name, fingerprint and per-target status", () => {
    const html = renderDashboard([m]);
    expect(html).toContain("DATABASE_URL");
    expect(html).toContain("a1b2c3d4");
    expect(html).toContain("in-sync");
    expect(html).toContain("missing");
    expect(html).toContain("/klprism/prod");
  });
  it("shows an empty state with no manifests", () => {
    expect(renderDashboard([])).toContain("hub push");
  });
  it("escapes HTML in names (XSS guard)", () => {
    const evil: Manifest = { ...m, namespace: "<script>", keys: [] };
    const html = renderDashboard([evil]);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("renderLogin", () => {
  it("renders a password form", () => {
    const html = renderLogin();
    expect(html).toContain('name="password"');
    expect(html).toContain('action="/login"');
  });
  it("shows an error message when given one", () => {
    expect(renderLogin("wrong password")).toContain("wrong password");
  });
});
